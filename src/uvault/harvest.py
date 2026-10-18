"""Resumable metadata/collection commands; archive bytes never become a local mirror.

The optional publisher is invoked only after a per-version archive license decision.
No command in this module publishes by default.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile

from . import sources

SCHEMA_VERSION = "1.0"
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "BSL-1.0", "CC0-1.0", "Unlicense"}
LICENSE_REVIEW_ALGORITHM = "archive-rights-v3-binary-layout"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".pending")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def discover(commit=None, extra_seeds=()):
    if commit or extra_seeds:
        raise ValueError("R4 discovery uses the explicit common whitelist; add a named gap instead of an ecosystem snapshot")
    from .curated import queue
    return queue()

def legacy_discover(commit=None, extra_seeds=()):
    snapshot = sources.discover_openupm(commit)
    by_id = {item["id"]: item for item in snapshot["packages"]}
    for seed in sources.seed_packages() + list(extra_seeds):
        if seed["id"] in by_id:
            # Keep immutable OpenUPM provenance alongside priority/target hints.
            by_id[seed["id"]].update({k: v for k, v in seed.items() if k not in ("versions", "sourceSnapshot", "definitionBlobSha", "definitionUrl")})
        else:
            by_id[seed["id"]] = copy.deepcopy(seed)
    return {"schemaVersion": SCHEMA_VERSION, "createdAt": sources.utc_now(),
            "snapshots": [{k: v for k, v in snapshot.items() if k != "packages"}],
            "completeEnumeration": snapshot["completeEnumeration"], "scope": "OpenUPM definitions plus explicit Unity/runtime/reference seeds; not the whole ecosystem",
            "packages": sorted(by_id.values(), key=lambda item: item["id"]), "frontier": []}


def update_metadata(queue, *, limit=None, retry_failed=False, package_ids=(), progress=None, refresh=False):
    """Mutate a queue incrementally; callback checkpoints after every attempted package.

    R4 retains only selected common versions. Dependencies are named gaps and
    never implicitly add package families or historical version tasks.
    """
    attempted = 0
    by_id = {item["id"]: item for item in queue["packages"]}
    pending = list(queue["packages"])
    selected_ids = set(package_ids)
    for seed in pending:
        if selected_ids and seed["id"] not in selected_ids:
            continue
        state = seed.get("metadataStatus", "pending")
        if state == "reference-only" or (state == "complete" and not refresh) or (state == "failed" and not retry_failed):
            continue
        if limit is not None and attempted >= limit:
            break
        attempted += 1
        try:
            package = sources.fetch_package(seed)
            old_versions = {(v["version"], v.get("variantId")): v for v in seed.get("versions", [])}
            merged = []
            for version in package["versions"]:
                key = (version["version"], version.get("variantId"))
                old = old_versions.pop(key, None)
                if old and (old.get("artifact") or old.get("fetchStatus") not in (None, "pending")):
                    # The original observed object/provenance is immutable. Refresh
                    # discovers new variants without rewriting an old hash or grant.
                    version = copy.deepcopy(old)
                    version["upstreamListed"] = True
                    version["metadataRefreshedAt"] = sources.utc_now()
                merged.append(version)
            for old in old_versions.values():
                old = copy.deepcopy(old)
                old["upstreamListed"] = False
                merged.append(old)
            package["versions"] = sorted(merged, key=lambda v: (sources.version_key(v["version"]), v.get("variantId", "")))
            for key in ("definitionUrl", "definitionBlobSha", "sourceSnapshot", "family", "targetVersions"):
                if key in seed:
                    package[key] = seed[key]
            if seed.get("curatedPolicy"):
                from .curated import curate_package
                package = curate_package(package, seed)
            else:
                package.update(sources.selection_status(package["versions"], seed.get("targetVersions", ())))
            seed.clear()
            seed.update(package)
            # Unity package dependencies are served by the same authoritative registry.
            for version in package["versions"]:
                for dep_id, spec in version.get("dependencies", {}).items():
                    if queue.get("scopeVersion")=="R4":
                        gap={"packageId":dep_id,"specification":spec,"discoveredBy":package["id"],"status":"explicit-consumer-gap-if-needed"}
                        if gap not in queue.setdefault("frontier",[]):queue["frontier"].append(gap)
                        continue
                    if dep_id in by_id:
                        existing=by_id[dep_id]
                        if isinstance(spec,str) and re.fullmatch(r"\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?",spec):
                            targets=sorted(set(existing.get("targetVersions",[])+[spec]),key=sources.version_key)
                            existing["targetVersions"]=targets
                            request={"version":spec,"discoveredBy":package["id"],"registryHint":package.get("registry"),"sourceVerified":False}
                            if request not in existing.setdefault("versionRequests",[]):
                                existing["versionRequests"].append(request)
                            if existing.get("versions"):
                                existing.update(sources.selection_status(existing["versions"],targets))
                        continue
                    if dep_id.startswith("com.unity.modules."):
                        dep = {"schemaVersion": SCHEMA_VERSION, "id": dep_id, "displayName": dep_id, "adapter": "reference", "metadataStatus": "reference-only",
                               "sources": [{"kind": "unity-editor-builtin", "url": "https://docs.unity3d.com/Manual/upm-ui-disable.html"}],
                               "versions": [], "disposition": "builtin-reference", "declaredPackageVersions": [spec], "discoveredBy": package["id"],
                               "reason": "Built-in module implementation belongs to the selected Unity Editor; package version is not an engine source version"}
                        by_id[dep_id] = dep
                        queue["packages"].append(dep)
                        continue
                    if isinstance(spec, str) and re.match(r"^\d", spec) and package.get("registry"):
                        dep = {"id": dep_id, "adapter": "registry", "registry": package["registry"], "metadataStatus": "pending", "versions": [], "discoveredBy": package["id"]}
                        if re.fullmatch(r"\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?", spec):
                            dep["targetVersions"] = [spec]
                        by_id[dep_id] = dep
                        queue["packages"].append(dep)
                        pending.append(dep)
                    else:
                        frontier = {"packageId": dep_id, "specification": spec, "discoveredBy": package["id"], "status": "unresolved-source"}
                        if frontier not in queue.setdefault("frontier", []):
                            queue["frontier"].append(frontier)
        except sources.SourceError as exc:
            seed["metadataStatus"] = "failed"
            seed["metadataError"] = exc.as_dict()
            seed["metadataAttemptedAt"] = sources.utc_now()
        if progress:
            progress(queue, seed)
    return {"attempted": attempted, "coverage": coverage(queue)}


def coverage(queue):
    dispositions, metadata, fetches = {}, {}, {}
    selected, completed, listed, published, verified = 0, 0, 0, 0, 0
    for package in queue["packages"]:
        status = package.get("metadataStatus", "pending")
        metadata[status] = metadata.get(status, 0) + 1
        selected_names = set(package.get("selectedVersions", []))
        selected += sum(1 for version in package.get("versions", []) if version["version"] in selected_names and version.get("fetchStatus")!="reference-only")
        listed += len(package.get("versions", []))
        if not package.get("versions") and package.get("disposition"):
            value = package["disposition"]
            dispositions[value] = dispositions.get(value, 0) + 1
        for version in package.get("versions", []):
            value = version.get("disposition", "license-unresolved")
            dispositions[value] = dispositions.get(value, 0) + 1
            fetch = version.get("fetchStatus", "pending")
            fetches[fetch] = fetches.get(fetch, 0) + 1
            if fetch == "published":
                published += 1
            if (version.get("artifact") or {}).get("verifiedRemote"):
                verified += 1
            if version["version"] in selected_names and fetch in ("collected", "published", "fetched"):
                completed += 1
    return {"schemaVersion": SCHEMA_VERSION, "generatedAt": sources.utc_now(),
            "sourceSnapshots": queue.get("snapshots", []), "completeEnumeration": queue.get("completeEnumeration", False),
            "scope": queue.get("scope"), "discoveredPackages": len(queue["packages"]),
            "requirementRevision":queue.get("requirementRevision","R4"),"compatibilitySets":queue.get("compatibilitySets",[]),
            "nugetDependencyCandidates":queue.get("nugetDependencyCandidates",{}),
            "onDemandCandidates":queue.get("onDemandCandidates",[]),"providerRuleCandidates":queue.get("providerRuleCandidates",[]),
            "activatedDemandCandidates":queue.get("activatedDemandCandidates",[]),"coverageDecision":queue.get("coverageDecision",{}),
            "activatedProviderCandidates":queue.get("activatedProviderCandidates",[]),
            "registeredPackages": metadata.get("complete", 0) + metadata.get("reference-only", 0),
            "metadataStatusCounts": metadata, "listedVersions": listed, "selectedVersionTasks": selected,
            "completedSelectedVersionTasks": completed, "pendingSelectedVersionTasks": selected - completed,
            "fetchedVersionRecords": sum(fetches.get(state, 0) for state in ("collected", "published", "fetched")),
            "publishedVersionRecords": published, "remoteReadbackVerifiedVersionRecords": verified,
            "dispositionCounts": dispositions, "fetchStatusCounts": fetches, "discoveryFrontier": queue.get("frontier", []),
            "pendingPackageIds": [p["id"] for p in queue["packages"] if p.get("metadataStatus", "pending") not in ("complete", "reference-only")],
            "missingTargetVersions": [{"packageId": p["id"], "versions": p["missingTargetVersions"]} for p in queue["packages"] if p.get("missingTargetVersions")]}


def _archive_entries(data, archive_format):
    """Yield small rights/metadata documents plus names; never extract to disk."""
    if archive_format in ("zip", "nupkg"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                name = item.filename.replace("\\", "/")
                yield name, archive.read(item) if _needed_document(name) and item.file_size <= 1024 * 1024 else None
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for item in archive:
                if not item.isfile():
                    continue
                name = item.name.replace("\\", "/")
                if _needed_document(name) and item.size <= 1024 * 1024:
                    stream = archive.extractfile(item)
                    yield name, stream.read() if stream else None
                else:
                    yield name, None


def _needed_document(name):
    base = PurePosixPath(name).name.lower()
    return base.startswith(("license", "licence", "copying", "notice")) or base.endswith(".nuspec") or base == "package.json"


def license_expression(text):
    """Recognize actual grant texts, never a package's unverified SPDX hint alone."""
    lower = re.sub(r"\s+", " ", text.lower())
    if "unity reference-only" in lower or "unity reference only" in lower:
        return "LicenseRef-Unity-Reference-Only"
    if "unity companion license" in lower:
        return "LicenseRef-Unity-Companion"
    if "spine runtimes license" in lower or "spine runtime software license" in lower:
        return "LicenseRef-Spine-Runtimes"
    if "primetween" in lower and any(word in lower for word in ("prohibit", "not permitted", "not allowed", "may not", "must not")):
        return "LicenseRef-PrimeTween"
    if any(phrase in lower for phrase in ("non-commercial use only", "noncommercial use only", "commercial use is prohibited", "redistribution is prohibited", "you may not redistribute", "you may not distribute", "distribution of source code is prohibited")):
        return "LicenseRef-Restricted"
    if "permission is hereby granted, free of charge" in lower and "the software is provided" in lower and "without restriction" in lower:
        return "MIT"
    if "apache license" in lower and "version 2.0" in lower and "end of terms and conditions" in lower:
        return "Apache-2.0"
    if "redistribution and use in source and binary forms" in lower and "this software is provided" in lower:
        return "BSD-3-Clause" if "neither the name" in lower or "neither the names" in lower else "BSD-2-Clause"
    if "permission to use, copy, modify, and/or distribute this software for any purpose with or without fee" in lower and "the software is provided" in lower:
        return "ISC"
    if "this is free and unencumbered software released into the public domain" in lower and "unlicense.org" in lower:
        return "Unlicense"
    if "boost software license - version 1.0" in lower and "the software is provided" in lower:
        return "BSL-1.0"
    if "this software is provided 'as-is'" in lower and "the origin of this software must not be misrepresented" in lower:
        return "Zlib"
    return None


def inspect_licenses(data, archive_format, record, *, upstream_license=None, component_review=None):
    if component_review and (component_review.get("archiveSha256") != _sha(data)
                             or component_review.get("packageId") != record.get("packageId")
                             or component_review.get("version") != record.get("version")
                             or component_review.get("reviewStatus") != "reviewed"):
        component_review = None
    entries = list(_archive_entries(data, archive_format))
    files = [name for name, _ in entries]
    first = {name.split("/", 1)[0] for name in files}
    prefix = next(iter(first)) + "/" if len(first) == 1 and all("/" in name for name in files) else ""
    components, notices, nuspec_info, manifest_info = [], [], {}, {}
    for name, content in entries:
        relative = name[len(prefix):] if prefix and name.startswith(prefix) else name
        base = PurePosixPath(relative).name.lower()
        if content is not None and base == "package.json" and "/" not in relative:
            try:
                manifest = json.loads(content.decode("utf-8-sig"))
                manifest_info = {key: manifest.get(key) for key in ("name", "version", "license", "repository")}
                manifest_info["sha256"] = _sha(content)
            except (ValueError, UnicodeError):
                manifest_info = {"error": "invalid-package-json"}
        if content is not None and base.endswith(".nuspec"):
            try:
                from .nuget import parse_nuspec
                nuspec_info = parse_nuspec(content, relative)
            except ET.ParseError:
                nuspec_info = {"error": "invalid-nuspec"}
        if content is not None and base.startswith(("license", "licence", "copying")):
            text = content.decode("utf-8-sig", errors="replace")
            components.append({"path": relative, "expression": license_expression(text), "sha256": _sha(content),
                               "evidenceUrl": record.get("downloadUrl", "") + "#" + urllib.parse.quote(name), "text": text})
        elif content is not None and base.startswith("notice"):
            notices.append({"path": relative, "sha256": _sha(content), "text": content.decode("utf-8-sig", errors="replace")})
    root_licenses = [item for item in components if "/" not in item["path"]]
    if not root_licenses and upstream_license:
        components.append(upstream_license)
        root_licenses = [upstream_license]
    # A NuGet license file can live in a dedicated folder; it is not automatically a root grant.
    primary = root_licenses[0] if root_licenses else None
    expressions = {item["expression"] for item in components}
    restricted = [item for item in components if item["expression"] not in PERMISSIVE]
    from .license_components import binary_components
    native = binary_components(data, archive_format)
    for binary in native:
        name = binary["path"][len(prefix):] if prefix else binary["path"]
        components.append({"path": name, "expression": None, "sha256": None, "reviewStatus": "native-component-rights-unresolved",
                           "detection": binary["detection"],
                           "reason": "Wrapper/root license does not by itself establish this bundled binary's origin and redistribution rights; managed/native classification requires separate review"})
    license_dirs = {str(PurePosixPath(c["path"]).parent) for c in components if c.get("sha256")}
    suspicious = set()
    for name in files:
        relative = name[len(prefix):] if prefix else name
        parts = PurePosixPath(relative).parts
        for index, part in enumerate(parts[:-1]):
            if part.lower().replace("_", "").replace("-", "") in ("thirdparty", "vendor", "vendors", "external", "externals"):
                component = "/".join(parts[:min(index + 2, len(parts) - 1)])
                if not any(directory == component or directory.startswith(component + "/") for directory in license_dirs):
                    suspicious.add(component)
    for component in sorted(suspicious):
        reviewed_component = next((item for item in (component_review or {}).get("components", [])
                                   if item.get("classification") == "project-authored-integration-adapters"
                                   and (component == item["path"] or component.startswith(item["path"] + "/"))), None)
        if reviewed_component:
            continue
        components.append({"path": component, "expression": None, "sha256": None,
                           "reviewStatus": "bundled-component-rights-unresolved", "reason": "Bundled third-party directory has no separately detected license evidence"})
    if component_review:
        for reviewed in component_review.get("components", []):
            components.append({"path": reviewed["path"], "expression": reviewed["expression"],
                               "reviewStatus": "reviewed-project-authored-integration-adapters",
                               "evidenceUrl": component_review["sourceUrl"] + "/tree/" + component_review["sourceRef"],
                               "archiveSha256": component_review["archiveSha256"], "files": reviewed["files"], "reason": reviewed["basis"]})
        suspicious = {path for path in suspicious if not any(path == item["path"] or path.startswith(item["path"] + "/") for item in component_review.get("components", []))}
    expression = primary["expression"] if primary else None
    disposition = "mirror-allowed" if primary and expression in PERMISSIVE and not restricted and not native and not suspicious else "license-unresolved"
    reasons = []
    if native:
        disposition = "official-fetch-only"
        reasons.append("Native/SDK components require their own redistribution evidence")
    if expression and expression.startswith("LicenseRef-"):
        disposition = "builtin-reference" if expression == "LicenseRef-Unity-Reference-Only" else "official-fetch-only"
        reasons.append("Special-purpose or usage-restricted license")
    if restricted:
        reasons.append("One or more component license texts are unrecognized or restricted")
    if suspicious:
        reasons.append("Bundled third-party directories need component-specific rights evidence")
    if not primary:
        reasons.append("No recognized archive-root license grant")
    license_record = {"expression": expression, "evidenceUrl": primary.get("evidenceUrl") if primary else None,
                      "sha256": primary.get("sha256") if primary else None, "text": primary.get("text") if primary else None,
                      "components": components, "notices": notices, "reviewStatus": "archive-text-reviewed",
                      "reviewAlgorithm": LICENSE_REVIEW_ALGORITHM,
                      "reviewedAt": sources.utc_now(), "decisionBasis": reasons or ["Recognized permissive root grant; all detected license documents reviewed; no detected native SDK components"]}
    if upstream_license:
        license_record["noticeDelivery"] = "Archive omits license text; preserve catalog license text as a companion when materializing or redistributing"
    if component_review:
        license_record["componentReviewSha256"] = _sha(json.dumps(component_review, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return {"license": license_record, "disposition": disposition, "nuspec": nuspec_info, "packageManifest": manifest_info, "binaryComponents": native}


def _pinned_upstream_license(record, manifest):
    """Retrieve a missing grant from the package's own immutable repository revision.

    A floating licensesUrl or a license from another package version is insufficient.
    """
    repository = manifest.get("repository") or {}
    if not isinstance(repository, dict) or manifest.get("license") not in PERMISSIVE:
        return None
    commit = repository.get("revision") or record.get("sourceRef")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        return None
    url = sources._repo_url(repository).removesuffix(".git")
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/?", url)
    if not match:
        return None
    for filename in ("LICENSE", "LICENSE.md", "LICENSE.txt", "License.txt", "COPYING"):
        license_url = "https://raw.githubusercontent.com/" + match.group(1) + "/" + commit + "/" + filename
        try:
            content = sources.request_bytes(license_url, max_bytes=1024 * 1024)
        except sources.SourceError as exc:
            if exc.status == 404:
                continue
            return None
        text = content.decode("utf-8-sig", errors="replace")
        expression = license_expression(text)
        if expression != manifest["license"]:
            return None
        return {"path": filename, "expression": expression, "sha256": _sha(content), "text": text,
                "evidenceUrl": license_url, "scope": "pinned-upstream-repository-root", "sourceRef": commit}
    return None


def _find_component_review(record, artifact_sha=None):
    """Only exact artifact/version review records may override a directory warning."""
    locations = [Path(__file__).resolve().parents[2] / "sources" / "component-reviews.json",
                 Path(sys.prefix) / "share" / "uvault" / "component-reviews.json"]
    reviews = []
    for location in locations:
        if location.is_file():
            try:
                reviews = json.loads(location.read_text(encoding="utf-8"))["reviews"]
                break
            except (ValueError, OSError, KeyError):
                continue
    artifact_sha = artifact_sha or (record.get("artifact") or {}).get("sha256")
    for review in reviews:
        if (review.get("packageId") == record.get("packageId") and review.get("version") == record.get("version")
                and review.get("archiveSha256") == artifact_sha and review.get("reviewStatus") == "reviewed"
                and review.get("upstreamComparison", {}).get("completeCodeFileEquality")
                and re.fullmatch(r"[0-9a-fA-F]{40}", review.get("sourceRef", ""))):
            evidence = review.get("licenseEvidence", {})
            if evidence.get("expression") in PERMISSIVE and _sha(evidence.get("text", "").encode("utf-8")) == evidence.get("sha256"):
                return review
    return None


def needs_license_recheck(record):
    if (record.get("license") or {}).get("reviewAlgorithm") != LICENSE_REVIEW_ALGORITHM:
        return True
    review = _find_component_review(record)
    if review:
        review_sha = _sha(json.dumps(review, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        return (record.get("license") or {}).get("componentReviewSha256") != review_sha
    return False


def _verify_integrity(data, record):
    shasum = record.get("upstreamShasum")
    if shasum and hashlib.sha1(data).hexdigest().lower() != shasum.lower():
        raise ValueError("Upstream SHA1 mismatch")
    integrity = record.get("upstreamIntegrity")
    if integrity:
        checked = []
        for token in integrity.split():
            algorithm, _, encoded = token.partition("-")
            if algorithm not in ("sha256", "sha384", "sha512", "sha1"):
                continue
            actual = base64.b64encode(hashlib.new(algorithm, data).digest()).decode("ascii")
            checked.append(actual == encoded.split("?", 1)[0])
        if checked and not any(checked):
            raise ValueError("Upstream integrity mismatch")


def collect_version(package, version, *, publish=None):
    """Fetch/review/fingerprint one version. Publisher(data, record) -> artifact.

    The callback must upload and anonymously read back/hash the object before
    returning a verifiedRemote artifact. Bytes are otherwise released on return.
    """
    record = copy.deepcopy(version)
    record["packageId"] = package["id"]
    url = record.get("downloadUrl")
    if not url:
        record["fetchStatus"] = "source-unavailable"
        record["fetchError"] = {"kind": "no-archive-url"}
        return record
    data = None
    try:
        data = sources.request_bytes(url)
        _verify_integrity(data, record)
        if record.get("artifact") and record["artifact"].get("sha256") and record["artifact"]["sha256"] != _sha(data):
            raise ValueError("Previously observed upstream artifact changed; preserve the old variant and review a new variant")
        archive_format = "nupkg" if url.lower().endswith(".nupkg") else "zip" if data[:4] == b"PK\x03\x04" else "tar.gz"
        rights = inspect_licenses(data, archive_format, record)
        review = _find_component_review(record, _sha(data))
        if review:
            record["sourceRef"] = review["sourceRef"]
            record["sourceUrl"] = review["sourceUrl"]
            record["sourceRefEvidence"] = {"kind": "reviewed-archive-upstream-code-equality", "archiveSha256": review["archiveSha256"], "comparison": review["upstreamComparison"]}
            rights = inspect_licenses(data, archive_format, record, upstream_license=review["licenseEvidence"], component_review=review)
        manifest = rights["packageManifest"]
        if manifest.get("name") == package["id"] and manifest.get("version") == record["version"]:
            repository = manifest.get("repository") or {}
            if isinstance(repository, dict) and re.fullmatch(r"[0-9a-fA-F]{40}", str(repository.get("revision", ""))):
                record["sourceRef"] = repository["revision"]
                record["sourceUrl"] = sources._repo_url(repository).removesuffix(".git")
                record["sourceRefEvidence"] = {"kind": "archive-package-json", "sha256": manifest["sha256"]}
            if not rights["license"].get("expression"):
                evidence = _pinned_upstream_license(record, manifest)
                if evidence:
                    rights = inspect_licenses(data, archive_format, record, upstream_license=evidence)
        record["license"], record["disposition"] = rights["license"], rights["disposition"]
        if rights["nuspec"]:
            record["nuget"] = rights["nuspec"]
            repo = rights["nuspec"].get("repository", {})
            if repo.get("url"):
                record["sourceUrl"] = repo["url"]
            if repo.get("commit"):
                record["sourceRef"] = repo["commit"]
        from .inventory import fingerprint_archive
        fingerprint = fingerprint_archive(data, archive_format)
        record["fingerprint"] = fingerprint
        component=(record.get("componentScope") or {}).get("metadata")
        if component:
            observed=next((f for f in fingerprint["files"] if f["path"]==component["path"]),None)
            if not observed or observed["sha256"]!=component["sha256"]:
                raise ValueError("Pinned component package metadata differs from the original archive")
        if record.get("nuget"):
            from .nuget import assets
            record["nuget"]["assets"] = assets(fingerprint["files"])
            record["nuget"]["archiveSha256"] = _sha(data)
        if package.get("componentBundle")=="sentry-unity":
            record["sdkBundle"]={"packageId":package["id"],"version":record["version"],"archiveSha256":_sha(data),
                "assemblies":[{"path":item["path"],"sha256":item["sha256"],"assemblyIdentity":copy.deepcopy(item["assemblyIdentity"]),
                               "basis":"actual-sdk-archive-offline-managed-metadata"}
                              for item in fingerprint.get("managedMetadata",[]) if item.get("metadataStatus")=="managed"
                              and (item.get("assemblyIdentity") or {}).get("name","").startswith(("Sentry", "io.sentry."))],
                "scope":"SDK bundled assembly versions; never substitute similarly named System packages","profileVerified":False}
            record["sdkBundle"]["metadataStatus"]="decoded-sdk-assemblies" if record["sdkBundle"]["assemblies"] else "managed-metadata-unavailable"
            record["sdkBundle"]["unparsedDlls"]=[{"path":item["path"],"status":item.get("metadataStatus"),"reason":item.get("metadataError")}
                                                 for item in fingerprint.get("managedMetadata",[]) if item.get("metadataStatus") not in ("managed","native")]
        elif package.get("componentBundle")=="sdk-managed-components":
            record["sdkBundle"]={"packageId":package["id"],"version":record["version"],"archiveSha256":_sha(data),
                "assemblies":[{"path":item["path"],"sha256":item["sha256"],"assemblyIdentity":copy.deepcopy(item["assemblyIdentity"]),
                               "basis":"actual-sdk-archive-offline-managed-metadata"}
                              for item in fingerprint.get("managedMetadata",[]) if item.get("metadataStatus")=="managed"],
                "scope":"Actual bundled managed identities only; no inference of native SDK versions or interchangeable dependencies","profileVerified":False}
            record["sdkBundle"]["metadataStatus"]="decoded-managed-identities" if record["sdkBundle"]["assemblies"] else "no-decoded-managed-dll-identities"
            record["sdkBundle"]["unparsedDlls"]=[{"path":item["path"],"status":item.get("metadataStatus"),"reason":item.get("metadataError")}
                                                 for item in fingerprint.get("managedMetadata",[]) if item.get("metadataStatus")!="managed"]
        names = [item["path"] for item in fingerprint.get("files", [])]
        has_sources = any(name.lower().endswith(".cs") for name in names)
        has_binary = bool(rights["binaryComponents"])
        kind = "mixed-source-binary" if has_sources and has_binary else "source" if has_sources else "binary-only" if has_binary else "no-csharp-source"
        record["artifact"] = {"sha256": _sha(data), "size": len(data), "format": archive_format, "kind": kind,
                              "url": url, "verifiedRemote": False}
        record["fetchStatus"] = "collected"
        record["collectedAt"] = sources.utc_now()
        if publish is not None and record["disposition"] == "mirror-allowed":
            try:
                artifact = publish(data, record)
                if not artifact.get("verifiedRemote") or artifact.get("sha256") != _sha(data) or artifact.get("size") != len(data):
                    raise ValueError("Publisher did not return a verified matching remote artifact")
                record["artifact"] = artifact
                record["fetchStatus"] = "published"
                record["publicationStatus"] = "verified"
                record.pop("publicationError", None)
            except Exception as exc:
                # Collection succeeded. Never persist an upload temp path, token,
                # unverified remote URL, or an exception's arbitrary private text.
                record["publicationStatus"] = "failed"
                record["publicationError"] = {"kind": type(exc).__name__, "message": "Publication or anonymous readback failed; no remote reference adopted"}
        return record
    except sources.SourceError as exc:
        record["fetchStatus"] = "fetch-failed"
        record["fetchError"] = exc.as_dict()
        record["fetchAttemptedAt"] = sources.utc_now()
        return record
    except (ValueError, tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        record["fetchStatus"] = "fetch-failed"
        record["fetchError"] = {"kind": "integrity-or-archive-error", "message": str(exc)}
        record["fetchAttemptedAt"] = sources.utc_now()
        return record
    finally:
        data = None


def collect_selected(queue, *, package_ids=(), limit=None, retry_failed=False, publish=None, progress=None):
    attempted, selected_ids = 0, set(package_ids)
    for package in queue["packages"]:
        if selected_ids and package["id"] not in selected_ids:
            continue
        if package.get("metadataStatus") != "complete":
            continue
        if not package.get("curatedPolicy"):
            package.update(sources.selection_status(package["versions"], package.get("targetVersions", ())))
        selected = set(package["selectedVersions"])
        for index, version in enumerate(package["versions"]):
            if version["version"] not in selected:
                continue
            state = version.get("fetchStatus", "pending")
            if state == "reference-only":
                continue
            version_identity = dict(version, packageId=package["id"])
            recheck = needs_license_recheck(version_identity)
            if (state == "published" and not recheck) or (state == "collected" and not recheck and (publish is None or version.get("disposition") != "mirror-allowed")) or (state == "fetch-failed" and not retry_failed):
                continue
            if limit is not None and attempted >= limit:
                return {"attempted": attempted, "coverage": coverage(queue)}
            attempted += 1
            package["versions"][index] = collect_version(package, version, publish=publish)
            if progress:
                progress(queue, package)
    return {"attempted": attempted, "coverage": coverage(queue)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    discovery = sub.add_parser("discover", help="Enumerate pinned OpenUPM and explicit seeds")
    discovery.add_argument("--commit")
    discovery.add_argument("--out", required=True)
    for name in ("metadata", "collect"):
        command = sub.add_parser(name, help="Resume " + name + " tasks; no persistent archive cache")
        command.add_argument("--queue", required=True)
        command.add_argument("--limit", type=int)
        command.add_argument("--package", action="append", default=[])
        command.add_argument("--retry-failed", action="store_true")
        if name == "metadata":
            command.add_argument("--refresh", action="store_true", help="Discover new versions while preserving previously observed immutable variants")
    report = sub.add_parser("coverage")
    report.add_argument("--queue", required=True)
    report.add_argument("--out")
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            queue = discover(args.commit)
            _save(args.out, queue)
            result = coverage(queue)
        elif args.command == "coverage":
            result = coverage(_load(args.queue))
            if args.out:
                _save(args.out, result)
        else:
            queue = _load(args.queue)
            if queue.get("scopeVersion")!="R4":
                raise ValueError("Historical exhaustive queues are retired; create the R4 common whitelist queue")
            operation = update_metadata if args.command == "metadata" else collect_selected
            options = {"limit": args.limit, "retry_failed": args.retry_failed, "package_ids": args.package,
                       "progress": lambda state, package: _save(args.queue, state)}
            if args.command == "metadata":
                options["refresh"] = args.refresh
            result = operation(queue, **options)
            _save(args.queue, queue)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (sources.SourceError, ValueError, OSError, KeyError) as exc:
        error = exc.as_dict() if isinstance(exc, sources.SourceError) else {"kind": "invalid-or-failed", "message": str(exc)}
        print(json.dumps({"error": error}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
