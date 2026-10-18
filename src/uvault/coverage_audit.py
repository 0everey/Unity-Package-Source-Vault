"""Audit public project metadata against an expanded catalog, without I/O.

This measures package ID/version *records*, not installed consumers, source
equality, runtime dependency closure, or the probability of recovering a game.
Manifest requirements and lock observations remain separate. Local specs are
represented by hashes, and source/fork/variant uncertainty survives a version
label match. Input dictionaries are never modified.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import re
from urllib.parse import parse_qs, urlsplit


_VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_COMMIT = re.compile(r"[0-9a-fA-F]{40}\Z")
_ACQUIRED = {"collected", "published", "fetched"}
_DISPOSITIONS = {"mirror-allowed", "official-fetch-only", "user-provided-only",
                 "builtin-reference", "license-unresolved", "source-unavailable", "fetch-failed"}
_STRATA = ("Runtime", "Editor", "Test", "default-builtin", "unknown")
_METRICS = (
    "declaredIdsRegistered", "observedIdsRegistered",
    "manifestExactVersionsRecorded", "lockExactVersionsRecorded",
    "exactObservedVersionsRecorded", "exactObservedVersionsAcquired",
    "exactObservedVersionsReferenceOnly", "exactObservedVersionsWithRightsMetadata",
)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def _local(value):
    return isinstance(value, str) and bool(
        value.lower().startswith(("file:", "git+file:", "embedded:", "local:"))
        or re.match(r"^[A-Za-z]:[/\\]", value)
        or value.startswith(("/", "\\", "./", "../")))


def _url(value):
    try:
        return urlsplit(value)
    except ValueError:
        return None


def _public(value):
    """Never echo a local path or credential-bearing source URL."""
    if value is None:
        return None
    if not isinstance(value, str):
        return {"redacted": True, "sha256": _hash(value)}
    if _local(value):
        return {"redacted": True, "sha256": _hash(value)}
    if "://" in value:
        parsed = _url(value.removeprefix("git+"))
        if parsed is None or parsed.username or parsed.password or any(
                key.lower() not in ("path",) for key in parse_qs(parsed.query)):
            return {"redacted": True, "sha256": _hash(value)}
    return value


def _repository(url):
    if not isinstance(url, str):
        return None
    url = url.removeprefix("git+")
    if url.startswith("git@") and ":" in url:
        host, path = url[4:].split(":", 1)
        url = "ssh://" + host + "/" + path
    parsed = _url(url)
    if parsed is None or parsed.scheme not in ("https", "http", "ssh", "git") or not parsed.hostname:
        return None
    return "https://" + parsed.hostname.lower() + parsed.path.removesuffix(".git").rstrip("/")


def _spec(value, source=None, commit=None, registry=None, context="manifest"):
    result = {"kind": "unknown", "specSha256": _hash(value), "value": _public(value),
                      "exactVersion": None, "registry": _public(registry),
              "declaredSource": _public(source), "observedHash": _public(commit),
              "fixedCommit": commit.lower() if isinstance(commit, str) and _COMMIT.fullmatch(commit) else None}
    if _local(value) or source in ("local", "embedded"):
        result.update(kind="file", value=None, redacted=True,
                      sourceIdentityStatus="local-content-unverified")
        return result
    parsed_value = _url(value.removeprefix("git+")) if isinstance(value, str) else None
    remote_git = isinstance(value, str) and (value.startswith(("git+", "git@")) or
                                           (parsed_value is not None and parsed_value.path.endswith(".git")))
    if isinstance(value, str) and (source == "git" or remote_git):
        parsed = parsed_value
        fragment = parsed.fragment if parsed is not None else ""
        path = parse_qs(parsed.query).get("path", [None])[0] if parsed is not None else None
        path = path.lstrip("/") if isinstance(path, str) and not re.match(r"^/?[A-Za-z]:", path) else path
        result.update(kind="git", repository=_repository(value), packagePath=_public(path),
                      requestedRef=_public(fragment) if fragment else None,
                      sourceIdentityStatus="git-content-and-fork-unverified")
        if not result["fixedCommit"] and _COMMIT.fullmatch(fragment or ""):
            result["fixedCommit"] = fragment.lower()
    elif isinstance(value, str) and _VERSION.fullmatch(value):
        kind = "builtin" if source == "builtin" else "registry" if source == "registry" or context == "manifest" else "unknown"
        result.update(kind=kind,
                      exactVersion=value, sourceIdentityStatus="version-label-only")
    elif source == "builtin":
        result.update(kind="builtin", sourceIdentityStatus="builtin-profile-unverified")
    else:
        result["sourceIdentityStatus"] = "source-spec-unassessed"
    return result


def _file_metadata(project, ending):
    matches = [f for f in project.get("files", []) if isinstance(f, dict)
               and isinstance(f.get("path"), str)
               and f["path"].replace("\\", "/").endswith(ending)]
    available = [f for f in matches if isinstance(f.get("metadata"), dict)]
    if len({_hash(f["metadata"]) for f in available}) > 1:
        raise ValueError("Conflicting metadata observations for " + ending)
    metadata = available[0]["metadata"] if available else None
    if metadata is not None and not isinstance(metadata.get("dependencies", {}), dict):
        raise ValueError("Metadata dependencies must be an object")
    return metadata, {"status": "observed" if available else "metadata-unavailable",
                      "files": [{"path": _public(f.get("path")), "sha256": f.get("sha256"),
                                 "status": f.get("status", "observed" if f in available else "unavailable")}
                                for f in matches]}


def _editor_version(project):
    for file in project.get("files", []):
        if isinstance(file, dict) and str(file.get("path", "")).endswith("ProjectVersion.txt"):
            text = file.get("metadata")
            if isinstance(text, str):
                found = re.search(r"(?m)^m_EditorVersion:\s*([0-9][0-9A-Za-z.+-]*)", text)
                if found:
                    return found[1]
    return None


def _manifest_registry(manifest, package_id):
    candidates = []
    for entry in (manifest or {}).get("scopedRegistries", []):
        if not isinstance(entry, dict):
            continue
        for scope in entry.get("scopes", []):
            if isinstance(scope, str) and package_id.startswith(scope):
                candidates.append((len(scope), entry.get("url")))
    if not candidates:
        return None
    length = max(n for n, _ in candidates)
    urls = {url for n, url in candidates if n == length and isinstance(url, str)}
    return next(iter(urls)) if len(urls) == 1 else None


def _source_conflicts(manifest, locked):
    if manifest is None or locked is None:
        return []
    conflicts = []
    left, right = manifest["kind"], locked["kind"]
    if left != right and "unknown" not in (left, right) and {left, right} != {"registry", "builtin"}:
        conflicts.append({"kind": "manifest-lock-source-conflict", "manifestKind": left, "lockKind": right})
    if manifest["exactVersion"] and locked["exactVersion"] and manifest["exactVersion"] != locked["exactVersion"]:
        conflicts.append({"kind": "manifest-lock-version-difference",
                          "manifestVersion": manifest["exactVersion"], "lockVersion": locked["exactVersion"]})
    if left == right == "git":
        if manifest.get("repository") != locked.get("repository") or manifest.get("packagePath") != locked.get("packagePath"):
            conflicts.append({"kind": "manifest-lock-git-source-difference"})
        if manifest.get("fixedCommit") and locked.get("fixedCommit") and manifest["fixedCommit"] != locked["fixedCommit"]:
            conflicts.append({"kind": "manifest-lock-git-commit-difference"})
    if left == right == "registry" and manifest.get("registry") and locked.get("registry") and manifest["registry"] != locked["registry"]:
        conflicts.append({"kind": "manifest-lock-registry-difference"})
    return conflicts


def _record(version):
    artifact = version.get("artifact") if isinstance(version.get("artifact"), dict) else {}
    license_info = version.get("license") if isinstance(version.get("license"), dict) else {}
    digest = artifact.get("sha256")
    acquired = version.get("fetchStatus") in _ACQUIRED and isinstance(digest, str) and bool(_SHA256.fullmatch(digest))
    reference = version.get("fetchStatus") == "reference-only" or version.get("disposition") == "builtin-reference"
    return {"version": version["version"], "variantId": _public(version.get("variantId")),
            "fetchStatus": version.get("fetchStatus", "unknown"),
            "catalogReportedAcquired": bool(acquired and not reference),
            "referenceOnly": bool(reference), "artifactSha256": digest if acquired else None,
            "remoteReadbackRecorded": bool(artifact.get("verifiedRemote") and acquired and not reference),
            "sourceUrl": _public(version.get("sourceUrl")), "sourceRef": _public(version.get("sourceRef")),
            "disposition": version.get("disposition", "unknown"),
            "licenseExpression": license_info.get("expression"),
            "licenseReviewStatus": license_info.get("reviewStatus"),
            "licenseEvidenceRecorded": bool(_SHA256.fullmatch(str(license_info.get("sha256", ""))) and (license_info.get("evidenceUrl") or license_info.get("text"))),
            "rightsMetadataRecorded": version.get("disposition") in _DISPOSITIONS,
            "targetVariantVerified": False}


def _git_candidates(package, specs):
    """Metadata alignment only; a lock hash cannot authenticate an upstream fork."""
    candidates = []
    for version in (package or {}).get("versions", []):
        for spec in specs:
            if spec["kind"] != "git" or not spec.get("fixedCommit"):
                continue
            if (version.get("sourceRef", "").lower() if isinstance(version.get("sourceRef"), str) else None) != spec["fixedCommit"]:
                continue
            same_repository = _repository(version.get("sourceUrl")) == spec.get("repository")
            component = version.get("componentScope")
            component = component if isinstance(component, dict) else {}
            source_path = version.get("sourcePath") or component.get("path") or component.get("subpath")
            same_path = (source_path or "").strip("/") == (spec.get("packagePath") or "").strip("/") if isinstance(source_path, (str, type(None))) and isinstance(spec.get("packagePath"), (str, type(None))) else False
            candidates.append({"version": version["version"], "variantId": _public(version.get("variantId")),
                               "sameCommitRecorded": True, "sameRepositoryRecorded": same_repository,
                               "sameSubpathRecorded": same_path, "targetOrForkEquivalenceVerified": False})
    return list({_hash(candidate): candidate for candidate in candidates}.values())


def _stratum(project, package_id, specs):
    # Optional, explicit purpose annotations do not establish a complete runtime
    # inventory. Package names and manifest.testables alone are not such proof.
    roles = project.get("dependencyRoles")
    evidence = roles.get(package_id, {}) if isinstance(roles, dict) else {}
    if isinstance(evidence, dict) and evidence.get("role") in _STRATA[:3] and evidence.get("evidenceRefs"):
        return evidence["role"], "explicit-panel-purpose-annotation"
    if package_id.startswith("com.unity.modules.") or any(s["kind"] == "builtin" for s in specs):
        return "default-builtin", "default-or-builtin-declaration-runtime-use-unproven"
    return "unknown", "no-real-consumer-purpose-evidence"


def _metric(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "ratio": numerator / denominator if denominator else None}


def _summarize(projects):
    counts = Counter({name: 0 for name in ("projects", "metadataUnavailableProjects",
                                         "projectsWithSourceConflicts", "declarationsWithSourceConflicts",
                                         "observedPackageIdEntries")})
    strata = {name: {"declarations": 0, "registeredIds": 0} for name in _STRATA}
    totals = {key: [0, 0] for key in _METRICS}
    unknowns = []
    for project in projects:
        counts["projects"] += 1
        counts["metadataUnavailableProjects"] += project["metadataAvailability"] == "metadata-unavailable"
        counts["projectsWithSourceConflicts"] += bool(project["sourceConflicts"])
        counts["declarationsWithSourceConflicts"] += len(project["sourceConflicts"])
        counts["observedPackageIdEntries"] += len(project["declarations"])
        for key in _METRICS:
            totals[key][0] += project["metrics"][key]["numerator"]
            totals[key][1] += project["metrics"][key]["denominator"]
        for name in _STRATA:
            for field in strata[name]:
                strata[name][field] += project["strata"][name][field]
        if project["unknownObjects"]:
            unknowns.append({"repository": project["repository"], "projectPath": project["projectPath"],
                             "cohortRole": project["cohortRole"], "objects": project["unknownObjects"]})
    return {"counts": dict(counts), "metrics": {key: _metric(*value) for key, value in totals.items()},
            "strata": strata, "unknownObjects": unknowns,
            "completeRuntimeDependencyCoverage": {"numerator": None, "denominator": None, "ratio": None,
                                                   "reason": "complete-real-runtime-consumer-inventory-not-provided"}}


def audit_panel(panel: dict, catalog: dict) -> dict:
    """Audit R7-PANEL-INPUTS ``projects[].files[].metadata`` against full packages.

    Denominators are observed package-ID entries or distinct (ID, exact numeric
    version) observations per project. Manifest and lock metrics are also
    supplied separately. A known version record is never target source equality.
    Runtime ratios remain null because this metadata contract has no complete
    source/assembly/runtime-consumer inventory. Optional dependencyRoles annotate
    purpose only and cannot change that limit or the immutable cohort labels.
    """
    if not isinstance(panel, dict) or not isinstance(panel.get("projects"), list):
        raise ValueError("panel must contain a projects list")
    if not isinstance(catalog, dict) or not isinstance(catalog.get("packages"), list):
        raise ValueError("catalog must contain expanded packages")
    packages = {}
    for package in catalog["packages"]:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str) or not isinstance(package.get("versions"), list):
            raise ValueError("catalog packages must be expanded records with id and versions")
        if package["id"] in packages:
            raise ValueError("duplicate catalog package ID")
        if any(not isinstance(v, dict) or not isinstance(v.get("version"), str) for v in package["versions"]):
            raise ValueError("catalog version records require a string version")
        packages[package["id"]] = package
    projects = []
    seen_projects = set()
    for project in panel["projects"]:
        if not isinstance(project, dict) or not isinstance(project.get("repository"), str):
            raise ValueError("each panel project requires its repository")
        if not isinstance(project.get("files", []), list) or not isinstance(project.get("cohortRole", "unknown"), str):
            raise ValueError("project files must be a list and cohortRole a string")
        key = (project["repository"], project.get("projectPath", ""))
        if key in seen_projects:
            raise ValueError("duplicate panel project identity")
        seen_projects.add(key)
        manifest, manifest_info = _file_metadata(project, "Packages/manifest.json")
        locked, lock_info = _file_metadata(project, "Packages/packages-lock.json")
        declared = (manifest or {}).get("dependencies", {})
        lock_deps = (locked or {}).get("dependencies", {})
        if any(not isinstance(i, str) for i in set(declared) | set(lock_deps)):
            raise ValueError("dependency IDs must be strings")
        rows = []
        for package_id in sorted(set(declared) | set(lock_deps)):
            package = packages.get(package_id)
            lock_entry = lock_deps.get(package_id)
            if lock_entry is not None and not isinstance(lock_entry, dict):
                raise ValueError("lock dependency records must be objects")
            left = _spec(declared[package_id], registry=_manifest_registry(manifest, package_id)) if package_id in declared else None
            right = _spec(lock_entry.get("version"), lock_entry.get("source"), lock_entry.get("hash"), lock_entry.get("url"), context="lock") if lock_entry is not None else None
            if right is not None:
                right["depth"] = lock_entry.get("depth")
            specs = [s for s in (left, right) if s is not None]
            conflicts = _source_conflicts(left, right)
            versions = []
            for value in sorted({s["exactVersion"] for s in specs if s["exactVersion"]}):
                records = [_record(v) for v in (package or {}).get("versions", []) if v["version"] == value]
                versions.append({"version": value,
                                 "origins": [name for name, s in (("manifest", left), ("lock", right)) if s and s["exactVersion"] == value],
                                 "recordPresent": bool(records), "records": records,
                                 "catalogReportedAcquired": any(v["catalogReportedAcquired"] for v in records),
                                 "referenceOnly": bool(records) and all(v["referenceOnly"] for v in records),
                                 "rightsMetadataRecorded": bool(records) and all(v["rightsMetadataRecorded"] for v in records),
                                 "variantStatus": "ambiguous-catalog-variants" if len(records) > 1 else "target-variant-unverified",
                                 "sourceRequirementVerified": False})
            role, role_basis = _stratum(project, package_id, specs)
            unknown = ["real-runtime-consumer-use-unproven", "target-variant-unverified"]
            if any(s["kind"] == "git" for s in specs):
                unknown.append("git-content-and-fork-equivalence-unverified")
            if any(s["kind"] == "file" for s in specs):
                unknown.append("local-content-unverified")
            if any(s["kind"] == "unknown" for s in specs):
                unknown.append("source-spec-unassessed")
            if conflicts:
                unknown.append("manifest-lock-conflict-unresolved")
            missing_versions = [v["version"] for v in versions if not v["recordPresent"]]
            catalog_status = ("id-not-registered" if package is None else
                              "known-id-missing-exact-version" if versions and len(missing_versions) == len(versions) else
                              "known-id-partial-exact-versions" if missing_versions else
                              "known-id-nonversioned-source-unverified" if not versions else "exact-label-records-present")
            rows.append({"packageId": _public(package_id), "declaredInManifest": package_id in declared,
                         "observedInLock": package_id in lock_deps, "manifest": left, "lock": right,
                         "idRegistered": package is not None, "catalogStatus": catalog_status,
                         "missingExactVersions": missing_versions, "exactVersionObservations": versions,
                         "idOnlyReference": bool(package and (package.get("metadataStatus") == "reference-only" or package.get("disposition") == "builtin-reference")),
                         "gitCatalogCandidates": _git_candidates(package, specs), "sourceConflicts": conflicts,
                         "usageStratum": role, "usageBasis": role_basis,
                         "manifestTestable": package_id in (manifest or {}).get("testables", []),
                         "unknowns": unknown, "targetSourceEqualityVerified": False})
        exacts = [v for row in rows for v in row["exactVersionObservations"]]
        counters = {
            "declaredIdsRegistered": (sum(r["idRegistered"] for r in rows if r["declaredInManifest"]), len(declared)),
            "observedIdsRegistered": (sum(r["idRegistered"] for r in rows), len(rows)),
        }
        for name, origin in (("manifestExactVersionsRecorded", "manifest"), ("lockExactVersionsRecorded", "lock")):
            observed = [v for v in exacts if origin in v["origins"]]
            counters[name] = (sum(v["recordPresent"] for v in observed), len(observed))
        for name, field in (("exactObservedVersionsRecorded", "recordPresent"),
                            ("exactObservedVersionsAcquired", "catalogReportedAcquired"),
                            ("exactObservedVersionsReferenceOnly", "referenceOnly"),
                            ("exactObservedVersionsWithRightsMetadata", "rightsMetadataRecorded")):
            counters[name] = (sum(v[field] for v in exacts), len(exacts))
        availability = "metadata-unavailable" if manifest is None and locked is None else "observed" if manifest is not None and locked is not None else "partial"
        unknowns = [{"kind": "runtime-consumer-inventory-unavailable",
                     "scope": "actual Assets/DLL/native/embedded use and complete runtime dependencies are not provided"}]
        for name, info in (("manifest", manifest_info), ("lock", lock_info)):
            if info["status"] != "observed":
                unknowns.append({"kind": "metadata-unavailable", "object": name})
        unknowns.extend({"kind": "declaration-uncertainty", "packageId": row["packageId"], "reasons": row["unknowns"]} for row in rows)
        strata = {name: {"declarations": sum(r["usageStratum"] == name for r in rows),
                         "registeredIds": sum(r["usageStratum"] == name and r["idRegistered"] for r in rows)} for name in _STRATA}
        projects.append({"repository": _public(project["repository"]), "projectPath": _public(project.get("projectPath", "")),
                         "sourceRef": _public(project.get("sourceRef")), "sourceStatus": project.get("sourceStatus", "unknown"),
                         "cohortRole": project.get("cohortRole", "unknown"), "metadataAvailability": availability,
                         "unityEditorVersion": _editor_version(project), "manifestObservation": manifest_info,
                         "lockObservation": lock_info, "declarations": rows, "strata": strata,
                         "metrics": {name: _metric(*counters[name]) for name in _METRICS},
                         "sourceConflicts": [{"packageId": r["packageId"], "conflicts": r["sourceConflicts"]} for r in rows if r["sourceConflicts"]],
                         "unknownObjects": unknowns,
                         "completeRuntimeDependencyCoverage": {"numerator": None, "denominator": None, "ratio": None,
                                                                "reason": "complete-real-runtime-consumer-inventory-not-provided"}})
    repositories = defaultdict(set)
    for project in projects:
        repository_key = _hash(project["repository"])
        repositories[repository_key].add(project["cohortRole"])
    cohort_overlaps = []
    for project in projects:
        roles = repositories[_hash(project["repository"])]
        groups = {"diagnostic" if role.startswith("diagnostic") else role for role in roles}
        if "held-out" in groups and "diagnostic" in groups:
            conflict = {"repository": project["repository"], "cohortRoles": sorted(roles)}
            if conflict not in cohort_overlaps:
                cohort_overlaps.append(conflict)
            project["unknownObjects"].append({"kind": "same-repository-diagnostic-held-out-overlap",
                                              "cohortRoles": sorted(roles)})
    cohort_groups = defaultdict(list)
    for project in projects:
        cohort_groups[project["cohortRole"]].append(project)
    summary = _summarize(projects)
    summary["cohorts"] = {role: _summarize(items) for role, items in sorted(cohort_groups.items())}
    summary["cohortRoleCounts"] = dict(sorted(Counter(p["cohortRole"] for p in projects).items()))
    summary["cohortGroupCounts"] = dict(sorted(Counter(
        "diagnostic" if p["cohortRole"].startswith("diagnostic") else p["cohortRole"]
        for p in projects).items()))
    summary["cohortRepositoryOverlaps"] = cohort_overlaps
    return {"schemaVersion": "1.0", "kind": "public-project-declaration-coverage-audit",
            "panelContentSha256": _hash(panel), "catalogCommit": catalog.get("catalogCommit"),
            "catalogContentSha256": _hash({"schemaVersion": catalog.get("schemaVersion"), "catalogCommit": catalog.get("catalogCommit"), "packages": catalog["packages"]}),
            "projects": projects, "summary": summary,
            "limits": ["Ratios describe this panel's observed ID/version records, not market/game coverage.",
                       "Manifest requirements and lock observations do not prove installed runtime consumers or target byte equality.",
                       "References never count as acquired archives; rights fields describe catalog metadata, not independent legal clearance.",
                       "Git commits, file specs and matching version labels never authenticate target variants or fork equivalence.",
                       "Cohort labels are preserved; this audit does not select versions, add packages or tune the held-out cohort."]}
