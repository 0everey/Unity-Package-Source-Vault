"""Evidence-tiered package matching; source provenance is not target equality."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from pathlib import Path

from .inventory import fingerprint_archive, inventory_directory, fingerprint_binary


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def _empty_fingerprint():
    return {"files": [], "assemblies": [], "namespaces": [], "types": [], "profileVerified": False}


def _names(values, field="name"):
    result = set()
    for value in values or []:
        if isinstance(value, str):
            result.add(value)
        elif isinstance(value, dict):
            name = value.get(field) or value.get("fullName") or (value.get("scope") or {}).get("name")
            if name:
                result.add(name)
    return result


def _source_map(fingerprint):
    files = fingerprint.get("files", [])
    return {f["path"]: f["sha256"] for f in files
            if isinstance(f, dict) and f.get("path", "").lower().endswith(".cs") and f.get("sha256")}


def _format(path):
    name = path.name.lower()
    for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".unitypackage", ".nupkg", ".zip", ".tgz", ".tar"):
        if name.endswith(ext):
            return ext[1:]
    return None


def _is_dummy(assembly):
    path = str(assembly.get("path", "")).replace("\\", "/")
    references = assembly.get("references", [])
    return bool(assembly.get("dummyDll") or assembly.get("isDummyDll") or
                "dummydll" in path.lower().split("/") or
                "dummy" in str(assembly.get("origin", "")).lower() or
                any(((r.get("scope") or {}).get("name") if isinstance(r, dict) else r) == "Il2CppDummyDll" for r in references))


def _structure_fingerprint(document, directory=None):
    """Adapt ReMaker StructureAssembly/StructureType JSON without loading DLLs."""
    if isinstance(document, list):
        # Native arrays are distinguished by their actual record fields.
        if all(isinstance(x, dict) and "scope" in x for x in document):
            assemblies, types = document, []
        elif all(isinstance(x, dict) and "fullName" in x for x in document):
            assemblies, types = [], document
        else:
            raise ValueError("JSON array is not a recognized ReMaker structure export")
    elif isinstance(document, dict):
        assemblies = document.get("assemblies", [])
        types = document.get("types", [])
        # A real structure-query result contains items and a graph selector.
        if document.get("graph") in ("types", "assemblies"):
            items = document.get("items", document.get("results", []))
            if isinstance(items, list):
                if document["graph"] == "assemblies":
                    assemblies = items
                else:
                    types = items
        if not isinstance(assemblies, list) or not isinstance(types, list):
            raise ValueError("ReMaker structure arrays must be lists")
    else:
        raise ValueError("Unsupported identity JSON")
    if directory:
        for name, values in (("assemblies.json", assemblies), ("types.json", types)):
            sibling = directory / name
            if not values and sibling.is_file():
                value = _read_json(sibling)
                if isinstance(value, list):
                    values.extend(value)
    fingerprint = _empty_fingerprint()
    for value in assemblies:
        if not isinstance(value, dict):
            continue
        scope = value.get("scope") or {}
        assembly = {"name": scope.get("name") or value.get("name"), "scope": scope,
                    "id": value.get("id"), "sha256": value.get("sha256"),
                    "dummyDll": _is_dummy(value), "metadataOnly": True,
                    "origin": value.get("origin", "normalized-structure")}
        fingerprint["assemblies"].append(assembly)
        # An exported SHA is an observation, not newly authenticated target bytes.
        # Keep it out of actual-byte files, even when the DLL was not a dummy.
    fingerprint["types"] = sorted(_names(types, "fullName"))
    fingerprint["typeDeclarations"] = [
        {key: value[key] for key in ("id", "assemblyId", "fullName", "namespace", "kind", "members") if key in value}
        for value in types if isinstance(value, dict)]
    fingerprint["namespaces"] = sorted({t.get("namespace") for t in types
                                         if isinstance(t, dict) and t.get("namespace")})
    fingerprint["declarationBasis"] = "ReMaker-normalized-metadata-declarations"
    fingerprint["dummyDllObserved"] = any(a["dummyDll"] for a in fingerprint["assemblies"])
    return fingerprint


def _locks(directory):
    packages = directory / "Packages" if (directory / "Packages").is_dir() else directory
    manifest_path, lock_path = packages / "manifest.json", packages / "packages-lock.json"
    manifest = _read_json(manifest_path) if manifest_path.is_file() else {}
    lock = _read_json(lock_path) if lock_path.is_file() else {}
    dependencies = lock.get("dependencies", {}) if isinstance(lock, dict) else {}
    declarations = manifest.get("dependencies", {}) if isinstance(manifest, dict) else {}
    observations = []
    for package_id in sorted(set(dependencies) | set(declarations)):
        pinned = dependencies.get(package_id, {})
        if not isinstance(pinned, dict):
            pinned = {}
        version = pinned.get("version") or declarations.get(package_id)
        source = pinned.get("source")
        fixed = bool(pinned and source in ("registry", "builtin") and isinstance(version, str) and
                     re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version))
        commit = pinned.get("hash")
        if source == "git":
            commit = commit or (version.rsplit("#", 1)[-1] if isinstance(version, str) else None)
            fixed = bool(commit and re.fullmatch(r"[0-9a-fA-F]{40}", commit))
        observations.append({"packageId": package_id, "version": version, "lockedVersion": version, "source": source,
                             "registryUrl": pinned.get("url"), "sourceSpecification": version,
                             "commit": commit, "lockPinned": fixed, "declaredOnly": not bool(pinned),
                             "targetPresent": False, "fingerprint": None})
    return observations, packages


def _directory_observations(directory, profile):
    observations, packages = _locks(directory)
    by_id = {o["packageId"]: o for o in observations}
    roots = []
    if (directory / "package.json").is_file():
        roots.append(directory)
    if packages.is_dir():
        roots.extend(child for child in packages.iterdir()
                     if child.is_dir() and not child.is_symlink() and (child / "package.json").is_file())
    # Lock metadata can be overridden by an embedded/local package. Read actual
    # bytes, including file: paths, before deciding whether provenance survives.
    for observation in observations:
        version = observation.get("version")
        if isinstance(version, str) and version.startswith("file:"):
            relative = version[5:]
            local = Path(relative) if Path(relative).is_absolute() else packages / relative
            if not local.is_dir():
                local = directory / relative
            if local.is_dir():
                roots.append(local)
    cache = directory / "Library" / "PackageCache"
    cache_roots = set()
    if cache.is_dir():
        cache_roots={child.resolve() for child in cache.iterdir() if child.is_dir() and not child.is_symlink() and (child / "package.json").is_file()}
        roots.extend(sorted(cache_roots))
    seen = set()
    for root in roots:
        resolved = root.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        metadata = _read_json(root / "package.json")
        package_id = metadata.get("name") if isinstance(metadata, dict) else None
        if not package_id:
            continue
        if resolved in cache_roots:
            active=by_id.get(package_id)
            # PackageCache can retain obsolete installations. It is evidence of
            # the current project only when the active lock selects this source
            # and version and no embedded/local package overrides it.
            if (not active or active.get("source")!="registry" or (active.get("targetPresent") and active.get("installationKind")!="cache") or
                    active.get("lockedVersion")!=metadata.get("version")):
                continue
        observation = dict(by_id.get(package_id, {"packageId": package_id, "lockPinned": False, "declaredOnly": True}))
        observation.update(version=metadata.get("version") or observation.get("version"),
                           targetPresent=True, installationKind="cache" if resolved in cache_roots else "embedded-or-local",
                           fingerprint=inventory_directory(root, profile))
        # Multiple installations of one package stay separate observations.
        if package_id in by_id and not by_id[package_id].get("targetPresent"):
            observations.remove(by_id[package_id])
        observations.append(observation)
        by_id[package_id] = observation
    return observations


def _input(path, profile):
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise ValueError("Input must not be a symbolic link or junction")
    if path.is_dir():
        if (path / "assemblies.json").is_file() and (path / "types.json").is_file():
            document = {"assemblies": _read_json(path / "assemblies.json"), "types": _read_json(path / "types.json")}
            fingerprint = _structure_fingerprint(document)
            fingerprint["inputSha256"] = _sha(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
            return fingerprint, "remaker-structure", []
        fingerprint = inventory_directory(path, profile)
        return fingerprint, "directory", _directory_observations(path, profile)
    if not path.is_file():
        raise ValueError("Input does not exist")
    data = path.read_bytes()
    fmt = _format(path)
    if fmt:
        return fingerprint_archive(data, fmt), "archive", []
    if path.suffix.lower() == ".dll":
        dummy = "dummydll" in str(path).replace("\\", "/").lower().split("/") or b"Il2CppDummyDll" in data
        fingerprint = fingerprint_binary(data,path.name)
        for file in fingerprint["files"]:
            file["dummyDll"]=bool(file.get("dummyDll") or dummy)
        return fingerprint, "dummy-dll" if dummy else "dll", []
    if path.suffix.lower() == ".json":
        if path.name.lower() in ("manifest.json", "packages-lock.json"):
            observations, _ = _locks(path.parent)
            fingerprint = _empty_fingerprint()
            fingerprint["inputSha256"] = _sha(data)
            # Include neighboring embedded target bytes even when entry is lock.
            return fingerprint, "unity-lock", _directory_observations(path.parent, profile)
        document = json.loads(data.decode("utf-8-sig"))
        fingerprint = _structure_fingerprint(document, path.parent)
        fingerprint["inputSha256"] = _sha(data)
        return fingerprint, "remaker-structure", []
    raise ValueError("Unsupported input; use directory, archive, DLL, Unity lock or ReMaker structure JSON")


def _candidate(package_id, version):
    return dict(version, packageId=package_id)


def _match_candidate(fingerprint, version, observation=None):
    target = (observation or {}).get("fingerprint") or fingerprint
    catalog_fp = version.get("fingerprint") or {}
    evidence, conflicts, scope = [], [], []
    target_sources, source_files = _source_map(target), _source_map(catalog_fp)
    identity = bool(observation)
    stated = observation.get("version") if observation else None
    # UPM Git refs/file paths are not semantic package versions.
    different_version = bool(stated and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", str(stated))
                             and stated != version.get("version"))
    if different_version:
        return None
    artifact = version.get("artifact") or {}
    artifact_equal = bool(target.get("artifactSha256") and target["artifactSha256"] == artifact.get("sha256"))
    source_equal = bool(target_sources and source_files and target_sources == source_files)
    dll_equal = []
    binary_files = [f for f in target.get("files", []) if f.get("path", "").lower().endswith(".dll") and not f.get("dummyDll")]
    catalog_binaries = [f for f in catalog_fp.get("files", []) if f.get("path", "").lower().endswith(".dll") and not f.get("dummyDll")]
    for file in binary_files:
        if any(file.get("sha256") == other.get("sha256") for other in catalog_binaries) or (
                artifact.get("format") == "dll" and file.get("sha256") == artifact.get("sha256")):
            dll_equal.append(file["path"])
    modified = bool(identity and observation.get("targetPresent") and source_files and target_sources != source_files)
    if modified:
        conflicts.append({"kind": "modified-or-incomplete-target", "basis": "actual-source-path-hash-set-differs",
                          "changed": sorted(p for p in source_files.keys() & target_sources.keys() if source_files[p] != target_sources[p]),
                          "missing": sorted(source_files.keys() - target_sources.keys()),
                          "extra": sorted(target_sources.keys() - source_files.keys())})
    if artifact_equal:
        evidence.append({"kind": "target-artifact-bytes-equal", "sha256": target["artifactSha256"]})
        scope.append({"kind": "artifact", "sha256": target["artifactSha256"]})
    if source_equal:
        evidence.append({"kind": "complete-source-path-hash-set-equal", "files": len(target_sources)})
        scope.extend({"kind": "source-file", "path": p} for p in sorted(target_sources))
    if dll_equal:
        evidence.append({"kind": "actual-dll-bytes-equal", "files": dll_equal})
        scope.extend({"kind": "binary-file", "path": p} for p in dll_equal)
    lock_conflict = bool(identity and observation.get("lockedVersion") and observation.get("lockedVersion") != stated
                         and not str(observation["lockedVersion"]).startswith(("file:", "git+", "http")))
    if (artifact_equal or source_equal or dll_equal) and not modified and not lock_conflict:
        return {"status": "exact-artifact", "evidence": evidence, "conflicts": conflicts, "scope": scope, "rank": 4}
    if identity:
        evidence.append({"kind": "package-identity-metadata", "version": stated})
        if lock_conflict:
            conflicts.append({"kind": "package-version-lock-conflict", "declaredVersion": stated,
                              "lockedVersion": observation["lockedVersion"]})
        if observation.get("lockPinned") and not observation.get("targetPresent"):
            # For Git, require the catalog's immutable ref to be the actual lock.
            commit = observation.get("commit")
            archive_verified = bool(re.fullmatch(r"[0-9a-f]{64}",str(artifact.get("sha256",""))) and
                                    version.get("fetchStatus") in ("collected","published","fetched"))
            source_verified = False
            if observation.get("source") == "registry":
                locked_registry=observation.get("registryUrl")
                known_registry=(version.get("upstream") or {}).get("registry")
                source_verified=bool(locked_registry and known_registry and
                                     locked_registry.rstrip("/")==known_registry.rstrip("/"))
            elif observation.get("source") == "git":
                specification=str(observation.get("sourceSpecification","")).removeprefix("git+")
                parsed=urllib.parse.urlsplit(specification)
                repository=urllib.parse.urlunsplit((parsed.scheme,parsed.netloc,parsed.path.removesuffix(".git"),"",""))
                package_path=urllib.parse.parse_qs(parsed.query).get("path",[None])[0]
                source_verified=bool(commit and version.get("sourceRef")==commit and
                                     repository==str(version.get("sourceUrl","")).removesuffix(".git") and
                                     (not package_path or package_path==version.get("sourcePath")))
            if archive_verified and source_verified and (not commit or version.get("sourceRef") == commit):
                evidence.append({"kind": "lock-pinned-source-provenance", "source": observation.get("source"), "commit": commit})
                return {"status": "pinned-source", "evidence": evidence, "conflicts": conflicts, "scope": [], "rank": 3}
            conflicts.append({"kind":"unverified-lock-provenance","archiveVerified":archive_verified,"sourceVerified":source_verified,
                              "reason":"Lock source must agree with immutable, actually fetched catalog provenance"})
    assemblies = _names(target.get("assemblies")) & _names(catalog_fp.get("assemblies"))
    types = _names(target.get("types"), "fullName") & _names(catalog_fp.get("types"), "fullName")
    namespaces = _names(target.get("namespaces")) & _names(catalog_fp.get("namespaces"))
    overlap = sorted(p for p in source_files.keys() & target_sources.keys() if source_files[p] == target_sources[p])
    if target_sources and source_files and not source_equal and not modified and (overlap or assemblies or types):
        conflicts.append({"kind": "modified-or-incomplete-source-set", "basis": "actual-source-path-hash-set-differs",
                          "changed": sorted(p for p in source_files.keys() & target_sources.keys() if source_files[p] != target_sources[p]),
                          "missing": sorted(source_files.keys() - target_sources.keys()),
                          "extra": sorted(target_sources.keys() - source_files.keys())})
    if assemblies:
        evidence.append({"kind": "assembly-name-clue", "names": sorted(assemblies)})
    if types:
        evidence.append({"kind": "type-declaration-clue", "names": sorted(types), "basis": target.get("declarationBasis")})
        # A declaration subset can result from trimming, merges or modifications.
        if _names(target.get("types"), "fullName") != _names(catalog_fp.get("types"), "fullName"):
            conflicts.append({"kind": "partial-or-modified-declarations", "reason": "type subsets do not authenticate implementation"})
    if namespaces:
        evidence.append({"kind": "namespace-weak-clue", "names": sorted(namespaces)})
    if overlap:
        evidence.append({"kind": "partial-source-bytes-equal", "files": overlap})
    if target.get("dummyDllObserved") or any(f.get("dummyDll") for f in target.get("files", [])):
        conflicts.append({"kind": "dummy-dll-not-original-binary", "reason": "generated DLL hashes cannot establish original artifact equality"})
    if not evidence:
        return None
    strong = identity or bool(assemblies and types) or bool(overlap)
    return {"status": "strong-candidate" if strong else "unknown", "evidence": evidence,
            "conflicts": conflicts, "scope": [], "rank": 2 if strong else 1}


def identify(input_path, catalog, profile=None) -> dict:
    fingerprint, kind, observations = _input(Path(input_path), profile)
    result = {"schemaVersion": "1.0", "catalogCommit": catalog.get("catalogCommit"),
              "fingerprintRegistry":catalog.get("fingerprintRegistry") or catalog.get("registry"),
              "input": {"kind": kind, "fingerprint": fingerprint}, "profile": profile,
              "matches": [], "unknown": [], "conflicts": []}
    observed_ids = {o["packageId"] for o in observations}
    catalog_ids = set()
    for package in catalog.get("packages", []):
        if not isinstance(package, dict) or not package.get("id"):
            continue
        package_id = package["id"]
        catalog_ids.add(package_id)
        package_observations = [o for o in observations if o["packageId"] == package_id]
        # A lock establishes only packages it names; source/metadata still may
        # identify unrelated assemblies from the complete input inventory.
        targets = package_observations or [None]
        candidates = []
        for version in package.get("versions", []):
            summary=version.get("fingerprint") or {}
            if summary.get("fileManifestRef"):
                eligible=bool(package_observations)
                relevant=[observation.get("fingerprint") or fingerprint for observation in targets if observation] or [fingerprint]
                for target in relevant:
                    hashes={item.get("sha256") for item in target.get("files",[]) if item.get("path","").lower().endswith(".dll")}
                    eligible=eligible or bool(target.get("artifactSha256") and target["artifactSha256"]==(version.get("artifact") or {}).get("sha256"))
                    eligible=eligible or bool(summary.get("sourceSetNonEmpty") and target.get("sourceSetSha256")==summary.get("sourceSetSha256"))
                    eligible=eligible or any(item.get("sha256") in hashes for item in summary.get("binaryFingerprints",[]))
                    eligible=eligible or bool(_names(target.get("assemblies"))&_names(summary.get("assemblies")) and _names(target.get("types"),"fullName")&_names(summary.get("types"),"fullName"))
                if eligible:
                    from .fingerprints import load_full_fingerprint
                    version={**version,"fingerprint":load_full_fingerprint(version,catalog)}
            found = [_match_candidate(fingerprint, version, observation) for observation in targets]
            found = [f for f in found if f]
            if found:
                best = max(found, key=lambda f: f["rank"])
                # A second conflicting installation must not be lost behind an
                # exact match for another installation of the same package.
                all_conflicts = [c for f in found for c in f["conflicts"]]
                best = dict(best, conflicts=all_conflicts)
                if any(c["kind"] == "modified-or-incomplete-target" for c in all_conflicts):
                    best.update(status="strong-candidate", rank=2, scope=[])
                candidates.append((_candidate(package_id, version), best))
        if not candidates:
            if package_id in observed_ids:
                result["unknown"].append({"packageId": package_id, "reason": "observed-version-not-in-catalog-or-no-evidence"})
            continue
        rank = max(match["rank"] for _, match in candidates)
        selected = [(candidate, match) for candidate, match in candidates if match["rank"] == rank]
        status = selected[0][1]["status"] if len(selected) == 1 else "ambiguous"
        evidence, conflicts, scope = [], [], []
        for candidate, match in selected:
            identity = {"version": candidate.get("version"), "variantId": candidate.get("variantId")}
            evidence.extend(dict(e, candidate=identity) for e in match["evidence"])
            conflicts.extend(dict(c, candidate=identity) for c in match["conflicts"])
            if len(selected) == 1:
                scope.extend(match["scope"])
        if len(selected) > 1:
            conflicts.append({"kind": "version-or-variant-ambiguity", "reason": "available evidence cannot uniquely select an immutable variant"})
        result["matches"].append({"packageId": package_id, "status": status,
                                  "candidates": [candidate for candidate, _ in selected],
                                  "evidence": evidence, "conflicts": conflicts,
                                  "suggestedReuseScope": scope, "skipNativeRecovery": False})
        if status == "unknown":
            result["unknown"].append({"packageId": package_id, "reason": "weak-clues-only"})
        result["conflicts"].extend(dict(c, packageId=package_id) for c in conflicts)
    for package_id in sorted(observed_ids - catalog_ids):
        result["unknown"].append({"packageId": package_id, "reason": "package-not-in-catalog"})
    if not result["matches"] and not result["unknown"]:
        result["unknown"].append({"reason": "no-package-evidence"})
    from .named_identity import fingerprint_pending, match_pending
    pending=fingerprint_pending(fingerprint,observations)
    if pending:
        result["namedPending"]=pending
        result["unknown"].extend({"reason":"named-origin-and-modification-unresolved",**item} for item in pending)
        target_families={item["familyId"] for item in pending}
        for match in result["matches"]:
            candidates={}
            for item in match_pending(package_id=match["packageId"]):candidates[item["familyId"]]=item
            for candidate in match["candidates"]:
                for item in fingerprint_pending(candidate.get("fingerprint") or {}):candidates[item["familyId"]]=item
            implicated=[item for family,item in candidates.items() if family in target_families]
            if implicated:
                match["status"]="origin-unresolved"
                conflict={"kind":"named-origin-and-modification-unresolved","families":implicated,"reason":"Public name or explicit selection does not establish original source or absence of project modifications"}
                match["conflicts"].append(conflict)
                result["conflicts"].append({"packageId":match["packageId"],**conflict})
    return result
