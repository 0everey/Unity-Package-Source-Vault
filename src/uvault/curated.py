"""R4 common packages: bounded current catalog, explicit gaps, no ecosystem crawl."""
from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path
import sys

def configuration():
    local=Path(__file__).resolve().parents[2]/"sources"/"common-packages.json"
    path=local if local.is_file() else Path(sys.prefix)/"share"/"uvault"/"common-packages.json"
    return json.loads(path.read_text(encoding="utf-8-sig"))

def seeds():
    config=configuration();result=[]
    for entry in config["packages"]:
        item=deepcopy(entry)
        item.setdefault("adapter","registry");item.setdefault("registry","https://packages.unity.com")
        item.update(schemaVersion="1.0",family="common-"+entry["category"],metadataStatus="pending",versions=[],curatedPolicy={
            "scopeVersion":"R4","versionCount":2,"maxCommonVersions":3,
            "preferredVersions":entry.get("preferredVersions",[]),"legacyMajor":entry.get("legacyMajor"),
            "retainVerifiedLegacy":entry.get("retainVerifiedLegacy",False), "commonArchiveFallback":entry.get("commonArchiveFallback",False)})
        result.append(item)
    for entry in config["references"]:
        reference=deepcopy(entry)
        reference.update(schemaVersion="1.0",displayName=entry["id"],adapter="reference",metadataStatus="reference-only",selectedVersions=[])
        reference.setdefault("family","restricted-reference")
        reference.setdefault("versions",[])
        reference.setdefault("sources",[{"kind":"official-reference","url":entry["sourceUrl"]}] if entry.get("sourceUrl") else [])
        reference.setdefault("disposition","official-fetch-only")
        result.append(reference)
    from .builtin import package_records
    for package in package_records():
        package.update(adapter="reference", family="unity-builtin", metadataStatus="reference-only", selectedVersions=[])
        result.append(package)
    return result

def choose_versions(versions,policy,requests=()):
    from .sources import version_key,_is_prerelease
    by_name={v["version"]:v for v in versions}
    stable=sorted((v for v in by_name if not _is_prerelease(v)),key=version_key,reverse=True)
    ordered=stable or sorted(by_name,key=version_key,reverse=True)
    selected=[]
    def add(version):
        if version in by_name and version not in selected:selected.append(version)
    for version in policy.get("preferredVersions",[]):add(version)
    # These are explicit actual gaps, not historical dependency expansion.
    for request in requests:
        if not request.get("reason"):raise ValueError("An actual version gap requires a reason")
        add(request["version"])
    if ordered:
        preferred_major=version_key(selected[0])[1][0] if selected else None
        compatible=[v for v in ordered if preferred_major is None or version_key(v)[1][0]==preferred_major]
        if compatible and len(selected)<policy.get("versionCount",2):add(compatible[0])
        for version in compatible+ordered:
            if len(selected)>=policy.get("versionCount",2):break
            add(version)
    legacy=policy.get("legacyMajor")
    if legacy is not None and len(selected)<policy.get("maxCommonVersions",3):
        add(next((v for v in ordered if version_key(v)[1][0]==legacy),None))
    if policy.get("retainVerifiedLegacy") and len(selected)<3:
        retained=sorted((v["version"] for v in versions if v.get("fetchStatus")=="published" and v["version"] not in selected),key=version_key,reverse=True)
        if retained:add(retained[0])
    if policy.get("commonArchiveFallback") and len(selected)<3:
        add(next((v for v in ordered if by_name[v].get("downloadUrl")), None))
    if len(selected)>policy.get("maxCommonVersions",3):
        raise ValueError("More than three requested versions requires explicitly revising this package's common-version budget")
    return [v for v in versions if v["version"] in selected]

def curate_package(package,seed):
    policy=seed.get("curatedPolicy")
    if not policy:return package
    package=deepcopy(package)
    # Preserve successful immutable records selected again after a metadata refresh.
    old={(v["version"],v["variantId"]):v for v in seed.get("versions",[])}
    for index,version in enumerate(package.get("versions",[])):
        previous=old.get((version["version"],version["variantId"]))
        immutable_same=previous and all(previous.get(key)==version.get(key) for key in ("upstreamShasum","upstreamIntegrity","downloadUrl"))
        if previous and previous.get("artifact") and immutable_same:
            package["versions"][index]=deepcopy(previous)
    package["availableUpstreamVersionCount"]=len({v["version"] for v in package.get("versions",[])})
    package["versions"]=choose_versions(package.get("versions",[]),policy,seed.get("explicitVersionRequests",[]))
    package["curatedPolicy"]=deepcopy(policy)
    package["explicitVersionRequests"]=deepcopy(seed.get("explicitVersionRequests",[]))
    package["selectedVersions"]=sorted({v["version"] for v in package["versions"]})
    package["targetVersions"]=[]
    package.pop("versionRequests",None)
    package["missingTargetVersions"]=[r["version"] for r in seed.get("explicitVersionRequests",[]) if r["version"] not in package["selectedVersions"]]
    package["missingPreferredVersions"]=[v for v in policy.get("preferredVersions",[]) if v not in package["selectedVersions"]]
    for key in ("manifestReferences", "category", "integrationNote", "componentBundle", "coverageBasis", "priority"):
        if key in seed: package[key]=deepcopy(seed[key])
    package["versionPolicy"]="R4: two common versions; at most three including a justified gap/legacy"
    return package

def queue(existing=None):
    from .sources import utc_now
    old={p["id"]:p for p in (existing or {}).get("packages",[])}
    packages=[]
    for seed in seeds():
        previous=old.get(seed["id"])
        if seed["adapter"]=="reference" or previous is None:
            packages.append(seed);continue
        # Correct registry/source configuration before reusing source records.
        source_keys=("adapter","registry") if seed["adapter"]=="registry" else ("adapter","repository") if seed["adapter"]=="github" else ("adapter",)
        same_source=all(seed.get(key)==previous.get(key) for key in source_keys)
        if not same_source:
            seed["explicitVersionRequests"]=deepcopy(previous.get("explicitVersionRequests",[]))
            packages.append(seed);continue
        # Explicit consumer intent and immutable successes survive interrupted or
        # failed metadata refreshes. Curating is not a reset of pending work.
        retained={**deepcopy(previous),**seed,"versions":previous.get("versions",[]),
                  "metadataStatus":previous.get("metadataStatus","pending"),
                  "explicitVersionRequests":deepcopy(previous.get("explicitVersionRequests",[]))}
        packages.append(curate_package(retained,retained))
        for key in ("family","category","integrationNote"):
            if key in seed:packages[-1][key]=seed[key]
    return {"schemaVersion":"1.0","scopeVersion":"R4","requirementRevision":configuration().get("requirementRevision","R4"),"scope":"Common Unity builtin providers and explicitly listed common packages; two or three versions per family",
            "createdAt":utc_now(),"completeEnumeration":True,"enumerationMeaning":"Complete current common whitelist, not an ecosystem enumeration",
            "snapshots":[{"source":"common-packages.json","scopeVersion":"R4","configuredPackageFamilies":len(configuration()["packages"]),"discoveredAt":utc_now()}],
            "packages":packages,"frontier":[],"compatibilitySetDefinitions":deepcopy(configuration().get("compatibilitySetDefinitions",[]))}

def compatibility_sets(state):
    """Verify declared member edges and expose exact shared gaps, never install."""
    by_id={p["id"]:p for p in state["packages"]}
    result=[]
    for definition in state.get("compatibilitySetDefinitions",[]):
        members=definition["members"];declarations=[];gaps=[];conflicts=[];missing=[]
        for pid,version in members.items():
            records=[v for v in by_id.get(pid,{}).get("versions",[]) if v["version"]==version]
            if not records:missing.append({"packageId":pid,"version":version});continue
            variants={json.dumps(v.get("dependencies",{}),sort_keys=True) for v in records}
            if len(variants)>1:conflicts.append({"packageId":pid,"version":version,"reason":"variant-dependency-disagreement"})
            for record in records:
                declarations.append({"packageId":pid,"version":version,"variantId":record["variantId"],"unity":record.get("unity"),
                                     "metadataUrl":record.get("metadataUrl"),"dependencies":deepcopy(record.get("dependencies",{}))})
                for dep,spec in record.get("dependencies",{}).items():
                    if dep in members:
                        if members[dep]!=spec:conflicts.append({"packageId":pid,"dependency":dep,"declared":spec,"groupVersion":members[dep]})
                    elif spec not in {v["version"] for v in by_id.get(dep,{}).get("versions",[])}:
                        gap={"packageId":dep,"version":spec,"requiredBy":pid,"reason":"exact-declared-dependency-not-in-current-catalog","automaticSubstitution":False}
                        if gap not in gaps:gaps.append(gap)
        result.append({**deepcopy(definition),"status":"member-declaration-conflict" if conflicts else "member-metadata-pending" if missing else "member-declarations-verified",
                       "profileVerified":False,"installed":False,"compiled":False,"declarations":declarations,"missingMembers":missing,"memberConflicts":conflicts,"exactDependencyGaps":gaps})
    return result

def prune_catalog(root,state):
    """Retire only this task's unreferenced generated metadata; Git history stays."""
    from .pipeline import shard_name
    root=Path(root).resolve()
    active={str((root/shard_name(p["id"])).resolve()) for p in state["packages"]}
    removed=0
    directory=root/"packages"
    if directory.is_dir():
        for path in directory.glob("*.json"):
            if path.is_symlink() or path.resolve().parent!=directory.resolve():raise ValueError("Unsafe generated catalog path")
            if str(path.resolve()) not in active:path.unlink();removed+=1
    index=json.loads((root/"catalog.json").read_text(encoding="utf-8-sig"))
    metadata_paths={str((root/b["path"]).resolve()) for b in index.get("bundles",[])}
    for package in state["packages"]:
        for version in package.get("versions",[]):
            ref=(version.get("fingerprint") or {}).get("fileManifestRef")
            if ref:metadata_paths.add(str((root/ref["path"]).resolve()))
    # Only generated, content-addressed metadata under this exact catalog.
    for directory, pattern in ((root,"lookup-*.json.gz"),(root/"fingerprints","*.json.gz")):
        if not directory.is_dir():continue
        if directory.is_symlink() or directory.resolve().parent not in (root,root.parent):
            raise ValueError("Unsafe generated metadata directory")
        for path in directory.glob(pattern):
            if path.is_symlink() or path.resolve().parent!=directory.resolve():raise ValueError("Unsafe generated metadata path")
            if str(path.resolve()) not in metadata_paths:path.unlink();removed+=1
    return removed

def add_gap(state, package_id, version, reason):
    if not reason.strip() or not version.strip():
        raise ValueError("A named version gap requires package, version and a concrete reason")
    package = next((p for p in state["packages"] if p["id"] == package_id), None)
    if not package or not package.get("curatedPolicy"):
        raise ValueError("Add a new common family to sources/common-packages.json explicitly before requesting its version")
    requests = deepcopy(package.get("explicitVersionRequests", []))
    request = {"version": version, "reason": reason.strip()}
    if request not in requests:
        requests.append(request)
    if len({r["version"] for r in requests} | set(package["curatedPolicy"].get("preferredVersions", []))) > 3:
        raise ValueError("More than three explicit versions exceeds the common package scope")
    package["explicitVersionRequests"] = requests
    package["metadataStatus"] = "pending"
    return package
