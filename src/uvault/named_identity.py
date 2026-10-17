"""Installed named-origin safeguards; a public catalog cannot erase a pending family."""
from __future__ import annotations
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from .curated import configuration


def pending_rules():
    return [entry for entry in configuration()["references"]
            if entry.get("identificationPending") and entry.get("resolutionStatus")=="origin-and-modification-pending"]


def rules_identity():
    raw=json.dumps(pending_rules(),sort_keys=True,ensure_ascii=False,separators=(",",":")).encode("utf-8")
    return {"rulesSha256":hashlib.sha256(raw).hexdigest(),"producerSha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def match_pending(assembly="",type_name="",package_id="",rules=None):
    matches=[]
    for entry in pending_rules() if rules is None else rules:
        rule=entry["identificationPending"]
        if (assembly in rule.get("assemblyNames",[]) or any(assembly.startswith(p) for p in rule.get("assemblyPrefixes",[]))
                or any(type_name.startswith(p) for p in rule.get("namespacePrefixes",[]))
                or any(package_id.startswith(p) for p in rule.get("packagePrefixes",[]))):
            matches.append({"familyId":entry["id"],"status":"origin-and-modification-pending","sourceStatus":"candidate-only" if entry.get("sourceUrl") else "unknown",
                            "mappingStatus":"unverified","modificationStatus":"unverified","automaticReplacementAllowed":False})
    return matches


def fingerprint_pending(fingerprint,observations=()):
    rules=pending_rules();found={}
    for row in fingerprint.get("assemblies",[]):
        name=row if isinstance(row,str) else row.get("name") or (row.get("scope") or {}).get("name","")
        for item in match_pending(assembly=name or "",rules=rules):found[item["familyId"]]=item
    for row in fingerprint.get("types",[]):
        name=row if isinstance(row,str) else row.get("fullName") or row.get("typeFullName","")
        for item in match_pending(type_name=name or "",rules=rules):found[item["familyId"]]=item
    for observation in observations:
        for item in match_pending(package_id=observation.get("packageId", ""),rules=rules):found[item["familyId"]]=item
        for item in fingerprint_pending(observation.get("fingerprint") or {}):found[item["familyId"]]=item
    return list(found.values())


def preserve_pending(document):
    """Recheck old matches/locks too; propagation alone would trust stale inputs."""
    source=document.get("input") or document.get("inputIdentity") or {}
    found={item["familyId"]:item for item in document.get("namedPending",[])}
    for item in fingerprint_pending(source.get("fingerprint") or {}):found[item["familyId"]]=item
    # Explicit distribution choice narrows acquisition, not observed identity.
    # Old inputs may carry the only named-origin clue in an unselected candidate.
    retained = [entry.get("match", {}) for entry in document.get("unselectedAlternatives", [])]
    retained.extend(document.get("unresolved", []))
    for match in retained:
        for row in [match, *match.get("candidates", [])]:
            for item in row.get("namedPending", []):found[item["familyId"]]=item
            for item in match_pending(package_id=row.get("packageId", match.get("packageId", ""))):found[item["familyId"]]=item
            for item in fingerprint_pending(row.get("fingerprint") or {}):found[item["familyId"]]=item
    for library in document.get("libraries",[]):
        affected={item["familyId"]:item for item in match_pending(package_id=library.get("packageId", ""))}
        for item in fingerprint_pending(library.get("fingerprint") or {}):affected[item["familyId"]]=item
        if not affected:continue
        if library.get("status")!="origin-unresolved":library.setdefault("observedMatchStatus",library.get("status","unknown"))
        if library.get("suggestedReuseScope"):
            library.setdefault("unverifiedSuggestedReuseScope",deepcopy(library["suggestedReuseScope"]))
        library.update(namedPending=list(affected.values()),status="origin-unresolved",skipNativeRecovery=False,
                       suggestedReuseScope=[],scopeUsageStatus="comparison-only-origin-and-differences-unresolved")
        for family,item in affected.items():found[family]=item
        conflict={"kind":"named-origin-and-modification-unresolved","families":list(affected.values())}
        if conflict not in library.setdefault("conflicts",[]):library["conflicts"].append(conflict)
        top={"packageId":library.get("packageId"),**conflict}
        if top not in document.setdefault("conflicts",[]):document["conflicts"].append(top)
    if found:
        document["namedPending"]=list(found.values())
        for item in found.values():
            unknown={"reason":"named-origin-and-modification-unresolved",**item}
            if unknown not in document.setdefault("unknown",[]):document["unknown"].append(unknown)
    return document
