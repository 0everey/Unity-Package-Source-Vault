"""Official family clues, deliberately separate from versioned source adoption."""
from __future__ import annotations
from collections import defaultdict
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sysconfig


CONTEXT_FIELDS = ("knownFamilies", "familyHints", "missingVersionRequests")


def _rules():
    paths=(Path(__file__).resolve().parents[2]/"sources"/"family-references.json",
           Path(sysconfig.get_path("data"))/"share"/"uvault"/"family-references.json")
    for path in paths:
        if path.is_file():
            raw=path.read_bytes()
            return json.loads(raw.decode("utf-8-sig")),hashlib.sha256(raw).hexdigest()
    raise ValueError("Installed official family-reference rules are missing")


def rules_identity():
    rules,digest=_rules()
    return {"version":rules["ruleVersion"],"rulesSha256":digest,
            "producerSha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def reference_catalog():
    rules,digest=_rules()
    return {"ruleVersion":rules["ruleVersion"],"rulesSha256":digest,
            "references":deepcopy(rules["references"]),"sources":deepcopy(rules["sources"])}


def _identity(value):
    scope=value.get("scope") or value.get("assemblyIdentity") or value
    if not isinstance(scope,dict) or not scope.get("name"):
        return None
    return {key:deepcopy(scope[key]) for key in ("name","version","culture","publicKeyToken","ownershipVerified") if key in scope}


def _match(groups):
    rules,digest=_rules()
    found=[]
    for identity,types,ids in groups:
        name=identity["name"]
        for rule in rules["references"]:
            qualified={f["fullName"] for f in rule["typeFeatures"] if f.get("fullName")}
            observed=qualified & types
            bindings=rule.get("assemblyTypeBindings",[])
            bound={b["typeFullName"] for b in bindings if b["assemblyName"]==name and b["typeFullName"] in observed}
            contrary={typ for typ in observed if any(b["typeFullName"]==typ for b in bindings) and typ not in bound}
            unbound=observed-contrary
            simple_features={f["apiName"] for f in rule["typeFeatures"] if not f.get("fullName") and f.get("apiName")}
            simple={typ for typ in types if typ.rsplit(".",1)[-1] in simple_features}
            if bound:
                status="official-assembly-api-clue";matched=bound
            elif len(unbound)>=2:
                status="same-input-assembly-api-pair-clue";matched=unbound
            elif observed:
                status="reference-attribution-differs" if contrary else "single-qualified-api-clue";matched=observed
            elif len({typ.rsplit(".",1)[-1] for typ in simple})>=2:
                status="weak-simple-api-names-only";matched=simple
            else:
                continue
            if identity.get("ownershipVerified") is False:
                status="ownership-unverified-api-clue"
            feature_refs={s for f in rule["typeFeatures"] if f.get("fullName") in matched or f.get("apiName") in {t.rsplit(".",1)[-1] for t in matched} for s in f["sourceRefs"]}
            binding_refs={s for b in bindings if b["assemblyName"]==name and b["typeFullName"] in bound for s in b["sourceRefs"]}
            version_refs={s for hint in rule.get("versionHints",[]) for s in hint.get("sourceRefs",[])}
            selected_sources=feature_refs|binding_refs|version_refs
            row={"familyId":rule["familyId"],"displayName":rule["displayName"],"status":status,
                 "assemblyIdentity":deepcopy(identity),"matchedTypes":sorted(matched),
                 "assemblyTypeBindings":[deepcopy(b) for b in bindings if b["assemblyName"]==name and b["typeFullName"] in bound],
                 "sourceRefs":[deepcopy(s) for s in rules["sources"] if s["id"] in selected_sources],
                 "versionHints":deepcopy(rule.get("versionHints",[])),"acquisition":deepcopy(rule["acquisition"]),
                 "unknowns":deepcopy(rule.get("unknowns",[])),"generation":rule.get("generation"),
                 "packageVersion":None,"targetVersionConfirmed":False,"targetBytesVerified":False,
                 "sourceEquivalenceVerified":False,"profileVerified":False,"automaticNativeExclusionAuthorized":False,
                 "rulesSha256":digest}
            if contrary:
                row["referenceAttributionDifferences"]=sorted(contrary)
            for key in ("componentObservations", "componentDependencyObservation"):
                if key in rule:row[key]=deepcopy(rule[key])
            found.append((row,{identifier for typ in matched for identifier in ids.get(typ,[])}))
    return found


def detect_inventory(inventory):
    groups={}
    for declaration in inventory.get("declarations",[]):
        identity=_identity(declaration.get("assemblyIdentity") or {})
        if not identity:continue
        key=json.dumps(identity,sort_keys=True,separators=(",",":"))
        if key not in groups:groups[key]=(identity,set(),defaultdict(list))
        groups[key][1].add(declaration["typeFullName"])
        groups[key][2][declaration["typeFullName"]].append(declaration["id"])
    rows=defaultdict(list)
    for reference,identifiers in _match(groups.values()):
        for identifier in identifiers:rows[identifier].append(deepcopy(reference))
    return dict(rows)


def detect_fingerprint(fingerprint):
    groups={};assemblies={}
    def add(identity,typ):
        identity=_identity(identity or {})
        if not identity or not isinstance(typ,str) or not typ:return
        key=json.dumps(identity,sort_keys=True,separators=(",",":"))
        if key not in groups:groups[key]=(identity,set(),{})
        groups[key][1].add(typ)
    for assembly in fingerprint.get("assemblies",[]):
        if not isinstance(assembly,dict):continue
        if assembly.get("id"):assemblies[assembly["id"]]=assembly
        for typ in assembly.get("types",[]):
            add(assembly,typ if isinstance(typ,str) else typ.get("fullName") or typ.get("typeFullName"))
    for record in fingerprint.get("managedMetadata",[]):
        if record.get("metadataStatus")!="managed":continue
        for typ in record.get("types",[]):
            add(record.get("assemblyIdentity"),typ if isinstance(typ,str) else typ.get("fullName"))
    for typ in fingerprint.get("typeDeclarations",[]):
        owner=typ.get("assemblyIdentity") or typ.get("assembly") or assemblies.get(typ.get("assemblyId"))
        if isinstance(owner,str):owner={"name":owner}
        add(owner,typ.get("fullName") or typ.get("typeFullName"))
    rows=[];seen=set()
    for row,_ in _match(groups.values()):
        key=json.dumps(row,sort_keys=True,separators=(",",":"))
        if key not in seen:rows.append(row);seen.add(key)
    return rows


def preserve_context(document):
    """Old locks cannot hide unresolved family/version facts by clearing status."""
    for family in document.get("knownFamilies",[]):
        unknown={"reason":"official-family-clue-version-and-source-unresolved","familyId":family.get("familyId"),
                 "assemblyIdentity":deepcopy(family.get("assemblyIdentity")),"status":family.get("status")}
        if unknown not in document.setdefault("unknown",[]):document["unknown"].append(unknown)
    for request in document.get("missingVersionRequests",[]):
        if any(item.get("packageId")==request.get("packageId") and item.get("reason")=="observed-version-not-in-catalog-or-no-evidence"
               for item in document.get("unknown",[]) if isinstance(item,dict)):
            continue
        unknown={"reason":"observed-package-version-not-collected","request":deepcopy(request)}
        if unknown not in document.setdefault("unknown",[]):document["unknown"].append(unknown)
    return document
