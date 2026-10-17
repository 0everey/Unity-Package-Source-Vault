"""Finite Unity builtin-provider declaration rules; never an engine payload."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sysconfig
from collections import defaultdict
from pathlib import Path


_PROTECTED = {"modified", "project-wrapper", "game-business", "application-generated", "unknown", "mixed-owner"}


def _rules():
    locations = (Path(__file__).resolve().parents[2] / "sources" / "builtin-modules.json",
                 Path(sysconfig.get_path("data")) / "share" / "uvault" / "builtin-modules.json")
    for path in locations:
        if path.is_file():
            payload = path.read_bytes()
            return json.loads(payload.decode("utf-8-sig")), hashlib.sha256(payload).hexdigest()
    raise ValueError("Installed builtin-modules.json reference rules are missing")


def rules_identity():
    rules, digest = _rules()
    return {"version": rules["ruleVersion"], "rulesSha256": digest,
            "producerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def package_records() -> list:
    """Return reference-only package records, with no fabricated Unity artifact."""
    rules, digest = _rules()
    packages = []
    for module in rules["modules"]:
        features = module["apiFeatures"]
        members=module.get("memberFeatures",[])
        types=sorted({feature["typeFullName"] for feature in features+members})
        version = {"version": module["moduleVersion"], "moduleVersion": module["moduleVersion"],
                   "unityVersion": "unknown", "referenceUnityVersions": rules["referenceUnityVersions"],
                   "variantId": "unity-builtin-reference", "disposition": "builtin-reference",
                   "sourceUrl": module["manualUrl"], "sourceRef": None, "downloadUrl": None,
                   "artifact": None, "fetchStatus": "reference-only", "dependencies": {},
                   "license": {"expression": "Unity-Engine-License", "evidenceUrl": "https://unity.com/legal/terms-of-service/software",
                               "sha256": None, "components": [], "redistribution": "no-payload-reference-only"},
                   "provider": {"kind": "unity-builtin-module", "assemblyName": module["assemblyName"],
                                "referenceStatus": "reference-pending", "installationUrl": rules["installationUrl"],
                                "manualUrl": module["manualUrl"], "apiFeatures": copy.deepcopy(features),
                                "memberFeatures":copy.deepcopy(members),"recognitionMode":module.get("recognitionMode","multiple-api-types"),
                                "namespaceScopes": module["namespaceScopes"], "rulesSha256": digest,
                                "profileVerified": False},
                   "fingerprint": {"files": [], "assemblies": [{"name": module["assemblyName"], "version": rules["assemblyVersion"]}],
                                   "types": types,
                                   "typeDeclarations": [{"fullName": name, "assemblyIdentity": {"name": module["assemblyName"]},
                                                         "ownershipVerified": True, "profileVerified": False} for name in types],
                                   "namespaces": module["namespaceScopes"], "profileVerified": False,
                                   "declarationBasis": "official-module-api-reference-features-not-target-byte-equality"}}
        packages.append({"schemaVersion": "1.0", "id": module["id"], "displayName": module["displayName"],
                         "sources": [{"kind": "unity-builtin-reference", "url": module["manualUrl"]}], "versions": [version]})
    return packages


def _protected(declaration):
    identity = declaration.get("assemblyIdentity") or {}
    return (declaration.get("category") in _PROTECTED or declaration.get("modified") is True
            or declaration.get("isModified") is True or declaration.get("ownershipVerified") is False
            or identity.get("ownershipVerified") is False or not isinstance(declaration.get("evidenceRefs"), list)
            or not declaration.get("evidenceRefs"))


def _scope(type_name, scopes):
    return next((scope for scope in scopes if type_name.startswith(scope + ".")), None)


def _owner(declaration):
    owner = declaration.get("owner") or {}
    identifier = owner.get("declarationId") or declaration.get("ownerDeclarationId")
    verified = owner.get("verified") is True or declaration.get("ownerVerified") is True
    evidence = owner.get("evidenceRefs") or declaration.get("ownerEvidenceRefs")
    return identifier if verified and evidence else None


def _type_identity(value):
    aliases={"string":"System.String","object":"System.Object","bool":"System.Boolean","int":"System.Int32",
             "byte[]":"System.Byte[]","Type":"System.Type","Texture2D":"UnityEngine.Texture2D"}
    value=value.strip().removeprefix("global::")
    return aliases.get(value,value)


def _public_member_matches(declaration,feature):
    if declaration.get("typeFullName")!=feature["typeFullName"]:return False
    signature=declaration.get("memberSignature","")
    # A single complete public static method declaration, not a method-name hit.
    match=re.fullmatch(r"public\s+static\s+([\w.\[\]:]+)\s+([A-Za-z_]\w*)\s*\(([^()]*)\)\s*(?:\{\s*\}|;)?",signature.strip())
    if not match or match.group(2)!=feature["name"] or _type_identity(match.group(1))!=feature["returnType"]:return False
    parameters=[]
    for value in match.group(3).split(",") if match.group(3).strip() else []:
        parameter=re.fullmatch(r"\s*([\w.\[\]:]+)\s+[A-Za-z_]\w*\s*",value)
        if not parameter:return False
        parameters.append(_type_identity(parameter.group(1)))
    return parameters==feature["parameterTypes"]


def detect_providers(inventory, profile=None) -> dict:
    """Map confirmed original declaration IDs to builtin provider proof.

    Exact finite module identity and multiple distinct, assembly-scoped official
    API types establish provider identity. Registered namespace scopes then
    delimit provider declarations. Installation/profile remain unverified.
    """
    if (not isinstance(inventory, dict) or inventory.get("schemaVersion") != "1.0"
            or not isinstance(inventory.get("declarations"), list)
            or any(not isinstance(declaration, dict) for declaration in inventory["declarations"])):
        raise ValueError("Builtin detection requires an original declaration inventory")
    declarations = inventory["declarations"]
    identifiers = [declaration.get("id") for declaration in declarations]
    complete = inventory.get("completeScope") or {}
    if (not isinstance(complete, dict) or complete.get("complete") is not True
            or isinstance(complete.get("declarationCount"), bool)
            or complete.get("declarationCount") != len(identifiers)
            or any(not isinstance(identifier, str) or not identifier for identifier in identifiers)
            or len(identifiers) != len(set(identifiers))
            or not isinstance(complete.get("declarationIds"), list)
            or len(complete["declarationIds"]) != len(identifiers)
            or any(not isinstance(identifier, str) for identifier in complete["declarationIds"])
            or set(complete["declarationIds"]) != set(identifiers)):
        raise ValueError("Builtin detection requires the complete, unique original declaration scope")
    for field in ("targetId", "dumpSha256", "inputSha256"):
        if not isinstance(inventory.get(field), str) or not inventory[field]:
            raise ValueError("Builtin detection requires original " + field)
        if field.endswith("Sha256") and not re.fullmatch(r"[0-9a-fA-F]{64}", inventory[field]):
            raise ValueError("Builtin detection requires original SHA256 identity")
    if profile is not None and not isinstance(profile, dict):
        raise ValueError("profile must be an object or null")
    rules, digest = _rules()
    modules = {module["assemblyName"]: module for module in rules["modules"]}
    groups = defaultdict(list)
    by_id = {declaration["id"]: declaration for declaration in declarations}
    for declaration in declarations:
        identity = declaration.get("assemblyIdentity") or {}
        name = identity.get("name")
        if name not in modules or _protected(declaration):
            continue
        # Supplied full identity conflicts are contrary evidence. No broad
        # UnityEngine.* DLL-name prefix rule is used.
        if identity.get("version") not in (None, rules["assemblyVersion"]):
            continue
        if identity.get("culture") not in (None, "", "neutral") or identity.get("publicKeyToken") not in (None, "", "null"):
            continue
        # Keep complete identities separate even when their names agree.
        groups[json.dumps(identity, sort_keys=True, separators=(",", ":"))].append(declaration)
    detected = {}
    for group in groups.values():
        identity = group[0]["assemblyIdentity"]
        module = modules[identity["name"]]
        observed_types = {declaration.get("typeFullName") for declaration in group if declaration.get("category") != "compiler-generated"}
        features = [feature for feature in module["apiFeatures"] if feature["typeFullName"] in observed_types]
        singleton=module.get("recognitionMode")=="single-type-two-public-members"
        matched_members=[]
        if singleton:
            # Only the two finite single-public-type engine modules use this
            # exception. Other modules retain the global two-type minimum.
            if module["assemblyName"] not in ("UnityEngine.JSONSerializeModule","UnityEngine.ImageConversionModule"):continue
            matched_members=[feature for feature in module.get("memberFeatures",[])
                             if any(d.get("category")!="compiler-generated" and _public_member_matches(d,feature) for d in group)]
            if len({f["name"] for f in matched_members})<2:continue
        elif len(features) < rules["minimumDistinctApiTypes"]:
            continue
        unity_version = (profile or {}).get("unityVersion") or "unknown"
        proof = {"kind": "unity-builtin-module", "moduleId": module["id"], "moduleVersion": module["moduleVersion"],
                 "assemblyName": module["assemblyName"], "assemblyIdentity": copy.deepcopy(identity),
                 "matchedApiTypes": sorted({feature["typeFullName"] for feature in features+matched_members}),
                 "matchedPublicMembers":copy.deepcopy(matched_members),
                 "recognitionScope":"exact-type" if singleton else "registered-namespaces",
                 "apiEvidenceUrls": [feature["url"] for feature in features+matched_members],
                 "manualUrl": module["manualUrl"], "installationUrl": rules["installationUrl"],
                 "referenceUnityVersions": rules["referenceUnityVersions"], "unityVersion": unity_version,
                 "unityVersionStatus": "unknown" if unity_version == "unknown" else "reported-unverified",
                 "installationStatus": "unverified", "referenceStatus": "reference-pending", "profileVerified": False,
                 "rulesSha256": digest,
                 "identityBasis": "complete-original-metadata-exact-module-and-two-public-signatures" if singleton else "complete-original-metadata-exact-module-plus-multiple-official-api-types",
                 "targetId": inventory["targetId"], "dumpSha256": inventory["dumpSha256"], "inputSha256": inventory["inputSha256"]}
        for declaration in group:
            namespace_scope = (module["exactType"] if declaration.get("typeFullName")==module["exactType"] else None) if singleton else _scope(declaration.get("typeFullName", ""), module["namespaceScopes"])
            if namespace_scope and declaration.get("category") != "compiler-generated":
                detected[declaration["id"]] = dict(proof, namespaceScope=namespace_scope)
    # Generated declarations follow a verified actual provider owner only; a
    # namespace-looking state machine with no owner stays eligible for native.
    pending = [d for d in declarations if d.get("category") == "compiler-generated" and not _protected(d)]
    while pending:
        remaining, progressed = [], False
        for declaration in pending:
            owner_id = _owner(declaration)
            proof = detected.get(owner_id)
            identity = declaration.get("assemblyIdentity") or {}
            if proof is not None and identity == proof["assemblyIdentity"]:
                module = modules[proof["assemblyName"]]
                namespace_scope = _scope(declaration.get("typeFullName", ""), module["namespaceScopes"])
                if namespace_scope and module.get("recognitionMode")!="single-type-two-public-members":
                    detected[declaration["id"]] = dict(proof, namespaceScope=namespace_scope, generatedOwnerId=owner_id)
                    progressed = True
                    continue
            if owner_id in by_id and by_id[owner_id].get("category") == "compiler-generated":
                remaining.append(declaration)
        if not progressed:
            break
        pending = remaining
    return detected
