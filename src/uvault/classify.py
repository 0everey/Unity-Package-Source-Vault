"""Cheap declaration routing proposals, before native recovery work begins.

The original metadata/Core writer owns input authenticity and final selection.
This module conserves the supplied complete declaration inventory and does not
decode IL2CPP, adopt sources, execute generators, or authenticate a Core workset.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from .builtin import detect_providers, rules_identity
from .named_identity import match_pending, pending_rules, rules_identity as named_rules_identity


ACTIONS = ("recover-native", "provider-reference", "reuse-upstream", "skip-native",
           "defer-library-resolution", "regenerate")
PROTECTED = {"modified", "project-wrapper", "game-business", "application-generated", "unknown", "mixed-owner"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value, field):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError(field + " must be a SHA256 hexadecimal string")
    return value.lower()


def _identity(declaration):
    return {"assemblyIdentity": declaration["assemblyIdentity"],
            "typeFullName": declaration["typeFullName"], "memberSignature": declaration["memberSignature"]}


def _assembly(value):
    if isinstance(value, str):
        return {"name": value}
    if not isinstance(value, dict):
        return {}
    return value.get("assemblyIdentity") or value.get("scope") or value


def _same_assembly(actual, expected, exact=False):
    actual, expected = _assembly(actual), _assembly(expected)
    if not actual.get("name") or actual.get("name") != expected.get("name"):
        return False
    if exact:
        return _canonical(actual) == _canonical(expected)
    # Catalog sources need not invent an AssemblyVersion. Every actually supplied
    # identity component must agree; a conflict cannot be hidden by the name.
    for field in ("version", "culture", "publicKeyToken"):
        if expected.get(field) is not None and actual.get(field) != expected[field]:
            return False
    return True


def _address(value):
    if value in (None, "", 0, "0", "0x0"):
        return None
    if isinstance(value, bool):
        raise ValueError("nativeAddress must not be boolean")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("nativeAddress must not be negative")
        return hex(value)
    if isinstance(value, str):
        try:
            number = int(value, 16 if value.lower().startswith("0x") else 10)
            if number < 0:
                raise ValueError()
            return hex(number) if number else None
        except ValueError:
            raise ValueError("nativeAddress must be an integer or hexadecimal address") from None
    raise ValueError("Unsupported nativeAddress")


def _validate(inventory):
    if not isinstance(inventory, dict) or str(inventory.get("schemaVersion")) != "1.0":
        raise ValueError("Expected normalized declaration inventory schemaVersion 1.0")
    if not isinstance(inventory.get("targetId"), str) or not inventory["targetId"].strip():
        raise ValueError("Inventory targetId is required")
    _digest(inventory.get("dumpSha256"), "dumpSha256")
    _digest(inventory.get("inputSha256"), "inputSha256")
    declarations = inventory.get("declarations")
    if not isinstance(declarations, list):
        raise ValueError("Inventory declarations must be a list")
    by_id = {}
    for declaration in declarations:
        if not isinstance(declaration, dict) or not isinstance(declaration.get("id"), str) or not declaration["id"]:
            raise ValueError("Every declaration requires a nonempty string id")
        if declaration["id"] in by_id:
            raise ValueError("Duplicate declaration id: " + declaration["id"])
        if not isinstance(declaration.get("assemblyIdentity"), dict) or not declaration["assemblyIdentity"].get("name"):
            raise ValueError("Every declaration requires its actual assemblyIdentity")
        for field in ("typeFullName", "memberSignature"):
            if not isinstance(declaration.get(field), str) or not declaration[field]:
                raise ValueError("Every declaration requires " + field)
        if not isinstance(declaration.get("evidenceRefs", []), list):
            raise ValueError("evidenceRefs must be a list")
        if not isinstance(declaration.get("aliases", []), list):
            raise ValueError("aliases must be a list")
        _address(declaration.get("nativeAddress"))
        by_id[declaration["id"]] = declaration
    complete = inventory.get("completeScope")
    if not isinstance(complete, dict) or complete.get("complete") is not True:
        raise ValueError("completeScope must explicitly describe the complete original declaration inventory")
    expected = complete.get("declarationIds")
    if not isinstance(expected, list) or any(not isinstance(x, str) or not x for x in expected) or len(expected) != len(set(expected)):
        raise ValueError("completeScope.declarationIds must list unique original ids")
    if isinstance(complete.get("declarationCount"), bool) or complete.get("declarationCount") != len(expected) or set(expected) != set(by_id):
        raise ValueError("Missing, extra or partial declarations relative to complete original scope")
    external = {}
    for declaration in declarations:
        seen = set()
        for alias in declaration.get("aliases", []):
            if isinstance(alias, str):
                alias_id, alias_address = alias, None
            elif isinstance(alias, dict):
                alias_id = alias.get("id") or alias.get("declarationId") or alias.get("methodId")
                alias_address = _address(alias.get("nativeAddress"))
            else:
                raise ValueError("Alias requires an id or a scoped alias record")
            if not isinstance(alias_id, str) or not alias_id or alias_id in seen or alias_id == declaration["id"]:
                raise ValueError("Empty, duplicate or self alias reference")
            seen.add(alias_id)
            actual = _address(by_id[alias_id].get("nativeAddress")) if alias_id in by_id else None
            owner_address = _address(declaration.get("nativeAddress"))
            observed = {address for address in (alias_address, actual, owner_address) if address is not None}
            if len(observed) > 1:
                raise ValueError("Alias native addresses conflict for " + alias_id)
            if alias_id not in by_id:
                entry = external.setdefault(alias_id, {"id": alias_id, "referencedBy": [], "nativeAddress": None,
                                                       "scope": "outside-supplied-declaration-inventory",
                                                       "category": "unknown", "nativeAction": "recover-native",
                                                       "originalDeclaration": False, "requiresResolution": True,
                                                       "requiresNativeEligibilityCheck": True,
                                                       "skipNativeRecovery": False, "isRecovered": False})
                value = next(iter(observed), None)
                if entry["nativeAddress"] is not None and value is not None and entry["nativeAddress"] != value:
                    raise ValueError("External alias has inconsistent address observations")
                entry["nativeAddress"] = entry["nativeAddress"] or value
                entry["referencedBy"].append(declaration["id"])
    return declarations, by_id, sorted(external.values(), key=lambda x: x["id"])


def _catalog_index(catalog, matches):
    matching = {}
    for match in (matches or {}).get("matches", []):
        for candidate in match.get("candidates", []):
            key = (match.get("packageId"), candidate.get("version"), candidate.get("variantId"))
            matching[key] = match
    index, weak = defaultdict(list), defaultdict(list)
    for package in catalog.get("packages", []):
        if not isinstance(package, dict) or not package.get("id"):
            continue
        for version in package.get("versions", []):
            if version.get("disposition") == "builtin-reference":
                # Builtin references use their multi-feature provider detector.
                # One sampled API must not become a generic library defer.
                continue
            key = (package["id"], version.get("version"), version.get("variantId"))
            match = matching.get(key, {})
            candidate = {"packageId": key[0], "version": key[1], "variantId": key[2],
                         "sourceRef": version.get("sourceRef"), "sourceUrl": version.get("sourceUrl"),
                         "disposition": version.get("disposition"),
                         "artifactSha256": (version.get("artifact") or {}).get("sha256"),
                         "matchStatus": match.get("status", "declaration-candidate"),
                         "conflicts": match.get("conflicts", [])}
            fingerprint = version.get("fingerprint") or {}
            assemblies = fingerprint.get("assemblies", [])
            assemblies_by_id = {a["id"]: a for a in assemblies if isinstance(a, dict) and a.get("id")}
            scoped = []
            for declaration in fingerprint.get("typeDeclarations", []):
                if not isinstance(declaration, dict):
                    continue
                assembly = declaration.get("assemblyIdentity") or declaration.get("assembly") or assemblies_by_id.get(declaration.get("assemblyId"))
                full_name = declaration.get("typeFullName") or declaration.get("fullName")
                uncertain = declaration.get("ownershipVerified") is False or (isinstance(assembly, dict) and assembly.get("ownershipVerified") is False)
                if assembly and full_name and not uncertain:
                    scoped.append((_assembly(assembly), full_name))
            for assembly in assemblies:
                if not isinstance(assembly, dict) or assembly.get("ownershipVerified") is False:
                    continue
                for declaration in assembly.get("types", []):
                    name = declaration if isinstance(declaration, str) else declaration.get("typeFullName") or declaration.get("fullName")
                    if name:
                        scoped.append((_assembly(assembly), name))
            # Existing v1 source fingerprints have a global lexical type set.
            # Attribution is justified only if every source belongs to a single
            # verified assembly. Multi-assembly/global name joins remain weak.
            sources = [f for f in fingerprint.get("files", []) if f.get("path", "").lower().endswith(".cs")]
            verified = [a for a in assemblies if isinstance(a, dict) and a.get("ownershipVerified") is True and _assembly(a).get("name")]
            if not scoped and len(verified) == 1 and sources and all(f.get("assembly") == _assembly(verified[0]).get("name") for f in sources):
                scoped.extend((_assembly(verified[0]), t if isinstance(t, str) else t.get("fullName")) for t in fingerprint.get("types", []))
            for assembly, type_name in scoped:
                if assembly.get("name") and type_name:
                    index[(assembly["name"], type_name)].append((assembly, candidate))
            for assembly in assemblies:
                name = _assembly(assembly).get("name")
                if name:
                    weak[name].append(candidate)
    return index, weak


def _candidate_key(candidate):
    return (str(candidate.get("packageId")), str(candidate.get("version")), str(candidate.get("variantId")))


def _unique_candidates(candidates):
    return [value for _, value in sorted({_candidate_key(c): c for c in candidates}.items())]


def _scope_matches(scope, declaration):
    return (isinstance(scope, dict) and _same_assembly(declaration["assemblyIdentity"], scope.get("assemblyIdentity"), exact=True)
            and scope.get("typeFullName") == declaration["typeFullName"]
            and scope.get("memberSignature") == declaration["memberSignature"])


def _decisions(document, binding, by_id):
    if document is None:
        return {}
    if not isinstance(document, dict) or document.get("binding") != binding:
        raise ValueError("Decision binding must exactly match target/dump/input/catalog/profile")
    items = document.get("decisions")
    if not isinstance(items, list):
        raise ValueError("Decision document requires a decisions list")
    result = {}
    for decision in items:
        if not isinstance(decision, dict) or decision.get("id") not in by_id:
            raise ValueError("Decision must reference an original declaration id")
        identifier = decision["id"]
        if identifier in result:
            raise ValueError("Duplicate decision for declaration " + identifier)
        if decision.get("action") not in ACTIONS or decision["action"] in ("recover-native", "defer-library-resolution"):
            raise ValueError("Decision action must be a confirmed provider/reuse/skip/regeneration action")
        if decision.get("status") != "accepted" or decision.get("acceptedBy") != "original-writer" or not decision.get("evidenceRefs"):
            raise ValueError("Exclusion requires an explicit accepted original-writer decision and evidence")
        if not _scope_matches(decision.get("scope"), by_id[identifier]):
            raise ValueError("Decision scope must exactly match assembly identity, type and member")
        result[identifier] = decision
    return result


def _generated_owner(declaration):
    owner = declaration.get("owner") or {}
    identifier = owner.get("declarationId") or declaration.get("ownerDeclarationId")
    verified = owner.get("verified") is True or declaration.get("ownerVerified") is True
    evidence = owner.get("evidenceRefs") or declaration.get("ownerEvidenceRefs")
    return identifier if verified and evidence else None


def classify(inventory, catalog, matches=None, profile=None, decisions=None, restore_ids=(), restore_reason=None):
    """Return classifications and unauthenticated selector/workset proposals.

    ``completeScope`` must contain complete=true, declarationCount and the
    original declarationIds. ``decisions.binding`` equals classification.binding.
    No input dictionary or existing selection is modified.
    """
    declarations, by_id, external_aliases = _validate(inventory)
    restore_ids = list(restore_ids)
    if any(not isinstance(identifier, str) for identifier in restore_ids):
        raise ValueError("Restoration ids must be strings")
    if not isinstance(catalog, dict) or not catalog.get("catalogCommit"):
        raise ValueError("A pinned catalogCommit is required")
    if profile is not None and not isinstance(profile, dict):
        raise ValueError("profile must be an object or null")
    if matches is not None:
        if not isinstance(matches, dict) or matches.get("catalogCommit") != catalog.get("catalogCommit"):
            raise ValueError("Matches must belong to the current catalog commit")
        if matches.get("profile") is not None and matches["profile"] != profile:
            raise ValueError("Matches profile differs from classification profile")
    binding = {"targetId": inventory["targetId"], "dumpSha256": inventory["dumpSha256"].lower(),
               "inputSha256": inventory["inputSha256"].lower(), "catalogCommit": catalog["catalogCommit"],
               "catalogSha256": _hash(catalog), "profileSha256": _hash(profile)}
    classifier_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    builtin_identity = rules_identity()
    from .family_identity import detect_inventory,rules_identity as family_rules_identity
    family_rules=family_rules_identity()
    cache_key = _hash(dict(binding, classifierSha256=classifier_sha, inventorySha256=_hash(inventory),
                           matchesSha256=_hash(matches), decisionsSha256=_hash(decisions),
                           builtinRules=builtin_identity,
                           namedOriginRules=named_rules_identity(),
                           officialFamilyRules=family_rules,
                           restoration={"ids": sorted(restore_ids), "reason": restore_reason}))
    accepted = _decisions(decisions, binding, by_id)
    index, weak = _catalog_index(catalog, matches)
    builtin_proofs = detect_providers(inventory, profile=profile)
    family_clues=detect_inventory(inventory)
    named_rules=pending_rules()
    rows, rows_by_id = [], {}
    for declaration in declarations:
        assembly = declaration["assemblyIdentity"]
        strong = _unique_candidates(candidate for expected, candidate in index.get((assembly["name"], declaration["typeFullName"]), [])
                                    if _same_assembly(assembly, expected))
        weak_candidates = _unique_candidates(weak.get(assembly["name"], []))
        category = declaration.get("category")
        modified = declaration.get("modified") is True or declaration.get("isModified") is True
        named=match_pending(assembly=assembly["name"],type_name=declaration["typeFullName"],rules=named_rules)
        # A package-level known body/source conflict has no safe member-level
        # exclusion until its differences have been localized by the writer.
        match_modified = any(str(c.get("kind", "")).startswith("modified-or-") for candidate in strong for c in candidate["conflicts"])
        protected = category in PROTECTED or modified or match_modified or bool(named)
        if modified or match_modified:
            category = "modified"
        category = category or ("third-party-library" if strong else "possible-library" if weak_candidates else "unknown")
        evidence = [{"kind": "assembly-scoped-type-overlap", "assemblyIdentity": assembly,
                     "typeFullName": declaration["typeFullName"]}] if strong else []
        if not strong and weak_candidates:
            evidence.append({"kind": "assembly-name-only-weak-clue", "name": assembly["name"]})
        row = {"id": declaration["id"], **copy.deepcopy(_identity(declaration)),
               "targetId": binding["targetId"], "dumpSha256": binding["dumpSha256"],
               "aliases": copy.deepcopy(declaration.get("aliases", [])), "nativeAddress": declaration.get("nativeAddress"),
               "category": category, "candidatePackages": copy.deepcopy(strong or weak_candidates),
               "confidence": "high-library-identity" if strong and not protected else "weak" if weak_candidates else "unknown",
               "evidence": evidence, "evidenceRefs": copy.deepcopy(declaration.get("evidenceRefs", [])),
               "profileVerified": False, "nativeAction": "recover-native", "skipNativeRecovery": False,
               "reuseStatus": "not-adopted", "isRecovered": False, "nextQueue": "native-recovery",
               "reason": "protected-business-difference-or-unknown" if protected else "insufficient-scoped-library-evidence"}
        if family_clues.get(declaration["id"]):
            row["familyReferences"]=copy.deepcopy(family_clues[declaration["id"]])
            row["familyReferenceUsage"]="source-investigation-only-no-native-exclusion-or-adoption-authority"
        if named:
            row.update(namedPending=copy.deepcopy(named),reason="named-origin-and-modification-unresolved")
            row["evidence"].append({"kind":"named-origin-and-modification-unresolved","families":copy.deepcopy(named)})
        if strong and not protected and category != "compiler-generated":
            row.update(nativeAction="defer-library-resolution", nextQueue="library-resolution",
                       reuseStatus="resolution-pending", reason="library-identity-evidence-source-version-and-differences-unresolved")
        provider = builtin_proofs.get(declaration["id"])
        if provider and not protected and category != "compiler-generated":
            row.update(category=declaration.get("category") or "builtin-provider",
                       nativeAction="provider-reference", nextQueue="provider-integration",
                       provider=copy.deepcopy(provider), profileVerified=False,
                       confidence="confirmed-builtin-provider-identity", reuseStatus="provider-reference-pending",
                       reason="registered-module-identity-and-multiple-official-api-features-confirmed")
            row["candidatePackages"] = [{"packageId": provider["moduleId"], "version": provider["moduleVersion"],
                                          "variantId": "unity-builtin-reference", "disposition": "builtin-reference"}]
            row["evidence"].append({"kind": "builtin-module-provider-confirmed",
                                    "assemblyIdentity": copy.deepcopy(provider["assemblyIdentity"]),
                                    "matchedApiTypes": provider["matchedApiTypes"], "namespaceScope": provider["namespaceScope"],
                                    "rulesSha256": provider["rulesSha256"]})
        decision = accepted.get(declaration["id"])
        if decision and protected:
            row["decisionRejected"] = "protected declaration requires difference/owner resolution before exclusion"
        elif decision:
            action = decision["action"]
            if action in ("reuse-upstream", "skip-native"):
                chosen = [candidate for candidate in strong if all(candidate.get(key) == decision.get(key)
                          for key in ("packageId", "version", "variantId"))]
                if not chosen or decision.get("sourceConfirmed") is not True:
                    raise ValueError("Confirmed adoption requires an assembly-scoped catalog candidate and sourceConfirmed=true")
                row.update(nativeAction=action, reuseStatus="accepted-by-original-writer", nextQueue="upstream-integration")
            elif action == "provider-reference":
                if decision.get("providerVerified") is not True or decision.get("profileVerified") is not True or not decision.get("provider"):
                    raise ValueError("provider-reference requires verified provider and target profile evidence")
                row.update(nativeAction=action, profileVerified=True, provider=copy.deepcopy(decision["provider"]),
                           reuseStatus="provider-accepted-by-original-writer", nextQueue="provider-integration")
            elif action == "regenerate":
                if category not in ("package-generated", "regenerable-generated") or decision.get("inputsVerified") is not True or not decision.get("generator") or not decision.get("sourceRefs"):
                    raise ValueError("regenerate requires a verified generator, complete inputs and a regenerable category")
                row.update(nativeAction=action, generator=copy.deepcopy(decision["generator"]),
                           regenerationInputs=copy.deepcopy(decision["sourceRefs"]), nextQueue="generated-code",
                           reuseStatus="regeneration-pending")
            row["reason"] = "explicit-bound-original-writer-decision"
            row["decisionEvidenceRefs"] = copy.deepcopy(decision["evidenceRefs"])
        rows.append(row)
        rows_by_id[row["id"]] = row
    # Generated declarations can follow verified business/library scheduling,
    # but owner acceptance cannot expand an exact adoption scope implicitly.
    resolved, visiting = set(), set()

    def follow(identifier):
        if identifier in resolved:
            return
        row, declaration = rows_by_id[identifier], by_id[identifier]
        if row.get("namedPending"):
            # A verified generated owner cannot erase this declaration's own
            # unresolved origin. Its generated descendants follow native too.
            resolved.add(identifier)
            return
        if row.get("restoredToNative"):
            # An explicit restoration, or recovery inherited from an already
            # resolved restored owner, must survive the final ownership pass.
            resolved.add(identifier)
            return
        if row["category"] != "compiler-generated":
            resolved.add(identifier)
            return
        owner = _generated_owner(declaration)
        if not owner or owner not in rows_by_id or owner in visiting or owner == identifier:
            row.update(nativeAction="recover-native", nextQueue="native-recovery", reuseStatus="not-adopted",
                       profileVerified=False, reason="compiler-generated-owner-unverified")
            if identifier in accepted:
                row["decisionRejected"] = "compiler-generated declaration lacks a verified actual owner"
            resolved.add(identifier)
            return
        visiting.add(identifier)
        follow(owner)
        visiting.remove(identifier)
        owner_row = rows_by_id[owner]
        row["ownerDeclarationId"] = owner
        row["ownerCategory"] = owner_row["category"]
        if owner_row["nativeAction"] == "recover-native" or owner_row["category"] in PROTECTED:
            if owner_row.get("restoredToNative"):
                row.update(originalNativeAction=row["nativeAction"], restoredToNative=True,
                           restorationReason=owner_row["restorationReason"],
                           restorationInheritedFrom=owner,
                           restorationRootId=owner_row.get("restorationRootId", owner))
            row.update(nativeAction="recover-native", nextQueue="native-recovery", reuseStatus="not-adopted",
                       profileVerified=False, reason="verified-compiler-generated-owner-retains-native-recovery")
            if identifier in accepted:
                row["decisionRejected"] = "compiler-generated declaration follows its actual native-recovery owner"
        elif identifier in accepted and row["nativeAction"] != "recover-native":
            pass  # Its own exact, accepted member scope does not expand to peers.
        elif (owner_row["nativeAction"] == "provider-reference"
              and (owner_row.get("provider") or {}).get("kind") == "unity-builtin-module"
              and builtin_proofs.get(identifier, {}).get("generatedOwnerId") == owner):
            row.update(nativeAction="provider-reference", provider=copy.deepcopy(builtin_proofs[identifier]),
                       profileVerified=False, confidence="confirmed-builtin-provider-owner",
                       reuseStatus="provider-reference-pending", nextQueue="provider-integration",
                       reason="verified-compiler-generated-owner-is-confirmed-builtin-provider")
        elif owner_row["nativeAction"] == "defer-library-resolution":
            row.update(nativeAction="defer-library-resolution", candidatePackages=copy.deepcopy(owner_row["candidatePackages"]),
                       confidence=owner_row["confidence"], reason="verified-compiler-generated-library-owner-awaits-resolution",
                       reuseStatus="resolution-pending", nextQueue="library-resolution")
        else:
            row["reason"] = "verified-compiler-generated-owner-native-or-own-adoption-scope-required"
        resolved.add(identifier)

    for identifier in by_id:
        follow(identifier)
    if len(restore_ids) != len(set(restore_ids)) or any(identifier not in by_id for identifier in restore_ids):
        raise ValueError("Restoration ids must be unique original declaration ids")
    if restore_ids and (not isinstance(restore_reason, str) or not restore_reason.strip()):
        raise ValueError("Restoration requires a nonempty reason")
    for identifier in restore_ids:
        row = rows_by_id[identifier]
        if row["nativeAction"] != "defer-library-resolution":
            raise ValueError("Only deferred library declarations can be restored to native selection")
        row.update(originalNativeAction="defer-library-resolution", nativeAction="recover-native",
                   nextQueue="native-recovery", restorationReason=restore_reason.strip(), restoredToNative=True,
                   restorationRootId=identifier)
    if restore_ids:
        # Owner following initially determines which rows are deferred and may
        # be explicitly restored. Re-evaluate it against those final recovery
        # actions, so generated execution scopes cannot remain deferred behind
        # a restored owner. This only propagates recovery, never acceptance.
        resolved.clear()
        for identifier in by_id:
            follow(identifier)
    for row in rows:
        action = row["nativeAction"]
        if action == "defer-library-resolution" or row.get("restoredToNative"):
            row["deferReason"] = row["reason"]
        if action in ("provider-reference", "reuse-upstream", "skip-native"):
            row["skipReason"] = row["reason"]
        if action == "recover-native":
            row["nativeReason"] = row.get("restorationReason", row["reason"])
        if action == "regenerate":
            row["regenerationReason"] = row["reason"]
    if len(rows) != len(by_id) or {r["id"] for r in rows} != set(by_id):
        raise ValueError("Classification failed original declaration conservation")
    common = {"schemaVersion": "1.0", "binding": binding, "cacheKey": cache_key,
              "integrationStatus": "integration-pending"}
    library = [copy.deepcopy(row) for row in rows if row["nativeAction"] == "defer-library-resolution" or row.get("restoredToNative") or row.get("namedPending") or row.get("familyReferences")]
    generated = [copy.deepcopy(row) for row in rows if row["nativeAction"] == "regenerate"]
    native = [row for row in rows if row["nativeAction"] == "recover-native"]
    native_ids = {row["id"] for row in native}
    declaration_addresses = {_address(row.get("nativeAddress")) for row in rows} - {None}
    native_declaration_addresses = {_address(row.get("nativeAddress")) for row in native} - {None}
    external_alias_addresses = {_address(alias.get("nativeAddress")) for alias in external_aliases} - {None}
    # External aliases are not invented original declaration IDs. Their unknown
    # eligibility nevertheless keeps every observed address available to Core;
    # deferring their sole library referrer cannot count that work as avoided.
    before_addresses = declaration_addresses | external_alias_addresses
    native_addresses = native_declaration_addresses | external_alias_addresses
    address_owners = defaultdict(list)
    external_address_owners = defaultdict(list)
    for row in rows:
        address = _address(row.get("nativeAddress"))
        if address is not None:
            address_owners[address].append(row["id"])
    for alias in external_aliases:
        address = _address(alias.get("nativeAddress"))
        if address is not None:
            external_address_owners[address].append(alias["id"])
    summary = {**common, "declarationCount": len(rows), "classifiedCount": len(rows),
               "actionCounts": {action: sum(row["nativeAction"] == action for row in rows) for action in ACTIONS},
               "categoryCounts": dict(sorted(Counter(row["category"] for row in rows).items())),
               "nativeDeclarationCount": len(native), "deferredDeclarationCount": sum(row["nativeAction"] == "defer-library-resolution" for row in rows),
               "originalAddressCount": len(before_addresses), "nativeAddressCount": len(native_addresses),
               "originalDeclarationAddressCount": len(declaration_addresses),
               "nativeDeclarationAddressCount": len(native_declaration_addresses),
               "externalAliasAddressCount": len(external_alias_addresses),
               "avoidedAddressCount": len(before_addresses - native_addresses),
               "sharedAddresses": [{"nativeAddress": address, "declarationIds": address_owners[address],
                                    "nativeDeclarationIds": [identifier for identifier in address_owners[address] if identifier in native_ids],
                                    "unknownExternalAliasIds": external_address_owners[address]}
                                   for address in sorted(before_addresses)
                                   if len(address_owners[address]) + len(external_address_owners[address]) > 1],
               "externalAliasCount": len(external_aliases), "isRecovered": False,
               "builtinProviderDeclarationCount": sum(row["nativeAction"] == "provider-reference" and (row.get("provider") or {}).get("kind") == "unity-builtin-module" for row in rows),
               "builtinProviderModuleCounts": dict(sorted(Counter((row.get("provider") or {}).get("moduleId") for row in rows
                                                                if row["nativeAction"] == "provider-reference" and (row.get("provider") or {}).get("kind") == "unity-builtin-module").items())),
               "externalAliasResolutionRequired": bool(external_aliases),
               "namedPendingDeclarationCount":sum(bool(row.get("namedPending")) for row in rows),
               "officialFamilyClueDeclarationCount":sum(bool(row.get("familyReferences")) for row in rows),
               "conservation": {"input": len(by_id), "routed": len(rows), "missing": [], "duplicate": []}}
    return {"classification": {**common, "classifierSha256": classifier_sha, "profile": copy.deepcopy(profile),
                                "builtinRules": builtin_identity,
                                "officialFamilyRules":family_rules,
                                "completeScope": copy.deepcopy(inventory["completeScope"]),
                                "sourceRefs": copy.deepcopy(inventory.get("sourceRefs", [])),
                                "items": rows, "externalAliases": external_aliases, "adoptionStatus": "pending"},
            "libraryResolutionWorkset": {**common, "items": library},
            "generatedCodeWorkset": {**common, "items": generated},
            "nativeSelection": {**common, "kind": "native-selection-proposal", "authenticated": False,
                                "methodIds": [row["id"] for row in native],
                                "requiresNativeEligibilityCheck": True,
                                "addressedDeclarationIds": [row["id"] for row in native if _address(row.get("nativeAddress")) is not None],
                                "unaddressedDeclarationIds": [row["id"] for row in native if _address(row.get("nativeAddress")) is None],
                                "declarations": [copy.deepcopy(row) for row in native],
                                "externalAliases": copy.deepcopy(external_aliases),
                                "requiresExternalAliasResolution": bool(external_aliases),
                                "unresolvedExternalAliasIds": [alias["id"] for alias in external_aliases],
                                "unaddressedExternalAliasIds": [alias["id"] for alias in external_aliases if _address(alias.get("nativeAddress")) is None],
                                "sourceInventory": None,
                                "requiredConsumer": "original-ReMaker-Core-writer-with-authenticated-original-inputs"},
            "summary": summary}
