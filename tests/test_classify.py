import copy
import unittest

from uvault.classify import ACTIONS, classify


def declaration(identifier, *, assembly="Library.Runtime", type_name="Library.Utility", category=None, address=None, **fields):
    result = {"id": identifier, "assemblyIdentity": {"name": assembly, "version": "1.0.0.0", "culture": "neutral", "publicKeyToken": "null"},
              "typeFullName": type_name, "memberSignature": "System.Void " + identifier + "()",
              "nativeAddress": address, "aliases": [], "evidenceRefs": [{"kind": "original-dump", "declarationId": identifier}]}
    if category is not None:
        result["category"] = category
    result.update(fields)
    return result


def inventory(*declarations):
    return {"schemaVersion": "1.0", "targetId": "synthetic-target", "dumpSha256": "a" * 64,
            "inputSha256": "b" * 64, "declarations": list(declarations),
            "completeScope": {"complete": True, "declarationCount": len(declarations), "declarationIds": [d["id"] for d in declarations]},
            "sourceRefs": [{"kind": "original-declaration-export", "sha256": "b" * 64}]}


def catalog(*versions):
    return {"schemaVersion": "1.0", "catalogCommit": "c" * 40, "packages": [{"id": "com.example.library", "versions": [
        {"version": number, "variantId": "upstream", "sourceRef": "d" * 40, "sourceUrl": "https://example.invalid/library",
         "disposition": "mirror-allowed", "artifact": {"sha256": "e" * 64},
         "fingerprint": {"assemblies": [{"id": "lib", "name": "Library.Runtime", "ownershipVerified": True}],
                         "types": ["Library.Utility"], "typeDeclarations": [
                             {"assemblyId": "lib", "fullName": "Library.Utility"}]}}
        for number in (versions or ("1.0.0",))]}]}


def accepted_decision(declaration, action, **fields):
    result = {"id": declaration["id"], "action": action, "status": "accepted", "acceptedBy": "original-writer",
              "scope": {key: copy.deepcopy(declaration[key]) for key in ("assemblyIdentity", "typeFullName", "memberSignature")},
              "evidenceRefs": [{"kind": "original-writer-acceptance", "sha256": "f" * 64}]}
    if action in ("reuse-upstream", "skip-native"):
        result.update(packageId="com.example.library", version="1.0.0", variantId="upstream", sourceConfirmed=True)
    result.update(fields)
    return result


def decision_document(inv, cat, *decisions, profile=None):
    return {"binding": classify(inv, cat, profile=profile)["classification"]["binding"], "decisions": list(decisions)}


class ClassificationTests(unittest.TestCase):
    def test_all_six_routes_are_unique_and_never_claim_recovered(self):
        business = declaration("business", category="game-business", address="0x1000")
        provider = declaration("provider", assembly="UnityEngine.CoreModule", type_name="UnityEngine.Object", category="engine-provider", address="0x2000")
        reuse, skip, defer = (declaration(name, address=hex(number)) for name, number in (("reuse", 0x3000), ("skip", 0x4000), ("defer", 0x5000)))
        generated = declaration("generated", assembly="App.Generated", type_name="Generated.Client", category="package-generated", address="0x6000")
        inv, cat, profile = inventory(business, provider, reuse, skip, defer, generated), catalog(), {"unityVersion": "2022.3", "platform": "WindowsStandalone64"}
        decisions = decision_document(inv, cat,
            accepted_decision(provider, "provider-reference", provider={"id": "UnityEngine.CoreModule", "unityVersion": "2022.3"}, providerVerified=True, profileVerified=True),
            accepted_decision(reuse, "reuse-upstream"), accepted_decision(skip, "skip-native"),
            accepted_decision(generated, "regenerate", inputsVerified=True, generator={"id": "synthetic-generator", "version": "1", "sha256": "7" * 64}, sourceRefs=[{"sha256": "8" * 64}]), profile=profile)
        result = classify(inv, cat, profile=profile, decisions=decisions)
        rows = result["classification"]["items"]
        self.assertEqual(set(row["nativeAction"] for row in rows), set(ACTIONS))
        self.assertTrue(all(count == 1 for count in result["summary"]["actionCounts"].values()))
        self.assertTrue(all(not row["isRecovered"] and not row["skipNativeRecovery"] for row in rows))
        self.assertEqual(result["nativeSelection"]["methodIds"], ["business"])
        self.assertFalse(result["nativeSelection"]["authenticated"])
        self.assertIsNone(result["nativeSelection"]["sourceInventory"])
        self.assertEqual(result["summary"]["conservation"], {"input": 6, "routed": 6, "missing": [], "duplicate": []})
        self.assertEqual(len(result["libraryResolutionWorkset"]["items"]), 1)
        self.assertEqual(len(result["generatedCodeWorkset"]["items"]), 1)

    def test_unknown_and_weak_names_remain_native(self):
        unknown = declaration("unknown", assembly="Assembly-CSharp", type_name="Game.Business")
        similar = declaration("similar", type_name="Library.GameWrapper")
        explicit_unknown = declaration("explicit-unknown", category="unknown")
        result = classify(inventory(unknown, similar, explicit_unknown), catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], ["unknown", "similar", "explicit-unknown"])
        self.assertEqual(result["classification"]["items"][1]["confidence"], "weak")
        self.assertEqual(len(result["classification"]["items"]), 3)

    def test_global_multi_assembly_type_names_cannot_be_joined_to_wrong_assembly(self):
        cat = catalog()
        fingerprint = cat["packages"][0]["versions"][0]["fingerprint"]
        fingerprint["typeDeclarations"] = []
        fingerprint["assemblies"].append({"name": "Other.Runtime", "ownershipVerified": True})
        result = classify(inventory(declaration("lib")), cat)
        self.assertEqual(result["nativeSelection"]["methodIds"], ["lib"])
        self.assertEqual(result["classification"]["items"][0]["confidence"], "weak")

    def test_single_verified_source_owner_can_attribute_existing_v1_fingerprint(self):
        cat = catalog()
        fingerprint = cat["packages"][0]["versions"][0]["fingerprint"]
        fingerprint["typeDeclarations"] = []
        fingerprint["files"] = [{"path": "Runtime/Utility.cs", "assembly": "Library.Runtime"}]
        result = classify(inventory(declaration("lib")), cat)
        self.assertEqual(result["classification"]["items"][0]["nativeAction"], "defer-library-resolution")

    def test_shared_va_library_alias_does_not_remove_business_declaration(self):
        lib = declaration("lib", address="0x1234", aliases=["business"])
        business = declaration("business", assembly="Assembly-CSharp", type_name="Game.Actor", category="game-business", address=0x1234, aliases=["lib"])
        result = classify(inventory(lib, business), catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], ["business"])
        self.assertEqual(result["summary"]["originalAddressCount"], 1)
        self.assertEqual(result["summary"]["nativeAddressCount"], 1)
        self.assertEqual(result["summary"]["avoidedAddressCount"], 0)
        self.assertEqual(result["summary"]["sharedAddresses"][0]["nativeDeclarationIds"], ["business"])

    def test_business_wrapper_modification_and_application_messages_stay_native(self):
        categories = ("game-business", "project-wrapper", "modified", "application-generated", "mixed-owner")
        declarations = [declaration(category, category=category) for category in categories]
        result = classify(inventory(*declarations), catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], list(categories))
        self.assertEqual(result["libraryResolutionWorkset"]["items"], [])

    def test_package_source_modification_conflict_prevents_deferral(self):
        cat = catalog()
        matches = {"catalogCommit": cat["catalogCommit"], "matches": [{"packageId": "com.example.library", "status": "strong-candidate",
            "candidates": [{"version": "1.0.0", "variantId": "upstream"}], "conflicts": [{"kind": "modified-or-incomplete-target"}]}]}
        result = classify(inventory(declaration("lib")), cat, matches=matches)
        self.assertEqual(result["nativeSelection"]["methodIds"], ["lib"])
        self.assertEqual(result["classification"]["items"][0]["category"], "modified")

    def test_version_ambiguity_defers_once_to_resolution_with_both_candidates(self):
        result = classify(inventory(declaration("lib")), catalog("1.0.0", "2.0.0"))
        self.assertEqual(result["nativeSelection"]["methodIds"], [])
        self.assertEqual(result["summary"]["deferredDeclarationCount"], 1)
        self.assertEqual(len(result["libraryResolutionWorkset"]["items"]), 1)
        self.assertEqual(len(result["classification"]["items"][0]["candidatePackages"]), 2)

    def test_catalog_commit_content_profile_dump_and_source_input_change_cache_key(self):
        inv, cat = inventory(declaration("lib")), catalog()
        baseline = classify(inv, cat)["classification"]["cacheKey"]
        variants = []
        changed = copy.deepcopy(cat)
        changed["catalogCommit"] = "9" * 40
        variants.append(classify(inv, changed)["classification"]["cacheKey"])
        changed = copy.deepcopy(cat)
        changed["packages"][0]["versions"][0]["sourceRef"] = "9" * 40
        variants.append(classify(inv, changed)["classification"]["cacheKey"])
        variants.append(classify(inv, cat, profile={"defines": ["FEATURE"]})["classification"]["cacheKey"])
        for key in ("dumpSha256", "inputSha256"):
            changed = copy.deepcopy(inv)
            changed[key] = "9" * 64
            variants.append(classify(changed, cat)["classification"]["cacheKey"])
        self.assertTrue(all(value != baseline for value in variants))
        self.assertEqual(baseline, classify(inv, cat)["classification"]["cacheKey"])

    def test_restoration_requires_reason_and_preserves_library_class_and_queue(self):
        inv, cat = inventory(declaration("lib")), catalog()
        with self.assertRaises(ValueError):
            classify(inv, cat, restore_ids=["lib"])
        restored = classify(inv, cat, restore_ids=["lib"], restore_reason="Original writer requests differential native examination")
        row = restored["classification"]["items"][0]
        self.assertEqual(row["category"], "third-party-library")
        self.assertEqual(row["originalNativeAction"], "defer-library-resolution")
        self.assertEqual(restored["nativeSelection"]["methodIds"], ["lib"])
        self.assertTrue(restored["libraryResolutionWorkset"]["items"][0]["restoredToNative"])
        self.assertTrue(row["restorationReason"])

    def test_restored_owner_recovers_verified_generated_chain_in_any_input_order(self):
        owner = declaration("owner")
        state = declaration("state", type_name="Library.Utility+StateMachine", category="compiler-generated",
                            owner={"declarationId": "owner", "verified": True, "evidenceRefs": [{"kind": "metadata-owner"}]})
        nested = declaration("nested", type_name="Library.Utility+StateMachine+Closure", category="compiler-generated",
                             owner={"declarationId": "state", "verified": True, "evidenceRefs": [{"kind": "metadata-owner"}]})
        for ordering in ((owner, state, nested), (nested, state, owner)):
            inv = inventory(*ordering)
            baseline = classify(inv, catalog())
            self.assertTrue(all(row["nativeAction"] == "defer-library-resolution" for row in baseline["classification"]["items"]))
            restored = classify(inv, catalog(), restore_ids=["owner"], restore_reason="Review actual modified task implementation")
            rows = {row["id"]: row for row in restored["classification"]["items"]}
            self.assertEqual(set(restored["nativeSelection"]["methodIds"]), {"owner", "state", "nested"})
            self.assertEqual(rows["state"]["restorationInheritedFrom"], "owner")
            self.assertEqual(rows["nested"]["restorationInheritedFrom"], "state")
            self.assertEqual(rows["nested"]["restorationRootId"], "owner")
            self.assertEqual(rows["nested"]["restorationReason"], rows["owner"]["restorationReason"])
            self.assertEqual(rows["nested"]["category"], "compiler-generated")
            self.assertTrue(all(not row["isRecovered"] for row in rows.values()))
            self.assertEqual(len(restored["libraryResolutionWorkset"]["items"]), 3)
            self.assertEqual(restored["summary"]["deferredDeclarationCount"], 0)

    def test_restoring_generated_scope_does_not_redefer_it_to_its_library_owner(self):
        owner = declaration("owner")
        state = declaration("state", type_name="Library.Utility+StateMachine", category="compiler-generated",
                            owner={"declarationId": "owner", "verified": True, "evidenceRefs": [{"kind": "metadata-owner"}]})
        nested = declaration("nested", type_name="Library.Utility+StateMachine+Closure", category="compiler-generated",
                             owner={"declarationId": "state", "verified": True, "evidenceRefs": [{"kind": "metadata-owner"}]})
        result = classify(inventory(nested, state, owner), catalog(), restore_ids=["state"], restore_reason="Investigate generated body")
        rows = {row["id"]: row for row in result["classification"]["items"]}
        self.assertEqual(rows["owner"]["nativeAction"], "defer-library-resolution")
        self.assertEqual(set(result["nativeSelection"]["methodIds"]), {"state", "nested"})
        self.assertEqual(rows["nested"]["restorationRootId"], "state")

    def test_owner_adoption_does_not_expand_exact_acceptance_to_generated_member(self):
        owner = declaration("owner")
        state = declaration("state", type_name="Library.Utility+StateMachine", category="compiler-generated",
                            owner={"declarationId": "owner", "verified": True, "evidenceRefs": [{"kind": "metadata-owner"}]})
        inv, cat = inventory(owner, state), catalog()
        decisions = decision_document(inv, cat, accepted_decision(owner, "reuse-upstream"))
        result = classify(inv, cat, decisions=decisions)
        rows = {row["id"]: row for row in result["classification"]["items"]}
        self.assertEqual(rows["owner"]["nativeAction"], "reuse-upstream")
        self.assertEqual(rows["state"]["nativeAction"], "recover-native")
        self.assertFalse(rows["state"].get("restoredToNative", False))

    def test_duplicate_missing_partial_and_non_original_coverage_are_rejected(self):
        inv = inventory(declaration("first"), declaration("second"))
        invalid = []
        duplicate = copy.deepcopy(inv)
        duplicate["declarations"].append(copy.deepcopy(duplicate["declarations"][0]))
        invalid.append(duplicate)
        missing = copy.deepcopy(inv)
        missing["declarations"].pop()
        invalid.append(missing)
        partial = copy.deepcopy(inv)
        partial["completeScope"]["complete"] = False
        invalid.append(partial)
        count = copy.deepcopy(inv)
        count["completeScope"]["declarationCount"] = 1
        invalid.append(count)
        bare = copy.deepcopy(inv)
        bare["completeScope"] = True
        invalid.append(bare)
        for value in invalid:
            with self.subTest(scope=value["completeScope"]), self.assertRaises(ValueError):
                classify(value, catalog())

    def test_external_alias_is_preserved_but_address_contradiction_rejected(self):
        inv = inventory(declaration("business", category="game-business", address="0x1000", aliases=[{"id": "external", "nativeAddress": "0x1000"}]))
        result = classify(inv, catalog())
        self.assertEqual(result["nativeSelection"]["externalAliases"][0]["id"], "external")
        self.assertEqual(result["summary"]["externalAliasCount"], 1)
        inv["declarations"][0]["aliases"][0]["nativeAddress"] = "0x2000"
        with self.assertRaises(ValueError):
            classify(inv, catalog())

    def test_external_unknown_alias_retains_address_when_its_only_referrer_is_deferred(self):
        inv = inventory(declaration("lib", address="0x1000", aliases=["unclassified-external"]))
        result = classify(inv, catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], [])
        alias = result["nativeSelection"]["externalAliases"][0]
        self.assertEqual(alias["id"], "unclassified-external")
        self.assertEqual(alias["category"], "unknown")
        self.assertEqual(alias["nativeAction"], "recover-native")
        self.assertFalse(alias["originalDeclaration"])
        self.assertEqual(alias["nativeAddress"], "0x1000")
        self.assertTrue(result["nativeSelection"]["requiresExternalAliasResolution"])
        self.assertEqual(result["summary"]["nativeDeclarationAddressCount"], 0)
        self.assertEqual(result["summary"]["externalAliasAddressCount"], 1)
        self.assertEqual(result["summary"]["nativeAddressCount"], 1)
        self.assertEqual(result["summary"]["avoidedAddressCount"], 0)
        self.assertEqual(result["summary"]["conservation"]["routed"], 1)

    def test_unaddressed_external_alias_is_an_explicit_unresolved_eligibility_gap(self):
        result = classify(inventory(declaration("lib", aliases=["unknown-external"])), catalog())
        self.assertEqual(result["nativeSelection"]["unresolvedExternalAliasIds"], ["unknown-external"])
        self.assertEqual(result["nativeSelection"]["unaddressedExternalAliasIds"], ["unknown-external"])
        self.assertIsNone(result["nativeSelection"]["externalAliases"][0]["nativeAddress"])
        self.assertEqual(result["summary"]["nativeAddressCount"], 0)
        self.assertEqual(result["summary"]["avoidedAddressCount"], 0)

    def test_external_alias_and_same_address_business_are_counted_without_invented_ids(self):
        lib = declaration("lib", address="0x1000", aliases=["unknown-external"])
        business = declaration("business", category="game-business", address="0x1000")
        result = classify(inventory(lib, business), catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], ["business"])
        self.assertEqual(result["summary"]["nativeAddressCount"], 1)
        self.assertEqual(result["summary"]["avoidedAddressCount"], 0)
        shared = result["summary"]["sharedAddresses"][0]
        self.assertEqual(shared["nativeDeclarationIds"], ["business"])
        self.assertEqual(shared["unknownExternalAliasIds"], ["unknown-external"])
        self.assertEqual(result["summary"]["conservation"]["input"], 2)

    def test_compiler_generated_only_follows_verified_actual_owner(self):
        owner = declaration("owner")
        verified = declaration("state", type_name="Library.Utility+StateMachine", category="compiler-generated",
                               owner={"declarationId": "owner", "verified": True, "evidenceRefs": [{"kind": "metadata-owner"}]})
        unverified = declaration("unknown-state", type_name="Library.Utility+OtherState", category="compiler-generated", ownerDeclarationId="owner")
        result = classify(inventory(owner, verified, unverified), catalog())
        rows = {row["id"]: row for row in result["classification"]["items"]}
        self.assertEqual(rows["state"]["nativeAction"], "defer-library-resolution")
        self.assertEqual(rows["unknown-state"]["nativeAction"], "recover-native")
        owner["category"] = "game-business"
        result = classify(inventory(owner, verified), catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], ["owner", "state"])

    def test_stale_binding_and_broad_scope_cannot_authorize_adoption(self):
        lib = declaration("lib")
        inv, cat = inventory(lib), catalog()
        document = decision_document(inv, cat, accepted_decision(lib, "skip-native"))
        document["binding"]["dumpSha256"] = "9" * 64
        with self.assertRaises(ValueError):
            classify(inv, cat, decisions=document)
        document = decision_document(inv, cat, accepted_decision(lib, "skip-native"))
        document["decisions"][0]["scope"].pop("memberSignature")
        with self.assertRaises(ValueError):
            classify(inv, cat, decisions=document)

    def test_source_match_and_exact_artifact_do_not_automatically_adopt(self):
        cat = catalog()
        matches = {"catalogCommit": cat["catalogCommit"], "matches": [{"packageId": "com.example.library", "status": "exact-artifact", "candidates": [{"version": "1.0.0", "variantId": "upstream"}]}]}
        result = classify(inventory(declaration("lib")), cat, matches=matches)
        self.assertEqual(result["classification"]["items"][0]["nativeAction"], "defer-library-resolution")
        self.assertEqual(result["classification"]["adoptionStatus"], "pending")

    def test_uncertain_catalog_ownership_and_conflicting_assembly_version_stay_native(self):
        for field, value in (("ownershipVerified", False), ("version", "2.0.0.0")):
            cat = catalog()
            cat["packages"][0]["versions"][0]["fingerprint"]["assemblies"][0][field] = value
            result = classify(inventory(declaration("lib")), cat)
            self.assertEqual(result["nativeSelection"]["methodIds"], ["lib"])

    def test_compiler_generated_adoption_cannot_bypass_unverified_owner(self):
        generated = declaration("state", category="compiler-generated")
        inv, cat = inventory(generated), catalog()
        document = decision_document(inv, cat, accepted_decision(generated, "skip-native"))
        result = classify(inv, cat, decisions=document)
        row = result["classification"]["items"][0]
        self.assertEqual(row["nativeAction"], "recover-native")
        self.assertIn("owner", row["decisionRejected"])

    def test_unaddressed_unknown_declaration_is_preserved_for_original_core_eligibility_check(self):
        result = classify(inventory(declaration("abstract", category="unknown")), catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], ["abstract"])
        self.assertEqual(result["nativeSelection"]["unaddressedDeclarationIds"], ["abstract"])
        self.assertTrue(result["nativeSelection"]["requiresNativeEligibilityCheck"])

    def test_input_is_not_mutated_and_output_identity_retains_evidence_and_aliases(self):
        inv, cat = inventory(declaration("lib", address="0x1000", aliases=["external"])), catalog()
        original, original_cat = copy.deepcopy(inv), copy.deepcopy(cat)
        result = classify(inv, cat)
        self.assertEqual(inv, original)
        self.assertEqual(cat, original_cat)
        row = result["classification"]["items"][0]
        for key in ("assemblyIdentity", "typeFullName", "memberSignature", "evidenceRefs", "aliases", "nativeAddress"):
            self.assertEqual(row[key], inv["declarations"][0][key])


if __name__ == "__main__":
    unittest.main()
