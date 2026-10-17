import copy
import unittest

from uvault.builtin import detect_providers, package_records, rules_identity
from uvault.classify import classify


def declaration(identifier, type_name, assembly="UnityEngine.PhysicsModule", **fields):
    value = {"id": identifier, "assemblyIdentity": {"name": assembly, "version": "0.0.0.0", "culture": "neutral", "publicKeyToken": "null"},
             "typeFullName": type_name, "memberSignature": "System.Void " + identifier + "()",
             "evidenceRefs": [{"kind": "original-metadata-declaration", "id": identifier}], "aliases": [], "nativeAddress": None}
    value.update(fields)
    return value


def inventory(*declarations):
    return {"schemaVersion": "1.0", "targetId": "synthetic-engine-target", "dumpSha256": "a" * 64, "inputSha256": "b" * 64,
            "declarations": list(declarations),
            "completeScope": {"complete": True, "declarationCount": len(declarations), "declarationIds": [d["id"] for d in declarations]}}


def catalog():
    return {"schemaVersion": "1.0", "catalogCommit": "c" * 40, "packages": package_records()}


def physics_inventory(*extras):
    return inventory(declaration("physics", "UnityEngine.Physics"), declaration("collider", "UnityEngine.Collider"), *extras)


class BuiltinTests(unittest.TestCase):
    def test_finite_reference_packages_have_no_artifact_or_invented_unity_version(self):
        records = package_records()
        self.assertEqual(len(records), 17)
        self.assertEqual(len({p["id"] for p in records}), 17)
        for package in records:
            version = package["versions"][0]
            self.assertEqual(version["disposition"], "builtin-reference")
            self.assertIsNone(version["artifact"])
            self.assertEqual(version["unityVersion"], "unknown")
            self.assertFalse(version["fingerprint"]["profileVerified"])
            self.assertGreaterEqual(len(version["provider"]["apiFeatures"]), 2)
            self.assertTrue(all(feature["url"].startswith("https://docs.unity3d.com/") for feature in version["provider"]["apiFeatures"]))
        by_id = {p["id"]: p for p in records}
        self.assertEqual(by_id["unity.builtin.core-module"]["versions"][0]["moduleVersion"], "unknown")
        self.assertEqual(by_id["unity.builtin.legacy-input-module"]["versions"][0]["moduleVersion"], "unknown")
        self.assertEqual(by_id["com.unity.modules.physics"]["versions"][0]["moduleVersion"], "1.0.0")
        self.assertNotIn("com.unity.inputsystem", by_id)
        self.assertNotIn("com.unity.render-pipelines.universal", by_id)

    def test_multiple_actual_api_types_confirm_provider_without_verified_profile_or_adoption(self):
        inv = physics_inventory(declaration("internal", "UnityEngine.PhysicsInternalUtility"))
        proof = detect_providers(inv)
        self.assertEqual(set(proof), {"physics", "collider", "internal"})
        result = classify(inv, catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], [])
        for row in result["classification"]["items"]:
            self.assertEqual(row["nativeAction"], "provider-reference")
            self.assertEqual(row["provider"]["referenceStatus"], "reference-pending")
            self.assertEqual(row["provider"]["unityVersion"], "unknown")
            self.assertFalse(row["profileVerified"])
            self.assertFalse(row["isRecovered"])
            self.assertFalse(row["skipNativeRecovery"])
            self.assertEqual(row["reuseStatus"], "provider-reference-pending")
        self.assertEqual(result["summary"]["builtinProviderDeclarationCount"], 3)

    def test_one_sample_type_with_multiple_members_is_insufficient_and_not_generic_defer(self):
        inv = inventory(declaration("first", "UnityEngine.Physics"), declaration("second", "UnityEngine.Physics"))
        self.assertEqual(detect_providers(inv), {})
        result = classify(inv, catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], ["first", "second"])
        self.assertEqual(result["libraryResolutionWorkset"]["items"], [])

    def test_namespace_similarity_wrong_assembly_and_unregistered_fake_module_stay_native(self):
        for assembly in ("Assembly-CSharp", "UnityEngine.FakeModule", "Game.UnityEngine.PhysicsModule"):
            inv = inventory(declaration("fake-physics", "UnityEngine.Physics", assembly), declaration("fake-collider", "UnityEngine.Collider", assembly))
            self.assertEqual(detect_providers(inv), {})
            result = classify(inv, catalog())
            self.assertEqual(len(result["nativeSelection"]["methodIds"]), 2)
        named_fake = inventory(declaration("fake-one", "UnityEngine.FakePhysics"), declaration("fake-two", "UnityEngine.FakeCollider"))
        self.assertEqual(detect_providers(named_fake), {})
        self.assertEqual(len(classify(named_fake, catalog())["nativeSelection"]["methodIds"]), 2)

    def test_same_module_business_wrapper_modified_unknown_and_foreign_namespace_stay_native(self):
        protected = [declaration(category, "UnityEngine." + category.replace("-", ""), category=category)
                     for category in ("game-business", "project-wrapper", "modified", "unknown", "mixed-owner", "application-generated")]
        modified = declaration("flagged", "UnityEngine.ModifiedImplementation", modified=True)
        foreign = declaration("foreign", "Game.PhysicsWrapper")
        inv = physics_inventory(*protected, modified, foreign)
        proof = detect_providers(inv)
        self.assertEqual(set(proof), {"physics", "collider"})
        result = classify(inv, catalog())
        self.assertEqual(set(result["nativeSelection"]["methodIds"]), {d["id"] for d in protected + [modified, foreign]})

    def test_protected_api_feature_cannot_supply_module_identity(self):
        inv = inventory(declaration("physics", "UnityEngine.Physics"), declaration("collider", "UnityEngine.Collider", category="modified"))
        self.assertEqual(detect_providers(inv), {})
        self.assertEqual(len(classify(inv, catalog())["nativeSelection"]["methodIds"]), 2)

    def test_provider_route_keeps_same_address_business_and_unresolved_alias_eligibility(self):
        physics = declaration("physics", "UnityEngine.Physics", nativeAddress="0x1000", aliases=["external-unknown"])
        collider = declaration("collider", "UnityEngine.Collider", nativeAddress="0x2000")
        business = declaration("business", "Game.Actor", "Assembly-CSharp", category="game-business", nativeAddress="0x1000")
        result = classify(inventory(physics, collider, business), catalog())
        self.assertEqual(result["nativeSelection"]["methodIds"], ["business"])
        self.assertEqual(result["nativeSelection"]["unresolvedExternalAliasIds"], ["external-unknown"])
        self.assertEqual(result["summary"]["nativeAddressCount"], 1)
        self.assertEqual(result["summary"]["avoidedAddressCount"], 1)
        self.assertEqual(result["summary"]["builtinProviderDeclarationCount"], 2)

    def test_supplied_assembly_identity_conflict_and_unverified_ownership_do_not_reference(self):
        for field, value in (("version", "1.2.3.4"), ("publicKeyToken", "abcdef1234567890"), ("ownershipVerified", False)):
            inv = physics_inventory()
            for declaration in inv["declarations"]:
                declaration["assemblyIdentity"][field] = value
            self.assertEqual(detect_providers(inv), {})

    def test_features_from_distinct_full_assembly_identities_cannot_be_joined(self):
        inv = physics_inventory()
        inv["declarations"][0]["assemblyIdentity"]["imageScope"] = "scope-one"
        inv["declarations"][1]["assemblyIdentity"]["imageScope"] = "scope-two"
        self.assertEqual(detect_providers(inv), {})

    def test_reported_unity_version_stays_unverified_reference_pending(self):
        profile = {"unityVersion": "6000.0.31f1", "platform": "WindowsStandalone64", "profileVerified": True}
        proof = detect_providers(physics_inventory(), profile)
        self.assertEqual(proof["physics"]["unityVersion"], "6000.0.31f1")
        self.assertEqual(proof["physics"]["unityVersionStatus"], "reported-unverified")
        self.assertFalse(proof["physics"]["profileVerified"])
        self.assertEqual(proof["physics"]["referenceStatus"], "reference-pending")

    def test_compiler_generated_follows_verified_provider_owner_only(self):
        state = declaration("state", "UnityEngine.Physics+State", category="compiler-generated",
                            owner={"declarationId": "physics", "verified": True, "evidenceRefs": [{"kind": "actual-owner"}]})
        nested = declaration("nested", "UnityEngine.Physics+State+Closure", category="compiler-generated",
                             owner={"declarationId": "state", "verified": True, "evidenceRefs": [{"kind": "actual-owner"}]})
        unverified = declaration("unverified", "UnityEngine.Physics+Unverified", category="compiler-generated", ownerDeclarationId="physics")
        inv = physics_inventory(nested, state, unverified)
        proof = detect_providers(inv)
        self.assertEqual(proof["nested"]["generatedOwnerId"], "state")
        self.assertNotIn("unverified", proof)
        result = classify(inv, catalog())
        rows = {row["id"]: row for row in result["classification"]["items"]}
        self.assertEqual(rows["state"]["nativeAction"], "provider-reference")
        self.assertEqual(rows["nested"]["nativeAction"], "provider-reference")
        self.assertEqual(rows["unverified"]["nativeAction"], "recover-native")

    def test_generated_business_owner_retains_native_with_confirmed_module_nearby(self):
        business = declaration("business", "UnityEngine.GameWrapper", category="game-business")
        state = declaration("state", "UnityEngine.GameWrapper+State", category="compiler-generated",
                            owner={"declarationId": "business", "verified": True, "evidenceRefs": [{"kind": "actual-owner"}]})
        result = classify(physics_inventory(business, state), catalog())
        self.assertEqual(set(result["nativeSelection"]["methodIds"]), {"business", "state"})

    def test_missing_partial_duplicate_or_raw_dll_input_is_rejected(self):
        valid = physics_inventory()
        invalid = [None, {"files": [{"path": "UnityEngine.PhysicsModule.dll", "sha256": "d" * 64}]}]
        for mutation in ("missing", "partial", "duplicate"):
            inv = copy.deepcopy(valid)
            if mutation == "missing":
                inv["declarations"].pop()
            elif mutation == "partial":
                inv["completeScope"]["complete"] = False
            else:
                inv["declarations"].append(copy.deepcopy(inv["declarations"][0]))
            invalid.append(inv)
        for value in invalid:
            with self.assertRaises(ValueError):
                detect_providers(value)

    def test_rule_identity_and_detection_do_not_modify_original_inventory(self):
        inv = physics_inventory()
        before = copy.deepcopy(inv)
        identity = rules_identity()
        self.assertEqual(len(identity["rulesSha256"]), 64)
        self.assertEqual(len(identity["producerSha256"]), 64)
        detect_providers(inv)
        self.assertEqual(inv, before)


if __name__ == "__main__":
    unittest.main()
