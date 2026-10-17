import copy
import unittest

from uvault.materialize import canonical_hash
from uvault.remaker import export_remaker


class RemakerTests(unittest.TestCase):
    def lock(self):
        return {"schemaVersion": "1.0", "catalogCommit": "a" * 40,
            "input": {"kind": "remaker", "fingerprint": {"sha256": "target"}},
            "profile": {"platform": "Windows", "verified": False},
            "libraries": [{"packageId": "test.pkg", "version": "1.0", "variantId": "upstream", "status": "pinned-source",
                "sourceUrl": "https://example.test/repo", "sourceRef": "v1.0", "disposition": "mirror-allowed",
                "artifact": {"sha256": "b" * 64, "url": "https://example.test/test.zip"},
                "evidence": [{"kind": "lock-provenance"}], "suggestedReuseScope": ["source-reference"],
                "fingerprint": {"sourceSetSha256": "c" * 64}, "skipNativeRecovery": True,
                "conflicts": [{"kind": "unverified-profile"}]}], "unresolved": [], "unknown": [{"assembly": "Game"}], "conflicts": []}

    def test_complete_stable_pending_export(self):
        lock = self.lock()
        original = copy.deepcopy(lock)
        receipt = {"schemaVersion": "1.0", "lockSha256": canonical_hash(lock), "libraries": [], "unresolved": []}
        result = export_remaker(lock, receipt)
        self.assertEqual(result, export_remaker(lock, receipt))
        self.assertEqual(lock, original)
        self.assertEqual(result["lockSha256"], canonical_hash(lock))
        self.assertEqual(result["inputIdentity"], lock["input"])
        self.assertEqual(result["profile"], lock["profile"])
        self.assertEqual(result["sourceRefs"][0]["sourceRef"], "v1.0")
        self.assertEqual(result["matchBasis"][0]["status"], "pinned-source")
        self.assertTrue(result["conflicts"])
        self.assertEqual(result["unknown"], lock["unknown"])
        self.assertEqual(result["materialized"], receipt)
        self.assertEqual(result["adoptionStatus"], "pending")
        self.assertFalse(result["skipNativeRecovery"])
        self.assertFalse(result["libraries"][0]["skipNativeRecovery"])
        self.assertEqual(result["fetchInstructions"][0]["action"], "materialize")

    def test_mismatched_receipt_rejected(self):
        with self.assertRaisesRegex(ValueError, "does not belong"):
            export_remaker(self.lock(), {"lockSha256": "wrong"})


if __name__ == "__main__":
    unittest.main()
