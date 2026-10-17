import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from uvault.fingerprints import externalize_fingerprint, load_full_fingerprint
from uvault import fingerprints
from uvault.inventory import fingerprint_archive


def sample_version():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("root/A.asmdef", json.dumps({"name": "A.Runtime"}))
        archive.writestr("root/A.cs", "namespace Example { public class A {} }")
        archive.writestr("root/Sub/B.asmdef", json.dumps({"name": "B.Runtime"}))
        archive.writestr("root/Sub/B.cs", "#if SOMETHING\nnamespace Example { public class B {} }\n#endif")
        archive.writestr("root/LICENSE", "Synthetic test fixture")
    data = stream.getvalue()
    return {"version": "1.0.0", "variantId": "test", "artifact": {"sha256": hashlib.sha256(data).hexdigest()},
            "fingerprint": fingerprint_archive(data, "zip")}


class RemoteBytes(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


class FingerprintShardTests(unittest.TestCase):
    def test_roundtrip_preserves_full_manifest_and_scoped_types(self):
        version = sample_version()
        original = copy.deepcopy(version["fingerprint"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertTrue(externalize_fingerprint(root, version))
            summary = version["fingerprint"]
            self.assertNotIn("files", summary)
            self.assertNotIn("typeDeclarations", summary)
            self.assertNotIn("conditionalSources", summary)
            self.assertEqual(summary["sourceSetSha256"], original["sourceSetSha256"])
            self.assertEqual(summary["fileCount"], 5)
            self.assertEqual(summary["sourceFileCount"], 2)
            self.assertTrue(summary["sourceSetNonEmpty"])
            self.assertEqual(summary["conditionalSourceCount"], 1)
            self.assertFalse(summary["profileVerified"])
            scopes = {a["name"]: a.get("types", []) for a in summary["assemblies"]}
            self.assertEqual(scopes, {"A.Runtime": ["Example.A"], "B.Runtime": ["Example.B"]})
            self.assertTrue(all("sourceFiles" not in a and a["profileVerified"] is False for a in summary["assemblies"]))
            self.assertEqual(load_full_fingerprint(version, {"registry": root / "catalog.json"}), original)
            self.assertFalse(externalize_fingerprint(root, version))
            self.assertEqual(len(list(root.rglob("*json.gz"))), 1)

    def test_same_bytes_deduplicate_without_rewriting(self):
        version = sample_version()
        second = copy.deepcopy(version)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            path = root / version["fingerprint"]["fileManifestRef"]["path"]
            before = (path.read_bytes(), path.stat().st_mtime_ns)
            externalize_fingerprint(root, second)
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)
            self.assertEqual(second["fingerprint"]["fileManifestRef"], version["fingerprint"]["fileManifestRef"])
            self.assertEqual(len(list(root.rglob("*.json.gz"))), 1)

    def test_producer_update_writes_distinct_object(self):
        version = sample_version()
        changed = copy.deepcopy(version)
        changed["fingerprint"]["fingerprintProducer"]["version"] = "future-version"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            externalize_fingerprint(root, changed)
            self.assertNotEqual(version["fingerprint"]["fileManifestRef"]["path"], changed["fingerprint"]["fileManifestRef"]["path"])
            self.assertEqual(len(list(root.rglob("*.json.gz"))), 2)
            self.assertEqual(load_full_fingerprint(changed, {"registry": str(root / "catalog.json")})["fingerprintProducer"]["version"], "future-version")

    def test_cross_platform_gzip_reuses_exact_manifest_without_overwriting(self):
        version=sample_version();second=copy.deepcopy(version);original=copy.deepcopy(version["fingerprint"])
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            externalize_fingerprint(root,version)
            path=root/version["fingerprint"]["fileManifestRef"]["path"]
            data=path.read_bytes();foreign=data[:9]+b"\x03"+data[10:]
            path.write_bytes(foreign)
            stamp=path.stat().st_mtime_ns
            externalize_fingerprint(root,second)
            self.assertEqual(path.read_bytes(),foreign)
            self.assertEqual(path.stat().st_mtime_ns,stamp)
            self.assertEqual(second["fingerprint"]["fileManifestRef"]["sha256"],hashlib.sha256(foreign).hexdigest())
            self.assertEqual(load_full_fingerprint(second,{"registry":root/"catalog.json"}),original)

    def test_changed_bytes_at_existing_object_are_never_overwritten(self):
        version = sample_version()
        changed = copy.deepcopy(version)
        changed["fingerprint"]["diagnostics"].append({"kind": "different-observation"})
        original_changed = copy.deepcopy(changed)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            path = root / version["fingerprint"]["fileManifestRef"]["path"]
            stored = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "different bytes"):
                externalize_fingerprint(root, changed)
            self.assertEqual(changed, original_changed)
            self.assertEqual(path.read_bytes(), stored)
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_failed_atomic_write_cleans_its_own_temporary_file(self):
        version = sample_version()
        original = copy.deepcopy(version)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(fingerprints.os, "link", side_effect=OSError("synthetic write failure")):
                with self.assertRaises(OSError):
                    externalize_fingerprint(root, version)
            self.assertEqual(version, original)
            self.assertEqual(list(root.rglob("*.tmp")), [])
            self.assertEqual(list(root.rglob("*.json.gz")), [])

    def test_corruption_and_wrong_size_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            version = sample_version()
            externalize_fingerprint(root, version)
            path = root / version["fingerprint"]["fileManifestRef"]["path"]
            path.write_bytes(path.read_bytes() + b"corruption")
            with self.assertRaisesRegex(ValueError, "checksum|size"):
                load_full_fingerprint(version, {"registry": str(root / "catalog.json")})

    def test_unsafe_reference_paths_are_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            version = sample_version()
            externalize_fingerprint(root, version)
            for unsafe in ("../outside.json.gz", "/absolute.json.gz", "C:/outside.json.gz", "fingerprints/../../outside", "fingerprints\\outside", "https://example.invalid/out", "fingerprints/%2e%2e/out", "fingerprints/x?secret", "fingerprints/x#fragment"):
                changed = copy.deepcopy(version)
                changed["fingerprint"]["fileManifestRef"]["path"] = unsafe
                with self.subTest(path=unsafe), self.assertRaises(ValueError):
                    load_full_fingerprint(changed, {"registry": str(root / "catalog.json")})

    def test_local_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            root = Path(temporary)
            version = sample_version()
            externalize_fingerprint(root, version)
            path = root / version["fingerprint"]["fileManifestRef"]["path"]
            other = Path(outside) / path.name
            other.write_bytes(path.read_bytes())
            path.unlink()
            try:
                path.symlink_to(other)
            except OSError as exc:
                self.skipTest("This host does not permit synthetic symlinks: " + type(exc).__name__)
            with self.assertRaisesRegex(ValueError, "link"):
                load_full_fingerprint(version, {"registry": str(root / "catalog.json")})

    def test_empty_source_set_cannot_claim_nonempty_equality(self):
        version = sample_version()
        version["fingerprint"]["files"] = []
        version["fingerprint"]["sourceSetSha256"] = hashlib.sha256(b"[]").hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            self.assertEqual(version["fingerprint"]["sourceFileCount"], 0)
            self.assertFalse(version["fingerprint"]["sourceSetNonEmpty"])
            self.assertEqual(load_full_fingerprint(version, {"registry": str(root / "catalog.json")})["files"], [])

    def test_unverified_ownership_never_gets_scoped_types_from_global_names(self):
        version = sample_version()
        fp = version["fingerprint"]
        fp["assemblies"][0]["ownershipVerified"] = False
        fp["assemblies"][0]["types"] = ["Example.A"]
        fp["typeDeclarations"].append({"fullName": "Guessed.Unknown", "assemblyIdentity": {"name": "B.Runtime"}})
        with tempfile.TemporaryDirectory() as temporary:
            externalize_fingerprint(Path(temporary), version)
        scopes = {a["name"]: a.get("types", []) for a in version["fingerprint"]["assemblies"]}
        self.assertEqual(scopes["A.Runtime"], [])
        self.assertEqual(scopes["B.Runtime"], ["Example.B"])

    def test_legacy_producer_is_not_silently_invented(self):
        version = sample_version()
        version["fingerprint"].pop("fingerprintProducer")
        original = copy.deepcopy(version["fingerprint"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            self.assertNotIn("fingerprintProducer", version["fingerprint"])
            self.assertIsNone(version["fingerprint"]["fileManifestRef"]["producer"])
            self.assertEqual(load_full_fingerprint(version, {"registry": str(root / "catalog.json")}), original)

    def test_inline_fingerprint_returns_independent_original_copy(self):
        version = sample_version()
        loaded = load_full_fingerprint(version, {})
        self.assertEqual(loaded, version["fingerprint"])
        loaded["files"].clear()
        self.assertTrue(version["fingerprint"]["files"])
        self.assertEqual(load_full_fingerprint({"fingerprint": None}, {}), {})
        self.assertFalse(externalize_fingerprint(Path("unused"), {"fingerprint": None}))

    def test_remote_load_uses_one_pinned_object_without_cache(self):
        version = sample_version()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            reference = version["fingerprint"]["fileManifestRef"]
            data = (root / reference["path"]).read_bytes()
            commit = "a" * 40
            registry = "https://raw.githubusercontent.com/owner/repo/" + commit + "/catalog/catalog.json"
            expected_url = registry.rsplit("/", 1)[0] + "/" + reference["path"]
            with patch.object(fingerprints.urllib.request, "urlopen", return_value=RemoteBytes(data, expected_url)) as opener:
                loaded = load_full_fingerprint(version, {"registry": registry, "catalogCommit": commit})
            self.assertEqual(opener.call_count, 1)
            self.assertEqual(opener.call_args.args[0].full_url, expected_url)
            self.assertTrue(loaded["files"])
            with patch.object(fingerprints.urllib.request, "urlopen") as opener:
                with self.assertRaisesRegex(ValueError, "immutable"):
                    load_full_fingerprint(version, {"registry": registry.replace(commit, "main")})
                opener.assert_not_called()

    def test_content_with_valid_compressed_checksum_still_needs_valid_metadata(self):
        version = sample_version()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            reference = version["fingerprint"]["fileManifestRef"]
            corrupt = gzip.compress(b"not JSON", mtime=0)
            (root / reference["path"]).write_bytes(corrupt)
            reference.update(sha256=hashlib.sha256(corrupt).hexdigest(), size=len(corrupt))
            with self.assertRaisesRegex(ValueError, "Invalid compressed"):
                load_full_fingerprint(version, {"registry": str(root / "catalog.json")})

    def test_summary_keeps_only_needed_dll_hashes(self):
        version = sample_version()
        version["fingerprint"]["files"].extend([
            {"path": "lib/Actual.dll", "sha256": "b" * 64, "size": 42, "kind": "managed-or-native-binary", "dummyDll": False},
            {"path": "lib/Other.bin", "sha256": "c" * 64, "size": 12, "kind": "other"}])
        with tempfile.TemporaryDirectory() as temporary:
            externalize_fingerprint(Path(temporary), version)
        self.assertEqual(version["fingerprint"]["binaryFingerprints"], [{"path": "lib/Actual.dll", "sha256": "b" * 64, "size": 42, "dummyDll": False}])
        self.assertNotIn("files", version["fingerprint"])

    def test_synced_catalog_keeps_immutable_remote_fingerprint_origin(self):
        version = sample_version()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            reference = version["fingerprint"]["fileManifestRef"]
            data = (root / reference["path"]).read_bytes()
            commit = "a" * 40
            origin = "https://raw.githubusercontent.com/owner/repo/" + commit + "/catalog/catalog.json"
            url = origin.rsplit("/", 1)[0] + "/" + reference["path"]
            with patch.object(fingerprints.urllib.request, "urlopen", return_value=RemoteBytes(data, url)) as opener:
                full = load_full_fingerprint(version, {"registry": str(root / "sync" / "catalog.json"), "fingerprintRegistry": origin, "catalogCommit": commit})
            self.assertTrue(full["files"])
            self.assertEqual(opener.call_args.args[0].full_url, url)

    def test_producer_and_artifact_relabeling_cannot_reuse_a_shard(self):
        version = sample_version()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            changed = copy.deepcopy(version)
            changed["fingerprint"]["fingerprintProducer"]["version"] = "different"
            with self.assertRaisesRegex(ValueError, "producer"):
                load_full_fingerprint(changed, {"registry": str(root / "catalog.json")})
            changed = copy.deepcopy(version)
            changed["artifact"]["sha256"] = "d" * 64
            with self.assertRaisesRegex(ValueError, "artifact"):
                load_full_fingerprint(changed, {"registry": str(root / "catalog.json")})

    def test_unknown_storage_version_and_decompression_limit_are_rejected(self):
        version = sample_version()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            changed = copy.deepcopy(version)
            changed["fingerprint"]["fingerprintStorageVersion"] = "future"
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                load_full_fingerprint(changed, {"registry": str(root / "catalog.json")})
            with patch.object(fingerprints, "MAX_FULL_FINGERPRINT_BYTES", 32):
                with self.assertRaisesRegex(ValueError, "size limit"):
                    load_full_fingerprint(version, {"registry": str(root / "catalog.json")})

    def test_redirect_cannot_change_commit_pinned_location(self):
        version = sample_version()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            externalize_fingerprint(root, version)
            reference = version["fingerprint"]["fileManifestRef"]
            data = (root / reference["path"]).read_bytes()
            registry = "https://raw.githubusercontent.com/owner/repo/" + "a" * 40 + "/catalog.json"
            with patch.object(fingerprints.urllib.request, "urlopen", return_value=RemoteBytes(data, "https://example.invalid/floating")):
                with self.assertRaisesRegex(ValueError, "redirect"):
                    load_full_fingerprint(version, {"registry": registry})


if __name__ == "__main__":
    unittest.main()
