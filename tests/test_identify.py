import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from uvault.identify import identify
from uvault.inventory import fingerprint_archive


def archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        for path, text in files.items():
            data = text.encode() if isinstance(text, str) else text
            entry = tarfile.TarInfo("package/" + path)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
    return output.getvalue()


def version(number="1.0.0", variant="upstream", files=None):
    data = archive(files or {"Runtime/A.cs": "namespace Example { class A {} }", "Runtime/R.asmdef": '{"name":"Example.Runtime"}'})
    return {"version": number, "variantId": variant, "sourceRef": "b" * 40,
            "sourceUrl": "https://example.test/project", "disposition": "mirror-allowed", "fetchStatus":"collected",
            "upstream":{"registry":"https://registry.example.test"},
            "license": {"expression": "MIT", "sha256": "c" * 64, "evidenceUrl": "https://example.test/license"},
            "artifact": {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "format": "tgz"},
            "fingerprint": fingerprint_archive(data, "tgz")}


def catalog(*versions):
    return {"catalogCommit": "a" * 40, "packages": [{"id": "com.example.runtime", "versions": list(versions)}]}


class IdentifyTests(unittest.TestCase):
    def write_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_actual_archive_and_complete_source_are_exact(self):
        files = {"Runtime/A.cs": "namespace Example { class A {} }", "Runtime/R.asmdef": '{"name":"Example.Runtime"}'}
        v = version(files=files)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tar = root / "target.tgz"
            tar.write_bytes(archive(files))
            direct = identify(tar, catalog(v))
            source = root / "source"
            for path, text in files.items():
                target = source / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            expanded = identify(source, catalog(v))
        for result in (direct, expanded):
            self.assertEqual(result["matches"][0]["status"], "exact-artifact")
            self.assertFalse(result["matches"][0]["skipNativeRecovery"])
            self.assertTrue(result["matches"][0]["suggestedReuseScope"])

    def test_empty_source_sets_never_establish_exact(self):
        v = version(files={"README.md": "metadata only"})
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, "README.md").write_text("metadata only")
            result = identify(temp, catalog(v))
        self.assertEqual(result["matches"], [])
        self.assertTrue(result["unknown"])

    def test_sdk_archive_distinguishes_shared_sources_and_dlls_both_directions(self):
        common = {"Runtime/A.cs": "namespace Example { class A {} }", "lib/shared.dll": b"MZ shared"}
        a = dict(common, **{"lib/integration.dll": b"MZ A"})
        b = dict(common, **{"lib/integration.dll": b"MZ B"})
        va, vb = version("1.0.0", files=a), version("1.0.1", files=b)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp, "sdk.tgz")
            for number, files in [("1.0.0", a), ("1.0.1", b)]:
                target.write_bytes(archive(files))
                match = identify(target, catalog(va, vb))["matches"][0]
                self.assertEqual(match["status"], "exact-artifact")
                self.assertEqual([v["version"] for v in match["candidates"]], [number])

    def test_sdk_shared_subsets_remain_ambiguous_and_changed_binary_is_not_exact(self):
        common = {"Runtime/A.cs": "namespace Example { class A {} }", "lib/shared.dll": b"MZ shared"}
        va = version("1.0.0", files=dict(common, **{"lib/integration.dll": b"MZ A"}))
        vb = version("1.0.1", files=dict(common, **{"lib/integration.dll": b"MZ B"}))
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp, "sdk.tgz")
            for files in [common, {"Runtime/A.cs": common["Runtime/A.cs"]}, {"lib/shared.dll": b"MZ shared"}]:
                target.write_bytes(archive(files))
                match = identify(target, catalog(va, vb))["matches"][0]
                self.assertEqual(match["status"], "ambiguous")
                self.assertEqual(len(match["candidates"]), 2)
            target.write_bytes(archive(dict(common, **{"lib/integration.dll": b"MZ modified"})))
            result = identify(target, catalog(va, vb))
        self.assertNotEqual(result["matches"][0]["status"], "exact-artifact")
        self.assertEqual(result["matches"][0]["suggestedReuseScope"], [])
        self.assertTrue(any(c["kind"] == "modified-or-different-binary-target" for c in result["conflicts"]))

    def test_identical_versions_and_variants_are_explicitly_ambiguous(self):
        v1, v2 = version(), version("2.0.0", "other")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "target.tgz")
            path.write_bytes(archive({"Runtime/A.cs": "namespace Example { class A {} }", "Runtime/R.asmdef": '{"name":"Example.Runtime"}'}))
            result = identify(path, catalog(v1, v2))
        match = result["matches"][0]
        self.assertEqual(match["status"], "ambiguous")
        self.assertEqual(len(match["candidates"]), 2)
        self.assertEqual(match["suggestedReuseScope"], [])

    def test_lock_only_is_pinned_but_changed_embedded_body_is_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_json(root / "Packages" / "manifest.json", {"dependencies": {"com.example.runtime": "1.0.0"}})
            self.write_json(root / "Packages" / "packages-lock.json", {"dependencies": {"com.example.runtime": {"version": "1.0.0", "source": "registry", "url":"https://registry.example.test", "depth": 0}}})
            pinned = identify(root, catalog(version()))
            package = root / "Packages" / "com.example.runtime"
            self.write_json(package / "package.json", {"name": "com.example.runtime", "version": "1.0.0"})
            (package / "Runtime").mkdir()
            (package / "Runtime" / "A.cs").write_text("namespace Example { class A { int changed; } }", encoding="utf-8")
            modified = identify(root, catalog(version()))
            via_lock = identify(root / "Packages" / "packages-lock.json", catalog(version()))
        self.assertEqual(pinned["matches"][0]["status"], "pinned-source")
        for result in (modified, via_lock):
            self.assertEqual(result["matches"][0]["status"], "strong-candidate")
            self.assertTrue(any(c["kind"] == "modified-or-incomplete-target" for c in result["conflicts"]))
            self.assertFalse(result["matches"][0]["skipNativeRecovery"])

    def test_lock_version_absent_and_unknown_packages_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            self.write_json(Path(temp, "packages-lock.json"), {"dependencies": {
                "com.example.runtime": {"version": "9.0.0", "source": "registry"},
                "com.private.unknown": {"version": "1.0.0", "source": "registry"}}})
            result = identify(Path(temp, "packages-lock.json"), catalog(version()))
        self.assertEqual(result["matches"], [])
        self.assertEqual(len(result["unknown"]), 2)

    def test_namespace_only_and_same_assembly_version_do_not_claim_exact(self):
        v = version()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_json(root / "identity.json", {"assemblies": [{"scope": {"name": "Example.Runtime", "version": "1.0.0.0"}}],
                "types": [{"fullName": "Example.Unrelated", "namespace": "Example"}]})
            result = identify(root / "identity.json", catalog(v))
        self.assertEqual(result["matches"][0]["status"], "unknown")
        self.assertFalse(result["matches"][0]["skipNativeRecovery"])

    def test_real_remaker_record_shape_and_dummy_hash_never_exact(self):
        binary = b"MZ\0Il2CppDummyDll\0"
        v = version(files={"Example.Runtime.dll": binary, "Runtime/A.cs": "namespace Example { class A {} }", "Runtime/R.asmdef": '{"name":"Example.Runtime"}'})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_json(root / "assemblies.json", [{"id": "a000", "path": "metadata/DummyDll/Example.Runtime.dll", "sha256": hashlib.sha256(binary).hexdigest(),
                "scope": {"name": "Example.Runtime", "version": "1.0.0.0", "publicKeyToken": "null"},
                "origin": "dump-image-name-match", "references": [{"scope": {"name": "Il2CppDummyDll"}}]}])
            self.write_json(root / "types.json", [{"id": "a000:0x02000001", "assemblyId": "a000", "fullName": "Example.A", "namespace": "Example", "members": {"fields": 0, "methods": 1}}])
            result = identify(root, catalog(v))
            dll = root / "Example.Runtime.dll"
            dll.write_bytes(binary)
            raw = identify(dll, catalog(v))
        self.assertEqual(result["matches"][0]["status"], "strong-candidate")
        self.assertTrue(any(c["kind"] == "dummy-dll-not-original-binary" for c in result["conflicts"]))
        self.assertFalse(any(m["status"] == "exact-artifact" for m in raw["matches"]))

    def test_actual_dll_bytes_can_match_binary_only_package(self):
        binary = b"MZ\0synthetic-original-byte-control\0"
        v = version(files={"lib/netstandard2.0/Example.Runtime.dll": binary})
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "Example.Runtime.dll")
            path.write_bytes(binary)
            result = identify(path, catalog(v))
        self.assertEqual(result["matches"][0]["status"], "exact-artifact")
        self.assertEqual(result["matches"][0]["evidence"][0]["kind"], "actual-dll-bytes-equal")

    def test_trimmed_partial_source_keeps_conflict(self):
        v = version(files={"Runtime/A.cs": "namespace Example { class A {} }", "Runtime/B.cs": "namespace Example { class B {} }", "Runtime/R.asmdef": '{"name":"Example.Runtime"}'})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Runtime").mkdir()
            (root / "Runtime" / "A.cs").write_text("namespace Example { class A {} }", encoding="utf-8")
            result = identify(root, catalog(v))
        self.assertEqual(result["matches"][0]["status"], "strong-candidate")
        self.assertTrue(any(c["kind"] == "partial-or-modified-declarations" for c in result["conflicts"]))

    def test_changed_source_with_identical_types_has_source_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Runtime").mkdir()
            (root / "Runtime" / "A.cs").write_text("namespace Example { class A { int changed; } }", encoding="utf-8")
            result = identify(root, catalog(version()))
        self.assertTrue(any(c["kind"] == "modified-or-incomplete-source-set" for c in result["conflicts"]))
        self.assertNotEqual(result["matches"][0]["status"], "exact-artifact")

    def test_structure_hash_without_actual_dll_bytes_is_not_exact(self):
        binary = b"MZ\0synthetic-original-byte-control\0"
        v = version(files={"Example.Runtime.dll": binary})
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "identity.json")
            self.write_json(path, {"assemblies": [{"scope": {"name": "Example.Runtime"}, "sha256": hashlib.sha256(binary).hexdigest(), "path": "Managed/Example.Runtime.dll"}], "types": []})
            result = identify(path, catalog(v))
        self.assertFalse(any(m["status"] == "exact-artifact" for m in result["matches"]))

    def test_git_lock_requires_full_immutable_commit_and_catalog_ref(self):
        v = version()
        v["sourceUrl"]="https://example.test/repo"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "packages-lock.json"
            self.write_json(path, {"dependencies": {"com.example.runtime": {"version": "https://example.test/repo.git#main", "hash": "b" * 40, "source": "git"}}})
            fixed = identify(path, catalog(v))
            self.write_json(path, {"dependencies": {"com.example.runtime": {"version": "https://example.test/repo.git#main", "hash": "main", "source": "git"}}})
            mutable = identify(path, catalog(v))
        self.assertEqual(fixed["matches"][0]["status"], "pinned-source")
        self.assertEqual(mutable["matches"][0]["status"], "strong-candidate")

    def test_matching_dll_does_not_hide_changed_embedded_source(self):
        binary = b"MZ\0synthetic-original-byte-control\0"
        v = version(files={"Runtime/A.cs": "namespace Example { class A {} }", "Plugin.dll": binary})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_json(root / "Packages" / "packages-lock.json", {"dependencies": {"com.example.runtime": {"version": "1.0.0", "source": "registry"}}})
            package = root / "Packages" / "com.example.runtime"
            self.write_json(package / "package.json", {"name": "com.example.runtime", "version": "1.0.0"})
            (package / "Runtime").mkdir()
            (package / "Runtime" / "A.cs").write_text("namespace Example { class A { int changed; } }", encoding="utf-8")
            (package / "Plugin.dll").write_bytes(binary)
            result = identify(root, catalog(v))
        self.assertEqual(result["matches"][0]["status"], "strong-candidate")
        self.assertTrue(any(c["kind"] == "modified-or-incomplete-target" for c in result["conflicts"]))


if __name__ == "__main__":
    unittest.main()
