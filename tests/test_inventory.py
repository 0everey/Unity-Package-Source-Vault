import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from uvault.inventory import fingerprint_archive, inventory_directory, source_set_sha256


def make_tar(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for path, content in files.items():
            content = content.encode() if isinstance(content, str) else content
            entry = tarfile.TarInfo(path)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


class InventoryTests(unittest.TestCase):
    def test_archive_directory_source_set_equality_and_canonical_unicode(self):
        files = {"Runtime/中文.cs": "namespace Example { class First {} }", "package.json": "{}"}
        archive = make_tar({"package/" + p: c for p, c in files.items()})
        fingerprint = fingerprint_archive(archive, "tgz")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for path, content in files.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            observed = inventory_directory(root)
        self.assertEqual(fingerprint["sourceSetSha256"], observed["sourceSetSha256"])
        expected = [{"path": "Runtime/中文.cs", "sha256": hashlib.sha256(files["Runtime/中文.cs"].encode()).hexdigest()}]
        self.assertEqual(source_set_sha256(fingerprint["files"]), hashlib.sha256(json.dumps(expected, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest())
        self.assertEqual(fingerprint["artifactSha256"], hashlib.sha256(archive).hexdigest())

    def test_archive_rejects_traversal_duplicate_and_symlink(self):
        for name in ("../escape.cs", "C:/escape.cs", "/escape.cs", "safe/../escape.cs"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                fingerprint_archive(make_tar({name: "class Evil {}"}), "tgz")
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            entry = tarfile.TarInfo("link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "elsewhere"
            archive.addfile(entry)
        with self.assertRaises(ValueError):
            fingerprint_archive(output.getvalue(), "tar")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("package/a.cs", "class A {}")
            archive.writestr("package/./a.cs", "class B {}")
        with self.assertRaises(ValueError):
            fingerprint_archive(output.getvalue(), "zip")

    def test_asmdef_nearest_and_guid_asmref_do_not_use_first_directory(self):
        guid = "a" * 32
        files = {
            "package/OddRoot/NotFolderName.asmdef": json.dumps({"name": "Real.Runtime"}),
            "package/OddRoot/NotFolderName.asmdef.meta": "fileFormatVersion: 2\nguid: " + guid,
            "package/OddRoot/A.cs": "namespace Real { class A {} }",
            "package/Shared/Shared.asmref": json.dumps({"reference": "GUID:" + guid}),
            "package/Shared/B.cs": "namespace Real { class B {} }",
            "package/OddRoot/Child/Nested.asmdef": json.dumps({"name": "Nested.Runtime"}),
            "package/OddRoot/Child/C.cs": "class C {}",
            "package/Editor/D.cs": "class D {}",
        }
        fingerprint = fingerprint_archive(make_tar(files), "tgz")
        ownership = {f["path"]: f.get("assembly") for f in fingerprint["files"]}
        self.assertEqual(ownership["OddRoot/A.cs"], "Real.Runtime")
        self.assertEqual(ownership["Shared/B.cs"], "Real.Runtime")
        self.assertEqual(ownership["OddRoot/Child/C.cs"], "Nested.Runtime")
        self.assertEqual(ownership["Editor/D.cs"], "Assembly-CSharp-Editor")

    def test_unresolved_asmref_is_unknown_not_inherited_default(self):
        fingerprint = fingerprint_archive(make_tar({
            "package/Runtime/Broken.asmref": '{"reference":"GUID:ffffffffffffffffffffffffffffffff"}',
            "package/Runtime/A.cs": "class A {}"}), "tgz")
        source = next(f for f in fingerprint["files"] if f["path"].endswith(".cs"))
        self.assertIsNone(source["assembly"])
        self.assertEqual(source["ownershipBasis"], "ambiguous-assembly-boundary")

    def test_conditional_all_branches_and_explicit_profile_are_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Runtime.asmdef").write_text(json.dumps({"name": "Example", "defineConstraints": ["FEATURE || ALT"]}), encoding="utf-8")
            (root / "A.cs").write_text("namespace Example;\n#if FEATURE\nclass Enabled {}\n#else\nclass Disabled {}\n#endif\n", encoding="utf-8")
            unknown = inventory_directory(root)
            explicit = inventory_directory(root, {"defines": ["FEATURE"], "definesComplete": True, "platform": "Standalone"})
            incomplete = inventory_directory(root, {"defines": ["FEATURE"]})
        self.assertEqual(unknown["types"], ["Example.Disabled", "Example.Enabled"])
        self.assertFalse(unknown["profileVerified"])
        self.assertIsNone(unknown["assemblies"][0]["active"])
        self.assertEqual(explicit["activeTypes"], ["Example.Enabled"])
        self.assertFalse(explicit["profileVerified"])
        self.assertEqual(incomplete["activeTypes"], [])
        self.assertEqual(explicit["sourceSetSha256"], incomplete["sourceSetSha256"])

    def test_platform_and_version_defines_preserved_without_assumed_exclusion(self):
        fingerprint = fingerprint_archive(make_tar({
            "package/A.asmdef": json.dumps({"name": "A", "includePlatforms": ["Editor"],
                "excludePlatforms": [], "defineConstraints": ["VERSION_OK"],
                "versionDefines": [{"name": "com.test", "expression": "[1.0,2.0)", "define": "VERSION_OK"}]}),
            "package/A.cs": "class A {}"}), "tgz")
        self.assertIsNone(fingerprint["assemblies"][0]["active"])
        self.assertTrue(fingerprint["assemblies"][0]["versionDefines"])
        self.assertFalse(fingerprint["profileVerified"])

    def test_unknown_platform_and_editor_default_do_not_claim_exclusion(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Runtime.asmdef").write_text('{"name":"OnlyEditor","includePlatforms":["Editor"]}', encoding="utf-8")
            (root / "A.cs").write_text("class A {}", encoding="utf-8")
            unknown = inventory_directory(root, {"platform": "invented-platform"})
            player = inventory_directory(root, {"platform": "WindowsStandalone64"})
        self.assertIsNone(unknown["assemblies"][0]["active"])
        self.assertFalse(player["assemblies"][0]["active"])


    def test_comments_strings_and_dummy_dll_are_not_source_implementations(self):
        fingerprint = fingerprint_archive(make_tar({
            "package/A.cs": '// namespace Fake { class Fake {} }\nnamespace Actual { class Real { string x = "class Nope {}"; } }',
            "package/DummyDll/Fake.dll": b"MZ\0Il2CppDummyDll\0"}), "tgz")
        self.assertEqual(fingerprint["types"], ["Actual.Real"])
        self.assertTrue(next(f for f in fingerprint["files"] if f["path"].endswith(".dll"))["dummyDll"])


if __name__ == "__main__":
    unittest.main()
