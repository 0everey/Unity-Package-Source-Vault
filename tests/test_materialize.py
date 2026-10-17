import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from uvault.materialize import materialize, RECEIPT_NAME


def archive(files=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as writer:
        for name, content in (files or {"package/Runtime/Source.cs": "class Source {}", "package/LICENSE": "MIT"}).items():
            writer.writestr(name, content)
    return output.getvalue()


def lock(data):
    return {"schemaVersion": "1.0", "catalogCommit": "a" * 40, "input": {}, "profile": None, "unresolved": [], "conflicts": [],
            "libraries": [{"packageId": "test.pkg", "version": "1.0", "variantId": "upstream", "disposition": "mirror-allowed",
                           "artifact": {"url": "https://example.test/test.zip", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "format": "zip"}}]}


class MaterializeTests(unittest.TestCase):
    def test_valid_and_verified_reuse_without_download(self):
        data = archive()
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data) as download:
            target = Path(temp) / "usage"
            receipt = materialize(lock(data), target)
            self.assertEqual(receipt["libraries"][0]["status"], "materialized")
            self.assertTrue((Path(receipt["libraries"][0]["path"]) / "Runtime/Source.cs").is_file())
            download.assert_called_once()
            receipt = materialize(lock(data), target, offline=True)
            self.assertEqual(receipt["libraries"][0]["status"], "reused")
            download.assert_called_once()
            self.assertEqual(list(Path(temp).glob(".uvault-stage-*")), [])

    def test_changed_existing_content_refuses_reuse(self):
        data = archive()
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
            target = Path(temp) / "usage"
            receipt = materialize(lock(data), target)
            source = Path(receipt["libraries"][0]["path"]) / "Runtime/Source.cs"
            source.write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed"):
                materialize(lock(data), target)
            self.assertEqual(source.read_text(encoding="utf-8"), "changed")

    def test_checksum_failure_cleans_stage_and_leaves_no_target(self):
        data = archive()
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data + b"changed"):
            target = Path(temp) / "usage"
            with self.assertRaisesRegex(ValueError, "checksum"):
                materialize(lock(data), target)
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_traversal_case_collision_and_prefix_collision_rejected(self):
        for files in ({"../escape": "bad"}, {"package/A.cs": "a", "package/a.cs": "b"}, {"package/file": "a", "package/file/nested": "b"}, {"C:/escape": "bad"}, {"package/CON.cs": "bad"}):
            data = archive(files)
            with self.subTest(files=files), tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
                with self.assertRaises(ValueError):
                    materialize(lock(data), Path(temp) / "usage")
                self.assertEqual(list(Path(temp).iterdir()), [])

    def test_symlink_archive_rejected(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as writer:
            member = zipfile.ZipInfo("package/link")
            member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            writer.writestr(member, "outside")
        data = output.getvalue()
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
            with self.assertRaisesRegex(ValueError, "links"):
                materialize(lock(data), Path(temp) / "usage")
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_duplicate_archive_entries_rejected(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as writer:
            writer.writestr("package/A.cs", "a")
            with self.assertWarns(UserWarning):
                writer.writestr("package/A.cs", "b")
        data = output.getvalue()
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                materialize(lock(data), Path(temp) / "usage")

    def test_tar_hardlinks_rejected(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as writer:
            member = tarfile.TarInfo("package/link")
            member.type = tarfile.LNKTYPE
            member.linkname = "outside"
            writer.addfile(member)
        data = output.getvalue()
        value = lock(data)
        value["libraries"][0]["artifact"]["format"] = "tar.gz"
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
            with self.assertRaisesRegex(ValueError, "links"):
                materialize(value, Path(temp) / "usage")

    def test_restricted_and_offline_are_explicit_partial(self):
        data = archive()
        for disposition, offline, reason in (("user-provided-only", False, "user-provided-only"), ("official-fetch-only", True, "offline-no-package-cache")):
            value = lock(data)
            value["libraries"][0]["disposition"] = disposition
            with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download") as download:
                receipt = materialize(value, Path(temp) / "usage", offline=offline)
                self.assertFalse(receipt["libraries"])
                self.assertEqual(receipt["unresolved"][0]["reason"], reason)
                download.assert_not_called()

    def test_official_fetch_only_direct_verified_url_is_usable(self):
        data = archive()
        value = lock(data)
        value["libraries"][0]["disposition"] = "official-fetch-only"
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
            self.assertEqual(len(materialize(value, Path(temp) / "usage")["libraries"]), 1)

    def test_extra_file_and_different_lock_refuse_reuse(self):
        data = archive()
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
            target = Path(temp) / "usage"
            materialize(lock(data), target)
            extra = target / "foreign.txt"
            extra.write_text("foreign", encoding="utf-8")
            with self.assertRaises(ValueError):
                materialize(lock(data), target)
            extra.unlink()
            value = lock(data)
            value["profile"] = {"changed": True}
            with self.assertRaisesRegex(ValueError, "different lock"):
                materialize(value, target)

    def test_receipt_cannot_silently_omit_locked_library(self):
        data = archive()
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
            target = Path(temp) / "usage"
            receipt = materialize(lock(data), target)
            receipt["libraries"] = []
            (target / RECEIPT_NAME).write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "silently omits"):
                materialize(lock(data), target)

    def test_catalog_full_file_inventory_is_verified(self):
        data = archive()
        value = lock(data)
        value["libraries"][0]["fingerprint"] = {"files": [{"path": "Runtime/Source.cs", "sha256": "0" * 64}]}
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
            with self.assertRaisesRegex(ValueError, "catalog inventory"):
                materialize(value, Path(temp) / "usage")
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_unitypackage_uses_same_logical_paths_as_inventory(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as writer:
            for name, content in {"guid/pathname": b"Assets/Runtime/A.cs", "guid/asset": b"class A {}", "guid/asset.meta": b"guid: example"}.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                writer.addfile(member, io.BytesIO(content))
        data = output.getvalue()
        value = lock(data)
        value["libraries"][0]["artifact"]["format"] = "unitypackage"
        with tempfile.TemporaryDirectory() as temp, patch("uvault.materialize._download", return_value=data):
            receipt = materialize(value, Path(temp) / "usage")
            output = Path(receipt["libraries"][0]["path"])
            self.assertEqual((output / "Runtime/A.cs").read_bytes(), b"class A {}")
            self.assertTrue((output / "Runtime/A.cs.meta").is_file())


if __name__ == "__main__":
    unittest.main()
