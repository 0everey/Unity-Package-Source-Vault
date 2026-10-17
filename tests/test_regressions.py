import json
from pathlib import Path
import tempfile
import unittest
from test_identify import version, catalog
from uvault.identify import identify
from uvault.cli import _partial
from uvault.resolve import resolve
from uvault.remaker import export_remaker

class RegressionTests(unittest.TestCase):
    def write(self,path,value):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(value),encoding="utf-8")

    def test_registry_source_and_actual_archive_evidence_required_for_pinned(self):
        v=version()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"packages-lock.json"
            for url,status in (("https://registry.example.test","pinned-source"),("https://private.example.test","strong-candidate"),(None,"strong-candidate")):
                self.write(path,{"dependencies":{"com.example.runtime":{"version":"1.0.0","source":"registry","url":url}}})
                self.assertEqual(identify(path,catalog(v))["matches"][0]["status"],status)
            self.write(path,{"dependencies":{"com.example.runtime":{"version":"1.0.0","source":"registry","url":"https://registry.example.test"}}})
            v.update(artifact=None,fetchStatus="pending",sourceRef=None)
            self.assertEqual(identify(path,catalog(v))["matches"][0]["status"],"strong-candidate")

    def test_stale_cache_cannot_hide_active_embedded_modifications(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.write(root/"Packages/manifest.json",{"dependencies":{"com.example.runtime":"file:com.example.runtime"}})
            self.write(root/"Packages/packages-lock.json",{"dependencies":{"com.example.runtime":{"version":"file:com.example.runtime","source":"embedded"}}})
            for folder,number,source in ((root/"Packages/com.example.runtime","1.0.0","namespace Example { class A { int changed; } }"),
                                        (root/"Library/PackageCache/com.example.runtime@2.0.0","2.0.0","namespace Example { class A {} }")):
                self.write(folder/"package.json",{"name":"com.example.runtime","version":number})
                (folder/"Runtime").mkdir();(folder/"Runtime/A.cs").write_text(source)
                (folder/"Runtime/R.asmdef").write_text('{"name":"Example.Runtime"}')
            result=identify(root,catalog(version(),version("2.0.0")))
            self.assertEqual(result["matches"][0]["status"],"strong-candidate")
            self.assertEqual({v["version"] for v in result["matches"][0]["candidates"]},{"1.0.0"})
            self.assertTrue(result["conflicts"])

    def test_resolve_and_export_keep_partial_candidate_status(self):
        for status in ("unknown","strong-candidate"):
            matches={"schemaVersion":"1.0","catalogCommit":"a"*40,"input":{},"matches":[{"packageId":"com.example.runtime","status":status,"candidates":[dict(version(),packageId="com.example.runtime")]}]}
            lock=resolve(matches)
            self.assertTrue(_partial(lock))
            self.assertTrue(_partial(export_remaker(lock)))

    def test_same_version_different_cache_contents_both_remain_observed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.write(root/"Packages/packages-lock.json",{"dependencies":{"com.example.runtime":{"version":"1.0.0","source":"registry","url":"https://registry.example.test"}}})
            for name,source in (("aaa","namespace Example { class A {} }"),("zzz","namespace Example { class A { int changed; } }")):
                folder=root/f"Library/PackageCache/com.example.runtime@{name}"
                self.write(folder/"package.json",{"name":"com.example.runtime","version":"1.0.0"})
                (folder/"Runtime").mkdir();(folder/"Runtime/A.cs").write_text(source)
                (folder/"Runtime/R.asmdef").write_text('{"name":"Example.Runtime"}')
            result=identify(root,catalog(version()))
            self.assertEqual(result["matches"][0]["status"],"strong-candidate")
            self.assertTrue(any(x["kind"]=="modified-or-incomplete-target" for x in result["conflicts"]))

    def test_export_library_has_schema_source_refs(self):
        matches={"schemaVersion":"1.0","catalogCommit":"a"*40,"input":{},"matches":[{"packageId":"com.example.runtime","status":"exact-artifact","candidates":[dict(version(),packageId="com.example.runtime")]}]}
        exported=export_remaker(resolve(matches))
        self.assertEqual(exported["sourceRefs"],exported["libraries"][0]["sourceRefs"])
