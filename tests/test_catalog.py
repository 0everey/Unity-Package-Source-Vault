import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from uvault.catalog import load_registry, write_json
from uvault.cli import main
from uvault.pipeline import writer_lock

class CatalogTests(unittest.TestCase):
    def setup_catalog(self,root):
        package={"schemaVersion":"1.0","id":"com.example.demo","versions":[]}
        data=gzip.compress(json.dumps({"schemaVersion":"1.0","packages":[package]}).encode())
        (root/"lookup.json.gz").write_bytes(data)
        write_json(root/"catalog.json",{"schemaVersion":"1.0","catalogCommit":"a"*40,"packages":[{"id":package["id"],"path":"packages/demo.json"}],"bundle":{"path":"lookup.json.gz","sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}})
        return root/"catalog.json"

    def test_synced_bundle_is_self_contained_and_identifiable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=self.setup_catalog(root);dest=root/"synced"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["catalog","sync","--registry",str(path),"--out",str(dest)]),0)
            result=load_registry(dest/"catalog.json")
            self.assertEqual(result["packages"][0]["id"],"com.example.demo")
            self.assertNotIn("bundle",result)
            package=root/"target";package.mkdir();(package/"A.cs").write_text("class A {}")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["identify","--registry",str(dest/"catalog.json"),"--input",str(package),"--out",str(root/"matches")]),3)

    def test_corrupt_bundle_and_escaping_reference_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=self.setup_catalog(root)
            (root/"lookup.json.gz").write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError,"checksum"):
                load_registry(path)
            value=json.loads(path.read_text());value["bundle"]["path"]="https://other.test/catalog.gz";write_json(path,value)
            with self.assertRaisesRegex(ValueError,"Unsafe"):
                load_registry(path)

    def test_two_catalog_writers_cannot_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"catalog"
            with writer_lock(root):
                with self.assertRaisesRegex(ValueError,"writer"):
                    with writer_lock(root):
                        self.fail("Second writer acquired live state")
            with writer_lock(root):
                pass
