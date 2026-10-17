from copy import deepcopy
import json,hashlib,tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from test_materialize import lock as make_lock, archive
from uvault.fingerprints import externalize_fingerprint
from uvault.inventory import fingerprint_archive
from uvault.materialize import materialize,RECEIPT_NAME,canonical_hash
from uvault.pipeline import save_index,save_package,load_queue,validate_snapshot

class ShardedConsumerTests(unittest.TestCase):
    def test_old_checkpoint_survives_interrupted_bundle_pointer_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"catalog";root.mkdir()
            p={"schemaVersion":"1.0","id":"example","versions":[],"metadataStatus":"complete"}
            q={"schemaVersion":"1.0","packages":[p]}
            save_package(root,p);save_index(root,q,bundle=True)
            original=load_queue(root)
            p["displayName"]="changed";save_package(root,p)
            from uvault import pipeline
            actual_write=pipeline.write_json
            def interrupted(path,value):
                if Path(path).name=="catalog.json":
                    raise OSError("interruption before pointer swap")
                actual_write(path,value)
            with patch.object(pipeline,"write_json",side_effect=interrupted):
                with self.assertRaises(OSError):
                    save_index(root,q,bundle=True)
            self.assertEqual(load_queue(root)["packages"],original["packages"])
            with self.assertRaisesRegex(ValueError,"disagrees"):
                validate_snapshot(root,check_shards=True)
            save_package(root,original["packages"][0])
            validate_snapshot(root,check_shards=True)

    def test_sharded_manifest_rejects_forged_receipt_and_reuses_offline(self):
        data=archive({"package/Runtime/Source.cs":b"class Source {}"})
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);catalog=root/"catalog";catalog.mkdir()
            value=make_lock(data);library=value["libraries"][0]
            library["fingerprint"]=fingerprint_archive(data,"zip")
            externalize_fingerprint(catalog,library)
            value["fingerprintRegistry"]=str(catalog/"catalog.json")
            target=root/"usage"
            with patch("uvault.materialize._download",return_value=data):
                receipt=materialize(value,target)
            self.assertEqual(materialize(value,target,offline=True)["libraries"][0]["status"],"reused")
            source=Path(receipt["libraries"][0]["path"])/"Runtime/Source.cs"
            source.write_bytes(b"class Source { int changed; }")
            item=receipt["libraries"][0]
            for row in item["files"]:
                if row["path"]=="Runtime/Source.cs":
                    row.update(sha256=hashlib.sha256(source.read_bytes()).hexdigest(),size=source.stat().st_size)
            item["contentSha256"]=canonical_hash(item["files"])
            (target/RECEIPT_NAME).write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError,"catalog inventory"):
                materialize(value,target,offline=True)
            item["fingerprintMetadataBase64"]="AAAA"
            (target/RECEIPT_NAME).write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError,"checksum"):
                materialize(value,target,offline=True)
