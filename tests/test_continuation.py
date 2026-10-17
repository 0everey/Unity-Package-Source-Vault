import base64,json,unittest
from uvault.continuation import validate_parent

class ContinuationTests(unittest.TestCase):
    def responses(self):
        manifest={"needsContinuation":True,"runId":"12","runAttempt":"2","mode":"collect","continuationId":"b"*32}
        return {"actions/runs/12":{"status":"completed","conclusion":"success","run_attempt":2,"workflow_id":9,"event":"workflow_dispatch"},
                "actions/workflows/collect.yml":{"id":9},"commits/main":{"sha":"a"*40},
                "contents/catalog/collection-run.json?ref="+"a"*40:{"encoding":"base64","content":base64.b64encode(json.dumps(manifest).encode()).decode()}}
    def check(self,values):
        return validate_parent("owner/repo","12","2","a"*40,"b"*32,lambda path:values[path.removeprefix("repos/owner/repo/")])
    def test_bound_success_and_manual_dispatch(self):
        self.assertEqual(self.check(self.responses())["status"],"verified-parent")
        self.assertEqual(validate_parent("owner/repo","","","","")["status"],"manual-dispatch")
    def test_canceled_failed_pending_and_wrong_attempt_do_not_start(self):
        for field,value in (("conclusion","cancelled"),("conclusion","failure"),("status","in_progress"),("run_attempt",3)):
            data=self.responses();data["actions/runs/12"][field]=value
            with self.assertRaises(ValueError):self.check(data)
    def test_stale_checkpoint_and_old_manifest_do_not_start(self):
        data=self.responses();data["commits/main"]["sha"]="c"*40
        with self.assertRaises(ValueError):self.check(data)
        for field,value in (("runId","11"),("runAttempt","1"),("mode","metadata"),("continuationId","d"*32),("needsContinuation",False)):
            data=self.responses();key="contents/catalog/collection-run.json?ref="+"a"*40
            manifest=json.loads(base64.b64decode(data[key]["content"]));manifest[field]=value
            data[key]["content"]=base64.b64encode(json.dumps(manifest).encode()).decode()
            with self.assertRaises(ValueError):self.check(data)
