"""Verify a collector's completed parent before starting any successor work."""
import argparse,base64,json,os,re,subprocess

def github_json(path):
    result=subprocess.run(["gh","api",path],capture_output=True,text=True,check=True)
    return json.loads(result.stdout)

def validate_parent(repository,run_id,attempt,checkpoint,nonce,fetch=github_json):
    values=(run_id,attempt,checkpoint,nonce)
    if not any(values):
        return {"status":"manual-dispatch","parentRequired":False}
    if (not all(values) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",repository)
            or not run_id.isdigit() or not attempt.isdigit() or not re.fullmatch(r"[0-9a-f]{40}",checkpoint)
            or not re.fullmatch(r"[0-9a-f]{32}",nonce)):
        raise ValueError("Incomplete or invalid parent continuation binding")
    prefix="repos/"+repository
    parent=fetch(prefix+"/actions/runs/"+run_id)
    if parent.get("status")!="completed" or parent.get("conclusion")!="success" or str(parent.get("run_attempt"))!=attempt:
        raise ValueError("Parent collector did not complete this attempt successfully")
    workflow=fetch(prefix+"/actions/workflows/collect.yml")
    if parent.get("workflow_id")!=workflow.get("id") or parent.get("event")!="workflow_dispatch":
        raise ValueError("Parent is not the configured collector workflow")
    if fetch(prefix+"/commits/main").get("sha")!=checkpoint:
        raise ValueError("Continuation checkpoint is stale; resume manually from current main")
    document=fetch(prefix+"/contents/catalog/collection-run.json?ref="+checkpoint)
    if document.get("encoding")!="base64":
        raise ValueError("Missing committed continuation manifest")
    manifest=json.loads(base64.b64decode(document["content"]).decode("utf-8"))
    if (manifest.get("needsContinuation") is not True or manifest.get("runId")!=run_id or manifest.get("runAttempt")!=attempt
            or manifest.get("mode")!="collect" or manifest.get("continuationId")!=nonce):
        raise ValueError("Committed continuation manifest does not bind this successful parent")
    return {"status":"verified-parent","parentRunId":run_id,"checkpoint":checkpoint}

def main():
    result=validate_parent(os.environ.get("GITHUB_REPOSITORY",""),os.environ.get("PARENT_RUN",""),os.environ.get("PARENT_ATTEMPT",""),
                           os.environ.get("PARENT_CHECKPOINT",""),os.environ.get("CONTINUATION_ID",""))
    print(json.dumps(result))

if __name__=="__main__":
    main()
