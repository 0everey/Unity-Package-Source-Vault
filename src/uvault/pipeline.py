"""Single-writer catalog orchestration with bounded concurrent upstream reads.

Package shards are the resumable task state. No second queue copy or archive
cache is persisted. Only the publication callback temporarily holds payloads.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import json
import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
from contextlib import contextmanager
from . import harvest, sources
from .catalog import write_json

def shard_name(package_id):
    return "packages/" + urllib.parse.quote(package_id, safe="") + ".json"

def save_package(root, package):
    write_json(root / shard_name(package["id"]), package)

def save_index(root, queue, bundle=False):
    index={"schemaVersion":"1.0","catalogCommit":"pending", "scope":queue.get("scope"),
           "snapshots":queue.get("snapshots",[]),"completeEnumeration":queue.get("completeEnumeration",False),
           "frontier":queue.get("frontier",[]),"coverage":"coverage.json",
           "packages":[{"id":p["id"],"path":shard_name(p["id"]),"metadataStatus":p.get("metadataStatus","pending")}
                       for p in sorted(queue["packages"],key=lambda p:p["id"])]}
    if bundle:
        data=gzip.compress(json.dumps({"schemaVersion":"1.0","packages":queue["packages"]},ensure_ascii=False,separators=(",",":")).encode("utf-8"),mtime=0)
        temp=root/"lookup.json.gz.tmp"
        temp.write_bytes(data);temp.replace(root/"lookup.json.gz")
        index["bundle"]={"path":"lookup.json.gz","sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
    write_json(root / "catalog.json",index)
    write_json(root / "coverage.json",harvest.coverage(queue))

def load_queue(root):
    index=json.loads((root/"catalog.json").read_text(encoding="utf-8-sig"))
    return {**index,"packages":[json.loads((root/e["path"]).read_text(encoding="utf-8-sig")) for e in index["packages"]]}

def metadata(queue, root, workers=12, only=(), retry_failed=False):
    known={p["id"]:p for p in queue["packages"]}
    allowed=set(only)
    pending=[p for p in queue["packages"] if (not allowed or p["id"] in allowed)
             and p.get("metadataStatus","pending") not in ("complete","reference-only")
             and (retry_failed or p.get("metadataStatus")!="failed")]
    def fetch(seed):
        state={"packages":[seed],"frontier":[]}
        harvest.update_metadata(state,package_ids=[seed["id"]],retry_failed=retry_failed)
        return state
    done=0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        active={pool.submit(fetch,seed):seed for seed in pending}
        try:
            while active:
                finished,_=concurrent.futures.wait(active,return_when=concurrent.futures.FIRST_COMPLETED)
                for task in finished:
                    seed=active.pop(task)
                    try:
                        state=task.result()
                    except Exception as exc:
                        seed["metadataStatus"]="failed"
                        seed["metadataError"]={"kind":type(exc).__name__,"message":str(exc)}
                        state={"packages":[seed],"frontier":[]}
                    save_package(root,seed);done+=1
                    for dep in state["packages"][1:]:
                        if dep["id"] not in known:
                            known[dep["id"]]=dep;queue["packages"].append(dep);save_package(root,dep)
                            if not allowed:
                                active[pool.submit(fetch,dep)]=dep
                        else:
                            existing=known[dep["id"]]
                            targets=sorted(set(existing.get("targetVersions",[])+dep.get("targetVersions",[])))
                            if targets!=existing.get("targetVersions",[]):
                                existing["targetVersions"]=targets
                                if existing.get("versions"):
                                    existing.update(sources.selection_status(existing["versions"],targets))
                                save_package(root,existing)
                    for frontier in state.get("frontier",[]):
                        if frontier not in queue.setdefault("frontier",[]):
                            queue["frontier"].append(frontier)
                    if done%100==0:
                        save_index(root,queue)
                        print(json.dumps({"metadataAttempted":done,"active":len(active),"discovered":len(known)}),flush=True)
        finally:
            save_index(root,queue)
    return done

def _run(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",default="catalog")
    parser.add_argument("--discover",action="store_true")
    parser.add_argument("--metadata",action="store_true")
    parser.add_argument("--collect",action="store_true")
    parser.add_argument("--publish",action="store_true")
    parser.add_argument("--repo",default="0everey/Unity-Package-Source-Vault")
    parser.add_argument("--commit",help="Immutable OpenUPM discovery commit")
    parser.add_argument("--package",action="append",default=[])
    parser.add_argument("--workers",type=int,default=12)
    parser.add_argument("--retry-failed",action="store_true")
    args=parser.parse_args(argv)
    if args.workers<1 or args.workers>32:
        parser.error("workers must be 1..32")
    # Capture credential only in process memory, never in persisted task state.
    if not (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
        try:
            token=subprocess.run(["gh","auth","token"],capture_output=True,text=True)
            if token.returncode==0:
                os.environ["GH_TOKEN"]=token.stdout.strip()
        except FileNotFoundError:
            pass
    root=Path(args.root).resolve();root.mkdir(parents=True,exist_ok=True)
    if args.discover:
        queue=harvest.discover(args.commit)
        if (root/"catalog.json").exists():
            old={p["id"]:p for p in load_queue(root)["packages"]}
            current={p["id"] for p in queue["packages"]}
            queue["packages"]=[old.get(p["id"],p) for p in queue["packages"]]
            queue["packages"].extend(p for ident,p in old.items() if ident not in current)
        for package in queue["packages"]:
            save_package(root,package)
        save_index(root,queue)
        print(json.dumps({"discovered":len(queue["packages"]),"snapshots":queue["snapshots"]}),flush=True)
    else:
        queue=load_queue(root)
    if args.metadata:
        metadata(queue,root,args.workers,args.package,args.retry_failed)
    if args.collect:
        publisher=None
        if args.publish:
            from .publish import publish_artifact
            publisher=lambda data,record:publish_artifact(data,record,args.repo)
        def checkpoint(state,package):
            save_package(root,package);save_index(root,state)
            latest=next((v for v in reversed(package["versions"]) if v.get("collectedAt") or v.get("fetchError")),{})
            print(json.dumps({"package":package["id"],"version":latest.get("version"),"fetchStatus":latest.get("fetchStatus"),"disposition":latest.get("disposition")}),flush=True)
        harvest.collect_selected(queue,package_ids=args.package,retry_failed=args.retry_failed,publish=publisher,progress=checkpoint)
    save_index(root,queue,bundle=True)
    report=harvest.coverage(queue)
    print(json.dumps({k:v for k,v in report.items() if k not in ("pendingPackageIds","discoveryFrontier","missingTargetVersions")},ensure_ascii=False),flush=True)
    return 0

@contextmanager
def writer_lock(root):
    directory=root.parent/".local"
    directory.mkdir(parents=True,exist_ok=True)
    path=directory/("catalog-writer-"+hashlib.sha256(str(root).encode()).hexdigest()[:16]+".lock")
    with path.open("a+b") as handle:
        handle.seek(0);handle.write(b"0");handle.flush();handle.seek(0)
        try:
            if os.name=="nt":
                import msvcrt
                msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as exc:
            raise ValueError("A catalog writer already holds this task state") from exc
        try:
            yield
        finally:
            if os.name=="nt":
                handle.seek(0);msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
            else:
                fcntl.flock(handle.fileno(),fcntl.LOCK_UN)

def main(argv=None):
    probe=argparse.ArgumentParser(add_help=False)
    probe.add_argument("--root",default="catalog")
    args,_=probe.parse_known_args(argv)
    with writer_lock(Path(args.root).resolve()):
        return _run(argv)

if __name__=="__main__":
    raise SystemExit(main())
