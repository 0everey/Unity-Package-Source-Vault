"""Single-writer catalog orchestration with bounded concurrent upstream reads.

Package shards are the resumable task state. No second queue copy or archive
cache is persisted. Only the publication callback temporarily holds payloads.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import copy
import json
import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time
import secrets
import urllib.parse
from contextlib import contextmanager
from . import harvest, sources
from .catalog import write_json

def shard_name(package_id):
    return "packages/" + urllib.parse.quote(package_id, safe="") + ".json"

def save_package(root, package):
    package.setdefault("schemaVersion","1.0")
    from .fingerprints import externalize_fingerprint
    for version in package.get("versions",[]):
        if version.get("artifact") and (version.get("fingerprint") or {}).get("files") is not None:
            externalize_fingerprint(root,version)
    write_json(root / shard_name(package["id"]), package)

def save_index(root, queue, bundle=False):
    from .curated import compatibility_sets
    queue["compatibilitySets"]=compatibility_sets(queue)
    from .nuget import dependency_candidates
    queue["nugetDependencyCandidates"] = dependency_candidates(queue)
    from .family_identity import reference_catalog
    family_references=reference_catalog()
    index={"schemaVersion":"1.0","catalogCommit":"pending", "scope":queue.get("scope"), "scopeVersion":queue.get("scopeVersion"),
           "requirementRevision":queue.get("requirementRevision","R4"),"compatibilitySetDefinitions":queue.get("compatibilitySetDefinitions",[]),"compatibilitySets":queue["compatibilitySets"],
           "nugetDependencyCandidates":queue["nugetDependencyCandidates"],
           "onDemandCandidates":queue.get("onDemandCandidates",[]), "providerRuleCandidates":queue.get("providerRuleCandidates",[]),
           "activatedDemandCandidates":queue.get("activatedDemandCandidates",[]),"coverageDecision":queue.get("coverageDecision",{}),
           "activatedProviderCandidates":queue.get("activatedProviderCandidates",[]),
           "familyReferences":family_references,
           "enumerationMeaning":queue.get("enumerationMeaning"),
           "snapshots":queue.get("snapshots",[]),"completeEnumeration":queue.get("completeEnumeration",False),
           "frontier":queue.get("frontier",[]),"coverage":"coverage.json",
           "packages":[{"id":p["id"],"path":shard_name(p["id"]),"metadataStatus":p.get("metadataStatus","pending")}
                       for p in sorted(queue["packages"],key=lambda p:p["id"])]}
    if bundle:
        index["bundles"]=[]
        ordered=sorted(queue["packages"],key=lambda p:p["id"])
        pending=[ordered[offset:offset+256] for offset in range(0,len(ordered),256)]
        while pending:
            group=pending.pop(0)
            data=gzip.compress(json.dumps({"schemaVersion":"1.0","packages":group},ensure_ascii=False,separators=(",",":")).encode("utf-8"),mtime=0)
            if len(data)>80*1024*1024:
                if len(group)==1:
                    raise ValueError("Package metadata exceeds Git object size contract; split version metadata before publishing")
                half=len(group)//2;pending[:0]=[group[:half],group[half:]];continue
            name=f"lookup-{len(index['bundles']):04d}-{hashlib.sha256(data).hexdigest()[:24]}.json.gz"
            path=root/name
            if not path.exists() or path.read_bytes()!=data:
                temp=path.with_suffix(path.suffix+".tmp");temp.write_bytes(data);temp.replace(path)
            index["bundles"].append({"path":name,"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)})
    write_json(root / "catalog.json",index)
    write_json(root / "coverage.json",harvest.coverage(queue))

def validate_snapshot(root, check_shards=False):
    queue=load_queue(root)
    if check_shards:
        for package in queue["packages"]:
            path=root/shard_name(package["id"])
            if json.loads(path.read_text(encoding="utf-8-sig"))!=package:
                raise ValueError("Package shard disagrees with the authoritative metadata checkpoint: "+package["id"])
    report=harvest.coverage(queue)
    if report["selectedVersionTasks"]!=report["completedSelectedVersionTasks"]+report["pendingSelectedVersionTasks"]:
        raise ValueError("Checkpoint task conservation failed")
    return queue

def load_queue(root):
    index=json.loads((root/"catalog.json").read_text(encoding="utf-8-sig"))
    bundles=index.get("bundles") or ([index["bundle"]] if index.get("bundle") else [])
    if bundles:
        # The hash-bound index bundle is the atomic checkpoint authority.
        # An interrupted later shard is safely retried/deduplicated remotely.
        packages=[]
        for descriptor in bundles:
            data=(root/descriptor["path"]).read_bytes()
            if len(data)!=descriptor["size"] or hashlib.sha256(data).hexdigest()!=descriptor["sha256"]:
                raise ValueError("Task metadata bundle checksum mismatch")
            packages.extend(json.loads(gzip.decompress(data))["packages"])
        return {**index,"packages":packages}
    return {**index,"packages":[json.loads((root/e["path"]).read_text(encoding="utf-8-sig")) for e in index["packages"]]}

def metadata(queue, root, workers=12, only=(), retry_failed=False, refresh=False):
    known={p["id"]:p for p in queue["packages"]}
    allowed=set(only)
    pending=[p for p in queue["packages"] if (not allowed or p["id"] in allowed)
             and (refresh or p.get("metadataStatus","pending") not in ("complete","reference-only"))
             and (retry_failed or p.get("metadataStatus")!="failed")]
    def fetch(seed):
        # Worker reads use detached state; only this main loop mutates the
        # authoritative queue, including targets arriving during network reads.
        state={"packages":[copy.deepcopy(seed)],"frontier":[], "scopeVersion":queue.get("scopeVersion")}
        harvest.update_metadata(state,package_ids=[seed["id"]],retry_failed=retry_failed,refresh=refresh)
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
                        fetched=state["packages"][0]
                        targets=sorted(set(seed.get("targetVersions",[])+fetched.get("targetVersions",[])),key=sources.version_key)
                        seed.clear();seed.update(fetched)
                        if targets:
                            seed["targetVersions"]=targets
                            if seed.get("versions"):
                                seed.update(sources.selection_status(seed["versions"],targets))
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

def push_checkpoint(root,queue):
    save_index(root,queue,bundle=True)
    validate_snapshot(root,check_shards=True)
    repository=root.parent
    commands=(["git","-C",str(repository),"add","--",str(root)],
              ["git","-C",str(repository),"diff","--cached","--quiet"])
    subprocess.run(commands[0],check=True,capture_output=True)
    changed=subprocess.run(commands[1],capture_output=True).returncode
    if changed==1:
        subprocess.run(["git","-C",str(repository),"commit","-q","-m","Checkpoint verified artifacts and remaining version tasks"],check=True,capture_output=True)
        subprocess.run(["git","-C",str(repository),"push"],check=True,capture_output=True)
    elif changed:
        raise ValueError("Cannot inspect collection checkpoint")

def _run(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",default="catalog")
    parser.add_argument("--discover",action="store_true",help="Load the bounded common-package whitelist")
    parser.add_argument("--curate",action="store_true",help="Project the previous catalog to R4 common packages, preserving Git history and Releases")
    parser.add_argument("--add-gap",nargs=3,metavar=("PACKAGE","VERSION","REASON"),help="Explicit consumer gap in a registered common package; refresh metadata to acquire it")
    parser.add_argument("--metadata",action="store_true")
    parser.add_argument("--collect",action="store_true")
    parser.add_argument("--publish",action="store_true")
    parser.add_argument("--reindex",action="store_true",help="Rebuild stale fingerprint metadata from SHA-verified immutable bytes")
    parser.add_argument("--repo",default="0everey/Unity-Package-Source-Vault")
    parser.add_argument("--commit",help="Immutable OpenUPM discovery commit")
    parser.add_argument("--package",action="append",default=[])
    parser.add_argument("--workers",type=int,default=12)
    parser.add_argument("--retry-failed",action="store_true")
    parser.add_argument("--refresh",action="store_true",help="Refresh metadata while retaining prior immutable variants")
    parser.add_argument("--checkpoint-push",action="store_true",help="Publish resumable metadata checkpoints from an ephemeral Actions runner")
    parser.add_argument("--checkpoint-every",type=int,default=100)
    parser.add_argument("--runner-deadline-seconds",type=int,help="Yield a resumable checkpoint before the hosting runner's enforced deadline")
    args=parser.parse_args(argv)
    if args.workers<1 or args.workers>32:
        parser.error("workers must be 1..32")
    if args.checkpoint_every<1:
        parser.error("checkpoint-every must be positive")
    if args.checkpoint_push and os.environ.get("GITHUB_ACTIONS")!="true":
        parser.error("checkpoint-push is restricted to the explicitly configured Actions collector")
    if args.runner_deadline_seconds is not None and (args.runner_deadline_seconds<1 or os.environ.get("GITHUB_ACTIONS")!="true"):
        parser.error("runner-deadline-seconds requires the explicitly configured Actions runner")
    started=time.monotonic()
    class RunnerWindowEnded(Exception):
        pass
    yielded=False
    # Capture credential only in process memory, never in persisted task state.
    if not (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
        try:
            token=subprocess.run(["gh","auth","token"],capture_output=True,text=True)
            if token.returncode==0:
                os.environ["GH_TOKEN"]=token.stdout.strip()
        except FileNotFoundError:
            pass
    root=Path(args.root).resolve();root.mkdir(parents=True,exist_ok=True)
    if args.discover or args.curate:
        if args.commit:
            parser.error("R4 uses the common whitelist, not OpenUPM ecosystem discovery")
        from .curated import queue as common_queue, prune_catalog
        previous=load_queue(root) if (root/"catalog.json").exists() else None
        queue=common_queue(previous)
        for package in queue["packages"]:
            save_package(root,package)
        save_index(root,queue,bundle=True)
        retired=prune_catalog(root,queue)
        print(json.dumps({"retiredGeneratedPackageShards":retired,"scopeVersion":"R4"}),flush=True)
        print(json.dumps({"discovered":len(queue["packages"]),"snapshots":queue["snapshots"]}),flush=True)
    else:
        queue=load_queue(root)
    if queue.get("scopeVersion")!="R4":
        parser.error("Retired ecosystem queue: run --curate to use the R4 common whitelist")
    if args.add_gap:
        from .curated import add_gap
        changed=add_gap(queue,*args.add_gap)
        save_package(root,changed)
    # Recover an interrupted shard-before-index write from the last valid,
    # hash-bound index checkpoint. This is task state, never package payloads.
    if args.checkpoint_push:
        for package in queue["packages"]:
            path=root/shard_name(package["id"])
            if not path.exists() or json.loads(path.read_text(encoding="utf-8-sig"))!=package:
                save_package(root,package)
    for package in queue["packages"]:
        if package.get("schemaVersion")!="1.0":
            package["schemaVersion"]="1.0"
            save_package(root,package)
        elif any((version.get("fingerprint") or {}).get("files") is not None for version in package.get("versions",[])):
            save_package(root,package)
    if args.metadata:
        metadata(queue,root,args.workers,args.package,args.retry_failed,args.refresh)
    if args.reindex:
        from .reindex import reindex_queue
        reindex_queue(queue,progress=lambda state,package:save_package(root,package))
    if args.collect:
        queue["packages"].sort(key=lambda package:(0 if package.get("family") else 1,package["id"]))
        publisher=None
        if args.publish:
            from .publish import publish_artifact
            publisher=lambda data,record:publish_artifact(data,record,args.repo)
        checkpoint_count=0
        def checkpoint(state,package):
            nonlocal checkpoint_count
            save_package(root,package);save_index(root,state)
            checkpoint_count+=1
            if args.checkpoint_push and checkpoint_count%args.checkpoint_every==0:
                push_checkpoint(root,state)
            latest=max(package["versions"],key=lambda v:v.get("collectedAt") or v.get("fetchAttemptedAt") or "")
            print(json.dumps({"package":package["id"],"version":latest.get("version"),"fetchStatus":latest.get("fetchStatus"),"disposition":latest.get("disposition")}),flush=True)
            if args.runner_deadline_seconds is not None and time.monotonic()-started>=args.runner_deadline_seconds:
                raise RunnerWindowEnded()
        try:
            harvest.collect_selected(queue,package_ids=args.package,retry_failed=args.retry_failed,publish=publisher,progress=checkpoint)
        except RunnerWindowEnded:
            yielded=True
        write_json(root/"collection-run.json",{"schemaVersion":"1.0","attempted":checkpoint_count,"needsContinuation":yielded,
                   "reason":"Hosting runner deadline; completed tasks retained remotely" if yielded else "Selected queue traversal finished; failures and restrictions remain explicit",
                   "packages":args.package,"mode":"collect","runId":os.environ.get("GITHUB_RUN_ID"),
                   "runAttempt":os.environ.get("GITHUB_RUN_ATTEMPT"),"continuationId":secrets.token_hex(16) if yielded else None,
                   "generatedAt":sources.utc_now()})
    save_index(root,queue,bundle=True)
    if args.checkpoint_push:
        push_checkpoint(root,queue)
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
