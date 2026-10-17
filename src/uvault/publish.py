"""Publish permitted immutable bytes, verify anonymously, then return references.

No credentials are read or printed by Python: the existing gh credential store is
used. Only a task-owned TemporaryDirectory holds the upload file.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request

def gh(*args, binary=False):
    result = subprocess.run(["gh", *map(str,args)], capture_output=True, text=not binary)
    if result.returncode:
        error = result.stderr.decode("utf-8", "replace") if binary else result.stderr
        raise RuntimeError(error.strip())
    return result.stdout

def publish_artifact(data, record, repo="0everey/Unity-Package-Source-Vault"):
    if record.get("disposition") != "mirror-allowed":
        raise ValueError("Only individually approved mirror-allowed artifacts may be uploaded")
    if not record.get("license",{}).get("sha256") or not record.get("license",{}).get("evidenceUrl"):
        raise ValueError("Version-specific license evidence required")
    digest = hashlib.sha256(data).hexdigest()
    expected = (record.get("artifact") or {}).get("sha256")
    if expected and expected != digest:
        raise ValueError("Collector/upload bytes mismatch")
    tag = "objects-" + digest[:2]
    fmt = (record.get("artifact") or {}).get("format", "tgz")
    suffix = {"tar.gz":".tar.gz", "tgz":".tgz", "zip":".zip", "nupkg":".nupkg"}.get(fmt)
    if not suffix:
        raise ValueError("Unsupported artifact format")
    name = digest + suffix
    lookup = subprocess.run(["gh","release","view",tag,"--repo",repo,"--json","assets"],capture_output=True,text=True)
    if lookup.returncode:
        gh("release","create",tag,"--repo",repo,"--title",f"Immutable content objects {digest[:2]}","--notes","Third-party originals. Each catalog version has independent licensing and provenance; the vault tool MIT license does not cover these archives.")
        assets=[]
    else:
        assets=json.loads(lookup.stdout)["assets"]
    found=next((asset for asset in assets if asset["name"]==name),None)
    if not found:
        with tempfile.TemporaryDirectory(prefix="uvault-upload-") as root:
            archive=Path(root)/name
            archive.write_bytes(data)
            gh("release","upload",tag,archive,"--repo",repo)
        assets=json.loads(gh("release","view",tag,"--repo",repo,"--json","assets"))["assets"]
        found=next(asset for asset in assets if asset["name"]==name)
    url=found["url"]
    request=urllib.request.Request(url, headers={"User-Agent":"uvault/0.1"})
    h=hashlib.sha256(); size=0
    with urllib.request.urlopen(request,timeout=180) as response:
        while chunk:=response.read(1024*1024):
            h.update(chunk);size+=len(chunk)
    if h.hexdigest()!=digest or size!=len(data):
        raise ValueError("Anonymous remote readback failed; catalog must not reference this object")
    return {**(record.get("artifact") or {}), "sha256":digest,"size":size,"format":fmt,"url":url,"assetId":found.get("id"),"releaseTag":tag,"verifiedRemote":True}
