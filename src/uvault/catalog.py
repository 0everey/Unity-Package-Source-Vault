"""Small catalog loading with commit-pinned remote shard resolution."""
from __future__ import annotations
import concurrent.futures
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import urllib.parse
import urllib.request

DEFAULT_REGISTRY = "https://raw.githubusercontent.com/0everey/Unity-Package-Source-Vault/main/catalog/catalog.json"

def read_json(location):
    if str(location).startswith(("https://", "http://")):
        request = urllib.request.Request(str(location), headers={"User-Agent": "uvault/0.1"})
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.load(response)
    return json.loads(Path(location).read_text(encoding="utf-8-sig"))

def _remote_pin(url):
    parts = urllib.parse.urlsplit(url)
    if parts.hostname != "raw.githubusercontent.com":
        raise ValueError("Remote catalog must use raw.githubusercontent.com to establish a Git snapshot")
    pieces = parts.path.strip("/").split("/")
    if len(pieces) < 5:
        raise ValueError("Invalid catalog URL")
    owner, repo, ref = pieces[:3]
    if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
        commit = read_json(f"https://api.github.com/repos/{owner}/{repo}/commits/{urllib.parse.quote(ref, safe='')}")["sha"]
        pieces[2] = commit
    else:
        commit = ref.lower()
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, "/" + "/".join(pieces), "", "")), commit

def load_registry(registry=DEFAULT_REGISTRY):
    registry = str(registry or DEFAULT_REGISTRY)
    remote = registry.startswith(("https://", "http://"))
    if remote:
        registry, commit = _remote_pin(registry)
    else:
        path = Path(registry).resolve()
        if path.is_dir():
            path /= "catalog.json"
        registry = str(path)
        commit = None
    index = read_json(registry)
    if index.get("schemaVersion") != "1.0":
        raise ValueError("Unsupported catalog schemaVersion")
    if not commit:
        commit = index.get("catalogCommit")
        if not commit or commit == "pending":
            result = subprocess.run(["git", "-C", str(Path(registry).parent), "rev-parse", "HEAD"], capture_output=True, text=True)
            commit = result.stdout.strip() if result.returncode == 0 else "local-uncommitted"
    def location_for(relative):
        if PurePosixPath(relative).is_absolute() or any(x in relative for x in ("\\", ":", "?", "#")) or ".." in PurePosixPath(relative).parts:
            raise ValueError("Unsafe catalog shard path")
        return urllib.parse.urljoin(registry, relative) if remote else str(Path(registry).parent / relative)
    def load(entry):
        if "versions" in entry:
            return entry
        relative = entry["path"]
        location = location_for(relative)
        package = read_json(location)
        if package.get("id") != entry["id"]:
            raise ValueError("Catalog shard identity mismatch")
        return package
    bundles=(index.get("bundles") or ([index["bundle"]] if index.get("bundle") else [])) if not all("versions" in p for p in index.get("packages",[])) else []
    def read_bundle(bundle):
        location=location_for(bundle["path"])
        if remote:
            with urllib.request.urlopen(urllib.request.Request(location,headers={"User-Agent":"uvault/0.1"}),timeout=180) as response:
                data=response.read()
        else:
            data=Path(location).read_bytes()
        if len(data)!=bundle["size"] or hashlib.sha256(data).hexdigest()!=bundle["sha256"]:
            raise ValueError("Catalog metadata bundle checksum mismatch")
        return json.loads(gzip.decompress(data).decode("utf-8"))["packages"]
    if bundles:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            chunks=list(pool.map(read_bundle,bundles))
        packages=[package for chunk in chunks for package in chunk]
        if {p["id"] for p in packages}!={p["id"] for p in index["packages"]} or len(packages)!=len(index["packages"]):
            raise ValueError("Catalog metadata bundle identities mismatch")
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            packages = list(pool.map(load, index.get("packages", [])))
    expanded={**index, "catalogCommit": commit, "registry": registry,
              "fingerprintRegistry":index.get("fingerprintRegistry") or index.get("registry") or registry,"packages": packages}
    for field in ("bundle","bundles"):
        if field in expanded:
            expanded["source"+field.title()]=expanded.pop(field)
    return expanded

def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",newline="\n")
    temporary.replace(path)
