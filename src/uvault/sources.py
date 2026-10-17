"""Pinned upstream discovery. Downloads are in memory; this module has no cache."""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "Unity-Package-Source-Vault/1.0"
OPENUPM_REPO = "openupm/openupm"


class SourceError(RuntimeError):
    def __init__(self, message, *, url=None, status=None, retryable=False):
        super().__init__(message)
        self.url, self.status, self.retryable = url, status, retryable

    def as_dict(self):
        kind = {404: "not-found", 401: "unauthorized", 403: "forbidden-or-rate-limited", 429: "rate-limited"}.get(self.status, "network-error")
        return {"kind": kind, "url": self.url, "httpStatus": self.status,
                "retryable": self.retryable, "message": str(self)}


def utc_now():
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def request_bytes(url, *, retries=2, timeout=90, max_bytes=512 * 1024 * 1024):
    """Read an upstream object without writing archives or exposing credentials."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.username or parts.password:
        raise SourceError("An HTTPS URL without embedded credentials is required", url=url)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json" if parts.netloc == "api.github.com" else "*/*"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and parts.netloc == "api.github.com":
        headers["Authorization"] = "Bearer " + token
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as response:
                length = response.headers.get("Content-Length")
                if length and int(length) > max_bytes:
                    raise SourceError("Upstream object exceeds configured in-memory limit", url=url)
                chunks, total = [], 0
                while True:
                    chunk = response.read(min(1024 * 1024, max_bytes + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > max_bytes:
                        raise SourceError("Upstream object exceeds configured in-memory limit", url=url)
                return b"".join(chunks)
        except urllib.error.HTTPError as exc:
            retryable = exc.code in (408, 429, 500, 502, 503, 504)
            if retryable and attempt < retries:
                time.sleep(min(2 ** attempt, 8))
                continue
            raise SourceError("Upstream HTTP %s" % exc.code, url=url, status=exc.code, retryable=retryable) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8))
                continue
            raise SourceError("Upstream network request failed: " + type(exc).__name__, url=url, retryable=True) from None


def request_json(url):
    try:
        return json.loads(request_bytes(url).decode("utf-8-sig"))
    except (ValueError, UnicodeError):
        raise SourceError("Upstream response is not valid UTF-8 JSON", url=url) from None


def _github(path):
    return request_json("https://api.github.com/repos/" + path)


def discover_openupm(commit=None):
    """Enumerate every definition from one immutable Git tree, without contents' 1000 cap.

    Definitions stay pending until their per-package registry metadata is fetched.
    A truncated recursive tree is replaced by a complete non-recursive subtree walk.
    """
    if commit is None:
        commit = _github(OPENUPM_REPO + "/commits/master")["sha"]
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise ValueError("OpenUPM discovery requires a full immutable Git commit SHA")
    tree = _github(OPENUPM_REPO + "/git/trees/" + commit + "?recursive=1")
    complete = not tree.get("truncated", False)
    entries = tree.get("tree", [])
    mode = "recursive-tree"
    if not complete:
        entries = []
        pending = [("", commit)]
        while pending:
            prefix, sha = pending.pop()
            subtree = _github(OPENUPM_REPO + "/git/trees/" + sha)
            if subtree.get("truncated"):
                raise SourceError("Non-recursive OpenUPM tree was truncated; enumeration is incomplete")
            for entry in subtree.get("tree", []):
                path = prefix + entry["path"]
                if entry["type"] == "tree":
                    if "data/packages/".startswith(path + "/") or path.startswith("data/packages"):
                        pending.append((path + "/", entry["sha"]))
                else:
                    entries.append(dict(entry, path=path))
        complete, mode = True, "complete-subtree-walk"
    packages = []
    for entry in entries:
        path = entry["path"]
        if entry.get("type") != "blob" or not path.startswith("data/packages/") or not path.endswith((".yml", ".yaml")):
            continue
        package_id = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        packages.append({"id": package_id, "adapter": "registry", "registry": "https://package.openupm.com",
                         "definitionUrl": "https://raw.githubusercontent.com/" + OPENUPM_REPO + "/" + commit + "/" + path,
                         "definitionBlobSha": entry["sha"], "sourceSnapshot": commit,
                         "metadataStatus": "pending", "versions": []})
    packages.sort(key=lambda item: item["id"])
    return {"schemaVersion": "1.0", "source": "OpenUPM", "repository": "https://github.com/" + OPENUPM_REPO,
            "commit": commit, "enumeration": mode, "completeEnumeration": complete,
            "discoveredAt": utc_now(), "discoveredCount": len(packages), "packages": packages}


def _repo_url(repository):
    if isinstance(repository, dict):
        repository = repository.get("url", "")
    if not isinstance(repository, str):
        return ""
    return repository.removeprefix("git+").replace("git://github.com/", "https://github.com/")


def _record(package_id, version, metadata, registry):
    dist = metadata.get("dist", {})
    repository = _repo_url(metadata.get("repository"))
    source_ref = metadata.get("gitHead") or (metadata.get("repository", {}).get("revision") if isinstance(metadata.get("repository"), dict) else None)
    if source_ref and not re.fullmatch(r"[0-9a-fA-F]{40}", source_ref):
        source_ref = None
    variant_basis = json.dumps([dist.get("tarball"), dist.get("integrity"), dist.get("shasum"), source_ref], separators=(",", ":"))
    record = {"version": version, "variantId": "registry-" + urllib.parse.urlsplit(registry).netloc + "-" + hashlib.sha256(variant_basis.encode()).hexdigest()[:16],
              "sourceUrl": repository or registry.rstrip("/") + "/" + urllib.parse.quote(package_id, safe=""),
              "sourceRef": source_ref, "downloadUrl": dist.get("tarball"),
              "upstreamIntegrity": dist.get("integrity"), "upstreamShasum": dist.get("shasum"),
              "disposition": "license-unresolved", "license": {"expression": metadata.get("license") if isinstance(metadata.get("license"), str) else None,
                  "evidenceUrl": None, "sha256": None, "components": [], "reviewStatus": "pending-per-version-archive"},
              "dependencies": metadata.get("dependencies", {}), "artifact": None, "fingerprint": None,
              "fetchStatus": "pending", "versionStatus": "prerelease" if _is_prerelease(version) else "stable",
              "metadataUrl": registry.rstrip("/") + "/" + urllib.parse.quote(package_id, safe="") + "/" + urllib.parse.quote(version, safe=""),
              "deprecated": metadata.get("deprecated"), "unity": metadata.get("unity"),
              "upstream": {"registry": registry, "dist": {key: dist[key] for key in ("integrity", "shasum") if key in dist}}}
    return record


def registry_package(package_id, registry):
    registry = registry.rstrip("/")
    url = registry + "/" + urllib.parse.quote(package_id, safe="")
    data = request_json(url)
    versions = [_record(package_id, version, metadata, registry) for version, metadata in data.get("versions", {}).items()]
    versions.sort(key=lambda record: version_key(record["version"]))
    return {"schemaVersion": "1.0", "id": package_id, "displayName": data.get("displayName", package_id),
            "sources": [{"kind": "registry", "url": registry, "metadataUrl": url, "fetchedAt": utc_now()}],
            "adapter": "registry", "registry": registry, "versions": versions,
            "metadataStatus": "complete", "distTags": data.get("dist-tags", {})}


def version_key(value):
    """SemVer/NuGet numeric ordering, including prerelease identifiers and 4-part versions."""
    text = str(value)
    match = re.search(r"(?:^|[/_-])[vV]?(\d+(?:\.\d+){0,3})(?:-([^+]+))?(?:\+.*)?$", text)
    if not match:
        return (0, (), 0, (), text.casefold())
    numbers = tuple(int(part) for part in match.group(1).split("."))
    numbers = numbers + (0,) * (4 - len(numbers))
    prerelease = match.group(2)
    identifiers = tuple((0, int(part)) if part.isdigit() else (1, part.casefold()) for part in (prerelease or "").split("."))
    return (1, numbers, int(prerelease is None), identifiers, "")


def _is_prerelease(version):
    return version_key(version)[2] == 0


def select_versions(versions, target_versions=(), count=3):
    """Select 3–5 real versions; all available target versions bypass that default cap.

    Targets missing upstream are reported by selection_status(), never fabricated.
    Return the same values (strings or version records) supplied by the caller.
    """
    if count < 1:
        raise ValueError("count must be positive")
    count = min(5, max(3, count))
    by_version = {}
    for item in versions:
        by_version.setdefault(item["version"] if isinstance(item, dict) else str(item), item)
    ordered = sorted(by_version, key=version_key, reverse=True)
    selected = []
    def add(value):
        if value in by_version and value not in selected:
            selected.append(value)
    for target in target_versions:
        add(target)
    stable = [value for value in ordered if not _is_prerelease(value)]
    pool = stable or ordered
    if pool:
        add(pool[0])
    # Keep a compatible neighbor for observed targets before broadening majors.
    for target in list(selected):
        same_major = [v for v in pool if version_key(v)[1][:1] == version_key(target)[1][:1] and v != target]
        if same_major and len(selected) < count:
            add(min(same_major, key=lambda v: (abs(version_key(v)[1][1] - version_key(target)[1][1]),
                                               abs(version_key(v)[1][2] - version_key(target)[1][2]), version_key(v))))
    seen_majors = {version_key(value)[1][:1] for value in selected}
    for value in pool:
        major = version_key(value)[1][:1]
        if major not in seen_majors and len(selected) < count:
            add(value)
            seen_majors.add(major)
    for value in pool + ordered:
        if len(selected) >= count:
            break
        add(value)
    return [by_version[value] for value in selected]


def selection_status(versions, target_versions=(), count=3):
    available = {v["version"] if isinstance(v, dict) else str(v) for v in versions}
    return {"selectedVersions": [v["version"] if isinstance(v, dict) else str(v) for v in select_versions(versions, target_versions, count)],
            "targetVersions": list(target_versions), "missingTargetVersions": [v for v in target_versions if v not in available],
            "allListedVersions": len(available), "versionPolicy": "3-5-plus-all-available-targets"}


def git_package(package_id, repository):
    """Enumerate every GitHub tag, following all pages; tag API commit SHAs pin sources."""
    repository = repository.removeprefix("https://github.com/").removesuffix(".git").strip("/")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Expected a GitHub owner/repository")
    tags, page = [], 1
    while True:
        batch = _github(repository + "/tags?per_page=100&page=" + str(page))
        if not isinstance(batch, list):
            raise SourceError("GitHub tag response is not a list")
        tags.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    versions = []
    for tag in tags:
        sha = tag["commit"]["sha"]
        versions.append({"version": tag["name"], "variantId": "git-" + sha[:12],
                         "sourceUrl": "https://github.com/" + repository, "sourceRef": sha,
                         "downloadUrl": "https://codeload.github.com/" + repository + "/tar.gz/" + sha,
                         "disposition": "license-unresolved", "license": {"expression": None, "evidenceUrl": None, "sha256": None, "components": [], "reviewStatus": "pending-per-version-archive"},
                         "dependencies": {}, "artifact": None, "fingerprint": None, "fetchStatus": "pending",
                         "versionStatus": "prerelease" if _is_prerelease(tag["name"]) else "stable", "sourceTag": tag["name"]})
    return {"schemaVersion": "1.0", "id": package_id, "displayName": package_id,
            "adapter": "github", "repository": repository, "sources": [{"kind": "github-tags", "url": "https://github.com/" + repository, "fetchedAt": utc_now(), "completeEnumeration": True}],
            "versions": sorted(versions, key=lambda item: version_key(item["version"])), "metadataStatus": "complete"}


def nuget_package(package_id):
    base = "https://api.nuget.org/v3-flatcontainer/" + urllib.parse.quote(package_id.lower(), safe="")
    data = request_json(base + "/index.json")
    versions = []
    for version in data["versions"]:
        versions.append({"version": version, "variantId": "nuget", "sourceUrl": "https://www.nuget.org/packages/" + package_id + "/" + version,
                         "sourceRef": None, "downloadUrl": base + "/" + version.lower() + "/" + package_id.lower() + "." + version.lower() + ".nupkg",
                         "disposition": "license-unresolved", "license": {"expression": None, "evidenceUrl": None, "sha256": None, "components": [], "reviewStatus": "pending-per-version-nuspec"},
                         "dependencies": {}, "artifact": None, "fingerprint": None, "fetchStatus": "pending",
                         "versionStatus": "prerelease" if _is_prerelease(version) else "stable"})
    return {"schemaVersion": "1.0", "id": package_id, "displayName": package_id, "adapter": "nuget",
            "sources": [{"kind": "nuget", "url": base + "/index.json", "fetchedAt": utc_now()}],
            "versions": versions, "metadataStatus": "complete"}


def seed_packages():
    """Known entry points, not a claim that these exhaust the Unity ecosystem."""
    seeds = []
    official = ("inputsystem mathematics collections addressables ugui textmeshpro render-pipelines.core render-pipelines.universal "
                "render-pipelines.high-definition shadergraph serialization burst entities jobs timeline cinemachine "
                "nuget.newtonsoft-json visualeffectgraph splines netcode.gameobjects test-framework profiling.core render-pipelines.universal-config").split()
    targets = {"addressables": "2.6.0", "profiling.core": "1.0.2", "ugui": "2.0.0", "burst": "1.8.20", "mathematics": "1.3.2", "collections": "2.4.3",
               "inputsystem": "1.12.0", "render-pipelines.core": "17.0.4", "render-pipelines.universal": "17.0.4", "render-pipelines.universal-config": "17.0.3", "shadergraph": "17.0.4", "serialization": "3.1.5"}
    for name in official:
        seeds.append({"id": "com.unity." + name, "adapter": "registry", "registry": "https://packages.unity.com", "family": "Unity", "metadataStatus": "pending", "versions": [], "targetVersions": [targets[name]] if name in targets else []})
    for package_id in ("com.cysharp.unitask", "com.neuecc.unirx", "com.cysharp.r3", "com.cysharp.memorypack", "jp.hadashikick.vcontainer", "com.svermeulen.extenject", "com.svermeulen.zenject", "com.valvesoftware.unity.openvr"):
        seeds.append({"id": package_id, "adapter": "registry", "registry": "https://package.openupm.com", "family": "runtime", "metadataStatus": "pending", "versions": []})
    for package_id, repository in (("Facepunch.Steamworks", "Facepunch/Facepunch.Steamworks"), ("Steamworks.NET", "rlabrecque/Steamworks.NET"),
                                   ("Spine.Runtimes", "EsotericSoftware/spine-runtimes"), ("PrimeTween", "KyrylKuzyk/PrimeTween")):
        seeds.append({"id": package_id, "adapter": "github", "repository": repository, "metadataStatus": "pending", "versions": []})
    seeds.append({"id": "io.sentry.unity", "adapter": "registry", "registry": "https://package.openupm.com", "family": "runtime", "metadataStatus": "pending", "versions": [], "targetVersions": ["3.2.3"]})
    for name in ("common", "logger", "injectors", "treestate", "panelviews", "editorutils", "nsubstitute"):
        seeds.append({"id": "ca.tekly." + name, "adapter": "registry", "registry": "https://package.openupm.com", "family": "unverified-public-upstream", "metadataStatus": "pending", "versions": []})
    for package_id in ("Newtonsoft.Json", "Google.Protobuf", "Grpc.Core", "Grpc.Core.Api", "Grpc.Net.Client", "BouncyCastle.Cryptography", "Portable.BouncyCastle", "System.Memory", "System.Buffers", "System.Threading.Tasks.Extensions", "System.Runtime", "System.Collections", "System.Numerics.Vectors", "System.Runtime.CompilerServices.Unsafe", "System.Text.Json", "System.Text.Encodings.Web", "System.Diagnostics.DiagnosticSource"):
        seeds.append({"id": package_id, "adapter": "nuget", "metadataStatus": "pending", "versions": []})
    for package_id, url, disposition in (("Best.HTTP", "https://bestdocshub.pages.dev/HTTP/", "user-provided-only"),
                                         ("Tekly", None, "source-unavailable"), ("OOI", None, "source-unavailable"), ("EADP", None, "source-unavailable"),
                                         ("UnityEngine.Modules", "https://docs.unity3d.com/Manual/pack-build.html", "builtin-reference"),
                                         ("UnityCsReference", "https://github.com/Unity-Technologies/UnityCsReference", "builtin-reference"),
                                         ("Unity.IL2CPP.Mono.BCL", "https://docs.unity3d.com/Manual/dotnetProfileSupport.html", "builtin-reference")):
        seeds.append({"schemaVersion": "1.0", "id": package_id, "displayName": package_id, "adapter": "reference", "metadataStatus": "reference-only", "sources": [{"kind": "reference", "url": url}], "versions": [], "disposition": disposition,
                      "reason": "No verified public redistributable upstream/version mapping" if not url else "Official acquisition or reference terms require individual review"})
    return seeds


def fetch_package(seed):
    adapter = seed["adapter"]
    if adapter == "registry":
        return registry_package(seed["id"], seed["registry"])
    if adapter == "github":
        return git_package(seed["id"], seed["repository"])
    if adapter == "nuget":
        return nuget_package(seed["id"])
    if adapter == "reference":
        return dict(seed)
    raise ValueError("Unsupported adapter: " + str(adapter))
