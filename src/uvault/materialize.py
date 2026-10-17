"""Verified, transient archive reads into one explicit usage directory."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
import shutil
from copy import deepcopy
import unicodedata
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile

RECEIPT_NAME = ".uvault-receipt.json"
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024


def canonical_hash(value: dict | list) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path(name: str) -> str:
    if not isinstance(name, str) or "\x00" in name:
        raise ValueError("invalid archive path")
    name = unicodedata.normalize("NFC", name.replace("\\", "/"))
    if name.startswith("/"):
        raise ValueError("absolute archive path")
    while name.startswith("./"):
        name = name[2:]
    parts = name.rstrip("/").split("/")
    if not name.rstrip("/") or any(part in ("", ".", "..") for part in parts):
        raise ValueError("unsafe archive path")
    for part in parts:
        if part[-1] in " ." or re.search(r'[<>:"|?*\x00-\x1f]', part):
            raise ValueError("non-portable archive path")
        if part.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL", *["COM" + str(i) for i in range(1, 10)], *["LPT" + str(i) for i in range(1, 10)]}:
            raise ValueError("reserved archive path")
    return "/".join(parts)


def _archive_files(data: bytes, format_name: str | None) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes | None]] = []
    expanded = 0
    if format_name in ("zip", ".zip") or zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                mode = member.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError("archive links and special files are forbidden")
                name = _path(member.filename)
                expanded += member.file_size
                if expanded > MAX_EXPANDED_BYTES:
                    raise ValueError("expanded archive exceeds size limit")
                entries.append((name, None if member.is_dir() else archive.read(member)))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for member in archive:
                if member.name.rstrip("/") in (".", "") and member.isdir():
                    continue
                name = _path(member.name)
                if not (member.isfile() or member.isdir()):
                    raise ValueError("archive links and special files are forbidden")
                expanded += member.size
                if expanded > MAX_EXPANDED_BYTES:
                    raise ValueError("expanded archive exceeds size limit")
                if member.isdir():
                    content = None
                else:
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("archive member has no content")
                    with source:
                        content = source.read()
                entries.append((name, content))
    seen: dict[str, bool] = {}
    for name, content in entries:
        key = name.casefold()
        if key in seen:
            raise ValueError("duplicate or case-colliding archive path")
        seen[key] = content is None
    for key in seen:
        ancestors = key.split("/")[:-1]
        for count in range(1, len(ancestors) + 1):
            if seen.get("/".join(ancestors[:count])) is False:
                raise ValueError("archive file/directory collision")
    files = [(name, content) for name, content in entries if content is not None]
    if (format_name or "").lower().lstrip(".") == "unitypackage":
        raw = dict(files)
        logical: dict[str, bytes] = {}
        for name, content in files:
            if not name.endswith("/pathname"):
                continue
            prefix = name.rsplit("/", 1)[0]
            target = _path(content.decode("utf-8-sig").strip())
            for suffix, destination in (("asset", target), ("asset.meta", target + ".meta")):
                member = prefix + "/" + suffix
                if member in raw:
                    if destination.casefold() in {path.casefold() for path in logical}:
                        raise ValueError("duplicate or case-colliding Unity asset path")
                    logical[destination] = raw[member]
        files = sorted(logical.items())
        paths = {name.casefold() for name, _ in files}
        for name in paths:
            parts = name.split("/")
            if any("/".join(parts[:count]) in paths for count in range(1, len(parts))):
                raise ValueError("Unity asset file/directory collision")
    if not files:
        raise ValueError("archive contains no files")
    roots = {name.split("/", 1)[0] for name, _ in files}
    if len(roots) == 1 and all("/" in name for name, _ in files):
        files = [(name.split("/", 1)[1], content) for name, content in files]
    return sorted(files)


def _download(url: str) -> bytes:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("download URL must be an unauthenticated HTTP(S) URL")
    request = Request(url, headers={"User-Agent": "Unity-Package-Source-Vault/0.1"})
    with urlopen(request, timeout=90) as response:
        redirected = urlsplit(response.geturl())
        if redirected.scheme not in ("http", "https") or redirected.username or redirected.password:
            raise ValueError("unsafe archive redirect")
        data = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds size limit")
    return data


def _identity(library: dict) -> tuple:
    return tuple(library.get(key) for key in ("packageId", "version", "variantId"))


def _check_inventory(library: dict, manifest: list[dict]) -> None:
    """When full catalog file hashes exist, bind a receipt to that inventory."""
    inventory = (library.get("fingerprint") or {}).get("files")
    if inventory:
        expected = {item["path"]: item["sha256"].lower() for item in inventory}
        actual = {item["path"]: item["sha256"].lower() for item in manifest}
        if len(expected) != len(inventory) or actual != expected:
            raise ValueError("materialized file hashes differ from catalog inventory")


def _scan_files(root: Path) -> dict[str, dict]:
    result = {}
    for parent, directories, filenames in os.walk(root, followlinks=False):
        for name in directories + filenames:
            path = Path(parent) / name
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise ValueError("materialization contains a link")
        for name in filenames:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            data = path.read_bytes()
            result[relative] = {"path": relative, "sha256": _sha(data), "size": len(data)}
    return result


def _reuse(lock: dict, target: Path) -> dict:
    receipt_path = target / RECEIPT_NAME
    if target.is_symlink() or not target.is_dir() or not receipt_path.is_file() or receipt_path.is_symlink():
        raise ValueError("target already exists without a reusable receipt")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("lockSha256") != canonical_hash(lock):
        raise ValueError("target belongs to a different lock")
    expected = {}
    lock_libraries = {_identity(item): item for item in lock.get("libraries", [])}
    observed = set()
    for item in receipt.get("libraries", []):
        library = lock_libraries.get(_identity(item))
        if _identity(item) in observed or library is None or str(item.get("artifactSha256", "")).lower() != str((library.get("artifact") or {}).get("sha256", "")).lower():
            raise ValueError("receipt library differs from lock")
        observed.add(_identity(item))
        if item.get("status") not in ("materialized", "reused") or not item.get("files"):
            raise ValueError("receipt library has no successful content evidence")
        if item.get("contentSha256") != canonical_hash(item["files"]):
            raise ValueError("receipt content manifest has changed")
        _check_inventory(library, item["files"])
        relative_root = _path(item.get("relativePath", ""))
        if str(target / relative_root) != item.get("path"):
            raise ValueError("receipt destination differs from target")
        for original in item.get("files", []):
            relative = relative_root + "/" + _path(original["path"])
            if relative in expected:
                raise ValueError("duplicate receipt path")
            expected[relative] = {**original, "path": relative}
    unresolved_ids = {_identity(item) for item in receipt.get("unresolved", []) if item.get("packageId")}
    if set(lock_libraries) - observed - unresolved_ids:
        raise ValueError("receipt silently omits a locked library")
    actual = _scan_files(target)
    actual.pop(RECEIPT_NAME, None)
    if actual != expected:
        raise ValueError("materialized content has changed; refusing immutable reuse")
    for item in receipt["libraries"]:
        item["status"] = "reused"
    return receipt


def materialize(lock: dict, target: str | Path, offline: bool = False) -> dict:
    """Materialize permitted payloads without a persistent archive or cache.

    Failures leave no stage or new destination. Restricted/unavailable items
    remain explicit in the receipt; successful siblings may still be used.
    """
    if not isinstance(lock, dict) or lock.get("schemaVersion") != "1.0":
        raise ValueError("lock must use schemaVersion 1.0")
    target = Path(target).absolute()
    if target.is_symlink():
        raise ValueError("target may not be a symlink")
    target = target.resolve()
    if target.exists():
        receipt=_reuse(lock,target)
        missing={_identity(item) for item in receipt.get("unresolved",[]) if item.get("packageId")}
        pending=[item for item in lock.get("libraries",[]) if _identity(item) in missing and item.get("disposition") in ("mirror-allowed","official-fetch-only")]
        if offline or not pending:
            return receipt
        # Verify every existing byte first; stage only the missing libraries.
        # Existing successful siblings are never copied or replaced.
        sublock={**deepcopy(lock),"libraries":pending,"unresolved":[]}
        added=[]
        with tempfile.TemporaryDirectory(prefix=".uvault-resume-",dir=target.parent) as temporary:
            addition=materialize(sublock,Path(temporary)/"new",False)
            successful={_identity(item) for item in addition["libraries"]}
            combined=deepcopy(receipt)
            attempted={_identity(item) for item in pending}
            combined["unresolved"]=[item for item in combined["unresolved"] if _identity(item) not in attempted]
            combined["unresolved"].extend(addition.get("unresolved",[]))
            try:
                for item in addition["libraries"]:
                    destination=target/item["relativePath"]
                    if destination.exists() or destination.is_symlink():
                        raise ValueError("Resume destination collision")
                    Path(item["path"]).rename(destination);added.append(destination)
                    item["path"]=str(destination)
                    combined["libraries"].append(item)
                combined["lockSha256"]=canonical_hash(lock)
                # Atomically replace only this task's receipt after all new
                # package directories have moved; preserve the original input.
                receipt_temp=target/(RECEIPT_NAME+".pending")
                with receipt_temp.open("x",encoding="utf-8") as output:
                    output.write(json.dumps(combined,ensure_ascii=False,indent=2)+"\n")
                receipt_temp.replace(target/RECEIPT_NAME)
            except Exception:
                for path in added:
                    if path.resolve().parent==target and not path.is_symlink():
                        shutil.rmtree(path)
                raise
            return _reuse(lock,target)
    target.parent.mkdir(parents=True, exist_ok=True)
    receipt = {"schemaVersion": "1.0", "lockSha256": canonical_hash(lock),
               "libraries": [], "unresolved": list(lock.get("unresolved", []))}
    seen = set()
    with tempfile.TemporaryDirectory(prefix=".uvault-stage-", dir=target.parent) as temporary:
        stage = Path(temporary) / "content"
        stage.mkdir()
        for library in lock.get("libraries", []):
            identity = _identity(library)
            if not all(identity) or identity in seen:
                raise ValueError("missing or duplicate library identity")
            seen.add(identity)
            artifact = library.get("artifact") or {}
            disposition = library.get("disposition")
            url = artifact.get("url") or library.get("downloadUrl")
            reason = None
            if disposition not in ("mirror-allowed", "official-fetch-only"):
                reason = disposition or "license-unresolved"
            elif not url or not re.fullmatch(r"[0-9a-fA-F]{64}", str(artifact.get("sha256", ""))):
                reason = "no-verified-download"
            elif offline:
                reason = "offline-no-package-cache"
            if reason:
                receipt["unresolved"].append({"packageId": identity[0], "version": identity[1],
                    "variantId": identity[2], "reason": reason, "sourceUrl": library.get("sourceUrl")})
                continue
            data = _download(url)
            digest = _sha(data)
            if digest.lower() != artifact["sha256"].lower():
                raise ValueError("archive checksum mismatch: " + identity[0])
            if artifact.get("size") is not None and artifact["size"] != len(data):
                raise ValueError("archive size mismatch: " + identity[0])
            files = _archive_files(data, artifact.get("format"))
            directory = re.sub(r"[^a-zA-Z0-9._-]", "_", identity[0])[:80] + "-" + canonical_hash(list(identity))[:16]
            output = stage / directory
            output.mkdir()
            manifest = []
            for name, content in files:
                destination = output.joinpath(*name.split("/"))
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as writer:
                    writer.write(content)
                manifest.append({"path": name, "sha256": _sha(content), "size": len(content)})
            _check_inventory(library, manifest)
            receipt["libraries"].append({"packageId": identity[0], "version": identity[1], "variantId": identity[2],
                "path": str(target / directory), "relativePath": directory, "artifactSha256": digest,
                "status": "materialized", "files": manifest, "contentSha256": canonical_hash(manifest),
                "license": library.get("license"), "licenseDelivery": "Full license and NOTICE evidence retained in .uvault-receipt.json; preserve this companion with the original extracted package"})
        if not receipt["libraries"]:
            # A pure failure/offline result must not reserve a future use path.
            return receipt
        (stage / RECEIPT_NAME).write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if target.exists() or target.is_symlink():
            raise ValueError("target appeared while materializing; refusing collision")
        stage.rename(target)
    return receipt
