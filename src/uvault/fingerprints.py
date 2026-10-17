"""Immutable, lazy fingerprint metadata shards. No archive or source-byte cache.

The catalog keeps compact declaration clues. Exact source comparisons and
materialization explicitly load the original file manifest from its pinned shard.
"""
from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import urllib.parse
import urllib.request

STORAGE_VERSION = "1"
MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_FULL_FINGERPRINT_BYTES = 256 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _hash(value, description):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(description + " must be a SHA256 hex digest")
    return value.lower()


def _relative_path(value):
    if (not isinstance(value, str) or not value or value.startswith("/")
            or any(char in value for char in ("\\", ":", "?", "#", "%", "\x00"))):
        raise ValueError("Unsafe fingerprint shard path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts) or PurePosixPath(value).is_absolute():
        raise ValueError("Unsafe fingerprint shard path")
    return value


def _is_link(path):
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def _local_path(base, relative):
    base = Path(base)
    if _is_link(base):
        raise ValueError("Fingerprint catalog base may not be a link")
    base = base.resolve()
    relative = _relative_path(relative)
    child = base
    for part in relative.split("/"):
        child /= part
        if _is_link(child):
            raise ValueError("Fingerprint shard path may not traverse links")
    try:
        child.resolve().relative_to(base)
    except ValueError:
        raise ValueError("Fingerprint shard escapes the catalog base") from None
    return child


def _artifact_sha(version, fingerprint):
    artifact = version.get("artifact") or {}
    value = artifact.get("sha256") or fingerprint.get("artifactSha256")
    digest = _hash(value, "Fingerprint artifact identity")
    observed = fingerprint.get("artifactSha256")
    if observed is not None and _hash(observed, "Observed fingerprint artifact identity") != digest:
        raise ValueError("Fingerprint artifact identity differs from the version artifact")
    return digest


def _shard_relative(artifact_sha, producer):
    return "fingerprints/" + artifact_sha + "-" + _sha(_canonical(producer))[:12] + ".json.gz"


def _identity(value):
    if isinstance(value, str):
        return {"name": value}
    if not isinstance(value, dict):
        return {}
    nested = value.get("assemblyIdentity")
    if isinstance(nested, dict):
        value = nested
    return {key: value[key] for key in ("name", "version", "culture", "publicKeyToken") if value.get(key) is not None}


def _verified_scoped_types(fingerprint, assemblies):
    """Retain explicit ownership; never join a global type set onto an assembly."""
    mappings = [set() for _ in assemblies]
    for index, assembly in enumerate(assemblies):
        if assembly.get("ownershipVerified") is not True:
            continue
        for entry in assembly.get("types", []):
            if isinstance(entry, str):
                mappings[index].add(entry)
            elif isinstance(entry, dict) and entry.get("ownershipVerified") is not False:
                name = entry.get("typeFullName") or entry.get("fullName")
                if isinstance(name, str):
                    mappings[index].add(name)
    for declaration in fingerprint.get("typeDeclarations", []):
        if not isinstance(declaration, dict) or declaration.get("ownershipVerified") is not True:
            continue
        name = declaration.get("typeFullName") or declaration.get("fullName")
        identity = _identity(declaration.get("assemblyIdentity") or declaration.get("assembly"))
        assembly_id = declaration.get("assemblyId")
        candidates = []
        for index, assembly in enumerate(assemblies):
            if assembly.get("ownershipVerified") is not True:
                continue
            if assembly_id is not None and assembly.get("id") == assembly_id:
                candidates.append(index)
            elif identity.get("name") and all(_identity(assembly).get(key) == value for key, value in identity.items()):
                candidates.append(index)
        if len(candidates) == 1 and isinstance(name, str):
            mappings[candidates[0]].add(name)
    return mappings


def _summary(fingerprint, reference, artifact_sha):
    # Unknown future fingerprint facts remain available from the full shard. An
    # explicit summary allow-list prevents adding source/path lists to the bundle.
    keep = ("fingerprintProducer", "sourceSetSha256", "artifactSha256", "artifactSize", "artifactFormat",
            "namespaces", "types", "profileVerified", "profile", "declarationBasis", "activeTypes",
            "activeDeclarationBasis", "diagnostics", "ownershipVerified", "ownershipBasis", "profileIssues")
    summary = {key: copy.deepcopy(fingerprint[key]) for key in keep if key in fingerprint}
    files = fingerprint["files"]
    source_count = sum(1 for file in files if isinstance(file, dict) and str(file.get("path", "")).lower().endswith(".cs"))
    assemblies = [assembly for assembly in fingerprint.get("assemblies", []) if isinstance(assembly, dict)]
    scoped = _verified_scoped_types(fingerprint, assemblies)
    summary["assemblies"] = []
    for assembly, types in zip(assemblies, scoped):
        row = {key: copy.deepcopy(value) for key, value in assembly.items()
               if key not in ("sourceFiles", "files", "conditionalSources", "typeDeclarations", "types")}
        if assembly.get("ownershipVerified") is True and types:
            row["types"] = sorted(types)
        summary["assemblies"].append(row)
    summary.update(fingerprintStorageVersion=STORAGE_VERSION, artifactSha256=artifact_sha,
                   fileManifestRef=reference, fileCount=len(files), sourceFileCount=source_count,
                   sourceSetNonEmpty=source_count > 0,
                   conditionalSourceCount=len(fingerprint.get("conditionalSources", [])),
                   scopedTypeBasis="explicit-verified-ownership-only; lexical declarations retain their original profile status")
    summary["binaryFingerprints"] = [{key: copy.deepcopy(file[key]) for key in ("path", "sha256", "size", "dummyDll") if key in file}
                                     for file in files if isinstance(file, dict) and str(file.get("path", "")).lower().endswith(".dll")]
    return summary


def _write_immutable(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if _is_link(path.parent) or _is_link(path):
        raise ValueError("Fingerprint shard destination may not be a link")
    if path.exists():
        if not path.is_file() or path.read_bytes() != data:
            raise ValueError("Immutable fingerprint shard already exists with different bytes")
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".uvault-fingerprint-", suffix=".tmp", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # A hard link atomically creates the name without replacing any earlier
        # object. Both writers either see identical bytes or report a conflict.
        try:
            os.link(temporary, path)
        except FileExistsError:
            if _is_link(path) or not path.is_file() or path.read_bytes() != data:
                raise ValueError("Immutable fingerprint shard already exists with different bytes") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def externalize_fingerprint(root: Path, version: dict) -> bool:
    """Write one immutable metadata object and replace a full fingerprint summary.

    Return False for absent/full-manifest-free fingerprints. A legacy missing
    producer stays missing (its key uses canonical null); it is never relabeled
    as a current inventory algorithm. Mutation happens only after a safe write.
    """
    fingerprint = version.get("fingerprint")
    if not isinstance(fingerprint, dict) or "files" not in fingerprint or "fileManifestRef" in fingerprint:
        return False
    if not isinstance(fingerprint["files"], list):
        raise ValueError("Fingerprint files must be a list")
    artifact_sha = _artifact_sha(version, fingerprint)
    producer = copy.deepcopy(fingerprint.get("fingerprintProducer"))
    relative = _shard_relative(artifact_sha, producer)
    raw = _canonical(fingerprint)
    if len(raw) > MAX_FULL_FINGERPRINT_BYTES:
        raise ValueError("Fingerprint metadata exceeds the uncompressed size limit")
    data = gzip.compress(raw, mtime=0)
    if len(data) > MAX_COMPRESSED_BYTES:
        raise ValueError("Fingerprint metadata exceeds the compressed size limit")
    reference = {"path": relative, "sha256": _sha(data), "size": len(data), "producer": producer}
    summary = _summary(fingerprint, reference, artifact_sha)
    path = _local_path(root, relative)
    _write_immutable(path, data)
    version["fingerprint"] = summary
    return True


def _read_reference(reference, catalog):
    relative = _relative_path(reference.get("path"))
    size = reference.get("size")
    if type(size) is not int or size < 1 or size > MAX_COMPRESSED_BYTES:
        raise ValueError("Invalid fingerprint shard compressed size")
    digest = _hash(reference.get("sha256"), "Fingerprint shard checksum")
    registry = catalog.get("fingerprintRegistry") or catalog.get("registry")
    if not isinstance(registry, (str, Path)) or not str(registry):
        raise ValueError("Loading a fingerprint shard requires its catalog registry location")
    registry = str(registry)
    parsed = urllib.parse.urlsplit(registry)
    if parsed.scheme in ("http", "https"):
        parts = parsed.path.strip("/").split("/")
        if (parsed.scheme != "https" or parsed.netloc != "raw.githubusercontent.com" or parsed.username or parsed.password
                or parsed.query or parsed.fragment or len(parts) < 4 or not re.fullmatch(r"[0-9a-fA-F]{40}", parts[2])):
            raise ValueError("Remote fingerprint catalog must use an immutable GitHub raw commit URL")
        commit = catalog.get("catalogCommit")
        if commit and str(commit).lower() != parts[2].lower():
            raise ValueError("Fingerprint catalog URL and catalogCommit disagree")
        location = urllib.parse.urljoin(registry, relative)
        request = urllib.request.Request(location, headers={"User-Agent": "Unity-Package-Source-Vault/1.0"})
        with urllib.request.urlopen(request, timeout=90) as response:
            if response.geturl() != location:
                raise ValueError("Fingerprint shard redirect changed its immutable location")
            data = response.read(size + 1)
    else:
        # A Windows drive letter is a local path, not a URI scheme.
        if parsed.scheme and not re.match(r"^[A-Za-z]:[\\/]", registry):
            raise ValueError("Unsupported fingerprint catalog registry location")
        registry_path = Path(registry)
        base = registry_path if registry_path.is_dir() else registry_path.parent
        path = _local_path(base, relative)
        with path.open("rb") as stream:
            data = stream.read(size + 1)
    if len(data) != size or _sha(data) != digest:
        raise ValueError("Fingerprint shard size or checksum mismatch")
    return data


def load_full_fingerprint(version: dict, catalog: dict, *, metadata_bytes: bytes | None = None) -> dict:
    """Load and verify one shard in memory, or return an untouched inline copy."""
    fingerprint = version.get("fingerprint")
    if fingerprint is None:
        return {}
    if not isinstance(fingerprint, dict):
        raise ValueError("Fingerprint must be an object")
    reference = fingerprint.get("fileManifestRef")
    if reference is None:
        return copy.deepcopy(fingerprint)
    if not isinstance(reference, dict) or fingerprint.get("fingerprintStorageVersion") != STORAGE_VERSION:
        raise ValueError("Unsupported fingerprint shard reference version")
    expected_artifact = _artifact_sha(version, fingerprint)
    if reference.get("path") != _shard_relative(expected_artifact, reference.get("producer")):
        raise ValueError("Fingerprint shard path does not match its artifact and producer identities")
    data = metadata_bytes if metadata_bytes is not None else _read_reference(reference, catalog)
    if not isinstance(data,bytes) or len(data)!=reference.get("size") or _sha(data)!=reference.get("sha256"):
        raise ValueError("Fingerprint shard size or checksum mismatch")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            raw = stream.read(MAX_FULL_FINGERPRINT_BYTES + 1)
        if len(raw) > MAX_FULL_FINGERPRINT_BYTES:
            raise ValueError("Fingerprint shard expands beyond the metadata size limit")
        full = json.loads(raw.decode("utf-8"))
    except (OSError, EOFError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid compressed fingerprint metadata") from exc
    if not isinstance(full, dict) or not isinstance(full.get("files"), list) or "fileManifestRef" in full:
        raise ValueError("Fingerprint shard does not contain an original full file manifest")
    if full.get("fingerprintProducer") != reference.get("producer") or full.get("fingerprintProducer") != fingerprint.get("fingerprintProducer"):
        raise ValueError("Fingerprint shard producer identity mismatch")
    if full.get("artifactSha256") is not None and _hash(full["artifactSha256"], "Fingerprint shard artifact identity") != expected_artifact:
        raise ValueError("Fingerprint shard artifact identity mismatch")
    if full.get("sourceSetSha256") != fingerprint.get("sourceSetSha256"):
        raise ValueError("Fingerprint shard source-set identity mismatch")
    if len(full["files"]) != fingerprint.get("fileCount"):
        raise ValueError("Fingerprint shard file count mismatch")
    source_count = sum(1 for file in full["files"] if isinstance(file, dict) and str(file.get("path", "")).lower().endswith(".cs"))
    if source_count != fingerprint.get("sourceFileCount") or (source_count > 0) != fingerprint.get("sourceSetNonEmpty"):
        raise ValueError("Fingerprint shard source count mismatch")
    return full
