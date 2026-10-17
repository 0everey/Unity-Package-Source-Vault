"""Optional offline SRM adapter; target DLL bytes are never executed or cached.

Set UVAULT_MANAGED_INDEXER to the decoder executable/ManagedIndex.dll path, or a
JSON argv list. No decoder build, SDK install, dependency download or target-file
write is triggered by parse_binaries(). Explicit `build` compiles our helper only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

MAX_BINARY_BYTES = 32 * 1024 * 1024
MAX_BATCH_BYTES = 32 * 1024 * 1024
MAX_BATCH_FILES = 128


def _checkout():
    return Path(__file__).resolve().parents[2]

def _user_tool():
    root=Path(os.environ.get("LOCALAPPDATA") or (Path.home()/".local"/"share"))
    return root/"uvault-tools"/"managed-index"


def _safe_path(path):
    if (not isinstance(path, str) or not path or path.startswith("/") or any(value in path for value in ("\\", ":", "\x00"))
            or any(part in ("", ".", "..") for part in path.split("/"))):
        raise ValueError("Managed metadata input paths must be relative POSIX paths")
    return path


def _launcher():
    configured = os.environ.get("UVAULT_MANAGED_INDEXER")
    if configured:
        try:
            command = json.loads(configured) if configured.lstrip().startswith("[") else [configured]
        except ValueError:
            return None
        if not isinstance(command, list) or not command or not all(isinstance(value, str) and value for value in command):
            return None
    else:
        local=_checkout()/".local"/"managed-index"/"ManagedIndex.dll"
        command = [str(local if local.is_file() else _user_tool()/"ManagedIndex.dll")]
    if len(command) == 1 and command[0].lower().endswith(".dll"):
        if not Path(command[0]).is_file() or not shutil.which("dotnet"):
            return None
        return [shutil.which("dotnet"), command[0]]
    executable = shutil.which(command[0]) or (str(Path(command[0]).resolve()) if Path(command[0]).is_file() else None)
    return [executable, *command[1:]] if executable else None


def _unavailable(path, data, reason):
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "metadataStatus": "unavailable", "metadataError": reason,
            "assemblyIdentity": None, "references": [], "types": [], "dummyDll": False, "profileVerified": False,
            "metadataHint": "Optional offline PEReader helper: configure UVAULT_MANAGED_INDEXER or run python -m uvault.managed build"}

def producer_identity():
    launcher=_launcher()
    identity={"name":"uvault.managed-index","version":"1","reader":"System.Reflection.Metadata/PEReader","available":bool(launcher)}
    if launcher:
        candidate=Path(launcher[-1])
        if candidate.is_file():
            identity["adapterSha256"]=hashlib.sha256(candidate.read_bytes()).hexdigest()
    return identity


def parse_binaries(payloads: dict[str, bytes]) -> list[dict]:
    """Batch in-memory DLL bytes through the explicitly configured offline reader.

    Unavailable/bad adapter results remain explicit hash-only observations. Path
    or data contract violations raise ValueError before any subprocess starts.
    """
    if not isinstance(payloads, dict):
        raise ValueError("Managed metadata payloads must be a path-to-bytes mapping")
    for path, data in payloads.items():
        _safe_path(path)
        if not isinstance(data, bytes):
            raise ValueError("Managed metadata payload values must be bytes")
    if not payloads:
        return []
    launcher = _launcher()
    if launcher is None:
        return [_unavailable(path, data, "offline-metadata-adapter-unavailable") for path, data in payloads.items()]
    results, batch, batch_size = {}, {}, 0

    def flush():
        nonlocal batch, batch_size
        if not batch:
            return
        rows = [{"path": path, "base64": base64.b64encode(data).decode("ascii")} for path, data in batch.items()]
        try:
            response = subprocess.run(launcher, input=json.dumps(rows, separators=(",", ":")), capture_output=True,
                                      text=True, encoding="utf-8", timeout=120, check=False)
            if response.returncode != 0:
                raise ValueError("adapter-failed")
            decoded = json.loads(response.stdout)
            if (not isinstance(decoded, list) or len(decoded) != len(batch)
                    or {row.get("path") for row in decoded if isinstance(row, dict)} != set(batch)):
                raise ValueError("adapter-identity-mismatch")
            for row in decoded:
                data = batch[row["path"]]
                if row.get("sha256") != hashlib.sha256(data).hexdigest() or row.get("size") != len(data):
                    raise ValueError("adapter-byte-identity-mismatch")
                if row.get("metadataStatus") not in ("managed", "managed-module", "native-binary", "invalid-binary", "unavailable"):
                    raise ValueError("adapter-status-invalid")
                results[row["path"]] = row
        except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError, KeyError, TypeError):
            for path, data in batch.items():
                results[path] = _unavailable(path, data, "offline-metadata-adapter-failed-or-invalid")
        finally:
            batch, batch_size = {}, 0

    for path, data in payloads.items():
        if len(data) > MAX_BINARY_BYTES:
            results[path] = _unavailable(path, data, "binary-exceeds-metadata-input-limit")
            continue
        if batch and (batch_size + len(data) > MAX_BATCH_BYTES or len(batch) >= MAX_BATCH_FILES):
            flush()
        batch[path] = data
        batch_size += len(data)
    flush()
    return [results[path] for path in payloads]


def build_indexer(out=None):
    """Explicitly compile our dependency-free helper with local SDK packs only."""
    dotnet = shutil.which("dotnet")
    project = _checkout() / "tools" / "managed-index" / "ManagedIndex.csproj"
    checkout_source=project.is_file()
    if not checkout_source:
        project=Path(sys.prefix)/"share"/"uvault"/"managed-index"/"ManagedIndex.csproj"
    if not dotnet or not project.is_file():
        return {"metadataStatus": "unavailable", "error": "dotnet-sdk-or-checkout-tool-source-unavailable"}
    destination = Path(out).resolve() if out else (_checkout() / ".local" / "managed-index" if checkout_source else _user_tool())
    destination.mkdir(parents=True, exist_ok=True)
    empty_feed = destination / "empty-feed"
    empty_feed.mkdir(exist_ok=True)
    intermediate = destination / "obj"
    command = [dotnet, "build", str(project), "--configuration", "Release", "--output", str(destination),
               "--source", str(empty_feed), "--verbosity", "quiet", "-p:NuGetAudit=false", "-p:NuGetInteractive=false",
               "-p:EnableTargetingPackDownload=false", "-p:EnableRuntimePackDownload=false",
               "-p:BaseIntermediateOutputPath=" + str(intermediate) + os.sep,
               "-p:MSBuildProjectExtensionsPath=" + str(intermediate) + os.sep]
    environment = {**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_NOLOGO": "1"}
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=180, env=environment)
    except (OSError, subprocess.TimeoutExpired):
        return {"metadataStatus": "unavailable", "error": "local-sdk-build-failed"}
    decoder = destination / "ManagedIndex.dll"
    if result.returncode or not decoder.is_file():
        return {"metadataStatus": "unavailable", "error": "local-sdk-build-failed", "details": (result.stdout + result.stderr)[-12000:]}
    return {"metadataStatus": "ready", "framework": "net8.0", "indexer": str(decoder), "launcher": [dotnet, str(decoder)]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="Build only our reader using installed .NET8 SDK reference packs, with network restore disabled")
    build.add_argument("--out", help="Own-tool output directory; default checkout .local/managed-index")
    args = parser.parse_args(argv)
    result = build_indexer(args.out)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["metadataStatus"] == "ready" else 2


if __name__ == "__main__":
    sys.exit(main())
