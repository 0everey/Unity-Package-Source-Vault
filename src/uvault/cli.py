"""JSON command-line interface for the public source vault."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import zipfile

from .materialize import materialize
from .remaker import export_remaker
from .resolve import resolve

DEFAULT_REGISTRY = "https://raw.githubusercontent.com/0everey/Unity-Package-Source-Vault/main/catalog/catalog.json"


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({"schemaVersion": "1.0", "error": message}), file=sys.stderr)
        raise SystemExit(2)


def _read(path: str) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("JSON input must be an object")
    return value


def _write(path: str | Path, value: dict) -> None:
    path = Path(path)
    if not path.parent.is_dir():
        raise ValueError("output parent must already exist")
    # Exclusive creation protects existing evidence and review artifacts.
    with path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _partial(result: dict) -> bool:
    if any(result.get(key) for key in ("unresolved", "unknown", "conflicts")):
        return True
    for match in result.get("matches", []):
        if match.get("conflicts") or len(match.get("candidates", [])) != 1:
            return True
        if match.get("status") not in ("exact-artifact", "exact-source", "source-exact", "pinned-source"):
            return True
    if any(item.get("conflicts") or item.get("status") not in ("exact-artifact","pinned-source","materialized","reused")
           for item in result.get("libraries", [])):
        return True
    return False


def parser() -> argparse.ArgumentParser:
    result = _Parser(prog="uvault", description="Identify and materialize Unity package sources with preserved evidence.")
    commands = result.add_subparsers(dest="command", required=True)
    catalog = commands.add_parser("catalog", help="Read or synchronize a pinned registry")
    catalog_commands = catalog.add_subparsers(dest="catalog_command", required=True)
    sync = catalog_commands.add_parser("sync", help="Load a registry; optionally write expanded catalog.json")
    sync.add_argument("--registry", default=DEFAULT_REGISTRY)
    sync.add_argument("--out", help="New directory for the small expanded catalog; no packages are downloaded")
    identify = commands.add_parser("identify", help="Identify an archive, directory, Unity lock or ReMaker input")
    identify.add_argument("--input", required=True)
    identify.add_argument("--registry", default=DEFAULT_REGISTRY)
    identify.add_argument("--profile", help="Profile JSON file or inline JSON object")
    identify.add_argument("--out", required=True, help="New result directory containing matches.json")
    select = commands.add_parser("resolve", help="Resolve unique candidates or select explicit immutable identities")
    select.add_argument("--matches", required=True)
    select.add_argument("--out", required=True)
    select.add_argument("--package", action="append", default=[], help="Package ID; repeat with corresponding version and variant")
    select.add_argument("--version", action="append", default=[])
    select.add_argument("--variant", action="append", default=[])
    fetch = commands.add_parser("materialize", help="Verify and extract permitted sources into one usage directory")
    fetch.add_argument("--lock", required=True)
    fetch.add_argument("--target", required=True)
    fetch.add_argument("--offline", action="store_true", help="Only verified existing destination reuse; no package cache")
    export = commands.add_parser("export-remaker", help="Write a pending handoff without changing ReMaker production")
    export.add_argument("--lock", required=True)
    export.add_argument("--out", required=True)
    export.add_argument("--materialized", help="Materialization receipt JSON file")
    return result


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = parser().parse_args(argv)
    try:
        if args.command == "catalog":
            from .catalog import load_registry
            result = load_registry(args.registry)
            if args.out:
                output = Path(args.out)
                output.mkdir(parents=False, exist_ok=False)
                try:
                    _write(output / "catalog.json", result)
                except Exception:
                    # Only this command's just-created, empty directory is removed.
                    if not any(output.iterdir()):
                        output.rmdir()
                    raise
        elif args.command == "identify":
            from .catalog import load_registry
            from .identify import identify
            profile = None
            if args.profile:
                profile = json.loads(args.profile) if args.profile.lstrip().startswith("{") else _read(args.profile)
                if not isinstance(profile, dict):
                    raise ValueError("profile must be a JSON object")
            output = Path(args.out)
            if output.exists() or output.is_symlink():
                raise ValueError("identify requires a new output directory")
            result = identify(args.input, load_registry(args.registry), profile=profile)
            output.mkdir(parents=False, exist_ok=False)
            try:
                _write(output / "matches.json", result)
            except Exception:
                if not any(output.iterdir()):
                    output.rmdir()
                raise
        elif args.command == "resolve":
            if not (len(args.package) == len(args.version) == len(args.variant)):
                raise ValueError("each --package requires a corresponding --version and --variant")
            selections = [{"packageId": package, "version": version, "variantId": variant}
                          for package, version, variant in zip(args.package, args.version, args.variant)]
            result = resolve(_read(args.matches), selections)
            _write(args.out, result)
        elif args.command == "materialize":
            result = materialize(_read(args.lock), args.target, offline=args.offline)
        else:
            result = export_remaker(_read(args.lock), _read(args.materialized) if args.materialized else None,
                                    lock_file_sha256=hashlib.sha256(Path(args.lock).read_bytes()).hexdigest())
            _write(args.out, result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 3 if _partial(result) else 0
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(json.dumps({"schemaVersion": "1.0", "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
