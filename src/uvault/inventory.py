"""Byte fingerprints and conservative Unity source observations.

Declarations are lexical clues over every preprocessor branch, not a C# compiler.
No target assembly is loaded and no package payload is persisted by this module.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def source_set_sha256(files):
    """Contract v1 canonical hash; the empty hash does not establish equality."""
    sources = sorted(({"path": f["path"], "sha256": f["sha256"]}
                      for f in files if f["path"].lower().endswith(".cs")),
                     key=lambda f: f["path"])
    return _sha(json.dumps(sources, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _safe_name(name):
    name = name.replace("\\", "/")
    # Reject before normalization, including Windows drive/ADS and UNC forms.
    if name.startswith("/") or ":" in name or "\x00" in name:
        raise ValueError("Archive contains an unsafe path")
    parts = name.split("/")
    if ".." in parts:
        raise ValueError("Archive contains path traversal")
    return "/".join(p for p in parts if p not in ("", "."))


def _kind(path):
    ext = PurePosixPath(path).suffix.lower()
    return {".cs": "source", ".dll": "managed-or-native-binary", ".asmdef": "assembly-definition",
            ".asmref": "assembly-reference", ".meta": "unity-metadata"}.get(ext, "other")


def _strip_root(files):
    roots = {p.split("/", 1)[0] for p in files}
    if len(roots) == 1 and files and all("/" in p for p in files):
        return {p.split("/", 1)[1]: data for p, data in files.items()}
    return files


def fingerprint_archive(data: bytes, format: str) -> dict:
    """Read a tar/zip/Unity package in memory, reject links/traversal/duplicates."""
    fmt = format.lower().lstrip(".")
    files = {}
    total = 0

    def add(name, payload):
        nonlocal total
        name = _safe_name(name)
        if not name:
            return
        if name in files:
            raise ValueError("Archive contains duplicate file paths")
        total += len(payload)
        if total > 1024 * 1024 * 1024:
            raise ValueError("Archive expands beyond the 1 GiB inventory limit")
        files[name] = payload

    if fmt in ("zip", "nupkg"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for entry in archive.infolist():
                _safe_name(entry.filename)
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError("Archive contains a symbolic link")
                if not entry.is_dir():
                    if entry.file_size + total > 1024 * 1024 * 1024:
                        raise ValueError("Archive expands beyond the 1 GiB inventory limit")
                    add(entry.filename, archive.read(entry))
    elif fmt in ("tar", "tgz", "tar.gz", "gz", "tar.bz2", "tar.xz", "unitypackage"):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for entry in archive:
                _safe_name(entry.name)
                if entry.isdir():
                    continue
                if not entry.isfile():
                    raise ValueError("Archive contains a link or special file")
                if entry.size + total > 1024 * 1024 * 1024:
                    raise ValueError("Archive expands beyond the 1 GiB inventory limit")
                add(entry.name, archive.extractfile(entry).read())
        if fmt == "unitypackage":
            logical = {}
            for name, payload in files.items():
                if name.endswith("/pathname"):
                    prefix = name.rsplit("/", 1)[0]
                    target = _safe_name(payload.decode("utf-8-sig").strip())
                    for suffix, destination in (("asset", target), ("asset.meta", target + ".meta")):
                        member = prefix + "/" + suffix
                        if member in files:
                            if destination in logical:
                                raise ValueError("Unity package contains duplicate asset paths")
                            logical[destination] = files[member]
            files = logical
    else:
        raise ValueError("Unsupported archive format: " + format)
    result = _inventory(_strip_root(files), None)
    result.update(artifactSha256=_sha(data), artifactSize=len(data), artifactFormat=fmt)
    return result


def inventory_directory(path, profile=None) -> dict:
    """Inventory exactly this directory; reject links and do not follow projects."""
    root = Path(path)
    if not root.is_dir() or root.is_symlink() or getattr(root, "is_junction", lambda: False)():
        raise ValueError("Inventory input must be a directory without links")
    payloads, file_rows = {}, []
    for current, directories, names in os.walk(root, followlinks=False):
        # These are tool/build state rather than actual source inputs. Do not
        # exclude Library globally: a selected PackageCache can itself be input.
        directories[:] = sorted(d for d in directories if d not in (".git", ".hg", ".svn", "__pycache__"))
        for name in directories + sorted(names):
            child = Path(current) / name
            if child.is_symlink() or getattr(child, "is_junction", lambda: False)():
                raise ValueError("Inventory does not follow symbolic links or junctions")
        for name in sorted(names):
            child = Path(current) / name
            relative = child.relative_to(root).as_posix()
            parse_needed = relative.lower().endswith((".cs", ".asmdef", ".asmref", ".asmdef.meta"))
            if parse_needed:
                data = child.read_bytes()
                payloads[relative] = data
                digest, size, dummy = _sha(data), len(data), False
            else:
                digestor, size, dummy, previous = hashlib.sha256(), 0, False, b""
                with child.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digestor.update(chunk)
                        size += len(chunk)
                        if relative.lower().endswith(".dll"):
                            dummy = dummy or b"Il2CppDummyDll" in previous + chunk
                            previous = chunk[-32:]
                digest = digestor.hexdigest()
            row = {"path": relative, "sha256": digest, "size": size, "kind": _kind(relative)}
            if relative.lower().endswith(".dll"):
                row["dummyDll"] = dummy or any(p.lower() == "dummydll" for p in PurePosixPath(relative).parts)
            file_rows.append(row)
    return _inventory(payloads, profile, file_rows)


def _json(data):
    try:
        value = json.loads(data.decode("utf-8-sig"))
        return value if isinstance(value, dict) else None
    except (UnicodeError, ValueError):
        return None


def _bool_expression(expression, symbols):
    """Small C# preprocessor boolean grammar. Unsupported expressions => None."""
    if symbols is None:
        return None
    tokens = re.findall(r"&&|\|\||==|!=|[!()]|[A-Za-z_]\w*", expression)
    if "".join(tokens) != re.sub(r"\s+", "", expression):
        return None
    position = 0

    def atom():
        nonlocal position
        if position >= len(tokens):
            raise ValueError()
        token = tokens[position]
        position += 1
        if token == "!":
            return not atom()
        if token == "(":
            result = expr()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError()
            position += 1
            return result
        if not re.fullmatch(r"[A-Za-z_]\w*", token):
            raise ValueError()
        return token == "true" or (token != "false" and token in symbols)

    def equality():
        nonlocal position
        result = atom()
        while position < len(tokens) and tokens[position] in ("==", "!="):
            operator = tokens[position]
            position += 1
            other = atom()
            result = result == other if operator == "==" else result != other
        return result

    def conjunction():
        nonlocal position
        result = equality()
        while position < len(tokens) and tokens[position] == "&&":
            position += 1
            other = equality()
            result = result and other
        return result

    def expr():
        nonlocal position
        result = conjunction()
        while position < len(tokens) and tokens[position] == "||":
            position += 1
            other = conjunction()
            result = result or other
        return result

    try:
        result = expr()
        return result if position == len(tokens) else None
    except (ValueError, RecursionError):
        return None


def _active_text(text, profile):
    # Never infer a complete compiler define set from a handful of user symbols.
    symbols = set(profile.get("defines", [])) if profile and profile.get("definesComplete") is True else None
    stack, output, issues = [], [], []
    active = True
    for line in text.splitlines():
        match = re.match(r"\s*#\s*(if|elif|else|endif|define|undef)\b(.*)", line)
        if not match:
            if active is not False:
                output.append(line)
            continue
        directive, argument = match.groups()
        argument = argument.split("//", 1)[0].strip()
        if directive in ("define", "undef"):
            # C# file-local symbols are not a package profile.
            if symbols is not None and active is True:
                if directive == "define":
                    symbols.add(argument)
                else:
                    symbols.discard(argument)
            continue
        if directive == "if":
            condition = _bool_expression(argument, symbols)
            stack.append([active, condition])
            active = False if active is False or condition is False else (None if active is None or condition is None else True)
        elif not stack:
            issues.append("unbalanced-preprocessor")
        elif directive == "endif":
            active = stack.pop()[0]
        else:
            parent, seen = stack[-1]
            condition = True if directive == "else" else _bool_expression(argument, symbols)
            branch = False if seen is True or condition is False else (None if seen is None or condition is None else True)
            active = False if parent is False or branch is False else (None if parent is None or branch is None else True)
            stack[-1][1] = True if seen is True or condition is True else (None if seen is None or condition is None else False)
        if active is None:
            issues.append("unknown-preprocessor-condition")
    if stack:
        issues.append("unbalanced-preprocessor")
    return "\n".join(output), sorted(set(issues))


def _declarations(text):
    # Remove comments/string literals while preserving punctuation/newlines.
    clean = re.sub(r'//[^\n]*|/\*.*?\*/|@"(?:""|[^"])*"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                   lambda m: "\n" * m.group().count("\n") + " ", text, flags=re.S)
    tokens = re.findall(r"@?[A-Za-z_]\w*(?:\.@?[A-Za-z_]\w*)*|[{};]", clean)
    namespaces, types, scopes = set(), set(), []
    namespace, file_namespace, pending = "", "", None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "namespace" and index + 1 < len(tokens):
            value = tokens[index + 1].replace("@", "")
            pending = ("namespace", ".".join(p for p in (namespace, value) if p))
            namespaces.add(pending[1])
            index += 1
        elif token in ("class", "struct", "interface", "enum", "record", "delegate") and index + 1 < len(tokens):
            offset = 2 if token == "record" and tokens[index + 1] in ("class", "struct") else 1
            if index + offset < len(tokens):
                value = tokens[index + offset].replace("@", "")
                if re.fullmatch(r"[A-Za-z_]\w*", value):
                    parents = [s[1] for s in scopes if s[0] == "type"]
                    full = ".".join(p for p in (namespace, "+".join(parents + [value])) if p)
                    types.add(full)
                    pending = ("type", value)
                    index += offset
        elif token == "{":
            scopes.append(pending or ("block", ""))
            if pending and pending[0] == "namespace":
                namespace = pending[1]
            pending = None
        elif token == "}":
            if scopes:
                scopes.pop()
            namespace = next((s[1] for s in reversed(scopes) if s[0] == "namespace"), file_namespace)
            pending = None
        elif token == ";":
            if pending and pending[0] == "namespace":
                namespace = file_namespace = pending[1]
            pending = None
        index += 1
    return namespaces, types


def _assembly_active(definition, profile):
    issues = []
    platform = (profile or {}).get("platform") or (profile or {}).get("targetPlatform")
    includes, excludes = definition.get("includePlatforms", []), definition.get("excludePlatforms", [])
    known_platforms = {"Editor", "Android", "iOS", "WebGL", "WindowsStandalone32", "WindowsStandalone64",
                       "LinuxStandalone64", "OSXStandalone", "macOSStandalone", "WSA", "PS4", "PS5",
                       "XboxOne", "tvOS", "Switch", "Lumin", "Stadia", "GameCoreXboxSeries",
                       "GameCoreXboxOne", "EmbeddedLinux", "QNX", "VisionOS"}
    active = True
    if includes or excludes:
        if not platform or platform not in known_platforms or any(p not in known_platforms for p in includes + excludes):
            active = None
            issues.append("unknown-platform" if not platform else "unrecognized-platform")
        elif (includes and platform not in includes) or platform in excludes:
            active = False
    symbols = set(profile.get("defines", [])) if profile and profile.get("definesComplete") is True else None
    if definition.get("versionDefines"):
        # Version-defined symbols depend on Unity's package/version expression
        # rules. Preserve the raw requirements rather than inventing symbols.
        symbols = None
        issues.append("version-defines-unverified")
    for constraint in definition.get("defineConstraints", []):
        value = _bool_expression(constraint.replace("||", " || "), symbols)
        if value is False:
            active = False
        elif value is None:
            if active is not False:
                active = None
            issues.append("unknown-define-constraint")
    return active, issues


def _inventory(payloads, profile, file_rows=None):
    files = sorted(file_rows, key=lambda f: f["path"]) if file_rows is not None else [
        {"path": path, "sha256": _sha(data), "size": len(data), "kind": _kind(path)}
        for path, data in sorted(payloads.items())]
    diagnostics, definitions, by_name, guids, owners = [], {}, {}, {}, {}
    for path, data in payloads.items():
        if path.lower().endswith(".asmdef"):
            definition = _json(data)
            if not definition or not isinstance(definition.get("name"), str):
                diagnostics.append({"kind": "invalid-asmdef", "path": path})
                # Retain a boundary so invalid child asmdef cannot inherit parent.
                definition = {"name": None}
            guid_match = re.search(r"(?m)^guid:\s*([0-9a-fA-F]{32})\s*$", payloads.get(path + ".meta", b"").decode("utf-8-sig", "replace"))
            guid = guid_match.group(1).lower() if guid_match else None
            active, issues = _assembly_active(definition, profile)
            entry = {"name": definition["name"], "path": path, "guid": guid,
                     "sourceFiles": [], "ownershipVerified": bool(definition["name"]),
                     "profileVerified": False, "active": active,
                     "includePlatforms": definition.get("includePlatforms", []),
                     "excludePlatforms": definition.get("excludePlatforms", []),
                     "defineConstraints": definition.get("defineConstraints", []),
                     "versionDefines": definition.get("versionDefines", []),
                     "references": definition.get("references", []), "profileIssues": issues}
            definitions[path] = entry
            by_name.setdefault(entry["name"], []).append(entry)
            if guid:
                guids.setdefault(guid, []).append(entry)
            owners.setdefault(str(PurePosixPath(path).parent), []).append(entry)
    for name, entries in by_name.items():
        if name and len(entries) > 1:
            diagnostics.append({"kind": "duplicate-assembly-name", "name": name,
                                "paths": sorted(entry["path"] for entry in entries)})
            for entry in entries:
                entry["ownershipVerified"] = False
    for path, data in payloads.items():
        if path.lower().endswith(".asmref"):
            reference = (_json(data) or {}).get("reference", "")
            candidates = guids.get(reference[5:].lower(), []) if reference.startswith("GUID:") else by_name.get(reference, [])
            owner = candidates[0] if len(candidates) == 1 and candidates[0]["name"] else None
            owners.setdefault(str(PurePosixPath(path).parent), []).append(owner)
            if not owner:
                diagnostics.append({"kind": "unresolved-asmref", "path": path, "reference": reference})
    namespaces, types, active_types, defaults = set(), set(), set(), {}
    conditionals = []
    for file in files:
        path = file["path"]
        if not path.lower().endswith(".cs"):
            if path.lower().endswith(".dll"):
                dummy = file.get("dummyDll", False) or any(p.lower() == "dummydll" for p in PurePosixPath(path).parts) or b"Il2CppDummyDll" in payloads.get(path, b"")
                file["dummyDll"] = dummy
            continue
        parent = PurePosixPath(path).parent
        owner, reason = None, "unity-default"
        while True:
            boundary = owners.get(str(parent))
            if boundary is not None:
                if len(boundary) == 1 and boundary[0] is not None:
                    owner, reason = boundary[0], "nearest-asmdef-or-asmref"
                else:
                    reason = "ambiguous-assembly-boundary"
                    diagnostics.append({"kind": "ambiguous-assembly-boundary", "path": path})
                break
            if str(parent) == ".":
                break
            parent = parent.parent
        if owner is None and reason == "unity-default":
            parts = PurePosixPath(path).parts[:-1]
            editor = "Editor" in parts
            firstpass = any(p in ("Standard Assets", "Pro Standard Assets", "Plugins") for p in parts)
            name = "Assembly-CSharp" + ("-Editor" if editor else "") + ("-firstpass" if firstpass else "")
            editor_mode = (profile or {}).get("isEditor")
            owner = defaults.setdefault(name, {"name": name, "path": None, "sourceFiles": [],
                                       "ownershipVerified": not firstpass, "profileVerified": False,
                                       "active": (editor_mode if isinstance(editor_mode, bool) else None) if editor else True,
                                       "profileIssues": ["unity-default-rules-not-compiler-verified"]})
        if owner:
            owner["sourceFiles"].append(path)
        file["assembly"] = owner["name"] if owner else None
        file["ownershipBasis"] = reason
        text = payloads[path].decode("utf-8-sig", "replace")
        ns, ts = _declarations(text)
        namespaces.update(ns)
        types.update(ts)
        active_text, issues = _active_text(text, profile)
        if re.search(r"(?m)^\s*#\s*(if|elif)\b", text):
            conditionals.append({"path": path, "issues": issues})
        if profile is not None and not issues and owner and owner.get("active") is True:
            active_types.update(_declarations(active_text)[1])
    result = {"files": files, "sourceSetSha256": source_set_sha256(files),
              "assemblies": sorted(list(definitions.values()) + list(defaults.values()), key=lambda a: (a["name"] or "", a["path"] or "")),
              "namespaces": sorted(namespaces), "types": sorted(types), "profileVerified": False,
              "declarationBasis": "lexical-all-source-branches-not-a-CSharp-parser",
              "conditionalSources": conditionals, "diagnostics": diagnostics}
    if profile is not None:
        result["profile"] = profile
        result["activeTypes"] = sorted(active_types)
        result["activeDeclarationBasis"] = "partial-explicit-profile-observation-not-compiler-verified"
    return result
