"""Limit component attribution while preserving the original archive manifest."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import hashlib
from .inventory import source_set_sha256


def producer_identity():
    return {"name":"file-path-component-scope-1","sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def component_path(version):
    path=version.get("sourcePath") or (version.get("componentScope") or {}).get("sourcePath")
    if not path:return None
    if not isinstance(path,str) or path.startswith("/") or any(p in ("", ".", "..") for p in path.split("/")) or any(c in path for c in ("\\", ":", "?", "#")):
        raise ValueError("Invalid component source path")
    return path


def scoped_fingerprint(version):
    fingerprint=version.get("fingerprint") or {}
    path=component_path(version)
    if path is None:return fingerprint
    inside=lambda value:isinstance(value,str) and value.startswith(path+"/")
    if "files" not in fingerprint:
        index=fingerprint.get("componentIndex") or {}
        if index.get("sourcePath")==path and index.get("basis")=="file-path-scoped-original-manifest":
            return index
        # Older compact fingerprints cannot prove per-type paths. Preserve only
        # weak assembly clues rather than treating the whole repo as a component.
        return {"assemblies":[{**deepcopy(a),"ownershipVerified":False,"types":[]} for a in fingerprint.get("assemblies",[]) if isinstance(a,dict)],
                "types":[],"namespaces":[],"profileVerified":False,"sourcePath":path,
                "scopeStatus":"component-path-attribution-unavailable"}
    files=[deepcopy(f) for f in fingerprint["files"] if inside(f.get("path"))]
    file_paths={f["path"] for f in files}
    declarations=[deepcopy(d) for d in fingerprint.get("typeDeclarations",[]) if inside(d.get("sourcePath")) and d.get("sourcePath") in file_paths]
    assemblies=[]
    for original in fingerprint.get("assemblies",[]):
        if not isinstance(original,dict):continue
        identity=original.get("assemblyIdentity") or original.get("scope") or original
        name=identity.get("name")
        owned=[d for d in declarations if (d.get("assemblyIdentity") or {}).get("name")==name]
        source_files=[p for p in original.get("sourceFiles",[]) if p in file_paths]
        if not owned and not source_files and original.get("path") not in file_paths:continue
        row=deepcopy(original);row["sourceFiles"]=source_files
        # Source asmdef paths alone do not bind all their types: asmref sources
        # may live outside this component. Managed DLL paths bind their own types.
        types={d.get("fullName") or d.get("typeFullName") for d in owned if d.get("ownershipVerified") is not False}
        if original.get("path") in file_paths and str(original.get("path","")).lower().endswith(".dll"):
            types.update(t if isinstance(t,str) else t.get("fullName") for t in original.get("types",[]))
        row["types"]=sorted(t for t in types if t)
        assemblies.append(row)
    names={d.get("fullName") or d.get("typeFullName") for d in declarations}
    names.update(t for a in assemblies for t in a.get("types",[]))
    return {"files":files,"assemblies":assemblies,"typeDeclarations":declarations,
            "types":sorted(n for n in names if n),"namespaces":sorted({n.rsplit('.',1)[0] for n in names if n and '.' in n}),
            "sourceSetSha256":source_set_sha256(files),"profileVerified":False,
            "managedMetadata":[deepcopy(m) for m in fingerprint.get("managedMetadata",[]) if m.get("path") in file_paths],
            "sourcePath":path,"basis":"file-path-scoped-original-manifest"}


def routing_index(version):
    scoped=deepcopy(scoped_fingerprint(version))
    files=scoped.pop("files",[])
    scoped.pop("typeDeclarations",None);scoped.pop("managedMetadata",None)
    for assembly in scoped.get("assemblies",[]):assembly.pop("sourceFiles",None)
    scoped["sourceSetNonEmpty"]=any(f.get("path","").lower().endswith(".cs") for f in files)
    scoped["binaryFingerprints"]=[f for f in files if f.get("path","").lower().endswith(".dll")]
    return scoped
