"""Detect bundled binary components without extracting or executing payloads."""
from __future__ import annotations
import io
from pathlib import PurePosixPath
import tarfile
import zipfile


def binary_reason(name, header):
    path = PurePosixPath(name.replace("\\", "/"))
    parts = path.parts
    if path.suffix.lower() in (".dll", ".so", ".dylib", ".a", ".lib", ".exe"):
        return "binary-extension"
    if header.startswith((b"MZ", b"\x7fELF", b"!<arch>\n")) or header[:4] in (
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    ):
        return "binary-header"
    for index, part in enumerate(parts[:-1]):
        if part.lower().endswith(".bundle") and tuple(p.lower() for p in parts[index+1:index+3]) == ("contents", "macos"):
            return "macos-bundle-executable-layout"
        if part.lower().endswith(".framework") and path.name.casefold() == part[:-10].casefold():
            return "macos-framework-executable-layout"
    return None


def binary_components(data, archive_format):
    """Read at most 32 uncompressed bytes per file; keep names/reasons only."""
    result = []
    def inspect(name, stream):
        reason = binary_reason(name, stream.read(32) if stream else b"")
        if reason:
            result.append({"path": name.replace("\\", "/"), "detection": reason})
    if archive_format in ("zip", "nupkg"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for item in archive.infolist():
                if not item.is_dir():
                    with archive.open(item) as stream:
                        inspect(item.filename, stream)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|*") as archive:
            for item in archive:
                if item.isfile():
                    with archive.extractfile(item) as stream:
                        inspect(item.name, stream)
    return result
