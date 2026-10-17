"""Raw NuGet group/asset evidence and finite .NET Standard candidates, no installer."""
from copy import deepcopy
import hashlib
import re
import xml.etree.ElementTree as ET


def parse_nuspec(content, path):
    root = ET.fromstring(content)
    local = lambda node: node.tag.rsplit("}", 1)[-1]
    nodes = lambda name: [n for n in root.iter() if local(n) == name]
    groups = []
    for dependencies in nodes("dependencies"):
        direct = [dict(n.attrib) for n in dependencies if local(n) == "dependency"]
        if direct:
            groups.append({"targetFramework": None, "dependencies": direct})
        for group in dependencies:
            if local(group) == "group":
                groups.append({"targetFramework": group.attrib.get("targetFramework"),
                               "dependencies": [dict(n.attrib) for n in group if local(n) == "dependency"]})
    licenses, repositories = nodes("license"), nodes("repository")
    return {"declaredLicense": licenses[0].text if licenses else None,
            "repository": dict(repositories[0].attrib) if repositories else {},
            "dependencies": [dict(n.attrib) for n in nodes("dependency")],
            "targetFrameworks": sorted({g["targetFramework"] for g in groups if g["targetFramework"]}),
            "dependencyGroups": groups, "nuspecSha256": hashlib.sha256(content).hexdigest(), "nuspecPath": path}


def assets(files):
    result = []
    for file in files:
        parts = file.get("path", "").split("/")
        if len(parts) >= 3 and parts[0] in ("lib", "ref") and parts[-1].lower().endswith(".dll"):
            result.append({"path": file["path"], "targetFramework": parts[1], "kind": parts[0],
                           "sha256": file["sha256"], "size": file.get("size")})
    return result


def _number(text):
    if not isinstance(text, str) or not re.fullmatch(r"\d+(?:\.\d+){0,3}", text):
        return None
    parts = tuple(map(int, text.split(".")))
    return parts + (0,) * (4-len(parts))


def satisfies(version, specification):
    """Only numeric NuGet minimum/exact/interval ranges; unknown stays None."""
    actual = _number(version)
    if actual is None or not isinstance(specification, str):
        return None
    spec = specification.strip()
    minimum = _number(spec)
    if minimum is not None:
        return actual >= minimum
    if re.fullmatch(r"\[\d+(?:\.\d+){0,3}\]", spec):
        return actual == _number(spec[1:-1])
    if len(spec) < 3 or spec[0] not in "[(" or spec[-1] not in ")]" or spec.count(",") != 1:
        return None
    low, high = (s.strip() for s in spec[1:-1].split(","))
    lo, hi = _number(low), _number(high)
    if (low and lo is None) or (high and hi is None) or not (low or high):
        return None
    if (not low and spec[0] != "(") or (not high and spec[-1] != ")"):
        return None
    if lo is not None and hi is not None and (lo > hi or (lo == hi and (spec[0] != "[" or spec[-1] != "]"))):
        return None
    return (lo is None or actual > lo or (actual == lo and spec[0] == "[")) and (hi is None or actual < hi or (actual == hi and spec[-1] == "]"))


def _tfm(value):
    return str(value or "").casefold().replace(".netstandard", "netstandard")


def dependency_candidates(state):
    by_id = {p["id"].casefold(): p for p in state.get("packages", [])}
    report = []
    for package in state.get("packages", []):
        for version in package.get("versions", []):
            nuget = version.get("nuget") or {}
            if "dependencyGroups" not in nuget:
                continue
            for requested in ("netstandard2.0", "netstandard2.1"):
                groups = [g for g in nuget["dependencyGroups"] if _tfm(g.get("targetFramework")) == requested]
                fallback = False
                if not groups and requested == "netstandard2.1":
                    groups = [g for g in nuget["dependencyGroups"] if _tfm(g.get("targetFramework")) == "netstandard2.0"]
                    fallback = bool(groups)
                row = {"parent": {"packageId": package["id"], "version": version["version"], "variantId": version["variantId"],
                                  "archiveSha256": (version.get("artifact") or {}).get("sha256"), "nuspecSha256": nuget.get("nuspecSha256")},
                       "requestedFramework": requested, "status": "explicit-compatible-fallback-candidate" if fallback else "declared-framework-candidate" if groups else "framework-group-unavailable",
                       "dependencyGroups": deepcopy(groups), "assets": [], "dependencies": [],
                       "profileVerified": False, "installed": False, "compiled": False, "completeClosure": False}
                frameworks = {_tfm(g.get("targetFramework")) for g in groups}
                row["assets"] = [deepcopy(a) for a in nuget.get("assets", []) if _tfm(a.get("targetFramework")) in frameworks]
                for group in groups:
                    for dependency in group["dependencies"]:
                        candidates = []
                        for record in by_id.get(str(dependency.get("id", "")).casefold(), {}).get("versions", []):
                            candidates.append({"version": record["version"], "variantId": record["variantId"],
                                               "satisfiesRange": satisfies(record["version"], dependency.get("version"))})
                        row["dependencies"].append({**deepcopy(dependency), "declaringFramework": group.get("targetFramework"),
                            "catalogEvaluations": candidates, "status": "range-unassessed" if satisfies("0.0.0", dependency.get("version")) is None else "catalog-range-candidates-only" if any(c["satisfiesRange"] is True for c in candidates) else "named-dependency-gap",
                            "automaticSubstitution": False})
                report.append(row)
    return {"kind": "catalog-dependency-candidates-not-installed", "frameworkPolicy": "netstandard2.0/2.1 only; explicit 2.0 fallback candidate, never reference verification",
            "completeClosure": False, "parents": report}
