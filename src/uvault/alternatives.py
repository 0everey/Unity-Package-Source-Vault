"""Finite distribution alternatives; choosing a source never authenticates it."""
from copy import deepcopy

NEWTONSOFT = frozenset(("Newtonsoft.Json", "com.unity.nuget.newtonsoft-json"))
_NORMALIZED = frozenset(p.casefold() for p in NEWTONSOFT)


def excluded_by_selection(package_id, requested):
    selected = _NORMALIZED & {p.casefold() for p in requested}
    normalized = package_id.casefold()
    return normalized in _NORMALIZED and len(selected) == 1 and normalized not in selected


def preserve_conflicts(result):
    libraries = [p for p in result.get("libraries", []) if str(p.get("packageId", "")).casefold() in _NORMALIZED]
    if len({p["packageId"].casefold() for p in libraries}) < 2:
        return result
    conflict = {"kind": "alternative-distributions-selected", "group": "newtonsoft-json",
                "packageIds": sorted({p["packageId"] for p in libraries}), "policy": "alternative-not-coinstall",
                "reason": "Select one distribution explicitly; matching assembly names/versions do not establish interchangeable packages"}
    if conflict not in result.setdefault("conflicts", []):
        result["conflicts"].append(deepcopy(conflict))
    for library in libraries:
        if conflict not in library.setdefault("conflicts", []):
            library["conflicts"].append(deepcopy(conflict))
        if library.get("suggestedReuseScope"):
            library.setdefault("conflictedSuggestedReuseScope", deepcopy(library["suggestedReuseScope"]))
            library["suggestedReuseScope"] = []
    return result
