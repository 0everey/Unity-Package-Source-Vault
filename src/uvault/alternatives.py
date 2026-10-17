"""Finite distribution alternatives; choosing a source never authenticates it."""
from copy import deepcopy

NEWTONSOFT = frozenset(("Newtonsoft.Json", "com.unity.nuget.newtonsoft-json"))


def excluded_by_selection(package_id, requested):
    selected = NEWTONSOFT & set(requested)
    return package_id in NEWTONSOFT and len(selected) == 1 and package_id not in selected


def preserve_conflicts(result):
    libraries = [p for p in result.get("libraries", []) if p.get("packageId") in NEWTONSOFT]
    if len({p["packageId"] for p in libraries}) < 2:
        return result
    conflict = {"kind": "alternative-distributions-selected", "group": "newtonsoft-json",
                "packageIds": sorted(NEWTONSOFT), "policy": "alternative-not-coinstall",
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
