"""Resolve evidence into explicit, immutable library selections."""
from __future__ import annotations

from copy import deepcopy


def _identity(candidate: dict) -> tuple[str, str, str]:
    return (str(candidate.get("packageId", "")), str(candidate.get("version", "")),
            str(candidate.get("variantId", "")))


def resolve(matches: dict, selections: list[dict] | None = None) -> dict:
    """Select unique candidates, never interpreting ordering as a preference.

    An explicit selection identifies all three of package/version/variant. It
    chooses a source to inspect; it never promotes the underlying evidence.
    """
    if not isinstance(matches, dict) or matches.get("schemaVersion") != "1.0":
        raise ValueError("matches must use schemaVersion 1.0")
    requested: dict[str, tuple[str, str, str]] = {}
    for selection in selections or []:
        key = _identity(selection)
        if not all(key):
            raise ValueError("selection requires packageId, version and variantId")
        if key[0] in requested:
            raise ValueError("only one selection per package is permitted")
        requested[key[0]] = key
    result = {"schemaVersion": "1.0", "catalogCommit": matches.get("catalogCommit"),
              "input": deepcopy(matches.get("input", {})),
              "profile": deepcopy(matches.get("profile")), "libraries": [],
              "unresolved": [], "unknown": deepcopy(matches.get("unknown", [])),
              "conflicts": deepcopy(matches.get("conflicts", []))}
    observed: set[str] = set()
    for match in matches.get("matches", []):
        package_id = match.get("packageId")
        if not package_id or package_id in observed:
            raise ValueError("matches must contain one record per packageId")
        observed.add(package_id)
        candidates: dict[tuple[str, str, str], dict] = {}
        for original in match.get("candidates", []):
            candidate = deepcopy(original)
            candidate.setdefault("packageId", package_id)
            key = _identity(candidate)
            if key[0] != package_id or not all(key):
                raise ValueError("candidate requires consistent packageId/version/variantId")
            if key in candidates and candidates[key] != candidate:
                raise ValueError("conflicting duplicate candidate identity")
            candidates[key] = candidate
        chosen = requested.get(package_id)
        if chosen is not None and chosen not in candidates:
            raise ValueError("explicit selection is absent from match candidates: " + package_id)
        if chosen is None and len(candidates) == 1:
            chosen = next(iter(candidates))
        if chosen is None:
            result["unresolved"].append({
                "packageId": package_id, "reason": "ambiguous-candidates" if candidates else "no-candidate",
                "status": match.get("status", "unknown"),
                "candidates": list(candidates.values()),
                "evidence": deepcopy(match.get("evidence", [])),
                "conflicts": deepcopy(match.get("conflicts", []))})
            continue
        candidate = candidates[chosen]
        library = {key: deepcopy(candidate.get(key)) for key in (
            "packageId", "version", "variantId", "artifact", "license", "sourceUrl",
            "sourceRef", "downloadUrl", "disposition", "fingerprint")}
        library.update({"status": match.get("status", "candidate"),
                        "evidence": deepcopy(match.get("evidence", [])),
                        "conflicts": deepcopy(match.get("conflicts", [])),
                        "suggestedReuseScope": deepcopy(match.get("suggestedReuseScope", [])),
                        "selection": "explicit" if package_id in requested else "unique-candidate",
                        "skipNativeRecovery": False})
        result["libraries"].append(library)
    missing = set(requested) - observed
    if missing:
        raise ValueError("selected package is absent from matches: " + ", ".join(sorted(missing)))
    result["unresolved"].extend({"reason": "unknown-input", "detail": deepcopy(item)}
                                for item in result["unknown"])
    return result
