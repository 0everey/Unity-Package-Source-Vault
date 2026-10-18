"""Build a reviewable handoff; never mutate a ReMaker project."""
from __future__ import annotations

from copy import deepcopy
from .materialize import canonical_hash


def export_remaker(lock: dict, materialized: dict | None = None, lock_file_sha256: str | None = None) -> dict:
    if not isinstance(lock, dict) or lock.get("schemaVersion") != "1.0":
        raise ValueError("lock must use schemaVersion 1.0")
    digest = canonical_hash(lock)
    if materialized is not None and materialized.get("lockSha256") != digest:
        raise ValueError("materialized receipt does not belong to this lock")
    result = {"schemaVersion": "1.0", "lockSha256": lock_file_sha256 or digest,
              "lockContentSha256": digest, "lockHashBasis":"file-bytes" if lock_file_sha256 else "canonical-json-dict-api",
              "catalogCommit": lock.get("catalogCommit"),
              "inputIdentity": deepcopy(lock.get("input", {})),
              "profile": deepcopy(lock.get("profile")),
              "sourceRefs": [], "libraries": deepcopy(lock.get("libraries", [])),
              "materialized": deepcopy(materialized), "fetchInstructions": [], "matchBasis": [],
              "conflicts": deepcopy(lock.get("conflicts", [])),
              "unknown": deepcopy(lock.get("unknown", [])),
              "unresolved": deepcopy(lock.get("unresolved", [])),
              "suggestedReuseScope": [], "adoptionStatus": "pending", "skipNativeRecovery": False}
    if lock.get("namedPending"):
        result["namedPending"]=deepcopy(lock["namedPending"])
    for unresolved in (materialized or {}).get("unresolved",[]):
        if unresolved not in result["unresolved"]:
            result["unresolved"].append(deepcopy(unresolved))
    # Bind the original input/receipt first, then derive every consumer field
    # from a protected copy, so status and reuse suggestions cannot diverge.
    from .family_identity import CONTEXT_FIELDS,preserve_context
    for key in ("nugetDependencyCandidates", "unselectedAlternatives", *CONTEXT_FIELDS):
        if key in lock:
            result[key] = deepcopy(lock[key])
    from .named_identity import preserve_pending
    preserve_pending(result)
    from .alternatives import preserve_conflicts
    preserve_conflicts(result)
    preserve_context(result)
    for library in result["libraries"]:
        identity = {key: library.get(key) for key in ("packageId", "version", "variantId")}
        result["sourceRefs"].append({**identity, "sourceUrl": library.get("sourceUrl"),
            "sourceRef": library.get("sourceRef"), "artifact": deepcopy(library.get("artifact")),
            "disposition": library.get("disposition"), "license": deepcopy(library.get("license"))})
        result["matchBasis"].append({**identity, "status": library.get("status", "unknown"),
            "selection": library.get("selection"), "evidence": deepcopy(library.get("evidence", [])),
            "sourceSetSha256": (library.get("fingerprint") or {}).get("sourceSetSha256"),
            "conflicts": deepcopy(library.get("conflicts", []))})
        scope = deepcopy(library.get("suggestedReuseScope", []))
        result["suggestedReuseScope"].append({**identity, "scope": scope, "adoptionStatus": "pending"})
        for conflict in library.get("conflicts", []):
            result["conflicts"].append({**identity, "detail": deepcopy(conflict)})
        artifact = library.get("artifact") or {}
        allowed = library.get("disposition") in ("mirror-allowed", "official-fetch-only")
        result["fetchInstructions"].append({**identity,
            "action": "materialize" if allowed and artifact.get("sha256") and (artifact.get("url") or library.get("downloadUrl")) else "manual-review-required",
            "disposition": library.get("disposition"), "url": artifact.get("url") or library.get("downloadUrl"),
            "sha256": artifact.get("sha256"), "sourceUrl": library.get("sourceUrl")})
        # Handoffs cannot override the owning ReMaker writer's recovery/adoption decision.
    for library in result["libraries"]:
        library["skipNativeRecovery"] = False
        library["adoptionStatus"] = "pending"
        library["sourceRefs"]=[deepcopy(ref) for ref in result["sourceRefs"] if all(ref.get(k)==library.get(k) for k in ("packageId","version","variantId"))]
    return result
