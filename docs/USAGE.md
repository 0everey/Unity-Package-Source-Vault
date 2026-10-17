# CLI usage

Install with Python 3.10+ and `python -m pip install
git+https://github.com/0everey/Unity-Package-Source-Vault.git`. The runtime uses
the Python standard library. All commands provide `--help` and JSON results.
Exit codes: 0 success, 2 invalid input/failure, 3 unresolved or partial result.

```powershell
uvault catalog sync --out ./catalog-input
uvault identify --input ./ActualPackage --registry ./catalog-input/catalog.json --out ./matches
uvault resolve --matches ./matches/matches.json --out ./libraries.lock.json
uvault materialize --lock ./libraries.lock.json --target ./SelectedLibraries
uvault export-remaker --lock ./libraries.lock.json --out ./REMAKER-LIBRARIES.json
```

The default remote index is fixed by URL; loading it resolves the branch to a
Git commit before reading shards. Use a 40-character commit in the URL to pin a
previous catalog. Sync stores metadata/fingerprints, never package archives.

Resolve does not choose latest from ambiguous versions/variants. Use explicit
`--package ID --version VERSION --variant VARIANT` selection to lock a candidate;
selection preserves its evidence status and does not make it exact.

Only actual target archive/DLL bytes or the full actual source set can establish
`exact-artifact`. Lock provenance is `pinned-source`. API/namespace clues yield
candidates, and missing/modified data remains unknown/conflicted. Profiles
include Unity version, platform/CPU, backend, API level, defines, dependencies
and TFM. Unknown profile means active declarations are unverified.

Materialize downloads to a task-owned temporary area, verifies SHA256, extracts
safely into a new use destination and cleans temporary payloads on success or
failure. It refuses different contents at an existing destination; offline reuse
rehashes actual files. Do not use an existing Unity Assets root as a blind
overwrite destination. Restricted/unavailable records return explicit status.

The maintainer pipeline uses the explicit `sources/common-packages.json` whitelist:

```powershell
python -m uvault.pipeline --root catalog --curate --metadata
python -m uvault.pipeline --root catalog --collect --publish
python -m uvault.pipeline --root catalog --add-gap com.cysharp.unitask 2.5.9 "Observed consumer lock" --metadata --package com.cysharp.unitask
```

An explicit gap requires package, version and reason, within the three-version
budget. Add a new common family to the whitelist deliberately. Metadata refresh
queries only those packages and persists selected versions. Dependencies are
named gaps; they never start an ecosystem crawl. A retired ecosystem queue is
rejected until explicitly projected with `--curate`. That projection retires
unreferenced generated metadata; Git history and legal Releases remain.

Managed DLL metadata uses the optional offline .NET8 PEReader helper. If a local
SDK is already installed, run `python -m uvault.managed build`; this explicit
operation builds only vault tool code from local SDK packs and downloads no
dependencies. `UVAULT_MANAGED_INDEXER` can point to an existing decoder. Missing
capability remains an explicit hash-only observation. Target DLLs never execute.

Detailed fingerprints are immutable metadata shards, loaded only for relevant
candidates. A synchronized metadata catalog retains its fixed remote origin for
those shards; it does not cache package payloads. Materialization receipts can
retain the small hash-bound manifest for offline verification of the one actual
use directory. A receipt cannot certify its own changed file hashes.

The manual Actions collector makes one bounded pass over the whitelist and
checkpoints verified references every ten attempts. There is no automatic
successor workflow or scheduled service. Explicitly rerun the same command or
workflow to resume; successful results are retained, failures and restrictions
remain visible. Local storage contains tools/metadata and one chosen actual use
directory, with no package mirror, archive backup or permanent payload cache.
