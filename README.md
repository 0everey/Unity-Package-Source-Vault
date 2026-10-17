# Unity Package Source Vault

A curated public catalog of common Unity packages, conservative version identification and locked
source retrieval. Permitted original archives live in GitHub Releases; Git
contains tools, provenance, fingerprints and version-specific rights records.
No permanent local package mirror or payload cache is created.

R4 covers 35 common package families, 17 built-in module providers and three
restricted references. Each package keeps two common versions, at most three
for a justified legacy or consumer gap. Cold packages and complete version
histories are outside the current catalog. See [coverage](docs/COVERAGE.md) and
`catalog/coverage.json` for actual acquisition, rights and remaining gaps.

Built-in modules use registered assembly/API rules to propose direct provider
references and skip implementation recovery. An unknown Editor installation or
profile remains pending. Some newer rendering/UI packages ship with the Editor;
their pinned official manifests are references, not mirrored archives.

## Install

```powershell
python -m pip install "git+https://github.com/0everey/Unity-Package-Source-Vault.git"
uvault --help
uvault identify --input C:/YourProject --out C:/YourResults/package-match
uvault resolve --matches C:/YourResults/package-match/matches.json --out C:/YourResults/libraries.lock.json
uvault materialize --lock C:/YourResults/libraries.lock.json --target C:/YourSelectedLibraries
uvault export-remaker --lock C:/YourResults/libraries.lock.json --out C:/YourResults/REMAKER-LIBRARIES.json
```

Catalog: https://raw.githubusercontent.com/0everey/Unity-Package-Source-Vault/main/catalog/catalog.json

`exact-artifact` requires actual bytes or complete source-set equality. A lock
file alone provides `pinned-source`. Ambiguity, modifications and unknown
profiles stay explicit. ReMaker exports are suggestions with adoption pending;
Core and its original writer retain adoption and native-recovery decisions.

See [usage](docs/USAGE.md), [ReMaker contract](docs/REMAKER-INTEGRATION.md), and
[third-party notices](THIRD-PARTY-NOTICES.md). Tool licensing never relicenses
Unity, Steam SDK, commercial plugins or other upstream payloads.

Forward [the original-writer entry](docs/REMAKER-WRITER-START-HERE.md) for early
ReMaker classification and selection integration. Its adoption remains pending.
