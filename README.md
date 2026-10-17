# Unity Package Source Vault

A curated public catalog of common Unity packages, conservative version identification and locked
source retrieval. Permitted original archives live in GitHub Releases; Git
contains tools, provenance, fingerprints and version-specific rights records.
No permanent local package mirror or payload cache is created.

R6 covers 48 common root package families, four parent-constrained companion
entries, 23 built-in module providers and seven
commercial, Editor, restricted or unresolved reference entries. Each common
package keeps two versions, at most three for a justified gap or legacy need.
See [coverage](docs/COVERAGE.md) and `catalog/coverage.json` for actual acquisition,
rights and remaining gaps. Cold packages and full version histories remain
outside the catalog.

The named additions include Sentry Unity and its own bundled assembly versions,
Best HTTP identification and official acquisition, Sprite 1.0.0 as an Editor core
reference, and selected Localization/2D/DOTS versions. [R5 details](docs/R5-ADDITIONS.md)
separate observed requirements from general coverage and list exact dependency
sets. Tekly and OOI remain named origin/modification pending; a public namesake
or explicit selection cannot authorize replacement.

[R6 additions](docs/R6-ADDITIONS.md) cover Unity Newtonsoft, Splines, VFX Graph,
Post Processing and Tilemap Extras. gRPC companions preserve raw NuGet framework
groups, version ranges and asset hashes without claiming a complete installed
closure. Unity/NuGet Newtonsoft are alternative distributions; selecting both
produces an explicit conflict. Six demand candidates and four unverified module
candidates are registered separately and remain inactive.

Built-in modules propose direct provider references after finite identity/API
checks. JSONSerialize and ImageConversion use two exact public signatures in a
single registered type; other modules retain the two-type rule. Unknown Editor
installation/profile remains pending. Reference records are not downloaded
archives or build compatibility claims. Permitted payloads stay in remote
Releases; local storage contains tools/metadata and no permanent package mirror.

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
