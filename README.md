# Unity Package Source Vault

Public Unity package discovery, conservative version identification and locked
source retrieval. Permitted original archives live in GitHub Releases; Git
contains tools, provenance, fingerprints and version-specific rights records.
No permanent local package mirror or payload cache is created.

Implementation and collection are in progress. See `catalog/coverage.json` for
the full discovered queue and actual version/artifact state. A listed package
does not mean its source is available or its license permits mirroring.

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
