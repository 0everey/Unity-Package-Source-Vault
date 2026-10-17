# Common package sources (R4)

`common-packages.json` is the current whitelist: 43 common official/third-party
families and seven commercial/Editor/restricted/unresolved reference entries. `builtin-modules.json` defines 23
finite Unity providers. No normal CLI or workflow enumerates OpenUPM, persists
all historical versions, or recursively expands dependency version tasks.

Default selection keeps two common stable versions, at most three including an
observed gap, verified legacy version or useful archive fallback. One available
version stays one. Queries may read a selected package's version list in memory;
only chosen versions persist. Missing dependencies remain named consumer gaps.
Use `uvault.pipeline --add-gap PACKAGE VERSION REASON --metadata` for an explicit
need; add new families deliberately to the whitelist.

Registry/Git/NuGet adapters retain source and immutable variant identities.
Pinned official manifests register newer Editor-bundled SRP/UI versions that
are absent from the public registry. These records have no archive, no payload
rights grant and fetchStatus=reference-only. They link the exact official commit,
source path and installation instructions. They never stand in for acquired
bytes, exact matches or build compatibility. Available old SRP10 archives are
separate versions. Experimental-only UGUI releases are not common stable picks.

License decisions apply to each observed version/archive. Root grants, nested
licenses, notices, bundled component directories, binary extensions, PE/ELF/
Mach-O headers and macOS bundle/framework executable layouts are checked without
execution. A wrapper's MIT license does not grant bundled SDK redistribution.
Unresolved, restricted or binary-component rights prevent automatic publication.
The v3 review algorithm invalidates older decisions for a targeted recheck.

`component-reviews.json` binds individual integration-adapter reviews to exact
archive hashes, pinned upstream commits, file comparisons and license evidence.
It cannot waive native binary rights or a restricted nested license. A missing
archive license may use only a matching manifest's full immutable repository
revision and agreeing grant; preserve its notice text with the archive.

Archives exist only in memory or task-owned temporary upload/extraction areas.
Permitted bytes and license sidecars live in remote GitHub Releases, anonymously
read back and hash-verified before registration. No local mirror, archive backup,
payload cache, Actions cache, scheduled collection or automatic runner chain is
maintained. Explicit reruns resume saved metadata/results. Retired ecosystem
metadata is absent from the active catalog and preserved in Git history.

R5 dependency sets are limited to two explicitly selected DOTS groups. Every
member edge comes from actual package metadata; shared exact-version gaps stay
visible without implicit substitution or recursive collection. Sentry keeps its
bundled renamed assemblies per SDK archive. Best HTTP and Sprite are acquisition
references. Tekly/OOI have named unresolved components; installed rules preserve
origin/modification uncertainty through identify/classify/resolve/export.
