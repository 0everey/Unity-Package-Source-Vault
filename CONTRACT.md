# Implementation contract v1

Python >=3.10, standard-library runtime; package src/uvault. Shared contract owned by root. JSON schemaVersion is "1.0".

Catalog index: {schemaVersion,catalogCommit,packages:[{id,path}],coverage:"coverage.json"}. Package shards catalog/packages/<URL-quoted-id>.json: {schemaVersion,id,displayName,sources:[],versions:[VERSION]}. VERSION: {version,variantId,sourceUrl,sourceRef,downloadUrl,disposition,license:{expression,evidenceUrl,sha256,text?,components:[]},dependencies:{},artifact:{sha256,size,format,kind,url,assetId?,releaseTag?,verifiedRemote?},fingerprint:{files:[{path,sha256,size,kind}],sourceSetSha256,assemblies:[],namespaces:[],types:[],profileVerified:false},fetchStatus}. artifact/fingerprint nullable for metadata-only. Dispositions mirror-allowed, official-fetch-only, user-provided-only, builtin-reference, license-unresolved, source-unavailable, fetch-failed. R4 persists only the common whitelist and two/three selected versions per family; upstream counts are informational. Official Editor-bundled manifest references have artifact=null and fetchStatus=reference-only; they are not archive collection tasks. All file paths in fingerprints normalized to archive root (strip one common root), POSIX; sourceSetSha256 = SHA256(canonical JSON sorted [{path,sha256}] for all .cs, separators comma/colon, ensure_ascii=False, UTF8). Source sets must not be empty for source exact.

Library APIs (plain dicts): sources.discover_openupm(commit=None)->dict; sources.registry_package(package_id,registry)->dict; sources.select_versions(versions,target_versions=(),count=3)->list; inventory.fingerprint_archive(data:bytes,format:str)->dict; inventory.inventory_directory(path,profile=None)->dict. sources collector CLI independently `python -m uvault.harvest ...`; no publishing without license decision.

Registry: local catalog.json path OR remote catalog URL. cli loads via catalog.load_registry(registry)->dict containing expanded packages (list of full package dicts), catalogCommit, registry. Root implements catalog.py. Default remote https://raw.githubusercontent.com/0everey/Unity-Package-Source-Vault/main/catalog/catalog.json. Remote catalogs pinned to Git commit upon loading; local catalogCommit is git HEAD if index field is pending. No persistent package cache.

identify.identify(input_path, catalog, profile=None)->MATCHES {schemaVersion,catalogCommit,input:{fingerprint,kind},profile,matches:[{packageId,status,candidates:[VERSION+packageId],evidence:[],conflicts:[],suggestedReuseScope:[],skipNativeRecovery:false}],unknown:[],conflicts:[]}. Inputs directory/archive, Unity manifest+lock, ReMaker structure normalized JSON; raw DLL hashes allowed, metadata comes from ReMaker SRM exports, never load DLL. Strict no exact from lock; a changed embedded source defeats pinned-source for that target. Unverified profile does not prohibit literal target archive equality but cannot justify inferred active declarations/exclusion. asmdef/asmref/GUID/default assembly conservative ownership.

CLI commands: uvault catalog sync --registry URL --out DIR(optional); identify --input PATH --registry URL(default) --profile JSON(optional) --out new-result-directory (write matches.json); resolve --matches FILE --out FILE [--package ID --version V --variant ID repeatable selection if desired]; materialize --lock FILE --target DIR [--offline]; export-remaker --lock FILE --out FILE [--materialized receipt]. JSON stdout, errors JSON stderr, exit 0 success, 2 invalid/failure, 3 unresolved/partial. CLI `--help` on every command. Unknown/restricted must emit result.

lock {schemaVersion,catalogCommit,input,profile,libraries:[{packageId,version,variantId,status,artifact,license,sourceUrl,sourceRef,disposition,fingerprint,suggestedReuseScope,skipNativeRecovery:false}],unresolved:[],conflicts:[]}. No silent selection on ambiguity; explicit candidate selection preserves match status. materialize returns {schemaVersion,libraries:[{packageId,version,variantId,path,artifactSha256,status}],unresolved:[]}; atomic destination staging under target parent, safe traversal/symlink rejection, verified receipt reuse, reject collisions and checksum mismatch, finally cleanup. export contains lockSha256, inputIdentity, sourceRefs, profile, fetch instructions, matchBasis, conflicts, unknown, suggestedReuseScope, adoptionStatus:"pending", skipNativeRecovery:false. Never writes ReMaker production.

Files: source worker owns sources.py/harvest.py and tests/test_sources.py plus sources/*; identity worker owns inventory.py/identify.py and tests/test_identify.py/test_inventory.py; CLI worker owns cli.py/materialize.py/remaker.py/resolve.py and tests/test_cli.py/test_materialize.py/test_remaker.py. Root owns all other files, schemas, index, publication, integration/handoff. Workers deliver directly in disjoint files; root alone stages/commits/pushes. No copying local plan/evidence into Public repo.

R3: classify.py consumes a complete original declaration inventory and emits explicit nativeAction proposals before expensive native selection. See docs/CLASSIFICATION.md for full bound input, original-writer adoption decisions, restore semantics and six routes. CLI `uvault classify --inventory DECLARATIONS.json --registry URL --out NEWDIR` writes five local classification/workset/proposal files. Complete input conservation includes unknown declarations; address sharing never removes a business alias. Proposal remains unauthenticated/integration-pending; original Core verifies input and produces its own actual selection/sourceInventory. This does not grant package adoption or game execution.

R4 builtin exception: finite registered assembly identities plus multiple module-scoped official API features establish provider-reference for registered namespace scopes. Explicit business/modified/unknown declarations remain native; unknown installation/profile remains reference-pending, profileVerified=false, isRecovered=false. This proposal does not authenticate Core selection or actual adoption.

R5: optional version.sdkBundle contains actual archive-bound SDK component full
assembly identities, versions, SHA256 and relative paths, decoded offline. It
survives resolve/export. Catalog compatibilitySets records two finite groups,
actual metadata dependencies, member conflicts and exactDependencyGaps; verified
member declarations do not mean profile/installation/compilation readiness.
Installed named-origin rules (producer+rule SHA in classification cache) preserve
Tekly/OOI namedPending across matches/lock/export and keep recover-native even
when public candidates or ordinary accepted sourceConfirmed decisions exist.
Named native rows also appear in libraryResolutionWorkset. Two singleton builtin
modules may use two exact public static signatures in one registered type; other
modules keep two distinct official API types. All retain profile=false/pending.

R6: version.nuget.dependencyGroups retains raw nuspec targetFramework and dependency
attributes/ranges; assets binds lib/ref DLL path, TFM and actual SHA. Original
archiveSha256/nuspecSha256 bind extensions. nugetDependencyCandidates is catalog
metadata (not installed closure) propagated through matches/lock/export, with
finite netstandard2.0/2.1 declarations, explicit fallback and named gaps. Bare
numeric NuGet versions are minimum ranges, unsupported ranges unassessed.
Six onDemandCandidates and four inactive providerRuleCandidates are separate
from active package queues/providers. Four companions use parent-constrained
selection without automatic latest neighbors. Installed finite Newtonsoft
alternative rules recheck resolve and old-lock export; dual selection carries
conflicts and empty bare scopes. Explicit one-distribution selection preserves
the skipped match in unselectedAlternatives and never promotes evidence.
