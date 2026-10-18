# Early declaration classification

The Python API is ready for an original ReMaker writer to integrate after metadata declarations are readable and before native analysis or draft selection. Its output is a scheduling proposal. It does not adopt a package, authenticate a ReMaker selection, run a generator, or establish recovered behavior. Integration remains `integration-pending` until the original writer accepts and verifies the adapter.

```python
from uvault.classify import classify

result = classify(original_inventory, pinned_catalog, matches=matches, profile=profile)
```

The five result keys map to these suggested local files:

| API key | Suggested file |
| --- | --- |
| `classification` | `CLASSIFICATION.json` |
| `libraryResolutionWorkset` | `LIBRARY-RESOLUTION-WORKSET.json` |
| `generatedCodeWorkset` | `GENERATED-CODE-WORKSET.json` |
| `nativeSelection` | `NATIVE-SELECTION-PROPOSAL.json` |
| `summary` | `CLASSIFICATION-SUMMARY.json` |

These files contain target-specific identities and evidence. Keep real results local. The public repository contains tools and synthetic examples.

## Original inventory contract

Supply every original declaration, including unknown and unaddressed declarations. The producer must authenticate the original run/dump and create its scope manifest from that original inventory, independently of the classifier's output.

```json
{
  "schemaVersion": "1.0",
  "targetId": "synthetic-target",
  "dumpSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "inputSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "declarations": [{
    "id": "method-001",
    "assemblyIdentity": {"name": "Example.Runtime", "version": "1.0.0.0"},
    "typeFullName": "Example.Utility",
    "memberSignature": "System.Void Run(System.Int32)",
    "aliases": [],
    "nativeAddress": "0x1000",
    "evidenceRefs": [{"kind": "original-dump", "declarationId": "method-001"}]
  }],
  "completeScope": {
    "complete": true,
    "declarationCount": 1,
    "declarationIds": ["method-001"]
  },
  "sourceRefs": [{"kind": "original-inventory", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
}
```

`inputSha256` identifies the original declaration input, not a classifier-produced selection. A count/ID mismatch, duplicate ID, explicit partial scope, bare `completeScope: true`, missing identity, or inconsistent alias address is rejected. The manifest comparison checks the producer's supplied complete scope; only the original Core writer can establish that this scope actually covers its authenticated original input.

Aliases may be declaration IDs or records containing `id`, `declarationId`, or `methodId`, with an optional `nativeAddress`. Aliases outside the supplied declaration inventory are preserved separately with their referring declaration IDs. They are not silently promoted to new original declarations or deleted. Every unresolved external alias remains an explicit unknown native-eligibility proposal, even when its only referring declaration is deferred. `nativeSelection.externalAliases` keeps them, `requiresExternalAliasResolution` marks the missing authentication, and `unaddressedExternalAliasIds` exposes unresolved addresses. Their IDs never enter `methodIds` without the original writer authenticating actual declarations. Observed alias addresses remain active in address statistics and cannot be reported as avoided native work. Declaration-only and external-alias address counts are reported separately. Shared addresses never determine routing.

## Routes and evidence

| `nativeAction` | Meaning |
| --- | --- |
| `recover-native` | Preserve recovery eligibility for business, differences, weak clues, unknowns, and unverified generated ownership. |
| `defer-library-resolution` | A scoped library identity has declaration evidence. Queue source/version/difference resolution and defer this round of expensive native work. |
| `provider-reference` | Registered Unity builtin module identity is confirmed from original metadata, or an exact original-writer decision verifies another provider. Installation/profile may remain pending for builtin references. |
| `reuse-upstream` | An original-writer decision accepts a named member scope and confirmed source. |
| `skip-native` | An original-writer decision explicitly excludes that exact member scope from native production. |
| `regenerate` | An original-writer decision verifies the generator and complete inputs for a regenerable scope; regeneration remains pending. |

Every declaration receives exactly one current route. Multiple candidate versions remain candidates on one declaration; they do not duplicate the work item. Strong identity without a confirmed source/version defaults to `defer-library-resolution`, including restricted, unavailable, or ambiguous candidates. Source acquisition failure leaves that named queue unresolved. It does not silently send the entire plugin back to native production.

High confidence requires actual assembly-scoped type overlap. The classifier accepts catalog `typeDeclarations` with `assemblyIdentity` or `assemblyId`, or `assemblies[].types`. Existing global lexical `types` can be attributed only when every source file belongs to a single verified assembly. Global types from multiple assemblies, namespace similarity, and assembly names alone cannot defer a declaration. Conflicting supplied assembly version/culture/public-key-token or explicit uncertain ownership preserves native eligibility. Type overlap is not proof that method bodies are unmodified.

Explicit `game-business`, `project-wrapper`, `modified`, `application-generated`, `unknown`, and `mixed-owner` categories stay native. Known package source differences also preserve native recovery until the original writer localizes them. Application protocol messages are not protobuf runtime merely because they reference that runtime. A regeneration decision requires `package-generated` or `regenerable-generated`, verified complete inputs, generator metadata and source references.

Compiler-generated declarations require a verified actual owner, for example `owner: {declarationId, verified: true, evidenceRefs: [...]}`. Verified library owners can pass pending library resolution to their generated declarations. Business owners retain their generated recovery. Owner acceptance cannot expand an adopted member scope: generated members need their own exact original-writer adoption decision. Unverified ownership never skips native work.

## R4 builtin provider references

`uvault.builtin.package_records()` registers reference-only catalog entries. `detect_providers(original_inventory, profile=None)` returns a mapping from proven declaration IDs to their provider evidence. The finite [builtin module table](../sources/builtin-modules.json) covers Core, Physics/2D, AI, Animation, Audio, AssetBundle, IMGUI, UIElements/UI, ParticleSystem, Terrain, Tilemap, Video, legacy Input, and UnityWebRequest/AssetBundle. It does not match arbitrary `UnityEngine.*` assembly names or treat independent Input System, URP, UGUI, or other packages as builtins.

The detector first checks the complete original declaration scope and target/dump/input identity. Each registered module requires the exact assembly name, no supplied assembly identity conflict, and at least two distinct official API types in that same complete assembly identity. The official API URLs identify which module implements those types; references cover Unity 2022.3 and 6000.x. Multiple methods on one sampled type remain insufficient. Features split across different assembly scopes cannot be joined. A DLL filename, source namespace, or unscoped package fingerprint is insufficient.

After module identity is established, its explicitly registered namespace scopes delimit provider declarations, including internal SDK implementation types. This avoids sending thousands of known engine members to native recovery merely because only the public API probes were enumerated. Explicit business, wrapper, modified, unknown, mixed-owner, application-generated, uncertain ownership, and foreign namespace declarations still retain native eligibility. Unmarked private body modifications cannot be disproved by metadata; this is an engine-provider scheduling reference, not an `exact-artifact` or behavior-equivalence claim. Compiler-generated engine declarations follow a verified actual provider owner in the same full assembly scope; unverified owners and business owners stay native.

Confirmed builtin declarations receive `nativeAction: "provider-reference"` and leave the native proposal without requiring an adoption decision or a verified compilation profile. They preserve `provider.referenceStatus: "reference-pending"`, `reuseStatus: "provider-reference-pending"`, `profileVerified: false`, and `isRecovered: false`. A reported Unity version stays `reported-unverified`; an absent version stays `unknown`. Registered module package version `1.0.0` is a UPM builtin package version, not the Unity Editor version. Core and legacy Input have no separately established module package version and remain `unknown`. No engine source artifact or invented installation receipt is emitted. The installation/API URLs tell the original writer where to bind the target's real Unity installation.

Builtin reference fingerprints never enter generic third-party deferral: if the module's multi-feature identity test fails, one sampled API remains native. `CLASSIFICATION.json` binds the builtin rule content and producer SHA alongside the classifier/cache identity. `summary.builtinProviderDeclarationCount` and `builtinProviderModuleCounts` report the actual reference scope. The original ReMaker consumer still authenticates the proposal before applying it; this repository does not modify that production consumer.

`isRecovered` stays false. `reuseStatus` records scheduling/adoption information separately. Legacy `skipNativeRecovery` stays false because the unauthenticated proposal has no authority over an old boolean-only consumer. The new consumer must read `nativeAction` explicitly and authenticate its inputs before applying the proposal.

## Bound original-writer decisions

Run the classifier first and use `result["classification"]["binding"]` for an independently reviewed decision document. The binding includes `targetId`, `dumpSha256`, `inputSha256`, `catalogCommit`, `catalogSha256`, and `profileSha256`.

```python
decisions = {
    "binding": result["classification"]["binding"],
    "decisions": [{
        "id": declaration["id"],
        "scope": {key: declaration[key] for key in
                  ("assemblyIdentity", "typeFullName", "memberSignature")},
        "action": "reuse-upstream",
        "status": "accepted",
        "acceptedBy": "original-writer",
        "evidenceRefs": [{"kind": "writer-receipt", "sha256": receipt_sha256}],
        "packageId": "com.example.runtime",
        "version": "1.0.0",
        "variantId": "upstream",
        "sourceConfirmed": True
    }]
}
result = classify(original_inventory, pinned_catalog, profile=profile, decisions=decisions)
```

The classifier validates this explicit contract; it does not authenticate the writer's identity or create the receipt. `reuse-upstream` and `skip-native` require that exact catalog candidate and `sourceConfirmed: true`. An explicit provider decision outside the builtin detection path requires `provider`, `providerVerified: true`, and `profileVerified: true`. The registered builtin path above separates confirmed engine identity from pending installation/profile and needs no adoption decision. `regenerate` requires `inputsVerified: true`, `generator`, and nonempty `sourceRefs`. Every manual decision names one exact assembly/type/member scope. A namespace, assembly wildcard, or native address alone cannot authorize exclusion. An `exact-artifact` identification result alone never becomes adoption.

## Restoration and cache binding

```python
result = classify(original_inventory, pinned_catalog,
                  restore_ids=["method-001"],
                  restore_reason="Original writer requests differential native examination")
```

Only current deferred declarations can be explicitly restored. A nonempty reason is mandatory. Their category and candidates remain, `originalNativeAction` records the previous route, and their unresolved library queue item remains visible while `nativeAction` becomes `recover-native`. After explicit restoration, recovery also follows every verified compiler-generated owner chain, including multiple levels and input orders where a child precedes its owner. Those rows preserve the reason, `restorationInheritedFrom`, and `restorationRootId`; their pending source-resolution items remain visible. Restoring a generated member itself does not re-defer it to a library owner. This propagates native examination, never upstream acceptance: every generated member still needs its own exact original-writer adoption scope.

The deterministic cache key binds target, dump/input SHA, the complete inventory content, catalog commit and content, classifier file SHA, builtin producer/rule content, profile, matches, decisions, and restoration arguments. Reuse an existing result only when the complete key agrees. No network access, package download or full native decoding occurs during classification.

## Original ReMaker integration recommendation

1. In the original writer's authenticated preparation path, export the complete metadata declaration inventory after `AnalysisPipeline.Open` has verified the run, dump and `MethodRecord` identities. Populate assembly/type/member identity from that metadata authority or its existing SRM structure export. Do not infer assemblies from source folder names, decode IL2CPP again, or require fully recovered C#.
2. Place classification before the `source-mapping-and-selection` stage in `scripts/benchmark-installation.py` and before its `strengthen-drafts.ps1` production invocation. Existing `tools/source-census/Program.cs` output remains independent source evidence. The original writer should replace the limited package-name handling in `tools/map_draft_sources.py` with explicit per-declaration `nativeAction` handling and visible resolution/generated queues.
3. Validate the proposal binding against the same original run and complete declaration set. Intersect `recover-native` declaration IDs with the writer's independently established native eligibility and original source-aware selection rules. Preserve unaddressed and unbounded declarations in the complete classification; they remain explicit gaps, and this tool does not invent native ranges. `nativeSelection.requiresNativeEligibilityCheck` is true, with addressed/unaddressed IDs separated for that check. Resolve every external alias against the authenticated original metadata separately before using a reduced address workset; an unresolved alias retains native eligibility and its known address even if all classified referrers defer.
4. Produce a new real Core selection using the original writer's actual authenticated `sourceInventory`, `targetId`, `dumpSha256`, and selected `methodIds`. Existing `DraftSelection.Prepared` verifies those inputs, file inventory, unique IDs and bounded native addresses. This proposal deliberately has `authenticated: false`, `sourceInventory: null`, and a different schema contract; passing it directly to that Core reader is unsupported. A metadata-only mode requires a real Core contract from its writer, not fabricated census data.
5. Compare the same run's baseline and routed selection by declaration ID. Check every original declaration, all unresolved queues, shared-address business aliases, restored members, and original evidence. Report declaration counts separately from address, alias and package counts. No fixed speedup or recovered game logic follows merely from fewer native tasks.

The repository adapter is ready only for this bounded handoff. Real ReMaker integration, adoption, compilation, and runtime validation require separate original-writer receipts.

## R5 named additions

`namedPending` marks Tekly/OOI original-source and modification uncertainty. The
installed rules protect these families even if an alternate catalog presents a
same-name public strong candidate. Identify returns unresolved (exit 3), and
resolve/export retain the pending state after explicit selection. Classify keeps
`recover-native`, preserves shared addresses/business aliases, and also places
these rows in the library resolution workset. A normal sourceConfirmed receipt
cannot clear the named origin/difference work. Closing it requires a separately
reviewed origin/version/target-difference and original-writer adoption decision.

JSONSerialize and ImageConversion are two finite single-public-type module
exceptions: the same complete assembly identity and exact registered type must
supply two different exact public static signatures, including return and
parameter types. Private/Internal/Injected, substrings, altered shapes, duplicate
members and cross-identity evidence do not authenticate the module. This routes
only the exact type. R7 adds PlayableDirector (public instance void Play/Stop)
and ScreenCapture (two exact public static signatures) to the singleton allowlist.
AndroidJNI and Analytics retain two-type confirmation. Legacy UnityEngine only
routes GameObject/Transform after their complete assembly identity is established;
it does not authenticate the whole namespace. Other modules retain two types.
TextCore references use pinned official declaration URLs where API pages are
unavailable. Installation/profile stays pending and isRecovered stays false.

Sentry's sdkBundle is per archive and preserves each renamed System/Bcl component
assembly version/hash. Plain System assemblies and Assembly-CSharp wrappers do
not inherit that attribution. Best HTTP remains a commercial candidate with
legal acquisition links. 2D/DOTS group registration records official dependency
edges and explicit exact-version gaps, not installation or compilation success.

## R7 official family clues and missing versions

Installed `family-references.json` contains official API observations and explicit
type-to-assembly evidence where available. It never combines every product type
with every listed assembly. Unproved assemblies, full names and exact versions
remain unknown. `knownFamilies`/`familyHints` enter identify, resolve and export;
classify attaches references and a library work item while keeping native actions,
addresses and business aliases. A family clue does not authorize upstream adoption.
Rules and producer hashes bind the classification cache.

Numeric versions actually observed in package manifests/locks but missing from
the catalog become `missingVersionRequests`, including source/lock context.
Assembly versions and documentation generations cannot create package versions.
These facts survive explicit selections and old-lock export. Existing lock/receipt
digests are checked before context is restored; the added context cannot legitimize
a modified receipt. A selected nearby version is never an exact substitute.

Spine component observations retain spine-unity 4.2.120 and spine-csharp 4.2.37
at one fixed source commit. The Unity component still declares csharp 4.2.0;
neither a single whole-SDK version nor resolved dependency closure is inferred.
