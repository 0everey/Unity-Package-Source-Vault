# R6 common additions and parent dependencies

This finite batch adds five root packages and four parent-constrained companion
entries. R5 SDK/2D/DOTS, commercial references, named pending identities and
23 active builtin rules are retained without duplicate collection tasks.

| Root package | Selected versions / handling | Boundary |
| --- | --- | --- |
| Unity Newtonsoft | 3.0.2, 3.2.2 | 3.0.2 closes the recorded Localization dependency; retain its UPM identity separately from NuGet Newtonsoft.Json. |
| Splines | 2.9.0, 2.9.1 | Official minimum Unity 2022.3; retain Runtime/Editor asmdefs and Mathematics/SettingsManager dependencies. |
| VFX Graph | 14.0.12, 17.0.4 official manifest references; 10.10.1 legacy archive | Exact SRP/Shader Graph relationships remain declared gaps where absent. A legacy archive is not the newer Editor package. |
| Post Processing | 3.5.3, 3.5.4 | Legacy Built-in rendering, official minimum 2019.4; no automatic URP/HDRP installation. |
| Tilemap Extras | 3.1.3, 4.1.2 | Minimum 2022.1 / 6000.0 respectively; distinct from the engine Tilemap provider. No automatic 6000.7/latest line. |

| Companion | Finite candidates | Parent basis |
| --- | --- | --- |
| Grpc.Net.Common | 2.83.0, 2.84.0 | Selected Grpc.Net.Client 2.83/2.84 .NET Standard groups. |
| Logging.Abstractions | 8.0.0, 8.0.1 | Corresponding Client minimum ranges. |
| DiagnosticSource | 6.0.1, 8.0.1 | Corresponding Client .NET Standard groups; other TFMs differ. |
| Unsafe | 6.0.0 only | DiagnosticSource .NET Standard dependency; no second version for padding. |

`parent-constrained` selection never adds a latest neighbor. Catalog candidates
are not authenticated original-game package versions. NuGet bare `8.0.1` means
`>=8.0.1`; `[8.0.1]` is exact. Numeric minimum/exact/interval ranges are evaluated;
unrecognized ranges remain unassessed. No general NuGet/TFM installer is added.

`nuget.dependencyGroups` retains raw framework labels, version ranges and
dependency attributes. `nuget.assets` records actual lib/ref DLL paths, TFMs and
SHA256. Existing parent metadata is extended only after the original archive
and original nuspec SHA match; artifact, license and fingerprint records stay
immutable. `scripts/enrich_nuget.py --package <id>` can explicitly resume missing
extensions without retaining a payload cache.

`nugetDependencyCandidates` passes through identify, resolve and ReMaker export.
It reports netstandard2.0/2.1 candidates, explicit 2.0 fallback when no 2.1 group
exists, raw edges, catalog range evaluations and named missing dependencies.
DI.Abstractions, Memory, Buffers and Bcl.AsyncInterfaces are not silently fetched.
Four companion entries do not constitute a complete closure. Installation,
target framework/profile, compilation and original writer adoption remain unverified.

Unity and NuGet Newtonsoft use independent IDs, versions, variants and archives.
Simultaneous resolve selections and old double-distribution locks exported by
the current tool carry `alternative-distributions-selected`, return partial,
and clear bare reuse suggestions. Explicit selection of one distribution keeps
the unselected match under `unselectedAlternatives`; it preserves other unknowns
and never promotes source evidence. Matching assembly versions do not prove
matching bytes or interchangeable TFMs; no whole-package equivalence is asserted.
Actual archive fingerprints contain four Unity Newtonsoft DLL assets across
3.0.2/3.2.2 and sixteen NuGet DLL assets across 13.0.3/13.0.4. None of the four
Unity hashes equals a recorded NuGet asset hash. Unity AOT/Runtime folder names
do not certify a NuGet TFM, so no cross-distribution file reuse is certified.

Services Core, Authentication, Purchasing/IAP, Odin Serializer, YooAsset and
ZString are `onDemandCandidates` only: official source, license hint where known,
trigger, null version/ref, no selected tag or payload. Normal refresh/collect
does not activate them or invoke services/stores. Odin Serializer is separate
from commercial Inspector; YooAsset does not replace Addressables.

AndroidJNI, Director, ScreenCapture and UnityAnalytics remain inactive
`providerRuleCandidates`. Names alone do not establish the official API rules or
authorize native exclusion. ResourceManager/Core.Shared/ShaderLibrary and other
internal assemblies are attributed to their parent package, not new root families.

Actual acquisition/rights/publication states are generated in
[COVERAGE.md](COVERAGE.md) and `catalog/coverage.json`. Permitted payloads live
remotely; local task downloads and usage directories are cleaned after verification.
