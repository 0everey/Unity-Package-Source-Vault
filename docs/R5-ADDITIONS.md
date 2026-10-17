# R5 named common additions

The common whitelist remains bounded: normally two versions, at most three for a
justified gap. No ecosystem discovery or automatic dependency closure resumes.

| Addition | Registered versions / handling | Evidence and limits |
| --- | --- | --- |
| Sentry Unity | 3.2.3, 3.2.4 | Each actual SDK archive carries its own sdkBundle managed component identities/versions/SHA/paths. 3.2.3 official release uses .NET SDK 5.11.2. Renamed System/Bcl assemblies stay SDK-owned; native/SDK components retain independent rights checks. |
| Best HTTP | 3.0.15, 3.0.14 official candidates | Official changelog verifies releases; com.Tivadar.Best.HTTP assembly/type references identify candidates. An assembly version does not certify target package bytes, license entitlement or absence of modifications. Acquire through official Store/My Assets or a licensed copy; no public commercial payload. |
| Unity 2D Sprite | 1.0.0 Editor core reference | Obtain through the selected Editor. No fabricated SpriteModule/runtime or independent registry archive. |
| Localization | 1.5.13, 1.5.12 | General coverage, not a proven current-game requirement. |
| 2D Animation | 9.2.2 / 10.2.4 | Official declared Unity 2022.3 / 6000.0 respectively; no automatic choice of 6000.7 latest. |
| SpriteShape | 9.1.1 / 10.1.1 | Corresponding declared Editor lines. |
| 2D Common | 8.1.1 / 9.1.2 | Finite selected 2D companion dependency. |
| DOTS 2022.3 | Entities 1.3.14 / Graphics 1.4.12 / Physics 1.3.14 | Graphics and Physics explicitly require Entities 1.3.14; SRP 14.0.10 remains an exact shared gap if absent. |
| DOTS 6000.0 | Entities / Graphics / Physics 1.5.0 | Official member dependency edges align. SRP 17.0.3, Burst and other shared exact requirements remain explicit. |

Dependency-set status verifies declarations only. It does not install, compile,
assert a target Editor profile, or claim this game uses the general additions.
See catalog/coverage.json for exact shared gaps and actual archive states.

TextCore font/text engines, JSONSerialize, ImageConversion, XR and VR have finite
provider references. TextCore uses pinned official source declaration URLs, not
redistributed engine sources. Only JSONSerialize/ImageConversion permit the
registered exact-type/two-public-signature exception; other modules still require
two types in one complete assembly identity. All profile/install/adoption states
remain independently pending.

Tekly and OOI are named origin/modification pending. Tekly lists the identified
assembly names and declared ca.tekly package versions; a public repository is a
source candidate, not the authenticated original revision. OOI.Logging and
OOI.Platform have no independently authenticated upstream source. Same names,
version strings, current-source equality or user selection cannot authorize
replacement. Keep native recovery eligibility and business/alias identities.
Actual private target comparisons and source bodies are not published here.

Whole archive byte equality takes precedence over equal source/DLL subsets when
distinguishing releases of one SDK. Shared source or shared DLLs alone preserve
version ambiguity. Observed non-Dummy DLL differences at the same relative path
prevent source/shared-DLL equality from certifying a modified SDK as exact.

Official sources: [Sentry release](https://github.com/getsentry/unity/releases/tag/3.2.3),
[Best installation](https://bestdocshub.pages.dev/HTTP/installation/),
[Best versions](https://bestdocshub.pages.dev/HTTP/changelog/),
[Sprite Editor package](https://docs.unity3d.com/6000.0/Documentation/Manual/com.unity.2d.sprite.html).
ReMaker consumes [the writer handoff](REMAKER-WRITER-START-HERE.md); integration
remains pending and this vault does not write its production files or run games.
