# ReMaker library intake v1

`uvault identify` accepts an existing ReMaker `structure-analyze` output directory
(assemblies.json/types.json), normalized identity JSON, actual managed binaries,
Unity package/project directories or archives. It never executes assemblies or
decodes IL2CPP itself. Generated DummyDLL signatures are candidate evidence only.

Run identify → resolve → materialize → export-remaker. Keep output local to the
consumer. `REMAKER-LIBRARIES.json` carries schemaVersion, catalogCommit,
lockSha256, inputIdentity, profile, original artifact SHA256, version/variant,
sourceRefs, rights, materialized location or retrieval instructions, match basis,
conflicts, unknown and suggestedReuseScope. Schemas are under `schemas/`.

Core retains target/run/member identity. Assembly-qualified full type/member
signatures are portable hints; tokens/RVAs are scoped to the original run.
Package version, compile success and behavior equivalence are separate facts.
Game-specific protobuf/RPC output is not replaced by the protobuf runtime.

Every exported library has `adoptionStatus: pending` and
`skipNativeRecovery: false`. The original writer must validate actual input
identity, profile, local modifications, dependencies and duplicate types, and
record an adoption receipt with precise adopted type/member scope before it
reduces native-recovery work. Namespace/assembly-only guesses cannot authorize
whole-assembly exclusion. Unknown, modified and mixed game code remains queued.

Suggested original-writer receipt (kept in the ReMaker consumer workspace):

```json
{
  "schemaVersion": "1.0",
  "exportSha256": "<actual export bytes SHA256>",
  "inputIdentity": "<Core-authenticated identity>",
  "status": "pending",
  "adoptedScopes": [],
  "conflicts": [],
  "skipNativeRecovery": false,
  "writer": "<actual accepting writer>"
}
```

This repository does not write the existing ReMaker or game project. An export
test proves contract production and offline readability; original-writer
adoption must be reported independently. See delivery status for actual intake.
