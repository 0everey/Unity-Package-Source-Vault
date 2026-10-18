"""Render current common catalog status, never infer acquisition from metadata."""
from pathlib import Path
from uvault.pipeline import load_queue
from uvault.harvest import coverage

root=Path(__file__).resolve().parents[1]
queue=load_queue(root/"catalog")
report=coverage(queue)
companions=sum(p.get('dependencyRole')=='companion-not-root-family' for p in queue['packages'])
common=sum(bool(p.get('curatedPolicy')) for p in queue['packages'])-companions
builtin=sum(p.get('family')=='unity-builtin' for p in queue['packages'])
references=len(queue['packages'])-common-companions-builtin
lines=["# Common package coverage ("+queue.get('requirementRevision','R4')+")","",
       f"Current denominator: {common} common root families, {companions} parent-constrained companion entries, {builtin} builtin module providers and {references} commercial/Editor/restricted/unresolved reference entries.",
       "The whitelist is complete for this scope; it is not a Unity ecosystem census.",
       "Normally two versions within a default budget of three; named per-package legacy/dependency exceptions allow four or five and retain previous immutable evidence. Fewer available versions remain explicit.","",
       f"Generated: {report['generatedAt']}. Registered {report['registeredPackages']}/{report['discoveredPackages']} entries; "
       f"{report['listedVersions']} version records; {report['completedSelectedVersionTasks']}/{report['selectedVersionTasks']} archive tasks collected; "
       f"{report['publishedVersionRecords']} published version/variant records with anonymous remote hash verification.","",
       "`reference-only` means no archive was acquired. Newer Editor-bundled rendering/UI versions link pinned official manifests/source paths and the matching Editor installation route.",
       "`collected` means bytes were reviewed/fingerprinted then released locally; only published objects are held by this vault remotely.",
       "`official-fetch-only` and `license-unresolved` are explicit acquisition/rights limits. They are not public payload mirrors or exact target matches.","",
       "| Package | Versions and actual state |", "| --- | --- |"]
for package in queue['packages']:
    if package.get('family')=='unity-builtin':continue
    states=[]
    for version in package.get('versions',[]):
        artifact=version.get('artifact') or {}
        status=version.get('fetchStatus','pending')
        label=f"{version['version']}: {status}, {version.get('disposition','license-unresolved')}"
        if version.get('fetchError'):label+=' — '+version['fetchError'].get('message',version['fetchError'].get('kind','unresolved'))
        url=artifact.get('url') if artifact.get('verifiedRemote') else version.get('downloadUrl') or version.get('sourceUrl')
        states.append(f"[{label}]({url})" if url else label)
    if not states:states=[package.get('reason') or package.get('metadataStatus','pending')]
    lines.append('| '+package['id']+' | '+'; '.join(states)+' |')
lines += ["", "## Named additions and dependency sets", "",
          "Sentry Unity keeps each SDK archive's own bundled assembly identity, version and hash in sdkBundle. Renamed Sentry.System.* and Sentry.Microsoft.* assemblies are not generic System package replacements.",
          "Best HTTP is a commercial version/API candidate with official acquisition links. Sprite 1.0.0 is an Editor core package reference. Neither is an independently mirrored engine/commercial payload.",
          "Tekly and OOI stay named origin/modification pending, including identified assembly names and declared package versions. Installed identity rules preserve unresolved status through identify/resolve/export and keep native eligibility in classify, even with a same-name public candidate.",
          "Localization/2D/DOTS additions are general coverage; current game requirements and compilation remain unproven.", ""]
for group in queue.get('compatibilitySets',[]):
    members=', '.join(f"{p} {v}" for p,v in group['members'].items())
    lines.append(f"- {group['id']}: {members}. {group['status']}; {len(group['exactDependencyGaps'])} exact shared dependency gaps. Installation/profile/compilation unverified.")
lines += ["", "Builtin providers: "+", ".join(p['id'] for p in queue['packages'] if p.get('family')=='unity-builtin')+".","",
          "Builtin identity confirmation proposes provider-reference and skips implementation recovery. Installation/profile remain reference-pending and false until independently verified; no engine payload is mirrored.","",
          "Selected-version dependencies remain named gaps in catalog/coverage.json. They do not enqueue cold packages or historical versions. Explicit consumer gaps use package/version/reason.","",
          "ReMaker adapter: ready; actual writer adoption: integration-pending. See [writer handoff](REMAKER-WRITER-START-HERE.md).", ""]
lines += ["## R6 dependency and demand boundaries", "",
          "Unity Newtonsoft, Splines, VFX Graph, Post Processing and Tilemap Extras add general coverage. VFX Graph 14/17 are pinned official manifest references; 10.10.1 is a separately acquired legacy archive, never their replacement.",
          "Grpc.Net.Common, Logging.Abstractions, DiagnosticSource and Unsafe are parent-constrained companions, not new root families. Raw nuspec groups/ranges and hash-bound lib/ref assets are preserved; see catalog.nugetDependencyCandidates for .NET Standard candidates and named remaining gaps. Bare NuGet versions are minimum ranges. Explicit 2.0 fallback candidates do not certify a 2.1 target or complete closure.",
          "Unity and NuGet Newtonsoft remain alternative distributions. resolve/export report a conflict when both are selected, including old locks; explicitly choosing one preserves the unselected evidence and all other unresolved facts.", "",
          "On-demand candidates (no selected version or collection): "+", ".join(p['id'] for p in queue.get('onDemandCandidates',[]))+".",
          "Unverified provider candidates (inactive): "+", ".join(p['providerHint'] for p in queue.get('providerRuleCandidates',[]))+".", ""]
lines += ["## R7 explicit activation and family references", "",
          "Activated former demand candidates: "+", ".join(p['id'] for p in queue.get('activatedDemandCandidates',[]))+".",
          "Activated finite provider rules: "+", ".join(p['providerHint'] for p in queue.get('activatedProviderCandidates',[]))+".",
          "Official family clues keep exact version/target bytes and missing full names/assemblies unknown. They add acquisition work without removing native eligibility. Four singleton exceptions are finite; old UnityEngine only routes its registered GameObject/Transform types.",
          "[R7 additions](R7-ADDITIONS.md) lists the finite expansion and diagnostic comparison. Registration, acquisition, legal redistribution, target equality and real game use are separate results.", ""]
(root/'docs/COVERAGE.md').write_text('\n'.join(lines),encoding='utf-8')
