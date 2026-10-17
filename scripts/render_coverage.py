"""Render current common catalog status, never infer acquisition from metadata."""
from pathlib import Path
from uvault.pipeline import load_queue
from uvault.harvest import coverage

root=Path(__file__).resolve().parents[1]
queue=load_queue(root/"catalog")
report=coverage(queue)
lines=["# Common package coverage (R4)","",
       "Current denominator: 35 common families, 17 builtin module providers and three restricted references.",
       "The whitelist is complete for this scope; it is not a Unity ecosystem census.",
       "Two common versions per family, at most three for justified gaps/legacy; fewer available versions remain explicit.","",
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
lines += ["", "Builtin providers: "+", ".join(p['id'] for p in queue['packages'] if p.get('family')=='unity-builtin')+".","",
          "Builtin identity confirmation proposes provider-reference and skips implementation recovery. Installation/profile remain reference-pending and false until independently verified; no engine payload is mirrored.","",
          "Selected-version dependencies remain named gaps in catalog/coverage.json. They do not enqueue cold packages or historical versions. Explicit consumer gaps use package/version/reason.","",
          "ReMaker adapter: ready; actual writer adoption: integration-pending. See [writer handoff](REMAKER-WRITER-START-HERE.md).", ""]
(root/'docs/COVERAGE.md').write_text('\n'.join(lines),encoding='utf-8')
