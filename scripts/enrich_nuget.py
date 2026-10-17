"""Add raw group/asset metadata from existing SHA-verified NuGet archives only."""
import argparse
import hashlib
import io
from pathlib import Path
import zipfile

from uvault import nuget, sources
from uvault.curated import prune_catalog
from uvault.pipeline import load_queue, save_index, save_package

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', default='catalog')
parser.add_argument('--package', action='append', required=True)
args = parser.parse_args()
root = Path(args.root).resolve()
state = load_queue(root)
for package in state['packages']:
    if package['id'] not in args.package:
        continue
    if package.get('adapter') != 'nuget':
        raise ValueError('Only existing NuGet archives may be enriched')
    for version in package['versions']:
        old = version.get('nuget') or {}
        if 'dependencyGroups' in old and 'assets' in old:
            continue
        artifact = version.get('artifact') or {}
        if not artifact.get('sha256') or not old.get('nuspecSha256'):
            raise ValueError('Original archive and nuspec evidence are required')
        data = sources.request_bytes(version['downloadUrl'])
        if hashlib.sha256(data).hexdigest() != artifact['sha256']:
            raise ValueError('Original archive bytes changed; no metadata is overwritten')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            body = archive.read(old['nuspecPath'])
            if hashlib.sha256(body).hexdigest() != old['nuspecSha256']:
                raise ValueError('Original nuspec bytes changed')
            parsed = nuget.parse_nuspec(body, old['nuspecPath'])
            files = [{'path':n.filename, 'sha256':hashlib.sha256(archive.read(n)).hexdigest(), 'size':n.file_size}
                     for n in archive.infolist() if not n.is_dir() and n.filename.lower().endswith('.dll') and n.filename.startswith(('lib/','ref/'))]
        # Preserve old license, artifact, fingerprint and immutable nuspec digest.
        version['nuget'] = {**old, 'dependencyGroups':parsed['dependencyGroups'], 'assets':nuget.assets(files),
                            'archiveSha256':artifact['sha256'], 'metadataExtensionBasis':'original-sha-verified-archive-and-nuspec'}
        data = body = None
        print(package['id'], version['version'], 'group/asset evidence added', flush=True)
    save_package(root, package)
save_index(root, state, bundle=True)
prune_catalog(root, state)
