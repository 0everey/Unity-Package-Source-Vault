"""Validate every version record and content reference; requires jsonschema for CI."""
import gzip,hashlib,json
from pathlib import Path
import jsonschema

root=Path(__file__).resolve().parents[1]
index=json.loads((root/'catalog/catalog.json').read_text(encoding='utf-8-sig'))
schema=json.loads((root/'schemas/package.schema.json').read_text())
validator=jsonschema.Draft202012Validator(schema)
count=published=0
for entry in index['packages']:
    package=json.loads((root/'catalog'/entry['path']).read_text(encoding='utf-8-sig'))
    validator.validate(package)
    if package['id']!=entry['id']:
        raise ValueError('Catalog identity mismatch')
    identities=set()
    for record in package['versions']:
        identity=(record['version'],record['variantId'])
        if identity in identities:
            raise ValueError('Overwritten variant identity: '+package['id'])
        identities.add(identity);count+=1
        if record.get('fetchStatus')=='published':
            artifact=record['artifact'];rights=record['license']
            if record['disposition']!='mirror-allowed' or not artifact.get('verifiedRemote') or not artifact.get('licenseUrl') or not artifact.get('licenseSha256') or not rights.get('sha256') or not rights.get('evidenceUrl'):
                raise ValueError('Incomplete published provenance: '+package['id'])
            published+=1
bundles=index.get('bundles') or ([index['bundle']] if index.get('bundle') else [])
all_packages=[]
for bundle in bundles:
    data=(root/'catalog'/bundle['path']).read_bytes()
    if len(data)!=bundle['size'] or hashlib.sha256(data).hexdigest()!=bundle['sha256']:
        raise ValueError('Metadata bundle hash mismatch')
    all_packages.extend(json.loads(gzip.decompress(data))['packages'])
if bundles and {p['id'] for p in all_packages}!={p['id'] for p in index['packages']}:
    raise ValueError('Metadata bundle identity mismatch')
coverage=json.loads((root/'catalog/coverage.json').read_text(encoding='utf-8-sig'))
if coverage['selectedVersionTasks']!=coverage['completedSelectedVersionTasks']+coverage['pendingSelectedVersionTasks']:
    raise ValueError('Version task conservation failed')
print(json.dumps({'packages':len(index['packages']),'versions':count,'remoteVerifiedVersions':published,'schema':'Draft202012'}))
