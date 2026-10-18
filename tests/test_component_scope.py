import copy,hashlib,io,json,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from uvault import sources,harvest
from uvault.classify import classify
from uvault.identify import _match_candidate
from uvault.fingerprints import externalize_fingerprint,load_full_fingerprint
from uvault.component_scope import scoped_fingerprint
from test_builtin import declaration,inventory


class ComponentScopeTests(unittest.TestCase):
    def collected(self):
        manifest=b'{"name":"com.example.core","version":"1.0.0","unity":"2020.3"}'
        files={'LICENSE':b'MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy\nTHE SOFTWARE IS PROVIDED AS IS',
               'unity/core/package.json':manifest,'unity/core/Core.asmdef':b'{"name":"Example.Core"}',
               'unity/core/Widget.cs':b'namespace Example { public class Widget {} }',
               'unity/other/Other.asmdef':b'{"name":"Example.Other"}',
               'unity/other/Sibling.cs':b'namespace Example { public class Sibling {} }',
               'outside/Shared.asmref':b'{"reference":"Example.Core"}',
               'outside/Shared.cs':b'namespace Example { public class Shared {} }'}
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:gz') as archive:
            for path,data in files.items():
                info=tarfile.TarInfo('repo/'+path);info.size=len(data);archive.addfile(info,io.BytesIO(data))
        seed={'id':'com.example.core','adapter':'github','repository':'Example/Monorepo','gitPins':[
            {'version':'1.0.0','sourceRef':'a'*40,'sourcePath':'unity/core',
             'componentMetadata':{'path':'unity/core/package.json','sha256':hashlib.sha256(manifest).hexdigest()}}]}
        package=sources.pinned_git_package(seed)
        with patch('uvault.sources.request_bytes',return_value=stream.getvalue()):
            record=harvest.collect_version(package,package['versions'][0])
        self.assertEqual(record['fetchStatus'],'collected')
        return record

    def check_routing(self,record):
        cat={'schemaVersion':'1.0','catalogCommit':'c'*40,'packages':[{'id':'com.example.core','versions':[record]}]}
        inv=inventory(declaration('core','Example.Widget','Example.Core'),
                      declaration('sibling','Example.Sibling','Example.Other'),
                      declaration('outside','Example.Shared','Example.Core'))
        result=classify(inv,cat);by={r['id']:r for r in result['classification']['items']}
        self.assertEqual(by['core']['nativeAction'],'defer-library-resolution')
        self.assertEqual(by['sibling']['nativeAction'],'recover-native')
        self.assertEqual(by['outside']['nativeAction'],'recover-native')

    def test_full_and_compact_component_indexes_exclude_sibling_and_external_asmref(self):
        record=self.collected();original=copy.deepcopy(record['fingerprint'])
        self.assertIn('Example.Sibling',original['types']);self.assertIn('Example.Shared',original['types'])
        self.check_routing(record)
        target={'files':[],'assemblies':[{'name':'Example.Other'}],'types':['Example.Sibling'],'namespaces':[]}
        self.assertIsNone(_match_candidate(target,record))
        with tempfile.TemporaryDirectory() as temporary:
            externalize_fingerprint(Path(temporary),record);self.check_routing(record)
            self.assertIsNone(_match_candidate(target,record))
            full=load_full_fingerprint(record,{'registry':temporary})
            self.assertEqual(full,original)
            scoped=scoped_fingerprint({**record,'fingerprint':full})
            self.assertEqual(scoped['types'],['Example.Widget'])

    def test_legacy_compact_component_without_path_evidence_is_weak(self):
        record={'sourcePath':'unity/core','version':'1.0.0','variantId':'old',
                'fingerprint':{'assemblies':[{'name':'Example.Core','ownershipVerified':True,'types':['Example.Widget']}],
                               'types':['Example.Widget']}}
        cat={'schemaVersion':'1.0','catalogCommit':'c'*40,'packages':[{'id':'com.example.core','versions':[record]}]}
        result=classify(inventory(declaration('core','Example.Widget','Example.Core')),cat)
        self.assertEqual(result['classification']['items'][0]['nativeAction'],'recover-native')

    def test_git_lock_component_path_is_required_and_normalized(self):
        record=self.collected()
        observation={'packageId':'com.example.core','version':'https://github.com/Example/Monorepo.git#'+'a'*40,
                     'sourceSpecification':'https://github.com/Example/Monorepo.git#'+'a'*40,
                     'source':'git','lockPinned':True,'targetPresent':False,'commit':'a'*40}
        target={'files':[],'assemblies':[],'types':[],'namespaces':[]}
        result=_match_candidate(target,record,observation)
        self.assertNotEqual(result['status'],'pinned-source')
        observation['sourceSpecification']='https://github.com/Example/Monorepo.git?path=/unity/core#'+'a'*40
        result=_match_candidate(target,record,observation)
        self.assertEqual(result['status'],'pinned-source')
