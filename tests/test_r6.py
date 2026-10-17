import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from uvault import curated, harvest, nuget, pipeline
from uvault.cli import main
from uvault.materialize import canonical_hash
from uvault.remaker import export_remaker
from uvault.resolve import resolve


class R6Tests(unittest.TestCase):
    def test_parent_selection_does_not_add_latest_or_fill_missing_preference(self):
        p = {'selectionMode':'parent-constrained','preferredVersions':['6.0.0'],'versionCount':2}
        records = [{'version':v} for v in ('5.0.0','6.0.0','9.0.0')]
        self.assertEqual(curated.choose_versions(records,p),[records[1]])
        p['preferredVersions']=['7.0.0']
        self.assertEqual(curated.choose_versions(records,p),[])

    def test_numeric_nuget_ranges_keep_minimum_and_unknown_distinct(self):
        for actual,spec,expected in [('9.0.0','8.0.1',True),('8.0.0','8.0.1',False),('9.0.0','[8.0.1]',False),
            ('8.0.1','[8.0.1]',True),('8.0.1','[8.0.0,9.0.0)',True),('9.0.0','[8.0.0,9.0.0)',False),
            ('8.0.0','(8.0.0,)',False),('9.0.0','(,8.0.0]',False),('8.0.0','8.*',None),('8.0.0','latest',None),
            ('8.0.0','[9.0.0,8.0.0]',None),('8.0.0-preview','8.0.0',None)]:
            with self.subTest(actual=actual,spec=spec):self.assertIs(nuget.satisfies(actual,spec),expected)

    def test_nuspec_retains_empty_groups_raw_attributes_and_dll_asset_hashes(self):
        content=b'<package><metadata><dependencies><group targetFramework="netstandard2.0"><dependency id="A" version="8.0.1" exclude="Build,Analyzers" /></group><group targetFramework="net8.0" /></dependencies></metadata></package>'
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:
            z.writestr('X.nuspec',content);z.writestr('lib/netstandard2.0/X.dll',b'MZ synthetic')
        rights=harvest.inspect_licenses(stream.getvalue(),'nupkg',{'downloadUrl':'https://example.test/x.nupkg'})
        info=rights['nuspec']
        self.assertEqual(info['dependencyGroups'][0]['dependencies'][0],{'id':'A','version':'8.0.1','exclude':'Build,Analyzers'})
        self.assertEqual(info['dependencyGroups'][1]['dependencies'],[])
        with patch('uvault.sources.request_bytes',return_value=stream.getvalue()):
            record=harvest.collect_version({'id':'X'},{'version':'1.0.0','variantId':'nuget','downloadUrl':'https://example.test/x.nupkg'})
        self.assertEqual(record['nuget']['assets'][0]['targetFramework'],'netstandard2.0')
        self.assertEqual(record['nuget']['archiveSha256'],record['artifact']['sha256'])
        self.assertEqual(len(record['nuget']['assets'][0]['sha256']),64)

    def test_tfm_fallback_is_explicit_and_server_only_dependencies_do_not_mix(self):
        v={'version':'1','variantId':'nuget','nuget':{'dependencyGroups':[
            {'targetFramework':'.NETStandard2.0','dependencies':[{'id':'A','version':'8.0.1'},{'id':'Missing','version':'1.0.0'}]},
            {'targetFramework':'net8.0','dependencies':[{'id':'ServerOnly','version':'9.0.0'}]}],
            'assets':[{'path':'lib/netstandard2.0/X.dll','targetFramework':'netstandard2.0','sha256':'a'*64}]}}
        result=nuget.dependency_candidates({'packages':[{'id':'Parent','versions':[v]},{'id':'A','versions':[{'version':'9.0.0','variantId':'nuget'}]}]})
        first,second=result['parents']
        self.assertEqual(second['status'],'explicit-compatible-fallback-candidate')
        self.assertEqual(second['dependencyGroups'][0]['targetFramework'],'.NETStandard2.0')
        self.assertEqual({d['id'] for d in first['dependencies']},{'A','Missing'})
        self.assertIs(first['dependencies'][0]['catalogEvaluations'][0]['satisfiesRange'],True)
        self.assertEqual(first['dependencies'][1]['status'],'named-dependency-gap')
        self.assertFalse(second['profileVerified']);self.assertFalse(result['completeClosure'])

    def matches(self):
        def match(pid):
            return {'packageId':pid,'status':'strong-candidate','candidates':[{'packageId':pid,'version':'1.0.0','variantId':'test','nuget':{'dependencyGroups':[]}}],
                    'evidence':[{'kind':'synthetic-candidate'}],'conflicts':[],'suggestedReuseScope':[{'kind':'comparison'}]}
        return {'schemaVersion':'1.0','catalogCommit':'c'*40,'profile':{'verified':False},
                'matches':[match('Newtonsoft.Json'),match('com.unity.nuget.newtonsoft-json'),match('Other')],
                'unknown':[{'reason':'other-unknown'}], 'conflicts':[],
                'nugetDependencyCandidates':{'completeClosure':False,'parents':[]}}

    def test_dual_distribution_resolve_and_old_lock_export_preserve_binding(self):
        matches=self.matches();before=copy.deepcopy(matches)
        lock=resolve(matches)
        self.assertTrue(any(c['kind']=='alternative-distributions-selected' for c in lock['conflicts']))
        self.assertEqual(matches,before)
        self.assertTrue(all(not l['suggestedReuseScope'] for l in lock['libraries'] if l['packageId']!='Other'))
        old=copy.deepcopy(lock);old['conflicts']=[]
        for library in old['libraries']:library['conflicts']=[]
        original=copy.deepcopy(old);receipt={'lockSha256':canonical_hash(old),'libraries':[]}
        exported=export_remaker(old,receipt,'f'*64)
        self.assertEqual(old,original);self.assertEqual(exported['lockSha256'],'f'*64)
        self.assertEqual(exported['lockContentSha256'],canonical_hash(old))
        self.assertEqual(exported['materialized'],receipt)
        self.assertTrue(exported['conflicts']);self.assertEqual(exported['unknown'],matches['unknown'])
        self.assertEqual(exported['nugetDependencyCandidates'],matches['nugetDependencyCandidates'])

    def test_explicit_one_alternative_preserves_other_evidence_and_normal_multilib(self):
        matches=self.matches();selection={'packageId':'Newtonsoft.Json','version':'1.0.0','variantId':'test'}
        result=resolve(matches,[selection])
        self.assertEqual({l['packageId'] for l in result['libraries']},{'Newtonsoft.Json','Other'})
        self.assertEqual(result['unselectedAlternatives'][0]['match'],matches['matches'][1])
        self.assertEqual(result['unknown'],matches['unknown'])
        self.assertTrue(all(l['status']=='strong-candidate' for l in result['libraries']))
        self.assertFalse(result['conflicts']);self.assertFalse(result['profile']['verified'])
        self.assertEqual(result['libraries'][0]['nuget'],{'dependencyGroups':[]})

    def test_ondemand_and_unverified_providers_never_enqueue_or_activate_even_refresh(self):
        state=curated.queue();ids={p['id'] for p in state['packages']}
        self.assertEqual(len(state['onDemandCandidates']),6);self.assertEqual(len(state['providerRuleCandidates']),4)
        self.assertTrue(all(p['version'] is None and p['id'] not in ids for p in state['onDemandCandidates']))
        self.assertTrue(all(not p['active'] and p['providerHint'] not in ids for p in state['providerRuleCandidates']))
        with tempfile.TemporaryDirectory() as temporary, patch('uvault.sources.fetch_package',side_effect=AssertionError('dormant fetched')):
            pipeline.metadata(state,Path(temporary),only=[p['id'] for p in state['onDemandCandidates']],refresh=True)
        with patch('uvault.harvest.collect_version',side_effect=AssertionError('dormant collected')):
            self.assertEqual(harvest.collect_selected(state,package_ids=[p['id'] for p in state['onDemandCandidates']])['attempted'],0)

    def test_cli_conflict_and_explicit_choice_both_remain_partial_with_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'matches.json';source.write_text(json.dumps(self.matches()))
            with patch('sys.stdout',new=io.StringIO()):
                self.assertEqual(main(['resolve','--matches',str(source),'--out',str(root/'both.json')]),3)
                self.assertEqual(main(['resolve','--matches',str(source),'--package','Newtonsoft.Json','--version','1.0.0','--variant','test','--out',str(root/'one.json')]),3)
                self.assertEqual(main(['export-remaker','--lock',str(root/'both.json'),'--out',str(root/'export.json')]),3)
            self.assertTrue(json.loads((root/'both.json').read_text())['conflicts'])
            self.assertEqual(len(json.loads((root/'one.json').read_text())['libraries']),2)
