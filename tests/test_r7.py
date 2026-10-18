import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uvault import builtin,curated,family_identity,sources
from uvault.classify import classify
from uvault.identify import identify
from uvault.materialize import canonical_hash
from uvault.remaker import export_remaker
from uvault.resolve import resolve
from test_builtin import declaration,inventory,catalog


class R7Tests(unittest.TestCase):
    def test_budget_exception_is_consumed_by_seed_selector_and_gap(self):
        seed=next(p for p in curated.seeds() if p['id']=='com.unity.cinemachine')
        self.assertEqual(seed['curatedPolicy']['maxCommonVersions'],4)
        rows=[{'version':v} for v in ['2.1.13','2.9.1','3.1.6','3.1.7','9.0.0']]
        self.assertEqual(len(curated.choose_versions(rows,seed['curatedPolicy'])),4)
        state={'packages':[seed]}
        with self.assertRaises(ValueError):curated.add_gap(state,seed['id'],'9.0.0','fifth explicit target')
        normal={'preferredVersions':['1.0.0','2.0.0','3.0.0','4.0.0'],'maxCommonVersions':3}
        with self.assertRaises(ValueError):curated.choose_versions([{'version':v} for v in normal['preferredVersions']],normal)

    def test_legacy_fallback_respects_actual_budget(self):
        rows=[{'version':v,'downloadUrl':'https://example.test/archive'} for v in ['1.0.0','2.0.0','3.0.0','4.0.0']]
        rows[0]['fetchStatus']='published'
        policy={'preferredVersions':['2.0.0','3.0.0','4.0.0'],'selectionMode':'fixed-common','maxCommonVersions':4,'retainVerifiedLegacy':True}
        self.assertEqual(len(curated.choose_versions(rows,policy)),4)

    def test_pinned_git_menu_does_not_enumerate_tags_or_confuse_component_version(self):
        seed={'id':'com.example.core','adapter':'github','repository':'Example/Monorepo','gitPins':[
            {'version':'3.0.3','sourceRef':'a'*40,'sourcePath':'unity/core','sourceTag':'unrelated-repository-tag',
             'versionBasis':'actual-component-manifest','componentMetadata':{'path':'unity/core/package.json','sha256':'b'*64}}],
             'curatedPolicy':{'selectionMode':'fixed-common','preferredVersions':['3.0.3'],'maxCommonVersions':3}}
        with patch('uvault.sources._github',side_effect=AssertionError('tag traversal')):record=sources.fetch_package(seed)['versions'][0]
        self.assertEqual(record['version'],'3.0.3');self.assertEqual(record['sourceRef'],'a'*40)
        self.assertEqual(record['sourcePath'],'unity/core');self.assertFalse(record['componentScope']['targetComponentEquivalenceVerified'])
        seed['gitPins'][0]['sourcePath']='../escape'
        with self.assertRaises(ValueError):sources.fetch_package(seed)

    def test_six_demand_entries_are_now_selected_without_background_activation(self):
        config=curated.configuration();state=curated.queue();by={p['id']:p for p in state['packages']}
        self.assertEqual(len(config['activatedDemandCandidates']),6);self.assertFalse(config['onDemandCandidates'])
        for row in config['activatedDemandCandidates']:
            self.assertIn(row['id'],by);self.assertTrue(row['selectedVersions']);self.assertIsNotNone(row['version'])
            self.assertFalse(row['automaticCollection'])
        self.assertEqual(len(config['activatedProviderCandidates']),4);self.assertFalse(config['providerRuleCandidates'])

    def test_vendor_tag_syntax_does_not_invent_prerelease_state(self):
        seed={'id':'example','repository':'Owner/Example','gitPins':[]}
        for label,status in [('Unity/R11','vendor-tag-unassessed'),('Release2.45','vendor-tag-unassessed'),
                             ('release_8_6_5','vendor-tag-unassessed'),('1.2.0','stable'),('v1.2.0-beta.1','prerelease'),
                             ('source-abc','snapshot')]:
            seed['gitPins']=[{'version':label,'sourceRef':'a'*40}]
            self.assertEqual(sources.pinned_git_package(seed)['versions'][0]['versionStatus'],status)
        seed['gitPins']=[{'version':'Unity/R12','sourceRef':'a'*40,'versionStatus':'stable',
                          'versionStatusEvidence':{'kind':'official-release','prerelease':False}}]
        record=sources.pinned_git_package(seed)['versions'][0]
        self.assertEqual(record['versionStatus'],'stable');self.assertFalse(record['versionStatusEvidence']['prerelease'])

    def _director(self,a='extern public void Play();',b='public extern void Stop();'):
        return inventory(declaration('play','UnityEngine.Playables.PlayableDirector','UnityEngine.DirectorModule',memberSignature=a),
                         declaration('stop','UnityEngine.Playables.PlayableDirector','UnityEngine.DirectorModule',memberSignature=b))

    def test_director_is_exact_type_and_public_instance_signature_scoped(self):
        inv=self._director();inv['declarations'].append(declaration('other','UnityEngine.Playables.PlayableAsset','UnityEngine.DirectorModule'))
        inv=inventory(*inv['declarations'])
        detected=builtin.detect_providers(inv)
        self.assertEqual(set(detected),{'play','stop'});self.assertEqual(detected['play']['recognitionScope'],'exact-type')
        for signature in ['public static void Play();','private void Play();','public int Play();','public void Play(int time);',
                          'public public void Play();','/* public void Play(); */']:
            with self.subTest(signature=signature):self.assertEqual(builtin.detect_providers(self._director(a=signature)),{})
        inv=self._director();inv['declarations'][1]['assemblyIdentity']['version']='different'
        self.assertEqual(builtin.detect_providers(inv),{})

    def test_screencapture_and_remaining_two_type_modules(self):
        inv=inventory(declaration('capture','UnityEngine.ScreenCapture','UnityEngine.ScreenCaptureModule',memberSignature='public static void CaptureScreenshot(string filename);'),
                      declaration('texture','UnityEngine.ScreenCapture','UnityEngine.ScreenCaptureModule',memberSignature='public static Texture2D CaptureScreenshotAsTexture();'))
        self.assertEqual(set(builtin.detect_providers(inv)),{'capture','texture'})
        inv['declarations'][1]['memberSignature']='public static object CaptureScreenshotAsTexture();'
        self.assertEqual(builtin.detect_providers(inv),{})
        for assembly,types in [('UnityEngine.AndroidJNIModule',['UnityEngine.AndroidJNI','UnityEngine.AndroidJavaObject']),
                               ('UnityEngine.UnityAnalyticsModule',['UnityEngine.Analytics.Analytics','UnityEngine.Analytics.AnalyticsSessionInfo'])]:
            inv=inventory(*(declaration(str(i),t,assembly) for i,t in enumerate(types)))
            self.assertEqual(len(builtin.detect_providers(inv)),2)
            self.assertEqual(builtin.detect_providers(inventory(inv['declarations'][0])),{})

    def test_legacy_engine_does_not_route_entire_namespace_or_business(self):
        inv=inventory(declaration('object','UnityEngine.GameObject','UnityEngine'),declaration('transform','UnityEngine.Transform','UnityEngine'),
                      declaration('extra','UnityEngine.PrivateThing','UnityEngine'),declaration('business','UnityEngine.GameObject','UnityEngine',category='game-business'))
        detected=builtin.detect_providers(inv)
        self.assertEqual(set(detected),{'object','transform'})
        self.assertEqual(detected['object']['referenceUnityVersions'],['5.6'])
        self.assertFalse(detected['object']['profileVerified'])

    def test_family_rules_never_cross_product_types_and_assemblies(self):
        inv=inventory(declaration('good','Sirenix.OdinInspector.ShowIfAttribute','Sirenix.OdinInspector.Attributes'),
                      declaration('wrong','Sirenix.OdinInspector.Editor.OdinEditor','Sirenix.OdinInspector.Attributes'))
        clues=family_identity.detect_inventory(inv)
        self.assertIn('good',clues)
        self.assertFalse(any(r['status']=='official-assembly-api-clue' for r in clues.get('wrong',[])))
        inv=inventory(declaration('skeleton','Spine.Skeleton','spine-csharp'),declaration('animation','Spine.Unity.SkeletonAnimation','spine-unity'))
        clues=family_identity.detect_inventory(inv)
        for key,expected in [('skeleton','spine-csharp'),('animation','spine-unity')]:
            self.assertEqual(clues[key][0]['assemblyTypeBindings'][0]['assemblyName'],expected)

    def test_unknown_assembly_api_pair_and_weak_simple_names_keep_native(self):
        inv=inventory(declaration('network','Photon.Pun.PhotonNetwork','Assembly-CSharp',category='game-business'),
                      declaration('callbacks','Photon.Pun.MonoBehaviourPunCallbacks','Assembly-CSharp',modified=True),
                      declaration('es3','User.ES3','Business'),declaration('settings','User.ES3Settings','Business'))
        original=copy.deepcopy(inv);result=classify(inv,catalog())
        rows=result['classification']['items'];self.assertTrue(all(r['nativeAction']=='recover-native' for r in rows))
        self.assertTrue(all(r.get('familyReferences') for r in rows));self.assertEqual(result['summary']['avoidedAddressCount'],0)
        self.assertEqual({r['id'] for r in result['libraryResolutionWorkset']['items']},{'network','callbacks','es3','settings'})
        self.assertEqual(inv,original)
        inv['declarations'][1]['assemblyIdentity']['name']='Other'
        clues=family_identity.detect_inventory(inv)
        self.assertFalse(any(r['status']=='same-input-assembly-api-pair-clue' for r in clues.get('network',[])))

    def test_missing_version_and_family_context_survive_resolve_and_old_lock_export(self):
        cat={'schemaVersion':'1.0','catalogCommit':'c'*40,'packages':[{'id':'com.example.package','versions':[{'version':'1.0.0','variantId':'upstream'}]}]}
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary,'manifest.json');path.write_text(json.dumps({'dependencies':{'com.example.package':'2.0.0'}}))
            found=identify(path,cat)
        self.assertEqual(found['missingVersionRequests'][0]['version'],'2.0.0');self.assertFalse(found['matches'])
        result=resolve(found);original=copy.deepcopy(result);result.pop('unknown');result.pop('unresolved')
        receipt={'lockSha256':canonical_hash(result),'libraries':[]}
        exported=export_remaker(result,receipt,'e'*64)
        self.assertTrue(exported['unknown']);self.assertEqual(exported['missingVersionRequests'],original['missingVersionRequests'])
        self.assertEqual(exported['lockContentSha256'],canonical_hash(result));self.assertEqual(exported['lockSha256'],'e'*64)

    def test_metadata_assembly_version_does_not_create_package_version_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            p=Path(temporary,'metadata.json');p.write_text(json.dumps({'assemblies':[{'scope':{'name':'Rewired_Core','version':'99.0.0.0'},'id':'a'}],
                 'types':[{'assemblyId':'a','fullName':'Rewired.ReInput'},{'assemblyId':'a','fullName':'Rewired.Player'}]}))
            result=identify(p,{'schemaVersion':'1.0','catalogCommit':'c'*40,'packages':[]})
        self.assertTrue(result['knownFamilies']);self.assertFalse(result.get('missingVersionRequests'))
        lock=resolve(result);lock.pop('unknown',None)
        self.assertTrue(export_remaker(lock)['unknown'])

    def test_matching_installation_does_not_swallow_other_observed_version_gap(self):
        from uvault.inventory import inventory_directory
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for folder,version,body in [('old-copy','1.0.0','void Old() {}'),('new-copy','2.0.0','void New() {}')]:
                package=root/'Packages'/folder;package.mkdir(parents=True)
                (package/'package.json').write_text(json.dumps({'name':'com.example.shared','version':version,'unity':'2020.3'}))
                (package/'Runtime.asmdef').write_text('{"name":"Example.Shared"}')
                (package/'Widget.cs').write_text('namespace Example { public class Widget { '+body+' } }')
            fp=inventory_directory(root/'Packages'/'old-copy',None)
            cat={'schemaVersion':'1.0','catalogCommit':'c'*40,'packages':[{'id':'com.example.shared','versions':[
                {'version':'1.0.0','variantId':'test','fingerprint':fp}]}]}
            result=identify(root,cat)
        self.assertEqual(result['matches'][0]['status'],'exact-artifact')
        self.assertEqual(result['matches'][0]['candidates'][0]['version'],'1.0.0')
        request=result['missingVersionRequests'][0]
        self.assertEqual(request['version'],'2.0.0');self.assertTrue(request['targetPresent'])
        self.assertTrue(request['observedSourceSetSha256']);self.assertTrue(result['unknown'])
        lock=resolve(result);self.assertTrue(lock['unresolved'])
        lock.pop('unknown');lock.pop('unresolved')
        export=export_remaker(lock)
        self.assertTrue(export['unknown']);self.assertEqual(export['missingVersionRequests'],result['missingVersionRequests'])

    def test_family_cache_binding_changes_when_producer_or_rules_change(self):
        inv=inventory(declaration('app','Game.App','Assembly-CSharp',category='game-business'))
        first=classify(inv,catalog())
        identity=family_identity.rules_identity();identity['rulesSha256']='f'*64
        with patch('uvault.family_identity.rules_identity',return_value=identity):second=classify(inv,catalog())
        self.assertNotEqual(first['classification']['cacheKey'],second['classification']['cacheKey'])

    def test_weak_family_hint_stays_unresolved_in_old_lock_export(self):
        found={'schemaVersion':'1.0','catalogCommit':'c'*40,'input':{},'matches':[],
               'familyHints':[{'familyId':'Moodkie.EasySave','status':'weak-simple-api-names-only',
                               'assemblyIdentity':{'name':'Game.Business'},'packageVersion':None}]}
        lock=resolve(found)
        self.assertTrue(lock['unknown'])
        lock.pop('unknown');lock.pop('unresolved')
        original=copy.deepcopy(lock)
        receipt={'lockSha256':canonical_hash(lock),'libraries':[]}
        exported=export_remaker(lock,receipt,'a'*64)
        self.assertEqual(lock,original);self.assertTrue(exported['unknown'])
        self.assertEqual(exported['familyHints'],lock['familyHints'])
        self.assertEqual(exported['lockContentSha256'],canonical_hash(original))

    def test_actual_binary_difference_protects_native_like_source_difference(self):
        cat=catalog();cat['packages'].append({'id':'com.example.library','versions':[{'version':'1.0.0','variantId':'test',
            'fingerprint':{'assemblies':[{'name':'Vendor.Runtime','types':['Vendor.Widget'],'ownershipVerified':True}]}}]})
        matches={'schemaVersion':'1.0','catalogCommit':cat['catalogCommit'],'matches':[{'packageId':'com.example.library',
            'status':'strong-candidate','candidates':[{'packageId':'com.example.library','version':'1.0.0','variantId':'test'}],
            'conflicts':[{'kind':'modified-or-different-binary-target','changed':['Runtime.dll']}]}]}
        inv=inventory(declaration('widget','Vendor.Widget','Vendor.Runtime'))
        row=classify(inv,cat,matches=matches)['classification']['items'][0]
        self.assertEqual(row['nativeAction'],'recover-native');self.assertEqual(row['category'],'modified')
