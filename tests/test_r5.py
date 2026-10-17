import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from uvault import builtin,curated,harvest
from uvault.classify import classify
from uvault.identify import identify
from uvault.inventory import inventory_directory
from uvault.resolve import resolve
from uvault.remaker import export_remaker
from test_builtin import declaration,inventory,catalog
from test_sources import MIT,tar_bytes


def json_inventory(first="public static string ToJson(object obj) { }",second="public static object FromJson(string json, Type type) { }"):
    return inventory(declaration("to","UnityEngine.JsonUtility","UnityEngine.JSONSerializeModule",memberSignature=first),
                     declaration("from","UnityEngine.JsonUtility","UnityEngine.JSONSerializeModule",memberSignature=second))


class R5Tests(unittest.TestCase):
    def test_singleton_two_complete_public_members_only_route_exact_type(self):
        inv=json_inventory()
        inv["declarations"] += [declaration("helper","UnityEngine.JsonUtility","UnityEngine.JSONSerializeModule",memberSignature="private static string ToJsonInternal(object obj) { }"),
                              declaration("other","UnityEngine.Unrelated","UnityEngine.JSONSerializeModule")]
        inv=inventory(*inv["declarations"])
        result=classify(inv,catalog())
        rows={r["id"]:r for r in result["classification"]["items"]}
        self.assertEqual({k for k,r in rows.items() if r["nativeAction"]=="provider-reference"},{"to","from","helper"})
        self.assertEqual(rows["other"]["nativeAction"],"recover-native")
        self.assertEqual(rows["to"]["provider"]["recognitionScope"],"exact-type")
        self.assertFalse(rows["to"]["profileVerified"])

    def test_singleton_shape_access_name_and_generic_counterexamples(self):
        invalid=["private static string ToJson(object obj) { }","public string ToJson(object obj) { }",
                 "public static object ToJson(object obj) { }","public static string NotToJson(object obj) { }",
                 "public static string ToJson(string obj) { }","public static string ToJson(ref object obj) { }",
                 "public static string ToJson<T>(object obj) { }","/* public static string ToJson(object obj) */"]
        for signature in invalid:
            with self.subTest(signature=signature):self.assertEqual(builtin.detect_providers(json_inventory(first=signature)),{})
        inv=json_inventory(second="private static object FromJsonInternal(string json, Type type) { }")
        self.assertEqual(builtin.detect_providers(inv),{})

    def test_singleton_duplicate_private_cross_identity_and_protected_do_not_supply_second_member(self):
        inv=json_inventory();inv["declarations"][1]["assemblyIdentity"]["culture"]="foreign"
        self.assertEqual(builtin.detect_providers(inv),{})
        for flag in ({"category":"game-business"},{"category":"unknown"},{"modified":True},{"ownershipVerified":False}):
            inv=json_inventory();inv["declarations"][1].update(flag)
            self.assertEqual(builtin.detect_providers(inv),{})
        inv=json_inventory(second="public static string ToJson(object obj) { }")
        self.assertEqual(builtin.detect_providers(inv),{})

    def test_image_conversion_and_two_type_textcore_xr_providers(self):
        inv=inventory(declaration("jpg","UnityEngine.ImageConversion","UnityEngine.ImageConversionModule",memberSignature="public static byte[] EncodeToJPG(Texture2D tex, int quality) { }"),
                      declaration("load","UnityEngine.ImageConversion","UnityEngine.ImageConversionModule",memberSignature="public static bool LoadImage(Texture2D tex, byte[] data, bool markNonReadable) { }"))
        self.assertEqual(set(builtin.detect_providers(inv)),{"jpg","load"})
        for assembly,types in [("UnityEngine.TextCoreFontEngineModule",["UnityEngine.TextCore.FaceInfo","UnityEngine.TextCore.Glyph"]),
                               ("UnityEngine.TextCoreTextEngineModule",["UnityEngine.TextCore.Text.FontAsset","UnityEngine.TextCore.Text.TextSettings"]),
                               ("UnityEngine.XRModule",["UnityEngine.XR.InputDevices","UnityEngine.XR.InputTracking"]),
                               ("UnityEngine.VRModule",["UnityEngine.XR.XRDevice","UnityEngine.XR.XRSettings"])]:
            inv=inventory(*(declaration(str(n),typ,assembly) for n,typ in enumerate(types)))
            self.assertEqual(len(builtin.detect_providers(inv)),2)
            self.assertEqual(builtin.detect_providers(inventory(inv['declarations'][0])),{})

    def test_best_http_references_defer_documented_types_but_do_not_claim_exact_or_business(self):
        package=next(p for p in curated.seeds() if p['id']=='com.Tivadar.Best.HTTP')
        self.assertTrue(all(v['artifact'] is None and v['fetchStatus']=='reference-only' for v in package['versions']))
        inv=inventory(declaration('request','Best.HTTP.HTTPRequest','com.Tivadar.Best.HTTP'),declaration('business','Best.HTTP.HTTPRequest','Assembly-CSharp'))
        r=classify(inv,{'catalogCommit':'c'*40,'packages':[package]})
        self.assertEqual(r['classification']['items'][0]['nativeAction'],'defer-library-resolution')
        self.assertEqual(r['classification']['items'][1]['nativeAction'],'recover-native')

    def test_named_pending_survives_strong_catalog_and_writer_source_confirmed(self):
        for family,assembly in [('Tekly','Tekly.Common.Runtime'),('OOI','OOI.Platform')]:
            inv=inventory(declaration('x',family+'.Type',assembly,nativeAddress='0x1000'))
            candidate={'version':'1.0.0','variantId':'public','sourceRef':'a'*40,'sourceUrl':'https://example.invalid/source','disposition':'mirror-allowed',
                       'fingerprint':{'assemblies':[{'name':assembly,'ownershipVerified':True,'types':[family+'.Type']}]}}
            cat={'catalogCommit':'c'*40,'packages':[{'id':'arbitrary.public.package','versions':[candidate]}]}
            r=classify(inv,cat)
            self.assertEqual(r['classification']['items'][0]['nativeAction'],'recover-native')
            self.assertEqual(r['summary']['namedPendingDeclarationCount'],1)
            self.assertEqual(r['libraryResolutionWorkset']['items'][0]['id'],'x')
            decision={'binding':r['classification']['binding'],'decisions':[{'id':'x','action':'reuse-upstream','status':'accepted','acceptedBy':'original-writer',
                       'scope':{key:copy.deepcopy(inv['declarations'][0][key]) for key in ('assemblyIdentity','typeFullName','memberSignature')},
                       'packageId':'arbitrary.public.package','version':'1.0.0','variantId':'public','sourceConfirmed':True,'evidenceRefs':[{'kind':'synthetic-writer-source'}]}]}
            r=classify(inv,cat,decisions=decision)
            self.assertEqual(r['classification']['items'][0]['nativeAction'],'recover-native')
            self.assertIn('decisionRejected',r['classification']['items'][0])

    def test_identify_resolve_export_keep_named_pending_even_for_literal_equal_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'X.asmdef').write_text('{"name":"Tekly.Common.Runtime"}')
            (root/'X.cs').write_text('namespace Tekly.Common { public class X {} }')
            fp=inventory_directory(root)
            cat={'catalogCommit':'c'*40,'packages':[{'id':'ca.tekly.common','versions':[{'version':'1.0.0','variantId':'public','fingerprint':fp,'artifact':None,'disposition':'mirror-allowed'}]}]}
            m=identify(root,cat)
            self.assertEqual(m['matches'][0]['status'],'origin-unresolved')
            self.assertTrue(m['namedPending'])
            lock=resolve(m,[{'packageId':'ca.tekly.common','version':'1.0.0','variantId':'public'}])
            self.assertTrue(lock['namedPending']);self.assertEqual(lock['libraries'][0]['status'],'origin-unresolved')
            export=export_remaker(lock);self.assertTrue(export['namedPending']);self.assertEqual(export['adoptionStatus'],'pending')
            legacy=copy.deepcopy(m);legacy.pop('namedPending');legacy['unknown']=[];legacy['conflicts']=[]
            legacy['matches'][0].update(status='exact-artifact',conflicts=[])
            locked=resolve(legacy,[{'packageId':'ca.tekly.common','version':'1.0.0','variantId':'public'}])
            self.assertTrue(locked['namedPending']);self.assertEqual(locked['libraries'][0]['status'],'origin-unresolved')
            locked.pop('namedPending');locked['unknown']=[];locked['conflicts']=[]
            locked['libraries'][0].pop('namedPending');locked['libraries'][0]['status']='exact-artifact'
            exported=export_remaker(locked)
            self.assertTrue(exported['namedPending']);self.assertEqual(exported['libraries'][0]['status'],'origin-unresolved')

    def test_named_prefix_lookalikes_are_not_marked_and_shared_business_keeps_address(self):
        inv=inventory(declaration('p','UnityEngine.Physics'),declaration('c','UnityEngine.Collider'),
                      declaration('tek','Tekly.SomeBusiness','Assembly-CSharp',nativeAddress='0x1000'),
                      declaration('look','TeklyX.Type','TeklyX.Runtime'))
        inv['declarations'][0]['nativeAddress']='0x1000'
        result=classify(inv,catalog());rows={r['id']:r for r in result['classification']['items']}
        self.assertTrue(rows['tek']['namedPending']);self.assertNotIn('namedPending',rows['look'])
        self.assertIn('tek',result['nativeSelection']['methodIds'])
        self.assertEqual(result['summary']['nativeAddressCount'],1)

    def test_named_embedded_alias_is_protected_from_all_unity_entrypoints(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);packages=root/'Packages';packages.mkdir()
            deps={};records=[]
            for pid,assembly,namespace in [('com.example.embedded','Tekly.Common.Runtime','Tekly.Common'),('com.example.clean','Other.Runtime','Other')]:
                folder=packages/pid;folder.mkdir()
                (folder/'package.json').write_text(json.dumps({'name':pid,'version':'1.0.0'}))
                (folder/'X.asmdef').write_text(json.dumps({'name':assembly}))
                (folder/'X.cs').write_text('namespace '+namespace+' { public class X {} }')
                fp=inventory_directory(folder)
                records.append({'id':pid,'versions':[{'version':'1.0.0','variantId':'public','fingerprint':fp,'artifact':None,'disposition':'mirror-allowed'}]})
                deps[pid]={'version':'file:'+pid,'source':'embedded','dependencies':{}}
            (packages/'manifest.json').write_text(json.dumps({'dependencies':{k:'file:'+k for k in deps}}))
            (packages/'packages-lock.json').write_text(json.dumps({'dependencies':deps}))
            cat={'catalogCommit':'c'*40,'packages':records}
            for path in (root,packages,packages/'manifest.json',packages/'packages-lock.json'):
                with self.subTest(path=path.name):
                    result=identify(path,cat);matches={m['packageId']:m for m in result['matches']}
                    self.assertTrue(result['namedPending']);self.assertTrue(result['unknown'])
                    self.assertEqual(matches['com.example.embedded']['status'],'origin-unresolved')
                    self.assertNotEqual(matches['com.example.clean']['status'],'origin-unresolved')

    def test_named_generated_scope_cannot_inherit_library_defer_in_either_order(self):
        import itertools
        owner=declaration('owner','Other.Library','Other.Runtime')
        child=declaration('child','Tekly.GeneratedState','Other.Runtime',category='compiler-generated',owner={'declarationId':'owner','verified':True,'evidenceRefs':[{'kind':'original-owner'}]})
        leaf=declaration('leaf','Other.GeneratedLeaf','Other.Runtime',category='compiler-generated',owner={'declarationId':'child','verified':True,'evidenceRefs':[{'kind':'original-owner'}]})
        cat={'catalogCommit':'c'*40,'packages':[{'id':'public.library','versions':[{'version':'1','variantId':'public','fingerprint':{'assemblies':[{'name':'Other.Runtime','ownershipVerified':True,'types':['Other.Library']}]}}]}]}
        for rows in itertools.permutations([owner,child,leaf]):
            result=classify(inventory(*rows),cat)
            self.assertEqual(set(result['nativeSelection']['methodIds']),{'child','leaf'})
        ordinary=copy.deepcopy(child);ordinary['typeFullName']='Other.GeneratedState'
        result=classify(inventory(owner,ordinary),cat)
        self.assertEqual(result['nativeSelection']['methodIds'],[])
        business=copy.deepcopy(owner);business['category']='game-business'
        result=classify(inventory(business,ordinary),cat)
        self.assertEqual(set(result['nativeSelection']['methodIds']),{'owner','child'})

    def test_dots_sets_check_actual_edges_and_exact_gaps_without_substitution(self):
        state={'packages':[{'id':'entities','versions':[{'version':'1.3.14','variantId':'a','dependencies':{}}]},
                           {'id':'graphics','versions':[{'version':'1.4.12','variantId':'a','dependencies':{'entities':'1.3.14','srp':'14.0.10'}}]},
                           {'id':'srp','versions':[{'version':'14.0.12','variantId':'a'}]}],
               'compatibilitySetDefinitions':[{'id':'test','members':{'entities':'1.3.14','graphics':'1.4.12'}}]}
        group=curated.compatibility_sets(state)[0]
        self.assertEqual(group['status'],'member-declarations-verified');self.assertFalse(group['profileVerified'])
        self.assertEqual(group['exactDependencyGaps'][0]['version'],'14.0.10')
        self.assertFalse(group['exactDependencyGaps'][0]['automaticSubstitution'])
        state['packages'][1]['versions'][0]['dependencies']['entities']='1.4.12'
        self.assertEqual(curated.compatibility_sets(state)[0]['status'],'member-declaration-conflict')

    def test_sentry_bundled_versions_stay_with_sdk_and_not_generic_system(self):
        data=tar_bytes({'package/LICENSE':MIT,'package/A.cs':b'class A{}','package/Sentry.dll':b'MZ synthetic'})
        rows=[{'path':'Runtime/Sentry.dll','sha256':'a'*64,'metadataStatus':'managed','assemblyIdentity':{'name':'Sentry','version':'5.11.2.0'}},
              {'path':'Runtime/Sentry.System.Memory.dll','sha256':'b'*64,'metadataStatus':'managed','assemblyIdentity':{'name':'Sentry.System.Memory','version':'4.0.1.1'}},
              {'path':'Other/System.Memory.dll','sha256':'d'*64,'metadataStatus':'managed','assemblyIdentity':{'name':'System.Memory','version':'9.0.0.0'}}]
        fingerprint={'files':[{'path':'A.cs'},{'path':'Sentry.dll'}],'managedMetadata':rows}
        publisher=Mock()
        with patch('uvault.sources.request_bytes',return_value=data),patch('uvault.inventory.fingerprint_archive',return_value=fingerprint):
            r=harvest.collect_version({'id':'io.sentry.unity','componentBundle':'sentry-unity'},{'version':'3.2.3','variantId':'test','downloadUrl':'https://example.invalid/sdk.tgz'},publish=publisher)
        self.assertEqual({x['assemblyIdentity']['name'] for x in r['sdkBundle']['assemblies']},{'Sentry','Sentry.System.Memory'})
        self.assertEqual(r['sdkBundle']['version'],'3.2.3');self.assertEqual(r['disposition'],'official-fetch-only');publisher.assert_not_called()

    def test_sentry_renamed_system_assembly_does_not_match_plain_system(self):
        version={'version':'3.2.3','variantId':'sdk','fingerprint':{'assemblies':[{'name':'Sentry.System.Text.Json','ownershipVerified':True,'types':['System.Text.Json.JsonSerializer']}]}}
        cat={'catalogCommit':'c'*40,'packages':[{'id':'io.sentry.unity','versions':[version]}]}
        inv=inventory(declaration('sdk','System.Text.Json.JsonSerializer','Sentry.System.Text.Json'),declaration('other','System.Text.Json.JsonSerializer','System.Text.Json'))
        r=classify(inv,cat)
        self.assertEqual([x['nativeAction'] for x in r['classification']['items']],['defer-library-resolution','recover-native'])
