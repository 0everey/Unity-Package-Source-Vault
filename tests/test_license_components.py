import io
import unittest
from unittest.mock import Mock, patch
import zipfile

from uvault import harvest
from test_sources import MIT


def archive(files):
    output=io.BytesIO()
    with zipfile.ZipFile(output,"w") as z:
        for name,data in files.items():z.writestr(name,data)
    return output.getvalue()


class BinaryRightsTests(unittest.TestCase):
    def test_wrapper_license_never_authorizes_extensionless_binary(self):
        cases = {
            "plugin.dylib": b"native",
            "Plugin.bundle/Contents/MacOS/VendorSDK": b"\xcf\xfa\xed\xfe" + bytes(28),
            "VendorSDK.framework/Versions/A/VendorSDK": b"\xca\xfe\xba\xbe" + bytes(28),
            "VendorSDK.framework/VendorSDK": b"opaque",
            "tools/unknown": b"\x7fELF" + bytes(28),
            "tools/windows": b"MZ" + bytes(30),
        }
        for path,content in cases.items():
            with self.subTest(path=path):
                data=archive({"LICENSE":MIT,"Wrapper.cs":b"class Wrapper{}",path:content})
                publisher=Mock()
                with patch("uvault.sources.request_bytes",return_value=data):
                    result=harvest.collect_version({"id":"test"},{"version":"1","variantId":"test","downloadUrl":"https://example.invalid/test.zip"},publish=publisher)
                self.assertEqual(result["disposition"],"official-fetch-only")
                self.assertEqual(result["artifact"]["kind"],"mixed-source-binary")
                publisher.assert_not_called()

    def test_source_and_plain_unity_asset_bundle_stay_mirrorable(self):
        data=archive({"LICENSE":MIT,"A.cs":b"class A{}","data.bundle":b"UnityFS\0synthetic resource"})
        result=harvest.inspect_licenses(data,"zip",{})
        self.assertEqual(result["disposition"],"mirror-allowed")
        self.assertEqual(result["binaryComponents"],[])

    def test_old_published_review_is_rechecked(self):
        self.assertTrue(harvest.needs_license_recheck({"fetchStatus":"published","license":{"reviewAlgorithm":"archive-rights-v2"}}))
