import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from uvault import managed


def native_pe():
    """A synthetic PE32 image with no CLR directory; never run this image."""
    image = bytearray(1024)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    for offset, value in ((4, 0x200), (16, 0x1000), (20, 0x1000), (24, 0x2000), (28, 0x400000),
                          (32, 0x1000), (36, 0x200), (56, 0x2000), (60, 0x200),
                          (72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16)):
        struct.pack_into("<I", image, optional + offset, value)
    struct.pack_into("<H", image, optional + 40, 6)
    struct.pack_into("<H", image, optional + 68, 3)
    section = optional + 0xE0
    image[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 1, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200] = 0xC3
    return bytes(image)


class ManagedUnavailableTests(unittest.TestCase):
    def test_missing_adapter_is_hash_only_explicit_and_never_executes(self):
        data = b"synthetic unknown bytes"
        with patch.dict(os.environ, {"UVAULT_MANAGED_INDEXER": "missing-vault-metadata-decoder-77d289"}), patch.object(managed.subprocess, "run") as runner:
            records = managed.parse_binaries({"lib/Unknown.dll": data})
        runner.assert_not_called()
        self.assertEqual(records[0]["metadataStatus"], "unavailable")
        self.assertEqual(records[0]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(records[0]["types"], [])
        self.assertIsNone(records[0]["assemblyIdentity"])
        self.assertEqual(records[0]["path"], "lib/Unknown.dll")
        with self.assertRaises(ValueError):
            managed.parse_binaries({"../private.dll": data})


@unittest.skipUnless(shutil.which("dotnet"), "Installed .NET SDK is needed for real PEReader verification")
class ManagedRealReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="uvault-managed-synthetic-")
        cls.root = Path(cls.temporary.name)
        result = managed.build_indexer(cls.root / "reader")
        if result["metadataStatus"] != "ready":
            cls.temporary.cleanup()
            raise AssertionError("Installed SDK could not build the local dependency-free reader: " + json.dumps(result))
        cls.launcher = json.dumps(result["launcher"])
        fixture = cls.root / "fixture"
        fixture.mkdir()
        (fixture / "Fixture.csproj").write_text('''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
<TargetFramework>net8.0</TargetFramework><AssemblyName>Vault.Synthetic.Metadata</AssemblyName>
<AssemblyVersion>1.2.3.4</AssemblyVersion><NuGetAudit>false</NuGetAudit>
<EnableTargetingPackDownload>false</EnableTargetingPackDownload><EnableRuntimePackDownload>false</EnableRuntimePackDownload>
</PropertyGroup></Project>''', encoding="utf-8")
        (fixture / "Fixture.cs").write_text('''using System;
using System.IO;
using System.Runtime.CompilerServices;
namespace Example;
public class Outer<T> { public class Inner<U> { public V Convert<V>(T left, U right, V fallback) => fallback; } }
public interface IWork { void Work(int value); }
public enum Kind { First, Second }
public struct Payload { public int X; }
public static class NeverExecute {
    [ModuleInitializer] public static void Init() {
        var marker = Environment.GetEnvironmentVariable("UVAULT_TEST_EXECUTION_MARKER");
        if (marker != null) File.WriteAllText(marker, "TARGET WAS EXECUTED");
        throw new Exception("This synthetic target must never execute");
    }
}''', encoding="utf-8")
        empty_feed = cls.root / "empty-feed"
        empty_feed.mkdir()
        build = subprocess.run([shutil.which("dotnet"), "build", str(fixture / "Fixture.csproj"), "--configuration", "Release",
                                "--output", str(cls.root / "fixture-out"), "--source", str(empty_feed),
                                "--verbosity", "quiet", "-p:NuGetAudit=false", "-p:EnableTargetingPackDownload=false", "-p:EnableRuntimePackDownload=false"],
                               capture_output=True, text=True, encoding="utf-8", timeout=180,
                               env={**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1"})
        if build.returncode:
            cls.temporary.cleanup()
            raise AssertionError("Could not compile our own synthetic metadata fixture: " + build.stdout + build.stderr)
        cls.payload = (cls.root / "fixture-out" / "Vault.Synthetic.Metadata.dll").read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_managed_metadata_identity_nested_arity_methods_without_execution(self):
        marker = self.root / "must-not-be-created.txt"
        with patch.dict(os.environ, {"UVAULT_MANAGED_INDEXER": self.launcher, "UVAULT_TEST_EXECUTION_MARKER": str(marker)}):
            records = managed.parse_binaries({"lib/net8.0/Vault.Synthetic.Metadata.dll": self.payload})
        self.assertFalse(marker.exists(), "Target module initializer executed")
        record = records[0]
        self.assertEqual(record["metadataStatus"], "managed")
        self.assertEqual(record["assemblyIdentity"], {"name": "Vault.Synthetic.Metadata", "version": "1.2.3.4", "culture": "neutral", "publicKeyToken": None})
        self.assertFalse(record["dummyDll"])
        self.assertFalse(record["profileVerified"])
        types = {row["fullName"]: row for row in record["types"]}
        inner = types["Example.Outer`1+Inner`1"]
        convert = next(row for row in inner["methods"] if row["name"] == "Convert")
        self.assertEqual((convert["arity"], convert["parameterCount"]), (1, 3))
        self.assertEqual(len(convert["signatureBlobSha256"]), 64)
        self.assertEqual(types["Example.IWork"]["kind"], "interface")
        self.assertEqual(types["Example.Kind"]["kind"], "enum")
        self.assertEqual(types["Example.Payload"]["kind"], "struct")
        runtime = next(row for row in record["references"] if row["name"] == "System.Runtime")
        self.assertEqual(runtime["publicKeyToken"], "b03f5f7f11d50a3a")

    def test_native_pe_and_invalid_bytes_remain_explicit_nonmanaged(self):
        with patch.dict(os.environ, {"UVAULT_MANAGED_INDEXER": self.launcher}):
            rows = managed.parse_binaries({"native/sdk.dll": native_pe(), "broken/invalid.dll": b"not a PE image"})
        self.assertEqual([row["metadataStatus"] for row in rows], ["native-binary", "invalid-binary"])
        self.assertTrue(all(row["assemblyIdentity"] is None and row["types"] == [] for row in rows))


if __name__ == "__main__":
    unittest.main()
