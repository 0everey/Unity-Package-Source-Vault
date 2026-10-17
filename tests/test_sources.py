import hashlib
import io
import json
import tarfile
import unittest
from unittest.mock import patch

from uvault import harvest, sources


MIT = b'''MIT License\nCopyright (c) Synthetic Test Author\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files, to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies.\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.\n'''


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


class SourceTests(unittest.TestCase):
    def test_semantic_order_and_targets(self):
        values = ["1.9.0", "1.10.0", "2.0.0-pre.1", "2.0.0", "2.0.10", "2.0.2", "0.9.0"]
        self.assertGreater(sources.version_key("1.10.0"), sources.version_key("1.9.0"))
        self.assertGreater(sources.version_key("v2.0.0"), sources.version_key("v2.0.0-rc.12"))
        self.assertGreater(sources.version_key("2.0.0-rc.12"), sources.version_key("2.0.0-rc.2"))
        selected = sources.select_versions(values, ["1.9.0", "99.0.0"])
        self.assertIn("1.9.0", selected)
        self.assertIn("2.0.10", selected)
        self.assertNotIn("99.0.0", selected)
        self.assertEqual(sources.selection_status(values, ["99.0.0"])["missingTargetVersions"], ["99.0.0"])

    def test_all_targets_bypass_default_count_without_fabrication(self):
        values = ["1.0." + str(n) for n in range(8)]
        selected = sources.select_versions(values, values[:6])
        self.assertTrue(set(values[:6]).issubset(selected))
        self.assertEqual(sources.select_versions(["1.0.0"]), ["1.0.0"])

    def test_registry_keeps_all_versions_and_integrity(self):
        response = {"versions": {"1.10.0": {"dist": {"tarball": "https://example.invalid/a.tgz", "shasum": "abc"}}, "1.2.0": {"license": "MIT", "dist": {}}}}
        with patch.object(sources, "request_json", return_value=response):
            package = sources.registry_package("com.test.example", "https://registry.example")
        self.assertEqual([v["version"] for v in package["versions"]], ["1.2.0", "1.10.0"])
        self.assertEqual(package["versions"][1]["upstreamShasum"], "abc")
        self.assertEqual(package["versions"][0]["disposition"], "license-unresolved")

    def test_same_version_changed_registry_object_is_new_variant(self):
        a = sources._record("test", "1.0", {"dist": {"shasum": "aaa"}}, "https://registry.example")
        b = sources._record("test", "1.0", {"dist": {"shasum": "bbb"}}, "https://registry.example")
        self.assertNotEqual(a["variantId"], b["variantId"])

    def test_openupm_enumeration_exceeds_contents_limit(self):
        tree = {"truncated": False, "tree": [{"path": "data/packages/com.test.p%04d.yml" % i, "type": "blob", "sha": str(i)} for i in range(1201)]}
        with patch.object(sources, "_github", return_value=tree):
            result = sources.discover_openupm("a" * 40)
        self.assertEqual(result["discoveredCount"], 1201)
        self.assertTrue(result["completeEnumeration"])
        self.assertEqual(result["packages"][-1]["metadataStatus"], "pending")

    def test_truncated_tree_walk(self):
        responses = [{"truncated": True, "tree": []},
                     {"tree": [{"path": "data", "type": "tree", "sha": "data"}, {"path": "irrelevant", "type": "tree", "sha": "skip"}]},
                     {"tree": [{"path": "packages", "type": "tree", "sha": "packages"}]},
                     {"tree": [{"path": "com.test.yml", "type": "blob", "sha": "definition"}]}]
        with patch.object(sources, "_github", side_effect=responses):
            result = sources.discover_openupm("a" * 40)
        self.assertTrue(result["completeEnumeration"])
        self.assertEqual(result["enumeration"], "complete-subtree-walk")
        self.assertEqual(result["packages"][0]["id"], "com.test")

    def test_git_paginates_and_pins_tag_sha(self):
        first = [{"name": "v1.0." + str(i), "commit": {"sha": "%040x" % i}} for i in range(100)]
        last = [{"name": "v2.0.0", "commit": {"sha": "b" * 40}}]
        with patch.object(sources, "_github", side_effect=[first, last]) as getter:
            result = sources.git_package("example", "owner/repo")
        self.assertEqual(len(result["versions"]), 101)
        self.assertIn("page=2", getter.call_args.args[0])
        self.assertEqual(result["versions"][-1]["sourceRef"], "b" * 40)

    def test_permissive_archive_and_native_boundary(self):
        record = {"downloadUrl": "https://example.invalid/archive.tgz"}
        clean = tar_bytes({"package/LICENSE": MIT, "package/A.cs": b"class A{}"})
        rights = harvest.inspect_licenses(clean, "tar.gz", record)
        self.assertEqual(rights["disposition"], "mirror-allowed")
        mixed = tar_bytes({"package/LICENSE": MIT, "package/A.cs": b"class A{}", "package/native/steam_api64.dll": b"native"})
        rights = harvest.inspect_licenses(mixed, "tar.gz", record)
        self.assertEqual(rights["disposition"], "official-fetch-only")
        self.assertTrue(any(c.get("reviewStatus") == "native-component-rights-unresolved" for c in rights["license"]["components"]))

    def test_unknown_nested_license_prevents_blanket_mirror(self):
        data = tar_bytes({"p/LICENSE": MIT, "p/vendor/LICENSE": b"All rights reserved"})
        rights = harvest.inspect_licenses(data, "tar.gz", {"downloadUrl": "https://example.invalid/a"})
        self.assertEqual(rights["disposition"], "license-unresolved")

    def test_special_license_does_not_become_mit(self):
        for text in (b"Spine Runtimes License Agreement", b"Unity Companion License", b"PrimeTween: You may not distribute source code"):
            data = tar_bytes({"p/LICENSE": text})
            rights = harvest.inspect_licenses(data, "tar.gz", {"downloadUrl": "https://example.invalid/a"})
            self.assertEqual(rights["disposition"], "official-fetch-only")

    def test_integrity_failure_is_not_success(self):
        version = {"version": "1.0.0", "downloadUrl": "https://example.invalid/a", "upstreamShasum": "0" * 40, "disposition": "license-unresolved"}
        with patch.object(sources, "request_bytes", return_value=b"corrupt"):
            result = harvest.collect_version({"id": "test"}, version)
        self.assertEqual(result["fetchStatus"], "fetch-failed")
        self.assertIn("SHA1 mismatch", result["fetchError"]["message"])

    def test_resume_and_full_coverage_queue(self):
        queue = {"packages": [{"id": "done", "metadataStatus": "complete", "versions": []}, {"id": "todo", "adapter": "registry", "metadataStatus": "pending", "versions": []}, {"id": "later", "adapter": "registry", "metadataStatus": "pending", "versions": []}]}
        fetched = {"schemaVersion": "1.0", "id": "todo", "metadataStatus": "complete", "versions": [{"version": "1.0.0", "dependencies": {}, "fetchStatus": "pending"}]}
        with patch.object(sources, "fetch_package", return_value=fetched) as getter:
            result = harvest.update_metadata(queue, limit=1)
        self.assertEqual(getter.call_count, 1)
        self.assertEqual(result["coverage"]["discoveredPackages"], 3)
        self.assertEqual(result["coverage"]["pendingPackageIds"], ["later"])

    def test_refresh_preserves_old_objects_and_discovers_variants(self):
        old = {"version": "1.0.0", "variantId": "old", "artifact": {"sha256": "original"}, "fetchStatus": "published", "disposition": "mirror-allowed"}
        queue = {"packages": [{"id": "test", "metadataStatus": "complete", "versions": [old], "targetVersions": ["1.0.0"]}]}
        fetched = {"id": "test", "metadataStatus": "complete", "versions": [{"version": "1.0.0", "variantId": "new", "dependencies": {}}, {"version": "2.0.0", "variantId": "v2", "dependencies": {}}]}
        with patch.object(sources, "fetch_package", return_value=fetched):
            harvest.update_metadata(queue, refresh=True)
        versions = queue["packages"][0]["versions"]
        self.assertEqual(len(versions), 3)
        original = next(v for v in versions if v["variantId"] == "old")
        self.assertEqual(original["artifact"]["sha256"], "original")
        self.assertFalse(original["upstreamListed"])
        self.assertEqual(queue["packages"][0]["targetVersions"], ["1.0.0"])

    def test_publishing_resume_does_not_refetch_restricted_collected(self):
        queue = {"packages": [{"id": "test", "metadataStatus": "complete", "versions": [{"version": "1.0.0", "fetchStatus": "collected", "disposition": "official-fetch-only", "license": {"reviewAlgorithm": harvest.LICENSE_REVIEW_ALGORITHM}}]}]}
        with patch.object(harvest, "collect_version") as collector:
            result = harvest.collect_selected(queue, publish=lambda data, record: None)
        self.assertEqual(result["attempted"], 0)
        collector.assert_not_called()

    def test_upstream_license_must_match_pinned_manifest(self):
        manifest = {"license": "MIT", "repository": {"url": "https://github.com/owner/repo", "revision": "a" * 40}}
        with patch.object(sources, "request_bytes", return_value=MIT) as getter:
            evidence = harvest._pinned_upstream_license({}, manifest)
        self.assertEqual(evidence["sourceRef"], "a" * 40)
        self.assertIn("/" + "a" * 40 + "/LICENSE", getter.call_args.args[0])
        manifest["repository"]["revision"] = "main"
        with patch.object(sources, "request_bytes") as getter:
            self.assertIsNone(harvest._pinned_upstream_license({}, manifest))
        getter.assert_not_called()

    def test_vendor_without_license_blocks_root_mit(self):
        data = tar_bytes({"p/LICENSE": MIT, "p/ThirdParty/Other/Other.cs": b"class Other{}"})
        rights = harvest.inspect_licenses(data, "tar.gz", {"downloadUrl": "https://example.invalid/a"})
        self.assertEqual(rights["disposition"], "license-unresolved")

    def test_mit_quote_with_added_restriction_is_not_permissive(self):
        self.assertEqual(harvest.license_expression(MIT.decode() + "\nYou may not redistribute source code."), "LicenseRef-Restricted")

    def test_old_license_result_needs_recheck(self):
        self.assertTrue(harvest.needs_license_recheck({"license": {"expression": "MIT"}}))
        self.assertFalse(harvest.needs_license_recheck({"license": {"reviewAlgorithm": harvest.LICENSE_REVIEW_ALGORITHM}}))

    def test_review_for_other_archive_cannot_override_unknown_component(self):
        data = tar_bytes({"p/LICENSE": MIT, "p/External/Other/Other.cs": b"class Other{}"})
        review = {"archiveSha256": "wrong", "packageId": "test", "version": "1.0", "reviewStatus": "reviewed", "components": [{"path": "External", "classification": "project-authored-integration-adapters"}]}
        rights = harvest.inspect_licenses(data, "tar.gz", {"packageId": "test", "version": "1.0", "downloadUrl": "https://example.invalid/a"}, component_review=review)
        self.assertEqual(rights["disposition"], "license-unresolved")

    def test_coverage_counts_selected_variants_as_separate_tasks(self):
        queue = {"packages": [{"id": "test", "selectedVersions": ["1.0"], "versions": [{"version": "1.0", "variantId": "a", "fetchStatus": "collected"}, {"version": "1.0", "variantId": "b", "fetchStatus": "published", "artifact": {"verifiedRemote": True}}]}]}
        result = harvest.coverage(queue)
        self.assertEqual(result["selectedVersionTasks"], 2)
        self.assertEqual(result["pendingSelectedVersionTasks"], 0)
        self.assertEqual(result["publishedVersionRecords"], 1)
        self.assertEqual(result["remoteReadbackVerifiedVersionRecords"], 1)
        queue["packages"][0]["versions"][1]["fetchStatus"] = "pending"
        queue["packages"][0]["versions"][1]["artifact"] = None
        result = harvest.coverage(queue)
        self.assertEqual(result["selectedVersionTasks"], 2)
        self.assertEqual(result["completedSelectedVersionTasks"], 1)
        self.assertEqual(result["pendingSelectedVersionTasks"], 1)
        queue["packages"][0]["versions"].pop()
        result = harvest.coverage(queue)
        self.assertEqual(result["selectedVersionTasks"], 1)
        self.assertEqual(result["completedSelectedVersionTasks"], 1)
        self.assertEqual(result["pendingSelectedVersionTasks"], 0)

    def test_publication_failure_preserves_successful_collection(self):
        data = tar_bytes({"p/LICENSE": MIT, "p/A.cs": b"class A{}"})
        version = {"version": "1.0", "variantId": "x", "downloadUrl": "https://example.invalid/a"}
        def failing_publisher(data, record):
            raise RuntimeError("private temporary path should not be persisted")
        with patch.object(sources, "request_bytes", return_value=data):
            result = harvest.collect_version({"id": "test"}, version, publish=failing_publisher)
        self.assertEqual(result["fetchStatus"], "collected")
        self.assertEqual(result["publicationStatus"], "failed")
        self.assertFalse(result["artifact"]["verifiedRemote"])
        self.assertNotIn("private temporary path", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
