import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uvault import curated, harvest, pipeline, sources


def versions(*names):
    return [{"version": name, "variantId": "test", "dependencies": {}} for name in names]


class CuratedTests(unittest.TestCase):
    def test_default_whitelist_has_no_ecosystem_discovery(self):
        with patch("uvault.sources.discover_openupm", side_effect=AssertionError("ecosystem crawl")):
            state = harvest.discover()
        self.assertEqual(state["scopeVersion"], "R4")
        self.assertEqual(len(state["packages"]), 73)
        builtin = [p for p in state["packages"] if p.get("family") == "unity-builtin"]
        self.assertEqual(len(builtin), 23)
        self.assertTrue(all(p["metadataStatus"] == "reference-only" and not p["selectedVersions"] for p in builtin))

    def test_retired_queue_projects_to_common_versions(self):
        seed = curated.seeds()[0]
        old = {**seed, "metadataStatus": "complete", "versions": versions("1.0.0", "1.11.0", "1.12.0", "1.13.0", "2.0.0")}
        result = curated.queue({"packages": [old, {"id": "cold.package"}]})
        package = next(p for p in result["packages"] if p["id"] == old["id"])
        self.assertEqual({v["version"] for v in package["versions"]}, {"1.12.0", "1.13.0"})
        self.assertNotIn("cold.package", [p["id"] for p in result["packages"]])

    def test_real_gap_is_preserved_and_budgeted(self):
        state = curated.queue()
        p = curated.add_gap(state, "com.unity.inputsystem", "0.9.0", "Observed consumer lock")
        chosen = curated.curate_package({"versions": versions("0.9.0", "1.12.0", "1.13.0")}, p)
        self.assertIn("0.9.0", chosen["selectedVersions"])
        with self.assertRaises(ValueError):
            curated.add_gap(state, "cold.package", "1.0.0", "")

    def test_three_explicit_versions_do_not_add_a_fourth_optional_neighbor(self):
        policy={"preferredVersions":["1.12.0"],"versionCount":2,"maxCommonVersions":3}
        requests=[{"version":"0.9.0","reason":"consumer A"},{"version":"0.8.0","reason":"consumer B"}]
        chosen=curated.choose_versions(versions("0.8.0","0.9.0","1.12.0","1.13.0"),policy,requests)
        self.assertEqual({v["version"] for v in chosen},{"0.8.0","0.9.0","1.12.0"})

    def test_consumer_gap_survives_failed_and_pending_projection(self):
        for status in ("pending","failed","complete"):
            state=curated.queue()
            p=curated.add_gap(state,"com.unity.inputsystem","0.9.0","Actual locked consumer")
            p["metadataStatus"]=status
            p["versions"]=versions("0.9.0","1.12.0")
            p["versions"][0]["artifact"]={"sha256":"a"*64}
            p["versions"][0]["fetchStatus"]="published"
            current=curated.queue(state)
            result=next(item for item in current["packages"] if item["id"]==p["id"])
            self.assertEqual(result["explicitVersionRequests"],p["explicitVersionRequests"])
            self.assertEqual(result["metadataStatus"],status)
            self.assertEqual(result["versions"][0]["artifact"]["sha256"],"a"*64)

    def test_worker_metadata_does_not_add_dependency_tasks_or_old_versions(self):
        seed = curated.seeds()[0]
        seed["versions"] = versions("0.1.0", "0.2.0", "0.3.0", "1.12.0")
        state = {"scopeVersion": "R4", "packages": [seed], "frontier": []}
        upstream = {"id": seed["id"], "metadataStatus": "complete", "versions": versions("1.12.0", "1.13.0")}
        upstream["versions"][0]["dependencies"] = {"cold.package": "1.0.0"}
        with tempfile.TemporaryDirectory() as directory, patch("uvault.sources.fetch_package", return_value=upstream):
            pipeline.metadata(state, Path(directory), workers=1)
        self.assertEqual(len(state["packages"]), 1)
        self.assertEqual(seed["selectedVersions"], ["1.12.0", "1.13.0"])
        self.assertEqual(len(seed["versions"]), 2)
        self.assertEqual(state["frontier"][0]["status"], "explicit-consumer-gap-if-needed")

    def test_collector_keeps_explicit_third_common_version(self):
        p = {"id": "test", "metadataStatus": "complete", "curatedPolicy": {"versionCount": 2},
             "versions": versions("1.0.0", "1.1.0", "2.0.0"), "selectedVersions": ["1.0.0", "1.1.0", "2.0.0"]}
        with patch("uvault.harvest.collect_version", side_effect=lambda p,v,**kw: {**v,"fetchStatus":"collected"}) as collect:
            harvest.collect_selected({"packages": [p]})
        self.assertEqual(collect.call_count, 3)

    def test_pinned_official_manifest_is_a_reference_not_an_archive_task(self):
        ref={"repository":"Unity-Technologies/Graphics","sourceRef":"a"*40,"path":"Packages/com.unity.test/package.json","version":"17.0.4"}
        seed={"id":"com.unity.test","adapter":"registry","registry":"https://packages.unity.com","manifestReferences":[ref]}
        with patch("uvault.sources.registry_package",side_effect=sources.SourceError("not listed",status=404)), patch("uvault.sources.request_bytes",return_value=b'{"name":"com.unity.test","version":"17.0.4"}'):
            package=sources.fetch_package(seed)
        version=package["versions"][0]
        self.assertIsNone(version["artifact"])
        self.assertEqual(version["fetchStatus"],"reference-only")
        package["selectedVersions"]=["17.0.4"]
        self.assertEqual(harvest.coverage({"packages":[package]})["selectedVersionTasks"],0)
        with patch("uvault.harvest.collect_version",side_effect=AssertionError("reference fetched")):
            harvest.collect_selected({"packages":[package]})

    def test_wrong_pinned_manifest_identity_is_rejected(self):
        seed={"id":"com.unity.test","adapter":"registry","registry":"https://packages.unity.com",
              "manifestReferences":[{"repository":"Unity-Technologies/Graphics","sourceRef":"a"*40,"path":"package.json","version":"17.0.4"}]}
        with patch("uvault.sources.registry_package",return_value={"sources":[],"versions":[]}), patch("uvault.sources.request_bytes",return_value=b'{"name":"other","version":"17.0.4"}'), self.assertRaises(ValueError):
            sources.fetch_package(seed)

    def test_retired_queue_is_rejected_by_default_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"catalog";root.mkdir()
            pipeline.save_index(root, {"packages":[],"scope":"retired"}, bundle=True)
            with self.assertRaises(SystemExit):
                pipeline.main(["--root", str(root), "--metadata"])
