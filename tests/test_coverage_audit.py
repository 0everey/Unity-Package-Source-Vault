import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uvault.coverage_audit import audit_panel


def version(number="1.0.0", status="collected", disposition="mirror-allowed", variant="upstream", **extra):
    row = {"version": number, "variantId": variant, "fetchStatus": status, "disposition": disposition,
           "artifact": {"sha256": "a" * 64, "size": 100},
           "license": {"expression": "MIT", "sha256": "b" * 64, "evidenceUrl": "https://example.test/LICENSE"}}
    row.update(extra)
    return row


def catalog(*packages, commit="c" * 40):
    return {"schemaVersion": "1.0", "catalogCommit": commit, "packages": list(packages)}


def package(identifier="com.example.runtime", versions=None, **extra):
    return {"id": identifier, "versions": [version()] if versions is None else versions, **extra}


def project(dependencies=None, locked=None, repository="example/game", cohort="diagnostic", **extra):
    files = [{"path": "ProjectSettings/ProjectVersion.txt", "metadata": "m_EditorVersion: 2022.3.10f1"},
             {"path": "Packages/manifest.json", "metadata": {"dependencies": dependencies or {}}}]
    if locked is None:
        files.append({"path": "Packages/packages-lock.json", "status": "unavailable"})
    else:
        files.append({"path": "Packages/packages-lock.json", "metadata": {"dependencies": locked}})
    return {"repository": repository, "projectPath": "", "sourceRef": "d" * 40,
            "sourceStatus": "metadata-observed", "cohortRole": cohort, "files": files, **extra}


def audit(sample, data):
    return audit_panel({"kind": "public-project-diagnostic-metadata-not-market-sample", "projects": [sample]}, data)


class CoverageAuditTests(unittest.TestCase):
    def setUp(self):
        self.network = patch("urllib.request.urlopen", side_effect=AssertionError("audit unit test attempted network"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def test_baseline_current_record_gain_preserves_known_missing_version(self):
        sample = project({"com.example.runtime": "2.0.0", "com.example.missing": "1.0.0"})
        baseline = catalog(package(versions=[version("1.0.0")]))
        current = catalog(package(versions=[version("1.0.0"), version("2.0.0")]))
        before, after = audit(sample, baseline), audit(sample, current)
        old = before["projects"][0]["declarations"][-1]
        self.assertEqual(old["catalogStatus"], "known-id-missing-exact-version")
        self.assertEqual(old["missingExactVersions"], ["2.0.0"])
        self.assertEqual(before["summary"]["metrics"]["declaredIdsRegistered"], {"numerator": 1, "denominator": 2, "ratio": .5})
        self.assertEqual(before["summary"]["metrics"]["exactObservedVersionsRecorded"]["numerator"], 0)
        self.assertEqual(after["summary"]["metrics"]["exactObservedVersionsRecorded"]["numerator"], 1)
        self.assertEqual(after["summary"]["metrics"]["exactObservedVersionsAcquired"]["numerator"], 1)
        self.assertEqual(before["panelContentSha256"], after["panelContentSha256"])

    def test_zero_denominator_and_unavailable_project_are_explicit(self):
        unavailable = {"repository": "example/unavailable", "projectPath": "", "cohortRole": "held-out",
                       "sourceStatus": "metadata-unavailable", "files": [], "error": "file:/private-fixture/error"}
        result = audit(unavailable, catalog())
        self.assertEqual(result["summary"]["counts"]["projects"], 1)
        self.assertEqual(result["summary"]["counts"]["metadataUnavailableProjects"], 1)
        self.assertIsNone(result["summary"]["metrics"]["observedIdsRegistered"]["ratio"])
        self.assertIsNone(result["summary"]["completeRuntimeDependencyCoverage"]["ratio"])
        self.assertEqual(result["projects"][0]["metadataAvailability"], "metadata-unavailable")
        objects = result["projects"][0]["unknownObjects"]
        self.assertEqual({x["object"] for x in objects if x["kind"] == "metadata-unavailable"}, {"manifest", "lock"})
        self.assertTrue(any(x["kind"] == "runtime-consumer-inventory-unavailable" for x in objects))
        self.assertNotIn("private-fixture", json.dumps(result))
        empty = audit_panel({"projects": []}, catalog())
        self.assertEqual(empty["summary"]["counts"]["projects"], 0)
        self.assertTrue(all(m["ratio"] is None for m in empty["summary"]["metrics"].values()))

    def test_references_and_unhashed_status_do_not_count_as_acquired(self):
        sample = project({"com.ref": "1.0.0", "com.bytes": "1.0.0", "com.unhashed": "1.0.0"}, locked={})
        data = catalog(package("com.ref", [version(status="reference-only", disposition="official-fetch-only", artifact=None)]),
                       package("com.bytes"), package("com.unhashed", [version(artifact=None)]))
        result = audit(sample, data)
        metrics = result["summary"]["metrics"]
        self.assertEqual(metrics["exactObservedVersionsRecorded"]["numerator"], 3)
        self.assertEqual(metrics["exactObservedVersionsAcquired"]["numerator"], 1)
        self.assertEqual(metrics["exactObservedVersionsReferenceOnly"]["numerator"], 1)
        record = next(r for r in result["projects"][0]["declarations"] if r["packageId"] == "com.ref")["exactVersionObservations"][0]["records"][0]
        self.assertEqual(record["disposition"], "official-fetch-only")
        self.assertFalse(record["catalogReportedAcquired"])

    def test_builtin_reference_cannot_be_promoted_by_a_spurious_artifact(self):
        result = audit(project({"com.unity.modules.audio": "1.0.0"}),
                       catalog(package("com.unity.modules.audio", [version(status="published", disposition="builtin-reference")])))
        self.assertEqual(result["summary"]["metrics"]["exactObservedVersionsAcquired"]["numerator"], 0)
        self.assertEqual(result["summary"]["strata"]["default-builtin"]["declarations"], 1)
        self.assertIsNone(result["summary"]["completeRuntimeDependencyCoverage"]["denominator"])

    def test_manifest_lock_git_registry_conflict_keeps_both_observations(self):
        identifier = "com.unity.2d.tilemap.extras"
        spec = "https://github.com/Unity-Technologies/2d-extras.git#package_6000.3"
        sample = project({identifier: spec}, {identifier: {"version": "6.0.1", "source": "registry", "url": "https://packages.unity.com", "depth": 0}})
        result = audit(sample, catalog(package(identifier, [version("6.0.1")])))
        row = result["projects"][0]["declarations"][0]
        self.assertEqual(row["manifest"]["value"], spec)
        self.assertEqual(row["manifest"]["kind"], "git")
        self.assertEqual(row["lock"]["exactVersion"], "6.0.1")
        self.assertEqual(row["sourceConflicts"][0]["kind"], "manifest-lock-source-conflict")
        self.assertEqual(row["exactVersionObservations"][0]["origins"], ["lock"])
        self.assertFalse(row["exactVersionObservations"][0]["sourceRequirementVerified"])
        self.assertFalse(row["targetSourceEqualityVerified"])

    def test_git_commit_does_not_establish_fork_or_target_equivalence(self):
        spec = "https://github.com/example/private-fork.git?path=/Runtime#feature"
        sample = project({"com.example.runtime": spec}, {"com.example.runtime": {"version": spec, "source": "git", "hash": "a" * 40}})
        source = version(sourceUrl="https://github.com/upstream/library", sourceRef="a" * 40, sourcePath="Runtime")
        result = audit(sample, catalog(package(versions=[source])))
        row = result["projects"][0]["declarations"][0]
        self.assertEqual(row["lock"]["fixedCommit"], "a" * 40)
        self.assertEqual(row["lock"]["packagePath"], "Runtime")
        self.assertEqual(row["exactVersionObservations"], [])
        candidate = row["gitCatalogCandidates"][0]
        self.assertTrue(candidate["sameCommitRecorded"])
        self.assertFalse(candidate["sameRepositoryRecorded"])
        self.assertFalse(candidate["targetOrForkEquivalenceVerified"])

    def test_same_repository_commit_is_still_only_metadata_alignment(self):
        spec = "https://github.com/example/library.git?path=Runtime#" + "a" * 40
        sample = project({"com.example.runtime": spec}, {"com.example.runtime": {"version": spec, "source": "git", "hash": "a" * 40}})
        source = version(sourceUrl="https://github.com/example/library", sourceRef="a" * 40, sourcePath="Runtime")
        row = audit(sample, catalog(package(versions=[source])))["projects"][0]["declarations"][0]
        candidate = row["gitCatalogCandidates"][0]
        self.assertTrue(candidate["sameRepositoryRecorded"] and candidate["sameSubpathRecorded"])
        self.assertFalse(candidate["targetOrForkEquivalenceVerified"])
        self.assertIn("git-content-and-fork-equivalence-unverified", row["unknowns"])

    def test_numeric_git_lock_is_not_a_registry_exact_version(self):
        sample = project({}, {"com.example.runtime": {"version": "1.0.0", "source": "git", "hash": "a" * 40}})
        row = audit(sample, catalog(package()))["projects"][0]["declarations"][0]
        self.assertEqual(row["lock"]["kind"], "git")
        self.assertEqual(row["exactVersionObservations"], [])

    def test_missing_lock_source_is_unknown_not_a_proved_git_registry_conflict(self):
        spec = "https://github.com/example/library.git#feature"
        sample = project({"com.example.runtime": spec}, {"com.example.runtime": {"version": "1.0.0", "hash": "short-observed-hash"}})
        row = audit(sample, catalog(package()))["projects"][0]["declarations"][0]
        self.assertEqual(row["lock"]["kind"], "unknown")
        self.assertIsNone(row["lock"]["declaredSource"])
        self.assertEqual(row["lock"]["observedHash"], "short-observed-hash")
        self.assertIsNone(row["lock"]["fixedCommit"])
        self.assertFalse(row["sourceConflicts"])
        self.assertFalse(row["exactVersionObservations"][0]["sourceRequirementVerified"])

    def test_git_ssh_repository_normalization_and_duplicate_alignment(self):
        sha = "a" * 40
        spec = "git@github.com:example/library.git?path=Runtime#" + sha
        sample = project({"com.example.runtime": spec}, {"com.example.runtime": {"version": spec, "source": "git", "hash": sha}})
        source = version(sourceUrl="https://github.com/example/library", sourceRef=sha, sourcePath="Runtime")
        row = audit(sample, catalog(package(versions=[source])))["projects"][0]["declarations"][0]
        self.assertEqual(row["manifest"]["repository"], "https://github.com/example/library")
        self.assertEqual(len(row["gitCatalogCandidates"]), 1)
        self.assertTrue(row["gitCatalogCandidates"][0]["sameRepositoryRecorded"])
        self.assertFalse(row["gitCatalogCandidates"][0]["targetOrForkEquivalenceVerified"])

    def test_file_specs_and_paths_are_hashes_never_reported_verbatim(self):
        secret = "file:C:/private-fixture/local-plugin"
        sample = project({"com.local": secret}, {"com.local": {"version": secret, "source": "embedded", "depth": 0}})
        result = audit(sample, catalog(package("com.local")))
        row = result["projects"][0]["declarations"][0]
        self.assertNotIn("private-fixture", json.dumps(result))
        self.assertEqual(row["manifest"]["kind"], "file")
        self.assertIsNone(row["manifest"]["value"])
        self.assertEqual(len(row["manifest"]["specSha256"]), 64)
        self.assertFalse(row["targetSourceEqualityVerified"])

    def test_variant_records_are_reported_without_silent_selection(self):
        sample = project({"com.example.runtime": "1.0.0"}, {"com.example.runtime": {"version": "1.0.0", "source": "registry"}})
        result = audit(sample, catalog(package(versions=[version(variant="a"), version(variant="b")])) )
        observation = result["projects"][0]["declarations"][0]["exactVersionObservations"][0]
        self.assertEqual(observation["origins"], ["manifest", "lock"])
        self.assertEqual(observation["variantStatus"], "ambiguous-catalog-variants")
        self.assertEqual(len(observation["records"]), 2)
        self.assertEqual(result["summary"]["metrics"]["exactObservedVersionsRecorded"]["denominator"], 1)
        self.assertTrue(all(not r["targetVariantVerified"] for r in observation["records"]))

    def test_version_difference_is_not_silently_replaced_by_lock(self):
        sample = project({"com.example.runtime": "1.0.0"}, {"com.example.runtime": {"version": "2.0.0", "source": "registry"}})
        row = audit(sample, catalog(package(versions=[version("2.0.0")])))["projects"][0]["declarations"][0]
        self.assertEqual([v["version"] for v in row["exactVersionObservations"]], ["1.0.0", "2.0.0"])
        self.assertEqual(row["missingExactVersions"], ["1.0.0"])
        self.assertEqual(row["sourceConflicts"][0]["kind"], "manifest-lock-version-difference")

    def test_purpose_annotations_do_not_make_a_runtime_denominator(self):
        sample = project({"com.runtime": "1.0.0", "com.editor": "1.0.0", "com.test": "1.0.0", "com.unity.test-framework": "1.0.0"},
                         dependencyRoles={name: {"role": role, "evidenceRefs": ["explicit-purpose-note"]}
                                          for name, role in (("com.runtime", "Runtime"), ("com.editor", "Editor"), ("com.test", "Test"))})
        sample["files"][1]["metadata"]["testables"] = ["com.unity.test-framework"]
        result = audit(sample, catalog())
        for role in ("Runtime", "Editor", "Test", "unknown"):
            self.assertEqual(result["summary"]["strata"][role]["declarations"], 1)
        self.assertIsNone(result["summary"]["completeRuntimeDependencyCoverage"]["ratio"])

    def test_held_out_known_diagnostic_and_inputs_are_preserved(self):
        projects = [project({"com.example.runtime": "1.0.0"}, repository="example/diagnostic"),
                    project({"com.example.runtime": "1.0.0"}, repository="example/known", cohort="diagnostic-known-evidence"),
                    project({"com.example.runtime": "1.0.0"}, repository="example/held-out", cohort="held-out")]
        panel, data = {"projects": projects}, catalog(package())
        saved_panel, saved_catalog = copy.deepcopy(panel), copy.deepcopy(data)
        result = audit_panel(panel, data)
        self.assertEqual(panel, saved_panel)
        self.assertEqual(data, saved_catalog)
        self.assertEqual([p["cohortRole"] for p in result["projects"]], [p["cohortRole"] for p in panel["projects"]])
        self.assertEqual(result["summary"]["cohortGroupCounts"], {"diagnostic": 2, "held-out": 1})
        self.assertEqual(result["summary"]["cohortRoleCounts"]["diagnostic-known-evidence"], 1)

    def test_unexpanded_or_duplicate_catalogs_are_rejected(self):
        with self.assertRaises(ValueError):
            audit(project(), {"packages": [{"id": "com.example.runtime", "path": "packages/x.json"}]})
        with self.assertRaises(ValueError):
            audit(project(), catalog(package(), package()))

    def test_same_repository_different_paths_cannot_hide_cohort_overlap(self):
        diagnostic = project(repository="example/shared", projectPath="GameA/", cohort="diagnostic-known-evidence")
        held_out = project(repository="example/shared", projectPath="GameB/", cohort="held-out")
        panel = {"projects": [diagnostic, held_out]}
        before = copy.deepcopy(panel)
        result = audit_panel(panel, catalog())
        self.assertEqual(panel, before)
        self.assertEqual(result["summary"]["cohortRoleCounts"], {"diagnostic-known-evidence": 1, "held-out": 1})
        self.assertEqual(len(result["summary"]["cohortRepositoryOverlaps"]), 1)
        self.assertTrue(all(any(x["kind"] == "same-repository-diagnostic-held-out-overlap" for x in p["unknownObjects"]) for p in result["projects"]))

    def test_script_compares_same_input_and_refuses_existing_output(self):
        path = Path(__file__).resolve().parents[1] / "scripts" / "audit_coverage_panel.py"
        spec = importlib.util.spec_from_file_location("coverage_panel_script_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        baseline, current = catalog(package(versions=[]), commit="a" * 40), catalog(package(), commit="b" * 40)
        with tempfile.TemporaryDirectory(prefix="uvault-audit-unit-") as directory:
            panel_path, output = Path(directory) / "panel.json", Path(directory) / "result.json"
            panel_path.write_text(json.dumps({"projects": [project({"com.example.runtime": "1.0.0"})]}), encoding="utf-8")
            args = ["--panel", str(panel_path), "--registry", "current-catalog", "--baseline-registry", "fixed-baseline", "--out", str(output)]
            with patch.object(module, "load_registry", side_effect=[baseline, current]) as load, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(module.main(args), 0)
            self.assertEqual([call.args[0] for call in load.call_args_list], ["fixed-baseline", "current-catalog"])
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(result["samePanelContent"])
            self.assertEqual(result["metricComparison"]["exactObservedVersionsAcquired"]["numeratorChange"], 1)
            self.assertIsNone(result["completeRuntimeDependencyCoverage"]["currentRatio"])
            original = output.read_bytes()
            with patch.object(module, "load_registry", side_effect=AssertionError("existing output triggered read")), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(module.main(args), 2)
            self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
