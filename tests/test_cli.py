import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from uvault.cli import main
from uvault.resolve import resolve


def matches():
    return {"schemaVersion": "1.0", "catalogCommit": "a" * 40, "input": {"kind": "lock"}, "profile": None,
            "matches": [{"packageId": "test.pkg", "status": "candidate", "evidence": [{"kind": "lock"}],
                         "candidates": [{"packageId": "test.pkg", "version": version, "variantId": "upstream", "disposition": "license-unresolved"} for version in ("1.0", "2.0")],
                         "suggestedReuseScope": ["inspect"], "skipNativeRecovery": False}], "unknown": [], "conflicts": []}


class CliTests(unittest.TestCase):
    def invoke(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main(args)
        return code, output.getvalue(), errors.getvalue()

    def test_ambiguous_never_selects_latest(self):
        lock = resolve(matches())
        self.assertEqual(lock["libraries"], [])
        self.assertEqual(lock["unresolved"][0]["reason"], "ambiguous-candidates")
        lock = resolve(matches(), [{"packageId": "test.pkg", "version": "1.0", "variantId": "upstream"}])
        self.assertEqual(lock["libraries"][0]["version"], "1.0")
        self.assertEqual(lock["libraries"][0]["status"], "candidate")
        self.assertEqual(lock["libraries"][0]["evidence"], [{"kind": "lock"}])
        self.assertFalse(lock["libraries"][0]["skipNativeRecovery"])

    def test_variant_ambiguity_requires_selection(self):
        value = matches()
        value["matches"][0]["candidates"][1].update(version="1.0", variantId="modified")
        self.assertFalse(resolve(value)["libraries"])

    def test_unresolved_is_written_and_exit_three(self):
        with tempfile.TemporaryDirectory() as temp:
            input_path, output_path = Path(temp) / "matches.json", Path(temp) / "lock.json"
            input_path.write_text(json.dumps(matches()), encoding="utf-8")
            code, output, errors = self.invoke(["resolve", "--matches", str(input_path), "--out", str(output_path)])
            self.assertEqual(code, 3, errors)
            self.assertTrue(json.loads(output)["unresolved"])
            self.assertTrue(output_path.exists())
            code, _, errors = self.invoke(["resolve", "--matches", str(input_path), "--out", str(output_path)])
            self.assertEqual(code, 2)
            self.assertIn("error", json.loads(errors))

    def test_bad_selections_are_json_failure(self):
        code, _, errors = self.invoke(["resolve", "--matches", "unused", "--out", "unused", "--package", "test.pkg"])
        self.assertEqual(code, 2)
        self.assertIn("corresponding", json.loads(errors)["error"])

    def test_help_all_commands(self):
        for command in ([], ["catalog"], ["catalog", "sync"], ["identify"], ["resolve"], ["materialize"], ["export-remaker"]):
            with self.subTest(command=command), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    main(command + ["--help"])
                self.assertEqual(result.exception.code, 0)

    def test_invalid_command_json_stderr(self):
        with contextlib.redirect_stderr(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as result:
                main(["nonesuch"])
        self.assertEqual(result.exception.code, 2)
        self.assertIn("error", json.loads(output.getvalue()))


if __name__ == "__main__":
    unittest.main()
