"""Exercise the action adapter against the real compiled CLI."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import quote

BINARY = Path(sys.argv.pop(1)).resolve()
SCRIPT = Path(__file__).with_name("run.py")
SOURCE = "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"


class ActionContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name).resolve()
        (self.workspace / "app").mkdir()
        (self.workspace / "app/main.py").write_text(SOURCE)
        self.output = self.workspace / "command-output"

    def run_action(self, **overrides):
        self.output.write_text("")
        environment = dict(os.environ, GITHUB_WORKSPACE=str(self.workspace),
                           GITHUB_OUTPUT=str(self.output), SNOOT_BINARY=str(BINARY),
                           SNOOT_SCAN_PATH="app", SNOOT_SARIF="report.sarif",
                           SNOOT_FAIL_ON="high", SNOOT_UPLOAD="false",
                           SNOOT_CATEGORY="snoot", SNOOT_BASELINE="", SNOOT_EXCLUDE="")
        environment.update(overrides)
        result = subprocess.run([sys.executable, str(SCRIPT)], env=environment,
                                capture_output=True, text=True)
        outputs = dict(line.split("=", 1) for line in self.output.read_text().splitlines())
        return result, outputs

    def results(self):
        return json.loads((self.workspace / "report.sarif").read_text())["runs"][0]["results"]

    def test_gate_is_deferred_and_subdirectory_paths_are_rebased(self):
        result, outputs = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs["exit-code"], "2")
        self.assertEqual(outputs["finding-count"], "1")
        self.assertEqual(outputs["sarif"], str(self.workspace / "report.sarif"))
        self.assertEqual(self.results()[0]["locations"][0]["physicalLocation"]
                         ["artifactLocation"]["uri"], "app/main.py")

    def test_file_scan_path_and_uri_encoding(self):
        file = self.workspace / "app/key #é.py"
        file.write_text(SOURCE, encoding="utf-8")
        result, _ = self.run_action(SNOOT_SCAN_PATH="app/key #é.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.results()[0]["locations"][0]["physicalLocation"]
                         ["artifactLocation"]["uri"], "app/key%20%23%C3%A9.py")

    def test_inputs_with_shell_metacharacters_remain_literal(self):
        directory = self.workspace / "$(touch PWNED) `touch OWNED` space"
        directory.mkdir()
        (directory / "key.py").write_text(SOURCE)
        result, _ = self.run_action(SNOOT_SCAN_PATH=directory.name)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.workspace / "PWNED").exists())
        self.assertFalse((self.workspace / "OWNED").exists())
        self.assertEqual(self.results()[0]["locations"][0]["physicalLocation"]
                         ["artifactLocation"]["uri"], quote(directory.name + "/key.py", safe="-._~/"))

    def test_baseline_and_exclusion_suppress_the_gate(self):
        subprocess.run([str(BINARY), "init", str(self.workspace / "app"), "--output",
                        str(self.workspace / "baseline.json")], check=True, capture_output=True)
        for overrides in ({"SNOOT_BASELINE": "baseline.json"}, {"SNOOT_EXCLUDE": "*.py"}):
            result, outputs = self.run_action(**overrides)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(outputs["exit-code"], "0")
            self.assertEqual(outputs["finding-count"], "0")

    def test_empty_threshold_keeps_findings_without_gate(self):
        result, outputs = self.run_action(SNOOT_FAIL_ON="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs["exit-code"], "0")
        self.assertEqual(outputs["finding-count"], "1")

    def test_invalid_inputs_do_not_expose_a_stale_report(self):
        for overrides in ({"SNOOT_FAIL_ON": "HIGH"}, {"SNOOT_UPLOAD": "yes"},
                          {"SNOOT_SARIF": ""}, {"SNOOT_CATEGORY": "x\ny"},
                          {"SNOOT_SCAN_PATH": "missing"}, {"SNOOT_SCAN_PATH": ".."},
                          {"SNOOT_SARIF": "../outside.sarif"},
                          {"SNOOT_BASELINE": "missing.json"}, {"SNOOT_EXCLUDE": "["}):
            with self.subTest(overrides=overrides):
                (self.workspace / "report.sarif").write_text("stale report")
                result, outputs = self.run_action(**overrides)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(outputs, {"exit-code": "3"})
                self.assertEqual((self.workspace / "report.sarif").read_text(), "stale report")

    def test_bad_manifest_and_protected_source_outputs_fail(self):
        (self.workspace / "app/package.json").write_text("{bad json")
        result, outputs = self.run_action()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertNotIn("sarif", outputs)
        (self.workspace / "app/package.json").unlink()
        result, outputs = self.run_action(SNOOT_SARIF="app/main.py")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertNotIn("sarif", outputs)
        self.assertEqual((self.workspace / "app/main.py").read_text(), SOURCE)


if __name__ == "__main__":
    unittest.main()
