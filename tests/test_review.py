import json
import tempfile
import unittest
from pathlib import Path

from shrike.checks import inspect
from shrike.cli import main


class ReviewTests(unittest.TestCase):
    def test_flags_explicit_settings_through_import_aliases(self):
        source = b"""
import yaml as y
from subprocess import run as launch
import requests as web
launch(arguments, shell=True)
y.load(config, Loader=y.UnsafeLoader)
web.get(url, verify=False)
launch(arguments)
y.safe_load(config)
web.get(url, verify=True)
"""
        findings = inspect(source, "app.py")
        self.assertEqual([item.rule.id for item in findings], ["SHR001", "SHR002", "SHR003"])
        shifted = inspect(b"\n" + source, "app.py")
        self.assertEqual([item.fingerprint for item in findings], [item.fingerprint for item in shifted])

    def test_cli_reports_and_fails_closed_on_partial_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / ".shrike"
            source = root / "app #1.py"
            source.write_text("import subprocess\nsubprocess.run(args, shell=True)\n", encoding="utf-8")
            args = ["--target", folder, "--output", str(output)]
            self.assertEqual(main(args), 2)
            sarif = json.loads((output / "findings.sarif").read_text(encoding="utf-8"))
            location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            self.assertEqual(location["artifactLocation"]["uri"], "app%20%231.py")

            (root / "broken.py").write_text("def broken(", encoding="utf-8")
            self.assertEqual(main(args), 1)
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(report["issues"][0]["path"], "broken.py")
            self.assertEqual(len(report["findings"]), 1)

            (root / "broken.py").write_text("# fixed\n", encoding="utf-8")
            source.write_text("import subprocess\nsubprocess.run(args)\n", encoding="utf-8")
            self.assertEqual(main(args), 0)
