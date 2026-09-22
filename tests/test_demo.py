"""Integration test for the repository's guided offline demo."""

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class DemoIntegrationTests(unittest.TestCase):
    def test_demo_runs_outside_repo_and_writes_reviewable_artifacts(self) -> None:
        with TemporaryDirectory() as working, TemporaryDirectory() as output:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "demo.py"),
                    "--output-dir",
                    output,
                ],
                cwd=working,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            for marker in (
                "[1/5] Password hygiene",
                "[2/5] SHA-256 file integrity",
                "[3/5] Authentication-log triage",
                "[4/5] Local IOC comparison",
                "[5/5] Portable reports",
                "Network requests: none",
            ):
                self.assertIn(marker, completed.stdout)

            destination = Path(output)
            summary = json.loads(
                (destination / "demo_summary.json").read_text(encoding="utf-8")
            )
            report = json.loads(
                (destination / "authentication_findings.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(summary["offline"])
            self.assertFalse(summary["integrity"]["after_change_ok"])
            self.assertEqual(summary["ioc"]["status"], "listed")
            self.assertEqual(report["finding_count"], 1)
            self.assertEqual(report["findings"][0]["source_ip"], "203.0.113.44")


if __name__ == "__main__":
    unittest.main()
