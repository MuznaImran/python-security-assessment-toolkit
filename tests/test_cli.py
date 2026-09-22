import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cybersec_toolkit.cli import main


class CliTests(unittest.TestCase):
    def test_password_generate_returns_json(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["password", "generate", "--length", "16"])
        payload = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(payload["length"], 16)
        self.assertGreater(payload["estimated_pool_entropy_bits"], 90)

    def test_network_scan_requires_authorization_flag(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            status = main(["network", "scan", "127.0.0.1", "--ports", "80"])
        self.assertEqual(status, 2)
        self.assertIn("authorized=True", errors.getvalue())

    def test_log_analysis_exports_json(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "report.json"
            output = io.StringIO()
            with redirect_stdout(output):
                status = main(
                    [
                        "logs",
                        "analyze",
                        "samples/sample_auth.log",
                        "--output",
                        str(report),
                    ]
                )
            self.assertEqual(status, 0)
            self.assertTrue(report.exists())
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertGreaterEqual(payload["finding_count"], 1)

    def test_online_ioc_lookup_requires_explicit_transmission_flag(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            status = main(
                ["ioc", "lookup", "203.0.113.42", "--provider", "virustotal"]
            )
        self.assertEqual(status, 2)
        self.assertIn("add --online", errors.getvalue())

    def test_online_provider_failure_is_a_clean_cli_error(self):
        errors = io.StringIO()
        with patch(
            "cybersec_toolkit.cli.lookup_virustotal",
            side_effect=RuntimeError("provider unavailable"),
        ), redirect_stderr(errors):
            status = main(
                [
                    "ioc",
                    "lookup",
                    "example.org",
                    "--provider",
                    "virustotal",
                    "--online",
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(errors.getvalue(), "error: provider unavailable\n")


if __name__ == "__main__":
    unittest.main()
