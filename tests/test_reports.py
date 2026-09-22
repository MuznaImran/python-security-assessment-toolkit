"""Tests for JSON, CSV, and plain-text finding exports."""

import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cybersec_toolkit.logs import analyze_auth_log
from cybersec_toolkit.reports import export_report, write_csv, write_json, write_text


def example_findings():
    text = "\n".join(
        f"2026-09-20T09:00:{second:02d}Z sshd[1]: Failed password for alice from 203.0.113.44 port 22 ssh2"
        for second in range(5)
    )
    return analyze_auth_log(text)


class ReportTests(unittest.TestCase):
    def test_json_round_trip_has_iso_timestamps_and_count(self) -> None:
        with TemporaryDirectory() as folder:
            path = write_json(example_findings(), Path(folder) / "findings.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["finding_count"], 1)
            self.assertEqual(payload["findings"][0]["source_ip"], "203.0.113.44")
            self.assertEqual(payload["findings"][0]["evidence_lines"], [1, 2, 3, 4, 5])
            self.assertTrue(payload["findings"][0]["first_seen"].endswith("+00:00"))

    def test_csv_quotes_and_round_trips_fields(self) -> None:
        with TemporaryDirectory() as folder:
            path = write_csv(example_findings(), Path(folder) / "findings.csv")
            with path.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["failure_count"], "5")
            self.assertEqual(rows[0]["usernames"], "alice")
            self.assertIn("T1110", rows[0]["attack_mapping"])

    def test_text_is_readable_and_empty_report_is_valid(self) -> None:
        with TemporaryDirectory() as folder:
            path = write_text(example_findings(), Path(folder) / "findings.txt")
            text = path.read_text(encoding="utf-8")
            self.assertIn("Severity: medium", text)
            self.assertIn("Source IP: 203.0.113.44", text)
            self.assertIn("Evidence lines: 1, 2, 3, 4, 5", text)

            empty = write_json([], Path(folder) / "empty.json")
            self.assertEqual(json.loads(empty.read_text(encoding="utf-8"))["finding_count"], 0)

    def test_dispatch_rejects_unknown_extension(self) -> None:
        with TemporaryDirectory() as folder:
            path = export_report(example_findings(), Path(folder) / "report.CSV")
            self.assertEqual(path.suffix, ".CSV")
            with self.assertRaises(ValueError):
                export_report([], Path(folder) / "report.html")

    def test_generic_records_keep_all_fields_in_csv_and_text(self) -> None:
        records = [{"target": "localhost", "ports": [80, 443], "ok": True}]
        with TemporaryDirectory() as folder:
            csv_path = write_csv(records, Path(folder) / "network.csv")
            with csv_path.open(encoding="utf-8", newline="") as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row["target"], "localhost")
            self.assertEqual(row["ports"], "80; 443")
            self.assertEqual(row["ok"], "True")

            text = write_text(records, Path(folder) / "network.txt").read_text(
                encoding="utf-8"
            )
            self.assertIn("Target: localhost", text)
            self.assertIn("Ports: 80, 443", text)

    def test_csv_neutralizes_spreadsheet_formulas(self) -> None:
        records = [
            {
                "title": "=HYPERLINK(\"https://invalid.example\")",
                "values": ["+SUM(1,1)", "safe"],
            }
        ]
        with TemporaryDirectory() as folder:
            path = write_csv(records, Path(folder) / "safe.csv")
            with path.open(encoding="utf-8", newline="") as stream:
                row = next(csv.DictReader(stream))
            self.assertTrue(row["title"].startswith("'="))
            self.assertTrue(row["values"].startswith("'+"))


if __name__ == "__main__":
    unittest.main()
