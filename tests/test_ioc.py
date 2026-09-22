"""Local indicator-list tests with no external provider calls."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cybersec_toolkit.ioc import (
    classify_indicator,
    load_denylist,
    lookup_abuseipdb,
    lookup_local,
    lookup_virustotal,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class IndicatorTests(unittest.TestCase):
    def test_classification_and_normalization(self):
        self.assertEqual(classify_indicator("192.0.2.7"), ("ip", "192.0.2.7"))
        self.assertEqual(classify_indicator("2001:0DB8::1"), ("ip", "2001:db8::1"))
        self.assertEqual(classify_indicator("Example.ORG"), ("domain", "example.org"))
        self.assertEqual(classify_indicator("A" * 64), ("sha256", "a" * 64))
        self.assertEqual(
            classify_indicator("HTTPS://Example.ORG/login?q=1"),
            ("url", "https://example.org/login?q=1"),
        )

    def test_rejects_malformed_indicators(self):
        for indicator in ("", " example.org", "ftp://example.org", "https://user:pass@example.org", "bad_domain.org", "-bad.org", "oneword", "f" * 63):
            with self.subTest(indicator=indicator), self.assertRaises(ValueError):
                classify_indicator(indicator)

    def test_local_match_and_absence_have_careful_interpretations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "list.json"
            path.write_text(json.dumps({"indicators": [
                {"value": "EXAMPLE.org", "source": "analyst sample", "note": "test record"},
                {"value": "192.0.2.10"},
            ]}), encoding="utf-8")
            self.assertEqual(len(load_denylist(path)), 2)
            listed = lookup_local("example.org", path)
            self.assertEqual(listed["status"], "listed")
            self.assertEqual(listed["source"], "analyst sample")
            self.assertIn("verify", listed["interpretation"])
            absent = lookup_local("example.net", path)
            self.assertEqual(absent["status"], "not_listed")
            self.assertIn("does not mean", absent["interpretation"])

    def test_invalid_list_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "list.json"
            for document in ([], {"indicators": "bad"}, {"indicators": [{}]}, {"indicators": [{"value": "example.org", "source": 5}]}):
                with self.subTest(document=document):
                    path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_denylist(path)

    @patch("cybersec_toolkit.ioc.urlopen")
    def test_virustotal_lookup_uses_header_and_summarizes(self, mocked):
        mocked.return_value = FakeResponse(
            {"data": {"attributes": {"reputation": -2, "last_analysis_stats": {"malicious": 3}}}}
        )
        result = lookup_virustotal("203.0.113.42", "secret-key")
        request = mocked.call_args.args[0]
        self.assertEqual(request.headers["X-apikey"], "secret-key")
        self.assertNotIn("secret-key", request.full_url)
        self.assertEqual(result["last_analysis_stats"]["malicious"], 3)
        self.assertNotIn("secret-key", repr(result))
        lookup_virustotal("https://example.org/path", "secret-key")
        self.assertIn("/api/v3/urls/", mocked.call_args.args[0].full_url)

    @patch("cybersec_toolkit.ioc.urlopen")
    def test_abuseipdb_accepts_only_ip_and_uses_header(self, mocked):
        mocked.return_value = FakeResponse(
            {"data": {"abuseConfidenceScore": 18, "totalReports": 2, "countryCode": "ZZ"}}
        )
        result = lookup_abuseipdb("203.0.113.42", "secret-key", max_age_days=30)
        request = mocked.call_args.args[0]
        self.assertEqual(request.headers["Key"], "secret-key")
        self.assertIn("maxAgeInDays=30", request.full_url)
        self.assertEqual(result["abuse_confidence_score"], 18)
        with self.assertRaises(ValueError):
            lookup_abuseipdb("example.org", "secret-key")


if __name__ == "__main__":
    unittest.main()
