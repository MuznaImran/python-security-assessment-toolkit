"""Tests for offline SSH authentication log analysis."""

from datetime import datetime, timezone
from pathlib import Path
import unittest

from cybersec_toolkit.logs import (
    analyze_auth_log,
    analyze_auth_log_file,
    detect_brute_force,
    parse_auth_log,
)


def line(second: int, ip: str = "203.0.113.44", username: str = "alice") -> str:
    return (
        f"2026-09-20T09:14:{second:02d}+05:00 host sshd[42]: "
        f"Failed password for {username} from {ip} port 51234 ssh2"
    )


class ParseAuthLogTests(unittest.TestCase):
    def test_parses_failures_successes_invalid_user_ipv6_and_utc(self) -> None:
        text = "\n".join(
            [
                "2026-09-20T04:00:00Z sshd[1]: Failed password for invalid user root from 2001:db8::1 port 22 ssh2",
                "2026-09-20T09:01:00+05:00 host sshd[2]: Accepted publickey for alice from 192.0.2.9 port 23 ssh2",
                "2026-09-20T09:01:00+05:00 host sshd[2]: Connection closed by authenticating user alice",
                "2026-09-20T09:01:00+05:00 host sshd[2]: Failed password for bob from not-an-ip port 23 ssh2",
                "2026-09-20T09:01:00 host sshd[2]: Failed password for bob from 192.0.2.9 port 23 ssh2",
            ]
        )
        events = parse_auth_log(text)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].source_ip, "2001:db8::1")
        self.assertEqual(events[0].username, "root")
        self.assertEqual(events[0].outcome, "failure")
        self.assertEqual(events[0].timestamp, datetime(2026, 9, 20, 4, 0, tzinfo=timezone.utc))
        self.assertEqual(events[1].outcome, "success")
        self.assertEqual(events[1].line_number, 2)

    def test_ignores_unrelated_lines(self) -> None:
        self.assertEqual(parse_auth_log("random text\n2026-09-20T04:00:00Z kernel: hello"), [])


class DetectBruteForceTests(unittest.TestCase):
    def test_detects_rolling_window_and_keeps_sources_separate(self) -> None:
        text = "\n".join(
            [
                line(0),
                line(10),
                line(20),
                line(30),
                line(40),
                line(50, "198.51.100.23"),
            ]
        )
        findings = analyze_auth_log(text, threshold=5, window_minutes=5)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.source_ip, "203.0.113.44")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.failure_count, 5)
        self.assertEqual(finding.evidence_lines, (1, 2, 3, 4, 5))
        self.assertIn("T1110", finding.attack_mapping)

    def test_requires_repeated_failures_within_actual_rolling_window(self) -> None:
        text = "\n".join(
            f"2026-09-20T09:{minute:02d}:00+05:00 host sshd[1]: Failed password for alice from 203.0.113.44 port 22 ssh2"
            for minute in (0, 4, 8, 12, 16)
        )
        self.assertEqual(analyze_auth_log(text, threshold=3, window_minutes=5), [])

    def test_one_finding_per_burst_and_severity_scales(self) -> None:
        first = [
            f"2026-09-20T09:00:{second:02d}Z sshd[1]: Failed password for alice from 203.0.113.44 port 22 ssh2"
            for second in range(10)
        ]
        second = [
            f"2026-09-20T09:30:{second:02d}Z sshd[1]: Failed password for bob from 203.0.113.44 port 22 ssh2"
            for second in range(20)
        ]
        findings = analyze_auth_log("\n".join(first + second), threshold=5)
        self.assertEqual(len(findings), 2)
        self.assertEqual([finding.severity for finding in findings], ["high", "critical"])
        self.assertEqual(findings[1].usernames, ("bob",))

    def test_successes_do_not_count_as_failures(self) -> None:
        failures = [line(second) for second in (0, 10, 20, 30)]
        success = "2026-09-20T09:14:40+05:00 sshd[1]: Accepted password for alice from 203.0.113.44 port 22 ssh2"
        self.assertEqual(analyze_auth_log("\n".join(failures + [success])), [])

    def test_invalid_parameters(self) -> None:
        with self.assertRaises(ValueError):
            detect_brute_force([], threshold=1)
        with self.assertRaises(ValueError):
            detect_brute_force([], window_minutes=0)

    def test_sample_file_has_documented_finding(self) -> None:
        sample = Path(__file__).resolve().parents[1] / "samples" / "sample_auth.log"
        findings = analyze_auth_log_file(sample)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source_ip, "203.0.113.44")


if __name__ == "__main__":
    unittest.main()
