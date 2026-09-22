"""Tests use loopback sockets and mocks; they never scan a public target."""

import socket
import itertools
from contextlib import nullcontext
import unittest
from unittest.mock import patch

from cybersec_toolkit.network import (
    check_connectivity,
    parse_port_spec,
    resolve_host,
    scan_tcp_ports,
)


class PortParsingTests(unittest.TestCase):
    def test_port_spec_sorts_deduplicates_and_expands(self):
        self.assertEqual(parse_port_spec("443, 80, 8000-8002, 80"), [80, 443, 8000, 8001, 8002])

    def test_port_spec_rejects_invalid_and_oversized_ranges(self):
        for spec in ("", "0", "65536", "4-3", "1-1025", "80,,443", "1-99999", "80;443"):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                parse_port_spec(spec)


class NetworkTests(unittest.TestCase):
    def test_resolution_rejects_urls_and_multiple_hosts(self):
        for host in ("https://example.org", "example.org,example.net", "example.org/path", " localhost"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                resolve_host(host)

    def test_scanning_requires_explicit_authorization_before_dns(self):
        with patch("cybersec_toolkit.network.socket.getaddrinfo") as dns:
            with self.assertRaises(PermissionError):
                scan_tcp_ports("localhost", "80")
            dns.assert_not_called()

    def test_scan_limits_workers_timeout_and_ports(self):
        for kwargs in ({"max_workers": 0}, {"max_workers": 65}, {"timeout": 6}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                scan_tcp_ports("127.0.0.1", [80], authorized=True, **kwargs)
        with self.assertRaises(ValueError):
            scan_tcp_ports("127.0.0.1", range(1, 1026), authorized=True)
        with self.assertRaises(ValueError):
            scan_tcp_ports("127.0.0.1", itertools.repeat(80), authorized=True)

    def test_loopback_open_port_and_scan_result(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(2)
            port = server.getsockname()[1]
            single = check_connectivity("127.0.0.1", port)
            self.assertEqual(single["state"], "open")
            result = scan_tcp_ports("127.0.0.1", [port], authorized=True, max_workers=1)
            self.assertEqual(result["resolved_address"], "127.0.0.1")
            self.assertEqual(result["ports"][0]["state"], "open")
            self.assertIsNone(result["ports"][0]["service_hint"])

    def test_connection_refused_is_closed_not_vulnerable(self):
        with patch("cybersec_toolkit.network.resolve_host", return_value=["127.0.0.1"]), patch(
            "cybersec_toolkit.network.socket.create_connection", side_effect=ConnectionRefusedError()
        ):
            result = check_connectivity("localhost", 443)
        self.assertEqual(result["state"], "closed")
        self.assertIn("conventional port", result["service_hint"])

    def test_dual_stack_checks_every_resolved_address(self):
        def connect(target, timeout):
            del timeout
            if target[0] == "::1":
                raise socket.timeout()
            return nullcontext()

        with patch(
            "cybersec_toolkit.network.resolve_host",
            return_value=["::1", "127.0.0.1"],
        ), patch(
            "cybersec_toolkit.network.socket.create_connection",
            side_effect=connect,
        ):
            single = check_connectivity("localhost", 443)
            scanned = scan_tcp_ports(
                "localhost", [443], authorized=True, max_workers=1
            )

        self.assertEqual(single["state"], "open")
        self.assertEqual(single["resolved_address"], "127.0.0.1")
        self.assertEqual(len(single["address_results"]), 2)
        self.assertEqual(scanned["ports"][0]["state"], "open")
        self.assertEqual(scanned["resolved_addresses"], ["::1", "127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
