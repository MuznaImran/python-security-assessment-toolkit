"""Bounded, non-invasive TCP connectivity checks for authorized targets.

An open TCP port says only that a connection succeeded.  The service hints
below are conventional port names, not fingerprints of what actually runs.
"""

from __future__ import annotations

import errno
import ipaddress
import itertools
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable

MAX_PORTS = 1024
MAX_WORKERS = 64
MAX_TIMEOUT_SECONDS = 5.0

_COMMON_PORT_HINTS = {
    21: "FTP (conventional port)",
    22: "SSH (conventional port)",
    25: "SMTP (conventional port)",
    53: "DNS (conventional port)",
    80: "HTTP (conventional port)",
    110: "POP3 (conventional port)",
    143: "IMAP (conventional port)",
    443: "HTTPS (conventional port)",
    445: "SMB (conventional port)",
    587: "SMTP submission (conventional port)",
    993: "IMAPS (conventional port)",
    995: "POP3S (conventional port)",
    3389: "RDP (conventional port)",
    5432: "PostgreSQL (conventional port)",
    6379: "Redis (conventional port)",
    8080: "Alternate HTTP (conventional port)",
}

_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_PORT_PART = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?\Z")


def _validate_host(host: str) -> str:
    if not isinstance(host, str) or not host or host != host.strip():
        raise ValueError("host must be one IP address or DNS name")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if len(host) > 253 or host.endswith("."):
        raise ValueError("host must be one IP address or DNS name")
    labels = host.split(".")
    if not all(_DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("host must be one IP address or DNS name")
    return host.lower()


def _validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    return port


def _validate_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be a number of seconds")
    value = float(timeout)
    if not 0 < value <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g} seconds")
    return value


def parse_port_spec(spec: str) -> list[int]:
    """Parse ``80,443,8000-8002`` into sorted, unique port numbers.

    At most 1024 distinct ports are accepted.  Expansions are checked before
    allocation, so an oversized range is rejected promptly.
    """
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("port specification is empty")
    result: set[int] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        match = _PORT_PART.fullmatch(part)
        if match is None:
            raise ValueError(f"invalid port or range: {part!r}")
        start = _validate_port(int(match.group(1)))
        end = _validate_port(int(match.group(2))) if match.group(2) else start
        if end < start:
            raise ValueError(f"port range is reversed: {part!r}")
        if end - start + 1 > MAX_PORTS:
            raise ValueError(f"port range exceeds {MAX_PORTS} ports")
        result.update(range(start, end + 1))
        if len(result) > MAX_PORTS:
            raise ValueError(f"scan is limited to {MAX_PORTS} ports")
    return sorted(result)


def resolve_host(host: str) -> list[str]:
    """Return unique numeric TCP addresses from a single validated host."""
    target = _validate_host(host)
    records = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise OSError(f"No address records found for {target}")
    return addresses


def _probe(address: str, port: int, timeout: float) -> dict[str, object]:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            state = "open"
            detail = "TCP connection succeeded"
    except (socket.timeout, TimeoutError):
        state = "timeout"
        detail = "No TCP response before the timeout"
    except ConnectionRefusedError:
        state = "closed"
        detail = "TCP connection was refused"
    except OSError as exc:
        if exc.errno in {errno.ECONNREFUSED, 10061}:
            state = "closed"
            detail = "TCP connection was refused"
        else:
            state = "error"
            detail = str(exc)
    return {
        "port": port,
        "resolved_address": address,
        "state": state,
        "detail": detail,
        "service_hint": _COMMON_PORT_HINTS.get(port),
    }


_STATE_PRIORITY = {"open": 0, "closed": 1, "timeout": 2, "error": 3}


def _probe_addresses(addresses: list[str], port: int, timeout: float) -> dict[str, object]:
    """Try every resolved address and return the most useful result.

    DNS names commonly resolve to both IPv4 and IPv6. Trying every address
    avoids reporting a false negative when a service listens on only one
    address family.
    """
    attempts = [_probe(address, port, timeout) for address in addresses]
    selected = min(attempts, key=lambda result: _STATE_PRIORITY[str(result["state"])])
    return {**selected, "address_results": attempts}


def check_connectivity(host: str, port: int, timeout: float = 1.0) -> dict[str, object]:
    """Check one TCP port; an open result does not identify the service."""
    _validate_port(port)
    seconds = _validate_timeout(timeout)
    addresses = resolve_host(host)
    return {"target": host, **_probe_addresses(addresses, port, seconds)}


def scan_tcp_ports(
    host: str,
    ports: Iterable[int] | str,
    *,
    authorized: bool = False,
    timeout: float = 1.0,
    max_workers: int = 32,
) -> dict[str, object]:
    """Connect to a bounded set of ports on one host after explicit opt-in.

    This performs TCP connect checks only; it sends no application payload,
    attempts no authentication, and makes no vulnerability assessment.
    """
    if authorized is not True:
        raise PermissionError("TCP scanning requires authorized=True for a target you may assess")
    seconds = _validate_timeout(timeout)
    if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= MAX_WORKERS:
        raise ValueError(f"max_workers must be from 1 to {MAX_WORKERS}")
    if isinstance(ports, str):
        port_list = parse_port_spec(ports)
    else:
        try:
            port_list = list(itertools.islice(iter(ports), MAX_PORTS + 1))
        except TypeError as exc:
            raise ValueError("ports must be an iterable of port numbers or a port specification") from exc
        if not port_list or len(port_list) > MAX_PORTS:
            raise ValueError(f"scan must contain 1 to {MAX_PORTS} ports")
        port_list = sorted({_validate_port(port) for port in port_list})
    addresses = resolve_host(host)
    with ThreadPoolExecutor(max_workers=min(max_workers, len(port_list))) as pool:
        results = list(
            pool.map(lambda port: _probe_addresses(addresses, port, seconds), port_list)
        )
    return {
        "target": host,
        "resolved_address": addresses[0],
        "resolved_addresses": addresses,
        "ports": results,
        "note": "Service names are port hints only; open ports are not proof of a particular service or vulnerability.",
    }
