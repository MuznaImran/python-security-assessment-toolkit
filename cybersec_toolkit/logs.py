"""Offline analysis of SSH authentication logs.

Supported input is one event per line, with an ISO 8601 timestamp followed by
an OpenSSH ``sshd`` message, for example::

    2026-09-20T09:14:22+05:00 sshd[4312]: Failed password for alice from 203.0.113.10 port 51234 ssh2

``Z`` timestamps, IPv6 addresses, ``invalid user`` failures, and accepted
password/public-key logins are understood. Unrelated lines are ignored. This
module reads local data only; it never contacts hosts mentioned in a log.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import re
from typing import Iterable


_LINE = re.compile(
    r"^(?P<timestamp>\S+)\s+(?:\S+\s+)?sshd(?:\[\d+\])?:\s+(?P<message>.+)$"
)
_FAILURE = re.compile(
    r"^Failed\s+(?:password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?:(?:invalid|illegal)\s+user\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<ip>\S+)(?:\s+port\s+\d+)?(?:\s|$)",
    re.IGNORECASE,
)
_SUCCESS = re.compile(
    r"^Accepted\s+(?:password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?P<username>\S+)\s+from\s+(?P<ip>\S+)"
    r"(?:\s+port\s+\d+)?(?:\s|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class LogEvent:
    timestamp: datetime
    source_ip: str
    username: str
    outcome: str  # "failure" or "success"
    line_number: int
    raw_line: str


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    failure_count: int
    usernames: tuple[str, ...]
    evidence_lines: tuple[int, ...]
    summary: str
    attack_mapping: str = "MITRE ATT&CK T1110 (Brute Force, contextual mapping)"


def _timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def parse_auth_log(text: str) -> list[LogEvent]:
    """Parse supported OpenSSH lines; discard unrelated or malformed lines.

    Every returned timestamp is normalized to UTC. Only valid IP addresses
    are retained, so arbitrary hostnames cannot be mistaken for source IPs.
    """

    events: list[LogEvent] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        match = _LINE.match(raw_line.strip())
        if not match:
            continue
        timestamp = _timestamp(match.group("timestamp"))
        if timestamp is None:
            continue

        message = match.group("message")
        event_match = _FAILURE.match(message)
        outcome = "failure"
        if event_match is None:
            event_match = _SUCCESS.match(message)
            outcome = "success"
        if event_match is None:
            continue

        try:
            ip = str(ipaddress.ip_address(event_match.group("ip")))
        except ValueError:
            continue
        events.append(
            LogEvent(
                timestamp=timestamp,
                source_ip=ip,
                username=event_match.group("username"),
                outcome=outcome,
                line_number=line_number,
                raw_line=raw_line,
            )
        )
    return events


def _severity(count: int) -> str:
    if count >= 20:
        return "critical"
    if count >= 10:
        return "high"
    return "medium"


def detect_brute_force(
    events: Iterable[LogEvent], *, threshold: int = 5, window_minutes: int = 5
) -> list[Finding]:
    """Find source IPs with ``threshold`` failures in a rolling time window.

    One finding is emitted per burst. Consecutive failures from the same IP
    remain in one burst while the gap between them does not exceed the window.
    A successful login is parsed but is not treated as proof that an attacker
    succeeded, and does not count toward the failure threshold.
    """

    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")

    window = timedelta(minutes=window_minutes)
    by_source: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.outcome == "failure":
            by_source[event.source_ip].append(event)

    findings: list[Finding] = []
    for source_ip, failures in by_source.items():
        failures.sort(key=lambda event: (event.timestamp, event.line_number))
        bursts: list[list[LogEvent]] = []
        burst: list[LogEvent] = []
        for event in failures:
            if burst and event.timestamp - burst[-1].timestamp > window:
                bursts.append(burst)
                burst = []
            burst.append(event)
        if burst:
            bursts.append(burst)

        for segment in bursts:
            rolling: deque[LogEvent] = deque()
            triggered = False
            for event in segment:
                rolling.append(event)
                while rolling and event.timestamp - rolling[0].timestamp > window:
                    rolling.popleft()
                if len(rolling) >= threshold:
                    triggered = True
                    break
            if not triggered:
                continue

            first, last = segment[0], segment[-1]
            usernames = tuple(sorted({event.username for event in segment}))
            count = len(segment)
            findings.append(
                Finding(
                    finding_id=f"SSH-BRUTE-{len(findings) + 1:03d}",
                    title="Repeated SSH authentication failures",
                    severity=_severity(count),
                    source_ip=source_ip,
                    first_seen=first.timestamp,
                    last_seen=last.timestamp,
                    failure_count=count,
                    usernames=usernames,
                    evidence_lines=tuple(event.line_number for event in segment),
                    summary=(
                        f"{count} SSH authentication failures from {source_ip} "
                        f"included at least {threshold} within {window_minutes} minutes. "
                        "Review the source and account activity; this pattern may indicate "
                        "password guessing."
                    ),
                )
            )

    findings.sort(key=lambda item: (item.first_seen, item.source_ip))
    return findings


def analyze_auth_log(
    text: str, *, threshold: int = 5, window_minutes: int = 5
) -> list[Finding]:
    """Parse a log and return repeated-failure findings."""

    return detect_brute_force(
        parse_auth_log(text), threshold=threshold, window_minutes=window_minutes
    )


def analyze_auth_log_file(
    path: str | Path, *, threshold: int = 5, window_minutes: int = 5
) -> list[Finding]:
    """Read a UTF-8 auth log file and analyze it offline."""

    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return analyze_auth_log(text, threshold=threshold, window_minutes=window_minutes)
