"""Validate IP, domain, URL, and SHA-256 indicators and enrich them carefully.

The module does not consult threat-intelligence services.  Presence in a
local list is a match, not a definitive maliciousness verdict; absence does
not establish that an indicator is safe.
"""

from __future__ import annotations

import ipaddress
import json
import re
from base64 import urlsafe_b64encode
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")


def classify_indicator(value: str) -> tuple[str, str]:
    """Return ``(type, normalized_value)`` for an IP, domain, URL, or SHA-256.

    Domain input must be an ASCII DNS name with at least two labels.  IPv4
    and IPv6 addresses are normalized with the standard ``ipaddress`` module.
    """
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("indicator must be a nonempty IP, domain, or SHA-256 value")
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if _SHA256.fullmatch(value):
        return "sha256", value.lower()
    parsed = urlsplit(value)
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("URL indicators cannot contain credentials or fragments")
        hostname = parsed.hostname.lower()
        try:
            normalized_host = str(ipaddress.ip_address(hostname))
            if ":" in normalized_host:
                normalized_host = f"[{normalized_host}]"
        except ValueError:
            if len(hostname) > 253 or not all(
                _DOMAIN_LABEL.fullmatch(label) for label in hostname.split(".")
            ):
                raise ValueError("URL indicator has an invalid hostname") from None
            normalized_host = hostname
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("URL indicator has an invalid port") from error
        netloc = normalized_host if port is None else f"{normalized_host}:{port}"
        return "url", urlunsplit(
            (parsed.scheme.lower(), netloc, parsed.path, parsed.query, "")
        )
    domain = value.lower()
    if len(domain) <= 253 and "." in domain and all(
        _DOMAIN_LABEL.fullmatch(label) for label in domain.split(".")
    ):
        return "domain", domain
    raise ValueError("indicator must be a valid IP address, DNS domain, HTTP(S) URL, or SHA-256 digest")


def load_denylist(path: str | Path) -> dict[tuple[str, str], dict[str, str]]:
    """Load JSON records from ``{"indicators": [{"value": ..., ...}]}``.

    Optional record fields are ``source`` and ``note``.  The file is local;
    its accuracy and provenance are the user's responsibility.
    """
    with Path(path).open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    if not isinstance(document, dict) or not isinstance(document.get("indicators"), list):
        raise ValueError("denylist must be a JSON object with an indicators array")
    result: dict[tuple[str, str], dict[str, str]] = {}
    for index, record in enumerate(document["indicators"]):
        if not isinstance(record, dict):
            raise ValueError(f"indicator entry {index} must be an object")
        kind, normalized = classify_indicator(record.get("value"))
        source = record.get("source", "local list")
        note = record.get("note", "")
        if not isinstance(source, str) or not isinstance(note, str):
            raise ValueError(f"indicator entry {index} source and note must be strings")
        result[(kind, normalized)] = {"source": source, "note": note}
    return result


def lookup_local(indicator: str, denylist_path: str | Path) -> dict[str, str | None]:
    """Match one indicator against a local list without making a safety claim."""
    kind, normalized = classify_indicator(indicator)
    record = load_denylist(denylist_path).get((kind, normalized))
    if record is None:
        return {
            "indicator": normalized,
            "type": kind,
            "status": "not_listed",
            "source": None,
            "note": None,
            "interpretation": "No local list match; this does not mean the indicator is safe.",
        }
    return {
        "indicator": normalized,
        "type": kind,
        "status": "listed",
        "source": record["source"],
        "note": record["note"],
        "interpretation": "Matched the local list; verify provenance and context before drawing a conclusion.",
    }


def _request_json(request: Request, timeout: float) -> dict[str, object]:
    if not 0 < timeout <= 30:
        raise ValueError("timeout must be greater than 0 and at most 30 seconds")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed HTTPS providers
            document = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise RuntimeError(f"provider returned HTTP {error.code}") from error
    except URLError as error:
        raise RuntimeError("provider request failed") from error
    if not isinstance(document, dict):
        raise RuntimeError("provider returned an unexpected response")
    return document


def lookup_virustotal(
    indicator: str, api_key: str, *, timeout: float = 10.0
) -> dict[str, object]:
    """Retrieve a VirusTotal v3 report for an IP, domain, or SHA-256.

    Calling this function transmits the indicator to VirusTotal. The caller
    must obtain an API key from the environment and decide whether that
    disclosure is appropriate. The key is sent only in the ``x-apikey`` header.
    """
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("VirusTotal API key is required")
    kind, normalized = classify_indicator(indicator)
    collection = {
        "ip": "ip_addresses",
        "domain": "domains",
        "sha256": "files",
        "url": "urls",
    }[kind]
    identifier = normalized
    if kind == "url":
        identifier = urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")
    request = Request(
        f"https://www.virustotal.com/api/v3/{collection}/{quote(identifier, safe='')}",
        headers={"Accept": "application/json", "x-apikey": api_key.strip()},
    )
    document = _request_json(request, timeout)
    data = document.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        raise RuntimeError("VirusTotal returned an unexpected response")
    stats = attributes.get("last_analysis_stats", {})
    return {
        "provider": "VirusTotal",
        "indicator": normalized,
        "type": kind,
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": stats if isinstance(stats, dict) else {},
        "last_analysis_date": attributes.get("last_analysis_date"),
        "interpretation": (
            "Provider observations are context, not proof of compromise or safety; "
            "review detection names, timing, provenance, and local evidence."
        ),
    }


def lookup_abuseipdb(
    indicator: str,
    api_key: str,
    *,
    max_age_days: int = 90,
    timeout: float = 10.0,
) -> dict[str, object]:
    """Retrieve an AbuseIPDB v2 check report for one IP address.

    Calling this function transmits the IP address to AbuseIPDB. The API key is
    sent only in the recommended ``Key`` header.
    """
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("AbuseIPDB API key is required")
    kind, normalized = classify_indicator(indicator)
    if kind != "ip":
        raise ValueError("AbuseIPDB lookup accepts IP addresses only")
    if isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or not 1 <= max_age_days <= 365:
        raise ValueError("max_age_days must be from 1 to 365")
    query = urlencode({"ipAddress": normalized, "maxAgeInDays": max_age_days})
    request = Request(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        headers={"Accept": "application/json", "Key": api_key.strip()},
    )
    document = _request_json(request, timeout)
    data = document.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("AbuseIPDB returned an unexpected response")
    return {
        "provider": "AbuseIPDB",
        "indicator": normalized,
        "type": "ip",
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "last_reported_at": data.get("lastReportedAt"),
        "interpretation": (
            "A reputation score is a lead, not proof of maliciousness; verify age, "
            "report quality, ownership, and local telemetry."
        ),
    }
