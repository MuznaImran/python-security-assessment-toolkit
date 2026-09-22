"""Deterministic exports for structured security assessment results."""

from __future__ import annotations

import csv
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
import json
from pathlib import Path
from typing import Any, Iterable


_PREFERRED_FIELDS = (
    "finding_id",
    "title",
    "severity",
    "source_ip",
    "first_seen",
    "last_seen",
    "failure_count",
    "usernames",
    "evidence_lines",
    "attack_mapping",
    "summary",
)

_SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _serializable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _serializable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _serializable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_serializable(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Unsupported report value: {type(value).__name__}")


def _records(findings: Iterable[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for finding in findings:
        value = _serializable(finding)
        if not isinstance(value, dict):
            raise TypeError("Each finding must be a dataclass or mapping")
        result.append(value)
    return result


def _fieldnames(records: list[dict[str, Any]]) -> list[str]:
    keys = list(dict.fromkeys(key for record in records for key in record))
    preferred = [key for key in _PREFERRED_FIELDS if key in keys]
    return preferred + [key for key in keys if key not in preferred]


def _display_value(value: Any, *, separator: str = ", ") -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            return separator.join(str(item) for item in value)
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _safe_csv_cell(value: Any) -> str:
    text = _display_value(value, separator="; ")
    if text.startswith(_SPREADSHEET_FORMULA_PREFIXES):
        return "'" + text
    return text


def _field_label(key: str) -> str:
    labels = {"source_ip": "Source IP", "attack_mapping": "ATT&CK mapping"}
    return labels.get(key, key.replace("_", " ").capitalize())


def write_json(findings: Iterable[Any], output_path: str | Path) -> Path:
    """Write a structured JSON document with finding count and records."""

    path = Path(output_path)
    records = _records(findings)
    payload = {"schema_version": 1, "finding_count": len(records), "findings": records}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def write_csv(findings: Iterable[Any], output_path: str | Path) -> Path:
    """Write one record per row without dropping tool-specific fields.

    String values that spreadsheet software could interpret as formulas are
    prefixed with an apostrophe to keep exported reports inert when opened.
    """

    path = Path(output_path)
    records = _records(findings)
    fields = _fieldnames(records)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        if fields:
            writer.writeheader()
        for record in records:
            row = {key: _safe_csv_cell(record.get(key)) for key in fields}
            writer.writerow(row)
    return path


def write_text(findings: Iterable[Any], output_path: str | Path) -> Path:
    """Write a readable report for arbitrary mapping or dataclass records."""

    path = Path(output_path)
    records = _records(findings)
    lines = ["Security Assessment Findings", "============================", f"Findings: {len(records)}", ""]
    for index, record in enumerate(records, start=1):
        finding_id = _display_value(record.get("finding_id")) or f"Finding {index}"
        title = _display_value(record.get("title"))
        lines.append(f"{finding_id}: {title}" if title else finding_id)
        for key, value in record.items():
            if key in {"finding_id", "title"}:
                continue
            rendered = _display_value(value) or "n/a"
            lines.append(f"{_field_label(key)}: {rendered}")
        lines.append("")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return path


def export_report(findings: Iterable[Any], output_path: str | Path) -> Path:
    """Choose JSON, CSV, or text output from the file extension."""

    path = Path(output_path)
    extension = path.suffix.lower()
    if extension == ".json":
        return write_json(findings, path)
    if extension == ".csv":
        return write_csv(findings, path)
    if extension == ".txt":
        return write_text(findings, path)
    raise ValueError("Report extension must be .json, .csv, or .txt")
