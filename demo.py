"""Guided, fully offline demonstration of the security toolkit.

Every input is synthetic. The demo makes no network requests and deletes its
temporary artifacts unless ``--output-dir`` is supplied.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from typing import Sequence, TextIO

from cybersec_toolkit.files import create_integrity_manifest, verify_integrity_manifest
from cybersec_toolkit.ioc import lookup_local
from cybersec_toolkit.logs import analyze_auth_log_file
from cybersec_toolkit.passwords import (
    analyze_password,
    estimate_pool_entropy,
    generate_password,
)
from cybersec_toolkit.reports import export_report


REPOSITORY_ROOT = Path(__file__).resolve().parent


def _line(stream: TextIO, text: str = "") -> None:
    print(text, file=stream)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"demo validation failed: {message}")


def _prepare_output(path: Path) -> Path:
    output = path.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"output directory must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    return output


def run_demo(output_dir: str | Path, *, stream: TextIO | None = None) -> dict[str, object]:
    """Run the synthetic workflow and return its machine-readable summary."""

    destination = _prepare_output(Path(output_dir))
    console = stream if stream is not None else sys.stdout

    _line(console, "Python Security Assessment Toolkit | Guided Offline Demo")
    _line(console, "============================================================")
    _line(console, "Synthetic inputs only. Network requests: none.")

    password = generate_password(length=20, exclude_ambiguous=True)
    password_analysis = analyze_password(password)
    entropy = estimate_pool_entropy(length=20, exclude_ambiguous=True)
    _require(len(password) == 20, "generated password length")
    _require(password_analysis["rating"] == "very strong", "generated password rating")
    _line(console, "\n[1/5] Password hygiene")
    _line(console, "  [OK] Generated 20 characters with Python's secrets module")
    _line(
        console,
        f"  [OK] Rating: {password_analysis['rating']} | pool entropy estimate: {entropy:.2f} bits",
    )
    _line(console, "  [OK] Generated value intentionally omitted from the demo log")

    monitored = destination / "monitored_asset.txt"
    monitored.write_text("approved configuration\n", encoding="utf-8")
    manifest = create_integrity_manifest([monitored], destination)
    manifest_path = destination / "integrity_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    baseline_result = verify_integrity_manifest(manifest, destination)
    monitored.write_text("approved configuration\nunauthorized change\n", encoding="utf-8")
    changed_result = verify_integrity_manifest(manifest, destination)
    _require(baseline_result["ok"] is True, "clean integrity baseline")
    _require(
        changed_result["modified"] == ["monitored_asset.txt"],
        "modified file detection",
    )
    digest = str(manifest["files"][0]["sha256"])
    _line(console, "\n[2/5] SHA-256 file integrity")
    _line(console, f"  [OK] Baseline digest: {digest[:16]}...")
    _line(console, f"  [OK] Baseline verified: {baseline_result['ok']}")
    _line(console, f"  [ALERT] Modified after change: {', '.join(changed_result['modified'])}")

    findings = analyze_auth_log_file(REPOSITORY_ROOT / "samples" / "sample_auth.log")
    _require(len(findings) == 1, "synthetic authentication finding count")
    primary_finding = findings[0]
    _require(primary_finding.source_ip == "203.0.113.44", "finding source IP")
    _require(primary_finding.failure_count == 5, "finding failure count")
    _line(console, "\n[3/5] Authentication-log triage")
    _line(
        console,
        f"  [ALERT] {primary_finding.failure_count} failures from {primary_finding.source_ip}",
    )
    _line(console, f"  [OK] Context mapping: {primary_finding.attack_mapping}")
    _line(
        console,
        "  [OK] Evidence lines: " + ", ".join(str(line) for line in primary_finding.evidence_lines),
    )

    ioc_result = lookup_local(
        "203.0.113.42", REPOSITORY_ROOT / "samples" / "iocs.json"
    )
    _require(ioc_result["status"] == "listed", "synthetic local IOC match")
    _line(console, "\n[4/5] Local IOC comparison")
    _line(
        console,
        f"  [MATCH] {ioc_result['indicator']} | status: {ioc_result['status']} | source: {ioc_result['source']}",
    )
    _line(console, "  [OK] No external provider contacted")

    report_paths = [
        export_report(findings, destination / "authentication_findings.json"),
        export_report(findings, destination / "authentication_findings.csv"),
        export_report(findings, destination / "authentication_findings.txt"),
    ]
    json_report = json.loads(report_paths[0].read_text(encoding="utf-8"))
    _require(json_report["schema_version"] == 1, "JSON report schema")
    _require(json_report["finding_count"] == 1, "JSON report finding count")
    artifacts = [manifest_path.name, *(path.name for path in report_paths)]
    summary: dict[str, object] = {
        "demo_version": 1,
        "offline": True,
        "synthetic_data": True,
        "password": {
            "length": len(password),
            "estimated_pool_entropy_bits": entropy,
            "rating": password_analysis["rating"],
            "value_logged": False,
        },
        "integrity": {
            "baseline_ok": baseline_result["ok"],
            "after_change_ok": changed_result["ok"],
            "modified": changed_result["modified"],
        },
        "authentication_log": {
            "finding_count": len(findings),
            "source_ip": primary_finding.source_ip,
            "failure_count": primary_finding.failure_count,
            "attack_mapping": primary_finding.attack_mapping,
        },
        "ioc": {
            "indicator": ioc_result["indicator"],
            "status": ioc_result["status"],
            "source": ioc_result["source"],
        },
        "artifacts": [*artifacts, "demo_summary.json"],
    }
    summary_path = destination / "demo_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    _line(console, "\n[5/5] Portable reports")
    _line(console, "  [OK] Exported JSON, CSV, and plain-text findings")
    _line(console, "  [OK] Wrote demo_summary.json for automated review")
    _line(console, "\nDemo complete. All results require analyst interpretation.")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a guided, synthetic, fully offline toolkit demonstration."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Keep generated manifests and reports in an empty directory.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.output_dir is not None:
            output = _prepare_output(args.output_dir)
            run_demo(output)
            print(f"Artifacts retained in: {output}")
        else:
            with TemporaryDirectory(prefix="security-toolkit-demo-") as folder:
                run_demo(folder)
            print("Temporary demo artifacts removed.")
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
