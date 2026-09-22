"""Command-line interface for the defensive security toolkit."""

from __future__ import annotations

import argparse
from getpass import getpass
import json
import os
from pathlib import Path
import sys
from typing import Any, Sequence

from . import __version__
from .files import (
    create_integrity_manifest,
    find_duplicate_files,
    sha256_file,
    verify_integrity_manifest,
)
from .ioc import lookup_abuseipdb, lookup_local, lookup_virustotal
from .logs import analyze_auth_log_file
from .network import check_connectivity, resolve_host, scan_tcp_ports
from .passwords import analyze_password, estimate_pool_entropy, generate_password
from .reports import export_report


def _json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def _password_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--length", type=int, default=20)
    parser.add_argument("--no-lowercase", action="store_true")
    parser.add_argument("--no-uppercase", action="store_true")
    parser.add_argument("--no-digits", action="store_true")
    parser.add_argument("--no-symbols", action="store_true")
    parser.add_argument("--exclude-ambiguous", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybersec",
        description=(
            "Local defensive security utilities. Run network checks only on "
            "systems you own or are expressly authorized to assess."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    areas = parser.add_subparsers(dest="area", required=True)

    password = areas.add_parser("password", help="Generate or review a password locally")
    password_commands = password.add_subparsers(dest="command", required=True)
    generate = password_commands.add_parser("generate", help="Generate a cryptographic password")
    _password_options(generate)
    password_commands.add_parser(
        "analyze", help="Prompt privately for a password and return heuristic feedback"
    )

    file_parser = areas.add_parser("file", help="Hash files and verify integrity")
    file_commands = file_parser.add_subparsers(dest="command", required=True)
    hash_parser = file_commands.add_parser("hash", help="Calculate a streaming SHA-256 digest")
    hash_parser.add_argument("path", type=Path)
    manifest_create = file_commands.add_parser(
        "manifest-create", help="Create a portable SHA-256 manifest"
    )
    manifest_create.add_argument("--root", type=Path, required=True)
    manifest_create.add_argument("--output", type=Path, required=True)
    manifest_create.add_argument("files", nargs="+", type=Path)
    manifest_verify = file_commands.add_parser(
        "manifest-verify", help="Verify files against a saved manifest"
    )
    manifest_verify.add_argument("--root", type=Path, required=True)
    manifest_verify.add_argument("manifest", type=Path)
    duplicates = file_commands.add_parser(
        "duplicates", help="Find identical content using size and SHA-256"
    )
    duplicates.add_argument("files", nargs="+", type=Path)

    network = areas.add_parser("network", help="Bounded TCP checks for authorized targets")
    network_commands = network.add_subparsers(dest="command", required=True)
    resolve = network_commands.add_parser("resolve", help="Resolve one DNS name or IP address")
    resolve.add_argument("host")
    check = network_commands.add_parser("check", help="Check one TCP port")
    check.add_argument("host")
    check.add_argument("port", type=int)
    check.add_argument("--timeout", type=float, default=1.0)
    scan = network_commands.add_parser("scan", help="Run bounded TCP connect checks")
    scan.add_argument("host")
    scan.add_argument("--ports", required=True, help="Example: 22,80,443,8000-8005")
    scan.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own or have permission to assess this target",
    )
    scan.add_argument("--timeout", type=float, default=1.0)
    scan.add_argument("--workers", type=int, default=32)

    ioc = areas.add_parser(
        "ioc", help="Look up indicators locally or with an opt-in provider"
    )
    ioc_commands = ioc.add_subparsers(dest="command", required=True)
    lookup = ioc_commands.add_parser(
        "lookup", help="Look up one IP, domain, URL, or SHA-256"
    )
    lookup.add_argument("indicator")
    lookup.add_argument(
        "--provider",
        choices=("local", "virustotal", "abuseipdb"),
        default="local",
    )
    lookup.add_argument("--list", dest="denylist", type=Path)
    lookup.add_argument(
        "--online",
        action="store_true",
        help="Confirm the indicator may be transmitted to the selected provider",
    )
    lookup.add_argument("--max-age-days", type=int, default=90)

    logs = areas.add_parser("logs", help="Analyze local SSH authentication logs")
    log_commands = logs.add_subparsers(dest="command", required=True)
    analyze = log_commands.add_parser("analyze", help="Detect repeated failed logins")
    analyze.add_argument("log", type=Path)
    analyze.add_argument("--threshold", type=int, default=5)
    analyze.add_argument("--window-minutes", type=int, default=5)
    analyze.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Report path ending in .json, .csv, or .txt",
    )
    return parser


def _selected_password_options(args: argparse.Namespace) -> dict[str, object]:
    return {
        "length": args.length,
        "use_lowercase": not args.no_lowercase,
        "use_uppercase": not args.no_uppercase,
        "use_digits": not args.no_digits,
        "use_symbols": not args.no_symbols,
        "exclude_ambiguous": args.exclude_ambiguous,
    }


def _run(args: argparse.Namespace) -> int:
    if args.area == "password" and args.command == "generate":
        options = _selected_password_options(args)
        password = generate_password(**options)
        _json(
            {
                "password": password,
                "length": len(password),
                "estimated_pool_entropy_bits": estimate_pool_entropy(**options),
                "entropy_note": (
                    "Pool-size approximation for cryptographic generation; not a "
                    "cracking-time prediction."
                ),
            }
        )
    elif args.area == "password" and args.command == "analyze":
        _json(analyze_password(getpass("Password (input hidden): ")))
    elif args.area == "file" and args.command == "hash":
        _json({"path": str(args.path), "algorithm": "sha256", "digest": sha256_file(args.path)})
    elif args.area == "file" and args.command == "manifest-create":
        manifest = create_integrity_manifest(args.files, args.root)
        args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        _json({"output": str(args.output), "files": len(manifest["files"]), "algorithm": "sha256"})
    elif args.area == "file" and args.command == "manifest-verify":
        document = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = verify_integrity_manifest(document, args.root)
        _json(result)
        return 0 if result["ok"] else 1
    elif args.area == "file" and args.command == "duplicates":
        _json({"duplicate_groups": find_duplicate_files(args.files)})
    elif args.area == "network" and args.command == "resolve":
        _json({"host": args.host, "addresses": resolve_host(args.host)})
    elif args.area == "network" and args.command == "check":
        _json(check_connectivity(args.host, args.port, timeout=args.timeout))
    elif args.area == "network" and args.command == "scan":
        _json(
            scan_tcp_ports(
                args.host,
                args.ports,
                authorized=args.authorized,
                timeout=args.timeout,
                max_workers=args.workers,
            )
        )
    elif args.area == "ioc" and args.command == "lookup":
        if args.provider == "local":
            if args.denylist is None:
                raise ValueError("--list is required for the local provider")
            _json(lookup_local(args.indicator, args.denylist))
        elif not args.online:
            raise PermissionError(
                "online IOC lookup transmits the indicator; add --online after review"
            )
        elif args.provider == "virustotal":
            _json(
                lookup_virustotal(
                    args.indicator,
                    os.environ.get("VIRUSTOTAL_API_KEY", ""),
                )
            )
        else:
            _json(
                lookup_abuseipdb(
                    args.indicator,
                    os.environ.get("ABUSEIPDB_API_KEY", ""),
                    max_age_days=args.max_age_days,
                )
            )
    elif args.area == "logs" and args.command == "analyze":
        findings = analyze_auth_log_file(
            args.log,
            threshold=args.threshold,
            window_minutes=args.window_minutes,
        )
        output = export_report(findings, args.output)
        _json(
            {
                "findings": len(findings),
                "report": str(output),
                "note": "Findings are triage leads and require analyst review.",
            }
        )
    else:  # pragma: no cover - argparse prevents this state
        raise ValueError("unsupported command")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process status code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except (
        FileNotFoundError,
        json.JSONDecodeError,
        OSError,
        PermissionError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
