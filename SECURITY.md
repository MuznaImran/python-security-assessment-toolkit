# Security policy and ethical use

The [Python Security Assessment Toolkit](https://github.com/MuznaImran/python-security-assessment-toolkit)
is for defensive analysis of systems you own or are expressly authorized to
assess. The TCP scanner requires `--authorized`, scans one host per invocation,
and enforces bounded ports, timeouts, and concurrency. It does not exploit
services, send application payloads, or attempt credentials.

## Data handling and credentials

Local IOC comparison is the default and makes no external network request. The
optional VirusTotal and AbuseIPDB integrations run only when the user selects a
remote provider and supplies the explicit `--online` flag. Their API keys are
read from the current process environment:

- `VIRUSTOTAL_API_KEY` for VirusTotal
- `ABUSEIPDB_API_KEY` for AbuseIPDB

The CLI does not automatically load `.env` files. Keep real keys out of source
files, command arguments, reports, screenshots, issues, and commits.

An online lookup discloses the submitted indicator to the selected provider.
The provider also receives connection and request metadata and may retain or
process that information under its own terms and privacy policy. Do not submit
internal hostnames, customer data, private investigation details, or indicators
you are not authorized to share.

Do not commit real logs, private IP inventories, credentials, sensitive reports,
or `.env` files. The bundled samples use synthetic events and reserved
documentation addresses.

## Interpretation

The password analyzer and entropy estimates are educational heuristics. They do
not check breach corpora or prove resistance to guessing. Use the hidden prompt
for analysis, and never paste real passwords into issue reports or recordings.

An IOC match, provider score, or absence is contextual evidence rather than a
verdict. Authentication-log findings are triage leads rather than proof of
intent, attribution, or compromise. Review freshness, provenance, false
positives, ownership, and local telemetry before acting.

## Reporting a vulnerability

If you find a security issue in this repository, avoid publishing exploit
details in a public issue. Contact the repository owner privately through the
[MuznaImran GitHub profile](https://github.com/MuznaImran) with the affected
version, impact, reproduction steps, and any suggested mitigation.
