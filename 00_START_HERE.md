# Start here

This repository is a read-only incident scanner for the August 2026 Keyv/Cacheable npm supply-chain compromise.

## Fastest safe run

Linux or macOS:

```bash
./scan.sh --system
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scan.ps1 --system
```

Maximum exact-hash coverage, including known payload bytes renamed to unrelated filenames:

```bash
./scan.sh --system --hash-all --strict-permissions
```

This mode reads every regular file to compute SHA-256 and is intentionally more I/O intensive.

The scanner creates three reports in a timestamped `keyv-scan-reports/` directory:

- `report.txt` — human-readable response
- `report.json` — complete structured evidence
- `report.sarif` — SARIF 2.1.0 for security tooling

## Interpret the exit code

| Code | Meaning |
|---:|---|
| 0 | No actionable indicators found and all requested checks completed |
| 1 | One or more actionable indicators found; requested checks completed |
| 2 | No actionable indicators found, but one or more requested checks were incomplete |
| 3 | Indicators found and one or more requested checks were incomplete |

A code `2` is **not clean**. Findings and incomplete coverage are independent bit flags.

## When a finding appears

Do not immediately rotate GitHub/npm/cloud credentials. First isolate the host and disable/preserve any `gh-token-monitor` persistence: the documented watcher can react to token revocation. Then investigate and rotate all credentials that were reachable from the machine or CI runner. Read [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).

## Verify the scanner package

```bash
npm test
node bin/keyv-scan.js verify-iocs
npm run verify-manifest
```

The scanner requires Node.js 18 or newer and has no third-party runtime dependencies.
