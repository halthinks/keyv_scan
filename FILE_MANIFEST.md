# File manifest

## Entry points

- `bin/keyv-scan.js` — direct Node CLI
- `scan.sh` — Linux/macOS launcher
- `scan.ps1` — PowerShell launcher
- `scan.cmd` — Windows CMD launcher
- `check_packages.sh` — compatibility launcher for the original scanner name

## Engine

- `src/cli.js` — CLI parsing and commands
- `src/ioc.js` — IOC acquisition, validation, freshness, and regression controls
- `src/csv.js` — strict CSV parsing/canonicalization
- `src/roots.js` — project/cache/global/home/system root discovery
- `src/scan.js` — orchestration, report lifecycle, and exit contract
- `src/context.js` — shared scan state and coverage accounting
- `src/findings.js` — finding normalization, remediation, and de-duplication
- `src/report.js` — text, JSON, and SARIF renderers
- `src/semver.js` — dependency-range exposure evaluation
- `src/util.js` — bounded I/O, hashing, command execution, paths, and stable JSON

## Specialized scanners

- `src/scanners/packages.js`
- `src/scanners/lockfiles.js`
- `src/scanners/filesystem.js`
- `src/scanners/archives.js`
- `src/scanners/content.js`
- `src/scanners/persistence.js`

## Indicators

- `iocs/keyv-packages.csv.part01` … `.part04` — line-safe pieces that concatenate byte-for-byte to the canonical package/version snapshot
- `iocs/source-manifest.json` — provenance, hashes, counts, and acquisition metadata
- `iocs/hashes.json` — exact payload/archive hashes
- `iocs/persistence.json` — paths, filenames, process indicators, and platform scope

## Contracts and documentation

- `schemas/report.schema.json`
- `docs/REPORT_FORMAT.md`
- `docs/RULE_REFERENCE.md`
- `docs/DETECTION_COVERAGE.md`
- `docs/INCIDENT_RESPONSE.md`
- `docs/IOC_LIFECYCLE.md`
- `docs/ARCHITECTURE.md`
- `docs/PRIVACY.md`

## Verification and release

- `test/` — safe deterministic regression tests
- `test_support/helpers.js` — safe archive/context fixtures
- `.github/workflows/test.yml` — Linux/macOS/Windows, Node 18/20/22 matrix
- `scripts/check-syntax.js` — cross-platform syntax verifier for every JavaScript source/test file
- `scripts/generate-manifest.js` — release file checksum generator
- `scripts/verify-manifest.js` — complete release-file set and SHA-256 verifier
- `MANIFEST.sha256` — per-file SHA-256 inventory
- `RELEASE_NOTES.md` — release usage, guarantees, IOC snapshot, and verification steps
- `package-lock.json` — dependency-free npm lock
