# Release notes — Keyv Incident Scanner 1.0.0

Release date: 2026-08-05

This is a complete, standalone replacement for the original `keyv_scan` package-presence script. It is designed for defensive incident triage of the August 2026 Keyv/Cacheable npm supply-chain compromise.

## Recommended runs

Standard host and developer-workspace scan:

```bash
./scan.sh --system
```

Maximum exact-hash coverage, including payloads renamed to unrelated filenames:

```bash
./scan.sh --system --hash-all --strict-permissions
```

PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scan.ps1 --system --hash-all --strict-permissions
```

`--hash-all` streams SHA-256 over every regular file under the requested roots. It can be substantially slower and more I/O intensive than the standard scan.

## Release guarantees

- Target scanning is read-only.
- The runtime has no third-party npm dependencies.
- The IOC provenance manifest is mandatory and binds the package CSV plus auxiliary hash/persistence rules.
- IOC refresh is HTTPS-only, host-allowlisted, bounded, schema-validated, regression-checked, canonicalized, and atomically written.
- A stale, future-dated, malformed, missing, or explicitly failed IOC refresh cannot produce a complete clean result.
- Findings and incomplete coverage are independent exit-code bits.
- Relevant ZIP/TAR corruption, unsupported relevant ZIP entries, malformed requested lockfiles/manifests, and file limits fail closed.
- Reports are emitted as text, JSON, and SARIF 2.1.0.

## Bundled IOC snapshot

- Package names: 443
- Exact package/version pairs: 2,235
- Canonical CSV SHA-256: `27a11ac94f9fbfe8435c8e3371e0f0c8d1abfe8f92e44e8a1a070748cccdb7c9`
- Acquired: `2026-08-05T10:48:58Z`

The complete source provenance and acquisition hashes are in `iocs/source-manifest.json`.

## Verification

```bash
npm ci --ignore-scripts
npm run check
```

`npm run check` runs the regression suite, verifies the bundled IOC set, and validates every release file against `MANIFEST.sha256`.

The package CSV is stored as four line-safe parts for GitHub API portability; the loader concatenates and hashes the exact canonical bytes before parsing. A validated live refresh writes the normal single `iocs/keyv-packages.csv` file.
