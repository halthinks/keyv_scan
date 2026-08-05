# Keyv Incident Scanner

A fail-closed, cross-platform, read-only scanner for the **August 2026 Keyv/Cacheable npm supply-chain compromise**.

It replaces the narrow package-presence script in `AlextheYounga/keyv_scan` with a complete incident-oriented scanner that checks exact package versions, dependency declarations, all major JavaScript lockfile families, installed dependency trees, package-manager caches, package archives, cryptographic payload hashes, repository autostart hooks, documented persistence, temporary execution artifacts, and running process command lines.

The scanner has **no third-party runtime dependencies**. It requires Node.js 18+ and uses only Node's standard library.

## What it detects

| Evidence class | Coverage |
|---|---|
| Installed packages | Recursive `package.json` inspection under project/global dependency trees, npm layouts, pnpm virtual stores, Yarn unplugged trees, and Bun package trees |
| Dependency declarations | Exact versions, semver ranges that admit affected versions, mutable tags, bundled dependencies, and npm aliases such as `safe-name: npm:keyv@6.0.0` |
| Lockfiles | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `pnpm-lock.yml`, Yarn Classic/Berry `yarn.lock`, text `bun.lock`, and binary `bun.lockb` with Bun-assisted resolution plus heuristic fallback |
| npm cache | cacache index keys, metadata, SRI SHA-256/SHA-512 digests, and content-addressed objects |
| pnpm/Yarn/Bun caches | Package metadata, encoded package/version paths, Yarn archives, package folders, and relevant archives |
| Archives | Bounded ZIP, gzip/TGZ, and TAR inspection, including extensionless cache objects identified by magic bytes, TAR-header checksum validation, and ZIP CRC/local-central consistency validation |
| Payload hashes | Three documented SHA-256 payload/loader hashes and the documented SHA-512 of the malicious `keyv@6.0.0` tarball; `--hash-all` detects exact SHA-256 matches after arbitrary renaming |
| Malicious hooks | npm lifecycle scripts, Claude `SessionStart`, and VS Code `folderOpen` tasks referencing campaign loader/payload names |
| Payload heuristics | `setup.mjs`, `Math_Symbol.js`, `math_init.js`, and characteristic campaign markers |
| Persistence | Documented `gh-token-monitor` watcher/state, macOS LaunchAgent, Linux systemd user service, and monitor logs without reading stored token/handler secrets |
| Runtime artifacts | `bun-dl-*` temporary paths and running process command lines containing campaign indicators |
| Reporting | Human text, stable JSON, and SARIF 2.1.0 with deterministic finding IDs |

## Quick start

Clone or unpack the scanner, then run it from any directory.

### Linux and macOS

```bash
chmod +x scan.sh
./scan.sh --system
```

### Windows PowerShell

```powershell
powershell -ExecutionPolicy Bypass -File .\scan.ps1 --system
```

### Direct Node invocation

```bash
node bin/keyv-scan.js scan --system
```

By default, the scanner checks the current project, discovered npm/pnpm/Yarn caches and global roots, known persistence paths, relevant temporary artifacts, and running processes. `--system` adds discovered user homes and common workspace roots and enables deep JavaScript/archive inspection.

For maximum exact-hash coverage—including known payload bytes renamed to unrelated filenames—add `--hash-all`. Pair it with `--strict-permissions` when an inaccessible nested path must make the result incomplete:

```bash
./scan.sh --system --hash-all --strict-permissions
```

`--hash-all` streams SHA-256 over every regular file under the requested roots and can be substantially more I/O intensive.

For a particular repository:

```bash
node bin/keyv-scan.js scan /path/to/project --project-only
```

For a deliberately broad filesystem scan, explicitly supply the filesystem root and use elevated permissions only when appropriate:

```bash
sudo node bin/keyv-scan.js scan / --project-only --deep --strict-permissions
```

On Windows:

```powershell
node .\bin\keyv-scan.js scan C:\ --project-only --deep --strict-permissions
```

## IOC safety model

The bundled line-safe `iocs/keyv-packages.csv.part01` … `.part04` files concatenate byte-for-byte to a canonical snapshot of the Wiz Research IOC feed acquired on August 5, 2026. The bundled snapshot contains **443 package names and 2,235 exact package-version pairs**.

Before it trusts the feed, the scanner requires the provenance manifest and validates:

1. CSV syntax and recognized headers.
2. Every package name and exact-version value.
3. Minimum package and exact-pair counts.
4. The canonical CSV SHA-256 recorded in `iocs/source-manifest.json`.
5. The exact package and version counts recorded in the manifest.
6. SHA-256 values for `iocs/hashes.json` and `iocs/persistence.json`.
7. Manifest time sanity, including future-dated timestamp rejection.
8. During refresh, that no previously known exact package/version pair silently disappears unless `--allow-ioc-regression` is explicitly supplied after manual review.

The default live refresh is pinned to the HTTPS raw GitHub host for:

```text
https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/keyv-packages.csv
```

The updater permits only allowlisted GitHub raw-content hosts, limits redirects and response size, validates the new feed before writing, canonicalizes line endings, and uses atomic file replacement. A missing or structurally incomplete provenance manifest is rejected; counts alone are never accepted as feed authenticity or integrity evidence. An update failure cannot silently turn an invalid or stale feed into a clean result.

Refresh manually:

```bash
node bin/keyv-scan.js update-iocs
node bin/keyv-scan.js verify-iocs
```

Run without network access:

```bash
node bin/keyv-scan.js scan --offline --no-auto-update
```

If an offline IOC snapshot exceeds `--max-ioc-age-hours`, the scan exits with the incomplete-coverage bit even when it finds nothing.

## Reports

Every scan writes:

```text
keyv-scan-reports/YYYYMMDDTHHMMSSZ/
├── report.txt
├── report.json
└── report.sarif
```

Choose another output directory:

```bash
node bin/keyv-scan.js scan --output-dir ./evidence/keyv-scan
```

Reports are written with restrictive file permissions where the operating system supports them. They contain paths, package names, versions, process command lines that matched campaign indicators, and operational errors. They do **not** read or include the contents of the documented stolen-token or remote-handler state files.

The JSON contract is documented in [`docs/REPORT_FORMAT.md`](docs/REPORT_FORMAT.md) and [`schemas/report.schema.json`](schemas/report.schema.json).

## Exit-code contract

Exit codes are a two-bit mask:

- bit `1`: findings at or above `--fail-on`
- bit `2`: requested coverage incomplete

| Exit | Findings | Coverage |
|---:|---|---|
| `0` | none actionable | complete |
| `1` | present | complete |
| `2` | none actionable | incomplete |
| `3` | present | incomplete |

The default actionable threshold is `medium`. Change it with:

```bash
node bin/keyv-scan.js scan --fail-on high
```

Low-confidence and informational evidence remains in the report even when it does not set the finding bit.

## Important options

```text
--system                  Add discovered user homes/common workspaces; implies --deep
--full-home               Recursively inspect the current user's home
--project-only            Do not add package-manager cache/global roots
--root PATH               Add a root; repeatable
--exclude PATH            Exclude a subtree; repeatable
--deep                     Hash/inspect JavaScript files and all recognized archives
--hash-all                 Stream SHA-256 over every regular file under requested roots
--strict-permissions       Nested permission errors make coverage incomplete
--offline                  Do not make an IOC request
--no-auto-update           Do not auto-refresh the local feed
--force-update             Refresh the feed before scanning
--no-processes             Skip process-list inspection
--no-persistence           Skip persistence, temp-artifact, and process checks
--no-potential             Suppress dependency-range/tag exposure findings
--max-files N              Fail closed after N files
--max-ioc-age-hours N      Maximum age for complete IOC coverage
--fail-on LEVEL            critical, high, medium, low, or info
```

Run `node bin/keyv-scan.js help` for the complete CLI reference.

## Incident-response order

A positive installed-package, payload-hash, hook, or persistence finding should be treated as potential host compromise—not merely a vulnerable dependency.

1. Isolate the machine or CI runner and preserve volatile evidence.
2. Identify and disable/preserve the documented GitHub token monitor and its LaunchAgent/systemd persistence.
3. Preserve relevant package-manager caches, lockfiles, process listings, shell/CI logs, and scanner reports.
4. Determine whether npm/pnpm/Yarn/Bun lifecycle scripts executed.
5. Rotate npm, GitHub, cloud, Vault, Kubernetes, CI, and other reachable credentials only after the dead-man-switch mechanism is neutralized.
6. Audit unauthorized package publications, GitHub repositories and Actions, cloud audit logs, secret-manager access, Kubernetes audit logs, and DNS/network telemetry.
7. Rebuild the host/runner and dependencies from trusted sources rather than relying on deletion of `node_modules` alone.

See [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).

## CI usage

Example GitHub Actions step:

```yaml
- name: Scan for Keyv/Cacheable campaign indicators
  run: |
    node tools/keyv-incident-scanner/bin/keyv-scan.js scan . \
      --project-only \
      --offline \
      --no-auto-update \
      --no-persistence \
      --no-processes \
      --strict-permissions \
      --output-dir keyv-scan-results
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: keyv-scan-results/report.sarif
```

Keep the pinned IOC snapshot current in the scanner artifact used by CI, or permit the controlled live refresh. Do not coerce exit codes `2` or `3` to success.

## Tests and verification

```bash
npm ci --ignore-scripts
npm test
npm run verify-manifest
npm run check
```

The test suite uses only safe synthetic fixtures. It never includes or executes the documented malware payload. `npm run check` also verifies the bundled IOC set and every packaged source file against `MANIFEST.sha256`.

## Read-only guarantee and writes

Target scanning is read-only. The scanner does not install, update, remove, quarantine, execute, or repair project dependencies. It invokes package-manager commands only to discover cache/global paths and invokes `bun pm ls --all` only to decode a local `bun.lockb` when Bun is available.

The only writes are:

- report files under the selected output directory;
- validated IOC refreshes under this scanner's `iocs/` directory;
- temporary atomic-write files adjacent to those destinations, removed or renamed immediately.

## Limitations

No scanner can prove that a host was never compromised. In particular:

- Deleted payloads, cleared caches, missing logs, and already-removed dependencies may leave no local indicator.
- A package/version match establishes exposure; it does not by itself prove lifecycle execution.
- A cache-only match proves retained content or metadata, not execution.
- Binary Bun lockfile parsing is strongest when Bun is installed; fallback parsing is heuristic and explicitly marks coverage incomplete.
- Encrypted or unsupported-compression relevant ZIP entries are reported as a coverage gap. Corrupt relevant ZIP/TAR structures also fail closed.
- Exact payload hashes hidden behind arbitrary filenames require `--hash-all`; the default scan hashes documented candidate names, deep JavaScript targets, and relevant archives.
- `--system` targets likely developer/CI locations, not every mounted byte. Use explicit roots for broader collection.
- The campaign IOC set can evolve. Keep the feed current and correlate with endpoint, identity, registry, GitHub, cloud, and CI telemetry.

## Repository map

```text
00_START_HERE.md
bin/keyv-scan.js             CLI entry point
iocs/                        pinned package, hash, and persistence indicators
src/                         scanner engine
src/scanners/                package, lockfile, archive, content, cache, persistence scanners
schemas/report.schema.json   JSON report contract
docs/                        architecture, coverage, IOC, response, and report documentation
test/                        safe deterministic tests
scan.sh / scan.ps1 / scan.cmd
check_packages.sh            compatibility entry point for the original repository
```

## Sources

- Wiz Research IOC list: `wiz-sec-public/wiz-research-iocs`, `reports/keyv-packages.csv`
- Socket Research incident analysis: `Popular npm Packages in the Keyv and Cacheable Namespaces Compromised in Active Supply Chain Attack`
- Socket campaign tracker: `Keyv and Cacheable Compromise`

Source URLs, acquisition hashes, and the exact bundled snapshot metadata are recorded in `iocs/source-manifest.json`, `iocs/hashes.json`, and `iocs/persistence.json`.
