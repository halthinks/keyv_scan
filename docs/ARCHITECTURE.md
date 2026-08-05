# Architecture

## Design goals

- Read-only scanning of target systems and repositories.
- No third-party runtime packages or install-time scripts.
- Exact indicators where available; clearly labeled heuristics where not.
- Separate finding state from coverage state.
- Bounded parsing of untrusted CSV, JSON, lockfiles, TAR, gzip, and ZIP data.
- Stable machine-readable output and deterministic finding IDs.
- Cross-platform behavior on Linux, macOS, and Windows.

## Execution flow

1. `src/cli.js` parses the command and options.
2. `src/ioc.js` loads and validates the package CSV, hash rules, persistence rules, and manifest. It may perform a controlled live refresh.
3. `src/roots.js` discovers explicit roots, the current project, package-manager cache/global roots, user homes, and common workspaces.
4. `src/scanners/persistence.js` checks documented paths, temporary artifacts, and process command lines.
5. `src/scanners/filesystem.js` performs an iterative, symlink-aware walk with visited-path tracking and exclusion rules.
6. Specialized scanners inspect package manifests, lockfiles, cache records, source hooks, candidate payloads, hashes, and archives.
7. `src/findings.js` normalizes and de-duplicates evidence.
8. `src/report.js` produces human, JSON, and SARIF reports.
9. `src/scan.js` sets independent exit bits for actionable findings and incomplete coverage.

## Trust boundaries

All scanned files are untrusted. Parsers enforce file-size, archive-output, archive-entry, recursion, process-output, network-response, and total-file limits. Archives are parsed in memory but never extracted or executed; TAR headers and ZIP CRC/local-central metadata are validated before evidence is trusted. Oversized exact-hash targets are streamed instead of loaded into memory. Symlinks are followed only within the requested root by default.

The live IOC endpoint is also treated as untrusted until it passes schema, count, exact-pair regression, and canonicalization checks.

## No remediation side effects

The engine intentionally has no delete, quarantine, package-install, package-update, service-stop, credential-rotation, or process-kill function. Incident remediation requires human-controlled evidence preservation and sequencing.
