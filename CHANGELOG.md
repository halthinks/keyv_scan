# Changelog

## 1.0.0 — 2026-08-05

- Replaced the narrow Bash package scanner with a standalone Node.js 18+ incident scanner.
- Added required provenance-manifest validation and validated live/bundled Wiz IOC handling with 443 packages and 2,235 exact versions in the bundled snapshot.
- Added exact-pair regression blocking, auxiliary-rule hashing, future-time checks, bounded HTTPS refresh, canonicalization, and atomic writes.
- Added npm/pnpm/Yarn/Bun installed-tree, cache, global, lockfile, and archive coverage, including extensionless cache archives discovered by magic bytes.
- Added npm alias detection and semver range exposure analysis.
- Added exact SHA-256/SHA-512 campaign artifact checks, streaming oversized-file hashing, and opt-in whole-root `--hash-all` detection for renamed payloads.
- Added Claude/VS Code autostart, lifecycle hook, candidate payload, persistence, temp artifact, and process checks.
- Added human, JSON, and SARIF reporting with deterministic IDs and independent findings/incomplete exit bits.
- Added bounded archive parsing with TAR checksum and ZIP CRC/local-central validation.
- Added cross-platform launchers, JSON schema, documentation, CI, release-manifest generation/verification, and safe regression tests.
