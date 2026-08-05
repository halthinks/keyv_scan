# IOC lifecycle and provenance

## Package feed

The canonical source is:

```text
https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/keyv-packages.csv
```

`iocs/source-manifest.json` records the acquisition time, raw and canonical SHA-256 values, Git blob SHA when available, line-ending normalization, package count, exact-pair count, HTTP validators, and auxiliary rule-file hashes.

## Update validation

`update-iocs` performs these checks before replacing the local feed:

1. HTTPS and host allowlist.
2. Redirect count, timeout, and byte limit.
3. Recognized CSV headers.
4. Valid package names and exact versions only.
5. Minimum package and exact-pair counts.
6. No count regression unless explicitly authorized.
7. No removal of any previously known exact package/version pair unless explicitly authorized.
8. Canonical LF serialization.
9. Atomic replacement of CSV and manifest.

`--allow-ioc-regression` is an emergency/manual-review escape hatch. It should never be used merely to make an update succeed.

## Auxiliary indicators

`iocs/hashes.json` and `iocs/persistence.json` are pinned rule files derived from the Socket Research incident report. Their SHA-256 values are bound into the source manifest so an unreviewed local edit causes IOC verification to fail.

After an intentional rule update, run the test suite, recompute the auxiliary hashes in `source-manifest.json`, and document the source and rationale in `CHANGELOG.md`.
