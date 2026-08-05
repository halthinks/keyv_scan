# Report format

The authoritative schema is [`../schemas/report.schema.json`](../schemas/report.schema.json).

## Top-level sections

- `scanner`: scanner identity, version, and read-only declaration.
- `campaign`: campaign name and source references.
- `scan`: timestamps, roots, options, host metadata, and output directory.
- `iocs`: exact hashes/counts/freshness and update events.
- `coverage`: completion state, explicit gaps, and operational errors.
- `statistics`: files, bytes, package manifests, lockfiles, archives, cache records, persistence paths, and processes examined.
- `summary`: finding counts and configured failure threshold.
- `findings`: de-duplicated evidence objects.
- `fatal_errors`: scanner-level failures captured after initialization.
- `exit_code`: 0–3 bitmask result.

## Finding fields

Each finding includes a deterministic `id`, a stable `rule_id`, title, category, severity, confidence, source kind, location, evidence, remediation, references, and optional package/metadata fields.

Confidence values have these meanings:

- `exact`: cryptographic hash or exact package/version IOC match.
- `strong`: multiple documented behavioral/content indicators or an exact documented persistence path.
- `potential`: declaration/range evidence requiring resolution confirmation.
- `heuristic`: filename, process text, or other lower-specificity evidence.

## Coverage

`coverage.complete` is true only when no requested check produced a coverage gap or fatal error. Operational errors can be recorded without making coverage incomplete when they affect optional/non-determinative locations. Every incomplete condition is retained in `coverage.gaps` and represented in SARIF as `KVS-SCAN-INCOMPLETE`.
