# Migration from `AlextheYounga/keyv_scan`

This package retains `check_packages.sh` as a compatibility entry point, but the underlying behavior is intentionally broader and fail-closed.

## Important differences

- The Wiz CSV is parsed in its real quoted-CSV form; no `==` transformation is required.
- A feed that loads zero or too few indicators is rejected rather than reported clean.
- Exact-pair regressions are detected, not only total-count regressions.
- Lockfiles, Bun, caches, archives, payload hashes, autostart hooks, persistence, temp artifacts, and processes are included.
- Negative results can return exit code `2` when coverage is incomplete.
- Reports are emitted as text, JSON, and SARIF.
- Target files are never deleted or changed.

Existing automation that treated every nonzero result as “infected” should be updated to distinguish exit code `2` from `1`, while still failing the job for both.
