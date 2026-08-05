# Rule reference

| Rule ID | Evidence |
|---|---|
| `KVS-AFFECTED-PACKAGE` | Exact package/version IOC in an installed tree, lockfile, archive, cache, or source package manifest |
| `KVS-DECLARED-AFFECTED-PACKAGE` | Bundled dependency name with unresolved exact version |
| `KVS-DECLARED-EXACT-AFFECTED` | Manifest pins an exact affected version, including through an npm alias |
| `KVS-DECLARED-RANGE-EXPOSED` | Manifest semver range admits one or more exact affected versions |
| `KVS-DECLARED-TAG-UNRESOLVED` | Affected package declared through a mutable/unrecognized tag |
| `KVS-MALICIOUS-LIFECYCLE-HOOK` | Lifecycle script invokes a documented campaign loader/payload filename |
| `KVS-BUN-LOCKB-HEURISTIC` | Binary Bun lock contains exact affected package/version bytes after Bun-assisted resolution failed |
| `KVS-HASH-SETUP-NPM` | Exact SHA-256 of the npm-tarball `setup.mjs` loader |
| `KVS-HASH-SETUP-REPOSITORY` | Exact SHA-256 of the repository-autostart `setup.mjs` variant |
| `KVS-HASH-PAYLOAD` | Exact SHA-256 of the documented second-stage payload |
| `KVS-HASH-KEYV-TARBALL` | Exact SHA-512 of the documented malicious `keyv@6.0.0` tarball |
| `KVS-SUSPICIOUS-SETUP-LOADER` | `setup.mjs` with multiple documented loader markers |
| `KVS-SUSPICIOUS-SECOND-STAGE` | Campaign-named second stage with multiple documented capability markers |
| `KVS-SUSPICIOUS-FILENAME` | Campaign-associated filename without an exact current hash match |
| `KVS-CLAUDE-AUTOSTART-HOOK` | Claude `SessionStart` hook references a campaign loader/payload |
| `KVS-VSCODE-AUTOSTART-HOOK` | VS Code `folderOpen` task references a campaign loader/payload |
| `KVS-PERSISTENCE-PATH` | Exact documented token-monitor persistence/state path exists |
| `KVS-DEADMAN-SWITCH-SCRIPT` | Token-monitor script contains documented watcher/handler behavior |
| `KVS-PERSISTENCE-DEFINITION` | LaunchAgent/systemd definition contains token-monitor behavior |
| `KVS-SUSPICIOUS-PERSISTENCE-FILE` | Campaign persistence filename without enough content for a strong behavioral match |
| `KVS-PERSISTENCE-TEMP-ARTIFACT` | Token-monitor temporary log/artifact name |
| `KVS-BUN-DOWNLOAD-TEMP` | `bun-dl-*` temporary execution artifact |
| `KVS-SUSPICIOUS-PROCESS` | Running process command line contains campaign indicators |
| `KVS-SCAN-INCOMPLETE` | SARIF-only rule representing an explicit coverage gap |

Hash-backed rule values and source URLs are in `iocs/hashes.json`. Persistence paths and process indicators are in `iocs/persistence.json`.
