# Incident response playbook

This scanner is evidence collection and triage tooling. It does not remove malware or certify a host as clean.

## Severity triage

### Immediate compromise indicators

Treat these as potential host compromise:

- exact SHA-256 match for `setup.mjs`, `Math_Symbol.js`, or `math_init.js`;
- exact SHA-512 match for the documented malicious `keyv@6.0.0` tarball;
- an installed exact affected package version on a host where package lifecycle scripts may have run;
- a Claude `SessionStart` or VS Code `folderOpen` hook invoking campaign filenames;
- `gh-token-monitor` script/state, LaunchAgent, systemd unit, or active process;
- a package lifecycle script invoking `setup.mjs` or a documented second-stage filename.

### Exposure indicators requiring investigation

- affected exact version in a lockfile;
- affected archive in a cache;
- package-manager cache metadata or path match;
- a dependency range that admits an affected version;
- an unrecognized candidate filename with no exact hash match.

## Required response sequence

1. **Isolate the host or runner.** Prevent new network access and package publication while preserving evidence.
2. **Preserve volatile state.** Save the scanner reports, process list, network connections, environment/CI context, relevant shell history, package-manager logs, and service definitions.
3. **Locate the token monitor before revocation.** Inspect the documented paths in the report. Do not read or paste stored token/handler contents into tickets or chat systems.
4. **Disable and preserve persistence.** Stop/unload the LaunchAgent or systemd user unit and neutralize the watcher in a controlled forensic workflow. Preserve copies and hashes.
5. **Then rotate credentials.** Rotate GitHub, npm, cloud, Vault, Kubernetes, CI, SSH, signing, and other credentials accessible from the host.
6. **Audit downstream abuse.** Review npm publications, package ownership, GitHub repositories and Actions, cloud audit logs, secret-manager access, Kubernetes audit logs, and DNS/network telemetry.
7. **Rebuild rather than clean in place.** Reimage developer machines and recreate CI runners from trusted infrastructure. Regenerate dependency trees and lockfiles from known-clean versions.
8. **Rescan and monitor.** Run the scanner on restored systems and monitor identity/registry/cloud activity for delayed abuse.

## Evidence to preserve

- `report.json`, `report.sarif`, and `report.txt`;
- affected `package.json` and lockfiles;
- package-manager cache index records and referenced cache objects;
- hashes, timestamps, owners, and permissions for candidate payload/persistence files;
- LaunchAgent/systemd definitions;
- process listings and command lines;
- CI job logs and artifacts;
- npm/GitHub/cloud audit logs;
- a disk or VM snapshot when organizational policy permits.

## Do not

- do not treat deletion of `node_modules` as remediation;
- do not clear caches before preserving useful evidence;
- do not execute candidate JavaScript to “test” it;
- do not open a suspicious repository in an agent-enabled IDE before inspecting `.claude` and `.vscode` hooks;
- do not publish sensitive token/handler file contents in incident tickets;
- do not suppress exit code `2`, which means coverage was incomplete.
