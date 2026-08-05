'use strict';

const path = require('path');
const { deterministicId, sortFindings } = require('./util');

const REMEDIATION = Object.freeze({
  installed: 'Isolate the host, preserve evidence, remove documented persistence before rotating credentials, then rebuild from trusted dependencies.',
  lockfile: 'Replace the affected version, regenerate the lockfile from a trusted source, and investigate whether install scripts ran on this host or CI runner.',
  cache: 'Preserve evidence if needed, clear the affected package-manager cache only after investigation, and verify that no affected version was installed.',
  payload: 'Treat this as evidence of compromise. Isolate the host and engage incident response before deleting the artifact.',
  persistence: 'Do not rotate GitHub or npm credentials until the documented token-monitor dead-man switch has been disabled and preserved for investigation.',
  hook: 'Treat the repository or package as hostile. Do not open it in an agent-enabled IDE or run package installation until the hook is removed and investigated.',
  declaration: 'Pin to a known-clean exact version and regenerate the lockfile. A declaration alone does not prove installation or execution.',
});

function createFinding(input) {
  const normalizedPath = input.location?.path ? path.resolve(input.location.path) : undefined;
  const finding = {
    id: input.id || deterministicId(
      input.rule_id,
      normalizedPath,
      input.location?.entry,
      input.package?.name,
      input.package?.version,
      input.evidence,
    ),
    rule_id: input.rule_id,
    title: input.title,
    description: input.description,
    category: input.category,
    severity: input.severity,
    confidence: input.confidence,
    source_kind: input.source_kind,
    package: input.package,
    location: normalizedPath || input.location?.entry
      ? { ...input.location, path: normalizedPath }
      : undefined,
    evidence: input.evidence,
    remediation: input.remediation || REMEDIATION[input.remediation_key] || REMEDIATION.payload,
    references: input.references || [],
    metadata: input.metadata,
  };

  for (const [key, value] of Object.entries(finding)) {
    if (value === undefined || value === null || value === '') delete finding[key];
  }
  return finding;
}

class FindingStore {
  constructor() {
    this.byId = new Map();
  }

  add(input) {
    const finding = input.id ? input : createFinding(input);
    if (!this.byId.has(finding.id)) this.byId.set(finding.id, finding);
    return finding;
  }

  values() {
    return sortFindings([...this.byId.values()]);
  }

  get size() {
    return this.byId.size;
  }
}

module.exports = {
  FindingStore,
  REMEDIATION,
  createFinding,
};
