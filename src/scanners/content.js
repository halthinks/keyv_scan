'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { CAMPAIGN_URL, INCIDENT_URL, MAX_TEXT_INSPECTION_BYTES } = require('../constants');
const { hashBuffer, hashFileMany } = require('../util');
const { inspectLifecycleScripts, recordPackageOccurrence } = require('./packages');

const CANDIDATE_NAMES = new Set([
  'setup.mjs',
  'math_symbol.js',
  'math_init.js',
  'gh-token-monitor.sh',
  'com.user.gh-token-monitor.plist',
  'gh-token-monitor.service',
]);

const TEXT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.json', '.sh', '.bash', '.zsh', '.plist', '.service', '.txt', '.yaml', '.yml']);

function isCandidateName(name) {
  return CANDIDATE_NAMES.has(String(name || '').toLowerCase());
}

function hashIndex(iocs) {
  if (iocs._hashIndex) return iocs._hashIndex;
  const index = new Map();
  for (const entry of iocs.hashes) index.set(`${entry.algorithm}:${entry.hash}`, entry);
  Object.defineProperty(iocs, '_hashIndex', { value: index, enumerable: false });
  return index;
}

function addExactHashFinding(context, match, location, digest) {
  context.findings.add({
    rule_id: match.rule_id,
    title: 'Exact cryptographic hash match for a campaign artifact',
    description: match.description,
    category: match.algorithm === 'sha512' ? 'malicious-archive' : 'malicious-payload',
    severity: match.severity || 'critical',
    confidence: 'exact',
    source_kind: location.entry ? 'archive-entry' : 'filesystem',
    location,
    evidence: `${match.algorithm.toUpperCase()} ${digest}`,
    remediation_key: 'payload',
    references: [match.source || INCIDENT_URL, CAMPAIGN_URL],
    metadata: { algorithm: match.algorithm, hash: digest, known_names: match.names },
  });
  context.statistics.hash_matches += 1;
}

function inspectTextSignatures(context, text, location, nameHint) {
  const lowerName = String(nameHint || path.basename(location.path || '')).toLowerCase();
  const lower = text.toLowerCase();

  if (lowerName === 'setup.mjs') {
    const loaderMarkers = [
      'bun-v1.3.13',
      'math_symbol.js',
      'math_init.js',
      'oven-sh/bun/releases/download',
      'execfilesync',
      'bun-dl-',
    ].filter((marker) => lower.includes(marker));
    context.findings.add({
      rule_id: loaderMarkers.length >= 2 ? 'KVS-SUSPICIOUS-SETUP-LOADER' : 'KVS-SUSPICIOUS-FILENAME',
      title: loaderMarkers.length >= 2
        ? 'setup.mjs contains multiple documented campaign loader markers'
        : 'Campaign-associated loader filename exists but its hash is not currently recognized',
      description: 'The campaign used setup.mjs as an npm preinstall loader and as a repository autostart loader variant.',
      category: 'malicious-payload',
      severity: loaderMarkers.length >= 2 ? 'critical' : 'medium',
      confidence: loaderMarkers.length >= 2 ? 'strong' : 'heuristic',
      source_kind: location.entry ? 'archive-entry' : 'filesystem',
      location,
      evidence: loaderMarkers.length ? `Markers: ${loaderMarkers.join(', ')}` : 'Filename: setup.mjs',
      remediation_key: 'payload',
      references: [INCIDENT_URL],
    });
  }

  if (lowerName === 'math_symbol.js' || lowerName === 'math_init.js') {
    const payloadMarkers = [
      '[collector]',
      '[dispatcher]',
      '[provenance]',
      '[publish]',
      'registry.npmjs.org/-/whoami',
      'oidc/token/exchange/package',
      '169.254.169.254',
      'createcommitonbranch',
    ].filter((marker) => lower.includes(marker));
    context.findings.add({
      rule_id: payloadMarkers.length >= 2 ? 'KVS-SUSPICIOUS-SECOND-STAGE' : 'KVS-SUSPICIOUS-FILENAME',
      title: payloadMarkers.length >= 2
        ? 'Campaign-named second stage contains multiple documented capability markers'
        : 'Campaign-associated second-stage filename exists but its hash is not currently recognized',
      description: 'Math_Symbol.js and math_init.js are documented names for the same second-stage Bun payload.',
      category: 'malicious-payload',
      severity: payloadMarkers.length >= 2 ? 'critical' : 'high',
      confidence: payloadMarkers.length >= 2 ? 'strong' : 'heuristic',
      source_kind: location.entry ? 'archive-entry' : 'filesystem',
      location,
      evidence: payloadMarkers.length ? `Markers: ${payloadMarkers.join(', ')}` : `Filename: ${nameHint}`,
      remediation_key: 'payload',
      references: [INCIDENT_URL],
    });
  }

  if (lowerName === 'gh-token-monitor.sh') {
    const markers = ['http_status', 'handler', 'eval', 'github', 'started_file'].filter((marker) => lower.includes(marker));
    const strong = lower.includes('eval') && lower.includes('handler') && /(?:http_status|status)[^\n]{0,80}40(?:\[0-9\]|[0-9x])/i.test(lower);
    context.findings.add({
      rule_id: strong ? 'KVS-DEADMAN-SWITCH-SCRIPT' : 'KVS-SUSPICIOUS-PERSISTENCE-FILE',
      title: strong ? 'GitHub-token revocation dead-man switch script detected' : 'Campaign persistence filename detected',
      description: 'The documented watcher polls a stolen GitHub token and evaluates a handler when revocation causes an HTTP 4xx response.',
      category: 'persistence',
      severity: strong ? 'critical' : 'high',
      confidence: strong ? 'strong' : 'heuristic',
      source_kind: 'persistence',
      location,
      evidence: markers.length ? `Markers: ${markers.join(', ')}` : 'Filename: gh-token-monitor.sh',
      remediation_key: 'persistence',
      references: [INCIDENT_URL],
    });
  }

  if (lowerName === 'com.user.gh-token-monitor.plist' || lowerName === 'gh-token-monitor.service') {
    const strong = lower.includes('gh-token-monitor') && (lower.includes('keepalive') || lower.includes('github token validity monitor') || lower.includes('execstart'));
    context.findings.add({
      rule_id: strong ? 'KVS-PERSISTENCE-DEFINITION' : 'KVS-SUSPICIOUS-PERSISTENCE-FILE',
      title: 'Campaign-associated persistence service definition detected',
      description: 'The campaign used a macOS LaunchAgent or Linux systemd user service to keep the GitHub token monitor active.',
      category: 'persistence',
      severity: 'critical',
      confidence: strong ? 'strong' : 'heuristic',
      source_kind: 'persistence',
      location,
      evidence: `Persistence filename: ${nameHint}`,
      remediation_key: 'persistence',
      references: [INCIDENT_URL],
    });
  }

  const normalizedPath = String(location.entry || location.path || '').replace(/\\/g, '/').toLowerCase();
  if (normalizedPath.endsWith('/.claude/settings.json') || normalizedPath === '.claude/settings.json') {
    if (lower.includes('sessionstart') && (lower.includes('setup.mjs') || lower.includes('math_init.js') || lower.includes('math_symbol.js'))) {
      context.findings.add({
        rule_id: 'KVS-CLAUDE-AUTOSTART-HOOK',
        title: 'Claude SessionStart autostart hook references a campaign loader',
        description: 'The repository variant can execute without npm install when an AI coding agent opens the project.',
        category: 'malicious-hook',
        severity: 'critical',
        confidence: 'strong',
        source_kind: 'repository-autostart',
        location,
        evidence: 'SessionStart plus a documented loader or payload filename',
        remediation_key: 'hook',
        references: [INCIDENT_URL],
      });
    }
  }

  if (normalizedPath.endsWith('/.vscode/tasks.json') || normalizedPath === '.vscode/tasks.json') {
    if (lower.includes('folderopen') && (lower.includes('setup.mjs') || lower.includes('math_init.js') || lower.includes('math_symbol.js'))) {
      context.findings.add({
        rule_id: 'KVS-VSCODE-AUTOSTART-HOOK',
        title: 'VS Code folderOpen task references a campaign loader',
        description: 'The repository variant can execute when the folder is opened, without npm install.',
        category: 'malicious-hook',
        severity: 'critical',
        confidence: 'strong',
        source_kind: 'repository-autostart',
        location,
        evidence: 'folderOpen plus a documented loader or payload filename',
        remediation_key: 'hook',
        references: [INCIDENT_URL],
      });
    }
  }
}

function inspectPackageJsonBuffer(context, buffer, location) {
  try {
    const manifest = JSON.parse(buffer.toString('utf8'));
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
      throw new Error('package.json root must be an object');
    }
    recordPackageOccurrence(context, {
      name: manifest.name,
      version: manifest.version,
      path: location.path,
      entry: location.entry,
      sourceKind: location.entry ? 'archive' : undefined,
      evidence: location.entry ? 'archived package.json name/version' : 'package.json name/version',
    });
    inspectLifecycleScripts(context, manifest, location.path, location.entry);
  } catch (error) {
    const target = location.entry ? `${location.path}!${location.entry}` : location.path;
    context.addCoverageGap('archive-package-json', `${target}: ${error.message}`, 'warning');
  }
}

function inspectBufferArtifact(context, buffer, location, nameHint, options = {}) {
  const name = String(nameHint || path.basename(location.entry || location.path || ''));
  const lowerName = name.toLowerCase();
  const index = hashIndex(context.iocs);
  const sha256 = hashBuffer(buffer, 'sha256');
  const sha256Match = index.get(`sha256:${sha256}`);
  if (sha256Match) addExactHashFinding(context, sha256Match, location, sha256);

  if (options.computeSha512) {
    const sha512 = hashBuffer(buffer, 'sha512');
    const sha512Match = index.get(`sha512:${sha512}`);
    if (sha512Match) addExactHashFinding(context, sha512Match, location, sha512);
  }

  if (lowerName === 'package.json') inspectPackageJsonBuffer(context, buffer, location);

  const extension = path.extname(lowerName);
  if (isCandidateName(lowerName) || TEXT_EXTENSIONS.has(extension) || options.inspectText) {
    if (buffer.length <= MAX_TEXT_INSPECTION_BYTES && !buffer.includes(0)) {
      inspectTextSignatures(context, buffer.toString('utf8'), location, name);
    } else if (isCandidateName(lowerName) && !sha256Match) {
      context.findings.add({
        rule_id: 'KVS-SUSPICIOUS-FILENAME',
        title: 'Campaign-associated artifact filename detected',
        description: 'The filename is documented in the campaign, but the file was binary or too large for text inspection and did not match a currently known hash.',
        category: 'malicious-payload',
        severity: 'high',
        confidence: 'heuristic',
        source_kind: location.entry ? 'archive-entry' : 'filesystem',
        location,
        evidence: `Filename: ${name}`,
        remediation_key: 'payload',
        references: [INCIDENT_URL],
      });
    }
  }
  return { sha256, sha256Match };
}

async function inspectFileArtifact(context, file, options = {}) {
  const name = path.basename(file);
  const lowerName = name.toLowerCase();
  const extension = path.extname(lowerName);
  const candidate = isCandidateName(lowerName);
  const shouldRead = candidate || options.deep || options.hashAll || options.inspectText || options.computeSha512;
  if (!shouldRead) return;

  try {
    const stat = await fsp.stat(file);
    const maxBytes = options.maxBytes || MAX_TEXT_INSPECTION_BYTES;
    if (stat.size > maxBytes) {
      const algorithms = ['sha256'];
      if (options.computeSha512) algorithms.push('sha512');
      const digests = await hashFileMany(file, algorithms);
      const index = hashIndex(context.iocs);
      let sha256Match = false;
      for (const algorithm of algorithms) {
        const digest = digests[algorithm];
        const match = index.get(`${algorithm}:${digest}`);
        if (match) {
          addExactHashFinding(context, match, { path: file }, digest);
          if (algorithm === 'sha256') sha256Match = true;
        }
      }
      if (candidate && !sha256Match) {
        context.findings.add({
          rule_id: 'KVS-SUSPICIOUS-FILENAME',
          title: 'Campaign-associated artifact filename detected',
          description: 'The candidate exceeded the content-inspection limit and did not match a known SHA-256.',
          category: 'malicious-payload',
          severity: 'high',
          confidence: 'heuristic',
          source_kind: 'filesystem',
          location: { path: file },
          evidence: `Filename: ${name}; size ${stat.size} bytes`,
          remediation_key: 'payload',
          references: [INCIDENT_URL],
        });
      }
      if (options.inspectText && !candidate) {
        context.addCoverageGap(
          'artifact-content-limit',
          `${file}: text inspection skipped because ${stat.size} bytes exceeds the ${maxBytes}-byte limit`,
          options.required ? 'error' : 'warning',
        );
      }
      context.statistics.artifacts_inspected += 1;
      return;
    }

    const buffer = await fsp.readFile(file);
    inspectBufferArtifact(context, buffer, { path: file }, name, {
      computeSha512: options.computeSha512 || ['.tgz', '.gz'].includes(extension),
      inspectText: options.inspectText,
    });
    context.statistics.artifacts_inspected += 1;
  } catch (error) {
    context.addOperationalError('artifact-inspection', file, error, { incomplete: candidate || options.inspectText || options.computeSha512 || options.deep || options.required });
  }
}

module.exports = {
  CANDIDATE_NAMES,
  inspectBufferArtifact,
  inspectFileArtifact,
  inspectPackageJsonBuffer,
  inspectTextSignatures,
  isCandidateName,
};
