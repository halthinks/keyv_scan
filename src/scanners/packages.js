'use strict';

const path = require('path');
const { CAMPAIGN_URL, INCIDENT_URL, MAX_JSON_BYTES } = require('../constants');
const { classifySpec } = require('../semver');
const { readJsonFile } = require('../util');

function parseNpmAliasSpec(spec) {
  const raw = String(spec || '').trim();
  if (!raw.toLowerCase().startsWith('npm:')) return null;
  const target = raw.slice(4).trim();
  if (!target) return null;
  let separator = -1;
  if (target.startsWith('@')) {
    const slash = target.indexOf('/');
    if (slash === -1) return null;
    separator = target.indexOf('@', slash + 1);
  } else {
    separator = target.indexOf('@');
  }
  if (separator === -1) return { name: target, spec: '*', raw };
  const name = target.slice(0, separator).trim();
  const aliasSpec = target.slice(separator + 1).trim() || '*';
  return name ? { name, spec: aliasSpec, raw } : null;
}

function inferSourceKind(file, rootKind = 'project') {
  const normalized = file.replace(/\\/g, '/').toLowerCase();
  if (rootKind.includes('cache') || /\/(?:\.npm|npm-cache|_cacache|pnpm-store|\.pnpm-store|\.yarn\/cache|\.cache\/yarn|\.bun\/install\/cache)\//.test(normalized)) return 'cache';
  if (rootKind.includes('global')) return 'installed-global';
  if (/\/node_modules\//.test(normalized) || /\/\.yarn\/unplugged\//.test(normalized) || /\/\.pnpm\//.test(normalized)) return 'installed-project';
  return rootKind === 'archive' ? 'archive' : 'source-tree';
}

function severityForOccurrence(sourceKind) {
  if (sourceKind.startsWith('installed')) return 'critical';
  if (sourceKind === 'lockfile') return 'high';
  if (sourceKind === 'archive') return 'high';
  if (sourceKind === 'cache') return 'medium';
  return 'high';
}

function occurrenceTitle(sourceKind) {
  if (sourceKind.startsWith('installed')) return 'Confirmed affected package version is installed';
  if (sourceKind === 'lockfile') return 'Affected package version is resolved in a lockfile';
  if (sourceKind === 'archive') return 'Affected package version is present in a package archive';
  if (sourceKind === 'cache') return 'Affected package version is present in a package-manager cache';
  return 'Affected package version is present in a source tree';
}

function recordPackageOccurrence(context, occurrence) {
  if (!occurrence?.name || !occurrence?.version) return false;
  const affected = context.iocs.packages.get(occurrence.name);
  if (!affected || !affected.has(occurrence.version)) return false;
  const sourceKind = occurrence.sourceKind || inferSourceKind(occurrence.path || '', occurrence.rootKind);
  context.findings.add({
    rule_id: 'KVS-AFFECTED-PACKAGE',
    title: occurrenceTitle(sourceKind),
    description: 'The exact package name and version matches the validated Keyv/Cacheable campaign IOC feed.',
    category: 'affected-package',
    severity: severityForOccurrence(sourceKind),
    confidence: 'exact',
    source_kind: sourceKind,
    package: { name: occurrence.name, version: occurrence.version },
    location: { path: occurrence.path, entry: occurrence.entry, line: occurrence.line },
    evidence: `Exact IOC match from ${occurrence.evidence || sourceKind}`,
    remediation_key: sourceKind === 'cache' ? 'cache' : sourceKind === 'lockfile' ? 'lockfile' : 'installed',
    references: [CAMPAIGN_URL, INCIDENT_URL],
    metadata: occurrence.metadata,
  });
  context.statistics.package_occurrences += 1;
  return true;
}

function scanDependencyDeclarations(context, manifest, file) {
  const includePotential = context.options.includePotential !== false;
  const groups = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies'];
  for (const group of groups) {
    const dependencies = manifest[group];
    if (!dependencies) continue;
    if (Array.isArray(dependencies)) {
      if (!includePotential) continue;
      for (const packageName of dependencies) {
        if (!context.iocs.packages.has(packageName)) continue;
        context.findings.add({
          rule_id: 'KVS-DECLARED-AFFECTED-PACKAGE',
          title: 'Manifest bundles a package name affected by the campaign',
          description: 'The manifest lists an affected package name but does not identify the resolved exact version.',
          category: 'dependency-declaration',
          severity: 'medium',
          confidence: 'potential',
          source_kind: 'manifest',
          package: { name: packageName },
          location: { path: file },
          evidence: `${group} includes ${packageName}; inspect the built package contents and lockfile`,
          remediation_key: 'declaration',
          references: [CAMPAIGN_URL],
        });
      }
      continue;
    }
    if (typeof dependencies !== 'object') continue;

    for (const [declaredName, spec] of Object.entries(dependencies)) {
      const alias = parseNpmAliasSpec(spec);
      const packageName = alias?.name || declaredName;
      const effectiveSpec = alias?.spec || spec;
      const affected = context.iocs.packages.get(packageName);
      if (!affected) continue;
      const classification = classifySpec(effectiveSpec, [...affected]);
      const declarationEvidence = `${group}.${declaredName} = ${JSON.stringify(spec)}${alias ? `; npm alias target ${packageName}@${effectiveSpec}` : ''}`;
      const declarationMetadata = alias ? { declared_as: declaredName, alias_target: packageName, alias_spec: effectiveSpec } : undefined;
      if (classification.status === 'exact-affected') {
        context.findings.add({
          rule_id: 'KVS-DECLARED-EXACT-AFFECTED',
          title: 'Manifest directly declares an affected exact package version',
          description: 'The dependency declaration itself pins an exact version present in the campaign IOC feed.',
          category: 'dependency-declaration',
          severity: 'high',
          confidence: 'exact',
          source_kind: 'manifest',
          package: { name: packageName, version: classification.matches[0] },
          location: { path: file },
          evidence: declarationEvidence,
          remediation_key: 'declaration',
          references: [CAMPAIGN_URL],
          metadata: declarationMetadata,
        });
      } else if (includePotential && classification.status === 'range-includes-affected') {
        const preview = classification.matches.slice(0, 8).join(', ');
        context.findings.add({
          rule_id: 'KVS-DECLARED-RANGE-EXPOSED',
          title: 'Dependency range can resolve to affected campaign versions',
          description: 'The manifest range admits at least one exact malicious version, although the installed version must be confirmed from a lockfile or package tree.',
          category: 'dependency-declaration',
          severity: 'medium',
          confidence: 'potential',
          source_kind: 'manifest',
          package: { name: packageName },
          location: { path: file },
          evidence: `${declarationEvidence}; affected admitted: ${preview}${classification.matches.length > 8 ? ' …' : ''}`,
          remediation_key: 'declaration',
          references: [CAMPAIGN_URL],
          metadata: { ...declarationMetadata, admitted_versions: classification.matches },
        });
      } else if (includePotential && classification.status === 'tag-or-unknown') {
        context.findings.add({
          rule_id: 'KVS-DECLARED-TAG-UNRESOLVED',
          title: 'Affected package is declared through a mutable or unrecognized tag',
          description: 'A mutable tag or unsupported specification prevents a deterministic clean result from the manifest alone.',
          category: 'dependency-declaration',
          severity: 'low',
          confidence: 'potential',
          source_kind: 'manifest',
          package: { name: packageName },
          location: { path: file },
          evidence: declarationEvidence,
          remediation_key: 'declaration',
          references: [CAMPAIGN_URL],
          metadata: declarationMetadata,
        });
      }
    }
  }
}

function inspectLifecycleScripts(context, manifest, file, entry) {
  const scripts = manifest?.scripts;
  if (!scripts || typeof scripts !== 'object') return;
  for (const [name, command] of Object.entries(scripts)) {
    if (typeof command !== 'string') continue;
    const normalized = command.toLowerCase();
    if (/\bsetup\.mjs\b/.test(normalized) || /\bmath_symbol\.js\b/.test(normalized) || /\bmath_init\.js\b/.test(normalized)) {
      context.findings.add({
        rule_id: 'KVS-MALICIOUS-LIFECYCLE-HOOK',
        title: 'Package lifecycle script references a campaign loader or payload name',
        description: 'The campaign used a preinstall hook invoking setup.mjs, which then executed Math_Symbol.js or math_init.js through a downloaded Bun runtime.',
        category: 'malicious-hook',
        severity: name === 'preinstall' ? 'critical' : 'high',
        confidence: 'strong',
        source_kind: entry ? 'archive' : inferSourceKind(file),
        package: manifest.name && manifest.version ? { name: manifest.name, version: manifest.version } : undefined,
        location: { path: file, entry },
        evidence: `scripts.${name} references a documented campaign filename`,
        remediation_key: 'hook',
        references: [INCIDENT_URL],
      });
    }
  }
}

async function scanPackageJson(context, file, rootKind = 'project') {
  let manifest;
  try {
    manifest = await readJsonFile(file, MAX_JSON_BYTES);
  } catch (error) {
    context.addOperationalError('package-json', file, error, { incomplete: true });
    return;
  }
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    context.addCoverageGap('package-json', `${file}: package.json root must be an object`, 'error');
    return;
  }
  context.statistics.package_json_files += 1;
  if (manifest && typeof manifest === 'object') {
    const sourceKind = inferSourceKind(file, rootKind);
    recordPackageOccurrence(context, {
      name: manifest.name,
      version: manifest.version,
      path: file,
      rootKind,
      sourceKind,
      evidence: 'package.json name/version',
    });
    inspectLifecycleScripts(context, manifest, file);
    if (sourceKind === 'source-tree') scanDependencyDeclarations(context, manifest, file);
  }
}

function inspectMetadataObject(context, value, location, options = {}) {
  const seen = new Set();
  const stack = [value];
  let visited = 0;
  const maxNodes = options.maxNodes || 100_000;
  while (stack.length) {
    const current = stack.pop();
    if (!current || typeof current !== 'object' || seen.has(current)) continue;
    seen.add(current);
    visited += 1;
    if (visited > maxNodes) {
      context.addCoverageGap('metadata-recursion', `Stopped after ${maxNodes} objects while inspecting ${location.path}`, 'warning');
      break;
    }
    if (typeof current.name === 'string' && typeof current.version === 'string') {
      recordPackageOccurrence(context, {
        name: current.name,
        version: current.version,
        path: location.path,
        entry: location.entry,
        sourceKind: options.sourceKind || 'cache',
        evidence: options.evidence || 'cache metadata name/version',
      });
    }
    for (const child of Object.values(current)) {
      if (child && typeof child === 'object') stack.push(child);
    }
  }
}

module.exports = {
  inferSourceKind,
  parseNpmAliasSpec,
  inspectLifecycleScripts,
  inspectMetadataObject,
  recordPackageOccurrence,
  scanDependencyDeclarations,
  scanPackageJson,
  severityForOccurrence,
};
