'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { ScanContext } = require('../src/context');
const { parseNpmAliasSpec, scanDependencyDeclarations } = require('../src/scanners/packages');

test('parses unscoped and scoped npm aliases', () => {
  assert.deepEqual(parseNpmAliasSpec('npm:keyv@6.0.0'), { name: 'keyv', spec: '6.0.0', raw: 'npm:keyv@6.0.0' });
  assert.deepEqual(parseNpmAliasSpec('npm:@scope/name@1.2.3'), { name: '@scope/name', spec: '1.2.3', raw: 'npm:@scope/name@1.2.3' });
  assert.equal(parseNpmAliasSpec('^1.0.0'), null);
});

test('detects an affected package hidden behind an npm alias', () => {
  const context = new ScanContext({
    iocs: { packages: new Map([['keyv', new Set(['6.0.0'])]]) },
    options: { includePotential: true },
    scannerRoot: process.cwd(),
  });
  scanDependencyDeclarations(context, { dependencies: { harmlessName: 'npm:keyv@6.0.0' } }, '/tmp/package.json');
  const findings = context.findings.values();
  assert.equal(findings.length, 1);
  assert.equal(findings[0].package.name, 'keyv');
  assert.equal(findings[0].package.version, '6.0.0');
  assert.equal(findings[0].metadata.declared_as, 'harmlessName');
});

test('no-potential suppresses ranges and tags but preserves exact affected declarations', () => {
  const context = new ScanContext({
    iocs: { packages: new Map([['keyv', new Set(['6.0.0'])]]) },
    options: { includePotential: false },
    scannerRoot: process.cwd(),
  });
  scanDependencyDeclarations(context, {
    dependencies: { exact: 'npm:keyv@6.0.0', keyv: '^6.0.0' },
  }, '/tmp/package.json');
  const findings = context.findings.values();
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule_id, 'KVS-DECLARED-EXACT-AFFECTED');
  assert.equal(findings[0].package.version, '6.0.0');
});
