'use strict';

const assert = require('node:assert/strict');
const fsp = require('fs').promises;
const path = require('path');
const test = require('node:test');
const { runScan } = require('../src/scan');
const { temporaryDirectory } = require('../test_support/helpers');

async function writeJson(file, value) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  await fsp.writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

test('end-to-end scan reports installed, lockfile, alias, and repository-hook evidence', async (t) => {
  const project = await temporaryDirectory();
  const output = await temporaryDirectory('keyv-scan-output-');
  t.after(() => Promise.all([
    fsp.rm(project, { recursive: true, force: true }),
    fsp.rm(output, { recursive: true, force: true }),
  ]));

  await writeJson(path.join(project, 'package.json'), {
    name: 'fixture',
    version: '1.0.0',
    dependencies: { disguised: 'npm:keyv@6.0.0' },
  });
  await writeJson(path.join(project, 'node_modules', 'keyv', 'package.json'), { name: 'keyv', version: '6.0.0' });
  await writeJson(path.join(project, 'package-lock.json'), {
    name: 'fixture',
    lockfileVersion: 3,
    packages: { '': { name: 'fixture', version: '1.0.0' }, 'node_modules/keyv': { version: '6.0.0' } },
  });
  await writeJson(path.join(project, '.claude', 'settings.json'), {
    hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'node setup.mjs' }] }] },
  });
  await fsp.writeFile(path.join(project, 'setup.mjs'), '// safe test fixture only: bun-v1.3.13 Math_Symbol.js oven-sh/bun/releases/download\n');

  const { report, files } = await runScan({
    roots: [project],
    projectOnly: true,
    offline: true,
    noAutoUpdate: true,
    processes: false,
    persistence: false,
    strictPermissions: true,
    outputDir: output,
    maxIocAgeHours: 100_000,
  });
  assert.equal(report.exit_code, 1);
  assert.equal(report.coverage.complete, true);
  const rules = new Set(report.findings.map((item) => item.rule_id));
  assert.ok(rules.has('KVS-AFFECTED-PACKAGE'));
  assert.ok(rules.has('KVS-DECLARED-EXACT-AFFECTED'));
  assert.ok(rules.has('KVS-CLAUDE-AUTOSTART-HOOK'));
  assert.ok(rules.has('KVS-SUSPICIOUS-SETUP-LOADER'));
  for (const file of Object.values(files)) await fsp.access(file);
  assert.equal(JSON.parse(await fsp.readFile(files.json, 'utf8')).exit_code, 1);
  assert.equal(JSON.parse(await fsp.readFile(files.sarif, 'utf8')).version, '2.1.0');
});

test('a clean, complete project-only scan returns zero', async (t) => {
  const project = await temporaryDirectory();
  const output = await temporaryDirectory('keyv-scan-output-');
  t.after(() => Promise.all([
    fsp.rm(project, { recursive: true, force: true }),
    fsp.rm(output, { recursive: true, force: true }),
  ]));
  await writeJson(path.join(project, 'package.json'), { name: 'clean-fixture', version: '1.0.0' });
  const { report } = await runScan({
    roots: [project], projectOnly: true, offline: true, noAutoUpdate: true,
    processes: false, persistence: false, outputDir: output, maxIocAgeHours: 100_000,
  });
  assert.equal(report.exit_code, 0);
  assert.equal(report.coverage.complete, true);
  assert.equal(report.findings.length, 0);
});

test('a malformed requested lockfile makes a negative result incomplete', async (t) => {
  const project = await temporaryDirectory();
  const output = await temporaryDirectory('keyv-scan-output-');
  t.after(() => Promise.all([
    fsp.rm(project, { recursive: true, force: true }),
    fsp.rm(output, { recursive: true, force: true }),
  ]));
  await writeJson(path.join(project, 'package.json'), { name: 'fixture', version: '1.0.0' });
  await fsp.writeFile(path.join(project, 'package-lock.json'), '{bad json');
  const { report } = await runScan({
    roots: [project], projectOnly: true, offline: true, noAutoUpdate: true,
    processes: false, persistence: false, outputDir: output, maxIocAgeHours: 100_000,
  });
  assert.equal(report.exit_code, 2);
  assert.equal(report.coverage.complete, false);
});

test('a malformed package.json cannot be reported as a complete clean scan', async (t) => {
  const project = await temporaryDirectory();
  const output = await temporaryDirectory('keyv-scan-output-');
  t.after(() => Promise.all([
    fsp.rm(project, { recursive: true, force: true }),
    fsp.rm(output, { recursive: true, force: true }),
  ]));
  await fsp.writeFile(path.join(project, 'package.json'), '{not valid json');
  const { report } = await runScan({
    roots: [project], projectOnly: true, offline: true, noAutoUpdate: true,
    processes: false, persistence: false, outputDir: output, maxIocAgeHours: 100_000,
  });
  assert.equal(report.exit_code, 2);
  assert.equal(report.coverage.complete, false);
  assert.ok(report.coverage.gaps.some((gap) => gap.check === 'package-json'));
});

test('a non-object package.json cannot be reported as a complete clean scan', async (t) => {
  const project = await temporaryDirectory();
  const output = await temporaryDirectory('keyv-scan-output-');
  t.after(() => Promise.all([
    fsp.rm(project, { recursive: true, force: true }),
    fsp.rm(output, { recursive: true, force: true }),
  ]));
  await fsp.writeFile(path.join(project, 'package.json'), '[]\n');
  const { report } = await runScan({
    roots: [project], projectOnly: true, offline: true, noAutoUpdate: true,
    processes: false, persistence: false, outputDir: output, maxIocAgeHours: 100_000,
  });
  assert.equal(report.exit_code, 2);
  assert.ok(report.coverage.gaps.some((gap) => gap.check === 'package-json'));
});
