'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { ScanContext } = require('../src/context');
const { inspectBufferArtifact, inspectFileArtifact } = require('../src/scanners/content');
const { hashBuffer } = require('../src/util');

test('detects exact custom hash and safe synthetic campaign markers', () => {
  const benign = Buffer.from('safe synthetic fixture');
  const context = new ScanContext({
    iocs: {
      packages: new Map(),
      hashes: [{
        algorithm: 'sha256',
        hash: hashBuffer(benign),
        rule_id: 'KVS-TEST-HASH',
        severity: 'critical',
        description: 'test-only hash',
        source: 'https://example.invalid',
      }],
    },
    options: {},
    scannerRoot: process.cwd(),
  });
  inspectBufferArtifact(context, benign, { path: '/tmp/fixture.bin' }, 'fixture.bin');
  inspectBufferArtifact(context, Buffer.from('// fixture markers: bun-v1.3.13 Math_Symbol.js oven-sh/bun/releases/download'), { path: '/tmp/setup.mjs' }, 'setup.mjs', { inspectText: true });
  const rules = context.findings.values().map((item) => item.rule_id);
  assert.ok(rules.includes('KVS-TEST-HASH'));
  assert.ok(rules.includes('KVS-SUSPICIOUS-SETUP-LOADER'));
});

test('oversized artifacts use streaming SHA-256 and SHA-512 matching', async (t) => {
  const fsp = require('node:fs').promises;
  const path = require('node:path');
  const { temporaryDirectory } = require('../test_support/helpers');
  const directory = await temporaryDirectory();
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const data = Buffer.from('streamed hash fixture larger than the test inspection limit');
  const file = path.join(directory, 'archive-object');
  await fsp.writeFile(file, data);
  const context = new ScanContext({
    iocs: {
      packages: new Map(),
      hashes: [
        { algorithm: 'sha256', hash: hashBuffer(data, 'sha256'), rule_id: 'KVS-STREAM-SHA256', severity: 'critical', description: 'fixture', source: 'https://example.invalid' },
        { algorithm: 'sha512', hash: hashBuffer(data, 'sha512'), rule_id: 'KVS-STREAM-SHA512', severity: 'critical', description: 'fixture', source: 'https://example.invalid' },
      ],
    },
    options: {},
    scannerRoot: process.cwd(),
  });
  await inspectFileArtifact(context, file, { hashAll: true, computeSha512: true, maxBytes: 4 });
  const rules = new Set(context.findings.values().map((finding) => finding.rule_id));
  assert.ok(rules.has('KVS-STREAM-SHA256'));
  assert.ok(rules.has('KVS-STREAM-SHA512'));
});
