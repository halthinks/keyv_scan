'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { digestHexFromIntegrity, digestsFromIntegrity, extractPackageFromRegistryUrl } = require('../src/scanners/filesystem');

test('extracts scoped and unscoped registry tarball identities', () => {
  assert.deepEqual(extractPackageFromRegistryUrl('https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz'), { name: 'keyv', version: '6.0.0' });
  assert.deepEqual(extractPackageFromRegistryUrl('https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz'), { name: '@scope/pkg', version: '1.2.3' });
});

test('parses multiple Subresource Integrity digests', () => {
  const sha256 = Buffer.alloc(32, 1).toString('base64');
  const sha512 = Buffer.alloc(64, 2).toString('base64');
  const parsed = digestsFromIntegrity(`sha256-${sha256} sha512-${sha512}`);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].algorithm, 'sha256');
  assert.equal(parsed[1].algorithm, 'sha512');
  assert.deepEqual(digestHexFromIntegrity(`sha256-${sha256}`), parsed[0]);
});

test('hash-all detects a known digest after the payload is renamed to an unrelated extension', async (t) => {
  const fsp = require('node:fs').promises;
  const path = require('node:path');
  const { ScanContext } = require('../src/context');
  const { processFile } = require('../src/scanners/filesystem');
  const { hashBuffer } = require('../src/util');
  const { temporaryDirectory } = require('../test_support/helpers');
  const directory = await temporaryDirectory();
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const data = Buffer.from('safe renamed hash fixture');
  const file = path.join(directory, 'unrelated.data');
  await fsp.writeFile(file, data);
  const context = new ScanContext({
    iocs: {
      packages: new Map(),
      hashes: [{ algorithm: 'sha256', hash: hashBuffer(data), rule_id: 'KVS-RENAMED-TEST', severity: 'critical', description: 'fixture', source: 'https://example.invalid' }],
    },
    options: { hashAll: true, deep: false, maxFiles: 100, exclude: [] },
    scannerRoot: process.cwd(),
  });
  await processFile(context, file, { path: directory, kind: 'project', required: true });
  assert.ok(context.findings.values().some((finding) => finding.rule_id === 'KVS-RENAMED-TEST'));
});

test('normal cache walks discover extensionless gzip archives by magic bytes', async (t) => {
  const fsp = require('node:fs').promises;
  const path = require('node:path');
  const zlib = require('node:zlib');
  const { processFile } = require('../src/scanners/filesystem');
  const { makeTar, realContext, temporaryDirectory } = require('../test_support/helpers');
  const directory = await temporaryDirectory();
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'content-addressed-object');
  await fsp.writeFile(file, zlib.gzipSync(makeTar({
    'package/package.json': '{"name":"keyv","version":"6.0.0"}',
  })));
  const context = await realContext({ deep: false });
  await processFile(context, file, { path: directory, kind: 'npm-cache', required: false });
  assert.ok(context.findings.values().some((finding) => finding.package?.name === 'keyv' && finding.package?.version === '6.0.0'));
  assert.equal(context.statistics.archives_inspected, 1);
});
