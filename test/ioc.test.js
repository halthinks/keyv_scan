'use strict';

const assert = require('node:assert/strict');
const fsp = require('fs').promises;
const path = require('path');
const test = require('node:test');
const { HASH_IOC_FILE, PERSISTENCE_IOC_FILE } = require('../src/constants');
const { findMissingPairs, loadIocs } = require('../src/ioc');
const { hashFile } = require('../src/util');
const { temporaryDirectory } = require('../test_support/helpers');

test('bundled IOC snapshot and auxiliary rules are internally verified', async () => {
  const iocs = await loadIocs();
  assert.equal(iocs.packageCount, 443);
  assert.equal(iocs.versionPairCount, 2235);
  assert.equal(iocs.sha256, '27a11ac94f9fbfe8435c8e3371e0f0c8d1abfe8f92e44e8a1a070748cccdb7c9');
  assert.equal(iocs.auxiliarySha256.hashes_json, await hashFile(HASH_IOC_FILE));
  assert.equal(iocs.auxiliarySha256.persistence_json, await hashFile(PERSISTENCE_IOC_FILE));
  assert.equal(iocs.futureDated, false);
});

test('exact-pair regression detection catches substitutions even with equal counts', () => {
  const previous = new Map([['keyv', new Set(['6.0.0'])], ['cacheable', new Set(['2.5.1'])]]);
  const next = new Map([['keyv', new Set(['6.0.1'])], ['cacheable', new Set(['2.5.1'])]]);
  assert.deepEqual(findMissingPairs(previous, next), ['keyv@6.0.0']);
});

test('future-dated manifests are loaded but marked unsafe for a complete scan', async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const csv = path.join(directory, 'iocs.csv');
  const manifest = path.join(directory, 'manifest.json');
  await fsp.writeFile(csv, 'Package,Versions\nkeyv,6.0.0\n');
  const sha = await hashFile(csv);
  await fsp.writeFile(manifest, JSON.stringify({
    schema_version: 1,
    fetched_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    canonical_sha256: sha,
    auxiliary_sha256: {
      hashes_json: await hashFile(HASH_IOC_FILE),
      persistence_json: await hashFile(PERSISTENCE_IOC_FILE),
    },
    package_count: 1,
    version_pair_count: 1,
    bootstrap: false,
    source_url: 'https://raw.githubusercontent.com/example/iocs.csv',
    resolved_url: 'https://raw.githubusercontent.com/example/iocs.csv',
    generated_by: 'test',
    canonical_line_endings: 'LF',
  }));
  const iocs = await loadIocs({ iocFile: csv, manifestFile: manifest, minPackages: 1, minPairs: 1 });
  assert.equal(iocs.futureDated, true);
});

test('missing or structurally incomplete IOC provenance manifests fail closed', async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const csv = path.join(directory, 'iocs.csv');
  const missingManifest = path.join(directory, 'missing-manifest.json');
  const partialManifest = path.join(directory, 'partial-manifest.json');
  await fsp.writeFile(csv, 'Package,Versions\nkeyv,6.0.0\n');

  await assert.rejects(() => loadIocs({
    iocFile: csv,
    manifestFile: missingManifest,
    minPackages: 1,
    minPairs: 1,
  }), /source manifest is required/);

  await fsp.writeFile(partialManifest, JSON.stringify({
    schema_version: 1,
    fetched_at: new Date().toISOString(),
    canonical_sha256: await hashFile(csv),
    package_count: 1,
    version_pair_count: 1,
    bootstrap: false,
  }));
  await assert.rejects(() => loadIocs({
    iocFile: csv,
    manifestFile: partialManifest,
    minPackages: 1,
    minPairs: 1,
  }), /auxiliary_sha256 object is required/);
});
