'use strict';

const assert = require('node:assert/strict');
const fsp = require('fs').promises;
const path = require('path');
const test = require('node:test');
const zlib = require('zlib');
const { parseTarEntries, parseZipEntries, scanArchive } = require('../src/scanners/archives');
const { makeStoredZip, makeTar, realContext, temporaryDirectory } = require('../test_support/helpers');

test('parses bounded TAR and ZIP package entries', () => {
  const tar = makeTar({ 'package/package.json': '{"name":"keyv","version":"6.0.0"}' });
  const tarNames = [];
  parseTarEntries(tar, (entry) => tarNames.push(entry.name));
  assert.deepEqual(tarNames, ['package/package.json']);

  const zip = makeStoredZip({ 'node_modules/keyv/package.json': '{"name":"keyv","version":"6.0.0"}' });
  const zipNames = [];
  parseZipEntries(zip, (entry) => zipNames.push(entry.name));
  assert.deepEqual(zipNames, ['node_modules/keyv/package.json']);
});

test('archive parsers enforce entry and output limits', () => {
  const tar = makeTar({ 'a.txt': 'one', 'b.txt': 'two' });
  assert.throws(() => parseTarEntries(tar, () => {}, { maxEntries: 1 }), /entry limit/);
  const zip = makeStoredZip({ 'a.txt': '12345' });
  assert.throws(() => parseZipEntries(zip, () => {}, { maxOutputBytes: 4 }), /declared output/);
});

test('scans extensionless gzip and ZIP cache objects by magic', async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const manifest = '{"name":"keyv","version":"6.0.0"}';
  const tgz = path.join(directory, 'content-object');
  const zipPath = path.join(directory, 'another-object');
  await fsp.writeFile(tgz, zlib.gzipSync(makeTar({ 'package/package.json': manifest })));
  await fsp.writeFile(zipPath, makeStoredZip({ 'node_modules/keyv/package.json': manifest }));
  const context = await realContext();
  assert.equal(await scanArchive(context, tgz, { required: true }), true);
  assert.equal(await scanArchive(context, zipPath, { required: true }), true);
  assert.equal(context.findings.values().filter((item) => item.package?.name === 'keyv').length, 2);
});

test('archive parsers reject corrupted TAR headers and ZIP payload CRCs', () => {
  const tar = makeTar({ 'package/package.json': '{"name":"keyv","version":"6.0.0"}' });
  const corruptTar = Buffer.from(tar);
  corruptTar[0] ^= 0x01;
  assert.throws(() => parseTarEntries(corruptTar, () => {}), /TAR header checksum/);

  const zip = makeStoredZip({ 'node_modules/keyv/package.json': '{"name":"keyv","version":"6.0.0"}' });
  const corruptZip = Buffer.from(zip);
  const localNameLength = corruptZip.readUInt16LE(26);
  const localExtraLength = corruptZip.readUInt16LE(28);
  const dataOffset = 30 + localNameLength + localExtraLength;
  corruptZip[dataOffset] ^= 0x01;
  assert.throws(() => parseZipEntries(corruptZip, () => {}), /CRC-32 mismatch/);
});

test('malformed package.json inside a relevant archive creates an incomplete-coverage gap', async () => {
  const context = await realContext();
  const zip = makeStoredZip({ 'node_modules/keyv/package.json': '{bad json' });
  const directory = await temporaryDirectory();
  const file = path.join(directory, 'fixture.zip');
  try {
    await fsp.writeFile(file, zip);
    assert.equal(await scanArchive(context, file, { required: true }), true);
    assert.ok(context.coverageGaps.some((gap) => gap.check === 'archive-package-json'));
  } finally {
    await fsp.rm(directory, { recursive: true, force: true });
  }
});
