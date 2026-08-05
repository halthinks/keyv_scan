'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fsp = require('node:fs').promises;
const https = require('node:https');
const path = require('node:path');
const test = require('node:test');
const { fetchText, updateIocs } = require('../src/ioc');
const { hashFile } = require('../src/util');
const { temporaryDirectory } = require('../test_support/helpers');

function installHttpsFixture(t, body, options = {}) {
  const original = https.get;
  t.after(() => { https.get = original; });
  https.get = (url, requestOptions, callback) => {
    const request = new EventEmitter();
    request.setTimeout = () => request;
    request.destroy = (error) => {
      if (error) process.nextTick(() => request.emit('error', error));
    };
    const response = new EventEmitter();
    response.statusCode = options.statusCode || 200;
    response.headers = options.headers || { etag: '"fixture"', 'last-modified': 'Wed, 05 Aug 2026 00:00:00 GMT' };
    response.resume = () => {};
    process.nextTick(() => {
      callback(response);
      if (response.statusCode === 200) {
        response.emit('data', Buffer.from(body, 'utf8'));
        response.emit('end');
      }
    });
    return request;
  };
}

test('bounded HTTPS IOC fetch and atomic canonical update work with a controlled source', async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const body = 'Package,Malicious Versions\r\nkeyv,6.0.0\r\ncacheable,2.5.1\r\n';
  installHttpsFixture(t, body);
  const iocFile = path.join(directory, 'packages.csv');
  const manifestFile = path.join(directory, 'manifest.json');
  const result = await updateIocs({
    iocFile,
    manifestFile,
    sourceUrl: 'https://raw.githubusercontent.com/example/feed.csv',
    minPackages: 2,
    minPairs: 2,
  });
  assert.equal(result.package_count, 2);
  assert.equal(result.version_pair_count, 2);
  assert.equal(result.source_line_endings, 'CRLF');
  assert.equal(result.canonical_line_endings, 'LF');
  assert.equal(result.canonical_sha256, await hashFile(iocFile));
  assert.equal(await fsp.readFile(iocFile, 'utf8'), 'Package,Malicious Versions\ncacheable,2.5.1\nkeyv,6.0.0\n');
});

test('updater rejects removal of a previously known exact pair even when counts stay equal', async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const iocFile = path.join(directory, 'packages.csv');
  const manifestFile = path.join(directory, 'manifest.json');
  await fsp.writeFile(iocFile, 'Package,Malicious Versions\nkeyv,6.0.0\n');
  await fsp.writeFile(manifestFile, JSON.stringify({
    canonical_sha256: await hashFile(iocFile),
    package_count: 1,
    version_pair_count: 1,
    fetched_at: new Date().toISOString(),
    bootstrap: false,
  }));
  installHttpsFixture(t, 'Package,Malicious Versions\nkeyv,6.0.1\n');
  await assert.rejects(() => updateIocs({
    iocFile,
    manifestFile,
    sourceUrl: 'https://raw.githubusercontent.com/example/feed.csv',
    minPackages: 1,
    minPairs: 1,
  }), /removed previously known exact indicators/);
});

test('IOC network client rejects non-HTTPS and unallowlisted hosts before making a request', () => {
  assert.throws(() => fetchText('http://raw.githubusercontent.com/example.csv'), /must use HTTPS/);
  assert.throws(() => fetchText('https://example.com/example.csv'), /not allowlisted/);
});
