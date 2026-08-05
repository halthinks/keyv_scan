'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { parsePackageCsv, serializePackageCsv, splitVersions } = require('../src/csv');

test('parses current Wiz CSV shape and quoted version lists', () => {
  const parsed = parsePackageCsv('Package,Malicious Versions\nkeyv,6.0.0\n@scope/pkg,"1.0.0, 1.0.1"\n');
  assert.equal(parsed.packageCount, 2);
  assert.equal(parsed.versionPairCount, 3);
  assert.deepEqual([...parsed.packages.get('@scope/pkg')], ['1.0.0', '1.0.1']);
});

test('parses legacy transformed == format without silently loading zero entries', () => {
  assert.deepEqual(splitVersions('== 1.0.0 || == 1.0.1'), ['1.0.0', '1.0.1']);
  const parsed = parsePackageCsv('Package,Affected Versions\nkeyv,== 6.0.0\n');
  assert.equal(parsed.versionPairCount, 1);
});

test('rejects bad headers, malformed versions, and empty feeds', () => {
  assert.throws(() => parsePackageCsv('name,bad\nkeyv,6.0.0\n'), /unsupported IOC CSV headers/);
  assert.throws(() => parsePackageCsv('Package,Versions\nkeyv,^6.0.0\n'), /validation failed/);
  assert.throws(() => parsePackageCsv('Package,Versions\nkeyv,latest\n'), /validation failed/);
  assert.throws(() => parsePackageCsv('Package,Versions\n'), /no package rows/);
});

test('canonical serialization round-trips deterministically', () => {
  const first = parsePackageCsv('Package,Versions\nzeta,2.0.0\nalpha,"1.0.1, 1.0.0"\n');
  const canonical = serializePackageCsv(first.packages);
  assert.equal(canonical, 'Package,Malicious Versions\nalpha,"1.0.0, 1.0.1"\nzeta,2.0.0\n');
  const second = parsePackageCsv(canonical);
  assert.equal(second.versionPairCount, first.versionPairCount);
});
