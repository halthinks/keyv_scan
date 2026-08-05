'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  parseGenericNameVersionText,
  parsePackageLockObject,
  parsePnpmLock,
  parsePnpmPackageKey,
  parseYarnLock,
  validateTextLockStructure,
} = require('../src/scanners/lockfiles');

test('parses npm package-lock v1 and v2/v3 structures', () => {
  const occurrences = parsePackageLockObject({
    packages: { 'node_modules/keyv': { version: '6.0.0' }, 'node_modules/@scope/pkg': { version: '1.2.3' } },
    dependencies: { cacheable: { version: '2.5.1', dependencies: { keyv: { version: '6.0.0' } } } },
  });
  assert.ok(occurrences.some((item) => item.name === 'keyv' && item.version === '6.0.0'));
  assert.ok(occurrences.some((item) => item.name === '@scope/pkg' && item.version === '1.2.3'));
  assert.ok(occurrences.some((item) => item.name === 'cacheable' && item.version === '2.5.1'));
});

test('parses modern and legacy pnpm package keys', () => {
  assert.deepEqual(parsePnpmPackageKey('keyv@6.0.0'), { name: 'keyv', version: '6.0.0' });
  assert.deepEqual(parsePnpmPackageKey('@scope/pkg@1.2.3(peer@4.0.0)'), { name: '@scope/pkg', version: '1.2.3' });
  assert.deepEqual(parsePnpmPackageKey('/keyv/6.0.0'), { name: 'keyv', version: '6.0.0' });
  assert.deepEqual(parsePnpmPackageKey('/@scope/pkg/1.2.3'), { name: '@scope/pkg', version: '1.2.3' });
});

test('parses pnpm importers/packages and Yarn classic/Berry locks', () => {
  const pnpm = parsePnpmLock(`lockfileVersion: '9.0'\npackages:\n  keyv@6.0.0:\n    resolution: {}\n  '@scope/pkg@1.2.3':\n    resolution: {}\nimporters:\n  .:\n    dependencies:\n      cacheable:\n        specifier: 2.5.1\n        version: 2.5.1\n`);
  assert.ok(pnpm.some((item) => item.name === 'keyv' && item.version === '6.0.0'));
  assert.ok(pnpm.some((item) => item.name === 'cacheable' && item.version === '2.5.1'));

  const yarn = parseYarnLock(`keyv@^6.0.0:\n  version "6.0.0"\n\n"cacheable@npm:^2.5.0":\n  version: 2.5.1\n  resolution: "cacheable@npm:2.5.1"\n`);
  assert.ok(yarn.some((item) => item.name === 'keyv' && item.version === '6.0.0'));
  assert.ok(yarn.some((item) => item.name === 'cacheable' && item.version === '2.5.1'));
});

test('extracts package/version pairs from Bun-style text', () => {
  const values = parseGenericNameVersionText('keyv@6.0.0 "@scope/pkg@1.2.3"');
  assert.ok(values.some((item) => item.name === 'keyv'));
  assert.ok(values.some((item) => item.name === '@scope/pkg'));
});

test('rejects structurally unrecognized text lockfiles instead of treating them as clean', () => {
  assert.throws(() => validateTextLockStructure('pnpm-lock', 'not: a lockfile\n'), /lockfileVersion/);
  assert.throws(() => validateTextLockStructure('yarn-lock', 'random unparseable content\n'), /recognizable lock entries/);
  assert.throws(() => validateTextLockStructure('bun-lock', 'random unparseable content\n'), /recognized text lockfile structure/);
  assert.doesNotThrow(() => validateTextLockStructure('yarn-lock', '# yarn lockfile v1\n'));
});
