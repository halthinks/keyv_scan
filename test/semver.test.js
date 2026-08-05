'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { classifySpec, compare, parseVersion, satisfies } = require('../src/semver');

test('supports exact, caret, tilde, comparator, wildcard, and OR ranges', () => {
  assert.equal(compare('1.0.0', '1.0.1') < 0, true);
  assert.ok(parseVersion('v1.2.3-beta.1'));
  assert.equal(satisfies('6.0.0', '^6.0.0'), true);
  assert.equal(satisfies('6.0.0', '~5.9.0'), false);
  assert.equal(satisfies('6.0.0', '>=5.0.0 <7.0.0'), true);
  assert.equal(satisfies('6.0.0', '5.x || 6.x'), true);
});

test('classifies affected declaration exposure', () => {
  assert.equal(classifySpec('6.0.0', ['6.0.0']).status, 'exact-affected');
  assert.equal(classifySpec('^6.0.0', ['6.0.0']).status, 'range-includes-affected');
  assert.equal(classifySpec('5.0.0', ['6.0.0']).status, 'exact-clean');
  assert.equal(classifySpec('latest', ['6.0.0']).status, 'tag-or-unknown');
  assert.equal(classifySpec('file:../local', ['6.0.0']).status, 'nonregistry');
});

test('handles npm partial caret, comparator, operator-spacing, and hyphen semantics', () => {
  assert.equal(satisfies('0.0.9', '^0.0'), true);
  assert.equal(satisfies('0.1.0', '^0.0'), false);
  assert.equal(satisfies('0.9.9', '^0'), true);
  assert.equal(satisfies('1.0.0', '^0'), false);
  assert.equal(satisfies('1.9.9', '<=1'), true);
  assert.equal(satisfies('2.0.0', '<=1'), false);
  assert.equal(satisfies('1.3.0', '>1.2'), true);
  assert.equal(satisfies('1.2.9', '>1.2'), false);
  assert.equal(satisfies('1.5.0', '>= 1.2.0, < 2.0.0'), true);
  assert.equal(satisfies('2.3.9', '1.2 - 2.3'), true);
  assert.equal(satisfies('2.4.0', '1.2 - 2.3'), false);
  assert.equal(satisfies('1.8.0', '~1.x'), true);
  assert.equal(satisfies('2.0.0', '~1.x'), false);
});
