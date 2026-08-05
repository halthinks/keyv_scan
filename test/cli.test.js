'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { parseArgs } = require('../src/cli');

test('parses scanner coverage and fail-closed options', () => {
  const parsed = parseArgs(['scan', '/tmp/project', '--system', '--hash-all', '--offline', '--no-processes', '--no-persistence', '--fail-on', 'high']);
  assert.equal(parsed.command, 'scan');
  assert.deepEqual(parsed.options.positionalRoots, ['/tmp/project']);
  assert.equal(parsed.options.system, true);
  assert.equal(parsed.options.hashAll, true);
  assert.equal(parsed.options.offline, true);
  assert.equal(parsed.options.processes, false);
  assert.equal(parsed.options.persistence, false);
  assert.equal(parsed.options.failOn, 'high');
});

test('rejects unknown options and invalid thresholds', () => {
  assert.throws(() => parseArgs(['--unknown']), /unknown option/);
  assert.throws(() => parseArgs(['--allow-bootstrap']), /unknown option/);
  assert.throws(() => parseArgs(['--fail-on', 'severe']), /must be/);
  assert.throws(() => parseArgs(['--offline', '--force-update']), /cannot be used together/);
  assert.throws(() => parseArgs(['--no-auto-update', '--force-update']), /cannot be used together/);
  assert.throws(() => parseArgs(['--max-files', '1.5']), /non-negative integer/);
  assert.throws(() => parseArgs(['--timeout-ms', '0']), /positive integer/);
});
