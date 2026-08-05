#!/usr/bin/env node
'use strict';

const nodeMajor = Number.parseInt(process.versions.node.split('.')[0], 10);
if (!Number.isFinite(nodeMajor) || nodeMajor < 18) {
  process.stderr.write(`Error: Node.js 18 or newer is required; found ${process.versions.node}.\n`);
  process.exit(2);
}

const { main } = require('../src/cli');

main(process.argv.slice(2)).catch((error) => {
  const message = error && error.stack ? error.stack : String(error);
  process.stderr.write(`Fatal scanner error: ${message}\n`);
  process.exitCode = 2;
});
