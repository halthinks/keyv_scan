#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'MANIFEST.sha256');
const excluded = new Set(['MANIFEST.sha256']);

async function walk(directory, files = []) {
  const entries = await fsp.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const target = path.join(directory, entry.name);
    const relative = path.relative(root, target).replace(/\\/g, '/');
    if (entry.isDirectory()) {
      if (['.git', 'node_modules', 'reports', 'keyv-scan-reports'].includes(entry.name)) continue;
      await walk(target, files);
    } else if (entry.isFile() && !excluded.has(relative) && !/\.(?:zip|tgz|tar\.gz)$/.test(relative)) {
      files.push({ target, relative });
    }
  }
  return files;
}

(async () => {
  const files = (await walk(root)).sort((a, b) => a.relative.localeCompare(b.relative));
  const lines = [];
  for (const file of files) {
    const digest = await new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(file.target);
      stream.on('error', reject);
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
    });
    lines.push(`${digest}  ${file.relative}`);
  }
  await fsp.writeFile(output, `${lines.join('\n')}\n`, { mode: 0o644 });
  process.stdout.write(`Wrote ${files.length} entries to ${output}\n`);
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
