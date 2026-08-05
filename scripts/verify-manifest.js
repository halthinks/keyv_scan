#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const root = path.resolve(__dirname, '..');
const manifestPath = path.join(root, 'MANIFEST.sha256');
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
      files.push(relative);
    }
  }
  return files;
}

async function digestFile(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(file);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

(async () => {
  const text = await fsp.readFile(manifestPath, 'utf8');
  const listed = new Map();
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (!line) continue;
    const match = line.match(/^([0-9a-f]{64})  (.+)$/);
    if (!match) throw new Error(`invalid manifest line ${index + 1}`);
    const relative = match[2];
    if (relative.includes('\\') || path.isAbsolute(relative) || relative.split('/').includes('..')) {
      throw new Error(`unsafe manifest path on line ${index + 1}: ${relative}`);
    }
    if (listed.has(relative)) throw new Error(`duplicate manifest path: ${relative}`);
    listed.set(relative, match[1]);
  }

  const actualFiles = new Set((await walk(root)).sort());
  for (const relative of actualFiles) {
    if (!listed.has(relative)) throw new Error(`file is not covered by MANIFEST.sha256: ${relative}`);
  }
  for (const relative of listed.keys()) {
    if (!actualFiles.has(relative)) throw new Error(`manifest lists a missing or excluded file: ${relative}`);
  }

  for (const [relative, expected] of listed) {
    const actual = await digestFile(path.join(root, ...relative.split('/')));
    if (actual !== expected) throw new Error(`SHA-256 mismatch for ${relative}: expected ${expected}, got ${actual}`);
  }
  process.stdout.write(`Verified ${listed.size} files against ${manifestPath}\n`);
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
