#!/usr/bin/env node
'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const excludedDirectories = new Set(['.git', 'node_modules', 'keyv-scan-reports', 'reports']);

async function walk(directory, files = []) {
  const entries = await fsp.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) await walk(target, files);
    else if (entry.isFile() && entry.name.endsWith('.js')) files.push(target);
  }
  return files;
}

(async () => {
  const files = (await walk(root)).sort();
  for (const file of files) {
    const result = spawnSync(process.execPath, ['--check', file], {
      cwd: root,
      encoding: 'utf8',
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      const detail = result.stderr || result.stdout || result.error?.message || `exit ${result.status}`;
      throw new Error(`syntax check failed for ${path.relative(root, file)}:\n${detail}`);
    }
  }
  process.stdout.write(`Syntax verified for ${files.length} JavaScript files.\n`);
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
