'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { pathToFileURL } = require('url');

async function pathExists(target) {
  try {
    await fsp.access(target, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function pathExistsSync(target) {
  try {
    fs.accessSync(target, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function safeRealpath(target) {
  try {
    return await fsp.realpath(target);
  } catch {
    return path.resolve(target);
  }
}

function safeRealpathSync(target) {
  try {
    return fs.realpathSync(target);
  } catch {
    return path.resolve(target);
  }
}

function normalizeForComparison(target) {
  const resolved = path.resolve(target);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function isSubpath(candidate, parent) {
  const child = normalizeForComparison(candidate);
  const root = normalizeForComparison(parent);
  if (child === root) return true;
  const relative = path.relative(root, child);
  return Boolean(relative) && !relative.startsWith('..') && !path.isAbsolute(relative);
}

function uniquePaths(paths) {
  const seen = new Set();
  const result = [];
  for (const value of paths) {
    if (!value) continue;
    const resolved = path.resolve(value);
    const key = process.platform === 'win32' ? resolved.toLowerCase() : resolved;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(resolved);
    }
  }
  return result;
}

async function readTextFile(file, maxBytes = Infinity) {
  const stat = await fsp.stat(file);
  if (stat.size > maxBytes) {
    throw new Error(`file exceeds ${maxBytes} bytes: ${file}`);
  }
  return fsp.readFile(file, 'utf8');
}

async function readJsonFile(file, maxBytes = Infinity) {
  const text = await readTextFile(file, maxBytes);
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`invalid JSON in ${file}: ${error.message}`);
  }
}

async function atomicWriteFile(file, data, options = {}) {
  const directory = path.dirname(file);
  await fsp.mkdir(directory, { recursive: true });
  const temp = path.join(
    directory,
    `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );
  try {
    await fsp.writeFile(temp, data, options);
    await fsp.rename(temp, file);
  } catch (error) {
    await fsp.rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}

function hashBuffer(buffer, algorithm = 'sha256') {
  return crypto.createHash(algorithm).update(buffer).digest('hex');
}

async function hashFileMany(file, algorithms = ['sha256']) {
  const uniqueAlgorithms = [...new Set(algorithms)];
  if (!uniqueAlgorithms.length) return {};
  const hashes = new Map(uniqueAlgorithms.map((algorithm) => [algorithm, crypto.createHash(algorithm)]));
  return new Promise((resolve, reject) => {
    const stream = fs.createReadStream(file);
    stream.on('error', reject);
    stream.on('data', (chunk) => {
      for (const hash of hashes.values()) hash.update(chunk);
    });
    stream.on('end', () => {
      resolve(Object.fromEntries([...hashes].map(([algorithm, hash]) => [algorithm, hash.digest('hex')])));
    });
  });
}

async function hashFile(file, algorithm = 'sha256') {
  const hashes = await hashFileMany(file, [algorithm]);
  return hashes[algorithm];
}

function stableStringify(value, space = 2) {
  const stack = new WeakSet();
  const normalize = (input) => {
    if (!input || typeof input !== 'object') return input;
    if (stack.has(input)) throw new TypeError('cannot stringify circular structure');
    stack.add(input);
    try {
      if (Array.isArray(input)) return input.map(normalize);
      if (input instanceof Date) return input.toISOString();
      if (input instanceof Map) {
        return Object.fromEntries([...input.entries()].sort(([a], [b]) => String(a).localeCompare(String(b))).map(([key, value]) => [key, normalize(value)]));
      }
      if (input instanceof Set) return [...input].map(normalize).sort();
      const output = {};
      for (const key of Object.keys(input).sort()) output[key] = normalize(input[key]);
      return output;
    } finally {
      stack.delete(input);
    }
  };
  return JSON.stringify(normalize(value), null, space);
}

function nowIso() {
  return new Date().toISOString();
}

function compactTimestamp(date = new Date()) {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return String(bytes);
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let index = 0;
  while (Math.abs(value) >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${(ms / 60_000).toFixed(1)} min`;
}

function runCommand(command, args = [], options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env || process.env,
    encoding: 'utf8',
    timeout: options.timeoutMs || 20_000,
    maxBuffer: options.maxBuffer || 16 * 1024 * 1024,
    windowsHide: true,
    shell: false,
  });
  return {
    command,
    args,
    status: result.status,
    signal: result.signal,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error || null,
    ok: !result.error && result.status === 0,
  };
}

function commandExists(command) {
  const probe = process.platform === 'win32' ? 'where.exe' : 'sh';
  const args = process.platform === 'win32' ? [command] : ['-lc', `command -v -- "$1" >/dev/null 2>&1`, 'sh', command];
  return runCommand(probe, args, { timeoutMs: 5_000 }).ok;
}

function fileUri(file) {
  try {
    return pathToFileURL(path.resolve(file)).href;
  } catch {
    return undefined;
  }
}

function redactHome(file) {
  const home = os.homedir();
  if (!home) return file;
  if (isSubpath(file, home)) return `~${path.sep}${path.relative(home, file)}`;
  return file;
}

function sanitizeError(error) {
  if (!error) return null;
  return {
    name: error.name || 'Error',
    message: error.message || String(error),
    code: error.code,
  };
}

function deterministicId(...parts) {
  return crypto.createHash('sha256').update(parts.map((part) => String(part ?? '')).join('\0')).digest('hex').slice(0, 20);
}

function severityRank(severity) {
  return ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity] || 0);
}

function sortFindings(findings) {
  return findings.sort((a, b) => {
    const severity = severityRank(b.severity) - severityRank(a.severity);
    if (severity) return severity;
    return [a.rule_id, a.location?.path, a.package?.name, a.package?.version, a.id]
      .map((value) => value || '')
      .join('\0')
      .localeCompare(
        [b.rule_id, b.location?.path, b.package?.name, b.package?.version, b.id]
          .map((value) => value || '')
          .join('\0'),
      );
  });
}

module.exports = {
  atomicWriteFile,
  commandExists,
  compactTimestamp,
  deterministicId,
  fileUri,
  formatBytes,
  formatDuration,
  hashBuffer,
  hashFile,
  hashFileMany,
  isSubpath,
  normalizeForComparison,
  nowIso,
  pathExists,
  pathExistsSync,
  readJsonFile,
  readTextFile,
  redactHome,
  runCommand,
  safeRealpath,
  safeRealpathSync,
  sanitizeError,
  severityRank,
  sortFindings,
  stableStringify,
  uniquePaths,
};
