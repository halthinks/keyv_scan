'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { MAX_LOCKFILE_BYTES } = require('../constants');
const { recordPackageOccurrence } = require('./packages');
const { runCommand } = require('../util');

function inferNameFromPackageLockPath(key) {
  const normalized = String(key || '').replace(/\\/g, '/');
  const marker = '/node_modules/';
  const index = normalized.lastIndexOf(marker);
  const tail = index >= 0 ? normalized.slice(index + marker.length) : normalized.replace(/^node_modules\//, '');
  if (!tail || tail === normalized && !normalized.startsWith('node_modules/')) return null;
  const parts = tail.split('/').filter(Boolean);
  if (!parts.length) return null;
  if (parts[0].startsWith('@') && parts[1]) return `${parts[0]}/${parts[1]}`;
  return parts[0];
}

function parsePackageLockObject(lock) {
  const occurrences = [];
  if (!lock || typeof lock !== 'object') return occurrences;

  if (lock.packages && typeof lock.packages === 'object') {
    for (const [packagePath, metadata] of Object.entries(lock.packages)) {
      if (!metadata || typeof metadata !== 'object') continue;
      const name = metadata.name || inferNameFromPackageLockPath(packagePath);
      const version = metadata.version;
      if (typeof name === 'string' && typeof version === 'string') {
        occurrences.push({ name, version, entry: packagePath || '(root)' });
      }
    }
  }

  const visited = new Set();
  const walkDependencies = (dependencies, prefix = 'dependencies') => {
    if (!dependencies || typeof dependencies !== 'object' || visited.has(dependencies)) return;
    visited.add(dependencies);
    for (const [name, metadata] of Object.entries(dependencies)) {
      if (!metadata || typeof metadata !== 'object') continue;
      if (typeof metadata.version === 'string') {
        occurrences.push({ name, version: metadata.version, entry: `${prefix}.${name}` });
      }
      walkDependencies(metadata.dependencies, `${prefix}.${name}.dependencies`);
    }
  };
  walkDependencies(lock.dependencies);
  return dedupeOccurrences(occurrences);
}

function stripYamlScalar(value) {
  return String(value || '').trim().replace(/^['"]|['"]$/g, '');
}

function parsePnpmPackageKey(input) {
  let key = stripYamlScalar(input).replace(/^\//, '');
  if (!key || /^(?:file|link|workspace|https?|git):/i.test(key)) return null;

  key = key.replace(/\([^)]*\).*$/g, '').replace(/\[[^\]]*\].*$/g, '');
  let name;
  let version;

  if (key.startsWith('@')) {
    const slash = key.indexOf('/');
    if (slash <= 1) return null;
    const modernSeparator = key.lastIndexOf('@');
    if (modernSeparator > slash) {
      name = key.slice(0, modernSeparator);
      version = key.slice(modernSeparator + 1);
    } else {
      const secondSlash = key.indexOf('/', slash + 1);
      if (secondSlash === -1) return null;
      name = key.slice(0, secondSlash);
      version = key.slice(secondSlash + 1);
    }
  } else {
    const modernSeparator = key.lastIndexOf('@');
    const legacySeparator = key.lastIndexOf('/');
    const separator = modernSeparator > 0 ? modernSeparator : legacySeparator;
    if (separator <= 0) return null;
    name = key.slice(0, separator);
    version = key.slice(separator + 1);
  }

  version = String(version || '').replace(/_.+$/, '').replace(/\(.+$/, '').trim();
  if (!name || !version || /[/:]/.test(version)) return null;
  return { name, version };
}

function parsePnpmLock(text) {
  const occurrences = [];
  const lines = String(text).split(/\r?\n/);
  let topSection = null;
  let dependencyGroupIndent = null;
  let pendingDependency = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const indent = line.length - line.trimStart().length;

    const top = line.match(/^([A-Za-z][A-Za-z0-9_-]*):\s*$/);
    if (top) {
      topSection = top[1];
      dependencyGroupIndent = null;
      pendingDependency = null;
      continue;
    }

    if (['packages', 'snapshots'].includes(topSection)) {
      const entry = line.match(/^\s{2}(.+):\s*$/);
      if (entry) {
        const parsed = parsePnpmPackageKey(entry[1]);
        if (parsed) occurrences.push({ ...parsed, entry: `${topSection}.${stripYamlScalar(entry[1])}`, line: index + 1 });
      }
    }

    if (topSection === 'importers') {
      const group = line.match(/^(\s*)(dependencies|devDependencies|optionalDependencies|peerDependencies):\s*$/);
      if (group) {
        dependencyGroupIndent = group[1].length;
        pendingDependency = null;
        continue;
      }
      if (dependencyGroupIndent !== null) {
        if (indent <= dependencyGroupIndent) {
          dependencyGroupIndent = null;
          pendingDependency = null;
        } else {
          const dep = line.match(/^(\s+)(['"]?)(@?[^:'"\s][^:]*?)\2:\s*(.*)$/);
          if (dep && dep[1].length === dependencyGroupIndent + 2) {
            const name = dep[3].trim();
            const inline = stripYamlScalar(dep[4]);
            pendingDependency = { name, line: index + 1 };
            const inlineParsed = parsePnpmPackageKey(`${name}@${inline.replace(/^npm:/, '')}`);
            if (inlineParsed && /^\d/.test(inline)) {
              occurrences.push({ ...inlineParsed, entry: `importers.${name}`, line: index + 1 });
            }
            continue;
          }
          if (pendingDependency) {
            const versionLine = line.match(/^\s+version:\s*(.+?)\s*$/);
            if (versionLine) {
              const value = stripYamlScalar(versionLine[1]).replace(/^npm:/, '');
              const parsed = parsePnpmPackageKey(`${pendingDependency.name}@${value}`);
              if (parsed) occurrences.push({ ...parsed, entry: `importers.${pendingDependency.name}`, line: index + 1 });
            }
          }
        }
      }
    }
  }
  return dedupeOccurrences(occurrences);
}

function splitYarnSelectors(header) {
  const selectors = [];
  let current = '';
  let quoted = false;
  let quote = '';
  for (const char of header) {
    if (quoted) {
      if (char === quote) quoted = false;
      current += char;
    } else if (char === '"' || char === "'") {
      quoted = true;
      quote = char;
      current += char;
    } else if (char === ',') {
      selectors.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  if (current.trim()) selectors.push(current.trim());
  return selectors;
}

function yarnNameFromSelector(input) {
  let selector = stripYamlScalar(input).trim();
  if (!selector) return null;
  if (selector.includes('@npm:')) selector = selector.replace('@npm:', '@');
  if (selector.startsWith('@')) {
    const slash = selector.indexOf('/');
    if (slash === -1) return null;
    const separator = selector.indexOf('@', slash + 1);
    return separator === -1 ? selector : selector.slice(0, separator);
  }
  const separator = selector.indexOf('@');
  return separator <= 0 ? null : selector.slice(0, separator);
}

function parseYarnLock(text) {
  const occurrences = [];
  const lines = String(text).split(/\r?\n/);
  let block = null;

  const flush = () => {
    if (!block || !block.version) return;
    const names = new Set();
    if (block.resolution) {
      const name = yarnNameFromSelector(block.resolution);
      if (name) names.add(name);
    }
    for (const selector of splitYarnSelectors(block.header)) {
      const name = yarnNameFromSelector(selector);
      if (name) names.add(name);
    }
    for (const name of names) {
      occurrences.push({ name, version: block.version, entry: block.header, line: block.line });
    }
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^\S.*:\s*$/.test(line) && !line.startsWith('#')) {
      flush();
      block = { header: line.replace(/:\s*$/, ''), line: index + 1, version: null, resolution: null };
      continue;
    }
    if (!block) continue;
    const version = line.match(/^\s+version(?::|\s+)\s*["']?([^"'\s]+)["']?\s*$/);
    if (version) block.version = version[1];
    const resolution = line.match(/^\s+resolution:\s*["']?(.+?)["']?\s*$/);
    if (resolution) block.resolution = resolution[1];
  }
  flush();
  return dedupeOccurrences(occurrences);
}

function parseGenericNameVersionText(text) {
  const occurrences = [];
  const patterns = [
    /["'](@[A-Za-z0-9._~-]+\/[A-Za-z0-9._~-]+|[A-Za-z0-9._~-]+)@(?:npm:)?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)["']/g,
    /\b(@[A-Za-z0-9._~-]+\/[A-Za-z0-9._~-]+|[A-Za-z0-9._~-]+)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\b/g,
  ];
  for (const pattern of patterns) {
    for (const match of String(text).matchAll(pattern)) {
      occurrences.push({ name: match[1], version: match[2], entry: 'text-lockfile' });
    }
  }
  return dedupeOccurrences(occurrences);
}

function dedupeOccurrences(occurrences) {
  const seen = new Set();
  const output = [];
  for (const occurrence of occurrences) {
    const key = `${occurrence.name}\0${occurrence.version}\0${occurrence.entry || ''}`;
    if (!seen.has(key)) {
      seen.add(key);
      output.push(occurrence);
    }
  }
  return output;
}

function recordOccurrences(context, file, type, occurrences) {
  for (const occurrence of occurrences) {
    recordPackageOccurrence(context, {
      ...occurrence,
      path: file,
      sourceKind: 'lockfile',
      evidence: `${type} resolved dependency`,
      metadata: { lockfile_type: type },
    });
  }
}

async function scanPackageLock(context, file) {
  try {
    const stat = await fsp.stat(file);
    if (stat.size > MAX_LOCKFILE_BYTES) throw new Error(`lockfile exceeds ${MAX_LOCKFILE_BYTES} bytes`);
    const lock = JSON.parse(await fsp.readFile(file, 'utf8'));
    if (!lock || typeof lock !== 'object' || Array.isArray(lock) || !Number.isInteger(lock.lockfileVersion) || lock.lockfileVersion < 1) {
      throw new Error('package lockfile is missing a valid lockfileVersion');
    }
    const occurrences = parsePackageLockObject(lock);
    recordOccurrences(context, file, path.basename(file), occurrences);
    context.statistics.lockfiles += 1;
  } catch (error) {
    context.addOperationalError('package-lock', file, error, { incomplete: true });
  }
}

function validateTextLockStructure(type, text) {
  const source = String(text || '');
  const meaningful = source.split(/\r?\n/)
    .filter((line) => line.trim() && !line.trim().startsWith('#'))
    .join('\n')
    .trim();
  if (type === 'pnpm-lock') {
    if (!/^lockfileVersion:\s*[^\s]+/m.test(source)) throw new Error('pnpm lockfile is missing lockfileVersion');
    if (!/^(?:packages|snapshots|importers):\s*$/m.test(source)) throw new Error('pnpm lockfile has no recognized dependency section');
  } else if (type === 'yarn-lock') {
    if (!meaningful) return;
    const berry = /^__metadata:\s*$/m.test(source);
    const classicHeader = /^\S.*:\s*$/m.test(source);
    const version = /^\s+version(?::|\s+)\s*["']?[^"'\s]+/m.test(source);
    if (!berry && !(classicHeader && version)) throw new Error('Yarn lockfile has no recognizable lock entries');
  } else if (type === 'bun-lock') {
    if (!meaningful || !/(?:["']?lockfileVersion["']?\s*[:=]|["']?packages["']?\s*:)/.test(source)) {
      throw new Error('bun.lock has no recognized text lockfile structure');
    }
  }
}

async function scanTextLock(context, file, type, parser) {
  try {
    const stat = await fsp.stat(file);
    if (stat.size > MAX_LOCKFILE_BYTES) throw new Error(`lockfile exceeds ${MAX_LOCKFILE_BYTES} bytes`);
    const text = await fsp.readFile(file, 'utf8');
    validateTextLockStructure(type, text);
    const occurrences = parser(text);
    recordOccurrences(context, file, type, occurrences);
    context.statistics.lockfiles += 1;
    return text;
  } catch (error) {
    context.addOperationalError(type, file, error, { incomplete: true });
    return null;
  }
}

async function scanBunLockBinary(context, file) {
  context.statistics.lockfiles += 1;
  const directory = path.dirname(file);
  const command = process.platform === 'win32' ? 'bun.exe' : 'bun';
  const safeEnv = {
    ...process.env,
    npm_config_ignore_scripts: 'true',
    NPM_CONFIG_IGNORE_SCRIPTS: 'true',
    BUN_INSTALL_CACHE_DIR: process.env.BUN_INSTALL_CACHE_DIR || '',
    COREPACK_ENABLE_PROJECT_SPEC: '0',
    COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
  };
  const result = runCommand(command, ['pm', 'ls', '--all'], { cwd: directory, timeoutMs: 30_000, env: safeEnv });
  if (result.ok) {
    recordOccurrences(context, file, 'bun.lockb via bun pm ls', parseGenericNameVersionText(result.stdout));
    return;
  }

  try {
    const stat = await fsp.stat(file);
    if (stat.size > MAX_LOCKFILE_BYTES) throw new Error(`bun.lockb exceeds heuristic scan limit ${MAX_LOCKFILE_BYTES} bytes`);
    const buffer = await fsp.readFile(file);
    const text = buffer.toString('latin1');
    const occurrences = parseGenericNameVersionText(text);
    for (const occurrence of occurrences) {
      const affected = context.iocs.packages.get(occurrence.name);
      if (!affected?.has(occurrence.version)) continue;
      context.findings.add({
        rule_id: 'KVS-BUN-LOCKB-HEURISTIC',
        title: 'Binary Bun lockfile contains an affected package/version string',
        description: 'The binary lockfile could not be resolved through Bun; an exact campaign package/version string was found heuristically.',
        category: 'affected-package',
        severity: 'high',
        confidence: 'strong',
        source_kind: 'lockfile',
        package: { name: occurrence.name, version: occurrence.version },
        location: { path: file },
        evidence: 'Exact package/version bytes found in bun.lockb',
        remediation_key: 'lockfile',
      });
    }
    context.addCoverageGap('bun-lockb', `Bun was unavailable or failed for ${file}; binary parsing was heuristic only`, 'warning');
  } catch (error) {
    context.addOperationalError('bun-lockb', file, error, { incomplete: true });
  }
}

async function scanLockfile(context, file) {
  const name = path.basename(file).toLowerCase();
  if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') return scanPackageLock(context, file);
  if (name === 'pnpm-lock.yaml' || name === 'pnpm-lock.yml') return scanTextLock(context, file, 'pnpm-lock', parsePnpmLock);
  if (name === 'yarn.lock') return scanTextLock(context, file, 'yarn-lock', parseYarnLock);
  if (name === 'bun.lock') return scanTextLock(context, file, 'bun-lock', parseGenericNameVersionText);
  if (name === 'bun.lockb') return scanBunLockBinary(context, file);
  return undefined;
}

function isLockfileName(name) {
  return ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'pnpm-lock.yml', 'yarn.lock', 'bun.lock', 'bun.lockb'].includes(String(name).toLowerCase());
}

module.exports = {
  inferNameFromPackageLockPath,
  isLockfileName,
  parseGenericNameVersionText,
  parsePackageLockObject,
  parsePnpmLock,
  parsePnpmPackageKey,
  parseYarnLock,
  scanLockfile,
  validateTextLockStructure,
  yarnNameFromSelector,
};
