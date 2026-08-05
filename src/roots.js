'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathExistsSync, runCommand, uniquePaths } = require('./util');

function cleanCommandPath(value) {
  const lines = String(value || '').trim().split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length) return null;
  let result = lines.at(-1);
  try {
    const parsed = JSON.parse(result);
    if (typeof parsed === 'string') result = parsed;
  } catch {
    // Plain text path.
  }
  if (!result || result === 'undefined' || result === 'null') return null;
  return path.resolve(result);
}

function managerCommandRoots(events) {
  const roots = [];
  const safeCwd = os.tmpdir();
  const safeEnv = {
    ...process.env,
    npm_config_ignore_scripts: 'true',
    NPM_CONFIG_IGNORE_SCRIPTS: 'true',
    npm_config_update_notifier: 'false',
    NPM_CONFIG_UPDATE_NOTIFIER: 'false',
    YARN_IGNORE_PATH: '1',
    COREPACK_ENABLE_PROJECT_SPEC: '0',
    COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
    COREPACK_DEFAULT_TO_LATEST: '0',
  };
  const commands = [
    { manager: 'npm', command: 'npm', args: ['config', 'get', 'cache'], kind: 'npm-cache' },
    { manager: 'npm', command: 'npm', args: ['root', '--global'], kind: 'npm-global' },
    { manager: 'pnpm', command: 'pnpm', args: ['store', 'path'], kind: 'pnpm-cache' },
    { manager: 'pnpm', command: 'pnpm', args: ['root', '--global'], kind: 'pnpm-global', optionalFailure: true },
  ];

  for (const item of commands) {
    const result = runCommand(item.command, item.args, { timeoutMs: 12_000, cwd: safeCwd, env: safeEnv });
    if (!result.ok) {
      const absent = result.error?.code === 'ENOENT';
      events.push({ manager: item.manager, check: item.args.join(' '), ok: false, absent, optional: item.optionalFailure, error: result.error?.message || result.stderr.trim() || `exit ${result.status}` });
      continue;
    }
    const target = cleanCommandPath(result.stdout);
    if (target) roots.push({ path: target, kind: item.kind, required: false, source: `${item.command} ${item.args.join(' ')}` });
    events.push({ manager: item.manager, check: item.args.join(' '), ok: Boolean(target), path: target });
  }

  const yarnVersion = runCommand('yarn', ['--version'], { timeoutMs: 8_000, cwd: safeCwd, env: safeEnv });
  if (yarnVersion.ok) {
    const major = Number.parseInt(yarnVersion.stdout.trim().split('.')[0], 10);
    const yarnCommand = major === 1 ? ['cache', 'dir', '--silent'] : ['config', 'get', 'cacheFolder'];
    const cache = runCommand('yarn', yarnCommand, { timeoutMs: 12_000, cwd: safeCwd, env: safeEnv });
    const target = cache.ok ? cleanCommandPath(cache.stdout) : null;
    if (target) roots.push({ path: target, kind: 'yarn-cache', required: false, source: `yarn ${yarnCommand.join(' ')}` });
    events.push({ manager: 'yarn', check: yarnCommand.join(' '), ok: Boolean(target), path: target, error: cache.ok ? undefined : cache.stderr.trim() || cache.error?.message });
    if (major === 1) {
      const global = runCommand('yarn', ['global', 'dir', '--silent'], { timeoutMs: 12_000, cwd: safeCwd, env: safeEnv });
      const globalTarget = global.ok ? cleanCommandPath(global.stdout) : null;
      if (globalTarget) roots.push({ path: globalTarget, kind: 'yarn-global', required: false, source: 'yarn global dir' });
      events.push({ manager: 'yarn', check: 'global dir', ok: Boolean(globalTarget), path: globalTarget, optional: true, error: global.ok ? undefined : global.stderr.trim() || global.error?.message });
    }
  } else {
    events.push({ manager: 'yarn', check: '--version', ok: false, absent: yarnVersion.error?.code === 'ENOENT' });
  }
  return roots;
}

function standardRoots(home = os.homedir()) {
  const env = process.env;
  const candidates = [];
  const add = (target, kind) => {
    if (target) candidates.push({ path: path.resolve(target), kind, required: false, source: 'standard-path' });
  };

  add(env.npm_config_cache, 'npm-cache');
  add(env.PNPM_HOME, 'pnpm-home');
  add(env.BUN_INSTALL ? path.join(env.BUN_INSTALL, 'install', 'cache') : null, 'bun-cache');

  if (home) {
    add(path.join(home, '.npm'), 'npm-cache');
    add(path.join(home, '.cache', 'yarn'), 'yarn-cache');
    add(path.join(home, '.yarn', 'cache'), 'yarn-cache');
    add(path.join(home, '.local', 'share', 'pnpm', 'store'), 'pnpm-cache');
    add(path.join(home, '.pnpm-store'), 'pnpm-cache');
    add(path.join(home, '.bun', 'install', 'cache'), 'bun-cache');
    add(path.join(home, '.cache', 'node', 'corepack'), 'corepack-cache');
    add(path.join(home, 'Library', 'Caches', 'Yarn'), 'yarn-cache');
    add(path.join(home, 'Library', 'pnpm', 'store'), 'pnpm-cache');
  }

  if (process.platform === 'win32') {
    add(env.LOCALAPPDATA && path.join(env.LOCALAPPDATA, 'npm-cache'), 'npm-cache');
    add(env.LOCALAPPDATA && path.join(env.LOCALAPPDATA, 'Yarn', 'Cache'), 'yarn-cache');
    add(env.LOCALAPPDATA && path.join(env.LOCALAPPDATA, 'pnpm', 'store'), 'pnpm-cache');
    add(env.APPDATA && path.join(env.APPDATA, 'npm', 'node_modules'), 'npm-global');
  } else {
    add('/usr/local/lib/node_modules', 'npm-global');
    add('/usr/lib/node_modules', 'npm-global');
  }
  return candidates;
}

function mergeRootDescriptors(roots) {
  const byPath = new Map();
  for (const root of roots) {
    if (!root?.path) continue;
    const resolved = path.resolve(root.path);
    const key = process.platform === 'win32' ? resolved.toLowerCase() : resolved;
    const existing = byPath.get(key);
    if (existing) {
      const kinds = new Set(String(existing.kind).split('+').concat(String(root.kind).split('+')));
      existing.kind = [...kinds].sort().join('+');
      existing.required = existing.required || root.required;
      existing.sources = [...new Set([...(existing.sources || [existing.source]).filter(Boolean), root.source].filter(Boolean))];
    } else {
      byPath.set(key, { ...root, path: resolved, sources: root.source ? [root.source] : [] });
    }
  }
  return [...byPath.values()];
}

function discoverRoots(options = {}) {
  const events = [];
  const requested = [];
  const explicit = uniquePaths([...(options.roots || []), ...(options.positionalRoots || [])]);
  if (explicit.length) {
    for (const target of explicit) requested.push({ path: target, kind: 'project', required: true, source: 'command-line' });
  } else {
    requested.push({ path: process.cwd(), kind: 'project', required: true, source: 'working-directory' });
  }

  if (!options.projectOnly) {
    requested.push(...standardRoots());
    requested.push(...managerCommandRoots(events));
  }

  if (options.fullHome || options.system) {
    const home = os.homedir();
    if (home) requested.push({ path: home, kind: 'home', required: true, source: 'full-home' });
    requested.push({ path: os.tmpdir(), kind: 'temp', required: false, source: 'system-temp' });
  }

  if (options.system) {
    for (const userHome of discoverUserHomes(options)) {
      requested.push({ path: userHome, kind: 'system-user-home', required: false, source: 'system-user-discovery' });
    }
    const ciRoots = [
      process.env.GITHUB_WORKSPACE,
      process.env.CI_PROJECT_DIR,
      process.env.BUILD_SOURCESDIRECTORY,
      process.env.WORKSPACE,
      process.env.RUNNER_WORKSPACE,
    ];
    for (const ciRoot of ciRoots.filter(Boolean)) {
      requested.push({ path: ciRoot, kind: 'ci-workspace', required: false, source: 'ci-environment' });
    }
    if (process.platform !== 'win32') {
      for (const common of ['/workspace', '/workspaces', '/srv', '/opt']) {
        requested.push({ path: common, kind: 'system-workspace', required: false, source: 'common-system-path' });
      }
    } else if (process.env.SystemDrive) {
      requested.push({ path: path.join(process.env.SystemDrive, 'Users'), kind: 'system-user-root', required: false, source: 'windows-user-root' });
    }
  }

  const merged = mergeRootDescriptors(requested);
  const existing = [];
  for (const root of merged) {
    if (pathExistsSync(root.path)) existing.push(root);
    else if (root.required) events.push({ check: 'root-exists', ok: false, required: true, path: root.path, error: 'path does not exist' });
  }

  existing.sort((a, b) => {
    const priority = (root) => root.kind === 'project' ? 0 : /cache|global|store/.test(root.kind) ? 1 : 2;
    return priority(a) - priority(b) || a.path.localeCompare(b.path);
  });
  return { roots: existing, events };
}

function discoverUserHomes(options = {}) {
  const homes = new Set();
  if (os.homedir()) homes.add(os.homedir());
  if (!options.system || process.platform === 'win32') return [...homes];
  for (const base of ['/home', '/Users']) {
    try {
      for (const entry of fs.readdirSync(base, { withFileTypes: true })) {
        if (entry.isDirectory()) homes.add(path.join(base, entry.name));
      }
    } catch {
      // Missing or inaccessible base is expected on other platforms.
    }
  }
  if (process.platform !== 'win32') homes.add('/root');
  return [...homes].filter(pathExistsSync);
}

module.exports = {
  cleanCommandPath,
  discoverRoots,
  discoverUserHomes,
  managerCommandRoots,
  mergeRootDescriptors,
  standardRoots,
};
