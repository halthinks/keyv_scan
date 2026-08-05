'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const {
  DEFAULT_IOC_FILE,
  DEFAULT_IOC_MANIFEST,
  DEFAULT_MAX_IOC_AGE_HOURS,
  DEFAULT_REFRESH_HOURS,
  SCANNER_NAME,
  SOURCE_URL,
  VERSION,
} = require('./constants');
const { loadIocs, updateIocs } = require('./ioc');
const { runScan } = require('./scan');
const { stableStringify } = require('./util');

const VALUE_OPTIONS = new Map([
  ['--root', 'roots'],
  ['--exclude', 'exclude'],
  ['--output-dir', 'outputDir'],
  ['--ioc-file', 'iocFile'],
  ['--manifest-file', 'manifestFile'],
  ['--source-url', 'sourceUrl'],
  ['--max-ioc-age-hours', 'maxIocAgeHours'],
  ['--refresh-hours', 'refreshHours'],
  ['--max-files', 'maxFiles'],
  ['--fail-on', 'failOn'],
  ['--timeout-ms', 'timeoutMs'],
]);

const BOOLEAN_OPTIONS = new Map([
  ['--project-only', ['projectOnly', true]],
  ['--full-home', ['fullHome', true]],
  ['--system', ['system', true]],
  ['--deep', ['deep', true]],
  ['--hash-all', ['hashAll', true]],
  ['--offline', ['offline', true]],
  ['--no-auto-update', ['noAutoUpdate', true]],
  ['--force-update', ['forceUpdate', true]],
  ['--allow-ioc-regression', ['allowRegression', true]],
  ['--strict-permissions', ['strictPermissions', true]],
  ['--no-processes', ['processes', false]],
  ['--no-persistence', ['persistence', false]],
  ['--no-follow-symlinks', ['followSymlinks', false]],
  ['--follow-external-symlinks', ['followExternalSymlinks', true]],
  ['--no-potential', ['includePotential', false]],
  ['--verbose', ['verbose', true]],
]);

function parseNumber(name, value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`${name} requires a non-negative number`);
  return parsed;
}

function parseArgs(argv) {
  const args = [...argv];
  let command = 'scan';
  if (args[0] && ['scan', 'update-iocs', 'verify-iocs', 'self-test', 'help'].includes(args[0])) command = args.shift();
  if (args.includes('--help') || args.includes('-h')) command = 'help';
  if (args.includes('--version') || args.includes('-V')) return { command: 'version', options: {} };

  const options = { roots: [], exclude: [], positionalRoots: [] };
  let positionalOnly = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--') {
      positionalOnly = true;
      continue;
    }
    if (!positionalOnly && VALUE_OPTIONS.has(arg)) {
      const key = VALUE_OPTIONS.get(arg);
      const value = args[index + 1];
      if (value === undefined) throw new Error(`${arg} requires a value`);
      index += 1;
      const converted = ['maxIocAgeHours', 'refreshHours', 'maxFiles', 'timeoutMs'].includes(key) ? parseNumber(arg, value) : value;
      if (key === 'maxFiles' && !Number.isInteger(converted)) throw new Error(`${arg} requires a non-negative integer`);
      if (key === 'timeoutMs' && (!Number.isInteger(converted) || converted < 1)) throw new Error(`${arg} requires a positive integer`);
      if (key === 'roots' || key === 'exclude') options[key].push(converted);
      else options[key] = converted;
      continue;
    }
    if (!positionalOnly && BOOLEAN_OPTIONS.has(arg)) {
      const [key, value] = BOOLEAN_OPTIONS.get(arg);
      options[key] = value;
      continue;
    }
    if (!positionalOnly && arg.startsWith('-')) throw new Error(`unknown option: ${arg}`);
    options.positionalRoots.push(arg);
  }

  options.iocFile = options.iocFile ? path.resolve(options.iocFile) : DEFAULT_IOC_FILE;
  options.manifestFile = options.manifestFile ? path.resolve(options.manifestFile) : DEFAULT_IOC_MANIFEST;
  options.sourceUrl = options.sourceUrl || SOURCE_URL;
  options.maxIocAgeHours ??= DEFAULT_MAX_IOC_AGE_HOURS;
  options.refreshHours ??= DEFAULT_REFRESH_HOURS;
  if (options.offline && options.forceUpdate) throw new Error('--offline and --force-update cannot be used together');
  if (options.noAutoUpdate && options.forceUpdate) throw new Error('--no-auto-update and --force-update cannot be used together');
  options.failOn ||= 'medium';
  if (!['critical', 'high', 'medium', 'low', 'info'].includes(options.failOn)) {
    throw new Error('--fail-on must be critical, high, medium, low, or info');
  }
  return { command, options };
}

function helpText() {
  return `${SCANNER_NAME} v${VERSION}\n\n` +
`USAGE\n` +
`  node bin/keyv-scan.js scan [paths...] [options]\n` +
`  node bin/keyv-scan.js update-iocs [options]\n` +
`  node bin/keyv-scan.js verify-iocs [options]\n` +
`  node bin/keyv-scan.js self-test\n\n` +
`SCAN COVERAGE\n` +
`  Default: current project, installed dependency trees, detected npm/pnpm/Yarn\n` +
`  caches and global roots, known persistence paths, temp artifacts, and processes.\n` +
`  --system             Add discovered user homes, common workspaces, and temp roots; implies --deep\n` +
`  --full-home          Recursively scan the current user's home directory\n` +
`  --project-only       Do not add package-manager caches or global roots\n` +
`  --deep               Hash/inspect JavaScript files and all archives encountered\n` +
`  --hash-all           Compute SHA-256 for every regular file under requested roots (expensive)\n` +
`  --root PATH          Add a root; may be repeated\n` +
`  --exclude PATH       Exclude a subtree; may be repeated\n` +
`  --strict-permissions Treat nested permission failures as incomplete coverage\n` +
`  --no-processes       Skip running-process inspection\n` +
`  --no-persistence     Skip documented persistence, temp-artifact, and process checks\n` +
`  --no-follow-symlinks Do not follow symlinks even when they remain inside a root\n` +
`  --follow-external-symlinks  Permit symlinks to targets outside the requested root\n` +
`  --max-files N        Stop after N files (default 2000000)\n\n` +
`IOC SAFETY\n` +
`  The scanner auto-refreshes the pinned Wiz Research CSV when older than 6 hours.\n` +
`  --offline            Never make the IOC update request\n` +
`  --no-auto-update     Use the local feed without automatic refresh\n` +
`  --force-update       Refresh before scanning\n` +
`  --max-ioc-age-hours N  Maximum feed age for a complete result (default 24)\n` +
`  --ioc-file PATH      Alternate canonical package IOC CSV\n` +
`  --manifest-file PATH Alternate IOC manifest\n\n` +
`OUTPUT\n` +
`  --output-dir PATH    Directory for report.txt, report.json, and report.sarif\n` +
`  --fail-on LEVEL      Exit finding bit threshold (default medium)\n` +
`  --no-potential       Suppress manifest-range exposure findings\n` +
`  --verbose            Print each root as it begins\n\n` +
`EXIT CODES (BITMASK)\n` +
`  0 clean for requested checks; 1 actionable findings; 2 incomplete; 3 both.\n`;
}

async function commandUpdate(options) {
  const result = await updateIocs(options);
  process.stdout.write(`${stableStringify(result, 2)}\n`);
  return 0;
}

async function commandVerify(options) {
  const iocs = await loadIocs(options);
  const validForCompleteScan = !iocs.bootstrap
    && !iocs.futureDated
    && iocs.ageHours <= options.maxIocAgeHours;
  process.stdout.write(`${stableStringify({
    file: iocs.file,
    manifest_file: iocs.manifestFile,
    sha256: iocs.sha256,
    fetched_at: iocs.fetchedAt,
    age_hours: iocs.ageHours,
    max_ioc_age_hours: options.maxIocAgeHours,
    bootstrap: iocs.bootstrap,
    package_count: iocs.packageCount,
    version_pair_count: iocs.versionPairCount,
    hash_ioc_count: iocs.hashes.length,
    auxiliary_sha256: iocs.auxiliarySha256,
    future_dated: iocs.futureDated,
    persistence_path_count: iocs.persistence.paths.length,
    valid_for_complete_scan: validForCompleteScan,
  }, 2)}
`);
  return validForCompleteScan ? 0 : 2;
}

function commandSelfTest() {
  const result = spawnSync(process.execPath, ['--test'], {
    cwd: path.resolve(__dirname, '..'),
    stdio: 'inherit',
    windowsHide: true,
  });
  return result.status ?? 2;
}

async function main(argv) {
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`Argument error: ${error.message}\n\n${helpText()}`);
    process.exitCode = 2;
    return;
  }

  if (parsed.command === 'help') {
    process.stdout.write(helpText());
    return;
  }
  if (parsed.command === 'version') {
    process.stdout.write(`${VERSION}\n`);
    return;
  }

  let exitCode;
  if (parsed.command === 'update-iocs') exitCode = await commandUpdate(parsed.options);
  else if (parsed.command === 'verify-iocs') exitCode = await commandVerify(parsed.options);
  else if (parsed.command === 'self-test') exitCode = commandSelfTest();
  else {
    const result = await runScan(parsed.options);
    process.stdout.write(result.human);
    process.stdout.write(`Reports:\n  ${result.files.human}\n  ${result.files.json}\n  ${result.files.sarif}\n`);
    exitCode = result.report.exit_code;
  }
  process.exitCode = exitCode;
}

module.exports = {
  helpText,
  main,
  parseArgs,
};
