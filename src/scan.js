'use strict';

const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const path = require('path');
const {
  CAMPAIGN,
  DEFAULT_MAX_FILES,
  CAMPAIGN_URL,
  EXIT_FINDINGS_BIT,
  EXIT_INCOMPLETE_BIT,
  INCIDENT_URL,
  REPORT_SCHEMA_VERSION,
  SCANNER_ID,
  SCANNER_NAME,
  VERSION,
} = require('./constants');
const { ScanContext } = require('./context');
const { prepareIocsForScan } = require('./ioc');
const { outputFileNames, renderHuman, renderJson, summarizeFindings, toSarif } = require('./report');
const { discoverRoots } = require('./roots');
const { scanRoots } = require('./scanners/filesystem');
const { scanPersistencePaths, scanProcesses } = require('./scanners/persistence');
const {
  atomicWriteFile,
  compactTimestamp,
  nowIso,
  severityRank,
  stableStringify,
} = require('./util');

function defaultOutputDir() {
  return path.resolve(process.cwd(), 'keyv-scan-reports', compactTimestamp());
}

function applyRootDiscoveryEvents(context, events) {
  for (const event of events) {
    if (event.required && !event.ok) {
      context.addCoverageGap('scan-root', `${event.path}: ${event.error || 'unavailable'}`, 'error');
      continue;
    }
    if (event.manager && !event.ok && !event.absent && !event.optional) {
      context.addCoverageGap(
        `${event.manager}-discovery`,
        `${event.check} failed${event.error ? `: ${event.error}` : ''}; that manager's global/cache coverage may be incomplete`,
        'warning',
      );
    }
  }
}

function applyIocEvents(context, prepared) {
  for (const event of prepared.events) {
    if (event.type === 'update-failed' && (!prepared.fresh || context.options.forceUpdate)) {
      context.addCoverageGap('ioc-update', `Live IOC refresh failed: ${event.error.message}`, 'error');
    }
  }
  if (!prepared.fresh) {
    const reason = prepared.iocs.bootstrap
      ? 'the bundled IOC file is a bootstrap feed and was not replaced by a validated live update'
      : prepared.iocs.futureDated
        ? `IOC manifest timestamp is ${prepared.iocs.futureByHours?.toFixed(2) || 'an unknown number of'} hours in the future`
        : `IOC feed age ${prepared.iocs.ageHours.toFixed(1)} hours exceeds the configured ${prepared.maxAgeHours}-hour maximum`;
    context.addCoverageGap('ioc-freshness', reason, 'error');
  }
}

function makeReport(context, prepared, roots, startedAt, finishedAt, options, outputDir) {
  const findings = context.findings.values();
  const failThreshold = severityRank(options.failOn || 'medium');
  const actionableFindings = findings.filter((finding) => severityRank(finding.severity) >= failThreshold);
  const coverageComplete = context.coverageGaps.length === 0 && context.fatalErrors.length === 0;
  let exitCode = 0;
  if (actionableFindings.length) exitCode |= EXIT_FINDINGS_BIT;
  if (!coverageComplete) exitCode |= EXIT_INCOMPLETE_BIT;
  const started = new Date(startedAt);
  const finished = new Date(finishedAt);

  return {
    schema_version: REPORT_SCHEMA_VERSION,
    scanner: {
      id: SCANNER_ID,
      name: SCANNER_NAME,
      version: VERSION,
      read_only: true,
    },
    campaign: {
      name: CAMPAIGN,
      references: [INCIDENT_URL, CAMPAIGN_URL],
    },
    scan: {
      started_at: startedAt,
      finished_at: finishedAt,
      duration_ms: finished.getTime() - started.getTime(),
      working_directory: process.cwd(),
      requested_roots: roots.map((root) => ({ path: root.path, kind: root.kind, required: root.required, sources: root.sources })),
      options: {
        project_only: options.projectOnly,
        full_home: options.fullHome,
        system: options.system,
        deep: options.deep,
        hash_all: options.hashAll,
        offline: options.offline,
        processes: options.processes,
        persistence: options.persistence,
        follow_symlinks: options.followSymlinks,
        follow_external_symlinks: options.followExternalSymlinks,
        strict_permissions: options.strictPermissions,
        max_files: options.maxFiles,
        fail_on: options.failOn,
      },
      host: {
        hostname: os.hostname(),
        platform: process.platform,
        release: os.release(),
        architecture: process.arch,
        node_version: process.version,
        username: (() => {
          try { return os.userInfo().username; } catch { return process.env.USER || process.env.USERNAME || null; }
        })(),
      },
      output_directory: outputDir,
    },
    iocs: {
      file: prepared.iocs.file,
      manifest_file: prepared.iocs.manifestFile,
      sha256: prepared.iocs.sha256,
      auxiliary_sha256: prepared.iocs.auxiliarySha256,
      fetched_at: prepared.iocs.fetchedAt,
      age_hours: Number.isFinite(prepared.iocs.ageHours) ? Number(prepared.iocs.ageHours.toFixed(3)) : null,
      future_dated: prepared.iocs.futureDated,
      fresh: prepared.fresh,
      bootstrap: prepared.iocs.bootstrap,
      package_count: prepared.iocs.packageCount,
      version_pair_count: prepared.iocs.versionPairCount,
      duplicate_pairs_ignored: prepared.iocs.duplicates.length,
      update_events: prepared.events,
      manifest: prepared.iocs.manifest,
    },
    coverage: {
      complete: coverageComplete,
      gaps: context.coverageGaps,
      operational_errors: context.operationalErrors,
    },
    statistics: context.statistics,
    summary: {
      ...summarizeFindings(findings),
      actionable_findings: actionableFindings.length,
      fail_threshold: options.failOn,
    },
    findings,
    fatal_errors: context.fatalErrors,
    exit_code: exitCode,
    exit_code_contract: {
      0: 'no actionable findings and complete requested coverage',
      1: 'one or more actionable findings; requested coverage complete',
      2: 'no actionable findings; requested coverage incomplete',
      3: 'one or more actionable findings and requested coverage incomplete',
    },
  };
}

async function writeReports(report, outputDir) {
  await fsp.mkdir(outputDir, { recursive: true });
  const files = outputFileNames(outputDir);
  await Promise.all([
    atomicWriteFile(files.human, renderHuman(report), { mode: 0o600 }),
    atomicWriteFile(files.json, renderJson(report), { mode: 0o600 }),
    atomicWriteFile(files.sarif, `${stableStringify(toSarif(report), 2)}\n`, { mode: 0o600 }),
  ]);
  return files;
}

async function runScan(options = {}) {
  const normalized = {
    ...options,
    roots: options.roots || [],
    positionalRoots: options.positionalRoots || [],
    exclude: options.exclude || [],
    projectOnly: Boolean(options.projectOnly),
    fullHome: Boolean(options.fullHome || options.system),
    system: Boolean(options.system),
    deep: Boolean(options.deep || options.system),
    hashAll: Boolean(options.hashAll),
    offline: Boolean(options.offline),
    processes: options.processes !== false,
    persistence: options.persistence !== false,
    followSymlinks: options.followSymlinks !== false,
    followExternalSymlinks: Boolean(options.followExternalSymlinks),
    strictPermissions: Boolean(options.strictPermissions),
    maxFiles: options.maxFiles ?? DEFAULT_MAX_FILES,
    failOn: options.failOn || 'medium',
    includePotential: options.includePotential !== false,
    verbose: Boolean(options.verbose),
  };
  const outputDir = path.resolve(options.outputDir || defaultOutputDir());
  const startedAt = nowIso();

  const prepared = await prepareIocsForScan(normalized);
  const scannerRoot = path.resolve(__dirname, '..');
  const context = new ScanContext({ iocs: prepared.iocs, options: normalized, scannerRoot });
  applyIocEvents(context, prepared);

  const discovery = discoverRoots(normalized);
  applyRootDiscoveryEvents(context, discovery.events);
  if (!discovery.roots.length) context.addCoverageGap('scan-root', 'No accessible scan roots were discovered', 'error');

  if (normalized.persistence) {
    await scanPersistencePaths(context);
    await scanProcesses(context);
  }
  await scanRoots(context, discovery.roots);

  const finishedAt = nowIso();
  const report = makeReport(context, prepared, discovery.roots, startedAt, finishedAt, normalized, outputDir);
  const files = await writeReports(report, outputDir);
  return { report, files, human: renderHuman(report) };
}

module.exports = {
  applyIocEvents,
  applyRootDiscoveryEvents,
  defaultOutputDir,
  makeReport,
  runScan,
  writeReports,
};
