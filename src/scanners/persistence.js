'use strict';

const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const path = require('path');
const { INCIDENT_URL } = require('../constants');
const { discoverUserHomes } = require('../roots');
const { runCommand } = require('../util');
const { inspectFileArtifact } = require('./content');

function expandHome(template, home) {
  if (template === '~') return home;
  if (template.startsWith(`~${path.sep}`) || template.startsWith('~/')) return path.join(home, template.slice(2));
  return template;
}

function globNameMatches(name, pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i').test(name);
}

function appliesToPlatform(indicator, platform = process.platform) {
  return !indicator.platforms || indicator.platforms.includes(platform);
}

async function scanPersistencePaths(context) {
  if (context.options.persistence === false) return;
  const homes = discoverUserHomes(context.options);
  const checkedTargets = new Set();
  for (const home of homes) {
    for (const indicator of context.iocs.persistence.paths) {
      if (!appliesToPlatform(indicator)) continue;
      const target = path.resolve(expandHome(indicator.path, home));
      const targetKey = process.platform === 'win32' ? target.toLowerCase() : target;
      if (checkedTargets.has(targetKey)) continue;
      checkedTargets.add(targetKey);
      context.statistics.persistence_paths_checked += 1;
      try {
        const stat = await fsp.lstat(target);
        context.findings.add({
          rule_id: 'KVS-PERSISTENCE-PATH',
          title: `Documented campaign persistence artifact exists: ${indicator.type}`,
          description: 'This exact path is documented for the campaign token-monitor persistence or its state.',
          category: 'persistence',
          severity: indicator.severity || 'critical',
          confidence: 'strong',
          source_kind: 'persistence',
          location: { path: target },
          evidence: `Exact documented path exists (${stat.isDirectory() ? 'directory' : 'file'}, ${stat.size} bytes)`,
          remediation_key: 'persistence',
          references: [INCIDENT_URL],
          metadata: { sensitive_content_not_read: Boolean(indicator.sensitive), mode: stat.mode & 0o777 },
        });
        if (indicator.read_content && stat.isFile()) {
          await inspectFileArtifact(context, target, { inspectText: true });
        }
      } catch (error) {
        if (error.code !== 'ENOENT') context.addOperationalError('persistence-path', target, error, { incomplete: true });
      }
    }
  }

  const tempDirectories = new Set([os.tmpdir()]);
  if (process.platform !== 'win32') tempDirectories.add('/tmp');
  for (const directory of tempDirectories) {
    try {
      const entries = await fsp.readdir(directory, { withFileTypes: true });
      for (const entry of entries) {
        const matched = context.iocs.persistence.temp_globs.find((pattern) => globNameMatches(entry.name, pattern));
        if (!matched) continue;
        const target = path.join(directory, entry.name);
        const isMonitor = entry.name.toLowerCase().includes('gh-token-monitor');
        context.findings.add({
          rule_id: isMonitor ? 'KVS-PERSISTENCE-TEMP-ARTIFACT' : 'KVS-BUN-DOWNLOAD-TEMP',
          title: isMonitor ? 'Campaign token-monitor temporary artifact detected' : 'Campaign-associated Bun download directory detected',
          description: isMonitor
            ? 'The campaign writes gh-token-monitor output/error logs in temporary storage.'
            : 'The setup.mjs loader uses bun-dl-* temporary directories while downloading and executing Bun.',
          category: isMonitor ? 'persistence' : 'execution-artifact',
          severity: isMonitor ? 'high' : 'medium',
          confidence: 'heuristic',
          source_kind: 'temporary-artifact',
          location: { path: target },
          evidence: `Name matched documented pattern ${matched}`,
          remediation_key: isMonitor ? 'persistence' : 'payload',
          references: [INCIDENT_URL],
        });
      }
    } catch (error) {
      context.addOperationalError('temp-artifacts', directory, error, { incomplete: false });
    }
  }
}

function parseProcessLines(output) {
  return String(output).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

async function scanProcesses(context) {
  if (context.options.processes === false || context.options.persistence === false) return;
  let result;
  if (process.platform === 'win32') {
    result = runCommand('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      'Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress',
    ], { timeoutMs: 20_000, maxBuffer: 32 * 1024 * 1024 });
  } else {
    result = runCommand('ps', ['-axo', 'pid=,user=,command='], { timeoutMs: 15_000, maxBuffer: 32 * 1024 * 1024 });
  }
  if (!result.ok) {
    context.addOperationalError('process-list', '(local processes)', result.error || new Error(result.stderr || `exit ${result.status}`), { incomplete: true });
    return;
  }

  const indicators = context.iocs.persistence.process_indicators;
  const lines = process.platform === 'win32'
    ? (() => {
      try {
        const parsed = JSON.parse(result.stdout || '[]');
        return (Array.isArray(parsed) ? parsed : [parsed]).map((item) => `${item.ProcessId} ${item.CommandLine || ''}`);
      } catch {
        return parseProcessLines(result.stdout);
      }
    })()
    : parseProcessLines(result.stdout);

  context.statistics.processes_checked += lines.length;
  for (const line of lines) {
    const lower = line.toLowerCase();
    const matched = indicators.filter((indicator) => lower.includes(indicator.toLowerCase()));
    if (!matched.length) continue;
    const listedPid = Number.parseInt(line.match(/^\s*(\d+)/)?.[1] || '', 10);
    if (listedPid === process.pid) continue;
    context.findings.add({
      rule_id: 'KVS-SUSPICIOUS-PROCESS',
      title: 'Running process command line contains campaign indicators',
      description: 'The process list contains a documented loader, payload, temporary-directory, or persistence name.',
      category: 'running-process',
      severity: matched.some((indicator) => indicator.includes('gh-token-monitor')) ? 'critical' : 'high',
      confidence: 'strong',
      source_kind: 'process-list',
      location: { entry: line.slice(0, 2048) },
      evidence: `Indicators: ${matched.join(', ')}`,
      remediation_key: 'persistence',
      references: [INCIDENT_URL],
    });
  }
}

module.exports = {
  appliesToPlatform,
  expandHome,
  globNameMatches,
  scanPersistencePaths,
  scanProcesses,
};
