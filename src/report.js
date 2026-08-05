'use strict';

const path = require('path');
const { fileUri, formatDuration, severityRank, stableStringify } = require('./util');

function summarizeFindings(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategory = {};
  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
  }
  return { total: findings.length, by_severity: bySeverity, by_category: byCategory };
}

function renderHuman(report) {
  const lines = [];
  const summary = report.summary;
  lines.push(`${report.scanner.name} v${report.scanner.version}`);
  lines.push(`Campaign: ${report.campaign.name}`);
  lines.push(`Started:  ${report.scan.started_at}`);
  lines.push(`Finished: ${report.scan.finished_at}`);
  lines.push(`Duration: ${formatDuration(report.scan.duration_ms)}`);
  lines.push(`IOC feed: ${report.iocs.package_count} packages / ${report.iocs.version_pair_count} exact versions`);
  lines.push(`IOC SHA-256: ${report.iocs.sha256}`);
  lines.push(`Coverage: ${report.coverage.complete ? 'COMPLETE FOR REQUESTED CHECKS' : 'INCOMPLETE'}`);
  lines.push(`Files examined: ${report.statistics.files_examined}`);
  lines.push(`Findings: ${summary.total} (${summary.by_severity.critical} critical, ${summary.by_severity.high} high, ${summary.by_severity.medium} medium, ${summary.by_severity.low} low)`);
  lines.push('');

  if (!report.coverage.complete) {
    lines.push('Coverage gaps:');
    for (const gap of report.coverage.gaps) {
      lines.push(`  - [${gap.severity || 'warning'}] ${gap.check}: ${gap.message}`);
    }
    lines.push('');
  }

  if (!report.findings.length) {
    lines.push('No campaign indicators were found in the locations successfully scanned.');
    if (!report.coverage.complete) {
      lines.push('This is NOT a clean bill of health because one or more requested checks were incomplete.');
    }
  } else {
    lines.push('Findings:');
    for (const finding of report.findings) {
      const target = finding.location?.path
        ? `${finding.location.path}${finding.location.entry ? ` :: ${finding.location.entry}` : ''}`
        : finding.location?.entry || '(no path)';
      const packageText = finding.package ? ` ${finding.package.name}@${finding.package.version || '?'}` : '';
      lines.push(`  [${finding.severity.toUpperCase()}] ${finding.rule_id}${packageText}`);
      lines.push(`    ${finding.title}`);
      lines.push(`    Location: ${target}`);
      if (finding.evidence) lines.push(`    Evidence: ${finding.evidence}`);
      lines.push(`    Confidence: ${finding.confidence}`);
      lines.push(`    Action: ${finding.remediation}`);
    }
  }

  lines.push('');
  lines.push(`Exit code: ${report.exit_code} (bit 1=findings, bit 2=incomplete)`);
  return `${lines.join('\n')}\n`;
}

function sarifLevel(severity) {
  if (severityRank(severity) >= severityRank('high')) return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function toSarif(report) {
  const rules = new Map();
  for (const finding of report.findings) {
    if (!rules.has(finding.rule_id)) {
      rules.set(finding.rule_id, {
        id: finding.rule_id,
        name: finding.rule_id.replace(/[^A-Za-z0-9]/g, '_'),
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description || finding.title },
        help: { text: finding.remediation },
        defaultConfiguration: { level: sarifLevel(finding.severity) },
        properties: {
          category: finding.category,
          severity: finding.severity,
          confidence: finding.confidence,
          tags: ['security', 'supply-chain', 'npm', 'keyv'],
        },
      });
    }
  }

  const results = report.findings.map((finding) => {
    const result = {
      ruleId: finding.rule_id,
      level: sarifLevel(finding.severity),
      message: { text: `${finding.title}${finding.evidence ? `: ${finding.evidence}` : ''}` },
      fingerprints: { keyvIncidentScannerId: finding.id },
      properties: {
        severity: finding.severity,
        confidence: finding.confidence,
        category: finding.category,
        package: finding.package,
        sourceKind: finding.source_kind,
      },
    };
    if (finding.location?.path) {
      result.locations = [{
        physicalLocation: {
          artifactLocation: {
            uri: fileUri(finding.location.path),
            uriBaseId: '%SRCROOT%',
          },
          region: finding.location.line ? { startLine: finding.location.line } : undefined,
        },
        logicalLocations: finding.location.entry ? [{ name: finding.location.entry }] : undefined,
      }];
    }
    return result;
  });

  if (!report.coverage.complete) {
    for (const gap of report.coverage.gaps) {
      results.push({
        ruleId: 'KVS-SCAN-INCOMPLETE',
        level: 'warning',
        message: { text: `${gap.check}: ${gap.message}` },
        properties: { coverageGap: true },
      });
    }
    rules.set('KVS-SCAN-INCOMPLETE', {
      id: 'KVS-SCAN-INCOMPLETE',
      name: 'KVS_SCAN_INCOMPLETE',
      shortDescription: { text: 'Requested scanner coverage was incomplete' },
      defaultConfiguration: { level: 'warning' },
      properties: { tags: ['security', 'scan-coverage'] },
    });
  }

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: report.scanner.name,
          version: report.scanner.version,
          informationUri: report.campaign.references[0],
          rules: [...rules.values()],
        },
      },
      invocations: [{
        executionSuccessful: report.fatal_errors.length === 0,
        startTimeUtc: report.scan.started_at,
        endTimeUtc: report.scan.finished_at,
        exitCode: report.exit_code,
        workingDirectory: { uri: fileUri(report.scan.working_directory) },
      }],
      results,
      properties: {
        iocSha256: report.iocs.sha256,
        iocPackageCount: report.iocs.package_count,
        iocVersionPairCount: report.iocs.version_pair_count,
        coverageComplete: report.coverage.complete,
      },
    }],
  };
}

function renderJson(report) {
  return `${stableStringify(report, 2)}\n`;
}

function outputFileNames(outputDir) {
  return {
    human: path.join(outputDir, 'report.txt'),
    json: path.join(outputDir, 'report.json'),
    sarif: path.join(outputDir, 'report.sarif'),
  };
}

module.exports = {
  outputFileNames,
  renderHuman,
  renderJson,
  summarizeFindings,
  toSarif,
};
