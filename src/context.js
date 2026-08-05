'use strict';

const { FindingStore } = require('./findings');
const { sanitizeError } = require('./util');

class ScanContext {
  constructor({ iocs, options, scannerRoot }) {
    this.iocs = iocs;
    this.options = options;
    this.scannerRoot = scannerRoot;
    this.findings = new FindingStore();
    this.coverageGaps = [];
    this.coverageGapKeys = new Set();
    this.operationalErrors = [];
    this.fatalErrors = [];
    this.statistics = {
      roots_requested: 0,
      roots_scanned: 0,
      directories_examined: 0,
      files_examined: 0,
      bytes_examined: 0,
      package_json_files: 0,
      package_occurrences: 0,
      lockfiles: 0,
      archives_inspected: 0,
      archive_entries_inspected: 0,
      artifacts_inspected: 0,
      hash_matches: 0,
      cache_metadata_files: 0,
      npm_cache_index_entries: 0,
      persistence_paths_checked: 0,
      processes_checked: 0,
      skipped_paths: 0,
    };
    this.visitedDirectories = new Set();
    this.visitedFiles = new Set();
  }

  addCoverageGap(check, message, severity = 'warning', metadata) {
    const key = `${check}\0${message}`;
    if (this.coverageGapKeys.has(key)) return;
    this.coverageGapKeys.add(key);
    this.coverageGaps.push({ check, message, severity, metadata });
  }

  addOperationalError(check, target, error, options = {}) {
    const record = { check, target, error: sanitizeError(error), incomplete: Boolean(options.incomplete) };
    this.operationalErrors.push(record);
    if (options.incomplete) {
      this.addCoverageGap(check, `${target}: ${record.error.message}`, options.severity || 'warning');
    }
  }

  addFatalError(check, error) {
    const record = { check, error: sanitizeError(error) };
    this.fatalErrors.push(record);
    this.addCoverageGap(check, record.error.message, 'error');
  }
}

module.exports = { ScanContext };
