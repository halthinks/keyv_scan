'use strict';

const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');

module.exports = Object.freeze({
  SCANNER_NAME: 'Keyv Incident Scanner',
  SCANNER_ID: 'keyv-incident-scanner',
  VERSION: '1.0.0',
  REPORT_SCHEMA_VERSION: '1.0.0',
  CAMPAIGN: 'Keyv/Cacheable npm supply-chain compromise (2026-08-04)',
  SOURCE_URL: 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/keyv-packages.csv',
  SOURCE_PAGE_URL: 'https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv',
  INCIDENT_URL: 'https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain',
  CAMPAIGN_URL: 'https://socket.dev/supply-chain-attacks/keyv-and-cacheable-compromise',
  DEFAULT_IOC_FILE: path.join(ROOT_DIR, 'iocs', 'keyv-packages.csv'),
  DEFAULT_IOC_MANIFEST: path.join(ROOT_DIR, 'iocs', 'source-manifest.json'),
  HASH_IOC_FILE: path.join(ROOT_DIR, 'iocs', 'hashes.json'),
  PERSISTENCE_IOC_FILE: path.join(ROOT_DIR, 'iocs', 'persistence.json'),
  DEFAULT_REFRESH_HOURS: 6,
  DEFAULT_MAX_IOC_AGE_HOURS: 24,
  MIN_PACKAGE_COUNT: 300,
  MIN_VERSION_PAIR_COUNT: 1000,
  MAX_IOC_BYTES: 10 * 1024 * 1024,
  MAX_JSON_BYTES: 8 * 1024 * 1024,
  MAX_LOCKFILE_BYTES: 64 * 1024 * 1024,
  MAX_TEXT_INSPECTION_BYTES: 8 * 1024 * 1024,
  MAX_ARCHIVE_BYTES: 150 * 1024 * 1024,
  MAX_ARCHIVE_OUTPUT_BYTES: 512 * 1024 * 1024,
  MAX_ARCHIVE_ENTRIES: 100_000,
  DEFAULT_MAX_FILES: 2_000_000,
  EXIT_FINDINGS_BIT: 1,
  EXIT_INCOMPLETE_BIT: 2,
});
