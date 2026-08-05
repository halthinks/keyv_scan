'use strict';

const fs = require('fs');
const fsp = fs.promises;
const https = require('https');
const path = require('path');
const {
  DEFAULT_IOC_FILE,
  DEFAULT_IOC_MANIFEST,
  DEFAULT_MAX_IOC_AGE_HOURS,
  DEFAULT_REFRESH_HOURS,
  HASH_IOC_FILE,
  MAX_IOC_BYTES,
  MIN_PACKAGE_COUNT,
  MIN_VERSION_PAIR_COUNT,
  PERSISTENCE_IOC_FILE,
  SCANNER_ID,
  SOURCE_URL,
  VERSION,
} = require('./constants');
const { parsePackageCsv, serializePackageCsv } = require('./csv');
const {
  atomicWriteFile,
  hashBuffer,
  hashFile,
  nowIso,
  pathExists,
  readJsonFile,
  readTextFile,
  sanitizeError,
  stableStringify,
} = require('./util');

const ALLOWED_IOC_HOSTS = new Set(['raw.githubusercontent.com', 'githubusercontent.com']);
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

async function readPackageIocBundle(iocFile) {
  if (await pathExists(iocFile)) {
    const [buffer, stat] = await Promise.all([
      fsp.readFile(iocFile),
      fsp.stat(iocFile),
    ]);
    if (buffer.length > MAX_IOC_BYTES) throw new Error(`IOC package feed exceeded ${MAX_IOC_BYTES} bytes`);
    return { buffer, text: buffer.toString('utf8'), stat, sourceFiles: [iocFile] };
  }

  const buffers = [];
  const stats = [];
  const sourceFiles = [];
  for (let index = 1; index <= 99; index += 1) {
    const part = `${iocFile}.part${String(index).padStart(2, '0')}`;
    if (!(await pathExists(part))) break;
    const [buffer, stat] = await Promise.all([fsp.readFile(part), fsp.stat(part)]);
    buffers.push(buffer);
    stats.push(stat);
    sourceFiles.push(part);
  }
  if (buffers.length < 2) throw new Error(`IOC package feed not found: ${iocFile}`);
  const buffer = Buffer.concat(buffers);
  if (buffer.length > MAX_IOC_BYTES) throw new Error(`IOC package feed exceeded ${MAX_IOC_BYTES} bytes`);
  const mtimeMs = Math.max(...stats.map((stat) => stat.mtimeMs));
  return {
    buffer,
    text: buffer.toString('utf8'),
    stat: { mtime: new Date(mtimeMs), mtimeMs },
    sourceFiles,
  };
}

function fetchText(url, options = {}, redirectCount = 0) {
  const timeoutMs = options.timeoutMs || 10_000;
  const maxBytes = options.maxBytes || MAX_IOC_BYTES;
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') throw new Error(`IOC source must use HTTPS: ${url}`);
  if (!ALLOWED_IOC_HOSTS.has(parsed.hostname)) {
    throw new Error(`IOC source host is not allowlisted: ${parsed.hostname}`);
  }
  if (redirectCount > 3) throw new Error('too many IOC source redirects');

  return new Promise((resolve, reject) => {
    const request = https.get(parsed, {
      headers: {
        'User-Agent': `${SCANNER_ID}/${VERSION}`,
        Accept: 'text/csv,text/plain;q=0.9,*/*;q=0.1',
      },
    }, (response) => {
      const status = response.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(status)) {
        const location = response.headers.location;
        response.resume();
        if (!location) return reject(new Error(`IOC source returned ${status} without Location`));
        const next = new URL(location, parsed).toString();
        return resolve(fetchText(next, options, redirectCount + 1));
      }
      if (status !== 200) {
        response.resume();
        return reject(new Error(`IOC source returned HTTP ${status}`));
      }

      const chunks = [];
      let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > maxBytes) {
          request.destroy(new Error(`IOC source exceeded ${maxBytes} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        const buffer = Buffer.concat(chunks);
        resolve({
          text: buffer.toString('utf8'),
          buffer,
          url: parsed.toString(),
          headers: response.headers,
          status,
        });
      });
      response.on('error', reject);
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error(`IOC update timed out after ${timeoutMs} ms`)));
    request.on('error', reject);
  });
}

function validateHashIocs(entries) {
  if (!Array.isArray(entries) || entries.length < 3) throw new Error('hash IOC file must contain at least three entries');
  const seen = new Set();
  for (const entry of entries) {
    if (!entry || !['sha256', 'sha512'].includes(entry.algorithm)) {
      throw new Error('hash IOC entry has unsupported algorithm');
    }
    const expectedLength = entry.algorithm === 'sha256' ? 64 : 128;
    if (!new RegExp(`^[a-f0-9]{${expectedLength}}$`, 'i').test(entry.hash || '')) {
      throw new Error(`invalid ${entry.algorithm} IOC: ${entry.hash}`);
    }
    if (typeof entry.rule_id !== 'string' || !entry.rule_id.startsWith('KVS-')) {
      throw new Error('hash IOC entry has an invalid rule_id');
    }
    const key = `${entry.algorithm}:${entry.hash.toLowerCase()}`;
    if (seen.has(key)) throw new Error(`duplicate hash IOC: ${key}`);
    seen.add(key);
  }
  return entries.map((entry) => ({ ...entry, hash: entry.hash.toLowerCase() }));
}

function validatePersistenceIocs(config) {
  if (!config || !Array.isArray(config.paths) || !Array.isArray(config.temp_globs)) {
    throw new Error('persistence IOC file is missing paths or temp_globs arrays');
  }
  if (!Array.isArray(config.process_indicators) || !Array.isArray(config.autostart_files)) {
    throw new Error('persistence IOC file is missing process_indicators or autostart_files arrays');
  }
  for (const indicator of config.paths) {
    if (!indicator || typeof indicator.path !== 'string' || !indicator.path.trim()) {
      throw new Error('persistence IOC path entry is invalid');
    }
    if (indicator.platforms && (!Array.isArray(indicator.platforms) || !indicator.platforms.every((value) => ['linux', 'darwin', 'win32'].includes(value)))) {
      throw new Error(`persistence IOC has invalid platforms for ${indicator.path}`);
    }
  }
  return config;
}

function validateSourceManifest(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('IOC source manifest is required and must be a JSON object');
  }
  if (manifest.schema_version !== 1) throw new Error(`unsupported IOC manifest schema_version: ${manifest.schema_version}`);
  if (typeof manifest.bootstrap !== 'boolean') throw new Error('IOC manifest bootstrap must be a boolean');
  if (!Number.isInteger(manifest.package_count) || manifest.package_count < 1) {
    throw new Error('IOC manifest package_count must be a positive integer');
  }
  if (!Number.isInteger(manifest.version_pair_count) || manifest.version_pair_count < 1) {
    throw new Error('IOC manifest version_pair_count must be a positive integer');
  }
  if (!/^[a-f0-9]{64}$/i.test(manifest.canonical_sha256 || '')) {
    throw new Error('IOC manifest canonical_sha256 must be a SHA-256 hex digest');
  }
  if (!manifest.auxiliary_sha256 || typeof manifest.auxiliary_sha256 !== 'object' || Array.isArray(manifest.auxiliary_sha256)) {
    throw new Error('IOC manifest auxiliary_sha256 object is required');
  }
  for (const field of ['hashes_json', 'persistence_json']) {
    if (!/^[a-f0-9]{64}$/i.test(manifest.auxiliary_sha256[field] || '')) {
      throw new Error(`IOC manifest auxiliary_sha256.${field} must be a SHA-256 hex digest`);
    }
  }
  if (typeof manifest.fetched_at !== 'string' || !Number.isFinite(new Date(manifest.fetched_at).getTime())) {
    throw new Error('IOC manifest fetched_at must be a valid date-time');
  }
  for (const field of ['source_url', 'resolved_url', 'generated_by']) {
    if (typeof manifest[field] !== 'string' || !manifest[field].trim()) {
      throw new Error(`IOC manifest ${field} is required`);
    }
  }
  for (const field of ['source_url', 'resolved_url']) {
    let parsed;
    try { parsed = new URL(manifest[field]); } catch { throw new Error(`IOC manifest ${field} must be a valid URL`); }
    if (parsed.protocol !== 'https:') throw new Error(`IOC manifest ${field} must use HTTPS`);
  }
  if (manifest.canonical_line_endings !== 'LF') {
    throw new Error('IOC manifest canonical_line_endings must be LF');
  }
  return manifest;
}

async function loadManifest(file = DEFAULT_IOC_MANIFEST) {
  if (!(await pathExists(file))) return null;
  return readJsonFile(file, 1024 * 1024);
}

function verifyManifestValue(manifest, field, actual, label = field) {
  if (manifest?.[field] !== undefined && manifest[field] !== actual) {
    throw new Error(`IOC manifest ${label} mismatch: expected ${manifest[field]}, got ${actual}`);
  }
}

function findMissingPairs(previousPackages, nextPackages, limit = 20) {
  const missing = [];
  for (const [packageName, versions] of previousPackages) {
    const nextVersions = nextPackages.get(packageName);
    for (const version of versions) {
      if (!nextVersions?.has(version)) {
        missing.push(`${packageName}@${version}`);
        if (missing.length >= limit) return missing;
      }
    }
  }
  return missing;
}

function detectLineEndings(buffer) {
  const text = buffer.toString('utf8');
  if (/\r\n/.test(text)) return 'CRLF';
  if (/\n/.test(text)) return 'LF';
  return 'none';
}

function computeGitBlobSha(buffer) {
  const header = Buffer.from(`blob ${buffer.length}\0`, 'utf8');
  return hashBuffer(Buffer.concat([header, buffer]), 'sha1');
}

async function loadIocs(options = {}) {
  const iocFile = path.resolve(options.iocFile || DEFAULT_IOC_FILE);
  const manifestFile = path.resolve(options.manifestFile || DEFAULT_IOC_MANIFEST);
  const hashIocFile = path.resolve(options.hashIocFile || HASH_IOC_FILE);
  const persistenceIocFile = path.resolve(options.persistenceIocFile || PERSISTENCE_IOC_FILE);
  const minPackages = options.minPackages ?? MIN_PACKAGE_COUNT;
  const minPairs = options.minPairs ?? MIN_VERSION_PAIR_COUNT;

  const [packageBundle, manifest, hashEntries, persistenceConfig, hashIocSha256, persistenceIocSha256] = await Promise.all([
    readPackageIocBundle(iocFile),
    loadManifest(manifestFile),
    readJsonFile(hashIocFile, 1024 * 1024),
    readJsonFile(persistenceIocFile, 1024 * 1024),
    hashFile(hashIocFile, 'sha256'),
    hashFile(persistenceIocFile, 'sha256'),
  ]);
  const { text, stat, buffer, sourceFiles } = packageBundle;
  const sha256 = hashBuffer(buffer, 'sha256');
  validateSourceManifest(manifest);
  const parsed = parsePackageCsv(text, { minPackages, minPairs });

  verifyManifestValue(manifest, 'canonical_sha256', sha256, 'canonical hash');
  verifyManifestValue(manifest, 'package_count', parsed.packageCount, 'package count');
  verifyManifestValue(manifest, 'version_pair_count', parsed.versionPairCount, 'version-pair count');
  verifyManifestValue(manifest.auxiliary_sha256, 'hashes_json', hashIocSha256, 'hashes.json hash');
  verifyManifestValue(manifest.auxiliary_sha256, 'persistence_json', persistenceIocSha256, 'persistence.json hash');

  const timestamp = manifest?.fetched_at || stat.mtime.toISOString();
  const fetchedAt = new Date(timestamp);
  const timestampMs = fetchedAt.getTime();
  const timestampValid = Number.isFinite(timestampMs);
  const futureByMs = timestampValid ? timestampMs - Date.now() : Infinity;
  const futureDated = !timestampValid || futureByMs > MAX_FUTURE_SKEW_MS;
  const ageHours = timestampValid ? Math.max(0, (Date.now() - timestampMs) / 3_600_000) : Infinity;

  return {
    file: iocFile,
    sourceFiles,
    manifestFile,
    hashIocFile,
    persistenceIocFile,
    manifest,
    packages: parsed.packages,
    packageCount: parsed.packageCount,
    versionPairCount: parsed.versionPairCount,
    duplicates: parsed.duplicates,
    sha256,
    auxiliarySha256: {
      hashes_json: hashIocSha256,
      persistence_json: persistenceIocSha256,
    },
    fetchedAt: timestamp,
    ageHours,
    futureDated,
    futureByHours: Number.isFinite(futureByMs) ? Math.max(0, futureByMs / 3_600_000) : null,
    bootstrap: Boolean(manifest?.bootstrap),
    hashes: validateHashIocs(hashEntries),
    persistence: validatePersistenceIocs(persistenceConfig),
  };
}

async function readPreviousPackages(iocFile) {
  try {
    const { text } = await readPackageIocBundle(iocFile);
    return parsePackageCsv(text, { minPackages: 1, minPairs: 1 }).packages;
  } catch {
    return null;
  }
}

async function updateIocs(options = {}) {
  const iocFile = path.resolve(options.iocFile || DEFAULT_IOC_FILE);
  const manifestFile = path.resolve(options.manifestFile || DEFAULT_IOC_MANIFEST);
  const hashIocFile = path.resolve(options.hashIocFile || HASH_IOC_FILE);
  const persistenceIocFile = path.resolve(options.persistenceIocFile || PERSISTENCE_IOC_FILE);
  const sourceUrl = options.sourceUrl || SOURCE_URL;
  const [existingManifest, previousPackages] = await Promise.all([
    loadManifest(manifestFile).catch(() => null),
    readPreviousPackages(iocFile),
  ]);
  const response = await fetchText(sourceUrl, {
    timeoutMs: options.timeoutMs || 10_000,
    maxBytes: MAX_IOC_BYTES,
  });

  const parsed = parsePackageCsv(response.text, {
    minPackages: options.minPackages ?? MIN_PACKAGE_COUNT,
    minPairs: options.minPairs ?? MIN_VERSION_PAIR_COUNT,
  });

  if (!options.allowRegression) {
    if (existingManifest && !existingManifest.bootstrap) {
      if (parsed.packageCount < existingManifest.package_count) {
        throw new Error(`IOC feed regressed from ${existingManifest.package_count} to ${parsed.packageCount} packages; use --allow-ioc-regression only after manual verification`);
      }
      if (parsed.versionPairCount < existingManifest.version_pair_count) {
        throw new Error(`IOC feed regressed from ${existingManifest.version_pair_count} to ${parsed.versionPairCount} exact versions; use --allow-ioc-regression only after manual verification`);
      }
    }
    if (previousPackages) {
      const missing = findMissingPairs(previousPackages, parsed.packages);
      if (missing.length) {
        throw new Error(`IOC feed removed previously known exact indicators (${missing.join(', ')}${missing.length >= 20 ? ', …' : ''}); use --allow-ioc-regression only after manual verification`);
      }
    }
  }

  const canonical = serializePackageCsv(parsed.packages);
  const canonicalBuffer = Buffer.from(canonical, 'utf8');
  const [hashIocSha256, persistenceIocSha256] = await Promise.all([
    hashFile(hashIocFile, 'sha256'),
    hashFile(persistenceIocFile, 'sha256'),
  ]);
  const manifest = {
    schema_version: 1,
    source_url: sourceUrl,
    resolved_url: response.url,
    fetched_at: nowIso(),
    raw_sha256: hashBuffer(response.buffer, 'sha256'),
    canonical_sha256: hashBuffer(canonicalBuffer, 'sha256'),
    auxiliary_sha256: {
      hashes_json: hashIocSha256,
      persistence_json: persistenceIocSha256,
    },
    package_count: parsed.packageCount,
    version_pair_count: parsed.versionPairCount,
    response_etag: response.headers.etag || null,
    response_last_modified: response.headers['last-modified'] || null,
    source_blob_sha: computeGitBlobSha(response.buffer),
    source_line_endings: detectLineEndings(response.buffer),
    canonical_line_endings: 'LF',
    bootstrap: false,
    generated_by: `${SCANNER_ID}/${VERSION}`,
    acquisition_note: 'Downloaded over HTTPS from the allowlisted Wiz Research raw GitHub source, parsed as CSV, validated for schema/minimum counts/exact-pair regression, canonicalized to LF, and written atomically.',
  };

  await atomicWriteFile(iocFile, canonical, { mode: 0o644 });
  await atomicWriteFile(manifestFile, `${stableStringify(manifest, 2)}\n`, { mode: 0o644 });
  return { ...manifest, file: iocFile, manifest_file: manifestFile };
}

async function prepareIocsForScan(options = {}) {
  const events = [];
  let iocs;
  try {
    iocs = await loadIocs(options);
  } catch (error) {
    events.push({ type: 'load-failed', error: sanitizeError(error) });
  }

  const refreshHours = options.refreshHours ?? DEFAULT_REFRESH_HOURS;
  const shouldUpdate = !options.offline && !options.noAutoUpdate && (
    options.forceUpdate || !iocs || iocs.bootstrap || iocs.futureDated || iocs.ageHours > refreshHours
  );

  if (shouldUpdate) {
    try {
      const update = await updateIocs(options);
      events.push({ type: 'updated', update });
      iocs = await loadIocs(options);
    } catch (error) {
      events.push({ type: 'update-failed', error: sanitizeError(error) });
    }
  }

  if (!iocs) {
    const loadError = events.find((event) => event.type === 'load-failed')?.error?.message;
    const updateError = events.find((event) => event.type === 'update-failed')?.error?.message;
    throw new Error(`no validated IOC feed is available${loadError ? `; load failed: ${loadError}` : ''}${updateError ? `; update failed: ${updateError}` : ''}`);
  }

  const maxAgeHours = options.maxIocAgeHours ?? DEFAULT_MAX_IOC_AGE_HOURS;
  const fresh = !iocs.bootstrap && !iocs.futureDated && iocs.ageHours <= maxAgeHours;
  return { iocs, events, fresh, maxAgeHours };
}

module.exports = {
  computeGitBlobSha,
  detectLineEndings,
  fetchText,
  findMissingPairs,
  loadIocs,
  loadManifest,
  prepareIocsForScan,
  updateIocs,
  validateHashIocs,
  validatePersistenceIocs,
  validateSourceManifest,
};
