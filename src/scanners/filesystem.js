'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { MAX_ARCHIVE_BYTES, MAX_JSON_BYTES, MAX_TEXT_INSPECTION_BYTES } = require('../constants');
const { hashBuffer, isSubpath, safeRealpath } = require('../util');
const { isGzipBuffer, isTarBuffer, isZipBuffer, scanArchive } = require('./archives');
const { inspectFileArtifact, isCandidateName } = require('./content');
const { isLockfileName, parseGenericNameVersionText, scanLockfile } = require('./lockfiles');
const { inspectMetadataObject, recordPackageOccurrence, scanPackageJson } = require('./packages');

const DEEP_SCRIPT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs']);
const ARCHIVE_EXTENSIONS = ['.tgz', '.tar.gz', '.tar', '.zip'];

function isCacheKind(kind) {
  return /cache|store/.test(String(kind || ''));
}

function isGlobalKind(kind) {
  return /global/.test(String(kind || ''));
}

function shouldSkipDirectory(directory, root, context) {
  const relative = path.relative(root.path, directory).replace(/\\/g, '/');
  const lower = relative.toLowerCase();
  const base = path.basename(directory).toLowerCase();
  if (!relative) return false;
  if (lower === '.git/objects' || lower.startsWith('.git/objects/')) return true;
  if (lower === '.git/lfs/objects' || lower.startsWith('.git/lfs/objects/')) return true;
  if (lower === '.hg/store' || lower.startsWith('.hg/store/')) return true;
  if (lower === '.svn/pristine' || lower.startsWith('.svn/pristine/')) return true;
  if (['system volume information', '$recycle.bin'].includes(base)) return true;
  if (path.resolve(root.path) === path.parse(root.path).root && ['/proc', '/sys', '/dev', '/run'].includes(directory.replace(/\\/g, '/'))) return true;
  if (context.options.exclude?.some((excluded) => isSubpath(directory, excluded))) return true;
  return false;
}

function extractPackageFromRegistryUrl(input) {
  let value = String(input || '');
  try { value = decodeURIComponent(value); } catch { /* retain original */ }
  const match = value.match(/registry\.npmjs\.org\/(?:@?[^/]+\/)?/i);
  if (!match) return null;
  const tarball = value.match(/registry\.npmjs\.org\/(@[^/]+\/[^/]+|[^/]+)\/-\/([^/?#]+)\.tgz(?:[?#]|$)/i);
  if (!tarball) return null;
  const name = tarball[1];
  const base = name.slice(name.lastIndexOf('/') + 1);
  const prefix = `${base}-`;
  if (!tarball[2].startsWith(prefix)) return null;
  return { name, version: tarball[2].slice(prefix.length) };
}

function digestsFromIntegrity(integrity) {
  const digests = [];
  const seen = new Set();
  for (const token of String(integrity || '').trim().split(/\s+/)) {
    const match = token.match(/^sha(256|512)-([A-Za-z0-9+/=]+)$/);
    if (!match) continue;
    try {
      const digest = { algorithm: `sha${match[1]}`, hex: Buffer.from(match[2], 'base64').toString('hex') };
      const expectedLength = digest.algorithm === 'sha256' ? 64 : 128;
      const key = `${digest.algorithm}:${digest.hex}`;
      if (digest.hex.length === expectedLength && !seen.has(key)) {
        seen.add(key);
        digests.push(digest);
      }
    } catch {
      // Ignore malformed SRI tokens while retaining any other valid tokens.
    }
  }
  return digests;
}

function digestHexFromIntegrity(integrity) {
  return digestsFromIntegrity(integrity)[0] || null;
}

function npmContentPath(indexFile, integrity) {
  const parsed = digestsFromIntegrity(integrity);
  const digest = parsed.find((item) => item.algorithm === 'sha512') || parsed[0];
  if (!digest) return null;
  const normalized = indexFile.replace(/\\/g, '/');
  const marker = '/_cacache/index-v5/';
  const index = normalized.indexOf(marker);
  if (index === -1) return null;
  const cacacheRoot = normalized.slice(0, index + '/_cacache'.length);
  return path.join(cacacheRoot, 'content-v2', digest.algorithm, digest.hex.slice(0, 2), digest.hex.slice(2, 4), digest.hex.slice(4));
}

function addIntegrityHashFinding(context, digest, file, key) {
  const match = context.iocs.hashes.find((entry) => entry.algorithm === digest.algorithm && entry.hash === digest.hex);
  if (!match) return;
  context.findings.add({
    rule_id: match.rule_id,
    title: 'npm cache index contains the exact integrity digest of a campaign artifact',
    description: match.description,
    category: 'malicious-archive',
    severity: match.severity || 'critical',
    confidence: 'exact',
    source_kind: 'npm-cache-index',
    location: { path: file },
    evidence: `${digest.algorithm.toUpperCase()} ${digest.hex} for ${key}`,
    remediation_key: 'payload',
    references: [match.source],
  });
  context.statistics.hash_matches += 1;
}

async function scanNpmCacheIndex(context, file) {
  try {
    const stat = await fsp.stat(file);
    if (stat.size > MAX_TEXT_INSPECTION_BYTES) throw new Error(`npm cache index shard exceeds ${MAX_TEXT_INSPECTION_BYTES} bytes`);
    const lines = (await fsp.readFile(file, 'utf8')).split(/\r?\n/);
    let malformedEntries = 0;
    for (const line of lines) {
      if (!line.trim()) continue;
      const tab = line.indexOf('\t');
      const jsonText = tab >= 0 ? line.slice(tab + 1) : line;
      let entry;
      try { entry = JSON.parse(jsonText); } catch { malformedEntries += 1; continue; }
      context.statistics.npm_cache_index_entries += 1;
      const key = entry.key || entry.metadata?.url || '';
      const occurrence = extractPackageFromRegistryUrl(key);
      if (occurrence) {
        recordPackageOccurrence(context, {
          ...occurrence,
          path: file,
          sourceKind: 'cache',
          evidence: 'npm cacache index tarball key',
          metadata: { cache_key: key, integrity: entry.integrity },
        });
      }
      if (entry.metadata && typeof entry.metadata === 'object') {
        inspectMetadataObject(context, entry.metadata, { path: file }, { sourceKind: 'cache', evidence: 'npm cache metadata' });
      }
      for (const digest of digestsFromIntegrity(entry.integrity)) addIntegrityHashFinding(context, digest, file, key);

      if (occurrence && context.iocs.packages.get(occurrence.name)?.has(occurrence.version)) {
        const content = npmContentPath(file, entry.integrity);
        if (content) {
          try {
            await fsp.access(content, fs.constants.R_OK);
            const realContent = await safeRealpath(content);
            if (!context.visitedFiles.has(realContent)) {
              context.visitedFiles.add(realContent);
              await inspectFileArtifact(context, realContent, { computeSha512: true, maxBytes: MAX_ARCHIVE_BYTES });
              await scanArchive(context, realContent, { required: false });
            }
          } catch {
            // The cache index can outlive its content file. The index match itself is retained.
          }
        }
      }
    }
    if (malformedEntries) {
      context.addCoverageGap('npm-cache-index-parse', `${file}: ${malformedEntries} non-empty cache index entr${malformedEntries === 1 ? 'y was' : 'ies were'} malformed`, 'warning');
    }
  } catch (error) {
    context.addOperationalError('npm-cache-index', file, error, { incomplete: true });
  }
}

async function scanCacheMetadataJson(context, file) {
  try {
    const stat = await fsp.stat(file);
    if (stat.size > MAX_JSON_BYTES) return;
    const value = JSON.parse(await fsp.readFile(file, 'utf8'));
    inspectMetadataObject(context, value, { path: file }, { sourceKind: 'cache', evidence: 'package-manager cache metadata' });
    context.statistics.cache_metadata_files += 1;
  } catch {
    // Cache trees contain unrelated and malformed JSON. Individual failures do
    // not make the scan incomplete because package.json receives strict parsing.
  }
}

function recordCacheNameOccurrences(context, file) {
  const normalized = file.replace(/\\/g, '/');
  const base = path.basename(file);
  for (const occurrence of parseGenericNameVersionText(`${base} ${normalized}`)) {
    recordPackageOccurrence(context, {
      ...occurrence,
      path: file,
      sourceKind: 'cache',
      evidence: 'package/version encoded in cache path',
    });
  }

  const lowerBase = base.toLowerCase();
  if (lowerBase.endsWith('.zip') && lowerBase.includes('-npm-')) {
    for (const [packageName, versions] of context.iocs.packages) {
      const prefix = `${packageName.replace('/', '-')}-npm-`.toLowerCase();
      if (!lowerBase.startsWith(prefix)) continue;
      for (const version of versions) {
        if (lowerBase.startsWith(`${prefix}${version.toLowerCase()}-`) || lowerBase === `${prefix}${version.toLowerCase()}.zip`) {
          recordPackageOccurrence(context, {
            name: packageName,
            version,
            path: file,
            sourceKind: 'cache',
            evidence: 'Yarn cache archive filename',
          });
        }
      }
    }
  }
}

function isNpmIndexPath(file) {
  return file.replace(/\\/g, '/').includes('/_cacache/index-v5/');
}

function isAutostartFile(file) {
  const normalized = file.replace(/\\/g, '/').toLowerCase();
  return normalized.endsWith('/.claude/settings.json') || normalized.endsWith('/.vscode/tasks.json');
}

function isArchiveFile(file) {
  const lower = file.toLowerCase();
  return ARCHIVE_EXTENSIONS.some((extension) => lower.endsWith(extension));
}

async function detectArchiveMagic(file, size) {
  if (!Number.isFinite(size) || size < 2) return null;
  const length = Math.min(512, size);
  const buffer = Buffer.alloc(length);
  const handle = await fsp.open(file, 'r');
  try {
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    const head = buffer.subarray(0, bytesRead);
    if (isZipBuffer(head)) return 'zip';
    if (isGzipBuffer(head)) return 'gzip';
    if (isTarBuffer(head)) return 'tar';
    return null;
  } finally {
    await handle.close();
  }
}

async function processFile(context, file, root) {
  let real;
  let stat;
  try {
    real = await safeRealpath(file);
    if (context.visitedFiles.has(real)) return;
    context.visitedFiles.add(real);
    stat = await fsp.stat(real);
    if (!stat.isFile()) return;
    context.statistics.files_examined += 1;
    context.statistics.bytes_examined += stat.size;
    if (context.statistics.files_examined > context.options.maxFiles) {
      throw Object.assign(new Error(`maximum file count ${context.options.maxFiles} reached`), { code: 'MAX_FILES' });
    }
  } catch (error) {
    if (error.code === 'MAX_FILES') throw error;
    context.addOperationalError('file-stat', file, error, { incomplete: root.required && context.options.strictPermissions });
    return;
  }

  const name = path.basename(real);
  const lowerName = name.toLowerCase();
  const extension = path.extname(lowerName);
  const cacheRoot = isCacheKind(root.kind);

  if (lowerName === 'package.json') await scanPackageJson(context, real, root.kind);
  if (isLockfileName(lowerName)) await scanLockfile(context, real);
  if (isNpmIndexPath(real)) await scanNpmCacheIndex(context, real);
  if (cacheRoot && lowerName.endsWith('.json') && lowerName !== 'package.json' && !isNpmIndexPath(real)) {
    await scanCacheMetadataJson(context, real);
  }
  if (cacheRoot) recordCacheNameOccurrences(context, real);

  const candidate = isCandidateName(lowerName);
  const autostart = isAutostartFile(real);
  const extensionArchive = isArchiveFile(real);
  let magicArchiveType = null;
  if (cacheRoot && !extensionArchive) {
    try {
      magicArchiveType = await detectArchiveMagic(real, stat.size);
    } catch (error) {
      context.addOperationalError('archive-magic', real, error, { incomplete: false });
    }
  }
  const archive = extensionArchive || Boolean(magicArchiveType);
  if (candidate || autostart || context.options.hashAll || (context.options.deep && DEEP_SCRIPT_EXTENSIONS.has(extension))) {
    await inspectFileArtifact(context, real, {
      deep: context.options.deep || context.options.hashAll,
      hashAll: context.options.hashAll,
      inspectText: candidate || autostart,
      required: root.required,
    });
  }
  if (archive && (cacheRoot || context.options.deep || /(?:keyv|cacheable|flat-cache|file-entry-cache)/i.test(lowerName))) {
    const tarLike = magicArchiveType === 'gzip' || magicArchiveType === 'tar' || lowerName.endsWith('.tgz') || lowerName.endsWith('.tar.gz') || lowerName.endsWith('.tar');
    await inspectFileArtifact(context, real, { computeSha512: tarLike, maxBytes: MAX_ARCHIVE_BYTES, required: root.required });
    await scanArchive(context, real, { required: Boolean(root.required || cacheRoot) });
  }
}

async function resolveDirectoryEntry(entryPath, entry, root, context) {
  if (!entry.isSymbolicLink()) return { path: entryPath, isDirectory: entry.isDirectory(), isFile: entry.isFile() };
  if (context.options.followSymlinks === false) return null;
  try {
    const real = await fsp.realpath(entryPath);
    if (!context.options.followExternalSymlinks && !isSubpath(real, root.path)) return null;
    const stat = await fsp.stat(real);
    return { path: real, isDirectory: stat.isDirectory(), isFile: stat.isFile() };
  } catch (error) {
    context.addOperationalError('symlink', entryPath, error, { incomplete: false });
    return null;
  }
}

async function scanRoot(context, root) {
  context.statistics.roots_requested += 1;
  const stack = [root.path];
  let rootOpened = false;

  while (stack.length) {
    const directory = stack.pop();
    if (shouldSkipDirectory(directory, root, context)) {
      context.statistics.skipped_paths += 1;
      continue;
    }
    let realDirectory;
    try {
      realDirectory = await safeRealpath(directory);
      if (context.visitedDirectories.has(realDirectory)) continue;
      context.visitedDirectories.add(realDirectory);
      const stat = await fsp.stat(realDirectory);
      if (!stat.isDirectory()) {
        await processFile(context, realDirectory, root);
        rootOpened = true;
        continue;
      }
      const handle = await fsp.opendir(realDirectory);
      rootOpened = true;
      context.statistics.directories_examined += 1;
      for await (const entry of handle) {
        const entryPath = path.join(realDirectory, entry.name);
        const resolved = await resolveDirectoryEntry(entryPath, entry, root, context);
        if (!resolved) continue;
        if (resolved.isDirectory) stack.push(resolved.path);
        else if (resolved.isFile) await processFile(context, resolved.path, root);
      }
    } catch (error) {
      if (error.code === 'MAX_FILES') {
        context.addCoverageGap('file-limit', error.message, 'error');
        return false;
      }
      const incomplete = !rootOpened || (root.required && context.options.strictPermissions);
      context.addOperationalError('directory-walk', directory, error, { incomplete });
    }
  }

  if (rootOpened) context.statistics.roots_scanned += 1;
  return rootOpened;
}

async function scanRoots(context, roots) {
  for (const root of roots) {
    if (context.options.verbose) process.stderr.write(`Scanning ${root.kind}: ${root.path}\n`);
    await scanRoot(context, root);
  }
}

module.exports = {
  digestHexFromIntegrity,
  digestsFromIntegrity,
  extractPackageFromRegistryUrl,
  isArchiveFile,
  isAutostartFile,
  detectArchiveMagic,
  isCacheKind,
  isGlobalKind,
  npmContentPath,
  processFile,
  recordCacheNameOccurrences,
  scanNpmCacheIndex,
  scanRoot,
  scanRoots,
  shouldSkipDirectory,
};
