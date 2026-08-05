'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const zlib = require('zlib');
const {
  MAX_ARCHIVE_BYTES,
  MAX_ARCHIVE_ENTRIES,
  MAX_ARCHIVE_OUTPUT_BYTES,
} = require('../constants');
const { inspectBufferArtifact, isCandidateName } = require('./content');

function readTarString(buffer, start, length) {
  const slice = buffer.subarray(start, Math.min(buffer.length, start + length));
  const nul = slice.indexOf(0);
  return slice.subarray(0, nul === -1 ? slice.length : nul).toString('utf8').trim();
}

function parseTarNumber(buffer, start, length) {
  const slice = buffer.subarray(start, start + length);
  if (slice.length && (slice[0] & 0x80)) {
    let value = 0n;
    const copy = Buffer.from(slice);
    copy[0] &= 0x7f;
    for (const byte of copy) value = (value << 8n) | BigInt(byte);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('TAR numeric field exceeds safe integer range');
    return Number(value);
  }
  const text = readTarString(buffer, start, length).replace(/\0/g, '').trim();
  if (!text) return 0;
  const value = Number.parseInt(text, 8);
  if (!Number.isFinite(value) || value < 0) throw new Error(`invalid TAR numeric field: ${text}`);
  return value;
}

function tarHeaderChecksums(header) {
  let unsigned = 0;
  let signed = 0;
  for (let index = 0; index < header.length; index += 1) {
    const value = index >= 148 && index < 156 ? 0x20 : header[index];
    unsigned += value;
    signed += value > 127 ? value - 256 : value;
  }
  return { unsigned, signed };
}

function validateTarHeaderChecksum(header) {
  const stored = parseTarNumber(header, 148, 8);
  const checksums = tarHeaderChecksums(header);
  if (stored !== checksums.unsigned && stored !== checksums.signed) {
    throw new Error(`invalid TAR header checksum: expected ${stored}, calculated ${checksums.unsigned}`);
  }
}

function parsePaxPath(data) {
  const text = data.toString('utf8');
  for (const line of text.split('\n')) {
    const equals = line.indexOf('=');
    if (equals === -1) continue;
    const keyStart = line.indexOf(' ');
    const key = line.slice(keyStart + 1, equals);
    if (key === 'path') return line.slice(equals + 1);
  }
  return null;
}

function parseTarEntries(buffer, visitor, options = {}) {
  const maxEntries = options.maxEntries || MAX_ARCHIVE_ENTRIES;
  const maxOutputBytes = options.maxOutputBytes || MAX_ARCHIVE_OUTPUT_BYTES;
  let offset = 0;
  let longName = null;
  let paxPath = null;
  let count = 0;
  let fileBytes = 0;

  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    validateTarHeaderChecksum(header);
    count += 1;
    if (count > maxEntries) throw new Error(`TAR entry limit ${maxEntries} exceeded`);

    const name = readTarString(header, 0, 100);
    const prefix = readTarString(header, 345, 155);
    const size = parseTarNumber(header, 124, 12);
    const type = String.fromCharCode(header[156] || 48);
    const fullName = paxPath || longName || (prefix ? `${prefix}/${name}` : name);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > buffer.length) throw new Error(`truncated TAR entry ${fullName || '(unnamed)'}`);
    const data = buffer.subarray(dataStart, dataEnd);

    if (type === 'L') {
      longName = data.toString('utf8').replace(/\0+$/, '').replace(/\n$/, '');
    } else if (type === 'x') {
      paxPath = parsePaxPath(data);
    } else {
      if (type === '0' || type === '\0' || type === '') {
        fileBytes += size;
        if (fileBytes > maxOutputBytes) throw new Error(`TAR file content exceeds ${maxOutputBytes} bytes`);
        if (!options.filter || options.filter(fullName)) visitor({ name: fullName, data, size });
      }
      longName = null;
      paxPath = null;
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return { entries: count, uncompressed_bytes: fileBytes, skipped_unsupported: 0 };
}

let crc32Table;

function getCrc32Table() {
  if (crc32Table) return crc32Table;
  crc32Table = new Uint32Array(256);
  for (let value = 0; value < 256; value += 1) {
    let crc = value;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    crc32Table[value] = crc >>> 0;
  }
  return crc32Table;
}

function crc32(buffer) {
  const table = getCrc32Table();
  let crc = 0xffffffff;
  for (const byte of buffer) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function findZipEocd(buffer) {
  if (buffer.length < 22) return -1;
  const minimum = Math.max(0, buffer.length - 65_557);
  for (let offset = buffer.length - 22; offset >= minimum; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  return -1;
}

function parseZipEntries(buffer, visitor, options = {}) {
  const eocd = findZipEocd(buffer);
  if (eocd === -1) throw new Error('ZIP end-of-central-directory record not found');
  const disk = buffer.readUInt16LE(eocd + 4);
  const centralDisk = buffer.readUInt16LE(eocd + 6);
  const diskEntries = buffer.readUInt16LE(eocd + 8);
  const entryCount = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  const centralOffset = buffer.readUInt32LE(eocd + 16);
  const commentLength = buffer.readUInt16LE(eocd + 20);
  if (eocd + 22 + commentLength > buffer.length) throw new Error('truncated ZIP end-of-central-directory comment');
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== entryCount) throw new Error('multi-disk ZIP archives are not supported');
  if (entryCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) throw new Error('ZIP64 archives are not supported');
  const maxEntries = options.maxEntries || MAX_ARCHIVE_ENTRIES;
  const maxOutputBytes = options.maxOutputBytes || MAX_ARCHIVE_OUTPUT_BYTES;
  if (entryCount > maxEntries) throw new Error(`ZIP entry limit ${maxEntries} exceeded`);
  const centralEnd = centralOffset + centralSize;
  if (centralEnd > eocd || centralEnd > buffer.length) throw new Error('ZIP central directory exceeds archive bounds');

  let offset = centralOffset;
  let declaredBytes = 0;
  let inspectedBytes = 0;
  let skippedUnsupported = 0;

  for (let index = 0; index < entryCount; index += 1) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== 0x02014b50) {
      throw new Error(`invalid ZIP central directory at entry ${index}`);
    }
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const expectedCrc32 = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    if ([compressedSize, uncompressedSize, localOffset].includes(0xffffffff)) throw new Error('ZIP64 entry is not supported');
    const nextCentral = offset + 46 + nameLength + extraLength + commentLength;
    if (nextCentral > centralEnd || nextCentral > buffer.length) throw new Error(`truncated ZIP central record at entry ${index}`);
    const centralName = buffer.subarray(offset + 46, offset + 46 + nameLength);
    const name = centralName.toString('utf8');
    declaredBytes += uncompressedSize;
    if (declaredBytes > maxOutputBytes) throw new Error(`ZIP declared output exceeds ${maxOutputBytes} bytes`);

    const shouldInspect = !options.filter || options.filter(name);
    if (!shouldInspect) {
      offset = nextCentral;
      continue;
    }
    if (flags & 0x1) {
      skippedUnsupported += 1;
      offset = nextCentral;
      continue;
    }
    if (![0, 8].includes(method)) {
      skippedUnsupported += 1;
      offset = nextCentral;
      continue;
    }
    if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== 0x04034b50) {
      throw new Error(`invalid ZIP local header for ${name}`);
    }
    const localFlags = buffer.readUInt16LE(localOffset + 6);
    const localMethod = buffer.readUInt16LE(localOffset + 8);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const localNameStart = localOffset + 30;
    const localNameEnd = localNameStart + localNameLength;
    if (localNameEnd > buffer.length) throw new Error(`truncated ZIP local filename for ${name}`);
    const localName = buffer.subarray(localNameStart, localNameEnd);
    if (!localName.equals(centralName)) throw new Error(`ZIP local/central filename mismatch for ${name}`);
    if (localMethod !== method || localFlags !== flags) throw new Error(`ZIP local/central method or flag mismatch for ${name}`);
    const dataStart = localNameEnd + localExtraLength;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > buffer.length) throw new Error(`truncated ZIP entry ${name}`);
    const compressed = buffer.subarray(dataStart, dataEnd);

    let data;
    if (method === 0) data = compressed;
    else data = zlib.inflateRawSync(compressed, { maxOutputLength: Math.max(1, Math.min(maxOutputBytes, uncompressedSize || maxOutputBytes)) });
    if (uncompressedSize !== 0 && data.length !== uncompressedSize) {
      throw new Error(`ZIP entry size mismatch for ${name}: expected ${uncompressedSize}, got ${data.length}`);
    }
    const actualCrc32 = crc32(data);
    if (actualCrc32 !== expectedCrc32) {
      throw new Error(`ZIP CRC-32 mismatch for ${name}: expected ${expectedCrc32.toString(16).padStart(8, '0')}, got ${actualCrc32.toString(16).padStart(8, '0')}`);
    }
    inspectedBytes += data.length;
    if (inspectedBytes > maxOutputBytes) throw new Error(`ZIP inspected output exceeds ${maxOutputBytes} bytes`);
    visitor({ name, data, size: data.length });
    offset = nextCentral;
  }
  if (offset !== centralEnd) throw new Error('ZIP central directory size does not match parsed entries');
  return { entries: entryCount, uncompressed_bytes: declaredBytes, skipped_unsupported: skippedUnsupported };
}

function shouldInspectArchiveEntry(name) {
  const normalized = String(name).replace(/\\/g, '/');
  const base = path.posix.basename(normalized).toLowerCase();
  return base === 'package.json'
    || isCandidateName(base)
    || normalized.toLowerCase().endsWith('/.claude/settings.json')
    || normalized.toLowerCase().endsWith('/.vscode/tasks.json');
}

function inspectArchiveEntries(context, archivePath, parser, buffer, options = {}) {
  let inspected = 0;
  const stats = parser(buffer, ({ name, data }) => {
    inspectBufferArtifact(context, data, { path: archivePath, entry: name }, path.posix.basename(name), { inspectText: true });
    inspected += 1;
  }, {
    filter: shouldInspectArchiveEntry,
    maxEntries: options.maxEntries || MAX_ARCHIVE_ENTRIES,
    maxOutputBytes: options.maxOutputBytes || MAX_ARCHIVE_OUTPUT_BYTES,
  });
  context.statistics.archive_entries_inspected += inspected;
  if (stats.skipped_unsupported) {
    context.addCoverageGap(
      'archive-entry-format',
      `${archivePath}: ${stats.skipped_unsupported} relevant encrypted or unsupported-compression ZIP entr${stats.skipped_unsupported === 1 ? 'y was' : 'ies were'} not inspected`,
      options.required ? 'error' : 'warning',
    );
  }
  return stats;
}

function isZipBuffer(buffer) {
  return buffer.length >= 4 && [0x04034b50, 0x06054b50, 0x08074b50].includes(buffer.readUInt32LE(0));
}

function isGzipBuffer(buffer) {
  return buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b;
}

function isTarBuffer(buffer) {
  return buffer.length >= 512 && buffer.subarray(257, 262).toString('ascii') === 'ustar';
}

async function scanArchive(context, file, options = {}) {
  try {
    const stat = await fsp.stat(file);
    if (stat.size > (options.maxBytes || MAX_ARCHIVE_BYTES)) {
      throw new Error(`archive size ${stat.size} exceeds limit ${options.maxBytes || MAX_ARCHIVE_BYTES}`);
    }
    const buffer = await fsp.readFile(file);
    const lower = file.toLowerCase();
    let recognized = true;
    if (lower.endsWith('.zip') || isZipBuffer(buffer)) {
      inspectArchiveEntries(context, file, parseZipEntries, buffer, options);
    } else if (lower.endsWith('.tgz') || lower.endsWith('.tar.gz') || isGzipBuffer(buffer)) {
      const output = zlib.gunzipSync(buffer, { maxOutputLength: options.maxOutputBytes || MAX_ARCHIVE_OUTPUT_BYTES });
      inspectArchiveEntries(context, file, parseTarEntries, output, options);
    } else if (lower.endsWith('.tar') || isTarBuffer(buffer)) {
      inspectArchiveEntries(context, file, parseTarEntries, buffer, options);
    } else {
      recognized = false;
    }
    if (recognized) context.statistics.archives_inspected += 1;
    return recognized;
  } catch (error) {
    context.addOperationalError('archive-inspection', file, error, { incomplete: Boolean(options.required) });
    return false;
  }
}

module.exports = {
  crc32,
  findZipEocd,
  isGzipBuffer,
  isTarBuffer,
  isZipBuffer,
  parseTarEntries,
  validateTarHeaderChecksum,
  parseZipEntries,
  scanArchive,
  shouldInspectArchiveEntry,
};
