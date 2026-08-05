'use strict';

const PACKAGE_NAME_RE = /^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*\/)?[A-Za-z0-9][A-Za-z0-9._~-]*$/;
const EXACT_VERSION_RE = /^[vV]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"') {
      quoted = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field.endsWith('\r') ? field.slice(0, -1) : field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += char;
    }
  }

  if (quoted) throw new Error('unterminated quoted CSV field');
  if (field.length || row.length) {
    row.push(field.endsWith('\r') ? field.slice(0, -1) : field);
    rows.push(row);
  }
  return rows;
}

function normalizeHeader(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function splitVersions(value) {
  const source = String(value || '').trim();
  if (!source) return [];

  const legacyMatches = [...source.matchAll(/==\s*([^|,;\s]+)/g)].map((match) => match[1]);
  const values = legacyMatches.length
    ? legacyMatches
    : source.split(/\s*(?:\|\||,|;)\s*/g);

  return values
    .map((version) => version.trim().replace(/^={1,2}\s*/, '').replace(/^['"]|['"]$/g, ''))
    .filter(Boolean);
}

function parsePackageCsv(text, options = {}) {
  const rows = parseCsv(String(text).replace(/^\uFEFF/, ''));
  if (rows.length < 2) throw new Error('IOC CSV contains no package rows');

  const headers = rows[0].map(normalizeHeader);
  const packageIndex = headers.findIndex((header) => ['package', 'packagename', 'name'].includes(header));
  const versionsIndex = headers.findIndex((header) => [
    'maliciousversions',
    'affectedversions',
    'versions',
    'affectedversion',
  ].includes(header));

  if (packageIndex === -1 || versionsIndex === -1) {
    throw new Error(`unsupported IOC CSV headers: ${rows[0].join(', ')}`);
  }

  const packages = new Map();
  const errors = [];
  const duplicates = [];

  for (let rowNumber = 2; rowNumber <= rows.length; rowNumber += 1) {
    const row = rows[rowNumber - 1];
    if (!row || row.every((field) => !String(field).trim())) continue;
    const packageName = String(row[packageIndex] || '').trim();
    if (!PACKAGE_NAME_RE.test(packageName)) {
      errors.push(`row ${rowNumber}: invalid npm package name ${JSON.stringify(packageName)}`);
      continue;
    }

    const versions = splitVersions(row[versionsIndex]);
    if (!versions.length) {
      errors.push(`row ${rowNumber}: no exact versions for ${packageName}`);
      continue;
    }

    const set = packages.get(packageName) || new Set();
    for (const version of versions) {
      if (!EXACT_VERSION_RE.test(version) || /[<>=~^*|\s]/.test(version)) {
        errors.push(`row ${rowNumber}: invalid exact version ${JSON.stringify(version)} for ${packageName}`);
        continue;
      }
      if (set.has(version)) duplicates.push(`${packageName}@${version}`);
      set.add(version);
    }
    if (set.size) packages.set(packageName, set);
  }

  const packageCount = packages.size;
  const versionPairCount = [...packages.values()].reduce((sum, versions) => sum + versions.size, 0);
  const minPackages = options.minPackages ?? 0;
  const minPairs = options.minPairs ?? 0;

  if (errors.length) {
    const preview = errors.slice(0, 10).join('; ');
    throw new Error(`IOC CSV validation failed (${errors.length} error${errors.length === 1 ? '' : 's'}): ${preview}`);
  }
  if (packageCount < minPackages) {
    throw new Error(`IOC feed regression: ${packageCount} packages is below required minimum ${minPackages}`);
  }
  if (versionPairCount < minPairs) {
    throw new Error(`IOC feed regression: ${versionPairCount} package-version pairs is below required minimum ${minPairs}`);
  }

  return {
    packages,
    packageCount,
    versionPairCount,
    duplicates,
    headers: rows[0],
  };
}

function csvEscape(value) {
  const text = String(value ?? '');
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function serializePackageCsv(packages) {
  const lines = ['Package,Malicious Versions'];
  for (const packageName of [...packages.keys()].sort()) {
    const versions = [...packages.get(packageName)].sort(compareVersionText);
    lines.push(`${csvEscape(packageName)},${csvEscape(versions.join(', '))}`);
  }
  return `${lines.join('\n')}\n`;
}

function compareVersionText(a, b) {
  return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
}

module.exports = {
  EXACT_VERSION_RE,
  PACKAGE_NAME_RE,
  parseCsv,
  parsePackageCsv,
  serializePackageCsv,
  splitVersions,
};
