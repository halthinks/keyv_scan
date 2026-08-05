'use strict';

function parseVersion(input) {
  const match = String(input || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split('.') : [],
    raw: String(input).trim(),
  };
}

function compareIdentifiers(a, b) {
  const aNumeric = /^\d+$/.test(a);
  const bNumeric = /^\d+$/.test(b);
  if (aNumeric && bNumeric) return Number(a) - Number(b);
  if (aNumeric) return -1;
  if (bNumeric) return 1;
  return a.localeCompare(b);
}

function compare(aInput, bInput) {
  const a = typeof aInput === 'string' ? parseVersion(aInput) : aInput;
  const b = typeof bInput === 'string' ? parseVersion(bInput) : bInput;
  if (!a || !b) return null;
  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] !== b[key]) return a[key] - b[key];
  }
  if (!a.prerelease.length && !b.prerelease.length) return 0;
  if (!a.prerelease.length) return 1;
  if (!b.prerelease.length) return -1;
  const length = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    if (a.prerelease[index] === undefined) return -1;
    if (b.prerelease[index] === undefined) return 1;
    const result = compareIdentifiers(a.prerelease[index], b.prerelease[index]);
    if (result) return result;
  }
  return 0;
}

function normalizePartial(input) {
  const parts = String(input).trim().replace(/^v/, '').split('.');
  if (!parts.length || parts.length > 3) return null;
  const normalized = [];
  let wildcardAt = -1;
  for (let index = 0; index < 3; index += 1) {
    const part = parts[index];
    if (part === undefined || /^(?:x|X|\*)$/.test(part)) {
      if (wildcardAt === -1) wildcardAt = index;
      normalized.push(0);
    } else if (/^\d+$/.test(part)) {
      normalized.push(Number(part));
    } else {
      return null;
    }
  }
  return { major: normalized[0], minor: normalized[1], patch: normalized[2], wildcardAt };
}

function partialBounds(input) {
  const text = String(input || '').trim();
  const partial = normalizePartial(text);
  if (!partial) return null;
  const lower = parseVersion(`${partial.major}.${partial.minor}.${partial.patch}`);
  const componentCount = text.replace(/^v/, '').split('.').length;
  const wildcardAt = partial.wildcardAt !== -1 ? partial.wildcardAt : (componentCount < 3 ? componentCount : -1);
  let upper = null;
  if (wildcardAt === 0) upper = null;
  else if (wildcardAt === 1) upper = parseVersion(`${partial.major + 1}.0.0`);
  else if (wildcardAt === 2) upper = parseVersion(`${partial.major}.${partial.minor + 1}.0`);
  return { lower, upper, partial, componentCount, wildcardAt };
}

function cmp(version, operator, target) {
  const result = compare(version, target);
  if (result === null) return false;
  switch (operator) {
    case '>': return result > 0;
    case '>=': return result >= 0;
    case '<': return result < 0;
    case '<=': return result <= 0;
    case '=':
    case '==':
    case '': return result === 0;
    default: return false;
  }
}

function satisfiesComparator(version, token) {
  const trimmed = token.trim();
  if (!trimmed || trimmed === '*') return true;

  const caret = trimmed.match(/^\^\s*(.+)$/);
  if (caret) {
    const source = caret[1].trim();
    const bounds = partialBounds(source);
    if (bounds?.wildcardAt === 0) return true;
    const base = bounds?.lower || parseVersion(expandVersion(source));
    if (!base) return false;
    let upper;
    if (base.major > 0) upper = { ...base, major: base.major + 1, minor: 0, patch: 0, prerelease: [] };
    else if (base.minor > 0) upper = { ...base, minor: base.minor + 1, patch: 0, prerelease: [] };
    else if (base.patch > 0) upper = { ...base, patch: base.patch + 1, prerelease: [] };
    else if (bounds?.wildcardAt === 1) upper = { ...base, major: 1, minor: 0, patch: 0, prerelease: [] };
    else if (bounds?.wildcardAt === 2) upper = { ...base, minor: 1, patch: 0, prerelease: [] };
    else upper = { ...base, patch: 1, prerelease: [] };
    return cmp(version, '>=', base) && cmp(version, '<', upper);
  }

  const tilde = trimmed.match(/^~\s*(.+)$/);
  if (tilde) {
    const source = tilde[1].trim();
    const bounds = partialBounds(source);
    if (bounds?.wildcardAt === 0) return true;
    const base = bounds?.lower || parseVersion(expandVersion(source));
    if (!base) return false;
    const upper = bounds?.wildcardAt === 1 || source.split('.').length === 1
      ? { ...base, major: base.major + 1, minor: 0, patch: 0, prerelease: [] }
      : { ...base, minor: base.minor + 1, patch: 0, prerelease: [] };
    return cmp(version, '>=', base) && cmp(version, '<', upper);
  }

  const comparison = trimmed.match(/^(<=|>=|<|>|==|=)?\s*(.+)$/);
  if (!comparison) return false;
  const operator = comparison[1] || '';
  const targetText = comparison[2];
  const bounds = partialBounds(targetText);
  if (bounds && bounds.wildcardAt !== -1) {
    const { lower, upper } = bounds;
    if (!upper) return ['', '=', '==', '>=', '<='].includes(operator);
    if (operator === '>') return cmp(version, '>=', upper);
    if (operator === '>=') return cmp(version, '>=', lower);
    if (operator === '<') return cmp(version, '<', lower);
    if (operator === '<=') return cmp(version, '<', upper);
    return cmp(version, '>=', lower) && cmp(version, '<', upper);
  }

  const target = parseVersion(targetText);
  return target ? cmp(version, operator, target) : false;
}

function expandVersion(input) {
  const value = String(input).trim();
  const parts = value.split('.');
  if (parts.length === 1 && /^\d+$/.test(parts[0])) return `${parts[0]}.0.0`;
  if (parts.length === 2 && parts.every((part) => /^\d+$/.test(part))) return `${parts[0]}.${parts[1]}.0`;
  return value;
}

function satisfies(versionInput, rangeInput) {
  const version = parseVersion(versionInput);
  if (!version) return false;
  let range = String(rangeInput || '').trim();
  if (!range || range === '*' || range.toLowerCase() === 'latest') return true;
  range = range.replace(/(<=|>=|<|>|==|=)\s+/g, '$1').replace(/\s*,\s*/g, ' ');
  if (range.startsWith('npm:')) {
    const at = range.lastIndexOf('@');
    range = at > 4 ? range.slice(at + 1) : '*';
  }

  for (const alternative of range.split(/\s*\|\|\s*/)) {
    const hyphen = alternative.match(/^\s*(\S+)\s+-\s+(\S+)\s*$/);
    if (hyphen) {
      const lowBounds = partialBounds(hyphen[1]);
      const highBounds = partialBounds(hyphen[2]);
      const low = lowBounds?.lower || parseVersion(expandVersion(hyphen[1]));
      const high = parseVersion(expandVersion(hyphen[2]));
      const highSatisfied = highBounds?.upper
        ? cmp(version, '<', highBounds.upper)
        : high && cmp(version, '<=', high);
      if (low && highSatisfied && cmp(version, '>=', low)) return true;
      continue;
    }

    const tokens = alternative.trim().split(/\s+/).filter(Boolean);
    if (tokens.length && tokens.every((token) => satisfiesComparator(version, token))) return true;
  }
  return false;
}

function classifySpec(spec, affectedVersions) {
  const raw = String(spec || '').trim();
  if (!raw) return { status: 'unknown', matches: [] };
  if (/^(?:file:|link:|workspace:|git\+|https?:|github:|gitlab:|bitbucket:)/i.test(raw)) {
    return { status: 'nonregistry', matches: [] };
  }

  const exact = parseVersion(raw.replace(/^=/, ''));
  if (exact && !/[~^<>*|\s]/.test(raw)) {
    const matches = affectedVersions.filter((version) => compare(exact, version) === 0);
    return { status: matches.length ? 'exact-affected' : 'exact-clean', matches };
  }

  if (/^[A-Za-z][A-Za-z0-9._-]*$/.test(raw)) return { status: 'tag-or-unknown', matches: [] };
  const matches = affectedVersions.filter((version) => satisfies(version, raw));
  if (matches.length) return { status: 'range-includes-affected', matches };
  return { status: 'range-excludes-affected', matches: [] };
}

module.exports = {
  classifySpec,
  compare,
  parseVersion,
  partialBounds,
  satisfies,
};
