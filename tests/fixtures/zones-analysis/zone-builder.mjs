/**
 * Test-only builder of parsed `Zone` objects (the lib/zoneparse.js shape, zone spec
 * §6.1.2) for the analysis tests — they never import the parser.
 *
 *   zone([
 *     ['@', 'A', '192.0.2.10', { proxied: true }],
 *     ['www', 'CNAME', '@'],
 *     ['@', 'MX', '10 mail'],
 *     ['_dmarc', 'TXT', 'v=DMARC1; p=none']
 *   ], { origin: 'example.com', dialect: 'cloudflare' })
 *
 * Owner and RDATA names follow master-file rules: `@` is the origin, a name ending in
 * `.` is absolute, anything else is relative to the origin. `data` is built in the
 * dnswire decoder's shape; `text` is the dnswire presentation (via encode → decode,
 * or a plain rendering when the value cannot be encoded, e.g. a 266-byte string).
 * Extra fields (`proxied`, `ttl`, `ttlAuto`, `alias`, `routing`, `flattenCname`,
 * `intendedTargets`, `invalid`, `occludedBy`, `duplicateOf`, …) are copied onto the
 * record. Documentation addresses only (192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24, 2001:db8::/32) and example.* names.
 */

import { encodeMessage, decodeMessage } from '../../../assets/js/lib/dnswire.js';

export function fqdn(name, origin) {
  const n = String(name).trim().toLowerCase();
  if (n === '@') return origin;
  if (n === '.') return '.';
  if (n.endsWith('.')) return n.slice(0, -1);
  return origin ? `${n}.${origin}` : n;
}

function quoted(v) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(v))) out.push(m[1].replace(/\\(.)/g, '$1'));
  return out.length ? out : [v];
}

/** RDATA value → dnswire-shaped data. */
export function rdata(type, value, origin) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'object' && !Array.isArray(value)) return value;
  const s = Array.isArray(value) ? value : String(value).trim();
  const f = typeof s === 'string' ? s.split(/\s+/) : [];
  switch (type) {
    case 'A':
    case 'AAAA':
      return s;
    case 'NS':
    case 'CNAME':
    case 'PTR':
    case 'DNAME':
      return fqdn(s, origin);
    case 'MX':
      return { preference: Number(f[0]), exchange: fqdn(f[1], origin) };
    case 'SRV':
      return { priority: Number(f[0]), weight: Number(f[1]), port: Number(f[2]), target: fqdn(f[3], origin) };
    case 'TXT':
    case 'SPF':
      return Array.isArray(s) ? s.map(String) : (s.startsWith('"') ? quoted(s) : [s]);
    case 'CAA': {
      const m = /^(\d+)\s+(\S+)\s+"?(.*?)"?$/.exec(s);
      return { flags: Number(m[1]), tag: m[2].toLowerCase(), value: m[3] };
    }
    case 'DS':
      return { keyTag: Number(f[0]), algorithm: Number(f[1]), digestType: Number(f[2]), digest: f.slice(3).join('').toLowerCase() };
    default:
      return s;
  }
}

function present(name, type, data) {
  try {
    const rr = decodeMessage(encodeMessage({ answers: [{ name: name === '' ? '.' : name, type, ttl: 300, data }] })).answers[0];
    return { data: rr.data, text: rr.text };
  } catch {
    const text = Array.isArray(data) ? data.map((x) => `"${x}"`).join(' ') : typeof data === 'string' ? data : JSON.stringify(data);
    return { data, text };
  }
}

function targetsOf(type, data) {
  if (data === null || data === undefined) return [];
  const t = (v) => (v === '.' ? '' : String(v));
  if (type === 'NS' || type === 'CNAME' || type === 'PTR' || type === 'DNAME') return typeof data === 'string' ? [t(data)] : [];
  if (type === 'MX') return [t(data.exchange)];
  if (type === 'SRV' || type === 'SVCB' || type === 'HTTPS') return [t(data.target)];
  if (type === 'SOA') return [t(data.mname), t(data.rname)];
  return [];
}

/**
 * Build one record.
 * @returns {object} ZoneRecord
 */
export function record(id, [owner, type, value, extra = {}], origin) {
  const name = fqdn(owner, origin);
  let data = null;
  let text = '';
  if (!extra.invalid && !extra.alias) {
    const raw = rdata(type, value, origin);
    ({ data, text } = present(name, type, raw));
  } else if (extra.alias) {
    text = `${extra.alias.target}.`;
  } else {
    text = String(value ?? '');
  }
  const rec = { id, name, type, ttl: 300, data, text, targets: targetsOf(type, data), proxied: null, line: id + 1, source: 0, ...extra };
  if (extra.alias) rec.ttl = extra.ttl ?? null;
  return rec;
}

/**
 * Build a Zone.
 * @param {Array} rows `[owner, type, value, extra?]`
 * @param {{ origin?: string, format?: string, dialect?: string|null, partial?: boolean, fatal?: object|null }} [opts]
 * @returns {object} Zone
 */
export function zone(rows, { origin = 'example.com', format = 'bind', dialect = 'generic', partial = false, fatal = null } = {}) {
  const records = rows.map((row, i) => record(i, row, origin));
  return {
    format, dialect, markers: [], origin, originSource: 'user', originConfidence: 'high',
    records, warnings: [], fatal, partial, sources: [{ name: 'test.zone', size: 0, format, dialect }],
    stats: { records: records.length }
  };
}

/** Shorthand: a Cloudflare BIND export zone. */
export const cfZone = (rows, opts = {}) => zone(rows, { dialect: 'cloudflare', ...opts });

/** Cloudflare-proxied / DNS-only record extras. */
export const P = Object.freeze({ proxied: true, ttlAuto: true });
export const D = Object.freeze({ proxied: false, ttlAuto: true });
