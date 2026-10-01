/**
 * zonediff.js — two zones compared record set by record set (Zone File › Compare): a semantic
 * diff, never a text diff.
 *
 * - Records are matched by owner and type; each record set (RRset) is compared as a set of
 *   values, so the order of the lines, duplicates and the file format do not matter.
 * - Names are compared relative to each zone's own origin ('@', 'www', '*.apps'; a name outside
 *   the zone stays absolute with its root dot), also inside RDATA (a CNAME target, an MX
 *   exchange …), so two copies of a zone under different names can be compared; lib/zoneparse.js
 *   has already made them lowercase, without the trailing dot, with canonical escapes.
 * - Values are compared by lib/zoneparse.js rdataKey (IPv6 in its compressed form, MX / SRV
 *   fields instead of spacing, CAA tags in lowercase), with three refinements: an SOA by every
 *   field (rdataKey looks at its serial only), a CAA issuer domain in lowercase, a TXT set by the
 *   joined text of its character-strings when `joinTxt` is on. A Route 53 alias compares by its
 *   target, a value the parser could not decode by its text.
 * - Options ({@link DIFF_DEFAULTS}): `ignoreTtl` (a TTL difference does not change a set),
 *   `joinTxt` (TXT strings split differently are equal), `ignoreSoa` (the SOA serial and timers do
 *   not count; its name server and mailbox still do), `ignoreApexNs` (the NS set at the apex is
 *   left out: two providers each name their own). What an option hid stays visible as a note on
 *   the row ({@link DIFF_NOTES}).
 * - The first zone is the starting point: `added` is only in the second one, `removed` only in
 *   the first, `changed` in both with different values, TTL, Cloudflare proxy flag or Route 53
 *   routing ({@link DIFF_REASONS}).
 *
 * Pure, synchronous and DOM-free; nothing is sent or stored. Runs in browsers and Node 22.
 */

import { rdataKey } from './zoneparse.js';
import { toCsv, toJson } from './export.js';

/** Row statuses, in display order. */
export const DIFF_STATUSES = Object.freeze(['added', 'removed', 'changed', 'same', 'ignored']);

/** Why a set present in both zones changed. */
export const DIFF_REASONS = Object.freeze(['values', 'ttl', 'proxied', 'routing', 'soa-names', 'soa-serial', 'soa-timers']);

/** What an option kept from counting (the row says so) — or why a set was left out. */
export const DIFF_NOTES = Object.freeze(['ttl-ignored', 'txt-split', 'soa-ignored', 'apex-ns']);

/** Comparison options and their defaults. */
export const DIFF_DEFAULTS = Object.freeze({ ignoreTtl: false, joinTxt: true, ignoreSoa: false, ignoreApexNs: false });

/** Option names, in display order. */
export const DIFF_OPTIONS = Object.freeze(Object.keys(DIFF_DEFAULTS));

/** Table filters: `diff` = added, removed and changed; `all` = every row. */
export const DIFF_FILTERS = Object.freeze(['diff', 'added', 'removed', 'changed', 'same', 'ignored', 'all']);

/** Record types first in a name's rows; the rest follow alphabetically. */
const TYPE_ORDER = ['SOA', 'NS', 'A', 'AAAA', 'CNAME', 'MX', 'TXT'];
/** CAA tags whose value starts with an issuer domain name (case-insensitive, RFC 8659 §4.2). */
const CAA_ISSUER_TAGS = new Set(['issue', 'issuewild', 'issuemail', 'issuevmc']);

/* ------------------------------------------------------------------------ */
/* Names                                                                    */
/* ------------------------------------------------------------------------ */

/** Is the character at `i` escaped by an odd run of backslashes before it? */
function escapedAt(s, i) {
  let n = 0;
  for (let k = i - 1; k >= 0 && s[k] === '\\'; k -= 1) n += 1;
  return n % 2 === 1;
}

/**
 * A name in canonical presentation: lowercase, no trailing (unescaped) dot, a decimal escape of
 * a plain letter, digit, hyphen, underscore or asterisk written as the character ('\042' and '*'
 * are the same wire label). '' for the root.
 * @param {string} name
 * @returns {string}
 */
export function canonicalName(name) {
  let s = String(name ?? '').trim().toLowerCase();
  s = s.replace(/\\(\d{3})/g, (m, d, i, all) => {
    if (escapedAt(all, i)) return m;
    const c = Number(d);
    const ch = c < 256 ? String.fromCharCode(c) : '';
    return /^[a-z0-9_*-]$/.test(ch) ? ch : m;
  });
  if (s.endsWith('.') && !escapedAt(s, s.length - 1)) s = s.slice(0, -1);
  return s === '.' ? '' : s;
}

/**
 * A name relative to a zone origin: '@' for the apex, the labels below it ('www', '*.apps'), or
 * the absolute name with its root dot when it lies outside (a suffix that is only an escaped dot
 * is not a label boundary).
 * @param {string} name
 * @param {string|null} origin
 * @returns {string}
 */
export function relativeName(name, origin) {
  const n = canonicalName(name);
  const o = origin ? canonicalName(origin) : '';
  if (!o) return n ? `${n}.` : '.';
  if (n === o) return '@';
  const cut = n.length - o.length - 1;
  if (cut > 0 && n.endsWith(`.${o}`) && !escapedAt(n, cut)) return n.slice(0, cut);
  return n ? `${n}.` : '.';
}

/* ------------------------------------------------------------------------ */
/* Values                                                                   */
/* ------------------------------------------------------------------------ */

/** RDATA name fields per type (dnswire data shape): a string for the name types, else field names. */
const NAME_FIELDS = Object.freeze({
  MX: ['exchange'], SRV: ['target'], SVCB: ['target'], HTTPS: ['target'], NAPTR: ['replacement'],
  RP: ['mbox', 'txt'], AFSDB: ['hostname'], KX: ['exchanger'], SOA: ['mname', 'rname']
});
const NAME_TYPES = new Set(['NS', 'CNAME', 'PTR', 'DNAME']);

/** The data with every name inside it relative to the zone (the comparison form). */
function relativeData(type, data, origin) {
  if (NAME_TYPES.has(type) && typeof data === 'string') return relativeName(data, origin);
  const fields = NAME_FIELDS[type];
  if (!fields || !data || typeof data !== 'object') return data;
  const out = { ...data };
  for (const f of fields) if (typeof out[f] === 'string') out[f] = relativeName(out[f], origin);
  return out;
}

/** A CAA value with an issuer domain in lowercase and the parameters trimmed. */
function caaValue(tag, value) {
  const v = String(value ?? '');
  if (!CAA_ISSUER_TAGS.has(tag)) return v;
  const [domain, ...params] = v.split(';');
  return [domain.trim().toLowerCase(), ...params.map((p) => p.trim()).filter(Boolean)].join('; ');
}

/** Whitespace-collapsed RDATA text (a value the parser kept as text). */
const textKey = (s) => String(s ?? '').trim().replace(/\s+/g, ' ');

/**
 * The comparison key of one record's value.
 * @param {object} r ZoneRecord
 * @param {{ origin?: string|null, joinTxt?: boolean, ignoreSoa?: boolean }} [opts]
 * @returns {string}
 */
export function valueKey(r, { origin = null, joinTxt = DIFF_DEFAULTS.joinTxt, ignoreSoa = DIFF_DEFAULTS.ignoreSoa } = {}) {
  const type = String(r.type || '').toUpperCase();
  if (r.alias) return `alias ${relativeName(r.alias.target, origin)}`;
  if (r.data === null || r.data === undefined) return `text ${textKey(r.text)}`;
  const data = relativeData(type, r.data, origin);
  switch (type) {
    case 'TXT':
    case 'SPF':
      return joinTxt ? `txt ${JSON.stringify((Array.isArray(data) ? data : [data]).join(''))}` : rdataKey(type, data);
    case 'SOA': {
      const names = `${data.mname} ${data.rname}`;
      return ignoreSoa ? names : `${names} ${data.serial} ${data.refresh} ${data.retry} ${data.expire} ${data.minimum}`;
    }
    case 'CAA':
      return `${data.flags} ${String(data.tag).toLowerCase()} ${caaValue(String(data.tag).toLowerCase(), data.value)}`;
    default:
      return rdataKey(type, data);
  }
}

/** What the table shows of one value: the record's own text, an alias as "ALIAS target.". */
export function displayValue(r) {
  if (r.alias) return `ALIAS ${r.alias.target}.`;
  return String(r.text ?? '');
}

/* ------------------------------------------------------------------------ */
/* Record sets                                                              */
/* ------------------------------------------------------------------------ */

/** A routing variant as one comparable string (Route 53 / cli53 / octoDNS routing). */
function routingKey(r) {
  if (!r.routing) return '';
  const x = r.routing;
  return JSON.stringify([x.policy, x.id ?? null, x.weight ?? null, x.region ?? null, x.failover ?? null,
    x.geo ? [x.geo.continentCode ?? null, x.geo.countryCode ?? null, x.geo.subdivisionCode ?? null] : null]);
}

/**
 * The record sets of a zone keyed `<relative name>|<TYPE>`, in file order, duplicates folded.
 * @param {object} zone
 * @param {{ joinTxt?: boolean, ignoreSoa?: boolean }} [opts]
 * @returns {Map<string, { key: string, rel: string, name: string, type: string, values: Map<string, { text: string, stricts: string[], records: object[] }>,
 *   ttls: number[], proxied: boolean[], routing: string[], soa: object|null, records: object[] }>}
 */
export function recordSets(zone, { joinTxt = DIFF_DEFAULTS.joinTxt, ignoreSoa = DIFF_DEFAULTS.ignoreSoa } = {}) {
  const origin = zone && zone.origin ? zone.origin : null;
  const sets = new Map();
  for (const r of (zone && Array.isArray(zone.records) ? zone.records : [])) {
    const type = String(r.type || '').toUpperCase();
    const rel = relativeName(r.name, origin);
    const key = `${rel}|${type}`;
    let set = sets.get(key);
    if (!set) {
      set = { key, rel, name: canonicalName(r.name), type, values: new Map(), ttls: [], proxied: [], routing: [], soa: null, records: [] };
      sets.set(key, set);
    }
    set.records.push(r);
    const vk = valueKey(r, { origin, joinTxt, ignoreSoa });
    const strict = joinTxt && (type === 'TXT' || type === 'SPF') ? valueKey(r, { origin, joinTxt: false }) : vk;
    const entry = set.values.get(vk);
    if (entry) {
      entry.records.push(r);
      if (!entry.stricts.includes(strict)) entry.stricts.push(strict);
    } else {
      set.values.set(vk, { text: displayValue(r), stricts: [strict], records: [r] });
    }
    if (Number.isFinite(r.ttl) && !set.ttls.includes(r.ttl)) set.ttls.push(r.ttl);
    if (r.proxied === true || r.proxied === false) {
      if (!set.proxied.includes(r.proxied)) set.proxied.push(r.proxied);
    }
    const rk = routingKey(r);
    if (rk && !set.routing.includes(rk)) set.routing.push(rk);
    if (type === 'SOA' && !set.soa && r.data && typeof r.data === 'object') set.soa = relativeData('SOA', r.data, origin);
  }
  for (const set of sets.values()) {
    set.ttls.sort((x, y) => x - y);
    set.proxied.sort();
    set.routing.sort();
  }
  return sets;
}

/* ------------------------------------------------------------------------ */
/* The diff                                                                 */
/* ------------------------------------------------------------------------ */

const sameList = (x, y) => x.length === y.length && x.every((v, i) => v === y[i]);

/** One side of a row: its values (file order), TTL(s), proxy flag. */
function side(set) {
  if (!set) return null;
  const proxied = !set.proxied.length ? null : set.proxied.length > 1 ? 'mixed' : set.proxied[0];
  return {
    values: [...set.values.values()].map((v) => v.text),
    ttl: set.ttls.length ? set.ttls[0] : null,
    ttls: [...set.ttls],
    proxied,
    count: set.values.size
  };
}

/** The SOA fields that differ: names (mname / rname), serial, timers. */
function soaReasons(a, b) {
  const out = [];
  if (a.mname !== b.mname || a.rname !== b.rname) out.push('soa-names');
  if (a.serial !== b.serial) out.push('soa-serial');
  if (['refresh', 'retry', 'expire', 'minimum'].some((k) => a[k] !== b[k])) out.push('soa-timers');
  return out;
}

/** A row compared on both sides: its status, reasons and notes. */
function compareSets(sa, sb, opts) {
  const reasons = [];
  const notes = [];
  const ka = [...sa.values.keys()];
  const kb = new Set(sb.values.keys());
  const valuesSame = ka.length === kb.size && ka.every((k) => kb.has(k));
  const ttlDiffers = sa.ttls.length && sb.ttls.length && !sameList(sa.ttls, sb.ttls);
  const soaQuiet = sa.type === 'SOA' && opts.ignoreSoa;
  if (sa.type === 'SOA' && sa.soa && sb.soa) {
    const soa = soaReasons(sa.soa, sb.soa);
    if (opts.ignoreSoa) {
      if (soa.includes('soa-names')) reasons.push('soa-names');
      // The serial, the timers and the record's own TTL: hidden, and said so.
      if (soa.some((x) => x !== 'soa-names') || ttlDiffers) notes.push('soa-ignored');
    } else {
      reasons.push(...soa);
    }
  } else if (!valuesSame) {
    reasons.push('values');
  } else if (opts.joinTxt && (sa.type === 'TXT' || sa.type === 'SPF')) {
    const strictA = [...new Set([...sa.values.values()].flatMap((v) => v.stricts))].sort();
    const strictB = [...new Set([...sb.values.values()].flatMap((v) => v.stricts))].sort();
    if (!sameList(strictA, strictB)) notes.push('txt-split');
  }
  if (ttlDiffers && !soaQuiet) {
    if (opts.ignoreTtl) notes.push('ttl-ignored');
    else reasons.push('ttl');
  }
  if (sa.proxied.length && sb.proxied.length && !sameList(sa.proxied, sb.proxied)) reasons.push('proxied');
  if ((sa.routing.length || sb.routing.length) && !sameList(sa.routing, sb.routing)) reasons.push('routing');
  return { status: reasons.length ? 'changed' : 'same', reasons, notes };
}

/** Row order: the apex first, then names by their labels from the right, then TYPE_ORDER. */
function rowOrder(x, y) {
  const lx = x.rel === '@' ? [] : x.rel.replace(/\.$/, '').split('.').reverse();
  const ly = y.rel === '@' ? [] : y.rel.replace(/\.$/, '').split('.').reverse();
  const outside = (r) => (r.rel.endsWith('.') ? 1 : 0);
  if (outside(x) !== outside(y)) return outside(x) - outside(y);
  for (let i = 0; i < Math.min(lx.length, ly.length); i += 1) {
    if (lx[i] !== ly[i]) return lx[i] < ly[i] ? -1 : 1;
  }
  if (lx.length !== ly.length) return lx.length - ly.length;
  const tx = TYPE_ORDER.indexOf(x.type);
  const ty = TYPE_ORDER.indexOf(y.type);
  if (tx !== ty) return (tx < 0 ? 99 : tx) - (ty < 0 ? 99 : ty) || (x.type < y.type ? -1 : 1);
  return x.type < y.type ? -1 : x.type > y.type ? 1 : 0;
}

/**
 * Compare two parsed zones (neither with a fatal issue).
 * @param {object} a the first zone (the starting point)
 * @param {object} b the second zone
 * @param {{ ignoreTtl?: boolean, joinTxt?: boolean, ignoreSoa?: boolean, ignoreApexNs?: boolean }} [options]
 * @returns {{ a: object, b: object, relative: boolean, options: object, rows: DiffRow[],
 *   counts: { added: number, removed: number, changed: number, same: number, ignored: number, total: number } }}
 *   `relative`: the zones have different origins (names compared relative to each);
 *   DiffRow = { key, rel, name, type, status, reasons: string[], notes: string[], a: Side|null, b: Side|null,
 *   added: string[], removed: string[] } — `added` / `removed`: the values only in b / only in a;
 *   Side = { values: string[], ttl: number|null (the lowest), ttls: number[], proxied: true|false|'mixed'|null, count }
 */
export function diffZones(a, b, options = {}) {
  if (!a || !b || a.fatal || b.fatal) throw new TypeError('zonediff: two zones without a fatal issue are needed');
  const opts = { ...DIFF_DEFAULTS };
  for (const k of DIFF_OPTIONS) if (options && typeof options[k] === 'boolean') opts[k] = options[k];
  const setsA = recordSets(a, opts);
  const setsB = recordSets(b, opts);
  const rows = [];
  const keys = [...setsA.keys(), ...[...setsB.keys()].filter((k) => !setsA.has(k))];
  for (const key of keys) {
    const sa = setsA.get(key) || null;
    const sb = setsB.get(key) || null;
    const any = sa || sb;
    const row = {
      key, rel: any.rel, name: any.name, type: any.type, status: 'same', reasons: [], notes: [],
      a: side(sa), b: side(sb), added: [], removed: []
    };
    if (opts.ignoreApexNs && any.type === 'NS' && any.rel === '@') {
      row.status = 'ignored';
      row.notes.push('apex-ns');
    } else if (!sa) {
      row.status = 'added';
      row.added = [...sb.values.values()].map((v) => v.text);
    } else if (!sb) {
      row.status = 'removed';
      row.removed = [...sa.values.values()].map((v) => v.text);
    } else {
      Object.assign(row, compareSets(sa, sb, opts));
      row.added = [...sb.values.entries()].filter(([k]) => !sa.values.has(k)).map(([, v]) => v.text);
      row.removed = [...sa.values.entries()].filter(([k]) => !sb.values.has(k)).map(([, v]) => v.text);
    }
    rows.push(row);
  }
  rows.sort(rowOrder);
  const counts = { added: 0, removed: 0, changed: 0, same: 0, ignored: 0, total: rows.length };
  for (const r of rows) counts[r.status] += 1;
  const about = (z, sets) => ({
    origin: z.origin || null, format: z.format || null, dialect: z.dialect || null,
    records: (z.records || []).filter((r) => r.duplicateOf === undefined).length, rrsets: sets.size
  });
  return {
    a: about(a, setsA), b: about(b, setsB),
    relative: !!(a.origin && b.origin && canonicalName(a.origin) !== canonicalName(b.origin)),
    options: opts, rows, counts
  };
}

/**
 * Does a row pass a table filter ({@link DIFF_FILTERS})?
 * @param {{ status: string }} row
 * @param {string} filter
 * @returns {boolean}
 */
export function diffFilter(row, filter = 'diff') {
  if (filter === 'all') return true;
  if (filter === 'diff') return row.status === 'added' || row.status === 'removed' || row.status === 'changed';
  return row.status === filter;
}

/** Is there any difference at all? */
export const hasDifferences = (result) => !!result && (result.counts.added + result.counts.removed + result.counts.changed) > 0;

/* ------------------------------------------------------------------------ */
/* Exports                                                                  */
/* ------------------------------------------------------------------------ */

/** Columns of the CSV export, in order. */
export const DIFF_CSV_COLUMNS = Object.freeze(['status', 'name', 'type', 'ttl_a', 'ttl_b', 'values_a', 'values_b', 'added', 'removed', 'reasons', 'notes']);

/** One row as the exports write it; `redact` maps a value list (origin addresses hidden). */
function exportRow(r, redact) {
  return {
    status: r.status,
    // Absolute: a spreadsheet takes '@' for a formula (lib/export.js quotes it), and a reader of
    // the file needs no zone name to read it.
    name: r.name,
    relative: r.rel,
    type: r.type,
    ttl_a: r.a ? r.a.ttl : null,
    ttl_b: r.b ? r.b.ttl : null,
    values_a: r.a ? redact(r.a.values) : [],
    values_b: r.b ? redact(r.b.values) : [],
    added: redact(r.added),
    removed: redact(r.removed),
    proxied_a: r.a ? r.a.proxied : null,
    proxied_b: r.b ? r.b.proxied : null,
    reasons: [...r.reasons],
    notes: [...r.notes]
  };
}

/**
 * The rows as CSV (lib/export.js toCsv: formula-safe, BOM): one line per record set, values
 * separated by ' | '.
 * @param {object[]} rows DiffRow
 * @param {{ redact?: (values: string[]) => string[] }} [opts]
 * @returns {string}
 */
export function diffCsv(rows, { redact = (v) => [...v] } = {}) {
  const join = (list) => list.join(' | ');
  const out = (rows || []).map((r) => exportRow(r, redact));
  return toCsv(out, DIFF_CSV_COLUMNS.map((key) => ({
    key,
    get: (x) => (Array.isArray(x[key]) ? (key === 'reasons' || key === 'notes' ? x[key].join(' ') : join(x[key])) : x[key])
  })));
}

/**
 * The comparison as JSON: both zones, the options, the counts and the rows given.
 * @param {object} result {@link diffZones}
 * @param {object[]} [rows] default: every row
 * @param {{ redact?: (values: string[]) => string[] }} [opts]
 * @returns {string}
 */
export function diffJson(result, rows = result.rows, { redact = (v) => [...v] } = {}) {
  return toJson({
    a: result.a, b: result.b, relative: result.relative, options: result.options, counts: result.counts,
    rows: (rows || []).map((r) => exportRow(r, redact))
  });
}

/**
 * What Copy summary says (lib/summary.js zoneSummary with `compare`): both zones, the counts,
 * the options that are on, and the first differences by name and type — never a value.
 * @param {object} result {@link diffZones}
 * @param {{ max?: number, formatA?: string, formatB?: string }} [opts] `formatA` / `formatB`: the
 *   format labels the view shows
 * @returns {{ a: { origin, format }, b: { origin, format }, relative: boolean, counts: object, options: string[],
 *   differences: Array<{ status: string, name: string, type: string, reasons: string[] }>, more: number }}
 */
export function diffSummaryFacts(result, { max = 5, formatA = null, formatB = null } = {}) {
  const diffs = result.rows.filter((r) => diffFilter(r, 'diff'));
  return {
    a: { origin: result.a.origin, format: formatA || result.a.format },
    b: { origin: result.b.origin, format: formatB || result.b.format },
    relative: result.relative,
    counts: { ...result.counts },
    options: DIFF_OPTIONS.filter((k) => result.options[k]),
    differences: diffs.slice(0, max).map((r) => ({ status: r.status, name: r.rel, type: r.type, reasons: [...r.reasons] })),
    more: Math.max(0, diffs.length - max)
  };
}
