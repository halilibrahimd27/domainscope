/**
 * fixes.js — DNS change requests and fix-as-code: what a change needs, said for the DNS admin
 * (instructions in English and Turkish) and written as code for BIND, a Route 53 change batch,
 * the Cloudflare API (curl), octoDNS and Terraform (cloudflare_record / aws_route53_record).
 *
 * - A change request ({@link ChangeRequest}) is a list of record-set changes in one zone. Each
 *   {@link RRsetChange} says what the set of one name and type must be afterwards (`mode`):
 *   exactly these values (`is`), at least these values (`has`, e.g. an ACME token next to older
 *   ones) or nothing (`none`). A TXT set can be scoped to one kind of record (`family`: the
 *   `v=spf1` record, the `v=DMARC1` record …), so the site verifications next to an SPF record
 *   are never touched. What the name holds now (`before`, `others`) is known only after a live
 *   read ({@link readCurrent}, on a click) or from a zone file; a format that replaces whole
 *   record sets (Route 53, aws_route53_record) then writes the full set, otherwise it says what
 *   it cannot know.
 * - {@link CHANGE_TEMPLATES}: ACME DNS-01 TXT, a CNAME delegation of `_acme-challenge`, Microsoft
 *   365 and Google Workspace mail, CAA for chosen CAs (RFC 8657 accounturi / validationmethods),
 *   an SPF include added or removed, a DMARC policy step-up, TTLs lowered before a migration, one
 *   plain A / AAAA / CNAME / TXT / MX set, and the lock-down of a parked domain. {@link buildChange}
 *   turns a template's form into a change request.
 * - {@link validateChange}: the change's records after the change (and what a live read found at
 *   the same names) linted as a zone with lib/zonelint.js — CNAME conflicts, SPF / DMARC syntax,
 *   CAA tags and flags, private addresses — plus the SPF lookup budget and the RFC 8659 / 8657
 *   grammar of every CAA issue value (lib/health.js).
 * - {@link renderFix} writes one format; {@link changeInstructions} the admin's text in either
 *   language, whatever the UI language.
 * - {@link healthFix} / {@link lintFix}: the fix of a Domain Health check or a Zone File lint
 *   finding — a change request where the fix is a record (a missing DMARC record → p=none to
 *   start, a missing CAA → the CAs seen in Certificate Transparency), advice where it is not
 *   (SPF over 10 lookups → flatten; never an automatic record).
 *
 * Nothing here sends anything: {@link readCurrent} and {@link countSpfLookups} use an injected
 * DohClient. Secrets never appear in the output: the Cloudflare script reads the API token and
 * the zone ID from shell variables it names. DOM-free, runs in browsers and Node 22.
 */

import { normalizeHostname, registrableDomain, isSubdomainOf } from './domain.js';
import { normalizeIP, ipVersion } from './netinfo.js';
import { parseSpf, parseDmarc, parseCaaIssueValue, spfLookupCount, CAA_ISSUERS, SPF_LOOKUP_LIMIT } from './health.js';
import { quoteArg } from './cmdline.js';
import { parseZone, rdataKey, txtJoinedKey, presentCharString } from './zoneparse.js';
import { lintZone } from './zonelint.js';
// The Route 53 string escapes, the YAML quoting, the octoDNS TXT escapes and key order (lib/zonetext.js, the zone converter's too).
import { route53String, yamlString as yamlStr, octodnsTxt, octodnsTxtValue, octodnsTxtRefused, naturalCompare } from './zonetext.js';

/* ------------------------------------------------------------------------ */
/* Vocabulary                                                               */
/* ------------------------------------------------------------------------ */

/** Record types a change request can hold. */
export const FIX_TYPES = Object.freeze(['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'CAA']);
/** What a record set must be after the change. */
export const FIX_MODES = Object.freeze(['is', 'has', 'none']);
/** Output formats of {@link renderFix}, in the order the UI offers them. */
export const FIX_FORMATS = Object.freeze(['bind', 'route53', 'cloudflare', 'octodns', 'terraform-cloudflare', 'terraform-route53']);
/** A file extension per format (downloads). */
export const FIX_FORMAT_EXT = Object.freeze({ bind: 'zone', route53: 'json', cloudflare: 'sh', octodns: 'yaml', 'terraform-cloudflare': 'tf', 'terraform-route53': 'tf' });
/** Languages {@link changeInstructions} writes. */
export const FIX_LANGS = Object.freeze(['en', 'tr']);
/** Bounds of one change request. */
export const FIX_LIMITS = Object.freeze({ rrsets: 20, values: 40, valueBytes: 4000, ttlMin: 1, ttlMax: 2147483647 });
/** The TTL a template uses when the form leaves it empty. */
export const DEFAULT_TTL = 3600;
/** Shell variables the Cloudflare script reads (never filled in by this app). */
export const CLOUDFLARE_VARS = Object.freeze({ token: 'CLOUDFLARE_API_TOKEN', zone: 'CLOUDFLARE_ZONE_ID' });
/** Terraform variables the two Terraform formats declare. */
export const TERRAFORM_VARS = Object.freeze({ cloudflare: 'cloudflare_zone_id', route53: 'route53_zone_id' });
/** ACME validation methods a CAA value may name in the form (RFC 8657; the IANA registry). */
export const CAA_FORM_METHODS = Object.freeze(['dns-01', 'http-01', 'tls-alpn-01']);
/** The `v=` tags of TXT record kinds a set can be scoped to, with their display names. */
export const TXT_FAMILIES = Object.freeze({ spf1: 'SPF', dmarc1: 'DMARC', tlsrptv1: 'TLS-RPT', stsv1: 'MTA-STS', dkim1: 'DKIM', bimi1: 'BIMI' });

/**
 * CAs the CAA template offers: lib/health.js CAA_ISSUERS without the distrusted ones, each with
 * the identifier it asks for in CAA (the first of its domains). ZeroSSL issues from Sectigo
 * intermediates and asks for `sectigo.com`.
 * @type {ReadonlyArray<{ id: string, name: string, caa: string }>}
 */
export const FIX_CAS = Object.freeze([
  ...CAA_ISSUERS.filter((ca) => !ca.distrusted).map((ca) => Object.freeze({ id: ca.id, name: ca.name, caa: ca.domains[0] })),
  Object.freeze({ id: 'zerossl', name: 'ZeroSSL', caa: 'sectigo.com' })
]);

/* ------------------------------------------------------------------------ */
/* Names and values                                                         */
/* ------------------------------------------------------------------------ */

const utf8 = new TextEncoder();
const canon = (s) => {
  const v = String(s ?? '').trim().toLowerCase();
  return v === '.' ? '' : v.replace(/\.$/, '');
};
const arr = (v) => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
const uniqBy = (list, key) => {
  const seen = new Set();
  return list.filter((x) => {
    const k = key(x);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
};

/**
 * A zone name as the form holds it: a host name without `*.` or `_` labels at the start, never
 * an IP address. null when it is none.
 * @param {string} input
 * @returns {string|null}
 */
export function zoneName(input) {
  const raw = String(input ?? '').trim();
  if (!raw || normalizeIP(raw.replace(/^\[|\]$/g, ''))) return null;
  const name = normalizeHostname(raw);
  if (!name || !name.includes('.') || name.split('.').some((l) => l.startsWith('_'))) return null;
  return name;
}

/**
 * The name relative to its zone as BIND and the instructions write it: '@' for the apex.
 * @param {string} name absolute
 * @param {string} zone
 * @returns {string}
 */
export function relativeName(name, zone) {
  const n = canon(name);
  const z = canon(zone);
  if (!z || n === z) return '@';
  return n.endsWith(`.${z}`) ? n.slice(0, -z.length - 1) : `${n}.`;
}

/**
 * A name typed into a form, in a zone: absolute when it ends with the zone, '@' / empty for the
 * apex, else relative (`www`, `_acme-challenge.www`, `selector1._domainkey`, `*.dev`) when it has
 * no dot, starts with `_` or `*`, or has a service label. Any other dotted name outside the zone
 * is an error, never silently appended to it.
 * @param {string} input
 * @param {string} zone
 * @param {{ wildcard?: boolean }} [opts] allow a `*.` label at the start
 * @returns {{ name: string|null, error: 'invalid'|'outside'|null }}
 */
export function absoluteName(input, zone, { wildcard = true } = {}) {
  const z = canon(zone);
  let raw = String(input ?? '').trim().toLowerCase();
  if (raw === '@' || raw === '') return { name: z || null, error: z ? null : 'invalid' };
  const dotted = raw.endsWith('.');
  raw = raw.replace(/\.$/, '');
  let name = raw;
  if (!(raw === z || raw.endsWith(`.${z}`))) {
    // A dotted name is relative only with a service label (`_acme-challenge.www`, `s1._domainkey`): no TLD has one.
    if (dotted || (raw.includes('.') && !/^[_*]/.test(raw) && !raw.includes('._'))) return { name: null, error: 'outside' };
    name = `${raw}.${z}`;
  }
  const star = name.startsWith('*.');
  if (star && !wildcard) return { name: null, error: 'invalid' };
  const host = normalizeHostname(star ? name.slice(2) : name, { allowSingleLabel: true });
  if (!host || host.includes('*') || !(host === z || isSubdomainOf(host, z))) return { name: null, error: 'invalid' };
  return { name: star ? `*.${host}` : host, error: null };
}

/** An owner name with the root dot: 'www.example.com.' ('.' for the root). */
const fqdn = (name) => (canon(name) ? `${canon(name)}.` : '.');

/**
 * TXT text as character-strings of at most 255 bytes each, never splitting a UTF-8 sequence.
 * @param {string} text
 * @returns {string[]}
 */
export function txtChunks(text) {
  const s = String(text ?? '');
  const out = [];
  let cur = '';
  let bytes = 0;
  for (const ch of s) {
    const n = utf8.encode(ch).length;
    if (bytes + n > 255) {
      out.push(cur);
      cur = '';
      bytes = 0;
    }
    cur += ch;
    bytes += n;
  }
  out.push(cur);
  return out;
}

/** The joined text of TXT data (character-strings, or one string). */
export const txtText = (data) => arr(data).map((x) => String(x ?? '')).join('');

/**
 * Canonical data of one value (lib/dnswire.js RR.data shape), or null when it is not one:
 * A / AAAA an address of that family, CNAME a host name, MX `{ preference, exchange }` ('' for a
 * null MX), TXT character-strings of ≤ 255 bytes, CAA `{ flags, tag, value }`.
 * @param {string} type
 * @param {any} data
 * @returns {any|null}
 */
export function normalizeValue(type, data) {
  switch (type) {
    case 'A':
    case 'AAAA': {
      const ip = normalizeIP(String(data ?? ''));
      return ip && ipVersion(ip) === (type === 'A' ? 4 : 6) ? ip : null;
    }
    case 'CNAME': {
      const host = normalizeHostname(canon(data), { allowSingleLabel: false });
      return host && !host.includes('*') ? host : null;
    }
    case 'MX': {
      if (!data || typeof data !== 'object') return null;
      const pref = Number(data.preference);
      if (!Number.isInteger(pref) || pref < 0 || pref > 65535) return null;
      const ex = canon(data.exchange);
      if (!ex) return { preference: pref, exchange: '' };
      const host = normalizeHostname(ex);
      return host && !host.includes('*') ? { preference: pref, exchange: host } : null;
    }
    case 'TXT': {
      const text = txtText(data);
      return utf8.encode(text).length <= FIX_LIMITS.valueBytes ? txtChunks(text) : null;
    }
    case 'CAA': {
      if (!data || typeof data !== 'object') return null;
      const flags = Number(data.flags ?? 0);
      const tag = String(data.tag ?? '').trim().toLowerCase();
      if (!Number.isInteger(flags) || flags < 0 || flags > 255 || !/^[a-z0-9]{1,15}$/.test(tag)) return null;
      return { flags, tag, value: String(data.value ?? '') };
    }
    default:
      return null;
  }
}

/**
 * The comparison key of one value: TXT by its joined text (a provider may split long strings
 * differently), every other type by lib/zoneparse.js rdataKey — the key live answers get too.
 * @param {string} type
 * @param {any} data
 * @returns {string}
 */
export function valueKey(type, data) {
  return type === 'TXT' ? `txt:${txtJoinedKey('TXT', arr(data))}` : `${type}:${rdataKey(type, data)}`;
}

/**
 * The presentation text of one value, as BIND writes it: names absolute with the root dot,
 * TXT and CAA values quoted (lib/zoneparse.js presentCharString).
 * @param {string} type
 * @param {any} data
 * @returns {string}
 */
export function valueText(type, data) {
  switch (type) {
    case 'CNAME':
      return fqdn(data);
    case 'MX':
      return `${data.preference} ${fqdn(data.exchange)}`;
    case 'TXT':
      return arr(data).map((s) => presentCharString(utf8.encode(String(s)))).join(' ');
    case 'CAA':
      return `${data.flags} ${data.tag} ${presentCharString(utf8.encode(String(data.value)))}`;
    default:
      return String(data ?? '');
  }
}

/**
 * One value written in presentation form (a BIND rdata, e.g. from a check link), read with the
 * zone parser, or null.
 * @param {string} type
 * @param {string} text
 * @param {string} zone the origin relative names are read against
 * @returns {any|null} normalized data
 */
export function parseValueText(type, text, zone) {
  if (!FIX_TYPES.includes(type)) return null;
  const s = String(text ?? '');
  if (!s.trim() || /[\r\n]/.test(s)) return null;
  const z = parseZone(`@ 300 IN ${type} ${s}\n`, { origin: canon(zone) || 'invalid', format: 'bind' });
  const rec = !z.fatal && z.records.length === 1 && !z.records[0].invalid ? z.records[0] : null;
  if (!rec || rec.type !== type || z.warnings.some((w) => w.severity === 'error')) return null;
  return normalizeValue(type, rec.data);
}

/**
 * The `v=` kind of a TXT value ('spf1', 'dmarc1', 'tlsrptv1' …, lowercase), or null.
 * @param {any} data TXT data or text
 * @returns {string|null}
 */
export function txtFamily(data) {
  const m = /^v=([a-z0-9]+)(?=[\s;]|$)/i.exec(txtText(data).trim());
  return m && TXT_FAMILIES[m[1].toLowerCase()] ? m[1].toLowerCase() : null;
}

/**
 * The family a TXT value list shares (every value the same kind of `v=` record), else null.
 * @param {string} type
 * @param {any[]} values
 * @returns {string|null}
 */
export function familyOf(type, values) {
  if (type !== 'TXT' || !values.length) return null;
  const f = txtFamily(values[0]);
  return f && values.every((v) => txtFamily(v) === f) ? f : null;
}

/* ------------------------------------------------------------------------ */
/* Record-set changes                                                       */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} RRsetChange
 * @property {string} name absolute owner name (lowercase, no root dot)
 * @property {string} type one of {@link FIX_TYPES}
 * @property {number} ttl the TTL after the change
 * @property {'is'|'has'|'none'} mode exactly `values` / at least `values` / nothing
 * @property {string|null} family TXT only: the kind of record (`spf1`, `dmarc1` …) the set is scoped to
 * @property {any[]} values the values `mode` is about (canonical data)
 * @property {any[]|null} before the set's current values (in the family), null when not known
 * @property {any[]|null} others TXT with a family: the other TXT values at the name, null when not known
 * @property {number|null} beforeTtl the current TTL, null when not known
 * @property {number|null} maxTtl a TTL change: a resolver's copy must expire within this many seconds
 * @property {boolean} rewrite the same values written again in their right form (a TXT string over
 *   255 bytes split): a change for a zone file and Route 53, although every value stays
 */

/**
 * A record-set change with defaults and canonical values (unknown `before` / `others` stay null).
 * @param {Partial<RRsetChange>} r
 * @returns {RRsetChange}
 */
export function rrset(r) {
  const type = String(r.type || '').toUpperCase();
  const values = uniqBy(arr(r.values).map((v) => normalizeValue(type, v)).filter((v) => v !== null), (v) => valueKey(type, v));
  const norm = (list) => (list === null || list === undefined ? null
    : uniqBy(arr(list).map((v) => normalizeValue(type, v)).filter((v) => v !== null), (v) => valueKey(type, v)));
  const mode = FIX_MODES.includes(r.mode) ? r.mode : 'is';
  const family = type === 'TXT' ? (r.family === undefined ? familyOf(type, values) : r.family || null) : null;
  return {
    name: canon(r.name),
    type,
    ttl: validTtl(r.ttl) ? Number(r.ttl) : DEFAULT_TTL,
    mode,
    family,
    values: mode === 'none' ? [] : values,
    before: norm(r.before),
    others: family ? norm(r.others) : [],
    beforeTtl: validTtl(r.beforeTtl) ? Number(r.beforeTtl) : null,
    maxTtl: validTtl(r.maxTtl) ? Number(r.maxTtl) : null,
    rewrite: !!r.rewrite
  };
}

function validTtl(v) {
  if (v === null || v === undefined || v === '') return false;
  const n = Number(v);
  return Number.isInteger(n) && n >= FIX_LIMITS.ttlMin && n <= FIX_LIMITS.ttlMax;
}

/**
 * What one record-set change does, as far as it is known.
 * @param {RRsetChange} r
 * @returns {{ add: any[], remove: any[]|null, keep: any[], after: any[]|null, full: any[]|null,
 *   ttlOnly: boolean, rewrite: boolean, unchanged: boolean, complete: boolean }}
 *   `remove` null: not known (the current values were not read); `after`: the set (in the family)
 *   afterwards; `full`: every value of the name and type afterwards (null when not known);
 *   `complete`: `full` is known, so a format that replaces whole sets can write it
 */
export function rrsetPlan(r) {
  const key = (v) => valueKey(r.type, v);
  const has = (list, v) => list.some((x) => key(x) === key(v));
  const before = r.before;
  let add;
  let remove;
  let after;
  if (r.mode === 'none') {
    add = [];
    remove = before ? [...before] : null;
    after = [];
  } else if (r.mode === 'has') {
    add = before ? r.values.filter((v) => !has(before, v)) : [...r.values];
    remove = [];
    after = before ? [...before, ...add] : null;
  } else {
    add = before ? r.values.filter((v) => !has(before, v)) : [...r.values];
    remove = before ? before.filter((v) => !has(r.values, v)) : null;
    after = [...r.values];
  }
  let keep = [];
  if (before && r.mode === 'has') keep = [...before];
  else if (before && r.mode === 'is') keep = before.filter((v) => has(r.values, v));
  const full = !after ? null : r.family ? (r.others ? [...r.others, ...after] : null) : after;
  const noValueChange = before !== null && !add.length && remove !== null && !remove.length;
  // Only an asked-for TTL change (maxTtl) or a TTL from the zone file counts: a resolver's TTL counts down.
  const ttlOnly = noValueChange && r.mode !== 'none' && (r.maxTtl !== null || (r.beforeTtl !== null && r.beforeTtl !== r.ttl));
  const rewrite = noValueChange && r.mode !== 'none' && !!r.rewrite;
  return { add, remove, keep, after, full, ttlOnly, rewrite, unchanged: noValueChange && !ttlOnly && !rewrite, complete: full !== null };
}

/* ------------------------------------------------------------------------ */
/* Change requests                                                          */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {{ key: string, params?: object }} FixText  a {@link FIX_I18N} key with its params
 * @typedef {{ severity: 'error'|'warn'|'info', key: string, params?: object, name?: string, type?: string }} FixProblem
 * @typedef {object} ChangeRequest
 * @property {1} v
 * @property {string|null} template the {@link CHANGE_TEMPLATES} id it was built from (null: a fix)
 * @property {string|null} zone
 * @property {RRsetChange[]} rrsets
 * @property {FixText[]} notes what the admin should know (in the instructions too)
 * @property {FixProblem[]} problems what is wrong with the form (errors stop the outputs)
 * @property {Array<{ name: string, type: string }>} reads what a live read asks: {@link readPlan}, and what a template
 *   built from the current state looked at (the SPF record it edits, the records whose TTL it lowers)
 */

/**
 * A change request from record-set changes (merged per name and type, capped at
 * {@link FIX_LIMITS}.rrsets).
 * @param {{ zone: string|null, template?: string|null, rrsets?: object[], notes?: FixText[], problems?: FixProblem[] }} spec
 * @returns {ChangeRequest}
 */
export function changeRequest({ zone, template = null, rrsets = [], notes = [], problems = [] }) {
  const sets = [];
  const probs = [...problems];
  for (const raw of rrsets) {
    const r = rrset(raw);
    if (!r.name || !FIX_TYPES.includes(r.type)) continue;
    const same = sets.find((x) => x.name === r.name && x.type === r.type && x.family === r.family);
    if (same) {
      same.values = uniqBy([...same.values, ...r.values], (v) => valueKey(r.type, v));
      continue;
    }
    sets.push(r);
  }
  if (sets.length > FIX_LIMITS.rrsets) probs.push({ severity: 'error', key: 'fix.p.too-many', params: { max: FIX_LIMITS.rrsets } });
  const values = sets.reduce((n, r) => n + r.values.length, 0);
  if (values > FIX_LIMITS.values) probs.push({ severity: 'error', key: 'fix.p.too-many-values', params: { max: FIX_LIMITS.values } });
  const req = { v: 1, template, zone: zone ? canon(zone) : null, rrsets: sets.slice(0, FIX_LIMITS.rrsets), notes: [...notes], problems: probs, reads: [] };
  req.reads = readPlan(req);
  return req;
}

/** Does a request have an error that stops its outputs? */
export const hasErrors = (req) => !!req && (req.problems || []).some((p) => p.severity === 'error');

/**
 * What a live read asks for a request: the name and type of every set, and at each name the types
 * a CNAME collides with (a CNAME must be alone at its name).
 * @param {ChangeRequest} req
 * @returns {Array<{ name: string, type: string }>}
 */
export function readPlan(req) {
  const out = [];
  const add = (name, type) => {
    if (!out.some((q) => q.name === name && q.type === type)) out.push({ name, type });
  };
  for (const r of req.rrsets) {
    add(r.name, r.type);
    if (r.type === 'CNAME') for (const t of ['A', 'AAAA', 'TXT', 'MX']) add(r.name, t);
    else add(r.name, 'CNAME');
  }
  return out;
}

/**
 * Read what the names of a request hold now, through a DohClient (names and types only). An
 * answer that goes through a CNAME holds the CNAME, never the target's records.
 * @param {Array<{ name: string, type: string }>} queries {@link readPlan}
 * @param {{ dns: { query: Function }, signal?: AbortSignal }} opts
 * @returns {Promise<Record<string, { status: 'ok'|'nodata'|'nxdomain'|'error', values: any[], ttl: number|null, cname: string|null }>>}
 *   keyed 'name|TYPE'
 */
export async function readCurrent(queries, { dns, signal } = {}) {
  const out = {};
  await Promise.all(arr(queries).map(async ({ name, type }) => {
    const res = await dns.query(name, type, { signal, noCache: true });
    out[`${name}|${type}`] = currentEntry(res, name, type);
  }));
  return out;
}

/**
 * One answer as a current-state entry (the records the name itself holds).
 * @param {object|null} res DnsResponse
 * @param {string} name
 * @param {string} type
 * @returns {{ status: 'ok'|'nodata'|'nxdomain'|'error', values: any[], ttl: number|null, cname: string|null }}
 */
export function currentEntry(res, name, type) {
  if (!res || !res.ok || (res.rcode !== 'NOERROR' && res.rcode !== 'NXDOMAIN')) return { status: 'error', values: [], ttl: null, cname: null };
  if (res.rcode === 'NXDOMAIN') return { status: 'nxdomain', values: [], ttl: null, cname: null };
  const own = arr(res.answers).filter((rr) => canon(rr.name) === canon(name));
  const cnameRr = own.find((rr) => rr.type === 'CNAME');
  const recs = own.filter((rr) => rr.type === type);
  const values = uniqBy(recs.map((rr) => normalizeValue(type, rr.data)).filter((v) => v !== null), (v) => valueKey(type, v));
  const ttls = recs.map((rr) => rr.ttl).filter(Number.isFinite);
  return {
    status: values.length ? 'ok' : 'nodata',
    values,
    ttl: ttls.length ? Math.min(...ttls) : null,
    cname: cnameRr && type !== 'CNAME' ? canon(cnameRr.data) : null
  };
}

/**
 * The request with what a live read found filled in: each set's `before` (its family's values),
 * `others` and `beforeTtl`. Entries whose lookup failed stay unknown.
 * @param {ChangeRequest} req
 * @param {Record<string, object>} current {@link readCurrent}
 * @returns {ChangeRequest}
 */
export function applyCurrent(req, current) {
  if (!current) return req;
  const rrsets = req.rrsets.map((r) => {
    const cur = current[`${r.name}|${r.type}`];
    if (!cur || cur.status === 'error') return r;
    const scoped = r.family ? cur.values.filter((v) => txtFamily(v) === r.family) : cur.values;
    const others = r.family ? cur.values.filter((v) => txtFamily(v) !== r.family) : [];
    // Not the TTL: a resolver reports what is left of its cached copy, not the zone's value.
    return { ...r, before: r.before ?? scoped, others: r.family ? (r.others ?? others) : [] };
  });
  return { ...req, rrsets };
}

/* ------------------------------------------------------------------------ */
/* Validation                                                               */
/* ------------------------------------------------------------------------ */

/** Zone File lint codes that apply to a change's records (the rest need the whole zone). */
export const CHANGE_LINT_CODES = Object.freeze(['CNAME_AND_OTHER_DATA', 'CNAME_AT_APEX', 'MULTIPLE_CNAME', 'TARGET_IS_IP', 'PRIVATE_IP',
  'LOCALHOST_RECORD', 'NON_GLOBAL_IPV6', 'MULTIPLE_SPF', 'SPF_INVALID', 'DMARC_INVALID', 'CAA_UNKNOWN_TAG', 'CAA_CRITICAL_UNKNOWN_TAG', 'CAA_FLAGS',
  'TTL_TOO_LOW']);
const SEV_RANK = { error: 0, warn: 1, info: 2 };

/**
 * The records of a change as they would be afterwards, as BIND text: every set's values (the
 * full set where known), and what a live read found at the same names for the other types.
 * @param {ChangeRequest} req
 * @param {Record<string, object>|null} [current]
 * @returns {string}
 */
export function afterZoneText(req, current = null) {
  const lines = [`$ORIGIN ${fqdn(req.zone)}`];
  const changed = new Set(req.rrsets.map((r) => `${r.name}|${r.type}`));
  for (const r of req.rrsets) {
    const plan = rrsetPlan(r);
    const values = plan.full || plan.after || r.values;
    for (const v of values) lines.push(`${fqdn(r.name)} ${r.ttl} IN ${r.type} ${valueText(r.type, v)}`);
  }
  for (const [key, cur] of Object.entries(current || {})) {
    const [name, type] = key.split('|');
    if (changed.has(key) || !cur || cur.status !== 'ok' || !FIX_TYPES.includes(type)) continue;
    for (const v of cur.values) lines.push(`${fqdn(name)} ${cur.ttl ?? DEFAULT_TTL} IN ${type} ${valueText(type, v)}`);
  }
  return `${lines.join('\n')}\n`;
}

/**
 * Check a change request before anyone applies it: its own problems, the Zone File lint rules
 * that apply to its records ({@link CHANGE_LINT_CODES}; with what a live read found at its names,
 * a CNAME next to other data is seen), the SPF lookup budget (the record's own lookup terms, and
 * the recursive count when {@link countSpfLookups} ran — for the record it counted: a record the form
 * has changed since gets a "read again" instead) and the RFC 8659 / 8657 grammar of each CAA issue
 * value.
 * @param {ChangeRequest} req
 * @param {{ current?: Record<string, object>|null, spf?: Record<string, { record: string, count: number|null, exceeded: boolean, error?: string|null }>|null }} [opts]
 * @returns {FixProblem[]} errors first
 */
export function validateChange(req, { current = null, spf = null } = {}) {
  const problems = [...(req.problems || [])];
  if (!req.zone || !req.rrsets.length) return sortProblems(problems);
  const names = new Set(req.rrsets.map((r) => r.name));
  const z = parseZone(afterZoneText(req, current), { origin: req.zone, format: 'bind' });
  if (!z.fatal) {
    const { findings } = lintZone({ ...z, partial: true });
    for (const f of findings) {
      if (!CHANGE_LINT_CODES.includes(f.code) || !names.has(f.name)) continue;
      problems.push({ severity: f.severity, key: `zone.lint.${f.code}`, params: f.params, name: f.name, type: f.type });
    }
  }
  for (const r of req.rrsets) {
    if (r.family === 'spf1') {
      for (const v of r.values) {
        const parsed = parseSpf(txtText(v));
        if (parsed.valid && parsed.lookupTerms > SPF_LOOKUP_LIMIT) {
          problems.push({ severity: 'error', key: 'fix.p.spf-terms', params: { name: r.name, count: parsed.lookupTerms, limit: SPF_LOOKUP_LIMIT }, name: r.name, type: 'TXT' });
        }
      }
      const counted = spf && spf[r.name];
      if (counted && (r.values.length !== 1 || counted.record !== txtText(r.values[0]))) {
        // Counted for the record the form held at the read, not this one: the count says nothing about it.
        problems.push({ severity: 'info', key: 'fix.p.spf-recount', params: { name: r.name }, name: r.name, type: 'TXT' });
      } else if (counted && Number.isFinite(counted.count)) {
        const severity = counted.count > SPF_LOOKUP_LIMIT ? 'error' : counted.count >= SPF_LOOKUP_LIMIT - 1 ? 'warn' : 'info';
        problems.push({ severity, key: `fix.p.spf-lookups-${severity === 'info' ? 'ok' : severity === 'warn' ? 'high' : 'over'}`,
          params: { name: r.name, count: counted.count, limit: SPF_LOOKUP_LIMIT }, name: r.name, type: 'TXT' });
      }
    }
    if (r.type === 'CAA') {
      for (const v of r.values) {
        if (v.tag !== 'issue' && v.tag !== 'issuewild') continue;
        if (v.value.trim() === ';') continue;
        const p = parseCaaIssueValue(v.value);
        if (!p.valid) problems.push({ severity: 'error', key: 'fix.p.caa-malformed', params: { value: v.value, problem: p.error }, name: r.name, type: 'CAA' });
        else if (p.problem) problems.push({ severity: 'error', key: 'fix.p.caa-unsatisfiable', params: { value: v.value, problem: p.problem }, name: r.name, type: 'CAA' });
      }
    }
    if (r.ttl < 60 && r.mode !== 'none') problems.push({ severity: 'info', key: 'fix.p.ttl-low', params: { name: r.name, type: r.type, ttl: r.ttl }, name: r.name, type: r.type });
    if (r.ttl > 86400 && r.mode !== 'none') problems.push({ severity: 'info', key: 'fix.p.ttl-high', params: { name: r.name, type: r.type, ttl: r.ttl }, name: r.name, type: r.type });
  }
  return sortProblems(dedupeProblems(problems));
}

function dedupeProblems(list) {
  return uniqBy(list, (p) => `${p.key}|${JSON.stringify(p.params || {})}`);
}

function sortProblems(list) {
  return list.map((p, i) => ({ p, i })).sort((a, b) => (SEV_RANK[a.p.severity] ?? 3) - (SEV_RANK[b.p.severity] ?? 3) || a.i - b.i).map((x) => x.p);
}

/**
 * The recursive SPF lookup count (RFC 7208 §4.6.4) of every new SPF record in a request, through
 * a DohClient: the record as it will be, its includes as they are published now.
 * @param {ChangeRequest} req
 * @param {{ dns: object, signal?: AbortSignal }} opts
 * @returns {Promise<Record<string, { record: string, count: number|null, exceeded: boolean, error: string|null }>>} keyed by owner
 *   name; `record` is the text counted ({@link validateChange} uses the count only while the set still holds it)
 */
export async function countSpfLookups(req, { dns, signal } = {}) {
  const out = {};
  for (const r of req.rrsets) {
    if (r.family !== 'spf1' || r.values.length !== 1) continue;
    const record = txtText(r.values[0]);
    try {
      const res = await spfLookupCount(r.name, { dns, signal, record });
      out[r.name] = { record, count: res.count, exceeded: res.exceeded, error: null };
    } catch (err) {
      if (err && err.name === 'AbortError') throw err;
      out[r.name] = { record, count: null, exceeded: false, error: err && err.message ? err.message : String(err) };
    }
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Formats                                                                  */
/* ------------------------------------------------------------------------ */

const HEADER = (zone) => `DNS change request for ${zone} (DomainScope)`;

/**
 * One change request written in one format. The request should have no errors
 * ({@link hasErrors}); a set whose current values are not known is written with what can be
 * said (a comment, a placeholder), never with a guess.
 * @param {ChangeRequest} req
 * @param {string} format one of {@link FIX_FORMATS}
 * @returns {string}
 */
export function renderFix(req, format) {
  switch (format) {
    case 'bind': return bindText(req);
    case 'route53': return route53Text(req);
    case 'cloudflare': return cloudflareText(req);
    case 'octodns': return octodnsText(req);
    case 'terraform-cloudflare': return terraformCloudflareText(req);
    case 'terraform-route53': return terraformRoute53Text(req);
    default: throw new RangeError(`fixes: unknown format "${format}"`);
  }
}

/** Notes of a template that edits a TXT family set it did not read (`params.name`: the set's name). */
const UNREAD_EDIT_NOTES = Object.freeze({ 'fix.n.spf-unread': 'spf1', 'fix.n.dmarc-unread': 'dmarc1', 'fix.n.dmarc-first-unread': 'dmarc1' });

/**
 * The TXT family sets a template edits without having read them (an include added to the SPF
 * record, DMARC tags changed, a first DMARC record): whether the name has such a record is not
 * known, so no output may read as "replace it with this value" — its note says what to do with one.
 * @param {ChangeRequest} req
 * @returns {RRsetChange[]}
 */
export function unreadEdits(req) {
  const keys = new Set(arr(req && req.notes).filter((n) => UNREAD_EDIT_NOTES[n.key] && n.params && n.params.name)
    .map((n) => `${n.params.name}|${UNREAD_EDIT_NOTES[n.key]}`));
  return arr(req && req.rrsets).filter((r) => r.family && r.mode === 'is' && r.before === null && keys.has(`${r.name}|${r.family}`));
}

/**
 * What the admin must know about one format's output: a family set a template edits without a
 * read (every format replaces the record it has), a set whose current values were not read
 * (Route 53, aws_route53_record and octoDNS replace whole sets), a Route 53 DELETE that must name
 * the set exactly, Cloudflare's TTL range and record ids.
 * @param {ChangeRequest} req
 * @param {string} format
 * @returns {FixText[]}
 */
export function formatNotes(req, format) {
  const notes = unreadEdits(req).map((r) => ({ key: 'fix.fn.unread-edit', params: { name: r.name, family: TXT_FAMILIES[r.family] } }));
  const plans = req.rrsets.map((r) => ({ r, plan: rrsetPlan(r) }));
  if (format === 'route53' || format === 'octodns' || format === 'terraform-route53') {
    for (const { r, plan } of plans) if (r.mode !== 'none' && !plan.complete) notes.push({ key: 'fix.fn.incomplete', params: { name: r.name, type: r.type } });
  }
  if (format === 'route53' && plans.some(({ r }) => r.mode === 'none' && (!r.family || !(r.others && r.others.length)))) notes.push({ key: 'fix.fn.route53-delete' });
  if (format === 'cloudflare' || format === 'terraform-cloudflare') {
    if (req.rrsets.some((r) => r.mode !== 'none' && (r.ttl < 60 || r.ttl > 86400))) notes.push({ key: 'fix.fn.cloudflare-ttl' });
  }
  if (format === 'cloudflare' && plans.some(({ plan }) => plan.ttlOnly || plan.remove === null || plan.remove.length)) notes.push({ key: 'fix.fn.cloudflare-ids' });
  if (format === 'octodns') {
    const quoted = req.rrsets.find((r) => r.type === 'TXT' && octoWritten(r).some(octoMangled));
    if (quoted) notes.push({ key: 'fix.fn.octodns-quote', params: { name: quoted.name } });
  }
  return notes;
}

const describeSet = (r) => `${r.name} ${r.type}${r.family ? ` (${TXT_FAMILIES[r.family]})` : ''}`;

/** BIND: the sets as they will be, relative to `$ORIGIN`, with what goes as comments. */
function bindText(req) {
  const out = [`; ${HEADER(req.zone)}`, '; The records below are what the changed sets hold afterwards;', '; every other record of the zone stays as it is.', `$ORIGIN ${fqdn(req.zone)}`];
  for (const r of req.rrsets) {
    const plan = rrsetPlan(r);
    if (plan.unchanged) continue;
    const owner = relativeName(r.name, req.zone);
    const line = (v, ttl = r.ttl) => `${owner} ${ttl} IN ${r.type} ${valueText(r.type, v)}`;
    out.push('');
    out.push(`; ${describeSet(r)}${r.family ? `; the other TXT records of ${owner} stay` : ''}`);
    if (r.mode === 'none') {
      if (plan.remove) for (const v of plan.remove) out.push(`; delete: ${line(v, r.beforeTtl ?? r.ttl)}`);
      else out.push(`; delete every ${r.type}${r.family ? ` ${TXT_FAMILIES[r.family]}` : ''} record of ${owner}`);
      continue;
    }
    if (plan.ttlOnly) out.push(`; TTL -> ${r.ttl}, values unchanged`);
    if (plan.rewrite) out.push('; the same values, each TXT string at most 255 bytes');
    if (r.mode === 'has' && !r.before) out.push(`; add; keep the ${r.type} records ${owner} already has`);
    if (r.mode === 'is' && plan.remove === null) {
      out.push(r.family ? `; replaces the ${TXT_FAMILIES[r.family]} record of ${owner}` : `; replaces every ${r.type} record of ${owner}`);
    }
    for (const v of plan.after || r.values) out.push(line(v));
    if (plan.remove) for (const v of plan.remove) out.push(`; delete: ${line(v, r.beforeTtl ?? r.ttl)}`);
  }
  return `${out.join('\n')}\n`;
}

/** A Route 53 value: the presentation text, names without the root dot, TXT and CAA strings in its escape form. */
function route53Value(type, v) {
  if (type === 'CNAME') return canon(v) || '.';
  if (type === 'MX') return `${v.preference} ${v.exchange || '.'}`;
  if (type === 'TXT') return arr(v).map(route53String).join(' ');
  if (type === 'CAA') return `${v.flags} ${v.tag} ${route53String(v.value)}`;
  return valueText(type, v);
}

/** Route 53: one UPSERT (or DELETE) per set, for `aws route53 change-resource-record-sets`. */
function route53Text(req) {
  const changes = [];
  for (const r of req.rrsets) {
    const plan = rrsetPlan(r);
    if (plan.unchanged) continue;
    const set = (values, ttl) => ({ Name: fqdn(r.name), Type: r.type, TTL: ttl, ResourceRecords: values.map((v) => ({ Value: route53Value(r.type, v) })) });
    if (r.mode === 'none') {
      // A DELETE names the set exactly as it is (values and TTL); a family's other TXT values are UPSERTed back.
      if (r.family && r.others && r.others.length) changes.push({ Action: 'UPSERT', ResourceRecordSet: set(r.others, r.beforeTtl ?? r.ttl) });
      else if (r.before && r.before.length) changes.push({ Action: 'DELETE', ResourceRecordSet: set(r.before, r.beforeTtl ?? r.ttl) });
      else if (!r.before || (r.family && !r.others)) {
        changes.push({ Action: 'DELETE', ResourceRecordSet: { Name: fqdn(r.name), Type: r.type, TTL: r.beforeTtl ?? r.ttl, ResourceRecords: [{ Value: 'CURRENT_VALUE' }] } });
      }
      continue;
    }
    const values = plan.full || plan.after || r.values;
    changes.push({ Action: 'UPSERT', ResourceRecordSet: set(values, r.ttl) });
  }
  return `${JSON.stringify({ Comment: HEADER(req.zone), Changes: changes }, null, 2)}\n`;
}

/** JSON with every non-ASCII character escaped, safe inside a single-quoted shell word. */
function asciiJson(value) {
  return JSON.stringify(value).replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/** A Cloudflare API record body for one value. */
function cloudflareBody(r, v) {
  const body = { type: r.type, name: r.name };
  if (r.type === 'MX') Object.assign(body, { content: v.exchange || '.', priority: v.preference });
  else if (r.type === 'CAA') body.data = { flags: v.flags, tag: v.tag, value: v.value };
  else if (r.type === 'TXT') body.content = valueText('TXT', v);
  else body.content = canon(v);
  body.ttl = r.ttl;
  return body;
}

/**
 * A query value inside a double-quoted shell word: percent-encoded, `!` too (an interactive
 * bash expands it), so nothing of a name from a zone file (`` ` `` `$` `"` `\`) reaches the shell.
 */
const shellQueryValue = (s) => encodeURIComponent(String(s ?? '')).replace(/!/g, '%21');

/** The Cloudflare API as a POSIX shell script (curl); the token and zone ID come from the shell. */
function cloudflareText(req) {
  const { token, zone } = CLOUDFLARE_VARS;
  const auth = `-H "Authorization: Bearer $${token}"`;
  // The zone's name in the ${VAR:?word} message only as a plain host name: that word is expanded by the shell.
  const zoneWord = /^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/.test(String(req.zone ?? '')) ? req.zone : 'the zone above';
  const out = [
    '#!/bin/sh',
    `# ${HEADER(req.zone)}`,
    '# Needs an API token that may edit this zone\'s DNS records (Zone > DNS > Edit) and the zone ID',
    '# (the zone\'s Overview page). Neither is written here: set both in your shell first.',
    `: "\${${token}:?set ${token} to your API token}"`,
    `: "\${${zone}:?set ${zone} to the zone ID of ${zoneWord}}"`,
    `API="https://api.cloudflare.com/client/v4/zones/$${zone}/dns_records"`
  ];
  const find = (r, what) => [`#    ${what}`, `curl -sS "$API?type=${r.type}&name=${shellQueryValue(r.name)}" ${auth}`];
  const patch = (body) => [`curl -sS -X PATCH "$API/RECORD_ID" ${auth} -H "Content-Type: application/json" \\`, `  --data ${quoteArg(asciiJson(body))}`];
  const del = `curl -sS -X DELETE "$API/RECORD_ID" ${auth}`;
  let step = 0;
  const head = (text) => {
    step += 1;
    out.push('', `# ${step}. ${text}`);
  };
  for (const r of req.rrsets) {
    const plan = rrsetPlan(r);
    const add = r.mode === 'none' ? [] : plan.add;
    const valueList = (list) => list.map((v) => valueText(r.type, v)).join(', ');
    if (plan.unchanged) continue;
    if (plan.rewrite) {
      head(`${describeSet(r)}: nothing to do, the API splits a value over 255 bytes itself`);
      continue;
    }
    if (plan.ttlOnly) {
      head(`TTL of ${describeSet(r)} -> ${r.ttl}, values unchanged`);
      out.push(...find(r, 'Find the id of each record, then:'), ...patch({ ttl: r.ttl }));
      continue;
    }
    if (plan.remove && plan.remove.length === 1 && add.length === 1) {
      // One value for another (an SPF record, a CNAME target, one MX): changed in place, never two at once.
      head(`Change ${describeSet(r)}: ${valueText(r.type, plan.remove[0])} -> ${valueText(r.type, add[0])}`);
      out.push(...find(r, "Find the record's id, then:"), ...patch(cloudflareBody(r, add[0])));
      continue;
    }
    if (plan.remove === null) {
      // Not read: whatever is there goes first (Cloudflare refuses a second CNAME next to one).
      head(r.mode === 'none' ? `Delete every ${describeSet(r)} record` : `Delete the ${describeSet(r)} records there now (they were not read)`);
      out.push(...find(r, r.mode === 'none' ? "Find each record's id, then:" : 'Find their ids (none: skip this step), then:'), del);
    }
    for (const v of add) {
      head(`Add ${r.name} ${r.type} ${valueText(r.type, v)}`);
      out.push(`curl -sS -X POST "$API" ${auth} -H "Content-Type: application/json" \\`, `  --data ${quoteArg(asciiJson(cloudflareBody(r, v)))}`);
    }
    if (plan.remove && plan.remove.length) {
      head(`Delete ${r.name} ${r.type} ${valueList(plan.remove)}`);
      out.push(...find(r, "Find each record's id, then:"), del);
    }
    if (r.mode !== 'none' && plan.keep.length && r.beforeTtl !== null && r.beforeTtl !== r.ttl) {
      head(`TTL of the ${r.type} records ${r.name} keeps -> ${r.ttl}`);
      out.push(...find(r, 'Find their ids, then:'), ...patch({ ttl: r.ttl }));
    }
  }
  return `${out.join('\n')}\n`;
}

/**
 * octoDNS: a TXT value's raw text with `;` escaped (octoDNS refuses a bare one), in one more pair of
 * quotes when it starts with one (octoDNS strips them as it loads it); lib/zoneconvert.js writes whole
 * zones the same way.
 */
const octoRaw = (v) => octodnsTxt(txtText(v));
const octoTxt = (v) => octodnsTxtValue(txtText(v)) ?? octoRaw(v);
/** A TXT value octoDNS changes as it loads it (it deletes a `" "` inside): written, with a note. */
const octoMangled = (v) => octodnsTxtValue(txtText(v)) === null;
/** The values an octoDNS entry writes for a record set. */
const octoWritten = (r) => (r.mode === 'none' ? [] : rrsetPlan(r).full || rrsetPlan(r).after || r.values);

function octoValue(type, v, indent) {
  const pad = ' '.repeat(indent);
  if (type === 'MX') return [`${pad}- exchange: ${yamlStr(fqdn(v.exchange))}`, `${pad}  preference: ${v.preference}`];
  if (type === 'CAA') return [`${pad}- flags: ${v.flags}`, `${pad}  tag: ${yamlStr(v.tag)}`, `${pad}  value: ${yamlStr(v.value)}`];
  if (type === 'TXT') return [`${pad}- ${yamlStr(octoTxt(v))}`];
  if (type === 'CNAME') return [`${pad}- ${yamlStr(fqdn(v))}`];
  return [`${pad}- ${yamlStr(v)}`];
}

/** octoDNS: the zone file's entries for the changed names (a record list per name). */
function octodnsText(req) {
  const out = [`# ${HEADER(req.zone)}`, `# In the zone's YAML (${req.zone}.yaml): set these entries; the other names stay as they are.`];
  // A `;` is written `\;`: the YamlProvider must read it so (octoDNS's default until 2.0, deprecated).
  if (req.rrsets.some((r) => r.type === 'TXT' && octoWritten(r).some((v) => txtText(v).includes(';')))) {
    out.push('# TXT values write ; as \\; : the YamlProvider needs escaped_semicolons: true (octoDNS refuses them with false, its default from 2.0).');
  }
  out.push('---');
  const byName = new Map();
  for (const r of req.rrsets) {
    const key = r.name === req.zone ? '' : relativeName(r.name, req.zone);
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key).push(r);
  }
  // The names in octoDNS's natural key order, so the entries go into a sorted file as they are.
  for (const key of [...byName.keys()].sort(naturalCompare)) {
    out.push(`${key === '' ? "''" : yamlStr(key)}:`);
    for (const r of byName.get(key)) {
      const plan = rrsetPlan(r);
      if (r.mode === 'none') {
        out.push(r.family ? `  # delete: remove the ${TXT_FAMILIES[r.family]} value from this name's TXT values; the other values stay`
          : `  # delete: remove the ${r.type} record from this name's list; its other records stay`);
        continue;
      }
      const values = plan.full || plan.after || r.values;
      if (!plan.complete) {
        out.push(r.family ? `  # keep the other TXT values this name has; replace its ${TXT_FAMILIES[r.family]} value with the one below`
          : `  # keep the ${r.type} values this name already has, and add the ones below`);
      }
      // In octoDNS's key order (YamlProvider enforce_order): octodns, ttl, type, value(s). A TXT value
      // octoDNS's own check refuses (outside ASCII, a \ before a ;) loads only as lenient.
      if (r.type === 'TXT' && values.some(octoMangled)) {
        out.push('  # octoDNS deletes " " inside a TXT value as it loads it: it publishes this value without them; set it at the provider another way');
      }
      if (r.type === 'TXT' && values.some((v) => octodnsTxtRefused(octoRaw(v)))) {
        out.push("  # octoDNS's check refuses this text (characters outside ASCII, or a \\ before a ;): lenient loads it with a warning",
          '  - octodns:', '      lenient: true', `    ttl: ${r.ttl}`);
      } else {
        out.push(`  - ttl: ${r.ttl}`);
      }
      out.push(`    type: ${r.type}`);
      if (r.type === 'CNAME') out.push(`    value: ${yamlStr(fqdn(values[0]))}`);
      else out.push('    values:', ...values.flatMap((v) => octoValue(r.type, v, 6)));
    }
  }
  return `${out.join('\n')}\n`;
}

/** An HCL string literal. */
function hcl(s) {
  return `"${String(s ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r')
    .replace(/\$\{/g, '$$$${').replace(/%\{/g, '%%{')}"`;
}

/**
 * Terraform resource names: `<type>_<name>` in [a-z0-9_], unique: a repeat takes `_<n>`, past any
 * name already given (the second value at `x` and the first at `x-2` would both be `…_x_2`).
 */
function resourceNamer(zone) {
  const used = new Map();
  const given = new Set();
  return (type, name) => {
    const rel = relativeName(name, zone);
    const base = `${type}_${rel === '@' ? 'apex' : rel}`.toLowerCase().replace(/\*/g, 'wildcard').replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
    let n = used.get(base) || 0;
    let out;
    do {
      n += 1;
      out = n === 1 ? base : `${base}_${n}`;
    } while (given.has(out));
    used.set(base, n);
    given.add(out);
    return out;
  };
}

/** Terraform, terraform-provider-cloudflare v4: one cloudflare_record per value. */
function terraformCloudflareText(req) {
  const v = TERRAFORM_VARS.cloudflare;
  const out = [`# ${HEADER(req.zone)}`, '# terraform-provider-cloudflare v4 (cloudflare_record; v5 names it cloudflare_dns_record).',
    `variable "${v}" {`, '  type        = string', `  description = "The zone ID of ${req.zone}"`, '}'];
  const nameOf = resourceNamer(req.zone);
  for (const r of req.rrsets) {
    const plan = rrsetPlan(r);
    const values = r.mode === 'none' ? [] : (plan.after || r.values);
    if (plan.remove && plan.remove.length === 1 && plan.add.length === 1 && r.mode !== 'none') {
      out.push('', `# change: the resource that holds ${r.name} ${r.type} ${valueText(r.type, plan.remove[0])} gets the value below`);
    } else if (plan.remove && plan.remove.length) {
      out.push('', `# delete: remove the resources of ${r.name} ${r.type} ${plan.remove.map((x) => valueText(r.type, x)).join(', ')}`);
    } else if (plan.remove === null) {
      out.push('', r.mode === 'none' ? `# delete: remove the resources of every ${describeSet(r)} record`
        : `# remove the resources of any other ${describeSet(r)} record (the current ones were not read)`);
    }
    for (const val of values) {
      const lines = ['', `resource "cloudflare_record" "${nameOf(r.type.toLowerCase(), r.name)}" {`, `  zone_id  = var.${v}`,
        `  name     = ${hcl(r.name)}`, `  type     = ${hcl(r.type)}`];
      if (r.type === 'CAA') lines.push('  data {', `    flags = ${val.flags}`, `    tag   = ${hcl(val.tag)}`, `    value = ${hcl(val.value)}`, '  }');
      else if (r.type === 'MX') lines.push(`  content  = ${hcl(val.exchange || '.')}`, `  priority = ${val.preference}`);
      else if (r.type === 'TXT') lines.push(`  content  = ${hcl(txtText(val))}`);
      else lines.push(`  content  = ${hcl(canon(val))}`);
      lines.push(`  ttl      = ${r.ttl}`, '}');
      out.push(...lines);
    }
  }
  return `${out.join('\n')}\n`;
}

/**
 * An aws_route53_record value. The provider wraps a TXT value in quotes as it is, so each string
 * is written as Route 53 reads it (the change batch's escapes, without the outer quotes), and
 * strings over 255 bytes are joined with `""` (the provider's split).
 */
function awsValue(type, v) {
  if (type === 'TXT') return arr(v).map((s) => route53String(s).slice(1, -1)).join('""');
  if (type === 'CAA') return `${v.flags} ${v.tag} "${v.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  return route53Value(type, v);
}

/** Terraform, the AWS provider: one aws_route53_record per set (it owns the whole set). */
function terraformRoute53Text(req) {
  const v = TERRAFORM_VARS.route53;
  const out = [`# ${HEADER(req.zone)}`, '# aws_route53_record manages a whole record set: every value of the name and type is listed.',
    `variable "${v}" {`, '  type        = string', `  description = "The hosted zone ID of ${req.zone}"`, '}'];
  const nameOf = resourceNamer(req.zone);
  for (const r of req.rrsets) {
    const plan = rrsetPlan(r);
    const values = plan.full || plan.after || r.values;
    if (r.mode === 'none') {
      if (r.family && r.others && r.others.length) {
        out.push('', `# ${describeSet(r)} goes: the set keeps its other TXT values`, ...awsResource(nameOf('txt', r.name), v, r, r.others, r.beforeTtl ?? r.ttl));
      } else {
        out.push('', `# delete: remove the resource of ${r.name} ${r.type} (terraform destroys the record set)`);
      }
      continue;
    }
    if (!plan.complete) {
      out.push('', r.family ? `# list the other TXT values of ${r.name} here too (they were not read): this resource replaces the whole set`
        : `# list the ${r.type} values ${r.name} already has here too (they were not read): this resource replaces the whole set`);
    }
    out.push(...awsResource(nameOf(r.type.toLowerCase(), r.name), v, r, values, r.ttl));
  }
  return `${out.join('\n')}\n`;
}

function awsResource(id, v, r, values, ttl) {
  return ['', `resource "aws_route53_record" "${id}" {`, `  zone_id = var.${v}`, `  name    = ${hcl(r.name)}`, `  type    = ${hcl(r.type)}`,
    `  ttl     = ${ttl}`, `  records = [${values.map((x) => hcl(awsValue(r.type, x))).join(', ')}]`, '}'];
}

/* ------------------------------------------------------------------------ */
/* Instructions for the DNS admin                                           */
/* ------------------------------------------------------------------------ */

/** What a set change does, in one word ({@link FIX_ACTIONS}). */
export const FIX_ACTIONS = Object.freeze(['add', 'replace', 'delete', 'ttl', 'rewrite', 'unchanged']);

/**
 * The action of one set change: `add` (values join the set: `has`, or nothing there before),
 * `replace` (the set becomes exactly these values), `delete`, `ttl` (only the TTL changes),
 * `rewrite` (the same values in their right form) or `unchanged`.
 * @param {RRsetChange} r
 * @param {ReturnType<typeof rrsetPlan>} [plan]
 * @returns {string}
 */
export function rrsetAction(r, plan = rrsetPlan(r)) {
  if (plan.unchanged) return 'unchanged';
  if (r.mode === 'none') return 'delete';
  if (plan.ttlOnly) return 'ttl';
  if (plan.rewrite) return 'rewrite';
  if (r.mode === 'has' || (r.before && !r.before.length)) return 'add';
  return 'replace';
}

/**
 * The Copy summary of a change request's result (lib/summary.js changeSummary, with `request`):
 * the template's name as the view words it, each record set by name and type (a TXT family's
 * name too) with what the change does to it — a family set a template edits without a read is
 * "add or change" ({@link unreadEdits}) — and how many of the problems shown are errors and
 * warnings. Never a value: the change's values travel in its check link, the summary's URL.
 * @param {ChangeRequest} req
 * @param {{ problems?: FixProblem[]|null, templateName?: string|null, at?: Date|null }} [opts] `problems`: the ones
 *   shown with the result (validateChange), else the request's own
 * @returns {{ request: true, zone: string|null, template: string|null, templateName: string|null,
 *   sets: Array<{ name: string, type: string, family: string|null, action: string }>, errors: number, warnings: number, at: Date|null }}
 */
export function requestSummaryFacts(req, { problems = null, templateName = null, at = null } = {}) {
  const unread = new Set(unreadEdits(req));
  const list = arr(problems === null ? req && req.problems : problems);
  return {
    request: true,
    zone: (req && req.zone) || null,
    template: (req && req.template) || null,
    templateName: templateName || null,
    sets: arr(req && req.rrsets).map((r) => ({
      name: r.name, type: r.type, family: r.family ? TXT_FAMILIES[r.family] || null : null, action: unread.has(r) ? 'set' : rrsetAction(r)
    })),
    errors: list.filter((p) => p && p.severity === 'error').length,
    warnings: list.filter((p) => p && p.severity === 'warn').length,
    at: at || null
  };
}

/**
 * What a set's action counts as in a change request's result header (docs/DESIGN.md §5.6: added,
 * changed, removed); an unread family edit (`set`, "add or change") is a change, an unchanged set
 * none.
 */
export const CHANGE_STATUS_OF = Object.freeze({ add: 'added', replace: 'changed', ttl: 'changed', rewrite: 'changed', set: 'changed', delete: 'removed' });

/** The sign a set's action is written with in the result title: + added, ~ changed, − removed. */
export const CHANGE_SIGNS = Object.freeze({ added: '+', changed: '~', removed: '−' });

/**
 * The status summary of a change request (docs/DESIGN.md §5.4, §5.6: · added · changed · removed),
 * after the errors and warnings shown with it — which a press brings into view. From
 * {@link requestSummaryFacts}.
 * @param {{ sets?: Array<{ action: string }>, errors?: number, warnings?: number }|null} facts
 * @returns {Array<{ key: string, severity: string, count: number }>}
 */
export function changeStatus(facts) {
  const n = { added: 0, changed: 0, removed: 0 };
  for (const s of arr(facts && facts.sets)) {
    const kind = s && CHANGE_STATUS_OF[s.action];
    if (kind) n[kind] += 1;
  }
  const num = (v) => Math.max(0, Number(v) || 0);
  return [
    { key: 'error', severity: 'error', count: num(facts && facts.errors) },
    { key: 'warn', severity: 'warn', count: num(facts && facts.warnings) },
    { key: 'added', severity: 'neutral', count: n.added },
    { key: 'changed', severity: 'neutral', count: n.changed },
    { key: 'removed', severity: 'neutral', count: n.removed }
  ];
}

/**
 * The result title of a change request (docs/DESIGN.md §5.6: "What changes: + TXT
 * _acme-challenge.example.com"): the first set that changes something, with its sign
 * ({@link CHANGE_SIGNS}), and how many more change. A request that changes nothing has no set.
 * @param {{ sets?: Array<{ name: string, type: string, family?: string|null, action: string }> }|null} facts
 * @returns {{ set: { sign: string, kind: string, name: string, type: string, family: string|null }|null, more: number }}
 */
export function changeHeadline(facts) {
  const changing = arr(facts && facts.sets).filter((s) => s && CHANGE_STATUS_OF[s.action]);
  if (!changing.length) return { set: null, more: 0 };
  const first = changing[0];
  const kind = CHANGE_STATUS_OF[first.action];
  return { set: { sign: CHANGE_SIGNS[kind], kind, name: first.name, type: first.type, family: first.family || null }, more: changing.length - 1 };
}

/**
 * The admin's instructions in one language (either, whatever the UI language): one numbered step
 * per set (add / replace / delete / change the TTL), the template's notes and, when given, the
 * check link.
 * @param {ChangeRequest} req
 * @param {{ lang?: 'en'|'tr', checkUrl?: string|null }} [opts]
 * @returns {string}
 */
export function changeInstructions(req, { lang = 'en', checkUrl = null } = {}) {
  const L = FIX_LANGS.includes(lang) ? lang : 'en';
  const tx = (key, params) => textIn(L, key, params);
  const out = [tx('fix.ins.title', { zone: req.zone }), '', tx('fix.ins.intro', { zone: req.zone }), ''];
  const unread = unreadEdits(req);
  let step = 0;
  for (const r of req.rrsets) {
    const plan = rrsetPlan(r);
    if (plan.unchanged) continue;
    step += 1;
    const kind = r.family ? tx('fix.ins.family', { family: TXT_FAMILIES[r.family] }) : tx('fix.ins.records', { type: r.type });
    const vals = (list) => list.map((v) => `     ${valueText(r.type, v)}`);
    const action = rrsetAction(r, plan);
    // Not read, and a record there would be edited, not replaced: "add or change", the notes say how.
    const edit = unread.includes(r);
    out.push(`${step}. ${tx(`fix.ins.action.${edit ? 'set' : action}`)}: ${kind}`);
    out.push(`   ${tx('fix.ins.name')}: ${r.name}`);
    if (action === 'ttl') {
      out.push(`   ${tx('fix.ins.ttlChange', { to: r.ttl })}`);
    } else if (action === 'rewrite') {
      out.push(`   ${tx('fix.ins.rewrite')}`, ...vals(r.values));
    } else if (action === 'delete') {
      if (plan.remove && plan.remove.length) out.push(`   ${tx('fix.ins.values')}:`, ...vals(plan.remove));
      else out.push(`   ${tx(r.family ? 'fix.ins.deleteFamily' : 'fix.ins.deleteAll', { type: r.type, family: r.family ? TXT_FAMILIES[r.family] : '' })}`);
    } else {
      const shown = action === 'replace' ? r.values : plan.add;
      out.push(`   ${tx(shown.length === 1 ? 'fix.ins.value' : 'fix.ins.values')}:`, ...vals(shown));
      out.push(`   TTL: ${r.ttl}`);
      if (r.mode === 'has' && (!r.before || r.before.length)) out.push(`   ${tx('fix.ins.keepOthers', { type: r.type })}`);
      if (action === 'replace') {
        if (plan.remove && plan.remove.length) out.push(`   ${tx('fix.ins.removes')}:`, ...vals(plan.remove));
        else if (plan.remove === null) {
          const key = edit ? 'fix.ins.editFamily' : r.family ? 'fix.ins.replaceFamily' : 'fix.ins.replaceAll';
          out.push(`   ${tx(key, { type: r.type, family: r.family ? TXT_FAMILIES[r.family] : '' })}`);
        }
        if (r.family) out.push(`   ${tx('fix.ins.familyOthers')}`);
      }
    }
  }
  if (!step) out.push(tx('fix.ins.nothing'));
  const notes = (req.notes || []).map((n) => `- ${tx(n.key, n.params)}`);
  if (notes.length) out.push('', tx('fix.ins.notes'), ...notes);
  if (checkUrl) out.push('', tx('fix.ins.check'), checkUrl);
  return `${out.join('\n')}\n`;
}

/* ------------------------------------------------------------------------ */
/* SPF and DMARC editing                                                    */
/* ------------------------------------------------------------------------ */

const ALL_RANK = { '-': 0, '~': 1, '?': 2, '+': 3 };

/**
 * An SPF record with `include:<domain>` added before its `all` term (or its `redirect=`), unless it
 * already has it; the `all` qualifier replaced when `all` is given ('~all' / '-all').
 * @param {string} record
 * @param {{ add?: string[], remove?: string[], all?: string|null }} edits
 * @returns {{ record: string, added: string[], removed: string[], missing: string[], present: string[] }}
 */
export function editSpf(record, { add = [], remove = [], all = null } = {}) {
  const tokens = String(record ?? '').trim().split(/\s+/).filter(Boolean);
  const head = tokens.length && /^v=spf1$/i.test(tokens[0]) ? tokens.shift() : 'v=spf1';
  const isInclude = (tok, d) => new RegExp(`^\\+?include:${d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i').test(tok);
  const removed = [];
  const missing = [];
  let body = tokens;
  for (const d of remove) {
    const before = body.length;
    body = body.filter((tok) => !isInclude(tok, d));
    if (body.length === before) missing.push(d);
    else removed.push(d);
  }
  const added = [];
  const present = [];
  for (const d of add) {
    if (body.some((tok) => isInclude(tok, d))) {
      present.push(d);
      continue;
    }
    const at = body.findIndex((tok) => /^[+?~-]?all$/i.test(tok) || /^redirect=/i.test(tok));
    const term = `include:${d}`;
    if (at === -1) body.push(term);
    else body.splice(at, 0, term);
    added.push(d);
  }
  if (all) {
    const at = body.findIndex((tok) => /^[+?~-]?all$/i.test(tok));
    if (at === -1) body = [...body.filter((tok) => !/^redirect=/i.test(tok)), all];
    else body[at] = all;
  }
  return { record: [head, ...body].join(' '), added, removed, missing, present };
}

/**
 * Several SPF records merged into one (RFC 7208 allows one): every term once, in order, the
 * strictest `all` last; a `redirect=` only when no record has an `all`; then the first `exp=` and
 * every other modifier once (by name, the first record's value).
 * @param {string[]} records
 * @returns {string}
 */
export function mergeSpf(records) {
  const terms = [];
  const mods = new Map();
  let all = null;
  let redirect = null;
  for (const rec of records) {
    const parsed = parseSpf(rec);
    for (const t of parsed.terms) {
      if (t.mechanism === 'all') {
        if (all === null || ALL_RANK[t.qualifier] < ALL_RANK[all]) all = t.qualifier;
        continue;
      }
      if (!terms.some((x) => x.toLowerCase() === t.raw.toLowerCase())) terms.push(t.raw);
    }
    if (parsed.modifiers.redirect && !redirect) redirect = parsed.modifiers.redirect;
    // exp= and unknown modifiers as written (RFC 7208 §6: an unknown one is ignored, never an error).
    for (const tok of String(rec ?? '').trim().split(/\s+/).slice(1)) {
      const m = /^([a-z][a-z0-9_.-]*)=/i.exec(tok);
      const key = m ? m[1].toLowerCase() : null;
      if (key && key !== 'redirect' && !mods.has(key)) mods.set(key, tok);
    }
  }
  const tail = all !== null ? [`${all === '+' ? '' : all}all`.replace(/^all$/, '+all')] : redirect ? [`redirect=${redirect}`] : [];
  return ['v=spf1', ...terms, ...tail, ...mods.values()].join(' ');
}

/**
 * A DMARC record with tags set or removed (`null` removes one), `v` first and `p` second, the
 * other tags kept in their order.
 * @param {string|null} record the current record, null for a new one
 * @param {Record<string, string|null>} set
 * @returns {string}
 */
export function editDmarc(record, set) {
  const tags = [];
  for (const part of String(record ?? '').split(';')) {
    const m = /^\s*([a-z]+)\s*=\s*(.*?)\s*$/i.exec(part);
    if (m && !tags.some(([k]) => k === m[1].toLowerCase())) tags.push([m[1].toLowerCase(), m[2]]);
  }
  for (const [k, v] of Object.entries(set)) {
    const i = tags.findIndex(([key]) => key === k);
    if (v === null || v === undefined || v === '') {
      if (i !== -1) tags.splice(i, 1);
    } else if (i === -1) tags.push([k, v]);
    else tags[i][1] = v;
  }
  const get = (k) => (tags.find(([key]) => key === k) || [null, null])[1];
  const rest = tags.filter(([k]) => k !== 'v' && k !== 'p');
  return [`v=${get('v') || 'DMARC1'}`, `p=${get('p') || 'none'}`, ...rest.map(([k, v]) => `${k}=${v}`)].join('; ');
}

/* ------------------------------------------------------------------------ */
/* Templates                                                                */
/* ------------------------------------------------------------------------ */

/**
 * Form fields of the templates. `kind`: domain (a zone name), name (a name in the zone, `*.`
 * where allowed), host, lines (one value per line), text, email, ttl, number, check, select,
 * multi (several options). Labels are `fix.field.<id>`, hints `fix.field.<id>.hint`, options
 * `fix.opt.<id>.<value>` ({@link FIX_I18N}); a `literal` field's options are their own labels.
 */
export const FIX_FIELDS = Object.freeze({
  domain: Object.freeze({ kind: 'domain' }),
  name: Object.freeze({ kind: 'name' }),
  tokens: Object.freeze({ kind: 'lines' }),
  target: Object.freeze({ kind: 'host' }),
  mxHost: Object.freeze({ kind: 'host', optional: true }),
  autodiscover: Object.freeze({ kind: 'check', default: true }),
  tenant: Object.freeze({ kind: 'host', optional: true }),
  dkimSelector: Object.freeze({ kind: 'text', default: 'google' }),
  dkimKey: Object.freeze({ kind: 'text', optional: true }),
  dmarc: Object.freeze({ kind: 'check', default: true }),
  rua: Object.freeze({ kind: 'email', optional: true }),
  cas: Object.freeze({ kind: 'multi', options: Object.freeze(FIX_CAS.map((c) => c.id)), default: Object.freeze(['letsencrypt']) }),
  wild: Object.freeze({ kind: 'select', options: Object.freeze(['unset', 'same', 'none']), default: 'unset' }),
  accountUri: Object.freeze({ kind: 'text', optional: true }),
  methods: Object.freeze({ kind: 'multi', options: CAA_FORM_METHODS, default: Object.freeze([]) }),
  iodef: Object.freeze({ kind: 'email', optional: true }),
  spfAction: Object.freeze({ kind: 'select', options: Object.freeze(['add', 'remove']), default: 'add' }),
  includes: Object.freeze({ kind: 'lines' }),
  all: Object.freeze({ kind: 'select', options: Object.freeze(['keep', '~all', '-all']), default: 'keep' }),
  policy: Object.freeze({ kind: 'select', options: Object.freeze(['none', 'quarantine', 'reject']), default: 'quarantine' }),
  pct: Object.freeze({ kind: 'number', optional: true, min: 1, max: 100 }),
  sp: Object.freeze({ kind: 'select', options: Object.freeze(['keep', 'none', 'quarantine', 'reject']), default: 'keep' }),
  records: Object.freeze({ kind: 'lines' }),
  type: Object.freeze({ kind: 'select', options: FIX_TYPES, default: 'A', literal: true }),
  action: Object.freeze({ kind: 'select', options: Object.freeze(['set', 'add', 'delete']), default: 'set' }),
  values: Object.freeze({ kind: 'lines' }),
  caa: Object.freeze({ kind: 'check', default: true }),
  dkim: Object.freeze({ kind: 'check', default: false }),
  ttl: Object.freeze({ kind: 'ttl', optional: true }),
  zone: Object.freeze({ kind: 'domain', optional: true })
});

/**
 * The templates of the DNS change request, in the order the form lists them. `fields` in form
 * order; `ttl` the default TTL; `needsCurrent`: the change is built from what the names hold now
 * (a live read makes it exact).
 * @type {ReadonlyArray<{ id: string, fields: string[], ttl: number, needsCurrent: boolean }>}
 */
export const CHANGE_TEMPLATES = Object.freeze([
  ['acme-txt', ['name', 'tokens', 'ttl', 'zone'], 300, false],
  ['acme-cname', ['name', 'target', 'ttl', 'zone'], 3600, false],
  ['m365', ['domain', 'mxHost', 'autodiscover', 'tenant', 'dmarc', 'rua', 'ttl', 'zone'], 3600, true],
  ['google', ['domain', 'dkimSelector', 'dkimKey', 'dmarc', 'rua', 'ttl', 'zone'], 3600, true],
  ['caa', ['domain', 'cas', 'wild', 'accountUri', 'methods', 'iodef', 'ttl', 'zone'], 3600, false],
  ['spf', ['domain', 'spfAction', 'includes', 'all', 'ttl', 'zone'], 3600, true],
  ['dmarc', ['domain', 'policy', 'pct', 'rua', 'sp', 'ttl', 'zone'], 3600, true],
  ['ttl', ['domain', 'records', 'ttl', 'zone'], 300, true],
  ['record', ['name', 'type', 'action', 'values', 'ttl', 'zone'], 3600, false],
  ['parked', ['domain', 'caa', 'dkim', 'ttl', 'zone'], 3600, false]
].map(([id, fields, ttl, needsCurrent]) => Object.freeze({ id, fields: Object.freeze(fields), ttl, needsCurrent })));

/** Template ids. */
export const TEMPLATE_IDS = Object.freeze(CHANGE_TEMPLATES.map((t) => t.id));

/**
 * A template by id, or null.
 * @param {string} id
 * @returns {{ id: string, fields: string[], ttl: number, needsCurrent: boolean }|null}
 */
export function changeTemplate(id) {
  return CHANGE_TEMPLATES.find((t) => t.id === id) || null;
}

/**
 * A template's form values with defaults for every field it has (strings, booleans, arrays).
 * @param {string} id
 * @param {Record<string, any>} [input]
 * @returns {Record<string, any>}
 */
export function templateInput(id, input = {}) {
  const tpl = changeTemplate(id);
  const out = {};
  for (const f of tpl ? tpl.fields : []) {
    const def = FIX_FIELDS[f];
    const v = input[f];
    if (def.kind === 'check') out[f] = v === undefined || v === null || v === '' ? !!def.default : v === true || v === '1' || v === 'true' || v === 'on';
    else if (def.kind === 'multi') out[f] = (Array.isArray(v) ? v : typeof v === 'string' ? v.split(',') : [...(def.default || [])]).map((s) => String(s).trim()).filter((s) => def.options.includes(s));
    else if (def.kind === 'select') out[f] = def.options.includes(v) ? v : def.default;
    else out[f] = v === undefined || v === null ? String(def.default ?? '') : String(v);
  }
  return out;
}

/** Lines of a text box: trimmed, no empties, '#' comment lines skipped. */
const linesOf = (text) => String(text ?? '').split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#'));

/** An email address or `mailto:` URI → 'mailto:…', or null. */
export function mailtoUri(input) {
  const s = String(input ?? '').trim().replace(/^mailto:/i, '');
  const m = /^([^\s@,;!]+)@([^\s@,;!]+)$/.exec(s);
  if (!m) return null;
  const host = normalizeHostname(m[2]);
  return host ? `mailto:${m[1]}@${host}` : null;
}

/** An ACME DNS-01 TXT value: base64url of a SHA-256 digest (RFC 8555 §8.4), 43 characters. */
export const ACME_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

/**
 * Build a change request from a template's form.
 * @param {string} id a {@link TEMPLATE_IDS} id
 * @param {Record<string, any>} input the form ({@link templateInput} fills the defaults)
 * @param {{ current?: Record<string, object>|null }} [opts] what a live read found ({@link readCurrent})
 * @returns {ChangeRequest}
 */
export function buildChange(id, input = {}, { current = null } = {}) {
  const tpl = changeTemplate(id);
  if (!tpl) return changeRequest({ zone: null, template: id, problems: [{ severity: 'error', key: 'fix.p.template' }] });
  const form = templateInput(id, input);
  const problems = [];
  const notes = [];
  const ttlRaw = String(form.ttl ?? '').trim();
  const ttl = ttlRaw === '' ? tpl.ttl : Number(ttlRaw);
  if (ttlRaw !== '' && !validTtl(ttlRaw)) problems.push({ severity: 'error', key: 'fix.p.ttl', params: { value: ttlRaw } });

  // The zone: the form's, else the registrable domain of the domain / name.
  const subject = tpl.fields.includes('domain') ? form.domain : form.name;
  const subjectHost = normalizeHostname(String(subject ?? '').trim().replace(/^\*\./, ''), { allowSingleLabel: false });
  let zone = form.zone ? zoneName(form.zone) : null;
  if (form.zone && !zone) problems.push({ severity: 'error', key: 'fix.p.zone', params: { value: form.zone } });
  if (!zone && subjectHost) zone = registrableDomain(subjectHost.replace(/^_[^.]*\./, '')) || null;
  if (!String(subject ?? '').trim()) {
    problems.push({ severity: 'error', key: tpl.fields.includes('domain') ? 'fix.p.domain-missing' : 'fix.p.name-missing' });
    return changeRequest({ zone, template: id, problems });
  }
  if (!zone) {
    problems.push({ severity: 'error', key: 'fix.p.zone', params: { value: String(subject) } });
    return changeRequest({ zone: null, template: id, problems });
  }
  let domain = null;
  if (tpl.fields.includes('domain')) {
    const abs = absoluteName(form.domain, zone, { wildcard: false });
    domain = abs.name;
    if (!domain || domain.includes('_')) {
      problems.push({ severity: 'error', key: abs.error === 'outside' ? 'fix.p.outside' : 'fix.p.domain', params: { value: form.domain, zone } });
      return changeRequest({ zone, template: id, problems });
    }
  }
  // What the template looks at in the current state is what a live read must ask too.
  const asked = [];
  const cur = (name, type) => {
    if (!asked.some((q) => q.name === name && q.type === type)) asked.push({ name, type });
    return current ? current[`${name}|${type}`] || null : null;
  };
  const ctx = { form, zone, domain, ttl, problems, notes, cur, current };
  const rrsets = TEMPLATE_BUILDERS[id](ctx) || [];
  const req = changeRequest({ zone, template: id, rrsets, notes, problems });
  for (const q of asked) if (!req.reads.some((x) => x.name === q.name && x.type === q.type)) req.reads.push(q);
  return current ? applyCurrent(req, current) : req;
}

/** The current SPF record(s) of a name from a live read: `null` when not read or not answered. */
function currentFamily(ctx, name, family) {
  const c = ctx.cur(name, 'TXT');
  if (!c || c.status === 'error') return null;
  return c.values.filter((v) => txtFamily(v) === family).map(txtText);
}

/** A name in the zone from a form field (or `value`, the field's text as a template reads it), or null with a problem. */
function formName(ctx, field, { wildcard = false, value = ctx.form[field] } = {}) {
  const abs = absoluteName(value, ctx.zone, { wildcard });
  if (!abs.name) ctx.problems.push({ severity: 'error', key: abs.error === 'outside' ? 'fix.p.outside' : 'fix.p.name', params: { value: ctx.form[field], zone: ctx.zone } });
  return abs.name;
}

/**
 * The certificate name of an ACME template. The record name an ACME client prints
 * (`_acme-challenge.example.com`) is taken for the name it validates, with a word that says so:
 * the record goes at `_acme-challenge.<name>`, never at a doubled label.
 */
function acmeName(ctx) {
  const raw = String(ctx.form.name ?? '').trim();
  const bare = raw.replace(/^_acme-challenge\./i, '');
  const name = formName(ctx, 'name', { wildcard: true, value: bare });
  if (name && bare !== raw) ctx.problems.push({ severity: 'info', key: 'fix.p.acme-name', params: { value: raw, name: `_acme-challenge.${name.replace(/^\*\./, '')}` } });
  return name;
}

/** The SPF set of a template: `include:` added to the current record (after a read) or a new record. */
function spfWithInclude(ctx, include, all) {
  const current = currentFamily(ctx, ctx.domain, 'spf1');
  if (current && current.length > 1) {
    ctx.problems.push({ severity: 'error', key: 'fix.p.spf-multiple', params: { name: ctx.domain, count: current.length } });
    return null;
  }
  if (current && current.length === 1) {
    const edit = editSpf(current[0], { add: [include] });
    if (edit.present.length) ctx.notes.push({ key: 'fix.n.spf-present', params: { include } });
    return { name: ctx.domain, type: 'TXT', ttl: ctx.ttl, mode: 'is', family: 'spf1', values: [edit.record] };
  }
  if (!current) ctx.notes.push({ key: 'fix.n.spf-unread', params: { include, name: ctx.domain } });
  return { name: ctx.domain, type: 'TXT', ttl: ctx.ttl, mode: 'is', family: 'spf1', values: [`v=spf1 include:${include} ${all}`] };
}

/**
 * Does an SPF record let a server send as the domain: any term but a failing `all` (`-all`,
 * `~all`) and `exp=`? A `?all` or `+all`, a mechanism, a `redirect=` all do.
 */
function spfSends(record) {
  return String(record ?? '').trim().split(/\s+/).slice(1).some((tok) => !/^[-~]all$/i.test(tok) && !/^exp=/i.test(tok));
}

/** A p=none DMARC record to start with, unless a read found one. */
function dmarcStart(ctx) {
  if (!ctx.form.dmarc) return null;
  const name = `_dmarc.${ctx.domain}`;
  const existing = currentFamily(ctx, name, 'dmarc1');
  if (existing && existing.length) {
    ctx.notes.push({ key: 'fix.n.dmarc-kept', params: { name } });
    return null;
  }
  const rua = ruaOf(ctx);
  // Not read: a DMARC record there (a stricter policy, its report addresses) must stay.
  if (!existing) ctx.notes.push({ key: 'fix.n.dmarc-first-unread', params: { name } });
  ctx.notes.push({ key: 'fix.n.dmarc-start' });
  return { name, type: 'TXT', ttl: ctx.ttl, mode: 'is', family: 'dmarc1', values: [editDmarc(null, { p: 'none', rua })] };
}

function ruaOf(ctx) {
  if (!String(ctx.form.rua ?? '').trim()) return null;
  const uri = mailtoUri(ctx.form.rua);
  if (!uri) ctx.problems.push({ severity: 'error', key: 'fix.p.email', params: { value: ctx.form.rua } });
  return uri;
}

/** Microsoft's MX host of a domain: its name with dots as dashes under mail.protection.outlook.com. */
export function m365MxHost(domain) {
  return `${canon(domain).replace(/\./g, '-')}.mail.protection.outlook.com`;
}

/** One value line of the plain-record template, or null. */
function recordValue(type, line) {
  const s = line.trim();
  if (type === 'TXT') {
    if (/^".*"$/.test(s)) {
      const parsed = parseValueText('TXT', s, 'example.com');
      if (parsed) return parsed;
    }
    return normalizeValue('TXT', s);
  }
  if (type === 'MX') {
    const m = /^(?:(\d{1,5})\s+)?(\S+)$/.exec(s);
    return m ? normalizeValue('MX', { preference: m[1] === undefined ? 10 : Number(m[1]), exchange: m[2] }) : null;
  }
  if (type === 'CAA') {
    const m = /^(?:(\d{1,3})\s+)?([a-z0-9]+)\s+"?(.*?)"?$/i.exec(s);
    return m ? normalizeValue('CAA', { flags: m[1] === undefined ? 0 : Number(m[1]), tag: m[2], value: m[3] }) : null;
  }
  return normalizeValue(type, s);
}

const TEMPLATE_BUILDERS = {
  'acme-txt'(ctx) {
    const name = acmeName(ctx);
    if (!name) return [];
    const base = name.replace(/^\*\./, '');
    const owner = `_acme-challenge.${base}`;
    const tokens = linesOf(ctx.form.tokens).map((s) => s.replace(/^"|"$/g, ''));
    if (!tokens.length) ctx.problems.push({ severity: 'error', key: 'fix.p.tokens-missing' });
    const odd = tokens.filter((tk) => !ACME_TOKEN_RE.test(tk));
    if (odd.length) ctx.problems.push({ severity: 'warn', key: 'fix.p.token-format', params: { values: odd.slice(0, 3).join(', ') } });
    const alias = ctx.cur(owner, 'CNAME');
    const cname = alias && alias.status === 'ok' && alias.values.length ? alias.values[0] : null;
    if (cname) ctx.problems.push({ severity: 'error', key: 'fix.p.acme-delegated', params: { name: owner, target: cname } });
    ctx.notes.push({ key: 'fix.n.acme-remove', params: { name: owner } });
    if (name.startsWith('*.')) ctx.notes.push({ key: 'fix.n.acme-wildcard', params: { name: owner } });
    return [{ name: owner, type: 'TXT', ttl: ctx.ttl, mode: 'has', family: null, values: tokens }];
  },

  'acme-cname'(ctx) {
    const name = acmeName(ctx);
    const target = normalizeValue('CNAME', ctx.form.target);
    if (!String(ctx.form.target ?? '').trim()) ctx.problems.push({ severity: 'error', key: 'fix.p.target-missing' });
    else if (!target) ctx.problems.push({ severity: 'error', key: 'fix.p.host', params: { value: ctx.form.target } });
    if (!name || !target) return [];
    const owner = `_acme-challenge.${name.replace(/^\*\./, '')}`;
    ctx.notes.push({ key: 'fix.n.acme-cname', params: { name: owner, target } });
    return [{ name: owner, type: 'CNAME', ttl: ctx.ttl, mode: 'is', values: [target] }];
  },

  m365(ctx) {
    const d = ctx.domain;
    const mxHost = String(ctx.form.mxHost ?? '').trim() ? normalizeValue('CNAME', ctx.form.mxHost) : m365MxHost(d);
    if (!mxHost) ctx.problems.push({ severity: 'error', key: 'fix.p.host', params: { value: ctx.form.mxHost } });
    if (!String(ctx.form.mxHost ?? '').trim()) ctx.notes.push({ key: 'fix.n.m365-mx', params: { host: mxHost } });
    const sets = [];
    if (mxHost) sets.push({ name: d, type: 'MX', ttl: ctx.ttl, mode: 'is', values: [{ preference: 0, exchange: mxHost }] });
    const spf = spfWithInclude(ctx, 'spf.protection.outlook.com', '-all');
    if (spf) sets.push(spf);
    if (ctx.form.autodiscover) sets.push({ name: `autodiscover.${d}`, type: 'CNAME', ttl: ctx.ttl, mode: 'is', values: ['autodiscover.outlook.com'] });
    if (String(ctx.form.tenant ?? '').trim()) {
      const tenant = normalizeValue('CNAME', ctx.form.tenant);
      if (!tenant) ctx.problems.push({ severity: 'error', key: 'fix.p.host', params: { value: ctx.form.tenant } });
      else {
        const key = d.replace(/\./g, '-');
        for (const s of ['selector1', 'selector2']) {
          sets.push({ name: `${s}._domainkey.${d}`, type: 'CNAME', ttl: ctx.ttl, mode: 'is', values: [`${s}-${key}._domainkey.${tenant}`] });
        }
        ctx.notes.push({ key: 'fix.n.m365-dkim' });
      }
    }
    const dmarc = dmarcStart(ctx);
    if (dmarc) sets.push(dmarc);
    return sets;
  },

  google(ctx) {
    const d = ctx.domain;
    const sets = [{ name: d, type: 'MX', ttl: ctx.ttl, mode: 'is', values: [{ preference: 1, exchange: 'smtp.google.com' }] }];
    ctx.notes.push({ key: 'fix.n.google-mx' });
    const spf = spfWithInclude(ctx, '_spf.google.com', '~all');
    if (spf) sets.push(spf);
    const key = String(ctx.form.dkimKey ?? '').replace(/\s+/g, ' ').trim().replace(/^"|"$/g, '');
    if (key) {
      const selector = String(ctx.form.dkimSelector || 'google').trim().toLowerCase();
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(selector)) ctx.problems.push({ severity: 'error', key: 'fix.p.selector', params: { value: selector } });
      else if (!/^v=DKIM1\b/i.test(key) || !/\bp=[A-Za-z0-9+/=]{16,}/.test(key.replace(/\s+/g, ''))) {
        ctx.problems.push({ severity: 'error', key: 'fix.p.dkim-key' });
      } else {
        sets.push({ name: `${selector}._domainkey.${d}`, type: 'TXT', ttl: ctx.ttl, mode: 'is', family: 'dkim1', values: [key.replace(/;\s*/g, '; ').replace(/\s+/g, ' ')] });
      }
    } else {
      ctx.notes.push({ key: 'fix.n.google-dkim' });
    }
    const dmarc = dmarcStart(ctx);
    if (dmarc) sets.push(dmarc);
    return sets;
  },

  caa(ctx) {
    const cas = ctx.form.cas.map((id) => FIX_CAS.find((c) => c.id === id)).filter(Boolean);
    const params = [];
    const acct = String(ctx.form.accountUri ?? '').trim();
    if (acct) {
      if (cas.length !== 1) ctx.problems.push({ severity: 'error', key: 'fix.p.accounturi-one' });
      else if (!/^https:\/\/\S+$/.test(acct)) ctx.problems.push({ severity: 'error', key: 'fix.p.accounturi', params: { value: acct } });
      else params.push(`accounturi=${acct}`);
    }
    if (ctx.form.methods.length) params.push(`validationmethods=${ctx.form.methods.join(',')}`);
    const issuers = uniqBy(cas, (c) => c.caa).map((c) => (params.length ? `${c.caa}; ${params.join('; ')}` : c.caa));
    const values = issuers.map((v) => ({ flags: 0, tag: 'issue', value: v }));
    if (!cas.length) {
      values.push({ flags: 0, tag: 'issue', value: ';' });
      ctx.problems.push({ severity: 'warn', key: 'fix.p.caa-none' });
    }
    if (ctx.form.wild === 'none') values.push({ flags: 0, tag: 'issuewild', value: ';' });
    else if (ctx.form.wild === 'same' && cas.length) values.push(...issuers.map((v) => ({ flags: 0, tag: 'issuewild', value: v })));
    if (String(ctx.form.iodef ?? '').trim()) {
      const uri = mailtoUri(ctx.form.iodef);
      if (!uri) ctx.problems.push({ severity: 'error', key: 'fix.p.email', params: { value: ctx.form.iodef } });
      else values.push({ flags: 0, tag: 'iodef', value: uri });
    }
    if (ctx.form.methods.length && !ctx.form.methods.includes('dns-01') && ctx.form.wild !== 'none') {
      ctx.notes.push({ key: 'fix.n.caa-wildcard-dns01' });
    }
    ctx.notes.push({ key: 'fix.n.caa-tree', params: { name: ctx.domain } });
    return [{ name: ctx.domain, type: 'CAA', ttl: ctx.ttl, mode: 'is', values }];
  },

  spf(ctx) {
    const includes = linesOf(ctx.form.includes).flatMap((l) => l.split(/[\s,]+/)).map((s) => s.replace(/^include:/i, '').toLowerCase()).filter(Boolean);
    const bad = includes.filter((d) => !normalizeHostname(d));
    if (!includes.length) ctx.problems.push({ severity: 'error', key: 'fix.p.includes-missing' });
    if (bad.length) {
      ctx.problems.push({ severity: 'error', key: 'fix.p.host', params: { value: bad.join(', ') } });
      includes.splice(0, includes.length, ...includes.filter((d) => !bad.includes(d)));
    }
    const all = ctx.form.all === 'keep' ? null : ctx.form.all;
    const current = currentFamily(ctx, ctx.domain, 'spf1');
    // An include is removed from the record there now: written without it, the record would drop every other sender.
    if (!current && ctx.form.spfAction === 'remove') {
      ctx.problems.push({ severity: 'error', key: 'fix.p.spf-remove-read', params: { name: ctx.domain } });
      return [];
    }
    if (!current) ctx.problems.push({ severity: 'warn', key: 'fix.p.read-first' });
    if (current && current.length > 1) {
      ctx.problems.push({ severity: 'error', key: 'fix.p.spf-multiple', params: { name: ctx.domain, count: current.length } });
      return [];
    }
    const now = current && current.length ? current[0] : null;
    if (ctx.form.spfAction === 'remove' && current && !now) {
      ctx.problems.push({ severity: 'error', key: 'fix.p.spf-none', params: { name: ctx.domain } });
      return [];
    }
    const edit = ctx.form.spfAction === 'remove'
      ? editSpf(now || 'v=spf1 ~all', { remove: includes, all })
      : editSpf(now || `v=spf1 ${all || '~all'}`, { add: includes, all });
    if (edit.missing.length && now) ctx.problems.push({ severity: 'warn', key: 'fix.p.include-absent', params: { values: edit.missing.join(', ') } });
    if (edit.present.length) ctx.notes.push({ key: 'fix.n.spf-present', params: { include: edit.present.join(', ') } });
    // Not read: whether there is a record to add to is not known, and the instructions say so.
    if (!current && includes.length) ctx.notes.push({ key: 'fix.n.spf-unread', params: { include: includes.join(' include:'), name: ctx.domain } });
    else if (current && !now) ctx.notes.push({ key: 'fix.n.spf-new' });
    const parsed = parseSpf(edit.record);
    for (const e of parsed.errors) ctx.problems.push({ severity: 'error', key: 'fix.p.spf-syntax', params: { token: e.token } });
    return [{ name: ctx.domain, type: 'TXT', ttl: ctx.ttl, mode: 'is', family: 'spf1', values: [edit.record] }];
  },

  dmarc(ctx) {
    const name = `_dmarc.${ctx.domain}`;
    const current = currentFamily(ctx, name, 'dmarc1');
    if (!current) ctx.problems.push({ severity: 'warn', key: 'fix.p.read-first' });
    if (current && current.length > 1) {
      ctx.problems.push({ severity: 'error', key: 'fix.p.dmarc-multiple', params: { name, count: current.length } });
      return [];
    }
    const now = current && current.length ? current[0] : null;
    // pct: empty keeps the record's own (none: all of it), 100 removes it.
    const pctRaw = String(ctx.form.pct ?? '').trim();
    const set = { p: ctx.form.policy };
    if (pctRaw) {
      const n = Number(pctRaw);
      if (!Number.isInteger(n) || n < 1 || n > 100) ctx.problems.push({ severity: 'error', key: 'fix.p.pct', params: { value: pctRaw } });
      else set.pct = n < 100 ? String(n) : null;
    }
    const rua = ruaOf(ctx);
    if (rua) set.rua = rua;
    if (ctx.form.sp !== 'keep') set.sp = ctx.form.sp === ctx.form.policy ? null : ctx.form.sp;
    const record = editDmarc(now, set);
    const parsed = parseDmarc(record);
    for (const e of parsed.errors) ctx.problems.push({ severity: 'error', key: 'fix.p.dmarc-syntax', params: { token: e.token } });
    if (!parsed.rua.length) ctx.problems.push({ severity: 'warn', key: 'fix.p.dmarc-no-rua' });
    const parsedNow = now ? parseDmarc(now) : null;
    const before = parsedNow ? parsedNow.policy : null;
    // Not read: the value holds only what the form sets, and the policy it replaces is not known.
    if (!current) ctx.notes.push({ key: 'fix.n.dmarc-unread', params: { name } });
    // What steps up gets a note: the policy (not when it stays), and a subdomain policy the form sets.
    if (ctx.form.policy === 'none') ctx.notes.push({ key: 'fix.n.dmarc-start' });
    else if (!current) ctx.notes.push({ key: 'fix.n.dmarc-to', params: { to: ctx.form.policy } });
    else if (before !== ctx.form.policy) ctx.notes.push({ key: 'fix.n.dmarc-step', params: { from: before || 'none', to: ctx.form.policy } });
    if (parsedNow && ctx.form.sp !== 'keep' && parsed.subdomainPolicy && parsed.subdomainPolicy !== parsedNow.subdomainPolicy) {
      ctx.notes.push({ key: 'fix.n.dmarc-sp', params: { from: parsedNow.subdomainPolicy || 'none', to: parsed.subdomainPolicy } });
    }
    return [{ name, type: 'TXT', ttl: ctx.ttl, mode: 'is', family: 'dmarc1', values: [record] }];
  },

  ttl(ctx) {
    const lines = linesOf(ctx.form.records);
    if (!lines.length) ctx.problems.push({ severity: 'error', key: 'fix.p.records-missing' });
    const sets = [];
    let unread = false;
    for (const line of lines) {
      const m = /^(\S+)\s+([A-Za-z]+)$/.exec(line);
      const type = m ? m[2].toUpperCase() : '';
      const abs = m ? absoluteName(m[1], ctx.zone) : { name: null };
      if (!m || !FIX_TYPES.includes(type) || !abs.name) {
        ctx.problems.push({ severity: 'error', key: 'fix.p.ttl-line', params: { value: line } });
        continue;
      }
      const c = ctx.cur(abs.name, type);
      if (!c || c.status === 'error') unread = true;
      else if (!c.values.length) ctx.problems.push({ severity: 'error', key: 'fix.p.ttl-empty', params: { name: abs.name, type } });
      else {
        if (c.ttl !== null && c.ttl <= ctx.ttl) ctx.problems.push({ severity: 'info', key: 'fix.p.ttl-already', params: { name: abs.name, type, ttl: c.ttl } });
        sets.push({ name: abs.name, type, ttl: ctx.ttl, mode: 'is', family: null, values: c.values, before: c.values, beforeTtl: c.ttl, maxTtl: ctx.ttl });
      }
    }
    if (unread && lines.length) ctx.problems.push({ severity: 'error', key: 'fix.p.ttl-read' });
    const old = sets.map((s) => s.beforeTtl).filter(Number.isFinite);
    if (old.length) ctx.notes.push({ key: 'fix.n.ttl-wait', params: { ttl: Math.max(...old) } });
    return sets;
  },

  record(ctx) {
    const type = ctx.form.type;
    const name = formName(ctx, 'name', { wildcard: true });
    const mode = ctx.form.action === 'delete' ? 'none' : ctx.form.action === 'add' ? 'has' : 'is';
    const values = [];
    for (const line of mode === 'none' ? [] : linesOf(ctx.form.values)) {
      const v = recordValue(type, line);
      if (v === null) ctx.problems.push({ severity: 'error', key: 'fix.p.value', params: { type, value: line } });
      else values.push(v);
    }
    if (mode !== 'none' && !values.length && !ctx.problems.some((p) => p.key === 'fix.p.value')) ctx.problems.push({ severity: 'error', key: 'fix.p.values-missing' });
    if (type === 'CNAME' && values.length > 1) ctx.problems.push({ severity: 'error', key: 'fix.p.cname-one' });
    if (type === 'CNAME' && mode === 'has') ctx.problems.push({ severity: 'error', key: 'fix.p.cname-add' });
    if (!name) return [];
    return [{ name, type, ttl: ctx.ttl, mode, family: type === 'TXT' ? familyOf('TXT', values) : null, values }];
  },

  parked(ctx) {
    const d = ctx.domain;
    const mx = ctx.cur(d, 'MX');
    if (mx && mx.status === 'ok' && mx.values.some((v) => v.exchange)) ctx.problems.push({ severity: 'warn', key: 'fix.p.parked-mail', params: { name: d } });
    // Mail sent as the domain (a send-only domain has no MX): -all and p=reject would fail all of it.
    const sending = (currentFamily(ctx, d, 'spf1') || []).filter(spfSends);
    if (sending.length) ctx.problems.push({ severity: 'warn', key: 'fix.p.parked-sends', params: { name: d, record: sending[0] } });
    // A DMARC record there keeps its report addresses: the spoofing reports of a parked domain are worth reading.
    const dmarcNow = currentFamily(ctx, `_dmarc.${d}`, 'dmarc1');
    const dmarc = dmarcNow && dmarcNow.length === 1 ? editDmarc(dmarcNow[0], { p: 'reject', sp: null, pct: null }) : 'v=DMARC1; p=reject';
    const sets = [
      { name: d, type: 'MX', ttl: ctx.ttl, mode: 'is', values: [{ preference: 0, exchange: '' }] },
      { name: d, type: 'TXT', ttl: ctx.ttl, mode: 'is', family: 'spf1', values: ['v=spf1 -all'] },
      { name: `_dmarc.${d}`, type: 'TXT', ttl: ctx.ttl, mode: 'is', family: 'dmarc1', values: [dmarc] }
    ];
    if (ctx.form.caa) sets.push({ name: d, type: 'CAA', ttl: ctx.ttl, mode: 'is', values: [{ flags: 0, tag: 'issue', value: ';' }] });
    if (ctx.form.dkim) sets.push({ name: `*._domainkey.${d}`, type: 'TXT', ttl: ctx.ttl, mode: 'is', family: 'dkim1', values: ['v=DKIM1; p='] });
    ctx.notes.push({ key: ctx.form.caa ? 'fix.n.parked' : 'fix.n.parked-mail' });
    return sets;
  }
};

/* ------------------------------------------------------------------------ */
/* Fixes of Domain Health checks and Zone File findings                     */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} Fix
 * @property {string} id the check id or lint code
 * @property {'records'|'advice'} kind
 * @property {ChangeRequest|null} request the records (kind 'records')
 * @property {string|null} template the change builder's template and form that make the same change
 * @property {Record<string, any>|null} input
 * @property {FixText[]} advice what to do (kind 'advice'; with records: what else to know)
 * @property {boolean} needsCt the records need the CAs of the domain's certificates (Certificate Transparency, on a click)
 */

const fix = (id, kind, { request = null, template = null, input = null, advice = [], needsCt = false } = {}) => ({ id, kind, request, template, input, advice, needsCt });

/**
 * What a Domain Health report says the names hold now, as a live read would: the TXT and MX of
 * the domain, the CAA set that applies to it (where the climb up the tree found it; none at the
 * names in between), the DMARC record of `_dmarc.<domain>` and, for an inherited policy, the
 * organizational domain's record it uses — where their lookups did not fail.
 * @param {object} report a lib/health.js domainHealth report
 * @returns {Record<string, object>} {@link readCurrent} shape
 */
export function currentFromReport(report) {
  const d = report.domain;
  const failed = (k) => arr(report.failedLookups).includes(k);
  const out = {};
  const entry = (values) => ({ status: 'ok', values, ttl: null, cname: null });
  if (!failed('txt')) out[`${d}|TXT`] = entry(arr(report.records.txt).map((s) => txtChunks(String(s))));
  if (!failed('mx')) out[`${d}|MX`] = entry(arr(report.records.mx).map((m) => normalizeValue('MX', m)).filter(Boolean));
  if (!arr(report.checks).some((c) => c.id === 'caa.error')) {
    const at = caaAt(report) || d;
    out[`${at}|CAA`] = entry(arr(report.records.caa).map((c) => normalizeValue('CAA', c)).filter(Boolean));
    if (at !== d) out[`${d}|CAA`] = entry([]);
  }
  if (!arr(report.checks).some((c) => c.id === 'dmarc.error')) {
    const dm = report.dmarc || {};
    out[`_dmarc.${d}|TXT`] = entry(dm.record && !dm.inherited ? [txtChunks(dm.record)] : []);
    if (dm.record && dm.inherited && dm.foundAt) out[`_dmarc.${canon(dm.foundAt)}|TXT`] = entry([txtChunks(dm.record)]);
  }
  for (const v of Object.values(out)) if (!v.values.length) v.status = 'nodata';
  return out;
}

/** The name whose CAA set applies to a report's domain (RFC 8659 §3: the domain or a parent), or null. */
const caaAt = (report) => (report.caa && report.caa.foundAt ? canon(report.caa.foundAt) : null);

/** The zone a name of a report lives in: the report's SOA zone when that holds the name, else the name's registrable domain. */
function zoneFor(report, name) {
  return report.zone && (name === report.zone || isSubdomainOf(name, report.zone)) ? report.zone : registrableDomain(name) || name;
}

/**
 * A record fix built from a template over what the report read, in the zone of `input.domain`
 * (the report's domain unless a fix edits a record of a parent, e.g. an inherited DMARC policy).
 */
function reportFix(id, report, template, input, extra = {}) {
  const domain = input.domain || report.domain;
  const zone = zoneFor(report, domain);
  const full = { domain, zone: zone === registrableDomain(domain) ? '' : zone, ...input };
  const request = buildChange(template, full, { current: currentFromReport(report) });
  return fix(id, 'records', { request, template, input: full, ...extra });
}

/** The policy tags of the DMARC record a report found, for a fix that leaves them as they are. */
function dmarcKept(report) {
  const parsed = report.dmarc && report.dmarc.parsed;
  return { policy: (parsed && parsed.policy) || 'none', pct: parsed && parsed.pct < 100 ? String(parsed.pct) : '' };
}

/**
 * A DMARC fix: of the domain's own record, or — a policy inherited from the organizational domain
 * (RFC 7489 §6.6.3) — of that record, where the policy comes from; the advice says which.
 */
function dmarcFix(id, report, input, advice = []) {
  const dm = report.dmarc || {};
  if (!(dm.inherited && dm.foundAt)) return reportFix(id, report, 'dmarc', input, { advice });
  const org = canon(dm.foundAt);
  return reportFix(id, report, 'dmarc', { ...input, domain: org }, {
    advice: [{ key: 'fix.a.dmarc-inherited', params: { domain: report.domain, name: `_dmarc.${org}`, org } }, ...advice]
  });
}

/** A record fix of one TXT family value at the domain (an SPF record rewritten), as the plain-record template. */
function spfRecordFix(id, report, record) {
  return reportFix(id, report, 'record', { name: report.domain, type: 'TXT', action: 'set', values: record });
}

const MAIL_PLATFORM_SPF = [
  { mx: ['mail.protection.outlook.com', 'mx.microsoft'], include: 'spf.protection.outlook.com', all: '-all' },
  { mx: ['aspmx.l.google.com', 'googlemail.com', 'smtp.google.com'], include: '_spf.google.com', all: '~all' }
];

/** The SPF include of the domain's mail platform (Microsoft 365, Google Workspace), from its MX hosts. */
function platformSpf(report) {
  const hosts = arr(report.records.mx).map((m) => canon(m.exchange)).filter(Boolean);
  if (!hosts.length) return null;
  const hit = MAIL_PLATFORM_SPF.find((p) => hosts.every((h) => p.mx.some((s) => h === s || h.endsWith(`.${s}`))));
  return hit || null;
}

/** The includes that cost the most lookups in an SPF tree (for the flattening advice). */
function costliestIncludes(report, max = 4) {
  const tree = report.spf && report.spf.lookups && report.spf.lookups.tree;
  const terms = tree && Array.isArray(tree.terms) ? tree.terms : [];
  return terms.filter((t) => t && t.child && t.target && typeof t.child.count === 'number')
    .map((t) => ({ target: t.target, cost: 1 + t.child.count })).sort((a, b) => b.cost - a.cost).slice(0, max)
    .map((x) => `${x.target} (${x.cost})`).join(', ');
}

/**
 * Domain Health checks with a fix, and how it is made. The views keep a copy of the ids (they
 * load this module on the first "Show the fix"); a unit test keeps them equal.
 */
const HEALTH_FIXES = {
  'dmarc.missing': (r) => reportFix('dmarc.missing', r, 'dmarc', { policy: 'none', rua: `dmarc-reports@${registrableDomain(r.domain) || r.domain}` },
    { advice: [{ key: 'fix.a.rua-mailbox', params: { address: `dmarc-reports@${registrableDomain(r.domain) || r.domain}` } }] }),
  // Inherited, the policy that is none is the organizational record's subdomain policy: that steps up, p stays.
  'dmarc.policy-none': (r) => dmarcFix('dmarc.policy-none', r, r.dmarc && r.dmarc.inherited ? { ...dmarcKept(r), sp: 'quarantine' } : { ...dmarcKept(r), policy: 'quarantine' }),
  'dmarc.pct': (r) => dmarcFix('dmarc.pct', r, { ...dmarcKept(r), pct: '100' }),
  'dmarc.sp-none': (r) => {
    const kept = dmarcKept(r);
    return dmarcFix('dmarc.sp-none', r, { ...kept, sp: kept.policy });
  },
  'dmarc.rua-missing': (r) => {
    const address = `dmarc-reports@${registrableDomain(r.domain) || r.domain}`;
    return dmarcFix('dmarc.rua-missing', r, { ...dmarcKept(r), rua: address }, [{ key: 'fix.a.rua-mailbox', params: { address } }]);
  },
  'dmarc.multiple': () => fix('dmarc.multiple', 'advice', { advice: [{ key: 'fix.a.dmarc-multiple' }] }),
  'spf.missing': (r) => {
    const noMail = !arr(r.records.mx).length || arr(r.records.mx).every((m) => !canon(m.exchange));
    if (noMail && !arr(r.failedLookups).includes('mx')) return { ...spfRecordFix('spf.missing', r, 'v=spf1 -all'), advice: [{ key: 'fix.a.spf-no-mail' }] };
    const platform = platformSpf(r);
    if (platform) return reportFix('spf.missing', r, 'spf', { spfAction: 'add', includes: platform.include, all: platform.all });
    return fix('spf.missing', 'advice', { advice: [{ key: 'fix.a.spf-senders', params: { domain: r.domain } }] });
  },
  'spf.null-mx': (r) => spfRecordFix('spf.null-mx', r, 'v=spf1 -all'),
  'spf.all-pass': (r) => spfAllFix('spf.all-pass', r),
  'spf.all-neutral': (r) => spfAllFix('spf.all-neutral', r),
  'spf.all-missing': (r) => spfAllFix('spf.all-missing', r),
  'spf.ptr': (r) => spfTermsFix('spf.ptr', r, (t) => t.mechanism !== 'ptr'),
  'spf.after-all': (r) => spfTermsFix('spf.after-all', r, (t, i, all) => all < 0 || i <= all),
  'spf.redirect-ignored': (r) => {
    const rec = r.spf && r.spf.record;
    if (!rec) return null;
    return spfRecordFix('spf.redirect-ignored', r, rec.split(/\s+/).filter((tok) => !/^redirect=/i.test(tok)).join(' '));
  },
  'spf.multiple': (r) => {
    const spfs = arr(r.records.txt).filter((s) => txtFamily(s) === 'spf1');
    if (spfs.length < 2) return fix('spf.multiple', 'advice', { advice: [{ key: 'fix.a.spf-merge' }] });
    return fix('spf.multiple', 'records', {
      ...spfRecordFix('spf.multiple', r, mergeSpf(spfs)),
      advice: [{ key: 'fix.a.spf-merged' }]
    });
  },
  'spf.lookups-exceeded': (r) => fix('spf.lookups-exceeded', 'advice', { advice: [{ key: 'fix.a.spf-flatten', params: { includes: costliestIncludes(r) || '—' } }] }),
  'spf.lookups-high': (r) => fix('spf.lookups-high', 'advice', { advice: [{ key: 'fix.a.spf-flatten', params: { includes: costliestIncludes(r) || '—' } }] }),
  'mx.none': (r) => {
    // A send-only domain has no MX either: its SPF record lets servers send, and the lock-down would fail all of that mail.
    const sends = arr(r.records.txt).filter((x) => txtFamily(x) === 'spf1' && spfSends(x));
    if (sends.length) return fix('mx.none', 'advice', { advice: [{ key: 'fix.a.no-mx-sends', params: { record: sends[0] } }] });
    return reportFix('mx.none', r, 'parked', { caa: false }, { advice: [{ key: 'fix.a.no-mail' }] });
  },
  'mx.null-mixed': () => fix('mx.null-mixed', 'advice', { advice: [{ key: 'fix.a.null-mixed' }] }),
  'caa.missing': (r) => reportFix('caa.missing', r, 'caa', { cas: [] }, { needsCt: true }),
  'caa.cert-denied': (r, check) => {
    // The current certificate's CA joins the property that decided (issuewild for a wildcard when there is one); the listed CAs stay.
    const cert = r.caaCert || {};
    const ids = arr(cert.issuerDomains).map(canon).filter(Boolean);
    if (!ids.length) return null;
    const known = FIX_CAS.find((c) => ids.includes(c.caa));
    const add = { flags: 0, tag: cert.property === 'issuewild' ? 'issuewild' : 'issue', value: known ? known.caa : ids[0] };
    const issuer = (check && check.params && check.params.issuer) || add.value;
    return caaSetFix('caa.cert-denied', r, (values) => [...values, add], [{ key: 'fix.a.caa-cert', params: { issuer, value: add.value, property: add.tag } }]);
  },
  'caa.critical-unknown': (r) => {
    const tags = uniqBy(arr(r.caa && r.caa.parsed && r.caa.parsed.unknown).filter((u) => u && u.critical).map((u) => String(u.tag).toLowerCase()), (x) => x);
    if (!tags.length) return null;
    // Only the critical flag goes (as the Zone File's CAA_FLAGS fix): the tag stays, a CA that does not know it ignores it.
    return caaSetFix('caa.critical-unknown', r, (values) => values.map((v) => (tags.includes(v.tag) && v.flags & 128 ? { ...v, flags: 0 } : v)),
      [{ key: 'fix.a.caa-critical', params: { tags: tags.join(', ') } }]);
  },
  'tls-rpt.missing': (r) => {
    const address = `tls-reports@${registrableDomain(r.domain) || r.domain}`;
    return fix('tls-rpt.missing', 'records', {
      ...reportFix('tls-rpt.missing', r, 'record', { name: `_smtp._tls.${r.domain}`, type: 'TXT', action: 'set', values: `v=TLSRPTv1; rua=mailto:${address}` }),
      advice: [{ key: 'fix.a.rua-mailbox', params: { address } }]
    });
  }
};

/**
 * A fix of the CAA set that applies to the report's domain, at the name it was found (the domain
 * or a parent): exact, since the report read the whole set; the plain-record template edits it.
 */
function caaSetFix(id, r, edit, advice) {
  const at = caaAt(r);
  const before = arr(r.records.caa).map((c) => normalizeValue('CAA', c)).filter(Boolean);
  if (!at || !before.length) return null;
  const values = edit(before);
  const zone = zoneFor(r, at);
  const request = changeRequest({ zone, rrsets: [{ name: at, type: 'CAA', ttl: DEFAULT_TTL, mode: 'is', values, before }] });
  const input = { name: at, type: 'CAA', action: 'set', values: values.map((v) => valueText('CAA', v)).join('\n'), zone: zone === registrableDomain(at) ? '' : zone };
  const where = at === r.domain ? [] : [{ key: 'fix.a.caa-at', params: { domain: r.domain, name: at } }];
  return fix(id, 'records', { request, template: 'record', input, advice: [...where, ...advice] });
}

function spfAllFix(id, r) {
  const rec = r.spf && r.spf.record;
  if (!rec) return null;
  return spfRecordFix(id, r, editSpf(rec, { all: '~all' }).record);
}

function spfTermsFix(id, r, keep) {
  const rec = r.spf && r.spf.record;
  const parsed = r.spf && r.spf.parsed;
  if (!rec || !parsed) return null;
  const kept = parsed.terms.filter((t, i) => keep(t, i, parsed.allIndex)).map((t) => t.raw);
  // Modifiers stay (exp= and unknown ones), except a redirect= an `all` makes void (RFC 7208 §6.1).
  const mods = rec.split(/\s+/).filter((tok) => /^[a-z][a-z0-9_.-]*=/i.test(tok) && !/^v=/i.test(tok) && !(parsed.allIndex >= 0 && /^redirect=/i.test(tok)));
  return spfRecordFix(id, r, ['v=spf1', ...kept, ...mods].join(' '));
}

/** Domain Health check ids that have a fix. */
export const HEALTH_FIX_IDS = Object.freeze(Object.keys(HEALTH_FIXES).sort());

/**
 * The fix of one Domain Health check, or null when it has none (or the report cannot say).
 * @param {{ id: string }} check
 * @param {object} report the lib/health.js report the check is part of
 * @returns {Fix|null}
 */
export function healthFix(check, report) {
  const make = check && Object.hasOwn(HEALTH_FIXES, check.id) ? HEALTH_FIXES[check.id] : null;
  if (!make || !report || !report.domain || !report.records) return null;
  const f = make(report, check) || null;
  return f && f.request ? { ...f, request: withReportTtlNote(f.request) } : f;
}

/**
 * A report's answers came from resolvers, whose TTL is what is left of their cached copy: a set a
 * fix only changes gets the template's TTL, with a note that it may keep its own.
 */
function withReportTtlNote(req) {
  const changed = req.rrsets.find((r) => r.mode !== 'none' && r.before && r.before.length);
  return changed ? { ...req, notes: [...req.notes, { key: 'fix.n.report-ttl', params: { ttl: changed.ttl } }] } : req;
}

/**
 * The CAA fix of a domain once the issuers of its certificates are known (Certificate
 * Transparency, lib/passport.js lookupCtIssuers): one issue value per CA, the CAs this form knows
 * by their CAA identifier, others by the first CAA domain CT gives.
 * @param {Fix} base the caa.missing fix
 * @param {Array<{ caaDomains: string[] }>} issuers
 * @returns {Fix}
 */
export function caaFixFromIssuers(base, issuers) {
  const known = [];
  const domains = [];
  for (const iss of arr(issuers)) {
    const ds = arr(iss.caaDomains).map(canon).filter(Boolean);
    const ca = FIX_CAS.find((c) => ds.includes(c.caa)) || FIX_CAS.find((c) => CAA_ISSUERS.some((x) => x.id === c.id && x.domains.some((d) => ds.includes(d))));
    if (ca && !known.includes(ca.id)) known.push(ca.id);
    else if (!ca && ds[0] && !domains.includes(ds[0])) domains.push(ds[0]);
  }
  let input = { ...base.input, cas: known };
  // What the report read at the name (no CAA set): the change still adds, never "replaces what was not read".
  const current = {};
  for (const r of arr(base.request && base.request.rrsets)) {
    if (r.before) current[`${r.name}|${r.type}`] = { status: r.before.length ? 'ok' : 'nodata', values: r.before, ttl: null, cname: null };
  }
  let request = buildChange('caa', input, { current });
  if (domains.length && request.rrsets.length) {
    const r = request.rrsets[0];
    const extra = domains.map((d) => ({ flags: 0, tag: 'issue', value: d }));
    const values = [...r.values.filter((v) => !(v.tag === 'issue' && v.value === ';')), ...extra];
    request = { ...request, rrsets: [rrset({ ...r, values })], problems: request.problems.filter((p) => p.key !== 'fix.p.caa-none') };
    // A CA the form does not list: the edit link opens the plain-record template with every value.
    input = { name: r.name, type: 'CAA', action: 'set', values: values.map((v) => valueText('CAA', v)).join('\n'), zone: base.input.zone || '' };
    return { ...base, template: 'record', input, request, needsCt: false };
  }
  return { ...base, input, request, needsCt: false };
}

/** Zone File lint codes with a fix, as {@link HEALTH_FIX_IDS}. */
const LINT_FIXES = {
  TXT_STRING_TOO_LONG: (f, idx) => zoneSetFix(f, idx, (r) => ({ ...r, rewrite: true })),
  LOCALHOST_RECORD: (f, idx) => zoneSetFix(f, idx, (r) => ({ ...r, mode: 'none' })),
  CAA_FLAGS: (f, idx) => zoneSetFix(f, idx, (r) => ({ ...r, values: r.before.map((v) => (v.tag === String(f.params && f.params.tag || v.tag) && v.flags === Number(f.params.flags) ? { ...v, flags: 0 } : v)) })),
  // Only the critical flag goes, as for the live CAA check: the tag stays, a CA that does not know it ignores it.
  CAA_CRITICAL_UNKNOWN_TAG: (f, idx) => LINT_FIXES.CAA_FLAGS(f, idx),
  TTL_TOO_LOW: (f, idx) => zoneSetFix(f, idx, (r) => ({ ...r, ttl: 300 })),
  MULTIPLE_SPF: (f, idx) => {
    const recs = zoneValues(idx, f.name, 'TXT');
    const spfs = recs.filter((v) => txtFamily(v) === 'spf1').map(txtText);
    if (spfs.length < 2) return null;
    return fix(f.code, 'records', {
      request: changeRequest({
        zone: idx.origin,
        rrsets: [{ name: f.name, type: 'TXT', ttl: zoneTtl(idx, f.name, 'TXT'), mode: 'is', family: 'spf1', values: [mergeSpf(spfs)],
          before: recs.filter((v) => txtFamily(v) === 'spf1'), others: recs.filter((v) => txtFamily(v) !== 'spf1'), beforeTtl: zoneTtl(idx, f.name, 'TXT') }]
      }),
      advice: [{ key: 'fix.a.spf-merged' }]
    });
  }
};

/** Zone File lint codes that have a fix. */
export const LINT_FIX_CODES = Object.freeze(Object.keys(LINT_FIXES).sort());

/** The values of one name and type in a parsed zone (unique records). */
function zoneValues(idx, name, type) {
  return uniqBy(idx.records.filter((r) => r.name === name && r.type === type && r.duplicateOf === undefined && !r.invalid)
    .map((r) => normalizeValue(type, r.data)).filter((v) => v !== null), (v) => valueKey(type, v));
}

function zoneTtl(idx, name, type) {
  const ttls = idx.records.filter((r) => r.name === name && r.type === type && Number.isFinite(r.ttl)).map((r) => r.ttl);
  return ttls.length ? Math.min(...ttls) : null;
}

/** A fix of one record set of the zone, the set rewritten by `edit` (before = what the file holds). */
function zoneSetFix(f, idx, edit) {
  const type = f.type;
  if (!FIX_TYPES.includes(type) || !idx.origin) return null;
  const values = zoneValues(idx, f.name, type);
  if (!values.length) return null;
  const ttl = zoneTtl(idx, f.name, type);
  const base = { name: f.name, type, ttl: ttl ?? DEFAULT_TTL, mode: 'is', family: null, values, before: values, others: [], beforeTtl: ttl };
  const r = edit(base);
  return fix(f.code, 'records', { request: changeRequest({ zone: idx.origin, rrsets: [r] }) });
}

/**
 * The fix of one Zone File lint finding, or null. The zone file is the current state, so the
 * outputs are exact.
 * @param {{ code: string, name: string, type: string, params?: object }} finding lib/zonelint.js
 * @param {{ origin: string|null, records: object[] }} zone lib/zoneparse.js zone
 * @returns {Fix|null}
 */
export function lintFix(finding, zone) {
  const make = finding && Object.hasOwn(LINT_FIXES, finding.code) ? LINT_FIXES[finding.code] : null;
  if (!make || !zone || !Array.isArray(zone.records)) return null;
  return make(finding, { origin: zone.origin ? canon(zone.origin) : null, records: zone.records }) || null;
}

/* ------------------------------------------------------------------------ */
/* i18n                                                                     */
/* ------------------------------------------------------------------------ */

// [key, [en, tr]]; a text that shows a number is a plural object picked by its `count` param.
const STRINGS = [
  // templates
  ['fix.tpl.acme-txt', ['ACME DNS-01 TXT record', 'ACME DNS-01 TXT kaydı']],
  ['fix.tpl.acme-txt.desc', ['The _acme-challenge TXT value your ACME client (certbot, acme.sh, lego …) asks for.', 'ACME istemcinizin (certbot, acme.sh, lego …) istediği _acme-challenge TXT değeri.']],
  ['fix.tpl.acme-cname', ['Delegate _acme-challenge (CNAME)', '_acme-challenge devri (CNAME)']],
  ['fix.tpl.acme-cname.desc', ['Point _acme-challenge at a zone your ACME client can write (acme-dns, a DNS-01 proxy), once.', '_acme-challenge adını ACME istemcinizin yazabildiği bir zone’a (acme-dns, bir DNS-01 aracısı) bir kez yönlendirin.']],
  ['fix.tpl.m365', ['Microsoft 365 mail', 'Microsoft 365 e-postası']],
  ['fix.tpl.m365.desc', ['MX, SPF, Autodiscover, the DKIM CNAMEs and a first DMARC record for Exchange Online.', 'Exchange Online için MX, SPF, Autodiscover, DKIM CNAME kayıtları ve ilk DMARC kaydı.']],
  ['fix.tpl.google', ['Google Workspace mail', 'Google Workspace e-postası']],
  ['fix.tpl.google.desc', ['MX, SPF, the DKIM key and a first DMARC record for Gmail.', 'Gmail için MX, SPF, DKIM anahtarı ve ilk DMARC kaydı.']],
  ['fix.tpl.caa', ['CAA for your CAs', 'Sertifika otoriteleriniz için CAA']],
  ['fix.tpl.caa.desc', ['Only the CAs you use may issue certificates, optionally only to your ACME account and by chosen validation methods (RFC 8657).', 'Yalnızca kullandığınız otoriteler sertifika verebilir; isterseniz yalnızca ACME hesabınıza ve seçtiğiniz doğrulama yöntemleriyle (RFC 8657).']],
  ['fix.tpl.spf', ['SPF: add or remove an include', 'SPF: include ekle ya da kaldır']],
  ['fix.tpl.spf.desc', ['Change the one SPF record of the domain; its other TXT records stay.', 'Alan adının tek SPF kaydını değiştirin; diğer TXT kayıtları olduğu gibi kalır.']],
  ['fix.tpl.dmarc', ['DMARC: step up the policy', 'DMARC: politikayı sıkılaştır']],
  ['fix.tpl.dmarc.desc', ['none → quarantine → reject, keeping the report addresses and other tags.', 'none → quarantine → reject; rapor adresleri ve diğer etiketler korunur.']],
  ['fix.tpl.ttl', ['Lower TTLs before a migration', 'Taşımadan önce TTL’leri düşür']],
  ['fix.tpl.ttl.desc', ['The same records with a short TTL, so the switch itself spreads fast.', 'Aynı kayıtlar kısa bir TTL ile; böylece asıl geçiş hızla yayılır.']],
  ['fix.tpl.record', ['One record set (A, AAAA, CNAME, TXT, MX, CAA)', 'Tek kayıt kümesi (A, AAAA, CNAME, TXT, MX, CAA)']],
  ['fix.tpl.record.desc', ['Set, add or delete the records of one name and type.', 'Bir ad ve türün kayıtlarını ayarlayın, ekleyin ya da silin.']],
  ['fix.tpl.parked', ['Lock down a parked domain', 'Park edilmiş alan adını kilitle']],
  ['fix.tpl.parked.desc', ['Null MX, SPF -all, DMARC p=reject and a CAA record no CA may use: the domain sends and receives no mail and gets no certificate.', 'Null MX, SPF -all, DMARC p=reject ve hiçbir otoritenin kullanamayacağı bir CAA kaydı: alan adı e-posta almaz, göndermez ve sertifika alamaz.']],
  // fields
  ['fix.field.domain', ['Domain', 'Alan adı']],
  ['fix.field.domain.hint', ['The name the records are for, e.g. example.com.', 'Kayıtların ait olduğu ad, ör. example.com.']],
  ['fix.field.name', ['Name', 'Ad']],
  ['fix.field.name.hint', ['A full name (www.example.com), a name relative to the zone (www) or @ for the zone itself.', 'Tam ad (www.example.com), zone’a göre ad (www) ya da zone’un kendisi için @.']],
  ['fix.field.name.acme', ['Certificate name', 'Sertifikadaki ad']],
  ['fix.field.name.acme.hint', ['The name being validated, e.g. example.com or *.example.com: the record goes to _acme-challenge under it.', 'Doğrulanan ad, ör. example.com ya da *.example.com: kayıt onun altındaki _acme-challenge adına yazılır.']],
  ['fix.field.tokens', ['TXT values', 'TXT değerleri']],
  ['fix.field.tokens.hint', ['One per line, exactly as your ACME client prints them (43 characters each). A wildcard and its base name validate with two values at the same name.', 'Her satıra bir tane, ACME istemcinizin yazdığı gibi (her biri 43 karakter). Joker ad ve temel adı aynı adda iki değerle doğrulanır.']],
  ['fix.field.target', ['Delegate to', 'Devredilecek ad']],
  ['fix.field.target.hint', ['The name your ACME client writes its TXT record to, e.g. the fulldomain acme-dns gave you.', 'ACME istemcinizin TXT kaydını yazdığı ad; ör. acme-dns’in verdiği fulldomain.']],
  ['fix.field.mxHost', ['MX host', 'MX sunucusu']],
  ['fix.field.mxHost.hint', ['Copy it from the Microsoft 365 admin center (Settings › Domains). Empty: the usual <domain-with-dashes>.mail.protection.outlook.com.', 'Microsoft 365 yönetim merkezinden kopyalayın (Ayarlar › Etki alanları). Boş bırakılırsa bilinen <tireli-alan-adı>.mail.protection.outlook.com kullanılır.']],
  ['fix.field.autodiscover', ['Autodiscover CNAME', 'Autodiscover CNAME kaydı']],
  ['fix.field.tenant', ['DKIM: tenant domain', 'DKIM: kiracı alan adı']],
  ['fix.field.tenant.hint', ['Your initial domain, e.g. contoso.onmicrosoft.com, for the selector1 / selector2 CNAMEs. Empty: no DKIM records.', 'selector1 / selector2 CNAME kayıtları için ilk alan adınız, ör. contoso.onmicrosoft.com. Boş: DKIM kaydı yok.']],
  ['fix.field.dkimSelector', ['DKIM selector', 'DKIM seçicisi']],
  ['fix.field.dkimKey', ['DKIM TXT value', 'DKIM TXT değeri']],
  ['fix.field.dkimKey.hint', ['“v=DKIM1; k=rsa; p=…” from the Google Admin console (Apps › Gmail › Authenticate email). Empty: no DKIM record.', 'Google Yönetici konsolundaki “v=DKIM1; k=rsa; p=…” (Uygulamalar › Gmail › E-posta kimliğini doğrula). Boş: DKIM kaydı yok.']],
  ['fix.field.dmarc', ['A first DMARC record (p=none) if there is none', 'Yoksa ilk DMARC kaydı (p=none)']],
  ['fix.field.rua', ['DMARC reports to', 'DMARC raporlarının adresi']],
  ['fix.field.rua.hint', ['A mailbox you read, e.g. dmarc-reports@example.com.', 'Okuduğunuz bir posta kutusu, ör. dmarc-reports@example.com.']],
  ['fix.field.cas', ['CAs that may issue', 'Sertifika verebilecek otoriteler']],
  ['fix.field.wild', ['Wildcard certificates', 'Joker (wildcard) sertifikalar']],
  ['fix.field.accountUri', ['Only this ACME account (accounturi)', 'Yalnızca bu ACME hesabı (accounturi)']],
  ['fix.field.accountUri.hint', ['Optional, with one CA only: the account URL your ACME client registered, e.g. https://acme-v02.api.letsencrypt.org/acme/acct/123456.', 'İsteğe bağlı, yalnızca tek otoriteyle: ACME istemcinizin kaydettiği hesap adresi, ör. https://acme-v02.api.letsencrypt.org/acme/acct/123456.']],
  ['fix.field.methods', ['Only these validation methods (validationmethods)', 'Yalnızca bu doğrulama yöntemleri (validationmethods)']],
  ['fix.field.methods.hint', ['None ticked: any method. A wildcard can only be validated by dns-01.', 'Hiçbiri seçilmezse: her yöntem. Joker ad yalnızca dns-01 ile doğrulanabilir.']],
  ['fix.field.iodef', ['Report violations to (iodef)', 'İhlalleri bildir (iodef)']],
  ['fix.field.spfAction', ['Change', 'Değişiklik']],
  ['fix.field.includes', ['Include domains', 'include alan adları']],
  ['fix.field.includes.hint', ['One per line, e.g. _spf.google.com or spf.protection.outlook.com.', 'Her satıra bir tane, ör. _spf.google.com ya da spf.protection.outlook.com.']],
  ['fix.field.all', ['Other senders (all)', 'Diğer gönderenler (all)']],
  ['fix.field.policy', ['Policy (p)', 'Politika (p)']],
  ['fix.field.pct', ['Share of failing mail the policy covers (pct)', 'Politikanın kapsadığı başarısız e-posta oranı (pct)']],
  ['fix.field.pct.hint', ['1–100; empty keeps the record’s own (all of it when it has none), 100 removes it. A step-up can start at 10 and grow.', '1–100; boş bırakılırsa kaydın kendi değeri kalır (yoksa tamamı), 100 onu kaldırır. Sıkılaştırma 10 ile başlayıp büyüyebilir.']],
  ['fix.field.sp', ['Subdomain policy (sp)', 'Alt alan adı politikası (sp)']],
  ['fix.field.records', ['Records to lower', 'TTL’i düşürülecek kayıtlar']],
  ['fix.field.records.hint', ['One “name TYPE” per line, e.g. “www A” or “@ MX”. Read the current records: their values stay, only the TTL changes.', 'Her satıra bir “ad TÜR”, ör. “www A” ya da “@ MX”. Mevcut kayıtları okuyun: değerleri kalır, yalnızca TTL değişir.']],
  ['fix.field.type', ['Type', 'Tür']],
  ['fix.field.action', ['Action', 'İşlem']],
  ['fix.field.values', ['Values', 'Değerler']],
  ['fix.field.values.hint', ['One per line: an address (A / AAAA), a host name (CNAME), “10 mail.example.com” (MX), the text (TXT), “0 issue letsencrypt.org” (CAA).', 'Her satıra bir tane: adres (A / AAAA), host adı (CNAME), “10 mail.example.com” (MX), metin (TXT), “0 issue letsencrypt.org” (CAA).']],
  ['fix.field.caa', ['Refuse every CA (CAA issue ";")', 'Tüm otoriteleri reddet (CAA issue ";")']],
  ['fix.field.dkim', ['Revoke every DKIM key (*._domainkey “v=DKIM1; p=”)', 'Tüm DKIM anahtarlarını iptal et (*._domainkey “v=DKIM1; p=”)']],
  ['fix.field.ttl', ['TTL (seconds)', 'TTL (saniye)']],
  ['fix.field.ttl.hint', ['Empty: {ttl}.', 'Boş: {ttl}.']],
  ['fix.field.zone', ['DNS zone', 'DNS zone’u']],
  ['fix.field.zone.hint', ['Empty: {zone}. Set it when the name lives in a delegated zone of its own.', 'Boş: {zone}. Ad kendine ait devredilmiş bir zone’daysa belirtin.']],
  ['fix.opt.wild.unset', ['As the issue records', 'issue kayıtlarıyla aynı']],
  ['fix.opt.wild.same', ['The same CAs (issuewild)', 'Aynı otoriteler (issuewild)']],
  ['fix.opt.wild.none', ['None (issuewild ";")', 'Hiçbiri (issuewild ";")']],
  ['fix.opt.spfAction.add', ['Add the includes', 'include’ları ekle']],
  ['fix.opt.spfAction.remove', ['Remove the includes', 'include’ları kaldır']],
  ['fix.opt.all.keep', ['Keep as it is', 'Olduğu gibi kalsın']],
  ['fix.opt.all.~all', ['~all (soft fail)', '~all (soft fail)']],
  ['fix.opt.all.-all', ['-all (fail)', '-all (fail)']],
  ['fix.opt.policy.none', ['none (monitor)', 'none (izleme)']],
  ['fix.opt.policy.quarantine', ['quarantine (spam folder)', 'quarantine (spam klasörü)']],
  ['fix.opt.policy.reject', ['reject (bounce)', 'reject (reddet)']],
  ['fix.opt.sp.keep', ['Keep as it is', 'Olduğu gibi kalsın']],
  ['fix.opt.sp.none', ['none', 'none']],
  ['fix.opt.sp.quarantine', ['quarantine', 'quarantine']],
  ['fix.opt.sp.reject', ['reject', 'reject']],
  ['fix.opt.action.set', ['Set (replace the set)', 'Ayarla (kümeyi değiştir)']],
  ['fix.opt.action.add', ['Add (keep the others)', 'Ekle (diğerleri kalsın)']],
  ['fix.opt.action.delete', ['Delete the set', 'Kümeyi sil']],
  // formats
  ['fix.fmt.bind', ['BIND', 'BIND']],
  ['fix.fmt.route53', ['Route 53', 'Route 53']],
  ['fix.fmt.cloudflare', ['Cloudflare API', 'Cloudflare API']],
  ['fix.fmt.octodns', ['octoDNS', 'octoDNS']],
  ['fix.fmt.terraform-cloudflare', ['Terraform (Cloudflare)', 'Terraform (Cloudflare)']],
  ['fix.fmt.terraform-route53', ['Terraform (Route 53)', 'Terraform (Route 53)']],
  ['fix.fmt.bind.how', ['Zone-file lines relative to $ORIGIN; bump the SOA serial and reload the zone.', '$ORIGIN’e göre zone dosyası satırları; SOA seri numarasını artırıp zone’u yeniden yükleyin.']],
  ['fix.fmt.route53.how', ['Save as change.json, then: aws route53 change-resource-record-sets --hosted-zone-id <zone ID> --change-batch file://change.json', 'change.json olarak kaydedin, sonra: aws route53 change-resource-record-sets --hosted-zone-id <zone ID> --change-batch file://change.json']],
  ['fix.fmt.cloudflare.how', ['A shell script: set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID first. The token is never part of it.', 'Bir kabuk betiği: önce CLOUDFLARE_API_TOKEN ve CLOUDFLARE_ZONE_ID değişkenlerini ayarlayın. Belirteç hiçbir zaman betiğin içinde değildir.']],
  ['fix.fmt.octodns.how', ['Entries for the zone’s YAML config; then octodns-sync.', 'Zone’un YAML yapılandırması için girdiler; ardından octodns-sync.']],
  ['fix.fmt.terraform-cloudflare.how', ['terraform-provider-cloudflare v4 resources; the zone ID is a variable.', 'terraform-provider-cloudflare v4 kaynakları; zone ID bir değişkendir.']],
  ['fix.fmt.terraform-route53.how', ['AWS provider resources; the hosted zone ID is a variable.', 'AWS sağlayıcısı kaynakları; hosted zone ID bir değişkendir.']],
  ['fix.fn.incomplete', ['The {type} values {name} has now were not read, and this format replaces the whole set: read the current records, or add them yourself.', '{name} adının şu anki {type} değerleri okunmadı ve bu biçim kümenin tamamını değiştirir: mevcut kayıtları okuyun ya da onları kendiniz ekleyin.']],
  ['fix.fn.unread-edit', ['Built without reading the current records: if {name} already has a {family} record, this output replaces it. Read the current records first, or edit that record as the instructions say.', 'Mevcut kayıtlar okunmadan oluşturuldu: {name} adında zaten bir {family} kaydı varsa bu çıktı onu değiştirir. Önce mevcut kayıtları okuyun ya da o kaydı talimatlarda yazıldığı gibi düzenleyin.']],
  ['fix.fn.route53-delete', ['A DELETE must name the set exactly as it is, its TTL included: check the TTL in the Route 53 console (a resolver reports only what is left of its cached copy).', 'DELETE, kümeyi TTL’i dahil tam olarak olduğu gibi belirtmelidir: TTL’i Route 53 konsolunda kontrol edin (bir çözümleyici yalnızca önbellekteki kopyasının kalan süresini bildirir).']],
  ['fix.fn.cloudflare-ttl', ['Cloudflare accepts TTLs from 60 to 86400 seconds (below 60 only on Enterprise plans), or 1 for automatic.', 'Cloudflare 60 ile 86400 saniye arasındaki TTL’leri (60 altını yalnızca Enterprise planlarında) ya da otomatik için 1’i kabul eder.']],
  ['fix.fn.octodns-quote', ['{name}: a TXT value with " " inside (a quote, a space, a quote). octoDNS deletes it as it loads the file, so it publishes another value: set this one at the provider another way.',
    '{name}: içinde " " (tırnak, boşluk, tırnak) olan bir TXT değeri. octoDNS dosyayı yüklerken bunu siler, bu yüzden başka bir değer yayımlar: bu değeri sağlayıcıya başka bir yoldan girin.']],
  ['fix.fn.cloudflare-ids', ['Deleting or changing a record needs its id: the list call before that step shows it; put it in place of RECORD_ID.', 'Bir kaydı silmek ya da değiştirmek için kimliği gerekir: o adımdan önceki listeleme çağrısı onu gösterir; RECORD_ID yerine yazın.']],
  // instructions
  ['fix.ins.title', ['DNS change request: {zone}', 'DNS değişiklik talebi: {zone}']],
  ['fix.ins.intro', ['Please make the following changes in the DNS zone {zone}. Records not listed here stay as they are.', 'Lütfen {zone} DNS zone’unda aşağıdaki değişiklikleri yapın. Burada yer almayan kayıtlar olduğu gibi kalır.']],
  ['fix.ins.records', ['{type} records', '{type} kayıtları']],
  ['fix.ins.family', ['{family} record (TXT)', '{family} kaydı (TXT)']],
  ['fix.ins.action.add', ['Add', 'Ekle']],
  ['fix.ins.action.replace', ['Replace', 'Değiştir']],
  ['fix.ins.action.delete', ['Delete', 'Sil']],
  ['fix.ins.action.ttl', ['Change the TTL', 'TTL’i değiştir']],
  ['fix.ins.action.rewrite', ['Rewrite', 'Yeniden yaz']],
  ['fix.ins.action.unchanged', ['No change', 'Değişiklik yok']],
  ['fix.ins.action.set', ['Add or change', 'Ekle ya da değiştir']],
  ['fix.ins.rewrite', ['The same text, split into strings of at most 255 bytes:', 'Aynı metin, en fazla 255 baytlık dizelere bölünmüş olarak:']],
  ['fix.ins.name', ['Name', 'Ad']],
  ['fix.ins.value', ['Value', 'Değer']],
  ['fix.ins.values', ['Values', 'Değerler']],
  ['fix.ins.removes', ['This removes', 'Bu değişiklikle kaldırılanlar']],
  ['fix.ins.keepOthers', ['Keep the {type} records the name already has.', 'Adın mevcut {type} kayıtları kalsın.']],
  ['fix.ins.replaceAll', ['Replace every {type} record of the name with the values above.', 'Adın tüm {type} kayıtlarını yukarıdaki değerlerle değiştirin.']],
  ['fix.ins.replaceFamily', ['Replace the name’s {family} record with the value above.', 'Adın {family} kaydını yukarıdaki değerle değiştirin.']],
  ['fix.ins.editFamily', ['If the name has no {family} record yet, add the value above; if it has one, the notes below say what to do with it.', 'Adın henüz bir {family} kaydı yoksa yukarıdaki değeri ekleyin; varsa onunla ne yapılacağını aşağıdaki notlar söyler.']],
  ['fix.ins.familyOthers', ['The other TXT records of the name stay as they are.', 'Adın diğer TXT kayıtları olduğu gibi kalır.']],
  ['fix.ins.deleteAll', ['Delete every {type} record of the name.', 'Adın tüm {type} kayıtlarını silin.']],
  ['fix.ins.deleteFamily', ['Delete the {family} record of the name; its other TXT records stay.', 'Adın {family} kaydını silin; diğer TXT kayıtları kalır.']],
  ['fix.ins.ttlChange', ['New TTL: {to} seconds (the values stay the same)', 'Yeni TTL: {to} saniye (değerler aynı kalır)']],
  ['fix.ins.nothing', ['Nothing to change: the names already hold these records.', 'Değiştirilecek bir şey yok: adlar bu kayıtları zaten tutuyor.']],
  ['fix.ins.notes', ['Notes:', 'Notlar:']],
  ['fix.ins.check', ['Once the change is made, this link shows whether public DNS resolvers see it:', 'Değişiklik yapıldıktan sonra genel DNS çözümleyicilerinin onu görüp görmediğini bu bağlantı gösterir:']],
  // notes
  ['fix.n.acme-remove', ['Once the certificate is issued, the TXT values at {name} can be removed; leftovers do no harm but pile up.', 'Sertifika verildikten sonra {name} adındaki TXT değerleri kaldırılabilir; kalanlar zarar vermez ama birikir.']],
  ['fix.n.acme-wildcard', ['A wildcard and its base name are validated at the same name ({name}): keep both values until the certificate is issued.', 'Joker ad ve temel adı aynı adda ({name}) doğrulanır: sertifika verilene kadar iki değeri de tutun.']],
  ['fix.n.acme-cname', ['After this, validations of the name look up {target}; the ACME client writes its TXT there, and {name} never changes again.', 'Bundan sonra adın doğrulamaları {target} adına bakar; ACME istemcisi TXT kaydını oraya yazar ve {name} bir daha değişmez.']],
  ['fix.n.m365-mx', ['The MX host {host} is the usual form; the admin center shows the one of your tenant (newer tenants may get one under mx.microsoft).', 'MX sunucusu {host} bilinen biçimdir; kiracınızınkini yönetim merkezi gösterir (yeni kiracılar mx.microsoft altında bir ad alabilir).']],
  ['fix.n.m365-dkim', ['Turn DKIM on in Microsoft Defender (Email authentication settings) once the CNAMEs resolve; compare the two values with the ones it shows.', 'CNAME kayıtları çözümlendikten sonra DKIM’i Microsoft Defender’da (E-posta kimlik doğrulama ayarları) açın; iki değeri orada gösterilenlerle karşılaştırın.']],
  ['fix.n.google-mx', ['smtp.google.com with priority 1 is Google’s current single MX; the older five aspmx records keep working.', 'Öncelik 1 ile smtp.google.com, Google’ın güncel tek MX kaydıdır; eski beş aspmx kaydı da çalışmaya devam eder.']],
  ['fix.n.google-dkim', ['No DKIM key given: generate one in the Google Admin console and publish it as a TXT record at google._domainkey.', 'DKIM anahtarı girilmedi: Google Yönetici konsolunda oluşturup google._domainkey adında TXT kaydı olarak yayınlayın.']],
  ['fix.n.spf-unread', ['The current records were not read: if the name already has an SPF record, add include:{include} to that record (before its all term) instead of replacing it with the value above, which would drop the senders it lists; a second SPF record would fail SPF for all mail.', 'Mevcut kayıtlar okunmadı: adın zaten bir SPF kaydı varsa onu yukarıdaki değerle değiştirmek yerine include:{include} ifadesini o kayda (all teriminden önce) ekleyin; değiştirmek kayıtta listelenen gönderenleri düşürür, ikinci bir SPF kaydı ise tüm e-postalarda SPF’i başarısız kılar.']],
  ['fix.n.spf-present', ['The SPF record already includes {include}.', 'SPF kaydında {include} zaten var.']],
  ['fix.n.spf-new', ['There is no SPF record yet: this creates one. List every service that sends mail as the domain.', 'Henüz SPF kaydı yok: bu değişiklik bir tane oluşturur. Alan adı adına e-posta gönderen her hizmeti listeleyin.']],
  ['fix.n.dmarc-start', ['p=none only asks for reports: watch them until every legitimate sender passes, then step up to quarantine and reject.', 'p=none yalnızca rapor ister: tüm meşru gönderenler geçene kadar raporları izleyin, sonra quarantine ve reject’e geçin.']],
  ['fix.n.dmarc-step', ['From p={from} to p={to}: watch the reports for a week or two after the change; a sender that fails DMARC now loses mail.', 'p={from} politikasından p={to} politikasına: değişiklikten sonra bir iki hafta raporları izleyin; DMARC’tan geçemeyen bir gönderenin e-postaları artık kaybolur.']],
  ['fix.n.dmarc-to', ['To p={to}: watch the reports for a week or two after the change; a sender that fails DMARC then loses mail.', 'p={to} politikasına geçiş: değişiklikten sonra bir iki hafta raporları izleyin; DMARC’tan geçemeyen bir gönderenin e-postaları artık kaybolur.']],
  ['fix.n.dmarc-unread', ['The current DMARC record of {name} was not read: the value above holds only what this request sets. If there is a record, change only those tags in it and keep the others (rua, ruf, sp, pct …): replacing it with the value above would drop them.', '{name} adının mevcut DMARC kaydı okunmadı: yukarıdaki değer yalnızca bu talebin belirlediği etiketleri taşır. Bir kayıt varsa onda yalnızca bu etiketleri değiştirin ve diğerlerini (rua, ruf, sp, pct …) koruyun: kaydı yukarıdaki değerle değiştirmek onları düşürür.']],
  ['fix.n.dmarc-sp', ['Names under the domain without a DMARC record of their own go from sp={from} to sp={to}: watch the reports of mail sent as them for a week or two.', 'Alan adının altında kendi DMARC kaydı olmayan adlar sp={from} politikasından sp={to} politikasına geçer: onların adına gönderilen e-postaların raporlarını bir iki hafta izleyin.']],
  ['fix.n.dmarc-kept', ['{name} already has a DMARC record; it stays as it is.', '{name} adında zaten bir DMARC kaydı var; olduğu gibi kalır.']],
  ['fix.n.dmarc-first-unread', ['The current records were not read: if {name} already has a DMARC record, leave it as it is and skip this record.', 'Mevcut kayıtlar okunmadı: {name} adında zaten bir DMARC kaydı varsa olduğu gibi bırakın ve bu kaydı atlayın.']],
  ['fix.n.caa-tree', ['CAA at {name} applies to every name below it that has no CAA record of its own.', '{name} adındaki CAA, kendi CAA kaydı olmayan altındaki her ada da uygulanır.']],
  ['fix.n.caa-wildcard-dns01', ['Without dns-01 no CA can validate a wildcard certificate here.', 'dns-01 olmadan hiçbir otorite burada joker (wildcard) sertifika doğrulayamaz.']],
  ['fix.n.ttl-wait', ['Wait at least the old TTL after this change before the migration: until then resolvers may keep the longer-lived copies. A resolver still had one for {ttl} s; the zone’s own value can be higher.', 'Bu değişiklikten sonra taşımadan önce en az eski TTL kadar bekleyin: o zamana kadar çözümleyiciler uzun ömürlü kopyaları tutabilir. Bir çözümleyicide {ttl} sn kalmış bir kopya vardı; zone’daki asıl değer daha yüksek olabilir.']],
  ['fix.n.parked', ['Only for a domain that sends and receives no mail and needs no certificate: all mail as the domain is rejected and every CA refuses to issue.', 'Yalnızca e-posta almayan, göndermeyen ve sertifika gerektirmeyen bir alan adı için: alan adı adına tüm e-postalar reddedilir ve her otorite sertifika vermeyi reddeder.']],
  ['fix.n.report-ttl', ['The TTL {ttl} is a default: a public resolver does not tell a zone’s own TTL. A record that is only changed can keep the TTL it has.', '{ttl} TTL değeri varsayılandır: genel bir çözümleyici zone’daki asıl TTL’i bildirmez. Yalnızca değiştirilen bir kayıt mevcut TTL’ini koruyabilir.']],
  ['fix.n.parked-mail', ['Only for a domain that sends and receives no mail: mail to it bounces at once and mail as it is rejected.', 'Yalnızca e-posta almayan ve göndermeyen bir alan adı için: ona gelen e-posta hemen geri döner, onun adına gönderilen e-posta reddedilir.']],
  // problems
  ['fix.p.template', ['Unknown template.', 'Bilinmeyen şablon.']],
  ['fix.p.too-many', ['A change request holds at most {max} record sets.', 'Bir değişiklik talebi en fazla {max} kayıt kümesi içerir.']],
  ['fix.p.too-many-values', ['A change request holds at most {max} values.', 'Bir değişiklik talebi en fazla {max} değer içerir.']],
  ['fix.p.ttl', ['The TTL “{value}” is not a whole number of seconds.', '“{value}” geçerli bir TTL değil: saniye cinsinden bir tam sayı girin.']],
  ['fix.p.zone', ['“{value}” is not a DNS zone name.', '“{value}” bir DNS zone adı değil.']],
  ['fix.p.domain-missing', ['Enter a domain name such as example.com.', 'example.com gibi bir alan adı girin.']],
  ['fix.p.name-missing', ['Enter a name such as www.example.com.', 'www.example.com gibi bir ad girin.']],
  ['fix.p.domain', ['“{value}” is not a domain name in the zone {zone}.', '“{value}”, {zone} zone’unda bir alan adı değil.']],
  ['fix.p.name', ['“{value}” is not a name in the zone {zone}.', '“{value}”, {zone} zone’unda bir ad değil.']],
  ['fix.p.outside', ['“{value}” is outside the zone {zone}: set the zone, or type the name in full.', '“{value}”, {zone} zone’unun dışında: zone’u belirtin ya da adı tam yazın.']],
  ['fix.p.host', ['“{value}” is not a host name.', '“{value}” bir host adı değil.']],
  ['fix.p.email', ['“{value}” is not an email address.', '“{value}” bir e-posta adresi değil.']],
  ['fix.p.tokens-missing', ['Enter the TXT value your ACME client printed.', 'ACME istemcinizin yazdığı TXT değerini girin.']],
  ['fix.p.token-format', ['Does not look like an ACME DNS-01 value (43 characters of A–Z, a–z, 0–9, - and _): {values}', 'ACME DNS-01 değerine benzemiyor (A–Z, a–z, 0–9, - ve _ karakterlerinden 43 karakter): {values}']],
  ['fix.p.acme-delegated', ['{name} is a CNAME to {target}: CAs follow it, so the TXT record belongs at {target}, and a TXT next to the CNAME is not allowed.', '{name}, {target} adına bir CNAME: otoriteler onu izler, bu yüzden TXT kaydı {target} adına yazılmalı; CNAME’in yanında TXT olamaz.']],
  ['fix.p.acme-name', ['The name field takes the name the certificate is for: “_acme-challenge.” was taken off {value}, and the record goes at {name}.', 'Ad alanı sertifikadaki adı alır: {value} adının başındaki “_acme-challenge.” çıkarıldı; kayıt {name} adına yazılır.']],
  ['fix.p.target-missing', ['Enter the name to delegate to.', 'Devredilecek adı girin.']],
  ['fix.p.selector', ['“{value}” is not a DKIM selector.', '“{value}” bir DKIM seçicisi değil.']],
  ['fix.p.dkim-key', ['The DKIM value must start with “v=DKIM1” and carry the key in p=.', 'DKIM değeri “v=DKIM1” ile başlamalı ve anahtarı p= içinde taşımalı.']],
  ['fix.p.accounturi-one', ['accounturi names one CA’s ACME account: choose exactly one CA with it.', 'accounturi tek bir otoritenin ACME hesabını belirtir: onunla tam olarak bir otorite seçin.']],
  ['fix.p.accounturi', ['“{value}” is not an ACME account URL (https://…).', '“{value}” bir ACME hesap adresi (https://…) değil.']],
  ['fix.p.caa-none', ['No CA chosen: the record lets no CA issue a certificate for the domain.', 'Otorite seçilmedi: kayıt hiçbir otoritenin alan adı için sertifika vermesine izin vermez.']],
  ['fix.p.caa-malformed', ['The CAA value “{value}” is malformed ({problem}); a malformed value lets no CA issue.', '“{value}” CAA değeri hatalı ({problem}); hatalı bir değer hiçbir otoritenin sertifika vermesine izin vermez.']],
  ['fix.p.caa-unsatisfiable', ['No CA can satisfy the CAA value “{value}” ({problem}).', 'Hiçbir otorite “{value}” CAA değerini karşılayamaz ({problem}).']],
  ['fix.p.includes-missing', ['Enter at least one include domain.', 'En az bir include alan adı girin.']],
  ['fix.p.read-first', ['Read the current records first: the change is built from the record the name holds now.', 'Önce mevcut kayıtları okuyun: değişiklik adın şu anki kaydından oluşturulur.']],
  ['fix.p.spf-multiple', ['{name} has {count} SPF records: merge them into one first (the “Show the fix” of Domain Health does it).', '{name} adında {count} SPF kaydı var: önce tek kayıtta birleştirin (Alan Adı Sağlığı’ndaki “Düzeltmeyi göster” bunu yapar).']],
  ['fix.p.spf-none', ['{name} has no SPF record to remove an include from.', '{name} adında include kaldırılacak bir SPF kaydı yok.']],
  ['fix.p.spf-remove-read', ['Read the current records first: an include is removed from the SPF record {name} holds now, and a record written without that read would drop every other sender.', 'Önce mevcut kayıtları okuyun: include, {name} adının şu anki SPF kaydından kaldırılır; bu okuma olmadan yazılan bir kayıt diğer tüm gönderenleri düşürür.']],
  ['fix.p.include-absent', ['The SPF record has no include of {values}.', 'SPF kaydında {values} için include yok.']],
  ['fix.p.spf-syntax', ['The new SPF record has an invalid term: {token}', 'Yeni SPF kaydında geçersiz bir ifade var: {token}']],
  ['fix.p.spf-terms', ['The SPF record of {name} has {count} lookup terms of its own, over the limit of {limit} before any include is expanded.', '{name} SPF kaydının kendi {count} sorgu ifadesi var; include’lar açılmadan önce bile {limit} sınırını aşıyor.']],
  ['fix.p.spf-lookups-over', ['With its includes as published now, the SPF record of {name} needs {count} DNS lookups (limit {limit}): SPF would fail for all mail.', 'include’ların şu anki hâliyle {name} SPF kaydı {count} DNS sorgusu gerektiriyor (sınır {limit}): SPF tüm e-postalarda başarısız olur.']],
  ['fix.p.spf-lookups-high', ['With its includes as published now, the SPF record of {name} needs {count} of {limit} DNS lookups: one more include breaks it.', 'include’ların şu anki hâliyle {name} SPF kaydı {limit} DNS sorgusunun {count} tanesini kullanıyor: bir include daha onu bozar.']],
  ['fix.p.spf-recount', ['The SPF record of {name} changed after its DNS lookups were counted: read the current records again to count them.', '{name} SPF kaydı DNS sorguları sayıldıktan sonra değişti: saymak için mevcut kayıtları yeniden okuyun.']],
  ['fix.p.spf-lookups-ok', ['With its includes as published now, the SPF record of {name} needs {count} of {limit} DNS lookups.', 'include’ların şu anki hâliyle {name} SPF kaydı {limit} DNS sorgusunun {count} tanesini kullanıyor.']],
  ['fix.p.dmarc-multiple', ['{name} has {count} DMARC records: keep exactly one.', '{name} adında {count} DMARC kaydı var: yalnızca birini bırakın.']],
  ['fix.p.pct', ['pct must be a whole number from 1 to 100, not “{value}”.', 'pct 1 ile 100 arasında bir tam sayı olmalı; “{value}” değil.']],
  ['fix.p.dmarc-syntax', ['The new DMARC record has an error: {token}', 'Yeni DMARC kaydında hata var: {token}']],
  ['fix.p.dmarc-no-rua', ['Without rua= you get no reports, so you cannot see what a stricter policy would block.', 'rua= olmadan rapor almazsınız; daha sıkı bir politikanın neyi engelleyeceğini göremezsiniz.']],
  ['fix.p.records-missing', ['Enter at least one “name TYPE” line.', 'En az bir “ad TÜR” satırı girin.']],
  ['fix.p.ttl-line', ['Not a “name TYPE” line of this zone: {value}', 'Bu zone’a ait bir “ad TÜR” satırı değil: {value}']],
  ['fix.p.ttl-read', ['Read the current records: a TTL change keeps their values, and they are not known yet.', 'Mevcut kayıtları okuyun: TTL değişikliği değerlerini korur ve henüz bilinmiyorlar.']],
  ['fix.p.ttl-empty', ['{name} has no {type} records.', '{name} adının {type} kaydı yok.']],
  ['fix.p.ttl-already', ['{name} {type} already has a TTL of {ttl} s.', '{name} {type} kaydının TTL’i zaten {ttl} sn.']],
  ['fix.p.value', ['Not a {type} value: {value}', '{type} değeri değil: {value}']],
  ['fix.p.values-missing', ['Enter at least one value.', 'En az bir değer girin.']],
  ['fix.p.cname-one', ['A name has at most one CNAME.', 'Bir adın en fazla bir CNAME kaydı olur.']],
  ['fix.p.cname-add', ['A CNAME cannot be added next to another one: use Set.', 'Bir CNAME başka birinin yanına eklenemez: Ayarla’yı kullanın.']],
  ['fix.p.parked-mail', ['{name} has MX records now: after this change it receives no mail.', '{name} adının şu anda MX kayıtları var: bu değişiklikten sonra e-posta almaz.']],
  ['fix.p.parked-sends', ['{name} has an SPF record that lets servers send as it ({record}): after this change all of that mail fails SPF and DMARC rejects it.', '{name} adının, sunucuların onun adına göndermesine izin veren bir SPF kaydı var ({record}): bu değişiklikten sonra o e-postaların tümü SPF’ten geçemez ve DMARC onları reddeder.']],
  ['fix.p.ttl-low', ['TTL {ttl} s for {name} {type}: some providers refuse TTLs under 60 s (Cloudflare needs an Enterprise plan for them).', '{name} {type} için TTL {ttl} sn: bazı sağlayıcılar 60 sn altındaki TTL’leri reddeder (Cloudflare’de Enterprise planı gerekir).']],
  ['fix.p.ttl-high', ['TTL {ttl} s for {name} {type}: over a day, so the next change takes that long to reach everyone.', '{name} {type} için TTL {ttl} sn: bir günden uzun; bir sonraki değişikliğin herkese ulaşması bu kadar sürer.']],
  // advice
  ['fix.a.rua-mailbox', ['Reports go to {address}: create that mailbox, or change the address in the change request.', 'Raporlar {address} adresine gider: o posta kutusunu oluşturun ya da değişiklik talebinde adresi değiştirin.']],
  ['fix.a.dmarc-multiple', ['Delete every DMARC record at _dmarc but one; keep the one with the policy and report addresses you want.', '_dmarc adındaki DMARC kayıtlarından biri dışında hepsini silin; istediğiniz politika ve rapor adreslerini içereni tutun.']],
  ['fix.a.spf-senders', ['List every service that sends mail as {domain} (your mail platform, newsletters, ticketing, invoices …) as include: or ip4: terms, then end with ~all. No record is suggested here: a guess would fail real mail.', '{domain} adına e-posta gönderen her hizmeti (e-posta platformunuz, bülten, destek sistemi, fatura …) include: ya da ip4: ifadesi olarak listeleyin ve ~all ile bitirin. Burada kayıt önerilmez: tahmin gerçek e-postaları başarısız kılar.']],
  ['fix.a.spf-no-mail', ['Only if the domain sends no mail at all: “-all” then fails every message sent as it.', 'Yalnızca alan adı hiç e-posta göndermiyorsa: “-all” onun adına gönderilen her iletiyi başarısız kılar.']],
  ['fix.a.spf-merge', ['Merge the SPF records into one: every mechanism once, one all at the end.', 'SPF kayıtlarını tek kayıtta birleştirin: her mekanizma bir kez, sonda tek bir all.']],
  ['fix.a.spf-merged', ['The records are merged into one with every term once and the strictest all; count its DNS lookups before you publish it.', 'Kayıtlar her ifade bir kez ve en sıkı all ile tek kayıtta birleştirildi; yayınlamadan önce DNS sorgu sayısını kontrol edin.']],
  ['fix.a.spf-flatten', ['No automatic record: flatten the include that costs the most into ip4: / ip6: terms (and keep them in sync with the provider), move a sender to its own subdomain, or drop includes that no longer send. Most expensive: {includes}.', 'Otomatik kayıt yok: en çok sorgu harcayan include’u ip4: / ip6: ifadelerine düzleştirin (ve sağlayıcıyla güncel tutun), bir göndereni kendi alt alan adına taşıyın ya da artık göndermeyen include’ları kaldırın. En pahalıları: {includes}.']],
  ['fix.a.no-mail', ['Only if the domain sends and receives no mail: these records say so, and receivers then reject spoofed mail at once.', 'Yalnızca alan adı e-posta almıyor ve göndermiyorsa: bu kayıtlar bunu söyler ve alıcılar sahte e-postaları hemen reddeder.']],
  ['fix.a.no-mx-sends', ['The domain sends mail: its SPF record lets servers send as it ({record}). A null MX, “v=spf1 -all” and DMARC p=reject would fail all of that mail, so no record is suggested. To get bounces and replies, add the MX records of the mail platform that sends as it.', 'Alan adı e-posta gönderiyor: SPF kaydı sunucuların onun adına göndermesine izin veriyor ({record}). Null MX, “v=spf1 -all” ve DMARC p=reject bu e-postaların tümünü başarısız kılar; bu yüzden kayıt önerilmez. Geri dönen iletileri ve yanıtları almak için onun adına gönderen e-posta platformunun MX kayıtlarını ekleyin.']],
  ['fix.a.dmarc-inherited', ['{domain} has no DMARC record of its own and uses the one at {name}: the fix changes that record, which also holds the policy of {org} and of every name under it without a DMARC record of its own.', '{domain} adının kendi DMARC kaydı yok, {name} adındakini kullanıyor: düzeltme o kaydı değiştirir; bu kayıt {org} alan adının ve altında kendi DMARC kaydı olmayan her adın politikasını da taşır.']],
  ['fix.a.caa-at', ['The CAA records that apply to {domain} are at {name}: the fix changes them there, so it applies to every name under {name} without CAA records of its own.', '{domain} için geçerli CAA kayıtları {name} adında: düzeltme onları orada değiştirir; bu yüzden {name} altında kendi CAA kaydı olmayan her ada uygulanır.']],
  ['fix.a.caa-cert', ['The certificate’s CA ({issuer}) joins the {property} values as “{value}”; the CAs already listed stay.', 'Sertifikanın otoritesi ({issuer}) {property} değerlerine “{value}” olarak eklenir; listedeki otoriteler kalır.']],
  ['fix.a.caa-critical', ['The critical flag goes from {tags}: a CA that does not know the tag then ignores it instead of refusing every certificate. If the tag was meant to restrict issuance, ask your CA what it supports instead.', 'Kritik bayrak {tags} etiketinden kaldırılır: etiketi tanımayan bir otorite her sertifikayı reddetmek yerine onu yok sayar. Etiket sertifika verilmesini kısıtlamak içinse otoritenize neyi desteklediğini sorun.']],
  ['fix.a.null-mixed', ['Keep either the null MX (“0 .”, the domain receives no mail) or the real MX records, not both.', 'Ya null MX’i (“0 .”, alan adı e-posta almaz) ya da gerçek MX kayıtlarını tutun; ikisini birden değil.']]
];

function buildStrings(lang) {
  return Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));
}

/**
 * English and Turkish texts of every `fix.*` key this module and the views use. Register with
 * `registerStrings('en', FIX_I18N.en)` / `registerStrings('tr', FIX_I18N.tr)`.
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const FIX_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });

/**
 * A {@link FIX_I18N} text in one language, with `{params}` filled (the instructions are written in
 * either language whatever the UI's is, so they do not go through i18n.js).
 * @param {'en'|'tr'} lang
 * @param {string} key
 * @param {Record<string, unknown>} [params]
 * @returns {string}
 */
export function textIn(lang, key, params = {}) {
  const dict = FIX_I18N[lang] || FIX_I18N.en;
  let s = dict[key] ?? FIX_I18N.en[key] ?? key;
  if (s && typeof s === 'object') {
    let cat = 'other';
    try {
      cat = new Intl.PluralRules(lang === 'tr' ? 'tr-TR' : 'en-US').select(Number(params.count));
    } catch {
      cat = 'other';
    }
    s = s[cat] ?? s.other;
  }
  return String(s).replace(/\{([A-Za-z0-9_]+)\}/g, (whole, k) => (Object.hasOwn(params || {}, k) && params[k] !== null && params[k] !== undefined
    ? (Array.isArray(params[k]) ? params[k].join(', ') : String(params[k])) : whole));
}
