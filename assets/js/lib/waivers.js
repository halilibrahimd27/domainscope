/**
 * waivers.js — accepted risks (waivers) and known certificates: a finding, a policy rule or a
 * certificate someone decided to live with, for a reason, by an owner, until a day. Shared by the
 * app (Domain Health, the Domain portfolio's policy matrix and its CT tab, the Workspaces dialog)
 * and the headless runner (tools/ds.mjs `--waivers`), so both read the same file the same way.
 *
 * An entry:
 *   { id, kind: 'finding'|'rule'|'cert', domain, ref, reason, owner, created, expires }
 * - `kind` 'finding': `ref` is a Domain Health check id (`dmarc.policy-none`); 'rule': a policy
 *   rule id of lib/policy.js (`transferLock`, `dmarc.policy`); 'cert': a certificate's SHA-256 or
 *   its public key's (SPKI) SHA-256, 64 hex digits — a known certificate, which the CT watch never
 *   marks new or from an unexpected CA.
 * - `domain`: the domain it applies to, exactly (a host name: a subdomain is not covered).
 * - `reason`: why (1 to {@link WAIVER_REASON_MAX} characters); `owner`: who decided (up to
 *   {@link WAIVER_OWNER_MAX}, may be empty); `created`: when (ISO, null when not known).
 * - `expires`: the last day it applies (YYYY-MM-DD, UTC), required and at most
 *   {@link WAIVER_MAX_DAYS} days ahead when it is read (a day of grace for the time zones). The
 *   day after, it no longer applies: its item counts again and the waiver is listed as expired.
 * - `id`: `w-` and 16 hex digits of FNV-1a over kind, domain and ref ({@link waiverId}): one waiver
 *   per item, so accepting the same item again replaces the old one.
 *
 * The file (waivers.json — the runner's `--waivers` input — and the workspace's `waivers` part):
 *   { "format": "domainscope-waivers", "v": 1, "waivers": [ … ] }      (a bare list is read too)
 * An entry that is not valid is left out and said ({@link parseWaivers} `errors`), never applied:
 * an item whose waiver cannot be read counts.
 *
 * DOM-free; the clock is injected (`now`). Runs in browsers and Node 22.
 */

import { normalizeHostname } from './domain.js';

/** What a waiver can accept. */
export const WAIVER_KINDS = Object.freeze(['finding', 'rule', 'cert']);
/** The `format` of a waivers file. */
export const WAIVERS_FORMAT = 'domainscope-waivers';
/** The file version this module writes and the newest it reads. */
export const WAIVERS_VERSION = 1;
/** Longest waivers text kept (the workspace part's limit, lib/workspace.js WORKSPACE_LIMITS.waivers). */
export const WAIVERS_MAX_CHARS = 65536;
/** Most waivers one file holds. */
export const WAIVERS_MAX = 500;
/** Longest reason, in characters. */
export const WAIVER_REASON_MAX = 200;
/** Longest owner, in characters. */
export const WAIVER_OWNER_MAX = 80;
/** A waiver ends at most this many days ahead. */
export const WAIVER_MAX_DAYS = 366;
/** The end date the forms offer: this many days ahead. */
export const WAIVER_DEFAULT_DAYS = 90;
/** A waiver that ends within this many days is "expiring". */
export const WAIVER_SOON_DAYS = 14;
/** Where a waiver stands at a moment ({@link waiverState}). */
export const WAIVER_STATES = Object.freeze(['active', 'expiring', 'expired']);
/** Why a file or an entry was refused ({@link parseWaivers}, {@link validateWaiver}). */
export const WAIVER_ERRORS = Object.freeze(['not-json', 'not-waivers', 'newer', 'too-large', 'too-many', 'not-object', 'kind', 'domain', 'ref',
  'reason', 'owner', 'expires', 'too-far', 'created']);

const DAY_MS = 86400000;
const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const REF_RES = Object.freeze({
  finding: /^[a-z0-9][a-z0-9._-]{0,79}$/,
  rule: /^[A-Za-z][A-Za-z0-9._-]{0,39}$/,
  cert: /^[0-9a-f]{64}$/
});
// C0 / C1 controls, zero-width characters, line / paragraph separators and bidi overrides: never
// part of a reason or an owner shown on a page or in a report.
// eslint-disable-next-line no-control-regex
const JUNK_RE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;

/** A refused waiver or waivers file; `code` is one of {@link WAIVER_ERRORS}. */
export class WaiverError extends Error {
  /**
   * @param {string} code
   * @param {string} [message]
   */
  constructor(code, message) {
    super(message || code);
    this.name = 'WaiverError';
    this.code = code;
  }
}

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */
/* ------------------------------------------------------------------------ */

const ms = (now) => (now instanceof Date ? now.getTime() : typeof now === 'function' ? Number(now()) : Number(now));
const pad = (n) => String(n).padStart(2, '0');

/**
 * The UTC day of an instant: 'YYYY-MM-DD'.
 * @param {Date|number} now
 * @returns {string}
 */
export function utcDay(now) {
  const d = new Date(ms(now));
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

/** The day `days` after `day` ('YYYY-MM-DD'). */
export function addDays(day, days) {
  const m = DAY_RE.exec(day);
  return utcDay(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + days));
}

/** A real calendar day ('2026-02-30' is not one), or null. */
function calendarDay(text) {
  const m = DAY_RE.exec(String(text ?? '').trim());
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const t = Date.UTC(y, mo - 1, d);
  const back = new Date(t);
  return back.getUTCFullYear() === y && back.getUTCMonth() === mo - 1 && back.getUTCDate() === d ? `${m[1]}-${m[2]}-${m[3]}` : null;
}

/** At most `max` characters (code points), controls out, whitespace collapsed. */
function cleanLine(value, max) {
  const s = String(value ?? '').normalize('NFC').replace(JUNK_RE, ' ').replace(/\s+/g, ' ').trim();
  return [...s].length <= max ? s : null;
}

/** FNV-1a, 64 bits, of a text's UTF-8 bytes: 16 hex digits (as lib/ctwatch.js fnv64). */
function fnv64(text) {
  let h = 0xcbf29ce484222325n;
  for (const b of new TextEncoder().encode(String(text))) {
    h ^= BigInt(b);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

/* ------------------------------------------------------------------------ */
/* One entry                                                                */
/* ------------------------------------------------------------------------ */

/**
 * A waiver's ref as it is kept, or null when it is not one its kind takes: a check id in lower
 * case; a rule id as written; a SHA-256 as 64 lower-case hex digits (colons, spaces and a
 * `sha256:` prefix dropped).
 * @param {string} kind
 * @param {unknown} ref
 * @returns {string|null}
 */
export function normalizeRef(kind, ref) {
  if (typeof ref !== 'string' || !Object.hasOwn(REF_RES, kind)) return null;
  let s = ref.trim();
  if (kind === 'finding') s = s.toLowerCase();
  if (kind === 'cert') s = s.toLowerCase().replace(/^sha-?256[:/]/, '').replace(/[\s:]/g, '');
  return REF_RES[kind].test(s) ? s : null;
}

/**
 * The key of the item a waiver accepts (kind, domain and ref).
 * @param {string} kind
 * @param {string} domain
 * @param {string} ref
 * @returns {string}
 */
export function waiverKey(kind, domain, ref) {
  return `${kind}|${domain}|${ref}`;
}

/**
 * A waiver's id: `w-` and 16 hex digits of FNV-1a over its key, the same for the same item.
 * @param {string} kind
 * @param {string} domain
 * @param {string} ref
 * @returns {string}
 */
export function waiverId(kind, domain, ref) {
  return `w-${fnv64(waiverKey(kind, domain, ref))}`;
}

/**
 * The day a waiver offers by default: {@link WAIVER_DEFAULT_DAYS} days after today (UTC).
 * @param {Date|number} [now]
 * @param {number} [days]
 * @returns {string}
 */
export function defaultExpiry(now = Date.now(), days = WAIVER_DEFAULT_DAYS) {
  return addDays(utcDay(now), days);
}

/**
 * The last day a new waiver may end: {@link WAIVER_MAX_DAYS} days after today (UTC).
 * @param {Date|number} [now]
 * @returns {string}
 */
export function maxExpiry(now = Date.now()) {
  return addDays(utcDay(now), WAIVER_MAX_DAYS);
}

/**
 * Check one entry and write it as it is kept. `expires` takes a day or an ISO time (its UTC day);
 * it must be a day no more than {@link WAIVER_MAX_DAYS} days after today, plus a day of grace (a
 * form in a time zone ahead of UTC). An expired waiver is valid: it is listed as expired.
 * @param {unknown} entry
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ waiver: object, error: null } | { waiver: null, error: { code: string, field?: string } }}
 */
export function validateWaiver(entry, { now = Date.now() } = {}) {
  const fail = (code, field = code) => ({ waiver: null, error: { code, field } });
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return fail('not-object', null);
  const kind = typeof entry.kind === 'string' ? entry.kind.trim().toLowerCase() : '';
  if (!WAIVER_KINDS.includes(kind)) return fail('kind');
  const domain = typeof entry.domain === 'string' ? normalizeHostname(entry.domain) : null;
  if (!domain) return fail('domain');
  const ref = normalizeRef(kind, entry.ref);
  if (!ref) return fail('ref');
  const reason = cleanLine(entry.reason, WAIVER_REASON_MAX);
  if (!reason) return fail('reason');
  const owner = entry.owner === undefined || entry.owner === null ? '' : cleanLine(entry.owner, WAIVER_OWNER_MAX);
  if (owner === null) return fail('owner');
  const raw = typeof entry.expires === 'string' ? entry.expires.trim() : '';
  let expires = calendarDay(raw);
  if (!expires && /^\d{4}-\d{2}-\d{2}T/.test(raw) && Number.isFinite(Date.parse(raw))) expires = utcDay(Date.parse(raw));
  if (!expires) return fail('expires');
  if (expires > addDays(maxExpiry(now), 1)) return fail('too-far', 'expires');
  let created = null;
  if (entry.created !== undefined && entry.created !== null && entry.created !== '') {
    const t = typeof entry.created === 'string' ? Date.parse(entry.created) : NaN;
    if (!Number.isFinite(t)) return fail('created');
    created = new Date(t).toISOString();
  }
  return { waiver: { id: waiverId(kind, domain, ref), kind, domain, ref, reason, owner, created, expires }, error: null };
}

/**
 * The instant a waiver stops applying: the end of its last day (UTC).
 * @param {{ expires: string }} w
 * @returns {number} ms
 */
export function waiverEnd(w) {
  const m = DAY_RE.exec(String(w && w.expires));
  return m ? Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + 1) : -Infinity;
}

/**
 * Where a waiver stands at `now`: 'expired' (its last day is over), 'expiring' (it ends within
 * {@link WAIVER_SOON_DAYS} days) or 'active'.
 * @param {{ expires: string }} w
 * @param {{ now?: Date|number }} [opts]
 * @returns {'active'|'expiring'|'expired'}
 */
export function waiverState(w, { now = Date.now() } = {}) {
  const left = waiverEnd(w) - ms(now);
  if (left <= 0) return 'expired';
  return left <= WAIVER_SOON_DAYS * DAY_MS ? 'expiring' : 'active';
}

/**
 * Does a waiver apply at `now` (its last day is not over)?
 * @param {{ expires: string }} w
 * @param {{ now?: Date|number }} [opts]
 * @returns {boolean}
 */
export function isWaiverActive(w, { now = Date.now() } = {}) {
  return waiverEnd(w) > ms(now);
}

/* ------------------------------------------------------------------------ */
/* A list, a file                                                           */
/* ------------------------------------------------------------------------ */

/**
 * Valid entries, one per item (a later entry for the same item replaces an earlier one, in its
 * place), at most {@link WAIVERS_MAX}; the others in `errors` with their index.
 * @param {unknown[]} list
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ waivers: object[], errors: Array<{ index: number, code: string, field?: string|null }> }}
 */
export function sanitizeWaivers(list, { now = Date.now() } = {}) {
  const byId = new Map();
  const errors = [];
  (Array.isArray(list) ? list : []).forEach((entry, index) => {
    const { waiver, error } = validateWaiver(entry, { now });
    if (error) errors.push({ index, ...error });
    else byId.set(waiver.id, waiver);
  });
  const waivers = [...byId.values()];
  if (waivers.length > WAIVERS_MAX) {
    errors.push({ index: WAIVERS_MAX, code: 'too-many', field: null });
    waivers.length = WAIVERS_MAX;
  }
  return { waivers, errors };
}

/**
 * Read a waivers file (or the workspace part): JSON text or a parsed value, `{ format, v, waivers }`
 * or a bare list. `ok` false when nothing could be read (not JSON, not a waivers file, a newer
 * version, too large); the entries that are not valid are left out and said in `errors`.
 * @param {unknown} input
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ ok: boolean, waivers: object[], errors: Array<{ index: number|null, code: string, field?: string|null }> }}
 */
export function parseWaivers(input, { now = Date.now() } = {}) {
  const refused = (code) => ({ ok: false, waivers: [], errors: [{ index: null, code, field: null }] });
  let doc = input;
  if (typeof input === 'string') {
    const text = input.replace(/^\ufeff/, '');
    if (!text.trim()) return { ok: true, waivers: [], errors: [] };
    if (text.length > WAIVERS_MAX_CHARS * 4) return refused('too-large');
    try {
      doc = JSON.parse(text);
    } catch {
      return refused('not-json');
    }
  }
  if (doc === null || doc === undefined) return { ok: true, waivers: [], errors: [] };
  let list;
  if (Array.isArray(doc)) list = doc;
  else if (doc && typeof doc === 'object' && doc.format === WAIVERS_FORMAT && Array.isArray(doc.waivers)) {
    if (Number.isInteger(doc.v) && doc.v > WAIVERS_VERSION) return refused('newer');
    list = doc.waivers;
  } else return refused('not-waivers');
  if (list.length > WAIVERS_MAX * 4) return refused('too-many');
  return { ok: true, ...sanitizeWaivers(list, { now }) };
}

/** Order of a list as it is written: by domain, kind, ref. */
function sorted(list) {
  return [...list].sort((a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0)
    || WAIVER_KINDS.indexOf(a.kind) - WAIVER_KINDS.indexOf(b.kind) || (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
}

const entryOut = (w) => ({ id: w.id, kind: w.kind, domain: w.domain, ref: w.ref, reason: w.reason, owner: w.owner, created: w.created, expires: w.expires });

/**
 * The workspace's `waivers` part: compact JSON of the file's shape, '' for none.
 * @param {object[]} list valid waivers
 * @returns {string}
 * @throws {WaiverError} 'too-large' past {@link WAIVERS_MAX_CHARS}, 'too-many' past {@link WAIVERS_MAX}
 */
export function waiversPartText(list) {
  const waivers = sorted(list || []).map(entryOut);
  if (!waivers.length) return '';
  if (waivers.length > WAIVERS_MAX) throw new WaiverError('too-many');
  const text = JSON.stringify({ format: WAIVERS_FORMAT, v: WAIVERS_VERSION, waivers });
  if (text.length > WAIVERS_MAX_CHARS) throw new WaiverError('too-large');
  return text;
}

/**
 * waivers.json as the Workspaces dialog exports it (the runner's `--waivers` input): indented, the
 * time of the export and the tool, a trailing newline.
 * @param {object[]} list valid waivers
 * @param {{ now?: Date|number, app?: string }} [opts]
 * @returns {string}
 */
export function waiversFileText(list, { now = Date.now(), app = 'DomainScope' } = {}) {
  const doc = { format: WAIVERS_FORMAT, v: WAIVERS_VERSION, app: String(app), exportedAt: new Date(ms(now)).toISOString(), waivers: sorted(list || []).map(entryOut) };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

/**
 * The waivers of the workspace's part (or of any text): the valid ones, read leniently.
 * @param {unknown} text
 * @param {{ now?: Date|number }} [opts]
 * @returns {object[]}
 */
export function readWaivers(text, { now = Date.now() } = {}) {
  return parseWaivers(typeof text === 'string' ? text : '', { now }).waivers;
}

/**
 * A list with one more waiver: the input checked ({@link validateWaiver}, `created` now when it has
 * none, an end date before today refused: it would never apply), a waiver of the same item
 * replaced in its place.
 * @param {object[]} list
 * @param {object} input `{ kind, domain, ref, reason, owner, expires }`
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ list: object[], waiver: object, replaced: boolean }}
 * @throws {WaiverError} the entry's error code
 */
export function addWaiver(list, input, { now = Date.now() } = {}) {
  const { waiver, error } = validateWaiver({ ...input, created: input && input.created ? input.created : new Date(ms(now)).toISOString() }, { now });
  if (error) throw new WaiverError(error.code);
  if (waiver.expires < utcDay(now)) throw new WaiverError('expires');
  const current = Array.isArray(list) ? list : [];
  const replaced = current.some((w) => w.id === waiver.id);
  const next = replaced ? current.map((w) => (w.id === waiver.id ? waiver : w)) : [...current, waiver];
  if (next.length > WAIVERS_MAX) throw new WaiverError('too-many');
  return { list: next, waiver, replaced };
}

/**
 * A list without the waiver `id`.
 * @param {object[]} list
 * @param {string} id
 * @returns {object[]}
 */
export function removeWaiver(list, id) {
  return (Array.isArray(list) ? list : []).filter((w) => w.id !== id);
}

/**
 * A list with an imported file's waivers: each replaces the one of the same item, the rest are added.
 * @param {object[]} list
 * @param {object[]} incoming valid waivers
 * @returns {{ list: object[], added: number, replaced: number }}
 */
export function mergeWaivers(list, incoming) {
  const byId = new Map((Array.isArray(list) ? list : []).map((w) => [w.id, w]));
  let added = 0;
  let replaced = 0;
  for (const w of Array.isArray(incoming) ? incoming : []) {
    if (byId.has(w.id)) replaced += 1;
    else added += 1;
    byId.set(w.id, w);
  }
  return { list: [...byId.values()], added, replaced };
}

/**
 * How many waivers stand where, and the first day an active one ends.
 * @param {object[]} list
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ total: number, active: number, expiring: number, expired: number, next: string|null }}
 *   `active` counts the expiring ones too
 */
export function waiverCounts(list, { now = Date.now() } = {}) {
  const out = { total: 0, active: 0, expiring: 0, expired: 0, next: null };
  for (const w of Array.isArray(list) ? list : []) {
    out.total += 1;
    const s = waiverState(w, { now });
    if (s === 'expired') out.expired += 1;
    else {
      out.active += 1;
      if (s === 'expiring') out.expiring += 1;
      if (!out.next || w.expires < out.next) out.next = w.expires;
    }
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Matching                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * The waiver of an item: an active one first, else an expired one (its item counts again).
 * @param {object[]} list
 * @param {{ kind: string, domain: string, ref?: string|null, refs?: Array<string|null> }} item `refs`:
 *   several refs (a certificate's SHA-256 and its key's), any of them matches
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ waiver: object, active: boolean }|null}
 */
export function matchWaiver(list, item, { now = Date.now() } = {}) {
  if (!item || !Array.isArray(list) || !list.length) return null;
  const refs = (Array.isArray(item.refs) ? item.refs : [item.ref]).map((r) => normalizeRef(item.kind, r)).filter(Boolean);
  const domain = typeof item.domain === 'string' ? normalizeHostname(item.domain) : null;
  if (!refs.length || !domain) return null;
  let expired = null;
  for (const w of list) {
    if (!w || w.kind !== item.kind || w.domain !== domain || !refs.includes(w.ref)) continue;
    if (isWaiverActive(w, { now })) return { waiver: w, active: true };
    if (!expired || w.expires > expired.expires) expired = w;
  }
  return expired ? { waiver: expired, active: false } : null;
}

/**
 * Split items by their waivers: `kept` (no active waiver: they count), `waived` (an active waiver
 * accepts them) and `expired` (kept items whose waiver is over: they count again), in item order.
 * Each item names its `kind` (else `opts.kind`), `domain` and `ref` (or `refs`).
 * @template T
 * @param {T[]} items
 * @param {object[]} list waivers
 * @param {{ now?: Date|number, kind?: string }} [opts]
 * @returns {{ kept: T[], waived: Array<{ item: T, waiver: object }>, expired: Array<{ item: T, waiver: object }> }}
 */
export function applyWaivers(items, list, { now = Date.now(), kind = null } = {}) {
  const out = { kept: [], waived: [], expired: [] };
  for (const item of Array.isArray(items) ? items : []) {
    const m = matchWaiver(list, { ...item, kind: (item && item.kind) || kind }, { now });
    if (m && m.active) {
      out.waived.push({ item, waiver: m.waiver });
      continue;
    }
    out.kept.push(item);
    if (m) out.expired.push({ item, waiver: m.waiver });
  }
  return out;
}

/** Severities a waiver can accept: what costs points or needs a look. */
const WAIVABLE = new Set(['error', 'warn']);
/** Checks a waiver never accepts (lib/healthscore.js FATAL_CHECKS: the name does not exist). */
const NEVER_WAIVED = new Set(['domain.dangling-cname', 'domain.name-missing', 'domain.nxdomain']);

/**
 * Can a Domain Health check be accepted as a risk? An error or a warning, not one that says the name
 * does not exist.
 * @param {{ id?: string, severity?: string }} check
 * @returns {boolean}
 */
export function isWaivableCheck(check) {
  return !!check && typeof check.id === 'string' && WAIVABLE.has(check.severity) && !NEVER_WAIVED.has(check.id);
}

/**
 * The waivers of a Domain Health report: its errors and warnings an active waiver of its domain
 * accepts (`ids`, `applied`), the ones whose waiver is over (`expired`: they count again), and the
 * first day one of the applied waivers ends (`until`).
 * @param {{ domain: string, checks?: object[] }} report lib/health.js domainHealth()
 * @param {object[]} list waivers
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ ids: Set<string>, applied: Array<{ check: object, waiver: object }>, expired: Array<{ check: object, waiver: object }>,
 *   until: string|null, byId: Map<string, object> }} `byId`: check id → its active waiver
 */
export function healthWaivers(report, list, { now = Date.now() } = {}) {
  const checks = (report && Array.isArray(report.checks) ? report.checks : []).filter(isWaivableCheck);
  const domain = report && report.domain;
  const split = applyWaivers(checks.map((c) => ({ kind: 'finding', domain, ref: c.id, check: c })), list, { now });
  const applied = split.waived.map(({ item, waiver }) => ({ check: item.check, waiver }));
  const expired = split.expired.map(({ item, waiver }) => ({ check: item.check, waiver }));
  const byId = new Map(applied.map((a) => [a.check.id, a.waiver]));
  const until = applied.length ? applied.map((a) => a.waiver.expires).sort()[0] : null;
  return { ids: new Set(byId.keys()), applied, expired, until, byId };
}

/* ------------------------------------------------------------------------ */
/* Texts                                                                    */
/* ------------------------------------------------------------------------ */

const STRINGS = [
  ['wvr.kind.finding', ['Finding', 'Bulgu']],
  ['wvr.kind.rule', ['Policy rule', 'Politika kuralı']],
  ['wvr.kind.cert', ['Known certificate', 'Bilinen sertifika']],
  ['wvr.state.active', ['Active', 'Geçerli']],
  ['wvr.state.expiring', ['Ends soon', 'Yakında bitiyor']],
  ['wvr.state.expired', ['Expired', 'Süresi doldu']],

  ['wvr.accept', ['Accept this risk…', 'Bu riski kabul et…']],
  ['wvr.acceptAgain', ['Accept again…', 'Yeniden kabul et…']],
  ['wvr.acceptRule', ['Accept…', 'Kabul et…']],
  ['wvr.acceptRuleTitle', ['Accept that {domain} does not meet {rule}', '{domain} alan adının {rule} kuralına uymamasını kabul et']],
  ['wvr.known', ['Known certificate…', 'Bilinen sertifika…']],
  ['wvr.knownTitle', ['Mark this certificate’s key as expected: it is no longer flagged new or from an unexpected CA', 'Bu sertifikanın anahtarını beklenen olarak işaretle: artık yeni ya da beklenmeyen bir CA’dan diye işaretlenmez']],
  ['wvr.remove', ['Remove', 'Kaldır']],
  ['wvr.removeTitle', ['Remove the accepted risk of {subject}: it counts again', '{subject} için kabul edilen riski kaldır: yeniden hesaba katılır']],
  ['wvr.removed', ['Accepted risk removed: {subject} counts again.', 'Kabul edilen risk kaldırıldı: {subject} yeniden hesaba katılıyor.']],
  ['wvr.saved', ['Accepted until {date}: {subject}.', '{date} tarihine kadar kabul edildi: {subject}.']],
  ['wvr.notSaved', ['Kept on this page only: {reason}.', 'Yalnızca bu sayfada tutuluyor: {reason}.']],

  ['wvr.dialog.title', ['Accept a risk', 'Bir riski kabul et']],
  ['wvr.dialog.titleCert', ['Known certificate', 'Bilinen sertifika']],
  ['wvr.dialog.what', ['What is accepted', 'Kabul edilen']],
  ['wvr.dialog.domain', ['Domain', 'Alan adı']],
  ['wvr.dialog.intro', ['It is left out of the score, the counts, the summary and the report until the end date; then it counts again and is listed as expired. Kept in this workspace and in its hand-over file.',
    'Bitiş tarihine kadar puana, sayılara, özete ve rapora katılmaz; sonra yeniden hesaba katılır ve süresi dolmuş olarak listelenir. Bu çalışma alanında ve devir dosyasında tutulur.']],
  ['wvr.dialog.introCert', ['The CT watch no longer flags this key’s certificates as new or from an unexpected CA until the end date. Its expiry and revocation are still watched.',
    'CT izlemesi, bitiş tarihine kadar bu anahtarın sertifikalarını artık yeni ya da beklenmeyen bir CA’dan diye işaretlemez. Bitiş tarihi ve iptal durumu izlenmeye devam eder.']],
  ['wvr.dialog.reason', ['Reason', 'Gerekçe']],
  ['wvr.dialog.reasonHint', ['Why it is accepted, in a sentence (up to {max} characters).', 'Neden kabul edildiği, tek cümleyle (en fazla {max} karakter).']],
  ['wvr.dialog.reasonCert', ['Our own certificate', 'Kendi sertifikamız']],
  ['wvr.dialog.owner', ['Owner', 'Sorumlu']],
  ['wvr.dialog.ownerHint', ['Who decided, or who looks at it again (up to {max} characters).', 'Kararı veren ya da yeniden bakacak kişi (en fazla {max} karakter).']],
  ['wvr.dialog.expires', ['End date', 'Bitiş tarihi']],
  ['wvr.dialog.expiresHint', ['The last day it applies; at most {days} days ahead.', 'Geçerli olduğu son gün; en fazla {days} gün sonrası.']],
  ['wvr.dialog.save', ['Accept until the end date', 'Bitiş tarihine kadar kabul et']],
  ['wvr.dialog.saveCert', ['Mark as known', 'Bilinen olarak işaretle']],

  ['wvr.err.not-json', ['This file is not JSON.', 'Bu dosya JSON değil.']],
  ['wvr.err.not-waivers', ['This file is not a DomainScope waivers file (waivers.json).', 'Bu dosya bir DomainScope kabul edilen riskler dosyası (waivers.json) değil.']],
  ['wvr.err.newer', ['This file was made by a newer version of DomainScope.', 'Bu dosya DomainScope’un daha yeni bir sürümüyle yapılmış.']],
  ['wvr.err.too-large', ['Too many accepted risks for one workspace (at most {max}, {size} in all).', 'Bir çalışma alanı için çok fazla kabul edilen risk var (en fazla {max}, toplam {size}).']],
  ['wvr.err.too-many', ['Too many accepted risks for one workspace (at most {max}, {size} in all).', 'Bir çalışma alanı için çok fazla kabul edilen risk var (en fazla {max}, toplam {size}).']],
  ['wvr.err.not-object', ['An entry is not an object.', 'Bir kayıt nesne değil.']],
  ['wvr.err.kind', ['The kind is not finding, rule or cert.', 'Tür finding, rule ya da cert değil.']],
  ['wvr.err.domain', ['Not a domain name.', 'Bir alan adı değil.']],
  ['wvr.err.ref', ['Not a check id, a rule id or a SHA-256 of its kind.', 'Türüne uygun bir kontrol kimliği, kural kimliği ya da SHA-256 değil.']],
  ['wvr.err.reason', ['Give a reason (up to {max} characters).', 'Bir gerekçe yazın (en fazla {max} karakter).']],
  ['wvr.err.owner', ['The owner is longer than {max} characters.', 'Sorumlu {max} karakterden uzun.']],
  ['wvr.err.expires', ['Pick the last day it applies.', 'Geçerli olacağı son günü seçin.']],
  ['wvr.err.too-far', ['The end date is more than {days} days ahead.', 'Bitiş tarihi {days} günden daha ileride.']],
  ['wvr.err.created', ['The creation time is not a date.', 'Oluşturulma zamanı bir tarih değil.']],

  ['wvr.line', ['Accepted until {date}: {reason}', '{date} tarihine kadar kabul edildi: {reason}']],
  ['wvr.lineOwner', ['Accepted until {date} by {owner}: {reason}', '{date} tarihine kadar {owner} tarafından kabul edildi: {reason}']],
  ['wvr.expiredLine', ['Accepted risk expired on {date}: it counts again', 'Kabul edilen riskin süresi {date} tarihinde doldu: yeniden hesaba katılıyor']],
  ['wvr.badge', ['Accepted', 'Kabul edildi']],
  ['wvr.badgeUntil', ['Accepted until {date}', '{date} tarihine kadar kabul edildi']],
  ['wvr.badgeExpired', ['Acceptance expired', 'Kabulün süresi doldu']],
  ['wvr.count', [{ one: '{count} accepted risk (until {date})', other: '{count} accepted risks (the first ends {date})' },
    { one: '{count} kabul edilen risk ({date} tarihine kadar)', other: '{count} kabul edilen risk (ilki {date} tarihinde bitiyor)' }]],
  ['wvr.withThem', ['With them the score would be {score}/100 ({grade}).', 'Onlarla birlikte puan {score}/100 ({grade}) olurdu.']],
  ['wvr.expiredCount', [{ one: '{count} accepted risk has expired and counts again.', other: '{count} accepted risks have expired and count again.' },
    { one: '{count} kabul edilen riskin süresi doldu; yeniden hesaba katılıyor.', other: '{count} kabul edilen riskin süresi doldu; yeniden hesaba katılıyor.' }]],
  ['wvr.section', [{ one: '{count} accepted risk', other: '{count} accepted risks' }, '{count} kabul edilen risk']],
  ['wvr.noneOpen', ['No open errors or warnings: every one is an accepted risk.', 'Açık hata ya da uyarı yok: hepsi kabul edilen risk.']],

  ['wvr.whatIf', ['What if you fix…', 'Düzeltirseniz ne olur…']],
  ['wvr.whatIfHint', ['Tick the problems you plan to fix: the score and the grade they would give, by the same formula. Nothing is changed or saved.',
    'Düzeltmeyi planladığınız sorunları işaretleyin: aynı formülle verecekleri puan ve not. Hiçbir şey değişmez ya da kaydedilmez.']],
  ['wvr.whatIfNone', ['Tick a problem to see the projected score.', 'Tahmini puanı görmek için bir sorun işaretleyin.']],
  ['wvr.whatIfResult', [{ one: 'Fixing {count} problem: {from}/100 ({fromGrade}) → {to}/100 ({toGrade})', other: 'Fixing {count} problems: {from}/100 ({fromGrade}) → {to}/100 ({toGrade})' },
    '{count} sorunu düzeltmek: {from}/100 ({fromGrade}) → {to}/100 ({toGrade})']],
  ['wvr.whatIfClear', ['Clear', 'Temizle']],

  ['wvr.ws.title', ['Accepted risks', 'Kabul edilen riskler']],
  ['wvr.ws.hint', ['Findings, policy rules and known certificates accepted in this workspace, each with a reason, an owner and an end date. waivers.json is the headless runner’s --waivers input.',
    'Bu çalışma alanında kabul edilen bulgular, politika kuralları ve bilinen sertifikalar; her birinin gerekçesi, sorumlusu ve bitiş tarihi var. waivers.json, komut satırı çalıştırıcısının --waivers girdisidir.']],
  ['wvr.ws.empty', ['None yet: “Accept this risk…” in Domain Health, “Accept…” in the policy matrix and “Known certificate…” in the CT tab add them here.',
    'Henüz yok: Alan Adı Sağlığı’ndaki “Bu riski kabul et…”, politika matrisindeki “Kabul et…” ve CT sekmesindeki “Bilinen sertifika…” düğmeleri buraya ekler.']],
  ['wvr.ws.counts', ['{active} active · {expiring} end within {days} days · {expired} expired', '{active} geçerli · {expiring} tanesi {days} gün içinde bitiyor · {expired} tanesinin süresi doldu']],
  ['wvr.ws.export', ['Export waivers.json', 'waivers.json dışa aktar']],
  ['wvr.ws.import', ['Import waivers.json', 'waivers.json içe aktar']],
  ['wvr.ws.importHint', ['drop waivers.json here or click to choose', 'waivers.json dosyasını buraya bırakın ya da seçmek için tıklayın']],
  ['wvr.ws.exported', ['{file} saved: {count} accepted risks.', '{file} kaydedildi: {count} kabul edilen risk.']],
  ['wvr.ws.imported', ['{added} added, {replaced} replaced.', '{added} eklendi, {replaced} değiştirildi.']],
  ['wvr.ws.skipped', [{ one: '{count} entry was left out: {reason}', other: '{count} entries were left out; the first: {reason}' },
    { one: '{count} kayıt alınmadı: {reason}', other: '{count} kayıt alınmadı; ilki: {reason}' }]],
  ['wvr.ws.dropExpired', ['Remove the expired ones', 'Süresi dolanları kaldır']],
  ['wvr.ws.until', ['until {date}', '{date} tarihine kadar']],
  ['wvr.ws.expiredOn', ['expired {date}', '{date} tarihinde doldu']],
  ['wvr.ws.removeOne', ['Remove the accepted risk {ref} of {domain}', '{domain} için {ref} kabulünü kaldır']],
  ['wvr.ws.sum', [{ one: '{count} accepted risk', other: '{count} accepted risks' }, '{count} kabul edilen risk']]
];

function buildStrings(lang) {
  return Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));
}

/**
 * English and Turkish texts of every `wvr.*` key: the dialog, the lines and badges, the what-if
 * planner, the Workspaces dialog's part and the errors. Placeholders `{param}`; a text with a count
 * is a plural object.
 * @type {{ en: Record<string, string|object>, tr: Record<string, string|object> }}
 */
export const WAIVERS_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
