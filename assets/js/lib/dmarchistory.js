/**
 * lib/dmarchistory.js — the DMARC report history of a workspace (DMARC & TLS reports › History):
 * an opt-in summary of the aggregate reports dropped into the view, kept in the workspace part
 * `reportHistory` (lib/workspace.js) as the JSON text {@link historyText} writes, so the trend of
 * each domain, the senders that appeared and a roll-up across the workspace's domains outlast the
 * tab. DOM-free and pure: the view (views/reports.js) merges each drop with the classes it gave
 * the sources, ui/report-history.js draws the result.
 *
 * The shape ({@link HISTORY_VERSION}), per reported domain — the domain whose policy the
 * receivers applied (`policy_published`), as lib/dmarcreport.js aggregateDmarc groups the reports,
 * so it covers the header-from names under it:
 *   days     'YYYY-MM-DD' → { msgs, dmarcPass, spfAligned, dkimAligned, quarantine, reject, unknownMsgs, knownFail }
 *            ({@link DAY_FIELDS}): one UTC day, kept {@link HISTORY_DAYS} days. `unknownMsgs`: mail of
 *            unknown senders; `knownFail`: mail of your servers and authorized third parties that
 *            failed DMARC (what stands between the domain and p=reject)
 *   sources  ip → { first, last, msgs, passMsgs, cls, checked?, service, type }: the days it was first and
 *            last seen, its messages and those that passed, its class (lib/dmarcreport.js
 *            SOURCE_CLASSES; `checked` when that came from the domain's current SPF, not from the
 *            reports alone) and the service behind it (lib/senders.js); dropped {@link HISTORY_DAYS}
 *            days after `last`
 *   recent   'YYYY-MM-DD' → ip → [msgs, dmarcPass, spfAligned, dkimAligned, quarantine, reject]
 *            ({@link RECENT_FIELDS}) for the last {@link RECENT_DAYS} days: what lets a later class
 *            (the SPF looked up, the server list changed) correct those days
 *   policy   { p, sp, pct, testing?, seenAt }: the last one published, from the report that ends last
 *   seen     'YYYY-MM-DD' → the reports filed that day, as {@link reportHash}es of 'org|report_id':
 *            kept {@link HISTORY_DAYS} days, so a report dropped again never counts twice
 *   cut      the newest day {@link prune} dropped to fit (null: none): a report filed on or before it
 *            is not taken again
 *   checked  the last day the domain's sources were classified against its current SPF (null: from
 *            the reports' own evidence and the server list only)
 *
 * Rules: a report is filed under the UTC day of its date_range begin; one older than the window or
 * more than a day ahead of the clock is not taken. Over the size cap, {@link prune} drops the
 * oldest recent days first, then the sources with the fewest messages, then the oldest days, each
 * stage only once the one before it has nothing left; every write goes through {@link fitHistory},
 * so no change (a class, a service, the switch) ever takes the text over the cap. Never kept: the
 * report XML, file names, envelope_to, the reporters' contacts and failure-report content; a
 * report's key only as its hash.
 */

import { normalizeHostname } from './domain.js';
import { normalizeIP } from './ip.js';

/** Version of the history's JSON (a text of another version is no history). */
export const HISTORY_VERSION = 1;
/** Days kept: the days, the reports seen, and a source after its last day. */
export const HISTORY_DAYS = 400;
/** Days whose rows are kept per sending address (`recent`), today included. */
export const RECENT_DAYS = 31;
/** Largest history text, in UTF-8 bytes (= lib/workspace.js WORKSPACE_LIMITS.reportHistory, in characters). */
export const HISTORY_MAX_BYTES = 4 * 1024 * 1024;
/** The periods the History tab offers, in days (the last one is everything kept). */
export const HISTORY_PERIODS = Object.freeze([30, 90, 400]);
/** A period longer than this many days is drawn one bar per week. */
export const WEEK_BIN_AFTER = 92;
/** A sender is "new" only once the domain's history covers this many days before it. */
export const NEW_BASELINE_DAYS = 7;
/** …and when it was first seen in the last this many days. */
export const NEW_WINDOW_DAYS = 30;
/** The source classes (lib/dmarcreport.js SOURCE_CLASSES; a unit test keeps them equal). */
export const HISTORY_CLASSES = Object.freeze(['yours', 'third-party', 'forwarder', 'unknown']);
/** The classes whose failing mail would be refused with p=reject (the view's "fix first"). */
export const KNOWN_CLASSES = Object.freeze(['yours', 'third-party']);
/** The policies a day's record keeps. */
export const POLICIES = Object.freeze(['none', 'quarantine', 'reject']);
/** The counts of one day, in their order. */
export const DAY_FIELDS = Object.freeze(['msgs', 'dmarcPass', 'spfAligned', 'dkimAligned', 'quarantine', 'reject', 'unknownMsgs', 'knownFail']);
/** The counts of one sending address on one day (`recent` rows), in their order. */
export const RECENT_FIELDS = Object.freeze(['msgs', 'dmarcPass', 'spfAligned', 'dkimAligned', 'quarantine', 'reject']);
/** A domain's verdict in the roll-up (worst first after no-mail). */
export const ROLLUP_VERDICTS = Object.freeze(['no-mail', 'enforced-losing', 'fix-first', 'ready', 'enforced']);
/** Characters of a service name kept. */
export const SERVICE_MAX = 80;
/** The roll-up's CSV columns ({@link rollupCsvRows}). */
export const ROLLUP_CSV_COLUMNS = Object.freeze([
  'domain', 'messages', 'dmarc_pass', 'compliance_pct', 'unknown_messages', 'unknown_pct', 'known_fail', 'quarantine', 'reject',
  'policy_p', 'policy_sp', 'policy_pct', 'policy_seen', 'verdict', 'reported_days', 'first_day', 'last_day', 'sources', 'new_sources', 'spf_checked'
]);

const DAY_MS = 86400000;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const HASH_RE = /^[0-9a-f]{16}$/;
const TYPE_RE = /^[a-z][a-z-]{0,23}$/;
// C0 / C1 controls, zero-width characters, line / paragraph separators and bidi controls.
// eslint-disable-next-line no-control-regex
const JUNK_RE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g;

/* ------------------------------------------------------------------------ */
/* Days and small helpers                                                   */
/* ------------------------------------------------------------------------ */

const two = (n) => String(n).padStart(2, '0');

/** Milliseconds of a clock value (a Date, a number, a date string; else the real clock). */
function clockMs(now) {
  const n = now instanceof Date ? now.getTime() : typeof now === 'number' ? now : typeof now === 'string' ? Date.parse(now) : NaN;
  return Number.isFinite(n) ? n : Date.now();
}

/**
 * The UTC day of a date as 'YYYY-MM-DD', or null for no date.
 * @param {Date|number|string|null|undefined} value
 * @returns {string|null}
 */
export function dayOf(value) {
  if (value === null || value === undefined || value === '') return null;
  const d = value instanceof Date ? value : new Date(value);
  const ms = d.getTime();
  if (!Number.isFinite(ms)) return null;
  return `${d.getUTCFullYear()}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())}`;
}

/** The instant a day starts (UTC), in ms; NaN for no day. */
const dayStart = (day) => Date.parse(`${day}T00:00:00Z`);

/**
 * Is `s` a real day 'YYYY-MM-DD' (2026-02-30 is not)?
 * @param {unknown} s
 * @returns {boolean}
 */
export function isDay(s) {
  return typeof s === 'string' && DAY_RE.test(s) && dayOf(dayStart(s)) === s;
}

/**
 * A day `n` days after `day` (before it when negative).
 * @param {string} day
 * @param {number} n
 * @returns {string}
 */
export function addDays(day, n) {
  return dayOf(dayStart(day) + n * DAY_MS);
}

/** Whole days from `a` to `b` (both days). */
const daysBetween = (a, b) => Math.round((dayStart(b) - dayStart(a)) / DAY_MS);

const nonNeg = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : 0);
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const isoOrNull = (v) => {
  if (typeof v !== 'string' && !(v instanceof Date)) return null;
  const ms = v instanceof Date ? v.getTime() : Date.parse(v);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
};
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/** A service name as the history keeps it (controls out, whitespace collapsed, capped), or null. */
function cleanText(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.normalize('NFC').replace(JUNK_RE, ' ').replace(/\s+/g, ' ').trim();
  return s ? [...s].slice(0, max).join('').trim() : null;
}

const cleanType = (v) => (typeof v === 'string' && TYPE_RE.test(v) ? v : null);

let encoder = null;

/**
 * UTF-8 bytes of a text (what the size cap counts).
 * @param {string} text
 * @returns {number}
 */
export function utf8Length(text) {
  const s = String(text ?? '');
  // ASCII only (the usual history): one byte a character.
  // eslint-disable-next-line no-control-regex
  if (!/[^\u0000-\u007f]/.test(s)) return s.length;
  encoder = encoder || new TextEncoder();
  return encoder.encode(s).length;
}

/**
 * The hash a report is remembered by: FNV-1a 64 of its key ('org|report_id', lib/dmarcreport.js
 * AggregateReport.key) as 16 hex digits, so the history holds neither the reporter nor the id.
 * @param {string} key
 * @returns {string}
 */
export function reportHash(key) {
  encoder = encoder || new TextEncoder();
  let h = 0xcbf29ce484222325n;
  for (const b of encoder.encode(String(key ?? ''))) {
    h ^= BigInt(b);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

/* ------------------------------------------------------------------------ */
/* The shape: empty values and reading a stored text                        */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {{ msgs: number, dmarcPass: number, spfAligned: number, dkimAligned: number, quarantine: number,
 *   reject: number, unknownMsgs: number, knownFail: number }} HistoryDay
 * @typedef {{ first: string, last: string, msgs: number, passMsgs: number, cls: string|null, checked?: boolean,
 *   service: string|null, type: string|null }} HistorySource
 * @typedef {{ p: string, sp: string, pct: number, testing?: string, seenAt: string }} HistoryPolicy
 * @typedef {{ days: Record<string, HistoryDay>, sources: Record<string, HistorySource>,
 *   recent: Record<string, Record<string, number[]>>, policy: HistoryPolicy|null, seen: Record<string, string[]>,
 *   cut: string|null, checked: string|null }} HistoryDomain
 * @typedef {{ v: number, keep: boolean, updatedAt: string|null, domains: Record<string, HistoryDomain> }} History
 */

/**
 * An empty history.
 * @param {{ keep?: boolean }} [opts] `keep`: the switch "Keep a summary of these reports in this workspace"
 * @returns {History}
 */
export function emptyHistory({ keep = false } = {}) {
  return { v: HISTORY_VERSION, keep: !!keep, updatedAt: null, domains: {} };
}

/** @returns {HistoryDomain} */
function emptyDomain() {
  return { days: {}, sources: {}, recent: {}, policy: null, seen: {}, cut: null, checked: null };
}

/** @returns {HistoryDay} */
function zeroDay() {
  return Object.fromEntries(DAY_FIELDS.map((f) => [f, 0]));
}

/** A day's counts, each a non-negative integer, none more than the day's messages. */
function cleanDay(raw) {
  const d = zeroDay();
  for (const f of DAY_FIELDS) d[f] = nonNeg(raw && raw[f]);
  for (const f of ['dmarcPass', 'spfAligned', 'dkimAligned', 'quarantine', 'reject', 'unknownMsgs']) d[f] = Math.min(d[f], d.msgs);
  d.knownFail = Math.min(d.knownFail, d.msgs - d.dmarcPass);
  return d;
}

/** A recent row: six non-negative integers, none more than its messages; null when it is not one. */
function cleanRow(raw) {
  if (!Array.isArray(raw) || raw.length !== RECENT_FIELDS.length) return null;
  const r = raw.map(nonNeg);
  for (let i = 1; i < r.length; i += 1) r[i] = Math.min(r[i], r[0]);
  return r;
}

function cleanSource(raw) {
  if (!isObject(raw) || !isDay(raw.first) || !isDay(raw.last) || raw.first > raw.last) return null;
  const msgs = nonNeg(raw.msgs);
  const s = {
    first: raw.first,
    last: raw.last,
    msgs,
    passMsgs: Math.min(nonNeg(raw.passMsgs), msgs),
    cls: HISTORY_CLASSES.includes(raw.cls) ? raw.cls : null,
    service: cleanText(raw.service, SERVICE_MAX),
    type: null
  };
  if (s.cls && raw.checked === true) s.checked = true;
  s.type = s.service ? cleanType(raw.type) : null;
  return s;
}

function cleanPolicy(raw) {
  if (!isObject(raw) || !POLICIES.includes(raw.p)) return null;
  const pct = Number.isSafeInteger(raw.pct) ? clamp(raw.pct, 0, 100) : 100;
  const out = { p: raw.p, sp: POLICIES.includes(raw.sp) ? raw.sp : raw.p, pct, seenAt: isoOrNull(raw.seenAt) };
  if (!out.seenAt) return null;
  if (raw.testing === 'y') out.testing = 'y';
  return out;
}

/**
 * A history as stored (a stored text parsed, a value from a file): every entry checked on its
 * own and dropped when it is not one, never trusted. Another version is no history.
 * @param {unknown} data
 * @returns {History}
 */
export function sanitizeHistory(data) {
  const out = emptyHistory();
  if (!isObject(data) || data.v !== HISTORY_VERSION) return out;
  out.keep = data.keep === true;
  out.updatedAt = isoOrNull(data.updatedAt);
  for (const [name, raw] of Object.entries(isObject(data.domains) ? data.domains : {})) {
    if (normalizeHostname(name) !== name || !isObject(raw)) continue;
    const d = emptyDomain();
    for (const [day, v] of Object.entries(isObject(raw.days) ? raw.days : {})) if (isDay(day) && isObject(v)) d.days[day] = cleanDay(v);
    for (const [ip, v] of Object.entries(isObject(raw.sources) ? raw.sources : {})) {
      const s = normalizeIP(ip) === ip ? cleanSource(v) : null;
      if (s) d.sources[ip] = s;
    }
    for (const [day, rows] of Object.entries(isObject(raw.recent) ? raw.recent : {})) {
      if (!isDay(day) || !isObject(rows)) continue;
      const kept = {};
      for (const [ip, row] of Object.entries(rows)) {
        const r = normalizeIP(ip) === ip ? cleanRow(row) : null;
        if (r) kept[ip] = r;
      }
      if (Object.keys(kept).length) d.recent[day] = kept;
    }
    d.policy = cleanPolicy(raw.policy);
    for (const [day, list] of Object.entries(isObject(raw.seen) ? raw.seen : {})) {
      if (!isDay(day) || !Array.isArray(list)) continue;
      const hashes = [...new Set(list.filter((x) => typeof x === 'string' && HASH_RE.test(x)))];
      if (hashes.length) d.seen[day] = hashes;
    }
    d.cut = isDay(raw.cut) ? raw.cut : null;
    d.checked = isDay(raw.checked) ? raw.checked : null;
    if (Object.keys(d.days).length || Object.keys(d.sources).length || Object.keys(d.seen).length) out.domains[name] = d;
  }
  return out;
}

/**
 * The history in the workspace's text (lib/workspace.js part `reportHistory`): another version,
 * broken JSON or a stray value is no history (empty, the switch off).
 * @param {unknown} text
 * @returns {History}
 */
export function readHistory(text) {
  let data = null;
  try {
    data = typeof text === 'string' && text.trim() ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  return sanitizeHistory(data);
}

/** The keys of an object sorted, as a new object (a stable text, a readable hand-over file). */
const sortedObject = (o, map = (v) => v) => Object.fromEntries(Object.keys(o).sort().map((k) => [k, map(o[k], k)]));

/** A domain as the text holds it: its parts in order, their keys sorted. */
const domainShape = (d) => ({
  days: sortedObject(d.days),
  sources: sortedObject(d.sources),
  recent: sortedObject(d.recent, (rows) => sortedObject(rows)),
  policy: d.policy,
  seen: sortedObject(d.seen, (list) => [...list].sort()),
  cut: d.cut || null,
  checked: d.checked || null
});

/**
 * The history as the workspace keeps it: JSON with its keys in order (days and domains sorted),
 * '' when there is nothing to keep (the switch off and no domain).
 * @param {History} history
 * @returns {string}
 */
export function historyText(history) {
  const h = history || emptyHistory();
  const domains = Object.keys(h.domains || {});
  if (!h.keep && !domains.length) return '';
  return JSON.stringify({
    v: HISTORY_VERSION,
    keep: !!h.keep,
    updatedAt: h.updatedAt || null,
    domains: sortedObject(h.domains, domainShape)
  });
}

/** A deep copy (the history is plain JSON). */
function copyHistory(history) {
  const h = history && isObject(history) ? history : emptyHistory();
  return typeof structuredClone === 'function' ? structuredClone(h) : JSON.parse(JSON.stringify(h));
}

/**
 * The switch turned on or off. Off writes nothing new; what is kept stays until it is forgotten.
 * @param {History} history
 * @param {boolean} on
 * @returns {History} a new history
 */
export function setKeep(history, on) {
  const h = copyHistory(history);
  h.keep = !!on;
  return h;
}

/**
 * Every domain forgotten; the switch stays as it was.
 * @param {History} history
 * @param {{ now?: Date|number }} [opts]
 * @returns {History}
 */
export function forgetHistory(history, { now = Date.now() } = {}) {
  const h = emptyHistory({ keep: !!(history && history.keep) });
  h.updatedAt = new Date(clockMs(now)).toISOString();
  return h;
}

/* ------------------------------------------------------------------------ */
/* Merging the reports of a drop                                            */
/* ------------------------------------------------------------------------ */

/**
 * @callback HistoryClassify the class and service the view gives a source of a domain now
 * @param {string} domain
 * @param {string} ip
 * @returns {{ cls?: string|null, service?: string|null, type?: string|null, provisional?: boolean }|null}
 *   `provisional`: classed without the domain's current SPF (from the reports and the server list):
 *   it fills a class the history does not have, or one it had from the same kind of evidence,
 *   never one the SPF decided
 */

/** What a recent row adds to its day's unknown mail and known failures under a class. */
function share(cls, row) {
  return {
    unknown: cls === 'unknown' ? row[0] : 0,
    known: KNOWN_CLASSES.includes(cls) ? row[0] - row[1] : 0
  };
}

/** A source moved from class `from` to `to`: its rows of the recent days move with it. */
function shiftRecent(d, ip, from, to) {
  for (const [day, rows] of Object.entries(d.recent)) {
    const row = rows[ip];
    const entry = d.days[day];
    if (!row || !entry) continue;
    const a = share(from, row);
    const b = share(to, row);
    entry.unknownMsgs = clamp(entry.unknownMsgs - a.unknown + b.unknown, 0, entry.msgs);
    entry.knownFail = clamp(entry.knownFail - a.known + b.known, 0, entry.msgs - entry.dmarcPass);
  }
}

/**
 * Apply what `classify` says of a source the history holds: its class (with its recent days), its
 * service. A provisional class never replaces one the SPF decided; a service is never erased.
 * @returns {boolean} something changed
 */
function applyClass(d, ip, c, today) {
  const s = d.sources[ip];
  if (!s || !c || typeof c !== 'object') return false;
  let changed = false;
  const cls = HISTORY_CLASSES.includes(c.cls) ? c.cls : null;
  const strong = !c.provisional;
  // A provisional class (the reports and the server list only) never replaces one the SPF decided.
  if (cls && (strong || !s.checked)) {
    if (cls !== s.cls) {
      shiftRecent(d, ip, s.cls, cls);
      s.cls = cls;
      changed = true;
    }
    if (strong && !s.checked) {
      s.checked = true;
      changed = true;
    }
  }
  if (cls && strong && d.checked !== today) {
    d.checked = today;
    changed = true;
  }
  const service = cleanText(c.service, SERVICE_MAX);
  if (service) {
    const type = cleanType(c.type);
    if (service !== s.service || type !== s.type) {
      s.service = service;
      s.type = type;
      changed = true;
    }
  }
  return changed;
}

/** Add a count to a list of counts in place. */
function addTo(target, key, n) {
  if (n) target[key] += n;
}

/**
 * Merge parsed aggregate reports into a history (the view: the reports of a drop, or every report
 * of the tab when the switch is turned on). Each report is filed under the UTC day of its
 * date_range begin; one the history has seen (its {@link reportHash}) counts once, one older than
 * {@link HISTORY_DAYS} days, more than a day ahead of `now`, or on a day {@link prune} cut is not
 * taken. Every record adds to its day, its source (first / last day, messages) and, in the last
 * {@link RECENT_DAYS} days, its recent row; the class `classify` gives the source decides whether
 * its mail counts as an unknown sender's or as a known source that fails. The policy of the report
 * that ends last is the domain's. Does not cap the size: {@link prune} does.
 * @param {History} history
 * @param {Array<import('./dmarcreport.js').AggregateReport>} reports TLS reports and anything else are skipped
 * @param {{ now?: Date|number, classify?: HistoryClassify|null }} [opts]
 * @returns {{ history: History, merged: number, duplicates: number, skipped: { old: number, future: number, cut: number, invalid: number },
 *   domains: string[] }} a new history; `domains`: those a report was merged into
 */
export function mergeReports(history, reports, { now = Date.now(), classify = null } = {}) {
  const h = copyHistory(history);
  const nowMs = clockMs(now);
  const today = dayOf(nowMs);
  const oldest = addDays(today, -(HISTORY_DAYS - 1));
  const latest = addDays(today, 1);
  const recentFrom = addDays(today, -(RECENT_DAYS - 1));
  const skipped = { old: 0, future: 0, cut: 0, invalid: 0 };
  let merged = 0;
  let duplicates = 0;
  const touched = new Set();
  const seenSets = new Map();
  // One class per source per call: classify is asked once, its class applied (with its recent days) once.
  const classed = new Set();
  for (const r of Array.isArray(reports) ? reports : []) {
    if (!r || r.kind !== 'dmarc') continue;
    const domain = normalizeHostname(String((r.policy && r.policy.domain) || ''));
    const day = dayOf(r.begin);
    if (!domain || !day || !Array.isArray(r.records)) {
      skipped.invalid += 1;
      continue;
    }
    if (day < oldest) {
      skipped.old += 1;
      continue;
    }
    if (day > latest) {
      skipped.future += 1;
      continue;
    }
    const existing = hasOwn(h.domains, domain) ? h.domains[domain] : null;
    if (existing && existing.cut && day <= existing.cut) {
      skipped.cut += 1;
      continue;
    }
    const d = existing || emptyDomain();
    if (!seenSets.has(domain)) seenSets.set(domain, new Set(Object.values(d.seen).flat()));
    const seen = seenSets.get(domain);
    const hash = reportHash(r.key);
    if (seen.has(hash)) {
      duplicates += 1;
      continue;
    }
    if (!existing) h.domains[domain] = d;
    seen.add(hash);
    (d.seen[day] = d.seen[day] || []).push(hash);
    merged += 1;
    touched.add(domain);
    const entry = d.days[day] || (d.days[day] = zeroDay());
    for (const rec of r.records) {
      const ip = normalizeIP(String((rec && rec.ip) || ''));
      const count = nonNeg(rec && rec.count);
      if (!ip) continue;
      let s = d.sources[ip];
      if (!s) {
        s = { first: day, last: day, msgs: 0, passMsgs: 0, cls: null, service: null, type: null };
        d.sources[ip] = s;
      } else {
        if (day < s.first) s.first = day;
        if (day > s.last) s.last = day;
      }
      const key = `${domain}\n${ip}`;
      if (!classed.has(key)) {
        classed.add(key);
        if (typeof classify === 'function') applyClass(d, ip, classify(domain, ip), today);
      }
      const pass = rec.dkim === 'pass' || rec.spf === 'pass';
      const row = [count, pass ? count : 0, rec.spf === 'pass' ? count : 0, rec.dkim === 'pass' ? count : 0,
        rec.disposition === 'quarantine' ? count : 0, rec.disposition === 'reject' ? count : 0];
      addTo(entry, 'msgs', row[0]);
      addTo(entry, 'dmarcPass', row[1]);
      addTo(entry, 'spfAligned', row[2]);
      addTo(entry, 'dkimAligned', row[3]);
      addTo(entry, 'quarantine', row[4]);
      addTo(entry, 'reject', row[5]);
      const sh = share(s.cls, row);
      addTo(entry, 'unknownMsgs', sh.unknown);
      addTo(entry, 'knownFail', sh.known);
      s.msgs += count;
      s.passMsgs += row[1];
      if (day >= recentFrom) {
        const rows = d.recent[day] || (d.recent[day] = {});
        const prev = rows[ip];
        rows[ip] = prev ? prev.map((v, i) => v + row[i]) : row;
      }
    }
    const p = r.policy || {};
    const end = r.end instanceof Date && Number.isFinite(r.end.getTime()) ? r.end : null;
    if (POLICIES.includes(p.p) && end && (!d.policy || end.getTime() > Date.parse(d.policy.seenAt))) {
      d.policy = { p: p.p, sp: POLICIES.includes(p.sp) ? p.sp : p.p, pct: Number.isSafeInteger(p.pct) ? clamp(p.pct, 0, 100) : 100, seenAt: end.toISOString() };
      if (p.testing === 'y') d.policy.testing = 'y';
    }
  }
  if (merged) h.updatedAt = new Date(nowMs).toISOString();
  return { history: h, merged, duplicates, skipped, domains: [...touched].sort() };
}

/**
 * The view classified the sources again (the domain's SPF landed, the server list changed, Identify
 * senders named more of them): their classes and services in the history follow, and the recent
 * days of a source whose class changed are corrected (older days keep the classes they were kept
 * with). A provisional class never replaces one the SPF decided.
 * @param {History} history
 * @param {HistoryClassify} classify
 * @param {{ now?: Date|number, domains?: string[] }} [opts] `domains`: only these (default: every one)
 * @returns {{ history: History, changed: boolean }} the same history object when nothing changed
 */
export function reclassify(history, classify, { now = Date.now(), domains = null } = {}) {
  if (typeof classify !== 'function' || !history || !isObject(history.domains)) return { history, changed: false };
  const today = dayOf(clockMs(now));
  const names = (domains || Object.keys(history.domains)).filter((n) => hasOwn(history.domains, n));
  // Ask first, copy only when something will change.
  const verdicts = names.map((name) => [name, Object.keys(history.domains[name].sources).map((ip) => [ip, classify(name, ip)]).filter(([, c]) => c)]);
  if (!verdicts.some(([, list]) => list.length)) return { history, changed: false };
  const h = copyHistory(history);
  let changed = false;
  for (const [name, list] of verdicts) {
    const d = h.domains[name];
    for (const [ip, c] of list) if (applyClass(d, ip, c, today)) changed = true;
  }
  return changed ? { history: h, changed } : { history, changed };
}

/* ------------------------------------------------------------------------ */
/* Keeping it small                                                         */
/* ------------------------------------------------------------------------ */

/**
 * The UTF-8 bytes an entry takes in its object's text: "key":value, and the comma that goes with
 * it unless it was the object's last entry (`last`).
 */
const weight = (key, value, last) => utf8Length(JSON.stringify(key)) + utf8Length(JSON.stringify(value)) + (last ? 1 : 2);

/**
 * Keep the history within its window and its size: days, reports seen and sources older than
 * {@link HISTORY_DAYS} days (a source by its last day) and recent rows older than
 * {@link RECENT_DAYS} days go; then, while its text is over `maxBytes`, the oldest recent days
 * (every domain's at once), then the sources with the fewest messages, then the oldest days with
 * the reports filed on them (the domain's `cut` moves, so those reports are not taken again). A
 * stage goes on until the text fits, and the next one starts only when it has nothing left: no
 * source goes while a recent day is kept, no day while a source is. With the switch on, a byte is
 * left for turning it off ("false" is a byte longer than "true"). A domain with nothing left goes.
 * @param {History} history
 * @param {{ now?: Date|number, maxBytes?: number }} [opts]
 * @returns {{ history: History, dropped: { recentDays: number, sources: number, days: number, domains: number }, bytes: number, text: string }}
 *   `text`: {@link historyText} of the history; `bytes`: its UTF-8 length
 */
export function prune(history, { now = Date.now(), maxBytes = HISTORY_MAX_BYTES } = {}) {
  const h = copyHistory(history);
  const today = dayOf(clockMs(now));
  const oldest = addDays(today, -(HISTORY_DAYS - 1));
  const recentFrom = addDays(today, -(RECENT_DAYS - 1));
  const dropped = { recentDays: 0, sources: 0, days: 0, domains: 0 };
  const entries = () => Object.entries(h.domains);
  const isEmpty = (d) => !Object.keys(d.days).length && !Object.keys(d.sources).length && !Object.keys(d.seen).length;
  for (const [name, d] of entries()) {
    for (const day of Object.keys(d.days)) if (day < oldest) delete d.days[day];
    for (const day of Object.keys(d.seen)) if (day < oldest) delete d.seen[day];
    for (const day of Object.keys(d.recent)) if (day < recentFrom) delete d.recent[day];
    for (const [ip, s] of Object.entries(d.sources)) if (s.last < oldest) delete d.sources[ip];
    if (d.cut && d.cut < oldest) d.cut = null;
    if (isEmpty(d)) {
      delete h.domains[name];
      dropped.domains += 1;
    }
  }
  const limit = Math.max(0, (Number(maxBytes) || 0) - (h.keep ? 1 : 0));
  let text = historyText(h);
  let bytes = utf8Length(text);
  // A stage counts what it drops (`est`, exact) and measures the text once a round.
  const measure = () => {
    text = historyText(h);
    bytes = utf8Length(text);
  };
  // The entries each domain has left in one of its parts: true when the one taken was the last.
  const counts = (part) => new Map(entries().map(([, d]) => [d, Object.keys(d[part]).length]));
  const take = (left, d) => {
    const n = left.get(d);
    left.set(d, n - 1);
    return n === 1;
  };
  // A domain left with nothing goes, with its comma unless it was the last.
  const dropDomain = (name, d) => {
    const w = weight(name, domainShape(d), Object.keys(h.domains).length === 1);
    delete h.domains[name];
    dropped.domains += 1;
    return w;
  };
  // 1. The oldest recent days, every domain's at once.
  while (bytes > limit) {
    const days = [...new Set(entries().flatMap(([, d]) => Object.keys(d.recent)))].sort();
    if (!days.length) break;
    const left = counts('recent');
    let est = bytes;
    for (const day of days) {
      if (est <= limit) break;
      for (const [, d] of entries()) {
        if (!d.recent[day]) continue;
        est -= weight(day, d.recent[day], take(left, d));
        delete d.recent[day];
      }
      dropped.recentDays += 1;
    }
    measure();
  }
  // 2. The sources with the fewest messages (the least recently seen first among equals); no
  //    recent row is left by now.
  while (bytes > limit) {
    const all = entries().flatMap(([name, d]) => Object.entries(d.sources).map(([ip, s]) => ({ name, d, ip, s })));
    if (!all.length) break;
    all.sort((a, b) => a.s.msgs - b.s.msgs || (a.s.last < b.s.last ? -1 : a.s.last > b.s.last ? 1 : 0) || (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0));
    const left = counts('sources');
    let est = bytes;
    for (const { name, d, ip, s } of all) {
      if (est <= limit) break;
      const last = take(left, d);
      est -= weight(ip, s, last);
      delete d.sources[ip];
      dropped.sources += 1;
      if (last && isEmpty(d)) est -= dropDomain(name, d);
    }
    measure();
  }
  // 3. The oldest days with the reports filed on them, every domain's at once (no source is left
  //    by now): the domain's cut moves past them, and a domain with nothing left goes.
  while (bytes > limit) {
    const days = [...new Set(entries().flatMap(([, d]) => [...Object.keys(d.days), ...Object.keys(d.seen)]))].sort();
    if (!days.length) break;
    const daysLeft = counts('days');
    const seenLeft = counts('seen');
    let est = bytes;
    for (const day of days) {
      if (est <= limit) break;
      for (const [name, d] of entries()) {
        if (!d.days[day] && !d.seen[day]) continue;
        if (d.days[day]) {
          est -= weight(day, d.days[day], take(daysLeft, d));
          delete d.days[day];
        }
        if (d.seen[day]) {
          est -= weight(day, d.seen[day], take(seenLeft, d));
          delete d.seen[day];
        }
        if (!d.cut || day > d.cut) {
          est += utf8Length(JSON.stringify(day)) - utf8Length(JSON.stringify(d.cut || null));
          d.cut = day;
        }
        if (!daysLeft.get(d) && !seenLeft.get(d) && isEmpty(d)) est -= dropDomain(name, d);
      }
      dropped.days += 1;
    }
    measure();
  }
  return { history: h, dropped, bytes, text };
}

/**
 * The text the workspace keeps of a history (lib/workspace.js part `reportHistory`, kept whole or
 * not at all): {@link historyText}, pruned first ({@link prune}) when it is over `maxBytes`. Every
 * write goes through here, so a change that makes the text longer — the sources classed against
 * the SPF (`checked`), the services Identify senders named, the switch turned off — trims the
 * history instead of losing all of it.
 * @param {History} history
 * @param {{ now?: Date|number, maxBytes?: number }} [opts]
 * @returns {{ history: History, text: string, dropped: { recentDays: number, sources: number, days: number, domains: number }|null }}
 *   `history`: the one `text` is of (the same object when it fit); `dropped`: what {@link prune} dropped, null when it fit
 */
export function fitHistory(history, { now = Date.now(), maxBytes = HISTORY_MAX_BYTES } = {}) {
  const text = historyText(history);
  if (utf8Length(text) <= Math.max(0, Number(maxBytes) || 0)) return { history, text, dropped: null };
  const p = prune(history, { now, maxBytes });
  return { history: p.history, text: p.text, dropped: p.dropped };
}

/* ------------------------------------------------------------------------ */
/* Reading it back: the trend, new senders, the roll-up                     */
/* ------------------------------------------------------------------------ */

/**
 * The domains of a history, the most mail kept first.
 * @param {History} history
 * @returns {Array<{ domain: string, msgs: number, first: string|null, last: string|null }>}
 */
export function historyDomains(history) {
  const out = [];
  for (const [domain, d] of Object.entries((history && history.domains) || {})) {
    const days = Object.keys(d.days).sort();
    out.push({ domain, msgs: days.reduce((n, day) => n + d.days[day].msgs, 0), first: days[0] || null, last: days[days.length - 1] || null });
  }
  return out.sort((a, b) => b.msgs - a.msgs || (a.domain < b.domain ? -1 : 1));
}

/**
 * What a history holds, in a few numbers (the switch's line, a workspace file's summary).
 * @param {History} history
 * @returns {{ keep: boolean, domains: number, days: number, sources: number, reports: number, first: string|null, last: string|null }}
 */
export function historySummary(history) {
  const out = { keep: !!(history && history.keep), domains: 0, days: 0, sources: 0, reports: 0, first: null, last: null };
  const allDays = new Set();
  for (const d of Object.values((history && history.domains) || {})) {
    out.domains += 1;
    out.sources += Object.keys(d.sources).length;
    out.reports += Object.values(d.seen).reduce((n, list) => n + list.length, 0);
    for (const day of Object.keys(d.days)) allDays.add(day);
  }
  const sorted = [...allDays].sort();
  out.days = sorted.length;
  out.first = sorted[0] || null;
  out.last = sorted[sorted.length - 1] || null;
  return out;
}

/** The sums of a list of days. */
function sumDays(list) {
  const t = zeroDay();
  for (const x of list) for (const f of DAY_FIELDS) t[f] += x[f];
  return t;
}

/** Shares of a sum: compliance and the unknown senders' share, null without mail. */
const shares = (t) => ({
  compliance: t.msgs ? t.dmarcPass / t.msgs : null,
  unknownShare: t.msgs ? t.unknownMsgs / t.msgs : null
});

/**
 * @typedef {object} TrendSlot one bar: a day, or a week
 * @property {string} day its first day
 * @property {string} to its last day
 * @property {number} reportedDays the days of it with a report (0: no report, not "no mail")
 * @property {number|null} compliance
 * @property {number|null} unknownShare
 */

/**
 * A domain's trend over the last `days` days up to today (UTC): one slot per day, or per week
 * (the last slot ends today; the first may be shorter) for a period over {@link WEEK_BIN_AFTER}
 * days, with the day's counts ({@link DAY_FIELDS}), and the period's totals.
 * @param {History} history
 * @param {string} domain
 * @param {{ days?: number, now?: Date|number, bin?: 'day'|'week' }} [opts]
 * @returns {{ domain: string, from: string, to: string, bin: 'day'|'week', slots: Array<TrendSlot & HistoryDay>,
 *   totals: HistoryDay & { reportedDays: number, compliance: number|null, unknownShare: number|null, first: string|null, last: string|null },
 *   last: string|null }} `totals.first` / `.last`: the first and last day with a report in the period; `last`: the domain's last day of all
 */
export function trend(history, domain, { days = HISTORY_PERIODS[0], now = Date.now(), bin = null } = {}) {
  const span = clamp(Math.floor(Number(days)) || HISTORY_PERIODS[0], 1, HISTORY_DAYS);
  const to = dayOf(clockMs(now));
  const from = addDays(to, -(span - 1));
  const d = history && history.domains && hasOwn(history.domains, domain) ? history.domains[domain] : null;
  const kind = bin === 'day' || bin === 'week' ? bin : span > WEEK_BIN_AFTER ? 'week' : 'day';
  const width = kind === 'week' ? 7 : 1;
  const count = Math.ceil(span / width);
  const slots = [];
  for (let i = count - 1; i >= 0; i -= 1) {
    const end = addDays(to, -i * width);
    const startRaw = addDays(end, -(width - 1));
    const start = startRaw < from ? from : startRaw;
    const list = [];
    for (let day = start; day <= end; day = addDays(day, 1)) if (d && d.days[day]) list.push(d.days[day]);
    const sum = sumDays(list);
    slots.push({ day: start, to: end, reportedDays: list.length, ...sum, ...shares(sum) });
  }
  const inPeriod = d ? Object.keys(d.days).filter((day) => day >= from && day <= to).sort() : [];
  const totals = sumDays(inPeriod.map((day) => d.days[day]));
  const allDays = d ? Object.keys(d.days).sort() : [];
  return {
    domain,
    from,
    to,
    bin: kind,
    slots,
    totals: { ...totals, reportedDays: inPeriod.length, ...shares(totals), first: inPeriod[0] || null, last: inPeriod[inPeriod.length - 1] || null },
    last: allDays[allDays.length - 1] || null
  };
}

/**
 * The day from which a domain's senders count as new: {@link NEW_WINDOW_DAYS} days before today,
 * but never before the history of the domain has covered {@link NEW_BASELINE_DAYS} days (the first
 * drop does not call every sender new). Null when that day is still to come.
 * @param {History} history
 * @param {string} domain
 * @param {{ now?: Date|number }} [opts]
 * @returns {string|null}
 */
export function newSince(history, domain, { now = Date.now() } = {}) {
  const d = history && history.domains && hasOwn(history.domains, domain) ? history.domains[domain] : null;
  if (!d) return null;
  const firsts = [...Object.keys(d.days), ...Object.values(d.sources).map((s) => s.first)].sort();
  if (!firsts.length) return null;
  const today = dayOf(clockMs(now));
  const baseline = addDays(firsts[0], NEW_BASELINE_DAYS);
  const window = addDays(today, -(NEW_WINDOW_DAYS - 1));
  const since = baseline > window ? baseline : window;
  return since > today ? null : since;
}

/**
 * The senders of a domain first seen on or after `since`, the newest first (then the most mail).
 * @param {History} history
 * @param {string} domain
 * @param {string|null} since a day ({@link newSince}); null: none
 * @returns {Array<HistorySource & { ip: string }>}
 */
export function newSources(history, domain, since) {
  const d = history && history.domains && hasOwn(history.domains, domain) ? history.domains[domain] : null;
  if (!d || !isDay(since)) return [];
  return Object.entries(d.sources).filter(([, s]) => s.first >= since).map(([ip, s]) => ({ ip, ...s }))
    .sort((a, b) => (a.first < b.first ? 1 : a.first > b.first ? -1 : 0) || b.msgs - a.msgs || (a.ip < b.ip ? -1 : 1));
}

/**
 * Every sender of a domain, with whether it is new (first seen on or after `since`): the most mail first.
 * @param {History} history
 * @param {string} domain
 * @param {{ since?: string|null }} [opts]
 * @returns {Array<HistorySource & { ip: string, isNew: boolean }>}
 */
export function historySources(history, domain, { since = null } = {}) {
  const d = history && history.domains && hasOwn(history.domains, domain) ? history.domains[domain] : null;
  if (!d) return [];
  return Object.entries(d.sources).map(([ip, s]) => ({ ip, ...s, isNew: isDay(since) && s.first >= since }))
    .sort((a, b) => b.msgs - a.msgs || (a.ip < b.ip ? -1 : 1));
}

/**
 * A domain's verdict in the roll-up, as the DMARC tab words its own: no mail; p=reject in force
 * (100 %, not in test mode) with or without mail of known sources refused; known sources that fail
 * (fix them first); else ready for p=reject (only unknown senders would be turned away).
 * @param {{ msgs: number, knownFail: number, policy: HistoryPolicy|null }} row
 * @returns {'no-mail'|'enforced-losing'|'fix-first'|'ready'|'enforced'}
 */
export function rollupVerdict(row) {
  if (!row || !row.msgs) return 'no-mail';
  const p = row.policy;
  const enforced = !!p && p.p === 'reject' && p.pct === 100 && !p.testing;
  if (enforced) return row.knownFail > 0 ? 'enforced-losing' : 'enforced';
  return row.knownFail > 0 ? 'fix-first' : 'ready';
}

/**
 * The roll-up across the workspace's domains over the last `days` days: volume, compliance, the
 * unknown senders' share, the known sources' failures, the policy last published, the senders seen
 * in the period and the new ones, and the verdict; the most mail first. `totals`: every domain.
 * @param {History} history
 * @param {{ now?: Date|number, days?: number }} [opts]
 * @returns {{ from: string, to: string, rows: object[], totals: HistoryDay & { domains: number, compliance: number|null, unknownShare: number|null } }}
 */
export function rollup(history, { now = Date.now(), days = HISTORY_PERIODS[0] } = {}) {
  const span = clamp(Math.floor(Number(days)) || HISTORY_PERIODS[0], 1, HISTORY_DAYS);
  const to = dayOf(clockMs(now));
  const from = addDays(to, -(span - 1));
  const rows = [];
  for (const [domain, d] of Object.entries((history && history.domains) || {})) {
    const inPeriod = Object.keys(d.days).filter((day) => day >= from && day <= to).sort();
    const sum = sumDays(inPeriod.map((day) => d.days[day]));
    const all = Object.keys(d.days).sort();
    const since = newSince(history, domain, { now });
    const sources = Object.values(d.sources);
    const row = {
      domain,
      ...sum,
      ...shares(sum),
      reportedDays: inPeriod.length,
      first: inPeriod[0] || null,
      last: all[all.length - 1] || null,
      policy: d.policy,
      sources: sources.filter((s) => s.last >= from).length,
      newSources: since ? sources.filter((s) => s.first >= since).length : 0,
      checked: d.checked
    };
    row.verdict = rollupVerdict(row);
    rows.push(row);
  }
  rows.sort((a, b) => b.msgs - a.msgs || (a.domain < b.domain ? -1 : 1));
  const total = sumDays(rows);
  return { from, to, rows, totals: { ...total, domains: rows.length, ...shares(total) } };
}

/** A share as a percentage with one decimal ('' without mail). */
const pct = (v) => (v === null || v === undefined ? '' : String(Math.round(v * 1000) / 10));

/**
 * The roll-up's rows for CSV ({@link ROLLUP_CSV_COLUMNS}).
 * @param {object[]} rows {@link rollup} rows
 * @returns {object[]}
 */
export function rollupCsvRows(rows) {
  return (rows || []).map((r) => ({
    domain: r.domain,
    messages: r.msgs,
    dmarc_pass: r.dmarcPass,
    compliance_pct: pct(r.compliance),
    unknown_messages: r.unknownMsgs,
    unknown_pct: pct(r.unknownShare),
    known_fail: r.knownFail,
    quarantine: r.quarantine,
    reject: r.reject,
    policy_p: r.policy ? r.policy.p : '',
    policy_sp: r.policy ? r.policy.sp : '',
    policy_pct: r.policy ? r.policy.pct : '',
    policy_seen: r.policy ? dayOf(r.policy.seenAt) : '',
    verdict: r.verdict,
    reported_days: r.reportedDays,
    first_day: r.first || '',
    last_day: r.last || '',
    sources: r.sources,
    new_sources: r.newSources,
    spf_checked: r.checked || ''
  }));
}

/**
 * The days of a trend for CSV and the table view: one row per slot with a report.
 * @param {ReturnType<typeof trend>} tr
 * @returns {object[]}
 */
export function trendCsvRows(tr) {
  return (tr ? tr.slots : []).filter((s) => s.reportedDays).map((s) => ({
    day: s.day,
    to: s.to,
    messages: s.msgs,
    dmarc_pass: s.dmarcPass,
    compliance_pct: pct(s.compliance),
    spf_aligned: s.spfAligned,
    dkim_aligned: s.dkimAligned,
    quarantine: s.quarantine,
    reject: s.reject,
    unknown_messages: s.unknownMsgs,
    unknown_pct: pct(s.unknownShare),
    known_fail: s.knownFail
  }));
}

/** The trend's CSV columns ({@link trendCsvRows}). */
export const TREND_CSV_COLUMNS = Object.freeze(['day', 'to', 'messages', 'dmarc_pass', 'compliance_pct', 'spf_aligned', 'dkim_aligned', 'quarantine', 'reject',
  'unknown_messages', 'unknown_pct', 'known_fail']);

/** Days since a day, from today (0: today). */
export function daysSince(day, { now = Date.now() } = {}) {
  return isDay(day) ? daysBetween(day, dayOf(clockMs(now))) : null;
}
