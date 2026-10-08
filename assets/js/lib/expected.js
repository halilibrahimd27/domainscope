/**
 * expected.js — Global DNS › Expected value: which sources already serve the value a DNS change
 * should publish, and how long the others may keep the old answer (ROADMAP P0.6, the part wave 6
 * left for Global DNS).
 *
 * - {@link parseExpected}: the typed value and its mode, or why it cannot be used. `exact`: the
 *   records of the queried type, as a set (order, case, quotes and trailing dots aside; `NXDOMAIN`
 *   and `NODATA` stand for "no such name" and "no record of the type"); `contains`: text found in
 *   any answer, the CNAME chain included; `regex`: a pattern any answer matches (case-insensitive).
 * - {@link expectedVerdict} / {@link expectedTally}: one source's answer against it ('match',
 *   'mismatch', 'failed', or null when there is nothing to judge: still asking, not asked, not
 *   readable, blocked by a filtering resolver) and the counts.
 * - {@link cachedTtl} / {@link negativeTtl} / {@link cacheEnd}: how long the answer a source gave may
 *   stay cached there, and until when: the longest TTL in the answer (no part of it outlives that),
 *   or for an empty answer the negative-cache time min(SOA TTL, SOA minimum) (RFC 2308 §5).
 * - {@link worstCaseEta} / {@link expectedEta}: how long after a change every resolver serves it at
 *   the latest — the longest TTL the old answer has (the highest over the zone's name servers when
 *   several are known), and where the old answer is "no such record", the zone's negative-cache
 *   time. Never the remaining TTLs one by one: anycast caches count down out of step.
 * - {@link COMMON_TTLS} / {@link likelyTtl}: a counted-down TTL read as the zone TTL it most likely
 *   started from (lib/cutover.js's planner re-exports them).
 * - {@link FLUSH_LINKS}: the public resolvers' own cache-flush pages — links the user opens, never
 *   fetched.
 *
 * DOM-free, no network, no clock of its own (every time is passed in); runs in browsers and Node 22.
 */

import { normalizeIP } from './ip.js';

/** How the expected value is compared with an answer. */
export const EXPECT_MODES = Object.freeze(['exact', 'contains', 'regex']);
/** Why an expected value cannot be used: nothing typed, a pattern that does not compile, too long. */
export const EXPECT_ERRORS = Object.freeze(['empty', 'regex', 'long']);
/** What one source's answer is against the expected value (null: nothing to judge). */
export const EXPECT_VERDICTS = Object.freeze(['match', 'mismatch', 'failed']);
/** The longest value (or pattern) taken. */
export const EXPECT_MAX_LENGTH = 300;
/** The special values of an exact match: the name does not exist; it has no record of the type. */
export const EXPECT_SPECIALS = Object.freeze(['NXDOMAIN', 'NODATA']);
/** TTLs zones commonly use: a TTL a resolver counted down is read as the next one up. */
export const COMMON_TTLS = Object.freeze([60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400, 172800, 604800]);
/**
 * The public resolvers' cache-flush pages: after a change, asking them to drop a name speeds the
 * change up for their users (links, never fetched; checked 2026-10-08: both answer 200).
 */
export const FLUSH_LINKS = Object.freeze([
  Object.freeze({ id: 'google', name: 'Google Public DNS', url: 'https://developers.google.com/speed/public-dns/cache' }),
  Object.freeze({ id: 'cloudflare', name: 'Cloudflare 1.1.1.1', url: 'https://one.one.one.one/purge-cache/' })
]);

/** The largest TTL (RFC 2181 §8). */
const TTL_MAX = 2147483647;
/** Types whose expected values are separate tokens (a list of addresses or names). */
const LIST_TYPES = new Set(['A', 'AAAA', 'CNAME', 'NS', 'PTR']);
/** Types whose leading number (MX preference, CAA flags) may be left out of an expected value. */
const LEADING_NUMBER_TYPES = new Set(['MX', 'CAA']);

const isFiniteTtl = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0;

/**
 * The zone's TTL a counted-down TTL most likely started from: the smallest of {@link COMMON_TTLS}
 * that is not lower (a TTL above them all stays as it is), or null for no TTL.
 * @param {number|null} seen seconds
 * @returns {number|null}
 */
export function likelyTtl(seen) {
  const v = Number(seen);
  if (seen === null || seen === undefined || !Number.isFinite(v) || v <= 0) return null;
  return COMMON_TTLS.find((x) => x >= v) ?? Math.min(Math.ceil(v), TTL_MAX);
}

/* ------------------------------------------------------------------------ */
/* Values                                                                   */
/* ------------------------------------------------------------------------ */

/** The character-strings of a TXT presentation text ('"a" "b"'), unescaped and joined (RFC 7208 §3.3). */
function txtText(text) {
  const s = String(text ?? '');
  const parts = [...s.matchAll(/"((?:[^"\\]|\\.)*)"/g)];
  if (!parts.length) return s.trim();
  return parts.map((m) => m[1].replace(/\\(\d{3}|.)/g, (_, x) => (/^\d{3}$/.test(x) ? String.fromCharCode(Number(x)) : x))).join('');
}

/** A token as compared: no surrounding quotes, lower case, no trailing dot (but the root '.'). */
function canonToken(token) {
  let s = String(token).replace(/^"(.*)"$/, '$1').toLowerCase();
  if (s.length > 1 && s.endsWith('.')) s = s.slice(0, -1);
  return s;
}

/**
 * One record value as compared: an address in its canonical form, a TXT record's text, else its
 * tokens lower-cased without quotes or trailing dots.
 * @param {string} type
 * @param {string} text presentation text (lib/propagation.js answerValues)
 * @returns {string}
 */
export function canonValue(type, text) {
  const t = String(type || '').toUpperCase();
  const s = String(text ?? '').trim();
  if (t === 'A' || t === 'AAAA') return normalizeIP(s) || s.toLowerCase();
  if (t === 'TXT' || t === 'SPF') return txtText(s);
  return s.split(/\s+/).filter(Boolean).map(canonToken).join(' ');
}

/** What `contains` and `regex` read of one answer value: a chain entry's target, a TXT text, a record as compared. */
function displayValue(type, value) {
  const v = String(value ?? '');
  if (v.startsWith('CNAME ')) return canonToken(v.slice(6));
  if (EXPECT_SPECIALS.includes(v)) return v;
  return canonValue(type, v);
}

/**
 * @typedef {object} ExpectedValue
 * @property {true} ok
 * @property {'exact'|'contains'|'regex'} mode
 * @property {string} type the queried record type
 * @property {string} pattern the text as typed (trimmed)
 * @property {string[]} values exact: the canonical values (empty for a special)
 * @property {'NXDOMAIN'|'NODATA'|null} special exact: the name should not exist / have no record of the type
 * @property {RegExp|null} re regex: the compiled pattern (case-insensitive)
 */

/**
 * The expected value of a check, or why it cannot be used. Exact values of an address or name type
 * (A, AAAA, CNAME, NS, PTR) are separated by commas or spaces, MX values by commas; any other type
 * takes the whole text as one value (a TXT record may hold both).
 * @param {{ mode?: string, pattern?: string, type?: string }} input
 * @returns {ExpectedValue|{ ok: false, error: 'empty'|'regex'|'long', mode: string, pattern: string, detail?: string }}
 */
export function parseExpected({ mode = 'exact', pattern = '', type = 'A' } = {}) {
  const m = EXPECT_MODES.includes(mode) ? mode : 'exact';
  const t = String(type || 'A').toUpperCase();
  const text = String(pattern ?? '').trim();
  const fail = (error, detail) => ({ ok: false, error, mode: m, pattern: text, ...(detail ? { detail } : {}) });
  if (!text) return fail('empty');
  if (text.length > EXPECT_MAX_LENGTH) return fail('long');
  const base = { ok: true, mode: m, type: t, pattern: text, values: [], special: null, re: null };
  if (m === 'regex') {
    try {
      return { ...base, re: new RegExp(text, 'i') };
    } catch (err) {
      return fail('regex', String((err && err.message) || err).slice(0, 160));
    }
  }
  if (m === 'contains') return { ...base, values: [text.toLowerCase()] };
  const special = EXPECT_SPECIALS.find((s) => s === text.toUpperCase()) || null;
  if (special) return { ...base, special };
  const raw = LIST_TYPES.has(t) ? text.split(/[\s,]+/) : t === 'MX' ? text.split(',') : [text];
  const values = [...new Set(raw.map((v) => v.trim()).filter(Boolean).map((v) => canonValue(t, v)))];
  return values.length ? { ...base, values } : fail('empty');
}

/** An answer that is a failure: a transport error ('ERROR') or an rcode other than NXDOMAIN. */
function isFailure(values) {
  if (values.length !== 1) return false;
  const v = values[0];
  return v === 'ERROR' || (/^[A-Z]+\d*$/.test(v) && !EXPECT_SPECIALS.includes(v));
}

/** An exact expected value against the plain records: the same set (an MX or CAA value may leave out its leading number). */
function exactMatch(records, expected) {
  if (expected.special) return records.length === 1 && records[0] === expected.special;
  if (records.some((v) => EXPECT_SPECIALS.includes(v))) return false;
  const seen = records.map((v) => canonValue(expected.type, v));
  if (!seen.length) return false;
  const loose = LEADING_NUMBER_TYPES.has(expected.type);
  const covers = (want, got) => got === want || (loose && !/^\d+\s/.test(want) && got.replace(/^\d+\s+/, '') === want);
  return expected.values.every((w) => seen.some((g) => covers(w, g))) && seen.every((g) => expected.values.some((w) => covers(w, g)));
}

/**
 * Does an answer carry the expected value? `values` as lib/propagation.js answerValues gives them:
 * the records of the type (presentation text), then the CNAME chain as 'CNAME <target>' entries;
 * ['NXDOMAIN'] / ['NODATA'] for the empty answers. Exact compares the records only; contains and
 * regex read the chain too (a target name), every value as {@link canonValue} words it.
 * @param {string[]} values
 * @param {ExpectedValue} expected
 * @returns {boolean}
 */
export function matchExpected(values, expected) {
  if (!expected || !expected.ok || !Array.isArray(values) || !values.length || isFailure(values)) return false;
  if (expected.mode === 'exact') return exactMatch(values.filter((v) => !String(v).startsWith('CNAME ')), expected);
  const shown = values.map((v) => displayValue(expected.type, v));
  if (expected.mode === 'contains') return shown.some((v) => v.toLowerCase().includes(expected.values[0]));
  return shown.some((v) => expected.re.test(v));
}

/**
 * One source's answer against the expected value: 'match', 'mismatch', 'failed' (no DNS answer, or
 * an rcode such as SERVFAIL), or null when there is nothing to judge — still asking, not asked, not
 * readable in browsers (`skipped`), or blocked by a filtering resolver (its policy, not an answer).
 * @param {{ pending?: boolean, skipped?: boolean, notAsked?: boolean, filtered?: boolean, values?: string[]|null }|null} row
 * @param {ExpectedValue|null} expected
 * @returns {'match'|'mismatch'|'failed'|null}
 */
export function expectedVerdict(row, expected) {
  if (!row || !expected || !expected.ok || row.pending || row.skipped || row.notAsked || row.filtered) return null;
  const values = Array.isArray(row.values) ? row.values : [];
  if (!values.length) return null;
  if (isFailure(values)) return 'failed';
  return matchExpected(values, expected) ? 'match' : 'mismatch';
}

/**
 * The counts of a check against its expected value. `done`: every source that answered serves it.
 * @param {object[]} rows
 * @param {ExpectedValue|null} expected
 * @returns {{ match: number, mismatch: number, failed: number, judged: number, done: boolean }}
 */
export function expectedTally(rows, expected) {
  const out = { match: 0, mismatch: 0, failed: 0, judged: 0, done: false };
  for (const row of Array.isArray(rows) ? rows : []) {
    const v = expectedVerdict(row, expected);
    if (v) out[v] += 1;
  }
  out.judged = out.match + out.mismatch;
  out.done = out.match > 0 && out.mismatch === 0;
  return out;
}

/* ------------------------------------------------------------------------ */
/* How long an answer stays cached                                          */
/* ------------------------------------------------------------------------ */

const soaOf = (response) => (response && Array.isArray(response.authorities)
  ? response.authorities.find((rr) => rr && rr.type === 'SOA' && rr.data && typeof rr.data === 'object') || null : null);

/**
 * The negative-caching TTL of an empty answer: min(SOA TTL, SOA minimum) of its authority SOA
 * (RFC 2308 §5), or null without one.
 * @param {object|null} response a DohClient DnsResponse (or one shaped like it)
 * @returns {number|null}
 */
export function negativeTtl(response) {
  const soa = soaOf(response);
  if (!soa) return null;
  const ttls = [soa.ttl, Number(soa.data.minimum)].filter(isFiniteTtl);
  return ttls.length ? Math.min(...ttls) : null;
}

/**
 * How long the answer a source gave may stay cached there: the longest TTL of its records (no
 * part of the answer outlives it), or for NXDOMAIN / NODATA the negative TTL; null when unknown.
 * A row that carries its own `ttl` (an ISP resolver's, read from its probe) keeps it.
 * @param {{ ttl?: number|null, values?: string[]|null, response?: object|null }|null} row
 * @returns {number|null}
 */
export function cachedTtl(row) {
  if (!row) return null;
  if (isFiniteTtl(row.ttl)) return row.ttl;
  const res = row.response;
  if (!res || !res.ok) return null;
  const values = Array.isArray(row.values) ? row.values : [];
  if (values.length === 1 && EXPECT_SPECIALS.includes(values[0])) return negativeTtl(res);
  const ttls = (Array.isArray(res.answers) ? res.answers : []).map((rr) => rr && rr.ttl).filter(isFiniteTtl);
  return ttls.length ? Math.max(...ttls) : null;
}

/**
 * Until when a source may keep the answer it gave (ms epoch): an ISP resolver's `expiresAt`, else
 * when it answered (`at`) plus {@link cachedTtl}; null when unknown.
 * @param {{ at?: number|Date|null, expiresAt?: string|number|Date|null }|null} row
 * @returns {number|null}
 */
export function cacheEnd(row) {
  if (!row) return null;
  if (row.expiresAt !== null && row.expiresAt !== undefined) {
    const t = new Date(row.expiresAt).getTime();
    if (Number.isFinite(t)) return t;
  }
  const ttl = cachedTtl(row);
  const at = row.at instanceof Date ? row.at.getTime() : Number(row.at);
  return ttl === null || row.at === null || row.at === undefined || !Number.isFinite(at) ? null : at + ttl * 1000;
}

/**
 * How long after a change every resolver serves it at the latest, in seconds: the longest of the
 * TTLs the old answer has — one per authoritative name server when they are known (multi-provider
 * zones differ, 3600 on one and 900 on another) — and, where the old answer was "no such record"
 * (`negative`), the zone's negative-cache time. Null when nothing is known.
 * @param {{ ttls?: Array<number|null>, negativeTtl?: number|null, negative?: boolean }} input
 * @returns {number|null}
 */
export function worstCaseEta({ ttls = [], negativeTtl: neg = null, negative = false } = {}) {
  const list = (Array.isArray(ttls) ? ttls : []).filter(isFiniteTtl);
  if (negative && isFiniteTtl(neg)) list.push(neg);
  return list.length ? Math.max(...list) : null;
}

/**
 * The negative-cache time the empty answers say: their SOA minimum is exact, the SOA's own TTL is
 * counted down (read as the zone TTL it most likely started from). Null without an SOA.
 * @param {object[]} rows
 * @returns {number|null}
 */
function negativeFromAnswers(rows) {
  let minimum = null;
  let soaTtl = null;
  for (const row of rows) {
    const soa = soaOf(row && row.response);
    if (!soa) continue;
    const min = Number(soa.data.minimum);
    if (isFiniteTtl(min)) minimum = minimum === null ? min : Math.max(minimum, min);
    if (isFiniteTtl(soa.ttl)) soaTtl = soaTtl === null ? soa.ttl : Math.max(soaTtl, soa.ttl);
  }
  const ttl = likelyTtl(soaTtl);
  const both = [minimum, ttl].filter((v) => v !== null);
  return both.length ? Math.min(...both) : null;
}

/**
 * The worst case of a check against its expected value, from the sources that do not serve it yet:
 * the highest TTL their records carried (`observedTtl`) read as the zone TTL it most likely counts
 * down from (`recordTtl`), and when some of them say the name or the record does not exist
 * (`negative`), the negative-cache time — the authoritative one when an SOA probe read it
 * (`authoritative.negativeTtl`), else what their own SOA says. `last`: when the latest cached copy
 * among these sources ends (ms epoch).
 * @param {object[]} rows the check's rows
 * @param {ExpectedValue|null} expected
 * @param {{ authoritative?: { negativeTtl?: number|null }|null }} [opts]
 * @returns {{ mismatched: number, positive: number, negative: number, observedTtl: number|null, recordTtl: number|null,
 *   negativeTtl: number|null, negativeFrom: 'name-server'|'answers'|null, seconds: number|null, last: number|null }}
 */
export function expectedEta(rows, expected, { authoritative = null } = {}) {
  const old = (Array.isArray(rows) ? rows : []).filter((r) => expectedVerdict(r, expected) === 'mismatch');
  const empty = old.filter((r) => r.values.length === 1 && EXPECT_SPECIALS.includes(r.values[0]));
  const records = old.filter((r) => !empty.includes(r));
  const ttls = records.map(cachedTtl).filter((v) => v !== null);
  const observedTtl = ttls.length ? Math.max(...ttls) : null;
  const recordTtl = likelyTtl(observedTtl);
  const probed = authoritative && isFiniteTtl(authoritative.negativeTtl) ? authoritative.negativeTtl : null;
  const fromAnswers = empty.length ? negativeFromAnswers(empty) : null;
  const neg = probed ?? fromAnswers;
  const ends = old.map(cacheEnd).filter((v) => v !== null);
  return {
    mismatched: old.length,
    positive: records.length,
    negative: empty.length,
    observedTtl,
    recordTtl,
    negativeTtl: empty.length ? neg : probed,
    negativeFrom: probed !== null ? 'name-server' : (empty.length && fromAnswers !== null ? 'answers' : null),
    seconds: old.length ? worstCaseEta({ ttls: recordTtl === null ? [] : [recordTtl], negativeTtl: neg, negative: empty.length > 0 }) : null,
    last: ends.length ? Math.max(...ends) : null
  };
}
