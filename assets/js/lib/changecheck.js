/**
 * changecheck.js — "is it done?": the expected state of a DNS change request carried in a link
 * (`#/change/check?z=example.com&r=…`), and what each public resolver answers for it.
 *
 * - The link holds the zone and the expected record sets, nothing else: no name of a person, no
 *   ticket, no server. Each set is one `r` parameter in presentation form, readable in the URL:
 *   `has _acme-challenge TXT "gfj9…"`, `is/300 www A 192.0.2.10^198.51.100.5` (mode, `/` the
 *   TTL a resolver's copy must expire within, the relative name, the type, the values separated
 *   by `|`, then `^` and the values the set held before, when they were known). A TXT set's
 *   family is read from its values (or the old ones of a deletion); where that would read it
 *   wrong, the type says it (`TXT:*` every TXT record, `TXT:spf1` the SPF record only).
 *   {@link encodeCheck} / {@link decodeCheck} are exact inverses; both refuse a link over
 *   {@link CHECK_LIMITS}, counted as the link writes it (a URLSearchParams re-serialized by
 *   {@link linkQuery}).
 * - {@link judgeAnswer}: one resolver's answer for one set — `done` (the answer is what the
 *   change asks for), `pending` (not yet: the record is not there, or still the old value, or the
 *   old TTL), `wrong` (a value that is neither the new nor the known old one) or `error` (no
 *   answer). Without the old values in the link another value can only read "not yet".
 * - {@link checkRound} asks {@link CHECK_RESOLVERS} (names and types only, never cached here);
 *   {@link nextCheck} decides when asking again is worth it: a backoff from 15 s up to 5 min, never
 *   before a resolver's cached copy (its TTL, or the negative TTL of the SOA) can have expired, and
 *   a stop after two hours, once nothing can change before then, or once a record set has had no
 *   answer from any resolver three rounds in a row (`failed`).
 *
 * DOM-free, no I/O of its own (an injected DohClient); runs in browsers and Node 22.
 */

import {
  FIX_TYPES, FIX_MODES, TXT_FAMILIES, rrsetPlan, valueKey, valueText, parseValueText, txtFamily, familyOf, relativeName, absoluteName,
  zoneName, normalizeValue
} from './fixes.js';

/** The link format's version (`v`, left out for 1). */
export const CHECK_VERSION = 1;
/**
 * The resolvers a check asks: four browser-readable, unfiltered public resolvers of different
 * operators (the same four Renewal readiness compares CAA on).
 */
export const CHECK_RESOLVERS = Object.freeze(['cloudflare', 'google', 'dnssb', 'cznic']);
/** Bounds of a link: record sets, values (new and old together) and characters after `?`. */
export const CHECK_LIMITS = Object.freeze({ rrsets: 20, values: 40, chars: 4000 });
/** Verdicts of one set on one resolver, best first. */
export const CHECK_VERDICTS = Object.freeze(['done', 'pending', 'wrong', 'error']);
/** Why a set is not done yet on a resolver. */
export const PENDING_REASONS = Object.freeze(['missing', 'old', 'other', 'partial', 'ttl', 'present']);
/** Headlines of a check (`no-answer`: every pair has answered or failed, and a set got no answer at all). */
export const CHECK_HEADLINES = Object.freeze(['done', 'done-partial', 'wrong', 'pending', 'no-answer', 'unknown']);
/** When a stopped check stopped by itself (`failed`: a set had no answer from any resolver, three rounds in a row). */
export const CHECK_STOPS = Object.freeze(['done', 'timeout', 'cached', 'failed']);
/**
 * Re-check timing (ms): the first wait `base`, then × `factor` per round up to `max`; a check
 * stops `stopAfter` after it started. A resolver's cached copy is waited for up to `maxTtlWait`.
 */
export const CHECK_TIMING = Object.freeze({ base: 15000, factor: 1.6, max: 300000, stopAfter: 2 * 3600 * 1000, maxTtlWait: 24 * 3600 * 1000 });

const canon = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');
const arr = (v) => (Array.isArray(v) ? v : []);

/**
 * @typedef {object} ExpectedSet
 * @property {string} name absolute
 * @property {string} type
 * @property {'is'|'has'|'none'} mode
 * @property {string|null} family a TXT set scoped to one kind of record (`spf1` …): the other TXT values do not count
 * @property {any[]} values what the set must hold ('has': at least; 'none': nothing)
 * @property {any[]|null} old what it held before, when that was known
 * @property {number|null} maxTtl a resolver's copy must expire within this many seconds (a lowered TTL)
 * @typedef {{ zone: string, sets: ExpectedSet[] }} ExpectedCheck
 */

/**
 * The expected state of a change request (lib/fixes.js): per set its values afterwards (in its
 * family), and what it held before when that was read. A set the change leaves as it is stays
 * in the check (it is done at once).
 * @param {import('./fixes.js').ChangeRequest} req
 * @returns {ExpectedCheck}
 */
export function checkFromRequest(req) {
  const sets = [];
  for (const r of arr(req && req.rrsets)) {
    const plan = rrsetPlan(r);
    const old = r.before === null ? null : [...r.before];
    const values = r.mode === 'none' ? [] : [...r.values];
    sets.push({ name: r.name, type: r.type, mode: r.mode, family: r.family || null, values, old, maxTtl: r.maxTtl ?? (plan.ttlOnly ? r.ttl : null) });
  }
  return { zone: req ? req.zone : null, sets };
}

/**
 * A query value as the link writes it: percent-encoded, but with the characters a URL fragment
 * may hold as they are (`@ : / , ; =`, RFC 3986 §3.5) and spaces as `+`, so the link stays
 * readable in a ticket. URLSearchParams reads it back unchanged.
 * @param {string} value
 * @returns {string}
 */
export function linkEncode(value) {
  return encodeURIComponent(String(value ?? '')).replace(/%20/g, '+').replace(/%(40|3A|2F|2C|3B|3D)/g, (m) => decodeURIComponent(m));
}

/**
 * A query's parameters written as the link writes them ({@link linkEncode}): what a URLSearchParams
 * holds, never its own serialization (which percent-encodes `@ : / , ; =` and more, and so makes
 * a link longer than the one that was opened).
 * @param {URLSearchParams} params
 * @returns {string}
 */
export function linkQuery(params) {
  return [...params].map(([k, v]) => `${linkEncode(k)}=${linkEncode(v)}`).join('&');
}

/** A value's presentation text as the link holds it: `|` and `^` escaped (they only occur in quoted strings). */
const linkValue = (type, v) => valueText(type, v).replace(/\|/g, '\\124').replace(/\^/g, '\\094');

/** The family a link that names none reads for a set: its values', else (a deletion) its old values'. */
const impliedFamily = (type, mode, values, old) => (type === 'TXT'
  ? (familyOf('TXT', values) || (mode === 'none' && old ? familyOf('TXT', old) : null)) : null);

/**
 * The link's query (after `#/change/check?`) of an expected check, or why there is none (`outside`:
 * a set's name is not in the zone, which the link cannot write — {@link decodeCheck} would refuse it).
 * @param {ExpectedCheck} check
 * @returns {{ ok: boolean, query: string, length: number, reason: 'empty'|'too-many'|'too-long'|'zone'|'outside'|null }}
 */
export function encodeCheck(check) {
  const fail = (reason, query = '') => ({ ok: false, query, length: query.length, reason });
  const zone = check && zoneName(check.zone);
  if (!zone) return fail('zone');
  const sets = arr(check.sets).filter((s) => s && FIX_TYPES.includes(s.type) && FIX_MODES.includes(s.mode));
  if (!sets.length) return fail('empty');
  const values = sets.reduce((n, s) => n + arr(s.values).length + arr(s.old).length, 0);
  if (sets.length > CHECK_LIMITS.rrsets || values > CHECK_LIMITS.values) return fail('too-many');
  if (sets.some((s) => relativeName(s.name, zone).endsWith('.'))) return fail('outside');
  const parts = [`z=${linkEncode(zone)}`];
  for (const s of sets) {
    // The family only where the values would give another one (a deletion of every TXT record where only an SPF record was read).
    const family = s.type === 'TXT' ? s.family || null : null;
    const named = family === impliedFamily(s.type, s.mode, arr(s.values), s.old) ? '' : `:${family || '*'}`;
    const head = `${s.mode}${Number.isInteger(s.maxTtl) ? `/${s.maxTtl}` : ''} ${relativeName(s.name, zone)} ${s.type}${named}`;
    const vals = arr(s.values).map((v) => linkValue(s.type, v)).join('|');
    const old = s.old && s.old.length ? `^${s.old.map((v) => linkValue(s.type, v)).join('|')}` : s.old && !s.old.length ? '^' : '';
    parts.push(`r=${linkEncode(`${head}${vals || old ? ` ${vals}${old}` : ''}`)}`);
  }
  const query = parts.join('&');
  return query.length > CHECK_LIMITS.chars ? fail('too-long', query) : { ok: true, query, length: query.length, reason: null };
}

const SET_RE = /^(is|has|none)(?:\/(\d{1,10}))? (\S+) ([A-Z]{1,10})(?::(\*|[a-z0-9]{1,16}))?(?: ([\s\S]*))?$/;

/**
 * Read a check link's query back. Every name must lie in the zone, every value parse as its type,
 * and the link must stay within {@link CHECK_LIMITS}; anything else refuses the whole link. The
 * length counted is that of the query as written; a URLSearchParams counts as {@link linkQuery}
 * writes it, so a link {@link encodeCheck} made is never refused for its length.
 * @param {URLSearchParams|string} input the query (with or without the leading '?')
 * @returns {{ ok: true, check: ExpectedCheck } | { ok: false, error: 'too-long'|'version'|'zone'|'empty'|'too-many'|'set', detail: string|null }}
 */
export function decodeCheck(input) {
  const raw = typeof input === 'string' ? input.replace(/^\?/, '') : input instanceof URLSearchParams ? linkQuery(input) : '';
  const fail = (error, detail = null) => ({ ok: false, error, detail });
  if (raw.length > CHECK_LIMITS.chars) return fail('too-long');
  const sp = new URLSearchParams(raw);
  if (sp.has('v') && sp.get('v') !== String(CHECK_VERSION)) return fail('version', sp.get('v'));
  const zone = zoneName(sp.get('z'));
  if (!zone) return fail('zone', sp.get('z'));
  const list = sp.getAll('r');
  if (!list.length) return fail('empty');
  if (list.length > CHECK_LIMITS.rrsets) return fail('too-many');
  const sets = [];
  let count = 0;
  for (const text of list) {
    const m = SET_RE.exec(text);
    if (!m || !FIX_TYPES.includes(m[4])) return fail('set', text);
    if (m[5] !== undefined && (m[4] !== 'TXT' || (m[5] !== '*' && !TXT_FAMILIES[m[5]]))) return fail('set', text);
    // The link writes every name relative to the zone ('@' for the apex).
    const abs = m[3].endsWith('.') ? { name: null } : absoluteName(m[3] === '@' ? '@' : `${m[3]}.${zone}`, zone);
    if (!abs.name) return fail('set', text);
    const [valuePart, oldPart] = splitOld(m[6] ?? '');
    const values = parseList(m[4], valuePart, zone);
    const old = oldPart === null ? null : parseList(m[4], oldPart, zone);
    if (!values || (oldPart !== null && !old)) return fail('set', text);
    if (m[1] === 'none' ? values.length : !values.length) return fail('set', text);
    count += values.length + (old ? old.length : 0);
    if (count > CHECK_LIMITS.values) return fail('too-many');
    const family = m[5] === undefined ? impliedFamily(m[4], m[1], values, old) : m[5] === '*' ? null : m[5];
    sets.push({ name: abs.name, type: m[4], mode: m[1], family, values, old, maxTtl: m[2] === undefined ? null : Number(m[2]) });
  }
  return { ok: true, check: { zone, sets } };
}

/** 'a|b^c|d' → ['a|b', 'c|d'], 'a' → ['a', null] ('^' escaped inside values). */
function splitOld(text) {
  const i = text.indexOf('^');
  return i === -1 ? [text, null] : [text.slice(0, i), text.slice(i + 1)];
}

function parseList(type, text, zone) {
  if (!text.trim()) return [];
  const out = [];
  for (const part of text.split('|')) {
    const v = parseValueText(type, part.trim(), zone);
    if (v === null) return null;
    if (!out.some((x) => valueKey(type, x) === valueKey(type, v))) out.push(v);
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Verdicts                                                                 */
/* ------------------------------------------------------------------------ */

/** The negative-caching TTL of an empty answer: min(SOA TTL, SOA minimum) (RFC 2308), or null. */
function negativeTtl(res) {
  const soa = arr(res.authorities).find((rr) => rr && rr.type === 'SOA');
  if (!soa) return null;
  const min = soa.data && Number.isFinite(Number(soa.data.minimum)) ? Number(soa.data.minimum) : Infinity;
  const ttl = Number.isFinite(soa.ttl) ? soa.ttl : Infinity;
  const v = Math.min(min, ttl);
  return Number.isFinite(v) ? v : null;
}

const keysOf = (type, list) => new Set(list.map((v) => valueKey(type, v)));
const sameKeys = (a, b) => a.size === b.size && [...a].every((k) => b.has(k));

/**
 * One resolver's answer for one expected set.
 * @param {ExpectedSet} exp
 * @param {object|null} res a DohClient DnsResponse
 * @returns {{ verdict: 'done'|'pending'|'wrong'|'error', reason: string|null, seen: any[], ttl: number|null }}
 *   `seen`: the values the resolver gave (in the set's family); `ttl`: seconds its copy has left
 *   (the negative TTL for an empty answer); `reason`: why it is pending ({@link PENDING_REASONS}),
 *   or the rcode / error kind of an error
 */
export function judgeAnswer(exp, res) {
  if (!res || !res.ok) return { verdict: 'error', reason: (res && res.errorKind) || 'network', seen: [], ttl: null };
  if (res.rcode !== 'NOERROR' && res.rcode !== 'NXDOMAIN') return { verdict: 'error', reason: String(res.rcode || 'ERROR'), seen: [], ttl: null };
  // What a CA or a mail server sees: the records of the type, through a CNAME chain for any other type.
  const rrs = res.rcode === 'NXDOMAIN' ? [] : arr(res.answers).filter((rr) => rr && rr.type === exp.type
    && (exp.type !== 'CNAME' || canon(rr.name) === canon(exp.name)));
  const all = [];
  for (const rr of rrs) {
    const v = normalizeValue(exp.type, rr.data);
    if (v !== null && !all.some((x) => valueKey(exp.type, x) === valueKey(exp.type, v))) all.push(v);
  }
  const seen = exp.family ? all.filter((v) => txtFamily(v) === exp.family) : all;
  const ttls = rrs.map((rr) => rr.ttl).filter(Number.isFinite);
  const ttl = ttls.length ? Math.min(...ttls) : negativeTtl(res);
  const S = keysOf(exp.type, seen);
  const E = keysOf(exp.type, exp.values);
  const O = exp.old ? keysOf(exp.type, exp.old) : null;
  let match;
  if (exp.mode === 'none') match = S.size === 0;
  else if (exp.mode === 'has') match = [...E].every((k) => S.has(k));
  else match = sameKeys(E, S);
  const pending = (reason) => ({ verdict: 'pending', reason, seen, ttl });
  if (match) {
    if (exp.maxTtl !== null && exp.maxTtl !== undefined && ttl !== null && ttl > exp.maxTtl) return pending('ttl');
    return { verdict: 'done', reason: null, seen, ttl };
  }
  // Still the old values — an empty answer where nothing was before is "no record", never "the old value".
  if (O && O.size && sameKeys(S, O)) return pending('old');
  if (exp.mode === 'none') return O ? { verdict: 'wrong', reason: null, seen, ttl } : pending('present');
  if (!S.size) return pending('missing');
  if (exp.mode === 'has') return pending('partial');
  if (!O) return pending('other');
  return { verdict: 'wrong', reason: null, seen, ttl };
}

/* ------------------------------------------------------------------------ */
/* Rounds and timing                                                        */
/* ------------------------------------------------------------------------ */

/** The key of one set on one resolver. */
export const pairKey = (index, resolver) => `${index}|${resolver}`;

/**
 * @typedef {{ set: number, resolver: string, verdict: string, reason: string|null, seen: any[], ttl: number|null, at: number }} PairResult
 */

/**
 * Ask each resolver for each set (the pairs in `only`, else all), without any cache.
 * @param {ExpectedCheck} check
 * @param {{ dns: { query: Function }, resolvers?: string[], only?: Set<string>|null, signal?: AbortSignal,
 *   now?: () => number, onResult?: (r: PairResult) => void, timeoutMs?: number }} opts
 * @returns {Promise<PairResult[]>}
 */
export async function checkRound(check, { dns, resolvers = CHECK_RESOLVERS, only = null, signal, now = Date.now, onResult = null, timeoutMs = 6000 } = {}) {
  const jobs = [];
  check.sets.forEach((exp, set) => {
    for (const resolver of resolvers) {
      if (only && !only.has(pairKey(set, resolver))) continue;
      jobs.push((async () => {
        const res = await dns.query(exp.name, exp.type, { resolver, noCache: true, signal, timeoutMs, retries: 0 });
        const out = { set, resolver, ...judgeAnswer(exp, res), at: now() };
        if (onResult) onResult(out);
        return out;
      })());
    }
  });
  return Promise.all(jobs);
}

/**
 * The state of a check over the latest result of each pair: per set and overall.
 * @param {ExpectedCheck} check
 * @param {Map<string, PairResult>|Record<string, PairResult>} latest pairKey → result
 * @param {string[]} [resolvers]
 * @returns {{ headline: string, counts: Record<string, number>, sets: Array<{ state: string, counts: Record<string, number> }>,
 *   settled: boolean, answered: number, pairs: number }}
 *   `settled`: no pair is pending or wrong (errors aside); set state: done (every resolver that
 *   answered), wrong, pending, unknown (nothing answered yet, or every resolver failed); headline
 *   `no-answer` once every pair has answered or failed and a set got no answer at all
 */
export function checkState(check, latest, resolvers = CHECK_RESOLVERS) {
  const get = (k) => (latest instanceof Map ? latest.get(k) : latest && latest[k]) || null;
  const counts = { done: 0, pending: 0, wrong: 0, error: 0, waiting: 0 };
  const sets = check.sets.map((_, set) => {
    const c = { done: 0, pending: 0, wrong: 0, error: 0, waiting: 0 };
    for (const r of resolvers) {
      const res = get(pairKey(set, r));
      c[res ? res.verdict : 'waiting'] += 1;
    }
    for (const k of Object.keys(c)) counts[k] += c[k];
    let state = 'unknown';
    if (c.wrong) state = 'wrong';
    else if (c.pending || (c.waiting && c.done)) state = 'pending';
    else if (!c.waiting && c.done) state = 'done';
    return { state, counts: c };
  });
  const pairs = check.sets.length * resolvers.length;
  const settled = !counts.pending && !counts.wrong && !counts.waiting;
  let headline = 'unknown';
  if (counts.wrong) headline = 'wrong';
  else if (counts.pending || (counts.waiting && counts.done)) headline = 'pending';
  else if (settled && sets.every((s) => s.counts.done > 0)) headline = counts.error ? 'done-partial' : 'done';
  else if (settled) headline = 'no-answer';
  return { headline, counts, sets, settled, answered: pairs - counts.error - counts.waiting, pairs };
}

/**
 * How bad each headline is: the status icon of the check page's result header (docs/DESIGN.md §6.2).
 * `unknown` (still asking) has none: a spinner or nothing takes its place.
 */
export const CHECK_HEADLINE_SEVERITY = Object.freeze({
  done: 'ok', 'done-partial': 'ok', wrong: 'error', pending: 'warn', 'no-answer': 'warn', unknown: null
});

/** The status summary's items of a check page, in their order (lib/template.js statusItems sorts them by severity). */
export const CHECK_STATUS_KEYS = Object.freeze(['wrong', 'pending', 'done', 'noanswer', 'waiting']);

/**
 * The status item that counts a record set (one of CHECK_STATUS_KEYS): its state, and for a set no
 * resolver has given a usable answer for, whether one is still being asked (`waiting`) or none
 * answered (`noanswer`).
 * @param {{ state: string, counts: { waiting: number } }} set one of checkState's sets
 * @returns {string}
 */
export function checkSetKey(set) {
  return set.state === 'unknown' ? (set.counts.waiting ? 'waiting' : 'noanswer') : set.state;
}

/**
 * The status summary of a check page (docs/DESIGN.md §5.4): its record sets by state — ✕ a wrong
 * value somewhere, ⚠ not live everywhere yet, ✓ live on every resolver that answered, · no
 * resolver answered, · still asking — and the key metric, the sets done of all.
 * @param {ExpectedCheck} check
 * @param {Map<string, PairResult>|Record<string, PairResult>} latest
 * @param {string[]} [resolvers]
 * @returns {{ items: Array<{ key: string, severity: string, count: number }>, done: number, total: number }}
 */
export function checkStatus(check, latest, resolvers = CHECK_RESOLVERS) {
  const st = checkState(check, latest, resolvers);
  const n = Object.fromEntries(CHECK_STATUS_KEYS.map((k) => [k, 0]));
  for (const s of st.sets) n[checkSetKey(s)] += 1;
  const severity = { wrong: 'error', pending: 'warn', done: 'ok', noanswer: 'neutral', waiting: 'neutral' };
  return {
    items: CHECK_STATUS_KEYS.map((key) => ({ key, severity: severity[key], count: n[key] })),
    done: n.done,
    total: check.sets.length
  };
}

/**
 * When to ask again, and which pairs: never sooner than the backoff of this round, and a pair only
 * once its resolver's cached copy can have expired (its TTL after it answered, at most
 * `maxTtlWait`). Stops when every pair is settled (`done`; a pair that failed three rounds in a row
 * is given up), `stopAfter` after the start, when no pair can change before then (`cached`), or
 * (`failed`) when what was given up leaves a set with no answer from any resolver. With `lastAt`
 * (the last round's end) the backoff counts from then rather than from `now`, never before `now`:
 * a watch turned on long after a check stopped asks at once (lib/cutover.js nextWatch).
 * @param {{ latest: Map<string, PairResult>, check: ExpectedCheck, round: number, startedAt: number, now: number,
 *   resolvers?: string[], timing?: typeof CHECK_TIMING, errorRounds?: number, lastAt?: number|null }} state
 * @returns {{ stop: 'done'|'timeout'|'cached'|'failed'|null, at: number|null, pairs: string[], cachedUntil: number|null }}
 *   `at`: when to run the next round (ms epoch); `pairs`: the pairs it asks; `cachedUntil`: the
 *   latest time a resolver's copy of an old answer expires (for the 'cached' stop)
 */
export function nextCheck({ latest, check, round, startedAt, now, resolvers = CHECK_RESOLVERS, timing = CHECK_TIMING, errorRounds = 0, lastAt = null }) {
  const get = (k) => (latest instanceof Map ? latest.get(k) : latest[k]) || null;
  const deadline = startedAt + timing.stopAfter;
  const open = [];
  let cachedUntil = null;
  let givenUp = 0;
  check.sets.forEach((_, set) => {
    for (const r of resolvers) {
      const k = pairKey(set, r);
      const res = get(k);
      if (res && res.verdict === 'done') continue;
      if (res && res.verdict === 'error' && errorRounds >= 3) {
        givenUp += 1;
        continue;
      }
      const wait = res && res.verdict !== 'error' && Number.isFinite(res.ttl) ? Math.min(res.ttl * 1000, timing.maxTtlWait) : 0;
      const ready = res ? res.at + wait + (wait ? 1000 : 0) : now;
      if (wait) cachedUntil = Math.max(cachedUntil ?? 0, ready);
      open.push({ k, ready });
    }
  });
  if (!open.length) {
    // Nothing left to ask: done, unless a set was left with no answer at all (DoH blocked, offline, rate-limited, SERVFAIL).
    const unanswered = givenUp > 0 && check.sets.some((_, set) => !resolvers.some((r) => (get(pairKey(set, r)) || {}).verdict === 'done'));
    return { stop: unanswered ? 'failed' : 'done', at: null, pairs: [], cachedUntil: null };
  }
  if (now >= deadline) return { stop: 'timeout', at: null, pairs: [], cachedUntil };
  const soonest = Math.min(...open.map((p) => p.ready));
  if (soonest > deadline) return { stop: 'cached', at: null, pairs: [], cachedUntil };
  const backoff = Math.min(timing.base * timing.factor ** Math.max(0, round), timing.max);
  const from = Number.isFinite(lastAt) ? Math.min(lastAt, now) : now;
  const at = Math.min(Math.max(from + backoff, soonest, now), deadline);
  return { stop: null, at, pairs: open.filter((p) => p.ready <= at).map((p) => p.k), cachedUntil };
}
