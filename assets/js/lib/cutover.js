/**
 * cutover.js — the cutover assistant of the "is it live?" page (`#/change/check`): watch mode's
 * schedule, each resolver's cache countdown, and the TTL plan of a change with its checklist.
 *
 * - {@link nextWatch}: lib/changecheck.js nextCheck with the watch's timing. A watch keeps asking
 *   while the page is open, up to {@link WATCH_TIMING}.stopAfter (24 hours instead of a check's
 *   two), with the same backoff counted from the last round (a watch turned on long after a check
 *   stopped asks at once), and never asks a resolver before its cached copy can have expired.
 * - {@link watchProgress}: how many resolver answers are done (the long job's progress).
 * - {@link cacheCountdown}: until when a resolver that is not done yet may keep the answer it gave:
 *   the TTL its answer had left when it came, or the negative TTL of an empty answer (RFC 2308).
 *   {@link lastExpiry} is the latest of them: no cached copy of an old answer outlives it.
 * - {@link ttlPlan}: lower the TTL to the low TTL at T − the current TTL, make the change at T,
 *   expect it on every resolver by T + the low TTL, raise the TTL back from T + 2 × the low TTL.
 *   {@link planChecklist} writes it out in English or Turkish ({@link CUTOVER_I18N}).
 *
 * DOM-free and without a clock of its own (every time is passed in); runs in browsers and Node 22.
 */

import { CHECK_RESOLVERS, CHECK_TIMING, nextCheck, pairKey } from './changecheck.js';

/** A watch's timing: a check's backoff, but it stops only after 24 hours (it asks while the page is open). */
export const WATCH_TIMING = Object.freeze({ ...CHECK_TIMING, stopAfter: 24 * 3600 * 1000 });
/** What a cached copy holds, as a countdown says it: the old values, "no record", the old TTL, another answer. */
export const CACHE_KINDS = Object.freeze(['old', 'empty', 'ttl', 'other']);
/** The low TTLs a plan offers (seconds); 300 is the default. */
export const PLAN_LOW_TTLS = Object.freeze([60, 120, 300, 600]);
/** The low TTL a plan uses unless another is picked. */
export const PLAN_DEFAULT_LOW = 300;
/** TTLs zones commonly use: a TTL a resolver counted down is read as the next one up. */
export const COMMON_TTLS = Object.freeze([60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400, 172800, 604800]);
/** Why there is no plan: the current TTL, the low TTL or the change time is not usable. */
export const PLAN_ERRORS = Object.freeze(['ttl', 'low', 'time']);
/**
 * Notes on a plan: `past` the change time has gone by; `late` the TTL can no longer be lowered in
 * time (copies with the old TTL may outlive the change time); `already-low` nothing to lower.
 */
export const PLAN_NOTES = Object.freeze(['past', 'late', 'already-low']);
/** The steps of a plan, in order (`lower` and `raise` only when the TTL is lowered). */
export const PLAN_STEPS = Object.freeze(['lower', 'change', 'live', 'raise']);
/** The largest TTL (RFC 2181 §8). */
const TTL_MAX = 2147483647;

const getter = (latest) => (k) => (latest instanceof Map ? latest.get(k) : latest && latest[k]) || null;

/* ------------------------------------------------------------------------ */
/* Watch                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * When a watch asks again, and which pairs: {@link nextCheck} with {@link WATCH_TIMING} and the
 * backoff counted from the last round (`lastAt`). `startedAt` is when the watch started.
 * @param {{ latest: Map<string, object>, check: import('./changecheck.js').ExpectedCheck, round: number, startedAt: number,
 *   now: number, lastAt?: number|null, resolvers?: string[], timing?: typeof WATCH_TIMING, errorRounds?: number }} s
 * @returns {{ stop: 'done'|'timeout'|'cached'|'failed'|null, at: number|null, pairs: string[], cachedUntil: number|null }}
 */
export function nextWatch({ latest, check, round, startedAt, now, lastAt = null, resolvers = CHECK_RESOLVERS, timing = WATCH_TIMING, errorRounds = 0 }) {
  return nextCheck({ latest, check, round, startedAt, now, lastAt, resolvers, timing, errorRounds });
}

/**
 * How far a watch has come: the resolver answers that are done, of all (a set × a resolver each).
 * @param {import('./changecheck.js').ExpectedCheck} check
 * @param {Map<string, object>|Record<string, object>} latest pairKey → result
 * @param {string[]} [resolvers]
 * @returns {{ done: number, pairs: number, fraction: number }}
 */
export function watchProgress(check, latest, resolvers = CHECK_RESOLVERS) {
  const get = getter(latest);
  let done = 0;
  let pairs = 0;
  (check && Array.isArray(check.sets) ? check.sets : []).forEach((_, set) => {
    for (const r of resolvers) {
      pairs += 1;
      if ((get(pairKey(set, r)) || {}).verdict === 'done') done += 1;
    }
  });
  return { done, pairs, fraction: pairs ? done / pairs : 0 };
}

/* ------------------------------------------------------------------------ */
/* Cache countdown                                                          */
/* ------------------------------------------------------------------------ */

/**
 * Until when a resolver that is not done yet may keep the answer it gave: when it answered plus
 * the TTL that answer had left (a resolver counts its copy's TTL down; an empty answer carries the
 * negative TTL of the SOA). Null for a resolver that is done, failed, or gave no TTL.
 * @param {{ verdict: string, reason: string|null, ttl: number|null, at: number }|null} result a PairResult
 * @param {number} now ms epoch
 * @returns {{ kind: 'old'|'empty'|'ttl'|'other', until: number, leftMs: number, expired: boolean }|null}
 */
export function cacheCountdown(result, now) {
  if (!result || (result.verdict !== 'pending' && result.verdict !== 'wrong')) return null;
  if (!Number.isFinite(result.ttl) || result.ttl <= 0 || !Number.isFinite(Number(result.at))) return null;
  const until = Number(result.at) + result.ttl * 1000;
  const kind = result.verdict === 'wrong' ? 'other'
    : result.reason === 'old' ? 'old' : result.reason === 'missing' ? 'empty' : result.reason === 'ttl' ? 'ttl' : 'other';
  const leftMs = Math.max(0, until - now);
  return { kind, until, leftMs, expired: leftMs === 0 };
}

/**
 * The latest time a resolver that is not done yet may keep its cached answer (the countdowns'
 * last end), or null when no countdown runs.
 * @param {import('./changecheck.js').ExpectedCheck} check
 * @param {Map<string, object>|Record<string, object>} latest
 * @param {number} now
 * @param {string[]} [resolvers]
 * @returns {number|null}
 */
export function lastExpiry(check, latest, now, resolvers = CHECK_RESOLVERS) {
  const get = getter(latest);
  let last = null;
  (check && Array.isArray(check.sets) ? check.sets : []).forEach((_, set) => {
    for (const r of resolvers) {
      const cd = cacheCountdown(get(pairKey(set, r)), now);
      if (cd) last = Math.max(last ?? 0, cd.until);
    }
  });
  return last;
}

/**
 * Time left as a clock reads it: '4:07', '1:02:30' (never negative; seconds rounded up, so a
 * countdown reads 0:00 only once it has run out).
 * @param {number} ms
 * @returns {string}
 */
export function clockLeft(ms) {
  const total = Math.max(0, Math.ceil((Number(ms) || 0) / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const pad = (n) => String(n).padStart(2, '0');
  return hours ? `${hours}:${pad(minutes)}:${pad(total % 60)}` : `${minutes}:${pad(total % 60)}`;
}

/* ------------------------------------------------------------------------ */
/* TTL plan                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * The highest TTL a resolver returned with records, per set and over the whole check: a resolver
 * counts its cached copy down, so the zone's own TTL is at least this. Empty answers (whose TTL is
 * the negative TTL) and failures are left out.
 * @param {import('./changecheck.js').ExpectedCheck} check
 * @param {Map<string, object>|Record<string, object>} latest
 * @param {string[]} [resolvers]
 * @returns {{ max: number|null, sets: Array<number|null> }}
 */
export function observedTtl(check, latest, resolvers = CHECK_RESOLVERS) {
  const get = getter(latest);
  const sets = (check && Array.isArray(check.sets) ? check.sets : []).map((_, set) => {
    let best = null;
    for (const r of resolvers) {
      const res = get(pairKey(set, r));
      if (!res || res.verdict === 'error' || !Array.isArray(res.seen) || !res.seen.length || !Number.isFinite(res.ttl)) continue;
      best = Math.max(best ?? 0, res.ttl);
    }
    return best;
  });
  const known = sets.filter((x) => x !== null);
  return { max: known.length ? Math.max(...known) : null, sets };
}

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

/**
 * The first change time a plan proposes: once copies with the current TTL can have expired after
 * the TTL is lowered now, rounded up to the next quarter of an hour.
 * @param {number} now ms epoch
 * @param {number} currentTtl seconds
 * @param {number} [lowTtl]
 * @param {number} [stepMs] the rounding step
 * @returns {number} ms epoch
 */
export function defaultChangeAt(now, currentTtl, lowTtl = PLAN_DEFAULT_LOW, stepMs = 15 * 60 * 1000) {
  const cur = Number(currentTtl);
  const lead = Number.isFinite(cur) && cur > Number(lowTtl) ? cur * 1000 : 0;
  return Math.ceil((now + lead) / stepMs) * stepMs;
}

/**
 * @typedef {object} TtlPlan
 * @property {true} ok
 * @property {null} error
 * @property {number} currentTtl seconds
 * @property {number} lowTtl seconds (the current TTL when that is already as low)
 * @property {boolean} lower whether the TTL is lowered before the change
 * @property {number|null} lowerAt the latest time to lower it (ms epoch)
 * @property {number} changeAt
 * @property {number} liveBy every resolver's copy of the old answer has expired by then
 * @property {number|null} raiseAt raise the TTL back from then
 * @property {number} earliest the earliest change time if the TTL is lowered now
 * @property {string[]} notes {@link PLAN_NOTES}
 */

/**
 * The TTL plan of a change: lower the TTL at T − the current TTL (every copy cached before then
 * has expired at T), make the change at T, every resolver serves it by T + the low TTL, raise the
 * TTL back from T + 2 × the low TTL. A TTL that is already as low as the low one is not lowered.
 * @param {{ changeAt: number, currentTtl: number, lowTtl?: number, now: number }} input times in ms epoch, TTLs in seconds
 * @returns {TtlPlan|{ ok: false, error: 'ttl'|'low'|'time' }}
 */
export function ttlPlan({ changeAt, currentTtl, lowTtl = PLAN_DEFAULT_LOW, now }) {
  const cur = Number(currentTtl);
  const low = Number(lowTtl);
  const ttlOk = (v) => Number.isInteger(v) && v >= 1 && v <= TTL_MAX;
  if (!ttlOk(cur)) return { ok: false, error: 'ttl' };
  if (!ttlOk(low)) return { ok: false, error: 'low' };
  if (changeAt === null || changeAt === undefined || !Number.isFinite(Number(changeAt))) return { ok: false, error: 'time' };
  const at = Number(changeAt);
  const lower = cur > low;
  const used = lower ? low : cur;
  const lowerAt = lower ? at - cur * 1000 : null;
  const notes = [];
  if (at < now) notes.push('past');
  else if (lower && lowerAt < now) notes.push('late');
  if (!lower) notes.push('already-low');
  return {
    ok: true, error: null, currentTtl: cur, lowTtl: used, lower, lowerAt, changeAt: at,
    liveBy: at + used * 1000, raiseAt: lower ? at + 2 * used * 1000 : null, earliest: now + (lower ? cur * 1000 : 0), notes
  };
}

/** The plan's checklist texts, in both languages (views register them too, for the i18n checks). */
export const CUTOVER_I18N = Object.freeze({
  en: Object.freeze({
    'chg.cut.list.title': 'DNS cutover plan — zone {zone}',
    'chg.cut.list.records': 'Records: {records}',
    'chg.cut.list.lower': 'By {time}: lower the TTL of these records from {from} s to {to} s.',
    'chg.cut.list.change': 'At {time}: make the change (copies cached with the old TTL have expired by then).',
    'chg.cut.list.changeLow': 'At {time}: make the change (the TTL is already {ttl} s, nothing to lower first).',
    'chg.cut.list.live': 'By {time}: every resolver serves the new records.',
    'chg.cut.list.check': 'Check: {url}',
    'chg.cut.list.raise': 'From {time}: raise the TTL back to {to} s, once the check shows the change everywhere.'
  }),
  tr: Object.freeze({
    'chg.cut.list.title': 'DNS geçiş planı — zone {zone}',
    'chg.cut.list.records': 'Kayıtlar: {records}',
    'chg.cut.list.lower': 'En geç {time}: bu kayıtların TTL değerini {from} sn’den {to} sn’ye düşürün.',
    'chg.cut.list.change': 'Saat {time}: değişikliği yapın (eski TTL ile önbelleğe alınan kopyaların süresi o zamana kadar dolar).',
    'chg.cut.list.changeLow': 'Saat {time}: değişikliği yapın (TTL zaten {ttl} sn; önce düşürülecek bir şey yok).',
    'chg.cut.list.live': 'En geç {time}: tüm çözümleyiciler yeni kayıtları döndürür.',
    'chg.cut.list.check': 'Kontrol: {url}',
    'chg.cut.list.raise': '{time} itibarıyla: kontrol değişikliği her yerde gösterince TTL değerini yeniden {to} sn’ye yükseltin.'
  })
});

/** A plan's text in one language (English for an unknown one). */
function planText(lang, key, params = {}) {
  const dict = CUTOVER_I18N[lang] || CUTOVER_I18N.en;
  return String(dict[key] ?? CUTOVER_I18N.en[key] ?? key).replace(/\{([A-Za-z0-9_]+)\}/g, (m, k) => (params[k] === undefined ? m : String(params[k])));
}

/**
 * A time as a plan writes it, the same in every language and unambiguous across time zones:
 * '2026-10-08 14:00 UTC+03:00'.
 * @param {number} ms epoch
 * @param {number} [offsetMinutes] the time zone's offset east of UTC at that time (`-new Date(ms).getTimezoneOffset()`)
 * @returns {string}
 */
export function planStamp(ms, offsetMinutes = 0) {
  const off = Number.isFinite(offsetMinutes) ? Math.round(offsetMinutes) : 0;
  const d = new Date(ms + off * 60000);
  const pad = (n) => String(n).padStart(2, '0');
  const sign = off < 0 ? '-' : '+';
  const abs = Math.abs(off);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}

/**
 * The plan as a checklist to paste into a ticket or a chat, in English or Turkish: the zone, its
 * record sets, then one box per step with its time.
 * @param {TtlPlan} plan
 * @param {{ lang?: 'en'|'tr', zone: string, records: string[], url?: string|null, offsetOf?: (ms: number) => number }} opts
 *   `records`: the sets as 'name TYPE'; `offsetOf`: the time zone's offset (minutes east of UTC) at a time
 * @returns {string}
 */
export function planChecklist(plan, { lang = 'en', zone, records = [], url = null, offsetOf = () => 0 } = {}) {
  if (!plan || !plan.ok) return '';
  const tx = (key, params) => planText(lang, key, params);
  const at = (ms) => planStamp(ms, offsetOf(ms));
  const steps = [];
  if (plan.lower) steps.push(tx('chg.cut.list.lower', { time: at(plan.lowerAt), from: plan.currentTtl, to: plan.lowTtl }));
  steps.push(plan.lower ? tx('chg.cut.list.change', { time: at(plan.changeAt) }) : tx('chg.cut.list.changeLow', { time: at(plan.changeAt), ttl: plan.currentTtl }));
  steps.push(url ? `${tx('chg.cut.list.live', { time: at(plan.liveBy) })} ${tx('chg.cut.list.check', { url })}` : tx('chg.cut.list.live', { time: at(plan.liveBy) }));
  if (plan.lower) steps.push(tx('chg.cut.list.raise', { time: at(plan.raiseAt), to: plan.currentTtl }));
  const out = [tx('chg.cut.list.title', { zone })];
  if (records.length) out.push(tx('chg.cut.list.records', { records: records.join(' · ') }));
  out.push('', ...steps.map((s, i) => `[ ] ${i + 1}. ${s}`));
  return `${out.join('\n')}\n`;
}
