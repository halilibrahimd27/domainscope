// Unit tests for assets/js/lib/cutover.js — the cutover assistant of the "is it live?" page: the
// watch's schedule, the cache countdowns and the TTL plan with its checklist. Pure: every time is
// injected, a fake DohClient answers from a table. Documentation names and addresses only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  WATCH_TIMING, CACHE_KINDS, PLAN_LOW_TTLS, PLAN_DEFAULT_LOW, COMMON_TTLS, PLAN_ERRORS, PLAN_NOTES, CUTOVER_I18N, nextWatch, watchProgress,
  cacheCountdown, lastExpiry, clockLeft, observedTtl, likelyTtl, defaultChangeAt, ttlPlan, planStamp, planChecklist
} from '../../assets/js/lib/cutover.js';
import { CHECK_RESOLVERS, CHECK_TIMING, checkRound, nextCheck, pairKey } from '../../assets/js/lib/changecheck.js';

const T0 = Date.UTC(2026, 9, 8, 11, 0, 0);
const exp = (over) => ({ name: 'www.example.com', type: 'A', mode: 'is', family: null, values: ['192.0.2.10'], old: ['198.51.100.5'], maxTtl: null, ...over });
const check = { zone: 'example.com', sets: [exp()] };
const pair = (verdict, over = {}) => ({ set: 0, resolver: 'cloudflare', verdict, reason: null, seen: [], ttl: null, at: T0, ...over });
/** pairKey → result for the one set of `check`, one entry per resolver. */
const latestOf = (byResolver) => new Map(Object.entries(byResolver).map(([r, v]) => [pairKey(0, r), { ...v, resolver: r }]));

describe('watch schedule', () => {
  test('the watch keeps asking past a check’s two hours, up to 24 hours', () => {
    assert.equal(WATCH_TIMING.stopAfter, 24 * 3600 * 1000);
    assert.equal(WATCH_TIMING.base, CHECK_TIMING.base, 'the same backoff: never faster than a check');
    assert.equal(WATCH_TIMING.max, CHECK_TIMING.max);
    const latest = latestOf({ cloudflare: pair('pending', { reason: 'old', seen: ['198.51.100.5'], ttl: 60 }), google: pair('done'), dnssb: pair('done'), cznic: pair('done') });
    const late = T0 + 3 * 3600 * 1000;
    assert.equal(nextCheck({ latest, check, round: 9, startedAt: T0, now: late }).stop, 'timeout', 'a check stops after two hours');
    const n = nextWatch({ latest, check, round: 9, startedAt: T0, now: late });
    assert.equal(n.stop, null, 'a watch goes on');
    assert.deepEqual(n.pairs, [pairKey(0, 'cloudflare')], 'only what is not done');
    assert.equal(nextWatch({ latest, check, round: 9, startedAt: T0, now: T0 + 25 * 3600 * 1000 }).stop, 'timeout', 'and stops after 24 hours');
  });

  test('a TTL longer than a check’s deadline stops a check (cached), a watch waits for it', () => {
    const latest = latestOf({ cloudflare: pair('pending', { reason: 'old', seen: ['198.51.100.5'], ttl: 10800 }), google: pair('done'), dnssb: pair('done'), cznic: pair('done') });
    assert.equal(nextCheck({ latest, check, round: 1, startedAt: T0, now: T0 + 1000 }).stop, 'cached');
    const n = nextWatch({ latest, check, round: 1, startedAt: T0, now: T0 + 1000 });
    assert.equal(n.stop, null);
    assert.equal(n.at, T0 + 10800 * 1000 + 1000, 'never before the cached copy can have expired');
  });

  test('never faster than the schedule: the backoff and every cached copy are waited for', () => {
    const latest = latestOf({ cloudflare: pair('pending', { reason: 'old', seen: ['198.51.100.5'], ttl: 5 }), google: pair('pending', { reason: 'old', seen: ['198.51.100.5'], ttl: 600 }), dnssb: pair('done'), cznic: pair('done') });
    for (let round = 0; round < 12; round += 1) {
      const now = T0 + 2000;
      const n = nextWatch({ latest, check, round, startedAt: T0, now, lastAt: now });
      const backoff = Math.min(CHECK_TIMING.base * CHECK_TIMING.factor ** round, CHECK_TIMING.max);
      assert.ok(n.at >= now + backoff, `round ${round}: the backoff`);
      for (const k of n.pairs) {
        const r = latest.get(k);
        assert.ok(n.at >= r.at + r.ttl * 1000, `round ${round}: ${k} asked only once its copy can have expired`);
      }
    }
  });

  test('the backoff counts from the last round: a watch turned on long after a stop asks at once, never before now', () => {
    const latest = latestOf({ cloudflare: pair('pending', { reason: 'old', seen: ['198.51.100.5'], ttl: 60 }), google: pair('done'), dnssb: pair('done'), cznic: pair('done') });
    const now = T0 + 3600 * 1000;
    const n = nextWatch({ latest, check, round: 4, startedAt: now, now, lastAt: T0 + 5000 });
    assert.equal(n.at, now, 'due long ago: now');
    assert.deepEqual(n.pairs, [pairKey(0, 'cloudflare')]);
    const soon = nextWatch({ latest, check, round: 1, startedAt: T0, now: T0 + 10_000, lastAt: T0 + 5000 });
    assert.equal(soon.at, Math.max(T0 + 5000 + CHECK_TIMING.base * CHECK_TIMING.factor, T0 + 61_000), 'the backoff from the last round, or the cache');
    const without = nextCheck({ latest, check, round: 1, startedAt: T0, now: T0 + 10_000 });
    assert.equal(without.at, Math.max(T0 + 10_000 + CHECK_TIMING.base * CHECK_TIMING.factor, T0 + 61_000), 'nextCheck without lastAt: as before');
  });

  test('done, failed: the watch stops as a check does', () => {
    const done = latestOf(Object.fromEntries(CHECK_RESOLVERS.map((r) => [r, pair('done')])));
    assert.equal(nextWatch({ latest: done, check, round: 2, startedAt: T0, now: T0 }).stop, 'done');
    const failed = latestOf(Object.fromEntries(CHECK_RESOLVERS.map((r) => [r, pair('error', { reason: 'timeout' })])));
    assert.equal(nextWatch({ latest: failed, check, round: 3, startedAt: T0, now: T0, errorRounds: 3 }).stop, 'failed');
  });

  test('a watch round on a fake resolver whose answer flips: pending, then done', async () => {
    let flipped = false;
    const dns = { query: async (name, type, { resolver }) => ({ ok: true, rcode: 'NOERROR', authorities: [], answers: [{ name, type, ttl: 30, data: flipped || resolver === 'google' ? '192.0.2.10' : '198.51.100.5' }] }) };
    const latest = new Map();
    const record = (r) => latest.set(pairKey(r.set, r.resolver), r);
    (await checkRound(check, { dns, now: () => T0 })).forEach(record);
    assert.deepEqual(watchProgress(check, latest), { done: 1, pairs: 4, fraction: 0.25 });
    const n = nextWatch({ latest, check, round: 1, startedAt: T0, now: T0 + 500, lastAt: T0 + 500 });
    assert.equal(n.pairs.length, 3, 'the three that still serve the old value');
    assert.ok(n.at >= T0 + 31_000, 'once their 30 s copies can have expired');
    flipped = true;
    (await checkRound(check, { dns, only: new Set(n.pairs), now: () => n.at })).forEach(record);
    assert.deepEqual(watchProgress(check, latest), { done: 4, pairs: 4, fraction: 1 });
    assert.equal(nextWatch({ latest, check, round: 2, startedAt: T0, now: n.at + 100, lastAt: n.at + 100 }).stop, 'done');
  });
});

describe('cache countdown', () => {
  test('the old value, “no record”, the old TTL, another answer; a resolver that is done or failed has none', () => {
    const at = T0;
    assert.deepEqual(cacheCountdown(pair('pending', { reason: 'old', seen: ['198.51.100.5'], ttl: 300, at }), at + 60_000),
      { kind: 'old', until: at + 300_000, leftMs: 240_000, expired: false });
    assert.equal(cacheCountdown(pair('pending', { reason: 'missing', ttl: 900, at }), at).kind, 'empty');
    assert.equal(cacheCountdown(pair('pending', { reason: 'ttl', seen: ['192.0.2.10'], ttl: 3600, at }), at).kind, 'ttl');
    assert.equal(cacheCountdown(pair('pending', { reason: 'other', seen: ['203.0.113.9'], ttl: 60, at }), at).kind, 'other');
    assert.equal(cacheCountdown(pair('wrong', { seen: ['203.0.113.9'], ttl: 60, at }), at).kind, 'other');
    assert.equal(cacheCountdown(pair('done', { ttl: 300 }), at), null);
    assert.equal(cacheCountdown(pair('error', { reason: 'timeout' }), at), null);
    assert.equal(cacheCountdown(pair('pending', { reason: 'old', ttl: null }), at), null, 'no TTL: no countdown');
    assert.equal(cacheCountdown(pair('pending', { reason: 'old', ttl: 0 }), at), null);
    assert.equal(cacheCountdown(null, at), null);
    assert.deepEqual(CACHE_KINDS, ['old', 'empty', 'ttl', 'other']);
  });

  test('it runs out: expired once its time has come, never negative', () => {
    const r = pair('pending', { reason: 'old', ttl: 90, at: T0 });
    assert.equal(cacheCountdown(r, T0 + 89_999).expired, false);
    assert.deepEqual(cacheCountdown(r, T0 + 90_000), { kind: 'old', until: T0 + 90_000, leftMs: 0, expired: true });
    assert.equal(cacheCountdown(r, T0 + 999_999).leftMs, 0);
  });

  test('the last expiry: no cached old answer outlives it', () => {
    const latest = latestOf({
      cloudflare: pair('pending', { reason: 'old', ttl: 120, at: T0 }), google: pair('pending', { reason: 'missing', ttl: 900, at: T0 + 5000 }),
      dnssb: pair('done', { ttl: 9999 }), cznic: pair('error', { reason: 'timeout' })
    });
    assert.equal(lastExpiry(check, latest, T0), T0 + 905_000);
    assert.equal(lastExpiry(check, new Map(), T0), null);
  });

  test('clockLeft reads as a clock, seconds rounded up', () => {
    assert.equal(clockLeft(0), '0:00');
    assert.equal(clockLeft(1), '0:01');
    assert.equal(clockLeft(59_001), '1:00');
    assert.equal(clockLeft(247_000), '4:07');
    assert.equal(clockLeft(3_750_000), '1:02:30');
    assert.equal(clockLeft(-5), '0:00');
    assert.equal(clockLeft(NaN), '0:00');
  });
});

describe('TTL plan', () => {
  test('the observed TTL: the highest a resolver returned with records; empty answers and failures left out', () => {
    const latest = latestOf({
      cloudflare: pair('pending', { reason: 'old', seen: ['198.51.100.5'], ttl: 3487 }), google: pair('pending', { reason: 'old', seen: ['198.51.100.5'], ttl: 1200 }),
      dnssb: pair('pending', { reason: 'missing', seen: [], ttl: 86400 }), cznic: pair('error', { reason: 'timeout', ttl: 99999 })
    });
    assert.deepEqual(observedTtl(check, latest), { max: 3487, sets: [3487] });
    assert.deepEqual(observedTtl({ sets: [exp(), exp({ name: 'api.example.com' })] }, latest), { max: 3487, sets: [3487, null] });
    assert.deepEqual(observedTtl(check, new Map()), { max: null, sets: [null] });
  });

  test('likelyTtl rounds a counted-down TTL up to a common one', () => {
    assert.equal(likelyTtl(3487), 3600);
    assert.equal(likelyTtl(3600), 3600);
    assert.equal(likelyTtl(250), 300);
    assert.equal(likelyTtl(1), 60);
    assert.equal(likelyTtl(700000), 700000, 'above them all: as it is');
    assert.equal(likelyTtl(null), null);
    assert.equal(likelyTtl(0), null);
    assert.ok(COMMON_TTLS.every((x, i) => i === 0 || x > COMMON_TTLS[i - 1]), 'ascending');
  });

  test('lower at T − the current TTL, change at T, live by T + low, raise from T + 2 × low', () => {
    const changeAt = T0 + 2 * 3600 * 1000;
    const plan = ttlPlan({ changeAt, currentTtl: 3600, lowTtl: 300, now: T0 });
    assert.deepEqual(plan, {
      ok: true, error: null, currentTtl: 3600, lowTtl: 300, lower: true, lowerAt: changeAt - 3600_000, changeAt,
      liveBy: changeAt + 300_000, raiseAt: changeAt + 600_000, earliest: T0 + 3600_000, notes: []
    });
    assert.equal(PLAN_DEFAULT_LOW, 300);
    assert.ok(PLAN_LOW_TTLS.includes(PLAN_DEFAULT_LOW));
    assert.equal(ttlPlan({ changeAt, currentTtl: 3600, now: T0 }).lowTtl, 300, 'the default low TTL');
  });

  test('too late to lower in time, a time gone by, a TTL already low; what cannot be planned', () => {
    const late = ttlPlan({ changeAt: T0 + 600_000, currentTtl: 3600, lowTtl: 300, now: T0 });
    assert.deepEqual(late.notes, ['late']);
    assert.equal(late.earliest, T0 + 3600_000, 'lowered now: the earliest change time');
    assert.deepEqual(ttlPlan({ changeAt: T0 - 1000, currentTtl: 3600, now: T0 }).notes, ['past']);
    const low = ttlPlan({ changeAt: T0 + 600_000, currentTtl: 120, lowTtl: 300, now: T0 });
    assert.equal(low.lower, false);
    assert.equal(low.lowerAt, null);
    assert.equal(low.raiseAt, null);
    assert.equal(low.lowTtl, 120, 'the TTL as it is');
    assert.equal(low.liveBy, T0 + 600_000 + 120_000);
    assert.deepEqual(low.notes, ['already-low']);
    assert.deepEqual(ttlPlan({ changeAt: T0, currentTtl: 300, lowTtl: 300, now: T0 }).notes, ['already-low'], 'equal: nothing to lower');
    for (const bad of [0, -5, 1.5, NaN, '', null, 2147483648]) assert.equal(ttlPlan({ changeAt: T0, currentTtl: bad, now: T0 }).error, 'ttl', String(bad));
    assert.equal(ttlPlan({ changeAt: T0, currentTtl: 3600, lowTtl: 0, now: T0 }).error, 'low');
    assert.equal(ttlPlan({ changeAt: NaN, currentTtl: 3600, now: T0 }).error, 'time');
    assert.equal(ttlPlan({ changeAt: null, currentTtl: 3600, now: T0 }).error, 'time');
    assert.deepEqual(PLAN_ERRORS, ['ttl', 'low', 'time']);
    assert.deepEqual(PLAN_NOTES, ['past', 'late', 'already-low']);
  });

  test('the proposed change time: copies with the current TTL expired, on a quarter of an hour', () => {
    const now = Date.UTC(2026, 9, 8, 11, 2, 0);
    assert.equal(defaultChangeAt(now, 3600, 300), Date.UTC(2026, 9, 8, 12, 15, 0));
    assert.equal(defaultChangeAt(now, 120, 300), Date.UTC(2026, 9, 8, 11, 15, 0), 'nothing to lower: the next quarter');
    assert.equal(defaultChangeAt(Date.UTC(2026, 9, 8, 11, 0, 0), 900, 300), Date.UTC(2026, 9, 8, 11, 15, 0), 'already on a quarter');
  });

  test('planStamp: the same in every language, with its UTC offset', () => {
    const ms = Date.UTC(2026, 9, 8, 11, 0, 0);
    assert.equal(planStamp(ms, 180), '2026-10-08 14:00 UTC+03:00');
    assert.equal(planStamp(ms, 0), '2026-10-08 11:00 UTC+00:00');
    assert.equal(planStamp(ms, -330), '2026-10-08 05:30 UTC-05:30');
    assert.equal(planStamp(Date.UTC(2026, 9, 8, 22, 30, 0), 180), '2026-10-09 01:30 UTC+03:00', 'the next day');
  });

  test('the checklist in English and Turkish: one box per step, its times, the check link', () => {
    const changeAt = Date.UTC(2026, 9, 8, 11, 0, 0);
    const plan = ttlPlan({ changeAt, currentTtl: 3600, lowTtl: 300, now: changeAt - 2 * 3600_000 });
    const opts = { zone: 'example.com', records: ['www.example.com A', 'api.example.com CNAME'], url: 'https://example.org/#/change/check?z=example.com', offsetOf: () => 180 };
    assert.equal(planChecklist(plan, { ...opts, lang: 'en' }), [
      'DNS cutover plan — zone example.com',
      'Records: www.example.com A · api.example.com CNAME',
      '',
      '[ ] 1. By 2026-10-08 13:00 UTC+03:00: lower the TTL of these records from 3600 s to 300 s.',
      '[ ] 2. At 2026-10-08 14:00 UTC+03:00: make the change (copies cached with the old TTL have expired by then).',
      '[ ] 3. By 2026-10-08 14:05 UTC+03:00: every resolver serves the new records. Check: https://example.org/#/change/check?z=example.com',
      '[ ] 4. From 2026-10-08 14:10 UTC+03:00: raise the TTL back to 3600 s, once the check shows the change everywhere.',
      ''
    ].join('\n'));
    const trText = planChecklist(plan, { ...opts, lang: 'tr' });
    assert.match(trText, /^DNS geçiş planı — zone example\.com\nKayıtlar: /);
    assert.match(trText, /\[ \] 1\. En geç 2026-10-08 13:00 UTC\+03:00: bu kayıtların TTL değerini 3600 sn’den 300 sn’ye düşürün\./);
    assert.match(trText, /\[ \] 4\. 2026-10-08 14:10 UTC\+03:00 itibarıyla: /);
    assert.doesNotMatch(trText, /'/, 'Turkish uses ’, never \'');
    const low = planChecklist(ttlPlan({ changeAt, currentTtl: 120, now: changeAt - 1000 }), { ...opts, url: null, lang: 'en' });
    assert.deepEqual(low.split('\n').filter((l) => l.startsWith('[ ]')), [
      '[ ] 1. At 2026-10-08 14:00 UTC+03:00: make the change (the TTL is already 120 s, nothing to lower first).',
      '[ ] 2. By 2026-10-08 14:02 UTC+03:00: every resolver serves the new records.'
    ]);
    assert.equal(planChecklist({ ok: false, error: 'ttl' }, opts), '');
    assert.equal(planChecklist(plan, { ...opts, lang: 'de' }).split('\n')[0], 'DNS cutover plan — zone example.com', 'an unknown language: English');
  });

  test('the checklist texts: the same keys and placeholders in both languages', () => {
    const ph = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
    assert.deepEqual(Object.keys(CUTOVER_I18N.tr).sort(), Object.keys(CUTOVER_I18N.en).sort());
    for (const [k, v] of Object.entries(CUTOVER_I18N.en)) assert.equal(ph(CUTOVER_I18N.tr[k]), ph(v), k);
  });
});
