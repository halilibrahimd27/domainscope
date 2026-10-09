/**
 * lib/waivers.js — accepted risks and known certificates: validation (every refusal), the file and
 * the workspace part, expiry on an injected clock (the end of the last day, UTC; the 14-day
 * "ending soon"), matching (kind, exact domain, refs; an active waiver before an expired one),
 * applyWaivers, a Domain Health report's waivers, and the list operations. No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  WAIVER_KINDS, WAIVER_ERRORS, WAIVER_STATES, WAIVERS_FORMAT, WAIVERS_VERSION, WAIVERS_MAX, WAIVERS_MAX_CHARS, WAIVER_REASON_MAX, WAIVER_OWNER_MAX,
  WAIVER_MAX_DAYS, WAIVER_DEFAULT_DAYS, WAIVER_SOON_DAYS, WAIVERS_I18N, WaiverError, normalizeRef, waiverKey, waiverId, validateWaiver, sanitizeWaivers,
  parseWaivers, waiversPartText, waiversFileText, readWaivers, addWaiver, removeWaiver, mergeWaivers, waiverCounts, waiverEnd, waiverState,
  isWaiverActive, matchWaiver, applyWaivers, healthWaivers, isWaivableCheck, defaultExpiry, maxExpiry, utcDay, addDays
} from '../../assets/js/lib/waivers.js';

/** The instant the expectations were written for. */
const NOW = Date.parse('2026-10-09T12:00:00Z');
const DAY = 86400000;
const SPKI = 'ab'.repeat(32);
const CERT = 'cd'.repeat(32);
const entry = (o = {}) => ({ kind: 'finding', domain: 'example.com', ref: 'dmarc.policy-none', reason: 'Moving to quarantine in Q1', owner: 'Mail team', expires: '2026-12-31', ...o });
const valid = (o) => validateWaiver(entry(o), { now: NOW });

describe('one entry', () => {
  test('a valid entry is written as it is kept: normalized, its id from kind, domain and ref', () => {
    const { waiver, error } = validateWaiver(entry({ domain: ' Example.COM. ', ref: 'DMARC.Policy-None', reason: '  Moving\tto  quarantine ', owner: ' Mail team ', created: '2026-10-01T08:00:00Z' }), { now: NOW });
    assert.equal(error, null);
    assert.deepEqual(waiver, {
      id: waiverId('finding', 'example.com', 'dmarc.policy-none'), kind: 'finding', domain: 'example.com', ref: 'dmarc.policy-none',
      reason: 'Moving to quarantine', owner: 'Mail team', created: '2026-10-01T08:00:00.000Z', expires: '2026-12-31'
    });
    assert.match(waiver.id, /^w-[0-9a-f]{16}$/);
    assert.equal(waiverId('finding', 'example.com', 'dmarc.policy-none'), waiver.id, 'the same item, the same id');
    assert.notEqual(waiverId('finding', 'example.org', 'dmarc.policy-none'), waiver.id);
    assert.equal(waiverKey('rule', 'example.com', 'transferLock'), 'rule|example.com|transferLock');
  });

  test('every refusal has its code', () => {
    const code = (o) => valid(o).error && valid(o).error.code;
    assert.equal(validateWaiver(null).error.code, 'not-object');
    assert.equal(validateWaiver([entry()]).error.code, 'not-object');
    assert.equal(code({ kind: 'host' }), 'kind');
    assert.equal(code({ domain: 'not a domain' }), 'domain');
    assert.equal(code({ domain: 42 }), 'domain');
    assert.equal(code({ ref: 'no spaces allowed' }), 'ref');
    assert.equal(code({ kind: 'cert', ref: 'abcd' }), 'ref');
    assert.equal(code({ kind: 'rule', ref: '1rule' }), 'ref');
    assert.equal(code({ reason: '' }), 'reason');
    assert.equal(code({ reason: '   ' }), 'reason');
    assert.equal(code({ reason: 'x'.repeat(WAIVER_REASON_MAX + 1) }), 'reason');
    assert.equal(code({ owner: 'x'.repeat(WAIVER_OWNER_MAX + 1) }), 'owner');
    assert.equal(code({ expires: '' }), 'expires');
    assert.equal(code({ expires: '2026-02-30' }), 'expires', 'not a calendar day');
    assert.equal(code({ expires: '31.12.2026' }), 'expires');
    assert.equal(code({ created: 'yesterday' }), 'created');
    assert.deepEqual(WAIVER_KINDS, ['finding', 'rule', 'cert']);
    for (const c of ['not-object', 'kind', 'domain', 'ref', 'reason', 'owner', 'expires', 'too-far', 'created']) assert.ok(WAIVER_ERRORS.includes(c), c);
  });

  test('a reason of exactly the limit, no owner, no created: valid', () => {
    const { waiver } = valid({ reason: 'é'.repeat(WAIVER_REASON_MAX), owner: undefined, created: undefined });
    assert.equal([...waiver.reason].length, WAIVER_REASON_MAX);
    assert.equal(waiver.owner, '');
    assert.equal(waiver.created, null);
  });

  test('controls and bidi overrides never reach a reason or an owner', () => {
    const { waiver } = valid({ reason: `ok${String.fromCharCode(0x202e)}gnirts\u0007 here`, owner: `a${String.fromCharCode(0x200b)}b` });
    assert.equal(waiver.reason, 'ok gnirts here');
    assert.equal(waiver.owner, 'a b');
    // the bidi isolates (U+2066–U+2069) and the Arabic letter mark (U+061C) reorder text too
    const isolates = valid({ reason: ['a', 'b', 'c', 'd', 'e', 'f'].join(String.fromCharCode(0x2066)), owner: `x${String.fromCharCode(0x061c)}y${String.fromCharCode(0x2069)}z` }).waiver;
    assert.equal(isolates.reason, 'a b c d e f');
    assert.equal(isolates.owner, 'x y z');
    for (const cp of [0x2067, 0x2068, 0x2069]) assert.equal(valid({ reason: `p${String.fromCharCode(cp)}q` }).waiver.reason, 'p q', cp.toString(16));
  });

  test('refs by kind: a check id in lower case, a rule id as written, a SHA-256 as 64 lower-case hex digits', () => {
    assert.equal(normalizeRef('finding', ' SPF.Lookups-High '), 'spf.lookups-high');
    assert.equal(normalizeRef('rule', 'dmarc.policy'), 'dmarc.policy');
    assert.equal(normalizeRef('rule', 'transferLock'), 'transferLock');
    const colons = SPKI.toUpperCase().match(/../g).join(':');
    assert.equal(normalizeRef('cert', colons), SPKI);
    assert.equal(normalizeRef('cert', `sha256:${SPKI}`), SPKI);
    assert.equal(normalizeRef('cert', SPKI.slice(1)), null);
    assert.equal(normalizeRef('nothing', 'x'), null);
    assert.equal(normalizeRef('finding', null), null);
  });

  test('expires: a day, or an ISO time read as its UTC day; at most 366 days ahead with a day of grace; an expired one is valid', () => {
    assert.equal(valid({ expires: '2026-12-31T22:30:00-05:00' }).waiver.expires, '2027-01-01');
    const max = maxExpiry(NOW);
    assert.equal(max, addDays(utcDay(NOW), WAIVER_MAX_DAYS));
    assert.equal(max, '2027-10-10');
    assert.equal(valid({ expires: max }).error, null);
    assert.equal(valid({ expires: addDays(max, 1) }).error, null, 'a form in a time zone ahead of UTC');
    assert.deepEqual(valid({ expires: addDays(max, 2) }).error, { code: 'too-far', field: 'expires' });
    assert.equal(valid({ expires: '2026-01-01' }).error, null, 'listed as expired, never refused');
  });
});

describe('expiry on an injected clock', () => {
  const w = valid({ expires: '2026-10-20' }).waiver;

  test('a waiver applies to the end of its last day (UTC)', () => {
    assert.equal(waiverEnd(w), Date.parse('2026-10-21T00:00:00Z'));
    assert.equal(isWaiverActive(w, { now: Date.parse('2026-10-20T23:59:59Z') }), true);
    assert.equal(isWaiverActive(w, { now: Date.parse('2026-10-21T00:00:00Z') }), false);
    assert.equal(waiverEnd({ expires: 'bad' }), -Infinity);
  });

  test('active, then ending within 14 days, then expired', () => {
    assert.equal(waiverState(valid({ expires: '2026-12-31' }).waiver, { now: NOW }), 'active');
    assert.equal(waiverState(w, { now: NOW }), 'expiring', `${WAIVER_SOON_DAYS} days or fewer left`);
    // 13.5 days left, then 14.5: the end of the last day counts
    assert.equal(waiverState(valid({ expires: '2026-10-22' }).waiver, { now: NOW }), 'expiring');
    assert.equal(waiverState(valid({ expires: '2026-10-23' }).waiver, { now: NOW }), 'active');
    assert.equal(waiverState(w, { now: Date.parse('2026-10-21T00:00:00Z') }), 'expired');
    assert.deepEqual(WAIVER_STATES, ['active', 'expiring', 'expired']);
  });

  test('the counts and the first day an active one ends', () => {
    const list = [valid({ expires: '2026-12-31' }).waiver, valid({ ref: 'spf.ptr', expires: '2026-10-20' }).waiver, valid({ ref: 'caa.missing', expires: '2026-10-01' }).waiver];
    assert.deepEqual(waiverCounts(list, { now: NOW }), { total: 3, active: 2, expiring: 1, expired: 1, next: '2026-10-20' });
    assert.deepEqual(waiverCounts([], { now: NOW }), { total: 0, active: 0, expiring: 0, expired: 0, next: null });
  });

  test('the forms offer 90 days, at most 366', () => {
    assert.equal(WAIVER_DEFAULT_DAYS, 90);
    assert.equal(defaultExpiry(NOW), '2027-01-07');
    assert.equal(defaultExpiry(new Date(NOW), 10), '2026-10-19');
    assert.equal(utcDay(Date.parse('2026-10-09T23:59:59Z')), '2026-10-09');
  });
});

describe('a list and its file', () => {
  test('sanitize: invalid entries said with their index, one waiver per item (the later one, in place), at most 500', () => {
    const { waivers, errors } = sanitizeWaivers([entry({ reason: 'first' }), { kind: 'x' }, entry({ ref: 'spf.ptr' }), entry({ reason: 'second' })], { now: NOW });
    assert.deepEqual(waivers.map((w) => [w.ref, w.reason]), [['dmarc.policy-none', 'second'], ['spf.ptr', 'Moving to quarantine in Q1']]);
    assert.deepEqual(errors, [{ index: 1, code: 'kind', field: 'kind' }]);
    const many = Array.from({ length: WAIVERS_MAX + 2 }, (_, i) => entry({ ref: `x.check-${i}` }));
    const capped = sanitizeWaivers(many, { now: NOW });
    assert.equal(capped.waivers.length, WAIVERS_MAX);
    assert.deepEqual(capped.errors, [{ index: WAIVERS_MAX, code: 'too-many', field: null }]);
  });

  test('parse: the file, a bare list, nothing; refused when it is not JSON, not a waivers file or newer', () => {
    const file = { format: WAIVERS_FORMAT, v: WAIVERS_VERSION, waivers: [entry(), { kind: 'rule' }] };
    const parsed = parseWaivers(JSON.stringify(file), { now: NOW });
    assert.equal(parsed.ok, true);
    assert.equal(parsed.waivers.length, 1);
    assert.deepEqual(parsed.errors.map((e) => [e.index, e.code]), [[1, 'domain']]);
    assert.equal(parseWaivers(`\ufeff${JSON.stringify([entry()])}`, { now: NOW }).waivers.length, 1, 'a bare list, a BOM');
    assert.deepEqual(parseWaivers(file, { now: NOW }).waivers, parsed.waivers, 'a parsed value too');
    for (const empty of ['', '  ', null, undefined]) assert.deepEqual(parseWaivers(empty), { ok: true, waivers: [], errors: [] });
    const refused = (input) => { const r = parseWaivers(input, { now: NOW }); return [r.ok, r.errors[0].code]; };
    assert.deepEqual(refused('{ nope'), [false, 'not-json']);
    assert.deepEqual(refused('{"format":"domainscope-workspace","waivers":[]}'), [false, 'not-waivers']);
    assert.deepEqual(refused('{"waivers":[]}'), [false, 'not-waivers']);
    assert.deepEqual(refused(JSON.stringify({ ...file, v: 2 })), [false, 'newer']);
    assert.deepEqual(refused('x'.repeat(WAIVERS_MAX_CHARS * 4 + 1)), [false, 'too-large']);
    assert.deepEqual(refused(Array.from({ length: WAIVERS_MAX * 4 + 1 }, () => ({}))), [false, 'too-many']);
  });

  test('the workspace part: compact JSON of the file, sorted, read back the same; empty is ""; too large refused', () => {
    const list = [valid({ domain: 'example.org' }).waiver, valid({ kind: 'cert', ref: SPKI }).waiver, valid({ kind: 'rule', ref: 'transferLock' }).waiver];
    const text = waiversPartText(list);
    const doc = JSON.parse(text);
    assert.deepEqual([doc.format, doc.v], [WAIVERS_FORMAT, WAIVERS_VERSION]);
    assert.deepEqual(doc.waivers.map((w) => `${w.domain} ${w.kind}`), ['example.com rule', 'example.com cert', 'example.org finding']);
    assert.deepEqual(readWaivers(text, { now: NOW }), doc.waivers);
    assert.ok(!text.includes('\n'), 'compact');
    assert.equal(waiversPartText([]), '');
    assert.throws(() => waiversPartText(Array.from({ length: 400 }, (_, i) => valid({ ref: `x.c-${i}`, reason: 'r'.repeat(200) }).waiver)), (e) => e instanceof WaiverError && e.code === 'too-large');
    assert.deepEqual(readWaivers('not json'), []);
    assert.deepEqual(readWaivers(42), []);
  });

  test('waivers.json: indented, with the tool and the time of the export; the runner reads it back', () => {
    const list = [valid().waiver];
    const text = waiversFileText(list, { now: NOW, app: 'DomainScope 1.0.0' });
    assert.ok(text.endsWith('\n') && text.includes('\n  "format"'));
    const doc = JSON.parse(text);
    assert.deepEqual([doc.app, doc.exportedAt], ['DomainScope 1.0.0', '2026-10-09T12:00:00.000Z']);
    assert.deepEqual(parseWaivers(text, { now: NOW }).waivers, list);
  });

  test('add (created now, the same item replaced, an end date before today refused), remove, merge', () => {
    const { list, waiver, replaced } = addWaiver([], entry(), { now: NOW });
    assert.equal(replaced, false);
    assert.equal(waiver.created, '2026-10-09T12:00:00.000Z');
    const again = addWaiver(list, entry({ reason: 'still', expires: '2027-01-31' }), { now: NOW });
    assert.equal(again.replaced, true);
    assert.deepEqual(again.list.map((w) => [w.reason, w.expires]), [['still', '2027-01-31']]);
    assert.throws(() => addWaiver(list, entry({ expires: '2026-10-08' }), { now: NOW }), (e) => e instanceof WaiverError && e.code === 'expires');
    assert.doesNotThrow(() => addWaiver(list, entry({ ref: 'spf.ptr', expires: '2026-10-09' }), { now: NOW }), 'today is the last day it applies');
    assert.throws(() => addWaiver(list, entry({ reason: '' }), { now: NOW }), (e) => e.code === 'reason');
    const full = Array.from({ length: WAIVERS_MAX }, (_, i) => valid({ ref: `x.c-${i}` }).waiver);
    assert.throws(() => addWaiver(full, entry(), { now: NOW }), (e) => e.code === 'too-many');
    assert.deepEqual(removeWaiver(again.list, waiver.id), []);
    assert.deepEqual(removeWaiver(null, 'x'), []);
    const merged = mergeWaivers(list, [valid({ reason: 'imported' }).waiver, valid({ ref: 'spf.ptr' }).waiver]);
    assert.deepEqual([merged.added, merged.replaced], [1, 1]);
    assert.deepEqual(merged.list.map((w) => w.reason), ['imported', 'Moving to quarantine in Q1']);
  });
});

describe('matching', () => {
  const active = valid().waiver;
  const old = valid({ ref: 'spf.ptr', expires: '2026-09-30' }).waiver;
  const later = valid({ ref: 'spf.ptr', domain: 'example.org', expires: '2026-12-01' }).waiver;
  const cert = valid({ kind: 'cert', ref: SPKI, reason: 'Our CDN' }).waiver;

  test('the kind, the exact domain and the ref: a subdomain is not covered', () => {
    assert.deepEqual(matchWaiver([active], { kind: 'finding', domain: 'Example.com', ref: 'DMARC.policy-none' }, { now: NOW }), { waiver: active, active: true });
    assert.equal(matchWaiver([active], { kind: 'finding', domain: 'www.example.com', ref: 'dmarc.policy-none' }, { now: NOW }), null);
    assert.equal(matchWaiver([active], { kind: 'rule', domain: 'example.com', ref: 'dmarc.policy-none' }, { now: NOW }), null);
    assert.equal(matchWaiver([active], { kind: 'finding', domain: 'example.com', ref: 'spf.ptr' }, { now: NOW }), null);
    assert.equal(matchWaiver([], { kind: 'finding', domain: 'example.com', ref: 'x' }), null);
    assert.equal(matchWaiver([active], null), null);
  });

  test('an expired waiver is found as expired; an active one wins over it', () => {
    assert.deepEqual(matchWaiver([old], { kind: 'finding', domain: 'example.com', ref: 'spf.ptr' }, { now: NOW }), { waiver: old, active: false });
    const renewed = { ...old, id: 'w-renewed', expires: '2027-01-01' };
    assert.deepEqual(matchWaiver([old, renewed], { kind: 'finding', domain: 'example.com', ref: 'spf.ptr' }, { now: NOW }), { waiver: renewed, active: true });
  });

  test('a certificate by any of its refs (its key, or itself)', () => {
    assert.equal(matchWaiver([cert], { kind: 'cert', domain: 'example.com', refs: [SPKI, CERT] }, { now: NOW }).waiver, cert);
    assert.equal(matchWaiver([cert], { kind: 'cert', domain: 'example.com', refs: [null, CERT] }, { now: NOW }), null);
    const byCert = valid({ kind: 'cert', ref: CERT }).waiver;
    assert.equal(matchWaiver([byCert], { kind: 'cert', domain: 'example.com', refs: [SPKI, CERT] }, { now: NOW }).waiver, byCert);
  });

  test('applyWaivers: kept, waived and expired (kept: they count again), in item order', () => {
    const items = [
      { domain: 'example.com', ref: 'dmarc.policy-none', n: 1 },
      { domain: 'example.com', ref: 'spf.ptr', n: 2 },
      { domain: 'example.org', ref: 'spf.ptr', n: 3 },
      { domain: 'example.org', ref: 'caa.missing', n: 4 }
    ];
    const r = applyWaivers(items, [active, old, later], { now: NOW, kind: 'finding' });
    assert.deepEqual(r.kept.map((x) => x.n), [2, 4]);
    assert.deepEqual(r.waived.map((x) => [x.item.n, x.waiver.id]), [[1, active.id], [3, later.id]]);
    assert.deepEqual(r.expired.map((x) => [x.item.n, x.waiver.id]), [[2, old.id]]);
    assert.deepEqual(applyWaivers(items, [], { now: NOW }), { kept: items, waived: [], expired: [] });
    // a month on, everything has expired
    const later2 = applyWaivers(items, [active, old, later], { now: NOW + 120 * DAY, kind: 'finding' });
    assert.deepEqual([later2.kept.length, later2.waived.length, later2.expired.length], [4, 0, 3]);
  });
});

describe('a Domain Health report\'s waivers', () => {
  const report = {
    domain: 'example.com',
    checks: [
      { id: 'dmarc.policy-none', severity: 'warn' },
      { id: 'spf.ptr', severity: 'warn' },
      { id: 'caa.missing', severity: 'info' },
      { id: 'mx.unresolvable', severity: 'error' },
      { id: 'domain.nxdomain', severity: 'error' }
    ]
  };

  test('only errors and warnings, never a name that does not exist; the first day one ends', () => {
    const list = [
      valid({ expires: '2026-12-31' }).waiver,
      valid({ ref: 'mx.unresolvable', expires: '2026-11-15' }).waiver,
      valid({ ref: 'caa.missing' }).waiver,
      valid({ ref: 'domain.nxdomain' }).waiver,
      valid({ ref: 'spf.ptr', expires: '2026-10-01' }).waiver
    ];
    const hw = healthWaivers(report, list, { now: NOW });
    assert.deepEqual([...hw.ids], ['dmarc.policy-none', 'mx.unresolvable']);
    assert.equal(hw.until, '2026-11-15');
    assert.deepEqual(hw.expired.map((e) => e.check.id), ['spf.ptr']);
    assert.equal(hw.byId.get('mx.unresolvable').expires, '2026-11-15');
    assert.equal(healthWaivers({ domain: 'example.org', checks: report.checks }, list, { now: NOW }).ids.size, 0, 'another domain');
    assert.deepEqual([...healthWaivers(report, [], { now: NOW }).ids], []);
    assert.equal(healthWaivers(null, list).until, null);
  });

  test('which checks can be accepted', () => {
    assert.equal(isWaivableCheck({ id: 'spf.ptr', severity: 'warn' }), true);
    assert.equal(isWaivableCheck({ id: 'mx.unresolvable', severity: 'error' }), true);
    assert.equal(isWaivableCheck({ id: 'caa.missing', severity: 'info' }), false);
    assert.equal(isWaivableCheck({ id: 'domain.name-missing', severity: 'error' }), false);
    assert.equal(isWaivableCheck(null), false);
  });
});

test('every text in English and Turkish, the same placeholders', () => {
  const keys = Object.keys(WAIVERS_I18N.en);
  assert.deepEqual(Object.keys(WAIVERS_I18N.tr), keys);
  const ph = (v) => [...new Set([...String(typeof v === 'string' ? v : v.other).matchAll(/\{(\w+)\}/g)].map((m) => m[1]))].sort().join(',');
  for (const k of keys) assert.equal(ph(WAIVERS_I18N.tr[k]), ph(WAIVERS_I18N.en[k]), k);
  for (const c of WAIVER_ERRORS) assert.ok(keys.includes(`wvr.err.${c}`), c);
  // the hero's line: a sentence each, the score with one accepted risk or several
  assert.equal(WAIVERS_I18N.en['wvr.count'].one, '{count} accepted risk (until {date}).');
  assert.deepEqual(WAIVERS_I18N.en['wvr.withThem'], { one: 'With it, the score would be {score}/100 ({grade}).', other: 'With them, the score would be {score}/100 ({grade}).' });
  assert.deepEqual(WAIVERS_I18N.tr['wvr.withThem'], { one: 'O da sayılsaydı puan {score}/100 ({grade}) olurdu.', other: 'Onlar da sayılsaydı puan {score}/100 ({grade}) olurdu.' });
  // a policy rule has no score: its dialog says what accepting it does
  assert.match(WAIVERS_I18N.en['wvr.dialog.introRule'], /“Accepted”: neither a pass nor a fail/);
  assert.ok(!/score/.test(WAIVERS_I18N.en['wvr.dialog.introRule']) && !/puan/.test(WAIVERS_I18N.tr['wvr.dialog.introRule']));
  assert.equal(WAIVERS_I18N.en['wvr.knownExpiredLine'], 'Accepted as known until {date}, expired: flagged again');
});
