/**
 * lib/session.js — the page session: parsing the current target, the routes that carry it (filled
 * in, never run), the kept result of each tool (one per tool, memory-bounded) and when a route
 * brings it back; plus the shell's use of it (app.js navHref) and the note's time text
 * (ui/session-ui.js). No DOM, no network; example names and documentation addresses only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseTarget, commonTarget, targetFits, fillRoute, isFillOnly, routeKey, carryRoute, restorePlan, normalizeResult,
  keptNote, estimateSize, createSessionStore, TARGET_ROUTES, TARGET_KINDS, FILL_PARAM, FILL_VALUE, DEFAULT_LIMITS
} from '../../assets/js/lib/session.js';
import { VIEWS, buildRoute, parseRoute, navHref, pageSession } from '../../assets/js/app.js';
import { keptTimeText } from '../../assets/js/ui/session-ui.js';
import { setLang } from '../../assets/js/i18n.js';

/** A clock that moves one second per call. */
function clock(start = Date.UTC(2026, 8, 27, 12, 0, 0)) {
  let now = start;
  return () => {
    now += 1000;
    return new Date(now);
  };
}

describe('parseTarget', () => {
  test('domains, host names and IP addresses, normalised', () => {
    assert.deepEqual(parseTarget('example.com'), { value: 'example.com', kind: 'domain' });
    assert.deepEqual(parseTarget('  WWW.Example.COM. '), { value: 'www.example.com', kind: 'host' });
    assert.deepEqual(parseTarget('https://user@shop.example.co.uk:8443/cart?x=1'), { value: 'shop.example.co.uk', kind: 'host' });
    assert.deepEqual(parseTarget('example.co.uk'), { value: 'example.co.uk', kind: 'domain' });
    assert.deepEqual(parseTarget('*.example.net'), { value: 'example.net', kind: 'domain' });
    assert.deepEqual(parseTarget('192.0.2.10'), { value: '192.0.2.10', kind: 'ip' });
    assert.deepEqual(parseTarget('[2001:DB8::0:1]'), { value: '2001:db8::1', kind: 'ip' });
  });

  test('an IP address written with a port or as a URL gives the address', () => {
    assert.deepEqual(parseTarget('192.0.2.1:443'), { value: '192.0.2.1', kind: 'ip' });
    assert.deepEqual(parseTarget('[2001:db8::1]:443'), { value: '2001:db8::1', kind: 'ip' });
    assert.deepEqual(parseTarget('http://192.0.2.1/'), { value: '192.0.2.1', kind: 'ip' });
    assert.deepEqual(parseTarget('https://user@[2001:DB8::1]:8443/status?x=1'), { value: '2001:db8::1', kind: 'ip' });
    assert.deepEqual(parseTarget('2001:db8::1:443'), { value: '2001:db8::1:443', kind: 'ip' }, 'a bare IPv6 address stays whole');
    assert.equal(parseTarget('192.0.2.0/24'), null, 'an address range is no target');
    assert.equal(parseTarget('192.0.2.1:99999'), null);
    assert.deepEqual(parseTarget('example.com:8080'), { value: 'example.com', kind: 'domain' }, 'host names as before');
  });

  test('service labels name a record, not a host', () => {
    assert.deepEqual(parseTarget('_dmarc.example.com'), { value: 'example.com', kind: 'domain' });
    assert.deepEqual(parseTarget('s1._domainkey.example.org'), { value: 'example.org', kind: 'domain' });
    assert.deepEqual(parseTarget('_443._tcp.www.example.com'), { value: 'www.example.com', kind: 'host' });
    assert.equal(parseTarget('_dmarc.com'), null, 'nothing left but a public suffix');
  });

  test('no target: public suffixes, single labels, reverse names, junk', () => {
    for (const bad of ['com', 'co.uk', 'github.io', 'localhost', '10.2.0.192.in-addr.arpa', 'in-addr.arpa', '', '   ',
      'not a host', 'foo_bar.example.com', 'bad..example.com', 'x'.repeat(3000), null, undefined, 42, {}]) {
      assert.equal(parseTarget(bad), null, String(bad).slice(0, 40));
    }
  });
});

describe('commonTarget', () => {
  test('one entry, or the registrable domain every name shares', () => {
    assert.deepEqual(commonTarget(['www.example.com']), { value: 'www.example.com', kind: 'host' });
    assert.deepEqual(commonTarget(['www.example.com', 'api.example.com', 'example.com', 'www.example.com']), { value: 'example.com', kind: 'domain' });
    assert.deepEqual(commonTarget(['192.0.2.1', '192.0.2.1']), { value: '192.0.2.1', kind: 'ip' });
    assert.deepEqual(commonTarget(['bad!', 'mail.example.org']), { value: 'mail.example.org', kind: 'host' }, 'invalid entries are skipped');
  });

  test('several unrelated things: none', () => {
    assert.equal(commonTarget(['example.com', 'example.net']), null);
    assert.equal(commonTarget(['192.0.2.1', '198.51.100.1']), null);
    assert.equal(commonTarget(['www.example.com', '192.0.2.1']), null);
    assert.equal(commonTarget([]), null);
    assert.equal(commonTarget(null), null);
  });
});

describe('routes', () => {
  const domain = parseTarget('example.com');
  const host = parseTarget('www.example.com');
  const ip = parseTarget('192.0.2.10');

  test('every tool that takes a target is a real view, and every kind is known', () => {
    const ids = new Set(VIEWS.map((v) => v.id));
    for (const [view, spec] of Object.entries(TARGET_ROUTES)) {
      assert.ok(ids.has(view), view);
      assert.ok(spec.kinds.length && spec.kinds.every((k) => TARGET_KINDS.includes(k)), view);
    }
    for (const none of ['zone', 'inventory', 'about']) assert.equal(targetFits(none, domain), false, none);
  });

  test('fillRoute puts the target into the tool main input with run=0', () => {
    assert.deepEqual(fillRoute('lookup', ip), { name: '192.0.2.10', run: '0' });
    assert.deepEqual(fillRoute('health', host), { domain: 'www.example.com', run: '0' });
    assert.deepEqual(fillRoute('global', domain), { name: 'example.com', run: '0' });
    assert.deepEqual(fillRoute('ip', ip), { ips: '192.0.2.10', run: '0' });
    assert.deepEqual(fillRoute('bulk', host), { names: 'www.example.com', run: '0' });
    assert.deepEqual(fillRoute('cert', domain), { host: 'example.com', run: '0' });
    assert.deepEqual(fillRoute('subdomains', domain), { domain: 'example.com', run: '0' });
    assert.deepEqual(fillRoute('scan', domain), { domain: 'example.com', run: '0' });
  });

  test('a tool whose input does not take the kind gets nothing', () => {
    assert.equal(fillRoute('ip', domain), null);
    assert.equal(fillRoute('health', ip), null);
    assert.equal(fillRoute('global', ip), null);
    assert.equal(fillRoute('subdomains', ip), null);
    assert.equal(fillRoute('zone', domain), null);
    assert.equal(fillRoute('lookup', null), null);
    assert.equal(fillRoute('constructor', domain), null, 'no prototype lookups');
  });

  test('isFillOnly and routeKey', () => {
    assert.equal(isFillOnly({ name: 'x', run: '0' }), true);
    assert.equal(isFillOnly({ name: 'x', run: '1' }), false);
    assert.equal(isFillOnly({ name: 'x' }), false);
    assert.equal(isFillOnly(null), false);
    assert.equal(`${FILL_PARAM}=${FILL_VALUE}`, 'run=0');
    assert.equal(routeKey({}), '');
    assert.equal(routeKey({ run: '0' }), '', 'the fill marker is not part of the key');
    assert.equal(routeKey({ type: 'A', name: 'example.com' }), routeKey({ name: 'example.com', run: '0', type: 'A' }), 'order-independent');
    assert.notEqual(routeKey({ name: 'example.com' }), routeKey({ name: 'example.net' }));
    assert.equal(routeKey({ name: 'example.com', resolver: null }), 'name=example.com', 'empty values are dropped');
  });

  test('carryRoute: back to a kept result (with run=0), else the target filled in, else bare', () => {
    const kept = { params: { domain: 'example.com', selectors: 's1' } };
    assert.deepEqual(carryRoute('health', { kept, target: host }), { domain: 'example.com', selectors: 's1', run: '0' }, 'kept wins');
    assert.deepEqual(carryRoute('subdomains', { kept: { params: {} }, target: domain }), {}, 'a tool keeping its own state opens bare');
    assert.deepEqual(carryRoute('health', { kept: null, target: host }), { domain: 'www.example.com', run: '0' });
    assert.deepEqual(carryRoute('ip', { target: domain }), {});
    assert.deepEqual(carryRoute('about', { target: domain }), {});
    assert.deepEqual(carryRoute('lookup'), {});
    // The routes are real routes: they round-trip through the router.
    const r = parseRoute(buildRoute('lookup', carryRoute('lookup', { target: ip })));
    assert.deepEqual([r.view, r.params], ['lookup', { name: '192.0.2.10', run: '0' }]);
  });

  test('restorePlan: a bare route or the result own params bring it back; others are a new query', () => {
    const kept = { params: { name: 'example.com', type: 'A' }, snapshot: { q: 1 }, dropped: false };
    assert.equal(restorePlan({}, kept), 'restore');
    assert.equal(restorePlan({ run: '0' }, kept), 'restore');
    assert.equal(restorePlan({ type: 'A', name: 'example.com', run: '0' }, kept), 'restore');
    assert.equal(restorePlan({ type: 'A', name: 'example.com' }, kept), 'restore', 'back button to the same URL');
    assert.equal(restorePlan({ name: 'example.net' }, kept), null);
    assert.equal(restorePlan({ name: 'example.com', type: 'MX' }, kept), null);
    assert.equal(restorePlan({}, { ...kept, snapshot: null, dropped: true }), 'dropped');
    assert.equal(restorePlan({}, { params: {}, snapshot: null, dropped: false }), null, 'a tool keeping its own state');
    assert.equal(restorePlan({}, null), null);
  });
});

describe('results and the note', () => {
  test('normalizeResult accepts { subject, at } with a valid date', () => {
    const at = new Date(Date.UTC(2026, 8, 27, 10, 0));
    assert.deepEqual(normalizeResult({ subject: 'example.com', at }), { subject: 'example.com', at });
    assert.deepEqual(normalizeResult({ subject: '', at: at.getTime() }), { subject: null, at });
    assert.deepEqual(normalizeResult({ at: at.toISOString() }), { subject: null, at });
    assert.equal(normalizeResult({ subject: 'x', at: null }), null);
    assert.equal(normalizeResult({ subject: 'x', at: 'soon' }), null);
    assert.equal(normalizeResult(null), null);
    assert.equal(normalizeResult('example.com'), null);
  });

  test('keptNote: a language re-mount keeps its note; an older result gets one; a fresh one none', () => {
    const mountedAt = Date.UTC(2026, 8, 27, 12, 0);
    const older = { at: new Date(mountedAt - 60000) };
    const fresh = { at: new Date(mountedAt + 5) };
    const shown = { at: older.at, dropped: false };
    assert.equal(keptNote({ note: shown, result: fresh, mountedAt }), shown, 'language re-mount: as it was');
    assert.equal(keptNote({ note: null, result: older, mountedAt }), null, 'language re-mount without a note');
    assert.deepEqual(keptNote({ result: older, mountedAt }), { at: older.at, dropped: false });
    assert.equal(keptNote({ result: fresh, mountedAt }), null);
    assert.equal(keptNote({ result: null, mountedAt }), null);
    assert.deepEqual(keptNote({ plan: 'dropped', kept: { at: older.at }, result: null, mountedAt }), { at: older.at, dropped: true });
  });
});

describe('estimateSize', () => {
  test('strings, numbers, arrays, objects, maps, sets, buffers, dates', () => {
    assert.equal(estimateSize('abcd'), 8);
    assert.equal(estimateSize(1), 8);
    assert.equal(estimateSize(null), 0);
    assert.equal(estimateSize(undefined), 0);
    assert.equal(estimateSize(() => 1), 0);
    assert.equal(estimateSize(new Uint8Array(1000)), 1000);
    assert.equal(estimateSize(new Date()), 8);
    assert.ok(estimateSize(['abc', 1]) >= 6 + 8);
    assert.ok(estimateSize({ name: 'example.com' }) >= 22 + 8);
    assert.ok(estimateSize(new Map([['a', 'bb']])) >= 6);
    assert.ok(estimateSize(new Set(['abc'])) >= 6);
  });

  test('cycles and shared objects count once', () => {
    const a = { s: 'x'.repeat(100) };
    a.self = a;
    const once = estimateSize(a);
    assert.ok(once > 200 && once < 400, String(once));
    assert.ok(estimateSize([a, a, a]) < once + 100, 'a shared object is counted once');
  });

  test('stops soon after the limit, so a huge result costs no more than the limit', () => {
    const wide = Array.from({ length: 50 }, () => ({ text: 'x'.repeat(10000) }));
    const n = estimateSize(wide, 10000);
    assert.ok(n > 10000 && n < 50000, `stopped after the first large string (${n})`);
    assert.ok(estimateSize(wide) > 1000000, 'the full walk sees all of it');
    const long = Array.from({ length: 200000 }, (_, i) => ({ name: `host${i}.example.com`, ips: ['192.0.2.1'] }));
    const t0 = performance.now();
    assert.ok(estimateSize(long, 10000) > 10000, 'over the limit');
    assert.ok(performance.now() - t0 < 100, 'without walking the rows');
    assert.ok(estimateSize(long) > 10 * 1024 * 1024);
  });
});

describe('createSessionStore', () => {
  test('target: set, normalised, only real targets, cleared', () => {
    const s = createSessionStore({ now: clock() });
    const seen = [];
    s.subscribe((c) => seen.push(c.type));
    assert.equal(s.target, null);
    assert.equal(s.setTarget('not a host'), null);
    assert.equal(s.target, null, 'nothing changes');
    const t = s.setTarget('https://www.example.com/', { view: 'health' });
    assert.deepEqual([t.value, t.kind, t.view], ['www.example.com', 'host', 'health']);
    assert.ok(t.at instanceof Date);
    s.setTarget('www.example.com', { view: 'lookup' });
    assert.equal(s.target.view, 'lookup');
    assert.deepEqual(seen, ['target'], 'the same value again notifies nobody');
    s.target.value = 'tampered';
    assert.equal(s.target.value, 'www.example.com', 'a copy');
    assert.equal(s.clearTarget(), true);
    assert.equal(s.clearTarget(), false);
    assert.equal(s.target, null);
    assert.deepEqual(seen, ['target', 'target']);
  });

  test('keep: one result per tool, a copy out, the snapshot shared', () => {
    const s = createSessionStore({ now: clock() });
    const snap = { report: { domain: 'example.com' } };
    const at = new Date(Date.UTC(2026, 8, 27, 9, 30));
    const e = s.keep('health', { params: { domain: 'example.com', run: '0' }, subject: 'example.com', at, snapshot: snap });
    assert.deepEqual(e.params, { domain: 'example.com' }, 'no fill marker');
    assert.equal(e.at.getTime(), at.getTime());
    assert.equal(e.dropped, false);
    assert.ok(e.size > 0);
    const k = s.kept('health');
    assert.equal(k.snapshot, snap, 'the snapshot itself is handed back');
    k.params.domain = 'tampered';
    assert.equal(s.kept('health').params.domain, 'example.com');
    s.keep('health', { params: { domain: 'example.org' }, subject: 'example.org', at, snapshot: { report: { domain: 'example.org' } } });
    assert.equal(s.kept('health').subject, 'example.org', 'replaced');
    assert.equal(s.usage().entries, 1);
    assert.equal(s.kept('lookup'), null);
  });

  test('keep: a tool that keeps its own state keeps only the fact', () => {
    const s = createSessionStore({ now: clock() });
    const e = s.keep('subdomains', { subject: 'example.com', at: Date.UTC(2026, 8, 27) });
    assert.deepEqual([e.snapshot, e.size, e.dropped, e.params], [null, 0, false, {}]);
    assert.equal(restorePlan({}, s.kept('subdomains')), null);
    assert.deepEqual(carryRoute('subdomains', { kept: s.kept('subdomains'), target: parseTarget('example.net') }), {});
  });

  test('keep: an invalid time becomes now', () => {
    const now = clock();
    const s = createSessionStore({ now });
    assert.ok(Number.isFinite(s.keep('ip', { at: 'garbage', snapshot: { rows: [] } }).at.getTime()));
  });

  test('memory: a snapshot over the entry bound is dropped, its query kept', () => {
    const s = createSessionStore({ now: clock(), entryBytes: 1000, totalBytes: 5000 });
    const e = s.keep('ip', { params: { ips: '192.0.2.1' }, subject: '192.0.2.1', at: new Date(), snapshot: { rows: ['x'.repeat(2000)] } });
    assert.deepEqual([e.snapshot, e.dropped, e.size], [null, true, 0]);
    assert.equal(restorePlan({}, s.kept('ip')), 'dropped');
    assert.deepEqual(carryRoute('ip', { kept: s.kept('ip') }), { ips: '192.0.2.1', run: '0' }, 'the query comes back filled in');
  });

  test('memory: over the total bound the oldest other snapshots go first', () => {
    const s = createSessionStore({ now: clock(), entryBytes: 3000, totalBytes: 5000 });
    const big = () => ({ text: 'x'.repeat(1200) });
    s.keep('lookup', { params: { name: 'a.example.com' }, at: new Date(), snapshot: big() });
    s.keep('global', { params: { name: 'b.example.com' }, at: new Date(), snapshot: big() });
    assert.equal(s.usage().entries, 2);
    s.keep('health', { params: { domain: 'example.com' }, at: new Date(), snapshot: big() });
    assert.equal(s.kept('lookup').dropped, true, 'the oldest went');
    assert.equal(s.kept('global').dropped, false);
    assert.equal(s.kept('health').dropped, false);
    assert.ok(s.usage().bytes <= 5000);
    // Keeping a tool again makes it the newest.
    s.keep('global', { params: { name: 'b.example.com' }, at: new Date(), snapshot: big() });
    s.keep('ip', { params: { ips: '192.0.2.1' }, at: new Date(), snapshot: big() });
    assert.equal(s.kept('health').dropped, true);
    assert.equal(s.kept('global').dropped, false);
  });

  test('drop and clear ("Delete all local data") forget; subscribers hear it', () => {
    const s = createSessionStore({ now: clock() });
    const seen = [];
    s.subscribe((c) => seen.push(`${c.type}:${c.view || ''}`));
    s.setTarget('example.com');
    s.keep('health', { at: new Date(), snapshot: {} });
    s.keep('lookup', { at: new Date(), snapshot: {} });
    assert.equal(s.drop('health'), true);
    assert.equal(s.drop('health'), false);
    s.clear();
    assert.deepEqual([s.target, s.kept('lookup'), s.usage()], [null, null, { entries: 0, bytes: 0 }]);
    assert.deepEqual(seen, ['target:', 'kept:health', 'kept:lookup', 'kept:health', 'cleared:']);
  });

  test('unsubscribe', () => {
    const s = createSessionStore({ now: clock() });
    const seen = [];
    const off = s.subscribe((c) => seen.push(c.type));
    s.setTarget('example.com');
    off();
    s.setTarget('example.net');
    assert.deepEqual(seen, ['target']);
  });

  test('default bounds', () => {
    assert.ok(DEFAULT_LIMITS.entryBytes <= DEFAULT_LIMITS.totalBytes);
  });
});

describe('the shell: nav links carry the target (app.js)', () => {
  test('navHref: the target filled in with run=0, a kept result, else bare', () => {
    pageSession.clear();
    try {
      assert.equal(navHref('lookup'), '#/lookup');
      pageSession.setTarget('www.example.com', { view: 'health' });
      assert.equal(navHref('lookup'), '#/lookup?name=www.example.com&run=0');
      assert.equal(navHref('health'), '#/health?domain=www.example.com&run=0');
      assert.equal(navHref('ip'), '#/ip', 'IP Intel does not take a host name');
      assert.equal(navHref('zone'), '#/zone', 'nothing ever goes into the Zone File URL');
      pageSession.keep('health', { params: { domain: 'example.com' }, subject: 'example.com', at: new Date(), snapshot: { report: {} } });
      assert.equal(navHref('health'), '#/health?domain=example.com&run=0', 'back to the kept result');
      pageSession.setTarget('192.0.2.10');
      assert.equal(navHref('ip'), '#/ip?ips=192.0.2.10&run=0');
      assert.equal(navHref('lookup'), '#/lookup?name=192.0.2.10&run=0');
    } finally {
      pageSession.clear();
    }
    assert.equal(navHref('health'), '#/health', '"Delete all local data" forgets both');
  });
});

describe('the note time (ui/session-ui.js)', () => {
  test('the time alone on the same day, the date too otherwise', () => {
    setLang('en');
    const at = new Date(2026, 8, 27, 14, 2);
    const same = keptTimeText(at, new Date(2026, 8, 27, 18, 0));
    assert.match(same, /2:02|14:02/);
    assert.doesNotMatch(same, /2026/);
    assert.match(keptTimeText(at, new Date(2026, 8, 28, 9, 0)), /2026/);
    assert.equal(keptTimeText('nope'), '—');
    setLang('tr');
    assert.match(keptTimeText(at, new Date(2026, 8, 27, 18, 0)), /14:02/);
    setLang('en');
  });
});
