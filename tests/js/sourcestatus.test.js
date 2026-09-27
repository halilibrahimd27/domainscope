/**
 * lib/sourcestatus.js: a failed data source becomes a status ("rate limited — try again in
 * 5 min") and marks only the empty fields it explains (IP Intel, Domain Health's RDAP card,
 * DNS Lookup's failed queries).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  sourceStatus, ipFieldStatus, ipRetrySources, ipSourceChips, sourceGroupOf, rdapStatus, dohStatus,
  STATUS_SOURCES, STATUS_REASONS, IP_FIELDS, IP_FIELD_SOURCES, IP_SOURCE_GROUPS
} from '../../assets/js/lib/sourcestatus.js';

const NOW = Date.UTC(2026, 8, 27, 12, 0, 0);
const MIN = 60 * 1000;

/** An IpInfo as lib/ipintel.js returns it, with the given fields and failures. */
function info(fields = {}, errors = []) {
  return {
    ip: '203.0.113.7', version: 4, private: false, provider: null, ptr: [], asn: null, asName: null, holder: null,
    prefix: null, country: null, city: null, sources: [], error: null, errorKind: null, asns: [], announced: null, rir: null,
    ...fields,
    errors: errors.map((e) => ({ error: 'HTTP 429', errorKind: 'rate-limit', status: 429, retryAfterMs: null, at: NOW, ...e }))
  };
}

describe('sourceStatus', () => {
  test('a rate limit with a Retry-After: minutes left, counted from the failure, rounded up', () => {
    const s = sourceStatus({ source: 'ripestat', error: 'HTTP 429', errorKind: 'rate-limit', status: 429, retryAfterMs: 5 * MIN, at: NOW - MIN }, { now: NOW });
    assert.equal(s.kind, 'rate-limit');
    assert.equal(s.reason, 'rate-limit-wait');
    assert.deepEqual(s.params, { minutes: 4 });
    assert.equal(s.retryAt.getTime(), NOW + 4 * MIN);
    assert.equal(s.detail, 'HTTP 429');
    const soon = sourceStatus({ source: 'rdap', status: 429, retryAfterMs: 20 * 1000, at: new Date(NOW) }, { now: NOW });
    assert.deepEqual([soon.reason, soon.params], ['rate-limit-wait', { minutes: 1 }], 'never "in 0 min"');
  });

  test('a Retry-After that has run out: try again now', () => {
    const s = sourceStatus({ source: 'ripestat', status: 429, retryAfterMs: MIN, at: NOW - 2 * MIN }, { now: NOW });
    assert.equal(s.reason, 'rate-limit-now');
    assert.deepEqual(s.params, {});
  });

  test('without a Retry-After the service\'s usual quota window words it', () => {
    const at = (source, extra = {}) => sourceStatus({ source, errorKind: 'rate-limit', ...extra }, { now: NOW }).reason;
    assert.equal(at('ripestat'), 'rate-limit-minutes');
    assert.equal(at('ripestat-geo'), 'rate-limit-minutes');
    assert.equal(at('rdap'), 'rate-limit-minutes');
    assert.equal(at('doh'), 'rate-limit-minutes');
    assert.equal(at('hackertarget'), 'rate-limit-day');
    assert.equal(at('ipwhois'), 'rate-limit', 'an unknown window: "later"');
    assert.equal(at('something-else'), 'rate-limit');
    assert.equal(sourceStatus({ source: 'hackertarget', limited: true, errorKind: 'http' }).reason, 'rate-limit-day', 'the quota text of a 200 answer');
    assert.equal(sourceStatus({ source: 'ripestat', error: 'HTTP 429 Too Many Requests', errorKind: 'http' }).kind, 'rate-limit', 'a 429 in the message');
  });

  test('other failures: timeout, network, unavailable, HTTP status, parse, unknown', () => {
    const r = (f) => { const s = sourceStatus(f, { now: NOW }); return [s.kind, s.reason, s.params]; };
    assert.deepEqual(r({ source: 'ripestat', errorKind: 'timeout' }), ['timeout', 'timeout', {}]);
    assert.deepEqual(r({ source: 'rdap', errorKind: 'network', error: 'Network error (the RDAP server may not allow browser access): Failed to fetch' }), ['network', 'network', {}]);
    assert.deepEqual(r({ source: 'ripestat', errorKind: 'unavailable' }), ['unavailable', 'unavailable', {}]);
    assert.deepEqual(r({ source: 'rdap', errorKind: 'http', status: 503 }), ['http', 'http-status', { status: 503 }]);
    assert.deepEqual(r({ source: 'doh', errorKind: 'http', error: 'HTTP 502 Bad Gateway' }), ['http', 'http-status', { status: 502 }], 'status read from the message');
    assert.deepEqual(r({ source: 'rdap', errorKind: 'http' }), ['http', 'http', {}]);
    assert.deepEqual(r({ source: 'ipwhois', errorKind: 'parse' }), ['parse', 'parse', {}]);
    assert.deepEqual(r({ source: 'ptr', errorKind: 'unknown', error: 'dns down' }), ['unknown', 'unknown', {}]);
    assert.deepEqual(r({ source: 'ptr', errorKind: 'abort' }), ['unknown', 'unknown', {}]);
    assert.deepEqual(r({ source: 'ptr', errorKind: 'invalid' }), ['unknown', 'unknown', {}]);
    assert.deepEqual(r(null), ['unknown', 'unknown', {}]);
    assert.equal(sourceStatus({ source: 'x', status: 99 }).reason, 'unknown', 'not an HTTP status');
  });

  test('every reason is listed, and every source has a policy', () => {
    const seen = new Set();
    for (const source of Object.keys(STATUS_SOURCES)) {
      for (const f of [
        { errorKind: 'rate-limit' }, { errorKind: 'rate-limit', retryAfterMs: MIN, at: NOW }, { errorKind: 'rate-limit', retryAfterMs: 0, at: NOW - 1 },
        { errorKind: 'timeout' }, { errorKind: 'network' }, { errorKind: 'unavailable' }, { errorKind: 'http', status: 500 }, { errorKind: 'http' },
        { errorKind: 'parse' }, {}
      ]) seen.add(sourceStatus({ source, ...f }, { now: NOW }).reason);
    }
    seen.add(sourceStatus({ source: 'unknown-source', errorKind: 'rate-limit' }).reason);
    assert.deepEqual([...seen].sort(), [...STATUS_REASONS].sort());
    for (const p of Object.values(STATUS_SOURCES)) assert.ok(['day', 'minutes', null].includes(p.period));
  });
});

describe('ipFieldStatus / ipRetrySources', () => {
  test('a value, a real "none", a private address or a pending row is never n/a', () => {
    for (const field of IP_FIELDS) {
      assert.equal(ipFieldStatus(null, field), null);
      assert.equal(ipFieldStatus(info({ private: true }, [{ source: 'ripestat' }]), field), null, `${field}: private`);
      assert.equal(ipFieldStatus(info(), field), null, `${field}: nothing failed`);
    }
    const full = info({ ptr: ['a.example.com'], asn: 64500, holder: 'Example', prefix: '203.0.113.0/24', country: 'NL' },
      [{ source: 'ptr' }, { source: 'ripestat' }, { source: 'ripestat-geo' }, { source: 'ipwhois' }]);
    for (const field of IP_FIELDS) assert.equal(ipFieldStatus(full, field), null, `${field}: has a value`);
    assert.equal(ipFieldStatus(info({}, [{ source: 'ripestat' }]), 'nope'), null, 'unknown field');
  });

  test('an empty field names the failed sources that feed it, primary first', () => {
    const i = info({}, [{ source: 'ipwhois', errorKind: 'parse', status: null, error: 'ipwho.is: empty response' }, { source: 'ripestat', retryAfterMs: 2 * MIN }]);
    const net = ipFieldStatus(i, 'network', { now: NOW });
    assert.deepEqual(net.sources, ['ripestat', 'ipwhois']);
    assert.deepEqual(net.statuses.map((s) => s.reason), ['rate-limit-wait', 'parse']);
    assert.deepEqual(ipFieldStatus(i, 'prefix', { now: NOW }).sources, ['ripestat']);
    assert.deepEqual(ipFieldStatus(i, 'location', { now: NOW }).sources, ['ipwhois'], 'RIPEstat geo answered: only ipwho.is failed');
    assert.equal(ipFieldStatus(i, 'ptr'), null);
    const slow = info({}, [{ source: 'ptr', errorKind: 'timeout', status: null, error: 'Request timed out after 8000 ms' }]);
    assert.equal(ipFieldStatus(slow, 'ptr').statuses[0].reason, 'timeout');
  });

  test('a failure another source made up for is not shown, and not retried', () => {
    // RIPEstat's geo dataset failed, but ipwho.is found the country; the prefix only RIPEstat knows.
    const i = info({ asn: 64500, holder: 'Example', country: 'NL', sources: ['dns', 'ipwhois'] }, [{ source: 'ripestat' }, { source: 'ripestat-geo' }]);
    assert.equal(ipFieldStatus(i, 'location'), null);
    assert.equal(ipFieldStatus(i, 'network'), null);
    assert.deepEqual(ipFieldStatus(i, 'prefix').sources, ['ripestat']);
    assert.deepEqual(ipRetrySources(i), ['ripestat']);
  });

  test('ipRetrySources: every source that left a field empty, once, in field order', () => {
    const i = info({}, [{ source: 'ipwhois' }, { source: 'ripestat-geo' }, { source: 'ripestat' }, { source: 'ptr' }]);
    assert.deepEqual(ipRetrySources(i), ['ptr', 'ripestat', 'ipwhois', 'ripestat-geo']);
    assert.deepEqual(ipRetrySources(info()), []);
    assert.deepEqual(ipRetrySources(null), []);
    for (const list of Object.values(IP_FIELD_SOURCES)) for (const s of list) assert.ok(sourceGroupOf(s), s);
  });
});

describe('ipSourceChips', () => {
  const ok = (ip, extra = {}) => ({ ip, pending: false, info: info({ ip, ptr: ['x.example.com'], asn: 64500, holder: 'Example', prefix: '203.0.113.0/24', country: 'NL', sources: ['dns', 'ripestat'], ...extra }) });

  test('ok, idle (a fallback nobody needed) and pending', () => {
    const chips = ipSourceChips([ok('203.0.113.1'), ok('203.0.113.2')]);
    assert.deepEqual(chips.map((c) => [c.id, c.state, c.rows, c.failed]), [['ripestat', 'ok', 2, 0], ['ipwhois', 'idle', 0, 0], ['ptr', 'ok', 2, 0]]);
    assert.deepEqual(Object.keys(IP_SOURCE_GROUPS), chips.map((c) => c.id));
    const pending = ipSourceChips([ok('203.0.113.1'), { ip: '203.0.113.2', pending: true, info: null }]);
    assert.deepEqual(pending.map((c) => [c.state, c.rows]), [['pending', 1], ['pending', 0], ['pending', 1]], 'nothing is settled while rows are still looked up');
    assert.deepEqual(ipSourceChips([]).map((c) => c.state), ['idle', 'idle', 'idle']);
    const priv = ipSourceChips([{ ip: '10.0.0.1', pending: false, info: { ...info(), ip: '10.0.0.1', private: true } }]);
    assert.deepEqual(priv.map((c) => c.state), ['idle', 'idle', 'idle'], 'private addresses are never looked up');
  });

  test('failed: which rows, which sources a chip Retry asks, and the latest reason', () => {
    const rows = [
      ok('203.0.113.1'),
      { ip: '203.0.113.2', pending: false, info: info({ ip: '203.0.113.2', ptr: ['y.example.com'], sources: ['dns'] }, [{ source: 'ripestat', at: NOW - 5 * MIN }, { source: 'ripestat-geo', at: NOW - 5 * MIN }, { source: 'ipwhois', errorKind: 'network', status: null, error: 'Failed to fetch' }]) },
      { ip: '203.0.113.3', pending: false, info: info({ ip: '203.0.113.3', ptr: ['z.example.com'], country: 'NL', sources: ['dns', 'ripestat'] }, [{ source: 'ripestat', retryAfterMs: 3 * MIN, at: NOW }]) }
    ];
    const [ripe, whois, ptr] = ipSourceChips(rows, { now: NOW });
    assert.deepEqual([ripe.state, ripe.rows, ripe.failed, ripe.ips], ['failed', 3, 2, ['203.0.113.2', '203.0.113.3']]);
    assert.deepEqual(ripe.sources, ['ripestat', 'ripestat-geo']);
    assert.deepEqual([ripe.status.reason, ripe.status.params], ['rate-limit-wait', { minutes: 3 }], 'the most recent failure');
    assert.deepEqual([whois.state, whois.failed, whois.sources, whois.status.reason], ['failed', 1, ['ipwhois'], 'network']);
    assert.deepEqual([ptr.state, ptr.rows], ['ok', 3]);
  });
});

describe('rdapStatus / dohStatus', () => {
  test('RDAP: an answer, a TLD without RDAP and an unregistered domain are not failures', () => {
    assert.equal(rdapStatus(null), null);
    assert.equal(rdapStatus({ ok: true }), null);
    assert.equal(rdapStatus({ ok: false, unsupportedTld: true, errorKind: 'unsupported' }), null);
    assert.equal(rdapStatus({ ok: false, notFound: true, errorKind: 'http' }), null);
    assert.equal(rdapStatus({ ok: false, errorKind: 'invalid', error: 'Invalid domain name' }), null);
  });

  test('RDAP: a failed lookup with its HTTP status and Retry-After', () => {
    const s = rdapStatus({ ok: false, error: 'HTTP 429 Too Many Requests', errorKind: 'rate-limit', httpStatus: 429, retryAfterMs: 10 * MIN, failedAt: NOW, status: ['client transfer prohibited'] }, { now: NOW + MIN });
    assert.deepEqual([s.source, s.kind, s.reason, s.params], ['rdap', 'rate-limit', 'rate-limit-wait', { minutes: 9 }]);
    const n = rdapStatus({ ok: false, error: 'Network error (the RDAP server may not allow browser access): Failed to fetch', errorKind: 'network', httpStatus: null, status: [] });
    assert.deepEqual([n.kind, n.reason], ['network', 'network']);
    assert.equal(rdapStatus({ ok: false, errorKind: 'http', httpStatus: 500, status: [] }).reason, 'http-status');
  });

  test('DoH: only a transport failure is a status (an rcode is an answer)', () => {
    assert.equal(dohStatus(null), null);
    assert.equal(dohStatus({ ok: true, rcode: 'SERVFAIL' }), null);
    assert.equal(dohStatus({ ok: false, errorKind: 'abort' }), null);
    const s = dohStatus({ ok: false, error: 'HTTP 429', errorKind: 'rate-limit' }, { now: NOW });
    assert.deepEqual([s.source, s.reason], ['doh', 'rate-limit-minutes']);
    assert.equal(dohStatus({ ok: false, error: 'Request timed out after 8000 ms', errorKind: 'timeout' }).reason, 'timeout');
  });
});
