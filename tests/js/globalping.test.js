/**
 * lib/globalping.js — the Globalping v1 transport. No network: every response is a recorded
 * fixture (tests/fixtures/globalping, real measurements from 2026-09-24) replayed through a fake
 * fetch, with a fake clock and a fake sleep (the sleep advances the clock).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  GLOBALPING_API, GP_LIMITS, NON_HTTP_TLS_PORTS, GP_ERROR_CODES, GlobalpingError,
  isMeasurementId, isProbeableIP, probeTarget, isProbeableHost, isProbeablePort, httpsCheckRequest, httpsGetRequest, httpGetRequest,
  httpsGetAtRequest, isProbeableDnsName, isProbeableResolver, dnsQueryRequest, GP_DNS_TYPES,
  probeSummary, quotaFromHeaders, quotaFromLimits, mergeQuota, createGlobalping
} from '../../assets/js/lib/globalping.js';
import { errorKind, throwIfAborted } from '../../assets/js/lib/util.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'globalping');
const fx = (name) => JSON.parse(readFileSync(join(FIX, `${name}.json`), 'utf8'));

const T0 = Date.parse('2026-09-24T07:00:00.000Z');
const S = 1000;

/* ---- harness --------------------------------------------------------------------------- */

/** Fake clock + fake sleep: every sleep is recorded and advances the clock by its duration. */
function env() {
  const clock = { t: T0 };
  const sleeps = [];
  const sleepImpl = async (ms, signal) => {
    sleeps.push(ms);
    clock.t += ms;
    throwIfAborted(signal);
  };
  return { clock, sleeps, sleepImpl, now: () => clock.t };
}

function respond({ status = 200, headers = {}, body = null, raw }) {
  return new Response(raw !== undefined ? raw : body === null ? '' : JSON.stringify(body), { status, headers });
}

/** Scripted fetch: each step is a response spec, an Error to throw, or a function (url, init) → Response. */
function fakeFetch(script, clock) {
  const calls = [];
  const queue = [...script];
  const impl = async (url, init = {}) => {
    calls.push({ url: String(url), init, at: clock ? clock.t : 0 });
    if (!queue.length) throw new Error(`unexpected request #${calls.length}: ${init.method} ${url}`);
    const step = queue.shift();
    if (typeof step === 'function') return step(url, init);
    if (step instanceof Error) throw step;
    return respond(step);
  };
  return { impl, calls, queue };
}

function client(script, opts = {}) {
  const e = env();
  const f = fakeFetch(script, e.clock);
  const gp = createGlobalping({ fetchImpl: f.impl, sleepImpl: e.sleepImpl, now: e.now, ...opts });
  return { gp, ...e, calls: f.calls, queue: f.queue };
}

const postOf = (name) => fx(name).post;
const finalOf = (name) => ({ status: 200, body: fx(name).final.body });
const inProgressOf = (name) => ({ status: 200, body: fx(name).inProgress });
const responseOf = (name) => fx(name).response;
const ID = '2xRWY3nxugT4lMyRW00021C1N'; // m12

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof GlobalpingError, `expected GlobalpingError, got ${err?.name}: ${err?.message}`);
    assert.equal(err.code, code);
    return true;
  });
}

/* ---- constants ------------------------------------------------------------------------- */

test('constants: API base, limits and vocabularies are frozen', () => {
  assert.equal(GLOBALPING_API, 'https://api.globalping.io/v1');
  assert.ok(Object.isFrozen(GP_LIMITS) && Object.isFrozen(NON_HTTP_TLS_PORTS) && Object.isFrozen(GP_ERROR_CODES));
  assert.equal(GP_LIMITS.anonymousPerHour, 250);
  assert.equal(GP_LIMITS.pollIntervalMs, 500);
  assert.deepEqual([GP_LIMITS.minTimeoutS, GP_LIMITS.maxTimeoutS, GP_LIMITS.clientSlackS], [5, 30, 10]);
  assert.ok(GP_ERROR_CODES.includes('private-target') && GP_ERROR_CODES.includes('poll-rate'));
});

test('GlobalpingError: fields and util.errorKind compatibility', () => {
  const quota = { limit: 250, remaining: 0 };
  const e = new GlobalpingError('rate-limit', 'used up', { status: 429, quota, retryAfterMs: 5, resetAt: new Date(T0), body: 'x'.repeat(900) });
  assert.equal(e.name, 'GlobalpingError');
  assert.ok(e instanceof Error);
  assert.equal(e.status, 429);
  assert.equal(e.quota, quota);
  assert.equal(e.body.length, 500);
  assert.equal(errorKind(e), 'rate-limit');
  assert.equal(errorKind(new GlobalpingError('insufficient-credits', '')), 'rate-limit');
  assert.equal(errorKind(new GlobalpingError('deadline', '')), 'timeout');
  assert.equal(errorKind(new GlobalpingError('bad-response', '')), 'parse');
  for (const code of ['validation', 'private-target', 'bad-host', 'no-probes', 'unauthorized', 'not-found', 'poll-rate', 'server']) {
    assert.equal(errorKind(new GlobalpingError(code, '')), 'http', code);
  }
  const bare = new GlobalpingError('server', 'x');
  assert.deepEqual([bare.status, bare.params, bare.quota, bare.retryAfterMs, bare.resetAt, bare.body], [null, null, null, null, null, '']);
});

test('isMeasurementId: only plain alphanumeric ids of 8–64 characters', () => {
  assert.ok(isMeasurementId(ID));
  assert.ok(isMeasurementId(fx('m01-github-valid').post.body.id));
  for (const bad of ['../x', 'abc', '', 'a'.repeat(65), '2xRWY3nxug/T4lMyRW', '2xRWY3nxug%2F', 'a b c d e f', null, 42]) {
    assert.equal(isMeasurementId(bad), false, String(bad));
  }
});

/* ---- target prefilters ----------------------------------------------------------------- */

test('isProbeableIP / probeTarget: public addresses; IPv4-mapped is sent as IPv4, IPv6 as RFC 5952', () => {
  for (const ip of ['140.82.121.4', '1.1.1.1', '2606:4700::6810:7c60', '::ffff:140.82.121.4', '2a01:4f8::1']) {
    assert.equal(isProbeableIP(ip), true, ip);
  }
  assert.equal(probeTarget('::ffff:140.82.121.4'), '140.82.121.4');
  assert.equal(probeTarget('140.82.121.4'), '140.82.121.4');
  assert.equal(probeTarget('2606:4700:0:0:0:0:6810:7C60'), '2606:4700::6810:7c60');
  assert.equal(probeTarget('[2606:4700::6810:7c60]'), '2606:4700::6810:7c60');
});

test('isProbeableIP / probeTarget: the whole refused list (F:C2 + review) is filtered before any request', () => {
  for (const ip of ['10.0.0.1', '172.16.5.4', '192.168.1.1', '127.0.0.1', '100.64.0.1', '169.254.1.1', '192.0.0.8',
    '192.0.2.1', '198.51.100.7', '203.0.113.5', '198.18.0.1', '224.0.0.1', '240.0.0.1', '255.255.255.255', '0.0.0.0',
    '::', '::1', 'fd00::1', 'fe80::1', 'ff02::1', '100::1', '2001:db8::1', '::ffff:10.0.0.1',
    '3fff::1', '2001:2::1', '64:ff9b::808:808', 'fec0::1', 'x', '', null]) {
    assert.equal(isProbeableIP(ip), false, String(ip));
    assert.equal(probeTarget(ip), null, String(ip));
  }
});

test('prefilter vs the live API: every refused target and host of validation-cases.json is refused locally', () => {
  const { cases, accepted } = fx('validation-cases');
  assert.ok(cases.length >= 30, `${cases.length} cases`);
  let targets = 0;
  let hosts = 0;
  for (const c of cases) {
    const params = c.body?.error?.params || {};
    const host = c.request.measurementOptions?.request?.host;
    if (typeof params.target === 'string') {
      targets += 1;
      assert.equal(isProbeableIP(c.request.target), false, `${c.name}: ${c.request.target} must be refused locally`);
      assert.throws(() => httpsCheckRequest({ ip: c.request.target, name: 'www.example.com' }), TypeError, c.name);
    }
    if (Object.keys(params).some((k) => k.includes('request.host'))) {
      hosts += 1;
      assert.equal(isProbeableHost(host), false, `${c.name}: ${host} must be refused locally`);
      assert.throws(() => httpsCheckRequest({ ip: '140.82.121.4', name: host }), TypeError, c.name);
    }
  }
  assert.ok(targets >= 20 && hosts >= 4, `targets ${targets}, hosts ${hosts}`);
  // accepted AND charged by the API although no probe can reach it: the client must refuse it itself
  for (const a of accepted) assert.equal(isProbeableIP(a.target), false, a.target);
  const m25 = fx('m25-v6-doc-enetunreach').final.body.results[0].result;
  assert.match(m25.rawOutput, /ENETUNREACH/, 'the real ENETUNREACH text verify.parseFailure maps to "unreachable"');
});

test('isProbeableHost: normalised LDH names with two or more labels only', () => {
  for (const ok of ['www.example.com', 'xn--mnchen-3ya.example-test.com.tr', 'a.b', 'github.com', 'one.one.one.one',
    `${'a'.repeat(63)}.example.com`]) {
    assert.equal(isProbeableHost(ok), true, ok);
  }
  for (const bad of ['_dmarc.example.com', '*.example.com', 'example.com:443', 'example.com.', '140.82.121.4', 'localhost',
    'a..example.com', '-a.example.com', 'a-.example.com', `${'a'.repeat(64)}.example.com`, 'Example.com', 'münchen.example.com',
    'example.123', 'https://example.com', 'example.com/x', ' example.com', `${'a.'.repeat(127)}com`, '', null, 42, '2606:4700::1']) {
    assert.equal(isProbeableHost(bad), false, String(bad));
  }
});

test('isProbeablePort: integers 1–65535 that are not non-HTTP TLS ports (port 0 is charged by the API)', () => {
  for (const p of [443, 8443, 1, 65535, 80, 4443]) assert.equal(isProbeablePort(p), true, String(p));
  for (const p of [0, -1, 70000, 65536, 1.5, '443', null, undefined, NaN, 993, 5432, 25, 3389]) {
    assert.equal(isProbeablePort(p), false, String(p));
  }
  for (const p of NON_HTTP_TLS_PORTS) assert.equal(isProbeablePort(p), false, String(p));
});

/* ---- request builder ------------------------------------------------------------------- */

test('httpsCheckRequest: the exact default body', () => {
  assert.deepEqual(httpsCheckRequest({ ip: '1.2.3.4', name: 'www.example.com' }), {
    type: 'http', target: '1.2.3.4', limit: 1, timeout: 10,
    measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'HEAD', host: 'www.example.com', path: '/' } }
  });
});

test('httpsCheckRequest: timeout is rounded and clamped to 5–30 and always sent; port always sent', () => {
  const t = (timeoutS) => httpsCheckRequest({ ip: '1.2.3.4', name: 'www.example.com', timeoutS }).timeout;
  assert.equal(t(3), 5);
  assert.equal(t(99), 30);
  assert.equal(t(7.6), 8);
  assert.equal(t(5), 5);
  for (const bad of [NaN, Infinity, '10', null]) {
    assert.throws(() => httpsCheckRequest({ ip: '1.2.3.4', name: 'www.example.com', timeoutS: bad }), TypeError, String(bad));
  }
  const b = httpsCheckRequest({ ip: '1.2.3.4', name: 'www.example.com', port: 8443, probes: 3 });
  assert.equal(b.measurementOptions.port, 8443);
  assert.equal(b.limit, 3);
});

test('httpsCheckRequest: ipVersion is never sent (a v6 target included) and refused as an option', () => {
  const v6 = httpsCheckRequest({ ip: '2606:4700::6810:7c60', name: 'www.cloudflare.com' });
  assert.equal(v6.target, '2606:4700::6810:7c60');
  assert.equal('ipVersion' in v6, false);
  assert.equal('ipVersion' in v6.measurementOptions, false);
  assert.throws(() => httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com', ipVersion: 4 }), TypeError);
  assert.throws(() => httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com', timeout: 5 }), /Unknown option: timeout/);
  // the live API refuses both (free 400), the builder can never produce them
  assert.equal(fx('v-ip-with-ipversion-400').post.status, 400);
});

test('httpsCheckRequest: locations — array entries get limit 1 and no global limit; an id passes through', () => {
  const arr = httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com', probes: 5, locations: [{ country: 'DE' }, { country: 'US', limit: 2 }] });
  assert.deepEqual(arr.locations, [{ country: 'DE', limit: 1 }, { country: 'US', limit: 2 }]);
  assert.equal('limit' in arr, false, 'a global limit plus locations[i].limit is a 400 (v-limit-and-location-limit-400)');
  const id = httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com', locations: ID });
  assert.equal(id.locations, ID);
  assert.equal('limit' in id, false);
  const src = [{ tags: ['eyeball-network'] }];
  httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com', locations: src });
  assert.deepEqual(src, [{ tags: ['eyeball-network'] }], 'the caller\'s array is not mutated');
  for (const bad of [[], '../x', 'abc', [{}], [{ limit: 2 }], [{ country: 'DE', limit: 0 }], [{ country: 'DE', limit: 51 }],
    [{ country: 'DE', limit: 30 }, { country: 'US', limit: 30 }], [{ country: 'DE', ipVersion: 6 }], [['DE']], [null], 42, {}]) {
    assert.throws(() => httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com', locations: bad }), TypeError, JSON.stringify(bad));
  }
});

test('httpsCheckRequest: refuses private / reserved IPs, bad hosts, bad ports and probe counts', () => {
  const base = { ip: '140.82.121.4', name: 'github.com' };
  for (const ip of ['10.0.0.1', '192.0.2.1', '3fff::1', 'nope']) assert.throws(() => httpsCheckRequest({ ...base, ip }), TypeError, ip);
  for (const name of ['_x.github.com', 'github.com.', 'github.com:443', '*.github.com', '140.82.121.4']) {
    assert.throws(() => httpsCheckRequest({ ...base, name }), TypeError, name);
  }
  for (const port of [0, 70000, 993, '443']) assert.throws(() => httpsCheckRequest({ ...base, port }), TypeError, String(port));
  for (const probes of [0, 51, 1.5, '1']) assert.throws(() => httpsCheckRequest({ ...base, probes }), TypeError, String(probes));
  assert.throws(() => httpsCheckRequest(), TypeError);
  assert.equal(httpsCheckRequest({ ...base, ip: '::ffff:140.82.121.4' }).target, '140.82.121.4');
});

test('httpsGetRequest: the MTA-STS policy fetch body, exactly as sent live (m26)', () => {
  const body = httpsGetRequest({ host: 'mta-sts.example.com', path: '/.well-known/mta-sts.txt' });
  assert.deepEqual(body, fx('m26-mta-sts-policy').request);
  assert.deepEqual(body, {
    type: 'http', target: 'mta-sts.example.com', limit: 1, timeout: 10,
    measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'GET', path: '/.well-known/mta-sts.txt' } }
  });
  assert.equal('host' in body.measurementOptions.request, false, 'the target is the host: no request.host');
  assert.equal(httpsGetRequest({ host: 'www.example.com' }).measurementOptions.request.path, '/');
  assert.equal(httpsGetRequest({ host: 'www.example.com', timeoutS: 99 }).timeout, 30);
});

test('httpsGetRequest: refuses hosts Globalping rejects, paths with a query, spaces or no leading slash, and unknown options', () => {
  for (const host of ['10.0.0.1', '_mta-sts.example.com', 'mta-sts.example.com.', 'localhost', '*.example.com', '', null]) {
    assert.throws(() => httpsGetRequest({ host }), TypeError, String(host));
  }
  for (const path of ['.well-known/mta-sts.txt', '/a b', '/a?x=1', '/a#top', '/a\n', '', 42, `/${'a'.repeat(501)}`]) {
    assert.throws(() => httpsGetRequest({ host: 'mta-sts.example.com', path }), TypeError, JSON.stringify(path));
  }
  assert.throws(() => httpsGetRequest({ host: 'mta-sts.example.com', port: 0 }), TypeError);
  assert.throws(() => httpsGetRequest({ host: 'mta-sts.example.com', probes: 0 }), TypeError);
  assert.throws(() => httpsGetRequest({ host: 'mta-sts.example.com', method: 'POST' }), /Unknown option: method/);
  assert.throws(() => httpsGetRequest(), TypeError);
});

test('httpGetRequest: the HTTP-01 reachability bodies, exactly as sent live (m28, m30)', () => {
  const locations = [{ continent: 'EU' }, { continent: 'NA' }, { continent: 'AS' }];
  const path = '/.well-known/acme-challenge/ds-fixture-tg6denb8mh';
  assert.deepEqual(httpGetRequest({ host: 'example.com', path, locations }), fx('m28-acme-http-404').request);
  assert.deepEqual(httpGetRequest({ host: 'example.com', path, locations, ipVersion: 6 }), fx('m30-acme-http-v6').request);
  assert.deepEqual(httpGetRequest({ host: 'www.example.com' }), {
    type: 'http', target: 'www.example.com', limit: 1, timeout: 10,
    measurementOptions: { protocol: 'HTTP', port: 80, request: { method: 'GET', path: '/' } }
  });
  const v4 = httpGetRequest({ host: 'www.example.com', ipVersion: 4, probes: 3, timeoutS: 2 });
  assert.deepEqual([v4.limit, v4.timeout, v4.measurementOptions.ipVersion], [3, 5, 4]);
  assert.equal('host' in v4.measurementOptions.request, false, 'the target is the host: no request.host');
  assert.equal(httpGetRequest({ host: 'www.example.com', locations: '2VxnLwVQJ9HR4iB2M00021DR4' }).locations, '2VxnLwVQJ9HR4iB2M00021DR4');
});

test('httpGetRequest: refuses bad hosts, paths, ports, IP versions, location lists and unknown options', () => {
  for (const host of ['192.0.2.1', '_acme-challenge.example.com', '*.example.com', 'localhost', '', null]) {
    assert.throws(() => httpGetRequest({ host }), TypeError, String(host));
  }
  for (const path of ['a', '/a b', '/a?x=1', '']) assert.throws(() => httpGetRequest({ host: 'example.com', path }), TypeError, path);
  for (const ipVersion of [0, 5, '6', true]) assert.throws(() => httpGetRequest({ host: 'example.com', ipVersion }), TypeError, String(ipVersion));
  assert.throws(() => httpGetRequest({ host: 'example.com', port: 0 }), TypeError);
  assert.throws(() => httpGetRequest({ host: 'example.com', locations: [] }), TypeError);
  assert.throws(() => httpGetRequest({ host: 'example.com', locations: [{ planet: 'Mars' }] }), /unknown key: planet/);
  assert.throws(() => httpGetRequest({ host: 'example.com', locations: [{ continent: 'EU', limit: 51 }] }), TypeError);
  assert.throws(() => httpGetRequest({ host: 'example.com', method: 'HEAD' }), /Unknown option: method/);
});

test('httpsGetAtRequest: a GET at an address with the name as SNI / Host, as sent live (h01), and the same probe again (h02)', () => {
  assert.deepEqual(httpsGetAtRequest({ ip: '140.82.121.3', host: 'github.com' }), fx('h01-get-at-first').request);
  const id = fx('h01-get-at-first').final.body.id;
  assert.deepEqual(httpsGetAtRequest({ ip: '140.82.121.4', host: 'github.com', locations: id }), fx('h02-get-at-same-probe').request);
  const v6 = httpsGetAtRequest({ ip: '2606:4700::6810:7c60', host: 'www.example.com', path: '/healthz', port: 8443, timeoutS: 99 });
  assert.deepEqual([v6.target, v6.timeout, v6.measurementOptions.port, v6.measurementOptions.request], ['2606:4700::6810:7c60', 30, 8443, { method: 'GET', host: 'www.example.com', path: '/healthz' }]);
  assert.equal(httpsGetAtRequest({ ip: '::ffff:140.82.121.3', host: 'github.com' }).target, '140.82.121.3');
});

test('httpsGetAtRequest: refuses private / documentation addresses, bad hosts, paths, ports and unknown options', () => {
  for (const ip of ['10.0.0.1', '192.0.2.10', '2001:db8::1', 'example.com', '', null]) {
    assert.throws(() => httpsGetAtRequest({ ip, host: 'www.example.com' }), TypeError, String(ip));
  }
  for (const host of ['192.0.2.1', '_x.example.com', '*.example.com', 'www.example.com.', 'localhost']) {
    assert.throws(() => httpsGetAtRequest({ ip: '140.82.121.3', host }), TypeError, host);
  }
  assert.throws(() => httpsGetAtRequest({ ip: '140.82.121.3', host: 'github.com', path: '/a?b=1' }), TypeError);
  assert.throws(() => httpsGetAtRequest({ ip: '140.82.121.3', host: 'github.com', port: 25 }), TypeError);
  assert.throws(() => httpsGetAtRequest({ ip: '140.82.121.3', host: 'github.com', method: 'HEAD' }), /Unknown option: method/);
});

test('measure: an HTTPS GET at an address returns status, headers, the cut body and tls; the second one ran on the same probe (h01, h02)', async () => {
  const { gp } = client([postOf('h01-get-at-first'), finalOf('h01-get-at-first'), postOf('h02-get-at-same-probe'), finalOf('h02-get-at-same-probe')]);
  const a = await gp.measure(fx('h01-get-at-first').request);
  const b = await gp.measure(fx('h02-get-at-same-probe').request);
  const [ra, rb] = [a.measurement.results[0], b.measurement.results[0]];
  assert.deepEqual([ra.result.statusCode, ra.result.truncated, ra.result.headers['strict-transport-security']], [200, true, 'max-age=31536000; includeSubdomains; preload']);
  assert.equal(ra.result.tls.fingerprint256, rb.result.tls.fingerprint256);
  assert.equal(ra.result.rawBody, rb.result.rawBody);
  assert.deepEqual(ra.probe, rb.probe, 'locations: <id> sends the same probe');
});

test('DNS measurements: isProbeableDnsName / isProbeableResolver / dnsQueryRequest', () => {
  for (const name of ['example.com', '_dmarc.example.com', '_sip._tcp.example.com', 'xn--mnchen-3ya.example.com', 'a-b.example.com']) {
    assert.equal(isProbeableDnsName(name), true, name);
  }
  for (const name of ['*.example.com', 'example.com.', 'com', 'Example.com', '192.0.2.1', 'a..example.com', '-a.example.com', `${'a'.repeat(64)}.example.com`, '', null, 7]) {
    assert.equal(isProbeableDnsName(name), false, String(name));
  }
  for (const r of ['ns1.example.net', '1.1.1.1', '2606:4700:4700::1111']) assert.equal(isProbeableResolver(r), true, r);
  for (const r of ['ns1.example.net.', '10.0.0.1', '192.0.2.53', '2001:db8::53', 'localhost', '', null]) assert.equal(isProbeableResolver(r), false, String(r));
  assert.deepEqual(dnsQueryRequest({ name: 'example.com', type: 'SOA', resolver: 'ns1.example.net' }), {
    type: 'dns', target: 'example.com', limit: 1, timeout: 15, measurementOptions: { query: { type: 'SOA' }, resolver: 'ns1.example.net', protocol: 'UDP', port: 53 }
  });
  const tcp = dnsQueryRequest({ name: '_dmarc.example.com', type: 'TXT', resolver: '::ffff:1.1.1.1', protocol: 'TCP', timeoutS: 1, locations: '2fMBxbOuE4PyivQYo00021DVq' });
  assert.deepEqual([tcp.measurementOptions.resolver, tcp.measurementOptions.protocol, tcp.timeout, tcp.locations, 'limit' in tcp], ['1.1.1.1', 'TCP', 5, '2fMBxbOuE4PyivQYo00021DVq', false]);
  assert.ok(Object.isFrozen(GP_DNS_TYPES) && GP_DNS_TYPES.includes('SVCB') && !GP_DNS_TYPES.includes('CAA'));
  for (const bad of [{ type: 'CAA' }, { type: 'a' }, { name: '*.example.com' }, { resolver: 'ns1.example.net.' }, { resolver: '10.0.0.1' }, { protocol: 'DOH' },
    { port: 0 }, { probes: 0 }, { timeoutS: NaN }, { recursion: false }]) {
    assert.throws(() => dnsQueryRequest({ name: 'example.com', type: 'A', resolver: 'ns1.example.net', ...bad }), TypeError, JSON.stringify(bad));
  }
});

test('DNS prefilter vs the live API: every refused DNS request of v-dns-cases.json is refused locally (free 400s never sent)', () => {
  for (const c of fx('v-dns-cases').cases) {
    const o = c.request.measurementOptions;
    assert.throws(() => dnsQueryRequest({ name: c.request.target, type: o.query.type, resolver: o.resolver, ...(o.recursion !== undefined ? { recursion: o.recursion } : {}) }), TypeError, c.name);
  }
});

test('measure: a DNS measurement of an authoritative server replays d01 at a cost of one probe', async () => {
  const { gp } = client([postOf('d01-soa'), finalOf('d01-soa')]);
  const res = await gp.measure(fx('d01-soa').request);
  assert.equal(res.cost, 1);
  const r = res.measurement.results[0].result;
  assert.deepEqual([r.status, r.statusCodeName, r.answers[0].type, r.resolver], ['finished', 'NOERROR', 'SOA', 'ns1.example.net']);
  assert.match(r.rawOutput, /;; flags: qr aa rd;/);
});

test('measure: an HTTP GET is not redirected by the probe — a 301 carries its Location (m29)', async () => {
  const { gp } = client([postOf('m29-acme-http-redirect'), finalOf('m29-acme-http-redirect')]);
  const res = await gp.measure(fx('m29-acme-http-redirect').request);
  assert.equal(res.cost, 3);
  for (const { result } of res.measurement.results) {
    assert.deepEqual([result.status, result.statusCode, result.tls], ['finished', 301, null]);
    assert.equal(result.headers.location, 'https://example.net/.well-known/acme-challenge/ds-fixture-tg6denb8mh');
  }
});

test('measure: an HTTPS GET measurement replays m26 (status, headers, decoded body, tls) at a cost of one probe', async () => {
  const { gp, calls } = client([postOf('m26-mta-sts-policy'), finalOf('m26-mta-sts-policy')]);
  const res = await gp.measure(fx('m26-mta-sts-policy').request);
  assert.equal(res.cost, 1);
  assert.equal(JSON.parse(calls[0].init.body).measurementOptions.request.method, 'GET');
  const r = res.measurement.results[0].result;
  assert.deepEqual([r.statusCode, r.headers['content-type'], r.truncated, r.tls.authorized], [200, 'text/plain', false, true]);
  assert.match(r.rawBody, /^version: STSv1\r\nmode: enforce\r\n/);
  const nx = fx('m27-mta-sts-no-host').final.body.results[0].result;
  assert.deepEqual([nx.status, nx.statusCode, nx.tls, nx.rawOutput], ['failed', null, null, 'queryA ENODATA mta-sts.example.com']);
});

/* ---- probe summary --------------------------------------------------------------------- */

test('probeSummary: country / city / network / kind / adopted, never coordinates or resolvers', () => {
  const probe = fx('m12-sni-refused').final.body.results[0].probe;
  const raw = { ...probe, latitude: 6.45, longitude: 3.39, state: null, resolvers: ['1.1.1.1'], tags: ['datacenter-network', 'u-someone'] };
  const s = probeSummary(raw);
  assert.deepEqual(s, { continent: 'AF', country: 'NG', city: 'Lagos', asn: 214354, network: 'SiteHUB Agency', kind: 'datacenter', adopted: true });
  assert.deepEqual(Object.keys(s).sort(), ['adopted', 'asn', 'city', 'continent', 'country', 'kind', 'network']);
  assert.equal(probeSummary(fx('m05-untrusted-root').final.body.results[0].probe).kind, 'eyeball');
  assert.equal(probeSummary(fx('m02-wrong-host').final.body.results[0].probe).adopted, false);
  assert.deepEqual(probeSummary(null), { continent: null, country: null, city: null, asn: null, network: null, kind: null, adopted: false });
  assert.deepEqual(probeSummary({ country: '', asn: '24940', tags: 'u-x' }).asn, null);
});

/* ---- quota ----------------------------------------------------------------------------- */

test('quotaFromHeaders: the 202 headers of m01 (plain object or Headers, any case)', () => {
  const q = quotaFromHeaders(fx('m01-github-valid').post.headers, T0);
  assert.deepEqual({ ...q, resetAt: q.resetAt.getTime(), at: q.at.getTime() }, {
    limit: 250, remaining: 248, consumed: 2, resetAt: T0 + 3600 * S, cost: 2, type: null, source: 'create', at: T0
  });
  const h = new Headers({ 'X-RateLimit-Remaining': '7', 'X-RateLimit-Limit': '250', 'X-RateLimit-Reset': '12' });
  const q2 = quotaFromHeaders(h, new Date(T0));
  assert.equal(q2.remaining, 7);
  assert.equal(q2.resetAt.getTime(), T0 + 12 * S);
  assert.equal(q2.cost, null);
  assert.equal(quotaFromHeaders({ 'X-RateLimit-Remaining': '3' }, T0).remaining, 3);
  assert.equal(quotaFromHeaders({}, T0), null, 'errors carry no X-RateLimit headers');
  assert.equal(quotaFromHeaders(null, T0), null);
  assert.equal(quotaFromHeaders({ 'x-ratelimit-remaining': 'abc' }, T0), null);
});

test('quotaFromLimits: body only; reset 0 means no window is open yet', () => {
  const fresh = quotaFromLimits(responseOf('limits-fresh').body, T0);
  assert.equal(fresh.resetAt, null);
  assert.deepEqual([fresh.limit, fresh.remaining, fresh.consumed, fresh.type, fresh.source, fresh.cost], [250, 250, 0, 'ip', 'limits', null]);
  const used = quotaFromLimits(responseOf('limits-used').body, T0);
  assert.equal(used.resetAt.getTime(), T0 + 3314 * S);
  assert.equal(used.consumed, 9);
  for (const bad of [null, {}, { rateLimit: {} }, { rateLimit: { measurements: { create: { remaining: 'x' } } } }]) {
    assert.equal(quotaFromLimits(bad, T0), null);
  }
});

test('mergeQuota: six concurrent POST readings in one window → the minimum (215), never raised', () => {
  const { posts } = fx('create-parallel-quota');
  assert.deepEqual(posts.map((p) => Number(p.headers['x-ratelimit-remaining'])), [220, 216, 215, 219, 217, 218]);
  let q = null;
  const seen = [];
  for (const [i, p] of posts.entries()) {
    q = mergeQuota(q, quotaFromHeaders(p.headers, T0 + i * 10), T0 + i * 10);
    seen.push(q.remaining);
  }
  assert.deepEqual(seen, [220, 216, 215, 215, 215, 215]);
  assert.equal(q.cost, 1);
});

test('mergeQuota: a /limits reading never raises remaining inside an open window', () => {
  const created = quotaFromHeaders({ 'x-ratelimit-remaining': '200', 'x-ratelimit-limit': '250', 'x-ratelimit-reset': '1800', 'x-request-cost': '1' }, T0);
  const later = quotaFromLimits({ rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: 240, reset: 1790 } } } }, T0 + 10 * S);
  const m = mergeQuota(created, later, T0 + 10 * S);
  assert.equal(m.remaining, 200);
  assert.equal(m.type, 'ip', 'type comes from the reading that knows it');
  assert.equal(m.cost, 1, 'cost stays the last create\'s');
  assert.equal(m.source, 'limits');
  // a reading without a window (reset 0) cannot end an open one
  const noWindow = quotaFromLimits(responseOf('limits-fresh').body, T0 + 20 * S);
  const m2 = mergeQuota(m, noWindow, T0 + 20 * S);
  assert.equal(m2.remaining, 200);
  assert.equal(m2.resetAt.getTime(), T0 + 1800 * S);
});

test('mergeQuota: a later window replaces the reading; 429 → 0; null handling', () => {
  const old = quotaFromHeaders({ 'x-ratelimit-remaining': '3', 'x-ratelimit-reset': '100' }, T0);
  const fresh = quotaFromLimits(responseOf('limits-fresh').body, T0 + 200 * S);
  assert.equal(mergeQuota(old, fresh, T0 + 200 * S).remaining, 250, 'prev window has ended');
  const next = quotaFromHeaders({ 'x-ratelimit-remaining': '249', 'x-ratelimit-reset': '3600' }, T0 + 50 * S);
  assert.equal(mergeQuota(old, next, T0 + 50 * S).remaining, 249, 'a window ending > 60 s later is a new window');
  // a window opened since a no-window reading
  const opened = mergeQuota(quotaFromLimits(responseOf('limits-fresh').body, T0), next, T0 + 50 * S);
  assert.equal(opened.remaining, 249);
  assert.equal(opened.resetAt.getTime(), T0 + 3650 * S);
  // two no-window readings: a /limits one is the server's word that no window is open (it replaces);
  // any other windowless reading after it is min-merged
  const a = quotaFromLimits({ rateLimit: { measurements: { create: { limit: 250, remaining: 250, reset: 0 } } } }, T0);
  const b = quotaFromLimits({ rateLimit: { measurements: { create: { limit: 250, remaining: 240, reset: 0 } } } }, T0);
  assert.equal(mergeQuota(b, a, T0).remaining, 250);
  const bare = { limit: null, remaining: 230, consumed: null, resetAt: null, cost: 1, type: null, source: 'create', at: new Date(T0) };
  assert.equal(mergeQuota(a, bare, T0).remaining, 230);
  // 429 → 0, in the current window and with nothing known before
  const r429 = { limit: null, remaining: 0, consumed: null, resetAt: null, cost: null, type: null, source: '429', at: new Date(T0) };
  const z = mergeQuota(next, { ...r429, remaining: 5 }, T0 + 60 * S);
  assert.equal(z.remaining, 0);
  assert.equal(z.limit, null, 'limit unknown on both sides');
  assert.equal(z.resetAt.getTime(), T0 + 3650 * S, 'keeps the open window');
  assert.equal(mergeQuota(null, { ...r429, remaining: 9 }, T0).remaining, 0);
  assert.equal(mergeQuota(next, null, T0), next);
  assert.equal(mergeQuota(null, null, T0), null);
});

/* ---- create ---------------------------------------------------------------------------- */

test('create: JSON POST, no authorization without a token; 202 → id / probesCount / cost; quota merged + onQuota', async () => {
  const m01 = fx('m01-github-valid');
  const { gp, calls } = client([m01.post]);
  const seen = [];
  const off = gp.onQuota((q) => seen.push(q.remaining));
  const out = await gp.create(m01.request);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${GLOBALPING_API}/measurements`);
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(calls[0].init.headers, { 'content-type': 'application/json' });
  assert.deepEqual(JSON.parse(calls[0].init.body), m01.request);
  assert.equal(out.id, '2BQe3etLekZmRGfMF00021C1L');
  assert.equal(out.probesCount, 2);
  assert.equal(out.cost, 2);
  assert.equal(out.quota.remaining, 248);
  assert.equal(gp.quota.remaining, 248);
  assert.equal(gp.quota.resetAt.getTime(), T0 + 3600 * S);
  assert.deepEqual(seen, [248]);
  off();
  assert.equal(gp.tokenState, 'none');
});

test('create: quota min-tracking across a burst of creates in one window', async () => {
  const { posts } = fx('create-parallel-quota');
  const { gp } = client(posts);
  const seen = [];
  gp.onQuota((q) => seen.push(q.remaining));
  const body = httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com' });
  for (let i = 0; i < posts.length; i += 1) assert.equal((await gp.create(body)).cost, 1);
  assert.deepEqual(seen, [220, 216, 215, 215, 215, 215]);
  assert.equal(gp.quota.remaining, 215);
});

test('create: free validation errors map to codes and leave the quota alone', async () => {
  for (const [name, code] of [['v-private-target-400', 'private-target'], ['v-testnet1-400', 'private-target'],
    ['v-bad-host-400', 'bad-host'], ['v-limit-and-location-limit-400', 'validation'], ['v-ip-with-ipversion-400', 'validation'],
    ['v-no-probes-422', 'no-probes']]) {
    const { gp, calls } = client([postOf(name)]);
    await assert.rejects(gp.create(fx(name).request), (err) => {
      assert.equal(err.code, code, name);
      assert.equal(err.status, fx(name).post.status);
      assert.equal(errorKind(err), 'http');
      return true;
    });
    assert.equal(calls.length, 1, `${name}: no retry`);
    assert.equal(gp.quota, null, `${name}: no quota reading on a free error`);
  }
  const { gp } = client([postOf('v-limit-and-location-limit-400')]);
  await assert.rejects(gp.create({ type: 'http' }), (err) => {
    assert.deepEqual(Object.keys(err.params), ['locations.0.limit']);
    return true;
  });
  const underscore = fx('validation-cases').cases.find((c) => c.name === 'v2-host-underscore');
  const u = client([{ status: underscore.status, body: underscore.body }]);
  await rejectsCode(u.gp.create(underscore.request), 'bad-host');
});

test('create: 401 with a token → the same request once without authorization; the token is dropped', async () => {
  const m12 = fx('m12-sni-refused');
  const { gp, calls } = client([postOf('create-401'), m12.post, m12.post], { token: 'bad-token-123' });
  assert.equal(gp.tokenState, 'set');
  const out = await gp.create(m12.request);
  assert.equal(out.id, ID);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].init.headers.authorization, 'Bearer bad-token-123');
  assert.equal('authorization' in calls[1].init.headers, false);
  assert.equal(calls[0].init.body, calls[1].init.body, 'the same body is repeated');
  assert.equal(gp.tokenState, 'rejected');
  await gp.create(m12.request);
  assert.equal('authorization' in calls[2].init.headers, false, 'no token afterwards');
  gp.setToken(null);
  assert.equal(gp.tokenState, 'none');
  gp.setToken(' good-token ');
  assert.equal(gp.tokenState, 'set');
  assert.throws(() => gp.setToken('bad token with spaces'), TypeError);
  assert.throws(() => gp.setToken(42), TypeError);
});

test('create: 401 without a token → unauthorized', async () => {
  const { gp, calls } = client([postOf('create-401')]);
  await rejectsCode(gp.create(fx('create-401').request), 'unauthorized');
  assert.equal(calls.length, 1);
});

test('create: 429 rate_limit_exceeded → rate-limit, remaining 0, resetAt from x-ratelimit-reset', async () => {
  const m12 = fx('m12-sni-refused');
  const { gp, calls } = client([m12.post, postOf('create-429')]);
  const seen = [];
  gp.onQuota((q) => seen.push(q.remaining));
  await gp.create(m12.request);
  await assert.rejects(gp.create(m12.request), (err) => {
    assert.equal(err.code, 'rate-limit');
    assert.equal(errorKind(err), 'rate-limit');
    assert.equal(err.status, 429);
    assert.equal(err.quota.remaining, 0);
    assert.equal(err.resetAt.getTime(), T0 + 1200 * S, 'the reset header of the 429 is the newest word on the window');
    assert.equal(err.retryAfterMs, 1200 * S);
    return true;
  });
  assert.equal(calls.length, 2, 'no /limits call when the reset header is readable');
  assert.deepEqual(seen, [237, 0]);
  assert.equal(gp.quota.remaining, 0);
});

test('create: 429 without a readable reset header → exactly one free /limits read fills resetAt', async () => {
  const bare = { ...postOf('create-429'), headers: {} };
  const { gp, calls } = client([bare, responseOf('limits-used')]);
  await assert.rejects(gp.create(fx('create-429').request), (err) => {
    assert.equal(err.code, 'rate-limit');
    assert.equal(err.resetAt.getTime(), T0 + 3314 * S);
    assert.equal(err.quota.remaining, 0, '/limits said 241, the 429 wins');
    return true;
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[1].url, `${GLOBALPING_API}/limits`);
  assert.equal(calls[1].init.method, 'GET');
});

test('create: 429 insufficient_credits → insufficient-credits (a quota stop too)', async () => {
  const p = postOf('create-429');
  const { gp } = client([{ ...p, body: { error: { type: 'insufficient_credits', message: 'No credits.' } } }]);
  await assert.rejects(gp.create(fx('create-429').request), (err) => {
    assert.equal(err.code, 'insufficient-credits');
    assert.equal(errorKind(err), 'rate-limit');
    return true;
  });
});

test('create: a burst 429 (too_many_requests / short Retry-After) waits and repeats the same POST once', async () => {
  const m12 = fx('m12-sni-refused');
  const burst = { status: 429, headers: { 'retry-after': '5' }, body: { error: { type: 'too_many_requests', message: 'Too many requests.' } } };
  const a = client([burst, m12.post]);
  const out = await a.gp.create(m12.request);
  assert.equal(out.id, ID);
  assert.equal(a.calls.length, 2);
  assert.deepEqual(a.sleeps, [5000]);
  assert.equal(a.calls[0].init.body, a.calls[1].init.body);
  assert.equal(a.gp.quota.remaining, 237, 'a burst 429 is not a quota stop');
  const b = client([burst, burst]);
  await rejectsCode(b.gp.create(m12.request), 'poll-rate');
  assert.equal(b.calls.length, 2, 'repeated once only');
  // an unknown 429 type is a slow-down too (only the two quota types stop the queue): Retry-After, else 5 s
  const c = client([{ status: 429, headers: { 'retry-after': '3' }, body: { error: { type: 'slow_down' } } }, m12.post]);
  await c.gp.create(m12.request);
  assert.deepEqual(c.sleeps, [3000]);
  const d = client([{ status: 429, headers: { 'x-ratelimit-reset': '600' }, body: { error: { type: 'slow_down' } } }, m12.post]);
  assert.equal((await d.gp.create(m12.request)).id, ID);
  assert.deepEqual(d.sleeps, [5000]);
});

test('create: an unrecognised 429 is never a quota stop and never pins the quota at 0', async () => {
  const m12 = fx('m12-sni-refused');
  // an edge / WAF 429: no type, not JSON, no headers — after /limits said 250 with no window open
  const edge = { status: 429, raw: 'Too Many Requests' };
  const a = client([responseOf('limits-fresh'), edge, edge, responseOf('limits-fresh')]);
  await a.gp.limits();
  await assert.rejects(a.gp.create(m12.request), (err) => {
    assert.equal(err.code, 'poll-rate');
    assert.notEqual(errorKind(err), 'rate-limit');
    assert.equal(err.quota, null);
    return true;
  });
  assert.equal(a.calls.length, 3, 'repeated once after 5 s, and no /limits read');
  assert.deepEqual(a.sleeps, [5000]);
  assert.deepEqual([a.gp.quota.remaining, a.gp.quota.resetAt], [250, null], 'the quota is untouched');
  a.clock.t += 3600 * S;
  assert.equal((await a.gp.limits()).remaining, 250);
  // an unknown type asking for a long wait: reported at once, nothing slept, quota untouched
  const b = client([{ status: 429, headers: { 'retry-after': '3600' }, body: { error: { type: 'some_new_type' } } }]);
  await assert.rejects(b.gp.create(m12.request), (err) => err.code === 'poll-rate' && err.retryAfterMs === 3600 * S);
  assert.deepEqual([b.calls.length, b.sleeps.length, b.gp.quota], [1, 0, null]);
  // a real quota 429 without any reset time (while /limits reports no window) is lifted by the next /limits read
  const q = { status: 429, body: { error: { type: 'rate_limit_exceeded', message: 'Limit exceeded.' } } };
  const c = client([q, responseOf('limits-fresh'), responseOf('limits-fresh')]);
  await rejectsCode(c.gp.create(m12.request), 'rate-limit');
  assert.deepEqual([c.gp.quota.remaining, c.gp.quota.resetAt], [0, null]);
  c.clock.t += 60 * S;
  assert.equal((await c.gp.limits()).remaining, 250, 'the server says no window is open');
});

test('a response body that stalls after its headers is cut by the request timeout (TimeoutError)', async () => {
  const stalled = (status) => () => new Response(new ReadableStream({
    start(ctl) { ctl.enqueue(new TextEncoder().encode('{"id":')); } // never closed
  }), { status, headers: { 'content-type': 'application/json' } });
  const started = Date.now();
  const a = client([stalled(202)], { requestTimeoutMs: 30 });
  await assert.rejects(a.gp.create(fx('m12-sni-refused').request), (err) => err.name === 'TimeoutError' && errorKind(err) === 'timeout');
  assert.equal(a.calls.length, 1, 'a POST is never repeated: it may have been charged');
  const b = client([stalled(200), stalled(200), stalled(200)], { requestTimeoutMs: 30 });
  await assert.rejects(b.gp.get(ID), { name: 'TimeoutError' });
  assert.equal(b.calls.length, 3, 'a GET is retried twice, then reported');
  const c = client([stalled(200), responseOf('limits-fresh')], { requestTimeoutMs: 30 });
  assert.equal((await c.gp.limits()).remaining, 250, '/limits is retried once');
  assert.ok(Date.now() - started < 5000, 'bounded by the request timeout, not hung');
});

test('create: 502 / 503 are retried once after 1 s; 504, other 5xx and other statuses never', async () => {
  const m12 = fx('m12-sni-refused');
  const a = client([{ status: 502 }, m12.post]);
  assert.equal((await a.gp.create(m12.request)).id, ID);
  assert.deepEqual(a.sleeps, [1000]);
  const b = client([{ status: 503 }, { status: 503 }]);
  await rejectsCode(b.gp.create(m12.request), 'server');
  assert.equal(b.calls.length, 2);
  for (const status of [500, 504, 403, 404, 405, 413]) {
    const c = client([{ status, raw: '<html>proxy</html>' }]);
    await assert.rejects(c.gp.create(m12.request), (err) => {
      assert.equal(err.code, 'server', String(status));
      assert.equal(err.status, status);
      assert.equal(err.body, '<html>proxy</html>');
      return true;
    });
    assert.equal(c.calls.length, 1, `${status}: a retried POST could double-spend`);
  }
});

test('create: a network TypeError or a request timeout is never retried (the POST may have been charged)', async () => {
  const m12 = fx('m12-sni-refused');
  const a = client([new TypeError('Failed to fetch'), m12.post]);
  await assert.rejects(a.gp.create(m12.request), (err) => err instanceof TypeError && errorKind(err) === 'network');
  assert.equal(a.calls.length, 1);
  const hang = (url, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason)));
  const b = client([hang, m12.post], { requestTimeoutMs: 20 });
  await assert.rejects(b.gp.create(m12.request), (err) => err.name === 'TimeoutError' && errorKind(err) === 'timeout');
  assert.equal(b.calls.length, 1);
});

test('create: unusable 202 bodies → bad-response', async () => {
  const m12 = fx('m12-sni-refused');
  for (const spec of [{ status: 202, raw: 'not json' }, { status: 202, body: { probesCount: 1 } }, { status: 202, body: { id: '../x' } }, { status: 202 }]) {
    const { gp } = client([spec]);
    await assert.rejects(gp.create(m12.request), (err) => err.code === 'bad-response' && errorKind(err) === 'parse');
  }
  // cost falls back to probesCount without X-Request-Cost
  const { gp } = client([{ status: 202, body: { id: ID, probesCount: 3 } }]);
  const out = await gp.create(m12.request);
  assert.deepEqual([out.cost, out.probesCount, out.quota], [3, 3, null]);
});

test('create: port 0 or a non-object body is refused before any request', async () => {
  const { gp, calls } = client([]);
  const body = httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com' });
  for (const port of [0, 70000, 1.5, '443']) {
    await assert.rejects(gp.create({ ...body, measurementOptions: { ...body.measurementOptions, port } }), TypeError);
  }
  for (const bad of [null, 'x', [body]]) await assert.rejects(gp.create(bad), TypeError);
  assert.equal(calls.length, 0);
});

test('create: AbortError propagates (before the request, during it, and during the retry wait)', async () => {
  const m12 = fx('m12-sni-refused');
  const ctl = new AbortController();
  ctl.abort();
  const a = client([m12.post]);
  await assert.rejects(a.gp.create(m12.request, { signal: ctl.signal }), { name: 'AbortError' });
  assert.equal(a.calls.length, 0);

  const ctl2 = new AbortController();
  const hang = (url, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))));
  const b = client([hang]);
  const p = b.gp.create(m12.request, { signal: ctl2.signal });
  setTimeout(() => ctl2.abort(), 5);
  await assert.rejects(p, { name: 'AbortError' });

  const ctl3 = new AbortController();
  const c = client([{ status: 502 }, m12.post], {
    sleepImpl: async (ms, signal) => { ctl3.abort(); throwIfAborted(signal); }
  });
  await assert.rejects(c.gp.create(m12.request, { signal: ctl3.signal }), { name: 'AbortError' });
  assert.equal(c.calls.length, 1, 'no request after the abort');
});

/* ---- limits ---------------------------------------------------------------------------- */

test('limits: GET /limits (no-store, no headers without a token); body-only quota; merged into client.quota', async () => {
  const { gp, calls } = client([responseOf('limits-fresh')]);
  const q = await gp.limits();
  assert.equal(calls[0].url, `${GLOBALPING_API}/limits`);
  assert.equal(calls[0].init.method, 'GET');
  assert.equal(calls[0].init.cache, 'no-store');
  assert.equal(calls[0].init.headers, undefined);
  assert.equal(q.remaining, 250);
  assert.equal(q.resetAt, null);
  assert.equal(gp.quota, q);
});

test('limits: a token is sent; a 401 drops it and repeats anonymously (a free validity check)', async () => {
  const { gp, calls } = client([{ status: 401, body: { error: { type: 'unauthorized', message: 'Unauthorized.' } } }, responseOf('limits-used')], { token: 'tok-1234' });
  const q = await gp.limits();
  assert.equal(calls[0].init.headers.authorization, 'Bearer tok-1234');
  assert.equal(calls[1].init.headers, undefined);
  assert.equal(gp.tokenState, 'rejected');
  assert.equal(q.remaining, 241);
  const bad = client([{ status: 200, body: { nope: 1 } }]);
  await rejectsCode(bad.gp.limits(), 'bad-response');
});

test('limits after creates: remaining stays the minimum of the window', async () => {
  const m12 = fx('m12-sni-refused'); // remaining 237, reset 3512
  const limitsLater = { status: 200, body: { rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: 240, reset: 3500 } } } } };
  const { gp } = client([m12.post, limitsLater]);
  await gp.create(m12.request);
  const q = await gp.limits();
  assert.equal(q.remaining, 237);
  assert.equal(q.type, 'ip');
});

/* ---- get / poll ------------------------------------------------------------------------ */

test('poll: sleeps 500 ms before the first GET and after each response; GETs are simple no-store requests', async () => {
  const m12 = fx('m12-sni-refused');
  const { gp, calls, sleeps } = client([inProgressOf('m12-sni-refused'), inProgressOf('m12-sni-refused'), finalOf('m12-sni-refused')]);
  const updates = [];
  const m = await gp.poll(ID, { onUpdate: (x) => updates.push(x.status) });
  assert.equal(m.status, 'finished');
  assert.deepEqual(m.results[0].result.rawOutput, m12.final.body.results[0].result.rawOutput);
  assert.equal(calls.length, 3);
  assert.deepEqual(sleeps, [500, 500, 500]);
  assert.equal(calls[0].at, T0 + 500, 'the first GET only after sleepImpl(500)');
  for (const c of calls) {
    assert.equal(c.url, `${GLOBALPING_API}/measurements/${ID}`);
    assert.equal(c.init.method, 'GET');
    assert.equal(c.init.cache, 'no-store');
    assert.equal(c.init.headers, undefined, 'no custom header → no CORS preflight');
    assert.equal(c.init.body, undefined);
  }
  assert.deepEqual(updates, ['in-progress', 'in-progress', 'finished']);
});

test('poll: onUpdate receives the in-progress measurement with its probe metadata', async () => {
  const { gp } = client([inProgressOf('m01-github-valid'), finalOf('m01-github-valid')]);
  const first = [];
  await gp.poll('2BQe3etLekZmRGfMF00021C1L', { onUpdate: (m) => first.push(m) });
  assert.equal(first[0].status, 'in-progress');
  assert.deepEqual(first[0].results.map((r) => probeSummary(r.probe).country), ['DE', 'US']);
  // recorded live: the measurement is still in progress while the DE test has already finished
  assert.deepEqual(first[0].results.map((r) => r.result.status), ['finished', 'in-progress']);
});

test('get: a 429 honours Retry-After (5 s) and continues; three in a row → poll-rate', async () => {
  const a = client([responseOf('poll-429'), finalOf('m12-sni-refused')]);
  const m = await a.gp.poll(ID);
  assert.equal(m.status, 'finished');
  assert.deepEqual(a.sleeps, [500, 5000]);
  const b = client([responseOf('poll-429'), responseOf('poll-429'), responseOf('poll-429'), finalOf('m12-sni-refused')]);
  await assert.rejects(b.gp.get(ID), (err) => err.code === 'poll-rate' && err.retryAfterMs === 5000);
  assert.equal(b.calls.length, 3);
  const c = client([{ status: 429, body: { error: { type: 'too_many_requests' } } }, finalOf('m12-sni-refused')]);
  await c.gp.get(ID);
  assert.deepEqual(c.sleeps, [5000], 'default 5 s without Retry-After');
  const d = client([{ status: 429, headers: { 'retry-after': '120' } }]);
  await rejectsCode(d.gp.get(ID), 'poll-rate');
  assert.deepEqual(d.sleeps, [], 'a long Retry-After is reported, not slept through');
});

test('get: 404 → not-found; 5xx / network errors retried twice at 1 s; bad bodies → bad-response', async () => {
  const a = client([responseOf('get-404')]);
  await rejectsCode(a.gp.get(ID), 'not-found');
  const b = client([{ status: 503 }, new TypeError('Failed to fetch'), finalOf('m12-sni-refused')]);
  assert.equal((await b.gp.get(ID)).status, 'finished');
  assert.deepEqual(b.sleeps, [1000, 1000]);
  const c = client([{ status: 500 }, { status: 502 }, { status: 503 }, finalOf('m12-sni-refused')]);
  await rejectsCode(c.gp.get(ID), 'server');
  assert.equal(c.calls.length, 3);
  const d = client([new TypeError('x'), new TypeError('y'), new TypeError('z')]);
  await assert.rejects(d.gp.get(ID), (err) => err instanceof TypeError && err.message === 'z');
  assert.equal(d.calls.length, 3);
  for (const spec of [{ status: 200, raw: '<html>' }, { status: 200, body: { status: 'finished' } }, { status: 200, body: [] }]) {
    const e = client([spec]);
    await rejectsCode(e.gp.get(ID), 'bad-response');
  }
  const f = client([{ status: 403, raw: 'denied' }]);
  await rejectsCode(f.gp.get(ID), 'server');
});

test('get / poll: an id that is not a measurement id is refused before any request', async () => {
  const { gp, calls } = client([]);
  for (const id of ['../x', '../../limits', 'abc', '', null, 'a/b/c/d/e/f', `${ID}?x=1`]) {
    await rejectsCode(gp.get(id), 'validation');
    await rejectsCode(gp.poll(id), 'validation');
  }
  assert.equal(calls.length, 0);
});

test('get: per-id throttle — concurrent GETs on one id are ≥ 500 ms apart; other ids are not delayed', async () => {
  const other = '2BQe3etLekZmRGfMF00021C1L';
  const { gp, calls, sleeps } = client([inProgressOf('m12-sni-refused'), finalOf('m12-sni-refused'), finalOf('m01-github-valid')]);
  const [x, y, z] = await Promise.all([gp.get(ID), gp.get(ID), gp.get(other)]);
  assert.deepEqual([x.status, y.status, z.status], ['in-progress', 'finished', 'finished']);
  assert.deepEqual(calls.map((c) => c.url.slice(-25)), [ID, other, ID], 'the other id did not wait');
  const sameId = calls.filter((c) => c.url.endsWith(ID));
  assert.ok(sameId[1].at - sameId[0].at >= 500, `${sameId[1].at - sameId[0].at} ms apart`);
  assert.deepEqual(sleeps, [500]);
});

test('get: a caller queued behind another GET on the same id is released at once by its abort; its GET never leaves', async () => {
  let release;
  const slow = () => new Promise((resolve) => { release = () => resolve(respond(finalOf('m12-sni-refused'))); });
  const { gp, calls } = client([slow, finalOf('m12-sni-refused')]);
  const first = gp.get(ID);
  const ctl = new AbortController();
  const second = gp.get(ID, { signal: ctl.signal });
  await new Promise((r) => setImmediate(r));
  ctl.abort();
  await assert.rejects(second, { name: 'AbortError' });
  assert.equal(calls.length, 1, 'still only the first GET');
  release();
  assert.equal((await first).status, 'finished');
  await new Promise((r) => setImmediate(r));
  assert.equal(calls.length, 1, 'the aborted caller never sent its GET');
});

test('poll: deadline (absolute deadlineAt or relative deadlineMs) → deadline error, errorKind timeout', async () => {
  const inProg = inProgressOf('m12-sni-refused');
  const a = client(Array.from({ length: 20 }, () => inProg));
  await assert.rejects(a.gp.poll(ID, { deadlineAt: T0 + 3000 }), (err) => err.code === 'deadline' && errorKind(err) === 'timeout');
  assert.deepEqual(a.calls.map((c) => c.at - T0), [500, 1000, 1500, 2000, 2500, 3000]);
  const b = client(Array.from({ length: 20 }, () => inProg));
  await rejectsCode(b.gp.poll(ID, { deadlineMs: 1000 }), 'deadline');
  assert.equal(b.calls.length, 2);
});

test('poll: an abort during a sleep rejects with AbortError and sends no further GET', async () => {
  const ctl = new AbortController();
  let n = 0;
  const { gp, calls } = client([inProgressOf('m12-sni-refused'), finalOf('m12-sni-refused')], {
    sleepImpl: async (ms, signal) => {
      n += 1;
      if (n === 2) ctl.abort(); // the sleep after the first response
    }
  });
  await assert.rejects(gp.poll(ID, { signal: ctl.signal }), { name: 'AbortError' });
  assert.equal(calls.length, 1);
});

/* ---- measure --------------------------------------------------------------------------- */

test('measure: create + poll; returns measurement, id, cost and the merged quota', async () => {
  const m01 = fx('m01-github-valid');
  const { gp, calls } = client([m01.post, inProgressOf('m01-github-valid'), finalOf('m01-github-valid')]);
  const out = await gp.measure(m01.request);
  assert.equal(out.id, '2BQe3etLekZmRGfMF00021C1L');
  assert.equal(out.cost, 2);
  assert.equal(out.quota.remaining, 248);
  assert.equal(out.measurement.results.length, 2);
  assert.equal(out.measurement.results[0].result.tls.fingerprint256.slice(0, 11), '46:B6:01:EE');
  assert.equal(calls.length, 3);
});

test('measure: the deadline is (timeout + 10) s after the 202; the error keeps the paid id', async () => {
  const body = httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com', port: 8443, timeoutS: 5 });
  const inProg = inProgressOf('m11-filtered-timeout5');
  const { gp, clock, calls } = client([postOf('m11-filtered-timeout5'), ...Array.from({ length: 60 }, () => inProg)]);
  await assert.rejects(gp.measure(body), (err) => {
    assert.equal(err.code, 'deadline');
    assert.equal(err.measurementId, fx('m11-filtered-timeout5').post.body.id);
    assert.equal(err.cost, 1);
    return true;
  });
  assert.equal(clock.t - T0, 15 * S, 'gave up exactly 15 s after the POST');
  assert.equal(calls.length, 1 + 30);
  // no timeout in the body → the API maximum (30 s) + 10 s
  const c = client([postOf('m12-sni-refused'), ...Array.from({ length: 100 }, () => inProgressOf('m12-sni-refused'))]);
  const { timeout, ...noTimeout } = httpsCheckRequest({ ip: '140.82.121.4', name: 'github.com' });
  assert.equal(timeout, 10);
  await rejectsCode(c.gp.measure(noTimeout), 'deadline');
  assert.equal(c.clock.t - T0, 40 * S);
});

test('measure: a filtered port finishes as a failed test within the deadline (m11 replay)', async () => {
  const m11 = fx('m11-filtered-timeout5');
  const { gp } = client([m11.post, inProgressOf('m11-filtered-timeout5'), finalOf('m11-filtered-timeout5')]);
  const out = await gp.measure(m11.request);
  const r = out.measurement.results[0].result;
  assert.equal(out.measurement.status, 'finished');
  assert.equal(r.status, 'failed');
  assert.match(r.rawOutput, /timed out while establishing the TCP connection/);
  assert.equal(r.tls, null);
});
