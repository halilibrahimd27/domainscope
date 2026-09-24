import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createIpIntel, splitAsHolder, parsePrefixOverview, parseGeoLite, parseIpwhois,
  parseRipeReverseDns, parseReverseIpText, RIPESTAT_SOURCEAPP
} from '../../assets/js/lib/ipintel.js';

/* -------------------------------------------------------------------- */
/* Fixtures (shapes captured live 2026-09-23, trimmed)                  */
/* -------------------------------------------------------------------- */

const PO_GITHUB = {
  status: 'ok',
  messages: [['warning', 'Given resource is not announced but result has been aligned to first-level less-specific (140.82.121.0/24).']],
  data: {
    is_less_specific: true,
    announced: true,
    asns: [{ asn: 36459, holder: 'GITHUB - GitHub, Inc.' }],
    related_prefixes: ['140.82.112.0/20', '140.82.120.0/23'],
    resource: '140.82.121.0/24',
    type: 'prefix',
    block: { resource: '140.0.0.0/8', desc: 'Administered by ARIN', name: 'IANA IPv4 Address Space Registry' }
  }
};
const GEO_GITHUB = {
  status: 'ok',
  data: {
    located_resources: [{
      resource: '140.82.121.4/32',
      locations: [{ country: 'DE', city: 'Frankfurt am Main', resources: ['140.82.120.0/23'], covered_percentage: 100.0 }],
      unknown_percentage: 0
    }]
  }
};
const PO_UNANNOUNCED = {
  status: 'ok',
  data: {
    announced: false, asns: [], resource: '192.0.2.1', is_less_specific: false,
    block: { resource: '192.0.2.0/24', desc: 'Documentation (TEST-NET-1)', name: 'IANA IPv4 Special Purpose Address Registry' }
  }
};
const IPWHO_GITHUB = {
  ip: '140.82.121.4', success: true, type: 'IPv4', country: 'Germany', country_code: 'DE', city: 'Frankfurt am Main',
  connection: { asn: 36459, org: 'GitHub, Inc.', isp: 'GitHub, Inc.', domain: 'github.com' }
};

function jsonResponse(body, status = 200) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status, headers: { 'content-type': 'application/json' }
  });
}

/**
 * Mock fetch routing by URL substring. `routes` maps a substring to a body
 * (object → JSON), a function (url) => Response|body, or an Error to throw.
 */
function mockFetch(routes, { delayMs = 0, log = [] } = {}) {
  let active = 0;
  const stats = { maxActive: 0, calls: log };
  const impl = async (url, init = {}) => {
    const u = String(url);
    log.push(u);
    active += 1;
    stats.maxActive = Math.max(stats.maxActive, active);
    try {
      if (delayMs) {
        await new Promise((resolve, reject) => {
          const t = setTimeout(resolve, delayMs);
          init.signal?.addEventListener('abort', () => { clearTimeout(t); reject(init.signal.reason); }, { once: true });
        });
      }
      const key = Object.keys(routes).find((k) => u.includes(k));
      if (!key) return jsonResponse({ error: 'no route' }, 404);
      let v = routes[key];
      if (typeof v === 'function') v = await v(u, init);
      if (v instanceof Error) throw v;
      if (v instanceof Response) return v;
      return jsonResponse(v);
    } finally {
      active -= 1;
    }
  };
  impl.stats = stats;
  return impl;
}

/* -------------------------------------------------------------------- */
/* Parsers                                                              */
/* -------------------------------------------------------------------- */

test('splitAsHolder separates the AS name from the organisation', () => {
  assert.deepEqual(splitAsHolder('GOOGLE - Google LLC'), { asName: 'GOOGLE', holder: 'Google LLC' });
  assert.deepEqual(splitAsHolder('CLOUDFLARENET - Cloudflare, Inc.'), { asName: 'CLOUDFLARENET', holder: 'Cloudflare, Inc.' });
  assert.deepEqual(splitAsHolder('Example Networks Ltd without a short name'),
    { asName: 'Example Networks Ltd without a short name', holder: 'Example Networks Ltd without a short name' });
  assert.deepEqual(splitAsHolder('A-B - Org - with dash'), { asName: 'A-B', holder: 'Org - with dash' });
  assert.deepEqual(splitAsHolder(''), { asName: null, holder: null });
  assert.deepEqual(splitAsHolder(null), { asName: null, holder: null });
});

test('parsePrefixOverview: announced prefix, AS, RIR', () => {
  const r = parsePrefixOverview(PO_GITHUB);
  assert.equal(r.asn, 36459);
  assert.equal(r.asName, 'GITHUB');
  assert.equal(r.holder, 'GitHub, Inc.');
  assert.equal(r.prefix, '140.82.121.0/24');
  assert.equal(r.announced, true);
  assert.equal(r.rir, 'ARIN');
  assert.deepEqual(r.asns, [{ asn: 36459, holder: 'GITHUB - GitHub, Inc.' }]);
});

test('parsePrefixOverview: unannounced space, MOAS, RIR variants, errors', () => {
  const u = parsePrefixOverview(PO_UNANNOUNCED);
  assert.equal(u.asn, null);
  assert.equal(u.prefix, null); // bare IP echoed back is not a prefix
  assert.equal(u.announced, false);
  assert.equal(u.rir, null);

  const moas = parsePrefixOverview({
    status: 'ok',
    data: {
      announced: true, resource: '198.51.100.0/24',
      asns: [{ asn: 64500, holder: 'EXAMPLE-NET Example Networks Ltd' }, { asn: '64501', holder: '' }, { asn: 'x' }],
      block: { desc: 'RIPE NCC (Status: ALLOCATED)' }
    }
  });
  assert.equal(moas.asn, 64500);
  assert.equal(moas.rir, 'RIPE NCC');
  assert.deepEqual(moas.asns, [{ asn: 64500, holder: 'EXAMPLE-NET Example Networks Ltd' }, { asn: 64501, holder: null }]);

  assert.throws(() => parsePrefixOverview({ status: 'error', messages: [['error', 'bad resource']] }), /bad resource/);
  assert.throws(() => parsePrefixOverview(null), SyntaxError);
  assert.throws(() => parsePrefixOverview({ status: 'ok' }), SyntaxError);
});

test('parseGeoLite picks the best-covered location; empty strings become null', () => {
  assert.deepEqual(parseGeoLite(GEO_GITHUB), { country: 'DE', city: 'Frankfurt am Main' });
  const multi = {
    status: 'ok',
    data: {
      located_resources: [{
        locations: [
          { country: 'US', city: '', covered_percentage: 30 },
          { country: 'tr', city: 'Istanbul', covered_percentage: 70 }
        ]
      }]
    }
  };
  assert.deepEqual(parseGeoLite(multi), { country: 'TR', city: 'Istanbul' });
  assert.deepEqual(parseGeoLite({ status: 'ok', data: { located_resources: [] } }), { country: null, city: null });
  assert.deepEqual(parseGeoLite({ status: 'ok', data: { located_resources: [{ locations: [{ country: '', city: '' }] }] } }),
    { country: null, city: null });
});

test('parseIpwhois: success, reserved range, quota', () => {
  assert.deepEqual(parseIpwhois(IPWHO_GITHUB), {
    asn: 36459, holder: 'GitHub, Inc.', isp: 'GitHub, Inc.', country: 'DE', city: 'Frankfurt am Main'
  });
  assert.throws(() => parseIpwhois({ ip: '10.0.0.1', success: false, message: 'Reserved range' }), /Reserved range/);
  try {
    parseIpwhois({ success: false, message: 'You have reached the monthly limit' });
    assert.fail('should throw');
  } catch (err) {
    assert.equal(err.kind, 'rate-limit');
  }
  assert.deepEqual(parseIpwhois({ success: true, connection: {} }), { asn: null, holder: null, isp: null, country: null, city: null });
});

test('parseRipeReverseDns normalises names', () => {
  assert.deepEqual(parseRipeReverseDns({ status: 'ok', data: { result: ['dns.google.', 'DNS.google', 'bad name'] } }), ['dns.google']);
  assert.deepEqual(parseRipeReverseDns({ status: 'ok', data: { result: null, error: 'NXDOMAIN' } }), []);
});

test('parseReverseIpText: hosts, quota, errors, empty', () => {
  const ok = parseReverseIpText('www.b.com\na.com\nb.com\nA.com\n\nnot a host!\n');
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.domains, ['a.com', 'b.com', 'www.b.com']);
  assert.equal(ok.limited, false);

  const quota = parseReverseIpText('API count exceeded - Increase Quota with Membership');
  assert.deepEqual(quota, {
    ok: false, domains: [], error: 'API count exceeded - Increase Quota with Membership', limited: true, errorKind: 'rate-limit'
  });
  const err = parseReverseIpText('error check your search parameter');
  assert.equal(err.ok, false);
  assert.equal(err.limited, false);
  assert.equal(err.error, 'error check your search parameter');

  assert.deepEqual(parseReverseIpText('No DNS A records found for 1.2.3.4').domains, []);
  assert.equal(parseReverseIpText('No DNS A records found').ok, true);
  assert.equal(parseReverseIpText('').ok, true);
  assert.equal(parseReverseIpText('<html>oops</html>').ok, false);
  // hostsearch-style "host,ip" lines are tolerated
  assert.deepEqual(parseReverseIpText('x.example.com,1.2.3.4').domains, ['x.example.com']);
});

/* -------------------------------------------------------------------- */
/* createIpIntel().info                                                  */
/* -------------------------------------------------------------------- */

const RIPE_OK_ROUTES = {
  'prefix-overview': PO_GITHUB,
  'maxmind-geo-lite': GEO_GITHUB,
  'reverse-dns-ip': { status: 'ok', data: { result: ['lb-140-82-121-4-fra.github.com'] } }
};

test('info: private and invalid addresses make no requests', async () => {
  const f = mockFetch({});
  const intel = createIpIntel({ fetchImpl: f });
  const p = await intel.info('10.1.2.3');
  assert.equal(p.private, true);
  assert.equal(p.version, 4);
  assert.equal(p.error, null);
  assert.deepEqual(p.sources, []);
  const p6 = await intel.info('fe80::1%eth0');
  assert.equal(p6.private, true);
  assert.equal(p6.ip, 'fe80::1');
  const bad = await intel.info('999.1.1.1');
  assert.equal(bad.version, 0);
  assert.equal(bad.error, 'Invalid IP address');
  assert.equal(bad.errorKind, 'invalid');
  const none = await intel.info(undefined);
  assert.equal(none.version, 0);
  assert.equal(f.stats.calls.length, 0);
});

test('info: RIPEstat + DNS PTR, sourceapp on every RIPEstat URL', async () => {
  const log = [];
  const f = mockFetch(RIPE_OK_ROUTES, { log });
  const ptrCalls = [];
  const dns = { ptr: async (ip, { signal } = {}) => { ptrCalls.push({ ip, hasSignal: signal !== undefined }); return ['LB-140-82-121-4-FRA.github.com.']; } };
  const intel = createIpIntel({ fetchImpl: f, dns });
  const r = await intel.info('140.82.121.4');
  assert.equal(r.ip, '140.82.121.4');
  assert.equal(r.version, 4);
  assert.equal(r.private, false);
  assert.equal(r.provider, null);
  assert.deepEqual(r.ptr, ['lb-140-82-121-4-fra.github.com']);
  assert.equal(r.asn, 36459);
  assert.equal(r.asName, 'GITHUB');
  assert.equal(r.holder, 'GitHub, Inc.');
  assert.equal(r.prefix, '140.82.121.0/24');
  assert.equal(r.country, 'DE');
  assert.equal(r.city, 'Frankfurt am Main');
  assert.equal(r.rir, 'ARIN');
  assert.equal(r.announced, true);
  assert.deepEqual(r.sources, ['dns', 'ripestat']);
  assert.equal(r.error, null);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(ptrCalls.map((c) => c.ip), ['140.82.121.4']);
  assert.equal(log.length, 2); // no reverse-dns-ip (DNS client given), no ipwho.is
  for (const u of log) {
    assert.match(u, /^https:\/\/stat\.ripe\.net\/data\/[a-z-]+\/data\.json\?resource=140\.82\.121\.4&sourceapp=/);
    assert.ok(u.endsWith(`sourceapp=${RIPESTAT_SOURCEAPP}`));
  }
});

test('info: provider detection and IPv6 canonicalisation', async () => {
  const log = [];
  const f = mockFetch({
    'prefix-overview': { status: 'ok', data: { announced: true, asns: [{ asn: 13335, holder: 'CLOUDFLARENET - Cloudflare, Inc.' }], resource: '2606:4700::/44' } },
    'maxmind-geo-lite': { status: 'ok', data: { located_resources: [{ locations: [{ country: 'US', city: '' }] }] } },
    'reverse-dns-ip': { status: 'ok', data: { result: null } }
  }, { log });
  const intel = createIpIntel({ fetchImpl: f });
  const r = await intel.info('2606:4700:0000:0000:0000:0000:0000:1111');
  assert.equal(r.ip, '2606:4700::1111');
  assert.equal(r.version, 6);
  assert.equal(r.provider?.id, 'cloudflare');
  assert.equal(r.asName, 'CLOUDFLARENET');
  assert.equal(r.country, 'US');
  assert.equal(r.city, null);
  assert.deepEqual(r.ptr, []);
  assert.ok(log.every((u) => u.includes('resource=2606:4700::1111&')));
});

test('info: IPv4-mapped IPv6 is looked up as IPv4', async () => {
  const log = [];
  const intel = createIpIntel({ fetchImpl: mockFetch(RIPE_OK_ROUTES, { log }) });
  const r = await intel.info('::ffff:140.82.121.4');
  assert.equal(r.ip, '140.82.121.4');
  assert.equal(r.version, 4);
  assert.ok(log.every((u) => u.includes('resource=140.82.121.4&')));
});

test('info: without a DNS client, PTR comes from RIPEstat reverse-dns-ip', async () => {
  const log = [];
  const intel = createIpIntel({ fetchImpl: mockFetch(RIPE_OK_ROUTES, { log }) });
  const r = await intel.info('140.82.121.4');
  assert.deepEqual(r.ptr, ['lb-140-82-121-4-fra.github.com']);
  assert.deepEqual(r.sources, ['ripestat']);
  assert.ok(log.some((u) => u.includes('/reverse-dns-ip/')));
});

test('info: RIPEstat failure falls back to ipwho.is for missing fields only', async () => {
  const log = [];
  let poCalls = 0;
  const f = mockFetch({
    'prefix-overview': () => { poCalls += 1; return jsonResponse('upstream error', 502); },
    'maxmind-geo-lite': GEO_GITHUB,
    'ipwho.is': IPWHO_GITHUB
  }, { log });
  const intel = createIpIntel({ fetchImpl: f, dns: { ptr: async () => [] } });
  const r = await intel.info('140.82.121.4');
  assert.equal(poCalls, 2, 'one retry on 5xx');
  assert.equal(r.asn, 36459);
  assert.equal(r.holder, 'GitHub, Inc.');
  assert.equal(r.asName, null);
  assert.equal(r.country, 'DE'); // from RIPEstat, kept
  assert.deepEqual(r.sources, ['dns', 'ripestat', 'ipwhois']);
  assert.equal(r.error, null);
  assert.equal(r.errors.length, 1);
  assert.equal(r.errors[0].source, 'ripestat');
  assert.equal(r.errors[0].errorKind, 'http');
  assert.ok(log.some((u) => u === 'https://ipwho.is/140.82.121.4'));
});

test('info: unannounced space does not call ipwho.is', async () => {
  const log = [];
  const f = mockFetch({
    'prefix-overview': PO_UNANNOUNCED,
    'maxmind-geo-lite': { status: 'ok', data: { located_resources: [] } }
  }, { log });
  const intel = createIpIntel({ fetchImpl: f, dns: { ptr: async () => [] } });
  const r = await intel.info('192.0.2.1');
  assert.equal(r.announced, false);
  assert.equal(r.asn, null);
  assert.equal(r.error, null);
  assert.ok(!log.some((u) => u.includes('ipwho.is')));
});

test('info: total failure is reported, not thrown, and not cached', async () => {
  let calls = 0;
  const f = mockFetch({
    'stat.ripe.net': () => { calls += 1; return new TypeError('Failed to fetch'); },
    'ipwho.is': () => { calls += 1; return { success: false, message: 'Reserved range' }; }
  });
  const intel = createIpIntel({ fetchImpl: f, dns: { ptr: async () => { throw new Error('dns down'); } }, retries: 0 });
  const r = await intel.info('8.8.8.8');
  assert.ok(r.error);
  assert.match(r.error, /ripestat/);
  assert.equal(r.errorKind, 'unknown'); // first failure: the PTR lookup's plain Error
  assert.deepEqual(r.errors.map((e) => e.source), ['ptr', 'ripestat', 'ripestat-geo', 'ipwhois']);
  assert.equal(r.errors[1].errorKind, 'network');
  const before = calls;
  await intel.info('8.8.8.8');
  assert.ok(calls > before, 'failures are not cached');
});

test('info: results are cached; noCache and clearCache refetch', async () => {
  const log = [];
  const intel = createIpIntel({ fetchImpl: mockFetch(RIPE_OK_ROUTES, { log }), dns: { ptr: async () => [] } });
  const a = await intel.info('140.82.121.4');
  const n = log.length;
  const b = await intel.info('140.82.121.4');
  assert.equal(log.length, n);
  assert.deepEqual(b, a);
  b.ptr.push('mutated');
  assert.deepEqual((await intel.info('140.82.121.4')).ptr, [], 'callers get copies');
  await intel.info('140.82.121.4', { noCache: true });
  assert.equal(log.length, n * 2);
  intel.clearCache();
  await intel.info('140.82.121.4');
  assert.equal(log.length, n * 3);
});

test('info: concurrent calls for one IP share a single lookup', async () => {
  const log = [];
  const intel = createIpIntel({ fetchImpl: mockFetch(RIPE_OK_ROUTES, { log, delayMs: 20 }), dns: { ptr: async () => [] } });
  const [a, b, c] = await Promise.all([intel.info('140.82.121.4'), intel.info('140.82.121.4'), intel.info('140.82.121.4')]);
  assert.equal(log.length, 2);
  assert.equal(a.asn, 36459);
  assert.deepEqual(a, b);
  assert.deepEqual(b, c);
});

test('info: an aborting caller does not break other waiters', async () => {
  const log = [];
  const intel = createIpIntel({ fetchImpl: mockFetch(RIPE_OK_ROUTES, { log, delayMs: 30 }), dns: { ptr: async () => [] } });
  const ctl = new AbortController();
  const first = intel.info('140.82.121.4', { signal: ctl.signal });
  const second = intel.info('140.82.121.4');
  setTimeout(() => ctl.abort(), 5);
  await assert.rejects(first, { name: 'AbortError' });
  const r = await second;
  assert.equal(r.asn, 36459);
  assert.equal(r.error, null);
});

test('info: pre-aborted signal rejects with AbortError', async () => {
  const intel = createIpIntel({ fetchImpl: mockFetch(RIPE_OK_ROUTES) });
  await assert.rejects(intel.info('8.8.8.8', { signal: AbortSignal.abort() }), { name: 'AbortError' });
  await assert.rejects(intel.reverseIp('8.8.8.8', { signal: AbortSignal.abort() }), { name: 'AbortError' });
});

test('info: HTTP concurrency is bounded by the limiter', async () => {
  const f = mockFetch(RIPE_OK_ROUTES, { delayMs: 15 });
  const intel = createIpIntel({ fetchImpl: f, dns: { ptr: async () => [] }, concurrency: 2 });
  const ips = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '140.82.121.4', '185.199.108.153'];
  const results = await Promise.all(ips.map((ip) => intel.info(ip)));
  assert.equal(results.length, 5);
  assert.ok(f.stats.maxActive <= 2, `max active ${f.stats.maxActive}`);
  assert.equal(f.stats.calls.length, 10);
});

test('info: ipwho.is fallback can be disabled', async () => {
  const log = [];
  const f = mockFetch({ 'stat.ripe.net': () => jsonResponse('x', 500) }, { log });
  const intel = createIpIntel({ fetchImpl: f, ipwhois: false, retries: 0, dns: { ptr: async () => ['a.example'] } });
  const r = await intel.info('8.8.8.8');
  assert.deepEqual(r.ptr, ['a.example']);
  assert.equal(r.error, null); // PTR was learned
  assert.ok(!log.some((u) => u.includes('ipwho')));
});

/* -------------------------------------------------------------------- */
/* reverseIp                                                            */
/* -------------------------------------------------------------------- */

test('reverseIp: parses hosts and caches successful answers', async () => {
  const log = [];
  const f = mockFetch({ reverseiplookup: () => new Response('b.example.com\na.example.com\n', { status: 200 }) }, { log });
  const intel = createIpIntel({ fetchImpl: f });
  const r = await intel.reverseIp('140.82.121.4');
  assert.deepEqual(r, { ok: true, domains: ['a.example.com', 'b.example.com'], error: null, limited: false, errorKind: null });
  assert.equal(log[0], 'https://api.hackertarget.com/reverseiplookup/?q=140.82.121.4');
  await intel.reverseIp('140.82.121.4');
  assert.equal(log.length, 1);
});

test('reverseIp: quota text and HTTP 429 → limited; errors are not cached', async () => {
  let n = 0;
  const f = mockFetch({
    reverseiplookup: () => {
      n += 1;
      return n === 1
        ? new Response('API count exceeded - Increase Quota with Membership', { status: 200 })
        : new Response('Too Many Requests', { status: 429 });
    }
  });
  const intel = createIpIntel({ fetchImpl: f });
  const a = await intel.reverseIp('8.8.8.8');
  assert.equal(a.ok, false);
  assert.equal(a.limited, true);
  const b = await intel.reverseIp('8.8.8.8');
  assert.equal(b.ok, false);
  assert.equal(b.limited, true);
  assert.equal(b.errorKind, 'rate-limit');
  assert.equal(n, 2);
});

test('reverseIp: private / invalid IPs, network errors, api key', async () => {
  const log = [];
  const f = mockFetch({ reverseiplookup: () => new TypeError('Failed to fetch') }, { log });
  const intel = createIpIntel({ fetchImpl: f, hackertargetApiKey: 'k&y' });
  assert.equal((await intel.reverseIp('192.168.1.1')).ok, false);
  assert.equal((await intel.reverseIp('nope')).error, 'Invalid IP address');
  assert.equal(log.length, 0);
  const r = await intel.reverseIp('2001:4860:4860::8888');
  assert.equal(r.ok, false);
  assert.equal(r.limited, false);
  assert.equal(r.errorKind, 'network');
  assert.equal(log[0], 'https://api.hackertarget.com/reverseiplookup/?q=2001:4860:4860::8888&apikey=k%26y');
});
