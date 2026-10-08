// Unit tests for assets/js/lib/doh.js — no network: every DoH server is a mock
// fetchImpl that decodes the RFC 8484 `?dns=` query and answers with real
// wire-format messages (dnswire.encodeMessage) or captured fixtures.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DohClient, hostResolutionFrom, followCnames, detectWildcardDeep } from '../../assets/js/lib/doh.js';
import { RESOLVERS, DEFAULT_CHAIN } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { AbortError } from '../../assets/js/lib/util.js';

/* ------------------------------------------------------------------------ */
/* Mock DoH infrastructure                                                  */
/* ------------------------------------------------------------------------ */

const FIX_DIR = new URL('../fixtures/dns/', import.meta.url);
const fixtureBytes = (id) => new Uint8Array(readFileSync(new URL(`${id}.bin`, FIX_DIR)));

const SOA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };

function resolverIdOf(url) {
  const r = RESOLVERS.find((x) => url.startsWith(`${x.url}?`) || url.startsWith(`${x.url}&`));
  return r ? r.id : new URL(url).host;
}

/**
 * Mock fetch. `handler({ resolver, question, query, url, init })` returns a
 * Response, or `{ rcode, answers, authorities, edns, ad, qr, question }` which
 * is encoded as a real DNS message, or throws (network error).
 */
function mockFetch(handler) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const query = decodeMessage(base64UrlDecode(u.searchParams.get('dns')));
    const question = query.questions[0];
    const resolver = resolverIdOf(url);
    const call = { url, init, resolver, name: question.name, type: question.type, query };
    calls.push(call);
    const out = await handler(call);
    if (out instanceof Response) return out;
    if (out && out.raw) return out.raw; // hand-made Response-like object
    const bytes = encodeMessage({
      id: 0,
      flags: { qr: out.qr !== false, rd: true, ra: true, ad: !!out.ad, cd: query.flags.cd },
      rcode: out.rcode || 'NOERROR',
      questions: [out.question || { name: question.name, type: question.type }],
      answers: out.answers || [],
      authorities: out.authorities || [],
      edns: out.edns === undefined ? {} : out.edns
    });
    return new Response(bytes, { status: 200, headers: { 'content-type': 'application/dns-message' } });
  };
  return { fetchImpl, calls };
}

/** Tiny authoritative-zone emulator: CNAME chasing, wildcards, NXDOMAIN vs NODATA. */
function zoneAnswer(zone, name, type) {
  const answers = [];
  let current = name;
  for (let hop = 0; hop < 12; hop += 1) {
    let node = zone[current];
    let owner = current;
    if (!node) {
      const parent = current.split('.').slice(1).join('.');
      const exists = Object.keys(zone).some((k) => k.endsWith(`.${current}`) && !k.startsWith('*.'));
      if (!exists && zone[`*.${parent}`]) node = zone[`*.${parent}`];
      else return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers, authorities: [{ name: 'example.com', type: 'SOA', ttl: 600, data: SOA }] };
      owner = current;
    }
    const ttl = node.ttl ?? 300;
    if (node.CNAME && type !== 'CNAME') {
      answers.push({ name: owner, type: 'CNAME', ttl, data: node.CNAME });
      current = node.CNAME;
      continue;
    }
    for (const data of node[type] || []) answers.push({ name: owner, type, ttl, data });
    return {
      rcode: 'NOERROR',
      answers,
      authorities: answers.length ? [] : [{ name: 'example.com', type: 'SOA', ttl: 600, data: SOA }]
    };
  }
  return { rcode: 'SERVFAIL', answers: [] };
}

const ZONE = {
  'example.com': { A: ['93.184.216.34'], AAAA: ['2606:2800:220:1:248:1893:25c8:1946'], ttl: 3600 },
  'www.example.com': { CNAME: 'edge.cdn.example.net', ttl: 1200 },
  'edge.cdn.example.net': { CNAME: 'e1.cdn.example.net', ttl: 60 },
  'e1.cdn.example.net': { A: ['104.16.1.1', '104.16.1.2', '104.16.1.1'], AAAA: ['2606:4700::1'], ttl: 30 },
  'dangling.example.com': { CNAME: 'gone.herokuapp.com' },
  'loop1.example.com': { CNAME: 'loop2.example.com' },
  'loop2.example.com': { CNAME: 'loop1.example.com' },
  'v6only.example.com': { AAAA: ['2001:db8::10'] },
  'deep.sub.example.com': { A: ['10.0.0.5'] },
  '*.wild.example.org': { A: ['198.51.100.7'] },
  '*.cnw.example.org': { CNAME: 'lb.example.net' },
  'lb.example.net': { A: ['203.0.113.9'] },
  '8.8.8.8.in-addr.arpa': { PTR: ['dns.google'] },
  '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa': { PTR: ['host6.example.com'] }
};

const zoneFetch = (zone = ZONE) => mockFetch(({ name, type }) => zoneAnswer(zone, name, type));

const fast = (extra = {}) => ({ baseDelayMs: 1, maxDelayMs: 5, timeoutMs: 2000, ...extra });

/* ------------------------------------------------------------------------ */
/* query()                                                                  */
/* ------------------------------------------------------------------------ */

describe('DohClient.query', () => {
  test('sends an RFC 8484 GET with id 0, RD, accept header and decodes the answer', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const res = await dns.query('Example.COM.', 'a');
    assert.equal(res.ok, true);
    assert.equal(res.rcode, 'NOERROR');
    assert.equal(res.name, 'example.com');
    assert.equal(res.type, 'A');
    assert.equal(res.resolver, 'cloudflare');
    assert.equal(res.error, null);
    assert.equal(res.errorKind, null);
    assert.deepEqual(res.answers.map((a) => a.data), ['93.184.216.34']);
    assert.equal(res.ecs, null);
    assert.deepEqual(res.ede, []);
    assert.equal(typeof res.elapsedMs, 'number');
    assert.equal(res.cached, false);
    assert.equal(calls.length, 1);
    const call = calls[0];
    assert.ok(call.url.startsWith('https://cloudflare-dns.com/dns-query?dns='));
    assert.ok(!/[+/=]/.test(new URL(call.url).searchParams.get('dns')), 'base64url without padding');
    assert.equal(call.init.headers.accept, 'application/dns-message');
    assert.equal(call.init.method, 'GET');
    assert.equal(call.query.id, 0);
    assert.equal(call.query.flags.rd, true);
    assert.equal(call.query.flags.cd, false);
    assert.equal(call.query.edns.dnssecOk, false);
    assert.equal(call.name, 'example.com');
  });

  test('passes DO / CD bits and ECS; exposes the echoed ECS scope, EDE and NSID', async () => {
    const { fetchImpl, calls } = mockFetch(({ query }) => ({
      answers: [{ name: 'www.amazon.com', type: 'A', ttl: 60, data: '65.9.93.124' }],
      edns: { ecs: { address: query.edns.ecs.address, sourcePrefix: 24, scopePrefix: 20 }, ede: [{ code: 3, text: 'stale' }], nsid: 'edge03' },
      ad: true
    }));
    const dns = new DohClient({ fetchImpl, ...fast() });
    const res = await dns.query('www.amazon.com', 'A', { resolver: 'google', ecs: '198.51.100.34/24', dnssec: true, cd: true });
    const q = calls[0].query;
    assert.ok(calls[0].url.startsWith('https://dns.google/dns-query?dns='));
    assert.equal(q.edns.dnssecOk, true);
    assert.equal(q.flags.cd, true);
    assert.equal(q.edns.ecs.subnet, '198.51.100.0/24', 'host bits zeroed');
    assert.equal(res.ecs.scopePrefix, 20);
    assert.equal(res.ecs.subnet, '198.51.100.0/24');
    assert.deepEqual(res.ede.map((e) => e.code), [3]);
    assert.equal(res.nsid, 'edge03');
    assert.equal(res.ad, true);
    assert.equal(res.flags.ad, true);
  });

  test('decodes a real captured response (Cloudflare, CNAME chain)', async () => {
    const { fetchImpl } = mockFetch(() => new Response(fixtureBytes('cf-a-cname-chain')));
    const dns = new DohClient({ fetchImpl, ...fast() });
    const res = await dns.query('www.microsoft.com', 'A', { resolver: 'cloudflare' });
    assert.equal(res.ok, true);
    assert.deepEqual(res.answers.map((a) => a.type), ['CNAME', 'CNAME', 'A']);
  });

  test('invalid names, unknown types and unknown resolvers fail without network', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const long = `${'a'.repeat(64)}.example.com`;
    const r1 = await dns.query(long, 'A');
    assert.equal(r1.ok, false);
    assert.equal(r1.errorKind, 'parse');
    assert.match(r1.error, /Invalid query/);
    const r2 = await dns.query('example.com', 'NOPE');
    assert.equal(r2.ok, false);
    assert.equal(r2.errorKind, 'parse');
    const r3 = await dns.query('example.com', 'A', { resolver: 'nonexistent' });
    assert.equal(r3.ok, false);
    assert.match(r3.error, /Unknown resolver/);
    assert.equal(r3.resolver, 'nonexistent');
    assert.equal(calls.length, 0);
    assert.equal(dns.stats().failures, 3);
  });

  test('IDN names are queried in punycode', async () => {
    const { fetchImpl, calls } = mockFetch(() => ({ rcode: 'NXDOMAIN' }));
    const dns = new DohClient({ fetchImpl, ...fast() });
    const res = await dns.query('Bücher.example', 'A');
    assert.equal(res.name, 'xn--bcher-kva.example');
    assert.equal(calls[0].name, 'xn--bcher-kva.example');
    assert.equal(res.rcode, 'NXDOMAIN');
  });

  test('unknown numeric types are sent and reported as TYPEnnn', async () => {
    const { fetchImpl, calls } = mockFetch(() => ({ answers: [] }));
    const dns = new DohClient({ fetchImpl, ...fast() });
    const res = await dns.query('example.com', 65280);
    assert.equal(res.type, 'TYPE65280');
    assert.equal(calls[0].query.questions[0].typeNum, 65280);
  });
});

/* ------------------------------------------------------------------------ */
/* Failover, retries, timeouts                                              */
/* ------------------------------------------------------------------------ */

describe('failover and retries', () => {
  test('network error on the first resolver → next in chain', async () => {
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') throw new TypeError('Failed to fetch');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const res = await dns.query('example.com');
    assert.equal(res.ok, true);
    assert.equal(res.resolver, 'google');
    assert.deepEqual(calls.map((c) => c.resolver), ['cloudflare', 'google']);
    assert.deepEqual(res.attempts.map((a) => [a.resolver, a.ok]), [['cloudflare', false], ['google', true]]);
    assert.equal(res.attempts[0].errorKind, 'network');
    const s = dns.stats();
    assert.equal(s.byResolver.cloudflare.fail, 1);
    assert.equal(s.byResolver.google.ok, 1);
    assert.equal(s.failures, 0);
  });

  for (const status of [400, 415, 429, 500, 502, 503]) {
    test(`HTTP ${status} is a transport error → failover`, async () => {
      const { fetchImpl } = mockFetch(({ resolver, name, type }) => {
        if (resolver === 'cloudflare') return new Response('nope', { status });
        return zoneAnswer(ZONE, name, type);
      });
      const dns = new DohClient({ fetchImpl, ...fast() });
      const res = await dns.query('example.com');
      assert.equal(res.resolver, 'google');
      assert.equal(res.attempts[0].errorKind, status === 429 ? 'rate-limit' : 'http');
      assert.match(res.attempts[0].error, new RegExp(`HTTP ${status}`));
    });
  }

  test('SERVFAIL / REFUSED fail over; when everyone fails the first DNS answer is returned', async () => {
    const { fetchImpl } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') return { rcode: 'SERVFAIL', edns: { ede: [{ code: 9, text: 'no SEP' }] } };
      if (resolver === 'google') return { rcode: 'REFUSED' };
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const ok = await dns.query('example.com');
    assert.equal(ok.resolver, DEFAULT_CHAIN[2]);
    assert.equal(ok.rcode, 'NOERROR');

    const { fetchImpl: allFail, calls } = mockFetch(({ resolver }) => (resolver === DEFAULT_CHAIN[2]
      ? Promise.reject(new TypeError('Failed to fetch'))
      : { rcode: 'SERVFAIL', edns: { ede: [{ code: 6, text: 'bogus' }] } }));
    const dns2 = new DohClient({ fetchImpl: allFail, ...fast() });
    const bogus = await dns2.query('dnssec-failed.org');
    assert.equal(bogus.ok, true);
    assert.equal(bogus.rcode, 'SERVFAIL');
    assert.equal(bogus.resolver, 'cloudflare');
    assert.equal(bogus.ede[0].code, 6);
    // one pass only: a DNS answer exists, so the transport failure of the third resolver is not retried
    assert.deepEqual(calls.map((c) => c.resolver), [...DEFAULT_CHAIN]);
  });

  test('explicit resolver: no failover, SERVFAIL returned as-is', async () => {
    const { fetchImpl, calls } = mockFetch(() => ({ rcode: 'SERVFAIL' }));
    const dns = new DohClient({ fetchImpl, ...fast() });
    const res = await dns.query('example.com', 'A', { resolver: 'iij' });
    assert.equal(res.rcode, 'SERVFAIL');
    assert.equal(res.resolver, 'iij');
    assert.equal(calls.length, 1);
    assert.ok(calls[0].url.startsWith('https://public.dns.iij.jp/dns-query?dns='));
  });

  test('explicit resolver: transient errors are retried (retries+1 attempts), then ok=false', async () => {
    const { fetchImpl, calls } = mockFetch(() => new Response('busy', { status: 503 }));
    const dns = new DohClient({ fetchImpl, retries: 2, ...fast() });
    const res = await dns.query('example.com', 'A', { resolver: 'cznic' });
    assert.equal(res.ok, false);
    assert.equal(res.rcode, null);
    assert.equal(res.errorKind, 'http');
    assert.match(res.error, /HTTP 503/);
    assert.equal(res.resolver, 'cznic');
    assert.equal(calls.length, 3);
    assert.equal(dns.stats().failures, 1);
  });

  test('non-retryable errors (HTTP 400, malformed body) are not retried', async () => {
    const { fetchImpl, calls } = mockFetch(() => new Response('bad request', { status: 400 }));
    const dns = new DohClient({ fetchImpl, retries: 3, ...fast() });
    const res = await dns.query('example.com', 'A', { resolver: 'seby' });
    assert.equal(res.ok, false);
    assert.equal(calls.length, 1);

    const { fetchImpl: html, calls: c2 } = mockFetch(() => new Response('<html>captive portal</html>'));
    const dns2 = new DohClient({ fetchImpl: html, retries: 3, ...fast() });
    const r2 = await dns2.query('example.com', 'A', { resolver: 'seby' });
    assert.equal(r2.ok, false);
    assert.equal(r2.errorKind, 'parse');
    assert.equal(c2.length, 1);
  });

  test('chain: second pass retries only the retryable failures, with backoff', async () => {
    let round = 0;
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') round += 1;
      if (resolver === 'google') return new Response('', { status: 400 });
      if (round < 2) return new Response('', { status: 502 });
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, retries: 1, ...fast() });
    const res = await dns.query('example.com');
    assert.equal(res.ok, true);
    assert.equal(res.resolver, 'cloudflare');
    assert.deepEqual(calls.map((c) => c.resolver), [...DEFAULT_CHAIN, 'cloudflare']);
  });

  test('all transport failures → ok=false with the last error; no throw', async () => {
    const { fetchImpl, calls } = mockFetch(() => { throw new TypeError('offline'); });
    const dns = new DohClient({ fetchImpl, retries: 1, ...fast() });
    const res = await dns.query('example.com');
    assert.equal(res.ok, false);
    assert.equal(res.errorKind, 'network');
    assert.equal(res.error, 'offline');
    assert.equal(calls.length, 8, '4 resolvers × 2 passes');
    assert.equal(res.attempts.length, 8);
  });

  test('timeouts (fetch that never answers) → TimeoutError → failover', async () => {
    const { fetchImpl } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') return new Promise(() => {}); // hangs, ignores the signal
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, timeoutMs: 40, baseDelayMs: 1 });
    const t0 = Date.now();
    const res = await dns.query('example.com');
    assert.equal(res.resolver, 'google');
    assert.equal(res.attempts[0].errorKind, 'timeout');
    assert.ok(Date.now() - t0 < 1500);
  });

  test('a stalled body read is covered by the timeout too', async () => {
    const { fetchImpl } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') {
        return { raw: { ok: true, status: 200, headers: new Headers(), arrayBuffer: () => new Promise(() => {}) } };
      }
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, timeoutMs: 40, baseDelayMs: 1 });
    const res = await dns.query('example.com');
    assert.equal(res.resolver, 'google');
    assert.equal(res.attempts[0].errorKind, 'timeout');
  });

  test('answers for a different question / non-responses are rejected (parse) → failover', async () => {
    const { fetchImpl } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') return { question: { name: 'evil.example', type: 'A' }, answers: [{ name: 'evil.example', type: 'A', data: '6.6.6.6' }] };
      if (resolver === 'google') return { qr: false };
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const res = await dns.query('example.com');
    assert.equal(res.resolver, DEFAULT_CHAIN[2]);
    assert.deepEqual(res.attempts.slice(0, 2).map((a) => a.errorKind), ['parse', 'parse']);
  });

  test('circuit breaker: a resolver failing 3 times in a row is tried last for a while', async () => {
    let now = 1000;
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') throw new TypeError('blocked');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, cache: false, now: () => now, ...fast() });
    for (let i = 0; i < 3; i += 1) await dns.query(`h${i}.example.com`);
    assert.equal(dns.stats().byResolver.cloudflare.down, true);
    calls.length = 0;
    const res = await dns.query('example.com');
    assert.equal(res.resolver, 'google');
    assert.deepEqual(calls.map((c) => c.resolver), ['google'], 'cloudflare skipped while down');
    now += 31000; // cooldown elapsed
    calls.length = 0;
    await dns.query('example.com');
    assert.deepEqual(calls.map((c) => c.resolver), ['cloudflare', 'google']);
  });

  test('custom chain objects and setChain()', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const custom = { id: 'lab', url: 'https://doh.lab.example/dns-query?token=x' };
    const dns = new DohClient({ fetchImpl, chain: [custom, 'google'], ...fast() });
    assert.deepEqual(dns.chain, ['lab', 'google']);
    await dns.query('example.com');
    assert.ok(calls[0].url.startsWith('https://doh.lab.example/dns-query?token=x&dns='));
    dns.setChain(['dnssb']);
    assert.deepEqual(dns.chain, ['dnssb']);
    assert.throws(() => dns.setChain(['nope']), TypeError);
    assert.throws(() => new DohClient({ chain: [] }), TypeError);
    assert.deepEqual(new DohClient({ fetchImpl }).chain, [...DEFAULT_CHAIN]);
  });
});

/* ------------------------------------------------------------------------ */
/* Cache, de-duplication, concurrency                                       */
/* ------------------------------------------------------------------------ */

describe('cache and in-flight de-duplication', () => {
  test('repeat queries are served from the cache; noCache refetches', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const a = await dns.query('example.com');
    const b = await dns.query('EXAMPLE.com.');
    assert.equal(calls.length, 1);
    assert.equal(b.cached, true);
    assert.deepEqual(b.answers, a.answers);
    assert.equal(dns.stats().cacheHits, 1);
    assert.equal(dns.stats().queries, 2);
    const c = await dns.query('example.com', 'A', { noCache: true });
    assert.equal(c.cached, false);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].init.cache, 'no-store');
  });

  test('cache key includes type, resolver, ECS, DO and CD', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    await dns.query('example.com', 'A');
    await dns.query('example.com', 'AAAA');
    await dns.query('example.com', 'A', { resolver: 'google' });
    await dns.query('example.com', 'A', { resolver: 'google', ecs: '1.2.3.0/24' });
    await dns.query('example.com', 'A', { resolver: 'google', ecs: '5.6.7.0/24' });
    await dns.query('example.com', 'A', { dnssec: true });
    await dns.query('example.com', 'A', { cd: true });
    assert.equal(calls.length, 7);
    await dns.query('example.com', 'A', { resolver: 'google', ecs: '5.6.7.0/24' });
    assert.equal(calls.length, 7);
  });

  test('entries expire with the (clamped) TTL; negative answers use the SOA minimum', async () => {
    let now = 0;
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, now: () => now, ...fast() });
    await dns.query('e1.cdn.example.net'); // TTL 30
    now = 29_000;
    await dns.query('e1.cdn.example.net');
    assert.equal(calls.length, 1);
    now = 31_000;
    await dns.query('e1.cdn.example.net');
    assert.equal(calls.length, 2);

    await dns.query('nope.example.com'); // NXDOMAIN, SOA ttl 600 / minimum 60
    now += 59_000;
    await dns.query('nope.example.com');
    assert.equal(calls.length, 3);
    now += 2000;
    await dns.query('nope.example.com');
    assert.equal(calls.length, 4);
  });

  test('transport failures are never cached; cache:false disables caching', async () => {
    let fail = true;
    const { fetchImpl, calls } = mockFetch(({ name, type }) => {
      if (fail) throw new TypeError('down');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, retries: 0, ...fast() });
    assert.equal((await dns.query('example.com', 'A', { resolver: 'google' })).ok, false);
    fail = false;
    assert.equal((await dns.query('example.com', 'A', { resolver: 'google' })).ok, true);
    assert.equal(calls.length, 2);

    const { fetchImpl: f2, calls: c2 } = zoneFetch();
    const nocache = new DohClient({ fetchImpl: f2, cache: false, ...fast() });
    await nocache.query('example.com');
    await nocache.query('example.com');
    assert.equal(c2.length, 2);
  });

  test('a custom cache object can be shared between clients', async () => {
    const store = new Map();
    const cache = { get: (k) => store.get(k), set: (k, v) => store.set(k, v) };
    const { fetchImpl, calls } = zoneFetch();
    await new DohClient({ fetchImpl, cache, ...fast() }).query('example.com');
    const res = await new DohClient({ fetchImpl, cache, ...fast() }).query('example.com');
    assert.equal(calls.length, 1);
    assert.equal(res.cached, true);
  });

  test('identical concurrent queries share one request', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const { fetchImpl, calls } = mockFetch(async ({ name, type }) => {
      await gate;
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const p = Promise.all([dns.query('example.com'), dns.query('example.com'), dns.query('example.com')]);
    await new Promise((r) => setTimeout(r, 5));
    release();
    const results = await p;
    assert.equal(calls.length, 1);
    assert.ok(results.every((r) => r.ok && r.answers[0].data === '93.184.216.34'));
    assert.notEqual(results[0], results[1], 'each caller gets its own object');
    assert.equal(dns.stats().shared, 2);
  });

  test('the limiter caps parallel requests; setConcurrency changes it', async () => {
    let active = 0;
    let peak = 0;
    const { fetchImpl } = mockFetch(async ({ name, type }) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 3));
      active -= 1;
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, concurrency: 3, ...fast() });
    await Promise.all(Array.from({ length: 20 }, (_, i) => dns.query(`n${i}.example.com`)));
    assert.equal(peak, 3);
    peak = 0;
    dns.setConcurrency(7);
    await Promise.all(Array.from({ length: 30 }, (_, i) => dns.query(`m${i}.example.com`)));
    assert.equal(peak, 7);
  });

  test('stats() shape', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    await dns.query('example.com');
    await dns.query('example.com');
    const s = dns.stats();
    assert.equal(s.queries, 2);
    assert.equal(s.cacheHits, 1);
    assert.equal(s.failures, 0);
    assert.equal(s.requests, 1);
    assert.equal(s.byResolver.cloudflare.ok, 1);
    assert.equal(s.byResolver.cloudflare.fail, 0);
    assert.equal(typeof s.byResolver.cloudflare.avgMs, 'number');
    dns.clearCache();
    await dns.query('example.com');
    assert.equal(dns.stats().requests, 2);
  });
});

/* ------------------------------------------------------------------------ */
/* Cancellation                                                             */
/* ------------------------------------------------------------------------ */

describe('cancellation', () => {
  test('an already-aborted signal rejects immediately without fetching', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(dns.query('example.com', 'A', { signal: ctl.signal }), (e) => e instanceof AbortError);
    await assert.rejects(dns.resolveHost('example.com', { signal: ctl.signal }), (e) => e.name === 'AbortError');
    await assert.rejects(dns.detectWildcard('example.com', { signal: ctl.signal }), (e) => e.name === 'AbortError');
    await assert.rejects(dns.ptr('8.8.8.8', { signal: ctl.signal }), (e) => e.name === 'AbortError');
    assert.equal(calls.length, 0);
  });

  test('aborting during a hanging request rejects promptly with AbortError and aborts the fetch', async () => {
    let seenSignal = null;
    const { fetchImpl } = mockFetch(({ init }) => {
      seenSignal = init.signal;
      return new Promise(() => {});
    });
    const dns = new DohClient({ fetchImpl, timeoutMs: 60_000 });
    const ctl = new AbortController();
    const p = dns.query('example.com', 'A', { signal: ctl.signal });
    setTimeout(() => ctl.abort(), 10);
    const t0 = Date.now();
    await assert.rejects(p, (e) => e instanceof AbortError);
    assert.ok(Date.now() - t0 < 1000);
    assert.equal(seenSignal.aborted, true);
  });

  test('abort reasons that are timeouts are still reported as AbortError', async () => {
    const { fetchImpl } = mockFetch(() => new Promise(() => {}));
    const dns = new DohClient({ fetchImpl, timeoutMs: 60_000 });
    await assert.rejects(dns.query('example.com', 'A', { signal: AbortSignal.timeout(15) }), (e) => e instanceof AbortError);
  });

  test('aborting during backoff between passes rejects', async () => {
    const { fetchImpl } = mockFetch(() => new Response('', { status: 503 }));
    const dns = new DohClient({ fetchImpl, retries: 3, baseDelayMs: 5000, maxDelayMs: 5000 });
    const ctl = new AbortController();
    const p = dns.query('example.com', 'A', { signal: ctl.signal });
    setTimeout(() => ctl.abort(), 20);
    await assert.rejects(p, (e) => e instanceof AbortError);
  });

  test('shared in-flight work survives one caller aborting; aborted when all callers leave', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const signals = [];
    const { fetchImpl, calls } = mockFetch(async ({ init, name, type }) => {
      signals.push(init.signal);
      await gate;
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const c1 = new AbortController();
    const p1 = dns.query('example.com', 'A', { signal: c1.signal });
    const p2 = dns.query('example.com', 'A');
    await new Promise((r) => setTimeout(r, 5));
    c1.abort();
    await assert.rejects(p1, (e) => e instanceof AbortError);
    assert.equal(signals[0].aborted, false);
    release();
    const r2 = await p2;
    assert.equal(r2.ok, true);
    assert.equal(calls.length, 1);

    // both callers abort → the underlying request is cancelled
    const sigs = [];
    const { fetchImpl: hang } = mockFetch(({ init }) => { sigs.push(init.signal); return new Promise(() => {}); });
    const dns2 = new DohClient({ fetchImpl: hang, timeoutMs: 60_000 });
    const a = new AbortController();
    const b = new AbortController();
    const q1 = dns2.query('example.com', 'A', { signal: a.signal });
    const q2 = dns2.query('example.com', 'A', { signal: b.signal });
    await new Promise((r) => setTimeout(r, 5));
    a.abort();
    await assert.rejects(q1);
    assert.equal(sigs[0].aborted, false);
    b.abort();
    await assert.rejects(q2);
    assert.equal(sigs[0].aborted, true);
    assert.equal(dns2.stats().pending, 0);
    // a new identical query starts fresh work instead of joining the cancelled one
    const q3 = dns2.query('example.com', 'A', { signal: AbortSignal.timeout(20) });
    await assert.rejects(q3, (e) => e instanceof AbortError);
    assert.equal(sigs.length, 2);
    assert.equal(sigs[1].aborted, true);
  });
});

/* ------------------------------------------------------------------------ */
/* resolveHost / detectWildcard / ptr                                       */
/* ------------------------------------------------------------------------ */

describe('resolveHost', () => {
  test('A + AAAA concurrently, CNAME chain in order, addresses of the final target, min TTL', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const r = await dns.resolveHost('WWW.example.com');
    assert.equal(r.name, 'www.example.com');
    assert.equal(r.status, 'NOERROR');
    assert.deepEqual(r.cnames, ['edge.cdn.example.net', 'e1.cdn.example.net']);
    assert.deepEqual(r.ipv4, ['104.16.1.1', '104.16.1.2'], 'de-duplicated, answer order');
    assert.deepEqual(r.ipv6, ['2606:4700::1']);
    assert.equal(r.ttl, 30);
    assert.equal(r.resolver, 'cloudflare');
    assert.equal(r.error, null);
    assert.deepEqual(calls.map((c) => c.type).sort(), ['A', 'AAAA']);
  });

  test('NXDOMAIN, dangling CNAME, NODATA, IPv6-only', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const nx = await dns.resolveHost('missing.example.com');
    assert.equal(nx.status, 'NXDOMAIN');
    assert.deepEqual([nx.cnames, nx.ipv4, nx.ipv6, nx.ttl, nx.error], [[], [], [], null, null]);

    const dangling = await dns.resolveHost('dangling.example.com');
    assert.equal(dangling.status, 'NXDOMAIN');
    assert.deepEqual(dangling.cnames, ['gone.herokuapp.com']);
    assert.deepEqual(dangling.ipv4, []);

    const ent = await dns.resolveHost('sub.example.com'); // empty non-terminal
    assert.equal(ent.status, 'NOERROR');
    assert.deepEqual(ent.ipv4, []);

    const v6 = await dns.resolveHost('v6only.example.com');
    assert.deepEqual(v6.ipv4, []);
    assert.deepEqual(v6.ipv6, ['2001:db8::10']);
  });

  test('CNAME loops terminate', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const r = await dns.resolveHost('loop1.example.com');
    assert.ok(r.cnames.length <= 16);
    assert.deepEqual(r.ipv4, []);
  });

  test('status comes from A; AAAA is used when A failed at transport level', async () => {
    const { fetchImpl } = mockFetch(({ type, name }) => {
      if (type === 'A') throw new TypeError('A lost');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, retries: 0, ...fast() });
    const r = await dns.resolveHost('example.com');
    assert.equal(r.status, 'NOERROR');
    assert.deepEqual(r.ipv4, []);
    assert.deepEqual(r.ipv6, ['2606:2800:220:1:248:1893:25c8:1946']);
    assert.equal(r.error, null);
  });

  test('A failed and AAAA has no record → the A failure is the status, never "no address" (NODATA)', async () => {
    const { fetchImpl } = mockFetch(({ type, name }) => {
      if (type === 'A') throw new TypeError('A lost');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, retries: 0, ...fast() });
    const r = await dns.resolveHost('deep.sub.example.com');
    assert.equal(r.status, 'ERROR');
    assert.deepEqual([r.ipv4, r.ipv6], [[], []]);
    assert.equal(r.error, 'A lost');
    assert.equal(r.errorKind, 'network');
  });

  test('both queries failing → ERROR with the transport error', async () => {
    const { fetchImpl } = mockFetch(() => { throw new TypeError('offline'); });
    const dns = new DohClient({ fetchImpl, retries: 0, ...fast() });
    const r = await dns.resolveHost('example.com');
    assert.equal(r.status, 'ERROR');
    assert.equal(r.error, 'offline');
    assert.equal(r.errorKind, 'network');
  });

  test('SERVFAIL (DNSSEC bogus, real fixture) → status SERVFAIL with the EDE text', async () => {
    const { fetchImpl } = mockFetch(({ type }) => (type === 'A'
      ? new Response(fixtureBytes('cf-servfail-dnssec-bogus'))
      : { rcode: 'SERVFAIL', question: { name: 'dnssec-failed.org', type: 'AAAA' } }));
    const dns = new DohClient({ fetchImpl, ...fast() });
    const r = await dns.resolveHost('dnssec-failed.org', { resolver: 'cloudflare' });
    assert.equal(r.status, 'SERVFAIL');
    assert.match(r.error, /^SERVFAIL \(DNSKEY Missing: no SEP/);
    assert.equal(r.ede[0].code, 9);
  });

  test('real captured chain (www.microsoft.com → edgekey → akamaiedge)', async () => {
    const { fetchImpl } = mockFetch(({ type }) => (type === 'A'
      ? new Response(fixtureBytes('cf-a-cname-chain'))
      : { rcode: 'NOERROR', answers: [
        { name: 'www.microsoft.com', type: 'CNAME', ttl: 3578, data: 'www.microsoft.com-c-3.edgekey.net' },
        { name: 'www.microsoft.com-c-3.edgekey.net', type: 'CNAME', ttl: 878, data: 'e13678.dscb.akamaiedge.net' },
        { name: 'e13678.dscb.akamaiedge.net', type: 'AAAA', ttl: 20, data: '2600:1406:3a00:293::356e' }
      ] }));
    const dns = new DohClient({ fetchImpl, ...fast() });
    const r = await dns.resolveHost('www.microsoft.com');
    assert.deepEqual(r.cnames, ['www.microsoft.com-c-3.edgekey.net', 'e13678.dscb.akamaiedge.net']);
    assert.deepEqual(r.ipv4, ['184.29.240.90']);
    assert.deepEqual(r.ipv6, ['2600:1406:3a00:293::356e']);
    assert.equal(r.ttl, 0);
  });
});

describe('hostResolutionFrom / followCnames helpers', () => {
  const resp = (rcode, answers, extra = {}) => ({ ok: true, rcode, answers, resolver: 'google', ede: [], flags: { ad: false }, elapsedMs: 5, ...extra });

  test('ignores address records of owners outside the chain', () => {
    const a = resp('NOERROR', [
      { name: 'x.example.com', type: 'CNAME', ttl: 50, data: 'y.example.net' },
      { name: 'y.example.net', type: 'A', ttl: 40, data: '192.0.2.1' },
      { name: 'unrelated.example', type: 'A', ttl: 1, data: '192.0.2.99' }
    ]);
    const r = hostResolutionFrom('x.example.com', a, null);
    assert.deepEqual(r.ipv4, ['192.0.2.1']);
    assert.equal(r.ttl, 40);
  });

  test('A SERVFAIL but AAAA answered → AAAA wins; REFUSED alone → REFUSED; odd rcodes → ERROR', () => {
    const aaaa = resp('NOERROR', [{ name: 'h.example', type: 'AAAA', ttl: 9, data: '2001:db8::1' }]);
    assert.equal(hostResolutionFrom('h.example', resp('SERVFAIL', []), aaaa).status, 'NOERROR');
    assert.equal(hostResolutionFrom('h.example', resp('REFUSED', []), null).status, 'REFUSED');
    const odd = hostResolutionFrom('h.example', resp('FORMERR', []), null);
    assert.equal(odd.status, 'ERROR');
    assert.equal(odd.error, 'FORMERR');
    assert.equal(hostResolutionFrom('h.example', null, null).status, 'ERROR');
  });

  test('a lost family next to an empty answer is the failure (with its EDE), never NODATA; NXDOMAIN settles the name', () => {
    const ede = [{ code: 6, name: 'DNSSEC Bogus', text: 'signature expired' }];
    const nodata = resp('NOERROR', []);
    const r = hostResolutionFrom('h.example', resp('SERVFAIL', [], { ede }), nodata);
    assert.equal(r.status, 'SERVFAIL');
    assert.equal(r.error, 'SERVFAIL (DNSSEC Bogus: signature expired)');
    assert.deepEqual(r.ede, ede);
    const lost = { ok: false, rcode: null, answers: [], error: 'HTTP 503', errorKind: 'http', resolver: 'quad9', ede: [] };
    const m = hostResolutionFrom('h.example', nodata, lost);
    assert.deepEqual([m.status, m.error, m.errorKind, m.resolver], ['ERROR', 'HTTP 503', 'http', 'quad9']);
    const alias = resp('NOERROR', [{ name: 'h.example', type: 'CNAME', ttl: 9, data: 'lb.example.net' }]);
    assert.equal(hostResolutionFrom('h.example', lost, alias).status, 'ERROR');
    assert.equal(hostResolutionFrom('h.example', resp('SERVFAIL', []), resp('NXDOMAIN', [])).status, 'NXDOMAIN');
    assert.equal(hostResolutionFrom('h.example', lost, resp('NXDOMAIN', [])).status, 'NXDOMAIN');
  });

  test('ad is true only when every answered query was validated', () => {
    const a = resp('NOERROR', [], { flags: { ad: true } });
    assert.equal(hostResolutionFrom('h.example', a, resp('NOERROR', [], { flags: { ad: true } })).ad, true);
    assert.equal(hostResolutionFrom('h.example', a, resp('NOERROR', [], { flags: { ad: false } })).ad, false);
  });

  test('followCnames returns records and the final target', () => {
    const answers = [
      { name: 'a.example', type: 'CNAME', data: 'b.example' },
      { name: 'b.example', type: 'CNAME', data: 'c.example' },
      { name: 'c.example', type: 'A', data: '192.0.2.3' }
    ];
    const r = followCnames(answers, 'A.example.');
    assert.deepEqual(r.cnames, ['b.example', 'c.example']);
    assert.equal(r.records.length, 2);
    assert.equal(r.target, 'c.example');
    assert.deepEqual(followCnames(null, 'x').cnames, []);
  });
});

describe('detectWildcard', () => {
  test('wildcard A record', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await dns.detectWildcard('wild.example.org');
    assert.equal(w.wildcard, true);
    assert.deepEqual(w.ipv4, ['198.51.100.7']);
    assert.deepEqual(w.ipv6, []);
    assert.deepEqual(w.cnames, []);
    assert.equal(w.probes.length, 2);
    const probeNames = [...new Set(calls.map((c) => c.name))];
    assert.equal(probeNames.length, 2);
    for (const n of probeNames) assert.match(n, /^[a-z0-9]{12}\.wild\.example\.org$/);
  });

  test('wildcard CNAME', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await dns.detectWildcard('cnw.example.org');
    assert.equal(w.wildcard, true);
    assert.deepEqual(w.cnames, ['lb.example.net']);
    assert.deepEqual(w.ipv4, ['203.0.113.9']);
    assert.equal(w.dangling, false);
  });

  test('dangling wildcard CNAME (NXDOMAIN + CNAME) is still a wildcard, flagged dangling', async () => {
    const { fetchImpl } = zoneFetch({ ...ZONE, '*.dw.example.org': { CNAME: 'gone.herokuapp.com' } });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await dns.detectWildcard('dw.example.org');
    assert.equal(w.wildcard, true);
    assert.deepEqual(w.cnames, ['gone.herokuapp.com']);
    assert.deepEqual(w.ipv4, []);
    assert.equal(w.dangling, true);
    assert.equal(w.error, null);
    assert.deepEqual(w.probes.map((p) => p.status), ['NXDOMAIN', 'NXDOMAIN']);
    // both detectors agree on the same zone
    const deep = await detectWildcardDeep(dns, 'dw.example.org');
    assert.equal(deep.kind, 'CNAME');
  });

  test('no wildcard; failures are inconclusive; invalid domains', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await dns.detectWildcard('example.com');
    assert.equal(w.wildcard, false);
    assert.equal(w.error, null);

    const { fetchImpl: down } = mockFetch(() => { throw new TypeError('offline'); });
    const dns2 = new DohClient({ fetchImpl: down, retries: 0, ...fast() });
    const w2 = await dns2.detectWildcard('example.com');
    assert.equal(w2.wildcard, false);
    assert.equal(w2.error, 'offline');

    const w3 = await dns.detectWildcard('not a domain');
    assert.equal(w3.wildcard, false);
    assert.equal(w3.error, 'Invalid domain');
  });
});

describe('ptr', () => {
  test('IPv4 and IPv6 reverse names', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    assert.deepEqual(await dns.ptr('8.8.8.8'), ['dns.google']);
    assert.equal(calls[0].name, '8.8.8.8.in-addr.arpa');
    assert.equal(calls[0].type, 'PTR');
    assert.deepEqual(await dns.ptr('2001:db8::1'), ['host6.example.com']);
    assert.deepEqual(await dns.ptr('192.0.2.200'), []);
  });

  test('invalid IPs and failures → []', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    assert.deepEqual(await dns.ptr('not-an-ip'), []);
    assert.equal(calls.length, 0);
    const { fetchImpl: down } = mockFetch(() => { throw new TypeError('x'); });
    assert.deepEqual(await new DohClient({ fetchImpl: down, retries: 0, ...fast() }).ptr('8.8.8.8'), []);
  });

  test('real captured PTR answer', async () => {
    const { fetchImpl } = mockFetch(() => new Response(fixtureBytes('cf-ptr-8.8.8.8')));
    const dns = new DohClient({ fetchImpl, ...fast() });
    assert.deepEqual(await dns.ptr('8.8.8.8'), ['dns.google']);
  });

  test('throwOnError: "could not ask" rejects, "no PTR record" stays []', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    assert.deepEqual(await dns.ptr('192.0.2.200', { throwOnError: true }), [], 'NXDOMAIN is an answer');
    assert.deepEqual(await dns.ptr('8.8.8.8', { throwOnError: true }), ['dns.google']);
    const { fetchImpl: down } = mockFetch(() => { throw new TypeError('Failed to fetch'); });
    await assert.rejects(new DohClient({ fetchImpl: down, retries: 0, ...fast() }).ptr('8.8.8.8', { throwOnError: true }),
      (e) => e.kind === 'network' && /Failed to fetch|network/i.test(e.message));
    const { fetchImpl: servfail } = mockFetch(() => ({ rcode: 'SERVFAIL' }));
    await assert.rejects(new DohClient({ fetchImpl: servfail, ...fast() }).ptr('8.8.8.8', { throwOnError: true }),
      (e) => e.message === 'PTR lookup answered SERVFAIL' && e.rcode === 'SERVFAIL');
    await assert.rejects(new DohClient({ fetchImpl: down, retries: 0, ...fast() }).ptr('8.8.8.8', { throwOnError: true }),
      (e) => e.rcode === undefined, 'no rcode without a DNS answer');
    assert.deepEqual(await new DohClient({ fetchImpl: servfail, ...fast() }).ptr('8.8.8.8'), [], 'without the option: [] as before');
  });
});
