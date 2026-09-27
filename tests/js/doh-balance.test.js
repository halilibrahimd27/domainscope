// Unit tests for the doh.js additions: balance mode, the circuit breaker in
// balance mode, and detectWildcardDeep (incl. NODATA / CNAME wildcards).
// No network: every DoH server is a mock fetchImpl answering real wire messages.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { DohClient, detectWildcardDeep } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';

/* ---- mock DoH infrastructure (mirrors doh.test.js) --------------------- */

const SOA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };

function resolverIdOf(url) {
  const r = RESOLVERS.find((x) => url.startsWith(`${x.url}?`) || url.startsWith(`${x.url}&`));
  return r ? r.id : new URL(url).host;
}

function mockFetch(handler) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const query = decodeMessage(base64UrlDecode(u.searchParams.get('dns')));
    const question = query.questions[0];
    const resolver = resolverIdOf(url);
    calls.push({ url, init, resolver, name: question.name, type: question.type });
    const out = await handler({ resolver, name: question.name, type: question.type, query });
    if (out instanceof Response) return out;
    const bytes = encodeMessage({
      id: 0,
      flags: { qr: true, rd: true, ra: true, ad: !!out.ad, cd: query.flags.cd },
      rcode: out.rcode || 'NOERROR',
      questions: [{ name: question.name, type: question.type }],
      answers: out.answers || [],
      authorities: out.authorities || [],
      edns: {}
    });
    return new Response(bytes, { status: 200, headers: { 'content-type': 'application/dns-message' } });
  };
  return { fetchImpl, calls };
}

function zoneAnswer(zone, name, type) {
  const answers = [];
  let current = name;
  for (let hop = 0; hop < 12; hop += 1) {
    let node = zone[current];
    const owner = current;
    if (!node) {
      const parent = current.split('.').slice(1).join('.');
      const exists = Object.keys(zone).some((k) => k.endsWith(`.${current}`) && !k.startsWith('*.'));
      if (!exists && zone[`*.${parent}`]) node = zone[`*.${parent}`];
      else return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers, authorities: [{ name: 'example.org', type: 'SOA', ttl: 600, data: SOA }] };
    }
    const ttl = node.ttl ?? 300;
    if (node.CNAME && type !== 'CNAME') {
      answers.push({ name: owner, type: 'CNAME', ttl, data: node.CNAME });
      current = node.CNAME;
      continue;
    }
    for (const data of node[type] || []) answers.push({ name: owner, type, ttl, data });
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: 'example.org', type: 'SOA', ttl: 600, data: SOA }] };
  }
  return { rcode: 'SERVFAIL', answers: [] };
}

const ZONE = {
  'example.com': { A: ['93.184.216.34'], AAAA: ['2606:2800:220:1:248:1893:25c8:1946'], ttl: 3600 },
  '*.wild.example.org': { A: ['198.51.100.7'] },
  '*.cnw.example.org': { CNAME: 'lb.example.net' },
  'lb.example.net': { A: ['203.0.113.9'] }
};

const zoneFetch = (zone = ZONE) => mockFetch(({ name, type }) => zoneAnswer(zone, name, type));
const fast = (extra = {}) => ({ baseDelayMs: 1, maxDelayMs: 5, timeoutMs: 2000, ...extra });

/* ---- balance mode ------------------------------------------------------ */

describe('balance mode', () => {
  test('round-robins primary queries across the healthy pool; quad9 (h3-no-cors) stays off the primaries', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    for (let i = 0; i < 8; i += 1) await dns.query(`n${i}.example.com`, 'A', { balance: true });
    // every candidate succeeds on its primary → one call per query
    assert.equal(calls.length, 8);
    const primaries = new Set(calls.map((c) => c.resolver));
    for (const id of ['cloudflare', 'google', 'dnssb']) {
      assert.ok(primaries.has(id), `expected ${id} to appear as a rotating primary`);
    }
    assert.ok(!primaries.has('quad9'), 'quad9 (h3-no-cors) is not in the default pool');
    assert.ok(!primaries.has('controld'), 'controld (unreachable from some networks) is not in the default pool');
  });

  test('an explicit resolver ignores balance', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    await dns.query('example.com', 'A', { resolver: 'iij', balance: true });
    assert.deepEqual(calls.map((c) => c.resolver), ['iij']);
  });

  test('balanced queries fail over and share one pool-wide cache key', async () => {
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') throw new TypeError('blocked');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const first = await dns.query('example.com', 'A', { balance: true });
    assert.equal(first.ok, true);
    assert.notEqual(first.resolver, 'cloudflare');
    const before = calls.length;
    const second = await dns.query('EXAMPLE.com', 'A', { balance: true });
    assert.equal(second.cached, true, 'served from the shared balance cache key');
    assert.equal(calls.length, before);
  });

  test('the default pool is the large unfiltered resolvers browsers read reliably (no quad9 / controld)', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    for (let i = 0; i < 12; i += 1) await dns.query(`p${i}.example.com`, 'A', { balance: true });
    assert.deepEqual([...new Set(calls.map((c) => c.resolver))].sort(), ['cloudflare', 'dnssb', 'google']);
    for (const id of ['cloudflare', 'dnssb', 'google']) {
      const r = RESOLVERS.find((x) => x.id === id);
      assert.ok(r.browserReliable && !r.filtering, `${id} is browser-readable and unfiltered`);
    }
  });

  test('a custom pool may include a browser-unreliable resolver: failover only, never a rotating primary', async () => {
    let failing = false;
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (failing && resolver !== 'quad9') throw new TypeError('Failed to fetch');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, cache: false, balancePool: ['cloudflare', 'quad9', 'google'], ...fast({ retries: 0 }) });
    for (let i = 0; i < 6; i += 1) await dns.query(`c${i}.example.com`, 'A', { balance: true });
    assert.ok(!calls.some((c) => c.resolver === 'quad9'), 'quad9 never primary');
    failing = true;
    const res = await dns.query('late.example.com', 'A', { balance: true });
    assert.equal(res.resolver, 'quad9', 'used as the last failover');
  });

  test('the default pool follows the chain: with chain [cloudflare] no bulk query hits google / dnssb', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, chain: ['cloudflare'], cache: false, ...fast() });
    for (let i = 0; i < 9; i += 1) await dns.query(`q${i}.example.com`, 'A', { balance: true });
    assert.deepEqual([...new Set(calls.map((c) => c.resolver))], ['cloudflare']);
  });

  test('the default pool follows the chain: a chain that excludes the whole pool still gets queried in balance mode', async () => {
    // cloudflare/google/dnssb (the default pool) are all unreachable; only cznic answers.
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (resolver !== 'cznic') throw new TypeError('Failed to fetch');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, chain: ['cznic'], cache: false, ...fast({ retries: 0 }) });
    const res = await dns.query('www.example.com', 'A', { balance: true });
    assert.equal(res.ok, true, 'balance mode fell back to the configured chain (cznic)');
    assert.equal(res.resolver, 'cznic');
    assert.ok(calls.every((c) => c.resolver === 'cznic'), 'only the chain resolver was tried');
  });

  test('setChain invalidates cached balanced answers from a removed resolver', async () => {
    const { fetchImpl, calls } = zoneFetch();
    const dns = new DohClient({ fetchImpl, chain: ['cloudflare', 'google'], ...fast() });
    await dns.query('shared.example.com', 'A', { balance: true });
    const before = calls.length;
    dns.setChain(['dnssb']);
    const res = await dns.query('shared.example.com', 'A', { balance: true });
    assert.equal(res.cached, false, 'the chain changed, so the balanced answer is not reused');
    assert.ok(calls.length > before);
    assert.equal(res.resolver, 'dnssb');
  });

  test('a fully breaker-open pool fails fast: one pass, not a retry storm', async () => {
    let now = 1000;
    const { fetchImpl, calls } = mockFetch(({ name, type }) => {
      // every resolver is unreachable
      throw new TypeError('Failed to fetch');
    });
    // eslint-disable-next-line no-unused-vars
    const dns = new DohClient({ fetchImpl, cache: false, now: () => now, chain: ['cloudflare', 'google', 'dnssb'], retries: 1, baseDelayMs: 1, maxDelayMs: 2, timeoutMs: 50 });
    // Warm up until all three breakers are open.
    for (let i = 0; i < 12; i += 1) await dns.query(`w${i}.example.com`, 'A', { balance: true });
    for (const id of ['cloudflare', 'google', 'dnssb']) assert.equal(dns.stats().byResolver[id].down, true, id);
    calls.length = 0;
    const res = await dns.query('dead.example.com', 'A', { balance: true });
    assert.equal(res.ok, false);
    // One pass over the (deferred-once) pool: at most one request per resolver, never a second retry pass.
    assert.ok(calls.length <= 3, `expected ≤ 3 requests for a dead pool, got ${calls.length}`);
  });

  test('circuit breaker removes a resolver that keeps failing as primary', async () => {
    let now = 1000;
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') throw new TypeError('blocked');
      return zoneAnswer(ZONE, name, type);
    });
    // A two-resolver pool makes cloudflare the primary every other query.
    const dns = new DohClient({ fetchImpl, cache: false, now: () => now, balancePool: ['cloudflare', 'google'], ...fast() });
    for (let i = 0; i < 6; i += 1) await dns.query(`h${i}.example.com`, 'A', { balance: true });
    assert.equal(dns.stats().byResolver.cloudflare.down, true);
    calls.length = 0;
    const res = await dns.query('later.example.com', 'A', { balance: true });
    assert.equal(res.ok, true);
    assert.ok(!calls.some((c) => c.resolver === 'cloudflare'), 'cloudflare skipped while its breaker is open');
  });
});

/* ---- circuit breaker under concurrent load ------------------------------ */

const tick = (ms) => new Promise((r) => setTimeout(r, ms));

describe('circuit breaker under load', () => {
  test('a burst stops hitting a failing resolver as soon as its breaker opens', async () => {
    const { fetchImpl, calls } = mockFetch(async ({ resolver, name, type }) => {
      if (resolver === 'cloudflare') {
        await tick(5);
        throw new TypeError('Failed to fetch'); // what a CORS-blocked answer looks like to fetch()
      }
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, cache: false, chain: ['cloudflare', 'google'], concurrency: 2, ...fast() });
    // Every query fixes its order [cloudflare, google] when it starts — before any failure.
    const res = await Promise.all(Array.from({ length: 30 }, (_, i) => dns.query(`b${i}.example.com`)));
    assert.ok(res.every((r) => r.ok && r.resolver === 'google'));
    const tried = calls.filter((c) => c.resolver === 'cloudflare').length;
    assert.ok(tried <= 4, `cloudflare tried ${tried}× — expected ≤ threshold (3) + concurrency - 1, not once per query`);
    assert.equal(dns.stats().byResolver.cloudflare.down, true);
    const skipped = res.filter((r) => r.attempts.every((a) => a.resolver === 'google'));
    assert.ok(skipped.length >= 26, 'queued queries went straight to the next resolver');
  });

  test('a skipped resolver is still tried last when every other one fails', async () => {
    const { fetchImpl, calls } = mockFetch(async ({ resolver, name, type }) => {
      await tick(2);
      if (resolver === 'google') throw new TypeError('offline');
      if (resolver === 'cloudflare' && calls.filter((c) => c.resolver === 'cloudflare').length <= 3) throw new TypeError('blip');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, cache: false, chain: ['cloudflare', 'google'], concurrency: 1, ...fast({ retries: 0 }) });
    const res = await Promise.all(Array.from({ length: 6 }, (_, i) => dns.query(`s${i}.example.com`)));
    // q0–q2 open cloudflare's breaker (and then google's); q3–q5 skip both while down, then still
    // try the deferred ones as a last resort instead of giving up — cloudflare has recovered.
    assert.ok(res.slice(0, 3).every((r) => !r.ok));
    assert.ok(res.slice(3).every((r) => r.ok && r.resolver === 'cloudflare'), JSON.stringify(res.map((r) => r.attempts)));
    assert.equal(calls.filter((c) => c.resolver === 'google').length, 3, 'google skipped once its breaker opened');
    assert.equal(dns.stats().byResolver.cloudflare.down, false, 'a success closes the breaker');
  });

  test('after the cooldown only one trial request goes to the resolver (half-open)', async () => {
    let now = 1000;
    let up = false;
    const { fetchImpl, calls } = mockFetch(async ({ resolver, name, type }) => {
      if (resolver === 'cloudflare') {
        await tick(5);
        if (!up) throw new TypeError('Failed to fetch');
      }
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, cache: false, now: () => now, chain: ['cloudflare', 'google'], concurrency: 4, ...fast() });
    for (let i = 0; i < 3; i += 1) await dns.query(`t${i}.example.com`);
    assert.equal(dns.stats().byResolver.cloudflare.down, true);

    now += 31000; // cooldown over, resolver still broken: one trial, then open again
    calls.length = 0;
    let res = await Promise.all(Array.from({ length: 10 }, (_, i) => dns.query(`h${i}.example.com`)));
    assert.ok(res.every((r) => r.ok && r.resolver === 'google'));
    assert.equal(calls.filter((c) => c.resolver === 'cloudflare').length, 1, 'a single trial request');
    assert.equal(dns.stats().byResolver.cloudflare.down, true, 'failed trial re-opens the breaker');

    now += 31000; // cooldown over, resolver healthy again: the trial succeeds and it is primary again
    up = true;
    calls.length = 0;
    res = await Promise.all(Array.from({ length: 10 }, (_, i) => dns.query(`r${i}.example.com`)));
    assert.ok(res.every((r) => r.ok));
    assert.equal(dns.stats().byResolver.cloudflare.down, false);
    const after = await dns.query('after.example.com');
    assert.equal(after.resolver, 'cloudflare');
    assert.deepEqual(after.attempts.map((a) => a.resolver), ['cloudflare']);
  });

  test('explicit single-resolver queries ignore the breaker (Global DNS asks every resolver)', async () => {
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'cloudflare') throw new TypeError('Failed to fetch');
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, cache: false, chain: ['cloudflare', 'google'], ...fast({ retries: 0 }) });
    for (let i = 0; i < 3; i += 1) await dns.query(`x${i}.example.com`);
    assert.equal(dns.stats().byResolver.cloudflare.down, true);
    calls.length = 0;
    const res = await dns.query('example.com', 'A', { resolver: 'cloudflare' });
    assert.equal(res.ok, false);
    assert.deepEqual(calls.map((c) => c.resolver), ['cloudflare']);
  });
});

/* ---- per-query timeout / retries (Global DNS: ask once, fail fast) ------ */

describe('per-query timeoutMs / retries', () => {
  test('a per-query timeout and retries:0 bound an unreachable resolver to one short attempt', async () => {
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (resolver === 'controld') return new Promise(() => {}); // black hole (ignores the signal)
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, timeoutMs: 5000, retries: 2, baseDelayMs: 1, maxDelayMs: 5 });
    const t0 = Date.now();
    const res = await dns.query('example.com', 'A', { resolver: 'controld', timeoutMs: 40, retries: 0 });
    assert.equal(res.ok, false);
    assert.equal(res.errorKind, 'timeout');
    assert.equal(calls.length, 1, 'no retry');
    assert.ok(Date.now() - t0 < 1000, 'the per-query timeout wins over the client one');
    const ok = await dns.query('example.com', 'A', { resolver: 'google', timeoutMs: 40, retries: 0 });
    assert.equal(ok.ok, true);
  });

  test('without overrides the client settings apply; invalid overrides are ignored', async () => {
    const { fetchImpl, calls } = mockFetch(() => new Response('busy', { status: 503 }));
    const dns = new DohClient({ fetchImpl, retries: 2, cache: false, ...fast() });
    await dns.query('example.com', 'A', { resolver: 'iij' });
    assert.equal(calls.length, 3, 'client retries: 2 → 3 attempts');
    calls.length = 0;
    await dns.query('example.org', 'A', { resolver: 'iij', retries: -1, timeoutMs: 0 });
    assert.equal(calls.length, 3, 'invalid overrides fall back to the client settings');
    calls.length = 0;
    await dns.query('example.net', 'A', { resolver: 'iij', retries: 0 });
    assert.equal(calls.length, 1);
  });
});

/* ---- detectWildcardDeep ------------------------------------------------ */

describe('detectWildcardDeep', () => {
  test('A wildcard (both random labels agree on the same address)', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'wild.example.org');
    assert.equal(w.wildcard, true);
    assert.equal(w.kind, 'A');
    assert.deepEqual(w.ipv4, ['198.51.100.7']);
    assert.deepEqual(w.cnames, []);
  });

  test('CNAME wildcard', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'cnw.example.org');
    assert.equal(w.wildcard, true);
    assert.equal(w.kind, 'CNAME');
    assert.deepEqual(w.cnames, ['lb.example.net']);
  });

  test('NODATA wildcard (NOERROR, no records, for any label)', async () => {
    const { fetchImpl } = mockFetch(({ name, type }) => {
      if (name.endsWith('.nodata.example.org')) {
        return { rcode: 'NOERROR', answers: [], authorities: [{ name: 'nodata.example.org', type: 'SOA', ttl: 600, data: SOA }] };
      }
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'nodata.example.org');
    assert.equal(w.wildcard, true);
    assert.equal(w.kind, 'NODATA');
    assert.deepEqual(w.ipv4, []);
    assert.deepEqual(w.cnames, []);
  });

  test('DNSSEC compact denial (Cloudflare black lies / NXNAME) is NOT a NODATA wildcard', async () => {
    // Every label answers NOERROR-empty (looks like NODATA), but a DNSSEC query
    // returns an NSEC owned by the queried name proving it does not exist.
    const { fetchImpl } = mockFetch(({ name, type, query }) => {
      if (!name.endsWith('.cd.example.org')) return zoneAnswer(ZONE, name, type);
      const dnssec = !!(query.edns && query.edns.dnssecOk);
      const authorities = dnssec
        ? [{ name, type: 'NSEC', ttl: 300, data: { nextDomain: `\\000.${name}`, types: ['RRSIG', 'NSEC', 'NXNAME'] } }]
        : [{ name: 'cd.example.org', type: 'SOA', ttl: 600, data: SOA }];
      return { rcode: 'NOERROR', answers: [], authorities };
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'cd.example.org');
    assert.equal(w.wildcard, false, 'compact denial must not be reported as a wildcard');
    assert.equal(w.kind, null);
  });

  test('a genuine NODATA wildcard with no DNSSEC denial is still reported', async () => {
    // NOERROR-empty for every label, and the DNSSEC query carries only an SOA
    // (no NSEC proving non-existence) — a real wildcard that yields NODATA.
    const { fetchImpl } = mockFetch(({ name, type }) => {
      if (name.endsWith('.nd.example.org')) {
        return { rcode: 'NOERROR', answers: [], authorities: [{ name: 'nd.example.org', type: 'SOA', ttl: 600, data: SOA }] };
      }
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'nd.example.org');
    assert.equal(w.wildcard, true);
    assert.equal(w.kind, 'NODATA');
  });

  test('no wildcard: random labels are NXDOMAIN', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'example.com');
    assert.equal(w.wildcard, false);
    assert.equal(w.kind, null);
  });

  test('disagreeing probes are not a wildcard', async () => {
    const verdict = new Map();
    const { fetchImpl } = mockFetch(({ name, type }) => {
      if (name.endsWith('.dis.example.org')) {
        const label = name.slice(0, name.indexOf('.'));
        if (!verdict.has(label)) verdict.set(label, verdict.size === 0 ? 'a' : 'nx');
        if (verdict.get(label) === 'nx') return { rcode: 'NXDOMAIN' };
        return type === 'A' ? { answers: [{ name, type: 'A', ttl: 60, data: '203.0.113.5' }] } : { rcode: 'NOERROR', answers: [] };
      }
      return zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'dis.example.org');
    assert.equal(w.wildcard, false);
    assert.equal(w.kind, null);
  });

  test('invalid parent / missing client → no wildcard', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const none = { wildcard: false, kind: null, ipv4: [], ipv6: [], cnames: [], targets: [], variable: false, conclusive: false };
    assert.deepEqual(await detectWildcardDeep(dns, 'not a domain'), none);
    assert.deepEqual(await detectWildcardDeep(null, 'example.org'), none);
  });

  test('conclusive: every probe NXDOMAIN proves "no wildcard"; failed or disagreeing probes prove nothing', async () => {
    const { fetchImpl } = zoneFetch();
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'example.com');
    assert.equal(w.wildcard, false);
    assert.equal(w.conclusive, true);
    assert.equal((await detectWildcardDeep(dns, 'wild.example.org')).conclusive, true);

    const { fetchImpl: down } = mockFetch(({ name, type }) => (name.endsWith('.broken.example.org')
      ? new Response('busy', { status: 503 }) : zoneAnswer(ZONE, name, type)));
    const dns2 = new DohClient({ fetchImpl: down, ...fast({ retries: 0 }) });
    const w2 = await detectWildcardDeep(dns2, 'broken.example.org');
    assert.equal(w2.wildcard, false);
    assert.equal(w2.conclusive, false);
  });

  test('a wildcard whose answer varies per label (multivalue pool) is an A wildcard with the union', async () => {
    const pool = ['198.51.100.10', '198.51.100.11', '198.51.100.12', '198.51.100.13', '198.51.100.14', '198.51.100.15'];
    let n = 0;
    const byLabel = new Map();
    const { fetchImpl } = mockFetch(({ name, type }) => {
      if (!name.endsWith('.pool.example.org')) return zoneAnswer(ZONE, name, type);
      if (!byLabel.has(name)) { byLabel.set(name, [pool[(2 * n) % 6], pool[(2 * n + 1) % 6]]); n += 1; }
      return type === 'A' ? { answers: byLabel.get(name).map((data) => ({ name, type: 'A', ttl: 60, data })) } : { rcode: 'NOERROR', answers: [] };
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'pool.example.org');
    assert.equal(w.wildcard, true);
    assert.equal(w.kind, 'A');
    assert.equal(w.variable, true);
    assert.deepEqual([...w.ipv4].sort(), pool.slice(0, 4));
  });

  test('per-resolver probes: an answer that differs on one resolver (GeoDNS / ECS) joins the union', async () => {
    const { fetchImpl, calls } = mockFetch(({ resolver, name, type }) => {
      if (name.endsWith('.geo.example.org') && type === 'A') {
        const data = resolver === 'google' ? ['198.51.100.20', '198.51.100.21'] : ['198.51.100.10', '198.51.100.11'];
        return { answers: data.map((d) => ({ name, type: 'A', ttl: 60, data: d })) };
      }
      return name.endsWith('.geo.example.org') ? { rcode: 'NOERROR', answers: [] } : zoneAnswer(ZONE, name, type);
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    assert.deepEqual(dns.balancePool, ['cloudflare', 'google', 'dnssb']);
    const w = await detectWildcardDeep(dns, 'geo.example.org', { resolvers: dns.balancePool });
    assert.equal(w.kind, 'A');
    assert.equal(w.variable, true);
    assert.deepEqual([...w.ipv4].sort(), ['198.51.100.10', '198.51.100.11', '198.51.100.20', '198.51.100.21']);
    assert.ok(['cloudflare', 'google', 'dnssb'].every((id) => calls.some((c) => c.resolver === id && c.name.endsWith('.geo.example.org'))));
  });

  test('a CNAME wildcard whose target varies per label keeps every target', async () => {
    const targets = ['va01.ingress.paas.example.net', 'ie02.ingress.paas.example.net'];
    let n = 0;
    const byLabel = new Map();
    const { fetchImpl } = mockFetch(({ name, type }) => {
      if (!name.endsWith('.paas.example.org')) return zoneAnswer(ZONE, name, type);
      if (!byLabel.has(name)) { byLabel.set(name, targets[n % 2]); n += 1; }
      return { answers: [{ name, type: 'CNAME', ttl: 60, data: byLabel.get(name) }] };
    });
    const dns = new DohClient({ fetchImpl, ...fast() });
    const w = await detectWildcardDeep(dns, 'paas.example.org', { probes: 4 });
    assert.equal(w.kind, 'CNAME');
    assert.equal(w.variable, true);
    assert.deepEqual([...w.targets].sort(), [...targets].sort());
    assert.equal(w.cnames.length, 1);
  });
});
