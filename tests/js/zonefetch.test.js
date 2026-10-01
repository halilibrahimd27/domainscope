// Unit tests for assets/js/lib/zonefetch.js — offline: every answer comes from tests/fixtures/zonefetch
// (recorded or documented provider answers) and tests/fixtures/zones (the listings), through a fake fetch.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ZONE_PROVIDERS, ZONE_FETCH_ERRORS, DESEC_TYPES, MAX_RECORDS, MAX_WAIT_MS, DEFAULT_WAIT_MS, ZoneFetchError,
  fetchZone, getZoneProvider, cleanToken, zoneName, desecTotal, retryAfterMs
} from '../../assets/js/lib/zonefetch.js';
import { parseZone, ZONE_LIMITS, ZONE_FORMATS } from '../../assets/js/lib/zoneparse.js';
import { lintZone } from '../../assets/js/lib/zonelint.js';
import { zoneScanInput } from '../../assets/js/lib/zoneorigins.js';
import { planDrift } from '../../assets/js/lib/zonedrift.js';
import { planParity } from '../../assets/js/lib/nsparity.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const read = (...p) => readFileSync(join(FIX, ...p), 'utf8');
const DESEC = JSON.parse(read('zonefetch', 'desec.json'));
const DO = JSON.parse(read('zonefetch', 'digitalocean.json'));
const DESEC_LISTING = JSON.parse(read('zones', 'desec-api.json'));
const DO_PAGE1 = JSON.parse(read('zones', 'digitalocean-api-page1.json'));
const DO_PAGE2 = JSON.parse(read('zones', 'digitalocean-api-page2.json'));

/** A made-up token, built from pieces so that no file holds anything token-shaped. */
const TOKEN = ['made', 'up', 'test', 'token', '0123456789'].join('-');
const DESEC_BASE = 'https://desec.io/api/v1/domains/example.com/rrsets/';
const DO_BASE = 'https://api.digitalocean.com/v2/domains/example.com/records';

/**
 * A fake fetch answering from `routes` (URL → answer, or a function of the call count); records
 * every request with its options. An answer is `{ status, body, headers }`; anything else throws.
 */
function fakeFetch(routes) {
  const calls = [];
  const count = new Map();
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    const n = (count.get(String(url)) || 0) + 1;
    count.set(String(url), n);
    let answer = routes[String(url)];
    if (typeof answer === 'function') answer = answer(n);
    if (answer instanceof Error) throw answer;
    if (!answer) return new Response('{"detail":"Not found."}', { status: 404, headers: { 'content-type': 'application/json' } });
    const headers = new Headers(answer.headers || { 'content-type': 'application/json' });
    return new Response(answer.raw ?? JSON.stringify(answer.body), { status: answer.status, headers });
  };
  return { fetchImpl, calls };
}
const ok = (body) => ({ status: 200, body });
/** A sleep that only records what it was asked to wait. */
function fakeSleep() {
  const waits = [];
  return { waits, sleepImpl: async (ms) => { waits.push(ms); } };
}
const longWaits = (waits) => waits.filter((ms) => ms >= 1000);

describe('providers and inputs', () => {
  test('two providers, each mapped to a zoneparse format; links are https', () => {
    assert.deepEqual(ZONE_PROVIDERS.map((p) => p.id), ['desec', 'digitalocean']);
    for (const p of ZONE_PROVIDERS) {
      assert.ok(ZONE_FORMATS.includes(p.format), p.id);
      for (const u of [p.api, p.tokenUrl, p.docsUrl]) assert.match(u, /^https:\/\//);
      assert.equal(getZoneProvider(p.id), p);
    }
    assert.equal(getZoneProvider('cloudflare'), null);
    assert.equal(MAX_RECORDS, ZONE_LIMITS.maxRecords);
    assert.equal(new Set(DESEC_TYPES).size, DESEC_TYPES.length);
    assert.deepEqual(DESEC_TYPES.slice(0, 4), ['A', 'AAAA', 'CNAME', 'TXT']);
  });

  test('a pasted token is trimmed; white space inside, control characters or a wrong length refuse it', () => {
    assert.equal(cleanToken(`  ${TOKEN}\n`), TOKEN);
    for (const bad of ['', 'short', `${TOKEN} x`, `${TOKEN}\u0000`, 'x'.repeat(513), null, undefined, 42]) assert.equal(cleanToken(bad), null, String(bad));
  });

  test('the zone name: a host name with a dot, punycode for IDN, URLs reduced to their host', () => {
    assert.equal(zoneName('Example.COM.'), 'example.com');
    assert.equal(zoneName('https://example.com/path'), 'example.com');
    assert.equal(zoneName('bücher.example'), 'xn--bcher-kva.example');
    for (const bad of ['', 'localhost', 'not a name', null]) assert.equal(zoneName(bad), null, String(bad));
  });

  test('nothing is sent for a bad provider, zone or token', async () => {
    const { fetchImpl, calls } = fakeFetch({});
    const cases = [['cloudflare', 'example.com', TOKEN, 'provider'], ['desec', 'localhost', TOKEN, 'domain'], ['digitalocean', 'example.com', 'x y', 'token']];
    for (const [p, d, tok, code] of cases) {
      await assert.rejects(fetchZone(p, d, tok, { fetchImpl }), (err) => err instanceof ZoneFetchError && err.code === code, code);
    }
    assert.equal(calls.length, 0);
    for (const code of ['provider', 'domain', 'token', 'auth', 'forbidden', 'not-found', 'rate-limited', 'network', 'timeout', 'response']) {
      assert.ok(ZONE_FETCH_ERRORS.includes(code), code);
    }
  });

  test('deSEC texts: the total of a pagination answer, the wait of a throttled one', () => {
    assert.equal(desecTotal(DESEC.pagination.body), 612);
    assert.equal(desecTotal(DESEC['invalid-token'].body), null);
    assert.equal(retryAfterMs({ body: DESEC.throttled.body, retryAfterMs: null }), 3000);
    assert.equal(retryAfterMs({ body: DO['too-many-requests'].body, retryAfterMs: null }), null);
    assert.equal(retryAfterMs({ body: DESEC.throttled.body, retryAfterMs: 7000 }), 7000, 'a readable Retry-After wins');
  });
});

describe('deSEC', () => {
  test('a zone under 500 RRsets: one GET with the token in the header only, no cookies, referrer or redirects', async () => {
    const { fetchImpl, calls } = fakeFetch({ [DESEC_BASE]: ok(DESEC_LISTING) });
    const out = await fetchZone('desec', 'example.com', TOKEN, { fetchImpl });
    assert.equal(calls.length, 1);
    const { url, init } = calls[0];
    assert.equal(url, DESEC_BASE);
    assert.ok(!url.includes(TOKEN));
    assert.deepEqual(init.headers, { authorization: `Token ${TOKEN}`, accept: 'application/json' });
    assert.deepEqual([init.method, init.credentials, init.referrerPolicy, init.cache, init.redirect], ['GET', 'omit', 'no-referrer', 'no-store', 'error']);
    assert.deepEqual([out.provider, out.domain, out.format, out.requests, out.records, out.total, out.partial, out.byType],
      ['desec', 'example.com', 'desec-api', 1, DESEC_LISTING.length, DESEC_LISTING.length, false, false]);
    assert.ok(!out.text.includes('created') && !out.text.includes('touched'), 'timestamps are left out');
    assert.ok(!JSON.stringify(out).includes(TOKEN), 'the token is not in the result');
    // The same records as the listing itself.
    const fetched = parseZone(out.text);
    const pasted = parseZone(JSON.stringify(DESEC_LISTING));
    assert.equal(fetched.format, 'desec-api');
    assert.deepEqual(fetched.records, pasted.records);
  });

  test('over 500 RRsets: read type by type, most common first, until the total is in', async () => {
    const byType = (type) => DESEC_LISTING.filter((s) => s.type === type);
    const routes = { [DESEC_BASE]: DESEC.pagination };
    for (const type of DESEC_TYPES) routes[`${DESEC_BASE}?type=${type}`] = ok(byType(type));
    // The total says 612 but the listing has 21 RRsets: every type is asked, and the zone is partial.
    const { fetchImpl, calls } = fakeFetch(routes);
    const progress = [];
    const { waits, sleepImpl } = fakeSleep();
    const out = await fetchZone('desec', 'example.com', TOKEN, { fetchImpl, sleepImpl, onProgress: (p) => progress.push(p) });
    assert.deepEqual(calls.map((c) => c.url), [DESEC_BASE, ...DESEC_TYPES.map((t) => `${DESEC_BASE}?type=${t}`)]);
    assert.deepEqual([out.records, out.total, out.partial, out.byType], [DESEC_LISTING.length, 612, true, true]);
    assert.ok(waits.every((ms) => ms > 0 && ms < 1000), 'requests are spaced, never waited on');
    assert.equal(progress.at(-1).requests, calls.length);
    const z = parseZone(out.text);
    assert.deepEqual(z.warnings.find((w) => w.code === 'PARTIAL_EXPORT').params, { have: DESEC_LISTING.length, total: 612, provider: 'desec' });
  });

  test('type by type stops as soon as the total is in; a type over 500 brings its first page (cursor=)', async () => {
    const pagination = { status: 400, body: { detail: 'Pagination required. You can query up to 500 items at a time (4 total). Please use the `first` page link (see Link header).' } };
    const routes = {
      [DESEC_BASE]: pagination,
      [`${DESEC_BASE}?type=A`]: { status: 400, body: { detail: 'Pagination required. You can query up to 500 items at a time (3 total).' } },
      [`${DESEC_BASE}?type=A&cursor=`]: ok(DESEC_LISTING.filter((s) => s.type === 'A').slice(0, 3)),
      [`${DESEC_BASE}?type=AAAA`]: ok(DESEC_LISTING.filter((s) => s.type === 'AAAA').slice(0, 1))
    };
    const { fetchImpl, calls } = fakeFetch(routes);
    const out = await fetchZone('desec', 'example.com', TOKEN, { fetchImpl, sleepImpl: fakeSleep().sleepImpl });
    assert.deepEqual(calls.map((c) => c.url.replace(DESEC_BASE, '')), ['', '?type=A', '?type=A&cursor=', '?type=AAAA']);
    assert.deepEqual([out.records, out.total, out.partial], [4, 4, false]);
    assert.equal(parseZone(out.text).partial, false);
  });

  test('401 / 403 / 404: the code, the status and deSEC\'s own words; never the token', async () => {
    for (const [answer, code] of [[DESEC['invalid-token'], 'auth'], [DESEC['no-credentials'], 'auth'], [DESEC['not-found'], 'not-found'],
      [{ status: 403, body: { detail: 'You do not have permission to perform this action.' } }, 'forbidden']]) {
      const { fetchImpl } = fakeFetch({ [DESEC_BASE]: answer });
      await assert.rejects(fetchZone('desec', 'example.com', TOKEN, { fetchImpl }), (err) => {
        assert.equal(err.code, code);
        assert.deepEqual(err.params, { status: answer.status, detail: answer.body.detail });
        assert.ok(!JSON.stringify({ m: err.message, p: err.params, s: String(err) }).includes(TOKEN));
        return true;
      });
    }
  });

  test('429: waits as long as deSEC says, then asks again', async () => {
    const { fetchImpl, calls } = fakeFetch({ [DESEC_BASE]: (n) => (n === 1 ? DESEC.throttled : ok(DESEC_LISTING)) });
    const { waits, sleepImpl } = fakeSleep();
    const progress = [];
    const out = await fetchZone('desec', 'example.com', TOKEN, { fetchImpl, sleepImpl, onProgress: (p) => progress.push(p) });
    assert.equal(calls.length, 2);
    assert.deepEqual(longWaits(waits), [3000]);
    assert.deepEqual(progress.filter((p) => p.phase === 'wait').map((p) => p.waitMs), [3000]);
    assert.equal(out.records, DESEC_LISTING.length);
  });

  test('429 again and again: gives up after three waits with the time to wait', async () => {
    const { fetchImpl, calls } = fakeFetch({ [DESEC_BASE]: DESEC.throttled });
    const { waits, sleepImpl } = fakeSleep();
    await assert.rejects(fetchZone('desec', 'example.com', TOKEN, { fetchImpl, sleepImpl }),
      (err) => err.code === 'rate-limited' && err.params.retryAfterS === 3 && err.params.status === 429);
    assert.equal(calls.length, 4);
    assert.deepEqual(longWaits(waits), [3000, 3000, 3000]);
  });

  test('a wait longer than a minute is not waited out', async () => {
    const long = { status: 429, body: { detail: 'Request was throttled. Expected available in 86400 seconds.' } };
    const { fetchImpl, calls } = fakeFetch({ [DESEC_BASE]: long });
    const { waits, sleepImpl } = fakeSleep();
    await assert.rejects(fetchZone('desec', 'example.com', TOKEN, { fetchImpl, sleepImpl }),
      (err) => err.code === 'rate-limited' && err.params.retryAfterS === 86400);
    assert.deepEqual([calls.length, waits], [1, []]);
    assert.ok(86400 * 1000 > MAX_WAIT_MS);
  });

  test('an answer that is not an RRset listing is a response error', async () => {
    for (const body of [{ detail: 'odd' }, [{ name: 'x' }], null]) {
      const { fetchImpl } = fakeFetch({ [DESEC_BASE]: body === null ? { status: 200, raw: '<html>' } : ok(body) });
      await assert.rejects(fetchZone('desec', 'example.com', TOKEN, { fetchImpl }), (err) => err.code === 'response', JSON.stringify(body));
    }
  });
});

describe('DigitalOcean', () => {
  const page = (n) => `${DO_BASE}?per_page=200&page=${n}`;

  test('every page until meta.total, with a Bearer token; one merged listing', async () => {
    const { fetchImpl, calls } = fakeFetch({ [page(1)]: ok(DO_PAGE1), [page(2)]: ok(DO_PAGE2) });
    const out = await fetchZone('digitalocean', 'example.com', TOKEN, { fetchImpl, sleepImpl: fakeSleep().sleepImpl });
    assert.deepEqual(calls.map((c) => c.url), [page(1), page(2)]);
    assert.ok(calls.every((c) => c.init.headers.authorization === `Bearer ${TOKEN}` && c.init.redirect === 'error'));
    assert.deepEqual([out.format, out.records, out.total, out.partial], ['digitalocean-api', 17, 17, false]);
    const z = parseZone(out.text, { origin: out.domain });
    assert.deepEqual([z.format, z.origin, z.records.length, z.partial], ['digitalocean-api', 'example.com', 16, false]);
    assert.ok(!z.warnings.some((w) => w.code === 'JSON_PAGES_MERGED'), 'the pages arrive merged');
  });

  test('a listing without meta.total follows links.pages.next; an empty page ends it', async () => {
    const strip = (p) => ({ domain_records: p.domain_records, links: p.links });
    const { fetchImpl, calls } = fakeFetch({ [page(1)]: ok(strip(DO_PAGE1)), [page(2)]: ok(strip(DO_PAGE2)) });
    const out = await fetchZone('digitalocean', 'example.com', TOKEN, { fetchImpl, sleepImpl: fakeSleep().sleepImpl });
    assert.deepEqual([calls.length, out.records, out.total, out.partial], [2, 17, 17, false]);
    const empty = fakeFetch({ [page(1)]: ok({ domain_records: [], links: {}, meta: { total: 0 } }) });
    const none = await fetchZone('digitalocean', 'example.com', TOKEN, { fetchImpl: empty.fetchImpl });
    assert.deepEqual([empty.calls.length, none.records], [1, 0]);
  });

  test('401 / 403 (no domain:read scope) / 404 with DigitalOcean\'s message', async () => {
    for (const [key, code] of [['unauthorized', 'auth'], ['forbidden', 'forbidden'], ['not-found', 'not-found']]) {
      const { fetchImpl } = fakeFetch({ [page(1)]: DO[key] });
      await assert.rejects(fetchZone('digitalocean', 'example.com', TOKEN, { fetchImpl }),
        (err) => err.code === code && err.params.detail === DO[key].body.message && err.params.status === DO[key].status, key);
    }
  });

  test('429 without a readable wait: a fixed pause, then the same page again', async () => {
    const { fetchImpl, calls } = fakeFetch({ [page(1)]: (n) => (n === 1 ? DO['too-many-requests'] : ok(DO_PAGE1)), [page(2)]: ok(DO_PAGE2) });
    const { waits, sleepImpl } = fakeSleep();
    const out = await fetchZone('digitalocean', 'example.com', TOKEN, { fetchImpl, sleepImpl });
    assert.deepEqual(calls.map((c) => c.url), [page(1), page(1), page(2)]);
    assert.deepEqual(longWaits(waits), [DEFAULT_WAIT_MS]);
    assert.equal(out.records, 17);
  });

  test('a Retry-After the page can read is honoured', async () => {
    const limited = { ...DO['too-many-requests'], headers: { 'content-type': 'application/json', 'retry-after': '5' } };
    const { fetchImpl } = fakeFetch({ [page(1)]: (n) => (n === 1 ? limited : ok(DO_PAGE1)), [page(2)]: ok(DO_PAGE2) });
    const { waits, sleepImpl } = fakeSleep();
    await fetchZone('digitalocean', 'example.com', TOKEN, { fetchImpl, sleepImpl });
    assert.deepEqual(longWaits(waits), [5000]);
  });
});

describe('a fetched zone is analysed like a dropped one', () => {
  test('lint, scan seeds, the live check plan and the New name servers plan work on both providers\' zones', async () => {
    const desec = fakeFetch({ [DESEC_BASE]: ok(DESEC_LISTING) });
    const doFake = fakeFetch({ [`${DO_BASE}?per_page=200&page=1`]: ok(DO_PAGE1), [`${DO_BASE}?per_page=200&page=2`]: ok(DO_PAGE2) });
    const outs = [
      await fetchZone('desec', 'example.com', TOKEN, { fetchImpl: desec.fetchImpl }),
      await fetchZone('digitalocean', 'example.com', TOKEN, { fetchImpl: doFake.fetchImpl, sleepImpl: fakeSleep().sleepImpl })
    ];
    for (const out of outs) {
      const z = parseZone(out.text, { origin: out.domain });
      assert.equal(z.fatal, null, out.provider);
      const lint = lintZone(z);
      const seeds = zoneScanInput(z);
      const drift = planDrift(z);
      const parity = planParity(z, { nameservers: ['ns1.example.net'] });
      assert.ok(Array.isArray(lint.findings), out.provider);
      assert.equal(seeds.origin, 'example.com');
      assert.ok(seeds.names.includes('www.example.com'), out.provider);
      assert.ok(drift.queries > 0 && drift.rrsets > 0, out.provider);
      assert.ok(parity.probes > 0, out.provider);
    }
    // The deSEC fixture's internal address is linted like a dropped file's.
    assert.ok(lintZone(parseZone(outs[0].text)).findings.some((f) => f.code === 'PRIVATE_IP'));
  });
});

describe('transport', () => {
  test('a CORS or network failure, a timeout and a cancel', async () => {
    const net = fakeFetch({ [DESEC_BASE]: new TypeError('Failed to fetch') });
    await assert.rejects(fetchZone('desec', 'example.com', TOKEN, { fetchImpl: net.fetchImpl }), (err) => err.code === 'network');
    const hang = (url, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true }));
    await assert.rejects(fetchZone('desec', 'example.com', TOKEN, { fetchImpl: hang, timeoutMs: 20 }), (err) => err.code === 'timeout');
    const ctl = new AbortController();
    const p = fetchZone('desec', 'example.com', TOKEN, { fetchImpl: hang, signal: ctl.signal });
    ctl.abort();
    await assert.rejects(p, (err) => err.name === 'AbortError');
  });

  test('the token appears in no request URL, progress event or error', async () => {
    const seen = [];
    const { fetchImpl, calls } = fakeFetch({ [DESEC_BASE]: DESEC['invalid-token'] });
    await assert.rejects(fetchZone('desec', 'example.com', TOKEN, { fetchImpl, onProgress: (p) => seen.push(p) }), (err) => {
      seen.push({ message: err.message, params: err.params, stack: err.stack });
      return true;
    });
    assert.ok(!JSON.stringify(seen).includes(TOKEN));
    assert.ok(calls.every((c) => !c.url.includes(TOKEN)));
  });

  test('an observer that throws does not break the fetch', async () => {
    const { fetchImpl } = fakeFetch({ [DESEC_BASE]: ok(DESEC_LISTING) });
    const out = await fetchZone('desec', 'example.com', TOKEN, { fetchImpl, onProgress: () => { throw new Error('boom'); } });
    assert.equal(out.records, DESEC_LISTING.length);
  });
});
