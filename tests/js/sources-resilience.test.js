// Resilience tests for assets/js/lib/sources.js — no network: fetch is mocked,
// waiting goes through an injected `sleepImpl` that records the delays.
// Covers crt.sh backoff / fallback query forms / outage classification,
// ip.thc.org pagination + spacing, quota (rate-limit) classification per source
// and sourceHealthSummary().
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  SOURCES, fetchSource, fetchAllSources, sourceHealthSummary, SOURCE_HEALTH_STATES
} from '../../assets/js/lib/sources.js';
import { AbortError } from '../../assets/js/lib/util.js';

/**
 * Mock fetch routing by URL prefix. A handler gets (url, n, init) where n is
 * the 1-based call number and returns a Response, a JSON value, or throws.
 */
function router(routes) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init, method: init.method || 'GET', body: init.body });
    for (const [prefix, handler] of Object.entries(routes)) {
      if (url.startsWith(prefix)) {
        const out = await handler(url, calls.length, init);
        if (out instanceof Response) return out;
        return Response.json(out);
      }
    }
    throw new TypeError(`unexpected URL ${url}`);
  };
  return { fetchImpl, calls };
}

/** sleepImpl that resolves at once (still honouring an already-aborted signal) and records delays. */
function recorder() {
  const delays = [];
  const sleepImpl = async (ms, signal) => {
    delays.push(ms);
    if (signal && signal.aborted) throw new AbortError();
  };
  return { delays, sleepImpl };
}

const CRT = 'https://crt.sh/';
const CS = 'https://api.certspotter.com/v1/issuances';
const HT = 'https://api.hackertarget.com/hostsearch/';
const AN = 'https://anubisdb.com/anubis/subdomains/';
const OTX = 'https://otx.alienvault.com/api/v1/indicators/domain/';
const THC = 'https://ip.thc.org/api/v1/lookup/subdomains';

const bad = (status, body = `<html><head><title>${status}</title></head></html>`, headers = {}) =>
  new Response(body, { status, headers: { 'content-type': 'text/html', ...headers } });

const crtRow = (id, names, extra = {}) => ({
  issuer_ca_id: 1, issuer_name: 'C=US, O=Google Trust Services, CN=WE1', common_name: names[0],
  name_value: names.join('\n'), id, entry_timestamp: '2026-07-22T06:10:51.123',
  not_before: '2026-07-22T05:10:51', not_after: '2026-10-20T05:10:50', serial_number: `0${id}`, result_count: 2, ...extra
});

const SUBDOMAINS_URL = 'https://crt.sh/?q=%25.example.net&output=json&exclude=expired&deduplicate=Y';
const IDENTITY_URL = 'https://crt.sh/?q=example.net&output=json&exclude=expired&deduplicate=Y';

/* ------------------------------------------------------------------------ */

describe('crt.sh resilience', () => {
  test('502 → 502 → 200: retried with exponential backoff + jitter, not partial', async () => {
    const { fetchImpl, calls } = router({
      [CRT]: (url, n) => (n <= 2 ? bad(502) : [crtRow(11, ['*.example.net', 'example.net'])])
    });
    const { delays, sleepImpl } = recorder();
    const events = [];
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl, onEvent: (e) => events.push(e) });
    assert.equal(r.ok, true);
    assert.equal(r.partial, false);
    assert.equal(r.error, null);
    assert.equal(r.attempts, 3);
    assert.equal(r.queryForm, 'subdomains');
    assert.deepEqual(calls.map((c) => c.url), [SUBDOMAINS_URL, SUBDOMAINS_URL, SUBDOMAINS_URL]);
    assert.deepEqual(r.names, ['example.net']);
    assert.deepEqual(r.wildcardBases, ['example.net'], 'wildcard-only certificate → wildcard base for brute force');
    // base 4 s doubling, ±25 % jitter
    assert.equal(delays.length, 2);
    assert.ok(delays[0] >= 3000 && delays[0] <= 5000, `first delay ${delays[0]}`);
    assert.ok(delays[1] >= 6000 && delays[1] <= 10000, `second delay ${delays[1]}`);
    assert.deepEqual(events.map((e) => [e.source, e.domain, e.type, e.attempt, e.maxAttempts, e.reason]), [
      ['crtsh', 'example.net', 'retry', 2, 5, 'HTTP 502'],
      ['crtsh', 'example.net', 'retry', 3, 5, 'HTTP 502']
    ]);
    assert.deepEqual(events.map((e) => e.delayMs), delays);
  });

  test('network TypeErrors (CORS-less error pages) are retried like 5xx', async () => {
    const { fetchImpl, calls } = router({
      [CRT]: (url, n) => {
        if (n <= 2) throw new TypeError('Failed to fetch');
        return [crtRow(5, ['api.example.net'])];
      }
    });
    const { delays, sleepImpl } = recorder();
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl });
    assert.equal(r.ok, true);
    assert.equal(calls.length, 3);
    assert.equal(delays.length, 2);
    assert.deepEqual(r.names, ['api.example.net']);
  });

  test('a total outage: 4 tries, then the identity search once (~60 s of waiting), then "unavailable"', async () => {
    const { fetchImpl, calls } = router({ [CRT]: (url, n) => (n % 2 ? bad(502) : Promise.reject(new TypeError('Failed to fetch'))) });
    const { delays, sleepImpl } = recorder();
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl });
    assert.equal(r.ok, false);
    assert.equal(r.errorKind, 'unavailable');
    assert.deepEqual(calls.map((c) => c.url), [SUBDOMAINS_URL, SUBDOMAINS_URL, SUBDOMAINS_URL, SUBDOMAINS_URL, IDENTITY_URL]);
    assert.equal(r.attempts, 5);
    assert.match(r.error, /^crt\.sh is temporarily unavailable: 5 attempts over \d+ s failed \(HTTP 502 ×3, network error ×2\)\. Its error pages carry no CORS header/);
    assert.equal(delays.length, 4);
    const ranges = [[3000, 5000], [6000, 10000], [12000, 20000], [24000, 40000]];
    delays.forEach((d, i) => assert.ok(d >= ranges[i][0] && d <= ranges[i][1], `delay ${i} = ${d}`));
    const total = delays.reduce((a, b) => a + b, 0);
    assert.ok(total >= 45000 && total <= 75000, `total wait ${total}`);
    assert.equal(r.quota, null, 'an outage is not a quota problem');
  });

  test('fallback query form: subdomain search keeps failing, identity search answers → partial', async () => {
    const { fetchImpl, calls } = router({
      [CRT]: (url) => (url.includes('%25.') ? bad(503) : [crtRow(7, ['example.net', 'www.example.net'])])
    });
    const { sleepImpl } = recorder();
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl });
    assert.equal(calls.length, 5);
    assert.equal(calls[4].url, IDENTITY_URL);
    assert.equal(r.ok, true);
    assert.equal(r.partial, true);
    assert.equal(r.queryForm, 'identity');
    assert.equal(r.errorKind, 'unavailable');
    assert.match(r.error, /^crt\.sh subdomain search failed \(HTTP 503 ×4\); these results come from the lighter identity search/);
    assert.deepEqual(r.names, ['example.net', 'www.example.net']);
    assert.equal(r.certs.length, 1);
  });

  test('a timed-out query form is not repeated: the next attempt uses the identity search', async () => {
    const { fetchImpl, calls } = router({
      [CRT]: (url) => (url.includes('%25.') ? new Promise(() => {}) : [crtRow(9, ['example.net'])])
    });
    const { delays, sleepImpl } = recorder();
    const events = [];
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl, timeoutMs: 30, onEvent: (e) => events.push(e) });
    assert.deepEqual(calls.map((c) => c.url), [SUBDOMAINS_URL, IDENTITY_URL]);
    assert.equal(delays.length, 1);
    // the skipped (timed-out) form is not counted: this retry is the last possible attempt
    assert.deepEqual(events.map((e) => [e.type, e.attempt, e.maxAttempts, e.form, e.reason]), [['retry', 2, 2, 'identity', 'timed out']]);
    assert.equal(r.ok, true);
    assert.equal(r.partial, true);
    assert.equal(r.errorKind, 'timeout');
    assert.match(r.error, /\(timed out\)/);

    // every form timing out → 'timeout' (distinct from 'unavailable')
    const { fetchImpl: f2, calls: c2 } = router({ [CRT]: () => new Promise(() => {}) });
    const r2 = await fetchSource('crtsh', 'example.net', { fetchImpl: f2, sleepImpl, timeoutMs: 30 });
    assert.equal(c2.length, 2);
    assert.equal(r2.ok, false);
    assert.equal(r2.errorKind, 'timeout');
    assert.match(r2.error, /^crt\.sh timed out: no response within 0 s \(2 attempts: subdomain search, identity search\)/);
  });

  test('includeExpired: full history twice, then unexpired (partial), deduplicate=Y everywhere', async () => {
    const { fetchImpl, calls } = router({
      [CRT]: (url) => (url.includes('exclude=expired') ? [crtRow(3, ['a.example.net'])] : bad(502))
    });
    const { sleepImpl } = recorder();
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl, includeExpired: true });
    assert.deepEqual(calls.map((c) => c.url), [
      'https://crt.sh/?q=%25.example.net&output=json&deduplicate=Y',
      'https://crt.sh/?q=%25.example.net&output=json&deduplicate=Y',
      SUBDOMAINS_URL
    ]);
    assert.equal(r.partial, true);
    assert.equal(r.queryForm, 'subdomains');
    assert.equal(r.error, 'Expired certificates omitted: the full crt.sh history failed (HTTP 502 ×2)');
  });

  test('abort during a backoff wait rejects promptly with AbortError', async () => {
    const { fetchImpl, calls } = router({ [CRT]: () => bad(502) });
    const ctl = new AbortController();
    const started = Date.now();
    // default util.sleep with a 60 s base delay: only the abort can end the wait
    const p = fetchSource('crtsh', 'example.net', { fetchImpl, signal: ctl.signal, retryDelayMs: 60000 });
    setTimeout(() => ctl.abort(), 30);
    await assert.rejects(p, (e) => e instanceof AbortError);
    assert.equal(calls.length, 1);
    assert.ok(Date.now() - started < 2000, 'did not wait for the backoff');

    // an injected sleep that ignores the signal: the abort is still honoured right after it
    const c2 = new AbortController();
    const lazySleep = async () => { c2.abort(); };
    const { fetchImpl: f2, calls: k2 } = router({ [CRT]: () => bad(502) });
    await assert.rejects(fetchSource('crtsh', 'example.net', { fetchImpl: f2, signal: c2.signal, sleepImpl: lazySleep }),
      (e) => e instanceof AbortError);
    assert.equal(k2.length, 1);
  });

  test('429: a short Retry-After is honoured exactly; a long one ends the retries as rate-limit', async () => {
    const { fetchImpl, calls } = router({
      [CRT]: (url, n) => (n === 1 ? bad(429, 'slow down', { 'retry-after': '2' }) : [crtRow(1, ['example.net'])])
    });
    const { delays, sleepImpl } = recorder();
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl });
    assert.equal(r.ok, true);
    assert.equal(calls.length, 2);
    assert.deepEqual(delays, [2000]);

    const { fetchImpl: f2, calls: c2 } = router({ [CRT]: () => bad(429, 'Too Many Requests', { 'retry-after': '3600' }) });
    const r2 = await fetchSource('crtsh', 'example.net', { fetchImpl: f2, sleepImpl });
    assert.equal(c2.length, 1);
    assert.equal(r2.errorKind, 'rate-limit');
    assert.equal(r2.quota.limited, true);
    assert.equal(r2.quota.retryAfterMs, 3600000);
    assert.ok(r2.quota.resetAt instanceof Date);

    // 429 on every attempt (short Retry-After) → rate-limit, not 'unavailable'
    const { fetchImpl: f3, calls: c3 } = router({ [CRT]: () => bad(429, 'x', { 'retry-after': '1' }) });
    const r3 = await fetchSource('crtsh', 'example.net', { fetchImpl: f3, sleepImpl });
    assert.equal(c3.length, 5);
    assert.equal(r3.errorKind, 'rate-limit');
  });

  test('overall budget (~3 min of requests + waits): no attempt starts beyond it', async () => {
    // Retry-After 50 s is honoured (≤ 60 s) but the 4th wait would end past 180 s → stop after 4 requests
    const { fetchImpl, calls } = router({ [CRT]: () => bad(429, 'x', { 'retry-after': '50' }) });
    const { delays, sleepImpl } = recorder();
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl });
    assert.equal(calls.length, 4);
    assert.deepEqual(delays, [50000, 50000, 50000]);
    assert.equal(r.errorKind, 'rate-limit');
    assert.match(r.error, /^crt\.sh rate limit \(HTTP 429 ×4\)\.$/);
  });

  test('the Apache "404 Not Found" page crt.sh serves while flapping is retried like a 5xx', async () => {
    const apache404 = '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title>404 Not Found</title></head>'
      + '<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p><address>Apache Server at crt.sh Port 443</address></body></html>';
    const { fetchImpl, calls } = router({ [CRT]: (url, n) => (n === 1 ? bad(404, apache404) : [crtRow(2, ['www.example.net'])]) });
    const { sleepImpl } = recorder();
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl });
    assert.equal(calls.length, 2);
    assert.equal(r.ok, true);
    assert.deepEqual(r.names, ['www.example.net']);
  });

  test('other 4xx and unparsable bodies are not retried', async () => {
    const { sleepImpl, delays } = recorder();
    const { fetchImpl, calls } = router({ [CRT]: () => bad(400, 'bad request') });
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl });
    assert.equal(calls.length, 1);
    assert.equal(r.errorKind, 'http');
    const { fetchImpl: f2, calls: c2 } = router({ [CRT]: () => new Response('<html>maintenance</html>') });
    const r2 = await fetchSource('crtsh', 'example.net', { fetchImpl: f2, sleepImpl });
    assert.equal(c2.length, 1);
    assert.equal(r2.errorKind, 'parse');
    assert.equal(delays.length, 0);
  });

  test('a throwing onEvent observer never breaks the fetch', async () => {
    const { fetchImpl } = router({ [CRT]: (url, n) => (n === 1 ? bad(502) : []) });
    const { sleepImpl } = recorder();
    const r = await fetchSource('crtsh', 'example.net', { fetchImpl, sleepImpl, onEvent: () => { throw new Error('ui'); } });
    assert.equal(r.ok, true);
  });
});

/* ------------------------------------------------------------------------ */

describe('ip.thc.org', () => {
  const page = (names, next, total = 250) => ({
    comment: 'Free Service!, Do not abuse', processed_domain: 'example.net', matching_records: total,
    domains: names.map(([domain, last]) => ({ domain, last_seen_on: last })), next_page_state: next
  });

  test('catalogue entry', () => {
    const def = SOURCES.find((s) => s.id === 'thc');
    assert.equal(def.homepage, 'https://ip.thc.org');
    assert.equal(def.noteKey, 'source.thc.note');
    assert.equal(def.defaultEnabled, true);
    assert.equal(def.providesIps, false);
    assert.equal(def.providesCerts, false);
  });

  test('POST text/plain JSON (no preflight), pagination with next_page_state, ≥2 s spacing, last_seen_on', async () => {
    const pages = [
      page([['example.net', '2026-09-22'], ['API.example.net', '2024-12-11'], ['x.other.org', '2026-01-01']], 'state-1'),
      page([['cdn.example.net', '2025-08-18'], ['api.example.net', '2025-01-02']], 'state-2'),
      page([['adm.example.net', '2024-12-11']], '')
    ];
    const { fetchImpl, calls } = router({ [THC]: (url, n) => pages[n - 1] });
    const { delays, sleepImpl } = recorder();
    const events = [];
    const r = await fetchSource('thc', 'example.net', { fetchImpl, sleepImpl, onEvent: (e) => events.push(e) });
    assert.equal(r.ok, true);
    assert.equal(calls.length, 3);
    for (const c of calls) {
      assert.equal(c.url, THC);
      assert.equal(c.method, 'POST');
      assert.equal(c.init.headers['content-type'], 'text/plain;charset=UTF-8', 'CORS-safelisted type → no preflight');
      assert.equal(c.init.credentials, 'omit');
    }
    assert.deepEqual(calls.map((c) => JSON.parse(c.body)), [
      { domain: 'example.net', limit: 100 },
      { domain: 'example.net', limit: 100, page_state: 'state-1' },
      { domain: 'example.net', limit: 100, page_state: 'state-2' }
    ]);
    assert.deepEqual(delays, [2000, 2000]);
    assert.deepEqual(events.map((e) => [e.type, e.page, e.delayMs]), [['page', 2, 2000], ['page', 3, 2000]]);
    assert.deepEqual(r.names, ['example.net', 'adm.example.net', 'api.example.net', 'cdn.example.net']);
    assert.deepEqual(r.lastSeen, {
      'example.net': '2026-09-22', 'adm.example.net': '2024-12-11', 'api.example.net': '2025-01-02', 'cdn.example.net': '2025-08-18'
    }, 'latest day per name, sorted');
    assert.equal(r.available, 250);
    assert.equal(r.rows, 6);
    assert.equal(r.truncated, false);
    assert.equal(r.attempts, 3);
  });

  test('stops after 10 pages (truncated) and on an empty page', async () => {
    let n = 0;
    const { fetchImpl, calls } = router({ [THC]: () => { n += 1; return page([[`h${n}.github.com`, '2024-12-11']], `s${n}`, 4293); } });
    const { delays, sleepImpl } = recorder();
    const r = await fetchSource('thc', 'github.com', { fetchImpl, sleepImpl });
    assert.equal(calls.length, 10);
    assert.equal(delays.length, 9);
    assert.equal(r.truncated, true);
    assert.equal(r.available, 4293);
    assert.equal(r.names.length, 10);

    const { fetchImpl: f2, calls: c2 } = router({ [THC]: (url, k) => (k === 1 ? page([['a.github.com', '2024-12-11']], 'more') : page([], 'still-more')) });
    const r2 = await fetchSource('thc', 'github.com', { fetchImpl: f2, sleepImpl });
    assert.equal(c2.length, 2);
    assert.equal(r2.truncated, false);
  });

  test('a single page with no records; null domains', async () => {
    const { fetchImpl } = router({ [THC]: () => ({ matching_records: 0, domains: null, next_page_state: '' }) });
    const r = await fetchSource('thc', 'example.net', { fetchImpl });
    assert.equal(r.ok, true);
    assert.deepEqual(r.names, []);
    assert.equal(r.available, 0);
  });

  test('429 on the first page → rate-limit; on a later page → partial result with quota', async () => {
    const { sleepImpl } = recorder();
    const limited = () => new Response(JSON.stringify({ status: 'error', error: 'rate limit exceeded' }), { status: 429 });
    const { fetchImpl, calls } = router({ [THC]: limited });
    const r = await fetchSource('thc', 'example.net', { fetchImpl, sleepImpl });
    assert.equal(calls.length, 1, 'never retried');
    assert.equal(r.ok, false);
    assert.equal(r.errorKind, 'rate-limit');
    assert.equal(r.error, 'HTTP 429: rate limit exceeded');
    assert.equal(r.quota.limited, true);
    assert.equal(r.quota.period, 'minutes');
    assert.equal(r.quota.hintKey, 'source.quota.minutes');

    const { fetchImpl: f2 } = router({ [THC]: (url, n) => (n === 1 ? page([['a.example.net', '2024-12-11']], 'next') : limited()) });
    const r2 = await fetchSource('thc', 'example.net', { fetchImpl: f2, sleepImpl });
    assert.equal(r2.ok, true);
    assert.equal(r2.partial, true);
    assert.equal(r2.errorKind, 'rate-limit');
    assert.deepEqual(r2.names, ['a.example.net']);
    assert.equal(r2.quota.limited, true);
  });

  test('service errors: HTTP 406 invalid domain, 200 {status:"error"}', async () => {
    const { fetchImpl } = router({ [THC]: () => new Response(JSON.stringify({ status: 'error', error: 'invalid domain' }), { status: 406 }) });
    const r = await fetchSource('thc', 'example.net', { fetchImpl });
    assert.equal(r.errorKind, 'http');
    assert.equal(r.error, 'HTTP 406: invalid domain');

    const { fetchImpl: f2 } = router({ [THC]: () => ({ status: 'error', error: 'Too many requests, slow down' }) });
    const r2 = await fetchSource('thc', 'example.net', { fetchImpl: f2 });
    assert.equal(r2.errorKind, 'rate-limit');
    assert.equal(r2.error, 'ip.thc.org: Too many requests, slow down');

    const { fetchImpl: f3 } = router({ [THC]: () => ['not', 'an', 'object'] });
    const r3 = await fetchSource('thc', 'example.net', { fetchImpl: f3 });
    assert.equal(r3.errorKind, 'parse');
  });

  test('abort during page spacing rejects with AbortError', async () => {
    const { fetchImpl, calls } = router({ [THC]: () => page([['a.example.net', '2024-12-11']], 'next') });
    const ctl = new AbortController();
    const p = fetchSource('thc', 'example.net', { fetchImpl, signal: ctl.signal }); // real 2 s sleep
    setTimeout(() => ctl.abort(), 30);
    await assert.rejects(p, (e) => e instanceof AbortError);
    assert.equal(calls.length, 1);
  });
});

/* ------------------------------------------------------------------------ */

describe('quota / rate-limit classification', () => {
  test('HackerTarget: 200 "API count exceeded" → rate-limit, daily quota hint, no retry', async () => {
    const { fetchImpl, calls } = router({ [HT]: () => new Response('API count exceeded - Increase Quota with Membership') });
    const r = await fetchSource('hackertarget', 'example.net', { fetchImpl });
    assert.equal(calls.length, 1);
    assert.equal(r.ok, false);
    assert.equal(r.errorKind, 'rate-limit');
    assert.equal(r.error, 'HackerTarget: API count exceeded - Increase Quota with Membership');
    assert.deepEqual({ ...r.quota, resetAt: null }, {
      limited: true, period: 'day', retryAfterMs: null, resetAt: null, limit: null, remaining: null,
      resetHint: 'Daily free quota for your IP is used up (about 50 requests); it resets within 24 hours.',
      hintKey: 'source.quota.day'
    });

    // same text with a non-2xx status
    const { fetchImpl: f2 } = router({ [HT]: () => new Response('API count exceeded - Increase Quota with Membership', { status: 429 }) });
    const r2 = await fetchSource('hackertarget', 'example.net', { fetchImpl: f2 });
    assert.equal(r2.errorKind, 'rate-limit');
    assert.equal(r2.quota.period, 'day');

    const { fetchImpl: f3 } = router({ [HT]: () => new Response('API count exceeded', { status: 403 }) });
    const r3 = await fetchSource('hackertarget', 'example.net', { fetchImpl: f3 });
    assert.equal(r3.errorKind, 'rate-limit');
  });

  test('OTX: 429 {"detail"} and 200 {"detail"} → rate-limit, no retry', async () => {
    const detail = 'Anonymous access to this endpoint is limited. Please authenticate.';
    const { fetchImpl, calls } = router({ [OTX]: () => new Response(JSON.stringify({ detail }), { status: 429 }) });
    const r = await fetchSource('otx', 'example.net', { fetchImpl });
    assert.equal(calls.length, 1);
    assert.equal(r.errorKind, 'rate-limit');
    assert.equal(r.error, `HTTP 429: ${detail}`);
    assert.equal(r.quota.limited, true);
    assert.equal(r.quota.hintKey, 'source.quota.later');

    const { fetchImpl: f2 } = router({ [OTX]: () => ({ detail }) });
    const r2 = await fetchSource('otx', 'example.net', { fetchImpl: f2 });
    assert.equal(r2.errorKind, 'rate-limit');
    assert.equal(r2.error, `OTX: ${detail}`);

    const { fetchImpl: f3 } = router({ [OTX]: () => ({ detail: 'Something else' }) });
    const r3 = await fetchSource('otx', 'example.net', { fetchImpl: f3 });
    assert.equal(r3.errorKind, 'parse');
  });

  test('OTX: lastSeen per name from passive DNS', async () => {
    const { fetchImpl } = router({
      [OTX]: () => ({
        passive_dns: [
          { hostname: 'api.example.net', address: '203.0.113.66', record_type: 'A', first: '2024-01-01T00:00:00', last: '2025-03-01T10:00:00' },
          { hostname: 'api.example.net', address: '104.16.1.1', record_type: 'A', first: '2023-01-01T00:00:00', last: '2023-06-01T00:00:00' },
          { hostname: 'ftp.example.net', address: 'example.net', record_type: 'CNAME', last: '2026-09-01T00:00:00' }
        ]
      })
    });
    const r = await fetchSource('otx', 'example.net', { fetchImpl });
    assert.deepEqual(r.lastSeen, { 'api.example.net': '2025-03-01', 'ftp.example.net': '2026-09-01' });
    assert.deepEqual(r.ipHints.map((h) => h.ip), ['104.16.1.1', '203.0.113.66']);
  });

  test('Cert Spotter: 429 with Retry-After → rate-limit, hourly quota, retryAfterMs, resetAt', async () => {
    const { fetchImpl, calls } = router({
      [CS]: () => new Response(JSON.stringify({ code: 'rate_limited', message: 'You have exceeded the rate limit.' }),
        { status: 429, headers: { 'retry-after': '3600' } })
    });
    const before = Date.now();
    const r = await fetchSource('certspotter', 'example.net', { fetchImpl });
    assert.equal(calls.length, 1);
    assert.equal(r.errorKind, 'rate-limit');
    assert.equal(r.quota.period, 'hour');
    assert.equal(r.quota.retryAfterMs, 3600000);
    assert.ok(Math.abs(r.quota.resetAt.getTime() - (before + 3600000)) < 5000);
    assert.equal(r.quota.hintKey, 'source.quota.hour');
  });

  test('Cert Spotter: readable X-RateLimit headers → quota info; remaining 0 skips further pages', async () => {
    const iss = (id, names) => ({ id: String(id), cert_sha256: String(id).padStart(64, 'b'), dns_names: names, not_before: '2026-07-22T05:10:51Z', not_after: '2026-10-20T05:10:50Z' });
    const { fetchImpl, calls } = router({
      [CS]: (url) => new Response(JSON.stringify(url.includes('after=') ? [] : [iss(1, ['*.example.net', 'example.net'])]), {
        headers: { 'x-ratelimit-limit': '10', 'x-ratelimit-remaining': '5' }
      })
    });
    const r = await fetchSource('certspotter', 'example.net', { fetchImpl });
    assert.equal(calls.length, 2);
    assert.equal(r.ok, true);
    assert.equal(r.partial, false);
    assert.deepEqual(r.names, ['example.net']);
    assert.deepEqual(r.wildcardBases, ['example.net'], 'wildcard-only certificate populates wildcardBases');
    assert.deepEqual({ limited: r.quota.limited, limit: r.quota.limit, remaining: r.quota.remaining, hintKey: r.quota.hintKey },
      { limited: false, limit: 10, remaining: 5, hintKey: null });

    const { fetchImpl: f2, calls: c2 } = router({
      [CS]: () => new Response(JSON.stringify([iss(2, ['a.example.net'])]), {
        headers: { 'x-ratelimit-limit': '10', 'x-ratelimit-remaining': '0', link: '<https://api.certspotter.com/issuances?after=2>; rel="next"' }
      })
    });
    const r2 = await fetchSource('certspotter', 'example.net', { fetchImpl: f2 });
    assert.equal(c2.length, 1, 'the next page would only earn a 429');
    assert.equal(r2.ok, true);
    assert.equal(r2.partial, true);
    assert.equal(r2.errorKind, 'rate-limit');
    assert.equal(r2.quota.limited, true);
    assert.equal(r2.quota.remaining, 0);
    assert.deepEqual(r2.names, ['a.example.net']);
  });

  test('Anubis: [] is a clean empty answer; error objects; one retry on 5xx; wildcard spellings normalised', async () => {
    const { fetchImpl } = router({ [AN]: () => [] });
    const r = await fetchSource('anubis', 'example.net', { fetchImpl });
    assert.equal(r.ok, true);
    assert.equal(r.error, null);
    assert.deepEqual(r.names, []);

    const { fetchImpl: f2 } = router({ [AN]: () => ({ detail: 'Too many requests' }) });
    const r2 = await fetchSource('anubis', 'example.net', { fetchImpl: f2 });
    assert.equal(r2.errorKind, 'rate-limit');
    assert.equal(r2.quota.limited, true);

    const { delays, sleepImpl } = recorder();
    const { fetchImpl: f3, calls: c3 } = router({ [AN]: (url, n) => (n === 1 ? bad(502) : ['app.example.net']) });
    const r3 = await fetchSource('anubis', 'example.net', { fetchImpl: f3, sleepImpl });
    assert.equal(c3.length, 2);
    assert.deepEqual(delays, [2000]);
    assert.deepEqual(r3.names, ['app.example.net']);

    const { fetchImpl: f4, calls: c4 } = router({ [AN]: () => bad(503) });
    const r4 = await fetchSource('anubis', 'example.net', { fetchImpl: f4, sleepImpl });
    assert.equal(c4.length, 2, 'only one retry');
    assert.equal(r4.errorKind, 'http');

    const { fetchImpl: f5 } = router({ [AN]: () => ['.a.example.net', '**.b.example.net', '*.*.c.example.net', '*.D.example.net.', 'e.example.net'] });
    const r5 = await fetchSource('anubis', 'example.net', { fetchImpl: f5 });
    assert.deepEqual(r5.wildcardBases, ['a.example.net', 'b.example.net', 'c.example.net', 'd.example.net']);
    assert.deepEqual(r5.names, ['a.example.net', 'b.example.net', 'c.example.net', 'd.example.net', 'e.example.net']);
  });

  test('successful results without readable rate headers carry quota: null', async () => {
    const { fetchImpl } = router({ [AN]: () => ['x.example.net'] });
    const r = await fetchSource('anubis', 'example.net', { fetchImpl });
    assert.equal(r.quota, null);
    assert.deepEqual(r.lastSeen, {});
    assert.equal(r.truncated, false);
    assert.equal(r.available, null);
    assert.equal(r.queryForm, null);
    assert.equal(r.attempts, 1);
  });
});

/* ------------------------------------------------------------------------ */

describe('sourceHealthSummary', () => {
  test('crt.sh down + Cert Spotter ok → "unavailable" with the Cert Spotter fallback noted', async () => {
    const { sleepImpl } = recorder();
    const { fetchImpl } = router({
      [CRT]: () => { throw new TypeError('Failed to fetch'); },
      [CS]: (url) => (url.includes('after=') ? [] : [{ id: '1', cert_sha256: 'a'.repeat(64), dns_names: ['*.example.net', 'example.net'] }]),
      [HT]: () => new Response('API count exceeded - Increase Quota with Membership'),
      [AN]: () => [],
      [OTX]: () => new Response(JSON.stringify({ detail: 'Anonymous access to this endpoint is limited.' }), { status: 429 }),
      [THC]: () => ({ matching_records: 1, domains: [{ domain: 'example.net', last_seen_on: '2026-09-20' }], next_page_state: '' })
    });
    const out = await fetchAllSources('example.net', { fetchImpl, sleepImpl });
    const byId = Object.fromEntries(out.health.map((s) => [s.source, s]));
    assert.deepEqual(out.health.map((s) => s.source), ['crtsh', 'certspotter', 'hackertarget', 'anubis', 'otx', 'thc']);
    assert.equal(byId.crtsh.state, 'unavailable');
    assert.equal(byId.crtsh.errorKind, 'unavailable');
    assert.equal(byId.crtsh.fallback, 'certspotter');
    assert.equal(byId.crtsh.message, 'crt.sh is temporarily down; Cert Spotter was used for certificate data');
    assert.equal(byId.crtsh.attempts, 5);
    assert.equal(byId.certspotter.state, 'ok');
    assert.equal(byId.certspotter.fallback, null);
    assert.equal(byId.hackertarget.state, 'rate-limited');
    assert.match(byId.hackertarget.message, /resets within 24 hours/);
    assert.equal(byId.hackertarget.quota.period, 'day');
    assert.equal(byId.anubis.state, 'empty');
    assert.equal(byId.anubis.message, 'No names found');
    assert.equal(byId.otx.state, 'rate-limited');
    assert.equal(byId.thc.state, 'ok');
    assert.equal(byId.thc.message, '1 name');
    assert.deepEqual(sourceHealthSummary(out), out.health, 'accepts the fetchAllSources output too');
    for (const s of out.health) assert.ok(SOURCE_HEALTH_STATES.includes(s.state));
  });

  test('several domains: aggregated state, unique names, per-domain detail; unknown ids last', () => {
    const base = { ipHints: [], certs: [], error: null, errorKind: null, partial: false, elapsedMs: 10, attempts: 1 };
    const results = [
      { ...base, source: 'bogus', domain: 'a.com', ok: false, names: [], error: 'Unknown source "bogus"', errorKind: 'unknown' },
      { ...base, source: 'crtsh', domain: 'a.com', ok: true, names: ['a.com', 'www.a.com'] },
      { ...base, source: 'crtsh', domain: 'b.com', ok: false, names: [], error: 'crt.sh timed out', errorKind: 'timeout', attempts: 2, elapsedMs: 90000 },
      { ...base, source: 'anubis', domain: 'a.com', ok: true, names: ['x.a.com'] },
      { ...base, source: 'anubis', domain: 'b.com', ok: true, names: ['x.a.com', 'y.b.com'], partial: true, error: 'Incomplete: HTTP 502', errorKind: 'http' },
      { ...base, source: 'thc', domain: 'a.com', ok: true, names: ['a.com'], truncated: true, available: 4000 },
      { ...base, source: 'thc', domain: 'b.com', ok: true, names: [], available: 0 }
    ];
    const h = sourceHealthSummary(results);
    assert.deepEqual(h.map((s) => [s.source, s.state]), [['crtsh', 'partial'], ['anubis', 'partial'], ['thc', 'ok'], ['bogus', 'error']]);
    const crt = h[0];
    assert.equal(crt.names, 2);
    assert.equal(crt.attempts, 3);
    assert.equal(crt.elapsedMs, 90000);
    assert.equal(crt.errorKind, 'timeout');
    assert.equal(crt.fallback, null, 'no Cert Spotter result to fall back on');
    assert.deepEqual(crt.domains.map((d) => [d.domain, d.state]), [['a.com', 'ok'], ['b.com', 'timeout']]);
    assert.equal(h[1].names, 2, 'unique names');
    assert.equal(h[2].truncated, true);
    assert.equal(h[2].available, 4000);
    assert.equal(h[2].message, '1 name (page limit reached)');
    assert.equal(h[3].name, 'bogus');
    assert.equal(h[3].homepage, null);
    assert.deepEqual(sourceHealthSummary(null), []);
    assert.deepEqual(sourceHealthSummary([null, 42, {}]), []);
  });

  test('every state, quota hint and the new error kind has EN + TR strings', async () => {
    const i18n = await import('../../assets/js/i18n.js');
    const keys = [
      'error.kind.unavailable', 'source.fallback',
      ...SOURCE_HEALTH_STATES.map((s) => `source.state.${s}`),
      ...['day', 'hour', 'minutes', 'later'].map((p) => `source.quota.${p}`)
    ];
    for (const k of keys) {
      assert.ok(i18n.hasString(k, 'en'), `${k} [en]`);
      assert.ok(i18n.hasString(k, 'tr'), `${k} [tr]`);
    }
  });
});
