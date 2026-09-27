// Unit tests for assets/js/lib/sources.js — no network: fetch is mocked per URL
// with payloads shaped exactly like the real services (probed 2026-09-23).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { SOURCES, fetchSource, fetchAllSources, mergeCerts, sourceHealthSummary } from '../../assets/js/lib/sources.js';
import { AbortError } from '../../assets/js/lib/util.js';

/** Route requests by URL prefix; each route returns a Response, a value (JSON), or throws. */
function router(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    for (const [prefix, handler] of Object.entries(routes)) {
      if (url.startsWith(prefix)) {
        const out = await handler(url, calls.length);
        if (out instanceof Response) return out;
        return Response.json(out);
      }
    }
    throw new TypeError(`unexpected URL ${url}`);
  };
  return { fetchImpl, calls };
}

const CRT = 'https://crt.sh/';
const CS = 'https://api.certspotter.com/v1/issuances';
const HT = 'https://api.hackertarget.com/hostsearch/';
const AN = 'https://anubisdb.com/anubis/subdomains/';
const OTX = 'https://otx.alienvault.com/api/v1/indicators/domain/';

const crtRows = [
  {
    issuer_ca_id: 432477, issuer_name: "C=US, O=Let's Encrypt, CN=YR2", common_name: 'yardim.example.com.tr',
    name_value: 'e-kutup.example.com.tr\nyardim.example.com.tr', id: 29500727975,
    not_before: '2026-09-08T23:40:48', not_after: '2026-12-07T23:40:47', serial_number: '06350e3dbd1f76f6bae3d7a8997e6d320d06', result_count: 3
  },
  // the precertificate log entry of the same certificate (same issuer + serial)
  {
    issuer_ca_id: 432477, issuer_name: "C=US, O=Let's Encrypt, CN=YR2", common_name: 'yardim.example.com.tr',
    name_value: 'e-kutup.example.com.tr\nyardim.example.com.tr', id: 29500727001,
    not_before: '2026-09-08T23:40:48', not_after: '2026-12-07T23:40:47', serial_number: '06350E3DBD1F76F6BAE3D7A8997E6D320D06', result_count: 3
  },
  {
    issuer_ca_id: 176211, issuer_name: 'C=US, O=DigiCert Inc, CN=DigiCert EV RSA CA G2', common_name: '*.Example.com.tr',
    name_value: '*.example.com.tr\nexample.com.tr\n*.dev.example.com.tr\nWWW.EXAMPLE.COM.TR.\nhostmaster@example.com.tr\nOther.Example.NET',
    id: 29208441602, not_before: '2026-09-01T00:00:00', not_after: '2027-03-18T23:59:59', serial_number: '00c3aa11', result_count: 2
  },
  {
    issuer_ca_id: 1, issuer_name: 'C=TR, O=Örnek CA', common_name: 'Örnek Ltd. Şti.',
    name_value: 'mağaza.example.com.tr\n10.0.0.1\nexample.com.tr.evil.org', id: 5,
    not_before: '2025-01-01T00:00:00.123', not_after: '2025-12-31T00:00:00Z', serial_number: '01'
  }
];

describe('SOURCES', () => {
  test('catalogue fields', () => {
    assert.deepEqual(SOURCES.map((s) => s.id), ['crtsh', 'certspotter', 'hackertarget', 'anubis', 'otx', 'thc']);
    for (const s of SOURCES) {
      for (const k of ['id', 'name', 'homepage', 'noteKey']) assert.equal(typeof s[k], 'string', `${s.id}.${k}`);
      for (const k of ['providesIps', 'providesCerts', 'defaultEnabled']) assert.equal(typeof s[k], 'boolean');
      assert.equal(s.noteKey, `source.${s.id}.note`);
      assert.ok(Object.isFrozen(s));
    }
    assert.equal(SOURCES.find((s) => s.id === 'crtsh').timeoutMs, 90000);
    assert.deepEqual(SOURCES.filter((s) => s.providesIps).map((s) => s.id), ['hackertarget', 'otx']);
    assert.deepEqual(SOURCES.filter((s) => s.providesCerts).map((s) => s.id), ['crtsh', 'certspotter']);
  });
});

describe('crt.sh', () => {
  test('URL, newline-separated SANs, scope filtering, wildcard bases, dedupe by serial+issuer, UTC dates', async () => {
    const { fetchImpl, calls } = router({ [CRT]: () => crtRows });
    const r = await fetchSource('crtsh', 'https://Example.com.tr/', { fetchImpl });
    assert.equal(calls[0].url, 'https://crt.sh/?q=%25.example.com.tr&output=json&exclude=expired&deduplicate=Y');
    assert.equal(r.ok, true);
    assert.equal(r.source, 'crtsh');
    assert.equal(r.domain, 'example.com.tr');
    assert.deepEqual(r.names, [
      'example.com.tr', 'dev.example.com.tr', 'e-kutup.example.com.tr', 'www.example.com.tr',
      'xn--maaza-l1a.example.com.tr', 'yardim.example.com.tr'
    ]);
    assert.deepEqual(r.wildcardBases, ['example.com.tr', 'dev.example.com.tr']);
    assert.deepEqual(r.ipHints, []);
    assert.equal(r.certs.length, 3, 'precert + leaf rows collapse into one certificate');
    const le = r.certs.find((c) => c.issuer.includes("Let's Encrypt"));
    assert.equal(le.serialHex, '06350e3dbd1f76f6bae3d7a8997e6d320d06');
    assert.deepEqual(le.ids.sort(), [29500727001, 29500727975]);
    assert.equal(le.notBefore.toISOString(), '2026-09-08T23:40:48.000Z');
    assert.equal(le.notAfter.toISOString(), '2026-12-07T23:40:47.000Z');
    assert.deepEqual(le.names, ['e-kutup.example.com.tr', 'yardim.example.com.tr']);
    assert.equal(le.sha256, null);
    assert.equal(le.url, 'https://crt.sh/?id=29500727975');
    const dc = r.certs.find((c) => c.issuer.includes('DigiCert'));
    assert.equal(dc.serialHex, 'c3aa11', 'leading 00 stripped like x509.serialHex');
    assert.deepEqual(dc.names, ['other.example.net', 'example.com.tr', '*.example.com.tr', '*.dev.example.com.tr', 'www.example.com.tr']);
    const tr = r.certs.find((c) => c.id === 5);
    assert.equal(tr.notBefore.toISOString(), '2025-01-01T00:00:00.123Z');
    assert.equal(tr.notAfter.toISOString(), '2025-12-31T00:00:00.000Z');
    // newest first
    assert.deepEqual(r.certs.map((c) => c.id), [29500727975, 29208441602, 5]);
    assert.equal(r.rows, 4);
    assert.equal(typeof r.elapsedMs, 'number');
    assert.equal(r.error, null);
  });

  test('includeExpired drops &exclude=expired; empty results are fine', async () => {
    const { fetchImpl, calls } = router({ [CRT]: () => [] });
    const r = await fetchSource('crtsh', 'example.com', { fetchImpl, includeExpired: true });
    assert.equal(calls[0].url, 'https://crt.sh/?q=%25.example.com&output=json&deduplicate=Y');
    assert.equal(r.ok, true);
    assert.deepEqual(r.names, []);
  });

  test('retries on 5xx / network errors, then succeeds', async () => {
    const { fetchImpl, calls } = router({ [CRT]: (url, n) => (n === 1 ? new Response('Bad gateway', { status: 502 }) : crtRows.slice(0, 1)) });
    const r = await fetchSource('crtsh', 'example.com.tr', { fetchImpl, retryDelayMs: 1 });
    assert.equal(calls.length, 2);
    assert.equal(r.ok, true);
    assert.equal(r.attempts, 2);
    assert.deepEqual(r.names, ['e-kutup.example.com.tr', 'yardim.example.com.tr']);

    // browsers see crt.sh's CORS-less 502 pages as a network TypeError: 4 tries + the identity fallback
    const { fetchImpl: f2, calls: c2 } = router({ [CRT]: () => { throw new TypeError('Failed to fetch'); } });
    const r2 = await fetchSource('crtsh', 'example.com', { fetchImpl: f2, retryDelayMs: 1 });
    assert.equal(c2.length, 5);
    assert.equal(r2.ok, false);
    assert.equal(r2.errorKind, 'unavailable');
    assert.match(r2.error, /^crt\.sh is temporarily unavailable: 5 attempts over \d+ s failed \(network error ×5\)\. Its error pages carry no CORS header/);
  });

  test('includeExpired: when the full history fails, fall back to unexpired certificates (partial)', async () => {
    const { fetchImpl, calls } = router({
      [CRT]: (url) => (url.includes('exclude=expired') ? crtRows.slice(0, 1) : new Response('<html>502 Bad Gateway</html>', { status: 502 }))
    });
    const r = await fetchSource('crtsh', 'example.com.tr', { fetchImpl, includeExpired: true, retryDelayMs: 1 });
    assert.deepEqual(calls.map((c) => c.url), [
      'https://crt.sh/?q=%25.example.com.tr&output=json&deduplicate=Y',
      'https://crt.sh/?q=%25.example.com.tr&output=json&deduplicate=Y',
      'https://crt.sh/?q=%25.example.com.tr&output=json&exclude=expired&deduplicate=Y'
    ]);
    assert.equal(r.ok, true);
    assert.equal(r.partial, true);
    assert.equal(r.queryForm, 'subdomains');
    assert.equal(r.errorKind, 'unavailable');
    assert.equal(r.error, 'Expired certificates omitted: the full crt.sh history failed (HTTP 502 ×2)');
    assert.deepEqual(r.names, ['e-kutup.example.com.tr', 'yardim.example.com.tr']);

    // the fallbacks failing too → a plain failure (2 × history, 2 × unexpired, 1 × identity)
    const { fetchImpl: f2, calls: c2 } = router({ [CRT]: () => { throw new TypeError('Failed to fetch'); } });
    const r2 = await fetchSource('crtsh', 'example.com', { fetchImpl: f2, includeExpired: true, retryDelayMs: 1 });
    assert.equal(c2.length, 5);
    assert.equal(r2.ok, false);
    assert.equal(r2.errorKind, 'unavailable');

    // non-transient errors do not trigger the fallback
    const { fetchImpl: f3, calls: c3 } = router({ [CRT]: () => new Response('not json') });
    const r3 = await fetchSource('crtsh', 'example.com', { fetchImpl: f3, includeExpired: true, retryDelayMs: 1 });
    assert.equal(c3.length, 1);
    assert.equal(r3.errorKind, 'parse');
  });

  test('gives up after 4 tries + the identity fallback; 4xx and bad JSON are not retried', async () => {
    const { fetchImpl, calls } = router({ [CRT]: () => new Response('<html>503</html>', { status: 503 }) });
    const r = await fetchSource('crtsh', 'example.com', { fetchImpl, retryDelayMs: 1 });
    assert.equal(calls.length, 5);
    assert.equal(r.ok, false);
    assert.equal(r.errorKind, 'unavailable');
    assert.match(r.error, /^crt\.sh is temporarily unavailable: 5 attempts over \d+ s failed \(HTTP 503 ×5\)\.$/);

    const { fetchImpl: f2, calls: c2 } = router({ [CRT]: () => new Response('<html>oops</html>') });
    const r2 = await fetchSource('crtsh', 'example.com', { fetchImpl: f2, retryDelayMs: 1 });
    assert.equal(c2.length, 1);
    assert.equal(r2.errorKind, 'parse');
    assert.match(r2.error, /Invalid JSON/);

    const { fetchImpl: f3 } = router({ [CRT]: () => ({ error: 'x' }) });
    const r3 = await fetchSource('crtsh', 'example.com', { fetchImpl: f3 });
    assert.equal(r3.errorKind, 'parse');
  });

  test('timeouts are retried once and reported as timeout', async () => {
    const { fetchImpl, calls } = router({ [CRT]: () => new Promise(() => {}) });
    const r = await fetchSource('crtsh', 'example.com', { fetchImpl, timeoutMs: 20, retryDelayMs: 1 });
    assert.equal(calls.length, 2);
    assert.equal(r.ok, false);
    assert.equal(r.errorKind, 'timeout');
  });
});

describe('Cert Spotter', () => {
  const issuance = (id, names, extra = {}) => ({
    id: String(id), tbs_sha256: `${id}`.padStart(64, 'a'), cert_sha256: `${id}`.padStart(64, 'b'), dns_names: names,
    pubkey_sha256: 'c'.repeat(64), issuer: { friendly_name: 'Sectigo', name: 'C=GB, O=Sectigo Limited, CN=Sectigo DV R36' },
    not_before: '2025-10-06T00:00:00Z', not_after: '2026-10-12T23:59:59Z', revoked: false, ...extra
  });

  test('paginates with after=<last id> until an empty page', async () => {
    const pages = [
      [issuance(11, ['a.example.com', 'www.a.example.com']), issuance(12, ['*.b.example.com'])],
      [issuance(13, ['c.example.com'])],
      []
    ];
    const { fetchImpl, calls } = router({ [CS]: (url, n) => pages[n - 1] });
    const r = await fetchSource('certspotter', 'example.com', { fetchImpl });
    assert.equal(calls.length, 3);
    assert.equal(calls[0].url, 'https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names&expand=issuer');
    assert.ok(calls[1].url.endsWith('&after=12'));
    assert.ok(calls[2].url.endsWith('&after=13'));
    assert.deepEqual(r.names, ['a.example.com', 'www.a.example.com', 'b.example.com', 'c.example.com']);
    assert.deepEqual(r.wildcardBases, ['b.example.com']);
    assert.equal(r.certs.length, 3);
    const c = r.certs.find((x) => x.id === '11');
    assert.equal(c.sha256, '11'.padStart(64, 'b'));
    assert.equal(c.key, `sha256:${'11'.padStart(64, 'b')}`);
    assert.equal(c.issuer, 'C=GB, O=Sectigo Limited, CN=Sectigo DV R36');
    assert.equal(c.serialHex, null);
    assert.equal(c.notAfter.toISOString(), '2026-10-12T23:59:59.000Z');
    assert.equal(c.revoked, false);
  });

  test('stops at 5 pages; a readable Link header without rel=next ends pagination', async () => {
    let n = 0;
    const { fetchImpl, calls } = router({ [CS]: () => { n += 1; return [issuance(n, [`h${n}.example.com`])]; } });
    const r = await fetchSource('certspotter', 'example.com', { fetchImpl });
    assert.equal(calls.length, 5);
    assert.equal(r.names.length, 5);

    const { fetchImpl: f2, calls: c2 } = router({
      [CS]: () => new Response(JSON.stringify([issuance(1, ['x.example.com'])]), { headers: { link: '<https://api.certspotter.com/issuances?after=0>; rel="prev"' } })
    });
    await fetchSource('certspotter', 'example.com', { fetchImpl: f2 });
    assert.equal(c2.length, 1);

    const { fetchImpl: f3, calls: c3 } = router({
      [CS]: (url, k) => new Response(JSON.stringify(k === 1 ? [issuance(1, ['x.example.com'])] : []), {
        headers: k === 1 ? { link: '<https://api.certspotter.com/issuances?after=1&domain=example.com>; rel="next"' } : {}
      })
    });
    await fetchSource('certspotter', 'example.com', { fetchImpl: f3 });
    assert.equal(c3.length, 2);
  });

  test('a full 5th page sets truncated (page limit reached); an early end or a final Link header does not', async () => {
    let n = 0;
    const { fetchImpl } = router({ [CS]: () => { n += 1; return [issuance(n, [`h${n}.example.com`])]; } });
    const r = await fetchSource('certspotter', 'example.com', { fetchImpl });
    assert.equal(r.truncated, true);
    assert.match(sourceHealthSummary([r])[0].message, /\(page limit reached\)$/);

    const pages = [[issuance(1, ['a.example.com'])], [issuance(2, ['b.example.com'])], []];
    const { fetchImpl: f2 } = router({ [CS]: (url, k) => pages[k - 1] });
    assert.equal((await fetchSource('certspotter', 'example.com', { fetchImpl: f2 })).truncated, false);

    // a readable Link header on page 5 without rel="next": the last page, nothing was cut
    const { fetchImpl: f3 } = router({
      [CS]: (url, k) => new Response(JSON.stringify([issuance(k, [`h${k}.example.com`])]), {
        headers: { link: k === 5 ? '<https://api.certspotter.com/issuances?after=0>; rel="prev"' : '<https://api.certspotter.com/issuances?after=1>; rel="next"' }
      })
    });
    assert.equal((await fetchSource('certspotter', 'example.com', { fetchImpl: f3 })).truncated, false);
  });

  test('429 on the first page → rate-limit error; on a later page → partial result', async () => {
    const limited = () => new Response(JSON.stringify({ code: 'rate_limited', message: 'You have exceeded the rate limit.' }), { status: 429, headers: { 'retry-after': '3600' } });
    const { fetchImpl } = router({ [CS]: limited });
    const r = await fetchSource('certspotter', 'example.com', { fetchImpl });
    assert.equal(r.ok, false);
    assert.equal(r.errorKind, 'rate-limit');
    assert.equal(r.error, 'HTTP 429: You have exceeded the rate limit.');

    const { fetchImpl: f2 } = router({ [CS]: (url, n) => (n === 1 ? [issuance(1, ['x.example.com'])] : limited()) });
    const r2 = await fetchSource('certspotter', 'example.com', { fetchImpl: f2 });
    assert.equal(r2.ok, true);
    assert.equal(r2.partial, true);
    assert.equal(r2.errorKind, 'rate-limit');
    assert.match(r2.error, /^Incomplete: HTTP 429/);
    assert.deepEqual(r2.names, ['x.example.com']);
  });
});

describe('HackerTarget', () => {
  test('host,ip lines → names + IP hints (in scope only)', async () => {
    const body = [
      'example.org,203.0.113.10',
      '000.example.org,104.18.33.183',
      'API.Example.org,172.64.154.73',
      'mail.example.org,2001:db8:4017:80b::200e',
      'nohost.example.org',
      'example.org.evil.net,1.2.3.4',
      'bad.example.org,999.1.1.1',
      ''
    ].join('\n');
    const { fetchImpl, calls } = router({ [HT]: () => new Response(body, { headers: { 'content-type': 'text/plain' } }) });
    const r = await fetchSource('hackertarget', 'example.org', { fetchImpl });
    assert.equal(calls[0].url, 'https://api.hackertarget.com/hostsearch/?q=example.org');
    assert.equal(r.ok, true);
    assert.deepEqual(r.names, ['example.org', '000.example.org', 'api.example.org', 'bad.example.org', 'mail.example.org', 'nohost.example.org']);
    assert.deepEqual(r.ipHints, [
      { name: 'example.org', ip: '203.0.113.10', source: 'hackertarget' },
      { name: '000.example.org', ip: '104.18.33.183', source: 'hackertarget' },
      { name: 'api.example.org', ip: '172.64.154.73', source: 'hackertarget' },
      { name: 'mail.example.org', ip: '2001:db8:4017:80b::200e', source: 'hackertarget' }
    ]);
  });

  test('quota / error messages arrive as HTTP 200 text', async () => {
    const quota = await fetchSource('hackertarget', 'example.com', {
      fetchImpl: router({ [HT]: () => new Response('API count exceeded - Increase Quota with Membership') }).fetchImpl
    });
    assert.equal(quota.ok, false);
    assert.equal(quota.errorKind, 'rate-limit');
    assert.match(quota.error, /API count exceeded/);

    const err = await fetchSource('hackertarget', 'example.com', {
      fetchImpl: router({ [HT]: () => new Response('error check your search parameter') }).fetchImpl
    });
    assert.equal(err.ok, false);
    assert.equal(err.errorKind, 'http');

    const none = await fetchSource('hackertarget', 'example.com', {
      fetchImpl: router({ [HT]: () => new Response('No records found for example.com') }).fetchImpl
    });
    assert.equal(none.ok, true);
    assert.deepEqual(none.names, []);

    const html = await fetchSource('hackertarget', 'example.com', {
      fetchImpl: router({ [HT]: () => new Response('<html><body>Cloudflare challenge</body></html>') }).fetchImpl
    });
    assert.equal(html.ok, false);
    assert.equal(html.errorKind, 'parse');
  });
});

describe('Anubis', () => {
  test('JSON array of names (wildcards and junk handled)', async () => {
    const { fetchImpl, calls } = router({ [AN]: () => ['ad.example.com', '*.cdn.example.com', 'Example.com', 'x.other.org', 42, null, 'bad name.example.com'] });
    const r = await fetchSource('anubis', 'example.com', { fetchImpl });
    assert.equal(calls[0].url, 'https://anubisdb.com/anubis/subdomains/example.com');
    assert.deepEqual(r.names, ['example.com', 'ad.example.com', 'cdn.example.com']);
    assert.deepEqual(r.wildcardBases, ['cdn.example.com']);
  });

  test('JSON error object → service error; non-array payload → parse error; HTTP errors reported', async () => {
    const r = await fetchSource('anubis', 'example.com', { fetchImpl: router({ [AN]: () => ({ error: 'nope' }) }).fetchImpl });
    assert.equal(r.errorKind, 'http');
    assert.equal(r.error, 'Anubis: nope');
    const r1 = await fetchSource('anubis', 'example.com', { fetchImpl: router({ [AN]: () => ({ names: 1 }) }).fetchImpl });
    assert.equal(r1.errorKind, 'parse');
    const r2 = await fetchSource('anubis', 'example.com', { fetchImpl: router({ [AN]: () => new Response('gone', { status: 404 }) }).fetchImpl });
    assert.equal(r2.ok, false);
    assert.equal(r2.error, 'HTTP 404: gone');
  });
});

describe('OTX', () => {
  test('passive DNS → names + historical IP hints with first/last seen (UTC)', async () => {
    const body = {
      passive_dns: [
        { hostname: 'www.example.com', address: '203.0.113.10', record_type: 'A', first: '2021-03-01T10:00:00', last: '2022-01-01T00:00:00' },
        { hostname: 'www.example.com', address: '203.0.113.10', record_type: 'A', first: '2020-01-01T00:00:00', last: '2021-06-01T00:00:00' },
        { hostname: 'www.example.com', address: '2001:db8::5', record_type: 'AAAA', first: '2023-01-01T00:00:00', last: '2023-02-01T00:00:00' },
        { hostname: 'old.example.com', address: 'legacy.example.com', record_type: 'CNAME', first: '2019-01-01T00:00:00', last: '2019-02-01T00:00:00' },
        { hostname: 'mx.example.com', address: 'NXDOMAIN', record_type: 'A' },
        { hostname: 'x.elsewhere.org', address: '198.51.100.1', record_type: 'A' }
      ],
      count: 6
    };
    const { fetchImpl, calls } = router({ [OTX]: () => body });
    const r = await fetchSource('otx', 'example.com', { fetchImpl });
    assert.equal(calls[0].url, 'https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns');
    assert.deepEqual(r.names, ['legacy.example.com', 'mx.example.com', 'old.example.com', 'www.example.com']);
    assert.equal(r.ipHints.length, 2);
    const v4 = r.ipHints.find((h) => h.ip === '203.0.113.10');
    assert.equal(v4.source, 'otx');
    assert.equal(v4.name, 'www.example.com');
    assert.equal(v4.firstSeen.toISOString(), '2020-01-01T00:00:00.000Z', 'widest window kept');
    assert.equal(v4.lastSeen.toISOString(), '2022-01-01T00:00:00.000Z');
  });

  test('anonymous 429 → rate-limit with the detail message', async () => {
    const { fetchImpl } = router({
      [OTX]: () => new Response(JSON.stringify({ detail: 'Anonymous access to this endpoint is limited. Please authenticate.' }), { status: 429 })
    });
    const r = await fetchSource('otx', 'example.com', { fetchImpl });
    assert.equal(r.ok, false);
    assert.equal(r.errorKind, 'rate-limit');
    assert.equal(r.error, 'HTTP 429: Anonymous access to this endpoint is limited. Please authenticate.');
  });
});

describe('fetchSource edge cases', () => {
  test('unknown source / invalid domain → ok=false without network', async () => {
    const { fetchImpl, calls } = router({});
    const r = await fetchSource('nope', 'example.com', { fetchImpl });
    assert.equal(r.ok, false);
    assert.match(r.error, /Unknown source/);
    const r2 = await fetchSource('crtsh', 'not a domain', { fetchImpl });
    assert.equal(r2.ok, false);
    assert.match(r2.error, /Invalid domain/);
    assert.equal(calls.length, 0);
  });

  test('network errors are classified', async () => {
    const { fetchImpl } = router({ [AN]: () => { throw new TypeError('Failed to fetch'); } });
    const r = await fetchSource('anubis', 'example.com', { fetchImpl });
    assert.equal(r.ok, false);
    assert.equal(r.errorKind, 'network');
    assert.equal(r.error, 'Failed to fetch');
  });

  test('abort rejects with AbortError (before and during the request)', async () => {
    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(fetchSource('anubis', 'example.com', { fetchImpl: router({}).fetchImpl, signal: ctl.signal }), (e) => e instanceof AbortError);
    const c2 = new AbortController();
    const p = fetchSource('crtsh', 'example.com', { fetchImpl: router({ [CRT]: () => new Promise(() => {}) }).fetchImpl, signal: c2.signal });
    setTimeout(() => c2.abort(), 10);
    await assert.rejects(p, (e) => e instanceof AbortError);
  });
});

describe('fetchAllSources', () => {
  const routes = () => ({
    [CRT]: () => crtRows.slice(0, 3),
    [CS]: (url) => (url.includes('after=') ? [] : [{
      id: '77', cert_sha256: 'ab'.repeat(32), tbs_sha256: 'cd'.repeat(32), dns_names: ['e-kutup.example.com.tr', 'yardim.example.com.tr'],
      issuer: { name: "C=US, O=Let's Encrypt, CN=YR2" }, not_before: '2026-09-08T23:40:48Z', not_after: '2026-12-07T23:40:47Z'
    }]),
    [HT]: () => new Response('api.example.com.tr,192.0.2.10\nyardim.example.com.tr,104.16.1.1'),
    [AN]: () => ['api.example.com.tr', 'anubis-only.example.com.tr'],
    [OTX]: () => new Response(JSON.stringify({ detail: 'limited' }), { status: 429 }),
    'https://ip.thc.org/': () => ({
      matching_records: 2, next_page_state: '',
      domains: [{ domain: 'thc-only.example.com.tr', last_seen_on: '2024-12-11' }, { domain: 'api.example.com.tr', last_seen_on: '2026-09-20' }]
    })
  });

  test('parallel fetch, results in source order, name → sources map, merged hints and certs', async () => {
    const { fetchImpl } = router(routes());
    const seen = [];
    const out = await fetchAllSources('example.com.tr', { fetchImpl, onResult: (r) => seen.push(r.source) });
    assert.deepEqual(out.results.map((r) => r.source), ['crtsh', 'certspotter', 'hackertarget', 'anubis', 'otx', 'thc']);
    assert.deepEqual(seen.sort(), ['anubis', 'certspotter', 'crtsh', 'hackertarget', 'otx', 'thc']);
    assert.equal(out.results.find((r) => r.source === 'otx').errorKind, 'rate-limit');
    assert.deepEqual([...out.names.get('thc-only.example.com.tr')], ['thc']);
    assert.deepEqual(out.lastSeen, { 'api.example.com.tr': '2026-09-20', 'thc-only.example.com.tr': '2024-12-11' });
    assert.deepEqual(out.health.map((s) => [s.source, s.state]), [
      ['crtsh', 'ok'], ['certspotter', 'ok'], ['hackertarget', 'ok'], ['anubis', 'ok'], ['otx', 'rate-limited'], ['thc', 'ok']
    ]);
    assert.ok(out.names instanceof Map);
    assert.deepEqual([...out.names.get('yardim.example.com.tr')].sort(), ['certspotter', 'crtsh', 'hackertarget']);
    assert.deepEqual([...out.names.get('anubis-only.example.com.tr')], ['anubis']);
    assert.deepEqual([...out.names.keys()][0], 'example.com.tr', 'sorted, apex first');
    assert.deepEqual(out.ipHints.map((h) => `${h.name}=${h.ip}`), ['api.example.com.tr=192.0.2.10', 'yardim.example.com.tr=104.16.1.1']);
    assert.deepEqual(out.wildcardBases, ['example.com.tr', 'dev.example.com.tr']);
    // the Cert Spotter issuance is the same certificate as the crt.sh LE cert → merged
    assert.equal(out.certs.length, 2);
    const le = out.certs.find((c) => c.serialHex === '06350e3dbd1f76f6bae3d7a8997e6d320d06');
    assert.deepEqual(le.sources, ['crtsh', 'certspotter']);
    assert.equal(le.sha256, 'ab'.repeat(32));
  });

  test('source subset; unknown ids reported; a throwing onResult is ignored', async () => {
    const { fetchImpl, calls } = router(routes());
    const out = await fetchAllSources('example.com.tr', { fetchImpl, sources: ['anubis', 'bogus'], onResult: () => { throw new Error('ui'); } });
    assert.deepEqual(out.results.map((r) => [r.source, r.ok]), [['anubis', true], ['bogus', false]]);
    assert.equal(calls.length, 1);
  });

  test('abort rejects', async () => {
    const ctl = new AbortController();
    const { fetchImpl } = router({ ...routes(), [CRT]: () => new Promise(() => {}) });
    const p = fetchAllSources('example.com.tr', { fetchImpl, signal: ctl.signal });
    setTimeout(() => ctl.abort(), 10);
    await assert.rejects(p, (e) => e instanceof AbortError);
  });
});

describe('mergeCerts', () => {
  test('exact key duplicates and cross-source twins', () => {
    const d = (s) => new Date(s);
    const a = { key: 'crtsh:1:0a', source: 'crtsh', sources: ['crtsh'], serialHex: '0a', sha256: null, names: ['a.example'], notBefore: d('2026-01-01'), notAfter: d('2026-04-01') };
    const b = { key: 'sha256:ff', source: 'certspotter', sources: ['certspotter'], serialHex: null, sha256: 'ff', names: ['a.example'], notBefore: d('2026-01-01'), notAfter: d('2026-04-01') };
    const c = { key: 'sha256:ee', source: 'certspotter', sources: ['certspotter'], serialHex: null, sha256: 'ee', names: ['b.example'], notBefore: d('2026-02-01'), notAfter: d('2026-05-01') };
    const merged = mergeCerts([a, { ...a }, b, c]);
    assert.equal(merged.length, 2);
    assert.deepEqual(merged.map((x) => x.key), ['sha256:ee', 'crtsh:1:0a']);
    assert.equal(merged[1].sha256, 'ff');
    assert.deepEqual(merged[1].sources, ['crtsh', 'certspotter']);
    assert.equal(a.sha256, null, 'inputs are not mutated');
  });
});
