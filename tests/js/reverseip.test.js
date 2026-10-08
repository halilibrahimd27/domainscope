// Unit tests for assets/js/lib/reverseip.js ("Domains on this IP") — offline: every answer comes from
// a fake fetch, a fake ipintel service and a fake DohClient, with documentation data only. The answer
// shapes follow the live responses checked on 2026-10-08 (see the module header); no live data here.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  REVERSE_SOURCES, KEYED_SOURCES, NAME_STATUSES, SKIP_REASONS, VERIFY_BATCH, MAX_REVERSE_IPS, INTERNETDB_LOCK_MS,
  OTX_INDICATORS, ROBTEX_PDNS_REVERSE, INTERNETDB_BASE, SHODAN_HOST, WHOISXML_REVERSE_IP,
  isLocalOnly, normalizeName, looksInternal, seenTime, parseOtxPassiveDns, parseRobtexReverse, parseInternetDb,
  parseShodanHost, parseWhoisXmlReverse, otxUrl, robtexUrl, internetDbUrl, mergeNames, forwardStatus, reverseCounts,
  reverseExportRows, createReverseIp
} from '../../assets/js/lib/reverseip.js';
import { sourceStatus, STATUS_SOURCES } from '../../assets/js/lib/sourcestatus.js';

const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);
const IP = '203.0.113.10';
const IP2 = '198.51.100.20';
/** Made-up keys, built from pieces so that no file holds anything key-shaped. */
const SHODAN_KEY = ['made', 'up', 'shodan', 'key'].join('-');
const WHOIS_KEY = ['made', 'up', 'whois', 'key'].join('-');

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

/** A fake fetch answering from `routes` (URL → Response factory); records every URL. Unknown → network error. */
function fakeFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push(String(url));
    if (init.signal && init.signal.aborted) throw new DOMException('Aborted', 'AbortError');
    const route = routes[String(url)];
    if (!route) throw new TypeError('Failed to fetch');
    return route();
  };
  return { fetchImpl, calls };
}

const OTX_BODY = {
  passive_dns: [
    { address: IP, first: '2026-07-10T08:55:03', last: '2026-10-03T07:53:19', hostname: 'www.example.com', record_type: 'A' },
    { address: IP, first: '2025-01-01T00:00:00', last: '2025-02-01T00:00:00', hostname: 'WWW.Example.com.', record_type: 'A' },
    { address: IP, first: '2026-01-01T00:00:00', last: '2026-01-02T00:00:00', hostname: '203.0.113.10', record_type: 'A' }
  ],
  count: 3
};
const ROBTEX_BODY = [
  { rrname: 'shop.example.net', rrdata: IP, rrtype: 'A', time_first: 1780000000, time_last: 1790000000, count: 4 },
  { rrname: 'www.example.com', rrdata: IP, rrtype: 'A', time_first: 1700000000, time_last: 1701000000, count: 1 }
].map((r) => JSON.stringify(r)).join('\n');
const INTERNETDB_BODY = { cpes: ['cpe:/a:example:server'], hostnames: ['mail.example.org', '*.cdn.example.org'], ip: IP, ports: [443, 80, 443], tags: ['cloud'], vulns: ['CVE-2026-0001'] };

function routesFor(ip, extra = {}) {
  return {
    [otxUrl(ip)]: () => json(OTX_BODY),
    [robtexUrl(ip)]: () => new Response(ROBTEX_BODY, { status: 200, headers: { 'content-type': 'application/x-ndjson' } }),
    [internetDbUrl(ip)]: () => json(INTERNETDB_BODY),
    ...extra
  };
}

function fakeIntel({ ht = { ok: true, domains: ['www.example.com', 'blog.example.com'], error: null, limited: false, errorKind: null },
  thc = { ok: true, domains: ['api.example.com'], error: null, limited: false, errorKind: null, total: 250, truncated: true } } = {}) {
  const calls = [];
  return {
    calls,
    reverseIp: async (ip, opts = {}) => { calls.push(['hackertarget', ip, !!opts.noCache]); return typeof ht === 'function' ? ht() : ht; },
    reverseIpThc: async (ip, opts = {}) => { calls.push(['thc', ip, !!opts.noCache]); return typeof thc === 'function' ? thc() : thc; }
  };
}

/** A fake DohClient: PTR answers by address, forward answers by name. */
function fakeDns({ ptr = { [IP]: ['host-10.example.net.'] }, hosts = {} } = {}) {
  const calls = [];
  return {
    calls,
    ptr: async (ip) => {
      calls.push(['ptr', ip]);
      if (ptr[ip] instanceof Error) throw ptr[ip];
      return ptr[ip] || [];
    },
    resolveHost: async (name, { signal } = {}) => {
      calls.push(['host', name]);
      if (signal && signal.aborted) throw new DOMException('Aborted', 'AbortError');
      const h = hosts[name] || { status: 'NXDOMAIN', ipv4: [], ipv6: [], cnames: [] };
      return { name, status: h.status || 'NOERROR', ipv4: h.ipv4 || [], ipv6: h.ipv6 || [], cnames: h.cnames || [], error: h.error || null };
    }
  };
}

const classify = ({ cnames = [] }) => (cnames.some((c) => c.endsWith('.cdn.example.net')) ? { hidesOrigin: true, provider: { name: 'ExampleCDN' } } : { hidesOrigin: false, provider: null });

describe('names and addresses', () => {
  test('normalizeName: case, trailing dot, punycode and a leading *. are normalised; junk is dropped', () => {
    assert.equal(normalizeName('WWW.Example.COM.'), 'www.example.com');
    assert.equal(normalizeName('*.Shop.example.com'), 'shop.example.com');
    assert.equal(normalizeName('*.*.deep.example.com'), 'deep.example.com');
    assert.equal(normalizeName('bücher.example'), 'xn--bcher-kva.example');
    assert.equal(normalizeName('203.0.113.10'), null, 'an address written as a name');
    assert.equal(normalizeName('203.0.113.10.'), null);
    assert.equal(normalizeName('10.113.0.203.in-addr.arpa'), null, 'a reverse-zone name');
    assert.equal(normalizeName('bad_label!.example.com'), null, 'an invalid label');
    assert.equal(normalizeName('localhost'), null, 'a single label');
    assert.equal(normalizeName(''), null);
    assert.equal(normalizeName(42), null);
  });

  test('isLocalOnly: private and reserved stay home; documentation ranges and public addresses do not', () => {
    for (const ip of ['10.0.0.5', '192.168.1.1', '127.0.0.1', '100.64.0.1', '224.0.0.1', '255.255.255.255', 'fe80::1', 'fc00::1', '::1', 'ff02::1', 'not-an-ip']) {
      assert.equal(isLocalOnly(ip), true, ip);
    }
    for (const ip of [IP, IP2, '192.0.2.1', '2001:db8::1']) assert.equal(isLocalOnly(ip), false, ip);
  });

  test('looksInternal: single labels and internal suffixes', () => {
    assert.equal(looksInternal('db.corp'), true);
    assert.equal(looksInternal('printer.local'), true);
    assert.equal(looksInternal('nas.home.arpa'), true);
    assert.equal(looksInternal('intranet'), true);
    assert.equal(looksInternal('www.example.com'), false);
  });

  test('seenTime: ms, Unix seconds, ISO without a zone as UTC; out-of-range is null', () => {
    assert.equal(seenTime('2026-07-10T08:55:03', { now: NOW }), Date.UTC(2026, 6, 10, 8, 55, 3));
    assert.equal(seenTime('2026-07-10', { now: NOW }), Date.UTC(2026, 6, 10));
    assert.equal(seenTime(1780000000, { seconds: true, now: NOW }), 1780000000 * 1000);
    assert.equal(seenTime('1780000000', { seconds: true, now: NOW }), 1780000000 * 1000);
    assert.equal(seenTime(0, { seconds: true, now: NOW }), null, '1970');
    assert.equal(seenTime(NOW + 3 * 86400000, { now: NOW }), null, 'the future');
    assert.equal(seenTime('soon', { now: NOW }), null);
  });

  test('frozen code lists', () => {
    for (const list of [REVERSE_SOURCES, KEYED_SOURCES, NAME_STATUSES, SKIP_REASONS]) assert.ok(Object.isFrozen(list));
    assert.ok(KEYED_SOURCES.every((s) => REVERSE_SOURCES.includes(s)));
    assert.equal(VERIFY_BATCH, 300);
    assert.ok(MAX_REVERSE_IPS >= 1 && MAX_REVERSE_IPS <= 25);
    for (const s of REVERSE_SOURCES) assert.ok(STATUS_SOURCES[s], `STATUS_SOURCES has ${s}`);
  });

  test('URLs: https, the address in the path, the IPv6 indicator for IPv6', () => {
    assert.equal(otxUrl(IP), `${OTX_INDICATORS}/IPv4/${IP}/passive_dns`);
    assert.equal(otxUrl('2001:db8::1'), `${OTX_INDICATORS}/IPv6/2001:db8::1/passive_dns`);
    assert.equal(robtexUrl(IP), `${ROBTEX_PDNS_REVERSE}${IP}`);
    assert.equal(internetDbUrl(IP), `${INTERNETDB_BASE}${IP}`);
    for (const u of [OTX_INDICATORS, ROBTEX_PDNS_REVERSE, INTERNETDB_BASE, SHODAN_HOST, WHOISXML_REVERSE_IP]) assert.ok(u.startsWith('https://'));
  });
});

describe('parsers', () => {
  test('OTX: names merged per name with the widest first / last; junk dropped; count kept', () => {
    const p = parseOtxPassiveDns(OTX_BODY, { now: NOW });
    assert.equal(p.ok, true);
    assert.deepEqual(p.names, [{ name: 'www.example.com', first: Date.UTC(2025, 0, 1), last: Date.UTC(2026, 9, 3, 7, 53, 19) }]);
    assert.equal(p.total, 3);
    assert.equal(parseOtxPassiveDns({ detail: 'nope' }).ok, false);
    assert.equal(parseOtxPassiveDns(null).ok, false);
  });

  test('Robtex: ndjson lines, Unix seconds; a blank body is nothing seen; garbage is a failure', () => {
    const p = parseRobtexReverse(ROBTEX_BODY, { now: NOW });
    assert.equal(p.ok, true);
    assert.deepEqual(p.names.map((n) => [n.name, n.first, n.last]), [['shop.example.net', 1780000000000, 1790000000000], ['www.example.com', 1700000000000, 1701000000000]]);
    assert.deepEqual(parseRobtexReverse(''), { ok: true, names: [], error: null });
    assert.equal(parseRobtexReverse('<html>rate limited</html>').ok, false);
  });

  test('InternetDB: host names plus ports, tags, vulns and CPEs (kept for the panel)', () => {
    const p = parseInternetDb(INTERNETDB_BODY);
    assert.equal(p.ok, true);
    assert.deepEqual(p.names.map((n) => n.name), ['mail.example.org', 'cdn.example.org']);
    assert.deepEqual(p.extra, { ports: [80, 443], tags: ['cloud'], vulns: ['CVE-2026-0001'], cpes: ['cpe:/a:example:server'] });
    assert.equal(parseInternetDb({ detail: 'No information available' }).ok, false);
  });

  test('Shodan host: host names and domains; an error document is a failure', () => {
    const p = parseShodanHost({ ip_str: IP, hostnames: ['web.example.com'], domains: ['example.com'], ports: [22, 443], last_update: '2026-10-01T10:00:00.000000' }, { now: NOW });
    assert.equal(p.ok, true);
    assert.deepEqual(p.names.map((n) => n.name), ['web.example.com', 'example.com']);
    assert.equal(p.names[0].last, Date.UTC(2026, 9, 1, 10));
    assert.deepEqual(p.extra.ports, [22, 443]);
    const e = parseShodanHost({ error: 'No information available for that IP.' });
    assert.equal(e.ok, false);
    assert.match(e.error, /No information/);
  });

  test('WhoisXML: result[].name with first_seen / last_visit; an error document is a failure', () => {
    const p = parseWhoisXmlReverse({ current_page: '0', size: 2, result: [{ name: 'a.example.com', first_seen: 1700000000, last_visit: 1780000000 }, { name: 'b.example.com', first_seen: 1700000000, last_visit: 1700000100 }] }, { now: NOW });
    assert.equal(p.ok, true);
    assert.deepEqual(p.names.map((n) => [n.name, n.first, n.last]), [['a.example.com', 1700000000000, 1780000000000], ['b.example.com', 1700000000000, 1700000100000]]);
    assert.equal(p.total, 2);
    const e = parseWhoisXmlReverse({ code: 403, messages: 'Access restricted. Reasons: insufficient credits balance, incorrect API key' });
    assert.equal(e.ok, false);
    assert.match(e.error, /Access restricted/);
  });
});

describe('merge and forward status', () => {
  const lookups = [
    { ip: IP, results: {
      otx: { state: 'ok', names: [{ name: 'www.example.com', first: 100, last: 200 }] },
      robtex: { state: 'ok', names: [{ name: 'www.example.com', first: 50, last: 150 }, { name: 'shop.example.net', first: null, last: null }] },
      hackertarget: { state: 'failed', names: [{ name: 'ignored.example.com', first: null, last: null }] },
      workspace: { state: 'ok', names: [{ name: 'db.corp', first: null, last: null }] }
    } },
    { ip: IP2, results: { ptr: { state: 'ok', names: [{ name: 'www.example.com', first: null, last: 300 }] } } }
  ];

  test('one row per name: addresses, sources (in source order), widest first / last, registrable domain', () => {
    const rows = mergeNames(lookups);
    assert.deepEqual(rows.map((r) => r.name), ['www.example.com', 'db.corp', 'shop.example.net'], 'by reversed labels');
    const www = rows.find((r) => r.name === 'www.example.com');
    assert.deepEqual([www.ips, www.sources, www.first, www.last, www.domain, www.status], [[IP, IP2], ['ptr', 'otx', 'robtex'], 50, 300, 'example.com', 'unchecked']);
    assert.equal(rows.find((r) => r.name === 'db.corp').status, 'internal', 'an internal-looking name is never checked');
    const ws = mergeNames([{ ip: IP, results: { workspace: { state: 'ok', names: [{ name: 'origin.example.com', first: null, last: null }] } } }]);
    assert.equal(ws[0].status, 'workspace', 'a name only the workspace knows is never sent');
    const both = mergeNames([{ ip: IP, results: { workspace: { state: 'ok', names: [{ name: 'origin.example.com', first: null, last: null }] }, otx: { state: 'ok', names: [{ name: 'origin.example.com', first: null, last: null }] } } }], { previous: ws });
    assert.equal(both[0].status, 'unchecked', 'once a public source has it too, it is checked');
    assert.equal(rows.some((r) => r.name === 'ignored.example.com'), false, 'a failed source adds nothing');
  });

  test('a merge keeps the check of a name it had before', () => {
    const first = mergeNames(lookups);
    Object.assign(first.find((r) => r.name === 'www.example.com'), { status: 'here', resolvesTo: [IP] });
    const again = mergeNames(lookups, { previous: first });
    assert.deepEqual([again.find((r) => r.name === 'www.example.com').status, again.find((r) => r.name === 'www.example.com').resolvesTo], ['here', [IP]]);
  });

  test('forwardStatus: here, moved (with where), behind a CDN, does not resolve, failed', () => {
    assert.equal(forwardStatus({ status: 'NOERROR', ipv4: [IP, '192.0.2.1'] }, [IP], classify).status, 'here');
    assert.deepEqual(forwardStatus({ status: 'NOERROR', ipv4: ['192.0.2.1'] }, [IP], classify), { status: 'moved', resolvesTo: ['192.0.2.1'], provider: null, rcode: null, error: null });
    assert.deepEqual(forwardStatus({ status: 'NOERROR', ipv4: ['192.0.2.9'], cnames: ['x.cdn.example.net'] }, [IP], classify), { status: 'cdn', resolvesTo: ['192.0.2.9'], provider: 'ExampleCDN', rcode: null, error: null });
    assert.equal(forwardStatus({ status: 'NXDOMAIN', ipv4: [] }, [IP], classify).status, 'none');
    assert.equal(forwardStatus({ status: 'NOERROR', ipv4: [] }, [IP], classify).status, 'none', 'no address');
    assert.deepEqual(forwardStatus({ status: 'SERVFAIL', ipv4: [], error: 'answered SERVFAIL' }, [IP], classify), { status: 'failed', resolvesTo: [], provider: null, rcode: 'SERVFAIL', error: 'answered SERVFAIL' });
    assert.equal(forwardStatus({ status: 'NOERROR', ipv6: ['2001:DB8::0:1'] }, ['2001:db8::1'], classify).status, 'here', 'IPv6 compared canonically');
  });

  test('reverseCounts and reverseExportRows', () => {
    const rows = mergeNames(lookups);
    const c = reverseCounts(rows);
    assert.equal(c.names, 3);
    assert.equal(c.byStatus.unchecked, 2);
    assert.equal(c.byStatus.workspace, 0);
    assert.equal(c.byStatus.internal, 1);
    assert.equal(c.bySource.robtex, 2);
    assert.deepEqual(c.domains, ['example.com', 'db.corp', 'example.net']);
    const out = reverseExportRows(rows).find((r) => r.name === 'www.example.com');
    assert.deepEqual(out, { name: 'www.example.com', status: 'unchecked', domain: 'example.com', addresses: [IP, IP2], sources: ['ptr', 'otx', 'robtex'], firstSeen: new Date(50).toISOString(), lastSeen: new Date(300).toISOString(), resolvesTo: [], provider: null, rcode: null });
  });
});

describe('createReverseIp', () => {
  test('a public address: every source asked once, the keyed ones skipped without a key', async () => {
    const { fetchImpl, calls } = fakeFetch(routesFor(IP));
    const intel = fakeIntel();
    const dns = fakeDns();
    const svc = createReverseIp({ fetchImpl, dns, intel, now: () => NOW, classify });
    const heard = [];
    const r = await svc.lookup(IP, { workspace: { servers: ['web01'], origins: [{ name: 'origin.example.com', last: '2026-09-01T00:00:00Z' }] }, onSource: (x) => heard.push(x.source) });
    assert.equal(r.local, false);
    assert.deepEqual(calls.sort(), [internetDbUrl(IP), otxUrl(IP), robtexUrl(IP)].sort());
    assert.deepEqual(intel.calls, [['hackertarget', IP, false], ['thc', IP, false]]);
    assert.deepEqual(dns.calls, [['ptr', IP]]);
    assert.deepEqual(heard.sort(), [...REVERSE_SOURCES].sort());
    assert.deepEqual([r.results.shodan.state, r.results.shodan.skip, r.results.whoisxml.skip], ['skipped', 'no-key', 'no-key']);
    assert.deepEqual(r.results.workspace.extra, { servers: ['web01'] });
    assert.deepEqual(r.results.workspace.names.map((n) => n.name), ['origin.example.com']);
    assert.deepEqual(r.results.ptr.names.map((n) => n.name), ['host-10.example.net']);
    assert.deepEqual([r.results.thc.total, r.results.thc.truncated], [250, true]);
    assert.deepEqual(r.results.internetdb.extra.ports, [80, 443]);
    const rows = mergeNames([r]);
    assert.deepEqual(rows.map((x) => x.name), ['api.example.com', 'blog.example.com', 'origin.example.com', 'www.example.com', 'host-10.example.net', 'shop.example.net', 'cdn.example.org', 'mail.example.org']);
  });

  test('a private or reserved address: nothing leaves — no request, no PTR question; only the workspace', async () => {
    for (const ip of ['10.0.0.5', '224.0.0.5', 'fe80::5']) {
      const { fetchImpl, calls } = fakeFetch({});
      const intel = fakeIntel();
      const dns = fakeDns();
      const r = await createReverseIp({ fetchImpl, dns, intel, now: () => NOW }).lookup(ip, { keys: { shodan: SHODAN_KEY, whoisxml: WHOIS_KEY }, workspace: { origins: [{ name: 'app.example.com' }] } });
      assert.equal(r.local, true, ip);
      assert.deepEqual([calls, intel.calls, dns.calls], [[], [], []], `${ip}: nothing sent`);
      assert.deepEqual(REVERSE_SOURCES.filter((s) => r.results[s].skip === 'local'), REVERSE_SOURCES.filter((s) => s !== 'workspace'));
      assert.deepEqual(r.results.workspace.names.map((n) => n.name), ['app.example.com']);
    }
  });

  test('typed keys: one request each with the key in the query; the key never reaches a result', async () => {
    const shodanUrl = `${SHODAN_HOST}${IP}?key=${SHODAN_KEY}`;
    const whoisUrl = `${WHOISXML_REVERSE_IP}?apiKey=${WHOIS_KEY}&ip=${IP}`;
    const { fetchImpl, calls } = fakeFetch(routesFor(IP, {
      [shodanUrl]: () => json({ ip_str: IP, hostnames: ['web.example.com'], domains: ['example.com'], ports: [443] }),
      [whoisUrl]: () => { throw new TypeError(`Failed to fetch ${whoisUrl}`); }
    }));
    const svc = createReverseIp({ fetchImpl, dns: fakeDns(), intel: fakeIntel(), now: () => NOW, shodanPaceMs: 0 });
    const r = await svc.lookup(IP, { keys: { shodan: ` ${SHODAN_KEY} `, whoisxml: WHOIS_KEY } });
    assert.ok(calls.includes(shodanUrl) && calls.includes(whoisUrl));
    assert.deepEqual(r.results.shodan.names.map((n) => n.name), ['web.example.com', 'example.com']);
    assert.equal(r.results.whoisxml.state, 'failed');
    assert.equal(r.results.whoisxml.failure.errorKind, 'network');
    const text = JSON.stringify(r);
    assert.equal(text.includes(SHODAN_KEY) || text.includes(WHOIS_KEY), false, 'no key in the result');
  });

  test('a refused key is a failure with its HTTP status (401 / 403)', async () => {
    const shodanUrl = `${SHODAN_HOST}${IP}?key=${SHODAN_KEY}`;
    const whoisUrl = `${WHOISXML_REVERSE_IP}?apiKey=${WHOIS_KEY}&ip=${IP}`;
    const { fetchImpl } = fakeFetch(routesFor(IP, {
      [shodanUrl]: () => new Response('401 Unauthorized', { status: 401, headers: { 'content-type': 'text/plain' } }),
      [whoisUrl]: () => json({ code: 403, messages: 'Access restricted.' }, 403)
    }));
    const r = await createReverseIp({ fetchImpl, dns: fakeDns(), intel: fakeIntel(), now: () => NOW, shodanPaceMs: 0 })
      .lookup(IP, { sources: ['shodan', 'whoisxml'], keys: { shodan: SHODAN_KEY, whoisxml: WHOIS_KEY } });
    assert.deepEqual([r.results.shodan.failure.status, r.results.whoisxml.failure.status], [401, 403]);
    assert.equal(sourceStatus(r.results.shodan.failure).reason, 'http-status');
  });

  test('InternetDB: the first 429 locks it (no request until the lock ends) and says when to retry', async () => {
    let now = NOW;
    const { fetchImpl, calls } = fakeFetch({
      [internetDbUrl(IP)]: () => new Response('{"detail":"Too Many Requests"}', { status: 429 }),
      [internetDbUrl(IP2)]: () => json(INTERNETDB_BODY)
    });
    const svc = createReverseIp({ fetchImpl, dns: fakeDns(), intel: fakeIntel(), now: () => now });
    const a = await svc.lookup(IP, { sources: ['internetdb'] });
    assert.equal(a.results.internetdb.state, 'failed');
    assert.equal(sourceStatus(a.results.internetdb.failure, { now }).reason, 'rate-limit-wait');
    assert.equal(svc.lockedUntil(), NOW + INTERNETDB_LOCK_MS);
    now += 10 * 60 * 1000;
    const b = await svc.lookup(IP2, { sources: ['internetdb'] });
    assert.deepEqual(calls, [internetDbUrl(IP)], 'the second address is not sent while locked');
    assert.equal(b.results.internetdb.skip, 'locked');
    assert.deepEqual(sourceStatus(b.results.internetdb.failure, { now }).params, { minutes: 50 });
    now = NOW + INTERNETDB_LOCK_MS + 1;
    const c = await svc.lookup(IP2, { sources: ['internetdb'] });
    assert.equal(c.results.internetdb.state, 'ok', 'asked again once the lock is over');
    assert.equal(svc.lockedUntil(), null);
  });

  test('InternetDB 404 and Shodan 404 are answers (nothing known), not failures', async () => {
    const shodanUrl = `${SHODAN_HOST}${IP}?key=${SHODAN_KEY}`;
    const { fetchImpl } = fakeFetch({
      [internetDbUrl(IP)]: () => json({ detail: 'No information available' }, 404),
      [shodanUrl]: () => json({ error: 'No information available for that IP.' }, 404)
    });
    const r = await createReverseIp({ fetchImpl, now: () => NOW, shodanPaceMs: 0 }).lookup(IP, { sources: ['internetdb', 'shodan'], keys: { shodan: SHODAN_KEY } });
    assert.deepEqual([r.results.internetdb.state, r.results.internetdb.names, r.results.shodan.state], ['ok', [], 'ok']);
  });

  test('failures are statuses: a quota, a timeout-like network error, a PTR SERVFAIL; Retry asks only those again', async () => {
    let otxFails = true;
    const { fetchImpl, calls } = fakeFetch(routesFor(IP, {
      [otxUrl(IP)]: () => (otxFails ? new Response('Too Many Requests', { status: 429, headers: { 'retry-after': '120' } }) : json(OTX_BODY))
    }));
    const ptrErr = Object.assign(new Error('PTR lookup answered SERVFAIL'), { kind: 'unknown', rcode: 'SERVFAIL' });
    const intel = fakeIntel({ ht: { ok: false, domains: [], error: 'API count exceeded', limited: true, errorKind: 'rate-limit' } });
    const dns = fakeDns({ ptr: { [IP]: ptrErr } });
    const svc = createReverseIp({ fetchImpl, dns, intel, now: () => NOW });
    const first = await svc.lookup(IP);
    assert.deepEqual(REVERSE_SOURCES.filter((s) => first.results[s].state === 'failed'), ['ptr', 'hackertarget', 'otx']);
    assert.equal(sourceStatus(first.results.hackertarget.failure).reason, 'rate-limit-day');
    assert.deepEqual(sourceStatus(first.results.otx.failure, { now: NOW }).params, { minutes: 2 });
    assert.deepEqual(sourceStatus(first.results.ptr.failure).params, { rcode: 'SERVFAIL' });
    otxFails = false;
    calls.length = 0;
    intel.calls.length = 0;
    const again = await svc.retry(first, { sources: ['otx', 'hackertarget'] });
    assert.deepEqual(calls, [otxUrl(IP)], 'only OTX was fetched again');
    assert.deepEqual(intel.calls, [['hackertarget', IP, true]], 'HackerTarget asked again past its cache');
    assert.equal(again.results.otx.state, 'ok');
    assert.equal(again.results.ptr.state, 'failed', 'a source left out of the Retry keeps its failure');
    assert.equal(again.results.robtex.state, 'ok', 'the answers kept');
  });

  test('answers are cached per address; noCache asks again', async () => {
    const { fetchImpl, calls } = fakeFetch(routesFor(IP));
    const svc = createReverseIp({ fetchImpl, now: () => NOW });
    await svc.lookup(IP, { sources: ['otx', 'robtex'] });
    await svc.lookup(IP, { sources: ['otx', 'robtex'] });
    assert.equal(calls.length, 2);
    await svc.lookup(IP, { sources: ['otx'], noCache: true });
    assert.equal(calls.length, 3);
  });

  test('verify: a batch at a time; here / moved / cdn / none / failed; internal names never sent', async () => {
    const dns = fakeDns({
      hosts: {
        'www.example.com': { ipv4: [IP] },
        'shop.example.net': { ipv4: ['192.0.2.1'] },
        'cdn.example.org': { ipv4: ['192.0.2.9'], cnames: ['edge.cdn.example.net'] },
        'mail.example.org': { status: 'SERVFAIL', error: 'answered SERVFAIL' }
      }
    });
    const svc = createReverseIp({ dns, now: () => NOW, classify });
    const rows = mergeNames([{ ip: IP, results: { robtex: { state: 'ok', names: ['www.example.com', 'shop.example.net', 'cdn.example.org', 'mail.example.org', 'gone.example.com', 'db.corp'].map((name) => ({ name, first: null, last: null })) } } }]);
    const heard = [];
    assert.equal(await svc.verify(rows, { limit: 3, onRow: (r) => heard.push(r.name) }), 3);
    assert.equal(heard.length, 3);
    assert.equal(rows.filter((r) => r.status === 'unchecked').length, 2, 'the rest wait for "check more"');
    assert.equal(await svc.verify(rows), 2);
    const st = Object.fromEntries(rows.map((r) => [r.name, r.status]));
    assert.deepEqual(st, { 'db.corp': 'internal', 'gone.example.com': 'none', 'www.example.com': 'here', 'shop.example.net': 'moved', 'cdn.example.org': 'cdn', 'mail.example.org': 'failed' });
    assert.deepEqual(rows.find((r) => r.name === 'shop.example.net').resolvesTo, ['192.0.2.1']);
    assert.equal(rows.find((r) => r.name === 'cdn.example.org').provider, 'ExampleCDN');
    assert.equal(dns.calls.some(([, n]) => n === 'db.corp'), false, 'an internal name is never sent');
    assert.equal(await svc.verify(rows), 0, 'nothing left');
  });

  test('verify without an injected classification loads lib/netinfo.js on first use', async () => {
    const dns = fakeDns({ hosts: { 'www.example.com': { ipv4: ['192.0.2.1'] } } });
    const rows = mergeNames([{ ip: IP, results: { otx: { state: 'ok', names: [{ name: 'www.example.com', first: null, last: null }] } } }]);
    await createReverseIp({ dns }).verify(rows);
    assert.equal(rows[0].status, 'moved');
  });

  test('an abort rejects; names it did not reach stay unchecked', async () => {
    const ctl = new AbortController();
    ctl.abort();
    const { fetchImpl } = fakeFetch(routesFor(IP));
    await assert.rejects(createReverseIp({ fetchImpl }).lookup(IP, { signal: ctl.signal }), { name: 'AbortError' });
    const rows = mergeNames([{ ip: IP, results: { otx: { state: 'ok', names: [{ name: 'www.example.com', first: null, last: null }] } } }]);
    await assert.rejects(createReverseIp({ dns: fakeDns(), classify }).verify(rows, { signal: ctl.signal }), { name: 'AbortError' });
    assert.equal(rows[0].status, 'unchecked');
  });
});
