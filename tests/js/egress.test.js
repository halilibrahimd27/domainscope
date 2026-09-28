/**
 * "What this page sent" (About): the request log (lib/egresslog.js), the registry of endpoints and
 * what each receives (lib/egress.js), the ledger rows, and the fetch / Resource Timing meter
 * (ui/egress-meter.js) against a fake window.
 *
 * The code scan at the end is the registry's guarantee: every file that can send a request is
 * declared below with the services it talks to, and every URL literal in those files must be one
 * the registry classifies (as one of those services) or a link the user opens. A new endpoint, or
 * a new file that sends, fails here until the registry — and so the ledger — knows it. No network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  requestSignature, requestCount, countRequests, createEgressLog, EGRESS_VIA, MAX_SIGNATURES, OVERFLOW_PATH
} from '../../assets/js/lib/egresslog.js';
import {
  DATA_KINDS, EGRESS_ROLES, EGRESS_SERVICES, NEVER_SENT, SELF_SERVICE, classifySignature, classifyUrl, getEgressService,
  ledgerRows, ledgerTotals, serviceSends
} from '../../assets/js/lib/egress.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { certspotterUrl, crtshSearchUrls, CRTSH_BASE, CERTSPOTTER_ISSUANCES } from '../../assets/js/lib/ctcert.js';
import { certspotterIssuersUrl, crtshIssuersUrl } from '../../assets/js/lib/passport.js';
import { announcedPrefixesUrl } from '../../assets/js/lib/ptrsweep.js';
import { RIPESTAT_BASE, RIPESTAT_SOURCEAPP, IPWHOIS_BASE, HACKERTARGET_REVERSE_IP, THC_REVERSE_IP } from '../../assets/js/lib/ipintel.js';
import { IANA_BOOTSTRAP, RDAP_ORG } from '../../assets/js/lib/rdap.js';
import { GLOBALPING_API } from '../../assets/js/lib/globalping.js';
import { crtshKeyUrl } from '../../assets/js/lib/keycontinuity.js';
import { startEgressMeter, egressLog, egressMeterStatus } from '../../assets/js/ui/egress-meter.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PAGE = 'https://example.org';
const HASH = 'ab'.repeat(32);

/* ------------------------------------------------------------------------ */
/* lib/egresslog.js                                                         */
/* ------------------------------------------------------------------------ */

describe('requestSignature', () => {
  test('keeps where a request went and the shape of what it asked, never a value', () => {
    const sig = requestSignature('https://crt.sh/?q=%25.example.com&output=json&exclude=expired&deduplicate=Y');
    assert.deepEqual(sig, {
      key: 'https://crt.sh/?deduplicate&exclude&output&q', origin: 'https://crt.sh', host: 'crt.sh', path: '/', query: 'deduplicate&exclude&output&q'
    });
    assert.equal(requestSignature('https://ipwho.is/192.0.2.1').key, 'https://ipwho.is/*');
    assert.equal(requestSignature('https://anubisdb.com/anubis/subdomains/example.com').path, '/anubis/subdomains/*');
    assert.equal(requestSignature('https://api.globalping.io/v1/measurements/AbC123xyz').path, '/*/measurements/*');
    assert.equal(requestSignature('https://rdap.example.net/com/v1/domain/EXAMPLE.COM').path, '/com/*/domain/*');
    assert.equal(requestSignature('https://rdap.example.net/ip/192.0.2.0/24').path, '/ip/*/*');
    assert.equal(requestSignature('https://doh.cleanbrowsing.org/doh/security-filter/?dns=AAAB').key, 'https://doh.cleanbrowsing.org/doh/security-filter/?dns');
    assert.equal(requestSignature('https://api.hackertarget.com/hostsearch/?q=example.com').path, '/hostsearch/');
    // Only plain words of a path are kept; names, addresses, hashes and ids never are.
    for (const url of ['https://crt.sh/?spkisha256=' + HASH, 'https://ipwho.is/2001:db8::1', 'https://x.example/secret.example.com/v2?token=s3cr3t']) {
      const s = requestSignature(url);
      assert.ok(!/example\.com|2001|db8|secret|s3cr3t|abab/i.test(JSON.stringify({ ...s, key: s.key.replace(s.origin, '') })), url);
    }
    assert.equal(requestSignature('https://x.example/p?Token=1&token=2&%24weird=3').query, '*&token', 'names lower-cased, odd ones as *');
  });

  test('relative URLs resolve against the page; anything but http(s) is not a request of the page', () => {
    assert.equal(requestSignature('assets/data/wordlist-base.txt', `${PAGE}/domainscope/`).key, `${PAGE}/domainscope/assets/data/*`);
    assert.equal(requestSignature('v/abc123/assets/version.json', `${PAGE}/domainscope/`).path, '/domainscope/v/*/assets/*');
    for (const bad of ['data:text/plain,hello', 'blob:https://example.org/1', 'chrome-extension://abc/x.js', 'not a url', '', null]) {
      assert.equal(requestSignature(bad), null, String(bad));
    }
  });

  test('long paths and long queries are cut, so the key stays short', () => {
    const long = requestSignature('https://example.org/a/b/c/d/e/f/g/h/i/j/k');
    assert.equal(long.path, `/a/b/c/d/e/f/g/h${OVERFLOW_PATH}`);
    const many = requestSignature(`https://example.org/?${Array.from({ length: 12 }, (_, i) => `p${String.fromCharCode(97 + i)}=1`).join('&')}`);
    assert.equal(many.query.split('&').length, 11);
    assert.ok(many.query.endsWith('&…'));
  });
});

describe('createEgressLog', () => {
  const clock = () => {
    let t = 1000;
    return { now: () => t, tick: (ms = 1) => { t += ms; } };
  };

  test('counts each witness; a request seen by both counts once; redirects add up; failures are marked', () => {
    const c = clock();
    const log = createEgressLog({ now: c.now });
    const url = 'https://dns.google/dns-query?dns=AAAB';
    for (let i = 0; i < 3; i += 1) log.record(url, { via: 'fetch' });
    log.record(url, { via: 'resource' });
    log.record(url, { via: 'resource' });
    log.record(url, { via: 'failed' });
    c.tick(5);
    log.record('https://rdap.example.net/domain/example.com', { via: 'redirect' });
    const [dns, rdap] = log.snapshot().entries;
    assert.deepEqual({ fetch: dns.fetch, resource: dns.resource, failed: dns.failed, redirect: dns.redirect }, { fetch: 3, resource: 2, failed: 1, redirect: 0 });
    assert.equal(requestCount(dns), 3, 'the larger witness: Resource Timing misses the unanswered one');
    assert.equal(requestCount(rdap), 1);
    assert.equal(rdap.first, 1005);
    assert.equal(requestCount({ fetch: 1, resource: 4, redirect: 2 }), 6);
    assert.equal(requestCount(null), 0);
    assert.equal(log.record(url, { via: 'beacon' }), false, 'an unknown witness is ignored');
    assert.equal(log.record('data:,x'), false);
  });

  test('a snapshot is a copy; clear starts over; since moves', () => {
    const c = clock();
    const log = createEgressLog({ now: c.now });
    log.record('https://crt.sh/?q=example.com&output=json');
    const snap = log.snapshot();
    snap.entries[0].fetch = 99;
    assert.equal(log.snapshot().entries[0].fetch, 1);
    c.tick(500);
    log.clear();
    const empty = log.snapshot();
    assert.deepEqual(empty.entries, []);
    assert.equal(empty.since, 1500);
  });

  test('listeners hear once per burst of records, never per request, and a failing listener harms nobody', async () => {
    const log = createEgressLog();
    let calls = 0;
    log.subscribe(() => { throw new Error('listener bug'); });
    const off = log.subscribe(() => { calls += 1; });
    for (let i = 0; i < 1000; i += 1) log.record(`https://cloudflare-dns.com/dns-query?dns=${i}`);
    await Promise.resolve();
    assert.equal(calls, 1);
    log.clear();
    await Promise.resolve();
    assert.equal(calls, 2);
    off();
    log.record('https://cloudflare-dns.com/dns-query?dns=x');
    await Promise.resolve();
    assert.equal(calls, 2);
  });

  test('past the signature cap, new shapes of an origin share one overflow entry', () => {
    const log = createEgressLog({ maxSignatures: 3 });
    for (const p of ['a', 'b', 'c', 'd', 'e']) log.record(`https://example.net/${p}`);
    log.record('https://example.net/a');
    const entries = log.snapshot().entries;
    assert.equal(entries.length, 4);
    const overflow = entries.find((e) => e.path === OVERFLOW_PATH);
    assert.equal(overflow.fetch, 2);
    assert.equal(entries.find((e) => e.path === '/a').fetch, 2, 'a known shape keeps its own entry');
    assert.equal(MAX_SIGNATURES, 400);
    assert.deepEqual([...EGRESS_VIA], ['fetch', 'resource', 'redirect', 'failed']);
  });

  test('countRequests splits third parties from the page\'s own files', () => {
    const log = createEgressLog();
    log.record(`${PAGE}/assets/js/app.js`, { via: 'resource' });
    log.record(`${PAGE}/assets/js/app.js`, { via: 'resource' });
    log.record('https://crt.sh/?q=example.com');
    log.record('https://crt.sh/?q=example.net');
    log.record('https://dns.google/dns-query?dns=x', { via: 'failed' });
    assert.deepEqual(countRequests(log.snapshot().entries, PAGE), { thirdParty: 2, self: 2, hosts: 1 });
    assert.deepEqual(countRequests(null, PAGE), { thirdParty: 0, self: 0, hosts: 0 });
  });
});

/* ------------------------------------------------------------------------ */
/* lib/egress.js: the registry                                              */
/* ------------------------------------------------------------------------ */

describe('the registry', () => {
  test('is consistent: unique ids and hosts, known roles and kinds, every kind used', () => {
    const ids = EGRESS_SERVICES.map((s) => s.id);
    assert.equal(new Set(ids).size, ids.length);
    const hosts = EGRESS_SERVICES.flatMap((s) => s.hosts);
    assert.equal(new Set(hosts).size, hosts.length, 'a host belongs to one service');
    const used = new Set(SELF_SERVICE.endpoints[0].sends);
    for (const s of EGRESS_SERVICES) {
      assert.ok(EGRESS_ROLES.includes(s.role), s.id);
      assert.ok(s.endpoints.length, s.id);
      for (const e of s.endpoints) {
        assert.ok(e.sends.length, `${s.id}.${e.id}`);
        for (const k of e.sends) {
          assert.ok(DATA_KINDS.includes(k), `${s.id}.${e.id}: ${k}`);
          used.add(k);
        }
      }
      assert.deepEqual(serviceSends(s), DATA_KINDS.filter((k) => s.endpoints.some((e) => e.sends.includes(k))));
    }
    assert.deepEqual(DATA_KINDS.filter((k) => !used.has(k)), [], 'a kind nothing sends');
    assert.equal(getEgressService('crtsh').name, 'crt.sh');
    assert.equal(getEgressService('self'), SELF_SERVICE);
    assert.equal(getEgressService('nope'), null);
    assert.deepEqual([...NEVER_SENT], ['certificates', 'keys', 'zone', 'inventory', 'workspace', 'tracking']);
  });

  test('every DoH resolver is a DNS-over-HTTPS host of the registry, named as the resolver', () => {
    for (const r of RESOLVERS) {
      const c = classifyUrl(`${r.url}?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE`);
      assert.equal(c.service.id, 'doh', r.id);
      assert.equal(c.label, r.name, r.id);
      assert.deepEqual(c.sends, ['dnsQuestions'], r.id);
    }
  });

  test('maps each endpoint the code builds to what it receives', () => {
    const cases = [
      // Certificate Transparency: domain searches, the Certificate view's serial search, the key search
      [certspotterUrl('www.example.com'), 'certspotter', 'issuances', ['domains']],
      [certspotterIssuersUrl('example.com'), 'certspotter', 'issuances', ['domains']],
      ['https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names&after=123', 'certspotter', 'issuances', ['domains']],
      [crtshSearchUrls('www.example.com')[0], 'crtsh', 'search', ['domains']],
      [crtshIssuersUrl('example.com'), 'crtsh', 'search', ['domains']],
      ['https://crt.sh/?q=%25.example.com&output=json&exclude=expired&deduplicate=Y', 'crtsh', 'search', ['domains']],
      ['https://crt.sh/?serial=0123abcd&output=json', 'crtsh', 'serial', ['certSerial']],
      [crtshKeyUrl(HASH), 'crtsh', 'key', ['keyHash']],
      // passive sources
      ['https://api.hackertarget.com/hostsearch/?q=example.com', 'hackertarget', 'hostsearch', ['domains']],
      [`${HACKERTARGET_REVERSE_IP}?q=192.0.2.1`, 'hackertarget', 'reverseip', ['ipAddresses']],
      ['https://anubisdb.com/anubis/subdomains/example.com', 'anubis', 'subdomains', ['domains']],
      ['https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns', 'otx', 'passive-dns', ['domains']],
      ['https://ip.thc.org/api/v1/lookup/subdomains', 'thc', 'subdomains', ['domains']],
      [THC_REVERSE_IP, 'thc', 'reverseip', ['ipAddresses']],
      // IP data
      [`${RIPESTAT_BASE}/prefix-overview/data.json?resource=192.0.2.1&sourceapp=${RIPESTAT_SOURCEAPP}`, 'ripestat', 'address', ['ipAddresses']],
      [`${RIPESTAT_BASE}/maxmind-geo-lite/data.json?resource=2001:db8::1&sourceapp=${RIPESTAT_SOURCEAPP}`, 'ripestat', 'address', ['ipAddresses']],
      [announcedPrefixesUrl(64496), 'ripestat', 'prefixes', ['asNumbers']],
      [`${IPWHOIS_BASE}/192.0.2.1`, 'ipwhois', 'address', ['ipAddresses']],
      // registration: the bootstrap is a public list; any registry server the bootstrap names, by its path
      [IANA_BOOTSTRAP.dns, 'rdap-bootstrap', 'bootstrap', ['nothing']],
      [IANA_BOOTSTRAP.ipv6, 'rdap-bootstrap', 'bootstrap', ['nothing']],
      [`${RDAP_ORG}domain/example.com`, 'rdap', 'domain', ['domains']],
      ['https://rdap.example.net/com/v1/domain/EXAMPLE.COM', 'rdap', 'domain', ['domains']],
      ['https://rdap.example.net/rdap/ip/192.0.2.1', 'rdap', 'ip', ['ipAddresses']],
      ['https://rdap.example.net/ip/2001:db8::/32', 'rdap', 'ip-network', ['ipAddresses']],
      // checks from the internet
      [`${GLOBALPING_API}/limits`, 'globalping', 'limits', ['nothing']],
      [`${GLOBALPING_API}/measurements`, 'globalping', 'create', ['hostnames', 'ipNamePairs']],
      [`${GLOBALPING_API}/measurements/AbCdEf123`, 'globalping', 'result', ['measurementIds']]
    ];
    for (const [url, service, endpoint, sends] of cases) {
      const c = classifyUrl(url);
      assert.equal(c.service && c.service.id, service, url);
      assert.equal(c.endpoint && c.endpoint.id, endpoint, url);
      assert.deepEqual([...c.sends].sort(), [...sends].sort(), url);
    }
    assert.equal(CRTSH_BASE, 'https://crt.sh/');
    assert.equal(classifyUrl(CERTSPOTTER_ISSUANCES).service.id, 'certspotter');
  });

  test('the page\'s own origin is the app\'s files; an unknown host, plain http or an odd crt.sh request say so', () => {
    const self = classifyUrl(`${PAGE}/assets/data/sample-cert.pem`, { origin: PAGE });
    assert.equal(self.service, SELF_SERVICE);
    assert.deepEqual(self.sends, ['appFiles']);
    const unknown = classifyUrl('https://tracker.example.net/pixel.gif?id=1');
    assert.deepEqual({ service: unknown.service, endpoint: unknown.endpoint, sends: unknown.sends }, { service: null, endpoint: null, sends: [] });
    assert.equal(classifyUrl('http://crt.sh/?q=example.com').service, null, 'never over plain http');
    const odd = classifyUrl('https://crt.sh/?id=123');
    assert.equal(odd.service.id, 'crtsh');
    assert.equal(odd.endpoint, null);
    assert.deepEqual(odd.sends, serviceSends(getEgressService('crtsh')), 'an unknown endpoint: everything the service can get');
    assert.equal(classifyUrl('ftp://example.org/x'), null);
  });
});

describe('ledgerRows / ledgerTotals', () => {
  const snapshotOf = (records) => {
    let t = 0;
    const log = createEgressLog({ now: () => (t += 1) });
    for (const [url, via = 'fetch', times = 1] of records) for (let i = 0; i < times; i += 1) log.record(url, { via });
    return log.snapshot();
  };

  test('one row per host, unknown hosts first, services in registry order, the page last', () => {
    const snap = snapshotOf([
      [`${PAGE}/assets/js/app.js`, 'resource', 5],
      ['https://crt.sh/?q=example.com&output=json', 'fetch', 2],
      ['https://crt.sh/?q=example.com&output=json', 'resource', 2],
      [crtshKeyUrl(HASH), 'fetch', 1],
      [crtshKeyUrl(HASH), 'failed', 1],
      ['https://dns.google/dns-query?dns=a', 'fetch', 7],
      ['https://cloudflare-dns.com/dns-query?dns=a', 'resource', 9],
      ['https://tracker.example.net/pixel.gif', 'resource', 1],
      [`${GLOBALPING_API}/limits`, 'fetch', 1],
      [`${GLOBALPING_API}/measurements`, 'fetch', 2],
      [`${GLOBALPING_API}/measurements/Abc1`, 'fetch', 3]
    ]);
    const rows = ledgerRows(snap, { origin: PAGE });
    assert.deepEqual(rows.map((r) => [r.host, r.kind, r.serviceId]), [
      ['tracker.example.net', 'unknown', null],
      ['cloudflare-dns.com', 'service', 'doh'],
      ['dns.google', 'service', 'doh'],
      ['crt.sh', 'service', 'crtsh'],
      ['api.globalping.io', 'service', 'globalping'],
      ['example.org', 'self', 'self']
    ]);
    const crt = rows.find((r) => r.host === 'crt.sh');
    assert.equal(crt.requests, 3);
    assert.equal(crt.failed, 1);
    assert.deepEqual(crt.sends, ['domains', 'keyHash']);
    assert.deepEqual(crt.endpoints.map((e) => [e.id, e.requests]), [['search', 2], ['key', 1]]);
    assert.equal(rows.find((r) => r.host === 'dns.google').name, 'Google Public DNS');
    const gp = rows.find((r) => r.serviceId === 'globalping');
    assert.deepEqual(gp.sends, ['nothing', 'hostnames', 'ipNamePairs', 'measurementIds']);
    assert.equal(rows[0].name, '');
    assert.deepEqual(rows[0].sends, []);
    assert.deepEqual(ledgerTotals(rows), { requests: 3 + 7 + 9 + 1 + 6, services: 3, hosts: 5, self: 5, unknown: 1, failed: 1 });
  });

  test('an unregistered host stays unknown even when one of its paths looks like an RDAP query', () => {
    const rows = ledgerRows(snapshotOf([
      ['https://tracker.example.net/domain/example.com'],
      ['https://tracker.example.net/collect?x=1']
    ]), { origin: PAGE });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].kind, 'unknown');
    assert.equal(rows[0].requests, 2);
    const rdap = ledgerRows(snapshotOf([['https://rdap.example.net/domain/example.com', 'fetch', 2]]), { origin: PAGE });
    assert.deepEqual([rdap[0].kind, rdap[0].serviceId, rdap[0].name], ['service', 'rdap', 'RDAP']);
  });

  test('an empty session is an empty ledger', () => {
    assert.deepEqual(ledgerRows({ entries: [] }), []);
    assert.deepEqual(ledgerRows(null), []);
    assert.deepEqual(ledgerTotals([]), { requests: 0, services: 0, hosts: 0, self: 0, unknown: 0, failed: 0 });
    assert.equal(classifySignature(requestSignature(`${PAGE}/x`), { origin: PAGE }).service, SELF_SERVICE);
  });
});

/* ------------------------------------------------------------------------ */
/* ui/egress-meter.js against a fake window                                 */
/* ------------------------------------------------------------------------ */

test('the meter wraps fetch without changing it, and feeds Resource Timing entries in', async () => {
  let observer = null;
  class FakeObserver {
    static supportedEntryTypes = ['resource', 'navigation'];
    constructor(cb) {
      this.cb = cb;
      observer = this;
    }
    observe(opts) {
      this.opts = opts;
    }
  }
  const calls = [];
  const win = {
    location: { href: `${PAGE}/domainscope/` },
    PerformanceObserver: FakeObserver,
    fetch(input, init) {
      calls.push([this, input, init]);
      const url = typeof input === 'string' ? input : input.url;
      if (url.includes('down')) return Promise.reject(new TypeError('Failed to fetch'));
      if (url.includes('moved')) return Promise.resolve({ ok: true, redirected: true, url: 'https://rdap.example.net/domain/example.com' });
      return Promise.resolve({ ok: true, redirected: false, url });
    }
  };
  const original = win.fetch;
  assert.deepEqual(startEgressMeter(win), { fetch: true, resourceTiming: true });
  assert.notEqual(win.fetch, original);
  assert.deepEqual(observer.opts, { type: 'resource', buffered: true });

  const init = { headers: { accept: 'application/json' } };
  const res = await win.fetch('https://crt.sh/?q=example.com', init);
  assert.equal(res.url, 'https://crt.sh/?q=example.com');
  assert.equal(calls[0][0], win, 'called on the window');
  assert.equal(calls[0][2], init, 'the same init');
  await assert.rejects(win.fetch({ url: 'https://down.example.net/x' }), /Failed to fetch/);
  await win.fetch('https://rdap.org/domain/moved.example');
  await win.fetch('assets/data/wordlist-base.txt');
  observer.cb({ getEntries: () => [{ name: 'https://crt.sh/?q=example.com' }, { name: `${PAGE}/domainscope/assets/js/app.js` }] });

  const rows = ledgerRows(egressLog.snapshot(), { origin: PAGE });
  const byHost = Object.fromEntries(rows.map((r) => [r.host, r]));
  assert.equal(byHost['crt.sh'].requests, 1, 'fetch + Resource Timing of one request');
  assert.equal(byHost['down.example.net'].failed, 1);
  assert.equal(byHost['rdap.example.net'].redirect, 1, 'the redirect target counts as contacted');
  assert.equal(byHost['example.org'].requests, 2, 'a relative fetch and a module, both the page\'s own');
  assert.deepEqual(egressMeterStatus(), { fetch: true, resourceTiming: true });
  assert.deepEqual(startEgressMeter(win), { fetch: true, resourceTiming: true }, 'installed once');
});

/* ------------------------------------------------------------------------ */
/* The code scan: the registry knows every endpoint the code can call       */
/* ------------------------------------------------------------------------ */

/**
 * Every file that can send a request (a fetch call, a fetch function passed on, a URL fetched),
 * relative to the repository, with the registry services it sends to. [] = it only passes a fetch
 * function or a URL it was given to another module (a transport or a forwarder). 'self' = the
 * page's own origin only.
 */
const CALL_SITES = {
  'sw.js': ['self'],
  'assets/js/app.js': ['self'],
  'assets/js/lib/util.js': [],
  'assets/js/lib/doh.js': ['doh'],
  'assets/js/lib/ctcert.js': ['certspotter', 'crtsh'],
  'assets/js/lib/sources.js': ['crtsh', 'certspotter', 'hackertarget', 'anubis', 'otx', 'thc'],
  'assets/js/lib/ipintel.js': ['ripestat', 'ipwhois', 'hackertarget', 'thc'],
  'assets/js/lib/ptrsweep.js': ['ripestat'],
  'assets/js/lib/rdap.js': ['rdap-bootstrap', 'rdap'],
  'assets/js/lib/globalping.js': ['globalping'],
  'assets/js/lib/passport.js': ['certspotter', 'crtsh', 'rdap'],
  'assets/js/lib/keycontinuity.js': ['crtsh'],
  'assets/js/lib/wordlist.js': ['self'],
  'assets/js/lib/scanner.js': [],
  'assets/js/lib/health.js': [],
  'assets/js/views/bulk.js': [],
  'assets/js/views/cert.js': ['self', 'crtsh'],
  'assets/js/ui/egress-meter.js': [],
  'assets/js/ui/egress-panel.js': ['self']
};
/** Links the user opens (never fetched) in a call-site file, by host. */
const LINK_HOSTS = {
  'assets/js/app.js': ['github.com'],
  'assets/js/lib/passport.js': ['www.trabis.gov.tr', 'webwhois.denic.de', 'whois.jprs.jp', 'www.nic.ch', 'www.iana.org']
};
/** Network APIs the app never uses: every request goes through fetch, where the meter counts it. */
const FORBIDDEN = /\bXMLHttpRequest\b|\bsendBeacon\b|\bnew\s+WebSocket\b|\bnew\s+EventSource\b|\bimportScripts\s*\(|\bnew\s+(?:Shared)?Worker\b|\bnew\s+Image\s*\(|\bRTCPeerConnection\b/;
/** A network call site: a fetch call, a fetch function passed on, or the global fetch touched. */
const CALL_RE = /\b(?:fetch|fetchJson|fetchText|fetchWithTimeout|fetchAndRead)\s*\(|\bfetchImpl\b|\b(?:globalThis|window|self|win)\.fetch\b/;

const walk = (d) => readdirSync(d).flatMap((f) => {
  const p = join(d, f);
  return statSync(p).isDirectory() ? walk(p) : [p];
});

/**
 * JavaScript source without comments, and the contents of its string and template literals
 * (a template's `${…}` becomes `0`). Enough of a lexer for this codebase: strings, templates with
 * nested expressions, regular expression literals, line and block comments.
 * @param {string} src
 * @returns {{ code: string, literals: string[] }}
 */
function lex(src) {
  const literals = [];
  let code = '';
  let i = 0;
  let prev = '';
  let word = '';
  const REGEX_AFTER = new Set(['', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^']);
  const REGEX_WORDS = new Set(['return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'void', 'yield', 'await', 'new', 'delete', 'throw', 'instanceof']);
  const readString = (quote) => {
    let text = '';
    i += 1;
    while (i < src.length && src[i] !== quote) {
      if (src[i] === '\\') {
        text += src[i + 1];
        i += 2;
      } else {
        text += src[i];
        i += 1;
      }
    }
    i += 1;
    return text;
  };
  const scan = (stopAtBrace) => {
    let depth = 0;
    while (i < src.length) {
      const c = src[i];
      const n = src[i + 1];
      if (c === '/' && n === '/') {
        while (i < src.length && src[i] !== '\n') i += 1;
        continue;
      }
      if (c === '/' && n === '*') {
        const end = src.indexOf('*/', i + 2);
        i = end === -1 ? src.length : end + 2;
        code += ' ';
        continue;
      }
      if (c === '"' || c === "'") {
        const text = readString(c);
        literals.push(text);
        code += `${c}${text.replace(/[\n\r]/g, ' ')}${c}`;
        prev = c;
        word = '';
        continue;
      }
      if (c === '`') {
        let text = '';
        i += 1;
        while (i < src.length && src[i] !== '`') {
          if (src[i] === '\\') {
            text += src[i + 1];
            i += 2;
          } else if (src[i] === '$' && src[i + 1] === '{') {
            i += 2;
            text += '0';
            code += '`';
            scan(true);
            code += '`';
          } else {
            text += src[i];
            i += 1;
          }
        }
        i += 1;
        literals.push(text);
        code += `\`${text.replace(/[\n\r]/g, ' ')}\``;
        prev = '`';
        word = '';
        continue;
      }
      if (c === '/' && (REGEX_AFTER.has(prev) || REGEX_WORDS.has(word))) {
        let inClass = false;
        code += c;
        i += 1;
        while (i < src.length) {
          const r = src[i];
          code += r;
          i += 1;
          if (r === '\\') {
            code += src[i];
            i += 1;
          } else if (r === '[') inClass = true;
          else if (r === ']') inClass = false;
          else if (r === '/' && !inClass) break;
        }
        prev = '/';
        word = '';
        continue;
      }
      if (stopAtBrace) {
        if (c === '{') depth += 1;
        if (c === '}') {
          if (depth === 0) {
            i += 1;
            return;
          }
          depth -= 1;
        }
      }
      code += c;
      i += 1;
      if (/[A-Za-z0-9_$]/.test(c)) word = /[A-Za-z0-9_$]/.test(prev) ? word + c : c;
      if (!/\s/.test(c)) prev = /[A-Za-z0-9_$]/.test(c) ? 'w' : c;
    }
  };
  scan(false);
  return { code, literals };
}

describe('the code scan', () => {
  const files = [...walk(join(ROOT, 'assets', 'js')).filter((f) => f.endsWith('.js')), join(ROOT, 'sw.js')];
  const rel = (f) => relative(ROOT, f).split(sep).join('/');
  const lexed = new Map(files.map((f) => [rel(f), lex(readFileSync(f, 'utf8'))]));

  test('the lexer sees comments, strings, templates and regular expressions for what they are', () => {
    const { code, literals } = lex([
      "const a = 'https://one.example/x'; // fetch('https://two.example/')",
      '/* fetchImpl https://three.example/ */ const re = /\\/\\/[a-z]+/g;',
      'const t = `https://four.example/${host}/y?z=${a ? \'1\' : `in${2}`}`;',
      'const d = x / 2 / y;'
    ].join('\n'));
    assert.deepEqual(literals, ['https://one.example/x', '1', 'in0', 'https://four.example/0/y?z=0']);
    assert.ok(!/two\.example|three\.example|fetchImpl/.test(code), code);
    assert.match(code, /x \/ 2 \/ y/);
  });

  test('no file uses a network API the meter cannot see (XHR, beacons, sockets, workers, images)', () => {
    const bad = [...lexed].filter(([, l]) => FORBIDDEN.test(l.code)).map(([f]) => f);
    assert.deepEqual(bad, []);
  });

  test('every file that can send a request is declared, and every declared one still can', () => {
    const found = [...lexed].filter(([, l]) => CALL_RE.test(l.code)).map(([f]) => f).sort();
    assert.deepEqual(found, Object.keys(CALL_SITES).sort(), 'declare a new call site in CALL_SITES (and its endpoints in lib/egress.js)');
    for (const ids of Object.values(CALL_SITES)) {
      for (const id of ids) assert.ok(id === 'self' || getEgressService(id), `${id} is a registry service`);
    }
  });

  test('every URL literal of a call site is an endpoint the registry classifies as one of its services, or a link', () => {
    const bad = [];
    const seen = new Set();
    for (const [file, ids] of Object.entries(CALL_SITES)) {
      const links = LINK_HOSTS[file] || [];
      for (const lit of lexed.get(file).literals) {
        if (!/^https?:\/\//i.test(lit)) continue;
        let host;
        try {
          host = new URL(lit).host;
        } catch {
          bad.push(`${file}: unparseable ${lit}`);
          continue;
        }
        // a link the user opens, or a reserved .invalid name (a URL-parsing trick, never contacted)
        if (links.includes(host) || host.endsWith('.invalid')) continue;
        const c = classifyUrl(lit);
        if (!c || !c.service) bad.push(`${file}: ${lit} is not in lib/egress.js`);
        else if (!ids.includes(c.service.id)) bad.push(`${file}: ${lit} is ${c.service.id}, not declared for this file`);
        else seen.add(c.service.id);
      }
    }
    assert.deepEqual(bad, []);
    // every registry service has an endpoint in the code (DNS-over-HTTPS: lib/resolvers.js, above)
    assert.deepEqual(EGRESS_SERVICES.map((s) => s.id).filter((id) => id !== 'doh' && !seen.has(id)), [], 'a service no code calls');
  });

  test('the links the call sites carry are declared hosts, and no link host is a service the page calls', () => {
    for (const [file, hosts] of Object.entries(LINK_HOSTS)) {
      const present = new Set(lexed.get(file).literals.filter((l) => /^https?:\/\//.test(l)).map((l) => new URL(l).host));
      for (const host of hosts) {
        assert.ok(present.has(host), `${file}: ${host} is no longer linked`);
        assert.equal(classifyUrl(`https://${host}/`).service, null, host);
      }
    }
  });
});
