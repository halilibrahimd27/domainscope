/**
 * "What this page sent" (About): the request log (lib/egresslog.js), the registry of endpoints and
 * what each receives (lib/egress.js), the ledger rows, and the fetch / Resource Timing meter
 * (ui/egress-meter.js) against a fake window.
 *
 * The code scan at the end is the registry's guarantee: every file that can send a request is
 * declared below with the services it talks to, and every URL literal of every file must be one
 * the registry classifies (in a call site, as one of its services) or a link that file declares —
 * a URL constant can live in a module without a fetch call and be fetched by one that imports it.
 * A new endpoint, or a new file that sends, fails here until the registry — and so the ledger —
 * knows it. The senders' notes (what a POST body carried, a registry's RDAP server) are checked
 * against the real lib/globalping.js and lib/rdap.js. No network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  requestSignature, requestCount, countRequests, createEgressLog, noteRequest, onRequestNote, EGRESS_VIA, MAX_NOTES, MAX_SIGNATURES,
  OVERFLOW_PATH
} from '../../assets/js/lib/egresslog.js';
import {
  DATA_KINDS, EGRESS_ROLES, EGRESS_SERVICES, NEVER_SENT, SELF_SERVICE, classifySignature, classifyUrl, getEgressService,
  ledgerRows, ledgerTotals, serviceSends
} from '../../assets/js/lib/egress.js';
import { RESOLVERS, ECS_RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { certspotterUrl, crtshSearchUrls, CRTSH_BASE, CERTSPOTTER_ISSUANCES } from '../../assets/js/lib/ctcert.js';
import { certspotterIssuersUrl, crtshIssuersUrl } from '../../assets/js/lib/passport.js';
import { announcedPrefixesUrl } from '../../assets/js/lib/ptrsweep.js';
import { RIPESTAT_BASE, RIPESTAT_SOURCEAPP, IPWHOIS_BASE, HACKERTARGET_REVERSE_IP, THC_REVERSE_IP } from '../../assets/js/lib/ipintel.js';
import { IANA_BOOTSTRAP, RDAP_ORG, rdapDomain } from '../../assets/js/lib/rdap.js';
import { GLOBALPING_API, createGlobalping, httpsGetRequest, dnsQueryRequest } from '../../assets/js/lib/globalping.js';
import { crtshKeyUrl } from '../../assets/js/lib/keycontinuity.js';
import { ZONE_PROVIDERS, getZoneProvider } from '../../assets/js/lib/zonefetch.js';
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

  test('the segment after a word that names a value is masked, even a plain word', () => {
    // a Globalping id without digits, a single-label RDAP name, an Anubis search of a bare word
    assert.equal(requestSignature('https://api.globalping.io/v1/measurements/abcdefghijklmnop').path, '/*/measurements/*');
    assert.equal(requestSignature('https://rdap.example.net/domain/localhost').path, '/domain/*');
    assert.equal(requestSignature('https://rdap.example.net/rdap/ip/fe/80').path, '/rdap/ip/*/*');
    assert.equal(requestSignature('https://anubisdb.com/anubis/subdomains/intranet').path, '/anubis/subdomains/*');
    assert.equal(requestSignature('https://otx.alienvault.com/api/v1/indicators/domain/intranet/passive_dns').path,
      '/api/*/indicators/domain/*/passive_dns', 'the fixed words after the value stay');
    assert.equal(requestSignature('https://ip.thc.org/api/v1/lookup/subdomains').path, '/api/*/lookup/subdomains');
    // a zone name at a DNS provider's API, even one without a dot
    assert.equal(requestSignature('https://desec.io/api/v1/domains/intranet/rrsets/?type=A').key, 'https://desec.io/api/*/domains/*/rrsets/?type');
    assert.equal(requestSignature('https://api.digitalocean.com/v2/domains/example.com/records?per_page=200&page=1').path, '/*/domains/*/records');
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

  test('notes attach to a signature, only as fixed words; a redirect takes its request\'s notes along', () => {
    const log = createEgressLog();
    const create = `${GLOBALPING_API}/measurements`;
    assert.equal(log.note(create, 'host-target'), true);
    log.record(create);
    log.note(create, 'ip-target');
    log.note(create, 'host-target');
    for (const bad of ['203.0.113.7', 'Example', 'www.example.com', '', null, 'x'.repeat(40)]) assert.equal(log.note(create, bad), false, String(bad));
    const rdap = 'https://rdap.org/domain/example.com';
    log.note(rdap, 'rdap');
    log.record(rdap);
    log.record('https://rdap.example.net/v1/domain/example.com', { via: 'redirect', from: rdap });
    log.record('https://other.example.net/next', { via: 'redirect', from: 'https://unseen.example.org/x' });
    const byHost = Object.fromEntries(log.snapshot().entries.map((e) => [e.host, e]));
    assert.deepEqual(byHost['api.globalping.io'].notes, ['host-target', 'ip-target']);
    assert.deepEqual(byHost['rdap.example.net'].notes, ['rdap'], 'the registry server rdap.org redirected to');
    assert.deepEqual(byHost['other.example.net'].notes, []);
    const many = createEgressLog();
    for (let i = 0; i < MAX_NOTES + 3; i += 1) many.note('https://example.net/', `n${i}`);
    assert.equal(many.snapshot().entries[0].notes.length, MAX_NOTES);
    assert.equal(ledgerRows(many.snapshot()).length, 0, 'a note alone is no request');
  });

  test('noteRequest reaches the listeners with fixed words only, and a failing listener harms nobody', () => {
    const heard = [];
    const offBad = onRequestNote(() => { throw new Error('listener bug'); });
    const off = onRequestNote((url, note) => heard.push([url, note]));
    noteRequest(new URL('https://rdap.org/domain/example.com'), 'rdap');
    noteRequest('https://api.globalping.io/v1/measurements', '203.0.113.7');
    noteRequest('https://api.globalping.io/v1/measurements', { toString: () => 'ip-target' });
    off();
    offBad();
    noteRequest('https://rdap.org/', 'rdap');
    assert.deepEqual(heard, [['https://rdap.org/domain/example.com', 'rdap']]);
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
    // Resolvers asked only for a location, in the JSON form (AliDNS): DNS questions too.
    for (const r of ECS_RESOLVERS) {
      const c = classifyUrl(`${r.url}?name=www.example.com&type=1&edns_client_subnet=192.0.2.0/24`);
      assert.deepEqual([c.service.id, c.label, c.sends], ['doh', r.name, ['dnsQuestions']], r.id);
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
      [`${RIPESTAT_BASE}/prefix-overview/data.json?resource=192.0.2.1&sourceapp=${RIPESTAT_SOURCEAPP}`, 'ripestat', 'prefix-overview', ['ipAddresses']],
      [`${RIPESTAT_BASE}/prefix-overview/data.json?resource=192.0.2.0/24&sourceapp=${RIPESTAT_SOURCEAPP}`, 'ripestat', 'prefix-overview', ['ipAddresses']],
      [`${RIPESTAT_BASE}/maxmind-geo-lite/data.json?resource=2001:db8::1&sourceapp=${RIPESTAT_SOURCEAPP}`, 'ripestat', 'geo', ['ipAddresses']],
      [`${RIPESTAT_BASE}/reverse-dns-ip/data.json?resource=198.51.100.7&sourceapp=${RIPESTAT_SOURCEAPP}`, 'ripestat', 'reverse-dns', ['ipAddresses']],
      // a data call the registry does not name (one could take a domain): everything RIPEstat can get, never "IP addresses" alone
      [`${RIPESTAT_BASE}/dns-chain/data.json?resource=example.com&sourceapp=${RIPESTAT_SOURCEAPP}`, 'ripestat', null, ['ipAddresses', 'asNumbers']],
      [announcedPrefixesUrl(64496), 'ripestat', 'prefixes', ['asNumbers']],
      [`${IPWHOIS_BASE}/192.0.2.1`, 'ipwhois', 'address', ['ipAddresses']],
      // registration: the bootstrap is a public list; a registry server lib/rdap.js noted (the
      // bootstrap named it, or rdap.org redirected to it), by its path
      [IANA_BOOTSTRAP.dns, 'rdap-bootstrap', 'bootstrap', ['nothing']],
      [IANA_BOOTSTRAP.ipv6, 'rdap-bootstrap', 'bootstrap', ['nothing']],
      [`${RDAP_ORG}domain/example.com`, 'rdap', 'domain', ['domains']],
      ['https://rdap.example.net/com/v1/domain/EXAMPLE.COM', 'rdap', 'domain', ['domains'], ['rdap']],
      ['https://rdap.example.net/rdap/ip/192.0.2.1', 'rdap', 'ip', ['ipAddresses'], ['rdap']],
      ['https://rdap.example.net/ip/2001:db8::/32', 'rdap', 'ip-network', ['ipAddresses'], ['rdap']],
      ['https://rdap.example.net/help', 'rdap', null, ['domains', 'ipAddresses'], ['rdap']],
      // checks from the internet: what a measurement sent is the note lib/globalping.js gave it
      [`${GLOBALPING_API}/limits`, 'globalping', 'limits', ['nothing']],
      [`${GLOBALPING_API}/measurements`, 'globalping', 'create', ['ipNamePairs'], ['ip-target']],
      [`${GLOBALPING_API}/measurements`, 'globalping', 'create', ['hostnames'], ['host-target']],
      [`${GLOBALPING_API}/measurements`, 'globalping', 'create', ['dnsQuestions', 'nameServers'], ['dns-query']],
      [`${GLOBALPING_API}/measurements`, 'globalping', 'create', ['hostnames', 'ipNamePairs'], ['host-target', 'ip-target']],
      [`${GLOBALPING_API}/measurements`, 'globalping', 'create', ['dnsQuestions', 'nameServers', 'hostnames', 'ipNamePairs'], ['rdap']],
      [`${GLOBALPING_API}/measurements`, 'globalping', 'create', ['dnsQuestions', 'nameServers', 'hostnames', 'ipNamePairs']],
      [`${GLOBALPING_API}/measurements/AbCdEf123`, 'globalping', 'result', ['measurementIds']],
      // Zone File › Fetch: the zone name and the user's token, to the provider's API only
      ...ZONE_PROVIDERS.map((p) => [`${p.api}/domains/example.com/${p.id === 'desec' ? 'rrsets/' : 'records'}`, p.id,
        p.id === 'desec' ? 'rrsets' : 'records', ['domains', 'apiToken']]),
      ['https://desec.io/api/v1/domains/example.com/rrsets/?type=A&cursor=', 'desec', 'rrsets', ['domains', 'apiToken']],
      ['https://api.digitalocean.com/v2/domains/example.com/records?per_page=200&page=2', 'digitalocean', 'records', ['domains', 'apiToken']],
      // the token page, a link on the API host: no endpoint
      [getZoneProvider('desec').tokenUrl, 'desec', null, ['domains', 'apiToken']]
    ];
    for (const [url, service, endpoint, sends, notes = []] of cases) {
      const c = classifyUrl(url, { notes });
      const what = `${url} ${notes.join(',')}`;
      assert.equal(c.service && c.service.id, service, what);
      assert.equal(c.endpoint && c.endpoint.id, endpoint, what);
      assert.deepEqual(c.sends, DATA_KINDS.filter((k) => sends.includes(k)), what);
    }
    assert.equal(CRTSH_BASE, 'https://crt.sh/');
    assert.equal(classifyUrl(CERTSPOTTER_ISSUANCES).service.id, 'certspotter');
  });

  test('a host whose path merely looks like an RDAP query is not a registry server', () => {
    for (const url of ['https://rdap.example.net/domain/example.com', 'https://tracker.example.net/rdap/ip/192.0.2.1']) {
      assert.equal(classifyUrl(url).service, null, url);
      assert.equal(classifyUrl(url, { notes: ['host-target'] }).service, null, `${url}: another note`);
    }
    assert.equal(classifyUrl('http://rdap.example.net/domain/example.com', { notes: ['rdap'] }).service, null, 'never over plain http');
    assert.equal(classifyUrl('https://crt.sh/?q=example.com', { notes: ['rdap'] }).service.id, 'crtsh', 'a registered host is its own service');
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
  /** A snapshot of `[url, via, times, notes]` records (the notes given before the requests, as the code does). */
  const snapshotOf = (records) => {
    let t = 0;
    const log = createEgressLog({ now: () => (t += 1) });
    for (const [url, via = 'fetch', times = 1, notes = []] of records) {
      for (const n of notes) log.note(url, n);
      for (let i = 0; i < times; i += 1) log.record(url, { via });
    }
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
      [`${GLOBALPING_API}/measurements`, 'fetch', 2, ['ip-target', 'host-target']],
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

  test('a session whose only measurement checked a host name says Globalping got host names, never an address', () => {
    // Domain Health's MTA-STS check alone: the quota read, one measurement with a host-name target, its polls.
    const rows = ledgerRows(snapshotOf([
      [`${GLOBALPING_API}/limits`, 'fetch', 1],
      [`${GLOBALPING_API}/measurements`, 'fetch', 1, ['host-target']],
      [`${GLOBALPING_API}/measurements/Abc1`, 'fetch', 4]
    ]), { origin: PAGE });
    assert.deepEqual(rows.map((r) => [r.serviceId, r.sends]), [['globalping', ['nothing', 'hostnames', 'measurementIds']]]);
    assert.deepEqual(rows[0].endpoints.find((e) => e.id === 'create').sends, ['hostnames']);
    // Verify's origin check afterwards adds the address, host name and port.
    const both = ledgerRows(snapshotOf([
      [`${GLOBALPING_API}/measurements`, 'fetch', 1, ['host-target']],
      [`${GLOBALPING_API}/measurements`, 'fetch', 2, ['ip-target']]
    ]), { origin: PAGE });
    assert.deepEqual(both[0].sends, ['hostnames', 'ipNamePairs']);
  });

  test('a host is a registry\'s RDAP server only when lib/rdap.js noted every request of it', () => {
    const rows = ledgerRows(snapshotOf([
      ['https://tracker.example.net/domain/example.com'],
      ['https://tracker.example.net/collect?x=1']
    ]), { origin: PAGE });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].kind, 'unknown');
    assert.equal(rows[0].requests, 2);
    const unnoted = ledgerRows(snapshotOf([['https://rdap.example.net/domain/example.com', 'fetch', 2]]), { origin: PAGE });
    assert.deepEqual([unnoted[0].kind, unnoted[0].serviceId], ['unknown', null], 'a path that looks like RDAP is not enough');
    const noted = ledgerRows(snapshotOf([
      ['https://rdap.example.net/domain/example.com', 'fetch', 2, ['rdap']],
      ['https://rdap.example.net/ip/192.0.2.1', 'fetch', 1, ['rdap']]
    ]), { origin: PAGE });
    assert.deepEqual([noted[0].kind, noted[0].serviceId, noted[0].name, noted[0].sends], ['service', 'rdap', 'RDAP', ['domains', 'ipAddresses']]);
    const mixed = ledgerRows(snapshotOf([
      ['https://rdap.example.net/domain/example.com', 'fetch', 1, ['rdap']],
      ['https://rdap.example.net/collect?x=1']
    ]), { origin: PAGE });
    assert.equal(mixed[0].kind, 'unknown', 'a request the code did not note makes the host one to look at');
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
  noteRequest('https://rdap.org/domain/moved.example', 'rdap'); // as lib/rdap.js does before its fetch
  await win.fetch('https://rdap.org/domain/moved.example');
  await win.fetch('assets/data/wordlist-base.txt');
  observer.cb({ getEntries: () => [{ name: 'https://crt.sh/?q=example.com' }, { name: `${PAGE}/domainscope/assets/js/app.js` }] });

  const rows = ledgerRows(egressLog.snapshot(), { origin: PAGE });
  const byHost = Object.fromEntries(rows.map((r) => [r.host, r]));
  assert.equal(byHost['crt.sh'].requests, 1, 'fetch + Resource Timing of one request');
  assert.equal(byHost['down.example.net'].failed, 1);
  assert.equal(byHost['rdap.example.net'].redirect, 1, 'the redirect target counts as contacted');
  assert.deepEqual([byHost['rdap.example.net'].serviceId, byHost['rdap.example.net'].sends], ['rdap', ['domains']],
    'the registry server rdap.org redirected to, with the note of the request');
  assert.equal(byHost['example.org'].requests, 2, 'a relative fetch and a module, both the page\'s own');
  assert.deepEqual(egressMeterStatus(), { fetch: true, resourceTiming: true });
  assert.deepEqual(startEgressMeter(win), { fetch: true, resourceTiming: true }, 'installed once');
});

test('the senders note what the URL cannot say: a measurement\'s target kind, a registry\'s RDAP server', async () => {
  const log = createEgressLog();
  const off = onRequestNote((url, note) => log.note(url, note));
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const fetchImpl = async (input) => {
    const url = String(input);
    log.record(url);
    if (url === `${GLOBALPING_API}/measurements`) return json({ id: 'AbCdEf123456', probesCount: 1 }, 202);
    if (url === IANA_BOOTSTRAP.dns) return json({ services: [[['com'], ['https://rdap.example.net/com/v1/']]] });
    if (url.startsWith('https://rdap.example.net/')) return json({ objectClassName: 'domain', ldhName: 'EXAMPLE.COM', status: ['active'] });
    throw new TypeError(`unexpected ${url}`);
  };
  try {
    const gp = createGlobalping({ fetchImpl });
    // Domain Health's MTA-STS check: a host name only.
    await gp.create(httpsGetRequest({ host: 'mta-sts.example.com', path: '/.well-known/mta-sts.txt' }));
    const gpRow = () => ledgerRows(log.snapshot()).find((r) => r.serviceId === 'globalping');
    assert.deepEqual(gpRow().sends, ['hostnames']);
    // Verify's origin check: an address with the host name and port (a body as httpsCheckRequest builds it).
    await gp.create({ type: 'http', target: '203.0.113.7', limit: 1, timeout: 10, measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'HEAD', host: 'www.example.com', path: '/' } } });
    assert.deepEqual(gpRow().sends, ['hostnames', 'ipNamePairs']);
    // Retire an IP's old-versus-new server comparison: an address with the host name, path and port
    // (a body as httpsGetAtRequest builds it; it refuses documentation addresses).
    await gp.create({ type: 'http', target: '203.0.113.8', limit: 1, timeout: 10, measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'GET', host: 'www.example.com', path: '/health' } } });
    assert.deepEqual(gpRow().sends, ['hostnames', 'ipNamePairs']);
    // Zone File › New name servers: a DNS question asked at the name server named.
    await gp.create(dnsQueryRequest({ name: 'www.example.com', type: 'A', resolver: 'ns1.example.net' }));
    assert.deepEqual(gpRow().sends, ['dnsQuestions', 'nameServers', 'hostnames', 'ipNamePairs']);
    // RDAP: the server the bootstrap named is the registry's, by lib/rdap.js's note.
    const r = await rdapDomain('www.example.com', { fetchImpl, fallback: false });
    assert.equal(r.ok, true);
    const rdapRow = ledgerRows(log.snapshot()).find((row) => row.host === 'rdap.example.net');
    assert.deepEqual([rdapRow.kind, rdapRow.serviceId, rdapRow.sends], ['service', 'rdap', ['domains']]);
    assert.deepEqual(log.snapshot().entries.flatMap((e) => e.notes).sort(), ['dns-query', 'host-target', 'ip-target', 'rdap']);
  } finally {
    off();
  }
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
  'assets/js/lib/ctwatch.js': ['certspotter', 'crtsh'],
  'assets/js/lib/sources.js': ['crtsh', 'certspotter', 'hackertarget', 'anubis', 'otx', 'thc'],
  'assets/js/lib/ipintel.js': ['ripestat', 'ipwhois', 'hackertarget', 'thc'],
  'assets/js/lib/ptrsweep.js': ['ripestat'],
  'assets/js/lib/rdap.js': ['rdap-bootstrap', 'rdap'],
  'assets/js/lib/globalping.js': ['globalping'],
  'assets/js/lib/passport.js': ['certspotter', 'crtsh', 'rdap'],
  // the Domain portfolio: hands its fetch to lib/rdap.js (and its DNS client to lib/passport.js)
  'assets/js/lib/portfolio.js': [],
  'assets/js/lib/keycontinuity.js': ['crtsh'],
  // Zone File › Fetch from deSEC / DigitalOcean, with the user's token
  'assets/js/lib/zonefetch.js': ['desec', 'digitalocean'],
  // the CCADB intermediate list, from this site (assets/data/intermediates/)
  'assets/js/lib/chainfix.js': ['self'],
  'assets/js/lib/wordlist.js': ['self'],
  'assets/js/lib/scanner.js': [],
  'assets/js/lib/health.js': [],
  'assets/js/views/bulk.js': [],
  'assets/js/views/cert.js': ['self', 'crtsh'],
  'assets/js/ui/egress-meter.js': [],
  'assets/js/ui/egress-panel.js': ['self']
};
/**
 * Links the user opens (never fetched), by file and host. Every other http(s) literal of every
 * file — a call site or a module that only holds a URL a call site imports — must be an endpoint
 * the registry classifies: a link host is declared for the one file that shows it.
 */
const LINK_HOSTS = {
  'assets/js/app.js': ['github.com'],
  'assets/js/lib/passport.js': ['www.trabis.gov.tr', 'webwhois.denic.de', 'whois.jprs.jp', 'www.nic.ch', 'www.iana.org'],
  // the platforms' home pages and the lists their built-in ranges were copied from (by hand, never by the page)
  'assets/js/lib/netinfo.js': [
    'www.cloudflare.com', 'www.fastly.com', 'api.fastly.com', 'aws.amazon.com', 'ip-ranges.amazonaws.com', 'www.akamai.com',
    'azure.microsoft.com', 'www.imperva.com', 'my.imperva.com', 'sucuri.net', 'docs.sucuri.net', 'www.stackpath.com', 'bunny.net',
    'www.keycdn.com', 'www.cdn77.com', 'edg.io', 'www.medianova.com', 'gcore.com', 'www.cachefly.com', 'pages.github.com',
    'api.github.com', 'docs.gitlab.com', 'www.heroku.com', 'vercel.com', 'www.netlify.com', 'docs.netlify.com', 'support.google.com',
    'firebase.google.com', 'www.shopify.com', 'wpengine.com', 'pantheon.io', 'render.com', 'fly.io', 'railway.com',
    'www.digitalocean.com', 'www.wix.com', 'www.squarespace.com', 'webflow.com'
  ],
  // the resolvers' home pages (their DoH endpoints are the registry's)
  'assets/js/lib/resolvers.js': [
    'one.one.one.one', 'developers.google.com', 'quad9.net', 'www.nic.cz', 'dns.sb', 'controld.com', 'cleanbrowsing.org', 'dns.seby.io',
    'tiarap.org', 'www.alidns.com'
  ],
  'assets/js/lib/sourceinfo.js': ['hackertarget.com', 'sslmate.com'],
  // where a DNS provider's read-only token is made, and how (deSEC's token page is on its API host,
  // desec.io/tokens: a desec URL the registry gives no endpoint)
  'assets/js/lib/zonefetch.js': ['desec.readthedocs.io', 'cloud.digitalocean.com', 'docs.digitalocean.com'],
  // the SVG namespace, a name and never a request
  'assets/js/ui/dom.js': ['www.w3.org'],
  'assets/js/ui/verify-panel.js': ['globalping.io'],
  'assets/js/ui/chain-repair.js': ['www.ccadb.org'],
  // an example CAA accounturi in the field's placeholder, never requested
  'assets/js/views/change.js': ['acme-v02.api.letsencrypt.org'],
  'assets/js/views/about.js': ['about.rdap.org', 'datatracker.ietf.org', 'globalping.io', 'hackertarget.com', 'sslmate.com'],
  'assets/js/views/ip.js': ['bgp.he.net']
};
/**
 * Files with a URL whose host is data (a template's `${…}` there), and why the page never
 * requests it. A call site may have none: the registry could not name the host it sends to.
 */
const BUILT_HOSTS = {
  'assets/js/lib/domain.js': 'a typed host name read through the URL parser',
  'assets/js/lib/x509.js': 'a certificate name read through the URL parser',
  'assets/js/lib/mtasts.js': 'the policy URL a Globalping probe fetches, shown',
  'assets/js/lib/renewal.js': 'the base a probe\'s redirect Location is read against',
  'assets/js/views/health.js': 'the policy URL a Globalping probe fetches, shown'
};
/** What the lexer puts in a template literal's text where an expression `${…}` stood. */
const HOLE = '${}';
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
 * (a template's `${…}` becomes {@link HOLE}). Enough of a lexer for this codebase: strings,
 * templates with nested expressions, regular expression literals, line and block comments.
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
            text += HOLE;
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

/**
 * The http(s) literals of the lexed files the registry does not account for. Every file counts,
 * not only the call sites: a URL constant can live in a module without a fetch call
 * (lib/sourceinfo.js) and be fetched by a call site that imports it. A literal must be a link its
 * own file declares (LINK_HOSTS), a reserved `.invalid` name (a URL-parsing trick, never
 * contacted), a URL whose host is data in a file that says why it is never requested
 * (BUILT_HOSTS; never in a call site), or classify through the registry — in a call site, as one
 * of the services it declares.
 * @param {Map<string, { literals: string[] }>} lexed file → lex() of it
 * @returns {{ bad: string[], seen: Set<string> }} seen: the services the literals name
 */
function urlLiteralProblems(lexed) {
  const bad = [];
  const seen = new Set();
  for (const [file, { literals }] of lexed) {
    const ids = Object.hasOwn(CALL_SITES, file) ? CALL_SITES[file] : null;
    const links = LINK_HOSTS[file] || [];
    for (const lit of literals) {
      if (!/^https?:\/\//i.test(lit)) continue;
      const authority = lit.replace(/^https?:\/\//i, '').split(/[/?#]/)[0];
      if (/\.invalid(?::\d+)?$/i.test(authority)) continue; // a URL-parsing trick, never contacted
      if (authority.includes(HOLE)) {
        if (ids) bad.push(`${file}: ${lit} sends to a host built from data, which the registry cannot name`);
        else if (!Object.hasOwn(BUILT_HOSTS, file)) bad.push(`${file}: ${lit} has a host built from data: say why in BUILT_HOSTS`);
        continue;
      }
      let host;
      try {
        host = new URL(lit).host;
      } catch {
        bad.push(`${file}: unparseable ${lit}`);
        continue;
      }
      if (links.includes(host)) continue;
      const c = classifyUrl(lit);
      if (!c || !c.service) bad.push(`${file}: ${lit} is not in lib/egress.js`);
      else if (ids && !ids.includes(c.service.id)) bad.push(`${file}: ${lit} is ${c.service.id}, not declared for this file`);
      else seen.add(c.service.id);
    }
  }
  return { bad, seen };
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
    assert.deepEqual(literals, ['https://one.example/x', '1', `in${HOLE}`, `https://four.example/${HOLE}/y?z=${HOLE}`]);
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

  test('every URL literal of every file is an endpoint the registry classifies (in a call site: one of its services), or a link', () => {
    const { bad, seen } = urlLiteralProblems(lexed);
    assert.deepEqual(bad, []);
    // every registry service has an endpoint in the code (DNS-over-HTTPS: lib/resolvers.js, above)
    assert.deepEqual(EGRESS_SERVICES.map((s) => s.id).filter((id) => id !== 'doh' && !seen.has(id)), [], 'a service no code calls');
  });

  test('the scan catches a new endpoint whose URL lives in a module without a fetch call', () => {
    /** The sources with `src` appended to some files. */
    const plant = (added) => {
      const out = new Map(lexed);
      for (const [file, src] of Object.entries(added)) {
        const l = lex(src);
        out.set(file, { code: `${lexed.get(file).code}\n${l.code}`, literals: [...lexed.get(file).literals, ...l.literals] });
      }
      return out;
    };
    // A constant planted in a module a call site imports (lib/sourceinfo.js holds such URLs), and
    // the call site fetching it: the ledger would not know the host, so the scan must fail.
    assert.ok(!CALL_RE.test(lexed.get('assets/js/lib/sourceinfo.js').code), 'lib/sourceinfo.js has no call site of its own');
    assert.deepEqual(urlLiteralProblems(plant({
      'assets/js/lib/sourceinfo.js': "export const NEW_API = 'https://api.newservice.example/v1/lookup/';",
      'assets/js/lib/sources.js': 'export const look = (domain, fetchImpl) => fetchImpl(`${NEW_API}${encodeURIComponent(domain)}`);'
    })).bad, ['assets/js/lib/sourceinfo.js: https://api.newservice.example/v1/lookup/ is not in lib/egress.js']);
    // A link host is one file's: the same host in another file is not a link there.
    assert.deepEqual(urlLiteralProblems(plant({ 'assets/js/lib/sourceinfo.js': "const x = 'https://webwhois.denic.de/x';" })).bad,
      ['assets/js/lib/sourceinfo.js: https://webwhois.denic.de/x is not in lib/egress.js']);
    // A registry service a call site does not declare is refused there.
    assert.deepEqual(urlLiteralProblems(plant({ 'assets/js/lib/ptrsweep.js': "const x = 'https://ipwho.is/';" })).bad,
      ['assets/js/lib/ptrsweep.js: https://ipwho.is/ is ipwhois, not declared for this file']);
    // A host built from data: never in a call site, elsewhere only where BUILT_HOSTS says why.
    assert.deepEqual(urlLiteralProblems(plant({
      'assets/js/lib/sources.js': 'const u = (host) => `https://${host}/api`;',
      'assets/js/lib/sourceinfo.js': 'const v = (host) => `https://api.${host}/`;'
    })).bad.sort(), [
      'assets/js/lib/sourceinfo.js: https://api.${}/ has a host built from data: say why in BUILT_HOSTS',
      'assets/js/lib/sources.js: https://${}/api sends to a host built from data, which the registry cannot name'
    ]);
  });

  test('every RIPEstat data call the code builds is one the registry names, and ipwho.is has its one request', () => {
    // RIPEstat's calls differ in what `resource` carries (an address, an AS number, a domain …): each
    // is its own endpoint. A call is a literal path segment after RIPESTAT_BASE, or the literal first
    // argument of lib/ipintel.js ripeUrl(), the one template that takes the call from a variable.
    const calls = new Map();
    const fromVariable = [];
    for (const [file, { code, literals }] of lexed) {
      if (!/\bRIPESTAT_BASE\b/.test(code)) continue;
      for (const lit of literals) {
        const m = /^\$\{\}\/([^/?#]*)\/data\.json/.exec(lit);
        if (!m) continue;
        if (m[1].includes(HOLE)) fromVariable.push(file);
        else calls.set(m[1], file);
      }
      for (const m of code.matchAll(/\bripeUrl\(\s*(?:'([^']*)'|(\S))/g)) {
        assert.ok(m[1] !== undefined, `${file}: a ripeUrl() call whose data call is not a string literal`);
        calls.set(m[1], file);
      }
    }
    assert.deepEqual(fromVariable, ['assets/js/lib/ipintel.js'], 'one template takes the call from a variable (ripeUrl)');
    const ripestat = getEgressService('ripestat');
    for (const call of calls.keys()) {
      const c = classifyUrl(`${RIPESTAT_BASE}/${call}/data.json?resource=192.0.2.1&sourceapp=${RIPESTAT_SOURCEAPP}`);
      assert.ok(c.endpoint, `RIPEstat's ${call} (${calls.get(call)}) has no endpoint in lib/egress.js`);
    }
    assert.deepEqual(ripestat.endpoints.map((e) => e.path.split('/')[2]).filter((call) => !calls.has(call)), [], 'a registry endpoint no code calls');
    assert.ok(!ripestat.endpoints.some((e) => e.path.includes('**')), 'no catch-all: a new call must be named');
    // ipwho.is has one API, /<address>: its one caller builds it once.
    assert.deepEqual([...lexed].filter(([, l]) => /\bIPWHOIS_BASE\b/.test(l.code)).map(([f]) => f), ['assets/js/lib/ipintel.js']);
    assert.equal((lexed.get('assets/js/lib/ipintel.js').code.match(/`IPWHOIS_BASE`/g) || []).length, 1, 'one ipwho.is request built');
  });

  test('the declared links and data-built hosts are still there, and no link host is a service the page calls', () => {
    for (const [file, hosts] of Object.entries(LINK_HOSTS)) {
      assert.ok(lexed.has(file), `${file} is gone`);
      const present = new Set(lexed.get(file).literals.filter((l) => /^https?:\/\/[^/?#$]+(?:[/?#]|$)/.test(l)).map((l) => new URL(l).host));
      for (const host of hosts) {
        assert.ok(present.has(host), `${file}: ${host} is no longer linked`);
        assert.equal(classifyUrl(`https://${host}/`).service, null, host);
      }
    }
    for (const file of Object.keys(BUILT_HOSTS)) {
      assert.ok(lexed.has(file) && lexed.get(file).literals.some((l) => /^https?:\/\/[^/?#]*\$\{\}/.test(l)), `${file} no longer builds a host`);
      assert.ok(!Object.hasOwn(CALL_SITES, file), `${file} is a call site`);
    }
  });
});
