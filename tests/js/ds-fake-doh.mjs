/**
 * A fake DNS-over-HTTPS service for the headless runner's offline tests (tests/js/ds-runner.test.js).
 *
 * The zone is the Zone File e2e suite's fake live zone (tests/e2e/zone.e2e.mjs fakeTable): the
 * records of the Cloudflare export fixture, every proxied name answering the Cloudflare edge
 * except www, which answers its origin (the proxy switched off live → origin-exposed), and a newer
 * SOA serial. {@link createFakeFetch} answers RFC 8484 GET `?dns=` requests from such a table in
 * Node, as the suite's in-page stub does in the browser; every other request gets `other()`
 * (by default a 404: RDAP, the passive sources and CT fail cleanly, nothing leaves the machine).
 *
 * Loaded with `node --import <this file>` and DS_FAKE_DOH=1 in the environment it replaces
 * globalThis.fetch of a spawned runner, and DS_FAKE_DOH_LOG=<file> receives the questions asked
 * (JSON) when the process exits; DS_FAKE_DOH=portfolio gives it the Domain portfolio's three zones
 * and their RDAP registry ({@link portfolioZone}, {@link createPortfolioFetch}: the `audit`
 * command); DS_FAKE_DOH=takeover two domains whose records name other people's domains, with their
 * registry ({@link takeoverZone}, {@link createTakeoverFetch}: the `takeover` command);
 * DS_FAKE_DOH=hang a network that never answers ({@link createHangingFetch}, the
 * Ctrl-C test). Documentation data only (example.com / .net / .org, example-test.com.tr,
 * 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, the fake Cloudflare edge 104.16.1.1).
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeMessage, decodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { parseZone } from '../../assets/js/lib/zoneparse.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const CF_EXPORT = join(ROOT, 'tests', 'fixtures', 'zones', 'cloudflare-export.txt');
export const CF_EDGE_V4 = '104.16.1.1';
export const CF_EDGE_V6 = '2606:4700::6810:101';

/**
 * The fake live zone of the Cloudflare export: `{ name: { TYPE: [dnswire data…] } }`.
 * @returns {Record<string, Record<string, any[]>>}
 */
export function zoneTable() {
  const z = parseZone(readFileSync(CF_EXPORT, 'utf8'), { filename: 'example.com.txt' });
  const table = {};
  const proxied = new Set();
  for (const r of z.records) {
    if (r.data === null || r.data === undefined || r.duplicateOf !== undefined) continue;
    if (r.name.endsWith('.dev.example.com')) continue; // below the delegation: served by the child zone
    const node = table[r.name] || (table[r.name] = {});
    (node[r.type] || (node[r.type] = [])).push(r.data);
    if (r.proxied === true) proxied.add(r.name);
  }
  for (const name of proxied) {
    const node = table[name];
    delete node.CNAME;
    node.A = [CF_EDGE_V4];
    if (name === 'www.example.com' || node.AAAA) node.AAAA = [CF_EDGE_V6];
  }
  table['www.example.com'].A = ['192.0.2.10'];
  const soa = table['example.com'].SOA[0];
  table['example.com'].SOA = [{ ...soa, serial: Number(soa.serial) + 1 }];
  return table;
}

/**
 * One answer from a table with the in-page stub's rules: CNAME chains inside the apex, a
 * `*.parent` node for names without a node of their own (RFC 4592), NXDOMAIN outside the table.
 * @param {object} table
 * @param {string} apex
 * @param {string} qname
 * @param {string} type
 * @returns {{ rcode: string, answers: object[] }}
 */
export function answerFrom(table, apex, qname, type) {
  const hasBelow = (name) => Object.keys(table).some((k) => k.endsWith(`.${name}`));
  const nodeOf = (name) => {
    if (table[name]) return table[name];
    const parent = name.split('.').slice(1).join('.');
    if (table[`*.${parent}`] && !hasBelow(name)) return table[`*.${parent}`];
    return null;
  };
  const answers = [];
  let name = qname;
  for (let hop = 0; hop < 8; hop += 1) {
    const node = nodeOf(name);
    if (!node) return { rcode: hop || hasBelow(name) ? 'NOERROR' : 'NXDOMAIN', answers };
    if (node[type]) {
      for (const data of node[type]) answers.push({ name, type, ttl: 300, data });
      return { rcode: 'NOERROR', answers };
    }
    if (node.CNAME && type !== 'CNAME') {
      const target = String(node.CNAME[0]).replace(/[.]$/, '');
      answers.push({ name, type: 'CNAME', ttl: 300, data: target });
      if (target !== apex && !target.endsWith(`.${apex}`)) return { rcode: 'NOERROR', answers };
      name = target;
      continue;
    }
    return { rcode: 'NOERROR', answers };
  }
  return { rcode: 'NOERROR', answers };
}

/**
 * A fetch that answers DoH wire queries from `table` (names outside `apex` are NXDOMAIN) and
 * every other request with `other(url, init)` (a 404 by default). `log` receives each question.
 * @param {object} table
 * @param {{ apex?: string, log?: Array<{ name: string, type: string, url: string }>, other?: Function,
 *   rcodes?: Record<string, string> }} [opts] `rcodes`: 'name|TYPE' → a forced rcode (SERVFAIL …)
 * @returns {typeof fetch}
 */
export function createFakeFetch(table, { apex = 'example.com', log = [], other, rcodes = {} } = {}) {
  const soa = table[apex] && table[apex].SOA ? table[apex].SOA[0] : null;
  return async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (typeof other === 'function') return other(url, init);
      return new Response('not found', { status: 404 });
    }
    const q = decodeMessage(base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    log.push({ name, type: q.type, url: url.slice(0, url.indexOf('?')) });
    const forced = rcodes[`${name}|${q.type}`];
    const out = forced ? { rcode: forced, answers: [] }
      : (name === apex || name.endsWith(`.${apex}`)) ? answerFrom(table, apex, name, q.type) : { rcode: 'NXDOMAIN', answers: [] };
    return new Response(encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers,
      authorities: out.answers.length || !soa ? [] : [{ name: apex, type: 'SOA', ttl: 300, data: soa }], edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
}

/* ------------------------------------------------------------------------ */
/* The Domain portfolio (the runner's `audit`)                              */
/* ------------------------------------------------------------------------ */

const DAY_MS = 86400000;
/** The registry server the fake IANA bootstrap names for .com, .net and .org (none for .tr). */
export const PORTFOLIO_RDAP_BASE = 'https://rdap.example.net/';

/**
 * Three zones on one provider's name servers (ns*.example.net), as the portfolio e2e suite has
 * them: example.com signed, locked and sending mail with SPF, DMARC p=reject, a DKIM key,
 * MTA-STS and TLS-RPT; example.org a parked domain (null MX, -all, p=reject) without a transfer
 * lock that expires in 20 days; example-test.com.tr on a registry without RDAP, with ~all and no
 * DMARC. The name servers' domain example.net expires in 12 days. Dates count from `now`.
 * @param {{ now?: number }} [opts]
 * @returns {{ table: Record<string, Record<string, any[]>>, rdap: Record<string, object>, signed: string[] }}
 */
export function portfolioZone({ now = Date.now() } = {}) {
  // half a day past the count, so a test a few minutes later still counts the same whole days
  const iso = (days) => new Date(now + days * DAY_MS + DAY_MS / 2).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const dnskey = { flags: 257, protocol: 3, algorithm: 13, publicKey: Buffer.alloc(64, 7).toString('base64') };
  const keyTag = decodeMessage(encodeMessage({ answers: [{ name: 'example.com', type: 'DNSKEY', ttl: 300, data: dnskey }] })).answers[0].data.keyTag;
  const table = {
    'example.com': {
      NS: ['ns1.example.net', 'ns2.example.net'],
      DS: [{ keyTag, algorithm: 13, digestType: 2, digest: 'ab'.repeat(32) }],
      DNSKEY: [dnskey],
      CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }],
      MX: [{ preference: 10, exchange: 'mx.example.com' }],
      TXT: [['v=spf1 include:_spf.example.net -all'], ['site-verification=ds']]
    },
    '_spf.example.net': { TXT: [['v=spf1 ip4:192.0.2.0/24 -all']] },
    'mx.example.com': { A: ['192.0.2.25'] },
    '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']] },
    'google._domainkey.example.com': { TXT: [['v=DKIM1; k=rsa; p=MIIBIjANBgkqh']] },
    '_mta-sts.example.com': { TXT: [['v=STSv1; id=20261001']] },
    '_smtp._tls.example.com': { TXT: [['v=TLSRPTv1; rua=mailto:tls@example.com']] },
    'example.org': { NS: ['ns1.example.net', 'ns.example.org'], MX: [{ preference: 0, exchange: '.' }], TXT: [['v=spf1 -all']] },
    '_dmarc.example.org': { TXT: [['v=DMARC1; p=reject']] },
    'example-test.com.tr': { NS: ['ns1.example.net'], MX: [{ preference: 10, exchange: 'mx.example-test.com.tr' }], TXT: [['v=spf1 ~all']] },
    'mx.example-test.com.tr': { A: ['203.0.113.25'] }
  };
  const rdapJson = (domain, status, days) => ({
    objectClassName: 'domain', ldhName: domain.toUpperCase(), status,
    events: [{ eventAction: 'registration', eventDate: '2001-05-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: iso(days) }],
    entities: [{ objectClassName: 'entity', roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar, Inc.']]], publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }] }],
    secureDNS: { delegationSigned: domain === 'example.com' }
  });
  const rdap = {
    'example.com': rdapJson('example.com', ['client transfer prohibited', 'client delete prohibited'], 400),
    'example.org': rdapJson('example.org', ['active'], 20),
    'example.net': rdapJson('example.net', ['client transfer prohibited'], 12)
  };
  return { table, rdap, signed: ['example.com'] };
}

/**
 * A fetch with the portfolio's services: DoH answers from `table` (each name as it is, no CNAME
 * or wildcard; NXDOMAIN for a name with nothing at or below it; AD on the `signed` zones), the
 * IANA RDAP bootstrap and the registry at {@link PORTFOLIO_RDAP_BASE} (rdap.org answers the same,
 * so a test sees if it was asked), every other request a 404.
 * @param {{ table: object, rdap: object, signed?: string[] }} zone {@link portfolioZone}
 * @param {{ log?: Array<{ name: string, type: string }>, rdapLog?: Array<{ host: string, domain: string }>,
 *   rcodes?: Record<string, string>, rdapStatus?: Record<string, number> }} [opts] `rcodes`: 'name|TYPE' →
 *   a forced rcode; `rdapStatus`: domain → an HTTP status the registry answers instead
 * @returns {typeof fetch}
 */
export function createPortfolioFetch({ table, rdap, signed = [] }, { log = [], rdapLog = [], rcodes = {}, rdapStatus = {} } = {}) {
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/rdap+json' } });
  const below = (name) => Object.keys(table).some((k) => k.endsWith(`.${name}`));
  return async (input) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://data.iana.org/rdap/dns.json')) return json({ services: [[['com', 'net', 'org'], [PORTFOLIO_RDAP_BASE]]] });
    if (url.startsWith(PORTFOLIO_RDAP_BASE) || url.startsWith('https://rdap.org/')) {
      const domain = decodeURIComponent(url.split('/domain/')[1] || '');
      rdapLog.push({ host: new URL(url).host, domain });
      if (rdapStatus[domain]) return json({ errorCode: rdapStatus[domain] }, rdapStatus[domain]);
      return rdap[domain] ? json(rdap[domain]) : json({ errorCode: 404 }, 404);
    }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return new Response('not found', { status: 404 });
    const q = decodeMessage(base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    log.push({ name, type: q.type });
    const forced = rcodes[`${name}|${q.type}`];
    const node = table[name];
    const rcode = forced || (node || below(name) ? 'NOERROR' : 'NXDOMAIN');
    const answers = !forced && node ? (node[q.type] || []).map((data) => ({ name, type: q.type, ttl: 300, data })) : [];
    const ad = signed.some((z) => name === z || name.endsWith(`.${z}`));
    return new Response(encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true, ad }, rcode, questions: [{ name: q.name, type: q.type }], answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
}

/* ------------------------------------------------------------------------ */
/* The takeover watch (the runner's `takeover`)                             */
/* ------------------------------------------------------------------------ */

/**
 * Two domains of ours, example.com and example.net, in a world where example.org and
 * example-test.com.tr are other people's: example.com's DMARC reports go to reports.example.org
 * (not registered: RDAP 404 and NXDOMAIN), its SPF record names a:relay.example-test.com.tr and
 * example.net's CAA iodef caa@example-test.com.tr (expiring in 20 days), example.net's
 * `_acme-challenge` is delegated into example.com (ours: never looked up), and old.example.com is
 * a CNAME to an Azure app that is gone. `registry` (domain → RDAP JSON, or null for a 404) can be
 * changed between runs; dates count from `now`.
 * @param {{ now?: number }} [opts]
 * @returns {{ table: Record<string, Record<string, any>>, registry: Record<string, object|null> }}
 */
export function takeoverZone({ now = Date.now() } = {}) {
  const iso = (days) => new Date(now + days * DAY_MS + DAY_MS / 2).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const table = {
    'example.com': {
      NS: ['ns1.example.net', 'ns2.example.net'], MX: [{ preference: 10, exchange: 'mx.example.com' }],
      TXT: [['v=spf1 include:_spf.example.net a:relay.example-test.com.tr exists:%{i}._spf.example.com -all']]
    },
    'mx.example.com': { A: ['192.0.2.25'] },
    '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; rua=mailto:dmarc@reports.example.org!10m, mailto:dmarc@example.com']] },
    'selector1._domainkey.example.com': { CNAME: 'selector1.dkim.example.net' },
    'selector1.dkim.example.net': { TXT: [['v=DKIM1; k=rsa; p=MIIBIjANBgkqh']] },
    'old.example.com': { CNAME: 'old-app.azurewebsites.net' },
    'www.example.com': { A: ['192.0.2.10'] },
    'relay.example-test.com.tr': { A: ['203.0.113.25'] },
    'example-test.com.tr': { NS: ['ns1.example-test.com.tr'] },
    'example.net': {
      NS: ['ns1.example.net', 'ns2.example.net'], MX: [{ preference: 10, exchange: 'mx.example.com' }], TXT: [['v=spf1 -all']],
      CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'iodef', value: 'mailto:caa@example-test.com.tr' }]
    },
    '_spf.example.net': { TXT: [['v=spf1 ip4:192.0.2.0/24 -all']] },
    'ns1.example.net': { A: ['198.51.100.53'] },
    'ns2.example.net': { A: ['198.51.100.54'] },
    '_acme-challenge.example.net': { CNAME: 'example-net.acme.example.com' },
    'example-net.acme.example.com': { TXT: [['token']] }
  };
  const rdapJson = (domain, status, days) => ({
    objectClassName: 'domain', ldhName: domain.toUpperCase(), status,
    events: [{ eventAction: 'registration', eventDate: '2001-05-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: iso(days) }]
  });
  return {
    table,
    registry: { 'example-test.com.tr': rdapJson('example-test.com.tr', ['client transfer prohibited'], 20), 'example.org': null },
    rdapJson
  };
}

/**
 * A fetch for {@link takeoverZone}: DoH answers from the table with CNAME chains followed across
 * it (as a recursive resolver does; NXDOMAIN for a name with nothing at or below it, the chain
 * kept), the IANA RDAP bootstrap naming {@link PORTFOLIO_RDAP_BASE} for .com, .net, .org and .tr,
 * and that registry answering from `zone.registry` (a 404 for null or a domain it does not hold).
 * @param {{ table: object, registry: object }} zone
 * @param {{ log?: Array<{ name: string, type: string }>, rdapLog?: string[], rdapStatus?: Record<string, number> }} [opts]
 *   `rdapStatus`: domain → an HTTP status the registry answers instead (read on every request, so a test can change it)
 * @returns {typeof fetch}
 */
export function createTakeoverFetch(zone, { log = [], rdapLog = [], rdapStatus = {} } = {}) {
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/rdap+json' } });
  const below = (name) => Object.keys(zone.table).some((k) => k.endsWith(`.${name}`));
  const answer = (qname, type) => {
    const answers = [];
    let name = qname;
    for (let hop = 0; hop < 8; hop += 1) {
      const node = zone.table[name];
      if (!node) return { rcode: below(name) ? 'NOERROR' : 'NXDOMAIN', answers };
      if (node.CNAME && type !== 'CNAME') {
        answers.push({ name, type: 'CNAME', ttl: 300, data: node.CNAME });
        name = node.CNAME;
        continue;
      }
      for (const data of node[type] || []) answers.push({ name, type, ttl: 300, data });
      return { rcode: 'NOERROR', answers };
    }
    return { rcode: 'SERVFAIL', answers };
  };
  return async (input) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://data.iana.org/rdap/dns.json')) return json({ services: [[['com', 'net', 'org', 'tr'], [PORTFOLIO_RDAP_BASE]]] });
    if (url.startsWith(PORTFOLIO_RDAP_BASE) || url.startsWith('https://rdap.org/')) {
      const domain = decodeURIComponent(url.split('/domain/')[1] || '');
      rdapLog.push(domain);
      if (rdapStatus[domain]) return json({ errorCode: rdapStatus[domain] }, rdapStatus[domain]);
      return zone.registry[domain] ? json(zone.registry[domain]) : json({ errorCode: 404 }, 404);
    }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return new Response('not found', { status: 404 });
    const q = decodeMessage(base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    log.push({ name, type: q.type });
    const out = answer(name, q.type);
    return new Response(encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode, questions: [{ name: q.name, type: q.type }], answers: out.answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
}

/**
 * A fetch that never answers: each request waits for its signal (a request without one waits
 * for ever) and `onRequest(url)` hears of it. The Ctrl-C test's network.
 * @param {(url: string) => void} [onRequest]
 * @returns {typeof fetch}
 */
export function createHangingFetch(onRequest = () => {}) {
  return (input, init = {}) => new Promise((resolve, reject) => {
    onRequest(typeof input === 'string' ? input : (input && input.url) || String(input));
    const signal = init.signal;
    if (!signal) return;
    if (signal.aborted) reject(signal.reason);
    else signal.addEventListener('abort', () => reject(signal.reason), { once: true });
  });
}

// `node --import tests/js/ds-fake-doh.mjs` with DS_FAKE_DOH=1: the spawned runner's fetch;
// DS_FAKE_DOH=portfolio: the portfolio's zones and RDAP (the `audit` command);
// DS_FAKE_DOH=hang: nothing ever answers, and each request is named on stderr (`fake: GET <url>`).
if (process.env.DS_FAKE_DOH === '1') {
  const log = [];
  globalThis.fetch = createFakeFetch(zoneTable(), { log });
  if (process.env.DS_FAKE_DOH_LOG) {
    process.on('exit', () => writeFileSync(process.env.DS_FAKE_DOH_LOG, JSON.stringify(log)));
  }
} else if (process.env.DS_FAKE_DOH === 'portfolio') {
  const log = [];
  const rdapLog = [];
  globalThis.fetch = createPortfolioFetch(portfolioZone(), { log, rdapLog });
  if (process.env.DS_FAKE_DOH_LOG) {
    process.on('exit', () => writeFileSync(process.env.DS_FAKE_DOH_LOG, JSON.stringify({ dns: log, rdap: rdapLog })));
  }
} else if (process.env.DS_FAKE_DOH === 'takeover') {
  const log = [];
  const rdapLog = [];
  globalThis.fetch = createTakeoverFetch(takeoverZone(), { log, rdapLog });
  if (process.env.DS_FAKE_DOH_LOG) {
    process.on('exit', () => writeFileSync(process.env.DS_FAKE_DOH_LOG, JSON.stringify({ dns: log, rdap: rdapLog })));
  }
} else if (process.env.DS_FAKE_DOH === 'hang') {
  globalThis.fetch = createHangingFetch((url) => process.stderr.write(`fake: GET ${url.split('?')[0]}\n`));
}
