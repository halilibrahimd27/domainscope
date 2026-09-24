#!/usr/bin/env node
/**
 * LIVE (network) smoke test for assets/js/lib/{health,ipintel,rdap}.js.
 * Not run by `npm test`.
 *
 *   node tests/live/health-smoke.mjs                     # default domains / IPs
 *   node tests/live/health-smoke.mjs example.org nic.tr  # custom domains
 *   node tests/live/health-smoke.mjs --tr                # print check texts in Turkish
 *   node tests/live/health-smoke.mjs --reverse           # also 1 HackerTarget reverse-IP call (quota ~50/day)
 *   node tests/live/health-smoke.mjs --no-cors           # skip the Origin / ACAO endpoint check
 *
 * DNS goes through the real DohClient (lib/doh.js) over node:http2 — Node's
 * fetch is HTTP/1.1 only and Quad9 (in the default failover chain) needs
 * HTTP/2. RDAP, RIPEstat and ipwho.is use Node's fetch. Every request that a
 * browser would send cross-origin is also checked for
 * Access-Control-Allow-Origin with `Origin: https://example.github.io`.
 *
 * Exit code 1 when an expectation fails (see EXPECT below).
 */
import http2 from 'node:http2';
import tls from 'node:tls';
import { DohClient } from '../../assets/js/lib/doh.js';
import { domainHealth, HEALTH_I18N, checkCaaAllows } from '../../assets/js/lib/health.js';
import { createIpIntel } from '../../assets/js/lib/ipintel.js';
import { rdapDomain, rdapIp, IANA_BOOTSTRAP } from '../../assets/js/lib/rdap.js';

const args = process.argv.slice(2);
const LANG = args.includes('--tr') ? 'tr' : 'en';
const REVERSE = args.includes('--reverse');
const CORS = !args.includes('--no-cors');
const domainsArg = args.filter((a) => !a.startsWith('--'));
// denic.de: a ccTLD registry without RDAP in the IANA bootstrap (like .jp and .tr), so the 'unsupported' path is exercised
const DOMAINS = domainsArg.length ? domainsArg : ['github.com', 'denic.de', 'cloudflare.com', 'dnssec-failed.org'];
const ORIGIN = 'https://example.github.io';

/** Per-domain expectations (only for the default set). */
const EXPECT = {
  'github.com': (r) => [
    ['rdap ok', r.rdap?.ok === true],
    ['registrar known', !!r.rdap?.registrar],
    ['expiry date', r.rdap?.expires instanceof Date],
    ['SOA found', !!r.records.soa],
    ['≥2 NS', r.records.ns.length >= 2],
    ['SPF present', !!r.records.spf],
    ['SPF lookups counted', Number.isInteger(r.spf.lookups?.count)],
    ['DMARC present', !!r.records.dmarc],
    ['CAA present', r.records.caa.length > 0],
    ['no errors', r.summary.error === 0]
  ],
  'denic.de': (r) => [
    ['.de → rdap.unsupported', r.checks.some((c) => c.id === 'rdap.unsupported')],
    ['unsupportedTld flag', r.rdap?.unsupportedTld === true],
    ['SOA found', !!r.records.soa],
    ['MX found', r.records.mx.length > 0]
  ],
  'cloudflare.com': (r) => [
    ['DNSSEC ok', r.checks.some((c) => c.id === 'dnssec.ok')],
    ['validated (AD)', r.dnssec.validated === true],
    ['DS matches DNSKEY', !r.checks.some((c) => c.id === 'dnssec.ds-mismatch')],
    ['CAA present', r.records.caa.length > 0],
    ['rdap ok', r.rdap?.ok === true]
  ],
  'dnssec-failed.org': (r) => [
    ['DNSSEC broken detected', r.dnssec.broken === true],
    ['dnssec.broken check', r.checks.some((c) => c.id === 'dnssec.broken' && c.severity === 'error')]
  ]
};

/* ------------------------------------------------------------------------ */
/* HTTP/2 fetch shim for DoH                                                */
/* ------------------------------------------------------------------------ */

function caBundle() {
  try {
    // family.cloudflare-dns.com chains to a root missing from Node's bundle.
    return [...tls.getCACertificates('default'), ...tls.getCACertificates('system')];
  } catch {
    return undefined;
  }
}

function makeH2Fetch() {
  const ca = caBundle();
  const sessions = new Map();
  const session = (origin) => {
    let s = sessions.get(origin);
    if (!s || s.closed || s.destroyed) {
      s = http2.connect(origin, ca ? { ca } : {});
      s.on('error', () => sessions.delete(origin));
      s.on('close', () => sessions.delete(origin));
      sessions.set(origin, s);
    }
    return s;
  };
  const h2fetch = (url, init = {}) => new Promise((resolve, reject) => {
    const u = new URL(String(url));
    const signal = init.signal;
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const headers = { ':method': 'GET', ':path': `${u.pathname}${u.search}`, origin: ORIGIN };
    for (const [k, v] of Object.entries(init.headers || {})) headers[k.toLowerCase()] = v;
    let req;
    try {
      req = session(u.origin).request(headers);
    } catch (err) {
      reject(new TypeError(`fetch failed: ${err.message}`));
      return;
    }
    const chunks = [];
    let head = {};
    const onAbort = () => {
      req.close(http2.constants.NGHTTP2_CANCEL);
      reject(signal.reason);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    req.setTimeout(15000, () => req.close(http2.constants.NGHTTP2_CANCEL));
    req.on('response', (h) => { head = h; });
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      signal?.removeEventListener('abort', onAbort);
      const h = new Headers();
      for (const [k, v] of Object.entries(head)) if (!k.startsWith(':')) h.set(k, Array.isArray(v) ? v.join(', ') : String(v));
      const status = Number(head[':status']) || 0;
      if (!status) {
        reject(new TypeError('fetch failed: stream closed without a response'));
        return;
      }
      resolve(new Response(status === 204 || status === 304 ? null : Buffer.concat(chunks), { status, headers: h }));
    });
    req.on('error', (err) => {
      signal?.removeEventListener('abort', onAbort);
      reject(new TypeError(`fetch failed: ${err.message}`, { cause: err }));
    });
    req.end();
  });
  h2fetch.close = () => { for (const s of sessions.values()) s.close(); };
  return h2fetch;
}

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

const t = (key, params) => (HEALTH_I18N[LANG][key] ?? key).replace(/\{(\w+)\}/g, (m, n) => (n in params ? String(params[n]) : m));
const ICON = { ok: '[ OK ]', info: '[INFO]', warn: '[WARN]', error: '[FAIL]' };
let failures = 0;

function expect(label, cond) {
  console.log(`   ${cond ? 'pass' : 'FAIL'}  ${label}`);
  if (!cond) failures += 1;
}

/** Plain Node fetch that also records whether the response carries ACAO. */
const acaoLog = new Map();
async function loggingFetch(url, init = {}) {
  const res = await fetch(url, { ...init, headers: { ...(init.headers || {}), origin: ORIGIN } });
  const host = new URL(res.url || String(url)).host;
  const acao = res.headers.get('access-control-allow-origin');
  if (!acaoLog.has(host) || acao) acaoLog.set(host, acao);
  return res;
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

const h2fetch = makeH2Fetch();
const dns = new DohClient({ fetchImpl: h2fetch });

console.log(`# Domain health (${LANG}) — DohClient chain: ${dns.chain.join(', ')}`);
for (const domain of DOMAINS) {
  const t0 = Date.now();
  const steps = [];
  const r = await domainHealth(domain, { dns, fetchImpl: loggingFetch, onProgress: (p) => steps.push(p.step) });
  const ms = Date.now() - t0;
  console.log(`\n## ${r.domain}  (${ms} ms, zone ${r.zone ?? '?'})  ok=${r.summary.ok} info=${r.summary.info} warn=${r.summary.warn} error=${r.summary.error}`);
  console.log(`   NS ${r.records.ns.join(' ')} | MX ${r.records.mx.map((m) => `${m.preference} ${m.exchange}`).join(', ') || '-'}`);
  console.log(`   SPF lookups ${r.spf.lookups ? `${r.spf.lookups.count} (void ${r.spf.lookups.voidCount})` : '-'} | DNSSEC ${JSON.stringify(r.dnssec)}`);
  console.log(`   CAA ${r.caa?.foundAt ? `@${r.caa.foundAt}: ${r.records.caa.map((c) => `${c.tag} "${c.value}"`).join('; ')}` : '-'}`);
  if (r.rdap) {
    console.log(`   RDAP ${r.rdap.ok ? `${r.rdap.registrar} (IANA ${r.rdap.registrarIanaId}) expires ${r.rdap.expires?.toISOString().slice(0, 10)} via ${r.rdap.rdapServer}` : r.rdap.error}`);
  }
  for (const c of r.checks) console.log(`   ${ICON[c.severity]} ${c.id}: ${t(c.titleKey, c.params)} — ${t(c.detailKey, c.params)}`);
  const exp = EXPECT[r.domain];
  expect('progress reported all 10 steps', new Set(steps).size === 10);
  if (exp) for (const [label, cond] of exp(r)) expect(label, cond);
  if (r.records.caa.length) {
    const le = checkCaaAllows(r.records.caa, "CN=R11,O=Let's Encrypt,C=US");
    console.log(`   CAA would ${le.allowed ? 'ALLOW' : le.allowed === false ? 'DENY' : '?'} Let's Encrypt (${le.reason})`);
  }
}

console.log('\n# IP intel');
const intel = createIpIntel({ fetchImpl: loggingFetch, dns });
// 193.0.6.139 = www.ripe.net (RIPE NCC's own network): a stable RIPE-region address
const IPS = ['140.82.121.4', '8.8.8.8', '2606:4700::1111', '193.0.6.139', '104.16.132.229', '10.0.0.1'];
const infos = await Promise.all(IPS.map((ip) => intel.info(ip)));
for (const i of infos) {
  console.log(`   ${i.ip.padEnd(18)} AS${i.asn ?? '-'} ${i.asName ?? ''} | ${i.holder ?? '-'} | ${i.prefix ?? '-'} | ${i.country ?? '-'} ${i.city ?? ''} | PTR ${i.ptr.join(',') || '-'} | provider ${i.provider?.id ?? '-'} | ${i.sources.join('+') || (i.private ? 'private' : '-')}${i.error ? ` | ERROR ${i.error}` : ''}`);
}
expect('github IP → AS36459', infos[0].asn === 36459);
expect('8.8.8.8 → AS15169 US', infos[1].asn === 15169 && infos[1].country === 'US');
expect('8.8.8.8 PTR dns.google', infos[1].ptr.includes('dns.google'));
expect('Cloudflare v6 → AS13335 + provider cloudflare', infos[2].asn === 13335 && infos[2].provider?.id === 'cloudflare');
expect('RIPE NCC → AS3333 NL', infos[3].asn === 3333 && infos[3].country === 'NL');
expect('private IP → no lookups', infos[5].private === true && infos[5].sources.length === 0);
if (REVERSE) {
  const rev = await intel.reverseIp('140.82.121.4');
  console.log(`   reverse IP 140.82.121.4: ok=${rev.ok} limited=${rev.limited} ${rev.domains.length} domains ${rev.domains.slice(0, 5).join(', ')}${rev.error ? ` error=${rev.error}` : ''}`);
  expect('reverse IP answered (or quota-limited)', rev.ok || rev.limited);
}

console.log('\n# RDAP');
for (const d of ['github.com', 'bbc.co.uk', 'wikipedia.org', 'example.com.tr']) {
  const r = await rdapDomain(d, { fetchImpl: loggingFetch });
  console.log(`   ${d.padEnd(16)} ok=${r.ok} unsupported=${r.unsupportedTld} registrar=${r.registrar ?? '-'} created=${r.created?.toISOString().slice(0, 10) ?? '-'} expires=${r.expires?.toISOString().slice(0, 10) ?? '-'} ns=${r.nameservers.length} dnssec=${r.dnssecSigned} server=${r.rdapServer ?? '-'}${r.error ? ` error=${r.error}` : ''}`);
  if (d === 'example.com.tr') expect('.com.tr unsupportedTld', r.unsupportedTld === true);
  else expect(`${d} ok`, r.ok);
}
for (const ip of ['140.82.121.4', '193.0.6.139', '1.1.1.1', '200.160.2.3', '41.1.1.1', '2606:4700::1111', '2a00:1450:4001::1']) {
  const r = await rdapIp(ip, { fetchImpl: loggingFetch });
  console.log(`   ${ip.padEnd(18)} ok=${r.ok} rir=${r.rir ?? '-'} name=${r.name ?? '-'} org=${r.org ?? '-'} country=${r.country ?? '-'} cidr=${r.cidr ?? '-'} server=${r.rdapServer ?? '-'}${r.error ? ` error=${r.error}` : ''}`);
  expect(`rdapIp ${ip} ok`, r.ok && !!r.cidr);
}

if (CORS) {
  console.log('\n# Access-Control-Allow-Origin seen by the lookups above (browser usability)');
  // hosts reached only through redirects are recorded under their final host
  for (const [host, acao] of [...acaoLog.entries()].sort()) {
    console.log(`   ${acao ? 'ok  ' : 'NONE'}  ${host}  ${acao ?? ''}`);
    expect(`ACAO from ${host}`, !!acao);
  }
  const boot = await fetch(IANA_BOOTSTRAP.ipv4, { headers: { origin: ORIGIN } });
  expect('IANA ipv4 bootstrap ACAO', !!boot.headers.get('access-control-allow-origin'));
}

console.log('\nDoH stats:', JSON.stringify(dns.stats().byResolver));
h2fetch.close();
console.log(failures ? `\n${failures} expectation(s) FAILED` : '\nALL EXPECTATIONS PASSED');
process.exit(failures ? 1 : 0);
