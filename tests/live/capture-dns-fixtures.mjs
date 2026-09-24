#!/usr/bin/env node
/**
 * LIVE (network) script — captures REAL DNS-over-HTTPS responses as binary
 * fixtures for tests/js/dnswire.test.js. Not run by `npm test`.
 *
 *   node tests/live/capture-dns-fixtures.mjs            # (re)capture everything
 *   node tests/live/capture-dns-fixtures.mjs --dry-run  # query + decode, write nothing
 *
 * Writes tests/fixtures/dns/<id>.bin (raw application/dns-message bodies) and
 * tests/fixtures/dns/manifest.json. The manifest holds, per fixture, the query
 * that produced it and hand-written *structural* expectations (types, owner
 * names, flags, rcode, EDNS facts) that do not depend on volatile values such
 * as TTLs or rotating IPs. For Google fixtures of stable RRsets it also stores
 * an independent oracle: the `data` strings returned at capture time by Google's
 * JSON API (https://dns.google/resolve), which the unit tests compare with our
 * presentation text after per-type normalization.
 *
 * Uses node:http2 because Quad9 only speaks HTTP/2 and Node's fetch is HTTP/1.1.
 * System CA certificates are added because family.cloudflare-dns.com chains to
 * a root (Comodo "AAA Certificate Services") missing from Node's bundled store.
 */
import http2 from 'node:http2';
import tls from 'node:tls';
import { mkdirSync, writeFileSync, readdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeQuery, decodeMessage, base64UrlEncode } from '../../assets/js/lib/dnswire.js';

const OUT_DIR = fileURLToPath(new URL('../fixtures/dns/', import.meta.url));
const DRY_RUN = process.argv.includes('--dry-run');
const ORIGIN = 'https://example.github.io';

const ENDPOINTS = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  'cloudflare-family': 'https://family.cloudflare-dns.com/dns-query',
  google: 'https://dns.google/dns-query',
  quad9: 'https://dns.quad9.net/dns-query'
};

function caBundle() {
  try {
    return [...tls.getCACertificates('default'), ...tls.getCACertificates('system')];
  } catch {
    return undefined; // older Node: default store only
  }
}

const sessions = new Map();
function session(origin) {
  let s = sessions.get(origin);
  if (s && !s.closed && !s.destroyed) return s;
  s = http2.connect(origin, { ca: caBundle() });
  s.on('error', () => {});
  sessions.set(origin, s);
  return s;
}

/** GET over HTTP/2; resolves { status, headers, body: Buffer }. */
function h2get(url, headers = {}, timeoutMs = 15000) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = session(u.origin).request({ ':method': 'GET', ':path': u.pathname + u.search, ...headers });
    const chunks = [];
    let resHeaders = {};
    const timer = setTimeout(() => { req.close(); reject(new Error(`timeout ${url}`)); }, timeoutMs);
    req.on('response', (h) => { resHeaders = h; });
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      clearTimeout(timer);
      resolve({ status: resHeaders[':status'], headers: resHeaders, body: Buffer.concat(chunks) });
    });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
    req.end();
  });
}

function randomLabel(n = 12) {
  const abc = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < n; i++) s += abc[Math.floor(Math.random() * abc.length)];
  return s;
}

const IPV4_RE = '^\\d{1,3}(\\.\\d{1,3}){3}$';
const IPV6_RE = '^[0-9a-f:]+$';
const NX_GOOGLE = `nx-${randomLabel(12)}.google.com`;
const NX_COM = `nx-${randomLabel(12)}.com`;
const NX_CLOUDFLARE = `nx-${randomLabel(12)}.cloudflare.com`;

const HEADER_OK = { qr: true, rd: true, ra: true, tc: false, opcode: 0 };

/**
 * Fixture definitions. `expect` is interpreted by tests/js/dnswire.test.js:
 *  rcode, flags (subset), question, edns (subset + nsid:true = non-empty string),
 *  sections.{answers|authorities|additionals}: { types (set equality), min, names (set equality) },
 *  records: [{ section, type, name?, data? (deep subset), text?, textRe? }] each must match ≥1 RR,
 *  ecs: { family, sourcePrefix, address, scopePrefixMin }, ede: [{ code }], chain: true (CNAME chain order).
 * `oracle: true` → store Google JSON API data for the same query (Google fixtures, stable RRsets).
 */
const DEFS = [];
function def(id, resolver, name, type, opts, expect, extra = {}) {
  DEFS.push({ id, resolver, name, type, opts, expect, ...extra });
}

for (const [p, r] of [['cf', 'cloudflare'], ['gg', 'google']]) {
  const nsidOpt = { nsid: true };
  def(`${p}-a-example.com`, r, 'example.com', 'A', nsidOpt, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'example.com', type: 'A' },
    edns: { dnssecOk: false, nsid: true },
    sections: { answers: { types: ['A'], min: 1, names: ['example.com'] } },
    records: [{ section: 'answers', type: 'A', textRe: IPV4_RE }]
  });
  def(`${p}-aaaa-example.com`, r, 'example.com', 'AAAA', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'example.com', type: 'AAAA' },
    sections: { answers: { types: ['AAAA'], min: 1, names: ['example.com'] } },
    records: [{ section: 'answers', type: 'AAAA', textRe: IPV6_RE }]
  });
  def(`${p}-a-cname-chain`, r, 'www.microsoft.com', 'A', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'www.microsoft.com', type: 'A' },
    chain: true,
    sections: { answers: { types: ['CNAME', 'A'], min: 3 } },
    records: [
      { section: 'answers', type: 'CNAME', name: 'www.microsoft.com', data: 'www.microsoft.com-c-3.edgekey.net', text: 'www.microsoft.com-c-3.edgekey.net.' },
      { section: 'answers', type: 'CNAME', name: 'www.microsoft.com-c-3.edgekey.net', textRe: '^e\\d+\\.dscb\\.akamaiedge\\.net\\.$' },
      { section: 'answers', type: 'A', textRe: IPV4_RE }
    ]
  });
  def(`${p}-mx-google.com`, r, 'google.com', 'MX', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'google.com', type: 'MX' },
    sections: { answers: { types: ['MX'], min: 1, names: ['google.com'] } },
    records: [{ section: 'answers', type: 'MX', data: { preference: 10, exchange: 'smtp.google.com' }, text: '10 smtp.google.com.' }]
  }, { oracle: true });
  def(`${p}-mx-null-example.com`, r, 'example.com', 'MX', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'example.com', type: 'MX' },
    sections: { answers: { types: ['MX'], min: 1, names: ['example.com'] } },
    records: [{ section: 'answers', type: 'MX', data: { preference: 0, exchange: '.' }, text: '0 .' }]
  }, { oracle: true });
  def(`${p}-txt-spf-long`, r, '_spf.apple.com', 'TXT', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: '_spf.apple.com', type: 'TXT' },
    sections: { answers: { types: ['TXT'], min: 1, names: ['_spf.apple.com'] } },
    records: [{ section: 'answers', type: 'TXT', textRe: '^"v=spf1 [^"]+" "[^"]+"' }],
    txtMultiString: true
  }, { oracle: true });
  def(`${p}-soa-example.com`, r, 'example.com', 'SOA', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'example.com', type: 'SOA' },
    sections: { answers: { types: ['SOA'], min: 1, max: 1, names: ['example.com'] } },
    records: [{ section: 'answers', type: 'SOA', textRe: '^\\S+\\. \\S+\\. \\d+ \\d+ \\d+ \\d+ \\d+$' }]
  }, { oracle: true });
  def(`${p}-ns-google.com`, r, 'google.com', 'NS', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'google.com', type: 'NS' },
    sections: { answers: { types: ['NS'], min: 4, names: ['google.com'] } },
    records: ['ns1', 'ns2', 'ns3', 'ns4'].map((n) => ({ section: 'answers', type: 'NS', data: `${n}.google.com`, text: `${n}.google.com.` }))
  }, { oracle: true });
  def(`${p}-caa-google.com`, r, 'google.com', 'CAA', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'google.com', type: 'CAA' },
    sections: { answers: { types: ['CAA'], min: 1, names: ['google.com'] } },
    records: [{ section: 'answers', type: 'CAA', data: { flags: 0, tag: 'issue', value: 'pki.goog' }, text: '0 issue "pki.goog"' }]
  }, { oracle: true });
  def(`${p}-ds-cloudflare.com-do`, r, 'cloudflare.com', 'DS', { dnssecOk: true }, {
    rcode: 'NOERROR', flags: { ...HEADER_OK, ad: true }, question: { name: 'cloudflare.com', type: 'DS' },
    edns: { dnssecOk: true },
    sections: { answers: { types: ['DS', 'RRSIG'], min: 2, names: ['cloudflare.com'] } },
    records: [
      { section: 'answers', type: 'DS', data: { keyTag: 2371, algorithm: 13, digestType: 2 } },
      { section: 'answers', type: 'RRSIG', data: { typeCovered: 'DS', algorithm: 13, labels: 2, signerName: 'com' } }
    ]
  }, { oracle: true });
  def(`${p}-dnskey-cloudflare.com-do`, r, 'cloudflare.com', 'DNSKEY', { dnssecOk: true }, {
    rcode: 'NOERROR', flags: { ...HEADER_OK, ad: true }, question: { name: 'cloudflare.com', type: 'DNSKEY' },
    edns: { dnssecOk: true },
    sections: { answers: { types: ['DNSKEY', 'RRSIG'], min: 3, names: ['cloudflare.com'] } },
    records: [
      { section: 'answers', type: 'DNSKEY', data: { flags: 257, protocol: 3, algorithm: 13, keyTag: 2371, sep: true, zoneKey: true } },
      { section: 'answers', type: 'DNSKEY', data: { flags: 256, protocol: 3, algorithm: 13, sep: false, zoneKey: true } },
      { section: 'answers', type: 'RRSIG', data: { typeCovered: 'DNSKEY', algorithm: 13, labels: 2, keyTag: 2371, signerName: 'cloudflare.com' } }
    ]
  }, { oracle: true });
  def(`${p}-https-cloudflare.com`, r, 'cloudflare.com', 'HTTPS', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'cloudflare.com', type: 'HTTPS' },
    sections: { answers: { types: ['HTTPS'], min: 1, names: ['cloudflare.com'] } },
    records: [{ section: 'answers', type: 'HTTPS', data: { priority: 1, target: '.', params: { alpn: ['h3', 'h2'] } }, textRe: '^1 \\. alpn="h3,h2" ipv4hint=[0-9.,]+ ipv6hint=[0-9a-f:,]+$' }]
  }, { oracle: true });
  def(`${p}-srv-jabber`, r, '_xmpp-server._tcp.jabber.org', 'SRV', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: '_xmpp-server._tcp.jabber.org', type: 'SRV' },
    sections: { answers: { types: ['SRV'], min: 1, names: ['_xmpp-server._tcp.jabber.org'] } },
    records: [{ section: 'answers', type: 'SRV', data: { port: 5269 }, textRe: '^\\d+ \\d+ 5269 [a-z0-9.-]+\\.jabber\\.org\\.$' }]
  }, { oracle: true });
  def(`${p}-nxdomain`, r, NX_GOOGLE, 'A', {}, {
    rcode: 'NXDOMAIN', flags: HEADER_OK, question: { name: NX_GOOGLE, type: 'A' },
    sections: { answers: { types: [], min: 0 }, authorities: { types: ['SOA'], min: 1, names: ['google.com'] } },
    records: [{ section: 'authorities', type: 'SOA', name: 'google.com', data: { mname: 'ns1.google.com', rname: 'dns-admin.google.com', email: 'dns-admin@google.com' } }]
  });
  def(`${p}-ptr-8.8.8.8`, r, '8.8.8.8.in-addr.arpa', 'PTR', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: '8.8.8.8.in-addr.arpa', type: 'PTR' },
    sections: { answers: { types: ['PTR'], min: 1, names: ['8.8.8.8.in-addr.arpa'] } },
    records: [{ section: 'answers', type: 'PTR', data: 'dns.google', text: 'dns.google.' }]
  }, { oracle: true });
  def(`${p}-servfail-dnssec-bogus`, r, 'dnssec-failed.org', 'A', {}, {
    rcode: 'SERVFAIL', flags: HEADER_OK, question: { name: 'dnssec-failed.org', type: 'A' },
    sections: { answers: { types: [], min: 0 } },
    ede: [{ code: 9 }]
  });
  def(`${p}-tlsa-ietf`, r, '_25._tcp.mail.ietf.org', 'TLSA', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: '_25._tcp.mail.ietf.org', type: 'TLSA' },
    sections: { answers: { types: ['TLSA'], min: 1, names: ['_25._tcp.mail.ietf.org'] } },
    records: [{ section: 'answers', type: 'TLSA', data: { usage: 3, selector: 1, matchingType: 1 }, textRe: '^3 1 1 [0-9A-F]{64}$' }]
  }, { oracle: true });
  def(`${p}-naptr-sip2sip`, r, 'sip2sip.info', 'NAPTR', {}, {
    rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'sip2sip.info', type: 'NAPTR' },
    sections: { answers: { types: ['NAPTR'], min: 3, names: ['sip2sip.info'] } },
    records: [{ section: 'answers', type: 'NAPTR', data: { order: 10, preference: 100, flags: 's', services: 'SIP+D2T', regexp: '', replacement: '_sip._tcp.sip2sip.info' }, text: '10 100 "s" "SIP+D2T" "" _sip._tcp.sip2sip.info.' }]
  }, { oracle: true });
  def(`${p}-svcb-ddr`, r, '_dns.resolver.arpa', 'SVCB', {}, {
    rcode: 'NOERROR', flags: { qr: true, rd: true }, question: { name: '_dns.resolver.arpa', type: 'SVCB' },
    sections: { answers: { types: ['SVCB'], min: 2, names: ['_dns.resolver.arpa'] } },
    records: r === 'google'
      ? [{ section: 'answers', type: 'SVCB', data: { priority: 2, target: 'dns.google', params: { alpn: ['h2', 'h3'], dohpath: '/dns-query{?dns}' } }, text: '2 dns.google. alpn="h2,h3" dohpath="/dns-query{?dns}"' }]
      : [{ section: 'answers', type: 'SVCB', data: { priority: 1, target: 'one.one.one.one', params: { alpn: ['h2', 'h3'], port: 443, ipv4hint: ['1.1.1.1', '1.0.0.1'] } } }]
  });
}

// NSEC3 denial of existence from the .com zone (DO bit) — Google.
// AD stays 0 here: .com uses NSEC3 opt-out, which cannot prove the name insecure-free (RFC 5155 §6).
def('gg-nxdomain-com-nsec3-do', 'google', NX_COM, 'A', { dnssecOk: true }, {
  rcode: 'NXDOMAIN', flags: HEADER_OK, question: { name: NX_COM, type: 'A' },
  edns: { dnssecOk: true },
  sections: { answers: { types: [], min: 0 }, authorities: { types: ['SOA', 'RRSIG', 'NSEC3'], min: 4 } },
  records: [
    { section: 'authorities', type: 'SOA', name: 'com' },
    { section: 'authorities', type: 'NSEC3', data: { hashAlgorithm: 1 }, textRe: '^1 1 0 - [0-9A-V]{32}( [A-Z0-9]+)*$' },
    { section: 'authorities', type: 'RRSIG', data: { typeCovered: 'NSEC3', signerName: 'com' } }
  ]
});
// Cloudflare "black lies" / compact denial: NOERROR + NSEC (DO bit).
def('cf-nodata-cloudflare.com-nsec-do', 'cloudflare', NX_CLOUDFLARE, 'A', { dnssecOk: true }, {
  flags: { qr: true, rd: true, ra: true, ad: true }, question: { name: NX_CLOUDFLARE, type: 'A' },
  edns: { dnssecOk: true },
  sections: { answers: { types: [], min: 0 }, authorities: { types: ['SOA', 'RRSIG', 'NSEC'], min: 3 } },
  records: [{ section: 'authorities', type: 'NSEC', name: NX_CLOUDFLARE, data: { types: ['RRSIG', 'NSEC'] } }]
});
// ANY → RFC 8482 HINFO via Google (with RRSIG thanks to DO); Cloudflare answers NOTIMP.
def('gg-any-cloudflare.com-do', 'google', 'cloudflare.com', 'ANY', { dnssecOk: true }, {
  rcode: 'NOERROR', question: { name: 'cloudflare.com', type: 'ANY' },
  sections: { answers: { types: ['HINFO', 'RRSIG'], min: 2, names: ['cloudflare.com'] } },
  records: [{ section: 'answers', type: 'HINFO', data: { cpu: 'RFC8482', os: '' }, text: '"RFC8482" ""' }]
});
def('cf-any-notimp', 'cloudflare', 'cloudflare.com', 'ANY', {}, {
  rcode: 'NOTIMP', question: { name: 'cloudflare.com', type: 'ANY' },
  sections: { answers: { types: [], min: 0 } },
  ede: [{ code: 21 }]
});
// ECS through Google: IPv4 vantage (a consumer-ISP /24) on a geo-aware name → non-zero scope.
def('gg-ecs-v4-amazon', 'google', 'www.amazon.com', 'A', { ecs: '85.105.0.0/24' }, {
  rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'www.amazon.com', type: 'A' },
  chain: true,
  sections: { answers: { min: 2 } },
  records: [{ section: 'answers', type: 'A', textRe: IPV4_RE }],
  ecs: { family: 1, sourcePrefix: 24, address: '85.105.0.0', scopePrefixMin: 1 }
});
def('gg-ecs-v4-wikipedia', 'google', 'www.wikipedia.org', 'A', { ecs: '46.211.64.0/24' }, {
  rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'www.wikipedia.org', type: 'A' },
  sections: { answers: { min: 1 } },
  ecs: { family: 1, sourcePrefix: 24, address: '46.211.64.0', scopePrefixMin: 1 }
});
// ECS with an IPv6 source prefix (echo of family 2).
def('gg-ecs-v6', 'google', 'www.wikipedia.org', 'AAAA', { ecs: '2a01:cb00::/32' }, {
  rcode: 'NOERROR', flags: HEADER_OK, question: { name: 'www.wikipedia.org', type: 'AAAA' },
  sections: { answers: { min: 1 } },
  ecs: { family: 2, sourcePrefix: 32, address: '2a01:cb00::' }
});
// Filtering resolvers: Extended DNS Errors on blocked names.
def('cff-blocked-ede', 'cloudflare-family', 'malware.wicar.org', 'A', {}, {
  rcode: 'NOERROR', question: { name: 'malware.wicar.org', type: 'A' },
  records: [{ section: 'answers', type: 'A', data: '0.0.0.0' }],
  ede: [{ code: 16 }]
});
def('q9-blocked-ede', 'quad9', 'isitblocked.org', 'A', { nsid: true }, {
  rcode: 'NXDOMAIN', question: { name: 'isitblocked.org', type: 'A' },
  edns: { nsid: true },
  ede: [{ code: 17 }]
});

/** Query one fixture and return the raw body. */
async function capture(d) {
  const u = new URL(ENDPOINTS[d.resolver]);
  u.searchParams.set('dns', base64UrlEncode(encodeQuery(d.name, d.type, d.opts)));
  const res = await h2get(u.href, { accept: 'application/dns-message', origin: ORIGIN });
  if (res.status !== 200) throw new Error(`${d.id}: HTTP ${res.status}`);
  if (!res.headers['access-control-allow-origin']) console.warn(`  ! ${d.id}: no access-control-allow-origin header`);
  return res.body;
}

/** Google JSON API answers (type + data) for the oracle; excludes RRSIGs (signed online, not stable). */
async function googleJson(d) {
  const url = new URL('https://dns.google/resolve');
  url.searchParams.set('name', d.name);
  url.searchParams.set('type', d.type);
  if (d.opts.dnssecOk) url.searchParams.set('do', '1');
  const res = await fetch(url, { headers: { accept: 'application/dns-json' } });
  if (!res.ok) throw new Error(`google json HTTP ${res.status}`);
  const j = await res.json();
  return (j.Answer || []).filter((a) => a.type !== 46).map((a) => ({ type: a.type, data: a.data }));
}

async function main() {
  if (!DRY_RUN) {
    mkdirSync(OUT_DIR, { recursive: true });
    for (const f of readdirSync(OUT_DIR)) if (f.endsWith('.bin')) unlinkSync(join(OUT_DIR, f));
  }
  const manifest = {
    description: 'Real DoH (RFC 8484) responses captured by tests/live/capture-dns-fixtures.mjs; expectations are structural. Regenerate with: node tests/live/capture-dns-fixtures.mjs',
    capturedAt: new Date().toISOString(),
    fixtures: []
  };
  let failed = 0;
  for (const d of DEFS) {
    try {
      const body = await capture(d);
      const msg = decodeMessage(body); // sanity: must decode
      const entry = {
        id: d.id,
        file: `${d.id}.bin`,
        resolver: d.resolver,
        url: ENDPOINTS[d.resolver],
        query: { name: d.name, type: d.type, ...d.opts },
        size: body.length,
        expect: d.expect
      };
      if (d.oracle && d.resolver === 'google') {
        entry.oracle = { source: 'https://dns.google/resolve', answers: await googleJson(d) };
      }
      manifest.fixtures.push(entry);
      if (!DRY_RUN) writeFileSync(join(OUT_DIR, entry.file), body);
      console.log(`${d.id.padEnd(34)} ${String(body.length).padStart(5)}B ${msg.rcodeName.padEnd(8)} an=${msg.answers.length} ns=${msg.authorities.length} ar=${msg.additionals.length}${msg.edns?.ecs ? ` ecs=${msg.edns.ecs.subnet}/scope${msg.edns.ecs.scopePrefix}` : ''}${msg.edns?.ede?.length ? ` ede=${msg.edns.ede.map((e) => e.code).join(',')}` : ''}`);
    } catch (err) {
      failed++;
      console.error(`FAILED ${d.id}: ${err.message}`);
    }
  }
  if (!DRY_RUN) writeFileSync(join(OUT_DIR, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  for (const s of sessions.values()) s.close();
  console.log(`\n${manifest.fixtures.length} captured, ${failed} failed${DRY_RUN ? ' (dry run, nothing written)' : ` → ${OUT_DIR}`}`);
  process.exitCode = failed ? 1 : 0;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
