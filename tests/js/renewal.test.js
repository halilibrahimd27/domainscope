/**
 * lib/renewal.js — Renewal readiness. No network: DNS is a fake DohClient (real wire-format RRs,
 * CNAME chains, NXDOMAIN / NODATA with the zone's SOA, AD for signed zones, bogus zones, per-resolver
 * views and failures); Globalping results are the recorded fixtures m28–m30 plus synthetic results.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  RENEWAL_CHALLENGES, RENEWAL_VERDICTS, RENEWAL_LIMITS, CONSISTENCY_RESOLVERS, RENEWAL_CAS, DNS_PROVIDERS, RENEWAL_FINDINGS,
  RENEWAL_AREAS, HTTP01_OUTCOMES, HTTP01_VERDICTS, HTTP01_LOCATIONS, RENEWAL_CSV_COLUMNS, RENEWAL_I18N,
  parseRenewalNames, renewalCa, caForIssuer, dnsProvidersFor, isAcmeDnsTarget, pluginText, nameFindings, nameVerdict,
  checkRenewal, http01Token, http01Plan, http01Request, redirectOutcome, http01Outcome, http01Verdict, interpretHttp01,
  http01Findings, applyHttp01, renewalSummary, renewalRows, renewalExport
} from '../../assets/js/lib/renewal.js';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';
import { toCsv, toJson } from '../../assets/js/lib/export.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'globalping');
const fx = (name) => JSON.parse(readFileSync(join(FIX, `${name}.json`), 'utf8'));

/* ==================================================================== */
/* Fake DNS                                                              */
/* ==================================================================== */

const SOA = (zone) => ({ mname: `ns1.${zone}`, rname: `hostmaster.${zone}`, serial: 1, refresh: 7200, retry: 900, expire: 1209600, minimum: 300 });
const CAA = (tag, value, flags = 0) => ({ flags, tag, value });

function rrs(list) {
  if (!list.length) return [];
  return decodeMessage(encodeMessage({ answers: list.map((r) => ({ ttl: 300, ...r })) })).answers;
}
const asList = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

/**
 * A zone map `{ name: { TYPE: value | value[], CNAME: target } }` answered like a DohClient: the chain
 * resolver is 'cloudflare'; `views[resolver]` replaces names for one resolver (a lagging server),
 * `down[resolver]` makes a resolver unreachable, `rcodes['name|TYPE']` (or `rcodes[resolver]`) forces
 * an rcode; names under `signed` get AD, names under `broken` SERVFAIL unless CD is set.
 */
function fakeDns(zone, { signed = [], broken = [], rcodes = {}, views = {}, down = {}, fail = {} } = {}) {
  const calls = [];
  const under = (name, list) => list.some((z) => name === z || name.endsWith(`.${z}`));
  async function query(qname, type = 'A', { resolver, cd = false, dnssec = false, signal, noCache = false } = {}) {
    throwIfAborted(signal);
    const name = String(qname).toLowerCase().replace(/\.$/, '');
    const rid = resolver || 'cloudflare';
    calls.push({ name, type, resolver: resolver || null, cd, dnssec, noCache });
    const base = (extra) => ({
      name, type, resolver: rid, ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: false, cd },
      answers: [], authorities: [], ede: [], error: null, errorKind: null, ...extra
    });
    if (down[rid] || fail[`${name}|${type}`]) return base({ ok: false, rcode: null, flags: null, error: down[rid] || fail[`${name}|${type}`], errorKind: 'network' });
    const forced = (rcodes[rid] || {})[`${name}|${type}`] || rcodes[`${name}|${type}`];
    if (forced && !(cd && forced === 'SERVFAIL' && rcodes.cdAnswers)) return base({ rcode: forced });
    const bogus = base({ rcode: 'SERVFAIL', ede: [{ code: 6, text: 'signature expired' }] });
    const z = { ...zone, ...(views[rid] || {}) };
    const lookup = (n) => z[n] || null;
    const answers = [];
    let cur = name;
    let rcode = 'NOERROR';
    for (let i = 0; i < 12; i += 1) {
      // A validating resolver fails the whole answer once the chain enters a bogus zone.
      if (under(cur, broken) && !cd) return bogus;
      const node = lookup(cur);
      if (!node) {
        rcode = 'NXDOMAIN';
        break;
      }
      if (node.CNAME && type !== 'CNAME') {
        answers.push({ name: cur, type: 'CNAME', data: node.CNAME });
        cur = node.CNAME;
        continue;
      }
      for (const data of asList(node[type])) answers.push({ name: cur, type, data: type === 'TXT' ? [data] : data });
      break;
    }
    const res = base({ rcode, answers: rrs(answers) });
    if (!res.answers.some((rr) => rr.type === type)) {
      let owner = cur;
      while (owner.includes('.') && !(z[owner] && z[owner].SOA)) owner = owner.slice(owner.indexOf('.') + 1);
      if (z[owner] && z[owner].SOA) res.authorities = rrs([{ name: owner, type: 'SOA', data: z[owner].SOA }]);
    }
    res.flags = { ...res.flags, ad: under(cur, signed) && !cd };
    return res;
  }
  return { query, calls };
}

/** The example zone most tests start from: a signed example.com on Cloudflare, Let's Encrypt allowed. */
function exampleZone(extra = {}) {
  return {
    'example.com': {
      SOA: SOA('example.com'), NS: ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'],
      CAA: [CAA('issue', 'letsencrypt.org'), CAA('iodef', 'mailto:security@example.com')], A: '203.0.113.10'
    },
    'www.example.com': { A: '203.0.113.10', AAAA: '2001:db8::10' },
    'shop.example.com': { CNAME: 'shop.example.net' },
    'example.net': { SOA: SOA('example.net'), NS: ['ns-cloud-a1.googledomains.com'] },
    'shop.example.net': { A: '198.51.100.20' },
    ...extra
  };
}

const names = (...list) => parseRenewalNames(list.join('\n')).names;
const ids = (r) => r.findings.map((f) => f.id);
const sev = (r, id) => (r.findings.find((f) => f.id === id) || {}).severity;
const run = (zone, list, input = {}, opts = {}) => {
  const dns = opts.dns || fakeDns(zone, opts.fake || {});
  return checkRenewal({ names: names(...list), ...input }, { dns, ...opts });
};

/* ==================================================================== */
/* Constants and input                                                   */
/* ==================================================================== */

test('constants: vocabularies are frozen and consistent', () => {
  assert.deepEqual([...RENEWAL_CHALLENGES], ['http-01', 'dns-01', 'tls-alpn-01', 'unknown']);
  assert.deepEqual([...RENEWAL_VERDICTS], ['fail', 'warnings', 'ready']);
  assert.deepEqual([...CONSISTENCY_RESOLVERS], ['cloudflare', 'google', 'dnssb', 'cznic']);
  assert.equal(RENEWAL_LIMITS.names, 50);
  for (const x of [RENEWAL_CHALLENGES, RENEWAL_CAS, DNS_PROVIDERS, RENEWAL_FINDINGS, RENEWAL_AREAS, HTTP01_OUTCOMES, HTTP01_VERDICTS, HTTP01_LOCATIONS]) {
    assert.ok(Object.isFrozen(x));
  }
  for (const id of RENEWAL_FINDINGS) assert.ok(RENEWAL_AREAS.includes(id.slice(0, id.indexOf('.'))), id);
  assert.equal(new Set(DNS_PROVIDERS.map((p) => p.id)).size, DNS_PROVIDERS.length);
  assert.deepEqual(HTTP01_LOCATIONS.map((l) => l.continent), ['EU', 'NA', 'AS']);
});

test('RENEWAL_CAS: CAA identifiers from lib/health.js; ZeroSSL uses Sectigo\'s', () => {
  assert.deepEqual(renewalCa('letsencrypt').domains, ['letsencrypt.org']);
  assert.equal(renewalCa('zerossl').name, 'ZeroSSL');
  assert.ok(renewalCa('zerossl').domains.includes('sectigo.com'));
  assert.deepEqual(renewalCa('google').domains, ['pki.goog']);
  assert.equal(renewalCa('etugra'), null, 'a distrusted CA is not offered');
  assert.equal(renewalCa(null), null);
});

test('parseRenewalNames: host names and wildcards, URLs, duplicates, comments; IPs, "_" and junk are invalid', () => {
  const r = parseRenewalNames('# the certificate\nWWW.Example.COM., *.example.com\nhttps://shop.example.com/x ; www.example.com\n192.0.2.1 [2001:db8::1] _acme-challenge.example.com bad..name localhost');
  assert.deepEqual(r.names, [
    { name: 'www.example.com', base: 'www.example.com', wildcard: false },
    { name: '*.example.com', base: 'example.com', wildcard: true },
    { name: 'shop.example.com', base: 'shop.example.com', wildcard: false }
  ]);
  assert.deepEqual(r.invalid, ['192.0.2.1', '[2001:db8::1]', '_acme-challenge.example.com', 'bad..name', 'localhost']);
  assert.equal(r.overCap, 0);
  const many = parseRenewalNames(Array.from({ length: 55 }, (_, i) => `h${i}.example.com`));
  assert.equal(many.names.length, 50);
  assert.equal(many.overCap, 5);
  assert.equal(parseRenewalNames('a.example.com b.example.com', { max: 1 }).overCap, 1);
  assert.deepEqual(parseRenewalNames('').names, []);
});

test('caForIssuer: the CA of a certificate issuer (DN or parsed object); ZeroSSL before Sectigo', () => {
  assert.equal(caForIssuer("CN=R11,O=Let's Encrypt,C=US"), 'letsencrypt');
  assert.equal(caForIssuer({ CN: 'WE1', O: 'Google Trust Services', C: 'US' }), 'google');
  assert.equal(caForIssuer('CN=ZeroSSL RSA Domain Secure Site CA,O=ZeroSSL,C=AT'), 'zerossl');
  assert.equal(caForIssuer('CN=Sectigo RSA Domain Validation Secure Server CA,O=Sectigo Limited'), 'sectigo');
  assert.equal(caForIssuer('CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc'), 'digicert');
  assert.equal(caForIssuer('CN=Example Internal CA,O=Example'), null);
  assert.equal(caForIssuer('CN=E-Tugra TLS CA,O=E-Tugra'), null);
  assert.equal(caForIssuer(''), null);
  assert.equal(caForIssuer(null), null);
});

test('dnsProvidersFor: suffixes on a label boundary and patterns; unknown servers are listed', () => {
  const one = (ns) => dnsProvidersFor(ns).providers.map((p) => p.id);
  assert.deepEqual(one(['ada.ns.cloudflare.com.', 'BOB.NS.CLOUDFLARE.COM']), ['cloudflare']);
  assert.deepEqual(one(['ns-1234.awsdns-12.org', 'ns-567.awsdns-34.co.uk']), ['route53']);
  assert.deepEqual(one(['ns-cloud-a1.googledomains.com']), ['gcloud']);
  assert.deepEqual(one(['ns1.googledomains.com']), [], 'Google Domains is not Cloud DNS');
  assert.deepEqual(one(['ns1-01.azure-dns.com', 'ns2-01.azure-dns.net']), ['azure']);
  assert.deepEqual(one(['hydrogen.ns.hetzner.com', 'helium.ns.hetzner.de']), ['hetzner']);
  assert.deepEqual(one(['ns1.natrohost.com', 'ns2.natrohost.com']), ['natro']);
  assert.deepEqual(one(['tr.dnsenable.com', 'ns1.isimtescil.net']), ['isimtescil']);
  assert.deepEqual(one(['ns1.turhost.com']), ['turhost']);
  assert.deepEqual(one(['notcloudflare.com']), [], 'no partial label match');
  const mixed = dnsProvidersFor(['ada.ns.cloudflare.com', 'ns-1.awsdns-01.com', 'ns1.example.net']);
  assert.deepEqual(mixed.providers.map((p) => p.id), ['cloudflare', 'route53']);
  assert.deepEqual(mixed.unmatched, ['ns1.example.net']);
  for (const id of ['natro', 'turhost', 'isimtescil']) {
    const p = DNS_PROVIDERS.find((x) => x.id === id);
    assert.deepEqual([p.api, p.lego, p.acmesh, p.certbot], [false, null, null, null], id);
  }
  const cf = DNS_PROVIDERS.find((x) => x.id === 'cloudflare');
  assert.equal(pluginText(cf), 'lego --dns cloudflare · acme.sh --dns dns_cf · certbot-dns-cloudflare');
  assert.equal(pluginText(DNS_PROVIDERS.find((x) => x.id === 'vultr')), 'lego --dns vultr · acme.sh --dns dns_vultr');
});

test('isAcmeDnsTarget: a UUID first label', () => {
  assert.equal(isAcmeDnsTarget('3f5c9a0e-1b2c-4d5e-8f90-a1b2c3d4e5f6.auth.acme-dns.example.net'), true);
  assert.equal(isAcmeDnsTarget('_acme-challenge.example.net'), false);
  assert.equal(isAcmeDnsTarget(''), false);
});

/* ==================================================================== */
/* checkRenewal: the DNS side                                            */
/* ==================================================================== */

test('ready: CAA allows the CA, resolvers agree, signed zone, public IPv4 + IPv6 (HTTP-01)', async () => {
  const dns = fakeDns(exampleZone(), { signed: ['example.com'] });
  const report = await run(null, ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' }, { dns, noCache: true });
  assert.equal(report.challenge, 'http-01');
  assert.equal(report.ca.id, 'letsencrypt');
  const r = report.names[0];
  assert.deepEqual(ids(r), ['caa.allowed', 'resolvers.agree', 'dnssec.secure', 'http.ok', 'http.ipv6']);
  assert.equal(r.verdict, 'ready');
  const allowed = r.findings[0];
  assert.deepEqual(allowed.params, { ca: "Let's Encrypt", property: 'issue', foundAt: 'example.com', authorized: 'letsencrypt.org' });
  assert.equal(allowed.area, 'caa');
  assert.deepEqual(r.caa.records, ['0 issue "letsencrypt.org"', '0 iodef "mailto:security@example.com"']);
  assert.equal(r.findings[1].params.count, 4);
  assert.deepEqual(r.address.ipv4, ['203.0.113.10']);
  assert.deepEqual(r.address.ipv6, ['2001:db8::10']);
  assert.equal(r.dnssec.zone, 'example.com');
  assert.equal(r.dnsHost, null, 'HTTP-01 on a plain name: no provider lookup');
  assert.equal(r.acme.state, 'none');
  assert.ok(dns.calls.every((c) => c.noCache), 'noCache reaches every query');
  // Every consistency resolver was asked by name, the effective lookup on the chain.
  for (const id of CONSISTENCY_RESOLVERS) assert.ok(dns.calls.some((c) => c.resolver === id && c.type === 'CAA'), id);
  assert.ok(dns.calls.some((c) => c.resolver === null && c.type === 'CAA'));
  for (const f of r.findings) for (const v of Object.values(f.params)) assert.ok(['string', 'number'].includes(typeof v), `${f.id}: ${v}`);
});

test('one check shares the DNS answers between its names (a parent CAA set is asked once per resolver)', async () => {
  const dns = fakeDns(exampleZone());
  await run(null, ['www.example.com', 'api.example.com', 'mail.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' }, { dns });
  const parentCaa = dns.calls.filter((c) => c.name === 'example.com' && c.type === 'CAA');
  assert.equal(parentCaa.length, 1 + CONSISTENCY_RESOLVERS.length);
  assert.equal(dns.calls.filter((c) => c.name === 'example.com' && c.type === 'NS').length, 1);
});

test('CAA names another CA → will fail, with the record to add', async () => {
  const zone = exampleZone({ 'example.com': { SOA: SOA('example.com'), CAA: CAA('issue', 'pki.goog'), NS: ['ada.ns.cloudflare.com'] } });
  const r = (await run(zone, ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' })).names[0];
  assert.equal(r.verdict, 'fail');
  const f = r.findings.find((x) => x.id === 'caa.denied');
  assert.deepEqual(f.params, { ca: "Let's Encrypt", property: 'issue', foundAt: 'example.com', authorized: 'pki.goog', domain: 'letsencrypt.org' });
  // No CA chosen: the same records only say who is allowed.
  const open = (await run(zone, ['www.example.com'], { challenge: 'http-01' })).names[0];
  assert.equal(sev(open, 'caa.no-ca'), 'info');
  assert.equal(open.findings.find((x) => x.id === 'caa.no-ca').params.authorized, 'pki.goog');
  assert.equal(open.verdict, 'ready');
});

test('CAA without records, without an issue property, deny-all, a critical unknown tag, a malformed value', async () => {
  const noCaa = exampleZone({ 'example.com': { SOA: SOA('example.com'), NS: ['ada.ns.cloudflare.com'] } });
  let r = (await run(noCaa, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.equal(ids(r)[0], 'caa.none');
  assert.equal(r.findings[0].params.name, 'www.example.com');
  const iodefOnly = exampleZone({ 'example.com': { SOA: SOA('example.com'), CAA: CAA('iodef', 'mailto:a@example.com') } });
  r = (await run(iodefOnly, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.equal(ids(r)[0], 'caa.open');
  const denyAll = exampleZone({ 'example.com': { SOA: SOA('example.com'), CAA: CAA('issue', ';') } });
  r = (await run(denyAll, ['www.example.com'], { challenge: 'dns-01' })).names[0];
  assert.equal(sev(r, 'caa.deny-all'), 'error', 'deny-all needs no CA to be an error');
  const critical = exampleZone({ 'example.com': { SOA: SOA('example.com'), CAA: [CAA('issue', 'letsencrypt.org'), CAA('tbs', 'x', 128)] } });
  r = (await run(critical, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.equal(r.findings.find((f) => f.id === 'caa.critical').params.tags, 'tbs');
  const malformed = exampleZone({ 'example.com': { SOA: SOA('example.com'), CAA: CAA('issue', 'letsencrypt.org; validationmethods=dns-01;') } });
  r = (await run(malformed, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.equal(sev(r, 'caa.unusable'), 'error');
  assert.match(r.findings.find((f) => f.id === 'caa.unusable').params.values, /empty-parameter/);
});

test('RFC 8657 validationmethods against the chosen challenge; accounturi pins the account', async () => {
  const zone = exampleZone({
    'example.com': {
      SOA: SOA('example.com'), NS: ['ada.ns.cloudflare.com'],
      CAA: CAA('issue', 'letsencrypt.org; validationmethods=dns-01; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234')
    }
  });
  let r = (await run(zone, ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' })).names[0];
  assert.equal(r.verdict, 'fail');
  assert.deepEqual(r.findings.find((f) => f.id === 'caa.method-blocked').params, { challenge: 'http-01', methods: 'dns-01', foundAt: 'example.com' });
  assert.ok(!ids(r).includes('caa.account'), 'no alternative is usable, so no account note');
  r = (await run(zone, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.deepEqual(ids(r).slice(0, 2), ['caa.restricted', 'caa.account']);
  assert.equal(r.findings[1].params.accounts, 'https://acme-v02.api.letsencrypt.org/acme/acct/1234');
  assert.match(r.findings[0].params.restrictions, /^letsencrypt\.org: validationmethods=dns-01; accounturi=https/);
  assert.equal(r.verdict, 'ready');
  r = (await run(zone, ['www.example.com'], { ca: 'letsencrypt', challenge: 'unknown' })).names[0];
  assert.equal(sev(r, 'caa.method-check'), 'warn');
  assert.equal(r.verdict, 'warnings');
  // Two alternatives, one without methods: any method passes through that one.
  const alt = exampleZone({ 'example.com': { SOA: SOA('example.com'), CAA: [CAA('issue', 'letsencrypt.org; validationmethods=dns-01'), CAA('issue', 'letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/9')] } });
  r = (await run(alt, ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' })).names[0];
  assert.ok(!ids(r).includes('caa.method-blocked'));
  assert.equal(r.findings.find((f) => f.id === 'caa.account').params.accounts, 'https://acme-v02.api.letsencrypt.org/acme/acct/9', 'only the account path allows http-01');
});

test('wildcards: issuewild applies, DNS-01 only, the provider of the zone', async () => {
  const zone = exampleZone({
    'example.com': { SOA: SOA('example.com'), NS: ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'], CAA: [CAA('issue', ';'), CAA('issuewild', 'letsencrypt.org')] }
  });
  let r = (await run(zone, ['*.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.deepEqual(ids(r), ['caa.allowed', 'resolvers.agree', 'wildcard.dns01', 'acme.none', 'provider.known', 'dnssec.unsigned']);
  assert.equal(r.findings[0].params.property, 'issuewild');
  assert.equal(r.findings.find((f) => f.id === 'provider.known').params.plugins, 'lego --dns cloudflare · acme.sh --dns dns_cf · certbot-dns-cloudflare');
  assert.equal(r.address, null, 'no address lookup for a wildcard');
  assert.equal(r.verdict, 'ready');
  r = (await run(zone, ['*.example.com'], { ca: 'letsencrypt', challenge: 'http-01' })).names[0];
  assert.equal(sev(r, 'wildcard.method'), 'error');
  r = (await run(zone, ['*.example.com'], { ca: 'letsencrypt', challenge: 'unknown' })).names[0];
  assert.equal(sev(r, 'wildcard.unknown'), 'warn');
  // The same zone denies the apex itself (issue ";").
  r = (await run(zone, ['example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.equal(sev(r, 'caa.deny-all'), 'error');
});

test('resolvers: a lagging server that denies the CA is an error; SERVFAIL on one is a warning; an unreachable one is a note', async () => {
  const old = { 'example.com': { SOA: SOA('example.com'), CAA: CAA('issue', 'pki.goog') } };
  let r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' }, { fake: { views: { cznic: old } } })).names[0];
  const differ = r.findings.find((f) => f.id === 'resolvers.differ');
  assert.equal(differ.severity, 'error');
  assert.equal(differ.params.count, 2);
  assert.equal(differ.params.variants, 'Cloudflare, Google Public DNS, DNS.SB: 0 iodef "mailto:security@example.com", 0 issue "letsencrypt.org" (example.com) | CZ.NIC ODVR: 0 issue "pki.goog" (example.com)');
  assert.equal(r.verdict, 'fail');
  // The same difference without a CA to judge: a warning.
  r = (await run(exampleZone(), ['www.example.com'], { challenge: 'http-01' }, { fake: { views: { cznic: old } } })).names[0];
  assert.equal(sev(r, 'resolvers.differ'), 'warn');
  r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' }, {
    fake: { rcodes: { dnssb: { 'example.com|CAA': 'SERVFAIL' } }, down: { google: 'Failed to fetch' } }
  })).names[0];
  assert.deepEqual(r.findings.filter((f) => f.area === 'resolvers').map((f) => [f.id, f.severity, f.params.resolvers]),
    [['resolvers.servfail', 'warn', 'DNS.SB'], ['resolvers.unreachable', 'info', 'Google Public DNS']]);
  assert.equal(r.verdict, 'warnings');
  assert.deepEqual(r.resolvers.map((x) => x.state), ['ok', 'error', 'servfail', 'ok']);
});

test('the effective CAA lookup: SERVFAIL is an error (the CA must refuse), a transport failure only "not checked"', async () => {
  let r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' }, { fake: { rcodes: { 'www.example.com|CAA': 'SERVFAIL' } } })).names[0];
  const f = r.findings.find((x) => x.id === 'caa.servfail');
  assert.equal(f.severity, 'error');
  assert.equal(f.params.rcode, 'SERVFAIL');
  r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' }, { fake: { fail: { 'www.example.com|CAA': 'Failed to fetch' } } })).names[0];
  assert.equal(sev(r, 'caa.error'), 'warn');
});

test('CAA through a CNAME: the alias target answers, the climb goes on with the name\'s parents', async () => {
  const zone = exampleZone({ 'example.net': { SOA: SOA('example.net'), CAA: CAA('issue', 'pki.goog') } });
  const r = (await run(zone, ['shop.example.com'], { ca: 'letsencrypt', challenge: 'http-01' })).names[0];
  assert.deepEqual(r.findings.find((f) => f.id === 'caa.cname').params, { from: 'shop.example.com', chain: 'shop.example.net', name: 'shop.example.com' });
  assert.equal(r.caa.foundAt, 'example.com', 'shop.example.net has no CAA: the parent of shop.example.com answers, not example.net');
  assert.equal(sev(r, 'caa.allowed'), 'ok');
});

test('_acme-challenge: none, leftovers, a CNAME delegation, acme-dns, a dangling one (a takeover risk)', async () => {
  const uuid = '3f5c9a0e-1b2c-4d5e-8f90-a1b2c3d4e5f6';
  const zone = exampleZone({
    '_acme-challenge.old.example.com': { TXT: ['tok-1', 'tok-2'] },
    'old.example.com': { A: '203.0.113.11' },
    '_acme-challenge.alias.example.com': { CNAME: 'alias.acme.example.net' },
    'alias.example.com': { A: '203.0.113.12' },
    'acme.example.net': { SOA: SOA('acme.example.net'), NS: ['ns1.natrohost.com', 'ns2.natrohost.com'] },
    'alias.acme.example.net': {},
    '_acme-challenge.adns.example.com': { CNAME: `${uuid}.auth.acme-dns.example.net` },
    [`${uuid}.auth.acme-dns.example.net`]: { TXT: ['current-token'] },
    '_acme-challenge.gone.example.com': { CNAME: 'deleted.acme.example.org' }
  });
  const report = await run(zone, ['www.example.com', 'old.example.com', 'alias.example.com', 'adns.example.com', 'gone.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' });
  const [www, old, alias, adns, gone] = report.names;
  assert.equal(sev(www, 'acme.none'), 'ok');
  const left = old.findings.find((f) => f.id === 'acme.leftover');
  assert.deepEqual(left.params, { owner: '_acme-challenge.old.example.com', target: '', count: 2, values: 'tok-1, tok-2' });
  assert.equal(left.severity, 'info');
  assert.deepEqual(alias.acme.cnames, ['alias.acme.example.net']);
  assert.equal(sev(alias, 'acme.cname'), 'info');
  // The TXT record goes into the delegation target's zone: its provider (no API) matters, but the delegation covers it.
  assert.equal(alias.dnsHost.zone, 'acme.example.net');
  assert.deepEqual([alias.findings.find((f) => f.id === 'provider.no-api').severity, alias.findings.find((f) => f.id === 'provider.no-api').params.provider], ['info', 'Natro']);
  assert.equal(sev(adns, 'acme.acme-dns'), 'info');
  assert.ok(adns.acme.acmeDns);
  assert.equal(adns.acme.txt.length, 1, 'acme-dns keeps its last token: not a leftover');
  assert.ok(!ids(adns).includes('acme.leftover'));
  assert.equal(gone.acme.state, 'dangling');
  assert.equal(sev(gone, 'acme.dangling'), 'error');
  assert.equal(gone.dnsHost, null, 'no provider lookup for a target that does not exist');
  assert.equal(gone.verdict, 'fail');
  // For an HTTP-01 renewal the dangling delegation is still a risk (a warning); "nothing there" is not news.
  const http = await run(zone, ['gone.example.com', 'www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' });
  assert.equal(sev(http.names[0], 'acme.dangling'), 'warn');
  assert.ok(!ids(http.names[1]).includes('acme.none'));
});

test('a wildcard is validated with DNS-01 whatever the chosen challenge: its _acme-challenge problems fail it', async () => {
  const zone = exampleZone({
    'example.com': { SOA: SOA('example.com'), NS: ['ns1.natrohost.com', 'ns2.natrohost.com'], CAA: CAA('issue', 'letsencrypt.org') },
    '_acme-challenge.example.com': { CNAME: 'deleted.acme.example.org' },
    '_acme-challenge.shop.example.com': { CNAME: 'x.acme.example.net' },
    'acme.example.net': { SOA: SOA('acme.example.net') },
    'x.acme.example.net': {}
  });
  for (const challenge of ['unknown', 'dns-01', 'http-01']) {
    const r = (await run(zone, ['*.example.com'], { ca: 'letsencrypt', challenge })).names[0];
    assert.equal(sev(r, 'acme.dangling'), 'error', `dangling, ${challenge}`);
    assert.equal(r.verdict, 'fail', challenge);
  }
  // Not sure, and the zone's provider has no API: the wildcard needs it, so a warning (not a note).
  const bare = exampleZone({ 'example.com': { SOA: SOA('example.com'), NS: ['ns1.natrohost.com'], CAA: CAA('issue', 'letsencrypt.org') } });
  let r = (await run(bare, ['*.example.com'], { ca: 'letsencrypt', challenge: 'unknown' })).names[0];
  assert.deepEqual(r.findings.filter((f) => f.severity !== 'ok').map((f) => `${f.id}:${f.severity}`), ['wildcard.unknown:warn', 'provider.no-api:warn']);
  // SERVFAIL and bogus at the delegation target.
  r = (await run(zone, ['*.shop.example.com'], { ca: 'letsencrypt', challenge: 'unknown' }, { fake: { rcodes: { '_acme-challenge.shop.example.com|TXT': 'SERVFAIL' } } })).names[0];
  assert.deepEqual([r.acme.state, sev(r, 'acme.servfail'), r.verdict], ['servfail', 'error', 'fail']);
  r = (await run(zone, ['*.shop.example.com'], { ca: 'letsencrypt', challenge: 'unknown' }, { fake: { broken: ['acme.example.net'] } })).names[0];
  assert.deepEqual([r.acme.state, sev(r, 'acme.bogus'), r.verdict], ['bogus', 'error', 'fail']);
  // A plain name with the challenge not known: the same dangling delegation stays a warning.
  r = (await run(zone, ['example.com'], { ca: 'letsencrypt', challenge: 'unknown' })).names[0];
  assert.equal(sev(r, 'acme.dangling'), 'warn');
  // CAA's validationmethods: for a wildcard only DNS-01 counts, so no "make sure your client uses
  // one of" note — an alternative that leaves DNS-01 out is unusable (lib/health.js), one with it is fine.
  const methods = (value) => exampleZone({ 'example.com': { SOA: SOA('example.com'), NS: ['ada.ns.cloudflare.com'], CAA: CAA('issue', value) } });
  r = (await run(methods('letsencrypt.org; validationmethods=http-01'), ['*.example.com'], { ca: 'letsencrypt', challenge: 'unknown' })).names[0];
  assert.equal(sev(r, 'caa.unusable'), 'error');
  assert.match(r.findings.find((f) => f.id === 'caa.unusable').params.values, /wildcard-method/);
  assert.ok(!ids(r).includes('caa.method-check'));
  r = (await run(methods('letsencrypt.org; validationmethods=dns-01,http-01'), ['*.example.com'], { ca: 'letsencrypt', challenge: 'unknown' })).names[0];
  assert.deepEqual(ids(r).filter((id) => id.startsWith('caa.')), ['caa.restricted'], 'DNS-01 is among the methods');
  r = (await run(methods('letsencrypt.org; validationmethods=dns-01,http-01'), ['example.com'], { ca: 'letsencrypt', challenge: 'unknown' })).names[0];
  assert.equal(sev(r, 'caa.method-check'), 'warn', 'a plain name with the method not known still gets the note');
});

test('_acme-challenge SERVFAIL: bogus (answers with CD) or broken', async () => {
  const zone = exampleZone({ '_acme-challenge.www.example.com': { CNAME: 'x.acme.example.net' }, 'acme.example.net': { SOA: SOA('acme.example.net') }, 'x.acme.example.net': {} });
  let r = (await run(zone, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' }, { fake: { broken: ['acme.example.net'] } })).names[0];
  // The name itself is fine; only the delegation target's zone is bogus.
  assert.equal(r.acme.state, 'bogus');
  assert.equal(r.acme.target, 'x.acme.example.net');
  assert.equal(r.findings.find((f) => f.id === 'acme.bogus').params.ede, '6 DNSSEC Bogus: signature expired');
  assert.equal(r.verdict, 'fail');
  r = (await run(zone, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' }, { fake: { rcodes: { '_acme-challenge.www.example.com|TXT': 'SERVFAIL' } } })).names[0];
  assert.equal(r.acme.state, 'servfail');
  assert.equal(sev(r, 'acme.servfail'), 'error');
});

test('DNSSEC: secure, unsigned, bogus (every lookup fails: said once), servfail without DNSSEC, transport error', async () => {
  let r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' }, { fake: { signed: ['example.com'] } })).names[0];
  assert.equal(r.dnssec.state, 'secure');
  r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' })).names[0];
  assert.equal(r.dnssec.state, 'unsigned');
  r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' }, { fake: { broken: ['example.com'] } })).names[0];
  assert.equal(r.dnssec.state, 'bogus');
  assert.deepEqual(r.dnssec.ede, ['6 DNSSEC Bogus: signature expired']);
  assert.equal(sev(r, 'dnssec.bogus'), 'error');
  assert.equal(sev(r, 'caa.servfail'), 'error', 'the CAA lookup fails too');
  assert.ok(!ids(r).includes('http.error'), 'the address lookup failure is the same cause: not said twice');
  assert.equal(r.verdict, 'fail');
  r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' }, { fake: { rcodes: { 'www.example.com|SOA': 'SERVFAIL' } } })).names[0];
  assert.equal(r.dnssec.state, 'servfail');
  assert.equal(r.findings.find((f) => f.id === 'dnssec.servfail').params.rcode, 'SERVFAIL');
  r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'http-01' }, { fake: { fail: { 'www.example.com|SOA': 'Failed to fetch' } } })).names[0];
  assert.equal(sev(r, 'dnssec.error'), 'warn');
});

test('HTTP-01 / TLS-ALPN-01 prerequisites: private, some private, none, NXDOMAIN, a dangling CNAME, a CDN', async () => {
  const zone = exampleZone({
    'intra.example.com': { A: '10.0.0.5' },
    'mixed.example.com': { A: ['203.0.113.13', '192.168.1.13'] },
    'noaddr.example.com': { MX: { preference: 10, exchange: 'mail.example.com' } },
    'lost.example.com': { CNAME: 'lost.example.org' },
    'cdn.example.com': { A: '104.16.1.1' }
  });
  const list = ['intra.example.com', 'mixed.example.com', 'noaddr.example.com', 'nothere.example.com', 'lost.example.com', 'cdn.example.com'];
  const http = await run(zone, list, { ca: 'letsencrypt', challenge: 'http-01' });
  const at = (i, id) => http.names[i].findings.find((f) => f.id === id);
  assert.deepEqual([at(0, 'http.private').severity, at(0, 'http.private').params.ips], ['error', '10.0.0.5']);
  assert.deepEqual([at(1, 'http.ok').params.ips, at(1, 'http.private-some').severity, at(1, 'http.private-some').params.ips], ['203.0.113.13', 'warn', '192.168.1.13']);
  assert.equal(at(2, 'http.none').severity, 'error');
  assert.equal(at(3, 'http.nxdomain').severity, 'error');
  assert.deepEqual(at(4, 'http.dangling').params, { name: 'lost.example.com', chain: 'lost.example.org', rcode: 'NXDOMAIN' });
  assert.deepEqual([at(5, 'http.cdn').severity, at(5, 'http.cdn').params.provider], ['info', 'Cloudflare']);
  // The method not known: the same problems are warnings.
  const unknown = await run(zone, list.slice(0, 1), { ca: 'letsencrypt', challenge: 'unknown' });
  assert.equal(sev(unknown.names[0], 'http.private'), 'warn');
  // TLS-ALPN-01 cannot pass a CDN that terminates TLS.
  const alpn = await run(zone, ['cdn.example.com'], { ca: 'letsencrypt', challenge: 'tls-alpn-01' });
  assert.equal(sev(alpn.names[0], 'http.alpn-cdn'), 'error');
  // DNS-01 needs no address at all.
  const dns01 = await run(zone, ['intra.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' });
  assert.equal(dns01.names[0].address, null);
  assert.ok(!dns01.names[0].findings.some((f) => f.area === 'http'));
});

test('DNS provider: several providers, one without an API (not delegated), unknown name servers, a failed NS lookup', async () => {
  const split = exampleZone({ 'example.com': { SOA: SOA('example.com'), NS: ['ada.ns.cloudflare.com', 'ns-1.awsdns-01.org'], CAA: CAA('issue', 'letsencrypt.org') } });
  let r = (await run(split, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.deepEqual([sev(r, 'provider.multiple'), r.findings.find((f) => f.id === 'provider.multiple').params.providers], ['warn', 'Cloudflare, Amazon Route 53']);
  const natro = exampleZone({ 'example.com': { SOA: SOA('example.com'), NS: ['ns1.natrohost.com', 'ns2.natrohost.com'] } });
  r = (await run(natro, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.equal(sev(r, 'provider.no-api'), 'warn');
  assert.equal(r.verdict, 'warnings');
  r = (await run(natro, ['www.example.com'], { ca: 'letsencrypt', challenge: 'unknown' })).names[0];
  assert.equal(sev(r, 'provider.no-api'), 'info', 'the method is not known: only a note');
  const own = exampleZone({ 'example.com': { SOA: SOA('example.com'), NS: ['ns1.example.com', 'ns2.example.com'] } });
  r = (await run(own, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' })).names[0];
  assert.equal(r.findings.find((f) => f.id === 'provider.unknown').params.ns, 'ns1.example.com, ns2.example.com');
  r = (await run(exampleZone(), ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' }, { fake: { fail: { 'example.com|NS': 'Failed to fetch' } } })).names[0];
  assert.equal(sev(r, 'provider.error'), 'info');
});

test('checkRenewal: progress, argument checks, abort', async () => {
  const seen = [];
  const report = await run(exampleZone(), ['www.example.com', 'example.com'], { challenge: 'dns-01' }, { onProgress: (p) => seen.push(p) });
  assert.deepEqual(seen.map((p) => [p.done, p.total]).sort(), [[1, 2], [2, 2]]);
  assert.ok(report.startedAt instanceof Date && report.finishedAt instanceof Date);
  assert.deepEqual(report.resolvers, [...CONSISTENCY_RESOLVERS]);
  await assert.rejects(checkRenewal({ names: [], challenge: 'http-02' }, { dns: fakeDns({}) }), TypeError);
  await assert.rejects(checkRenewal({ names: [], ca: 'nope' }, { dns: fakeDns({}) }), TypeError);
  await assert.rejects(checkRenewal({ names: names('www.example.com') }, { dns: {} }), TypeError);
  const ctl = new AbortController();
  ctl.abort();
  await assert.rejects(checkRenewal({ names: names('www.example.com') }, { dns: fakeDns(exampleZone()), signal: ctl.signal }), { name: 'AbortError' });
  const late = new AbortController();
  const slow = { query: async (...args) => { late.abort(); return fakeDns(exampleZone()).query(...args); } };
  await assert.rejects(checkRenewal({ names: names('www.example.com', 'api.example.com') }, { dns: slow, signal: late.signal }), { name: 'AbortError' });
});

/* ==================================================================== */
/* HTTP-01 reachability                                                  */
/* ==================================================================== */

const PATH = '/.well-known/acme-challenge/ds-fixture-tg6denb8mh';
const res = (extra) => ({ status: 'finished', statusCode: 404, resolvedAddress: '203.0.113.10', headers: {}, ...extra });
const probe = (continent, country) => ({ continent, country, city: null, asn: 64496, network: 'Example Net', tags: ['datacenter-network'] });

test('http01Request: a plain-HTTP GET on port 80 from three continents; the token is checked', () => {
  const body = http01Request('example.com', { token: 'ds-fixture-tg6denb8mh' });
  assert.deepEqual(body, fx('m28-acme-http-404').request);
  assert.deepEqual(http01Request('example.com', { token: 'ds-fixture-tg6denb8mh', ipVersion: 6 }), fx('m30-acme-http-v6').request);
  for (const token of ['', 'a/b', 'a b', 'x'.repeat(65), null]) assert.throws(() => http01Request('example.com', { token }), TypeError, String(token));
  assert.throws(() => http01Request('*.example.com', { token: 'abc' }), TypeError);
  assert.match(http01Token(), /^domainscope-check-[a-z0-9]{16}$/);
  assert.notEqual(http01Token(), http01Token());
});

test('redirectOutcome: what a CA that follows the redirect gets', () => {
  const ctx = { host: 'example.com', path: PATH };
  assert.equal(redirectOutcome(`https://example.com${PATH}`, ctx), 'redirect');
  assert.equal(redirectOutcome(`https://www.example.com:443${PATH}`, ctx), 'redirect');
  assert.equal(redirectOutcome(`/en${PATH}`, ctx), 'redirect', 'a relative Location keeping the token');
  assert.equal(redirectOutcome(`http://example.com${PATH}`, ctx), 'redirect-loop');
  assert.equal(redirectOutcome(`https://example.com:8443${PATH}`, ctx), 'redirect-port');
  assert.equal(redirectOutcome(`https://192.0.2.10${PATH}`, ctx), 'redirect-ip');
  assert.equal(redirectOutcome(`https://[2001:db8::10]${PATH}`, ctx), 'redirect-ip');
  assert.equal(redirectOutcome('https://example.com/', ctx), 'redirect-path');
  assert.equal(redirectOutcome(`ftp://example.com${PATH}`, ctx), 'redirect-scheme');
  assert.equal(redirectOutcome(null, ctx), 'redirect-none');
  assert.equal(redirectOutcome('http://[bad', ctx), 'redirect-none');
});

test('http01Outcome: statuses and probe-side failures', () => {
  const ctx = { host: 'example.com', path: PATH };
  const o = (r) => http01Outcome(r, ctx).outcome;
  assert.equal(o(res({})), 'not-found');
  assert.equal(o(res({ statusCode: 410 })), 'not-found');
  assert.equal(o(res({ statusCode: 200 })), 'catch-all');
  assert.equal(o(res({ statusCode: 403 })), 'forbidden');
  assert.equal(o(res({ statusCode: 401 })), 'forbidden');
  assert.equal(o(res({ statusCode: 503 })), 'server-error');
  assert.equal(o(res({ statusCode: 421 })), 'status');
  assert.equal(o(res({ statusCode: 301, headers: { Location: [`https://example.com${PATH}`] } })), 'redirect');
  assert.equal(o(res({ statusCode: 302 })), 'redirect-none');
  const failed = (rawOutput, extra = {}) => ({ status: 'failed', statusCode: null, resolvedAddress: null, rawOutput, ...extra });
  assert.equal(o(failed('Request timed out while establishing the TCP connection.')), 'timeout');
  assert.equal(o(failed('Request timed out.')), 'timeout');
  assert.equal(o(failed('connect ECONNREFUSED 203.0.113.10:80')), 'refused');
  assert.equal(o(failed('queryA ENODATA example.com')), 'dns');
  assert.equal(o(failed('connect ENETUNREACH 2001:db8::10:80')), 'unreachable');
  assert.equal(o(failed('Private IP ranges are not allowed.')), 'private');
  assert.equal(o(failed('read ECONNRESET')), 'reset');
  assert.equal(o(failed('', { failureSource: 'internal' })), 'probe');
  assert.equal(o({ status: 'offline' }), 'probe');
  assert.equal(o(failed('something else')), 'unknown');
  const r = http01Outcome(failed('connect ECONNREFUSED 203.0.113.10:80'), ctx);
  assert.deepEqual([r.status, r.location, r.failure], [null, null, 'connect ECONNREFUSED 203.0.113.10:80']);
});

test('http01Verdict: ok, catch-all, partial, failed, inconclusive', () => {
  const v = (...outcomes) => http01Verdict(outcomes.map((outcome) => ({ outcome })));
  assert.equal(v('not-found', 'redirect', 'not-found'), 'ok');
  assert.equal(v('not-found', 'probe'), 'ok', 'a probe problem is not counted');
  assert.equal(v('catch-all', 'catch-all', 'not-found'), 'catch-all');
  assert.equal(v('not-found', 'timeout', 'not-found'), 'partial');
  assert.equal(v('catch-all', 'refused'), 'partial');
  assert.equal(v('timeout', 'refused', 'forbidden'), 'failed');
  assert.equal(v('probe', 'probe'), 'inconclusive');
  assert.equal(v(), 'inconclusive');
});

test('interpretHttp01: the live fixtures (404 everywhere; a redirect to HTTPS keeping the token; IPv6)', () => {
  const m28 = interpretHttp01(fx('m28-acme-http-404').final.body, { host: 'example.com', path: PATH });
  assert.equal(m28.verdict, 'ok');
  assert.equal(m28.ipVersion, 4);
  assert.equal(m28.measurementId, '2VxnLwVQJ9HR4iB2M00021DR4');
  assert.deepEqual(m28.probes.map((p) => [p.outcome, p.status, p.place]), [['not-found', 404, 'Helsinki, FI'], ['not-found', 404, 'Buffalo, US'], ['not-found', 404, 'Tokyo, JP']]);
  assert.equal(m28.probes[0].probe.latitude, undefined, 'no coordinates kept');
  const m29 = interpretHttp01(fx('m29-acme-http-redirect').final.body, { host: 'example.net', path: PATH });
  assert.equal(m29.verdict, 'ok');
  assert.deepEqual(m29.probes.map((p) => p.outcome), ['redirect', 'redirect', 'redirect']);
  assert.equal(m29.probes[0].location, `https://example.net${PATH}`);
  const m30 = interpretHttp01(fx('m30-acme-http-v6').final.body, { host: 'example.com', path: PATH, ipVersion: 6 });
  assert.equal(m30.ipVersion, 6);
  assert.ok(m30.probes.every((p) => p.address.includes(':')));
  assert.deepEqual(interpretHttp01(null, { host: 'example.com', path: PATH }).probes, []);
});

test('http01Findings + applyHttp01: a failed test fails an HTTP-01 renewal, warns when the method is not known', async () => {
  const report = await run(exampleZone(), ['www.example.com', 'example.com'], { ca: 'letsencrypt', challenge: 'http-01' });
  assert.equal(report.names[0].verdict, 'ready');
  const ok = { at: new Date(), families: [interpretHttp01(fx('m28-acme-http-404').final.body, { host: 'www.example.com', path: PATH })] };
  let next = applyHttp01(report, 'www.example.com', ok);
  assert.notEqual(next, report);
  assert.equal(report.names[0].http01, null, 'the given report is not changed');
  const okF = next.names[0].findings.find((f) => f.id === 'http01.ok');
  assert.deepEqual(okF.params, { name: 'www.example.com', family: 'IPv4', answers: '404', count: 3, places: 'Helsinki, FI; Buffalo, US; Tokyo, JP' });
  assert.equal(next.names[0].findings[next.names[0].findings.length - 1].id, 'http01.ok', 'reachability comes last');
  assert.equal(next.names[1], report.names[1], 'other names are untouched');
  const redirect = { at: new Date(), families: [interpretHttp01(fx('m29-acme-http-redirect').final.body, { host: 'www.example.com', path: PATH })] };
  assert.equal(applyHttp01(report, 'www.example.com', redirect).names[0].findings.find((f) => f.id === 'http01.redirect').params.location, `https://example.net${PATH}`);
  const failedFam = interpretHttp01({ id: 'x1234567', results: [
    { probe: probe('EU', 'DE'), result: { status: 'failed', rawOutput: 'Request timed out while establishing the TCP connection.' } },
    { probe: probe('NA', 'US'), result: { status: 'failed', rawOutput: 'connect ECONNREFUSED 2001:db8::10:80' } }
  ] }, { host: 'www.example.com', path: PATH, ipVersion: 6 });
  next = applyHttp01(report, 'www.example.com', { at: new Date(), families: [ok.families[0], failedFam] });
  const f = next.names[0].findings.find((x) => x.id === 'http01.failed');
  assert.deepEqual([f.severity, f.params.family, f.params.outcomes], ['error', 'IPv6', 'timeout, refused']);
  assert.equal(next.names[0].verdict, 'fail');
  assert.equal(applyHttp01(next, 'www.example.com', null).names[0].verdict, 'ready', 'removing the test restores the verdict');
  // Partial, catch-all and inconclusive families.
  const fam = (...results) => ({ ipVersion: 4, verdict: http01Verdict(results.map((outcome) => ({ outcome }))), probes: results.map((outcome, i) => ({ outcome, status: outcome === 'catch-all' ? 200 : null, place: `P${i}` })) });
  const find = (families, challenge = 'http-01') => http01Findings({ families }, { challenge, name: 'www.example.com' }).map((x) => [x.id, x.severity]);
  assert.deepEqual(find([fam('not-found', 'timeout')]), [['http01.partial', 'warn']]);
  assert.deepEqual(find([fam('catch-all', 'catch-all')]), [['http01.catch-all', 'warn']]);
  assert.deepEqual(find([fam('probe')]), [['http01.inconclusive', 'info']]);
  assert.deepEqual(find([fam('timeout')], 'unknown'), [['http01.failed', 'warn']]);
  assert.equal(http01Findings({ families: [fam('not-found', 'timeout')] }, { challenge: 'http-01', name: 'x' })[0].params.places, 'P1');
  assert.deepEqual(http01Findings(null, { challenge: 'http-01', name: 'x' }), []);
});

test('http01Plan: which names can be tested, over which families', async () => {
  const zone = exampleZone({ 'intra.example.com': { A: '10.0.0.5' }, 'v6.example.com': { AAAA: '2001:db8::66' } });
  const report = await run(zone, ['www.example.com', 'intra.example.com', 'v6.example.com', '*.example.com'], { ca: 'letsencrypt', challenge: 'http-01' });
  assert.deepEqual(report.names.map(http01Plan), [
    { ok: true, families: [4, 6] }, { ok: false, families: [] }, { ok: true, families: [6] }, { ok: false, families: [] }
  ]);
  const dns01 = await run(zone, ['www.example.com'], { ca: 'letsencrypt', challenge: 'dns-01' });
  assert.equal(http01Plan(dns01.names[0]).ok, false, 'no address lookup, no test');
  assert.equal(http01Plan(null).ok, false);
});

/* ==================================================================== */
/* Verdicts, summary, exports, texts                                     */
/* ==================================================================== */

test('nameVerdict / nameFindings: worst severity wins; findings in area order', () => {
  assert.equal(nameVerdict([{ severity: 'ok' }, { severity: 'info' }]), 'ready');
  assert.equal(nameVerdict([{ severity: 'warn' }, { severity: 'info' }]), 'warnings');
  assert.equal(nameVerdict([{ severity: 'warn' }, { severity: 'error' }]), 'fail');
  assert.equal(nameVerdict([]), 'ready');
  const r = {
    name: 'www.example.com', base: 'www.example.com', wildcard: false, caa: null, resolvers: [],
    dnssec: { state: 'unsigned', zone: 'example.com', ede: [] }, acme: null, address: null, dnsHost: null, http01: null
  };
  assert.deepEqual(nameFindings(r, { ca: null, challenge: 'http-01' }).map((f) => f.id), ['dnssec.unsigned']);
});

test('renewalSummary, renewalRows (CSV) and renewalExport (JSON)', async () => {
  const zone = exampleZone({ 'intra.example.com': { A: '10.0.0.5' }, 'example.com': { SOA: SOA('example.com'), NS: ['ns1.natrohost.com'], CAA: CAA('issue', 'letsencrypt.org') } });
  const report = await run(zone, ['www.example.com', 'intra.example.com', '*.example.com'], { ca: 'letsencrypt', challenge: 'unknown' });
  const s = renewalSummary(report);
  assert.deepEqual(s, { total: 3, counts: { ready: 1, warnings: 2, fail: 0 }, headline: 'warnings', tested: 0 });
  assert.equal(renewalSummary({ names: [] }).headline, 'none');
  const rows = renewalRows(report);
  assert.deepEqual(Object.keys(rows[0]), [...RENEWAL_CSV_COLUMNS]);
  assert.deepEqual([rows[0].name, rows[0].verdict, rows[0].caa_at, rows[0].resolvers, rows[0].dnssec, rows[0].dns_provider], ['www.example.com', 'ready', 'example.com', 'agree (4)', 'unsigned', 'Natro']);
  assert.equal(rows[1].addresses, '10.0.0.5');
  assert.match(rows[1].warnings, /http\.private/);
  const csv = toCsv(rows, RENEWAL_CSV_COLUMNS.map((key) => ({ key, header: key })));
  assert.match(csv, /^﻿name,verdict,caa_at/);
  const json = renewalExport(report, { version: '1.0.0' });
  assert.equal(json.schema, 'domainscope.renewal/1');
  assert.deepEqual(json.ca, { id: 'letsencrypt', name: "Let's Encrypt", caa: ['letsencrypt.org'] });
  assert.deepEqual(json.summary, { total: 3, ready: 1, warnings: 2, fail: 0, headline: 'warnings' });
  assert.equal(json.names[2].wildcard, true);
  assert.equal(json.names[0].caa.records[0], '0 issue "letsencrypt.org"');
  assert.equal(json.names[0].dnsProvider.providers[0].id, 'natro');
  assert.equal(typeof json.startedAt, 'string');
  const round = JSON.parse(toJson(json));
  assert.equal(round.names.length, 3);
  assert.ok(!('parsed' in round.names[0].caa), 'parsed CAA objects stay out');
  // A tested name carries its probes, never coordinates.
  const tested = applyHttp01(report, 'www.example.com', { at: new Date(0), families: [interpretHttp01(fx('m28-acme-http-404').final.body, { host: 'www.example.com', path: PATH })] });
  const ex = renewalExport(tested);
  assert.deepEqual(ex.names[0].http01.families[0].probes[0], { place: 'Helsinki, FI', network: 'Hetzner Online', outcome: 'not-found', status: 404, location: null, address: '104.20.23.154', failure: null });
  assert.equal(ex.names[0].http01.at, '1970-01-01T00:00:00.000Z');
  assert.equal(renewalRows(tested)[0].http01, 'IPv4 ok');
  assert.equal(renewalSummary(tested).tested, 1);
});

test('RENEWAL_I18N: every finding, outcome, verdict, headline, challenge and area in both languages, same placeholders', () => {
  const ph = (v) => {
    const s = typeof v === 'string' ? v : v.other;
    return [...new Set([...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]))].sort().join(',');
  };
  const keys = [
    ...RENEWAL_FINDINGS.flatMap((id) => [`renew.f.${id}.title`, `renew.f.${id}.detail`]),
    ...HTTP01_OUTCOMES.map((o) => `renew.o.${o}`),
    ...RENEWAL_VERDICTS.map((v) => `renew.v.${v}`),
    ...['fail', 'warnings', 'ready', 'none'].map((x) => `renew.head.${x}`),
    ...RENEWAL_CHALLENGES.map((c) => `renew.ch.${c}`),
    ...RENEWAL_AREAS.map((a) => `renew.area.${a}`)
  ];
  for (const k of keys) {
    assert.ok(RENEWAL_I18N.en[k], `en ${k}`);
    assert.ok(RENEWAL_I18N.tr[k], `tr ${k}`);
    assert.equal(ph(RENEWAL_I18N.en[k]), ph(RENEWAL_I18N.tr[k]), k);
  }
  assert.deepEqual(Object.keys(RENEWAL_I18N.en).sort(), [...keys].sort(), 'no stray key');
  assert.deepEqual(Object.keys(RENEWAL_I18N.tr).sort(), [...keys].sort());
});
