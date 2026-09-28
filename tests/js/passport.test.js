/**
 * lib/passport.js — the Domain overview's lookups, cards, tables and CT issuers.
 * No network: a table-driven fake DoH client (DohClient contract, answers built from real wire
 * records) and a fake fetch for RDAP, Cert Spotter and crt.sh.
 */
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  PASSPORT_CARDS, PASSPORT_LOOKUPS, CARD_LOOKUPS, HEALTH_LOOKUPS, LOOKUP_SOURCES, DNS_PROVIDERS, MAIL_PLATFORMS, TXT_VENDORS, REGISTRY_WHOIS,
  passportDomain, dnsProviderOf, dnsHosting, mailPlatformOf, spfSenders, txtVendorOf, saasFingerprints, registryWhois,
  rdapStatusFlags, serialDate, lookupStatus, passportCards, cardsOfLookup, passportDns, runLookup, buildPassport,
  registrationCard, dnsCard, mailCard, webCard, certsCard, saasCard, healthCard,
  certspotterIssuersUrl, crtshIssuersUrl, issuersFromCertspotter, issuersFromCrtsh, lookupCtIssuers, passportSummaryFacts
} from '../../assets/js/lib/passport.js';
import { domainHealth } from '../../assets/js/lib/health.js';
import { clearRdapCache } from '../../assets/js/lib/rdap.js';
import { createCtCooldown, CT_COOLDOWN_MS } from '../../assets/js/lib/ctcert.js';
import { healthScore } from '../../assets/js/lib/summary.js';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';

const NOW = new Date('2026-09-28T12:00:00Z');
const CF_EDGE = '104.16.1.1';

/* ------------------------------------------------------------------------ */
/* Fakes                                                                     */
/* ------------------------------------------------------------------------ */

/** Real decoded RR objects (the shapes DohClient answers carry). */
function rrs(list) {
  if (!list.length) return [];
  return decodeMessage(encodeMessage({ answers: list.map((r) => ({ ttl: 300, ...r })) })).answers;
}

const asList = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

/**
 * A zone map { name: { TYPE: value | value[], CNAME: target } } with DohClient semantics:
 * CNAME chains, NXDOMAIN outside the map, the AD flag under `signed`, a transport failure per
 * `fail['name|TYPE']` and a forced rcode per `rcodes['name|TYPE']`. `calls` records every query
 * with its options.
 */
function fakeDns(zone, { signed = [], fail = {}, rcodes = {}, delayMs = 0 } = {}) {
  const calls = [];
  const under = (name, list) => list.some((z) => name === z || name.endsWith(`.${z}`));
  const base = (name, type, extra) => ({
    name, type, resolver: 'fake', ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: false, cd: false },
    answers: [], authorities: [], ede: [], elapsedMs: 1, error: null, errorKind: null, ...extra
  });
  async function query(qname, type = 'A', { dnssec = false, cd = false, signal, noCache = false } = {}) {
    throwIfAborted(signal);
    if (delayMs) {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, delayMs);
        signal?.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
      });
    }
    const name = String(qname).toLowerCase().replace(/\.$/, '');
    calls.push({ name, type, dnssec, cd, noCache });
    const f = fail[`${name}|${type}`];
    if (f) return base(name, type, { ok: false, rcode: null, flags: null, error: f, errorKind: /429/.test(f) ? 'rate-limit' : 'network' });
    if (rcodes[`${name}|${type}`]) return base(name, type, { rcode: rcodes[`${name}|${type}`] });
    const answers = [];
    let cur = name;
    let rcode = 'NOERROR';
    for (let i = 0; i < 12; i += 1) {
      const node = zone[cur];
      if (!node) {
        rcode = 'NXDOMAIN';
        break;
      }
      if (node.CNAME && type !== 'CNAME') {
        answers.push({ name: cur, type: 'CNAME', data: node.CNAME });
        cur = node.CNAME;
        continue;
      }
      for (const data of asList(node[type])) answers.push({ name: cur, type, data: type === 'TXT' && typeof data === 'string' ? [data] : data });
      break;
    }
    const res = base(name, type, { rcode, answers: rrs(answers) });
    res.flags = { ...res.flags, ad: under(cur, signed) && !cd };
    return res;
  }
  return { calls, query };
}

const json = (value, { status = 200, headers = {} } = {}) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...headers } });

const RDAP_BASE = 'https://rdap.example.net/';
/** An RDAP registry answer for `domain` (fictional registrar; the RFC 8056 status wording). */
function rdapJson(domain, { status = ['client transfer prohibited', 'client delete prohibited'], expires = '2027-08-13T04:00:00Z', ns = [] } = {}) {
  return {
    objectClassName: 'domain',
    ldhName: domain.toUpperCase(),
    status,
    events: [
      { eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' },
      { eventAction: 'expiration', eventDate: expires },
      { eventAction: 'last changed', eventDate: '2026-08-14T07:01:34Z' }
    ],
    entities: [{
      objectClassName: 'entity', roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar, Inc.']]],
      publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }]
    }],
    nameservers: ns.map((n) => ({ objectClassName: 'nameserver', ldhName: n.toUpperCase() })),
    secureDNS: { delegationSigned: true }
  };
}

/**
 * fetch for RDAP (a bootstrap naming .com / .net / .org, no .tr), Cert Spotter and crt.sh.
 * `routes` override per service: rdap(url, n) / spotter(url, n) / crtsh(url, n) → Response.
 */
function mockFetch(routes = {}) {
  const log = [];
  const count = { rdap: 0, spotter: 0, crtsh: 0 };
  const impl = async (url, init = {}) => {
    const u = String(url);
    log.push(u);
    if (init.signal && init.signal.aborted) throw init.signal.reason;
    if (u.startsWith('https://data.iana.org/rdap/dns.json')) return json({ services: [[['com', 'net', 'org'], [RDAP_BASE]]] });
    if (u.startsWith(RDAP_BASE)) return routes.rdap ? routes.rdap(u, count.rdap++) : json(rdapJson(decodeURIComponent(u.split('/domain/')[1])));
    if (u.startsWith('https://api.certspotter.com/')) return routes.spotter ? routes.spotter(u, count.spotter++) : json([]);
    if (u.startsWith('https://crt.sh/')) return routes.crtsh ? routes.crtsh(u, count.crtsh++) : json([]);
    // rdap.org (the fallback) answers what the registry answers: it redirects there.
    if (u.startsWith('https://rdap.org/')) return routes.rdap ? routes.rdap(u, count.rdap++) : json({ errorCode: 404 }, { status: 404 });
    throw new TypeError(`unexpected fetch ${u}`);
  };
  return Object.assign(impl, { log, count });
}

const KSK = { flags: 257, protocol: 3, algorithm: 13, publicKey: Buffer.alloc(64, 7).toString('base64') };

/** A domain on Cloudflare DNS, mail at Microsoft 365, www an alias of the apex, SaaS tokens. */
function zoneOf(domain = 'example.com') {
  return {
    [domain]: {
      SOA: { mname: 'adam.ns.cloudflare.com', rname: 'dns.cloudflare.com', serial: 2026092801, refresh: 10000, retry: 2400, expire: 604800, minimum: 1800 },
      NS: ['adam.ns.cloudflare.com', 'bella.ns.cloudflare.com'],
      A: [CF_EDGE],
      MX: [{ preference: 0, exchange: `${domain.replace(/\./g, '-')}.mail.protection.outlook.com` }],
      TXT: [
        'v=spf1 include:spf.protection.outlook.com include:sendgrid.net -all',
        'google-site-verification=TOKENVALUEgoogle123',
        'google-site-verification=TOKENVALUEgoogle456',
        'MS=ms12345678',
        'atlassian-domain-verification=TOKENVALUEatlassian',
        'stripe-verification=0123456789abcdef',
        'some-unknown-thing=zzz'
      ],
      CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'iodef', value: `mailto:security@${domain}` }],
      DS: [{ keyTag: 2371, algorithm: 13, digestType: 2, digest: 'ab'.repeat(32) }],
      DNSKEY: [KSK],
      HTTPS: [{ priority: 1, target: '.', params: { alpn: ['h3', 'h2'] } }]
    },
    [`www.${domain}`]: { CNAME: domain },
    [`_dmarc.${domain}`]: { TXT: [`v=DMARC1; p=reject; rua=mailto:dmarc@${domain}`] },
    [`${domain.replace(/\./g, '-')}.mail.protection.outlook.com`]: { A: ['198.51.100.25'] },
    'adam.ns.cloudflare.com': { A: ['198.51.100.53'] },
    'bella.ns.cloudflare.com': { A: ['198.51.100.54'] }
  };
}

beforeEach(() => clearRdapCache());

/* ------------------------------------------------------------------------ */
/* Tables and names                                                          */
/* ------------------------------------------------------------------------ */

describe('names and tables', () => {
  test('passportDomain: the registrable domain of a host, URL or wildcard; IPs, suffixes and junk are refused', () => {
    assert.deepEqual(passportDomain('example.com'), { domain: 'example.com', host: null });
    assert.deepEqual(passportDomain('https://WWW.Example.COM/login?x=1'), { domain: 'example.com', host: 'www.example.com' });
    assert.deepEqual(passportDomain('*.shop.example.co.uk'), { domain: 'example.co.uk', host: 'shop.example.co.uk' });
    assert.deepEqual(passportDomain('mail.example-test.com.tr.'), { domain: 'example-test.com.tr', host: 'mail.example-test.com.tr' });
    assert.deepEqual(passportDomain('bücher.example'), { domain: 'xn--bcher-kva.example', host: null });
    for (const bad of ['', '   ', '192.0.2.1', '[2001:db8::1]', '2001:db8::1', 'com', 'com.tr', 'co.uk', 'not a domain', 'localhost']) {
      assert.equal(passportDomain(bad), null, bad);
    }
  });

  test('the tables are frozen, their ids unique, their patterns anchored', () => {
    for (const [table, key] of [[DNS_PROVIDERS, 'id'], [MAIL_PLATFORMS, 'id'], [TXT_VENDORS, 'id']]) {
      assert.ok(Object.isFrozen(table) && table.every(Object.isFrozen));
      const ids = table.map((x) => x[key]);
      assert.equal(new Set(ids).size, ids.length, 'unique ids');
    }
    for (const v of TXT_VENDORS) {
      assert.ok(v.re.source.startsWith('^'), `${v.id}: anchored at the start`);
      assert.ok(v.name && v.key && !/[=:]\S/.test(v.key), `${v.id}: a display key, never a token`);
    }
    for (const p of DNS_PROVIDERS) assert.ok((p.suffixes || []).length || (p.patterns || []).length, p.id);
    for (const p of MAIL_PLATFORMS) {
      assert.ok(['mailbox', 'gateway', 'forwarding', 'sending'].includes(p.kind), p.id);
      assert.ok((p.mx || []).length || (p.mxPatterns || []).length || (p.spf || []).length, p.id);
    }
    assert.deepEqual(PASSPORT_CARDS, ['registration', 'dns', 'mail', 'web', 'certs', 'saas', 'health']);
    for (const lookups of Object.values(CARD_LOOKUPS)) for (const l of lookups) assert.ok(PASSPORT_LOOKUPS.includes(l), l);
    assert.deepEqual(new Set(Object.values(LOOKUP_SOURCES)), new Set(['rdap', 'doh']));
    // What the health run asks too: the apex's own questions, never RDAP, www or itself.
    assert.ok(HEALTH_LOOKUPS.every((l) => PASSPORT_LOOKUPS.includes(l)));
    for (const l of ['rdap', 'www', 'wwwHttps', 'health']) assert.ok(!HEALTH_LOOKUPS.includes(l), l);
  });

  test('DNS providers: every suffix entry matches on a label boundary; pattern providers; own name servers', () => {
    for (const p of DNS_PROVIDERS) {
      for (const s of p.suffixes || []) {
        assert.equal(dnsProviderOf(`ns1.${s}`)?.id, p.id, s);
        assert.equal(dnsProviderOf(`ns1.${s}.example.net`), null, `${s} inside another name`);
        assert.equal(dnsProviderOf(`ns1.x${s}`), null, `x${s} is another domain`);
      }
    }
    assert.equal(dnsProviderOf('NS-1447.AWSDNS-52.ORG.')?.id, 'route53');
    assert.equal(dnsProviderOf('ns-1707.awsdns-21.co.uk')?.id, 'route53');
    assert.equal(dnsProviderOf('ns1-39.azure-dns.com')?.id, 'azure');
    assert.equal(dnsProviderOf('ns4-39.azure-dns.info')?.id, 'azure');
    assert.equal(dnsProviderOf('ns-cloud-a1.googledomains.com')?.id, 'google-cloud');
    assert.equal(dnsProviderOf('ns1.googledomains.com'), null, 'Google Domains is not Cloud DNS');
    assert.equal(dnsProviderOf('dns1.p06.nsone.net')?.id, 'ns1');
    assert.deepEqual(dnsProviderOf('ns1.example.com', { domain: 'example.com' }), { id: 'self', name: null });
    assert.equal(dnsProviderOf('ns1.example.com'), null, 'unknown without the domain');
    const h = dnsHosting(['bella.ns.cloudflare.com', 'ns-1.awsdns-01.com', 'adam.ns.cloudflare.com.', 'ns1.example.com', 'ns.example.org', 'ns.example.org'], { domain: 'example.com' });
    assert.deepEqual(h, {
      providers: [{ id: 'cloudflare', name: 'Cloudflare', hosts: ['bella.ns.cloudflare.com', 'adam.ns.cloudflare.com'] }, { id: 'route53', name: 'Amazon Route 53', hosts: ['ns-1.awsdns-01.com'] }],
      self: ['ns1.example.com'],
      other: ['ns.example.org']
    });
  });

  test('mail platforms by MX host, including the Turkish providers; consumer Gmail is not Workspace', () => {
    assert.equal(mailPlatformOf('example-com.mail.protection.outlook.com.')?.id, 'microsoft365');
    assert.equal(mailPlatformOf('example-com.o-v1.mx.microsoft')?.id, 'microsoft365');
    assert.equal(mailPlatformOf('ALT1.ASPMX.L.GOOGLE.COM')?.id, 'google');
    assert.equal(mailPlatformOf('aspmx2.googlemail.com')?.id, 'google');
    assert.equal(mailPlatformOf('gmail-smtp-in.l.google.com'), null);
    assert.equal(mailPlatformOf('mx.yaanimail.com')?.id, 'yaani');
    assert.equal(mailPlatformOf('cmx.yaanimail.com')?.name, 'Yaani Mail (Turkcell)');
    assert.equal(mailPlatformOf('mx.turktelekomeposta.com')?.id, 'turktelekom');
    assert.equal(mailPlatformOf('mx.yandex.net')?.id, 'yandex');
    assert.equal(mailPlatformOf('mxa-00148501.gslb.pphosted.com')?.kind, 'gateway');
    assert.equal(mailPlatformOf('eu-smtp-inbound-1.mimecast.com')?.id, 'mimecast');
    assert.equal(mailPlatformOf('inbound-smtp.eu-west-1.amazonaws.com')?.id, 'amazonses');
    assert.equal(mailPlatformOf('route1.mx.cloudflare.net')?.kind, 'forwarding');
    assert.equal(mailPlatformOf('mail.example.com'), null);
    assert.equal(mailPlatformOf(''), null);
  });

  test('spfSenders: includes and the redirect by platform, a macro include by its suffix, the rest as written', () => {
    const r = spfSenders('v=spf1 include:spf.protection.outlook.com include:_spf.google.com include:%{ir}.%{v}.%{d}.spf.has.pphosted.com include:eu._netblocks.mimecast.com include:spf.example.net include:SPF.PROTECTION.OUTLOOK.COM ~all');
    assert.deepEqual(r.senders.map((s) => s.id), ['microsoft365', 'google', 'proofpoint', 'mimecast']);
    assert.deepEqual(r.other, ['spf.example.net']);
    assert.deepEqual(spfSenders('v=spf1 redirect=_spf.yandex.net').senders.map((s) => s.id), ['yandex']);
    assert.deepEqual(spfSenders('not spf'), { senders: [], other: [] });
  });

  test('TXT vendors: anchored prefixes, the documented keys, never a token', () => {
    const cases = {
      'google-site-verification=abc': 'google',
      'MS=ms12345678': 'microsoft',
      'MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805': 'microsoft',
      'facebook-domain-verification=abc': 'facebook',
      'atlassian-domain-verification=abc/def+': 'atlassian',
      'apple-domain-verification=abc': 'apple',
      'docusign=087098e3-3d46-47b7-9b4e-8a23028154cd': 'docusign',
      'stripe-verification=abc': 'stripe',
      'ZOOM_verify_abc': 'zoom',
      'zoom-domain-verification=ZOOM_verify_abc': 'zoom',
      'adobe-idp-site-verification=abc': 'adobe',
      'hubspot-developer-verification=abc': 'hubspot',
      'hubspot-domain-verification=abc': 'hubspot',
      'anthropic-domain-verification-4az7qn=abc': 'anthropic',
      'openai-domain-verification=dv-abc': 'openai',
      'TAILSCALE-abc': 'tailscale',
      'yandex-verification: 1234abcd': 'yandex',
      '_globalsign-domain-verification=abc': 'globalsign',
      'webexdomainverification.ABC=uuid': 'webex',
      'OSSRH-53577': 'sonatype',
      'pardot_84442_*=abc': 'pardot',
      'pardot548382=abc': 'pardot'
    };
    for (const [record, id] of Object.entries(cases)) assert.equal(txtVendorOf(record)?.id, id, record);
    assert.equal(txtVendorOf(['google-site-verification=', 'abc'])?.id, 'google', 'split character-strings');
    for (const not of ['x google-site-verification=abc', 'ms=lowercase-is-not-microsoft', 'MSabc', 'v=spf1 -all', 'hello', '']) assert.equal(txtVendorOf(not), null, not);
    const hit = txtVendorOf('google-site-verification=SECRETTOKEN');
    assert.deepEqual(hit, { id: 'google', name: 'Google', key: 'google-site-verification' });
  });

  test('saasFingerprints: one entry per vendor, most records first; policy records apart; no token anywhere', () => {
    const r = saasFingerprints([
      'v=spf1 -all', 'v=DMARC1; p=none', ['google-site-verification=TOKEN1'], 'google-site-verification=TOKEN2', 'stripe-verification=TOKEN3',
      'atlassian-domain-verification=TOKEN4', 'something-else', 'v=STSv1; id=1'
    ]);
    assert.deepEqual(r.vendors.map((v) => [v.id, v.count]), [['google', 2], ['atlassian', 1], ['stripe', 1]]);
    assert.deepEqual([r.other, r.policy, r.total], [1, 3, 8]);
    assert.doesNotMatch(JSON.stringify(r), /TOKEN/);
    assert.deepEqual(saasFingerprints(null), { vendors: [], other: 0, policy: 0, total: 0 });
  });

  test('registryWhois: the registry of .tr / .de / .jp / .ch, IANA for any other TLD', () => {
    assert.deepEqual(registryWhois('tr', 'example.com.tr'), { name: 'TRABİS', url: 'https://www.trabis.gov.tr/whois', iana: false });
    assert.deepEqual(registryWhois('DE', 'example.de'), { name: 'DENIC', url: 'https://webwhois.denic.de/?lang=en&query=example.de', iana: false });
    assert.equal(registryWhois('de', 'a&b.de').url, 'https://webwhois.denic.de/?lang=en&query=a%26b.de', 'the domain is URL-encoded');
    assert.equal(registryWhois('jp').name, 'JPRS');
    assert.deepEqual(registryWhois('es'), { name: null, url: 'https://www.iana.org/domains/root/db/es.html', iana: true });
    assert.equal(registryWhois('xn--p1ai').url, 'https://www.iana.org/domains/root/db/xn--p1ai.html');
    for (const bad of ['', 'a', 'x/y', '../tr', null]) assert.equal(registryWhois(bad), null, String(bad));
    assert.ok(Object.values(REGISTRY_WHOIS).every((w) => w.url.startsWith('https://')));
  });

  test('rdapStatusFlags: holds and pending deletes first, then locks; serialDate reads YYYYMMDDnn only', () => {
    assert.deepEqual(rdapStatusFlags(['client transfer prohibited', 'active', 'client hold', 'pending delete', 'client transfer prohibited', 'renew period']),
      [{ code: 'client hold', kind: 'hold' }, { code: 'pending delete', kind: 'pending' }, { code: 'client transfer prohibited', kind: 'lock' },
        { code: 'active', kind: 'ok' }, { code: 'renew period', kind: 'other' }]);
    assert.equal(serialDate(2026092801), '2026-09-28');
    assert.equal(serialDate('1999123199'), '1999-12-31');
    for (const bad of [1, 2350000000, 2026023101, 2026130101, 1989010101, '20260928', null, 'x']) assert.equal(serialDate(bad), null, String(bad));
  });

  test('lookupStatus: a failed query, an error rcode, a failed RDAP lookup or host; never for an answer', () => {
    assert.equal(lookupStatus({ ok: true, rcode: 'NOERROR', answers: [] }), null);
    assert.equal(lookupStatus({ ok: true, rcode: 'NXDOMAIN', answers: [] }), null);
    assert.deepEqual(lookupStatus({ ok: true, rcode: 'SERVFAIL' }), { source: 'doh', kind: 'rcode', reason: 'rcode', params: { rcode: 'SERVFAIL' }, retryAt: null, detail: null });
    assert.equal(lookupStatus({ ok: false, error: 'Request timed out', errorKind: 'timeout' }).reason, 'timeout');
    assert.equal(lookupStatus({ ok: false, error: 'aborted', errorKind: 'abort' }).reason, 'unknown', 'an aborted query that was kept still says it failed');
    assert.equal(lookupStatus({ failed: true, source: 'rdap', error: 'boom', errorKind: 'network' }).source, 'rdap');
    assert.equal(lookupStatus({ ok: false, unsupportedTld: true, registrar: null, error: 'x' }), null, 'a TLD without RDAP is an answer');
    assert.equal(lookupStatus({ ok: false, unsupportedTld: false, registrar: null, error: 'HTTP 503', errorKind: 'http', httpStatus: 503 }).reason, 'http-status');
    assert.equal(lookupStatus({ name: 'x', status: 'ERROR', cnames: [], ipv4: [], ipv6: [], error: 'down', errorKind: 'network' }).reason, 'network');
    assert.equal(lookupStatus({ name: 'x', status: 'NXDOMAIN', cnames: [], ipv4: [], ipv6: [] }), null);
    assert.equal(lookupStatus(null), null);
  });

  test('cardsOfLookup: the cards a lookup feeds', () => {
    assert.deepEqual(cardsOfLookup('rdap'), ['registration', 'dns', 'health']);
    assert.deepEqual(cardsOfLookup('txt'), ['mail', 'saas']);
    assert.deepEqual(cardsOfLookup('health'), ['health']);
    assert.deepEqual(cardsOfLookup('wwwHttps'), ['web']);
  });
});

/* ------------------------------------------------------------------------ */
/* Building a passport                                                       */
/* ------------------------------------------------------------------------ */

describe('buildPassport', () => {
  test('every lookup lands once, reported as it lands; one build asks each DNS question once (the health run included)', async () => {
    const dns = fakeDns(zoneOf(), { signed: ['example.com'] });
    const f = mockFetch();
    const seen = [];
    const raw = await buildPassport('example.com', { dns, fetchImpl: f, now: NOW, onLookup: (id) => seen.push(id) });
    assert.deepEqual([...seen].sort(), [...PASSPORT_LOOKUPS].sort());
    assert.equal(raw.domain, 'example.com');
    const keys = dns.calls.map((c) => `${c.name}|${c.type}|${c.dnssec ? 1 : 0}|${c.cd ? 1 : 0}`);
    const dupes = keys.filter((k, i) => keys.indexOf(k) !== i);
    assert.deepEqual(dupes, [], 'no question asked twice');
    assert.ok(keys.includes('example.com|DS|1|0') && keys.includes('_dmarc.example.com|TXT|0|0') && keys.includes('www.example.com|HTTPS|0|0'));
    assert.equal(f.log.filter((u) => u.startsWith(RDAP_BASE)).length, 1, 'one RDAP lookup: the health run makes none');
    assert.equal(f.log.filter((u) => /certspotter|crt\.sh/.test(u)).length, 0, 'CT only on request');
  });

  test('the cards of a healthy domain', async () => {
    const raw = await buildPassport('example.com', { dns: fakeDns(zoneOf(), { signed: ['example.com'] }), fetchImpl: mockFetch(), now: NOW });
    const cards = passportCards(raw, { now: NOW });
    assert.deepEqual(Object.keys(cards), PASSPORT_CARDS);
    for (const id of PASSPORT_CARDS) assert.deepEqual([cards[id].state, cards[id].failures, cards[id].retry], ['ready', [], []], id);

    const reg = cards.registration;
    assert.equal(reg.outcome, 'ok');
    assert.equal(reg.registrar, 'Example Registrar, Inc.');
    assert.equal(reg.ianaId, '9999');
    assert.equal(reg.daysLeft, 318);
    assert.equal(reg.expiry, 'ok');
    assert.equal(reg.transferLock, true);
    assert.equal(reg.dnssec, true);
    assert.deepEqual(reg.flags.map((x) => x.kind), ['lock', 'lock']);

    const dns = cards.dns;
    assert.deepEqual(dns.nameservers, ['adam.ns.cloudflare.com', 'bella.ns.cloudflare.com']);
    assert.deepEqual(dns.hosting.providers.map((p) => p.name), ['Cloudflare']);
    assert.deepEqual([dns.soa.mname, dns.soa.email, dns.soa.serialDate, dns.soa.provider.id], ['adam.ns.cloudflare.com', 'dns@cloudflare.com', '2026-09-28', 'cloudflare']);
    assert.equal(dns.dnssec, 'validated');
    assert.equal(dns.delegation, null, 'RDAP lists no name servers here');
    assert.equal(dns.exists, true);

    const mail = cards.mail;
    assert.equal(mail.mx.state, 'some');
    assert.deepEqual(mail.mx.platforms.map((p) => p.name), ['Microsoft 365']);
    assert.deepEqual([mail.spf.state, mail.spf.all, mail.spf.senders.map((s) => s.id)], ['ok', '-', ['microsoft365', 'sendgrid']]);
    assert.deepEqual([mail.dmarc.state, mail.dmarc.policy, mail.dmarc.pct, mail.dmarc.reports], ['ok', 'reject', 100, 1]);

    const web = cards.web;
    assert.deepEqual(web.hosts.map((x) => [x.name, x.state, x.classification.kind]), [['example.com', 'ok', 'cloudflare'], ['www.example.com', 'ok', 'cloudflare']]);
    assert.equal(web.hosts[1].aliasOfApex, true);
    assert.equal(web.hosts[1].sameAsApex, true);
    assert.deepEqual(web.https.apex, { present: true, alpn: ['h3', 'h2'] });
    assert.deepEqual(web.https.www, { present: true, alpn: ['h3', 'h2'] }, 'through the alias');

    const certs = cards.certs;
    assert.equal(certs.caa.state, 'present');
    assert.deepEqual(certs.caa.issue.map((e) => [e.issuer, e.ca.name, e.restricted]), [['letsencrypt.org', "Let's Encrypt", false]]);
    assert.deepEqual([certs.caa.iodef, certs.caa.wildcardOnly, certs.ct], [1, false, null]);

    const saas = cards.saas;
    assert.deepEqual(saas.saas.vendors.map((v) => [v.name, v.count]), [['Google', 2], ['Atlassian', 1], ['Microsoft 365', 1], ['Stripe', 1]]);
    assert.deepEqual([saas.saas.other, saas.saas.policy], [1, 1]);
    assert.doesNotMatch(JSON.stringify(saas), /TOKENVALUE|0123456789abcdef|ms12345678/, 'no token value in the card');
  });

  test('the health card scores exactly like Domain Health (the same checks, the RDAP ones applied)', async () => {
    const zone = zoneOf();
    const f = mockFetch();
    const raw = await buildPassport('example.com', { dns: fakeDns(zone, { signed: ['example.com'] }), fetchImpl: f, now: NOW });
    const card = healthCard(raw, { now: NOW });
    const direct = await domainHealth('example.com', { dns: fakeDns(zone, { signed: ['example.com'] }), fetchImpl: mockFetch(), now: NOW });
    assert.deepEqual(card.summary, direct.summary);
    assert.equal(card.score, healthScore(direct.summary));
    assert.deepEqual(card.report.checks.map((c) => c.id).sort(), direct.checks.map((c) => c.id).sort());
    assert.ok(card.problems.length <= 3 && card.problems.every((p) => p.severity === 'error' || p.severity === 'warn'));
    // Without the registration lookup the score is not shown yet: it would change under the reader.
    const early = healthCard({ ...raw, rdap: undefined }, { now: NOW });
    assert.deepEqual([early.state, early.score], ['pending', undefined]);
  });

  test('a failed MX query: n/a on the mail card with its reason, Retry asks MX alone past the cache', async () => {
    const dns = fakeDns(zoneOf(), { fail: { 'example.com|MX': 'Request timed out after 8000 ms' } });
    const raw = await buildPassport('example.com', { dns, fetchImpl: mockFetch(), now: NOW });
    let mail = mailCard(raw, { now: NOW });
    assert.equal(mail.state, 'ready');
    assert.deepEqual(mail.retry, ['mx']);
    assert.deepEqual([mail.failures[0].lookup, mail.failures[0].source, mail.failures[0].reason], ['mx', 'doh', 'network']);
    assert.equal(mail.mx, null, 'not "no MX"');
    assert.equal(mail.spf.state, 'ok', 'the other parts stay');
    // Retry: only the failed lookup, past the cache
    const fixed = fakeDns(zoneOf());
    const again = await buildPassport('example.com', { dns: fixed, fetchImpl: mockFetch(), lookups: mail.retry, noCache: true, now: NOW });
    assert.deepEqual(fixed.calls.map((c) => [c.name, c.type, c.noCache]), [['example.com', 'MX', true]]);
    mail = mailCard({ ...raw, ...again }, { now: NOW });
    assert.deepEqual([mail.failures, mail.retry, mail.mx.platforms[0].id], [[], [], 'microsoft365']);
  });

  test('SERVFAIL for NS, a DoH failure for www: statuses on their cards, the answers of the others kept', async () => {
    const dns = fakeDns(zoneOf(), { rcodes: { 'example.com|NS': 'SERVFAIL' }, fail: { 'www.example.com|A': 'down', 'www.example.com|AAAA': 'down' } });
    const cards = passportCards(await buildPassport('example.com', { dns, fetchImpl: mockFetch(), now: NOW }), { now: NOW });
    assert.deepEqual(cards.dns.failures.map((f) => [f.lookup, f.reason, f.params.rcode]), [['ns', 'rcode', 'SERVFAIL']]);
    assert.deepEqual(cards.dns.nameservers, []);
    assert.equal(cards.dns.soa.mname, 'adam.ns.cloudflare.com');
    assert.deepEqual(cards.web.retry, ['www']);
    assert.deepEqual(cards.web.hosts.map((x) => x.state), ['ok', 'failed']);
    assert.equal(cards.web.hosts[1].failure.reason, 'network');
  });

  test('registration: a TLD without RDAP names its registry; an RDAP 503 is n/a with Retry; not registered', async () => {
    const tr = await buildPassport('example-test.com.tr', { dns: fakeDns(zoneOf('example-test.com.tr')), fetchImpl: mockFetch(), now: NOW });
    const card = registrationCard(tr, { now: NOW });
    assert.deepEqual([card.outcome, card.tld, card.whois.name, card.failures, card.retry], ['unsupported', 'tr', 'TRABİS', [], []]);
    assert.equal(healthCard(tr, { now: NOW }).state, 'ready', 'the health score does not need RDAP');

    const down = mockFetch({ rdap: () => json({ errorCode: 503 }, { status: 503 }) });
    const r = await buildPassport('example.com', { dns: fakeDns(zoneOf()), fetchImpl: down, lookups: ['rdap'], now: NOW });
    const failed = registrationCard(r, { now: NOW });
    assert.deepEqual([failed.outcome, failed.retry, failed.failures[0].source, failed.failures[0].reason, failed.failures[0].params], ['failed', ['rdap'], 'rdap', 'http-status', { status: 503 }]);

    const gone = mockFetch({ rdap: () => json({ errorCode: 404 }, { status: 404 }) });
    const nf = registrationCard(await buildPassport('example.com', { dns: fakeDns(zoneOf()), fetchImpl: gone, lookups: ['rdap'], now: NOW }), { now: NOW });
    assert.deepEqual([nf.outcome, nf.failures], ['not-found', []]);
  });

  test('registration: no transfer lock, the expiry thresholds, the registry delegation compared with the zone', async () => {
    const f = mockFetch({ rdap: (url) => json(rdapJson('example.com', { status: ['active'], expires: '2026-10-20T00:00:00Z', ns: ['ns1.example.net', 'adam.ns.cloudflare.com'] })) });
    const raw = await buildPassport('example.com', { dns: fakeDns(zoneOf()), fetchImpl: f, now: NOW });
    const reg = registrationCard(raw, { now: NOW });
    assert.deepEqual([reg.transferLock, reg.daysLeft, reg.expiry], [false, 21, 'error']);
    assert.deepEqual(registrationCard({ rdap: { ...raw.rdap, status: [] } }, { now: NOW }).transferLock, null, 'no statuses: not known');
    assert.equal(registrationCard({ rdap: { ...raw.rdap, expires: new Date('2026-11-20T00:00:00Z') } }, { now: NOW }).expiry, 'warn');
    assert.equal(registrationCard({ rdap: { ...raw.rdap, expires: new Date('2026-09-01T00:00:00Z') } }, { now: NOW }).expiry, 'expired');
    const dns = dnsCard(raw, { now: NOW });
    assert.deepEqual(dns.delegation, { registry: ['adam.ns.cloudflare.com', 'ns1.example.net'], onlyRegistry: ['ns1.example.net'], onlyZone: ['bella.ns.cloudflare.com'] });
  });

  test('a domain that does not exist; a null MX; no SPF or DMARC; DNSSEC unsigned and failing', async () => {
    const none = passportCards(await buildPassport('example.org', { dns: fakeDns({}), fetchImpl: mockFetch(), now: NOW }), { now: NOW });
    assert.deepEqual([none.dns.exists, none.mail.exists, none.saas.exists], [false, false, false]);
    assert.deepEqual(none.web.hosts.map((x) => x.state), ['nxdomain', 'nxdomain']);
    assert.equal(none.dns.dnssec, 'unsigned');
    const zone = zoneOf('example.net');
    zone['example.net'].MX = [{ preference: 0, exchange: '.' }];
    zone['example.net'].TXT = ['hello'];
    delete zone['_dmarc.example.net'];
    const raw = await buildPassport('example.net', { dns: fakeDns(zone, { rcodes: { 'example.net|DNSKEY': 'SERVFAIL' } }), fetchImpl: mockFetch(), now: NOW });
    const cards = passportCards(raw, { now: NOW });
    assert.deepEqual([cards.mail.mx.state, cards.mail.spf.state, cards.mail.dmarc.state], ['null', 'none', 'none']);
    assert.equal(cards.dns.dnssec, 'failing');
    assert.deepEqual(cards.dns.failures.map((x) => x.lookup), ['dnskey']);
    delete zone['example.net'].DS;
    const plain = passportCards(await buildPassport('example.net', { dns: fakeDns(zone), fetchImpl: mockFetch(), now: NOW, lookups: ['ds', 'dnskey'] }), { now: NOW });
    assert.equal(plain.dns.dnssec, 'unsigned');
  });

  test('two SPF records, an invalid DMARC, an MX host of an unknown provider and one of the domain itself', async () => {
    const zone = zoneOf('example.net');
    zone['example.net'].TXT = ['v=spf1 -all', 'v=spf1 include:_spf.google.com ~all'];
    zone['example.net'].MX = [{ preference: 10, exchange: 'mx.example.net' }, { preference: 20, exchange: 'mx.example.org' }];
    zone['_dmarc.example.net'] = { TXT: ['v=DMARC1; p=maybe'] };
    const mail = mailCard(await buildPassport('example.net', { dns: fakeDns(zone), fetchImpl: mockFetch(), now: NOW, lookups: ['mx', 'txt', 'dmarc'] }), { now: NOW });
    assert.deepEqual(mail.spf, { state: 'many', count: 2 });
    assert.equal(mail.dmarc.state, 'invalid');
    assert.deepEqual(mail.mx.hosts.map((m) => [m.exchange, m.own, m.platform]), [['mx.example.net', true, null], ['mx.example.org', false, null]]);
    assert.deepEqual(mail.mx.other, ['mx.example.net', 'mx.example.org']);
  });

  test('a stop rejects with an AbortError and reports nothing after it', async () => {
    const ctl = new AbortController();
    const seen = [];
    const p = buildPassport('example.com', { dns: fakeDns(zoneOf(), { delayMs: 30 }), fetchImpl: mockFetch(), signal: ctl.signal, now: NOW, onLookup: (id) => seen.push(id) });
    setTimeout(() => ctl.abort(), 5);
    await assert.rejects(p, { name: 'AbortError' });
    const after = seen.length;
    await new Promise((r) => setTimeout(r, 60));
    assert.equal(seen.length, after, 'nothing reported after the abort');
    await assert.rejects(buildPassport('not a domain!', { dns: fakeDns({}) }), TypeError);
    await assert.rejects(runLookup('nope', 'example.com', { dns: passportDns(fakeDns({})) }), RangeError);
  });

  test('a lookup that throws is kept as its failure, never as "no data"', async () => {
    const dns = { query: async () => { throw new Error('socket closed'); } };
    const r = await runLookup('mx', 'example.com', { dns: passportDns(dns) });
    assert.deepEqual([r.ok, r.errorKind, r.error], [false, 'unknown', 'socket closed']);
    const crash = await runLookup('rdap', 'example.com', { dns: passportDns(dns), fetchImpl: () => { throw new Error('fetch broke'); } });
    assert.equal(crash.ok, false, 'rdapDomain reports its own failures');
    assert.throws(() => passportDns(null), TypeError);
  });

  test('HEALTH_LOOKUPS: exactly the lookups that ask a question the health run asks too', async () => {
    const questions = async (fn) => {
      const dns = fakeDns(zoneOf(), { signed: ['example.com'] });
      await fn(passportDns(dns));
      return new Set(dns.calls.map((c) => `${c.name}|${c.type}|${c.dnssec ? 1 : 0}`));
    };
    const health = await questions((d) => runLookup('health', 'example.com', { dns: d, fetchImpl: mockFetch(), now: NOW }));
    for (const id of PASSPORT_LOOKUPS.filter((l) => l !== 'health' && l !== 'rdap')) {
      const own = await questions((d) => runLookup(id, 'example.com', { dns: d, now: NOW }));
      assert.equal([...own].some((k) => health.has(k)), HEALTH_LOOKUPS.includes(id), id);
    }
  });

  test('passportDns: one question once, noCache passed on, an abort is not remembered', async () => {
    const calls = [];
    const inner = { query: async (name, type, opts) => { calls.push([name, type, opts.dnssec, opts.noCache]); throwIfAborted(opts.signal); return { ok: true, rcode: 'NOERROR', answers: [] }; } };
    const d = passportDns(inner, { noCache: true });
    await Promise.all([d.query('Example.COM.', 'MX'), d.query('example.com', 'MX'), d.query('example.com', 'DS', { dnssec: true })]);
    assert.deepEqual(calls, [['example.com', 'MX', false, true], ['example.com', 'DS', true, true]]);
    await assert.rejects(d.query('example.net', 'A', { signal: AbortSignal.abort() }), { name: 'AbortError' });
    await d.query('example.net', 'A');
    assert.equal(calls.filter((c) => c[0] === 'example.net').length, 1, 'asked again after the abort');
    assert.equal(typeof d.resolveHost, 'undefined', 'health emulates it through the memo');
    const withHost = passportDns({ query: inner.query, resolveHost: async (n, o) => ({ n, o }) }, { noCache: true });
    assert.deepEqual(await withHost.resolveHost('x.example.com', { signal: null }), { n: 'x.example.com', o: { signal: null, noCache: true } });
  });
});

/* ------------------------------------------------------------------------ */
/* Certificate Transparency                                                  */
/* ------------------------------------------------------------------------ */

const LE = "C=US, O=Let's Encrypt, CN=R11";
const SECTIGO = 'C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV R36';

/** A Cert Spotter issuance row with the issuer expanded. */
function issuance(id, { dn = LE, friendly = "Let's Encrypt", caa = ['letsencrypt.org'], nb = '2026-08-01T00:00:00Z', na = '2026-10-30T00:00:00Z', revoked = false } = {}) {
  return {
    id: String(id), tbs_sha256: 'aa'.repeat(32), cert_sha256: 'bb'.repeat(32), pubkey_sha256: 'cc'.repeat(32),
    issuer: { friendly_name: friendly, caa_domains: caa, operator: { name: friendly, website: 'https://ca.example.org/' }, pubkey_sha256: 'dd'.repeat(32), name: dn },
    not_before: nb, not_after: na, revoked
  };
}

describe('CT issuers', () => {
  test('the request URLs: one single-host Cert Spotter query with the issuer expanded; the crt.sh identity search', () => {
    assert.equal(certspotterIssuersUrl('Example.COM'), 'https://api.certspotter.com/v1/issuances?domain=example.com&match_wildcards=true&expand=issuer&expand=issuer.caa_domains&expand=issuer.operator');
    assert.equal(crtshIssuersUrl('example.com'), 'https://crt.sh/?q=example.com&output=json&exclude=expired');
    assert.doesNotMatch(certspotterIssuersUrl('example.com'), /include_subdomains/, 'never the 10-per-hour full-domain search');
  });

  test('issuersFromCertspotter: current and not revoked, grouped by CA, most certificates first', () => {
    const r = issuersFromCertspotter([
      issuance(1), issuance(2, { nb: '2026-09-01T00:00:00Z' }), issuance(3, { revoked: true }), issuance(4, { na: '2026-09-01T00:00:00Z' }),
      issuance(5, { dn: SECTIGO, friendly: 'Sectigo', caa: ['sectigo.com', 'comodoca.com'] }), issuance(6, { nb: '2026-12-01T00:00:00Z' }), null, 'junk'
    ], { now: NOW });
    assert.equal(r.certificates, 3);
    assert.deepEqual(r.issuers.map((i) => [i.name, i.count, i.newest.toISOString().slice(0, 10), i.intermediates, i.caaDomains]), [
      ["Let's Encrypt", 2, '2026-09-01', ['R11'], ['letsencrypt.org']],
      ['Sectigo', 1, '2026-08-01', ['Sectigo Public Server Authentication CA DV R36'], ['sectigo.com', 'comodoca.com']]
    ]);
    // Without Cert Spotter's CAA domains, the known CA's are used; an unknown CA keeps its O.
    const own = issuersFromCertspotter([{ ...issuance(7), issuer: { name: 'C=XX, O=Example Trust Services, CN=Example CA 1' } }], { now: NOW });
    assert.deepEqual([own.issuers[0].name, own.issuers[0].caaDomains], ['Example Trust Services', []]);
  });

  test('issuersFromCrtsh: the precertificate and the certificate of one issuance count once', () => {
    const row = (id, serial, extra = {}) => ({ id, issuer_ca_id: 1, issuer_name: LE, serial_number: serial, not_before: '2026-08-01T00:00:00', not_after: '2026-10-30T00:00:00', ...extra });
    const r = issuersFromCrtsh([row(10, '0abc'), row(11, 'abc'), row(12, 'def'), row(13, '123', { not_after: '2026-01-01T00:00:00' })], { now: NOW });
    assert.deepEqual([r.certificates, r.issuers[0].name, r.issuers[0].count, r.issuers[0].caaDomains], [2, "Let's Encrypt", 2, ['letsencrypt.org']]);
  });

  test('lookupCtIssuers: one Cert Spotter request when it answers', async () => {
    const f = mockFetch({ spotter: () => json([issuance(1), issuance(2, { dn: SECTIGO, friendly: 'Sectigo', caa: ['sectigo.com'] })]) });
    const r = await lookupCtIssuers('example.com', { fetchImpl: f, now: NOW, cooldown: createCtCooldown() });
    assert.deepEqual([r.status, r.provider, r.requests, r.certificates, r.failures], ['ok', 'certspotter', 1, 2, []]);
    assert.deepEqual(f.log, [certspotterIssuersUrl('example.com')]);
  });

  test('lookupCtIssuers: a Cert Spotter 429 starts the shared cool-down and crt.sh answers; later lookups skip Cert Spotter', async () => {
    const cooldown = createCtCooldown();
    const f = mockFetch({
      spotter: () => json({ code: 'rate_limited' }, { status: 429 }),
      crtsh: () => json([{ id: 1, issuer_ca_id: 1, issuer_name: LE, serial_number: '01', not_before: '2026-08-01T00:00:00', not_after: '2026-10-30T00:00:00' }])
    });
    const r = await lookupCtIssuers('example.com', { fetchImpl: f, now: NOW, cooldown });
    assert.deepEqual([r.status, r.provider, r.requests], ['ok', 'crtsh', 2]);
    assert.deepEqual([r.failures[0].source, r.failures[0].reason, r.failures[0].params], ['certspotter', 'rate-limit-wait', { minutes: 60 }]);
    assert.ok(cooldown.get(NOW.getTime() + 1000), 'the cool-down runs');
    const again = await lookupCtIssuers('example.com', { fetchImpl: f, now: new Date(NOW.getTime() + 60000), cooldown });
    assert.deepEqual([again.provider, again.requests, again.failures[0].params], ['crtsh', 1, { minutes: 59 }]);
    assert.equal(f.count.spotter, 1, 'Cert Spotter asked once');
    const later = await lookupCtIssuers('example.com', { fetchImpl: mockFetch({ spotter: () => json([]) }), now: new Date(NOW.getTime() + CT_COOLDOWN_MS + 1000), cooldown });
    assert.equal(later.provider, 'certspotter', 'after the hour');
  });

  test('lookupCtIssuers: both services down → failed with each reason; an abort rejects; a bad name throws', async () => {
    const f = mockFetch({ spotter: () => json({}, { status: 500 }), crtsh: () => { throw new TypeError('Failed to fetch'); } });
    const r = await lookupCtIssuers('example.com', { fetchImpl: f, now: NOW, cooldown: createCtCooldown() });
    assert.deepEqual([r.status, r.provider, r.requests], ['failed', null, 2]);
    assert.deepEqual(r.failures.map((x) => [x.source, x.reason]), [['certspotter', 'http-status'], ['crtsh', 'network']]);
    const odd = await lookupCtIssuers('example.com', { fetchImpl: mockFetch({ spotter: () => json({ not: 'a list' }), crtsh: () => json('nope') }), now: NOW, cooldown: createCtCooldown() });
    assert.deepEqual(odd.failures.map((x) => x.reason), ['parse', 'parse']);
    await assert.rejects(lookupCtIssuers('example.com', { fetchImpl: f, signal: AbortSignal.abort(), cooldown: createCtCooldown() }), { name: 'AbortError' });
    await assert.rejects(lookupCtIssuers('not a name', { fetchImpl: f }), TypeError);
  });

  test('the certificates card compares the CT issuers with CAA', async () => {
    const raw = await buildPassport('example.com', { dns: fakeDns(zoneOf()), fetchImpl: mockFetch(), now: NOW, lookups: ['caa'] });
    raw.ct = await lookupCtIssuers('example.com', {
      fetchImpl: mockFetch({ spotter: () => json([issuance(1), issuance(2, { dn: SECTIGO, friendly: 'Sectigo', caa: ['sectigo.com'] })]) }), now: NOW, cooldown: createCtCooldown()
    });
    const card = certsCard(raw, { now: NOW });
    assert.deepEqual(card.ct.issuers.map((i) => [i.name, i.verdict]), [["Let's Encrypt", 'allowed'], ['Sectigo', 'denied']]);
    assert.deepEqual([card.ct.notAllowed, card.ct.firstPage, card.ct.certificates], [['Sectigo'], true, 2]);
    // No CAA at all: every CA may issue
    const open = zoneOf();
    delete open['example.com'].CAA;
    const raw2 = await buildPassport('example.com', { dns: fakeDns(open), fetchImpl: mockFetch(), now: NOW, lookups: ['caa'] });
    raw2.ct = raw.ct;
    const card2 = certsCard(raw2, { now: NOW });
    assert.equal(card2.caa.state, 'none');
    assert.deepEqual(card2.ct.issuers.map((i) => i.verdict), ['allowed', 'allowed']);
    // A failed CT lookup, and a failed CAA climb
    const failedCt = certsCard({ ...raw, ct: { status: 'failed', provider: null, failures: [{ source: 'crtsh', reason: 'network' }] } }, { now: NOW });
    assert.deepEqual([failedCt.ct.state, failedCt.ct.failures.length], ['failed', 1]);
    const caaDown = certsCard(await buildPassport('example.com', { dns: fakeDns(zoneOf(), { rcodes: { 'example.com|CAA': 'SERVFAIL' } }), fetchImpl: mockFetch(), now: NOW, lookups: ['caa'] }), { now: NOW });
    assert.deepEqual([caaDown.caa, caaDown.retry, caaDown.failures[0].reason], [null, ['caa'], 'rcode']);
    // issue ";" only: nobody may issue
    const deny = zoneOf();
    deny['example.com'].CAA = [{ flags: 0, tag: 'issue', value: ';' }];
    assert.equal(certsCard(await buildPassport('example.com', { dns: fakeDns(deny), fetchImpl: mockFetch(), now: NOW, lookups: ['caa'] }), { now: NOW }).caa.state, 'deny-all');
  });
});

/* ------------------------------------------------------------------------ */
/* Summary facts                                                             */
/* ------------------------------------------------------------------------ */

describe('passportSummaryFacts', () => {
  test('names only: vendors, platforms, providers, CAs — never a token, a record or an address', async () => {
    const raw = await buildPassport('example.com', { dns: fakeDns(zoneOf(), { signed: ['example.com'] }), fetchImpl: mockFetch(), now: NOW });
    const facts = passportSummaryFacts(passportCards(raw, { now: NOW }), { domain: 'example.com', at: NOW });
    assert.deepEqual(facts.registration, {
      pending: false, failed: false, outcome: 'ok', registrar: 'Example Registrar, Inc.', expires: new Date('2027-08-13T04:00:00Z'),
      daysLeft: 318, transferLock: true, tld: 'com', whois: null
    });
    assert.deepEqual(facts.dns, { pending: false, failed: false, exists: true, providers: ['Cloudflare'], self: false, other: [], nsFailed: false, dnssec: 'validated', delegationDiffers: false });
    assert.deepEqual(facts.mail, {
      pending: false, failed: false, mx: 'some', platforms: ['Microsoft 365'], other: [],
      spf: { state: 'ok', all: '-', redirect: false, count: 1 }, dmarc: { state: 'ok', policy: 'reject', count: 1 }
    });
    assert.deepEqual(facts.web.hosts.map((x) => [x.name, x.kind, x.provider]), [['example.com', 'cloudflare', 'Cloudflare'], ['www.example.com', 'cloudflare', 'Cloudflare']]);
    assert.equal(facts.web.https, true);
    assert.deepEqual(facts.certs, { pending: false, failed: false, caa: 'present', cas: ["Let's Encrypt"], ct: null });
    assert.deepEqual(facts.saas.vendors, ['Google', 'Atlassian', 'Microsoft 365', 'Stripe']);
    assert.equal(typeof facts.health.score, 'number');
    const text = JSON.stringify(facts);
    assert.doesNotMatch(text, /TOKENVALUE|ms12345678|198\.51\.100|104\.16|v=spf1|DMARC1/);
  });

  test('pending and failed parts are said, not guessed', () => {
    const facts = passportSummaryFacts(passportCards({ domain: 'example.com', mx: { ok: false, error: 'down', errorKind: 'network' } }, { now: NOW }), { domain: 'example.com' });
    assert.deepEqual([facts.registration.pending, facts.mail.failed, facts.mail.mx, facts.health.pending], [true, true, null, true]);
  });
});
