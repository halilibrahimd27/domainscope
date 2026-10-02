import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  rdapDomain, rdapIp, registryDomain, parseBootstrap, findDomainService, findIpService,
  parseRdapDomain, parseRdapIp, rangeToCidrs, clearRdapCache, IANA_BOOTSTRAP, RDAP_ORG, RDAP_OVERRIDES, RDAP_ORG_INTERVAL_MS,
  RDAP_ORG_COOLDOWN_MS
} from '../../assets/js/lib/rdap.js';

/* -------------------------------------------------------------------- */
/* Fixtures (trimmed from live responses, 2026-09-23)                   */
/* -------------------------------------------------------------------- */

const DNS_BOOTSTRAP = {
  version: '1.0',
  publication: '2026-09-16T19:00:03Z',
  services: [
    [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
    [['org'], ['https://rdap.publicinterestregistry.org/rdap/']],
    [['uk'], ['https://rdap.nominet.uk/uk/']],
    [['kg'], ['http://rdap.cctld.kg/']],
    [['nb'], ['https://rdap.no-slash.example/rdap']],
    [['xn--p1ai'], ['http://rdap.tcinet.ru/', 'https://rdap.tcinet.ru/']],
    [['co.test'], ['https://sld.registry.test/']],
    [['test'], ['https://tld.registry.test/']]
  ]
};

const IPV4_BOOTSTRAP = {
  services: [
    [['140.0.0.0/8', '8.0.0.0/8'], ['https://rdap.arin.net/registry/', 'http://rdap.arin.net/registry/']],
    [['193.0.0.0/8'], ['https://rdap.db.ripe.net/']],
    [['200.0.0.0/8'], ['https://rdap.lacnic.net/rdap/']],
    [['200.160.0.0/16'], ['https://rdap.more-specific.test/']]
  ]
};
const IPV6_BOOTSTRAP = {
  services: [
    [['2600::/12'], ['https://rdap.arin.net/registry/']],
    [['2a00::/12'], ['https://rdap.db.ripe.net/']]
  ]
};

const GITHUB_COM = {
  objectClassName: 'domain',
  handle: '1264983250_DOMAIN_COM-VRSN',
  ldhName: 'GITHUB.COM',
  links: [
    { value: 'https://rdap.verisign.com/com/v1/domain/github.com', rel: 'self', href: 'https://rdap.verisign.com/com/v1/domain/github.com', type: 'application/rdap+json' },
    { value: 'https://rdap.verisign.com/com/v1/domain/github.com', rel: 'related', href: 'https://rdap.markmonitor.com/rdap/domain/GITHUB.COM', type: 'application/rdap+json' }
  ],
  status: ['client delete prohibited', 'client transfer prohibited', 'client update prohibited'],
  entities: [{
    objectClassName: 'entity',
    handle: '292',
    roles: ['registrar'],
    links: [{ href: 'http://www.markmonitor.com', type: 'text/html', value: 'https://rdap.markmonitor.com/rdap/', rel: 'about' }],
    publicIds: [{ type: 'IANA Registrar ID', identifier: '292' }],
    vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'MarkMonitor Inc.']]],
    entities: [{
      objectClassName: 'entity',
      roles: ['abuse'],
      vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', ''], ['tel', { type: 'voice' }, 'uri', 'tel:+1.2086851750'],
        ['email', {}, 'text', 'abusecomplaints@markmonitor.com']]]
    }]
  }],
  events: [
    { eventAction: 'registration', eventDate: '2007-10-09T18:20:50Z' },
    { eventAction: 'expiration', eventDate: '2028-10-09T18:20:50Z' },
    { eventAction: 'last changed', eventDate: '2026-09-07T09:22:52Z' },
    { eventAction: 'last update of RDAP database', eventDate: '2026-09-23T08:16:35Z' }
  ],
  secureDNS: { delegationSigned: false },
  nameservers: [
    { objectClassName: 'nameserver', ldhName: 'DNS1.P08.NSONE.NET' },
    { objectClassName: 'nameserver', ldhName: 'DNS2.P08.NSONE.NET.' },
    { objectClassName: 'nameserver', ldhName: 'dns1.p08.nsone.net' },
    { objectClassName: 'nameserver', unicodeName: 'NS-1283.AWSDNS-32.ORG' }
  ]
};

const ARIN_GITHUB = {
  cidr0_cidrs: [{ v4prefix: '140.82.112.0', length: 20 }],
  endAddress: '140.82.127.255',
  entities: [{
    handle: 'GITHU',
    roles: ['registrant'],
    vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'GitHub, Inc.'], ['kind', {}, 'text', 'org']]],
    entities: [
      { handle: 'GITHU-ARIN', roles: ['administrative', 'noc', 'technical'], vcardArray: ['vcard', [['fn', {}, 'text', 'GitHub Ops'], ['kind', {}, 'text', 'group'], ['email', {}, 'text', 'hostmaster@github.com']]] },
      { handle: 'GITHU1-ARIN', roles: ['abuse'], vcardArray: ['vcard', [['fn', {}, 'text', 'GitHub Abuse'], ['kind', {}, 'text', 'group'], ['email', {}, 'text', 'noc@github.com']]] }
    ]
  }],
  events: [
    { eventAction: 'last changed', eventDate: '2021-12-14T20:28:48-05:00' },
    { eventAction: 'registration', eventDate: '2018-04-25T15:34:18-04:00' }
  ],
  handle: 'NET-140-82-112-0-1',
  ipVersion: 'v4',
  name: 'GITHU',
  objectClassName: 'ip network',
  parentHandle: 'NET-140-0-0-0-0',
  port43: 'whois.arin.net',
  startAddress: '140.82.112.0',
  status: ['active'],
  type: 'DIRECT ALLOCATION'
};

// RIPE-style answer (shape of a real RIPE DB object), modelled on the RIPE NCC's own block.
const RIPE_NET = {
  handle: '193.0.0.0 - 193.0.7.255',
  startAddress: '193.0.0.0',
  endAddress: '193.0.7.255',
  ipVersion: 'v4',
  name: 'RIPE-NCC',
  type: 'ASSIGNED PA',
  country: 'nl',
  parentHandle: '193.0.0.0 - 193.0.7.255',
  cidr0_cidrs: [{ v4prefix: '193.0.0.0', length: 21 }],
  entities: [
    { handle: 'ripe-ncc-mnt', roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'RIPE-NCC-MNT'], ['kind', {}, 'text', 'individual']]] },
    { handle: 'OPS4-RIPE', roles: ['administrative', 'technical'], vcardArray: ['vcard', [['fn', {}, 'text', 'Operations Contact Role'], ['kind', {}, 'text', 'group']]] },
    { handle: 'AR1-RIPE', roles: ['abuse'], vcardArray: ['vcard', [['fn', {}, 'text', 'Abuse Role'], ['kind', {}, 'text', 'group'], ['email', { type: 'abuse' }, 'text', 'abuse@ripe.net']]] }
  ],
  remarks: [{ description: ['Office network'] }, { title: 'Terms and Conditions', description: ['ignore me'] }],
  port43: 'whois.ripe.net'
};

function jsonResponse(body, status = 200) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status, headers: { 'content-type': 'application/rdap+json' }
  });
}

/** Route by URL prefix; values are bodies, (url, init) => body|Response|Error, or Errors. */
function mockFetch(routes) {
  const calls = [];
  const impl = async (url, init = {}) => {
    const u = String(url);
    calls.push({ url: u, accept: init.headers?.accept ?? null });
    const key = Object.keys(routes).sort((a, b) => b.length - a.length).find((k) => u.startsWith(k));
    if (!key) return jsonResponse({ errorCode: 404, title: 'Not Found' }, 404);
    let v = routes[key];
    if (typeof v === 'function') v = await v(u, init);
    if (v instanceof Error) throw v;
    if (v instanceof Response) return v;
    return jsonResponse(v);
  };
  impl.calls = calls;
  return impl;
}

const BOOT = {
  [IANA_BOOTSTRAP.dns]: DNS_BOOTSTRAP,
  [IANA_BOOTSTRAP.ipv4]: IPV4_BOOTSTRAP,
  [IANA_BOOTSTRAP.ipv6]: IPV6_BOOTSTRAP
};

beforeEach(() => clearRdapCache());

/* -------------------------------------------------------------------- */
/* Pure helpers                                                         */
/* -------------------------------------------------------------------- */

test('registryDomain uses ICANN suffixes only', () => {
  assert.equal(registryDomain('www.Example.com.tr'), 'example.com.tr');
  assert.equal(registryDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registryDomain('user.github.io'), 'github.io'); // private suffix ignored
  assert.equal(registryDomain('github.io'), 'github.io');
  assert.equal(registryDomain('*.x.example.com'), 'example.com');
  assert.equal(registryDomain('com.tr'), null);
  assert.equal(registryDomain('co.uk'), null);
  assert.equal(registryDomain('com'), null);
  assert.equal(registryDomain(''), null);
  assert.equal(registryDomain(null), null);
  assert.equal(registryDomain('1.2.3.4'), null);
});

test('parseBootstrap validates structure and normalises entries', () => {
  const s = parseBootstrap({ services: [[['COM.'], ['https://x/']], ['bad'], [[], ['https://y/']], [['net'], []]] });
  assert.deepEqual(s, [{ entries: ['com'], urls: ['https://x/'] }]);
  assert.throws(() => parseBootstrap({}), SyntaxError);
  assert.throws(() => parseBootstrap(null), SyntaxError);
});

test('findDomainService: longest label match, https preference, slash, http upgrade', () => {
  const s = parseBootstrap(DNS_BOOTSTRAP);
  assert.deepEqual(findDomainService(s, 'github.com'), { entry: 'com', urls: ['https://rdap.verisign.com/com/v1/'] });
  assert.deepEqual(findDomainService(s, 'x.co.test'), { entry: 'co.test', urls: ['https://sld.registry.test/'] });
  assert.deepEqual(findDomainService(s, 'x.test'), { entry: 'test', urls: ['https://tld.registry.test/'] });
  assert.deepEqual(findDomainService(s, 'a.nb').urls, ['https://rdap.no-slash.example/rdap/']);
  assert.deepEqual(findDomainService(s, 'a.kg').urls, ['https://rdap.cctld.kg/']);
  assert.deepEqual(findDomainService(s, 'a.xn--p1ai').urls, ['https://rdap.tcinet.ru/']);
  assert.equal(findDomainService(s, 'example.com.tr'), null);
});

test('findIpService: longest prefix per address family', () => {
  const v4 = parseBootstrap(IPV4_BOOTSTRAP);
  const v6 = parseBootstrap(IPV6_BOOTSTRAP);
  assert.deepEqual(findIpService(v4, '140.82.121.4'), { entry: '140.0.0.0/8', urls: ['https://rdap.arin.net/registry/'] });
  assert.equal(findIpService(v4, '200.160.2.3').urls[0], 'https://rdap.more-specific.test/');
  assert.equal(findIpService(v4, '200.1.2.3').urls[0], 'https://rdap.lacnic.net/rdap/');
  assert.equal(findIpService(v4, '9.9.9.9'), null);
  assert.equal(findIpService(v4, '2606:4700::1'), null);
  assert.equal(findIpService(v6, '2606:4700::1111').urls[0], 'https://rdap.arin.net/registry/');
  assert.equal(findIpService(v6, 'nope'), null);
});

test('rangeToCidrs', () => {
  assert.deepEqual(rangeToCidrs('193.0.0.0', '193.0.7.255'), ['193.0.0.0/21']);
  assert.deepEqual(rangeToCidrs('10.0.0.1', '10.0.0.6'), ['10.0.0.1/32', '10.0.0.2/31', '10.0.0.4/31', '10.0.0.6/32']);
  assert.deepEqual(rangeToCidrs('0.0.0.0', '255.255.255.255'), ['0.0.0.0/0']);
  assert.deepEqual(rangeToCidrs('2606:4700::', '2606:4700:ffff:ffff:ffff:ffff:ffff:ffff'), ['2606:4700::/32']);
  assert.deepEqual(rangeToCidrs('1.2.3.4', '1.2.3.4'), ['1.2.3.4/32']);
  assert.deepEqual(rangeToCidrs('1.2.3.5', '1.2.3.4'), []);
  assert.deepEqual(rangeToCidrs('1.2.3.4', '::1'), []);
  assert.deepEqual(rangeToCidrs('x', 'y'), []);
  assert.equal(rangeToCidrs('0.0.0.1', '255.255.255.254', 5).length, 5); // capped
});

test('parseRdapDomain: Verisign github.com', () => {
  const r = parseRdapDomain(GITHUB_COM);
  assert.equal(r.ldhName, 'github.com');
  assert.equal(r.registrar, 'MarkMonitor Inc.');
  assert.equal(r.registrarIanaId, '292');
  assert.equal(r.registrarUrl, 'http://www.markmonitor.com');
  assert.equal(r.abuseEmail, 'abusecomplaints@markmonitor.com');
  assert.equal(r.created.toISOString(), '2007-10-09T18:20:50.000Z');
  assert.equal(r.expires.toISOString(), '2028-10-09T18:20:50.000Z');
  assert.equal(r.updated.toISOString(), '2026-09-07T09:22:52.000Z');
  assert.deepEqual(r.status, ['client delete prohibited', 'client transfer prohibited', 'client update prohibited']);
  assert.deepEqual(r.nameservers, ['dns1.p08.nsone.net', 'dns2.p08.nsone.net', 'ns-1283.awsdns-32.org']);
  assert.equal(r.dnssecSigned, false);
  assert.equal(r.selfUrl, 'https://rdap.verisign.com/com/v1/domain/github.com');
});

test('parseRdapDomain: DNSSEC variants, nested registrar, dates without zone, junk', () => {
  const signed = parseRdapDomain({ secureDNS: { dsData: [{ keyTag: 2371 }] } });
  assert.equal(signed.dnssecSigned, true);
  assert.equal(parseRdapDomain({ secureDNS: { delegationSigned: true } }).dnssecSigned, true);
  assert.equal(parseRdapDomain({}).dnssecSigned, null);
  const nested = parseRdapDomain({
    entities: [{ roles: ['registrant'], entities: [{ roles: ['Registrar'], handle: 'REG-1', vcardArray: ['vcard', [['org', {}, 'text', ['Acme', 'Registrar']]]] }] }],
    events: [{ eventAction: 'Expiration', eventDate: '2030-01-02T03:04:05' }, { eventAction: 'expiration', eventDate: '2099-01-01T00:00:00Z' }, { eventAction: 'registration', eventDate: 'garbage' }],
    status: ['Active', '', 7]
  });
  assert.equal(nested.registrar, 'Acme Registrar');
  assert.equal(nested.registrarIanaId, null);
  assert.equal(nested.expires.toISOString(), '2030-01-02T03:04:05.000Z'); // first event wins, UTC assumed
  assert.equal(nested.created, null);
  assert.deepEqual(nested.status, ['active']);
  const handleOnly = parseRdapDomain({ entities: [{ roles: ['registrar'], handle: '1068' }] });
  assert.equal(handleOnly.registrar, '1068');
  assert.equal(parseRdapDomain({ events: [{ eventAction: 'registrar expiration', eventDate: '2031-01-01T00:00:00Z' }] }).expires.getUTCFullYear(), 2031);
  assert.throws(() => parseRdapDomain(null), SyntaxError);
  assert.throws(() => parseRdapDomain([]), SyntaxError);
});

test('parseRdapIp: ARIN, RIPE (maintainer is not an org), LACNIC string lengths, computed CIDRs', () => {
  const a = parseRdapIp(ARIN_GITHUB);
  assert.equal(a.name, 'GITHU');
  assert.equal(a.handle, 'NET-140-82-112-0-1');
  assert.equal(a.org, 'GitHub, Inc.');
  assert.equal(a.cidr, '140.82.112.0/20');
  assert.deepEqual(a.cidrs, ['140.82.112.0/20']);
  assert.equal(a.startAddress, '140.82.112.0');
  assert.equal(a.endAddress, '140.82.127.255');
  assert.equal(a.country, null);
  assert.equal(a.rir, 'ARIN');
  assert.equal(a.abuseEmail, 'noc@github.com');
  assert.equal(a.type, 'DIRECT ALLOCATION');
  assert.equal(a.parentHandle, 'NET-140-0-0-0-0');
  assert.equal(a.registered.toISOString(), '2018-04-25T19:34:18.000Z');

  const r = parseRdapIp(RIPE_NET);
  assert.equal(r.name, 'RIPE-NCC');
  assert.equal(r.country, 'NL');
  assert.equal(r.org, null); // "RIPE-NCC-MNT" is a maintainer, not an organisation
  assert.equal(r.cidr, '193.0.0.0/21');
  assert.equal(r.rir, 'RIPE NCC');
  assert.equal(r.abuseEmail, 'abuse@ripe.net');
  assert.deepEqual(r.description, ['Office network']);

  const l = parseRdapIp({
    handle: '200.160.0.0/20', name: '22817', country: 'BR', startAddress: '200.160.0.0', endAddress: '200.160.15.255',
    cidr0_cidrs: [{ length: '20', v4prefix: '200.160.0.0' }],
    entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['kind', {}, 'text', 'org'], ['fn', {}, 'text', 'Núcleo de Inf. e Coord. do Ponto BR - NIC.BR']]] }],
    links: [{ rel: 'self', href: 'https://rdap.registro.br/ip/200.160.2.3' }]
  });
  assert.equal(l.cidr, '200.160.0.0/20');
  assert.equal(l.org, 'Núcleo de Inf. e Coord. do Ponto BR - NIC.BR');
  assert.equal(l.rir, 'LACNIC');

  const computed = parseRdapIp({ startAddress: '10.0.0.0', endAddress: '10.0.1.255', entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Org']]] }] });
  assert.deepEqual(computed.cidrs, ['10.0.0.0/23']);
  assert.equal(computed.org, 'Example Org');
  const mnt = parseRdapIp({ entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'MNT-GOOG-PROD']]] }] });
  assert.equal(mnt.org, null);
  const multi = parseRdapIp({ startAddress: '10.0.0.1', endAddress: '10.0.0.2' });
  assert.equal(multi.cidr, '10.0.0.1/32, 10.0.0.2/32');
  assert.throws(() => parseRdapIp('x'), SyntaxError);
});

/* -------------------------------------------------------------------- */
/* rdapDomain                                                           */
/* -------------------------------------------------------------------- */

test('rdapDomain: registry from the bootstrap, registrable domain queried', async () => {
  const f = mockFetch({ ...BOOT, 'https://rdap.verisign.com/com/v1/domain/github.com': GITHUB_COM });
  const r = await rdapDomain('https://WWW.GitHub.com/path', { fetchImpl: f });
  assert.equal(r.ok, true);
  assert.equal(r.domain, 'github.com');
  assert.equal(r.input, 'www.github.com');
  assert.equal(r.tld, 'com');
  assert.equal(r.registrar, 'MarkMonitor Inc.');
  assert.equal(r.registrarIanaId, '292');
  assert.equal(r.expires.toISOString(), '2028-10-09T18:20:50.000Z');
  assert.equal(r.created.getUTCFullYear(), 2007);
  assert.equal(r.updated.getUTCFullYear(), 2026);
  assert.equal(r.dnssecSigned, false);
  assert.equal(r.nameservers.length, 3);
  assert.equal(r.rdapServer, 'https://rdap.verisign.com/com/v1/');
  assert.equal(r.url, 'https://rdap.verisign.com/com/v1/domain/github.com');
  assert.equal(r.unsupportedTld, false);
  assert.equal(r.notFound, false);
  assert.equal(r.error, null);
  assert.deepEqual(f.calls.map((c) => c.url), [IANA_BOOTSTRAP.dns, 'https://rdap.verisign.com/com/v1/domain/github.com']);
  assert.match(f.calls[1].accept, /application\/rdap\+json/);
});

test('rdapDomain: .tr has no RDAP → unsupportedTld without a registry request', async () => {
  const f = mockFetch(BOOT);
  const r = await rdapDomain('www.example.com.tr', { fetchImpl: f });
  assert.equal(r.ok, false);
  assert.equal(r.unsupportedTld, true);
  assert.equal(r.domain, 'example.com.tr');
  assert.equal(r.tld, 'tr');
  assert.equal(r.errorKind, 'unsupported');
  assert.match(r.error, /\.tr/);
  assert.deepEqual(f.calls.map((c) => c.url), [IANA_BOOTSTRAP.dns]);
});

test('rdapDomain: bootstrap cached per fetch implementation; clearRdapCache refetches', async () => {
  const f = mockFetch({ ...BOOT, 'https://rdap.verisign.com/': GITHUB_COM });
  await rdapDomain('github.com', { fetchImpl: f });
  await rdapDomain('example.net', { fetchImpl: f });
  await rdapDomain('x.com.tr', { fetchImpl: f });
  assert.equal(f.calls.filter((c) => c.url === IANA_BOOTSTRAP.dns).length, 1);
  const g = mockFetch({ ...BOOT, 'https://rdap.verisign.com/': GITHUB_COM });
  await rdapDomain('github.com', { fetchImpl: g });
  assert.equal(g.calls.filter((c) => c.url === IANA_BOOTSTRAP.dns).length, 1, 'separate cache for another fetchImpl');
  clearRdapCache();
  await rdapDomain('github.com', { fetchImpl: f });
  assert.equal(f.calls.filter((c) => c.url === IANA_BOOTSTRAP.dns).length, 2);
});

test('rdapDomain: concurrent lookups share one bootstrap download', async () => {
  let boots = 0;
  const f = mockFetch({
    [IANA_BOOTSTRAP.dns]: async () => { boots += 1; await new Promise((r) => setTimeout(r, 10)); return DNS_BOOTSTRAP; },
    'https://rdap.verisign.com/': GITHUB_COM
  });
  const rs = await Promise.all(['a.com', 'b.com', 'c.net'].map((d) => rdapDomain(d, { fetchImpl: f })));
  assert.equal(boots, 1);
  assert.ok(rs.every((r) => r.ok));
});

test('rdapDomain: registry 404 → notFound, no fallback', async () => {
  const f = mockFetch({
    ...BOOT,
    'https://rdap.verisign.com/': () => jsonResponse({ errorCode: 404, title: 'Not Found' }, 404),
    [RDAP_ORG]: () => { throw new Error('must not be called'); }
  });
  const r = await rdapDomain('surely-unregistered-xyz.com', { fetchImpl: f });
  assert.equal(r.ok, false);
  assert.equal(r.notFound, true);
  assert.equal(r.unsupportedTld, false);
  assert.equal(r.rdapServer, 'https://rdap.verisign.com/com/v1/');
  assert.equal(f.calls.length, 2);
});

test('rdapDomain: registry network/CORS failure → rdap.org fallback (server from self link)', async () => {
  const f = mockFetch({
    ...BOOT,
    'https://rdap.verisign.com/': () => new TypeError('Failed to fetch'),
    'https://rdap.org/domain/github.com': GITHUB_COM
  });
  const r = await rdapDomain('github.com', { fetchImpl: f });
  assert.equal(r.ok, true);
  assert.equal(r.rdapServer, 'https://rdap.verisign.com/com/v1/');
  assert.equal(r.url, 'https://rdap.org/domain/github.com');
  // network TypeErrors are not retried (CORS failures never recover)
  assert.deepEqual(f.calls.map((c) => c.url), [
    IANA_BOOTSTRAP.dns, 'https://rdap.verisign.com/com/v1/domain/github.com', 'https://rdap.org/domain/github.com'
  ]);
});

test('rdapDomain: 5xx is retried once before falling back', async () => {
  let n = 0;
  const f = mockFetch({
    ...BOOT,
    'https://rdap.publicinterestregistry.org/': () => { n += 1; return jsonResponse('busy', 503); },
    [RDAP_ORG]: () => jsonResponse('busy', 503)
  });
  const r = await rdapDomain('wikipedia.org', { fetchImpl: f });
  assert.equal(n, 2);
  assert.equal(r.ok, false);
  assert.equal(r.errorKind, 'http');
  assert.match(r.error, /HTTP 503/);
});

test('rdapDomain: bootstrap unreachable → rdap.org; its "No RDAP service" 404 → unsupportedTld', async () => {
  const f = mockFetch({
    [IANA_BOOTSTRAP.dns]: () => new TypeError('offline'),
    [RDAP_ORG]: () => jsonResponse({ errorCode: 404, title: 'No RDAP service is available for this resource' }, 404)
  });
  const r = await rdapDomain('example.de', { fetchImpl: f });
  assert.equal(r.unsupportedTld, true);
  assert.equal(r.url, 'https://rdap.org/domain/example.de');
  const f2 = mockFetch({ [IANA_BOOTSTRAP.dns]: () => new TypeError('offline'), [RDAP_ORG]: GITHUB_COM });
  clearRdapCache();
  const ok = await rdapDomain('github.com', { fetchImpl: f2 });
  assert.equal(ok.ok, true);
  const f3 = mockFetch({ [IANA_BOOTSTRAP.dns]: () => new TypeError('offline') });
  clearRdapCache();
  const none = await rdapDomain('github.com', { fetchImpl: f3, fallback: false });
  assert.equal(none.ok, false);
  assert.equal(none.errorKind, 'network');
});

test('rdapDomain: base URL without trailing slash, http-only upgraded', async () => {
  const f = mockFetch({
    ...BOOT,
    'https://rdap.no-slash.example/rdap/domain/x.nb': GITHUB_COM,
    'https://rdap.cctld.kg/domain/x.kg': GITHUB_COM
  });
  assert.equal((await rdapDomain('x.nb', { fetchImpl: f })).ok, true);
  assert.equal((await rdapDomain('x.kg', { fetchImpl: f })).ok, true);
});

test('rdapDomain: invalid input and public suffixes', async () => {
  const f = mockFetch(BOOT);
  const bad = await rdapDomain('not a domain', { fetchImpl: f });
  assert.equal(bad.ok, false);
  assert.equal(bad.errorKind, 'invalid');
  const ps = await rdapDomain('com.tr', { fetchImpl: f });
  assert.equal(ps.errorKind, 'invalid');
  assert.match(ps.error, /public suffix/);
  assert.equal(f.calls.length, 0);
});

test('rdapDomain: parse errors and abort', async () => {
  const f = mockFetch({ ...BOOT, 'https://rdap.verisign.com/': () => new Response('<html>', { status: 200 }), [RDAP_ORG]: () => new Response('[]', { status: 200 }) });
  const r = await rdapDomain('github.com', { fetchImpl: f });
  assert.equal(r.ok, false);
  assert.equal(r.errorKind, 'parse');
  await assert.rejects(rdapDomain('github.com', { fetchImpl: f, signal: AbortSignal.abort() }), { name: 'AbortError' });
  const slow = mockFetch({
    ...BOOT,
    'https://rdap.verisign.com/': (u, init) => new Promise((resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true });
    })
  });
  const ctl = new AbortController();
  setTimeout(() => ctl.abort(), 10);
  await assert.rejects(rdapDomain('github.com', { fetchImpl: slow, signal: ctl.signal }), { name: 'AbortError' });
});

/* -------------------------------------------------------------------- */
/* rdapIp                                                               */
/* -------------------------------------------------------------------- */

test('rdapIp: RIR from the IPv4 bootstrap', async () => {
  const f = mockFetch({ ...BOOT, 'https://rdap.arin.net/registry/ip/140.82.121.4': ARIN_GITHUB });
  const r = await rdapIp('140.82.121.4', { fetchImpl: f });
  assert.equal(r.ok, true);
  assert.equal(r.name, 'GITHU');
  assert.equal(r.org, 'GitHub, Inc.');
  assert.equal(r.cidr, '140.82.112.0/20');
  assert.equal(r.startAddress, '140.82.112.0');
  assert.equal(r.endAddress, '140.82.127.255');
  assert.equal(r.handle, 'NET-140-82-112-0-1');
  assert.equal(r.country, null);
  assert.equal(r.rdapServer, 'https://rdap.arin.net/registry/');
  assert.equal(r.error, null);
  assert.deepEqual(f.calls.map((c) => c.url), [IANA_BOOTSTRAP.ipv4, 'https://rdap.arin.net/registry/ip/140.82.121.4']);
});

test('rdapIp: IPv6, IPv4-mapped, more-specific service', async () => {
  const f = mockFetch({
    ...BOOT,
    'https://rdap.arin.net/registry/ip/2606:4700::1111': { ...ARIN_GITHUB, cidr0_cidrs: [{ v6prefix: '2606:4700::', length: 32 }], startAddress: '2606:4700::', endAddress: '2606:4700:ffff:ffff:ffff:ffff:ffff:ffff' },
    'https://rdap.db.ripe.net/ip/193.0.6.139': RIPE_NET,
    'https://rdap.more-specific.test/ip/200.160.2.3': { name: 'BR', startAddress: '200.160.0.0', endAddress: '200.160.15.255' }
  });
  const v6 = await rdapIp('2606:4700:0:0::1111', { fetchImpl: f });
  assert.equal(v6.ok, true);
  assert.equal(v6.ip, '2606:4700::1111');
  assert.equal(v6.cidr, '2606:4700::/32');
  const mapped = await rdapIp('::ffff:193.0.6.139', { fetchImpl: f });
  assert.equal(mapped.ok, true);
  assert.equal(mapped.country, 'NL');
  const ms = await rdapIp('200.160.2.3', { fetchImpl: f });
  assert.equal(ms.cidr, '200.160.0.0/20');
});

test('rdapIp: private/invalid (no requests), not in bootstrap → rdap.org, 404 → notFound', async () => {
  const f = mockFetch({
    ...BOOT,
    'https://rdap.org/ip/9.9.9.9': { name: 'QUAD9', startAddress: '9.9.9.0', endAddress: '9.9.9.255' },
    'https://rdap.arin.net/registry/ip/8.8.8.8': () => jsonResponse({ errorCode: 404 }, 404)
  });
  const p = await rdapIp('10.0.0.1', { fetchImpl: f });
  assert.equal(p.ok, false);
  assert.equal(p.private, true);
  const bad = await rdapIp('1.2.3', { fetchImpl: f });
  assert.equal(bad.errorKind, 'invalid');
  assert.equal(f.calls.length, 0);
  const q = await rdapIp('9.9.9.9', { fetchImpl: f });
  assert.equal(q.ok, true);
  assert.equal(q.cidr, '9.9.9.0/24');
  assert.equal(q.rdapServer, RDAP_ORG);
  const nf = await rdapIp('8.8.8.8', { fetchImpl: f });
  assert.equal(nf.notFound, true);
  assert.equal(nf.ok, false);
});

test('rdapIp: all servers failing yields an error; abort rejects', async () => {
  const f = mockFetch({ ...BOOT, 'https://rdap.arin.net/': () => new TypeError('CORS'), [RDAP_ORG]: () => new TypeError('CORS') });
  const r = await rdapIp('140.82.121.4', { fetchImpl: f });
  assert.equal(r.ok, false);
  assert.equal(r.errorKind, 'network');
  await assert.rejects(rdapIp('140.82.121.4', { fetchImpl: f, signal: AbortSignal.abort() }), { name: 'AbortError' });
});

/* -------------------------------------------------------------------- */
/* TLDs missing from the bootstrap; rdap.org paced and paused           */
/* -------------------------------------------------------------------- */

test('rdapDomain: a TLD the bootstrap does not list but RDAP_OVERRIDES does goes to that registry server', async () => {
  assert.deepEqual(Object.keys(RDAP_OVERRIDES), ['io', 'sh', 'ac', 'me']);
  const io = { ...GITHUB_COM, ldhName: 'EXAMPLE.IO', links: [] };
  const f = mockFetch({ ...BOOT, 'https://rdap.identitydigital.services/rdap/domain/example.io': io, [RDAP_ORG]: () => { throw new Error('not the fallback'); } });
  const r = await rdapDomain('www.example.io', { fetchImpl: f });
  assert.equal(r.ok, true);
  assert.equal(r.rdapServer, 'https://rdap.identitydigital.services/rdap/');
  assert.equal(r.unsupportedTld, false);
  // a TLD without RDAP and without an override: no request at all
  const none = await rdapDomain('example.example', { fetchImpl: f });
  assert.equal(none.unsupportedTld, true);
  assert.deepEqual(f.calls.map((c) => c.url), [IANA_BOOTSTRAP.dns, 'https://rdap.identitydigital.services/rdap/domain/example.io']);
  // the bootstrap out of reach: the override still answers
  clearRdapCache();
  const g = mockFetch({ [IANA_BOOTSTRAP.dns]: () => new TypeError('offline'), 'https://rdap.identitydigital.services/rdap/': io });
  assert.equal((await rdapDomain('example.io', { fetchImpl: g, fallback: false })).ok, true);
});

test('rdap.org: one request a second at most, every lookup of the page together, in call order', async () => {
  assert.equal(RDAP_ORG_INTERVAL_MS, 1000);
  const at = [];
  const f = mockFetch({
    ...BOOT,
    'https://tld.registry.test/': () => new TypeError('Failed to fetch'),
    [RDAP_ORG]: (u) => { at.push([u.split('/').pop(), Date.now()]); return GITHUB_COM; }
  });
  const rs = await Promise.all(['a.test', 'b.test', 'c.test'].map((d) => rdapDomain(d, { fetchImpl: f, rdapOrgIntervalMs: 80 })));
  assert.ok(rs.every((r) => r.ok));
  assert.deepEqual(at.map((x) => x[0]), ['a.test', 'b.test', 'c.test']);
  for (let i = 1; i < at.length; i += 1) assert.ok(at[i][1] - at[i - 1][1] >= 75, `spaced: ${at[i][1] - at[i - 1][1]} ms`);
});

test('rdap.org: an unreadable answer (a browser\'s view of its 429) pauses it; the registry\'s own error stands meanwhile', async () => {
  assert.equal(RDAP_ORG_COOLDOWN_MS, 60000);
  let orgCalls = 0;
  const f = mockFetch({
    ...BOOT,
    'https://tld.registry.test/': () => jsonResponse('busy', 503),
    [RDAP_ORG]: () => { orgCalls += 1; return new TypeError('Failed to fetch'); }
  });
  const first = await rdapDomain('a.test', { fetchImpl: f, rdapOrgIntervalMs: 0 });
  assert.equal(first.ok, false);
  assert.equal(first.errorKind, 'network');
  assert.match(first.error, /rdap\.org gave no readable answer/);
  assert.equal(orgCalls, 1, 'a TypeError is never retried');
  const second = await rdapDomain('b.test', { fetchImpl: f, rdapOrgIntervalMs: 0 });
  assert.equal(orgCalls, 1, 'paused: not asked again');
  assert.equal(second.rdapOrgPaused, true);
  assert.equal(second.httpStatus, 503, 'the registry\'s answer is the one reported');
  // a readable 429 pauses it too, and is not retried
  clearRdapCache();
  let n = 0;
  const g = mockFetch({ ...BOOT, 'https://tld.registry.test/': () => new TypeError('x'), [RDAP_ORG]: () => { n += 1; return jsonResponse('slow down', 429); } });
  await rdapDomain('a.test', { fetchImpl: g, rdapOrgIntervalMs: 0 });
  await rdapDomain('b.test', { fetchImpl: g, rdapOrgIntervalMs: 0 });
  assert.equal(n, 1);
  // after the pause it is asked again (the registry answered readably: the unreadable answer was rdap.org's)
  clearRdapCache();
  let m = 0;
  const h = mockFetch({ ...BOOT, 'https://tld.registry.test/': () => jsonResponse('bad request', 400), [RDAP_ORG]: () => { m += 1; return new TypeError('y'); } });
  await rdapDomain('a.test', { fetchImpl: h, rdapOrgIntervalMs: 0, rdapOrgCooldownMs: 30 });
  const paused = await rdapDomain('b.test', { fetchImpl: h, rdapOrgIntervalMs: 0, rdapOrgCooldownMs: 30 });
  assert.deepEqual([m, paused.rdapOrgPaused], [1, true], 'paused');
  await new Promise((r) => setTimeout(r, 40));
  await rdapDomain('c.test', { fetchImpl: h, rdapOrgIntervalMs: 0, rdapOrgCooldownMs: 30 });
  assert.equal(m, 2);
});

/** A Response as a redirect followed to `url` leaves it (fetch's `response.url`). */
function redirectedResponse(url, body, status) {
  const res = jsonResponse(body, status);
  Object.defineProperty(res, 'url', { value: url });
  return res;
}

test('rdap.org: a 429 pauses the lookups already waiting for their turn too; they are not sent and keep the registry\'s error', async () => {
  let orgCalls = 0;
  const f = mockFetch({
    ...BOOT,
    'https://tld.registry.test/': () => new TypeError('Failed to fetch'),
    [RDAP_ORG]: () => { orgCalls += 1; return jsonResponse('slow down', 429); }
  });
  // a slot of 250 ms: the first answer lands long before the next turn, even on a busy test machine
  const rs = await Promise.all(['a.test', 'b.test', 'c.test', 'd.test'].map((d) => rdapDomain(d, { fetchImpl: f, rdapOrgIntervalMs: 250 })));
  assert.equal(orgCalls, 1, 'only the first one reaches rdap.org');
  assert.equal(rs.filter((r) => r.rdapOrgPaused).length, 3);
  assert.ok(rs.filter((r) => r.rdapOrgPaused).every((r) => !r.ok && r.errorKind === 'network'), 'the registry\'s own failure is the one reported');
});

test('registries: one request in flight per server; a 429 is waited out and asked again, never blamed on rdap.org', async () => {
  // A registry that answers one request per 60 ms and 429 (with CORS, no Retry-After) to the rest.
  let last = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  let orgCalls = 0;
  const registry = async (u) => {
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await new Promise((r) => setTimeout(r, 5));
    inFlight -= 1;
    const now = Date.now();
    if (now - last < 60) return jsonResponse({ errorCode: 429 }, 429);
    last = now;
    return { ...GITHUB_COM, ldhName: u.split('/').pop().toUpperCase(), links: [] };
  };
  const f = mockFetch({ ...BOOT, 'https://tld.registry.test/': registry, [RDAP_ORG]: () => { orgCalls += 1; return new TypeError('x'); } });
  const domains = Array.from({ length: 6 }, (_, i) => `example${i}.test`);
  const rs = await Promise.all(domains.map((d) => rdapDomain(d, { fetchImpl: f, registryRetryMs: 25 })));
  assert.equal(rs.filter((r) => r.ok).length, 6, rs.map((r) => r.error).join(' | '));
  assert.equal(maxInFlight, 1, 'one request at a time to one registry server');
  assert.equal(orgCalls, 0, 'rdap.org would only forward to the same registry');
});

test('registries: a Retry-After is honoured before the server is asked again', async () => {
  let calls = 0;
  const at = [];
  const f = mockFetch({
    ...BOOT,
    'https://tld.registry.test/': () => {
      calls += 1;
      at.push(Date.now());
      if (calls === 1) {
        const res = jsonResponse({ errorCode: 429 }, 429);
        res.headers.set('retry-after', '1');
        return res;
      }
      return GITHUB_COM;
    }
  });
  const r = await rdapDomain('example.test', { fetchImpl: f, registryRetryMs: 10 });
  assert.equal(r.ok, true);
  assert.ok(at[1] - at[0] >= 950, `waited ${at[1] - at[0]} ms`);
});

test('registries: one that keeps answering 429 fails as rate limited after its retries, without rdap.org', async () => {
  let orgCalls = 0;
  const f = mockFetch({ ...BOOT, 'https://tld.registry.test/': () => jsonResponse({ errorCode: 429 }, 429), [RDAP_ORG]: () => { orgCalls += 1; return GITHUB_COM; } });
  const r = await rdapDomain('example.test', { fetchImpl: f, registryRetryMs: 5 });
  assert.deepEqual([r.ok, r.errorKind, r.httpStatus], [false, 'rate-limit', 429]);
  assert.equal(orgCalls, 0);
  assert.equal(f.calls.filter((c) => c.url.startsWith('https://tld.registry.test/')).length, 4, 'asked once and again three times');
});

test('rdap.org pauses for its own 429 only: a registry\'s 429 behind its redirect, or a registry that gave no readable answer either, does not', async () => {
  // rdap.org redirected to the registry, which answered 429 (the final URL is the registry's).
  let orgCalls = 0;
  const f = mockFetch({
    ...BOOT,
    'https://tld.registry.test/': () => new TypeError('Failed to fetch'),
    [RDAP_ORG]: (u) => { orgCalls += 1; return redirectedResponse(`https://tld.registry.test/domain/${u.split('/').pop()}`, { errorCode: 429 }, 429); }
  });
  await rdapDomain('a.test', { fetchImpl: f, rdapOrgIntervalMs: 0, registryRetryMs: 5 });
  const second = await rdapDomain('b.test', { fetchImpl: f, rdapOrgIntervalMs: 0, registryRetryMs: 5 });
  assert.equal(orgCalls, 2, 'not paused: the 429 was the registry\'s');
  assert.equal(second.rdapOrgPaused, undefined);
  // The registry fails without a readable answer (CORS) and so does the redirect: the registry again, not rdap.org's limit.
  clearRdapCache();
  let n = 0;
  const g = mockFetch({ ...BOOT, 'https://tld.registry.test/': () => new TypeError('Failed to fetch'), [RDAP_ORG]: () => { n += 1; return new TypeError('Failed to fetch'); } });
  await rdapDomain('a.test', { fetchImpl: g, rdapOrgIntervalMs: 0 });
  const again = await rdapDomain('b.test', { fetchImpl: g, rdapOrgIntervalMs: 0 });
  assert.equal(n, 2, 'asked again: nothing says rdap.org was limited');
  assert.equal(again.rdapOrgPaused, undefined);
});

test('RDAP_OVERRIDES: a 404 from an override server is not conclusive (it answers 404 for TLDs it does not serve too): no "not registered", no rdap.org', async () => {
  let orgCalls = 0;
  const f = mockFetch({
    ...BOOT,
    'https://rdap.identitydigital.services/rdap/domain/': () => jsonResponse({ errorCode: 404, title: 'Not Found' }, 404),
    [RDAP_ORG]: () => { orgCalls += 1; return jsonResponse({ errorCode: 404, title: 'No RDAP service is available for this resource' }, 404); }
  });
  const r = await rdapDomain('example.io', { fetchImpl: f });
  assert.equal(r.notFound, false, 'never "not registered" on the override\'s word');
  assert.equal(r.unsupportedTld, false);
  assert.deepEqual([r.ok, r.errorKind, r.httpStatus], [false, 'http', 404]);
  assert.match(r.error, /not conclusive/);
  assert.equal(orgCalls, 0, 'rdap.org does not serve the TLD either');
});

/** A registry's 429 with this Retry-After header value. */
function tooMany(retryAfter) {
  const res = jsonResponse({ errorCode: 429 }, 429);
  if (retryAfter !== null) res.headers.set('retry-after', retryAfter);
  return res;
}

test('registries: a Retry-After past the wait a lookup takes (an hour, in seconds or as a date; one past setTimeout\'s range) fails that lookup and every one queued or asked after it at once, with the time left; nothing sleeps', async () => {
  const cases = [
    ['3600 s', () => '3600', 3500e3],
    ['an HTTP date an hour ahead', () => new Date(Date.now() + 3600e3).toUTCString(), 3500e3],
    ['99999999 s (past 2^31 ms)', () => '99999999', 2 ** 31]
  ];
  for (const [label, header, atLeast] of cases) {
    clearRdapCache();
    let calls = 0;
    let orgCalls = 0;
    const f = mockFetch({
      ...BOOT,
      'https://tld.registry.test/': () => { calls += 1; return tooMany(header()); },
      [RDAP_ORG]: () => { orgCalls += 1; return GITHUB_COM; }
    });
    const warnings = [];
    const onWarning = (w) => warnings.push(w.name);
    process.on('warning', onWarning);
    const t0 = Date.now();
    // bounded: a lookup that sleeps is cut short (AbortError) instead of holding the test for an hour
    const signal = AbortSignal.timeout(3000);
    try {
      const queued = await Promise.all(['a.test', 'b.test', 'c.test'].map((d) => rdapDomain(d, { fetchImpl: f, signal })));
      const later = await rdapDomain('d.test', { fetchImpl: f, signal });
      await new Promise((r) => setImmediate(r));
      assert.ok(Date.now() - t0 < 1500, `${label}: nobody waited (${Date.now() - t0} ms)`);
      assert.deepEqual([calls, orgCalls], [1, 0], `${label}: the registry asked once, rdap.org never`);
      for (const r of [...queued, later]) {
        assert.deepEqual([r.ok, r.errorKind, r.httpStatus], [false, 'rate-limit', 429], `${label}: ${r.domain}`);
        assert.ok(r.retryAfterMs >= atLeast, `${label}: ${r.domain} says how long is left (${r.retryAfterMs})`);
      }
      assert.deepEqual(warnings, [], `${label}: no timer past its range`);
    } finally {
      process.off('warning', onWarning);
    }
  }
});

test('registries: rdap.org\'s redirect to a registry that asks for an hour blocks that registry the same way, without a sleep', async () => {
  let calls = 0;
  let orgCalls = 0;
  const f = mockFetch({
    ...BOOT,
    'https://tld.registry.test/': () => { calls += 1; return new TypeError('Failed to fetch'); },
    [RDAP_ORG]: (u) => {
      orgCalls += 1;
      const res = tooMany('3600');
      Object.defineProperty(res, 'url', { value: `https://tld.registry.test/domain/${u.split('/').pop()}` });
      return res;
    }
  });
  const t0 = Date.now();
  const signal = AbortSignal.timeout(3000);
  const first = await rdapDomain('a.test', { fetchImpl: f, rdapOrgIntervalMs: 0, signal });
  const rest = await Promise.all(['b.test', 'c.test'].map((d) => rdapDomain(d, { fetchImpl: f, rdapOrgIntervalMs: 0, signal })));
  assert.ok(Date.now() - t0 < 1500, `nobody waited (${Date.now() - t0} ms)`);
  assert.deepEqual([calls, orgCalls], [1, 1], 'neither asked again within the hour');
  for (const r of [first, ...rest]) assert.deepEqual([r.ok, r.errorKind, r.httpStatus], [false, 'rate-limit', 429], r.domain);
  assert.ok(rest.every((r) => r.retryAfterMs > 3500e3), 'the time left');
});

test('registries: one that answers 429 to everything costs one lookup\'s retries; the lookups queued behind it fail at once until its wait ends, then it is asked again', async () => {
  let calls = 0;
  const f = mockFetch({ ...BOOT, 'https://tld.registry.test/': () => { calls += 1; return tooMany(null); } });
  const t0 = Date.now();
  const signal = AbortSignal.timeout(3000);
  const rs = await Promise.all(['a.test', 'b.test', 'c.test', 'd.test'].map((d) => rdapDomain(d, { fetchImpl: f, registryRetryMs: 20, signal })));
  assert.equal(calls, 4, 'a.test: once and three retries (20, 40, 80 ms); the others are not sent');
  assert.ok(rs.every((r) => !r.ok && r.errorKind === 'rate-limit' && r.httpStatus === 429), rs.map((r) => r.error).join(' | '));
  assert.ok(rs.every((r) => r.retryAfterMs > 0 && r.retryAfterMs <= 160), `the wait left, at most 160 ms: ${rs.map((r) => r.retryAfterMs)}`);
  assert.ok(Date.now() - t0 < 1000, `the queue did not wait its turn (${Date.now() - t0} ms)`);
  await new Promise((r) => setTimeout(r, 220));
  await rdapDomain('e.test', { fetchImpl: f, registryRetryMs: 20 });
  assert.equal(calls, 8, 'after the wait the next lookup is sent again');
});
