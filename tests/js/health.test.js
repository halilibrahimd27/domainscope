import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  domainHealth, parseSpf, parseDmarc, parseCaa, parseCaaIssueValue, parseDkim, rsaKeyBits,
  spfLookupCount, caaDomainsForIssuer, caaIssuerInfo, checkCaaAllows, findCaa,
  DEFAULT_DKIM_SELECTORS, HEALTH_I18N, HEALTH_CHECK_IDS, HEALTH_CATEGORIES, SPF_LOOKUP_LIMIT
} from '../../assets/js/lib/health.js';
import { clearRdapCache, IANA_BOOTSTRAP } from '../../assets/js/lib/rdap.js';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';

/* ==================================================================== */
/* Fake DNS (DohClient contract, §5.9) built on real wire-format RRs     */
/* ==================================================================== */

/** Real decoded RR objects (same shapes as DohClient answers). */
function rrs(list) {
  if (!list.length) return [];
  return decodeMessage(encodeMessage({ answers: list.map((r) => ({ ttl: 300, ...r })) })).answers;
}

/** Like DNS providers do: split TXT strings longer than 255 bytes into character-strings. */
function splitTxt(data) {
  const parts = [];
  for (const str of Array.isArray(data) ? data : [data]) {
    if (str.length <= 255) parts.push(str);
    else for (let i = 0; i < str.length; i += 255) parts.push(str.slice(i, i + 255));
  }
  return parts;
}

/** Zone values: one record or an array of records (a TXT record may itself be an array of strings). */
const asList = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

/**
 * A zone map { name: { TYPE: value | value[] , CNAME: target } } served with
 * DohClient semantics: CNAME chains, NXDOMAIN, NODATA with the enclosing
 * SOA in the authority section, wildcard owners ('*.example.com'), AD flag
 * for names under `signed` zones, broken-DNSSEC zones (SERVFAIL unless CD=1,
 * DS still served by the parent), and per-name/type transport failures.
 * TXT values: 'string' or ['chunk1', 'chunk2'] per record.
 */
function fakeDns(zone, {
  signed = [], broken = [], fail = {}, rcodes = {}, resolveHost = true, detectWildcard = true, delayMs = 0
} = {}) {
  const calls = [];
  const under = (name, list) => list.some((z) => name === z || name.endsWith(`.${z}`));
  const lookup = (name) => {
    if (zone[name]) return zone[name];
    const labels = name.split('.');
    for (let i = 1; i < labels.length - 1; i += 1) {
      const w = `*.${labels.slice(i).join('.')}`;
      if (zone[w]) return zone[w];
    }
    return null;
  };
  const soaOwner = (name) => {
    let cur = name;
    while (cur.includes('.')) {
      if (zone[cur] && zone[cur].SOA) return cur;
      cur = cur.slice(cur.indexOf('.') + 1);
    }
    return null;
  };
  const base = (name, type, extra) => ({
    name, type, resolver: 'fake', ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: false, cd: false },
    answers: [], authorities: [], ecs: null, ede: [], elapsedMs: 1, error: null, errorKind: null, ...extra
  });

  async function query(qname, type = 'A', { cd = false, dnssec = false, signal } = {}) {
    throwIfAborted(signal);
    if (delayMs) {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, delayMs);
        signal?.addEventListener('abort', () => { clearTimeout(t); reject(signal.reason); }, { once: true });
      });
    }
    const name = String(qname).toLowerCase().replace(/\.$/, '');
    calls.push({ name, type, cd, dnssec });
    const f = fail[`${name}|${type}`] ?? fail[name];
    if (f) {
      if (f instanceof Error) throw f;
      return base(name, type, { ok: false, rcode: null, flags: null, error: f, errorKind: 'network' });
    }
    const forced = rcodes[`${name}|${type}`];
    if (forced) return base(name, type, { rcode: forced });
    const brokenZone = under(name, broken) && !(type === 'DS' && broken.includes(name));
    if (brokenZone && !cd) {
      return base(name, type, { rcode: 'SERVFAIL', ede: [{ code: 9, name: 'DNSKEY Missing', text: 'no SEP matching the DS found.' }] });
    }
    const answers = [];
    let cur = name;
    let rcode = 'NOERROR';
    for (let i = 0; i < 12; i += 1) {
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
      for (const data of asList(node[type])) answers.push({ name: cur, type, data: type === 'TXT' ? splitTxt(data) : data });
      break;
    }
    const res = base(name, type, { rcode, answers: rrs(answers) });
    if (!res.answers.some((rr) => rr.type === type)) {
      const owner = soaOwner(cur);
      if (owner) res.authorities = rrs([{ name: owner, type: 'SOA', data: zone[owner].SOA }]);
    }
    res.flags = { ...res.flags, ad: under(cur, signed) && !cd, cd };
    return res;
  }

  const dns = { calls, query };
  if (resolveHost) {
    dns.resolveHost = async (name, { signal } = {}) => {
      const [a, aaaa] = await Promise.all([query(name, 'A', { signal }), query(name, 'AAAA', { signal })]);
      const cnames = a.answers.filter((rr) => rr.type === 'CNAME').map((rr) => rr.data);
      const status = a.ok ? a.rcode : 'ERROR';
      return {
        name, status, cnames,
        ipv4: a.answers.filter((rr) => rr.type === 'A').map((rr) => rr.data),
        ipv6: aaaa.answers.filter((rr) => rr.type === 'AAAA').map((rr) => rr.data),
        ttl: 300, resolver: 'fake', error: a.ok ? null : a.error
      };
    };
  }
  if (detectWildcard && resolveHost) {
    dns.detectWildcard = async (domain, { signal } = {}) => {
      const probes = await Promise.all(['zz9probe1', 'zz9probe2'].map((l) => dns.resolveHost(`${l}.${domain}`, { signal })));
      const hits = probes.filter((p) => p.status === 'NOERROR' && (p.ipv4.length || p.ipv6.length || p.cnames.length));
      return {
        wildcard: hits.length > 0,
        ipv4: [...new Set(hits.flatMap((h) => h.ipv4))],
        ipv6: [...new Set(hits.flatMap((h) => h.ipv6))],
        cnames: hits.length ? hits[0].cnames : [],
        probes: probes.map((p) => ({ name: p.name, status: p.status })),
        error: null
      };
    };
  }
  return dns;
}

/* ==================================================================== */
/* Keys and fixtures                                                    */
/* ==================================================================== */

const spki = (bits) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const KEY_2048 = spki(2048);
const KEY_1024 = spki(1024);
let KEY_512 = null;
try { KEY_512 = spki(512); } catch { /* OpenSSL policy may forbid it */ }
const KEY_2048_PKCS1 = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64');
const ED25519 = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64');

// DNSKEY records → decoded key tags → DS that matches the KSK.
const KSK = { flags: 257, protocol: 3, algorithm: 13, publicKey: randomBytes(64).toString('base64') };
const ZSK = { flags: 256, protocol: 3, algorithm: 13, publicKey: randomBytes(64).toString('base64') };
const [KSK_RR] = rrs([{ name: 'example.com', type: 'DNSKEY', data: KSK }]);
const DS_OK = { keyTag: KSK_RR.data.keyTag, algorithm: 13, digestType: 2, digest: 'ab'.repeat(32) };

const SOA = (zone) => ({
  mname: `ns1.dns-a.net`, rname: `hostmaster.${zone}`, serial: 2026092301, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600
});

/** A healthy, fully configured zone. */
function goodZone() {
  return {
    'example.com': {
      SOA: SOA('example.com'),
      NS: ['ns1.dns-a.net', 'ns2.dns-b.org'],
      A: ['93.184.215.14'],
      AAAA: ['2606:2800:21f:cb07:6820:80da:af6b:8b2c'],
      MX: [{ preference: 20, exchange: 'mx2.example.com' }, { preference: 10, exchange: 'mx1.example.com' }],
      TXT: ['v=spf1 mx include:_spf.mailer.net -all', 'google-site-verification=abc'],
      CAA: [
        { flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=dns-01' },
        { flags: 0, tag: 'issuewild', value: ';' },
        { flags: 0, tag: 'iodef', value: 'mailto:sec@example.com' }
      ],
      DS: [DS_OK],
      DNSKEY: [KSK, ZSK],
      HTTPS: [{ priority: 1, target: '.', params: { alpn: ['h3', 'h2'], ech: 'AEX+DQBB' } }]
    },
    'ns1.dns-a.net': { A: ['198.51.100.1'], AAAA: ['2001:db8:1::1'] },
    'ns2.dns-b.org': { A: ['203.0.113.1'] },
    'mx1.example.com': { A: ['192.0.2.10'] },
    'mx2.example.com': { A: ['192.0.2.20'] },
    '_spf.mailer.net': { TXT: ['v=spf1 ip4:198.51.100.0/24 include:_spf2.mailer.net ~all'] },
    '_spf2.mailer.net': { TXT: [['v=spf1 ip6:2001:db8::/32', ' -all']] },
    '_dmarc.example.com': { TXT: ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:x@reports.vendor.net; pct=100'] },
    'example.com._report._dmarc.reports.vendor.net': { TXT: ['v=DMARC1'] },
    'selector1._domainkey.example.com': { TXT: [`v=DKIM1; k=rsa; p=${KEY_2048}`] },
    '_mta-sts.example.com': { TXT: ['v=STSv1; id=20260101'] },
    '_smtp._tls.example.com': { TXT: ['v=TLSRPTv1; rua=mailto:tls@example.com'] },
    'default._bimi.example.com': { TXT: ['v=BIMI1; l=https://example.com/logo.svg'] }
  };
}

const DNS_BOOTSTRAP = { services: [[['com', 'net', 'org'], ['https://rdap.verisign.com/com/v1/']]] };

function rdapBody({ expires = '2030-01-01T00:00:00Z', status = ['client transfer prohibited'], nameservers = ['NS1.DNS-A.NET', 'NS2.DNS-B.ORG'] } = {}) {
  return {
    objectClassName: 'domain',
    ldhName: 'EXAMPLE.COM',
    status,
    entities: [{ roles: ['registrar'], publicIds: [{ type: 'IANA Registrar ID', identifier: '376' }], vcardArray: ['vcard', [['fn', {}, 'text', 'Acme Registrar']]] }],
    events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }, ...(expires ? [{ eventAction: 'expiration', eventDate: expires }] : [])],
    secureDNS: { delegationSigned: true },
    nameservers: nameservers.map((n) => ({ ldhName: n }))
  };
}

/** fetch mock for RDAP: bootstrap + one domain route (object | status number | Error). */
function rdapFetch(domainBody = rdapBody()) {
  const calls = [];
  const impl = async (url) => {
    const u = String(url);
    calls.push(u);
    if (u === IANA_BOOTSTRAP.dns) return new Response(JSON.stringify(DNS_BOOTSTRAP), { status: 200 });
    if (u.startsWith('https://rdap.verisign.com/')) {
      if (domainBody instanceof Error) throw domainBody;
      if (typeof domainBody === 'number') return new Response('{"errorCode":404}', { status: domainBody });
      return new Response(JSON.stringify(domainBody), { status: 200 });
    }
    throw new TypeError(`unexpected fetch ${u}`);
  };
  impl.calls = calls;
  return impl;
}

const NOW = new Date('2026-09-23T12:00:00Z');
const ids = (report) => report.checks.map((c) => c.id);
const find = (report, id) => report.checks.find((c) => c.id === id);
const has = (report, id, severity) => {
  const c = find(report, id);
  assert.ok(c, `expected check ${id}; got ${ids(report).join(', ')}`);
  if (severity) assert.equal(c.severity, severity, `${id} severity`);
  return c;
};
const lacks = (report, id) => assert.ok(!find(report, id), `unexpected check ${id}`);

/** Every text of every emitted check must exist (en + tr) and every placeholder must be filled. */
function assertRenderable(report) {
  for (const c of report.checks) {
    assert.ok(HEALTH_CHECK_IDS.includes(c.id), `unknown id ${c.id}`);
    assert.equal(c.titleKey, `health.${c.id}.title`);
    assert.equal(c.detailKey, `health.${c.id}.detail`);
    assert.equal(c.group, HEALTH_CATEGORIES[c.category]);
    for (const lang of ['en', 'tr']) {
      for (const key of [c.titleKey, c.detailKey]) {
        const text = HEALTH_I18N[lang][key];
        assert.equal(typeof text, 'string', `${lang} ${key}`);
        for (const [, p] of text.matchAll(/\{(\w+)\}/g)) {
          assert.ok(p in c.params, `${key} needs param {${p}} (${lang})`);
        }
      }
    }
    for (const v of Object.values(c.params)) assert.ok(typeof v === 'string' || typeof v === 'number', `${c.id} param type`);
  }
}

const run = (domain, dns, opts = {}) => domainHealth(domain, {
  dns, rdap: false, dkimSelectors: ['selector1', 's1'], now: NOW, ...opts
});

beforeEach(() => clearRdapCache());

/* ==================================================================== */
/* domainHealth — full report                                           */
/* ==================================================================== */

test('domainHealth: healthy domain — records, checks, RDAP, progress, i18n', async () => {
  const dns = fakeDns(goodZone(), { signed: ['example.com'] });
  const f = rdapFetch();
  const progress = [];
  const r = await domainHealth('Example.COM.', {
    dns, fetchImpl: f, now: NOW, dkimSelectors: ['selector1', 'google'], onProgress: (p) => progress.push(p)
  });
  assertRenderable(r);
  assert.equal(r.domain, 'example.com');
  assert.equal(r.zone, 'example.com');
  assert.equal(r.checkedAt, NOW);
  assert.deepEqual(r.summary.error, 0, ids(r).join());
  assert.deepEqual(r.summary.warn, 0, r.checks.filter((c) => c.severity === 'warn').map((c) => c.id).join());

  // records
  assert.deepEqual(r.records.ns, ['ns1.dns-a.net', 'ns2.dns-b.org']);
  assert.equal(r.records.soa.serial, 2026092301);
  assert.deepEqual(r.records.mx, [{ preference: 10, exchange: 'mx1.example.com' }, { preference: 20, exchange: 'mx2.example.com' }]);
  assert.deepEqual(r.records.a, ['93.184.215.14']);
  assert.deepEqual(r.records.aaaa, ['2606:2800:21f:cb07:6820:80da:af6b:8b2c']);
  assert.deepEqual(r.records.txt, ['v=spf1 mx include:_spf.mailer.net -all', 'google-site-verification=abc']);
  assert.equal(r.records.spf, 'v=spf1 mx include:_spf.mailer.net -all');
  assert.match(r.records.dmarc, /^v=DMARC1; p=reject/);
  assert.equal(r.records.dkim.length, 1);
  assert.equal(r.records.dkim[0].selector, 'selector1');
  assert.equal(r.records.dkim[0].keyBits, 2048);
  assert.equal(r.records.caa.length, 3);
  assert.equal(r.records.mtaSts, 'v=STSv1; id=20260101');
  assert.equal(r.records.tlsRpt, 'v=TLSRPTv1; rua=mailto:tls@example.com');
  assert.equal(r.records.bimi, 'v=BIMI1; l=https://example.com/logo.svg');
  assert.equal(r.records.ds.length, 1);
  assert.equal(r.records.dnskey.length, 2);
  assert.equal(r.records.https.length, 1);

  // sections
  assert.deepEqual(r.dnssec, {
    signed: true, validated: true, broken: false, dsCount: 1, dnskeyCount: 2, algorithms: ['ECDSAP256SHA256'], ede: []
  });
  assert.equal(r.spf.lookups.count, 3); // mx + include + nested include
  assert.equal(r.spf.lookups.voidCount, 0);
  assert.equal(r.dmarc.foundAt, 'example.com');
  assert.equal(r.caa.foundAt, 'example.com');
  assert.equal(r.wildcard.wildcard, false);
  assert.equal(r.rdap.ok, true);
  assert.equal(r.rdap.registrar, 'Acme Registrar');
  assert.deepEqual(r.nsAddresses['ns1.dns-a.net'], ['198.51.100.1', '2001:db8:1::1']);

  for (const [id, sev] of [
    ['soa.ok', 'ok'], ['ns.ok', 'ok'], ['ns.diversity', 'ok'], ['apex.ok', 'ok'], ['ipv6.present', 'ok'],
    ['https-rr.present', 'info'], ['wildcard.none', 'ok'], ['mx.ok', 'ok'], ['spf.present', 'ok'], ['spf.all-fail', 'ok'],
    ['spf.lookups-ok', 'ok'], ['dmarc.policy-reject', 'ok'], ['dkim.found', 'ok'], ['mta-sts.present', 'ok'],
    ['tls-rpt.present', 'ok'], ['bimi.present', 'ok'], ['caa.present', 'ok'], ['dnssec.ok', 'ok'], ['rdap.expiry-ok', 'ok']
  ]) has(r, id, sev);
  assert.equal(find(r, 'spf.lookups-ok').params.count, 3);
  assert.equal(find(r, 'https-rr.present').params.alpn, 'h3, h2');
  assert.equal(find(r, 'https-rr.present').params.ech, 'yes');
  assert.equal(find(r, 'caa.present').params.issuers, 'letsencrypt.org');
  assert.equal(find(r, 'caa.present').params.wildIssuers, '—');
  assert.equal(find(r, 'rdap.expiry-ok').params.date, '2030-01-01');
  assert.equal(find(r, 'rdap.expiry-ok').params.days, 1195);
  lacks(r, 'ns.rdap-mismatch');
  lacks(r, 'dmarc.rua-unauthorized');

  // checks are grouped in category order
  const order = Object.keys(HEALTH_CATEGORIES);
  const positions = r.checks.map((c) => order.indexOf(c.category));
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b));
  assert.equal(r.summary.ok + r.summary.info + r.summary.warn + r.summary.error, r.checks.length);

  // progress: every step reported once, done increments to total
  assert.equal(progress.length, 10);
  assert.deepEqual(progress.map((p) => p.done), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.ok(progress.every((p) => p.total === 10));
  assert.deepEqual(new Set(progress.map((p) => p.step)).size, 10);
});

test('domainHealth: validates input and requires a DNS client', async () => {
  await assert.rejects(domainHealth('not a domain', { dns: fakeDns({}) }), TypeError);
  await assert.rejects(domainHealth('example.com', {}), TypeError);
  await assert.rejects(domainHealth('example.com', { dns: {} }), TypeError);
});

test('domainHealth: abort before and during the run', async () => {
  await assert.rejects(run('example.com', fakeDns(goodZone()), { signal: AbortSignal.abort() }), { name: 'AbortError' });
  const ctl = new AbortController();
  const p = run('example.com', fakeDns(goodZone(), { delayMs: 20 }), { signal: ctl.signal });
  setTimeout(() => ctl.abort(), 5);
  await assert.rejects(p, { name: 'AbortError' });
});

test('domainHealth: NXDOMAIN short-circuits to domain.nxdomain (+ RDAP)', async () => {
  const dns = fakeDns({ 'other.com': { A: ['1.1.1.1'] } });
  const r = await domainHealth('gone.com', { dns, fetchImpl: rdapFetch(404), now: NOW });
  assertRenderable(r);
  assert.deepEqual(ids(r), ['domain.nxdomain', 'rdap.not-found']);
  assert.equal(r.summary.error, 1);
  assert.deepEqual(r.records.ns, []);
});

test('domainHealth: NXDOMAIN below a live zone is a dangling CNAME or a missing name, not an unregistered domain', async () => {
  const zone = goodZone();
  zone['example.net'] = { SOA: SOA('example.net'), NS: ['ns1.dns-a.net'] };
  zone['shop.example.com'] = { CNAME: 'gone.example.net' };

  // RFC 6604: NXDOMAIN with the CNAME in the answer
  let r = await domainHealth('shop.example.com', { dns: fakeDns(zone), fetchImpl: rdapFetch(), now: NOW });
  assertRenderable(r);
  lacks(r, 'domain.nxdomain');
  const c = has(r, 'domain.dangling-cname', 'error');
  assert.equal(c.params.target, 'gone.example.net');
  assert.equal(c.params.chain, 'shop.example.com → gone.example.net');
  assert.equal(r.zone, 'example.com'); // not the target's zone
  has(r, 'rdap.expiry-ok'); // the registrable domain itself is fine

  r = await run('nosuch.example.com', fakeDns(zone));
  assertRenderable(r);
  assert.deepEqual(ids(r), ['domain.name-missing']);
  assert.equal(find(r, 'domain.name-missing').params.zone, 'example.com');
  assert.equal(r.zone, 'example.com');

  // below a registrable domain that does not exist either: the domain is not delegated
  r = await run('www.example.net', fakeDns({ 'example.com': zone['example.com'] }));
  assert.deepEqual(ids(r), ['domain.nxdomain']);
});

test('domainHealth: works with a minimal client (query only) and tolerates throwing queries', async () => {
  const zone = goodZone();
  const dns = fakeDns(zone, { resolveHost: false, detectWildcard: false, signed: ['example.com'] });
  const r = await run('example.com', dns);
  assertRenderable(r);
  has(r, 'ns.ok');
  has(r, 'mx.ok');
  has(r, 'wildcard.none', 'ok');
  assert.ok(dns.calls.some((c) => c.name.endsWith('.example.com') && /^[a-z0-9]{16}\./.test(c.name)), 'random wildcard probes');

  const throwing = fakeDns(zone, { fail: { '_dmarc.example.com': new Error('socket hang up') } });
  const r2 = await run('example.com', throwing);
  has(r2, 'dmarc.error', 'warn');
  assert.match(find(r2, 'dmarc.error').params.error, /socket hang up/);
});

/* ==================================================================== */
/* SOA / zone apex / NS                                                 */
/* ==================================================================== */

test('SOA timer warnings', async () => {
  const zone = goodZone();
  zone['example.com'].SOA = { ...SOA('example.com'), refresh: 3600, retry: 7200, expire: 86400, minimum: 172800 };
  const r = await run('example.com', fakeDns(zone));
  assertRenderable(r);
  has(r, 'soa.retry', 'warn');
  has(r, 'soa.expire', 'warn');
  has(r, 'soa.minimum', 'info');
  assert.equal(find(r, 'soa.ok').params.email, 'hostmaster@example.com');
});

test('not a zone apex; CNAME alias', async () => {
  const zone = goodZone();
  zone['www.example.com'] = { CNAME: 'example.com' };
  zone['app.example.com'] = { A: ['93.184.215.15'] };
  const r = await run('www.example.com', fakeDns(zone));
  assertRenderable(r);
  assert.equal(r.zone, 'example.com');
  has(r, 'soa.not-apex', 'warn');
  assert.equal(find(r, 'apex.cname').params.target, 'example.com');
  const plain = await run('app.example.com', fakeDns(zone));
  has(plain, 'soa.not-apex');
  lacks(plain, 'ns.none');
  lacks(plain, 'dnssec.unsigned');
  lacks(plain, 'apex.cname');
  assert.equal(plain.zone, 'example.com');
  assert.ok(!(plain.dnssec.signed === false && plain.dnssec.validated === true));
});

test('CNAME to another zone: SOA / NS of the target are not attributed to the alias', async () => {
  const zone = goodZone();
  zone['example.net'] = { SOA: SOA('example.net'), NS: ['ns1.example.net'], A: ['192.0.2.80'] };
  zone['ns1.example.net'] = { A: ['198.51.100.80'] };
  zone['app.example.net'] = { A: ['192.0.2.81'] };
  zone['www.example.com'] = { CNAME: 'example.net' };
  zone['shop.example.com'] = { CNAME: 'app.example.net' };
  for (const host of ['www.example.com', 'shop.example.com']) {
    const r = await run(host, fakeDns(zone));
    assertRenderable(r);
    assert.equal(r.zone, 'example.com', host); // the alias lives in example.com, not in the target's zone
    assert.equal(has(r, 'soa.not-apex', 'warn').params.zone, 'example.com');
    has(r, 'apex.cname', 'info');
    for (const id of ['ns.single', 'ns.no-ipv6', 'ns.ok', 'ns.none']) lacks(r, id);
    assert.deepEqual(r.records.ns, []);
  }
});

test('NS: single, unresolvable, private, same subnet, single provider, no IPv6', async () => {
  const zone = goodZone();
  zone['example.com'].NS = ['ns1.example.com'];
  zone['ns1.example.com'] = { A: ['198.51.100.53'] };
  let r = await run('example.com', fakeDns(zone));
  has(r, 'ns.single', 'warn');
  has(r, 'ns.no-ipv6', 'info');
  lacks(r, 'ns.same-subnet');

  zone['example.com'].NS = ['ns1.example.com', 'ns2.example.com', 'ns3.example.com', 'ns4.example.com'];
  zone['ns2.example.com'] = { A: ['198.51.100.54'] };
  zone['ns4.example.com'] = { A: ['10.0.0.53'] };
  r = await run('example.com', fakeDns(zone));
  assertRenderable(r);
  has(r, 'ns.ok');
  assert.equal(find(r, 'ns.unresolvable').params.hosts, 'ns3.example.com');
  assert.equal(find(r, 'ns.private-ip').params.hosts, 'ns4.example.com');
  has(r, 'ns.single-provider', 'info');
  assert.equal(find(r, 'ns.single-provider').params.provider, 'example.com');
  has(r, 'ns.diversity'); // 198.51.100.0/24 + 10.0.0.0/24

  zone['example.com'].NS = ['ns1.example.com', 'ns2.example.com'];
  r = await run('example.com', fakeDns(zone));
  assert.equal(find(r, 'ns.same-subnet').params.subnet, '198.51.100.0/24');
  lacks(r, 'ns.diversity');

  const noNs = goodZone();
  delete noNs['example.com'].NS;
  r = await run('example.com', fakeDns(noNs));
  has(r, 'ns.none', 'error');
  r = await run('example.com', fakeDns(goodZone(), { fail: { 'example.com|NS': 'timeout' } }));
  has(r, 'ns.error', 'error');
});

test('NS: registry (RDAP) vs zone mismatch', async () => {
  const r = await domainHealth('example.com', {
    dns: fakeDns(goodZone()), fetchImpl: rdapFetch(rdapBody({ nameservers: ['NS1.OLD-DNS.NET', 'NS2.OLD-DNS.NET'] })),
    now: NOW, dkimSelectors: []
  });
  assertRenderable(r);
  const c = has(r, 'ns.rdap-mismatch', 'warn');
  assert.equal(c.params.registry, 'ns1.old-dns.net, ns2.old-dns.net');
  assert.equal(c.params.dns, 'ns1.dns-a.net, ns2.dns-b.org');
});

/* ==================================================================== */
/* Apex / IPv6 / HTTPS / wildcard                                       */
/* ==================================================================== */

test('apex: no address, private IP, IPv6 missing', async () => {
  const zone = goodZone();
  delete zone['example.com'].A;
  delete zone['example.com'].AAAA;
  let r = await run('example.com', fakeDns(zone));
  has(r, 'apex.no-address', 'info');
  lacks(r, 'ipv6.missing');
  zone['example.com'].A = ['192.168.1.10', '93.184.215.14'];
  r = await run('example.com', fakeDns(zone));
  assert.equal(find(r, 'apex.private-ip').params.ips, '192.168.1.10');
  has(r, 'ipv6.missing', 'info');
  assertRenderable(r);
});

test('wildcard DNS: present, error (all probes SERVFAIL)', async () => {
  const zone = goodZone();
  zone['*.example.com'] = { A: ['93.184.215.99'] };
  let r = await run('example.com', fakeDns(zone));
  assert.equal(r.wildcard.wildcard, true);
  assert.equal(find(r, 'wildcard.present').params.values, '93.184.215.99');
  const dns = fakeDns(goodZone());
  dns.detectWildcard = async () => ({ wildcard: false, ipv4: [], ipv6: [], cnames: [], probes: [{ name: 'a', status: 'SERVFAIL' }, { name: 'b', status: 'ERROR' }], error: null });
  r = await run('example.com', dns);
  assert.equal(find(r, 'wildcard.error').params.error, 'SERVFAIL');
  dns.detectWildcard = async () => { throw new Error('boom'); };
  r = await run('example.com', dns);
  has(r, 'wildcard.error', 'info');
  assertRenderable(r);
});

/* ==================================================================== */
/* MX                                                                   */
/* ==================================================================== */

test('MX: none, null MX (+SPF advice), null mixed', async () => {
  const zone = goodZone();
  delete zone['example.com'].MX;
  let r = await run('example.com', fakeDns(zone));
  has(r, 'mx.none', 'info');
  lacks(r, 'mta-sts.missing'); // no mail → no MTA-STS advice

  zone['example.com'].MX = [{ preference: 0, exchange: '.' }];
  zone['example.com'].TXT = ['v=spf1 ~all'];
  r = await run('example.com', fakeDns(zone));
  has(r, 'mx.null', 'info');
  has(r, 'spf.null-mx', 'info');
  assert.deepEqual(r.records.mx, [{ preference: 0, exchange: '.' }]);

  zone['example.com'].TXT = [];
  r = await run('example.com', fakeDns(zone));
  has(r, 'spf.missing', 'info'); // null MX → only info

  zone['example.com'].MX = [{ preference: 0, exchange: '.' }, { preference: 10, exchange: 'mx1.example.com' }];
  r = await run('example.com', fakeDns(zone));
  has(r, 'mx.null-mixed', 'error');
  has(r, 'mx.ok');
  assertRenderable(r);
});

test('MX: CNAME target, unresolvable, IP literal, private IP, lookup failure', async () => {
  const zone = goodZone();
  zone['example.com'].MX = [
    { preference: 10, exchange: 'alias.example.com' },
    { preference: 20, exchange: 'missing.example.com' },
    { preference: 30, exchange: '192.0.2.99' },
    { preference: 40, exchange: 'internal.example.com' }
  ];
  zone['alias.example.com'] = { CNAME: 'mx1.example.com' };
  zone['internal.example.com'] = { A: ['10.1.1.1'] };
  let r = await run('example.com', fakeDns(zone));
  assertRenderable(r);
  assert.equal(find(r, 'mx.cname').params.hosts, 'alias.example.com');
  assert.equal(find(r, 'mx.unresolvable').params.hosts, 'missing.example.com');
  assert.equal(find(r, 'mx.ip-literal').params.hosts, '192.0.2.99');
  assert.equal(find(r, 'mx.private-ip').params.hosts, 'internal.example.com');
  lacks(r, 'mx.ok');
  assert.deepEqual(r.mxHosts['alias.example.com'].cnames, ['mx1.example.com']);
  r = await run('example.com', fakeDns(goodZone(), { fail: { 'example.com|MX': 'boom' } }));
  has(r, 'mx.error', 'warn');
  // a host whose lookup fails (SERVFAIL / transport) is not reported as unresolvable
  r = await run('example.com', fakeDns(goodZone(), { fail: { 'mx2.example.com': 'timeout' }, rcodes: { 'ns2.dns-b.org|A': 'SERVFAIL' } }));
  lacks(r, 'mx.unresolvable');
  lacks(r, 'ns.unresolvable');
  has(r, 'mx.ok');
});

/* ==================================================================== */
/* SPF                                                                  */
/* ==================================================================== */

test('parseSpf: terms, qualifiers, modifiers, CIDRs', () => {
  const p = parseSpf('v=spf1 +a -mx:mail.example.com/24//64 ~ip4:192.0.2.0/24 ?ip6:2001:DB8::/32 include:_spf.google.com exists:%{i}.bl.example.org ptr redirect=_spf.example.com exp=explain.example.com foo=bar -all');
  assert.equal(p.valid, true, JSON.stringify(p.errors));
  assert.equal(p.version, 'spf1');
  assert.deepEqual(p.terms.map((t) => `${t.qualifier}${t.mechanism}`), ['+a', '-mx', '~ip4', '?ip6', '+include', '+exists', '+ptr', '-all']);
  assert.deepEqual(p.terms[1], { qualifier: '-', mechanism: 'mx', value: 'mail.example.com', cidr4: 24, cidr6: 64, raw: '-mx:mail.example.com/24//64' });
  assert.equal(p.terms[2].value, '192.0.2.0');
  assert.equal(p.terms[2].cidr4, 24);
  assert.equal(p.terms[3].value, '2001:db8::');
  assert.equal(p.terms[3].cidr6, 32);
  assert.equal(p.all, '-');
  assert.equal(p.modifiers.redirect, '_spf.example.com');
  assert.equal(p.modifiers.exp, 'explain.example.com');
  assert.deepEqual(p.modifiers.other, { foo: 'bar' });
  assert.equal(p.lookupTerms, 5); // a mx include exists ptr (redirect ignored: all present)
  assert.deepEqual(p.warnings.map((w) => w.code), ['redirect-ignored', 'ptr']);
  assert.deepEqual(parseSpf(['v=spf1 ip4:1.2.3.4', ' -all']).terms.map((t) => t.mechanism), ['ip4', 'all']);
  assert.equal(parseSpf('V=SPF1 -ALL').all, '-');
});

test('parseSpf: errors and warnings', () => {
  const codes = (s) => parseSpf(s).errors.map((e) => e.code);
  assert.deepEqual(codes('v=spf10 -all'), ['not-spf']);
  assert.deepEqual(codes(' v=spf1 -all'), ['not-spf']);
  assert.deepEqual(codes('spf1'), ['not-spf']);
  assert.deepEqual(codes('v=spf1 inlcude:x.com -all'), ['unknown-mechanism']);
  assert.deepEqual(codes('v=spf1 include -all'), ['invalid-term']);
  assert.deepEqual(codes('v=spf1 include: -all'), ['invalid-term']);
  assert.deepEqual(codes('v=spf1 ip4:1.2.3.256 ip4:1.2.3.4/33 ip4:010.0.0.1 ip6:::1/129 ip6:1.2.3.4 all:x'), Array(6).fill('invalid-term'));
  assert.deepEqual(codes('v=spf1 a/33 mx//129 a:bad_host!/24'), Array(3).fill('invalid-term'));
  assert.deepEqual(codes('v=spf1 redirect=a.com redirect=b.com'), ['duplicate-modifier']);
  assert.deepEqual(codes('v=spf1 redirect='), ['invalid-domain-spec']);
  assert.deepEqual(codes('v=spf1 exists:%{i}.%{ir}.%{v}._spf.%{d2} -all'), []);
  assert.deepEqual(codes('v=spf1 exists:%{q}x -all'), ['invalid-term']);
  const w = (s) => parseSpf(s).warnings.map((x) => x.code);
  assert.deepEqual(w('v=spf1 -all ip4:1.2.3.4'), ['terms-after-all']);
  assert.deepEqual(w('v=spf1 ip4:0.0.0.0/0 ip6:::/0 -all'), ['broad-range', 'broad-range']);
  assert.deepEqual(w('v=spf1 -ip4:0.0.0.0/0 -all'), []); // a "-" broad range blocks, not authorizes
  // a / mx take a dual CIDR length: a/0 or mx//0 match every address like ip4:0.0.0.0/0
  assert.deepEqual(w('v=spf1 a/0 mx//0 a:mail.example.com/7 -all'), ['broad-range', 'broad-range', 'broad-range']);
  assert.deepEqual(w('v=spf1 a mx a/24 mx//64 -a/0 -all'), []);
  assert.deepEqual(w(`v=spf1 ${'ip4:192.0.2.1 '.repeat(40)}-all`), ['too-long']);
  assert.equal(parseSpf('v=spf1 -all').valid, true);
  assert.equal(parseSpf('v=spf1').all, null);
  assert.equal(parseSpf('v=spf1 redirect=_spf.x.com').lookupTerms, 1);
});

test('spfLookupCount: recursion, macros, void lookups, loops, MX limit', async () => {
  const zone = {
    'a.test': { TXT: ['v=spf1 a mx include:b.test exists:%{i}._ip.a.test exists:static.a.test ptr include:%{d}.c.test include:loop.test ~all'] },
    'b.test': { TXT: ['v=spf1 a:nohost.b.test mx:nomx.b.test -all'] },
    'nomx.b.test': { A: ['192.0.2.1'] },
    'a.test.c.test': { TXT: ['v=spf1 ip4:192.0.2.0/24 -all'] },
    'loop.test': { TXT: ['v=spf1 include:loop2.test -all'] },
    'loop2.test': { TXT: ['v=spf1 include:loop.test -all'] }
  };
  zone['a.test'].A = ['192.0.2.10'];
  const r = await spfLookupCount('a.test', { dns: fakeDns(zone) });
  // a.test: a mx include exists exists ptr include include = 8; b.test: a mx = 2; c: 0; loop: 1 + loop2: 1 (loop detected)
  assert.equal(r.count, 12);
  assert.equal(r.exceeded, true);
  assert.equal(r.limit, SPF_LOOKUP_LIMIT);
  // void: a.test mx (no MX), static.a.test exists (NXDOMAIN), nohost.b.test (NXDOMAIN), nomx.b.test MX (none)
  assert.equal(r.voidCount, 4);
  assert.deepEqual(r.errors.map((e) => e.code), ['loop']);
  assert.match(r.errors[0].detail, /a\.test → loop\.test → loop2\.test → loop\.test/);
  const t = r.tree.terms;
  assert.equal(t.find((x) => x.term === 'exists:%{i}._ip.a.test').macro, true);
  assert.equal(t.find((x) => x.term === 'exists:%{i}._ip.a.test').target, null);
  assert.equal(t.find((x) => x.term === 'include:%{d}.c.test').target, 'a.test.c.test');
  assert.equal(t.find((x) => x.term === 'include:b.test').child.count, 2);
  assert.equal(t.find((x) => x.term === 'ptr').lookup, true);
  assert.equal(r.tree.record, zone['a.test'].TXT[0]);
  assert.equal(r.tree.all, '~');
});

test('spfLookupCount: %{o} is the sender (checked) domain, %{d} the current one, also inside includes', async () => {
  const zone = {
    'example.com': { TXT: ['v=spf1 include:_spf.example.net -all'] },
    '_spf.example.net': { TXT: ['v=spf1 exists:%{o}._allow.example.net exists:%{d}._d.example.net -all'] },
    'example.com._allow.example.net': { A: ['127.0.0.2'] },
    '_spf.example.net._d.example.net': { A: ['127.0.0.2'] }
  };
  const dns = fakeDns(zone);
  const r = await spfLookupCount('example.com', { dns });
  const inc = r.tree.terms[0].child;
  assert.equal(inc.terms[0].target, 'example.com._allow.example.net');
  assert.equal(inc.terms[1].target, '_spf.example.net._d.example.net');
  assert.equal(r.voidCount, 0);
  assert.equal(r.count, 3);
  assert.ok(!dns.calls.some((c) => c.name === '_spf.example.net._allow.example.net'));
});

test('spfLookupCount: include errors, redirect, depth, too many MX, DNS errors, record option', async () => {
  const mx = Array.from({ length: 11 }, (_, i) => ({ preference: i, exchange: `mx${i}.big.test` }));
  const zone = {
    'x.test': { TXT: ['v=spf1 include:none.test include:dup.test include:nxd.test mx:big.test include:down.test redirect=r.test'] },
    'none.test': { TXT: ['hello'] },
    'dup.test': { TXT: ['v=spf1 -all', 'v=spf1 ~all'] },
    'big.test': { MX: mx },
    'r.test': { TXT: ['v=spf1 include:r2.test'] },
    'r2.test': { TXT: ['v=spf1 -all'] }
  };
  const r = await spfLookupCount('x.test', { dns: fakeDns(zone, { fail: { 'down.test|TXT': 'timeout' } }) });
  assert.deepEqual(r.errors.map((e) => e.code).sort(), ['dns-error', 'multiple-records', 'no-record', 'no-record', 'too-many-mx']);
  assert.equal(r.count, 7); // 4 includes + mx + redirect + r.test's include
  assert.equal(r.voidCount, 1); // nxd.test TXT lookup
  const redirect = r.tree.terms.find((t) => t.mechanism === 'redirect');
  assert.equal(redirect.child.domain, 'r.test');
  assert.equal(r.tree.terms.find((t) => t.term === 'include:none.test').error, 'no-record');

  // depth guard
  const chain = {};
  for (let i = 0; i < 6; i += 1) chain[`d${i}.test`] = { TXT: [`v=spf1 include:d${i + 1}.test -all`] };
  chain['d6.test'] = { TXT: ['v=spf1 -all'] };
  const deep = await spfLookupCount('d0.test', { dns: fakeDns(chain), maxDepth: 3 });
  assert.deepEqual(deep.errors.map((e) => e.code), ['depth']);
  assert.equal(deep.count, 4);

  // a known record skips the first TXT query; the domain itself failing is a dns-error
  const dns = fakeDns({});
  const known = await spfLookupCount('k.test', { dns, record: 'v=spf1 ip4:192.0.2.1 -all' });
  assert.equal(known.count, 0);
  assert.equal(dns.calls.length, 0);
  const failing = await spfLookupCount('k.test', { dns: fakeDns({}, { fail: { 'k.test|TXT': 'down' } }) });
  assert.deepEqual(failing.errors.map((e) => e.code), ['dns-error']);
  await assert.rejects(spfLookupCount('bad domain', { dns }), TypeError);
  await assert.rejects(spfLookupCount('k.test', { dns, signal: AbortSignal.abort() }), { name: 'AbortError' });
});

test('SPF checks in domainHealth: missing, multiple, +all, ?all, ~all, no all, syntax', async () => {
  const cases = [
    [[], 'spf.missing', 'warn'],
    [['v=spf1 -all', 'v=spf1 ~all'], 'spf.multiple', 'error'],
    [['v=spf1 +all'], 'spf.all-pass', 'error'],
    [['v=spf1 ?all'], 'spf.all-neutral', 'warn'],
    [['v=spf1 mx ~all'], 'spf.all-softfail', 'info'],
    [['v=spf1 mx'], 'spf.all-missing', 'warn'],
    [['v=spf1 mx inlcude:x.test -all'], 'spf.syntax', 'error'],
    [['v=spf1 -all mx'], 'spf.after-all', 'warn'],
    [['v=spf1 ptr -all'], 'spf.ptr', 'warn'],
    [['v=spf1 ip4:0.0.0.0/0 -all'], 'spf.broad', 'error'],
    [['v=spf1 ip4:10.0.0.0/7 -all'], 'spf.broad', 'warn'],
    [['v=spf1 a/0 -all'], 'spf.broad', 'error'],
    [['v=spf1 mx//0 -all'], 'spf.broad', 'error'],
    [['v=spf1 mx/4 -all'], 'spf.broad', 'warn'],
    [['v=spf1 redirect=_spf.mailer.net'], 'spf.lookups-ok', 'ok'],
    [['v=spf1 mx redirect=_spf.mailer.net -all'], 'spf.redirect-ignored', 'info'],
    [[`v=spf1 ${'ip4:192.0.2.1 '.repeat(40)}-all`], 'spf.too-long', 'warn']
  ];
  for (const [txt, id, sev] of cases) {
    const zone = goodZone();
    zone['example.com'].TXT = txt;
    const r = await run('example.com', fakeDns(zone));
    assertRenderable(r);
    has(r, id, sev);
  }
  const zone = goodZone();
  zone['example.com'].TXT = ['v=spf1 redirect=_spf.mailer.net'];
  const r = await run('example.com', fakeDns(zone));
  lacks(r, 'spf.all-missing');
});

test('SPF checks: lookup limit exceeded / high, void lookups, include errors, temp errors', async () => {
  const zone = goodZone();
  const incs = Array.from({ length: 11 }, (_, i) => `include:s${i}.mailer.net`);
  for (let i = 0; i < 11; i += 1) zone[`s${i}.mailer.net`] = { TXT: ['v=spf1 ip4:192.0.2.0/24 -all'] };
  zone['example.com'].TXT = [`v=spf1 ${incs.join(' ')} -all`];
  let r = await run('example.com', fakeDns(zone));
  assert.equal(find(r, 'spf.lookups-exceeded').params.count, 11);
  zone['example.com'].TXT = [`v=spf1 ${incs.slice(0, 9).join(' ')} -all`];
  r = await run('example.com', fakeDns(zone));
  has(r, 'spf.lookups-high', 'warn');
  zone['example.com'].TXT = ['v=spf1 a:x1.nowhere.test a:x2.nowhere.test mx:x3.nowhere.test include:gone.test include:_spf.mailer.net -all'];
  r = await run('example.com', fakeDns(zone, { fail: { '_spf2.mailer.net|TXT': 'timeout' } }));
  assertRenderable(r);
  assert.equal(find(r, 'spf.void').params.count, 4);
  assert.match(find(r, 'spf.include-error').params.details, /gone\.test: no-record/);
  assert.match(find(r, 'spf.dns-error').params.details, /_spf2\.mailer\.net: timeout/);
  r = await run('example.com', fakeDns(goodZone(), { fail: { 'example.com|TXT': 'boom' } }));
  has(r, 'spf.error', 'warn');
});

/* ==================================================================== */
/* DMARC                                                                */
/* ==================================================================== */

test('parseDmarc: tags, defaults, URIs, errors', () => {
  const p = parseDmarc('v=DMARC1; p=Quarantine; sp=none; pct=50; rua=mailto:a@x.com!10m, mailto:b@y.org; ruf=mailto:f@x.com; adkim=s; aspf=r; fo=1:d; ri=3600; zz=1');
  assert.equal(p.valid, true);
  assert.equal(p.policy, 'quarantine');
  assert.equal(p.subdomainPolicy, 'none');
  assert.equal(p.nonexistentPolicy, 'none');
  assert.equal(p.pct, 50);
  assert.deepEqual(p.rua, ['mailto:a@x.com', 'mailto:b@y.org']);
  assert.deepEqual(p.ruaTargets[0], { uri: 'mailto:a@x.com', scheme: 'mailto', address: 'a@x.com', domain: 'x.com', sizeLimit: '10m' });
  assert.deepEqual(p.ruf, ['mailto:f@x.com']);
  assert.equal(p.adkim, 's');
  assert.equal(p.aspf, 'r');
  assert.equal(p.fo, '1:d');
  assert.equal(p.ri, 3600);
  assert.deepEqual(p.warnings.map((w) => w.code), ['unknown-tag']);

  const d = parseDmarc(['v=DMARC1;', ' p=reject']);
  assert.equal(d.valid, true);
  assert.equal(d.subdomainPolicy, 'reject');
  assert.equal(d.pct, 100);
  assert.equal(d.adkim, 'r');
  assert.equal(d.np ?? d.nonexistentPolicy, 'reject');

  const codes = (s) => parseDmarc(s).errors.map((e) => e.code);
  assert.deepEqual(codes('v=DMARC2; p=none'), ['not-dmarc']);
  assert.deepEqual(codes('v=dmarc1; p=none'), ['not-dmarc']); // value is case-sensitive
  assert.deepEqual(codes('p=none; v=DMARC1'), ['not-dmarc']); // v must come first
  assert.deepEqual(codes('v=DMARC1; rua=mailto:a@b.com'), ['missing-p']);
  assert.deepEqual(codes('v=DMARC1; p=block'), ['invalid-p']);
  assert.deepEqual(codes('v=DMARC1; p=none; sp=x; pct=101; adkim=x; aspf=q'), ['invalid-sp', 'invalid-pct', 'invalid-adkim', 'invalid-aspf']);
  const w = parseDmarc('v=DMARC1; p=none; p=reject; rua=a@b.com; fo=x; ri=soon');
  assert.equal(w.policy, 'none');
  assert.deepEqual(w.warnings.map((x) => x.code).sort(), ['duplicate-tag', 'invalid-fo', 'invalid-ri', 'invalid-rua']);
});

test('DMARC checks: missing, multiple, invalid, none, quarantine, pct, sp=none, no rua', async () => {
  const cases = [
    [[], 'dmarc.missing', 'warn'],
    [['v=DMARC1; p=none', 'v=DMARC1; p=reject'], 'dmarc.multiple', 'error'],
    [['v=DMARC1; pct=100'], 'dmarc.invalid', 'error'],
    [['v=DMARC1; p=none; rua=mailto:d@example.com'], 'dmarc.policy-none', 'warn'],
    [['v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com'], 'dmarc.policy-quarantine', 'ok'],
    [['v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com'], 'dmarc.pct', 'warn'],
    [['v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com'], 'dmarc.sp-none', 'warn'],
    [['v=DMARC1; p=reject'], 'dmarc.rua-missing', 'info']
  ];
  for (const [txt, id, sev] of cases) {
    const zone = goodZone();
    zone['_dmarc.example.com'].TXT = txt;
    const r = await run('example.com', fakeDns(zone));
    assertRenderable(r);
    has(r, id, sev);
  }
  const r = await run('example.com', fakeDns(goodZone(), { fail: { '_dmarc.example.com': 'x' } }));
  has(r, 'dmarc.error');
});

test('DMARC: external report authorization and organizational-domain inheritance', async () => {
  const zone = goodZone();
  zone['_dmarc.example.com'].TXT = ['v=DMARC1; p=reject; rua=mailto:a@reports.vendor.net,mailto:b@other.vendor.org,mailto:c@sub.example.com'];
  let r = await run('example.com', fakeDns(zone));
  assert.equal(find(r, 'dmarc.rua-unauthorized').params.targets, 'other.vendor.org');

  zone['mail.example.com'] = { A: ['192.0.2.30'] };
  zone['_dmarc.example.com'].TXT = ['v=DMARC1; p=none; sp=quarantine'];
  r = await run('mail.example.com', fakeDns(zone));
  assertRenderable(r);
  assert.equal(r.dmarc.inherited, true);
  assert.equal(r.dmarc.foundAt, 'example.com');
  assert.equal(find(r, 'dmarc.inherited').params.org, 'example.com');
  has(r, 'dmarc.policy-quarantine'); // the subdomain policy applies
  lacks(r, 'dmarc.sp-none');

  // the organizational-domain lookup failing is a lookup error, not "no DMARC record"
  r = await run('mail.example.com', fakeDns(zone, { fail: { '_dmarc.example.com|TXT': 'timeout' } }));
  assertRenderable(r);
  lacks(r, 'dmarc.missing');
  assert.equal(has(r, 'dmarc.error', 'warn').params.error, '_dmarc.example.com: timeout');
  assert.equal(r.dmarc.inherited, false);
});

/* ==================================================================== */
/* DKIM                                                                 */
/* ==================================================================== */

test('rsaKeyBits / parseDkim', () => {
  assert.equal(rsaKeyBits(KEY_2048), 2048);
  assert.equal(rsaKeyBits(KEY_1024), 1024);
  assert.equal(rsaKeyBits(KEY_2048_PKCS1), 2048);
  if (KEY_512) assert.equal(rsaKeyBits(KEY_512), 512);
  assert.equal(rsaKeyBits('not base64!'), null);
  assert.equal(rsaKeyBits('AAAA'), null);
  assert.equal(rsaKeyBits(''), null);
  const folded = `${KEY_2048.slice(0, 50)} \t ${KEY_2048.slice(50)}`;
  const p = parseDkim(`v=DKIM1; k=rsa; t=y:s; p=${folded}`);
  assert.equal(p.valid, true);
  assert.equal(p.keyBits, 2048);
  assert.equal(p.testing, true);
  assert.equal(p.revoked, false);
  assert.equal(parseDkim('v=DKIM1; p=').revoked, true);
  assert.equal(parseDkim(`k=ed25519; p=${ED25519}`).keyBits, 256);
  assert.equal(parseDkim(['v=DKIM1; p=', KEY_1024]).keyBits, 1024);
  assert.equal(parseDkim('v=DKIM2; p=abc').valid, false);
  assert.equal(parseDkim('v=DKIM1').valid, false);
});

test('DKIM checks: found, 1024, weak, revoked, testing, none, error', async () => {
  const zone = goodZone();
  zone['s1._domainkey.example.com'] = { TXT: [`v=DKIM1; t=y; p=${KEY_1024}`] };
  zone['old._domainkey.example.com'] = { TXT: ['v=DKIM1; p='] };
  zone['alias._domainkey.example.com'] = { CNAME: 'selector1._domainkey.example.com' };
  if (KEY_512) zone['weak._domainkey.example.com'] = { TXT: [`p=${KEY_512}`] };
  let r = await run('example.com', fakeDns(zone), { dkimSelectors: ['selector1', 's1', 'old', 'alias', 'weak', 'none', 'Bad Selector!'] });
  assertRenderable(r);
  assert.equal(find(r, 'dkim.found').params.selectors, KEY_512 ? 'selector1, s1, alias, weak' : 'selector1, s1, alias');
  assert.equal(find(r, 'dkim.1024').params.selectors, 's1 (1024)');
  assert.equal(find(r, 'dkim.revoked').params.selectors, 'old');
  assert.equal(find(r, 'dkim.testing').params.selectors, 's1');
  if (KEY_512) has(r, 'dkim.weak', 'error');
  assert.equal(r.records.dkim.find((x) => x.selector === 'alias').cname, 'selector1._domainkey.example.com');

  r = await run('example.com', fakeDns(zone), { dkimSelectors: ['nothing1', 'nothing2'] });
  assert.equal(find(r, 'dkim.none').params.count, 2);
  r = await run('example.com', fakeDns(zone, { fail: { 'nothing1._domainkey.example.com': 'x', 'nothing2._domainkey.example.com': 'x' } }), { dkimSelectors: ['nothing1', 'nothing2'] });
  has(r, 'dkim.error', 'info');
  assert.ok(DEFAULT_DKIM_SELECTORS.includes('google') && DEFAULT_DKIM_SELECTORS.includes('selector1'));
});

test('DKIM: a wildcard *._domainkey record is detected and not reported per selector', async () => {
  const zone = goodZone();
  delete zone['selector1._domainkey.example.com'];
  zone['*._domainkey.example.com'] = { TXT: ['v=DKIM1; p='] };
  const r = await run('example.com', fakeDns(zone), { dkimSelectors: ['default', 'google', 'k1'] });
  assertRenderable(r);
  const w = has(r, 'dkim.wildcard', 'info');
  assert.equal(w.params.revoked, 'yes');
  lacks(r, 'dkim.found');
  lacks(r, 'dkim.revoked');
  lacks(r, 'dkim.none');
  assert.deepEqual(r.records.dkim.map((x) => x.selector), ['*']);
});

/* ==================================================================== */
/* CAA                                                                  */
/* ==================================================================== */

test('parseCaaIssueValue (RFC 8659 §4.2)', () => {
  assert.deepEqual(parseCaaIssueValue('letsencrypt.org; validationmethods=dns-01'),
    { issuer: 'letsencrypt.org', params: { validationmethods: 'dns-01' }, valid: true, error: null });
  assert.deepEqual(parseCaaIssueValue(' LetsEncrypt.org ;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1 ; validationmethods=http-01 '),
    { issuer: 'letsencrypt.org', params: { accounturi: 'https://acme-v02.api.letsencrypt.org/acme/acct/1', validationmethods: 'http-01' }, valid: true, error: null });
  assert.deepEqual(parseCaaIssueValue(';'), { issuer: '', params: {}, valid: true, error: null });
  assert.deepEqual(parseCaaIssueValue(''), { issuer: '', params: {}, valid: true, error: null });
  assert.equal(parseCaaIssueValue('lets encrypt').valid, false);
  assert.equal(parseCaaIssueValue('-bad.org').error, 'invalid-issuer');
  assert.equal(parseCaaIssueValue('ok.org; novalue').error, 'invalid-parameter');
  assert.equal(parseCaaIssueValue('ok.org; k=v;v').valid, false);
});

test('parseCaa: RRs, data objects, strings, critical flag, unknown tags', () => {
  const p = parseCaa([
    { type: 'CAA', data: { flags: 0, tag: 'issue', value: 'letsencrypt.org' } },
    { flags: 0, tag: 'ISSUE', value: 'pki.goog; cansignhttpexchanges=yes' },
    '0 issuewild "sectigo.com"',
    '0 iodef "mailto:security@example.com"',
    '0 iodef "ftp://nope"',
    '0 contactemail "admin@example.com"',
    '128 tbs "Unknown"',
    '0 future "x"',
    'garbage',
    null
  ]);
  assert.equal(p.count, 8);
  assert.deepEqual(p.issuers, ['letsencrypt.org', 'pki.goog']);
  assert.deepEqual(p.wildIssuers, ['sectigo.com']);
  assert.deepEqual(p.issue[1].params, { cansignhttpexchanges: 'yes' });
  assert.deepEqual(p.iodef.map((x) => x.valid), [true, false]);
  assert.deepEqual(p.other, [{ tag: 'contactemail', value: 'admin@example.com', critical: false }]);
  assert.equal(p.unknownCritical, true);
  assert.deepEqual(p.unknown.map((u) => u.tag), ['tbs', 'future']);
  assert.equal(parseCaa([]).count, 0);
  assert.equal(parseCaa(undefined).count, 0);
  // malformed values authorize nobody (RFC 8659 §4.2), so they are not listed as issuers
  assert.deepEqual(parseCaa(['0 issue "Let\'s Encrypt"', '0 issuewild "lets encrypt"']).issuers, []);
  assert.deepEqual(parseCaa(['0 issue "Let\'s Encrypt"', '0 issuewild "lets encrypt"']).wildIssuers, []);
  assert.deepEqual(parseCaa(['0 issue "letsencrypt.org"', '0 issue "pki.goog; bad"']).issuers, ['letsencrypt.org']);
});

test('caaDomainsForIssuer / caaIssuerInfo', () => {
  const m = (dn) => caaDomainsForIssuer(dn);
  assert.deepEqual(m("CN=R11,O=Let's Encrypt,C=US"), ['letsencrypt.org']);
  assert.deepEqual(m('CN=E6, O=Let\'s Encrypt, C=US'), ['letsencrypt.org']);
  assert.deepEqual(m('CN=ISRG Root X1,O=Internet Security Research Group,C=US'), ['letsencrypt.org']);
  assert.ok(m('CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US').includes('digicert.com'));
  assert.ok(m('CN=RapidSSL TLS RSA CA G1,OU=www.digicert.com,O=DigiCert Inc,C=US').includes('digicert.com'));
  assert.ok(m('CN=GeoTrust TLS RSA CA G1,O=DigiCert Inc,C=US').includes('geotrust.com'));
  assert.ok(m('CN=Thawte TLS RSA CA G1,O=DigiCert Inc,C=US').includes('thawte.com'));
  assert.ok(m('CN=Cloudflare Inc ECC CA-3,O=Cloudflare\\, Inc.,C=US').includes('digicert.com'));
  const sectigo = m('CN=Sectigo RSA Domain Validation Secure Server CA,O=Sectigo Limited,L=Salford,C=GB');
  assert.ok(sectigo.includes('sectigo.com') && sectigo.includes('comodoca.com'));
  assert.ok(m('CN=ZeroSSL RSA Domain Secure Site CA,O=ZeroSSL,C=AT').includes('sectigo.com'));
  assert.ok(m('CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited').includes('comodoca.com'));
  assert.deepEqual(m('CN=GlobalSign GCC R6 AlphaSSL CA 2025,O=GlobalSign nv-sa,C=BE'), ['globalsign.com']);
  assert.deepEqual(m('CN=Go Daddy Secure Certificate Authority - G2,O=GoDaddy.com\\, Inc.'), ['godaddy.com', 'starfieldtech.com']);
  assert.deepEqual(m('CN=Starfield Secure Certificate Authority - G2'), ['godaddy.com', 'starfieldtech.com']);
  assert.deepEqual(m('CN=WR1,O=Google Trust Services,C=US'), ['pki.goog']);
  assert.deepEqual(m('CN=GTS CA 1C3,O=Google Trust Services LLC,C=US'), ['pki.goog']);
  assert.deepEqual(m('CN=Amazon RSA 2048 M02,O=Amazon,C=US'), ['amazon.com', 'amazontrust.com', 'awstrust.com', 'amazonaws.com']);
  assert.deepEqual(m('CN=Buypass Class 2 CA 5,O=Buypass AS-983163327,C=NO'), ['buypass.com', 'buypass.no']);
  assert.deepEqual(m('CN=SSL.com RSA SSL subCA,O=SSL Corporation,C=US'), ['ssl.com']);
  assert.ok(m('CN=Entrust Certification Authority - L1K,O=Entrust\\, Inc.').includes('entrust.net'));
  assert.ok(m('CN=Certum Domain Validation CA SHA2,O=Unizeto Technologies S.A.').includes('certum.pl'));
  assert.deepEqual(m('CN=Microsoft Azure RSA TLS Issuing CA 03,O=Microsoft Corporation,C=US'), ['microsoft.com']);
  assert.deepEqual(m('CN=Actalis Organization Validated Server CA G3,O=Actalis S.p.A.'), ['actalis.it']);
  assert.deepEqual(m('CN=HARICA DV TLS RSA,O=Hellenic Academic and Research Institutions CA'), ['harica.gr']);
  assert.deepEqual(m('CN=E-Tugra SSL CA R2,O=E-Tugra EBG A.S.,C=TR'), ['e-tugra.com.tr']);
  assert.deepEqual(m({ CN: 'R10', O: "Let's Encrypt" }), ['letsencrypt.org']);
  assert.deepEqual(m('CN=Some Private CA,O=Corp'), []);
  assert.deepEqual(m(''), []);
  assert.deepEqual(m(null), []);
  assert.equal(caaIssuerInfo('CN=E-Tugra SSL CA R2,O=E-Tugra EBG A.S.')[0].distrusted, '2023');
});

test('checkCaaAllows: RFC 8659 decision table', () => {
  const LE = "CN=R11,O=Let's Encrypt,C=US";
  const recs = (...list) => list.map((s) => s);
  let r = checkCaaAllows([], LE);
  assert.equal(r.allowed, true);
  assert.equal(r.reason, 'none');
  assert.equal(r.reasonKey, 'health.caa.reason.none');
  r = checkCaaAllows(recs('0 issue "letsencrypt.org; validationmethods=dns-01"'), LE);
  assert.equal(r.allowed, true);
  assert.equal(r.reason, 'allowed');
  assert.equal(r.property, 'issue');
  assert.deepEqual(r.matched.params, { validationmethods: 'dns-01' });
  r = checkCaaAllows(recs('0 issue "digicert.com"'), LE);
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'not-listed');
  assert.deepEqual(r.authorized, ['digicert.com']);
  // wildcard: issuewild takes precedence over issue
  const mixed = recs('0 issue "letsencrypt.org"', '0 issuewild "digicert.com"');
  assert.equal(checkCaaAllows(mixed, LE, { wildcard: false }).allowed, true);
  r = checkCaaAllows(mixed, LE, { wildcard: true });
  assert.equal(r.allowed, false);
  assert.equal(r.property, 'issuewild');
  // wildcard without issuewild falls back to issue
  assert.equal(checkCaaAllows(recs('0 issue "letsencrypt.org"'), LE, { wildcard: true }).allowed, true);
  // only issuewild present → non-wildcard names are unrestricted
  r = checkCaaAllows(recs('0 issuewild ";"'), LE);
  assert.equal(r.allowed, true);
  assert.equal(r.reason, 'no-issue-property');
  assert.equal(checkCaaAllows(recs('0 issuewild ";"'), LE, { wildcard: true }).reason, 'deny-all');
  // only iodef → unrestricted
  assert.equal(checkCaaAllows(recs('0 iodef "mailto:a@b.c"'), LE).reason, 'no-issue-property');
  // deny-all
  assert.equal(checkCaaAllows(recs('0 issue ";"'), LE).reason, 'deny-all');
  // critical unknown tag
  r = checkCaaAllows(recs('0 issue "letsencrypt.org"', '128 tbs "x"'), LE);
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'critical-unknown');
  // unknown CA
  r = checkCaaAllows(recs('0 issue "letsencrypt.org"'), 'CN=Corp Private CA');
  assert.equal(r.allowed, null);
  assert.equal(r.reason, 'unknown-issuer');
  // malformed value never matches
  assert.equal(checkCaaAllows(recs('0 issue "letsencrypt.org; bad"'), LE).allowed, false);
  // parsed input, distrusted CA flag
  r = checkCaaAllows(parseCaa(recs('0 issue "e-tugra.com.tr"')), 'CN=E-Tugra SSL CA R2');
  assert.equal(r.allowed, true);
  assert.equal(r.distrusted, true);
});

test('findCaa: tree climbing stops at the registrable domain; CNAMEs; errors', async () => {
  const zone = {
    'example.com.tr': { SOA: SOA('example.com.tr'), CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }] },
    'b.example.com.tr': { A: ['192.0.2.1'] },
    'a.b.example.com.tr': { A: ['192.0.2.2'] },
    'own.example.com.tr': { CAA: [{ flags: 0, tag: 'issue', value: 'pki.goog' }] },
    'alias.example.com.tr': { CNAME: 'own.example.com.tr' },
    'nocaa.com.tr': { SOA: SOA('nocaa.com.tr') }
  };
  const dns = fakeDns(zone);
  let r = await findCaa('a.b.example.com.tr', { dns });
  assert.equal(r.foundAt, 'example.com.tr');
  assert.deepEqual(r.chain.map((c) => c.name), ['a.b.example.com.tr', 'b.example.com.tr', 'example.com.tr']);
  assert.deepEqual(r.parsed.issuers, ['letsencrypt.org']);
  assert.equal(r.records.length, 1);
  r = await findCaa('*.x.example.com.tr', { dns });
  assert.equal(r.name, 'x.example.com.tr');
  assert.equal(r.chain[0].rcode, 'NXDOMAIN');
  assert.equal(r.foundAt, 'example.com.tr');
  r = await findCaa('alias.example.com.tr', { dns });
  assert.equal(r.foundAt, 'alias.example.com.tr');
  assert.deepEqual(r.parsed.issuers, ['pki.goog']);
  const dns2 = fakeDns(zone);
  r = await findCaa('www.nocaa.com.tr', { dns: dns2 });
  assert.equal(r.foundAt, null);
  assert.equal(r.error, null);
  assert.deepEqual(dns2.calls.map((c) => c.name), ['www.nocaa.com.tr', 'nocaa.com.tr'], 'never queries com.tr / tr');
  r = await findCaa('a.b.example.com.tr', { dns: fakeDns(zone, { fail: { 'b.example.com.tr|CAA': 'timeout' } }) });
  assert.equal(r.foundAt, null);
  assert.match(r.error, /b\.example\.com\.tr: timeout/);
  r = await findCaa('a.b.example.com.tr', { dns: fakeDns(zone, { rcodes: { 'a.b.example.com.tr|CAA': 'SERVFAIL' } }) });
  assert.match(r.error, /SERVFAIL/);
  await assert.rejects(findCaa('bad name', { dns }), TypeError);
});

test('CAA checks in domainHealth: missing, deny-all, invalid, critical, distrusted, cert allowed/denied/unknown', async () => {
  const zone = goodZone();
  delete zone['example.com'].CAA;
  let r = await run('example.com', fakeDns(zone));
  has(r, 'caa.missing', 'info');

  zone['example.com'].CAA = [{ flags: 0, tag: 'issue', value: ';' }];
  r = await run('example.com', fakeDns(zone));
  has(r, 'caa.deny-all', 'warn');

  zone['example.com'].CAA = [
    { flags: 0, tag: 'issue', value: 'lets encrypt' }, { flags: 0, tag: 'issue', value: 'e-tugra.com.tr' },
    { flags: 128, tag: 'weird', value: 'x' }
  ];
  r = await run('example.com', fakeDns(zone));
  assertRenderable(r);
  assert.equal(find(r, 'caa.invalid').params.values, 'lets encrypt');
  assert.equal(find(r, 'caa.critical-unknown').params.tags, 'weird');
  assert.equal(find(r, 'caa.distrusted').params.issuers, 'e-tugra.com.tr');

  r = await run('example.com', fakeDns(goodZone()), { issuerDN: "CN=R11,O=Let's Encrypt,C=US" });
  has(r, 'caa.cert-allowed', 'ok');
  assert.equal(r.caaCert.allowed, true);
  r = await run('example.com', fakeDns(goodZone()), { issuerDN: "CN=R11,O=Let's Encrypt,C=US", wildcardCert: true });
  const denied = has(r, 'caa.cert-blocked', 'error'); // issuewild ";" lets no CA issue wildcards
  assert.equal(denied.params.property, 'issuewild');
  assert.equal(denied.params.reason, 'deny-all');
  r = await run('example.com', fakeDns(goodZone()), { issuerDN: 'CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US' });
  assert.equal(find(r, 'caa.cert-denied').params.issuer, 'DigiCert');
  r = await run('example.com', fakeDns(goodZone()), { issuerDN: 'CN=Corp CA' });
  has(r, 'caa.cert-unknown', 'info');
  assertRenderable(r);
  r = await run('example.com', fakeDns(goodZone(), { fail: { 'example.com|CAA': 'down' } }));
  has(r, 'caa.error', 'warn');
});

test('CAA: only malformed issue values forbid every CA; a blocked CA is not "missing from the list"', async () => {
  const LE = "CN=R11,O=Let's Encrypt,C=US";
  const zone = goodZone();
  zone['example.com'].CAA = [{ flags: 0, tag: 'issue', value: "Let's Encrypt" }];
  let r = await run('example.com', fakeDns(zone), { issuerDN: LE });
  assertRenderable(r);
  has(r, 'caa.invalid', 'warn');
  has(r, 'caa.deny-all', 'warn');
  lacks(r, 'caa.present');
  lacks(r, 'caa.cert-denied');
  assert.equal(has(r, 'caa.cert-blocked', 'error').params.reason, 'deny-all');

  // a malformed value next to a valid one: only the valid CA is listed
  zone['example.com'].CAA = [{ flags: 0, tag: 'issue', value: "Let's Encrypt" }, { flags: 0, tag: 'issue', value: 'letsencrypt.org' }];
  r = await run('example.com', fakeDns(zone), { issuerDN: LE });
  assert.equal(has(r, 'caa.present', 'ok').params.issuers, 'letsencrypt.org');
  has(r, 'caa.cert-allowed', 'ok');

  // an unknown critical tag blocks even a listed CA
  zone['example.com'].CAA = [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 128, tag: 'weird', value: 'x' }];
  r = await run('example.com', fakeDns(zone), { issuerDN: LE });
  assertRenderable(r);
  lacks(r, 'caa.cert-denied');
  assert.equal(has(r, 'caa.cert-blocked', 'error').params.reason, 'critical-unknown');

  // a CA missing from a real list is still "not in the list"
  r = await run('example.com', fakeDns(goodZone()), { issuerDN: 'CN=GTS CA 1C3,O=Google Trust Services LLC,C=US' });
  assert.equal(has(r, 'caa.cert-denied', 'error').params.authorized, 'letsencrypt.org');
});

/* ==================================================================== */
/* DNSSEC                                                               */
/* ==================================================================== */

test('DNSSEC: unsigned, no DS, DS without DNSKEY, mismatch, not validated, deprecated algorithms, SHA-1 DS', async () => {
  const zone = goodZone();
  delete zone['example.com'].DS;
  delete zone['example.com'].DNSKEY;
  let r = await run('example.com', fakeDns(zone));
  has(r, 'dnssec.unsigned', 'info');
  assert.equal(r.dnssec.signed, false);

  zone['example.com'].DNSKEY = [KSK, ZSK];
  r = await run('example.com', fakeDns(zone, { signed: ['example.com'] }));
  has(r, 'dnssec.no-ds', 'warn');

  delete zone['example.com'].DNSKEY;
  zone['example.com'].DS = [DS_OK];
  r = await run('example.com', fakeDns(zone));
  has(r, 'dnssec.ds-no-dnskey', 'error');

  zone['example.com'].DNSKEY = [KSK, ZSK];
  zone['example.com'].DS = [{ ...DS_OK, keyTag: (DS_OK.keyTag + 1) % 65536 }];
  r = await run('example.com', fakeDns(zone, { signed: ['example.com'] }));
  has(r, 'dnssec.ds-mismatch', 'error');

  zone['example.com'].DS = [DS_OK];
  r = await run('example.com', fakeDns(zone)); // no AD flag
  has(r, 'dnssec.not-validated', 'warn');
  assert.equal(r.dnssec.validated, false);

  const rsasha1 = { ...KSK, algorithm: 5 };
  const [rr] = rrs([{ name: 'example.com', type: 'DNSKEY', data: rsasha1 }]);
  zone['example.com'].DNSKEY = [rsasha1];
  zone['example.com'].DS = [{ keyTag: rr.data.keyTag, algorithm: 5, digestType: 1, digest: 'cd'.repeat(20) }];
  r = await run('example.com', fakeDns(zone, { signed: ['example.com'] }));
  assertRenderable(r);
  has(r, 'dnssec.ok', 'ok');
  assert.equal(find(r, 'dnssec.algorithm-deprecated').params.algorithms, 'RSASHA1');
  has(r, 'dnssec.ds-sha1', 'info');

  r = await run('example.com', fakeDns(goodZone(), { fail: { 'example.com|DS': 'x', 'example.com|DNSKEY': 'x' } }));
  has(r, 'dnssec.error', 'warn');
});

test('DNSSEC: a name below the zone apex takes the signed state of its zone (AD bit), never "unsigned but validated"', async () => {
  const zone = goodZone();
  zone['www.example.com'] = { A: ['192.0.2.41'] };
  let r = await run('www.example.com', fakeDns(zone, { signed: ['example.com'] }));
  assertRenderable(r);
  has(r, 'soa.not-apex');
  lacks(r, 'dnssec.unsigned');
  assert.equal(r.dnssec.dsCount, 0);
  assert.equal(r.dnssec.validated, true);
  assert.equal(r.dnssec.signed, true);

  // the DNSKEY lookup failed: unknown, not "not signed"
  r = await run('www.example.com', fakeDns(zone, { signed: ['example.com'], fail: { 'www.example.com|DNSKEY': 'timeout' } }));
  assert.equal(r.dnssec.signed, null);
  has(r, 'dnssec.error', 'warn');

  // an unsigned enclosing zone stays "not signed"
  delete zone['example.com'].DS;
  delete zone['example.com'].DNSKEY;
  r = await run('www.example.com', fakeDns(zone));
  assert.equal(r.dnssec.signed, false);
  assert.equal(r.dnssec.validated, false);
  lacks(r, 'dnssec.unsigned');
});

test('DNSSEC: one failed half (DS or DNSKEY) is a lookup error, not a misconfiguration', async () => {
  const noDnssecErrors = (r) => assert.deepEqual(r.checks.filter((c) => c.category === 'dnssec' && c.severity === 'error').map((c) => c.id), []);
  const signed = { signed: ['example.com'] };

  let r = await run('example.com', fakeDns(goodZone(), { ...signed, fail: { 'example.com|DNSKEY': 'timeout' } }));
  assertRenderable(r);
  assert.equal(has(r, 'dnssec.error', 'warn').params.error, 'DNSKEY: timeout');
  lacks(r, 'dnssec.ds-no-dnskey');
  noDnssecErrors(r);

  r = await run('example.com', fakeDns(goodZone(), { ...signed, fail: { 'example.com|DS': 'timeout' } }));
  assert.equal(has(r, 'dnssec.error', 'warn').params.error, 'DS: timeout');
  lacks(r, 'dnssec.no-ds');
  lacks(r, 'dnssec.unsigned');
  assert.equal(r.dnssec.signed, null);

  r = await run('example.com', fakeDns(goodZone(), { ...signed, rcodes: { 'example.com|DNSKEY': 'REFUSED' } }));
  assert.equal(has(r, 'dnssec.error', 'warn').params.error, 'DNSKEY: REFUSED');
  lacks(r, 'dnssec.ds-no-dnskey');

  // DNSKEY SERVFAIL that persists with CD=1 is not a broken chain either
  const lame = fakeDns(goodZone(), { rcodes: { 'example.com|DNSKEY': 'SERVFAIL' } });
  lame.query = ((orig) => async (n, t, o = {}) => (o.cd && t === 'SOA' ? { ...(await orig(n, t, o)), rcode: 'SERVFAIL' } : orig(n, t, o)))(lame.query);
  r = await run('example.com', lame);
  assert.equal(r.dnssec.broken, false);
  has(r, 'dnssec.error', 'warn');
  noDnssecErrors(r);
});

test('DNSSEC broken: SERVFAIL without CD, answer with CD → only dnssec.broken remains', async () => {
  const zone = goodZone();
  const dns = fakeDns(zone, { broken: ['example.com'] });
  const r = await domainHealth('example.com', { dns, fetchImpl: rdapFetch(), now: NOW, dkimSelectors: ['selector1'] });
  assertRenderable(r);
  assert.equal(r.dnssec.broken, true);
  assert.equal(r.dnssec.validated, false);
  assert.equal(r.dnssec.signed, true); // DS still served by the parent
  const c = has(r, 'dnssec.broken', 'error');
  assert.equal(c.params.ede, '9 DNSKEY Missing: no SEP matching the DS found');
  for (const id of ids(r)) assert.ok(!id.endsWith('.error'), `lookup failure ${id} should be folded into dnssec.broken`);
  assert.ok(dns.calls.some((q) => q.cd && q.type === 'SOA'), 'CD=1 probe sent');
  has(r, 'rdap.expiry-ok');

  // SERVFAIL that persists with CD=1 is not a DNSSEC problem
  const lame = fakeDns(goodZone(), { rcodes: { 'example.com|SOA': 'SERVFAIL' } });
  lame.query = ((orig) => async (n, t, o = {}) => (o.cd && t === 'SOA' ? { ...(await orig(n, t, o)), rcode: 'SERVFAIL' } : orig(n, t, o)))(lame.query);
  const r2 = await run('example.com', lame);
  assert.equal(r2.dnssec.broken, false);
  has(r2, 'soa.error', 'warn');

  // a name below a broken zone: its DS query SERVFAILs as well
  zone['www.example.com'] = { A: ['192.0.2.40'] };
  const sub = await run('www.example.com', fakeDns(zone, { broken: ['example.com'] }));
  assert.equal(sub.dnssec.broken, true);
  has(sub, 'dnssec.broken', 'error');
});

test('DNSSEC broken needs a DS and a failing SOA: other SERVFAILs keep their own checks', async () => {
  const unsigned = goodZone();
  delete unsigned['example.com'].DS;
  delete unsigned['example.com'].DNSKEY;
  /** SERVFAIL for some example.com types unless CD=1 (a flaky server, not DNSSEC). */
  const flaky = (zone, types) => {
    const dns = fakeDns(zone);
    dns.query = ((orig) => async (n, t, o = {}) => (!o.cd && n === 'example.com' && types.includes(t)
      ? { ...(await orig(n, t, o)), rcode: 'SERVFAIL', answers: [], authorities: [] }
      : orig(n, t, o)))(dns.query);
    return dns;
  };

  // unsigned zone (the DS answer proves it): a CD flip is not a broken chain
  let r = await run('example.com', flaky(unsigned, ['SOA', 'MX']));
  assertRenderable(r);
  assert.equal(r.dnssec.broken, false);
  lacks(r, 'dnssec.broken');
  has(r, 'soa.error', 'warn');
  has(r, 'mx.error', 'warn');

  // only DNSKEY fails while SOA validates: not broken, signed or not
  for (const zone of [unsigned, goodZone()]) {
    r = await run('example.com', flaky(zone, ['DNSKEY']));
    assert.equal(r.dnssec.broken, false);
    lacks(r, 'dnssec.broken');
    has(r, 'soa.ok');
    has(r, 'dnssec.error', 'warn');
  }
});

/* ==================================================================== */
/* MTA-STS / TLS-RPT / BIMI                                             */
/* ==================================================================== */

test('mail extras: MTA-STS invalid/missing, TLS-RPT missing, BIMI with weak DMARC', async () => {
  const zone = goodZone();
  zone['_mta-sts.example.com'].TXT = ['v=STSv1;'];
  delete zone['_smtp._tls.example.com'];
  zone['_dmarc.example.com'].TXT = ['v=DMARC1; p=none; rua=mailto:d@example.com'];
  let r = await run('example.com', fakeDns(zone));
  assertRenderable(r);
  has(r, 'mta-sts.invalid', 'warn');
  has(r, 'tls-rpt.missing', 'info');
  assert.equal(find(r, 'bimi.dmarc-weak').params.policy, 'none');
  zone['_mta-sts.example.com'].TXT = ['v=STSv1; id=1', 'v=STSv1; id=2'];
  r = await run('example.com', fakeDns(zone));
  assert.equal(find(r, 'mta-sts.invalid').params.count, 2);
  delete zone['_mta-sts.example.com'];
  delete zone['default._bimi.example.com'];
  r = await run('example.com', fakeDns(zone));
  has(r, 'mta-sts.missing', 'info');
  lacks(r, 'bimi.present');
  lacks(r, 'bimi.dmarc-weak');
});

/* ==================================================================== */
/* RDAP-derived checks                                                  */
/* ==================================================================== */

test('RDAP checks: expiry thresholds, statuses, unsupported TLD, errors', async () => {
  const day = 86400000;
  const at = (days) => new Date(NOW.getTime() + days * day).toISOString();
  const check = async (body, domain = 'example.com') => domainHealth(domain, {
    dns: fakeDns({ ...goodZone(), 'example.com.tr': goodZone()['example.com'] }), fetchImpl: rdapFetch(body), now: NOW, dkimSelectors: []
  });
  let r = await check(rdapBody({ expires: at(45) }));
  assert.equal(has(r, 'rdap.expiring-soon', 'warn').params.days, 45);
  r = await check(rdapBody({ expires: at(10) }));
  has(r, 'rdap.expiring', 'error');
  r = await check(rdapBody({ expires: at(-3) }));
  assert.equal(has(r, 'rdap.expired', 'error').params.days, 3);
  r = await check(rdapBody({ expires: null }));
  has(r, 'rdap.no-expiry', 'info');
  r = await check(rdapBody({ status: ['client hold', 'redemption period'] }));
  has(r, 'rdap.hold', 'error');
  has(r, 'rdap.pending-delete', 'error');
  has(r, 'rdap.transfer-unlocked', 'info');
  // "kilidini açın" means "unlock it": the advice is to turn the lock on
  assert.doesNotMatch(HEALTH_I18N.tr['health.rdap.transfer-unlocked.detail'], /kilidini açın/);
  r = await check(rdapBody({ status: ['server transfer prohibited'] }));
  lacks(r, 'rdap.transfer-unlocked');
  r = await check(404);
  has(r, 'rdap.not-found', 'warn');
  r = await check(new TypeError('Failed to fetch'));
  has(r, 'rdap.error', 'info');
  assertRenderable(r);
  r = await check(rdapBody(), 'example.com.tr');
  assert.equal(has(r, 'rdap.unsupported', 'info').params.tld, 'tr');
  assert.equal(r.rdap.unsupportedTld, true);
  const f = rdapFetch();
  r = await domainHealth('example.com', { dns: fakeDns(goodZone()), fetchImpl: f, rdap: false, dkimSelectors: [] });
  assert.equal(r.rdap, null);
  assert.equal(f.calls.length, 0);
  assert.ok(!r.checks.some((c) => c.category === 'rdap'));
});

/* ==================================================================== */
/* i18n                                                                 */
/* ==================================================================== */

test('HEALTH_I18N: every check id has English and Turkish title + detail; groups and CAA reasons exist', () => {
  assert.ok(HEALTH_CHECK_IDS.length > 90);
  for (const id of HEALTH_CHECK_IDS) {
    for (const lang of ['en', 'tr']) {
      assert.ok(HEALTH_I18N[lang][`health.${id}.title`], `${lang} title ${id}`);
      assert.ok(HEALTH_I18N[lang][`health.${id}.detail`], `${lang} detail ${id}`);
    }
    assert.ok(id.split('.')[0] in HEALTH_CATEGORIES, `category of ${id}`);
  }
  for (const g of ['dns', 'email', 'security', 'registration']) {
    assert.ok(HEALTH_I18N.en[`health.group.${g}`]);
    assert.ok(HEALTH_I18N.tr[`health.group.${g}`]);
  }
  for (const reason of ['none', 'critical-unknown', 'no-issue-property', 'unknown-issuer', 'allowed', 'deny-all', 'not-listed']) {
    const key = checkCaaAllows([], 'x').reasonKey.replace('none', reason);
    assert.equal(key, `health.caa.reason.${reason}`);
    assert.ok(HEALTH_I18N.en[key]);
    assert.ok(HEALTH_I18N.tr[key]);
  }
  assert.deepEqual(Object.keys(HEALTH_I18N.en).sort(), Object.keys(HEALTH_I18N.tr).sort());
  for (const key of Object.keys(HEALTH_I18N.en)) {
    const ph = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join();
    assert.equal(ph(HEALTH_I18N.en[key]), ph(HEALTH_I18N.tr[key]), `placeholders differ for ${key}`);
  }
  assert.ok(Object.isFrozen(HEALTH_I18N.en));
});
