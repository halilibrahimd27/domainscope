/**
 * lib/records.js — readable records for DNS Lookup › Explain: DMARC and CAA tag by tag, HTTPS / SVCB
 * parameter by parameter with the address hints compared and the ECH configuration decoded, and
 * explainName, what the panel asks (a fake zone, the lookup's own answers reused).
 * Documentation names and addresses only; the ECH configs are built here, shaped like the ones
 * large CDNs publish (version 0xfe0d, X25519, HKDF-SHA256 + AES-128-GCM).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  explainDmarc, explainCaa, caOfIssuer, decodeEch, compareHints, explainSvcb, explainName,
  DMARC_TAGS, DMARC_MEANINGS, DMARC_ISSUES, DMARC_FO, CAA_KINDS, ECH_VERSION, ECH_ERRORS, SVCB_NOTES, HINT_STATUSES, EXPLAIN_SECTIONS
} from '../../assets/js/lib/records.js';
import { base64Encode } from '../../assets/js/lib/dnswire.js';
import { zoneDns, rrs } from './zone-dns.mjs';

/* ---- an ECHConfigList, built byte by byte ---------------------------------------- */

const u16 = (n) => [(n >> 8) & 0xff, n & 0xff];
const ascii = (s) => [...s].map((c) => c.charCodeAt(0));
function echConfig({ version = ECH_VERSION, id = 0x2a, kem = 0x0020, key = Array.from({ length: 32 }, (_, i) => i + 1),
  suites = [[1, 1]], maxName = 0, name = 'ech.example.net', extensions = [] } = {}) {
  const contents = [id, ...u16(kem), ...u16(key.length), ...key, ...u16(suites.length * 4), ...suites.flatMap(([k, a]) => [...u16(k), ...u16(a)]),
    maxName, name.length, ...ascii(name), ...u16(extensions.reduce((n, e) => n + 4 + e.data.length, 0)),
    ...extensions.flatMap((e) => [...u16(e.type), ...u16(e.data.length), ...e.data])];
  return [...u16(version), ...u16(contents.length), ...contents];
}
const echList = (...configs) => {
  const body = configs.flat();
  return base64Encode(Uint8Array.from([...u16(body.length), ...body]));
};

describe('decodeEch', () => {
  test('a version 0xfe0d config: id, KEM, key, suites, public name, extensions', () => {
    const r = decodeEch(echList(echConfig()));
    assert.deepEqual([r.ok, r.error, r.length, r.configs.length], [true, null, 68, 1]);
    const c = r.configs[0];
    assert.deepEqual([c.versionHex, c.supported, c.configId, c.kemId, c.kem, c.publicKeyLength, c.publicKey.slice(0, 6)],
      ['0xfe0d', true, 42, 0x20, 'DHKEM(X25519, HKDF-SHA256)', 32, '010203']);
    assert.deepEqual(c.cipherSuites, [{ kdfId: 1, kdf: 'HKDF-SHA256', aeadId: 1, aead: 'AES-128-GCM' }]);
    assert.deepEqual([c.maxNameLength, c.publicName, c.extensions], [0, 'ech.example.net', []]);
  });

  test('another version is listed and skipped; several suites; a mandatory extension; an unknown KEM', () => {
    const r = decodeEch(echList([...u16(0xfe0a), ...u16(3), 1, 2, 3],
      echConfig({ kem: 0x0010, suites: [[1, 1], [2, 2], [1, 3]], maxName: 64, extensions: [{ type: 0x8001, data: [9] }, { type: 0x0002, data: [] }] }),
      echConfig({ kem: 0x7777, name: 'ech2.example.net' })));
    assert.equal(r.ok, true);
    assert.deepEqual(r.configs.map((c) => [c.versionHex, c.supported]), [['0xfe0a', false], ['0xfe0d', true], ['0xfe0d', true]]);
    assert.deepEqual(r.configs[1].cipherSuites.map((s) => `${s.kdf}+${s.aead}`), ['HKDF-SHA256+AES-128-GCM', 'HKDF-SHA384+AES-256-GCM', 'HKDF-SHA256+ChaCha20-Poly1305']);
    assert.deepEqual(r.configs[1].extensions, [{ type: 0x8001, mandatory: true, length: 1 }, { type: 2, mandatory: false, length: 0 }]);
    assert.deepEqual([r.configs[1].kem, r.configs[1].maxNameLength], ['DHKEM(P-256, HKDF-SHA256)', 64]);
    assert.deepEqual([r.configs[2].kem, r.configs[2].publicName], [null, 'ech2.example.net']);
  });

  test('broken values say why', () => {
    assert.equal(decodeEch('not base64!').error, 'base64');
    assert.equal(decodeEch('').error, 'empty');
    const good = Buffer.from(echList(echConfig()), 'base64');
    assert.equal(decodeEch(base64Encode(good.subarray(0, good.length - 5))).error, 'length');
    const shortList = Uint8Array.from([...u16(good.length - 7), ...good.subarray(2, good.length - 5)]);
    assert.equal(decodeEch(base64Encode(shortList)).error, 'truncated');
    assert.ok(ECH_ERRORS.includes('truncated') && Object.isFrozen(ECH_ERRORS));
  });
});

describe('compareHints and explainSvcb', () => {
  test('hints against the real addresses, in any order', () => {
    assert.equal(compareHints(['192.0.2.2', '192.0.2.1'], ['192.0.2.1', '192.0.2.2']).status, 'match');
    assert.deepEqual(compareHints(['192.0.2.1', '192.0.2.9'], ['192.0.2.1']), { hints: ['192.0.2.1', '192.0.2.9'], actual: ['192.0.2.1'], status: 'stale', stale: ['192.0.2.9'], missing: [] });
    assert.equal(compareHints(['192.0.2.1'], ['192.0.2.1', '192.0.2.2']).status, 'partial');
    assert.equal(compareHints(['192.0.2.1'], []).status, 'no-address');
    assert.equal(compareHints(['2001:db8::1'], null).status, 'unknown');
    assert.equal(compareHints(['2001:DB8::1'], ['2001:db8:0::1']).status, 'match', 'compared canonically');
  });

  test('a service record: protocols, hints, ECH; alias mode; the RFC 9460 mistakes', () => {
    const ech = echList(echConfig());
    const records = rrs([
      { name: 'example.com', type: 'HTTPS', data: { priority: 1, target: '.', params: { alpn: ['h3', 'h2'], ipv4hint: ['192.0.2.1', '192.0.2.9'], ech, ipv6hint: ['2001:db8::1'] } } },
      { name: 'example.com', type: 'HTTPS', data: { priority: 2, target: 'pool.example.net', params: { port: 8443, 'no-default-alpn': true, alpn: ['h2'], mandatory: ['alpn', 'port', 'ech'] } } }
    ]);
    const addresses = new Map([['example.com', { ipv4: ['192.0.2.1'], ipv6: ['2001:db8::1'] }]]);
    const [first, second] = explainSvcb(records, { owner: 'example.com', type: 'HTTPS', addresses });
    assert.deepEqual([first.mode, first.targetName, first.alpn.map((a) => a.name)], ['service', 'example.com', ['HTTP/3 (QUIC)', 'HTTP/2']]);
    assert.deepEqual([first.hints.v4.status, first.hints.v4.stale, first.hints.v6.status], ['stale', ['192.0.2.9'], 'match']);
    assert.equal(first.ech.configs[0].publicName, 'ech.example.net');
    assert.deepEqual(first.notes.map((n) => n.code), ['h3', 'hint-stale', 'ech']);
    assert.deepEqual(first.notes[1].params, { family: 'IPv4', stale: '192.0.2.9', actual: '192.0.2.1', target: 'example.com' });
    assert.deepEqual([second.port, second.defaultAlpn, second.targetName], [8443, false, 'pool.example.net']);
    assert.deepEqual(second.notes.map((n) => [n.code, n.severity]), [['other-target', 'info'], ['no-default-alpn', 'info'], ['mandatory-missing', 'error'], ['port', 'info']]);
    assert.equal(second.notes[2].params.keys, 'ech');

    const alias = explainSvcb(rrs([
      { name: 'example.org', type: 'HTTPS', data: { priority: 0, target: 'cdn.example.net', params: { alpn: ['h2'] } } },
      { name: 'example.org', type: 'HTTPS', data: { priority: 1, target: '.', params: { 'no-default-alpn': true, alpn: ['h2'] } } }
    ]), { owner: 'example.org' });
    assert.deepEqual(alias.map((r) => r.notes.map((n) => n.code)), [['alias', 'alias-params'], ['mixed-modes', 'no-default-alpn']]);
    const none = explainSvcb(rrs([{ name: 'example.org', type: 'HTTPS', data: { priority: 0, target: '.', params: {} } }]), { owner: 'example.org' });
    assert.deepEqual(none[0].notes.map((n) => n.code), ['alias-none']);
    const plain = explainSvcb(rrs([{ name: 'example.org', type: 'HTTPS', data: { priority: 1, target: '.', params: { ipv4hint: ['192.0.2.5'] } } }]), { owner: 'example.org' });
    assert.deepEqual(plain[0].notes.map((n) => n.code), ['no-alpn', 'hint-unknown']);
    const bad = explainSvcb(rrs([{ name: 'example.org', type: 'HTTPS', data: { priority: 1, target: '.', params: { alpn: ['h2'], ech: base64Encode(Uint8Array.from([0, 9, 1])) } } }]), { owner: 'example.org' });
    assert.deepEqual(bad[0].notes.map((n) => n.code), ['ech-invalid']);
    for (const list of [SVCB_NOTES, HINT_STATUSES]) assert.ok(Object.isFrozen(list));
  });
});

describe('explainDmarc', () => {
  test('every tag, the defaults a record leaves out, the reports and their domains', () => {
    const d = explainDmarc('v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com,mailto:reports@example.net!10m; ruf=mailto:forensic@example.com; fo=1:d; ri=3600; adkim=s; t=y',
      { domain: 'example.com', foundAt: 'example.com' });
    assert.equal(d.valid, true);
    assert.deepEqual(d.tags.map((x) => [x.tag, x.given, x.meaning]), [
      ['v', true, 'v'], ['p', true, 'p.quarantine'], ['sp', false, 'sp.default'], ['pct', true, 'pct'], ['t', true, 't.y'],
      ['rua', true, 'rua'], ['ruf', true, 'ruf'], ['adkim', true, 'adkim.s'], ['aspf', false, 'aspf.default'], ['fo', true, 'fo'], ['ri', true, 'ri']
    ]);
    assert.deepEqual(d.tags[3].params, { pct: 50, rest: 50, lower: 'none' });
    assert.deepEqual(d.tags[2].params, { policy: 'quarantine' });
    assert.deepEqual(d.tags.find((x) => x.tag === 'fo').params.options, ['1', 'd']);
    assert.deepEqual(d.reports.map((r) => [r.tag, r.address, r.external, r.sizeLimit]), [
      ['rua', 'dmarc@example.com', false, null], ['rua', 'reports@example.net', true, '10m'], ['ruf', 'forensic@example.com', false, null]
    ]);
    assert.deepEqual([d.applies, d.appliesTag, d.pct, d.testing], ['quarantine', 'p', 50, true]);
    assert.deepEqual(d.issues.map((i) => i.code), ['pct-partial', 'testing']);
  });

  test('an inherited record applies its sp; the problems of a broken one', () => {
    const inh = explainDmarc('v=DMARC1; p=reject; sp=none', { domain: 'mail.example.com', foundAt: 'example.com', inherited: true });
    assert.deepEqual([inh.applies, inh.appliesTag, inh.inherited], ['none', 'sp', true]);
    assert.deepEqual(inh.issues.map((i) => i.code), ['policy-none', 'no-rua']);
    const own = explainDmarc('v=DMARC1; p=reject; sp=none', { domain: 'example.com' });
    assert.deepEqual(own.issues.map((i) => i.code), ['sp-none', 'no-rua']);
    const broken = explainDmarc('v=DMARC1; p=block; pct=150; adkim=x; foo=bar; rua=nowhere', { domain: 'example.com' });
    assert.equal(broken.valid, false);
    assert.deepEqual(broken.issues.map((i) => [i.code, i.severity]), [['invalid-p', 'error'], ['invalid-pct', 'error'], ['invalid-adkim', 'error'], ['unknown-tag', 'warn'], ['invalid-rua', 'warn']]);
    assert.deepEqual(broken.tags.filter((x) => x.issue).map((x) => [x.tag, x.meaning, x.issue]), [
      ['p', 'invalid', 'invalid-p'], ['pct', 'invalid', 'invalid-pct'], ['rua', 'rua', 'invalid-rua'], ['adkim', 'invalid', 'invalid-adkim'], ['foo', 'unknown', 'unknown-tag']
    ]);
    const missing = explainDmarc('v=DMARC1; rua=mailto:d@example.com', { domain: 'example.com' });
    assert.deepEqual(missing.issues.map((i) => i.code), ['missing-p']);
    const bis = explainDmarc('v=DMARC1; p=reject; np=reject; psd=n; t=n', { domain: 'example.com' });
    assert.deepEqual(bis.tags.filter((x) => ['np', 'psd', 't'].includes(x.tag)).map((x) => x.meaning), ['np.reject', 't.n', 'psd.n']);
    for (const list of [DMARC_TAGS, DMARC_MEANINGS, DMARC_ISSUES, DMARC_FO]) assert.ok(Object.isFrozen(list));
    for (const tagRow of [...bis.tags, ...broken.tags, ...inh.tags]) assert.ok(DMARC_MEANINGS.includes(tagRow.meaning), tagRow.meaning);
  });
});

describe('explainCaa', () => {
  test('tag by tag: the CA, its restrictions, a deny, iodef, the other properties; who may issue', () => {
    const set = rrs([
      { name: 'example.com', type: 'CAA', data: { flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=dns-01; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1' } },
      { name: 'example.com', type: 'CAA', data: { flags: 0, tag: 'issue', value: 'pki.goog' } },
      { name: 'example.com', type: 'CAA', data: { flags: 0, tag: 'issuewild', value: ';' } },
      { name: 'example.com', type: 'CAA', data: { flags: 0, tag: 'iodef', value: 'mailto:security@example.com' } },
      { name: 'example.com', type: 'CAA', data: { flags: 0, tag: 'issuemail', value: 'ca.example.net' } },
      { name: 'example.com', type: 'CAA', data: { flags: 0, tag: 'tbs', value: 'x' } }
    ]);
    const c = explainCaa(set, { name: 'www.example.com', foundAt: 'example.com' });
    assert.deepEqual(c.rows.map((r) => [r.kind, r.ca && r.ca.name, r.usable]), [
      ['issue', "Let's Encrypt", true], ['issue', 'Google Trust Services', true], ['issuewild', null, false],
      ['iodef', null, false], ['issuemail', null, true], ['unknown', null, false]
    ]);
    assert.deepEqual([c.rows[4].issuer, c.rows[4].deny], ['ca.example.net', false]);
    assert.deepEqual([c.rows[0].methods, c.rows[0].accountUri], [['dns-01'], 'https://acme-v02.api.letsencrypt.org/acme/acct/1']);
    assert.equal(c.rows[2].deny, true);
    assert.deepEqual([c.inherited, c.anyone, c.blocked, c.denyAll, c.wild], [true, false, false, false, 'deny']);
    assert.deepEqual(c.issuers.map((x) => x.domain), ['letsencrypt.org', 'pki.goog']);
    assert.deepEqual(c.iodef, ['mailto:security@example.com']);
  });

  test('nothing published, a critical unknown tag, values that authorize no one', () => {
    const none = explainCaa([], { name: 'example.org' });
    assert.deepEqual([none.anyone, none.rows], [true, []]);
    const blocked = explainCaa(rrs([{ name: 'example.org', type: 'CAA', data: { flags: 128, tag: 'future', value: 'x' } }]));
    assert.deepEqual([blocked.blocked, blocked.anyone, blocked.rows[0].critical], [true, false, true]);
    const deny = explainCaa(rrs([
      { name: 'example.org', type: 'CAA', data: { flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=dns-01;' } },
      { name: 'example.org', type: 'CAA', data: { flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=email-reply-00' } }
    ]));
    assert.deepEqual(deny.rows.map((r) => r.problem), ['empty-parameter', 'validationmethods-none']);
    assert.deepEqual([deny.denyAll, deny.wild], [true, 'same']);
    const wild = explainCaa(rrs([{ name: 'example.org', type: 'CAA', data: { flags: 0, tag: 'issuewild', value: 'letsencrypt.org; validationmethods=http-01' } }]));
    assert.equal(wild.rows[0].problem, 'wildcard-method');
    // issuemail (RFC 9495) and issuevmc read like issue: an empty issuer forbids S/MIME and VMC certificates.
    const mail = explainCaa(rrs([
      { name: 'example.org', type: 'CAA', data: { flags: 0, tag: 'issuemail', value: ';' } },
      { name: 'example.org', type: 'CAA', data: { flags: 0, tag: 'issuevmc', value: ';' } },
      { name: 'example.org', type: 'CAA', data: { flags: 0, tag: 'issuemail', value: 'DigiCert.com; accounturi=https://acme.example.net/acct/1' } },
      { name: 'example.org', type: 'CAA', data: { flags: 0, tag: 'issuevmc', value: 'bad issuer!' } }
    ]));
    assert.deepEqual(mail.rows.map((r) => [r.kind, r.issuer, r.deny, r.usable, r.problem]), [
      ['issuemail', null, true, false, null], ['issuevmc', null, true, false, null],
      ['issuemail', 'digicert.com', false, true, null], ['issuevmc', 'bad issuer!', false, false, 'invalid-issuer']
    ]);
    assert.deepEqual([mail.rows[2].ca && mail.rows[2].ca.id, mail.rows[2].accountUri], ['digicert', 'https://acme.example.net/acct/1']);
    assert.deepEqual([mail.anyone, mail.denyAll], [true, false], 'neither says who may issue TLS certificates');
    assert.deepEqual(caOfIssuer('LetsEncrypt.org.'), { id: 'letsencrypt', name: "Let's Encrypt" });
    assert.equal(caOfIssuer('ca.example.net'), null);
    assert.ok(CAA_KINDS.includes('issuewild') && Object.isFrozen(CAA_KINDS));
  });
});

describe('explainName', () => {
  const ech = echList(echConfig());
  const ZONE = {
    'example.com': {
      TXT: ['v=spf1 mx include:_spf.example.net ~all', 'google-site-verification=abc'],
      MX: [{ preference: 10, exchange: 'mx1.example.com' }],
      A: '192.0.2.1',
      AAAA: '2001:db8::1',
      HTTPS: { priority: 1, target: '.', params: { alpn: ['h3', 'h2'], ipv4hint: ['192.0.2.1'], ech } }
    },
    'mx1.example.com': { A: '203.0.113.25' },
    '_spf.example.net': { TXT: 'v=spf1 ip4:198.51.100.0/24 -all' },
    '_dmarc.example.com': { TXT: 'v=DMARC1; p=reject; rua=mailto:d@example.com' }
  };
  ZONE['example.com'].CAA = [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }];

  test('every section of a mail and web domain, asked in one go', async () => {
    const dns = zoneDns(ZONE);
    const r = await explainName('example.com', { dns });
    assert.deepEqual(EXPLAIN_SECTIONS, ['spf', 'dmarc', 'caa', 'svcb']);
    assert.equal(r.spf.state, 'ok');
    assert.deepEqual([r.spf.meter.count, r.spf.policy.steps.length, r.spf.flatten.terms], [2, 3, ['ip4:203.0.113.25', 'ip4:198.51.100.0/24', '~all']]);
    assert.deepEqual(r.spf.checks.map((c) => c.id), ['spf.all-softfail', 'spf.lookups-ok']);
    assert.deepEqual([r.dmarc.state, r.dmarc.foundAt, r.dmarc.explained.applies], ['ok', 'example.com', 'reject']);
    assert.deepEqual([r.caa.state, r.caa.foundAt, r.caa.explained.issuers.map((x) => x.domain)], ['ok', 'example.com', ['letsencrypt.org']]);
    assert.deepEqual(r.svcb.map((s) => [s.type, s.state, s.explained[0].hints.v4.status, s.explained[0].ech.ok]), [['HTTPS', 'ok', 'match', true]]);
  });

  test('the lookup\'s own answers are used as they are; a subdomain inherits DMARC and CAA; a _dmarc name is its record', async () => {
    const dns = zoneDns(ZONE);
    const own = await dns.query('example.com', 'TXT');
    const before = dns.calls.length;
    const r = await explainName('example.com', { dns, known: new Map([['TXT', own]]) });
    assert.ok(!dns.calls.slice(before).some((c) => c.name === 'example.com' && c.type === 'TXT'), 'TXT not asked again');
    assert.equal(r.spf.record, 'v=spf1 mx include:_spf.example.net ~all');

    const sub = await explainName('mail.example.com', { dns: zoneDns({ ...ZONE, 'mail.example.com': { TXT: 'v=spf1 -all' } }) });
    assert.deepEqual([sub.dmarc.state, sub.dmarc.inherited, sub.dmarc.explained.appliesTag], ['ok', true, 'sp']);
    assert.deepEqual([sub.caa.state, sub.caa.foundAt, sub.caa.explained.inherited], ['ok', 'example.com', true]);
    assert.deepEqual(sub.svcb.map((s) => s.state), ['none']);

    const rec = await explainName('_dmarc.example.com', { dns: zoneDns(ZONE) });
    assert.deepEqual([rec.spf, rec.caa, rec.svcb, rec.dmarc.state, rec.dmarc.domain], [null, null, [], 'ok', 'example.com']);
  });

  test('a web host without mail gets no DMARC; a failed question fails its section only; nothing for a reverse name', async () => {
    const web = await explainName('www.example.net', { dns: zoneDns({ 'www.example.net': { A: '192.0.2.80' } }) });
    assert.deepEqual([web.spf.state, web.dmarc, web.caa.state], ['none', null, 'none']);
    const failing = await explainName('example.com', { dns: zoneDns(ZONE, { fail: { 'example.com|HTTPS': 'timeout', '_spf.example.net|TXT': 'timeout' } }) });
    assert.deepEqual([failing.svcb[0].state, failing.svcb[0].error, failing.spf.state, failing.dmarc.state], ['failed', 'timeout', 'ok', 'ok']);
    assert.deepEqual(failing.spf.checks.map((c) => c.id), ['spf.all-softfail', 'spf.lookups-ok', 'spf.dns-error']);
    const txtDown = await explainName('example.com', { dns: zoneDns(ZONE, { fail: { 'example.com|TXT': 'timeout' } }) });
    assert.deepEqual([txtDown.spf.state, txtDown.spf.error], ['failed', 'timeout']);
    const reverse = await explainName('1.2.0.192.in-addr.arpa', { dns: zoneDns({}) });
    assert.deepEqual([reverse.spf, reverse.dmarc, reverse.caa, reverse.svcb], [null, null, null, []]);
    // A top-level domain: no SPF to expand (check_host() needs two labels), no organizational domain, no CAA tree.
    const tldDns = zoneDns({ com: { TXT: 'v=spf1 -all' } });
    const tld = await explainName('com', { dns: tldDns });
    assert.deepEqual([tld.spf, tld.dmarc, tld.caa, tld.svcb.map((s) => s.state)], [null, null, null, ['none']]);
    assert.ok(!tldDns.calls.some((c) => c.type === 'TXT'), 'its TXT is not asked');
    await assert.rejects(explainName('example.com', { dns: zoneDns(ZONE), signal: AbortSignal.abort() }), { name: 'AbortError' });
  });

  test('DMARC for a name below the organizational domain: when it has MX hosts (asked once if the lookup did not), never for other _ names', async () => {
    const zone = {
      'mail.example.com': { MX: [{ preference: 10, exchange: 'mx1.example.com' }], A: '192.0.2.5' },
      'web.example.com': { A: '192.0.2.6' },
      '_dmarc.example.com': { TXT: 'v=DMARC1; p=reject' },
      '_spf.example.com': { TXT: 'v=spf1 ip4:198.51.100.0/24 -all' }
    };
    const dns = zoneDns(zone);
    const mail = await explainName('mail.example.com', { dns });
    assert.deepEqual([mail.spf.state, mail.dmarc && mail.dmarc.state, mail.dmarc && mail.dmarc.inherited], ['none', 'ok', true]);
    assert.equal(dns.calls.filter((c) => c.name === 'mail.example.com' && c.type === 'MX').length, 1, 'MX asked once');
    // The lookup's own MX answer decides the same, and is not asked again.
    const known = zoneDns(zone);
    const own = await known.query('mail.example.com', 'MX');
    const again = await explainName('mail.example.com', { dns: known, known: new Map([['MX', own]]) });
    assert.equal(again.dmarc.state, 'ok');
    assert.equal(known.calls.filter((c) => c.type === 'MX').length, 1, 'only the lookup asked MX');
    // No MX, no SPF: a web host. A registrable domain does not need MX asked.
    const web = zoneDns(zone);
    assert.equal((await explainName('web.example.com', { dns: web })).dmarc, null);
    const apex = zoneDns(zone);
    assert.equal((await explainName('example.com', { dns: apex })).dmarc.state, 'ok');
    assert.ok(!apex.calls.some((c) => c.type === 'MX'), 'no MX for a registrable domain');
    // An MX question that got no answer does not hide DMARC.
    assert.equal((await explainName('web.example.com', { dns: zoneDns(zone, { fail: { 'web.example.com|MX': 'timeout' } }) })).dmarc.state, 'ok');
    // An SPF include target has SPF but sends no mail of its own: no DMARC, as no CAA, for a _ name.
    const spf = await explainName('_spf.example.com', { dns: zoneDns(zone) });
    assert.deepEqual([spf.spf.state, spf.dmarc, spf.caa], ['ok', null, null]);
  });
});
