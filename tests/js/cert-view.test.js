/**
 * views/cert.js pure helpers: the copy-ready `openssl s_client` command must never carry a
 * certificate name that is not a plain host name (a hostile SAN would run in the user's shell);
 * the bundled "Try a sample" certificate, the CertLoad of a Certificate Transparency lookup and
 * the text of a lookup that loaded nothing (why crt.sh was asked, Cert Spotter's hourly limit).
 * Pure Node (the view is DOM-free at import time). Names are documentation data only.
 */
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  sClientHost, sClientCommand, SAMPLE_CERT_URL, loadSampleCert, ctCertLoad, dnDisplayName, analyzeChain, ctCrtshWhy, ctOutcomeMessage,
  ctCrtshIncomplete, focusLoadedCert, certTarget, loadCertificateData
} from '../../assets/js/views/cert.js';
import { CT_COOLDOWN_MS, createCtCooldown, lookupCtCertificate } from '../../assets/js/lib/ctcert.js';
import { formatDate, setLang } from '../../assets/js/i18n.js';
import { parseCertificate, parseCertificates } from '../../assets/js/lib/x509.js';
import { baseDomainsFromNames } from '../../assets/js/lib/domain.js';
import { caaIssuerInfo } from '../../assets/js/lib/health.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

// Minimal DER builder (the tests/js/x509.test.js pattern) for a certificate with crafted SANs.
const encLen = (n) => {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
};
const tlv = (tag, ...parts) => {
  const body = Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p))));
  return Buffer.concat([Buffer.from([tag]), encLen(body.length), body]);
};
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const ctx = (n, constructed, ...p) => tlv(0x80 | (constructed ? 0x20 : 0) | n, ...p);
const oid = (s) => {
  const arcs = s.split('.').map(Number);
  const out = [arcs[0] * 40 + arcs[1]];
  for (const a of arcs.slice(2)) {
    const bytes = [a & 0x7f];
    for (let x = a >> 7; x > 0; x >>= 7) bytes.unshift((x & 0x7f) | 0x80);
    out.push(...bytes);
  }
  return tlv(0x06, Buffer.from(out));
};
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const cn = (value) => seq(set(seq(oid('2.5.4.3'), utf8(value))));
const SHA256_RSA = seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00]));
const SPKI = Buffer.from(parseCertificates(readFileSync(join(FIX, 'rsa_multi_san.der'))).leaf.spkiDer);

/** A certificate whose SAN holds `names` as raw (latin1) dNSName bytes. */
function certWithSans(...names) {
  const san = seq(oid('2.5.29.17'), tlv(0x04, seq(...names.map((n) => ctx(2, false, Buffer.from(n, 'latin1'))))));
  const tbs = seq(
    ctx(0, true, tlv(0x02, Buffer.from([2]))),
    tlv(0x02, Buffer.from([1])),
    SHA256_RSA,
    cn('Test Issuer'),
    seq(tlv(0x17, Buffer.from('250101000000Z')), tlv(0x17, Buffer.from('350101000000Z'))),
    cn('test.example.com'),
    SPKI,
    ctx(3, true, seq(san))
  );
  return parseCertificate(seq(tbs, SHA256_RSA, tlv(0x03, Buffer.concat([Buffer.from([0]), Buffer.alloc(16, 0xab)]))));
}

const SAFE = /^openssl s_client -connect [a-z0-9_.-]+:443 -servername [a-z0-9_.-]+ -showcerts <\/dev\/null$/;

describe('cert view: the openssl s_client command', () => {
  test('a plain certificate keeps its first name (unchanged output)', () => {
    assert.equal(sClientHost(['www.example.com', 'example.com']), 'www.example.com');
    assert.equal(sClientCommand(['www.example.com']),
      'openssl s_client -connect www.example.com:443 -servername www.example.com -showcerts </dev/null');
    assert.equal(sClientHost(['*.example.com', 'api.example.com']), 'api.example.com', 'an exact name before a wildcard');
    assert.equal(sClientHost(['*.example.com']), 'www.example.com', 'a wildcard-only certificate');
    assert.equal(sClientHost(['_svc.example.com']), '_svc.example.com');
    assert.equal(sClientHost(['xn--mnchen-3ya.example.com']), 'xn--mnchen-3ya.example.com');
    assert.equal(sClientHost([]), 'example.com');
    assert.equal(sClientHost(undefined), 'example.com');
  });

  test('a hostile name is skipped, never pasted into the command', () => {
    const cases = [
      [['shop.example.com;touch /tmp/pwned;.example.com', 'shop.example.com'], 'shop.example.com'],
      [['a.example.com\rtouch x\r.example.com'], 'example.com'],
      [['a.example.com\ntouch x'], 'example.com'],
      [['$(id).example.com', '*.cdn.example.com'], 'www.cdn.example.com'],
      [['`id`.example.com'], 'example.com'],
      [["x'y.example.com"], 'example.com'],
      [['a b.example.com'], 'example.com'],
      [['-oproxycommand=x.example.com', 'ok.example.com'], 'ok.example.com'],
      [['example.com/;id', 'good.example.net'], 'good.example.net'],
      [['a.example.com:443', 'b.example.com'], 'b.example.com'],
      [['x@a.example.com'], 'example.com'],
      [['*.a;b.example.com'], 'example.com']
    ];
    for (const [names, want] of cases) {
      assert.equal(sClientHost(names), want, JSON.stringify(names));
      assert.match(sClientCommand(names), SAFE, JSON.stringify(names));
    }
  });

  test('end to end: SAN bytes from a crafted certificate', () => {
    const hostile = certWithSans('shop.example.com;touch /tmp/pwned;.example.com', 'shop.example.com');
    // The parser keeps non-conforming SAN bytes on purpose, so the command builder must validate.
    assert.equal(hostile.hostnames[0], 'shop.example.com;touch /tmp/pwned;.example.com');
    assert.equal(sClientCommand(hostile.hostnames),
      'openssl s_client -connect shop.example.com:443 -servername shop.example.com -showcerts </dev/null');
    for (const cert of [
      certWithSans('a.example.com\rtouch x\r.example.com'),
      certWithSans('$(id).example.com'),
      certWithSans('`id`.example.com'),
      certWithSans('a b.example.com'),
      certWithSans('-o.example.com')
    ]) {
      assert.match(sClientCommand(cert.hostnames), SAFE, JSON.stringify(cert.hostnames));
      assert.equal(sClientHost(cert.hostnames), 'example.com', JSON.stringify(cert.hostnames));
    }
  });
});

describe('cert view: the bundled sample certificate', () => {
  const SAMPLE = join(FIX, '..', '..', 'assets', 'data', 'sample-cert.pem');
  const text = readFileSync(SAMPLE, 'utf8');

  test('lives in assets/data (so the Pages bundle ships it) and is addressed relative to the module', () => {
    assert.equal(new URL(SAMPLE_CERT_URL).href, pathToFileURL(SAMPLE).href);
    assert.ok(!/PRIVATE KEY/.test(text), 'no key in the file');
  });

  test('a leaf for example.com / example.net and its intermediate, from a made-up CA, valid for years', () => {
    const r = parseCertificates(text, { now: new Date('2026-09-27T00:00:00Z') });
    assert.equal(r.certificates.length, 2);
    assert.deepEqual(r.warnings, []);
    const leaf = r.leaf;
    assert.deepEqual(leaf.hostnames, ['example.com', '*.example.com', 'example.net', 'www.example.net']);
    assert.deepEqual(baseDomainsFromNames(leaf.hostnames), ['example.com', 'example.net'], 'SSL Targets fills in only reserved domains');
    assert.deepEqual(leaf.ipAddresses, []);
    assert.equal(leaf.isCA, false);
    assert.equal(leaf.isPrecertificate, false);
    assert.deepEqual(leaf.extKeyUsage, ['serverAuth']);
    assert.equal(leaf.issuer.O, 'DomainScope Sample');
    assert.ok(leaf.notAfter >= new Date('2035-12-31T00:00:00Z'), 'does not expire on screen any time soon');
    assert.deepEqual(caaIssuerInfo(leaf.issuer), [], 'not a public CA: the CT tab never searches crt.sh for it by itself');
    const chain = analyzeChain(r.certificates, leaf);
    assert.deepEqual(chain.ordered.map((c) => c.subjectCN), ['example.com', 'DomainScope Sample Intermediate CA']);
    assert.deepEqual(chain.issues.map((i) => i.code), ['ends-at'], 'leaf + intermediate, the root left to trust stores');
  });

  test('loadSampleCert: a CertLoad with source "sample"', async () => {
    const urls = [];
    const fetchImpl = async (url) => {
      urls.push(String(url));
      return new Response(readFileSync(new URL(String(url))), { status: 200 });
    };
    const load = await loadSampleCert({ fetchImpl });
    assert.deepEqual(urls, [SAMPLE_CERT_URL]);
    assert.equal(load.source, 'sample');
    assert.equal(load.name, 'sample-cert.pem');
    assert.equal(load.result.leaf.subjectCN, 'example.com');
    await assert.rejects(loadSampleCert({ fetchImpl: async () => new Response('gone', { status: 404 }) }), { name: 'HttpError' });
  });
});

describe('cert view: a certificate from Certificate Transparency', () => {
  test('ctCertLoad: source "ct", named after the host, provenance kept', () => {
    const der = parseCertificates(readFileSync(join(FIX, 'ec_wildcard.pem'))).leaf.der;
    const issuance = { id: '17000000001', notBefore: new Date('2025-01-01T00:00:00Z'), notAfter: new Date('2051-01-01T00:00:00Z'), dnsNames: ['*.wild.example.net'], sha256: null, url: null };
    const load = ctCertLoad({ host: 'shop.wild.example.net', provider: 'certspotter', der, issuance, precertificate: false, newerPrecertificate: null, truncated: true });
    assert.equal(load.source, 'ct');
    assert.equal(load.name, 'shop.wild.example.net');
    assert.equal(load.result.leaf.subjectCN, '*.wild.example.net');
    assert.deepEqual(load.ct, { host: 'shop.wild.example.net', provider: 'certspotter', issuance, precertificate: false, newerPrecertificate: null, truncated: true });
  });

  test('certTarget: the looked-up host of a CT load, else the first DNS name (a wildcard as its base)', () => {
    const der = parseCertificates(readFileSync(join(FIX, 'ec_wildcard.pem'))).leaf.der;
    const ct = ctCertLoad({ host: 'shop.wild.example.net', provider: 'certspotter', der, issuance: null, precertificate: false, newerPrecertificate: null, truncated: false });
    assert.equal(certTarget(ct), 'shop.wild.example.net');
    const file = loadCertificateData(readFileSync(join(FIX, 'ec_wildcard.pem')), { name: 'ec_wildcard.pem' });
    assert.equal(file.result.leaf.hostnames[0], '*.wild.example.net');
    assert.equal(certTarget(file), 'wild.example.net');
    const sample = loadCertificateData(readFileSync(join(FIX, '..', '..', 'assets', 'data', 'sample-cert.pem'), 'utf8'), { source: 'sample' });
    assert.equal(certTarget(sample), 'example.com');
    assert.equal(certTarget(loadCertificateData('not a certificate')), null, 'no leaf');
    assert.equal(certTarget(null), null);
  });

  test('dnDisplayName: "O (CN)" of a crt.sh issuer', () => {
    assert.equal(dnDisplayName('C=US, O=Example Trust, CN=Example CA R1'), 'Example Trust (Example CA R1)');
    assert.equal(dnDisplayName('C=US, O="Example, Inc.", CN=R1'), 'Example, Inc. (R1)');
    assert.equal(dnDisplayName('CN=Only CN'), 'Only CN');
    assert.equal(dnDisplayName('O=Same, CN=Same'), 'Same');
    assert.equal(dnDisplayName(''), '—');
  });
});

describe('cert view: the text of a lookup that loaded nothing', () => {
  after(() => setLang('en'));
  const NOW = new Date('2026-09-27T12:00:00Z');
  const RESET = new Date(NOW.getTime() + CT_COOLDOWN_MS);
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const limited = (state) => ({ state, error: 'HTTP 429', errorKind: 'rate-limit', quota: { limited: true, period: 'hour', resetAt: RESET } });
  const base = { host: 'www.example.com', truncated: false, skipped: { notCovering: 0, notYetValid: 0, expired: 0, revoked: 0, unreadable: 0 } };

  test('Cert Spotter rate limited and crt.sh down: the limit, the crt.sh error and until when only crt.sh is searched', async () => {
    setLang('en');
    const fetchImpl = async (url) => (String(url).startsWith('https://api.certspotter.com/')
      ? json({ code: 'rate_limited', message: 'Rate limit exceeded' }, 429)
      : new Response('bad gateway', { status: 502 }));
    const cooldown = createCtCooldown();
    const opts = { fetchImpl, now: NOW, cooldown, crtshRetryDelayMs: 0 };
    const time = formatDate(RESET, { timeStyle: 'short' });
    for (const state of ['failed', 'skipped']) {
      const r = await lookupCtCertificate('www.example.com', opts);
      assert.deepEqual([r.status, r.certspotter.state], ['error', state]);
      assert.equal(ctOutcomeMessage(r, { now: NOW.getTime() }),
        `Cert Spotter’s hourly limit for your IP address is used up, and crt.sh could not answer either: The service returned an error. Until about ${time}, “Try again” searches crt.sh only.`);
    }
    setLang('tr');
    const r = await lookupCtCertificate('www.example.com', opts);
    assert.equal(ctOutcomeMessage(r, { now: NOW.getTime() }),
      `IP adresinizin saatlik Cert Spotter sınırı doldu ve crt.sh de yanıt veremedi: Hizmet bir hata döndürdü. Saat ${formatDate(RESET, { timeStyle: 'short' })} civarına kadar “Tekrar dene” yalnızca crt.sh’te arar.`);
    setLang('en');
    assert.equal(ctOutcomeMessage(r, { now: RESET.getTime() + 1 }),
      'Cert Spotter’s hourly limit for your IP address is used up, and crt.sh could not answer either: The service returned an error.',
      'a reset time that has passed is not promised');
  });

  test('any other error: the plain error text', () => {
    setLang('en');
    const r = { ...base, status: 'error', errorKind: 'network', error: 'Failed to fetch',
      certspotter: { state: 'failed', error: 'HTTP 500', errorKind: 'http', quota: null }, crtsh: { entry: null, error: 'Failed to fetch', errorKind: 'network' } };
    assert.equal(ctOutcomeMessage(r), 'Network error — offline, blocked by an extension or firewall, or the service is down.');
  });

  test('why crt.sh was asked: the hourly limit with its reset time, a refusal or no answer, a partial list, an unreadable copy', () => {
    setLang('en');
    const crtsh = { entry: null, candidates: 0, partial: false, error: null, errorKind: null };
    const why = (certspotter) => ctCrtshWhy({ ...base, certspotter, crtsh }, { now: NOW.getTime() });
    assert.equal(why(limited('skipped')),
      `Cert Spotter’s hourly limit for your IP address is used up, so crt.sh was searched instead. Cert Spotter is asked again from about ${formatDate(RESET, { timeStyle: 'short' })}.`);
    assert.equal(why({ state: 'failed', error: 'HTTP 403', errorKind: 'http', quota: null }), 'Cert Spotter could not answer, so crt.sh was searched instead.');
    assert.equal(why({ state: 'partial', error: 'HTTP 500', errorKind: 'http', quota: null }), 'Cert Spotter answered only in part, so crt.sh was searched too.');
    assert.equal(why({ state: 'ok', error: null, errorKind: null, quota: null }), 'Cert Spotter’s copy of the certificate could not be read, so crt.sh was searched instead.');
    assert.equal(ctCrtshWhy({ ...base, certspotter: { state: 'ok' }, crtsh: null }), null, 'crt.sh not asked');
  });

  test('not found: flat on a complete list, hedged when Cert Spotter lists more than was read', () => {
    setLang('en');
    const ok = { state: 'ok', error: null, errorKind: null, quota: null };
    const flat = ctOutcomeMessage({ ...base, status: 'not-found', certspotter: ok, crtsh: null, skipped: { ...base.skipped, revoked: 1 } });
    assert.equal(flat, 'No currently valid certificate for www.example.com is logged in Certificate Transparency. Internal names and private CAs are never logged, and a certificate issued in the last few hours may not be listed yet. 1 revoked certificate was skipped.');
    const cut = ctOutcomeMessage({ ...base, status: 'not-found', truncated: true, certspotter: ok, crtsh: null, skipped: { ...base.skipped, revoked: 500 } });
    assert.match(cut, /^None of the certificates read for www.example.com is currently valid, but Cert Spotter lists more than were read, and the newest are among the unread ones: a valid certificate may still be logged. 500 revoked certificates were skipped.$/);
    assert.doesNotMatch(cut, /No currently valid certificate/);
    setLang('tr');
    assert.match(ctOutcomeMessage({ ...base, status: 'not-found', truncated: true, certspotter: ok, crtsh: null }), /okunan sertifikaların hiçbiri şu an geçerli değil/);
    setLang('en');
    const partialThenCrtsh = ctOutcomeMessage({ ...base, status: 'not-found', truncated: true, certspotter: { ...ok, state: 'partial', errorKind: 'http' },
      crtsh: { entry: null, candidates: 0, partial: false, error: null, errorKind: null } });
    assert.match(partialThenCrtsh, /^Cert Spotter answered only in part, so crt.sh was searched too. No currently valid certificate/, 'crt.sh read the whole list');
  });

  // crt.sh's identity search is literal: the wildcard certificate that covers a host is only in the
  // `*.parent` search, which is the one that failed here (crt.sh answered it 502 on 2026-09-27).
  const spotter429 = () => json({ code: 'rate_limited', message: 'Rate limit exceeded' }, 429);
  const crtshWildcardDown = (literal) => async (url) => {
    const u = String(url);
    if (u.startsWith('https://api.certspotter.com/')) return spotter429();
    return new URL(u).searchParams.get('q').startsWith('*.') ? new Response('bad gateway', { status: 502 }) : json(literal);
  };
  const crtRow = (id) => ({
    id, issuer_ca_id: 1, issuer_name: 'C=US, O=Example Trust, CN=Example CA R1', common_name: 'www.example.com',
    name_value: 'www.example.com', not_before: '2026-08-01T00:00:00', not_after: '2026-10-30T00:00:00', serial_number: '0a0b0c'
  });

  test('not found while crt.sh left a search unanswered: hedged, never "not logged" or "internal name" (EN, TR)', async () => {
    const opts = { now: NOW, cooldown: createCtCooldown(), crtshRetryDelayMs: 0 };
    const r = await lookupCtCertificate('www.example.com', { ...opts, fetchImpl: crtshWildcardDown([]) });
    assert.deepEqual([r.status, r.certspotter.state, r.crtsh.partial, r.crtsh.errorKind], ['not-found', 'failed', true, 'http']);
    assert.equal(ctCrtshIncomplete(r), true);
    setLang('en');
    const time = formatDate(RESET, { timeStyle: 'short' });
    const en = ctOutcomeMessage(r, { now: NOW.getTime() });
    assert.equal(en, `Cert Spotter’s hourly limit for your IP address is used up, so crt.sh was searched instead. Cert Spotter is asked again from about ${time}. `
      + 'No currently valid certificate for www.example.com was found in the answers received, but crt.sh did not answer every search: a valid certificate may still be logged. Try again later.');
    assert.doesNotMatch(en, /is logged in Certificate Transparency|Internal names/);
    setLang('tr');
    const tr = ctOutcomeMessage(r, { now: NOW.getTime() });
    assert.equal(tr, `IP adresinizin saatlik Cert Spotter sınırı doldu; bu yüzden crt.sh’te arandı. Cert Spotter’a saat ${formatDate(RESET, { timeStyle: 'short' })} civarından itibaren yeniden sorulur. `
      + 'Alınan yanıtlarda www.example.com için şu an geçerli bir sertifika bulunamadı; ancak crt.sh her aramaya yanıt vermedi: geçerli bir sertifika yine de kayıtlı olabilir. Daha sonra tekrar deneyin.');
    assert.doesNotMatch(tr, /İç ağ adları/);
    setLang('en');
  });

  test('not found on a partial Cert Spotter list with crt.sh answering nothing: says crt.sh answered none of its searches', async () => {
    setLang('en');
    const other = { id: '1', dns_names: ['www.example.org'], not_before: '2026-08-01T00:00:00Z', not_after: '2026-10-30T00:00:00Z', revoked: false, cert_der: '' };
    const fetchImpl = async (url) => {
      const u = String(url);
      if (u.startsWith('https://api.certspotter.com/')) return /[?&]after=/.test(u) ? json({}, 500) : json([other]);
      return new Response('bad gateway', { status: 502 });
    };
    const r = await lookupCtCertificate('www.example.com', { fetchImpl, now: NOW, cooldown: createCtCooldown(), crtshRetryDelayMs: 0 });
    assert.deepEqual([r.status, r.certspotter.state, r.truncated, r.crtsh.partial], ['not-found', 'partial', true, false]);
    const msg = ctOutcomeMessage(r, { now: NOW.getTime() });
    assert.equal(msg, 'Cert Spotter answered only in part, so crt.sh was searched too. '
      + 'No currently valid certificate for www.example.com is among those Cert Spotter listed, and crt.sh answered none of its searches: a valid certificate may still be logged. Try again later.');
    assert.doesNotMatch(msg, /did not answer every search|Internal names/);
    setLang('tr');
    assert.match(ctOutcomeMessage(r, { now: NOW.getTime() }), /crt\.sh aramalarının hiçbirine yanıt vermedi: geçerli bir sertifika yine de kayıtlı olabilir\. Daha sonra tekrar deneyin\.$/);
    setLang('en');
    assert.equal(ctCrtshIncomplete({ ...base, status: 'not-found', crtsh: null }), false, 'crt.sh not asked');
  });

  test('a crt.sh find with a search unanswered: "may not be the newest"', async () => {
    const r = await lookupCtCertificate('www.example.com', {
      fetchImpl: crtshWildcardDown([crtRow(11), crtRow(12)]), now: NOW, cooldown: createCtCooldown(), crtshRetryDelayMs: 0
    });
    assert.deepEqual([r.status, r.crtsh.partial], ['manual', true]);
    setLang('en');
    assert.match(ctOutcomeMessage(r, { now: NOW.getTime() }),
      /Newest valid certificate for www\.example\.com: www\.example\.com, issued by Example Trust \(Example CA R1\), valid until .+\. crt\.sh did not answer every search, so a newer certificate for this name may be missing here\.$/);
    setLang('tr');
    assert.match(ctOutcomeMessage(r, { now: NOW.getTime() }), /bu ad için daha yeni bir sertifika burada eksik olabilir\.$/);
    setLang('en');
    const whole = { ...r, crtsh: { ...r.crtsh, partial: false, error: null, errorKind: null } };
    assert.doesNotMatch(ctOutcomeMessage(whole, { now: NOW.getTime() }), /may be missing/, 'every search answered');
  });
});

describe('cert view: the keyboard focus after a certificate loads from the "No file?" block', () => {
  const fakeEl = ({ connected = true, tabindex = null } = {}) => {
    const attrs = new Map(tabindex === null ? [] : [['tabindex', tabindex]]);
    const calls = [];
    return {
      isConnected: connected,
      calls,
      hasAttribute: (k) => attrs.has(k),
      getAttribute: (k) => (attrs.has(k) ? attrs.get(k) : null),
      setAttribute: (k, v) => attrs.set(k, String(v)),
      focus: (o) => calls.push(['focus', o]),
      scrollIntoView: (o) => calls.push(['scroll', o.block])
    };
  };

  test('focusLoadedCert: made focusable (tabindex -1), focused without a jump, scrolled only as far as needed', () => {
    const note = fakeEl();
    assert.equal(focusLoadedCert(note), true);
    assert.equal(note.getAttribute('tabindex'), '-1');
    assert.deepEqual(note.calls, [['focus', { preventScroll: true }], ['scroll', 'nearest']]);
    const heading = fakeEl({ tabindex: '0' });
    focusLoadedCert(heading);
    assert.equal(heading.getAttribute('tabindex'), '0', 'an element that is focusable already keeps its tabindex');
    assert.equal(focusLoadedCert(null), false);
    const gone = fakeEl({ connected: false });
    assert.equal(focusLoadedCert(gone), false);
    assert.deepEqual(gone.calls, []);
  });
});
