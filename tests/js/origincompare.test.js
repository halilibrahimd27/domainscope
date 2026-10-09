// Unit tests for assets/js/lib/origincompare.js — no network. The two real measurements
// tests/fixtures/globalping/h01 + h02 (an HTTPS GET of github.com at two of its addresses, the
// second from the same probe, captured 2026-09-28) are the "same" case; every other case is one of
// them edited. The certificate in them expires on 2026-11-29: every test passes `now`.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  checkCompare, compareRequest, pageTitle, parseHsts, readSide, compareSides, runCompare, buildCompareCommand, certNames, sideFields,
  COMPARE_FIELDS, COMPARE_VERDICTS, COMPARE_NOTES, COMPARE_SHARED, COMPARE_ISSUES, COMPARE_PROBES, COMPARE_EXPIRY_WARN_DAYS
} from '../../assets/js/lib/origincompare.js';
import { GlobalpingError } from '../../assets/js/lib/globalping.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'globalping');
const fx = (name) => JSON.parse(readFileSync(join(FIX, `${name}.json`), 'utf8'));
const H1 = fx('h01-get-at-first');
const H2 = fx('h02-get-at-same-probe');
const NOW = Date.parse(H1.capturedAt);
const OLD = '140.82.121.3';
const NEW = '140.82.121.4';
const HOST = 'github.com';
const seenNotes = new Set();
const seenVerdicts = new Set();
const seenShared = new Set();

/** h02's measurement with its result edited. */
function edited(fn, base = H2) {
  const m = structuredClone(base.final.body);
  fn(m.results[0].result);
  return m;
}
const sideOf = (m, ip = NEW, now = NOW) => readSide(m, { ip, host: HOST, now });
function compare(a, b, now = NOW) {
  const out = compareSides(a, b, { now });
  seenVerdicts.add(out.verdict);
  for (const f of out.fields) if (f.note) seenNotes.add(f.note);
  for (const n of out.shared) seenShared.add(n);
  return out;
}
const byKey = (out) => Object.fromEntries(out.fields.map((f) => [f.key, f]));

test('vocabularies are frozen; two probes per comparison', () => {
  for (const v of [COMPARE_FIELDS, COMPARE_VERDICTS, COMPARE_NOTES, COMPARE_SHARED, COMPARE_ISSUES]) assert.ok(Object.isFrozen(v));
  assert.ok(COMPARE_SHARED.every((n) => COMPARE_NOTES.includes(n)), 'a shared problem is a note of its field too');
  assert.equal(COMPARE_PROBES, 2);
  assert.equal(COMPARE_EXPIRY_WARN_DAYS, 14);
});

describe('the form', () => {
  test('checkCompare: host, two different addresses, a plain path, a port; private addresses go to the CLI', () => {
    const ok = checkCompare({ host: 'WWW.Example.com.', oldIp: '140.82.121.3', newIp: '[2606:4700::6810:7c60]', path: '', port: '443' });
    assert.deepEqual([ok.ok, ok.probeable, ok.host, ok.newIp, ok.path, ok.port], [true, true, 'www.example.com', '2606:4700::6810:7c60', '/', 443]);
    const priv = checkCompare({ host: 'www.example.com', oldIp: '10.0.0.5', newIp: '192.0.2.20' });
    assert.deepEqual([priv.ok, priv.probeable, priv.private], [true, false, ['10.0.0.5', '192.0.2.20']]);
    const bad = checkCompare({ host: '*.example.com', oldIp: 'old', newIp: '192.0.2.1', path: '/a b', port: 70000 });
    assert.deepEqual(bad.issues.map((i) => i.code), ['host', 'old-ip', 'path', 'port']);
    assert.deepEqual(checkCompare({ host: 'www.example.com', oldIp: '192.0.2.1', newIp: '192.0.2.1' }).issues.map((i) => i.code), ['same-ip']);
    assert.equal(checkCompare({ host: 'www.example.com', oldIp: OLD, newIp: NEW, port: 25 }).probeable, false, 'a mail port: CLI only');
    assert.equal(checkCompare().ok, false);
  });

  test('compareRequest: the live bodies of h01 and h02', () => {
    assert.deepEqual(compareRequest({ ip: OLD, host: HOST }), H1.request);
    assert.deepEqual(compareRequest({ ip: NEW, host: HOST, locations: H1.final.body.id }), H2.request);
  });

  test('buildCompareCommand: the CLI line for private addresses, quoted per shell', () => {
    assert.equal(buildCompareCommand({ host: 'www.example.com', oldIp: '10.0.0.5', newIp: '10.0.0.6' }),
      'python3 ssl_origin_scan.py --compare 10.0.0.5 10.0.0.6 -n www.example.com');
    assert.equal(buildCompareCommand({ host: 'www.example.com', oldIp: '10.0.0.5', newIp: '2001:db8::6', port: 8443, path: '/healthz', shell: 'powershell' }),
      'python ssl_origin_scan.py --compare 10.0.0.5 2001:db8::6 -n www.example.com -p 8443 --path /healthz');
    assert.equal(buildCompareCommand({ host: 'www.example.com', oldIp: '10.0.0.5', newIp: '10.0.0.6', path: "/a'b" }), null, 'a path no shell quoting should carry');
    assert.equal(buildCompareCommand({ host: 'bad host', oldIp: '10.0.0.5', newIp: '10.0.0.6' }), null);
  });
});

describe('one side', () => {
  test('readSide on h01: status, headers, the body hash and title, the certificate', () => {
    const s = sideOf(H1.final.body, OLD);
    assert.deepEqual([s.ok, s.status, s.contentType, s.server, s.location], [true, 200, 'text/html; charset=utf-8', 'github.com', null]);
    assert.deepEqual(s.hsts, { raw: 'max-age=31536000; includeSubdomains; preload', maxAge: 31536000, includeSubDomains: true, preload: true, valid: true });
    assert.match(s.body.sha256, /^[0-9a-f]{64}$/);
    assert.deepEqual([s.body.length, s.body.truncated], [1200, true]);
    assert.deepEqual([s.cert.subjectCN, s.cert.covers, s.cert.authorized, s.cert.daysLeft], ['github.com', true, true, 62]);
    assert.equal(s.cert.sha256, '46b601ee08b418cf8a3a1ebfe670ba5ce43bb05a917fa8b2dd087a30471cfc63');
    assert.match(s.cert.issuer, /^Sectigo Public Server Authentication CA DV E36 · Sectigo Limited$/);
    assert.deepEqual([s.probe.country, s.measurementId], ['US', H1.final.body.id]);
  });

  test('a failed test: the failure kind from rawOutput (a refused connection, a timeout), no HTTP fields', () => {
    const refused = sideOf(edited((r) => Object.assign(r, { status: 'failed', statusCode: null, tls: null, rawOutput: 'connect ECONNREFUSED 140.82.121.4:443' })));
    assert.deepEqual([refused.ok, refused.failure.kind, refused.status, refused.cert], [false, 'refused', null, null]);
    const slow = sideOf(edited((r) => Object.assign(r, { status: 'failed', statusCode: null, tls: null, rawOutput: 'Request timed out while establishing the TCP connection.' })));
    assert.equal(slow.failure.kind, 'connect-timeout');
    assert.equal(sideOf({ results: [] }).failure.kind, 'unknown');
  });

  test('pageTitle and parseHsts', () => {
    assert.equal(pageTitle('<html><head><TITLE lang="en">\n  Caf&eacute; &amp; Bar &#8212; &#x41;  </title>'), 'Caf&eacute; & Bar — A');
    assert.equal(pageTitle('<title></title>'), null);
    assert.equal(pageTitle('no title'), null);
    assert.equal(pageTitle(null), null);
    assert.equal(pageTitle(`<title>${'x'.repeat(300)}</title>`).length, 200);
    assert.deepEqual(parseHsts('max-age="600"'), { raw: 'max-age="600"', maxAge: 600, includeSubDomains: false, preload: false, valid: true });
    assert.deepEqual(parseHsts('max-age=0, max-age=31536000; includeSubDomains'), {
      raw: 'max-age=0, max-age=31536000; includeSubDomains', maxAge: 0, includeSubDomains: false, preload: false, valid: true
    }, 'joined headers: only the first counts (RFC 6797 8.1)');
    for (const bad of ['includeSubDomains', 'max-age=abc', 'max_age=600', 'max-age=600; max-age=0', 'max-age="600', 'max-age=600; includeSubDomains=1',
      'max-age=600; includeSubDomains; includeSubDomains', 'max-age=600 600']) {
      const h = parseHsts(bad);
      assert.deepEqual([h.valid, h.maxAge], [false, null], bad);
    }
    assert.deepEqual(parseHsts('MAX-AGE = "31536000" ; INCLUDESUBDOMAINS;; preload'), {
      raw: 'MAX-AGE = "31536000" ; INCLUDESUBDOMAINS;; preload', maxAge: 31536000, includeSubDomains: true, preload: true, valid: true
    });
    assert.equal(parseHsts(''), null);
    assert.equal(parseHsts(null), null);
  });
});

describe('the comparison', () => {
  const old = sideOf(H1.final.body, OLD);

  test('h01 against h02: the same site, the same certificate, the same probe → same', () => {
    const out = compare(old, sideOf(H2.final.body));
    assert.equal(out.verdict, 'same');
    assert.deepEqual(out.fields.map((f) => f.key), [...COMPARE_FIELDS]);
    assert.ok(out.fields.every((f) => f.same && f.severity === 'ok'), JSON.stringify(out.fields.filter((f) => !f.same)));
    assert.deepEqual([byKey(out).body.note, byKey(out).certFingerprint.note], ['body-cut', 'same-cert']);
    assert.equal(out.differences, 0);
    assert.deepEqual(out.shared, []);
  });

  test('another certificate, issuer and body: information only (a new server has its own)', () => {
    const b = sideOf(edited((r) => {
      r.tls.fingerprint256 = 'AA:'.repeat(31) + 'AA';
      r.tls.issuer = { C: 'US', O: "Let's Encrypt", CN: 'E7' };
      r.tls.expiresAt = '2026-12-20T00:00:00.000Z';
      r.rawBody = r.rawBody.replace('<html', '<html data-nonce="1"');
      r.headers.server = 'nginx';
    }));
    const out = compare(old, b);
    const f = byKey(out);
    assert.equal(out.verdict, 'same');
    assert.deepEqual(['certFingerprint', 'certIssuer', 'certExpires', 'body', 'server'].map((k) => [f[k].same, f[k].severity]),
      [[false, 'info'], [false, 'info'], [false, 'info'], [false, 'info'], [false, 'info']]);
    assert.deepEqual([f.certFingerprint.note, f.body.note], ['new-cert', 'dynamic-body']);
    assert.equal(out.differences, 5);
  });

  test('another status, redirect, type, title and a lost HSTS header: differs', () => {
    const b = sideOf(edited((r) => {
      r.statusCode = 301;
      r.headers.location = 'https://www.example.com/';
      r.headers['content-type'] = 'text/plain';
      delete r.headers['strict-transport-security'];
      r.rawBody = '<title>Moved</title>';
    }));
    const out = compare(old, b);
    const f = byKey(out);
    assert.equal(out.verdict, 'differs');
    assert.deepEqual(['status', 'location', 'contentType', 'title', 'hsts'].map((k) => f[k].severity), ['warn', 'warn', 'warn', 'warn', 'warn']);
    assert.equal(f.hsts.note, 'hsts-lost');
    assert.equal(compare(sideOf(edited((r) => { delete r.headers['strict-transport-security']; }), OLD), sideOf(H2.final.body)).fields.find((x) => x.key === 'hsts').note, 'hsts-new');
  });

  test('HSTS turned off (max-age=0) or made weaker on the new server: a warning', () => {
    // h01's header: max-age=31536000; includeSubdomains; preload
    const hsts = (value) => sideOf(edited((r) => { r.headers['strict-transport-security'] = value; }));
    const off = compare(old, hsts('max-age=0'));
    assert.deepEqual([off.verdict, byKey(off).hsts.severity, byKey(off).hsts.note], ['differs', 'warn', 'hsts-off'], 'browsers forget the policy');
    const weaker = compare(old, hsts('max-age=31536000'));
    assert.deepEqual([weaker.verdict, byKey(weaker).hsts.severity, byKey(weaker).hsts.note], ['differs', 'warn', 'hsts-weaker'], 'includeSubDomains dropped');
    assert.equal(byKey(compare(old, hsts('max-age=31536000; includeSubDomains'))).hsts.note, 'hsts-weaker', 'preload dropped');
    const longer = compare(old, hsts('max-age=63072000; includeSubDomains; preload'));
    assert.deepEqual([longer.verdict, byKey(longer).hsts.severity, byKey(longer).hsts.note], ['same', 'info', null]);
    // An old max-age=0 is no policy to lose; a new header after it is one added.
    const oldOff = sideOf(edited((r) => { r.headers['strict-transport-security'] = 'max-age=0'; }, H1), OLD);
    const none = compare(oldOff, sideOf(edited((r) => { delete r.headers['strict-transport-security']; })));
    assert.deepEqual([none.verdict, byKey(none).hsts.severity, byKey(none).hsts.note], ['same', 'info', null]);
    assert.equal(byKey(compare(oldOff, sideOf(H2.final.body))).hsts.note, 'hsts-new');
  });

  test('broken: an error status, a certificate for another name, an untrusted or soon-expiring one, no answer', () => {
    assert.equal(byKey(compare(old, sideOf(edited((r) => { r.statusCode = 502; })))).status.note, 'new-error-status');
    assert.equal(compare(old, sideOf(edited((r) => { r.statusCode = 404; }))).verdict, 'broken');
    const wrongName = compare(old, sideOf(edited((r) => { r.tls.subject = { CN: 'www.example.net', alt: 'DNS:www.example.net' }; })));
    assert.deepEqual([wrongName.verdict, byKey(wrongName).certCovers.note], ['broken', 'cert-name']);
    const untrusted = compare(old, sideOf(edited((r) => { r.tls.authorized = false; r.tls.error = 'DEPTH_ZERO_SELF_SIGNED_CERT'; })));
    assert.deepEqual([untrusted.verdict, byKey(untrusted).certTrusted.note], ['broken', 'cert-untrusted']);
    const later = Date.parse('2026-11-20T00:00:00Z');
    const renewed = sideOf(edited((r) => { r.tls.fingerprint256 = 'BB:'.repeat(31) + 'BB'; r.tls.expiresAt = '2026-11-25T00:00:00.000Z'; }), NEW, later);
    const expiring = compare(sideOf(H1.final.body, OLD, later), renewed, later);
    assert.deepEqual([expiring.verdict, byKey(expiring).certExpires.note, byKey(expiring).certExpires.severity, byKey(expiring).certExpires.shared],
      ['differs', 'cert-expiring', 'warn', false], 'the new certificate expires sooner than the old one');
    assert.deepEqual(expiring.shared, []);
    const down = compare(old, sideOf(edited((r) => Object.assign(r, { status: 'failed', statusCode: null, tls: null, rawOutput: 'connect ECONNREFUSED' }))));
    assert.deepEqual([down.verdict, byKey(down).reach.note, byKey(down).reach.new], ['broken', 'new-unreachable', 'refused']);
    assert.deepEqual(down.fields.map((f) => f.key), ['reach'], 'a server that does not answer is compared no further');
  });

  test('a certificate problem both servers share is no difference: same, and said apart', () => {
    // The same untrusted certificate on both (an origin CA certificate behind a CDN), everything else equal.
    const untrusted = (m) => { m.tls.authorized = false; m.tls.error = 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'; };
    const oldCa = sideOf(edited(untrusted, H1), OLD);
    const both = compare(oldCa, sideOf(edited(untrusted)));
    assert.deepEqual([both.verdict, both.shared, both.worst], ['same', ['cert-untrusted'], 'ok']);
    const f = byKey(both).certTrusted;
    assert.deepEqual([f.same, f.shared, f.severity, f.note], [true, true, 'warn', 'cert-untrusted']);
    assert.equal(both.fields.filter((x) => x.shared).length, 1, 'only the shared field is marked');
    // The same certificate expiring within 14 days on both.
    const later = Date.parse('2026-11-20T00:00:00Z');
    const soon = compare(sideOf(H1.final.body, OLD, later), sideOf(H2.final.body, NEW, later), later);
    assert.deepEqual([soon.verdict, soon.shared, byKey(soon).certExpires.severity], ['same', ['cert-expiring'], 'warn']);
    // Two certificates that both expire soon, the new one later: renew both, still no difference.
    const newer = sideOf(edited((r) => { r.tls.fingerprint256 = 'CC:'.repeat(31) + 'CC'; r.tls.expiresAt = '2026-12-01T00:00:00.000Z'; }), NEW, later);
    const both2 = compare(sideOf(H1.final.body, OLD, later), newer, later);
    assert.deepEqual([both2.verdict, both2.shared, byKey(both2).certExpires.same], ['same', ['cert-expiring'], false]);
    // A default certificate that covers the name on neither server.
    const other = (r) => { r.tls.subject = { CN: 'default.example.net', alt: 'DNS:default.example.net' }; };
    const noName = compare(sideOf(edited(other, H1), OLD), sideOf(edited(other)));
    assert.deepEqual([noName.verdict, noName.shared, byKey(noName).certCovers.severity], ['same', ['cert-name'], 'warn']);
    // Worse on the new side is a difference again; better is information.
    assert.equal(compare(old, sideOf(edited(untrusted))).verdict, 'broken', 'trusted → untrusted');
    const fixed = compare(oldCa, sideOf(H2.final.body));
    assert.deepEqual([fixed.verdict, fixed.shared, byKey(fixed).certTrusted.severity], ['same', [], 'info'], 'untrusted → trusted');
    // A shared problem next to a real difference: the verdict follows the difference.
    const moved = compare(oldCa, sideOf(edited((r) => { untrusted(r); r.statusCode = 301; r.headers.location = 'https://www.example.com/'; })));
    assert.deepEqual([moved.verdict, moved.shared], ['differs', ['cert-untrusted']]);
  });

  test('an untrusted certificate from another issuer is a difference, never a problem both share', () => {
    const selfSigned = (r) => { r.tls.authorized = false; r.tls.error = 'DEPTH_ZERO_SELF_SIGNED_CERT'; r.tls.issuer = { CN: 'github.com' }; };
    const fresh = (r) => { selfSigned(r); r.tls.fingerprint256 = 'DD:'.repeat(31) + 'DD'; };
    // The old server: an origin CA certificate (a CDN in strict mode trusts it, the probe does not);
    // the new one: a self-signed certificate (the same CDN refuses it).
    const originCa = (r) => {
      r.tls.authorized = false;
      r.tls.error = 'UNABLE_TO_VERIFY_LEAF_SIGNATURE';
      r.tls.issuer = { O: 'Example Origin CA, Inc.', CN: 'Example Origin SSL Certificate Authority' };
    };
    const oldCa = sideOf(edited(originCa, H1), OLD);
    const newSelf = sideOf(edited(fresh));
    const out = compare(oldCa, newSelf);
    const f = byKey(out).certTrusted;
    assert.deepEqual([out.verdict, out.shared], ['differs', []], 'origin CA → self-signed');
    assert.deepEqual([f.same, f.shared, f.severity, f.note], [false, false, 'warn', 'cert-untrusted-other']);
    // An internal CA's certificate on the old server, a self-signed one on the new.
    const internal = sideOf(edited((r) => {
      r.tls.authorized = false;
      r.tls.error = 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY';
      r.tls.issuer = { O: 'Example Corp', CN: 'Example Internal CA' };
    }, H1), OLD);
    const inside = compare(internal, newSelf);
    assert.deepEqual([inside.verdict, inside.shared, byKey(inside).certTrusted.note], ['differs', [], 'cert-untrusted-other'], 'internal CA → self-signed');
    // A renewed certificate from the same origin CA: no difference.
    const renewed = compare(oldCa, sideOf(edited((r) => { originCa(r); r.tls.fingerprint256 = 'EE:'.repeat(31) + 'EE'; })));
    assert.deepEqual([renewed.verdict, renewed.shared, byKey(renewed).certTrusted.shared], ['same', ['cert-untrusted'], true]);
    // A self-signed certificate is its own issuer: only the same one is shared.
    const oldSelf = sideOf(edited(selfSigned, H1), OLD);
    assert.equal(compare(oldSelf, newSelf).verdict, 'differs', 'two self-signed certificates with the same name');
    const twin = compare(oldSelf, sideOf(edited(selfSigned)));
    assert.deepEqual([twin.verdict, twin.shared], ['same', ['cert-untrusted']], 'the same self-signed certificate');
  });

  test('two untrusted certificates are a shared problem only when they fail alike, from the same issuer', () => {
    const fp = (x) => Array.from({ length: 32 }, () => x).join(':');
    const internal = (error, print) => (r) => {
      r.tls.authorized = false;
      r.tls.error = error;
      r.tls.issuer = { O: 'Example Corp', CN: 'Example Internal CA' };
      if (print) r.tls.fingerprint256 = fp(print);
    };
    // The old server sends its certificate with the intermediate; the new one sends the leaf
    // alone: a client that trusts only the root now refuses it.
    const oldChain = sideOf(edited(internal('UNABLE_TO_GET_ISSUER_CERT_LOCALLY'), H1), OLD);
    const leafOnly = compare(oldChain, sideOf(edited(internal('UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'B1'))));
    assert.deepEqual([leafOnly.verdict, leafOnly.shared, byKey(leafOnly).certTrusted.note], ['differs', [], 'cert-untrusted-other'], 'the chain lost its intermediate');
    // A new certificate that is not valid yet, whatever error the probe reports first.
    const early = compare(oldChain, sideOf(edited((r) => { internal('UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'B2')(r); r.tls.createdAt = '2027-01-01T00:00:00.000Z'; })));
    assert.deepEqual([early.verdict, early.shared, byKey(early).certTrusted.note], ['differs', [], 'cert-untrusted-other'], 'not valid yet');
    // The same failure from the same issuer, its name in another case and spacing (the CLI's DN key): shared.
    const recased = compare(oldChain, sideOf(edited((r) => { internal('UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'B3')(r); r.tls.issuer = { O: 'example  corp', CN: 'EXAMPLE INTERNAL CA' }; })));
    assert.deepEqual([recased.verdict, recased.shared], ['same', ['cert-untrusted']]);
    // Two expired self-signed certificates for the same name: the probe reports CERT_HAS_EXPIRED,
    // not the self-signed error; the issuer named as the subject still makes them self-signed.
    const expiredSelf = (print) => (r) => {
      r.tls.authorized = false;
      r.tls.error = 'CERT_HAS_EXPIRED';
      r.tls.issuer = { CN: 'github.com' };
      r.tls.expiresAt = '2026-01-01T00:00:00.000Z';
      if (print) r.tls.fingerprint256 = fp(print);
    };
    const oldSelf = sideOf(edited(expiredSelf(), H1), OLD);
    assert.deepEqual([oldSelf.cert.selfSigned, oldSelf.cert.issuerCN], [true, 'github.com']);
    const twoSelf = compare(oldSelf, sideOf(edited(expiredSelf('C1'))));
    assert.deepEqual([twoSelf.verdict, byKey(twoSelf).certTrusted.note, twoSelf.shared], ['differs', 'cert-untrusted-other', ['cert-expiring']]);
    // Cloudflare's RSA and ECC origin CAs have no CN: the probe names both 'CloudFlare, Inc.', and Cloudflare trusts both.
    const origin = (print) => (r) => {
      r.tls.authorized = false;
      r.tls.error = 'UNABLE_TO_VERIFY_LEAF_SIGNATURE';
      r.tls.issuer = { C: 'US', O: 'CloudFlare, Inc.' };
      if (print) r.tls.fingerprint256 = fp(print);
    };
    const rsaToEcc = compare(sideOf(edited(origin(), H1), OLD), sideOf(edited(origin('E1'))));
    assert.deepEqual([rsaToEcc.verdict, rsaToEcc.shared], ['same', ['cert-untrusted']]);
  });

  test('HSTS as a browser reads it: the first header only, one valid max-age, no directive twice', () => {
    const hsts = (value) => sideOf(edited((r) => { r.headers['strict-transport-security'] = value; }));
    const note = (value, from = old) => {
      const out = compare(from, hsts(value));
      return [out.verdict, byKey(out).hsts.severity, byKey(out).hsts.note];
    };
    // h01's header: max-age=31536000; includeSubdomains; preload
    for (const bad of ['includeSubDomains; preload', 'max-age=abc; includeSubDomains; preload', 'max_age=31536000; includeSubDomains; preload',
      'max-age=31536000; max-age=0; includeSubDomains; preload', 'max-age=31536000; includeSubDomains; includesubdomains; preload']) {
      assert.deepEqual(note(bad), ['differs', 'warn', 'hsts-invalid'], bad);
    }
    assert.deepEqual(note('max-age=0, max-age=31536000; includeSubDomains; preload'), ['differs', 'warn', 'hsts-off'], 'joined headers: the first one counts');
    assert.deepEqual(note('max-age=31536000; includeSubDomains; preload, max-age=0'), ['same', 'info', null]);
    assert.deepEqual(note('MAX-AGE="31536000"; INCLUDESUBDOMAINS; PRELOAD'), ['same', 'info', null]);
    assert.deepEqual(note('max-age = 300; includeSubDomains; preload'), ['differs', 'warn', 'hsts-weaker'], 'a much shorter max-age');
    // An old header no browser applies is no policy to lose.
    const oldBad = sideOf(edited((r) => { r.headers['strict-transport-security'] = 'max-age=31536000; max-age=0'; }, H1), OLD);
    assert.deepEqual(note('max-age=31536000', oldBad), ['same', 'info', 'hsts-new']);
  });

  test('the old server does not answer: incomplete; neither answers: unreachable, never "not ready"', () => {
    const gone = sideOf(edited((r) => Object.assign(r, { status: 'failed', statusCode: null, tls: null, rawOutput: 'connect ECONNREFUSED' }), H1), OLD);
    const out = compare(gone, sideOf(H2.final.body));
    assert.deepEqual([out.verdict, byKey(out).reach.note, byKey(out).reach.severity], ['incomplete', 'old-unreachable', 'info']);
    assert.ok(out.fields.every((f) => f.severity === 'info' || f.severity === 'ok'), 'the new values are information: nothing to compare with');
    assert.equal(byKey(out).status.new, 200);
    const both = compare(gone, gone);
    assert.deepEqual([both.verdict, byKey(both).reach.note, byKey(both).reach.severity], ['unreachable', 'both-unreachable', 'warn']);
    assert.equal(both.fields.length, 1, 'nothing else to compare');
    // The TLS handshake of the new one worked (a certificate for another name), its HTTP answer did not: still nobody answered.
    const tlsOnly = sideOf(edited((r) => Object.assign(r, { status: 'failed', statusCode: null, rawOutput: 'socket hang up' })));
    assert.equal(compare(gone, tlsOnly).verdict, 'unreachable');
  });

  test('the certificate names: the subject CN first, then the SANs, three and +N', () => {
    assert.equal(certNames({ subjectCN: 'www.example.com', hostnames: ['www.example.com', 'example.com'] }), 'www.example.com, example.com');
    assert.equal(certNames({ subjectCN: 'WWW.Example.com.', hostnames: ['www.example.com', 'a.example.com', 'b.example.com', 'c.example.com', 'd.example.com'] }),
      'WWW.Example.com, a.example.com, b.example.com +2');
    assert.equal(certNames({ subjectCN: null, hostnames: ['example.net'] }), 'example.net');
    assert.equal(certNames({ subjectCN: '', hostnames: [] }), null);
    assert.equal(certNames(null), null);
    const b = sideOf(edited((r) => { r.tls.subject = { CN: 'www.example.net', alt: 'DNS:www.example.net, DNS:example.net, DNS:a.example.net, DNS:b.example.net' }; }));
    const f = byKey(compare(old, b)).certSubject;
    assert.deepEqual([f.old, f.new, f.same, f.severity], ['github.com, www.github.com', 'www.example.net, example.net, a.example.net +1', false, 'info']);
  });

  test('sideFields: one side on its own, as the comparison would list it', () => {
    const fields = sideFields(old);
    assert.deepEqual(fields.map((f) => f.key), [...COMPARE_FIELDS]);
    assert.deepEqual([fields[0].value, fields[1].value, fields.find((f) => f.key === 'certSubject').value], ['ok', 200, 'github.com, www.github.com']);
    const gone = sideOf(edited((r) => Object.assign(r, { status: 'failed', statusCode: null, tls: null, rawOutput: 'connect ECONNREFUSED' })));
    assert.deepEqual(sideFields(gone), [{ key: 'reach', value: 'refused' }]);
  });
});

test('the card says why a certificate is not trusted, as the CLI does ("no: <reason>")', async () => {
  const { displayValue } = await import('../../assets/js/ui/origin-compare.js');
  assert.equal(displayValue('certTrusted', false, { cert: { error: 'DEPTH_ZERO_SELF_SIGNED_CERT' } }), 'no: DEPTH_ZERO_SELF_SIGNED_CERT');
  assert.equal(displayValue('certTrusted', false, { cert: { error: null } }), 'no');
  assert.equal(displayValue('certTrusted', true, { cert: { error: null } }), 'yes');
  assert.equal(displayValue('certCovers', false, null), 'no');
});

test('the boxes a mount of the compare page fills: a link\'s host and old address, typed-in boxes too, once per link; Retire\'s guess only where nobody typed', async () => {
  const { compareFill } = await import('../../assets/js/ui/origin-compare.js');
  const typed = { host: 'api.example.org', oldIp: '192.0.2.99', touched: true, link: null };
  const guess = { ip: '192.0.2.1', host: 'example.net' };
  const withLink = (ip, host) => ({ ...guess, link: { ip, host } });
  // A later Retire check's next step names the pair to compare: it fills its boxes, typed or not.
  const first = compareFill(typed, withLink('192.0.2.10', 'www.example.com'));
  assert.deepEqual([first.host, first.oldIp], ['www.example.com', '192.0.2.10']);
  assert.ok(first.link, 'the link filled in is remembered');
  const again = compareFill({ ...typed, link: first.link }, withLink('192.0.2.10', 'www.example.com'));
  assert.deepEqual([again.host, again.oldIp, again.link], ['api.example.org', '192.0.2.99', first.link], 'the same link again (a language switch, Back): what was typed since stays');
  const next = compareFill({ ...typed, link: first.link }, withLink('203.0.113.7', 'shop.example.org'));
  assert.deepEqual([next.host, next.oldIp], ['shop.example.org', '203.0.113.7'], 'another link: its pair');
  assert.notEqual(next.link, first.link);
  // Without a link: Retire's one address and first domain, only in boxes nobody has typed in.
  assert.deepEqual(compareFill(typed, { ...guess, link: null }), { host: 'api.example.org', oldIp: '192.0.2.99', link: null });
  assert.deepEqual(compareFill({ host: '', oldIp: '', touched: false, link: first.link }, { ...guess, link: null }), { host: 'example.net', oldIp: '192.0.2.1', link: null });
  // A link that names the host only: the old address is guessed while nobody typed there.
  const hostOnly = compareFill({ host: '', oldIp: '', touched: false, link: null }, withLink(null, 'www.example.com'));
  assert.deepEqual([hostOnly.host, hostOnly.oldIp], ['www.example.com', '192.0.2.1']);
  assert.deepEqual([compareFill(typed, withLink(null, 'www.example.com')).oldIp, compareFill(typed, {}).host], ['192.0.2.99', 'api.example.org']);
});

describe('runCompare', () => {
  function fakeClient({ failSecond = null } = {}) {
    const calls = [];
    return {
      calls,
      async measure(body) {
        calls.push(body);
        if (calls.length === 2 && failSecond) throw failSecond;
        const f = calls.length === 1 ? H1 : H2;
        return { measurement: f.final.body, id: f.final.body.id, cost: 1, quota: null };
      }
    };
  }

  test('the old address first, then the new one from the same probe', async () => {
    const client = fakeClient();
    const sides = [];
    const out = await runCompare({ client, host: HOST, oldIp: OLD, newIp: NEW, onSide: (w) => sides.push(w), now: () => NOW });
    assert.deepEqual(client.calls, [H1.request, H2.request]);
    assert.deepEqual(sides, ['old', 'new']);
    assert.deepEqual([out.comparison.verdict, out.spent, out.ids], ['same', 2, [H1.final.body.id, H2.final.body.id]]);
  });

  test('a quota stop after the first measurement says what was spent and keeps the old side', async () => {
    const err = new GlobalpingError('rate-limit', 'API rate limit exceeded.', { status: 429 });
    await assert.rejects(runCompare({ client: fakeClient({ failSecond: err }), host: HOST, oldIp: OLD, newIp: NEW, now: () => NOW }), (e) => {
      assert.equal(e.code, 'rate-limit');
      assert.equal(e.spent, 1);
      assert.equal(e.first.ip, OLD);
      return true;
    });
  });

  test('refused before any request: a bad form, private addresses, no client', async () => {
    await assert.rejects(runCompare({ client: fakeClient(), host: HOST, oldIp: '10.0.0.1', newIp: NEW }), TypeError);
    await assert.rejects(runCompare({ client: fakeClient(), host: '', oldIp: OLD, newIp: NEW }), TypeError);
    await assert.rejects(runCompare({ host: HOST, oldIp: OLD, newIp: NEW }), TypeError);
  });
});

test('every verdict and note was produced by this suite', () => {
  assert.deepEqual([...COMPARE_VERDICTS].filter((v) => !seenVerdicts.has(v)), []);
  assert.deepEqual([...COMPARE_NOTES].filter((n) => !seenNotes.has(n)), []);
  assert.deepEqual([...COMPARE_SHARED].filter((n) => !seenShared.has(n)), []);
});
