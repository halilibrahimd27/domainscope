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
  COMPARE_FIELDS, COMPARE_VERDICTS, COMPARE_NOTES, COMPARE_ISSUES, COMPARE_PROBES, COMPARE_EXPIRY_WARN_DAYS
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
  return out;
}
const byKey = (out) => Object.fromEntries(out.fields.map((f) => [f.key, f]));

test('vocabularies are frozen; two probes per comparison', () => {
  for (const v of [COMPARE_FIELDS, COMPARE_VERDICTS, COMPARE_NOTES, COMPARE_ISSUES]) assert.ok(Object.isFrozen(v));
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
    assert.deepEqual(s.hsts, { raw: 'max-age=31536000; includeSubdomains; preload', maxAge: 31536000, includeSubDomains: true, preload: true });
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
    assert.deepEqual(parseHsts('max-age="600"'), { raw: 'max-age="600"', maxAge: 600, includeSubDomains: false, preload: false });
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

  test('broken: an error status, a certificate for another name, an untrusted or soon-expiring one, no answer', () => {
    assert.equal(byKey(compare(old, sideOf(edited((r) => { r.statusCode = 502; })))).status.note, 'new-error-status');
    assert.equal(compare(old, sideOf(edited((r) => { r.statusCode = 404; }))).verdict, 'broken');
    const wrongName = compare(old, sideOf(edited((r) => { r.tls.subject = { CN: 'www.example.net', alt: 'DNS:www.example.net' }; })));
    assert.deepEqual([wrongName.verdict, byKey(wrongName).certCovers.note], ['broken', 'cert-name']);
    const untrusted = compare(old, sideOf(edited((r) => { r.tls.authorized = false; r.tls.error = 'DEPTH_ZERO_SELF_SIGNED_CERT'; })));
    assert.deepEqual([untrusted.verdict, byKey(untrusted).certTrusted.note], ['broken', 'cert-untrusted']);
    const later = Date.parse('2026-11-20T00:00:00Z');
    const expiring = compare(sideOf(H1.final.body, OLD, later), sideOf(H2.final.body, NEW, later), later);
    assert.deepEqual([expiring.verdict, byKey(expiring).certExpires.note, byKey(expiring).certExpires.severity], ['differs', 'cert-expiring', 'warn']);
    const down = compare(old, sideOf(edited((r) => Object.assign(r, { status: 'failed', statusCode: null, tls: null, rawOutput: 'connect ECONNREFUSED' }))));
    assert.deepEqual([down.verdict, byKey(down).reach.note, byKey(down).reach.new], ['broken', 'new-unreachable', 'refused']);
    assert.deepEqual(down.fields.map((f) => f.key), ['reach'], 'a server that does not answer is compared no further');
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
});
