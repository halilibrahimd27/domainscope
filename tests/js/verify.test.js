// Unit tests for assets/js/lib/verify.js — the Globalping certificate verdicts
// (ROADMAP P0.1 Phase A). No network: real measurements come from
// tests/fixtures/globalping (trimmed, scrubbed) and the runner drives a fake
// client. Every fixture classification passes `now: capturedAt`, never the wall
// clock: real_github.pem (the m01 certificate) expires on 2026-11-29.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as V from '../../assets/js/lib/verify.js';
import { GlobalpingError } from '../../assets/js/lib/globalping.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { toCsv } from '../../assets/js/lib/export.js';
import { TimeoutError } from '../../assets/js/lib/util.js';
import { runScan } from '../../assets/js/lib/scanner.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { parseInventory } from '../../assets/js/lib/inventory.js';
import { buildSweepCommand } from '../../assets/js/lib/cmdline.js';
import { parseZone } from '../../assets/js/lib/zoneparse.js';
import { zoneScanInput } from '../../assets/js/lib/zoneorigins.js';

const ROOT = new URL('../../', import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');
const FIX = new Map();
const fx = (n) => {
  if (!FIX.has(n)) FIX.set(n, JSON.parse(read(`tests/fixtures/globalping/${n}.json`)));
  return FIX.get(n);
};
const testsOf = (n) => fx(n).final.body.results;
const at = (n) => Date.parse(fx(n).capturedAt);
const tlsOf = (n, i = 0) => testsOf(n)[i].result.tls;
const leafOf = (file) => parseCertificates(read(`tests/fixtures/${file}`)).leaf;

const GH = leafOf('real_github.pem');
const NEW_GH = await V.expectationFor(GH);
const OTHER = { sha256: ['0'.repeat(64)], spkiHex: [], hostnames: [], subjectCN: null, notAfter: null };
const own = (n, i = 0) => ({ ...OTHER, sha256: [V.hexKey(tlsOf(n, i).fingerprint256)] });
const cls = (n, name, expect, i = 0) => V.classifyTest(testsOf(n)[i], { name, expect, now: at(n) });

const PROBE = { continent: 'EU', country: 'DE', city: 'Falkenstein', asn: 24940, network: 'Hetzner Online', tags: ['datacenter-network'] };
/** A raw failed test with this rawOutput (synthetic, shaped like the fixtures). */
const failed = (rawOutput, extra = {}) => ({
  probe: PROBE,
  result: { status: 'failed', failureSource: 'target', resolvedAddress: null, statusCode: null, timings: { total: null }, tls: null, rawOutput, ...extra }
});
/** A raw finished test with this tls (synthetic). */
const withTls = (tls, extra = {}) => ({
  probe: PROBE, result: { status: 'finished', resolvedAddress: '1.2.3.4', statusCode: 200, timings: { total: 30, tcp: 7, tls: 15 }, tls, ...extra }
});
const synthTls = (over = {}) => ({
  authorized: true, protocol: 'TLSv1.3', cipherName: 'TLS_AES_128_GCM_SHA256',
  createdAt: '2026-09-01T00:00:00.000Z', expiresAt: '2026-11-29T23:59:59.000Z',
  issuer: { C: 'US', O: 'Example CA', CN: 'Example Issuing CA' },
  subject: { CN: 'www.example.com', alt: 'DNS:www.example.com, DNS:example.com' },
  keyType: 'EC', keyBits: 256, serialNumber: '07', fingerprint256: 'AB:'.repeat(31) + 'AB', ...over
});
const NOW = Date.parse('2026-09-24T07:00:00.000Z');

/* ---- rows ----------------------------------------------------------------------- */

const pair = (o = {}) => {
  const p = { ip: '1.2.3.4', port: 443, name: 'www.example.com', server: { id: 'web01', name: 'web01' }, alsoServers: [],
    via: 'dns', proxied: false, provider: null, needsCert: true, newCertCovers: true, skip: null, ...o };
  return { ...p, key: `${p.ip}|${p.port}|${p.name}` };
};
const row = (o = {}) => V.createVerifyRows([pair(o)], { origins: true })[0];
/** Give a row a (done) verdict from probe verdicts, as the runner does (optionally with its raw tests). */
const done = (r, verdicts, rawTests = null) => {
  const v = V.aggregateVerdicts(verdicts);
  Object.assign(r, { verdict: v, served: v.served, warnings: v.warnings, httpStatus: v.httpStatus, state: 'done', stale: false });
  if (rawTests) r.tests = rawTests.map(V.trimTest);
  return r;
};
/** Classify raw tests for the row's name and give it the verdict + tests. */
const check = (r, rawTests, expect, now = NOW) =>
  done(r, rawTests.map((t) => V.classifyTest(t, { name: r.name, expect, now })), rawTests);
const settle = (rows) => {
  V.applyWorksRule(rows);
  for (const r of rows) r.exposure = V.exposureOf(r);
  return rows;
};

/* ---- fixture verdicts ----------------------------------------------------------- */

const V_UPDATED = () => cls('m01-github-valid', 'github.com', NEW_GH);
const V_OLD = () => cls('m01-github-valid', 'github.com', OTHER);
const V_NOT_COVERED = () => cls('m01-github-valid', 'api.github.com', NEW_GH);
const V_TIMEOUT = () => cls('m11-filtered-timeout5', 'github.com', NEW_GH);
const V_TIMEOUT_BR = () => cls('m10-filtered-default', 'github.com', NEW_GH);
const V_CLOSED = () => cls('m09-closed', 'scanme.nmap.org', NEW_GH);
const V_SNI = () => cls('m12-sni-refused', 'github.com', NEW_GH);
const V_CHAIN = () => cls('m06-incomplete-chain', 'incomplete-chain.badssl.com', own('m06-incomplete-chain'));

/* =================================================================================== */

describe('vocabularies', () => {
  test('statuses are the CLI STATUSES in CLI order', () => {
    const src = read('cli/ssl_origin_scan.py');
    const m = src.match(/^STATUSES = \(([^)]*)\)/m);
    assert.ok(m, 'STATUSES tuple found in the CLI');
    assert.deepEqual([...V.VERIFY_STATUSES], m[1].split(',').map((s) => s.trim()));
  });

  test('frozen, and the critic additions are present', () => {
    for (const list of [V.VERIFY_STATUSES, V.VERIFY_REASONS, V.VERIFY_ERRORS, V.VERIFY_WARNINGS, V.VERIFY_STATES,
      V.SKIP_REASONS, V.NOT_RUN_REASONS, V.EXPOSURES, V.FAILURE_KINDS, V.HEADLINE_KEYS, V.NOT_HERE_KEYS]) {
      assert.ok(Object.isFrozen(list));
    }
    assert.ok(V.NOT_RUN_REASONS.includes('optional'));
    assert.ok(V.EXPOSURES.includes('no-answer'));
    assert.ok(V.HEADLINE_KEYS.includes('incomplete'));
    assert.equal(V.VERIFY_WARNINGS.length, 12);
    assert.equal(V.VERIFY_WARNINGS.at(-1), 'other-set');
  });
});

describe('hexKey / serialKey / serialDisplay', () => {
  test('serials: comparison ignores leading zeros, display is byte-aligned like x509 and the CLI', () => {
    const gh = tlsOf('m01-github-valid').serialNumber; // high bit set: A5:…
    assert.equal(V.serialKey(gh), GH.serialHex, 'no 00 sign byte is re-added');
    assert.equal(V.serialDisplay(gh), GH.serialHex);
    const yr2 = tlsOf('m02-wrong-host').serialNumber; // 06:5B:…
    assert.ok(V.serialDisplay(yr2).startsWith('065be17b'), 'display keeps the leading nibble');
    assert.ok(V.serialKey(yr2).startsWith('65be17b'), 'comparison drops it');
    assert.equal(V.serialKey('00'), '0');
    assert.equal(V.serialDisplay('00'), '00');
    assert.equal(V.serialDisplay('07'), '07', 'ec_wildcard.pem-like serial stays 07');
    assert.equal(V.serialDisplay('00:A5:9E'), 'a59e');
    assert.equal(V.serialKey('00:00:07'), V.serialKey('07'));
  });

  test('fingerprint256 identity: hexKey equals computeFingerprints().sha256', () => {
    assert.equal(V.hexKey(tlsOf('m01-github-valid').fingerprint256), NEW_GH.sha256[0]);
    assert.equal(V.hexKey(null), '');
  });
});

describe('parseAltNames', () => {
  test('m01: two DNS names', () => {
    assert.deepEqual(V.parseAltNames(tlsOf('m01-github-valid').subject.alt), { dns: ['github.com', 'www.github.com'], ip: [], other: [] });
  });

  test('m23: IPv6 IP SANs are normalised to RFC 5952', () => {
    const alt = V.parseAltNames(tlsOf('m23-ip-san').subject.alt);
    assert.ok(alt.ip.includes('2606:4700:4700::1111'));
    assert.ok(alt.ip.includes('1.1.1.1'));
    assert.ok(alt.dns.includes('one.one.one.one'));
    assert.ok(!alt.ip.some((ip) => ip.includes(':0:0:')), 'no uncompressed form left');
  });

  test('JSON-quoted values and other types', () => {
    assert.deepEqual(V.parseAltNames('DNS:"a,b.example", email:x@y'), { dns: ['a,b.example'], ip: [], other: ['email:x@y'] });
    assert.deepEqual(V.parseAltNames(undefined), { dns: [], ip: [], other: [] });
    assert.deepEqual(V.parseAltNames(''), { dns: [], ip: [], other: [] });
  });
});

describe('servedCert', () => {
  test('m01', () => {
    const s = V.servedCert(tlsOf('m01-github-valid'));
    assert.ok(s.sha256.startsWith('46b601ee'));
    assert.equal(s.serialHex, 'a59ebdb596751db7f5c095079613953c');
    assert.equal(s.issuerO, 'Sectigo Limited');
    assert.equal(s.issuerCN, 'Sectigo Public Server Authentication CA DV E36');
    assert.equal(s.notAfter.toISOString(), '2026-11-29T23:59:59.000Z');
    assert.equal(s.keyType, 'EC');
    assert.equal(s.keyBits, 256);
    assert.equal(s.protocol, 'TLSv1.3');
    assert.equal(s.publicKeyHex.length, 130, 'EC P-256 raw point, in memory only');
    assert.deepEqual(s.hostnames, ['github.com', 'www.github.com']);
    assert.equal(s.authorized, true);
    assert.equal(s.error, null);
  });

  test('null without a fingerprint', () => {
    assert.equal(V.servedCert(null), null);
    assert.equal(V.servedCert({ subject: { CN: 'x.example.com' } }), null);
  });

  test('hostnames follow x509: CN fallback only without DNS SANs and only when hostname-like; SANs never filtered', () => {
    assert.deepEqual(V.servedCert(synthTls({ subject: { CN: 'Legacy.Example.ORG.' } })).hostnames, ['legacy.example.org']);
    assert.deepEqual(V.servedCert(synthTls({ subject: { CN: 'Test Root CA' } })).hostnames, []);
    assert.deepEqual(V.servedCert(tlsOf('m08-no-host-421')).hostnames, ['badssl-fallback-unknown-subdomain-or-no-sni'],
      'a single-label SAN stays');
    assert.deepEqual(V.servedCert(synthTls({ subject: { CN: 'www.example.com', alt: 'DNS:münchen.example-test.com' } })).hostnames,
      ['xn--mnchen-3ya.example-test.com']);
  });

  test('a non-ASCII name with "@", ":" or a path is never cut down to the name after it (x509 parity)', () => {
    // Node JSON-quotes and \u-escapes a non-ASCII SAN; the UTF-8 bytes arrive as Latin-1 characters.
    const alt = 'DNS:"\\u00c3\\u00a4@victim.example"';
    const served = V.servedCert(synthTls({ subject: { CN: 'ä@victim.example', alt } }));
    assert.deepEqual(served.hostnames, ['Ã¤@victim.example'.toLowerCase()]);
    const noSan = V.servedCert(synthTls({ subject: { CN: 'ä:1@victim.example', alt: undefined } }));
    assert.deepEqual(noSan.hostnames, [], 'never a CN fallback');
    const test = withTls(synthTls({ subject: { CN: 'www.example.com', alt } }));
    const v = V.classifyTest(test, { name: 'victim.example', expect: OTHER, now: NOW });
    assert.deepEqual([v.status, v.reason], ['NOT_HOSTED', 'not-covered']);
  });

  test('a non-ASCII name the IDNA mapping would make another ASCII name of stays as it is (x509 parity)', () => {
    const alt = 'DNS:"vic\\u00adtim.example"';
    assert.deepEqual(V.servedCert(synthTls({ subject: { CN: 'www.example.com', alt } })).hostnames, ['vic­tim.example']);
    for (const CN of ['ｖｉｃｔｉｍ.example', 'victim。example', 'ｍüｎｃｈｅｎ.example', 'm\u00fc\u00adnchen.example', '\u00e4\u200bvictim.example']) {
      assert.deepEqual(V.servedCert(synthTls({ subject: { CN, alt: undefined } })).hostnames, [], CN);
    }
    const v = V.classifyTest(withTls(synthTls({ subject: { CN: 'www.example.com', alt } })), { name: 'victim.example', expect: OTHER, now: NOW });
    assert.deepEqual([v.status, v.reason], ['NOT_HOSTED', 'not-covered']);
    assert.deepEqual(V.servedCert(synthTls({ subject: { CN: 'x', alt: 'DNS:"*.m\\u00fcnchen.example"' } })).hostnames,
      ['*.xn--mnchen-3ya.example']);
  });
});

describe('trimTest', () => {
  test('drops headers / body / publicKey; keeps the key in memory only', () => {
    const raw = {
      probe: { ...PROBE, latitude: 50.4, longitude: 12.3, resolvers: ['private'], tags: ['datacenter-network', 'u-someone'] },
      result: { status: 'finished', statusCode: 200, headers: { server: 'x' }, rawHeaders: 'Server: x', rawBody: null,
        rawOutput: 'HTTP/1.1 200\nServer: x', resolvedAddress: '140.82.121.4', timings: { total: 30, dns: null, tcp: 7, tls: 15, firstByte: 8, download: 0 },
        tls: tlsOf('m01-github-valid') }
    };
    const t = V.trimTest(raw);
    assert.equal(t.status, 'finished');
    assert.ok(!('headers' in t) && !('rawHeaders' in t) && !('rawBody' in t));
    assert.ok(!('publicKey' in t.tls), 'no publicKey inside tls');
    assert.equal(t.publicKeyHex.length, 130);
    assert.equal(t.rawOutput, null, 'rawOutput only for failures');
    assert.deepEqual(t.timings, { total: 30, tcp: 7, tls: 15 });
    assert.ok(!('latitude' in t.probe) && !('resolvers' in t.probe));
    assert.equal(t.probe.country, 'DE');
    assert.equal(V.trimTest(t), t, 'a trimmed test is returned as is');
    assert.ok(!JSON.stringify(t).includes('u-someone'));
  });

  test('failed: rawOutput kept, at most 300 characters', () => {
    const t = V.trimTest(failed(`connect ECONNREFUSED 1.2.3.4:443 ${'x'.repeat(500)}`));
    assert.equal(t.rawOutput.length, 300);
    assert.equal(t.tls, null);
  });
});

describe('parseFailure', () => {
  const kind = (n) => V.parseFailure(testsOf(n)[0].result);

  test('the verbatim Globalping strings', () => {
    assert.equal(kind('m09-closed').kind, 'refused');
    assert.equal(kind('m10-filtered-default').kind, 'connect-timeout');
    assert.equal(kind('m11-filtered-timeout5').kind, 'connect-timeout');
    assert.deepEqual([kind('m12-sni-refused').kind, kind('m12-sni-refused').alert], ['tls-alert', 40]);
    assert.equal(kind('m20-nxdomain').kind, 'dns');
    assert.equal(kind('m21-private-resolve').kind, 'private');
    assert.equal(kind('m24-not-tls').kind, 'not-tls');
    assert.equal(kind('m25-v6-doc-enetunreach').kind, 'unreachable', 'the first real ENETUNREACH string');
  });

  test('synthetic inputs and the first-line text', () => {
    const k = (raw, extra) => V.parseFailure(failed(raw, extra).result);
    assert.equal(k('The operation timed out').kind, 'tls-timeout');
    assert.equal(k('read ECONNRESET').kind, 'reset');
    assert.equal(k('socket hang up').kind, 'reset');
    // The server closing mid-handshake (HAProxy strict-sni): Node's message carries no ECONNRESET.
    assert.equal(k('Client network socket disconnected before secure TLS connection was established').kind, 'reset');
    assert.equal(k('error:0A000126:SSL routines::unexpected eof while reading').kind, 'reset');
    assert.equal(k('connect EHOSTUNREACH 1.2.3.4:443').kind, 'unreachable');
    assert.equal(k('anything', { failureSource: 'internal' }).kind, 'internal');
    assert.equal(k('', { status: 'offline' }).kind, 'offline');
    assert.equal(k('zzz').kind, 'unknown');
    assert.equal(k(`\nfirst line ${'y'.repeat(300)}\nsecond`).text.length, 200);
    assert.equal(k('line one\nline two').text, 'line one');
    assert.equal(V.parseFailure(null).kind, 'unknown');
  });
});

describe('classifyTest', () => {
  const st = (v) => [v.status, v.reason];

  test('m01: UPDATED for the new certificate on both probes (fingerprint identity)', () => {
    for (const i of [0, 1]) {
      const v = cls('m01-github-valid', 'github.com', NEW_GH, i);
      assert.deepEqual(st(v), ['UPDATED', 'new-cert']);
      assert.deepEqual(v.warnings, []);
      assert.equal(v.coveredBy, 'github.com');
      assert.equal(v.sameKey, true);
      assert.equal(v.httpStatus, 200);
    }
  });

  test('m01 with another expected certificate', () => {
    const sameKey = cls('m01-github-valid', 'github.com', { ...OTHER, spkiHex: NEW_GH.spkiHex });
    assert.deepEqual(st(sameKey), ['NEEDS_UPDATE', 'old-cert']);
    assert.deepEqual(sameKey.warnings, ['same-key'], 'EC raw point is the tail of the SPKI');
    const www = cls('m01-github-valid', 'www.github.com', OTHER);
    assert.deepEqual(st(www), ['NEEDS_UPDATE', 'old-cert']);
    assert.equal(www.coveredBy, 'www.github.com');
    assert.deepEqual(st(cls('m01-github-valid', 'github.com', null)), ['NEEDS_UPDATE', 'no-new-cert']);
    assert.equal(cls('m01-github-valid', 'github.com', null).sameKey, null);
  });

  test('coverage decides NOT_HOSTED, never the fingerprint', async () => {
    assert.deepEqual(st(cls('m01-github-valid', 'api.github.com', NEW_GH)), ['NOT_HOSTED', 'not-covered']);
    const google = await V.expectationFor(leafOf('real_google.pem'));
    assert.deepEqual(st(cls('m01-github-valid', 'github.com', google)), ['NEEDS_UPDATE', 'old-cert']);
  });

  test('m02: not covered → NOT_HOSTED without name-mismatch; covered → same-key (full RSA SPKI)', () => {
    const wrong = cls('m02-wrong-host', 'wrong.host.badssl.com', OTHER);
    assert.deepEqual(st(wrong), ['NOT_HOSTED', 'not-covered']);
    assert.ok(!wrong.warnings.includes('name-mismatch'));
    assert.equal(wrong.tlsError, 'ERR_TLS_CERT_ALTNAME_INVALID');
    const pk = V.hexKey(tlsOf('m02-wrong-host').publicKey);
    const apex = cls('m02-wrong-host', 'badssl.com', { ...OTHER, spkiHex: [pk] });
    assert.deepEqual(st(apex), ['NEEDS_UPDATE', 'old-cert']);
    assert.ok(apex.warnings.includes('same-key'));
    assert.ok(apex.warnings.includes('name-mismatch'), 'browsers disagree with our coverage: shown, not a verdict');
  });

  test('trust warnings: expired, self-signed, untrusted root, missing intermediate, revoked is invisible', () => {
    const exp = cls('m03-expired', 'expired.badssl.com', OTHER);
    assert.deepEqual(st(exp), ['NEEDS_UPDATE', 'old-cert']);
    assert.deepEqual(exp.warnings, ['expired']);
    const self = cls('m04-self-signed', 'self-signed.badssl.com', OTHER);
    assert.deepEqual(st(self), ['PRIVATE_CERT', 'self-signed'], 'PRIVATE_CERT as in the CLI, not an old certificate');
    assert.deepEqual(self.warnings, ['self-signed']);
    const root = cls('m05-untrusted-root', 'untrusted-root.badssl.com', OTHER);
    assert.deepEqual(st(root), ['NEEDS_UPDATE', 'old-cert'], 'a private root is unknown without --private-ca, as in the CLI');
    assert.deepEqual(root.warnings, ['untrusted-root']);
    const chain = V_CHAIN();
    assert.deepEqual(st(chain), ['UPDATED', 'new-cert']);
    assert.deepEqual(chain.warnings, ['chain-incomplete']);
    const revoked = cls('m07-revoked', 'revoked.badssl.com', own('m07-revoked'));
    assert.deepEqual(st(revoked), ['UPDATED', 'new-cert']);
    assert.deepEqual(revoked.warnings, [], 'revocation is not checked by Globalping (documented)');
  });

  test('m08: the fallback certificate for its own single-label name → UPDATED + expired + http-421', () => {
    const v = cls('m08-no-host-421', 'badssl-fallback-unknown-subdomain-or-no-sni', own('m08-no-host-421'));
    assert.deepEqual(st(v), ['UPDATED', 'new-cert']);
    assert.deepEqual(v.warnings, ['expired', 'http-421']);
    assert.equal(v.httpStatus, 421);
  });

  test('m17: NOT_HOSTED although tls.error says CERT_HAS_EXPIRED (chain errors mask name errors)', () => {
    const v = cls('m17-unknown-vhost', 'no-such-vhost.badssl.com', own('m17-unknown-vhost'));
    assert.deepEqual(st(v), ['NOT_HOSTED', 'not-covered']);
    assert.equal(v.tlsError, 'CERT_HAS_EXPIRED');
    assert.ok(v.warnings.includes('expired'));
    assert.ok(!v.warnings.includes('http-421'), '421 only warns when the certificate covers the name');
  });

  test('m13 / m15 / m22 / m23', async () => {
    const cf = await V.expectationFor(leafOf('real_cloudflare.pem'));
    const m13 = cls('m13-cf-8443-403', 'www.cloudflare.com', cf);
    assert.deepEqual(st(m13), ['NEEDS_UPDATE', 'old-cert']);
    assert.equal(m13.httpStatus, 403);
    assert.deepEqual(st(cls('m15-v6-literal', 'www.cloudflare.com', own('m15-v6-literal'))), ['UPDATED', 'new-cert']);
    assert.deepEqual(st(cls('m22-http2', 'github.com', NEW_GH)), ['UPDATED', 'new-cert'], 'HTTP2 tests carry tls too');
    const m23 = cls('m23-ip-san', 'one.one.one.one', own('m23-ip-san'));
    assert.deepEqual(st(m23), ['UPDATED', 'new-cert'], 'the CN differs, the alt covers it');
    assert.equal(m23.coveredBy, 'one.one.one.one');
  });

  test('failures', () => {
    assert.deepEqual(st(V_CLOSED()), ['CLOSED', 'refused']);
    assert.deepEqual(st(V_TIMEOUT()), ['TIMEOUT', 'connect-timeout']);
    const sni = V_SNI();
    assert.deepEqual(st(sni), ['TLS_ERROR', 'sni-refused']);
    assert.equal(sni.alert, 40);
    assert.ok(sni.detail.includes('SSL alert number 40'));
    assert.deepEqual(st(cls('m24-not-tls', 'http.badssl.com', OTHER)), ['TLS_ERROR', 'not-tls']);
    assert.deepEqual(st(cls('m25-v6-doc-enetunreach', 'example.com', OTHER)), ['CLOSED', 'unreachable']);
    const dns = cls('m20-nxdomain', 'x.example.com', OTHER);
    assert.deepEqual([dns.status, dns.error], [null, 'dns']);
    const priv = cls('m21-private-resolve', 'localtest.me', OTHER);
    assert.deepEqual([priv.status, priv.error], [null, 'private']);
  });

  test('synthetic failures: alert 112, other alerts (ALPN 120), reset, unknown, internal, offline', () => {
    const c = (t) => V.classifyTest(t, { name: 'www.example.com', expect: OTHER, now: NOW });
    assert.deepEqual(st(c(failed('ssl alert unrecognized name: SSL alert number 112'))), ['NOT_HOSTED', 'unrecognized-name']);
    const alpn = c(failed('no application protocol: SSL alert number 120'));
    assert.deepEqual([...st(alpn), alpn.alert], ['TLS_ERROR', 'tls-alert', 120]);
    assert.deepEqual(st(c(failed('read ECONNRESET'))), ['TLS_ERROR', 'reset']);
    const unk = c(failed('zzz'));
    assert.deepEqual(st(unk), ['TLS_ERROR', 'tls-failed']);
    assert.equal(unk.detail, 'zzz');
    const internal = c(failed('probe crashed', { failureSource: 'internal' }));
    assert.deepEqual([internal.status, internal.error], [null, 'probe']);
    const offline = c({ probe: PROBE, result: { status: 'offline' } });
    assert.deepEqual([offline.status, offline.error], [null, 'offline']);
  });

  test('odd finished tests (tls without fingerprint256, a status code without tls) are probe faults', () => {
    const c = (t) => V.classifyTest(t, { name: 'www.example.com', expect: OTHER, now: NOW });
    const noFp = c(withTls(synthTls({ fingerprint256: undefined })));
    assert.deepEqual([noFp.status, noFp.error], [null, 'probe']);
    const noTls = c(withTls(null));
    assert.deepEqual([noTls.status, noTls.error], [null, 'probe']);
  });

  test('synthetic certificates: CN fallback, unknown errors, validity window, Cloudflare Origin CA', () => {
    const c = (tls, name = 'www.example.com', extra) => V.classifyTest(withTls(tls, extra), { name, expect: OTHER, now: NOW });
    assert.deepEqual(st(c(synthTls({ subject: { CN: 'legacy.example.org' } }), 'legacy.example.org')), ['NEEDS_UPDATE', 'old-cert']);
    assert.deepEqual(c(synthTls({ authorized: false, error: 'SOMETHING_NEW' })).warnings, ['untrusted']);
    assert.deepEqual(c(synthTls({ createdAt: '2026-12-01T00:00:00.000Z', expiresAt: '2027-12-01T00:00:00.000Z' })).warnings, ['not-yet-valid']);
    assert.deepEqual(c(synthTls({ authorized: false, error: 'CERT_NOT_YET_VALID', createdAt: '2026-01-01T00:00:00.000Z' })).warnings, ['not-yet-valid']);
    const originCa = { O: 'CloudFlare, Inc.', OU: 'CloudFlare Origin SSL Certificate Authority', CN: 'CloudFlare Origin SSL Certificate Authority' };
    const ocaChain = c(synthTls({ authorized: false, error: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', issuer: originCa }));
    assert.deepEqual(st(ocaChain), ['ORIGIN_CERT', 'origin-ca']);
    assert.deepEqual(ocaChain.warnings, ['origin-ca'], 'origin-ca replaces chain-incomplete');
    assert.deepEqual(c(synthTls({ authorized: false, error: 'SELF_SIGNED_CERT_IN_CHAIN', issuer: originCa })).warnings, ['origin-ca'],
      'and untrusted-root (the Origin root sent along)');
    assert.deepEqual(c(synthTls({ issuer: { O: 'CloudFlare, Inc.', CN: 'CloudFlare Origin ECC Certificate Authority' } })).warnings, ['origin-ca']);
    assert.deepEqual(c(synthTls(), 'www.example.com', { statusCode: 421 }).warnings, ['http-421']);
  });

  test('certificate kinds: ORIGIN_CERT for the Cloudflare Origin CA, PRIVATE_CERT for self-signed (the CLI HostedClassifier)', () => {
    const c = (tls, expect = OTHER) => V.classifyTest(withTls(tls), { name: 'www.example.com', expect, now: NOW });
    // What a probe really reports for an Origin CA leaf: the issuer's C and O, no CN (the root's name is an OU).
    const real = { authorized: false, error: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', issuer: { C: 'US', O: 'CloudFlare, Inc.' },
      subject: { CN: 'CloudFlare Origin Certificate', alt: 'DNS:*.example.com, DNS:example.com' } };
    assert.deepEqual(st(c(synthTls(real))), ['ORIGIN_CERT', 'origin-ca']);
    assert.equal(V.servedKind(c(synthTls(real)).served), 'origin-ca');
    // Cloudflare's publicly trusted CAs carry a CN, and a trusted leaf is never the Origin CA's.
    const edge = synthTls({ issuer: { C: 'US', O: 'Cloudflare, Inc.', CN: 'Cloudflare Inc ECC CA-3' } });
    assert.deepEqual(st(c(edge)), ['NEEDS_UPDATE', 'old-cert']);
    assert.deepEqual(st(c(synthTls({ ...real, authorized: true, error: null }))), ['NEEDS_UPDATE', 'old-cert']);
    assert.deepEqual(st(c(synthTls({ ...real, issuer: { O: 'Example CloudFlare Resellers' } }))), ['NEEDS_UPDATE', 'old-cert']);
    const self = synthTls({ authorized: false, error: 'DEPTH_ZERO_SELF_SIGNED_CERT', issuer: { O: 'Example Corp', CN: 'www.example.com' } });
    assert.deepEqual(st(c(self)), ['PRIVATE_CERT', 'self-signed']);
    assert.equal(V.servedKind(c(self).served), 'self-signed');
    // Rolling out a certificate of that kind: the older ones of the kind still need it.
    assert.deepEqual(st(c(synthTls(real), { ...OTHER, kinds: ['origin-ca'] })), ['NEEDS_UPDATE', 'old-cert']);
    assert.deepEqual(st(c(self, { ...OTHER, kinds: ['self-signed'] })), ['NEEDS_UPDATE', 'old-cert']);
    assert.deepEqual(st(c(synthTls(real), { ...OTHER, kinds: ['self-signed'] })), ['ORIGIN_CERT', 'origin-ca']);
    assert.deepEqual(st(c(self, { ...OTHER, kinds: ['other'] })), ['PRIVATE_CERT', 'self-signed']);
    // Without a certificate to compare, each keeps its own status (the CLI without --cert).
    assert.deepEqual(st(c(synthTls(real), null)), ['ORIGIN_CERT', 'origin-ca']);
    assert.deepEqual(st(c(synthTls(), null)), ['NEEDS_UPDATE', 'no-new-cert']);
    // The new certificate itself is UPDATED whatever its kind; one that does not cover the name is NOT_HOSTED.
    const own = { ...OTHER, sha256: ['ab'.repeat(32)], kinds: ['other'] };
    assert.deepEqual(st(c(synthTls(real), own)), ['UPDATED', 'new-cert']);
    assert.deepEqual(st(V.classifyTest(withTls(synthTls(real)), { name: 'www.example.net', expect: OTHER, now: NOW })),
      ['NOT_HOSTED', 'not-covered']);
    assert.equal(V.servedKind(null), null);
    assert.deepEqual([...V.CERT_KINDS], ['origin-ca', 'self-signed', 'other']);
  });

  test('certKind and expectationFor: the kinds of the new certificate(s)', async () => {
    const leaf = (file) => parseCertificates(read(`tests/fixtures/${file}`)).certificates[0];
    assert.equal(V.certKind(leaf('cli_origin_wild.pem')), 'origin-ca', 'issuer OU names the Origin CA, no CN');
    assert.equal(V.certKind(leaf('cloudflare_origin_ca_ecc.pem')), 'origin-ca', 'the real ECC root');
    assert.equal(V.certKind(leaf('cloudflare_origin_ca_rsa.pem')), 'origin-ca', 'the real RSA root');
    assert.equal(V.certKind(leaf('cli_private_ca.pem')), 'self-signed');
    assert.equal(V.certKind(leaf('cli_private_wild.pem')), 'other', 'a private CA is unknown without --private-ca');
    assert.equal(V.certKind(leaf('cli_public_wild.pem')), 'other');
    assert.equal(V.certKind(GH), 'other');
    assert.equal(V.certKind(null), 'other');
    assert.deepEqual(NEW_GH.kinds, ['other']);
    assert.deepEqual((await V.expectationFor([leaf('cli_origin_wild.pem'), leaf('cli_public_wild.pem')])).kinds, ['origin-ca', 'other']);
  });

  test('aggregateVerdicts ranks the kinds between NOT_HOSTED and UPDATED', () => {
    const v = (status) => ({ status, served: {}, warnings: [] });
    assert.equal(V.aggregateVerdicts([v('UPDATED'), v('ORIGIN_CERT')]).status, 'ORIGIN_CERT');
    assert.equal(V.aggregateVerdicts([v('PRIVATE_CERT'), v('ORIGIN_CERT')]).status, 'ORIGIN_CERT');
    assert.equal(V.aggregateVerdicts([v('ORIGIN_CERT'), v('NOT_HOSTED')]).status, 'NOT_HOSTED');
    assert.equal(V.aggregateVerdicts([v('ORIGIN_CERT'), v('NEEDS_UPDATE')]).status, 'NEEDS_UPDATE');
    assert.deepEqual(V.aggregateVerdicts([v('UPDATED'), v('PRIVATE_CERT')]).warnings, ['mixed']);
  });

  test('now matters: the same m01 test gains `expired` after 2026-11-29 (why fixtures pass capturedAt)', () => {
    const later = V.classifyTest(testsOf('m01-github-valid')[0], { name: 'github.com', expect: NEW_GH, now: Date.parse('2027-01-01') });
    assert.deepEqual(later.warnings, ['expired']);
  });

  test('a trimmed test classifies like the raw one', () => {
    const raw = testsOf('m01-github-valid')[0];
    const a = V.classifyTest(raw, { name: 'github.com', expect: { ...OTHER, spkiHex: NEW_GH.spkiHex }, now: at('m01-github-valid') });
    const b = V.classifyTest(V.trimTest(raw), { name: 'github.com', expect: { ...OTHER, spkiHex: NEW_GH.spkiHex }, now: at('m01-github-valid') });
    assert.deepEqual(b, a);
  });
});

describe('aggregateVerdicts', () => {
  test('the worst certificate verdict wins; a failure never hides a certificate', () => {
    const a = V.aggregateVerdicts([V_UPDATED(), V_OLD()]);
    assert.equal(a.status, 'NEEDS_UPDATE');
    assert.equal(a.agreement, 'mixed');
    assert.ok(a.warnings.includes('mixed'));
    assert.equal(a.probes.length, 2);
    const b = V.aggregateVerdicts([V_TIMEOUT(), V_UPDATED()]);
    assert.equal(b.status, 'UPDATED');
    assert.deepEqual(b.warnings, ['mixed']);
    assert.ok(b.served, 'served = the chosen probe certificate');
    const c = V.aggregateVerdicts([V_UPDATED(), V_NOT_COVERED()]);
    assert.equal(c.status, 'NOT_HOSTED', 'NEEDS_UPDATE > NOT_HOSTED > UPDATED');
  });

  test('without a certificate: TLS_ERROR > TIMEOUT > CLOSED; all null → the first error', () => {
    assert.equal(V.aggregateVerdicts([V_CLOSED(), V_TIMEOUT()]).status, 'TIMEOUT');
    assert.equal(V.aggregateVerdicts([V_TIMEOUT(), V_SNI(), V_CLOSED()]).status, 'TLS_ERROR');
    const nulls = V.aggregateVerdicts([cls('m20-nxdomain', 'x.example.com', OTHER), cls('m21-private-resolve', 'x.example.com', OTHER)]);
    assert.deepEqual([nulls.status, nulls.error, nulls.agreement], [null, 'dns', 'all']);
    assert.equal(V.aggregateVerdicts([]), null);
  });

  test('one probe = that probe; warnings are a union', () => {
    const one = V.aggregateVerdicts([V_CHAIN()]);
    assert.deepEqual([one.status, one.agreement, one.warnings], ['UPDATED', 'all', ['chain-incomplete']]);
    const two = V.aggregateVerdicts([V_CHAIN(), V_UPDATED()]);
    assert.deepEqual([two.status, two.agreement, two.warnings], ['UPDATED', 'all', ['chain-incomplete']]);
  });
});

describe('applyWorksRule', () => {
  test('a certificate on ip:port turns a refused name into NOT_HOSTED / refused-name, reversibly', () => {
    const a = done(row({ name: 'github.com' }), [V_UPDATED()]);
    const b = done(row({ name: 'www.example.com' }), [V_SNI()]);
    const c = done(row({ name: 'api.example.com', port: 8443 }), [V_SNI()]);
    assert.deepEqual(V.applyWorksRule([a, b, c]), [a, b, c]);
    assert.deepEqual([b.status, b.reason], ['NOT_HOSTED', 'refused-name']);
    assert.deepEqual([c.status, c.reason], ['TLS_ERROR', 'sni-refused'], 'another port is not affected');
    assert.deepEqual(V.applyWorksRule([a, b, c]), [], 'idempotent');
    done(a, [V_TIMEOUT()]); // re-check: the working row now times out
    assert.deepEqual(V.applyWorksRule([a, b, c]), [a, b]);
    assert.deepEqual([b.status, b.reason], ['TLS_ERROR', 'sni-refused']);
  });

  test('reset counts as a refusal; not-tls and the ALPN alert 120 do not', () => {
    const cert = done(row({ name: 'github.com' }), [V_UPDATED()]);
    const c = (raw) => V.classifyTest(failed(raw), { name: 'x.example.com', expect: OTHER, now: NOW });
    const reset = done(row({ name: 'r.example.com' }), [c('read ECONNRESET')]);
    const alert = done(row({ name: 'a.example.com' }), [c('SSL alert number 70')]);
    const alpn = done(row({ name: 'h2.example.com' }), [c('SSL alert number 120')]);
    const notTls = done(row({ name: 'p.example.com' }), [c('wrong version number')]);
    V.applyWorksRule([cert, reset, alert, alpn, notTls]);
    assert.deepEqual([reset.status, reset.reason], ['NOT_HOSTED', 'refused-name']);
    assert.deepEqual([alert.status, alert.reason], ['NOT_HOSTED', 'refused-name']);
    assert.deepEqual([alpn.status, alpn.reason], ['TLS_ERROR', 'tls-alert']);
    assert.deepEqual([notTls.status, notTls.reason], ['TLS_ERROR', 'not-tls']);
  });

  test('a close during the handshake (strict SNI) is a refusal too, as the CLI treats ssl.SSLEOFError', () => {
    const early = 'Client network socket disconnected before secure TLS connection was established';
    const c = (raw) => V.classifyTest(failed(raw), { name: 'api.example.com', expect: OTHER, now: NOW });
    assert.deepEqual([c(early).status, c(early).reason], ['TLS_ERROR', 'reset'], 'alone: a TLS error, never "unknown"');
    const cert = done(row({ name: 'github.com' }), [V_UPDATED()]);
    const closed = done(row({ name: 'api.example.com' }), [c(early)]);
    V.applyWorksRule([cert, closed]);
    assert.deepEqual([closed.status, closed.reason], ['NOT_HOSTED', 'refused-name']);
  });
});

describe('serverStatus (CLI server_status parity)', () => {
  const sr = (status, reason = null, extra = {}) => ({ verdict: {}, status, reason, newCertCovers: true, warnings: [], ...extra });
  const cases = [
    [[sr('UPDATED'), sr('NOT_HOSTED')], 'UPDATED'],
    [[sr('NEEDS_UPDATE', 'old-cert', { newCertCovers: false }), sr('UPDATED')], 'UPDATED'],
    [[sr('NEEDS_UPDATE', 'old-cert', { newCertCovers: false })], 'NOT_HOSTED'],
    [[sr('NEEDS_UPDATE'), sr('UPDATED')], 'NEEDS_UPDATE'],
    [[sr('TLS_ERROR'), sr('NOT_HOSTED')], 'TLS_ERROR'],
    [[sr('NOT_HOSTED'), sr('TIMEOUT', 'connect-timeout')], 'NOT_HOSTED'],
    [[sr('TIMEOUT', 'tls-timeout'), sr('NOT_HOSTED')], 'TIMEOUT'],
    [[sr('TIMEOUT', 'connect-timeout'), sr('CLOSED')], 'TIMEOUT'],
    [[sr('CLOSED')], 'CLOSED'],
    [[sr('ORIGIN_CERT', 'origin-ca'), sr('TIMEOUT', 'connect-timeout')], 'ORIGIN_CERT'],
    [[sr('ORIGIN_CERT', 'origin-ca'), sr('UPDATED')], 'UPDATED'],
    [[sr('ORIGIN_CERT', 'origin-ca'), sr('NEEDS_UPDATE')], 'NEEDS_UPDATE'],
    [[sr('PRIVATE_CERT', 'self-signed'), sr('ORIGIN_CERT', 'origin-ca')], 'ORIGIN_CERT'],
    [[sr('PRIVATE_CERT', 'self-signed'), sr('TLS_ERROR')], 'PRIVATE_CERT'],
    [[sr('ORIGIN_CERT', 'origin-ca', { newCertCovers: false })], 'NOT_HOSTED'],
    [[sr('PRIVATE_CERT', 'self-signed', { newCertCovers: false }), sr('CLOSED')], 'NOT_HOSTED'],
    // an Origin CA rollout: an older Origin CA certificate is still old
    [[sr('NEEDS_UPDATE', 'old-cert', { warnings: ['origin-ca'] }), sr('TIMEOUT', 'connect-timeout')], 'NEEDS_UPDATE'],
    [[], null],
    [[{ verdict: null, status: null, state: 'pending' }], null]
  ];
  for (const [rows, want] of cases) {
    test(`[${rows.map((r) => `${r.status}${r.reason ? `/${r.reason}` : ''}${r.newCertCovers === false ? '(not covered)' : ''}`).join(', ')}] → ${want}`, () => {
      assert.equal(V.serverStatus(rows), want);
    });
  }

  test('stale rows count by their last verdict; rows that never answered are ignored', () => {
    assert.equal(V.serverStatus([sr('UPDATED'), sr('NEEDS_UPDATE', 'old-cert', { state: 'not-run', stale: true })]), 'NEEDS_UPDATE');
    assert.equal(V.serverStatus([sr('UPDATED'), { verdict: null, status: null, state: 'error' }]), 'UPDATED');
  });
});

describe('exposureOf', () => {
  const px = (verdicts, name = 'github.com') => settle([done(row({ name, via: 'hint', proxied: true }), verdicts)])[0].exposure;

  test('the table', () => {
    assert.equal(px([V_UPDATED()]), 'exposed');
    assert.equal(px([V_OLD()]), 'exposed');
    assert.equal(px([V_NOT_COVERED()], 'api.github.com'), 'not-this-host');
    assert.equal(px([V_SNI()]), 'not-this-host');
    assert.equal(px([V_TIMEOUT()]), 'no-answer', 'one probe cannot prove "filtered"');
    assert.equal(px([V_TIMEOUT(), V_TIMEOUT_BR()]), 'filtered', 'two probes, two ASNs');
    assert.equal(px([V_TIMEOUT(), V_TIMEOUT()]), 'no-answer', 'two probes, one ASN');
    assert.equal(px([V_CLOSED()]), 'closed');
    assert.equal(px([V_UPDATED(), V_TIMEOUT()]), 'exposed');
    assert.equal(px([V_TIMEOUT(), V_CLOSED()]), 'unknown');
    const fault = V.classifyTest(failed('probe crashed', { failureSource: 'internal' }), { name: 'api.github.com', expect: OTHER, now: NOW });
    assert.equal(px([V_NOT_COVERED(), fault], 'api.github.com'), 'not-this-host', 'any probe saying "not this name" is enough');
    assert.equal(px([V_TIMEOUT(), fault]), 'unknown');
    const reset = V.classifyTest(failed('read ECONNRESET'), { name: 'shop.example.com', expect: OTHER, now: NOW });
    const rows = settle([done(row({ name: 'github.com' }), [V_UPDATED()]),
      done(row({ name: 'shop.example.com', via: 'hint', proxied: true }), [reset])]);
    assert.deepEqual([rows[1].reason, rows[1].exposure], ['refused-name', 'not-this-host'], 'the works rule counts');
    const tlsTimeout = V.classifyTest(failed('TLS handshake timed out'), { name: 'github.com', expect: OTHER, now: NOW });
    assert.equal(px([tlsTimeout]), 'unknown', 'TCP answered: not filtered');
  });

  test('null when not proxied or never answered', () => {
    assert.equal(V.exposureOf(done(row({ name: 'github.com' }), [V_UPDATED()])), null);
    assert.equal(V.exposureOf(row({ proxied: true })), null);
    assert.equal(V.exposureOf(null), null);
  });
});

describe('recheckRows / requeueRows / applyOriginOptIn / verifyCost', () => {
  const build = () => {
    const needs = done(row({ name: 'github.com' }), [V_OLD()]);
    const tlsErr = done(row({ ip: '1.2.3.5', name: 'x.example.com' }), [V_SNI()]);
    const timeout = done(row({ ip: '1.2.3.6', name: 'github.com' }), [V_TIMEOUT()]);
    const err = Object.assign(row({ ip: '1.2.3.7' }), { state: 'error', error: { code: 'deadline', message: '', raw: null } });
    const notRun = Object.assign(row({ ip: '1.2.3.8' }), { state: 'not-run', notRun: 'quota' });
    const chain = done(row({ ip: '5.6.7.8', name: 'incomplete-chain.badssl.com' }), [V_CHAIN()]);
    const clean = done(row({ ip: '5.6.7.9', name: 'github.com' }), [V_UPDATED()]);
    const skipped = V.createVerifyRows([pair({ ip: '10.0.0.5', skip: 'private' })])[0];
    const filtered = done(row({ ip: '5.6.7.10', name: 'github.com', via: 'hint', proxied: true }), [V_TIMEOUT()]);
    const optional = V.createVerifyRows([pair({ ip: '5.6.7.12', via: 'hint', proxied: true })])[0];
    const rows = settle([needs, tlsErr, timeout, err, notRun, chain, clean, skipped, filtered, optional]);
    return { rows, needs, tlsErr, timeout, err, notRun, chain, clean, skipped, filtered, optional };
  };

  test('recheckRows includes what may change and excludes expected / clean / skipped / opted-out rows', () => {
    const b = build();
    assert.equal(b.optional.state, 'not-run');
    assert.equal(b.optional.notRun, 'optional');
    assert.deepEqual(V.recheckRows(b.rows), [b.needs, b.tlsErr, b.timeout, b.err, b.notRun, b.chain]);
  });

  test('recheckRows: origin candidates answering "not this name" are expected, never re-probed; DNS refusals are', () => {
    const mail = { server: { id: 'mail01', name: 'mail01' } };
    const hint = (name, verdicts, ip) => done(row({ ip, name, via: 'hint', proxied: true, ...mail }), verdicts);
    // the candidate serves its own certificate (NOT_HOSTED / not-covered) or, on its other address,
    // refuses the SNI (alert 40) with nothing there serving a certificate (no works rule)
    const own = hint('shop.example.com', [cls('m01-github-valid', 'shop.example.com', NEW_GH)], '5.6.7.20');
    const sni = hint('blog.example.com', [V_SNI()], '5.6.7.23');
    const dnsSni = done(row({ ip: '5.6.7.21', name: 'api.example.com' }), [V_SNI()]);
    const rows = settle([own, sni, dnsSni]);
    assert.deepEqual([own.status, own.exposure, sni.status, sni.exposure], ['NOT_HOSTED', 'not-this-host', 'TLS_ERROR', 'not-this-host']);
    assert.deepEqual(V.recheckRows(rows), [dnsSni], 'a DNS-matched name refused by its own server is a problem');
    // decided from the current verdict, not a stale stored exposure
    own.exposure = 'unknown';
    assert.deepEqual(V.recheckRows(rows), [dnsSni]);
  });

  test('requeueRows keeps the last verdict, marked stale', () => {
    const b = build();
    V.requeueRows([b.needs, b.skipped]);
    assert.equal(b.needs.state, 'pending');
    assert.equal(b.needs.stale, true);
    assert.equal(b.needs.status, 'NEEDS_UPDATE');
    assert.ok(b.needs.verdict);
    assert.equal(b.skipped.state, 'skipped');
  });

  test('applyOriginOptIn toggles never-checked origin pairs only', () => {
    const b = build();
    assert.deepEqual(V.applyOriginOptIn(b.rows, true), [b.optional]);
    assert.equal(b.optional.state, 'pending');
    assert.deepEqual(V.applyOriginOptIn(b.rows, false), [b.optional]);
    assert.deepEqual([b.optional.state, b.optional.notRun], ['not-run', 'optional']);
    assert.equal(b.filtered.state, 'done', 'a hint row with a verdict is never touched');
  });

  test('a zone-file origin is an origin pair: it waits for the opt-in and counts as an origin check', () => {
    const zone = V.createVerifyRows([pair({ ip: '5.6.7.13', name: 'shop.example.com', via: 'zone', proxied: true })])[0];
    assert.ok(V.isOriginPair(zone) && V.isOriginPair(pair({ via: 'hint' })) && !V.isOriginPair(pair()) && !V.isOriginPair(null));
    assert.deepEqual([zone.state, zone.notRun], ['not-run', 'optional']);
    assert.deepEqual(V.verifyCost([zone], { now: NOW }), { checks: 0, reuse: 0, probes: 0, servers: 0, origins: 0, optional: 1 });
    assert.deepEqual(V.applyOriginOptIn([zone], true), [zone]);
    assert.equal(zone.state, 'pending');
    assert.deepEqual(V.verifyCost([zone], { now: NOW }), { checks: 1, reuse: 0, probes: 1, servers: 1, origins: 1, optional: 0 });
    assert.deepEqual(V.applyOriginOptIn([zone], false), [zone]);
    assert.deepEqual([zone.state, zone.notRun], ['not-run', 'optional']);
  });

  test('verifyCost: a reusable paid measurement costs nothing', () => {
    const a = row({ ip: '1.2.3.4' });
    const b = Object.assign(row({ ip: '1.2.3.5' }), { measurementId: 'm1', measurementDone: false, measurementAt: NOW - 1000 });
    const c = Object.assign(row({ ip: '1.2.3.6' }), { measurementId: 'm2', measurementDone: false, measurementAt: NOW - 200000 });
    const d = Object.assign(row({ ip: '1.2.3.7' }), { state: 'done' });
    const opt = V.createVerifyRows([pair({ ip: '1.2.3.8', via: 'hint', proxied: true })])[0];
    const hint = row({ ip: '1.2.3.9', via: 'hint', proxied: true, server: null });
    assert.deepEqual(V.verifyCost([a, b, c, d, opt, hint], { now: NOW }),
      { checks: 3, reuse: 1, probes: 3, servers: 2, origins: 1, optional: 1 });
    assert.deepEqual(V.verifyCost([a, b], { now: NOW, probesPerCheck: 2 }),
      { checks: 1, reuse: 1, probes: 2, servers: 1, origins: 0, optional: 0 });
  });
});

/* ---- pairs ------------------------------------------------------------------------- */

const host = (name, { ips = [], kind = 'direct', provider = null, hidesOrigin = false, certManaged = false, covered = true,
  wildcardSuspect = false } = {}) => ({
  name, origins: ['input'],
  resolution: { status: 'NOERROR', ipv4: ips.filter((ip) => !ip.includes(':')), ipv6: ips.filter((ip) => ip.includes(':')), cnames: [] },
  classification: { kind, provider: provider ? { id: provider.toLowerCase(), name: provider } : null, hidesOrigin,
    certManagedByProvider: certManaged, dangling: false },
  cert: covered === null ? null : { covered, by: covered ? '*.example.com' : null },
  servers: [], wildcardSuspect, ipHints: [], candidateNetworks: [], customOnly: false
});
const srv = (id) => ({ id, name: id, ips: [], groups: [] });
const e = (name, ip, via = 'dns', covered = true) => ({ name, ip, covered, via });

function scanResult() {
  const cf = { kind: 'cloudflare', provider: 'Cloudflare', hidesOrigin: true, certManaged: true };
  return {
    hosts: [
      host('www.example.com', { ips: ['1.2.3.4'] }),
      host('zone.example.com', { ips: ['1.2.3.4'] }),
      host('shop.example.com', { ips: ['104.16.5.6'], ...cf }),
      host('old.example.com', { ips: ['1.2.3.4'], covered: false }),
      host('suspect.example.com', { ips: ['1.2.3.4'], wildcardSuspect: true }),
      host('edge.example.com', { ips: ['104.16.5.5'] }),
      host('vpn.example.com', { ips: ['10.0.0.5'], kind: 'private' }),
      host('api.example.com', { ips: ['5.6.7.8'] }),
      host('x_y.example.com', { ips: ['5.6.7.8'] }),
      host('doc.example.com', { ips: ['198.51.100.7'] }),
      host('v6doc.example.com', { ips: ['2001:db8::10'] }),
      host('legacy.example.com', { ips: ['54.1.2.3'] }),
      host('nope.example.com', { ips: ['54.1.2.3'], covered: false }),
      host('hidden.example.com', { ips: ['104.16.5.7'], ...cf }),
      host('site.example.com', { ips: ['1.2.3.9'], kind: 'platform', provider: 'Wix', certManaged: true })
    ],
    servers: [
      // scanner order: needs-cert groups (by name), then maybe-needs-cert
      { server: srv('db01'), hosts: [e('vpn.example.com', '10.0.0.5')], needsCert: true, maybeNeedsCert: false },
      { server: srv('edge01'), hosts: [e('edge.example.com', '104.16.5.5')], needsCert: true, maybeNeedsCert: false },
      { server: srv('web01'), needsCert: true, maybeNeedsCert: false, hosts: [
        e('shop.example.com', '1.2.3.4', 'hint'), e('zone.example.com', '1.2.3.4', 'zone'), e('www.example.com', '1.2.3.4'),
        e('old.example.com', '1.2.3.4', 'dns', false), e('suspect.example.com', '1.2.3.4')] },
      { server: srv('web01b'), hosts: [e('www.example.com', '1.2.3.4')], needsCert: true, maybeNeedsCert: false },
      { server: srv('web02'), hosts: [e('shop.example.com', '2a01:4f8::1', 'hint')], needsCert: false, maybeNeedsCert: true }
    ],
    unmatchedIps: [
      { ip: '2001:db8::10', hosts: ['v6doc.example.com'], provider: null, private: false },
      { ip: '198.51.100.7', hosts: ['doc.example.com'], provider: null, private: false },
      { ip: '54.1.2.3', hosts: ['legacy.example.com', 'nope.example.com'], provider: null, private: false },
      { ip: '5.6.7.8', hosts: ['x_y.example.com', 'api.example.com'], provider: null, private: false },
      { ip: '1.2.3.4', hosts: ['www.example.com'], provider: null, private: false } // defensive duplicate
    ]
  };
}

describe('buildVerifyPairs', () => {
  test('pairs, order, skips, dedupe and attribution', () => {
    const { pairs, stats } = V.buildVerifyPairs(scanResult());
    assert.deepEqual(pairs.map((p) => `${p.server?.id ?? '-'} ${p.name} ${p.ip} ${p.via} ${p.skip ?? 'ok'}`), [
      'db01 vpn.example.com 10.0.0.5 dns private',
      'edge01 edge.example.com 104.16.5.5 dns cdn-edge',
      'web01 www.example.com 1.2.3.4 dns ok',
      'web01 zone.example.com 1.2.3.4 zone ok',
      'web01 shop.example.com 1.2.3.4 hint ok',
      'web02 shop.example.com 2a01:4f8::1 hint ok',
      '- api.example.com 5.6.7.8 dns ok',
      '- x_y.example.com 5.6.7.8 dns bad-name',
      '- legacy.example.com 54.1.2.3 dns ok',
      '- doc.example.com 198.51.100.7 dns reserved',
      '- v6doc.example.com 2001:db8::10 dns reserved'
    ]);
    const www = pairs.find((p) => p.name === 'www.example.com');
    assert.equal(www.key, '1.2.3.4|443|www.example.com');
    assert.deepEqual(www.alsoServers, [{ id: 'web01b', name: 'web01b' }], 'a shared VIP keeps the second server');
    assert.equal(pairs.filter((p) => p.key === www.key).length, 1, 'the unmatched duplicate is dropped');
    const shop = pairs.find((p) => p.name === 'shop.example.com');
    assert.deepEqual([shop.proxied, shop.provider, shop.needsCert, shop.newCertCovers], [true, 'Cloudflare', true, true]);
    assert.equal(pairs.find((p) => p.ip === '2a01:4f8::1').needsCert, false, 'maybe-needs-cert group');
    assert.equal(pairs.find((p) => p.name === 'api.example.com').server, null);
    assert.ok(!pairs.some((p) => p.name === 'old.example.com' || p.name === 'nope.example.com'), 'not covered → left out');
    assert.ok(!pairs.some((p) => p.name === 'suspect.example.com'), 'wildcard suspects are left out');
    assert.deepEqual(stats, {
      names: 10, ips: 8, servers: 4, checkable: 6, originPairs: 3,
      skipped: { private: 1, reserved: 2, 'cdn-edge': 1, 'bad-name': 1, 'bad-port': 0 },
      proxiedNoOrigin: 1, managed: 1
    });
  });

  test('every pair is returned: the cap on checks is applied to the rows of a scope', () => {
    const { pairs } = V.buildVerifyPairs(scanResult());
    assert.equal(pairs.length, 11);
    assert.ok(!pairs.some((p) => p.skip === 'over-cap'));
    const over = (rows) => rows.filter((r) => r.overCap).map((r) => `${r.name} ${r.ip} ${r.state} ${r.skip ?? r.notRun}`);
    // Skipped pairs cost nothing; the first DNS pair of every address (www, api, legacy) comes first, the hints last.
    assert.deepEqual(over(V.createVerifyRows(pairs, { maxRows: 2, origins: true })), [
      'zone.example.com 1.2.3.4 skipped over-cap', 'shop.example.com 1.2.3.4 skipped over-cap',
      'shop.example.com 2a01:4f8::1 skipped over-cap', 'legacy.example.com 54.1.2.3 skipped over-cap'
    ]);
    const rows = V.createVerifyRows(pairs, { maxRows: 2 });
    assert.deepEqual(over(rows), [
      'zone.example.com 1.2.3.4 not-run optional', 'shop.example.com 1.2.3.4 not-run optional',
      'shop.example.com 2a01:4f8::1 not-run optional', 'legacy.example.com 54.1.2.3 skipped over-cap'
    ], 'an origin pair past the cap waits for the opt-in like the others');
    assert.equal(V.createVerifyRows(pairs).filter((r) => r.overCap).length, 0, 'VERIFY_MAX_ROWS by default');
    const vpn = rows.find((r) => r.name === 'vpn.example.com');
    assert.deepEqual([vpn.skip, vpn.overCap], ['private', false], 'a pair skip is kept and costs nothing');
  });

  test('empty / odd input never throws', () => {
    assert.deepEqual(V.buildVerifyPairs(null).pairs, []);
    assert.deepEqual(V.buildVerifyPairs({ servers: [{ server: null, hosts: null }] }).pairs, []);
  });
});

describe('scopePairs / createVerifyRows', () => {
  test('perIp keeps one DNS pair and one origin pair (zone before hint) per IP; skipped pairs stay', () => {
    const { pairs } = V.buildVerifyPairs(scanResult());
    const per = V.scopePairs(pairs, 'perIp');
    assert.deepEqual(per.filter((p) => p.ip === '1.2.3.4').map((p) => p.name), ['www.example.com', 'zone.example.com']);
    assert.ok(per.some((p) => p.name === 'x_y.example.com'), 'skipped kept');
    assert.equal(per.length, pairs.length - 1);
    assert.deepEqual(V.scopePairs(pairs, 'all'), pairs);
    assert.notEqual(V.scopePairs(pairs, 'all'), pairs, 'a copy');
  });

  test('origin pairs, hint and zone alike, wait for the opt-in; DNS rows do not', () => {
    const { pairs } = V.buildVerifyPairs(scanResult());
    const rows = V.createVerifyRows(pairs);
    const by = (name, ip) => rows.find((r) => r.name === name && (!ip || r.ip === ip));
    assert.deepEqual([by('shop.example.com', '1.2.3.4').state, by('shop.example.com', '1.2.3.4').notRun], ['not-run', 'optional']);
    assert.deepEqual([by('zone.example.com').state, by('zone.example.com').notRun], ['not-run', 'optional'],
      "the zone file's exact origin is not in public DNS either");
    assert.equal(by('www.example.com').state, 'pending');
    assert.equal(by('vpn.example.com').state, 'skipped');
    const on = V.createVerifyRows(pairs, { origins: true });
    assert.equal(on.find((r) => r.name === 'shop.example.com').state, 'pending');
    assert.equal(on.find((r) => r.name === 'zone.example.com').state, 'pending');
    assert.notEqual(rows[2].alsoServers, pairs[2].alsoServers, 'rows own their arrays');
  });
});

describe('the cap on checks', () => {
  /**
   * web01 serves many covered names on one address (and origin hints for proxied names); web02
   * serves api, or only proxied names whose origin the zone file gives (`zones`).
   */
  function busy(names, { hints = 0, zones = 0 } = {}) {
    const dnsNames = Array.from({ length: names }, (_, i) => `n${i}.example.com`);
    const hintNames = Array.from({ length: hints }, (_, i) => `p${i}.example.com`);
    const zoneNames = Array.from({ length: zones }, (_, i) => `z${i}.example.com`);
    const cf = { kind: 'cloudflare', provider: 'Cloudflare', hidesOrigin: true, certManaged: true };
    return {
      hosts: [...dnsNames.map((n) => host(n, { ips: ['1.2.3.4'] })), ...hintNames.map((n) => host(n, { ips: ['104.16.5.6'], ...cf })),
        ...zoneNames.map((n) => host(n, { ips: ['104.16.5.7'], ...cf })), host('api.example.com', { ips: ['1.2.3.5'] })],
      servers: [
        { server: srv('web01'), needsCert: true, hosts: [...dnsNames.map((n) => e(n, '1.2.3.4')), ...hintNames.map((n) => e(n, '1.2.3.4', 'hint'))] },
        { server: srv('web02'), needsCert: true, hosts: zones ? zoneNames.map((n) => e(n, '1.2.3.5', 'zone')) : [e('api.example.com', '1.2.3.5')] }
      ],
      unmatchedIps: []
    };
  }
  const short = (r) => r.name.replace('.example.com', '');
  const states = (rows) => rows.map((r) => `${short(r)} ${r.state}${r.skip ? ` ${r.skip}` : r.notRun ? ` ${r.notRun}` : ''}`);
  const upd = (rows) => settle(rows.map((r) => (r.state === 'pending' ? done(r, [V_UPDATED()]) : r)));

  test('it is applied after the scope, and every server address gets a check before any gets a second', () => {
    const { pairs } = V.buildVerifyPairs(busy(8));
    const all = V.createVerifyRows(V.scopePairs(pairs, 'all'), { maxRows: 5 });
    assert.deepEqual(all.filter((r) => r.state === 'pending').map(short), ['n0', 'n1', 'n2', 'n3', 'api']);
    assert.deepEqual(all.filter((r) => r.skip === 'over-cap').map(short), ['n4', 'n5', 'n6', 'n7']);
    const perIp = V.createVerifyRows(V.scopePairs(pairs, 'perIp'), { maxRows: 5 });
    assert.deepEqual(perIp.map((r) => `${short(r)} ${r.state}`), ['n0 pending', 'api pending'], 'one name per IP reaches web02');
  });

  test('checkCount: the checks a scope offers, as createVerifyRows makes them, without building rows', () => {
    const cases = [[busy(8), 5], [busy(1, { hints: 6 }), 4], [busy(8, { zones: 3 }), 5], [busy(3, { hints: 2, zones: 2 }), 100]];
    for (const [result, maxRows] of cases) {
      const { pairs } = V.buildVerifyPairs(result);
      for (const scope of ['all', 'perIp']) {
        for (const origins of [false, true]) {
          const scoped = V.scopePairs(pairs, scope);
          assert.equal(V.checkCount(scoped, { maxRows, origins }),
            V.createVerifyRows(scoped, { maxRows, origins }).filter((r) => r.state === 'pending').length, `${scope} ${origins}`);
        }
      }
    }
    const { pairs } = V.buildVerifyPairs(busy(600));
    assert.deepEqual([V.checkCount(pairs), V.checkCount(V.scopePairs(pairs, 'perIp'))], [V.VERIFY_MAX_ROWS, 2]);
    assert.equal(V.checkCount(null), 0);
  });

  test('hint pairs come after every DNS and zone pair; past the cap they wait like optional ones while the opt-in is off', () => {
    const { pairs } = V.buildVerifyPairs(busy(1, { hints: 6 }));
    const on = V.createVerifyRows(pairs, { maxRows: 4, origins: true });
    assert.deepEqual(states(on), ['n0 pending', 'p0 pending', 'p1 pending', 'p2 skipped over-cap', 'p3 skipped over-cap',
      'p4 skipped over-cap', 'p5 skipped over-cap', 'api pending']);
    const off = V.createVerifyRows(pairs, { maxRows: 4 });
    assert.deepEqual(states(off), ['n0 pending', 'p0 not-run optional', 'p1 not-run optional', 'p2 not-run optional',
      'p3 not-run optional', 'p4 not-run optional', 'p5 not-run optional', 'api pending']);
    assert.equal(V.verifyCost(off, { now: NOW }).optional, 2, 'the opt-in would send p0 and p1, never the others');
    assert.deepEqual(V.cliPlan(off), { targets: [], names: [], rows: 0 }, 'not handed to the CLI either');
    assert.deepEqual(V.notHereParts(V.summarizeVerify(off)), []);
    // The opt-in moves them both ways: within the cap to pending, past it to over-cap; nothing else moves.
    const rows = V.createVerifyRows(pairs, { maxRows: 4 });
    assert.deepEqual(V.applyOriginOptIn(rows, true).map(short), ['p0', 'p1', 'p2', 'p3', 'p4', 'p5']);
    assert.deepEqual(states(rows), states(on));
    V.applyOriginOptIn(rows, false);
    assert.deepEqual(states(rows), states(off));
    assert.deepEqual(V.requeueRows(rows.slice(3, 4)).map((r) => r.state), ['not-run'], 'a row past the cap is never queued');
    // Opted out, the origin checks past the cap count no more than the optional ones: both servers are live.
    upd(off);
    const sum = V.summarizeVerify(off);
    assert.deepEqual([sum.servers.live, sum.servers.base], [2, 2]);
    assert.equal(V.verifyHeadline(sum)[0].key, 'vfy.head.all');
    // Opted in, they speak for web01: it is not live while they were never checked.
    upd(on);
    const sumOn = V.summarizeVerify(on);
    assert.deepEqual([sumOn.servers.live, sumOn.servers.base], [1, 2]);
    assert.ok(!V.verifyHeadline(sumOn).some((x) => x.key === 'vfy.head.all'));
  });

  test('a server known only by the zone file gets its check like any other and never goes green with names past the cap', () => {
    // 500 names on web01 and web02 only as the zone origin of z0: the opt-in on, web02 is checked, web01 is not all checked.
    const big = V.createVerifyRows(V.buildVerifyPairs(busy(500, { zones: 1 })).pairs, { origins: true });
    assert.deepEqual(states(big.filter((r) => r.server.id === 'web02' || r.overCap)), ['n499 skipped over-cap', 'z0 pending']);
    upd(big);
    const bigSum = V.summarizeVerify(big);
    assert.deepEqual([bigSum.servers.total, bigSum.servers.live, bigSum.servers.base], [2, 1, 2]);
    assert.ok(!V.verifyHeadline(bigSum).some((x) => x.key === 'vfy.head.all'));

    const { pairs, stats } = V.buildVerifyPairs(busy(8, { zones: 3 }));
    const on = V.createVerifyRows(pairs, { maxRows: 5, origins: true });
    assert.deepEqual(on.filter((r) => r.state === 'pending').map(short), ['n0', 'n1', 'n2', 'n3', 'z0']);
    assert.deepEqual(on.filter((r) => r.skip === 'over-cap').map(short), ['n4', 'n5', 'n6', 'n7', 'z1', 'z2']);
    upd(on);
    const sum = V.summarizeVerify(on);
    assert.deepEqual([sum.servers.total, sum.servers.base, sum.servers.live, sum.servers.updated], [2, 2, 0, 2]);
    assert.equal(sum.servers.list.find((s) => s.key === 'web02').incomplete, true, 'z1 and z2 were never checked');
    const head = V.verifyHeadline(sum, stats);
    assert.deepEqual(head[0], { key: 'vfy.head.partial', variant: 'info', params: { live: 0, total: 2 } });
    assert.deepEqual(head.at(-1).parts, [{ key: 'vfy.notHere.over-cap', params: { count: 6 } }]);
    assert.deepEqual(V.cliPlan(on).targets, ['1.2.3.4', '1.2.3.5']);

    // The opt-in off, web02 is left out on purpose: not counted, not over the cap, not in the CLI card.
    const off = V.createVerifyRows(pairs, { maxRows: 5 });
    assert.deepEqual(states(off.filter((r) => r.server.id === 'web02')), ['z0 not-run optional', 'z1 not-run optional', 'z2 not-run optional']);
    upd(off);
    const sumOff = V.summarizeVerify(off);
    assert.deepEqual([sumOff.servers.total, sumOff.servers.live], [1, 0]);
    assert.deepEqual(V.notHereParts(sumOff), [{ key: 'vfy.notHere.over-cap', params: { count: 4 } }]);
    assert.deepEqual(V.cliPlan(off).targets, ['1.2.3.4']);
  });

  test('zone origins waiting for the opt-in take one cap place per address, never a DNS name of another server', () => {
    // A Cloudflare zone import: 400 exact origins on web01 first, 400 DNS names on web02.
    const cf = { kind: 'cloudflare', provider: 'Cloudflare', hidesOrigin: true, certManaged: true };
    const zoneNames = Array.from({ length: 400 }, (_, i) => `z${i}.example.com`);
    const dnsNames = Array.from({ length: 400 }, (_, i) => `d${i}.example.com`);
    const { pairs } = V.buildVerifyPairs({
      hosts: [...zoneNames.map((n) => host(n, { ips: ['104.16.5.7'], ...cf })), ...dnsNames.map((n) => host(n, { ips: ['1.2.3.5'] }))],
      servers: [
        { server: srv('web01'), needsCert: true, hosts: zoneNames.map((n) => e(n, '1.2.3.4', 'zone')) },
        { server: srv('web02'), needsCert: true, hosts: dnsNames.map((n) => e(n, '1.2.3.5')) }
      ],
      unmatchedIps: []
    });
    const off = V.createVerifyRows(pairs);
    assert.equal(off.filter((r) => r.state === 'pending').length, 400);
    assert.ok(off.filter((r) => r.server.id === 'web02').every((r) => r.state === 'pending'));
    assert.deepEqual(V.notHereParts(V.summarizeVerify(off)), [], 'nothing is over the limit while 400 checks are planned');
    const on = V.createVerifyRows(pairs, { origins: true });
    assert.equal(on.filter((r) => r.state === 'pending').length, V.VERIFY_MAX_ROWS);
    const over = on.filter((r) => r.skip === 'over-cap');
    assert.equal(over.length, 300);
    assert.ok(over.every((r) => r.via === 'zone'));
    assert.equal(V.checkCount(pairs), 400);
  });

  test('a server with names past the cap is never called live; its names go to the CLI card', () => {
    const { pairs, stats } = V.buildVerifyPairs(busy(8));
    const rows = V.createVerifyRows(pairs, { maxRows: 5 });
    upd(rows);
    const sum = V.summarizeVerify(rows);
    assert.deepEqual([sum.servers.total, sum.servers.base, sum.servers.live, sum.servers.updated], [2, 2, 1, 2]);
    assert.equal(sum.servers.incomplete, 0, '"Check again" cannot finish it: not called partly checked');
    assert.equal(sum.servers.list.find((s) => s.key === 'web01').incomplete, true);
    const head = V.verifyHeadline(sum, stats);
    assert.deepEqual(head[0], { key: 'vfy.head.partial', variant: 'info', params: { live: 1, total: 2 } });
    assert.ok(!head.some((x) => x.key === 'vfy.head.all' || x.key === 'vfy.head.incomplete'));
    assert.deepEqual(head.at(-1).parts, [{ key: 'vfy.notHere.over-cap', params: { count: 4 } }]);
    assert.deepEqual(V.cliPlan(rows), { targets: ['1.2.3.4'], names: ['n4.example.com', 'n5.example.com', 'n6.example.com', 'n7.example.com'], rows: 4 });
  });
});

/* ---- runner ------------------------------------------------------------------------ */

/**
 * A fake Globalping client. `script[target|host]` is a list of outcomes, one per create():
 * `{ tests }` (finished measurement), `{ polls: [outcome…] }` (per poll: Error to throw or
 * `{ tests }`), `{ createError }`, `{ cost }`. `pollScript[id]` adds polls for reused ids.
 */
function fakeClient(script = {}, { delayMs = 0, clock = null } = {}) {
  const calls = { create: [], poll: [] };
  const byId = new Map();
  let seq = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  const tick = () => new Promise((r) => setTimeout(r, delayMs));
  const span = async (fn) => {
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    try {
      await tick();
      return await fn();
    } finally {
      inFlight -= 1;
    }
  };
  const abortIf = (signal) => {
    if (signal?.aborted) {
      const err = new Error('aborted');
      err.name = 'AbortError';
      throw err;
    }
  };
  const client = {
    quota: { limit: 250, remaining: 250, consumed: null, resetAt: null, cost: null, type: 'ip', source: 'create', at: new Date(NOW) },
    calls,
    get maxInFlight() { return maxInFlight; },
    pollScript: byId,
    create(body, { signal } = {}) {
      return span(async () => {
        abortIf(signal);
        const key = `${body.target}|${body.measurementOptions.request.host}`;
        calls.create.push({ key, body });
        const outcome = (script[key] || []).shift() ?? { tests: [] };
        if (outcome.createError) throw outcome.createError;
        const id = `fake${++seq}`;
        byId.set(id, outcome.polls ? [...outcome.polls] : [{ tests: outcome.tests }]);
        client.quota = { ...client.quota, remaining: client.quota.remaining - (outcome.cost ?? body.limit ?? 1) };
        return { id, probesCount: body.limit ?? 1, cost: outcome.cost ?? body.limit ?? 1, quota: client.quota };
      });
    },
    poll(id, opts = {}) {
      return span(async () => {
        abortIf(opts.signal);
        calls.poll.push({ id, opts });
        const next = (byId.get(id) || []).shift();
        if (!next) throw new GlobalpingError('not-found', 'Not Found.', { status: 404 });
        if (next instanceof Error) throw next;
        return { id, type: 'http', status: 'finished', createdAt: new Date(clock ? clock() : NOW).toISOString(), results: next.tests };
      });
    }
  };
  return client;
}

const T_UPDATED = () => testsOf('m01-github-valid').slice(0, 1);
const T_TIMEOUT = () => testsOf('m11-filtered-timeout5');
const T_SNI = () => testsOf('m12-sni-refused');
const T_INTERNAL = () => [failed('probe crashed', { failureSource: 'internal' })];
const ghRow = (ip, name = 'github.com', o = {}) => row({ ip, name, server: { id: `srv-${ip}`, name: `srv-${ip}` }, ...o });
const runOpts = (client, o = {}) => ({ client, expect: NEW_GH, now: () => NOW, ...o });

describe('runVerify', () => {
  test('concurrency: at most 4 in flight by default, 2 when asked', async () => {
    for (const [concurrency, max] of [[undefined, 4], [2, 2]]) {
      const rows = Array.from({ length: 10 }, (_, i) => ghRow(`1.2.3.${i + 1}`));
      const client = fakeClient(Object.fromEntries(rows.map((r) => [`${r.ip}|github.com`, [{ tests: T_UPDATED() }]])), { delayMs: 5 });
      const res = await V.runVerify(rows, runOpts(client, concurrency ? { concurrency } : {}));
      assert.equal(client.maxInFlight, max);
      assert.equal(client.calls.create.length, 10);
      assert.ok(rows.every((r) => r.state === 'done' && r.status === 'UPDATED'));
      assert.deepEqual(res, { spent: 10, retries: 0, stoppedBy: null });
    }
  });

  test('rows are mutated in place: onRow sees the same object pending → running → done', async () => {
    const rows = [ghRow('1.2.3.4')];
    const seen = [];
    const client = fakeClient({ '1.2.3.4|github.com': [{ tests: T_UPDATED() }] });
    await V.runVerify(rows, runOpts(client, { onRow: (r) => seen.push([r, r.state]) }));
    assert.ok(seen.every(([r]) => r === rows[0]));
    assert.deepEqual([...new Set(seen.map(([, s]) => s))], ['running', 'done']);
    const r = rows[0];
    assert.equal(r.measurementId, 'fake1');
    assert.equal(r.measurementDone, true);
    assert.equal(r.cost, 1);
    assert.equal(r.tests.length, 1);
    assert.ok(!('publicKey' in r.tests[0].tls));
    assert.ok(r.checkedAt instanceof Date);
    assert.deepEqual(client.calls.create[0].body, {
      type: 'http', target: '1.2.3.4', limit: 1, timeout: 10,
      measurementOptions: { protocol: 'HTTPS', port: 443, request: { method: 'HEAD', host: 'github.com', path: '/' } }
    });
    const { opts } = client.calls.poll[0];
    assert.equal(opts.deadlineMs, 20000);
    assert.equal(opts.deadlineAt, NOW + 20000, 'absolute deadline from the POST');
  });

  test('the works rule fires across rows and reports the changed row', async () => {
    const a = ghRow('1.2.3.4', 'www.example.com');
    const b = ghRow('1.2.3.4', 'github.com');
    const client = fakeClient({ '1.2.3.4|www.example.com': [{ tests: T_SNI() }], '1.2.3.4|github.com': [{ tests: T_UPDATED() }] });
    const updates = [];
    await V.runVerify([a, b], runOpts(client, { concurrency: 1, onRow: (r) => updates.push([r.name, r.status]) }));
    assert.deepEqual([a.status, a.reason], ['NOT_HOSTED', 'refused-name']);
    assert.deepEqual([b.status, b.reason], ['UPDATED', 'new-cert']);
    assert.ok(updates.some(([n, s]) => n === 'www.example.com' && s === 'NOT_HOSTED'), 'onRow for the flipped row');
  });

  test('a quota 429 stops the queue: the rest is not-run: quota', async () => {
    const rows = Array.from({ length: 5 }, (_, i) => ghRow(`1.2.3.${i + 1}`));
    const quota = { limit: 250, remaining: 0, resetAt: new Date(NOW + 1200000), source: '429' };
    const script = Object.fromEntries(rows.map((r) => [`${r.ip}|github.com`, [{ tests: T_UPDATED() }]]));
    script['1.2.3.3|github.com'] = [{ createError: new GlobalpingError('rate-limit', 'hourly limit', { status: 429, quota }) }];
    const client = fakeClient(script);
    const quotas = [];
    const res = await V.runVerify(rows, runOpts(client, { concurrency: 1, onQuota: (q) => quotas.push(q) }));
    assert.deepEqual(rows.map((r) => r.state), ['done', 'done', 'not-run', 'not-run', 'not-run']);
    assert.ok(rows.slice(2).every((r) => r.notRun === 'quota'));
    assert.equal(res.stoppedBy, 'quota');
    assert.equal(client.calls.create.length, 3);
    assert.ok(quotas.some((q) => q && q.remaining === 0));
    assert.equal(res.spent, 2);
  });

  test('budget: maxProbes 2 → exactly 2 creates, the rest not-run: budget', async () => {
    const rows = Array.from({ length: 5 }, (_, i) => ghRow(`1.2.3.${i + 1}`));
    const client = fakeClient(Object.fromEntries(rows.map((r) => [`${r.ip}|github.com`, [{ tests: T_UPDATED() }]])));
    const res = await V.runVerify(rows, runOpts(client, { concurrency: 1, maxProbes: 2 }));
    assert.equal(client.calls.create.length, 2);
    assert.deepEqual(rows.map((r) => r.notRun), [null, null, 'budget', 'budget', 'budget']);
    assert.equal(res.stoppedBy, 'budget');
  });

  test('budget race: 4 workers, slow creates, maxProbes 2 → still exactly 2 creates', async () => {
    const rows = Array.from({ length: 8 }, (_, i) => ghRow(`1.2.3.${i + 1}`));
    const client = fakeClient(Object.fromEntries(rows.map((r) => [`${r.ip}|github.com`, [{ tests: T_UPDATED() }]])), { delayMs: 20 });
    const res = await V.runVerify(rows, runOpts(client, { concurrency: 4, maxProbes: 2 }));
    assert.equal(client.calls.create.length, 2);
    assert.equal(res.spent, 2);
    assert.equal(rows.filter((r) => r.state === 'done').length, 2);
    assert.equal(rows.filter((r) => r.notRun === 'budget').length, 6);
  });

  test('abort after the first result: no more creates, the rest not-run: cancelled', async () => {
    const rows = Array.from({ length: 4 }, (_, i) => ghRow(`1.2.3.${i + 1}`));
    const client = fakeClient(Object.fromEntries(rows.map((r) => [`${r.ip}|github.com`, [{ tests: T_UPDATED() }]])));
    const ctl = new AbortController();
    const res = await V.runVerify(rows, runOpts(client, { concurrency: 1, signal: ctl.signal,
      onRow: (r) => { if (r.state === 'done') ctl.abort(); } }));
    assert.equal(client.calls.create.length, 1);
    assert.deepEqual(rows.map((r) => r.state), ['done', 'not-run', 'not-run', 'not-run']);
    assert.ok(rows.slice(1).every((r) => r.notRun === 'cancelled'));
    assert.equal(res.stoppedBy, 'abort');
  });

  test('a paid measurement interrupted by Stop keeps its id', async () => {
    const r = ghRow('1.2.3.4');
    const aborted = new Error('stop');
    aborted.name = 'AbortError';
    const client = fakeClient({ '1.2.3.4|github.com': [{ polls: [aborted] }] });
    await V.runVerify([r], runOpts(client));
    assert.deepEqual([r.state, r.notRun, r.measurementId, r.measurementDone], ['not-run', 'cancelled', 'fake1', false]);
  });

  test('a free 400 that slipped past the prefilter skips the row at zero cost', async () => {
    const a = ghRow('1.2.3.4');
    const b = ghRow('1.2.3.5');
    const client = fakeClient({
      '1.2.3.4|github.com': [{ createError: new GlobalpingError('private-target', '"target" must not be a private hostname', { status: 400 }) }],
      '1.2.3.5|github.com': [{ createError: new GlobalpingError('bad-host', 'host', { status: 400 }) }]
    });
    const res = await V.runVerify([a, b], runOpts(client));
    assert.deepEqual([a.state, a.skip, a.cost], ['skipped', 'reserved', 0]);
    assert.deepEqual([b.state, b.skip, b.cost], ['skipped', 'bad-name', 0]);
    assert.equal(res.spent, 0);
  });

  test('probe faults are retried with a fresh measurement; at most maxRetries per run', async () => {
    const r = ghRow('1.2.3.4');
    const client = fakeClient({ '1.2.3.4|github.com': [{ tests: T_INTERNAL() }, { tests: T_UPDATED() }] });
    const res = await V.runVerify([r], runOpts(client));
    assert.equal(client.calls.create.length, 2);
    assert.deepEqual([r.state, r.status, r.retries, r.cost], ['done', 'UPDATED', 1, 2]);
    assert.deepEqual([res.retries, res.spent], [1, 2]);

    const r2 = ghRow('1.2.3.5');
    const client2 = fakeClient({ '1.2.3.5|github.com': Array.from({ length: 6 }, () => ({ tests: T_INTERNAL() })) });
    await V.runVerify([r2], runOpts(client2, { maxRetries: 5 }));
    assert.equal(client2.calls.create.length, 6);
    assert.deepEqual([r2.state, r2.error.code, r2.retries], ['error', 'probe', 5]);
  });

  test('empty results and tls without a fingerprint are probe errors', async () => {
    const a = ghRow('1.2.3.4');
    const b = ghRow('1.2.3.5');
    const client = fakeClient({
      '1.2.3.4|github.com': [{ tests: [] }],
      '1.2.3.5|github.com': [{ tests: [withTls(synthTls({ fingerprint256: undefined }))] }]
    });
    await V.runVerify([a, b], runOpts(client, { maxRetries: 0 }));
    assert.deepEqual([a.state, a.error.code, a.verdict], ['error', 'probe', null]);
    assert.deepEqual([b.state, b.error.code], ['error', 'probe']);
  });

  test('TIMEOUT is a verdict, never retried automatically', async () => {
    const r = ghRow('1.2.3.4');
    const client = fakeClient({ '1.2.3.4|github.com': [{ tests: T_TIMEOUT() }] });
    await V.runVerify([r], runOpts(client));
    assert.equal(client.calls.create.length, 1);
    assert.deepEqual([r.state, r.status, r.reason], ['done', 'TIMEOUT', 'connect-timeout']);
  });

  test('deadline keeps the paid id; the next run polls it for free (once, within 120 s)', async () => {
    let t = NOW;
    const clock = () => t;
    const r = ghRow('1.2.3.4');
    const deadline = () => new GlobalpingError('deadline', 'no result in time');
    const client = fakeClient({ '1.2.3.4|github.com': [{ polls: [deadline()] }, { tests: T_UPDATED() }] }, { clock });
    await V.runVerify([r], runOpts(client, { now: clock }));
    assert.deepEqual([r.state, r.error.code, r.measurementId, r.measurementDone], ['error', 'deadline', 'fake1', false]);
    assert.equal(V.verifyCost(V.requeueRows([r]), { now: clock() }).checks, 0, 'the preview counts it free');
    client.pollScript.get('fake1').push({ tests: T_UPDATED() });
    t += 30000;
    await V.runVerify([r], runOpts(client, { now: clock }));
    assert.equal(client.calls.create.length, 1, 'no new POST');
    assert.deepEqual([r.state, r.status, r.cost], ['done', 'UPDATED', 1]);
  });

  test('deadline reuse is bounded: a second deadline, or an id older than 120 s, posts anew', async () => {
    let t = NOW;
    const clock = () => t;
    const deadline = () => new GlobalpingError('deadline', 'no result in time');
    const r = ghRow('1.2.3.4');
    const client = fakeClient({ '1.2.3.4|github.com': [{ polls: [deadline(), deadline()] }, { tests: T_UPDATED() }] }, { clock });
    await V.runVerify([r], runOpts(client, { now: clock }));
    V.requeueRows([r]);
    await V.runVerify([r], runOpts(client, { now: clock })); // reuse #1 → deadline again
    assert.deepEqual([client.calls.create.length, r.error.code, r.reuseAttempts], [1, 'deadline', 1]);
    V.requeueRows([r]);
    await V.runVerify([r], runOpts(client, { now: clock })); // no second reuse
    assert.equal(client.calls.create.length, 2);
    assert.equal(r.status, 'UPDATED');

    const old = ghRow('1.2.3.5');
    const client2 = fakeClient({ '1.2.3.5|github.com': [{ polls: [deadline()] }, { tests: T_UPDATED() }] }, { clock });
    await V.runVerify([old], runOpts(client2, { now: clock }));
    t += 121000;
    V.requeueRows([old]);
    await V.runVerify([old], runOpts(client2, { now: clock }));
    assert.equal(client2.calls.create.length, 2, 'too old to poll again');
    assert.equal(client2.calls.poll.length, 2);
  });

  test('a reused id that is gone (404) falls back to a new measurement', async () => {
    const r = Object.assign(ghRow('1.2.3.4'), { measurementId: 'gone1', measurementDone: false, measurementAt: NOW });
    const client = fakeClient({ '1.2.3.4|github.com': [{ tests: T_UPDATED() }] });
    await V.runVerify([r], runOpts(client));
    assert.deepEqual(client.calls.poll.map((c) => c.id), ['gone1', 'fake1']);
    assert.equal(client.calls.create.length, 1);
    assert.equal(r.status, 'UPDATED');
  });

  test('network failures: TypeError and TimeoutError are "network"; three in a row stop the queue', async () => {
    const rows = Array.from({ length: 5 }, (_, i) => ghRow(`1.2.3.${i + 1}`));
    const script = Object.fromEntries(rows.map((r) => [`${r.ip}|github.com`, [{ createError: new TypeError('Failed to fetch') }]]));
    script['1.2.3.2|github.com'] = [{ createError: new TimeoutError('The operation timed out') }];
    const client = fakeClient(script);
    const res = await V.runVerify(rows, runOpts(client, { concurrency: 1 }));
    assert.deepEqual(rows.map((r) => r.state), ['error', 'error', 'error', 'not-run', 'not-run']);
    assert.ok(rows.slice(0, 3).every((r) => r.error.code === 'network'));
    assert.ok(rows.slice(3).every((r) => r.notRun === 'unreachable'));
    assert.equal(res.stoppedBy, 'unreachable');
  });

  test('GP codes outside VERIFY_ERRORS become "unknown" (raw code kept)', async () => {
    const a = ghRow('1.2.3.4');
    const b = ghRow('1.2.3.5');
    const client = fakeClient({
      '1.2.3.4|github.com': [{ createError: new GlobalpingError('unauthorized', 'Unauthorized.', { status: 401 }) }],
      '1.2.3.5|github.com': [{ createError: new GlobalpingError('no-probes', 'No matching probes', { status: 422 }) }]
    });
    await V.runVerify([a, b], runOpts(client));
    assert.deepEqual(a.error, { code: 'unknown', message: 'Unauthorized.', raw: 'unauthorized' });
    assert.equal(b.error.code, 'no-probes');
  });

  test('probesPerCheck 2: one 2-probe measurement, aggregated', async () => {
    const r = ghRow('140.82.121.4');
    const client = fakeClient({ '140.82.121.4|github.com': [{ tests: testsOf('m01-github-valid') }] });
    const res = await V.runVerify([r], runOpts(client, { probesPerCheck: 2 }));
    assert.equal(client.calls.create[0].body.limit, 2);
    assert.deepEqual([r.status, r.verdict.probes.length, r.verdict.agreement, r.tests.length], ['UPDATED', 2, 'all', 2]);
    assert.equal(res.spent, 2);
  });

  test('locationsFor is passed through (Phase B/C hook)', async () => {
    const r = ghRow('1.2.3.4');
    const client = fakeClient({ '1.2.3.4|github.com': [{ tests: T_UPDATED() }] });
    await V.runVerify([r], runOpts(client, { locationsFor: () => [{ country: 'DE' }] }));
    const body = client.calls.create[0].body;
    assert.deepEqual(body.locations, [{ country: 'DE', limit: 1 }]);
    assert.ok(!('limit' in body));
  });

  test('a body that cannot be built is a validation error on that row and gives its budget back', async () => {
    const rows = Array.from({ length: 4 }, (_, i) => ghRow(`1.2.3.${i + 1}`));
    const client = fakeClient(Object.fromEntries(rows.map((r) => [`${r.ip}|github.com`, [{ tests: T_UPDATED() }]])));
    const bad = new Set([rows[0], rows[1]]);
    const res = await V.runVerify(rows, runOpts(client, { concurrency: 1, maxProbes: 2,
      locationsFor: (r) => (bad.has(r) ? [{ bogus: 1 }] : null) }));
    assert.deepEqual(rows.map((r) => [r.state, r.error?.code ?? null, r.skip]),
      [['error', 'validation', null], ['error', 'validation', null], ['done', null, null], ['done', null, null]],
      'never a "bad-port" skip for a location fault');
    assert.equal(client.calls.create.length, 2, 'the confirmed rows still run');
    assert.deepEqual(res, { spent: 2, retries: 0, stoppedBy: null });
    // a pair that is really unprobeable (port 0, no skip set) is skipped, and its reservation is released too
    const port0 = ghRow('1.2.3.8', 'github.com', { port: 0 });
    const good = ghRow('1.2.3.9');
    const client2 = fakeClient({ '1.2.3.9|github.com': [{ tests: T_UPDATED() }] });
    const res2 = await V.runVerify([port0, good], runOpts(client2, { concurrency: 1, maxProbes: 1 }));
    assert.deepEqual([port0.state, port0.skip, good.state, res2.spent, res2.stoppedBy], ['skipped', 'bad-port', 'done', 1, null]);
  });

  test('the works rule refreshes the exposure of the sibling it changes (view and exports never stale)', async () => {
    const shop = ghRow('1.2.3.4', 'shop.example.com', { via: 'hint', proxied: true, provider: 'Cloudflare' });
    const gh = ghRow('1.2.3.4', 'github.com');
    const client = fakeClient({
      '1.2.3.4|shop.example.com': [{ tests: [failed('read ECONNRESET')] }],
      '1.2.3.4|github.com': [{ tests: T_UPDATED() }, { tests: T_TIMEOUT() }]
    });
    const seen = [];
    const onRow = (r) => { if (r === shop) seen.push([r.status, r.exposure]); };
    await V.runVerify([shop, gh], runOpts(client, { concurrency: 1, onRow }));
    assert.deepEqual([shop.status, shop.reason, shop.exposure], ['NOT_HOSTED', 'refused-name', 'not-this-host']);
    assert.deepEqual(seen.at(-1), ['NOT_HOSTED', 'not-this-host'], 'reported with the fresh exposure');
    assert.equal(V.verifyExportRows([shop], { now: NOW })[0].exposure, 'not-this-host');
    assert.equal(V.verifyExportJson([shop], { now: new Date(NOW) }).rows[0].exposure, 'not-this-host');
    // a re-check where the working name stops answering reverts both
    V.requeueRows([gh]);
    await V.runVerify([shop, gh], runOpts(client, { concurrency: 1 }));
    assert.deepEqual([shop.status, shop.reason, shop.exposure], ['TLS_ERROR', 'reset', 'unknown']);
  });

  test('a re-check that ends without a verdict keeps the last one (stale): the roll-up stays "old"', async () => {
    const wild = ghRow('1.2.3.4', 'github.com', { server: { id: 'web01', name: 'web01' } });
    const www = ghRow('1.2.3.4', 'www.github.com', { server: { id: 'web01', name: 'web01' } });
    const other = { ...OTHER, spkiHex: [] };
    const client = fakeClient({
      '1.2.3.4|github.com': [{ tests: T_UPDATED() }],
      '1.2.3.4|www.github.com': [{ tests: T_UPDATED() }, { createError: new GlobalpingError('rate-limit', 'quota', { status: 429 }) }]
    });
    // www serves another certificate: classify it against OTHER by giving it its own expectation run
    await V.runVerify([wild], runOpts(client));
    await V.runVerify([www], runOpts(client, { expect: other }));
    assert.equal(www.status, 'NEEDS_UPDATE');
    const rows = [wild, www];
    assert.equal(V.verifyHeadline(V.summarizeVerify(rows))[0].key, 'vfy.head.none');
    V.requeueRows([www]);
    const res = await V.runVerify(rows, runOpts(client, { expect: other }));
    assert.equal(res.stoppedBy, 'quota');
    assert.deepEqual([www.state, www.notRun, www.stale, www.status], ['not-run', 'quota', true, 'NEEDS_UPDATE']);
    const sum = V.summarizeVerify(rows);
    assert.deepEqual([sum.servers.old, sum.servers.live], [1, 0]);
    assert.notEqual(V.verifyHeadline(sum)[0].key, 'vfy.head.all');
  });
});

/* ---- a zone hand-off, end to end --------------------------------------------------- */

describe('a zone-file origin behind the CDN', () => {
  /** Live DNS: www is proxied (a Cloudflare edge) and the apex is direct; answered for every DoH resolver. */
  const LIVE = { 'example.com': { A: ['5.6.7.8'] }, 'www.example.com': { A: ['104.16.1.2'] } };
  const SOA = { mname: 'a.invalid', rname: 'b.invalid', serial: 1, refresh: 1, retry: 1, expire: 1, minimum: 60 };
  const fetchImpl = async (url) => {
    const resolver = RESOLVERS.find((x) => url.startsWith(`${x.url}?`));
    if (!resolver) throw new TypeError(`unexpected URL ${url}`);
    const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
    const node = LIVE[q.name];
    const answers = (node?.[q.type] || []).map((data) => ({ name: q.name, type: q.type, ttl: 300, data }));
    return new Response(encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: node ? 'NOERROR' : 'NXDOMAIN', questions: [{ name: q.name, type: q.type }],
      answers, authorities: answers.length ? [] : [{ name: 'example.com', type: 'SOA', ttl: 300, data: SOA }], edns: {}
    }));
  };
  // A Cloudflare export: www's origin is known only from the zone file.
  const ZONE = [
    'example.com.\t3600\tIN\tSOA\tada.ns.cloudflare.com. dns.cloudflare.com. 2051234567 10000 2400 604800 3600',
    'example.com.\t1\tIN\tA\t5.6.7.8 ; cf_tags=cf-proxied:false',
    'www.example.com.\t1\tIN\tA\t1.2.3.4 ; cf_tags=cf-proxied:true',
    ''
  ].join('\n');

  test('its pair (origin IP + proxied name) is never sent while the origin opt-in is off', async () => {
    const result = await runScan({
      domains: [], zone: zoneScanInput(parseZone(ZONE, { filename: 'example.com.txt' })), exact: true, originHints: false,
      cert: { hostnames: ['example.com', '*.example.com'], serialHex: 'aa' },
      inventory: parseInventory('web01 1.2.3.4\napex01 5.6.7.8'),
      dns: new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 }), fetchImpl, balance: false, sourceGraceMs: 0
    });
    const { pairs, stats } = V.buildVerifyPairs(result);
    const www = pairs.find((p) => p.name === 'www.example.com');
    assert.deepEqual([www.ip, www.via, www.proxied, www.skip], ['1.2.3.4', 'zone', true, null]);
    assert.equal(stats.originPairs, 1);
    const rows = V.createVerifyRows(pairs);
    const zoneRow = rows.find((r) => r.name === 'www.example.com');
    assert.deepEqual([zoneRow.state, zoneRow.notRun], ['not-run', 'optional']);
    assert.deepEqual(V.verifyCost(rows, { now: NOW }), { checks: 1, reuse: 0, probes: 1, servers: 1, origins: 0, optional: 1 });
    const client = fakeClient({ '5.6.7.8|example.com': [{ tests: T_UPDATED() }], '1.2.3.4|www.example.com': [{ tests: T_UPDATED() }] });
    await V.runVerify(rows, runOpts(client));
    assert.deepEqual(client.calls.create.map((c) => c.key), ['5.6.7.8|example.com'], 'the apex only');
    // Opted in, the origin check runs.
    V.applyOriginOptIn(rows, true);
    assert.equal(V.verifyCost(rows, { now: NOW }).origins, 1);
    await V.runVerify(rows, runOpts(client));
    assert.deepEqual(client.calls.create.map((c) => c.key), ['5.6.7.8|example.com', '1.2.3.4|www.example.com']);
  });
});

/* ---- summary / headline ------------------------------------------------------------ */

/** The E2E scenario, as rows: web01 {wild ✓, www old, shop hint ✓+chain, exposed}, db01 {vpn private}, api ✓, legacy timeout. */
const NEW_AB = { ...OTHER, sha256: [V.hexKey('AB:'.repeat(31) + 'AB')] };
function e2eRows({ flipped = false } = {}) {
  const s = (id) => ({ server: { id, name: id } });
  const served = (name, over = {}) => withTls(synthTls({ subject: { CN: name, alt: `DNS:${name}` }, ...over }));
  const chainTls = { authorized: false, error: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' };
  const rows = [
    check(row({ name: 'wild.example.net', ...s('web01') }), [served('wild.example.net')], NEW_AB),
    check(row({ name: 'www.wild.example.net', ...s('web01') }), [served('www.wild.example.net')], flipped ? NEW_AB : OTHER),
    check(row({ name: 'shop.wild.example.net', via: 'hint', proxied: true, provider: 'Cloudflare', ...s('web01') }),
      [served('shop.wild.example.net', flipped ? {} : chainTls)], NEW_AB),
    V.createVerifyRows([pair({ ip: '10.0.0.5', name: 'vpn.wild.example.net', skip: 'private', ...s('db01') })])[0],
    V.createVerifyRows([pair({ ip: '10.0.0.5', name: 'shop.wild.example.net', via: 'hint', skip: 'private', ...s('db01') })])[0],
    check(row({ ip: '5.6.7.8', name: 'api.wild.example.net', server: null }), [served('api.wild.example.net')], NEW_AB),
    check(row({ ip: '1.2.3.5', name: 'legacy.wild.example.net', server: null }), T_TIMEOUT(), NEW_AB)
  ];
  return settle(rows);
}
const keys = (h) => h.map((x) => x.key.replace('vfy.head.', ''));

describe('summarizeVerify / verifyHeadline', () => {
  test('the E2E scenario: some, chain (on a non-live server), unreachable, exposed, notHere', () => {
    const rows = e2eRows();
    const sum = V.summarizeVerify(rows);
    assert.deepEqual(
      (({ total, checked, live, old, other, tlsError, unreachable, filteredOrigins, unchecked, incomplete, chain, base }) =>
        ({ total, checked, live, old, other, tlsError, unreachable, filteredOrigins, unchecked, incomplete, chain, base }))(sum.servers),
      { total: 3, checked: 3, live: 1, old: 1, other: 0, tlsError: 0, unreachable: 1, filteredOrigins: 0, unchecked: 0, incomplete: 0, chain: 1, base: 3 });
    assert.deepEqual(sum.servers.list.map((s) => [s.key, s.status]), [['web01', 'NEEDS_UPDATE'], ['5.6.7.8', 'UPDATED'], ['1.2.3.5', 'TIMEOUT']]);
    assert.equal(sum.exposed, 1);
    assert.deepEqual(sum.rows.skippedBy, { private: 2 });
    assert.deepEqual(sum.rows.skippedUnits, { private: 1 }, 'one private ADDRESS behind two pairs');
    const h = V.verifyHeadline(sum, { skipped: { 'over-cap': 0 }, proxiedNoOrigin: 0, managed: 0 });
    assert.deepEqual(keys(h), ['some', 'chain', 'unreachable', 'exposed', 'notHere']);
    assert.deepEqual(h[0], { key: 'vfy.head.some', variant: 'warn', params: { live: 1, total: 3, old: 1 } });
    assert.deepEqual(h.at(-1).parts, [{ key: 'vfy.notHere.private', params: { count: 1 } }]);
    for (const x of h.slice(1, -1)) assert.equal(typeof x.params.count, 'number', `${x.key} carries params.count`);
  });

  test('after the flip: partial (2 of 3), no chain', () => {
    const h = V.verifyHeadline(V.summarizeVerify(e2eRows({ flipped: true })));
    assert.deepEqual(keys(h), ['partial', 'unreachable', 'exposed', 'notHere']);
    assert.deepEqual(h[0].params, { live: 2, total: 3 });
  });

  test('all / none / noAnswer / tlsError / other', () => {
    const one = (verdicts, o = {}) => done(row({ name: 'github.com', ...o }), verdicts);
    const all = settle([one([V_UPDATED()]), one([V_UPDATED()], { ip: '5.6.7.8', server: null })]);
    assert.deepEqual(V.verifyHeadline(V.summarizeVerify(all)), [{ key: 'vfy.head.all', variant: 'ok', params: { count: 2 } }]);
    const none = settle([one([V_OLD()]), one([V_OLD()], { ip: '5.6.7.8', server: null })]);
    assert.deepEqual(V.verifyHeadline(V.summarizeVerify(none))[0], { key: 'vfy.head.none', variant: 'warn', params: { count: 2 } });
    const quiet = settle([one([V_TIMEOUT()]), one([V_SNI()], { ip: '5.6.7.8', server: null })]);
    assert.deepEqual(keys(V.verifyHeadline(V.summarizeVerify(quiet))), ['noAnswer', 'tlsError', 'unreachable']);
    // a DNS-matched name served a certificate that does not cover it: not "no answer", and a warning
    const wrong = settle([...quiet, one([V_NOT_COVERED()], { ip: '5.6.7.9', server: null, name: 'api.github.com' })]);
    const hw = V.verifyHeadline(V.summarizeVerify(wrong));
    assert.deepEqual(keys(hw), ['none', 'tlsError', 'unreachable', 'other']);
    assert.deepEqual([hw[0].variant, hw[0].params, hw.at(-1).variant], ['warn', { count: 3 }, 'warn']);
    assert.deepEqual(V.verifyHeadline(V.summarizeVerify([])), []);
  });

  test('noAnswer only when no server returned a certificate', () => {
    // the finding's case: one DNS row, its server serves a certificate for another name
    const wrong = settle([done(row({ ip: '5.6.7.8', server: null, name: 'api.github.com' }), [V_NOT_COVERED()])]);
    const sum = V.summarizeVerify(wrong);
    assert.deepEqual([sum.servers.live, sum.servers.old, sum.servers.other, sum.servers.wrongCert, sum.servers.served], [0, 0, 1, 1, 1]);
    assert.deepEqual(V.verifyHeadline(sum), [
      { key: 'vfy.head.none', variant: 'warn', params: { count: 1 } },
      { key: 'vfy.head.other', variant: 'warn', params: { count: 1 } }
    ]);
    // a Cloudflare Origin CA certificate on a zone row (behind the CDN): hosted on purpose, yet a certificate came back
    const oca = V.classifyTest(withTls(synthTls({ subject: { CN: 'github.com', alt: 'DNS:github.com' }, authorized: false,
      error: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', issuer: { O: 'CloudFlare, Inc.', CN: 'CloudFlare Origin SSL Certificate Authority' } })),
    { name: 'github.com', expect: OTHER, now: NOW });
    const zone = V.summarizeVerify(settle([done(row({ name: 'github.com', via: 'zone', proxied: true }), [oca])]));
    assert.deepEqual([zone.servers.old, zone.servers.other, zone.servers.originCert, zone.servers.originDirect,
      zone.servers.wrongCert, zone.servers.served], [0, 0, 1, 0, 0, 1]);
    assert.deepEqual(V.verifyHeadline(zone).map((x) => [x.key, x.variant]),
      [['vfy.head.partial', 'info'], ['vfy.head.originCert', 'info'], ['vfy.head.exposed', 'warn']]);
    // an origin-hint candidate that serves another certificate is not a DNS-matched name: no warning
    const hint = settle([done(row({ name: 'github.com' }), [V_UPDATED()]),
      done(row({ ip: '5.6.7.9', name: 'api.github.com', via: 'hint', proxied: false, server: { id: 'mail01', name: 'mail01' } }), [V_NOT_COVERED()])]);
    const hs = V.summarizeVerify(hint);
    assert.equal(hs.servers.wrongCert, 0);
    assert.deepEqual(V.verifyHeadline(hs).map((x) => [x.key, x.variant]), [['vfy.head.partial', 'info'], ['vfy.head.other', 'info']]);
  });

  test('a partial run is incomplete, never "all"', () => {
    const rows = [
      done(row({ name: 'github.com' }), [V_UPDATED()]),
      done(row({ ip: '5.6.7.8', name: 'github.com', server: null }), [V_UPDATED()]),
      Object.assign(row({ ip: '5.6.7.9', server: null }), { state: 'not-run', notRun: 'budget' })
    ];
    const sum = V.summarizeVerify(settle(rows));
    assert.deepEqual([sum.servers.live, sum.servers.incomplete, sum.servers.unchecked, sum.servers.base], [2, 1, 1, 3]);
    const h = V.verifyHeadline(sum);
    assert.deepEqual(keys(h), ['partial', 'incomplete']);
    assert.deepEqual(h[0].params, { live: 2, total: 3 });
    assert.deepEqual(h[1], { key: 'vfy.head.incomplete', variant: 'info', params: { count: 1 } });
    // a server with one live row and one never-checked row is not live either (but not "no answer")
    const mixed = settle([done(row({ name: 'github.com' }), [V_UPDATED()]), Object.assign(row({ name: 'www.github.com' }), { state: 'error', error: { code: 'deadline' } })]);
    const s2 = V.summarizeVerify(mixed);
    assert.deepEqual([s2.servers.checked, s2.servers.live, s2.servers.updated, s2.servers.incomplete], [1, 0, 1, 1]);
    assert.deepEqual(V.verifyHeadline(s2).map((x) => [x.key, x.params]),
      [['vfy.head.partial', { live: 0, total: 1 }], ['vfy.head.incomplete', { count: 1 }]]);
  });

  test('a filtered origin row does not take an incomplete server out of the base: never "all"', () => {
    const web01 = { server: { id: 'web01', name: 'web01' } };
    const origin = () => done(row({ name: 'shop.example.com', via: 'hint', proxied: true, ...web01 }), [V_TIMEOUT()]);
    const live02 = () => done(row({ ip: '5.6.7.8', name: 'github.com', server: { id: 'web02', name: 'web02' } }), [V_UPDATED()]);
    const unfinished = [
      Object.assign(row({ name: 'www.example.com', ...web01 }), { state: 'error', error: { code: 'deadline', message: '', raw: null } }),
      Object.assign(row({ name: 'www.example.com', ...web01 }), { state: 'not-run', notRun: 'quota' })
    ];
    for (const www of unfinished) {
      const sum = V.summarizeVerify(settle([www, origin(), live02()]));
      const s = sum.servers;
      assert.deepEqual([s.total, s.live, s.filteredOrigins, s.incomplete, s.unreachable, s.base], [2, 1, 0, 1, 0, 2], www.state);
      const h = V.verifyHeadline(sum);
      assert.deepEqual(keys(h), ['partial', 'incomplete'], www.state);
      assert.deepEqual(h[0].params, { live: 1, total: 2 });
    }
    // belt and braces: a summary that says "incomplete" never yields "all"
    assert.equal(V.verifyHeadline({ servers: { checked: 1, base: 1, live: 1, updated: 1, old: 0, incomplete: 1 } })[0].key, 'vfy.head.partial');
  });

  test('origin candidates answering "not this name" are expected: out of the base, never other / tlsError', () => {
    const mail = { server: { id: 'mail01', name: 'mail01' } };
    const hint = (name, verdicts, ip = '5.6.7.20') => done(row({ ip, name, via: 'hint', proxied: true, ...mail }), verdicts);
    const web = () => done(row({ name: 'github.com' }), [V_UPDATED()]);
    // the MX candidate serves its own certificate
    const own = V.summarizeVerify(settle([web(), ...['shop', 'blog', 'docs', 'app'].map((l) =>
      hint(`${l}.example.com`, [cls('m01-github-valid', `${l}.example.com`, NEW_GH)]))]));
    assert.deepEqual([own.servers.notHostingOrigins, own.servers.other, own.servers.base, own.servers.live], [1, 0, 1, 1]);
    assert.deepEqual(V.verifyHeadline(own), [{ key: 'vfy.head.all', variant: 'ok', params: { count: 1 } }]);
    assert.equal(own.servers.list.find((x) => x.key === 'mail01').notHostingOrigin, true);
    // the candidate refuses the SNI (alert 40) and nothing on it serves a certificate: no works rule
    const sni = V.summarizeVerify(settle([web(), hint('shop.example.com', [V_SNI()]), hint('blog.example.com', [V_SNI()])]));
    assert.deepEqual([sni.servers.tlsError, sni.servers.notHostingOrigins, sni.servers.base], [0, 1, 1]);
    assert.deepEqual(keys(V.verifyHeadline(sni)), ['all']);
    // CLI parity: a DNS-matched server refusing its names stays TLS_ERROR
    const dns = V.summarizeVerify(settle([web(), done(row({ ip: '5.6.7.21', name: 'api.example.com', server: null }), [V_SNI()])]));
    assert.deepEqual([dns.servers.tlsError, dns.servers.base], [1, 2]);
    // a server with other answering rows rolls up without its expected origin rows
    const web01 = { server: { id: 'web01', name: 'web01' } };
    const mixed = V.summarizeVerify(settle([done(row({ name: 'github.com', ...web01 }), [V_TIMEOUT()]),
      done(row({ ip: '5.6.7.22', name: 'shop.example.com', via: 'hint', proxied: true, ...web01 }), [V_SNI()])]));
    assert.deepEqual([mixed.servers.list[0].status, mixed.servers.tlsError, mixed.servers.unreachable], ['TIMEOUT', 0, 1]);
    // the JSON export carries the new count
    assert.equal(V.verifyExportJson([], { summary: own, now: new Date(NOW) }).summary.servers.notHostingOrigins, 1);
  });

  test('filtered origins: out of the base and of "unreachable"; single-probe silence is info, two ASNs ok', () => {
    const origin = (verdicts) => done(row({ ip: '5.6.7.10', name: 'github.com', via: 'hint', proxied: true, server: { id: 'origin1', name: 'origin1' } }), verdicts);
    const rows = settle([done(row({ name: 'github.com' }), [V_UPDATED()]), origin([V_TIMEOUT()])]);
    const sum = V.summarizeVerify(rows);
    assert.deepEqual([sum.servers.filteredOrigins, sum.servers.unreachable, sum.servers.base, sum.servers.live], [1, 0, 1, 1]);
    const h = V.verifyHeadline(sum);
    assert.deepEqual(keys(h), ['all', 'filtered']);
    assert.equal(h[1].variant, 'info');
    const two = V.summarizeVerify(settle([origin([V_TIMEOUT(), V_TIMEOUT_BR()])]));
    assert.deepEqual(V.verifyHeadline(two), [{ key: 'vfy.head.filtered', variant: 'ok', params: { count: 1 } }],
      'only filtered origins checked: no first entry (base 0)');
  });

  test('shared VIP: the verdict counts for every inventory server listing the IP', () => {
    const r = done(row({ name: 'github.com', alsoServers: [{ id: 'web01b', name: 'web01b' }] }), [V_UPDATED()]);
    const sum = V.summarizeVerify(settle([r]));
    assert.deepEqual(sum.servers.list.map((s) => [s.key, s.status]), [['web01', 'UPDATED'], ['web01b', 'UPDATED']]);
    assert.equal(sum.servers.live, 2);
  });

  test('ORIGIN_CERT / PRIVATE_CERT servers are neither old nor live; warn when visitors reach them directly', () => {
    const tls = (over) => withTls(synthTls({ subject: { CN: 'github.com', alt: 'DNS:github.com' }, authorized: false, ...over }));
    const oca = V.classifyTest(tls({ error: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', issuer: { C: 'US', O: 'CloudFlare, Inc.' } }),
      { name: 'github.com', expect: OTHER, now: NOW });
    const self = V.classifyTest(tls({ error: 'DEPTH_ZERO_SELF_SIGNED_CERT', issuer: { CN: 'github.com' } }),
      { name: 'github.com', expect: OTHER, now: NOW });
    const origin = done(row({ name: 'github.com', via: 'hint', proxied: true }), [oca]);
    const sum = V.summarizeVerify(settle([origin]));
    assert.equal(origin.status, 'ORIGIN_CERT', 'the row keeps CLI parity');
    assert.equal(origin.exposure, 'exposed', 'an origin that answers the internet is exposed, whatever its certificate');
    assert.deepEqual([sum.servers.old, sum.servers.other, sum.servers.originCert, sum.servers.live], [0, 0, 1, 0]);
    // a DNS row is reached directly (no CDN in front): an error for visitors, so the entry warns
    const mixed = settle([
      done(row({ name: 'github.com', ip: '192.0.2.10', server: { id: 'web01', name: 'web01' } }), [oca]),
      done(row({ name: 'github.com', ip: '192.0.2.11', server: { id: 'web02', name: 'web02' } }), [self]),
      done(row({ name: 'github.com', ip: '192.0.2.12', server: { id: 'web03', name: 'web03' } }), [V_UPDATED()]),
      done(row({ name: 'github.com', ip: '192.0.2.13', server: { id: 'web04', name: 'web04' } }), [V_OLD()])
    ]);
    const ms = V.summarizeVerify(mixed);
    assert.deepEqual([ms.servers.base, ms.servers.live, ms.servers.old, ms.servers.originCert, ms.servers.originDirect,
      ms.servers.privateCert, ms.servers.privateDirect], [4, 1, 1, 1, 1, 1, 1]);
    assert.deepEqual(V.verifyHeadline(ms).map((x) => [x.key, x.variant, x.params]), [
      ['vfy.head.some', 'warn', { live: 1, total: 4, old: 1 }],
      ['vfy.head.originCert', 'warn', { count: 1 }],
      ['vfy.head.privateCert', 'warn', { count: 1 }]
    ]);
    assert.deepEqual(ms.rows.byStatus, { ORIGIN_CERT: 1, PRIVATE_CERT: 1, UPDATED: 1, NEEDS_UPDATE: 1 });
    // Check again re-checks them: the certificate there may be replaced on purpose.
    assert.equal(V.recheckRows(mixed).length, 3);
  });

  test('a via:"zone" row is judged like a DNS row', () => {
    const r = done(row({ name: 'github.com', via: 'zone' }), [V_UPDATED()]);
    const sum = V.summarizeVerify(settle([r]));
    assert.equal(sum.servers.live, 1);
    assert.equal(r.exposure, null);
    // …but it is an origin pair: in the per-IP scope it never shadows the DNS pair on its IP.
    assert.deepEqual(V.scopePairs([pair({ via: 'zone' }), pair({ via: 'dns', name: 'b.example.com' })], 'perIp').map((p) => p.via),
      ['zone', 'dns']);
  });

  test('origin pairs left out by the opt-in do not make a server incomplete', () => {
    const rows = settle([done(row({ name: 'github.com' }), [V_UPDATED()]),
      V.createVerifyRows([pair({ name: 'shop.example.com', via: 'hint', proxied: true })])[0]]);
    const sum = V.summarizeVerify(rows);
    assert.deepEqual([sum.servers.live, sum.servers.incomplete], [1, 0]);
    assert.deepEqual(sum.rows.notRunBy, { optional: 1 });
  });

  test('notHereParts: addresses, names, checks, proxied and managed', () => {
    const rows = [
      ...V.createVerifyRows([
        pair({ ip: '10.0.0.5', skip: 'private' }), pair({ ip: '10.0.0.5', name: 'b.example.com', skip: 'private' }),
        pair({ ip: '198.51.100.7', skip: 'reserved' }), pair({ ip: '104.16.5.5', skip: 'cdn-edge' }),
        pair({ ip: '5.6.7.8', name: 'x_y.example.com', skip: 'bad-name' }), pair({ ip: '5.6.7.9', name: 'x_y.example.com', skip: 'bad-name' })
      ]),
      // checks past the cap are counted from the rows of the current scope, never from the pair stats
      ...V.createVerifyRows(['a', 'b', 'c', 'd'].map((l) => pair({ name: `${l}.example.com` })), { maxRows: 0 })
    ];
    const parts = V.notHereParts(V.summarizeVerify(rows), { skipped: { 'over-cap': 9 }, proxiedNoOrigin: 2, managed: 3 });
    assert.deepEqual(parts.map((p) => [p.key.replace('vfy.notHere.', ''), p.params.count]),
      [['private', 1], ['reserved', 1], ['cdn-edge', 1], ['bad-name', 1], ['over-cap', 4], ['proxied', 2], ['managed', 3]]);
    for (const p of parts) assert.ok(V.NOT_HERE_KEYS.includes(p.key.replace('vfy.notHere.', '')));
  });
});

/* ---- CLI plan and exports ---------------------------------------------------------- */

describe('cliPlan', () => {
  test('private / reserved / bad-name / over-cap skips plus TIMEOUT and CLOSED rows; not cdn-edge or UPDATED', () => {
    const rows = settle([
      ...V.createVerifyRows([
        pair({ ip: '10.0.0.5', name: 'vpn.example.com', skip: 'private' }),
        pair({ ip: '198.51.100.7', name: 'doc.example.com', skip: 'reserved' }),
        pair({ ip: '5.6.7.8', name: 'x_y.example.com', skip: 'bad-name' }),
        pair({ ip: '104.16.5.5', name: 'edge.example.com', skip: 'cdn-edge' })
      ]),
      ...V.createVerifyRows([pair({ ip: '1.2.3.7', name: 'many.example.com' })], { maxRows: 0 }),
      done(row({ ip: '1.2.3.5', name: 'legacy.example.com' }), [V_TIMEOUT()]),
      done(row({ ip: '1.2.3.6', name: 'closed.example.com' }), [V_CLOSED()]),
      done(row({ ip: '5.6.7.10', name: 'shop.example.com', via: 'hint', proxied: true }), [V_TIMEOUT()]),
      done(row({ ip: '1.2.3.4', name: 'github.com' }), [V_UPDATED()])
    ]);
    assert.deepEqual(V.cliPlan(rows), {
      targets: ['10.0.0.5', '198.51.100.7', '5.6.7.8', '1.2.3.7', '1.2.3.5', '1.2.3.6', '5.6.7.10'],
      names: ['vpn.example.com', 'doc.example.com', 'x_y.example.com', 'many.example.com', 'legacy.example.com', 'closed.example.com',
        'shop.example.com'],
      rows: 7
    });
  });

  test('a pair on another port than 443 is the target ip:port, so the CLI scans that port', () => {
    const rows = V.createVerifyRows([
      pair({ ip: '10.0.0.5', port: 8443, name: 'vpn.example.com', skip: 'private' }),
      pair({ ip: 'fd00::5', port: 8443, name: 'vpn6.example.com', skip: 'private' }),
      pair({ ip: '10.0.0.6', port: 443, name: 'www.example.com', skip: 'private' })
    ]);
    assert.deepEqual(V.cliPlan(rows).targets, ['10.0.0.5:8443', '[fd00::5]:8443', '10.0.0.6']);
  });

  test('an inventory address written with its own port is planned on that port, as the CLI reads the inventory', () => {
    // The scan's ServerGroup carries the inventory Server itself, `ports` included (lib/inventory.parseInventory).
    const inv = parseInventory('web03 10.0.0.13:8443\nweb04 10.0.0.14 10.0.0.14:9443\nweb05 10.0.0.15\n'
      + 'web06 10.0.0.16:8443\nweb07 10.0.0.16\nweb08 [fd00::8]:8443');
    const byId = Object.fromEntries(inv.servers.map((s) => [s.id, s]));
    const result = {
      hosts: ['a', 'b', 'c', 'd', 'e'].map((n) => host(`${n}.example.com`, { ips: [], kind: 'private' })),
      servers: [
        { server: byId.web03, hosts: [e('a.example.com', '10.0.0.13')], needsCert: true, maybeNeedsCert: false },
        { server: byId.web04, hosts: [e('b.example.com', '10.0.0.14')], needsCert: true, maybeNeedsCert: false },
        { server: byId.web05, hosts: [e('c.example.com', '10.0.0.15')], needsCert: true, maybeNeedsCert: false },
        // a shared address: web06 wrote it with a port, web07 without one (the CLI's -p)
        { server: byId.web06, hosts: [e('d.example.com', '10.0.0.16')], needsCert: true, maybeNeedsCert: false },
        { server: byId.web07, hosts: [e('d.example.com', '10.0.0.16')], needsCert: true, maybeNeedsCert: false },
        { server: byId.web08, hosts: [e('e.example.com', 'fd00::8')], needsCert: true, maybeNeedsCert: false }
      ],
      unmatchedIps: []
    };
    const { pairs } = V.buildVerifyPairs(result);
    assert.deepEqual(pairs.map((p) => [p.ip, p.port, p.skip, p.cliTargets]), [
      ['10.0.0.13', 443, 'private', ['10.0.0.13:8443']],
      ['10.0.0.14', 443, 'private', ['10.0.0.14', '10.0.0.14:9443']],
      ['10.0.0.15', 443, 'private', null],
      ['10.0.0.16', 443, 'private', ['10.0.0.16:8443', '10.0.0.16']],
      ['fd00::8', 443, 'private', ['[fd00::8]:8443']]
    ]);
    const rows = V.createVerifyRows(pairs);
    assert.deepEqual(V.cliPlan(rows).targets,
      ['10.0.0.13:8443', '10.0.0.14', '10.0.0.14:9443', '10.0.0.15', '10.0.0.16:8443', '10.0.0.16', '[fd00::8]:8443']);
    // The CLI card's command keeps them (cmdline allowPorts), so the CLI dials 8443, not -p's 443.
    const sweep = buildSweepCommand({ targets: V.cliPlan(rows).targets, names: ['a.example.com'], allowPorts: true });
    assert.match(sweep.command, /^ssl_origin_scan\.py -t 10\.0\.0\.13:8443 10\.0\.0\.14 10\.0\.0\.14:9443 /);
  });

  test('the SSH port of an Ansible host never reaches the CLI card: the address is planned on -p', () => {
    const inv = parseInventory('[web]\n10.0.0.11:2222\nweb02.example.com:2222 ansible_host=10.0.0.12\n');
    const result = {
      hosts: ['a', 'b'].map((n) => host(`${n}.example.com`, { ips: [], kind: 'private' })),
      servers: [
        { server: inv.servers[0], hosts: [e('b.example.com', '10.0.0.12')], needsCert: true, maybeNeedsCert: false },
        { server: inv.servers[1], hosts: [e('a.example.com', '10.0.0.11')], needsCert: true, maybeNeedsCert: false }
      ],
      unmatchedIps: []
    };
    assert.deepEqual(inv.servers.map((s) => [s.id, s.ports]), [['web02.example.com', undefined], ['10.0.0.11', undefined]]);
    const { pairs } = V.buildVerifyPairs(result);
    assert.deepEqual(pairs.map((p) => [p.ip, p.port, p.cliTargets]), [['10.0.0.12', 443, null], ['10.0.0.11', 443, null]]);
    assert.deepEqual(V.cliPlan(V.createVerifyRows(pairs)).targets, ['10.0.0.12', '10.0.0.11']);
  });
});

describe('exports', () => {
  const src = read('cli/ssl_origin_scan.py');
  const cliColumns = () => {
    const m = src.match(/^CSV_COLUMNS = \(([\s\S]*?)\)/m);
    assert.ok(m, 'CSV_COLUMNS tuple found in the CLI');
    return [...m[1].matchAll(/'([a-z0-9_]+)'/g)].map((x) => x[1]);
  };
  const rowDictKeys = () => {
    const m = src.match(/def _row_dict\([^)]*\)[^\n]*\n([\s\S]*?)\n\s*\}\n/);
    assert.ok(m, '_row_dict found in the CLI');
    return [...m[1].matchAll(/'([a-zA-Z0-9]+)':/g)].map((x) => x[1]);
  };

  test('the first 17 CSV columns are the CLI CSV_COLUMNS, in CLI order (parsed from the CLI source)', () => {
    const cli = cliColumns();
    assert.equal(cli.length, 17);
    assert.deepEqual(V.VERIFY_CSV_COLUMNS.slice(0, 17).map((c) => c.header), cli);
    const csv = toCsv(V.verifyExportRows(e2eRows(), { now: NOW }), V.VERIFY_CSV_COLUMNS);
    assert.ok(csv.startsWith('﻿'));
    const header = csv.replace(/^﻿/, '').split('\r\n')[0];
    assert.ok(header.startsWith(`${cli.join(',')},source,state,`), header);
    assert.equal(csv.trim().split('\r\n').length, 1 + 7);
  });

  test('row values: CLI vocabulary only in status; yes/no covers; byte-aligned serial; days left', () => {
    const rows = e2eRows();
    const out = V.verifyExportRows(rows, { now: NOW });
    const vpn = out.find((r) => r.name === 'vpn.wild.example.net');
    assert.deepEqual([vpn.status, vpn.state, vpn.skip, vpn.error, vpn.source], ['', 'skipped', 'private', 'private', 'globalping']);
    const wild = out.find((r) => r.name === 'wild.example.net');
    assert.deepEqual([wild.status, wild.new_cert_covers, wild.probe, wild.sni, wild.server, wild.port], ['UPDATED', 'yes', 'sni', 'wild.example.net', 'web01', 443]);
    assert.equal(wild.cert_serial, '07', 'serial 07 stays 07');
    assert.equal(wild.cert_issuer, 'Example Issuing CA (Example CA)');
    assert.equal(wild.cert_not_after, '2026-11-29T23:59:59.000Z');
    assert.equal(wild.cert_days_left, 66);
    assert.equal(wild.vantage, 'DE Falkenstein AS24940');
    const legacy = out.find((r) => r.name === 'legacy.wild.example.net');
    assert.deepEqual([legacy.status, legacy.reason, legacy.cert_sha256], ['TIMEOUT', 'connect-timeout', '']);
    assert.ok(legacy.error.startsWith('Request timed out'));
    const shop = out.find((r) => r.name === 'shop.wild.example.net' && r.ip === '1.2.3.4');
    assert.deepEqual([shop.warnings, shop.exposure, shop.via], ['chain-incomplete', 'exposed', 'hint']);
  });

  test('a hostile certificate CN is neutralised in the CSV', () => {
    const tls = synthTls({ subject: { CN: '=HYPERLINK("x")', alt: 'DNS:www.example.com' } });
    const r = settle([done(row(), [V.classifyTest(withTls(tls), { name: 'www.example.com', expect: OTHER, now: NOW })])]);
    const csv = toCsv(V.verifyExportRows(r, { now: NOW }), V.VERIFY_CSV_COLUMNS);
    assert.ok(csv.includes(`"'=HYPERLINK(""x"")"`), 'formula-safe cell');
  });

  test('JSON: the first key block is the CLI _row_dict keys (parsed from the CLI source), then the extras', () => {
    const cliKeys = rowDictKeys();
    assert.equal(cliKeys[0], 'server');
    assert.ok(cliKeys.includes('newCertCovers') && cliKeys.includes('elapsedMs'));
    const json = V.verifyExportJson(e2eRows(), { expect: NEW_GH, version: '9.9.9', now: new Date(NOW) });
    assert.equal(json.schema, 'domainscope.verify/1');
    assert.equal(json.generator, 'DomainScope');
    assert.equal(json.version, '9.9.9');
    assert.equal(json.exportedAt, new Date(NOW).toISOString());
    assert.deepEqual(json.newCertificate.sha256, NEW_GH.sha256);
    assert.equal(json.newCertificate.notAfter, '2026-11-29T23:59:59.000Z');
    for (const r of json.rows) assert.deepEqual(Object.keys(r).slice(0, cliKeys.length), cliKeys);
    const wild = json.rows.find((r) => r.name === 'wild.example.net');
    assert.equal(wild.newCertCovers, true, 'a JSON boolean, not "yes"');
    assert.equal(wild.certSerial, '07');
    assert.equal(wild.elapsedMs, 30);
    assert.deepEqual(wild.vantage, [{ country: 'DE', city: 'Falkenstein', asn: 24940, network: 'Hetzner Online', kind: 'datacenter', adopted: false }]);
    const vpn = json.rows.find((r) => r.name === 'vpn.wild.example.net');
    assert.deepEqual([vpn.status, vpn.state, vpn.skip], [null, 'skipped', 'private']);
    assert.deepEqual(json.newCertificate.kinds, ['other']);
    assert.deepEqual(json.summary.servers, { total: 3, checked: 3, live: 1, old: 1, other: 0, originCert: 0, privateCert: 0,
      tlsError: 0, unreachable: 1, filteredOrigins: 0, notHostingOrigins: 0, unchecked: 0, incomplete: 0 });
    assert.equal(wild.certKind, 'other');
    assert.equal(vpn.certKind, null);
  });

  test('the JSON never carries a public key, headers or DER', async () => {
    const r = ghRow('140.82.121.4');
    const client = fakeClient({ '140.82.121.4|github.com': [{ tests: testsOf('m01-github-valid') }] });
    await V.runVerify([r], runOpts(client, { probesPerCheck: 2 }));
    assert.ok(r.served.publicKeyHex, 'kept in memory');
    const json = V.verifyExportJson([r], { expect: NEW_GH, now: new Date(NOW) });
    const banned = new Set(['publicKey', 'publicKeyHex', 'headers', 'rawHeaders', 'der', 'spkiDer', 'spkiHex']);
    const walk = (v, path) => {
      if (v && typeof v === 'object') {
        for (const [k, x] of Object.entries(v)) {
          assert.ok(!banned.has(k), `${path}.${k}`);
          walk(x, `${path}.${k}`);
        }
      }
    };
    walk(json, '$');
    const text = JSON.stringify(json);
    assert.ok(!text.includes(r.served.publicKeyHex.slice(0, 40)), 'no public key bytes');
    assert.ok(!text.includes(V.hexKey(tlsOf('m01-github-valid').publicKey).slice(-40)));
    const csv = toCsv(V.verifyExportRows([r], { now: NOW }), V.VERIFY_CSV_COLUMNS);
    assert.ok(!csv.includes(r.served.publicKeyHex.slice(0, 40)));
  });
});

describe('expectationFor', () => {
  test('ec_wildcard.pem: fingerprint from expected.json, SPKI DER hex', async () => {
    const expected = JSON.parse(read('tests/fixtures/expected.json'))['ec_wildcard.pem'];
    const ex = await V.expectationFor(leafOf('ec_wildcard.pem'));
    assert.deepEqual(ex.sha256, [expected.sha256]);
    assert.equal(ex.spkiHex.length, 1);
    assert.ok(ex.spkiHex[0].startsWith('3059301306072a8648ce3d0201'));
    assert.deepEqual(ex.hostnames.slice().sort(), ['*.wild.example.net', 'wild.example.net']);
    const js = await V.expectationFor(leafOf('ec_wildcard.pem'), { subtle: null });
    assert.deepEqual(js.sha256, ex.sha256, 'the pure-JS fallback agrees');
  });

  test('several leaves give several entries (dual RSA/ECDSA rollouts)', async () => {
    const ex = await V.expectationFor([leafOf('ec_wildcard.pem'), GH]);
    assert.equal(ex.sha256.length, 2);
    assert.equal(ex.spkiHex.length, 2);
    assert.equal(ex.subjectCN, leafOf('ec_wildcard.pem').subjectCN);
    assert.deepEqual((await V.expectationFor([])).sha256, []);
  });

  test('real_github.pem is the m01 certificate: same-key suffix matches', () => {
    const pk = V.hexKey(tlsOf('m01-github-valid').publicKey);
    assert.ok(NEW_GH.spkiHex[0].endsWith(pk));
  });
});

/* ---- several certificate sets (renewal week, lib/certsets.js) ------------------------ */

describe('several certificate sets', () => {
  // renew_a_*: an RSA + ECDSA pair for example.com and *.example.com (set A); renew_b_rsa:
  // shop.example.com and pay.example.com (set B, whose exact names win over A's wildcard).
  const RSA_A = leafOf('renew_a_rsa.pem');
  const EC_A = leafOf('renew_a_ecdsa.pem');
  const RSA_B = leafOf('renew_b_rsa.pem');
  const colon = (hex) => hex.toUpperCase().match(/../g).join(':');
  const fpOf = async (cert) => (await V.expectationFor(cert)).sha256[0];
  /** A probe test serving `cert` (its fingerprint and names, as Globalping reports them). */
  const serving = async (cert) => withTls(synthTls({
    subject: { CN: cert.subjectCN, alt: cert.dnsNames.map((n) => `DNS:${n}`).join(', ') },
    fingerprint256: colon(await fpOf(cert)), keyType: cert.keyAlgorithm === 'RSA' ? 'RSA' : 'EC'
  }));
  const oldShop = () => withTls(synthTls({ subject: { CN: 'shop.example.com', alt: 'DNS:shop.example.com' } }));
  const SETS = [{ id: 'A', certs: [RSA_A, EC_A] }, { id: 'B', certs: [RSA_B] }];

  test('setExpectations: one expectation per set, with the other sets\' fingerprints', async () => {
    const m = await V.setExpectations([...SETS, { id: 'C', certs: [] }, null]);
    assert.deepEqual([...m.keys()], ['A', 'B']);
    const [fpRsaA, fpEcA, fpB] = await Promise.all([RSA_A, EC_A, RSA_B].map(fpOf));
    assert.deepEqual(m.get('A').sha256, [fpRsaA, fpEcA]);
    assert.equal(m.get('A').setId, 'A');
    assert.deepEqual(m.get('A').others, [{ setId: 'B', sha256: [fpB] }]);
    assert.deepEqual(m.get('B').others, [{ setId: 'A', sha256: [fpRsaA, fpEcA] }]);
    assert.deepEqual(m.get('B').hostnames.slice().sort(), ['pay.example.com', 'shop.example.com']);
    assert.deepEqual(m.get('A').kinds, ['other']);
    assert.equal((await V.setExpectations(null)).size, 0);
  });

  test('classifyTest: either certificate of the planned set is UPDATED, another set\'s new one too (other-set), an old one NEEDS_UPDATE', async () => {
    const m = await V.setExpectations(SETS);
    const at = (test, name, set) => V.classifyTest(test, { name, expect: m.get(set), now: NOW });
    const twin = at(await serving(EC_A), 'www.example.com', 'A');
    assert.deepEqual([twin.status, twin.reason, twin.matchedSet, twin.warnings], ['UPDATED', 'new-cert', 'A', []]);
    const planned = at(await serving(RSA_B), 'shop.example.com', 'B');
    assert.deepEqual([planned.status, planned.matchedSet, planned.warnings], ['UPDATED', 'B', []]);
    const other = at(await serving(EC_A), 'shop.example.com', 'B');
    assert.deepEqual([other.status, other.reason, other.matchedSet, other.warnings], ['UPDATED', 'new-cert', 'A', ['other-set']]);
    const old = at(oldShop(), 'shop.example.com', 'B');
    assert.deepEqual([old.status, old.reason, old.matchedSet], ['NEEDS_UPDATE', 'old-cert', null]);
    // B's certificate does not cover www: not hosted, never "another set"
    const wrong = at(await serving(RSA_B), 'www.example.com', 'A');
    assert.deepEqual([wrong.status, wrong.matchedSet, wrong.warnings], ['NOT_HOSTED', null, []]);
    // a plain expectation (one certificate, no sets) carries no matchedSet at all
    assert.ok(!('matchedSet' in V.classifyTest(oldShop(), { name: 'shop.example.com', expect: NEW_AB, now: NOW })));
  });

  test('runVerify: expectFor gives each row the expectation of its set; null falls back to `expect`', async () => {
    const m = await V.setExpectations(SETS);
    const rows = [
      row({ ip: '1.2.3.4', name: 'www.example.com', setId: 'A' }),
      row({ ip: '1.2.3.4', name: 'shop.example.com', setId: 'B' }),
      row({ ip: '5.6.7.8', name: 'pay.example.com', setId: 'B' }),
      row({ ip: '5.6.7.9', name: 'shop.example.com', setId: null })
    ];
    const client = fakeClient({
      '1.2.3.4|www.example.com': [{ tests: [await serving(EC_A)] }],
      '1.2.3.4|shop.example.com': [{ tests: [await serving(EC_A)] }],
      '5.6.7.8|pay.example.com': [{ tests: [oldShop()] }],
      '5.6.7.9|shop.example.com': [{ tests: [await serving(RSA_B)] }]
    });
    await V.runVerify(rows, { client, expect: NEW_AB, expectFor: (r) => m.get(r.setId) ?? null, now: () => NOW });
    assert.deepEqual(rows.map((r) => [r.name, r.status, r.verdict.matchedSet ?? '-', r.warnings.join()]), [
      ['www.example.com', 'UPDATED', 'A', ''],
      ['shop.example.com', 'UPDATED', 'A', 'other-set'],
      ['pay.example.com', 'NOT_HOSTED', '-', ''],
      ['shop.example.com', 'NEEDS_UPDATE', '-', '']
    ]);
  });

  test('buildVerifyPairs: setOf gives every pair its planned set; without it the pairs are unchanged', () => {
    const plain = V.buildVerifyPairs(scanResult());
    assert.ok(plain.pairs.every((p) => !('setId' in p)));
    const withSets = V.buildVerifyPairs(scanResult(), { setOf: (n) => (n === 'shop.example.com' ? 'B' : n.endsWith('.example.com') ? 'A' : null) });
    assert.deepEqual(withSets.pairs.map((p) => p.setId), plain.pairs.map((p) => (p.name === 'shop.example.com' ? 'B' : 'A')));
    assert.deepEqual(withSets.stats, plain.stats);
    const rows = V.createVerifyRows(withSets.pairs);
    assert.equal(rows.find((r) => r.name === 'shop.example.com').setId, 'B');
  });

  test('one name per IP is one name per IP and set: a server that needs two sets keeps a check for each', () => {
    const result = {
      hosts: ['www', 'api', 'shop', 'pay'].map((n) => host(`${n}.example.com`, { ips: ['1.2.3.5'] })),
      servers: [{ server: srv('web02'), needsCert: true, maybeNeedsCert: false,
        hosts: ['www', 'api', 'shop', 'pay'].map((n) => e(`${n}.example.com`, '1.2.3.5')) }],
      unmatchedIps: []
    };
    const setOf = (n) => (n === 'shop.example.com' || n === 'pay.example.com' ? 'B' : 'A');
    const { pairs } = V.buildVerifyPairs(result, { setOf });
    const per = V.scopePairs(pairs, 'perIp');
    assert.deepEqual(per.map((p) => `${p.name} ${p.setId}`), ['api.example.com A', 'pay.example.com B']);
    assert.equal(V.checkCount(per), 2);
    // without sets the address keeps one name, as before
    assert.equal(V.scopePairs(V.buildVerifyPairs(result).pairs, 'perIp').length, 1);
    // the cap reaches each set of the server before a second name of either
    const capped = V.createVerifyRows(pairs, { maxRows: 2 });
    assert.deepEqual(capped.filter((r) => r.state === 'pending').map((r) => r.setId).sort(), ['A', 'B']);
  });

  test('exports: set / served_set after the CLI columns, certificateSets in the JSON; a single certificate exports as before', async () => {
    const m = await V.setExpectations(SETS);
    const r = row({ ip: '1.2.3.4', name: 'shop.example.com', setId: 'B' });
    settle([check(r, [await serving(EC_A)], m.get('B'))]);
    const [flat] = V.verifyExportRows([r], { now: NOW });
    assert.deepEqual([flat.set, flat.served_set, flat.warnings], ['B', 'A', 'other-set']);
    const csv = toCsv(V.verifyExportRows([r], { now: NOW }), [...V.VERIFY_CSV_COLUMNS, ...V.VERIFY_SET_COLUMNS], { bom: false });
    assert.match(csv.split('\r\n')[0], /,checked_at,set,served_set$/);
    assert.match(csv.split('\r\n')[1], /,B,A$/);
    const json = V.verifyExportJson([r], { expect: m.get('A'), sets: m, now: new Date(NOW) });
    assert.deepEqual(json.certificateSets.map((x) => [x.id, x.sha256.length]), [['A', 2], ['B', 1]]);
    assert.deepEqual([json.rows[0].set, json.rows[0].servedSet], ['B', 'A']);
    // a plain row and a plain export keep their keys
    const plain = row({ name: 'github.com' });
    settle([done(plain, [V_UPDATED()])]);
    assert.ok(!('set' in V.verifyExportRows([plain], { now: NOW })[0]));
    const pj = V.verifyExportJson([plain], { expect: NEW_GH, now: new Date(NOW) });
    assert.ok(!('certificateSets' in pj) && !('set' in pj.rows[0]));
  });
});
