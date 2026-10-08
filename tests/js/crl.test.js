/**
 * crl.test.js — lib/crl.js: DER CRLs made with OpenSSL (tests/fixtures/gen_crl_fixtures.sh: two
 * revoked serials with reason codes, an empty CRL, another issuer's CRL) and crafted ones for the
 * cases OpenSSL does not make (a delta CRL, an unknown critical extension, a CRL for some reasons
 * or for CA certificates only, removeFromCRL, version 1, RSA-PSS parameters), what each says about
 * a certificate at an injected time, and input that is no CRL. Documentation names only.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REVOCATION_REASONS, REVOCATION_REASON_NAMES, CRL_UNKNOWN, CrlParseError, reasonName, normalizeSerial, parseCrl, crlIssuedFor,
  crlStatus, crlUrlsOf, signatureScheme
} from '../../assets/js/lib/crl.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { seq, ctx, oid, int, bool, octet, bits, utc, gen, name, ext, ALG, A, utf8 } from '../fixtures/der-builder.mjs';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const read = (f) => readFileSync(join(FIX, f));
const certOf = (f) => parseCertificates(read(f)).certificates[0];
const DP = 'http://crl.example.com/test-ca.crl';
const NOW = Date.parse('2026-10-09T12:00:00Z');

const CA = certOf('crl_ca.pem');
const OTHER_CA = certOf('crl_other_ca.pem');
const LEAF = certOf('crl_leaf.pem');
const LEAF2 = certOf('crl_leaf2.pem');

test('the reason codes are RFC 5280 §5.3.1 CRLReason', () => {
  assert.deepEqual(Object.keys(REVOCATION_REASONS).map(Number), [0, 1, 2, 3, 4, 5, 6, 8, 9, 10], '7 is not used');
  assert.equal(REVOCATION_REASON_NAMES.length, 10);
  assert.equal(reasonName(1), 'keyCompromise');
  assert.equal(reasonName('4'), 'superseded');
  assert.equal(reasonName(0), 'unspecified');
  for (const bad of [7, 11, -1, null, undefined, '', 'x', 1.5]) assert.equal(reasonName(bad), null, String(bad));
  assert.ok(Object.isFrozen(REVOCATION_REASONS) && Object.isFrozen(CRL_UNKNOWN));
});

test('serial numbers are compared as lib/x509.js writes them', () => {
  assert.equal(normalizeSerial('0C1001'), '0c1001');
  assert.equal(normalizeSerial('000c1001'), '0c1001', 'a leading zero byte goes, the nibble stays');
  assert.equal(normalizeSerial('0x00AB'), 'ab');
  assert.equal(normalizeSerial('c1001'), '0c1001', 'an odd length is padded');
  assert.equal(normalizeSerial('0c:10:01'), '0c1001');
  assert.equal(normalizeSerial('00'), '00');
  for (const bad of ['', 'xyz', null, undefined, '12 g']) assert.equal(normalizeSerial(bad), null, String(bad));
  assert.equal(normalizeSerial(LEAF.serialHex), LEAF.serialHex);
});

test('OpenSSL’s CRL with two revoked serials: issuer, dates, entries with reasons, extensions and the signed part', () => {
  const crl = parseCrl(read('crl_revoked.der'));
  assert.equal(crl.version, 2);
  assert.equal(crl.issuerDN, 'CN=Example Test CRL CA,O=Example Test PKI');
  assert.equal(crl.issuerDN, CA.subjectDN, 'the CA certificate’s subject');
  assert.deepEqual({ ...crl.issuer }, { O: 'Example Test PKI', CN: 'Example Test CRL CA' });
  assert.equal(crl.thisUpdate.toISOString(), '2026-10-01T00:00:00.000Z');
  assert.equal(crl.nextUpdate.toISOString(), '2026-10-15T00:00:00.000Z');
  assert.equal(crl.count, 2);
  assert.equal(crl.filtered, null);
  assert.deepEqual(crl.revoked.map((e) => [e.serialHex, e.revocationDate.toISOString(), e.reasonCode, e.reason]), [
    ['0c1001', '2026-09-01T12:00:00.000Z', 1, 'keyCompromise'],
    ['0c1002', '2026-08-15T08:30:00.000Z', 4, 'superseded']
  ]);
  assert.equal(crl.crlNumber, '10');
  assert.equal(crl.authorityKeyId, CA.subjectKeyId, 'the CA’s key identifier');
  assert.deepEqual(crl.idp, { urls: [DP], relativeName: false, onlyUser: true, onlyCA: false, onlySomeReasons: false, indirect: false, onlyAttribute: false });
  assert.equal(crl.deltaCrl, false);
  assert.deepEqual(crl.unsupportedCritical, []);
  assert.equal(crl.signatureAlgorithm, 'ecdsa-with-SHA256');
  assert.deepEqual(crl.scheme, { scheme: 'ecdsa', hash: 'sha256' });
  const der = read('crl_revoked.der');
  assert.ok(Buffer.from(der).includes(Buffer.from(crl.tbsDer)), 'tbsDer is the signed TLV of the file');
  assert.equal(crl.tbsDer[0], 0x30);
  assert.ok(crl.signature.length >= 64 && crl.signature[0] === 0x30, 'a DER ECDSA signature');
});

test('only the serials asked for are kept; every entry is counted', () => {
  const crl = parseCrl(read('crl_revoked.der'), { serials: ['0C1001', 'ff'] });
  assert.deepEqual(crl.revoked.map((e) => e.serialHex), ['0c1001']);
  assert.equal(crl.count, 2);
  assert.deepEqual([...crl.filtered], ['0c1001', 'ff']);
  assert.equal(crlStatus(crl, LEAF, { url: DP, now: NOW }).status, 'revoked');
  assert.throws(() => crlStatus(crl, LEAF2, { now: NOW }), RangeError, 'read for other serials: never a false "good"');
});

test('the empty CRL and another CA’s CRL', () => {
  const empty = parseCrl(read('crl_empty.der'));
  assert.equal(empty.count, 0);
  assert.deepEqual(empty.revoked, []);
  assert.equal(empty.crlNumber, '11');
  assert.equal(empty.idp.urls[0], DP);
  const other = parseCrl(read('crl_other.der'));
  assert.equal(other.issuerDN, OTHER_CA.subjectDN);
  assert.deepEqual(other.scheme, { scheme: 'rsa-pkcs1', hash: 'sha256' });
  assert.equal(other.signatureAlgorithm, 'sha256WithRSAEncryption');
  assert.equal(other.idp, null);
  assert.equal(other.signature.length, 256, 'RSA 2048');
  assert.deepEqual(other.revoked.map((e) => [e.serialHex, e.reason]), [['0c1001', 'keyCompromise']]);
});

test('what each CRL says about the leaf', () => {
  const revoked = parseCrl(read('crl_revoked.der'));
  const empty = parseCrl(read('crl_empty.der'));
  const other = parseCrl(read('crl_other.der'));
  const r = crlStatus(revoked, LEAF, { url: DP, now: NOW });
  assert.equal(r.status, 'revoked');
  assert.equal(r.code, null);
  assert.equal(r.reasonCode, 1);
  assert.equal(r.reason, 'keyCompromise');
  assert.equal(r.time.toISOString(), '2026-09-01T12:00:00.000Z');
  assert.equal(r.thisUpdate.toISOString(), '2026-10-01T00:00:00.000Z');
  assert.equal(crlStatus(revoked, LEAF2, { url: DP, now: NOW }).reason, 'superseded');
  const g = crlStatus(empty, LEAF, { url: DP, now: NOW });
  assert.deepEqual([g.status, g.code, g.reason, g.time], ['good', null, null, null]);
  // the same serial on another CA's CRL says nothing about this certificate
  assert.deepEqual([crlStatus(other, LEAF, { now: NOW }).status, crlStatus(other, LEAF, { now: NOW }).code], ['unknown', 'issuer-mismatch']);
  assert.equal(crlIssuedFor(revoked, LEAF), true);
  assert.equal(crlIssuedFor(other, LEAF), false);
  // the CA re-keyed under the same name: its key identifier differs
  const rekeyed = { ...LEAF, authorityKeyId: 'ab'.repeat(20) };
  assert.equal(crlStatus(revoked, rekeyed, { url: DP, now: NOW }).code, 'issuer-mismatch');
  assert.equal(crlIssuedFor(revoked, { ...LEAF, authorityKeyId: null }), true, 'no key identifier: the name decides');
  // read from another partition's URL than the one it says it is
  assert.equal(crlStatus(revoked, LEAF, { url: 'http://crl.example.com/other.crl', now: NOW }).code, 'scope');
  assert.equal(crlStatus(revoked, LEAF, { url: 'HTTP://CRL.EXAMPLE.COM/test-ca.crl', now: NOW }).status, 'revoked', 'scheme and host in any case');
  assert.equal(crlStatus(revoked, LEAF, { now: NOW }).status, 'revoked', 'no URL given: not checked');
  // user certificates only: a CA certificate is not covered
  assert.equal(crlStatus(empty, { ...LEAF, isCA: true }, { url: DP, now: NOW }).code, 'scope');
  // after nextUpdate: an unlisted serial is unknown, a listed one stays revoked
  const later = Date.parse('2026-10-20T00:00:00Z');
  assert.deepEqual([crlStatus(empty, LEAF, { url: DP, now: later }).status, crlStatus(empty, LEAF, { url: DP, now: later }).code], ['unknown', 'stale']);
  assert.equal(crlStatus(revoked, LEAF, { url: DP, now: new Date(later) }).status, 'revoked');
  assert.throws(() => crlStatus(empty, { ...LEAF, serialHex: '' }), TypeError);
});

test('the CRL distribution point URLs a fetcher can read', () => {
  assert.deepEqual(crlUrlsOf(LEAF), [DP]);
  assert.deepEqual(crlUrlsOf({ crlUrls: ['ldap://ldap.example.com/cn=CA?certificateRevocationList', DP, DP, 'https://crl.example.org/a.crl', 'http://bad url', 7] }),
    [DP, 'https://crl.example.org/a.crl']);
  assert.deepEqual(crlUrlsOf({}), []);
  assert.deepEqual(crlUrlsOf(null), []);
});

/* ------------------------------------------------------------------------ */
/* Crafted CRLs                                                             */
/* ------------------------------------------------------------------------ */

const ISSUER = name([[[A.O, utf8('Example Test PKI')]], [[A.CN, utf8('Example Test CRL CA')]]]);
const DUMMY_SIG = bits(Buffer.alloc(8, 0xab));
const entry = (serial, when, ...exts) => seq(int(serial), utc(when), ...(exts.length ? [seq(...exts)] : []));
const reasonExt = (code) => ext('2.5.29.21', Buffer.from([0x0a, 0x01, code]));
const idpExt = (...fields) => ext('2.5.29.28', seq(...fields), true);
const fullName = (url) => ctx(0, true, ctx(0, true, ctx(6, false, Buffer.from(url, 'latin1'))));

/** A CRL by the CRL CA's name, version 2 unless `v1`. */
function crafted({ entries = [], exts = [], v1 = false, alg = ALG.ecdsa256, innerAlg = alg, thisUpdate = utc('261001000000Z'), nextUpdate = utc('261015000000Z') } = {}) {
  const tbs = seq(
    ...(v1 ? [] : [int('01')]),
    innerAlg,
    ISSUER,
    thisUpdate,
    ...(nextUpdate ? [nextUpdate] : []),
    ...(entries.length ? [seq(...entries)] : []),
    ...(exts.length ? [ctx(0, true, seq(...exts))] : [])
  );
  return seq(tbs, alg, DUMMY_SIG);
}

test('crafted: a delta CRL, an unknown critical extension, reasons-only and CA-only distribution points', () => {
  const at = { url: DP, now: NOW };
  const delta = parseCrl(crafted({ exts: [ext('2.5.29.27', int('05'), true)] }));
  assert.equal(delta.deltaCrl, true);
  assert.equal(crlStatus(delta, LEAF, at).code, 'delta');
  const critical = parseCrl(crafted({ exts: [ext('1.2.3.4.5', octet(Buffer.from([1])), true), ext('1.2.3.4.6', octet(Buffer.from([1])))] }));
  assert.deepEqual(critical.unsupportedCritical, ['1.2.3.4.5'], 'a non-critical unknown extension is no matter');
  assert.equal(crlStatus(critical, LEAF, at).code, 'critical-extension');
  const reasons = parseCrl(crafted({ exts: [idpExt(fullName(DP), ctx(3, false, Buffer.from([0x07, 0x80])))], entries: [entry('0c1002', '260815083000Z', reasonExt(1))] }));
  assert.equal(reasons.idp.onlySomeReasons, true);
  assert.equal(crlStatus(reasons, LEAF, at).code, 'reasons', 'a CRL for some reasons cannot say "good"');
  assert.equal(crlStatus(reasons, LEAF2, at).status, 'revoked', 'but a listed serial is revoked');
  const caOnly = parseCrl(crafted({ exts: [idpExt(fullName(DP), ctx(2, false, Buffer.from([0xff])))] }));
  assert.equal(caOnly.idp.onlyCA, true);
  assert.equal(crlStatus(caOnly, LEAF, at).code, 'scope');
  const indirect = parseCrl(crafted({ exts: [idpExt(ctx(4, false, Buffer.from([0xff])))] }));
  assert.deepEqual([indirect.idp.indirect, indirect.idp.urls], [true, []]);
  assert.equal(crlStatus(indirect, LEAF, at).code, 'scope');
  const attr = parseCrl(crafted({ exts: [idpExt(ctx(5, false, Buffer.from([0xff])))] }));
  assert.equal(crlStatus(attr, LEAF, at).code, 'scope');
  const relative = parseCrl(crafted({ exts: [idpExt(ctx(0, true, ctx(1, true, seq(oid(A.CN), utf8('part 1')))))] }));
  assert.deepEqual([relative.idp.relativeName, relative.idp.urls], [true, []]);
  assert.equal(crlStatus(relative, LEAF, at).status, 'good', 'no URL to compare: the URL check is skipped');
});

test('crafted: removeFromCRL, a missing reason, an unknown critical entry extension, GeneralizedTime and version 1', () => {
  const at = { now: NOW };
  const crl = parseCrl(crafted({
    entries: [
      entry('0c1001', '260901120000Z', reasonExt(8)),
      entry('0c1002', '260815083000Z'),
      entry('00ff', '260815083000Z', ext('2.5.29.24', gen('20260814000000Z')), reasonExt(6))
    ]
  }));
  assert.deepEqual(crl.revoked.map((e) => [e.serialHex, e.reasonCode, e.reason]), [['0c1001', 8, 'removeFromCRL'], ['0c1002', null, null], ['ff', 6, 'certificateHold']]);
  assert.equal(crl.revoked[2].invalidityDate.toISOString(), '2026-08-14T00:00:00.000Z');
  assert.equal(crlStatus(crl, LEAF, at).status, 'good', 'removeFromCRL: no longer on hold');
  const r = crlStatus(crl, LEAF2, at);
  assert.deepEqual([r.status, r.reasonCode, r.reason], ['revoked', null, null], 'no reason given: none said');
  assert.equal(crlStatus(crl, { ...LEAF, serialHex: 'ff' }, at).reason, 'certificateHold');
  const odd = parseCrl(crafted({ entries: [entry('0c1001', '260901120000Z', ext('1.2.3.9', octet(Buffer.from([1])), true))] }));
  assert.deepEqual(odd.revoked[0].unsupportedCritical, ['1.2.3.9']);
  assert.equal(crlStatus(odd, LEAF, at).code, 'critical-extension');
  const v1 = parseCrl(crafted({ v1: true, nextUpdate: null, thisUpdate: gen('20261001000000Z'), entries: [entry('0c1001', '260901120000Z')] }));
  assert.equal(v1.version, 1);
  assert.equal(v1.nextUpdate, null);
  assert.equal(v1.thisUpdate.toISOString(), '2026-10-01T00:00:00.000Z');
  assert.equal(crlStatus(v1, { ...LEAF2 }, { now: Date.parse('2099-01-01T00:00:00Z') }).status, 'good', 'no nextUpdate: never stale');
  assert.equal(crlStatus(v1, LEAF, at).status, 'revoked');
});

test('signature schemes: RSA PKCS#1, ECDSA, EdDSA and RSA-PSS with its parameters', () => {
  assert.deepEqual(signatureScheme('1.2.840.113549.1.1.11'), { scheme: 'rsa-pkcs1', hash: 'sha256' });
  assert.deepEqual(signatureScheme('1.2.840.113549.1.1.5'), { scheme: 'rsa-pkcs1', hash: 'sha1' });
  assert.deepEqual(signatureScheme('1.2.840.10045.4.3.3'), { scheme: 'ecdsa', hash: 'sha384' });
  assert.deepEqual(signatureScheme('1.3.101.112'), { scheme: 'ed25519', hash: null });
  assert.deepEqual(signatureScheme('1.3.101.113'), { scheme: 'ed448', hash: null });
  assert.equal(signatureScheme('1.2.840.10040.4.3'), null, 'DSA');
  assert.equal(signatureScheme('1.2.840.113549.1.1.4'), null, 'MD5');
  assert.deepEqual(signatureScheme('1.2.840.113549.1.1.10'), { scheme: 'rsa-pss', hash: 'sha1', saltLength: 20 }, 'the RFC 4055 defaults');
  const pss = seq(oid('1.2.840.113549.1.1.10'), seq(
    ctx(0, true, seq(oid('2.16.840.1.101.3.4.2.1'))),
    ctx(1, true, seq(oid('1.2.840.113549.1.1.8'), seq(oid('2.16.840.1.101.3.4.2.1')))),
    ctx(2, true, int('20'))
  ));
  const crl = parseCrl(crafted({ alg: pss }));
  assert.deepEqual(crl.scheme, { scheme: 'rsa-pss', hash: 'sha256', saltLength: 32 });
  assert.equal(crl.signatureAlgorithm, 'rsassaPss');
});

test('input that is no CRL is a CrlParseError, never a TypeError or RangeError', () => {
  const pem = Buffer.from(`-----BEGIN X509 CRL-----\n${read('crl_empty.der').toString('base64')}\n-----END X509 CRL-----\n`);
  const good = read('crl_empty.der');
  const cases = {
    pem,
    html: Buffer.from('<!doctype html><title>404</title>'),
    empty: Buffer.alloc(0),
    truncated: good.subarray(0, good.length - 10),
    trailing: Buffer.concat([good, Buffer.from([0])]),
    certificate: read('crl_leaf.pem'),
    'two algorithms': crafted({ alg: ALG.ecdsa256, innerAlg: ALG.ecdsa384 }),
    'version 3': seq(seq(int('02'), ALG.ecdsa256, ISSUER, utc('261001000000Z')), ALG.ecdsa256, DUMMY_SIG),
    'no thisUpdate': seq(seq(int('01'), ALG.ecdsa256, ISSUER), ALG.ecdsa256, DUMMY_SIG),
    'bad entry': crafted({ entries: [seq(int('01'))] }),
    'an extra field': seq(seq(int('01'), ALG.ecdsa256, ISSUER, utc('261001000000Z'), bool(true)), ALG.ecdsa256, DUMMY_SIG)
  };
  for (const [what, bytes] of Object.entries(cases)) {
    assert.throws(() => parseCrl(bytes), (err) => err instanceof CrlParseError && err.name === 'CrlParseError', what);
  }
  assert.throws(() => parseCrl('not bytes'), CrlParseError);
  assert.throws(() => parseCrl(null), CrlParseError);
  // an ArrayBuffer and a DataView work as well as a Uint8Array
  assert.equal(parseCrl(good.buffer.slice(good.byteOffset, good.byteOffset + good.length)).count, 0);
  assert.equal(parseCrl(new DataView(good.buffer, good.byteOffset, good.length)).count, 0);
});
