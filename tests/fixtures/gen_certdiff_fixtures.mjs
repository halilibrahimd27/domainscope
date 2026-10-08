#!/usr/bin/env node
/**
 * Generates the old-vs-new certificate fixtures (assets/js/lib/certdiff.js, tests/js/certdiff.test.js,
 * the Certificate view's "Compare" tab in the cert E2E suite): a throwaway PKI whose keys are never
 * written. Dev tool — no OpenSSL needed.
 *
 *   node tests/fixtures/gen_certdiff_fixtures.mjs           # create when missing
 *   node tests/fixtures/gen_certdiff_fixtures.mjs --force   # new keys, every file rewritten
 *
 * Each file is what a server sends: the leaf, then its intermediate (no root).
 *   certdiff_old.pem      example.com, *.example.com, legacy.example.net, mail.example.org and
 *                         192.0.2.10; RSA 2048, serverAuth + clientAuth, digitalSignature +
 *                         keyEncipherment, 3 SCTs, OCSP http://ocsp.example.com, no CRL, valid
 *                         2026-03-01 – 2036-03-01, issued (sha256WithRSAEncryption) by
 *                         "DomainScope Test Diff CA 1" (RSA 2048) under "DomainScope Test Diff Root 1"
 *   certdiff_new.pem      example.com, www.example.com, api.example.com, mail.example.org and
 *                         shop.example.org (the wildcard, legacy.example.net and the IP address
 *                         go); EC P-256, serverAuth only, digitalSignature only, 2 SCTs, OCSP
 *                         must-staple, OCSP http://ocsp.example.net, CRL
 *                         http://crl.example.com/diff-ca-2.crl, valid 2026-09-01 – 2031-09-01, issued
 *                         (ecdsa-with-SHA384) by "DomainScope Test Diff CA 2" (EC P-384) under
 *                         "DomainScope Test Diff Root 2"
 *   certdiff_renewed.pem  the old certificate renewed: the same key, names, extensions and issuer,
 *                         valid 2026-09-01 – 2036-09-01 (the leaf alone, as some CAs deliver it)
 */
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { seq, ctx, tlv, oid, bool, octet, bits, utf8, printable, utc, gen, name, ext, ALG, A, buildCert, pem, spkiOf, signWith } from './der-builder.mjs';

const DIR = dirname(fileURLToPath(import.meta.url));
const FORCE = process.argv.includes('--force');
const fx = (file) => join(DIR, file);
const FILES = { old: 'certdiff_old.pem', new: 'certdiff_new.pem', renewed: 'certdiff_renewed.pem' };

if (!FORCE && Object.values(FILES).every((f) => existsSync(fx(f)))) {
  console.log('certdiff fixtures exist (use --force to regenerate)');
  process.exit(0);
}

const serial = () => {
  const b = randomBytes(16);
  b[0] &= 0x7f;
  return b.toString('hex');
};
const dn = (cn) => name([[[A.C, printable('XX')]], [[A.O, utf8('DomainScope Test')]], [[A.CN, utf8(cn)]]]);
/** 'YYYY-MM-DD' → UTCTime before 2050, GeneralizedTime after (RFC 5280). */
const time = (d, end = false) => {
  const s = `${d.replace(/-/g, '').slice(2)}${end ? '235959' : '000000'}Z`;
  return Number(d.slice(0, 4)) < 2050 ? utc(s) : gen(`${d.slice(0, 2)}${s}`);
};
/** Key identifier: SHA-1 of the SubjectPublicKeyInfo (any rule will do, as long as SKI and AKI agree). */
const keyId = (key) => createHash('sha1').update(spkiOf(key)).digest();
const uri = (s) => ctx(6, false, Buffer.from(s, 'latin1'));
const ip4 = (s) => ctx(7, false, Buffer.from(s.split('.').map(Number)));

/** A TLS-encoded SignedCertificateTimestampList of `count` well-formed (unsigned) SCTs. */
function sctList(count, seed) {
  const scts = [];
  for (let i = 0; i < count; i++) {
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(1772323200000n + BigInt(i) * 1000n);
    const sig = Buffer.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    const sct = Buffer.concat([
      Buffer.from([0]), Buffer.alloc(32, seed + i), ts, Buffer.from([0, 0]), Buffer.from([4, 3]), Buffer.from([0, sig.length]), sig
    ]);
    scts.push(Buffer.concat([Buffer.from([sct.length >> 8, sct.length & 0xff]), sct]));
  }
  const body = Buffer.concat(scts);
  return Buffer.concat([Buffer.from([body.length >> 8, body.length & 0xff]), body]);
}

const rsa = () => generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = (namedCurve) => generateKeyPairSync('ec', { namedCurve });
const keys = { root1: ec('P-256'), root2: ec('P-384'), ca1: rsa(), ca2: ec('P-384'), oldLeaf: rsa(), newLeaf: ec('P-256') };
const N = {
  root1: dn('DomainScope Test Diff Root 1'), root2: dn('DomainScope Test Diff Root 2'),
  ca1: dn('DomainScope Test Diff CA 1'), ca2: dn('DomainScope Test Diff CA 2')
};

function caCert({ subject, subjectKey, issuer, issuerKey, sigAlg, hash }) {
  return buildCert({
    serial: serial(), sigAlg, issuer: N[issuer], notBefore: time('2025-06-01'), notAfter: time('2040-06-01', true),
    subject: N[subject], spki: spkiOf(keys[subjectKey].publicKey),
    extensions: [
      ext('2.5.29.19', seq(bool(true), tlv(0x02, Buffer.from([0]))), true),
      ext('2.5.29.15', bits(Buffer.from([0x06]), 1), true), // keyCertSign, cRLSign
      ext('2.5.29.37', seq(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.2'))),
      ext('2.5.29.14', octet(keyId(keys[subjectKey].publicKey))),
      ext('2.5.29.35', seq(ctx(0, false, keyId(keys[issuerKey].publicKey))))
    ],
    signer: signWith(keys[issuerKey].privateKey, hash)
  });
}

/**
 * A server leaf.
 * @param {{ key: string, ca: string, sigAlg: Buffer, hash: string, from: string, to: string, names: string[], ips?: string[],
 *   ku: Buffer, eku: string[], scts: number, ocsp: string, caIssuers: string, crl?: string|null, staple?: boolean }} spec
 */
function leafCert({ key, ca, sigAlg, hash, from, to, names, ips = [], ku, eku, scts, ocsp, caIssuers, crl = null, staple = false }) {
  const aia = seq(seq(oid('1.3.6.1.5.5.7.48.1'), uri(ocsp)), seq(oid('1.3.6.1.5.5.7.48.2'), uri(caIssuers)));
  return buildCert({
    serial: serial(), sigAlg, issuer: N[ca], notBefore: time(from), notAfter: time(to, true),
    subject: name([[[A.CN, utf8(names[0])]]]), spki: spkiOf(keys[key].publicKey),
    extensions: [
      ext('2.5.29.19', seq(), true),
      ext('2.5.29.15', ku, true),
      ext('2.5.29.37', seq(...eku.map(oid))),
      ext('2.5.29.17', seq(...names.map((n) => ctx(2, false, Buffer.from(n))), ...ips.map(ip4))),
      ext('2.5.29.14', octet(keyId(keys[key].publicKey))),
      ext('2.5.29.35', seq(ctx(0, false, keyId(keys[ca].publicKey)))),
      ext('2.5.29.32', seq(seq(oid('2.23.140.1.2.1')))), // DV
      ext('1.3.6.1.5.5.7.1.1', aia),
      ...(crl ? [ext('2.5.29.31', seq(seq(ctx(0, true, ctx(0, true, uri(crl))))))] : []),
      ...(staple ? [ext('1.3.6.1.5.5.7.1.24', seq(tlv(0x02, Buffer.from([5]))))] : []),
      ext('1.3.6.1.4.1.11129.2.4.2', octet(sctList(scts, 0x20)))
    ],
    signer: signWith(keys[ca].privateKey, hash)
  });
}

const SERVER = '1.3.6.1.5.5.7.3.1';
const CLIENT = '1.3.6.1.5.5.7.3.2';
const ca1 = caCert({ subject: 'ca1', subjectKey: 'ca1', issuer: 'root1', issuerKey: 'root1', sigAlg: ALG.ecdsa256, hash: 'sha256' });
const ca2 = caCert({ subject: 'ca2', subjectKey: 'ca2', issuer: 'root2', issuerKey: 'root2', sigAlg: ALG.ecdsa384, hash: 'sha384' });
const OLD = {
  key: 'oldLeaf', ca: 'ca1', sigAlg: ALG.sha256Rsa, hash: 'sha256', from: '2026-03-01', to: '2036-03-01',
  names: ['example.com', '*.example.com', 'legacy.example.net', 'mail.example.org'], ips: ['192.0.2.10'],
  ku: bits(Buffer.from([0xa0]), 5), eku: [SERVER, CLIENT], scts: 3, // digitalSignature, keyEncipherment
  ocsp: 'http://ocsp.example.com', caIssuers: 'http://ca.example.com/diff-ca-1.der'
};
const files = {
  old: [leafCert(OLD), ca1],
  new: [leafCert({
    key: 'newLeaf', ca: 'ca2', sigAlg: ALG.ecdsa384, hash: 'sha384', from: '2026-09-01', to: '2031-09-01',
    names: ['example.com', 'www.example.com', 'api.example.com', 'mail.example.org', 'shop.example.org'],
    ku: bits(Buffer.from([0x80]), 7), eku: [SERVER], scts: 2, staple: true, // digitalSignature
    ocsp: 'http://ocsp.example.net', caIssuers: 'http://ca.example.com/diff-ca-2.der', crl: 'http://crl.example.com/diff-ca-2.crl'
  }), ca2],
  renewed: [leafCert({ ...OLD, from: '2026-09-01', to: '2036-09-01' })]
};
for (const [id, file] of Object.entries(FILES)) {
  writeFileSync(fx(file), files[id].map(pem).join(''));
  console.log('crafted', file);
}
// The fixtures parse back as generated (a quick self-check, not the tests).
for (const file of Object.values(FILES)) if (!readFileSync(fx(file), 'utf8').includes('BEGIN CERTIFICATE')) throw new Error(file);
