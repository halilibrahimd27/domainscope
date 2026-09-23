#!/usr/bin/env node
/**
 * Generates the x509.js-specific fixtures and their OpenSSL ground truth
 * (tests/fixtures/x509_expected.json). Dev tool — needs `openssl` (3.x) on PATH.
 *
 *   node tests/fixtures/gen_x509_fixtures.mjs              # create missing fixtures, refresh x509_expected.json
 *   node tests/fixtures/gen_x509_fixtures.mjs --force      # also regenerate crafted / derived fixtures (new keys!)
 *   node tests/fixtures/gen_x509_fixtures.mjs --fetch-real # also re-download real_*.pem via `openssl s_client`
 *
 * Crafted certificates are built with an independent, minimal DER encoder
 * (below) and signed with node:crypto, so they exercise corner cases OpenSSL's
 * CLI cannot produce (string types, escaping, odd SAN entries, SCT lists, ...).
 * (OpenSSL 3.5 refuses names holding VisibleString, GeneralString,
 * VideotexString, GraphicString, OCTET STRING, ... values, so those are
 * covered by DER crafted inside tests/js/x509.test.js instead.)
 * The expected values are always taken from `openssl x509` output, never from
 * the parser under test. The pre-existing fixtures (expected.json) are read but
 * never modified.
 */
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign as cryptoSign, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = dirname(fileURLToPath(import.meta.url));
const FORCE = process.argv.includes('--force');
const FETCH_REAL = process.argv.includes('--fetch-real');
const TMP = mkdtempSync(join(tmpdir(), 'x509fx-'));
const fx = (name) => join(DIR, name);

function openssl(args, { input, encoding = 'utf8' } = {}) {
  return execFileSync('openssl', args, { input, encoding: encoding === 'buffer' ? undefined : encoding, stdio: ['pipe', 'pipe', 'pipe'] });
}

// ---------------------------------------------------------------------------
// Minimal DER encoder (independent of the parser under test)
// ---------------------------------------------------------------------------
const buf = (x) => (Buffer.isBuffer(x) ? x : Buffer.from(x));
const encLen = (n) => {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
};
const tlv = (tag, ...parts) => {
  const body = Buffer.concat(parts.map(buf));
  return Buffer.concat([Buffer.from([tag]), encLen(body.length), body]);
};
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...[...p].map(buf).sort(Buffer.compare)); // DER SET OF ordering
const ctx = (n, constructed, ...p) => tlv(0x80 | (constructed ? 0x20 : 0) | n, ...p);
const oid = (s) => {
  const arcs = s.split('.').map(BigInt);
  const out = [];
  const push = (v) => {
    const bytes = [Number(v & 0x7fn)];
    for (let x = v >> 7n; x > 0n; x >>= 7n) bytes.unshift(Number(x & 0x7fn) | 0x80);
    out.push(...bytes);
  };
  push(arcs[0] * 40n + arcs[1]);
  arcs.slice(2).forEach(push);
  return tlv(0x06, Buffer.from(out));
};
const int = (hex) => {
  let b = Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex');
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
};
const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0]));
const nul = () => Buffer.from([0x05, 0x00]);
const octet = (b) => tlv(0x04, b);
const bits = (b, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), buf(b)]));
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const printable = (s) => tlv(0x13, Buffer.from(s, 'latin1'));
const ia5 = (s) => tlv(0x16, Buffer.from(s, 'latin1'));
const t61 = (s) => tlv(0x14, Buffer.from(s, 'latin1'));
const numeric = (s) => tlv(0x12, Buffer.from(s, 'latin1'));
const bmp = (s) => tlv(0x1e, Buffer.from(s, 'utf16le').swap16());
const universal = (s) => tlv(0x1c, Buffer.concat(Array.from(s, (ch) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(ch.codePointAt(0));
  return b;
})));
const utc = (s) => tlv(0x17, Buffer.from(s, 'latin1'));
const gen = (s) => tlv(0x18, Buffer.from(s, 'latin1'));
/** rdns: Array<Array<[oid, valueDer]>> in DER order */
const name = (rdns) => seq(...rdns.map((rdn) => set(...rdn.map(([o, v]) => seq(oid(o), v)))));
const ext = (o, value, critical = false) => seq(oid(o), ...(critical ? [bool(true)] : []), octet(value));

const ALG = {
  sha256Rsa: seq(oid('1.2.840.113549.1.1.11'), nul()),
  ecdsa256: seq(oid('1.2.840.10045.4.3.2')),
  ecdsa384: seq(oid('1.2.840.10045.4.3.3')),
  ecdsa512: seq(oid('1.2.840.10045.4.3.4')),
  ed25519: seq(oid('1.3.101.112')),
  ed448: seq(oid('1.3.101.113')),
  dsa256: seq(oid('2.16.840.1.101.3.4.3.2'))
};

function buildCert({ version = 3, serial, sigAlg, issuer, notBefore, notAfter, subject, spki, issuerUid, subjectUid, extensions, signer }) {
  const tbs = seq(
    ...(version > 1 ? [ctx(0, true, int((version - 1).toString(16)))] : []),
    int(serial),
    sigAlg,
    issuer,
    seq(notBefore, notAfter),
    subject,
    spki,
    ...(issuerUid ? [ctx(1, false, Buffer.concat([Buffer.from([0]), issuerUid]))] : []),
    ...(subjectUid ? [ctx(2, false, Buffer.concat([Buffer.from([0]), subjectUid]))] : []),
    ...(extensions && extensions.length ? [ctx(3, true, seq(...extensions))] : [])
  );
  return seq(tbs, sigAlg, bits(signer(tbs)));
}

const pem = (der) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
const spkiOf = (key) => key.export({ type: 'spki', format: 'der' });
const signWith = (privateKey, hash) => (tbs) => cryptoSign(hash, tbs, privateKey);

// ---------------------------------------------------------------------------
// Crafted certificates
// ---------------------------------------------------------------------------
const A = {
  C: '2.5.4.6', ST: '2.5.4.8', L: '2.5.4.7', O: '2.5.4.10', OU: '2.5.4.11', CN: '2.5.4.3',
  title: '2.5.4.12', description: '2.5.4.13', pseudonym: '2.5.4.65', name: '2.5.4.41', DC: '0.9.2342.19200300.100.1.25',
  email: '1.2.840.113549.1.9.1', UID: '0.9.2342.19200300.100.1.1', serialNumber: '2.5.4.5',
  x121: '2.5.4.24', postalAddress: '2.5.4.16', initials: '2.5.4.43'
};

function craftDnTorture() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const subject = name([
    [[A.DC, ia5('com')]],
    [[A.DC, ia5('example')]],
    [[A.C, printable('TR')]],
    [[A.ST, utf8('İstanbul')]],
    [[A.L, bmp('Kadıköy')]],
    [[A.O, utf8('Örnek Bilişim A.Ş.')]],
    [[A.OU, t61('Gömlek Ürün é')]],
    [[A.CN, utf8('multi value')], [A.OU, utf8('team')]],
    [[A.CN, utf8('a,b+c;d<e>f"g\\h=i#j')]],
    [[A.OU, utf8('#hash')]],
    [[A.OU, utf8(' spaced ')]],
    [[A.title, utf8('#')]],
    [[A.description, utf8(' ')]],
    [[A.description, utf8('tab\there\x7fdel\x00nul')]],
    [[A.pseudonym, universal('😀 smile')]],
    [[A.email, ia5('ops@example.com')]],
    [[A.UID, utf8('user1')]],
    [[A.serialNumber, printable('12345')]],
    [[A.x121, numeric('12345')]],
    [[A.postalAddress, seq(utf8('Line 1'), utf8('Line 2'))]],
    [['1.2.3.4.5.6', utf8('unknown')]],
    [[A.initials, utf8('')]],
    [[A.CN, utf8('second-cn.example.com')]]
  ]);
  return buildCert({
    serial: '0a1b2c3d4e5f',
    sigAlg: ALG.ecdsa256,
    issuer: name([[[A.O, utf8('Test, Inc.')]], [[A.CN, utf8('Torture Issuer')]]]),
    notBefore: utc('991231235959Z'),
    notAfter: utc('491231235959Z'),
    subject,
    spki: spkiOf(publicKey),
    extensions: [ext('2.5.29.19', seq())],
    signer: signWith(privateKey, 'sha256')
  });
}

const DN_ATTR_OIDS = [
  '2.5.4.3', '2.5.4.4', '2.5.4.5', '2.5.4.6', '2.5.4.7', '2.5.4.8', '2.5.4.9', '2.5.4.10', '2.5.4.11', '2.5.4.12',
  '2.5.4.13', '2.5.4.14', '2.5.4.15', '2.5.4.16', '2.5.4.17', '2.5.4.18', '2.5.4.19', '2.5.4.20', '2.5.4.21',
  '2.5.4.22', '2.5.4.23', '2.5.4.24', '2.5.4.25', '2.5.4.26', '2.5.4.27', '2.5.4.28', '2.5.4.29', '2.5.4.30',
  '2.5.4.31', '2.5.4.32', '2.5.4.33', '2.5.4.34', '2.5.4.35', '2.5.4.36', '2.5.4.37', '2.5.4.38', '2.5.4.39',
  '2.5.4.40', '2.5.4.41', '2.5.4.42', '2.5.4.43', '2.5.4.44', '2.5.4.45', '2.5.4.46', '2.5.4.47', '2.5.4.48',
  '2.5.4.49', '2.5.4.50', '2.5.4.51', '2.5.4.52', '2.5.4.53', '2.5.4.54', '2.5.4.65', '2.5.4.72', '2.5.4.97',
  '2.5.4.98', '2.5.4.99', '2.5.4.100', '1.2.840.113549.1.9.1', '1.2.840.113549.1.9.2', '1.2.840.113549.1.9.8',
  '0.9.2342.19200300.100.1.1', '0.9.2342.19200300.100.1.3', '0.9.2342.19200300.100.1.25',
  '1.3.6.1.4.1.311.60.2.1.1', '1.3.6.1.4.1.311.60.2.1.2', '1.3.6.1.4.1.311.60.2.1.3',
  '1.3.6.1.5.5.7.9.1', '1.3.6.1.5.5.7.9.2', '1.3.6.1.5.5.7.9.3', '1.3.6.1.5.5.7.9.4', '1.3.6.1.5.5.7.9.5'
];

function craftDnAttrs() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return buildCert({
    serial: '01',
    sigAlg: ALG.ecdsa256,
    issuer: name([[[A.CN, utf8('DN Attribute Table')]]]),
    notBefore: utc('250101000000Z'),
    notAfter: utc('350101000000Z'),
    subject: name(DN_ATTR_OIDS.map((o, i) => [[o, utf8(`v${i}`)]])),
    spki: spkiOf(publicKey),
    signer: signWith(privateKey, 'sha256')
  });
}

function sctList(count) {
  const scts = [];
  for (let i = 0; i < count; i++) {
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(1735689600000n + BigInt(i) * 1000n);
    const sig = Buffer.concat([Buffer.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])]);
    const sct = Buffer.concat([
      Buffer.from([0]), // v1
      Buffer.alloc(32, 0x11 * (i + 1)), // log id
      ts,
      Buffer.from([0, 0]), // no extensions
      Buffer.from([4, 3]), // sha256 / ecdsa
      Buffer.from([0, sig.length]),
      sig
    ]);
    scts.push(Buffer.concat([Buffer.from([sct.length >> 8, sct.length & 0xff]), sct]));
  }
  const body = Buffer.concat(scts);
  return Buffer.concat([Buffer.from([body.length >> 8, body.length & 0xff]), body]);
}

function craftExtTorture() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const ip = (s) => ctx(7, false, s.includes(':') ? ipv6Bytes(s) : Buffer.from(s.split('.').map(Number)));
  const uri = (s) => ctx(6, false, Buffer.from(s, 'latin1'));
  const dirName = name([[[A.O, utf8('Dir Org')]], [[A.CN, utf8('dir name')]]]);
  const san = seq(
    ctx(2, false, Buffer.from('Mixed.Case.Example.COM.')),
    ctx(2, false, Buffer.from('*.wild.example.com')),
    ctx(2, false, Buffer.from('dup.example.com')),
    ctx(2, false, Buffer.from('DUP.example.com')),
    ctx(1, false, Buffer.from('a@example.com')),
    uri('https://example.com/path?q=1'),
    ip('192.0.2.1'),
    ip('2001:db8:0:0:1:0:0:1'),
    ip('0:0:0:0:0:0:0:1'),
    ip('0:0:0:0:0:0:0:0'),
    ip('fe80:0:0:0:0:0:1:2'),
    ip('2001:db8:0:1:1:1:1:1'),
    ip('2001:0:0:1:0:0:0:1'),
    ip('2001:db8:0:0:1:0:0:0'),
    ip('2001:0:0:1:0:0:1:1'),
    ip('0:0:0:0:0:ffff:c000:280'),
    ctx(4, true, dirName),
    ctx(0, true, oid('1.3.6.1.4.1.311.20.2.3'), ctx(0, true, utf8('user@corp.example'))),
    ctx(8, false, oid('1.2.3.4').subarray(2))
  );
  const ski = Buffer.from('00112233445566778899aabbccddeeff00112233', 'hex');
  const aki = seq(ctx(0, false, Buffer.from('a1b2c3d4e5f60718293a4b5c6d7e8f9001122334', 'hex')), ctx(1, true, ctx(4, true, dirName)), ctx(2, false, Buffer.from([0x05])));
  const aia = seq(
    seq(oid('1.3.6.1.5.5.7.48.1'), uri('http://ocsp.example.com')),
    seq(oid('1.3.6.1.5.5.7.48.1'), uri('http://ocsp2.example.com')),
    seq(oid('1.3.6.1.5.5.7.48.2'), uri('http://ca.example.com/ca.crt')),
    seq(oid('1.3.6.1.5.5.7.48.2'), ctx(4, true, dirName))
  );
  const crlDp = seq(
    seq(ctx(0, true, ctx(0, true, uri('http://crl.example.com/a.crl'), uri('ldap://ldap.example.com/cn=crl')))),
    seq(ctx(0, true, ctx(1, true, seq(oid(A.CN), utf8('relative'))))),
    seq(ctx(0, true, ctx(0, true, uri('http://crl2.example.com/b.crl'))), ctx(1, false, Buffer.from([0x06, 0x40])))
  );
  const policies = seq(
    seq(oid('2.23.140.1.2.2')),
    seq(oid('1.3.6.1.4.1.44947.1.1.1'), seq(seq(oid('1.3.6.1.5.5.7.2.1'), ia5('https://cps.example.com'))))
  );
  const eku = seq(...['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.3', '1.3.6.1.5.5.7.3.4',
    '1.3.6.1.5.5.7.3.8', '1.3.6.1.5.5.7.3.9', '2.5.29.37.0', '1.2.3.4.5.6.7'].map(oid));
  return buildCert({
    serial: 'c0ffee00112233445566778899aabbccddeeff01',
    sigAlg: ALG.ecdsa256,
    issuer: name([[[A.CN, utf8('Extension Torture')]]]),
    notBefore: utc('250101000000Z'),
    notAfter: gen('20510101123456.789Z'),
    subject: name([[[A.CN, utf8('Extension Torture')]]]),
    spki: spkiOf(publicKey),
    extensions: [
      ext('2.5.29.19', seq(bool(true), tlv(0x02, Buffer.from([0]))), true),
      ext('2.5.29.15', bits(Buffer.from([0xff, 0x80]), 7), true),
      ext('2.5.29.37', eku),
      ext('2.5.29.17', san),
      ext('2.5.29.14', octet(ski)),
      ext('2.5.29.35', aki),
      ext('1.3.6.1.5.5.7.1.1', aia),
      ext('2.5.29.31', crlDp),
      ext('2.5.29.32', policies),
      ext('1.3.6.1.4.1.11129.2.4.3', nul(), true),
      ext('1.3.6.1.4.1.11129.2.4.2', octet(sctList(3))),
      ext('1.3.6.1.5.5.7.1.24', seq(tlv(0x02, Buffer.from([5])))),
      ext('1.2.3.4.5.6.7.8', utf8('custom'))
    ],
    signer: signWith(privateKey, 'sha256')
  });
}

function ipv6Bytes(s) {
  const out = Buffer.alloc(16);
  s.split(':').forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return out;
}

function craftKeyCert(kind) {
  const rsaHelper = () => generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  const base = {
    serial: randomBytes(8).toString('hex'),
    notBefore: utc('250101000000Z'),
    notAfter: utc('350101000000Z')
  };
  const self = (cn, keyPair, sigAlg, hash) => buildCert({
    ...base, sigAlg, issuer: name([[[A.CN, utf8(cn)]]]), subject: name([[[A.CN, utf8(cn)]]]),
    spki: spkiOf(keyPair.publicKey), signer: signWith(keyPair.privateKey, hash)
  });
  switch (kind) {
    case 'p384': return self('p384.example.com', generateKeyPairSync('ec', { namedCurve: 'P-384' }), ALG.ecdsa384, 'sha384');
    case 'p521': return self('p521.example.com', generateKeyPairSync('ec', { namedCurve: 'P-521' }), ALG.ecdsa512, 'sha512');
    case 'secp256k1': return self('k1.example.com', generateKeyPairSync('ec', { namedCurve: 'secp256k1' }), ALG.ecdsa256, 'sha256');
    case 'brainpool': return self('bp.example.com', generateKeyPairSync('ec', { namedCurve: 'brainpoolP256r1' }), ALG.ecdsa256, 'sha256');
    case 'ed25519': return self('ed25519.example.com', generateKeyPairSync('ed25519'), ALG.ed25519, null);
    case 'ed448': return self('ed448.example.com', generateKeyPairSync('ed448'), ALG.ed448, null);
    case 'dsa': return self('dsa.example.com', generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 }), ALG.dsa256, 'sha256');
    case 'rsapss': {
      const pss = generateKeyPairSync('rsa-pss', { modulusLength: 3072 });
      return buildCert({
        ...base, sigAlg: ALG.sha256Rsa, issuer: name([[[A.CN, utf8('Helper RSA')]]]), subject: name([[[A.CN, utf8('pss.example.com')]]]),
        spki: spkiOf(pss.publicKey), signer: signWith(rsaHelper(), 'sha256')
      });
    }
    case 'rsa1025': {
      // Hand-built RSA key with a 1025-bit modulus (not a multiple of 8) and e = 3.
      const modulus = Buffer.concat([Buffer.from([0x01]), randomBytes(128)]);
      modulus[modulus.length - 1] |= 1;
      const spki = seq(seq(oid('1.2.840.113549.1.1.1'), nul()), bits(seq(int(modulus.toString('hex')), int('03'))));
      return buildCert({
        ...base, sigAlg: ALG.sha256Rsa, issuer: name([[[A.CN, utf8('Helper RSA')]]]), subject: name([[[A.CN, utf8('rsa1025.example.com')]]]),
        spki, signer: signWith(rsaHelper(), 'sha256')
      });
    }
    case 'v1': {
      const kp = generateKeyPairSync('rsa', { modulusLength: 2048 });
      return buildCert({
        version: 1, serial: '0123', sigAlg: ALG.sha256Rsa,
        issuer: name([[[A.CN, utf8('Legacy Root')]]]), subject: name([[[A.O, utf8('Only Org')]]]),
        notBefore: utc('980101000000Z'), notAfter: utc('491231235959Z'),
        spki: spkiOf(kp.publicKey), signer: signWith(kp.privateKey, 'sha256')
      });
    }
    case 'emptySubject': {
      const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      return buildCert({
        serial: '00ff', sigAlg: ALG.ecdsa256,
        issuer: name([[[A.CN, utf8('Empty Subject Issuer')]]]), subject: seq(),
        notBefore: gen('20250101000000Z'), notAfter: gen('20300101000000Z'),
        spki: spkiOf(kp.publicKey), issuerUid: Buffer.from('issuer'), subjectUid: Buffer.from('subject'),
        extensions: [ext('2.5.29.17', seq(ctx(2, false, Buffer.from('nosubject.example.com'))), true)],
        signer: signWith(kp.privateKey, 'sha256')
      });
    }
    default: throw new Error(kind);
  }
}

const CRAFTED = {
  'x509_dn_torture.pem': craftDnTorture,
  'x509_dn_attrs.pem': craftDnAttrs,
  'x509_ext_torture.pem': craftExtTorture,
  'x509_ec_p384.pem': () => craftKeyCert('p384'),
  'x509_ec_p521.pem': () => craftKeyCert('p521'),
  'x509_ec_secp256k1.pem': () => craftKeyCert('secp256k1'),
  'x509_ec_brainpool.pem': () => craftKeyCert('brainpool'),
  'x509_ed25519.pem': () => craftKeyCert('ed25519'),
  'x509_ed448.pem': () => craftKeyCert('ed448'),
  'x509_dsa.pem': () => craftKeyCert('dsa'),
  'x509_rsa_pss.pem': () => craftKeyCert('rsapss'),
  'x509_rsa1025.pem': () => craftKeyCert('rsa1025'),
  'x509_v1_legacy.pem': () => craftKeyCert('v1'),
  'x509_empty_subject.pem': () => craftKeyCert('emptySubject')
};

for (const [file, make] of Object.entries(CRAFTED)) {
  if (!FORCE && existsSync(fx(file))) continue;
  writeFileSync(fx(file), pem(make()));
  console.log('crafted', file);
}

// ---------------------------------------------------------------------------
// OpenSSL-derived fixtures (containers, CSR, DER private keys)
// ---------------------------------------------------------------------------
const DERIVED = {
  'chain.p7b': ['crl2pkcs7', '-nocrl', '-certfile', fx('chain.pem'), '-out', fx('chain.p7b')],
  'chain_der.p7b': ['crl2pkcs7', '-nocrl', '-certfile', fx('chain.pem'), '-outform', 'DER', '-out', fx('chain_der.p7b')],
  'test.pfx': ['pkcs12', '-export', '-passout', 'pass:test', '-in', fx('rsa_multi_san.pem'), '-inkey', fx('rsa_multi_san.key'), '-certfile', fx('ca.pem'), '-out', fx('test.pfx')],
  'test.csr': ['req', '-new', '-key', fx('rsa_multi_san.key'), '-subj', '/C=TR/O=Ornek AS/CN=www.example-test.com.tr', '-out', fx('test.csr')],
  'test_csr.der': ['req', '-in', fx('test.csr'), '-outform', 'DER', '-out', fx('test_csr.der')],
  'ec_wildcard.pkcs8.key.der': ['pkcs8', '-topk8', '-nocrypt', '-in', fx('ec_wildcard.key'), '-outform', 'DER', '-out', fx('ec_wildcard.pkcs8.key.der')],
  'ec_wildcard.sec1.key.der': ['ec', '-in', fx('ec_wildcard.key'), '-outform', 'DER', '-out', fx('ec_wildcard.sec1.key.der')],
  'ec_wildcard.enc.key.der': ['pkcs8', '-topk8', '-in', fx('ec_wildcard.key'), '-passout', 'pass:test', '-outform', 'DER', '-out', fx('ec_wildcard.enc.key.der')],
  'cn_only.pkcs1.key.der': ['rsa', '-in', fx('cn_only.key'), '-traditional', '-outform', 'DER', '-out', fx('cn_only.pkcs1.key.der')]
};
for (const [file, args] of Object.entries(DERIVED)) {
  if (!FORCE && existsSync(fx(file))) continue;
  openssl(args);
  console.log('derived', file);
}

if (FORCE || !existsSync(fx('x509_ec_explicit.pem'))) {
  const key = join(TMP, 'explicit.key');
  openssl(['ecparam', '-name', 'prime256v1', '-param_enc', 'explicit', '-genkey', '-noout', '-out', key]);
  openssl(['req', '-x509', '-new', '-key', key, '-subj', '/CN=explicit.example.com', '-days', '3650', '-out', fx('x509_ec_explicit.pem')]);
  console.log('derived x509_ec_explicit.pem');
}

// ---------------------------------------------------------------------------
// Real-world certificates (fetched once; refresh with --fetch-real)
// ---------------------------------------------------------------------------
const REAL = { 'real_github.pem': 'github.com', 'real_cloudflare.pem': 'cloudflare.com', 'real_google.pem': 'google.com' };
if (FETCH_REAL) {
  for (const [file, host] of Object.entries(REAL)) {
    const out = openssl(['s_client', '-connect', `${host}:443`, '-servername', host], { input: '' });
    writeFileSync(fx(file), openssl(['x509'], { input: out }));
    console.log('fetched', file);
  }
  const chain = openssl(['s_client', '-connect', 'google.com:443', '-servername', 'google.com', '-showcerts'], { input: '' });
  writeFileSync(fx('real_google_chain.pem'), `${chain.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g).join('\n')}\n`);
  console.log('fetched real_google_chain.pem');
}

// ---------------------------------------------------------------------------
// Ground truth from OpenSSL
// ---------------------------------------------------------------------------
const EKU_TEXT = {
  'TLS Web Server Authentication': 'serverAuth', 'TLS Web Client Authentication': 'clientAuth',
  'Code Signing': 'codeSigning', 'E-mail Protection': 'emailProtection', 'Time Stamping': 'timeStamping',
  'OCSP Signing': 'OCSPSigning', 'Any Extended Key Usage': 'anyExtendedKeyUsage',
  'IPSec End System': 'ipsecEndSystem', 'IPSec Tunnel': 'ipsecTunnel', 'IPSec User': 'ipsecUser',
  'Microsoft Server Gated Crypto': 'msSGC', 'Netscape Server Gated Crypto': 'nsSGC'
};
const KU_TEXT = {
  'Digital Signature': 'digitalSignature', 'Non Repudiation': 'nonRepudiation', 'Key Encipherment': 'keyEncipherment',
  'Data Encipherment': 'dataEncipherment', 'Key Agreement': 'keyAgreement', 'Certificate Sign': 'keyCertSign',
  'CRL Sign': 'cRLSign', 'Encipher Only': 'encipherOnly', 'Decipher Only': 'decipherOnly'
};
const CURVE_TEXT = { prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521' };

function canonicalIp(text) {
  if (!text.includes(':')) return text;
  const host = new URL(`http://[${text}]/`).hostname.slice(1, -1); // WHATWG URL = RFC 5952 compression
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (mapped) {
    const hi = parseInt(mapped[1], 16);
    const lo = parseInt(mapped[2], 16);
    return `::ffff:${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return host;
}

function extensionSections(text) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => /^ {8}X509v3 extensions:/.test(l));
  const sections = {};
  if (start < 0) return sections;
  let current = null;
  for (const line of lines.slice(start + 1)) {
    if (/^ {0,11}\S/.test(line)) break; // back to the Data / Signature level
    const header = /^ {12}(\S.*?):( critical)?\s*$/.exec(line);
    if (header) {
      current = header[1];
      sections[current] = { critical: !!header[2], body: [] };
    } else if (current && line.trim()) {
      sections[current].body.push(line.trim());
    }
  }
  return sections;
}

function groundTruth(pemText) {
  const run = (args, encoding) => openssl(['x509', ...args], { input: pemText, encoding });
  const field = (out, key) => new RegExp(`^${key}=(.*)$`, 'm').exec(out.replace(/\r/g, ''))[1];
  const iso = (s) => new Date(s.replace(' ', 'T')).toISOString();
  const basics = run(['-noout', '-subject', '-issuer', '-serial', '-startdate', '-enddate', '-dateopt', 'iso_8601', '-nameopt', 'RFC2253']);
  const utf8Names = run(['-noout', '-subject', '-issuer', '-nameopt', 'RFC2253,-esc_msb'], 'buffer').toString('utf8');
  const fp256 = run(['-noout', '-fingerprint', '-sha256']);
  const fp1 = run(['-noout', '-fingerprint', '-sha1']);
  const text = run(['-noout', '-text', '-nameopt', 'RFC2253', '-certopt', 'no_sigdump'], 'buffer').toString('utf8').replace(/\r/g, '');
  const ext = extensionSections(text);
  const body = (k) => (ext[k] ? ext[k].body.join('\n') : null);
  const list = (k) => (body(k) ? body(k).split(/,\s*/).map((s) => s.trim()).filter(Boolean) : []);

  const sanText = body('X509v3 Subject Alternative Name') || '';
  const sanItems = sanText ? sanText.split(/, (?=(?:DNS|IP Address|email|URI|DirName|othername|Registered ID|EdiPartyName|X400Name):)/) : [];
  const san = (prefix) => sanItems.filter((s) => s.startsWith(prefix)).map((s) => s.slice(prefix.length));
  const bc = body('X509v3 Basic Constraints') || '';
  const aki = (body('X509v3 Authority Key Identifier') || '').split('\n')
    .map((l) => /^(?:keyid:)?((?:[0-9A-F]{2}:)*[0-9A-F]{2})$/.exec(l)).find(Boolean);
  const aia = body('Authority Information Access') || '';
  const keyAlg = /Public Key Algorithm: (\S+)/.exec(text)[1];
  const keyBits = /Public-Key: \((\d+) bit\)/.exec(text);
  const nist = /NIST CURVE: (\S+)/.exec(text);
  const asn1Oid = /ASN1 OID: (\S+)/.exec(text);
  return {
    version: Number(/Version: (\d+)/.exec(text)[1]),
    serialHex: field(basics, 'serial').toLowerCase(),
    signatureAlgorithm: /Signature Algorithm: (\S+)/.exec(text)[1],
    subjectDN: field(utf8Names, 'subject'),
    issuerDN: field(utf8Names, 'issuer'),
    subjectDNEscaped: field(basics, 'subject'),
    issuerDNEscaped: field(basics, 'issuer'),
    notBefore: iso(field(basics, 'notBefore')),
    notAfter: iso(field(basics, 'notAfter')),
    sha256: field(fp256, 'sha256 Fingerprint').replace(/:/g, '').toLowerCase(),
    sha1: field(fp1, 'sha1 Fingerprint').replace(/:/g, '').toLowerCase(),
    keyAlgorithmName: keyAlg,
    keyBits: keyBits ? Number(keyBits[1]) : null,
    curve: nist ? nist[1] : asn1Oid ? (CURVE_TEXT[asn1Oid[1]] || asn1Oid[1]) : null,
    dnsNames: san('DNS:'),
    ipAddresses: san('IP Address:').map(canonicalIp),
    emails: san('email:'),
    uris: san('URI:'),
    isCA: /CA:TRUE/.test(bc),
    pathLen: /pathlen:(\d+)/.test(bc) ? Number(/pathlen:(\d+)/.exec(bc)[1]) : null,
    keyUsage: list('X509v3 Key Usage').map((k) => KU_TEXT[k] || k),
    extKeyUsage: list('X509v3 Extended Key Usage').map((k) => EKU_TEXT[k] || k),
    subjectKeyId: body('X509v3 Subject Key Identifier') ? body('X509v3 Subject Key Identifier').replace(/:/g, '').toLowerCase() : null,
    authorityKeyId: aki ? aki[1].replace(/:/g, '').toLowerCase() : null,
    ocspUrls: [...aia.matchAll(/^OCSP - URI:(.+)$/gm)].map((m) => m[1]),
    caIssuersUrls: [...aia.matchAll(/^CA Issuers - URI:(.+)$/gm)].map((m) => m[1]),
    crlUrls: [...(body('X509v3 CRL Distribution Points') || '').matchAll(/^URI:(.+)$/gm)].map((m) => m[1]),
    isPrecertificate: 'CT Precertificate Poison' in ext,
    sctCount: ext['CT Precertificate SCTs'] ? (body('CT Precertificate SCTs').match(/Signed Certificate Timestamp:/g) || []).length : null,
    policies: [...(body('X509v3 Certificate Policies') || '').matchAll(/^Policy: (\S+)$/gm)].map((m) => m[1]),
    mustStaple: /status_request/.test(body('TLS Feature') || '')
  };
}

const CERT_FILES = [
  'ca.pem', 'rsa_multi_san.pem', 'ec_wildcard.pem', 'cn_only.pem', 'many_sans.pem',
  ...Object.keys(CRAFTED), 'x509_ec_explicit.pem', ...Object.keys(REAL)
];
const expected = {};
for (const file of CERT_FILES) expected[file] = groundTruth(readFileSync(fx(file), 'utf8'));
readFileSync(fx('real_google_chain.pem'), 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)
  .forEach((block, i) => { expected[`real_google_chain.pem#${i}`] = groundTruth(`${block}\n`); });

writeFileSync(fx('x509_expected.json'), `${JSON.stringify(expected, null, 2)}\n`);
console.log(`x509_expected.json: ${Object.keys(expected).length} certificates`);
rmSync(TMP, { recursive: true, force: true });
