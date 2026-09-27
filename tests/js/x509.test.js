/**
 * Tests for assets/js/lib/x509.js — no network access.
 *
 * Ground truth:
 * - tests/fixtures/expected.json      (shared fixtures, OpenSSL-derived)
 * - tests/fixtures/x509_expected.json (x509-specific fixtures incl. three real-world
 *   certificates; produced by `openssl x509` via tests/fixtures/gen_x509_fixtures.mjs)
 * Edge cases OpenSSL itself cannot produce are covered by DER crafted below.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { certCovers } from '../../assets/js/lib/domain.js';
import {
  CertificateParseError,
  computeFingerprints,
  escapeDNValue,
  formatDN,
  formatFingerprint,
  parseCertificate,
  parseCertificates,
  pemEncode
} from '../../assets/js/lib/x509.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const read = (file) => readFileSync(join(FIX, file));
const readText = (file) => readFileSync(join(FIX, file), 'utf8');
const EXPECTED = JSON.parse(readText('expected.json'));
const OPENSSL = JSON.parse(readText('x509_expected.json'));
/** Fixed reference time so validity warnings are deterministic. */
const NOW = new Date('2026-01-01T00:00:00Z');

const codes = (result) => result.warnings.map((w) => w.code);
const only = (input, opts = { now: NOW }) => {
  const r = parseCertificates(input, opts);
  assert.equal(r.certificates.length, 1, `expected exactly one certificate, got ${r.certificates.length}: ${JSON.stringify(r.warnings)}`);
  return r.certificates[0];
};
const leafDer = () => only(read('rsa_multi_san.der')).der;

// ---------------------------------------------------------------------------
// Minimal DER builder (for crafting edge cases)
// ---------------------------------------------------------------------------
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
const rawInt = (hex) => tlv(0x02, Buffer.from(hex, 'hex'));
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const latin = (tag, s) => tlv(tag, Buffer.from(s, 'latin1'));
const utc = (s) => latin(0x17, s);
const gen = (s) => latin(0x18, s);
const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0]));
const octet = (b) => tlv(0x04, b);
const bits = (b, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), b]));
const name = (rdns) => seq(...rdns.map((rdn) => set(...rdn.map(([o, v]) => seq(oid(o), v)))));
const cn = (value) => name([[['2.5.4.3', utf8(value)]]]);
const ext = (o, value, critical = false) => seq(oid(o), ...(critical ? [bool(true)] : []), octet(value));
const SHA256_RSA = seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00]));
const SPKI = Buffer.from(only(read('rsa_multi_san.der')).spkiDer);

/** Builds a certificate with a dummy signature (signatures are not verified by the parser). */
function makeCert({
  version = 3, serial = rawInt('01'), issuer = cn('Test Issuer'), subject = cn('test.example.com'),
  notBefore = utc('250101000000Z'), notAfter = utc('350101000000Z'), spki = SPKI, extensions = null, tbsExtra = []
} = {}) {
  const tbs = seq(
    ...(version > 1 ? [ctx(0, true, rawInt(`0${version - 1}`))] : []),
    serial,
    SHA256_RSA,
    issuer,
    seq(notBefore, notAfter),
    subject,
    spki,
    ...tbsExtra,
    ...(extensions ? [ctx(3, true, seq(...extensions))] : [])
  );
  return seq(tbs, SHA256_RSA, bits(Buffer.alloc(16, 0xab)));
}

// ---------------------------------------------------------------------------
// Shared fixtures (expected.json)
// ---------------------------------------------------------------------------
describe('fixtures from expected.json', () => {
  for (const [file, want] of Object.entries(EXPECTED)) {
    test(`${file}: every field matches OpenSSL`, async () => {
      const result = parseCertificates(read(file), { now: NOW });
      assert.deepEqual(result.warnings, []);
      assert.equal(result.certificates.length, 1);
      const cert = result.leaf;
      assert.equal(cert, result.certificates[0]);
      const fp = await computeFingerprints(cert.der);
      const got = {
        subjectCN: cert.subjectCN, subjectDN: cert.subjectDN, issuerCN: cert.issuerCN, issuerDN: cert.issuerDN,
        dnsNames: cert.dnsNames, ipAddresses: cert.ipAddresses, emails: cert.emails, serialHex: cert.serialHex,
        notBefore: cert.notBefore.toISOString(), notAfter: cert.notAfter.toISOString(), sha256: fp.sha256, sha1: fp.sha1,
        keyAlgorithm: cert.keyAlgorithm, keyBits: cert.keyBits, curve: cert.curve, isCA: cert.isCA, selfSigned: cert.selfSigned
      };
      assert.deepEqual(got, want);
      assert.ok(cert.notBefore instanceof Date && cert.notAfter instanceof Date);
    });
  }

  test('rsa_multi_san: remaining contract fields', () => {
    const cert = only(read('rsa_multi_san.pem'));
    assert.equal(cert.version, 3);
    assert.equal(cert.signatureAlgorithm, 'sha256WithRSAEncryption');
    assert.deepEqual(cert.subject, { C: 'TR', O: 'Ornek AS', CN: 'www.example-test.com.tr' });
    assert.deepEqual(cert.issuer, { C: 'TR', O: 'Test CA', CN: 'Subdomain Scanner Test Root CA' });
    assert.deepEqual(cert.uris, []);
    assert.deepEqual(cert.hostnames, [
      'example-test.com.tr', 'www.example-test.com.tr', 'api.example-test.com.tr',
      '*.cdn.example-test.com.tr', 'xn--mnchen-3ya.example-test.com.tr'
    ]);
    assert.equal(cert.pathLen, null);
    assert.deepEqual(cert.keyUsage, ['digitalSignature', 'keyEncipherment']);
    assert.deepEqual(cert.extKeyUsage, ['serverAuth']);
    assert.equal(cert.subjectKeyId, '777a7b3d61140e1343090d9640d10852b93d322d');
    assert.equal(cert.authorityKeyId, '5ef68887857b91fecba907d567a0cd9ff78830e6');
    assert.deepEqual([cert.ocspUrls, cert.caIssuersUrls, cert.crlUrls], [[], [], []]);
    assert.equal(cert.isPrecertificate, false);
    assert.equal(cert.sctCount, null);
    assert.equal(cert.rsaExponent, 65537);
    assert.equal(cert.keyAlgorithmName, 'rsaEncryption');
    assert.deepEqual(cert.sans.map((s) => s.type), ['dns', 'dns', 'dns', 'dns', 'dns', 'ip', 'ip', 'email']);
    assert.deepEqual(cert.extensions.map((e) => [e.name, e.critical]), [
      ['basicConstraints', true], ['keyUsage', true], ['extendedKeyUsage', false],
      ['subjectAltName', false], ['subjectKeyIdentifier', false], ['authorityKeyIdentifier', false]
    ]);
    assert.deepEqual(cert.parseErrors, []);
    assert.ok(cert.der instanceof Uint8Array);
  });

  test('ca.pem: CA flags and key usage; CN with spaces is not a hostname', () => {
    const cert = only(read('ca.pem'));
    assert.equal(cert.isCA, true);
    assert.equal(cert.pathLen, null);
    assert.deepEqual(cert.keyUsage, ['keyCertSign', 'cRLSign']);
    assert.deepEqual(cert.hostnames, []);
    assert.equal(cert.subjectKeyId, cert.authorityKeyId);
  });

  test('cn_only.pem: legacy CN fallback for hostnames', () => {
    const cert = only(read('cn_only.pem'));
    assert.deepEqual(cert.dnsNames, []);
    assert.deepEqual(cert.hostnames, ['legacy.example.org']);
  });

  test('many_sans.pem: long-form DER lengths, 81 SANs, 9-byte serial', () => {
    const cert = only(read('many_sans.pem'));
    assert.equal(cert.dnsNames.length, 81);
    assert.equal(cert.hostnames.length, 81);
    assert.equal(cert.serialHex, '7fffffffffffffff01');
  });
});

// ---------------------------------------------------------------------------
// OpenSSL ground truth for the x509-specific fixtures (incl. real-world certs)
// ---------------------------------------------------------------------------
describe('fixtures from x509_expected.json (openssl x509 output)', () => {
  for (const [key, want] of Object.entries(OPENSSL)) {
    test(`${key} matches openssl`, async () => {
      const [file, index] = key.split('#');
      const { certificates } = parseCertificates(read(file), { now: NOW });
      const cert = certificates[Number(index || 0)];
      assert.ok(cert, 'certificate parsed');
      const fp = await computeFingerprints(cert.der);
      const got = {
        ...cert,
        ...fp,
        notBefore: cert.notBefore.toISOString(),
        notAfter: cert.notAfter.toISOString(),
        subjectDNEscaped: formatDN(cert.subjectRDNs, { escapeNonAscii: true }),
        issuerDNEscaped: formatDN(cert.issuerRDNs, { escapeNonAscii: true })
      };
      for (const [field, value] of Object.entries(want)) {
        if (field === 'keyBits' && value === null) continue; // OpenSSL prints no size for EdDSA keys
        assert.deepEqual(got[field], value, `${key}: ${field}`);
      }
      assert.deepEqual(cert.parseErrors, []);
    });
  }

  const keyCases = {
    'x509_ec_p384.pem': ['EC', 384, 'P-384', 'ecdsa-with-SHA384'],
    'x509_ec_p521.pem': ['EC', 521, 'P-521', 'ecdsa-with-SHA512'],
    'x509_ec_secp256k1.pem': ['EC', 256, 'secp256k1', 'ecdsa-with-SHA256'],
    'x509_ec_brainpool.pem': ['EC', 256, 'brainpoolP256r1', 'ecdsa-with-SHA256'],
    'x509_ec_explicit.pem': ['EC', 256, null, 'ecdsa-with-SHA256'],
    'x509_ed25519.pem': ['Ed25519', 256, null, 'ED25519'],
    'x509_ed448.pem': ['Ed448', 456, null, 'ED448'],
    'x509_dsa.pem': ['DSA', 2048, null, 'dsa_with_SHA256'],
    'x509_rsa_pss.pem': ['RSA', 3072, null, 'sha256WithRSAEncryption'],
    'x509_rsa1025.pem': ['RSA', 1025, null, 'sha256WithRSAEncryption']
  };
  for (const [file, [family, keyBits, curve, sigAlg]] of Object.entries(keyCases)) {
    test(`${file}: key ${family}/${keyBits}/${curve}`, () => {
      const cert = only(read(file));
      assert.deepEqual([cert.keyAlgorithm, cert.keyBits, cert.curve, cert.signatureAlgorithm], [family, keyBits, curve, sigAlg]);
    });
  }

  test('RSA-PSS key and odd-sized RSA modulus details', () => {
    assert.equal(only(read('x509_rsa_pss.pem')).keyAlgorithmName, 'rsassaPss');
    assert.equal(only(read('x509_rsa1025.pem')).rsaExponent, 3);
  });

  test('x509_dn_torture.pem: string types and first-value subject object', () => {
    const cert = only(read('x509_dn_torture.pem'));
    assert.equal(cert.subjectCN, 'multi value'); // first CN in DER order
    assert.equal(cert.subject.ST, 'İstanbul'); // UTF8String
    assert.equal(cert.subject.L, 'Kadıköy'); // BMPString
    assert.equal(cert.subject.O, 'Örnek Bilişim A.Ş.');
    assert.equal(cert.subject.OU, 'Gömlek Ürün é'); // T61String (Latin-1)
    assert.equal(cert.subject.pseudonym, '😀 smile'); // UniversalString
    assert.equal(cert.subject.x121Address, '12345'); // NumericString
    assert.equal(cert.subject.emailAddress, 'ops@example.com');
    assert.equal(cert.subject.DC, 'com');
    assert.equal(cert.subject.initials, '');
    assert.equal(cert.subject.postalAddress, '#30100C064C696E6520310C064C696E652032');
    // The subject object holds decoded text even for unknown OIDs; only the DN string dumps them.
    assert.equal(cert.subject['1.2.3.4.5.6'], 'unknown');
    assert.match(cert.subjectDN, /,1\.2\.3\.4\.5\.6=#0C07756E6B6E6F776E,/);
    assert.equal(cert.issuerCN, 'Torture Issuer');
    assert.equal(cert.issuer.O, 'Test, Inc.');
    assert.deepEqual(cert.hostnames, []); // 'multi value' is not hostname-like
    assert.equal(cert.selfSigned, false);
    assert.equal(cert.isCA, false); // empty basicConstraints
    const multi = cert.subjectRDNs.find((rdn) => rdn.length === 2);
    assert.deepEqual(multi.map((a) => a.shortName).sort(), ['CN', 'OU']);
  });

  test('x509_ext_torture.pem: extension details beyond the openssl comparison', () => {
    const cert = only(read('x509_ext_torture.pem'));
    assert.deepEqual(cert.hostnames, ['mixed.case.example.com', '*.wild.example.com', 'dup.example.com']);
    assert.deepEqual(cert.sans.filter((s) => !['dns', 'ip'].includes(s.type)), [
      { type: 'email', value: 'a@example.com' },
      { type: 'uri', value: 'https://example.com/path?q=1' },
      { type: 'dirName', value: 'CN=dir name,O=Dir Org' },
      { type: 'otherName', value: 'user@corp.example', oid: '1.3.6.1.4.1.311.20.2.3' },
      { type: 'registeredId', value: '1.2.3.4' }
    ]);
    assert.equal(cert.validationLevel, 'OV');
    assert.equal(cert.mustStaple, true);
    assert.equal(cert.notAfter.getUTCMilliseconds(), 789);
    assert.equal(cert.scts.length, 3);
    assert.deepEqual(cert.scts[0], {
      version: 1,
      logId: Buffer.alloc(32, 0x11).toString('base64'),
      timestamp: new Date(1735689600000)
    });
    assert.equal(cert.scts[2].timestamp.getTime(), 1735689602000);
    const unknown = cert.extensions.find((e) => e.oid === '1.2.3.4.5.6.7.8');
    assert.deepEqual(unknown, { oid: '1.2.3.4.5.6.7.8', name: '1.2.3.4.5.6.7.8', critical: false, length: 8 });
    assert.equal(cert.extensions.find((e) => e.name === 'ctPrecertificatePoison').critical, true);
  });

  test('x509_v1_legacy.pem: v1 certificate without extensions or CN', () => {
    const cert = only(read('x509_v1_legacy.pem'));
    assert.equal(cert.version, 1);
    assert.equal(cert.subjectCN, null);
    assert.deepEqual(cert.subject, { O: 'Only Org' });
    assert.deepEqual(cert.hostnames, []);
    assert.deepEqual(cert.extensions, []);
    assert.equal(cert.notBefore.toISOString(), '1998-01-01T00:00:00.000Z'); // UTCTime 98 → 1998
    assert.equal(cert.notAfter.toISOString(), '2049-12-31T23:59:59.000Z'); // UTCTime 49 → 2049
  });

  test('x509_empty_subject.pem: empty subject, unique IDs skipped, SAN hostnames', () => {
    const cert = only(read('x509_empty_subject.pem'));
    assert.equal(cert.subjectDN, '');
    assert.equal(cert.subjectCN, null);
    assert.deepEqual(cert.subject, {});
    assert.deepEqual(cert.hostnames, ['nosubject.example.com']);
    assert.equal(cert.extensions[0].critical, true);
  });

  test('real-world certificates carry CT / AIA / CRL data', () => {
    for (const [file, host] of [['real_github.pem', 'github.com'], ['real_cloudflare.pem', 'cloudflare.com'], ['real_google.pem', 'google.com']]) {
      const cert = only(read(file));
      assert.ok(cert.hostnames.some((h) => h === host || h === `*.${host}`), `${file} covers ${host}`);
      assert.ok(cert.sctCount >= 2, `${file} has embedded SCTs`);
      assert.ok(cert.scts.every((s) => s.version === 1 && s.logId && s.timestamp instanceof Date));
      assert.ok(cert.caIssuersUrls.length >= 1, `${file} has AIA caIssuers`);
      assert.equal(cert.validationLevel, 'DV');
      assert.equal(cert.isCA, false);
      assert.ok(cert.extKeyUsage.includes('serverAuth'));
    }
  });

  test('real_google_chain.pem: leaf, intermediate and root in order', () => {
    const { certificates, leaf } = parseCertificates(read('real_google_chain.pem'), { now: NOW });
    assert.equal(certificates.length, 3);
    assert.equal(leaf, certificates[0]);
    assert.equal(leaf.subjectCN, '*.google.com');
    assert.equal(certificates[0].issuerDN, certificates[1].subjectDN);
    assert.equal(certificates[1].issuerDN, certificates[2].subjectDN);
    assert.equal(certificates[0].authorityKeyId, certificates[1].subjectKeyId);
    // Reversed order still selects the end-entity certificate.
    const reversed = certificates.map((c) => pemEncode(c.der)).reverse().join('\n');
    assert.equal(parseCertificates(reversed, { now: NOW }).leaf.subjectCN, '*.google.com');
  });
});

// ---------------------------------------------------------------------------
// Input formats
// ---------------------------------------------------------------------------
describe('parseCertificates input formats', () => {
  const pemText = readText('rsa_multi_san.pem');
  const body = pemText.replace(/-----[^-]+-----/g, '').trim();

  test('raw DER as Buffer, Uint8Array, ArrayBuffer and DataView', () => {
    const der = read('rsa_multi_san.der');
    const expectedDer = only(pemText).der;
    const u8 = new Uint8Array(der);
    for (const input of [der, u8, u8.buffer.slice(0), new DataView(u8.buffer.slice(0))]) {
      assert.deepEqual(only(input).der, expectedDer);
    }
  });

  test('DER inside a larger buffer (byteOffset view)', () => {
    const der = read('rsa_multi_san.der');
    const big = new Uint8Array(der.length + 20);
    big.set(der, 10);
    assert.equal(only(big.subarray(10, 10 + der.length)).serialHex, 'f1e2d3c4b5a69788');
  });

  test('CRLF PEM, surrounding prose, indentation, e-mail quoting', () => {
    assert.equal(only(read('rsa_multi_san_crlf.pem')).serialHex, 'f1e2d3c4b5a69788');
    assert.equal(only(readText('pasted_with_text.txt')).serialHex, 'f1e2d3c4b5a69788');
    const indented = pemText.split('\n').map((l) => `      ${l}`).join('\n');
    assert.equal(only(`Config:\n${indented}\nend`).serialHex, 'f1e2d3c4b5a69788');
    const quoted = pemText.split('\n').map((l) => `> > ${l}`).join('\r\n');
    assert.equal(only(`On Monday Ali wrote:\r\n${quoted}`).serialHex, 'f1e2d3c4b5a69788');
  });

  test('JSON-escaped PEM, single-line PEM and trailing-dot noise', () => {
    assert.equal(only(JSON.stringify({ cert: pemText })).serialHex, 'f1e2d3c4b5a69788');
    assert.equal(only(pemText.replace(/\n/g, ' ')).serialHex, 'f1e2d3c4b5a69788');
    assert.equal(only(`"${pemText.trim().split('\n').join('",\n"')}"`).serialHex, 'f1e2d3c4b5a69788');
  });

  test('PEM from JSON encoders that escape more than the newline: PHP (\\/) and .NET (\\u002B)', () => {
    const json = JSON.stringify({ certificate: pemText });
    const php = json.replace(/\//g, '\\/');
    const dotnet = json.replace(/\+/g, '\\u002B');
    for (const text of [php, dotnet, php.slice(php.indexOf('-----'), php.lastIndexOf('"'))]) {
      assert.equal(only(text).serialHex, 'f1e2d3c4b5a69788');
    }
    // the same escapes around bare base64 (a JSON field holding the DER)
    const der = JSON.stringify({ der: body.replace(/\s+/g, '') });
    assert.equal(only(der.replace(/\//g, '\\/')).serialHex, 'f1e2d3c4b5a69788');
    assert.equal(only(der.replace(/\+/g, '\\u002B')).serialHex, 'f1e2d3c4b5a69788');
  });

  test('bare base64 (multi-line, single line, URL-safe, unpadded)', () => {
    assert.equal(only(body).serialHex, 'f1e2d3c4b5a69788');
    const single = body.replace(/\s+/g, '');
    assert.equal(only(single).serialHex, 'f1e2d3c4b5a69788');
    assert.equal(only(single.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')).serialHex, 'f1e2d3c4b5a69788');
  });

  test('base64-encoded PEM (Kubernetes tls.crt) and kubectl secret YAML', () => {
    const b64pem = Buffer.from(readText('chain.pem')).toString('base64');
    const r = parseCertificates(b64pem, { now: NOW });
    assert.equal(r.certificates.length, 2);
    assert.equal(r.leaf.subjectCN, 'www.example-test.com.tr');
    const keyPem = readText('with_key.pem').slice(readText('with_key.pem').indexOf('-----BEGIN PRIVATE KEY'));
    const yaml = [
      'apiVersion: v1', 'data:', `  tls.crt: ${b64pem}`, `  tls.key: ${Buffer.from(keyPem).toString('base64')}`,
      'kind: Secret', 'type: kubernetes.io/tls'
    ].join('\n');
    const y = parseCertificates(yaml, { now: NOW });
    assert.equal(y.certificates.length, 2);
    assert.deepEqual(codes(y), ['PRIVATE_KEY_PRESENT']);
  });

  test('text files as bytes: UTF-8 BOM, UTF-16LE (with and without BOM), UTF-16BE', () => {
    const utf8Bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(pemText)]);
    assert.equal(only(utf8Bom).serialHex, 'f1e2d3c4b5a69788');
    const le = Buffer.from(pemText, 'utf16le');
    assert.equal(only(Buffer.concat([Buffer.from([0xff, 0xfe]), le])).serialHex, 'f1e2d3c4b5a69788');
    assert.equal(only(le).serialHex, 'f1e2d3c4b5a69788');
    const be = Buffer.from(pemText, 'utf16le').swap16();
    assert.equal(only(Buffer.concat([Buffer.from([0xfe, 0xff]), be])).serialHex, 'f1e2d3c4b5a69788');
    assert.equal(only(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(readText('pasted_with_text.txt'))])).serialHex, 'f1e2d3c4b5a69788');
  });

  test('DER read as a binary string (latin1) is recovered; UTF-8 mangled DER is reported', () => {
    const der = read('rsa_multi_san.der');
    assert.equal(only(der.toString('latin1')).serialHex, 'f1e2d3c4b5a69788');
    const mangled = parseCertificates(der.toString('utf8'));
    assert.equal(mangled.certificates.length, 0);
    assert.deepEqual(codes(mangled), ['PARSE_ERROR', 'NO_CERTIFICATE']);
    assert.match(mangled.warnings[0].detail, /ArrayBuffer/);
  });

  test('chain.pem and chain_reversed.pem select the rsa_multi_san leaf', () => {
    const chain = parseCertificates(read('chain.pem'), { now: NOW });
    assert.deepEqual(chain.certificates.map((c) => c.subjectCN), ['www.example-test.com.tr', 'Subdomain Scanner Test Root CA']);
    assert.equal(chain.leaf.serialHex, 'f1e2d3c4b5a69788');
    const reversed = parseCertificates(read('chain_reversed.pem'), { now: NOW });
    assert.deepEqual(reversed.certificates.map((c) => c.subjectCN), ['Subdomain Scanner Test Root CA', 'www.example-test.com.tr']);
    assert.equal(reversed.leaf, reversed.certificates[1]);
    assert.deepEqual(reversed.warnings, []);
  });

  test('PKCS#7: PEM "PKCS7", DER .p7b, bare base64 and BER indefinite length', () => {
    for (const input of [read('chain.p7b'), readText('chain.p7b'), read('chain_der.p7b'), read('chain_der.p7b').toString('base64')]) {
      const r = parseCertificates(input, { now: NOW });
      assert.deepEqual(r.warnings, []);
      assert.deepEqual(r.certificates.map((c) => c.serialHex), ['f1e2d3c4b5a69788', '6366088175c49220e335ad54cdbbee952ecf5151']);
      assert.equal(r.leaf.serialHex, 'f1e2d3c4b5a69788');
    }
    // Re-encode the ContentInfo with an indefinite outer length (BER) — still accepted.
    const der = read('chain_der.p7b');
    const headerLen = der[1] & 0x80 ? 2 + (der[1] & 0x7f) : 2;
    const ber = Buffer.concat([Buffer.from([0x30, 0x80]), der.subarray(headerLen), Buffer.from([0, 0])]);
    assert.equal(parseCertificates(ber, { now: NOW }).certificates.length, 2);
    // PKCS#7 content under a CERTIFICATE label is sniffed by structure.
    assert.equal(parseCertificates(pemEncode(der), { now: NOW }).certificates.length, 2);
  });

  test('PKCS#7 without certificates reports NO_CERTIFICATE', () => {
    const empty = seq(oid('1.2.840.113549.1.7.2'), ctx(0, true, seq(rawInt('01'), set(), seq(oid('1.2.840.113549.1.7.1')), set())));
    const r = parseCertificates(empty);
    assert.deepEqual(codes(r), ['NO_CERTIFICATE']);
    assert.match(r.warnings[0].detail, /PKCS#7/);
  });

  test('concatenated DER certificates, trailing padding and exact duplicates', () => {
    const leaf = read('rsa_multi_san.der');
    const ca = only(read('ca.pem')).der;
    const r = parseCertificates(Buffer.concat([leaf, ca, Buffer.from('\r\n\0\0')]), { now: NOW });
    assert.equal(r.certificates.length, 2);
    assert.deepEqual(r.warnings, []);
    const dup = parseCertificates(`${pemText}\n${readText('chain.pem')}\n${pemText}`, { now: NOW });
    assert.equal(dup.certificates.length, 2);
  });

  test('DER followed by garbage keeps the certificate and warns', () => {
    const r = parseCertificates(Buffer.concat([read('rsa_multi_san.der'), Buffer.from([0x30, 0x82, 0xff])]), { now: NOW });
    assert.equal(r.certificates.length, 1);
    assert.deepEqual(codes(r), ['PARSE_ERROR']);
  });

  test('TRUSTED CERTIFICATE (OpenSSL auxiliary trust data) yields the certificate only', () => {
    const aux = seq(seq(oid('1.3.6.1.5.5.7.3.1')));
    const r = parseCertificates(pemEncode(Buffer.concat([read('rsa_multi_san.der'), aux]), 'TRUSTED CERTIFICATE'), { now: NOW });
    assert.equal(r.certificates.length, 1);
    assert.deepEqual(r.warnings, []);
  });

  test('X509 CERTIFICATE label and lower-case labels are accepted', () => {
    assert.equal(only(pemText.replace(/CERTIFICATE/g, 'X509 CERTIFICATE')).serialHex, 'f1e2d3c4b5a69788');
    assert.equal(only(pemText.replace(/CERTIFICATE/g, 'certificate')).serialHex, 'f1e2d3c4b5a69788');
  });

  test('PEM without END line: complete body is accepted, truncated body is reported', () => {
    const noEnd = pemText.replace(/-----END CERTIFICATE-----\s*$/, '');
    assert.equal(only(noEnd).serialHex, 'f1e2d3c4b5a69788');
    const half = pemText.split('\n').slice(0, 12).join('\n');
    const r = parseCertificates(half);
    assert.equal(r.certificates.length, 0);
    assert.deepEqual(codes(r), ['PARSE_ERROR', 'NO_CERTIFICATE']);
    assert.match(r.warnings[0].detail, /without END line/);
  });

  test('corrupted base64 in a CERTIFICATE block', () => {
    const r = parseCertificates(pemText.replace('MIIESzCC', 'MII*zCC'));
    assert.deepEqual(codes(r), ['PARSE_ERROR', 'NO_CERTIFICATE']);
    assert.match(r.warnings[0].detail, /base64/);
  });

  test('multiple problems in one paste are all reported, certificates still returned', () => {
    const text = [readText('test.csr'), readText('with_key.pem'), '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----'].join('\n');
    const r = parseCertificates(text, { now: NOW });
    assert.equal(r.certificates.length, 1);
    assert.deepEqual(codes(r), ['CSR_NOT_CERT', 'PRIVATE_KEY_PRESENT']);
  });
});

// ---------------------------------------------------------------------------
// PKCS#12, CSR, private keys
// ---------------------------------------------------------------------------
describe('non-certificate inputs', () => {
  test('PKCS#12 (.pfx) binary, base64 and BER indefinite length → PKCS12_UNSUPPORTED', () => {
    const pfx = read('test.pfx');
    for (const input of [pfx, pfx.toString('base64'), pemEncode(pfx, 'PKCS12')]) {
      const r = parseCertificates(input);
      assert.deepEqual(r.certificates, []);
      assert.equal(r.leaf, null);
      assert.deepEqual(codes(r), ['PKCS12_UNSUPPORTED', 'NO_CERTIFICATE']);
      assert.match(r.warnings[0].detail, /openssl pkcs12/);
    }
    const headerLen = pfx[1] & 0x80 ? 2 + (pfx[1] & 0x7f) : 2;
    const ber = Buffer.concat([Buffer.from([0x30, 0x80]), pfx.subarray(headerLen), Buffer.from([0, 0])]);
    assert.deepEqual(codes(parseCertificates(ber)), ['PKCS12_UNSUPPORTED', 'NO_CERTIFICATE']);
  });

  test('CSR as PEM, DER and base64 → CSR_NOT_CERT', () => {
    for (const input of [readText('test.csr'), read('test_csr.der'), read('test_csr.der').toString('base64')]) {
      const r = parseCertificates(input);
      assert.deepEqual(r.certificates, []);
      assert.deepEqual(codes(r), ['CSR_NOT_CERT', 'NO_CERTIFICATE']);
    }
    const legacy = readText('test.csr').replace(/CERTIFICATE REQUEST/g, 'NEW CERTIFICATE REQUEST');
    assert.deepEqual(codes(parseCertificates(legacy)), ['CSR_NOT_CERT', 'NO_CERTIFICATE']);
  });

  test('with_key.pem: certificate returned, key reported and never exposed', () => {
    const text = readText('with_key.pem');
    const r = parseCertificates(text, { now: NOW });
    assert.equal(r.certificates.length, 1);
    assert.equal(r.leaf.serialHex, 'f1e2d3c4b5a69788');
    assert.deepEqual(r.warnings, [{ code: 'PRIVATE_KEY_PRESENT', detail: 'PRIVATE KEY' }]);
    const keyBody = text.slice(text.indexOf('-----BEGIN PRIVATE KEY-----')).split('\n').slice(1, 3).join('');
    const serialized = JSON.stringify(r, (k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString('base64') : v));
    assert.ok(!serialized.includes(keyBody.slice(0, 40)), 'private key material must not appear in the result');
    assert.ok(!serialized.includes('BEGIN PRIVATE KEY'));
  });

  test('every PEM private-key label is detected', () => {
    const labels = ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ANY PRIVATE KEY'];
    for (const label of labels) {
      const r = parseCertificates(`${readText('ca.pem')}\n${pemEncode(read('cn_only.pkcs1.key.der'), label)}`, { now: NOW });
      assert.equal(r.certificates.length, 1, label);
      assert.deepEqual(r.warnings, [{ code: 'PRIVATE_KEY_PRESENT', detail: label }]);
    }
    const legacyEncrypted = '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----';
    assert.deepEqual(codes(parseCertificates(legacyEncrypted)), ['PRIVATE_KEY_PRESENT', 'NO_CERTIFICATE']);
    const pgp = '-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxcA\n-----END PGP PRIVATE KEY BLOCK-----';
    assert.deepEqual(codes(parseCertificates(pgp)), ['PRIVATE_KEY_PRESENT', 'NO_CERTIFICATE']);
  });

  test('DER private keys (PKCS#8, encrypted PKCS#8, SEC1, PKCS#1) and base64 thereof', () => {
    for (const file of ['ec_wildcard.pkcs8.key.der', 'ec_wildcard.enc.key.der', 'ec_wildcard.sec1.key.der', 'cn_only.pkcs1.key.der']) {
      for (const input of [read(file), read(file).toString('base64')]) {
        const r = parseCertificates(input);
        assert.deepEqual(r.certificates, [], file);
        assert.deepEqual(codes(r), ['PRIVATE_KEY_PRESENT', 'NO_CERTIFICATE'], file);
      }
    }
  });

  test('PuTTY and RFC 4716 SSH2 key files → PRIVATE_KEY_PRESENT', () => {
    const ppk = 'PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPublic-Lines: 2\nAAAA\n';
    assert.deepEqual(codes(parseCertificates(ppk)), ['PRIVATE_KEY_PRESENT', 'NO_CERTIFICATE']);
    const ssh2 = '---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: "key"\nP2/56wAAA\n---- END SSH2 ENCRYPTED PRIVATE KEY ----\n';
    assert.deepEqual(parseCertificates(ssh2).warnings, [{ code: 'PRIVATE_KEY_PRESENT', detail: 'SSH2 PRIVATE KEY' }, { code: 'NO_CERTIFICATE' }]);
  });

  test('public keys / CRLs only → NO_CERTIFICATE with detail', () => {
    const spki = only(read('ca.pem')).spkiDer;
    const r = parseCertificates(pemEncode(spki, 'PUBLIC KEY'));
    assert.deepEqual(r.warnings, [{ code: 'NO_CERTIFICATE', detail: 'Found only: PUBLIC KEY' }]);
    const der = parseCertificates(spki);
    assert.deepEqual(der.warnings, [{ code: 'NO_CERTIFICATE', detail: 'Found only: PUBLIC KEY' }]);
    const crl = seq(seq(rawInt('01'), SHA256_RSA, cn('CA'), utc('250101000000Z')), SHA256_RSA, bits(Buffer.alloc(4)));
    assert.deepEqual(parseCertificates(crl).warnings, [{ code: 'NO_CERTIFICATE', detail: 'Found only: X509 CRL' }]);
  });
});

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------
describe('malformed input', () => {
  test('empty / junk / wrong types never throw', () => {
    for (const input of ['', '   \n\t', 'hello world', 'aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBjZXJ0', null, undefined, new Uint8Array(0), new ArrayBuffer(0)]) {
      const r = parseCertificates(input);
      assert.deepEqual(r.certificates, []);
      assert.equal(r.leaf, null);
      assert.deepEqual(codes(r), ['NO_CERTIFICATE']);
    }
    for (const input of [42, {}, [], true, () => {}]) {
      const r = parseCertificates(input);
      assert.deepEqual(codes(r), ['PARSE_ERROR', 'NO_CERTIFICATE']);
    }
  });

  test('parseCertificate rejects non-bytes with CertificateParseError', () => {
    for (const input of [null, undefined, 'MII', 42, {}]) {
      assert.throws(() => parseCertificate(input), CertificateParseError);
    }
  });

  test('every truncation of a DER certificate is rejected (and never crashes parseCertificates)', () => {
    const der = read('rsa_multi_san.der');
    for (let n = 0; n < der.length; n++) {
      const prefix = der.subarray(0, n);
      assert.throws(() => parseCertificate(prefix), CertificateParseError, `prefix ${n}`);
      const r = parseCertificates(prefix);
      assert.equal(r.certificates.length, 0);
      assert.equal(r.warnings.at(-1).code, 'NO_CERTIFICATE');
    }
  });

  test('CertificateParseError carries name and offset', () => {
    let caught = null;
    try {
      parseCertificate(read('rsa_multi_san.der').subarray(0, 100));
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof CertificateParseError);
    assert.ok(caught instanceof Error);
    assert.equal(caught.name, 'CertificateParseError');
    assert.equal(caught.offset, 0);
    assert.match(caught.message, /Truncated value/);
  });

  test('trailing data, indefinite length and oversized length fields are rejected', () => {
    const der = read('rsa_multi_san.der');
    assert.throws(() => parseCertificate(Buffer.concat([der, Buffer.from([0])])), /after the certificate/);
    const indefinite = Buffer.concat([Buffer.from([0x30, 0x80]), der.subarray(4), Buffer.from([0, 0])]);
    assert.throws(() => parseCertificate(indefinite), /Indefinite length/);
    assert.deepEqual(codes(parseCertificates(indefinite)), ['PARSE_ERROR', 'NO_CERTIFICATE']);
    assert.throws(() => parseCertificate(Buffer.from([0x30, 0x85, 1, 0, 0, 0, 0])), /Length field too large/);
    assert.throws(() => parseCertificate(Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x30])), /Truncated value/);
    assert.throws(() => parseCertificate(Buffer.from([0x3f])), CertificateParseError);
    assert.throws(() => parseCertificate(Buffer.from([0x1f, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00])), /Tag number too large/);
  });

  test('structural errors in the certificate are rejected', () => {
    const tbsOnly = seq(seq(rawInt('01')));
    assert.throws(() => parseCertificate(tbsOnly), /must contain/);
    assert.throws(() => parseCertificate(seq(seq(), SHA256_RSA, bits(Buffer.alloc(1)))), /Missing serialNumber/);
    assert.throws(() => parseCertificate(makeCert({ serial: tlv(0x02, Buffer.alloc(0)) })), /Empty INTEGER/);
    assert.throws(() => parseCertificate(makeCert({ subject: seq(set()) })), /Empty RelativeDistinguishedName/);
    assert.throws(() => parseCertificate(makeCert({ subject: seq(seq()) })), /RelativeDistinguishedName/);
    assert.throws(() => parseCertificate(makeCert({ tbsExtra: [utf8('surprise')] })), /Unexpected field/);
    assert.throws(() => parseCertificate(makeCert({ serial: utf8('1') })), /Expected INTEGER/);
    // BIT STRING with more than 7 unused bits in the signature
    const good = makeCert();
    const bad = Buffer.from(good);
    bad[bad.length - 17] = 8;
    assert.throws(() => parseCertificate(bad), /unused-bits/);
    // Truncated OBJECT IDENTIFIER (continuation bit on the last byte)
    assert.throws(() => parseCertificate(makeCert({ subject: seq(set(seq(tlv(0x06, Buffer.from([0x55, 0x84])), utf8('x')))) })), /Truncated OBJECT IDENTIFIER/);
  });

  test('BER bomb (deeply nested indefinite lengths) is handled without crashing', () => {
    const depth = 20000;
    const nest = Buffer.alloc(depth * 2).fill(Buffer.from([0x30, 0x80]));
    // Starts like binary DER (control bytes), so the container sniffer walks into it.
    const binary = Buffer.concat([Buffer.from([0x30, 0x80, 0x02, 0x01, 0x00]), nest, Buffer.alloc(depth * 2 + 2)]);
    const r = parseCertificates(binary);
    assert.deepEqual(r.certificates, []);
    assert.deepEqual(codes(r), ['PARSE_ERROR', 'NO_CERTIFICATE']);
    assert.match(r.warnings[0].detail, /too deep/);
    const textish = parseCertificates(Buffer.concat([nest, Buffer.alloc(depth * 2)]));
    assert.equal(textish.warnings.at(-1).code, 'NO_CERTIFICATE');
  });

  test('fuzz: mutated certificates only ever raise CertificateParseError', () => {
    let seed = 0x5eed1234;
    const rand = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const sources = ['rsa_multi_san.der', 'x509_ext_torture.pem', 'x509_dn_torture.pem', 'real_google.pem', 'chain_der.p7b', 'test.pfx']
      .map((f) => (f.endsWith('.pem') ? only(read(f)).der : new Uint8Array(read(f))));
    let parsed = 0;
    for (let i = 0; i < 3000; i++) {
      const src = sources[i % sources.length];
      const buf = Uint8Array.from(src);
      const mutations = 1 + Math.floor(rand() * 4);
      for (let m = 0; m < mutations; m++) buf[Math.floor(rand() * buf.length)] = Math.floor(rand() * 256);
      const input = rand() < 0.2 ? buf.subarray(0, Math.floor(rand() * buf.length)) : buf;
      try {
        parseCertificate(input);
        parsed++;
      } catch (err) {
        assert.ok(err instanceof CertificateParseError, `iteration ${i}: ${err && err.name}: ${err && err.message}`);
      }
      const r = parseCertificates(input);
      assert.ok(Array.isArray(r.certificates) && Array.isArray(r.warnings));
    }
    assert.ok(parsed > 0, 'some mutations still parse (e.g. inside signature bytes)');
  });

  test('fuzz: random bytes and random text', () => {
    let x = 42;
    const next = () => (x = (x * 1103515245 + 12345) & 0x7fffffff);
    for (let i = 0; i < 500; i++) {
      const len = next() % 300;
      const bytes = Uint8Array.from({ length: len }, () => next() & 0xff);
      if (i % 3 === 0 && len) bytes[0] = 0x30;
      assert.doesNotThrow(() => parseCertificates(bytes));
      assert.doesNotThrow(() => parseCertificates(String.fromCharCode(...bytes)));
      assert.doesNotThrow(() => parseCertificates(`-----BEGIN CERTIFICATE-----\n${Buffer.from(bytes).toString('base64')}\n-----END CERTIFICATE-----`));
    }
  });
});

// ---------------------------------------------------------------------------
// DER primitives (via crafted certificates)
// ---------------------------------------------------------------------------
describe('DER primitives', () => {
  const at = (notBefore, notAfter = utc('350101000000Z')) => parseCertificate(makeCert({ notBefore, notAfter }));

  test('UTCTime pivot: YY < 50 → 20YY, YY ≥ 50 → 19YY', () => {
    assert.equal(at(utc('491231235959Z')).notBefore.toISOString(), '2049-12-31T23:59:59.000Z');
    assert.equal(at(utc('500101000000Z')).notBefore.toISOString(), '1950-01-01T00:00:00.000Z');
    assert.equal(at(utc('000229120000Z')).notBefore.toISOString(), '2000-02-29T12:00:00.000Z');
  });

  test('GeneralizedTime: fractional seconds, offsets, lenient forms', () => {
    assert.equal(at(gen('20250101000000Z'), gen('20510101000000.5Z')).notAfter.toISOString(), '2051-01-01T00:00:00.500Z');
    assert.equal(at(gen('20250101000000,25Z')).notBefore.getUTCMilliseconds(), 250);
    assert.equal(at(gen('20250101000000.123456Z')).notBefore.getUTCMilliseconds(), 123);
    assert.equal(at(gen('20250101030000+0300')).notBefore.toISOString(), '2025-01-01T00:00:00.000Z');
    assert.equal(at(gen('20241231220000-0200')).notBefore.toISOString(), '2025-01-01T00:00:00.000Z');
    assert.equal(at(gen('202501011230Z')).notBefore.toISOString(), '2025-01-01T12:30:00.000Z');
    assert.equal(at(gen('20250101000000')).notBefore.toISOString(), '2025-01-01T00:00:00.000Z');
    assert.equal(at(gen('99991231235959Z')).notBefore.getUTCFullYear(), 9999);
    assert.equal(at(utc('2501010000Z')).notBefore.toISOString(), '2025-01-01T00:00:00.000Z');
    assert.equal(at(gen('20240229000000Z')).notBefore.getUTCDate(), 29);
  });

  test('invalid times are rejected', () => {
    for (const bad of [utc('251301000000Z'), utc('250230000000Z'), utc('250101240000Z'), utc('2501010000'), gen('20230229000000Z'),
      gen('2025-01-01T00:00:00Z'), gen('20250101000000+2500'), latin(0x13, '250101000000Z'), utc('')]) {
      assert.throws(() => at(bad), CertificateParseError);
    }
  });

  test('serial numbers: sign byte stripped, zero, negative, long', () => {
    const serial = (hex) => parseCertificate(makeCert({ serial: rawInt(hex) })).serialHex;
    assert.equal(serial('00ff'), 'ff');
    assert.equal(serial('00'), '00');
    assert.equal(serial('8001'), '8001'); // negative (non-conforming) serial: raw octets
    assert.equal(serial('0000000001'), '01');
    assert.equal(serial('7f'.repeat(20)), '7f'.repeat(20));
    assert.equal(serial('00C0FFEE'), 'c0ffee');
  });

  test('versions: v1 (absent), v2 and v3', () => {
    assert.equal(parseCertificate(makeCert({ version: 1 })).version, 1);
    assert.equal(parseCertificate(makeCert({ version: 2 })).version, 2);
    assert.equal(parseCertificate(makeCert({ version: 3 })).version, 3);
  });

  test('string types: Visible, General, Videotex, Graphic, BMP (odd), Universal, OCTET STRING', () => {
    const subject = name([
      [['2.5.4.3', latin(0x1a, 'visible.example.com')]],
      [['2.5.4.10', latin(0x1b, 'general')]],
      [['2.5.4.11', latin(0x15, 'videotex')]],
      [['2.5.4.7', latin(0x19, 'graphic')]],
      [['2.5.4.8', tlv(0x1e, Buffer.from([0x00, 0x41, 0x00]))]],
      [['2.5.4.12', tlv(0x1c, Buffer.from([0, 0, 0, 0x41, 0x00, 0x11, 0x00, 0x00]))]],
      [['2.5.4.13', octet(Buffer.from([1, 2]))]]
    ]);
    const cert = parseCertificate(makeCert({ subject }));
    assert.equal(cert.subjectCN, 'visible.example.com');
    assert.deepEqual(cert.hostnames, ['visible.example.com']);
    assert.equal(cert.subject.O, 'general');
    assert.equal(cert.subject.ST, 'A\uFFFD');
    assert.equal(cert.subject.title, 'A\uFFFD');
    assert.equal(cert.subject.description, '#04020102');
    // VisibleString is printed as text; the other non-DirectoryString types are dumped like OpenSSL.
    assert.equal(cert.subjectDN, 'description=#04020102,title=A\uFFFD,ST=A\uFFFD,L=#190767726170686963,'
      + 'OU=#1508766964656F746578,O=#1B0767656E6572616C,CN=visible.example.com');
  });

  test('huge OID arcs (2.25.<uuid>) decode exactly', () => {
    const big = '2.25.329800735698586629295641978511506172918';
    const cert = parseCertificate(makeCert({ subject: name([[[big, utf8('x')]]]) }));
    assert.equal(cert.subjectRDNs[0][0].oid, big);
    assert.equal(cert.subjectDN, `${big}=#0C0178`);
    assert.equal(cert.subject[big], 'x');
  });

  test('cert.der is an independent copy of the input', () => {
    const der = Uint8Array.from(read('rsa_multi_san.der'));
    const cert = parseCertificate(der);
    der.fill(0);
    assert.equal(cert.der[0], 0x30);
    assert.equal(cert.serialHex, 'f1e2d3c4b5a69788');
  });
});

// ---------------------------------------------------------------------------
// Extensions (crafted)
// ---------------------------------------------------------------------------
describe('extensions', () => {
  const withExt = (...extensions) => parseCertificate(makeCert({ extensions }));
  const san = (...names) => ext('2.5.29.17', seq(...names));

  test('iPAddress formatting (RFC 5952) and invalid lengths', () => {
    const ip = (hex) => ctx(7, false, Buffer.from(hex, 'hex'));
    const cert = withExt(san(
      ip('7f000001'),
      ip('20010db8000000000000000000000001'),
      ip('00000000000000000000ffffc0a80001'),
      ip('00000000000000000000000001020304'),
      ip('20010db8000000010000000000000000'),
      ip('fe800000000000000000000000000000'),
      ip('0a000000ff000000') // address + mask: not valid in a SAN
    ));
    assert.deepEqual(cert.ipAddresses, ['127.0.0.1', '2001:db8::1', '::ffff:192.168.0.1', '::102:304', '2001:db8:0:1::', 'fe80::']);
    assert.deepEqual(cert.sans.at(-1), { type: 'ip', value: '#0a000000ff000000' });
  });

  test('hostnames: lowercase, trailing dot, dedupe, IDN → punycode, CN fallback rules', () => {
    // dNSName is an IA5String; a non-conforming Latin-1 byte is decoded as-is and punycoded in hostnames.
    const dns = (s) => ctx(2, false, Buffer.from(s, 'latin1'));
    const cert = withExt(san(dns('WWW.Example.COM.'), dns('www.example.com'), dns('münchen.example'), dns('*.Wild.Example.com')));
    assert.deepEqual(cert.dnsNames, ['WWW.Example.COM.', 'www.example.com', 'münchen.example', '*.Wild.Example.com']);
    assert.deepEqual(cert.hostnames, ['www.example.com', 'xn--mnchen-3ya.example', '*.wild.example.com']);
    const fallback = (value) => parseCertificate(makeCert({ subject: cn(value) })).hostnames;
    assert.deepEqual(fallback('Legacy.Example.ORG.'), ['legacy.example.org']);
    assert.deepEqual(fallback('*.example.org'), ['*.example.org']);
    assert.deepEqual(fallback('münchen.example'), ['xn--mnchen-3ya.example']);
    assert.deepEqual(fallback('_dmarc.example.org'), ['_dmarc.example.org']);
    for (const notHost of ['localhost', '10.0.0.1', 'Example Corp', 'a..b.com', '-bad.example.com', '*', '*.com', `${'a'.repeat(64)}.com`]) {
      assert.deepEqual(fallback(notHost), [], notHost);
    }
    // A non-ASCII name is converted only when it is made of label characters: the URL parser would read
    // '@', ':', '/', '\', '?' or '#' as a user name, port or path and keep only part of it.
    for (const name of ['ä@victim.example', 'ä:1@victim.example', 'victim.example/ä', 'victim.example\\ä', 'victim.example?ä', 'victim.example#ä']) {
      const hostnames = withExt(san(dns(name))).hostnames;
      assert.ok(!hostnames.includes('victim.example'), `${name} → ${hostnames}`);
      assert.equal(certCovers(hostnames, 'victim.example').covered, false, name);
      assert.deepEqual(fallback(name), [], `CN ${name}`);
    }
    // …and only into A-labels: the IDNA mapping would turn a soft hyphen, full-width letters or '。' into
    // another ASCII name, which no TLS client matches against this one.
    const softHyphen = withExt(san(dns('Vic­tim.example'))).hostnames;
    assert.deepEqual(softHyphen, ['vic­tim.example']);
    assert.equal(certCovers(softHyphen, 'victim.example').covered, false);
    for (const name of ['vic­tim.example', 'ｖｉｃｔｉｍ.example', 'victim。example']) {
      assert.deepEqual(fallback(name), [], `CN ${name}`);
    }
    // a label the mapping changes but keeps non-ASCII would become another IDN name
    const shy = withExt(san(dns('m\u00fc\u00adnchen.example'))).hostnames; // dns() writes Latin-1 bytes
    assert.deepEqual(shy, ['m\u00fc\u00adnchen.example']);
    assert.equal(certCovers(shy, 'xn--mnchen-3ya.example').covered, false);
    for (const name of ['ｍüｎｃｈｅｎ.example', 'm\u00fc\u00adnchen.example', '\u00e4\u200bvictim.example']) {
      assert.deepEqual(fallback(name), [], `CN ${name}`);
    }
    assert.deepEqual(withExt(san(dns('*.MÜNCHEN.example.'))).hostnames, ['*.xn--mnchen-3ya.example']);
    // SAN with only IP addresses → CN fallback still applies (no dnsNames)
    const ipOnly = parseCertificate(makeCert({ subject: cn('ip-only.example.com'), extensions: [san(ctx(7, false, Buffer.from([1, 2, 3, 4])))] }));
    assert.deepEqual(ipOnly.hostnames, ['ip-only.example.com']);
  });

  test('basicConstraints variants', () => {
    assert.deepEqual(pick(withExt(ext('2.5.29.19', seq()))), [false, null]);
    assert.deepEqual(pick(withExt(ext('2.5.29.19', seq(bool(true))))), [true, null]);
    assert.deepEqual(pick(withExt(ext('2.5.29.19', seq(bool(true), rawInt('03'))))), [true, 3]);
    assert.deepEqual(pick(parseCertificate(makeCert())), [false, null]);
    function pick(c) { return [c.isCA, c.pathLen]; }
  });

  test('keyUsage bit numbering and unused bits', () => {
    const ku = (bytes, unused) => withExt(ext('2.5.29.15', bits(Buffer.from(bytes), unused))).keyUsage;
    assert.deepEqual(ku([0x80], 7), ['digitalSignature']);
    assert.deepEqual(ku([0x06], 1), ['keyCertSign', 'cRLSign']);
    assert.deepEqual(ku([0x00, 0x80], 7), ['decipherOnly']);
    assert.deepEqual(ku([0xff], 1), ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign']);
    assert.deepEqual(ku([], 0), []);
  });

  test('extKeyUsage names and unknown OIDs', () => {
    const eku = withExt(ext('2.5.29.37', seq(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.8'), oid('1.3.6.1.4.1.311.10.3.3'), oid('1.2.3')))).extKeyUsage;
    assert.deepEqual(eku, ['serverAuth', 'timeStamping', 'msSGC', '1.2.3']);
  });

  test('AKI without keyIdentifier, AIA with non-URI locations, CRL DP with relative names', () => {
    const cert = withExt(
      ext('2.5.29.35', seq(ctx(2, false, Buffer.from([1])))),
      ext('1.3.6.1.5.5.7.1.1', seq(seq(oid('1.3.6.1.5.5.7.48.1'), ctx(2, false, Buffer.from('ocsp.example.com'))), seq(oid('1.2.3.4'), ctx(6, false, Buffer.from('http://other'))))),
      ext('2.5.29.31', seq(seq(ctx(0, true, ctx(1, true, seq(oid('2.5.4.3'), utf8('x'))))), seq(ctx(2, true, ctx(4, true, cn('issuer'))))))
    );
    assert.equal(cert.authorityKeyId, null);
    assert.deepEqual(cert.ocspUrls, []);
    assert.deepEqual(cert.caIssuersUrls, []);
    assert.deepEqual(cert.crlUrls, []);
    assert.deepEqual(cert.parseErrors, []);
  });

  test('policies → validation level; EV wins over DV', () => {
    const level = (...oids) => withExt(ext('2.5.29.32', seq(...oids.map((o) => seq(oid(o)))))).validationLevel;
    assert.equal(level('2.23.140.1.2.1'), 'DV');
    assert.equal(level('2.23.140.1.2.3'), 'IV');
    assert.equal(level('2.23.140.1.2.1', '2.23.140.1.1'), 'EV');
    assert.equal(level('1.2.3.4'), null);
  });

  test('SCT list: count, truncated entries, malformed list', () => {
    const sctExt = (payload) => ext('1.3.6.1.4.1.11129.2.4.2', octet(payload));
    const entry = (n) => Buffer.concat([Buffer.from([0, n]), Buffer.alloc(n)]);
    const list = (...entries) => {
      const b = Buffer.concat(entries);
      return Buffer.concat([Buffer.from([b.length >> 8, b.length & 0xff]), b]);
    };
    assert.equal(withExt(sctExt(list(entry(50), entry(50)))).sctCount, 2);
    assert.equal(withExt(sctExt(list())).sctCount, 0);
    const truncated = list(entry(50), entry(50)).subarray(0, 60);
    assert.equal(withExt(sctExt(truncated)).sctCount, 1);
    assert.deepEqual(withExt(sctExt(list(entry(10)))).scts, [{ version: 1, logId: null, timestamp: null }]);
    const broken = withExt(ext('1.3.6.1.4.1.11129.2.4.2', utf8('nope')));
    assert.equal(broken.sctCount, null);
    assert.equal(broken.parseErrors[0].field, 'ctPrecertificateScts');
  });

  test('malformed and duplicate extensions degrade gracefully', () => {
    const cert = parseCertificate(makeCert({
      subject: cn('fallback.example.com'),
      extensions: [
        ext('2.5.29.17', Buffer.from([0x30, 0x05, 0x82, 0x09, 0x61])), // truncated SAN
        ext('2.5.29.15', bits(Buffer.from([0x80]), 7)),
        ext('2.5.29.15', bits(Buffer.from([0x04]), 2)),
        ext('2.5.29.19', seq(rawInt('01'), bool(true))) // wrong order
      ]
    }));
    assert.deepEqual(cert.dnsNames, []);
    assert.deepEqual(cert.hostnames, ['fallback.example.com']);
    assert.deepEqual(cert.keyUsage, ['digitalSignature']);
    assert.equal(cert.isCA, false);
    assert.deepEqual(cert.parseErrors.map((p) => p.field), ['subjectAltName', 'keyUsage', 'basicConstraints']);
    assert.match(cert.parseErrors[1].message, /Duplicate/);
    const r = parseCertificates(pemEncode(cert.der), { now: NOW });
    assert.equal(r.certificates.length, 1);
    assert.deepEqual(codes(r), ['PARSE_ERROR', 'PARSE_ERROR', 'PARSE_ERROR']);
  });

  test('malformed Extension envelope is fatal', () => {
    assert.throws(() => withExt(seq(oid('2.5.29.17'))), /Malformed Extension/);
    assert.throws(() => withExt(seq(oid('2.5.29.17'), utf8('x'), octet(Buffer.alloc(0)))), /BOOLEAN/);
  });

  test('malformed public key does not hide the rest of the certificate', () => {
    const spki = seq(seq(oid('1.2.840.113549.1.1.1'), Buffer.from([0x05, 0x00])), bits(Buffer.from([0x01, 0x02])));
    const cert = parseCertificate(makeCert({ spki }));
    assert.equal(cert.keyAlgorithm, 'RSA');
    assert.equal(cert.keyBits, null);
    assert.equal(cert.parseErrors[0].field, 'subjectPublicKey');
    const unknown = parseCertificate(makeCert({ spki: seq(seq(oid('1.3.101.110')), bits(Buffer.alloc(32))) }));
    assert.deepEqual([unknown.keyAlgorithm, unknown.keyAlgorithmName, unknown.keyBits], ['unknown', 'X25519', null]);
    const dsaNoParams = parseCertificate(makeCert({ spki: seq(seq(oid('1.2.840.10040.4.1')), bits(rawInt('05'))) }));
    assert.deepEqual([dsaNoParams.keyAlgorithm, dsaNoParams.keyBits], ['DSA', null]);
    const ecUnknownCurve = parseCertificate(makeCert({ spki: seq(seq(oid('1.2.840.10045.2.1'), oid('1.2.3.4')), bits(Buffer.concat([Buffer.from([4]), Buffer.alloc(64)]))) }));
    assert.deepEqual([ecUnknownCurve.curve, ecUnknownCurve.keyBits], ['1.2.3.4', 256]);
  });
});

// ---------------------------------------------------------------------------
// Distinguished names
// ---------------------------------------------------------------------------
describe('DN formatting and escaping', () => {
  test('escapeDNValue follows OpenSSL RFC 2253 rules', () => {
    const cases = [
      ['plain', 'plain'],
      ['a,b', 'a\\,b'],
      ['a+b;c', 'a\\+b\\;c'],
      ['<>"\\', '\\<\\>\\"\\\\'],
      ['#lead', '\\#lead'],
      ['mid#dle', 'mid#dle'],
      ['#', '#'], // one-character value: only the "last" rule applies (OpenSSL quirk)
      [' ', '\\ '],
      [' both ', '\\ both\\ '],
      ['in side', 'in side'],
      ['a=b', 'a=b'],
      ['tab\there', 'tab\\09here'],
      ['nul\0', 'nul\\00'],
      ['del\x7f', 'del\\7F'],
      ['', ''],
      ['Örnek A.Ş.', 'Örnek A.Ş.'],
      ['😀', '😀']
    ];
    for (const [input, want] of cases) assert.equal(escapeDNValue(input), want, JSON.stringify(input));
    assert.equal(escapeDNValue('Örnek A.Ş.', { escapeNonAscii: true }), '\\C3\\96rnek A.\\C5\\9E.');
    assert.equal(escapeDNValue('😀 x', { escapeNonAscii: true }), '\\F0\\9F\\98\\80 x');
    assert.equal(escapeDNValue(null), '');
  });

  test('bidi control characters are always escaped', () => {
    assert.equal(escapeDNValue('evil\u202Egpj.exe'), 'evil\\E2\\80\\AEgpj.exe');
    assert.equal(escapeDNValue('a\u200Fb\u2066c'), 'a\\E2\\80\\8Fb\\E2\\81\\A6c');
  });

  test('formatDN: reverse order, multi-valued RDNs, dumps', () => {
    const atv = (oidStr, value, tag = 0x0c, valueDer) => ({ oid: oidStr, value, tag, valueDer });
    const rdns = [
      [atv('2.5.4.6', 'TR', 0x13)],
      [atv('2.5.4.10', 'Ornek, AS')],
      [atv('2.5.4.11', 'ops'), atv('2.5.4.3', 'www.example.com')],
      [atv('1.2.3.4', 'x', 0x0c, Uint8Array.of(0x0c, 0x01, 0x78))],
      [atv('2.5.4.16', '#3000', 0x30, Uint8Array.of(0x30, 0x00))]
    ];
    assert.equal(formatDN(rdns), 'postalAddress=#3000,1.2.3.4=#0C0178,CN=www.example.com+OU=ops,O=Ornek\\, AS,C=TR');
    assert.equal(formatDN([]), '');
    assert.equal(formatDN(null), '');
    assert.equal(formatDN([[atv('2.5.4.3', 'Çağrı')]], { escapeNonAscii: true }), 'CN=\\C3\\87a\\C4\\9Fr\\C4\\B1');
    // Unknown OID without DER falls back to an escaped value; prototype keys are not attribute names.
    assert.equal(formatDN([[{ oid: '1.2.3', value: 'a,b' }]]), '1.2.3=a\\,b');
    assert.equal(formatDN([[{ oid: 'constructor', value: 'v' }]]), 'constructor=v');
  });

  test('subjectDN of parsed certificates uses Unicode; formatDN can reproduce the escaped form', () => {
    const cert = only(read('x509_dn_torture.pem'));
    assert.match(cert.subjectDN, /O=Örnek Bilişim A\.Ş\./);
    assert.match(formatDN(cert.subjectRDNs, { escapeNonAscii: true }), /O=\\C3\\96rnek Bili\\C5\\9Fim A\.\\C5\\9E\./);
    assert.equal(formatDN(cert.issuerRDNs), cert.issuerDN);
  });
});

// ---------------------------------------------------------------------------
// Leaf selection and validity warnings
// ---------------------------------------------------------------------------
describe('leaf selection and validity', () => {
  const pems = (...files) => files.map(readText).join('\n');

  test('non-CA certificate that issues nothing is the leaf', () => {
    assert.equal(parseCertificates(pems('ca.pem', 'rsa_multi_san.pem'), { now: NOW }).leaf.subjectCN, 'www.example-test.com.tr');
    assert.equal(parseCertificates(pems('ca.pem', 'cn_only.pem', 'rsa_multi_san.pem'), { now: NOW }).leaf.subjectCN, 'legacy.example.org');
  });

  test('only CA certificates → first certificate', () => {
    const r = parseCertificates(pems('many_sans.pem', 'ca.pem'), { now: NOW });
    assert.equal(r.leaf, r.certificates[0]);
    assert.equal(r.leaf.subjectCN, 'bulk.example.com');
  });

  test('a non-CA certificate that issued another one is not the leaf', () => {
    // A (non-CA, no basicConstraints) issues B: the leaf is B even though A comes first.
    const a = makeCert({ issuer: cn('Root'), subject: cn('a.example.com') });
    const b = makeCert({ issuer: cn('a.example.com'), subject: cn('b.example.com'), serial: rawInt('02') });
    const r = parseCertificates(Buffer.concat([a, b]), { now: NOW });
    assert.equal(r.leaf.subjectCN, 'b.example.com');
    // Mismatching key identifiers break the issuer relation.
    const ski = (hex) => ext('2.5.29.14', octet(Buffer.from(hex, 'hex')));
    const aki = (hex) => ext('2.5.29.35', seq(ctx(0, false, Buffer.from(hex, 'hex'))));
    const a2 = makeCert({ issuer: cn('Root'), subject: cn('a.example.com'), extensions: [ski('01')] });
    const b2 = makeCert({ issuer: cn('a.example.com'), subject: cn('b.example.com'), serial: rawInt('02'), extensions: [aki('02')] });
    assert.equal(parseCertificates(Buffer.concat([a2, b2]), { now: NOW }).leaf.subjectCN, 'a.example.com');
  });

  test('EXPIRED / NOT_YET_VALID relative to options.now (leaf only)', () => {
    const at = (now) => parseCertificates(read('chain.pem'), { now }).warnings;
    assert.deepEqual(at(NOW), []);
    assert.deepEqual(at(new Date('2034-06-01T00:00:01Z')), [{ code: 'EXPIRED', detail: '2034-06-01T00:00:00.000Z' }]);
    assert.deepEqual(at(new Date('2025-05-31T23:59:59Z')), [{ code: 'NOT_YET_VALID', detail: '2025-06-01T00:00:00.000Z' }]);
    assert.deepEqual(at(Date.parse('2040-01-01T00:00:00Z')), [{ code: 'EXPIRED', detail: '2034-06-01T00:00:00.000Z' }]);
    assert.deepEqual(at('2020-01-01T00:00:00Z'), [{ code: 'NOT_YET_VALID', detail: '2025-06-01T00:00:00.000Z' }]);
    assert.deepEqual(at(new Date('2034-06-01T00:00:00Z')), []); // boundary is inclusive
    assert.doesNotThrow(() => parseCertificates(read('chain.pem'), { now: new Date('invalid') }));
    assert.doesNotThrow(() => parseCertificates(read('chain.pem'), { now: {} }));
    assert.doesNotThrow(() => parseCertificates(read('chain.pem')));
  });
});

// ---------------------------------------------------------------------------
// Fingerprints and formatting helpers
// ---------------------------------------------------------------------------
describe('fingerprints and helpers', () => {
  test('WebCrypto and pure-JS fallback agree with OpenSSL for every fixture', async () => {
    const all = { ...EXPECTED, ...OPENSSL };
    for (const [key, want] of Object.entries(all)) {
      const [file, index] = key.split('#');
      const cert = parseCertificates(read(file), { now: NOW }).certificates[Number(index || 0)];
      const viaSubtle = await computeFingerprints(cert.der);
      const viaJs = await computeFingerprints(cert.der, { subtle: null });
      assert.deepEqual(viaSubtle, { sha256: want.sha256, sha1: want.sha1 }, key);
      assert.deepEqual(viaJs, viaSubtle, key);
    }
  });

  test('pure-JS SHA-256/SHA-1 across padding boundaries', async () => {
    for (const len of [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 1000, 70000]) {
      const data = Uint8Array.from({ length: len }, (_, i) => (i * 31 + 7) & 0xff);
      const js = await computeFingerprints(data, { subtle: null });
      assert.equal(js.sha256, createHash('sha256').update(data).digest('hex'), `sha256 len ${len}`);
      assert.equal(js.sha1, createHash('sha1').update(data).digest('hex'), `sha1 len ${len}`);
    }
  });

  test('accepts ArrayBuffer and Certificate objects; falls back when subtle fails', async () => {
    const cert = only(read('ec_wildcard.pem'));
    const want = { sha256: EXPECTED['ec_wildcard.pem'].sha256, sha1: EXPECTED['ec_wildcard.pem'].sha1 };
    assert.deepEqual(await computeFingerprints(cert.der.slice().buffer), want);
    assert.deepEqual(await computeFingerprints(cert), want);
    const failing = { digest: () => Promise.reject(new Error('insecure context')) };
    assert.deepEqual(await computeFingerprints(cert.der, { subtle: failing }), want);
    await assert.rejects(computeFingerprints('nope'), TypeError);
  });

  test('pemEncode: 64-character lines, round trip, custom label', () => {
    const der = leafDer();
    const pemText = pemEncode(der);
    const lines = pemText.split('\n');
    assert.equal(lines[0], '-----BEGIN CERTIFICATE-----');
    assert.equal(lines.at(-2), '-----END CERTIFICATE-----');
    assert.equal(lines.at(-1), '');
    assert.ok(lines.slice(1, -2).every((l) => l.length > 0 && l.length <= 64));
    assert.equal(pemText, readText('rsa_multi_san.pem').replace(/\r\n/g, '\n'));
    assert.deepEqual(only(pemText).der, der);
    assert.match(pemEncode(der.buffer.slice(der.byteOffset, der.byteOffset + der.length), 'PKCS7'), /^-----BEGIN PKCS7-----\n/);
    assert.equal(pemEncode(new Uint8Array(0)), '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n');
    for (const n of [1, 2, 3, 4]) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => 250 + i);
      assert.ok(pemEncode(bytes).includes(Buffer.from(bytes).toString('base64')));
    }
    assert.throws(() => pemEncode('x'), TypeError);
  });

  test('formatFingerprint', () => {
    assert.equal(formatFingerprint('a0b856a5'), 'A0:B8:56:A5');
    assert.equal(formatFingerprint('A0:b8:56'), 'A0:B8:56');
    assert.equal(formatFingerprint(''), '');
    assert.equal(formatFingerprint(null), '');
    assert.equal(formatFingerprint('abc'), 'AB:C');
    assert.equal(formatFingerprint(EXPECTED['ca.pem'].sha1).length, 59);
  });
});
