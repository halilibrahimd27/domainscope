/**
 * Tests for assets/js/lib/pkcs12.js (PKCS#12 / .pfx) and lib/x509.js loadCertificates() — no
 * network access.
 *
 * Ground truth:
 * - the PKCS#12 KDF: the published vectors OpenSSL tests with (test/recipes/30-test_evp_data/
 *   evpkdf_pkcs12.txt, after Dr Stephen Henson's list), plus longer and SHA-2 cases computed with
 *   `openssl kdf … PKCS12KDF`;
 * - tests/fixtures/p12_*.p12 and p12_expected.json: bundles made by `openssl pkcs12 -export` and
 *   read back with OpenSSL (tests/fixtures/gen_p12_fixtures.mjs): certificate hashes in file order,
 *   MAC and encryption as `openssl pkcs12 -info` prints them, whether the key belongs to the leaf;
 * - damaged, unsupported and BER-encoded bundles are crafted below from those, with node:crypto
 *   for any MAC they need.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PKCS12_ERRORS, Pkcs12Error, bmpPassword, openPkcs12, passwordForms, pkcs12Kdf
} from '../../assets/js/lib/pkcs12.js';
import { loadCertificates, parseCertificates, pemEncode } from '../../assets/js/lib/x509.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const read = (file) => readFileSync(join(FIX, file));
const { passwords: PASSWORDS, bundles: BUNDLES } = JSON.parse(readFileSync(join(FIX, 'p12_expected.json'), 'utf8'));
const PASS = PASSWORDS.test;
const hex = (s) => Uint8Array.from(Buffer.from(s.replace(/[\s:]+/g, ''), 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

/** Resolves to the Pkcs12Error a promise rejects with (fails if it resolves or rejects otherwise). */
async function rejection(promise) {
  try {
    await promise;
  } catch (err) {
    assert.ok(err instanceof Pkcs12Error, `expected a Pkcs12Error, got ${err && err.stack}`);
    return err;
  }
  assert.fail('expected a rejection');
  return null;
}

// ---------------------------------------------------------------------------
// Minimal DER builder (crafted bundles)
// ---------------------------------------------------------------------------
const encLen = (n) => {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
};
const tlv = (tag, ...parts) => {
  const body = Buffer.concat(parts.map((p) => Buffer.from(p)));
  return Buffer.concat([Buffer.from([tag]), encLen(body.length), body]);
};
const seq = (...p) => tlv(0x30, ...p);
const explicit0 = (...p) => tlv(0xa0, ...p);
const octet = (b) => tlv(0x04, b);
const int = (n) => {
  const b = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  if (!b.length || b[0] & 0x80) b.unshift(0);
  return tlv(0x02, Buffer.from(b));
};
const oid = (s) => {
  const arcs = s.split('.').map(Number);
  const out = [];
  const push = (v) => {
    const bytes = [v & 0x7f];
    for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) bytes.unshift((x & 0x7f) | 0x80);
    out.push(...bytes);
  };
  push(arcs[0] * 40 + arcs[1]);
  arcs.slice(2).forEach(push);
  return tlv(0x06, Buffer.from(out));
};
const OIDS = {
  data: '1.2.840.113549.1.7.1', signedData: '1.2.840.113549.1.7.2', envelopedData: '1.2.840.113549.1.7.3',
  encryptedData: '1.2.840.113549.1.7.6', certBag: '1.2.840.113549.1.12.10.1.3', x509: '1.2.840.113549.1.9.22.1',
  sha256: '2.16.840.1.101.3.4.2.1', sha512: '2.16.840.1.101.3.4.2.3', sha224: '2.16.840.1.101.3.4.2.4', rc4: '1.2.840.113549.1.12.1.1',
  pbes2: '1.2.840.113549.1.5.13', pbkdf2: '1.2.840.113549.1.5.12', hmacSha256: '1.2.840.113549.2.9',
  aes256: '2.16.840.1.101.3.4.1.42', keyBag: '1.2.840.113549.1.12.10.1.1', shroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  localKeyId: '1.2.840.113549.1.9.21', pbe3des: '1.2.840.113549.1.12.1.3'
};
const contentInfo = (type, inner) => seq(oid(OIDS[type]), explicit0(inner));
/** bagAttributes with a localKeyId, or nothing. */
const keyIdAttr = (id) => (id ? tlv(0x31, seq(oid(OIDS.localKeyId), tlv(0x31, octet(id)))) : Buffer.alloc(0));
const certBag = (der, keyId = null) => seq(oid(OIDS.certBag), explicit0(seq(oid(OIDS.x509), explicit0(octet(der)))), keyIdAttr(keyId));
const keyBag = (pkcs8, keyId = null) => seq(oid(OIDS.keyBag), explicit0(pkcs8), keyIdAttr(keyId));
/** A pkcs8ShroudedKeyBag: EncryptedPrivateKeyInfo with the given AlgorithmIdentifier. */
const shroudedKeyBag = (alg, ciphertext, keyId = null) => seq(oid(OIDS.shroudedKeyBag), explicit0(seq(alg, octet(ciphertext))), keyIdAttr(keyId));
/** EncryptedData with the given AlgorithmIdentifier and ciphertext. */
const encryptedData = (alg, ciphertext) => contentInfo('encryptedData',
  seq(int(0), seq(oid(OIDS.data), alg, tlv(0x80, ciphertext))));
const pbes2Aes256 = (salt, iv, iterations = 2048) => seq(oid(OIDS.pbes2), seq(
  seq(oid(OIDS.pbkdf2), seq(octet(salt), int(iterations), seq(oid(OIDS.hmacSha256), Buffer.from([5, 0])))),
  seq(oid(OIDS.aes256), octet(iv))));
const pbe3des = (salt, iterations) => seq(oid(OIDS.pbe3des), seq(octet(salt), int(iterations)));

/**
 * A PFX around `authSafe` (the DER of the AuthenticatedSafe). With `password` it gets an
 * HMAC-SHA256 MAC keyed as RFC 7292 says (key from the PKCS#12 KDF, computed here with the
 * module's own KDF — checked against OpenSSL's vectors below — and node:crypto's HMAC).
 */
async function pfx(authSafe, { password = null, digest = OIDS.sha256, iterations = 2048 } = {}) {
  const parts = [int(3), contentInfo('data', octet(authSafe))];
  if (password !== null) {
    const salt = randomBytes(8);
    const key = await pkcs12Kdf({ hash: 'SHA-256', password: bmpPassword(password), salt, id: 3, iterations: Math.min(iterations, 4096), length: 32 });
    const mac = createHmac('sha256', key).update(authSafe).digest();
    parts.push(seq(seq(seq(oid(digest), Buffer.from([5, 0])), octet(mac)), octet(salt), int(iterations)));
  }
  return seq(...parts);
}

/**
 * The same PFX with BER as Windows writes it: indefinite lengths on the outer structures and the
 * AuthenticatedSafe octets split into a constructed OCTET STRING of `chunk`-byte segments (the MAC
 * covers the octets, not their encoding, so it still holds).
 */
function toWindowsBer(der, chunk = 500) {
  const read = (pos) => {
    let p = pos + 1;
    let len = der[p++];
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + der[p++];
    }
    return { offset: pos, start: p, end: p + len };
  };
  const kids = (node) => {
    const out = [];
    for (let p = node.start; p < node.end;) {
      const k = read(p);
      out.push(k);
      p = k.end;
    }
    return out;
  };
  const whole = (node) => der.subarray(node.offset, node.end);
  const indefinite = (tag, ...parts) => Buffer.concat([Buffer.from([tag, 0x80]), ...parts, Buffer.from([0, 0])]);
  const [version, authSafe, mac] = kids(read(0));
  const [ct, wrap] = kids(authSafe);
  const [os] = kids(wrap);
  const data = der.subarray(os.start, os.end);
  const segments = [];
  for (let i = 0; i < data.length; i += chunk) segments.push(octet(data.subarray(i, i + chunk)));
  return indefinite(0x30, whole(version),
    indefinite(0x30, whole(ct), indefinite(0xa0, indefinite(0x24, ...segments))),
    mac ? whole(mac) : Buffer.alloc(0));
}

// ---------------------------------------------------------------------------
// The PKCS#12 KDF (RFC 7292 Appendix B.2)
// ---------------------------------------------------------------------------
describe('pkcs12Kdf', () => {
  const SMEG = bmpPassword('smeg');
  const QUEEG = bmpPassword('queeg');
  // OpenSSL's evpkdf_pkcs12.txt (the classic SHA-1 vectors): password, salt, id, iterations, output.
  const PUBLISHED = [
    [SMEG, '0a58cf64530d823f', 1, 1, '8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3'],
    [SMEG, '0a58cf64530d823f', 2, 1, '79993dfe048d3b76'],
    [SMEG, '642b99ab44fb4b1f', 1, 1, 'f3a95fec48d7711e985cfe67908c5ab79fa3d7c5caa5d966'],
    [SMEG, '642b99ab44fb4b1f', 2, 1, 'c0a38d64a79bea1d'],
    [SMEG, '3d83c0e4546ac140', 3, 1, '8d967d88f6caa9d714800ab3d48051d63f73a312'],
    [QUEEG, '05dec959acff72f7', 1, 1000, 'ed2034e36328830ff09df1e1a07dd357185dac0d4f9eb3d4'],
    [QUEEG, '05dec959acff72f7', 2, 1000, '11dedad7758d4860']
  ];
  for (const [password, salt, id, iterations, out] of PUBLISHED) {
    test(`SHA-1, id ${id}, ${iterations} iteration(s), salt ${salt}`, async () => {
      const got = await pkcs12Kdf({ hash: 'SHA-1', password, salt: hex(salt), id, iterations, length: out.length / 2 });
      assert.equal(toHex(got), out);
    });
  }

  test('bmpPassword: UTF-16BE code units (a surrogate pair outside the BMP) and a zero terminator', () => {
    assert.equal(toHex(bmpPassword('smeg')), '0073006d006500670000');
    assert.equal(toHex(bmpPassword('')), '0000');
    assert.equal(toHex(bmpPassword('Ş🔑')), '015ed83ddd110000');
  });

  // Computed with `openssl kdf -kdfopt digest:… -kdfopt hexpass:… … PKCS12KDF`.
  test('SHA-256: a two-block password, a 40-byte salt and four output blocks (the I_j carry)', async () => {
    const got = await pkcs12Kdf({
      hash: 'SHA-256', password: bmpPassword('Parola-with-40-characters-to-span-blocks'),
      salt: hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627'), id: 1, iterations: 3, length: 100
    });
    assert.equal(toHex(got), '1e01d62239b4dfd7c392f93281ba6598648e2f8b4775a133636e3c1c5ab20eba66e142501792ddd5efb8f08b0ed757b7dc9c3ab4860f6e48592f3300364e15f8d143b63b94117f5c63464f635840199c2759d2ed822ae19c931ccbde0947ddb56b813eb6');
  });

  test('SHA-512 and SHA-384 (WebCrypto digests: v = 128)', async () => {
    const s512 = await pkcs12Kdf({ hash: 'SHA-512', password: bmpPassword('pfx'), salt: hex('a1b2c3d4e5f60718'), id: 3, iterations: 5, length: 64 });
    assert.equal(toHex(s512), '94b4c39b711374c5ed892db6f4a6b05fc98c2f484d6b13e7f39ed55e911d72a69563726a89818c81f6636efceb04776b9a808daf58dd30c2ef211bdf582ba2e2');
    const s384 = await pkcs12Kdf({ hash: 'SHA-384', password: bmpPassword(''), salt: hex('0011223344556677'), id: 3, iterations: 2, length: 48 });
    assert.equal(toHex(s384), '47fab1787a81b1286efe8b031fc711ebb298c993b3d4d02548e8a803fc429079cb5d957e72e3435fb390dbedd042b331');
  });

  test('an empty password (no bytes at all) leaves P empty', async () => {
    const got = await pkcs12Kdf({ hash: 'SHA-1', password: new Uint8Array(0), salt: hex('0011223344556677'), id: 1, iterations: 2048, length: 24 });
    assert.equal(toHex(got), '4cd8c9c3cee600937f61a0fcae8787b7b35b89403141da97');
  });

  test('passwordForms: the empty password twice, a non-ASCII one also as OpenSSL 1.0.x read it', () => {
    assert.deepEqual(passwordForms('').map((f) => [f.encoding, toHex(f.bmp), toHex(f.utf8)]), [['bmp', '0000', ''], ['none', '', '']]);
    assert.deepEqual(passwordForms('abc').map((f) => f.encoding), ['bmp']);
    const [bmp, bytes] = passwordForms('Ş');
    assert.equal(toHex(bmp.bmp), '015e0000');
    assert.equal(toHex(bytes.bmp), '00c5009e0000', 'UTF-8 C5 9E, one character each');
    assert.equal(toHex(bytes.utf8), 'c59e');
  });
});

// ---------------------------------------------------------------------------
// OpenSSL-made bundles
// ---------------------------------------------------------------------------

/** `openssl pkcs12 -info` lines → the module's description. */
function opensslEncryption(line) {
  const pbes2 = /: PBES2, PBKDF2, (AES-\d+-CBC), Iteration (\d+), PRF hmacWith(SHA\d+)$/.exec(line);
  if (pbes2) return { scheme: 'PBES2', cipher: pbes2[1], kdf: `PBKDF2-HMAC-${pbes2[3]}`, iterations: Number(pbes2[2]) };
  const pbe = /: pbeWithSHA1And(3-KeyTripleDES|2-KeyTripleDES|128BitRC2|40BitRC2)-CBC, Iteration (\d+)$/.exec(line);
  const cipher = { '3-KeyTripleDES': '3DES-CBC', '2-KeyTripleDES': '2-key 3DES-CBC', '128BitRC2': 'RC2-128-CBC', '40BitRC2': 'RC2-40-CBC' }[pbe[1]];
  return { scheme: 'PKCS#12', cipher, kdf: 'PKCS#12 KDF (SHA-1)', iterations: Number(pbe[2]) };
}
const strip = ({ strength, ...rest }) => rest; // eslint-disable-line no-unused-vars

describe('openPkcs12: the OpenSSL-made bundles', () => {
  for (const [file, want] of Object.entries(BUNDLES)) {
    test(`${file}: ${want.about}`, async () => {
      const got = await openPkcs12(read(file), PASSWORDS[want.password], { checkKey: true });
      assert.deepEqual(got.certificates.map((c) => sha256(c.der)), want.certificates, 'certificates in file order');
      assert.equal(got.keys.length, want.keys, 'private keys');
      assert.equal(got.passwordVerified, true);
      // MAC as OpenSSL printed it.
      if (!want.mac) assert.equal(got.mac, null);
      else if (/PBMAC1/.test(want.mac)) {
        assert.deepEqual(got.mac, { kind: 'pbmac1', hash: 'SHA-256', iterations: Number(/Iteration (\d+)/.exec(want.mac)[1]), kdf: 'PBKDF2-HMAC-SHA256' });
      } else {
        const [, hash, iterations] = /^MAC: sha(\d+), Iteration (\d+)$/.exec(want.mac);
        assert.deepEqual(got.mac, { kind: 'hmac', hash: `SHA-${hash}`, iterations: Number(iterations), kdf: null });
      }
      // Encryption as OpenSSL printed it: the certificate parts, then the shrouded keys.
      const certLines = want.encryption.filter((l) => l.startsWith('PKCS7 Encrypted data'));
      const keyLines = want.encryption.filter((l) => l.startsWith('Shrouded Keybag'));
      assert.deepEqual(got.encryption.map(strip), certLines.map(opensslEncryption), 'certificate encryption');
      assert.deepEqual(got.keys.filter((k) => k.encrypted).map((k) => strip(k.encryption)), keyLines.map(opensslEncryption), 'key encryption');
      assert.equal(got.keys.filter((k) => !k.encrypted).length, want.bags.filter((b) => b === 'Key bag').length, 'plain key bags');
      // The key check agrees with OpenSSL's `pkey -pubout` comparison.
      if (want.keys) {
        const leafIndex = want.certificates.indexOf(want.leaf);
        assert.equal(got.keys[0].check.status, 'checked');
        assert.equal(got.keys[0].check.certificates.includes(leafIndex), want.keyMatchesLeaf, 'key belongs to the leaf');
      }
      // A wrong password never opens it.
      const err = await rejection(openPkcs12(read(file), `${PASSWORDS[want.password]}x`));
      assert.equal(err.code, 'BAD_PASSWORD');
      assert.equal(err.detail, want.mac ? 'mac' : 'no-mac');
    });
  }

  test('the input is never written to, and what it returns is its own', async () => {
    const input = read('p12_plain.p12');
    const copy = Buffer.from(input);
    const got = await openPkcs12(input, PASS, { checkKey: true });
    assert.deepEqual(input, copy);
    got.certificates[0].der.fill(0);
    assert.deepEqual(input, copy, 'certificate bytes are copies');
  });

  test('the result holds certificates and descriptions only: no key bytes, nothing of the password', async () => {
    const got = await openPkcs12(read('p12_plain.p12'), PASS, { checkKey: true });
    const arrays = [];
    const walk = (v, path) => {
      if (v instanceof Uint8Array) arrays.push(path);
      else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`);
    };
    walk(got, 'result');
    assert.deepEqual(arrays, got.certificates.map((_, i) => `result.certificates.${i}.der`));
    assert.deepEqual(Object.keys(got.keys[0]).sort(), ['check', 'encrypted', 'encryption', 'friendlyName', 'localKeyId', 'unsupported']);
    assert.doesNotMatch(JSON.stringify(got, (k, v) => (v instanceof Uint8Array ? toHex(v) : v)), new RegExp(Buffer.from(PASS).toString('hex')));
  });

  test('without checkKey no key is decrypted or imported', async () => {
    const seen = [];
    const subtle = new Proxy(globalThis.crypto.subtle, {
      get(target, prop) {
        const v = Reflect.get(target, prop);
        return typeof v === 'function' ? (...args) => {
          seen.push(`${String(prop)}:${typeof args[0] === 'string' ? args[0] : ''}`);
          return v.apply(target, args);
        } : v;
      }
    });
    const got = await openPkcs12(read('p12_rsa_aes.p12'), PASS, { subtle });
    assert.equal(got.keys.length, 1);
    assert.equal(got.keys[0].check, null);
    assert.ok(!seen.includes('importKey:pkcs8'), `no pkcs8 import: ${seen.join(', ')}`);
    // One PBKDF2 for the certificates (the key's would be a second).
    assert.equal(seen.filter((s) => s === 'deriveBits:').length, 1);
  });

  test('the empty password, and the Turkish password with an emoji', async () => {
    assert.equal((await openPkcs12(read('p12_empty_password.p12'), '')).certificates.length, 1);
    assert.equal((await rejection(openPkcs12(read('p12_empty_password.p12'), ' '))).code, 'BAD_PASSWORD');
    const uni = await openPkcs12(read('p12_unicode.p12'), 'Şifre-ğüı 🔑');
    assert.equal(uni.passwordEncoding, 'bmp');
    assert.equal((await rejection(openPkcs12(read('p12_unicode.p12'), 'Sifre-ğüı 🔑'))).code, 'BAD_PASSWORD');
  });

  test('a bundle OpenSSL 1.0.x wrote for a non-ASCII password opens with the password as typed', async () => {
    const got = await openPkcs12(read('p12_old_openssl.p12'), 'Şifre', { checkKey: true });
    assert.equal(got.passwordEncoding, 'utf8-bytes');
    assert.equal(got.keys[0].check.status, 'checked');
  });

  test('no MAC: a wrong password is told apart only by what does not decrypt', async () => {
    const ok = await openPkcs12(read('p12_nomac.p12'), PASS, { checkKey: true });
    assert.equal(ok.mac, null);
    assert.equal(ok.passwordVerified, true);
    const err = await rejection(openPkcs12(read('p12_nomac.p12'), 'not-the-password'));
    assert.deepEqual([err.code, err.detail], ['BAD_PASSWORD', 'no-mac']);
  });

  test('a certificate-only trust store has no keys; its key check has nothing to check', async () => {
    const got = await openPkcs12(read('p12_certs_only.p12'), PASS, { checkKey: true });
    assert.deepEqual(got.keys, []);
    assert.equal(got.certificates.length, 3);
  });

  test('AES-192, which Chromium\'s WebCrypto refuses, falls back to the JS cipher', async () => {
    let refused = 0;
    const subtle = new Proxy(globalThis.crypto.subtle, {
      get(target, prop) {
        const v = Reflect.get(target, prop);
        if (prop !== 'importKey') return typeof v === 'function' ? v.bind(target) : v;
        return (format, key, alg, ...rest) => {
          if (alg && alg.name === 'AES-CBC' && key.byteLength === 24) {
            refused += 1;
            return Promise.reject(new DOMException('192-bit AES keys are not supported', 'OperationError'));
          }
          return v.call(target, format, key, alg, ...rest);
        };
      }
    });
    const got = await openPkcs12(read('p12_ec_aes128.p12'), PASS, { checkKey: true, subtle });
    assert.equal(refused, 1, 'the AES-192 key was refused once');
    assert.deepEqual(got.keys[0].check.certificates, [0], 'and still decrypted');
  });

  test('without WebCrypto (plain http) a bundle is UNSUPPORTED, never a wrong password', async () => {
    const err = await rejection(openPkcs12(read('p12_rsa_aes.p12'), PASS, { subtle: null }));
    assert.deepEqual([err.code, err.detail], ['UNSUPPORTED', 'webcrypto']);
  });

  test('BER as Windows writes it: indefinite lengths and a segmented OCTET STRING', async () => {
    const ber = toWindowsBer(read('p12_rsa_legacy.p12'), 300);
    assert.equal(ber[1], 0x80, 'indefinite outer length');
    const got = await openPkcs12(ber, PASS, { checkKey: true });
    assert.deepEqual(got.certificates.map((c) => sha256(c.der)), BUNDLES['p12_rsa_legacy.p12'].certificates);
    assert.equal(got.keys[0].check.certificates[0], 0);
  });
});

// ---------------------------------------------------------------------------
// Damaged, unsupported and hostile input
// ---------------------------------------------------------------------------
describe('openPkcs12: damaged and unsupported bundles', () => {
  const leaf = parseCertificates(read('p12_rsa.pem')).leaf.der;

  test('a crafted bundle: plain SafeContents and a MAC keyed as RFC 7292 says', async () => {
    const got = await openPkcs12(await pfx(seq(contentInfo('data', octet(seq(certBag(leaf))))), { password: 'crafted' }), 'crafted');
    assert.deepEqual(got.certificates.map((c) => sha256(c.der)), [sha256(leaf)]);
    assert.equal(got.passwordVerified, true);
    assert.equal((await rejection(openPkcs12(await pfx(seq(contentInfo('data', octet(seq(certBag(leaf))))), { password: 'crafted' }), 'other'))).code, 'BAD_PASSWORD');
  });

  test('MAC right, contents broken: DAMAGED — not a wrong password', async () => {
    const broken = await pfx(seq(contentInfo('data', octet(Buffer.from([0x30, 0x05, 0x06, 0x01])))), { password: 'crafted' });
    const err = await rejection(openPkcs12(broken, 'crafted'));
    assert.equal(err.code, 'DAMAGED');
    // Encrypted contents that do not decrypt although the MAC matched.
    const garbage = encryptedData(pbes2Aes256(randomBytes(8), randomBytes(16)), randomBytes(64));
    const err2 = await rejection(openPkcs12(await pfx(seq(garbage), { password: 'crafted' }), 'crafted'));
    assert.equal(err2.code, 'DAMAGED');
    assert.match(err2.message, /do not decrypt/);
    // The same without a MAC is a wrong password (or damage: nothing tells them apart).
    const err3 = await rejection(openPkcs12(await pfx(seq(garbage)), 'crafted'));
    assert.deepEqual([err3.code, err3.detail], ['BAD_PASSWORD', 'no-mac']);
  });

  test('truncated and garbage input', async () => {
    const whole = read('p12_rsa_aes.p12');
    for (const cut of [10, 100, whole.length - 40, whole.length - 1]) {
      assert.equal((await rejection(openPkcs12(whole.subarray(0, cut), PASS))).code, 'DAMAGED', `cut at ${cut}`);
    }
    for (const input of [read('p12_rsa.pem'), parseCertificates(read('p12_rsa.pem')).leaf.der, new Uint8Array(0), Buffer.from('hello')]) {
      assert.equal((await rejection(openPkcs12(input, PASS))).code, 'NOT_PKCS12');
    }
    await assert.rejects(openPkcs12('not bytes', PASS), TypeError);
    await assert.rejects(openPkcs12(whole, null), TypeError);
  });

  test('unsupported modes and algorithms are named, before any password is tried', async () => {
    const cases = [
      [seq(int(3), contentInfo('signedData', seq(int(1)))), 'signedData'],
      [await pfx(seq(contentInfo('envelopedData', seq(int(0))))), 'envelopedData'],
      [await pfx(seq(encryptedData(seq(oid(OIDS.rc4), seq(octet(randomBytes(8)), int(2048))), randomBytes(16)))), 'pbeWithSHAAnd128BitRC4'],
      [await pfx(seq(contentInfo('data', octet(seq()))), { password: 'x', digest: OIDS.sha224 }), 'SHA-224']
    ];
    for (const [input, detail] of cases) {
      const err = await rejection(openPkcs12(input, 'x'));
      assert.deepEqual([err.code, err.detail], ['UNSUPPORTED', detail]);
    }
  });

  test('a key this page cannot decrypt is described, and the certificates still open', async () => {
    const rc4 = seq(oid(OIDS.rc4), seq(octet(randomBytes(8)), int(2048)));
    const slow = pbes2Aes256(randomBytes(8), randomBytes(16), 20000000);
    for (const [alg, unsupported, encryption] of [
      [rc4, 'pbeWithSHAAnd128BitRC4', null],
      [slow, 'iterations', { scheme: 'PBES2', cipher: 'AES-256-CBC', kdf: 'PBKDF2-HMAC-SHA256', iterations: 20000000, strength: 'ok' }]
    ]) {
      const bundle = await pfx(seq(contentInfo('data', octet(seq(certBag(leaf, 'k1'), shroudedKeyBag(alg, randomBytes(32), 'k1'))))), { password: 'x' });
      const got = await openPkcs12(bundle, 'x', { checkKey: true });
      assert.equal(got.certificates.length, 1);
      assert.deepEqual([got.keys[0].unsupported, got.keys[0].encryption, got.keys[0].check.status], [unsupported, encryption, 'unsupported-encryption']);
    }
  });

  test('an iteration count above the cap names the encryption it belongs to', async () => {
    const part = encryptedData(pbe3des(randomBytes(8), 5000000), randomBytes(64));
    const err = await rejection(openPkcs12(await pfx(seq(part), { password: 'x' }), 'x'));
    assert.deepEqual([err.code, err.detail, err.encryption && err.encryption.cipher, err.encryption && err.encryption.iterations],
      ['UNSUPPORTED', 'iterations', '3DES-CBC', 5000000]);
  });

  test('a large 3DES bundle (as Windows writes them) opens without holding the event loop', async () => {
    // About 700 KB of certificate bags under pbeWithSHAAnd3-KeyTripleDES-CBC: several slices.
    const salt = randomBytes(8);
    const derive = (id, length) => pkcs12Kdf({ hash: 'SHA-1', password: bmpPassword('big'), salt, id, iterations: 2048, length });
    const cipher = createCipheriv('des-ede3-cbc', await derive(1, 24), await derive(2, 8));
    const bags = Array.from({ length: Math.ceil(700000 / leaf.length) }, () => certBag(leaf));
    const ct = Buffer.concat([cipher.update(seq(...bags)), cipher.final()]);
    const bundle = await pfx(seq(encryptedData(pbe3des(salt, 2048), ct)), { password: 'big' });
    let last = performance.now();
    let longest = 0;
    const timer = setInterval(() => {
      longest = Math.max(longest, performance.now() - last);
      last = performance.now();
    }, 1);
    try {
      const got = await openPkcs12(bundle, 'big');
      assert.equal(got.certificates.length, bags.length);
      assert.equal(got.encryption[0].cipher, '3DES-CBC');
    } finally {
      clearInterval(timer);
    }
    // A slice is a few milliseconds; the one-piece decryption of a bit-per-byte DES held it for 20 s.
    assert.ok(longest < 250, `the event loop was held for ${longest.toFixed(0)} ms`);
  });

  test('an absurd iteration count is refused at once instead of hanging the page', async () => {
    const t0 = Date.now();
    const err = await rejection(openPkcs12(await pfx(seq(contentInfo('data', octet(seq()))), { password: 'x', iterations: 2 ** 40 }), 'x'));
    assert.deepEqual([err.code, err.detail], ['UNSUPPORTED', 'iterations']);
    // A SHA-512 MAC key takes one WebCrypto digest a round: its cap is lower.
    const sha512 = await rejection(openPkcs12(await pfx(seq(contentInfo('data', octet(seq()))), { password: 'x', digest: OIDS.sha512, iterations: 200001 }), 'x'));
    assert.deepEqual([sha512.code, sha512.detail], ['UNSUPPORTED', 'iterations']);
    assert.ok(Date.now() - t0 < 2000);
  });

  test('a long JS key derivation yields to the event loop (the page keeps painting)', async () => {
    let done = false;
    let firedWhileRunning = null;
    setTimeout(() => { firedWhileRunning = !done; }, 0);
    await pkcs12Kdf({ hash: 'SHA-1', password: bmpPassword('x'), salt: new Uint8Array(8), id: 1, iterations: 45000, length: 20 }).then(() => { done = true; });
    assert.equal(firedWhileRunning, true);
  });

  test('random corruption never escapes as anything but a Pkcs12Error', async () => {
    const whole = read('p12_nomac.p12'); // no MAC: the corruption reaches the decryption and the parser
    let rejected = 0;
    for (let i = 0; i < 150; i++) {
      const copy = Buffer.from(whole);
      for (let j = 0; j < 1 + (i % 4); j++) copy[Math.floor(Math.random() * copy.length)] ^= 1 << (i % 8);
      try {
        await openPkcs12(copy, PASS, { checkKey: i % 2 === 0 });
      } catch (err) {
        assert.ok(err instanceof Pkcs12Error, String(err && err.stack));
        assert.ok(PKCS12_ERRORS.includes(err.code), err.code);
        rejected += 1;
      }
    }
    assert.ok(rejected > 0);
  });
});

// ---------------------------------------------------------------------------
// lib/x509.js loadCertificates
// ---------------------------------------------------------------------------
describe('x509 loadCertificates', () => {
  const codes = (r) => r.warnings.map((w) => w.code);
  const NOW = new Date('2026-06-01T00:00:00Z');

  test('opens a bundle: its certificates in file order, the leaf, no key warning', async () => {
    const r = await loadCertificates(read('p12_rsa_aes.p12'), { password: PASS, now: NOW });
    assert.deepEqual(r.certificates.map((c) => c.subjectCN), ['p12.example.com', 'Example P12 Test Root', 'Example P12 Test Intermediate']);
    assert.equal(r.leaf.subjectCN, 'p12.example.com');
    assert.deepEqual(r.warnings, []);
    assert.deepEqual(r.pkcs12, {
      certificates: 3, keys: 1, unencryptedKeys: 0, friendlyName: 'p12.example.com',
      mac: { kind: 'hmac', hash: 'SHA-256', iterations: 2048, kdf: null },
      encryption: [{ scheme: 'PBES2', cipher: 'AES-256-CBC', kdf: 'PBKDF2-HMAC-SHA256', iterations: 2048, strength: 'ok' }],
      keyEncryption: [{ scheme: 'PBES2', cipher: 'AES-256-CBC', kdf: 'PBKDF2-HMAC-SHA256', iterations: 2048, strength: 'ok' }],
      passwordVerified: true,
      keyCheck: null
    });
  });

  test('base64 and PEM-wrapped bundles open too; without a password it is parseCertificates', async () => {
    const der = read('p12_rsa_legacy.p12');
    for (const input of [der.toString('base64'), pemEncode(der, 'PKCS12')]) {
      assert.equal((await loadCertificates(input, { password: PASS })).certificates.length, 3);
    }
    const none = await loadCertificates(der);
    assert.deepEqual(none, parseCertificates(der));
    assert.deepEqual(codes(none), ['PKCS12_UNSUPPORTED', 'NO_CERTIFICATE']);
    assert.equal(none.pkcs12, undefined);
  });

  test('the earlier fixture tests/fixtures/test.pfx (password "test") opens', async () => {
    const r = await loadCertificates(read('test.pfx'), { password: 'test', checkKey: true, now: NOW });
    assert.equal(r.leaf.subjectCN, 'www.example-test.com.tr');
    assert.equal(r.certificates.length, 2);
    assert.equal(r.pkcs12.keyCheck.status, 'match');
  });

  test('failures become warnings: wrong password (mac / no-mac), unsupported, damaged', async () => {
    const bad = await loadCertificates(read('p12_rsa_aes.p12'), { password: 'nope' });
    assert.deepEqual(bad.warnings, [{ code: 'PKCS12_BAD_PASSWORD', detail: 'mac' }, { code: 'NO_CERTIFICATE' }]);
    assert.equal(bad.pkcs12, undefined);
    const nomac = await loadCertificates(read('p12_nomac.p12'), { password: 'nope' });
    assert.deepEqual(nomac.warnings[0], { code: 'PKCS12_BAD_PASSWORD', detail: 'no-mac' });
    const rc4 = await loadCertificates(await pfx(seq(encryptedData(seq(oid(OIDS.rc4), seq(octet(randomBytes(8)), int(1))), randomBytes(16)))), { password: 'x' });
    assert.deepEqual(rc4.warnings[0], { code: 'PKCS12_UNSUPPORTED', detail: 'pbeWithSHAAnd128BitRC4' });
    const damaged = await loadCertificates(await pfx(seq(contentInfo('data', octet(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00])))), { password: 'x' }), { password: 'x' });
    assert.equal(codes(damaged)[0], 'PKCS12_DAMAGED');
  });

  test('the key check: match (RSA, P-256, P-384), mismatch with the owner named, no key', async () => {
    const check = async (file, password = PASS) => (await loadCertificates(read(file), { password, checkKey: true })).pkcs12.keyCheck;
    assert.deepEqual(await check('p12_rsa_aes.p12').then(({ status, algorithm }) => [status, algorithm]), ['match', 'RSA']);
    assert.deepEqual(await check('p12_ec_aes128.p12').then(({ status, algorithm }) => [status, algorithm]), ['match', 'EC P-256']);
    assert.deepEqual(await check('p12_p384_pbmac1.p12').then(({ status, algorithm }) => [status, algorithm]), ['match', 'EC P-384']);
    const mismatch = await check('p12_mismatch.p12');
    assert.equal(mismatch.status, 'mismatch');
    assert.equal(mismatch.owner.subjectCN, 'Example P12 Test Intermediate');
    assert.equal((await check('p12_certs_only.p12')).status, 'nokey');
    const plain = await loadCertificates(read('p12_plain.p12'), { password: PASS, checkKey: true });
    assert.equal(plain.pkcs12.unencryptedKeys, 1);
    assert.equal(plain.pkcs12.keyCheck.status, 'match');
  });

  test('a bundle with a plain key and no certificate: NO_CERTIFICATE, the key counted, nothing to check it against', async () => {
    const pkcs8 = read('ec_wildcard.pkcs8.key.der');
    const keyBag = seq(oid('1.2.840.113549.1.12.10.1.1'), explicit0(pkcs8));
    const bundle = await pfx(seq(contentInfo('data', octet(seq(keyBag)))), { password: 'k' });
    const opened = await openPkcs12(bundle, 'k', { checkKey: true });
    assert.deepEqual(opened.keys.map((k) => [k.encrypted, k.check.status, k.check.algorithm, k.check.certificates]), [[false, 'checked', 'EC P-256', []]]);
    const r = await loadCertificates(bundle, { password: 'k', checkKey: true });
    assert.deepEqual(r.warnings.map((w) => w.code), ['NO_CERTIFICATE']);
    assert.deepEqual([r.pkcs12.certificates, r.pkcs12.keys, r.pkcs12.unencryptedKeys, r.pkcs12.keyCheck.status], [0, 1, 1, 'nocert']);
    assert.equal((await loadCertificates(bundle, { password: 'k' })).pkcs12.keyCheck, null, 'not asked');
  });

  test('a key this page cannot decrypt: its encryption in the summary, its own verdict', async () => {
    const [rsa] = parseCertificates(read('p12_rsa.pem')).certificates.map((c) => c.der);
    const rc4 = seq(oid(OIDS.rc4), seq(octet(randomBytes(8)), int(2048)));
    const bundle = await pfx(seq(contentInfo('data', octet(seq(certBag(rsa, 'k1'), shroudedKeyBag(rc4, randomBytes(32), 'k1'))))), { password: 'k' });
    const checked = await loadCertificates(bundle, { password: 'k', checkKey: true });
    assert.deepEqual(checked.pkcs12.keyEncryption, [{ unsupported: 'pbeWithSHAAnd128BitRC4' }]);
    assert.deepEqual(checked.pkcs12.keyCheck, { status: 'unsupported-encryption', algorithm: null, encryption: 'pbeWithSHAAnd128BitRC4', owner: null });
    assert.equal((await loadCertificates(bundle, { password: 'k' })).pkcs12.keyCheck, null, 'not asked');
  });

  test('two bundles in one input: the first opens, the second is said to be skipped', async () => {
    const der = read('p12_rsa_aes.p12');
    const r = await loadCertificates(pemEncode(der, 'PKCS12') + pemEncode(read('p12_ec_aes128.p12'), 'PKCS12'), { password: PASS });
    assert.equal(r.leaf.subjectCN, 'p12.example.com');
    assert.deepEqual(r.warnings, [{ code: 'PARSE_ERROR', detail: 'PKCS#12 bundle 2: not opened (one bundle per file; load it on its own)' }]);
  });

  test('a key WebCrypto imports but will not sign with is "unsupported", and the certificates still load', async () => {
    const subtle = new Proxy(globalThis.crypto.subtle, {
      get(target, prop) {
        const v = Reflect.get(target, prop);
        if (prop === 'sign') return (alg, ...rest) => (alg && alg.name === 'ECDSA' ? Promise.reject(new DOMException('no', 'OperationError')) : v.call(target, alg, ...rest));
        return typeof v === 'function' ? v.bind(target) : v;
      }
    });
    const r = await loadCertificates(read('p12_ec_aes128.p12'), { password: PASS, checkKey: true, subtle });
    assert.equal(r.certificates.length, 3);
    assert.deepEqual(r.pkcs12.keyCheck, { status: 'unsupported', algorithm: 'EC P-256', encryption: null, owner: null });
  });

  test('a key type the browser cannot check is "unsupported", not a mismatch', async () => {
    // WebCrypto without EC: the P-256 key cannot be imported.
    const subtle = new Proxy(globalThis.crypto.subtle, {
      get(target, prop) {
        const v = Reflect.get(target, prop);
        if (prop !== 'importKey') return typeof v === 'function' ? v.bind(target) : v;
        return (format, key, alg, ...rest) => (alg && alg.name === 'ECDSA'
          ? Promise.reject(new DOMException('Unsupported', 'NotSupportedError')) : v.call(target, format, key, alg, ...rest));
      }
    });
    const r = await loadCertificates(read('p12_unicode.p12'), { password: PASSWORDS.unicode, checkKey: true, subtle });
    assert.deepEqual(r.pkcs12.keyCheck, { status: 'unsupported', algorithm: 'EC P-256', encryption: null, owner: null });
  });
});
