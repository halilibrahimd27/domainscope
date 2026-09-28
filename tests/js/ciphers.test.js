/**
 * Tests for assets/js/lib/ciphers.js (DES / 3DES, RC2, AES CBC decryption) and lib/sha.js.
 *
 * Ground truth: published known-answer vectors — FIPS 46-3 worked example, SP 800-17 tables and
 * the SP 800-67 TDEA example for DES / 3DES, RFC 2268 section 5 for RC2, FIPS 197 Appendix C and
 * SP 800-38A F.2 for AES — plus node:crypto (OpenSSL) as an independent oracle for CBC chains and
 * padding. Speed is bounded too: the page decrypts legacy bundles with these.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHash, getCiphers, randomBytes } from 'node:crypto';
import {
  CipherError, SLICE_BYTES, aesCbcDecrypt, cbcDecryptInSlices, desEde3CbcDecrypt, rc2CbcDecrypt
} from '../../assets/js/lib/ciphers.js';
import { sha1, sha256 } from '../../assets/js/lib/sha.js';

const hex = (s) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ''), 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');
const ZERO8 = new Uint8Array(8);
const ZERO16 = new Uint8Array(16);
/** One block through CBC with a zero IV and no padding = the raw block decryption. */
const raw = { padding: false };

/** node:crypto encryption (the oracle); null when this OpenSSL build lacks the cipher. */
function encrypt(name, key, iv, data, padding = true) {
  if (!getCiphers().includes(name)) return null;
  try {
    const c = createCipheriv(name, key, iv);
    c.setAutoPadding(padding);
    return new Uint8Array(Buffer.concat([c.update(data), c.final()]));
  } catch {
    return null; // e.g. single DES only in OpenSSL's legacy provider
  }
}

describe('DES and DES-EDE (3DES)', () => {
  test('FIPS 46-3 worked example: single DES (an 8-byte key)', () => {
    assert.equal(toHex(desEde3CbcDecrypt(hex('133457799bbcdff1'), ZERO8, hex('85e813540f0ab405'), raw)), '0123456789abcdef');
  });

  test('SP 800-17 known answers: variable plaintext, variable key and S-box tests', () => {
    // [key, plaintext, ciphertext] — Tables 1, 2 and 4 (single DES: the key three times over).
    const VECTORS = [
      ['0101010101010101', '8000000000000000', '95f8a5e5dd31d900'],
      ['0101010101010101', '4000000000000000', 'dd7f121ca5015619'],
      ['0101010101010101', '2000000000000000', '2e8653104f3834ea'],
      ['0101010101010101', '1000000000000000', '4bd388ff6cd81d4f'],
      ['8001010101010101', '0000000000000000', '95a8d72813daa94d'],
      ['4001010101010101', '0000000000000000', '0eec1487dd8c26d5'],
      ['7ca110454a1a6e57', '01a1d6d039776742', '690f5b0d9a26939b'],
      ['0131d9619dc1376e', '5cd54ca83def57da', '7a389d10354bd271'],
      ['07a1133e4a0b2686', '0248d43806f67172', '868ebb51cab4599a']
    ];
    for (const [key, plain, cipher] of VECTORS) {
      assert.equal(toHex(desEde3CbcDecrypt(hex(key), ZERO8, hex(cipher), raw)), plain, `key ${key}`);
    }
  });

  test('SP 800-67 TDEA example: three keys, "The qufck brown fox jump"', () => {
    const key = hex('0123456789abcdef 23456789abcdef01 456789abcdef0123');
    const ct = hex('a826fd8ce53b855f cce21c8112256fe6 68d5c05dd9b6b900');
    // ECB: each block on its own (CBC with a zero IV, block by block).
    const out = [0, 8, 16].map((o) => Buffer.from(desEde3CbcDecrypt(key, ZERO8, ct.subarray(o, o + 8), raw)).toString('latin1')).join('');
    assert.equal(out, 'The qufck brown fox jump');
  });

  test('two-key 3DES is K1 K2 K1, and single DES is 3DES with one key three times', () => {
    const k1 = hex('0123456789abcdef');
    const k2 = hex('23456789abcdef01');
    const data = hex('a826fd8ce53b855fcce21c8112256fe6');
    const iv = hex('0102030405060708');
    assert.deepEqual(desEde3CbcDecrypt(Uint8Array.of(...k1, ...k2), iv, data, raw), desEde3CbcDecrypt(Uint8Array.of(...k1, ...k2, ...k1), iv, data, raw));
    assert.deepEqual(desEde3CbcDecrypt(k1, iv, data, raw), desEde3CbcDecrypt(Uint8Array.of(...k1, ...k1, ...k1), iv, data, raw));
  });

  test('CBC chaining and PKCS#5 padding agree with OpenSSL (des-ede3-cbc)', (t) => {
    for (const size of [0, 1, 7, 8, 9, 100]) {
      const key = randomBytes(24);
      const iv = randomBytes(8);
      const plain = randomBytes(size);
      const ct = encrypt('des-ede3-cbc', key, iv, plain);
      if (!ct) return t.skip('des-ede3-cbc not in this OpenSSL build');
      assert.equal(toHex(desEde3CbcDecrypt(key, iv, ct)), toHex(plain), `${size} bytes`);
    }
    return undefined;
  });

  test('64 KB of 3DES and of two-key 3DES agree with OpenSSL and take milliseconds, not seconds', (t) => {
    const plain = randomBytes(64 * 1024);
    for (const [name, size] of [['des-ede3-cbc', 24], ['des-ede-cbc', 16]]) {
      const key = randomBytes(size);
      const iv = randomBytes(8);
      const ct = encrypt(name, key, iv, plain);
      if (!ct) return t.skip(`${name} not in this OpenSSL build`);
      const t0 = performance.now();
      const out = desEde3CbcDecrypt(key, iv, ct);
      const ms = performance.now() - t0;
      assert.ok(Buffer.from(out).equals(plain), name);
      // About 5 ms here; a bit-per-byte DES took over two seconds, and it runs on the page's thread.
      assert.ok(ms < 500, `${name}: ${ms.toFixed(0)} ms for 64 KB`);
    }
    return undefined;
  });
});

describe('RC2 (RFC 2268)', () => {
  // RFC 2268 section 5: key length (bytes), effective key bits, key, plaintext, ciphertext.
  const VECTORS = [
    [63, '0000000000000000', '0000000000000000', 'ebb773f993278eff'],
    [64, 'ffffffffffffffff', 'ffffffffffffffff', '278b27e42e2f0d49'],
    [64, '3000000000000000', '1000000000000001', '30649edf9be7d2c2'],
    [64, '88', '0000000000000000', '61a8a244adacccf0'],
    [64, '88bca90e90875a', '0000000000000000', '6ccf4308974c267f'],
    [64, '88bca90e90875a7f0f79c384627bafb2', '0000000000000000', '1a807d272bbe5db1'],
    [128, '88bca90e90875a7f0f79c384627bafb2', '0000000000000000', '2269552ab0f85ca6'],
    [129, '88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e', '0000000000000000', '5b78d3a43dfff1f1']
  ];
  for (const [bits, key, plain, cipher] of VECTORS) {
    test(`${key.length / 2}-byte key ${key.slice(0, 8)}…, ${bits} effective bits`, () => {
      assert.equal(toHex(rc2CbcDecrypt(hex(key), bits, ZERO8, hex(cipher), raw)), plain);
    });
  }

  test('CBC chaining: block n is D(C_n) XOR C_(n-1)', () => {
    const key = hex('88bca90e90875a7f0f79c384627bafb2');
    const iv = hex('0011223344556677');
    const c1 = hex('2269552ab0f85ca6');
    const c2 = hex('1a807d272bbe5db1');
    const out = rc2CbcDecrypt(key, 128, iv, Uint8Array.of(...c1, ...c2), raw);
    const first = rc2CbcDecrypt(key, 128, ZERO8, c1, raw).map((b, i) => b ^ iv[i]);
    const second = rc2CbcDecrypt(key, 128, ZERO8, c2, raw).map((b, i) => b ^ c1[i]);
    assert.deepEqual(out, Uint8Array.of(...first, ...second));
  });

  test('refuses impossible keys', () => {
    assert.throws(() => rc2CbcDecrypt(new Uint8Array(0), 40, ZERO8, ZERO8), CipherError);
    assert.throws(() => rc2CbcDecrypt(new Uint8Array(5), 0, ZERO8, ZERO8), CipherError);
    assert.throws(() => rc2CbcDecrypt(new Uint8Array(129), 64, ZERO8, ZERO8), CipherError);
  });
});

describe('AES (FIPS 197)', () => {
  const PLAIN = '00112233445566778899aabbccddeeff';
  test('FIPS 197 Appendix C: AES-128, AES-192, AES-256', () => {
    assert.equal(toHex(aesCbcDecrypt(hex('000102030405060708090a0b0c0d0e0f'), ZERO16, hex('69c4e0d86a7b0430d8cdb78070b4c55a'), raw)), PLAIN);
    assert.equal(toHex(aesCbcDecrypt(hex('000102030405060708090a0b0c0d0e0f1011121314151617'), ZERO16, hex('dda97ca4864cdfe06eaf70a0ec0d7191'), raw)), PLAIN);
    assert.equal(toHex(aesCbcDecrypt(hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), ZERO16, hex('8ea2b7ca516745bfeafc49904b496089'), raw)), PLAIN);
  });

  test('SP 800-38A F.2.4: CBC-AES192.Decrypt, four blocks', () => {
    const key = hex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');
    const iv = hex('000102030405060708090a0b0c0d0e0f');
    const ct = hex(`4f021db243bc633d7178183a9fa071e8 b4d9ada9ad7dedf4e5e738763f69145a
      571b242012fb7ae07fa9baac3df102e0 08b0e27988598881d920a9e64f5615cd`);
    const pt = `6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
      30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710`.replace(/\s+/g, '');
    assert.equal(toHex(aesCbcDecrypt(key, iv, ct, raw)), pt);
  });

  test('agrees with OpenSSL for every key size, padding included', () => {
    for (const [name, size] of [['aes-128-cbc', 16], ['aes-192-cbc', 24], ['aes-256-cbc', 32]]) {
      for (const len of [0, 15, 16, 33]) {
        const key = randomBytes(size);
        const iv = randomBytes(16);
        const plain = randomBytes(len);
        assert.equal(toHex(aesCbcDecrypt(key, iv, encrypt(name, key, iv, plain))), toHex(plain), `${name}, ${len} bytes`);
      }
    }
  });
});

describe('cbcDecryptInSlices', () => {
  const des = (key) => (iv, data, options) => desEde3CbcDecrypt(key, iv, data, options);

  test('gives what one call gives, across slice boundaries, for each cipher', async () => {
    const cases = [
      ['des-ede3-cbc', 24, 8, (key) => des(key)],
      ['aes-192-cbc', 24, 16, (key) => (iv, data, options) => aesCbcDecrypt(key, iv, data, options)]
    ];
    for (const [name, keySize, block, make] of cases) {
      for (const len of [0, 5, 63, 64, 65, 200]) {
        const key = randomBytes(keySize);
        const iv = randomBytes(block);
        const plain = randomBytes(len);
        const ct = encrypt(name, key, iv, plain);
        // Slices of 2 blocks: many boundaries, one of them just before the padding block.
        const got = await cbcDecryptInSlices(make(key), block, iv, ct, { sliceBytes: 2 * block });
        assert.equal(toHex(got), toHex(plain), `${name}, ${len} bytes`);
      }
    }
    const key = hex('88bca90e90875a7f0f79c384627bafb2');
    const iv = randomBytes(8);
    const ct = randomBytes(8 * 37);
    const rc2 = (v, d, o) => rc2CbcDecrypt(key, 128, v, d, o);
    assert.deepEqual(await cbcDecryptInSlices(rc2, 8, iv, ct, { padding: false, sliceBytes: 40 }), rc2CbcDecrypt(key, 128, iv, ct, raw));
  });

  test('errors are those of one call: bad padding, partial blocks; the inputs stay untouched', async () => {
    const key = randomBytes(24);
    const iv = randomBytes(8);
    const bad = encrypt('des-ede3-cbc', key, iv, new Uint8Array(64).fill(9), false);
    const copy = Buffer.from(bad);
    await assert.rejects(cbcDecryptInSlices(des(key), 8, iv, bad, { sliceBytes: 16 }), (e) => e instanceof CipherError && e.code === 'padding');
    assert.deepEqual(Buffer.from(bad), copy);
    await assert.rejects(cbcDecryptInSlices(des(key), 8, iv, new Uint8Array(41), { sliceBytes: 16 }), (e) => e instanceof CipherError && e.code === 'length');
    await assert.rejects(cbcDecryptInSlices(des(key), 8, iv, bad, { sliceBytes: 12 }), RangeError);
  });

  test('yields to the event loop between slices (the page keeps painting)', async () => {
    const key = randomBytes(24);
    const iv = randomBytes(8);
    const plain = randomBytes(3 * SLICE_BYTES + 100);
    const ct = encrypt('des-ede3-cbc', key, iv, plain);
    let done = false;
    let firedWhileRunning = null;
    setTimeout(() => { firedWhileRunning = !done; }, 0);
    const out = await cbcDecryptInSlices(des(key), 8, iv, ct);
    done = true;
    assert.equal(firedWhileRunning, true);
    assert.ok(Buffer.from(out).equals(plain));
  });
});

describe('CBC framing', () => {
  test('the inputs are never written to (a Node Buffer slice() is a view)', () => {
    const key = randomBytes(24);
    const iv = randomBytes(16);
    const ct = Buffer.from(encrypt('aes-192-cbc', key, iv, randomBytes(70)));
    const copies = [Buffer.from(key), Buffer.from(iv), Buffer.from(ct)];
    aesCbcDecrypt(key, iv, ct);
    const iv8 = iv.subarray(0, 8);
    desEde3CbcDecrypt(key, iv8, ct, raw);
    rc2CbcDecrypt(key, 128, iv8, ct, raw);
    assert.deepEqual([key, iv, ct], copies);
  });

  test('bad padding and partial blocks are CipherErrors, never garbage', () => {
    const key = randomBytes(32);
    const iv = randomBytes(16);
    // A zero pad byte and a pad longer than the block are both invalid.
    for (const last of [0, 17]) {
      const block = new Uint8Array(16).fill(last);
      const ct = encrypt('aes-256-cbc', key, iv, block, false);
      assert.throws(() => aesCbcDecrypt(key, iv, ct), (e) => e instanceof CipherError && e.code === 'padding', `pad byte ${last}`);
    }
    // Inconsistent padding: ends in 03 03 but the byte before is not 03.
    const odd = encrypt('aes-256-cbc', key, iv, hex('000102030405060708090a0b0c0d0203'), false);
    assert.throws(() => aesCbcDecrypt(key, iv, odd), (e) => e.code === 'padding');
    assert.throws(() => aesCbcDecrypt(key, iv, new Uint8Array(20)), (e) => e.code === 'length');
    assert.throws(() => aesCbcDecrypt(key, iv, new Uint8Array(0)), (e) => e.code === 'length');
    assert.throws(() => desEde3CbcDecrypt(new Uint8Array(24), new Uint8Array(4), new Uint8Array(8)), (e) => e.code === 'key');
    assert.throws(() => aesCbcDecrypt(new Uint8Array(20), iv, new Uint8Array(16)), (e) => e.code === 'key');
  });
});

describe('lib/sha.js', () => {
  test('SHA-1 and SHA-256 agree with node:crypto across the padding boundaries', () => {
    for (const len of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000]) {
      const data = randomBytes(len);
      assert.equal(toHex(sha1(data)), createHash('sha1').update(data).digest('hex'), `sha1 ${len}`);
      assert.equal(toHex(sha256(data)), createHash('sha256').update(data).digest('hex'), `sha256 ${len}`);
    }
    assert.equal(toHex(sha256(new TextEncoder().encode('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});
