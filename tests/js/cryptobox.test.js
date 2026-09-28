/**
 * lib/cryptobox.js — PBKDF2-HMAC-SHA-256 + AES-GCM with Node's WebCrypto: the round trip, random
 * salt and IV, the iteration floor, a wrong password and every kind of tampering (ciphertext, IV,
 * salt, iteration count, the caller's context), unreadable boxes, and passwords typed in another
 * Unicode form. Boxes are sealed at MIN_ITERATIONS to keep the suite fast; one test seals at the
 * default. No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import {
  sealText, openText, checkBox, encodeBase64, decodeBase64, BoxError,
  DEFAULT_ITERATIONS, MIN_ITERATIONS, MAX_ITERATIONS, SALT_BYTES, IV_BYTES, TAG_BYTES, MIN_PASSWORD_LENGTH,
  KDF_NAME, KDF_HASH, CIPHER_NAME
} from '../../assets/js/lib/cryptobox.js';

const PASSWORD = 'correct horse battery';
const FAST = { iterations: MIN_ITERATIONS, context: 'test/1' };
const code = (c) => (err) => err instanceof BoxError && err.code === c;

/** A copy of a box with one base64 field's first byte changed (still valid base64, same length). */
function flip(box, path) {
  const out = structuredClone(box);
  const [a, b] = path;
  const holder = b ? out[a] : out;
  const key = b || a;
  const bytes = decodeBase64(holder[key]);
  bytes[0] ^= 0x01;
  holder[key] = encodeBase64(bytes);
  return out;
}

describe('constants', () => {
  test('PBKDF2 SHA-256 at ≥ 310,000 iterations, a 16-byte salt, AES-GCM with a 12-byte IV', () => {
    assert.equal(KDF_NAME, 'PBKDF2');
    assert.equal(KDF_HASH, 'SHA-256');
    assert.equal(CIPHER_NAME, 'AES-GCM');
    assert.ok(MIN_ITERATIONS >= 310000);
    assert.ok(DEFAULT_ITERATIONS >= MIN_ITERATIONS && DEFAULT_ITERATIONS <= MAX_ITERATIONS);
    assert.equal(SALT_BYTES, 16);
    assert.equal(IV_BYTES, 12);
    assert.equal(TAG_BYTES, 16);
    assert.equal(MIN_PASSWORD_LENGTH, 8);
  });
});

describe('base64', () => {
  test('round trip, large input, and only strict padded base64 is read', () => {
    const big = new Uint8Array(200000).map((_, i) => (i * 31) & 0xff);
    assert.deepEqual(decodeBase64(encodeBase64(big)), big);
    assert.equal(encodeBase64(new Uint8Array([1, 2, 3, 4])), 'AQIDBA==');
    for (const bad of ['AQIDBA=', 'AQID BA==', 'AQ-DBA==', '*', 42, null]) assert.throws(() => decodeBase64(bad), code('damaged'), String(bad));
    assert.deepEqual(decodeBase64(''), new Uint8Array(0));
  });
});

describe('sealing and opening', () => {
  test('round trip; the box names its parameters and carries no plaintext', async () => {
    const text = JSON.stringify({ inventory: 'web01 192.0.2.10', note: 'Müşteri notları — İstanbul' });
    const box = await sealText(text, PASSWORD, FAST);
    assert.deepEqual(Object.keys(box), ['kdf', 'cipher', 'data']);
    assert.deepEqual({ ...box.kdf, salt: undefined }, { name: 'PBKDF2', hash: 'SHA-256', iterations: MIN_ITERATIONS, salt: undefined });
    assert.equal(box.cipher.name, 'AES-GCM');
    assert.equal(decodeBase64(box.kdf.salt).length, SALT_BYTES);
    assert.equal(decodeBase64(box.cipher.iv).length, IV_BYTES);
    assert.equal(decodeBase64(box.data).length, new TextEncoder().encode(text).length + TAG_BYTES);
    assert.ok(!JSON.stringify(box).includes('web01') && !JSON.stringify(box).includes(PASSWORD));
    assert.equal(await openText(box, PASSWORD, { context: 'test/1' }), text);
  });

  test('the default iteration count is written into the box', async () => {
    const box = await sealText('x', PASSWORD, { context: 'test/1' });
    assert.equal(box.kdf.iterations, DEFAULT_ITERATIONS);
    assert.equal(await openText(box, PASSWORD, { context: 'test/1' }), 'x');
  });

  test('every box gets its own random salt and IV', async () => {
    const a = await sealText('same text', PASSWORD, FAST);
    const b = await sealText('same text', PASSWORD, FAST);
    assert.notEqual(a.kdf.salt, b.kdf.salt);
    assert.notEqual(a.cipher.iv, b.cipher.iv);
    assert.notEqual(a.data, b.data);
  });

  test('a wrong password is refused', async () => {
    const box = await sealText('secret', PASSWORD, FAST);
    await assert.rejects(openText(box, 'correct horse battery!', { context: 'test/1' }), code('wrong-password'));
    await assert.rejects(openText(box, 'Correct horse battery', { context: 'test/1' }), code('wrong-password'));
  });

  test('any change to the box is found: ciphertext, tag, IV, salt, iteration count, context', async () => {
    const box = await sealText('secret', PASSWORD, FAST);
    const opts = { context: 'test/1' };
    await assert.rejects(openText(flip(box, ['data']), PASSWORD, opts), code('wrong-password'), 'ciphertext');
    const tag = structuredClone(box);
    const bytes = decodeBase64(tag.data);
    bytes[bytes.length - 1] ^= 0x80;
    tag.data = encodeBase64(bytes);
    await assert.rejects(openText(tag, PASSWORD, opts), code('wrong-password'), 'tag');
    await assert.rejects(openText(flip(box, ['cipher', 'iv']), PASSWORD, opts), code('wrong-password'), 'iv');
    await assert.rejects(openText(flip(box, ['kdf', 'salt']), PASSWORD, opts), code('wrong-password'), 'salt');
    const more = structuredClone(box);
    more.kdf.iterations += 1;
    await assert.rejects(openText(more, PASSWORD, opts), code('wrong-password'), 'iterations');
    await assert.rejects(openText(box, PASSWORD, { context: 'test/2' }), code('wrong-password'), 'context');
  });

  test('a box that cannot be read is "damaged"; another algorithm "unsupported"', async () => {
    const box = await sealText('secret', PASSWORD, FAST);
    const variant = (fn) => {
      const b = structuredClone(box);
      fn(b);
      return b;
    };
    const damaged = [
      null, 'box', {}, { kdf: box.kdf }, variant((b) => { b.data = 'not base64!'; }),
      variant((b) => { b.cipher.iv = encodeBase64(new Uint8Array(16)); }),
      variant((b) => { b.kdf.salt = encodeBase64(new Uint8Array(8)); }),
      variant((b) => { b.data = encodeBase64(new Uint8Array(TAG_BYTES - 1)); }),
      variant((b) => { b.kdf.iterations = MIN_ITERATIONS - 1; }),
      variant((b) => { b.kdf.iterations = MAX_ITERATIONS + 1; }),
      variant((b) => { b.kdf.iterations = '600000'; }),
      variant((b) => { b.kdf.iterations = 1.5e5 + 0.5; })
    ];
    for (const b of damaged) await assert.rejects(openText(b, PASSWORD), code('damaged'), JSON.stringify(b)?.slice(0, 80));
    for (const b of [
      variant((x) => { x.kdf.name = 'scrypt'; }), variant((x) => { x.kdf.hash = 'SHA-1'; }), variant((x) => { x.cipher.name = 'AES-CBC'; })
    ]) {
      await assert.rejects(openText(b, PASSWORD), code('unsupported'));
    }
    assert.throws(() => checkBox({ kdf: {}, cipher: {} }), code('unsupported'));
  });

  test('passwords: required, at least 8 characters to seal; the same text in another Unicode form opens', async () => {
    await assert.rejects(sealText('x', '', FAST), code('password-required'));
    await assert.rejects(sealText('x', null, FAST), code('password-required'));
    await assert.rejects(sealText('x', 'short12', FAST), code('password-short'));
    await assert.rejects(sealText('x', '🙂🙂🙂🙂🙂🙂🙂', FAST), code('password-short'), 'counted in characters');
    const composed = 'parola-çözüm';
    const decomposed = composed.normalize('NFD');
    assert.notEqual(composed, decomposed);
    const box = await sealText('x', composed, FAST);
    assert.equal(await openText(box, decomposed, { context: 'test/1' }), 'x');
    await assert.rejects(openText(box, '', { context: 'test/1' }), code('password-required'));
  });

  test('iteration counts outside the range are refused when sealing', async () => {
    await assert.rejects(sealText('x', PASSWORD, { iterations: 1000 }), RangeError);
    await assert.rejects(sealText('x', PASSWORD, { iterations: MAX_ITERATIONS + 1 }), RangeError);
  });

  test('no WebCrypto (an insecure context): "crypto-unavailable"', async () => {
    await assert.rejects(sealText('x', PASSWORD, { ...FAST, crypto: {} }), code('crypto-unavailable'));
    const box = await sealText('x', PASSWORD, FAST);
    await assert.rejects(openText(box, PASSWORD, { crypto: { getRandomValues() {} } }), code('crypto-unavailable'));
  });

  test('an injected WebCrypto is used (the browser build passes window.crypto)', async () => {
    let calls = 0;
    const counting = {
      subtle: webcrypto.subtle,
      getRandomValues: (a) => {
        calls += 1;
        return webcrypto.getRandomValues(a);
      }
    };
    const box = await sealText('x', PASSWORD, { ...FAST, crypto: counting });
    assert.equal(calls, 2, 'salt and IV');
    assert.equal(await openText(box, PASSWORD, { context: 'test/1', crypto: counting }), 'x');
  });
});
