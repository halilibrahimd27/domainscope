/**
 * PKCS#12 (.pfx / .p12, RFC 7292) for the browser and Node: the certificates of a
 * password-protected bundle, read locally. lib/x509.js `loadCertificates()` uses it for the
 * Certificate view and SSL Targets step 1. Pure and DOM-free; WebCrypto is taken from
 * `globalThis.crypto.subtle` unless one is passed in.
 *
 * - Structure: PFX → AuthenticatedSafe → SafeContents → SafeBags, BER-tolerant (Windows writes
 *   indefinite lengths and constructed OCTET STRINGs). certBag (x509Certificate) certificates are
 *   returned in file order; keyBag and pkcs8ShroudedKeyBag keys are counted and described, never
 *   returned; safeContentsBag nests; CRL, secret and other bags are counted and skipped.
 * - Integrity: the HMAC of RFC 7292 (its key from the PKCS#12 KDF of Appendix B over SHA-1,
 *   SHA-256, SHA-384 or SHA-512) or PBMAC1 (RFC 9579). A MAC that no reading of the password
 *   matches is BAD_PASSWORD ('mac'); with the MAC right, contents that do not decrypt or parse are
 *   DAMAGED. Without a MAC a wrong password shows only as contents that do not decrypt, and that
 *   is BAD_PASSWORD ('no-mac'): a damaged file looks the same then.
 * - Encryption: PBES2 (PBKDF2 with HMAC-SHA-1 / 256 / 384 / 512, then AES-128 / 192 / 256-CBC
 *   through WebCrypto — with lib/ciphers.js for the AES-192 Chromium refuses — or 3DES, DES,
 *   RC2-CBC), and the PKCS#12 PBE of legacy files: pbeWithSHAAnd3-KeyTripleDES-CBC,
 *   pbeWithSHAAnd2-KeyTripleDES-CBC, pbeWithSHAAnd128BitRC2-CBC and pbeWithSHAAnd40BitRC2-CBC
 *   (lib/ciphers.js). RC4, PBES1 and the public-key integrity and privacy modes are UNSUPPORTED.
 * - Passwords: a BMPString (UTF-16BE plus two zero bytes) for the PKCS#12 KDF and UTF-8 for
 *   PBKDF2, as OpenSSL does. An empty password is also tried as no bytes at all, and a non-ASCII
 *   one also the way OpenSSL 1.0.x encoded it (each UTF-8 byte one character), like
 *   `openssl pkcs12` retries both.
 * - Private keys: with `checkKey`, each key is decrypted in memory, imported into WebCrypto as a
 *   non-extractable pkcs8 key, used to sign a fixed challenge that the public key (SPKI) of every
 *   certificate of the file is asked to verify, and dropped. The result names the certificates
 *   the key belongs to (RSA; EC P-256, P-384, P-521). Without `checkKey` no key is decrypted.
 *
 * The password is used inside {@link openPkcs12} only, and no error message carries it. Its bytes,
 * the KDF's working buffers (and lib/sha.js's), derived keys, key schedules and decrypted contents
 * are zeroed once used. That is best effort: a JS string (the password as typed) cannot be
 * cleared, and the engine may keep copies of its own (WebCrypto's buffers, garbage not yet
 * collected).
 */

import { sha1, sha256 } from './sha.js';
import { CipherError, aesCbcDecrypt, cbcDecryptInSlices, desEde3CbcDecrypt, rc2CbcDecrypt } from './ciphers.js';

/** Error codes of {@link Pkcs12Error}. */
export const PKCS12_ERRORS = Object.freeze(['NOT_PKCS12', 'BAD_PASSWORD', 'DAMAGED', 'UNSUPPORTED']);

/**
 * Why a bundle could not be opened. `code`: one of {@link PKCS12_ERRORS}; `detail`: 'mac' or
 * 'no-mac' for BAD_PASSWORD, what is not supported for UNSUPPORTED (an algorithm name or OID,
 * 'iterations', 'envelopedData' / 'signedData' for the public-key modes, 'webcrypto' when the page
 * has no WebCrypto, 'webcrypto-refused: <operation>' when WebCrypto refused one, …), else null.
 * `encryption`: for 'iterations', the {@link EncryptionInfo} the count belongs to when it is an
 * encryption's.
 */
export class Pkcs12Error extends Error {
  /**
   * @param {'NOT_PKCS12'|'BAD_PASSWORD'|'DAMAGED'|'UNSUPPORTED'} code
   * @param {string} message
   * @param {{ detail?: string|null, encryption?: EncryptionInfo|null, cause?: unknown }} [options]
   */
  constructor(code, message, { detail = null, encryption = null, cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'Pkcs12Error';
    this.code = code;
    this.detail = detail;
    this.encryption = encryption;
  }
}

/** Nesting depth the BER reader follows (a PFX needs about ten levels). */
const MAX_DEPTH = 40;
/** Safe bags read at most (a real bundle has a handful). */
const MAX_BAGS = 1000;
/**
 * Highest iteration counts accepted (real bundles use 2,000 to 100,000): PBKDF2 runs natively;
 * the PKCS#12 KDF hashes in JS (about 2 µs a round) or, for SHA-384 / SHA-512, one WebCrypto
 * digest a round (about 20 µs). A larger count is UNSUPPORTED ('iterations') at once.
 */
const MAX_PBKDF2_ITERATIONS = 10000000;
const MAX_KDF_ITERATIONS = 1000000;
const MAX_ASYNC_KDF_ITERATIONS = 200000;
/** Rounds of the JS KDF between two yields to the event loop (the page keeps painting). */
const KDF_YIELD_EVERY = 20000;
/** What the key check signs (any fixed bytes do: nothing leaves the page). */
const CHALLENGE = new TextEncoder().encode('DomainScope PKCS#12 key check');

const OID = Object.freeze({
  DATA: '1.2.840.113549.1.7.1',
  SIGNED_DATA: '1.2.840.113549.1.7.2',
  ENVELOPED_DATA: '1.2.840.113549.1.7.3',
  ENCRYPTED_DATA: '1.2.840.113549.1.7.6',
  KEY_BAG: '1.2.840.113549.1.12.10.1.1',
  SHROUDED_KEY_BAG: '1.2.840.113549.1.12.10.1.2',
  CERT_BAG: '1.2.840.113549.1.12.10.1.3',
  CRL_BAG: '1.2.840.113549.1.12.10.1.4',
  SECRET_BAG: '1.2.840.113549.1.12.10.1.5',
  SAFE_CONTENTS_BAG: '1.2.840.113549.1.12.10.1.6',
  X509_CERTIFICATE: '1.2.840.113549.1.9.22.1',
  FRIENDLY_NAME: '1.2.840.113549.1.9.20',
  LOCAL_KEY_ID: '1.2.840.113549.1.9.21',
  PBES2: '1.2.840.113549.1.5.13',
  PBKDF2: '1.2.840.113549.1.5.12',
  PBMAC1: '1.2.840.113549.1.5.14',
  RSA: '1.2.840.113549.1.1.1',
  EC: '1.2.840.10045.2.1'
});

/** Hashes: the PKCS#12 KDF's u (size) and v (block), and the pure-JS version where there is one. */
const HASHES = Object.freeze({
  'SHA-1': { size: 20, block: 64, sync: sha1 },
  'SHA-256': { size: 32, block: 64, sync: sha256 },
  'SHA-384': { size: 48, block: 128, sync: null },
  'SHA-512': { size: 64, block: 128, sync: null }
});

/** Digest algorithm OIDs (the MAC's DigestInfo). */
const DIGESTS = Object.freeze({
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
  '2.16.840.1.101.3.4.2.4': 'SHA-224',
  '2.16.840.1.101.3.4.2.5': 'SHA-512/224',
  '2.16.840.1.101.3.4.2.6': 'SHA-512/256'
});

/** HMAC OIDs (PBKDF2's PRF, PBMAC1's messageAuthScheme). */
const HMACS = Object.freeze({
  '1.2.840.113549.2.7': 'SHA-1',
  '1.2.840.113549.2.8': 'SHA-224',
  '1.2.840.113549.2.9': 'SHA-256',
  '1.2.840.113549.2.10': 'SHA-384',
  '1.2.840.113549.2.11': 'SHA-512'
});

/** The PKCS#12 PBE algorithms (RFC 7292 Appendix C): the key and IV come from the PKCS#12 KDF with SHA-1. */
const PKCS12_PBE = Object.freeze({
  '1.2.840.113549.1.12.1.3': { cipher: '3DES-CBC', kind: 'des', keyLength: 24, strength: 'legacy' },
  '1.2.840.113549.1.12.1.4': { cipher: '2-key 3DES-CBC', kind: 'des', keyLength: 16, strength: 'legacy' },
  '1.2.840.113549.1.12.1.5': { cipher: 'RC2-128-CBC', kind: 'rc2', keyLength: 16, bits: 128, strength: 'legacy' },
  '1.2.840.113549.1.12.1.6': { cipher: 'RC2-40-CBC', kind: 'rc2', keyLength: 5, bits: 40, strength: 'weak' }
});

/** PBES2 encryption schemes. */
const PBES2_CIPHERS = Object.freeze({
  '2.16.840.1.101.3.4.1.2': { cipher: 'AES-128-CBC', kind: 'aes', keyLength: 16, ivLength: 16, strength: 'ok' },
  '2.16.840.1.101.3.4.1.22': { cipher: 'AES-192-CBC', kind: 'aes', keyLength: 24, ivLength: 16, strength: 'ok' },
  '2.16.840.1.101.3.4.1.42': { cipher: 'AES-256-CBC', kind: 'aes', keyLength: 32, ivLength: 16, strength: 'ok' },
  '1.2.840.113549.3.7': { cipher: '3DES-CBC', kind: 'des', keyLength: 24, ivLength: 8, strength: 'legacy' },
  '1.3.14.3.2.7': { cipher: 'DES-CBC', kind: 'des', keyLength: 8, ivLength: 8, strength: 'weak' },
  '1.2.840.113549.3.2': { cipher: 'RC2-CBC', kind: 'rc2', keyLength: 16, ivLength: 8, strength: 'legacy' }
});

/** Algorithms met in the wild that are recognised but not supported (named in UNSUPPORTED). */
const KNOWN_UNSUPPORTED = Object.freeze({
  '1.2.840.113549.1.12.1.1': 'pbeWithSHAAnd128BitRC4',
  '1.2.840.113549.1.12.1.2': 'pbeWithSHAAnd40BitRC4',
  '1.2.840.113549.1.5.1': 'pbeWithMD2AndDES-CBC',
  '1.2.840.113549.1.5.3': 'pbeWithMD5AndDES-CBC',
  '1.2.840.113549.1.5.4': 'pbeWithMD2AndRC2-CBC',
  '1.2.840.113549.1.5.6': 'pbeWithMD5AndRC2-CBC',
  '1.2.840.113549.1.5.10': 'pbeWithSHA1AndDES-CBC',
  '1.2.840.113549.1.5.11': 'pbeWithSHA1AndRC2-CBC'
});

/** EC named curves WebCrypto can import. */
const CURVES = Object.freeze({
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521'
});

/** EC named curves WebCrypto cannot import, named for display (the OID stays the fallback). */
const OTHER_CURVES = Object.freeze({
  '1.3.132.0.10': 'secp256k1',
  '1.3.36.3.3.2.8.1.1.7': 'brainpoolP256r1',
  '1.3.36.3.3.2.8.1.1.11': 'brainpoolP384r1',
  '1.3.36.3.3.2.8.1.1.13': 'brainpoolP512r1'
});

/** Key algorithms the key check recognises but cannot check, by OID. */
const OTHER_KEY_ALGORITHMS = Object.freeze({
  '1.2.840.113549.1.1.10': 'RSA-PSS',
  '1.2.840.10040.4.1': 'DSA',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
  '1.3.101.110': 'X25519',
  '1.3.101.111': 'X448'
});

// ---------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
const toHex = (bytes) => Array.from(bytes, (b) => HEX[b]).join('');
const UTF8 = new TextEncoder();

/**
 * A plain Uint8Array view of binary input (no copy), or null. A Node Buffer becomes a plain view
 * too, so `slice()` copies everywhere below.
 */
function asBytes(input) {
  if (input == null || typeof input !== 'object') return null;
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  const tag = Object.prototype.toString.call(input);
  if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') return new Uint8Array(input);
  return null;
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Constant-time comparison of two byte strings. */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * The BMPString of a password as the PKCS#12 KDF takes it: UTF-16 big-endian code units (a
 * character outside the BMP is its surrogate pair) and a two-byte zero terminator. The empty
 * password is just the terminator.
 * @param {string} password
 * @returns {Uint8Array}
 */
export function bmpPassword(password) {
  const s = String(password);
  const out = new Uint8Array(s.length * 2 + 2);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out[2 * i] = c >> 8;
    out[2 * i + 1] = c & 0xff;
  }
  return out;
}

/**
 * The readings of a password tried against a bundle, in order: `bmp` feeds the PKCS#12 KDF,
 * `utf8` PBKDF2. The empty password is also tried as no bytes at all (some writers leave the
 * terminator out); a non-ASCII password also as OpenSSL 1.0.x encoded it, each UTF-8 byte one
 * BMPString character.
 * @param {string} password
 * @returns {Array<{ bmp: Uint8Array, utf8: Uint8Array, encoding: 'bmp'|'none'|'utf8-bytes' }>}
 */
export function passwordForms(password) {
  const s = String(password);
  const utf8 = UTF8.encode(s);
  const forms = [{ bmp: bmpPassword(s), utf8, encoding: 'bmp' }];
  if (!s) forms.push({ bmp: new Uint8Array(0), utf8, encoding: 'none' });
  else if (/[^\0-\x7f]/.test(s)) forms.push({ bmp: bmpPassword(String.fromCharCode(...utf8)), utf8, encoding: 'utf8-bytes' });
  return forms;
}

// ---------------------------------------------------------------------------
// BER reader (definite and indefinite lengths, constructed strings)
// ---------------------------------------------------------------------------

function damaged(message, cause) {
  throw new Pkcs12Error('DAMAGED', message, { cause });
}

/**
 * One TLV at `pos` (bounds-checked against `limit`): { id, constructed, offset, start, end, next,
 * bytes, depth }. Indefinite lengths are allowed on constructed values; `end` is then where the
 * end-of-contents octets start and `next` follows them.
 */
function readTlv(bytes, pos, limit, depth = 0) {
  if (depth > MAX_DEPTH) damaged('ASN.1 nesting too deep');
  if (pos + 2 > limit) damaged('Truncated ASN.1 value');
  const id = bytes[pos];
  if ((id & 0x1f) === 0x1f) damaged('Unexpected high tag number');
  const constructed = (id & 0x20) !== 0;
  let p = pos + 1;
  let len = bytes[p++];
  if (len === 0x80) {
    if (!constructed) damaged('Indefinite length on a primitive value');
    let q = p;
    for (;;) {
      if (q + 2 > limit) damaged('Missing end-of-contents');
      if (bytes[q] === 0 && bytes[q + 1] === 0) break;
      q = readTlv(bytes, q, limit, depth + 1).next;
    }
    return { id, constructed, offset: pos, start: p, end: q, next: q + 2, bytes, depth };
  }
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 4 || p + n > limit) damaged('Bad ASN.1 length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[p++];
  }
  const end = p + len;
  if (end > limit) damaged('Truncated ASN.1 value');
  return { id, constructed, offset: pos, start: p, end, next: end, bytes, depth };
}

function children(node) {
  if (!node.constructed) damaged('Expected a constructed ASN.1 value');
  const out = [];
  for (let p = node.start; p < node.end;) {
    const kid = readTlv(node.bytes, p, node.end, node.depth + 1);
    out.push(kid);
    p = kid.next;
  }
  return out;
}

function expect(node, id, what) {
  if (!node) damaged(`Missing ${what}`);
  if (node.id !== id) damaged(`Expected ${what}`);
  return node;
}

/** The value of an OCTET STRING (or of an IMPLICIT one), joining the segments of a constructed one. */
function octets(node) {
  if (!node) damaged('Missing OCTET STRING');
  if (!node.constructed) return node.bytes.subarray(node.start, node.end);
  return concat(children(node).map((kid) => {
    if ((kid.id & 0xdf) !== 0x04) damaged('Bad segment in a constructed OCTET STRING');
    return octets(kid);
  }));
}

/** The whole TLV of a node, header included. */
const tlvOf = (node) => node.bytes.subarray(node.offset, node.next);

/** The value of a node that must be an OCTET STRING (primitive or constructed). */
function octetString(node, what) {
  if (!node || (node.id & 0xdf) !== 0x04) damaged(`Expected ${what}`);
  return octets(node);
}

function oid(node) {
  const v = expect(node, 0x06, 'OBJECT IDENTIFIER').bytes.subarray(node.start, node.end);
  if (!v.length || v[v.length - 1] & 0x80) damaged('Bad OBJECT IDENTIFIER');
  const arcs = [];
  let n = 0;
  for (const b of v) {
    n = n * 128 + (b & 0x7f);
    if (n > Number.MAX_SAFE_INTEGER) damaged('OBJECT IDENTIFIER arc too large');
    if (!(b & 0x80)) {
      if (!arcs.length) arcs.push(n < 80 ? Math.floor(n / 40) : 2, n < 80 ? n % 40 : n - 80);
      else arcs.push(n);
      n = 0;
    }
  }
  return arcs.join('.');
}

/** A non-negative INTEGER that fits a JS number. */
function smallInt(node, what) {
  const v = expect(node, 0x02, what).bytes.subarray(node.start, node.end);
  if (!v.length || v[0] & 0x80) damaged(`Bad ${what}`);
  let n = 0;
  for (const b of v) {
    n = n * 256 + b;
    if (n > Number.MAX_SAFE_INTEGER) damaged(`${what} too large`);
  }
  return n;
}

/** AlgorithmIdentifier → { id, params } (params: the node, or null when absent or NULL). */
function algorithm(node) {
  const [idNode, params] = children(expect(node, 0x30, 'AlgorithmIdentifier'));
  return { id: oid(idNode), params: params && params.id !== 0x05 ? params : null };
}

/**
 * An iteration count: DAMAGED below 1, UNSUPPORTED ('iterations') above `max` — refused at once,
 * never run. `encryption`: the EncryptionInfo the count belongs to, carried by the error.
 */
function checkIterations(n, max, what, encryption = null) {
  if (!Number.isSafeInteger(n) || n < 1) damaged(`Bad ${what} iteration count`);
  if (n > max) throw new Pkcs12Error('UNSUPPORTED', `${what}: ${n} iterations is more than this page runs`, { detail: 'iterations', encryption });
  return n;
}

// ---------------------------------------------------------------------------
// Key derivation, MAC, decryption
// ---------------------------------------------------------------------------

function needSubtle(subtle) {
  if (!subtle || typeof subtle.importKey !== 'function') {
    throw new Pkcs12Error('UNSUPPORTED', 'WebCrypto is not available (open the page over https)', { detail: 'webcrypto' });
  }
  return subtle;
}

/**
 * `hash` iterated: H(data), then H of the previous output, `count` times in all. Each
 * intermediate output is zeroed once the next one is made (`data` is the caller's to zero).
 */
async function hashIterate(hash, data, count, subtle) {
  const { sync } = HASHES[hash];
  let a = data;
  const next = (b) => {
    if (a !== data) a.fill(0);
    a = b;
  };
  if (sync) {
    for (let i = 1; i <= count; i++) {
      next(sync(a));
      if (i % KDF_YIELD_EVERY === 0 && i < count) await new Promise((resolve) => setTimeout(resolve, 0));
    }
    return a;
  }
  const s = needSubtle(subtle);
  return webCrypto(hash, async () => {
    for (let i = 0; i < count; i++) next(new Uint8Array(await s.digest(hash, a)));
    return a;
  });
}

/**
 * The PKCS#12 key derivation function (RFC 7292 Appendix B.2).
 * @param {{ hash?: 'SHA-1'|'SHA-256'|'SHA-384'|'SHA-512', password: Uint8Array, salt: Uint8Array,
 *   id: 1|2|3, iterations: number, length: number, subtle?: SubtleCrypto }} opts
 *   password: the BMPString ({@link bmpPassword}); id: 1 key, 2 IV, 3 MAC key; subtle: only for
 *   SHA-384 / SHA-512 (SHA-1 and SHA-256 run in JS, lib/sha.js)
 * @returns {Promise<Uint8Array>} `length` bytes
 */
export async function pkcs12Kdf({ hash = 'SHA-1', password, salt, id, iterations, length, subtle = globalThis.crypto?.subtle }) {
  const h = HASHES[hash];
  if (!h) throw new Pkcs12Error('UNSUPPORTED', `PKCS#12 KDF with ${hash}`, { detail: hash });
  const { size: u, block: v } = h;
  const stretch = (src, n) => Uint8Array.from({ length: n }, (_, i) => src[i % src.length]);
  const S = salt.length ? stretch(salt, v * Math.ceil(salt.length / v)) : new Uint8Array(0);
  const P = password.length ? stretch(password, v * Math.ceil(password.length / v)) : new Uint8Array(0);
  const I = concat([S, P]);
  const D = new Uint8Array(v).fill(id);
  const blocks = Math.ceil(length / u);
  const out = new Uint8Array(blocks * u);
  for (let i = 0; i < blocks; i++) {
    const DI = concat([D, I]); // holds the stretched password: zeroed below
    let A;
    try {
      A = await hashIterate(hash, DI, iterations, subtle);
    } finally {
      DI.fill(0);
    }
    out.set(A, i * u);
    if (i + 1 < blocks) {
      // I_j = (I_j + B + 1) mod 2^(8v) for every v-byte block of I, B = A repeated to v bytes.
      for (let j = 0; j < I.length; j += v) {
        let carry = 1;
        for (let k = v - 1; k >= 0; k--) {
          const x = I[j + k] + A[k % u] + carry;
          I[j + k] = x & 0xff;
          carry = x >> 8;
        }
      }
    }
    A.fill(0);
  }
  I.fill(0);
  P.fill(0);
  const result = out.slice(0, length);
  out.fill(0);
  return result;
}

/**
 * A WebCrypto operation the browser refused although it has WebCrypto: UNSUPPORTED
 * ('webcrypto-refused: <what>', e.g. 'webcrypto-refused: PBKDF2-HMAC-SHA-256'), never a wrong
 * password. A page without WebCrypto at all is 'webcrypto' ({@link needSubtle}).
 */
async function webCrypto(what, run) {
  try {
    return await run();
  } catch (err) {
    throw new Pkcs12Error('UNSUPPORTED', `WebCrypto refused ${what}: ${(err && err.message) || err}`, { detail: `webcrypto-refused: ${what}`, cause: err });
  }
}

async function pbkdf2(subtle, { password, salt, iterations, hash, length }) {
  const s = needSubtle(subtle);
  return webCrypto(`PBKDF2-HMAC-${hash}`, async () => {
    const base = await s.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await s.deriveBits({ name: 'PBKDF2', salt, iterations, hash }, base, length * 8));
  });
}

async function hmac(subtle, hash, key, data) {
  const s = needSubtle(subtle);
  return webCrypto(`HMAC-${hash}`, async () => {
    const k = await s.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
    return new Uint8Array(await s.sign('HMAC', k, data));
  });
}

/**
 * PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER, keyLength INTEGER
 * OPTIONAL, prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }. The caller caps the iterations.
 */
function pbkdf2Params(node) {
  const kids = children(expect(node, 0x30, 'PBKDF2 parameters'));
  if (kids[0] && kids[0].id === 0x30) throw new Pkcs12Error('UNSUPPORTED', 'PBKDF2 with another salt source', { detail: 'PBKDF2 salt source' });
  const salt = octetString(kids[0], 'PBKDF2 salt');
  const iterations = checkIterations(smallInt(kids[1], 'PBKDF2 iteration count'), Infinity, 'PBKDF2');
  let i = 2;
  const keyLength = kids[i] && kids[i].id === 0x02 ? smallInt(kids[i++], 'PBKDF2 key length') : null;
  let hash = 'SHA-1';
  if (kids[i]) {
    const prf = algorithm(kids[i]);
    hash = HMACS[prf.id];
    if (!hash || !HASHES[hash]) throw new Pkcs12Error('UNSUPPORTED', `PBKDF2 with ${hash ? `HMAC-${hash}` : prf.id}`, { detail: hash ? `hmacWith${hash.replace('-', '')}` : prf.id });
  }
  return { salt, iterations, keyLength, hash };
}

/**
 * @typedef {object} EncryptionInfo how a part of the bundle is encrypted
 * @property {'PBES2'|'PKCS#12'} scheme
 * @property {string} cipher 'AES-256-CBC', '3DES-CBC', 'RC2-40-CBC', …
 * @property {string} kdf 'PBKDF2-HMAC-SHA256', 'PKCS#12 KDF (SHA-1)'
 * @property {number} iterations
 * @property {'ok'|'legacy'|'weak'} strength weak: a 40- or 56-bit key (RC2-40, DES); legacy: 3DES,
 *   RC2-128 or the SHA-1 PKCS#12 KDF
 */

/**
 * An encryption AlgorithmIdentifier: what it is ({@link EncryptionInfo}) and how to decrypt with a
 * password form. Unsupported algorithms throw UNSUPPORTED here, before any password is used.
 * @returns {{ info: EncryptionInfo, decrypt: (data: Uint8Array, form: object, subtle: SubtleCrypto) => Promise<Uint8Array> }}
 */
function encryptionScheme(node) {
  const alg = algorithm(node);
  const pbe = PKCS12_PBE[alg.id];
  if (pbe) {
    const [saltNode, iterNode] = children(expect(alg.params, 0x30, 'PBE parameters'));
    const salt = octetString(saltNode, 'PBE salt');
    const iterations = checkIterations(smallInt(iterNode, 'PBE iteration count'), Infinity, 'PKCS#12 KDF');
    const info = { scheme: 'PKCS#12', cipher: pbe.cipher, kdf: 'PKCS#12 KDF (SHA-1)', iterations, strength: pbe.strength };
    checkIterations(iterations, MAX_KDF_ITERATIONS, 'PKCS#12 KDF', info);
    return {
      info,
      async decrypt(data, form, subtle) {
        const derive = (id, length) => pkcs12Kdf({ hash: 'SHA-1', password: form.bmp, salt, id, iterations, length, subtle });
        const key = await derive(1, pbe.keyLength);
        const iv = await derive(2, 8);
        try {
          return await (pbe.kind === 'des' ? des(key, iv, data) : rc2(key, pbe.bits, iv, data));
        } finally {
          key.fill(0);
        }
      }
    };
  }
  if (alg.id === OID.PBES2) {
    const [kdfNode, encNode] = children(expect(alg.params, 0x30, 'PBES2 parameters'));
    const kdf = algorithm(kdfNode);
    if (kdf.id !== OID.PBKDF2) throw new Pkcs12Error('UNSUPPORTED', `PBES2 with the key derivation ${kdf.id}`, { detail: kdf.id });
    const params = pbkdf2Params(kdf.params);
    const enc = algorithm(encNode);
    const cipher = PBES2_CIPHERS[enc.id];
    if (!cipher) throw new Pkcs12Error('UNSUPPORTED', `PBES2 with the cipher ${enc.id}`, { detail: enc.id });
    let iv;
    let rc2Bits = 32;
    if (cipher.kind === 'rc2') {
      // RC2-CBC-Parameter ::= SEQUENCE { rc2ParameterVersion INTEGER OPTIONAL, iv OCTET STRING }
      const kids = children(expect(enc.params, 0x30, 'RC2 parameters'));
      const version = kids.length > 1 ? smallInt(kids[0], 'RC2 version') : 32;
      rc2Bits = { 160: 40, 120: 64, 58: 128 }[version] ?? version;
      iv = octetString(kids[kids.length - 1], 'RC2 IV');
    } else {
      iv = octetString(enc.params, 'IV');
    }
    if (iv.length !== cipher.ivLength) damaged(`Bad ${cipher.cipher} IV`);
    // RC2 takes any key length; the others only their own.
    if (cipher.kind !== 'rc2' && params.keyLength !== null && params.keyLength !== cipher.keyLength) damaged(`PBKDF2 key length does not fit ${cipher.cipher}`);
    const keyLength = params.keyLength ?? cipher.keyLength;
    const name = cipher.kind === 'rc2' ? `RC2-${rc2Bits}-CBC` : cipher.cipher;
    const info = {
      scheme: 'PBES2', cipher: name, kdf: `PBKDF2-HMAC-${params.hash.replace('-', '')}`, iterations: params.iterations,
      strength: cipher.kind === 'rc2' && rc2Bits <= 56 ? 'weak' : cipher.strength
    };
    checkIterations(params.iterations, MAX_PBKDF2_ITERATIONS, 'PBKDF2', info);
    return {
      info,
      async decrypt(data, form, subtle) {
        const key = await pbkdf2(subtle, { password: form.utf8, salt: params.salt, iterations: params.iterations, hash: params.hash, length: keyLength });
        try {
          if (cipher.kind === 'des') return await des(key, iv, data);
          if (cipher.kind === 'rc2') return await rc2(key, rc2Bits, iv, data);
          return await aesDecrypt(subtle, key, iv, data);
        } finally {
          key.fill(0);
        }
      }
    };
  }
  const name = KNOWN_UNSUPPORTED[alg.id] || alg.id;
  throw new Pkcs12Error('UNSUPPORTED', `Encryption ${name} is not supported`, { detail: name });
}

// The JS ciphers (lib/ciphers.js) run a slice at a time, yielding between slices: a large
// legacy bundle does not freeze the page while it decrypts.
const des = (key, iv, data) => cbcDecryptInSlices((v, d, o) => desEde3CbcDecrypt(key, v, d, o), 8, iv, data);
const rc2 = (key, bits, iv, data) => cbcDecryptInSlices((v, d, o) => rc2CbcDecrypt(key, bits, v, d, o), 8, iv, data);

/** AES-CBC through WebCrypto; lib/ciphers.js when WebCrypto refuses the key (AES-192 in Chromium). */
async function aesDecrypt(subtle, key, iv, data) {
  const s = needSubtle(subtle);
  let k;
  try {
    k = await s.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
  } catch {
    return cbcDecryptInSlices((v, d, o) => aesCbcDecrypt(key, v, d, o), 16, iv, data);
  }
  try {
    return new Uint8Array(await s.decrypt({ name: 'AES-CBC', iv }, k, data));
  } catch (err) {
    throw new CipherError('padding', `Decryption failed (${(err && err.name) || 'error'})`);
  }
}

/** A decryption that failed (wrong key or damaged data) — never a structural or support problem. */
const isDecryptFailure = (err) => err instanceof CipherError;

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

/**
 * Does the input start like a PFX — SEQUENCE { INTEGER 3, SEQUENCE … — whatever follows? Such a
 * file that does not parse is DAMAGED (e.g. cut short), anything else NOT_PKCS12.
 */
function looksLikePfx(bytes) {
  if (bytes.length < 8 || bytes[0] !== 0x30) return false;
  const lenBytes = bytes[1] === 0x80 ? 0 : bytes[1] & 0x80 ? bytes[1] & 0x7f : 0;
  const p = 2 + lenBytes;
  return bytes[p] === 0x02 && bytes[p + 1] === 0x01 && bytes[p + 2] === 0x03 && bytes[p + 3] === 0x30;
}

/**
 * PFX ::= SEQUENCE { version INTEGER (3), authSafe ContentInfo, macData MacData OPTIONAL }.
 * @returns {{ data: Uint8Array, mac: object|null }}
 */
function readPfx(bytes) {
  let kids;
  try {
    kids = children(expect(readTlv(bytes, 0, bytes.length), 0x30, 'PFX'));
    if (!kids[0] || kids[0].id !== 0x02 || !kids[1] || kids[1].id !== 0x30) damaged('Not a PFX');
  } catch (err) {
    if (looksLikePfx(bytes)) throw err;
    throw new Pkcs12Error('NOT_PKCS12', 'Not a PKCS#12 file', { cause: err });
  }
  if (smallInt(kids[0], 'PFX version') !== 3) damaged('Unknown PFX version');
  const [ctNode, content] = children(kids[1]);
  const type = oid(ctNode);
  if (type === OID.SIGNED_DATA) throw new Pkcs12Error('UNSUPPORTED', 'Public-key integrity mode (signedData) is not supported', { detail: 'signedData' });
  if (type !== OID.DATA) damaged('The authenticated safe is not data');
  const data = octets(children(expect(content, 0xa0, 'authSafe content'))[0]);
  return { data, mac: kids[2] ? readMac(kids[2]) : null };
}

/**
 * MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER DEFAULT 1 };
 * for PBMAC1 (RFC 9579) the digest algorithm carries the PBKDF2 and HMAC parameters.
 */
function readMac(node) {
  const [digestInfo, saltNode, iterNode] = children(expect(node, 0x30, 'MacData'));
  const [algNode, digestNode] = children(expect(digestInfo, 0x30, 'DigestInfo'));
  const alg = algorithm(algNode);
  const digest = octetString(digestNode, 'MAC digest');
  if (alg.id === OID.PBMAC1) {
    const [kdfNode, schemeNode] = children(expect(alg.params, 0x30, 'PBMAC1 parameters'));
    const kdf = algorithm(kdfNode);
    if (kdf.id !== OID.PBKDF2) throw new Pkcs12Error('UNSUPPORTED', `PBMAC1 with the key derivation ${kdf.id}`, { detail: kdf.id });
    const params = pbkdf2Params(kdf.params);
    checkIterations(params.iterations, MAX_PBKDF2_ITERATIONS, 'PBMAC1');
    const scheme = algorithm(schemeNode);
    const hash = HMACS[scheme.id];
    if (!hash || !HASHES[hash]) throw new Pkcs12Error('UNSUPPORTED', `PBMAC1 with ${scheme.id}`, { detail: hash ? `HMAC-${hash}` : scheme.id });
    if (!params.keyLength) damaged('PBMAC1 without a key length');
    return { kind: 'pbmac1', hash, digest, iterations: params.iterations, kdf: params };
  }
  const hash = DIGESTS[alg.id];
  if (!hash || !HASHES[hash]) throw new Pkcs12Error('UNSUPPORTED', `A ${hash || alg.id} MAC is not supported`, { detail: hash || alg.id });
  const salt = octetString(saltNode, 'MAC salt');
  const max = HASHES[hash].sync ? MAX_KDF_ITERATIONS : MAX_ASYNC_KDF_ITERATIONS;
  const iterations = iterNode ? checkIterations(smallInt(iterNode, 'MAC iteration count'), max, 'MAC') : 1;
  return { kind: 'hmac', hash, digest, salt, iterations };
}

/** The first password form whose MAC matches, or null. */
async function verifyMac(mac, data, forms, subtle) {
  // PBMAC1 derives its key from the UTF-8 password, the same for every form.
  for (const form of mac.kind === 'pbmac1' ? forms.slice(0, 1) : forms) {
    const key = mac.kind === 'pbmac1'
      ? await pbkdf2(subtle, { password: form.utf8, salt: mac.kdf.salt, iterations: mac.kdf.iterations, hash: mac.kdf.hash, length: mac.kdf.keyLength })
      : await pkcs12Kdf({ hash: mac.hash, password: form.bmp, salt: mac.salt, id: 3, iterations: mac.iterations, length: HASHES[mac.hash].size, subtle });
    const sig = await hmac(subtle, mac.hash, key, data);
    key.fill(0);
    if (sameBytes(sig, mac.digest)) return form;
  }
  return null;
}

/**
 * AuthenticatedSafe ::= SEQUENCE OF ContentInfo: plain data, password-encrypted EncryptedData,
 * or public-key EnvelopedData (unsupported).
 * @returns {Array<{ type: 'data', bytes: Uint8Array }|{ type: 'encrypted', scheme: object, ciphertext: Uint8Array }>}
 */
function readAuthenticatedSafe(data) {
  const out = [];
  for (const info of children(expect(readTlv(data, 0, data.length), 0x30, 'AuthenticatedSafe'))) {
    const [ctNode, content] = children(expect(info, 0x30, 'ContentInfo'));
    const type = oid(ctNode);
    const inner = content ? children(expect(content, 0xa0, 'ContentInfo content'))[0] : null;
    if (type === OID.DATA) {
      out.push({ type: 'data', bytes: inner ? octets(inner) : new Uint8Array(0) });
    } else if (type === OID.ENCRYPTED_DATA) {
      // EncryptedData ::= SEQUENCE { version, EncryptedContentInfo { contentType, algorithm, [0] IMPLICIT encryptedContent OPTIONAL } }
      const [, eci] = children(expect(inner, 0x30, 'EncryptedData'));
      const [, algNode, encrypted] = children(expect(eci, 0x30, 'EncryptedContentInfo'));
      out.push({ type: 'encrypted', scheme: encryptionScheme(algNode), ciphertext: encrypted ? octets(encrypted) : new Uint8Array(0) });
    } else if (type === OID.ENVELOPED_DATA) {
      throw new Pkcs12Error('UNSUPPORTED', 'Public-key privacy mode (envelopedData) is not supported', { detail: 'envelopedData' });
    } else {
      damaged('Unknown content in the authenticated safe');
    }
  }
  return out;
}

/** BMPString → string. */
function bmpText(node) {
  const v = node.bytes.subarray(node.start, node.end);
  let s = '';
  for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]);
  return s;
}

/** friendlyName and localKeyId of a bag's attributes. */
function bagAttributes(node) {
  const out = { friendlyName: null, localKeyId: null };
  if (!node) return out;
  for (const attr of children(expect(node, 0x31, 'bag attributes'))) {
    const [typeNode, values] = children(expect(attr, 0x30, 'bag attribute'));
    const type = oid(typeNode);
    const first = values ? children(expect(values, 0x31, 'attribute values'))[0] : null;
    if (!first) continue;
    if (type === OID.FRIENDLY_NAME && first.id === 0x1e) out.friendlyName = bmpText(first);
    else if (type === OID.LOCAL_KEY_ID && (first.id & 0xdf) === 0x04) out.localKeyId = toHex(octets(first));
  }
  return out;
}

/**
 * SafeContents ::= SEQUENCE OF SafeBag; SafeBag ::= SEQUENCE { bagId, bagValue [0] EXPLICIT,
 * bagAttributes SET OF OPTIONAL }. Certificates and keys go into `acc` (keys unopened).
 */
function readSafeContents(bytes, acc, depth = 0) {
  if (depth > 8) damaged('Safe contents nested too deep');
  for (const bag of children(expect(readTlv(bytes, 0, bytes.length), 0x30, 'SafeContents'))) {
    if (++acc.bagCount > MAX_BAGS) damaged('Too many bags');
    const [idNode, wrap, attrs] = children(expect(bag, 0x30, 'SafeBag'));
    const type = oid(idNode);
    const value = children(expect(wrap, 0xa0, 'bag value'))[0];
    const attributes = bagAttributes(attrs);
    if (type === OID.CERT_BAG) {
      const [certId, certWrap] = children(expect(value, 0x30, 'CertBag'));
      if (oid(certId) !== OID.X509_CERTIFICATE) {
        acc.ignored.other += 1;
        continue;
      }
      acc.certificates.push({ der: octets(children(expect(certWrap, 0xa0, 'certificate value'))[0]).slice(), ...attributes });
    } else if (type === OID.KEY_BAG) {
      acc.keys.push({ encrypted: false, encryption: null, unsupported: null, value: expect(value, 0x30, 'PrivateKeyInfo'), ...attributes });
    } else if (type === OID.SHROUDED_KEY_BAG) {
      // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData OCTET STRING }
      const [algNode, dataNode] = children(expect(value, 0x30, 'EncryptedPrivateKeyInfo'));
      let scheme = null;
      let unsupported = null;
      try {
        scheme = encryptionScheme(algNode);
      } catch (err) {
        if (!(err instanceof Pkcs12Error) || err.code !== 'UNSUPPORTED') throw err;
        unsupported = err; // the certificates can still be read
      }
      acc.keys.push({
        encrypted: true, encryption: scheme ? scheme.info : unsupported.encryption, scheme, unsupported, ciphertext: octets(dataNode), ...attributes
      });
    } else if (type === OID.SAFE_CONTENTS_BAG) {
      readSafeContents(tlvOf(value), acc, depth + 1);
    } else if (type === OID.CRL_BAG) {
      acc.ignored.crl += 1;
    } else if (type === OID.SECRET_BAG) {
      acc.ignored.secret += 1;
    } else {
      acc.ignored.other += 1;
    }
  }
}

// ---------------------------------------------------------------------------
// The key check
// ---------------------------------------------------------------------------

/** The SubjectPublicKeyInfo TLV of a DER certificate. */
function certificateSpki(der) {
  const cert = readTlv(der, 0, der.length);
  const tbs = children(expect(children(expect(cert, 0x30, 'Certificate'))[0], 0x30, 'TBSCertificate'));
  const spki = tbs[tbs[0] && tbs[0].id === 0xa0 ? 6 : 5];
  return tlvOf(expect(spki, 0x30, 'SubjectPublicKeyInfo'));
}

/** WebCrypto parameters for a key algorithm (from a PrivateKeyInfo or an SPKI), or its name. */
function keyAlgorithm(algNode) {
  const alg = algorithm(algNode);
  if (alg.id === OID.RSA) {
    return { name: 'RSA', importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, signAlg: { name: 'RSASSA-PKCS1-v1_5' } };
  }
  if (alg.id === OID.EC) {
    const curveOid = alg.params && alg.params.id === 0x06 ? oid(alg.params) : null;
    const curve = curveOid && CURVES[curveOid];
    if (!curve) return { name: `EC ${(curveOid && OTHER_CURVES[curveOid]) || curveOid || 'explicit curve'}`, unsupported: true };
    return { name: `EC ${curve}`, importAlg: { name: 'ECDSA', namedCurve: curve }, signAlg: { name: 'ECDSA', hash: 'SHA-256' } };
  }
  return { name: OTHER_KEY_ALGORITHMS[alg.id] || alg.id, unsupported: true };
}

/**
 * Which certificates a private key belongs to: the key signs a fixed challenge, each
 * certificate's public key of the same algorithm verifies it.
 * @param {Uint8Array} pkcs8 PrivateKeyInfo DER
 * @param {Array<{ der: Uint8Array }>} certificates
 * @returns {Promise<{ status: 'checked'|'unsupported', algorithm: string, certificates: number[] }>}
 */
async function checkKey(pkcs8, certificates, subtle) {
  const [, algNode] = children(expect(readTlv(pkcs8, 0, pkcs8.length), 0x30, 'PrivateKeyInfo'));
  const alg = keyAlgorithm(algNode);
  if (alg.unsupported) return { status: 'unsupported', algorithm: alg.name, certificates: [] };
  const s = needSubtle(subtle);
  let signature;
  try {
    const key = await s.importKey('pkcs8', pkcs8, alg.importAlg, false, ['sign']);
    signature = new Uint8Array(await s.sign(alg.signAlg, key, CHALLENGE));
  } catch {
    // The browser cannot use this key (a curve or size it refuses): nothing to compare, no verdict.
    return { status: 'unsupported', algorithm: alg.name, certificates: [] };
  }
  const matches = [];
  for (let i = 0; i < certificates.length; i++) {
    let spki;
    try {
      spki = certificateSpki(certificates[i].der);
      const [certAlg] = children(readTlv(spki, 0, spki.length));
      if (keyAlgorithm(certAlg).name !== alg.name) continue;
      const pub = await s.importKey('spki', spki, alg.importAlg, false, ['verify']);
      if (await s.verify(alg.signAlg, pub, signature, CHALLENGE)) matches.push(i);
    } catch {
      /* a certificate this browser cannot read the key of matches nothing */
    }
  }
  return { status: 'checked', algorithm: alg.name, certificates: matches };
}

// ---------------------------------------------------------------------------
// openPkcs12
// ---------------------------------------------------------------------------

/**
 * @typedef {object} Pkcs12Contents
 * @property {Array<{ der: Uint8Array, friendlyName: string|null, localKeyId: string|null }>} certificates
 *   in file order (localKeyId: lowercase hex)
 * @property {Array<{ encrypted: boolean, encryption: EncryptionInfo|null, unsupported: string|null,
 *   friendlyName: string|null, localKeyId: string|null, check: null|{ status: 'checked'|'unsupported'|
 *   'unsupported-encryption'|'failed', algorithm: string|null, certificates: number[] } }>} keys
 *   never the key itself. `unsupported`: why this page cannot decrypt a shrouded key — its
 *   encryption's name or OID ('pbeWithSHAAnd128BitRC4', …; `encryption` is then null) or
 *   'iterations' (`encryption` says which). `check` only with `checkKey`: 'checked' (certificates:
 *   the indexes the key belongs to), 'unsupported' (a key type this page cannot check; algorithm:
 *   its name), 'unsupported-encryption' (the key could not be decrypted here, see `unsupported`),
 *   'failed' (the key did not decrypt although the rest of the file did)
 * @property {{ kind: 'hmac'|'pbmac1', hash: string, iterations: number, kdf: string|null }|null} mac
 * @property {EncryptionInfo[]} encryption one per encrypted part holding certificates (usually one)
 * @property {boolean} passwordVerified the MAC matched, or a part decrypted with the password
 * @property {'bmp'|'none'|'utf8-bytes'|null} passwordEncoding the reading of the password that
 *   worked ({@link passwordForms}), null when nothing used it
 * @property {{ crl: number, secret: number, other: number }} ignored bags that were skipped
 */

/**
 * Open a PKCS#12 bundle with its password.
 * @param {Uint8Array|ArrayBuffer} input the .pfx / .p12 bytes (DER or BER)
 * @param {string} password '' for none
 * @param {{ checkKey?: boolean, subtle?: SubtleCrypto }} [options] checkKey: decrypt each private
 *   key in memory to find the certificates it belongs to (off by default)
 * @returns {Promise<Pkcs12Contents>}
 * @throws {Pkcs12Error} NOT_PKCS12, BAD_PASSWORD ('mac' | 'no-mac'), DAMAGED, UNSUPPORTED
 */
export async function openPkcs12(input, password, { checkKey = false, subtle = globalThis.crypto?.subtle } = {}) {
  const bytes = asBytes(input);
  if (!bytes) throw new TypeError('openPkcs12: expected bytes (Uint8Array or ArrayBuffer)');
  if (typeof password !== 'string') throw new TypeError('openPkcs12: the password must be a string');
  try {
    return await open(bytes, password, { checkKey, subtle });
  } catch (err) {
    if (err instanceof Pkcs12Error) throw err;
    // WebCrypto refusing an operation, or a bug: never an unexplained rejection.
    throw new Pkcs12Error('DAMAGED', `The file could not be read: ${(err && err.message) || err}`, { cause: err });
  }
}

/** An empty bag collector (readSafeContents). */
const collector = (bagCount = 0) => ({ certificates: [], keys: [], ignored: { crl: 0, secret: 0, other: 0 }, bagCount });

async function open(bytes, password, { checkKey, subtle }) {
  const pfx = readPfx(bytes);
  const forms = passwordForms(password);
  // What was decrypted, zeroed on the way out (it may hold plain keyBags).
  const plains = [];
  try {
    let form = null;
    if (pfx.mac) {
      form = await verifyMac(pfx.mac, pfx.data, forms, subtle);
      if (!form) throw new Pkcs12Error('BAD_PASSWORD', 'The password does not match the integrity check (MAC) of the file', { detail: 'mac' });
    }
    const macVerified = !!form;
    const wrong = () => new Pkcs12Error('BAD_PASSWORD', 'Wrong password, or a damaged file: it has no integrity check (MAC) to tell', { detail: 'no-mac' });
    const acc = collector();
    const encryption = [];

    for (const part of readAuthenticatedSafe(pfx.data)) {
      if (part.type === 'data') {
        readSafeContents(part.bytes, acc);
        continue;
      }
      // Until a password reading is verified each one is tried: the right one decrypts to SafeContents.
      let read = null;
      for (const f of form ? [form] : forms) {
        let plain;
        try {
          plain = await part.scheme.decrypt(part.ciphertext, f, subtle);
        } catch (err) {
          if (!isDecryptFailure(err)) throw err;
          continue;
        }
        plains.push(plain);
        const attempt = collector(acc.bagCount);
        try {
          readSafeContents(plain, attempt);
        } catch (err) {
          if (!(err instanceof Pkcs12Error) || err.code !== 'DAMAGED') throw err;
          continue;
        }
        read = attempt;
        form = f;
        break;
      }
      if (!read) {
        if (!macVerified) throw wrong();
        damaged('The contents do not decrypt although the password matches the integrity check');
      }
      acc.certificates.push(...read.certificates);
      acc.keys.push(...read.keys);
      for (const k of Object.keys(acc.ignored)) acc.ignored[k] += read.ignored[k];
      acc.bagCount = read.bagCount;
      encryption.push(part.scheme.info);
    }

    const keys = [];
    for (const key of acc.keys) {
      let check = null;
      if (checkKey) {
        const checked = await checkOneKey(key, form ? [form] : forms, !!form, acc.certificates, subtle);
        if (!checked) throw wrong(); // no reading of the password decrypts it, and nothing verified one
        check = checked.check;
        form = form || checked.form;
      }
      keys.push({
        encrypted: key.encrypted, encryption: key.encryption, unsupported: key.unsupported ? key.unsupported.detail : null,
        friendlyName: key.friendlyName, localKeyId: key.localKeyId, check
      });
    }

    const mac = pfx.mac ? {
      kind: pfx.mac.kind, hash: pfx.mac.hash, iterations: pfx.mac.iterations,
      kdf: pfx.mac.kind === 'pbmac1' ? `PBKDF2-HMAC-${pfx.mac.kdf.hash.replace('-', '')}` : null
    } : null;
    return {
      certificates: acc.certificates.map(({ der, friendlyName, localKeyId }) => ({ der, friendlyName, localKeyId })),
      keys,
      mac,
      encryption,
      passwordVerified: !!form,
      passwordEncoding: form ? form.encoding : null,
      ignored: acc.ignored
    };
  } finally {
    for (const plain of plains) plain.fill(0);
    for (const form of forms) {
      form.bmp.fill(0);
      form.utf8.fill(0);
    }
  }
}

/**
 * The key check of one key bag ({@link checkKey}), decrypting a shrouded key with the first
 * password reading that works. null when none does and none of `forms` was `verified` (they were
 * guesses): the caller reports a wrong password. A verified reading that does not decrypt the key
 * gives status 'failed' (another password for the key, or damage).
 * @returns {Promise<{ check: object, form: object|null }|null>}
 */
async function checkOneKey(key, forms, verified, certificates, subtle) {
  // An encryption this page cannot undo: no key to check, and nothing wrong with the password.
  if (key.unsupported) return { check: { status: 'unsupported-encryption', algorithm: null, certificates: [] }, form: null };
  if (!key.encrypted) return { check: await checkKey(tlvOf(key.value), certificates, subtle), form: null };
  for (const f of forms) {
    let pkcs8 = null;
    try {
      pkcs8 = await key.scheme.decrypt(key.ciphertext, f, subtle);
      // A wrong key that happens to leave valid padding does not decrypt to one whole TLV.
      if (readTlv(pkcs8, 0, pkcs8.length).next !== pkcs8.length) continue;
      return { check: await checkKey(pkcs8, certificates, subtle), form: f };
    } catch (err) {
      if (!isDecryptFailure(err) && !(err instanceof Pkcs12Error && err.code === 'DAMAGED')) throw err;
    } finally {
      if (pkcs8) pkcs8.fill(0);
    }
  }
  return verified ? { check: { status: 'failed', algorithm: null, certificates: [] }, form: null } : null;
}
