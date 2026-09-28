/**
 * lib/cryptobox.js — password-based encryption of a text that leaves the browser as a file (the
 * workspace hand-over file, lib/handover.js). WebCrypto only:
 *   - PBKDF2-HMAC-SHA-256 with a random 16-byte salt and {@link DEFAULT_ITERATIONS} iterations
 *     (at least {@link MIN_ITERATIONS}) derives a 256-bit AES key from the password;
 *   - AES-GCM with a random 12-byte IV encrypts and authenticates the text and, as additional
 *     data, the box's own parameters and the caller's `context` (the file format and version), so
 *     a changed iteration count, salt, IV or ciphertext fails exactly like a wrong password.
 * The password is never stored: it is encoded (NFC, UTF-8), handed to the key derivation and
 * dropped. AES-GCM cannot tell a wrong password from a changed file; {@link BoxError} 'wrong-password'
 * says both, and 'damaged' is kept for a box that cannot even be read.
 *
 * DOM-free: `crypto` (a WebCrypto implementation) is injectable; browsers and Node 22 have one.
 *
 * @example
 *   const box = await sealText('{"a":1}', 'correct horse battery', { context: 'example/1' });
 *   // { kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt: '…' }, cipher: { name: 'AES-GCM', iv: '…' }, data: '…' }
 *   await openText(box, 'correct horse battery', { context: 'example/1' });   // '{"a":1}'
 */

/** Key derivation, cipher and their parameters as written into a box. */
export const KDF_NAME = 'PBKDF2';
export const KDF_HASH = 'SHA-256';
export const CIPHER_NAME = 'AES-GCM';
/** PBKDF2 iterations of a new box (OWASP's 2023 figure for PBKDF2-HMAC-SHA-256). */
export const DEFAULT_ITERATIONS = 600000;
/** Fewer iterations than this are refused, when sealing and when opening. */
export const MIN_ITERATIONS = 310000;
/** More than this is refused on opening: a box that would keep the page busy for minutes is not ours. */
export const MAX_ITERATIONS = 5000000;
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
/** AES-GCM's authentication tag, at the end of `data`. */
export const TAG_BYTES = 16;
/** The shortest password a new box accepts (characters). */
export const MIN_PASSWORD_LENGTH = 8;

/**
 * Why a box could not be sealed or opened. `code`: 'password-required' (no password),
 * 'password-short' (under MIN_PASSWORD_LENGTH, sealing only), 'wrong-password' (the password is
 * wrong or the box was changed), 'damaged' (not a readable box), 'unsupported' (another KDF,
 * hash or cipher), 'crypto-unavailable' (no WebCrypto: an insecure context).
 */
export class BoxError extends Error {
  /**
   * @param {string} code
   * @param {string} [message]
   */
  constructor(code, message) {
    super(message || code);
    this.name = 'BoxError';
    this.code = code;
  }
}

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const CHUNK = 0x8000;

/**
 * Standard base64 of bytes (chunked, so a large box never overflows the call stack).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function encodeBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += CHUNK) bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  return btoa(bin);
}

/**
 * Bytes of a standard, padded base64 string; anything else is a 'damaged' box.
 * @param {unknown} text
 * @returns {Uint8Array}
 */
export function decodeBase64(text) {
  if (typeof text !== 'string' || !B64_RE.test(text)) throw new BoxError('damaged', 'not base64');
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** The WebCrypto `subtle` and `getRandomValues` of `crypto`, or a 'crypto-unavailable' error. */
function webCrypto(crypto) {
  if (!crypto || !crypto.subtle || typeof crypto.getRandomValues !== 'function') {
    throw new BoxError('crypto-unavailable', 'WebCrypto is not available (the page needs a secure context)');
  }
  return crypto;
}

/** The password as key material: NFC, UTF-8 (the same text typed anywhere gives the same key). */
function passwordBytes(password) {
  return new TextEncoder().encode(String(password).normalize('NFC'));
}

/** The additional authenticated data: the caller's context and every parameter of the box. */
function boxAad(context, iterations, salt, iv) {
  return new TextEncoder().encode([String(context ?? ''), KDF_NAME, KDF_HASH, iterations, salt, CIPHER_NAME, iv].join('|'));
}

async function deriveKey(subtle, password, salt, iterations) {
  const base = await subtle.importKey('raw', passwordBytes(password), KDF_NAME, false, ['deriveKey']);
  return subtle.deriveKey(
    { name: KDF_NAME, salt, iterations, hash: KDF_HASH },
    base,
    { name: CIPHER_NAME, length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * The parameters of a box, checked: the algorithms this module writes, an iteration count in
 * range, a 16-byte salt, a 12-byte IV and a ciphertext at least as long as the tag.
 * @param {unknown} box
 * @returns {{ iterations: number, salt: Uint8Array, iv: Uint8Array, data: Uint8Array, saltText: string, ivText: string }}
 */
export function checkBox(box) {
  if (!box || typeof box !== 'object') throw new BoxError('damaged', 'no box');
  const { kdf, cipher } = box;
  if (!kdf || typeof kdf !== 'object' || !cipher || typeof cipher !== 'object') throw new BoxError('damaged', 'no parameters');
  if (kdf.name !== KDF_NAME || kdf.hash !== KDF_HASH || cipher.name !== CIPHER_NAME) throw new BoxError('unsupported', 'unknown algorithm');
  const iterations = kdf.iterations;
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new BoxError('damaged', 'iteration count out of range');
  }
  const salt = decodeBase64(kdf.salt);
  const iv = decodeBase64(cipher.iv);
  const data = decodeBase64(box.data);
  if (salt.length !== SALT_BYTES || iv.length !== IV_BYTES || data.length < TAG_BYTES) throw new BoxError('damaged', 'wrong lengths');
  return { iterations, salt, iv, data, saltText: kdf.salt, ivText: cipher.iv };
}

/**
 * Encrypt `text` with a password.
 * @param {string} text
 * @param {string} password at least MIN_PASSWORD_LENGTH characters
 * @param {{ iterations?: number, context?: string, crypto?: Crypto }} [opts] `context`: bound to the
 *   box as additional data; openText needs the same
 * @returns {Promise<{ kdf: { name: string, hash: string, iterations: number, salt: string },
 *   cipher: { name: string, iv: string }, data: string }>}
 */
export async function sealText(text, password, { iterations = DEFAULT_ITERATIONS, context = '', crypto = globalThis.crypto } = {}) {
  if (typeof password !== 'string' || !password) throw new BoxError('password-required');
  if ([...password.normalize('NFC')].length < MIN_PASSWORD_LENGTH) throw new BoxError('password-short');
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new RangeError(`iterations must be an integer from ${MIN_ITERATIONS} to ${MAX_ITERATIONS}`);
  }
  const wc = webCrypto(crypto);
  const salt = wc.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = wc.getRandomValues(new Uint8Array(IV_BYTES));
  const saltText = encodeBase64(salt);
  const ivText = encodeBase64(iv);
  const key = await deriveKey(wc.subtle, password, salt, iterations);
  const sealed = await wc.subtle.encrypt(
    { name: CIPHER_NAME, iv, additionalData: boxAad(context, iterations, saltText, ivText), tagLength: TAG_BYTES * 8 },
    key,
    new TextEncoder().encode(String(text))
  );
  return {
    kdf: { name: KDF_NAME, hash: KDF_HASH, iterations, salt: saltText },
    cipher: { name: CIPHER_NAME, iv: ivText },
    data: encodeBase64(new Uint8Array(sealed))
  };
}

/**
 * Decrypt a box made by {@link sealText}.
 * @param {object} box
 * @param {string} password
 * @param {{ context?: string, crypto?: Crypto }} [opts]
 * @returns {Promise<string>}
 * @throws {BoxError} 'password-required', 'damaged', 'unsupported', 'wrong-password' (or a changed box),
 *   'crypto-unavailable'
 */
export async function openText(box, password, { context = '', crypto = globalThis.crypto } = {}) {
  const params = checkBox(box);
  if (typeof password !== 'string' || !password) throw new BoxError('password-required');
  const wc = webCrypto(crypto);
  const key = await deriveKey(wc.subtle, password, params.salt, params.iterations);
  let plain;
  try {
    plain = await wc.subtle.decrypt(
      { name: CIPHER_NAME, iv: params.iv, additionalData: boxAad(context, params.iterations, params.saltText, params.ivText), tagLength: TAG_BYTES * 8 },
      key,
      params.data
    );
  } catch {
    // OperationError: the tag does not verify — a wrong password, or the box was changed.
    throw new BoxError('wrong-password');
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(plain);
  } catch {
    throw new BoxError('damaged', 'not UTF-8');
  }
}
