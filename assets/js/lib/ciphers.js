/**
 * Small pure-JS block ciphers for reading PKCS#12 bundles (lib/pkcs12.js): CBC decryption with
 * DES / two- and three-key DES-EDE (3DES, FIPS 46-3 / SP 800-67), RC2 (RFC 2268) and AES
 * (FIPS 197). Decryption only; the PKCS#5 / PKCS#7 padding is checked and removed.
 *
 * WebCrypto has no DES or RC2, yet Windows, older Java and `openssl pkcs12 -legacy` still write
 * .pfx files with them. AES normally goes through WebCrypto; this AES is the fallback for the
 * AES-192 that Chromium's WebCrypto refuses. None of this protects anything new: it only opens
 * what the user already holds the password for. DOM-free and dependency-free.
 */

/** A ciphertext that cannot be decrypted: a length that is not whole blocks, or bad padding. */
export class CipherError extends Error {
  /**
   * @param {'length'|'padding'|'key'} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = 'CipherError';
    this.code = code;
  }
}

/**
 * CBC decryption of whole blocks with `decryptBlock(src, srcOffset, dst, dstOffset)`, then the
 * padding check: the last byte n (1..blockSize) and n bytes of n.
 */
function cbcDecrypt(decryptBlock, blockSize, iv, data, padding) {
  if (!(iv instanceof Uint8Array) || iv.length !== blockSize) throw new CipherError('key', `The IV must be ${blockSize} bytes`);
  if (!data.length || data.length % blockSize) throw new CipherError('length', `The ciphertext is not a whole number of ${blockSize}-byte blocks`);
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += blockSize) {
    decryptBlock(data, off, out, off);
    for (let i = 0; i < blockSize; i++) out[off + i] ^= off ? data[off - blockSize + i] : iv[i];
  }
  if (!padding) return out;
  const n = out[out.length - 1];
  let bad = n < 1 || n > blockSize;
  for (let i = 1; !bad && i <= n; i++) bad = out[out.length - i] !== n;
  if (bad) {
    out.fill(0);
    throw new CipherError('padding', 'Bad padding after decryption');
  }
  return out.subarray(0, out.length - n);
}

// ---------------------------------------------------------------------------
// DES and DES-EDE (FIPS 46-3 tables, bit positions counted from 1 at the most significant bit)
// ---------------------------------------------------------------------------

const DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const DES_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
const DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
const DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
  19, 13, 30, 6, 22, 11, 4, 25];
const DES_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
  29, 21, 13, 5, 28, 20, 12, 4];
const DES_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
const DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const DES_S = [
  '14 4 13 1 2 15 11 8 3 10 6 12 5 9 0 7 0 15 7 4 14 2 13 1 10 6 12 11 9 5 3 8 4 1 14 8 13 6 2 11 15 12 9 7 3 10 5 0 15 12 8 2 4 9 1 7 5 11 3 14 10 0 6 13',
  '15 1 8 14 6 11 3 4 9 7 2 13 12 0 5 10 3 13 4 7 15 2 8 14 12 0 1 10 6 9 11 5 0 14 7 11 10 4 13 1 5 8 12 6 9 3 2 15 13 8 10 1 3 15 4 2 11 6 7 12 0 5 14 9',
  '10 0 9 14 6 3 15 5 1 13 12 7 11 4 2 8 13 7 0 9 3 4 6 10 2 8 5 14 12 11 15 1 13 6 4 9 8 15 3 0 11 1 2 12 5 10 14 7 1 10 13 0 6 9 8 7 4 15 14 3 11 5 2 12',
  '7 13 14 3 0 6 9 10 1 2 8 5 11 12 4 15 13 8 11 5 6 15 0 3 4 7 2 12 1 10 14 9 10 6 9 0 12 11 7 13 15 1 3 14 5 2 8 4 3 15 0 6 10 1 13 8 9 4 5 11 12 7 2 14',
  '2 12 4 1 7 10 11 6 8 5 3 15 13 0 14 9 14 11 2 12 4 7 13 1 5 0 15 10 3 9 8 6 4 2 1 11 10 13 7 8 15 9 12 5 6 3 0 14 11 8 12 7 1 14 2 13 6 15 0 9 10 4 5 3',
  '12 1 10 15 9 2 6 8 0 13 3 4 14 7 5 11 10 15 4 2 7 12 9 5 6 1 13 14 0 11 3 8 9 14 15 5 2 8 12 3 7 0 4 10 1 13 11 6 4 3 2 12 9 5 15 10 11 14 1 7 6 0 8 13',
  '4 11 2 14 15 0 8 13 3 12 9 7 5 10 6 1 13 0 11 7 4 9 1 10 14 3 5 12 2 15 8 6 1 4 11 13 12 3 7 14 10 15 6 8 0 5 9 2 6 11 13 8 1 4 10 7 9 5 0 15 14 2 3 12',
  '13 2 8 4 6 15 11 1 10 9 3 14 5 0 12 7 1 15 13 8 10 3 7 4 12 5 6 11 0 14 9 2 7 11 4 1 9 12 14 2 0 6 10 13 15 3 5 8 2 1 14 7 4 10 8 13 15 12 9 0 3 5 6 11'
].map((row) => Uint8Array.from(row.split(' '), Number));

const permute = (bits, table) => Uint8Array.from(table, (p) => bits[p - 1]);

function toBits(bytes, offset, count) {
  const bits = new Uint8Array(count * 8);
  for (let i = 0; i < bits.length; i++) bits[i] = (bytes[offset + (i >> 3)] >> (7 - (i & 7))) & 1;
  return bits;
}

/** The 16 round keys (48 bits each) of an 8-byte DES key; parity bits are ignored. */
function desSubkeys(key, offset) {
  const cd = permute(toBits(key, offset, 8), DES_PC1);
  let c = cd.subarray(0, 28);
  let d = cd.subarray(28);
  const rotate = (half, n) => Uint8Array.from(half, (_, i) => half[(i + n) % 28]);
  return DES_SHIFTS.map((n) => {
    c = rotate(c, n);
    d = rotate(d, n);
    const joined = new Uint8Array(56);
    joined.set(c);
    joined.set(d, 28);
    return permute(joined, DES_PC2);
  });
}

/** DES on one block: the rounds with `subkeys` in the given order (reversed = decryption). */
function desBlock(subkeys, src, srcOffset, dst, dstOffset) {
  const block = permute(toBits(src, srcOffset, 8), DES_IP);
  let l = block.subarray(0, 32);
  let r = block.subarray(32);
  for (const k of subkeys) {
    const x = permute(r, DES_E);
    for (let i = 0; i < 48; i++) x[i] ^= k[i];
    const s = new Uint8Array(32);
    for (let box = 0; box < 8; box++) {
      const b = x.subarray(box * 6, box * 6 + 6);
      const v = DES_S[box][((b[0] << 1) | b[5]) * 16 + ((b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4])];
      for (let i = 0; i < 4; i++) s[box * 4 + i] = (v >> (3 - i)) & 1;
    }
    const f = permute(s, DES_P);
    const next = Uint8Array.from(l, (bit, i) => bit ^ f[i]);
    l = r;
    r = next;
  }
  const preout = new Uint8Array(64);
  preout.set(r);
  preout.set(l, 32);
  const out = permute(preout, DES_FP);
  for (let i = 0; i < 8; i++) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | out[i * 8 + j];
    dst[dstOffset + i] = v;
  }
}

/**
 * DES-EDE CBC decryption (3DES): 24-byte keys are K1 K2 K3, 16-byte keys two-key 3DES (K3 = K1)
 * and 8-byte keys single DES (K1 = K2 = K3).
 * @param {Uint8Array} key 8, 16 or 24 bytes
 * @param {Uint8Array} iv 8 bytes
 * @param {Uint8Array} data whole 8-byte blocks
 * @param {{ padding?: boolean }} [options] padding: check and remove the PKCS#5 padding (default)
 * @returns {Uint8Array}
 * @throws {CipherError}
 */
export function desEde3CbcDecrypt(key, iv, data, { padding = true } = {}) {
  if (![8, 16, 24].includes(key.length)) throw new CipherError('key', 'A DES / 3DES key has 8, 16 or 24 bytes');
  const k1 = desSubkeys(key, 0);
  const k2 = key.length > 8 ? desSubkeys(key, 8) : k1;
  const k3 = key.length > 16 ? desSubkeys(key, 16) : k1;
  const [d1, e2, d3] = [[...k1].reverse(), k2, [...k3].reverse()];
  const tmp = new Uint8Array(8);
  // EDE decryption: D(K1, E(K2, D(K3, block))).
  return cbcDecrypt((src, so, dst, doff) => {
    desBlock(d3, src, so, tmp, 0);
    desBlock(e2, tmp, 0, tmp, 0);
    desBlock(d1, tmp, 0, dst, doff);
  }, 8, iv, data, padding);
}

// ---------------------------------------------------------------------------
// RC2 (RFC 2268)
// ---------------------------------------------------------------------------

/** PITABLE of RFC 2268 section 2: a permutation of 0..255 derived from the digits of pi. */
const RC2_PITABLE = Uint8Array.from([
  'd9 78 f9 c4 19 dd b5 ed 28 e9 fd 79 4a a0 d8 9d', 'c6 7e 37 83 2b 76 53 8e 62 4c 64 88 44 8b fb a2',
  '17 9a 59 f5 87 b3 4f 13 61 45 6d 8d 09 81 7d 32', 'bd 8f 40 eb 86 b7 7b 0b f0 95 21 22 5c 6b 4e 82',
  '54 d6 65 93 ce 60 b2 1c 73 56 c0 14 a7 8c f1 dc', '12 75 ca 1f 3b be e4 d1 42 3d d4 30 a3 3c b6 26',
  '6f bf 0e da 46 69 07 57 27 f2 1d 9b bc 94 43 03', 'f8 11 c7 f6 90 ef 3e e7 06 c3 d5 2f c8 66 1e d7',
  '08 e8 ea de 80 52 ee f7 84 aa 72 ac 35 4d 6a 2a', '96 1a d2 71 5a 15 49 74 4b 9f d0 5e 04 18 a4 ec',
  'c2 e0 41 6e 0f 51 cb cc 24 91 af 50 a1 f4 70 39', '99 7c 3a 85 23 b8 b4 7a fc 02 36 5b 25 55 97 31',
  '2d 5d fa 98 e3 8a 92 ae 05 df 29 10 67 6c ba c9', 'd3 00 e6 cf e1 9e a8 2c 63 16 01 3f 58 e2 89 a9',
  '0d 38 34 1b ab 33 ff b0 bb 48 0c 5f b9 b1 cd 2e', 'c5 f3 db 47 e5 a5 9c 77 0a a6 20 68 fe 7f c1 ad'
].join(' ').split(' '), (x) => parseInt(x, 16));

/** The 64 key words of an RC2 key with `bits` effective key bits (RFC 2268 section 2). */
function rc2Expand(key, bits) {
  if (key.length < 1 || key.length > 128) throw new CipherError('key', 'An RC2 key has 1 to 128 bytes');
  if (!Number.isInteger(bits) || bits < 1 || bits > 1024) throw new CipherError('key', 'RC2 effective key bits must be 1 to 1024');
  const L = new Uint8Array(128);
  L.set(key);
  const T = key.length;
  const T8 = Math.ceil(bits / 8);
  const TM = 0xff >> (8 * T8 - bits);
  for (let i = T; i < 128; i++) L[i] = RC2_PITABLE[(L[i - 1] + L[i - T]) & 0xff];
  L[128 - T8] = RC2_PITABLE[L[128 - T8] & TM];
  for (let i = 127 - T8; i >= 0; i--) L[i] = RC2_PITABLE[L[i + 1] ^ L[i + T8]];
  const K = new Uint16Array(64);
  for (let i = 0; i < 64; i++) K[i] = L[2 * i] | (L[2 * i + 1] << 8);
  return K;
}

function rc2DecryptBlock(K, src, so, dst, doff) {
  const R = new Uint16Array(4);
  for (let i = 0; i < 4; i++) R[i] = src[so + 2 * i] | (src[so + 2 * i + 1] << 8);
  const S = [1, 2, 3, 5];
  let j = 63;
  const mixUp = () => {
    for (let i = 3; i >= 0; i--) {
      const x = R[i];
      R[i] = (x >>> S[i]) | (x << (16 - S[i])); // rotate right in 16 bits (Uint16Array truncates)
      R[i] -= K[j] + (R[(i + 3) & 3] & R[(i + 2) & 3]) + (~R[(i + 3) & 3] & R[(i + 1) & 3]);
      j -= 1;
    }
  };
  const mashUp = () => {
    for (let i = 3; i >= 0; i--) R[i] -= K[R[(i + 3) & 3] & 63];
  };
  for (let i = 0; i < 5; i++) mixUp();
  mashUp();
  for (let i = 0; i < 6; i++) mixUp();
  mashUp();
  for (let i = 0; i < 5; i++) mixUp();
  for (let i = 0; i < 4; i++) {
    dst[doff + 2 * i] = R[i] & 0xff;
    dst[doff + 2 * i + 1] = R[i] >> 8;
  }
}

/**
 * RC2 CBC decryption (RFC 2268).
 * @param {Uint8Array} key 1 to 128 bytes
 * @param {number} effectiveBits effective key bits (40 for RC2-40, 128 for RC2-128)
 * @param {Uint8Array} iv 8 bytes
 * @param {Uint8Array} data whole 8-byte blocks
 * @param {{ padding?: boolean }} [options]
 * @returns {Uint8Array}
 * @throws {CipherError}
 */
export function rc2CbcDecrypt(key, effectiveBits, iv, data, { padding = true } = {}) {
  const K = rc2Expand(key, effectiveBits);
  return cbcDecrypt((src, so, dst, doff) => rc2DecryptBlock(K, src, so, dst, doff), 8, iv, data, padding);
}

// ---------------------------------------------------------------------------
// AES (FIPS 197), byte-oriented
// ---------------------------------------------------------------------------

const AES = (() => {
  const sbox = new Uint8Array(256);
  const inv = new Uint8Array(256);
  const rotl8 = (x, n) => ((x << n) | (x >> (8 - n))) & 0xff;
  // p runs through the multiplicative group (× 3), q through its inverses (÷ 3).
  let p = 1;
  let q = 1;
  do {
    p = (p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0)) & 0xff;
    q ^= q << 1;
    q ^= q << 2;
    q ^= q << 4;
    q &= 0xff;
    if (q & 0x80) q ^= 0x09;
    sbox[p] = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63;
  } while (p !== 1);
  sbox[0] = 0x63;
  for (let i = 0; i < 256; i++) inv[sbox[i]] = i;
  return { sbox, inv };
})();

/** GF(2^8) multiplication (AES polynomial x^8 + x^4 + x^3 + x + 1). */
function gmul(a, b) {
  let out = 0;
  for (let i = 0; i < 8 && b; i++, b >>= 1) {
    if (b & 1) out ^= a;
    a = (a << 1) ^ (a & 0x80 ? 0x11b : 0);
  }
  return out;
}

/** The round keys of a 16-, 24- or 32-byte AES key: 16 bytes per round. */
function aesExpand(key) {
  if (![16, 24, 32].includes(key.length)) throw new CipherError('key', 'An AES key has 16, 24 or 32 bytes');
  const nk = key.length / 4;
  const rounds = nk + 6;
  const w = new Uint8Array(16 * (rounds + 1));
  w.set(key);
  let rcon = 1;
  for (let i = nk; i < 4 * (rounds + 1); i++) {
    let t = w.slice(4 * (i - 1), 4 * i);
    if (i % nk === 0) {
      t = Uint8Array.of(AES.sbox[t[1]] ^ rcon, AES.sbox[t[2]], AES.sbox[t[3]], AES.sbox[t[0]]);
      rcon = gmul(rcon, 2);
    } else if (nk > 6 && i % nk === 4) {
      t = t.map((b) => AES.sbox[b]);
    }
    for (let j = 0; j < 4; j++) w[4 * i + j] = w[4 * (i - nk) + j] ^ t[j];
  }
  return { w, rounds };
}

function aesDecryptBlock({ w, rounds }, src, so, dst, doff) {
  const s = new Uint8Array(16); // a copy: Buffer#slice would be a view of the ciphertext
  s.set(src.subarray(so, so + 16));
  const addKey = (round) => {
    for (let i = 0; i < 16; i++) s[i] ^= w[16 * round + i];
  };
  const invShiftSub = () => {
    const t = s.slice();
    // State bytes are column-major: s[row + 4 * col]; row r shifts right by r.
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) s[r + 4 * ((c + r) % 4)] = AES.inv[t[r + 4 * c]];
  };
  addKey(rounds);
  for (let round = rounds - 1; round >= 0; round--) {
    invShiftSub();
    addKey(round);
    if (!round) break;
    for (let c = 0; c < 4; c++) {
      const [a0, a1, a2, a3] = s.subarray(4 * c, 4 * c + 4);
      s[4 * c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
      s[4 * c + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
      s[4 * c + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
      s[4 * c + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
  }
  dst.set(s, doff);
}

/**
 * AES CBC decryption (128-, 192- or 256-bit keys).
 * @param {Uint8Array} key 16, 24 or 32 bytes
 * @param {Uint8Array} iv 16 bytes
 * @param {Uint8Array} data whole 16-byte blocks
 * @param {{ padding?: boolean }} [options]
 * @returns {Uint8Array}
 * @throws {CipherError}
 */
export function aesCbcDecrypt(key, iv, data, { padding = true } = {}) {
  const schedule = aesExpand(key);
  return cbcDecrypt((src, so, dst, doff) => aesDecryptBlock(schedule, src, so, dst, doff), 16, iv, data, padding);
}
