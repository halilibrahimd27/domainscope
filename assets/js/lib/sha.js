/**
 * SHA-1 and SHA-256 in pure JS (FIPS 180-4), synchronous, for the browser and Node.
 *
 * WebCrypto's `digest` is asynchronous and missing where the page is not a secure context (plain
 * http). Two places need a hash without it: certificate fingerprints in such a page (lib/x509.js
 * falls back to these) and the PKCS#12 key derivation of lib/pkcs12.js, which hashes its own
 * output thousands of times in a row — one await per round would make a legacy .pfx slow to open.
 * DOM-free and dependency-free.
 */

/** The message padded to whole 64-byte blocks: 0x80, zeros, the bit length (big-endian 64 bits). */
function padMessage(bytes) {
  const total = (Math.floor((bytes.length + 8) / 64) + 1) * 64;
  const out = new Uint8Array(total);
  out.set(bytes);
  out[bytes.length] = 0x80;
  const bitLen = bytes.length * 8;
  const view = new DataView(out.buffer);
  view.setUint32(total - 8, Math.floor(bitLen / 2 ** 32));
  view.setUint32(total - 4, bitLen >>> 0);
  return view;
}

/** 32-bit words → big-endian bytes. */
function wordsToBytes(words) {
  const out = new Uint8Array(words.length * 4);
  const view = new DataView(out.buffer);
  words.forEach((w, i) => view.setUint32(i * 4, w));
  return out;
}

const SHA256_K = (() => {
  // First 32 bits of the fractional parts of the cube roots of the first 64 primes
  // (and of the square roots of the first 8 for the initial hash value).
  const k = new Uint32Array(64);
  const h = new Uint32Array(8);
  let n = 0;
  for (let p = 2; n < 64; p++) {
    let prime = true;
    for (let d = 2; d * d <= p; d++) if (p % d === 0) { prime = false; break; }
    if (!prime) continue;
    if (n < 8) h[n] = (Math.sqrt(p) % 1) * 2 ** 32;
    k[n++] = (Math.cbrt(p) % 1) * 2 ** 32;
  }
  return { k, h };
})();

/**
 * SHA-256 of `bytes`.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array} 32 bytes
 */
export function sha256(bytes) {
  const view = padMessage(bytes);
  const H = Uint32Array.from(SHA256_K.h);
  const K = SHA256_K.k;
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < view.byteLength; off += 64) {
    for (let t = 0; t < 16; t++) W[t] = view.getUint32(off + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = W[t - 16] + s0 + W[t - 7] + s1;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + W[t]) | 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  return wordsToBytes(H);
}

/**
 * SHA-1 of `bytes`.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array} 20 bytes
 */
export function sha1(bytes) {
  const view = padMessage(bytes);
  const H = Uint32Array.of(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0);
  const W = new Uint32Array(80);
  const rotl = (x, n) => (x << n) | (x >>> (32 - n));
  for (let off = 0; off < view.byteLength; off += 64) {
    for (let t = 0; t < 16; t++) W[t] = view.getUint32(off + t * 4);
    for (let t = 16; t < 80; t++) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    let [a, b, c, d, e] = H;
    for (let t = 0; t < 80; t++) {
      let f;
      let k;
      if (t < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (t < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const temp = (rotl(a, 5) + f + e + k + W[t]) | 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = temp;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e;
  }
  return wordsToBytes(H);
}
