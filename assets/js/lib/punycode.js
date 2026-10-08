/**
 * punycode.js — RFC 3492 punycode of one DNS label, both ways (`bücher` ⇄ `bcher-kva`, without
 * the `xn--` prefix). Shared by the lookalike generator (lib/lookalike.js, which re-exports both)
 * and the adaptive locale packs (lib/localeevidence.js, which reads the letters of an IDN label).
 *
 * DOM-free, no I/O.
 */

const PC_BASE = 36;
const PC_TMIN = 1;
const PC_TMAX = 26;
const PC_SKEW = 38;
const PC_DAMP = 700;
const PC_BIAS = 72;
const PC_N = 128;

function adapt(delta, points, first) {
  let d = first ? Math.floor(delta / PC_DAMP) : delta >> 1;
  d += Math.floor(d / points);
  let k = 0;
  while (d > ((PC_BASE - PC_TMIN) * PC_TMAX) >> 1) {
    d = Math.floor(d / (PC_BASE - PC_TMIN));
    k += PC_BASE;
  }
  return k + Math.floor(((PC_BASE - PC_TMIN + 1) * d) / (d + PC_SKEW));
}

const threshold = (k, bias) => (k <= bias ? PC_TMIN : k >= bias + PC_TMAX ? PC_TMAX : k - bias);
const digitChar = (d) => String.fromCharCode(d < 26 ? 97 + d : 22 + d);

/**
 * Punycode of one label (RFC 3492), without the `xn--` prefix: `bücher` → `bcher-kva`.
 * @param {string} label lower case, NFC
 * @returns {string}
 */
export function punycodeEncode(label) {
  const cps = Array.from(String(label), (c) => c.codePointAt(0));
  let out = cps.filter((c) => c < 0x80).map((c) => String.fromCharCode(c)).join('');
  const basic = out.length;
  let handled = basic;
  if (basic > 0) out += '-';
  let n = PC_N;
  let delta = 0;
  let bias = PC_BIAS;
  while (handled < cps.length) {
    let m = Infinity;
    for (const c of cps) if (c >= n && c < m) m = c;
    delta += (m - n) * (handled + 1);
    n = m;
    for (const c of cps) {
      if (c < n) delta += 1;
      if (c !== n) continue;
      let q = delta;
      for (let k = PC_BASE; ; k += PC_BASE) {
        const t = threshold(k, bias);
        if (q < t) break;
        out += digitChar(t + ((q - t) % (PC_BASE - t)));
        q = Math.floor((q - t) / (PC_BASE - t));
      }
      out += digitChar(q);
      bias = adapt(delta, handled + 1, handled === basic);
      delta = 0;
      handled += 1;
    }
    delta += 1;
    n += 1;
  }
  return out;
}

function digitValue(code) {
  if (code >= 48 && code <= 57) return code - 22;
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 97;
  return PC_BASE;
}

/**
 * The Unicode text of a punycode label (without `xn--`), or null when it is not valid punycode.
 * @param {string} input
 * @returns {string|null}
 */
export function punycodeDecode(input) {
  const s = String(input);
  let basic = s.lastIndexOf('-');
  if (basic < 0) basic = 0;
  const out = [];
  for (let j = 0; j < basic; j += 1) {
    const c = s.charCodeAt(j);
    if (c >= 0x80) return null;
    out.push(c);
  }
  let n = PC_N;
  let bias = PC_BIAS;
  let i = 0;
  for (let idx = basic > 0 ? basic + 1 : 0; idx < s.length;) {
    const old = i;
    let w = 1;
    for (let k = PC_BASE; ; k += PC_BASE) {
      if (idx >= s.length) return null;
      const d = digitValue(s.charCodeAt(idx));
      idx += 1;
      if (d >= PC_BASE) return null;
      i += d * w;
      const t = threshold(k, bias);
      if (d < t) break;
      w *= PC_BASE - t;
      if (i > 0x7fffffff || w > 0x7fffffff) return null;
    }
    const len = out.length + 1;
    bias = adapt(i - old, len, old === 0);
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10ffff) return null;
    out.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...out);
}
