/**
 * zonetext.js — the small text helpers the zone file formats share: a Route 53 character-string,
 * a YAML scalar octoDNS reads back as written, octoDNS's TXT form and its key order.
 * lib/zoneconvert.js writes whole zones with them and lib/fixes.js a change request's entries,
 * so the change request, its check page and "Show the fix" never load the zone converter.
 *
 * Pure, synchronous, DOM-free and without imports. Runs in browsers and Node 22.
 */

const utf8 = new TextEncoder();
const octal = (b) => `\\${b.toString(8).padStart(3, '0')}`;

/**
 * A character-string as Route 53 reads it: quoted, `"` and `\` escaped, every byte outside
 * printable ASCII as a three-digit octal escape (Route 53's own escape form, never \DDD decimal).
 * @param {string} s
 * @returns {string}
 */
export function route53String(s) {
  let out = '"';
  for (const b of utf8.encode(String(s ?? ''))) {
    if (b === 0x22 || b === 0x5c) out += `\\${String.fromCharCode(b)}`;
    else if (b >= 0x20 && b <= 0x7e) out += String.fromCharCode(b);
    else out += octal(b);
  }
  return `${out}"`;
}

/**
 * Plain scalars YAML 1.1 (PyYAML, which octoDNS reads with) takes for something other than a
 * string: booleans, null, and the numbers and dates it resolves: `0x1f`, `0b101`, `1_000`,
 * `017`, `1.5e3`, `2026-10-02` and the like (digits, dots, underscores, signs and `e`).
 */
const YAML_NOT_A_STRING = /^(?:true|false|yes|no|on|off|null|~|0b[01_]+|0x[0-9a-f_]+|\d[\d._e+-]*)$/i;

/**
 * A YAML scalar: plain when it is a plain name or word that YAML cannot read as anything else,
 * single-quoted otherwise, double-quoted with escapes when it holds a control character.
 * @param {string} s
 * @returns {string}
 */
export function yamlString(s) {
  const v = String(s ?? '');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\u2028\u2029]/.test(v)) {
    return `"${[...v].map((ch) => {
      const cp = ch.codePointAt(0);
      if (ch === '"' || ch === '\\') return `\\${ch}`;
      if (cp < 0x20 || cp === 0x7f) return `\\x${cp.toString(16).padStart(2, '0')}`;
      if (cp === 0x2028 || cp === 0x2029) return `\\u${cp.toString(16)}`;
      return ch;
    }).join('')}"`;
  }
  return /^[a-z0-9_][a-z0-9._-]*$/i.test(v) && !YAML_NOT_A_STRING.test(v) ? v : `'${v.replace(/'/g, "''")}'`;
}

/**
 * The text of a TXT value as octoDNS keeps it: the character-strings joined, the raw text with
 * every `;` escaped as `\;` and nothing else (octoDNS refuses a bare `;`; a `\` is a backslash).
 * @param {string[]|string} data
 * @returns {string}
 */
export function octodnsTxt(data) {
  return (Array.isArray(data) ? data : [data]).map((x) => String(x ?? '')).join('').replace(/;/g, '\\;');
}

/**
 * Does octoDNS's check of TXT values (chunked-value-rfc) refuse this text: a character outside
 * ASCII, or a `\` before a `;` (which it takes for a `;` escaped twice)? Such a record is written
 * with `octodns: lenient: true` (lib/zoneconvert.js and lib/fixes.js): octoDNS then loads it
 * with a warning.
 * @param {string} escaped the text as {@link octodnsTxt} writes it
 * @returns {boolean}
 */
// eslint-disable-next-line no-control-regex
export const octodnsTxtRefused = (escaped) => /[^\x00-\x7f]/.test(escaped) || String(escaped).includes('\\\\;');

/**
 * Natural order of two strings as octoDNS checks its keys (YamlProvider's default `order_mode`,
 * Python's `natsort_keygen()`): the key is a tuple of text and numbers taking turns, always text
 * first ('' when the string starts with a digit), runs of digits compared as whole numbers of any
 * size ('007' = '7': equal keys keep their order), the text by code point; a tuple that is a
 * prefix of the other sorts first.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function naturalCompare(a, b) {
  const key = (s) => {
    const parts = String(s).split(/(\d+)/);
    if (parts.length > 1 && parts[parts.length - 1] === '') parts.pop();
    if (parts.length === 1 && parts[0] === '') return [];
    return parts.map((p, i) => (i % 2 ? BigInt(p) : p));
  };
  const ka = key(a);
  const kb = key(b);
  for (let i = 0; i < Math.min(ka.length, kb.length); i += 1) {
    const x = ka[i];
    const y = kb[i];
    if (x === y) continue;
    return x < y ? -1 : 1;
  }
  return ka.length - kb.length;
}
