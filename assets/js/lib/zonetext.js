/**
 * zonetext.js — the small text helpers the zone file formats share: a Route 53 character-string,
 * a YAML scalar octoDNS reads back as written, octoDNS's TXT form and its key order.
 * lib/zoneconvert.js writes whole zones with them and lib/fixes.js a change request's entries,
 * so the change request, its check page and "Show the fix" never load the zone converter.
 *
 * Pure, synchronous, DOM-free and without imports. Runs in browsers and Node 22.
 */

const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });
const octal = (b) => `\\${b.toString(8).padStart(3, '0')}`;

/* ------------------------------------------------------------------------ */
/* A TXT record's character-strings as bytes                                */
/* ------------------------------------------------------------------------ */

/**
 * The character-strings of a TXT-like presentation text as bytes: quoted strings or bare words,
 * `\DDD` a byte, `\X` the character X, any other character its UTF-8 bytes. lib/zoneparse.js
 * writes a TXT record's `text` so (its `data` decodes each string on its own, so a character
 * split across two strings, or a byte that is not UTF-8, cannot be told from it).
 * @param {string} text e.g. `"a\195" "\188b"`
 * @returns {Uint8Array[]}
 */
export function charStringBytes(text) {
  const s = String(text ?? '');
  const out = [];
  let i = 0;
  while (i < s.length) {
    while (i < s.length && (s[i] === ' ' || s[i] === '\t')) i += 1;
    if (i >= s.length) break;
    const quoted = s[i] === '"';
    if (quoted) i += 1;
    const bytes = [];
    let run = '';
    const flush = () => {
      if (run) for (const b of utf8.encode(run)) bytes.push(b);
      run = '';
    };
    while (i < s.length) {
      const c = s[i];
      if (quoted ? c === '"' : c === ' ' || c === '\t') break;
      if (c === '\\' && i + 1 < s.length) {
        flush();
        const d = s.slice(i + 1, i + 4);
        if (/^\d{3}$/.test(d)) {
          bytes.push(Number(d) & 0xff);
          i += 4;
        } else {
          const cp = s.codePointAt(i + 1);
          run = String.fromCodePoint(cp);
          flush();
          i += cp > 0xffff ? 3 : 2;
        }
        continue;
      }
      run += c;
      i += 1;
    }
    flush();
    if (quoted) i += 1;
    out.push(Uint8Array.from(bytes));
  }
  return out;
}

/**
 * A TXT / SPF record's character-strings as bytes (lib/zoneparse.js ZoneRecord): read from its
 * presentation text, which holds them exactly; else (no text) its decoded strings as UTF-8.
 * @param {{ text?: string, data?: string[]|string }} record
 * @returns {Uint8Array[]}
 */
export function txtBytes(record) {
  if (typeof record.text === 'string' && record.text) return charStringBytes(record.text);
  return (Array.isArray(record.data) ? record.data : [record.data]).map((s) => utf8.encode(String(s ?? '')));
}

/**
 * Byte strings joined into one.
 * @param {Uint8Array[]} list
 * @returns {Uint8Array}
 */
export function joinBytes(list) {
  const out = new Uint8Array(list.reduce((n, b) => n + b.length, 0));
  let at = 0;
  for (const b of list) {
    out.set(b, at);
    at += b.length;
  }
  return out;
}

/**
 * The UTF-8 text of bytes, or null when they are not UTF-8.
 * @param {Uint8Array} bytes
 * @returns {string|null}
 */
export function utf8Text(bytes) {
  try {
    return utf8Strict.decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Bytes cut into character-strings of at most 255 bytes (RFC 1035 §3.3; one empty string for none).
 * @param {Uint8Array} bytes
 * @returns {Uint8Array[]}
 */
export function split255(bytes) {
  if (!bytes.length) return [bytes];
  const out = [];
  for (let i = 0; i < bytes.length; i += 255) out.push(bytes.subarray(i, i + 255));
  return out;
}

/* ------------------------------------------------------------------------ */
/* Route 53, YAML, octoDNS                                                  */
/* ------------------------------------------------------------------------ */

/**
 * A character-string as Route 53 reads it: quoted, `"` and `\` escaped, every byte outside
 * printable ASCII as a three-digit octal escape (Route 53's own escape form, never \DDD decimal).
 * @param {string|Uint8Array} s a string (written as its UTF-8 bytes) or the bytes themselves
 * @returns {string}
 */
export function route53String(s) {
  let out = '"';
  for (const b of s instanceof Uint8Array ? s : utf8.encode(String(s ?? ''))) {
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

/** Is every character printable ASCII (U+0020 to U+007E)? */
function printableAscii(v) {
  for (let i = 0; i < v.length; i += 1) {
    const c = v.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

/** One character as a YAML double-quoted escape: `\xHH`, `\uHHHH` or `\UHHHHHHHH`. */
function yamlEscape(cp) {
  if (cp < 0x100) return `\\x${cp.toString(16).padStart(2, '0')}`;
  if (cp < 0x10000) return `\\u${cp.toString(16).padStart(4, '0')}`;
  return `\\U${cp.toString(16).padStart(8, '0')}`;
}

/**
 * A YAML scalar: plain when it is a plain name or word that YAML cannot read as anything else,
 * single-quoted otherwise, and double-quoted with every character outside printable ASCII
 * escaped when it holds one \u2014 PyYAML (octoDNS) refuses a whole file over a C1 control, U+FFFE or
 * U+FFFF written raw and folds a raw NEL, LS or PS, and octoDNS reads its files in the system's
 * code page on Windows: what this writes is ASCII only.
 * @param {string} s
 * @returns {string}
 */
export function yamlString(s) {
  const v = String(s ?? '');
  if (!printableAscii(v)) {
    let out = '"';
    for (const ch of v) {
      const cp = ch.codePointAt(0);
      if (ch === '"' || ch === '\\') out += `\\${ch}`;
      else if (cp >= 0x20 && cp <= 0x7e) out += ch;
      else out += yamlEscape(cp);
    }
    return `${out}"`;
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
