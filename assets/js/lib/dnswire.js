/**
 * DNS wire format (RFC 1035) encoder / decoder for DNS-over-HTTPS (RFC 8484).
 *
 * Pure, DOM-free and dependency-free: runs unchanged in browsers and Node 22.
 *
 * - `encodeQuery()` builds a query message that always carries an EDNS(0) OPT
 *   record (RFC 6891) with optional DO / CD flags and EDNS Client Subnet
 *   (RFC 7871, IPv4 + IPv6).
 * - `decodeMessage()` is a hardened decoder for untrusted input: every read is
 *   bounds-checked, name compression pointers are loop-protected, and malformed
 *   structure raises `DnsWireError` (never a RangeError/TypeError). Malformed
 *   RDATA of a single record does not fail the whole message: that record is
 *   degraded to the RFC 3597 generic form and gets an `error` field.
 * - `encodeMessage()` builds arbitrary messages (responses included); it exists
 *   mainly so other modules' unit tests can fabricate realistic DoH answers.
 *
 * Conventions (shared with the rest of the app): names in `data` are lowercase,
 * without trailing dot; the root name is represented as '.'. The `text` field of
 * every record is the dig-style presentation of its RDATA (like `dig +nosplit`),
 * where names are fully qualified (trailing dot).
 */

/** Error thrown for malformed wire data or invalid encoder input. */
export class DnsWireError extends Error {
  /**
   * @param {string} message
   * @param {number|null} [offset] byte offset in the message where the problem was found
   */
  constructor(message, offset = null) {
    super(message);
    this.name = 'DnsWireError';
    this.offset = offset;
  }
}

/**
 * RR type mnemonics → numbers. Contains every type of the module contract plus
 * a few extra well-known ones (extension, backward compatible).
 */
export const TYPES = Object.freeze({
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, HINFO: 13, MX: 15, TXT: 16, RP: 17, AFSDB: 18,
  AAAA: 28, LOC: 29, SRV: 33, NAPTR: 35, KX: 36, CERT: 37, DNAME: 39, OPT: 41, APL: 42,
  DS: 43, SSHFP: 44, IPSECKEY: 45, RRSIG: 46, NSEC: 47, DNSKEY: 48, DHCID: 49, NSEC3: 50,
  NSEC3PARAM: 51, TLSA: 52, SMIMEA: 53, HIP: 55, CDS: 59, CDNSKEY: 60, OPENPGPKEY: 61,
  CSYNC: 62, ZONEMD: 63, SVCB: 64, HTTPS: 65, SPF: 99, TKEY: 249, TSIG: 250, IXFR: 251,
  NXNAME: 128, AXFR: 252, ANY: 255, URI: 256, CAA: 257
});

const TYPE_NAMES = Object.freeze(Object.fromEntries(Object.entries(TYPES).map(([k, v]) => [v, k])));

/** DNS classes (extension). */
export const CLASSES = Object.freeze({ IN: 1, CH: 3, HS: 4, NONE: 254, ANY: 255 });
const CLASS_NAMES = Object.freeze(Object.fromEntries(Object.entries(CLASSES).map(([k, v]) => [v, k])));

/** Response codes (header RCODE extended by the EDNS extended-RCODE bits). */
export const RCODES = Object.freeze({
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED',
  6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE', 11: 'DSOTYPENI',
  16: 'BADVERS', 17: 'BADKEY', 18: 'BADTIME', 19: 'BADMODE', 20: 'BADNAME', 21: 'BADALG',
  22: 'BADTRUNC', 23: 'BADCOOKIE'
});

/** EDNS option codes (extension). */
export const EDNS_OPTIONS = Object.freeze({
  3: 'NSID', 5: 'DAU', 6: 'DHU', 7: 'N3U', 8: 'ECS', 9: 'EXPIRE', 10: 'COOKIE',
  11: 'KEEPALIVE', 12: 'PADDING', 13: 'CHAIN', 14: 'KEY-TAG', 15: 'EDE', 18: 'REPORT-CHANNEL', 19: 'ZONEVERSION'
});

/** Extended DNS Error info-codes, RFC 8914 + IANA registry (extension). */
export const EDE_CODES = Object.freeze({
  0: 'Other Error', 1: 'Unsupported DNSKEY Algorithm', 2: 'Unsupported DS Digest Type',
  3: 'Stale Answer', 4: 'Forged Answer', 5: 'DNSSEC Indeterminate', 6: 'DNSSEC Bogus',
  7: 'Signature Expired', 8: 'Signature Not Yet Valid', 9: 'DNSKEY Missing', 10: 'RRSIGs Missing',
  11: 'No Zone Key Bit Set', 12: 'NSEC Missing', 13: 'Cached Error', 14: 'Not Ready', 15: 'Blocked',
  16: 'Censored', 17: 'Filtered', 18: 'Prohibited', 19: 'Stale NXDomain Answer', 20: 'Not Authoritative',
  21: 'Not Supported', 22: 'No Reachable Authority', 23: 'Network Error', 24: 'Invalid Data',
  25: 'Signature Expired before Valid', 26: 'Too Early', 27: 'Unsupported NSEC3 Iterations Value',
  28: 'Unable to conform to policy', 29: 'Synthesized', 30: 'Invalid Query Type'
});

/** DNSSEC algorithm numbers → mnemonics (extension). */
export const DNSSEC_ALGORITHMS = Object.freeze({
  1: 'RSAMD5', 3: 'DSA', 5: 'RSASHA1', 6: 'DSA-NSEC3-SHA1', 7: 'RSASHA1-NSEC3-SHA1',
  8: 'RSASHA256', 10: 'RSASHA512', 12: 'ECC-GOST', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384',
  15: 'ED25519', 16: 'ED448', 17: 'SM2SM3', 23: 'ECC-GOST12'
});

/** DS digest types → names (extension). */
export const DS_DIGEST_TYPES = Object.freeze({
  1: 'SHA-1', 2: 'SHA-256', 3: 'GOST R 34.11-94', 4: 'SHA-384', 5: 'GOST R 34.11-2012', 6: 'SM3'
});

/** SVCB / HTTPS SvcParamKeys, RFC 9460 + IANA registry (extension). */
export const SVC_PARAM_KEYS = Object.freeze({
  0: 'mandatory', 1: 'alpn', 2: 'no-default-alpn', 3: 'port', 4: 'ipv4hint', 5: 'ech',
  6: 'ipv6hint', 7: 'dohpath', 8: 'ohttp', 9: 'tls-supported-groups'
});
const SVC_PARAM_NUMBERS = Object.freeze(Object.fromEntries(Object.entries(SVC_PARAM_KEYS).map(([k, v]) => [v, Number(k)])));

const OPT_ECS = 8;
const OPT_EDE = 15;
const OPT_NSID = 3;
const MAX_POINTER_JUMPS = 128;
const MAX_NAME_WIRE = 255;
const MAX_LABEL = 63;

// ---------------------------------------------------------------------------
// Type / class helpers
// ---------------------------------------------------------------------------

/**
 * Convert an RR type given as mnemonic ('AAAA', case-insensitive), RFC 3597 form
 * ('TYPE65'), numeric string ('28') or number to its number.
 * @param {string|number} t
 * @returns {number|null} type number, or null when unknown / out of range
 */
export function typeToNumber(t) {
  if (typeof t === 'number') return Number.isInteger(t) && t >= 0 && t <= 0xffff ? t : null;
  if (typeof t !== 'string') return null;
  const s = t.trim().toUpperCase();
  if (Object.prototype.hasOwnProperty.call(TYPES, s)) return TYPES[s];
  const m = /^(?:TYPE)?(\d{1,5})$/.exec(s);
  if (m) {
    const n = Number(m[1]);
    return n <= 0xffff ? n : null;
  }
  return null;
}

/**
 * Convert an RR type number to its mnemonic; unknown numbers → 'TYPE123'.
 * A mnemonic string is accepted too and normalized ('aaaa' → 'AAAA').
 * @param {number|string} n
 * @returns {string}
 */
export function typeToName(n) {
  const num = typeToNumber(n);
  if (num === null) return String(n);
  return TYPE_NAMES[num] || `TYPE${num}`;
}

/**
 * Class number → mnemonic ('IN', 'CH', ... or 'CLASS<n>').
 * @param {number} n
 * @returns {string}
 */
export function classToName(n) {
  return CLASS_NAMES[n] || `CLASS${n}`;
}

/**
 * Response code number → name ('NXDOMAIN', ... or 'RCODE<n>').
 * @param {number} n
 * @returns {string}
 */
export function rcodeToName(n) {
  return RCODES[n] || `RCODE${n}`;
}

// ---------------------------------------------------------------------------
// Byte / text encoding helpers
// ---------------------------------------------------------------------------

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = (() => {
  const map = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64.length; i++) map[B64.charCodeAt(i)] = i;
  map['-'.charCodeAt(0)] = 62; // base64url
  map['_'.charCodeAt(0)] = 63;
  return map;
})();
const B32HEX = '0123456789abcdefghijklmnopqrstuv';
const HEX = '0123456789abcdef';
const utf8Encoder = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

/**
 * Standard base64 (with padding).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function base64Encode(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[n >>> 18] + B64[(n >>> 12) & 63] + B64[(n >>> 6) & 63] + B64[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += B64[n >>> 18] + B64[(n >>> 12) & 63] + '==';
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[n >>> 18] + B64[(n >>> 12) & 63] + B64[(n >>> 6) & 63] + '=';
  }
  return out;
}

/**
 * base64url without padding (RFC 4648 §5), as required for the RFC 8484 `?dns=` parameter.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function base64UrlEncode(bytes) {
  return base64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode standard or url-safe base64 (padding optional, whitespace ignored).
 * @param {string} str
 * @returns {Uint8Array}
 * @throws {DnsWireError} on invalid characters or length
 */
export function base64Decode(str) {
  const s = String(str).replace(/\s+/g, '').replace(/=+$/, '');
  if (s.length % 4 === 1) throw new DnsWireError('invalid base64 length');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let j = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64_LOOKUP[c] : -1;
    if (v < 0) throw new DnsWireError(`invalid base64 character at ${i}`);
    acc = ((acc << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[j++] = (acc >>> bits) & 0xff;
    }
  }
  return out;
}

/**
 * Alias of `base64Decode` (accepts the url-safe alphabet) — handy to decode a `?dns=` value.
 * @param {string} str
 * @returns {Uint8Array}
 */
export function base64UrlDecode(str) {
  return base64Decode(str);
}

/**
 * Lowercase hex encoding.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function hexEncode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += HEX[bytes[i] >>> 4] + HEX[bytes[i] & 15];
  return out;
}

/**
 * Decode hex (whitespace and ':' separators ignored).
 * @param {string} str
 * @returns {Uint8Array}
 * @throws {DnsWireError}
 */
export function hexDecode(str) {
  const s = String(str).replace(/[\s:]+/g, '');
  if (s.length % 2 || !/^[0-9a-fA-F]*$/.test(s)) throw new DnsWireError('invalid hex string');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** base32hex without padding (RFC 4648 §7), lowercase — used by NSEC3. */
function base32HexEncode(bytes) {
  let out = '';
  let bits = 0;
  let acc = 0;
  for (let i = 0; i < bytes.length; i++) {
    acc = ((acc << 8) | bytes[i]) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32HEX[(acc >>> bits) & 31];
    }
  }
  if (bits > 0) out += B32HEX[(acc << (5 - bits)) & 31];
  return out;
}

/** Decode UTF-8; on invalid sequences fall back to Latin-1 (one char per byte, lossless). */
function decodeUtf8Lenient(bytes) {
  try {
    return utf8Strict.decode(bytes);
  } catch {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }
}

/** '\DDD' escape for one byte. */
function ddd(b) {
  return '\\' + String(b).padStart(3, '0');
}

/**
 * Code points that must not appear raw in presentation text: C0/C1 controls, DEL,
 * zero-width and bidirectional formatting characters (they can make untrusted TXT
 * data render deceptively, "Trojan Source" style).
 */
function isUnsafeCodePoint(cp) {
  return cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) || cp === 0xfeff ||
    (cp >= 0xfff9 && cp <= 0xfffb);
}

/**
 * Presentation form of a <character-string>: quoted, '"' and '\' escaped, unsafe
 * characters as \DDD (one per UTF-8 byte). Other valid UTF-8 stays readable
 * (e.g. Turkish text); bytes of invalid UTF-8 become \DDD.
 */
function quoteCharString(bytes) {
  let valid = true;
  let decoded = '';
  try {
    decoded = utf8Strict.decode(bytes);
  } catch {
    valid = false;
  }
  let out = '"';
  if (valid) {
    for (const ch of decoded) {
      const cp = ch.codePointAt(0);
      if (ch === '"' || ch === '\\') out += '\\' + ch;
      else if (isUnsafeCodePoint(cp)) for (const b of utf8Encoder.encode(ch)) out += ddd(b);
      else out += ch;
    }
  } else {
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === 0x22 || b === 0x5c) out += '\\' + String.fromCharCode(b);
      else if (b < 0x20 || b > 0x7e) out += ddd(b);
      else out += String.fromCharCode(b);
    }
  }
  return out + '"';
}

// ---------------------------------------------------------------------------
// IP helpers (self-contained so the wire codec has no module dependencies)
// ---------------------------------------------------------------------------

function parseIPv4Bytes(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = m[i + 1];
    if (part.length > 1 && part[0] === '0') return null; // no ambiguous leading zeros
    const v = Number(part);
    if (v > 255) return null;
    out[i] = v;
  }
  return out;
}

function parseIPv6Bytes(input) {
  let s = input;
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  if (!/^[0-9a-fA-F:.]+$/.test(s) || s.indexOf(':') < 0) return null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parseGroups = (part) => {
    if (part === '') return [];
    const groups = part.split(':');
    const out = [];
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i];
      if (i === groups.length - 1 && g.includes('.')) {
        const v4 = parseIPv4Bytes(g);
        if (!v4) return null;
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
        out.push(parseInt(g, 16));
      }
    }
    return out;
  };
  const head = parseGroups(halves[0]);
  const tail = halves.length === 2 ? parseGroups(halves[1]) : [];
  if (!head || !tail) return null;
  let groups;
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...new Array(missing).fill(0), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => { out[i * 2] = g >>> 8; out[i * 2 + 1] = g & 0xff; });
  return out;
}

function formatIPv4(b, off = 0) {
  return `${b[off]}.${b[off + 1]}.${b[off + 2]}.${b[off + 3]}`;
}

/** RFC 5952 canonical text; IPv4-mapped addresses as '::ffff:a.b.c.d'. */
function formatIPv6(b, off = 0) {
  let mapped = b[off + 10] === 0xff && b[off + 11] === 0xff;
  for (let i = 0; i < 10 && mapped; i++) if (b[off + i] !== 0) mapped = false;
  if (mapped) return `::ffff:${formatIPv4(b, off + 12)}`;
  const g = [];
  for (let i = 0; i < 8; i++) g.push((b[off + i * 2] << 8) | b[off + i * 2 + 1]);
  // Longest run (≥2) of zero groups; first one wins on ties.
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (bestStart < 0) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

// ---------------------------------------------------------------------------
// Name encoding
// ---------------------------------------------------------------------------

/**
 * Parse a presentation-format domain name into label byte arrays.
 * Supports '\.' / '\\' / '\DDD' escapes; rejects empty labels, labels > 63
 * octets, names > 255 octets, whitespace/control and non-ASCII characters
 * (IDNs must be converted to punycode by the caller).
 */
function parseNameLabels(name) {
  if (typeof name !== 'string') throw new DnsWireError('domain name must be a string');
  if (name === '' || name === '.') return [];
  const labels = [];
  let cur = [];
  let i = 0;
  const n = name.length;
  while (i < n) {
    const c = name.charCodeAt(i);
    if (c === 0x2e) {
      if (cur.length === 0) throw new DnsWireError(`empty label in domain name "${name}"`);
      labels.push(cur);
      cur = [];
      i++;
      continue;
    }
    if (c === 0x5c) {
      const digits = name.slice(i + 1, i + 4);
      if (/^\d{3}$/.test(digits)) {
        const v = Number(digits);
        if (v > 255) throw new DnsWireError(`invalid escape \\${digits} in domain name`);
        cur.push(v);
        i += 4;
        continue;
      }
      if (i + 1 >= n) throw new DnsWireError('dangling escape at end of domain name');
      const e = name.charCodeAt(i + 1);
      if (e > 0x7e || e < 0x20) throw new DnsWireError('invalid escaped character in domain name');
      cur.push(e);
      i += 2;
      continue;
    }
    if (c > 0x7e) throw new DnsWireError(`non-ASCII character in domain name "${name}" (convert IDN to punycode first)`);
    if (c <= 0x20 || c === 0x7f) throw new DnsWireError(`invalid character in domain name "${name}"`);
    cur.push(c);
    i++;
  }
  if (cur.length) labels.push(cur);
  let wire = 1;
  for (const label of labels) {
    if (label.length > MAX_LABEL) throw new DnsWireError(`label longer than 63 octets in "${name}"`);
    wire += label.length + 1;
  }
  if (wire > MAX_NAME_WIRE) throw new DnsWireError(`domain name longer than 255 octets: "${name.slice(0, 40)}..."`);
  return labels;
}

/**
 * Encode a presentation-format domain name to uncompressed wire format.
 * @param {string} name e.g. 'www.example.com' (trailing dot optional, '' or '.' = root)
 * @returns {Uint8Array}
 * @throws {DnsWireError} on invalid names
 */
export function encodeName(name) {
  const labels = parseNameLabels(name);
  const out = new Uint8Array(labels.reduce((n, l) => n + l.length + 1, 1));
  let p = 0;
  for (const label of labels) {
    out[p++] = label.length;
    out.set(label, p);
    p += label.length;
  }
  out[p] = 0;
  return out;
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

class Writer {
  constructor(size = 512) {
    this.buf = new Uint8Array(Number.isInteger(size) && size > 16 ? size : 64);
    this.len = 0;
  }

  ensure(n) {
    if (this.len + n <= this.buf.length) return;
    let size = Math.max(64, this.buf.length * 2);
    while (size < this.len + n) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buf.subarray(0, this.len));
    this.buf = next;
  }

  u8(v) {
    this.ensure(1);
    this.buf[this.len++] = v & 0xff;
  }

  u16(v) {
    this.ensure(2);
    this.buf[this.len++] = (v >>> 8) & 0xff;
    this.buf[this.len++] = v & 0xff;
  }

  u32(v) {
    this.ensure(4);
    this.buf[this.len++] = (v >>> 24) & 0xff;
    this.buf[this.len++] = (v >>> 16) & 0xff;
    this.buf[this.len++] = (v >>> 8) & 0xff;
    this.buf[this.len++] = v & 0xff;
  }

  bytes(arr) {
    this.ensure(arr.length);
    this.buf.set(arr, this.len);
    this.len += arr.length;
  }

  name(n) {
    this.bytes(encodeName(n));
  }

  setU16(pos, v) {
    this.buf[pos] = (v >>> 8) & 0xff;
    this.buf[pos + 1] = v & 0xff;
  }

  finish() {
    return this.buf.slice(0, this.len);
  }
}

function checkUint(v, max, what) {
  if (!Number.isInteger(v) || v < 0 || v > max) throw new DnsWireError(`${what} out of range: ${v}`);
  return v;
}

// ---------------------------------------------------------------------------
// ECS (RFC 7871)
// ---------------------------------------------------------------------------

/**
 * Normalize an ECS spec to { family, sourcePrefix, addressBytes (truncated, host bits zeroed) }.
 * Accepts 'a.b.c.d/24', '2001:db8::/56', a bare address (default /24 v4, /56 v6),
 * or { address, sourcePrefix } / { address, prefix } / { subnet }.
 */
function normalizeEcs(ecs) {
  let address;
  let prefix;
  if (typeof ecs === 'string') {
    const slash = ecs.indexOf('/');
    address = (slash >= 0 ? ecs.slice(0, slash) : ecs).trim();
    prefix = slash >= 0 ? ecs.slice(slash + 1).trim() : undefined;
  } else if (ecs && typeof ecs === 'object') {
    if (typeof ecs.subnet === 'string') return normalizeEcs(ecs.subnet);
    address = String(ecs.address ?? '').trim();
    prefix = ecs.sourcePrefix ?? ecs.prefix;
  } else {
    throw new DnsWireError('invalid ECS value');
  }
  let bytes = parseIPv4Bytes(address);
  let family = 1;
  if (!bytes) {
    bytes = parseIPv6Bytes(address);
    family = 2;
  }
  if (!bytes) throw new DnsWireError(`invalid ECS address "${address}"`);
  const maxPrefix = family === 1 ? 32 : 128;
  let source = prefix === undefined || prefix === null || prefix === '' ? (family === 1 ? 24 : 56) : Number(prefix);
  if (typeof prefix === 'string' && !/^\d{1,3}$/.test(prefix)) source = NaN;
  if (!Number.isInteger(source) || source < 0 || source > maxPrefix) {
    throw new DnsWireError(`invalid ECS source prefix "${prefix}"`);
  }
  const nBytes = Math.ceil(source / 8);
  const addr = bytes.slice(0, nBytes);
  const rem = source % 8;
  if (rem && nBytes) addr[nBytes - 1] &= (0xff << (8 - rem)) & 0xff;
  return { family, sourcePrefix: source, addressBytes: addr };
}

function ecsOptionData(ecs, scopePrefix = 0) {
  const { family, sourcePrefix, addressBytes } = normalizeEcs(ecs);
  const out = new Uint8Array(4 + addressBytes.length);
  out[0] = 0;
  out[1] = family;
  out[2] = sourcePrefix;
  out[3] = scopePrefix;
  out.set(addressBytes, 4);
  return out;
}

// ---------------------------------------------------------------------------
// Query encoder
// ---------------------------------------------------------------------------

function writeHeaderFlags(w, { qr = false, opcode = 0, aa = false, tc = false, rd = false, ra = false, z = false, ad = false, cd = false } = {}, rcode = 0) {
  checkUint(opcode, 15, 'opcode');
  const hi = (qr ? 0x80 : 0) | (opcode << 3) | (aa ? 0x04 : 0) | (tc ? 0x02 : 0) | (rd ? 0x01 : 0);
  const lo = (ra ? 0x80 : 0) | (z ? 0x40 : 0) | (ad ? 0x20 : 0) | (cd ? 0x10 : 0) | (rcode & 0x0f);
  w.u8(hi);
  w.u8(lo);
}

function writeOpt(w, { udpSize = 1232, version = 0, dnssecOk = false, extendedRcode = 0, options = [] } = {}) {
  checkUint(udpSize, 0xffff, 'EDNS UDP payload size');
  checkUint(version, 255, 'EDNS version');
  checkUint(extendedRcode, 255, 'EDNS extended rcode');
  w.u8(0); // root owner
  w.u16(TYPES.OPT);
  w.u16(udpSize);
  w.u8(extendedRcode);
  w.u8(version);
  w.u16(dnssecOk ? 0x8000 : 0);
  let rdlen = 0;
  for (const o of options) rdlen += 4 + o.data.length;
  checkUint(rdlen, 0xffff, 'OPT RDATA length');
  w.u16(rdlen);
  for (const o of options) {
    w.u16(checkUint(o.code, 0xffff, 'EDNS option code'));
    w.u16(o.data.length);
    w.bytes(o.data);
  }
}

/**
 * Build a DNS query message (always with an EDNS(0) OPT record).
 * @param {string} name query name in presentation format (IDN already punycoded)
 * @param {string|number} type RR type mnemonic or number
 * @param {object} [opts]
 * @param {number} [opts.id=0] message id (RFC 8484 recommends 0 for cache friendliness)
 * @param {boolean} [opts.rd=true] recursion desired
 * @param {boolean} [opts.cd=false] checking disabled (ask the resolver not to DNSSEC-validate)
 * @param {boolean} [opts.ad=true] set AD in the query (like dig): resolvers then report whether the answer was
 *   DNSSEC-validated (AD) even without DO (RFC 6840 §5.7) — extension
 * @param {boolean} [opts.dnssecOk=false] DO bit (request RRSIG / NSEC records)
 * @param {null|string|{address:string,sourcePrefix:number}} [opts.ecs=null] EDNS Client Subnet, e.g. '198.51.100.0/24'
 * @param {number} [opts.udpSize=1232] advertised EDNS UDP payload size
 * @param {boolean} [opts.nsid=false] request the server's NSID (RFC 5001) — extension
 * @param {number} [opts.qclass=1] query class — extension
 * @returns {Uint8Array}
 * @throws {DnsWireError} invalid name / type / ECS
 */
export function encodeQuery(name, type, {
  id = 0, rd = true, cd = false, ad = true, dnssecOk = false, ecs = null, udpSize = 1232, nsid = false, qclass = 1
} = {}) {
  const qname = encodeName(name); // validates before anything is written
  const typeNum = typeToNumber(type);
  if (typeNum === null) throw new DnsWireError(`unknown RR type "${type}"`);
  checkUint(id, 0xffff, 'message id');
  checkUint(qclass, 0xffff, 'query class');
  const options = [];
  if (nsid) options.push({ code: OPT_NSID, data: new Uint8Array(0) });
  if (ecs !== null && ecs !== undefined && ecs !== false) options.push({ code: OPT_ECS, data: ecsOptionData(ecs) });
  const w = new Writer(64 + qname.length);
  w.u16(id);
  writeHeaderFlags(w, { rd, cd, ad });
  w.u16(1); // QDCOUNT
  w.u16(0); // ANCOUNT
  w.u16(0); // NSCOUNT
  w.u16(1); // ARCOUNT (OPT)
  w.bytes(qname);
  w.u16(typeNum);
  w.u16(qclass);
  writeOpt(w, { udpSize, dnssecOk, options });
  return w.finish();
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/** Presentation text of one label: lowercase ASCII, special characters escaped (BIND style). */
function labelText(label) {
  let s = '';
  for (let i = 0; i < label.length; i++) {
    const b = label[i];
    if (b >= 0x41 && b <= 0x5a) s += String.fromCharCode(b + 32);
    else if (b === 0x2e || b === 0x5c || b === 0x22 || b === 0x28 || b === 0x29 || b === 0x3b || b === 0x40 || b === 0x24) {
      s += '\\' + String.fromCharCode(b);
    } else if (b <= 0x20 || b >= 0x7f) s += ddd(b);
    else s += String.fromCharCode(b);
  }
  return s;
}

/** Name without trailing dot; root → '.'. */
function nameData(labels) {
  return labels.length ? labels.map(labelText).join('.') : '.';
}

/** Fully-qualified presentation (trailing dot). */
function fqdn(name) {
  return name === '.' ? '.' : `${name}.`;
}

/**
 * Bounds-checked reader over a message. `end` limits the current region (e.g. an RDATA);
 * compression pointers may still reach anywhere inside the whole message.
 */
class Reader {
  constructor(msg, pos = 0, end = msg.length) {
    this.msg = msg;
    this.pos = pos;
    this.end = end;
  }

  get remaining() {
    return this.end - this.pos;
  }

  need(n) {
    if (this.pos + n > this.end) {
      throw new DnsWireError(`truncated data: need ${n} byte(s) at offset ${this.pos}`, this.pos);
    }
  }

  u8() {
    this.need(1);
    return this.msg[this.pos++];
  }

  u16() {
    this.need(2);
    const v = (this.msg[this.pos] << 8) | this.msg[this.pos + 1];
    this.pos += 2;
    return v;
  }

  u32() {
    this.need(4);
    const m = this.msg;
    const p = this.pos;
    this.pos += 4;
    return ((m[p] << 24) | (m[p + 1] << 16) | (m[p + 2] << 8) | m[p + 3]) >>> 0;
  }

  bytes(n) {
    this.need(n);
    const out = this.msg.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  rest() {
    return this.bytes(this.end - this.pos);
  }

  charString() {
    const len = this.u8();
    return this.bytes(len);
  }

  /** Read a (possibly compressed) name; returns label byte arrays. */
  nameLabels() {
    const msg = this.msg;
    const labels = [];
    let pos = this.pos;
    let limit = this.end;
    let after = -1;
    let jumps = 0;
    let wire = 1;
    for (;;) {
      if (pos >= limit) throw new DnsWireError('domain name runs past end of data', pos);
      const len = msg[pos];
      const kind = len & 0xc0;
      if (kind === 0xc0) {
        if (pos + 1 >= limit) throw new DnsWireError('truncated compression pointer', pos);
        const target = ((len & 0x3f) << 8) | msg[pos + 1];
        if (after < 0) after = pos + 2;
        if (++jumps > MAX_POINTER_JUMPS) throw new DnsWireError('compression pointer loop', pos);
        if (target >= msg.length) throw new DnsWireError('compression pointer out of range', pos);
        pos = target;
        limit = msg.length; // pointed-to data may live anywhere in the message
        continue;
      }
      if (kind !== 0) throw new DnsWireError(`unsupported label type 0x${len.toString(16)}`, pos);
      pos++;
      if (len === 0) break;
      if (pos + len > limit) throw new DnsWireError('label runs past end of data', pos);
      wire += len + 1;
      if (wire > MAX_NAME_WIRE) throw new DnsWireError('domain name longer than 255 octets', pos);
      labels.push(msg.subarray(pos, pos + len));
      pos += len;
    }
    this.pos = after >= 0 ? after : pos;
    return labels;
  }

  name() {
    return nameData(this.nameLabels());
  }
}

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  throw new DnsWireError('expected Uint8Array or ArrayBuffer');
}

/** Decode an RR type bitmap (NSEC, NSEC3, CSYNC) into type mnemonics. */
function readTypeBitmap(r) {
  const types = [];
  let lastWindow = -1;
  while (r.remaining > 0) {
    const win = r.u8();
    const len = r.u8();
    if (len < 1 || len > 32) throw new DnsWireError(`invalid type bitmap length ${len}`, r.pos);
    if (win <= lastWindow) throw new DnsWireError('type bitmap windows out of order', r.pos);
    lastWindow = win;
    const bits = r.bytes(len);
    for (let i = 0; i < len; i++) {
      for (let b = 0; b < 8; b++) {
        if (bits[i] & (0x80 >> b)) types.push(typeToName(win * 256 + i * 8 + b));
      }
    }
  }
  return types;
}

/**
 * RFC 4034 Appendix B key tag over DNSKEY RDATA.
 * @param {Uint8Array} rdata DNSKEY RDATA (flags | protocol | algorithm | public key)
 * @returns {number}
 */
export function computeKeyTag(rdata) {
  const b = toBytes(rdata);
  if (b.length >= 4 && b[3] === 1) {
    // Algorithm 1 (RSA/MD5): most significant 16 bits of the least significant 24 bits of the modulus.
    return b.length >= 7 ? ((b[b.length - 3] << 8) | b[b.length - 2]) : 0;
  }
  let ac = 0;
  for (let i = 0; i < b.length; i++) ac += (i & 1) ? b[i] : b[i] << 8;
  ac += Math.floor(ac / 65536) & 0xffff;
  return ac & 0xffff;
}

function rrsigTime(secs) {
  // RFC 4034 §3.1.5 serial arithmetic is not needed until 2106: interpret as unsigned seconds.
  return new Date(secs * 1000);
}

function formatRrsigTime(d) {
  const p = (n, l = 2) => String(n).padStart(l, '0');
  return `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
}

/** Split `value-list` items per RFC 9460 App. A.1 and quote as a char-string. */
function quoteValueList(items) {
  const joined = items.map((s) => s.replace(/[\\,]/g, (m) => '\\' + m)).join(',');
  return quoteCharString(utf8Encoder.encode(joined));
}

function readSvcParams(r) {
  const params = {};
  const parts = [];
  let lastKey = -1;
  while (r.remaining > 0) {
    const key = r.u16();
    const len = r.u16();
    const v = new Reader(r.msg, r.pos, r.pos + len);
    r.bytes(len); // bounds-check + advance
    if (key <= lastKey) throw new DnsWireError('SvcParamKeys not in strictly increasing order', r.pos);
    lastKey = key;
    const keyName = SVC_PARAM_KEYS[key] || `key${key}`;
    switch (key) {
      case 0: { // mandatory
        if (len === 0 || len % 2) throw new DnsWireError('invalid mandatory SvcParam', v.pos);
        const keys = [];
        while (v.remaining) {
          const k = v.u16();
          keys.push(SVC_PARAM_KEYS[k] || `key${k}`);
        }
        params.mandatory = keys;
        parts.push(`mandatory=${keys.join(',')}`);
        break;
      }
      case 1: { // alpn
        const ids = [];
        while (v.remaining) {
          const id = v.charString();
          if (!id.length) throw new DnsWireError('empty alpn-id', v.pos);
          ids.push(decodeUtf8Lenient(id));
        }
        if (!ids.length) throw new DnsWireError('empty alpn SvcParam', v.pos);
        params.alpn = ids;
        parts.push(`alpn=${quoteValueList(ids)}`);
        break;
      }
      case 2: // no-default-alpn
      case 8: // ohttp
        if (len !== 0) throw new DnsWireError(`${keyName} must be empty`, v.pos);
        params[keyName] = true;
        parts.push(keyName);
        break;
      case 3: // port
        if (len !== 2) throw new DnsWireError('invalid port SvcParam', v.pos);
        params.port = v.u16();
        parts.push(`port=${params.port}`);
        break;
      case 4: { // ipv4hint
        if (len === 0 || len % 4) throw new DnsWireError('invalid ipv4hint SvcParam', v.pos);
        const ips = [];
        while (v.remaining) ips.push(formatIPv4(v.bytes(4)));
        params.ipv4hint = ips;
        parts.push(`ipv4hint=${ips.join(',')}`);
        break;
      }
      case 5: // ech
        params.ech = base64Encode(v.rest());
        parts.push(`ech=${params.ech}`);
        break;
      case 6: { // ipv6hint
        if (len === 0 || len % 16) throw new DnsWireError('invalid ipv6hint SvcParam', v.pos);
        const ips = [];
        while (v.remaining) ips.push(formatIPv6(v.bytes(16)));
        params.ipv6hint = ips;
        parts.push(`ipv6hint=${ips.join(',')}`);
        break;
      }
      case 7: { // dohpath (URI template, UTF-8)
        const raw = v.rest();
        params.dohpath = decodeUtf8Lenient(raw);
        parts.push(`dohpath=${quoteCharString(raw)}`);
        break;
      }
      case 9: { // tls-supported-groups
        if (len === 0 || len % 2) throw new DnsWireError('invalid tls-supported-groups SvcParam', v.pos);
        const groups = [];
        while (v.remaining) groups.push(v.u16());
        params['tls-supported-groups'] = groups;
        parts.push(`tls-supported-groups=${groups.join(',')}`);
        break;
      }
      default: {
        const raw = v.rest();
        params[keyName] = hexEncode(raw);
        parts.push(raw.length ? `${keyName}=${quoteCharString(raw)}` : keyName);
      }
    }
  }
  return { params, text: parts.join(' ') };
}

/** RDATA parsers: (reader limited to the RDATA) → { data, text }. */
const RDATA_PARSERS = {
  [TYPES.A]: (r) => {
    if (r.remaining !== 4) throw new DnsWireError('A RDATA must be 4 bytes', r.pos);
    const ip = formatIPv4(r.bytes(4));
    return { data: ip, text: ip };
  },
  [TYPES.AAAA]: (r) => {
    if (r.remaining !== 16) throw new DnsWireError('AAAA RDATA must be 16 bytes', r.pos);
    const ip = formatIPv6(r.bytes(16));
    return { data: ip, text: ip };
  },
  [TYPES.NS]: nameRdata,
  [TYPES.CNAME]: nameRdata,
  [TYPES.PTR]: nameRdata,
  [TYPES.DNAME]: nameRdata,
  [TYPES.MX]: (r) => {
    const preference = r.u16();
    const exchange = r.name();
    return { data: { preference, exchange }, text: `${preference} ${fqdn(exchange)}` };
  },
  [TYPES.AFSDB]: (r) => {
    const subtype = r.u16();
    const hostname = r.name();
    return { data: { subtype, hostname }, text: `${subtype} ${fqdn(hostname)}` };
  },
  [TYPES.KX]: (r) => {
    const preference = r.u16();
    const exchanger = r.name();
    return { data: { preference, exchanger }, text: `${preference} ${fqdn(exchanger)}` };
  },
  [TYPES.RP]: (r) => {
    const mbox = r.name();
    const txt = r.name();
    return { data: { mbox, txt }, text: `${fqdn(mbox)} ${fqdn(txt)}` };
  },
  [TYPES.TXT]: txtRdata,
  [TYPES.SPF]: txtRdata,
  [TYPES.HINFO]: (r) => {
    const cpu = r.charString();
    const os = r.charString();
    return { data: { cpu: decodeUtf8Lenient(cpu), os: decodeUtf8Lenient(os) }, text: `${quoteCharString(cpu)} ${quoteCharString(os)}` };
  },
  [TYPES.SOA]: (r) => {
    const mname = r.name();
    const rname = r.name();
    const serial = r.u32();
    const refresh = r.u32();
    const retry = r.u32();
    const expire = r.u32();
    const minimum = r.u32();
    return {
      data: { mname, rname, serial, refresh, retry, expire, minimum, email: soaEmail(rname) },
      text: `${fqdn(mname)} ${fqdn(rname)} ${serial} ${refresh} ${retry} ${expire} ${minimum}`
    };
  },
  [TYPES.SRV]: (r) => {
    const priority = r.u16();
    const weight = r.u16();
    const port = r.u16();
    const target = r.name();
    return { data: { priority, weight, port, target }, text: `${priority} ${weight} ${port} ${fqdn(target)}` };
  },
  [TYPES.NAPTR]: (r) => {
    const order = r.u16();
    const preference = r.u16();
    const flags = r.charString();
    const services = r.charString();
    const regexp = r.charString();
    const replacement = r.name();
    return {
      data: {
        order, preference, flags: decodeUtf8Lenient(flags), services: decodeUtf8Lenient(services),
        regexp: decodeUtf8Lenient(regexp), replacement
      },
      text: `${order} ${preference} ${quoteCharString(flags)} ${quoteCharString(services)} ${quoteCharString(regexp)} ${fqdn(replacement)}`
    };
  },
  [TYPES.CAA]: (r) => {
    const flags = r.u8();
    const tagLen = r.u8();
    if (tagLen === 0) throw new DnsWireError('CAA tag must not be empty', r.pos);
    const tagBytes = r.bytes(tagLen);
    // RFC 8659 §4.1: the tag is ASCII letters and digits. It goes into `text`
    // unquoted, so anything else (a bidi override, a newline) must not pass.
    if (!tagBytes.every((b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a))) {
      throw new DnsWireError('CAA tag must be alphanumeric', r.pos);
    }
    const valueBytes = r.rest();
    const tag = decodeUtf8Lenient(tagBytes).toLowerCase();
    const value = decodeUtf8Lenient(valueBytes);
    return {
      data: { flags, tag, value, critical: (flags & 0x80) !== 0 },
      text: `${flags} ${tag} ${quoteCharString(valueBytes)}`
    };
  },
  [TYPES.DS]: dsRdata,
  [TYPES.CDS]: dsRdata,
  [TYPES.DNSKEY]: dnskeyRdata,
  [TYPES.CDNSKEY]: dnskeyRdata,
  [TYPES.RRSIG]: (r) => {
    const typeCoveredNum = r.u16();
    const algorithm = r.u8();
    const labels = r.u8();
    const originalTtl = r.u32();
    const expSecs = r.u32();
    const incSecs = r.u32();
    const keyTag = r.u16();
    const signerName = r.name();
    const sig = r.rest();
    const expiration = rrsigTime(expSecs);
    const inception = rrsigTime(incSecs);
    const typeCovered = typeToName(typeCoveredNum);
    const signature = base64Encode(sig);
    return {
      data: { typeCovered, algorithm, labels, originalTtl, expiration, inception, keyTag, signerName, signature },
      text: `${typeCovered} ${algorithm} ${labels} ${originalTtl} ${formatRrsigTime(expiration)} ${formatRrsigTime(inception)} ${keyTag} ${fqdn(signerName)} ${signature}`
    };
  },
  [TYPES.NSEC]: (r) => {
    const nextDomain = r.name();
    const types = readTypeBitmap(r);
    return { data: { nextDomain, types }, text: [fqdn(nextDomain), ...types].join(' ') };
  },
  [TYPES.NSEC3]: (r) => {
    const hashAlgorithm = r.u8();
    const flags = r.u8();
    const iterations = r.u16();
    const salt = hexEncode(r.charString());
    const hashLen = r.u8();
    if (hashLen === 0) throw new DnsWireError('NSEC3 hash length must not be 0', r.pos);
    const nextHashedOwner = base32HexEncode(r.bytes(hashLen));
    const types = readTypeBitmap(r);
    return {
      data: { hashAlgorithm, flags, optOut: (flags & 1) === 1, iterations, salt, nextHashedOwner, types },
      text: [hashAlgorithm, flags, iterations, salt ? salt.toUpperCase() : '-', nextHashedOwner.toUpperCase(), ...types].join(' ')
    };
  },
  [TYPES.NSEC3PARAM]: (r) => {
    const hashAlgorithm = r.u8();
    const flags = r.u8();
    const iterations = r.u16();
    const salt = hexEncode(r.charString());
    return {
      data: { hashAlgorithm, flags, iterations, salt },
      text: `${hashAlgorithm} ${flags} ${iterations} ${salt ? salt.toUpperCase() : '-'}`
    };
  },
  [TYPES.TLSA]: tlsaRdata,
  [TYPES.SMIMEA]: tlsaRdata,
  [TYPES.SSHFP]: (r) => {
    const algorithm = r.u8();
    const fpType = r.u8();
    const fingerprint = hexEncode(r.rest());
    return { data: { algorithm, fpType, fingerprint }, text: `${algorithm} ${fpType} ${fingerprint.toUpperCase()}` };
  },
  [TYPES.OPENPGPKEY]: (r) => {
    const key = base64Encode(r.rest());
    return { data: key, text: key };
  },
  [TYPES.SVCB]: svcbRdata,
  [TYPES.HTTPS]: svcbRdata,
  [TYPES.URI]: (r) => {
    const priority = r.u16();
    const weight = r.u16();
    const raw = r.rest();
    return { data: { priority, weight, target: decodeUtf8Lenient(raw) }, text: `${priority} ${weight} ${quoteCharString(raw)}` };
  },
  [TYPES.ZONEMD]: (r) => {
    const serial = r.u32();
    const scheme = r.u8();
    const hashAlgorithm = r.u8();
    const digest = hexEncode(r.rest());
    return { data: { serial, scheme, hashAlgorithm, digest }, text: `${serial} ${scheme} ${hashAlgorithm} ${digest.toUpperCase()}` };
  },
  [TYPES.CSYNC]: (r) => {
    const serial = r.u32();
    const flags = r.u16();
    const types = readTypeBitmap(r);
    return { data: { serial, flags, types }, text: [serial, flags, ...types].join(' ') };
  }
};

function nameRdata(r) {
  const target = r.name();
  return { data: target, text: fqdn(target) };
}

function txtRdata(r) {
  const strings = [];
  const quoted = [];
  while (r.remaining > 0) {
    const s = r.charString();
    strings.push(decodeUtf8Lenient(s));
    quoted.push(quoteCharString(s));
  }
  return { data: strings, text: quoted.join(' ') };
}

function dsRdata(r) {
  const keyTag = r.u16();
  const algorithm = r.u8();
  const digestType = r.u8();
  const digest = hexEncode(r.rest());
  return { data: { keyTag, algorithm, digestType, digest }, text: `${keyTag} ${algorithm} ${digestType} ${digest.toUpperCase()}` };
}

function dnskeyRdata(r) {
  const start = r.pos;
  const flags = r.u16();
  const protocol = r.u8();
  const algorithm = r.u8();
  const key = r.rest();
  const keyTag = computeKeyTag(r.msg.subarray(start, r.pos));
  const publicKey = base64Encode(key);
  return {
    data: {
      flags, protocol, algorithm, publicKey, keyTag,
      zoneKey: (flags & 0x0100) !== 0, sep: (flags & 0x0001) !== 0, revoked: (flags & 0x0080) !== 0
    },
    text: `${flags} ${protocol} ${algorithm} ${publicKey}`
  };
}

function tlsaRdata(r) {
  const usage = r.u8();
  const selector = r.u8();
  const matchingType = r.u8();
  const data = hexEncode(r.rest());
  return { data: { usage, selector, matchingType, data }, text: `${usage} ${selector} ${matchingType} ${data.toUpperCase()}` };
}

function svcbRdata(r) {
  const priority = r.u16();
  const target = r.name();
  const { params, text } = readSvcParams(r);
  return { data: { priority, target, params }, text: `${priority} ${fqdn(target)}${text ? ' ' + text : ''}` };
}

/** SOA RNAME → mailbox ('hostmaster.example.com' → 'hostmaster@example.com'), honouring '\.' escapes. */
function soaEmail(rname) {
  if (rname === '.') return null;
  const m = /^((?:[^.\\]|\\.)+)\.(.+)$/.exec(rname);
  if (!m) return null;
  return `${m[1].replace(/\\(\d{3}|.)/g, (_, e) => (e.length === 3 ? String.fromCharCode(Number(e)) : e))}@${m[2]}`;
}

/** Parse one RR's RDATA; malformed RDATA degrades to the RFC 3597 generic form with `error`. */
function parseRdata(msg, typeNum, start, end) {
  const parser = RDATA_PARSERS[typeNum];
  const raw = msg.subarray(start, end);
  const generic = () => ({
    data: hexEncode(raw),
    text: raw.length ? `\\# ${raw.length} ${hexEncode(raw).toUpperCase()}` : '\\# 0'
  });
  if (!parser) return generic();
  try {
    const r = new Reader(msg, start, end);
    const out = parser(r);
    if (r.pos !== end) throw new DnsWireError(`${r.end - r.pos} trailing byte(s) in RDATA`, r.pos);
    return out;
  } catch (err) {
    if (!(err instanceof DnsWireError)) throw err;
    return { ...generic(), error: err.message };
  }
}

function parseEdnsOptions(r) {
  const options = [];
  const edns = { ecs: null, ede: [], nsid: null };
  while (r.remaining > 0) {
    // A malformed option must not discard an otherwise valid answer: keep what was parsed.
    if (r.remaining < 4) {
      edns.error = 'truncated EDNS option header';
      break;
    }
    const code = r.u16();
    const len = r.u16();
    if (len > r.remaining) {
      edns.error = `EDNS option ${code} runs past the OPT record`;
      break;
    }
    const data = r.bytes(len);
    const opt = { code, name: EDNS_OPTIONS[code] || `OPT${code}`, data };
    options.push(opt);
    if (code === OPT_ECS && !edns.ecs) edns.ecs = parseEcsOption(data);
    else if (code === OPT_EDE && len >= 2) {
      const infoCode = (data[0] << 8) | data[1];
      const text = decodeUtf8Lenient(data.subarray(2)).replace(/\0+$/, '');
      edns.ede.push({ code: infoCode, name: EDE_CODES[infoCode] || `EDE${infoCode}`, text });
    } else if (code === OPT_NSID && len > 0) {
      edns.nsid = [...data].every((b) => b >= 0x20 && b < 0x7f) ? String.fromCharCode(...data) : hexEncode(data);
    }
  }
  return { options, ...edns };
}

/** RFC 7871 option payload → { family, sourcePrefix, scopePrefix, address, subnet } or null when malformed. */
function parseEcsOption(data) {
  if (data.length < 4) return null;
  const family = (data[0] << 8) | data[1];
  const sourcePrefix = data[2];
  const scopePrefix = data[3];
  const addr = data.subarray(4);
  const size = family === 1 ? 4 : family === 2 ? 16 : 0;
  if (!size || addr.length > size) return { family, sourcePrefix, scopePrefix, address: null, subnet: null };
  const full = new Uint8Array(size);
  full.set(addr);
  const address = size === 4 ? formatIPv4(full) : formatIPv6(full);
  return { family, sourcePrefix, scopePrefix, address, subnet: `${address}/${sourcePrefix}` };
}

/**
 * Decode a DNS message.
 *
 * The OPT pseudo-record is not listed in `additionals`; it is exposed as `edns`.
 * `rcode` combines the header RCODE with the EDNS extended-RCODE bits.
 * TTLs with the most significant bit set are treated as 0 (RFC 2181 §8).
 *
 * RR objects: { name, type, typeNum, class, className, ttl, data, text, rdata } where
 * `rdata` is the raw RDATA view (may contain compression pointers into THIS message,
 * so it is not portable on its own; encodeMessage rebuilds such types from `data`) and `error`
 * is set only when a known type's RDATA was malformed (data/text are then the
 * RFC 3597 generic hex form).
 *
 * @param {Uint8Array|ArrayBuffer} input
 * @returns {{
 *   id: number,
 *   flags: {qr:boolean,opcode:number,aa:boolean,tc:boolean,rd:boolean,ra:boolean,z:boolean,ad:boolean,cd:boolean},
 *   rcode: number, rcodeName: string,
 *   questions: Array<{name:string,type:string,typeNum:number,class:number,className:string}>,
 *   answers: object[], authorities: object[], additionals: object[],
 *   edns: null|{udpSize:number,version:number,dnssecOk:boolean,extendedRcode:number,
 *     options:Array<{code:number,name:string,data:Uint8Array}>,
 *     ecs:null|{family:number,sourcePrefix:number,scopePrefix:number,address:string|null,subnet:string|null},
 *     ede:Array<{code:number,name:string,text:string}>, nsid:string|null, error?:string},
 *   truncated: boolean, size: number
 * }}
 * @throws {DnsWireError} on malformed messages
 */
export function decodeMessage(input) {
  const msg = toBytes(input);
  if (msg.length < 12) throw new DnsWireError('message shorter than the 12-byte header', 0);
  const r = new Reader(msg);
  const id = r.u16();
  const hi = r.u8();
  const lo = r.u8();
  const flags = {
    qr: (hi & 0x80) !== 0,
    opcode: (hi >>> 3) & 0x0f,
    aa: (hi & 0x04) !== 0,
    tc: (hi & 0x02) !== 0,
    rd: (hi & 0x01) !== 0,
    ra: (lo & 0x80) !== 0,
    z: (lo & 0x40) !== 0,
    ad: (lo & 0x20) !== 0,
    cd: (lo & 0x10) !== 0
  };
  const counts = [r.u16(), r.u16(), r.u16(), r.u16()];
  // Cheap sanity check before allocating anything: a question needs ≥5 bytes, an RR ≥11.
  if (!flags.tc && counts[0] * 5 + (counts[1] + counts[2] + counts[3]) * 11 > msg.length - 12) {
    throw new DnsWireError('record counts exceed message size', 4);
  }
  let truncated = false;
  // With TC=1 the sender may have cut the message anywhere: stop at the first
  // incomplete item and report `truncated` instead of failing.
  const cut = (err) => {
    if (!flags.tc || !(err instanceof DnsWireError)) throw err;
    truncated = true;
  };
  const questions = [];
  for (let i = 0; i < counts[0]; i++) {
    if (flags.tc && r.remaining === 0) { truncated = true; break; }
    try {
      const name = r.name();
      const typeNum = r.u16();
      const cls = r.u16();
      questions.push({ name, type: typeToName(typeNum), typeNum, class: cls, className: classToName(cls) });
    } catch (err) {
      cut(err);
      break;
    }
  }
  const sections = [[], [], []];
  let edns = null;
  for (let s = 0; s < 3 && !truncated; s++) {
    for (let i = 0; i < counts[s + 1]; i++) {
      if (flags.tc && r.remaining === 0) { truncated = true; break; }
      const ownerStart = r.pos;
      let name, typeNum, cls, ttlRaw, rdlen;
      try {
        name = r.name();
        typeNum = r.u16();
        cls = r.u16();
        ttlRaw = r.u32();
        rdlen = r.u16();
        r.need(rdlen);
      } catch (err) {
        cut(err);
        break;
      }
      const start = r.pos;
      const end = start + rdlen;
      r.pos = end;
      if (typeNum === TYPES.OPT) {
        if (s !== 2) throw new DnsWireError('OPT record outside the additional section', ownerStart);
        if (edns) continue; // RFC 6891: more than one OPT is a FORMERR; keep the first
        if (name !== '.') throw new DnsWireError('OPT record owner must be the root', ownerStart);
        const opts = parseEdnsOptions(new Reader(msg, start, end));
        edns = {
          udpSize: cls,
          extendedRcode: ttlRaw >>> 24,
          version: (ttlRaw >>> 16) & 0xff,
          dnssecOk: (ttlRaw & 0x8000) !== 0,
          ...opts
        };
        continue;
      }
      const rr = {
        name,
        type: typeToName(typeNum),
        typeNum,
        class: cls,
        className: classToName(cls),
        ttl: ttlRaw > 0x7fffffff ? 0 : ttlRaw,
        ...parseRdata(msg, typeNum, start, end),
        rdata: msg.subarray(start, end)
      };
      sections[s].push(rr);
    }
  }
  const rcode = ((edns ? edns.extendedRcode : 0) << 4) | (lo & 0x0f);
  return {
    id,
    flags,
    rcode,
    rcodeName: rcodeToName(rcode),
    questions,
    answers: sections[0],
    authorities: sections[1],
    additionals: sections[2],
    edns,
    truncated,
    size: msg.length
  };
}

// ---------------------------------------------------------------------------
// Message encoder (responses included) — primarily for tests / mocks
// ---------------------------------------------------------------------------

function toStringList(v) {
  if (Array.isArray(v)) return v.map(String);
  return [String(v)];
}

function writeCharString(w, value) {
  const bytes = value instanceof Uint8Array ? value : utf8Encoder.encode(String(value));
  if (bytes.length > 255) throw new DnsWireError('character-string longer than 255 bytes');
  w.u8(bytes.length);
  w.bytes(bytes);
}

function writeIPv4(w, ip) {
  const b = parseIPv4Bytes(String(ip));
  if (!b) throw new DnsWireError(`invalid IPv4 address "${ip}"`);
  w.bytes(b);
}

function writeIPv6(w, ip) {
  const b = parseIPv6Bytes(String(ip));
  if (!b) throw new DnsWireError(`invalid IPv6 address "${ip}"`);
  w.bytes(b);
}

function writeTypeBitmap(w, types) {
  const nums = [...new Set(types.map((t) => {
    const n = typeToNumber(t);
    if (n === null) throw new DnsWireError(`unknown RR type "${t}" in bitmap`);
    return n;
  }))].sort((a, b) => a - b);
  const windows = new Map();
  for (const n of nums) {
    const win = n >>> 8;
    if (!windows.has(win)) windows.set(win, new Uint8Array(32));
    windows.get(win)[(n & 0xff) >>> 3] |= 0x80 >>> (n & 7);
  }
  for (const [win, bits] of windows) {
    let len = 32;
    while (len > 1 && bits[len - 1] === 0) len--;
    w.u8(win);
    w.u8(len);
    w.bytes(bits.subarray(0, len));
  }
}

function writeSvcParams(w, params = {}) {
  const entries = Object.entries(params).map(([k, v]) => {
    const m = /^key(\d+)$/.exec(k);
    const num = SVC_PARAM_NUMBERS[k] ?? (m ? Number(m[1]) : null);
    if (num === null || num > 0xffff) throw new DnsWireError(`unknown SvcParamKey "${k}"`);
    return [num, v];
  }).sort((a, b) => a[0] - b[0]);
  for (const [key, v] of entries) {
    const pw = new Writer(32);
    switch (key) {
      case 0: for (const k of v) {
        const n = SVC_PARAM_NUMBERS[k] ?? Number(/^key(\d+)$/.exec(k)?.[1]);
        pw.u16(checkUint(n, 0xffff, 'mandatory key'));
      } break;
      case 1: for (const id of toStringList(v)) writeCharString(pw, id); break;
      case 2: case 8: break;
      case 3: pw.u16(checkUint(Number(v), 0xffff, 'port')); break;
      case 4: for (const ip of toStringList(v)) writeIPv4(pw, ip); break;
      case 5: pw.bytes(base64Decode(v)); break;
      case 6: for (const ip of toStringList(v)) writeIPv6(pw, ip); break;
      case 7: pw.bytes(utf8Encoder.encode(String(v))); break;
      case 9: for (const g of v) pw.u16(checkUint(g, 0xffff, 'group')); break;
      default: pw.bytes(v instanceof Uint8Array ? v : hexDecode(v));
    }
    const val = pw.finish();
    w.u16(key);
    w.u16(val.length);
    w.bytes(val);
  }
}

function soaRname(v) {
  // Accept a mailbox ('hostmaster@example.com') for convenience.
  const at = v.indexOf('@');
  return at < 0 ? v : `${v.slice(0, at).replace(/\./g, '\\.')}.${v.slice(at + 1)}`;
}

/** RDATA writers keyed by type number (input shape = decoder `data` shape). */
const RDATA_WRITERS = {
  [TYPES.A]: (w, d) => writeIPv4(w, d),
  [TYPES.AAAA]: (w, d) => writeIPv6(w, d),
  [TYPES.NS]: (w, d) => w.name(d),
  [TYPES.CNAME]: (w, d) => w.name(d),
  [TYPES.PTR]: (w, d) => w.name(d),
  [TYPES.DNAME]: (w, d) => w.name(d),
  [TYPES.MX]: (w, d) => { w.u16(d.preference); w.name(d.exchange); },
  [TYPES.AFSDB]: (w, d) => { w.u16(d.subtype); w.name(d.hostname); },
  [TYPES.KX]: (w, d) => { w.u16(d.preference); w.name(d.exchanger); },
  [TYPES.RP]: (w, d) => { w.name(d.mbox); w.name(d.txt); },
  [TYPES.TXT]: (w, d) => { for (const s of toStringList(d)) writeCharString(w, s); },
  [TYPES.SPF]: (w, d) => { for (const s of toStringList(d)) writeCharString(w, s); },
  [TYPES.HINFO]: (w, d) => { writeCharString(w, d.cpu); writeCharString(w, d.os); },
  [TYPES.SOA]: (w, d) => {
    w.name(d.mname);
    w.name(soaRname(d.rname));
    for (const k of ['serial', 'refresh', 'retry', 'expire', 'minimum']) w.u32(checkUint(d[k] ?? 0, 0xffffffff, k));
  },
  [TYPES.SRV]: (w, d) => { w.u16(d.priority); w.u16(d.weight); w.u16(d.port); w.name(d.target); },
  [TYPES.NAPTR]: (w, d) => {
    w.u16(d.order); w.u16(d.preference);
    writeCharString(w, d.flags ?? ''); writeCharString(w, d.services ?? ''); writeCharString(w, d.regexp ?? '');
    w.name(d.replacement ?? '.');
  },
  [TYPES.CAA]: (w, d) => {
    const tag = utf8Encoder.encode(d.tag);
    w.u8(d.flags ?? 0); w.u8(tag.length); w.bytes(tag); w.bytes(utf8Encoder.encode(d.value ?? ''));
  },
  [TYPES.DS]: writeDs,
  [TYPES.CDS]: writeDs,
  [TYPES.DNSKEY]: writeDnskey,
  [TYPES.CDNSKEY]: writeDnskey,
  [TYPES.RRSIG]: (w, d) => {
    const secs = (x) => (x instanceof Date ? Math.floor(x.getTime() / 1000) : Number(x)) >>> 0;
    const covered = typeToNumber(d.typeCovered);
    if (covered === null) throw new DnsWireError(`unknown typeCovered "${d.typeCovered}"`);
    w.u16(covered); w.u8(d.algorithm); w.u8(d.labels); w.u32(d.originalTtl);
    w.u32(secs(d.expiration)); w.u32(secs(d.inception)); w.u16(d.keyTag);
    w.name(d.signerName); w.bytes(base64Decode(d.signature ?? ''));
  },
  [TYPES.NSEC]: (w, d) => { w.name(d.nextDomain); writeTypeBitmap(w, d.types ?? []); },
  [TYPES.TLSA]: writeTlsa,
  [TYPES.SMIMEA]: writeTlsa,
  [TYPES.SSHFP]: (w, d) => { w.u8(d.algorithm); w.u8(d.fpType); w.bytes(hexDecode(d.fingerprint)); },
  [TYPES.SVCB]: writeSvcb,
  [TYPES.HTTPS]: writeSvcb,
  [TYPES.URI]: (w, d) => { w.u16(d.priority); w.u16(d.weight); w.bytes(utf8Encoder.encode(d.target)); }
};

function writeDs(w, d) {
  w.u16(d.keyTag); w.u8(d.algorithm); w.u8(d.digestType); w.bytes(hexDecode(d.digest));
}

function writeDnskey(w, d) {
  w.u16(d.flags); w.u8(d.protocol ?? 3); w.u8(d.algorithm); w.bytes(base64Decode(d.publicKey));
}

function writeTlsa(w, d) {
  w.u8(d.usage); w.u8(d.selector); w.u8(d.matchingType); w.bytes(hexDecode(d.data));
}

function writeSvcb(w, d) {
  w.u16(d.priority); w.name(d.target ?? '.'); writeSvcParams(w, d.params);
}

/**
 * Types whose RDATA names a sender may compress (RFC 1035, RFC 3597 §4). A decoded
 * RR's raw `rdata` may then hold pointers into ITS message, so when the RR also
 * carries a valid `data` it is rebuilt from that (names written uncompressed).
 */
const COMPRESSIBLE_RDATA = new Set([
  TYPES.NS, TYPES.CNAME, TYPES.PTR, TYPES.DNAME, TYPES.MX, TYPES.SOA, TYPES.SRV, TYPES.AFSDB, TYPES.KX, TYPES.RP
]);

function writeRR(w, rr) {
  const typeNum = typeToNumber(rr.type ?? rr.typeNum);
  if (typeNum === null) throw new DnsWireError(`unknown RR type "${rr.type}"`);
  w.name(rr.name);
  w.u16(typeNum);
  w.u16(checkUint(rr.class ?? 1, 0xffff, 'class'));
  w.u32(checkUint(rr.ttl ?? 300, 0xffffffff, 'TTL'));
  const lenPos = w.len;
  w.u16(0);
  const start = w.len;
  const writer = RDATA_WRITERS[typeNum];
  const rebuild = writer && COMPRESSIBLE_RDATA.has(typeNum) && rr.data !== undefined && rr.data !== null && !rr.error;
  if (rr.rdata instanceof Uint8Array && !rebuild) {
    w.bytes(rr.rdata);
  } else {
    if (!writer) {
      if (typeof rr.data !== 'string') throw new DnsWireError(`no RDATA writer for ${typeToName(typeNum)}: pass rdata bytes or hex data`);
      w.bytes(hexDecode(rr.data));
    } else {
      writer(w, rr.data);
    }
  }
  w.setU16(lenPos, checkUint(w.len - start, 0xffff, 'RDATA length'));
}

/**
 * Encode a complete DNS message (no name compression). Mainly for tests and mocks:
 * the RR `data` shapes are the same as the decoder's output, so a decoded message can
 * be re-encoded. RRs may pass raw `rdata` (Uint8Array) instead of `data`; when an RR
 * carries both (a decoded RR), `rdata` is written as is, except for the types whose RDATA
 * names may be compressed (NS, CNAME, PTR, DNAME, MX, SOA, SRV, AFSDB, KX, RP): those
 * are rebuilt from a valid `data`, since the raw bytes may point into the old message.
 *
 * @param {object} msg
 * @param {number} [msg.id=0]
 * @param {object} [msg.flags] { qr, opcode, aa, tc, rd, ra, ad, cd }
 * @param {number|string} [msg.rcode=0] number or name ('NXDOMAIN'); >15 needs/creates EDNS
 * @param {Array<{name:string,type:string|number,class?:number}>} [msg.questions]
 * @param {Array<{name:string,type:string|number,ttl?:number,class?:number,data?:any,rdata?:Uint8Array}>} [msg.answers]
 * @param {Array} [msg.authorities]
 * @param {Array} [msg.additionals]
 * @param {null|object} [msg.edns] { udpSize, version, dnssecOk, options: [{code,data}], ecs: 'a.b.c.d/24'|{address,sourcePrefix,scopePrefix}, ede: [{code,text}], nsid: string }
 * @returns {Uint8Array}
 */
export function encodeMessage({
  id = 0, flags = {}, rcode = 0, questions = [], answers = [], authorities = [], additionals = [], edns = null
} = {}) {
  let rc = rcode;
  if (typeof rc === 'string') {
    const found = Object.entries(RCODES).find(([, v]) => v === rc.toUpperCase());
    if (!found) throw new DnsWireError(`unknown rcode "${rcode}"`);
    rc = Number(found[0]);
  }
  checkUint(rc, 0xfff, 'rcode');
  let opt = edns;
  if (rc > 15 && !opt) opt = {};
  const w = new Writer();
  w.u16(checkUint(id, 0xffff, 'message id'));
  writeHeaderFlags(w, flags, rc);
  w.u16(questions.length);
  w.u16(answers.length);
  w.u16(authorities.length);
  w.u16(additionals.length + (opt ? 1 : 0));
  for (const q of questions) {
    const t = typeToNumber(q.type ?? q.typeNum);
    if (t === null) throw new DnsWireError(`unknown RR type "${q.type}"`);
    w.name(q.name);
    w.u16(t);
    w.u16(checkUint(q.class ?? 1, 0xffff, 'class'));
  }
  for (const rr of answers) writeRR(w, rr);
  for (const rr of authorities) writeRR(w, rr);
  for (const rr of additionals) writeRR(w, rr);
  if (opt) {
    const options = [...(opt.options || [])].map((o) => ({ code: o.code, data: o.data instanceof Uint8Array ? o.data : hexDecode(o.data || '') }));
    if (opt.nsid !== undefined && opt.nsid !== null) options.push({ code: OPT_NSID, data: utf8Encoder.encode(String(opt.nsid)) });
    if (opt.ecs) {
      const scope = typeof opt.ecs === 'object' ? checkUint(opt.ecs.scopePrefix ?? 0, 128, 'ECS scope prefix') : 0;
      options.push({ code: OPT_ECS, data: ecsOptionData(opt.ecs, scope) });
    }
    for (const e of opt.ede || []) {
      const text = utf8Encoder.encode(e.text || '');
      const data = new Uint8Array(2 + text.length);
      data[0] = (e.code >>> 8) & 0xff;
      data[1] = e.code & 0xff;
      data.set(text, 2);
      options.push({ code: OPT_EDE, data });
    }
    writeOpt(w, {
      udpSize: opt.udpSize ?? 1232,
      version: opt.version ?? 0,
      dnssecOk: !!opt.dnssecOk,
      extendedRcode: rc >>> 4,
      options
    });
  }
  return w.finish();
}
