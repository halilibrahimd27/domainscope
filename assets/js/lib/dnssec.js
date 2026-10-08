/**
 * dnssec.js — in-browser DNSSEC chain-of-trust validator: from the IANA root trust anchors
 * (lib/dnssec-anchors.js) down every zone cut to a name, then that name's answer.
 *
 * Every question goes through the shared DoH client (`dns.query`, lib/doh.js) with the DO bit
 * (signatures and NSEC / NSEC3 records) and the CD bit (the resolver hands over what it would
 * refuse itself, so a broken chain is shown and explained instead of a bare SERVFAIL):
 *  - the root: its DNSKEY set must hold a key whose digest matches a trust anchor, and that key
 *    must sign the set;
 *  - every name between the root and the target, top down: its DS set at the parent, signed by
 *    the parent's keys. A DS set makes the name a zone cut: its DNSKEY set must hold a key that
 *    matches a DS digest (SHA-1, SHA-256, SHA-384) and that key must sign the set. No DS: the
 *    name is a cut only when it is a zone apex (the NSEC / NSEC3 record at the name says so, or
 *    else its SOA); an apex without DS is an unsigned delegation (insecure), proven when the
 *    parent's signed NSEC / NSEC3 records show the delegation without a DS;
 *  - the answer: the RRset of the type asked, signed by the deepest zone's keys; a CNAME is
 *    checked and followed (up to {@link MAX_ALIASES} hops); no data or no name is checked
 *    against the zone's NSEC (RFC 4035 §5.4) or NSEC3 (RFC 5155 §8) records.
 *
 * Signatures are checked as RFC 4034 §3.1.8.1 and §6 say: the RRSIG RDATA without its
 * signature and with the signer's name in canonical form, then each RR of the set with its
 * canonical owner name (the wildcard owner when the RRSIG has fewer labels), the original TTL
 * and canonical RDATA (names of the RFC 1035 types and SRV / RP / AFSDB / KX rebuilt in
 * lowercase, uncompressed), in canonical order, duplicates removed. The validity window is
 * checked against an injectable `now`. WebCrypto checks RSA/SHA-1 (algorithms 5 and 7),
 * RSA/SHA-256 (8), RSA/SHA-512 (10), ECDSA P-256 and P-384 with raw r||s signatures (13, 14),
 * Ed25519 (15) and Ed448 (16) where the runtime has them; any other algorithm, or one the
 * runtime lacks, is 'unsupported-algorithm', which RFC 4035 §5.2 makes insecure, never bogus.
 *
 * Result: `secure`, `insecure` (provably unsigned, or signed with what cannot be checked here),
 * `bogus` (with the exact reason and the zone it happened in) or `indeterminate` (a question got
 * no answer). Reasons are codes ({@link DNSSEC_REASONS}); the panel (ui/dnssec-panel.js) turns
 * them into words and into what to fix.
 *
 * DOM-free; I/O only through `dns.query`, crypto only through `crypto.subtle`. Only an abort
 * rejects.
 */

import { encodeName, computeKeyTag, hexEncode, base64Decode, base64UrlEncode, typeToNumber } from './dnswire.js';
import { ROOT_ANCHORS } from './dnssec-anchors.js';

/** Statuses of a zone, the answer and the whole chain, best first. */
export const DNSSEC_STATUSES = Object.freeze(['secure', 'insecure', 'bogus', 'indeterminate']);

/** Why a zone or the answer is not secure (`dnssec.reason.<code>` in the UI). */
export const DNSSEC_REASONS = Object.freeze([
  'anchor-mismatch', 'no-dnskey', 'ds-no-match', 'dnskey-unsigned', 'no-rrsig', 'no-key', 'sig-expired',
  'sig-not-yet-valid', 'sig-invalid', 'signer-mismatch', 'bad-labels', 'unsupported-algorithm', 'unsupported-digest',
  'no-ds', 'no-ds-unproven', 'denial-missing', 'denial-invalid', 'nsec3-iterations', 'opt-out', 'query-failed',
  'rcode', 'alias-loop', 'chain-broken'
]);

/** Outcomes of one RRSIG check. */
export const SIG_RESULTS = Object.freeze([
  'valid', 'expired', 'not-yet-valid', 'bad-signature', 'no-key', 'unsupported-algorithm', 'signer-mismatch', 'bad-labels'
]);

/** Algorithms this module can check when the runtime's WebCrypto has them. */
export const CHECKED_ALGORITHMS = Object.freeze([5, 7, 8, 10, 13, 14, 15, 16]);

/** DS digest types this module can check (SHA-1, SHA-256, SHA-384). */
export const CHECKED_DIGESTS = Object.freeze([1, 2, 4]);

/** How many CNAME hops the answer is followed. */
export const MAX_ALIASES = 8;

/** NSEC3 iterations above this are not computed (RFC 9276 §3.2: the answer is then insecure). */
export const MAX_NSEC3_ITERATIONS = 150;

const DIGEST_NAMES = Object.freeze({ 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' });
const RSA_HASH = Object.freeze({ 5: 'SHA-1', 7: 'SHA-1', 8: 'SHA-256', 10: 'SHA-512' });
const EC_PARAMS = Object.freeze({
  13: { curve: 'P-256', hash: 'SHA-256', size: 32 },
  14: { curve: 'P-384', hash: 'SHA-384', size: 48 }
});
const EDDSA = Object.freeze({ 15: { name: 'Ed25519', key: 32, sig: 64 }, 16: { name: 'Ed448', key: 57, sig: 114 } });
/** The failure a set of signatures is reported by, most telling first. */
const SIG_FAILURE_ORDER = ['expired', 'not-yet-valid', 'bad-signature', 'no-key', 'signer-mismatch', 'bad-labels', 'unsupported-algorithm'];
const SIG_REASON = Object.freeze({
  expired: 'sig-expired', 'not-yet-valid': 'sig-not-yet-valid', 'bad-signature': 'sig-invalid', 'no-key': 'no-key',
  'signer-mismatch': 'signer-mismatch', 'bad-labels': 'bad-labels', 'unsupported-algorithm': 'unsupported-algorithm'
});
const RANK = Object.freeze({ secure: 0, insecure: 1, indeterminate: 2, bogus: 3 });
const ANSWERED = new Set(['NOERROR', 'NXDOMAIN']);

/**
 * @typedef {object} SigCheck
 * @property {number} keyTag
 * @property {number} algorithm
 * @property {string} signer
 * @property {number|null} inception ms since the epoch
 * @property {number|null} expiration ms since the epoch
 * @property {number} labels
 * @property {string} result one of {@link SIG_RESULTS}
 */

/**
 * @typedef {object} KeyInfo
 * @property {number} keyTag
 * @property {number} flags
 * @property {number} algorithm
 * @property {'ksk'|'zsk'} role KSK: the secure entry point flag (257)
 * @property {boolean} revoked
 * @property {number|null} bits key size
 * @property {boolean} matchesDs a DS (or a trust anchor) names this key and its digest matches
 * @property {boolean} signsKeys this key's signature over the DNSKEY set verifies
 */

/**
 * @typedef {object} DsInfo
 * @property {number} keyTag
 * @property {number} algorithm
 * @property {number} digestType
 * @property {string} digest lowercase hex
 * @property {boolean} supported digest type and algorithm checked here
 * @property {number|null} matches key tag of the DNSKEY whose digest matches, or null
 */

/**
 * @typedef {object} Denial
 * @property {'nsec'|'nsec3'|null} kind
 * @property {boolean} signed every NSEC / NSEC3 record used verifies
 * @property {string|null} sigResult the failure when not signed
 * @property {boolean} nodata the name exists without the type (and without a CNAME)
 * @property {boolean} nxdomain the name and any wildcard that could answer for it do not exist
 * @property {boolean|null} delegation the name is a delegation (NS without SOA); null: unknown
 * @property {boolean} hasDs the record at the name says a DS exists
 * @property {boolean} optOut an opt-out NSEC3 covers the name (it may be an unsigned delegation)
 * @property {number|null} iterations NSEC3 iterations
 * @property {boolean} tooManyIterations NSEC3 iterations above {@link MAX_NSEC3_ITERATIONS}: not computed
 */

/**
 * @typedef {object} ZoneStep
 * @property {string} zone
 * @property {string|null} parent
 * @property {string} status one of {@link DNSSEC_STATUSES}
 * @property {string|null} reason one of {@link DNSSEC_REASONS}
 * @property {'anchor'|'parent'} dsSource
 * @property {DsInfo[]} ds
 * @property {SigCheck[]} dsSigs the parent's signatures over the DS set
 * @property {KeyInfo[]} keys
 * @property {SigCheck[]} keySigs signatures over the DNSKEY set
 * @property {Denial|null} denial how "no DS" was shown (an unsigned delegation)
 * @property {object|null} failure the DnsResponse of a question that got no answer
 *   ({ error, errorKind, retryAfterMs, resolver, rcode, qname, qtype })
 */

/**
 * @typedef {object} AnswerStep
 * @property {string} name
 * @property {string} type
 * @property {string|null} zone the zone whose keys checked it
 * @property {string} status
 * @property {string|null} reason
 * @property {string|null} rcode
 * @property {object[]} records the RRset (lib/dnswire RRs)
 * @property {SigCheck[]} sigs
 * @property {Denial|null} denial
 * @property {boolean} wildcard the answer was expanded from a wildcard (RRSIG labels)
 * @property {{ target: string, result: ChainResult }|null} alias the CNAME followed
 * @property {object|null} failure
 */

/**
 * @typedef {object} ChainResult
 * @property {string} name
 * @property {string} type
 * @property {string} status one of {@link DNSSEC_STATUSES}
 * @property {string|null} reason the first break's reason
 * @property {string|null} breakAt the zone (or 'answer') where the chain first stops being secure
 * @property {ZoneStep[]} zones top down, the root first
 * @property {AnswerStep|null} answer null when the chain broke above the answer
 * @property {number} queries questions asked
 * @property {number} at the `now` the run checked against (ms)
 */

/* ------------------------------------------------------------------------ */
/* Bytes and names                                                          */
/* ------------------------------------------------------------------------ */

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const u16 = (n) => Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
const u32 = (n) => Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

const sameBytes = (a, b) => a.length === b.length && compareBytes(a, b) === 0;

/**
 * A name in canonical wire form (RFC 4034 §6.2): uncompressed, ASCII letters lowercased.
 * @param {string} name presentation form ('www.example.com', '.' for the root)
 * @returns {Uint8Array}
 */
export function canonicalName(name) {
  const out = new Uint8Array(encodeName(name === '.' ? '' : String(name)));
  // Length octets are at most 63, never an uppercase ASCII letter (65–90).
  for (let i = 0; i < out.length; i++) if (out[i] >= 0x41 && out[i] <= 0x5a) out[i] |= 0x20;
  return out;
}

/** The labels of a wire name, leftmost first. */
function wireLabels(wire) {
  const out = [];
  let p = 0;
  while (p < wire.length && wire[p] !== 0) {
    out.push(wire.subarray(p + 1, p + 1 + wire[p]));
    p += wire[p] + 1;
  }
  return out;
}

const labelsOf = (name) => wireLabels(canonicalName(name));

/** Labels of a presentation name (escapes kept), leftmost first; [] for the root. */
function splitLabels(name) {
  if (!name || name === '.') return [];
  const out = [];
  let cur = '';
  for (let i = 0; i < name.length; i++) {
    const c = name[i];
    if (c === '\\') {
      cur += c + (name[i + 1] ?? '');
      i += 1;
    } else if (c === '.') {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  if (cur) out.push(cur);
  return out;
}

const joinLabels = (labels) => (labels.length ? labels.join('.') : '.');

/** Lowercase presentation name without trailing dot, '.' for the root. */
function normName(name) {
  const s = String(name ?? '').trim().toLowerCase().replace(/\.$/, '');
  return s || '.';
}

/**
 * The names from the top-level label down to `name` ('www.example.com' → com, example.com,
 * www.example.com); [] for the root.
 * @param {string} name
 * @returns {string[]}
 */
export function namesBelowRoot(name) {
  const labels = splitLabels(normName(name));
  const out = [];
  for (let i = labels.length - 1; i >= 0; i--) out.push(joinLabels(labels.slice(i)));
  return out;
}

const isAtOrBelow = (name, zone) => zone === '.' || name === zone || name.endsWith(`.${zone}`);

const parentName = (name) => (name === '.' ? null : joinLabels(splitLabels(name).slice(1)));

/**
 * RFC 4034 §6.1 canonical order of two names: label by label from the right, each label as
 * lowercase octets; an ancestor sorts before its descendants.
 * @param {string} a
 * @param {string} b
 * @returns {number} <0, 0 or >0
 */
export function compareNames(a, b) {
  const la = labelsOf(a).reverse();
  const lb = labelsOf(b).reverse();
  const n = Math.min(la.length, lb.length);
  for (let i = 0; i < n; i++) {
    const c = compareBytes(la[i], lb[i]);
    if (c) return c;
  }
  return la.length - lb.length;
}

/** RRSIG labels count of a name: the root and a leading '*' label do not count. */
function sigLabelCount(name) {
  const labels = labelsOf(name);
  return labels.length && labels[0].length === 1 && labels[0][0] === 0x2a ? labels.length - 1 : labels.length;
}

/* ------------------------------------------------------------------------ */
/* Canonical RRsets (RFC 4034 §3.1.8.1, §6)                                 */
/* ------------------------------------------------------------------------ */

/**
 * Canonical RDATA of a decoded RR: the names of the types whose RDATA names a sender may
 * compress, or that RFC 4034 §6.2 (as amended by RFC 6840 §5.1) lowercases, are rebuilt from the
 * decoded `data`; any other type's RDATA is its raw bytes.
 * @param {object} rr lib/dnswire RR ({ type, data, rdata })
 * @returns {Uint8Array}
 */
export function canonicalRdata(rr) {
  const d = rr.data;
  const raw = rr.rdata instanceof Uint8Array ? rr.rdata : null;
  if (!rr.error && d !== undefined && d !== null) {
    switch (rr.type) {
      case 'NS': case 'CNAME': case 'PTR': case 'DNAME': case 'MB': case 'MG': case 'MR': case 'MD': case 'MF':
        if (typeof d === 'string') return canonicalName(d);
        break;
      case 'MX':
        if (typeof d.exchange === 'string') return concat([u16(d.preference), canonicalName(d.exchange)]);
        break;
      case 'KX':
        if (typeof d.exchanger === 'string') return concat([u16(d.preference), canonicalName(d.exchanger)]);
        break;
      case 'AFSDB':
        if (typeof d.hostname === 'string') return concat([u16(d.subtype), canonicalName(d.hostname)]);
        break;
      case 'SRV':
        if (typeof d.target === 'string') return concat([u16(d.priority), u16(d.weight), u16(d.port), canonicalName(d.target)]);
        break;
      case 'RP':
        if (typeof d.mbox === 'string') return concat([canonicalName(d.mbox), canonicalName(d.txt)]);
        break;
      case 'NAPTR':
        // Never compressed (RFC 3403), but RFC 4034 §6.2 lowercases its replacement name.
        if (raw) return lowercaseNameAt(raw, naptrNameOffset(raw));
        break;
      case 'SOA':
        if (typeof d.mname === 'string' && raw && raw.length >= 20) {
          // The five counters are the last 20 octets, never compressed.
          return concat([canonicalName(d.mname), canonicalName(soaRnameAsName(d.rname)), raw.subarray(raw.length - 20)]);
        }
        break;
      default:
    }
  }
  if (raw) return raw;
  throw new Error(`no RDATA for ${rr.type}`);
}

/** Where a NAPTR's replacement name starts: after order, preference and three character strings. */
function naptrNameOffset(raw) {
  let p = 4;
  for (let i = 0; i < 3 && p < raw.length; i++) p += 1 + raw[p];
  return Math.min(p, raw.length);
}

/** A copy of `raw` with the ASCII letters of the wire name at `from` lowercased. */
function lowercaseNameAt(raw, from) {
  const out = new Uint8Array(raw);
  let p = from;
  while (p < out.length && out[p] !== 0 && out[p] < 64) {
    const end = Math.min(out.length, p + 1 + out[p]);
    for (let i = p + 1; i < end; i++) if (out[i] >= 0x41 && out[i] <= 0x5a) out[i] |= 0x20;
    p = end;
  }
  return out;
}

/** lib/dnswire may present an RNAME as a mailbox ('hostmaster@example.com'): back to a name. */
function soaRnameAsName(v) {
  const m = /^((?:[^@\\]|\\.)*)@(.*)$/.exec(String(v));
  return m ? `${m[1].replace(/\\.|\./g, (s) => (s === '.' ? '\\.' : s))}.${m[2]}` : String(v);
}

/** RFC 4034 §3.1.3: an RRSIG with fewer labels than its owner signed the wildcard owner. */
function signedOwner(owner, labels) {
  const all = labelsOf(owner);
  const own = sigLabelCount(owner);
  if (labels > own) return null;
  if (labels === own) return canonicalName(owner);
  const kept = all.slice(all.length - labels);
  return concat([Uint8Array.of(1, 0x2a), ...kept.flatMap((l) => [Uint8Array.of(l.length), l]), Uint8Array.of(0)]);
}

/**
 * The octets an RRSIG signs (RFC 4034 §3.1.8.1): RRSIG RDATA without the signature, then each RR
 * of the set in canonical form and order with the original TTL.
 * @param {object} sig decoded RRSIG RR
 * @param {object[]} rrset decoded RRs of one owner, type and class
 * @returns {Uint8Array|null} null when the RRSIG's labels exceed the owner's
 */
export function signedData(sig, rrset) {
  const d = sig.data;
  const owner = signedOwner(rrset[0].name, d.labels);
  if (!owner) return null;
  const typeNum = typeToNumber(rrset[0].type);
  const cls = rrset[0].class ?? 1;
  const head = sig.rdata instanceof Uint8Array && sig.rdata.length >= 18
    ? sig.rdata.subarray(0, 18)
    : concat([u16(typeToNumber(d.typeCovered)), Uint8Array.of(d.algorithm, d.labels), u32(d.originalTtl),
      u32(Math.floor(timeMs(d.expiration) / 1000)), u32(Math.floor(timeMs(d.inception) / 1000)), u16(d.keyTag)]);
  const rdatas = rrset.map(canonicalRdata).sort(compareBytes)
    .filter((r, i, all) => i === 0 || compareBytes(r, all[i - 1]) !== 0);
  const parts = [head, canonicalName(d.signerName)];
  for (const r of rdatas) parts.push(owner, u16(typeNum), u16(cls), u32(d.originalTtl), u16(r.length), r);
  return concat(parts);
}

function timeMs(x) {
  if (x instanceof Date) return x.getTime();
  if (typeof x === 'number') return x;
  const t = Date.parse(x);
  return Number.isFinite(t) ? t : NaN;
}

/* ------------------------------------------------------------------------ */
/* Crypto                                                                   */
/* ------------------------------------------------------------------------ */

function stripZeros(b) {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}

/** RFC 3110 RSA public key → { e, n } octets, or null. */
function rsaParts(key) {
  if (key.length < 3) return null;
  let p = 1;
  let eLen = key[0];
  if (eLen === 0) {
    eLen = (key[1] << 8) | key[2];
    p = 3;
  }
  if (!eLen || p + eLen >= key.length) return null;
  return { e: key.subarray(p, p + eLen), n: key.subarray(p + eLen) };
}

/**
 * The size of a DNSKEY's key in bits (RSA: the modulus), or null.
 * @param {number} algorithm
 * @param {Uint8Array} key public key octets
 * @returns {number|null}
 */
export function keyBits(algorithm, key) {
  if (RSA_HASH[algorithm]) {
    const parts = rsaParts(key);
    if (!parts) return null;
    const n = stripZeros(parts.n);
    return n.length ? (n.length - 1) * 8 + Math.floor(Math.log2(n[0])) + 1 : null;
  }
  if (EC_PARAMS[algorithm]) return EC_PARAMS[algorithm].size * 8;
  if (algorithm === 15) return 256;
  if (algorithm === 16) return 456;
  return null;
}

const unsupported = (err) => !!err && (err.name === 'NotSupportedError' || /not ?supported|unrecognized|unknown algorithm/i.test(String(err.message || '')));

/**
 * Verify one signature with one DNSKEY public key.
 * @param {number} algorithm
 * @param {Uint8Array} key DNSKEY public key octets
 * @param {Uint8Array} sig signature octets
 * @param {Uint8Array} data signed octets
 * @param {SubtleCrypto} subtle
 * @returns {Promise<'valid'|'bad-signature'|'unsupported-algorithm'>}
 */
export async function verifySignature(algorithm, key, sig, data, subtle) {
  if (!subtle) return 'unsupported-algorithm';
  let cryptoKey;
  let params;
  try {
    if (RSA_HASH[algorithm]) {
      const parts = rsaParts(key);
      if (!parts) return 'bad-signature';
      const jwk = { kty: 'RSA', e: base64UrlEncode(stripZeros(parts.e)), n: base64UrlEncode(stripZeros(parts.n)), ext: true };
      params = { name: 'RSASSA-PKCS1-v1_5' };
      cryptoKey = await subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: RSA_HASH[algorithm] }, false, ['verify']);
    } else if (EC_PARAMS[algorithm]) {
      const ec = EC_PARAMS[algorithm];
      if (key.length !== ec.size * 2 || sig.length !== ec.size * 2) return 'bad-signature';
      params = { name: 'ECDSA', hash: ec.hash };
      cryptoKey = await subtle.importKey('raw', concat([Uint8Array.of(4), key]), { name: 'ECDSA', namedCurve: ec.curve }, false, ['verify']);
    } else if (EDDSA[algorithm]) {
      const ed = EDDSA[algorithm];
      if (key.length !== ed.key || sig.length !== ed.sig) return 'bad-signature';
      params = { name: ed.name };
      cryptoKey = await subtle.importKey('raw', key, { name: ed.name }, false, ['verify']);
    } else {
      return 'unsupported-algorithm';
    }
  } catch (err) {
    return unsupported(err) ? 'unsupported-algorithm' : 'bad-signature';
  }
  try {
    return (await subtle.verify(params, cryptoKey, sig, data)) ? 'valid' : 'bad-signature';
  } catch (err) {
    return unsupported(err) ? 'unsupported-algorithm' : 'bad-signature';
  }
}

/**
 * The DS digest of a DNSKEY (RFC 4034 §5.1.4): hash(owner name | DNSKEY RDATA).
 * @param {string} owner
 * @param {Uint8Array} dnskeyRdata
 * @param {number} digestType 1, 2 or 4
 * @param {SubtleCrypto} subtle
 * @returns {Promise<string|null>} lowercase hex, null for a digest type not checked here
 */
export async function dsDigest(owner, dnskeyRdata, digestType, subtle) {
  const name = DIGEST_NAMES[digestType];
  if (!name || !subtle) return null;
  return hexEncode(new Uint8Array(await subtle.digest(name, concat([canonicalName(owner), dnskeyRdata]))));
}

/**
 * RFC 5155 §5 hash of a name: SHA-1 over the canonical name and the salt, iterated.
 * @param {string} name
 * @param {string} saltHex
 * @param {number} iterations
 * @param {SubtleCrypto} subtle
 * @returns {Promise<string>} lowercase base32hex without padding
 */
export async function nsec3Hash(name, saltHex, iterations, subtle) {
  const salt = saltHex ? hexToBytes(saltHex) : new Uint8Array(0);
  let x = new Uint8Array(await subtle.digest('SHA-1', concat([canonicalName(name), salt])));
  for (let i = 0; i < iterations; i++) x = new Uint8Array(await subtle.digest('SHA-1', concat([x, salt])));
  return base32Hex(x);
}

function hexToBytes(hex) {
  const s = String(hex).replace(/[^0-9a-f]/gi, '');
  const out = new Uint8Array(s.length >>> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function base32Hex(bytes) {
  const A = '0123456789abcdefghijklmnopqrstuv';
  let out = '';
  let bits = 0;
  let acc = 0;
  for (const b of bytes) {
    acc = ((acc << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += A[(acc >>> bits) & 31];
    }
  }
  if (bits > 0) out += A[(acc << (5 - bits)) & 31];
  return out;
}

/* ------------------------------------------------------------------------ */
/* RRset checks                                                             */
/* ------------------------------------------------------------------------ */

const keyOctets = (rr) => base64Decode(rr.data.publicKey || '');

/** RRSIGs in `rrs` over (owner, type). */
const sigsFor = (rrs, owner, type) => rrs.filter((rr) => rr.type === 'RRSIG' && !rr.error && rr.data && rr.name === owner && rr.data.typeCovered === type);

/**
 * Check the RRSIGs over one RRset with a zone's keys.
 * @param {object[]} rrset
 * @param {object[]} sigs RRSIG RRs over it
 * @param {object[]} keys DNSKEY RRs allowed to sign it
 * @param {string} zone the signer the RRSIGs must name
 * @param {{ now: number, subtle: SubtleCrypto }} env
 * @returns {Promise<{ result: string, checks: SigCheck[], validKeys: number[] }>} result 'valid', 'no-rrsig'
 *   or the most telling failure ({@link SIG_RESULTS})
 */
export async function verifyRRset(rrset, sigs, keys, zone, { now, subtle }) {
  const checks = [];
  const validKeys = [];
  for (const sig of sigs) {
    const d = sig.data;
    const check = {
      keyTag: d.keyTag, algorithm: d.algorithm, signer: d.signerName, labels: d.labels,
      inception: timeMs(d.inception), expiration: timeMs(d.expiration), result: 'bad-signature'
    };
    checks.push(check);
    if (normName(d.signerName) !== zone) {
      check.result = 'signer-mismatch';
      continue;
    }
    const data = signedData(sig, rrset);
    if (!data) {
      check.result = 'bad-labels';
      continue;
    }
    if (!(now >= check.inception)) {
      check.result = 'not-yet-valid';
      continue;
    }
    if (!(now <= check.expiration)) {
      check.result = 'expired';
      continue;
    }
    const candidates = keys.filter((k) => k.data.keyTag === d.keyTag && k.data.algorithm === d.algorithm
      && k.data.zoneKey && k.data.protocol === 3 && !k.data.revoked);
    if (!candidates.length) {
      check.result = 'no-key';
      continue;
    }
    const sigBytes = base64Decode(d.signature || '');
    for (const k of candidates) {
      check.result = await verifySignature(d.algorithm, keyOctets(k), sigBytes, data, subtle);
      if (check.result === 'valid') {
        validKeys.push(k.data.keyTag);
        break;
      }
    }
  }
  if (checks.some((c) => c.result === 'valid')) return { result: 'valid', checks, validKeys };
  if (!checks.length) return { result: 'no-rrsig', checks, validKeys };
  const result = SIG_FAILURE_ORDER.find((r) => checks.some((c) => c.result === r)) || 'bad-signature';
  return { result, checks, validKeys };
}

/** The zone status and reason a failed RRset check means. */
function sigOutcome(result) {
  if (result === 'valid') return { status: 'secure', reason: null };
  if (result === 'unsupported-algorithm') return { status: 'insecure', reason: 'unsupported-algorithm' };
  if (result === 'no-rrsig') return { status: 'bogus', reason: 'no-rrsig' };
  return { status: 'bogus', reason: SIG_REASON[result] || 'sig-invalid' };
}

/* ------------------------------------------------------------------------ */
/* Denial of existence (RFC 4035 §5.4, RFC 5155 §8)                          */
/* ------------------------------------------------------------------------ */

/** NSEC `owner`→`next` covers `name` (strictly between, the last NSEC wrapping to the apex). */
function nsecCovers(owner, next, name) {
  if (compareNames(owner, name) >= 0) return false;
  return compareNames(name, next) < 0 || compareNames(next, owner) <= 0;
}

function hashCovers(owner, next, hash) {
  if (owner < next) return owner < hash && hash < next;
  return hash > owner || hash < next; // the last NSEC3 of the chain wraps around
}

/** The longest ancestor of `name` (itself included) that is at or above both names. */
function commonAncestor(a, b) {
  const la = splitLabels(a).reverse();
  const lb = splitLabels(b).reverse();
  const out = [];
  for (let i = 0; i < Math.min(la.length, lb.length) && la[i] === lb[i]; i++) out.push(la[i]);
  return joinLabels(out.reverse());
}

/**
 * Read the NSEC or NSEC3 records of a negative answer: what they show about `qname` / `qtype`
 * and whether their signatures verify with the zone's keys.
 * @param {object} res DnsResponse
 * @param {string} qname
 * @param {string} qtype
 * @param {string} zone
 * @param {object[]} keys the zone's trusted DNSKEY RRs
 * @param {{ now: number, subtle: SubtleCrypto }} env
 * @param {{ closestEncloser?: string }} [opts] a wildcard answer: the closest encloser its RRSIG
 *   labels name, so only the next closer name must be shown not to exist
 * @returns {Promise<Denial>}
 */
export async function readDenial(res, qname, qtype, zone, keys, env, { closestEncloser = null } = {}) {
  const all = [...(res.answers || []), ...(res.authorities || [])];
  const out = {
    kind: null, signed: false, sigResult: null, nodata: false, nxdomain: false, delegation: null,
    hasDs: false, optOut: false, iterations: null, tooManyIterations: false
  };
  const nsecs = all.filter((rr) => rr.type === 'NSEC' && !rr.error && rr.data && isAtOrBelow(rr.name, zone));
  const nsec3s = all.filter((rr) => rr.type === 'NSEC3' && !rr.error && rr.data && isAtOrBelow(rr.name, zone));
  const used = [];
  if (nsecs.length) {
    out.kind = 'nsec';
    const match = nsecs.find((rr) => rr.name === qname);
    if (match) {
      used.push(match);
      readBitmap(out, match.data.types || [], qtype);
    } else {
      const cover = nsecs.find((rr) => nsecCovers(rr.name, normName(rr.data.nextDomain), qname));
      if (cover) {
        used.push(cover);
        const next = normName(cover.data.nextDomain);
        if (next !== qname && isAtOrBelow(next, qname)) {
          out.nodata = true; // an empty non-terminal: names exist below it
          out.delegation = false;
        } else {
          const ce = [commonAncestor(qname, cover.name), commonAncestor(qname, next)]
            .sort((a, b) => splitLabels(b).length - splitLabels(a).length)[0];
          const wildcard = ce === '.' ? '*' : `*.${ce}`;
          const wild = nsecs.find((rr) => nsecCovers(rr.name, normName(rr.data.nextDomain), wildcard));
          if (wild) {
            used.push(wild);
            out.nxdomain = true;
          }
        }
      }
    }
  } else if (nsec3s.length) {
    out.kind = 'nsec3';
    const p = nsec3s[0].data;
    out.iterations = p.iterations;
    if (p.hashAlgorithm !== 1 || p.iterations > MAX_NSEC3_ITERATIONS) {
      out.tooManyIterations = p.iterations > MAX_NSEC3_ITERATIONS;
    } else {
      const records = nsec3s.filter((rr) => rr.data.salt === p.salt && rr.data.iterations === p.iterations)
        .map((rr) => ({ rr, hash: splitLabels(rr.name)[0], next: String(rr.data.nextHashedOwner || '').toLowerCase() }));
      const hash = (name) => nsec3Hash(name, p.salt, p.iterations, env.subtle);
      const matchOf = async (name) => {
        const h = await hash(name);
        return records.find((r) => r.hash === h) || null;
      };
      const coverOf = async (name) => {
        const h = await hash(name);
        return records.find((r) => hashCovers(r.hash, r.next, h)) || null;
      };
      const match = closestEncloser ? null : await matchOf(qname);
      if (closestEncloser) {
        const labels = splitLabels(qname);
        const nextCloser = joinLabels(labels.slice(labels.length - splitLabels(closestEncloser).length - 1));
        const cover = await coverOf(nextCloser);
        if (cover) {
          used.push(cover.rr);
          out.optOut = (cover.rr.data.flags & 1) === 1;
        }
      } else if (match) {
        used.push(match.rr);
        readBitmap(out, match.rr.data.types || [], qtype);
      } else {
        // Closest encloser proof: the longest existing ancestor, the next closer name covered.
        const labels = splitLabels(qname);
        for (let i = 1; i <= labels.length; i++) {
          const ce = joinLabels(labels.slice(i));
          if (!isAtOrBelow(ce, zone)) break;
          const ceMatch = await matchOf(ce);
          if (!ceMatch) continue;
          const nextCloser = joinLabels(labels.slice(i - 1));
          const cover = await coverOf(nextCloser);
          if (!cover) break;
          used.push(ceMatch.rr, cover.rr);
          out.optOut = (cover.rr.data.flags & 1) === 1;
          const wild = await coverOf(ce === '.' ? '*' : `*.${ce}`);
          if (wild) {
            used.push(wild.rr);
            out.nxdomain = true;
          }
          break;
        }
      }
    }
  }
  if (used.length) {
    out.signed = true;
    for (const rr of [...new Set(used)]) {
      const v = await verifyRRset([rr], sigsFor(all, rr.name, rr.type), keys, zone, env);
      if (v.result !== 'valid') {
        out.signed = false;
        out.sigResult = v.result;
        break;
      }
    }
  }
  return out;
}

function readBitmap(out, types, qtype) {
  out.nodata = !types.includes(qtype) && !types.includes('CNAME');
  out.delegation = types.includes('NS') && !types.includes('SOA');
  out.hasDs = types.includes('DS');
}

/* ------------------------------------------------------------------------ */
/* The walk                                                                 */
/* ------------------------------------------------------------------------ */

function failureOf(res, qname, qtype) {
  return {
    qname, qtype, resolver: res ? res.resolver ?? null : null, rcode: res ? res.rcode ?? null : null,
    error: res ? res.error ?? null : null, errorKind: res ? res.errorKind ?? null : null,
    retryAfterMs: res ? res.retryAfterMs ?? null : null, ok: res ? !!res.ok : false
  };
}

const answered = (res) => !!res && res.ok && ANSWERED.has(res.rcode);

function dsInfo(ds) {
  return {
    keyTag: ds.keyTag, algorithm: ds.algorithm, digestType: ds.digestType, digest: String(ds.digest || '').toLowerCase(),
    supported: CHECKED_DIGESTS.includes(ds.digestType) && CHECKED_ALGORITHMS.includes(ds.algorithm), matches: null
  };
}

function keyInfo(rr) {
  const d = rr.data;
  return {
    keyTag: d.keyTag ?? computeKeyTag(rr.rdata), flags: d.flags, algorithm: d.algorithm,
    role: (d.flags & 1) === 1 ? 'ksk' : 'zsk', revoked: !!d.revoked, bits: keyBits(d.algorithm, keyOctets(rr)),
    matchesDs: false, signsKeys: false
  };
}

/**
 * Validate the chain of trust of `name` / `type` from the root trust anchors.
 * @param {string} name
 * @param {string} [type='A']
 * @param {object} opts
 * @param {{ query: Function }} opts.dns lib/doh.js DohClient (or a fake with the same `query`)
 * @param {AbortSignal} [opts.signal]
 * @param {number|(() => number)} [opts.now=Date.now] the time signatures are checked against
 * @param {ReadonlyArray<object>} [opts.anchors] root trust anchors (default {@link ROOT_ANCHORS})
 * @param {string} [opts.resolver] ask only this resolver
 * @param {boolean} [opts.noCache=false]
 * @param {number} [opts.timeoutMs]
 * @param {SubtleCrypto} [opts.subtle] default `globalThis.crypto.subtle`
 * @param {(p: { zone: string, done: number }) => void} [opts.onProgress] after each zone
 * @returns {Promise<ChainResult>} rejects only with an AbortError
 */
export async function validateChain(name, type = 'A', {
  dns, signal, now = Date.now, anchors = ROOT_ANCHORS, resolver, noCache = false, timeoutMs,
  subtle = globalThis.crypto && globalThis.crypto.subtle, onProgress
} = {}) {
  const env = {
    now: typeof now === 'function' ? now() : Number(now),
    subtle,
    asked: new Map(),
    zones: new Map(),
    queries: 0,
    ask(qname, qtype) {
      const key = `${qname}|${qtype}`;
      if (!this.asked.has(key)) {
        this.queries += 1;
        this.asked.set(key, dns.query(qname, qtype, { dnssec: true, cd: true, signal, resolver: resolver || undefined, noCache, timeoutMs }));
      }
      return this.asked.get(key);
    },
    signal,
    anchors,
    onProgress
  };
  const result = await walk(normName(name), String(type).toUpperCase(), env, 0, []);
  result.queries = env.queries;
  return result;
}

function throwIfAborted(signal) {
  if (signal && signal.aborted) {
    const err = new Error('The operation was aborted');
    err.name = 'AbortError';
    throw err;
  }
}

async function walk(target, type, env, depth, seen) {
  const zones = [];
  const out = { name: target, type, status: 'indeterminate', reason: null, breakAt: null, zones, answer: null, queries: 0, at: env.now };
  const stop = (step) => {
    out.status = step.status;
    out.reason = step.reason;
    out.breakAt = step.zone;
    return out;
  };
  let zone = await rootStep(env);
  zones.push(zone);
  report(env, zone, zones.length);
  if (zone.status !== 'secure') return stop(zone);
  let insecure = null; // the step that made the chain insecure
  for (const n of namesBelowRoot(target)) {
    throwIfAborted(env.signal);
    const res = await env.ask(n, 'DS');
    if (!answered(res)) {
      const step = emptyStep(n, zone.zone, 'indeterminate', res && res.ok ? 'rcode' : 'query-failed');
      step.failure = failureOf(res, n, 'DS');
      zones.push(step);
      return stop(step);
    }
    if (res.rcode === 'NXDOMAIN') break; // nothing below exists: the answer's proof says so
    const dsRRs = res.answers.filter((rr) => rr.type === 'DS' && rr.name === n && !rr.error && rr.data);
    if (dsRRs.length) {
      const step = await childStep(n, zone, dsRRs, sigsFor(res.answers, n, 'DS'), env);
      zones.push(step);
      report(env, step, zones.length);
      if (step.status !== 'secure') {
        if (step.status !== 'insecure') return stop(step);
        insecure = step;
        stop(step);
        break;
      }
      zone = step;
      continue;
    }
    if (res.answers.some((rr) => rr.name === n && rr.type === 'CNAME')) continue; // an alias is no zone apex
    // No DS: is n the apex of a zone of its own (an unsigned delegation)?
    const denial = await readDenial(res, n, 'DS', zone.zone, zone.trusted, env);
    let cut = denial.delegation;
    if (cut === null) {
      const soa = await env.ask(n, 'SOA');
      if (!answered(soa)) {
        const step = emptyStep(n, zone.zone, 'indeterminate', soa && soa.ok ? 'rcode' : 'query-failed');
        step.failure = failureOf(soa, n, 'SOA');
        zones.push(step);
        return stop(step);
      }
      cut = soa.answers.some((rr) => rr.type === 'SOA' && rr.name === n);
    }
    if (!cut) continue;
    const step = emptyStep(n, zone.zone, 'insecure', 'no-ds');
    step.denial = denial;
    if (denial.kind && denial.delegation && !denial.signed) {
      step.status = 'bogus';
      step.reason = 'denial-invalid';
    } else if (denial.hasDs) {
      step.status = 'bogus';
      step.reason = 'denial-invalid';
    } else if (!(denial.signed && (denial.delegation || denial.optOut))) {
      step.reason = denial.tooManyIterations ? 'nsec3-iterations' : 'no-ds-unproven';
    }
    zones.push(step);
    report(env, step, zones.length);
    if (step.status === 'bogus') return stop(step);
    insecure = step;
    stop(step);
    break;
  }
  throwIfAborted(env.signal);
  out.answer = await answerStep(target, type, zone, insecure, zones, env, depth, seen);
  // An unsigned zone makes the answer insecure whatever it holds: the chain's verdict stands.
  if (!insecure) {
    out.status = out.answer.status;
    out.reason = out.answer.reason;
    out.breakAt = out.answer.status === 'secure' ? null : 'answer';
  }
  return out;
}

function report(env, step, done) {
  if (typeof env.onProgress === 'function') {
    try {
      env.onProgress({ zone: step.zone, done });
    } catch {
      // a progress listener cannot break the run
    }
  }
}

function emptyStep(zone, parent, status, reason) {
  return { zone, parent, status, reason, dsSource: 'parent', ds: [], dsSigs: [], keys: [], keySigs: [], denial: null, failure: null, trusted: [] };
}

async function rootStep(env) {
  const step = emptyStep('.', null, 'indeterminate', null);
  step.dsSource = 'anchor';
  step.ds = env.anchors.map(dsInfo);
  return keyStep(step, env);
}

async function childStep(n, parent, dsRRs, dsSigRRs, env) {
  const step = emptyStep(n, parent.zone, 'indeterminate', null);
  step.ds = dsRRs.map((rr) => dsInfo(rr.data));
  const v = await verifyRRset(dsRRs, dsSigRRs, parent.trusted, parent.zone, env);
  step.dsSigs = v.checks;
  if (v.result !== 'valid') {
    Object.assign(step, sigOutcome(v.result));
    return step;
  }
  return keyStep(step, env);
}

/** Match the DS set (or the anchors) to the zone's DNSKEY set and check that set's signatures. */
async function keyStep(step, env) {
  const zone = step.zone;
  if (env.zones.has(zone)) return env.zones.get(zone);
  const res = await env.ask(zone, 'DNSKEY');
  if (!answered(res)) {
    step.status = 'indeterminate';
    step.reason = res && res.ok ? 'rcode' : 'query-failed';
    step.failure = failureOf(res, zone, 'DNSKEY');
    return step;
  }
  const keyRRs = res.answers.filter((rr) => rr.type === 'DNSKEY' && rr.name === zone && !rr.error && rr.data);
  step.keys = keyRRs.map(keyInfo);
  const supported = step.ds.filter((d) => d.supported);
  if (!keyRRs.length) {
    step.status = 'bogus';
    step.reason = 'no-dnskey';
    return step;
  }
  if (!supported.length) {
    step.status = 'insecure';
    step.reason = step.ds.some((d) => CHECKED_DIGESTS.includes(d.digestType)) ? 'unsupported-algorithm' : 'unsupported-digest';
    return step;
  }
  const matched = [];
  for (const ds of supported) {
    for (let i = 0; i < keyRRs.length; i++) {
      const k = keyRRs[i].data;
      if (k.keyTag !== ds.keyTag || k.algorithm !== ds.algorithm || !k.zoneKey) continue;
      const digest = await dsDigest(zone, keyRRs[i].rdata, ds.digestType, env.subtle);
      if (digest && digest === ds.digest) {
        ds.matches = k.keyTag;
        step.keys[i].matchesDs = true;
        if (!matched.includes(keyRRs[i])) matched.push(keyRRs[i]);
      }
    }
  }
  if (!matched.length) {
    step.status = 'bogus';
    step.reason = zone === '.' && step.dsSource === 'anchor' ? 'anchor-mismatch' : 'ds-no-match';
    // Shown, not trusted: which of its own keys the zone signs its key set with (after a rollover,
    // the key the DS should name).
    const own = await verifyRRset(keyRRs, sigsFor(res.answers, zone, 'DNSKEY'), keyRRs, zone, env);
    step.keySigs = own.checks;
    for (const info of step.keys) info.signsKeys = own.validKeys.includes(info.keyTag);
    return step;
  }
  const v = await verifyRRset(keyRRs, sigsFor(res.answers, zone, 'DNSKEY'), matched, zone, env);
  step.keySigs = v.checks;
  for (const info of step.keys) info.signsKeys = v.validKeys.includes(info.keyTag);
  if (v.result === 'valid') {
    step.status = 'secure';
    step.reason = null;
    step.trusted = keyRRs;
    env.zones.set(zone, step);
    return step;
  }
  Object.assign(step, sigOutcome(v.result));
  // Signatures by the zone's other keys only: none of the keys the DS vouches for signs the set.
  if (v.result === 'no-key' || v.result === 'no-rrsig') step.reason = 'dnskey-unsigned';
  return step;
}

async function answerStep(target, type, zone, insecure, zones, env, depth, seen) {
  const step = {
    name: target, type, zone: zone.zone, status: 'indeterminate', reason: null, rcode: null, records: [], sigs: [],
    denial: null, wildcard: false, alias: null, failure: null
  };
  // A DS set lives in the parent zone: the walk already checked it with the parent's keys.
  const cutStep = zones.find((z) => z.zone === target && z.zone !== '.' && z.ds.length);
  if (type === 'DS' && cutStep) {
    step.zone = cutStep.parent;
    step.records = [];
    step.sigs = cutStep.dsSigs;
    step.rcode = 'NOERROR';
    const v = cutStep.dsSigs.some((c) => c.result === 'valid');
    step.status = v ? 'secure' : cutStep.status;
    step.reason = v ? null : cutStep.reason;
    const res = await env.ask(target, 'DS');
    if (res && res.ok) step.records = res.answers.filter((rr) => rr.type === 'DS' && rr.name === target);
    return step;
  }
  const res = await env.ask(target, type);
  if (!answered(res)) {
    step.reason = res && res.ok ? 'rcode' : 'query-failed';
    step.rcode = res ? res.rcode ?? null : null;
    step.failure = failureOf(res, target, type);
    return step;
  }
  step.rcode = res.rcode;
  step.records = res.answers.filter((rr) => rr.name === target && rr.type === type && !rr.error);
  const cname = type !== 'CNAME' ? res.answers.filter((rr) => rr.name === target && rr.type === 'CNAME' && !rr.error) : [];
  if (insecure) {
    step.zone = insecure.zone;
    step.status = 'insecure';
    step.reason = insecure.reason;
    if (!step.records.length && cname.length) step.records = cname;
    return step;
  }
  if (step.records.length || cname.length) {
    const rrset = step.records.length ? step.records : cname;
    const sigs = sigsFor(res.answers, target, rrset[0].type);
    const v = await verifyRRset(rrset, sigs, zone.trusted, zone.zone, env);
    step.sigs = v.checks;
    Object.assign(step, sigOutcome(v.result));
    step.wildcard = v.checks.some((c) => c.result === 'valid' && c.labels < sigLabelCount(target));
    if (step.status === 'secure' && step.wildcard) {
      // RFC 4035 §5.3.4: a wildcard answer is secure only with proof that the name itself does not exist.
      const labels = v.checks.find((c) => c.result === 'valid').labels;
      const d = await readDenial(res, target, type, zone.zone, zone.trusted, env, {
        closestEncloser: labels === 0 ? '.' : joinLabels(splitLabels(target).slice(-labels))
      });
      step.denial = d;
      if (!d.signed) {
        step.status = 'bogus';
        step.reason = d.kind ? 'denial-invalid' : 'denial-missing';
      }
    }
    if (!step.records.length && cname.length) {
      step.records = cname;
      const targetName = normName(cname[0].data);
      if (step.status === 'secure' || step.status === 'insecure') {
        if (seen.includes(targetName) || depth >= MAX_ALIASES) {
          step.status = 'bogus';
          step.reason = 'alias-loop';
        } else {
          const next = await walk(targetName, type, env, depth + 1, [...seen, target]);
          step.alias = { target: targetName, result: next };
          if (RANK[next.status] > RANK[step.status]) {
            step.status = next.status;
            step.reason = 'chain-broken';
          }
        }
      }
    }
    return step;
  }
  // No data, or no name: the zone must prove it.
  const d = await readDenial(res, target, type, zone.zone, zone.trusted, env);
  step.denial = d;
  const proven = res.rcode === 'NXDOMAIN' ? d.nxdomain : d.nodata;
  if (d.tooManyIterations) {
    step.status = 'insecure';
    step.reason = 'nsec3-iterations';
  } else if (!d.kind) {
    step.status = 'bogus';
    step.reason = 'denial-missing';
  } else if (!d.signed) {
    step.status = 'bogus';
    step.reason = 'denial-invalid';
  } else if (d.optOut) {
    // An opt-out NSEC3 covers the name: an unsigned delegation could be there (RFC 5155 §12.2.1).
    step.status = 'insecure';
    step.reason = 'opt-out';
  } else if (proven) {
    step.status = 'secure';
    step.reason = null;
  } else {
    step.status = 'bogus';
    step.reason = 'denial-missing';
  }
  return step;
}

/**
 * The worse of two statuses (bogus > indeterminate > insecure > secure).
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
export function worstStatus(a, b) {
  return RANK[a] >= RANK[b] ? a : b;
}
