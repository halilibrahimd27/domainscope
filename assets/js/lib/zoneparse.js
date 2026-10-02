/**
 * zoneparse.js — parse DNS zone exports into records shaped like live DNS answers.
 *
 * Supported inputs (auto-detected):
 * - BIND / RFC 1035 master files, including the Cloudflare export (`;; Domain:` header,
 *   undotted SOA owner, `cf_tags=`), cPanel, DirectAdmin, GoDaddy (`_svc._tcp.@`), cli53
 *   (`AWS ALIAS`, `; AWS routing=`) and `dig AXFR` output;
 * - Cloudflare API JSON (`GET /zones/{id}/dns_records`, one or several pasted pages);
 * - Route 53 JSON (`aws route53 list-resource-record-sets`, octal escapes, aliases, routing sets);
 * - an octoDNS YAML subset (`? ''` apex, sequences at the parent's indent, `\;` escapes);
 * - Plesk `plesk bin dns --info` output (format unverified).
 *
 * Pure, synchronous, DOM-free and dependency-free: runs unchanged in browsers and Node 22.
 * `parseZone()` never throws. Every problem is an issue whose `code` comes from the closed
 * set `ISSUE_CODES`, with `params` for i18n; `detail` is English log text only.
 *
 * Record `data` has exactly the dnswire decoder's `RR.data` shape (names lowercase without a
 * trailing dot, root '.', TXT strings decoded with the same lenient UTF-8→Latin-1 decoder) and
 * `text` is what dnswire prints for the same RDATA, so `rdataKey()` compares a zone file with
 * live answers directly.
 *
 * @typedef {object} ZoneIssue
 * @property {string} code one of ISSUE_CODES
 * @property {'error'|'warn'|'info'} severity
 * @property {number} line 1-based source line (JSON: item index + 1; YAML: key line); 0 = whole file
 * @property {number} [source] index into Zone.sources (always set on warnings)
 * @property {string} [name] served owner name, when the issue is about one record
 * @property {string} [type] RR type, when the issue is about one record
 * @property {object} params i18n parameters (never pre-built English)
 * @property {string} detail English log text; the UI never parses it
 *
 * @typedef {object} ZoneRecord
 * @property {number} id 0-based file-order index
 * @property {string} name SERVED owner: lowercase presentation (dnswire escaping), '*' kept, no trailing dot
 * @property {string} [intendedName] likely intended owner (missing trailing dot)
 * @property {string} type 'A' … 'TYPE65534' (cli53 / Route 53 aliases: the aliased type)
 * @property {number|null} ttl seconds; null for aliases, Plesk and files without any TTL
 * @property {true} [ttlAuto] Cloudflare "Auto" (TTL 1) or octoDNS auto-ttl ⇒ ttl 300
 * @property {any} data dnswire RR.data shape (root name '.'); null when invalid / unsupported / alias
 * @property {string} text RDATA exactly as dnswire prints it ('' for aliases)
 * @property {string[]} targets served names inside RDATA, no trailing dot ('' = root); SOA: [mname, rname]
 * @property {string[]} [intendedTargets] parallel to targets when a missing trailing dot is suspected
 * @property {true|false|null} proxied Cloudflare proxy flag (null: no proxy notion)
 * @property {boolean} [proxiable] Cloudflare API only
 * @property {true} [flattenCname]
 * @property {{ target: string, zoneId: string|null, evaluateTargetHealth: boolean, provider: string }} [alias]
 * @property {{ policy: string, id: string|null, weight?: number, geo?: object, region?: string, failover?: string, healthCheck?: string }} [routing]
 * @property {'delegation'} [occludedBy] Cloudflare API meta.shadowed_by only (zonelint computes the rest)
 * @property {true} [invalid] BAD_RDATA (text = the raw tokens)
 * @property {true} [unsupported] RDATA_UNPARSED (text = the raw tokens)
 * @property {true} [generated] from $GENERATE
 * @property {number} [duplicateOf] id of the first identical RR (name, type, rdataKey, routing.id)
 * @property {string} [comment] free comment text (cf_tags removed), unsafe code points as \DDD
 * @property {Object<string,string>} [tags] Cloudflare tags (null prototype; reserved cf-* tags become flags)
 * @property {number} line
 * @property {number} source
 *
 * @typedef {object} Zone
 * @property {'bind'|'cloudflare-api'|'route53'|'octodns'|'plesk-info'|null} format
 * @property {'generic'|'cloudflare'|'cli53'|'godaddy'|'cpanel'|'directadmin'|null} dialect
 * @property {string[]} markers what the detector recognised (technical tokens, not translated)
 * @property {string|null} origin
 * @property {'user'|'$ORIGIN'|'header'|'soa'|'filename'|'records'|null} originSource
 * @property {'high'|'low'} originConfidence 'low' ⇒ ask the user to confirm
 * @property {ZoneRecord[]} records file order, duplicates kept
 * @property {ZoneIssue[]} warnings sorted by line, capped at maxIssues (+ WARNINGS_TRUNCATED)
 * @property {ZoneIssue|null} fatal non-null ⇒ records and warnings are empty
 * @property {boolean} partial PARTIAL_EXPORT or RECORDS_TRUNCATED raised
 * @property {Array<{ name: string, size: number, format: string|null, dialect: string|null }>} sources
 * @property {{ bytes: number, lines: number, entries: number, records: number, skipped: number, generated: number,
 *   proxied: number, dnsOnly: number, byType: Object<string, number>, elapsedMs: number }} stats
 * @property {number|null} defaultTtl the $TTL in force at the end of a BIND file (for $INCLUDE fragments)
 * @property {{ upserts: number, deletes: Array<{ name: string, type: string, id: string|null }> }|null} changeBatch
 *   a Route 53 change batch (CHANGE_BATCH): not a zone but changes to one. `records` are what its
 *   CREATE / UPSERT changes set (`upserts`: the sets read), `deletes` what its DELETEs take away
 */

import {
  TYPES, typeToName, typeToNumber, encodeMessage, encodeName, decodeMessage, base64Decode, base64Encode, hexDecode, DNSSEC_ALGORITHMS
} from './dnswire.js';
import { normalizeIP } from './netinfo.js';
import { normalizeHostname, registrableDomain, isPublicSuffix, isSubdomainOf, sortHostnames } from './domain.js';

/* ------------------------------------------------------------------------ */
/* Public constants                                                         */
/* ------------------------------------------------------------------------ */

/** Hard limits. Tests may pass a partial override through `parseZone(…, { limits })`. */
export const ZONE_LIMITS = Object.freeze({
  maxBytes: 5 * 1024 * 1024, // per file (FileDrop maxBytes); byte input over this → TOO_LARGE
  maxChars: 5_000_000, // decoded text / paste, checked before any scanning → TOO_LARGE
  maxRecords: 20_000, // kept records (= scanner maxHosts) → RECORDS_TRUNCATED
  maxEntries: 200_000, // logical entries tokenized before giving up → RECORDS_TRUNCATED
  maxLineChars: 65_535, // one physical line → LINE_TOO_LONG, the line is skipped
  maxParenLines: 1_000, // one parenthesised entry → UNBALANCED_PAREN
  maxTokensPerEntry: 4_096,
  maxGenerate: 4_096, // one $GENERATE range
  maxGenerateTotal: 20_000,
  maxJsonDocs: 50, // pasted JSON pages in one text
  maxYamlDepth: 32,
  maxIssues: 500, // then one WARNINGS_TRUNCATED
  maxCnameChain: 16, // (used by zonelint / zoneorigins)
  maxCommentChars: 500
});

/**
 * Input formats. `desec-api` / `digitalocean-api`: the record listings of those providers' APIs, as
 * lib/zonefetch.js reads them with the user's token (or as `curl` saved them).
 */
export const ZONE_FORMATS = Object.freeze(['bind', 'cloudflare-api', 'route53', 'octodns', 'plesk-info', 'desec-api', 'digitalocean-api']);
/** The JSON formats (parsed as JSON documents, one or several pages). */
const JSON_FORMATS = new Set(['cloudflare-api', 'route53', 'desec-api', 'digitalocean-api']);

/** BIND dialects. */
export const ZONE_DIALECTS = Object.freeze(['generic', 'cloudflare', 'cli53', 'godaddy', 'cpanel', 'directadmin']);

/** Where `Zone.origin` came from. */
export const ORIGIN_SOURCES = Object.freeze(['user', '$ORIGIN', 'header', 'soa', 'filename', 'records']);

/** `params.hint` values of the fatal NOT_A_ZONE issue. */
export const NOT_A_ZONE_HINTS = Object.freeze(['pem', 'html', 'gzip', 'csv', 'dns-csv', 'inventory', 'names', 'aws-output-json', 'unknown']);

const FATAL_CODES = ['EMPTY', 'TOO_LARGE', 'NOT_TEXT', 'NOT_A_ZONE', 'INVALID_JSON', 'UNSUPPORTED_JSON',
  'YAML_UNSUPPORTED', 'ORIGIN_REQUIRED', 'ORIGIN_MISMATCH', 'API_ERROR'];
const ERROR_CODES = ['INCLUDE_REJECTED', 'RELATIVE_WITHOUT_ORIGIN', 'UNTERMINATED_QUOTE', 'UNBALANCED_PAREN',
  'LINE_TOO_LONG', 'NO_OWNER', 'BAD_NAME', 'BAD_RDATA', 'BAD_RECORD', 'UNPARSED_LINE', 'PARTIAL_EXPORT',
  'OWNER_MISSING_TRAILING_DOT', 'RECORDS_TRUNCATED', 'GENERATE_TOO_LARGE'];
const WARN_CODES = ['GENERATE_UNSUPPORTED', 'BAD_TTL', 'TARGET_MISSING_TRAILING_DOT', 'AT_INSIDE_NAME',
  'DUPLICATE_KEY', 'OCTODNS_UNESCAPED_SEMICOLON', 'OUT_OF_ZONE', 'ORIGIN_OVERRIDDEN'];
const INFO_CODES = ['ORIGIN_INFERRED', 'ORIGIN_CORRECTED', 'CF_SOA_OWNER_UNDOTTED', 'NON_IN_CLASS',
  'GENERATE_EXPANDED', 'UNKNOWN_DIRECTIVE', 'FORMAT_UNVERIFIED', 'OCTODNS_IGNORED', 'RDATA_UNPARSED',
  'TTL_DEFAULTED', 'NON_ASCII_LABEL', 'ENCODING_REPLACED', 'JSON_PAGES_MERGED', 'PROXY_FLAG_IGNORED',
  'WARNINGS_TRUNCATED', 'INCLUDE_MERGED', 'NO_PROXY_FLAGS', 'CHANGE_BATCH'];

/**
 * The closed set of issue codes: `CODE → { severity: 'error'|'warn'|'info', fatal: boolean }`.
 * A fatal code only ever appears in `Zone.fatal`; the others in `Zone.warnings`.
 */
export const ISSUE_CODES = Object.freeze(Object.fromEntries([
  ...FATAL_CODES.map((c) => [c, Object.freeze({ severity: 'error', fatal: true })]),
  ...ERROR_CODES.map((c) => [c, Object.freeze({ severity: 'error', fatal: false })]),
  ...WARN_CODES.map((c) => [c, Object.freeze({ severity: 'warn', fatal: false })]),
  ...INFO_CODES.map((c) => [c, Object.freeze({ severity: 'info', fatal: false })])
]));

/**
 * Generic TLDs (plus a few popular two-letter ones) that make an undotted relative RDATA name
 * look absolute (the TARGET_MISSING_TRAILING_DOT heuristic). Any two-letter label counts as a
 * ccTLD too; `domain.isPublicSuffix()` alone is useless here (true for every single label).
 */
export const GTLDS = Object.freeze(['com', 'net', 'org', 'info', 'biz', 'io', 'co', 'dev', 'app', 'cloud', 'xyz',
  'online', 'site', 'tech', 'me', 'tv', 'ai', 'edu', 'gov', 'mil', 'int', 'name', 'pro', 'mobi', 'asia', 'shop',
  'store', 'blog', 'news', 'live', 'page', 'top', 'club', 'vip', 'link', 'space', 'website', 'email', 'host',
  'digital', 'agency', 'network', 'systems', 'solutions', 'company', 'services', 'group', 'world', 'tools', 'run',
  'media', 'studio', 'design', 'global', 'software', 'art', 'one', 'cc', 'ws', 'sh', 'gg']);
const GTLD_SET = new Set(GTLDS);

/**
 * AWS alias targets → `alias.provider` (Route 53 JSON and cli53). Matched against the target
 * without a leading `dualstack.`; a target inside the zone itself is `same-zone`, anything else
 * `other`. Each entry is `[provider, RegExp]`.
 */
export const AWS_ALIAS_PROVIDERS = Object.freeze([
  Object.freeze(['cloudfront', /(^|\.)cloudfront\.net$/]),
  Object.freeze(['elb', /(^|\.)elb\.amazonaws\.com(\.cn)?$/]),
  Object.freeze(['s3-website', /(^|\.)s3-website[.-][a-z0-9-]+\.amazonaws\.com(\.cn)?$/]),
  Object.freeze(['api-gateway', /\.execute-api\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$/]),
  Object.freeze(['elastic-beanstalk', /(^|\.)elasticbeanstalk\.com$/]),
  Object.freeze(['global-accelerator', /(^|\.)awsglobalaccelerator\.com$/]),
  Object.freeze(['vpc-endpoint', /(^|\.)vpce\.amazonaws\.com$/])
]);

/**
 * Provider of an AWS alias target.
 * @param {string} target alias DNS name (any case, trailing dot optional)
 * @param {{ origin?: string|null, self?: boolean }} [opts] `self`: cli53 `$self` zone id
 * @returns {'cloudfront'|'elb'|'s3-website'|'api-gateway'|'elastic-beanstalk'|'global-accelerator'|'vpc-endpoint'|'same-zone'|'other'}
 */
export function awsAliasProvider(target, { origin = null, self = false } = {}) {
  let t = String(target ?? '').trim().toLowerCase();
  if (t.endsWith('.')) t = t.slice(0, -1);
  const bare = t.startsWith('dualstack.') ? t.slice('dualstack.'.length) : t;
  for (const [provider, re] of AWS_ALIAS_PROVIDERS) if (re.test(bare)) return provider;
  if (self) return 'same-zone';
  if (origin && (t === origin || t.endsWith(`.${origin}`))) return 'same-zone';
  return 'other';
}

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */
/* ------------------------------------------------------------------------ */

const MAX_TTL = 2147483647;
const MAX_U32 = 4294967295;
const HAS_OWN = Object.prototype.hasOwnProperty;
/** Own property of an untrusted object (never an inherited one such as `constructor`). */
const own = (o, k) => (o !== null && typeof o === 'object' && HAS_OWN.call(o, k) ? o[k] : undefined);
const isPlainMap = (o) => o !== null && typeof o === 'object' && !Array.isArray(o);
const nowMs = () => (globalThis.performance && typeof globalThis.performance.now === 'function'
  ? globalThis.performance.now() : Date.now());
const fqdn = (name) => (name === '.' ? '.' : `${name}.`);
const rootToEmpty = (name) => (name === '.' ? '' : name);

const utf8Strict = new TextDecoder('utf-8', { fatal: true });
const utf8Encoder = new TextEncoder();

/**
 * Decode UTF-8; on invalid sequences fall back to Latin-1 (one char per byte, lossless).
 * Same algorithm as dnswire's decoder (pinned by a unit test).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function decodeUtf8Lenient(bytes) {
  try {
    return utf8Strict.decode(bytes);
  } catch {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }
}

function ddd(b) {
  return '\\' + String(b).padStart(3, '0');
}

/** C0/C1 controls, DEL, zero-width and bidi formatting characters (never shown raw). */
function isUnsafeCodePoint(cp) {
  return cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) || cp === 0xfeff ||
    (cp >= 0xfff9 && cp <= 0xfffb);
}

/**
 * Presentation form of a <character-string> exactly as dnswire prints it: quoted, `"` and `\`
 * escaped, unsafe characters as \DDD (per UTF-8 byte); invalid UTF-8 bytes as \DDD.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function presentCharString(bytes) {
  let decoded = null;
  try {
    decoded = utf8Strict.decode(bytes);
  } catch {
    decoded = null;
  }
  let out = '"';
  if (decoded !== null) {
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

/**
 * Presentation text of one label exactly as dnswire prints it: ASCII lowercase, special
 * characters (`. \ " ( ) ; @ $`) escaped with a backslash, others outside 0x21–0x7e as \DDD.
 * @param {Uint8Array|number[]} label
 * @returns {string}
 */
export function presentLabel(label) {
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

/** Untrusted text for params / comments: unsafe code points → \DDD, cut to `max` characters. */
function safeText(value, max = 200) {
  const s = String(value ?? '');
  let out = '';
  for (const ch of s) {
    if (out.length >= max) return `${out}…`;
    const cp = ch.codePointAt(0);
    if (isUnsafeCodePoint(cp)) for (const b of utf8Encoder.encode(ch)) out += ddd(b);
    else out += ch;
  }
  return out;
}

/** UTF-8 byte length without allocating. */
function utf8Length(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) { n += 4; i++; } else n += 3;
    } else n += 3;
  }
  return n;
}

/** Push the UTF-8 bytes of code unit(s) starting at `s[i]`; returns how many code units were used. */
function pushUtf8(out, s, i) {
  const c = s.charCodeAt(i);
  if (c < 0x80) { out.push(c); return 1; }
  if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 63)); return 1; }
  if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
    const d = s.charCodeAt(i + 1);
    if (d >= 0xdc00 && d <= 0xdfff) {
      const cp = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
      return 2;
    }
  }
  const cp = c >= 0xd800 && c <= 0xdfff ? 0xfffd : c;
  out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
  return 1;
}

/**
 * Decode RFC 1035 escapes of one presentation token into bytes: `\DDD` (decimal, or octal for
 * Route 53 with `base: 8`) and `\X` (literal X); other characters as UTF-8.
 * `ok` is false for `\DDD` > 255, non-octal digits in base 8 or a dangling backslash.
 * @param {string} raw
 * @param {{ base?: 8|10 }} [opts]
 * @returns {{ bytes: Uint8Array, ok: boolean }}
 */
export function decodeEscapes(raw, { base = 10 } = {}) {
  const s = String(raw ?? '');
  const out = [];
  let ok = true;
  for (let i = 0; i < s.length;) {
    const c = s.charCodeAt(i);
    if (c !== 0x5c) {
      i += pushUtf8(out, s, i);
      continue;
    }
    const d1 = s.charCodeAt(i + 1);
    const d2 = s.charCodeAt(i + 2);
    const d3 = s.charCodeAt(i + 3);
    if (isDigit(d1) && isDigit(d2) && isDigit(d3)) {
      if (base === 8 && (d1 > 0x37 || d2 > 0x37 || d3 > 0x37)) ok = false;
      else {
        const v = base === 8 ? (d1 - 48) * 64 + (d2 - 48) * 8 + (d3 - 48) : (d1 - 48) * 100 + (d2 - 48) * 10 + (d3 - 48);
        if (v > 255) ok = false;
        else out.push(v);
      }
      i += 4;
      continue;
    }
    if (i + 1 >= s.length) {
      ok = false;
      out.push(0x5c);
      i += 1;
      continue;
    }
    i += 1 + pushUtf8(out, s, i + 1);
  }
  return { bytes: Uint8Array.from(out), ok };
}

function isDigit(c) {
  return c >= 0x30 && c <= 0x39;
}

/** Split bytes into ≤255-byte character-strings (at least one, possibly empty). */
function split255(bytes) {
  if (bytes.length <= 255) return [bytes];
  const out = [];
  for (let i = 0; i < bytes.length; i += 255) out.push(bytes.subarray(i, i + 255));
  return out;
}

/** SOA RNAME → mailbox (as dnswire's decoder computes `email`). */
function soaEmail(rname) {
  if (rname === '.') return null;
  const m = /^((?:[^.\\]|\\.)+)\.(.+)$/.exec(rname);
  if (!m) return null;
  return `${m[1].replace(/\\(\d{3}|.)/g, (_, e) => (e.length === 3 ? String.fromCharCode(Number(e)) : e))}@${m[2]}`;
}

/* ------------------------------------------------------------------------ */
/* Types and classes                                                        */
/* ------------------------------------------------------------------------ */

const NOT_ZONE_TYPES = new Set(['OPT', 'TKEY', 'TSIG', 'IXFR', 'AXFR', 'ANY', 'NXNAME']);
const PSEUDO_TYPES = ['ALIAS', 'ANAME', 'URLFWD'];
const KNOWN_TYPES = new Set([...Object.keys(TYPES).filter((t) => !NOT_ZONE_TYPES.has(t)), ...PSEUDO_TYPES]);
const PROXIABLE = new Set(['A', 'AAAA', 'CNAME']);
const NAME_TYPES = new Set(['NS', 'CNAME', 'PTR', 'DNAME']);
const ALG_BY_NAME = Object.freeze(Object.fromEntries(Object.entries(DNSSEC_ALGORITHMS).map(([k, v]) => [v, Number(k)])));

/** Type mnemonic ('a', 'TYPE65534', 'TYPE1' → 'A') or null. */
function typeOf(tok) {
  const u = tok.toUpperCase();
  if (KNOWN_TYPES.has(u)) return u;
  const m = /^TYPE(\d{1,5})$/.exec(u);
  if (!m) return null;
  const n = Number(m[1]);
  if (n > 0xffff) return null;
  const name = typeToName(n);
  return NOT_ZONE_TYPES.has(name) ? null : name;
}

/** Class mnemonic ('IN', 'CH', …, 'AWS' for cli53) or null. */
function classOf(tok) {
  const u = tok.toUpperCase();
  if (u === 'IN') return 'IN';
  if (u === 'CH' || u === 'CHAOS') return 'CH';
  if (u === 'HS' || u === 'HESIOD') return 'HS';
  if (u === 'CS') return 'CS';
  if (u === 'AWS') return 'AWS';
  const m = /^CLASS(\d{1,5})$/.exec(u);
  if (!m) return null;
  const n = Number(m[1]);
  if (n > 0xffff) return null;
  return n === 1 ? 'IN' : `CLASS${n}`;
}

/**
 * BIND TTL (`3600`, `1h30m`, `2W`, case-insensitive units) → seconds, or null when the token is
 * not a TTL. The value may exceed 2^31−1 (the caller reports BAD_TTL). Linear, no regex.
 */
function parseTtlValue(tok) {
  if (typeof tok !== 'string' || tok === '') return null;
  let total = 0;
  let num = -1;
  let sawUnit = false;
  for (let i = 0; i < tok.length; i++) {
    const c = tok.charCodeAt(i);
    if (c >= 0x30 && c <= 0x39) {
      num = (num < 0 ? 0 : num) * 10 + (c - 48);
      if (num > 1e15) num = 1e15;
      continue;
    }
    let mult;
    switch (c | 0x20) {
      case 0x73: mult = 1; break; // s
      case 0x6d: mult = 60; break; // m
      case 0x68: mult = 3600; break; // h
      case 0x64: mult = 86400; break; // d
      case 0x77: mult = 604800; break; // w
      default: return null;
    }
    if (num < 0) return null;
    total = Math.min(total + num * mult, 1e18);
    num = -1;
    sawUnit = true;
  }
  if (num >= 0) {
    if (sawUnit) return null;
    return num;
  }
  return sawUnit ? total : null;
}

/* ------------------------------------------------------------------------ */
/* Names                                                                    */
/* ------------------------------------------------------------------------ */

const FAST_NAME = /^[A-Za-z0-9_*-]+(?:\.[A-Za-z0-9_*-]+)*$/;
const originWireCache = new Map();

function isEscapedAt(s, idx) {
  let n = 0;
  for (let k = idx - 1; k >= 0 && s.charCodeAt(k) === 0x5c; k--) n++;
  return n % 2 === 1;
}

/** Wire length of a presentation name (no trailing dot; '.' = root). */
function wireLengthOf(name) {
  if (name === '.' || name === '') return 1;
  const cached = originWireCache.get(name);
  if (cached !== undefined) return cached;
  let n = 2; // first length byte + root
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c === 0x5c) {
      if (isDigit(name.charCodeAt(i + 1)) && isDigit(name.charCodeAt(i + 2)) && isDigit(name.charCodeAt(i + 3))) i += 3;
      else i += 1;
      n += 1;
    } else if (c === 0x2e) n += 1; // the next label's length byte
    else n += 1;
  }
  if (originWireCache.size > 256) originWireCache.clear();
  originWireCache.set(name, n);
  return n;
}

/** Raw non-ASCII label → punycode through the WHATWG URL parser, or null. */
function toPunycodeLabel(label) {
  if (/[\s/?#@:%[\]\\<>^|.]/.test(label)) return null;
  try {
    const host = new URL(`http://${label}.invalid`).hostname;
    if (!host.endsWith('.invalid')) return null;
    const out = host.slice(0, -'.invalid'.length);
    return /^[a-z0-9_-]{1,63}$/.test(out) ? out : null;
  } catch {
    return null;
  }
}

/**
 * Parse a presentation domain name.
 * - `@` is the origin; a relative name is completed with `origin`.
 * - `absolute: true` (JSON sources): names without a trailing dot are absolute.
 * - GoDaddy `x.@` → `x.<origin>` (`at: true`).
 * - `\DDD` is decimal (octal with `base: 8`), `\X` a literal X.
 * @returns {{ ok: true, name: string, relative: boolean, rel: string, relLabels: number, at: boolean, idn: boolean }
 *   | { ok: false, reason: string }}
 */
function parseName(raw, { origin = null, base = 10, absolute = false } = {}) {
  if (typeof raw !== 'string' || raw === '') return { ok: false, reason: 'empty' };
  if (raw === '@' && !absolute) {
    if (origin === null) return { ok: false, reason: 'no-origin' };
    return { ok: true, name: origin, relative: true, rel: '', relLabels: 0, at: false, idn: false, apex: true };
  }
  if (raw === '.') return { ok: true, name: '.', relative: false, rel: '', relLabels: 0, at: false, idn: false };
  let s = raw;
  let at = false;
  if (!absolute && s.length > 2 && s.endsWith('.@') && !isEscapedAt(s, s.length - 2)) {
    at = true;
    s = s.slice(0, -2);
  }
  let isAbs = absolute && !at;
  if (s.endsWith('.') && !isEscapedAt(s, s.length - 1)) {
    if (at) return { ok: false, reason: 'empty-label' };
    isAbs = true;
    s = s.slice(0, -1);
    if (s === '') return { ok: false, reason: 'empty-label' };
  }
  let text;
  let labels;
  let wire;
  let idn = false;
  if (FAST_NAME.test(s)) {
    text = s.toLowerCase();
    let start = 0;
    labels = 0;
    for (let i = 0; i <= text.length; i++) {
      if (i === text.length || text.charCodeAt(i) === 0x2e) {
        if (i - start > 63) return { ok: false, reason: 'label-too-long' };
        labels++;
        start = i + 1;
      }
    }
    wire = text.length + 2;
  } else {
    const parts = [];
    let cur = [];
    let curStart = 0;
    let curEscaped = false;
    let curNonAscii = false;
    const finish = (endIdx) => {
      if (!cur.length) return 'empty-label';
      if (curNonAscii && !curEscaped) {
        const puny = toPunycodeLabel(s.slice(curStart, endIdx));
        if (!puny) return 'idn';
        idn = true;
        cur = Array.from(puny, (ch) => ch.charCodeAt(0));
      }
      if (cur.length > 63) return 'label-too-long';
      parts.push(cur);
      return null;
    };
    for (let i = 0; i < s.length;) {
      const c = s.charCodeAt(i);
      if (c === 0x5c) {
        curEscaped = true;
        const d1 = s.charCodeAt(i + 1);
        const d2 = s.charCodeAt(i + 2);
        const d3 = s.charCodeAt(i + 3);
        if (isDigit(d1) && isDigit(d2) && isDigit(d3)) {
          if (base === 8 && (d1 > 0x37 || d2 > 0x37 || d3 > 0x37)) return { ok: false, reason: 'bad-escape' };
          const v = base === 8 ? (d1 - 48) * 64 + (d2 - 48) * 8 + (d3 - 48) : (d1 - 48) * 100 + (d2 - 48) * 10 + (d3 - 48);
          if (v > 255) return { ok: false, reason: 'bad-escape' };
          cur.push(v);
          i += 4;
          continue;
        }
        if (i + 1 >= s.length) return { ok: false, reason: 'bad-escape' };
        i += 1 + pushUtf8(cur, s, i + 1);
        continue;
      }
      if (c === 0x2e) {
        const err = finish(i);
        if (err) return { ok: false, reason: err };
        cur = [];
        curStart = i + 1;
        curEscaped = false;
        curNonAscii = false;
        i++;
        continue;
      }
      if (c === 0x40) return { ok: false, reason: 'at-sign' };
      if (c > 0x7e) curNonAscii = true;
      i += pushUtf8(cur, s, i);
    }
    const err = finish(s.length);
    if (err) return { ok: false, reason: err };
    text = parts.map(presentLabel).join('.');
    labels = parts.length;
    wire = parts.reduce((n, l) => n + l.length + 1, 1);
  }
  let name = text;
  if (!isAbs) {
    if (origin === null) return { ok: false, reason: 'no-origin' };
    if (origin !== '.') {
      name = `${text}.${origin}`;
      wire += wireLengthOf(origin) - 1;
    }
  }
  if (wire > 255) return { ok: false, reason: 'too-long' };
  return { ok: true, name, relative: !isAbs, rel: text, relLabels: labels, at, idn };
}

/** A relative RDATA name that looks like a forgotten FQDN (`blog CNAME example-blog.github.io`). */
function looksLikeFqdn(rel, relLabels) {
  if (relLabels < 2) return false;
  const last = rel.slice(rel.lastIndexOf('.') + 1);
  if (/^[a-z]{2}$/.test(last) || GTLD_SET.has(last)) return true;
  const lastTwo = rel.split('.').slice(-2).join('.');
  return isPublicSuffix(lastTwo, { includePrivate: false });
}

/* ------------------------------------------------------------------------ */
/* Issues                                                                   */
/* ------------------------------------------------------------------------ */

const STICKY = new Set(['PARTIAL_EXPORT', 'RECORDS_TRUNCATED', 'CHANGE_BATCH']);

class IssueList {
  constructor(limits, source) {
    this.limits = limits;
    this.source = source;
    this.list = [];
    this.dropped = 0;
    this.once = new Set();
  }

  add(code, line = 0, params = {}, detail = '', extra = null) {
    const def = ISSUE_CODES[code];
    if (!def || def.fatal) throw new Error(`zoneparse: not a warning code ${code}`);
    if (this.list.length >= this.limits.maxIssues && !STICKY.has(code)) {
      this.dropped++;
      return;
    }
    const issue = { code, severity: def.severity, line, source: this.source };
    if (extra && extra.name !== undefined) issue.name = extra.name;
    if (extra && extra.type !== undefined) issue.type = extra.type;
    issue.params = params;
    issue.detail = detail;
    this.list.push(issue);
  }

  addOnce(key, code, line, params, detail, extra) {
    if (this.once.has(key)) return;
    this.once.add(key);
    this.add(code, line, params, detail, extra);
  }

  finish() {
    const sorted = this.list.map((x, i) => [x, i]).sort((a, b) => (a[0].line - b[0].line) || (a[1] - b[1])).map((x) => x[0]);
    if (this.dropped) {
      sorted.push({
        code: 'WARNINGS_TRUNCATED', severity: 'info', line: 0, source: this.source,
        params: { max: this.limits.maxIssues, dropped: this.dropped },
        detail: `${this.dropped} further issue(s) not listed`
      });
    }
    return sorted;
  }
}

function fatalIssue(code, params = {}, detail = '', line = 0) {
  return { code, severity: 'error', line, params, detail };
}

/* ------------------------------------------------------------------------ */
/* Input decoding and detection                                             */
/* ------------------------------------------------------------------------ */

function toByteArray(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  return null;
}

/** ui/components.decodeText, duplicated so the lib stays DOM-free. */
function decodeBytes(bytes) {
  let encoding = 'utf-8';
  let offset = 0;
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) offset = 3;
  else if (bytes[0] === 0xff && bytes[1] === 0xfe) {
    encoding = 'utf-16le';
    offset = 2;
  } else if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    encoding = 'utf-16be';
    offset = 2;
  }
  try {
    return new TextDecoder(encoding, { fatal: false }).decode(bytes.subarray(offset));
  } catch {
    return new TextDecoder('utf-8').decode(bytes.subarray(offset));
  }
}

/** → { text, bytes, fatal } */
function decodeInput(input, L) {
  if (input === null || input === undefined) return { text: '', bytes: 0, fatal: null };
  if (typeof input === 'string') {
    const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
    if (text.length > L.maxChars) {
      return { text: '', bytes: 0, fatal: fatalIssue('TOO_LARGE', { size: text.length, max: L.maxChars, unit: 'chars' }, 'text too large') };
    }
    return { text, bytes: utf8Length(text), fatal: null };
  }
  const bytes = toByteArray(input);
  if (!bytes) return { text: '', bytes: 0, fatal: fatalIssue('NOT_TEXT', { hint: 'binary' }, 'input is neither text nor bytes') };
  if (bytes.length > L.maxBytes) {
    return { text: '', bytes: bytes.length, fatal: fatalIssue('TOO_LARGE', { size: bytes.length, max: L.maxBytes, unit: 'bytes' }, 'file too large') };
  }
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return { text: '', bytes: bytes.length, fatal: fatalIssue('NOT_A_ZONE', { hint: 'gzip', samples: [] }, 'gzip-compressed file') };
  }
  const text = decodeBytes(bytes);
  if (text.length > L.maxChars) {
    return { text: '', bytes: bytes.length, fatal: fatalIssue('TOO_LARGE', { size: text.length, max: L.maxChars, unit: 'chars' }, 'text too large') };
  }
  return { text, bytes: bytes.length, fatal: null };
}

/** Binary / encoding checks on decoded text → fatal issue or { replaced: count }. */
function textChecks(text) {
  if (text.charCodeAt(0) === 0x1f && (text.charCodeAt(1) === 0x8b || text.charCodeAt(1) === 0xfffd)) {
    return { fatal: fatalIssue('NOT_A_ZONE', { hint: 'gzip', samples: [] }, 'gzip-compressed data') };
  }
  const nul = text.indexOf('\u0000');
  if (nul >= 0) {
    const head = text.slice(0, 64);
    let nuls = 0;
    for (let i = 1; i < head.length; i += 2) if (head.charCodeAt(i) === 0) nuls++;
    const utf16 = head.length >= 8 && nuls >= Math.floor(head.length / 2) - 1;
    return { fatal: fatalIssue('NOT_TEXT', { hint: utf16 ? 'utf16' : 'binary' }, 'NUL character in text') };
  }
  const head = text.length > 65536 ? text.slice(0, 65536) : text;
  let bad = 0;
  for (let i = head.indexOf('�'); i >= 0; i = head.indexOf('�', i + 1)) bad++;
  // more than 1% replacement characters (and more than a handful: one mis-encoded "café" in a
  // short file is ENCODING_REPLACED, not a binary file)
  if (bad >= 8 && bad > head.length / 100) {
    return { fatal: fatalIssue('NOT_TEXT', { hint: 'binary' }, 'too many undecodable bytes') };
  }
  let replaced = bad;
  if (text.length > head.length) for (let i = text.indexOf('�', head.length); i >= 0; i = text.indexOf('�', i + 1)) replaced++;
  return { fatal: null, replaced };
}

function normalizeNewlines(text) {
  return text.indexOf('\r') >= 0 ? text.replace(/\r\n?/g, '\n') : text;
}

/** Only whitespace and comments (`;`, `#`, `//`, YAML `---`). */
function isEmptyText(text) {
  let start = 0;
  while (start <= text.length) {
    let end = text.indexOf('\n', start);
    if (end < 0) end = text.length;
    let i = start;
    while (i < end) {
      const c = text.charCodeAt(i);
      if (c !== 32 && c !== 9 && c !== 13 && c !== 0xfeff) break;
      i++;
    }
    if (i < end) {
      const c = text.charCodeAt(i);
      const rest = text.slice(i, Math.min(end, i + 3));
      if (!(c === 0x3b || c === 0x23 || rest.startsWith('//') || rest === '---')) return false;
    }
    start = end + 1;
  }
  return true;
}

function firstContentChar(text) {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c !== 32 && c !== 9 && c !== 10 && c !== 13 && c !== 0xfeff) return text[i];
  }
  return '';
}

/** Non-empty, non-comment lines (up to `max`). */
function contentLines(text, max = 200) {
  const out = [];
  let start = 0;
  while (start < text.length && out.length < max) {
    let end = text.indexOf('\n', start);
    if (end < 0) end = text.length;
    const line = text.slice(start, Math.min(end, start + 4096)).trim();
    if (line && !line.startsWith(';') && !line.startsWith('#')) out.push(line);
    start = end + 1;
  }
  return out;
}

/** Split concatenated JSON documents (`{…}\n{…}`), string- and depth-aware. */
function splitJsonDocuments(text, maxDocs) {
  const docs = [];
  let error = null;
  let truncated = false;
  let i = 0;
  const n = text.length;
  for (;;) {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 32 || c === 9 || c === 10 || c === 13 || c === 0xfeff) i++;
      else break;
    }
    if (i >= n) break;
    if (docs.length >= maxDocs) {
      truncated = true;
      break;
    }
    const c0 = text[i];
    if (c0 !== '{' && c0 !== '[') {
      error = { position: i, reason: 'unexpected-text' };
      break;
    }
    const start = i;
    let depth = 0;
    let inStr = false;
    for (; i < n; i++) {
      const ch = text.charCodeAt(i);
      if (inStr) {
        if (ch === 0x5c) i++;
        else if (ch === 0x22) inStr = false;
        continue;
      }
      if (ch === 0x22) inStr = true;
      else if (ch === 0x7b || ch === 0x5b) depth++;
      else if (ch === 0x7d || ch === 0x5d) {
        depth--;
        if (depth === 0) {
          i++;
          break;
        }
      }
    }
    if (depth !== 0) {
      error = { position: n, reason: 'unterminated' };
      break;
    }
    try {
      docs.push({ value: JSON.parse(text.slice(start, i)), start });
    } catch (err) {
      const m = /position (\d+)/.exec(String(err && err.message));
      error = { position: start + (m ? Number(m[1]) : 0), reason: 'syntax' };
      break;
    }
  }
  return { docs, error, truncated };
}

function firstItem(v) {
  return Array.isArray(v) && v.length && isPlainMap(v[0]) ? v[0] : null;
}

/** A deSEC RRset (desec.io API v1 `rrsets/`): `{ domain, subname, name, type, ttl, records[] }`. */
const isDesecRrset = (o) => isPlainMap(o) && Array.isArray(own(o, 'records')) && typeof own(o, 'type') === 'string'
  && typeof own(o, 'subname') === 'string';
/** A DigitalOcean domain record (api.digitalocean.com v2): `{ id, type, name, data, priority, port, ttl, weight, flags, tag }`. */
const isDoRecord = (o) => isPlainMap(o) && typeof own(o, 'id') === 'number' && typeof own(o, 'type') === 'string'
  && typeof own(o, 'name') === 'string' && typeof own(o, 'data') === 'string' && own(o, 'content') === undefined;
/** deSEC's answer to a listing of more than 500 RRsets without a cursor; the total is in its text. */
const DESEC_PAGINATION_RE = /^Pagination required\b/;

/**
 * The changes of a Route 53 change batch (`{ Changes: [...] }`, the `--change-batch` file, or the
 * `{ ChangeBatch: { Changes } }` of a whole request), or null: at least one change with an
 * `Action` and a `ResourceRecordSet`.
 */
function changeList(v) {
  if (!isPlainMap(v)) return null;
  const batch = isPlainMap(own(v, 'ChangeBatch')) ? own(v, 'ChangeBatch') : v;
  const list = own(batch, 'Changes');
  if (!Array.isArray(list) || !list.length) return null;
  const f = list[0];
  return isPlainMap(f) && typeof own(f, 'Action') === 'string' && isPlainMap(own(f, 'ResourceRecordSet')) ? list : null;
}

/**
 * Kind of one parsed JSON document: 'route53' | 'cloudflare-api' | 'cf-error' | 'desec-api' |
 * 'desec-pagination' | 'desec-error' | 'digitalocean-api' | 'do-error' | 'empty' | null.
 */
function jsonKind(v) {
  if (Array.isArray(v)) {
    if (!v.length) return 'empty';
    const f = firstItem(v);
    if (!f) return null;
    if (own(f, 'ResourceRecords') !== undefined || own(f, 'AliasTarget') !== undefined) return 'route53';
    if (typeof own(f, 'type') === 'string' && own(f, 'content') !== undefined) return 'cloudflare-api';
    if (isDesecRrset(f)) return 'desec-api';
    if (isDoRecord(f)) return 'digitalocean-api';
    return null;
  }
  if (!isPlainMap(v)) return null;
  if (Array.isArray(own(v, 'ResourceRecordSets'))) return 'route53';
  if (changeList(v)) return 'route53';
  if (Array.isArray(own(v, 'result'))) return 'cloudflare-api';
  if (own(v, 'success') === false && Array.isArray(own(v, 'errors'))) return 'cf-error';
  if (Array.isArray(own(v, 'domain_records')) || isDoRecord(own(v, 'domain_record'))) return 'digitalocean-api';
  if (typeof own(v, 'type') === 'string' && typeof own(v, 'name') === 'string' && own(v, 'content') !== undefined) return 'cloudflare-api';
  if (isDesecRrset(v)) return 'desec-api';
  const keys = Object.keys(v);
  const detail = own(v, 'detail');
  if (typeof detail === 'string' && keys.length === 1) return DESEC_PAGINATION_RE.test(detail) ? 'desec-pagination' : 'desec-error';
  if (typeof own(v, 'id') === 'string' && typeof own(v, 'message') === 'string' && keys.length <= 3) return 'do-error';
  return null;
}

/** Error and pagination documents count as the format of the listing they answer. */
const KIND_FORMAT = Object.freeze({
  'cf-error': 'cloudflare-api', 'desec-pagination': 'desec-api', 'desec-error': 'desec-api', 'do-error': 'digitalocean-api'
});
/** The marker a JSON format shows (Zone.markers). */
const JSON_MARKER = Object.freeze({
  route53: 'ResourceRecordSets', 'cloudflare-api': 'result[]', 'desec-api': 'rrsets[]', 'digitalocean-api': 'domain_records[]'
});

const TYPE_TOKEN_RE = /^(?:A|AAAA|CNAME|MX|NS|TXT|SOA|SRV|CAA|PTR)$/;

function csvHint(firstLine) {
  let commas = 0;
  let inQ = false;
  for (let i = 0; i < firstLine.length; i++) {
    const c = firstLine[i];
    if (c === '"') inQ = !inQ;
    else if (c === ',' && !inQ) commas++;
  }
  if (commas < 2) return null;
  const fields = firstLine.split(',').map((f) => f.trim().replace(/^"|"$/g, '').toLowerCase());
  const has = (...names) => fields.some((f) => names.includes(f));
  if (has('type', 'record type', 'rrtype') && has('name', 'host', 'hostname', 'record name') &&
      has('content', 'value', 'data', 'address', 'rdata', 'target', 'record', 'points to')) return 'dns-csv';
  return 'csv';
}

/** Lines that show a text-shaped CSV (not a BIND file with commas inside TXT). */
function looksLikeCsv(lines) {
  if (!lines.length) return null;
  const first = lines[0];
  if (first.includes('\t') || first.startsWith('$')) return null;
  const hint = csvHint(first);
  if (!hint) return null;
  if (first.split(/\s+/).some((t) => TYPE_TOKEN_RE.test(t))) return null;
  return hint;
}

/** Headers that name the zone. */
function headerOrigin(text) {
  const head = text.length > 16384 ? text.slice(0, 16384) : text;
  const pats = [/^;;\s*Domain:\s+(\S+)/m, /^;\s*Domain:\s+(\S+)/m, /^;\s*Zone file for\s+(\S+)/m];
  for (const re of pats) {
    const m = re.exec(head);
    if (m) {
      const host = normalizeHostname(m[1], { allowSingleLabel: true });
      if (host) return host;
    }
  }
  return null;
}

/** Internal detection; `docs` holds parsed JSON documents for the JSON formats. */
function detectInternal(text, filename, maxJsonDocs = ZONE_LIMITS.maxJsonDocs) {
  const res = { format: null, dialect: null, markers: [], confidence: 'low', notZone: null, fatal: null, docs: null, docsTruncated: false };
  if (isEmptyText(text)) {
    res.notZone = 'empty';
    res.fatal = fatalIssue('EMPTY', {}, 'nothing but whitespace and comments');
    return res;
  }
  const head = text.length > 4096 ? text.slice(0, 4096) : text;
  if (head.includes('-----BEGIN ')) {
    res.notZone = 'pem';
    res.fatal = fatalIssue('NOT_A_ZONE', { hint: 'pem', samples: [] }, 'looks like a PEM certificate or key');
    return res;
  }
  if (/<!doctype\s+html|<html[\s>]/i.test(head)) {
    res.notZone = 'html';
    res.fatal = fatalIssue('NOT_A_ZONE', { hint: 'html', samples: [] }, 'looks like an HTML page');
    return res;
  }
  const first = firstContentChar(text);
  if (first === '{' || first === '[') {
    const split = splitJsonDocuments(text, maxJsonDocs);
    if (split.error) {
      res.fatal = fatalIssue('INVALID_JSON', { position: split.error.position, reason: split.error.reason }, 'invalid JSON');
      return res;
    }
    res.docs = split.docs;
    res.docsTruncated = split.truncated;
    const kinds = new Set(split.docs.map((d) => {
      const k = jsonKind(d.value);
      return k !== null && Object.hasOwn(KIND_FORMAT, k) ? KIND_FORMAT[k] : k;
    }));
    kinds.delete('empty');
    if (kinds.size === 0 && split.docs.length) {
      res.fatal = fatalIssue('EMPTY', {}, 'JSON without records');
      return res;
    }
    if (kinds.size !== 1 || kinds.has(null)) {
      res.fatal = fatalIssue('UNSUPPORTED_JSON', {}, 'JSON is not a Cloudflare, Route 53, deSEC or DigitalOcean record listing');
      return res;
    }
    res.format = [...kinds][0];
    res.confidence = 'high';
    res.markers.push(res.format === 'route53' && split.docs.some((d) => changeList(d.value)) ? 'Changes' : JSON_MARKER[res.format]);
    if (split.docs.length > 1) res.markers.push('json-pages');
    return res;
  }
  if (/^SUCCESS: Getting information for Domain '/m.test(head)) {
    res.format = 'plesk-info';
    res.confidence = 'high';
    res.markers.push('SUCCESS: Getting information');
    return res;
  }
  if (/^RESOURCERECORDSETS\s/m.test(head) || /^\|\s*ListResourceRecordSets\s*\|/m.test(head) || /^\|\|?\s*ResourceRecordSets\s*\|/m.test(head)) {
    res.notZone = 'aws-output-json';
    res.fatal = fatalIssue('NOT_A_ZONE', { hint: 'aws-output-json', samples: contentLines(text, 3).map((l) => safeText(l, 80)) }, 'AWS CLI text/table output');
    return res;
  }
  const yamlHead = text.length > 65536 ? text.slice(0, 65536) : text;
  const lowerName = String(filename ?? '').toLowerCase();
  if (/^\? ''\s*$/m.test(yamlHead)) {
    res.format = 'octodns';
    res.confidence = 'high';
    res.markers.push("? ''");
    return res;
  }
  if (/^[^\s;#$][^:\n]*:[ \t]*$/m.test(yamlHead) && /^[ \t]+(?:-[ \t]+)?type:[ \t]*[A-Za-z0-9]+[ \t]*$/m.test(yamlHead)) {
    res.format = 'octodns';
    res.confidence = 'high';
    res.markers.push('type: keys');
    return res;
  }
  if (/\.ya?ml$/.test(lowerName)) {
    res.format = 'octodns';
    res.confidence = 'low';
    res.markers.push('.yaml file name');
    return res;
  }
  const csv = looksLikeCsv(contentLines(text, 3));
  if (csv) {
    res.notZone = 'csv';
    res.fatal = fatalIssue('NOT_A_ZONE', { hint: csv, samples: contentLines(text, 3).map((l) => safeText(l, 80)) }, 'looks like CSV');
    return res;
  }
  res.format = 'bind';
  const m = res.markers;
  const hasCfHeader = /^;;\s*Domain:\s/m.test(head);
  const hasCfTags = text.includes('cf_tags=');
  const hasCfNs = /ns\.cloudflare\.com/i.test(text);
  if (/^; <<>> DiG/m.test(head) || /^;; (?:XFR size|Query time):/m.test(text)) m.push('dig AXFR');
  if (hasCfHeader && (hasCfTags || hasCfNs)) {
    res.dialect = 'cloudflare';
    m.push(';; Domain: header');
    if (hasCfTags) m.push('cf_tags');
    if (hasCfNs) m.push('ns.cloudflare.com');
  } else if (/(^|\s)AWS\s+ALIAS(\s|$)/m.test(text) || /;\s*AWS\s+routing=/.test(text)) {
    res.dialect = 'cli53';
    if (/(^|\s)AWS\s+ALIAS(\s|$)/m.test(text)) m.push('class AWS');
    if (/;\s*AWS\s+routing=/.test(text)) m.push('; AWS routing');
  } else if (/^;\s*Exported \(y-m-d hh:mm:ss\)/m.test(head) || /^[^\s;]*[^\\\s]\.@\s/m.test(text)) {
    res.dialect = 'godaddy';
    if (/^;\s*Exported \(y-m-d hh:mm:ss\)/m.test(head)) m.push('; Exported (y-m-d hh:mm:ss)');
    if (/^[^\s;]*[^\\\s]\.@\s/m.test(text)) m.push('.@ owner');
  } else if (head.includes('Cpanel::ZoneFile::VERSION') || /^;\s*Zone file for\s/m.test(head)) {
    res.dialect = 'cpanel';
    if (head.includes('Cpanel::ZoneFile::VERSION')) m.push('Cpanel::ZoneFile::VERSION');
    if (/^;\s*Zone file for\s/m.test(head)) m.push('; Zone file for');
  } else if (/^@[ \t]+IN[ \t]+SOA[ \t]/im.test(head) && !/^\$ORIGIN\s/im.test(head) &&
      (/^\$TTL[ \t]+14400\b/m.test(head) || /^x\._domainkey\s/m.test(text))) {
    res.dialect = 'directadmin';
    m.push('@ IN SOA without TTL');
    if (/^\$TTL[ \t]+14400\b/m.test(head)) m.push('$TTL 14400');
    if (/^x\._domainkey\s/m.test(text)) m.push('x._domainkey');
  } else {
    res.dialect = 'generic';
  }
  const structured = /^\$(?:ORIGIN|TTL)\s/im.test(head) || /\sSOA\s/i.test(head);
  res.confidence = res.dialect !== 'generic' || structured ? 'high' : 'low';
  return res;
}

/**
 * Cheap format detection (the JSON formats are parsed to classify them).
 * @param {string|Uint8Array|ArrayBuffer} text
 * @param {{ filename?: string|null }} [opts]
 * @returns {{ format: string|null, dialect: string|null, markers: string[], confidence: 'high'|'low',
 *   notZone: null|'empty'|'pem'|'html'|'binary'|'csv'|'gzip'|'aws-output-json',
 *   fatal: null|{ code: string, params: object } }}
 */
export function detectZoneFormat(text, { filename = null } = {}) {
  try {
    const dec = decodeInput(text, ZONE_LIMITS);
    if (dec.fatal) {
      const notZone = dec.fatal.code === 'NOT_TEXT' ? 'binary' : dec.fatal.params.hint === 'gzip' ? 'gzip' : null;
      return { format: null, dialect: null, markers: [], confidence: 'low', notZone, fatal: { code: dec.fatal.code, params: dec.fatal.params } };
    }
    const chk = textChecks(dec.text);
    if (chk.fatal) {
      const notZone = chk.fatal.code === 'NOT_TEXT' ? 'binary' : 'gzip';
      return { format: null, dialect: null, markers: [], confidence: 'low', notZone, fatal: { code: chk.fatal.code, params: chk.fatal.params } };
    }
    const d = detectInternal(normalizeNewlines(dec.text), filename);
    return {
      format: d.fatal ? null : d.format, dialect: d.fatal ? null : d.dialect, markers: d.markers,
      confidence: d.confidence, notZone: d.notZone, fatal: d.fatal ? { code: d.fatal.code, params: d.fatal.params } : null
    };
  } catch {
    return { format: null, dialect: null, markers: [], confidence: 'low', notZone: null, fatal: { code: 'NOT_A_ZONE', params: { hint: 'unknown', samples: [] } } };
  }
}

/**
 * Zone name from a file name: strips a trailing `.txt`, then `.db|.zone|.hosts|.bind|.yaml|.yml|.json`,
 * then a leading `db.`. The rest must be a valid hostname of ≥ 2 labels.
 * `directadmin-example.com.db.txt` → `directadmin-example.com`, `db.example.com` → `example.com`.
 * @param {string|null} filename
 * @returns {string|null}
 */
export function inferOriginFromFilename(filename) {
  if (typeof filename !== 'string' || !filename) return null;
  let base = filename.split(/[\\/]/).pop().trim().toLowerCase();
  if (base.endsWith('.txt')) base = base.slice(0, -4);
  const ext = /\.(?:db|zone|hosts|bind|yaml|yml|json)$/.exec(base);
  if (ext) base = base.slice(0, ext.index);
  if (base.startsWith('db.')) base = base.slice(3);
  if (!base || base.length > 253) return null;
  const host = normalizeHostname(base);
  if (!host || host !== base || !host.includes('.')) return null;
  const last = host.slice(host.lastIndexOf('.') + 1);
  if (FILE_EXTENSIONS.has(last)) return null;
  return host;
}

const FILE_EXTENSIONS = new Set(['txt', 'csv', 'tsv', 'pem', 'crt', 'cer', 'key', 'bak', 'old', 'orig', 'conf',
  'cfg', 'log', 'json', 'yaml', 'yml', 'db', 'zone', 'xml', 'html', 'htm', 'md', 'gz', 'zip', 'tmp']);

/* ------------------------------------------------------------------------ */
/* Origin inference over owner names                                        */
/* ------------------------------------------------------------------------ */

function labelCount(name) {
  return name === '.' ? 0 : name.split('.').length;
}

/** Longest common label suffix of names ('' when none). */
function commonSuffix(names) {
  let suffix = null;
  for (const n of names) {
    if (n === '.') return '';
    const labels = n.split('.');
    if (suffix === null) {
      suffix = labels;
      continue;
    }
    let k = 0;
    while (k < suffix.length && k < labels.length && suffix[suffix.length - 1 - k] === labels[labels.length - 1 - k]) k++;
    suffix = suffix.slice(suffix.length - k);
    if (!suffix.length) return '';
  }
  return suffix ? suffix.join('.') : '';
}

/**
 * The zone apex among absolute owners: the SOA owner; else the shortest NS owner that is an
 * ancestor of (or equal to) every owner (a delegation never qualifies); else the longest common
 * label suffix (weak); else the most common registrable domain (weak).
 */
function apexCandidate({ soa = null, ns = [], owners = [] }) {
  if (soa) return { name: soa, source: 'soa', strong: true };
  const all = [...new Set(owners)].filter((o) => o !== '.');
  const nsSorted = [...new Set(ns)].sort((a, b) => labelCount(a) - labelCount(b));
  for (const cand of nsSorted) {
    if (all.every((o) => isSubdomainOf(o.replace(/^\*\./, 'x.'), cand) || o === cand)) return { name: cand, source: 'records', strong: true };
  }
  if (!all.length) return null;
  const suffix = commonSuffix(all.map((o) => (o.startsWith('*.') ? o.slice(2) : o)));
  if (suffix && suffix.includes('.') && !isPublicSuffix(suffix, { includePrivate: false }) && !suffix.startsWith('*')) {
    return { name: suffix, source: 'records', strong: false };
  }
  const counts = new Map();
  for (const o of all) {
    const reg = registrableDomain(o);
    if (reg) counts.set(reg, (counts.get(reg) || 0) + 1);
  }
  let best = null;
  for (const [reg, c] of counts) if (!best || c > best[1]) best = [reg, c];
  return best ? { name: best[0], source: 'records', strong: false } : null;
}

/** Normalise a user-supplied origin ("Example.com.", a URL, an IDN) or null. */
function normalizeUserOrigin(origin) {
  if (typeof origin !== 'string' || !origin.trim()) return null;
  const s = origin.trim();
  if (s === '.') return '.';
  const host = normalizeHostname(s, { allowSingleLabel: true });
  if (host) return host;
  const r = parseName(s.endsWith('.') ? s : `${s}.`);
  return r.ok ? r.name : null;
}

/* ------------------------------------------------------------------------ */
/* Tokenizer (BIND master files)                                            */
/* ------------------------------------------------------------------------ */

function splitLines(text) {
  const t = normalizeNewlines(text);
  const lines = t.split('\n');
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/**
 * Scan one logical entry starting at line index `start`.
 * @returns {{ entry: object|null, next?: number, restart?: number, after?: number, scanned?: number }}
 */
function scanEntry(lines, start, L, issue) {
  let j = start;
  let line = lines[j];
  if (line.length > L.maxLineChars) {
    issue('LINE_TOO_LONG', j + 1, { length: line.length, max: L.maxLineChars }, 'line longer than the limit; skipped');
    return { entry: null, next: j + 1 };
  }
  const tokens = [];
  let comment = '';
  let depth = 0;
  let overflow = false;
  const c0 = line.charCodeAt(0);
  const blank = c0 === 32 || c0 === 9;
  const push = (t, q) => {
    if (tokens.length >= L.maxTokensPerEntry) overflow = true;
    else tokens.push({ t, q });
  };
  for (;;) {
    const n = line.length;
    let pos = 0;
    let buf = null;
    let runStart = -1;
    const flush = () => {
      if (runStart >= 0) {
        buf = (buf === null ? '' : buf) + line.slice(runStart, pos);
        runStart = -1;
      }
      if (buf !== null) {
        push(buf, false);
        buf = null;
      }
    };
    while (pos < n) {
      const c = line.charCodeAt(pos);
      if (c === 32 || c === 9) {
        flush();
        pos++;
        continue;
      }
      if (c === 0x3b) { // ;
        flush();
        const body = line.slice(pos + 1).trim();
        if (body) comment = comment ? `${comment} ${body}` : body;
        pos = n;
        break;
      }
      if (c === 0x28 || c === 0x29) { // ( )
        flush();
        if (c === 0x28) depth++;
        else if (depth > 0) depth--;
        else issue('UNBALANCED_PAREN', j + 1, { kind: 'close' }, 'unmatched ")" ignored');
        pos++;
        continue;
      }
      if (c === 0x22) { // "
        let k = pos + 1;
        while (k < n) {
          const d = line.charCodeAt(k);
          if (d === 0x5c) {
            k += 2;
            continue;
          }
          if (d === 0x22) break;
          k++;
        }
        if (k >= n) {
          issue('UNTERMINATED_QUOTE', j + 1, {}, 'quoted string not closed on its line; entry dropped');
          return { entry: null, next: j + 1 };
        }
        const content = line.slice(pos + 1, k);
        if (runStart >= 0 || buf !== null) { // glued: alpn="h3,h2" is one token
          if (runStart >= 0) buf = (buf === null ? '' : buf) + line.slice(runStart, pos);
          buf += content;
          pos = k + 1;
          runStart = pos;
          continue;
        }
        push(content, true);
        pos = k + 1;
        continue;
      }
      if (runStart < 0) runStart = pos;
      pos += c === 0x5c ? Math.min(2, n - pos) : 1;
    }
    flush();
    if (depth === 0) break;
    j++;
    if (j >= lines.length || j - start > L.maxParenLines) {
      issue('UNBALANCED_PAREN', start + 1, { kind: 'open' }, '"(" never closed; entry dropped');
      return { entry: null, restart: start + 1, after: Math.min(j, lines.length), scanned: j - start };
    }
    line = lines[j];
    if (line.charCodeAt(0) === 0x24) { // a column-0 $ directive
      issue('UNBALANCED_PAREN', start + 1, { kind: 'open' }, '"(" still open at a $ directive; entry dropped');
      return { entry: null, restart: start + 1, after: j, scanned: j - start };
    }
    if (line.length > L.maxLineChars) {
      issue('LINE_TOO_LONG', j + 1, { length: line.length, max: L.maxLineChars }, 'line longer than the limit; entry dropped');
      return { entry: null, next: j + 1 };
    }
  }
  if (!tokens.length) return { entry: null, next: j + 1 };
  return { entry: { line: start + 1, endLine: j + 1, blank, tokens, comment, overflow }, next: j + 1 };
}

/**
 * Split master-file text into logical entries. Single pass per entry; comments are kept on the
 * entry (Cloudflare `cf_tags`, cli53 routing), quotes and escapes survive raw for RDATA decoding.
 * @param {string|string[]} text text, or pre-split lines
 * @param {{ limits?: object, onIssue?: (code: string, line: number, params: object, detail: string) => void }} [opts]
 * @returns {Array<{ line: number, endLine: number, blank: boolean, tokens: Array<{ t: string, q: boolean }>, comment: string, overflow: boolean }>}
 */
export function tokenizeMaster(text, { limits = ZONE_LIMITS, onIssue = null } = {}) {
  const L = { ...ZONE_LIMITS, ...limits };
  const lines = Array.isArray(text) ? text : splitLines(String(text ?? ''));
  const issue = typeof onIssue === 'function' ? onIssue : () => {};
  const entries = [];
  const budget = lines.length + L.maxParenLines;
  let rescanned = 0;
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.length === 0) {
      i++;
      continue;
    }
    const r = scanEntry(lines, i, L, issue);
    if (r.entry) {
      if (entries.length >= L.maxEntries) {
        issue('RECORDS_TRUNCATED', r.entry.line, { max: L.maxEntries, unit: 'entries' }, 'too many entries; the rest was not read');
        break;
      }
      entries.push(r.entry);
    }
    if (r.restart !== undefined) {
      rescanned += r.scanned;
      i = rescanned > budget ? Math.max(r.after, i + 1) : r.restart;
    } else {
      i = r.next;
    }
  }
  return entries;
}

/** Tokenize one JSON / Plesk value (quotes and escapes, no comments or parentheses). null on an open quote. */
function splitValueTokens(str) {
  const toks = [];
  const n = str.length;
  let i = 0;
  while (i < n) {
    const c = str.charCodeAt(i);
    if (c === 32 || c === 9 || c === 10 || c === 13) {
      i++;
      continue;
    }
    if (c === 0x22) {
      let k = i + 1;
      while (k < n) {
        const d = str.charCodeAt(k);
        if (d === 0x5c) {
          k += 2;
          continue;
        }
        if (d === 0x22) break;
        k++;
      }
      if (k >= n) return null;
      toks.push({ t: str.slice(i + 1, k), q: true });
      i = k + 1;
      continue;
    }
    let buf = '';
    let k = i;
    while (k < n) {
      const d = str.charCodeAt(k);
      if (d === 32 || d === 9 || d === 10 || d === 13) break;
      if (d === 0x5c) {
        k += 2;
        continue;
      }
      if (d === 0x22) {
        buf += str.slice(i, k);
        let m = k + 1;
        while (m < n) {
          const e = str.charCodeAt(m);
          if (e === 0x5c) {
            m += 2;
            continue;
          }
          if (e === 0x22) break;
          m++;
        }
        if (m >= n) return null;
        buf += str.slice(k + 1, m);
        i = m + 1;
        k = i;
        continue;
      }
      k++;
    }
    toks.push({ t: buf + str.slice(i, Math.min(k, n)), q: false });
    i = k;
  }
  return toks;
}

/** A raw token for a literal string (escapes `\` and `"`), e.g. a YAML / JSON field. */
function rawToken(s, q = true) {
  return { t: String(s).replace(/[\\"]/g, (m) => `\\${m}`), q };
}

function rawText(toks) {
  return toks.map((t) => (t.q ? `"${t.t}"` : t.t)).join(' ');
}

/* ------------------------------------------------------------------------ */
/* RDATA                                                                    */
/* ------------------------------------------------------------------------ */

class RdataError extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

/**
 * Run data through dnswire encode → decode: canonical `data` (derived fields included) and `text`.
 * `rdata` (bytes) is used for types dnswire can decode but not encode from `data`.
 */
function viaWire(type, dataIn, rdata = null) {
  let rr;
  try {
    const answer = rdata ? { name: '.', type, ttl: 0, rdata } : { name: '.', type, ttl: 0, data: dataIn };
    rr = decodeMessage(encodeMessage({ answers: [answer] })).answers[0];
  } catch {
    throw new RdataError('invalid');
  }
  if (!rr || rr.error) throw new RdataError('invalid');
  return rr;
}

/** Wire RDATA from 16-bit integers and names (RP, AFSDB, KX). */
function wireOf(parts) {
  const bytes = [];
  try {
    for (const p of parts) {
      if (typeof p === 'number') bytes.push((p >> 8) & 0xff, p & 0xff);
      else bytes.push(...encodeName(p));
    }
  } catch {
    throw new RdataError('bad-name');
  }
  return Uint8Array.from(bytes);
}

/** Names inside RDATA (served form, '' = root) for any dnswire data shape. */
function targetsFromData(type, data) {
  if (data === null || data === undefined) return [];
  switch (type) {
    case 'NS': case 'CNAME': case 'PTR': case 'DNAME': return [rootToEmpty(data)];
    case 'MX': return [rootToEmpty(data.exchange)];
    case 'SRV': return [rootToEmpty(data.target)];
    case 'SOA': return [rootToEmpty(data.mname), rootToEmpty(data.rname)];
    case 'SVCB': case 'HTTPS': return [rootToEmpty(data.target)];
    case 'NAPTR': return [rootToEmpty(data.replacement)];
    case 'RP': return [rootToEmpty(data.mbox), rootToEmpty(data.txt)];
    case 'AFSDB': return [rootToEmpty(data.hostname)];
    case 'KX': return [rootToEmpty(data.exchanger)];
    default: return [];
  }
}

const SVC_KEYS = ['mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ech', 'ipv6hint', 'dohpath', 'ohttp', 'tls-supported-groups'];

function svcKeyName(k) {
  const lower = k.toLowerCase();
  if (SVC_KEYS.includes(lower)) return lower;
  const m = /^key(\d{1,5})$/.exec(lower);
  if (!m) return null;
  const n = Number(m[1]);
  if (n > 0xffff) return null;
  return n < SVC_KEYS.length ? SVC_KEYS[n] : `key${n}`;
}

/** RFC 9460 value-list: split at unescaped commas; `\,` and `\\` are literal. */
function splitValueList(s) {
  const items = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\' && i + 1 < s.length) {
      cur += s[++i];
      continue;
    }
    if (c === ',') {
      items.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  items.push(cur);
  return items;
}

/** Two bytes as a 16-bit number (network order). */
const u16 = (bytes, i) => (bytes[i] << 8) | bytes[i + 1];

/**
 * The value of a SvcParamKey written by number (`key1`, `key5` …): its wire bytes (RFC 9460
 * §2.1: "the decoded value SHALL be used as its wire-format encoding", as dnspython reads it), in
 * the shape the key's name gives it.
 */
function svcWireValue(key, bytes) {
  const list = (size, why, item) => {
    if (!bytes.length || bytes.length % size) throw new RdataError(why);
    const out = [];
    for (let i = 0; i < bytes.length; i += size) out.push(item(i));
    return out;
  };
  switch (key) {
    case 'mandatory': return list(2, 'svc-mandatory', (i) => (u16(bytes, i) < SVC_KEYS.length ? SVC_KEYS[u16(bytes, i)] : `key${u16(bytes, i)}`));
    case 'alpn': {
      const out = [];
      for (let i = 0; i < bytes.length;) {
        const len = bytes[i];
        if (!len || i + 1 + len > bytes.length) throw new RdataError('svc-alpn');
        out.push(decodeUtf8Lenient(bytes.subarray(i + 1, i + 1 + len)));
        i += 1 + len;
      }
      if (!out.length) throw new RdataError('svc-alpn');
      return out;
    }
    case 'no-default-alpn':
    case 'ohttp':
      if (bytes.length) throw new RdataError('svc-value-not-allowed');
      return true;
    case 'port':
      if (bytes.length !== 2) throw new RdataError('svc-port');
      return u16(bytes, 0);
    case 'ipv4hint': return list(4, 'svc-ipv4hint', (i) => [...bytes.subarray(i, i + 4)].join('.'));
    case 'ipv6hint': return list(16, 'svc-ipv6hint', (i) => normalizeIP(Array.from({ length: 8 }, (_, j) => u16(bytes, i + 2 * j).toString(16)).join(':')));
    case 'ech': return base64Encode(bytes);
    case 'dohpath': return decodeUtf8Lenient(bytes);
    case 'tls-supported-groups': return list(2, 'svc-groups', (i) => u16(bytes, i));
    default: {
      let hex = '';
      for (const b of bytes) hex += b.toString(16).padStart(2, '0');
      return hex;
    }
  }
}

function parseSvcParams(toks, base) {
  const params = {};
  for (const tok of toks) {
    const eq = tok.t.indexOf('=');
    const keyRaw = eq < 0 ? tok.t : tok.t.slice(0, eq);
    const key = svcKeyName(keyRaw);
    if (!key) throw new RdataError('svc-unknown-key');
    if (HAS_OWN.call(params, key)) throw new RdataError('svc-duplicate-key');
    const hasValue = eq >= 0;
    const dec = hasValue ? decodeEscapes(tok.t.slice(eq + 1), { base }) : { bytes: new Uint8Array(0), ok: true };
    if (!dec.ok) throw new RdataError('bad-escape');
    // A key with a name written by its number holds wire bytes, not the named key's text.
    if (/^key\d+$/i.test(keyRaw) && SVC_KEYS.includes(key)) {
      params[key] = svcWireValue(key, dec.bytes);
      continue;
    }
    const str = decodeUtf8Lenient(dec.bytes);
    switch (key) {
      case 'mandatory': {
        const keys = str.split(',').map((x) => svcKeyName(x.trim()));
        if (!hasValue || keys.some((x) => !x)) throw new RdataError('svc-mandatory');
        params.mandatory = keys;
        break;
      }
      case 'alpn': {
        const ids = splitValueList(str);
        if (!hasValue || ids.some((x) => !x)) throw new RdataError('svc-alpn');
        params.alpn = ids;
        break;
      }
      case 'no-default-alpn':
      case 'ohttp':
        if (hasValue && dec.bytes.length) throw new RdataError('svc-value-not-allowed');
        params[key] = true;
        break;
      case 'port':
        if (!/^\d{1,5}$/.test(str) || Number(str) > 0xffff) throw new RdataError('svc-port');
        params.port = Number(str);
        break;
      case 'ipv4hint':
      case 'ipv6hint': {
        const want = key === 'ipv4hint' ? 4 : 6;
        const ips = str.split(',').map((x) => {
          const ip = normalizeIP(x.trim());
          if (!ip || (want === 4) !== !ip.includes(':')) throw new RdataError(`svc-${key}`);
          return ip;
        });
        params[key] = ips;
        break;
      }
      case 'ech':
        try {
          base64Decode(str);
        } catch {
          throw new RdataError('svc-ech');
        }
        params.ech = str;
        break;
      case 'dohpath':
        params.dohpath = str;
        break;
      case 'tls-supported-groups': {
        const groups = str.split(',').map((x) => {
          if (!/^\d{1,5}$/.test(x.trim()) || Number(x) > 0xffff) throw new RdataError('svc-groups');
          return Number(x);
        });
        params['tls-supported-groups'] = groups;
        break;
      }
      default: {
        let hex = '';
        for (const b of dec.bytes) hex += b.toString(16).padStart(2, '0');
        params[key] = hex;
      }
    }
  }
  return params;
}

/**
 * Parse RDATA tokens of `type` into `{ data, text, targets, rel, at, idn }` (dnswire shapes).
 * Returns null for a type whose presentation format is not parsed (RDATA_UNPARSED).
 * Throws RdataError for invalid RDATA.
 * @param {{ origin: string|null, base: 8|10, absolute: boolean }} ctx
 */
function parseRdata(type, toks, ctx) {
  const out = { data: null, text: '', targets: [], rel: [], atNames: [], idn: false };
  const exact = (n) => {
    if (toks.length < n) throw new RdataError('missing-field');
    if (toks.length > n) throw new RdataError('extra-field');
  };
  const atLeast = (n) => {
    if (toks.length < n) throw new RdataError('missing-field');
  };
  const uint = (tok, max, what) => {
    if (!tok || !/^\d+$/.test(tok.t)) throw new RdataError(`bad-${what}`);
    const v = Number(tok.t);
    if (v > max) throw new RdataError(`bad-${what}`);
    return v;
  };
  const timer = (tok, what) => {
    const v = tok ? parseTtlValue(tok.t) : null;
    if (v === null || v > MAX_U32) throw new RdataError(`bad-${what}`);
    return v;
  };
  const name = (tok) => {
    if (!tok) throw new RdataError('missing-field');
    const r = parseName(tok.t, ctx);
    if (!r.ok) throw new RdataError(r.reason === 'no-origin' ? 'relative-without-origin' : 'bad-name');
    if (r.at) out.atNames.push({ raw: tok.t, name: r.name });
    if (r.idn) out.idn = true;
    if (r.relative && !r.at && !r.apex && r.relLabels >= 2 && r.name !== r.rel) out.rel.push({ index: out.targets.length, rel: r.rel, relLabels: r.relLabels });
    out.targets.push(rootToEmpty(r.name));
    return r.name;
  };
  const chars = (tok) => {
    const r = decodeEscapes(tok.t, { base: ctx.base });
    if (!r.ok) throw new RdataError('bad-escape');
    return r.bytes;
  };
  const hexOf = (list, what, allowEmpty = false) => {
    const hex = list.map((t) => t.t).join('');
    if ((!hex && !allowEmpty) || hex.length % 2 || !/^[0-9a-fA-F]*$/.test(hex)) throw new RdataError(`bad-${what}`);
    return hex.toLowerCase();
  };
  const alg = (tok) => {
    if (tok && HAS_OWN.call(ALG_BY_NAME, tok.t.toUpperCase())) return ALG_BY_NAME[tok.t.toUpperCase()];
    return uint(tok, 255, 'algorithm');
  };
  const b64 = (list, what) => {
    const s = list.map((t) => t.t).join('');
    try {
      base64Decode(s);
    } catch {
      throw new RdataError(`bad-${what}`);
    }
    if (!s) throw new RdataError(`bad-${what}`);
    return s;
  };

  if (toks.length && !toks[0].q && toks[0].t === '\\#') {
    atLeast(2);
    const len = uint(toks[1], 0xffff, 'generic-length');
    const hex = hexOf(toks.slice(2), 'generic-data', true);
    if (hex.length / 2 !== len) throw new RdataError('generic-length');
    const num = typeToNumber(type);
    if (num === null) return null;
    let rr;
    try {
      rr = decodeMessage(encodeMessage({ answers: [{ name: '.', type: num, ttl: 0, rdata: hexDecode(hex) }] })).answers[0];
    } catch {
      throw new RdataError('generic-data');
    }
    if (!rr || rr.error) throw new RdataError('generic-data');
    out.data = rr.data;
    out.text = rr.text;
    out.targets = targetsFromData(type, rr.data);
    return out;
  }

  switch (type) {
    case 'A':
    case 'AAAA': {
      exact(1);
      const t = toks[0].t;
      const shape = type === 'A' ? /^\d{1,3}(?:\.\d{1,3}){3}$/ : /^[0-9A-Fa-f:.]+$/;
      const ip = shape.test(t) ? normalizeIP(t) : null;
      if (!ip) throw new RdataError('bad-address');
      if ((type === 'A') === ip.includes(':')) throw new RdataError('wrong-family');
      out.data = ip;
      out.text = ip;
      return out;
    }
    case 'NS':
    case 'CNAME':
    case 'PTR':
    case 'DNAME': {
      exact(1);
      const n = name(toks[0]);
      out.data = n;
      out.text = fqdn(n);
      return out;
    }
    case 'MX': {
      exact(2);
      const preference = uint(toks[0], 0xffff, 'preference');
      const exchange = name(toks[1]);
      out.data = { preference, exchange };
      out.text = `${preference} ${fqdn(exchange)}`;
      return out;
    }
    case 'TXT':
    case 'SPF': {
      atLeast(1);
      const strings = [];
      const texts = [];
      for (const tok of toks) {
        const bytes = chars(tok);
        strings.push(decodeUtf8Lenient(bytes));
        texts.push(presentCharString(bytes));
      }
      out.data = strings;
      out.text = texts.join(' ');
      return out;
    }
    case 'SOA': {
      exact(7);
      const mname = name(toks[0]);
      const rname = name(toks[1]);
      const serial = uint(toks[2], MAX_U32, 'serial');
      const refresh = timer(toks[3], 'refresh');
      const retry = timer(toks[4], 'retry');
      const expire = timer(toks[5], 'expire');
      const minimum = timer(toks[6], 'minimum');
      out.data = { mname, rname, serial, refresh, retry, expire, minimum, email: soaEmail(rname) };
      out.text = `${fqdn(mname)} ${fqdn(rname)} ${serial} ${refresh} ${retry} ${expire} ${minimum}`;
      return out;
    }
    case 'SRV': {
      exact(4);
      const priority = uint(toks[0], 0xffff, 'priority');
      const weight = uint(toks[1], 0xffff, 'weight');
      const port = uint(toks[2], 0xffff, 'port');
      const target = name(toks[3]);
      out.data = { priority, weight, port, target };
      out.text = `${priority} ${weight} ${port} ${fqdn(target)}`;
      return out;
    }
    case 'CAA': {
      exact(3);
      const flags = uint(toks[0], 255, 'flags');
      if (!/^[A-Za-z0-9]{1,255}$/.test(toks[1].t)) throw new RdataError('bad-tag');
      const tag = toks[1].t.toLowerCase();
      const bytes = chars(toks[2]);
      out.data = { flags, tag, value: decodeUtf8Lenient(bytes), critical: (flags & 0x80) !== 0 };
      out.text = `${flags} ${tag} ${presentCharString(bytes)}`;
      return out;
    }
    case 'DS':
    case 'CDS': {
      atLeast(4);
      const rr = viaWire(type, {
        keyTag: uint(toks[0], 0xffff, 'key-tag'), algorithm: alg(toks[1]),
        digestType: uint(toks[2], 255, 'digest-type'), digest: hexOf(toks.slice(3), 'digest')
      });
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'DNSKEY':
    case 'CDNSKEY': {
      atLeast(4);
      const rr = viaWire(type, {
        flags: uint(toks[0], 0xffff, 'flags'), protocol: uint(toks[1], 255, 'protocol'),
        algorithm: alg(toks[2]), publicKey: b64(toks.slice(3), 'public-key')
      });
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'TLSA':
    case 'SMIMEA': {
      atLeast(4);
      const rr = viaWire(type, {
        usage: uint(toks[0], 255, 'usage'), selector: uint(toks[1], 255, 'selector'),
        matchingType: uint(toks[2], 255, 'matching-type'), data: hexOf(toks.slice(3), 'association-data')
      });
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'SSHFP': {
      atLeast(3);
      const rr = viaWire(type, {
        algorithm: uint(toks[0], 255, 'algorithm'), fpType: uint(toks[1], 255, 'fp-type'),
        fingerprint: hexOf(toks.slice(2), 'fingerprint')
      });
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'SVCB':
    case 'HTTPS': {
      atLeast(2);
      const priority = uint(toks[0], 0xffff, 'priority');
      const target = name(toks[1]);
      const params = parseSvcParams(toks.slice(2), ctx.base);
      const rr = viaWire(type, { priority, target, params });
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'NAPTR': {
      exact(6);
      const order = uint(toks[0], 0xffff, 'order');
      const preference = uint(toks[1], 0xffff, 'preference');
      const flags = decodeUtf8Lenient(chars(toks[2]));
      const services = decodeUtf8Lenient(chars(toks[3]));
      const regexp = decodeUtf8Lenient(chars(toks[4]));
      const replacement = name(toks[5]);
      const rr = viaWire(type, { order, preference, flags, services, regexp, replacement });
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'URI': {
      exact(3);
      const rr = viaWire(type, {
        priority: uint(toks[0], 0xffff, 'priority'), weight: uint(toks[1], 0xffff, 'weight'),
        target: decodeUtf8Lenient(chars(toks[2]))
      });
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'HINFO': {
      exact(2);
      const rr = viaWire(type, { cpu: decodeUtf8Lenient(chars(toks[0])), os: decodeUtf8Lenient(chars(toks[1])) });
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'RP': {
      exact(2);
      const rr = viaWire(type, null, wireOf([name(toks[0]), name(toks[1])]));
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'AFSDB':
    case 'KX': {
      exact(2);
      const n = uint(toks[0], 0xffff, type === 'KX' ? 'preference' : 'subtype');
      const rr = viaWire(type, null, wireOf([n, name(toks[1])]));
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    case 'OPENPGPKEY': {
      atLeast(1);
      const rr = viaWire(type, null, base64Decode(b64(toks, 'public-key')));
      out.data = rr.data;
      out.text = rr.text;
      return out;
    }
    default:
      return null;
  }
}

/* ------------------------------------------------------------------------ */
/* Cloudflare comments, cli53 routing                                       */
/* ------------------------------------------------------------------------ */

const CF_RESERVED_TAGS = new Set(['cf-proxied', 'cf-flatten-cname']);

/** Comment → { free, found, tags (null-prototype, all tags incl. reserved) }. The LAST ` cf_tags=` wins. */
function splitCfComment(comment) {
  let idx = comment.lastIndexOf('cf_tags=');
  while (idx > 0) {
    const c = comment.charCodeAt(idx - 1);
    if (c === 32 || c === 9) break;
    idx = idx === 0 ? -1 : comment.lastIndexOf('cf_tags=', idx - 1);
  }
  const tags = Object.create(null);
  if (idx < 0) return { free: comment.trim(), found: false, tags };
  const free = comment.slice(0, idx).trim();
  const src = comment.slice(idx + 'cf_tags='.length);
  const n = src.length;
  let p = 0;
  while (p < n) {
    while (p < n && (src[p] === ' ' || src[p] === '\t')) p++;
    let q = p;
    while (q < n && src[q] !== ':' && src[q] !== ',') q++;
    const key = src.slice(p, q).trim();
    let value = '';
    p = q;
    if (p < n && src[p] === ':') {
      p++;
      if (src[p] === '"') {
        let k = p + 1;
        while (k < n && src[k] !== '"') k += src[k] === '\\' ? 2 : 1;
        const raw = src.slice(p, Math.min(k + 1, n));
        try {
          value = JSON.parse(raw);
          if (typeof value !== 'string') value = raw;
        } catch {
          value = raw;
        }
        p = Math.min(k + 1, n);
        while (p < n && src[p] !== ',') p++;
      } else {
        let k = p;
        while (k < n && src[k] !== ',') k++;
        value = src.slice(p, k).trim();
        p = k;
      }
    }
    if (p < n && src[p] === ',') p++;
    if (key) tags[safeText(key, 100)] = safeText(value, 500);
  }
  return { free, found: true, tags };
}

const AWS_POLICY = {
  WEIGHTED: 'weighted', GEOLOCATION: 'geolocation', LATENCY: 'latency', FAILOVER: 'failover',
  MULTIVALUE: 'multivalue', CIDR: 'ip-based', IPBASED: 'ip-based', 'IP-BASED': 'ip-based', GEOPROXIMITY: 'geoproximity'
};

/** cli53 `; AWS routing="WEIGHTED" weight=1 identifier="One"` → routing or null. */
function parseAwsRouting(comment) {
  const m = /^\s*AWS\s+(.*)$/.exec(comment);
  if (!m) return null;
  const kv = Object.create(null);
  for (const x of m[1].matchAll(/([A-Za-z]+)=("(?:[^"\\]|\\.)*"|\S+)/g)) {
    let v = x[2];
    if (v.startsWith('"')) {
      try {
        v = JSON.parse(v);
      } catch {
        v = v.slice(1, -1);
      }
    }
    kv[x[1]] = String(v);
  }
  if (!kv.routing) return null;
  const routing = { policy: AWS_POLICY[kv.routing.toUpperCase()] || 'unknown', id: kv.identifier !== undefined ? safeText(kv.identifier, 200) : null };
  if (kv.weight !== undefined && /^\d+$/.test(kv.weight)) routing.weight = Number(kv.weight);
  if (kv.continentCode !== undefined || kv.countryCode !== undefined || kv.subdivisionCode !== undefined) {
    routing.geo = geoOf({ ContinentCode: kv.continentCode, CountryCode: kv.countryCode, SubdivisionCode: kv.subdivisionCode });
  }
  if (kv.region !== undefined) routing.region = safeText(kv.region, 60);
  if (kv.failover !== undefined) routing.failover = safeText(kv.failover.toUpperCase(), 20);
  if (kv.healthCheckId !== undefined) routing.healthCheck = safeText(kv.healthCheckId, 100);
  return routing;
}

function geoOf(g) {
  const out = {};
  const c = own(g, 'ContinentCode');
  const k = own(g, 'CountryCode');
  const s = own(g, 'SubdivisionCode');
  if (typeof c === 'string') out.continentCode = safeText(c, 10);
  if (typeof k === 'string') out.countryCode = safeText(k, 10);
  if (typeof s === 'string') out.subdivisionCode = safeText(s, 10);
  return out;
}

/* ------------------------------------------------------------------------ */
/* Record building (shared by every format)                                 */
/* ------------------------------------------------------------------------ */

const REC_KEYS = ['id', 'name', 'intendedName', 'type', 'ttl', 'ttlAuto', 'data', 'text', 'targets', 'intendedTargets',
  'proxied', 'proxiable', 'flattenCname', 'alias', 'routing', 'occludedBy', 'invalid', 'unsupported', 'generated',
  'duplicateOf', 'comment', 'tags', 'line', 'source'];

class Builder {
  constructor(L, source, issues) {
    this.L = L;
    this.source = source;
    this.issues = issues;
    this.records = [];
    this.relTargets = [];
    this.truncated = false;
    this.skipped = 0;
    this.generated = 0;
    this.entries = 0;
  }

  /** True when no further record may be added (raises RECORDS_TRUNCATED once). */
  full(line) {
    if (this.records.length < this.L.maxRecords) return false;
    if (!this.truncated) {
      this.truncated = true;
      this.issues.add('RECORDS_TRUNCATED', line, { max: this.L.maxRecords, unit: 'records' }, `only the first ${this.L.maxRecords} records are kept`);
    }
    return true;
  }

  /** Start a record (fields filled by the caller, finalized later). */
  make(name, type, line) {
    return { name, type, ttl: null, data: null, text: '', targets: [], proxied: null, line, source: this.source };
  }

  /**
   * Fill data/text/targets of `rec` from RDATA tokens, reporting BAD_RDATA / RDATA_UNPARSED.
   * @returns {boolean} false when the RDATA was invalid (the record is still kept)
   */
  fillRdata(rec, toks, ctx, line) {
    let res;
    try {
      res = parseRdata(rec.type, toks, ctx);
    } catch (err) {
      if (!(err instanceof RdataError)) throw err;
      rec.invalid = true;
      rec.text = rawText(toks);
      const reason = err.reason === 'relative-without-origin' ? 'relative-without-origin' : err.reason;
      this.issues.add('BAD_RDATA', line, { type: rec.type, reason }, `invalid ${rec.type} RDATA (${reason})`, { name: rec.name, type: rec.type });
      return false;
    }
    if (res === null) {
      rec.unsupported = true;
      rec.text = rawText(toks);
      this.issues.addOnce(`unparsed:${rec.type}`, 'RDATA_UNPARSED', line, { type: rec.type }, `${rec.type} RDATA kept as text`, { name: rec.name, type: rec.type });
      return true;
    }
    rec.data = res.data;
    rec.text = res.text;
    rec.targets = res.targets;
    for (const a of res.atNames) {
      this.issues.add('AT_INSIDE_NAME', line, { name: a.name, raw: safeText(a.raw, 80) }, '"x.@" read as a name below the origin', { name: rec.name, type: rec.type });
    }
    if (res.idn) this.issues.add('NON_ASCII_LABEL', line, { name: rec.name }, 'non-ASCII label converted to punycode', { name: rec.name, type: rec.type });
    for (const r of res.rel) this.relTargets.push({ rec, ...r });
    return true;
  }

  /** TXT/SPF data from literal byte strings (JSON / YAML / Plesk values). */
  fillTxt(rec, byteStrings) {
    rec.data = byteStrings.map(decodeUtf8Lenient);
    rec.text = byteStrings.map(presentCharString).join(' ');
  }

  push(rec) {
    this.records.push(rec);
    if (rec.generated) this.generated++;
  }
}

function applyTtl(rec, value, issues, line) {
  if (value > MAX_TTL) {
    issues.add('BAD_TTL', line, { ttl: value, max: MAX_TTL }, 'TTL above 2^31-1 treated as 0', { name: rec.name, type: rec.type });
    rec.ttl = 0;
    return false;
  }
  rec.ttl = value;
  return true;
}

/** Final record objects: ids, canonical key order, `duplicateOf`. */
function finalizeRecords(raw) {
  const firstByKey = new Map();
  return raw.map((r, id) => {
    const out = {};
    for (const k of REC_KEYS) {
      if (k === 'id') out.id = id;
      else if (r[k] !== undefined) out[k] = r[k];
    }
    const dataKey = r.alias ? `alias:${r.alias.target}` : r.data !== null ? `=${rdataKey(r.type, r.data)}` : `!${r.text}`;
    const key = `${r.name}|${r.type}|${r.routing ? r.routing.id ?? '' : ''}|${dataKey}`;
    const first = firstByKey.get(key);
    if (first === undefined) firstByKey.set(key, id);
    else {
      const withDup = {};
      for (const k of REC_KEYS) {
        if (k === 'duplicateOf') withDup.duplicateOf = first;
        else if (out[k] !== undefined) withDup[k] = out[k];
      }
      return withDup;
    }
    return out;
  });
}

/* ------------------------------------------------------------------------ */
/* Zone skeleton                                                            */
/* ------------------------------------------------------------------------ */

function newZone({ filename, bytes }) {
  return {
    format: null,
    dialect: null,
    markers: [],
    origin: null,
    originSource: null,
    originConfidence: 'low',
    records: [],
    warnings: [],
    fatal: null,
    partial: false,
    sources: [{ name: typeof filename === 'string' ? filename : '', size: bytes, format: null, dialect: null }],
    stats: { bytes, lines: 0, entries: 0, records: 0, skipped: 0, generated: 0, proxied: 0, dnsOnly: 0, byType: {}, elapsedMs: 0 },
    defaultTtl: null,
    changeBatch: null
  };
}

function failZone(zone, fatal) {
  zone.fatal = fatal;
  zone.records = [];
  zone.warnings = [];
  zone.partial = false;
  return zone;
}

/* ------------------------------------------------------------------------ */
/* BIND                                                                     */
/* ------------------------------------------------------------------------ */

/** owner / ttl / class / type layout of one entry. */
function splitStructure(tokens, blank) {
  let k = 0;
  const owner = blank ? null : tokens[k++];
  let ttlTok = null;
  let cls = null;
  for (let n = 0; n < 2 && k < tokens.length; n++) {
    const t = tokens[k];
    if (t.q) break;
    if (ttlTok === null && parseTtlValue(t.t) !== null) {
      ttlTok = t;
      k++;
      continue;
    }
    const c = cls === null ? classOf(t.t) : null;
    if (c) {
      cls = c;
      k++;
      continue;
    }
    break;
  }
  const typeTok = tokens[k];
  const type = typeTok && !typeTok.q ? typeOf(typeTok.t) : null;
  return { owner, ttlTok, cls, type, typeTok, rdataIndex: k + 1 };
}

function isDirective(e) {
  return !e.blank && !e.tokens[0].q && e.tokens[0].t.charCodeAt(0) === 0x24;
}

/** Substitute `$` / `$$` / `\$` of a $GENERATE template. */
function generateSubst(tpl, i) {
  let out = '';
  for (let k = 0; k < tpl.length; k++) {
    const c = tpl[k];
    if (c === '\\' && tpl[k + 1] === '$') {
      out += '$';
      k++;
    } else if (c === '$') {
      if (tpl[k + 1] === '$') {
        out += '$';
        k++;
      } else out += String(i);
    } else out += c;
  }
  return out;
}

function gateHint(text) {
  const lines = contentLines(text, 200);
  const samples = lines.slice(0, 3).map((l) => safeText(l, 80));
  if (!lines.length) return { hint: 'unknown', samples };
  const csv = csvHint(lines[0]);
  if (csv) return { hint: csv, samples };
  let inventory = 0;
  let names = 0;
  for (const l of lines) {
    const parts = l.split(/\s+/);
    if ((parts.length >= 2 && normalizeIP(parts[1])) || (parts.length === 1 && normalizeIP(parts[0]))) inventory++;
    else if (parts.length === 1 && normalizeHostname(parts[0], { allowWildcard: true })) names++;
  }
  if (inventory * 2 >= lines.length) return { hint: 'inventory', samples };
  if (names * 2 >= lines.length) return { hint: 'names', samples };
  return { hint: 'unknown', samples };
}

function parseBind(text, lines, zone, b, opts) {
  const { L, issues } = b;
  const dialect = zone.dialect;
  const entries = tokenizeMaster(lines, {
    limits: L,
    onIssue: (code, line, params, detail) => {
      if (code === 'RECORDS_TRUNCATED') zone.partial = true;
      issues.add(code, line, params, detail);
    }
  });

  // ---- pre-scan: owners, SOA, $ORIGIN (origin inference and the TTL fallback) ----
  // Only a `$ORIGIN` before the first record names the zone (`leadOrigin`); a later one opens a
  // sub-block (`$ORIGIN lab.example.com.`, an SRV block) and names it only as a last resort
  // (`lateOrigin`). `$ORIGIN .` (BIND secondary / named-compilezone / pdnsutil dumps) is never the
  // apex: undotted owners under it are absolute, so the SOA owner names the zone.
  const header = headerOrigin(text);
  let scanOrigin = header;
  let sawRecord = false;
  let leadOrigin = null;
  let leadOriginLine = 0;
  let lateOrigin = null;
  let lateOriginLine = 0;
  let soaAbs = null;
  let soaRaw = null;
  let soaMinimum = null;
  const absOwners = new Set();
  const nsOwners = [];
  for (const e of entries) {
    if (isDirective(e)) {
      const d = e.tokens[0].t.toUpperCase();
      if (d === '$ORIGIN' && e.tokens[1]) {
        const r = parseName(e.tokens[1].t, { origin: scanOrigin });
        if (r.ok) scanOrigin = r.name;
        if (r.ok && !r.relative && r.name !== '.') {
          if (!sawRecord && leadOrigin === null) {
            leadOrigin = r.name;
            leadOriginLine = e.line;
          }
          if (lateOrigin === null) {
            lateOrigin = r.name;
            lateOriginLine = e.line;
          }
        }
      } else if (d === '$GENERATE') sawRecord = true;
      continue;
    }
    const s = splitStructure(e.tokens, e.blank);
    if (!s.type) continue;
    sawRecord = true;
    let absOwner = null;
    if (s.owner && !s.owner.q) {
      const t = s.owner.t;
      if (t.endsWith('.') && !isEscapedAt(t, t.length - 1)) {
        const r = parseName(t);
        if (r.ok) absOwner = r.name;
      } else if (scanOrigin === '.') {
        const r = parseName(t, { origin: '.' });
        if (r.ok && !r.at) absOwner = r.name;
      }
    }
    if (absOwner && s.cls !== 'CH' && s.cls !== 'HS' && s.cls !== 'CS') {
      absOwners.add(absOwner);
      if (s.type === 'NS') nsOwners.push(absOwner);
    }
    if (s.type === 'SOA' && soaRaw === null && s.owner) {
      soaRaw = s.owner.t;
      if (absOwner) soaAbs = absOwner;
      const minTok = e.tokens[s.rdataIndex + 6];
      const v = minTok ? parseTtlValue(minTok.t) : null;
      if (v !== null && v <= MAX_TTL) soaMinimum = v;
    }
  }

  // ---- origin ----
  const user = opts.userOrigin;
  let initial = null;
  let soaApex = null; // an undotted SOA owner read as the apex
  const undottedSoa = () => {
    if (!soaRaw || soaRaw === '@' || (soaRaw.endsWith('.') && !isEscapedAt(soaRaw, soaRaw.length - 1))) return null;
    const r = parseName(`${soaRaw}.`);
    return r.ok && r.relLabels >= 2 ? r.name : null;
  };
  if (user) {
    zone.origin = user;
    zone.originSource = 'user';
    zone.originConfidence = 'high';
    initial = user;
    // a late $ORIGIN at or below the typed zone is a sub-block, not a disagreement
    const lateSays = lateOrigin && !isSubdomainOf(lateOrigin, user) ? lateOrigin : null;
    const fileSays = leadOrigin || soaAbs || header || lateSays;
    if (fileSays && fileSays !== user) {
      const line = fileSays === leadOrigin ? leadOriginLine : fileSays === lateSays ? lateOriginLine : 0;
      issues.add('ORIGIN_OVERRIDDEN', line, { user, file: fileSays }, 'the file names another origin');
    }
  } else if (leadOrigin) {
    zone.origin = leadOrigin;
    zone.originSource = '$ORIGIN';
    zone.originConfidence = 'high';
    initial = header;
  } else if (header) {
    zone.origin = header;
    zone.originSource = 'header';
    zone.originConfidence = 'high';
    initial = header;
  } else if (undottedSoa()) {
    soaApex = undottedSoa();
    zone.origin = soaApex;
    zone.originSource = 'soa';
    zone.originConfidence = 'high';
    initial = soaApex;
  } else {
    const cand = apexCandidate({ soa: soaAbs, ns: nsOwners, owners: [...absOwners] });
    const fromFile = inferOriginFromFilename(opts.filename);
    if (fromFile) {
      if (cand && cand.strong && cand.name !== fromFile) {
        issues.add('ORIGIN_CORRECTED', 0, { from: fromFile, to: cand.name }, 'the file name disagrees with the SOA/NS owner; the owner wins');
        zone.origin = cand.name;
        zone.originSource = cand.source;
        zone.originConfidence = 'high';
      } else {
        zone.origin = fromFile;
        zone.originSource = 'filename';
        zone.originConfidence = cand && cand.strong && cand.name === fromFile ? 'high' : 'low';
      }
    } else if (cand) {
      zone.origin = cand.name;
      zone.originSource = cand.source;
      zone.originConfidence = cand.strong ? 'high' : 'low';
    }
    initial = zone.origin;
    // a late $ORIGIN outside a mere guess (a file name like `example.com.backup.txt`, or one
    // deep record owner) names the zone better
    const guessOnly = zone.originConfidence === 'low';
    if (lateOrigin && (!zone.origin || (guessOnly && !isSubdomainOf(lateOrigin, zone.origin)))) {
      // records before it stay RELATIVE_WITHOUT_ORIGIN; the UI asks the user to confirm
      zone.origin = lateOrigin;
      zone.originSource = '$ORIGIN';
      zone.originConfidence = 'low';
      initial = null;
    }
  }
  if (zone.origin && zone.originSource !== 'user' && zone.originSource !== '$ORIGIN') {
    issues.add('ORIGIN_INFERRED', 0, { origin: zone.origin, source: zone.originSource }, `origin ${zone.origin} from ${zone.originSource}`);
  }
  if (dialect === 'cloudflare' && !text.includes('cf_tags=')) {
    issues.add('NO_PROXY_FLAGS', 0, {}, 'Cloudflare export without cf_tags: proxy status unknown');
  }

  // ---- main pass ----
  const st = {
    origin: initial, lastOwner: null, defaultTtl: opts.defaultTtl, lastTtl: null, soaMinimum,
    genTotal: 0, relFail: 0, structural: 0
  };
  const ctxFor = () => ({ origin: st.origin, base: 10, absolute: false });

  const handleRecord = (e, generated) => {
    const s = splitStructure(e.tokens, e.blank);
    if (!s.type) {
      issues.add('UNPARSED_LINE', e.line, { snippet: safeText(rawText(e.tokens), 80) }, `cannot read: ${safeText(rawText(e.tokens), 80)}`);
      b.skipped++;
      return;
    }
    st.structural++;
    const type = s.type;
    if (s.cls === 'AWS' && type !== 'ALIAS') {
      issues.add('UNPARSED_LINE', e.line, { snippet: safeText(rawText(e.tokens), 80) }, 'class AWS is only valid with ALIAS');
      b.skipped++;
      return;
    }
    // owner
    let owner;
    if (!s.owner) {
      if (!st.lastOwner) {
        issues.add('NO_OWNER', e.line, {}, 'blank owner before any owner');
        b.skipped++;
        return;
      }
      owner = st.lastOwner;
    } else {
      const raw = s.owner.t;
      const undotted = type === 'SOA' && raw !== '@' && !(raw.endsWith('.') && !isEscapedAt(raw, raw.length - 1));
      const lowerRaw = undotted ? parseName(`${raw}.`) : null;
      if (type === 'SOA' && undotted && lowerRaw && lowerRaw.ok &&
          ((dialect === 'cloudflare' && lowerRaw.name === zone.origin) || (soaApex && lowerRaw.name === soaApex))) {
        owner = { name: lowerRaw.name };
        if (dialect === 'cloudflare') issues.add('CF_SOA_OWNER_UNDOTTED', e.line, { name: lowerRaw.name }, 'undotted SOA owner read as the apex', { name: lowerRaw.name, type });
      } else {
        const r = parseName(raw, ctxFor());
        if (!r.ok) {
          if (r.reason === 'no-origin') {
            st.relFail++;
            issues.add('RELATIVE_WITHOUT_ORIGIN', e.line, { name: safeText(raw, 80) }, 'relative name and no origin', { type });
          } else {
            issues.add('BAD_NAME', e.line, { name: safeText(raw, 80), reason: r.reason }, `invalid owner name (${r.reason})`, { type });
          }
          b.skipped++;
          return;
        }
        owner = { name: r.name };
        if (r.at) issues.add('AT_INSIDE_NAME', e.line, { name: r.name, raw: safeText(raw, 80) }, '"x.@" read as a name below the origin', { name: r.name, type });
        if (r.idn) issues.add('NON_ASCII_LABEL', e.line, { name: r.name }, 'non-ASCII label converted to punycode', { name: r.name, type });
        if (r.relative && !r.apex && !r.at && r.name !== r.rel) {
          const bases = [st.origin, zone.origin].filter((o) => o && o !== '.');
          if (bases.some((o) => r.rel === o || r.rel.endsWith(`.${o}`))) {
            owner.intendedName = r.rel;
            issues.add('OWNER_MISSING_TRAILING_DOT', e.line, { name: r.name, intended: r.rel }, `owner "${r.rel}" has no trailing dot: served as ${r.name}`, { name: r.name, type });
          }
        }
      }
      st.lastOwner = owner;
    }
    // class
    if (s.cls && s.cls !== 'IN' && s.cls !== 'AWS') {
      issues.add('NON_IN_CLASS', e.line, { class: s.cls }, `${s.cls} record ignored`, { name: owner.name, type });
      b.skipped++;
      return;
    }
    if (b.full(e.line)) return;
    const rdata = e.tokens.slice(s.rdataIndex);
    // cli53 alias
    if (s.cls === 'AWS') {
      const aType = rdata[0] ? typeOf(rdata[0].t) : null;
      const tgt = rdata[1] ? parseName(rdata[1].t, ctxFor()) : null;
      if (!aType || !tgt || !tgt.ok || rdata.length > 4) {
        issues.add('BAD_RDATA', e.line, { type: 'ALIAS', reason: 'alias' }, 'invalid cli53 ALIAS', { name: owner.name, type: 'ALIAS' });
        b.skipped++;
        return;
      }
      const zoneId = rdata[2] ? rdata[2].t : null;
      const self = zoneId === '$self';
      const rec = b.make(owner.name, aType, e.line);
      if (owner.intendedName) rec.intendedName = owner.intendedName;
      rec.alias = {
        target: tgt.name,
        zoneId: self || zoneId === null ? null : safeText(zoneId, 100),
        evaluateTargetHealth: rdata[3] ? rdata[3].t.toLowerCase() === 'true' : false,
        provider: awsAliasProvider(tgt.name, { origin: zone.origin, self })
      };
      applyComment(rec, e.comment, b, e.line);
      if (generated) rec.generated = true;
      b.push(rec);
      return;
    }
    const rec = b.make(owner.name, type, e.line);
    if (owner.intendedName) rec.intendedName = owner.intendedName;
    // TTL
    if (s.ttlTok) {
      const v = parseTtlValue(s.ttlTok.t);
      if (applyTtl(rec, v, issues, e.line)) st.lastTtl = v;
    } else if (st.defaultTtl !== null && st.defaultTtl !== undefined) rec.ttl = st.defaultTtl;
    else if (st.lastTtl !== null) rec.ttl = st.lastTtl;
    else if (st.soaMinimum !== null) {
      rec.ttl = st.soaMinimum;
      issues.addOnce('ttl-defaulted', 'TTL_DEFAULTED', e.line, { ttl: st.soaMinimum }, 'no $TTL: SOA minimum used as the default TTL');
    }
    if (dialect === 'cloudflare' && rec.ttl === 1) {
      rec.ttl = 300;
      rec.ttlAuto = true;
    }
    b.fillRdata(rec, rdata, ctxFor(), e.line);
    applyComment(rec, e.comment, b, e.line);
    if (generated) rec.generated = true;
    b.push(rec);
  };

  const handleGenerate = (e) => {
    const toks = e.tokens;
    const range = toks[1] ? toks[1].t : '';
    const lhs = toks[2] ? toks[2].t : '';
    const rest = toks.slice(3);
    const all = [lhs, ...rest.map((t) => t.t)].join(' ');
    const m = /^(\d{1,9})-(\d{1,9})(?:\/(\d{1,9}))?$/.exec(range);
    if (!m || !lhs || !rest.length || all.includes('${')) {
      issues.add('GENERATE_UNSUPPORTED', e.line, { range: safeText(range, 40) }, '$GENERATE form not supported');
      return;
    }
    const a = Number(m[1]);
    const z = Number(m[2]);
    const step = m[3] ? Number(m[3]) : 1;
    if (z < a || step < 1) {
      issues.add('GENERATE_UNSUPPORTED', e.line, { range: safeText(range, 40) }, 'invalid $GENERATE range');
      return;
    }
    const count = Math.floor((z - a) / step) + 1;
    if (count > L.maxGenerate || st.genTotal + count > L.maxGenerateTotal) {
      issues.add('GENERATE_TOO_LARGE', e.line, { count, max: count > L.maxGenerate ? L.maxGenerate : L.maxGenerateTotal }, '$GENERATE range too large');
      return;
    }
    st.genTotal += count;
    let made = 0;
    for (let i = a; i <= z; i += step) {
      if (b.full(e.line)) break;
      const before = b.records.length;
      handleRecord({
        line: e.line, blank: false, comment: e.comment,
        tokens: [{ t: generateSubst(lhs, i), q: false }, ...rest.map((t) => ({ t: generateSubst(t.t, i), q: t.q }))]
      }, true);
      made += b.records.length - before;
    }
    issues.add('GENERATE_EXPANDED', e.line, { count: made, range: safeText(range, 40) }, `$GENERATE expanded to ${made} record(s)`);
  };

  for (const e of entries) {
    if (b.truncated) break;
    if (isDirective(e)) {
      const d = e.tokens[0].t.toUpperCase();
      const arg = e.tokens[1];
      if (d === '$ORIGIN') {
        const r = arg ? parseName(arg.t, ctxFor()) : { ok: false, reason: 'empty' };
        if (r.ok) st.origin = r.name;
        else if (r.reason === 'no-origin') issues.add('RELATIVE_WITHOUT_ORIGIN', e.line, { name: safeText(arg.t, 80) }, 'relative $ORIGIN and no origin');
        else issues.add('BAD_NAME', e.line, { name: safeText(arg ? arg.t : '', 80), reason: r.reason }, 'invalid $ORIGIN');
      } else if (d === '$TTL') {
        const v = arg ? parseTtlValue(arg.t) : null;
        if (v === null || v > MAX_TTL) issues.add('BAD_TTL', e.line, { ttl: arg ? safeText(arg.t, 40) : '', max: MAX_TTL, directive: true }, 'invalid $TTL ignored');
        else st.defaultTtl = v;
      } else if (d === '$INCLUDE') {
        // `at`: the origin the included file is read under (RFC 1035 §5.1: its argument, else the current one)
        const oTok = e.tokens[2];
        const r = oTok ? parseName(oTok.t, ctxFor()) : null;
        const at = oTok ? (r.ok ? r.name : null) : st.origin;
        issues.add('INCLUDE_REJECTED', e.line, {
          path: safeText(arg ? arg.t : '', 200), origin: oTok ? safeText(oTok.t, 200) : null, at: at === '.' ? null : at
        }, '$INCLUDE cannot be followed in the browser');
      } else if (d === '$GENERATE') {
        handleGenerate(e);
      } else {
        issues.add('UNKNOWN_DIRECTIVE', e.line, { directive: safeText(e.tokens[0].t, 40) }, 'unknown directive ignored');
      }
      continue;
    }
    b.entries++;
    if (e.overflow) {
      issues.add('BAD_RDATA', e.line, { type: '', reason: 'too-many-tokens' }, 'entry has too many tokens');
      b.skipped++;
      continue;
    }
    handleRecord(e, false);
  }
  zone.defaultTtl = st.defaultTtl ?? null;

  // dig AXFR prints the SOA again at the end
  if (zone.markers.includes('dig AXFR') && b.records.length >= 2) {
    const last = b.records[b.records.length - 1];
    const firstSoa = b.records.find((r) => r.type === 'SOA');
    if (last.type === 'SOA' && firstSoa !== last && firstSoa.name === last.name && firstSoa.text === last.text) b.records.pop();
  }

  // ---- whole-file verdicts ----
  const E = b.entries;
  const R = st.structural;
  if (!zone.origin && b.records.length === 0 && st.relFail > 0) {
    return { fatal: fatalIssue('ORIGIN_REQUIRED', { relative: st.relFail }, 'relative names and no origin') };
  }
  if ((E >= 3 && R / E < 0.3) || (E < 3 && R === 0)) {
    const g = gateHint(text);
    return { fatal: fatalIssue('NOT_A_ZONE', g, 'not a DNS zone') };
  }
  return { fatal: null };
}

/** Cloudflare tags / cli53 routing / free comment of a BIND record. */
function applyComment(rec, comment, b, line) {
  if (!comment) return;
  const routing = parseAwsRouting(comment);
  if (routing) {
    rec.routing = routing;
    return;
  }
  const cf = splitCfComment(comment);
  if (cf.found) {
    const proxied = cf.tags['cf-proxied'];
    if (proxied === 'true' || proxied === 'false') {
      if (PROXIABLE.has(rec.type) && !rec.alias) rec.proxied = proxied === 'true';
      else b.issues.addOnce(`proxy-ignored:${rec.type}`, 'PROXY_FLAG_IGNORED', line, { type: rec.type }, `cf-proxied ignored on ${rec.type}`, { name: rec.name, type: rec.type });
    }
    if ('cf-flatten-cname' in cf.tags && rec.type === 'CNAME') rec.flattenCname = true;
    const tags = Object.create(null);
    let n = 0;
    for (const k of Object.keys(cf.tags)) {
      if (CF_RESERVED_TAGS.has(k)) continue;
      tags[k] = cf.tags[k];
      n++;
    }
    if (n) rec.tags = tags;
  }
  if (cf.free) rec.comment = safeText(cf.free, b.L.maxCommentChars);
}

/* ------------------------------------------------------------------------ */
/* Cloudflare API JSON                                                      */
/* ------------------------------------------------------------------------ */

function jsonTtl(rec, v, b, line, { cloudflare = false } = {}) {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) return;
  if (cloudflare && v === 1) {
    rec.ttl = 300;
    rec.ttlAuto = true;
    return;
  }
  applyTtl(rec, v, b.issues, line);
}

function parseCloudflareApi(docs, zone, b, opts) {
  const { issues } = b;
  const items = [];
  const seen = new Set();
  let duplicates = 0;
  let totalCount = null;
  let totalPages = null;
  let pages = 0;
  let zoneName = null;
  for (const d of docs) {
    const v = d.value;
    if (jsonKind(v) === 'cf-error') {
      const errs = own(v, 'errors');
      const e0 = Array.isArray(errs) && isPlainMap(errs[0]) ? errs[0] : null;
      const msg = e0 && typeof own(e0, 'message') === 'string' ? own(e0, 'message') : '';
      const code = e0 && typeof own(e0, 'code') === 'number' ? own(e0, 'code') : null;
      return { fatal: fatalIssue('API_ERROR', { message: safeText(msg, 200), code }, 'the pasted API response is an error') };
    }
    pages++;
    let list;
    if (Array.isArray(v)) list = v;
    else if (Array.isArray(own(v, 'result'))) list = own(v, 'result');
    else list = [v];
    const info = own(v, 'result_info');
    if (isPlainMap(info)) {
      const tc = own(info, 'total_count');
      const tp = own(info, 'total_pages');
      if (typeof tc === 'number') totalCount = Math.max(totalCount ?? 0, tc);
      if (typeof tp === 'number') totalPages = Math.max(totalPages ?? 0, tp);
    }
    for (const item of list) {
      const id = own(item, 'id');
      if (typeof id === 'string') {
        if (seen.has(id)) {
          duplicates++;
          continue;
        }
        seen.add(id);
      }
      items.push(item);
      if (zoneName === null && typeof own(item, 'zone_name') === 'string') zoneName = own(item, 'zone_name');
    }
  }
  if (docs.length > 1 || duplicates) {
    issues.add('JSON_PAGES_MERGED', 0, { pages: docs.length, duplicates }, `${docs.length} pasted page(s) merged`);
  }
  if (!items.length) return { fatal: fatalIssue('EMPTY', {}, 'no DNS records in the response') };
  if ((totalCount !== null && totalCount > items.length) || (totalPages !== null && totalPages > pages)) {
    zone.partial = true;
    issues.add('PARTIAL_EXPORT', 0, { have: items.length, total: totalCount, pages, totalPages, provider: 'cloudflare' }, 'only part of the records was pasted');
  }
  // origin
  const owners = [];
  let soa = null;
  const ns = [];
  for (const item of items) {
    const n = own(item, 'name');
    const t = own(item, 'type');
    if (typeof n !== 'string') continue;
    const r = parseName(n, { absolute: true });
    if (!r.ok) continue;
    owners.push(r.name);
    if (t === 'SOA' && !soa) soa = r.name;
    if (t === 'NS') ns.push(r.name);
  }
  setJsonOrigin(zone, issues, opts, { explicit: zoneName, explicitSource: 'header', soa, ns, owners });
  b.entries = items.length;
  items.forEach((item, idx) => {
    if (b.full(idx + 1)) return;
    buildCfRecord(item, idx + 1, zone, b);
  });
  return { fatal: null };
}

function setJsonOrigin(zone, issues, opts, { explicit, explicitSource, soa, ns, owners }) {
  let fileSays = null;
  if (typeof explicit === 'string') {
    const r = parseName(explicit, { absolute: true });
    if (r.ok) fileSays = r.name;
  }
  if (opts.userOrigin) {
    zone.origin = opts.userOrigin;
    zone.originSource = 'user';
    zone.originConfidence = 'high';
    const other = fileSays || soa;
    if (other && other !== opts.userOrigin) issues.add('ORIGIN_OVERRIDDEN', 0, { user: opts.userOrigin, file: other }, 'the file names another origin');
    return;
  }
  if (fileSays) {
    zone.origin = fileSays;
    zone.originSource = explicitSource;
    zone.originConfidence = 'high';
  } else {
    const cand = apexCandidate({ soa, ns, owners });
    if (cand) {
      zone.origin = cand.name;
      zone.originSource = cand.source;
      zone.originConfidence = cand.strong ? 'high' : 'low';
    }
  }
  if (zone.origin) issues.add('ORIGIN_INFERRED', 0, { origin: zone.origin, source: zone.originSource }, `origin ${zone.origin} from ${zone.originSource}`);
}

function badRecord(b, line, reason) {
  b.issues.add('BAD_RECORD', line, { index: line - 1, reason }, `record #${line} skipped (${reason})`);
  b.skipped++;
}

function buildCfRecord(item, line, zone, b) {
  if (!isPlainMap(item)) return badRecord(b, line, 'not-an-object');
  const nameRaw = own(item, 'name');
  const typeRaw = own(item, 'type');
  if (typeof nameRaw !== 'string' || typeof typeRaw !== 'string') return badRecord(b, line, 'name-or-type');
  const type = typeOf(typeRaw);
  if (!type) return badRecord(b, line, 'type');
  const nr = parseName(nameRaw, { absolute: true });
  if (!nr.ok) {
    b.issues.add('BAD_NAME', line, { name: safeText(nameRaw, 80), reason: nr.reason }, `invalid name (${nr.reason})`, { type });
    b.skipped++;
    return;
  }
  const rec = b.make(nr.name, type, line);
  jsonTtl(rec, own(item, 'ttl'), b, line, { cloudflare: true });
  const content = own(item, 'content');
  const data = own(item, 'data');
  const ctx = { origin: null, base: 10, absolute: true };
  let toks;
  if (type === 'TXT' || type === 'SPF') {
    const s = typeof content === 'string' ? content : '';
    if (s.trim().startsWith('"')) toks = splitValueTokens(s);
    else {
      b.fillTxt(rec, split255(utf8Encoder.encode(s)));
      toks = undefined;
    }
  } else if (type === 'MX') {
    const prio = typeof own(item, 'priority') === 'number' ? own(item, 'priority') : own(data, 'priority');
    const parts = typeof content === 'string' ? splitValueTokens(content) : null;
    if (parts && parts.length === 2) toks = parts;
    else if (parts && parts.length === 1 && typeof prio === 'number') toks = [{ t: String(prio), q: false }, parts[0]];
    else toks = parts && parts.length === 1 ? parts : [];
  } else if (type === 'SRV' && isPlainMap(data) && typeof own(data, 'target') === 'string') {
    toks = ['priority', 'weight', 'port'].map((k) => ({ t: String(own(data, k)), q: false }));
    toks.push({ t: own(data, 'target'), q: false });
  } else if (type === 'SRV') {
    const parts = typeof content === 'string' ? splitValueTokens(content) : null;
    const prio = own(item, 'priority');
    toks = parts && parts.length === 3 && typeof prio === 'number' ? [{ t: String(prio), q: false }, ...parts] : parts || [];
  } else if (type === 'CAA' && isPlainMap(data) && typeof own(data, 'tag') === 'string') {
    toks = [{ t: String(own(data, 'flags') ?? 0), q: false }, { t: own(data, 'tag'), q: false }, rawToken(String(own(data, 'value') ?? ''))];
  } else {
    toks = typeof content === 'string' ? splitValueTokens(content) : [];
  }
  if (toks === null) {
    rec.invalid = true;
    rec.text = typeof content === 'string' ? safeText(content, 2000) : '';
    b.issues.add('BAD_RDATA', line, { type, reason: 'unterminated-quote' }, 'unterminated quote', { name: rec.name, type });
  } else if (toks !== undefined) {
    b.fillRdata(rec, toks, ctx, line);
  }
  const proxiable = own(item, 'proxiable');
  if (typeof proxiable === 'boolean') rec.proxiable = proxiable;
  if (PROXIABLE.has(type) && proxiable !== false) rec.proxied = own(item, 'proxied') === true;
  const settings = own(item, 'settings');
  if (type === 'CNAME' && own(settings, 'flatten_cname') === true) rec.flattenCname = true;
  const shadow = own(own(item, 'meta'), 'shadowed_by');
  if (Array.isArray(shadow) && shadow.length) rec.occludedBy = 'delegation';
  const comment = own(item, 'comment');
  if (typeof comment === 'string' && comment.trim()) rec.comment = safeText(comment.trim(), b.L.maxCommentChars);
  const tagsRaw = own(item, 'tags');
  if (Array.isArray(tagsRaw)) {
    const tags = Object.create(null);
    let n = 0;
    for (const t of tagsRaw) {
      if (typeof t !== 'string' || !t) continue;
      const c = t.indexOf(':');
      const k = safeText(c < 0 ? t : t.slice(0, c), 100);
      tags[k] = safeText(c < 0 ? '' : t.slice(c + 1), 500);
      n++;
    }
    if (n) rec.tags = tags;
  }
  b.push(rec);
}

/* ------------------------------------------------------------------------ */
/* Route 53 JSON                                                            */
/* ------------------------------------------------------------------------ */

function r53Routing(set) {
  const id = own(set, 'SetIdentifier');
  if (typeof id !== 'string') return undefined;
  const r = { policy: 'unknown', id: safeText(id, 200) };
  const w = own(set, 'Weight');
  const geo = own(set, 'GeoLocation');
  const region = own(set, 'Region');
  const fo = own(set, 'Failover');
  if (typeof w === 'number') {
    r.policy = 'weighted';
    r.weight = w;
  } else if (isPlainMap(geo)) {
    r.policy = 'geolocation';
    r.geo = geoOf(geo);
  } else if (typeof region === 'string') {
    r.policy = 'latency';
    r.region = safeText(region, 60);
  } else if (typeof fo === 'string') {
    r.policy = 'failover';
    r.failover = safeText(fo.toUpperCase(), 20);
  } else if (own(set, 'MultiValueAnswer') === true) r.policy = 'multivalue';
  else if (isPlainMap(own(set, 'CidrRoutingConfig'))) r.policy = 'ip-based';
  else if (isPlainMap(own(set, 'GeoProximityLocation'))) r.policy = 'geoproximity';
  const hc = own(set, 'HealthCheckId');
  if (typeof hc === 'string') r.healthCheck = safeText(hc, 100);
  return r;
}

/**
 * What a DELETE of a change batch takes away: its name, type and SetIdentifier; null when its set
 * is not one (no Name or Type, a name that is not one).
 */
function changeDelete(set) {
  const nameRaw = own(set, 'Name');
  const typeRaw = own(set, 'Type');
  if (typeof nameRaw !== 'string' || typeof typeRaw !== 'string' || !typeRaw.trim()) return null;
  const nr = parseName(nameRaw, { absolute: true, base: 8 });
  if (!nr.ok) return null;
  const id = own(set, 'SetIdentifier');
  return { name: nr.name, type: typeOf(typeRaw) || safeText(typeRaw.trim().toUpperCase(), 20), id: typeof id === 'string' ? safeText(id, 200) : null };
}

function parseRoute53(docs, zone, b, opts) {
  const { issues } = b;
  // The record sets in file order; a change batch adds one entry per change, so a record's line is
  // its change's number. `skip` holds the entries not read as sets: a DELETE, or why a change is
  // not one (a skipped record).
  const sets = [];
  const skip = new Map();
  const fromBatch = [];
  const deletes = [];
  let lastDoc = null;
  let batches = 0;
  for (const d of docs) {
    const v = d.value;
    const changes = changeList(v);
    if (changes) {
      // A change batch: what it sets are its CREATE / UPSERT sets; a DELETE takes a set away.
      batches += 1;
      for (const c of changes) {
        const action = typeof own(c, 'Action') === 'string' ? own(c, 'Action').trim().toUpperCase() : '';
        const set = own(c, 'ResourceRecordSet');
        const at = sets.length;
        sets.push(set);
        if (!isPlainMap(c) || !isPlainMap(set)) skip.set(at, 'not-an-object');
        else if (action === 'DELETE') {
          const del = changeDelete(set);
          if (del) {
            deletes.push(del);
            skip.set(at, 'delete');
          } else skip.set(at, 'name-or-type');
        } else if (action !== 'CREATE' && action !== 'UPSERT') skip.set(at, 'action');
        else fromBatch.push(at);
      }
      continue;
    }
    const list = Array.isArray(v) ? v : own(v, 'ResourceRecordSets');
    if (Array.isArray(list)) for (const s of list) sets.push(s);
    lastDoc = v;
  }
  const changeBatch = () => {
    if (!batches) return;
    const read = new Set(b.records.map((r) => r.line));
    const upserts = fromBatch.filter((at) => read.has(at + 1)).length;
    zone.changeBatch = { upserts, deletes };
    issues.add('CHANGE_BATCH', 0, { upserts, deletes: deletes.length }, `a change batch: ${upserts} set(s) read, ${deletes.length} DELETE(s) left out`);
  };
  if (sets.every((_, at) => skip.has(at))) return { fatal: fatalIssue('EMPTY', {}, 'no record sets') };
  const trunc = own(lastDoc, 'IsTruncated');
  if (trunc === true || trunc === 'true' || typeof own(lastDoc, 'NextToken') === 'string') {
    zone.partial = true;
    const next = own(lastDoc, 'NextRecordName');
    issues.add('PARTIAL_EXPORT', 0, { provider: 'route53', next: typeof next === 'string' ? safeText(next, 255) : null, have: sets.length }, 'the listing is truncated');
  }
  const owners = [];
  let soa = null;
  const ns = [];
  for (const s of sets) {
    const n = own(s, 'Name');
    if (typeof n !== 'string') continue;
    const r = parseName(n, { absolute: true, base: 8 });
    if (!r.ok) continue;
    owners.push(r.name);
    if (own(s, 'Type') === 'SOA' && !soa) soa = r.name;
    if (own(s, 'Type') === 'NS') ns.push(r.name);
  }
  setJsonOrigin(zone, issues, opts, { explicit: null, explicitSource: 'soa', soa, ns, owners });
  b.entries = sets.length;
  const ctx = { origin: null, base: 8, absolute: true };
  for (let idx = 0; idx < sets.length; idx++) {
    const set = sets[idx];
    const line = idx + 1;
    if (b.full(line)) break;
    const why = skip.get(idx);
    if (why === 'delete') continue;
    if (why) {
      badRecord(b, line, why);
      continue;
    }
    if (!isPlainMap(set)) {
      badRecord(b, line, 'not-an-object');
      continue;
    }
    const nameRaw = own(set, 'Name');
    const typeRaw = own(set, 'Type');
    if (typeof nameRaw !== 'string' || typeof typeRaw !== 'string') {
      badRecord(b, line, 'name-or-type');
      continue;
    }
    const type = typeOf(typeRaw);
    if (!type) {
      badRecord(b, line, 'type');
      continue;
    }
    const nr = parseName(nameRaw, { absolute: true, base: 8 });
    if (!nr.ok) {
      issues.add('BAD_NAME', line, { name: safeText(nameRaw, 80), reason: nr.reason }, `invalid name (${nr.reason})`, { type });
      b.skipped++;
      continue;
    }
    const routing = r53Routing(set);
    const alias = own(set, 'AliasTarget');
    if (isPlainMap(alias)) {
      const dn = own(alias, 'DNSName');
      const tr = typeof dn === 'string' ? parseName(dn, { absolute: true, base: 8 }) : null;
      if (!tr || !tr.ok) {
        badRecord(b, line, 'alias');
        continue;
      }
      const rec = b.make(nr.name, type, line);
      const zid = own(alias, 'HostedZoneId');
      rec.alias = {
        target: tr.name,
        zoneId: typeof zid === 'string' ? safeText(zid, 100) : null,
        evaluateTargetHealth: own(alias, 'EvaluateTargetHealth') === true,
        provider: awsAliasProvider(tr.name, { origin: zone.origin })
      };
      if (routing) rec.routing = routing;
      b.push(rec);
      continue;
    }
    const rrs = own(set, 'ResourceRecords');
    if (!Array.isArray(rrs) || !rrs.length) {
      badRecord(b, line, 'no-values');
      continue;
    }
    for (const rr of rrs) {
      if (b.full(line)) break;
      const value = own(rr, 'Value');
      if (typeof value !== 'string') {
        badRecord(b, line, 'value');
        continue;
      }
      const rec = b.make(nr.name, type, line);
      jsonTtl(rec, own(set, 'TTL'), b, line);
      const toks = splitValueTokens(value);
      if (toks === null) {
        rec.invalid = true;
        rec.text = safeText(value, 2000);
        issues.add('BAD_RDATA', line, { type, reason: 'unterminated-quote' }, 'unterminated quote', { name: rec.name, type });
      } else {
        b.fillRdata(rec, toks, ctx, line);
      }
      if (routing) rec.routing = routing;
      b.push(rec);
    }
  }
  changeBatch();
  return { fatal: null };
}

/* ------------------------------------------------------------------------ */
/* deSEC API JSON (desec.io API v1: GET /api/v1/domains/<zone>/rrsets/)     */
/* ------------------------------------------------------------------------ */

/** The fatal API_ERROR of a provider's error document (its text made safe to show). */
function apiErrorFatal(provider, message, code = null) {
  return { fatal: fatalIssue('API_ERROR', { message: safeText(message, 200), code, provider }, `the ${provider} API answered with an error`) };
}

/**
 * deSEC RRsets: one or several arrays (a listing, or the pages of a listing read type by type),
 * single RRset objects, and deSEC's "Pagination required … (N total)" answer, which says how many
 * RRsets the zone has: fewer read → PARTIAL_EXPORT. Every record is RFC 1035 presentation text with
 * absolute names (deSEC requires the trailing dot); the zone name is the RRsets' `domain`.
 */
function parseDesecApi(docs, zone, b, opts) {
  const { issues } = b;
  const sets = [];
  const seen = new Set();
  let total = null;
  let lists = 0;
  let duplicates = 0;
  let zoneName = null;
  for (const d of docs) {
    const v = d.value;
    const kind = jsonKind(v);
    if (kind === 'desec-error') return apiErrorFatal('desec', own(v, 'detail'));
    if (kind === 'desec-pagination') {
      const m = /\((\d+) total\)/.exec(own(v, 'detail'));
      if (m) total = Math.max(total ?? 0, Number(m[1]));
      continue;
    }
    const list = Array.isArray(v) ? v : [v];
    lists++;
    for (const set of list) {
      if (isDesecRrset(set)) {
        const key = `${own(set, 'subname')}|${own(set, 'type')}`;
        if (seen.has(key)) {
          duplicates++;
          continue;
        }
        seen.add(key);
        if (zoneName === null && typeof own(set, 'domain') === 'string') zoneName = own(set, 'domain');
      }
      sets.push(set);
    }
  }
  if (lists > 1 || duplicates) issues.add('JSON_PAGES_MERGED', 0, { pages: lists, duplicates }, `${lists} pasted page(s) merged`);
  if (!sets.length) return { fatal: fatalIssue('EMPTY', {}, 'no RRsets in the listing') };
  if (total !== null && total > sets.length) {
    zone.partial = true;
    issues.add('PARTIAL_EXPORT', 0, { have: sets.length, total, provider: 'desec' }, `only ${sets.length} of ${total} RRsets were read`);
  }
  const owners = [];
  const ns = [];
  for (const set of sets) {
    const r = typeof own(set, 'name') === 'string' ? parseName(own(set, 'name'), { absolute: true }) : null;
    if (!r || !r.ok) continue;
    owners.push(r.name);
    if (own(set, 'type') === 'NS') ns.push(r.name);
  }
  setJsonOrigin(zone, issues, opts, { explicit: zoneName, explicitSource: 'header', soa: null, ns, owners });
  b.entries = sets.length;
  const ctx = { origin: null, base: 10, absolute: true };
  for (let idx = 0; idx < sets.length; idx++) {
    const set = sets[idx];
    const line = idx + 1;
    if (b.full(line)) break;
    if (!isPlainMap(set)) {
      badRecord(b, line, 'not-an-object');
      continue;
    }
    const nameRaw = own(set, 'name');
    const typeRaw = own(set, 'type');
    if (typeof nameRaw !== 'string' || typeof typeRaw !== 'string') {
      badRecord(b, line, 'name-or-type');
      continue;
    }
    const type = typeOf(typeRaw);
    if (!type) {
      badRecord(b, line, 'type');
      continue;
    }
    const nr = parseName(nameRaw, { absolute: true });
    if (!nr.ok) {
      issues.add('BAD_NAME', line, { name: safeText(nameRaw, 80), reason: nr.reason }, `invalid name (${nr.reason})`, { type });
      b.skipped++;
      continue;
    }
    const values = own(set, 'records');
    if (!Array.isArray(values) || !values.length) {
      badRecord(b, line, 'no-values');
      continue;
    }
    for (const value of values) {
      if (b.full(line)) break;
      if (typeof value !== 'string') {
        badRecord(b, line, 'value');
        continue;
      }
      const rec = b.make(nr.name, type, line);
      jsonTtl(rec, own(set, 'ttl'), b, line);
      const toks = splitValueTokens(value);
      if (toks === null) {
        rec.invalid = true;
        rec.text = safeText(value, 2000);
        issues.add('BAD_RDATA', line, { type, reason: 'unterminated-quote' }, 'unterminated quote', { name: rec.name, type });
      } else {
        b.fillRdata(rec, toks, ctx, line);
      }
      b.push(rec);
    }
  }
  return { fatal: null };
}

/* ------------------------------------------------------------------------ */
/* DigitalOcean API JSON (api.digitalocean.com: GET /v2/domains/<zone>/records) */
/* ------------------------------------------------------------------------ */

/** Record types whose `data` is a host name: '@' for the apex, else the name without its trailing dot. */
const DO_NAME_DATA = new Set(['CNAME', 'NS', 'MX', 'SRV', 'PTR']);

/**
 * DigitalOcean domain records: `{ domain_records: [...], meta: { total } }` pages (or a bare array,
 * or one `{ domain_record }`), merged by id; fewer records than `meta.total` → PARTIAL_EXPORT.
 * Names are relative to the zone ('@' = the apex) and the listing never names the zone, so the
 * origin comes from the user, else the file name (ORIGIN_REQUIRED otherwise). Host-name data is
 * absolute without its trailing dot ('@' = the apex); MX / SRV / CAA keep their numbers and tag in
 * fields of their own; TXT data is the raw text. DigitalOcean lists the zone's SOA as a record whose
 * data is only a TTL: it is skipped.
 */
function parseDigitalOceanApi(docs, zone, b, opts) {
  const { issues } = b;
  const items = [];
  const seen = new Set();
  let total = null;
  let pages = 0;
  let duplicates = 0;
  for (const d of docs) {
    const v = d.value;
    const kind = jsonKind(v);
    if (kind === 'do-error') return apiErrorFatal('digitalocean', own(v, 'message'), safeText(own(v, 'id'), 60));
    pages++;
    let list;
    if (Array.isArray(v)) list = v;
    else if (Array.isArray(own(v, 'domain_records'))) list = own(v, 'domain_records');
    else list = [own(v, 'domain_record')];
    const tc = own(own(v, 'meta'), 'total');
    if (Number.isInteger(tc) && tc >= 0) total = Math.max(total ?? 0, tc);
    for (const item of list) {
      const id = own(item, 'id');
      if (typeof id === 'number') {
        if (seen.has(id)) {
          duplicates++;
          continue;
        }
        seen.add(id);
      }
      items.push(item);
    }
  }
  if (pages > 1 || duplicates) issues.add('JSON_PAGES_MERGED', 0, { pages, duplicates }, `${pages} pasted page(s) merged`);
  if (!items.length) return { fatal: fatalIssue('EMPTY', {}, 'no DNS records in the response') };
  if (total !== null && total > items.length) {
    zone.partial = true;
    issues.add('PARTIAL_EXPORT', 0, { have: items.length, total, provider: 'digitalocean' }, `only ${items.length} of ${total} records were read`);
  }
  const fromFile = inferOriginFromFilename(opts.filename);
  if (opts.userOrigin) {
    zone.origin = opts.userOrigin;
    zone.originSource = 'user';
    zone.originConfidence = 'high';
  } else if (fromFile) {
    zone.origin = fromFile;
    zone.originSource = 'filename';
    zone.originConfidence = 'low';
    issues.add('ORIGIN_INFERRED', 0, { origin: fromFile, source: 'filename' }, `origin ${fromFile} from the file name`);
  } else {
    return { fatal: fatalIssue('ORIGIN_REQUIRED', { relative: items.length }, 'DigitalOcean names are relative to a zone the listing does not name') };
  }
  b.entries = items.length;
  const origin = zone.origin;
  /** A host-name field: '@' (or nothing) = the apex; a name without a trailing dot is absolute. */
  const host = (s) => ({ t: s === '@' || s === '' ? fqdn(origin) : s.endsWith('.') ? s : `${s}.`, q: false });
  const num = (v) => ({ t: String(v ?? ''), q: false });
  const ctx = { origin, base: 10, absolute: false };
  for (let idx = 0; idx < items.length; idx++) {
    const item = items[idx];
    const line = idx + 1;
    if (b.full(line)) break;
    if (!isPlainMap(item)) {
      badRecord(b, line, 'not-an-object');
      continue;
    }
    const nameRaw = own(item, 'name');
    const typeRaw = own(item, 'type');
    const data = own(item, 'data');
    if (typeof nameRaw !== 'string' || typeof typeRaw !== 'string') {
      badRecord(b, line, 'name-or-type');
      continue;
    }
    const type = typeOf(typeRaw);
    if (!type) {
      badRecord(b, line, 'type');
      continue;
    }
    if (type === 'SOA') {
      b.skipped++;
      continue;
    }
    const nr = parseName(nameRaw === '' ? '@' : nameRaw, { origin });
    if (!nr.ok) {
      issues.add('BAD_NAME', line, { name: safeText(nameRaw, 80), reason: nr.reason }, `invalid name (${nr.reason})`, { type });
      b.skipped++;
      continue;
    }
    if (typeof data !== 'string') {
      badRecord(b, line, 'value');
      continue;
    }
    const rec = b.make(nr.name, type, line);
    jsonTtl(rec, own(item, 'ttl'), b, line);
    if (type === 'TXT' || type === 'SPF') {
      b.fillTxt(rec, split255(utf8Encoder.encode(data)));
    } else {
      let toks;
      if (type === 'MX') toks = [num(own(item, 'priority')), host(data)];
      else if (type === 'SRV') toks = [num(own(item, 'priority')), num(own(item, 'weight')), num(own(item, 'port')), host(data)];
      else if (type === 'CAA') toks = [num(own(item, 'flags') ?? 0), { t: String(own(item, 'tag') ?? ''), q: false }, rawToken(data)];
      else if (DO_NAME_DATA.has(type)) toks = [host(data)];
      else toks = splitValueTokens(data);
      if (toks === null) {
        rec.invalid = true;
        rec.text = safeText(data, 2000);
        issues.add('BAD_RDATA', line, { type, reason: 'unterminated-quote' }, 'unterminated quote', { name: rec.name, type });
      } else {
        b.fillRdata(rec, toks, ctx, line);
      }
    }
    b.push(rec);
  }
  return { fatal: null };
}

/* ------------------------------------------------------------------------ */
/* YAML subset (octoDNS)                                                    */
/* ------------------------------------------------------------------------ */

const YAML_LINE = Symbol('yamlLine');
const YAML_KEY_LINES = Symbol('yamlKeyLines');

class YamlError extends Error {
  constructor(feature, line) {
    super(feature);
    this.feature = feature;
    this.line = line;
  }
}

/** Remove a `#` comment (quote-aware: quotes only open at the start of a scalar). */
function stripYamlComment(s) {
  let quote = 0;
  let scalarStart = true;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (quote) {
      if (quote === 0x27 && c === 0x27) {
        if (s.charCodeAt(i + 1) === 0x27) i++;
        else quote = 0;
      } else if (quote === 0x22) {
        if (c === 0x5c) i++;
        else if (c === 0x22) quote = 0;
      }
      continue;
    }
    if (c === 0x23 && (i === 0 || s.charCodeAt(i - 1) === 32 || s.charCodeAt(i - 1) === 9)) return s.slice(0, i);
    if ((c === 0x27 || c === 0x22) && scalarStart) {
      quote = c;
      continue;
    }
    if (c === 32 || c === 9) continue;
    // a quote opens a scalar only after "- ", "? ", ": " or inside a flow sequence ("[", ",")
    const next = s.charCodeAt(i + 1);
    const spaceAfter = next === 32 || next === 9 || Number.isNaN(next);
    scalarStart = c === 0x5b || c === 0x2c || ((c === 0x2d || c === 0x3f || c === 0x3a) && spaceAfter);
  }
  return s; // no comment (an open quote is reported by the scalar parser)
}

/** `key: value` split (quote-aware); null when the text is not a mapping entry. */
function splitYamlKey(text) {
  const c0 = text.charCodeAt(0);
  if (c0 === 0x27 || c0 === 0x22) {
    let k = 1;
    while (k < text.length) {
      const c = text.charCodeAt(k);
      if (c0 === 0x27 && c === 0x27) {
        if (text.charCodeAt(k + 1) === 0x27) {
          k += 2;
          continue;
        }
        break;
      }
      if (c0 === 0x22 && c === 0x5c) {
        k += 2;
        continue;
      }
      if (c0 === 0x22 && c === 0x22) break;
      k++;
    }
    if (k >= text.length || text.charCodeAt(k + 1) !== 0x3a) return null;
    const after = text.charCodeAt(k + 2);
    if (!(Number.isNaN(after) || after === 32 || after === 9)) return null;
    return { key: text.slice(0, k + 1), value: text.slice(k + 2).trim(), quoted: true };
  }
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) !== 0x3a) continue;
    const next = text.charCodeAt(i + 1);
    if (Number.isNaN(next) || next === 32 || next === 9) {
      const key = text.slice(0, i).trim();
      if (!key) return null;
      return { key, value: text.slice(i + 1).trim(), quoted: false };
    }
  }
  return null;
}

const isSeqItem = (t) => t === '-' || t.startsWith('- ') || t.startsWith('-\t');

function yamlDouble(s, line) {
  let out = '';
  for (let i = 1; i < s.length - 1; i++) {
    const c = s[i];
    if (c !== '\\') {
      out += c;
      continue;
    }
    const e = s[++i];
    switch (e) {
      case 'n': out += '\n'; break;
      case 't': out += '\t'; break;
      case 'r': out += '\r'; break;
      case '0': out += '\0'; break;
      case '"': out += '"'; break;
      case '\\': out += '\\'; break;
      case '/': out += '/'; break;
      case ' ': out += ' '; break;
      case 'x': case 'u': case 'U': {
        const len = e === 'x' ? 2 : e === 'u' ? 4 : 8;
        const hex = s.slice(i + 1, i + 1 + len);
        if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== len) throw new YamlError('bad-escape', line);
        const cp = parseInt(hex, 16);
        if (cp > 0x10ffff) throw new YamlError('bad-escape', line);
        out += String.fromCodePoint(cp);
        i += len;
        break;
      }
      default: out += `\\${e}`; // e.g. octoDNS "\;" kept for the TXT unescaping
    }
  }
  return out;
}

function yamlScalar(s, line, { key = false } = {}) {
  if (s === '') return null;
  const c = s[0];
  if (c === '&') throw new YamlError('anchor', line);
  if (c === '*') throw new YamlError('alias', line);
  if (c === '!') throw new YamlError('tag', line);
  if (c === '|' || c === '>') throw new YamlError('block-scalar', line);
  if (c === '{') throw new YamlError('flow-mapping', line);
  if (c === '@' || c === '`' || c === '%') throw new YamlError('reserved-indicator', line);
  if (c === '[') {
    if (key) throw new YamlError('complex-key', line);
    return yamlFlowSeq(s, line);
  }
  if (c === "'") {
    let out = '';
    let i = 1;
    for (; i < s.length; i++) {
      if (s[i] === "'") {
        if (s[i + 1] === "'") {
          out += "'";
          i++;
          continue;
        }
        break;
      }
      out += s[i];
    }
    if (i !== s.length - 1) throw new YamlError(i >= s.length ? 'multi-line-scalar' : 'syntax', line);
    return out;
  }
  if (c === '"') {
    let i = 1;
    for (; i < s.length; i++) {
      if (s[i] === '\\') {
        i++;
        continue;
      }
      if (s[i] === '"') break;
    }
    if (i !== s.length - 1) throw new YamlError(i >= s.length ? 'multi-line-scalar' : 'syntax', line);
    return yamlDouble(s, line);
  }
  if (key) return s;
  if (s === '~' || s === 'null' || s === 'Null' || s === 'NULL') return null;
  if (s === 'true' || s === 'True' || s === 'TRUE') return true;
  if (s === 'false' || s === 'False' || s === 'FALSE') return false;
  if (/^[-+]?\d{1,15}$/.test(s)) return Number(s);
  return s;
}

function yamlFlowSeq(s, line) {
  if (!s.endsWith(']')) throw new YamlError('multi-line-scalar', line);
  const inner = s.slice(1, -1).trim();
  if (!inner) return [];
  const items = [];
  let cur = '';
  let quote = '';
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (quote) {
      cur += c;
      if (c === '\\' && quote === '"') {
        cur += inner[++i] ?? '';
        continue;
      }
      if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      cur += c;
      continue;
    }
    if (c === '[' || c === '{') throw new YamlError('nested-flow', line);
    if (c === ',') {
      items.push(cur.trim());
      cur = '';
      continue;
    }
    cur += c;
  }
  items.push(cur.trim());
  return items.filter((x, i) => x !== '' || i < items.length - 1).map((x) => yamlScalar(x, line));
}

/**
 * Parse the YAML subset octoDNS files use: block mappings and sequences (also at the parent
 * key's indent), `? key` complex keys, plain / single / double-quoted scalars, flow sequences,
 * quote-aware `#` comments and a leading `---`. Anchors, aliases, tags, block scalars, flow
 * mappings and further documents are rejected. Maps are null-prototype objects.
 * @param {string} text
 * @param {{ limits?: object }} [opts]
 * @returns {{ value: any, issues: Array<{ code: 'DUPLICATE_KEY', line: number, params: object }>, error: null|{ feature: string, line: number } }}
 */
export function parseYamlSubset(text, { limits = ZONE_LIMITS } = {}) {
  const L = { ...ZONE_LIMITS, ...limits };
  const issues = [];
  const lines = [];
  try {
    const raw = splitLines(String(text ?? ''));
    let content = false;
    let ended = false;
    for (let i = 0; i < raw.length; i++) {
      const s = raw[i];
      let indent = 0;
      while (indent < s.length && s.charCodeAt(indent) === 32) indent++;
      if (s.charCodeAt(indent) === 9 && s.slice(indent).trim() && !s.slice(indent).trim().startsWith('#')) throw new YamlError('tab-indent', i + 1);
      const t = stripYamlComment(s).trimEnd();
      if (!t.trim()) continue;
      const body = t.slice(indent);
      if (indent === 0 && /^---(?:\s|$)/.test(body)) {
        if (content || ended) throw new YamlError('multiple-documents', i + 1);
        if (body.trim() !== '---') throw new YamlError('document-header', i + 1);
        continue;
      }
      if (indent === 0 && /^\.\.\.(?:\s|$)/.test(body)) {
        ended = true;
        continue;
      }
      if (ended) throw new YamlError('multiple-documents', i + 1);
      if (indent === 0 && body.startsWith('%')) throw new YamlError('directive', i + 1);
      lines.push({ n: i + 1, indent, text: body });
      content = true;
    }
    let pos = 0;
    const setKey = (obj, key, value, line) => {
      if (HAS_OWN.call(obj, key)) issues.push({ code: 'DUPLICATE_KEY', line, params: { key: safeText(key, 80) } });
      obj[key] = value;
      obj[YAML_KEY_LINES][key] = line;
    };
    const newMap = (line) => {
      const o = Object.create(null);
      Object.defineProperty(o, YAML_LINE, { value: line, enumerable: false });
      Object.defineProperty(o, YAML_KEY_LINES, { value: Object.create(null), enumerable: false });
      return o;
    };
    const node = (depth) => {
      if (depth > L.maxYamlDepth) throw new YamlError('depth', lines[pos].n);
      const l = lines[pos];
      if (isSeqItem(l.text)) return seq(l.indent, depth);
      if (l.text === '?' || l.text.startsWith('? ') || splitYamlKey(l.text)) return map(l.indent, depth);
      pos++;
      const v = yamlScalar(l.text, l.n);
      if (pos < lines.length && lines[pos].indent > l.indent) throw new YamlError('multi-line-scalar', lines[pos].n);
      return v;
    };
    const seq = (indent, depth) => {
      const arr = [];
      while (pos < lines.length && lines[pos].indent === indent && isSeqItem(lines[pos].text)) {
        const l = lines[pos];
        const rest = l.text.slice(1).replace(/^[ \t]+/, '');
        const off = l.text.length - rest.length;
        if (rest === '') {
          pos++;
          if (pos < lines.length && lines[pos].indent > indent) arr.push(node(depth + 1));
          else arr.push(null);
        } else if (isSeqItem(rest) || rest === '?' || rest.startsWith('? ') || splitYamlKey(rest)) {
          l.indent = indent + off;
          l.text = rest;
          arr.push(node(depth + 1));
        } else {
          pos++;
          arr.push(yamlScalar(rest, l.n));
          if (pos < lines.length && lines[pos].indent > indent) throw new YamlError('multi-line-scalar', lines[pos].n);
        }
      }
      return arr;
    };
    const map = (indent, depth) => {
      const obj = newMap(lines[pos].n);
      while (pos < lines.length && lines[pos].indent === indent && !isSeqItem(lines[pos].text)) {
        const l = lines[pos];
        let key;
        let valueText;
        const keyLine = l.n;
        if (l.text === '?' || l.text.startsWith('? ')) {
          const kt = l.text.slice(1).trim();
          if (kt === '') throw new YamlError('complex-key', l.n);
          key = String(yamlScalar(kt, l.n, { key: true }) ?? '');
          pos++;
          const vl = lines[pos];
          if (!vl || vl.indent !== indent || !(vl.text === ':' || vl.text.startsWith(': '))) {
            setKey(obj, key, null, keyLine);
            continue;
          }
          valueText = vl.text.slice(1).replace(/^[ \t]+/, '');
          if (valueText && (isSeqItem(valueText) || valueText.startsWith('? ') || splitYamlKey(valueText))) {
            vl.indent = indent + (vl.text.length - valueText.length);
            vl.text = valueText;
            setKey(obj, key, node(depth + 1), keyLine);
            continue;
          }
          pos++;
        } else {
          const kv = splitYamlKey(l.text);
          if (!kv) throw new YamlError('syntax', l.n);
          key = String(yamlScalar(kv.key, l.n, { key: true }) ?? '');
          valueText = kv.value;
          pos++;
        }
        let value;
        if (valueText === '') {
          if (pos < lines.length && lines[pos].indent > indent) value = node(depth + 1);
          else if (pos < lines.length && lines[pos].indent === indent && isSeqItem(lines[pos].text)) value = seq(indent, depth + 1);
          else value = null;
        } else {
          value = yamlScalar(valueText, keyLine);
          if (pos < lines.length && lines[pos].indent > indent) throw new YamlError('multi-line-scalar', lines[pos].n);
        }
        setKey(obj, key, value, keyLine);
      }
      return obj;
    };
    if (!lines.length) return { value: null, issues, error: null };
    const value = node(0);
    if (pos < lines.length) throw new YamlError('syntax', lines[pos].n);
    return { value, issues, error: null };
  } catch (err) {
    if (err instanceof YamlError) return { value: null, issues, error: { feature: err.feature, line: err.line } };
    if (err instanceof RangeError) return { value: null, issues, error: { feature: 'depth', line: 0 } };
    throw err;
  }
}

/* ------------------------------------------------------------------------ */
/* octoDNS                                                                  */
/* ------------------------------------------------------------------------ */

function octoTokens(type, v) {
  const num = (x) => {
    if (typeof x === 'number' || (typeof x === 'string' && x !== '')) return { t: String(x), q: false };
    throw new RdataError('missing-field');
  };
  const str = (x) => {
    if (typeof x === 'string' || typeof x === 'number') return { t: String(x), q: false };
    throw new RdataError('missing-field');
  };
  const field = (m, ...keys) => {
    for (const k of keys) if (own(m, k) !== undefined && own(m, k) !== null) return own(m, k);
    return undefined;
  };
  switch (type) {
    case 'A': case 'AAAA': case 'CNAME': case 'DNAME': case 'PTR': case 'NS':
      return [str(v)];
    case 'MX':
      if (!isPlainMap(v)) throw new RdataError('missing-field');
      return [num(field(v, 'preference', 'priority')), str(field(v, 'exchange', 'value'))];
    case 'SRV':
      if (!isPlainMap(v)) throw new RdataError('missing-field');
      return [num(field(v, 'priority')), num(field(v, 'weight')), num(field(v, 'port')), str(field(v, 'target'))];
    case 'CAA':
      if (!isPlainMap(v)) throw new RdataError('missing-field');
      return [num(field(v, 'flags') ?? 0), str(field(v, 'tag')), rawToken(String(field(v, 'value') ?? ''))];
    case 'SSHFP':
      if (!isPlainMap(v)) throw new RdataError('missing-field');
      return [num(field(v, 'algorithm')), num(field(v, 'fingerprint_type')), str(field(v, 'fingerprint'))];
    case 'TLSA':
      if (!isPlainMap(v)) throw new RdataError('missing-field');
      return [num(field(v, 'certificate_usage')), num(field(v, 'selector')), num(field(v, 'matching_type')),
        str(field(v, 'certificate_association_data'))];
    case 'DS':
      if (!isPlainMap(v)) throw new RdataError('missing-field');
      return [num(field(v, 'key_tag')), num(field(v, 'algorithm')), num(field(v, 'digest_type')), str(field(v, 'digest'))];
    case 'NAPTR':
      if (!isPlainMap(v)) throw new RdataError('missing-field');
      return [num(field(v, 'order')), num(field(v, 'preference')), rawToken(String(field(v, 'flags') ?? '')),
        rawToken(String(field(v, 'service') ?? '')), rawToken(String(field(v, 'regexp') ?? '')), str(field(v, 'replacement'))];
    case 'SVCB':
    case 'HTTPS':
      if (!isPlainMap(v)) throw new RdataError('missing-field');
      return [num(field(v, 'svcpriority')), str(field(v, 'targetname')), ...octoSvcParams(own(v, 'svcparams'))];
    case 'URI': {
      if (!isPlainMap(v)) throw new RdataError('missing-field');
      const target = field(v, 'target');
      if (typeof target !== 'string') throw new RdataError('missing-field');
      return [num(field(v, 'priority')), num(field(v, 'weight')), rawToken(target)];
    }
    case 'OPENPGPKEY':
      return [str(v)];
    default:
      return null;
  }
}

/**
 * octoDNS `svcparams` (key → null, a value or a list) as the `key[=value]` tokens of a zone file:
 * a list joined with commas, a comma or backslash inside an item escaped twice (RFC 9460
 * value-list, then character-string); any other value is already zone file text.
 */
function octoSvcParams(params) {
  if (params === undefined || params === null) return [];
  if (!isPlainMap(params)) throw new RdataError('missing-field');
  return Object.keys(params).map((k) => {
    const v = params[k];
    if (v === null || v === true) return { t: k, q: false };
    if (Array.isArray(v)) {
      const items = v.map((x) => String(x).replace(/[\\,]/g, (m) => `\\${m}`).replace(/\\/g, '\\\\'));
      return { t: `${k}=${items.join(',')}`, q: false };
    }
    if (typeof v === 'object') throw new RdataError('missing-field');
    return { t: `${k}=${String(v)}`, q: false };
  });
}

function parseOctodns(text, zone, b, opts) {
  const { issues } = b;
  const y = parseYamlSubset(text, { limits: b.L });
  if (y.error) {
    return { fatal: fatalIssue('YAML_UNSUPPORTED', { feature: y.error.feature, line: y.error.line }, `YAML feature not supported: ${y.error.feature}`, y.error.line) };
  }
  for (const i of y.issues) issues.add('DUPLICATE_KEY', i.line, i.params, 'duplicate key: the last one wins');
  const doc = y.value;
  if (doc === null) return { fatal: fatalIssue('EMPTY', {}, 'empty YAML') };
  if (!isPlainMap(doc) || Array.isArray(doc)) return { fatal: fatalIssue('NOT_A_ZONE', { hint: 'unknown', samples: contentLines(text, 3).map((l) => safeText(l, 80)) }, 'YAML is not an octoDNS zone') };
  const fromFile = inferOriginFromFilename(opts.filename);
  if (opts.userOrigin) {
    zone.origin = opts.userOrigin;
    zone.originSource = 'user';
    zone.originConfidence = 'high';
  } else if (fromFile) {
    zone.origin = fromFile;
    zone.originSource = 'filename';
    zone.originConfidence = 'low';
    issues.add('ORIGIN_INFERRED', 0, { origin: fromFile, source: 'filename' }, `origin ${fromFile} from the file name`);
  } else if (Object.keys(doc).length) {
    return { fatal: fatalIssue('ORIGIN_REQUIRED', { relative: Object.keys(doc).length }, 'octoDNS zone names come from the file name') };
  }
  const keyLines = doc[YAML_KEY_LINES] || Object.create(null);
  for (const key of Object.keys(doc)) {
    if (b.truncated) break;
    const line = keyLines[key] || 0;
    const nr = parseName(key === '' ? '@' : key, { origin: zone.origin });
    if (!nr.ok) {
      issues.add('BAD_NAME', line, { name: safeText(key, 80), reason: nr.reason }, `invalid name (${nr.reason})`);
      b.skipped++;
      continue;
    }
    const spec = doc[key];
    const list = Array.isArray(spec) ? spec : [spec];
    for (const r of list) {
      b.entries++;
      if (!isPlainMap(r)) {
        badRecord(b, line, 'not-a-mapping');
        continue;
      }
      const typeRaw = own(r, 'type');
      const type = typeof typeRaw === 'string' ? typeOf(typeRaw) : null;
      if (!type) {
        badRecord(b, line, 'type');
        continue;
      }
      const octo = own(r, 'octodns');
      if (own(octo, 'ignored') === true) {
        issues.add('OCTODNS_IGNORED', line, { name: nr.name, type }, 'record marked octodns.ignored', { name: nr.name, type });
        b.skipped++;
        continue;
      }
      const cf = own(octo, 'cloudflare');
      const ttlRaw = own(r, 'ttl');
      const autoTtl = own(cf, 'auto-ttl') === true;
      const proxiedRaw = own(cf, 'proxied');
      const values = [];
      const vs = own(r, 'values');
      const v1 = own(r, 'value');
      if (vs !== undefined && vs !== null) (Array.isArray(vs) ? vs : [vs]).forEach((v) => values.push({ v, routing: undefined }));
      else if (v1 !== undefined && v1 !== null) values.push({ v: v1, routing: undefined });
      const dyn = own(r, 'dynamic');
      const geo = own(r, 'geo');
      if (isPlainMap(dyn)) {
        for (const x of values) x.routing = { policy: 'dynamic', id: null };
        const pools = own(dyn, 'pools');
        if (isPlainMap(pools)) {
          for (const pool of Object.keys(pools)) {
            const pv = own(own(pools, pool), 'values');
            if (!Array.isArray(pv)) continue;
            for (const item of pv) {
              const val = isPlainMap(item) ? own(item, 'value') : item;
              const routing = { policy: 'dynamic', id: safeText(pool, 100) };
              if (isPlainMap(item) && typeof own(item, 'weight') === 'number') routing.weight = own(item, 'weight');
              if (val !== undefined && val !== null) values.push({ v: val, routing });
            }
          }
        }
      } else if (isPlainMap(geo)) {
        for (const x of values) x.routing = { policy: 'geo', id: null };
        for (const code of Object.keys(geo)) {
          const gv = geo[code];
          for (const val of Array.isArray(gv) ? gv : [gv]) {
            if (val !== undefined && val !== null) values.push({ v: val, routing: { policy: 'geo', id: safeText(code, 40) } });
          }
        }
      }
      if (!values.length) {
        badRecord(b, line, 'no-value');
        continue;
      }
      for (const { v, routing } of values) {
        if (b.full(line)) break;
        const rec = b.make(nr.name, type, line);
        if (autoTtl) {
          rec.ttl = 300;
          rec.ttlAuto = true;
        } else if (typeof ttlRaw === 'number' && Number.isInteger(ttlRaw) && ttlRaw >= 0) applyTtl(rec, ttlRaw, issues, line);
        else rec.ttl = 3600;
        if (type === 'TXT' || type === 'SPF') {
          const s = typeof v === 'string' || typeof v === 'number' ? String(v) : '';
          if (/(^|[^\\]);/.test(s)) issues.add('OCTODNS_UNESCAPED_SEMICOLON', line, { name: nr.name }, 'bare ";" in an octoDNS TXT value (write \\;)', { name: nr.name, type });
          // octoDNS keeps a TXT value as its raw text with every `;` escaped as `\;` and nothing else
          // (its _ChunkedValue.to_raw_text; lib/zoneconvert.js octodnsTxt writes it so). As it loads a
          // value it strips the first and last character of one that starts with `"` and deletes every
          // `" "` (its _ChunkedValue.process, for values written as quoted strings).
          const raw = (s.startsWith('"') ? s.slice(1, -1) : s).split('" "').join('');
          b.fillTxt(rec, split255(utf8Encoder.encode(raw.replace(/\\;/g, ';'))));
        } else {
          let toks;
          try {
            toks = octoTokens(type, v);
          } catch {
            rec.invalid = true;
            rec.text = safeText(typeof v === 'object' ? JSON.stringify(v) : String(v), 500);
            issues.add('BAD_RDATA', line, { type, reason: 'missing-field' }, 'missing octoDNS value field', { name: nr.name, type });
            toks = undefined;
          }
          if (toks === null) {
            rec.unsupported = true;
            rec.text = safeText(typeof v === 'object' ? JSON.stringify(v) : String(v), 500);
            issues.addOnce(`unparsed:${type}`, 'RDATA_UNPARSED', line, { type }, `${type} value kept as text`, { name: nr.name, type });
          } else if (toks) {
            b.fillRdata(rec, toks, { origin: zone.origin, base: 10, absolute: false }, line);
          }
        }
        if (typeof proxiedRaw === 'boolean') {
          if (PROXIABLE.has(type)) rec.proxied = proxiedRaw;
          else issues.addOnce(`proxy-ignored:${type}`, 'PROXY_FLAG_IGNORED', line, { type }, `proxied ignored on ${type}`, { name: nr.name, type });
        }
        if (routing) rec.routing = routing;
        b.push(rec);
      }
    }
  }
  return { fatal: null };
}

/* ------------------------------------------------------------------------ */
/* Plesk `dns --info`                                                       */
/* ------------------------------------------------------------------------ */

function parsePlesk(text, lines, zone, b, opts) {
  const { issues } = b;
  issues.add('FORMAT_UNVERIFIED', 0, { format: 'plesk-info' }, 'Plesk "dns --info" layout is inferred, not documented');
  const hm = /^SUCCESS: Getting information for Domain '([^']+)'/m.exec(text);
  const header = hm ? normalizeHostname(hm[1], { allowSingleLabel: true }) : null;
  const rows = [];
  lines.forEach((raw, i) => {
    const t = raw.trim();
    if (!t || t.startsWith('SUCCESS:')) return;
    rows.push({ t, line: i + 1 });
  });
  const owners = [];
  for (const row of rows) {
    const m = /^(\S+)\s/.exec(row.t);
    if (m && m[1].endsWith('.')) {
      const r = parseName(m[1]);
      if (r.ok) owners.push(r.name);
    }
  }
  setJsonOrigin(zone, issues, opts, { explicit: header, explicitSource: 'header', soa: null, ns: [], owners });
  for (const row of rows) {
    b.entries++;
    if (b.full(row.line)) break;
    const m = /^(\S+)\s+([A-Za-z][A-Za-z0-9]*)(?:\s+(.*))?$/.exec(row.t);
    const type = m ? typeOf(m[2]) : null;
    if (!m || !type) {
      issues.add('UNPARSED_LINE', row.line, { snippet: safeText(row.t, 80) }, `cannot read: ${safeText(row.t, 80)}`);
      b.skipped++;
      continue;
    }
    const nr = parseName(m[1], { origin: zone.origin });
    if (!nr.ok) {
      issues.add('BAD_NAME', row.line, { name: safeText(m[1], 80), reason: nr.reason }, `invalid name (${nr.reason})`, { type });
      b.skipped++;
      continue;
    }
    const rec = b.make(nr.name, type, row.line);
    const value = m[3] ?? '';
    if (type === 'TXT' || type === 'SPF') b.fillTxt(rec, split255(utf8Encoder.encode(value)));
    else {
      const toks = splitValueTokens(value);
      if (toks === null) {
        rec.invalid = true;
        rec.text = safeText(value, 2000);
        issues.add('BAD_RDATA', row.line, { type, reason: 'unterminated-quote' }, 'unterminated quote', { name: rec.name, type });
      } else b.fillRdata(rec, toks, { origin: zone.origin, base: 10, absolute: false }, row.line);
    }
    b.push(rec);
  }
  return { fatal: null };
}

/* ------------------------------------------------------------------------ */
/* parseZone                                                                */
/* ------------------------------------------------------------------------ */

/**
 * Parse any supported zone export. Never throws.
 *
 * @param {string|ArrayBuffer|Uint8Array} input
 * @param {{ origin?: string|null, filename?: string|null, format?: 'auto'|string, source?: number,
 *   limits?: object, defaultTtl?: number|null }} [opts]
 *   - origin: user override (any form); it sets the initial origin, `$ORIGIN` still applies
 *   - filename: origin inference (`example.com.yaml`, `db.example.com`) and dialect hint
 *   - format: 'auto' or one of ZONE_FORMATS
 *   - source: index written to every record's / issue's `source` (multi-file)
 *   - defaultTtl: initial `$TTL` (a `$INCLUDE` fragment inherits the main file's)
 * @returns {Zone}
 */
export function parseZone(input, opts = {}) {
  const t0 = nowMs();
  const o = opts && typeof opts === 'object' ? opts : {};
  const L = { ...ZONE_LIMITS, ...(o.limits && typeof o.limits === 'object' ? o.limits : {}) };
  const source = Number.isInteger(o.source) && o.source >= 0 ? o.source : 0;
  const filename = typeof o.filename === 'string' ? o.filename : null;
  let zone;
  try {
    zone = parseZoneInner(input, {
      L, source, filename,
      userOrigin: normalizeUserOrigin(o.origin),
      format: typeof o.format === 'string' ? o.format : 'auto',
      defaultTtl: Number.isInteger(o.defaultTtl) && o.defaultTtl >= 0 && o.defaultTtl <= MAX_TTL ? o.defaultTtl : null
    });
  } catch (err) {
    zone = failZone(newZone({ filename, bytes: 0 }),
      fatalIssue('NOT_A_ZONE', { hint: 'unknown', samples: [], internal: true }, `internal error: ${safeText(err && err.message, 200)}`));
  }
  zone.stats.elapsedMs = Math.round((nowMs() - t0) * 100) / 100;
  return zone;
}

function parseZoneInner(input, opts) {
  const { L, source, filename } = opts;
  const dec = decodeInput(input, L);
  const zone = newZone({ filename, bytes: dec.bytes });
  if (dec.fatal) return failZone(zone, dec.fatal);
  const chk = textChecks(dec.text);
  if (chk.fatal) return failZone(zone, chk.fatal);
  const text = normalizeNewlines(dec.text);
  const issues = new IssueList(L, source);
  if (chk.replaced) issues.add('ENCODING_REPLACED', 0, { count: chk.replaced }, 'undecodable bytes replaced');

  let det;
  if (opts.format !== 'auto' && ZONE_FORMATS.includes(opts.format)) {
    det = detectInternal(text, filename, L.maxJsonDocs);
    if (det.fatal && det.fatal.code === 'EMPTY') return failZone(zone, det.fatal);
    if (JSON_FORMATS.has(opts.format)) {
      if (!det.docs) {
        const split = splitJsonDocuments(text, L.maxJsonDocs);
        if (split.error) return failZone(zone, fatalIssue('INVALID_JSON', { position: split.error.position, reason: split.error.reason }, 'invalid JSON'));
        det.docs = split.docs;
        det.docsTruncated = split.truncated;
      }
    } else if (opts.format === 'bind' && det.format !== 'bind') {
      det.dialect = 'generic';
      det.markers = [];
    }
    det.format = opts.format;
    det.fatal = null;
    if (det.format !== 'bind') det.dialect = null;
  } else {
    det = detectInternal(text, filename, L.maxJsonDocs);
    if (det.fatal) return failZone(zone, det.fatal);
  }
  zone.format = det.format;
  zone.dialect = det.format === 'bind' ? (det.dialect || 'generic') : null;
  zone.markers = det.markers;
  zone.sources[0].format = zone.format;
  zone.sources[0].dialect = zone.dialect;

  const lines = splitLines(text);
  zone.stats.lines = lines.length;
  const b = new Builder(L, source, issues);
  let res;
  if (zone.format === 'bind') res = parseBind(text, lines, zone, b, opts);
  else if (zone.format === 'cloudflare-api') {
    if (det.docsTruncated) issues.add('RECORDS_TRUNCATED', 0, { max: L.maxJsonDocs, unit: 'documents' }, 'too many pasted pages');
    res = parseCloudflareApi(det.docs, zone, b, opts);
  } else if (zone.format === 'route53') {
    if (det.docsTruncated) issues.add('RECORDS_TRUNCATED', 0, { max: L.maxJsonDocs, unit: 'documents' }, 'too many pasted pages');
    res = parseRoute53(det.docs, zone, b, opts);
  } else if (zone.format === 'desec-api' || zone.format === 'digitalocean-api') {
    if (det.docsTruncated) issues.add('RECORDS_TRUNCATED', 0, { max: L.maxJsonDocs, unit: 'documents' }, 'too many pasted pages');
    res = zone.format === 'desec-api' ? parseDesecApi(det.docs, zone, b, opts) : parseDigitalOceanApi(det.docs, zone, b, opts);
  } else if (zone.format === 'octodns') res = parseOctodns(text, zone, b, opts);
  else res = parsePlesk(text, lines, zone, b, opts);
  if (res.fatal) {
    const keepFormat = res.fatal.code === 'API_ERROR' || res.fatal.code === 'ORIGIN_REQUIRED' || res.fatal.code === 'YAML_UNSUPPORTED';
    if (!keepFormat) {
      zone.format = null;
      zone.dialect = null;
      zone.sources[0].format = null;
      zone.sources[0].dialect = null;
    }
    return failZone(zone, res.fatal);
  }
  if (det.docsTruncated || b.truncated) zone.partial = true;

  // missing trailing dot on relative RDATA names whose served form has no records
  const owners = new Set(b.records.map((r) => r.name));
  for (const rt of b.relTargets) {
    const served = rt.rec.targets[rt.index];
    if (owners.has(served) || !looksLikeFqdn(rt.rel, rt.relLabels)) continue;
    if (!rt.rec.intendedTargets) rt.rec.intendedTargets = rt.rec.targets.slice();
    rt.rec.intendedTargets[rt.index] = rt.rel;
    issues.add('TARGET_MISSING_TRAILING_DOT', rt.rec.line, { name: rt.rec.name, target: served, intended: rt.rel },
      `target "${rt.rel}" has no trailing dot: served as ${served}`, { name: rt.rec.name, type: rt.rec.type });
  }
  // names outside the zone
  if (zone.origin && zone.origin !== '.') {
    const seen = new Set();
    for (const r of b.records) {
      if (seen.has(r.name) || r.name === zone.origin || r.name.endsWith(`.${zone.origin}`)) continue;
      seen.add(r.name);
      issues.add('OUT_OF_ZONE', r.line, { name: r.name, origin: zone.origin }, `${r.name} is outside ${zone.origin}`, { name: r.name, type: r.type });
    }
  }
  zone.records = finalizeRecords(b.records);
  zone.warnings = issues.finish();
  const st = zone.stats;
  st.entries = b.entries;
  st.records = zone.records.length;
  st.skipped = b.skipped;
  st.generated = b.generated;
  for (const r of zone.records) {
    st.byType[r.type] = (st.byType[r.type] || 0) + 1;
    if (r.proxied === true) st.proxied++;
    else if (r.proxied === false) st.dnsOnly++;
  }
  return zone;
}

/* ------------------------------------------------------------------------ */
/* Helpers on parsed zones                                                  */
/* ------------------------------------------------------------------------ */

function canonName(n) {
  let s = String(n ?? '').toLowerCase();
  if (s.endsWith('.') && !isEscapedAt(s, s.length - 1)) s = s.slice(0, -1);
  return s === '.' ? '' : s;
}

function canonB64(s) {
  try {
    const bytes = base64Decode(String(s));
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return typeof btoa === 'function' ? btoa(bin) : String(s);
  } catch {
    return String(s);
  }
}

function listOf(v) {
  return Array.isArray(v) ? v.map(String) : v === undefined || v === null ? [] : [String(v)];
}

/** Stable JSON with sorted keys (fallback key for shapes without a dedicated rule). */
function stableJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (v instanceof Date) return JSON.stringify(v.toISOString());
  if (Array.isArray(v)) return `[${v.map(stableJson).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stableJson(v[k])}`).join(',')}}`;
}

/**
 * THE canonical comparison key of one RDATA — applied to `ZoneRecord.data` and to dnswire
 * `rr.data` of live answers alike. Root names ('.' or '') map to ''.
 * @param {string} type
 * @param {any} data
 * @returns {string}
 */
export function rdataKey(type, data) {
  if (data === null || data === undefined) return '';
  const t = String(type).toUpperCase();
  try {
    switch (t) {
      case 'A':
      case 'AAAA':
        return normalizeIP(String(data)) ?? String(data).toLowerCase();
      case 'NS': case 'CNAME': case 'PTR': case 'DNAME':
        return canonName(data);
      case 'MX':
        return `${data.preference} ${canonName(data.exchange)}`;
      case 'SRV':
        return `${data.priority} ${data.weight} ${data.port} ${canonName(data.target)}`;
      case 'TXT':
      case 'SPF':
        return JSON.stringify(listOf(data));
      case 'CAA':
        return `${data.flags} ${String(data.tag).toLowerCase()} ${data.value}`;
      case 'DS':
      case 'CDS':
        return `${data.keyTag} ${data.algorithm} ${data.digestType} ${String(data.digest).toLowerCase()}`;
      case 'TLSA':
      case 'SMIMEA':
        return `${data.usage} ${data.selector} ${data.matchingType} ${String(data.data).toLowerCase()}`;
      case 'SSHFP':
        return `${data.algorithm} ${data.fpType} ${String(data.fingerprint).toLowerCase()}`;
      case 'SOA':
        return String(data.serial);
      case 'DNSKEY':
      case 'CDNSKEY':
        return `${data.flags} ${data.protocol} ${data.algorithm} ${canonB64(data.publicKey)}`;
      case 'SVCB':
      case 'HTTPS': {
        const p = data.params && typeof data.params === 'object' ? data.params : {};
        const parts = Object.keys(p).sort().map((k) => {
          const v = p[k];
          if (k === 'ipv4hint' || k === 'ipv6hint') return `${k}=${listOf(v).map((x) => normalizeIP(x) ?? x).sort().join(',')}`;
          if (k === 'mandatory') return `${k}=${listOf(v).slice().sort().join(',')}`;
          if (k === 'alpn') return `${k}=${JSON.stringify(listOf(v))}`;
          if (k === 'ech') return `${k}=${canonB64(v)}`;
          if (v === true) return k;
          if (Array.isArray(v)) return `${k}=${v.join(',')}`;
          return `${k}=${String(v).toLowerCase()}`;
        });
        return [`${data.priority} ${canonName(data.target)}`, ...parts].join(' ');
      }
      case 'NAPTR':
        return `${data.order} ${data.preference} ${JSON.stringify([String(data.flags).toLowerCase(), String(data.services).toLowerCase(), data.regexp])} ${canonName(data.replacement)}`;
      case 'URI':
        return `${data.priority} ${data.weight} ${data.target}`;
      case 'HINFO':
        return JSON.stringify([data.cpu, data.os]);
      case 'RP':
        return `${canonName(data.mbox)} ${canonName(data.txt)}`;
      case 'AFSDB':
        return `${data.subtype} ${canonName(data.hostname)}`;
      case 'KX':
        return `${data.preference} ${canonName(data.exchanger)}`;
      case 'OPENPGPKEY':
        return canonB64(data);
      default:
        return typeof data === 'string' ? data.toLowerCase() : stableJson(data);
    }
  } catch {
    return stableJson(data);
  }
}

/**
 * TXT/SPF strings joined (chunking-insensitive comparison); '' for other types.
 * @param {string} type
 * @param {any} data
 * @returns {string}
 */
export function txtJoinedKey(type, data) {
  const t = String(type).toUpperCase();
  if ((t !== 'TXT' && t !== 'SPF') || data === null || data === undefined) return '';
  return listOf(data).join('');
}

/**
 * Records without duplicates (`duplicateOf` set), file order.
 * @param {object} zone
 * @returns {object[]}
 */
export function uniqueRecords(zone) {
  return (zone && Array.isArray(zone.records) ? zone.records : []).filter((r) => r.duplicateOf === undefined);
}

/**
 * Unique served owner names, `sortHostnames` order.
 * @param {object} zone
 * @returns {string[]}
 */
export function zoneNames(zone) {
  return sortHostnames([...new Set((zone && Array.isArray(zone.records) ? zone.records : []).map((r) => r.name))]);
}

const nodeCache = new WeakMap();

/** Every owner plus every ancestor inside the origin (empty non-terminals exist too). */
function zoneNodes(zone) {
  let entry = nodeCache.get(zone);
  if (entry && entry.records === zone.records && entry.count === zone.records.length) return entry;
  const owners = new Set();
  const nodes = new Set();
  const origin = zone.origin && zone.origin !== '.' ? zone.origin : null;
  for (const r of zone.records) {
    owners.add(r.name);
    let n = r.name;
    while (n && !nodes.has(n)) {
      nodes.add(n);
      if (origin && n === origin) break;
      const dot = n.indexOf('.');
      if (dot < 0) break;
      n = n.slice(dot + 1);
      if (origin && !(n === origin || n.endsWith(`.${origin}`))) break;
    }
  }
  entry = { records: zone.records, count: zone.records.length, owners, nodes };
  nodeCache.set(zone, entry);
  return entry;
}

/**
 * DNS wildcard coverage (RFC 4592): the in-file `*.<closest encloser>` owner that would answer
 * `name`, or null. A name that exists (as an owner or an empty non-terminal) is never covered,
 * and the wildcard only applies directly below the closest encloser.
 * `a.b.apps.example.com` is covered by `*.apps.example.com` unless `b.apps.example.com` exists.
 * @param {object} zone
 * @param {string} name
 * @returns {string|null}
 */
export function wildcardCovers(zone, name) {
  if (!zone || !Array.isArray(zone.records) || typeof name !== 'string') return null;
  const n = canonName(name);
  if (!n) return null;
  const { owners, nodes } = zoneNodes(zone);
  if (nodes.has(n)) return null;
  let cur = n;
  for (;;) {
    const dot = cur.indexOf('.');
    if (dot < 0) return null;
    cur = cur.slice(dot + 1);
    if (nodes.has(cur)) {
      const w = `*.${cur}`;
      return owners.has(w) ? w : null;
    }
  }
}

/* ------------------------------------------------------------------------ */
/* toBindText                                                               */
/* ------------------------------------------------------------------------ */

const AWS_POLICY_OUT = {
  weighted: 'WEIGHTED', geolocation: 'GEOLOCATION', latency: 'LATENCY', failover: 'FAILOVER',
  multivalue: 'MULTIVALUE', 'ip-based': 'CIDR', geoproximity: 'GEOPROXIMITY'
};

/** RDATA text that BIND can read back (no bare `;`, `(`, `)`, balanced quotes, no controls). */
function bindSafe(text) {
  let inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false;
    if (c === 0x5c) {
      i++;
      continue;
    }
    if (c === 0x22) inQ = !inQ;
    else if (!inQ && (c === 0x3b || c === 0x28 || c === 0x29)) return false;
  }
  return !inQ;
}

function tagValueOut(v) {
  return /["=,\\\s;]/.test(v) ? JSON.stringify(v) : v;
}

/**
 * The comment a BIND line carries for a record (' ; …', or ''): Route 53 routing in cli53 syntax,
 * else the Cloudflare tags and flags as `cf_tags=` after the free comment — what this parser reads
 * back from any BIND file. Shared by {@link toBindText} and lib/zoneconvert.js.
 * @param {object} r ZoneRecord
 * @returns {string}
 */
export function bindComment(r) {
  return recordComment(r);
}

function recordComment(r) {
  if (r.routing && AWS_POLICY_OUT[r.routing.policy]) {
    const parts = [`routing=${JSON.stringify(AWS_POLICY_OUT[r.routing.policy])}`];
    if (r.routing.weight !== undefined) parts.push(`weight=${r.routing.weight}`);
    if (r.routing.geo) {
      for (const k of ['continentCode', 'countryCode', 'subdivisionCode']) if (r.routing.geo[k]) parts.push(`${k}=${JSON.stringify(r.routing.geo[k])}`);
    }
    if (r.routing.region) parts.push(`region=${JSON.stringify(r.routing.region)}`);
    if (r.routing.failover) parts.push(`failover=${JSON.stringify(r.routing.failover)}`);
    if (r.routing.healthCheck) parts.push(`healthCheckId=${JSON.stringify(r.routing.healthCheck)}`);
    if (r.routing.id !== null && r.routing.id !== undefined) parts.push(`identifier=${JSON.stringify(r.routing.id)}`);
    return ` ; AWS ${parts.join(' ')}`;
  }
  const tags = [];
  if (r.tags) {
    for (const k of Object.keys(r.tags)) {
      if (/[:,\s]/.test(k) || !k) continue;
      tags.push(r.tags[k] === '' ? k : `${k}:${tagValueOut(r.tags[k])}`);
    }
  }
  if (r.flattenCname) tags.push('cf-flatten-cname');
  if (r.proxied === true || r.proxied === false) tags.push(`cf-proxied:${r.proxied}`);
  const free = r.comment ? r.comment : '';
  if (!tags.length && !free) return '';
  if (!tags.length) {
    const safeFree = /^\s*AWS\s/.test(free) ? `note: ${free}` : free;
    return free.includes('cf_tags=') ? ` ; ${safeFree} cf_tags=` : ` ; ${safeFree}`;
  }
  return ` ; ${free ? `${/^\s*AWS\s/.test(free) ? `note: ${free}` : free} ` : ''}cf_tags=${tags.join(',')}`;
}

/**
 * Canonical BIND text of a zone: absolute names, one record per line, dnswire RDATA text,
 * Cloudflare flags as `cf_tags=`, Route 53 aliases / routing in cli53 syntax. Invalid records
 * (and unsupported ones whose text BIND could not read back) are written as comments.
 * @param {object} zone
 * @param {{ header?: boolean }} [opts]
 * @returns {string}
 */
export function toBindText(zone, { header = true } = {}) {
  const out = [];
  const records = zone && Array.isArray(zone.records) ? zone.records : [];
  if (header) {
    out.push('; DomainScope zone export (canonical BIND)');
    if (zone && zone.origin) out.push(`; origin: ${zone.origin}`);
    out.push(`; source format: ${(zone && zone.format) || 'unknown'}${zone && zone.dialect ? ` (${zone.dialect})` : ''}`);
  }
  if (zone && zone.origin && zone.origin !== '.') out.push(`$ORIGIN ${fqdn(zone.origin)}`);
  for (const r of records) {
    const ttl = r.ttl === null || r.ttl === undefined ? '' : `${r.ttl} `;
    const owner = fqdn(r.name);
    if (r.alias) {
      out.push(`${owner} ${ttl}AWS ALIAS ${r.type} ${fqdn(r.alias.target)} ${r.alias.zoneId && !/\s/.test(r.alias.zoneId) ? r.alias.zoneId : '$self'} ${r.alias.evaluateTargetHealth ? 'true' : 'false'}${recordComment(r)}`);
      continue;
    }
    if (r.invalid || (r.unsupported && !bindSafe(r.text))) {
      out.push(`; not exported (${r.invalid ? 'invalid' : 'unsupported'}): ${owner} ${ttl}IN ${r.type} ${safeText(r.text, 2000)}`);
      continue;
    }
    out.push(`${owner} ${ttl}IN ${r.type} ${r.text}${recordComment(r)}`);
  }
  return `${out.join('\n')}\n`;
}

/* ------------------------------------------------------------------------ */
/* mergeZones                                                               */
/* ------------------------------------------------------------------------ */

/**
 * Merge zones that share an origin (several files, a BIND file plus its `$INCLUDE` part).
 * Ids are renumbered; `source` indexes the merged `sources`. Zones with a fatal issue contribute
 * no records (their fatal issue is listed as a warning). Different origins → fatal ORIGIN_MISMATCH.
 * An INCLUDE_REJECTED whose path names another merged file (one without a fatal issue) becomes
 * INCLUDE_MERGED.
 * @param {object[]} zones
 * @param {{ limits?: object, lead?: object|null }} [opts] `lead`: the zone (one of `zones`) whose
 *   format, dialect, origin and `$TTL` the merge takes; default: the first with a confident origin
 * @returns {object} Zone
 */
export function mergeZones(zones, { limits = ZONE_LIMITS, lead: chosen = null } = {}) {
  const L = { ...ZONE_LIMITS, ...limits };
  const list = Array.isArray(zones) ? zones.filter((z) => z && typeof z === 'object' && Array.isArray(z.records)) : [];
  const merged = newZone({ filename: '', bytes: 0 });
  merged.sources = [];
  if (!list.length) return failZone(merged, fatalIssue('EMPTY', {}, 'nothing to merge'));
  const good = list.filter((z) => !z.fatal);
  const origins = [...new Set(good.map((z) => z.origin).filter((x) => x))];
  if (origins.length > 1) {
    merged.sources = list.flatMap((z) => z.sources || []);
    return failZone(merged, fatalIssue('ORIGIN_MISMATCH', { origins }, 'the files belong to different zones'));
  }
  if (!good.length) {
    merged.sources = list.flatMap((z) => z.sources || []);
    return failZone(merged, list[0].fatal);
  }
  const lead = (chosen && good.includes(chosen) ? chosen : null)
    || good.find((z) => z.originConfidence === 'high' && z.origin) || good.find((z) => z.origin) || good[0];
  merged.format = lead.format;
  merged.dialect = lead.dialect;
  merged.origin = lead.origin;
  merged.originSource = lead.originSource;
  merged.originConfidence = lead.originConfidence;
  merged.defaultTtl = lead.defaultTtl ?? null;
  const markers = new Set();
  const names = new Set();
  for (const z of good) for (const s of z.sources || []) if (s && s.name) names.add(String(s.name).split(/[\\/]/).pop().toLowerCase());
  const records = [];
  const warnings = [];
  let offset = 0;
  let truncated = false;
  for (const z of list) {
    const srcs = Array.isArray(z.sources) && z.sources.length ? z.sources : [{ name: '', size: 0, format: z.format, dialect: z.dialect }];
    const single = srcs.length === 1;
    for (const m of z.markers || []) markers.add(m);
    const mapSource = (s) => offset + (single ? 0 : Number.isInteger(s) ? s : 0);
    if (z.fatal) {
      warnings.push({ ...z.fatal, severity: 'error', source: offset });
    } else {
      for (const w of z.warnings || []) {
        let issue = { ...w, source: mapSource(w.source) };
        if (w.code === 'INCLUDE_REJECTED' && w.params && typeof w.params.path === 'string') {
          const base = w.params.path.split(/[\\/]/).pop().toLowerCase();
          const ownName = String(srcs[single ? 0 : w.source]?.name ?? '').split(/[\\/]/).pop().toLowerCase();
          if (base && base !== ownName && names.has(base)) issue = { ...issue, code: 'INCLUDE_MERGED', severity: 'info', detail: 'included file merged' };
        }
        warnings.push(issue);
      }
      for (const r of z.records) {
        if (records.length >= L.maxRecords) {
          truncated = true;
          break;
        }
        records.push({ ...r, source: mapSource(r.source) });
      }
      if (z.partial) merged.partial = true;
      if (z.changeBatch) {
        merged.changeBatch = merged.changeBatch || { upserts: 0, deletes: [] };
        merged.changeBatch.upserts += z.changeBatch.upserts;
        merged.changeBatch.deletes.push(...z.changeBatch.deletes);
      }
      const st = z.stats || {};
      for (const k of ['bytes', 'lines', 'entries', 'skipped', 'generated', 'elapsedMs']) merged.stats[k] += Number(st[k]) || 0;
    }
    merged.sources.push(...srcs);
    offset += srcs.length;
  }
  if (truncated) {
    merged.partial = true;
    warnings.push({ code: 'RECORDS_TRUNCATED', severity: 'error', line: 0, source: 0, params: { max: L.maxRecords, unit: 'records' }, detail: 'merged zone too large' });
  }
  merged.markers = [...markers];
  merged.records = finalizeRecords(records.map((r) => {
    const x = { ...r };
    delete x.duplicateOf;
    return x;
  }));
  merged.warnings = warnings.length > L.maxIssues
    ? [...warnings.slice(0, L.maxIssues), { code: 'WARNINGS_TRUNCATED', severity: 'info', line: 0, source: 0, params: { max: L.maxIssues, dropped: warnings.length - L.maxIssues }, detail: 'further issues not listed' }]
    : warnings;
  const st = merged.stats;
  st.records = merged.records.length;
  for (const r of merged.records) {
    st.byType[r.type] = (st.byType[r.type] || 0) + 1;
    if (r.proxied === true) st.proxied++;
    else if (r.proxied === false) st.dnsOnly++;
  }
  return merged;
}
