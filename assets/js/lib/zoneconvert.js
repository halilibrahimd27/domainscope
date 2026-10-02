/**
 * zoneconvert.js — an imported zone written for another tool or provider (Zone File › Convert):
 * an RFC 1035 zone file (BIND, with `$ORIGIN` and `$TTL`), a Route 53 change batch (UPSERT of
 * every record set, for `aws route53 change-resource-record-sets`), an octoDNS zone YAML and a
 * DNSControl `dnsconfig.js` (`D("example.com", REG_NONE, DnsProvider(…), A(…), …)`).
 *
 * - Nothing is dropped silently: a record a target cannot hold is left out (BIND and DNSControl
 *   keep it as a comment with the reason) and every such case, and every change of meaning, is a
 *   pitfall ({@link PITFALL_CODES}, severity per target): a CNAME at the apex (BIND and Route 53
 *   cannot serve it; octoDNS and DNSControl write ALIAS), TXT over 255 bytes (how each format
 *   splits it), Route 53 aliases (no BIND or octoDNS equivalent; DNSControl's R53_ALIAS),
 *   Cloudflare's proxy flag (a cf_tags comment in BIND, lost in Route 53,
 *   `octodns.cloudflare.proxied`, `CF_PROXY_ON`), CAA flags and tags, the record types each
 *   target supports ({@link TARGET_TYPES}) or has but this module cannot write
 *   ({@link TARGET_BY_HAND}), wildcards, duplicates, routing policies, DNSSEC records, the SOA
 *   and the apex NS (the new provider writes its own), names outside the zone.
 * - Every file reads back: lib/zoneparse.js parses the BIND, Route 53 and octoDNS outputs into
 *   the same record sets (lib/zonediff.js finds no difference), less what the pitfalls say was
 *   left out (`omitted`) or written differently (`changed`: an apex CNAME as ALIAS). octoDNS and
 *   DNSControl keep a TXT value as one text (both split it again at 255 bytes), so they compare
 *   with `joinTxt`.
 * - octoDNS refuses a file whose keys are out of order (YamlProvider `enforce_order`, natural
 *   order by default): every mapping is written in that order ({@link naturalCompare}).
 *
 * Pure, synchronous and DOM-free; nothing is sent or stored. Runs in browsers and Node 22.
 */

import { bindComment, GTLDS } from './zoneparse.js';
import { relativeName, canonicalName } from './zonediff.js';

/* ------------------------------------------------------------------------ */
/* Vocabulary                                                               */
/* ------------------------------------------------------------------------ */

/** Output formats. */
export const CONVERT_TARGETS = Object.freeze(['bind', 'route53', 'octodns', 'dnscontrol']);

/** The name of each target as the texts write it (a product name: the same in every language). */
export const TARGET_NAMES = Object.freeze({ bind: 'BIND', route53: 'Route 53', octodns: 'octoDNS', dnscontrol: 'DNSControl' });

/** Media type of each output (for the download). */
export const CONVERT_MIME = Object.freeze({
  bind: 'text/plain;charset=utf-8', route53: 'application/json;charset=utf-8', octodns: 'application/yaml;charset=utf-8', dnscontrol: 'text/javascript;charset=utf-8'
});

/**
 * Record types this module writes for each target (BIND: every type the parser could read).
 * Route 53: its supported types (HTTPS, SVCB, SSHFP and TLSA since 2024); octoDNS: its record
 * types (HTTPS and SVCB since 1.8) that lib/zoneparse.js reads back from its YAML; DNSControl:
 * the record functions it has. The apex SOA and NS, DNSSEC records and provider pseudo-types
 * (ALIAS / ANAME, {@link PSEUDO_TYPES}) are handled on their own.
 */
export const TARGET_TYPES = Object.freeze({
  bind: null,
  route53: Object.freeze(['A', 'AAAA', 'CAA', 'CNAME', 'DS', 'HTTPS', 'MX', 'NAPTR', 'NS', 'PTR', 'SPF', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT']),
  octodns: Object.freeze(['A', 'AAAA', 'CAA', 'CNAME', 'DNAME', 'DS', 'HTTPS', 'MX', 'NAPTR', 'NS', 'OPENPGPKEY', 'PTR', 'SPF', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT', 'URI']),
  dnscontrol: Object.freeze(['A', 'AAAA', 'CAA', 'CNAME', 'DNAME', 'DS', 'HTTPS', 'MX', 'NAPTR', 'NS', 'OPENPGPKEY', 'PTR', 'RP', 'SMIMEA', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT'])
});

/**
 * Record types a target has but this module cannot write from a zone file (lib/zoneparse.js
 * keeps their value as text, or the target's form needs more than the file says): left out with
 * the pitfall `by-hand`, never called unsupported.
 */
export const TARGET_BY_HAND = Object.freeze({
  bind: Object.freeze([]),
  route53: Object.freeze([]),
  octodns: Object.freeze(['LOC', 'URLFWD']),
  dnscontrol: Object.freeze(['DHCID', 'LOC'])
});

/** Records a DNSSEC signer makes: the new provider signs the zone itself. */
export const DNSSEC_TYPES = Object.freeze(['DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'CDS', 'CDNSKEY']);
/** Provider pseudo-types a BIND server does not serve. */
export const PSEUDO_TYPES = Object.freeze(['ALIAS', 'ANAME', 'URLFWD']);
/** Pseudo-types that name one target host: DNSControl writes them as ALIAS(…), octoDNS at the apex as an ALIAS record. */
const PSEUDO_ALIAS = Object.freeze(['ALIAS', 'ANAME']);
/**
 * SvcParamKeys octoDNS takes by name (its SUPPORTED_PARAMS, less `ech`: its check of a valid ech
 * value fails with a TypeError, octoDNS 1.8–1.22); the others go by number, `key<N>`, which
 * octoDNS passes on unchecked and which mean the same on the wire.
 */
export const OCTODNS_SVC_KEYS = Object.freeze(['mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ipv6hint']);
/** Owner names octoDNS accepts for SRV and URI records (its srv-name / uri-name checks: `_service._proto` or a wildcard). */
const OCTODNS_SERVICE_NAME = /^(\*|_[^.]+)\.[^.]+/;
/** The numbers of the named SvcParamKeys (RFC 9460 and the IANA registry; lib/zoneparse.js reads `key<N>` back by them). */
const SVC_KEY_NUMBERS = Object.freeze({
  mandatory: 0, alpn: 1, 'no-default-alpn': 2, port: 3, ipv4hint: 4, ech: 5, ipv6hint: 6, dohpath: 7, ohttp: 8, 'tls-supported-groups': 9
});
/** Route 53 routing policies a change batch can carry (the parser reads them back). */
export const ROUTE53_ROUTING = Object.freeze(['weighted', 'latency', 'failover', 'geolocation', 'multivalue']);
/** Route 53 takes at most this many records in one change batch. */
export const ROUTE53_BATCH_MAX = 1000;
/**
 * CAA tags every provider knows (the IANA registry's, less the reserved ones); another tag may be
 * refused. DNSControl accepts exactly these: `dnscontrol check` refuses the file over any other.
 */
export const CAA_COMMON_TAGS = Object.freeze(['issue', 'issuewild', 'iodef', 'issuemail', 'issuevmc', 'contactemail', 'contactphone']);
/** The TTL of a record without one where the target needs one (unless the zone has a `$TTL`). */
export const CONVERT_DEFAULT_TTL = 3600;
/** Placeholder of a Route 53 alias whose hosted zone the source does not name. */
export const ALIAS_ZONE_PLACEHOLDER = 'HOSTED_ZONE_ID_OF_THE_TARGET';
/** The DNSControl provider's name in the file (the entry of creds.json). */
export const DNSCONTROL_PROVIDER = 'main';

/**
 * Pitfalls: code → severity per target (a target without an entry never raises it).
 * - error: the target cannot serve the record and the zone will not work as before;
 * - warn: left out, or its meaning changes;
 * - info: written differently, or something to know.
 */
export const PITFALL_SEVERITY = Object.freeze({
  'cname-apex': { bind: 'warn', route53: 'error', octodns: 'info', dnscontrol: 'info' },
  'cname-alone': { bind: 'error', route53: 'error', octodns: 'error', dnscontrol: 'error' },
  'r53-alias': { bind: 'warn', octodns: 'warn', dnscontrol: 'info' },
  'alias-zone-id': { route53: 'warn' },
  'alias-record': { octodns: 'info', dnscontrol: 'info' },
  proxied: { bind: 'info', route53: 'warn', octodns: 'info', dnscontrol: 'info' },
  'proxied-mixed': { octodns: 'warn' },
  'cname-flatten': { bind: 'info', route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'txt-long': { bind: 'info', route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'txt-split': { octodns: 'info', dnscontrol: 'info' },
  'caa-flags': { route53: 'warn', octodns: 'warn', dnscontrol: 'warn' },
  'caa-tag': { route53: 'info', octodns: 'info', dnscontrol: 'warn' },
  'svc-key': { octodns: 'info' },
  'txt-lenient': { octodns: 'warn' },
  'name-lenient': { octodns: 'warn' },
  'unsupported-type': { bind: 'warn', route53: 'warn', octodns: 'warn', dnscontrol: 'warn' },
  'by-hand': { octodns: 'warn', dnscontrol: 'warn' },
  unreadable: { bind: 'warn', route53: 'warn', octodns: 'warn', dnscontrol: 'warn' },
  dnssec: { bind: 'warn', route53: 'warn', octodns: 'warn', dnscontrol: 'warn' },
  routing: { bind: 'warn', route53: 'warn', octodns: 'warn', dnscontrol: 'warn' },
  'out-of-zone': { bind: 'warn', route53: 'warn', octodns: 'warn', dnscontrol: 'warn' },
  'wildcard-inner': { bind: 'warn', route53: 'warn', octodns: 'warn', dnscontrol: 'warn' },
  'escaped-name': { route53: 'warn', octodns: 'warn', dnscontrol: 'warn' },
  'repeated-domain': { dnscontrol: 'warn' },
  'no-soa': { bind: 'warn' },
  soa: { route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'apex-ns': { route53: 'info', octodns: 'info', dnscontrol: 'info' },
  wildcard: { bind: 'info', route53: 'info', octodns: 'info', dnscontrol: 'info' },
  duplicate: { bind: 'info', route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'ttl-mixed': { route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'ttl-default': { route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'batch-size': { route53: 'info' }
});

/** Every pitfall code, in the order a list shows codes of one severity. */
export const PITFALL_CODES = Object.freeze(Object.keys(PITFALL_SEVERITY));

/** Codes worded per target (`zconv.pit.<code>.<target>`); the others share `zconv.pit.<code>`. */
export const PITFALL_VARIANTS = Object.freeze({
  'cname-apex': ['bind', 'route53', 'octodns', 'dnscontrol'],
  'r53-alias': ['bind', 'octodns', 'dnscontrol'],
  'alias-record': ['octodns', 'dnscontrol'],
  proxied: ['bind', 'route53', 'octodns', 'dnscontrol'],
  'txt-long': ['bind', 'route53', 'octodns', 'dnscontrol'],
  routing: ['bind', 'route53', 'octodns', 'dnscontrol'],
  'unsupported-type': ['bind'],
  unreadable: ['bind'],
  dnssec: ['bind'],
  'out-of-zone': ['bind'],
  'caa-flags': ['dnscontrol'],
  'caa-tag': ['dnscontrol'],
  wildcard: ['route53']
});

const SEVERITY_RANK = Object.freeze({ error: 0, warn: 1, info: 2 });

/**
 * The i18n key of a pitfall's text for a target.
 * @param {string} code one of {@link PITFALL_CODES}
 * @param {string} target one of {@link CONVERT_TARGETS}
 * @returns {string}
 */
export function pitfallKey(code, target) {
  const v = PITFALL_VARIANTS[code];
  return v && v.includes(target) ? `zconv.pit.${code}.${target}` : `zconv.pit.${code}`;
}

/** Every pitfall text key a target can need (the i18n coverage test). */
export function pitfallKeys() {
  const keys = new Set();
  for (const code of PITFALL_CODES) for (const target of Object.keys(PITFALL_SEVERITY[code])) keys.add(pitfallKey(code, target));
  return [...keys];
}

/* ------------------------------------------------------------------------ */
/* Strings shared with lib/fixes.js                                         */
/* ------------------------------------------------------------------------ */

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
 * with `octodns: lenient: true` (lib/fixes.js too): octoDNS then loads it with a warning.
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

/* ------------------------------------------------------------------------ */
/* Names and values                                                         */
/* ------------------------------------------------------------------------ */

/** A name with its root dot ('.' for the root). */
const fqdn = (name) => {
  const n = canonicalName(name);
  return n ? `${n}.` : '.';
};

/**
 * A presentation name (lib/zoneparse.js: `\DDD` decimal and `\X` escapes) in Route 53's form:
 * every byte outside a–z, 0–9, `-`, `_` (and a leftmost `*` label) as a three-digit octal escape.
 * @param {string} name
 * @returns {string} with the root dot
 */
export function route53Name(name) {
  const s = canonicalName(name);
  if (!s) return '.';
  let out = '';
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (c === '\\') {
      const digits = /^\d{3}/.exec(s.slice(i + 1, i + 4));
      const code = digits ? Number(digits[0]) : s.charCodeAt(i + 1);
      i += digits ? 3 : 1;
      out += /^[a-z0-9_-]$/.test(String.fromCharCode(code)) ? String.fromCharCode(code) : octal(code);
    } else if (c === '.' || /^[a-z0-9_-]$/.test(c)) {
      out += c;
    } else if (c === '*' && (i === 0 && (s[1] === '.' || s.length === 1))) {
      out += c;
    } else {
      for (const b of utf8.encode(c)) out += octal(b);
    }
  }
  return `${out}.`;
}

/** Decimal `\DDD` escapes of a presentation text as Route 53's octal ones (values it reads with base 8). */
function octalEscapes(text) {
  return String(text ?? '').replace(/\\(\d{3})|\\(.)/g, (m, d, ch) => {
    if (d !== undefined) return octal(Number(d));
    return `\\${ch}`;
  });
}

/** The text of a TXT data list as one string. */
const txtJoined = (data) => (Array.isArray(data) ? data : [data]).map((x) => String(x ?? '')).join('');
const byteLength = (s) => utf8.encode(String(s ?? '')).length;

/** Character-strings that are not the 255-byte split of their joined text (octoDNS re-splits them). */
function customChunks(data) {
  const list = Array.isArray(data) ? data : [data];
  if (list.length < 2) return false;
  return list.slice(0, -1).some((s) => byteLength(s) !== 255);
}

/** RDATA text a BIND server reads back (no bare `;`, `(`, `)`, balanced quotes, no controls). */
function bindSafe(text) {
  const s = String(text ?? '');
  let inQ = false;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false;
    if (c === 0x5c) {
      i += 1;
      continue;
    }
    if (c === 0x22) inQ = !inQ;
    else if (!inQ && (c === 0x3b || c === 0x28 || c === 0x29)) return false;
  }
  return !inQ && s.trim() !== '';
}

/** One line of comment text (no line break can end the comment). */
const commentText = (s) => String(s ?? '').replace(/[\r\n\u2028\u2029]+/g, ' ');

/** A JavaScript string literal (DNSControl): JSON's, with U+2028 / U+2029 escaped for older engines. */
const js = (s) => JSON.stringify(String(s ?? '')).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

/* ------------------------------------------------------------------------ */
/* The plan                                                                 */
/* ------------------------------------------------------------------------ */

/** Why a record is not written as it is, in English (BIND / DNSControl comments in the file). */
const COMMENT_REASON = Object.freeze({
  'cname-apex': 'CNAME at the apex: it cannot sit next to the SOA and NS records. Use A / AAAA records of the target (or ALIAS / ANAME where the server has it)',
  'r53-alias': 'Route 53 alias, no equivalent here: resolve the target and add its A / AAAA records, or keep this name at Route 53',
  unreadable: 'the value could not be read',
  'unsupported-type': 'not a record type this format holds',
  'by-hand': 'DomainScope cannot write this record type for this format: add it by hand',
  'caa-tag': 'a CAA tag DNSControl refuses',
  dnssec: 'DNSSEC record: the new provider signs the zone itself',
  'out-of-zone': 'outside the zone',
  soa: 'SOA: the provider writes its own',
  'apex-ns': 'NS at the apex: the provider serves its own name servers',
  routing: 'another routing variant of a CNAME: one CNAME per name'
});

/** Pitfall params that collect a list of values (types, flags …) over the records flagged. */
const LIST_PARAMS = Object.freeze(['types', 'flags', 'tags', 'keys']);

/** A pitfall collector for one conversion. */
function collector(target, origin) {
  const map = new Map();
  return {
    flag(code, r = null, extra = {}) {
      const severity = PITFALL_SEVERITY[code] && PITFALL_SEVERITY[code][target];
      if (!severity) return;
      let p = map.get(code);
      if (!p) {
        p = { code, severity, count: 0, names: [], params: { target: TARGET_NAMES[target] } };
        map.set(code, p);
      }
      p.count += 1;
      if (r) {
        const rel = relativeName(r.name, origin);
        if (!p.names.includes(rel)) p.names.push(rel);
      }
      for (const [k, v] of Object.entries(extra)) {
        if (LIST_PARAMS.includes(k)) {
          if (!Array.isArray(p.params[k])) p.params[k] = [];
          for (const x of [].concat(v)) if (!p.params[k].includes(x)) p.params[k].push(x);
        } else {
          p.params[k] = v;
        }
      }
    },
    list() {
      return [...map.values()].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
        || PITFALL_CODES.indexOf(a.code) - PITFALL_CODES.indexOf(b.code));
    }
  };
}

/** Is a record's owner inside the zone (at or below the origin)? */
function inZone(r, origin) {
  return !String(relativeName(r.name, origin)).endsWith('.');
}

/** Labels of a presentation name (an escaped dot does not split). */
function labelsOf(name) {
  const out = [];
  let cur = '';
  for (let i = 0; i < name.length; i += 1) {
    if (name[i] === '\\') {
      cur += name.slice(i, i + 2);
      i += 1;
    } else if (name[i] === '.') {
      out.push(cur);
      cur = '';
    } else {
      cur += name[i];
    }
  }
  if (cur || out.length) out.push(cur);
  return out;
}

/**
 * The host a provider's ALIAS / ANAME record names, with its root dot: its text is one name
 * (relative to the zone without a final dot, `@` for the apex). Null when the text is not one name.
 */
function pseudoTarget(r, origin) {
  const t = String(r.text ?? '').trim();
  if (!/^[^\s"';()]+$/.test(t)) return null;
  if (t === '@') return fqdn(origin);
  return fqdn(t.endsWith('.') && !t.endsWith('\\.') ? t : `${t}.${canonicalName(origin)}`);
}

/**
 * What happens to each record for a target: `write` (as it is), `alias` (a Route 53 alias the
 * target writes as one), `apex-alias` (an apex CNAME written as ALIAS), `pseudo-alias` (a
 * provider's ALIAS / ANAME written as ALIAS, its host in `to`), `comment` (BIND / DNSControl: a
 * comment line with the reason) or `omit` (left out), with the pitfalls it raises.
 */
function plan(zone, target, pits) {
  const origin = zone.origin;
  const types = TARGET_TYPES[target];
  const steps = [];
  const omitted = [];
  const changed = [];
  for (const r of zone.records) {
    if (r.duplicateOf !== undefined) {
      pits.flag('duplicate', r);
      omitted.push({ id: r.id, code: 'duplicate' });
      continue;
    }
    const type = String(r.type || '').toUpperCase();
    const apex = canonicalName(r.name) === canonicalName(origin);
    const leave = (code, keep = target === 'bind' ? 'comment' : 'omit', extra = code === 'unsupported-type' ? { types: type } : {}) => {
      pits.flag(code, r, extra);
      omitted.push({ id: r.id, code });
      steps.push({ r, action: keep, code });
    };
    if (r.invalid) {
      leave('unreadable');
      continue;
    }
    if (r.alias) {
      if (target === 'route53') steps.push({ r, action: 'alias' });
      else if (target === 'dnscontrol') {
        pits.flag('r53-alias', r);
        steps.push({ r, action: 'alias' });
      } else leave('r53-alias');
      continue;
    }
    if (origin && !inZone(r, origin)) {
      if (target === 'bind') {
        pits.flag('out-of-zone', r);
        steps.push({ r, action: 'write' });
      } else leave('out-of-zone', 'omit');
      continue;
    }
    if (DNSSEC_TYPES.includes(type)) {
      if (target === 'bind' && bindSafe(r.text)) {
        pits.flag('dnssec', r);
        steps.push({ r, action: 'write' });
      } else leave('dnssec', 'omit');
      continue;
    }
    if (type === 'SOA' && target !== 'bind') {
      leave('soa', 'omit');
      continue;
    }
    if (type === 'NS' && apex && target !== 'bind') {
      leave('apex-ns', 'omit');
      continue;
    }
    if (type === 'CNAME' && apex) {
      if (target === 'octodns' || target === 'dnscontrol') {
        pits.flag('cname-apex', r);
        changed.push({ id: r.id, code: 'cname-apex' });
        steps.push({ r, action: 'apex-alias' });
      } else leave('cname-apex', target === 'bind' ? 'comment' : 'omit');
      continue;
    }
    // A provider's ALIAS / ANAME: DNSControl has ALIAS(…) at any name, octoDNS an ALIAS record at the apex.
    if (PSEUDO_ALIAS.includes(type) && (target === 'dnscontrol' || (target === 'octodns' && apex))) {
      const to = pseudoTarget(r, origin);
      if (to === null) leave('unreadable', target === 'dnscontrol' ? 'comment' : 'omit');
      else {
        pits.flag('alias-record', r);
        if (type !== 'ALIAS') changed.push({ id: r.id, code: 'alias-record' });
        steps.push({ r, action: 'pseudo-alias', to });
      }
      continue;
    }
    if (TARGET_BY_HAND[target].includes(type)) {
      leave('by-hand', target === 'dnscontrol' ? 'comment' : 'omit', { types: type });
      continue;
    }
    if (r.data === null || r.data === undefined) {
      if (target === 'bind') {
        if (PSEUDO_TYPES.includes(type)) leave('unsupported-type');
        else if (bindSafe(r.text)) steps.push({ r, action: 'write' });
        else leave('unreadable');
      } else {
        leave(types.includes(type) ? 'unreadable' : 'unsupported-type', target === 'dnscontrol' ? 'comment' : 'omit');
      }
      continue;
    }
    if (types && !types.includes(type)) {
      leave('unsupported-type', target === 'dnscontrol' ? 'comment' : 'omit');
      continue;
    }
    // DNSControl refuses the whole file over a CAA tag it does not know: that record stays a comment.
    if (target === 'dnscontrol' && type === 'CAA' && !CAA_COMMON_TAGS.includes(String(r.data.tag || '').toLowerCase())) {
      leave('caa-tag', 'comment', { tags: String(r.data.tag || '').toLowerCase() });
      continue;
    }
    steps.push({ r, action: 'write' });
  }

  // Notes on what is written.
  for (const s of steps) {
    if (s.action === 'omit' || s.action === 'comment') continue;
    const { r } = s;
    const type = String(r.type || '').toUpperCase();
    if (r.proxied === true) pits.flag('proxied', r);
    if (r.flattenCname && s.action === 'write') pits.flag('cname-flatten', r);
    if ((type === 'TXT' || type === 'SPF') && Array.isArray(r.data)) {
      if (byteLength(txtJoined(r.data)) > 255) pits.flag('txt-long', r);
      // octoDNS and DNSControl keep one text and split it again every 255 bytes.
      if ((target === 'octodns' || target === 'dnscontrol') && customChunks(r.data)) pits.flag('txt-split', r);
    }
    if (type === 'CAA' && r.data && target !== 'bind') {
      const flags = Number(r.data.flags);
      if (flags !== 0 && flags !== 128) pits.flag('caa-flags', r, { flags });
      const tag = String(r.data.tag || '').toLowerCase();
      if (!CAA_COMMON_TAGS.includes(tag)) pits.flag('caa-tag', r, { tags: tag });
    }
    if (target === 'octodns' && (type === 'HTTPS' || type === 'SVCB') && r.data && r.data.params) {
      const byNumber = Object.keys(r.data.params).filter((k) => !OCTODNS_SVC_KEYS.includes(k) && SVC_KEY_NUMBERS[k] !== undefined);
      if (byNumber.length) pits.flag('svc-key', r, { keys: byNumber });
    }
    // What octoDNS's own checks refuse is written with `octodns: lenient: true`: loaded, with a warning.
    if (target === 'octodns' && (type === 'TXT' || type === 'SPF') && octodnsTxtRefused(octodnsTxt(r.data))) {
      pits.flag('txt-lenient', r);
      s.lenient = true;
    }
    if (target === 'octodns' && (type === 'SRV' || type === 'URI') && !OCTODNS_SERVICE_NAME.test(relativeName(r.name, origin))) {
      pits.flag('name-lenient', r, { types: type });
      s.lenient = true;
    }
    const labels = labelsOf(canonicalName(r.name));
    if (labels[0] === '*') pits.flag('wildcard', r);
    if (labels.slice(1).includes('*')) pits.flag('wildcard-inner', r);
    if (target !== 'bind' && canonicalName(r.name).includes('\\')) pits.flag('escaped-name', r);
    if (target !== 'bind' && !r.alias && !Number.isFinite(r.ttl)) pits.flag('ttl-default', r, { ttl: defaultTtl(zone) });
  }
  return { steps, omitted, changed };
}

/** The zone's `$TTL`, else the TTL most of its records have, else {@link CONVERT_DEFAULT_TTL}. */
function defaultTtl(zone) {
  if (Number.isFinite(zone.defaultTtl)) return zone.defaultTtl;
  return commonTtl(zone.records.map((r) => r.ttl)) ?? CONVERT_DEFAULT_TTL;
}

/** The most common finite TTL (ties: the lowest), or null. */
function commonTtl(ttls) {
  const n = new Map();
  for (const t of ttls) if (Number.isFinite(t)) n.set(t, (n.get(t) || 0) + 1);
  let best = null;
  for (const [t, c] of n) if (best === null || c > n.get(best) || (c === n.get(best) && t < best)) best = t;
  return best;
}

/**
 * Written records grouped into record sets (first-seen order), with the set's TTL: the lowest of
 * its values, a mixed set flagged `ttl-mixed`.
 */
function groupSets(steps, zone, pits, { routing = false } = {}) {
  const sets = new Map();
  for (const s of steps) {
    if (s.action === 'omit' || s.action === 'comment') continue;
    const type = s.action === 'apex-alias' || s.action === 'pseudo-alias' ? 'ALIAS' : String(s.r.type || '').toUpperCase();
    const rk = routing && s.r.routing && ROUTE53_ROUTING.includes(s.r.routing.policy) ? JSON.stringify([s.r.routing.policy, s.r.routing.id ?? null]) : '';
    const key = `${canonicalName(s.r.name)}|${type}|${rk}`;
    let set = sets.get(key);
    if (!set) {
      set = { name: canonicalName(s.r.name), type, routing: rk ? s.r.routing : null, steps: [], ttl: null };
      sets.set(key, set);
    }
    set.steps.push(s);
  }
  const fallback = defaultTtl(zone);
  for (const set of sets.values()) {
    const ttls = [...new Set(set.steps.map((s) => s.r.ttl).filter((t) => Number.isFinite(t)))].sort((a, b) => a - b);
    set.ttl = ttls.length ? ttls[0] : fallback;
    if (ttls.length > 1) pits.flag('ttl-mixed', set.steps[0].r);
  }
  return [...sets.values()];
}

/** Records that may sit next to a CNAME: its own DNSSEC records (RFC 4035 §2.5). */
const CNAME_COMPANIONS = Object.freeze(['RRSIG', 'NSEC', 'NSEC3']);

/**
 * A CNAME must be alone at its name (RFC 1034 §3.6.2, RFC 2181 §10.1): every target refuses a
 * CNAME next to other records, or several CNAMEs (Zone File › Problems lists them too).
 */
function flagCnameAlone(sets, pits) {
  const byName = new Map();
  for (const set of sets) {
    if (!byName.has(set.name)) byName.set(set.name, []);
    byName.get(set.name).push(set);
  }
  for (const list of byName.values()) {
    const cnames = list.filter((s) => s.type === 'CNAME');
    if (!cnames.length) continue;
    const others = list.some((s) => s.type !== 'CNAME' && !CNAME_COMPANIONS.includes(s.type));
    const several = cnames.some((s) => new Set(s.steps.map((st) => canonicalName(st.r.data))).size > 1);
    if (others || several) pits.flag('cname-alone', cnames[0].steps[0].r);
  }
}

/** Routing variants a target has no place for: flagged, and a CNAME keeps its first value only. */
function mergeRouting(sets, pits, target, omitted) {
  for (const set of sets) {
    const routed = set.steps.filter((s) => s.r.routing);
    if (!routed.length || set.routing) continue;
    for (const s of routed) pits.flag('routing', s.r);
    if (set.type === 'CNAME' && set.steps.length > 1) {
      for (const s of set.steps.slice(1)) {
        omitted.push({ id: s.r.id, code: 'routing' });
        s.action = target === 'bind' || target === 'dnscontrol' ? 'comment' : 'omit';
        s.code = 'routing';
      }
      set.steps = set.steps.slice(0, 1);
    }
  }
}

/* ------------------------------------------------------------------------ */
/* BIND                                                                     */
/* ------------------------------------------------------------------------ */

function bindText(zone, steps, sets, pits, about) {
  const origin = zone.origin;
  const ttlDefault = defaultTtl(zone);
  // Relative to $ORIGIN; a relative name that looks like a whole domain name ('example.com' under
  // example.com, a 'www.example.com' a file meant without its dot) is written absolute, so nobody
  // reading the file (a name server's linter, this parser) takes it for a missing trailing dot.
  const owner = (r) => {
    const rel = relativeName(r.name, origin);
    if (rel === '@' || rel.endsWith('.')) return rel;
    const labels = labelsOf(rel);
    const last = labels[labels.length - 1];
    return labels.length >= 2 && (/^[a-z]{2}$/.test(last) || GTLDS.includes(last)) ? fqdn(r.name) : rel;
  };
  const written = steps.filter((s) => s.action === 'write' || s.action === 'comment');
  const width = Math.min(40, Math.max(1, ...written.map((s) => owner(s.r).length)));
  const line = (r) => {
    const ttl = Number.isFinite(r.ttl) ? String(r.ttl) : '';
    return `${owner(r).padEnd(width)} ${ttl.padStart(6)} IN ${String(r.type).padEnd(5)} ${r.text}`;
  };
  const out = [
    `; ${origin} as an RFC 1035 zone file (BIND), written by DomainScope from ${about}.`,
    '; Records that cannot be served as they are stay here as comments, with the reason.',
    `$ORIGIN ${fqdn(origin)}`,
    `$TTL ${ttlDefault}`
  ];
  // The SOA first, as a name server expects it; then the file order.
  const ordered = [...written.filter((s) => String(s.r.type).toUpperCase() === 'SOA'), ...written.filter((s) => String(s.r.type).toUpperCase() !== 'SOA')];
  if (!zone.records.some((r) => String(r.type).toUpperCase() === 'SOA' && r.duplicateOf === undefined)) {
    pits.flag('no-soa');
    out.push('; No SOA record in the source: add one before a name server loads this file.');
  }
  let count = 0;
  for (const s of ordered) {
    const { r } = s;
    if (s.action === 'comment') {
      out.push(`; ${commentText(COMMENT_REASON[s.code] || s.code)}:`);
      if (r.alias) out.push(`; ${owner(r)} ${r.type} ALIAS ${commentText(fqdn(r.alias.target))}`);
      else out.push(`; ${commentText(line(r))}`);
      continue;
    }
    out.push(`${line(r)}${commentText(bindComment(r))}`);
    count += 1;
  }
  return { text: `${out.join('\n')}\n`, written: count };
}

/* ------------------------------------------------------------------------ */
/* Route 53                                                                 */
/* ------------------------------------------------------------------------ */

/** One value of a Route 53 record set. */
function route53Value(r) {
  const type = String(r.type).toUpperCase();
  if (type === 'TXT' || type === 'SPF') return (Array.isArray(r.data) ? r.data : [r.data]).map(route53String).join(' ');
  if (type === 'CAA') return `${r.data.flags} ${String(r.data.tag).toLowerCase()} ${route53String(r.data.value)}`;
  if (type === 'A' || type === 'AAAA') return String(r.data);
  return octalEscapes(r.text);
}

/** The routing fields of a record set (the policies {@link ROUTE53_ROUTING} lists). */
function route53Routing(rt) {
  const out = { SetIdentifier: String(rt.id ?? '') };
  if (rt.policy === 'weighted') out.Weight = Number(rt.weight) || 0;
  if (rt.policy === 'latency') out.Region = String(rt.region || '');
  if (rt.policy === 'failover') out.Failover = String(rt.failover || 'PRIMARY').toUpperCase();
  if (rt.policy === 'geolocation') {
    const g = rt.geo || {};
    out.GeoLocation = {};
    if (g.continentCode) out.GeoLocation.ContinentCode = g.continentCode;
    if (g.countryCode) out.GeoLocation.CountryCode = g.countryCode;
    if (g.subdivisionCode) out.GeoLocation.SubdivisionCode = g.subdivisionCode;
  }
  if (rt.policy === 'multivalue') out.MultiValueAnswer = true;
  if (rt.healthCheck) out.HealthCheckId = String(rt.healthCheck);
  return out;
}

function route53Text(zone, steps, sets, pits, about) {
  const changes = [];
  let records = 0;
  for (const set of sets) {
    const first = set.steps[0].r;
    const rrs = { Name: route53Name(set.name), Type: set.type };
    if (set.routing) Object.assign(rrs, route53Routing(set.routing));
    if (set.steps[0].action === 'alias') {
      const a = first.alias;
      if (!a.zoneId) pits.flag('alias-zone-id', first);
      rrs.AliasTarget = { HostedZoneId: a.zoneId || ALIAS_ZONE_PLACEHOLDER, DNSName: route53Name(a.target), EvaluateTargetHealth: !!a.evaluateTargetHealth };
      records += 1;
    } else {
      const values = [...new Set(set.steps.map((s) => route53Value(s.r)))];
      rrs.TTL = set.ttl;
      rrs.ResourceRecords = values.map((Value) => ({ Value }));
      records += values.length;
    }
    changes.push({ Action: 'UPSERT', ResourceRecordSet: rrs });
  }
  if (records > ROUTE53_BATCH_MAX) pits.flag('batch-size', null, { max: ROUTE53_BATCH_MAX, records });
  const doc = { Comment: `${zone.origin}, written by DomainScope from ${about}`.slice(0, 256), Changes: changes };
  return { text: `${JSON.stringify(doc, null, 2)}\n`, written: records };
}

/* ------------------------------------------------------------------------ */
/* octoDNS                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Bytes as the text of a zone file character-string without quotes: printable ASCII as it is,
 * every other byte (and a space, `"`, `;`, `(`, `)`, `\`) as a `\DDD` decimal escape.
 */
function charStringText(bytes) {
  let out = '';
  for (const b of bytes) {
    if (b > 0x20 && b < 0x7f && ![0x22, 0x28, 0x29, 0x3b, 0x5c].includes(b)) out += String.fromCharCode(b);
    else out += `\\${String(b).padStart(3, '0')}`;
  }
  return out;
}

/** The bytes of a hex string (the parser keeps a SvcParam it has no name for as hex). */
const hexBytes = (hex) => (String(hex ?? '').match(/[0-9a-f]{2}/gi) || []).map((x) => parseInt(x, 16));

/** A SvcParamKey as octoDNS writes it: its own name, or `key<N>`. */
const octodnsSvcKey = (k) => (OCTODNS_SVC_KEYS.includes(k) || SVC_KEY_NUMBERS[k] === undefined ? k : `key${SVC_KEY_NUMBERS[k]}`);

/**
 * The `svcparams` mapping of an HTTPS / SVCB value (lib/zoneparse.js data `params`) as octoDNS
 * keeps it: lists for mandatory, alpn and the address hints, null for a key without a value,
 * the port as a number, any other value as the text after `key=` in a zone file.
 */
function octodnsSvcParams(params) {
  const out = {};
  const list = (v) => (Array.isArray(v) ? v : [v]).map((x) => String(x));
  for (const [k, v] of Object.entries(params || {})) {
    const key = octodnsSvcKey(k);
    if (k === 'mandatory') out[key] = list(v).map(octodnsSvcKey);
    else if (k === 'alpn' || k === 'ipv4hint' || k === 'ipv6hint') out[key] = list(v);
    else if (v === true) out[key] = null;
    else if (k === 'port') out[key] = Number(v);
    else if (k === 'ech') out[key] = String(v);
    else if (k === 'tls-supported-groups') out[key] = list(v).join(',');
    else if (k === 'dohpath') out[key] = charStringText(utf8.encode(String(v)));
    else out[key] = charStringText(hexBytes(v));
  }
  return out;
}

/** One octoDNS value (a scalar or a mapping) of a record. */
function octodnsValue(type, r) {
  const d = r.data;
  switch (type) {
    case 'A': case 'AAAA': return String(d);
    case 'CNAME': case 'DNAME': case 'PTR': case 'NS': return fqdn(d);
    case 'ALIAS': return fqdn(d);
    case 'MX': return { exchange: fqdn(d.exchange), preference: d.preference };
    case 'SRV': return { port: d.port, priority: d.priority, target: fqdn(d.target), weight: d.weight };
    case 'CAA': return { flags: d.flags, tag: String(d.tag).toLowerCase(), value: String(d.value) };
    case 'TXT': case 'SPF': return octodnsTxt(d);
    case 'TLSA': return { certificate_association_data: d.data, certificate_usage: d.usage, matching_type: d.matchingType, selector: d.selector };
    case 'SSHFP': return { algorithm: d.algorithm, fingerprint: d.fingerprint, fingerprint_type: d.fpType };
    case 'DS': return { algorithm: d.algorithm, digest: d.digest, digest_type: d.digestType, key_tag: d.keyTag };
    case 'NAPTR': return { flags: d.flags, order: d.order, preference: d.preference, regexp: d.regexp, replacement: fqdn(d.replacement), service: d.services };
    case 'HTTPS': case 'SVCB': {
      const v = { svcpriority: d.priority, targetname: fqdn(d.target) };
      const params = octodnsSvcParams(d.params);
      if (Object.keys(params).length) v.svcparams = params;
      return v;
    }
    case 'URI': return { priority: d.priority, target: String(d.target), weight: d.weight };
    case 'OPENPGPKEY': return String(d);
    default: return String(r.text);
  }
}

/** A YAML scalar of a number, a boolean, null (a key without a value) or a string. */
const yamlScalar = (v) => (v === null ? 'null' : typeof v === 'number' || typeof v === 'boolean' ? String(v) : yamlString(v));

/** Block YAML of a value at an indent, every mapping in natural key order. */
function yamlLines(value, indent) {
  const pad = ' '.repeat(indent);
  if (Array.isArray(value)) {
    const out = [];
    for (const item of value) {
      if (item && typeof item === 'object') {
        const inner = yamlLines(item, indent + 2);
        out.push(`${pad}- ${inner[0].slice(indent + 2)}`, ...inner.slice(1));
      } else {
        out.push(`${pad}- ${yamlScalar(item)}`);
      }
    }
    return out;
  }
  const out = [];
  for (const k of Object.keys(value).sort(naturalCompare)) {
    const v = value[k];
    if (v && typeof v === 'object') out.push(`${pad}${yamlString(k)}:`, ...yamlLines(v, indent + 2));
    else out.push(`${pad}${yamlString(k)}: ${yamlScalar(v)}`);
  }
  return out;
}

function octodnsText(zone, steps, sets, pits, about) {
  const origin = zone.origin;
  const byName = new Map();
  let records = 0;
  for (const set of sets) {
    const rel = relativeName(set.name, origin);
    const key = rel === '@' ? '' : rel;
    const rec = { ttl: set.ttl, type: set.type };
    const values = [];
    const seen = new Set();
    for (const s of set.steps) {
      const v = octodnsValue(set.type, s.action === 'pseudo-alias' ? { ...s.r, data: s.to } : s.r);
      const k = JSON.stringify(v);
      if (seen.has(k)) continue;
      seen.add(k);
      values.push(v);
    }
    records += values.length;
    // One value: `value`; several (a CNAME too, which the Problems tab flags): every one, never one silently.
    if (values.length === 1) rec.value = values[0];
    else rec.values = values;
    const flags = set.steps.map((s) => s.r.proxied).filter((p) => p === true || p === false);
    const cf = {};
    if (flags.length && ['A', 'AAAA', 'CNAME', 'ALIAS'].includes(set.type)) cf.proxied = flags.includes(true);
    if (set.steps.every((s) => s.r.ttlAuto)) cf['auto-ttl'] = true;
    const octo = {};
    if (Object.keys(cf).length) octo.cloudflare = cf;
    if (set.steps.some((s) => s.lenient)) octo.lenient = true;
    if (Object.keys(octo).length) rec.octodns = octo;
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key).push(rec);
  }
  const doc = {};
  for (const [key, recs] of byName) {
    recs.sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));
    doc[key] = recs.length === 1 ? recs[0] : recs;
  }
  const out = [
    `# ${origin} as an octoDNS zone (${origin}.yaml), written by DomainScope from ${about}.`,
    '# Keys are in octoDNS order; the SOA, the apex NS and what octoDNS cannot hold are left out (see the notes).',
    '---'
  ];
  for (const key of Object.keys(doc).sort(naturalCompare)) {
    const v = doc[key];
    out.push(`${key === '' ? "''" : yamlString(key)}:`, ...yamlLines(v, 2));
  }
  return { text: `${out.join('\n')}\n`, written: records };
}

/* ------------------------------------------------------------------------ */
/* DNSControl                                                               */
/* ------------------------------------------------------------------------ */

/** The HTTPS / SVCB parameters of a record's text (what follows the priority and the target). */
function svcParams(text) {
  const m = /^\s*\S+\s+\S+\s*(.*)$/.exec(String(text ?? ''));
  return m ? m[1].trim() : '';
}

/** One DNSControl record call (without modifiers). */
function dnscontrolCall(type, name, r) {
  const d = r.data;
  const n = js(name);
  switch (type) {
    case 'A': case 'AAAA': return `${type}(${n}, ${js(d)}`;
    case 'CNAME': case 'NS': case 'PTR': case 'DNAME': return `${type}(${n}, ${js(fqdn(d))}`;
    case 'ALIAS': return `ALIAS(${n}, ${js(fqdn(d))}`;
    case 'MX': return `MX(${n}, ${d.preference}, ${js(fqdn(d.exchange))}`;
    case 'SRV': return `SRV(${n}, ${d.priority}, ${d.weight}, ${d.port}, ${js(fqdn(d.target))}`;
    case 'CAA': return `CAA(${n}, ${js(String(d.tag).toLowerCase())}, ${js(d.value)}`;
    // DNSControl joins a list of strings into one text and splits it again every 255 bytes.
    case 'TXT': return `TXT(${n}, ${js(txtJoined(d))}`;
    case 'TLSA': case 'SMIMEA': return `${type}(${n}, ${d.usage}, ${d.selector}, ${d.matchingType}, ${js(d.data)}`;
    case 'SSHFP': return `SSHFP(${n}, ${d.algorithm}, ${d.fpType}, ${js(d.fingerprint)}`;
    case 'DS': return `DS(${n}, ${d.keyTag}, ${d.algorithm}, ${d.digestType}, ${js(d.digest)}`;
    case 'NAPTR': return `NAPTR(${n}, ${d.order}, ${d.preference}, ${js(d.flags)}, ${js(d.services)}, ${js(d.regexp)}, ${js(fqdn(d.replacement))}`;
    case 'HTTPS': case 'SVCB': return `${type}(${n}, ${d.priority}, ${js(fqdn(d.target))}, ${js(svcParams(r.text))}`;
    case 'RP': return `RP(${n}, ${js(fqdn(d.mbox))}, ${js(fqdn(d.txt))}`;
    case 'OPENPGPKEY': return `OPENPGPKEY(${n}, ${js(String(d))}`;
    default: return null;
  }
}

function dnscontrolText(zone, steps, sets, pits, about) {
  const origin = zone.origin;
  const zoneName = canonicalName(origin);
  const ttlDefault = commonTtl(sets.filter((s) => s.steps[0].action !== 'alias').map((s) => s.ttl)) ?? CONVERT_DEFAULT_TTL;
  const lines = [];
  const emitted = new Set();
  let records = 0;
  const setOf = new Map();
  for (const set of sets) for (const s of set.steps) setOf.set(s, set);
  // DNSControl refuses a label that repeats the domain ('example.com', 'www.example.com' under
  // example.com: often a final dot the source left out) unless the record says it is meant.
  const repeats = (rel, r) => {
    if (rel !== zoneName && !rel.endsWith(`.${zoneName}`)) return [];
    pits.flag('repeated-domain', r, { zone: zoneName });
    return ['DISABLE_REPEATED_DOMAIN_CHECK'];
  };
  for (const s of steps) {
    const { r } = s;
    const rel = relativeName(r.name, origin);
    if (s.action === 'omit') continue;
    if (s.action === 'comment') {
      lines.push(`    // not written (${commentText(COMMENT_REASON[s.code] || s.code)}): ${commentText(`${rel} ${r.type} ${r.alias ? fqdn(r.alias.target) : r.text}`)}`);
      continue;
    }
    const set = setOf.get(s);
    if (!set) continue;
    if (s.action === 'alias') {
      const a = r.alias;
      const mods = [];
      if (a.zoneId) mods.push(`R53_ZONE(${js(a.zoneId)})`);
      if (a.evaluateTargetHealth) mods.push('R53_EVALUATE_TARGET_HEALTH(true)');
      mods.push(...repeats(rel, r));
      lines.push(`    R53_ALIAS(${js(rel)}, ${js(r.type)}, ${js(fqdn(a.target))}${mods.map((m) => `, ${m}`).join('')}),`);
      records += 1;
      continue;
    }
    const type = s.action === 'apex-alias' || s.action === 'pseudo-alias' ? 'ALIAS' : String(r.type).toUpperCase();
    const call = dnscontrolCall(type, rel, s.action === 'pseudo-alias' ? { ...r, data: s.to } : r);
    if (!call) continue;
    const mods = [];
    if (set.ttl !== ttlDefault) mods.push(`TTL(${set.ttl})`);
    if (type === 'CAA' && Number(r.data.flags) === 128) mods.push('CAA_CRITICAL');
    if (r.proxied === true && ['A', 'AAAA', 'CNAME', 'ALIAS'].includes(type)) mods.push('CF_PROXY_ON');
    mods.push(...repeats(rel, r));
    const text = `    ${call}${mods.map((m) => `, ${m}`).join('')}),`;
    // Two routing variants with one value are one record here: DNSControl refuses a duplicate.
    if (emitted.has(text)) continue;
    emitted.add(text);
    lines.push(text);
    records += 1;
  }
  const out = [
    `// ${origin} as DNSControl's dnsconfig.js, written by DomainScope from ${about}.`,
    '// Read the notes DomainScope listed, then run `dnscontrol preview` before `dnscontrol push`.',
    'var REG_NONE = NewRegistrar("none");',
    `var DSP_MAIN = NewDnsProvider(${js(DNSCONTROL_PROVIDER)}); // the name of your provider's entry in creds.json`,
    '',
    `D(${js(origin)}, REG_NONE, DnsProvider(DSP_MAIN),`,
    `    DefaultTTL(${ttlDefault}),`,
    ...lines,
    'END);'
  ];
  return { text: `${out.join('\n')}\n`, written: records };
}

/* ------------------------------------------------------------------------ */
/* Entry point                                                              */
/* ------------------------------------------------------------------------ */

const WRITERS = { bind: bindText, route53: route53Text, octodns: octodnsText, dnscontrol: dnscontrolText };

/**
 * The file name of a target's output: `<zone>.zone`, `<zone>.route53.json`, `<zone>.yaml`
 * (octoDNS names a zone file after the zone), `dnsconfig.js`.
 * @param {string} origin
 * @param {string} target
 * @returns {string}
 */
export function convertFilename(origin, target) {
  const o = canonicalName(origin) || 'zone';
  return { bind: `${o}.zone`, route53: `${o}.route53.json`, octodns: `${o}.yaml`, dnscontrol: 'dnsconfig.js' }[target] || `${o}.txt`;
}

/**
 * The source as the files' first line names it: `bind (cloudflare)`, `route53` …
 * @param {object} zone
 * @returns {string}
 */
function sourceLabel(zone) {
  return `${zone.format || 'unknown format'}${zone.dialect && zone.dialect !== 'generic' ? ` (${zone.dialect})` : ''}`;
}

/**
 * Write a parsed zone for a target.
 * @param {object} zone lib/zoneparse.js Zone, with an origin and no fatal issue
 * @param {string} target one of {@link CONVERT_TARGETS}
 * @returns {{ target: string, text: string, filename: string, mime: string, written: number,
 *   pitfalls: Array<{ code: string, severity: 'error'|'warn'|'info', count: number, names: string[], params: object }>,
 *   omitted: Array<{ id: number, code: string }>, changed: Array<{ id: number, code: string }> }}
 *   `written`: the records (values) in the file; `names`: the record names concerned, relative
 *   to the zone; `omitted`: records left out (or commented out); `changed`: records written as
 *   another type (an apex CNAME as ALIAS)
 */
export function convertZone(zone, target) {
  if (!CONVERT_TARGETS.includes(target)) throw new RangeError(`zoneconvert: unknown target "${target}"`);
  if (!zone || zone.fatal || !Array.isArray(zone.records)) throw new TypeError('zoneconvert: a parsed zone without a fatal issue is needed');
  if (!zone.origin) throw new TypeError('zoneconvert: the zone needs its name (origin)');
  const pits = collector(target, zone.origin);
  const { steps, omitted, changed } = plan(zone, target, pits);
  const sets = groupSets(steps, zone, pits, { routing: target === 'route53' });
  // Routing variants with no place in the target (any in BIND, octoDNS and DNSControl; a policy
  // a change batch cannot write in Route 53) are merged into one set, and said so.
  mergeRouting(sets, pits, target, omitted);
  flagCnameAlone(sets, pits);
  if (target === 'octodns') {
    // octoDNS has one proxy flag per record set: a set with both gets "proxied" (Cloudflare's own
    // rule for the name), and its DNS-only records change.
    for (const set of sets) {
      const flags = set.steps.map((s) => s.r.proxied);
      if (!(flags.includes(true) && flags.includes(false))) continue;
      for (const s of set.steps) {
        if (s.r.proxied !== false) continue;
        pits.flag('proxied-mixed', s.r);
        changed.push({ id: s.r.id, code: 'proxied-mixed' });
      }
    }
  }
  const { text, written } = WRITERS[target](zone, steps, sets, pits, sourceLabel(zone));
  return {
    target,
    text,
    filename: convertFilename(zone.origin, target),
    mime: CONVERT_MIME[target],
    written,
    pitfalls: pits.list(),
    omitted,
    changed
  };
}
