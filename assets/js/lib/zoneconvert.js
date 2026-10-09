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
 * - Route 53 takes 1,000 values and 32,000 characters of values in one change batch, an UPSERT
 *   counting each twice ({@link ROUTE53_BATCH_LIMITS}): a zone over that is written as several
 *   change batches (`files`), whole record sets in each, aliases last.
 *
 * Pure, synchronous and DOM-free; nothing is sent or stored. Runs in browsers and Node 22.
 */

import { bindComment, presentCharString, GTLDS } from './zoneparse.js';
import { base64Decode } from './dnswire.js';
import { relativeName, canonicalName } from './zonediff.js';
import {
  route53String, yamlString, octodnsTxt, octodnsTxtValue, octodnsTxtRefused, naturalCompare, txtBytes, joinBytes, utf8Text, split255
} from './zonetext.js';

// The escapes, checks and orders of the formats live in lib/zonetext.js; they stay exported here too.
export { route53String, yamlString, octodnsTxt, octodnsTxtValue, octodnsTxtRefused, naturalCompare };

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
 * octoDNS passes on unchecked, their value as its wire bytes (RFC 9460 §2.1): the same on the wire.
 */
export const OCTODNS_SVC_KEYS = Object.freeze(['mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ipv6hint']);
/** Owner names octoDNS accepts for SRV and URI records (its srv-name / uri-name checks: `_service._proto` or a wildcard). */
const OCTODNS_SERVICE_NAME = /^(\*|_[^.]+)\.[^.]+/;
/** The numbers of the named SvcParamKeys (RFC 9460 and the IANA registry; lib/zoneparse.js reads `key<N>` back by them). */
const SVC_KEY_NUMBERS = Object.freeze({
  mandatory: 0, alpn: 1, 'no-default-alpn': 2, port: 3, ipv4hint: 4, ech: 5, ipv6hint: 6, dohpath: 7, ohttp: 8, 'tls-supported-groups': 9
});
/**
 * SvcParamKeys BIND, Route 53 and DNSControl files write by number, their value as wire bytes:
 * the ones dnspython 2.8 and DNSControl 5.3 have no name for (DNSControl refuses the whole file).
 */
const SVC_BY_NUMBER = Object.freeze(['tls-supported-groups']);
/** Route 53 routing policies a change batch can carry (the parser reads them back). */
export const ROUTE53_ROUTING = Object.freeze(['weighted', 'latency', 'failover', 'geolocation', 'multivalue']);
/**
 * What Route 53 takes in one ChangeResourceRecordSets request: 1,000 ResourceRecord elements (an
 * alias counts as one) and 32,000 characters in all Value elements, an UPSERT counting each
 * element and each character twice (`upsert`); and 400 values in one record set (its quotas).
 */
export const ROUTE53_BATCH_LIMITS = Object.freeze({ records: 1000, chars: 32000, upsert: 2, setValues: 400 });
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
  'txt-bytes': { octodns: 'warn', dnscontrol: 'warn' },
  'txt-quote': { octodns: 'warn' },
  'txt-quote-start': { octodns: 'info' },
  semicolons: { octodns: 'info' },
  'caa-flags': { route53: 'warn', octodns: 'warn', dnscontrol: 'warn' },
  'caa-tag': { route53: 'info', octodns: 'info', dnscontrol: 'warn' },
  'caa-quote': { octodns: 'warn' },
  'svc-key': { bind: 'info', route53: 'info', octodns: 'info', dnscontrol: 'info' },
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
  'escaped-target': { octodns: 'warn', dnscontrol: 'warn' },
  'repeated-domain': { dnscontrol: 'warn' },
  'no-soa': { bind: 'warn' },
  soa: { route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'apex-ns': { route53: 'info', octodns: 'info', dnscontrol: 'info' },
  wildcard: { bind: 'info', route53: 'info', octodns: 'info', dnscontrol: 'info' },
  duplicate: { bind: 'info', route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'ttl-mixed': { route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'ttl-default': { route53: 'info', octodns: 'info', dnscontrol: 'info' },
  'batch-size': { route53: 'error' },
  'batch-split': { route53: 'info' }
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
  'escaped-target': ['dnscontrol'],
  'svc-key': ['octodns'],
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
/* Strings (lib/zonetext.js, shared with lib/fixes.js)                      */
/* ------------------------------------------------------------------------ */

const utf8 = new TextEncoder();
/** A byte as Route 53's three-digit octal escape. */
const octal = (b) => `\\${b.toString(8).padStart(3, '0')}`;

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

/**
 * A TXT / SPF record's text: its character-strings' bytes joined, as UTF-8 (null when they are
 * not UTF-8 — a character split across two strings is joined first). What octoDNS and DNSControl
 * keep: one text, split again every 255 bytes.
 */
const txtText = (r) => utf8Text(joinBytes(txtBytes(r)));

/** Character-strings that are not the 255-byte split of their joined text (octoDNS and DNSControl re-split them). */
function customChunks(strings) {
  if (strings.length < 2) return false;
  return strings.slice(0, -1).some((b) => b.length !== 255);
}

/** A record's character-strings with any longer than 255 bytes cut at 255 (RFC 1035 §3.3; the parser reads a longer one). */
const txtStrings255 = (r) => txtBytes(r).flatMap((b) => split255(b));

/** The TXT / SPF RDATA of a BIND line: the record's own text, re-split where a string is over 255 bytes. */
function bindTxt(r) {
  const strings = txtBytes(r);
  return strings.every((b) => b.length <= 255) ? r.text : strings.flatMap((b) => split255(b)).map((b) => presentCharString(b)).join(' ');
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

/** A JavaScript string literal (DNSControl): JSON's, with U+2028 / U+2029 escaped for older engines and U+FEFF never raw. */
const js = (s) => JSON.stringify(String(s ?? '')).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029').replace(/\ufeff/g, '\\ufeff');

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
  'txt-bytes': 'TXT that is not UTF-8 text',
  'escaped-target': 'a target name with characters DNSControl refuses (it refuses the whole file over them)',
  dnssec: 'DNSSEC record: the new provider signs the zone itself',
  'out-of-zone': 'outside the zone',
  soa: 'SOA: the provider writes its own',
  'apex-ns': 'NS at the apex: the provider serves its own name servers',
  routing: 'another routing variant of a CNAME or an alias: one target per name'
});

/** Pitfall params that collect a list of values (types, flags …) over the records flagged. */
const LIST_PARAMS = Object.freeze(['types', 'flags', 'tags', 'keys']);

/** A pitfall collector for one conversion. */
function collector(target, origin) {
  const map = new Map();
  /** code → the names already listed (a zone of 20,000 proxied records lists 20,000 names). */
  const listed = new Map();
  return {
    flag(code, r = null, extra = {}) {
      const severity = PITFALL_SEVERITY[code] && PITFALL_SEVERITY[code][target];
      if (!severity) return;
      let p = map.get(code);
      if (!p) {
        p = { code, severity, count: 0, names: [], params: { target: TARGET_NAMES[target] } };
        map.set(code, p);
        listed.set(code, new Set());
      }
      p.count += 1;
      if (r) {
        const rel = relativeName(r.name, origin);
        if (!listed.get(code).has(rel)) {
          listed.get(code).add(rel);
          p.names.push(rel);
        }
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
    // octoDNS and DNSControl keep a TXT value as text: bytes that are not UTF-8 have no place there.
    if ((target === 'octodns' || target === 'dnscontrol') && (type === 'TXT' || type === 'SPF') && txtText(r) === null) {
      leave('txt-bytes', target === 'dnscontrol' ? 'comment' : 'omit');
      continue;
    }
    // octoDNS deletes a `" "` inside a TXT value as it loads it: no way to write one.
    if (target === 'octodns' && (type === 'TXT' || type === 'SPF') && octodnsTxtValue(txtText(r)) === null) {
      leave('txt-quote', 'omit');
      continue;
    }
    // octoDNS and DNSControl refuse the whole file over a target name with escapes (a space, a quote …).
    if ((target === 'octodns' || target === 'dnscontrol') && (r.targets || []).some((x) => String(x).includes('\\'))) {
      leave('escaped-target', target === 'dnscontrol' ? 'comment' : 'omit');
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
      if (joinBytes(txtBytes(r)).length > 255) pits.flag('txt-long', r);
      // octoDNS and DNSControl keep one text and split it again every 255 bytes.
      if ((target === 'octodns' || target === 'dnscontrol') && customChunks(txtBytes(r))) pits.flag('txt-split', r);
    }
    if (type === 'CAA' && r.data && target !== 'bind') {
      const flags = Number(r.data.flags);
      if (flags !== 0 && flags !== 128) pits.flag('caa-flags', r, { flags });
      const tag = String(r.data.tag || '').toLowerCase();
      if (!CAA_COMMON_TAGS.includes(tag)) pits.flag('caa-tag', r, { tags: tag });
    }
    if ((type === 'HTTPS' || type === 'SVCB') && r.data && r.data.params) {
      const byNumber = Object.keys(r.data.params).filter((k) => (target === 'octodns' ? !OCTODNS_SVC_KEYS.includes(k) : SVC_BY_NUMBER.includes(k))
        && SVC_KEY_NUMBERS[k] !== undefined);
      if (byNumber.length) pits.flag('svc-key', r, { keys: byNumber });
    }
    // What octoDNS's own checks refuse is written with `octodns: lenient: true`: loaded, with a warning.
    if (target === 'octodns' && (type === 'TXT' || type === 'SPF')) {
      const text = txtText(r);
      if (octodnsTxtRefused(octodnsTxt(text))) {
        pits.flag('txt-lenient', r);
        s.lenient = true;
      }
      if (text.startsWith('"')) pits.flag('txt-quote-start', r);
      if (text.includes(';')) pits.flag('semicolons', r);
    }
    // octoDNS writes a CAA value between quotes as it is (CaaValue.to_rdata_text): a quote or a backslash in it is not escaped.
    if (target === 'octodns' && type === 'CAA' && r.data && /["\\]/.test(String(r.data.value))) pits.flag('caa-quote', r);
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

/**
 * Routing variants a target has no place for: flagged and merged into one set. One target per
 * name: a CNAME keeps its first value only, and so does a set led by an alias (two alias targets
 * never merge; any alias after plain values is left out). What goes is listed in `omitted`.
 */
function mergeRouting(sets, pits, target, omitted) {
  for (const set of sets) {
    const routed = set.steps.filter((s) => s.r.routing);
    if (!routed.length || set.routing) continue;
    for (const s of routed) pits.flag('routing', s.r);
    if (set.steps.length < 2 || (set.type !== 'CNAME' && !set.steps.some((s) => s.action === 'alias'))) continue;
    const keep = set.type === 'CNAME' || set.steps[0].action === 'alias' ? set.steps.slice(0, 1) : set.steps.filter((s) => s.action !== 'alias');
    for (const s of set.steps) {
      if (keep.includes(s)) continue;
      omitted.push({ id: s.r.id, code: 'routing' });
      s.action = target === 'bind' || target === 'dnscontrol' ? 'comment' : 'omit';
      s.code = 'routing';
    }
    set.steps = keep;
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
    const type = String(r.type).toUpperCase();
    const rdata = (type === 'TXT' || type === 'SPF') && r.data !== null && r.data !== undefined ? bindTxt(r) : svcText(r);
    return `${owner(r).padEnd(width)} ${ttl.padStart(6)} IN ${String(r.type).padEnd(5)} ${rdata}`;
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
  if (type === 'TXT' || type === 'SPF') return txtStrings255(r).map((b) => route53String(b)).join(' ');
  if (type === 'CAA') return `${r.data.flags} ${String(r.data.tag).toLowerCase()} ${route53String(r.data.value)}`;
  if (type === 'A' || type === 'AAAA') return String(r.data);
  return octalEscapes(svcText(r));
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
  const L = ROUTE53_BATCH_LIMITS;
  // Each change with what Route 53 counts of it: its values (an alias is one) and their characters.
  const items = [];
  for (const set of sets) {
    const first = set.steps[0].r;
    const rrs = { Name: route53Name(set.name), Type: set.type };
    if (set.routing) Object.assign(rrs, route53Routing(set.routing));
    const item = { change: { Action: 'UPSERT', ResourceRecordSet: rrs }, records: 1, chars: 0, alias: null, name: canonicalName(set.name) };
    if (set.steps[0].action === 'alias') {
      const a = first.alias;
      if (!a.zoneId) pits.flag('alias-zone-id', first);
      rrs.AliasTarget = { HostedZoneId: a.zoneId || ALIAS_ZONE_PLACEHOLDER, DNSName: route53Name(a.target), EvaluateTargetHealth: !!a.evaluateTargetHealth };
      item.alias = canonicalName(a.target);
    } else {
      const values = [...new Set(set.steps.map((s) => route53Value(s.r)))];
      rrs.TTL = set.ttl;
      rrs.ResourceRecords = values.map((Value) => ({ Value }));
      item.records = values.length;
      item.chars = values.reduce((n, v) => n + v.length, 0);
      // No change batch takes it: more values than a set holds, or more characters than one UPSERT.
      if (values.length > L.setValues || item.chars * L.upsert > L.chars) {
        pits.flag('batch-size', first, { values: L.setValues, chars: L.chars / L.upsert });
      }
    }
    items.push(item);
  }
  const written = items.reduce((n, x) => n + x.records, 0);
  const fits = (records, chars) => records * L.upsert <= L.records && chars * L.upsert <= L.chars;
  const doc = (list, part = '') => `${JSON.stringify({
    Comment: `${zone.origin}, written by DomainScope from ${about}${part}`.slice(0, 256), Changes: list.map((x) => x.change)
  }, null, 2)}\n`;
  if (fits(written, items.reduce((n, x) => n + x.chars, 0))) return { files: [{ text: doc(items), written }], written };
  // Several batches, sent one after another: whole record sets in each, the aliases last (a
  // same-zone alias needs its target to exist), an alias after any alias it targets.
  const parts = [];
  let cur = null;
  for (const x of [...items.filter((i) => i.alias === null), ...aliasOrder(items.filter((i) => i.alias !== null))]) {
    if (!cur || (cur.items.length && !fits(cur.records + x.records, cur.chars + x.chars))) {
      cur = { items: [], records: 0, chars: 0 };
      parts.push(cur);
    }
    cur.items.push(x);
    cur.records += x.records;
    cur.chars += x.chars;
  }
  // One set too big for any batch alone (batch-size) is no reason to split.
  if (parts.length === 1) return { files: [{ text: doc(items), written }], written };
  pits.flag('batch-split', null, { records: written, files: parts.length, max: L.records / L.upsert, maxChars: L.chars / L.upsert });
  return { files: parts.map((part, i) => ({ text: doc(part.items, `, part ${i + 1} of ${parts.length}`), written: part.records })), written };
}

/**
 * Alias changes in an order Route 53 takes them: one that targets another alias of the batch after
 * it (its depth in the chain, then file order; a loop keeps file order).
 */
function aliasOrder(aliases) {
  const byName = new Map();
  for (const x of aliases) {
    if (!byName.has(x.name)) byName.set(x.name, []);
    byName.get(x.name).push(x);
  }
  const depth = new Map();
  const depthOf = (x, seen) => {
    if (depth.has(x)) return depth.get(x);
    if (seen.has(x)) return 0;
    seen.add(x);
    const targets = byName.get(x.alias) || [];
    const d = targets.length ? 1 + Math.max(...targets.map((t) => depthOf(t, seen))) : 0;
    depth.set(x, d);
    return d;
  };
  return aliases.map((x, i) => ({ x, i, d: depthOf(x, new Set()) })).sort((p, q) => p.d - q.d || p.i - q.i).map((p) => p.x);
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

/** The bytes of a base64 text (an ech value, as lib/zoneparse.js checked it), none when it is not base64. */
function base64Bytes(text) {
  try {
    return [...base64Decode(String(text ?? ''))];
  } catch {
    return [];
  }
}

/** The bytes of a hex string (the parser keeps a SvcParam it has no name for as hex). */
const hexBytes = (hex) => (String(hex ?? '').match(/[0-9a-f]{2}/gi) || []).map((x) => parseInt(x, 16));

/**
 * The wire bytes of a SvcParam value (lib/zoneparse.js data `params`) for a key written by number:
 * ech decoded from base64, tls-supported-groups as 16-bit numbers, dohpath as UTF-8, a key the
 * parser has no name for from its hex.
 */
function svcWireBytes(k, v) {
  if (k === 'ech') return base64Bytes(v);
  if (k === 'tls-supported-groups') return (Array.isArray(v) ? v : [v]).flatMap((g) => [(Number(g) >> 8) & 0xff, Number(g) & 0xff]);
  if (k === 'dohpath') return [...utf8.encode(String(v))];
  return hexBytes(v);
}

/**
 * An HTTPS / SVCB record's text (lib/zoneparse.js `text`) with the keys of {@link SVC_BY_NUMBER}
 * written by number, their value as wire bytes (RFC 9460 §2.1), and `mandatory` naming them so;
 * any other record's text as it is.
 */
function svcText(r) {
  const params = r.data && typeof r.data === 'object' ? r.data.params : null;
  const type = String(r.type || '').toUpperCase();
  if ((type !== 'HTTPS' && type !== 'SVCB') || !params || !SVC_BY_NUMBER.some((k) => HAS(params, k))) return r.text;
  const byNumber = (k) => (SVC_BY_NUMBER.includes(k) ? `key${SVC_KEY_NUMBERS[k]}` : k);
  const tokens = String(r.text).match(/(?:[^\s"\\]|\\.|"(?:[^"\\]|\\.)*")+/g) || [];
  return tokens.map((tok, i) => {
    if (i < 2) return tok;
    const eq = tok.indexOf('=');
    const name = eq < 0 ? tok : tok.slice(0, eq);
    if (name === 'mandatory' && eq > 0) return `mandatory=${tok.slice(eq + 1).split(',').map(byNumber).join(',')}`;
    if (!SVC_BY_NUMBER.includes(name)) return tok;
    const bytes = svcWireBytes(name, params[name]);
    return `${byNumber(name)}${bytes.length ? `=${charStringText(bytes)}` : ''}`;
  }).join(' ');
}

/** Own property test. */
const HAS = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

/** A SvcParamKey as octoDNS writes it: its own name, or `key<N>`. */
const octodnsSvcKey = (k) => (OCTODNS_SVC_KEYS.includes(k) || SVC_KEY_NUMBERS[k] === undefined ? k : `key${SVC_KEY_NUMBERS[k]}`);

/**
 * The `svcparams` mapping of an HTTPS / SVCB value (lib/zoneparse.js data `params`) as octoDNS
 * keeps it: lists for mandatory, alpn and the address hints, null for a key without a value,
 * the port as a number; a key written by number (`key<N>`) as its wire bytes in `\DDD` escapes:
 * ech decoded from base64, tls-supported-groups as 16-bit numbers, dohpath as UTF-8. A key whose
 * value is no bytes at all (`key65001`) is null as well: octoDNS writes '' as `key65001=`, which
 * no zone file parser reads.
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
    else {
      const bytes = svcWireBytes(k, v);
      out[key] = bytes.length ? charStringText(bytes) : null;
    }
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
    case 'TXT': case 'SPF': return octodnsTxtValue(txtText(r));
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
  // Keyed by the zone's names: no prototype, so a `__proto__` label is a key like any other.
  const doc = Object.create(null);
  for (const [key, recs] of byName) {
    recs.sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));
    doc[key] = recs.length === 1 ? recs[0] : recs;
  }
  const out = [
    `# ${origin} as an octoDNS zone (${origin}.yaml), written by DomainScope from ${about}.`,
    '# Keys are in octoDNS order; the SOA, the apex NS and what octoDNS cannot hold are left out (see the notes).',
    '# TXT values write ; as \\; : load this file with escaped_semicolons: true on the YamlProvider (octoDNS refuses them with false, its default from 2.0).',
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

/**
 * HTTPS / SVCB parameters as DNSControl takes them: it splits them at every space, quoted or not,
 * so a space in a value is \032; and a key written by number without a value (`key65001`) gets
 * an empty one, `key65001=""`, which DNSControl reads where it refuses the bare key.
 * @param {string} text the parameters (lib/zoneparse.js presentation tokens)
 * @returns {string}
 */
function dnscontrolSvcParams(text) {
  return (String(text).match(/(?:[^\s"\\]|\\.|"(?:[^"\\]|\\.)*")+/g) || [])
    .map((tok) => (/^key\d+$/i.test(tok) ? `${tok}=""` : tok.replace(/"(?:[^"\\]|\\.)*"/g, (q) => q.replace(/ /g, '\\032'))))
    .join(' ');
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
    case 'TXT': return `TXT(${n}, ${js(txtText(r))}`;
    case 'TLSA': case 'SMIMEA': return `${type}(${n}, ${d.usage}, ${d.selector}, ${d.matchingType}, ${js(d.data)}`;
    case 'SSHFP': return `SSHFP(${n}, ${d.algorithm}, ${d.fpType}, ${js(d.fingerprint)}`;
    case 'DS': return `DS(${n}, ${d.keyTag}, ${d.algorithm}, ${d.digestType}, ${js(d.digest)}`;
    case 'NAPTR': return `NAPTR(${n}, ${d.order}, ${d.preference}, ${js(d.flags)}, ${js(d.services)}, ${js(d.regexp)}, ${js(fqdn(d.replacement))}`;
    case 'HTTPS': case 'SVCB': return `${type}(${n}, ${d.priority}, ${js(fqdn(d.target))}, ${js(dnscontrolSvcParams(svcParams(svcText(r))))}`;
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
 * The file name of a target's output: `<zone>.zone`, `<zone>.route53.json` (`<zone>.route53.<n>.json`
 * for the n-th of several change batches), `<zone>.yaml` (octoDNS names a zone file after the
 * zone), `dnsconfig.js`.
 * @param {string} origin
 * @param {string} target
 * @param {number} [part] 1, 2 … for one of several files
 * @returns {string}
 */
export function convertFilename(origin, target, part = 0) {
  const o = canonicalName(origin) || 'zone';
  if (target === 'route53' && Number.isInteger(part) && part > 0) return `${o}.route53.${part}.json`;
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
 *   files: Array<{ filename: string, text: string, written: number }>,
 *   pitfalls: Array<{ code: string, severity: 'error'|'warn'|'info', count: number, names: string[], params: object }>,
 *   omitted: Array<{ id: number, code: string }>, changed: Array<{ id: number, code: string }> }}
 *   `files`: the output, one file (several change batches for a Route 53 zone over its limits,
 *   `batch-split`); `text` / `filename`: the first file; `written`: the records (values) in all of
 *   them; `names`: the record names concerned, relative to the zone; `omitted`: records left out
 *   (or commented out); `changed`: records written as another type (an apex CNAME as ALIAS)
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
  const out = WRITERS[target](zone, steps, sets, pits, sourceLabel(zone));
  const parts = out.files || [{ text: out.text, written: out.written }];
  const files = parts.map((f, i) => ({ filename: convertFilename(zone.origin, target, parts.length > 1 ? i + 1 : 0), text: f.text, written: f.written }));
  return {
    target,
    text: files[0].text,
    filename: files[0].filename,
    mime: CONVERT_MIME[target],
    written: out.written,
    files,
    pitfalls: pits.list(),
    omitted,
    changed
  };
}
