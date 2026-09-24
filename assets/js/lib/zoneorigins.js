/**
 * zoneorigins.js — what an imported DNS zone (ROADMAP P1.2) says about hosts and
 * origins: the shared zone index, the scan seeds, the proxied-origin map, the
 * address map and the hand-off to cli/ssl_origin_scan.py. DOM-free, synchronous and
 * pure: no network, no storage and no clock (only {@link handoffFiles} prints a
 * time, and it takes `now`). Runs in browsers and Node 22.
 *
 * Input is the `Zone` / `ZoneRecord` shape of lib/zoneparse.js (zone-import spec
 * §6.1.2): served owner names (lowercase ASCII, no trailing dot, dnswire escaping,
 * `*` kept), `data` in the dnswire decoder's shape, `targets` without a trailing dot
 * (`''` = root), `intendedName` / `intendedTargets` for a suspected missing dot,
 * `proxied: true|false|null`, `alias`, `routing`, `occludedBy`, `invalid`,
 * `duplicateOf` on a repeated RR, `id` and `line`. This module never imports the
 * parser: any object of that shape works (the unit tests build them by hand).
 * Zones are treated as immutable; the index is cached per zone object.
 *
 * Cloudflare rules applied by the origin map (Cloudflare "Proxy status" docs):
 *  - one proxied A/AAAA on a name makes every A/AAAA on that name proxied;
 *  - a DNS-only CNAME to a proxied in-zone name is proxied too (a chain);
 *  - a proxied 192.0.2.0 or 100:: is an originless placeholder (a Worker or a
 *    redirect rule): there is no server behind it;
 *  - a proxied address inside Cloudflare's own ranges gives error 1000: not an origin;
 *  - a proxied CNAME to *.cfargotunnel.com is a Tunnel; to a SaaS / CDN provider the
 *    origin is a third party; a provider that only steers DNS (Azure Traffic Manager)
 *    and any other CNAME target is a host origin, resolved by the CLI inside the
 *    user's network.
 *
 * Origins stay exact: an address is never widened to its /24, and every proxied name
 * keeps its own origin (one row per name, never "one origin for every proxied host").
 * Private origins are kept for the CLI (it runs inside the network) and flagged.
 *
 * No shell command is built here: {@link cliHandoff} / {@link zoneSweep} return
 * validated tokens (IP targets, host targets, names incl. `*.x`) under the injection-
 * safe rules of the zone spec §6.5, plus the options object for the later
 * `cmdline.buildSweepCommand` hand-off (`cmdline.quoteArg` only sizes the inline form).
 * Pass that function as `buildCommand` once it has the `allowHostTargets` /
 * `allowWildcardNames` opt-ins; until then `command` stays null. The validators here
 * ({@link validateHostTargets}, {@link validateSweepNames}, {@link isInetAtonNumeric})
 * are the rules those opt-ins should adopt.
 */

import {
  normalizeIP, parseIP, isPrivateIP, matchProviderByIP, matchProviderByCname, getProvider, PROVIDERS
} from './netinfo.js';
import { normalizeHostname, sortHostnames } from './domain.js';
import { lookupServers } from './inventory.js';
import { validateTargets, quoteArg } from './cmdline.js';
import { parseSpf } from './health.js';

/* ------------------------------------------------------------------------ */
/* Vocabularies and constants (frozen; the views derive i18n keys from them) */
/* ------------------------------------------------------------------------ */

/** Kinds of a proxied name's origin (`zone.kind.<kind>`). */
export const ORIGIN_KINDS = Object.freeze(['ip', 'host', 'tunnel', 'provider', 'placeholder', 'cloudflare-ip', 'unresolved', 'loop']);
/** Cloudflare-hosted platforms a proxied CNAME can point to (kept local: netinfo.PROVIDERS is unchanged). */
export const CF_HOSTED_SUFFIXES = Object.freeze(['pages.dev', 'workers.dev']);
/** Provider ids reported for {@link CF_HOSTED_SUFFIXES}, in the same order. */
export const CF_HOSTED_PROVIDERS = Object.freeze(['cloudflare-pages', 'cloudflare-workers']);
/** Cloudflare Tunnel targets: `<uuid>.cfargotunnel.com`. */
export const TUNNEL_SUFFIX = 'cfargotunnel.com';
/** Provider id reported for a Tunnel. */
export const TUNNEL_PROVIDER = 'cloudflare-tunnel';
/** Cloudflare's documented originless placeholders (proxied: "no server"). */
export const PLACEHOLDERS = Object.freeze(['192.0.2.0', '100::']);
/** Hops followed through in-zone CNAMEs before a chain is reported unresolved. */
export const MAX_CNAME_CHAIN = 16;
/**
 * AWS endpoints that netinfo does not know by CNAME (zone spec §6.1.8 alias table,
 * critic A8). `pattern` is regex source text so the table serialises to JSON for the
 * CLI conformance constants; `alias` is the Route 53 `alias.provider` value.
 */
export const AWS_ORIGIN_PROVIDERS = Object.freeze([
  Object.freeze({ id: 'aws-api-gateway', alias: 'api-gateway', pattern: '(?:^|\\.)execute-api\\.[a-z0-9-]+\\.amazonaws\\.com(?:\\.cn)?$' }),
  Object.freeze({ id: 'aws-elastic-beanstalk', alias: 'elastic-beanstalk', pattern: '(?:^|\\.)elasticbeanstalk\\.com(?:\\.cn)?$' }),
  Object.freeze({ id: 'aws-global-accelerator', alias: 'global-accelerator', pattern: '(?:^|\\.)awsglobalaccelerator\\.com$' }),
  Object.freeze({ id: 'aws-vpc-endpoint', alias: 'vpc-endpoint', pattern: '(?:^|\\.)vpce\\.amazonaws\\.com(?:\\.cn)?$' })
]);
/** Labels that make a name look internal ({@link privateLookingNames}). */
export const INTERNAL_LABELS = Object.freeze(['intranet', 'internal', 'corp', 'lan', 'local', 'private', 'localhost']);
/** Suffixes that make a name look internal. */
export const INTERNAL_SUFFIXES = Object.freeze(['local', 'internal', 'lan', 'corp', 'home.arpa']);
/** Why a candidate name is not a seed (`deriveSeeds().excluded[].why`). */
export const SEED_EXCLUSIONS = Object.freeze(['service-label', 'escaped', 'occluded', 'invalid', 'out-of-zone', 'skipped']);
/** Above either limit the sweep card offers the file form (`-t zone-targets.txt -n zone-names.txt`). */
export const SWEEP_INLINE_MAX_TOKENS = 60;
export const SWEEP_INLINE_MAX_CHARS = 2000;
/** File names of the hand-off downloads. */
export const ZONE_NAMES_FILE = 'zone-names.txt';
export const ZONE_TARGETS_FILE = 'zone-targets.txt';

const PLACEHOLDER_SET = new Set(PLACEHOLDERS);
const AWS_MATCHERS = AWS_ORIGIN_PROVIDERS.map((p) => ({ id: p.id, re: new RegExp(p.pattern) }));
const INTERNAL_LABEL_SET = new Set(INTERNAL_LABELS);
const ADDRESS_TYPES = new Set(['A', 'AAAA']);
/** Types still served at a delegation point (everything else there is occluded). */
const AT_CUT_TYPES = new Set(['NS', 'DS', 'NSEC', 'RRSIG']);
const SEED_TYPES = new Set(['A', 'AAAA', 'CNAME', 'HTTPS', 'SVCB']);
const TARGET_SEED_TYPES = new Set(['MX', 'SRV', 'NS']);
const HANDOFF_TYPES = new Set(['A', 'AAAA', 'CNAME']);
const NAME_DATA_TYPES = new Set(['CNAME', 'NS', 'PTR', 'DNAME']);
const DEFAULT_SCRIPT = 'ssl_origin_scan.py';
const PATH_TOKEN = /^(?!-)[A-Za-z0-9_./-]{1,200}$/;
const SAFE_SERVER_NAME = /^(?!-)[A-Za-z0-9_.-]{1,200}$/;
const HOST_TOKEN = /^[a-z0-9_.-]+$/;
const NAME_TOKEN = /^(?:\*\.)?[a-z0-9_.-]+$/;
const INET_ATON = /^(?:0x[0-9a-f]*|[0-9]+)(?:\.(?:0x[0-9a-f]*|[0-9]+)){0,3}$/i;

/**
 * @typedef {object} ProxiedOrigin
 * @property {string} name proxied name (may be `*.x`)
 * @property {string} kind one of {@link ORIGIN_KINDS}
 * @property {string[]} ips kind `ip`: the real origin addresses; `placeholder` / `cloudflare-ip`: those addresses; else []
 * @property {string[]} ignored extension: placeholder / Cloudflare addresses dropped next to real ones
 * @property {string|null} host kind `host`: the origin host name
 * @property {string[]} via in-zone chain followed (e.g. `['www.example.com']`)
 * @property {string|null} provider netinfo provider id, an AWS id, `cloudflare-pages|workers` or `cloudflare-tunnel`
 * @property {string|null} target extension: the last name reached (external target, the missing in-zone name, the revisit)
 * @property {'direct'|'chain'} proxiedBy extension: own proxy flag, or a DNS-only CNAME into a proxied name
 * @property {boolean} private any real origin address is private
 * @property {Array<{ serverId: string, name: string, ip: string }>} servers inventory matches
 * @property {Array<{ by: 'sibling'|'mx'|'spf', name: string }>} exposure where the origin is published
 * @property {number[]} recordIds records of the name and of its in-zone chain
 */

/* ------------------------------------------------------------------------ */
/* Name helpers (escape-aware: a served label may hold '\.')                 */
/* ------------------------------------------------------------------------ */

function escapedAt(s, i) {
  let n = 0;
  for (let j = i - 1; j >= 0 && s.charCodeAt(j) === 92; j -= 1) n += 1;
  return n % 2 === 1;
}

/** Lowercase, trimmed, one unescaped trailing dot removed; `'.'` (root) → `''`. */
function canonName(v) {
  const s = String(v ?? '').trim().toLowerCase();
  if (s === '.' || s === '') return '';
  return s.endsWith('.') && !escapedAt(s, s.length - 1) ? s.slice(0, -1) : s;
}

function firstDot(s) {
  for (let i = s.indexOf('.'); i !== -1; i = s.indexOf('.', i + 1)) {
    if (!escapedAt(s, i)) return i;
  }
  return -1;
}

/** Parent name (first label removed), or null for a single label. */
function parentOf(name) {
  const i = firstDot(name);
  return i === -1 ? null : name.slice(i + 1);
}

/** Is `name` strictly below `parent` (label boundary, escape-aware)? */
function isBelow(name, parent) {
  if (!parent || name.length <= parent.length + 1 || !name.endsWith(parent)) return false;
  const i = name.length - parent.length - 1;
  return name.charCodeAt(i) === 46 && !escapedAt(name, i);
}

const atOrBelow = (name, parent) => name === parent || isBelow(name, parent);

function labelsOf(name) {
  const out = [];
  let start = 0;
  for (let i = name.indexOf('.'); i !== -1; i = name.indexOf('.', i + 1)) {
    if (escapedAt(name, i)) continue;
    out.push(name.slice(start, i));
    start = i + 1;
  }
  out.push(name.slice(start));
  return out;
}

/**
 * Unique canonical addresses, IPv4 before IPv6, then by numeric value (invalid text
 * last, by text). Each address is parsed once.
 * @param {string[]} ips
 * @returns {string[]}
 */
export function sortIps(ips) {
  const keyed = [...new Set((Array.isArray(ips) ? ips : []).map((ip) => normalizeIP(ip) || String(ip)))]
    .map((ip) => ({ ip, p: parseIP(ip) }));
  keyed.sort((a, b) => {
    if (!a.p || !b.p) return a.p ? -1 : b.p ? 1 : (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0);
    if (a.p.version !== b.p.version) return a.p.version - b.p.version;
    return a.p.value < b.p.value ? -1 : a.p.value > b.p.value ? 1 : 0;
  });
  return keyed.map((k) => k.ip);
}

const uniqSorted = (names) => sortHostnames([...new Set(names)]);

const MASK32 = 0xffffffffn;
const netMask = (bits, prefix) => ((1n << BigInt(bits)) - 1n) ^ ((1n << BigInt(bits - prefix)) - 1n);
/** Cloudflare's ranges, parsed once (Cloudflare is netinfo's first provider, so this equals matchProviderByIP). */
const CF_NETS = ((getProvider('cloudflare') || { cidrs: [] }).cidrs).map((c) => {
  const [addr, len] = c.split('/');
  const p = parseIP(addr);
  const bits = p && p.version === 4 ? 32 : 128;
  const prefix = len === undefined ? bits : Number(len);
  return p ? { version: p.version, mask: netMask(bits, prefix), net: p.value & netMask(bits, prefix) } : null;
}).filter(Boolean);
const CF_CACHE = new Map();

/** Is `ip` inside Cloudflare's published ranges (IPv4-mapped IPv6 included)? Memoised. */
export function isCloudflareIp(ip) {
  const key = String(ip ?? '');
  const hit = CF_CACHE.get(key);
  if (hit !== undefined) return hit;
  const p = parseIP(key);
  let out = false;
  if (p) {
    const v4 = p.version === 4 ? p.value : (p.value >> 32n) === 0xffffn ? p.value & MASK32 : null;
    out = CF_NETS.some((n) => (n.version === 4 ? v4 !== null && (v4 & n.mask) === n.net : p.version === 6 && (p.value & n.mask) === n.net));
  }
  if (CF_CACHE.size > 50000) CF_CACHE.clear();
  CF_CACHE.set(key, out);
  return out;
}

const PRIVATE_CACHE = new Map();
const PROVIDER_CACHE = new Map();

function memo(cache, key, fn) {
  const hit = cache.get(key);
  if (hit !== undefined) return hit;
  const out = fn();
  if (cache.size > 50000) cache.clear();
  cache.set(key, out);
  return out;
}

/** `netinfo.isPrivateIP`, memoised (zones repeat addresses a lot). */
export function isPrivateAddress(ip) {
  const key = String(ip ?? '');
  return memo(PRIVATE_CACHE, key, () => isPrivateIP(key));
}

/**
 * `netinfo.matchProviderByIP(ip).id`, memoised; null when no provider range matches.
 * Private and documentation addresses are never inside a provider's published ranges.
 */
export function providerIdOfIp(ip) {
  const key = String(ip ?? '');
  return memo(PROVIDER_CACHE, key, () => {
    if (isPrivateAddress(key) || /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$|^2001:db8:/i.test(key)) return null;
    const p = matchProviderByIP(key);
    return p ? p.id : null;
  });
}

/** Is `ip` one of Cloudflare's originless placeholders (canonical text)? */
export function isPlaceholder(ip) {
  return PLACEHOLDER_SET.has(normalizeIP(ip) || '');
}

/* ------------------------------------------------------------------------ */
/* Record helpers                                                           */
/* ------------------------------------------------------------------------ */

function isRecord(r) {
  return !!r && typeof r === 'object' && typeof r.name === 'string' && typeof r.type === 'string';
}

function dataTargets(r) {
  const d = r.data;
  if (d === null || d === undefined) return [];
  if (NAME_DATA_TYPES.has(r.type)) return typeof d === 'string' ? [d] : [];
  if (r.type === 'MX') return d && typeof d.exchange === 'string' ? [d.exchange] : [];
  if (r.type === 'SRV' || r.type === 'SVCB' || r.type === 'HTTPS') return d && typeof d.target === 'string' ? [d.target] : [];
  return [];
}

/**
 * Served RDATA target names of a record (lowercase, no trailing dot, `''` = root):
 * `targets` when the parser set them, else read from `data`.
 * @param {object} r ZoneRecord
 * @returns {string[]}
 */
export function servedTargets(r) {
  if (!isRecord(r)) return [];
  const list = Array.isArray(r.targets) ? r.targets : dataTargets(r);
  return list.map(canonName);
}

/**
 * Effective RDATA targets: the intended form (`intendedTargets[i]`) where a missing
 * trailing dot is suspected, else the served one. Analysis follows these; drift
 * compares the served data.
 * @param {object} r ZoneRecord
 * @returns {string[]}
 */
export function effectiveTargets(r) {
  const served = servedTargets(r);
  const intended = isRecord(r) && Array.isArray(r.intendedTargets) ? r.intendedTargets : null;
  if (!intended) return served;
  return served.map((t, i) => (typeof intended[i] === 'string' && intended[i] ? canonName(intended[i]) : t));
}

const firstTarget = (r) => effectiveTargets(r)[0] ?? '';

const ADDRESS_CACHE = new WeakMap();

/**
 * Canonical address of a valid A/AAAA record (family matching the type), else null.
 * Memoised per record object.
 * @param {object} r ZoneRecord
 * @returns {string|null}
 */
export function addressOf(r) {
  if (!isRecord(r) || !ADDRESS_TYPES.has(r.type) || r.invalid || typeof r.data !== 'string') return null;
  const hit = ADDRESS_CACHE.get(r);
  if (hit !== undefined && hit.data === r.data) return hit.ip;
  let ip = normalizeIP(r.data);
  if (ip && (r.type === 'A') !== !ip.includes(':')) ip = null;
  ADDRESS_CACHE.set(r, { data: r.data, ip });
  return ip;
}

/** TXT / SPF character-strings joined (the value SPF and DMARC consumers read). */
function joinedText(r) {
  if (Array.isArray(r.data)) return r.data.map((s) => String(s ?? '')).join('');
  return typeof r.data === 'string' ? r.data : '';
}

/** Is this TXT / SPF record an SPF policy (`v=spf1` then a space or the end)? */
export function isSpfRecord(r) {
  return isRecord(r) && (r.type === 'TXT' || r.type === 'SPF') && /^v=spf1(?:\s|$)/i.test(joinedText(r));
}

/* ------------------------------------------------------------------------ */
/* The shared index                                                         */
/* ------------------------------------------------------------------------ */

const INDEX_CACHE = new WeakMap();

/**
 * @typedef {object} ZoneIndex
 * @property {string|null} origin
 * @property {string|null} format
 * @property {string|null} dialect
 * @property {boolean} partial
 * @property {boolean} cloudflare Cloudflare semantics apply (CF export / API, or any proxy flag)
 * @property {object[]} records well-formed records, file order, duplicates kept
 * @property {object[]} unique records without `duplicateOf`
 * @property {Map<string, object[]>} byName unique records by served owner
 * @property {Set<string>} owners
 * @property {Set<string>} nodes owners plus the empty non-terminals inside the zone
 * @property {Set<string>} cuts non-apex NS owners inside the zone (delegation points)
 * @property {Set<string>} dnames DNAME owners
 * @property {Set<string>} nsTargets effective NS targets (glue below a cut is exempt)
 * @property {Map<object, { kind: 'cut'|'dname', by: string|null }>} occludedRecords
 * @property {Map<string, 'cut'|'dname'>} occludedNames names whose every record is occluded
 * @property {(r: object) => number} idOf the record's `id` (its file position when absent)
 * @property {(name: string) => boolean} inZone
 * @property {(name: string) => string|null} cutAtOrAbove closest delegation point at or above a name
 */

/**
 * Build (or reuse) the index every analysis shares. Never throws: a missing or
 * fatal zone gives an empty index.
 * @param {object} zone Zone
 * @returns {ZoneIndex}
 */
export function zoneIndex(zone) {
  const z = zone && typeof zone === 'object' ? zone : {};
  const list = Array.isArray(z.records) ? z.records : [];
  const hit = INDEX_CACHE.get(z);
  if (hit && hit.source === list && hit.count === list.length) return hit.index;
  const index = buildIndex(z, list);
  if (zone && typeof zone === 'object') INDEX_CACHE.set(zone, { source: list, count: list.length, index });
  return index;
}

function buildIndex(z, list) {
  const origin = typeof z.origin === 'string' && z.origin.trim() ? canonName(z.origin) : null;
  const inZone = (n) => !origin || n === origin || isBelow(n, origin);
  const records = [];
  const ids = new Map();
  if (!z.fatal) {
    list.forEach((r, i) => {
      if (!isRecord(r)) return;
      records.push(r);
      ids.set(r, Number.isInteger(r.id) ? r.id : i);
    });
  }
  const unique = records.filter((r) => r.duplicateOf === undefined || r.duplicateOf === null);
  const byName = new Map();
  for (const r of unique) {
    const list2 = byName.get(r.name);
    if (list2) list2.push(r);
    else byName.set(r.name, [r]);
  }
  const owners = new Set(byName.keys());
  let nodes = null; // owners + empty non-terminals, built on first use (wildcard synthesis only)
  const nodeSet = () => {
    if (nodes) return nodes;
    nodes = new Set();
    for (const n of owners) {
      let cur = n;
      while (cur !== null && !nodes.has(cur)) {
        nodes.add(cur);
        if (cur === origin || !inZone(cur)) break;
        cur = parentOf(cur);
      }
    }
    return nodes;
  };
  const cuts = new Set();
  const dnames = new Set();
  const nsTargets = new Set();
  for (const r of unique) {
    if (r.type === 'NS') {
      if (r.name !== origin && inZone(r.name)) cuts.add(r.name);
      for (const t of effectiveTargets(r)) if (t) nsTargets.add(t);
    } else if (r.type === 'DNAME') {
      dnames.add(r.name);
    }
  }
  const above = (set, name) => {
    if (!set.size) return null;
    for (let cur = parentOf(name); cur !== null && inZone(cur) && cur !== origin; cur = parentOf(cur)) {
      if (set.has(cur)) return cur;
    }
    return null;
  };
  const cutAtOrAbove = (name) => (cuts.has(name) ? name : above(cuts, name));

  const occludedRecords = new Map();
  for (const r of unique) {
    let occ = null;
    const cutUp = above(cuts, r.name);
    if (cutUp && !(ADDRESS_TYPES.has(r.type) && nsTargets.has(r.name))) occ = { kind: 'cut', by: cutUp };
    else if (cuts.has(r.name) && !AT_CUT_TYPES.has(r.type)) occ = { kind: 'cut', by: r.name };
    else {
      const d = above(dnames, r.name);
      if (d) occ = { kind: 'dname', by: d };
    }
    if (!occ && r.occludedBy) occ = { kind: 'cut', by: cutAtOrAbove(r.name) };
    if (occ) occludedRecords.set(r, occ);
  }
  const occludedNames = new Map();
  for (const [name, recs] of byName) {
    if (recs.every((r) => occludedRecords.has(r))) occludedNames.set(name, occludedRecords.get(recs[0]).kind);
  }
  const cloudflare = z.format === 'cloudflare-api' || z.dialect === 'cloudflare'
    || unique.some((r) => r.proxied === true || r.proxied === false);
  return {
    origin,
    format: typeof z.format === 'string' ? z.format : null,
    dialect: typeof z.dialect === 'string' ? z.dialect : null,
    partial: !!z.partial,
    cloudflare,
    records,
    unique,
    byName,
    owners,
    get nodes() { return nodeSet(); },
    cuts,
    dnames,
    nsTargets,
    occludedRecords,
    occludedNames,
    idOf: (r) => (ids.has(r) ? ids.get(r) : -1),
    inZone,
    cutAtOrAbove,
    wildcards: null,
    proxied: null,
    core: null,
    exposure: null
  };
}

/**
 * RFC 4592 wildcard synthesis: which `*.x` owner would answer `name`? The closest
 * encloser is the longest existing ancestor (owners and empty non-terminals count);
 * an existing node is never synthesised, and nothing is synthesised at or below a
 * delegation point. Unlike `domain.wildcardMatches` (certificates, one label) a DNS
 * wildcard covers any depth.
 * @param {object} zoneOrIndex Zone or {@link ZoneIndex}
 * @param {string} name
 * @returns {string|null} the wildcard owner (e.g. `*.apps.example.com`), or null
 */
export function wildcardCovers(zoneOrIndex, name) {
  const idx = zoneOrIndex && zoneOrIndex.owners instanceof Set && typeof zoneOrIndex.inZone === 'function'
    ? zoneOrIndex : zoneIndex(zoneOrIndex);
  const n = canonName(name);
  if (!n || !idx.inZone(n) || n === idx.origin) return null;
  if (!idx.wildcards) idx.wildcards = [...idx.owners].some((o) => o.startsWith('*.'));
  if (!idx.wildcards) return null;
  const nodes = idx.nodes;
  if (nodes.has(n)) return null;
  for (let enc = parentOf(n); enc !== null; enc = parentOf(enc)) {
    if (!idx.inZone(enc)) return null;
    if (nodes.has(enc)) {
      if (idx.cutAtOrAbove(enc)) return null;
      const wc = `*.${enc}`;
      return idx.owners.has(wc) ? wc : null;
    }
    if (enc === idx.origin) return null;
  }
  return null;
}

/* ------------------------------------------------------------------------ */
/* Proxied origins (core, shared with zonelint / zonedrift)                  */
/* ------------------------------------------------------------------------ */

/**
 * What a CNAME target outside the zone is.
 * @param {string} target
 * @returns {{ kind: 'tunnel'|'provider'|'host', provider: string|null }}
 */
export function classifyExternalTarget(target) {
  const t = canonName(target);
  if (atOrBelow(t, TUNNEL_SUFFIX)) return { kind: 'tunnel', provider: TUNNEL_PROVIDER };
  for (let i = 0; i < CF_HOSTED_SUFFIXES.length; i += 1) {
    if (atOrBelow(t, CF_HOSTED_SUFFIXES[i])) return { kind: 'provider', provider: CF_HOSTED_PROVIDERS[i] };
  }
  for (const m of AWS_MATCHERS) if (m.re.test(t)) return { kind: 'provider', provider: m.id };
  const p = matchProviderByCname(t);
  if (p && !p.dnsOnly) return { kind: 'provider', provider: p.id };
  return { kind: 'host', provider: p ? p.id : null };
}

/** Records that answer `name`: its own (not occluded) or those of the covering wildcard. */
function nodeRecords(idx, name) {
  const own = (idx.byName.get(name) || []).filter((r) => !idx.occludedRecords.has(r));
  if (own.length) return own;
  const wc = wildcardCovers(idx, name);
  return wc ? (idx.byName.get(wc) || []).filter((r) => !idx.occludedRecords.has(r)) : null;
}

function fromAddresses(recs) {
  const all = sortIps(recs.map(addressOf).filter(Boolean));
  const real = all.filter((ip) => !PLACEHOLDER_SET.has(ip) && !isCloudflareIp(ip));
  if (real.length) {
    return { kind: 'ip', ips: real, ignored: all.filter((ip) => !real.includes(ip)), private: real.some(isPrivateAddress) };
  }
  if (all.some(isCloudflareIp)) return { kind: 'cloudflare-ip', ips: all, ignored: [], private: false };
  if (all.length) return { kind: 'placeholder', ips: all, ignored: [], private: false };
  return { kind: 'unresolved', ips: [], ignored: [], private: false };
}

function resolveProxied(idx, start) {
  const via = [];
  const seen = new Set([start]);
  const recordIds = [];
  const out = (fields) => ({
    kind: 'unresolved', ips: [], ignored: [], host: null, provider: null, target: null, private: false,
    ...fields, via, recordIds: [...new Set(recordIds)].sort((a, b) => a - b)
  });
  let cur = start;
  let hops = 0;
  for (;;) {
    const recs = nodeRecords(idx, cur);
    if (!recs) return out({ target: cur });
    const addrs = recs.filter((r) => ADDRESS_TYPES.has(r.type));
    const cname = recs.find((r) => r.type === 'CNAME');
    for (const r of addrs.length ? addrs : cname ? [cname] : []) recordIds.push(idx.idOf(r));
    if (addrs.length) return out(fromAddresses(addrs));
    if (!cname) return out({ target: cur === start ? null : cur });
    const t = firstTarget(cname);
    if (!t) return out({ target: null });
    if (seen.has(t)) return out({ kind: 'loop', target: t });
    hops += 1;
    if (hops > MAX_CNAME_CHAIN) return out({ target: t });
    if (idx.inZone(t) && !idx.cutAtOrAbove(t)) {
      if (!nodeRecords(idx, t)) return out({ target: t });
      via.push(t);
      seen.add(t);
      cur = t;
      continue;
    }
    const ext = classifyExternalTarget(t);
    return out({ kind: ext.kind, provider: ext.provider, target: t, host: ext.kind === 'host' ? t : null });
  }
}

/**
 * The proxied names and their origins (cached on the index). `rows` is keyed by
 * name in discovery order (file order, then chain members); callers that show it sort.
 * @param {ZoneIndex} idx
 * @returns {{ rows: Map<string, object>, direct: Set<string>, proxiedAddressNames: Set<string>,
 *   originIps: Map<string, string[]>, hostOrigins: Map<string, string[]> }} the name lists
 *   of `originIps` / `hostOrigins` are in sortHostnames order
 */
export function proxiedCore(idx) {
  if (idx.core) return idx.core;
  const { direct, proxiedAddressNames, all } = proxiedSets(idx);
  const rows = new Map();
  const originIps = new Map();
  const hostOrigins = new Map();
  const note = (map, key, name) => {
    const list = map.get(key);
    if (!list) map.set(key, [name]);
    else if (!list.includes(name)) list.push(name);
  };
  for (const name of all) {
    const row = { name, ...resolveProxied(idx, name), proxiedBy: direct.has(name) ? 'direct' : 'chain' };
    rows.set(name, row);
    if (row.kind === 'ip') for (const ip of row.ips) note(originIps, ip, name);
    if (row.kind === 'host' && row.host) note(hostOrigins, row.host, name);
  }
  for (const list of [...originIps.values(), ...hostOrigins.values()]) list.splice(0, list.length, ...sortHostnames(list));
  idx.core = { rows, direct, proxiedAddressNames, originIps, hostOrigins };
  return idx.core;
}

/**
 * Which names are proxied, without resolving their origins (cached on the index):
 * `direct` (own proxy flag on an A/AAAA/CNAME), `proxiedAddressNames` (a proxied
 * A/AAAA: every A/AAAA of the name is proxied) and `all` (plus the DNS-only CNAMEs
 * chained into a proxied in-zone name).
 * @param {ZoneIndex} idx
 * @returns {{ direct: Set<string>, proxiedAddressNames: Set<string>, all: Set<string> }}
 */
export function proxiedSets(idx) {
  if (idx.proxied) return idx.proxied;
  const direct = new Set();
  const proxiedAddressNames = new Set();
  for (const r of idx.unique) {
    if (r.proxied !== true || idx.occludedRecords.has(r)) continue;
    if (ADDRESS_TYPES.has(r.type)) {
      direct.add(r.name);
      proxiedAddressNames.add(r.name);
    } else if (r.type === 'CNAME') {
      direct.add(r.name);
    }
  }
  // Chain closure: a DNS-only CNAME whose in-zone target is proxied is proxied too.
  const byTarget = new Map();
  for (const r of idx.unique) {
    if (r.type !== 'CNAME' || r.proxied === true || idx.occludedRecords.has(r)) continue;
    const t = firstTarget(r);
    if (!t || !idx.inZone(t)) continue;
    const list = byTarget.get(t);
    if (list) list.push(r.name);
    else byTarget.set(t, [r.name]);
  }
  const all = new Set(direct);
  const queue = [...direct];
  for (let i = 0; i < queue.length; i += 1) {
    for (const n of byTarget.get(queue[i]) || []) {
      if (!all.has(n)) {
        all.add(n);
        queue.push(n);
      }
    }
  }
  idx.proxied = { direct, proxiedAddressNames, all };
  return idx.proxied;
}

/**
 * Where proxied origins are published (cached on the index): a DNS-only A/AAAA at a
 * name outside the proxied set holding an origin address (`by: 'sibling'`, or `'mx'`
 * when that name is an in-zone MX exchange), a DNS-only CNAME to a host origin, and SPF
 * `ip4` / `ip6` ranges covering origin addresses (once per SPF record).
 * @param {ZoneIndex} idx
 * @returns {Array<{ by: 'sibling'|'mx'|'spf', name: string, type: string, record: object,
 *   ip: string|null, host: string|null, ips: string[], proxied: string[] }>} file order
 */
export function exposureFacts(idx) {
  if (idx.exposure) return idx.exposure;
  const core = proxiedCore(idx);
  const facts = [];
  if (!core.originIps.size && !core.hostOrigins.size) {
    idx.exposure = facts;
    return facts;
  }
  const mxHosts = new Set();
  for (const r of idx.unique) if (r.type === 'MX' && !idx.occludedRecords.has(r)) mxHosts.add(firstTarget(r));
  // Origin addresses sorted by value per family: an SPF range is a binary search.
  const byFamily = { 4: [], 6: [] };
  for (const ip of core.originIps.keys()) {
    const p = parseIP(ip);
    if (p) byFamily[p.version].push({ ip, value: p.value });
  }
  for (const list of Object.values(byFamily)) list.sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
  const covered = (term) => {
    const p = parseIP(term.value);
    if (!p) return [];
    const bits = p.version === 4 ? 32 : 128;
    const prefix = p.version === 4 ? (term.cidr4 ?? 32) : (term.cidr6 ?? 128);
    const mask = netMask(bits, prefix);
    const low = p.value & mask;
    const high = low | (((1n << BigInt(bits)) - 1n) ^ mask);
    const list = byFamily[p.version];
    let lo = 0;
    let hi = list.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (list[mid].value < low) lo = mid + 1;
      else hi = mid;
    }
    const out = [];
    for (let i = lo; i < list.length && list[i].value <= high; i += 1) out.push(list[i].ip);
    return out;
  };
  for (const r of idx.unique) {
    if (idx.occludedRecords.has(r)) continue;
    const sibling = !core.rows.has(r.name) && r.proxied !== true;
    const by = mxHosts.has(r.name) ? 'mx' : 'sibling';
    const ip = addressOf(r);
    if (ip) {
      if (sibling && core.originIps.has(ip)) {
        facts.push({ by, name: r.name, type: r.type, record: r, ip, host: null, ips: [ip], proxied: core.originIps.get(ip) });
      }
    } else if (r.type === 'CNAME') {
      const t = firstTarget(r);
      if (sibling && t && core.hostOrigins.has(t)) {
        facts.push({ by, name: r.name, type: r.type, record: r, ip: null, host: t, ips: [], proxied: core.hostOrigins.get(t) });
      }
    } else if (isSpfRecord(r)) {
      const spf = parseSpf(joinedText(r));
      const ips = [...new Set(spf.terms.filter((t) => (t.mechanism === 'ip4' || t.mechanism === 'ip6') && t.value).flatMap(covered))];
      if (ips.length) {
        const proxied = sortHostnames([...new Set(ips.flatMap((ip) => core.originIps.get(ip)))]);
        facts.push({ by: 'spf', name: r.name, type: r.type, record: r, ip: null, host: null, ips: sortIps(ips), proxied });
      }
    }
  }
  idx.exposure = facts;
  return facts;
}

/* ------------------------------------------------------------------------ */
/* Seeds                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * Exact scan seeds from the zone (zone spec §6.3 "Seeds").
 *
 * Included: owners of A/AAAA/CNAME/HTTPS/SVCB records and of aliases, plus in-zone
 * MX/SRV/NS targets (the intended form when a missing dot is suspected). A `*.x`
 * owner becomes the wildcard base `x`. Excluded with a reason: `_` labels, escaped or
 * odd names, occluded names, invalid records, owners outside the zone, `skip`.
 * Delegation points (non-apex NS owners) are live names in the child zone: they are
 * listed in `delegations` (critic B5), not in `names`.
 *
 * @param {object} zone Zone
 * @param {{ lint?: object|null, skip?: Iterable<string>|null }} [opts] `lint`: a
 *   {@link lintZone} result (its `occluded` map is used when given; the index holds the
 *   same data)
 * @returns {{ names: string[], wildcardBases: string[], delegations: string[],
 *   excluded: Array<{ name: string, why: string }> }} sortHostnames order
 */
export function deriveSeeds(zone, { lint = null, skip = null } = {}) {
  const idx = zoneIndex(zone);
  const skipSet = new Set(skip ? [...skip].map(canonName) : []);
  const occludedNames = lint && lint.occluded instanceof Map ? lint.occluded : idx.occludedNames;
  const names = new Set();
  const bases = new Set();
  const excluded = new Map();
  const reject = (name, why) => {
    if (!excluded.has(name)) excluded.set(name, why);
  };
  const consider = (raw, r) => {
    const name = canonName(raw);
    if (!name) return;
    if (!idx.inZone(name)) {
      if (r) reject(name, 'out-of-zone');
      return;
    }
    const wildcard = name.startsWith('*.');
    const base = wildcard ? name.slice(2) : name;
    if (base.includes('\\') || base.includes('*') || normalizeHostname(base) !== base) return reject(name, 'escaped');
    if (labelsOf(base).some((l) => l.startsWith('_'))) return reject(name, 'service-label');
    if (r && (idx.occludedRecords.has(r) || occludedNames.has(r.name))) return reject(name, 'occluded');
    if (r && r.invalid) return reject(name, 'invalid');
    if (skipSet.has(name)) return reject(name, 'skipped');
    if (wildcard) bases.add(base);
    else names.add(name);
  };
  for (const r of idx.unique) {
    if (SEED_TYPES.has(r.type) || r.alias) consider(r.intendedName || r.name, r);
    if (TARGET_SEED_TYPES.has(r.type) && !idx.occludedRecords.has(r)) {
      for (const t of effectiveTargets(r)) if (t && idx.inZone(t)) consider(t, null);
    }
  }
  for (const n of [...names, ...[...bases].map((b) => `*.${b}`)]) excluded.delete(n);
  const delegations = [...idx.cuts].filter((c) => !idx.occludedNames.has(c) && !idx.cutAtOrAbove(parentOf(c) || '') && !skipSet.has(c));
  return {
    names: uniqSorted([...names]),
    wildcardBases: uniqSorted([...bases]),
    delegations: uniqSorted(delegations),
    excluded: sortHostnames([...excluded.keys()]).map((name) => ({ name, why: excluded.get(name) }))
  };
}

/**
 * The TLS-bearing names the CLI hand-off covers in scope `all` (critic F1): owners of
 * valid A/AAAA/CNAME records and of aliases, `*.x` kept, without `_` labels, escaped
 * names, occluded records and names outside the zone. The web seeds stay richer.
 * @param {object} zone
 * @returns {string[]} sortHostnames order
 */
export function handoffNames(zone) {
  const idx = zoneIndex(zone);
  const out = new Set();
  for (const r of idx.unique) {
    if (!(HANDOFF_TYPES.has(r.type) || r.alias) || r.invalid || idx.occludedRecords.has(r)) continue;
    const name = canonName(r.intendedName || r.name);
    if (!name || !idx.inZone(name)) continue;
    const base = name.startsWith('*.') ? name.slice(2) : name;
    if (base.includes('\\') || base.includes('*') || normalizeHostname(base) !== base) continue;
    if (labelsOf(base).some((l) => l.startsWith('_'))) continue;
    out.add(name);
  }
  return uniqSorted([...out]);
}

/* ------------------------------------------------------------------------ */
/* Origin map, address map                                                  */
/* ------------------------------------------------------------------------ */

function serversFor(ips, inventoryIndex) {
  if (!inventoryIndex || !ips.length) return [];
  return lookupServers(ips, inventoryIndex).map(({ server, ip }) => ({ serverId: server.id, name: server.name, ip }));
}

/**
 * Every proxied name and its origin (zone spec §6.3, with the critic's corrections):
 * one row per name, never one origin for every proxied host; exact addresses only.
 * @param {object} zone Zone
 * @param {{ inventoryIndex?: Map<string, object[]>|null }} [opts] `inventoryIndex`:
 *   `inventory.buildIpIndex(servers)`. Exposure comes from the shared index (the same
 *   facts `lintZone` reports), so no lint result is needed.
 * @returns {ProxiedOrigin[]} sortHostnames order by name
 */
export function proxiedOriginMap(zone, { inventoryIndex = null } = {}) {
  const idx = zoneIndex(zone);
  const core = proxiedCore(idx);
  const exposure = new Map();
  for (const f of exposureFacts(idx)) {
    for (const name of f.proxied) {
      const list = exposure.get(name) || [];
      if (!list.some((e) => e.by === f.by && e.name === f.name)) list.push({ by: f.by, name: f.name });
      exposure.set(name, list);
    }
  }
  return sortHostnames([...core.rows.keys()]).map((name) => core.rows.get(name)).map((row) => ({
    name: row.name,
    kind: row.kind,
    ips: [...row.ips],
    ignored: [...row.ignored],
    host: row.host,
    via: [...row.via],
    provider: row.provider,
    target: row.target,
    proxiedBy: row.proxiedBy,
    private: row.private,
    servers: row.kind === 'ip' ? serversFor(row.ips, inventoryIndex) : [],
    exposure: exposure.get(row.name) || [],
    recordIds: [...row.recordIds]
  }));
}

/**
 * Every address in the zone → the names that use it and the user's servers.
 * Proxied names reached through a chain (`docs → www`) are listed under the origin
 * addresses they resolve to. A name entry is `exposed` when it publishes a proxied
 * origin DNS-only; `occluded` when the record is never served.
 * @param {object} zone
 * @param {{ inventoryIndex?: Map<string, object[]>|null }} [opts]
 * @returns {Array<{ ip: string, names: Array<{ name: string, proxied: boolean|null, via?: string[],
 *   exposed?: true, occluded?: true }>, servers: Array<{ serverId: string, name: string, ip: string }>,
 *   private: boolean, provider: string|null, placeholder: boolean, exposed: boolean }>} compareIp order
 */
export function addressMap(zone, { inventoryIndex = null } = {}) {
  const idx = zoneIndex(zone);
  const core = proxiedCore(idx);
  const exposed = new Set(exposureFacts(idx).filter((f) => f.ip).map((f) => `${f.name}\u0000${f.ip}`));
  const byIp = new Map();
  const add = (ip, entry) => {
    let e = byIp.get(ip);
    if (!e) byIp.set(ip, (e = new Map()));
    const prev = e.get(entry.name);
    if (!prev) e.set(entry.name, entry);
    else if (entry.proxied === true) prev.proxied = true;
  };
  for (const r of idx.unique) {
    const ip = addressOf(r);
    if (!ip) continue;
    const proxied = core.proxiedAddressNames.has(r.name) ? true : r.proxied === false ? false : r.proxied === true ? true : null;
    const entry = { name: r.name, proxied };
    if (exposed.has(`${r.name}\u0000${ip}`)) entry.exposed = true;
    if (idx.occludedRecords.has(r)) entry.occluded = true;
    add(ip, entry);
  }
  for (const row of core.rows.values()) {
    if (row.kind !== 'ip' || !row.via.length) continue;
    for (const ip of row.ips) add(ip, { name: row.name, proxied: true, via: [...row.via] });
  }
  return sortIps([...byIp.keys()]).map((ip) => {
    const entries = byIp.get(ip);
    const names = sortHostnames([...entries.keys()]).map((n) => entries.get(n));
    return {
      ip,
      names,
      servers: serversFor([ip], inventoryIndex),
      private: isPrivateAddress(ip),
      provider: providerIdOfIp(ip),
      placeholder: PLACEHOLDER_SET.has(ip),
      exposed: names.some((n) => n.exposed)
    };
  });
}

/* ------------------------------------------------------------------------ */
/* Private-looking names                                                    */
/* ------------------------------------------------------------------------ */

function looksInternal(name) {
  const base = name.startsWith('*.') ? name.slice(2) : name;
  const labels = labelsOf(base);
  if (labels.some((l) => INTERNAL_LABEL_SET.has(l))) return true;
  return INTERNAL_SUFFIXES.some((s) => atOrBelow(base, s));
}

/**
 * Names that look internal: skipped by default before anything is sent to a public
 * resolver (drift) or used as a scan seed. A name is in the set when any of its
 * A/AAAA is private, a label is in {@link INTERNAL_LABELS}, it sits under one of
 * {@link INTERNAL_SUFFIXES}, or a DNS-only CNAME points to a name in the set.
 * Owners and in-zone RDATA targets are both considered.
 * @param {object} zone
 * @returns {Set<string>}
 */
export function privateLookingNames(zone) {
  const idx = zoneIndex(zone);
  const out = new Set();
  const candidates = new Set();
  for (const r of idx.unique) {
    candidates.add(r.name);
    if (r.intendedName) candidates.add(canonName(r.intendedName));
    const ip = addressOf(r);
    if (ip && isPrivateAddress(ip)) out.add(r.name);
    for (const t of effectiveTargets(r)) if (t && idx.inZone(t)) candidates.add(t);
  }
  for (const n of candidates) if (looksInternal(n)) out.add(n);
  const cnames = idx.unique.filter((r) => r.type === 'CNAME' && r.proxied !== true);
  for (let changed = true; changed;) {
    changed = false;
    for (const r of cnames) {
      if (!out.has(r.name) && out.has(firstTarget(r))) {
        out.add(r.name);
        changed = true;
      }
    }
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* CLI hand-off                                                              */
/* ------------------------------------------------------------------------ */

/**
 * The inet_aton numeric forms glibc accepts as an IPv4 address (`2026092401`,
 * `0x7f.0x1`, `0177.1`, `10.1`). Such a "host name" must never reach getaddrinfo.
 * @param {unknown} s
 * @returns {boolean}
 */
export function isInetAtonNumeric(s) {
  return INET_ATON.test(String(s ?? ''));
}

function validateList(list, canon) {
  const valid = [];
  const dropped = [];
  const seen = new Set();
  for (const raw of Array.isArray(list) ? list : []) {
    const c = canon(raw);
    if (c === null) {
      dropped.push(String(raw ?? ''));
    } else if (!seen.has(c)) {
      seen.add(c);
      valid.push(c);
    }
  }
  return { valid, dropped };
}

/**
 * Host-name sweep targets (zone spec §6.5 `allowHostTargets`): a token that is not an
 * IP / CIDR, passes `normalizeHostname`, matches `^[a-z0-9_.-]+$`, has a dot, does not
 * start with `-` and is not an inet_aton numeric form.
 * @param {unknown[]} list
 * @returns {{ valid: string[], dropped: string[] }}
 */
export function validateHostTargets(list) {
  return validateList(list, (raw) => {
    const s = String(raw ?? '').trim();
    if (!s || s.includes('/') || normalizeIP(s)) return null;
    const n = normalizeHostname(s);
    if (!n || n.startsWith('-') || !HOST_TOKEN.test(n) || !n.includes('.') || isInetAtonNumeric(n)) return null;
    return n;
  });
}

/**
 * Sweep names (zone spec §6.5 `allowWildcardNames`): `normalizeHostname` with a
 * leading `*.` allowed, then `^(\*\.)?[a-z0-9_.-]+$`; inet_aton numeric forms dropped.
 * @param {unknown[]} list
 * @returns {{ valid: string[], dropped: string[] }}
 */
export function validateSweepNames(list) {
  return validateList(list, (raw) => {
    const s = String(raw ?? '').trim();
    if (!s) return null;
    const n = normalizeHostname(s, { allowWildcard: true });
    if (!n || n.startsWith('-') || !NAME_TOKEN.test(n) || isInetAtonNumeric(n.replace(/^\*\./, ''))) return null;
    return n;
  });
}

function skipDetail(row) {
  if (row.kind === 'placeholder' || row.kind === 'cloudflare-ip') return row.ips.join(' ');
  if (row.kind === 'loop') return [row.name, ...row.via, row.target].filter(Boolean).join(' > ');
  return row.target || '';
}

/**
 * Exact CLI hand-off for the proxied names (scope `proxied`).
 * - `targets`: the addresses of kind `ip` rows, private ones included, IPv4 first;
 * - `hostTargets`: the host origins of kind `host` rows;
 * - `names`: every row of kind `ip` / `host`, chain names included, `*.x` kept;
 * - `skipped`: every other kind, with a detail (target / addresses / chain).
 * Every token passes the injection-safe validators; what fails is in `dropped`.
 * @param {object} zone
 * @param {{ origins?: ProxiedOrigin[]|null }} [opts] a {@link proxiedOriginMap} result to reuse
 * @returns {{ targets: string[], hostTargets: string[], names: string[],
 *   skipped: Array<{ name: string, kind: string, detail: string, provider: string|null }>,
 *   dropped: { targets: string[], names: string[] } }}
 */
export function cliHandoff(zone, { origins = null } = {}) {
  const rows = Array.isArray(origins) ? origins : proxiedOriginMap(zone);
  const ips = [];
  const hosts = [];
  const names = [];
  const skipped = [];
  for (const row of rows) {
    if (row.kind === 'ip') {
      ips.push(...row.ips);
      names.push(row.name);
    } else if (row.kind === 'host') {
      if (row.host) hosts.push(row.host);
      names.push(row.name);
    } else {
      skipped.push({ name: row.name, kind: row.kind, detail: skipDetail(row), provider: row.provider ?? null });
    }
  }
  const t = validateTargets(sortIps(ips));
  const h = validateHostTargets(uniqSorted(hosts));
  const n = validateSweepNames(uniqSorted(names));
  return {
    targets: t.valid,
    hostTargets: h.valid,
    names: n.valid,
    skipped,
    dropped: { targets: [...t.dropped, ...h.dropped], names: n.dropped }
  };
}

/** Distinct TLS probes per target: `*.x` is the base plus a wildcard SNI (CLI build_probe_names). */
function probeNameCount(names) {
  const seen = new Set();
  for (const n of names) {
    if (n.startsWith('*.')) {
      seen.add(n.slice(2));
      seen.add(`\u0000${n}`);
    } else {
      seen.add(n);
    }
  }
  return seen.size;
}

/**
 * The origin sweep for the zone, in scope `proxied` ({@link cliHandoff}) or `all`:
 * names = {@link handoffNames}; targets = every unique served A/AAAA except
 * Cloudflare-range addresses and the placeholders (private ones kept), plus the
 * proxied host origins.
 *
 * `probes` = distinct probe names × targets, a floor when host targets resolve to
 * several addresses (`probesAtLeast`). `tokens` / `chars` size the inline form, and
 * `fileForm` is true above {@link SWEEP_INLINE_MAX_TOKENS} tokens or
 * {@link SWEEP_INLINE_MAX_CHARS} characters. `commandOptions` is the argument for
 * `cmdline.buildSweepCommand` once it has the zone opt-ins; with `buildCommand` given
 * it is called and `command` is its result, else `command` is null.
 *
 * @param {object} zone
 * @param {{ scope?: 'proxied'|'all', shell?: 'posix'|'powershell', script?: string,
 *   origins?: ProxiedOrigin[]|null, buildCommand?: ((opts: object) => { command: string|null })|null }} [opts]
 * @returns {{ scope: 'proxied'|'all', targets: string[], hostTargets: string[], names: string[],
 *   skipped: Array<object>, dropped: { targets: string[], names: string[] }, command: string|null,
 *   tokens: number, chars: number, probes: number, probesAtLeast: boolean, fileForm: boolean,
 *   commandOptions: object }}
 */
export function zoneSweep(zone, {
  scope = 'proxied', shell = 'posix', script = DEFAULT_SCRIPT, origins = null, buildCommand = null
} = {}) {
  const sh = shell === 'powershell' ? 'powershell' : 'posix';
  const scriptTok = typeof script === 'string' && PATH_TOKEN.test(script) ? script : DEFAULT_SCRIPT;
  const rows = Array.isArray(origins) ? origins : proxiedOriginMap(zone);
  const proxied = cliHandoff(zone, { origins: rows });
  let h = proxied;
  const sc = scope === 'all' ? 'all' : 'proxied';
  if (sc === 'all') {
    const idx = zoneIndex(zone);
    const ips = [];
    for (const r of idx.unique) {
      if (idx.occludedRecords.has(r)) continue;
      const ip = addressOf(r);
      if (ip && !PLACEHOLDER_SET.has(ip) && !isCloudflareIp(ip)) ips.push(ip);
    }
    const t = validateTargets(sortIps(ips));
    const n = validateSweepNames(handoffNames(zone));
    h = {
      targets: t.valid,
      hostTargets: proxied.hostTargets,
      names: n.valid,
      skipped: proxied.skipped,
      dropped: { targets: [...t.dropped, ...proxied.dropped.targets.filter((x) => !normalizeIP(x))], names: n.dropped }
    };
  }
  const targetCount = h.targets.length + h.hostTargets.length;
  const tokens = targetCount + h.names.length;
  const q = (v) => quoteArg(v, sh);
  const chars = targetCount && h.names.length
    ? `${q(scriptTok)} -t ${[...h.targets, ...h.hostTargets].map(q).join(' ')} -n ${h.names.map(q).join(' ')}`.length
    : 0;
  const commandOptions = {
    targets: [...h.targets, ...h.hostTargets],
    names: [...h.names],
    script: scriptTok,
    shell: sh,
    allowHostTargets: true,
    allowWildcardNames: true,
    namesFile: ZONE_NAMES_FILE,
    targetsFile: ZONE_TARGETS_FILE,
    maxInlineNames: SWEEP_INLINE_MAX_TOKENS,
    maxInlineTargets: SWEEP_INLINE_MAX_TOKENS,
    maxLength: SWEEP_INLINE_MAX_CHARS
  };
  let command = null;
  if (typeof buildCommand === 'function' && targetCount && h.names.length) {
    const built = buildCommand(commandOptions);
    command = built && typeof built.command === 'string' ? built.command : null;
  }
  return {
    scope: sc,
    targets: h.targets,
    hostTargets: h.hostTargets,
    names: h.names,
    skipped: h.skipped,
    dropped: h.dropped,
    command,
    tokens,
    chars,
    probes: targetCount ? probeNameCount(h.names) * targetCount : 0,
    probesAtLeast: h.hostTargets.length > 0,
    fileForm: tokens > SWEEP_INLINE_MAX_TOKENS || chars > SWEEP_INLINE_MAX_CHARS,
    commandOptions
  };
}

/**
 * The two hand-off downloads for a sweep. Both start with a `#` comment header and
 * list one entry per line, so the CLI's `load_names` / `parse_inventory` read them
 * without a warning. A target address owned by an inventory server is written
 * `<server-name> <ip>` (only for a name of `[A-Za-z0-9_.-]`), host targets follow as
 * bare host names.
 * @param {{ names: string[], targets: string[], hostTargets?: string[] }} sweep
 * @param {{ origin?: string|null, inventoryIndex?: Map<string, object[]>|null, now?: Date }} [opts]
 * @returns {{ namesTxt: string, targetsTxt: string }}
 */
export function handoffFiles(sweep, { origin = null, inventoryIndex = null, now = new Date() } = {}) {
  const o = typeof origin === 'string' && /^[a-z0-9_.-]{1,253}$/.test(origin) ? origin : 'zone';
  const when = now instanceof Date && !Number.isNaN(now.getTime()) ? now.toISOString() : new Date(0).toISOString();
  const header = `# DomainScope zone hand-off for ${o} — ${when}`;
  const names = validateSweepNames(sweep && Array.isArray(sweep.names) ? sweep.names : []).valid;
  const targets = validateTargets(sweep && Array.isArray(sweep.targets) ? sweep.targets : []).valid;
  const hosts = validateHostTargets(sweep && Array.isArray(sweep.hostTargets) ? sweep.hostTargets : []).valid;
  const lines = targets.map((ip) => {
    const match = serversFor([ip], inventoryIndex)
      .find((s) => typeof s.name === 'string' && SAFE_SERVER_NAME.test(s.name) && !normalizeIP(s.name));
    return match ? `${match.name} ${ip}` : ip;
  });
  return {
    namesTxt: `${[header, ...names].join('\n')}\n`,
    targetsTxt: `${[header, ...lines, ...hosts].join('\n')}\n`
  };
}

/**
 * The scan input handed to Subdomains / SSL Targets (`state.session.zone`, zone spec
 * §6.8): exact seeds, wildcard bases, delegation points and the proxied names of kind
 * `ip` / `host` only (critic A5: placeholders, Cloudflare addresses, Tunnels and SaaS
 * never become hints or targets). Private-looking names are left out by default.
 * @param {object} zone
 * @param {{ skip?: Iterable<string>|null, skipPrivate?: boolean }} [opts]
 * @returns {{ v: 1, origin: string|null, names: string[], wildcardBases: string[], delegations: string[],
 *   proxied: Array<{ name: string, ips: string[], host: string|null }>, skipped: string[] }}
 */
export function zoneScanInput(zone, { skip = null, skipPrivate = true } = {}) {
  const idx = zoneIndex(zone);
  const skipSet = new Set(skip ? [...skip].map(canonName) : []);
  if (skipPrivate) for (const n of privateLookingNames(zone)) skipSet.add(n);
  const seeds = deriveSeeds(zone, { skip: skipSet });
  const proxied = [];
  const skipped = new Set(seeds.excluded.filter((e) => e.why === 'skipped').map((e) => e.name));
  const core = proxiedCore(idx);
  for (const row of sortHostnames([...core.rows.keys()]).map((n) => core.rows.get(n))) {
    if (row.kind !== 'ip' && row.kind !== 'host') continue;
    if (skipSet.has(row.name)) {
      skipped.add(row.name);
      continue;
    }
    proxied.push({ name: row.name, ips: [...row.ips], host: row.host });
  }
  return {
    v: 1,
    origin: idx.origin,
    names: seeds.names,
    wildcardBases: seeds.wildcardBases,
    delegations: seeds.delegations,
    proxied,
    skipped: sortHostnames([...skipped])
  };
}

/**
 * The constants the CLI port must mirror (`tests/fixtures/zones-analysis/zone-constants.json`).
 * @returns {object}
 */
export function zoneConstants() {
  const cf = getProvider('cloudflare');
  const cnameSuffixes = {};
  const cnamePatterns = {};
  const dnsOnly = [];
  for (const p of PROVIDERS) {
    if (p.cnameSuffixes.length) cnameSuffixes[p.id] = [...p.cnameSuffixes];
    if (p.cnamePatterns.length) cnamePatterns[p.id] = p.cnamePatterns.map((re) => re.source);
    if (p.dnsOnly) dnsOnly.push(p.id);
  }
  return {
    placeholders: [...PLACEHOLDERS],
    tunnel: TUNNEL_SUFFIX,
    cfHosted: CF_HOSTED_SUFFIXES.map((suffix, i) => ({ suffix, provider: CF_HOSTED_PROVIDERS[i] })),
    awsOrigins: AWS_ORIGIN_PROVIDERS.map((p) => ({ ...p })),
    cloudflareCidrs: cf ? [...cf.cidrs] : [],
    cnameSuffixes,
    cnamePatterns,
    dnsOnly,
    internalLabels: [...INTERNAL_LABELS],
    internalSuffixes: [...INTERNAL_SUFFIXES],
    maxCnameChain: MAX_CNAME_CHAIN
  };
}
