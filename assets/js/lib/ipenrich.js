/**
 * ipenrich.js — IP Intel's routing enrichment of one address: the announced prefix and origin AS,
 * the RPKI validity of prefix + origin (with the ROAs and their max length), routing sanity (not
 * announced, several origin ASes, more-specific routes, low visibility), the abuse contact, the
 * origin network's PeeringDB record, and a CIDR breadcrumb (/8 › /16 › /24 › announced prefix ›
 * address) with the user's servers inside each level.
 *
 * Data sources (CORS verified live 2026-10-08 with an Origin header):
 *  - RIPEstat (ACAO *; `sourceapp` is always sent, as RIPE NCC asks):
 *      network-info         → data.prefix, data.asns ['64496'] (only when IP Intel's row brought no prefix)
 *      rpki-validation      → data.status 'valid' | 'invalid_asn' | 'invalid_length' | 'unknown',
 *                             data.validating_roas [{ origin, prefix, max_length, validity }], data.validator
 *      routing-status       → data.origins [{ origin }], data.more_specifics / less_specifics [{ prefix, origin }],
 *                             data.visibility.v4|v6 { ris_peers_seeing, total_ris_peers }, data.first_seen { time }
 *      abuse-contact-finder → data.abuse_contacts [...], data.authoritative_rir ('arin', 'ripe' …)
 *  - PeeringDB `/api/net?asn=N` (ACAO echoes the page's origin): data[0] { id, name, aka, website,
 *    info_type, info_types [...], info_scope, policy_general, irr_as_set }; an AS it has no record of
 *    answers HTTP 404 `{ data: [] }`. Anonymous use is throttled after ~16 quick calls (429,
 *    Retry-After 10, a header CORS does not expose): one request per {@link PEERINGDB_INTERVAL_MS},
 *    one per AS number (cached), and a 429 pauses the queue for the Retry-After (10 s when it cannot
 *    be read) and asks once more.
 *
 * Only a globally routable address (lib/ip.js isGloballyRoutable) is ever sent: private, reserved
 * and documentation space is answered here with `skipped: 'not-routable'` and no request. The
 * breadcrumb and the server matching are local: the server list never leaves the browser.
 * DOM-free; runs in browsers and Node 22. All I/O is injectable (`fetchImpl`, `sleep`, `now`).
 */

import {
  fetchJson, fetchAndRead, retry, createLimiter, createCache, errorKind, sleep as realSleep,
  throwIfAborted, abortReasonToError, HttpError, ParseError, parseRetryAfter, uniq
} from './util.js';
import { parseIP, parseCidr, cidrContains, formatIP, normalizeIP, isGloballyRoutable } from './ip.js';
import { RIPESTAT_BASE, RIPESTAT_SOURCEAPP } from './ipintel.js';

/** PeeringDB's network API (`?asn=N`). */
export const PEERINGDB_NET = 'https://www.peeringdb.com/api/net';
/** Least time between two PeeringDB requests (its anonymous throttle trips after ~16 quick calls). */
export const PEERINGDB_INTERVAL_MS = 4000;
/** How long a PeeringDB 429 pauses the queue when its Retry-After cannot be read (it sends 10 s). */
export const PEERINGDB_PAUSE_MS = 10000;
/** The longest 429 pause the queue waits out before asking once more (else the failure is returned). */
export const PEERINGDB_WAIT_CAP_MS = 15000;
/** Origin ASes asked about per prefix (a MOAS prefix rarely has more). */
export const MAX_ORIGINS = 4;
/** More-specific routes kept per prefix (the count is always the full one). */
export const MAX_MORE_SPECIFICS = 20;

/**
 * Every source of an enrichment, as a lib/sourcestatus.js STATUS_SOURCES id: RIPEstat's four
 * data calls and PeeringDB.
 */
export const ENRICH_SOURCES = Object.freeze(['ripestat-network', 'ripestat-rpki', 'ripestat-routing', 'ripestat-abuse', 'peeringdb']);
/** RPKI route-origin validity (RFC 6811): RIPEstat's `unknown` is NotFound. */
export const RPKI_STATUSES = Object.freeze(['valid', 'invalid-asn', 'invalid-length', 'not-found']);
/** Routing sanity flags of {@link parseRoutingStatus}. */
export const ROUTING_FLAGS = Object.freeze(['not-announced', 'moas', 'more-specifics', 'low-visibility']);
/** Why an address was not looked up. */
export const ENRICH_SKIPS = Object.freeze(['invalid', 'not-routable']);
/** Below this share of RIS peers seeing a prefix, it is flagged 'low-visibility'. */
export const LOW_VISIBILITY = 0.5;

/** PeeringDB's network types (info_types labels) → codes the UI words. */
export const PEERINGDB_TYPES = Object.freeze({
  NSP: 'nsp',
  Content: 'content',
  'Cable/DSL/ISP': 'isp',
  Enterprise: 'enterprise',
  'Educational/Research': 'education',
  'Non-Profit': 'non-profit',
  'Route Server': 'route-server',
  'Network Services': 'network-services',
  'Route Collector': 'route-collector',
  Government: 'government',
  'Not Disclosed': 'not-disclosed'
});
/** The codes of {@link PEERINGDB_TYPES}. */
export const PEERINGDB_TYPE_CODES = Object.freeze([...new Set(Object.values(PEERINGDB_TYPES))]);

/** The breadcrumb's fixed levels per IP version (the announced prefix and the address are added). */
export const CIDR_BLOCKS = Object.freeze({ 4: Object.freeze([8, 16, 24]), 6: Object.freeze([32, 48, 64]) });

const DEFAULT_TIMEOUT_MS = 12000;
const RESULT_TTL_MS = 60 * 60 * 1000; // routing data change slowly
const PEERINGDB_TTL_MS = 6 * 60 * 60 * 1000;
const RIR_NAMES = Object.freeze({ arin: 'ARIN', ripe: 'RIPE NCC', apnic: 'APNIC', lacnic: 'LACNIC', afrinic: 'AFRINIC' });
const RPKI_CODES = Object.freeze({ valid: 'valid', invalid_asn: 'invalid-asn', invalid_length: 'invalid-length', unknown: 'not-found' });

/* ------------------------------------------------------------------------ */
/* URLs                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * RIPEstat network-info of an address (its most specific announced prefix and origin ASes).
 * @param {string} ip a canonical address
 * @returns {string}
 */
export function networkInfoUrl(ip) {
  return `${RIPESTAT_BASE}/network-info/data.json?resource=${ip}&sourceapp=${RIPESTAT_SOURCEAPP}`;
}

/**
 * RIPEstat rpki-validation of a prefix announced by an AS.
 * @param {number} asn
 * @param {string} prefix
 * @returns {string}
 */
export function rpkiValidationUrl(asn, prefix) {
  return `${RIPESTAT_BASE}/rpki-validation/data.json?resource=AS${asn}&prefix=${prefix}&sourceapp=${RIPESTAT_SOURCEAPP}`;
}

/**
 * RIPEstat routing-status of a prefix.
 * @param {string} prefix
 * @returns {string}
 */
export function routingStatusUrl(prefix) {
  return `${RIPESTAT_BASE}/routing-status/data.json?resource=${prefix}&sourceapp=${RIPESTAT_SOURCEAPP}`;
}

/**
 * RIPEstat abuse-contact-finder of an address.
 * @param {string} ip
 * @returns {string}
 */
export function abuseContactUrl(ip) {
  return `${RIPESTAT_BASE}/abuse-contact-finder/data.json?resource=${ip}&sourceapp=${RIPESTAT_SOURCEAPP}`;
}

/**
 * PeeringDB's network record of an AS number.
 * @param {number} asn
 * @returns {string}
 */
export function peeringdbNetUrl(asn) {
  return `${PEERINGDB_NET}?asn=${asn}`;
}

/* ------------------------------------------------------------------------ */
/* Parsers (exported for tests)                                             */
/* ------------------------------------------------------------------------ */

/** The `data` of a RIPEstat answer; an error answer or one without data throws. */
function ripeData(json) {
  if (!json || typeof json !== 'object') throw new ParseError('RIPEstat: empty response');
  if (json.status && json.status !== 'ok') {
    const msg = Array.isArray(json.messages) ? json.messages.map((m) => (Array.isArray(m) ? m[1] : m)).join('; ') : '';
    throw new Error(`RIPEstat: ${msg || json.status}`);
  }
  if (!json.data || typeof json.data !== 'object') throw new ParseError('RIPEstat: response has no data');
  return json.data;
}

/** A positive AS number from a number or a numeric string ('AS64496' too), else null. */
function asNumber(v) {
  const n = Number(typeof v === 'string' ? v.trim().replace(/^AS/i, '') : v);
  return Number.isInteger(n) && n > 0 && n < 2 ** 32 ? n : null;
}

/** A canonical prefix ('192.0.2.0/24'), or null. */
function canonicalPrefix(v) {
  const c = typeof v === 'string' ? parseCidr(v) : null;
  return c && v.includes('/') ? `${formatIP(c.network, c.version)}/${c.prefix}` : null;
}

/**
 * Parse a RIPEstat network-info answer.
 * @param {object} json `{ status, data: { asns: ['64496'], prefix: '192.0.2.0/24' } }`
 * @returns {{ prefix: string|null, asns: number[] }} prefix null: no route covers the address
 * @throws {Error} when the answer reports an error or has no data
 */
export function parseNetworkInfo(json) {
  const data = ripeData(json);
  const asns = uniq((Array.isArray(data.asns) ? data.asns : []).map(asNumber).filter((n) => n !== null));
  return { prefix: canonicalPrefix(data.prefix), asns };
}

/**
 * @typedef {object} Roa
 * @property {number|null} origin the AS the ROA authorises
 * @property {string|null} prefix
 * @property {number|null} maxLength
 * @property {string|null} validity a {@link RPKI_STATUSES} code of this ROA against the route
 */

/**
 * Parse a RIPEstat rpki-validation answer.
 * @param {object} json `{ status, data: { status, validating_roas: [{ origin, prefix, max_length, validity }], validator } }`
 * @returns {{ status: string, roas: Roa[], validator: string|null }} status: a {@link RPKI_STATUSES} code
 * @throws {Error} when the answer reports an error, has no data or an unknown status
 */
export function parseRpkiValidation(json) {
  const data = ripeData(json);
  const status = RPKI_CODES[String(data.status ?? '').toLowerCase()];
  if (!status) throw new ParseError(`RIPEstat: unknown RPKI status ${JSON.stringify(data.status ?? null)}`);
  const roas = (Array.isArray(data.validating_roas) ? data.validating_roas : []).filter((r) => r && typeof r === 'object').map((r) => ({
    origin: asNumber(r.origin),
    prefix: canonicalPrefix(r.prefix),
    maxLength: Number.isInteger(Number(r.max_length)) && r.max_length !== null && r.max_length !== '' ? Number(r.max_length) : null,
    validity: RPKI_CODES[String(r.validity ?? '').toLowerCase()] || null
  }));
  return { status, roas, validator: typeof data.validator === 'string' && data.validator ? data.validator : null };
}

/**
 * @typedef {object} RoutingStatus
 * @property {boolean} announced at least one origin AS announces the prefix
 * @property {number[]} origins origin ASes
 * @property {Array<{ prefix: string, origin: number|null }>} moreSpecifics longer prefixes inside it that are
 *   announced too (at most {@link MAX_MORE_SPECIFICS})
 * @property {number} moreSpecificCount every one of them
 * @property {Array<{ prefix: string, origin: number|null }>} lessSpecifics covering prefixes
 * @property {{ seeing: number, total: number }|null} visibility RIS peers seeing the prefix, of those of its IP version
 * @property {string|null} firstSeen when RIS first saw it (ISO time)
 * @property {string[]} flags {@link ROUTING_FLAGS}
 */

/**
 * Parse a RIPEstat routing-status answer of a prefix.
 * @param {object} json `{ status, data: { origins, more_specifics, less_specifics, visibility, first_seen } }`
 * @param {{ version?: 4|6 }} [opts] the prefix's IP version (whose visibility counts); default from data.resource
 * @returns {RoutingStatus}
 * @throws {Error} when the answer reports an error or has no data
 */
export function parseRoutingStatus(json, { version = null } = {}) {
  const data = ripeData(json);
  const origins = uniq((Array.isArray(data.origins) ? data.origins : []).map((o) => asNumber(o && typeof o === 'object' ? o.origin : o)).filter((n) => n !== null));
  const routes = (list) => (Array.isArray(list) ? list : [])
    .map((r) => (r && typeof r === 'object' ? { prefix: canonicalPrefix(r.prefix), origin: asNumber(r.origin) } : null))
    .filter((r) => r && r.prefix);
  const more = routes(data.more_specifics);
  const v = version || (typeof data.resource === 'string' && data.resource.includes(':') ? 6 : 4);
  const vis = data.visibility && typeof data.visibility === 'object' ? data.visibility[`v${v}`] : null;
  const seeing = vis ? Number(vis.ris_peers_seeing) : NaN;
  const total = vis ? Number(vis.total_ris_peers) : NaN;
  const visibility = Number.isFinite(seeing) && Number.isFinite(total) && total > 0 ? { seeing, total } : null;
  const announced = origins.length > 0;
  const flags = [];
  if (!announced) flags.push('not-announced');
  if (origins.length > 1) flags.push('moas');
  if (more.length) flags.push('more-specifics');
  if (announced && visibility && visibility.seeing / visibility.total < LOW_VISIBILITY) flags.push('low-visibility');
  const first = data.first_seen && typeof data.first_seen === 'object' && typeof data.first_seen.time === 'string' ? data.first_seen.time : null;
  return {
    announced,
    origins,
    moreSpecifics: more.slice(0, MAX_MORE_SPECIFICS),
    moreSpecificCount: more.length,
    lessSpecifics: routes(data.less_specifics),
    visibility,
    firstSeen: first,
    flags
  };
}

/** A plausible e-mail address (RIR abuse-c contacts are plain addresses). */
const EMAIL_RE = /^[^\s@<>()",;:]+@[^\s@<>()",;:]+\.[^\s@<>()",;:]+$/;

/**
 * Parse a RIPEstat abuse-contact-finder answer.
 * @param {object} json `{ status, data: { abuse_contacts: [...], authoritative_rir } }`
 * @returns {{ contacts: string[], rir: string|null }} rir: 'ARIN' | 'RIPE NCC' | 'APNIC' | 'LACNIC' | 'AFRINIC'
 * @throws {Error} when the answer reports an error or has no data
 */
export function parseAbuseContact(json) {
  const data = ripeData(json);
  const contacts = uniq((Array.isArray(data.abuse_contacts) ? data.abuse_contacts : [])
    .filter((c) => typeof c === 'string').map((c) => c.trim()).filter((c) => c.length <= 254 && EMAIL_RE.test(c)));
  const rir = RIR_NAMES[String(data.authoritative_rir ?? '').trim().toLowerCase()] || null;
  return { contacts, rir };
}

/**
 * @typedef {object} PeeringdbNet
 * @property {number} id PeeringDB's network id (its page is /net/<id>)
 * @property {number} asn
 * @property {string} name
 * @property {string|null} aka
 * @property {string|null} website an http(s) URL, else null
 * @property {string[]} types PeeringDB's labels ('Content', 'NSP' …; {@link PEERINGDB_TYPES} has codes)
 * @property {string|null} scope 'Global', 'Europe' …
 * @property {string|null} policy general peering policy: 'Open', 'Selective', 'Restrictive', 'No'
 * @property {string|null} irrAsSet
 */

/** Trimmed text or null. */
const text = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);

/**
 * Parse a PeeringDB `/api/net?asn=N` answer.
 * @param {object} json `{ data: [{ id, name, aka, website, asn, info_type, info_types, info_scope, policy_general, irr_as_set }], meta }`
 * @returns {PeeringdbNet|null} null: PeeringDB has no record of the AS
 * @throws {ParseError} when the answer is not PeeringDB's shape
 */
export function parsePeeringdbNet(json) {
  if (!json || typeof json !== 'object' || !Array.isArray(json.data)) throw new ParseError('PeeringDB: response has no data list');
  const n = json.data.find((d) => d && typeof d === 'object' && Number.isInteger(d.id));
  if (!n) return null;
  let website = null;
  try {
    const u = text(n.website) ? new URL(n.website.trim()) : null;
    website = u && (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : null;
  } catch {
    website = null;
  }
  const types = uniq([...(Array.isArray(n.info_types) ? n.info_types : []), n.info_type].map(text).filter(Boolean));
  return {
    id: n.id,
    asn: asNumber(n.asn),
    name: text(n.name) || `AS${n.asn}`,
    aka: text(n.aka),
    website,
    types,
    scope: text(n.info_scope),
    policy: text(n.policy_general),
    irrAsSet: text(n.irr_as_set)
  };
}

/**
 * The code of a PeeringDB network type label (null for a label it does not know).
 * @param {string} label
 * @returns {string|null}
 */
export function peeringdbTypeCode(label) {
  return Object.hasOwn(PEERINGDB_TYPES, label) ? PEERINGDB_TYPES[label] : null;
}

/* ------------------------------------------------------------------------ */
/* CIDR breadcrumb                                                          */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} CidrLevel
 * @property {string} cidr '192.0.0.0/8' … the address's own level is '/32' or '/128'
 * @property {number} length prefix length
 * @property {boolean} announced the announced prefix (it may also be one of the fixed blocks)
 * @property {boolean} address the address itself
 */

/** The canonical form a lookup uses: an IPv4-mapped IPv6 address is its IPv4 address. */
function lookupForm(ip) {
  const canonical = normalizeIP(typeof ip === 'string' ? ip : '');
  if (!canonical) return null;
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(canonical);
  return m ? m[1] : canonical;
}

/**
 * The breadcrumb of an address, broadest first: the fixed blocks of its version ({@link CIDR_BLOCKS}:
 * /8, /16, /24 or /32, /48, /64), the announced prefix where it falls (marked; merged with a block
 * of the same length; ignored when it does not hold the address) and the address itself.
 * @param {string} ip
 * @param {string|null} [prefix] the announced prefix
 * @returns {CidrLevel[]} [] for an invalid address
 */
export function cidrLevels(ip, prefix = null) {
  const canonical = lookupForm(ip);
  const addr = canonical ? parseIP(canonical) : null;
  if (!addr) return [];
  const bits = addr.version === 4 ? 32 : 128;
  const levels = new Map(CIDR_BLOCKS[addr.version].map((length) => [length, { length, announced: false, address: false }]));
  const p = typeof prefix === 'string' && prefix.includes('/') ? parseCidr(prefix) : null;
  if (p && p.version === addr.version && p.prefix > 0 && p.prefix < bits && cidrContains(p, addr)) {
    const level = levels.get(p.prefix) || { length: p.prefix, announced: false, address: false };
    level.announced = true;
    levels.set(p.prefix, level);
  }
  levels.set(bits, { length: bits, announced: false, address: true });
  return [...levels.values()].sort((a, b) => a.length - b.length).map((l) => {
    const c = parseCidr(`${canonical}/${l.length}`);
    return { cidr: `${formatIP(c.network, c.version)}/${l.length}`, ...l };
  });
}

/**
 * @typedef {object} LevelServer
 * @property {string} id the server's id (its name, or its first address)
 * @property {string} name
 * @property {string[]} ips its addresses inside the level
 * @property {boolean} here it holds the address the breadcrumb is of
 */

/**
 * The user's servers inside each breadcrumb level. Local only: nothing is sent.
 * @param {CidrLevel[]} levels from {@link cidrLevels}
 * @param {Iterable<[string, Array<{ id?: string, name?: string }>]>} entries the inventory index (address → servers)
 * @param {string|null} [ip] the address of the breadcrumb (its servers are marked `here`)
 * @returns {Array<CidrLevel & { servers: LevelServer[] }>} servers: those holding the address first, then by name
 */
export function serversInLevels(levels, entries, ip = null) {
  const ranges = levels.map((l) => parseCidr(l.cidr));
  const found = levels.map(() => new Map());
  const self = ip ? lookupForm(ip) : null;
  for (const [address, servers] of entries || []) {
    const canonical = lookupForm(address);
    const a = canonical ? parseIP(canonical) : null;
    if (!a) continue;
    ranges.forEach((range, i) => {
      if (!range || !cidrContains(range, a)) return;
      for (const s of Array.isArray(servers) ? servers : []) {
        if (!s || typeof s !== 'object') continue;
        const id = String(s.id || s.name || canonical);
        let entry = found[i].get(id);
        if (!entry) {
          entry = { id, name: String(s.name || id), ips: [], here: false };
          found[i].set(id, entry);
        }
        if (!entry.ips.includes(canonical)) entry.ips.push(canonical);
        if (self && canonical === self) entry.here = true;
      }
    });
  }
  const order = (a, b) => (a.here !== b.here ? (a.here ? -1 : 1) : a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  return levels.map((l, i) => ({ ...l, servers: [...found[i].values()].sort(order) }));
}

/* ------------------------------------------------------------------------ */
/* Service                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} EnrichFailure
 * @property {string} source an {@link ENRICH_SOURCES} id
 * @property {string} error technical message ('HTTP 429', 'Network error …')
 * @property {string} errorKind util.errorKind()
 * @property {number|null} status HTTP status, when the service answered one
 * @property {number|null} retryAfterMs the service's Retry-After (PeeringDB's pause when it could not be read)
 * @property {number|null} [asn] the origin AS a per-AS source failed for
 * @property {number} at when it failed (ms)
 */

/**
 * @typedef {object} EnrichResult
 * @property {string} ip the canonical address (an IPv4-mapped IPv6 address is its IPv4 address)
 * @property {4|6|0} version
 * @property {string|null} skipped an {@link ENRICH_SKIPS} code: nothing was sent
 * @property {string|null} prefix the announced prefix (null: not announced, or not known yet)
 * @property {number[]} origins origin ASes of the prefix
 * @property {'ip-intel'|'ripestat-network'|null} prefixFrom where the prefix and origins came from
 * @property {boolean|null} announced null while not known
 * @property {Array<{ asn: number, status: string, roas: Roa[], validator: string|null }>|null} rpki per origin; null: not asked
 * @property {RoutingStatus|null} routing null: not asked
 * @property {{ contacts: string[], rir: string|null }|null} abuse null: not asked
 * @property {Array<{ asn: number, net: PeeringdbNet|null }>|null} peeringdb per origin (net null: no record); null: not asked
 * @property {EnrichFailure[]} errors every source that failed (read by lib/sourcestatus.js)
 * @property {number} at when the result was made (ms)
 */

/**
 * What IP Intel's row already knows about an address (lib/ipintel.js IpInfo), so network-info is
 * asked only when it brought no prefix.
 * @param {object|null} info an IpInfo
 * @returns {{ prefix: string|null, asns: number[], announced: boolean|null }|null}
 */
export function knownFromInfo(info) {
  if (!info || typeof info !== 'object') return null;
  const asns = uniq((Array.isArray(info.asns) ? info.asns : []).map((a) => asNumber(a && typeof a === 'object' ? a.asn : a)).filter((n) => n !== null));
  return { prefix: canonicalPrefix(info.prefix), asns, announced: typeof info.announced === 'boolean' ? info.announced : null };
}

function emptyResult(ip, version, now) {
  return {
    ip, version, skipped: null, prefix: null, origins: [], prefixFrom: null, announced: null,
    rpki: null, routing: null, abuse: null, peeringdb: null, errors: [], at: now()
  };
}

function cloneResult(r) {
  return {
    ...r,
    origins: [...r.origins],
    rpki: r.rpki ? r.rpki.map((x) => ({ ...x, roas: x.roas.map((o) => ({ ...o })) })) : null,
    routing: r.routing ? { ...r.routing, origins: [...r.routing.origins], flags: [...r.routing.flags] } : null,
    abuse: r.abuse ? { ...r.abuse, contacts: [...r.abuse.contacts] } : null,
    peeringdb: r.peeringdb ? r.peeringdb.map((x) => ({ ...x })) : null,
    errors: r.errors.map((e) => ({ ...e }))
  };
}

const isAbort = (err) => errorKind(err) === 'abort';

/**
 * The enrichment service. It keeps complete results per address for an hour and PeeringDB records
 * per AS number for six hours, paces PeeringDB ({@link PEERINGDB_INTERVAL_MS}) and runs at most
 * `concurrency` RIPEstat requests at a time. Only an AbortError of the caller's signal rejects;
 * every other failure is an entry of `errors`.
 * @param {{ fetchImpl?: typeof fetch, timeoutMs?: number, retries?: number, concurrency?: number,
 *   now?: () => number, sleep?: (ms: number, signal?: AbortSignal) => Promise<void>,
 *   peeringdbIntervalMs?: number, routable?: (ip: string) => boolean }} [opts]
 *   `routable` decides which addresses may be sent (default lib/ip.js isGloballyRoutable).
 * @returns {{
 *   enrich: (ip: string, opts?: { known?: { prefix?: string|null, asns?: number[], announced?: boolean|null }|null,
 *     signal?: AbortSignal, noCache?: boolean }) => Promise<EnrichResult>,
 *   retry: (prev: EnrichResult, opts?: { sources?: string[]|null, signal?: AbortSignal }) => Promise<EnrichResult>,
 *   peek: (ip: string) => EnrichResult|null,
 *   clearCache: () => void }}
 */
export function createIpEnrich({
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  retries = 1,
  concurrency = 4,
  now = Date.now,
  sleep = realSleep,
  peeringdbIntervalMs = PEERINGDB_INTERVAL_MS,
  routable = isGloballyRoutable
} = {}) {
  const limiter = createLimiter(concurrency);
  const results = createCache({ maxEntries: 500, ttlMs: RESULT_TTL_MS, now });
  const nets = createCache({ maxEntries: 2000, ttlMs: PEERINGDB_TTL_MS, now });
  // PeeringDB's queue: each request waits for the one before it and for `pdbNextAt`.
  let pdbTail = Promise.resolve();
  let pdbNextAt = 0;

  const getRipe = (url, signal) => limiter.run(
    () => retry(() => fetchJson(url, { fetchImpl, signal, timeoutMs, headers: { accept: 'application/json' } }), {
      retries, signal, baseDelayMs: 400, maxDelayMs: 4000
    }),
    { signal }
  );

  function failure(source, err, extra = {}) {
    const status = err instanceof HttpError ? err.status : null;
    const retryAfterMs = err && Number.isFinite(err.retryAfterMs) ? err.retryAfterMs : null;
    const error = err instanceof HttpError ? `HTTP ${err.status}` : String((err && err.message) || err || 'Unknown error');
    return { source, error, errorKind: errorKind(err), status, retryAfterMs, ...extra, at: now() };
  }

  /** One PeeringDB request: 404 is "no record"; a 429 carries the pause it caused. */
  async function askPeeringdb(asn, signal) {
    return fetchAndRead(peeringdbNetUrl(asn), { fetchImpl, signal, timeoutMs, headers: { accept: 'application/json' } }, async (res) => {
      if (res.status === 404) return null;
      if (!res.ok) {
        const header = res.headers && typeof res.headers.get === 'function' ? res.headers.get('retry-after') : null;
        const wait = parseRetryAfter(header, now());
        throw new HttpError(res.status, res.url || peeringdbNetUrl(asn), '', {
          statusText: res.statusText || '',
          retryAfterMs: res.status === 429 ? (wait ?? PEERINGDB_PAUSE_MS) : wait
        });
      }
      const body = await res.text();
      let json;
      try {
        json = JSON.parse(body);
      } catch (err) {
        throw new ParseError(`PeeringDB: invalid JSON (${err.message})`, { cause: err, body });
      }
      return parsePeeringdbNet(json);
    });
  }

  /**
   * PeeringDB's record of an AS, through the paced queue: a cached answer needs no turn, a request
   * waits for the one before it and for the pace, and a 429 pauses the queue and is asked once more
   * when the pause is short enough. Resolves with the record (null: no record); rejects with the
   * failure, or an AbortError.
   */
  async function peeringdb(asn, signal) {
    if (nets.has(asn)) return nets.get(asn);
    const before = pdbTail;
    let release;
    const mine = new Promise((resolve) => { release = resolve; });
    pdbTail = before.then(() => mine);
    try {
      await waitFor(before, signal);
      // An earlier turn may have asked for the same AS.
      if (nets.has(asn)) return nets.get(asn);
      for (let attempt = 0; ; attempt += 1) {
        const wait = pdbNextAt - now();
        if (wait > 0) await sleep(wait, signal);
        throwIfAborted(signal);
        pdbNextAt = now() + peeringdbIntervalMs;
        try {
          const net = await askPeeringdb(asn, signal);
          nets.set(asn, net);
          return net;
        } catch (err) {
          if (!(err instanceof HttpError) || err.status !== 429) throw err;
          pdbNextAt = Math.max(pdbNextAt, now() + err.retryAfterMs);
          if (attempt >= 1 || err.retryAfterMs > PEERINGDB_WAIT_CAP_MS) throw err;
        }
      }
    } finally {
      release();
    }
  }

  /** Wait for `promise` (which never rejects) unless `signal` aborts first. */
  function waitFor(promise, signal) {
    if (!signal) return promise;
    throwIfAborted(signal);
    return new Promise((resolve, reject) => {
      const onAbort = () => reject(abortReasonToError(signal.reason));
      signal.addEventListener('abort', onAbort, { once: true });
      promise.then(() => {
        signal.removeEventListener('abort', onAbort);
        resolve();
      });
    });
  }

  /** Run `jobs` (each `[source, () => Promise, (value) => void, extra?]`) in parallel; failures go into `out.errors`. */
  async function settle(out, jobs, signal) {
    const settled = await Promise.allSettled(jobs.map(([, run]) => run()));
    throwIfAborted(signal);
    settled.forEach((res, i) => {
      const [source, , apply, extra] = jobs[i];
      if (res.status === 'fulfilled') apply(res.value);
      else if (isAbort(res.reason) && signal?.aborted) throw res.reason;
      else out.errors.push(failure(source, res.reason, extra));
    });
  }

  /** Has a stage-two source never been asked for `out` (no value, no failure)? */
  const neverAsked = (out, source) => !out.errors.some((e) => e.source === source) && ({
    'ripestat-rpki': out.rpki, 'ripestat-routing': out.routing, peeringdb: out.peeringdb
  })[source] === null;

  /**
   * Ask the sources in `want` (and the stage-two sources a newly learnt prefix lets ask): first the
   * abuse contact and, when wanted, the prefix and origins; then, for an announced prefix, RPKI and
   * PeeringDB per origin and the routing status.
   */
  async function fill(out, want, signal) {
    const first = [];
    if (want.has('ripestat-abuse')) {
      first.push(['ripestat-abuse', () => getRipe(abuseContactUrl(out.ip), signal).then(parseAbuseContact), (v) => { out.abuse = v; }]);
    }
    if (want.has('ripestat-network')) {
      first.push(['ripestat-network', () => getRipe(networkInfoUrl(out.ip), signal).then(parseNetworkInfo), (v) => {
        out.prefix = v.prefix;
        out.origins = v.prefix ? v.asns.slice(0, MAX_ORIGINS) : [];
        out.prefixFrom = 'ripestat-network';
        out.announced = !!v.prefix;
      }]);
    }
    await settle(out, first, signal);
    if (!out.prefix) return;
    const asks = (source) => want.has(source) || neverAsked(out, source);
    const second = [];
    if (asks('ripestat-routing')) {
      const version = out.prefix.includes(':') ? 6 : 4;
      second.push(['ripestat-routing', () => getRipe(routingStatusUrl(out.prefix), signal).then((j) => parseRoutingStatus(j, { version })), (v) => { out.routing = v; }]);
    }
    if (out.origins.length && asks('ripestat-rpki')) {
      out.errors = out.errors.filter((e) => e.source !== 'ripestat-rpki');
      const rpki = [];
      out.rpki = rpki;
      for (const asn of out.origins) {
        second.push(['ripestat-rpki', () => getRipe(rpkiValidationUrl(asn, out.prefix), signal).then(parseRpkiValidation),
          (v) => { rpki.push({ asn, ...v }); }, { asn }]);
      }
    }
    if (out.origins.length && asks('peeringdb')) {
      out.errors = out.errors.filter((e) => e.source !== 'peeringdb');
      const found = [];
      out.peeringdb = found;
      for (const asn of out.origins) second.push(['peeringdb', () => peeringdb(asn, signal), (net) => { found.push({ asn, net }); }, { asn }]);
    }
    await settle(out, second, signal);
    // Per-origin answers in origin order, whatever order they arrived in.
    const byOrigin = (a, b) => out.origins.indexOf(a.asn) - out.origins.indexOf(b.asn);
    if (out.rpki) out.rpki.sort(byOrigin);
    if (out.peeringdb) out.peeringdb.sort(byOrigin);
  }

  /** A result whose every asked source answered is kept for the next look. */
  function keep(out) {
    if (!out.errors.length && !out.skipped) results.set(out.ip, cloneResult(out));
  }

  /**
   * Enrich one address. Nothing is sent for an invalid or non-routable address (`skipped`).
   * @param {string} ip
   * @param {{ known?: { prefix?: string|null, asns?: number[], announced?: boolean|null }|null, signal?: AbortSignal,
   *   noCache?: boolean }} [opts] known: what IP Intel's row knows ({@link knownFromInfo}); with a prefix and an
   *   origin (or `announced: false`) network-info is not asked
   * @returns {Promise<EnrichResult>}
   */
  async function enrich(ip, { known = null, signal, noCache = false } = {}) {
    throwIfAborted(signal);
    const canonical = lookupForm(ip);
    if (!canonical) return { ...emptyResult(String(ip ?? ''), 0, now), skipped: 'invalid' };
    const out = emptyResult(canonical, canonical.includes(':') ? 6 : 4, now);
    if (!routable(canonical)) return { ...out, skipped: 'not-routable' };
    if (!noCache) {
      const hit = results.get(canonical);
      if (hit) return cloneResult(hit);
    }
    const want = new Set(ENRICH_SOURCES);
    const k = known && typeof known === 'object' ? known : null;
    const prefix = k ? canonicalPrefix(k.prefix) : null;
    const asns = k && Array.isArray(k.asns) ? uniq(k.asns.map(asNumber).filter((n) => n !== null)) : [];
    const levels = prefix ? cidrLevels(canonical, prefix) : [];
    if (prefix && asns.length && levels.some((l) => l.announced)) {
      Object.assign(out, { prefix, origins: asns.slice(0, MAX_ORIGINS), prefixFrom: 'ip-intel', announced: true });
      want.delete('ripestat-network');
    } else if (k && k.announced === false) {
      Object.assign(out, { prefixFrom: 'ip-intel', announced: false });
      want.delete('ripestat-network');
    }
    await fill(out, want, signal);
    out.at = now();
    keep(out);
    return out;
  }

  /**
   * Ask again only the sources that failed (or the ones given) and merge their answers into a copy
   * of `prev`; a prefix learnt now also lets the sources that need it be asked.
   * @param {EnrichResult} prev
   * @param {{ sources?: string[]|null, signal?: AbortSignal }} [opts] default: every source in `prev.errors`
   * @returns {Promise<EnrichResult>}
   */
  async function retrySources(prev, { sources = null, signal } = {}) {
    throwIfAborted(signal);
    if (!prev || typeof prev !== 'object') return prev;
    const out = cloneResult(prev);
    if (out.skipped) return out;
    const asked = uniq((Array.isArray(sources) ? sources : prev.errors.map((e) => e.source)).filter((s) => ENRICH_SOURCES.includes(s)));
    if (!asked.length) return out;
    out.errors = out.errors.filter((e) => !asked.includes(e.source));
    await fill(out, new Set(asked), signal);
    out.at = now();
    keep(out);
    return out;
  }

  return {
    enrich,
    retry: retrySources,
    peek(ip) {
      const canonical = lookupForm(ip);
      const hit = canonical ? results.get(canonical) : undefined;
      return hit ? cloneResult(hit) : null;
    },
    clearCache() {
      results.clear();
      nets.clear();
    }
  };
}
