/**
 * ispdns.js — Global DNS › ISP resolvers: what the resolvers of real ISPs answer.
 *
 * - One Globalping DNS measurement whose probes each ask their own default resolver — the
 *   resolver of the network the probe sits in, an ISP's for an eyeball network — planned over the
 *   countries / networks the user picks, by default {@link ISP_DEFAULT_PROBES} probes over the
 *   continents ({@link planIspMeasurement}, built with lib/globalping.js dnsQueryRequest without a
 *   resolver).
 * - Its results become Global DNS rows of their own (`kind: 'isp'`, keys 'isp:…',
 *   {@link mapIspResults}) with the probe's country, city, ASN / network and the resolver address,
 *   which lib/propagation.js propagationVerdict judges with the public resolvers and the ECS
 *   locations (by design, propagating, or stale at these ISPs).
 * - A resolver's cache counts down: the TTL a probe gets is what is left of it
 *   ({@link remainingTtl}), so `expiresAt` says when an old answer an ISP still holds expires.
 *
 * Verified live on 2026-10-08 (one measurement, two probes, no resolver given): the measurement
 * echoes no `measurementOptions`; `result.resolver` reads the address the probe asked, or
 * 'private' for a private one (the dig SERVER line is masked then); the answers' TTLs are the
 * caches' remaining TTLs (204 s and 15 s for a 300 s record).
 *
 * DOM-free and without I/O: the caller sends the body through ui/globalping-gate.js.
 */

import { dnsQueryRequest, isProbeableDnsName, probeSummary, GP_DNS_TYPES, GP_LIMITS } from './globalping.js';
import { answerValues, answerAddresses } from './propagation.js';
import { parseZone } from './zoneparse.js';
import { ipVersion, isPrivateIP, normalizeIP } from './ip.js';

/** Globalping gate purpose of the ISP resolver measurement (ui/globalping-gate.js consent). */
export const ISP_PURPOSE = 'isp-dns';

/** Probe counts the panel offers; one measurement holds at most GP_LIMITS.maxProbesPerMeasurement. */
export const ISP_PROBE_CHOICES = Object.freeze([5, 10, 20, 50]);

/** Probes of the default measurement. */
export const ISP_DEFAULT_PROBES = 10;

/** At most this many places (countries / networks) in one measurement. */
export const ISP_MAX_PICKS = 10;

/** The default spread: continents by weight (10 probes: 3 Europe, 2 North America, 2 Asia, 1 each else). */
export const ISP_CONTINENTS = Object.freeze([
  Object.freeze({ continent: 'EU', weight: 3 }),
  Object.freeze({ continent: 'NA', weight: 2 }),
  Object.freeze({ continent: 'AS', weight: 2 }),
  Object.freeze({ continent: 'SA', weight: 1 }),
  Object.freeze({ continent: 'OC', weight: 1 }),
  Object.freeze({ continent: 'AF', weight: 1 })
]);

/** The Globalping probe tag of consumer (ISP) networks. */
export const EYEBALL_TAG = 'eyeball-network';

/** Why {@link planIspMeasurement} refuses (nothing is sent): the name, an internal name, the type, the places, the count. */
export const ISP_PLAN_ERRORS = Object.freeze(['name', 'internal', 'type', 'picks', 'probes']);

/** What one ISP row holds: still asking, an answer (any rcode), or no answer (failed, the probe went offline). */
export const ISP_ROW_STATUSES = Object.freeze(['pending', 'answer', 'failed', 'offline']);

/**
 * Last labels of names that only exist inside a network (RFC 6761, 6762, 8375, 9476 and the usual
 * private suffixes): such a name never goes to Globalping.
 */
export const INTERNAL_SUFFIXES = Object.freeze(['local', 'localhost', 'localdomain', 'internal', 'intranet', 'lan', 'home', 'corp',
  'private', 'invalid', 'test', 'onion', 'alt', 'arpa']);

/** Public resolvers a probe may use instead of its ISP's (the name the row shows for the address). */
const PUBLIC_RESOLVERS = Object.freeze({
  '1.1.1.1': 'Cloudflare', '1.0.0.1': 'Cloudflare', '2606:4700:4700::1111': 'Cloudflare', '2606:4700:4700::1001': 'Cloudflare',
  '8.8.8.8': 'Google Public DNS', '8.8.4.4': 'Google Public DNS', '2001:4860:4860::8888': 'Google Public DNS', '2001:4860:4860::8844': 'Google Public DNS',
  '9.9.9.9': 'Quad9', '149.112.112.112': 'Quad9', '2620:fe::fe': 'Quad9', '2620:fe::9': 'Quad9'
});

const ASN_RE = /^AS(\d{1,10})$/i;
const COUNTRY_RE = /^[A-Za-z]{2}$/;
// Free text for Globalping's `magic` location: a city, region, continent or network name.
const MAGIC_RE = /^[\p{L}\p{N}][\p{L}\p{N} .&'’()-]{0,62}$/u;

/**
 * Is `name` a name that only exists inside a network (`printer.local`, `intranet.corp`,
 * `nas.home.arpa`)?
 * @param {string} name canonical host name
 * @returns {boolean}
 */
export function isInternalName(name) {
  const labels = String(name || '').toLowerCase().replace(/\.$/, '').split('.');
  return INTERNAL_SUFFIXES.includes(labels[labels.length - 1]);
}

/**
 * The places a user typed ("TR, DE, AS9121, Comcast, Istanbul"): a two-letter code is a country,
 * AS<number> a network by ASN, anything else Globalping's free-text location (`magic`: a city,
 * region, continent or network name). Separated by commas, semicolons or new lines; duplicates
 * are dropped.
 * @param {string} text
 * @returns {{ picks: Array<{ kind: 'country'|'asn'|'magic', value: string|number, label: string }>, invalid: string[] }}
 */
export function parsePicks(text) {
  const picks = [];
  const invalid = [];
  const seen = new Set();
  for (const raw of String(text || '').split(/[,;\n]+/)) {
    const entry = raw.trim().replace(/\s+/g, ' ');
    if (!entry) continue;
    let pick = null;
    const asn = ASN_RE.exec(entry);
    if (asn && Number(asn[1]) > 0 && Number(asn[1]) <= 4294967295) pick = { kind: 'asn', value: Number(asn[1]), label: `AS${Number(asn[1])}` };
    else if (COUNTRY_RE.test(entry)) pick = { kind: 'country', value: entry.toUpperCase(), label: entry.toUpperCase() };
    else if (MAGIC_RE.test(entry) && !ASN_RE.test(entry)) pick = { kind: 'magic', value: entry, label: entry };
    if (!pick) {
      invalid.push(entry);
      continue;
    }
    const id = `${pick.kind}:${String(pick.value).toLowerCase()}`;
    if (seen.has(id)) continue;
    seen.add(id);
    picks.push(pick);
  }
  return { picks, invalid };
}

/**
 * Split `probes` over weighted entries by largest remainder (ties: the earlier entry); an entry
 * left at 0 is dropped by the caller.
 * @param {number} probes
 * @param {number[]} weights
 * @returns {number[]} one limit per entry
 */
export function spreadProbes(probes, weights) {
  const total = weights.reduce((a, w) => a + w, 0) || 1;
  const exact = weights.map((w) => (probes * w) / total);
  const out = exact.map(Math.floor);
  let left = probes - out.reduce((a, n) => a + n, 0);
  const order = exact.map((x, i) => [x - Math.floor(x), i]).sort((a, b) => b[0] - a[0] || a[1] - b[1]);
  for (let k = 0; left > 0; k = (k + 1) % order.length, left -= 1) out[order[k][1]] += 1;
  return out;
}

/**
 * The Globalping body of one ISP resolver measurement: `name` / `type` asked by every probe of
 * the selected places through its own default resolver (no `resolver` sent).
 *
 * - No picks: {@link ISP_CONTINENTS} by weight; picks: the probes split evenly over them.
 * - `eyeball` (default true): only probes in consumer (ISP) networks (`tags: ['eyeball-network']`),
 *   since a probe in a data centre asks its host's resolver.
 * - Refused, with nothing to send: a name Globalping cannot query ('name'), an internal one
 *   ('internal'), a type it does not know such as CAA ('type'), invalid or more places than
 *   probes ('picks'), a probe count outside 1–50 ('probes').
 *
 * @param {{ name: string, type: string, probes?: number, picks?: Array<{ kind: string, value: string|number }>,
 *   invalid?: string[], eyeball?: boolean }} opts
 * @returns {{ ok: true, body: object, probes: number, locations: object[] }|{ ok: false, error: string, detail?: string }}
 */
export function planIspMeasurement({ name, type, probes = ISP_DEFAULT_PROBES, picks = [], invalid = [], eyeball = true } = {}) {
  const qname = String(name || '').toLowerCase().replace(/\.$/, '');
  if (!isProbeableDnsName(qname)) return { ok: false, error: 'name' };
  if (isInternalName(qname)) return { ok: false, error: 'internal' };
  if (!GP_DNS_TYPES.includes(type)) return { ok: false, error: 'type' };
  if (!Number.isInteger(probes) || probes < 1 || probes > GP_LIMITS.maxProbesPerMeasurement) return { ok: false, error: 'probes' };
  const list = Array.isArray(picks) ? picks : [];
  if ((Array.isArray(invalid) && invalid.length) || list.length > ISP_MAX_PICKS || list.length > probes) {
    return { ok: false, error: 'picks', detail: Array.isArray(invalid) && invalid.length ? invalid[0] : undefined };
  }
  const tags = eyeball ? { tags: [EYEBALL_TAG] } : {};
  let locations;
  if (!list.length) {
    const limits = spreadProbes(probes, ISP_CONTINENTS.map((c) => c.weight));
    locations = ISP_CONTINENTS.map((c, i) => ({ continent: c.continent, ...tags, limit: limits[i] })).filter((l) => l.limit > 0);
  } else {
    const limits = spreadProbes(probes, list.map(() => 1));
    locations = list.map((p, i) => ({ [p.kind]: p.value, ...tags, limit: limits[i] }));
  }
  const body = dnsQueryRequest({ name: qname, type, probes, locations });
  return { ok: true, body, probes, locations };
}

/**
 * The resolver a probe asked: an address (with the public resolver's name when it is one), or
 * private — Globalping masks a private address as 'private' (an ISP-internal resolver or the
 * home router in front of it).
 * @param {unknown} value `result.resolver`
 * @returns {{ address: string|null, private: boolean, publicName: string|null }}
 */
export function resolverOf(value) {
  if (value === 'private') return { address: null, private: true, publicName: null };
  const ip = typeof value === 'string' ? normalizeIP(value) : null;
  if (!ip) return { address: null, private: false, publicName: null };
  return { address: ip, private: isPrivateIP(ip), publicName: PUBLIC_RESOLVERS[ip] || null };
}

const canon = (n) => String(n || '').toLowerCase().replace(/\.$/, '');
const DIG_RR = /^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$/;
const RCODES = Object.freeze(['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED']);

/** One answer of a DNS test as a dnswire-shaped record (presentation text as lib/zoneparse.js writes it), or null. */
function recordOf(a) {
  if (!a || typeof a !== 'object') return null;
  const name = String(a.name ?? '');
  const type = String(a.type ?? '').toUpperCase();
  const value = String(a.value ?? '');
  const ttl = Number.isInteger(a.ttl) && a.ttl >= 0 ? a.ttl : null;
  if (!name || /[\s\x00-\x1f\x7f]/.test(name) || !/^[A-Z][A-Z0-9-]{0,15}$/.test(type) || /[\x00-\x1f\x7f]/.test(value)) return null;
  const owner = canon(name);
  // One record per parse: a stray parenthesis or quote spoils only its own line.
  const z = parseZone(`${owner}. ${ttl ?? 0} IN ${type} ${value}\n`, { format: 'bind' });
  const r = z && Array.isArray(z.records) ? z.records[0] : null;
  if (!r || r.invalid || r.unsupported || r.data === null || r.data === undefined) return { name: owner, type, ttl, data: value, text: value };
  return { name: owner, type: r.type, ttl, data: r.data, text: typeof r.text === 'string' && r.text ? r.text : value };
}

/** The records of a section of the dig text (`;; AUTHORITY SECTION:`), as Globalping answers. */
function digSection(raw, section) {
  const lines = (typeof raw === 'string' ? raw : '').split('\n');
  const start = lines.findIndex((l) => l.trim() === `;; ${section} SECTION:`);
  if (start < 0) return [];
  const out = [];
  for (const line of lines.slice(start + 1)) {
    if (!line.trim() || line.startsWith(';')) break;
    const m = DIG_RR.exec(line.trim());
    if (m && m[3] === 'IN') out.push({ name: m[1], type: m[4], ttl: Number(m[2]), class: m[3], value: m[5].trim() });
  }
  return out;
}

/** A dig header flag (`;; flags: qr rd ra ad;`): true / false, or null without a flags line. */
function digFlag(raw, flag) {
  const m = /;; flags:([^;\n]*);/.exec(typeof raw === 'string' ? raw : '');
  return m ? m[1].trim().split(/\s+/).includes(flag) : null;
}

/** The line of dig's text that says what went wrong (a failed test), without its ';;'. */
function failureLine(raw) {
  const lines = String(raw || '').split('\n').map((l) => l.replace(/^;+\s*/, '').trim()).filter(Boolean);
  const line = [...lines].reverse().find((l) => /error|timed out|reached|refused|unreachable|not found/i.test(l)) || lines[0];
  return (line || 'no answer').slice(0, 200);
}

/**
 * What is left of the TTL a resolver still caches its answer for: the shortest TTL of the answer
 * records, or for an empty answer (NXDOMAIN, NODATA) the TTL of the SOA record of the authority
 * section (the negative cache). null without one.
 * @param {object|null} response the row's response ({@link mapIspResults})
 * @returns {number|null}
 */
export function remainingTtl(response) {
  if (!response || !response.ok) return null;
  const ttls = (list) => (Array.isArray(list) ? list : []).map((rr) => rr && rr.ttl).filter((n) => Number.isInteger(n) && n >= 0);
  const answers = ttls(response.answers);
  if (answers.length) return Math.min(...answers);
  const soa = ttls((Array.isArray(response.authorities) ? response.authorities : []).filter((rr) => rr && rr.type === 'SOA'));
  return soa.length ? Math.min(...soa) : null;
}

/**
 * One probe's result as a Global DNS row.
 * @param {object} entry `results[i]` of the measurement
 * @param {{ key: string, name: string, type: string, at: number|null }} ctx
 * @returns {object}
 */
function ispRow(entry, { key, name, type, at }) {
  const probe = probeSummary(entry && entry.probe);
  const test = entry && entry.result && typeof entry.result === 'object' ? entry.result : {};
  const resolver = resolverOf(test.resolver);
  const isp = { ...probe, resolver };
  const base = { kind: 'isp', key, isp, resolver: null, vantage: null, filtered: false, scopePrefix: null, notAsked: false };
  if (test.status === 'in-progress' || test.status === undefined) {
    return { ...base, status: 'pending', pending: true, response: null, values: null, addresses: [], ttl: null, expiresAt: null };
  }
  const elapsedMs = test.timings && Number.isFinite(test.timings.total) ? test.timings.total : null;
  const rcode = typeof test.statusCodeName === 'string' && /^[A-Z]{3,12}$/.test(test.statusCodeName) ? test.statusCodeName
    : (Number.isInteger(test.statusCode) && RCODES[test.statusCode]) || null;
  let response;
  let status;
  if (test.status !== 'finished' || !rcode) {
    status = test.status === 'offline' ? 'offline' : 'failed';
    const timedOut = /timed out|no servers could be reached/i.test(String(test.rawOutput || ''));
    response = {
      ok: false, name, type, rcode: null, answers: [], authorities: [], ad: false, ede: [], resolver: resolver.address,
      error: status === 'offline' ? 'The probe went offline' : failureLine(test.rawOutput), errorKind: timedOut ? 'timeout' : 'network', totalMs: elapsedMs
    };
  } else {
    status = 'answer';
    const read = (list) => list.map(recordOf).filter(Boolean);
    response = {
      ok: true, name, type, rcode, answers: read(Array.isArray(test.answers) ? test.answers : []),
      authorities: read(digSection(test.rawOutput, 'AUTHORITY')), ad: digFlag(test.rawOutput, 'ad') === true, ede: [],
      resolver: resolver.address, error: null, errorKind: null, elapsedMs
    };
  }
  const ttl = remainingTtl(response);
  return {
    ...base, status, pending: false, response, values: answerValues(response, type), addresses: answerAddresses(response),
    ttl, expiresAt: ttl !== null && Number.isFinite(at) ? new Date(at + ttl * 1000).toISOString() : null
  };
}

/**
 * The rows of an ISP resolver measurement (finished or still running): one per probe, in the
 * measurement's order, keyed `isp:<run>-<index>` (pending while the probe is still asking).
 * @param {object|null} measurement a Globalping measurement (GET /measurements/:id)
 * @param {{ name: string, type: string, run?: string|number }} opts `run` keeps two measurements' keys apart
 * @returns {{ rows: object[], done: boolean, at: string|null }}
 *   `at`: when the measurement started — the moment the remaining TTLs count from
 */
export function mapIspResults(measurement, { name, type, run = 1 } = {}) {
  const m = measurement && typeof measurement === 'object' ? measurement : {};
  const at = Date.parse(m.createdAt);
  const startedAt = Number.isFinite(at) ? at : null;
  const qname = canon(name);
  const rows = (Array.isArray(m.results) ? m.results : []).map((entry, i) => ispRow(entry, { key: `isp:${run}-${i}`, name: qname, type, at: startedAt }));
  return { rows, done: m.status !== undefined && m.status !== 'in-progress', at: startedAt === null ? null : new Date(startedAt).toISOString() };
}

/**
 * Placeholder rows for a measurement that was created but not read yet (`probes` pending rows
 * without a probe), so the table shows every probe from the start.
 * @param {number} probes
 * @param {string|number} [run=1]
 * @returns {object[]}
 */
export function pendingIspRows(probes, run = 1) {
  const n = Number.isInteger(probes) && probes > 0 ? Math.min(probes, GP_LIMITS.maxProbesPerMeasurement) : 0;
  return Array.from({ length: n }, (_, i) => ({
    kind: 'isp', key: `isp:${run}-${i}`, isp: { ...probeSummary(null), resolver: resolverOf(null) }, resolver: null, vantage: null,
    status: 'pending', pending: true, response: null, values: null, addresses: [], filtered: false, scopePrefix: null, notAsked: false, ttl: null, expiresAt: null
  }));
}

/**
 * The longest remaining TTL among rows (when the last of their answers expires), with its expiry.
 * @param {object[]} rows ISP rows
 * @returns {{ ttl: number|null, expiresAt: string|null }}
 */
export function longestTtl(rows) {
  let best = null;
  for (const r of Array.isArray(rows) ? rows : []) {
    if (r && Number.isInteger(r.ttl) && (!best || r.ttl > best.ttl)) best = r;
  }
  return best ? { ttl: best.ttl, expiresAt: best.expiresAt || null } : { ttl: null, expiresAt: null };
}

/**
 * Is an address one a probe may be told about (a public resolver) — false for a private one or none.
 * @param {{ address: string|null }} resolver {@link resolverOf}
 * @returns {boolean}
 */
export function isPublicAddress(resolver) {
  return !!(resolver && resolver.address && ipVersion(resolver.address) && !isPrivateIP(resolver.address));
}
