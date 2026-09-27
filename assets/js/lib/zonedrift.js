/**
 * zonedrift.js — compare an imported zone with live DNS (ROADMAP P1.2, "drift"),
 * with semantics that understand Cloudflare's proxy, CNAME flattening, Route 53
 * aliases and routing sets, DNS wildcards and delegations, so a consistent zone never
 * shows a false "differs". DOM-free; all I/O goes through the injected DohClient
 * (`dns.query` only). Runs in browsers and Node 22.
 *
 * One row per RRset (served name, type) with a status from {@link DRIFT_STATUSES}
 * and reason codes from {@link DRIFT_REASONS} (closed sets; the view translates
 * `zone.drift.<status>` / `zone.reason.<reason>`).
 *
 * What is sent, and what never is (zone spec §10, critic D1/D2/G1):
 *  - names and types only, to the user's resolver chain with failover (or one chosen
 *    resolver); never `balance` rotation, never Globalping or a passive source;
 *  - names outside the zone origin are never queried (name servers ignore them);
 *  - private-looking names are skipped by default (`skipPrivate`), as owners and as
 *    flattened / alias targets (a skipped target is never sent, even with `resolveTargets`);
 *  - a proxied CNAME's target (the hidden origin host) is never queried, and neither
 *    are the external targets of flattened CNAMEs and Route 53 aliases unless
 *    `resolveTargets` is set (they are hidden from public DNS just like an origin);
 *  - types the file does not contain are never queried, so Cloudflare-synthesised
 *    AAAA / HTTPS answers cannot show up as drift; an HTTPS / SVCB RRset at a proxied
 *    name is skipped (`cf-synthesized`);
 *  - one query per unique (name, type) — memoised, counted, and planned exactly by
 *    {@link planDrift}; the budget (default {@link DRIFT_DEFAULT_BUDGET}, hard cap
 *    {@link DRIFT_MAX_BUDGET}) reserves an RRset's queries atomically, so no row is left
 *    half-checked; concurrency ≤ {@link DRIFT_MAX_CONCURRENCY}.
 *
 * Every comparison canonicalises both sides with {@link rdataKey} (`record.data` for the
 * file, `rr.data` from dnswire for live). {@link rdataKey} / {@link txtJoinedKey} mirror
 * lib/zoneparse.js (zone spec §6.1.6 with critic A6: root = `''`, DS / hex lowercase);
 * they live here too so the analysis modules never depend on the parser.
 */

import {
  zoneIndex, proxiedCore, proxiedSets, privateLookingNames, wildcardCovers, servedTargets, isCloudflareIp, sortIps,
  addressOf, isPrivateAddress, providerIdOfIp
} from './zoneorigins.js';
import { normalizeIP } from './netinfo.js';
import { encodeName, base64Decode, base64Encode } from './dnswire.js';
import { followCnames } from './doh.js';
import { isFilteredResponse } from './propagation.js';
import { getResolver } from './resolvers.js';
import { CAA_ISSUERS, parseCaaIssueValue } from './health.js';
import { createLimiter, randomLabel, errorKind, AbortError, abortReasonToError } from './util.js';
import { sortHostnames } from './domain.js';

/* ------------------------------------------------------------------------ */
/* Vocabularies                                                             */
/* ------------------------------------------------------------------------ */

export const DRIFT_STATUSES = Object.freeze(['match', 'differs', 'missing-live', 'proxied-ok', 'origin-exposed',
  'flattened-ok', 'alias-ok', 'routing-ok', 'occluded', 'skipped', 'error']);
export const DRIFT_REASONS = Object.freeze(['values', 'nxdomain', 'nodata', 'cname-live', 'proxy-on-live', 'proxy-off-live',
  'not-cloudflare', 'flatten-mismatch', 'alias-disjoint', 'routing-outside', 'wildcard', 'servfail', 'refused', 'transport',
  'timeout', 'budget', 'private', 'unsupported-type', 'dnssec-type', 'escaped-name', 'cf-synthesized', 'txt-chunking',
  'ttl-stale', 'placeholder', 'tunnel', 'provider', 'cf-caa-added', 'alias-rotating', 'filtered', 'target-hidden', 'out-of-zone']);
export const DRIFT_SEVERITY = Object.freeze({
  match: 'ok', 'proxied-ok': 'ok', 'flattened-ok': 'ok', 'alias-ok': 'ok', 'routing-ok': 'ok', occluded: 'info',
  skipped: 'info', differs: 'warn', 'missing-live': 'warn', 'origin-exposed': 'error', error: 'unknown'
});
export const DRIFT_DEFAULT_BUDGET = 2000;
export const DRIFT_MAX_BUDGET = 10000;
export const DRIFT_MAX_CONCURRENCY = 8;
/** Resolvers with a TTL floor inflate short TTLs: `ttl-stale` only above max(file TTL, this). */
export const DRIFT_TTL_FLOOR = 60;
/** CAs Cloudflare issues Universal SSL from; their hidden CAA records are `cf-caa-added` (critic C1). */
export const CF_CAA_ISSUER_IDS = Object.freeze(['letsencrypt', 'google', 'sslcom', 'sectigo', 'digicert']);
/** Route 53 alias providers whose answers rotate: disjoint live sets are still `alias-ok` (critic C2). */
export const MANAGED_ALIAS_PROVIDERS = Object.freeze(['cloudfront', 'elb', 's3-website', 'api-gateway', 'elastic-beanstalk',
  'global-accelerator', 'vpc-endpoint']);

const DNSSEC_TYPES = new Set(['RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM']);
const ADDRESS_TYPES = new Set(['A', 'AAAA']);
const STRING_DATA_TYPES = new Set(['A', 'AAAA', 'NS', 'CNAME', 'PTR', 'DNAME', 'OPENPGPKEY']);
const MANAGED = new Set(MANAGED_ALIAS_PROVIDERS);
const CF_CAA_DOMAINS = new Set(CAA_ISSUERS.filter((ca) => CF_CAA_ISSUER_IDS.includes(ca.id)).flatMap((ca) => ca.domains));
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PLAIN_NAME = /^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/**
 * @typedef {object} DriftRow
 * @property {string} key `name|type`
 * @property {string} name served owner (may be `*.x`)
 * @property {string} type
 * @property {string} status one of {@link DRIFT_STATUSES}
 * @property {string[]} reasons from {@link DRIFT_REASONS}
 * @property {string[]} file presentation values in the file
 * @property {string[]} live presentation values seen live
 * @property {string[]} added live values missing from the file (`differs`)
 * @property {string[]} removed file values missing live (`differs`)
 * @property {string|null} resolver resolver that answered the main query
 * @property {string|null} rcode of the main query
 * @property {number|null} fileTtl
 * @property {number|null} liveTtl minimum TTL of the live answers used
 * @property {boolean|null} proxied the name is proxied (Cloudflare), DNS-only (false) or has no proxy notion
 * @property {number[]} recordIds
 * @property {string|null} probe extension: the random name queried for a wildcard RRset
 */

/* ------------------------------------------------------------------------ */
/* Canonical keys                                                           */
/* ------------------------------------------------------------------------ */

const nameKey = (v) => {
  const s = String(v ?? '').trim().toLowerCase();
  return s === '.' || s === '' ? '' : s.replace(/\.$/, '');
};
const numKey = (v) => (Number.isFinite(Number(v)) ? String(Number(v)) : String(v ?? ''));
const hexKey = (v) => String(v ?? '').replace(/[^0-9a-f]/gi, '').toLowerCase();
const strings = (data) => (Array.isArray(data) ? data.map((s) => String(s ?? '')) : [String(data ?? '')]);

function b64Key(v) {
  const s = String(v ?? '').replace(/\s+/g, '');
  try {
    return base64Encode(base64Decode(s));
  } catch {
    return s;
  }
}

function svcbKey(d) {
  const params = d && d.params && typeof d.params === 'object' ? d.params : {};
  const parts = Object.keys(params).sort().map((k) => {
    const v = params[k];
    if (k === 'ipv4hint' || k === 'ipv6hint') return `${k}=${sortIps(strings(v)).join(',')}`;
    if (k === 'mandatory') return `${k}=${strings(v).sort().join(',')}`;
    if (k === 'ech') return `${k}=${b64Key(v)}`;
    if (v === true) return k;
    if (/^key\d+$/.test(k)) return `${k}=${hexKey(v)}`;
    return `${k}=${Array.isArray(v) ? v.map(String).join(',') : String(v)}`;
  });
  return [numKey(d.priority), nameKey(d.target), ...parts].join(' ');
}

function stableJson(v) {
  if (Array.isArray(v)) return `[${v.map(stableJson).join(',')}]`;
  if (v && typeof v === 'object' && !(v instanceof Date)) {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stableJson(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v ?? null);
}

/**
 * THE canonical comparison key of one RR's data, for the file side (`record.data`)
 * and the live side (dnswire `rr.data`) alike. Names are lowercase without the
 * trailing dot and the root is `''` (dnswire gives `'.'`); A/AAAA are canonical; TXT
 * keeps its character-strings; hex is lowercase; SOA compares the serial only; SVCB
 * params are sorted by key (IP hints sorted, alpn order kept). Structured types given
 * RFC 3597 hex compare as `#<hex>`.
 * @param {string} type
 * @param {unknown} data
 * @returns {string}
 */
export function rdataKey(type, data) {
  const t = String(type ?? '').toUpperCase();
  if (data === null || data === undefined) return '';
  if (typeof data === 'string' && !STRING_DATA_TYPES.has(t) && t !== 'TXT' && t !== 'SPF') return `#${hexKey(data)}`;
  switch (t) {
    case 'A':
    case 'AAAA':
      return normalizeIP(String(data)) || String(data).trim().toLowerCase();
    case 'NS':
    case 'CNAME':
    case 'PTR':
    case 'DNAME':
      return nameKey(data);
    case 'MX':
      return `${numKey(data.preference)} ${nameKey(data.exchange)}`;
    case 'SRV':
      return `${numKey(data.priority)} ${numKey(data.weight)} ${numKey(data.port)} ${nameKey(data.target)}`;
    case 'TXT':
    case 'SPF':
      return JSON.stringify(strings(data));
    case 'CAA':
      return `${numKey(data.flags)} ${String(data.tag ?? '').toLowerCase()} ${String(data.value ?? '')}`;
    case 'DS':
    case 'CDS':
      return `${numKey(data.keyTag)} ${numKey(data.algorithm)} ${numKey(data.digestType)} ${hexKey(data.digest)}`;
    case 'TLSA':
    case 'SMIMEA':
      return `${numKey(data.usage)} ${numKey(data.selector)} ${numKey(data.matchingType)} ${hexKey(data.data)}`;
    case 'SSHFP':
      return `${numKey(data.algorithm)} ${numKey(data.fpType)} ${hexKey(data.fingerprint)}`;
    case 'SOA':
      return numKey(data.serial);
    case 'DNSKEY':
    case 'CDNSKEY':
      return `${numKey(data.flags)} ${numKey(data.protocol)} ${numKey(data.algorithm)} ${b64Key(data.publicKey)}`;
    case 'SVCB':
    case 'HTTPS':
      return svcbKey(data);
    case 'OPENPGPKEY':
      return b64Key(data);
    default:
      return typeof data === 'string' ? `#${hexKey(data)}` : stableJson(data);
  }
}

/**
 * TXT / SPF: the character-strings joined (how SPF / DKIM consumers read them), so a
 * 255+N split and one long string compare equal. `''` for other types.
 * @param {string} type
 * @param {unknown} data
 * @returns {string}
 */
export function txtJoinedKey(type, data) {
  const t = String(type ?? '').toUpperCase();
  return (t === 'TXT' || t === 'SPF') && data !== null && data !== undefined ? strings(data).join('') : '';
}

/* ------------------------------------------------------------------------ */
/* Plan                                                                     */
/* ------------------------------------------------------------------------ */

const canon = (v) => nameKey(v);
const qkey = (name, type) => `${String(name).toLowerCase()}|${String(type).toUpperCase()}`;
const probeKey = (owner, type) => `\u0000probe\u0000${owner}|${type}`;

// The SOA + NS preflight always goes out for a live origin, so a budget below it
// would be reported as `maxQueries` yet exceeded: the floor is the preflight.
const PREFLIGHT_QUERIES = 2;

function clampBudget(n) {
  const v = Number.isFinite(n) ? Math.floor(n) : DRIFT_DEFAULT_BUDGET;
  return Math.max(PREFLIGHT_QUERIES, Math.min(DRIFT_MAX_BUDGET, v));
}

function encodable(name) {
  if (name.includes('\\')) return false;
  if (name.length <= 253 && PLAIN_NAME.test(name)) return true;
  try {
    encodeName(name);
    return true;
  } catch {
    return false;
  }
}

function usable(r, idx) {
  if (idx.occludedRecords.has(r)) return false;
  if (r.alias) return true;
  return !r.invalid && !r.unsupported && r.data !== null && r.data !== undefined;
}

function buildPlan(zone, opts) {
  const idx = zoneIndex(zone);
  const sets = proxiedSets(idx);
  const origin = idx.origin;
  const maxQueries = clampBudget(opts.maxQueries);
  const wildcardProbes = opts.wildcardProbes !== false;
  const resolveTargets = opts.resolveTargets === true;
  const skipSet = new Set(opts.skip ? [...opts.skip].map(canon) : []);
  if (opts.skipPrivate !== false) for (const n of privateLookingNames(zone)) skipSet.add(n);

  const groups = new Map();
  for (const r of idx.unique) {
    if (r.type === 'SOA') continue;
    const key = `${r.name}|${r.type}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = { key, name: r.name, type: r.type, records: [] }));
    g.records.push(r);
  }

  const skipped = { private: 0, occluded: 0, outOfZone: 0, unsupported: 0, escaped: 0, dnssec: 0, synthesized: 0, wildcard: 0, budget: 0 };
  const reserved = new Set();
  const needed = new Set();
  const live = !!origin && !(zone && zone.fatal);
  if (live) {
    for (const t of ['SOA', 'NS']) {
      reserved.add(qkey(origin, t));
      needed.add(qkey(origin, t));
    }
  }
  let exhausted = false;
  let hidden = 0;
  const items = [];
  const zero = (item, status, reason, counter) => {
    item.zero = { status, reasons: reason ? [reason] : [] };
    if (counter) skipped[counter] += 1;
    items.push(item);
  };

  for (const g of groups.values()) {
    const item = { ...g, index: items.length, mode: null, zero: null, queries: [], valid: [], wildcard: g.name.startsWith('*.'), targetHidden: false };
    const recs = g.records;
    if (recs.every((r) => idx.occludedRecords.has(r))) { zero(item, 'occluded', null, 'occluded'); continue; }
    // outside the origin: name servers ignore it (the parser's OUT_OF_ZONE), and it may be someone else's name
    if (origin && !idx.inZone(g.name)) { zero(item, 'skipped', 'out-of-zone', 'outOfZone'); continue; }
    if (DNSSEC_TYPES.has(g.type)) { zero(item, 'skipped', 'dnssec-type', 'dnssec'); continue; }
    item.valid = recs.filter((r) => usable(r, idx));
    if (!item.valid.length) { zero(item, 'skipped', 'unsupported-type', 'unsupported'); continue; }
    if (!encodable(g.name)) { zero(item, 'skipped', 'escaped-name', 'escaped'); continue; }
    if (skipSet.has(g.name) || (item.wildcard && skipSet.has(g.name.slice(2)))) { zero(item, 'skipped', 'private', 'private'); continue; }
    if ((g.type === 'HTTPS' || g.type === 'SVCB') && sets.all.has(g.name)) { zero(item, 'skipped', 'cf-synthesized', 'synthesized'); continue; }
    if (item.wildcard && !wildcardProbes) { zero(item, 'skipped', 'wildcard', 'wildcard'); continue; }

    const q = item.wildcard ? { probe: true } : { name: g.name };
    const at = (type) => ({ ...q, type });
    const alias = item.valid.find((r) => r.alias);
    const inZoneTarget = (t) => !!origin && idx.inZone(t) && !idx.cutAtOrAbove(t);
    if (ADDRESS_TYPES.has(g.type) && sets.proxiedAddressNames.has(g.name) && !alias) {
      item.mode = 'proxied-addr';
      item.queries = [at(g.type)];
    } else if (g.type === 'CNAME' && item.valid.some((r) => r.proxied === true)) {
      item.mode = 'proxied-cname';
      item.queries = [at('CNAME'), at('A')];
    } else if (g.type === 'CNAME' && (item.valid.some((r) => r.flattenCname) || (g.name === origin && idx.cloudflare))) {
      item.mode = 'flattened';
      item.queries = [at('A'), at('CNAME')];
      const t = servedTargets(item.valid[0])[0] || '';
      item.target = t;
      if (t && !skipSet.has(t) && (inZoneTarget(t) || resolveTargets)) item.queries.push({ name: t, type: 'A', role: 'target' });
      else if (t) { item.targetHidden = true; hidden += 1; }
    } else if (alias) {
      item.mode = 'alias';
      item.queries = [at(g.type)];
      const t = canon(alias.alias.target);
      item.target = t;
      if (t && !skipSet.has(t) && (alias.alias.provider === 'same-zone' || inZoneTarget(t) || resolveTargets)) item.queries.push({ name: t, type: g.type, role: 'target' });
      else if (t) { item.targetHidden = true; hidden += 1; }
    } else if (item.valid.some((r) => r.routing)) {
      item.mode = 'routing';
      item.queries = [at(g.type)];
    } else {
      item.mode = 'plain';
      item.queries = [at(g.type)];
    }

    const keys = [...new Set(item.queries.map((x) => (x.probe ? probeKey(g.name, x.type) : qkey(x.name, x.type))))];
    for (const k of keys) needed.add(k);
    const fresh = keys.filter((k) => !reserved.has(k));
    if (exhausted || reserved.size + fresh.length > maxQueries) {
      exhausted = true;
      item.queries = [];
      zero(item, 'skipped', 'budget', 'budget');
      continue;
    }
    for (const k of fresh) reserved.add(k);
    items.push(item);
  }

  let addrs = 0;
  let priv = 0;
  for (const r of idx.unique) {
    const ip = addressOf(r);
    if (!ip) continue;
    addrs += 1;
    if (isPrivateAddress(ip)) priv += 1;
  }
  return {
    idx, sets, origin, items, reserved, needed, maxQueries, skipped, hidden, skipSet, internalShare: addrs ? priv / addrs : 0, live,
    /** Origin resolution, only needed to evaluate answers (never for planning). */
    get core() { return proxiedCore(idx); }
  };
}

/**
 * What {@link driftZone} will do, without sending anything.
 * `queries` is the EXACT number of DNS queries it sends (preflight included) for the
 * same options — unless the origin turns out not to exist (then only the 2 preflight
 * queries go out) or the run is cancelled.
 * @param {object} zone
 * @param {{ skip?: Iterable<string>, skipPrivate?: boolean, wildcardProbes?: boolean, resolveTargets?: boolean,
 *   maxQueries?: number }} [opts]
 * @returns {{ rrsets: number, queries: number, needed: number, overBudget: boolean, maxQueries: number,
 *   names: number, skipped: { private: number, occluded: number, outOfZone: number, unsupported: number, escaped: number,
 *   dnssec: number, synthesized: number, wildcard: number, budget: number }, targetsHidden: number,
 *   internalShare: number }} `needed`: queries without a budget; `targetsHidden`: flattened / alias
 *   targets left out (sent only with `resolveTargets`); `internalShare`: share of private addresses (0..1)
 */
export function planDrift(zone, opts = {}) {
  const plan = buildPlan(zone, opts || {});
  return {
    rrsets: plan.items.length,
    queries: plan.reserved.size,
    needed: plan.needed.size,
    overBudget: plan.skipped.budget > 0,
    maxQueries: plan.maxQueries,
    names: new Set(plan.items.map((i) => i.name)).size,
    skipped: { ...plan.skipped },
    targetsHidden: plan.hidden,
    internalShare: plan.internalShare
  };
}

/* ------------------------------------------------------------------------ */
/* Live answers                                                             */
/* ------------------------------------------------------------------------ */

function failureResponse(name, type, err) {
  return {
    name, type, ok: false, rcode: null, answers: [], authorities: [], resolver: null,
    error: String((err && err.message) || err || 'query failed'), errorKind: errorKind(err), ede: []
  };
}

/** Why a response cannot be compared (a row in status `error`), or null. */
function failReason(resp) {
  if (!resp || !resp.ok) return resp && resp.errorKind === 'timeout' ? 'timeout' : 'transport';
  if (resp.rcode === 'NOERROR' || resp.rcode === 'NXDOMAIN') {
    return isFilteredResponse(resp, getResolver(resp.resolver) || null) ? 'filtered' : null;
  }
  return resp.rcode === 'REFUSED' ? 'refused' : 'servfail';
}

const answersOf = (resp) => (resp && Array.isArray(resp.answers) ? resp.answers.filter((rr) => rr && typeof rr.type === 'string') : []);

/** RRs of `type` owned by `qname` itself. */
function ownRrs(resp, qname, type) {
  return answersOf(resp).filter((rr) => rr.type === type && canon(rr.name) === qname);
}

/** RRs of `type` at the end of the qname's CNAME chain (the qname included) + the chain. */
function chainRrs(resp, qname, type) {
  const answers = answersOf(resp);
  const { cnames } = followCnames(answers, qname);
  const owners = new Set([qname, ...cnames]);
  return { cnames, rrs: answers.filter((rr) => rr.type === type && owners.has(canon(rr.name))) };
}

const addressesOf = (rrs) => sortIps(rrs.map((rr) => normalizeIP(rr.data)).filter(Boolean));
const minTtl = (rrs) => (rrs.length ? Math.min(...rrs.map((rr) => (Number.isFinite(rr.ttl) ? rr.ttl : Infinity))) : null);
const liveText = (rr) => (typeof rr.text === 'string' && rr.text ? rr.text : rdataKey(rr.type, rr.data));
const fileText = (r) => (r.alias ? `ALIAS ${canon(r.alias.target)}` : typeof r.text === 'string' && r.text ? r.text : rdataKey(r.type, r.data));

/* ------------------------------------------------------------------------ */
/* Evaluation                                                               */
/* ------------------------------------------------------------------------ */

function baseRow(item, plan) {
  const ttls = item.records.map((r) => r.ttl).filter((t) => Number.isFinite(t));
  let proxied = null;
  if (plan.sets.all.has(item.name)) proxied = true;
  else if (item.records.some((r) => r.proxied === false)) proxied = false;
  return {
    key: item.key,
    name: item.name,
    type: item.type,
    status: 'error',
    reasons: [],
    file: (item.valid.length ? item.valid : item.records).map(fileText),
    live: [],
    added: [],
    removed: [],
    resolver: null,
    rcode: null,
    fileTtl: ttls.length ? Math.min(...ttls) : null,
    liveTtl: null,
    proxied,
    recordIds: [...new Set(item.records.map(plan.idx.idOf))].sort((a, b) => a - b),
    probe: null
  };
}

function setStatus(row, status, ...reasons) {
  row.status = status;
  for (const r of reasons) if (r && !row.reasons.includes(r)) row.reasons.push(r);
  return row;
}

/** Compare key sets; returns the diff with display values. */
function diffSets(fileRecs, liveRrs, type) {
  const fileKeys = new Map();
  for (const r of fileRecs) if (!fileKeys.has(rdataKey(type, r.data))) fileKeys.set(rdataKey(type, r.data), fileText(r));
  const liveKeys = new Map();
  for (const rr of liveRrs) if (!liveKeys.has(rdataKey(type, rr.data))) liveKeys.set(rdataKey(type, rr.data), liveText(rr));
  const added = [...liveKeys.keys()].filter((k) => !fileKeys.has(k));
  const removed = [...fileKeys.keys()].filter((k) => !liveKeys.has(k));
  return { fileKeys, liveKeys, added, removed, equal: !added.length && !removed.length };
}

function joinedEqual(fileRecs, liveRrs, type) {
  const a = fileRecs.map((r) => txtJoinedKey(type, r.data)).sort();
  const b = [...new Set(liveRrs.map((rr) => txtJoinedKey(type, rr.data)))].sort();
  const aa = [...new Set(a)];
  return aa.length === b.length && aa.every((v, i) => v === b[i]);
}

function cfCaaAdded(diff, liveRrs) {
  if (diff.removed.length || !diff.added.length) return false;
  const byKey = new Map(liveRrs.map((rr) => [rdataKey('CAA', rr.data), rr]));
  return diff.added.every((k) => {
    const d = byKey.get(k) && byKey.get(k).data;
    if (!d || typeof d.tag !== 'string') return false;
    const tag = d.tag.toLowerCase();
    return (tag === 'issue' || tag === 'issuewild') && CF_CAA_DOMAINS.has(parseCaaIssueValue(d.value).issuer);
  });
}

function evaluatePlain(item, row, resp, qname, cfZone) {
  const type = item.type;
  if (resp.rcode === 'NXDOMAIN') return setStatus(row, 'missing-live', 'nxdomain');
  const own = ownRrs(resp, qname, type);
  const { cnames, rrs } = chainRrs(resp, qname, type);
  if (type !== 'CNAME' && cnames.length && !own.length) {
    row.live = [...cnames.map((c) => `CNAME ${c}`), ...rrs.map(liveText)];
    row.liveTtl = minTtl(rrs);
    return setStatus(row, 'differs', 'cname-live');
  }
  if (!own.length) return setStatus(row, 'missing-live', 'nodata');
  row.live = own.map(liveText);
  row.liveTtl = minTtl(own);
  const diff = diffSets(item.valid, own, type);
  if (diff.equal) return setStatus(row, 'match');
  if ((type === 'TXT' || type === 'SPF') && joinedEqual(item.valid, own, type)) return setStatus(row, 'match', 'txt-chunking');
  if (type === 'CAA' && cfZone && cfCaaAdded(diff, own)) return setStatus(row, 'match', 'cf-caa-added');
  row.added = diff.added.map((k) => diff.liveKeys.get(k));
  row.removed = diff.removed.map((k) => diff.fileKeys.get(k));
  if (ADDRESS_TYPES.has(type) && item.valid.every((r) => r.proxied === false)) {
    const ips = addressesOf(own);
    if (ips.length && ips.every(isCloudflareIp)) return setStatus(row, 'differs', 'proxy-on-live');
  }
  return setStatus(row, 'differs', 'values');
}

function evaluateProxiedAddr(item, row, resp, qname, plan) {
  if (resp.rcode === 'NXDOMAIN') return setStatus(row, 'missing-live', 'nxdomain');
  const { rrs } = chainRrs(resp, qname, item.type);
  const ips = addressesOf(rrs);
  row.live = rrs.map(liveText);
  row.liveTtl = minTtl(rrs);
  if (!ips.length) return setStatus(row, 'missing-live', 'nodata');
  const own = item.valid.map((r) => normalizeIP(r.data)).filter(Boolean);
  if (ips.some((ip) => plan.core.originIps.has(ip) || (own.includes(ip) && !isCloudflareIp(ip)))) {
    return setStatus(row, 'origin-exposed', 'proxy-off-live');
  }
  if (ips.every(isCloudflareIp)) {
    const kind = plan.core.rows.get(item.name)?.kind;
    return setStatus(row, 'proxied-ok', kind === 'placeholder' ? 'placeholder' : null);
  }
  row.added = ips.filter((ip) => !isCloudflareIp(ip));
  return setStatus(row, 'differs', 'not-cloudflare');
}

function evaluateProxiedCname(item, row, [respC, respA], qname, plan) {
  const fileTarget = rdataKey('CNAME', item.valid[0].data);
  const cn = ownRrs(respC, qname, 'CNAME');
  const chainA = chainRrs(respA, qname, 'A');
  row.live = [...cn.map(liveText), ...chainA.rrs.map(liveText)];
  row.liveTtl = minTtl([...cn, ...chainA.rrs]);
  if (cn.some((rr) => rdataKey('CNAME', rr.data) === fileTarget) || chainA.cnames[0] === fileTarget) {
    return setStatus(row, 'origin-exposed', 'proxy-off-live');
  }
  if (respC.rcode === 'NXDOMAIN' || respA.rcode === 'NXDOMAIN') return setStatus(row, 'missing-live', 'nxdomain');
  if (cn.length) {
    row.added = cn.map(liveText);
    row.removed = item.valid.map(fileText);
    return setStatus(row, 'differs', 'values');
  }
  const ips = addressesOf(chainA.rrs);
  if (!ips.length) return setStatus(row, 'missing-live', 'nodata');
  if (ips.every(isCloudflareIp)) {
    const kind = plan.core.rows.get(item.name)?.kind;
    return setStatus(row, 'proxied-ok', kind === 'tunnel' ? 'tunnel' : kind === 'provider' ? 'provider' : kind === 'placeholder' ? 'placeholder' : null);
  }
  row.added = ips.filter((ip) => !isCloudflareIp(ip));
  return setStatus(row, 'differs', 'not-cloudflare');
}

function evaluateFlattened(item, row, [respA, respC, respT], qname) {
  const cn = ownRrs(respC, qname, 'CNAME');
  const { rrs } = chainRrs(respA, qname, 'A');
  row.live = [...cn.map(liveText), ...rrs.map(liveText)];
  row.liveTtl = minTtl(rrs);
  if (respA.rcode === 'NXDOMAIN' || respC.rcode === 'NXDOMAIN') return setStatus(row, 'missing-live', 'nxdomain');
  if (cn.length) return setStatus(row, 'differs', 'flatten-mismatch');
  const ips = addressesOf(rrs);
  if (!ips.length) return setStatus(row, 'missing-live', 'nodata');
  if (!respT) return setStatus(row, 'flattened-ok', 'target-hidden');
  const target = addressesOf(chainRrs(respT, item.target, 'A').rrs);
  const same = target.length === ips.length && target.every((ip, i) => ip === ips[i]);
  if (same) return setStatus(row, 'flattened-ok');
  row.added = ips.filter((ip) => !target.includes(ip));
  row.removed = target.filter((ip) => !ips.includes(ip));
  return setStatus(row, 'differs', 'flatten-mismatch');
}

function evaluateAlias(item, row, [resp, respT], qname) {
  const type = item.type;
  if (resp.rcode === 'NXDOMAIN') return setStatus(row, 'missing-live', 'nxdomain');
  const { rrs } = chainRrs(resp, qname, type);
  row.live = rrs.map(liveText);
  row.liveTtl = minTtl(rrs);
  if (!rrs.length) return setStatus(row, 'missing-live', 'nodata');
  if (!respT) return setStatus(row, 'alias-ok', 'target-hidden');
  const keys = new Set(rrs.map((rr) => rdataKey(type, rr.data)));
  const t = chainRrs(respT, item.target, type).rrs.map((rr) => rdataKey(type, rr.data));
  if (t.some((k) => keys.has(k))) return setStatus(row, 'alias-ok');
  const provider = item.valid.find((r) => r.alias)?.alias?.provider;
  if (t.length && MANAGED.has(provider)) return setStatus(row, 'alias-ok', 'alias-rotating');
  if (t.length && ADDRESS_TYPES.has(type)) {
    const ids = new Set([...keys, ...t].map(providerIdOfIp));
    if (ids.size === 1 && !ids.has(null)) return setStatus(row, 'alias-ok', 'alias-rotating');
  }
  return setStatus(row, 'differs', 'alias-disjoint');
}

function evaluateRouting(item, row, resp, qname) {
  const type = item.type;
  if (resp.rcode === 'NXDOMAIN') return setStatus(row, 'missing-live', 'nxdomain');
  const own = ownRrs(resp, qname, type);
  const { cnames, rrs } = chainRrs(resp, qname, type);
  if (cnames.length && !own.length) {
    row.live = [...cnames.map((c) => `CNAME ${c}`), ...rrs.map(liveText)];
    row.liveTtl = minTtl(rrs);
    return setStatus(row, 'differs', 'cname-live');
  }
  if (!own.length) return setStatus(row, 'missing-live', 'nodata');
  row.live = own.map(liveText);
  row.liveTtl = minTtl(own);
  const diff = diffSets(item.valid, own, type);
  if (!diff.added.length) return setStatus(row, 'routing-ok');
  row.added = diff.added.map((k) => diff.liveKeys.get(k));
  return setStatus(row, 'differs', 'routing-outside');
}

/* ------------------------------------------------------------------------ */
/* Run                                                                      */
/* ------------------------------------------------------------------------ */

function serialCompare(file, live) {
  if (!Number.isFinite(file) || !Number.isFinite(live)) return 'unknown';
  if (file === live) return 'same';
  const half = 2 ** 31;
  const newer = (live > file && live - file < half) || (live < file && file - live > half);
  return newer ? 'newer' : 'older';
}

function safeCall(fn, arg) {
  if (typeof fn !== 'function') return;
  try {
    fn(arg);
  } catch {
    /* observer errors never break the run */
  }
}

/**
 * Compare the zone with live DNS. Resolves (never rejects on DNS failures or on
 * cancellation): an aborted run resolves with `aborted: true` and the rows so far.
 *
 * Rows that cost no query (occluded, DNSSEC types, unsupported / invalid, escaped
 * names, skipped private names, Cloudflare-synthesised HTTPS/SVCB, disabled wildcard
 * probes, over budget) are streamed first; then the 2 preflight queries (SOA and NS
 * at the origin); then every other RRset. An origin that does not exist (NXDOMAIN)
 * turns every remaining row into `error: nxdomain` without another query.
 *
 * @param {object} zone
 * @param {object} opts
 * @param {{ query: (name: string, type: string, opts: object) => Promise<object> }} opts.dns DohClient
 * @param {string} [opts.resolver] one resolver id (no failover); default: the client's chain
 * @param {AbortSignal} [opts.signal]
 * @param {(row: DriftRow) => void} [opts.onRow] streams rows as they complete
 * @param {(p: { done: number, total: number }) => void} [opts.onProgress]
 * @param {number} [opts.maxQueries=DRIFT_DEFAULT_BUDGET] capped at DRIFT_MAX_BUDGET
 * @param {number} [opts.concurrency=6] capped at DRIFT_MAX_CONCURRENCY
 * @param {Iterable<string>} [opts.skip] names never queried
 * @param {boolean} [opts.skipPrivate=true] also skip {@link privateLookingNames}
 * @param {boolean} [opts.wildcardProbes=true] query `<random>.x` for `*.x` RRsets
 * @param {boolean} [opts.resolveTargets=false] also query external flattened / alias targets
 * @param {() => string} [opts.labelFn=randomLabel] the wildcard probe label
 * @param {() => Date} [opts.now]
 * @returns {Promise<{ origin: string|null, startedAt: Date, finishedAt: Date, aborted: boolean, queries: number,
 *   planned: number, resolverPolicy: string, preflight: { originExists: boolean, liveSerial: number|null,
 *   fileSerial: number|null, serial: 'same'|'newer'|'older'|'unknown', fileNs: string[], liveNs: string[],
 *   nsMatch: 'same'|'overlap'|'disjoint'|'unknown' }, rows: DriftRow[], counts: Object<string, number> }>}
 */
export async function driftZone(zone, opts = {}) {
  const {
    dns, resolver, signal, onRow, onProgress, concurrency = 6, labelFn = randomLabel, now = () => new Date()
  } = opts || {};
  if (!dns || typeof dns.query !== 'function') throw new TypeError('driftZone: a DNS client with query() is required');
  const plan = buildPlan(zone, opts || {});
  const { idx, items, origin } = plan;
  const startedAt = now();
  const rows = new Array(items.length);
  let done = 0;
  const emit = (item, row) => {
    rows[item.index] = row;
    done += 1;
    safeCall(onRow, row);
    safeCall(onProgress, { done, total: items.length });
  };

  const fileSoa = idx.unique.find((r) => r.type === 'SOA' && r.name === origin && r.data && typeof r.data === 'object');
  const fileNs = sortHostnames([...new Set(idx.unique.filter((r) => r.type === 'NS' && r.name === origin).flatMap(servedTargets).filter(Boolean))]);
  const preflight = {
    originExists: true, liveSerial: null, fileSerial: fileSoa && Number.isFinite(Number(fileSoa.data.serial)) ? Number(fileSoa.data.serial) : null,
    serial: 'unknown', fileNs, liveNs: [], nsMatch: 'unknown'
  };

  // Wildcard probe names, one per wildcard owner, in plan order.
  const probes = new Map();
  for (const item of items) {
    if (!item.wildcard || item.zero || probes.has(item.name)) continue;
    let label = '';
    try {
      label = String(labelFn()).toLowerCase();
    } catch {
      label = '';
    }
    if (!LABEL_RE.test(label)) label = randomLabel(12);
    probes.set(item.name, `${label}.${item.name.slice(2)}`);
  }

  for (const item of items) if (item.zero) emit(item, setStatus(baseRow(item, plan), item.zero.status, ...item.zero.reasons));

  const limiter = createLimiter(Math.max(1, Math.min(DRIFT_MAX_CONCURRENCY, Math.floor(Number(concurrency)) || 1)));
  const memo = new Map();
  let sent = 0;
  const qopts = { signal, noCache: true };
  if (resolver !== undefined && resolver !== null && resolver !== '') qopts.resolver = resolver;
  const isAbort = (err) => errorKind(err) === 'abort' || !!(signal && signal.aborted);
  const query = (name, type) => {
    const key = qkey(name, type);
    if (memo.has(key)) return memo.get(key);
    const p = limiter.run(() => {
      if (signal && signal.aborted) throw abortReasonToError(signal.reason);
      sent += 1;
      return dns.query(name, type, { ...qopts });
    }, { signal }).then(
      (resp) => (resp && typeof resp === 'object' ? resp : failureResponse(name, type, new Error('empty response'))),
      (err) => {
        if (isAbort(err)) throw err instanceof AbortError ? err : new AbortError('drift cancelled');
        return failureResponse(name, type, err);
      }
    );
    memo.set(key, p);
    return p;
  };

  let aborted = !!(signal && signal.aborted);
  if (!aborted && plan.live) {
    try {
      const [soa, ns] = await Promise.all([query(origin, 'SOA'), query(origin, 'NS')]);
      preflight.originExists = !(soa.ok && soa.rcode === 'NXDOMAIN') && !(ns.ok && ns.rcode === 'NXDOMAIN');
      const liveSoa = ownRrs(soa, origin, 'SOA')[0];
      if (liveSoa && liveSoa.data && Number.isFinite(Number(liveSoa.data.serial))) preflight.liveSerial = Number(liveSoa.data.serial);
      preflight.serial = serialCompare(preflight.fileSerial, preflight.liveSerial);
      preflight.liveNs = sortHostnames([...new Set(ownRrs(ns, origin, 'NS').map((rr) => canon(rr.data)).filter(Boolean))]);
      if (fileNs.length && preflight.liveNs.length) {
        const shared = fileNs.filter((n) => preflight.liveNs.includes(n)).length;
        preflight.nsMatch = shared === fileNs.length && shared === preflight.liveNs.length ? 'same' : shared ? 'overlap' : 'disjoint';
      }
    } catch (err) {
      if (isAbort(err)) aborted = true;
    }
  }

  const pending = items.filter((item) => !item.zero);
  if (!aborted && !preflight.originExists) {
    for (const item of pending) emit(item, setStatus(baseRow(item, plan), 'error', 'nxdomain'));
  } else if (!aborted) {
    await Promise.all(pending.map(async (item) => {
      const qname = item.wildcard ? probes.get(item.name) : item.name;
      try {
        const resps = await Promise.all(item.queries.map((q) => query(q.probe ? qname : q.name, q.type)));
        const row = baseRow(item, plan);
        if (item.wildcard) {
          row.probe = qname;
          row.reasons.push('wildcard');
        }
        row.resolver = resps[0].resolver ?? null;
        row.rcode = resps[0].rcode ?? null;
        const fail = resps.map(failReason).find(Boolean);
        if (fail) {
          emit(item, setStatus(row, 'error', fail));
          return;
        }
        const cq = canon(qname);
        switch (item.mode) {
          case 'proxied-addr': evaluateProxiedAddr(item, row, resps[0], cq, plan); break;
          case 'proxied-cname': evaluateProxiedCname(item, row, resps, cq, plan); break;
          case 'flattened': evaluateFlattened(item, row, resps, cq); break;
          case 'alias': evaluateAlias(item, row, resps, cq); break;
          case 'routing': evaluateRouting(item, row, resps[0], cq); break;
          default: evaluatePlain(item, row, resps[0], cq, idx.cloudflare);
        }
        const auto = item.records.some((r) => r.ttlAuto);
        if (!auto && row.proxied !== true && Number.isFinite(row.liveTtl) && Number.isFinite(row.fileTtl)
          && row.liveTtl > Math.max(row.fileTtl, DRIFT_TTL_FLOOR)) row.reasons.push('ttl-stale');
        emit(item, row);
      } catch (err) {
        if (isAbort(err)) aborted = true;
        else emit(item, setStatus(baseRow(item, plan), 'error', 'transport'));
      }
    }));
  }

  const out = rows.filter(Boolean);
  const counts = Object.fromEntries(DRIFT_STATUSES.map((s) => [s, 0]));
  for (const row of out) counts[row.status] += 1;
  return {
    origin,
    startedAt,
    finishedAt: now(),
    aborted,
    queries: sent,
    planned: plan.reserved.size,
    resolverPolicy: qopts.resolver ? String(typeof qopts.resolver === 'object' ? qopts.resolver.id : qopts.resolver) : 'chain',
    preflight,
    rows: out,
    counts
  };
}

/**
 * Classify names that resolve live but are missing from the file (from a zone-seeded
 * scan): matched by an in-file DNS wildcard (RFC 4592), under a delegated sub-zone, or
 * an unknown extra. Names in the file and names outside the zone are left out.
 * @param {object} zone
 * @param {Iterable<string>} liveNames
 * @returns {Array<{ name: string, kind: 'wildcard'|'delegated'|'extra', matchedBy: string|null }>} sortHostnames order
 */
export function classifyExtraNames(zone, liveNames) {
  const idx = zoneIndex(zone);
  const out = new Map();
  for (const raw of liveNames || []) {
    const name = canon(raw);
    if (!name || out.has(name) || idx.owners.has(name) || !idx.origin || !idx.inZone(name)) continue;
    const cut = idx.cutAtOrAbove(name);
    if (cut) {
      out.set(name, { name, kind: 'delegated', matchedBy: cut });
      continue;
    }
    const wc = wildcardCovers(idx, name);
    out.set(name, wc ? { name, kind: 'wildcard', matchedBy: wc } : { name, kind: 'extra', matchedBy: null });
  }
  return sortHostnames([...out.keys()]).map((n) => out.get(n));
}
