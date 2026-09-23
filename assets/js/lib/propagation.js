/**
 * propagation.js — "Global DNS": ask every public resolver (and, through
 * EDNS Client Subnet, a set of geographic vantage points) the same question
 * and group identical answers.
 *
 * DOM-free; all I/O goes through the injected DohClient (`dns`).
 */

import { RESOLVERS, GEO_VANTAGES, DEFAULT_GEO_RESOLVER, getResolver, getVantage } from './resolvers.js';
import { typeToNumber, typeToName } from './dnswire.js';
import { followCnames } from './doh.js';
import { matchProviderByIP, normalizeIP, ipVersion, isPrivateIP, parseIP } from './netinfo.js';
import { AbortError, abortReasonToError } from './util.js';

/** EDE info-codes that mean "the resolver deliberately blocked this name" (RFC 8914). */
const FILTER_EDE = new Set([15, 16, 17, 18]); // Blocked, Censored, Filtered, Prohibited
const SINKHOLE_IPS = new Set(['0.0.0.0', '::']);

function toAbortError(reason) {
  const err = abortReasonToError(reason);
  return err instanceof AbortError ? err : new AbortError(err.message, { cause: err });
}

function checkAbort(signal) {
  if (signal && signal.aborted) throw toAbortError(signal.reason);
}

function safeCall(fn, arg) {
  if (typeof fn !== 'function') return;
  try {
    fn(arg);
  } catch {
    /* observer errors never break the check */
  }
}

/**
 * Canonical, comparable answer values of a response.
 *
 * - transport failure (ok=false) → ['ERROR']
 * - NXDOMAIN → ['NXDOMAIN']; any other non-NOERROR rcode → [rcode] (e.g. ['SERVFAIL'])
 * - NOERROR → sorted, de-duplicated presentation text (`rr.text`, no TTL) of
 *   the answer records of `type`; when `type` is not CNAME and the name is an
 *   alias, the chain is appended in order as 'CNAME <target>' entries; an
 *   empty answer (NODATA) → ['NODATA']. For ANY, every record as '<TYPE> <text>'.
 *
 * @param {object|null} response DnsResponse from DohClient.query
 * @param {string|number} type
 * @returns {string[]}
 */
export function answerValues(response, type) {
  if (!response || !response.ok) return ['ERROR'];
  if (response.rcode === 'NXDOMAIN') return ['NXDOMAIN'];
  if (response.rcode !== 'NOERROR') return [String(response.rcode || 'ERROR')];
  const typeNum = typeToNumber(type);
  const answers = Array.isArray(response.answers) ? response.answers : [];
  const any = typeNum === 255;
  const values = new Set();
  for (const rr of answers) {
    if (!rr) continue;
    if (any) values.add(`${rr.type} ${rr.text}`);
    else if (rr.typeNum === typeNum || rr.type === typeToName(typeNum)) values.add(String(rr.text));
  }
  const out = [...values].sort();
  if (!any && typeNum !== 5) {
    const { cnames } = followCnames(answers, response.name);
    for (const target of cnames) out.push(`CNAME ${target}`);
  }
  return out.length ? out : ['NODATA'];
}

/**
 * Did a (filtering) resolver block the name instead of answering it?
 * EDE 15–18, or a 0.0.0.0 / :: sinkhole answer from a filtering resolver.
 * @param {object|null} response
 * @param {object|null} [resolver] resolver definition (uses `filtering`)
 * @returns {boolean}
 */
export function isFilteredResponse(response, resolver = null) {
  if (!response || !response.ok) return false;
  if ((response.ede || []).some((e) => FILTER_EDE.has(e.code))) return true;
  if (!resolver || !resolver.filtering) return false;
  const addrs = (response.answers || []).filter((rr) => rr.type === 'A' || rr.type === 'AAAA');
  return addrs.length > 0 && addrs.every((rr) => SINKHOLE_IPS.has(rr.data));
}

function resolverInfo(id) {
  if (id && typeof id === 'object' && typeof id.id === 'string') return id;
  return getResolver(id) || { id: String(id), name: String(id), url: null, location: null, countryCode: null, filtering: null };
}

function vantageInfo(v) {
  if (v && typeof v === 'object' && typeof v.id === 'string') return v;
  return getVantage(v) || null;
}

const isErrorValues = (values) => values.length === 1 && values[0] === 'ERROR';

/**
 * Canonical A / AAAA addresses of a response (answer order, de-duplicated),
 * following the CNAME chain of the query name. [] for failures / other types.
 * @param {object|null} response DnsResponse
 * @returns {string[]}
 */
export function answerAddresses(response) {
  if (!response || !response.ok || response.rcode !== 'NOERROR') return [];
  const answers = Array.isArray(response.answers) ? response.answers : [];
  const { cnames } = followCnames(answers, response.name);
  const owners = new Set([String(response.name || '').toLowerCase(), ...cnames]);
  const out = [];
  for (const rr of answers) {
    if (!rr || (rr.type !== 'A' && rr.type !== 'AAAA') || !owners.has(String(rr.name).toLowerCase())) continue;
    const ip = normalizeIP(rr.data);
    if (ip && !out.includes(ip)) out.push(ip);
  }
  return out;
}

/**
 * Every address seen anywhere, with who returned it and what it is (CDN /
 * platform provider, private range). Sorted by how many resolvers / vantages
 * returned it, then by address.
 */
function summarizeAddresses(items) {
  const byIp = new Map();
  for (const item of items) {
    if (item.filtered) continue; // sinkhole answers (0.0.0.0) are not real addresses
    for (const ip of item.addresses) {
      let entry = byIp.get(ip);
      if (!entry) {
        const provider = matchProviderByIP(ip);
        entry = { ip, version: ipVersion(ip), provider: provider || null, private: isPrivateIP(ip), members: [] };
        byIp.set(ip, entry);
      }
      entry.members.push(item.key);
    }
  }
  const num = (ip) => {
    const p = parseIP(ip);
    return p ? p.value : 0n;
  };
  return [...byIp.values()].sort((a, b) => b.members.length - a.members.length
    || a.version - b.version || (num(a.ip) < num(b.ip) ? -1 : num(a.ip) > num(b.ip) ? 1 : 0));
}

/**
 * Query `name`/`type` on many resolvers and ECS vantage points concurrently
 * (the DohClient limiter bounds parallelism) and group identical answers.
 *
 * Result items: `resolverResults[i] = { resolver, response, values, key, filtered, addresses }`
 * and `geoResults[i] = { vantage, resolver, response, values, scopePrefix, key, filtered, addresses }`
 * where `resolver` / `vantage` are the definitions from resolvers.js,
 * `key` is 'resolver:<id>' / 'geo:<id>' and `addresses` (extension) the
 * canonical A/AAAA IPs of the answer. Both arrays keep input order.
 * `onResult` streams `{ kind, key, response, values, addresses, resolver?, vantage?, scopePrefix?, filtered }`
 * as each answer arrives.
 *
 * `groups` are sorted by member count (desc), ties by first appearance; each
 * carries extensions `error` (all members failed) and `filtered`.
 * `consistent` is true when all usable answers agree; transport errors and
 * filtered (blocked) answers are ignored, but when every result failed it is false.
 * Extensions: `resolversConsistent`, `geoConsistent`, `name`, `type`,
 * `startedAt`, `finishedAt`, and `addresses`: every IP seen worldwide as
 * `{ ip, version, provider (netinfo provider|null), private, members: keys }`,
 * most widely returned first — the "which IPs does this name have around the
 * world, and whose are they" view.
 *
 * @param {string} name
 * @param {string} [type='A']
 * @param {object} opts
 * @param {object} opts.dns DohClient
 * @param {Array<string|object>} [opts.resolvers] resolver ids (default: all RESOLVERS)
 * @param {Array<string|object>} [opts.vantages] vantages or ids (default: GEO_VANTAGES; [] = no geo)
 * @param {string} [opts.geoResolver='google'] resolver used for ECS queries
 * @param {AbortSignal} [opts.signal]
 * @param {(item: object) => void} [opts.onResult]
 * @param {boolean} [opts.noCache=true] extension: always ask the network
 * @param {boolean} [opts.dnssec=false] extension: set DO
 * @returns {Promise<{ resolverResults: object[], geoResults: object[],
 *   groups: Array<{ key: string, values: string[], members: string[] }>, consistent: boolean }>}
 */
export async function checkPropagation(name, type = 'A', {
  dns,
  resolvers,
  vantages,
  geoResolver = DEFAULT_GEO_RESOLVER,
  signal,
  onResult,
  noCache = true,
  dnssec = false
} = {}) {
  if (!dns || typeof dns.query !== 'function') throw new TypeError('checkPropagation: a DohClient (dns) is required');
  checkAbort(signal);
  const startedAt = new Date();
  const qtype = typeToName(type ?? 'A');
  const resolverIds = Array.isArray(resolvers) ? resolvers : RESOLVERS.map((r) => r.id);
  const vantageList = (Array.isArray(vantages) ? vantages : GEO_VANTAGES).map(vantageInfo).filter(Boolean);
  const geo = resolverInfo(geoResolver);

  const resolverResults = new Array(resolverIds.length);
  const geoResults = new Array(vantageList.length);

  const resolverTasks = resolverIds.map(async (rid, i) => {
    const resolver = resolverInfo(rid);
    const response = await dns.query(name, qtype, { resolver: resolver.id, signal, noCache, dnssec });
    const values = answerValues(response, qtype);
    const item = {
      resolver, response, values, key: `resolver:${resolver.id}`, filtered: isFilteredResponse(response, resolver),
      addresses: answerAddresses(response)
    };
    resolverResults[i] = item;
    safeCall(onResult, { kind: 'resolver', ...item });
  });

  const geoTasks = vantageList.map(async (vantage, i) => {
    const response = await dns.query(name, qtype, {
      resolver: geo.id, ecs: vantage.subnet, signal, noCache, dnssec
    });
    const values = answerValues(response, qtype);
    const scopePrefix = response && response.ecs && Number.isFinite(response.ecs.scopePrefix)
      ? response.ecs.scopePrefix
      : null;
    const item = {
      vantage, resolver: geo, response, values, scopePrefix, key: `geo:${vantage.id}`,
      filtered: isFilteredResponse(response, geo), addresses: answerAddresses(response)
    };
    geoResults[i] = item;
    safeCall(onResult, { kind: 'geo', ...item });
  });

  await Promise.all([...resolverTasks, ...geoTasks]);
  checkAbort(signal);

  const all = [...resolverResults, ...geoResults];
  const byKey = new Map();
  all.forEach((item, order) => {
    const key = item.values.join('\n');
    let g = byKey.get(key);
    if (!g) {
      g = { key, values: item.values, members: [], order, error: isErrorValues(item.values), filtered: true };
      byKey.set(key, g);
    }
    g.members.push(item.key);
    if (!item.filtered) g.filtered = false;
  });
  const groups = [...byKey.values()]
    .sort((a, b) => b.members.length - a.members.length || a.order - b.order)
    .map(({ order, ...g }) => g);

  // One distinct answer among the usable results. With no usable result at all
  // the check is only "consistent" when nothing failed (e.g. every resolver
  // blocked the name, or nothing was asked).
  const consistentOver = (items) => {
    const distinct = new Set(items
      .filter((it) => !it.filtered && !isErrorValues(it.values))
      .map((it) => it.values.join('\n'))).size;
    return distinct === 1 || (distinct === 0 && !items.some((it) => isErrorValues(it.values)));
  };

  return {
    name,
    type: qtype,
    resolverResults,
    geoResults,
    groups,
    consistent: consistentOver(all),
    resolversConsistent: consistentOver(resolverResults),
    geoConsistent: consistentOver(geoResults),
    addresses: summarizeAddresses(all),
    startedAt,
    finishedAt: new Date()
  };
}
