/**
 * propagation.js — "Global DNS": ask every public resolver (and, through
 * EDNS Client Subnet, a set of geographic vantage points) the same question,
 * group identical answers and explain why they differ (propagationVerdict).
 *
 * DOM-free; all I/O goes through the injected DohClient (`dns`).
 */

import { RESOLVERS, GEO_VANTAGES, DEFAULT_GEO_RESOLVER, getResolver, getVantage } from './resolvers.js';
import { typeToNumber, typeToName } from './dnswire.js';
import { followCnames } from './doh.js';
import {
  classifyResolution, getProvider, matchProviderByCname, matchProviderByIP, normalizeIP, ipVersion, isPrivateIP, parseIP
} from './netinfo.js';
import { networkHint } from './ipintel.js';
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
 * Split answer values (answerValues) into record values and the CNAME chain
 * ('CNAME <target>' entries, chain order).
 * @param {string[]} values
 * @returns {{ plain: string[], chain: string[] }}
 */
export function splitChain(values) {
  const plain = [];
  const chain = [];
  for (const v of Array.isArray(values) ? values : []) {
    if (typeof v === 'string' && v.startsWith('CNAME ')) chain.push(v.slice(6));
    else plain.push(v);
  }
  return { plain, chain };
}

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

/* ------------------------------------------------------------------------ */
/* Verdict: different by design (CDN / GeoDNS) or propagation / a mistake   */
/* ------------------------------------------------------------------------ */

/** States of propagationVerdict (see there). */
export const VERDICT_STATES = Object.freeze(['none', 'agree', 'by-design', 'geo', 'differ']);

/**
 * Finding codes of propagationVerdict, most serious first: `rcode` (SERVFAIL, REFUSED …
 * from some sources), `nxdomain`, `nodata` (no records of the type, or a CNAME chain without
 * addresses), `private` (internal addresses), `mixed` (direct addresses next to CDN /
 * platform edges), `cname` (the CNAME chain differs before it reaches a CDN), `direct`
 * (different addresses, no known operator) and `records` (other record types differ).
 */
export const VERDICT_FINDINGS = Object.freeze(['rcode', 'nxdomain', 'nodata', 'private', 'mixed', 'cname', 'direct', 'records']);

/** Record types whose answers are addresses, so the verdict can tell who operates them. */
const ADDRESS_TYPES = new Set(['A', 'AAAA']);
/** Classification kinds whose addresses the operator picks (edges): they differ by design. */
const EDGE_KINDS = new Set(['cloudflare', 'cdn', 'platform']);
/** netinfo provider categories of global edge networks (one entry name per property). */
const GLOBAL_EDGE_CATEGORIES = new Set(['cdn', 'waf']);
const RCODE_VALUE_RE = /^[A-Z][A-Z0-9]*$/;

/** 'answer' | 'nxdomain' | 'nodata' | 'rcode' for one answer's values (answerValues). */
function valuesStatus(values) {
  if (values.length !== 1) return 'answer';
  const v = values[0];
  if (v === 'NXDOMAIN') return 'nxdomain';
  if (v === 'NODATA') return 'nodata';
  return RCODE_VALUE_RE.test(v) && !normalizeIP(v) ? 'rcode' : 'answer';
}

/**
 * Operator record of a netinfo classification. `managed`: the operator chooses the address —
 * a CDN / WAF / platform edge, or DNS-level steering (netinfo `dnsOnly`, e.g. Azure Traffic
 * Manager: kind stays 'direct', the answers are the customer's endpoints picked per region).
 */
function operatorFrom(c, via = c.via) {
  const steering = c.kind === 'direct' && !!(c.provider && c.provider.dnsOnly);
  const managed = (EDGE_KINDS.has(c.kind) && !!c.provider) || steering;
  return {
    id: managed ? c.provider.id : c.kind,
    name: managed ? c.provider.name : null,
    kind: c.kind,
    provider: managed ? c.provider : null,
    via: managed ? via || null : null,
    reasonKey: c.reasonKey,
    managed,
    steering
  };
}

/**
 * Operator from what a caller already knows about a plain 'direct' address (ipintel IpInfo:
 * `ptr`, `asn` / `asns`): a PTR name under a provider's domain (server-….r.cloudfront.net,
 * a2-….deploy.static.akamaitechnologies.com), or the origin AS of a CDN that publishes no
 * edge ranges (ipintel.networkHint relation 'cdn-edge': Akamai, Imperva, Sucuri). Null otherwise.
 */
function hintedOperator(ip, info) {
  if (!info || typeof info !== 'object') return null;
  const ptrs = Array.isArray(info.ptr) ? info.ptr : typeof info.ptr === 'string' ? [info.ptr] : [];
  for (const ptr of ptrs) {
    const provider = matchProviderByCname(ptr);
    if (!provider || provider.dnsOnly) continue;
    const v = ipVersion(ip);
    const c = classifyResolution({ status: 'NOERROR', ipv4: v === 4 ? [ip] : [], ipv6: v === 6 ? [ip] : [], cnames: [ptr] });
    // The provider is known from the address itself, not from a CNAME of the queried name.
    return operatorFrom({ ...c, reasonKey: c.reasonKey.replace(/\.cname$/, '.ip') }, 'ptr');
  }
  const hint = networkHint(info);
  const provider = hint && hint.relation === 'cdn-edge' ? getProvider(hint.id) : null;
  return provider ? operatorFrom({ kind: 'cdn', provider, reasonKey: `class.${provider.category}.ip` }, 'asn') : null;
}

/** Operator of one answer address, reached through `chain` (netinfo classification first). */
function addressOperator(ip, chain, info) {
  const v = ipVersion(ip);
  const c = classifyResolution({ status: 'NOERROR', ipv4: v === 4 ? [ip] : [], ipv6: v === 6 ? [ip] : [], cnames: chain });
  if (c.kind === 'direct' && !c.provider) return hintedOperator(ip, info) || operatorFrom(c);
  return operatorFrom(c);
}

/**
 * Where an answer enters an operator's name space, as a position in [...chain, <addresses>]:
 * the first CNAME target under a provider domain, else its address records when those are
 * edges (a CDN found by IP range), else Infinity (a direct answer never enters one).
 */
function entryDepth(group) {
  const i = group.chain.findIndex((c) => matchProviderByCname(c));
  if (i !== -1) return i;
  return group.managed ? group.chain.length : Infinity;
}

/**
 * How far two answers' chains must agree: up to where either enters an operator's name space,
 * and through that entry name when both enter the same CDN / WAF there. A global edge network
 * has one entry name per property (d111….cloudfront.net, www.example.com.edgekey.net) and
 * steers only behind it, so another one is another property. Regional platforms (one load
 * balancer per region behind latency routing) may differ at the entry by design.
 */
function agreeLimit(ga, gb) {
  const da = entryDepth(ga);
  const db = entryDepth(gb);
  if (da === Infinity && db === Infinity) return Math.max(ga.chain.length, gb.chain.length) + 1;
  if (da !== db || da >= ga.chain.length || da >= gb.chain.length) return Math.min(da, db);
  const pa = matchProviderByCname(ga.chain[da]);
  const pb = matchProviderByCname(gb.chain[db]);
  return pa.id === pb.id && GLOBAL_EDGE_CATEGORIES.has(pa.category) ? da + 1 : da;
}

/**
 * CNAME conflicts before the CDN: for every pair of answers, the first position within
 * agreeLimit where they differ. Returned per owner (the name whose record differs; null = the
 * queried name), shallowest first.
 */
function chainConflicts(answers) {
  const byOwner = new Map();
  for (let a = 0; a < answers.length; a += 1) {
    for (let b = a + 1; b < answers.length; b += 1) {
      const ga = answers[a];
      const gb = answers[b];
      const seqA = [...ga.chain, null];
      const seqB = [...gb.chain, null];
      const limit = agreeLimit(ga, gb);
      for (let i = 0; i < limit; i += 1) {
        const x = i < seqA.length ? seqA[i] : undefined;
        const y = i < seqB.length ? seqB[i] : undefined;
        if (x === y) continue;
        const owner = i === 0 ? null : seqA[i - 1];
        const id = `${i}\n${owner}`;
        let c = byOwner.get(id);
        if (!c) {
          c = { depth: i, owner, targets: [], groups: [] };
          byOwner.set(id, c);
        }
        for (const [g, target] of [[ga, x], [gb, y]]) {
          if (target !== undefined && !c.targets.includes(target)) c.targets.push(target);
          if (!c.groups.includes(g)) c.groups.push(g);
        }
        break;
      }
    }
  }
  return [...byOwner.values()].sort((a, b) => a.depth - b.depth);
}

const uniqueList = (list) => [...new Set(list)];
const membersOf = (groups) => uniqueList(groups.flatMap((g) => g.members));

/**
 * Why do the answers differ? Groups the usable answers (answered, not blocked by a filtering
 * resolver, not a transport error) by identical values and tells apart differences that a
 * CDN / GeoDNS operator makes by design from those that look like propagation or a mistake.
 * DOM-free and offline: operators come from netinfo (published ranges, CNAME suffixes,
 * DNS-level steering) and, for addresses netinfo calls direct, from PTR names / origin ASNs a
 * caller already fetched (`ipInfo`). Operators are judged for A / AAAA only.
 *
 * States:
 * - 'none': no usable answer; 'agree': one distinct answer;
 * - 'by-design': A/AAAA answers that differ, every one an edge of a known operator
 *   (CDN / WAF / platform, or DNS-level steering), the CNAME chains agree until each enters
 *   the operator's name space (e.g. tp.example.com → a CloudFront edge in one region, and
 *   tp.example.com → *.edgekey.net → *.akamaiedge.net in another) — through the entry name
 *   when both enter the same CDN / WAF (d111….cloudfront.net vs d222….cloudfront.net are two
 *   distributions) — and no NXDOMAIN / NODATA / SERVFAIL / private address anywhere;
 * - 'geo': the resolvers agree and only the ECS locations differ, without anything above
 *   that looks wrong, and not every answer is a known edge (the classic GeoDNS case);
 * - 'differ': everything else; `findings` say which part looks like propagation or a
 *   misconfiguration, and `designPart` whether the rest are edge differences.
 * An answer that only filtering resolvers (resolver `filtering`, not ECS locations) return
 * while an unfiltered source answers differently, and that a finding points at — Cloudflare
 * Family's SafeSearch CNAME for www.google.com, a block page — is their policy: its group is
 * marked `rewritten`, its sources are listed in `rewritten`, and the answers are judged again
 * without it, like a blocked answer. One that is just another CDN edge stays in.
 *
 * Findings (VERDICT_FINDINGS order): `{ code, groups: string[] (group keys), members: string[] }`
 * plus `rcode` ('rcode'), `ips` ('private', 'mixed': the offending addresses) and
 * `owner` (null = the queried name) / `targets` (string, or null = address records) ('cname').
 *
 * @param {Array<{ key?: string, kind?: 'resolver'|'geo', values?: string[], filtered?: boolean,
 *   pending?: boolean, resolver?: { filtering?: string|null }|null }>} items resolver / geo results
 *   (checkPropagation items or streamed rows; 'geo:' keys or kind 'geo' mark locations)
 * @param {{ type?: string|number, ipInfo?: Map<string, object>|Record<string, object>|null }} [opts]
 *   `ipInfo`: already fetched ipintel IpInfo (or `{ ptr, asn, asns }`) per canonical address
 * @returns {{ state: 'none'|'agree'|'by-design'|'geo'|'differ', type: string,
 *   groups: Array<{ key: string, values: string[], members: string[], status: 'answer'|'nxdomain'|'nodata'|'rcode',
 *     chain: string[], addresses: string[], operators: object[], managed: boolean, rewritten: boolean }>,
 *   operators: object[], findings: object[], resolversAgree: boolean, designPart: boolean, multiOperator: boolean,
 *   rewritten: string[] }}
 *   Operators: `{ id, name, kind (netinfo kind), provider, via: 'ip'|'cname'|'ptr'|'asn'|null, reasonKey,
 *   managed, steering }`; the top-level list holds the managed ones with their `members`, most sources first.
 */
export function propagationVerdict(items, { type = 'A', ipInfo = null } = {}) {
  const qtype = typeToName(type ?? 'A');
  const address = ADDRESS_TYPES.has(qtype);
  const infoOf = (ip) => {
    if (!ipInfo || typeof ipInfo !== 'object') return null;
    if (ipInfo instanceof Map) return ipInfo.get(ip) || null;
    return Object.prototype.hasOwnProperty.call(ipInfo, ip) ? ipInfo[ip] : null;
  };
  const usable = (Array.isArray(items) ? items : []).filter((it) => it && !it.pending && !it.filtered
    && Array.isArray(it.values) && it.values.length && !isErrorValues(it.values));
  const isGeo = (it) => it.kind === 'geo' || String(it.key ?? '').startsWith('geo:');
  const isFiltering = (it) => !isGeo(it) && !!(it.resolver && it.resolver.filtering);
  const baseline = usable.some((it) => !isFiltering(it));

  const byKey = new Map();
  usable.forEach((it, order) => {
    const key = it.values.join('\n');
    let g = byKey.get(key);
    if (!g) {
      g = { key, values: [...it.values], members: [], order, geo: true, filteringOnly: baseline };
      byKey.set(key, g);
    }
    g.members.push(String(it.key ?? `#${order}`));
    if (!isGeo(it)) g.geo = false;
    if (!isFiltering(it)) g.filteringOnly = false;
  });
  const groups = [...byKey.values()]
    .sort((a, b) => b.members.length - a.members.length || a.order - b.order)
    .map(({ order, ...g }) => {
      let status = valuesStatus(g.values);
      const { plain, chain } = address ? splitChain(g.values) : { plain: g.values, chain: [] };
      const addresses = address && status === 'answer' ? uniqueList(plain.map(normalizeIP).filter(Boolean)) : [];
      if (address && status === 'answer' && !addresses.length) status = 'nodata'; // a chain without addresses
      const perIp = addresses.map((ip) => ({ ip, op: addressOperator(ip, chain, infoOf(ip)) }));
      const operators = [...new Map(perIp.map(({ op }) => [op.id, op])).values()];
      return { ...g, status, chain, addresses, operators, managed: perIp.length > 0 && perIp.every(({ op }) => op.managed), perIp };
    });

  // An answer only filtering resolvers give, while an unfiltered source answers differently, is
  // their policy (SafeSearch CNAMEs, block pages …) when it is what looks wrong: judged again
  // without it. One that is just another edge (a filtering resolver's own cache) stays in.
  let result = judgeGroups(groups, address);
  const policy = groups.filter((g) => g.filteringOnly && result.findings.some((f) => f.groups.includes(g.key)));
  if (policy.length) result = judgeGroups(groups.filter((g) => !policy.includes(g)), address);
  const { state, findings } = result;
  return {
    state: usable.length ? state : 'none',
    type: qtype,
    groups: groups.map(({ perIp, geo, filteringOnly, ...g }) => ({ ...g, rewritten: policy.some((p) => p.key === g.key) })),
    operators: result.operators,
    findings: state === 'differ' ? findings : [],
    resolversAgree: result.resolversAgree,
    designPart: state === 'differ' && result.managed > 1 && !findings.some((f) => f.code === 'cname'),
    multiOperator: result.operators.length > 1,
    rewritten: membersOf(policy)
  };
}

/**
 * The judgement of propagationVerdict over prepared answer groups (with `perIp` operators and
 * `geo`: only ECS locations gave it): managed operators, findings and the state.
 */
function judgeGroups(groups, address) {
  const answers = groups.filter((g) => g.status === 'answer');
  const opMembers = new Map();
  for (const g of answers) {
    for (const { op } of g.perIp) {
      if (!op.managed) continue;
      const entry = opMembers.get(op.id) || { ...op, members: [] };
      entry.members = uniqueList([...entry.members, ...g.members]);
      opMembers.set(op.id, entry);
    }
  }
  const operators = [...opMembers.values()].sort((a, b) => b.members.length - a.members.length);

  const findings = [];
  const add = (code, list, extra = {}) => {
    if (list.length) findings.push({ code, groups: list.map((g) => g.key), members: membersOf(list), ...extra });
  };
  if (groups.length > 1) {
    for (const g of groups.filter((x) => x.status === 'rcode')) add('rcode', [g], { rcode: g.values[0] });
    add('nxdomain', groups.filter((g) => g.status === 'nxdomain'));
    add('nodata', groups.filter((g) => g.status === 'nodata'));
    const ipsOf = (g, pred) => g.perIp.filter(({ op }) => pred(op)).map(({ ip }) => ip);
    const privateGroups = answers.filter((g) => ipsOf(g, (op) => op.kind === 'private').length);
    add('private', privateGroups, { ips: uniqueList(privateGroups.flatMap((g) => ipsOf(g, (op) => op.kind === 'private'))) });
    if (operators.length) {
      const direct = (op) => !op.managed && op.kind !== 'private';
      const mixedGroups = answers.filter((g) => ipsOf(g, direct).length);
      add('mixed', mixedGroups, { ips: uniqueList(mixedGroups.flatMap((g) => ipsOf(g, direct))) });
    }
    if (address) {
      for (const c of chainConflicts(answers)) add('cname', c.groups, { owner: c.owner, targets: c.targets });
    }
    if (!findings.some((f) => f.code === 'cname')) {
      // Public addresses that differ with no operator to explain it (private ones are named above).
      const publicAnswers = answers.filter((g) => ipsOf(g, (op) => op.kind !== 'private').length);
      if (!address && answers.length > 1) add('records', answers);
      else if (address && !operators.length && publicAnswers.length > 1) add('direct', publicAnswers);
    }
  }

  const resolversAgree = groups.filter((g) => !g.geo).length <= 1;
  const serious = findings.filter((f) => f.code !== 'direct' && f.code !== 'records');
  let state = 'differ';
  if (groups.length <= 1) state = 'agree';
  else if (!serious.length && address && answers.length && answers.every((g) => g.managed)) state = 'by-design';
  else if (!serious.length && resolversAgree) state = 'geo';
  return { state, operators, findings, resolversAgree, managed: answers.filter((g) => g.managed).length };
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
 * `startedAt`, `finishedAt`, `addresses`: every IP seen worldwide as
 * `{ ip, version, provider (netinfo provider|null), private, members: keys }`,
 * most widely returned first — the "which IPs does this name have around the
 * world, and whose are they" view — and `verdict` (propagationVerdict of all
 * results): different by design (CDN / GeoDNS edges) or propagation / a mistake.
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
    verdict: propagationVerdict(all, { type: qtype }),
    startedAt,
    finishedAt: new Date()
  };
}
