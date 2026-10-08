/**
 * propagation.js — "Global DNS": ask every public resolver (and, through
 * EDNS Client Subnet, a set of geographic vantage points) the same question,
 * group identical answers and explain why they differ (propagationVerdict).
 *
 * DOM-free; all I/O goes through the injected DohClient (`dns`).
 */

import { RESOLVERS, GEO_VANTAGES, DEFAULT_GEO_RESOLVER, getAnyResolver, getVantage } from './resolvers.js';
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
  return getAnyResolver(id) || { id: String(id), name: String(id), url: null, location: null, countryCode: null, filtering: null };
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
export const VERDICT_STATES = Object.freeze(['none', 'unresolved', 'agree', 'by-design', 'geo', 'stale', 'differ']);

/**
 * Finding codes of propagationVerdict, most serious first: `rcode` (SERVFAIL, REFUSED …
 * from some sources), `nxdomain`, `nodata` (no records of the type, or a CNAME chain without
 * addresses), `private` (internal addresses), `mixed` (direct addresses next to CDN /
 * platform edges), `cname` (the CNAME chain differs before it reaches a CDN), `operators`
 * (the queried name's own address records point to different operators), `direct`
 * (different addresses, no known operator) and `records` (other record types differ).
 */
export const VERDICT_FINDINGS = Object.freeze(['rcode', 'nxdomain', 'nodata', 'private', 'mixed', 'cname', 'operators', 'direct', 'records']);

/**
 * Names filtering resolvers rewrite search engines to (SafeSearch / restricted mode), as the
 * engines publish them for network-level enforcement. Measured on Cloudflare Family
 * (2026-09-27): www.google.com → forcesafesearch.google.com, www.bing.com → strict.bing.com,
 * duckduckgo.com → safe.duckduckgo.com. Blocks need no list: Cloudflare Family answers
 * 0.0.0.0 / :: with an EDE (isFilteredResponse), Quad9 and CleanBrowsing answer NXDOMAIN —
 * which a stale negative cache does too, so it is never taken for policy.
 */
export const SAFE_SEARCH_TARGETS = Object.freeze([
  'forcesafesearch.google.com', 'restrict.youtube.com', 'restrictmoderate.youtube.com', 'strict.bing.com',
  'safe.duckduckgo.com', 'familysearch.yandex.ru', 'safesearch.pixabay.com'
]);
const SAFE_SEARCH = new Set(SAFE_SEARCH_TARGETS);

/** Record types whose answers are addresses, so the verdict can tell who operates them. */
const ADDRESS_TYPES = new Set(['A', 'AAAA']);
/** Classification kinds whose addresses the operator picks (edges): they differ by design. */
const EDGE_KINDS = new Set(['cloudflare', 'cdn', 'platform']);
const RCODE_VALUE_RE = /^[A-Z][A-Z0-9]*$/;
const DUALSTACK_RE = /^dualstack\./;

/**
 * May two answers enter `provider` through different entry names by design? Only regional load
 * balancers behind latency routing (web-eu.….elb.amazonaws.com vs web-us.…). Every other operator
 * has one entry name per site: a CDN / WAF / platform property, or a DNS steering profile (Azure
 * Traffic Manager's <profile>.trafficmanager.net, the regional endpoints sit behind it), so
 * another one is another site.
 */
const regionalEntry = (provider) => provider.category === 'loadbalancer' && !provider.dnsOnly;

/**
 * Are two chain positions (a name, null = the address records, undefined = past the chain) the
 * same? A provider name also equals its 'dualstack.' variant: the IPv4 + IPv6 name of the same
 * service (reddit.map.fastly.net / dualstack.reddit.map.fastly.net, ELB's dualstack.…).
 */
function sameName(x, y) {
  if (x === y) return true;
  if (typeof x !== 'string' || typeof y !== 'string') return false;
  return x.replace(DUALSTACK_RE, '') === y.replace(DUALSTACK_RE, '') && !!matchProviderByCname(x);
}

/** The SafeSearch name an answer's CNAME chain (or, for a CNAME query, its record) reaches, or null. */
function safeSearchTarget(values, qtype) {
  for (const v of values) {
    const name = v.startsWith('CNAME ') ? v.slice(6) : qtype === 'CNAME' ? v : null;
    const bare = name && name.toLowerCase().replace(/\.$/, '');
    if (bare && SAFE_SEARCH.has(bare)) return bare;
  }
  return null;
}

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

/**
 * Operator of one answer address, reached through `chain` (netinfo classification first). A
 * private address is 'private' whatever the chain says: no CDN edge answers from one.
 */
function addressOperator(ip, chain, info) {
  if (isPrivateIP(ip)) return operatorFrom({ kind: 'private', provider: null, reasonKey: 'class.private' });
  const v = ipVersion(ip);
  const c = classifyResolution({ status: 'NOERROR', ipv4: v === 4 ? [ip] : [], ipv6: v === 6 ? [ip] : [], cnames: chain });
  if (c.kind === 'direct' && !c.provider) return hintedOperator(ip, info) || operatorFrom(c);
  return operatorFrom(c);
}

/**
 * Operator of an answer without addresses (NODATA) whose CNAME chain enters a provider's name
 * space (www.example.com → example.map.fastly.net, which has no AAAA records): that provider,
 * with the kind and reason netinfo gives an edge reached through the name (netinfo classifies
 * a chain without addresses as dangling). Null when the chain enters none.
 */
function chainOperator(chain) {
  const name = chain.find((c) => matchProviderByCname(c));
  if (!name) return null;
  const p = matchProviderByCname(name);
  if (p.dnsOnly) return operatorFrom({ kind: 'direct', provider: p, reasonKey: 'class.direct' }, 'cname');
  const cloudflare = p.id === 'cloudflare';
  const kind = cloudflare ? 'cloudflare' : p.category === 'cdn' || p.category === 'waf' ? 'cdn' : 'platform';
  return operatorFrom({ kind, provider: p, reasonKey: `class.${cloudflare ? 'cloudflare' : p.category}.cname` }, 'cname');
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
 * Who an answer enters at entryDepth: `{ depth, id, regional, dest }` — the provider of its entry
 * CNAME, else the managed operators of its addresses (ids joined; `regional` only for a single
 * one). `dest`: where it arrives — the entry name (without 'dualstack.'), or for an entry by
 * address the name that holds the edge addresses and the operator. Null for an answer that never
 * enters one.
 */
function entryOf(group) {
  const depth = entryDepth(group);
  if (depth === Infinity) return null;
  if (depth < group.chain.length) {
    const name = group.chain[depth];
    const p = matchProviderByCname(name);
    return { depth, id: p.id, regional: regionalEntry(p), dest: name.replace(DUALSTACK_RE, '') };
  }
  const ops = [...new Map(group.perIp.filter(({ op }) => op.managed).map(({ op }) => [op.id, op])).values()];
  const id = ops.map((op) => op.id).sort().join(' ');
  return { depth, id, regional: ops.length === 1 && regionalEntry(ops[0].provider), dest: `${group.chain[depth - 1] || ''}@${id}` };
}

/**
 * How far two answers' chains must agree (positions in [...chain, <addresses>]):
 * - neither enters an operator: all of it;
 * - both enter the same operator at the same depth: through that entry name. A CDN / WAF /
 *   platform has one entry name per site (d111….cloudfront.net, www.example.com.edgekey.net,
 *   site.netlify.app) and steers only behind it, so another one is another site; regional load
 *   balancers behind latency routing may differ at the entry by design (regionalEntry);
 * - otherwise: up to where either enters one, and at least the queried name's own record.
 *   Different operators are steering by design only behind a name both share (Amazon's
 *   tp.…frontier.amazon.com); one that differs at the queried name is a move between them.
 * One direct and one managed answer compare only the names before the entry: the direct
 * addresses are a finding of their own ('mixed'). Without records anywhere (`noRecords`, chains
 * only) there is no such finding, so the other chain must reach that entry name too.
 */
function agreeLimit(ga, gb, ea = entryOf(ga), eb = entryOf(gb), noRecords = false) {
  if (!ea && !eb) return Math.max(ga.chain.length, gb.chain.length) + 1;
  if (!ea || !eb) return (ea || eb).depth + (noRecords ? 1 : 0);
  if (ea.depth === eb.depth && ea.id === eb.id) return ea.regional ? ea.depth : ea.depth + 1;
  return Math.max(Math.min(ea.depth, eb.depth), 1);
}

/**
 * Where two answers' chains conflict: for every pair of answers, the first position within
 * agreeLimit where they differ — code 'cname', per owner (the name whose record differs; null =
 * the queried name) — or, when the queried name's own address records agree in shape but name
 * different operators (Netlify's address at the apex on one side, Vercel's on the other), code
 * 'operators'. `move`: the answers involved enter different operators. Shallowest first.
 *
 * A difference is steering in the name's own DNS instead (weighted or load-balanced records:
 * zone1.www.example.com / zone2.… → the same *.map.fastly.net name, or gslb / gslb2 → Akamai or
 * Fastly) when both sides are names and every answer through one of them arrives where answers
 * through the other one arrive too — the same entry names (entryOf `dest`), so it does not
 * matter which name a source got. Those are listed in `steered` (`{ owner, targets }`), not as
 * conflicts. Another entry name (d111… vs d222….cloudfront.net) is never steering.
 *
 * @returns {{ conflicts: object[], steered: Array<{ owner: string|null, targets: string[] }> }}
 */
function chainConflicts(answers, noRecords = false) {
  const entries = new Map(answers.map((g) => [g, entryOf(g)]));
  const seqs = new Map(answers.map((g) => [g, [...g.chain, null]]));
  const byOwner = new Map();
  const steered = new Map();
  const conflict = (code, depth, owner) => {
    const id = `${code}\n${depth}\n${owner}`;
    let c = byOwner.get(id);
    if (!c) {
      c = { code, depth, owner, targets: [], groups: [], operators: new Set() };
      byOwner.set(id, c);
    }
    return c;
  };
  const addTo = (c, pairs) => {
    for (const [g, target] of pairs) {
      if (target !== undefined && c.code === 'cname' && !c.targets.includes(target)) c.targets.push(target);
      if (!c.groups.includes(g)) c.groups.push(g);
      if (entries.get(g)) c.operators.add(entries.get(g).id);
    }
  };
  /** Entry names of the answers whose chain starts with `prefix`, then `name`; null if one never enters any. */
  const destinations = (prefix, name) => {
    const out = new Set();
    for (const g of answers) {
      const seq = seqs.get(g);
      if (!sameName(seq[prefix.length], name) || !prefix.every((n, k) => sameName(seq[k], n))) continue;
      const e = entries.get(g);
      if (!e) return null;
      out.add(e.dest);
    }
    return out;
  };
  const within = (a, b) => [...a].every((d) => b.has(d));
  const isSteering = (prefix, x, y) => {
    if (typeof x !== 'string' || typeof y !== 'string') return false;
    const dx = destinations(prefix, x);
    const dy = destinations(prefix, y);
    return !!dx && !!dy && (within(dx, dy) || within(dy, dx));
  };
  for (let a = 0; a < answers.length; a += 1) {
    for (let b = a + 1; b < answers.length; b += 1) {
      const ga = answers[a];
      const gb = answers[b];
      const seqA = seqs.get(ga);
      const seqB = seqs.get(gb);
      const ea = entries.get(ga);
      const eb = entries.get(gb);
      const limit = agreeLimit(ga, gb, ea, eb, noRecords);
      let differs = false;
      for (let i = 0; i < limit && !differs; i += 1) {
        const x = i < seqA.length ? seqA[i] : undefined;
        const y = i < seqB.length ? seqB[i] : undefined;
        if (sameName(x, y)) continue;
        differs = true;
        const owner = i === 0 ? null : seqA[i - 1];
        if (!isSteering(seqA.slice(0, i), x, y)) {
          addTo(conflict('cname', i, owner), [[ga, x], [gb, y]]);
          continue;
        }
        const key = `${i}\n${owner}`;
        const s = steered.get(key) || { depth: i, owner, targets: [] };
        s.targets = uniqueList([...s.targets, x, y]);
        steered.set(key, s);
      }
      if (!differs && limit >= 1 && !ga.chain.length && !gb.chain.length && ea && eb && ea.id !== eb.id) {
        addTo(conflict('operators', 0, null), [[ga], [gb]]);
      }
    }
  }
  return {
    conflicts: [...byOwner.values()]
      .sort((a, b) => a.depth - b.depth)
      .map(({ operators, ...c }) => ({ ...c, move: operators.size > 1 })),
    steered: [...steered.values()].sort((a, b) => a.depth - b.depth).map(({ owner, targets }) => ({ owner, targets }))
  };
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
 * - 'none': no usable answer; 'unresolved': every usable answer is an error rcode (SERVFAIL,
 *   REFUSED …), so nobody resolves the name — never "agree"; 'agree': one distinct answer;
 * - 'by-design': A/AAAA answers that differ, every one an edge of a known operator
 *   (CDN / WAF / platform, or DNS-level steering), the CNAME chains agree until each enters
 *   the operator's name space — through the entry name when both enter the same operator
 *   (d111….cloudfront.net vs d222….cloudfront.net are two distributions, old-site.netlify.app
 *   vs new-site.netlify.app two sites; only regional load balancers may differ there) — and
 *   different operators diverge only behind a name every answer shares (e.g. tp.example.com →
 *   a CloudFront edge in one region, and tp.example.com → *.edgekey.net → *.akamaiedge.net in
 *   another), never at the queried name itself — except where only locations asked through a
 *   resolver of their own (a vantage with `resolver`: mainland China through AliDNS) take another
 *   branch while every other answer takes the same one (www.example.com → a CloudFront
 *   distribution for the world, → *.w.kunluncan.com, Alibaba Cloud CDN, for mainland China: the
 *   name's DNS answers China's resolvers from a line of its own; listed in `geoSplits`; their
 *   edges must be the CDN their last CNAME names, and the control — that resolver asked on behalf
 *   of a subnet outside the region — must not take their branch too) and the
 *   resolvers do not all agree anyway; no NXDOMAIN / NODATA / rcode / private address
 *   anywhere, except empty answers whose chain enters the provider through the entry name the
 *   addresses come through while the resolvers agree (only some locations get its dual-stack
 *   variant with AAAA records: www.reddit.com AAAA). A name before the entry may differ when both names lead to the same entry names
 *   (weighted or load-balanced records in the name's own DNS: listed in `steering`). With no
 *   records of the type anywhere (`noRecords`: every answer NODATA, e.g. AAAA of a CDN name
 *   without IPv6), the CNAME chains alone are judged the same way, each entering by CNAME;
 * - 'geo': the resolvers agree and only the ECS locations differ, without anything above
 *   that looks wrong, and not every answer is a known edge (the classic GeoDNS case). A CNAME
 *   that differs only between locations (GeoDNS by CNAME, e.g. geolocation records) is GeoDNS
 *   too, and so are empty answers through another entry name than the addresses', and edges
 *   only locations asked through a resolver of their own get next to the direct addresses
 *   everyone else gets (a CDN in mainland China in front of an origin the world reaches directly;
 *   the CDN their last CNAME names, which the control does not get). A branch only those
 *   locations take is GeoDNS only with a `geoSplits` entry, even when the resolvers agree (an
 *   anycast CDN gives them all the same answer): one without (`regionalOnly`) stays a finding;
 * - 'stale': ISP resolver rows (kind 'isp' or 'isp:' keys, Global DNS › ISP resolvers,
 *   lib/ispdns.js) give answers no public resolver or location gives — an address, a CNAME,
 *   NXDOMAIN or NODATA — while the public resolvers and locations alone agree, differ by design or
 *   by location ('agree', 'by-design', 'geo' without the ISP rows), and with them the answers are
 *   not all edges by design: those ISPs still cache an older answer (or rewrite the name). Listed
 *   in `isp.stale`; not when an ISP alone gives an rcode (SERVFAIL, REFUSED: `isp.faults`, a
 *   finding as from any source), and only `isp.unsure` when the locations already differ by
 *   GeoDNS (state 'geo': for an ISP, its region's answer or an older one);
 * - 'differ': everything else; `findings` say which part looks like propagation or a
 *   misconfiguration, and `designPart` whether the rest are edge differences.
 * ISP rows are judged as locations otherwise: their own answers may differ by GeoDNS, an edge of
 * the CDN everyone else is on is by design, and next to public resolvers that disagree they are
 * part of the propagation the findings describe.
 * An answer that only filtering resolvers (resolver `filtering`, not ECS locations) return
 * while an unfiltered source answers differently is their policy only when it is recognisably
 * a rewrite: its CNAME chain reaches a SafeSearch name (SAFE_SEARCH_TARGETS; Cloudflare
 * Family's forcesafesearch.google.com for www.google.com). Its group is marked `rewritten`, its
 * sources and targets are listed in `rewritten` / `rewriteTargets`, and the rest is judged
 * without it. Any other answer only they give — an address, NXDOMAIN, NODATA, a CNAME to an
 * ordinary name — stays in: it is what a stale cache looks like; `filtering` on an rcode /
 * nxdomain / nodata finding only says that filtering resolvers alone give it.
 *
 * Findings (VERDICT_FINDINGS order; in 'differ' and 'unresolved'): `{ code, groups: string[]
 * (group keys), members: string[] }` plus `rcode` ('rcode'), `filtering` ('rcode', 'nxdomain',
 * 'nodata'), `ips` ('private', 'mixed': the offending addresses), `owner` (null = the queried
 * name) / `targets` (string, or null = address records — with `noRecords`, no records and no
 * CNAME) ('cname') and `operators` ('cname', 'operators': the managed operators of the answers
 * involved when they enter different ones — a move between providers — else []), `byLocation`
 * ('cname': its `geoSplits` entry when only locations asked through a resolver of their own take
 * another branch, else null), `regionalOnly` ('cname', 'operators': only those locations take
 * another branch, yet with no `geoSplits` entry — addresses with no name in front, edges that are
 * not the CDN their last CNAME names, or the control on their branch too; 'nodata', when set: only
 * those locations get the empty answer, and it is not their CDN's by the same rules). NXDOMAIN
 * and NODATA are findings only next to another kind of answer, not next to failures alone.
 * `geoSplits` (any state): `{ owner, targets, members, line }` per such CNAME — the names those
 * locations get instead (null: address records), their sources and whether the control confirms
 * the region's line (true) or could not tell (null).
 *
 * @param {Array<{ key?: string, kind?: 'resolver'|'geo', values?: string[], filtered?: boolean,
 *   pending?: boolean, resolver?: { filtering?: string|null }|null, vantage?: { resolver?: string }|null }>} items
 *   resolver / geo results (checkPropagation items or streamed rows; 'geo:' keys or kind 'geo' mark
 *   locations, a `vantage` with its own `resolver` one asked through a resolver of its own)
 * @param {{ type?: string|number, ipInfo?: Map<string, object>|Record<string, object>|null,
 *   controls?: Array<{ resolver: string|{ id: string }, values: string[] }>|null }} [opts]
 *   `ipInfo`: already fetched ipintel IpInfo (or `{ ptr, asn, asns }`) per canonical address;
 *   `controls`: a regional resolver's answer on behalf of a subnet outside its region (checkPropagation `controls`)
 * @returns {{ state: 'none'|'unresolved'|'agree'|'by-design'|'geo'|'differ', type: string,
 *   groups: Array<{ key: string, values: string[], members: string[], status: 'answer'|'nxdomain'|'nodata'|'rcode',
 *     chain: string[], addresses: string[], operators: object[], managed: boolean, rewritten: boolean }>,
 *   operators: object[], findings: object[], resolversAgree: boolean, designPart: boolean, multiOperator: boolean,
 *   noRecords: boolean, steering: Array<{ owner: string|null, targets: string[] }>,
 *   geoSplits: Array<{ owner: string|null, targets: Array<string|null>, members: string[], line: true|null }>,
 *   rewritten: string[], rewriteTargets: string[], isp: null|{ members: string[], reference: string,
 *     stale: Array<{ key: string, members: string[], status: string }>, faults: Array<{ key: string, members: string[],
 *     status: string }>, unsure: boolean } }}
 *   `isp` (null without ISP rows): the ISP rows that answered, the state without them (`reference`),
 *   the answer groups only ISPs give that look like older cached answers (`stale`) or faults.
 *   Operators: `{ id, name, kind (netinfo kind), provider, via: 'ip'|'cname'|'ptr'|'asn'|null, reasonKey,
 *   managed, steering }` — of a group's addresses, or for a NODATA group of the provider its CNAME
 *   chain enters; the top-level list holds the managed ones of the judged groups (the answers, or
 *   with `noRecords` the chains) with their `members`, most sources first.
 */
export function propagationVerdict(items, opts = {}) {
  const list = Array.isArray(items) ? items : [];
  const all = judgeItems(list, opts);
  if (!list.some(isIspItem)) return { ...all, isp: null };
  // The same question without the ISP rows: what the public resolvers and the locations say.
  const ref = judgeItems(list.filter((it) => !isIspItem(it)), opts);
  const ispKey = (key) => String(key).startsWith('isp:');
  const ispOnly = all.groups.filter((g) => !g.rewritten && g.members.every(ispKey));
  // An rcode (SERVFAIL, REFUSED) only an ISP gives is a fault there, never a cached answer; another
  // edge of a CDN the public sources are on is that CDN's choice for the ISP's region.
  const refOps = new Set(ref.groups.flatMap((g) => g.operators.filter((op) => op.managed).map((op) => op.id)));
  const refEdge = (g) => g.managed && g.operators.length > 0 && g.operators.every((op) => refOps.has(op.id));
  const cached = ispOnly.filter((g) => g.status !== 'rcode' && !refEdge(g));
  const faults = ispOnly.filter((g) => g.status === 'rcode');
  const entry = (g) => ({ key: g.key, members: [...g.members], status: g.status });
  const isp = {
    members: uniqueList(all.groups.flatMap((g) => g.members.filter(ispKey))),
    reference: ref.state,
    stale: [],
    faults: faults.map(entry),
    unsure: false
  };
  let state = all.state;
  if (cached.length && all.state !== 'by-design' && ['agree', 'by-design', 'geo'].includes(ref.state)) {
    isp.stale = cached.map(entry);
    if (ref.state === 'geo' && all.state === 'geo') isp.unsure = true; // GeoDNS for their region, or an older answer
    else if (!faults.length) state = 'stale';
  }
  return {
    ...all,
    state,
    findings: state === 'stale' ? [] : all.findings,
    designPart: state === 'stale' ? false : all.designPart,
    isp
  };
}

/** An ISP resolver row (Global DNS › ISP resolvers, lib/ispdns.js): kind 'isp' or an 'isp:' key. */
const isIspItem = (it) => !!it && (it.kind === 'isp' || String(it.key ?? '').startsWith('isp:'));

/** propagationVerdict over one set of items (with or without the ISP rows). */
function judgeItems(items, { type = 'A', ipInfo = null, controls = null } = {}) {
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
  // A location asked through a resolver of its own (mainland China: AliDNS), not Google's ECS.
  const isRegional = (it) => isGeo(it) && !!(it.vantage && it.vantage.resolver);
  const isFiltering = (it) => !isGeo(it) && !isIspItem(it) && !!(it.resolver && it.resolver.filtering);
  // Does the source validate DNSSEC? Google, which asks for the other locations, does; AliDNS does not.
  const validates = (it) => {
    const r = isRegional(it) ? getAnyResolver(it.vantage.resolver) : (isGeo(it) ? null : it.resolver);
    return !(r && r.dnssecValidating === false);
  };
  const baseline = usable.some((it) => !isFiltering(it));
  // The controls: a regional resolver's answer on behalf of a subnet outside its region, by resolver id.
  const controlOf = new Map();
  for (const c of Array.isArray(controls) ? controls : []) {
    const id = c && (typeof c.resolver === 'string' ? c.resolver : c.resolver && c.resolver.id);
    if (id && Array.isArray(c.values)) controlOf.set(id, c.values);
  }

  const byKey = new Map();
  usable.forEach((it, order) => {
    const key = it.values.join('\n');
    let g = byKey.get(key);
    if (!g) {
      g = { key, values: [...it.values], members: [], order, geo: true, regional: true, via: new Set(), unvalidated: true, filteringOnly: baseline };
      byKey.set(key, g);
    }
    g.members.push(String(it.key ?? `#${order}`));
    // An ISP's resolver answers for its region like a location (GeoDNS gives it that region's answer).
    if (!isGeo(it) && !isIspItem(it)) g.geo = false;
    if (!isRegional(it)) g.regional = false;
    else g.via.add(it.vantage.resolver);
    if (validates(it)) g.unvalidated = false;
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
      const entered = status === 'nodata' ? chainOperator(chain) : null;
      const operators = entered ? [entered] : [...new Map(perIp.map(({ op }) => [op.id, op])).values()];
      const rewrite = g.filteringOnly && status === 'answer' ? safeSearchTarget(g.values, qtype) : null;
      return { ...g, status, chain, addresses, operators, managed: perIp.length > 0 && perIp.every(({ op }) => op.managed), perIp, rewrite };
    });

  // A SafeSearch rewrite only filtering resolvers give is their policy: judged without it.
  const policy = groups.filter((g) => g.rewrite);
  const { state, operators, findings, resolversAgree, managed, noRecords, steering, geoSplits } = judgeGroups(groups.filter((g) => !g.rewrite), address, controlOf);
  return {
    state: usable.length ? state : 'none',
    type: qtype,
    groups: groups.map(({ perIp, geo, regional, via, unvalidated, filteringOnly, rewrite, ...g }) => ({ ...g, rewritten: !!rewrite })),
    operators,
    findings: state === 'differ' || state === 'unresolved' ? findings : [],
    resolversAgree,
    designPart: state === 'differ' && managed > 1 && !findings.some((f) => f.code === 'cname' || f.code === 'operators'),
    multiOperator: operators.length > 1,
    noRecords,
    steering,
    geoSplits,
    rewritten: membersOf(policy),
    rewriteTargets: uniqueList(policy.map((g) => g.rewrite))
  };
}

/**
 * The judgement of propagationVerdict over prepared answer groups (with `perIp` operators,
 * `geo`: only ECS locations gave it, `regional`: only locations asked through a resolver of
 * their own, and `filteringOnly`): managed operators, findings and the state.
 */
function judgeGroups(groups, address, controls = new Map()) {
  const answers = groups.filter((g) => g.status === 'answer');
  const resolved = groups.filter((g) => g.status !== 'rcode');
  // Nobody has records of the type (AAAA of an IPv4-only CDN name): only the chains can differ.
  const noRecords = address && resolved.length > 0 && resolved.every((g) => g.status === 'nodata');
  const judged = noRecords ? resolved : answers;
  const opMembers = new Map();
  for (const g of judged) {
    for (const op of g.operators) {
      if (!op.managed) continue;
      const entry = opMembers.get(op.id) || { ...op, members: [] };
      entry.members = uniqueList([...entry.members, ...g.members]);
      opMembers.set(op.id, entry);
    }
  }
  const operators = [...opMembers.values()].sort((a, b) => b.members.length - a.members.length);
  /** Managed operators of some groups, most sources first (as in `operators`). */
  const operatorsOf = (list) => operators.filter((op) => list.some((g) => g.operators.some((x) => x.id === op.id)));

  const findings = [];
  const add = (code, list, extra = {}) => {
    if (list.length) findings.push({ code, groups: list.map((g) => g.key), members: membersOf(list), ...extra });
  };
  const filtering = (list) => list.every((g) => g.filteringOnly);
  // `noDnssec`: only sources that do not validate DNSSEC (AliDNS) give it, so a SERVFAIL is no signature problem.
  for (const g of groups.filter((x) => x.status === 'rcode')) add('rcode', [g], { rcode: g.values[0], filtering: filtering([g]), noDnssec: g.unvalidated });
  // NXDOMAIN / NODATA differ only from another kind of answer — not from failures alone, and
  // an empty answer everywhere leaves only its CNAME chains to compare (below).
  if (new Set(resolved.map((g) => g.status)).size > 1) {
    for (const status of ['nxdomain', 'nodata']) {
      const list = groups.filter((g) => g.status === status);
      add(status, list, { filtering: filtering(list) });
    }
  }
  let steering = [];
  const geoSplits = [];
  if (groups.length > 1) {
    const ipsOf = (g, pred) => g.perIp.filter(({ op }) => pred(op)).map(({ ip }) => ip);
    const privateGroups = answers.filter((g) => ipsOf(g, (op) => op.kind === 'private').length);
    add('private', privateGroups, { ips: uniqueList(privateGroups.flatMap((g) => ipsOf(g, (op) => op.kind === 'private'))) });
    if (operators.length) {
      const direct = (op) => !op.managed && op.kind !== 'private';
      const mixedGroups = answers.filter((g) => ipsOf(g, direct).length);
      add('mixed', mixedGroups, { ips: uniqueList(mixedGroups.flatMap((g) => ipsOf(g, direct))) });
    }
    if (address) {
      const { conflicts, steered } = chainConflicts(judged, noRecords);
      steering = steered;
      for (const code of ['cname', 'operators']) {
        for (const c of conflicts.filter((x) => x.code === code)) {
          const split = code === 'cname' ? locationSplit(c, controls) : null;
          if (split) geoSplits.push(split);
          const extra = { operators: c.move ? operatorsOf(c.groups) : [], regionalOnly: !split && regionalBranch(c) };
          add(code, c.groups, code === 'cname' ? { owner: c.owner, targets: c.targets, ...extra, byLocation: split } : extra);
        }
      }
    }
    if (!findings.some((f) => f.code === 'cname' || f.code === 'operators')) {
      // Public addresses that differ with no operator to explain it (private ones are named above).
      const publicAnswers = answers.filter((g) => ipsOf(g, (op) => op.kind !== 'private').length);
      if (!address && answers.length > 1) add('records', answers);
      else if (address && !operators.length && publicAnswers.length > 1) add('direct', publicAnswers);
    }
  }

  const resolversAgree = groups.filter((g) => !g.geo).length <= 1;
  const chainFinding = (f) => f.code === 'cname' || f.code === 'operators';
  const groupOf = new Map(groups.map((g) => [g.key, g]));
  // An empty answer only the locations asked through a resolver of their own get (an IPv4-only
  // mainland CDN name for AAAA) is their CDN's under the rules their edges follow (below), or it
  // is marked `regionalOnly` like a branch without a split.
  for (const f of findings.filter((x) => x.code === 'nodata')) {
    const list = f.groups.map((k) => groupOf.get(k));
    if (list.every((g) => g.regional) && list.some((g) => !ownEdge(g) || controlEnters(g, controls))) f.regionalOnly = true;
  }
  const answerEntries = new Set(answers.map((g) => entryOf(g)?.dest).filter(Boolean));
  // Empty answers whose chains enter a provider (an IPv4-only edge name) next to addresses other
  // locations get through a name of it (Reddit's dualstack.x.map.fastly.net): GeoDNS by CNAME.
  const edgeNodata = (f) => f.code === 'nodata' && f.groups.every((k) => groupOf.get(k)?.operators.length);
  const sameEdges = (f) => edgeNodata(f) && f.groups.every((k) => answerEntries.has(entryOf(groupOf.get(k))?.dest));
  // A chain that differs only between locations while the resolvers agree is GeoDNS by CNAME,
  // as different addresses there are ('direct'): not serious, and "by design" only when the empty
  // answers enter the provider through the entry name the addresses come through (its
  // `dualstack.` variant included). So is, whatever the resolvers do, a branch only the locations
  // asked through a resolver of their own take (`byLocation`: the name's own DNS answers mainland
  // China's resolvers with a CDN there, a line of its own, and the rest of the world with another
  // one), and — while the resolvers agree — direct addresses next to edges only those locations
  // get (a CDN in mainland China in front of an origin the rest of the world reaches directly).
  // Those edges must be the CDN their last CNAME names, as every mainland CDN's are (an address
  // in a CDN's range with no name in front, only there, is the shape of a forged answer, and so
  // is another operator's address or a name nobody operates behind it), and the control must not
  // get them too (then they are the resolver's own answer, not the line's). A branch only those
  // locations take with no such split (`regionalOnly`) stays serious even when the resolvers
  // agree: an anycast CDN gives every resolver the same answer, so their agreement says nothing
  // about the region.
  const edgeGroups = answers.filter((g) => g.operators.some((op) => op.managed));
  const edgesOnlyRegional = edgeGroups.length > 0 && edgeGroups.every((g) => g.regional && ownEdge(g) && !controlEnters(g, controls));
  const locationOnly = (f) => !!f.byLocation
    || (resolversAgree && !f.regionalOnly && (chainFinding(f) || edgeNodata(f) || (f.code === 'mixed' && edgesOnlyRegional)));
  const serious = findings.filter((f) => f.code !== 'direct' && f.code !== 'records' && !locationOnly(f));
  const edges = address && judged.length > 0 && (noRecords ? judged.every((g) => entryOf(g)) : judged.every((g) => g.managed));
  // Edges everywhere with such a branch on the way are by design too — unless the resolvers
  // agree, which stays the classic GeoDNS case ('geo').
  const blocksDesign = (f) => (chainFinding(f) && (resolversAgree || !f.byLocation)) || (edgeNodata(f) && !sameEdges(f));
  let state = 'differ';
  if (!resolved.length) state = 'unresolved';
  else if (groups.length <= 1) state = 'agree';
  else if (!serious.length && edges && !findings.some(blocksDesign)) state = 'by-design';
  else if (!serious.length && resolversAgree) state = 'geo';
  return {
    state, operators, findings, resolversAgree, managed: answers.filter((g) => g.managed).length, noRecords, steering, geoSplits
  };
}

/**
 * Is a regional answer's edge the CDN its last CNAME names (…w.kunluncan.com → an Alibaba Cloud
 * CDN edge)? A mainland CDN is always reached through a name of its own last. Another operator's
 * address behind that name, a name nobody operates after it, or DNS-level steering (a Traffic
 * Manager profile) is not one.
 */
function ownEdge(g) {
  const last = g.chain.length ? matchProviderByCname(g.chain[g.chain.length - 1]) : null;
  const managed = g.operators.filter((op) => op.managed);
  return !!last && !last.dnsOnly && managed.length > 0 && managed.every((op) => op.id === last.id);
}

/**
 * Does only a location asked through a resolver of its own take another branch in a chain
 * conflict — every other answer involved takes one side there (the same name at that depth, or
 * for 'operators' the same operator)?
 */
function regionalBranch(c) {
  const side = (g) => {
    const x = c.code === 'cname' ? [...g.chain, null][c.depth] : entryOf(g)?.id;
    return typeof x === 'string' ? x.replace(DUALSTACK_RE, '') : x;
  };
  return c.groups.some((g) => g.regional) && new Set(c.groups.filter((g) => !g.regional).map(side)).size <= 1;
}

/** A control's answer when it is one (addresses or a chain): null for a failure, NXDOMAIN or NODATA. */
const controlAnswer = (values) => (Array.isArray(values) && !isErrorValues(values) && valuesStatus(values) === 'answer' ? values : null);

/** Does a regional resolver's control (its answer outside the region) enter the CDN name a group enters? */
function controlEnters(g, controls) {
  const dest = entryOf(g)?.dest;
  return !!dest && [...g.via].some((id) => {
    const values = controlAnswer(controls.get(id));
    return !!values && splitChain(values).chain.some((n) => n.replace(DUALSTACK_RE, '') === dest);
  });
}

/**
 * A CNAME conflict only the locations asked through a resolver of their own show (mainland China
 * through AliDNS): every other answer involved — the resolvers' and the Google ECS locations' —
 * takes one branch there (or none is involved) and some of those locations take another name, as a
 * name's DNS does that answers mainland China's resolvers from a line of its own. `{ owner,
 * targets, members, line }`: the names those locations get instead, their sources and whether the
 * control — the same resolver asked on behalf of a subnet outside the region — lands on the other
 * answers' branch (true: the region's line) or could not tell (null: no control, or another
 * branch). Null when the other answers take different branches too, when those locations get
 * addresses there instead of a name, when their edges are not the CDN their last CNAME names
 * (ownEdge), or when the control gets their branch as well: then it is that resolver's own answer
 * whatever the subnet (an older one it still holds, or a line by the resolver's own address), not
 * the region's.
 */
function locationSplit(c, controls) {
  const sideOf = (g) => [...g.chain, null][c.depth];
  const home = [];
  for (const g of c.groups) {
    if (!g.regional && !home.some((x) => sameName(x, sideOf(g)))) home.push(sideOf(g));
  }
  if (home.length > 1) return null;
  const away = c.groups.filter((g) => g.regional && !home.some((x) => sameName(x, sideOf(g))));
  if (!away.length || away.some((g) => typeof sideOf(g) !== 'string' || !ownEdge(g))) return null;
  const targets = uniqueList(away.map(sideOf));
  let line = home.length > 0;
  for (const id of new Set(away.flatMap((g) => [...g.via]))) {
    const values = controlAnswer(controls.get(id));
    const seq = values ? [...splitChain(values).chain, null] : [];
    const onTheWay = values && (c.depth === 0 || sameName(seq[c.depth - 1], c.owner));
    const side = onTheWay && c.depth < seq.length ? seq[c.depth] : undefined;
    if (side !== undefined && targets.some((x) => sameName(x, side))) return null;
    if (side === undefined || !home.some((x) => sameName(x, side))) line = false;
  }
  return { owner: c.owner, targets, members: membersOf(away), line: line || null };
}

/**
 * Query `name`/`type` on many resolvers and ECS vantage points concurrently
 * (the DohClient limiter bounds parallelism) and group identical answers.
 *
 * Result items: `resolverResults[i] = { resolver, response, values, key, filtered, addresses }`
 * and `geoResults[i] = { vantage, resolver, response, values, scopePrefix, key, filtered, addresses }`
 * where `resolver` / `vantage` are the definitions from resolvers.js,
 * `key` is 'resolver:<id>' / 'geo:<id>' and `addresses` (extension) the
 * canonical A/AAAA IPs of the answer. Both arrays keep input order. A location whose resolver
 * does not take the type (resolvers.js `types`) is not asked: `notAsked: true`, no values, and it
 * is left out of the groups, the consistency and the verdict.
 * `onResult` streams `{ kind, key, response, values, addresses, resolver?, vantage?, scopePrefix?, filtered }`
 * as each answer arrives.
 *
 * `groups` are sorted by member count (desc), ties by first appearance; each
 * carries extensions `error` (all members failed) and `filtered`.
 * `consistent` is true when all usable answers agree; transport errors and
 * filtered (blocked) answers are ignored, but when every result failed it is false.
 * Extensions: `resolversConsistent`, `geoConsistent` (rows not asked left out), `name`, `type`,
 * `startedAt`, `finishedAt`, `addresses`: every IP seen worldwide as
 * `{ ip, version, provider (netinfo provider|null), private, members: keys }`,
 * most widely returned first — the "which IPs does this name have around the
 * world, and whose are they" view — `controls` (for A / AAAA, once per resolver a vantage
 * names with a `control`: its answer on behalf of that vantage's subnet outside the region,
 * `{ kind: 'control', key: 'control:<id>', resolver, vantage, response, values, addresses }`,
 * streamed too, never a row) and `verdict` (propagationVerdict of all
 * results): different by design (CDN / GeoDNS edges) or propagation / a mistake.
 *
 * @param {string} name
 * @param {string} [type='A']
 * @param {object} opts
 * @param {object} opts.dns DohClient
 * @param {Array<string|object>} [opts.resolvers] resolver ids (default: all RESOLVERS)
 * @param {Array<string|object>} [opts.vantages] vantages or ids (default: GEO_VANTAGES; [] = no geo)
 * @param {string} [opts.geoResolver='google'] resolver used for ECS queries (a vantage with its own `resolver` uses that)
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

  // A resolver that is asked only for some types (AliDNS: its JSON API cuts a large answer short
  // without TC) is not asked for the others: its rows say so instead of showing a cut answer.
  const asks = (r) => !Array.isArray(r.types) || r.types.includes(qtype);
  const controls = [];
  const controlled = new Set();
  const controlTasks = [];

  const geoTasks = vantageList.map(async (vantage, i) => {
    // A vantage may name its own resolver (mainland China: AliDNS); the others use `geoResolver`.
    const via = vantage.resolver ? resolverInfo(vantage.resolver) : geo;
    if (!asks(via)) {
      const item = {
        vantage, resolver: via, response: null, values: [], scopePrefix: null, key: `geo:${vantage.id}`, filtered: false, addresses: [],
        notAsked: true
      };
      geoResults[i] = item;
      safeCall(onResult, { kind: 'geo', ...item });
      return;
    }
    // Once per such resolver, the same question on behalf of a subnet outside its region (the
    // control): a branch only its rows take is the region's line when the control is the world's.
    // Only for the address types: the verdict reads no other.
    const control = vantage.resolver && via.control && ADDRESS_TYPES.has(qtype) ? getVantage(via.control) : null;
    if (control && !controlled.has(via.id)) {
      controlled.add(via.id);
      controlTasks.push((async () => {
        const res = await dns.query(name, qtype, { resolver: via.id, ecs: control.subnet, signal, noCache, dnssec });
        const item = {
          kind: 'control', key: `control:${via.id}`, resolver: via, vantage: control, response: res, values: answerValues(res, qtype),
          filtered: false, addresses: answerAddresses(res)
        };
        controls.push(item);
        safeCall(onResult, item);
      })().catch(() => {})); // no control is an unsure split, never a failed check (an abort is checked below)
    }
    const response = await dns.query(name, qtype, {
      resolver: via.id, ecs: vantage.subnet, signal, noCache, dnssec
    });
    const values = answerValues(response, qtype);
    const scopePrefix = response && response.ecs && Number.isFinite(response.ecs.scopePrefix)
      ? response.ecs.scopePrefix
      : null;
    const item = {
      vantage, resolver: via, response, values, scopePrefix, key: `geo:${vantage.id}`,
      filtered: isFilteredResponse(response, via), addresses: answerAddresses(response)
    };
    geoResults[i] = item;
    safeCall(onResult, { kind: 'geo', ...item });
  });

  await Promise.all([...resolverTasks, ...geoTasks]);
  await Promise.all(controlTasks);
  checkAbort(signal);

  // Rows that were not asked (their resolver does not take this type) are not answers.
  const all = [...resolverResults, ...geoResults].filter((item) => !item.notAsked);
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
    geoConsistent: consistentOver(geoResults.filter((item) => !item.notAsked)),
    addresses: summarizeAddresses(all),
    controls,
    verdict: propagationVerdict(all, { type: qtype, controls }),
    startedAt,
    finishedAt: new Date()
  };
}
