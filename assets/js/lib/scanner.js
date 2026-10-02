/**
 * scanner.js — "SSL target finder": from a certificate and/or domains, find
 * every hostname and resolve it, classify it (Cloudflare / CDN / platform /
 * direct / private / NXDOMAIN), check certificate coverage, map it to the
 * user's servers, and collect origin hints for hosts hidden behind a CDN.
 *
 * The discovery engine is DNS-first: it does not depend on quota-limited
 * third-party APIs. Passive sources (CT logs, passive DNS) run in parallel with
 * DNS record mining (mineDnsNames), then a courteous wordlist brute force and
 * permutation sweep over DNS-over-HTTPS (balance mode spreads the load), with
 * multi-level wildcard filtering (detectWildcardDeep, NODATA/CNAME aware). This
 * finds the direct origin IPs a wildcard certificate / CT log hides — the whole
 * reason to build our own scanner instead of trusting online tools.
 *
 * DOM-free. All DNS goes through the injected DohClient (`config.dns`), all
 * HTTP through `config.fetchImpl`. Cancellation via `config.signal` rejects
 * the scan with an AbortError; results are also streamed through hooks.
 */

import {
  normalizeHostname, stripWildcard, isSubdomainOf, sortHostnames, registrableDomain, isPublicSuffix,
  baseDomainsFromNames, certCovers
} from './domain.js';
import {
  classifyResolution, matchProviderByIP, normalizeIP, parseCidr, parseIP, ipInCidr, isPrivateIP, formatIP,
  isSharedProvider
} from './netinfo.js';
import { buildIpIndex, lookupServers } from './inventory.js';
import { applyTopology, orderByLoadBalancer, terminatesTls, tlsNowhere } from './topology.js';
import {
  getWordlist, loadWordlist, WORDLIST_SMALL, parseCustomWordlist, localesForDomain, LOCALE_PACK_CODES
} from './wordlist.js';
import { SOURCES, fetchAllSources, mergeCerts, sourceHealthSummary } from './sources.js';
import { followCnames, detectWildcardDeep } from './doh.js';
import { mineDnsNames } from './dnsmine.js';
import { permutations, DEFAULT_WORDS } from './permute.js';
import { buildFittedSweepCommand, validateTargets } from './cmdline.js';
import { AbortError, abortReasonToError, splitList, sleep } from './util.js';
// The caps, the stage names and the pure helpers the views use without running a scan.
import {
  PROBE_ORIGINS, HOST_SPECIFIC_HINT_KINDS, MAX_SPF_LOOKUPS, MAX_MX, MAX_BRUTEFORCE_PER_BASE, LEGACY_MAX_BRUTEFORCE,
  MAX_BRUTEFORCE_TOTAL, MAX_PERMUTATIONS, DEFAULT_PERMUTATION_BUDGET, DEFAULT_RECURSIVE_PARENTS,
  RESOLVER_LEAK_MAX_QUERIES, RECURSIVE_EXTRA_WORDS, RECURSIVE_MAX, KNOWN_LEVELS, CORE_LABELS, leftmostLabels
} from './scanplan.js';

export { SCAN_STAGES, HOST_SPECIFIC_HINT_KINDS, estimateQueries, learnedLabelsFromScan } from './scanplan.js';

/* ------------------------------------------------------------------------ */
/* Types                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} HostRecord
 * @property {string} name
 * @property {string[]} origins where the name came from: 'input', 'zone' (the imported
 *   zone file, `config.zone`), 'cert', source ids, 'dns-mine:<record>'
 *   (MX|NS|SOA|SPF|DMARC|SRV|CNAME|CAA|HTTPS|PTR), 'wordlist', 'permutation',
 *   'recursive' (legacy runs may show 'bruteforce')
 * @property {object} resolution HostResolution (doh.js)
 * @property {object} classification netinfo.classifyResolution() result
 * @property {{ covered: boolean, by: string|null }|null} cert coverage by the scanned certificate (null without cert)
 * @property {Array<{ serverId: string, name: string, ip: string }>} servers inventory servers owning a resolved IP
 * @property {boolean} wildcardSuspect answer indistinguishable from the nearest wildcard's (see isWildcardSuspect)
 * @property {object[]} ipHints IpHint[] from passive sources for this name
 * @property {string[]} candidateNetworks extension (v2): the origin-network CIDRs (/24 · /48) worth
 *   sweeping for THIS proxied host's real origin, ranked (host-related networks, then the main
 *   cluster, then other multi-IP clusters; a lone 1-IP network unrelated to the host is left out).
 *   Empty unless the host hides its origin. The CIDRs of the `originCandidates` network entries.
 * @property {Array<{ ip?: string, cidr?: string, kind: 'known'|'zone'|'resolver-leak'|'history'|'sibling-domain'|'network',
 *   score: number, evidence: object }>} originCandidates extension (v3): the ordered origin
 *   candidates for THIS proxied host, strongest first — host-specific exact IPs (zone file,
 *   resolver-leak, history, sibling-domain) above candidate networks. Empty unless the host hides its origin.
 * @property {boolean} customOnly extension: found ONLY by a custom-wordlist label that is not in the
 *   built-in core list (the tab-only custom list is its sole evidence: the wordlist stage, or a
 *   permutation / recursive candidate carrying such a label) — never learned
 * @property {boolean} zoneOnly extension (zone import): its only evidence is the user's zone file
 *   (origin 'zone', possibly with probe origins) — like customOnly, its labels are never learned
 */

/**
 * @typedef {object} OriginHint
 * @property {string} ip
 * @property {Array<{ kind: 'spf'|'mx'|'direct-sibling'|'history'|'resolver-leak'|'sibling-domain'|'zone', detail: string,
 *   host?: string, source?: string, lastSeen?: string|null, resolver?: string, sibling?: string }>} reasons
 *   structured fields by kind: history → { host, source, lastSeen }; resolver-leak → { host, resolver };
 *   sibling-domain → { host, sibling } (the proxied host and the DNS-only sister-brand name at this IP);
 *   zone → { host } (the proxied name whose exact origin the imported zone file holds)
 * @property {Array<{ serverId: string, name: string }>} servers inventory servers with this IP
 * @property {object|null} provider netinfo provider of the IP (never a CDN that hides origins)
 * @property {string[]} hosts extension: hostnames the hint is specifically about (history / sibling-domain / resolver-leak)
 */

/**
 * @typedef {object} OriginNetwork extension (v2)
 * @property {string} cidr /24 (IPv4) or /48 (IPv6) block direct hosts / leaked origins cluster in
 * @property {string[]} ips the public, non-CDN origin IPs seen in the block
 * @property {string[]} hosts the DNS-only host names that resolve into the block
 * @property {object|null} provider netinfo provider of the block (usually null for a real origin)
 * @property {boolean} shared extension (v3): the block sits in known multi-tenant space (a CDN / cloud /
 *   hosting / platform PROVIDERS range) where one /24 serves many unrelated customers — offline only;
 *   ipintel.describeNetwork resolves the AS owner on demand for the rest
 * @property {'cidr'|'ips'} sweep extension (v3): how the CLI targets this block — the whole /24
 *   ('cidr') or its exact addresses ('ips': an IPv6 /48, a shared /24 with no inventory, or a single IP)
 */

/**
 * @typedef {object} ServerGroup
 * @property {object} server inventory Server
 * @property {Array<{ name: string, ip: string, covered: boolean|null, via: 'dns'|'known'|'zone'|'hint' }>} hosts
 *   sorted dns, then known (the workspace's origin map), then zone (the zone file's exact origin
 *   of a proxied name), then hint
 * @property {boolean} needsCert a DNS- or zone-matched host is covered by the certificate (without a
 *   certificate: any DNS- or zone-matched host)
 * @property {boolean} maybeNeedsCert extension: only origin hints point here
 */

/* ------------------------------------------------------------------------ */
/* Constants / helpers                                                      */
/* ------------------------------------------------------------------------ */

// Per-host origin-candidate scores (strongest first). Exact host-specific IPs
// rank above candidate networks; a network's relatedness to the host sets which
// band it lands in.
const CANDIDATE_SCORE = Object.freeze({
  known: 120, zone: 110, 'resolver-leak': 100, 'sibling-domain': 95, history: 90,
  'net-sibling': 70, 'net-related': 65, 'net-main': 60, 'net-cluster': 50
});
// Per-host cap on the weakest candidate band: other multi-IP clusters unrelated
// to the host (host-related networks and the main cluster are never capped).
const MAX_CLUSTER_CANDIDATES = 3;
const MAX_SPF_DEPTH = 5;
const MAX_WILDCARD_PARENTS = 80;
// Flood guard: a parent where more than FLOOD_SHARE of at least FLOOD_MIN_TRIED
// answered guesses "resolve" is re-sampled with FLOOD_RESAMPLE_PROBES random
// labels (plus one per pool resolver). No real zone holds most of a generic list.
const FLOOD_MIN_TRIED = 50;
const FLOOD_SHARE = 0.5;
const FLOOD_RESAMPLE_PROBES = 8;
// Max target domains querying the quota-limited passive sources at once, so a
// many-domain scan (SAN cert) does not exhaust the free per-IP quotas at once.
const SOURCE_DOMAIN_CONCURRENCY = 2;
// The DNS sweep must not sit idle behind the slowest passive source: crt.sh can
// back off for minutes. After mining finishes, wait at most this long for the
// sources before starting the wildcard / brute-force sweep; late source names
// are merged in before the permutation and resolve stages, so nothing is lost.
const DEFAULT_SOURCE_GRACE_MS = 12000;
const SIBLING_DETAIL_NAMES = 5;
// resolver-leak: re-resolve every proxied host through a few OTHER resolvers of
// the pool. A CDN edge often answers the same everywhere, but a mis-scoped ECS
// answer, a split-horizon slip or a GeoDNS pop can leak the real origin on one
// resolver. Capped so
// the extra courtesy queries stay tiny.
const RESOLVER_LEAK_PER_HOST = 3;
// A leak probe is a bonus check, never the critical path: cap each one short so
// a slow / black-holed resolver cannot stall the hints stage, and skip
// resolvers whose circuit breaker is already open (they would only time out).
const RESOLVER_LEAK_TIMEOUT_MS = 2500;
// Courtesy pace for the bulk A-only probes: keep it modest so we never hammer a
// target's authoritative servers, even though the public DoH resolvers tolerate
// far more. Balance mode spreads the queries across the healthy resolver pool.
const PROBE_CONCURRENCY = 24;
// Per-query timeout for the bulk balance probes. Failover to the other pool
// members already covers a slow / black-holed resolver, so a short cap (kept
// generous enough for high-latency mobile links) stops one dead resolver from
// stalling the whole sweep for the client's full 8 s timeout. retries:0 too.
const PROBE_TIMEOUT_MS = 2500;
// After this many consecutive fully-failed probes the bulk stages give up: the
// DoH pool is unreachable (blocked DoH, offline), so continuing would only fire
// thousands of doomed requests. A DNS_UNREACHABLE warning is pushed instead.
const PROBE_DEAD_STREAK = 50;
// Recursive round: bound the per-parent label list and the total candidate count
// so a large custom `config.wordlist` cannot multiply into hundreds of thousands
// of probes (bfCandidates and permutations are capped; this round was not).
// RECURSIVE_MAX_WORDS caps a legacy override list. The normal list is at most
// RECURSIVE_EXTRA_WORDS custom / learned labels (custom first) followed by the
// WHOLE built-in core (WORDLIST_SMALL): a big learned store or custom list must
// never push the generic core (www, dev, grafana …) out of this round.
const RECURSIVE_MAX_WORDS = 200;
// Adaptive back-off: after this many consecutive transport failures, pause a
// little before the next probe (grows with the streak, capped) so a struggling
// resolver pool is given room instead of being pounded.
const PROBE_ERR_THRESHOLD = 8;
const PROBE_BACKOFF_STEP = 50;
const PROBE_BACKOFF_MAX = 1000;
// Zone import: the Cloudflare placeholder origins ("no server behind this proxied
// record") are never a hint or a CLI target, even if a caller passes them.
const ZONE_PLACEHOLDER_IPS = new Set(['192.0.2.0', '100::']);
// Server-group host order: DNS matches, then remembered origins, then zone-file origins, then hints.
const VIA_RANK = { dns: 0, known: 1, zone: 2, hint: 3 };
// At most this many remembered origins (lib/originmap.js ORIGIN_MAP_LIMITS.entries) are read.
const MAX_KNOWN_ORIGINS = 2000;

/** Rank of an origin tag for stable display order. */
function rankOrigin(o) {
  if (o === 'input') return 0;
  if (o === 'zone') return 0.5;
  if (o === 'cert') return 1;
  if (typeof o === 'string' && o.startsWith('dns-mine:')) return 2;
  const si = SOURCES.findIndex((s) => s.id === o);
  if (si !== -1) return 100 + si;
  if (o === 'wordlist' || o === 'bruteforce') return 900;
  if (o === 'permutation') return 901;
  if (o === 'recursive') return 902;
  return 1000;
}

/** Passive sources that read certificates (CT logs): a certificate was issued for their names. */
const CT_ORIGINS = new Set(['crtsh', 'certspotter']);

/**
 * Which names a scan over `maxHosts` keeps first (lower first): 0 requested (input, certificate,
 * zone file), 1 shown by DNS (a probe hit, a mined record), 2 in a certificate (CT), 3 the rest.
 * @param {Set<string>} origins a name's origin tags
 * @returns {number}
 */
function truncationRank(origins) {
  let rank = 3;
  for (const o of origins) {
    if (o === 'input' || o === 'cert' || o === 'zone') return 0;
    if (PROBE_ORIGINS.has(o) || o === 'bruteforce' || o.startsWith('dns-mine:')) rank = Math.min(rank, 1);
    else if (CT_ORIGINS.has(o)) rank = Math.min(rank, 2);
  }
  return rank;
}

function toAbortError(reason) {
  const err = abortReasonToError(reason);
  return err instanceof AbortError ? err : new AbortError(err.message, { cause: err });
}

function checkAbort(signal) {
  if (signal && signal.aborted) throw toAbortError(signal.reason);
}

function safeCall(fn, ...args) {
  if (typeof fn !== 'function') return;
  try {
    fn(...args);
  } catch {
    /* UI hooks must never break the scan */
  }
}

/** Run `fn` over `items` with at most `limit` in flight; stops early on abort / error. */
async function mapPool(items, limit, fn, signal) {
  let next = 0;
  let failed = false;
  const worker = async () => {
    while (!failed && next < items.length) {
      checkAbort(signal);
      const i = next;
      next += 1;
      try {
        await fn(items[i], i);
      } catch (err) {
        failed = true;
        throw err;
      }
    }
  };
  const n = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: n }, worker));
}

function compareIp(a, b) {
  const x = parseIP(a);
  const y = parseIP(b);
  if (!x || !y) return String(a).localeCompare(String(b));
  if (x.version !== y.version) return x.version - y.version;
  return x.value < y.value ? -1 : x.value > y.value ? 1 : 0;
}

function orderOrigins(set) {
  return [...set].sort((a, b) => {
    const ra = rankOrigin(a);
    const rb = rankOrigin(b);
    if (ra !== rb) return ra - rb;
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function normalizeSerial(hex) {
  if (typeof hex !== 'string') return null;
  let s = hex.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (!s) return null;
  if (s.length % 2) s = `0${s}`;
  while (s.length > 2 && s.startsWith('00')) s = s.slice(2);
  return s;
}

function formatDay(d) {
  return d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString().slice(0, 10) : null;
}

/**
 * /24 (IPv4) or /48 (IPv6) network CIDR containing `ip`, or null when not an IP.
 * The IPv6 /48 is display-only context (originNetworks / candidateNetworks): a
 * /48 is far too large to sweep, so cliSuggestion emits exact IPv6 addresses.
 */
function networkCidr(ip) {
  const parsed = parseIP(ip);
  if (!parsed) return null;
  const prefix = parsed.version === 4 ? 24 : 48;
  const bits = parsed.version === 4 ? 32 : 128;
  const mask = ((1n << BigInt(bits)) - 1n) ^ ((1n << BigInt(bits - prefix)) - 1n);
  return `${formatIP(parsed.value & mask, parsed.version)}/${prefix}`;
}

/** A public, non-CDN address is a plausible origin (never a proxy / WAF edge). */
function isOriginIp(ip) {
  const norm = normalizeIP(ip);
  if (!norm || isPrivateIP(norm)) return false;
  const provider = matchProviderByIP(norm);
  return !(provider && provider.hidesOrigin);
}

/** Provider id of an address (netinfo PROVIDERS), or null. */
function providerIdOf(ip) {
  const p = matchProviderByIP(ip);
  return p ? p.id : null;
}

/**
 * Is a resolution indistinguishable from the parent's wildcard answer?
 * Handles the three wildcard kinds detectWildcardDeep reports:
 *  - 'CNAME': the first synthesized CNAME target is one of the wildcard's;
 *  - 'A': every address is one of the wildcard's addresses;
 *  - 'NODATA': the name has no address and no CNAME (the zone answers any label
 *    with NOERROR-empty, so a "hit" with nothing in it is just the wildcard).
 * A `variable` wildcard (its answer changed between the random labels or the
 * resolvers: a multivalue pool, GeoDNS, a CDN alias) is matched more loosely,
 * since its sample never holds every value: every address in the same /24 · /48
 * as a wildcard address or at the wildcard's one provider, or a first CNAME
 * target under the same parent as one of the wildcard's (va01 / ie02.ingress.x).
 * A stable wildcard keeps the exact test, so a real host next to it is kept.
 * A `flooded` wildcard (most guesses under it resolved, and so do random
 * labels) matches any answer of its kind: no guess there tells a host apart.
 * A wildcard object without `kind` (legacy) falls back to the combined test.
 */
function isWildcardSuspect(res, wc) {
  if (!wc || !wc.wildcard || !res) return false;
  const hc = res.cnames || [];
  const wcc = wc.cnames || [];
  const ips = [...(res.ipv4 || []), ...(res.ipv6 || [])];
  if (wc.flooded && wc.kind === 'CNAME') return hc.length > 0;
  if (wc.flooded && wc.kind === 'A') return ips.length > 0 && hc.length === 0;
  if (wc.kind === 'CNAME') {
    if (!hc.length) return false;
    const targets = Array.isArray(wc.targets) && wc.targets.length ? wc.targets : wcc.slice(0, 1);
    if (targets.includes(hc[0])) return true;
    const parent = parentOf(hc[0]);
    return !!wc.variable && parent.includes('.') && targets.some((t) => parentOf(t) === parent);
  }
  if (wc.kind === 'A') {
    if (!ips.length) return false;
    const wipList = [...(wc.ipv4 || []), ...(wc.ipv6 || [])];
    const wips = new Set(wipList);
    if (ips.every((ip) => wips.has(ip))) return true;
    if (!wc.variable) return false;
    const nets = new Set(wipList.map(networkCidr).filter(Boolean));
    if (ips.every((ip) => nets.has(networkCidr(ip)))) return true;
    const providers = new Set(wipList.map(providerIdOf));
    return providers.size === 1 && !providers.has(null) && ips.every((ip) => providers.has(providerIdOf(ip)));
  }
  // NODATA look-alike: only a NOERROR-empty answer matches an empty-answer
  // wildcard. An NXDOMAIN / SERVFAIL / transport error is a real non-answer,
  // never a wildcard suspect (guards names the user typed on DNSSEC zones).
  if (wc.kind === 'NODATA') {
    if (res.status !== undefined && res.status !== 'NOERROR') return false;
    if (res.error) return false;
    return ips.length === 0 && hc.length === 0;
  }
  // Legacy wildcard (no kind): compare CNAME target, else addresses.
  if (hc.length || wcc.length) return hc.length > 0 && wcc.length > 0 && hc[0] === wcc[0];
  if (!ips.length) return false;
  const wips = new Set([...(wc.ipv4 || []), ...(wc.ipv6 || [])]);
  return ips.every((ip) => wips.has(ip));
}

/** The CNAME chain and the IPv4 addresses of an A {@link DnsResponse} for `name`. */
function aAnswer(res, name) {
  const { cnames } = followCnames(res.answers, name);
  const owners = new Set([name, ...cnames]);
  const ipv4 = [...new Set(res.answers
    .filter((rr) => rr.type === 'A' && owners.has(rr.name))
    .map((rr) => normalizeIP(rr.data))
    .filter(Boolean))];
  return { cnames, ipv4 };
}

/** Immediate parent zone of a name ('a.b.c' → 'b.c'); '' when it has one label. */
function parentOf(name) {
  const dot = name.indexOf('.');
  return dot === -1 ? '' : name.slice(dot + 1);
}

/**
 * Validate `config.zone` (the zoneorigins.js `zoneScanInput` shape) defensively:
 * the scanner never imports the zone libraries, it takes plain arrays. Names are
 * normalised (invalid ones dropped), `delegations` join the names, proxied
 * entries keep only valid addresses (never a Cloudflare placeholder, never a
 * CDN / WAF edge address) and a host origin the CLI can take (cmdline's host-target
 * rule: no inet_aton numeric form); an entry with neither is dropped.
 * @param {unknown} zone
 * @returns {{ origin: string|null, names: string[], wildcardBases: string[],
 *   proxied: Array<{ name: string, ips: string[], host: string|null }> }|null}
 */
function normalizeZoneInput(zone) {
  if (!zone || typeof zone !== 'object') return null;
  const list = (v) => (Array.isArray(v) ? v : []);
  const host = (raw, opts) => (typeof raw === 'string' ? normalizeHostname(raw, opts) : null);
  const uniq = (arr) => [...new Set(arr.filter(Boolean))];
  const origin = host(zone.origin) || null;
  const names = uniq([...list(zone.names), ...list(zone.delegations)].map((n) => host(n)));
  const wildcardBases = uniq(list(zone.wildcardBases).map((b) => host(b)));
  const proxied = [];
  const seen = new Set();
  for (const p of list(zone.proxied)) {
    if (!p || typeof p !== 'object') continue;
    const name = host(p.name, { allowWildcard: true });
    if (!name || seen.has(name)) continue;
    const ips = uniq(list(p.ips).map((ip) => normalizeIP(String(ip ?? ''))))
      .filter((ip) => !ZONE_PLACEHOLDER_IPS.has(ip) && !(matchProviderByIP(ip) || {}).hidesOrigin);
    const hostTok = typeof p.host === 'string' && !normalizeIP(p.host) ? validateTargets([p.host], { allowHostTargets: true }).valid[0] : null;
    const origHost = hostTok && !parseCidr(hostTok) ? hostTok : null;
    if (!ips.length && !origHost) continue;
    seen.add(name);
    proxied.push({ name, ips, host: origHost || null });
  }
  if (!origin && !names.length && !wildcardBases.length && !proxied.length) return null;
  return { origin, names, wildcardBases, proxied };
}

/**
 * Validate `config.knownOrigins` (lib/originmap.js knownForScan: the workspace's remembered,
 * not stale origins) defensively, as plain data: a name (`*.x` allowed), an address that is no
 * CDN / WAF edge and no Cloudflare placeholder, a port 1-65535 (443 when absent); a wildcard's
 * `except` (the names it does not apply to) as a Set of host names. One entry per name, address
 * and port; at most MAX_KNOWN_ORIGINS.
 * @param {unknown} list
 * @returns {Array<{ name: string, ip: string, port: number, source: string|null, lastConfirmed: string|null, server: string|null }>}
 */
function normalizeKnownOrigins(list) {
  const out = [];
  const seen = new Set();
  const text = (v, max) => (typeof v === 'string' && v ? v.slice(0, max) : null);
  for (const k of Array.isArray(list) ? list.slice(0, MAX_KNOWN_ORIGINS) : []) {
    if (!k || typeof k !== 'object') continue;
    const name = typeof k.name === 'string' ? normalizeHostname(k.name, { allowWildcard: true }) : null;
    const ip = normalizeIP(String(k.ip ?? ''));
    const port = k.port === undefined || k.port === null ? 443 : Number(k.port);
    if (!name || !ip || !Number.isInteger(port) || port < 1 || port > 65535) continue;
    if (ZONE_PLACEHOLDER_IPS.has(ip) || (matchProviderByIP(ip) || {}).hidesOrigin) continue;
    const key = `${name}|${ip}|${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // A wildcard entry's `except`: the names it does not apply to (the origin map masked it for them).
    const except = name.startsWith('*.') && Array.isArray(k.except)
      ? new Set(k.except.slice(0, MAX_KNOWN_ORIGINS).map((n) => (typeof n === 'string' ? normalizeHostname(n) : null)).filter(Boolean)) : null;
    out.push({
      name, ip, port, source: text(k.source, 20), lastConfirmed: text(k.lastConfirmed, 40), server: text(k.server, 80),
      ...(except && except.size ? { except } : {})
    });
  }
  return out;
}

/** The CLI target of a remembered origin: the address on 443, `ip:port` / `[v6]:port` on another port. */
const knownTarget = (k) => (k.port === 443 ? k.ip : k.ip.includes(':') ? `[${k.ip}]:${k.port}` : `${k.ip}:${k.port}`);

/* ------------------------------------------------------------------------ */
/* Wordlist selection                                                        */
/* ------------------------------------------------------------------------ */

// Rank of a level for "degrade to the smallest served" reporting.
const LEVEL_RANK = { small: 0, smart: 1, large: 2, huge: 3 };

/**
 * Normalise a `customWordlist` config value (raw text OR a label array) to a
 * validated, de-duplicated label list, reusing the wordlist parser so the same
 * rules (fragments like `dev.api`, `_`-labels, caps) apply everywhere.
 * @param {string|string[]|undefined|null} input
 * @returns {string[]}
 */
function normalizeCustomLabels(input) {
  if (Array.isArray(input)) return parseCustomWordlist(input.join('\n')).labels;
  if (typeof input === 'string') return parseCustomWordlist(input).labels;
  return [];
}

/** The single, left-most labels of a fragment list (for permutation seeding). */
function singleLabels(fragments) {
  const out = [];
  const seen = new Set();
  for (const frag of fragments) {
    const label = String(frag).split('.')[0];
    if (label && !seen.has(label)) { seen.add(label); out.push(label); }
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* SPF (private, minimal — health.js has the full parser)                   */
/* ------------------------------------------------------------------------ */

function txtStrings(res) {
  if (!res || !res.ok || res.rcode !== 'NOERROR') return [];
  return (res.answers || [])
    .filter((rr) => rr.type === 'TXT')
    .map((rr) => (Array.isArray(rr.data) ? rr.data.join('') : String(rr.data ?? '')));
}

function mxExchanges(res) {
  if (!res || !res.ok || res.rcode !== 'NOERROR') return [];
  return (res.answers || [])
    .filter((rr) => rr.type === 'MX' && rr.data && typeof rr.data.exchange === 'string' && rr.data.exchange !== '.')
    .sort((a, b) => a.data.preference - b.data.preference)
    .slice(0, MAX_MX)
    .map((rr) => ({ exchange: rr.data.exchange, preference: rr.data.preference }));
}

/**
 * Walk an SPF policy (include / redirect, ≤ 5 levels, ≤ 10 DNS-querying
 * terms like RFC 7208 §4.6.4) and collect sender addresses:
 * `nets` from ip4:/ip6: and `hosts` from a / mx mechanisms. Only pass ('+')
 * mechanisms are used; macros are skipped. Entries remember whether the SPF
 * record that listed them belongs to one of the scanned domains (`own`).
 */
async function collectSpf(domain, { dns, signal, isOwn }) {
  const state = { lookups: 0, nets: [], hosts: [], errors: [], visited: new Set() };

  const walk = async (name, depth, path, ownChain) => {
    if (depth > MAX_SPF_DEPTH) {
      state.errors.push(`SPF include depth limit reached at ${name}`);
      return;
    }
    if (state.visited.has(name)) return;
    state.visited.add(name);
    const res = await dns.query(name, 'TXT', { signal });
    const record = txtStrings(res).find((t) => /^v=spf1(\s|$)/i.test(t.trim()));
    if (!record) return;
    const own = ownChain && isOwn(name);
    const where = [...path, name].join(' → ');
    const terms = record.trim().split(/\s+/).slice(1);
    let redirect = null;
    const hasAll = terms.some((t) => /^[+?~-]?all$/i.test(t));
    for (const term of terms) {
      if (term.includes('%')) continue; // macro-expanded terms cannot be evaluated here
      const m = /^([+?~-]?)([a-z][a-z0-9_.-]*)(?:([:=])(.*))?$/i.exec(term);
      if (!m) continue;
      const [, qualifier, rawMech, sep, rawValue = ''] = m;
      const mech = rawMech.toLowerCase();
      if (sep === '=') {
        if (mech === 'redirect') redirect = rawValue.toLowerCase().replace(/\.$/, '');
        continue;
      }
      if (qualifier && qualifier !== '+') continue; // -, ~, ? do not describe permitted senders
      if (mech === 'ip4' || mech === 'ip6') {
        const cidr = parseCidr(rawValue);
        if (cidr) state.nets.push({ text: rawValue, cidr, own, detail: `${where}: ${mech}:${rawValue}` });
        continue;
      }
      if (mech === 'a' || mech === 'mx' || mech === 'include' || mech === 'exists' || mech === 'ptr') {
        if (state.lookups >= MAX_SPF_LOOKUPS) {
          state.errors.push(`SPF lookup limit (${MAX_SPF_LOOKUPS}) reached`);
          continue;
        }
        state.lookups += 1;
      }
      const target = (rawValue.split('/')[0] || name).toLowerCase().replace(/\.$/, '');
      if (mech === 'a') {
        state.hosts.push({ host: target, own, detail: `${where}: a${rawValue ? `:${rawValue}` : ''}` });
      } else if (mech === 'mx') {
        const mx = await dns.query(target, 'MX', { signal });
        for (const { exchange } of mxExchanges(mx)) {
          state.hosts.push({ host: exchange, own, detail: `${where}: mx${rawValue ? `:${rawValue}` : ''} → ${exchange}` });
        }
      } else if (mech === 'include' && rawValue) {
        await walk(target, depth + 1, [...path, name], own);
      }
    }
    if (redirect && !hasAll) {
      if (state.lookups < MAX_SPF_LOOKUPS) {
        state.lookups += 1;
        await walk(redirect, depth + 1, [...path, name], own);
      } else {
        state.errors.push(`SPF lookup limit (${MAX_SPF_LOOKUPS}) reached`);
      }
    }
  };

  await walk(domain, 0, [], true);
  return state;
}

/* ------------------------------------------------------------------------ */
/* Per-host origin candidates                                               */
/* ------------------------------------------------------------------------ */

/**
 * Fill each proxied host's `originCandidates` (ordered, strongest first) and
 * `candidateNetworks` (the CIDRs of its network candidates), in place. This
 * replaces attaching every origin network to every proxied host.
 *
 * Order: host-specific exact IPs (resolver-leak / history / sibling-domain hints
 * that NAME the host) rank above candidate networks. A network is a candidate for
 * a host when it holds a DNS-only sibling that shares the host's label stem
 * (`ticket` under a sister brand), or the host's parent stem (`db.shop` for a
 * proxied `api.shop`), or it is the main cluster (where most origins sit), or
 * another multi-IP cluster. A lone 1-IP network unrelated to the host (a mail
 * server, a stray cloud VM) is left out as noise.
 *
 * @param {object[]} proxiedHosts hosts that hide their origin (no wildcard suspects)
 * @param {object[]} originNetworks the sorted ScanResult.originNetworks (main cluster first)
 * @param {object[]} originHintList the ScanResult.originHints (reasons carry structured host fields)
 * @param {(name: string) => ({ apex: string, stem: string }|null)} stemUnderApex
 * @param {(stem: string) => (string|null)} parentStem
 */
function assignOriginCandidates(proxiedHosts, originNetworks, originHintList, stemUnderApex, parentStem) {
  if (!proxiedHosts.length) return;
  const mainCidr = originNetworks.length ? originNetworks[0].cidr : null;
  // The member-host stems of each network, and their parent stems (for
  // relatedness scoring: `db.shop` in a network makes it related to a proxied
  // `api.shop`, as does `shop` itself).
  const netStems = new Map();
  const netParents = new Map();
  for (const net of originNetworks) {
    const stems = new Set();
    const parents = new Set();
    for (const name of net.hosts) {
      const info = stemUnderApex(name);
      if (!info) continue;
      stems.add(info.stem);
      const p = parentStem(info.stem);
      if (p) parents.add(p); // never '' (a top-level label would relate every host)
    }
    netStems.set(net.cidr, stems);
    netParents.set(net.cidr, parents);
  }
  // Host-specific exact-IP candidates, grouped by the proxied host they name.
  const exactByHost = new Map();
  for (const hint of originHintList) {
    for (const reason of hint.reasons || []) {
      if (!HOST_SPECIFIC_HINT_KINDS.has(reason.kind) || !reason.host) continue;
      const evidence = reason.kind === 'resolver-leak' ? { resolver: reason.resolver || null }
        : reason.kind === 'history' ? { source: reason.source || null, lastSeen: reason.lastSeen || null }
          : reason.kind === 'zone' ? { source: 'zone' }
            : reason.kind === 'known' ? { port: reason.port, source: reason.source || null, lastConfirmed: reason.lastConfirmed || null }
              : { sibling: reason.sibling || null };
      let list = exactByHost.get(reason.host);
      if (!list) exactByHost.set(reason.host, (list = []));
      // One candidate per IP: an address named by two kinds (zone file + sibling
      // match, leak + history) keeps only its strongest evidence, never two rows.
      const score = CANDIDATE_SCORE[reason.kind] || 0;
      const at = list.findIndex((e) => e.ip === hint.ip);
      if (at === -1) list.push({ ip: hint.ip, kind: reason.kind, score, evidence });
      else if (score > list[at].score) list[at] = { ip: hint.ip, kind: reason.kind, score, evidence };
    }
  }
  for (const host of proxiedHosts) {
    const info = stemUnderApex(host.name);
    const stem = info ? info.stem : null;
    const parent = stem !== null ? parentStem(stem) : null;
    const exact = (exactByHost.get(host.name) || []).slice()
      .sort((a, b) => b.score - a.score || compareIp(a.ip, b.ip));
    const nets = [];
    for (const net of originNetworks) {
      const stems = netStems.get(net.cidr) || new Set();
      const parents = netParents.get(net.cidr) || new Set();
      let relation = null;
      let score = 0;
      if (stem !== null && stems.has(stem)) { relation = 'sibling-label'; score = CANDIDATE_SCORE['net-sibling']; }
      else if (parent !== null && parent !== '' && (stems.has(parent) || parents.has(parent))) {
        relation = 'related-parent'; score = CANDIDATE_SCORE['net-related'];
      }
      else if (net.cidr === mainCidr) { relation = 'main-cluster'; score = CANDIDATE_SCORE['net-main']; }
      else if (net.ips.length >= 2) { relation = 'cluster'; score = CANDIDATE_SCORE['net-cluster']; }
      else continue; // a lone 1-IP network unrelated to this host: noise
      nets.push({ cidr: net.cidr, kind: 'network', score, evidence: { relation, ips: net.ips.length, sweep: net.sweep, shared: !!net.shared } });
    }
    nets.sort((a, b) => b.score - a.score || b.evidence.ips - a.evidence.ips || compareIp(a.cidr, b.cidr));
    // Noise cap: host-related networks and the main cluster are always kept; the
    // weakest band (clusters unrelated to this host) keeps only its largest few,
    // so a big estate does not list every cluster under every proxied host.
    let clusters = 0;
    const kept = nets.filter((n) => n.evidence.relation !== 'cluster' || (clusters += 1) <= MAX_CLUSTER_CANDIDATES);
    host.originCandidates = [...exact, ...kept];
    host.candidateNetworks = kept.map((n) => n.cidr);
  }
}

/* ------------------------------------------------------------------------ */
/* Scan                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Run a full scan.
 *
 * Pipeline (stages reported in execution order; skipped stages are still
 * reported with `{ skipped: true }`):
 *  1. `sources` — passive sources per registrable domain, in parallel with…
 *  2. `mining` — mineDnsNames(): in-domain hosts referenced by the zone's own
 *     records (MX, NS, SOA, SPF, DMARC, SRV, CNAME, CAA, HTTPS).
 *  3. `wildcard` — deep wildcard detection (detectWildcardDeep, NODATA/CNAME
 *     aware) at every level that hosts a discovered name, plus the apex and each
 *     certificate wildcard base.
 *  4. `bruteforce` — courteous A-only wordlist sweep (balance mode) under the
 *     apex and each certificate wildcard base; wildcard look-alikes dropped.
 *  5. `permutations` — alterx/dnsgen-style variants of everything found so far
 *     (env / number / region / sibling; every level above a candidate is
 *     wildcard-checked first), then one recursive wordlist round under
 *     discovered parents that already have children.
 *  6. `resolve` — resolve every surviving name (A + AAAA; streamed via `onHost`).
 *  7. `hints` — origin hints for hosts hidden behind a CDN, all DNS-only and
 *     cheap: SPF / MX / non-proxied siblings / historical IPs, plus (v2)
 *     resolver-leak (proxied hosts re-resolved through other resolvers) and
 *     same-network (origin /24·/48 clusters → `originNetworks`, `cliSuggestion`).
 *  8. `done`.
 *
 * @param {object} config
 * @param {string[]|string} [config.domains] target domains (default: registrable domains of the cert / extra names)
 * @param {object|null} [config.cert] x509 Certificate (uses `hostnames`, `serialHex`)
 * @param {object[]|null} [config.certs] extension (SSL Targets with several certificates,
 *   lib/certsets.js): every certificate of the renewal. Their names seed the scan like `cert`'s,
 *   a host is covered when any of them covers it, and a CT certificate matches when its serial is
 *   any of theirs. `cert` stays the first of them; without `certs` a run is unchanged.
 * @param {string[]|string} [config.extraNames] additional hostnames ('*.x' allowed)
 * @param {string[]} [config.sources] source ids (default: every defaultEnabled source; [] = none)
 * @param {boolean} [config.includeExpired=false]
 * @param {'off'|'small'|'medium'|'smart'|'large'|'huge'} [config.bruteforce='smart'] wordlist level (default 'smart')
 * @param {boolean} [config.mine=true] mine in-domain names from the zone's own DNS records
 * @param {number} [config.permutationBudget=1500] permutation candidate cap (0 disables permutations)
 * @param {boolean} [config.recursive=true] run one recursive wordlist round under discovered parents
 * @param {object[]} [config.inventory] Server[] (or a parseInventory() result)
 * @param {boolean} [config.originHints=true]
 * @param {object} config.dns DohClient
 * @param {typeof fetch} [config.fetchImpl]
 * @param {AbortSignal} [config.signal]
 * @param {string[]} [config.wordlist] extension: custom brute-force labels (REPLACES the level's
 *   list entirely, incl. locale packs / learned / custom — kept for tests and power users)
 * @param {string[]|string} [config.customWordlist] extension: user labels or raw text tried FIRST
 *   (before learned), then the level's list; unlike `wordlist` it adds rather than replaces. A pasted
 *   full hostname under a scanned zone (`api.example.com`) is used as its label (`api`) there and
 *   skipped under the other zones. Hosts only this list uncovered are flagged `customOnly`
 * @param {string[]} [config.learnedLabels] extension: labels from earlier scans (learned.js), tried
 *   after custom and before the level's list
 * @param {string[]} [config.locales] extension: locale-pack codes for the wordlist; undefined = auto
 *   per domain (from its TLD), [] = none, an explicit list = exactly those packs
 * @param {boolean} [config.balance=true] extension: use DohClient balance mode for bulk A-only probes
 * @param {boolean} [config.resolverLeak=true] extension: re-resolve proxied hosts through other resolvers (origin hint)
 * @param {number} [config.recursiveParents=8] extension: max parents in the recursive round
 * @param {number} [config.maxHosts=20000] extension: cap on resolved names
 * @param {number} [config.concurrency=32] extension: names in flight for the final resolve
 * @param {number} [config.maxConcurrency] extension: the user's Settings ceiling; caps both the
 *   final-resolve pool and the bulk-sweep raise (min(PROBE_CONCURRENCY, maxConcurrency))
 * @param {number} [config.sourceGraceMs=12000] extension: max wait for the passive sources
 *   before the DNS sweep starts (late source names are merged before resolve); 0 = wait fully
 * @param {boolean} [config.wordlistPreferFetch=false] extension (tests): load the wordlist data
 *   files through `fetchImpl` even under Node (the browser path; see loadWordlist `preferFetch`)
 * @param {object|null} [config.zone=null] extension (zone import): the zoneorigins.js
 *   `zoneScanInput` shape `{ v, origin, names, wildcardBases, delegations?, proxied: [{ name, ips, host }] }`,
 *   validated here. Zone names (and delegations) are seeds with origin 'zone' (never truncated;
 *   outside every scope root → dropped, one ZONE_OUT_OF_SCOPE warning); a zone wildcard base is
 *   seeded and wildcard-checked but never brute-forced; with no `domains` the zone origin is the
 *   target. Each proxied name's exact origin becomes a host-specific hint `{ kind: 'zone', host }`
 *   (even with `originHints` off: it costs no query), skips the resolver-leak pass, matches its
 *   inventory server as `via: 'zone'` (counts toward needsCert) and goes into the CLI command as
 *   exact addresses (private ones kept, never widened to a /24) plus host targets
 *   (`cliHostTargets`) and the proxied names (`*.x` kept). A run without it is unchanged.
 * @param {object[]|null} [config.knownOrigins=null] extension (origin map): the workspace's
 *   remembered, not stale origins `[{ name, ip, port, source?, lastConfirmed?, server? }]`
 *   (lib/originmap.js knownForScan), validated here. A proxied host with one (its own name, or a
 *   `*.parent` entry) gets a host-specific hint `{ kind: 'known', host, port, source,
 *   lastConfirmed }` that ranks above every other candidate (even with `originHints` off: it costs
 *   no query), skips the resolver-leak pass, matches its inventory server as `via: 'known'`
 *   (counts toward needsCert) and goes into the CLI command exactly (`ip`, or `ip:port` on
 *   another port; never widened to a /24). `result.known` says what was used; a run without the
 *   option has no `known` key.
 * @param {boolean} [config.exact=false] extension (zone import): resolve the given names only —
 *   no passive sources, no DNS mining, no wordlist, no permutations, no recursive round and no
 *   wildcard detection (the zone names are authoritative, so never wildcard suspects). Quota-free.
 * @param {object} [hooks] { onStage(stage, info), onSource(result), onHost(record),
 *   onProgress({ stage, done, total }), onFound(partial) }. `onFound` streams a
 *   probe hit the instant it resolves during the wordlist / permutation / recursive
 *   stages — `{ name, origin, status, ipv4, cnames, classification }`, a cheap A-only
 *   partial, not the final HostRecord — so the table can fill live; the same host
 *   arrives again as a full record through `onHost` at the resolve stage, so a
 *   consumer dedupes by name. Hook errors never break the scan.
 * @returns {Promise<object>} ScanResult
 */
export async function runScan(config = {}, hooks = {}) {
  const {
    domains = [], cert = null, certs = null, extraNames = [], sources, includeExpired = false,
    bruteforce = 'smart', mine = true, permutationBudget = DEFAULT_PERMUTATION_BUDGET, recursive = true,
    inventory = [], originHints = true, dns, fetchImpl = globalThis.fetch, signal,
    wordlist = null, customWordlist = null, learnedLabels = null, locales,
    balance = true, recursiveParents = DEFAULT_RECURSIVE_PARENTS,
    resolverLeak = true, maxHosts = 20000, concurrency = 32, maxConcurrency,
    sourceGraceMs = DEFAULT_SOURCE_GRACE_MS, wordlistPreferFetch = false,
    zone = null, exact = false, knownOrigins = null
  } = config || {};
  if (!dns || typeof dns.query !== 'function' || typeof dns.resolveHost !== 'function' || typeof dns.detectWildcard !== 'function') {
    throw new TypeError('runScan: config.dns must be a DohClient');
  }
  checkAbort(signal);
  const h = hooks || {};
  const startedAt = new Date();
  const t0 = Date.now();
  const warnings = [];
  const stage = (name, info = {}) => safeCall(h.onStage, name, info);
  const progress = (name, done, total) => safeCall(h.onProgress, { stage: name, done, total });
  // maxConcurrency (the user's Settings value) caps the whole scan; concurrency
  // is the requested final-resolve pool, itself never above that ceiling.
  const maxConc = Number.isFinite(maxConcurrency) && maxConcurrency > 0 ? Math.floor(maxConcurrency) : null;
  const pool = Math.max(1, Math.min(Math.floor(Number(concurrency)) || 32, maxConc ?? Infinity));
  const probePool = Math.max(1, Math.min(pool, PROBE_CONCURRENCY, maxConc ?? Infinity));
  const useBalance = balance !== false;
  // Exact mode (zone import): resolve the given names only — no guessing, no
  // passive sources, no mining (quota-free; the names are the user's own zone).
  const exactMode = exact === true;
  const zoneIn = normalizeZoneInput(zone);
  // The workspace's origin map: null when the option was not given at all, so such a run is unchanged.
  const knownIn = knownOrigins === null || knownOrigins === undefined ? null : normalizeKnownOrigins(knownOrigins);
  const bfMode = exactMode ? 'off' : bruteforce === undefined || bruteforce === null ? 'smart' : String(bruteforce);
  const permBudget = !exactMode && Number.isFinite(permutationBudget) && permutationBudget > 0
    ? Math.min(Math.floor(permutationBudget), MAX_PERMUTATIONS) : 0;
  const recursiveEnabled = !exactMode && recursive !== false && recursive !== 0;
  const recursiveCap = Math.max(0, Math.floor(Number(recursiveParents)) || 0);

  /* ---- wordlist inputs (custom → learned → level list) ------------------ */
  // `config.wordlist` (legacy) REPLACES everything; otherwise custom labels are
  // tried first, then learned labels, then the level's list (small / locale
  // packs / base / larger tiers, assembled per apex by loadWordlist).
  const overrideWords = !exactMode && Array.isArray(wordlist) && wordlist.length ? wordlist : null;
  const customLabels = overrideWords || exactMode ? [] : normalizeCustomLabels(customWordlist);
  const customSet = new Set(customLabels);
  // Learned labels come from OTHER scans, so they are never sent at level 'off'
  // (not even through permutations or the recursive round); only this scan's
  // own custom list may still feed those stages there.
  const learnedList = overrideWords || !Array.isArray(learnedLabels) || bfMode === 'off'
    ? [] : normalizeCustomLabels(learnedLabels).filter((l) => !customSet.has(l));
  const learnedSet = new Set(learnedList);
  // Ordered `extra` for loadWordlist: custom first, then learned.
  const extraLabels = [...customLabels, ...learnedList];
  // Permutations also seed from the learned / custom vocabulary: their single
  // labels join the sibling-swap word set, so a discovered `api.x` can be
  // mutated toward a label the user's estate is known to use. Undefined keeps
  // permute.js's built-in default set.
  const permWords = (customLabels.length || learnedList.length)
    ? [...new Set([...DEFAULT_WORDS, ...singleLabels(customLabels), ...singleLabels(learnedList)])]
    : undefined;
  // Per-apex locale packs actually applied (auto from TLD, or the explicit list).
  const localesForBase = (base) => (Array.isArray(locales)
    ? locales.filter((cc) => LOCALE_PACK_CODES.includes(cc))
    : localesForDomain(base));
  // Track a silent wordlist downgrade (e.g. the .gz tier failed to fetch /
  // decompress) so result.options reports the level actually served (the
  // smallest across apexes) and one warning is surfaced, instead of claiming a
  // large sweep that never ran.
  let servedBf = bfMode;
  const degradePairs = new Set();
  // (A locale pack that fails to load is tracked per list in wordsForBase, so it
  // is reported as NOT applied instead of being claimed from the config.)
  const loadOpts = {
    fetchImpl,
    signal,
    preferFetch: wordlistPreferFetch === true,
    onInfo: (info) => {
      if (info && info.type === 'degrade') {
        if ((LEVEL_RANK[info.served] ?? 0) < (LEVEL_RANK[servedBf] ?? 99)) servedBf = info.served;
        degradePairs.add(`${info.requested}→${info.served}`);
      }
    }
  };

  /* ---- seeds ----------------------------------------------------------- */
  const origins = new Map();
  const addName = (name, origin) => {
    let set = origins.get(name);
    if (!set) {
      set = new Set();
      origins.set(name, set);
    }
    set.add(origin);
  };
  const wildcardBases = new Set();
  const seed = (raw, origin) => {
    const n = normalizeHostname(String(raw ?? ''), { allowWildcard: true });
    if (!n) return false;
    const { base, wildcard } = stripWildcard(n);
    // `*.com.tr` / `*.github.io`: a wildcard on a public suffix names no single
    // organisation — never brute-forced, never a scope root (that would pull
    // every source name under the suffix into scope).
    if (wildcard && isPublicSuffix(base)) {
      if (!warnings.some((w) => w.code === 'PUBLIC_SUFFIX' && w.detail === base)) {
        warnings.push({ code: 'PUBLIC_SUFFIX', detail: base });
      }
      return true;
    }
    addName(base, origin);
    if (wildcard) wildcardBases.add(base);
    return true;
  };

  // Every certificate of a renewal (`certs`); a plain run has `cert` alone.
  const certList = [...new Set([cert, ...(Array.isArray(certs) ? certs : [])].filter(Boolean))];
  const hasCert = certList.length > 0;
  const certHostnames = [...new Set(certList.flatMap((c) => (Array.isArray(c.hostnames) ? c.hostnames : [])))];
  for (const name of certHostnames) seed(name, 'cert');
  const extras = Array.isArray(extraNames) ? extraNames : splitList(extraNames);
  for (const name of extras) {
    if (!seed(name, 'input')) warnings.push({ code: 'INVALID_NAME', detail: String(name) });
  }

  const targetDomains = [];
  const pushTarget = (base) => {
    if (isPublicSuffix(base)) {
      if (!warnings.some((w) => w.code === 'PUBLIC_SUFFIX' && w.detail === base)) {
        warnings.push({ code: 'PUBLIC_SUFFIX', detail: base });
      }
      return;
    }
    if (!targetDomains.includes(base)) targetDomains.push(base);
  };
  for (const raw of Array.isArray(domains) ? domains : splitList(domains)) {
    const n = normalizeHostname(String(raw ?? ''), { allowWildcard: true });
    if (!n) {
      warnings.push({ code: 'INVALID_DOMAIN', detail: String(raw) });
      continue;
    }
    pushTarget(stripWildcard(n).base);
  }
  const domainsGiven = targetDomains.length > 0;
  if (!targetDomains.length) {
    for (const d of baseDomainsFromNames([...certHostnames, ...extras])) pushTarget(d);
  }
  // Zone import with no typed domain: the zone's own origin is the target (or,
  // without a valid origin, the registrable domains of its names).
  if (zoneIn && !domainsGiven) {
    if (zoneIn.origin) pushTarget(zoneIn.origin);
    else for (const d of baseDomainsFromNames([...zoneIn.names, ...zoneIn.proxied.map((p) => p.name)])) pushTarget(d);
  }
  if (!targetDomains.length && !origins.size) {
    throw new TypeError('runScan: nothing to scan (no valid domain, certificate name or extra name)');
  }
  for (const d of targetDomains) addName(d, 'input');

  // Zone seeds (origin 'zone'): only names under a scanned root; the rest are
  // dropped and counted (one ZONE_OUT_OF_SCOPE warning). A zone wildcard base
  // (`*.apps` → apps) is seeded and becomes a scope root for wildcard detection,
  // but never a brute-force base nor a certificate wildcard base (critic A4).
  const zoneSeedNames = new Set();
  const zoneWildcardRoots = [];
  let zoneOutOfScope = 0;
  if (zoneIn) {
    const roots = [...targetDomains, ...wildcardBases];
    const underRoot = (n) => roots.some((root) => isSubdomainOf(n, root));
    for (const n of zoneIn.names) {
      if (!underRoot(n)) { zoneOutOfScope += 1; continue; }
      addName(n, 'zone');
      zoneSeedNames.add(n);
    }
    for (const b of zoneIn.wildcardBases) {
      if (!underRoot(b)) { zoneOutOfScope += 1; continue; }
      addName(b, 'zone');
      zoneSeedNames.add(b);
      if (!zoneWildcardRoots.includes(b)) zoneWildcardRoots.push(b);
    }
    if (zoneOutOfScope) warnings.push({ code: 'ZONE_OUT_OF_SCOPE', detail: String(zoneOutOfScope) });
  }

  const sourceDomains = [...new Set(targetDomains.map((d) => registrableDomain(d) || d))];
  const scopeRoots = [...new Set([...targetDomains, ...wildcardBases, ...zoneWildcardRoots])];
  const inScope = (name) => scopeRoots.some((root) => isSubdomainOf(name, root));
  const isOwn = (name) => [...sourceDomains, ...scopeRoots].some((root) => isSubdomainOf(name, root));
  // Wordlist entries may be pasted FULL hostnames (`api.example.com`, copied from
  // another tool). Under a base they end with, only the part left of the base is
  // used (`api` → api.example.com, never api.example.com.example.com); an entry
  // that names the base itself or a DIFFERENT scanned zone is skipped there
  // (never api.a.com.b.com). Plain labels / fragments (`dev.api`) pass unchanged.
  const zoneRoots = [...new Set([...scopeRoots, ...sourceDomains])];
  const relativeEntry = (entry, base) => {
    if (!entry.includes('.')) return entry;
    if (entry === base) return null;
    if (entry.endsWith(`.${base}`)) return entry.slice(0, entry.length - base.length - 1);
    for (const root of zoneRoots) if (entry === root || entry.endsWith(`.${root}`)) return null;
    return entry;
  };

  const servers = Array.isArray(inventory) ? inventory : inventory && Array.isArray(inventory.servers) ? inventory.servers : [];
  const ipIndex = buildIpIndex(servers);

  /* ---- passive sources ∥ DNS record mining ------------------------------ */
  const sourceIds = exactMode ? []
    : Array.isArray(sources) ? [...new Set(sources)] : SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
  const sourceTotal = sourceIds.length * sourceDomains.length;
  const sourceResults = [];
  const hintsByName = new Map();
  const lastSeenByName = {};
  let certsAll = [];
  // How many (source, domain) results each source id has produced so far. A source
  // is "still running" while its count is below the number of source domains. Used
  // to report honestly which passive sources were cut by the grace window (task 6):
  // the sources keep fetching after the DNS sweep starts, so a source pill going
  // green early must not claim the source finished (crt.sh can back off for minutes).
  const sourceDoneCount = new Map(sourceIds.map((id) => [id, 0]));
  const sourcesStillRunning = () => sourceIds.filter((id) => (sourceDoneCount.get(id) || 0) < sourceDomains.length);

  // Ingest one source's result as soon as it arrives, so the names it found are
  // in `origins` even if a slower source (crt.sh) is still backing off.
  const ingestSource = (r) => {
    for (const n of r.names) if (inScope(n)) addName(n, r.source);
    for (const hint of r.ipHints || []) {
      if (!inScope(hint.name)) continue;
      if (!hintsByName.has(hint.name)) hintsByName.set(hint.name, []);
      hintsByName.get(hint.name).push(hint);
    }
    for (const [n, day] of Object.entries(r.lastSeen || {})) {
      if (inScope(n) && (!lastSeenByName[n] || day > lastSeenByName[n])) lastSeenByName[n] = day;
    }
    if (Array.isArray(r.certs) && r.certs.length) certsAll = certsAll.concat(r.certs);
  };
  const runSources = async () => {
    if (sourceTotal <= 0) return;
    let done = 0;
    // Cap how many domains hit the passive sources at once. A multi-domain scan
    // (e.g. a SAN certificate covering 20 registrable domains) must not fire 20
    // concurrent crt.sh / Cert Spotter / HackerTarget calls and burn their free
    // per-IP quotas in one click; per-source courtesy pacing is per domain.
    const perDomain = new Array(sourceDomains.length);
    await mapPool(sourceDomains, SOURCE_DOMAIN_CONCURRENCY, async (d, i) => {
      perDomain[i] = await fetchAllSources(d, {
        sources: sourceIds,
        fetchImpl,
        signal,
        includeExpired,
        onResult: (r) => {
          done += 1;
          if (sourceDoneCount.has(r.source)) sourceDoneCount.set(r.source, sourceDoneCount.get(r.source) + 1);
          ingestSource(r); // incremental: names are usable before the slow sources settle
          safeCall(h.onSource, r);
          progress('sources', done, sourceTotal);
        }
      });
    }, signal);
    // Assemble result.sources in deterministic (sourceIds) order for the report.
    for (const out of perDomain) for (const r of out.results) sourceResults.push(r);
  };

  const mineEvidence = [];
  const mineExternal = new Set();
  const mineEnabled = !exactMode && mine !== false;
  // Mining runs concurrently with the sources stage, but its progress must not
  // paint over the still-active 'sources' progress. Buffer the count and only
  // emit 'mining' progress once the 'mining' stage has actually been reported.
  let miningStageShown = false;
  let miningDone = 0;
  const runMining = async () => {
    if (!mineEnabled) return;
    await mapPool(sourceDomains, 4, async (domain) => {
      const out = await mineDnsNames(domain, { dns, signal });
      for (const ev of out.evidence || []) {
        if (!inScope(ev.name)) continue;
        addName(ev.name, `dns-mine:${ev.from}`);
        mineEvidence.push(ev);
      }
      for (const ref of out.externalRefs || []) mineExternal.add(ref);
      miningDone += 1;
      if (miningStageShown) progress('mining', miningDone, sourceDomains.length);
    }, signal);
  };

  // Launch both concurrently. Mining is fast and its names seed the wildcard
  // parents, so wait for it; the passive sources get only a short grace window
  // before the DNS sweep starts (crt.sh's retry backoff must not stall it). The
  // sources keep running and their late names are folded in before the
  // permutation and resolve stages, so the result is still complete.
  stage('sources', { domains: sourceDomains, sources: sourceIds, total: sourceTotal, skipped: sourceTotal === 0 });
  const sourcesTask = runSources();
  const miningTask = runMining();
  sourcesTask.catch(() => {});
  miningTask.catch(() => {});
  await miningTask;
  checkAbort(signal);
  stage('mining', { domains: sourceDomains, total: mineEnabled ? sourceDomains.length : 0, skipped: !mineEnabled });
  miningStageShown = true;
  if (mineEnabled) progress('mining', miningDone, sourceDomains.length);
  const graceMs = Number.isFinite(sourceGraceMs) && sourceGraceMs >= 0 ? Math.floor(sourceGraceMs) : DEFAULT_SOURCE_GRACE_MS;
  // Snapshot of the passive sources when the DNS sweep is about to start: whether
  // the grace window cut them off and which ids were still fetching. The sources
  // keep running and their late names are folded in before the permutation and
  // resolve stages (nothing is lost), but the UI must not paint the grace wait as
  // "reading DNS records" or show a source pill as done while crt.sh still retries.
  let sourceGrace = { graceMs, cutOff: false, stillRunning: [] };
  if (sourceTotal > 0 && graceMs > 0) {
    // Proceed when the sources finish OR the grace timer fires, whichever comes
    // first (the timer is always cleared, so no dangling handle is left behind).
    const cutOff = await new Promise((resolve) => {
      let settled = false;
      const finish = (byTimer) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', onAbort);
        resolve(byTimer === true);
      };
      const timer = setTimeout(() => finish(true), graceMs);
      const onAbort = () => finish(false);
      sourcesTask.then(() => finish(false), () => finish(false));
      if (signal) signal.addEventListener('abort', onAbort, { once: true });
    });
    const running = sourcesStillRunning();
    sourceGrace = { graceMs, cutOff: cutOff && running.length > 0, stillRunning: running };
  } else {
    await sourcesTask;
  }
  checkAbort(signal);

  const wildcards = {};
  // Resolvers whose breaker is currently open would only time out — skip them.
  const downResolvers = () => {
    try {
      const byResolver = (typeof dns.stats === 'function' ? dns.stats().byResolver : null) || {};
      return new Set(Object.keys(byResolver).filter((id) => byResolver[id] && byResolver[id].down));
    } catch { return new Set(); }
  };
  // The bulk probes and the resolve stage rotate across the balance pool, and a
  // wildcard may answer each resolver differently (GeoDNS / ECS, a CDN alias):
  // each wildcard check also probes every pool resolver that is up, so the
  // fingerprint holds what any of them answers.
  const wildcardResolvers = useBalance && Array.isArray(dns.balancePool) ? dns.balancePool : [];
  const wildcardOpts = () => {
    const down = downResolvers();
    return { signal, resolvers: wildcardResolvers.filter((id) => !down.has(id)) };
  };
  /**
   * Deep-detect wildcards for a set of candidate parents not seen yet, in scope,
   * capped at MAX_WILDCARD_PARENTS. Reused for the catch-up passes (late source
   * names, permutation parents) so probes are never run under an unchecked parent.
   */
  const ensureWildcards = async (candidateParents) => {
    if (exactMode) return; // exact mode sends no probe, so no parent needs a check
    const todo = [];
    const seen = new Set();
    for (const p of candidateParents) {
      if (!p || !p.includes('.') || (p in wildcards) || seen.has(p)) continue;
      if (!scopeRoots.some((root) => p === root || isSubdomainOf(p, root))) continue;
      seen.add(p);
      todo.push(p);
      if (todo.length >= MAX_WILDCARD_PARENTS) break;
    }
    if (!todo.length) return;
    await mapPool(todo, 4, async (p) => {
      wildcards[p] = await detectWildcardDeep(dns, p, wildcardOpts());
    }, signal);
  };

  /* ---- deep wildcard detection (per parent level) ----------------------- */
  const wildcardParents = new Set(scopeRoots);
  for (const name of origins.keys()) {
    if (!inScope(name)) continue;
    const parent = parentOf(name);
    if (parent && parent.includes('.') && scopeRoots.some((root) => isSubdomainOf(parent, root))) wildcardParents.add(parent);
  }
  let parents = exactMode ? [] : sortHostnames([...wildcardParents]);
  if (parents.length > MAX_WILDCARD_PARENTS) {
    // keep the apex + certificate bases and the shallowest levels first
    const priority = new Set(scopeRoots);
    const kept = parents.filter((p) => priority.has(p));
    const rest = parents.filter((p) => !priority.has(p)).sort((a, b) => a.split('.').length - b.split('.').length);
    parents = sortHostnames([...kept, ...rest].slice(0, MAX_WILDCARD_PARENTS));
    warnings.push({ code: 'WILDCARD_PARENTS_TRUNCATED', detail: String(MAX_WILDCARD_PARENTS) });
  }

  let wildcardDone = 0;
  // The wildcard stage starts exactly when the source grace window ends, so its
  // event carries the source snapshot: the UI can show "still fetching: crt.sh"
  // instead of attributing the grace wait to mining (task 6). `stillRunning` is []
  // when every source settled inside the window.
  stage('wildcard', {
    parents, total: parents.length, sourcesStillRunning: sourceGrace.stillRunning, sourcesCutOff: sourceGrace.cutOff,
    ...(exactMode ? { skipped: true } : {})
  });
  await mapPool(parents, 4, async (p) => {
    wildcards[p] = await detectWildcardDeep(dns, p, wildcardOpts());
    wildcardDone += 1;
    progress('wildcard', wildcardDone, parents.length);
  }, signal);
  checkAbort(signal);
  /**
   * The wildcard that can synthesize `name`, walking its ancestors nearest first.
   * The first checked one decides (RFC 4592 closest encloser): its wildcard
   * applies; a conclusive "no wildcard" means that level exists, so no farther
   * `*` can synthesize anything below it. An inconclusive check (failed probes)
   * is skipped, so a farther wildcard still applies as the safe fallback.
   */
  const nearestWildcard = (name) => {
    for (let p = parentOf(name); p; p = parentOf(p)) {
      const w = Object.prototype.hasOwnProperty.call(wildcards, p) ? wildcards[p] : null;
      if (!w) continue;
      if (w.wildcard) return w;
      if (w.conclusive) return null;
    }
    return null;
  };

  /* ---- shared A-only probe (wordlist / permutation / recursive) --------- */
  /**
   * Probe candidate names with a single A query each (balance mode), keep the
   * ones that answer (addresses, or a CNAME chain — a dangling alias answers
   * NXDOMAIN with its chain) and are not wildcard look-alikes. Courteous concurrency
   * with an adaptive back-off when the resolver pool starts erroring.
   */
  // Set once every probe has failed for a long run: the DoH pool is unreachable.
  let dnsUnreachable = false;
  // Cap each balance probe short with no retry pass: failover to the other pool
  // members already covers a slow / dropped resolver, so one black-holed member
  // never stalls the sweep for the client's full timeout.
  const probeOpts = useBalance
    ? { signal, balance: true, timeoutMs: PROBE_TIMEOUT_MS, retries: 0 }
    : { signal, balance: false };
  // Every name already sent as a bulk A probe. A later stage (permutations,
  // recursive) never re-sends one: a brute-force miss re-queued as a sibling swap
  // or a level insertion would only spend budget re-asking for an NXDOMAIN (the
  // client's LRU is long flushed by a big sweep), so the budget goes to new names.
  const probed = new Set();
  // Flood guard: answered probes and hits per parent. A parent where most
  // guesses "resolve" holds a wildcard the check did not pin down (its answer
  // varies more than the sample showed, or the check failed). It is re-sampled
  // once, wider; if random labels resolve to values the first check had not seen
  // (or vary with no first check to compare), the wildcard is marked `flooded` and
  // the resolve stage drops the probe-only look-alikes.
  const probeLoad = new Map(); // parent → { tried, found }
  const resampled = new Set();
  const loadOf = (p) => {
    let l = probeLoad.get(p);
    if (!l) { l = { tried: 0, found: 0 }; probeLoad.set(p, l); }
    return l;
  };
  const resampleFlooded = async () => {
    const flooded = [...probeLoad]
      .filter(([p, l]) => !resampled.has(p) && l.tried >= FLOOD_MIN_TRIED && l.found > l.tried * FLOOD_SHARE)
      .map(([p]) => p);
    if (!flooded.length) return;
    await mapPool(flooded, 4, async (p) => {
      resampled.add(p);
      const next = await detectWildcardDeep(dns, p, { ...wildcardOpts(), probes: FLOOD_RESAMPLE_PROBES });
      // Random labels still do not resolve (none, or only NOERROR-empty): the hits stand.
      if (!next.wildcard || next.kind === 'NODATA') return;
      const prev = wildcards[p] && wildcards[p].wildcard && wildcards[p].kind === next.kind ? wildcards[p] : null;
      const union = (key) => [...new Set([...((prev && prev[key]) || []), ...(next[key] || [])])];
      const merged = { ...next, ipv4: union('ipv4'), ipv6: union('ipv6'), targets: union('targets') };
      const size = (w) => (w.ipv4 || []).length + (w.ipv6 || []).length + (w.targets || []).length;
      // Nothing the first check had not seen: the hits differ from it, so they stand (a
      // custom or override list can hold mostly real names).
      if (prev && size(merged) === size(prev)) return;
      // No usable first check (it failed, or the level was never checked) and a stable
      // answer now: that answer is the exact fingerprint, which still tells real hosts apart.
      if (!prev && !next.variable) {
        wildcards[p] = next;
        return;
      }
      wildcards[p] = { ...merged, variable: true, flooded: true };
    }, signal);
  };
  // The in-scope levels above a name (below its scope root) with no wildcard check yet.
  const uncheckedLevels = (name) => {
    const levels = [];
    for (let p = parentOf(name); p && p.includes('.') && !scopeRoots.includes(p); p = parentOf(p)) {
      if (!inScope(p)) break;
      if (!(p in wildcards)) levels.push(p);
    }
    return levels;
  };
  // `checkLevels`: a hit under a level nobody has wildcard-checked (api.dev.x,
  // dev.api.x) is held back until that level is checked, once the sweep is over.
  // Only levels with a hit cost a check, so an environment word that answers
  // nothing under it sends no extra query.
  const probeNames = async (candidates, origin, stageName, baseDone, grandTotal, { checkLevels = false } = {}) => {
    const out = { tried: candidates.length, found: 0, wildcardDropped: 0, errors: 0 };
    const held = [];
    const accept = (name, status, cnames, ipv4) => {
      if (isWildcardSuspect({ status, cnames, ipv4, ipv6: [] }, nearestWildcard(name))) {
        out.wildcardDropped += 1;
        return;
      }
      addName(name, origin);
      out.found += 1;
      loadOf(parentOf(name)).found += 1;
      // Stream the hit the moment it resolves (task 5) so the UI can show rows
      // live through the long wordlist / permutation stages instead of an empty
      // table until the resolve stage. This is a cheap PARTIAL — the A answer
      // only (AAAA is fetched in the resolve stage), classified from that A
      // record — never the final HostRecord; onHost still fires per host during
      // resolve with the full record, so a consumer must dedupe by name.
      safeCall(h.onFound, {
        name,
        origin,
        status,
        ipv4: [...ipv4],
        cnames: [...cnames],
        classification: classifyResolution({ status, ipv4, ipv6: [], cnames })
      });
    };
    for (const name of candidates) probed.add(name);
    if (!candidates.length || dnsUnreachable) return out;
    let done = 0;
    let streak = 0;
    await mapPool(candidates, probePool, async (name) => {
      if (dnsUnreachable) return; // the whole DoH pool is unreachable — stop probing
      if (streak >= PROBE_ERR_THRESHOLD) {
        await sleep(Math.min(PROBE_BACKOFF_MAX, PROBE_BACKOFF_STEP * (streak - PROBE_ERR_THRESHOLD + 1)), signal);
      }
      const res = await dns.query(name, 'A', probeOpts);
      // An answer that lands after the user cancelled is dropped: no late
      // onFound row / progress tick once the scan is aborted.
      if (signal && signal.aborted) return;
      done += 1;
      progress(stageName, (baseDone || 0) + done, grandTotal || candidates.length);
      if (!res.ok) {
        out.errors += 1;
        streak += 1;
        // Every probe failing for a long run means the DoH pool is unreachable
        // (blocked DoH, offline): stop the bulk stages instead of firing
        // thousands of doomed requests. resolve / hints still run on what we have.
        if (streak >= PROBE_DEAD_STREAK && !dnsUnreachable) {
          dnsUnreachable = true;
          warnings.push({ code: 'DNS_UNREACHABLE', detail: String(streak) });
        }
        return;
      }
      streak = 0;
      loadOf(parentOf(name)).tried += 1;
      if (res.rcode !== 'NOERROR' && res.rcode !== 'NXDOMAIN') return;
      const { cnames, ipv4 } = aAnswer(res, name);
      // A dangling alias (a CNAME to a target that no longer exists) answers
      // NXDOMAIN with the chain (RFC 6604): a real, takeover-prone name. A plain
      // NXDOMAIN is no such name.
      if (res.rcode === 'NXDOMAIN' && !cnames.length) return;
      if (!ipv4.length && !cnames.length) return; // NODATA / no address — not a real hit
      if (checkLevels && uncheckedLevels(name).length) {
        held.push([name, res.rcode, cnames, ipv4]);
        return;
      }
      accept(name, res.rcode, cnames, ipv4);
    }, signal);
    if (held.length) {
      // Shallowest first, so the cap keeps the environment levels (dev.x before api.dev.x).
      const levels = [...new Set(held.flatMap(([name]) => uncheckedLevels(name)))];
      await ensureWildcards(levels.sort((a, b) => a.split('.').length - b.split('.').length));
      checkAbort(signal);
      for (const hit of held) accept(...hit);
    }
    await resampleFlooded();
    return out;
  };

  /* ---- brute force (wordlist) under apex + certificate wildcard bases ---- */
  const bfBases = sortHostnames([...new Set([...targetDomains, ...wildcardBases])]);
  // Build each base's own label list. `config.wordlist` (legacy) replaces the
  // list for every base; otherwise each apex gets its ordered list from
  // loadWordlist — custom → learned (`extra`) → small → its locale packs → base
  // → the larger tiers — so a Turkish domain quietly gains the `tr` pack while a
  // German one gains `de`, without either being tuned into the product. Lists
  // are cached per (level, locale-set) since the custom/learned prefix is shared.
  const wlByLocaleKey = new Map();
  // list key → locale codes that failed to load for that list: loadWordlist
  // skips such a pack with a 'locale-missing' info; it is then reported as not
  // applied, with a WORDLIST_DEGRADED warning ('locale:<cc>').
  const missingByKey = new Map();
  const listKey = (base) => `${bfMode}|${localesForBase(base).join(',')}`;
  const wordsForBase = async (base) => {
    if (bfMode === 'off' || !bfMode) return [];
    if (overrideWords) return overrideWords;
    if (bfMode === 'medium') return getWordlist('medium');
    if (!KNOWN_LEVELS.has(bfMode)) return [];
    const key = listKey(base);
    if (wlByLocaleKey.has(key)) return wlByLocaleKey.get(key);
    const missing = new Set();
    const list = await loadWordlist(bfMode, {
      ...loadOpts,
      onInfo: (info) => {
        if (info && info.type === 'locale-missing' && info.locale) missing.add(String(info.locale));
        loadOpts.onInfo(info);
      },
      domain: base,
      locales,
      extra: extraLabels
    });
    wlByLocaleKey.set(key, list);
    missingByKey.set(key, missing);
    return list;
  };
  // The locale packs a base's list REALLY contains: requested minus failed loads.
  const localesUsedForBase = (base) => {
    const missing = missingByKey.get(listKey(base));
    return localesForBase(base).filter((cc) => !(missing && missing.has(cc)));
  };
  const baseWords = new Map();
  let maxRank = 0;
  for (const base of bfBases) {
    const list = await wordsForBase(base);
    checkAbort(signal);
    baseWords.set(base, list);
    if (list.length > maxRank) maxRank = list.length;
  }
  const anyWords = [...baseWords.values()].some((l) => l.length > 0);
  // Per-apex cap by level (huge must reach ~130k for one apex); a legacy custom
  // list / 'medium' keeps the old per-base share of LEGACY_MAX_BRUTEFORCE. The
  // custom / learned labels lead every list, so they get room ON TOP of the
  // level's cap: a 6,000-name custom list on Small tries all 6,000 AND the
  // level's own list (www, mail, api …) instead of silently pushing it out.
  // MAX_BRUTEFORCE_TOTAL still bounds the whole sweep.
  const perBaseCap = KNOWN_LEVELS.has(bfMode) && !overrideWords
    ? (MAX_BRUTEFORCE_PER_BASE[bfMode] || LEGACY_MAX_BRUTEFORCE) + extraLabels.length
    : (bfBases.length ? Math.max(1, Math.floor(LEGACY_MAX_BRUTEFORCE / bfBases.length)) : LEGACY_MAX_BRUTEFORCE);
  const bfCandidates = [];
  // candidate → { base, tier: 'custom'|'learned', entry, label } for the custom /
  // learned candidates only (a 'list' candidate has no entry): the per-domain
  // report, the distinct tried / found counts and the customOnly host flag.
  const bfAttribution = new Map();
  if (anyWords) {
    const seen = new Set();
    const perBaseCount = new Map(bfBases.map((p) => [p, 0]));
    const cappedBases = [];
    let bfTruncated = false;
    // Rank-major, round-robin across the bases so a domain listed later is not
    // starved of its top-ranked labels under the shared MAX_BRUTEFORCE_TOTAL
    // ceiling. With a single base this is the plain base×words order.
    outer: for (let rank = 0; rank < maxRank; rank += 1) {
      for (const p of bfBases) {
        const list = baseWords.get(p);
        if (rank >= list.length) continue;
        if (perBaseCount.get(p) >= perBaseCap) {
          // A label is left over under this base: the per-base cap cut the list.
          if (!cappedBases.includes(p)) cappedBases.push(p);
          continue;
        }
        const entry = String(list[rank] ?? '').trim().toLowerCase().replace(/\.+$/, '');
        if (!entry) continue;
        const label = relativeEntry(entry, p);
        if (!label) continue;
        const n = normalizeHostname(`${label}.${p}`);
        if (!n || origins.has(n) || seen.has(n)) continue;
        seen.add(n);
        bfCandidates.push(n);
        const tier = customSet.has(entry) ? 'custom' : learnedSet.has(entry) ? 'learned' : 'list';
        if (tier !== 'list') bfAttribution.set(n, { base: p, tier, entry, label });
        perBaseCount.set(p, perBaseCount.get(p) + 1);
        if (bfCandidates.length >= MAX_BRUTEFORCE_TOTAL) { bfTruncated = true; break outer; }
      }
    }
    if (cappedBases.length) {
      const shown = cappedBases.slice(0, 3).join(', ');
      const more = cappedBases.length > 3 ? ` +${cappedBases.length - 3}` : '';
      warnings.push({ code: 'BRUTEFORCE_TRUNCATED', detail: `${perBaseCap} (${shown}${more})` });
    }
    if (bfTruncated) {
      warnings.push({ code: 'BRUTEFORCE_TRUNCATED', detail: bfBases.length > 1 ? `${MAX_BRUTEFORCE_TOTAL} (${bfBases.length} domains)` : String(MAX_BRUTEFORCE_TOTAL) });
    }
  }
  const missingAll = [...new Set([...missingByKey.values()].flatMap((s) => [...s]))].sort();
  if (degradePairs.size || missingAll.length) {
    const parts = [...degradePairs, ...missingAll.map((cc) => `locale:${cc}`)];
    warnings.push({ code: 'WORDLIST_DEGRADED', detail: parts.join(', ') });
  }
  // Bulk probing (wordlist / permutation / recursive) is the courteous DNS
  // sweep that spreads across the balance pool. The UI's shared client runs at
  // a modest global limit, but a balanced sweep across the healthy resolver
  // pool safely uses more parallelism — each resolver still sees only its share
  // (well under the ~280 qps the slowest tolerates), and per-resolver caching
  // bounds what reaches the target's authoritative servers. Raise the client's
  // limit to PROBE_CONCURRENCY for the sweep and always restore it afterwards.
  const priorConcurrency = typeof dns.concurrency === 'number' ? dns.concurrency : null;
  const raiseSweep = priorConcurrency !== null && priorConcurrency < probePool && typeof dns.setConcurrency === 'function';

  const bf = { tried: 0, found: 0, wildcardDropped: 0, errors: 0 };
  const perm = { tried: 0, found: 0, wildcardDropped: 0, errors: 0 };
  const rec = { tried: 0, found: 0, wildcardDropped: 0, errors: 0 };
  const permStageActive = permBudget > 0 || recursiveEnabled;
  if (raiseSweep) dns.setConcurrency(probePool);
  try {
    stage('bruteforce', { total: bfCandidates.length, words: maxRank, parents: bfBases, skipped: bfCandidates.length === 0 });
    Object.assign(bf, await probeNames(bfCandidates, 'wordlist', 'bruteforce', 0, bfCandidates.length));

    // Fold in names from sources that were still arriving during the grace
    // window (added to `origins` incrementally). Ensure the sources task is
    // done and any new parents are wildcard-checked before the permutation and
    // resolve stages use / flag them, so late names are never lost.
    await sourcesTask;
    checkAbort(signal);
    const lateParents = [];
    for (const name of origins.keys()) {
      if (!inScope(name)) continue;
      const p = parentOf(name);
      if (p && p.includes('.')) lateParents.push(p);
    }
    await ensureWildcards(lateParents);
    checkAbort(signal);

    /* ---- permutations + one recursive round ----------------------------- */
    stage('permutations', { budget: permBudget, recursive: recursiveEnabled, skipped: !permStageActive });

    if (permBudget > 0) {
      const known = new Set(origins.keys());
      const permCandidates = [];
      const seen = new Set();
      for (const domain of targetDomains) {
        const found = [...known].filter((n) => n !== domain && isSubdomainOf(n, domain));
        if (!found.length) continue;
        const remaining = permBudget - permCandidates.length;
        if (remaining <= 0) break;
        // `exclude: probed` — names the brute force already asked for never take
        // a budget slot (permute skips them before counting toward the cap).
        for (const cand of permutations(found, domain, { budget: remaining, words: permWords, exclude: probed })) {
          if (origins.has(cand) || seen.has(cand) || probed.has(cand)) continue;
          seen.add(cand);
          permCandidates.push(cand);
          if (permCandidates.length >= permBudget) break;
        }
        if (permCandidates.length >= permBudget) break;
      }
      // Level-insertion permutations go one level deeper, both ways: under a
      // found parent (dev.api.x, us.api.x) and under a level nobody has seen
      // (api.dev.x, shop.staging.x — an empty non-terminal under a wildcard).
      // Every in-scope level above a hit that was not checked yet is wildcard-
      // checked before the hit counts (checkLevels), so neither a per-host
      // wildcard (*.api.x) nor an environment wildcard (*.dev.x) turns every
      // insertion into a false 'permutation' hit.
      Object.assign(perm, await probeNames(permCandidates, 'permutation', 'permutations', 0, permCandidates.length, { checkLevels: true }));
    }
    checkAbort(signal);

    if (recursiveEnabled && recursiveCap > 0) {
      // Parents we discovered that themselves have discovered children — the old
      // certificate often lives one level deeper (v2.api, stg.panel …).
      const discovered = [...origins.keys()].filter(inScope);
      const discoveredSet = new Set(discovered);
      const childCount = new Map();
      for (const n of discovered) {
        const p = parentOf(n);
        if (p && discoveredSet.has(p) && !targetDomains.includes(p)) childCount.set(p, (childCount.get(p) || 0) + 1);
      }
      const recParents = [...childCount.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].length - b[0].length)
        .slice(0, recursiveCap)
        .map(([p]) => p);
      if (recParents.length) {
        // Deep-detect wildcards for any recursive parent not seen in the wildcard stage.
        await ensureWildcards(recParents);
        checkAbort(signal);
        // Bound the label list and the candidate total: a large custom
        // `config.wordlist` must not multiply 8 parents into a huge probe set
        // (bfCandidates and permutations are capped; this round is too). Seed it
        // from a bounded share of the user's custom / learned vocabulary (custom
        // first), then the WHOLE small core, which that vocabulary can never
        // crowd out (a big learned store would otherwise fill every slot).
        const extraHead = [...new Set([...customLabels, ...learnedList])].slice(0, RECURSIVE_EXTRA_WORDS);
        const small = overrideWords
          ? overrideWords.slice(0, RECURSIVE_MAX_WORDS)
          : [...new Set([...extraHead, ...WORDLIST_SMALL])];
        const recCandidates = [];
        const seen = new Set();
        let recTruncated = false;
        outer: for (const p of recParents) {
          for (const w of small) {
            const entry = String(w ?? '').trim().toLowerCase().replace(/\.+$/, '');
            if (!entry) continue;
            const label = relativeEntry(entry, p);
            if (!label) continue;
            const n = normalizeHostname(`${label}.${p}`);
            if (!n || origins.has(n) || seen.has(n) || probed.has(n)) continue;
            seen.add(n);
            recCandidates.push(n);
            if (recCandidates.length >= RECURSIVE_MAX) { recTruncated = true; break outer; }
          }
        }
        if (recTruncated) warnings.push({ code: 'RECURSIVE_TRUNCATED', detail: String(RECURSIVE_MAX) });
        Object.assign(rec, await probeNames(recCandidates, 'recursive', 'permutations', 0, recCandidates.length));
      }
    }
    checkAbort(signal);
  } finally {
    // Restore only if nothing else changed it in the meantime (the client is
    // shared: a settings change or a second run may have set a new value that
    // must win over our restore).
    if (raiseSweep && typeof dns.concurrency === 'number' && dns.concurrency === probePool) {
      dns.setConcurrency(priorConcurrency);
    }
  }

  /* ---- resolve ---------------------------------------------------------- */
  let names = sortHostnames([...origins.keys()]);
  let truncated = false;
  if (names.length > maxHosts) {
    // Keep what most likely exists: explicitly requested names (input / certificate / zone
    // file), then names DNS itself showed (a wordlist, variation or deeper-round hit, a name
    // mined from the zone's records), then names certificates were issued for (CT logs), then
    // the other passive sources' names — name order within each group, so a flood of dead names
    // from one source cannot push out hosts that resolve.
    names = sortHostnames(names.map((n) => [n, truncationRank(origins.get(n))])
      .sort((a, b) => a[1] - b[1]).slice(0, maxHosts).map(([n]) => n));
    truncated = true;
    warnings.push({ code: 'TRUNCATED', detail: `${origins.size} > ${maxHosts}` });
  }
  stage('resolve', { total: names.length });
  // Found ONLY by a custom-list label that is not built-in core vocabulary: the
  // tab-only custom list is the sole evidence, so the host is never learned
  // (learnedLabelsFromScan). A core label (www, api …) is public, so not flagged.
  // The custom labels also feed the permutation sibling swap and the recursive
  // round (at every level, Off included), so a host only the probe stages found
  // whose left-most labels carry one of this scan's private custom labels
  // (zzx.api from the recursive round, zzx or zzx2 from a permutation) is
  // custom-only too. A wordlist hit needs no such guess: its attribution names
  // the tier, so a core-list 'jenkins' stays public next to a custom 'jenk'.
  const customPrivate = [...new Set(customLabels.flatMap((c) => c.split('.')))].filter((l) => l && !CORE_LABELS.has(l));
  const isCustomOnly = (name, nameOrigins) => {
    if (!nameOrigins.has('wordlist')) {
      return customPrivate.length > 0 && nameOrigins.size > 0 && [...nameOrigins].every((o) => PROBE_ORIGINS.has(o))
        && leftmostLabels(name, targetDomains).some((l) => customPrivate.some((p) => l.includes(p)));
    }
    if (nameOrigins.size !== 1) return false;
    const attr = bfAttribution.get(name);
    if (!attr || attr.tier !== 'custom') return false;
    return !attr.label.split('.').every((l) => CORE_LABELS.has(l));
  };
  const records = new Map();
  const matchesByName = new Map();
  let resolvedDone = 0;
  // Probe-only names dropped at resolve: as wildcard look-alikes, or because
  // they are gone now (a clean NXDOMAIN / empty answer) — never for a failure.
  const droppedProbe = { wordlist: 0, permutation: 0, recursive: 0 };
  const vanishedProbe = { wordlist: 0, permutation: 0, recursive: 0 };
  /**
   * A probe-only name answered its probe but has no answer at resolve. It is
   * gone only on a clean NXDOMAIN; a failure (SERVFAIL, a timeout — or a failed
   * A query hidden behind an empty AAAA answer) is re-asked once on the chain.
   * Returns the resolution to keep (the fresh A answer, or the failure itself so
   * the host is not lost), or null when the name is really gone.
   */
  const recheckProbeHit = async (name, resolution) => {
    if (resolution.status === 'NXDOMAIN' && !resolution.error) return null;
    const again = await dns.query(name, 'A', { signal, noCache: true });
    if (!again.ok || (again.rcode !== 'NOERROR' && again.rcode !== 'NXDOMAIN')) {
      if (resolution.error) return resolution;
      return { ...resolution, status: again.ok ? again.rcode : 'ERROR', error: again.error || again.rcode || 'Query failed', errorKind: again.errorKind || null };
    }
    const { cnames, ipv4 } = aAnswer(again, name);
    if (!ipv4.length && !cnames.length) return null;
    return { ...resolution, status: again.rcode, cnames, ipv4, error: null, errorKind: null };
  };
  await mapPool(names, pool, async (name) => {
    let resolution = await dns.resolveHost(name, { signal, balance: useBalance });
    resolvedDone += 1;
    progress('resolve', resolvedDone, names.length);
    const nameOrigins = origins.get(name);
    const onlyProbe = [...nameOrigins].every((o) => PROBE_ORIGINS.has(o));
    const hasAnswer = resolution.ipv4.length || resolution.ipv6.length || resolution.cnames.length;
    if (onlyProbe && !hasAnswer) {
      resolution = await recheckProbeHit(name, resolution);
      if (!resolution) {
        for (const o of nameOrigins) if (o in vanishedProbe) vanishedProbe[o] += 1;
        return;
      }
    }
    const classification = classifyResolution(resolution);
    // A zone-file name is authoritative: it is a real record even when its
    // answer equals a covering wildcard's.
    const wildcardSuspect = !nameOrigins.has('zone') && isWildcardSuspect(resolution, nearestWildcard(name));
    if (onlyProbe && wildcardSuspect) {
      for (const o of nameOrigins) if (o in droppedProbe) droppedProbe[o] += 1;
      return;
    }
    const matches = lookupServers([...resolution.ipv4, ...resolution.ipv6], ipIndex);
    matchesByName.set(name, matches);
    const record = {
      name,
      origins: orderOrigins(nameOrigins),
      resolution,
      classification,
      cert: hasCert ? certCovers(certHostnames, name) : null,
      // `through`: the answer is the server's shared (vip=) or public NAT (nat=) address
      servers: matches.map(({ server, ip, through }) => (through
        ? { serverId: server.id, name: server.name, ip, through } : { serverId: server.id, name: server.name, ip })),
      wildcardSuspect,
      ipHints: hintsByName.get(name) || [],
      candidateNetworks: [],
      originCandidates: [],
      customOnly: isCustomOnly(name, nameOrigins),
      zoneOnly: nameOrigins.has('zone') && [...nameOrigins].every((o) => o === 'zone' || PROBE_ORIGINS.has(o))
    };
    records.set(name, record);
    safeCall(h.onHost, record);
  }, signal);
  const hosts = sortHostnames([...records.keys()]).map((n) => records.get(n));
  checkAbort(signal);

  /* ---- origin hints ----------------------------------------------------- */
  const hintMap = new Map();
  const addHint = (rawIp, reason, { own = true, hostNames = [] } = {}) => {
    const ip = normalizeIP(rawIp);
    if (!ip) return;
    const provider = matchProviderByIP(ip);
    if (provider && provider.hidesOrigin) return; // a CDN / WAF edge is never an origin
    const matches = lookupServers([ip], ipIndex);
    if (!own && !matches.length) return; // third-party infrastructure (e.g. a mail provider)
    let hint = hintMap.get(ip);
    if (!hint) {
      hint = { ip, reasons: [], servers: [], provider: provider || null, hosts: new Set(), historyHosts: new Set() };
      hintMap.set(ip, hint);
    }
    if (!hint.reasons.some((r) => r.kind === reason.kind && r.detail === reason.detail)) hint.reasons.push(reason);
    for (const n of hostNames) {
      hint.hosts.add(n);
      // history / resolver-leak / sibling-domain hints are about one specific
      // proxied name (a host-specific exact origin), not a candidate origin for
      // every proxied host.
      if (HOST_SPECIFIC_HINT_KINDS.has(reason.kind)) hint.historyHosts.add(n);
    }
  };

  const hintsEnabled = originHints !== false;
  // Wildcard suspects only echo their parent's wildcard record, so they are no
  // evidence of a proxied origin: leave them out of the resolver-leak pass (which
  // has a query budget), the candidate networks and the CLI `-n` names.
  const proxiedHosts = hosts.filter((x) => x.classification.hidesOrigin && !x.wildcardSuspect);
  // Zone import: the in-scope proxied zone names and their exact origins. A name
  // the zone already maps skips the resolver-leak pass (its origin is exact).
  const zoneProxied = zoneIn ? zoneIn.proxied.filter((p) => inScope(stripWildcard(p.name).base)) : [];
  const zoneKnown = new Set(zoneProxied.map((p) => p.name));
  // The origin map: each proxied host's remembered origins (its own name first, then a `*.parent`
  // entry covering it). Such a host skips the resolver-leak pass too (its origin is exact).
  const knownByHost = new Map();
  if (knownIn && knownIn.length) {
    const byName = new Map();
    for (const k of knownIn) {
      if (!byName.has(k.name)) byName.set(k.name, []);
      byName.get(k.name).push(k);
    }
    for (const host of proxiedHosts) {
      const dot = host.name.indexOf('.');
      const wild = dot > 0 ? (byName.get(`*.${host.name.slice(dot + 1)}`) || []).filter((k) => !(k.except && k.except.has(host.name))) : [];
      const list = [...(byName.get(host.name) || []), ...wild];
      if (list.length) knownByHost.set(host.name, list);
    }
  }
  const leakHosts = zoneKnown.size || knownByHost.size
    ? proxiedHosts.filter((x) => !zoneKnown.has(x.name) && !knownByHost.has(x.name)) : proxiedHosts;
  // A 'direct' host is origin evidence only if its answer is its own: no CNAME,
  // or a CNAME chain that stays inside the scanned zones, OR one of its IPs
  // matches an inventory server. An in-zone name that CNAMEs out to third-party
  // SaaS (M365 autodiscover → outlook.com, a status page → uptimerobot) is NOT
  // an origin, so its provider's /24 must not be swept with the user's names.
  const answerIsOwned = (host) => {
    const chain = (host.resolution && host.resolution.cnames) || [];
    if (chain.every((c) => isOwn(c))) return true;
    return lookupServers([...host.resolution.ipv4, ...host.resolution.ipv6], ipIndex).length > 0;
  };
  // A host's stem relative to the LONGEST scanned apex it sits under: the labels
  // left of that apex ('' for the apex itself) plus that apex. null when the host
  // is under no scanned apex (another organisation's SAN). Used to match the same
  // left-most name across sibling brands (sibling-domain hint) and to judge how
  // related a candidate network is to a proxied host.
  const stemUnderApex = (name) => {
    let best = null;
    for (const apex of targetDomains) {
      if (name === apex) { if (!best || apex.length > best.apex.length) best = { apex, stem: '' }; continue; }
      if (isSubdomainOf(name, apex) && (!best || apex.length > best.apex.length)) {
        best = { apex, stem: name.slice(0, name.length - apex.length - 1) };
      }
    }
    return best;
  };
  /** The parent stem of a stem ('api.shop' → 'shop', 'shop' → '', '' → null). */
  const parentStem = (stem) => {
    if (stem === '') return null;
    const dot = stem.indexOf('.');
    return dot === -1 ? '' : stem.slice(dot + 1);
  };
  // Determinate hints-stage progress (task 6): the resolver-leak pass (which can
  // be the longest part) plus one unit per SPF/MX zone. The final reconcile below
  // makes the bar reach 100 % even when fewer leak queries actually run.
  const hintZones = hintsEnabled ? [...new Set([...sourceDomains, ...targetDomains])] : [];
  const plannedLeak = hintsEnabled && resolverLeak !== false
    ? Math.min(RESOLVER_LEAK_MAX_QUERIES, leakHosts.length * RESOLVER_LEAK_PER_HOST) : 0;
  const hintsTotal = plannedLeak + hintZones.length;
  let hintsDone = 0;
  stage('hints', { skipped: !hintsEnabled, total: hintsTotal, leakQueries: plannedLeak, zones: hintZones.length });
  const hintErrors = [];
  let resolverLeakQueries = 0;
  // 0a. Origin map: each proxied host's remembered origins, host-specific and ranked first. It costs
  //     no query, so it runs even with originHints off; addHint drops a CDN / WAF address.
  for (const [hostName, list] of knownByHost) {
    for (const k of list) {
      addHint(k.ip, {
        kind: 'known', host: hostName, port: k.port, source: k.source, lastConfirmed: k.lastConfirmed,
        detail: `origin map: ${hostName} -> ${knownTarget(k)}`
      }, { own: true, hostNames: [hostName] });
    }
  }
  // 0. Zone file: each proxied zone name's exact origin, host-specific. It costs
  //    no query, so it runs even with originHints off. A `*.x` name names no
  //    single host (its addresses still go to the CLI targets below); addHint
  //    drops a CDN / WAF address, so a Cloudflare-range origin never becomes one.
  for (const p of zoneProxied) {
    if (p.name.startsWith('*.')) continue;
    for (const ip of p.ips) addHint(ip, { kind: 'zone', host: p.name, detail: `zone file: ${p.name}` }, { own: true, hostNames: [p.name] });
  }
  if (hintsEnabled) {
    // 1. Historical / passive IPs of each name (not CDN, not the current answer).
    for (const host of hosts) {
      const current = new Set([...host.resolution.ipv4, ...host.resolution.ipv6]);
      for (const hint of host.ipHints) {
        if (current.has(hint.ip)) continue;
        const seen = formatDay(hint.lastSeen);
        addHint(hint.ip, {
          kind: 'history',
          // Structured fields so views need not parse `detail` (kept for logs).
          host: host.name,
          source: hint.source,
          lastSeen: seen,
          detail: `${hint.source}: ${host.name}${seen ? ` (last seen ${seen})` : ''}`
        }, { hostNames: [host.name] });
      }
    }
    // 2. Public IPs of non-proxied siblings (only useful when something is proxied).
    if (proxiedHosts.length) {
      const siblings = new Map();
      for (const host of hosts) {
        const kind = host.classification.kind;
        if (kind !== 'direct' && kind !== 'private') continue;
        const owned = answerIsOwned(host);
        for (const ip of [...host.resolution.ipv4, ...host.resolution.ipv6]) {
          let s = siblings.get(ip);
          if (!s) siblings.set(ip, (s = { names: [], own: false }));
          s.names.push(host.name);
          if (owned) s.own = true; // an IP shared by an in-zone name is an origin candidate
        }
      }
      for (const [ip, s] of siblings) {
        const list = s.names;
        const more = list.length > SIBLING_DETAIL_NAMES ? ` (+${list.length - SIBLING_DETAIL_NAMES})` : '';
        // own:false for a purely third-party IP (SaaS CNAME target) → dropped
        // unless it matches an inventory server.
        addHint(ip, { kind: 'direct-sibling', detail: `${list.slice(0, SIBLING_DETAIL_NAMES).join(', ')}${more}` }, { own: s.own, hostNames: list });
      }
    }
    // 2b. sibling-domain (task 1): when several apexes are scanned together, a
    //     proxied host X.<d1> whose EXACT left-most label X is also published under
    //     ANOTHER scanned apex <d2> as a DNS-only, public, non-CDN host is a strong,
    //     host-specific origin candidate — companies reuse names across brands, so
    //     ticket.<d1> hidden behind a CDN often has its real origin sitting in the
    //     open as ticket.<d2>. Exact left-most label only (an X-vs-Xapi variant is
    //     not clearly correct, so it is left out). The sibling's IP is already an
    //     origin-network member (it is a direct host on <d2>), so this adds the
    //     host-specific evidence and ranks that IP as an exact candidate for X.
    if (proxiedHosts.length && targetDomains.length > 1) {
      const directByStem = new Map(); // stem → [{ apex, name, ips: string[] }]
      for (const host of hosts) {
        if (host.classification.kind !== 'direct' || host.wildcardSuspect || !answerIsOwned(host)) continue;
        const info = stemUnderApex(host.name);
        if (!info) continue;
        const ips = [...host.resolution.ipv4, ...host.resolution.ipv6].filter(isOriginIp);
        if (!ips.length) continue;
        if (!directByStem.has(info.stem)) directByStem.set(info.stem, []);
        directByStem.get(info.stem).push({ apex: info.apex, name: host.name, ips });
      }
      for (const host of proxiedHosts) {
        const info = stemUnderApex(host.name);
        if (!info) continue;
        for (const sib of directByStem.get(info.stem) || []) {
          // same brand: a direct sibling, not a cross-brand match — and a nested
          // apex (shop.X scanned next to X) is the same organisation, not a sister brand
          if (isSubdomainOf(sib.apex, info.apex) || isSubdomainOf(info.apex, sib.apex)) continue;
          for (const ip of sib.ips) {
            addHint(ip, {
              kind: 'sibling-domain', host: host.name, sibling: sib.name,
              detail: `${host.name}: same name as ${sib.name} (direct at ${ip})`
            }, { hostNames: [host.name] });
          }
        }
      }
    }
    // 3. resolver-leak: re-resolve each proxied host through OTHER resolvers of
    //    the pool. Any non-CDN public IP that appears is a strong origin hint for
    //    that specific host. DNS only, capped — never an HTTP/TLS probe.
    if (resolverLeak !== false && leakHosts.length && typeof dns.query === 'function') {
      const poolIds = Array.isArray(dns.chain) ? dns.chain : [];
      await mapPool(leakHosts, 4, async (host) => {
        if (resolverLeakQueries >= RESOLVER_LEAK_MAX_QUERIES) return;
        const already = new Set([...host.resolution.ipv4, ...host.resolution.ipv6]);
        const down = downResolvers();
        const others = poolIds.filter((id) => id !== host.resolution.resolver && !down.has(id)).slice(0, RESOLVER_LEAK_PER_HOST);
        for (const rid of others) {
          if (resolverLeakQueries >= RESOLVER_LEAK_MAX_QUERIES) break;
          resolverLeakQueries += 1;
          hintsDone += 1;
          progress('hints', hintsDone, hintsTotal);
          let res;
          try {
            // retries:0 — the short cap is the whole point; a retry pass would
            // double the wait on a black-holed resolver.
            res = await dns.resolveHost(host.name, { signal, resolver: rid, timeoutMs: RESOLVER_LEAK_TIMEOUT_MS, retries: 0 });
          } catch (err) {
            if (err instanceof AbortError) throw err;
            continue; // a single resolver erroring must not sink the hint pass
          }
          // Only a leaked answer that is itself a DIRECT origin counts. A CDN
          // recognised only by its CNAME suffix (Akamai edgekey/akamaiedge,
          // Azure Front Door, AWS ELB, …) has no CIDRs in netinfo, so its edge
          // IPs pass isOriginIp; but GeoDNS / ECS make every resolver return a
          // different edge, which would look like a leak. Classifying the whole
          // resolution (CNAME chain included) rejects those.
          const cls = classifyResolution(res);
          if (cls.hidesOrigin || cls.kind !== 'direct') continue;
          for (const ip of [...res.ipv4, ...res.ipv6]) {
            if (already.has(ip) || !isOriginIp(ip)) continue;
            addHint(ip, { kind: 'resolver-leak', host: host.name, resolver: rid, detail: `${host.name} via ${rid}` }, { hostNames: [host.name] });
          }
        }
      }, signal);
    }
    checkAbort(signal);
    // 4. SPF and MX of each zone apex.
    const zones = hintZones;
    await mapPool(zones, 4, async (zone) => {
      const spf = await collectSpf(zone, { dns, signal, isOwn });
      hintErrors.push(...spf.errors);
      const mx = mxExchanges(await dns.query(zone, 'MX', { signal }));
      const hostJobs = [
        ...spf.hosts.map((x) => ({ ...x, kind: 'spf' })),
        ...mx.map(({ exchange, preference }) => ({
          host: exchange, own: isOwn(exchange), kind: 'mx', detail: `${zone}: MX ${preference} ${exchange}`
        }))
      ];
      await mapPool(hostJobs, 4, async (job) => {
        const r = await dns.resolveHost(job.host, { signal });
        for (const ip of [...r.ipv4, ...r.ipv6]) addHint(ip, { kind: job.kind, detail: job.detail }, { own: job.own });
      }, signal);
      for (const net of spf.nets) {
        const bits = net.cidr.version === 4 ? 32 : 128;
        if (net.cidr.prefix === bits) {
          addHint(net.text.split('/')[0], { kind: 'spf', detail: net.detail }, { own: net.own });
          continue;
        }
        // A range: only interesting where it contains inventory servers.
        if (net.cidr.prefix < (net.cidr.version === 4 ? 8 : 32)) continue;
        for (const ip of ipIndex.keys()) {
          if (ipInCidr(ip, net.cidr)) addHint(ip, { kind: 'spf', detail: net.detail }, { own: true });
        }
      }
      hintsDone += 1;
      progress('hints', hintsDone, hintsTotal);
    }, signal);
    // Reconcile: fewer resolver-leak queries may have run than planned (down
    // resolvers, the per-host / total caps), so drive the bar to 100 % at the end.
    if (hintsTotal > 0) progress('hints', hintsTotal, hintsTotal);
  }
  checkAbort(signal);

  const originHintList = [...hintMap.values()]
    .map((hint) => ({
      ip: hint.ip,
      reasons: hint.reasons,
      servers: lookupServers([hint.ip], ipIndex).map(({ server }) => ({ serverId: server.id, name: server.name })),
      provider: hint.provider,
      hosts: sortHostnames([...hint.hosts]),
      historyHosts: hint.historyHosts
    }))
    .sort((a, b) => b.servers.length - a.servers.length || b.reasons.length - a.reasons.length || compareIp(a.ip, b.ip));

  /* ---- same-network: origin /24 · /48 clusters + a ready-to-run command --- */
  // Direct (non-proxied) hosts and resolver-leak origins reveal where the real
  // servers live. Group their public, non-CDN IPs by network so a proxied host's
  // origin can be swept for from inside the customer's network — never from here.
  const netMap = new Map();
  const addToNetwork = (ip, hostName) => {
    if (!isOriginIp(ip)) return;
    const cidr = networkCidr(ip);
    if (!cidr) return;
    let net = netMap.get(cidr);
    if (!net) {
      net = { cidr, ips: new Set(), hosts: new Set() };
      netMap.set(cidr, net);
    }
    net.ips.add(normalizeIP(ip));
    if (hostName) net.hosts.add(hostName);
  };
  for (const host of hosts) {
    if (host.classification.kind !== 'direct' || host.wildcardSuspect) continue;
    if (!answerIsOwned(host)) continue; // skip in-zone names that CNAME out to third-party SaaS
    for (const ip of [...host.resolution.ipv4, ...host.resolution.ipv6]) addToNetwork(ip, host.name);
  }
  for (const hint of originHintList) {
    if (!hint.reasons.some((r) => r.kind === 'resolver-leak')) continue;
    for (const hostName of hint.hosts) addToNetwork(hint.ip, hostName);
  }
  const hasInventoryIn = (net) => (net.ips || []).some((ip) => lookupServers([ip], ipIndex).length > 0);
  // The sweep decision the CLI can actually accept, per network (task 4):
  //  - IPv6: exact addresses only — a /48 has 2^80 hosts and ssl_origin_scan.py
  //    rejects any block over 2^20, so the whole command would fail;
  //  - a /24 holding an inventory server the user owns → sweep it whole;
  //  - a shared cloud / hosting / CDN /24 (a PROVIDERS range) with no inventory →
  //    exact IPs only, so a single origin does not silently widen into a
  //    multi-tenant block the user does not own;
  //  - otherwise the /24 when the block clusters ≥ 2 origins, else the exact IP(s).
  const sweepDecision = (net) => {
    const parsed = parseCidr(net.cidr);
    if (!parsed || parsed.version !== 4) return 'ips';
    if (hasInventoryIn(net)) return 'cidr';
    if (net.shared) return 'ips';
    return net.ips.length >= 2 ? 'cidr' : 'ips';
  };
  const originNetworks = [...netMap.values()]
    .map((net) => {
      const ips = [...net.ips].sort(compareIp);
      const provider = matchProviderByIP(ips[0]) || null;
      const out = { cidr: net.cidr, ips, hosts: sortHostnames([...net.hosts]), provider, shared: isSharedProvider(provider) };
      out.sweep = sweepDecision(out); // 'cidr' | 'ips' — what the CLI targets carry for this block
      return out;
    })
    .sort((a, b) => b.hosts.length - a.hosts.length || b.ips.length - a.ips.length || compareIp(a.cidr, b.cidr));

  const proxiedNames = sortHostnames([...new Set(proxiedHosts.map((x) => x.name))]);
  // Per-host origin candidates (tasks 1 & 2): stop attaching every network to
  // every proxied host. Each proxied host gets an ordered candidate list —
  // host-specific exact IPs (resolver-leak / history / sibling-domain) first,
  // then the origin networks worth sweeping FOR IT: networks holding a DNS-only
  // sibling that shares the host's label stem (or its parent), then the main
  // cluster, then other multi-IP clusters. A lone 1-IP network unrelated to the
  // host (a mail server, a stray cloud VM) is left out as noise.
  assignOriginCandidates(proxiedHosts, originNetworks, originHintList, stemUnderApex, parentStem);

  // Build the CLI `-t` targets from each network's own sweep decision, so the
  // command and result agree exactly on what is swept whole vs by address.
  const cliTargets = [];
  for (const net of originNetworks) {
    if (net.sweep === 'cidr') cliTargets.push(net.cidr);
    else for (const ip of net.ips) cliTargets.push(ip);
  }
  // A ready-to-run cli/ssl_origin_scan.py command: TLS+SNI-sweep the origin
  // blocks / IPs with the proxied names. Built through cmdline.js so every token
  // is validated (IP/CIDR or hostname) and shell-quoted — never string-glued —
  // and cliTargets / cliNames report exactly what went into the command. A large
  // proxied estate (> 200 names / 8,000 chars) reads its names from
  // `proxied-names.txt` (= cliNames, one per line) instead of inline, and a target
  // list still too long for that its targets from `proxied-targets.txt` (= the
  // cliTargets, then the cliHostTargets), so the command never overflows a
  // shell's command-line limit.
  // Zone import: the zone's exact origins join as exact addresses (private ones
  // kept — the CLI runs inside the network — and never widened to a /24), its host
  // origins as host targets, its proxied names (`*.x` kept) as names. Only then
  // are the host-target / wildcard-name opt-ins on, so a run without a zone
  // builds exactly the command it always did.
  const zoneIps = [...new Set(zoneProxied.flatMap((p) => p.ips))].sort(compareIp);
  const zoneHosts = sortHostnames([...new Set(zoneProxied.map((p) => p.host).filter(Boolean))]);
  // Origin map: the remembered origins of this scan's proxied hosts join exactly, the address on
  // 443 and `ip:port` on another port (cmdline's allowPorts opt-in, on only when one needs it).
  const knownTokens = [...new Set([...knownByHost.values()].flat()
    .sort((a, b) => compareIp(a.ip, b.ip) || a.port - b.port).map(knownTarget))];
  const portOptIn = knownTokens.some((tok) => !normalizeIP(tok)) ? { allowPorts: true } : {};
  const sweep = zoneIn
    ? buildFittedSweepCommand({
      targets: [...cliTargets, ...knownTokens, ...zoneIps, ...zoneHosts],
      names: sortHostnames([...new Set([...proxiedNames, ...zoneProxied.map((p) => p.name)])]),
      script: 'cli/ssl_origin_scan.py', shell: 'posix', allowHostTargets: true, allowWildcardNames: true, ...portOptIn
    })
    : buildFittedSweepCommand({ targets: [...cliTargets, ...knownTokens], names: proxiedNames, script: 'cli/ssl_origin_scan.py', shell: 'posix', ...portOptIn });
  const cliSuggestion = sweep.command ? `python3 ${sweep.command}` : null;
  const cliNames = sweep.names;
  const knownTokenSet = new Set(knownTokens);
  const isAddressToken = (tok) => !!(normalizeIP(tok) || parseCidr(tok)) || knownTokenSet.has(tok);
  const cliValidTargets = zoneIn ? sweep.targets.filter(isAddressToken) : sweep.targets;
  const cliHostTargets = zoneIn ? sweep.targets.filter((tok) => !isAddressToken(tok)) : [];

  /* ---- server groups ---------------------------------------------------- */
  const groups = new Map();
  const groupOf = (server) => {
    let g = groups.get(server);
    if (!g) {
      g = { server, hosts: [], needsCert: false, maybeNeedsCert: false };
      groups.set(server, g);
    }
    return g;
  };
  const coveredOf = (host) => (host.cert ? host.cert.covered : null);
  for (const host of hosts) {
    for (const { server, ip, through } of matchesByName.get(host.name) || []) {
      const entry = { name: host.name, ip, covered: coveredOf(host), via: 'dns' };
      if (through) entry.through = through;
      groupOf(server).hosts.push(entry);
    }
  }
  for (const hint of originHintList) {
    if (!hint.servers.length) continue;
    // 'history' / 'resolver-leak' / 'sibling-domain' hints name one specific host;
    // spf / mx / direct-sibling hints are candidate origins for every host hidden
    // behind a CDN.
    const general = hint.reasons.some((r) => !HOST_SPECIFIC_HINT_KINDS.has(r.kind));
    // The zone file's exact origin of a proxied name matches that host as 'zone'
    // (authoritative: it counts toward needsCert); everything else stays a 'hint'.
    const zoneHosts = new Set(hint.reasons.filter((r) => r.kind === 'zone').map((r) => r.host));
    // A remembered origin (the workspace's origin map) matches as 'known', ahead of the zone.
    const knownHosts = new Set(hint.reasons.filter((r) => r.kind === 'known').map((r) => r.host));
    const targets = hosts.filter((x) => hint.historyHosts.has(x.name) || (general && x.classification.hidesOrigin));
    if (!targets.length) continue;
    for (const { server, through } of lookupServers([hint.ip], ipIndex)) {
      const g = groupOf(server);
      for (const host of targets) {
        if (g.hosts.some((e) => e.name === host.name && e.ip === hint.ip)) continue;
        const entry = {
          name: host.name, ip: hint.ip, covered: coveredOf(host),
          via: knownHosts.has(host.name) ? 'known' : zoneHosts.has(host.name) ? 'zone' : 'hint'
        };
        if (through) entry.through = through;
        g.hosts.push(entry);
      }
    }
  }
  for (const hint of originHintList) delete hint.historyHosts; // internal only
  // The inventory topology (lib/topology.js): a load balancer's names reach its backends
  // (entries with `lbs`), and a server with terminates_tls=no needs no certificate, unless the
  // inventory and DNS disagree (topology.suspect). Without a topology key in the inventory the
  // groups are exactly as before.
  let serverGroups = applyTopology([...groups.values()], servers);
  for (const g of serverGroups) {
    const order = new Map(sortHostnames([...new Set(g.hosts.map((e) => e.name))]).map((n, i) => [n, i]));
    g.hosts.sort((a, b) => (VIA_RANK[a.via] ?? 9) - (VIA_RANK[b.via] ?? 9)
      || order.get(a.name) - order.get(b.name) || compareIp(a.ip, b.ip));
    const tls = terminatesTls(g.server) || !!(g.topology && g.topology.suspect);
    g.needsCert = tls && g.hosts.some((e) => (e.via === 'dns' || e.via === 'zone' || e.via === 'known') && e.covered !== false);
    g.maybeNeedsCert = tls && !g.needsCert && g.hosts.some((e) => e.via === 'hint' && e.covered !== false);
  }
  serverGroups.sort((a, b) => Number(b.needsCert) - Number(a.needsCert)
    || Number(b.maybeNeedsCert) - Number(a.maybeNeedsCert)
    || String(a.server.name ?? '').localeCompare(String(b.server.name ?? ''), undefined, { numeric: true, sensitivity: 'base' })
    || String(a.server.id ?? '').localeCompare(String(b.server.id ?? '')));
  serverGroups = orderByLoadBalancer(serverGroups);
  const nowhereNames = tlsNowhere(serverGroups);

  /* ---- unmatched direct IPs --------------------------------------------- */
  const unmatched = new Map();
  for (const host of hosts) {
    const kind = host.classification.kind;
    if (kind !== 'direct' && kind !== 'private') continue;
    for (const ip of [...host.resolution.ipv4, ...host.resolution.ipv6]) {
      if (lookupServers([ip], ipIndex).length) continue;
      if (!unmatched.has(ip)) unmatched.set(ip, []);
      unmatched.get(ip).push(host.name);
    }
  }
  const unmatchedIps = [...unmatched.entries()]
    .map(([ip, list]) => ({ ip, hosts: sortHostnames(list), provider: matchProviderByIP(ip), private: isPrivateIP(ip) }))
    .sort((a, b) => compareIp(a.ip, b.ip));

  /* ---- CT certificates -------------------------------------------------- */
  const certSerials = new Set(certList.map((c) => normalizeSerial(c.serialHex)).filter(Boolean));
  const ctCerts = mergeCerts(certsAll).map((c) => ({
    ...c,
    matchesCert: certSerials.has(normalizeSerial(c.serialHex))
  }));

  /* ---- stats ------------------------------------------------------------ */
  const count = (pred) => hosts.filter(pred).length;
  const kindCount = (k) => count((x) => x.classification.kind === k);
  const hasSourceOrigin = (x) => x.origins.some((o) => SOURCES.some((s) => s.id === o));
  const hasDnsOrigin = (x) => x.origins.some((o) => o.startsWith('dns-mine:') || PROBE_ORIGINS.has(o) || o === 'bruteforce');
  const wildcardParentCount = Object.values(wildcards).filter((w) => w && w.wildcard).length;
  const stats = {
    total: hosts.length,
    resolved: count((x) => x.resolution.ipv4.length > 0 || x.resolution.ipv6.length > 0),
    cloudflare: kindCount('cloudflare'),
    cdn: kindCount('cdn'),
    platform: kindCount('platform'),
    direct: kindCount('direct'),
    private: kindCount('private'),
    nxdomain: kindCount('nxdomain'),
    dangling: count((x) => x.classification.dangling),
    covered: count((x) => !!(x.cert && x.cert.covered)),
    matchedServers: serverGroups.filter((g) => (terminatesTls(g.server) || (g.topology && g.topology.suspect))
      && g.hosts.some((e) => e.via === 'dns' && !e.lbs)).length,
    wildcardSuspects: count((x) => x.wildcardSuspect),
    // extensions
    unresolved: kindCount('unresolved'),
    hiddenOrigin: count((x) => x.classification.hidesOrigin),
    needsCert: serverGroups.filter((g) => g.needsCert).length,
    hintedServers: serverGroups.filter((g) => !g.hosts.some((e) => e.via === 'dns')).length,
    originHints: originHintList.length,
    unmatchedIps: unmatchedIps.length,
    sourcesOk: sourceResults.filter((r) => r.ok).length,
    sourcesFailed: sourceResults.filter((r) => !r.ok).length,
    // per-technique discovery counts
    fromSources: count(hasSourceOrigin),
    fromDns: count(hasDnsOrigin),
    wildcardParents: wildcardParentCount,
    mineFound: count((x) => x.origins.some((o) => o.startsWith('dns-mine:'))),
    wordlistFound: count((x) => x.origins.includes('wordlist')),
    permutationFound: count((x) => x.origins.includes('permutation')),
    recursiveFound: count((x) => x.origins.includes('recursive')),
    // brute-force accounting (bruteforce* kept for backward compatibility = wordlist stage)
    bruteforceTried: bf.tried,
    bruteforceFound: count((x) => x.origins.includes('wordlist')),
    bruteforceWildcardDropped: bf.wildcardDropped + droppedProbe.wordlist,
    bruteforceErrors: bf.errors,
    permutationTried: perm.tried,
    permutationWildcardDropped: perm.wildcardDropped + droppedProbe.permutation,
    permutationErrors: perm.errors,
    recursiveTried: rec.tried,
    recursiveWildcardDropped: rec.wildcardDropped + droppedProbe.recursive,
    recursiveErrors: rec.errors,
    // extension: probe hits that were gone by the resolve stage (a clean NXDOMAIN / empty answer)
    bruteforceVanished: vanishedProbe.wordlist,
    permutationVanished: vanishedProbe.permutation,
    recursiveVanished: vanishedProbe.recursive,
    ctCerts: ctCerts.length,
    dnsQueries: typeof dns.stats === 'function' ? dns.stats().queries : null,
    truncated,
    elapsedMs: Date.now() - t0,
    // zone import only (absent without a zone, so a plain run's stats are unchanged):
    // seeds taken from the zone, and how many of them resolved
    ...(zoneIn ? {
      zoneSeeds: zoneSeedNames.size,
      zoneResolved: count((x) => x.origins.includes('zone') && (x.resolution.ipv4.length > 0 || x.resolution.ipv6.length > 0))
    } : {})
  };

  /* ---- wordlist usage (per domain + custom/learned tried vs found) ------- */
  // What the brute-force stage actually used, per apex: the served level (after
  // any degrade), the locale packs that really loaded, and how many of the
  // custom / learned labels were tried and resolved. Honest reporting for the
  // UI; never tuned. "Tried" counts only candidates actually queued as probes
  // (bfAttribution): a label cut by a cap, skipped as already known, or never
  // used (bruteforce 'off' / 'medium') is not tried. Per domain the counts are
  // per base; the top-level ones count DISTINCT list entries, so a label that
  // hits under two domains is 1 found of 1 tried — found can never exceed tried.
  const levelUsed = anyWords ? (KNOWN_LEVELS.has(bfMode) ? servedBf : bfMode) : 'off';
  const byBaseTier = (map, base, tier) => map.get(`${base}\u0000${tier}`) || 0;
  const bump = (map, base, tier) => { const k = `${base}\u0000${tier}`; map.set(k, (map.get(k) || 0) + 1); };
  const triedByBaseTier = new Map(); // `${base}\u0000${tier}` → count
  const foundByBaseTier = new Map();
  const triedEntries = { custom: new Set(), learned: new Set() };
  const foundEntries = { custom: new Set(), learned: new Set() };
  for (const attr of bfAttribution.values()) {
    bump(triedByBaseTier, attr.base, attr.tier);
    triedEntries[attr.tier].add(attr.entry);
  }
  for (const host of hosts) {
    if (!host.origins.includes('wordlist')) continue;
    const attr = bfAttribution.get(host.name);
    if (!attr) continue;
    bump(foundByBaseTier, attr.base, attr.tier);
    foundEntries[attr.tier].add(attr.entry);
  }
  const usesLocalePacks = KNOWN_LEVELS.has(bfMode) && bfMode !== 'small' && !overrideWords;
  const wordlistPerDomain = bfBases.map((base) => ({
    domain: base,
    level: baseWords.get(base) && baseWords.get(base).length ? levelUsed : 'off',
    locales: usesLocalePacks ? localesUsedForBase(base) : [],
    words: (baseWords.get(base) || []).length,
    customTried: byBaseTier(triedByBaseTier, base, 'custom'),
    learnedTried: byBaseTier(triedByBaseTier, base, 'learned'),
    customFound: byBaseTier(foundByBaseTier, base, 'custom'),
    learnedFound: byBaseTier(foundByBaseTier, base, 'learned')
  }));
  const wordlistUsage = {
    requested: bfMode,
    level: levelUsed,
    degraded: [...degradePairs],
    localePacks: usesLocalePacks ? [...new Set(bfBases.flatMap(localesUsedForBase))].sort() : [],
    // extension: requested locale packs that failed to load (so were NOT used)
    localesMissing: usesLocalePacks ? missingAll : [],
    customTried: triedEntries.custom.size,
    learnedTried: triedEntries.learned.size,
    customFound: foundEntries.custom.size,
    learnedFound: foundEntries.learned.size,
    perDomain: wordlistPerDomain
  };

  const zoneNameSet = new Set(zoneProxied.map((p) => p.name));
  const zoneIpSet = new Set(zoneIps);
  const zoneSummary = zoneIn ? {
    origin: zoneIn.origin,
    exact: exactMode,
    seeds: zoneSeedNames.size,
    wildcardBases: sortHostnames([...zoneWildcardRoots]),
    proxied: zoneProxied.length,
    resolved: stats.zoneResolved,
    outOfScope: zoneOutOfScope,
    cliNames: cliNames.filter((n) => zoneNameSet.has(n)),
    cliTargets: cliValidTargets.filter((ip) => zoneIpSet.has(ip)),
    cliHostTargets: [...cliHostTargets]
  } : null;
  const result = {
    startedAt,
    finishedAt: new Date(),
    domains: targetDomains,
    hosts,
    sources: sourceResults,
    wildcards,
    originHints: originHintList,
    servers: serverGroups,
    unmatchedIps,
    ctCerts,
    stats,
    // topology: the covered names that reach only terminates_tls=no servers (absent without any)
    ...(nowhereNames.length ? { tlsNowhere: nowhereNames } : {}),
    // extensions
    sourceDomains,
    sourceHealth: sourceHealthSummary(sourceResults),
    wildcardBases: sortHostnames([...wildcardBases]),
    wildcardParents: sortHostnames(Object.keys(wildcards).filter((p) => wildcards[p] && wildcards[p].wildcard)),
    mineEvidence,
    mineExternalRefs: [...mineExternal].sort(),
    lastSeen: lastSeenByName,
    warnings,
    hintErrors: [...new Set(hintErrors)],
    // Passive-source snapshot when the DNS sweep started (task 6): whether the
    // grace window cut the sources off and which ids were still fetching then. By
    // the end every source is awaited, so this only describes the grace moment.
    sourceGrace,
    // v2 origin-hunting output
    originNetworks,
    cliSuggestion,
    cliTargets: cliValidTargets,
    cliNames,
    // zone import: host-name CLI targets (a proxied name's CNAME origin); [] without a zone
    cliHostTargets,
    options: {
      sources: sourceIds, includeExpired: !!includeExpired,
      bruteforce: levelUsed,
      mine: mineEnabled, permutationBudget: permBudget, recursive: recursiveEnabled,
      resolverLeak: resolverLeak !== false,
      originHints: hintsEnabled, cert: hasCert, inventoryServers: servers.length,
      wordlist: wordlistUsage,
      exact: exactMode,
      zone: zoneSummary && {
        origin: zoneSummary.origin, seeds: zoneSummary.seeds, wildcardBases: zoneSummary.wildcardBases.length,
        proxied: zoneSummary.proxied, resolved: zoneSummary.resolved, outOfScope: zoneSummary.outOfScope
      }
    },
    // zone import summary (null without a zone): counts, plus exactly which zone
    // names / addresses / hosts went into the CLI command
    zone: zoneSummary,
    // origin map (only when knownOrigins was given): how many remembered origins it held, the
    // proxied names one matched, and exactly which of their targets went into the CLI command
    ...(knownIn ? {
      known: {
        entries: knownIn.length,
        names: sortHostnames([...knownByHost.keys()]),
        cliTargets: sweep.targets.filter((tok) => knownTokenSet.has(tok))
      }
    } : {})
  };
  stage('done', { stats });
  return result;
}
