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
  classifyResolution, matchProviderByIP, normalizeIP, parseCidr, parseIP, ipInCidr, isPrivateIP, formatIP
} from './netinfo.js';
import { buildIpIndex, lookupServers } from './inventory.js';
import {
  getWordlist, loadWordlist, WORDLIST_SMALL, WORDLIST_LEVELS,
  parseCustomWordlist, localesForDomain, LOCALE_PACK_CODES
} from './wordlist.js';
import { SOURCES, fetchAllSources, mergeCerts, sourceHealthSummary } from './sources.js';
import { followCnames, detectWildcardDeep } from './doh.js';
import { mineDnsNames } from './dnsmine.js';
import { permutations, DEFAULT_WORDS } from './permute.js';
import { buildSweepCommand } from './cmdline.js';
import { isStorableLabel } from './learned.js';
import { AbortError, abortReasonToError, splitList, sleep } from './util.js';

/* ------------------------------------------------------------------------ */
/* Types                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} HostRecord
 * @property {string} name
 * @property {string[]} origins where the name came from: 'input', 'cert',
 *   source ids, 'dns-mine:<record>' (MX|NS|SOA|SPF|DMARC|SRV|CNAME|CAA|HTTPS|PTR),
 *   'wordlist', 'permutation', 'recursive' (legacy runs may show 'bruteforce')
 * @property {object} resolution HostResolution (doh.js)
 * @property {object} classification netinfo.classifyResolution() result
 * @property {{ covered: boolean, by: string|null }|null} cert coverage by the scanned certificate (null without cert)
 * @property {Array<{ serverId: string, name: string, ip: string }>} servers inventory servers owning a resolved IP
 * @property {boolean} wildcardSuspect answer identical to the parent's wildcard answer
 * @property {object[]} ipHints IpHint[] from passive sources for this name
 * @property {string[]} candidateNetworks extension (v2): /24 · /48 origin-network CIDRs to sweep for
 *   a proxied host's real origin (empty unless the host hides its origin)
 * @property {boolean} customOnly extension: found ONLY by a custom-wordlist label that is not in the
 *   built-in core list (the tab-only custom list is its sole evidence) — never learned
 */

/**
 * @typedef {object} OriginHint
 * @property {string} ip
 * @property {Array<{ kind: 'spf'|'mx'|'direct-sibling'|'history'|'resolver-leak', detail: string }>} reasons
 * @property {Array<{ serverId: string, name: string }>} servers inventory servers with this IP
 * @property {object|null} provider netinfo provider of the IP (never a CDN that hides origins)
 * @property {string[]} hosts extension: hostnames the hint is specifically about (history / sibling / resolver-leak)
 */

/**
 * @typedef {object} OriginNetwork extension (v2)
 * @property {string} cidr /24 (IPv4) or /48 (IPv6) block direct hosts / leaked origins cluster in
 * @property {string[]} ips the public, non-CDN origin IPs seen in the block
 * @property {string[]} hosts the DNS-only host names that resolve into the block
 * @property {object|null} provider netinfo provider of the block (usually null for a real origin)
 */

/**
 * @typedef {object} ServerGroup
 * @property {object} server inventory Server
 * @property {Array<{ name: string, ip: string, covered: boolean|null, via: 'dns'|'hint' }>} hosts
 * @property {boolean} needsCert a DNS-matched host is covered by the certificate (without a
 *   certificate: any DNS-matched host)
 * @property {boolean} maybeNeedsCert extension: only origin hints point here
 */

/* ------------------------------------------------------------------------ */
/* Constants / helpers                                                      */
/* ------------------------------------------------------------------------ */

const STAGES = ['sources', 'mining', 'wildcard', 'bruteforce', 'permutations', 'resolve', 'hints', 'done'];
/** DNS-discovery origin tags (a name found only through these can be dropped if it looks synthesized). */
const PROBE_ORIGINS = new Set(['wordlist', 'permutation', 'recursive']);
const MAX_SPF_DEPTH = 5;
const MAX_SPF_LOOKUPS = 10;
const MAX_MX = 10;
// Per-apex brute-force ceilings, by wordlist level. `huge` (~130k labels) must
// be fully reachable for a SINGLE apex — its cap sits just above the list size —
// while smaller levels keep a tight cap so a typo in the level cannot balloon a
// small scan. Legacy custom lists / 'medium' use LEGACY_MAX_BRUTEFORCE per base.
const MAX_BRUTEFORCE_PER_BASE = { small: 4000, smart: 20000, large: 80000, huge: 160000 };
const LEGACY_MAX_BRUTEFORCE = 60000;
// Hard ceiling on the COMBINED candidate count across every base / domain, so a
// SAN certificate covering many apexes (or a 'huge' sweep of several domains)
// cannot multiply into an unbounded probe storm. One 'huge' apex fits under
// this; a second is trimmed by the fair round-robin and a BRUTEFORCE_TRUNCATED
// warning is surfaced.
const MAX_BRUTEFORCE_TOTAL = 200000;
const MAX_PERMUTATIONS = 20000;
const MAX_WILDCARD_PARENTS = 80;
const DEFAULT_PERMUTATION_BUDGET = 1500;
const DEFAULT_RECURSIVE_PARENTS = 8;
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
const RESOLVER_LEAK_MAX_QUERIES = 300;
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
const RECURSIVE_EXTRA_WORDS = 100;
const RECURSIVE_MAX = MAX_PERMUTATIONS;
// Adaptive back-off: after this many consecutive transport failures, pause a
// little before the next probe (grows with the streak, capped) so a struggling
// resolver pool is given room instead of being pounded.
const PROBE_ERR_THRESHOLD = 8;
const PROBE_BACKOFF_STEP = 50;
const PROBE_BACKOFF_MAX = 1000;

/** Rank of an origin tag for stable display order. */
function rankOrigin(o) {
  if (o === 'input') return 0;
  if (o === 'cert') return 1;
  if (typeof o === 'string' && o.startsWith('dns-mine:')) return 2;
  const si = SOURCES.findIndex((s) => s.id === o);
  if (si !== -1) return 100 + si;
  if (o === 'wordlist' || o === 'bruteforce') return 900;
  if (o === 'permutation') return 901;
  if (o === 'recursive') return 902;
  return 1000;
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

/**
 * Is a resolution indistinguishable from the parent's wildcard answer?
 * Handles the three wildcard kinds detectWildcardDeep reports:
 *  - 'CNAME': the first synthesized CNAME target matches the wildcard's;
 *  - 'A': every address is one of the wildcard's addresses;
 *  - 'NODATA': the name has no address and no CNAME (the zone answers any label
 *    with NOERROR-empty, so a "hit" with nothing in it is just the wildcard).
 * A wildcard object without `kind` (legacy) falls back to the combined test.
 */
function isWildcardSuspect(res, wc) {
  if (!wc || !wc.wildcard || !res) return false;
  const hc = res.cnames || [];
  const wcc = wc.cnames || [];
  const ips = [...(res.ipv4 || []), ...(res.ipv6 || [])];
  if (wc.kind === 'CNAME') return hc.length > 0 && wcc.length > 0 && hc[0] === wcc[0];
  if (wc.kind === 'A') {
    if (!ips.length) return false;
    const wips = new Set([...(wc.ipv4 || []), ...(wc.ipv6 || [])]);
    return ips.every((ip) => wips.has(ip));
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

/** Immediate parent zone of a name ('a.b.c' → 'b.c'); '' when it has one label. */
function parentOf(name) {
  const dot = name.indexOf('.');
  return dot === -1 ? '' : name.slice(dot + 1);
}

/* ------------------------------------------------------------------------ */
/* Wordlist selection                                                        */
/* ------------------------------------------------------------------------ */

const KNOWN_LEVELS = new Set(WORDLIST_LEVELS); // small | smart | large | huge
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
/* Learned labels (privacy-preserving vocabulary from a completed scan)      */
/* ------------------------------------------------------------------------ */

// A bare, storable DNS label: [a-z0-9-], 1–63, no leading/trailing '-', not
// purely numeric and not an IP address written as a label (`198-51-100-7`,
// `ip-192-0-2-10`, `2001-db8--1`). The very rule of learned.js (imported, so
// the two can never drift): this helper only emits labels the store keeps.
const isLearnableLabel = isStorableLabel;
// The built-in core list is public vocabulary: a custom label that is also in it
// is never private (see customOnly below).
const CORE_LABELS = new Set(WORDLIST_SMALL);

/**
 * The left-most labels a host name contributes relative to the longest apex it
 * sits under. A host under no apex (another organisation's certificate SAN or
 * extra name) contributes nothing, so its brand label is never learned. Never
 * the full name. `*` / IP-looking names yield nothing.
 */
function leftmostLabels(name, apexes) {
  const host = String(name ?? '').trim().toLowerCase().replace(/\.+$/, '');
  if (!host || host.includes('*')) return [];
  let best = '';
  for (const apex of apexes) {
    const a = String(apex ?? '').trim().toLowerCase().replace(/\.+$/, '');
    if (!a) continue;
    if (host === a) return []; // the apex itself contributes no label
    if (host.endsWith(`.${a}`) && a.length > best.length) best = a;
  }
  if (!best) return [];
  return host.slice(0, host.length - best.length - 1).split('.').filter(isLearnableLabel);
}

/**
 * Labels worth remembering from a completed scan, for the per-browser learned
 * store (`createLearnedStore(...).record`). Returns bare, left-most DNS labels
 * relative to each scanned apex, taken ONLY from hosts that actually resolved
 * and are not wildcard look-alikes. Never returns a full hostname or an IP — a
 * privacy-preserving naming vocabulary only. Pure; safe to call in the UI.
 *
 * The custom wordlist is tab-only, so what ONLY it uncovered is never learned:
 * a `customOnly` host (found solely by a custom label outside the built-in core)
 * contributes nothing, and its private labels are also withheld from hosts that
 * only the probe stages derived (a permutation `secret2` / recursive
 * `www.secret` of a custom-only `secret`). A host some other method found
 * (sources, mining, input, certificate) is public evidence and is learned as usual.
 * @param {object} result a ScanResult from {@link runScan}
 * @returns {string[]} unique labels in first-seen order
 */
export function learnedLabelsFromScan(result) {
  const out = [];
  const seen = new Set();
  if (!result || !Array.isArray(result.hosts)) return out;
  const apexes = Array.isArray(result.domains) ? result.domains : [];
  const privateLabels = [];
  for (const host of result.hosts) {
    if (!host || !host.customOnly) continue;
    for (const label of leftmostLabels(host.name, apexes)) {
      if (!CORE_LABELS.has(label) && !privateLabels.includes(label)) privateLabels.push(label);
    }
  }
  const probeOnly = (host) => Array.isArray(host.origins) && host.origins.length > 0
    && host.origins.every((o) => PROBE_ORIGINS.has(o) || o === 'bruteforce');
  for (const host of result.hosts) {
    if (!host || host.wildcardSuspect || host.customOnly) continue;
    const res = host.resolution || {};
    const resolved = (res.ipv4 && res.ipv4.length) || (res.ipv6 && res.ipv6.length);
    if (!resolved) continue;
    const derived = privateLabels.length > 0 && probeOnly(host);
    for (const label of leftmostLabels(host.name, apexes)) {
      if (derived && privateLabels.some((p) => label.includes(p))) continue;
      if (!seen.has(label)) { seen.add(label); out.push(label); }
    }
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
 *     (env / number / region / sibling), then one recursive wordlist round under
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
 * @param {object} [hooks] { onStage(stage, info), onSource(result), onHost(record), onProgress({ stage, done, total }) }
 * @returns {Promise<object>} ScanResult
 */
export async function runScan(config = {}, hooks = {}) {
  const {
    domains = [], cert = null, extraNames = [], sources, includeExpired = false,
    bruteforce = 'smart', mine = true, permutationBudget = DEFAULT_PERMUTATION_BUDGET, recursive = true,
    inventory = [], originHints = true, dns, fetchImpl = globalThis.fetch, signal,
    wordlist = null, customWordlist = null, learnedLabels = null, locales,
    balance = true, recursiveParents = DEFAULT_RECURSIVE_PARENTS,
    resolverLeak = true, maxHosts = 20000, concurrency = 32, maxConcurrency,
    sourceGraceMs = DEFAULT_SOURCE_GRACE_MS, wordlistPreferFetch = false
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
  const bfMode = bruteforce === undefined || bruteforce === null ? 'smart' : String(bruteforce);
  const permBudget = Number.isFinite(permutationBudget) && permutationBudget > 0
    ? Math.min(Math.floor(permutationBudget), MAX_PERMUTATIONS) : 0;
  const recursiveEnabled = recursive !== false && recursive !== 0;
  const recursiveCap = Math.max(0, Math.floor(Number(recursiveParents)) || 0);

  /* ---- wordlist inputs (custom → learned → level list) ------------------ */
  // `config.wordlist` (legacy) REPLACES everything; otherwise custom labels are
  // tried first, then learned labels, then the level's list (small / locale
  // packs / base / larger tiers, assembled per apex by loadWordlist).
  const overrideWords = Array.isArray(wordlist) && wordlist.length ? wordlist : null;
  const customLabels = overrideWords ? [] : normalizeCustomLabels(customWordlist);
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

  const certHostnames = cert && Array.isArray(cert.hostnames) ? cert.hostnames : [];
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
  if (!targetDomains.length) {
    for (const d of baseDomainsFromNames([...certHostnames, ...extras])) pushTarget(d);
  }
  if (!targetDomains.length && !origins.size) {
    throw new TypeError('runScan: nothing to scan (no valid domain, certificate name or extra name)');
  }
  for (const d of targetDomains) addName(d, 'input');

  const sourceDomains = [...new Set(targetDomains.map((d) => registrableDomain(d) || d))];
  const scopeRoots = [...new Set([...targetDomains, ...wildcardBases])];
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
  const sourceIds = Array.isArray(sources) ? [...new Set(sources)] : SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
  const sourceTotal = sourceIds.length * sourceDomains.length;
  const sourceResults = [];
  const hintsByName = new Map();
  const lastSeenByName = {};
  let certsAll = [];

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
  const mineEnabled = mine !== false;
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
  if (sourceTotal > 0 && graceMs > 0) {
    // Proceed when the sources finish OR the grace timer fires, whichever comes
    // first (the timer is always cleared, so no dangling handle is left behind).
    await new Promise((resolve) => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', finish);
        resolve();
      };
      const timer = setTimeout(finish, graceMs);
      sourcesTask.then(finish, finish);
      if (signal) signal.addEventListener('abort', finish, { once: true });
    });
  } else {
    await sourcesTask;
  }
  checkAbort(signal);

  const wildcards = {};
  /**
   * Deep-detect wildcards for a set of candidate parents not seen yet, in scope,
   * capped at MAX_WILDCARD_PARENTS. Reused for the catch-up passes (late source
   * names, permutation parents) so probes are never run under an unchecked parent.
   */
  const ensureWildcards = async (candidateParents) => {
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
      wildcards[p] = await detectWildcardDeep(dns, p, { signal });
    }, signal);
  };

  /* ---- deep wildcard detection (per parent level) ----------------------- */
  const wildcardParents = new Set(scopeRoots);
  for (const name of origins.keys()) {
    if (!inScope(name)) continue;
    const parent = parentOf(name);
    if (parent && parent.includes('.') && scopeRoots.some((root) => isSubdomainOf(parent, root))) wildcardParents.add(parent);
  }
  let parents = sortHostnames([...wildcardParents]);
  if (parents.length > MAX_WILDCARD_PARENTS) {
    // keep the apex + certificate bases and the shallowest levels first
    const priority = new Set(scopeRoots);
    const kept = parents.filter((p) => priority.has(p));
    const rest = parents.filter((p) => !priority.has(p)).sort((a, b) => a.split('.').length - b.split('.').length);
    parents = sortHostnames([...kept, ...rest].slice(0, MAX_WILDCARD_PARENTS));
    warnings.push({ code: 'WILDCARD_PARENTS_TRUNCATED', detail: String(MAX_WILDCARD_PARENTS) });
  }

  let wildcardDone = 0;
  stage('wildcard', { parents, total: parents.length });
  await mapPool(parents, 4, async (p) => {
    wildcards[p] = await detectWildcardDeep(dns, p, { signal });
    wildcardDone += 1;
    progress('wildcard', wildcardDone, parents.length);
  }, signal);
  checkAbort(signal);
  const nearestWildcard = (name) => {
    let best = null;
    for (const p of Object.keys(wildcards)) {
      const w = wildcards[p];
      if (!w || !w.wildcard || name === p || !isSubdomainOf(name, p)) continue;
      if (!best || p.length > best.parent.length) best = { parent: p, w };
    }
    return best ? best.w : null;
  };

  /* ---- shared A-only probe (wordlist / permutation / recursive) --------- */
  /**
   * Probe candidate names with a single A query each (balance mode), keep the
   * ones that answer and are not wildcard look-alikes. Courteous concurrency
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
  const probeNames = async (candidates, origin, stageName, baseDone, grandTotal) => {
    const out = { tried: candidates.length, found: 0, wildcardDropped: 0, errors: 0 };
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
      if (res.rcode !== 'NOERROR') return;
      const { cnames } = followCnames(res.answers, name);
      const owners = new Set([name, ...cnames]);
      const ipv4 = [...new Set(res.answers
        .filter((rr) => rr.type === 'A' && owners.has(rr.name))
        .map((rr) => normalizeIP(rr.data))
        .filter(Boolean))];
      if (!ipv4.length && !cnames.length) return; // NODATA / no address — not a real hit
      if (isWildcardSuspect({ cnames, ipv4, ipv6: [] }, nearestWildcard(name))) {
        out.wildcardDropped += 1;
        return;
      }
      addName(name, origin);
      out.found += 1;
    }, signal);
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
      // Level-insertion permutations (dev.api.x, us.api.x) go one level deeper.
      // Wildcard-check any discovered parent of a candidate that was not seen in
      // the wildcard stage, so a per-host wildcard (*.api.x) does not turn every
      // insertion into a false 'permutation' hit.
      const permParents = new Set();
      for (const cand of permCandidates) {
        const p = parentOf(cand);
        if (p && origins.has(p) && !targetDomains.includes(p)) permParents.add(p);
      }
      await ensureWildcards([...permParents]);
      checkAbort(signal);
      Object.assign(perm, await probeNames(permCandidates, 'permutation', 'permutations', 0, permCandidates.length));
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
    // keep explicitly requested names (input / certificate) first
    const isPriority = (n) => origins.get(n).has('input') || origins.get(n).has('cert');
    const priority = names.filter(isPriority);
    const rest = names.filter((n) => !isPriority(n));
    names = sortHostnames([...priority, ...rest].slice(0, maxHosts));
    truncated = true;
    warnings.push({ code: 'TRUNCATED', detail: `${origins.size} > ${maxHosts}` });
  }
  stage('resolve', { total: names.length });
  // Found ONLY by a custom-list label that is not built-in core vocabulary: the
  // tab-only custom list is the sole evidence, so the host is never learned
  // (learnedLabelsFromScan). A core label (www, api …) is public, so not flagged.
  const isCustomOnly = (name, nameOrigins) => {
    if (nameOrigins.size !== 1 || !nameOrigins.has('wordlist')) return false;
    const attr = bfAttribution.get(name);
    if (!attr || attr.tier !== 'custom') return false;
    return !attr.label.split('.').every((l) => CORE_LABELS.has(l));
  };
  const records = new Map();
  const matchesByName = new Map();
  let resolvedDone = 0;
  const droppedProbe = { wordlist: 0, permutation: 0, recursive: 0 };
  await mapPool(names, pool, async (name) => {
    const resolution = await dns.resolveHost(name, { signal, balance: useBalance });
    resolvedDone += 1;
    progress('resolve', resolvedDone, names.length);
    const classification = classifyResolution(resolution);
    const wildcardSuspect = isWildcardSuspect(resolution, nearestWildcard(name));
    const nameOrigins = origins.get(name);
    const onlyProbe = [...nameOrigins].every((o) => PROBE_ORIGINS.has(o));
    const hasAnswer = resolution.ipv4.length || resolution.ipv6.length || resolution.cnames.length;
    if (onlyProbe && (wildcardSuspect || !hasAnswer)) {
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
      cert: cert ? certCovers(certHostnames, name) : null,
      servers: matches.map(({ server, ip }) => ({ serverId: server.id, name: server.name, ip })),
      wildcardSuspect,
      ipHints: hintsByName.get(name) || [],
      candidateNetworks: [],
      customOnly: isCustomOnly(name, nameOrigins)
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
      // history + resolver-leak hints are about one specific name, not a
      // candidate origin for every proxied host.
      if (reason.kind === 'history' || reason.kind === 'resolver-leak') hint.historyHosts.add(n);
    }
  };

  const hintsEnabled = originHints !== false;
  // Wildcard suspects only echo their parent's wildcard record, so they are no
  // evidence of a proxied origin: leave them out of the resolver-leak pass (which
  // has a query budget), the candidate networks and the CLI `-n` names.
  const proxiedHosts = hosts.filter((x) => x.classification.hidesOrigin && !x.wildcardSuspect);
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
  stage('hints', { skipped: !hintsEnabled });
  const hintErrors = [];
  let resolverLeakQueries = 0;
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
    // 3. resolver-leak: re-resolve each proxied host through OTHER resolvers of
    //    the pool. Any non-CDN public IP that appears is a strong origin hint for
    //    that specific host. DNS only, capped — never an HTTP/TLS probe.
    if (resolverLeak !== false && proxiedHosts.length && typeof dns.query === 'function') {
      const poolIds = Array.isArray(dns.chain) ? dns.chain : [];
      // Resolvers whose breaker is currently open would only time out — skip them.
      const downResolvers = () => {
        try {
          const byResolver = (typeof dns.stats === 'function' ? dns.stats().byResolver : null) || {};
          return new Set(Object.keys(byResolver).filter((id) => byResolver[id] && byResolver[id].down));
        } catch { return new Set(); }
      };
      await mapPool(proxiedHosts, 4, async (host) => {
        if (resolverLeakQueries >= RESOLVER_LEAK_MAX_QUERIES) return;
        const already = new Set([...host.resolution.ipv4, ...host.resolution.ipv6]);
        const down = downResolvers();
        const others = poolIds.filter((id) => id !== host.resolution.resolver && !down.has(id)).slice(0, RESOLVER_LEAK_PER_HOST);
        for (const rid of others) {
          if (resolverLeakQueries >= RESOLVER_LEAK_MAX_QUERIES) break;
          resolverLeakQueries += 1;
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
    const zones = [...new Set([...sourceDomains, ...targetDomains])];
    let zonesDone = 0;
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
      zonesDone += 1;
      progress('hints', zonesDone, zones.length);
    }, signal);
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
  const originNetworks = [...netMap.values()]
    .map((net) => ({
      cidr: net.cidr,
      ips: [...net.ips].sort(compareIp),
      hosts: sortHostnames([...net.hosts]),
      provider: matchProviderByIP([...net.ips][0]) || null
    }))
    .sort((a, b) => b.hosts.length - a.hosts.length || b.ips.length - a.ips.length || compareIp(a.cidr, b.cidr));

  const networkCidrs = originNetworks.map((n) => n.cidr); // display context (/24 · /48)
  const proxiedNames = sortHostnames([...new Set(proxiedHosts.map((x) => x.name))]);
  // Attach the candidate origin networks to every proxied host (display).
  if (networkCidrs.length) {
    for (const host of proxiedHosts) host.candidateNetworks = [...networkCidrs];
  }
  // Build the CLI `-t` targets the sweep can actually accept:
  //  - IPv6: exact addresses only — a /48 has 2^80 hosts and ssl_origin_scan.py
  //    rejects any block over 2^20, so the whole command would fail;
  //  - IPv4: the /24 when the block clusters several origins or holds an
  //    inventory server; otherwise the exact IPs, so the sweep does not blast a
  //    whole shared cloud/hosting /24 the user does not own.
  const hasInventoryIn = (net) => [...net.ips].some((ip) => lookupServers([ip], ipIndex).length > 0);
  const cliTargets = [];
  for (const net of originNetworks) {
    const parsed = parseCidr(net.cidr);
    const v4 = parsed && parsed.version === 4;
    if (v4 && (net.ips.length >= 2 || hasInventoryIn(net))) cliTargets.push(net.cidr);
    else for (const ip of net.ips) cliTargets.push(ip);
  }
  // A ready-to-run cli/ssl_origin_scan.py command: TLS+SNI-sweep the origin
  // blocks / IPs with the proxied names. Built through cmdline.js so every token
  // is validated (IP/CIDR or hostname) and shell-quoted — never string-glued —
  // and cliTargets / cliNames report exactly what went into the command. A large
  // proxied estate (> 200 names / 8,000 chars) reads its names from
  // `proxied-names.txt` (= cliNames, one per line) instead of inline, so the
  // command never overflows a shell's command-line limit.
  const sweep = buildSweepCommand({ targets: cliTargets, names: proxiedNames, script: 'cli/ssl_origin_scan.py', shell: 'posix' });
  const cliSuggestion = sweep.command ? `python3 ${sweep.command}` : null;
  const cliNames = sweep.names;
  const cliValidTargets = sweep.targets;

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
    for (const { server, ip } of matchesByName.get(host.name) || []) {
      groupOf(server).hosts.push({ name: host.name, ip, covered: coveredOf(host), via: 'dns' });
    }
  }
  for (const hint of originHintList) {
    if (!hint.servers.length) continue;
    // 'history' / 'resolver-leak' hints are about specific names; spf / mx /
    // sibling hints are candidate origins for every host hidden behind a CDN.
    const general = hint.reasons.some((r) => r.kind !== 'history' && r.kind !== 'resolver-leak');
    const targets = hosts.filter((x) => hint.historyHosts.has(x.name) || (general && x.classification.hidesOrigin));
    if (!targets.length) continue;
    for (const { server } of lookupServers([hint.ip], ipIndex)) {
      const g = groupOf(server);
      for (const host of targets) {
        if (g.hosts.some((e) => e.name === host.name && e.ip === hint.ip)) continue;
        g.hosts.push({ name: host.name, ip: hint.ip, covered: coveredOf(host), via: 'hint' });
      }
    }
  }
  for (const hint of originHintList) delete hint.historyHosts; // internal only
  const serverGroups = [...groups.values()];
  for (const g of serverGroups) {
    const order = new Map(sortHostnames([...new Set(g.hosts.map((e) => e.name))]).map((n, i) => [n, i]));
    g.hosts.sort((a, b) => (a.via === b.via ? 0 : a.via === 'dns' ? -1 : 1)
      || order.get(a.name) - order.get(b.name) || compareIp(a.ip, b.ip));
    g.needsCert = g.hosts.some((e) => e.via === 'dns' && e.covered !== false);
    g.maybeNeedsCert = !g.needsCert && g.hosts.some((e) => e.via === 'hint' && e.covered !== false);
  }
  serverGroups.sort((a, b) => Number(b.needsCert) - Number(a.needsCert)
    || Number(b.maybeNeedsCert) - Number(a.maybeNeedsCert)
    || String(a.server.name ?? '').localeCompare(String(b.server.name ?? ''), undefined, { numeric: true, sensitivity: 'base' })
    || String(a.server.id ?? '').localeCompare(String(b.server.id ?? '')));

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
  const certSerial = cert ? normalizeSerial(cert.serialHex) : null;
  const ctCerts = mergeCerts(certsAll).map((c) => ({
    ...c,
    matchesCert: !!certSerial && normalizeSerial(c.serialHex) === certSerial
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
    matchedServers: serverGroups.filter((g) => g.hosts.some((e) => e.via === 'dns')).length,
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
    ctCerts: ctCerts.length,
    dnsQueries: typeof dns.stats === 'function' ? dns.stats().queries : null,
    truncated,
    elapsedMs: Date.now() - t0
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
    // v2 origin-hunting output
    originNetworks,
    cliSuggestion,
    cliTargets: cliValidTargets,
    cliNames,
    options: {
      sources: sourceIds, includeExpired: !!includeExpired,
      bruteforce: levelUsed,
      mine: mineEnabled, permutationBudget: permBudget, recursive: recursiveEnabled,
      resolverLeak: resolverLeak !== false,
      originHints: hintsEnabled, cert: !!cert, inventoryServers: servers.length,
      wordlist: wordlistUsage
    }
  };
  stage('done', { stats });
  return result;
}

/** Stage names in the order they are reported (extension). */
export const SCAN_STAGES = Object.freeze([...STAGES]);
