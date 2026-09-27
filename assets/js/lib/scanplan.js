/**
 * scanplan.js — the pure parts of the discovery engine (lib/scanner.js) that the views need
 * without running a scan: the stage names, the DNS-query estimate of the plan line, the kinds of
 * host-specific origin hints and the labels a finished scan teaches the learned store. The
 * engine itself (and the DoH client it pulls in) is imported only when a scan starts, so the
 * Subdomains start page never downloads it before the user asks for a scan.
 *
 * lib/scanner.js imports every cap and default below (they bound the scan and its estimate
 * alike, so they are declared once) and re-exports SCAN_STAGES, HOST_SPECIFIC_HINT_KINDS,
 * estimateQueries and learnedLabelsFromScan unchanged.
 *
 * DOM-free, no I/O.
 */

import { normalizeHostname, registrableDomain, isPublicSuffix } from './domain.js';
import {
  getWordlist, WORDLIST_SMALL, WORDLIST_LEVELS, localesForDomain, LOCALE_PACK_CODES, wordlistInfo
} from './wordlist.js';
import { SRV_SERVICES } from './dnsmine.js';
import { isStorableLabel } from './learned.js';

/* ------------------------------------------------------------------------ */
/* Stages, origins, hint kinds                                              */
/* ------------------------------------------------------------------------ */

/** Stage names in the order they are reported (extension). */
export const SCAN_STAGES = Object.freeze(['sources', 'mining', 'wildcard', 'bruteforce', 'permutations', 'resolve', 'hints', 'done']);
/** DNS-discovery origin tags (a name found only through these can be dropped if it looks synthesized). */
export const PROBE_ORIGINS = new Set(['wordlist', 'permutation', 'recursive']);
// Origin-hint kinds that name ONE specific proxied host (a host-specific exact
// origin), as opposed to a general candidate (spf / mx / direct-sibling) that
// applies to every proxied host. Used for the per-host candidate list and the
// server-group attribution.
// 'zone' is the imported zone file's exact origin of one proxied name (exported
// so the views split host-specific from general hints the same way).
export const HOST_SPECIFIC_HINT_KINDS = new Set(['history', 'resolver-leak', 'sibling-domain', 'zone']);

/* ------------------------------------------------------------------------ */
/* Caps and defaults shared by the scan and its estimate                    */
/* ------------------------------------------------------------------------ */

/** SPF include / redirect lookups the origin-hint stage follows per zone (RFC 7208's limit). */
export const MAX_SPF_LOOKUPS = 10;
/** MX hosts the origin-hint stage resolves per zone. */
export const MAX_MX = 10;
// DNS queries mineDnsNames fires per domain: the apex records (NS, SOA, MX, TXT,
// CAA, HTTPS = 6) + _dmarc TXT (1) + one SRV per well-known service. A constant
// for the query estimate (kept in step with dnsmine.js through SRV_SERVICES).
export const MINE_QUERIES_PER_DOMAIN = 7 + SRV_SERVICES.length;
// DNS queries one wildcard check sends (for the query estimate): 2 random labels
// on the chain + 1 per balance-pool resolver (3 by default), each A + AAAA.
export const WILDCARD_QUERIES_PER_PARENT = 2 * (2 + 3);
// Per-apex brute-force ceilings, by wordlist level. `huge` (~130k labels) must
// be fully reachable for a SINGLE apex — its cap sits just above the list size —
// while smaller levels keep a tight cap so a typo in the level cannot balloon a
// small scan. Legacy custom lists / 'medium' use LEGACY_MAX_BRUTEFORCE per base.
export const MAX_BRUTEFORCE_PER_BASE = { small: 4000, smart: 20000, large: 80000, huge: 160000 };
export const LEGACY_MAX_BRUTEFORCE = 60000;
// Hard ceiling on the COMBINED candidate count across every base / domain, so a
// SAN certificate covering many apexes (or a 'huge' sweep of several domains)
// cannot multiply into an unbounded probe storm. One 'huge' apex fits under
// this; a second is trimmed by the fair round-robin and a BRUTEFORCE_TRUNCATED
// warning is surfaced.
export const MAX_BRUTEFORCE_TOTAL = 200000;
/** Permutation candidates one scan tries at most (a larger budget is clamped). */
export const MAX_PERMUTATIONS = 20000;
/** Permutation budget when the config names none. */
export const DEFAULT_PERMUTATION_BUDGET = 1500;
/** Found parents the recursive round sweeps when the config names none. */
export const DEFAULT_RECURSIVE_PARENTS = 8;
// resolver-leak re-resolves each proxied host through a few other resolvers of the pool; this
// caps the extra courtesy queries of one scan.
export const RESOLVER_LEAK_MAX_QUERIES = 300;
// Recursive round: at most RECURSIVE_EXTRA_WORDS custom / learned labels (custom first) are
// tried under each parent, followed by the WHOLE built-in core (WORDLIST_SMALL), and the round
// never exceeds RECURSIVE_MAX candidates.
export const RECURSIVE_EXTRA_WORDS = 100;
export const RECURSIVE_MAX = MAX_PERMUTATIONS;
/** The wordlist levels the scanner knows: small | smart | large | huge. */
export const KNOWN_LEVELS = new Set(WORDLIST_LEVELS);

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
export const CORE_LABELS = new Set(WORDLIST_SMALL);

/**
 * The left-most labels a host name contributes relative to the longest apex it
 * sits under. A host under no apex (another organisation's certificate SAN or
 * extra name) contributes nothing, so its brand label is never learned. Never
 * the full name. `*` / IP-looking names yield nothing.
 */
export function leftmostLabels(name, apexes) {
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
 * A `zoneOnly` host (only the user's zone file names it) is withheld the same way.
 * @param {object} result a ScanResult of lib/scanner.runScan
 * @returns {string[]} unique labels in first-seen order
 */
export function learnedLabelsFromScan(result) {
  const out = [];
  const seen = new Set();
  if (!result || !Array.isArray(result.hosts)) return out;
  const apexes = Array.isArray(result.domains) ? result.domains : [];
  const privateLabels = [];
  for (const host of result.hosts) {
    if (!host || !(host.customOnly || host.zoneOnly)) continue;
    for (const label of leftmostLabels(host.name, apexes)) {
      if (!CORE_LABELS.has(label) && !privateLabels.includes(label)) privateLabels.push(label);
    }
  }
  const probeOnly = (host) => Array.isArray(host.origins) && host.origins.length > 0
    && host.origins.every((o) => PROBE_ORIGINS.has(o) || o === 'bruteforce');
  for (const host of result.hosts) {
    if (!host || host.wildcardSuspect || host.customOnly || host.zoneOnly) continue;
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
/* Query estimate (plan line)                                               */
/* ------------------------------------------------------------------------ */

/** The wordlist size of a level (build-time counts; 0 for off / unknown). */
function levelWordCount(level) {
  if (level === 'off' || !level) return 0;
  if (level === 'small') return WORDLIST_SMALL.length;
  if (level === 'medium') return getWordlist('medium').length;
  const info = wordlistInfo().levels[level];
  return info ? Number(info.approxCount) || 0 : 0;
}

/** The build-time size of a locale pack (0 for unknown). */
function localePackWordCount(code) {
  const info = wordlistInfo().locales[code];
  return info ? Number(info.approxCount) || 0 : 0;
}

/**
 * Honest DNS-query estimate range for a planned scan, as `{ min, max }` with a
 * breakdown — for the UI plan line. The old line counted only the wordlist and so
 * undercounted real runs by ~20-25 %: the permutation budget, the recursive round
 * and the origin-hint queries were missing. This counts every stage.
 *
 * The range is genuine uncertainty, not padding: the wordlist / mining / wildcard
 * queries always fire, so they set the floor; the permutation budget, recursive
 * round, per-host resolver-leak and per-name resolve depend on what is found, so
 * they widen the ceiling. Counts use the same caps the scan enforces
 * (per-base + total brute-force caps, permutation & recursive caps, leak caps).
 * Pure — no DNS, safe to call on every keystroke.
 *
 * @param {object} opts
 * @param {'off'|'small'|'medium'|'smart'|'large'|'huge'} [opts.bruteforce='smart']
 * @param {string[]} [opts.domains] scanned apex domains (already normalized is fine)
 * @param {string[]} [opts.wildcardBases] extra brute-force bases from `*.x` names
 * @param {string[]} [opts.certNames] certificate hostnames (for the seed / resolve floor)
 * @param {string[]} [opts.extraNames] extra input names (seed / resolve floor)
 * @param {string[]|null} [opts.locales] explicit locale packs (null = auto per domain, [] = none)
 * @param {number} [opts.customCount=0] custom-wordlist labels
 * @param {number} [opts.learnedCount=0] learned labels
 * @param {number} [opts.permutationBudget=1500] 0 disables permutations
 * @param {boolean} [opts.recursive=true]
 * @param {number} [opts.recursiveParents=8]
 * @param {boolean} [opts.mine=true]
 * @param {boolean} [opts.originHints=true]
 * @param {boolean} [opts.resolverLeak=true]
 * @returns {{ min: number, max: number, breakdown: { wordlist: number, mining: number, wildcard: number,
 *   permutation: number, recursive: number, resolveMin: number, resolveMax: number, hintsMin: number,
 *   hintsMax: number, bases: number, zones: number } }}
 */
export function estimateQueries({
  bruteforce = 'smart', domains = [], wildcardBases = [], certNames = [], extraNames = [],
  locales = null, customCount = 0, learnedCount = 0,
  permutationBudget = DEFAULT_PERMUTATION_BUDGET, recursive = true, recursiveParents = DEFAULT_RECURSIVE_PARENTS,
  mine = true, originHints = true, resolverLeak = true
} = {}) {
  const level = bruteforce == null ? 'smart' : String(bruteforce);
  const norm = (d) => normalizeHostname(String(d ?? ''), { allowSingleLabel: true });
  const baseSet = [];
  const addBase = (d) => { const n = norm(d); if (n && !isPublicSuffix(n) && !baseSet.includes(n)) baseSet.push(n); };
  for (const d of Array.isArray(domains) ? domains : []) addBase(d);
  const domainBases = [...baseSet]; // the scanned domains (runScan's targetDomains)
  for (const b of Array.isArray(wildcardBases) ? wildcardBases : []) addBase(b);
  const extra = Math.max(0, Number(customCount) || 0) + Math.max(0, Number(learnedCount) || 0);
  const usesPacks = KNOWN_LEVELS.has(level) && level !== 'small';
  const packsFor = (base) => (Array.isArray(locales)
    ? locales.filter((cc) => LOCALE_PACK_CODES.includes(cc))
    : localesForDomain(base));

  // Brute-force candidates, with the scan's per-base and total caps.
  const levelCount = levelWordCount(level);
  let wordlist = 0;
  if (level !== 'off' && (levelCount > 0 || extra > 0)) {
    const perBaseCap = KNOWN_LEVELS.has(level)
      ? (MAX_BRUTEFORCE_PER_BASE[level] || LEGACY_MAX_BRUTEFORCE) + extra
      : (baseSet.length ? Math.max(1, Math.floor(LEGACY_MAX_BRUTEFORCE / baseSet.length)) : LEGACY_MAX_BRUTEFORCE);
    for (const base of baseSet.length ? baseSet : ['']) {
      const packSum = usesPacks ? packsFor(base).reduce((a, cc) => a + localePackWordCount(cc), 0) : 0;
      wordlist += Math.min(levelCount + packSum + extra, perBaseCap);
    }
    wordlist = Math.min(wordlist, MAX_BRUTEFORCE_TOTAL);
  }

  // As runScan: mining runs once per registrable domain of the scanned domains
  // (sourceDomains); the SPF/MX hints per registrable domain ∪ scanned domain
  // (hintZones). Certificate wildcard bases add neither.
  const regZones = [...new Set(domainBases.map((b) => registrableDomain(b) || b))];
  const zones = [...new Set([...regZones, ...domainBases])];
  const mining = mine ? regZones.length * MINE_QUERIES_PER_DOMAIN : 0;
  const wildcard = baseSet.length * WILDCARD_QUERIES_PER_PARENT; // grows with finds, capped elsewhere

  const permBudget = Number.isFinite(permutationBudget) && permutationBudget > 0
    ? Math.min(Math.floor(permutationBudget), MAX_PERMUTATIONS) : 0;
  const recCap = Math.max(0, Math.floor(Number(recursiveParents)) || 0);
  const recursiveMax = recursive && recCap > 0
    ? Math.min(RECURSIVE_MAX, recCap * (WORDLIST_SMALL.length + Math.min(extra, RECURSIVE_EXTRA_WORDS)))
    : 0;

  // Seeds (resolve floor): domains + certificate names + extra names, unique.
  const seedSet = new Set();
  for (const d of baseSet) seedSet.add(d);
  for (const n of [...(Array.isArray(certNames) ? certNames : []), ...(Array.isArray(extraNames) ? extraNames : [])]) {
    const nn = norm(String(n).replace(/^\*\./, ''));
    if (nn) seedSet.add(nn);
  }
  const seedCount = seedSet.size || 1;
  const resolveMin = 2 * seedCount;
  // Up to ~5 % of the swept candidates may resolve in a dense estate (upper bound).
  const resolveMax = 2 * (seedCount + Math.ceil(0.05 * (wordlist + permBudget + recursiveMax)));

  // Origin hints: SPF/MX always run when enabled; resolver-leak depends on how
  // many proxied hosts are found (bounded by the query cap).
  const leakMax = originHints && resolverLeak ? RESOLVER_LEAK_MAX_QUERIES : 0;
  const spfMxPerZone = MAX_SPF_LOOKUPS + 1 + (MAX_SPF_LOOKUPS + MAX_MX) * 2; // spf TXT walk + MX + resolving each
  const hintsMin = originHints ? zones.length * 2 : 0; // at least an MX + apex SPF TXT per zone
  const hintsMax = originHints ? leakMax + zones.length * spfMxPerZone : 0;

  const floor = wordlist + mining + wildcard;
  const min = floor + resolveMin + hintsMin;
  const max = floor + permBudget + recursiveMax + resolveMax + hintsMax;
  return {
    min,
    max,
    breakdown: {
      wordlist, mining, wildcard, permutation: permBudget, recursive: recursiveMax,
      resolveMin, resolveMax, hintsMin, hintsMax, bases: baseSet.length, zones: zones.length
    }
  };
}
