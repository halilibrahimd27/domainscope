/**
 * permute.js — alterx/dnsgen-style permutation candidates generated from the
 * subdomains already discovered for a domain. Pure and DOM-free (browser + Node).
 *
 * The idea (see projectdiscovery/alterx `permutations.yaml` and
 * AlephNullSK/dnsgen `words.txt`, both MIT — used for inspiration only, not
 * copied): a real environment that has `api.example.com` very likely also has
 * `api2`, `api-dev`, `dev.api`, `stg-api`, `app` … Those env/number/region
 * variants are exactly where an old certificate still lives and where CT logs
 * (which only see issued certs) miss names. We mutate the *discovered* labels
 * (never the apex), rank the output by likelihood, drop names already known and
 * cap the total so the caller can resolve them within a courtesy budget.
 *
 * All candidates are `"<mutated-sub>.<domain>"`; the caller resolves them over
 * DoH and keeps the ones that answer (dropping wildcard look-alikes).
 */

import { isSubdomainOf } from './domain.js';

/** Environment tokens (prefix / suffix / new label). */
export const DEFAULT_ENVS = Object.freeze([
  'dev', 'test', 'stg', 'stage', 'staging', 'uat', 'qa', 'preprod', 'prod',
  'beta', 'demo', 'sandbox', 'old', 'new', 'backup', 'v1', 'v2', 'internal', 'int', 'ext'
]);

/**
 * Region / geo tokens, applied to every domain, so global: each occurs often as a
 * `<token>-x` / `x-<token>` affix in the public lists (SecLists, bitquark,
 * commonspeak2). Codes that double as common words or record names (ca, mx, it,
 * in) are left out. Market-specific tokens (city codes …) go in `opts.regions`.
 */
export const DEFAULT_REGIONS = Object.freeze(['us', 'eu', 'uk', 'de', 'fr', 'jp', 'east', 'west']);

/** Small vendored word set for sibling swaps (api ↔ app ↔ admin …). */
export const DEFAULT_WORDS = Object.freeze([
  'api', 'app', 'admin', 'panel', 'portal', 'cdn', 'static', 'img', 'media',
  'mail', 'vpn', 'db', 'cache', 'redis', 'mq', 'auth', 'sso'
]);

/**
 * Service suffixes appended to a discovered label with no separator:
 * `billing → billingapi`, `shop → shopweb / shopadmin`, `app → appws`. This
 * `base → baseX` pattern is where an origin-only endpoint (often plain HTTP, so
 * never in CT) hides, so it earns a high-ranked tier of its own. Ranked by
 * public-list frequency: how often `<label><suffix>` appears in the shipped
 * public wordlist (wordlist-huge) where `<label>` is itself a listed label.
 * Kept short: each suffix multiplies the seed count.
 */
export const DEFAULT_SUFFIXES = Object.freeze([
  'web', 'api', 'admin', 'app', 'db', 'ws', 'service', 'gw', 'panel', 'srv', 'auth'
]);

// A single DNS label: [a-z0-9_-], 1–63 chars, no leading/trailing '-'.
const LABEL_RE = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;

/** Lowercase, trim, drop one trailing dot. */
function canon(name) {
  let s = String(name ?? '').trim().toLowerCase();
  if (s.length > 1 && s.endsWith('.')) s = s.slice(0, -1);
  return s;
}

/** Every dot-separated label of `sub` valid, and `<sub>.<domain>` ≤ 253. */
function validSub(sub, domain) {
  if (!sub || sub.includes('*')) return false;
  if (sub.length + 1 + domain.length > 253) return false;
  for (const label of sub.split('.')) if (!LABEL_RE.test(label)) return false;
  return true;
}

/**
 * Numeric variants of a label: increment/decrement a trailing number by ±1/±2
 * (zero-pad width preserved), or append 2/3 when there is no trailing number.
 * `api → api2, api3` · `web1 → web2, web0, web3` · `web01 → web02, web00, web03`.
 */
function numberVariants(label) {
  const out = [];
  const m = label.match(/^(.*?)(\d+)$/);
  if (m && m[1] !== '') {
    const stem = m[1];
    const width = m[2].length;
    const n = Number(m[2]);
    for (const d of [1, -1, 2, -2]) {
      const v = n + d;
      if (v < 0) continue;
      out.push(stem + String(v).padStart(width, '0'));
    }
  } else if (m && m[1] === '') {
    // A purely numeric label (e.g. "1"): just ±1/±2.
    const n = Number(m[2]);
    for (const d of [1, -1, 2, -2]) {
      const v = n + d;
      if (v >= 0) out.push(String(v).padStart(m[2].length, '0'));
    }
  } else {
    out.push(`${label}2`, `${label}3`);
  }
  return out;
}

/**
 * Split a sub into its most-specific (left-most) label and the remainder,
 * e.g. `"stg.api"` → `{ first: 'stg', rest: '.api' }`, `"api"` → `{ first:
 * 'api', rest: '' }`. Env/number mutations attach to `first`; dot mutations
 * add a new label around the whole sub.
 */
function splitFirst(sub) {
  const dot = sub.indexOf('.');
  return dot === -1 ? { first: sub, rest: '' } : { first: sub.slice(0, dot), rest: sub.slice(dot) };
}

/**
 * Generate permutation candidates from discovered names.
 *
 * @param {string[]} foundNames hostnames already found for `domain` (full names)
 * @param {string} domain the apex / registrable domain (never itself mutated)
 * @param {object} [opts]
 * @param {number} [opts.budget=1500] hard cap on the number of candidates
 * @param {string[]} [opts.words] sibling word set (default {@link DEFAULT_WORDS})
 * @param {string[]} [opts.envs] environment tokens (default {@link DEFAULT_ENVS})
 * @param {string[]} [opts.regions] region tokens (default {@link DEFAULT_REGIONS})
 * @param {string[]} [opts.suffixes] service suffixes for the `base → baseX` tier (default {@link DEFAULT_SUFFIXES})
 * @param {{ has(name: string): boolean }} [opts.exclude] full names never to emit (e.g. names an
 *   earlier stage already probed); skipped before counting toward the budget, so the budget
 *   goes to new names
 * @returns {string[]} candidate hostnames, ranked, de-duplicated, excluding
 *   already-known and excluded names, never longer than `budget`.
 */
export function permutations(foundNames, domain, { budget = 1500, words, envs, regions, suffixes, exclude } = {}) {
  const apex = canon(domain);
  if (!apex || !apex.includes('.')) return [];
  const cap = Number.isFinite(budget) && budget > 0 ? Math.floor(budget) : 0;
  if (cap === 0) return [];

  const wordSet = (Array.isArray(words) && words.length ? words : DEFAULT_WORDS).map((w) => String(w).toLowerCase());
  const envSet = (Array.isArray(envs) && envs.length ? envs : DEFAULT_ENVS).map((e) => String(e).toLowerCase());
  const regionSet = (Array.isArray(regions) && regions.length ? regions : DEFAULT_REGIONS).map((r) => String(r).toLowerCase());
  const suffixSet = (Array.isArray(suffixes) && suffixes.length ? suffixes : DEFAULT_SUFFIXES).map((s) => String(s).toLowerCase());
  const wordLookup = new Set(wordSet);

  // Discovered subs (below the apex), first-seen order, de-duplicated.
  const known = new Set([apex]);
  const seeds = [];
  const seedSeen = new Set();
  for (const raw of Array.isArray(foundNames) ? foundNames : []) {
    const name = canon(raw);
    if (!name || name.includes('*') || name === apex) continue;
    if (!isSubdomainOf(name, apex)) continue;
    known.add(name);
    const sub = name.slice(0, name.length - apex.length - 1);
    if (sub && !seedSeen.has(sub)) {
      seedSeen.add(sub);
      seeds.push(sub);
    }
  }
  if (!seeds.length) return [];

  const skip = exclude && typeof exclude.has === 'function' ? exclude : null;
  const out = [];
  const emitted = new Set();
  const emit = (sub) => {
    if (out.length >= cap) return false;
    if (!validSub(sub, apex)) return true;
    const full = `${sub}.${apex}`;
    if (known.has(full) || emitted.has(full) || (skip && skip.has(full))) return true;
    emitted.add(full);
    out.push(full);
    return out.length < cap;
  };

  // Mutation tiers, most-likely first. Each tier maps a seed → candidate subs;
  // we iterate tier-by-tier across all seeds so the ranking survives the budget.
  const tiers = [
    // 1. numbers (highest hit-rate for numbered infra)
    (sub) => {
      const { first, rest } = splitFirst(sub);
      return numberVariants(first).map((v) => v + rest);
    },
    // 2. service suffix, no separator (base → baseweb / baseapi / baseadmin):
    //    HTTP/WS endpoints next to a service that CT logs rarely see.
    (sub) => {
      const { first, rest } = splitFirst(sub);
      const r = [];
      for (const suf of suffixSet) {
        if (first === suf || first.endsWith(suf)) continue; // apiapi / ...api already ends in it
        r.push(`${first}${suf}${rest}`);
      }
      return r;
    },
    // 3. env with a dash, attached to the left-most label
    (sub) => {
      const { first, rest } = splitFirst(sub);
      const r = [];
      for (const env of envSet) r.push(`${env}-${first}${rest}`, `${first}-${env}${rest}`);
      return r;
    },
    // 4. env as a new dot-label (level insertion: dev.api / api.dev)
    (sub) => {
      const r = [];
      for (const env of envSet) r.push(`${env}.${sub}`, `${sub}.${env}`);
      return r;
    },
    // 5. sibling word swaps (api → app, admin, panel …)
    (sub) => {
      const { first, rest } = splitFirst(sub);
      if (!wordLookup.has(first)) return [];
      const r = [];
      for (const w of wordSet) if (w !== first) r.push(`${w}${rest}`);
      return r;
    },
    // 6. env with no separator (devapi / apidev)
    (sub) => {
      const { first, rest } = splitFirst(sub);
      const r = [];
      for (const env of envSet) r.push(`${env}${first}${rest}`, `${first}${env}${rest}`);
      return r;
    },
    // 7. regions (dash prefix/suffix + new dot-label)
    (sub) => {
      const { first, rest } = splitFirst(sub);
      const r = [];
      for (const reg of regionSet) r.push(`${reg}-${first}${rest}`, `${first}-${reg}${rest}`, `${reg}.${sub}`);
      return r;
    }
  ];

  // Budget allocation is fair across seeds. Phase 1 gives every seed a share of
  // the budget drawn from the highest-value tiers (numbers, service suffix,
  // env-dash), so a domain with a long CT history no longer spends the whole
  // budget on tier 1 of its first seeds — the service-suffix tier (billing →
  // billingapi) that the recall relies on now reaches every seed. Phase 2 then
  // spends any leftover budget tier-by-tier across all tiers (dups are skipped),
  // preserving the original ranking for the tail. With a single seed the two
  // phases reproduce the original tier-by-tier order exactly.
  const priorityTiers = tiers.slice(0, 3);
  const perSeed = Math.max(4, Math.floor(cap / seeds.length));
  for (const sub of seeds) {
    let n = 0;
    for (const tier of priorityTiers) {
      if (n >= perSeed) break;
      for (const candidate of tier(sub)) {
        const before = out.length;
        if (!emit(candidate)) return out;
        if (out.length > before && ++n >= perSeed) break;
      }
    }
  }
  for (const tier of tiers) {
    for (const sub of seeds) {
      for (const candidate of tier(sub)) {
        if (!emit(candidate)) return out;
      }
    }
  }
  return out;
}
