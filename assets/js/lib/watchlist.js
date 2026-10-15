/**
 * watchlist.js — the workspace part `watchlist` (lib/workspace.js): the domains this workspace
 * (one customer) is responsible for, as a plain list. Domain portfolio prefills its box from it
 * and can save its box to it; Home counts the list against the registration baseline (`rdapSeen`,
 * lib/regwatch.js): "12 of 50 domains checked in the last 7 days". DOM-free.
 */

import { parseTarget } from './session.js';
import { registrableDomain } from './domain.js';

/** The most domains one watchlist keeps (lib/portfolio.js PORTFOLIO_MAX_DOMAINS is 300 per run). */
export const WATCHLIST_MAX = 500;

/** The window Home counts "checked" in, in days. */
export const WATCHLIST_DAYS = 7;

/**
 * A watchlist as the workspace keeps it: registrable domains, de-duplicated in input order, at
 * most {@link WATCHLIST_MAX}. A string is read like Portfolio's box (whitespace, commas or
 * semicolons between names, `#` comments); an array is read entry by entry. Anything that is not a
 * name (an address, a public suffix, junk) is dropped.
 * @param {unknown} value
 * @returns {string[]}
 */
export function sanitizeWatchlist(value) {
  const tokens = typeof value === 'string'
    ? value.split(/\r?\n/).map((line) => line.replace(/#.*$/, '')).flatMap((line) => line.split(/[\s,;]+/))
    : (Array.isArray(value) ? value : []);
  const out = [];
  const seen = new Set();
  for (const raw of tokens) {
    if (typeof raw !== 'string') continue;
    const target = parseTarget(raw);
    if (!target || target.kind === 'ip') continue;
    const domain = registrableDomain(target.value.replace(/^\*\./, ''));
    if (!domain || seen.has(domain)) continue;
    seen.add(domain);
    out.push(domain);
    if (out.length >= WATCHLIST_MAX) break;
  }
  return out;
}

/**
 * How much of the watchlist the registration baseline has seen lately.
 * @param {unknown} list the workspace part `watchlist`
 * @param {unknown} seen the workspace part `rdapSeen` (lib/regwatch.js's JSON text; only each domain's `at` is read here,
 *   so this module does not pull regwatch.js into the start route)
 * @param {number|Date} now
 * @param {number} [days]
 * @returns {{ total: number, checked: number, days: number }}
 */
export function watchlistCoverage(list, seen, now, days = WATCHLIST_DAYS) {
  const domains = sanitizeWatchlist(list);
  const at = now instanceof Date ? now.getTime() : Number(now);
  const since = at - days * 86400000;
  let known = {};
  try {
    const data = typeof seen === 'string' && seen.trim() ? JSON.parse(seen) : null;
    if (data && data.domains && typeof data.domains === 'object' && !Array.isArray(data.domains)) known = data.domains;
  } catch {
    known = {};
  }
  let checked = 0;
  for (const d of domains) {
    const e = known[d];
    const time = e && e.at ? new Date(e.at).getTime() : NaN;
    if (Number.isFinite(time) && time >= since && time <= at + 86400000) checked += 1;
  }
  return { total: domains.length, checked, days };
}
