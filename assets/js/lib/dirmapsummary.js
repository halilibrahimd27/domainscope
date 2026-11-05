/**
 * dirmapsummary.js — "Copy summary" of the Endpoint map view (views/dirmap.js): the builder and
 * its texts, in lib/summarycore.js's model (its BUILDER_KIT). They load with the view alone:
 * views/dirmap.js registers {@link dirmapSummary} (summarycore.registerSummaryBuilder) and
 * {@link DIRMAP_SUMMARY_I18N}. Hosts and paths only — never a response body or header of the
 * reports; the link carries nothing (the reports never go into a URL). DOM-free.
 */

import { BUILDER_KIT } from './summarycore.js';

const { kit, doc, code, strong, whenText } = BUILDER_KIT;

/** Paths a summary names before "+N more". */
const DIRMAP_MAX_PATHS = 8;

/**
 * The Endpoint map view: how many hosts and paths the reports cover, the paths that answer
 * (host + path, listings marked), how many are protected or redirect, and what could not be
 * checked.
 * @param {{ hosts: number, reachable: number, counts: Record<string, number>,
 *   found: Array<{ host: string, path: string, listing: boolean }>, protectedCount: number,
 *   redirectCount: number, unchecked: number, reports: number, at: Date|null }} facts lib/dirmap.js dirmapSummaryFacts
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {import('./summarycore.js').SummaryDoc}
 */
export function dirmapSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const c = facts.counts || {};
  const n = (key) => Number(c[key]) || 0;
  const lines = [];
  const head = [t('sum.dirmap.hosts', { count: Number(facts.hosts) || 0 })];
  const tallies = [];
  if (n('found')) tallies.push(t('sum.dirmap.found', { count: n('found') }));
  if (n('listing')) tallies.push(t('sum.dirmap.listing', { count: n('listing') }));
  if (n('protected')) tallies.push(t('sum.dirmap.protected', { count: n('protected') }));
  if (n('redirect')) tallies.push(t('sum.dirmap.redirect', { count: n('redirect') }));
  if (tallies.length) head.push(' · ', tallies.join(' · '));
  lines.push(head);
  const found = facts.found || [];
  if (found.length) {
    const parts = [strong(`${t('sum.dirmap.answered')}:`), ' '];
    found.slice(0, DIRMAP_MAX_PATHS).forEach((f, i) => parts.push(i ? ', ' : '', code(`${f.host}${f.path}`), f.listing ? ` (${t('sum.dirmap.listingMark')})` : ''));
    if (found.length > DIRMAP_MAX_PATHS) parts.push(` ${t('common.moreCount', { count: found.length - DIRMAP_MAX_PATHS })}`);
    lines.push(parts);
  } else {
    lines.push([t('sum.dirmap.none')]);
  }
  if (Number(facts.unchecked) > 0) lines.push(k.cap([t('sum.dirmap.unchecked', { count: Number(facts.unchecked) })]));
  lines.push([t('sum.dirmap.filesStay')]);
  return doc('dirmap', k.title('dirmap', t('sum.dirmap.title', { count: Number(facts.hosts) || 0 })), lines,
    { when: whenText(t, 'sum.at.scanned', facts.at, opts.now || new Date()), url: opts.url });
}

/** English and Turkish texts of the `sum.dirmap.*` keys: [key, [en, tr]]. */
const STRINGS = [
  ['sum.dirmap.title', [{ one: '{count} host', other: '{count} hosts' }, '{count} host']],
  ['sum.dirmap.hosts', [{ one: '{count} host mapped', other: '{count} hosts mapped' }, '{count} host haritalandı']],
  ['sum.dirmap.found', [{ one: '{count} found', other: '{count} found' }, '{count} bulundu']],
  ['sum.dirmap.listing', [{ one: '{count} open listing', other: '{count} open listings' }, '{count} açık listeleme']],
  ['sum.dirmap.protected', [{ one: '{count} protected', other: '{count} protected' }, '{count} korumalı']],
  ['sum.dirmap.redirect', [{ one: '{count} redirect', other: '{count} redirects' }, '{count} yönlendirme']],
  ['sum.dirmap.answered', ['Answered', 'Yanıt veren']],
  ['sum.dirmap.listingMark', ['listing', 'listeleme']],
  ['sum.dirmap.none', ['No path answered', 'Hiçbir yol yanıt vermedi']],
  ['sum.dirmap.unchecked', [{ one: '{count} path not checked (rate limited, timed out or failed)', other: '{count} paths not checked (rate limited, timed out or failed)' }, '{count} yol kontrol edilemedi (hız sınırı, zaman aşımı ya da hata)']],
  ['sum.dirmap.filesStay', ['The scan reports stay in the browser; the link carries nothing.', 'Tarama raporları tarayıcıda kalır; bağlantı hiçbir şey taşımaz.']]
];

const buildStrings = (lang) => Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));

/**
 * English and Turkish texts of every `sum.dirmap.*` key {@link dirmapSummary} uses.
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const DIRMAP_SUMMARY_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
