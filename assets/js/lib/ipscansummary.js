/**
 * ipscansummary.js — "Copy summary" of the IP Scan view (views/ipscan.js): the builder and its
 * texts, in lib/summarycore.js's model (its BUILDER_KIT). They load with the view alone:
 * views/ipscan.js registers {@link ipscanSummary} (summarycore.registerSummaryBuilder) and
 * {@link IPSCAN_SUMMARY_I18N}. Addresses and states only — the range, the counts, the free
 * addresses folded into ranges, the taken ones —, never a server name, a MAC address or a DNS
 * name of the reports; the link carries the range, never a report. DOM-free.
 */

import { BUILDER_KIT } from './summarycore.js';

const { kit, doc, code, strong, whenText } = BUILDER_KIT;

/** Free ranges a summary names before "+N more". */
const IPSCAN_MAX_FREE = 5;
/** Taken addresses a summary names before "+N more". */
const IPSCAN_MAX_TAKEN = 8;

/**
 * The IP Scan view: the range and its counts, the free addresses (confirmed ones first when the
 * scan confirmed any), the taken ones with their state, and what the map could not know (no scan,
 * addresses no report covers).
 * @param {{ range: string, counts: Record<string, number>, scanned: number, free: string[], confirmed: string[],
 *   taken: Array<{ ip: string, state: string }>, reports: number, at: Date|null }} facts lib/ipscan.js ipscanSummaryFacts
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {import('./summarycore.js').SummaryDoc}
 */
export function ipscanSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const c = facts.counts || {};
  const n = (key) => Number(c[key]) || 0;
  const lines = [];
  const counts = [t('sum.ipscan.addresses', { count: n('total') })];
  if (facts.reports) {
    counts.push(t('sum.ipscan.used', { count: n('used') }));
    if (n('claimed')) counts.push(t('sum.ipscan.claimed', { count: n('claimed') }));
    counts.push(n('freeConfirmed') ? t('sum.ipscan.freeConfirmed', { count: n('free'), confirmed: n('freeConfirmed') }) : t('sum.ipscan.free', { count: n('free') }));
  } else if (n('claimed')) {
    counts.push(t('sum.ipscan.claimed', { count: n('claimed') }));
  }
  if (n('reserved')) counts.push(t('sum.ipscan.reserved', { count: n('reserved') }));
  if (n('unscanned') && facts.reports) counts.push(t('sum.ipscan.unscanned', { count: n('unscanned') }));
  lines.push([counts.join(' · ')]);
  if (!facts.reports) {
    lines.push([t('sum.ipscan.noScan')]);
  } else {
    const list = (facts.confirmed && facts.confirmed.length ? facts.confirmed : facts.free) || [];
    if (list.length) {
      lines.push([strong(`${t(facts.confirmed && facts.confirmed.length ? 'sum.ipscan.freeListConfirmed' : 'sum.ipscan.freeList')}:`), ' ',
        ...k.values(list, IPSCAN_MAX_FREE)]);
    } else {
      lines.push([t('sum.ipscan.noneFree')]);
    }
  }
  const taken = facts.taken || [];
  if (taken.length) {
    const parts = [strong(`${t('sum.ipscan.taken', { count: taken.length })}:`), ' '];
    taken.slice(0, IPSCAN_MAX_TAKEN).forEach((x, i) => parts.push(i ? ', ' : '', code(x.ip), ` (${t(`sum.ipscan.state.${x.state === 'claimed' ? 'claimed' : 'used'}`)})`));
    if (taken.length > IPSCAN_MAX_TAKEN) parts.push(` ${t('common.moreCount', { count: taken.length - IPSCAN_MAX_TAKEN })}`);
    lines.push(parts);
  }
  lines.push([t('sum.ipscan.filesStay')]);
  return doc('ipscan', k.title('ipscan', [code(facts.range || '')]), lines,
    { when: whenText(t, facts.reports ? 'sum.at.scanned' : 'sum.at.asOf', facts.at, opts.now || new Date()), url: opts.url });
}

/** English and Turkish texts of the `sum.ipscan.*` keys: [key, [en, tr]] (lib/summarycore.js's shape). */
const STRINGS = [
  ['sum.ipscan.addresses', [{ one: '{count} address', other: '{count} addresses' }, '{count} adres']],
  ['sum.ipscan.used', [{ one: '{count} used', other: '{count} used' }, '{count} dolu']],
  ['sum.ipscan.claimed', [{ one: '{count} claimed (server list or DNS)', other: '{count} claimed (server list or DNS)' }, '{count} kayıtlı (sunucu listesi ya da DNS)']],
  ['sum.ipscan.free', [{ one: '{count} free', other: '{count} free' }, '{count} boş']],
  ['sum.ipscan.freeConfirmed', [{ one: '{count} free ({confirmed} confirmed)', other: '{count} free ({confirmed} confirmed)' }, '{count} boş ({confirmed} doğrulandı)']],
  ['sum.ipscan.reserved', [{ one: '{count} reserved', other: '{count} reserved' }, '{count} ayrılmış']],
  ['sum.ipscan.unscanned', [{ one: '{count} not scanned', other: '{count} not scanned' }, '{count} taranmadı']],
  ['sum.ipscan.noScan', ['No scan yet: only what the server list claims is known.', 'Henüz tarama yok: yalnızca sunucu listesinin sahiplendiği adresler biliniyor.']],
  ['sum.ipscan.freeList', ['Free', 'Boş']],
  ['sum.ipscan.freeListConfirmed', ['Free, confirmed (no device answered ARP)', 'Boş, doğrulandı (ARP’ye hiçbir cihaz yanıt vermedi)']],
  ['sum.ipscan.noneFree', ['No free address in the range', 'Aralıkta boş adres yok']],
  ['sum.ipscan.taken', [{ one: '{count} taken', other: '{count} taken' }, '{count} dolu ya da kayıtlı']],
  ['sum.ipscan.state.used', ['used', 'dolu']],
  ['sum.ipscan.state.claimed', ['claimed', 'kayıtlı']],
  ['sum.ipscan.filesStay', ['The scan reports stay in the browser; the link carries only the range.', 'Tarama raporları tarayıcıda kalır; bağlantı yalnızca aralığı taşır.']]
];

const buildStrings = (lang) => Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));

/**
 * English and Turkish texts of every `sum.ipscan.*` key {@link ipscanSummary} uses; register with
 * `registerStrings('en', IPSCAN_SUMMARY_I18N.en)` / `registerStrings('tr', IPSCAN_SUMMARY_I18N.tr)`.
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const IPSCAN_SUMMARY_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
