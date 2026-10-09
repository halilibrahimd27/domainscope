/**
 * monitorsummary.js — "Copy summary" of the Monitoring view (views/monitor.js): the builder and its
 * texts, in lib/summarycore.js's model (its BUILDER_KIT: the same parts, escaping, footer and
 * rendering). They load with the view alone, as DMARC & TLS reports' do: views/monitor.js registers
 * {@link monitorSummary} (summarycore.registerSummaryBuilder) and {@link MONITOR_SUMMARY_I18N}.
 * Names only — the targets and the certificates' names —, never an address a report holds; the
 * link is the view's bare one (the results never go into a URL). DOM-free.
 */

import { BUILDER_KIT } from './summarycore.js';

const { kit, doc, code, strong, isoDay, whenText } = BUILDER_KIT;

/** Targets, certificates or checks a summary line names before "+N more". */
const MONITOR_MAX_NAMED = 5;

/**
 * The Monitoring view: how many targets the open results cover and since when, the targets with a
 * bad change in the last 7 days (with how many), the certificates under 21 days (soonest first), the
 * checks that did not complete and the health grades.
 * @param {{ targets: number, reports: number, runs: number, since: Date|null, bad: Array<{ target: string, count: number }>,
 *   expiring: Array<{ name: string, daysLeft: number }>, incomplete: Array<{ target: string, command: string, stale: boolean }>,
 *   grades: Array<{ target: string, grade: string, score: number|null }>, at: Date|null }} facts lib/monitor.js monitorSummaryFacts
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {import('./summarycore.js').SummaryDoc}
 */
export function monitorSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const lines = [];
  const named = (list, part) => {
    const parts = [];
    list.slice(0, MONITOR_MAX_NAMED).forEach((x, i) => parts.push(i ? ', ' : '', ...part(x)));
    if (list.length > MONITOR_MAX_NAMED) parts.push(` ${t('common.moreCount', { count: list.length - MONITOR_MAX_NAMED })}`);
    return parts;
  };
  const scope = [t('sum.mon.scope', { count: Number(facts.targets) || 0, reports: Number(facts.reports) || 0 })];
  if (facts.since) scope.push(' · ', t('sum.mon.since', { day: isoDay(facts.since) }));
  lines.push(scope);
  const bad = facts.bad || [];
  lines.push(bad.length
    ? [strong(`${t('sum.mon.bad', { count: bad.length })}:`), ' ', ...named(bad, (b) => [code(b.target), ` (${k.num(b.count)})`])]
    : [t('sum.mon.badNone')]);
  const expiring = facts.expiring || [];
  lines.push(expiring.length
    ? [strong(`${t('sum.mon.expiring', { count: expiring.length })}:`), ' ', ...named(expiring, (c) => [code(c.name), ' ',
      c.daysLeft < 0 ? t('sum.mon.expiredAgo', { count: -c.daysLeft }) : t('sum.mon.daysLeft', { count: c.daysLeft })])]
    : [t('sum.mon.expiringNone')]);
  const incomplete = facts.incomplete || [];
  lines.push(incomplete.length
    ? [strong(`${t('sum.mon.incomplete', { count: incomplete.length })}:`), ' ', ...named(incomplete, (x) => [code(x.target), ' ', x.command,
      x.stale ? ` (${t('sum.mon.stale')})` : ''])]
    : [t('sum.mon.complete')]);
  const grades = facts.grades || [];
  if (grades.length) {
    const by = new Map();
    for (const g of grades) by.set(g.grade, (by.get(g.grade) || 0) + 1);
    lines.push([`${t('sum.mon.grades')}: `, [...by].sort(([a], [b]) => (a < b ? -1 : 1)).map(([g, n]) => `${g} ${k.num(n)}`).join(' · ')]);
  }
  return doc('monitor', k.title('monitor', t('sum.mon.title', { count: Number(facts.targets) || 0 })), lines,
    { when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

/** English and Turkish texts of the `sum.mon.*` keys: [key, [en, tr]] (lib/summarycore.js's shape). */
const STRINGS = [
  ['sum.mon.title', [{ one: '{count} target', other: '{count} targets' }, '{count} hedef']],
  ['sum.mon.scope', [{ one: '{count} target, from {reports} reports', other: '{count} targets, from {reports} reports' }, '{reports} rapordan {count} hedef']],
  ['sum.mon.since', ['history since {day}', 'geçmiş {day} tarihinden başlıyor']],
  ['sum.mon.bad', [{ one: 'Bad changes in the last 7 days, {count} target', other: 'Bad changes in the last 7 days, {count} targets' }, 'Son 7 günde kötü değişiklikler, {count} hedef']],
  ['sum.mon.badNone', ['No bad change in the last 7 days', 'Son 7 günde kötü değişiklik yok']],
  ['sum.mon.expiring', [{ one: '{count} certificate under 21 days', other: '{count} certificates under 21 days' }, '21 günden az kalan {count} sertifika']],
  ['sum.mon.expiringNone', ['No certificate expires within 21 days', '21 gün içinde süresi dolan sertifika yok']],
  ['sum.mon.daysLeft', [{ one: '{count} day left', other: '{count} days left' }, '{count} gün kaldı']],
  ['sum.mon.expiredAgo', [{ one: 'expired {count} day ago', other: 'expired {count} days ago' }, '{count} gün önce doldu']],
  ['sum.mon.incomplete', [{ one: '{count} check did not complete', other: '{count} checks did not complete' }, 'Tamamlanmayan {count} kontrol']],
  ['sum.mon.stale', ['not run since', 'o tarihten beri çalışmadı']],
  ['sum.mon.complete', ['Every check completed', 'Her kontrol tamamlandı']],
  ['sum.mon.grades', ['Health grades', 'Sağlık notları']]
];

const buildStrings = (lang) => Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));

/**
 * English and Turkish texts of every `sum.mon.*` key {@link monitorSummary} uses; register with
 * `registerStrings('en', MONITOR_SUMMARY_I18N.en)` / `registerStrings('tr', MONITOR_SUMMARY_I18N.tr)`.
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const MONITOR_SUMMARY_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
