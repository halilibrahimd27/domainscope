/**
 * reportsummary.js — "Copy summary" of DMARC & TLS reports (views/reports.js): the builder and its
 * texts, in lib/summary.js's model (its {@link BUILDER_KIT}: the same parts, escaping, footer and
 * rendering). They live here, not in lib/summary.js, so they load with the view, not on the start
 * route: views/reports.js registers {@link reportsSummary} (summary.registerSummaryBuilder) and
 * {@link REPORTS_SUMMARY_I18N}. DOM-free; runs in browsers and Node 22.
 */

import { BUILDER_KIT } from './summary.js';
import { sharePercent } from './util.js';

const { kit, doc, code, strong, isoDay, whenText } = BUILDER_KIT;

/** Known sources a DMARC & TLS reports summary lists by address (the rest as "+N more"). */
const REPORTS_MAX_FIXES = 2;
/** Failure types a DMARC & TLS reports summary names. */
const REPORTS_MAX_TLS_TYPES = 3;

/**
 * DMARC & TLS reports: the DMARC compliance with the policy and what the reports cover, whether
 * `p=reject` can come (or, in force, what it refuses now), the known sources to fix first (≤ 2: address, class, failing messages — or
 * those that passed through SPF alone while the SPF record gives a permerror —, the first fix),
 * the unknown senders, whether the classes rest on the current SPF and the permerror it gives,
 * the TLS-RPT success rate and failure types, and the files that could not be read. Never a
 * server's name: a source of the list is "your server". A share has one decimal, as the page says it.
 * @param {{ domain: string, dmarc?: { overview: { compliance: number|null, messages: number, verdict: string, enforced?: boolean,
 *   blockers: Array<{ ip: string, cls: string, reason: string, detail: string|null, fail: number, fixes: string[] }>, blocked: number,
 *   atRisk?: Array<{ ip: string, cls: string, reason: string, detail: string|null, atRisk: number, fixes: string[] }>, atRiskMessages?: number,
 *   spfError?: { reason: string, sources: number }|null, unknown: Array<object>, unknownFail: number },
 *   policy: { p: string, pct: number, testing?: string|null }, reports: number, begin: Date, end: Date,
 *   spf: 'checked'|'failed'|'skipped', spfErrorKey?: string|null }|null, tls?: { success: number, failure: number, rate: number|null, reports: number,
 *   byType: Array<{ type: string, sessions: number }> }|null, problems?: number, at?: Date }} facts lib/dmarcreport.js
 *   dmarcOverview and lib/tlsrpt.js summarizeTls of the domain on screen; `problems`: files or entries that were no report
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {import('./summary.js').SummaryDoc}
 */
export function reportsSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const pct = (x) => k.num(sharePercent(x));
  const lines = [];
  const d = facts.dmarc;
  if (d) {
    const o = d.overview;
    const policy = [code(`p=${d.policy.p}${d.policy.pct < 100 ? `; pct=${d.policy.pct}` : ''}${d.policy.testing === 'y' ? '; t=y' : ''}`)];
    const period = t('sum.rpt.period', { count: d.reports, from: isoDay(d.begin), to: isoDay(d.end) });
    lines.push([strong('DMARC:'), ' ',
      o.compliance === null ? t('sum.rpt.noMail') : t('sum.rpt.compliance', { pct: pct(o.compliance), count: o.messages }), ' · ', ...policy, ` · ${period}`]);
    const blockers = o.blockers || [];
    const atRisk = o.atRisk || [];
    if (o.verdict === 'fix-first') lines.push([t('sum.rpt.verdict.fix-first', { count: blockers.length, messages: o.blocked })]);
    else if (o.verdict === 'enforced') lines.push([blockers.length ? t('sum.rpt.verdict.enforcedLosing', { count: blockers.length, messages: o.blocked }) : t('sum.rpt.verdict.enforced')]);
    // p=reject in force while the SPF record errs: the mail that passed through SPF alone is refused now.
    else if (o.verdict === 'spf-broken') lines.push([t(o.enforced ? 'sum.rpt.verdict.enforcedSpfBroken' : 'sum.rpt.verdict.spf-broken', { count: atRisk.length, messages: o.atRiskMessages || 0 })]);
    else if (o.verdict === 'ready') lines.push([t('sum.rpt.verdict.ready')]);
    const toFix = [...blockers, ...atRisk];
    for (const b of toFix.slice(0, REPORTS_MAX_FIXES)) {
      // A third party is named by the include or bounce domain the page shows; a server of the list never by its name.
      const named = b.detail && ['spf-include', 'include-listed', 'dkim-service'].includes(b.reason) ? [' ', code(b.detail)] : [];
      const count = b.fail ? t('sum.rpt.failing', { count: b.fail }) : t('sum.rpt.spfOnly', { count: b.atRisk });
      lines.push([strong(`${t('sum.rpt.fixFirst')}:`), ' ', code(b.ip), ` (${t(`sum.rpt.cls.${b.cls}`)}`, ...named, `): ${count}`,
        b.fixes && b.fixes.length ? ` — ${t(`sum.rpt.fix.${b.fixes[0]}`)}` : '']);
    }
    if (toFix.length > REPORTS_MAX_FIXES) lines.push([t('sum.rpt.moreFix', { count: toFix.length - REPORTS_MAX_FIXES })]);
    if ((o.unknown || []).length) lines.push([t('sum.rpt.unknown', { count: o.unknown.length, messages: o.unknownFail })]);
    lines.push([d.spf === 'checked' ? t('sum.rpt.spfChecked') : t('sum.rpt.spfNot')]);
    // Why, in the words of the key the facts carry (the view's own: `rpt.spfError.<reason>`).
    if (o.spfError && d.spfErrorKey) lines.push([t('sum.rpt.spfError', { count: o.spfError.sources, why: t(d.spfErrorKey) })]);
  }
  const tls = facts.tls;
  if (tls) {
    const sessions = tls.success + tls.failure;
    lines.push([strong('TLS-RPT:'), ' ', tls.rate === null ? t('sum.rpt.tlsNone') : t('sum.rpt.tlsRate', { pct: pct(tls.rate), count: sessions }),
      ` · ${t('sum.rpt.tlsReports', { count: tls.reports })}`]);
    const types = (tls.byType || []).filter((x) => x.sessions > 0);
    if (types.length) {
      const parts = [strong(`${t('sum.rpt.tlsFailures')}:`), ' '];
      types.slice(0, REPORTS_MAX_TLS_TYPES).forEach((x, i) => parts.push(i ? ', ' : '', code(x.type), ` ${k.num(x.sessions)}`));
      if (types.length > REPORTS_MAX_TLS_TYPES) parts.push(` ${t('common.moreCount', { count: types.length - REPORTS_MAX_TLS_TYPES })}`);
      lines.push(parts);
    }
  }
  if (Number(facts.problems) > 0) lines.push([t('sum.rpt.problems', { count: Number(facts.problems) })]);
  return doc('reports', k.title('reports', [code(facts.domain || '')]), lines, { when: whenText(t, 'sum.at.asOf', null, opts.now || new Date()), url: opts.url });
}

/** English and Turkish texts of the `sum.rpt.*` keys: [key, [en, tr]] (lib/summary.js's shape). */
const STRINGS = [
  ['sum.rpt.compliance', [{ one: '{pct}% of {count} message passes', other: '{pct}% of {count} messages pass' }, '{count} e-postanın %{pct} kadarı geçiyor']],
  ['sum.rpt.noMail', ['no message in the reports', 'raporlarda e-posta yok']],
  ['sum.rpt.period', [{ one: '{count} report, {from} → {to}', other: '{count} reports, {from} → {to}' }, '{count} rapor, {from} → {to}']],
  ['sum.rpt.verdict.fix-first', [{ one: 'Not ready for p=reject: {count} source you use fails DMARC ({messages} messages)', other: 'Not ready for p=reject: {count} sources you use fail DMARC ({messages} messages)' },
    'p=reject için hazır değil: kullandığınız {count} kaynak DMARC’den geçmiyor ({messages} e-posta)']],
  ['sum.rpt.verdict.ready', ['Ready for p=reject: every source you use passes DMARC', 'p=reject için hazır: kullandığınız her kaynak DMARC’den geçiyor']],
  ['sum.rpt.verdict.enforced', ['p=reject is in force, and every source you use passes', 'p=reject yürürlükte ve kullandığınız her kaynak geçiyor']],
  ['sum.rpt.verdict.enforcedLosing', [{ one: 'p=reject is in force, and {count} source you use fails: {messages} of its messages are refused', other: 'p=reject is in force, and {count} sources you use fail: {messages} of their messages are refused' },
    'p=reject yürürlükte ve kullandığınız {count} kaynak geçmiyor: {messages} e-postası reddediliyor']],
  ['sum.rpt.verdict.spf-broken', [{ one: 'Not ready for p=reject: the SPF record gives receivers a permanent error, and {count} source you use passed through SPF alone ({messages} messages)', other: 'Not ready for p=reject: the SPF record gives receivers a permanent error, and {count} sources you use passed through SPF alone ({messages} messages)' },
    'p=reject için hazır değil: SPF kaydı alıcılara kalıcı hata veriyor ve kullandığınız {count} kaynak yalnızca SPF ile geçti ({messages} e-posta)']],
  ['sum.rpt.verdict.enforcedSpfBroken', [{ one: 'p=reject is in force, and the SPF record gives receivers a permanent error: mail of {count} source you use that passed through SPF alone ({messages} messages) is refused now', other: 'p=reject is in force, and the SPF record gives receivers a permanent error: mail of {count} sources you use that passed through SPF alone ({messages} messages) is refused now' },
    'p=reject yürürlükte ve SPF kaydı alıcılara kalıcı hata veriyor: kullandığınız {count} kaynağın yalnızca SPF ile geçen e-postası artık reddediliyor ({messages} e-posta)']],
  ['sum.rpt.fixFirst', ['Fix first', 'Önce düzeltin']],
  ['sum.rpt.failing', [{ one: '{count} message fails', other: '{count} messages fail' }, '{count} e-posta geçmiyor']],
  ['sum.rpt.spfOnly', [{ one: '{count} message passed through SPF alone', other: '{count} messages passed through SPF alone' }, '{count} e-posta yalnızca SPF ile geçti']],
  ['sum.rpt.cls.yours', ['your server', 'sunucunuz']],
  ['sum.rpt.cls.third-party', ['authorized third party', 'yetkili üçüncü taraf']],
  ['sum.rpt.fix.spf-permerror', ['repair the SPF record: receivers get a permanent error from it', 'SPF kaydını onarın: alıcılar ondan kalıcı hata alıyor']],
  ['sum.rpt.fix.dkim-sign', ['sign its mail with DKIM for the domain', 'e-postalarını alan adı için DKIM ile imzalayın']],
  ['sum.rpt.fix.dkim-align', ['it signs DKIM only as another domain: set up DKIM for the domain there', 'DKIM’i yalnızca başka bir alan adı olarak imzalıyor: orada alan adınız için DKIM kurun']],
  ['sum.rpt.fix.dkim-fix', ['the domain’s DKIM signature does not verify', 'alan adının DKIM imzası doğrulanmıyor']],
  ['sum.rpt.fix.spf-add', ['add the address to SPF', 'adresi SPF’e ekleyin']],
  ['sum.rpt.fix.spf-align', ['SPF passes only for another domain: use a return-path under the domain', 'SPF yalnızca başka bir alan adı için geçiyor: alan adınızın altında bir return-path kullanın']],
  ['sum.rpt.moreFix', [{ one: '+{count} more source to fix', other: '+{count} more sources to fix' }, 'düzeltilecek +{count} kaynak daha']],
  ['sum.rpt.unknown', [{ one: 'Unknown senders: {count} source, {messages} failing messages (spoofing?)', other: 'Unknown senders: {count} sources, {messages} failing messages (spoofing?)' },
    'Bilinmeyen göndericiler: {count} kaynak, geçmeyen {messages} e-posta (sahte gönderim mi?)']],
  ['sum.rpt.spfChecked', ['Sources classified against the domain’s current SPF', 'Kaynaklar alan adının güncel SPF kaydına göre sınıflandı']],
  ['sum.rpt.spfNot', ['The current SPF was not checked: classes from the reports alone', 'Güncel SPF kontrol edilmedi: sınıflar yalnızca raporlardan']],
  ['sum.rpt.spfError', [{ one: 'The current SPF gives receivers a permanent error for {count} sending address: {why}', other: 'The current SPF gives receivers a permanent error for {count} sending addresses: {why}' },
    'Alıcılar güncel SPF kaydından {count} gönderen adres için kalıcı hata alıyor: {why}']],
  ['sum.rpt.tlsRate', [{ one: '{pct}% of {count} TLS session succeeded', other: '{pct}% of {count} TLS sessions succeeded' }, '{count} TLS oturumunun %{pct} kadarı başarılı']],
  ['sum.rpt.tlsNone', ['no TLS session reported', 'raporlanan TLS oturumu yok']],
  ['sum.rpt.tlsReports', [{ one: '{count} report', other: '{count} reports' }, '{count} rapor']],
  ['sum.rpt.tlsFailures', ['Failures', 'Hatalar']],
  ['sum.rpt.problems', [{ one: '{count} file or entry was no report or could not be read', other: '{count} files or entries were no report or could not be read' },
    '{count} dosya ya da arşiv girdisi rapor değildi ya da okunamadı']]
];

const buildStrings = (lang) => Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));

/**
 * English and Turkish texts of every `sum.rpt.*` key {@link reportsSummary} uses; register with
 * `registerStrings('en', REPORTS_SUMMARY_I18N.en)` / `registerStrings('tr', REPORTS_SUMMARY_I18N.tr)`.
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const REPORTS_SUMMARY_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
