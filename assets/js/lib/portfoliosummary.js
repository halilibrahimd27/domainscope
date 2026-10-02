/**
 * portfoliosummary.js — "Copy summary" of the Domain portfolio (views/portfolio.js): the builder and
 * its texts, in lib/summarycore.js's model (its BUILDER_KIT: the same parts, escaping, footer and
 * rendering). They live here, not in lib/summary.js, so they load with this view alone:
 * views/portfolio.js registers {@link portfolioSummary} (summarycore.registerSummaryBuilder) and
 * {@link PORTFOLIO_SUMMARY_I18N}. DOM-free; runs in browsers and Node 22.
 */

import { BUILDER_KIT } from './summarycore.js';

const { kit, doc, code, strong, whenText } = BUILDER_KIT;

/** Domains a line names before "+N more". */
const MAX_NAMED = 3;

/**
 * Domain portfolio: what expires within 30 days (the portfolio's domains and the name servers'
 * domains), critical registry statuses, domains without a transfer lock, DNSSEC, the mail posture
 * that needs a look, parked domains not locked down, the policy audit's result, and what could not
 * be read (no RDAP, failed lookups, a stopped run). Domain names are code spans; never a record value.
 * @param {object} facts lib/portfolio.js portfolioSummaryFacts()
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {import('./summarycore.js').SummaryDoc}
 */
export function portfolioSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const f = facts || {};
  const lines = [];
  /** Domains as code spans with a note each, then "+N more". */
  const named = (list, note) => {
    const parts = [];
    list.slice(0, MAX_NAMED).forEach((x, i) => {
      if (i) parts.push(', ');
      parts.push(code(x.domain || x));
      const n = note ? note(x) : null;
      if (n) parts.push(` (${n})`);
    });
    if (list.length > MAX_NAMED) parts.push(` ${t('common.moreCount', { count: list.length - MAX_NAMED })}`);
    return parts;
  };
  const days = (x) => (x.daysLeft < 0 ? t('sum.pf.expiredAgo', { count: -x.daysLeft }) : t('sum.pf.daysLeft', { count: x.daysLeft }));

  if ((f.expiring || []).length) lines.push([strong(`${t('sum.pf.expiring')}:`), ' ', ...named(f.expiring, days)]);
  else lines.push([t(f.noRdap || f.stopped ? 'sum.pf.noneExpiringKnown' : 'sum.pf.noneExpiring')]);
  if ((f.nsExpiring || []).length) {
    lines.push([strong(`${t('sum.pf.nsExpiring')}:`), ' ', ...named(f.nsExpiring, (x) => `${days(x)}; ${t('sum.pf.nsOf', { count: x.of.length })}`)]);
  }
  if ((f.critical || []).length) lines.push([strong(`${t('sum.pf.critical')}:`), ' ', ...named(f.critical, (x) => x.codes.join(', '))]);
  if ((f.notRegistered || []).length) lines.push([strong(`${t('sum.pf.notRegistered')}:`), ' ', ...named(f.notRegistered)]);
  if ((f.unlocked || []).length) lines.push([strong(`${t('sum.pf.unlocked')}:`), ' ', ...named(f.unlocked)]);
  const d = f.dnssec || {};
  lines.push([`DNSSEC: ${k.counts([['sum.pf.validated', d.validated], ['sum.pf.signed', d.signed], ['sum.pf.unsigned', d.unsigned]]) || t('sum.pf.notKnown')}`]);
  const mail = [];
  if ((f.spfOver || []).length) mail.push([t('sum.pf.spfOver', { count: f.spfOver.length }), ': ', ...named(f.spfOver)]);
  if ((f.dmarcWeak || []).length) mail.push([t('sum.pf.dmarcWeak', { count: f.dmarcWeak.length }), ': ', ...named(f.dmarcWeak)]);
  for (const m of mail) lines.push([strong(`${t('sum.pf.mail')}:`), ' ', ...m]);
  if ((f.parkedOpen || []).length) lines.push([strong(`${t('sum.pf.parkedOpen')}:`), ' ', ...named(f.parkedOpen)]);
  if (f.policy) {
    const c = f.policy.counts;
    const name = f.policy.name ? [' ', code(f.policy.name)] : [];
    const head = [strong(`${t('sum.pf.policy')}`), ...name, ': '];
    if (!c.failing) lines.push([...head, t(c.unknown ? 'sum.pf.policyPassKnown' : 'sum.pf.policyPass', { count: c.domains, unknown: c.unknown })]);
    else {
      lines.push([...head, t('sum.pf.policyFail', { count: c.failing, total: c.domains }), ' — ',
        ...named(f.policy.failing, (x) => x.rules.slice(0, 3).join(', ') + (x.rules.length > 3 ? ' …' : ''))]);
    }
  }
  const gaps = [
    f.noRdap ? t('sum.pf.noRdap', { count: f.noRdap }) : null,
    f.failedLookups ? t('sum.pf.failed', { count: f.failedLookups }) : null,
    f.stopped ? t('sum.pf.stopped', { count: f.notLooked || 0 }) : null
  ].filter(Boolean);
  if (gaps.length) lines.push([gaps.join(' · ')]);
  return doc('portfolio', k.title('portfolio', [t('sum.pf.domains', { count: f.domains || 0 })]), lines.slice(0, 11),
    { when: whenText(t, 'sum.at.checked', f.at, opts.now || new Date()), url: opts.url });
}

const STRINGS = [
  ['sum.pf.domains', [{ one: '{count} domain', other: '{count} domains' }, '{count} alan adı']],
  ['sum.pf.expiring', ['Expire within 30 days', '30 gün içinde süresi dolanlar']],
  ['sum.pf.noneExpiring', ['No domain expires within 30 days', '30 gün içinde süresi dolan alan adı yok']],
  ['sum.pf.noneExpiringKnown', ['No domain whose expiry is known expires within 30 days', 'Bitiş tarihi bilinenlerden 30 gün içinde süresi dolan yok']],
  ['sum.pf.daysLeft', [{ zero: 'today', one: '{count} day', other: '{count} days' }, { zero: 'bugün', other: '{count} gün' }]],
  ['sum.pf.expiredAgo', [{ one: 'expired {count} day ago', other: 'expired {count} days ago' }, '{count} gün önce doldu']],
  ['sum.pf.nsExpiring', ['Name server domains expiring within 30 days', '30 gün içinde süresi dolan ad sunucusu alan adları']],
  ['sum.pf.nsOf', [{ one: 'name servers of {count} domain', other: 'name servers of {count} domains' }, '{count} alan adının ad sunucuları']],
  ['sum.pf.critical', ['Critical registry status', 'Kritik kayıt durumu']],
  ['sum.pf.notRegistered', ['Not registered', 'Kayıtlı değil']],
  ['sum.pf.unlocked', ['No transfer lock (clientTransferProhibited)', 'Transfer kilidi yok (clientTransferProhibited)']],
  ['sum.pf.validated', ['{count} validated', '{count} doğrulanıyor']],
  ['sum.pf.signed', ['{count} signed', '{count} imzalı']],
  ['sum.pf.unsigned', ['{count} not signed', '{count} imzasız']],
  ['sum.pf.notKnown', ['not known', 'bilinmiyor']],
  ['sum.pf.mail', ['Mail', 'E-posta']],
  ['sum.pf.spfOver', [{ one: 'SPF over 10 lookups on {count} domain', other: 'SPF over 10 lookups on {count} domains' }, '{count} alan adında SPF 10 sorguyu aşıyor']],
  ['sum.pf.dmarcWeak', [{ one: 'no enforcing DMARC policy on {count} domain', other: 'no enforcing DMARC policy on {count} domains' }, '{count} alan adında uygulanan bir DMARC politikası yok']],
  ['sum.pf.parkedOpen', ['Take no mail but not locked down (null MX, -all, p=reject)', 'E-posta almıyor ama kilitlenmemiş (null MX, -all, p=reject)']],
  ['sum.pf.policy', ['Policy', 'Politika']],
  ['sum.pf.policyPass', [{ one: 'the {count} domain meets every rule', other: 'all {count} domains meet every rule' }, '{count} alan adının tamamı her kurala uyuyor']],
  ['sum.pf.policyPassKnown', ['no domain fails a rule; {unknown} could not be checked in full', 'kuralı karşılamayan alan adı yok; {unknown} tanesi tam kontrol edilemedi']],
  ['sum.pf.policyFail', [{ one: '{count} of {total} domains fails', other: '{count} of {total} domains fail' }, '{total} alan adından {count} tanesi kuralları karşılamıyor']],
  ['sum.pf.noRdap', [{ one: '{count} domain without RDAP (registry WHOIS only)', other: '{count} domains without RDAP (registry WHOIS only)' }, '{count} alan adında RDAP yok (yalnızca kayıt kuruluşunun WHOIS hizmeti)']],
  ['sum.pf.failed', [{ one: '{count} lookup failed', other: '{count} lookups failed' }, '{count} sorgu başarısız']],
  ['sum.pf.stopped', [{ one: 'stopped: {count} domain not looked up in full', other: 'stopped: {count} domains not looked up in full' }, 'durduruldu: {count} alan adı tam sorgulanmadı']]
];

function buildStrings(lang) {
  return Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));
}

/**
 * English and Turkish texts of the `sum.pf.*` keys (registered by views/portfolio.js).
 * @type {{ en: Record<string, string|object>, tr: Record<string, string|object> }}
 */
export const PORTFOLIO_SUMMARY_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
