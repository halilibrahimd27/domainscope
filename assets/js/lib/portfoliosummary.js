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
/** Lines between the title and the footer (12 in all, as every summary): past it the mail and parked lines give way. */
const MAX_LINES = 10;

/**
 * Domain portfolio: what changed in a registration since the workspace's last check (the registrar,
 * a lock removed, a hold, the name servers, the DS records, a renewal), what expires within 30 days (the portfolio's domains and the name servers'
 * domains), name server domains nobody has registered, critical registry statuses, domains without a transfer lock, DNSSEC, the mail posture
 * that needs a look, parked domains not locked down, the policy audit's result, and what could not
 * be read (no RDAP, failed lookups, a stopped run). Past {@link MAX_LINES} the last lines before the
 * policy give way (parked, then mail): what needs a look by name, the policy's result and what
 * could not be read always stay. Domain names are code spans; never a record value.
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

  // a registration that changed since the last check: the first sign of a hijack
  if ((f.changed || []).length) lines.push([strong(`${t('sum.pf.changed')}:`), ' ', ...named(f.changed, (x) => changedWords(x.changes, t))]);
  if ((f.expiring || []).length) lines.push([strong(`${t('sum.pf.expiring')}:`), ' ', ...named(f.expiring, days)]);
  else lines.push([t(f.noRdap || f.stopped ? 'sum.pf.noneExpiringKnown' : 'sum.pf.noneExpiring')]);
  if ((f.nsUnregistered || []).length) {
    lines.push([strong(`${t('sum.pf.nsUnregistered')}:`), ' ', ...named(f.nsUnregistered, (x) => t('sum.pf.nsOf', { count: x.of.length }))]);
  }
  if ((f.nsExpiring || []).length) {
    lines.push([strong(`${t('sum.pf.nsExpiring')}:`), ' ', ...named(f.nsExpiring, (x) => `${days(x)}; ${t('sum.pf.nsOf', { count: x.of.length })}`)]);
  }
  if ((f.critical || []).length) lines.push([strong(`${t('sum.pf.critical')}:`), ' ', ...named(f.critical, (x) => x.codes.join(', '))]);
  if ((f.pendingTransfer || []).length) lines.push([strong(`${t('sum.pf.pendingTransfer')}:`), ' ', ...named(f.pendingTransfer)]);
  if ((f.notRegistered || []).length) lines.push([strong(`${t('sum.pf.notRegistered')}:`), ' ', ...named(f.notRegistered)]);
  if ((f.unlocked || []).length) lines.push([strong(`${t('sum.pf.unlocked')}:`), ' ', ...named(f.unlocked)]);
  const d = f.dnssec || {};
  lines.push([`DNSSEC: ${k.counts([['sum.pf.validated', d.validated], ['sum.pf.signed', d.signed], ['sum.pf.broken', d.broken], ['sum.pf.unsigned', d.unsigned]]) || t('sum.pf.notKnown')}`]);
  const mail = [];
  if ((f.spfOver || []).length) mail.push([t('sum.pf.spfOver', { count: f.spfOver.length }), ': ', ...named(f.spfOver)]);
  if ((f.dmarcWeak || []).length) mail.push([t('sum.pf.dmarcWeak', { count: f.dmarcWeak.length }), ': ', ...named(f.dmarcWeak)]);
  for (const m of mail) lines.push([strong(`${t('sum.pf.mail')}:`), ' ', ...m]);
  if ((f.parkedOpen || []).length) lines.push([strong(`${t('sum.pf.parkedOpen')}:`), ' ', ...named(f.parkedOpen)]);
  // the policy's result and what could not be read: kept whatever comes before them
  const tail = [];
  if (f.policy) {
    const c = f.policy.counts;
    const name = f.policy.name ? [' ', code(f.policy.name)] : [];
    const head = [strong(`${t('sum.pf.policy')}`), ...name, ': '];
    if (!c.failing) tail.push([...head, t(c.unknown ? 'sum.pf.policyPassKnown' : 'sum.pf.policyPass', { count: c.domains, unknown: c.unknown })]);
    else {
      tail.push([...head, t('sum.pf.policyFail', { count: c.failing, total: c.domains }), ' — ',
        ...named(f.policy.failing, (x) => x.rules.slice(0, 3).join(', ') + (x.rules.length > 3 ? ' …' : ''))]);
    }
  }
  const gaps = [
    f.noRdap ? t('sum.pf.noRdap', { count: f.noRdap }) : null,
    f.failedLookups ? t('sum.pf.failed', { count: f.failedLookups }) : null,
    f.stopped ? t('sum.pf.stopped', { count: f.notLooked || 0 }) : null
  ].filter(Boolean);
  if (gaps.length) tail.push([gaps.join(' · ')]);
  return doc('portfolio', k.title('portfolio', [t('sum.pf.domains', { count: f.domains || 0 })]), [...lines.slice(0, MAX_LINES - tail.length), ...tail],
    { when: whenText(t, 'sum.at.checked', f.at, opts.now || new Date()), url: opts.url });
}

/**
 * The words of a domain's registration changes (lib/regwatch.js codes), each once: "registrar, lock removed".
 * @param {Array<{ code: string, item?: string|null }>} changes
 * @param {Function} t
 * @returns {string}
 */
export function changedWords(changes, t) {
  const out = [];
  for (const c of changes || []) {
    const label = c.code === 'hold' ? t('sum.pf.chg.hold', { status: c.item || '' }) : t(`sum.pf.chg.${c.code}`);
    if (!out.includes(label)) out.push(label);
  }
  return out.join(', ');
}

const STRINGS = [
  ['sum.pf.domains', [{ one: '{count} domain', other: '{count} domains' }, '{count} alan adı']],
  ['sum.pf.changed', ['Changed since your last check', 'Son kontrolünüzden beri değişenler']],
  ['sum.pf.chg.unregistered', ['no longer registered', 'artık kayıtlı değil']],
  ['sum.pf.chg.registered', ['registered again', 'yeniden kayıtlı']],
  ['sum.pf.chg.registrar', ['registrar', 'kayıt firması']],
  ['sum.pf.chg.registrar-name', ["registrar's name", 'kayıt firmasının adı']],
  ['sum.pf.chg.lock-removed', ['lock removed', 'kilit kaldırıldı']],
  ['sum.pf.chg.lock-added', ['lock added', 'kilit eklendi']],
  ['sum.pf.chg.hold', ['{status} added', '{status} eklendi']],
  ['sum.pf.chg.status', ['status changed', 'durum değişti']],
  ['sum.pf.chg.ns', ['name servers', 'ad sunucuları']],
  ['sum.pf.chg.ds-removed', ['DS removed', 'DS kaldırıldı']],
  ['sum.pf.chg.ds-changed', ['DS changed', 'DS değişti']],
  ['sum.pf.chg.ds-added', ['DS added', 'DS eklendi']],
  ['sum.pf.chg.expiry-later', ['renewed', 'yenilendi']],
  ['sum.pf.chg.expiry-earlier', ['expiry moved earlier', 'bitiş tarihi öne alındı']],
  ['sum.pf.expiring', ['Expire within 30 days', '30 gün içinde süresi dolanlar']],
  ['sum.pf.noneExpiring', ['No domain expires within 30 days', '30 gün içinde süresi dolan alan adı yok']],
  ['sum.pf.noneExpiringKnown', ['No domain whose expiry is known expires within 30 days', 'Bitiş tarihi bilinenlerden 30 gün içinde süresi dolan yok']],
  ['sum.pf.daysLeft', [{ zero: 'today', one: '{count} day', other: '{count} days' }, { zero: 'bugün', other: '{count} gün' }]],
  ['sum.pf.expiredAgo', [{ one: 'expired {count} day ago', other: 'expired {count} days ago' }, '{count} gün önce doldu']],
  ['sum.pf.nsExpiring', ['Name server domains expiring within 30 days', '30 gün içinde süresi dolan ad sunucusu alan adları']],
  ['sum.pf.nsUnregistered', ['Name server domains not registered (anyone can register them and take over DNS)', 'Kayıtlı olmayan ad sunucusu alan adları (herkes kaydedip DNS’i ele geçirebilir)']],
  ['sum.pf.nsOf', [{ one: 'name servers of {count} domain', other: 'name servers of {count} domains' }, '{count} alan adının ad sunucuları']],
  ['sum.pf.critical', ['Critical registry status', 'Kritik kayıt durumu']],
  ['sum.pf.pendingTransfer', ['Transfer pending (a hijack in progress if nobody here asked for it)', 'Transfer bekliyor (kimse istemediyse ele geçirme girişimi)']],
  ['sum.pf.notRegistered', ['Not registered', 'Kayıtlı değil']],
  ['sum.pf.unlocked', ['No transfer lock', 'Transfer kilidi yok']],
  ['sum.pf.validated', ['{count} validated', '{count} doğrulanıyor']],
  ['sum.pf.signed', ['{count} signed', '{count} imzalı']],
  ['sum.pf.broken', ['{count} broken', '{count} bozuk']],
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
