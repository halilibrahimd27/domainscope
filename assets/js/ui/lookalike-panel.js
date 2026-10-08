/**
 * ui/lookalike-panel.js — Domain overview › "Lookalike domains": the typosquats and lookalikes of
 * the overview's domain (lib/lookalike.js), checked on a click, worst first.
 *
 * The list is made in the browser as soon as the panel opens (nothing is sent: it says so): how
 * many names, how many techniques made them, and how many are the workspace's own domains (the
 * recent domains and the inventory's host names), which are never checked or flagged. "Check"
 * asks DNS for each name (NS, then A, AAAA and MX for the ones that exist) and RDAP for the
 * registration date and registrar of the ones in DNS; Stop keeps what landed and the rest can be
 * checked later. A larger budget adds names to the same list ("more on demand") without asking
 * the checked ones again. A lookup that failed shows "⚠ n/a" with its reason, and one Retry asks
 * only the failed lookups again, past the DNS cache. "Look up the certificates of the top N" asks
 * crt.sh, one name at a time, for the current certificates of the worst registered names; two
 * failures in a row end the round (the rest say why). CSV exports every row, worst first.
 *
 * Loaded by views/domain.js on the first click of its "Find lookalikes"; the last list is kept
 * in this module's memory for the page session (a language switch or a visit to another view
 * shows it again with no request), and dropped with "Delete all local data" or a workspace switch.
 */

import { h, clear } from './dom.js';
import { Badge, Button, Card, DataTable, ProgressBar, announce, checkbox, select } from './components.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import { sourceStatus } from '../lib/sourcestatus.js';
import { NaMark, RetryButton, setRetryBusy, statusText } from './source-status.js';
import { downloadText, timestampedName } from './download.js';
import { createLimiter, mergeSignals } from '../lib/util.js';
import { normalizeHostname } from '../lib/domain.js';
import {
  LOOKALIKE_BUDGETS, LOOKALIKE_DEFAULT_BUDGET, LOOKALIKE_CT_TOP, LOOKALIKE_LEVELS, LOOKALIKE_NEW_DAYS, LOOKALIKE_REASONS,
  LOOKALIKE_RECENT_DAYS, LOOKALIKE_TECHNIQUES, LOOKALIKE_RDAP_CONCURRENCY, checkLookalikes, generateLookalikes, lookalikeCsv,
  lookalikeState, lookupCertificates, lookupRegistration, scoreLookalike, targetFootprint
} from '../lib/lookalike.js';

registerStrings('en', {
  'lk.title': 'Lookalike domains',
  'lk.hint': 'Typosquats and lookalikes of {domain}: letters left out, swapped or doubled, keyboard slips (QWERTY and Turkish Q), lookalike letters (0 for o, the Turkish ı ş ğ ç ö ü, Cyrillic and Greek ones, as punycode), other endings and words such as login- or -support. The names are made in your browser.',
  'lk.sends': 'Check sends an NS question for each name to your DoH resolvers, then A, AAAA and MX questions for the names in DNS, and asks their registry’s RDAP server when they were registered. crt.sh is asked only for the top names, on its own button.',
  'lk.nothingSent': 'Nothing has been sent yet.',
  'lk.generated': {
    one: '{count} name to check ({total} made by {techniques} techniques).',
    other: '{count} names to check ({total} made by {techniques} techniques).'
  },
  'lk.own': {
    one: '{count} of them is a domain of your workspace: it is never checked or flagged.',
    other: '{count} of them are domains of your workspace: they are never checked or flagged.'
  },
  'lk.budget': 'Names in the list',
  'lk.budgetAll': 'All ({count})',
  'lk.check': { one: 'Check {count} name', other: 'Check {count} names' },
  'lk.allChecked': 'Every name in the list has been checked. Choose more names above to widen the list.',
  'lk.progress': 'Checking the lookalikes of {domain}',
  'lk.progressCount': '{done} of {total} names',
  'lk.rdapCount': 'registration dates: {done} of {total}',
  'lk.summary': 'In DNS: {registered} of {checked} checked names — {high} high, {medium} medium and {low} low risk.',
  'lk.failed': { one: '{count} lookup failed: {reason}', other: '{count} lookups failed: {reason}' },
  'lk.hideFree': 'Hide the names not in DNS',
  'lk.ct': { one: 'Look up the certificates of the top {count}', other: 'Look up the certificates of the top {count}' },
  'lk.ctHint': 'One crt.sh search per name, one at a time, sending only that name.',
  'lk.ctRunning': 'Asking crt.sh: {done} of {total}',
  'lk.ctNone': 'Certificates are looked up for the names in DNS: check the list first.',
  'lk.ctSkipped': 'crt.sh failed twice in a row: not asked',
  'lk.csv': 'Export CSV',
  'lk.csvDone': 'Saved {file}',
  'lk.done': 'Lookalikes of {domain} checked',
  'lk.stopped': 'Stopped: the names not checked yet can be checked later',
  'lk.retryTarget': 'the failed lookalike lookups',
  'lk.empty': 'No lookalike to show.',

  'lk.col.risk': 'Risk',
  'lk.col.name': 'Domain',
  'lk.col.technique': 'Technique',
  'lk.col.ns': 'Name servers',
  'lk.col.web': 'Web',
  'lk.col.mail': 'Mail',
  'lk.col.created': 'Registered',
  'lk.col.registrar': 'Registrar',
  'lk.col.certs': 'Certificates',
  'lk.col.why': 'Why',

  'lk.cell.notChecked': 'not checked',
  'lk.cell.notInDns': 'not in DNS',
  'lk.cell.yours': 'in your workspace',
  'lk.cell.none': 'none',
  'lk.cell.nullMx': 'takes no mail (null MX)',
  'lk.cell.more': '+{count}',
  'lk.cell.rdapPending': 'looking up…',
  'lk.cell.notFound': 'not in the registry',
  'lk.cell.noRdap': 'no RDAP for this ending',
  'lk.cell.certs': { one: '{count} current certificate', other: '{count} current certificates' },
  'lk.cell.certsNewest': 'newest {date}',
  'lk.cell.noCerts': 'none current',
  'lk.cell.score': 'score {score} of 100',

  'lk.level.high': 'High',
  'lk.level.medium': 'Medium',
  'lk.level.low': 'Low',
  'lk.level.unknown': 'Unknown',
  'lk.level.none': 'Not in DNS',
  'lk.level.pending': 'Not checked',
  'lk.level.own': 'Yours',

  'lk.tech.tld-swap': 'Other ending',
  'lk.tech.homoglyph': 'Lookalike letters',
  'lk.tech.omission': 'Letter left out',
  'lk.tech.transposition': 'Letters swapped',
  'lk.tech.replacement': 'Neighbouring key',
  'lk.tech.repetition': 'Letter doubled',
  'lk.tech.vowel-swap': 'Vowel swapped',
  'lk.tech.hyphenation': 'Hyphen added',
  'lk.tech.addition': 'Character added',
  'lk.tech.dictionary': 'Word added',
  'lk.tech.insertion': 'Neighbouring key added',
  'lk.tech.subdomain': 'Dot added',
  'lk.tech.bitsquatting': 'Bit flip',

  'lk.reason.mx': 'MX',
  'lk.reason.mx.title': 'Has MX records: it can take mail meant for you and send mail as a lookalike of you',
  'lk.reason.web': 'Web',
  'lk.reason.web.title': 'Resolves to a web host',
  'lk.reason.new': 'New',
  'lk.reason.new.title': 'Registered in the last {days} days',
  'lk.reason.recent': 'Recent',
  'lk.reason.recent.title': 'Registered in the last {days} days',
  'lk.reason.cert': 'Certificate',
  'lk.reason.cert.title': 'Has a current certificate in Certificate Transparency',
  'lk.reason.idn': 'IDN',
  'lk.reason.idn.title': 'Lookalike letters (punycode): hard to tell apart in a browser’s address bar',
  'lk.reason.same-ns': 'Same NS',
  'lk.reason.same-ns.title': 'The same name servers as {domain}: often the owner’s own defensive registration',
  'lk.reason.same-ip': 'Same IP',
  'lk.reason.same-ip.title': 'The same addresses as {domain}: often the owner’s own redirect'
});

registerStrings('tr', {
  'lk.title': 'Benzer alan adları',
  'lk.hint': '{domain} adının yazım hatası taklitleri ve benzerleri: eksik, yer değiştirmiş ya da çift yazılmış harfler, klavye kaymaları (QWERTY ve Türkçe Q), benzer harfler (o yerine 0, Türkçe ı ş ğ ç ö ü, Kiril ve Yunan harfleri; punycode olarak), başka uzantılar ve login- ya da -support gibi sözcükler. Adlar tarayıcınızda üretilir.',
  'lk.sends': 'Kontrol et, her ad için DoH çözümleyicilerinize bir NS sorgusu, DNS’te olan adlar için de A, AAAA ve MX sorguları gönderir ve bu adların ne zaman kaydedildiğini kayıt kuruluşlarının RDAP sunucusuna sorar. crt.sh’e yalnızca en riskli adlar için, kendi düğmesiyle sorulur.',
  'lk.nothingSent': 'Henüz hiçbir şey gönderilmedi.',
  'lk.generated': { other: 'Kontrol edilecek ad sayısı: {count} ({techniques} teknikle üretilen {total} addan).' },
  'lk.own': { other: 'Bunlardan {count} tanesi çalışma alanınızdaki bir alan adı; hiçbir zaman kontrol edilmez ya da işaretlenmez.' },
  'lk.budget': 'Listedeki ad sayısı',
  'lk.budgetAll': 'Tümü ({count})',
  'lk.check': { other: '{count} adı kontrol et' },
  'lk.allChecked': 'Listedeki her ad kontrol edildi. Listeyi genişletmek için yukarıdan daha fazla ad seçin.',
  'lk.progress': '{domain} benzerleri kontrol ediliyor',
  'lk.progressCount': '{total} addan {done} tanesi',
  'lk.rdapCount': 'kayıt tarihleri: {total} addan {done} tanesi',
  'lk.summary': 'DNS’te olan: kontrol edilen {checked} addan {registered} tanesi — {high} yüksek, {medium} orta ve {low} düşük risk.',
  'lk.failed': { other: '{count} sorgu başarısız: {reason}' },
  'lk.hideFree': 'DNS’te olmayan adları gizle',
  'lk.ct': { other: 'En riskli {count} adın sertifikalarını sorgula' },
  'lk.ctHint': 'Her ad için bir crt.sh araması; sırayla ve yalnızca o ad gönderilerek.',
  'lk.ctRunning': 'crt.sh’e soruluyor: {total} addan {done} tanesi',
  'lk.ctNone': 'Sertifikalar DNS’te olan adlar için sorgulanır: önce listeyi kontrol edin.',
  'lk.ctSkipped': 'crt.sh üst üste iki kez başarısız oldu: sorulmadı',
  'lk.csv': 'CSV olarak dışa aktar',
  'lk.csvDone': '{file} kaydedildi',
  'lk.done': '{domain} benzerleri kontrol edildi',
  'lk.stopped': 'Durduruldu: kontrol edilmeyen adlar daha sonra kontrol edilebilir',
  'lk.retryTarget': 'başarısız benzer alan adı sorguları',
  'lk.empty': 'Gösterilecek benzer alan adı yok.',

  'lk.col.risk': 'Risk',
  'lk.col.name': 'Alan adı',
  'lk.col.technique': 'Teknik',
  'lk.col.ns': 'Ad sunucuları',
  'lk.col.web': 'Web',
  'lk.col.mail': 'Posta',
  'lk.col.created': 'Kayıt tarihi',
  'lk.col.registrar': 'Kayıt firması',
  'lk.col.certs': 'Sertifikalar',
  'lk.col.why': 'Neden',

  'lk.cell.notChecked': 'kontrol edilmedi',
  'lk.cell.notInDns': 'DNS’te yok',
  'lk.cell.yours': 'çalışma alanınızda',
  'lk.cell.none': 'yok',
  'lk.cell.nullMx': 'posta kabul etmiyor (null MX)',
  'lk.cell.more': '+{count}',
  'lk.cell.rdapPending': 'sorgulanıyor…',
  'lk.cell.notFound': 'kayıt kuruluşunda yok',
  'lk.cell.noRdap': 'bu uzantı için RDAP yok',
  'lk.cell.certs': { other: '{count} geçerli sertifika' },
  'lk.cell.certsNewest': 'en yenisi {date}',
  'lk.cell.noCerts': 'geçerli sertifika yok',
  'lk.cell.score': 'puan: 100 üzerinden {score}',

  'lk.level.high': 'Yüksek',
  'lk.level.medium': 'Orta',
  'lk.level.low': 'Düşük',
  'lk.level.unknown': 'Bilinmiyor',
  'lk.level.none': 'DNS’te yok',
  'lk.level.pending': 'Kontrol edilmedi',
  'lk.level.own': 'Sizin',

  'lk.tech.tld-swap': 'Başka uzantı',
  'lk.tech.homoglyph': 'Benzer harfler',
  'lk.tech.omission': 'Eksik harf',
  'lk.tech.transposition': 'Yer değiştiren harfler',
  'lk.tech.replacement': 'Komşu tuş',
  'lk.tech.repetition': 'Çift harf',
  'lk.tech.vowel-swap': 'Değişen ünlü',
  'lk.tech.hyphenation': 'Eklenen kısa çizgi',
  'lk.tech.addition': 'Eklenen karakter',
  'lk.tech.dictionary': 'Eklenen sözcük',
  'lk.tech.insertion': 'Eklenen komşu tuş',
  'lk.tech.subdomain': 'Eklenen nokta',
  'lk.tech.bitsquatting': 'Bit hatası',

  'lk.reason.mx': 'MX',
  'lk.reason.mx.title': 'MX kaydı var: size gelecek postayı alabilir ve sizin taklidiniz olarak posta gönderebilir',
  'lk.reason.web': 'Web',
  'lk.reason.web.title': 'Bir web sunucusuna çözümleniyor',
  'lk.reason.new': 'Yeni',
  'lk.reason.new.title': 'Son {days} gün içinde kaydedilmiş',
  'lk.reason.recent': 'Yakın tarihli',
  'lk.reason.recent.title': 'Son {days} gün içinde kaydedilmiş',
  'lk.reason.cert': 'Sertifika',
  'lk.reason.cert.title': 'Certificate Transparency’de geçerli bir sertifikası var',
  'lk.reason.idn': 'IDN',
  'lk.reason.idn.title': 'Benzer harfler (punycode): tarayıcının adres çubuğunda ayırt etmesi zor',
  'lk.reason.same-ns': 'Aynı NS',
  'lk.reason.same-ns.title': '{domain} ile aynı ad sunucuları: çoğu zaman sahibinin kendi koruyucu kaydı',
  'lk.reason.same-ip': 'Aynı IP',
  'lk.reason.same-ip.title': '{domain} ile aynı adresler: çoğu zaman sahibinin kendi yönlendirmesi'
});

/**
 * The i18n keys this panel builds from codes (for the i18n coverage test).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...LOOKALIKE_TECHNIQUES.map((x) => `lk.tech.${x}`),
    ...LOOKALIKE_LEVELS.map((x) => `lk.level.${x}`),
    ...LOOKALIKE_REASONS.flatMap((x) => [`lk.reason.${x}`, `lk.reason.${x}.title`])
  ];
}

/** Badge variants of the levels. */
const LEVEL_VARIANTS = Object.freeze({ high: 'error', medium: 'warn', low: 'info', unknown: 'neutral', none: 'neutral', pending: 'neutral', own: 'ok' });

/**
 * The user's own domains: the workspace's recent domains and the inventory's server names that
 * are host names (lib/lookalike.js keeps their registrable domains).
 * @param {object} state the app state (state.js)
 * @returns {string[]}
 */
export function workspaceDomains(state) {
  const out = [];
  try {
    for (const r of state.workspaceData('recent') || []) if (r && typeof r.value === 'string') out.push(r.value);
  } catch { /* no workspace */ }
  const servers = (state.inventory && state.inventory.servers) || [];
  for (const s of servers) {
    for (const n of [s.name, ...(s.aliases || [])]) if (typeof n === 'string' && normalizeHostname(n)) out.push(n);
  }
  return out;
}

/** The last list, kept for the page session: { domain, budget, rows, target, at }. */
let kept = null;
let subscribed = false;

/** Customer data goes with "Delete all local data" and a workspace switch. */
function watchState(state) {
  if (subscribed || !state || typeof state.subscribe !== 'function') return;
  subscribed = true;
  state.subscribe(({ key }) => {
    if (key === 'cleared' || key === 'workspace') kept = null;
  });
}

/**
 * The panel for one domain.
 * @param {{ ctx: object, domain: string }} opts ctx: the Domain overview's view context
 * @returns {{ el: HTMLElement, destroy: () => void }}
 */
export function LookalikePanel({ ctx, domain }) {
  watchState(ctx.state);
  const own = workspaceDomains(ctx.state);
  const reuse = kept && kept.domain === domain ? kept : null;
  let budget = reuse ? reuse.budget : LOOKALIKE_DEFAULT_BUDGET;
  /** The rows by name, so a larger budget keeps what was checked. */
  const byName = new Map((reuse ? reuse.rows : []).map((r) => [r.candidate.name, r]));
  let list = null;
  let rows = [];
  let target = reuse ? reuse.target : null;
  let controller = null;
  let ctRunning = false;
  let rdapPending = new Set();
  const nowMs = () => Date.now();
  const scoreOpts = () => ({ now: nowMs(), target });

  /* --- controls ---------------------------------------------------------------------------- */
  const budgetField = select({
    label: t('lk.budget'),
    className: 'lk-budget',
    size: 'sm',
    options: [],
    onChange: (v) => {
      budget = Number(v) || LOOKALIKE_DEFAULT_BUDGET;
      build();
    }
  });
  budgetField.input.dataset.role = 'lk-budget';
  const checkBtn = Button({ label: t('lk.check', { count: 0 }), icon: 'search', variant: 'primary', dataset: { action: 'lk-check' }, onClick: () => run() });
  const stopBtn = Button({ label: t('common.stop'), icon: 'stop', dataset: { action: 'lk-stop' }, onClick: () => { if (controller) controller.abort(); } });
  stopBtn.hidden = true;
  const ctBtn = Button({ label: t('lk.ct', { count: LOOKALIKE_CT_TOP }), icon: 'certificate', size: 'sm', dataset: { action: 'lk-ct' }, onClick: () => lookUpCerts() });
  const csvBtn = Button({ label: t('lk.csv'), icon: 'download', size: 'sm', variant: 'secondary', dataset: { action: 'lk-csv' }, onClick: () => exportCsv() });
  const hideFree = checkbox({ label: t('lk.hideFree'), checked: true, className: 'lk-hide-free', onChange: () => applyFilter() });
  hideFree.input.dataset.role = 'lk-hide-free';
  const countsEl = h('p', { class: 'text-sm lk-counts', attrs: { 'aria-live': 'polite' } });
  const sentEl = h('p', { class: 'muted text-sm lk-sent' });
  const progress = ProgressBar({ format: (v, max) => t('lk.progressCount', { done: formatNumber(v), total: formatNumber(max) }) });
  progress.el.hidden = true;
  const rdapLine = h('p', { class: 'muted text-xs lk-rdap', hidden: true });
  const statusEl = h('div', { class: 'lk-status' });
  const ctLine = h('p', { class: 'muted text-xs lk-ct-hint' }, t('lk.ctHint'));

  /* --- table ------------------------------------------------------------------------------- */
  const risks = new Map();
  const riskOf = (row) => {
    if (!risks.has(row)) risks.set(row, scoreLookalike(row, scoreOpts()));
    return risks.get(row);
  };
  const touch = (row) => {
    risks.delete(row);
    table.updateRow(row);
  };
  const na = (failures) => NaMark(failures.map((f) => sourceStatus(f)));
  const listCell = (items) => {
    if (!items.length) return h('span', { class: 'muted' }, t('lk.cell.none'));
    const more = items.length > 2 ? h('span', { class: 'muted' }, ` ${t('lk.cell.more', { count: formatNumber(items.length - 2) })}`) : null;
    return h('span', { class: 'lk-list', title: items.join('\n') }, items.slice(0, 2).map((x) => h('span', { class: 'mono lk-item' }, x)), more);
  };
  const dnsFailures = (row, lookups) => (row.dns ? row.dns.failures.filter((f) => lookups.includes(f.lookup)) : []);
  const notDnsYet = (row) => {
    const st = lookalikeState(row);
    if (st === 'own') return h('span', { class: 'muted' }, t('lk.cell.yours'));
    if (st === 'pending') return h('span', { class: 'muted' }, t('lk.cell.notChecked'));
    if (st === 'failed') return na(row.dns.failures);
    if (st === 'free') return h('span', { class: 'muted' }, t('lk.cell.notInDns'));
    return null;
  };

  const columns = [
    {
      key: 'risk', label: t('lk.col.risk'), sortable: true,
      sortValue: (r) => LOOKALIKE_LEVELS.indexOf(riskOf(r).level) * 1e6 + (100 - (riskOf(r).score ?? 0)) * 1e4 + r.candidate.index,
      exportValue: (r) => riskOf(r).level,
      render: (r) => {
        const risk = riskOf(r);
        if (risk.level === 'unknown') return h('span', { class: 'lk-risk', dataset: { level: risk.level } }, na(r.dns.failures));
        return h('span', { class: 'lk-risk', dataset: { level: risk.level } },
          Badge(t(`lk.level.${risk.level}`), { variant: LEVEL_VARIANTS[risk.level] }),
          risk.score !== null && risk.level !== 'none' ? h('span', { class: 'muted text-xs num lk-score', title: t('lk.cell.score', { score: risk.score }) }, String(risk.score)) : null);
      }
    },
    {
      key: 'name', label: t('lk.col.name'), sortable: true, sortValue: (r) => r.candidate.name, searchValue: (r) => `${r.candidate.name} ${r.candidate.unicode}`,
      render: (r) => h('span', { class: 'lk-name', dataset: { name: r.candidate.name } },
        h('span', { class: 'mono lk-unicode' }, r.candidate.unicode),
        r.candidate.idn ? h('span', { class: 'mono muted text-xs lk-ascii' }, r.candidate.name) : null)
    },
    { key: 'technique', label: t('lk.col.technique'), sortable: true, sortValue: (r) => t(`lk.tech.${r.candidate.technique}`), render: (r) => t(`lk.tech.${r.candidate.technique}`) },
    {
      key: 'ns', label: t('lk.col.ns'),
      render: (r) => notDnsYet(r) || listCell(r.dns.ns)
    },
    {
      key: 'web', label: t('lk.col.web'),
      render: (r) => {
        if (!r.dns || r.dns.state !== 'registered') return null;
        const f = dnsFailures(r, ['a', 'aaaa']);
        return f.length && !r.dns.addresses.length ? na(f) : listCell(r.dns.addresses);
      }
    },
    {
      key: 'mail', label: t('lk.col.mail'),
      render: (r) => {
        if (!r.dns || r.dns.state !== 'registered') return null;
        const f = dnsFailures(r, ['mx']);
        if (f.length) return na(f);
        if (r.dns.nullMx) return h('span', { class: 'muted' }, t('lk.cell.nullMx'));
        return listCell(r.dns.mx);
      }
    },
    {
      key: 'created', label: t('lk.col.created'), sortable: true, defaultDir: 'desc',
      sortValue: (r) => (r.rdap && r.rdap.created ? r.rdap.created.getTime() : null),
      render: (r) => {
        if (!r.rdap) return rdapPending.has(r.candidate.registrable) ? h('span', { class: 'muted' }, t('lk.cell.rdapPending')) : null;
        if (r.rdap.state === 'failed') return na([r.rdap.failure]);
        if (r.rdap.state === 'not-found') return h('span', { class: 'muted' }, t('lk.cell.notFound'));
        if (r.rdap.state === 'unsupported') return h('span', { class: 'muted' }, t('lk.cell.noRdap'));
        return r.rdap.created ? h('span', { class: 'num' }, formatDate(r.rdap.created)) : null;
      }
    },
    { key: 'registrar', label: t('lk.col.registrar'), wrap: true, render: (r) => (r.rdap && r.rdap.state === 'ok' ? r.rdap.registrar : null) },
    {
      key: 'certs', label: t('lk.col.certs'),
      render: (r) => {
        if (!r.ct) return null;
        if (r.ct.state === 'failed') return na([r.ct.failure]);
        if (!r.ct.count) return h('span', { class: 'muted' }, t('lk.cell.noCerts'));
        return h('span', { class: 'lk-certs', title: r.ct.issuers.join(', ') }, t('lk.cell.certs', { count: r.ct.count }),
          r.ct.newest ? h('span', { class: 'muted text-xs' }, ` · ${t('lk.cell.certsNewest', { date: formatDate(r.ct.newest) })}`) : null);
      }
    },
    {
      key: 'why', label: t('lk.col.why'), wrap: true,
      render: (r) => {
        const reasons = riskOf(r).reasons;
        if (!reasons.length) return null;
        const params = { domain, days: reasons.includes('new') ? LOOKALIKE_NEW_DAYS : LOOKALIKE_RECENT_DAYS };
        return h('span', { class: 'lk-reasons' }, reasons.map((x) => Badge(t(`lk.reason.${x}`), {
          variant: x === 'same-ns' || x === 'same-ip' ? 'ok' : 'neutral', title: t(`lk.reason.${x}.title`, params), className: 'lk-reason'
        })));
      }
    }
  ];
  const table = DataTable({
    columns,
    rowKey: (r) => r.candidate.name,
    sort: { key: 'risk', dir: 'asc' },
    search: true,
    pageSize: 50,
    export: false,
    cellLabels: true,
    dense: true,
    className: 'lk-table',
    empty: t('lk.empty')
  });

  const actions = h('div', { class: 'lk-actions' }, csvBtn);
  const el = Card({
    title: t('lk.title'),
    icon: 'eye',
    className: 'lk-panel',
    actions,
    children: h('div', { class: 'stack lk-body' },
      h('p', { class: 'text-sm lk-hint' }, t('lk.hint', { domain })),
      h('p', { class: 'muted text-xs lk-sends' }, t('lk.sends')),
      h('div', { class: 'lk-controls' }, budgetField.el, h('div', { class: 'lk-buttons' }, stopBtn, checkBtn)),
      sentEl,
      progress.el,
      rdapLine,
      countsEl,
      statusEl,
      h('div', { class: 'lk-tools' }, hideFree.el, h('div', { class: 'lk-ct' }, ctBtn, ctLine)),
      table.el)
  });
  el.dataset.domain = domain;

  /* --- state ------------------------------------------------------------------------------- */
  function build() {
    list = generateLookalikes(domain, { budget, own });
    if (!list) return;
    rows = list.candidates.map((c) => {
      const old = byName.get(c.name);
      // a candidate kept from a smaller list keeps its answers; its place and own mark are the new list's
      const row = old ? Object.assign(old, { candidate: { ...c } }) : { candidate: c, dns: null, rdap: null, ct: null };
      byName.set(c.name, row);
      return row;
    });
    risks.clear();
    table.setRows(rows);
    renderBudget();
    renderState();
    keep();
  }

  function renderBudget() {
    const choices = [...new Set([...LOOKALIKE_BUDGETS.filter((b) => b < list.total), Math.min(list.total, budget)])].sort((a, b) => a - b);
    budgetField.setOptions(choices.map((b) => ({ value: String(b), label: b >= list.total ? t('lk.budgetAll', { count: formatNumber(list.total) }) : formatNumber(b) })));
    budgetField.input.value = String(Math.min(list.total, budget));
  }

  const toCheck = () => rows.filter((r) => !r.candidate.own && !r.dns);
  const failedRows = () => rows.filter((r) => (r.dns && (r.dns.state === 'failed' || r.dns.failures.length))
    || (r.rdap && r.rdap.state === 'failed') || (r.ct && r.ct.state === 'failed'));
  const ctTargets = () => rows.filter((r) => r.dns && r.dns.state === 'registered' && !r.candidate.own)
    .sort((a, b) => (riskOf(b).score ?? 0) - (riskOf(a).score ?? 0) || a.candidate.index - b.candidate.index).slice(0, LOOKALIKE_CT_TOP);

  function renderState() {
    const running = !!controller;
    const pending = toCheck().length;
    checkBtn.hidden = running || !pending;
    stopBtn.hidden = !running;
    budgetField.input.disabled = running || ctRunning;
    checkBtn.querySelector('.btn-label').textContent = t('lk.check', { count: pending });
    const checked = rows.filter((r) => r.dns);
    clear(sentEl);
    sentEl.append(t('lk.generated', { count: rows.length, total: formatNumber(list.total), techniques: formatNumber(Object.values(list.byTechnique).filter(Boolean).length) }));
    if (list.own) sentEl.append(' ', t('lk.own', { count: list.own }));
    if (!checked.length && !running) sentEl.append(' ', h('strong', { dataset: { note: 'nothing-sent' } }, t('lk.nothingSent')));
    else if (!pending && !running) sentEl.append(' ', t('lk.allChecked'));
    // counts
    clear(countsEl);
    if (checked.length) {
      const by = { high: 0, medium: 0, low: 0 };
      let registered = 0;
      for (const r of checked) {
        if (r.dns.state === 'registered') registered += 1;
        const lv = riskOf(r).level;
        if (Object.hasOwn(by, lv)) by[lv] += 1;
      }
      countsEl.dataset.registered = String(registered);
      countsEl.append(t('lk.summary', {
        registered: formatNumber(registered), checked: formatNumber(checked.length),
        high: formatNumber(by.high), medium: formatNumber(by.medium), low: formatNumber(by.low)
      }));
    }
    renderFailures(running);
    const targets = ctTargets();
    ctBtn.disabled = running || ctRunning || !targets.length;
    ctBtn.querySelector('.btn-label').textContent = t('lk.ct', { count: targets.length || LOOKALIKE_CT_TOP });
    if (!ctRunning) ctLine.textContent = targets.length ? t('lk.ctHint') : t('lk.ctNone');
    csvBtn.disabled = !checked.length;
    applyFilter();
  }

  function renderFailures(running) {
    clear(statusEl);
    if (running || ctRunning) return;
    const statuses = [];
    for (const r of failedRows()) {
      for (const f of (r.dns ? r.dns.failures : [])) statuses.push(sourceStatus(f));
      if (r.rdap && r.rdap.state === 'failed') statuses.push(sourceStatus(r.rdap.failure));
      if (r.ct && r.ct.state === 'failed') statuses.push(sourceStatus(r.ct.failure));
    }
    if (!statuses.length) return;
    const sources = [...new Set(statuses.map((s) => s.source))];
    const retry = RetryButton({ sources, target: t('lk.retryTarget'), dataset: { role: 'lk-retry' }, onClick: (e) => retryFailed(e.currentTarget) });
    statusEl.append(h('p', { class: 'text-sm lk-failed', dataset: { reason: statuses[0].reason } },
      NaMark(statuses.slice(0, 1)), ' ', t('lk.failed', { count: statuses.length, reason: statusText(statuses[0]) }), ' ', retry));
  }

  function applyFilter() {
    const hide = hideFree.input.checked;
    table.setFilter(hide ? (r) => lookalikeState(r) !== 'free' : null);
  }

  function keep() {
    kept = { domain, budget, rows: [...byName.values()], target, at: new Date() };
  }

  /* --- checks ------------------------------------------------------------------------------ */
  async function checkRows(targets, { noCache = false } = {}) {
    const dns = await ctx.getDns();
    const signal = mergeSignals(ctx.signal, controller.signal);
    if (!target) target = await targetFootprint(domain, { dns, signal });
    let done = 0;
    let rdapDone = 0;
    let rdapTotal = 0;
    progress.el.hidden = false;
    progress.setVariant('default');
    progress.setLabel(t('lk.progress', { domain }));
    progress.set(0, targets.length);
    const byCandidate = new Map(targets.map((r) => [r.candidate, r]));
    await checkLookalikes(targets.map((r) => r.candidate), {
      dns,
      signal,
      noCache,
      onDns: (c, res) => {
        const row = byCandidate.get(c);
        row.dns = res;
        row.rdap = null;
        done += 1;
        progress.set(done, targets.length);
        if (res.state === 'registered') {
          rdapTotal += 1;
          rdapPending.add(c.registrable);
          rdapLine.hidden = false;
          rdapLine.textContent = t('lk.rdapCount', { done: formatNumber(rdapDone), total: formatNumber(rdapTotal) });
        }
        touch(row);
      },
      onRdap: (c, res) => {
        const row = byCandidate.get(c);
        row.rdap = res;
        rdapDone += 1;
        rdapPending.delete(c.registrable);
        rdapLine.textContent = t('lk.rdapCount', { done: formatNumber(rdapDone), total: formatNumber(rdapTotal) });
        touch(row);
      }
    });
  }

  async function withRun(work, { announceDone = true } = {}) {
    if (controller || ctRunning) return;
    if (!ctx.requireOnline()) return;
    controller = new AbortController();
    const mine = controller;
    renderState();
    let stopped = false;
    try {
      await work();
      progress.done(t('common.done'));
    } catch (err) {
      if (err && err.name === 'AbortError') stopped = true;
      else ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    } finally {
      if (controller === mine) controller = null;
      rdapPending = new Set();
      if (!ctx.signal.aborted) {
        progress.el.hidden = true;
        rdapLine.hidden = true;
        risks.clear();
        table.updateRows(rows);
        renderState();
        keep();
        if (stopped) announce(t('lk.stopped'));
        else if (announceDone) announce(`${t('lk.done', { domain })}. ${countsEl.textContent}`);
      }
    }
  }

  function run() {
    const targets = toCheck();
    if (!targets.length) return;
    withRun(() => checkRows(targets));
  }

  /** Retry: only the failed lookups, past the DNS cache. */
  function retryFailed(btn) {
    if (btn) setRetryBusy(btn);
    const failed = failedRows();
    const dnsAgain = failed.filter((r) => r.dns && (r.dns.state === 'failed' || r.dns.failures.length));
    const rdapAgain = failed.filter((r) => !dnsAgain.includes(r) && r.rdap && r.rdap.state === 'failed');
    const ctAgain = failed.filter((r) => r.ct && r.ct.state === 'failed');
    withRun(async () => {
      if (dnsAgain.length) await checkRows(dnsAgain, { noCache: true });
      const signal = mergeSignals(ctx.signal, controller.signal);
      const limiter = createLimiter(LOOKALIKE_RDAP_CONCURRENCY);
      await Promise.all(rdapAgain.map((r) => limiter.run(async () => {
        r.rdap = await lookupRegistration(r.candidate.registrable, { signal });
        touch(r);
      }, { signal })));
      if (ctAgain.length) await askCrtsh(ctAgain, signal);
    });
  }

  /** crt.sh for each row, one at a time; two failures in a row end the round. */
  async function askCrtsh(targets, signal) {
    let done = 0;
    let failedInRow = 0;
    let lastFailure = null;
    for (const r of targets) {
      if (failedInRow >= 2) {
        r.ct = { state: 'failed', count: null, newest: null, issuers: [], failure: { ...lastFailure, error: `${t('lk.ctSkipped')}: ${lastFailure.error || ''}` } };
        touch(r);
        continue;
      }
      ctLine.textContent = t('lk.ctRunning', { done: formatNumber(done), total: formatNumber(targets.length) });
      r.ct = await lookupCertificates(r.candidate.name, { signal });
      done += 1;
      if (r.ct.state === 'failed') {
        failedInRow += 1;
        lastFailure = r.ct.failure;
      } else failedInRow = 0;
      touch(r);
    }
  }

  function lookUpCerts() {
    const targets = ctTargets();
    if (!targets.length || controller || ctRunning) return;
    withRun(async () => {
      ctRunning = true;
      try {
        await askCrtsh(targets, mergeSignals(ctx.signal, controller.signal));
      } finally {
        ctRunning = false;
      }
    });
  }

  function exportCsv() {
    const file = downloadText(timestampedName('lookalikes', 'csv', domain), lookalikeCsv(rows, scoreOpts()), 'text/csv;charset=utf-8');
    ctx.toast(t('lk.csvDone', { file }), { type: 'success' });
  }

  build();

  return {
    el,
    destroy() {
      if (controller) controller.abort();
    }
  };
}
