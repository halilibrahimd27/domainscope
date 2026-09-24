/**
 * views/health.js — "Domain Health": one click runs lib/health.domainHealth (NS, SOA, MX,
 * SPF with the recursive 10-lookup budget, DMARC, DKIM, CAA, DNSSEC, wildcard, MTA-STS,
 * TLS-RPT, BIMI, IPv6, HTTPS records and RDAP registration / expiry) and shows:
 *
 * - a summary with a traffic light, a score and ok / info / warning / error counts;
 * - every check grouped (DNS · Email security · Certificates & DNSSEC · Registration),
 *   worst first, each with a severity icon and a translated title + explanation;
 * - detail panels: registration (RDAP, expiry countdown), DNSSEC, email security (SPF tree
 *   with lookup meter, DMARC tags, DKIM selectors), CAA ("which CAs may issue") and the
 *   DNS records that were read.
 *
 * Shareable: `#/health?domain=example.com` (also `name=`) runs on open.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, CopyButton, Disclosure, EmptyState, ExternalLink, Icon, KeyValueList, KindBadge,
  ProgressBar, SegmentedControl, SeverityIcon, textInput
} from '../ui/components.js';
import {
  registerStrings, hasString, formatNumber, formatDate, formatDateTime, formatDuration, formatRelative, daysUntil, getLang
} from '../i18n.js';
import {
  domainHealth, DEFAULT_DKIM_SELECTORS, HEALTH_I18N, SPF_LOOKUP_LIMIT, SPF_VOID_LIMIT, CAA_ISSUERS
} from '../lib/health.js';
import { DNSSEC_ALGORITHMS, DS_DIGEST_TYPES } from '../lib/dnswire.js';
import { classifyResolution, ipVersion, normalizeIP } from '../lib/netinfo.js';
import { normalizeHostname } from '../lib/domain.js';
import { toJson } from '../lib/export.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { mergeSignals, splitList } from '../lib/util.js';

/** Route id (`#/health`). */
export const id = 'health';
/** i18n key of the page title. */
export const titleKey = 'nav.health';
/** Icon name (ui/components.js Icon). */
export const icon = 'activity';

/** Check groups in display order (lib/health HEALTH_CATEGORIES values). */
export const HEALTH_GROUPS = Object.freeze(['dns', 'email', 'security', 'registration']);
/** Severity order, worst first. */
export const SEVERITY_ORDER = Object.freeze(['error', 'warn', 'info', 'ok']);

// Every health.<id>.title / .detail string (EN + TR) ships with lib/health.js.
registerStrings('en', HEALTH_I18N.en);
registerStrings('tr', HEALTH_I18N.tr);

registerStrings('en', {
  'hlt.domain': 'Domain',
  'hlt.placeholder': 'example.com',
  'hlt.run': 'Check health',
  'hlt.options': 'Options',
  'hlt.dkimExtra': 'Extra DKIM selectors',
  'hlt.dkimExtraHint': '{count} common selectors are always tried. Add your own (e.g. from a DKIM-Signature “s=” tag), comma-separated.',
  'hlt.invalid': 'Enter a domain name such as example.com.',
  'hlt.examples': 'Try:',
  'hlt.emptyTitle': 'Check a domain’s DNS, email and registration health',
  'hlt.emptyBody': 'Name servers, SOA, MX, SPF (with the 10-lookup limit), DMARC, DKIM, CAA, DNSSEC, wildcard DNS and RDAP expiry — in one go, from your browser.',
  'hlt.progress': 'Checking {domain}',
  'hlt.step.records': 'DNS records',
  'hlt.step.ns': 'Name servers',
  'hlt.step.mx': 'Mail servers',
  'hlt.step.spf': 'SPF',
  'hlt.step.dmarc': 'DMARC',
  'hlt.step.dkim': 'DKIM selectors',
  'hlt.step.caa': 'CAA',
  'hlt.step.dnssec': 'DNSSEC',
  'hlt.step.wildcard': 'Wildcard test',
  'hlt.step.rdap': 'Registration (RDAP)',
  'hlt.failed': 'The health check could not run',

  'hlt.light.error': 'Problems found',
  'hlt.light.warn': 'Needs attention',
  'hlt.light.ok': 'Healthy',
  'hlt.light.errorBody': 'Fix the errors first — they break mail delivery, resolution or security for real users.',
  'hlt.light.warnBody': 'Nothing is broken, but some settings are weak or risky.',
  'hlt.light.okBody': 'No problems found in {count} checks.',
  'hlt.score': 'Score',
  'hlt.scoreTitle': '100 − 20 per error − 6 per warning. Info items do not count.',
  'hlt.checkedAt': 'Checked {time}',
  'hlt.zone': 'Zone: {zone}',
  'hlt.checkZone': 'Check {zone}',
  'hlt.download': 'Report (JSON)',
  'hlt.count.error': { one: '{count} error', other: '{count} errors' },
  'hlt.count.warn': { one: '{count} warning', other: '{count} warnings' },
  'hlt.count.info': { one: '{count} note', other: '{count} notes' },
  'hlt.count.ok': { one: '{count} passed', other: '{count} passed' },
  'hlt.filter': 'Show',
  'hlt.filter.all': 'All checks',
  'hlt.filter.problems': 'Warnings & errors',
  'hlt.noProblems': 'No warnings or errors in this group.',
  'hlt.checksTitle': 'Checks',
  'hlt.detailsTitle': 'Details',
  'hlt.links': 'More about this domain:',

  'hlt.rdap.title': 'Registration (RDAP)',
  'hlt.rdap.registrar': 'Registrar',
  'hlt.rdap.ianaId': 'IANA ID {id}',
  'hlt.rdap.created': 'Registered',
  'hlt.rdap.updated': 'Last changed',
  'hlt.rdap.expires': 'Expires',
  'hlt.rdap.daysLeft': { zero: 'expires today', one: '{count} day left', other: '{count} days left' },
  'hlt.rdap.daysAgo': { one: 'expired {count} day ago', other: 'expired {count} days ago' },
  'hlt.rdap.status': 'Status',
  'hlt.rdap.nameservers': 'Name servers (registry)',
  'hlt.rdap.dnssec': 'DNSSEC delegation',
  'hlt.rdap.signed': 'signed',
  'hlt.rdap.unsigned': 'not signed',
  'hlt.rdap.server': 'RDAP server',
  'hlt.rdap.abuse': 'Abuse contact',
  'hlt.rdap.domain': 'Registered domain',
  'hlt.rdap.unsupported': 'The .{tld} registry offers no RDAP service, so registration and expiry dates cannot be read from the browser.',
  'hlt.rdap.unsupportedTr': 'For .tr domains use the registry’s own WHOIS: nic.tr / TRABİS.',
  'hlt.rdap.notFound': '{domain} is not registered (the registry answered “not found”).',
  'hlt.rdap.error': 'Registration data could not be retrieved.',
  'hlt.rdap.skipped': 'Not checked.',

  'hlt.dnssec.title': 'DNSSEC',
  'hlt.dnssec.broken': 'Broken — validating resolvers fail',
  'hlt.dnssec.validated': 'Signed and validated',
  'hlt.dnssec.signed': 'Signed, not validated',
  'hlt.dnssec.unsigned': 'Not signed',
  'hlt.dnssec.unknown': 'Unknown',
  'hlt.dnssec.ds': 'DS records (at the parent)',
  'hlt.dnssec.dnskey': 'DNSKEY records (in the zone)',
  'hlt.dnssec.algorithms': 'Algorithms',
  'hlt.dnssec.ede': 'Resolver errors',
  'hlt.dnssec.ksk': 'KSK',
  'hlt.dnssec.zsk': 'ZSK',
  'hlt.col.keyTag': 'Key tag',
  'hlt.col.algorithm': 'Algorithm',
  'hlt.col.digest': 'Digest',
  'hlt.col.role': 'Role',

  'hlt.mail.title': 'Email security',
  'hlt.spf': 'SPF',
  'hlt.spf.none': 'No SPF record.',
  'hlt.spf.lookups': 'DNS lookups: {count} of {limit}',
  'hlt.spf.void': 'Void lookups: {count} of {limit}',
  'hlt.spf.tree': 'Include tree',
  'hlt.spf.lookupCount': { one: '{count} lookup', other: '{count} lookups' },
  'hlt.spf.voidBadge': 'void',
  'hlt.spf.truncated': 'The tree is incomplete (too many nested lookups to follow).',
  'hlt.dmarc': 'DMARC',
  'hlt.dmarc.none': 'No DMARC record.',
  'hlt.dmarc.inherited': 'Inherited from {org}',
  'hlt.dmarc.foundAt': 'Published at _dmarc.{domain}',
  'hlt.dmarc.p': 'Policy (p)',
  'hlt.dmarc.sp': 'Subdomain policy (sp)',
  'hlt.dmarc.pct': 'Applies to (pct)',
  'hlt.dmarc.rua': 'Aggregate reports (rua)',
  'hlt.dmarc.ruf': 'Failure reports (ruf)',
  'hlt.dmarc.align': 'Alignment DKIM / SPF',
  'hlt.dmarc.strict': 'strict',
  'hlt.dmarc.relaxed': 'relaxed',
  'hlt.dkim': 'DKIM',
  'hlt.dkim.none': 'No DKIM key found at the {count} selectors tried.',
  'hlt.dkim.selector': 'Selector',
  'hlt.dkim.key': 'Key',
  'hlt.dkim.state': 'State',
  'hlt.dkim.revoked': 'revoked',
  'hlt.dkim.testing': 'test mode',
  'hlt.dkim.active': 'active',
  'hlt.dkim.wildcard': 'wildcard',
  'hlt.mail.extras': 'MTA-STS · TLS-RPT · BIMI',
  'hlt.present': 'present',
  'hlt.missing': 'not published',

  'hlt.caa.title': 'Which CAs may issue certificates?',
  'hlt.caa.none': 'No CAA record — any certificate authority may issue certificates for this domain.',
  'hlt.caa.foundAt': 'CAA set found at {name}',
  'hlt.caa.issue': 'Certificates',
  'hlt.caa.issuewild': 'Wildcard certificates',
  'hlt.caa.sameAsIssue': 'same as above',
  'hlt.caa.nobody': 'nobody (issuance forbidden)',
  'hlt.caa.anyone': 'any CA',
  'hlt.caa.iodef': 'Violation reports',
  'hlt.caa.records': 'CAA records',
  'hlt.caa.distrusted': 'distrusted since {year}',
  'hlt.caa.error': 'The CAA lookup failed: {error}',

  'hlt.dns.title': 'DNS records',
  'hlt.dns.ns': 'Name servers',
  'hlt.dns.soa': 'SOA',
  'hlt.dns.soaValue': '{mname} · {email} · serial {serial}',
  'hlt.dns.mx': 'Mail servers (MX)',
  'hlt.dns.nullMx': 'null MX — accepts no email',
  'hlt.dns.a': 'IPv4 (A)',
  'hlt.dns.aaaa': 'IPv6 (AAAA)',
  'hlt.dns.txt': 'TXT records',
  'hlt.dns.txtCount': { zero: 'none', one: '{count} record', other: '{count} records' },
  'hlt.dns.https': 'HTTPS record',
  'hlt.dns.wildcard': 'Wildcard DNS',
  'hlt.dns.wildcardYes': 'yes → {values}',
  'hlt.dns.wildcardNo': 'no',
  'hlt.dns.lookupAll': 'Open in DNS Lookup'
});

registerStrings('tr', {
  'hlt.domain': 'Alan adı',
  'hlt.placeholder': 'ornek.com.tr',
  'hlt.run': 'Sağlığı kontrol et',
  'hlt.options': 'Seçenekler',
  'hlt.dkimExtra': 'Ek DKIM seçicileri',
  'hlt.dkimExtraHint': '{count} yaygın seçici her zaman denenir. Kendi seçicilerinizi (ör. DKIM-Signature başlığındaki “s=” değeri) virgülle ayırarak ekleyin.',
  'hlt.invalid': 'ornek.com.tr gibi bir alan adı girin.',
  'hlt.examples': 'Deneyin:',
  'hlt.emptyTitle': 'Bir alan adının DNS, e-posta ve kayıt sağlığını kontrol edin',
  'hlt.emptyBody': 'Ad sunucuları, SOA, MX, SPF (10 sorgu sınırıyla), DMARC, DKIM, CAA, DNSSEC, joker (wildcard) DNS ve RDAP bitiş tarihi — tek seferde, tarayıcınızdan.',
  'hlt.progress': '{domain} kontrol ediliyor',
  'hlt.step.records': 'DNS kayıtları',
  'hlt.step.ns': 'Ad sunucuları',
  'hlt.step.mx': 'E-posta sunucuları',
  'hlt.step.spf': 'SPF',
  'hlt.step.dmarc': 'DMARC',
  'hlt.step.dkim': 'DKIM seçicileri',
  'hlt.step.caa': 'CAA',
  'hlt.step.dnssec': 'DNSSEC',
  'hlt.step.wildcard': 'Joker kayıt testi',
  'hlt.step.rdap': 'Kayıt bilgisi (RDAP)',
  'hlt.failed': 'Sağlık kontrolü çalıştırılamadı',

  'hlt.light.error': 'Sorun bulundu',
  'hlt.light.warn': 'İlgilenilmesi gerekiyor',
  'hlt.light.ok': 'Sağlıklı',
  'hlt.light.errorBody': 'Önce hataları giderin — gerçek kullanıcılar için e-posta teslimini, çözümlemeyi ya da güvenliği bozuyorlar.',
  'hlt.light.warnBody': 'Bozuk bir şey yok ama bazı ayarlar zayıf ya da riskli.',
  'hlt.light.okBody': '{count} kontrolde sorun bulunmadı.',
  'hlt.score': 'Puan',
  'hlt.scoreTitle': '100 − hata başına 20 − uyarı başına 6. Bilgi maddeleri sayılmaz.',
  'hlt.checkedAt': '{time} kontrol edildi',
  'hlt.zone': 'Bölge: {zone}',
  'hlt.checkZone': '{zone} alan adını kontrol et',
  'hlt.download': 'Rapor (JSON)',
  'hlt.count.error': '{count} hata',
  'hlt.count.warn': '{count} uyarı',
  'hlt.count.info': '{count} bilgi',
  'hlt.count.ok': '{count} başarılı',
  'hlt.filter': 'Göster',
  'hlt.filter.all': 'Tüm kontroller',
  'hlt.filter.problems': 'Uyarılar ve hatalar',
  'hlt.noProblems': 'Bu grupta uyarı ya da hata yok.',
  'hlt.checksTitle': 'Kontroller',
  'hlt.detailsTitle': 'Ayrıntılar',
  'hlt.links': 'Bu alan adı hakkında daha fazlası:',

  'hlt.rdap.title': 'Kayıt bilgisi (RDAP)',
  'hlt.rdap.registrar': 'Kayıt firması',
  'hlt.rdap.ianaId': 'IANA no {id}',
  'hlt.rdap.created': 'Kayıt tarihi',
  'hlt.rdap.updated': 'Son değişiklik',
  'hlt.rdap.expires': 'Bitiş tarihi',
  'hlt.rdap.daysLeft': { zero: 'bugün sona eriyor', other: '{count} gün kaldı' },
  'hlt.rdap.daysAgo': '{count} gün önce sona erdi',
  'hlt.rdap.status': 'Durum',
  'hlt.rdap.nameservers': 'Ad sunucuları (kayıt kuruluşu)',
  'hlt.rdap.dnssec': 'DNSSEC yetkilendirmesi',
  'hlt.rdap.signed': 'imzalı',
  'hlt.rdap.unsigned': 'imzasız',
  'hlt.rdap.server': 'RDAP sunucusu',
  'hlt.rdap.abuse': 'Kötüye kullanım iletişimi',
  'hlt.rdap.domain': 'Kayıtlı alan adı',
  'hlt.rdap.unsupported': '.{tld} kayıt kuruluşu RDAP hizmeti sunmuyor; kayıt ve bitiş tarihleri tarayıcıdan okunamıyor.',
  'hlt.rdap.unsupportedTr': '.tr alan adları için kayıt kuruluşunun kendi WHOIS hizmetini kullanın: nic.tr / TRABİS.',
  'hlt.rdap.notFound': '{domain} kayıtlı değil (kayıt kuruluşu “bulunamadı” yanıtı verdi).',
  'hlt.rdap.error': 'Kayıt bilgileri alınamadı.',
  'hlt.rdap.skipped': 'Kontrol edilmedi.',

  'hlt.dnssec.title': 'DNSSEC',
  'hlt.dnssec.broken': 'Bozuk — doğrulayan çözümleyiciler başarısız',
  'hlt.dnssec.validated': 'İmzalı ve doğrulandı',
  'hlt.dnssec.signed': 'İmzalı, doğrulanmadı',
  'hlt.dnssec.unsigned': 'İmzasız',
  'hlt.dnssec.unknown': 'Bilinmiyor',
  'hlt.dnssec.ds': 'DS kayıtları (üst bölgede)',
  'hlt.dnssec.dnskey': 'DNSKEY kayıtları (bölgede)',
  'hlt.dnssec.algorithms': 'Algoritmalar',
  'hlt.dnssec.ede': 'Çözümleyici hataları',
  'hlt.dnssec.ksk': 'KSK',
  'hlt.dnssec.zsk': 'ZSK',
  'hlt.col.keyTag': 'Anahtar etiketi',
  'hlt.col.algorithm': 'Algoritma',
  'hlt.col.digest': 'Özet',
  'hlt.col.role': 'Rol',

  'hlt.mail.title': 'E-posta güvenliği',
  'hlt.spf': 'SPF',
  'hlt.spf.none': 'SPF kaydı yok.',
  'hlt.spf.lookups': 'DNS sorgusu: {count} / {limit}',
  'hlt.spf.void': 'Boş sorgu: {count} / {limit}',
  'hlt.spf.tree': 'Include ağacı',
  'hlt.spf.lookupCount': '{count} sorgu',
  'hlt.spf.voidBadge': 'boş',
  'hlt.spf.truncated': 'Ağaç eksik (izlenecek iç içe sorgu sayısı çok fazla).',
  'hlt.dmarc': 'DMARC',
  'hlt.dmarc.none': 'DMARC kaydı yok.',
  'hlt.dmarc.inherited': '{org} alan adından devralındı',
  'hlt.dmarc.foundAt': '_dmarc.{domain} adresinde yayınlanıyor',
  'hlt.dmarc.p': 'Politika (p)',
  'hlt.dmarc.sp': 'Alt alan adı politikası (sp)',
  'hlt.dmarc.pct': 'Uygulama oranı (pct)',
  'hlt.dmarc.rua': 'Toplu raporlar (rua)',
  'hlt.dmarc.ruf': 'Hata raporları (ruf)',
  'hlt.dmarc.align': 'Hizalama DKIM / SPF',
  'hlt.dmarc.strict': 'katı',
  'hlt.dmarc.relaxed': 'esnek',
  'hlt.dkim': 'DKIM',
  'hlt.dkim.none': 'Denenen {count} seçicide DKIM anahtarı bulunamadı.',
  'hlt.dkim.selector': 'Seçici',
  'hlt.dkim.key': 'Anahtar',
  'hlt.dkim.state': 'Durum',
  'hlt.dkim.revoked': 'iptal edilmiş',
  'hlt.dkim.testing': 'test modu',
  'hlt.dkim.active': 'etkin',
  'hlt.dkim.wildcard': 'joker',
  'hlt.mail.extras': 'MTA-STS · TLS-RPT · BIMI',
  'hlt.present': 'var',
  'hlt.missing': 'yayınlanmamış',

  'hlt.caa.title': 'Hangi sertifika otoriteleri sertifika verebilir?',
  'hlt.caa.none': 'CAA kaydı yok — herhangi bir sertifika otoritesi bu alan adı için sertifika verebilir.',
  'hlt.caa.foundAt': 'CAA kümesi {name} adresinde bulundu',
  'hlt.caa.issue': 'Sertifikalar',
  'hlt.caa.issuewild': 'Joker (wildcard) sertifikalar',
  'hlt.caa.sameAsIssue': 'yukarıdakiyle aynı',
  'hlt.caa.nobody': 'hiçbiri (sertifika verilmesi yasak)',
  'hlt.caa.anyone': 'herhangi bir CA',
  'hlt.caa.iodef': 'İhlal bildirimleri',
  'hlt.caa.records': 'CAA kayıtları',
  'hlt.caa.distrusted': '{year} yılından beri güvenilmiyor',
  'hlt.caa.error': 'CAA sorgusu başarısız oldu: {error}',

  'hlt.dns.title': 'DNS kayıtları',
  'hlt.dns.ns': 'Ad sunucuları',
  'hlt.dns.soa': 'SOA',
  'hlt.dns.soaValue': '{mname} · {email} · seri {serial}',
  'hlt.dns.mx': 'E-posta sunucuları (MX)',
  'hlt.dns.nullMx': 'null MX — e-posta kabul etmiyor',
  'hlt.dns.a': 'IPv4 (A)',
  'hlt.dns.aaaa': 'IPv6 (AAAA)',
  'hlt.dns.txt': 'TXT kayıtları',
  'hlt.dns.txtCount': { zero: 'yok', other: '{count} kayıt' },
  'hlt.dns.https': 'HTTPS kaydı',
  'hlt.dns.wildcard': 'Joker (wildcard) DNS',
  'hlt.dns.wildcardYes': 'evet → {values}',
  'hlt.dns.wildcardNo': 'hayır',
  'hlt.dns.lookupAll': 'DNS Sorgulama’da aç'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/**
 * Health score: 100 − 20 per error − 6 per warning, clamped to 0…100.
 * @param {{ ok?: number, info?: number, warn?: number, error?: number }} summary
 * @returns {number}
 */
export function healthScore(summary) {
  const s = summary || {};
  const score = 100 - 20 * (Number(s.error) || 0) - 6 * (Number(s.warn) || 0);
  return Math.max(0, Math.min(100, score));
}

/**
 * Traffic-light state for a summary: any error → 'error', any warning → 'warn', else 'ok'.
 * @param {{ warn?: number, error?: number }} summary
 * @returns {'error'|'warn'|'ok'}
 */
export function trafficLight(summary) {
  const s = summary || {};
  if (Number(s.error) > 0) return 'error';
  if (Number(s.warn) > 0) return 'warn';
  return 'ok';
}

/**
 * Checks of one group, worst severity first (stable within a severity).
 * @param {Array<{ severity: string, group?: string }>} checks
 * @param {string} group
 * @returns {object[]}
 */
export function groupChecks(checks, group) {
  const rank = (c) => {
    const i = SEVERITY_ORDER.indexOf(c.severity);
    return i === -1 ? SEVERITY_ORDER.length : i;
  };
  return (Array.isArray(checks) ? checks : [])
    .map((c, i) => ({ c, i }))
    .filter(({ c }) => (c.group || 'dns') === group)
    .sort((a, b) => rank(a.c) - rank(b.c) || a.i - b.i)
    .map(({ c }) => c);
}

/**
 * Extra DKIM selectors typed by the user → valid, lower-case, de-duplicated names that are
 * not already in the default list.
 * @param {string} text
 * @returns {string[]}
 */
export function parseSelectors(text) {
  const out = [];
  for (const token of splitList(text)) {
    const s = token.toLowerCase().replace(/\._domainkey.*$/, '');
    if (/^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$/.test(s) && !DEFAULT_DKIM_SELECTORS.includes(s) && !out.includes(s)) out.push(s);
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

let active = null;

/**
 * Mount the Domain Health view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const restored = ctx.restored && typeof ctx.restored === 'object' ? ctx.restored : null;
  const initialDomain = restored?.domain ?? ctx.params.domain ?? ctx.params.name ?? '';

  /* --- helpers ------------------------------------------------------------------ */
  const hostLink = (host, type = 'A,AAAA') => h('a', { class: 'hlt-host mono', href: ctx.href('lookup', { name: host, type }) }, host);
  const ipLink = (ip) => h('a', { class: 'hlt-ip mono', href: ctx.href('ip', { ips: ip }) }, ip);
  /** Translate a check key; fall back to readable text when a key is missing. */
  const tr = (key, params, fallback) => (hasString(key, getLang()) || hasString(key, 'en') ? t(key, params) : fallback);
  // lib/health passes booleans as the English words 'yes' / 'no': show them in the UI language.
  const localParams = (params) => Object.fromEntries(Object.entries(params || {}).map(([k, v]) => [k, v === 'yes' ? t('common.yes') : v === 'no' ? t('common.no') : v]));
  const checkTitle = (c) => tr(c.titleKey, localParams(c.params), c.id);
  const checkDetail = (c) => tr(c.detailKey, localParams(c.params), Object.entries(c.params || {}).map(([k, v]) => `${k}: ${v}`).join(' · '));
  const caNameFor = (issuer) => {
    const ca = CAA_ISSUERS.find((x) => x.domains.includes(String(issuer).toLowerCase()));
    return ca || null;
  };
  const algName = (n) => (DNSSEC_ALGORITHMS[n] ? `${DNSSEC_ALGORITHMS[n]} (${n})` : String(n));
  const ipList = (ips) => (ips && ips.length ? h('div', { class: 'cluster hlt-ips' }, ips.map(ipLink)) : null);
  const miniTable = (headers, rows, className = '') => h('div', { class: ['dt-scroll', 'dt-scroll-free', 'hlt-table', className], attrs: { tabindex: 0 } },
    h('table', { class: 'dt-table dt-dense' },
      h('thead', null, h('tr', null, headers.map((x) => h('th', { attrs: { scope: 'col' } }, x)))),
      h('tbody', null, rows.map((cells) => h('tr', { class: 'dt-row' }, cells.map((c) => h('td', null, c === null || c === undefined || c === '' ? h('span', { class: 'dt-null' }, '—') : c)))))));

  /* --- form ------------------------------------------------------------------------ */
  const domainField = textInput({
    label: t('hlt.domain'),
    value: initialDomain,
    placeholder: t('hlt.placeholder'),
    mono: true,
    className: 'hlt-domain',
    attrs: { 'data-role': 'health-domain', inputmode: 'url', enterkeyhint: 'go' },
    onEnter: () => start()
  });
  const selectorsField = textInput({
    label: t('hlt.dkimExtra'),
    value: restored?.selectors ?? ctx.params.selectors ?? '',
    placeholder: 'mailgun, s1024',
    mono: true,
    attrs: { 'data-role': 'health-selectors' },
    onEnter: () => start()
  });
  selectorsField.setHint(t('hlt.dkimExtraHint', { count: DEFAULT_DKIM_SELECTORS.length }));
  const runBtn = Button({ label: t('hlt.run'), icon: 'activity', variant: 'primary', dataset: { action: 'run' }, onClick: () => start() });
  const stopBtn = Button({ label: t('common.stop'), icon: 'stop', dataset: { action: 'stop' }, onClick: () => { if (current && current.controller) current.controller.abort(); } });
  stopBtn.hidden = true;
  const examples = ['github.com', 'cloudflare.com', 'wikipedia.org', 'example.com'];
  const examplesEl = h('div', { class: 'cluster text-sm hlt-examples' },
    h('span', { class: 'muted' }, t('hlt.examples')),
    examples.map((d) => h('button', {
      type: 'button', class: 'link-btn mono', dataset: { example: d },
      on: { click: () => { domainField.value = d; start(); } }
    }, d)));
  const formCard = Card({
    className: 'hlt-form-card',
    children: h('div', { class: 'stack' },
      h('div', { class: 'hlt-form' }, domainField.el, h('div', { class: 'hlt-buttons' }, stopBtn, runBtn)),
      h('div', { class: 'hlt-form-foot' },
        examplesEl,
        Disclosure({ summary: t('hlt.options'), className: 'hlt-options', open: !!(restored?.selectors || ctx.params.selectors), children: selectorsField.el })))
  });

  /* --- results skeleton ------------------------------------------------------------ */
  const progress = ProgressBar({ label: t('hlt.progress', { domain: '' }) });
  progress.el.hidden = true;
  const errorEl = h('div');
  const heroEl = h('div', { class: 'hlt-hero-wrap' });
  const checksEl = h('div', { class: 'hlt-groups' });
  const detailsEl = h('div', { class: 'hlt-details' });
  let filter = restored?.filter === 'problems' ? 'problems' : 'all';
  const filterCtl = SegmentedControl({
    label: t('hlt.filter'),
    size: 'sm',
    value: filter,
    options: [{ value: 'all', label: t('hlt.filter.all') }, { value: 'problems', label: t('hlt.filter.problems') }],
    onChange: (v) => {
      filter = v;
      if (current && current.report) renderChecks(current.report);
    }
  });
  filterCtl.el.dataset.control = 'health-filter';
  const emptyEl = h('div', { class: 'card hlt-empty' }, EmptyState({ icon: 'activity', title: t('hlt.emptyTitle'), message: t('hlt.emptyBody') }));
  const results = h('div', { class: 'stack-lg hlt-results', hidden: true },
    heroEl,
    h('section', { class: 'stack hlt-checks-section' },
      h('div', { class: 'hlt-section-head' }, h('h2', { class: 'section-title' }, t('hlt.checksTitle')), filterCtl.el),
      checksEl),
    h('section', { class: 'stack hlt-details-section' }, h('h2', { class: 'section-title' }, t('hlt.detailsTitle')), detailsEl));
  container.append(h('div', { class: 'stack-lg hlt-view' }, formCard, progress, errorEl, emptyEl, results));

  /* --- hero ------------------------------------------------------------------------------ */
  function renderHero(report) {
    clear(heroEl);
    const s = report.summary;
    const light = trafficLight(s);
    const score = healthScore(s);
    const total = s.ok + s.info + s.warn + s.error;
    const lightEl = h('div', { class: ['hlt-light', `hlt-light-${light}`], attrs: { role: 'img', 'aria-label': t(`hlt.light.${light}`) } },
      ['error', 'warn', 'ok'].map((k) => h('span', { class: ['hlt-lamp', `hlt-lamp-${k}`, { 'is-on': k === light }] })));
    const counts = h('div', { class: 'hlt-counts' }, SEVERITY_ORDER.map((sev) => h('span', {
      class: ['hlt-count', `hlt-count-${sev}`, { 'is-zero': !s[sev] }], dataset: { severity: sev, count: s[sev] }
    }, SeverityIcon(sev, { size: 15 }), h('span', null, t(`hlt.count.${sev}`, { count: s[sev] })))));
    const zoneLink = report.zone && report.zone !== report.domain
      ? h('a', { class: 'btn btn-secondary btn-sm', href: ctx.href('health', { domain: report.zone }) }, Icon('arrow-right', { size: 14 }), h('span', { class: 'btn-label' }, t('hlt.checkZone', { zone: report.zone })))
      : null;
    heroEl.append(h('div', { class: ['card', 'hlt-hero', `hlt-hero-${light}`], dataset: { light, score } },
      lightEl,
      h('div', { class: 'hlt-hero-main' },
        h('div', { class: 'hlt-hero-domain mono' }, report.domain),
        h('div', { class: 'hlt-hero-verdict' }, t(`hlt.light.${light}`)),
        h('p', { class: 'hlt-hero-body' }, light === 'ok' ? t('hlt.light.okBody', { count: formatNumber(total) }) : t(`hlt.light.${light}Body`)),
        counts,
        h('div', { class: 'hlt-hero-meta muted text-xs' },
          h('span', { title: formatDateTime(report.checkedAt) }, t('hlt.checkedAt', { time: formatRelative(report.checkedAt) })),
          report.zone ? h('span', null, t('hlt.zone', { zone: report.zone })) : null)),
      h('div', { class: 'hlt-hero-side' },
        h('div', { class: 'hlt-score', title: t('hlt.scoreTitle') },
          h('span', { class: 'hlt-score-value num' }, String(score)),
          h('span', { class: 'hlt-score-max' }, '/100'),
          h('span', { class: 'hlt-score-label' }, t('hlt.score'))),
        h('div', { class: 'hlt-hero-actions' },
          zoneLink,
          Button({
            label: t('hlt.download'), icon: 'download', size: 'sm', dataset: { action: 'download' },
            onClick: () => downloadText(timestampedName('domain-health', 'json', report.domain), toJson(report), 'application/json;charset=utf-8')
          })))));
    heroEl.append(h('div', { class: 'cluster text-sm hlt-links' },
      h('span', { class: 'muted' }, t('hlt.links')),
      h('a', { href: ctx.href('lookup', { name: report.domain, type: 'A,AAAA,MX,NS,TXT,SOA,CAA,HTTPS' }) }, Icon('search', { size: 14 }), ' ', t('nav.lookup')),
      h('a', { href: ctx.href('global', { name: report.domain, type: 'A' }) }, Icon('globe', { size: 14 }), ' ', t('nav.global')),
      h('a', { href: ctx.href('scan', { domain: report.domain }) }, Icon('target', { size: 14 }), ' ', t('nav.scan'))));
  }

  /* --- checks ----------------------------------------------------------------------------- */
  function renderCheck(c) {
    return h('li', { class: ['hlt-check', `hlt-sev-${c.severity}`], dataset: { id: c.id, severity: c.severity } },
      h('span', { class: 'hlt-check-icon' }, SeverityIcon(c.severity, { size: 18 })),
      h('div', { class: 'hlt-check-body' },
        h('div', { class: 'hlt-check-title' }, checkTitle(c)),
        h('div', { class: 'hlt-check-detail' }, checkDetail(c))));
  }

  function renderChecks(report) {
    clear(checksEl);
    for (const group of HEALTH_GROUPS) {
      const all = groupChecks(report.checks, group);
      if (!all.length) continue;
      const shown = filter === 'problems' ? all.filter((c) => c.severity === 'error' || c.severity === 'warn') : all;
      const counts = SEVERITY_ORDER.filter((sev) => sev !== 'ok' && all.some((c) => c.severity === sev))
        .map((sev) => Badge(formatNumber(all.filter((c) => c.severity === sev).length), { variant: sev, icon: sev === 'error' ? 'x-circle' : sev === 'warn' ? 'alert' : 'info', title: t(`hlt.count.${sev}`, { count: all.filter((c) => c.severity === sev).length }) }));
      const worst = all[0].severity;
      checksEl.append(Card({
        title: t(`health.group.${group}`),
        icon: { dns: 'globe', email: 'mail', security: 'shield', registration: 'calendar' }[group],
        className: ['hlt-group', `hlt-group-${worst}`].join(' '),
        actions: counts.length ? h('div', { class: 'cluster' }, counts) : Badge(t('severity.ok'), { variant: 'ok', icon: 'check' }),
        padded: false,
        children: shown.length
          ? h('ul', { class: 'hlt-check-list' }, shown.map(renderCheck))
          : h('p', { class: 'hlt-none muted text-sm' }, t('hlt.noProblems'))
      }));
      checksEl.lastChild.dataset.group = group;
    }
  }

  /* --- detail panels ------------------------------------------------------------------ */
  function rdapCard(report) {
    const r = report.rdap;
    let body;
    if (!r) body = h('p', { class: 'muted text-sm' }, t('hlt.rdap.skipped'));
    else if (r.unsupportedTld) {
      body = Alert({
        variant: 'info', compact: true,
        message: [t('hlt.rdap.unsupported', { tld: r.tld || '' }), r.tld === 'tr' ? t('hlt.rdap.unsupportedTr') : null].filter(Boolean).join(' ')
      });
    } else if (r.notFound) body = Alert({ variant: 'warn', compact: true, message: t('hlt.rdap.notFound', { domain: r.domain }) });
    else if (!r.ok) {
      body = Alert({
        variant: 'error', compact: true, title: t('hlt.rdap.error'),
        message: r.errorKind && hasString(`error.kind.${r.errorKind}`, 'en') ? t(`error.kind.${r.errorKind}`) : r.error
      });
    } else {
      const days = r.expires ? daysUntil(r.expires) : null;
      const daysBadge = days === null ? null : days < 0
        ? Badge(t('hlt.rdap.daysAgo', { count: -days }), { variant: 'error', icon: 'x-circle' })
        : Badge(t('hlt.rdap.daysLeft', { count: days }), { variant: days < 30 ? 'error' : days < 60 ? 'warn' : 'ok', icon: 'clock' });
      const locked = (s) => /prohibited|lock/.test(s);
      body = KeyValueList([
        { key: t('hlt.rdap.domain'), value: r.domain, mono: true },
        {
          key: t('hlt.rdap.registrar'),
          value: r.registrar ? h('span', { class: 'hlt-registrar' },
            r.registrarUrl ? ExternalLink(r.registrarUrl, r.registrar) : r.registrar,
            r.registrarIanaId ? h('span', { class: 'muted text-xs' }, ` · ${t('hlt.rdap.ianaId', { id: r.registrarIanaId })}`) : null) : null
        },
        { key: t('hlt.rdap.created'), value: r.created ? `${formatDate(r.created)} · ${formatRelative(r.created)}` : null },
        { key: t('hlt.rdap.updated'), value: r.updated ? formatDate(r.updated) : null },
        { key: t('hlt.rdap.expires'), value: r.expires ? h('span', { class: 'hlt-expiry', dataset: { days } }, h('strong', null, formatDate(r.expires)), ' ', daysBadge) : null },
        { key: t('hlt.rdap.status'), value: r.status.length ? h('div', { class: 'cluster' }, r.status.map((s) => Badge(s, { variant: locked(s) ? 'ok' : /hold|delete|redemption/.test(s) ? 'error' : 'neutral', icon: locked(s) ? 'lock' : null }))) : null },
        { key: t('hlt.rdap.nameservers'), value: r.nameservers.length ? h('div', { class: 'cluster' }, r.nameservers.map((n) => hostLink(n))) : null },
        { key: t('hlt.rdap.dnssec'), value: r.dnssecSigned === null ? null : r.dnssecSigned ? Badge(t('hlt.rdap.signed'), { variant: 'ok', icon: 'shield' }) : Badge(t('hlt.rdap.unsigned')) },
        { key: t('hlt.rdap.abuse'), value: r.abuseEmail, mono: true, copy: true },
        { key: t('hlt.rdap.server'), value: r.url ? ExternalLink(r.url, r.rdapServer || r.url) : r.rdapServer }
      ].filter((it) => it.value !== null && it.value !== undefined && it.value !== ''));
    }
    return Card({ title: t('hlt.rdap.title'), icon: 'calendar', className: 'hlt-card hlt-rdap', children: body });
  }

  function dnssecCard(report) {
    const d = report.dnssec;
    const state = d.broken ? 'broken' : d.signed && d.validated ? 'validated' : d.signed ? 'signed' : d.signed === false ? 'unsigned' : 'unknown';
    const variant = { broken: 'error', validated: 'ok', signed: 'warn', unsigned: 'neutral', unknown: 'neutral' }[state];
    const ds = report.records.ds || [];
    const keys = report.records.dnskey || [];
    const children = [
      h('div', { class: 'cluster' }, Badge(t(`hlt.dnssec.${state}`), { variant, icon: state === 'validated' ? 'shield' : state === 'broken' ? 'x-circle' : null })),
      d.ede && d.ede.length ? Alert({ variant: 'error', compact: true, title: t('hlt.dnssec.ede'), message: d.ede.join(' · ') }) : null,
      d.algorithms && d.algorithms.length ? h('div', { class: 'text-sm' }, h('span', { class: 'muted' }, `${t('hlt.dnssec.algorithms')}: `), d.algorithms.join(', ')) : null,
      ds.length ? h('div', { class: 'stack-sm' }, h('div', { class: 'hlt-subtitle' }, t('hlt.dnssec.ds')),
        miniTable([t('hlt.col.keyTag'), t('hlt.col.algorithm'), t('hlt.col.digest')], ds.map((x) => [h('span', { class: 'mono' }, String(x.keyTag)), algName(x.algorithm), DS_DIGEST_TYPES[x.digestType] || String(x.digestType)]))) : null,
      keys.length ? h('div', { class: 'stack-sm' }, h('div', { class: 'hlt-subtitle' }, t('hlt.dnssec.dnskey')),
        miniTable([t('hlt.col.keyTag'), t('hlt.col.role'), t('hlt.col.algorithm')], keys.map((k) => [h('span', { class: 'mono' }, String(k.keyTag)),
          Badge(k.sep ? t('hlt.dnssec.ksk') : t('hlt.dnssec.zsk'), { variant: k.sep ? 'accent' : 'neutral', icon: 'key' }), algName(k.algorithm)]))) : null
    ];
    return Card({ title: t('hlt.dnssec.title'), icon: 'shield', className: 'hlt-card hlt-dnssec', children: h('div', { class: 'stack-sm' }, children) });
  }

  /**
   * SPF include tree: DNS-querying terms (include, redirect, a, mx, exists, ptr) are tree items
   * (with their nested records); address terms (ip4/ip6) and "all" are one compact chip row.
   */
  function spfTree(node, depth = 0) {
    if (!node || depth > 12) return null;
    const terms = node.terms || [];
    const lookups = terms.filter((x) => x.lookup);
    const statics = terms.filter((x) => !x.lookup);
    const head = h('div', { class: 'hlt-spf-head' },
      hostLink(node.domain, 'TXT'),
      Badge(t('hlt.spf.lookupCount', { count: node.count }), { variant: node.count > SPF_LOOKUP_LIMIT ? 'error' : 'neutral' }),
      node.void ? Badge(t('hlt.spf.voidBadge'), { variant: 'warn' }) : null,
      ...(node.errors || []).filter((e) => e.domain === node.domain).map((e) => Badge(e.code, { variant: 'error', title: e.detail || null })));
    const items = lookups.map((term) => h('li', { class: 'hlt-spf-term' },
      h('span', { class: 'hlt-spf-term-head' },
        h('span', { class: 'mono hlt-spf-raw' }, term.term),
        h('span', { class: 'muted text-xs' }, '+1'),
        term.void ? Badge(t('hlt.spf.voidBadge'), { variant: 'warn' }) : null,
        term.error ? Badge(term.error, { variant: 'error' }) : null),
      term.child ? spfTree(term.child, depth + 1) : null));
    return h('div', { class: 'hlt-spf-node' }, head,
      statics.length ? h('div', { class: 'hlt-spf-static' }, statics.map((x) => h('span', { class: ['mono', 'hlt-spf-chip', { 'is-all': x.mechanism === 'all' }] }, x.term))) : null,
      items.length ? h('ul', { class: 'hlt-spf-terms' }, items) : null);
  }

  function mailCard(report) {
    const spf = report.spf || {};
    const lookups = spf.lookups;
    const dmarc = report.dmarc || {};
    const p = dmarc.parsed;
    const dkim = report.records.dkim || [];
    const selectorsTried = (current && current.selectorCount) || DEFAULT_DKIM_SELECTORS.length;

    const meter = lookups ? h('div', { class: 'hlt-meter-wrap' },
      h('div', { class: 'hlt-meter-label text-sm' }, t('hlt.spf.lookups', { count: lookups.count, limit: SPF_LOOKUP_LIMIT }),
        lookups.voidCount ? h('span', { class: 'muted' }, ` · ${t('hlt.spf.void', { count: lookups.voidCount, limit: SPF_VOID_LIMIT })}`) : null),
      h('div', { class: ['hlt-meter', lookups.count > SPF_LOOKUP_LIMIT ? 'is-error' : lookups.count >= SPF_LOOKUP_LIMIT - 1 ? 'is-warn' : 'is-ok'], attrs: { role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': SPF_LOOKUP_LIMIT, 'aria-valuenow': lookups.count, 'aria-label': t('hlt.spf.lookups', { count: lookups.count, limit: SPF_LOOKUP_LIMIT }) } },
        h('span', { class: 'hlt-meter-fill', style: { width: `${Math.min(100, (lookups.count / SPF_LOOKUP_LIMIT) * 100)}%` } }))) : null;

    const spfBlock = h('div', { class: 'stack-sm hlt-mail-block', dataset: { block: 'spf' } },
      h('div', { class: 'hlt-subtitle' }, t('hlt.spf')),
      spf.record ? CodeBlock(spf.record, { wrap: true, label: 'TXT' }) : h('p', { class: 'muted text-sm' }, t('hlt.spf.none')),
      meter,
      lookups && lookups.truncated ? h('p', { class: 'muted text-xs' }, t('hlt.spf.truncated')) : null,
      lookups && lookups.tree ? Disclosure({ summary: t('hlt.spf.tree'), className: 'hlt-spf', open: lookups.count >= SPF_LOOKUP_LIMIT - 2, children: spfTree(lookups.tree) }) : null);

    const align = (v) => (v === 's' ? t('hlt.dmarc.strict') : t('hlt.dmarc.relaxed'));
    const dmarcBlock = h('div', { class: 'stack-sm hlt-mail-block', dataset: { block: 'dmarc' } },
      h('div', { class: 'hlt-subtitle' }, t('hlt.dmarc'),
        dmarc.inherited ? Badge(t('hlt.dmarc.inherited', { org: dmarc.foundAt }), { variant: 'info' }) : null),
      dmarc.record ? CodeBlock(dmarc.record, { wrap: true, label: dmarc.foundAt ? `_dmarc.${dmarc.foundAt}` : 'TXT' }) : h('p', { class: 'muted text-sm' }, t('hlt.dmarc.none')),
      p && p.valid ? KeyValueList([
        { key: t('hlt.dmarc.p'), value: Badge(p.policy, { variant: p.policy === 'none' ? 'warn' : 'ok', mono: true }) },
        { key: t('hlt.dmarc.sp'), value: p.subdomainPolicy ? Badge(p.subdomainPolicy, { variant: p.subdomainPolicy === 'none' ? 'warn' : 'ok', mono: true }) : null },
        { key: t('hlt.dmarc.pct'), value: `${p.pct}%` },
        { key: t('hlt.dmarc.rua'), value: p.rua.length ? h('div', { class: 'stack-sm' }, p.rua.map((u) => h('span', { class: 'mono text-sm' }, u))) : null },
        { key: t('hlt.dmarc.ruf'), value: p.ruf.length ? h('div', { class: 'stack-sm' }, p.ruf.map((u) => h('span', { class: 'mono text-sm' }, u))) : null },
        { key: t('hlt.dmarc.align'), value: `${align(p.adkim)} / ${align(p.aspf)}` }
      ], { className: 'hlt-kv' }) : null);

    const dkimBlock = h('div', { class: 'stack-sm hlt-mail-block', dataset: { block: 'dkim' } },
      h('div', { class: 'hlt-subtitle' }, t('hlt.dkim')),
      dkim.length ? miniTable([t('hlt.dkim.selector'), t('hlt.dkim.key'), t('hlt.dkim.state')], dkim.map((k) => [
        k.selector === '*' ? Badge(t('hlt.dkim.wildcard'), { variant: 'info' }) : hostLink(`${k.selector}._domainkey.${report.domain}`, 'TXT'),
        k.revoked ? '—' : `${String(k.keyType).toUpperCase()}${k.keyBits ? ` · ${k.keyBits} bit` : ''}`,
        k.revoked ? Badge(t('hlt.dkim.revoked'), { variant: 'neutral' }) : k.testing ? Badge(t('hlt.dkim.testing'), { variant: 'warn' })
          : Badge(t('hlt.dkim.active'), { variant: k.keyBits && k.keyBits < 1024 ? 'error' : k.keyBits && k.keyBits < 2048 ? 'info' : 'ok', icon: 'key' })
      ])) : h('p', { class: 'muted text-sm' }, t('hlt.dkim.none', { count: selectorsTried })));

    const extra = (label, value) => h('div', { class: 'hlt-extra' },
      h('span', { class: 'hlt-extra-label' }, label),
      value ? h('span', { class: 'mono text-xs hlt-extra-value' }, value) : h('span', { class: 'muted text-xs' }, t('hlt.missing')));
    const extrasBlock = h('div', { class: 'stack-sm hlt-mail-block', dataset: { block: 'extras' } },
      h('div', { class: 'hlt-subtitle' }, t('hlt.mail.extras')),
      extra('MTA-STS', report.records.mtaSts),
      extra('TLS-RPT', report.records.tlsRpt),
      extra('BIMI', report.records.bimi));

    return Card({
      title: t('hlt.mail.title'), icon: 'mail', className: 'hlt-card hlt-mail',
      children: h('div', { class: 'hlt-mail-grid' }, spfBlock, dmarcBlock, dkimBlock, extrasBlock)
    });
  }

  function caaCard(report) {
    const caa = report.caa;
    const children = [];
    if (!caa) {
      children.push(h('p', { class: 'muted text-sm' }, '—'));
    } else if (caa.error) {
      children.push(Alert({ variant: 'warn', compact: true, message: t('hlt.caa.error', { error: caa.error }) }));
    } else if (!caa.foundAt) {
      children.push(Alert({ variant: 'info', compact: true, icon: 'info', message: t('hlt.caa.none') }));
    } else {
      const p = caa.parsed;
      const caItem = (issuer) => {
        const ca = caNameFor(issuer);
        return h('li', { class: 'hlt-ca' },
          Icon('check-circle', { size: 15, className: 'hlt-ca-icon' }),
          h('span', { class: 'hlt-ca-name' }, ca ? ca.name : issuer),
          ca ? h('span', { class: 'muted mono text-xs' }, issuer) : null,
          ca && ca.distrusted ? Badge(t('hlt.caa.distrusted', { year: ca.distrusted }), { variant: 'error', icon: 'alert' }) : null);
      };
      const list = (issuers, hasProperty) => {
        if (!hasProperty) return null;
        if (!issuers.length) return h('p', { class: 'hlt-caa-deny text-sm' }, Icon('x-circle', { size: 14 }), ' ', t('hlt.caa.nobody'));
        return h('ul', { class: 'hlt-ca-list' }, issuers.map(caItem));
      };
      children.push(h('p', { class: 'muted text-sm' }, t('hlt.caa.foundAt', { name: caa.foundAt })));
      children.push(h('div', { class: 'stack-sm' }, h('div', { class: 'hlt-subtitle' }, t('hlt.caa.issue')),
        p.issue.length ? list(p.issuers, true) : h('p', { class: 'text-sm' }, t('hlt.caa.anyone'))));
      children.push(h('div', { class: 'stack-sm' }, h('div', { class: 'hlt-subtitle' }, t('hlt.caa.issuewild')),
        p.issuewild.length ? list(p.wildIssuers, true) : h('p', { class: 'muted text-sm' }, t('hlt.caa.sameAsIssue'))));
      if (p.iodef.length) {
        children.push(h('div', { class: 'stack-sm' }, h('div', { class: 'hlt-subtitle' }, t('hlt.caa.iodef')),
          h('div', { class: 'stack-sm' }, p.iodef.map((x) => (/^https?:/i.test(x.url) ? ExternalLink(x.url, x.url) : h('span', { class: 'mono text-sm' }, x.url))))));
      }
      children.push(Disclosure({
        summary: `${t('hlt.caa.records')} (${formatNumber(caa.records.length)})`,
        children: CodeBlock(caa.records.map((rr) => `${rr.name}. ${rr.ttl} IN CAA ${rr.text}`).join('\n'), { wrap: true })
      }));
    }
    return Card({ title: t('hlt.caa.title'), icon: 'certificate', className: 'hlt-card hlt-caa', children: h('div', { class: 'stack' }, children) });
  }

  function dnsCard(report) {
    const rec = report.records;
    const classify = (ip) => classifyResolution({ status: 'NOERROR', ipv4: ipVersion(ip) === 4 ? [ip] : [], ipv6: ipVersion(ip) === 6 ? [ip] : [] });
    const addrList = (ips) => (ips && ips.length ? h('div', { class: 'stack-sm' }, ips.map((ip) => h('span', { class: 'cluster' }, ipLink(ip), KindBadge(classify(ip))))) : null);
    const nsValue = rec.ns.length ? h('div', { class: 'stack-sm' }, rec.ns.map((ns) => h('div', { class: 'hlt-ns' },
      hostLink(ns), ipList((report.nsAddresses || {})[ns] || [])))) : null;
    const mxHosts = report.mxHosts || {};
    const nullMx = rec.mx.length === 1 && rec.mx[0].exchange === '.';
    const mxValue = nullMx ? Badge(t('hlt.dns.nullMx'), { variant: 'info' }) : rec.mx.length ? h('div', { class: 'stack-sm' }, rec.mx.map((m) => h('div', { class: 'hlt-ns' },
      h('span', { class: 'num muted' }, String(m.preference)), ' ', hostLink(m.exchange),
      ipList(mxHosts[m.exchange] ? [...mxHosts[m.exchange].ipv4, ...mxHosts[m.exchange].ipv6] : [])))) : null;
    const w = report.wildcard;
    const https = rec.https || [];
    const alpn = [...new Set(https.flatMap((x) => (x.params && x.params.alpn) || []))];
    return Card({
      title: t('hlt.dns.title'), icon: 'globe', className: 'hlt-card hlt-dns',
      actions: h('a', { class: 'btn btn-ghost btn-sm', href: ctx.href('lookup', { name: report.domain, type: 'A,AAAA,MX,NS,TXT,SOA,CAA,HTTPS' }) }, Icon('search', { size: 14 }), h('span', { class: 'btn-label' }, t('hlt.dns.lookupAll'))),
      children: KeyValueList([
        { key: t('hlt.dns.ns'), value: nsValue },
        { key: t('hlt.dns.soa'), value: rec.soa ? h('span', { class: 'mono text-sm' }, t('hlt.dns.soaValue', { mname: rec.soa.mname, email: rec.soa.email || rec.soa.rname, serial: rec.soa.serial })) : null },
        { key: t('hlt.dns.mx'), value: mxValue },
        { key: t('hlt.dns.a'), value: addrList(rec.a) },
        { key: t('hlt.dns.aaaa'), value: addrList(rec.aaaa) },
        { key: t('hlt.dns.https'), value: https.length ? h('span', { class: 'cluster' }, alpn.map((a) => Badge(a, { mono: true }))) : null },
        { key: t('hlt.dns.txt'), value: h('a', { href: ctx.href('lookup', { name: report.domain, type: 'TXT' }) }, t('hlt.dns.txtCount', { count: rec.txt.length })) },
        { key: t('hlt.dns.wildcard'), value: w ? (w.wildcard ? h('span', { class: 'mono text-sm' }, t('hlt.dns.wildcardYes', { values: [...w.cnames, ...w.ipv4, ...w.ipv6].join(', ') })) : t('hlt.dns.wildcardNo')) : null }
      ], { className: 'hlt-kv' })
    });
  }

  function renderDetails(report) {
    clear(detailsEl);
    detailsEl.append(rdapCard(report), dnssecCard(report), mailCard(report), caaCard(report), dnsCard(report));
  }

  function renderReport(report) {
    emptyEl.hidden = true;
    results.hidden = false;
    renderHero(report);
    renderChecks(report);
    renderDetails(report);
  }

  /* --- run -------------------------------------------------------------------------------- */
  let current = null;

  function setRunning(on) {
    runBtn.hidden = on;
    stopBtn.hidden = !on;
    domainField.input.readOnly = on;
    ctx.setBusy(on);
  }

  function setShareAction() {
    ctx.setActions(CopyButton(() => ctx.shareUrl(), { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }));
  }

  function start() {
    domainField.setError(null);
    const raw = domainField.value.trim();
    const domain = normalizeHostname(raw.replace(/^\*\./, ''));
    if (!domain || normalizeIP(raw)) {
      domainField.setError(t('hlt.invalid'));
      domainField.focus();
      return;
    }
    domainField.value = domain;
    const extra = parseSelectors(selectorsField.value);
    ctx.setParams({ domain, selectors: extra.length ? extra.join(',') : null });
    setShareAction();
    run(domain, extra);
  }

  async function run(domain, extraSelectors) {
    if (current && current.controller) current.controller.abort();
    const controller = new AbortController();
    const state = { domain, controller, report: null, selectorCount: DEFAULT_DKIM_SELECTORS.length + extraSelectors.length };
    current = state;
    clear(errorEl);
    progress.el.hidden = false;
    progress.setVariant('default');
    progress.setLabel(t('hlt.progress', { domain }));
    progress.set(0, 10);
    setRunning(true);
    const startedAt = performance.now();
    try {
      const dns = await ctx.getDns();
      const report = await domainHealth(domain, {
        dns,
        signal: mergeSignals(ctx.signal, controller.signal),
        dkimSelectors: [...DEFAULT_DKIM_SELECTORS, ...extraSelectors],
        onProgress: ({ step, done, total }) => {
          if (current !== state) return;
          progress.set(done, total);
          progress.setLabel(`${t('hlt.progress', { domain })} · ${t(`hlt.step.${step}`)}`);
        }
      });
      if (current !== state) return;
      state.report = report;
      progress.done(`${t('common.done')} · ${formatDuration(performance.now() - startedAt)}`);
      renderReport(report);
      setTimeout(() => { if (current === state) progress.el.hidden = true; }, 1200);
    } catch (err) {
      if (current !== state) return;
      progress.el.hidden = true;
      if (err && err.name === 'AbortError') return;
      errorEl.append(Alert({ variant: 'error', title: t('hlt.failed'), message: err && err.message ? err.message : String(err) }));
    } finally {
      if (current === state) {
        state.controller = null;
        if (!ctx.signal.aborted) setRunning(false);
      }
    }
  }

  /* --- initial state ----------------------------------------------------------------- */
  if (restored && restored.report) {
    current = { domain: restored.report.domain, controller: null, report: restored.report, selectorCount: restored.selectorCount };
    renderReport(restored.report);
  } else if (initialDomain) {
    Promise.resolve().then(() => start());
  }
  if (restored && restored.report) setShareAction();

  active = {
    teardown() {
      if (current && current.controller) current.controller.abort();
    },
    snapshot() {
      return {
        domain: domainField.value,
        selectors: selectorsField.value,
        filter,
        report: current && !current.controller ? current.report : null,
        selectorCount: current ? current.selectorCount : null
      };
    },
    update(params) {
      const domain = params.domain || params.name;
      if (!domain) return false;
      domainField.value = domain;
      if (params.selectors !== undefined) selectorsField.value = params.selectors;
      start();
      return true;
    }
  };
}

/** Abort a running check. */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * Form + finished report carried over a language re-mount (no re-check).
 * @returns {object|null}
 */
export function snapshot() {
  return active ? active.snapshot() : null;
}

/**
 * Take new route params (e.g. "Check <zone>" links) without a re-mount.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, snapshot, update };
