/**
 * ui/revocation.js — the renewal radar in the page's words: the revocation reasons, a revoked
 * certificate's line and the CA's problem-reporting contact (Domain portfolio › Certificates (CT)),
 * and the renewal-window (ARI) and revocation cells and details of Certificate estate (what the
 * CLI's --ari and --revocation wrote). The Certificate view's "Is it revoked?" card is
 * ui/revocation-card.js, loaded with its tab.
 *
 * Light on purpose (no parser, no network): the CT tab and the estate view import it with
 * themselves, never the start route. Every value goes through h() / text nodes: the CA's
 * problem-reporting text is shown as text (line breaks kept), never as markup or links, and a CRL
 * URL from a report is text too.
 */

import { h } from './dom.js';
import { Badge, Disclosure, ExternalLink } from './components.js';
import { t, hasString, localeTag, registerStrings, formatDate, formatDateTime } from '../i18n.js';

/** The ARI errors of the CLI's --ari the estate names (cli/ssl_origin_scan.py _ARI_WHY). */
export const ARI_ERROR_CODES = Object.freeze(['not-found', 'unsupported', 'no-key-id', 'no-renewal-info', 'bad-window', 'rate-limit', 'http', 'timeout',
  'network', 'parse']);
/** Why the CLI's --revocation could not tell (cli/ssl_origin_scan.py _REVOCATION_WHY). */
export const REVOCATION_UNKNOWN_CODES = Object.freeze(['no-crl', 'too-large', 'http', 'timeout', 'network', 'parse', 'issuer-mismatch',
  'critical-extension', 'delta', 'scope', 'reasons', 'stale']);
/** The RFC 5280 reason names the page words (lib/crl.js REVOCATION_REASON_NAMES; tests/js/revocation.test.js keeps them in step). */
export const REASON_KEYS = Object.freeze(['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation',
  'certificateHold', 'removeFromCRL', 'privilegeWithdrawn', 'aACompromise']);

registerStrings('en', {
  'rev.reason.none': 'not given',
  'rev.reason.unspecified': 'unspecified',
  'rev.reason.keyCompromise': 'key compromise',
  'rev.reason.cACompromise': 'CA compromise',
  'rev.reason.affiliationChanged': 'affiliation changed',
  'rev.reason.superseded': 'superseded',
  'rev.reason.cessationOfOperation': 'cessation of operation',
  'rev.reason.certificateHold': 'on hold',
  'rev.reason.removeFromCRL': 'removed from the list',
  'rev.reason.privilegeWithdrawn': 'privilege withdrawn',
  'rev.reason.aACompromise': 'attribute authority compromise',
  'rev.when': 'on {date}, reason: {reason}',
  'rev.whenNoDate': 'reason: {reason}',
  'rev.whenTitle': 'Revoked at {time}',
  'rev.report.summary': 'Report a problem to the CA',
  'rev.report.intro': 'The CA’s own words, as Cert Spotter has them:',
  'rev.col.ari': 'Renewal window (ARI)',
  'rev.col.revocation': 'Revocation',
  'rev.ari.window': '{start} – {end}',
  'rev.ari.opensIn': { one: 'opens in {count} day', other: 'opens in {count} days' },
  'rev.ari.open': 'open: renew now',
  'rev.ari.past': 'ended: renewal overdue',
  'rev.ari.asOf': 'as of {date}',
  'rev.ari.explains': 'The CA explains',
  'rev.ari.err.not-found': 'not known to the CA',
  'rev.ari.err.unsupported': 'no ARI server known for this CA',
  'rev.ari.err.no-key-id': 'no authority key identifier',
  'rev.ari.err.no-renewal-info': 'the CA offers no ARI',
  'rev.ari.err.bad-window': 'the CA’s answer is no window',
  'rev.ari.err.rate-limit': 'the CA said “too many requests”',
  'rev.ari.err.http': 'HTTP error from the CA',
  'rev.ari.err.timeout': 'the CA did not answer in time',
  'rev.ari.err.network': 'the CA could not be reached',
  'rev.ari.err.parse': 'the CA’s answer could not be read',
  'rev.ari.err.other': 'not read ({code})',
  'rev.st.good': 'Not revoked',
  'rev.st.revoked': 'Revoked',
  'rev.st.unknown': 'Unknown',
  'rev.sigNotVerified': 'CRL signature not verified',
  'rev.unknown.no-crl': 'The certificate names no CRL to read (OCSP is not asked).',
  'rev.unknown.too-large': 'Its CRL is larger than 20 MB.',
  'rev.unknown.http': 'Its CRL could not be downloaded (HTTP error).',
  'rev.unknown.timeout': 'Its CRL download timed out.',
  'rev.unknown.network': 'Its CRL could not be downloaded.',
  'rev.unknown.parse': 'What its CRL address returned is not a CRL.',
  'rev.unknown.issuer-mismatch': 'The CRL is another CA’s.',
  'rev.unknown.critical-extension': 'The CRL has a critical extension the CLI does not read.',
  'rev.unknown.delta': 'It is a delta CRL.',
  'rev.unknown.scope': 'The CRL covers other certificates.',
  'rev.unknown.reasons': 'The CRL covers some revocation reasons only.',
  'rev.unknown.stale': 'The CRL is out of date (its next update has passed).',
  'rev.unknown.other': 'The CRL could not be read.',
  'rev.d.ariCa': 'CA asked (ARI)',
  'rev.d.window': 'Renewal window',
  'rev.d.retryAfter': 'Ask again after (the CA’s request)',
  'rev.d.checked': 'Asked',
  'rev.d.crl': 'CRL',
  'rev.d.crlIssued': 'CRL issued',
  'rev.d.status': 'Revocation',
  'rev.sum.ari.open': 'renew now',
  'rev.sum.ari.past': 'overdue',
  'rev.sum.ari.before': 'not open yet',
  'rev.sum.ari.error': 'not read',
  'rev.sum.rev.revoked': 'revoked',
  'rev.sum.rev.unknown': 'unknown',
  'rev.sum.rev.good': 'not revoked'
});

registerStrings('tr', {
  'rev.reason.none': 'belirtilmemiş',
  'rev.reason.unspecified': 'belirtilmemiş',
  'rev.reason.keyCompromise': 'anahtar ele geçirilmiş',
  'rev.reason.cACompromise': 'CA ele geçirilmiş',
  'rev.reason.affiliationChanged': 'kurum bilgisi değişmiş',
  'rev.reason.superseded': 'yenisiyle değiştirilmiş',
  'rev.reason.cessationOfOperation': 'kullanımdan kaldırılmış',
  'rev.reason.certificateHold': 'askıya alınmış',
  'rev.reason.removeFromCRL': 'listeden çıkarılmış',
  'rev.reason.privilegeWithdrawn': 'yetki geri alınmış',
  'rev.reason.aACompromise': 'öznitelik yetkilisi ele geçirilmiş',
  'rev.when': '{date} tarihinde, gerekçe: {reason}',
  'rev.whenNoDate': 'gerekçe: {reason}',
  'rev.whenTitle': 'İptal zamanı: {time}',
  'rev.report.summary': 'Sorunu CA’ya bildirin',
  'rev.report.intro': 'CA’nın kendi sözleriyle, Cert Spotter’daki hâliyle:',
  'rev.col.ari': 'Yenileme penceresi (ARI)',
  'rev.col.revocation': 'İptal durumu',
  'rev.ari.window': '{start} – {end}',
  'rev.ari.opensIn': { other: '{count} gün sonra açılıyor' },
  'rev.ari.open': 'açık: şimdi yenileyin',
  'rev.ari.past': 'kapandı: yenileme gecikti',
  'rev.ari.asOf': '{date} itibarıyla',
  'rev.ari.explains': 'CA’nın açıklaması',
  'rev.ari.err.not-found': 'CA bu sertifikayı tanımıyor',
  'rev.ari.err.unsupported': 'bu CA için bilinen bir ARI sunucusu yok',
  'rev.ari.err.no-key-id': 'yetkili anahtar tanımlayıcısı yok',
  'rev.ari.err.no-renewal-info': 'CA ARI sunmuyor',
  'rev.ari.err.bad-window': 'CA’nın yanıtı bir pencere değil',
  'rev.ari.err.rate-limit': 'CA “çok fazla istek” yanıtını verdi',
  'rev.ari.err.http': 'CA’dan HTTP hatası',
  'rev.ari.err.timeout': 'CA zamanında yanıt vermedi',
  'rev.ari.err.network': 'CA’ya ulaşılamadı',
  'rev.ari.err.parse': 'CA’nın yanıtı okunamadı',
  'rev.ari.err.other': 'okunamadı ({code})',
  'rev.st.good': 'İptal edilmemiş',
  'rev.st.revoked': 'İptal edilmiş',
  'rev.st.unknown': 'Bilinmiyor',
  'rev.sigNotVerified': 'CRL imzası doğrulanmadı',
  'rev.unknown.no-crl': 'Sertifika okunacak bir CRL belirtmiyor (OCSP’ye sorulmaz).',
  'rev.unknown.too-large': 'CRL’si 20 MB’tan büyük.',
  'rev.unknown.http': 'CRL’si indirilemedi (HTTP hatası).',
  'rev.unknown.timeout': 'CRL’sinin indirilmesi zaman aşımına uğradı.',
  'rev.unknown.network': 'CRL’si indirilemedi.',
  'rev.unknown.parse': 'CRL adresinden gelen yanıt bir CRL değil.',
  'rev.unknown.issuer-mismatch': 'CRL başka bir CA’ya ait.',
  'rev.unknown.critical-extension': 'CRL’de CLI’ın okumadığı kritik bir uzantı var.',
  'rev.unknown.delta': 'Bu bir delta CRL.',
  'rev.unknown.scope': 'CRL başka sertifikaları kapsıyor.',
  'rev.unknown.reasons': 'CRL yalnızca bazı iptal gerekçelerini kapsıyor.',
  'rev.unknown.stale': 'CRL güncel değil (bir sonraki güncelleme zamanı geçmiş).',
  'rev.unknown.other': 'CRL okunamadı.',
  'rev.d.ariCa': 'Sorulan CA (ARI)',
  'rev.d.window': 'Yenileme penceresi',
  'rev.d.retryAfter': 'Yeniden sorma zamanı (CA’nın isteği)',
  'rev.d.checked': 'Sorulma zamanı',
  'rev.d.crl': 'CRL',
  'rev.d.crlIssued': 'CRL’nin yayımlanma zamanı',
  'rev.d.status': 'İptal durumu',
  'rev.sum.ari.open': 'şimdi yenilenmeli',
  'rev.sum.ari.past': 'gecikmiş',
  'rev.sum.ari.before': 'henüz açılmadı',
  'rev.sum.ari.error': 'okunamadı',
  'rev.sum.rev.revoked': 'iptal edilmiş',
  'rev.sum.rev.unknown': 'bilinmiyor',
  'rev.sum.rev.good': 'iptal edilmemiş'
});

/**
 * Every i18n key this module builds from a code (the i18n coverage test reads them).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...REASON_KEYS.map((r) => `rev.reason.${r}`),
    ...ARI_ERROR_CODES.map((e) => `rev.ari.err.${e}`),
    ...REVOCATION_UNKNOWN_CODES.map((c) => `rev.unknown.${c}`),
    ...['good', 'revoked', 'unknown'].map((s) => `rev.st.${s}`),
    ...['open', 'past', 'before', 'error'].map((s) => `rev.sum.ari.${s}`),
    ...['revoked', 'unknown', 'good'].map((s) => `rev.sum.rev.${s}`)
  ];
}

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * A revocation reason (an RFC 5280 CRLReason name, as lib/crl.js and the CLI write it) in the
 * page's words; "not given" for none or a name it does not know.
 * @param {string|null|undefined} reason
 * @returns {string}
 */
export function reasonLabel(reason) {
  return typeof reason === 'string' && REASON_KEYS.includes(reason) && hasString(`rev.reason.${reason}`) ? t(`rev.reason.${reason}`) : t('rev.reason.none');
}

/**
 * When and why a certificate was revoked: "on 21 Sep 2026, reason: key compromise" (its tooltip
 * the exact time in UTC).
 * @param {{ time?: Date|string|null, reason?: string|null }|null|undefined} revocation
 * @param {{ className?: string }} [opts]
 * @returns {HTMLElement}
 */
export function RevokedLine(revocation, { className = '' } = {}) {
  const { text, title } = revokedText(revocation);
  return h('span', { class: ['rev-line', className], title, dataset: { role: 'rev-line' } }, text);
}

/** The text of {@link RevokedLine} and its tooltip. */
function revokedText(revocation) {
  const r = isObj(revocation) ? revocation : {};
  const reason = reasonLabel(r.reason);
  const time = r.time ? new Date(r.time) : null;
  if (!time || Number.isNaN(time.getTime())) return { text: t('rev.whenNoDate', { reason }), title: null };
  return { text: t('rev.when', { date: formatDate(time, { utc: true }), reason }), title: t('rev.whenTitle', { time: formatDateTime(time, { utc: true }) }) };
}

/**
 * The CA's problem-reporting contact, folded: the CA's own text, line breaks kept, never markup.
 * @param {string} text lib/revocation.js problemReportingText
 * @param {{ className?: string }} [opts]
 * @returns {HTMLDetailsElement}
 */
export function ProblemReporting(text, { className = '' } = {}) {
  const el = Disclosure({
    summary: t('rev.report.summary'),
    className: ['rev-report', className].filter(Boolean).join(' '),
    children: [h('p', { class: 'rev-report-intro' }, t('rev.report.intro')), h('div', { class: 'rev-report-text' }, text)]
  });
  el.dataset.role = 'rev-report';
  return el;
}

/* ------------------------------------------------------------------------ */
/* Certificate estate: the CLI's --ari and --revocation                     */
/* ------------------------------------------------------------------------ */

/** "not known to the CA", or "not read (code)" for a code the page does not word. */
function ariErrorText(code) {
  return ARI_ERROR_CODES.includes(code) ? t(`rev.ari.err.${code}`) : t('rev.ari.err.other', { code: String(code) });
}

/** Why the CLI could not tell, in the page's words. */
function unknownText(code) {
  return REVOCATION_UNKNOWN_CODES.includes(code) ? t(`rev.unknown.${code}`) : t('rev.unknown.other');
}

/** The window in UTC dates as a short range ("Oct 8 – 10, 2026"), or with times when `withTime`. */
function windowText(ari, withTime = false) {
  if (!withTime) {
    try {
      return new Intl.DateTimeFormat(localeTag(), { dateStyle: 'medium', timeZone: 'UTC' }).formatRange(new Date(ari.start), new Date(ari.end));
    } catch {
      // no formatRange, or a date it cannot take: the two dates
    }
  }
  const fmt = (v) => (withTime ? formatDateTime(v, { utc: true }) : formatDate(v, { utc: true }));
  return t('rev.ari.window', { start: fmt(ari.start), end: fmt(ari.end) });
}

/**
 * The estate's renewal-window cell: the window and where today is in it, or why there is none.
 * @param {object|null|undefined} ari the CLI's `ari` record
 * @param {{ state: 'before'|'open'|'past', days: number }|null|undefined} where lib/estate.js estateAriWindow
 * @returns {HTMLElement|null}
 */
export function AriCell(ari, where) {
  if (!isObj(ari)) return null;
  if (ari.error) {
    return h('div', { class: 'rev-cell', dataset: { ari: 'error' } },
      h('span', { class: 'muted text-xs' }, ariErrorText(ari.error)));
  }
  const state = isObj(where) ? where.state : null;
  return h('div', { class: 'rev-cell', dataset: { ari: state || 'none' } }, spaced(
    h('span', { class: 'rev-window' }, windowText(ari)),
    state === 'before' ? Badge(t('rev.ari.opensIn', { count: where.days }), { variant: 'neutral' }) : null,
    state === 'open' ? Badge(t('rev.ari.open'), { variant: 'error' }) : null,
    state === 'past' ? Badge(t('rev.ari.past'), { variant: 'error' }) : null,
    isObj(ari.carried) && ari.carried.from ? h('span', { class: 'muted text-xs' }, t('rev.ari.asOf', { date: formatDate(ari.carried.from, { utc: true }) })) : null));
}

/** The parts of a cell with a space between them: one per line on screen, words apart when copied or read out. */
function spaced(...parts) {
  return parts.filter(Boolean).flatMap((p, i) => (i ? [' ', p] : [p]));
}

/**
 * The estate's revocation cell: not revoked, revoked with when and why, or unknown with why.
 * @param {object|null|undefined} rev the CLI's `revocation` record
 * @returns {HTMLElement|null}
 */
export function RevocationCell(rev) {
  if (!isObj(rev)) return null;
  const status = rev.status === 'good' || rev.status === 'revoked' ? rev.status : 'unknown';
  const variant = status === 'revoked' ? 'error' : status === 'good' ? 'ok' : 'neutral';
  return h('div', { class: 'rev-cell', dataset: { revocation: status } }, spaced(
    Badge(t(`rev.st.${status}`), { variant, title: status !== 'unknown' && rev.signature === 'not-verified' ? t('rev.sigNotVerified') : null }),
    status === 'revoked' ? RevokedLine(rev, { className: 'text-xs' }) : null,
    status === 'unknown' ? h('span', { class: 'muted text-xs' }, unknownText(rev.error)) : null));
}

/**
 * The details rows of a certificate's --ari / --revocation records, as [label, value, mono]
 * for the estate's details list.
 * @param {{ ari?: object, revocation?: object }} cert lib/estate.js EstateCertificate
 * @returns {Array<[string, string|Node, boolean]>}
 */
export function statusDetails(cert) {
  const rows = [];
  const ari = isObj(cert && cert.ari) ? cert.ari : null;
  const rev = isObj(cert && cert.revocation) ? cert.revocation : null;
  if (ari) {
    const parts = [ari.error ? ariErrorText(ari.error) : windowText(ari, true)];
    if (ari.checkedAt) parts.push(`${t('rev.d.checked')}: ${formatDateTime(ari.checkedAt, { utc: true })}`);
    if (ari.retryAfter) parts.push(`${t('rev.d.retryAfter')}: ${formatDateTime(ari.retryAfter, { utc: true })}`);
    rows.push([t('rev.d.window'), h('span', { class: 'rev-d-parts' },
      parts.join(' · '),
      ari.explanationURL ? ExternalLink(ari.explanationURL, t('rev.ari.explains'), { className: 'rev-d-link' }) : null), false]);
    if (ari.ca) rows.push([t('rev.d.ariCa'), String(ari.ca), true]);
  }
  if (rev) {
    const status = rev.status === 'good' || rev.status === 'revoked' ? rev.status : 'unknown';
    const parts = [t(`rev.st.${status}`)];
    if (status === 'revoked') parts.push(revokedText(rev).text);
    if (status === 'unknown') parts.push(unknownText(rev.error));
    else if (rev.signature === 'not-verified') parts.push(t('rev.sigNotVerified'));
    rows.push([t('rev.d.status'), parts.join(' · '), false]);
    if (rev.crl) rows.push([t('rev.d.crl'), String(rev.crl), true]);
    if (rev.thisUpdate) rows.push([t('rev.d.crlIssued'), formatDateTime(rev.thisUpdate, { utc: true }), false]);
  }
  return rows;
}
