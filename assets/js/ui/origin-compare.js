/**
 * ui/origin-compare.js — "Compare the old and the new server" in Retire an IP: before DNS moves a
 * name to a new address, does the new server answer like the old one? The logic is
 * lib/origincompare.js; this module only renders it.
 *
 * It lives next to Retire an IP because that is where a server gets a new address: the old
 * address is the one being retired, and the names the reference check finds are the ones to move.
 *
 * - Nothing is sent until "Compare" is clicked. Then, behind the shared Globalping gate
 *   (ui/globalping-gate.js: the free quota read, the consent + cost dialog on the first send of
 *   the page session), two probes: one HTTPS GET of the path at each address, with the name as
 *   the SNI and the Host header, the second from the first one's probe.
 * - Private, documentation and reserved addresses are never sent: the card gives the CLI's
 *   `ssl_origin_scan.py --compare` command instead, which does the same from inside the network.
 * - The form and the last comparison live in this module (the page session): leaving the view
 *   or switching the language keeps them (a run goes on, and ends on the card shown when it
 *   ends); "Delete all local data" and another workspace drop them.
 * - Every string is rendered through h() / text nodes: status lines, titles, header values and
 *   certificate names come from the servers.
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import {
  Alert, Button, Card, CodeBlock, ErrorBanner, Icon, SegmentedControl, SeverityIcon, Spinner, announce, textInput
} from './components.js';
import { downloadJson, timestampedName } from './download.js';
import { gateProbes, noteQuota, whenText, measurementUrl } from './globalping-gate.js';
import { registerRunning } from './jobs.js';
import { t, registerStrings, formatNumber, formatDateTime } from '../i18n.js';
import {
  checkCompare, runCompare, buildCompareCommand, sideFields, COMPARE_FIELDS, COMPARE_VERDICTS, COMPARE_NOTES, COMPARE_SHARED, COMPARE_ISSUES,
  COMPARE_PROBES
} from '../lib/origincompare.js';
import { FAILURE_KINDS } from '../lib/verify.js';
import { errorKind } from '../lib/util.js';
import { state } from '../state.js';

/** Consent purpose of the gate (one per feature: each sends different data). */
export const COMPARE_PURPOSE = 'origin-compare';

const SEV_ICON = Object.freeze({ ok: 'ok', info: 'info', warn: 'warn', error: 'error' });
const VERDICT_VARIANT = Object.freeze({ same: 'ok', differs: 'warn', broken: 'error', incomplete: 'info', unreachable: 'warn' });
const QUOTA_CODES = new Set(['rate-limit', 'insufficient-credits']);

registerStrings('en', {
  'oc.title': 'Compare the old and the new server',
  'oc.lead': 'Before you point a name at a new address: does the new server answer like the old one? The same HTTPS request, with the name as SNI and Host header, goes to both addresses from one Globalping probe, and the two answers are compared side by side.',
  'oc.host': 'Host name',
  'oc.host.placeholder': 'www.example.com',
  'oc.old': 'Old address',
  'oc.new': 'New address',
  'oc.path': 'Path',
  'oc.port': 'Port',
  'oc.issue.host': 'Not a host name a probe can ask for: {value}',
  'oc.issue.old-ip': 'The old address is not an IP address: {value}',
  'oc.issue.new-ip': 'The new address is not an IP address: {value}',
  'oc.issue.same-ip': 'The old and the new address are the same.',
  'oc.issue.path': 'The path must start with / and hold printable characters only.',
  'oc.issue.port': 'Not a port: {value}',
  'oc.run': 'Compare ({probes} probes)',
  'oc.stop': 'Stop',
  'oc.switchRunning': 'Old and new server on Globalping (the probes it has used stay used)',
  'oc.running': 'Asking both servers…',
  'oc.privacy': 'Sends the two addresses, {host} and the path {path} to Globalping: one probe sends one HTTPS GET to each address (User-Agent “globalping probe”), so compare only servers you operate. Anyone with a measurement ID can read the results for about six months: the status, the response headers and the first 10,000 characters of each page.',
  'oc.private': {
    one: 'A probe cannot reach {list}: private, documentation and reserved addresses are never sent. Run the comparison from inside your network:',
    other: 'A probe cannot reach {list}: private, documentation and reserved addresses are never sent. Run the comparison from inside your network:'
  },
  'oc.cliPort': 'A probe asks HTTPS ports only (not {port}): compare with the CLI from inside your network:',
  'oc.cli.shell': 'Shell',
  'oc.cli.posix': 'Linux / macOS',
  'oc.cli.powershell': 'Windows PowerShell',
  'oc.cli.none': 'The path holds characters no command line should carry: use a plain path.',
  'oc.failed': 'The comparison failed',
  'oc.quota': 'Not enough Globalping probes left this hour. More are available {when}; the CLI needs none.',
  'oc.quotaAfter': 'The hourly Globalping quota ran out after the old server was asked: the new one was not. What the old one answered is below; compare again {when}.',
  'oc.failedAfter': 'The old server was asked, the new one could not be: what the old one answered is below.',
  'oc.stopped': 'Stopped after the old server was asked: the new one was not. What the old one answered is below.',
  'oc.at': { one: 'Compared {time} from {where} · {count} probe', other: 'Compared {time} from {where} · {count} probes' },
  'oc.oldAt': 'The old server, asked {time} from {where}',
  'oc.measurement': 'measurement {n}',
  'oc.json': 'Download JSON',
  'oc.col.field': 'Field',
  'oc.col.old': 'Old · {ip}',
  'oc.col.new': 'New · {ip}',
  'oc.verdict.same': 'The new server answers like the old one (only informational differences).',
  'oc.verdict.differs': 'The new server answers differently: check the marked fields before you move the name.',
  'oc.verdict.broken': 'The new server is not ready: fix the fields marked as errors before you move the name.',
  'oc.verdict.incomplete': 'The old server did not answer, so there is nothing to compare with: the new server’s answer is shown.',
  'oc.verdict.unreachable': 'Neither server answered this probe. Its network may be the cause as much as the servers: check the addresses and the port, then compare again, or run the CLI from your own network.',
  'oc.field.reach': 'Reached',
  'oc.field.status': 'HTTP status',
  'oc.field.location': 'Redirect (Location)',
  'oc.field.contentType': 'Content-Type',
  'oc.field.title': 'Page title',
  'oc.field.body': 'Body (SHA-256)',
  'oc.field.hsts': 'HSTS',
  'oc.field.server': 'Server header',
  'oc.field.certSubject': 'Certificate names',
  'oc.field.certCovers': 'Certificate covers the name',
  'oc.field.certTrusted': 'Certificate trusted',
  'oc.field.certIssuer': 'Issuer',
  'oc.field.certExpires': 'Expires',
  'oc.field.certFingerprint': 'Certificate (SHA-256)',
  'oc.note.new-unreachable': 'The new server did not answer.',
  'oc.note.old-unreachable': 'The old server did not answer: nothing to compare with.',
  'oc.note.both-unreachable': 'Neither server answered.',
  'oc.note.new-error-status': 'The new server answers with an error status.',
  'oc.note.dynamic-body': 'A page with a token or a time in it differs on every request: compare the title and the status too.',
  'oc.note.body-cut': 'The probe returns the first 10,000 characters of a page: only those are compared.',
  'oc.note.hsts-lost': 'The new server sends no HSTS header: visitors whose browsers never saw it lose HTTPS-only.',
  'oc.note.hsts-off': 'The new server sends max-age=0: browsers that kept the old header forget it and allow plain HTTP again.',
  'oc.note.hsts-invalid': 'The new server’s HSTS header is not valid (no single usable max-age, or a directive given twice): browsers ignore it, so visitors whose browsers never saw the old one lose HTTPS-only.',
  'oc.note.hsts-weaker': 'The new header is weaker than the old one: a shorter max-age, or without includeSubDomains or preload.',
  'oc.note.hsts-new': 'The new server adds HSTS.',
  'oc.note.cert-name': 'The certificate does not cover the name: browsers refuse it.',
  'oc.note.cert-untrusted': 'The probe did not trust the certificate.',
  'oc.note.cert-untrusted-other': 'Not trusted either, but for another reason or from another issuer than the old one: a CDN or client that trusts the old certificate may refuse this one.',
  'oc.note.cert-expiring': 'The certificate expires within 14 days.',
  'oc.note.new-cert': 'Another certificate: usual on a new server.',
  'oc.note.same-cert': 'The same certificate.',
  'oc.shared.cert-untrusted': 'Both servers serve a certificate the probe does not trust (the same one, or one from the same issuer). That is no difference between them (an origin CA certificate behind a CDN is trusted by the CDN only), but a browser that reaches either server directly refuses it.',
  'oc.shared.cert-name': 'Neither server’s certificate covers the name. That is no difference between them (behind a CDN that does not check it, it goes unnoticed), but a browser that reaches either server directly refuses it.',
  'oc.shared.cert-expiring': 'Both servers serve a certificate that expires within 14 days: no difference between them, but renew it on both.',
  'oc.yes': 'yes',
  'oc.no': 'no',
  'oc.none': '—',
  'oc.reach.ok': 'yes',
  'oc.fail.refused': 'no: connection refused',
  'oc.fail.unreachable': 'no: address unreachable',
  'oc.fail.connect-timeout': 'no: no TCP connection in time',
  'oc.fail.tls-timeout': 'no: the TLS handshake timed out',
  'oc.fail.tls-alert': 'no: the server ended the TLS handshake',
  'oc.fail.reset': 'no: the connection was reset',
  'oc.fail.not-tls': 'no: no TLS on this port',
  'oc.fail.dns': 'no: a name lookup failed',
  'oc.fail.private': 'no: a private address',
  'oc.fail.internal': 'no: the probe failed',
  'oc.fail.offline': 'no: the probe went offline',
  'oc.fail.unknown': 'no answer',
  'oc.days': { one: '{date} ({count} day)', other: '{date} ({count} days)' },
  'oc.body': { one: '{hash}… ({length} character)', other: '{hash}… ({length} characters)' },
  'oc.bodyCut': '{hash}… (the first {length} characters)'
});

registerStrings('tr', {
  'oc.title': 'Eski ve yeni sunucuyu karşılaştırın',
  'oc.lead': 'Bir adı yeni bir adrese yönlendirmeden önce: yeni sunucu eskisi gibi yanıt veriyor mu? Adın SNI ve Host başlığı olduğu aynı HTTPS isteği tek bir Globalping ölçüm noktasından iki adrese de gider ve iki yanıt yan yana karşılaştırılır.',
  'oc.host': 'Host adı',
  'oc.host.placeholder': 'www.example.com',
  'oc.old': 'Eski adres',
  'oc.new': 'Yeni adres',
  'oc.path': 'Yol',
  'oc.port': 'Port',
  'oc.issue.host': 'Ölçüm noktasının sorabileceği bir host adı değil: {value}',
  'oc.issue.old-ip': 'Eski adres bir IP adresi değil: {value}',
  'oc.issue.new-ip': 'Yeni adres bir IP adresi değil: {value}',
  'oc.issue.same-ip': 'Eski ve yeni adres aynı.',
  'oc.issue.path': 'Yol / ile başlamalı ve yalnızca yazdırılabilir karakterler içermeli.',
  'oc.issue.port': 'Port değil: {value}',
  'oc.run': 'Karşılaştır ({probes} ölçüm)',
  'oc.stop': 'Durdur',
  'oc.switchRunning': 'Globalping’de eski ve yeni sunucu (kullandığı ölçümler geri gelmez)',
  'oc.running': 'İki sunucuya da soruluyor…',
  'oc.privacy': 'İki adresi, {host} adını ve {path} yolunu Globalping’e gönderir: bir ölçüm noktası her adrese bir HTTPS GET isteği gönderir (User-Agent “globalping probe”); yalnızca yönettiğiniz sunucuları karşılaştırın. Ölçüm kimliğini bilen herkes sonuçları yaklaşık altı ay okuyabilir: durum kodu, yanıt başlıkları ve her sayfanın ilk 10.000 karakteri.',
  'oc.private': {
    one: 'Ölçüm noktası {list} adresine ulaşamaz: özel, dokümantasyon ve ayrılmış adresler asla gönderilmez. Karşılaştırmayı ağınızın içinden çalıştırın:',
    other: 'Ölçüm noktası {list} adreslerine ulaşamaz: özel, dokümantasyon ve ayrılmış adresler asla gönderilmez. Karşılaştırmayı ağınızın içinden çalıştırın:'
  },
  'oc.cliPort': 'Ölçüm noktası yalnızca HTTPS portlarını sorar ({port} değil): ağınızın içinden CLI ile karşılaştırın:',
  'oc.cli.shell': 'Kabuk',
  'oc.cli.posix': 'Linux / macOS',
  'oc.cli.powershell': 'Windows PowerShell',
  'oc.cli.none': 'Yol, hiçbir komut satırının taşımaması gereken karakterler içeriyor: düz bir yol kullanın.',
  'oc.failed': 'Karşılaştırma başarısız oldu',
  'oc.quota': 'Bu saat için yeterli Globalping ölçümü kalmadı. {when} yeniden kullanılabilir; CLI ölçüm harcamaz.',
  'oc.quotaAfter': 'Eski sunucu sorulduktan sonra saatlik Globalping kotası doldu: yenisi sorulmadı. Eskisinin yanıtı aşağıda; {when} yeniden karşılaştırın.',
  'oc.failedAfter': 'Eski sunucu soruldu, yenisi sorulamadı: eskisinin yanıtı aşağıda.',
  'oc.stopped': 'Eski sunucu sorulduktan sonra durduruldu: yenisi sorulmadı. Eskisinin yanıtı aşağıda.',
  'oc.at': '{where} üzerinden {time} tarihinde karşılaştırıldı · {count} ölçüm',
  'oc.oldAt': 'Eski sunucu, {time} tarihinde {where} üzerinden soruldu',
  'oc.measurement': 'ölçüm {n}',
  'oc.json': 'JSON indir',
  'oc.col.field': 'Alan',
  'oc.col.old': 'Eski · {ip}',
  'oc.col.new': 'Yeni · {ip}',
  'oc.verdict.same': 'Yeni sunucu eskisi gibi yanıt veriyor (yalnızca bilgi amaçlı farklar var).',
  'oc.verdict.differs': 'Yeni sunucu farklı yanıt veriyor: adı taşımadan önce işaretli alanlara bakın.',
  'oc.verdict.broken': 'Yeni sunucu hazır değil: adı taşımadan önce hata olarak işaretli alanları düzeltin.',
  'oc.verdict.incomplete': 'Eski sunucu yanıt vermedi, karşılaştırılacak bir şey yok: yeni sunucunun yanıtı gösteriliyor.',
  'oc.verdict.unreachable': 'İki sunucu da bu ölçüm noktasına yanıt vermedi. Sebep sunucular kadar ölçüm noktasının ağı da olabilir: adresleri ve portu kontrol edip yeniden karşılaştırın ya da CLI’ı kendi ağınızdan çalıştırın.',
  'oc.field.reach': 'Ulaşıldı',
  'oc.field.status': 'HTTP durum kodu',
  'oc.field.location': 'Yönlendirme (Location)',
  'oc.field.contentType': 'Content-Type',
  'oc.field.title': 'Sayfa başlığı',
  'oc.field.body': 'Gövde (SHA-256)',
  'oc.field.hsts': 'HSTS',
  'oc.field.server': 'Server başlığı',
  'oc.field.certSubject': 'Sertifikadaki adlar',
  'oc.field.certCovers': 'Sertifika adı kapsıyor',
  'oc.field.certTrusted': 'Sertifika güvenilir',
  'oc.field.certIssuer': 'Veren',
  'oc.field.certExpires': 'Bitiş',
  'oc.field.certFingerprint': 'Sertifika (SHA-256)',
  'oc.note.new-unreachable': 'Yeni sunucu yanıt vermedi.',
  'oc.note.old-unreachable': 'Eski sunucu yanıt vermedi: karşılaştırılacak bir şey yok.',
  'oc.note.both-unreachable': 'İki sunucu da yanıt vermedi.',
  'oc.note.new-error-status': 'Yeni sunucu bir hata durum koduyla yanıt veriyor.',
  'oc.note.dynamic-body': 'İçinde bir belirteç ya da zaman olan sayfa her istekte farklıdır: başlığı ve durum kodunu da karşılaştırın.',
  'oc.note.body-cut': 'Ölçüm noktası bir sayfanın ilk 10.000 karakterini döndürür: yalnızca onlar karşılaştırılır.',
  'oc.note.hsts-lost': 'Yeni sunucu HSTS başlığı göndermiyor: tarayıcısı onu hiç görmemiş ziyaretçiler yalnızca-HTTPS korumasını kaybeder.',
  'oc.note.hsts-off': 'Yeni sunucu max-age=0 gönderiyor: eski başlığı saklayan tarayıcılar onu unutur ve yeniden düz HTTP’ye izin verir.',
  'oc.note.hsts-invalid': 'Yeni sunucunun HSTS başlığı geçerli değil (tek ve kullanılabilir bir max-age yok ya da bir yönerge iki kez verilmiş): tarayıcılar onu yok sayar, bu yüzden eski başlığı hiç görmemiş ziyaretçiler yalnızca-HTTPS korumasını kaybeder.',
  'oc.note.hsts-weaker': 'Yeni başlık eskisinden zayıf: daha kısa bir max-age ya da includeSubDomains veya preload eksik.',
  'oc.note.hsts-new': 'Yeni sunucu HSTS ekliyor.',
  'oc.note.cert-name': 'Sertifika adı kapsamıyor: tarayıcılar onu reddeder.',
  'oc.note.cert-untrusted': 'Ölçüm noktası sertifikaya güvenmedi.',
  'oc.note.cert-untrusted-other': 'Buna da güvenilmiyor, ama başka bir nedenle ya da sertifikayı eskisinden farklı bir kuruluş vermiş: eski sertifikaya güvenen bir CDN ya da istemci bunu reddedebilir.',
  'oc.note.cert-expiring': 'Sertifikanın süresi 14 gün içinde doluyor.',
  'oc.note.new-cert': 'Başka bir sertifika: yeni bir sunucuda olağan.',
  'oc.note.same-cert': 'Aynı sertifika.',
  'oc.shared.cert-untrusted': 'İki sunucu da ölçüm noktasının güvenmediği bir sertifika sunuyor (aynı sertifika ya da aynı kuruluşun verdiği). Bu, ikisi arasında bir fark değil (CDN arkasındaki bir origin CA sertifikasına yalnızca CDN güvenir), ama sunuculardan birine doğrudan ulaşan bir tarayıcı onu reddeder.',
  'oc.shared.cert-name': 'İki sunucunun da sertifikası adı kapsamıyor. Bu, ikisi arasında bir fark değil (bunu denetlemeyen bir CDN arkasında fark edilmez), ama sunuculardan birine doğrudan ulaşan bir tarayıcı onu reddeder.',
  'oc.shared.cert-expiring': 'İki sunucu da süresi 14 gün içinde dolan bir sertifika sunuyor: ikisi arasında bir fark değil, ama ikisinde de yenileyin.',
  'oc.yes': 'evet',
  'oc.no': 'hayır',
  'oc.none': '—',
  'oc.reach.ok': 'evet',
  'oc.fail.refused': 'hayır: bağlantı reddedildi',
  'oc.fail.unreachable': 'hayır: adrese ulaşılamıyor',
  'oc.fail.connect-timeout': 'hayır: TCP bağlantısı zamanında kurulamadı',
  'oc.fail.tls-timeout': 'hayır: TLS el sıkışması zaman aşımına uğradı',
  'oc.fail.tls-alert': 'hayır: sunucu TLS el sıkışmasını sonlandırdı',
  'oc.fail.reset': 'hayır: bağlantı sıfırlandı',
  'oc.fail.not-tls': 'hayır: bu portta TLS yok',
  'oc.fail.dns': 'hayır: bir ad çözümlemesi başarısız oldu',
  'oc.fail.private': 'hayır: özel bir adres',
  'oc.fail.internal': 'hayır: ölçüm noktası başarısız oldu',
  'oc.fail.offline': 'hayır: ölçüm noktası çevrimdışı oldu',
  'oc.fail.unknown': 'yanıt yok',
  'oc.days': '{date} ({count} gün)',
  'oc.body': '{hash}… ({length} karakter)',
  'oc.bodyCut': '{hash}… (ilk {length} karakter)'
});

/**
 * Every i18n key this panel builds from a library code (for the coverage tests).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...COMPARE_FIELDS.map((f) => `oc.field.${f}`),
    ...COMPARE_VERDICTS.map((v) => `oc.verdict.${v}`),
    ...COMPARE_NOTES.map((n) => `oc.note.${n}`),
    ...COMPARE_SHARED.map((n) => `oc.shared.${n}`),
    ...COMPARE_ISSUES.map((i) => `oc.issue.${i}`),
    ...FAILURE_KINDS.map((k) => `oc.fail.${k}`)
  ];
}

/* ------------------------------------------------------------------------ */
/* Page-session state                                                       */
/* ------------------------------------------------------------------------ */

const fresh = () => ({
  host: '', oldIp: '', newIp: '', path: '/', port: '443', shell: 'posix', status: 'idle', result: null, error: null, resetAt: null,
  partial: null, controller: null, touched: false
});
let S = fresh();
/** The card on screen: a return to Retire an IP (or a language switch) during a run mounts a new one, and the run renders there. */
let shown = null;

state.subscribe(({ key }) => {
  // A comparison of one customer's servers is not another's.
  if (key !== 'cleared' && key !== 'workspace') return;
  if (S.controller) S.controller.abort();
  S = fresh();
});
// A switch to another workspace names a comparison still running before it stops it (ui/jobs.js).
registerRunning('oc.switchRunning', () => !!S.controller);

/* ------------------------------------------------------------------------ */
/* Display values                                                           */
/* ------------------------------------------------------------------------ */

/**
 * A field's value as the table shows it.
 * @param {string} key
 * @param {unknown} value
 * @param {object|null} side the CompareSide the value comes from
 * @returns {string}
 */
export function displayValue(key, value, side) {
  if (value === null || value === undefined || value === '') return t('oc.none');
  if (key === 'reach') {
    if (value === 'ok') return t('oc.reach.ok');
    // The failure kind in the page's language; the probe's own line (data) after it.
    const label = FAILURE_KINDS.includes(value) ? t(`oc.fail.${value}`) : String(value);
    return side && side.failure && side.failure.text ? `${label} — ${side.failure.text}` : label;
  }
  // Why the probe did not trust the certificate (the CLI's "no: <reason>"), before the plain yes / no.
  if (key === 'certTrusted' && value === false && side && side.cert && side.cert.error) return `${t('oc.no')}: ${side.cert.error}`;
  if (typeof value === 'boolean') return t(value ? 'oc.yes' : 'oc.no');
  if (key === 'body') {
    const b = side && side.body;
    return b ? t(b.truncated ? 'oc.bodyCut' : 'oc.body', { hash: String(value).slice(0, 16), count: b.length, length: formatNumber(b.length) }) : String(value);
  }
  if (key === 'certFingerprint') return `${String(value).slice(0, 16)}…`;
  if (key === 'certExpires' && side && side.cert && Number.isFinite(side.cert.daysLeft)) {
    return t('oc.days', { date: String(value), count: side.cert.daysLeft });
  }
  return String(value);
}

/* ------------------------------------------------------------------------ */
/* The card                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * The comparison card for Retire an IP.
 * @param {{ ctx: object, defaults?: () => { ip?: string|null, host?: string|null } }} opts
 *   `defaults`: what the view knows (the single address being retired, a domain being checked),
 *   filled into boxes nobody has typed in
 * @returns {{ el: HTMLElement, render(): void }}
 */
export function OriginCompareCard({ ctx, defaults = () => ({}) }) {
  const el = h('div', { class: 'oc-card-host' });

  function fillDefaults() {
    if (S.touched) return;
    const d = defaults() || {};
    if (d.ip) S.oldIp = d.ip;
    if (d.host) S.host = d.host;
  }

  function field(key, label, opts = {}) {
    const input = textInput({
      label,
      value: S[key],
      placeholder: opts.placeholder || '',
      mono: true,
      inputmode: opts.inputmode || 'url',
      className: `oc-field oc-field-${key}`,
      attrs: { 'data-role': `oc-${key}` },
      onInput: (v) => {
        S[key] = v;
        S.touched = true;
        renderSoon();
      },
      onEnter: () => start()
    });
    return input.el;
  }

  let timer = null;
  function renderSoon() {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const active = document.activeElement;
      const role = active && el.contains(active) ? active.dataset.role : null;
      const sel = role && typeof active.selectionStart === 'number' ? [active.selectionStart, active.selectionEnd] : null;
      render();
      const again = role ? el.querySelector(`[data-role="${role}"]`) : null;
      if (again) {
        again.focus();
        if (sel) again.setSelectionRange(sel[0], sel[1]);
      }
    }, 250);
  }

  /** The control that takes over keyboard focus from `role` after a rebuild: Compare ⇄ Stop as a run starts or ends. */
  const focusSuccessor = (role, running) => (role === 'oc-run' && running ? 'oc-stop' : role === 'oc-stop' && !running ? 'oc-run' : role);

  function render() {
    const doc = globalThis.document;
    const active = doc && doc.activeElement;
    const focusRole = active && el.contains(active) && active.dataset ? active.dataset.role || active.dataset.action || null : null;
    fillDefaults();
    clear(el);
    renderCard();
    // Keyboard focus stays on its control, rebuilt; from Compare to Stop and back as a run starts
    // and ends (a disabled or removed button would drop it to the page).
    const want = focusRole ? focusSuccessor(focusRole, !!S.controller) : null;
    const again = want ? el.querySelector(`[data-role="${want}"], [data-action="${want}"]`) : null;
    if (again && !again.disabled) again.focus({ preventScroll: true });
  }

  function renderCard() {
    const check = checkCompare({ host: S.host, oldIp: S.oldIp, newIp: S.newIp, path: S.path, port: S.port });
    const typed = !!(S.host.trim() || S.newIp.trim());
    const issues = typed ? check.issues.filter((i) => (i.code === 'host' ? S.host.trim() : true) && (i.code !== 'new-ip' || S.newIp.trim())) : [];
    const running = !!S.controller;
    const body = h('div', { class: 'stack-sm' },
      h('p', { class: 'text-sm' }, t('oc.lead')),
      h('div', { class: 'oc-form' },
        field('host', t('oc.host'), { placeholder: t('oc.host.placeholder') }),
        field('oldIp', t('oc.old'), { placeholder: '192.0.2.10' }),
        field('newIp', t('oc.new'), { placeholder: '198.51.100.20' }),
        field('path', t('oc.path'), { placeholder: '/' }),
        field('port', t('oc.port'), { placeholder: '443', inputmode: 'numeric' })));
    if (issues.length) {
      body.append(h('ul', { class: 'oc-issues text-sm', dataset: { role: 'oc-issues' } },
        issues.map((i) => h('li', { dataset: { code: i.code } }, SeverityIcon('warn'), ' ', t(`oc.issue.${i.code}`, { value: i.value })))));
    }
    if (check.ok && !check.probeable) {
      body.append(cliBlock(check));
    } else {
      body.append(h('div', { class: 'cluster oc-actions' },
        Button({
          label: t('oc.run', { probes: COMPARE_PROBES }),
          icon: 'swap',
          variant: 'primary',
          disabled: running || !check.ok,
          dataset: { action: 'oc-run' },
          onClick: () => start()
        }),
        running ? Button({ label: t('oc.stop'), icon: 'stop', variant: 'secondary', dataset: { action: 'oc-stop', shortcut: 'cancel' }, onClick: () => S.controller && S.controller.abort() }) : null,
        running ? Spinner({ size: 'sm', label: t('oc.running'), showLabel: true }) : null),
      h('p', { class: 'muted text-xs oc-privacy' }, Icon('lock', { size: 12 }), ' ',
        t('oc.privacy', { host: check.host || t('oc.host.placeholder'), path: check.path })));
    }
    if (S.status === 'quota') body.append(Alert({ variant: 'warn', compact: true, icon: 'clock', message: t('oc.quota', { when: whenText(S.resetAt) }) }));
    if (S.status === 'failed' && S.error) {
      const quotaAfter = S.partial && QUOTA_CODES.has(S.error.code);
      body.append(quotaAfter ? Alert({ variant: 'warn', compact: true, icon: 'clock', message: t('oc.quotaAfter', { when: whenText(S.error.resetAt) }) })
        : S.partial ? Alert({ variant: 'warn', compact: true, message: t('oc.failedAfter') })
          : ErrorBanner(S.error, { title: t('oc.failed'), compact: true }));
    }
    if (S.status === 'stopped' && S.partial) body.append(Alert({ variant: 'info', compact: true, message: t('oc.stopped') }));
    if (S.partial) body.append(partialResults(S.partial));
    if (S.result) body.append(results(S.result));
    el.append(Card({ title: t('oc.title'), icon: 'swap', className: 'oc-card', children: body }));
  }

  function cliBlock(check) {
    const cmd = buildCompareCommand({ host: check.host, oldIp: check.oldIp, newIp: check.newIp, path: check.path, port: check.port, shell: S.shell });
    const shell = SegmentedControl({
      label: t('oc.cli.shell'), size: 'sm', value: S.shell, className: 'oc-shell',
      options: [{ value: 'posix', label: t('oc.cli.posix') }, { value: 'powershell', label: t('oc.cli.powershell') }],
      onChange: (v) => {
        S.shell = v === 'powershell' ? 'powershell' : 'posix';
        render();
      }
    });
    const lead = check.private.length ? t('oc.private', { count: check.private.length, list: check.private.join(', ') }) : t('oc.cliPort', { port: check.port });
    return h('div', { class: 'stack-sm oc-cli', dataset: { role: 'oc-cli' } },
      Alert({ variant: 'info', compact: true, icon: 'terminal', message: lead }),
      shell.el,
      cmd ? CodeBlock(cmd, { wrap: true, className: 'oc-command' }) : h('p', { class: 'muted text-sm' }, t('oc.cli.none')));
  }

  async function start() {
    const check = checkCompare({ host: S.host, oldIp: S.oldIp, newIp: S.newIp, path: S.path, port: S.port });
    if (S.controller || !check.ok || !check.probeable || !ctx.requireOnline()) return;
    const ac = new AbortController();
    const prev = { status: S.status, result: S.result, partial: S.partial, error: S.error };
    Object.assign(S, { controller: ac, status: 'running', error: null, partial: null });
    ctx.setBusy(true);
    shown.render();
    try {
      const gate = await gateProbes(ctx, {
        purpose: COMPARE_PURPOSE, probes: COMPARE_PROBES, signal: ac.signal, className: 'oc-confirm',
        privacy: t('oc.privacy', { host: check.host, path: check.path })
      });
      if (S.controller !== ac) return;
      if (gate.status === 'cancelled') {
        Object.assign(S, prev);
        return;
      }
      if (gate.status === 'quota') {
        Object.assign(S, prev, { status: 'quota', resetAt: gate.resetAt });
        announce(t('oc.quota', { when: whenText(gate.resetAt) }));
        return;
      }
      if (gate.status === 'unreachable') throw gate.error;
      const result = await runCompare({ client: gate.client, host: check.host, oldIp: check.oldIp, newIp: check.newIp, path: check.path, port: check.port, signal: ac.signal });
      noteQuota(gate.client.quota);
      if (S.controller !== ac) return;
      Object.assign(S, { status: 'done', result: { ...result, host: check.host, path: check.path, port: check.port } });
      announce(t(`oc.verdict.${result.comparison.verdict}`));
    } catch (err) {
      if (S.controller !== ac) return;
      // The old server's answer, measured (and paid for) before a stop or a failure, stays on screen.
      const first = err && typeof err === 'object' && err.first ? { side: err.first, at: new Date() } : null;
      if (errorKind(err) === 'abort' || ac.signal.aborted) {
        if (first) Object.assign(S, { status: 'stopped', result: null, partial: first });
        else Object.assign(S, prev);
      } else {
        if (err && err.quota) noteQuota(err.quota);
        Object.assign(S, { status: 'failed', error: err, result: first ? null : S.result, partial: first });
      }
    } finally {
      if (S.controller === ac) S.controller = null;
      ctx.setBusy(false);
      // The card on screen now, which may not be the one that started the run.
      if (shown && shown.connected()) shown.render();
    }
  }

  function probeWhere(probe) {
    return probe ? [probe.city, probe.country].filter(Boolean).join(', ') + (probe.asn ? ` (AS${probe.asn})` : '') : '?';
  }

  function measurementLinks(ids) {
    const links = ids.map((id) => measurementUrl(id)).filter(Boolean);
    return links.length ? h('span', null, ' · ', ...links.flatMap((href, i) => [i ? ', ' : '',
      h('a', { href, class: 'link', attrs: { target: '_blank', rel: 'noopener noreferrer' } }, t('oc.measurement', { n: i + 1 }))])) : null;
  }

  /** The old server's answer alone: a stop or a failure came before the new one was asked. */
  function partialResults(p) {
    const side = p.side;
    const out = h('div', { class: 'stack-sm oc-results oc-partial', dataset: { verdict: 'partial' } });
    out.append(h('p', { class: 'muted text-sm oc-at' }, t('oc.oldAt', { time: formatDateTime(p.at), where: probeWhere(side.probe) }),
      measurementLinks(side.measurementId ? [side.measurementId] : [])));
    const label = t('oc.col.old', { ip: side.ip });
    const table = h('table', { class: 'oc-table oc-table-one', dataset: { role: 'oc-table' } },
      h('thead', null, h('tr', null,
        h('th', { attrs: { scope: 'col' } }, t('oc.col.field')),
        h('th', { attrs: { scope: 'col' } }, label))),
      h('tbody', null, sideFields(side).map((f) => h('tr', { class: 'oc-row', dataset: { field: f.key } },
        h('th', { attrs: { scope: 'row' } }, h('span', { class: 'oc-field-name' }, t(`oc.field.${f.key}`))),
        h('td', { class: 'mono', dataset: { label } }, displayValue(f.key, f.value, side))))));
    out.append(h('div', { class: 'oc-table-wrap' }, table));
    return out;
  }

  function results(r) {
    const c = r.comparison;
    const out = h('div', { class: 'stack-sm oc-results', dataset: { verdict: c.verdict } });
    out.append(Alert({ variant: VERDICT_VARIANT[c.verdict], message: t(`oc.verdict.${c.verdict}`) }));
    // A certificate problem both servers share: no difference, but worth knowing before the move.
    for (const note of c.shared || []) {
      out.append(Alert({ variant: 'warn', compact: true, message: t(`oc.shared.${note}`), icon: 'lock' }));
    }
    out.append(h('p', { class: 'muted text-sm oc-at' }, t('oc.at', { time: formatDateTime(r.at), where: probeWhere(r.old.probe || r.new.probe), count: r.spent }),
      measurementLinks(r.ids)));
    const table = h('table', { class: 'oc-table', dataset: { role: 'oc-table' } },
      h('thead', null, h('tr', null,
        h('th', { attrs: { scope: 'col' } }, t('oc.col.field')),
        h('th', { attrs: { scope: 'col' } }, t('oc.col.old', { ip: r.old.ip })),
        h('th', { attrs: { scope: 'col' } }, t('oc.col.new', { ip: r.new.ip })))),
      h('tbody', null, c.fields.map((f) => {
        const oldText = displayValue(f.key, f.old, r.old);
        const newText = displayValue(f.key, f.new, r.new);
        return h('tr', { class: ['oc-row', `oc-sev-${f.severity}`, { 'oc-differs': !f.same }], dataset: { field: f.key, severity: f.severity, same: String(f.same) } },
          h('th', { attrs: { scope: 'row' } },
            h('span', { class: 'oc-field-name' }, f.severity !== 'ok' ? SeverityIcon(SEV_ICON[f.severity]) : null, t(`oc.field.${f.key}`)),
            f.note ? h('span', { class: 'oc-note text-xs' }, t(`oc.note.${f.note}`)) : null),
          h('td', { class: 'mono', dataset: { label: t('oc.col.old', { ip: r.old.ip }) } }, oldText),
          h('td', { class: ['mono', { 'oc-new-differs': !f.same }], dataset: { label: t('oc.col.new', { ip: r.new.ip }) } }, newText));
      })));
    out.append(h('div', { class: 'oc-table-wrap' }, table));
    out.append(h('div', { class: 'cluster' }, Button({
      label: t('oc.json'), icon: 'download', size: 'sm', variant: 'secondary', dataset: { action: 'oc-json' },
      onClick: () => downloadJson(timestampedName('compare', 'json', r.host), {
        schema: 'domainscope.compare/1', name: r.host, path: r.path, port: r.port, at: r.at, verdict: c.verdict, shared: c.shared || [], fields: c.fields,
        old: sideJson(r.old), new: sideJson(r.new), measurements: r.ids
      })
    })));
    return out;
  }

  shown = { render, connected: () => el.isConnected };
  render();
  return { el, render };
}

/** A side for the JSON export: no probe network details beyond the summary, dates as ISO text. */
function sideJson(s) {
  return {
    ip: s.ip, ok: s.ok, failure: s.failure, status: s.status, location: s.location, contentType: s.contentType, server: s.server,
    hsts: s.hsts ? s.hsts.raw : null, title: s.body ? s.body.title : null, body: s.body ? { sha256: s.body.sha256, length: s.body.length, truncated: s.body.truncated } : null,
    certificate: s.cert ? {
      ...s.cert, notBefore: s.cert.notBefore ? s.cert.notBefore.toISOString() : null, notAfter: s.cert.notAfter ? s.cert.notAfter.toISOString() : null
    } : null,
    probe: s.probe, measurementId: s.measurementId
  };
}
