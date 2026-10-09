/**
 * ui/origin-compare.js — "Compare the old and the new server", Retire an IP's sub-page
 * `#/retire/compare`: before DNS moves a name to a new address, does the new server answer like
 * the old one? The logic is lib/origincompare.js; this module only renders it.
 *
 * It belongs to Retire an IP because that is where a server gets a new address: the old address
 * is the one being retired, and the names the reference check finds are the ones to move. It has a
 * page of its own (docs/DESIGN.md §8 phase 4: two tools no longer share one page), on the page
 * template (ui/template.js): the input card, Compare in the run bar, what is sent in the card's
 * footer, then the verdict as the result header and the table.
 *
 * - Nothing is sent until "Compare" is clicked. Then, behind the shared Globalping gate
 *   (ui/globalping-gate.js: the free quota read, the consent + cost dialog on the first send of
 *   the page session), two probes: one HTTPS GET of the path at each address, with the name as
 *   the SNI and the Host header, the second from the first one's probe.
 * - Private, documentation and reserved addresses are never sent: the card gives the CLI's
 *   `ssl_origin_scan.py --compare` command instead, which does the same from inside the network.
 * - The form and the last comparison live in this module (the page session): leaving the page
 *   or switching the language keeps them (a run goes on, and ends on the page shown when it
 *   ends); "Delete all local data" and another workspace drop them.
 * - A comparison whose new server answered with a certificate covering the name offers "Remember
 *   <address> as the origin of <name>": one click puts it into the workspace's origin map
 *   (ui/origin-map.js, source 'compare') while the workspace remembers origins.
 * - Every string is rendered through h() / text nodes: status lines, titles, header values and
 *   certificate names come from the servers.
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import {
  Alert, Button, CodeBlock, Disclosure, ErrorBanner, Icon, SegmentedControl, SeverityIcon, announce, textInput
} from './components.js';
import { downloadJson, timestampedName } from './download.js';
import { gateProbes, noteQuota, whenText, measurementUrl } from './globalping-gate.js';
import { registerRunning } from './jobs.js';
import { EmptyState, PrivacyNote, ResultActions, ResultHeader, ResultTitle, RunBar, ToolInput } from './template.js';
import { t, registerStrings, formatNumber, formatDateTime } from '../i18n.js';
import {
  checkCompare, runCompare, buildCompareCommand, sideFields, COMPARE_FIELDS, COMPARE_VERDICTS, COMPARE_NOTES, COMPARE_SHARED, COMPARE_ISSUES,
  COMPARE_PROBES, COMPARE_SEVERITY
} from '../lib/origincompare.js';
import { inputCompact, optionsSummary, templateState } from '../lib/template.js';
import { FAILURE_KINDS } from '../lib/verify.js';
import { errorKind } from '../lib/util.js';
import { state } from '../state.js';
import { compareObservations } from '../lib/originfill.js';
import { originTarget } from '../lib/originmap.js';
import { OriginMapOffNote, recordOrigins, recordText, rememberOn } from './origin-map.js';

/** Consent purpose of the gate (one per feature: each sends different data). */
export const COMPARE_PURPOSE = 'origin-compare';

/** The compared fields the empty page names (what a comparison looks at). */
const EMPTY_CHECKS = Object.freeze(['status', 'location', 'title', 'body', 'hsts', 'certSubject']);

const SEV_ICON = Object.freeze({ ok: 'ok', info: 'info', warn: 'warn', error: 'error' });
const QUOTA_CODES = new Set(['rate-limit', 'insufficient-credits']);

registerStrings('en', {
  'oc.title': 'Compare the old and the new server',
  'oc.purpose': 'The same HTTPS request to the old and the new server, side by side.',
  'oc.emptyLine': 'Each answer’s status, redirect, title, body, HSTS and certificate, side by side, with what differs marked.',
  'oc.how': 'How it works',
  'oc.portSummary': 'port {port}',
  'oc.partialTitle': 'Only the old server’s answer',
  'oc.jsonTitle': 'Download the comparison as JSON',
  'oc.back': 'Back to Retire an IP',
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
  'oc.remember': 'Remember {target} as the origin of {host}',
  'oc.rememberHint': 'Puts the new server into this workspace’s origin map, so Subdomains and SSL Targets rank it first for this name.',
  'oc.quota': 'Not enough Globalping probes left this hour. More are available {when}; the CLI needs none.',
  'oc.quotaAfter': 'The hourly Globalping quota ran out after the old server was asked: the new one was not. What the old one answered is below; compare again {when}.',
  'oc.failedAfter': 'The old server was asked, the new one could not be: what the old one answered is below.',
  'oc.stopped': 'Stopped after the old server was asked: the new one was not. What the old one answered is below.',
  'oc.at': { one: 'Compared {time} from {where} · {count} probe', other: 'Compared {time} from {where} · {count} probes' },
  'oc.oldAt': 'The old server, asked {time} from {where}',
  'oc.measurement': 'measurement {n}',
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
  'oc.purpose': 'Eski ve yeni sunucuya aynı HTTPS isteği, yan yana.',
  'oc.emptyLine': 'Her yanıtın durum kodu, yönlendirmesi, başlığı, gövdesi, HSTS’i ve sertifikası yan yana; farklı olanlar işaretli.',
  'oc.how': 'Nasıl çalışır',
  'oc.portSummary': 'port {port}',
  'oc.partialTitle': 'Yalnızca eski sunucunun yanıtı',
  'oc.jsonTitle': 'Karşılaştırmayı JSON olarak indir',
  'oc.back': 'IP emekliye ayırmaya dön',
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
  'oc.remember': '{target} adresini {host} adının origin’i olarak hatırla',
  'oc.rememberHint': 'Yeni sunucuyu bu çalışma alanının origin haritasına ekler; Subdomain Tarama ve SSL Hedefleri bu ad için onu ilk sıraya koyar.',
  'oc.quota': 'Bu saat için yeterli Globalping ölçümü kalmadı. {when} yeniden kullanılabilir; CLI ölçüm harcamaz.',
  'oc.quotaAfter': 'Eski sunucu sorulduktan sonra saatlik Globalping kotası doldu: yenisi sorulmadı. Eskisinin yanıtı aşağıda; {when} yeniden karşılaştırın.',
  'oc.failedAfter': 'Eski sunucu soruldu, yenisi sorulamadı: eskisinin yanıtı aşağıda.',
  'oc.stopped': 'Eski sunucu sorulduktan sonra durduruldu: yenisi sorulmadı. Eskisinin yanıtı aşağıda.',
  'oc.at': '{where} üzerinden {time} tarihinde karşılaştırıldı · {count} ölçüm',
  'oc.oldAt': 'Eski sunucu, {time} tarihinde {where} üzerinden soruldu',
  'oc.measurement': 'ölçüm {n}',
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
  partial: null, controller: null, touched: false, link: null
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

/**
 * What a mount of the page puts into the host name and old address boxes. A link's values
 * (`?host=`, `?old=`: a Retire check's next step names the pair to compare) fill their boxes, typed
 * in or not, the first time the page opens on that link; the same link mounted again (a language
 * switch, Back to it) keeps what was typed since. What the page only guesses — Retire's one address
 * and first domain — fills only the boxes nobody has typed in and no link names.
 * @param {{ host: string, oldIp: string, touched: boolean, link: string|null }} form the boxes, and the link filled in last
 * @param {{ link?: { ip?: string|null, host?: string|null }|null, ip?: string|null, host?: string|null }} [defaults] the link's
 *   normalized values, and the guesses (views/retire.js compareDefaults)
 * @returns {{ host: string, oldIp: string, link: string|null }} `link`: the link of this mount, null without one
 */
export function compareFill(form, { link = null, ip = null, host = null } = {}) {
  const linkIp = (link && link.ip) || null;
  const linkHost = (link && link.host) || null;
  const key = linkIp || linkHost ? `${linkIp || ''} ${linkHost || ''}` : null;
  const out = { host: form.host, oldIp: form.oldIp, link: key };
  if (key && key !== form.link) {
    if (linkIp) out.oldIp = linkIp;
    if (linkHost) out.host = linkHost;
  }
  if (!form.touched) {
    if (ip && !linkIp) out.oldIp = ip;
    if (host && !linkHost) out.host = host;
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* The page (#/retire/compare)                                              */
/* ------------------------------------------------------------------------ */

/**
 * The comparison on a page of its own, Retire an IP's sub-page `#/retire/compare`, on the page
 * template (docs/DESIGN.md §5): one input card — the host name with Compare on its row, the old and
 * the new address beside it, the path and the port under them (behind Edit once a comparison has
 * run), the form's problems and the CLI command for addresses a probe cannot reach under it, what is
 * sent in its footer —, then the result header (the verdict, when and from where, a certificate
 * problem both servers share, the JSON file, "Remember …") and the table. Compare and Stop take
 * turns in the run bar, the keyboard focus going with them.
 * @param {{ ctx: object, defaults?: () => { link?: { ip?: string|null, host?: string|null }|null, ip?: string|null, host?: string|null } }} opts
 *   `defaults`: what the page knows — the link's host and old address, which fill their boxes on a
 *   link not filled in yet, and Retire an IP's single address and first domain, which fill boxes
 *   nobody has typed in ({@link compareFill})
 * @returns {{ el: HTMLElement, render(): void, dispose(): void }}
 */
export function OriginComparePage({ ctx, defaults = () => ({}) }) {
  Object.assign(S, compareFill(S, defaults() || {}));

  const field = (key, label, opts = {}) => textInput({
    label,
    value: S[key],
    placeholder: opts.placeholder || '',
    mono: true,
    inputmode: opts.inputmode || 'url',
    className: `oc-field oc-field-${key}`,
    attrs: { 'data-role': `oc-${key}`, ...(opts.focus ? { 'data-shortcut': 'focus' } : {}) },
    onInput: (v) => {
      S[key] = v;
      S.touched = true;
      syncSoon();
    },
    onEnter: () => start()
  }).el;

  /** Whether Compare can run with what the boxes hold (an address a probe cannot reach goes to the CLI). */
  let canRun = false;
  const runBar = RunBar({
    label: t('oc.run', { probes: COMPARE_PROBES }),
    dataset: { action: 'oc-run', shortcut: 'submit' },
    stopLabel: t('oc.stop'),
    stopDataset: { action: 'oc-stop', shortcut: 'cancel' },
    onRun: () => start(),
    onStop: () => { if (S.controller) S.controller.abort(); },
    hasValue: () => canRun || !!S.controller
  });
  const notesEl = h('div', { class: 'stack-sm oc-notes' });
  const privacyText = h('span', { class: 'oc-privacy-text' });
  // A form of its own for the shell's shortcuts: Ctrl/Cmd+Enter in its fields compares (lib/shellnav.js pickShortcutTarget).
  const input = ToolInput({
    className: 'oc-card',
    fieldsClass: 'oc-form',
    label: t('oc.title'),
    dataset: { shortcutScope: 'origin-compare' },
    primary: field('host', t('oc.host'), { placeholder: t('oc.host.placeholder'), focus: true }),
    inline: [field('oldIp', t('oc.old'), { placeholder: '192.0.2.10' }), field('newIp', t('oc.new'), { placeholder: '198.51.100.20' })],
    run: runBar,
    notes: [notesEl],
    more: [h('div', { class: 'oc-more' }, field('path', t('oc.path'), { placeholder: '/' }), field('port', t('oc.port'), { placeholder: '443', inputmode: 'numeric' }))],
    privacy: PrivacyNote({ text: privacyText, className: 'oc-privacy' }),
    summary: () => optionsSummary([
      [S.oldIp.trim(), S.newIp.trim()].filter(Boolean).join(' → '),
      { label: S.path.trim(), isDefault: !S.path.trim() || S.path.trim() === '/' },
      { label: t('oc.portSummary', { port: S.port.trim() }), isDefault: !S.port.trim() || S.port.trim() === '443' }
    ])
  });
  const emptyEl = h('div', { class: 'oc-empty' }, EmptyState({
    icon: 'swap',
    message: t('oc.emptyLine'),
    checks: EMPTY_CHECKS.map((f) => t(`oc.field.${f}`)),
    details: Disclosure({ summary: t('oc.how'), className: 'oc-how', children: h('p', { class: 'text-sm' }, t('oc.lead')) })
  }));
  const resultsEl = h('div', { class: 'oc-results-host' });
  const el = h('div', { class: 'oc-page tool-stack' }, input.el, emptyEl, resultsEl, runBar.float);
  /** The result header's actions (the JSON file), disposed with the header they belong to. */
  let actions = null;
  /** The form as the result on screen was compared: Compare reads "Run again" while the boxes still ask for it. */
  const askedOf = (r) => (r ? [r.host, r.old && r.old.ip, r.new && r.new.ip, r.path, String(r.port)].join('\n') : null);

  /** The form's problems, the CLI command or the run bar, what is sent, the compact line and Run's state. */
  function sync() {
    const check = checkCompare({ host: S.host, oldIp: S.oldIp, newIp: S.newIp, path: S.path, port: S.port });
    const typed = !!(S.host.trim() || S.newIp.trim());
    const issues = typed ? check.issues.filter((i) => (i.code === 'host' ? S.host.trim() : true) && (i.code !== 'new-ip' || S.newIp.trim())) : [];
    const running = !!S.controller;
    const cli = check.ok && !check.probeable;
    clear(notesEl);
    if (issues.length) {
      notesEl.append(h('ul', { class: 'oc-issues text-sm', dataset: { role: 'oc-issues' } },
        issues.map((i) => h('li', { dataset: { code: i.code } }, SeverityIcon('warn'), ' ', t(`oc.issue.${i.code}`, { value: i.value })))));
    }
    if (cli) notesEl.append(cliBlock(check));
    for (const note of statusNotes()) notesEl.append(note);
    canRun = !cli && check.ok;
    runBar.el.hidden = cli && !running;
    privacyText.textContent = t('oc.privacy', { host: check.host || t('oc.host.placeholder'), path: check.path });
    const shownResult = S.result || S.partial;
    const stateNow = templateState({ running, result: !!shownResult });
    // Compare is disabled until the form is complete; it stays enabled while it leaves (a run starts): Stop takes its focus.
    if (!running) runBar.run.disabled = !check.ok || cli;
    runBar.setRunning(running);
    runBar.setState(stateNow);
    const asked = S.result ? askedOf(S.result) : null;
    runBar.setRerun(stateNow === 'done' && !!asked && asked === [check.host, check.oldIp, check.newIp, check.path, String(check.port)].join('\n'));
    input.setCompact(inputCompact(stateNow));
    input.refresh();
  }

  let timer = null;
  function syncSoon() {
    clearTimeout(timer);
    timer = setTimeout(sync, 150);
  }

  /** What the last run left to say: the quota, a failure (after the old server was asked or not), a stop. */
  function statusNotes() {
    const out = [];
    if (S.status === 'quota') out.push(Alert({ variant: 'warn', compact: true, icon: 'clock', message: t('oc.quota', { when: whenText(S.resetAt) }) }));
    if (S.status === 'failed' && S.error) {
      const quotaAfter = S.partial && QUOTA_CODES.has(S.error.code);
      out.push(quotaAfter ? Alert({ variant: 'warn', compact: true, icon: 'clock', message: t('oc.quotaAfter', { when: whenText(S.error.resetAt) }) })
        : S.partial ? Alert({ variant: 'warn', compact: true, message: t('oc.failedAfter') })
          : ErrorBanner(S.error, { title: t('oc.failed'), compact: true }));
    }
    if (S.status === 'stopped' && S.partial) out.push(Alert({ variant: 'info', compact: true, message: t('oc.stopped') }));
    return out;
  }

  function cliBlock(check) {
    const cmd = buildCompareCommand({ host: check.host, oldIp: check.oldIp, newIp: check.newIp, path: check.path, port: check.port, shell: S.shell });
    const shell = SegmentedControl({
      label: t('oc.cli.shell'), size: 'sm', value: S.shell, className: 'oc-shell',
      options: [{ value: 'posix', label: t('oc.cli.posix') }, { value: 'powershell', label: t('oc.cli.powershell') }],
      onChange: (v) => {
        S.shell = v === 'powershell' ? 'powershell' : 'posix';
        sync();
        notesEl.querySelector('.oc-shell [aria-pressed="true"]')?.focus();
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
      // The page on screen now, which may not be the one that started the run.
      if (shown && shown.connected()) shown.render();
    }
  }

  function probeWhere(probe) {
    return probe ? [probe.city, probe.country].filter(Boolean).join(', ') + (probe.asn ? ` (AS${probe.asn})` : '') : '?';
  }

  function measurementLinks(ids) {
    const links = ids.map((id) => measurementUrl(id)).filter(Boolean);
    return links.length ? h('span', { class: 'oc-measurements' }, ...links.flatMap((href, i) => [i ? ', ' : '',
      h('a', { href, class: 'link', attrs: { target: '_blank', rel: 'noopener noreferrer' } }, t('oc.measurement', { n: i + 1 }))])) : null;
  }

  /**
   * The result region: the result header — while a run goes on "Asking both servers…" over the
   * previous result, whose actions wait — and the table. A control redrawn under the keyboard
   * focus (Remember) keeps it, by its data-action / data-role.
   */
  function renderResult() {
    const doc = globalThis.document;
    const active = doc && doc.activeElement;
    const focusKey = active && resultsEl.contains(active) && active.dataset ? active.dataset.action || active.dataset.role || null : null;
    if (actions) actions.dispose();
    actions = null;
    clear(resultsEl);
    const running = !!S.controller;
    const r = S.result;
    const p = !r ? S.partial : null;
    emptyEl.hidden = !!(r || p || running);
    if (!r && !p && !running) return;
    const head = ResultHeader({ className: 'oc-head' });
    head.setState(running ? 'running' : 'done');
    const out = h('div', { class: ['stack', 'oc-results', { 'oc-partial': !!p }], dataset: { verdict: r ? r.comparison.verdict : p ? 'partial' : 'running' } }, head.el);
    if (running) head.set('title', ResultTitle({ running: true, text: t('oc.running') }));
    if (p) {
      if (!running) head.set('title', ResultTitle({ severity: 'info', text: t('oc.partialTitle') }));
      head.set('meta', [h('span', { class: 'oc-at' }, t('oc.oldAt', { time: formatDateTime(p.at), where: probeWhere(p.side.probe) })),
        measurementLinks(p.side.measurementId ? [p.side.measurementId] : [])]);
      out.append(partialTable(p));
    } else if (r) {
      const c = r.comparison;
      if (!running) head.set('title', ResultTitle({ severity: COMPARE_SEVERITY[c.verdict] || 'info', text: t(`oc.verdict.${c.verdict}`) }));
      head.set('meta', [h('span', { class: 'oc-at' }, t('oc.at', { time: formatDateTime(r.at), where: probeWhere(r.old.probe || r.new.probe), count: r.spent })),
        measurementLinks(r.ids)]);
      // A certificate problem both servers share: no difference, but worth knowing before the move.
      head.set('notes', (c.shared || []).map((note) => h('p', { class: 'result-note result-note-warn oc-shared', dataset: { shared: note } },
        Icon('lock', { size: 14 }), ' ', t(`oc.shared.${note}`))));
      actions = ResultActions({
        exports: [{
          label: t('result.export'), title: t('oc.jsonTitle'), icon: 'download', dataset: { action: 'oc-json' },
          onSelect: () => downloadJson(timestampedName('compare', 'json', r.host), {
            schema: 'domainscope.compare/1', name: r.host, path: r.path, port: r.port, at: r.at, verdict: c.verdict, shared: c.shared || [], fields: c.fields,
            old: sideJson(r.old), new: sideJson(r.new), measurements: r.ids
          })
        }]
      });
      actions.setDisabled(running);
      head.set('actions', actions.el);
      // The new server serves the name: it can go into the workspace's origin map (one click).
      const observed = compareObservations(r);
      if (observed.length && !running) head.set('next', rememberBlock(r, observed));
      out.append(fullTable(r));
    }
    resultsEl.append(out);
    if (focusKey) {
      const again = resultsEl.querySelector(`[data-action="${focusKey}"], [data-role="${focusKey}"]`);
      if (again && !again.disabled) again.focus({ preventScroll: true });
      else head.focusTitle();
    }
  }

  /** The old server's answer alone: a stop or a failure came before the new one was asked. */
  function partialTable(p) {
    const side = p.side;
    const label = t('oc.col.old', { ip: side.ip });
    const table = h('table', { class: 'oc-table oc-table-one', dataset: { role: 'oc-table' } },
      h('thead', null, h('tr', null,
        h('th', { attrs: { scope: 'col' } }, t('oc.col.field')),
        h('th', { attrs: { scope: 'col' } }, label))),
      h('tbody', null, sideFields(side).map((f) => h('tr', { class: 'oc-row', dataset: { field: f.key } },
        h('th', { attrs: { scope: 'row' } }, h('span', { class: 'oc-field-name' }, t(`oc.field.${f.key}`))),
        h('td', { class: 'mono', dataset: { label } }, displayValue(f.key, f.value, side))))));
    return h('div', { class: 'oc-table-wrap' }, table);
  }

  function fullTable(r) {
    const c = r.comparison;
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
    return h('div', { class: 'oc-table-wrap' }, table);
  }

  /** "Remember <address> as the origin of <name>", or why nothing is written: a next step of the result. */
  function rememberBlock(r, observed) {
    const box = h('div', { class: 'stack-sm oc-remember', dataset: { role: 'oc-remember' } });
    if (!rememberOn()) {
      box.append(OriginMapOffNote(ctx));
      return box;
    }
    const target = originTarget({ ip: observed[0].ip, port: observed[0].port });
    box.append(h('div', { class: 'next-steps' }, Button({
      label: t('oc.remember', { target, host: r.host }), icon: 'map-pin', size: 'sm', variant: 'ghost', className: 'next-step',
      dataset: { action: 'oc-remember' },
      onClick: () => {
        const res = recordOrigins(observed, { source: 'compare', at: r.at || new Date() });
        r.remembered = res.off ? null : recordText(res);
        renderResult();
        if (r.remembered) announce(r.remembered);
      }
    })), h('p', { class: 'muted text-sm' }, t('oc.rememberHint')));
    if (r.remembered) box.append(Alert({ variant: 'ok', compact: true, message: r.remembered }));
    return box;
  }

  function render() {
    sync();
    renderResult();
  }

  const api = {
    el,
    render,
    dispose() {
      clearTimeout(timer);
      runBar.dispose();
      if (actions) actions.dispose();
      actions = null;
      if (shown && shown.el === el) shown = null;
    }
  };
  shown = { el, render, connected: () => el.isConnected };
  render();
  return api;
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
