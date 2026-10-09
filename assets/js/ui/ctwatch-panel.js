/**
 * ui/ctwatch-panel.js — Domain portfolio › Certificates (CT): the CT watchlist of the portfolio's
 * domains (lib/ctwatch.js), loaded with the tab on its first use.
 *
 * A tab that is a tool of its own (docs/DESIGN.md §5.5): it has its own run row and privacy note,
 * and its own result header, metric strip and table.
 *
 * - The form: the portfolio's domains (the list of the check on screen, else the box's), the
 *   expiry radar's thresholds (30, 14, 7 days by default) and Check CT — the panel's primary
 *   button, its Stop in the same slot. Nothing is sent before the click. The privacy note under it
 *   says what goes where, and the line next to it Cert Spotter's quota as this page used it.
 * - The result: a header (`.pf-ct-head`, h3: the domains read, when, compared with which check,
 *   the status summary — lib/ctwatch.js ctWatchStatus, each count a filter of the table — and
 *   Export ▾ with the CSV and the calendar), the counts as a read-only metric strip (current
 *   certificates, expiring, new since the last check, unexpected CA, wildcard, precertificate
 *   only; the Show select filters by any of them); one row per unexpired certificate with its
 *   names, CA, validity and flags (a revoked one: when and why; a revoked one or one from an
 *   unexpected CA: the CA's problem-reporting contact, ui/revocation.js, all from the same Cert
 *   Spotter answers); per domain how it was read, a domain that could not be read is
 *   "⚠ n/a" with a Retry of that domain. Exports: CSV of the rows shown and an .ics calendar of
 *   the current certificates' expiries, with reminders at the radar's days.
 * - The baseline: after a check, the ids of the certificates read go into the workspace's
 *   `ctSeen` part with the time of the read, so the next check marks what was logged since.
 * - Known certificates (lib/waivers.js, kind 'cert'): a row flagged new or from an unexpected CA
 *   offers "Known certificate…" (ui/waivers.js: a reason, an owner and an end date): its public
 *   key (Cert Spotter's SHA-256 of it, else the certificate's) is then expected, and its rows are
 *   "Known" — never new nor unexpected — until that day; their expiry and revocation still count.
 *   The waivers are matched when the rows are drawn: the day after, a row is flagged again and says
 *   its acceptance is over.
 *
 * The last check belongs to the module, so a language switch (a re-mount) shows it again; leaving
 * the view stops a check that runs (what was read is kept), and another workspace or "Delete all
 * local data" drops it. Every string goes through h() / text nodes.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, DataTable, Disclosure, ExternalLink, Icon, ProgressBar, RelativeTime, announce, select, textInput, toast } from './components.js';
import { EmptyState, MetricStrip, PrivacyNote, ResultActions, ResultHeader, ResultTitle, StatusSummary } from './template.js';
import { registerStrings, formatDate, formatDateTime, formatNumber, formatRelative } from '../i18n.js';
import {
  CT_WATCH_DEFAULT_DAYS, CT_WATCH_FILTERS, CT_WATCH_FLAGS, CT_WATCH_NOTES, CT_WATCH_MAX_DOMAINS, CT_WATCH_MAX_DAYS, CT_WATCH_MAX_THRESHOLDS,
  CT_EXPORT_COLUMNS, analyzeCt, ctWatchStatus, exportCtRow, expiryEntries, matchesCtFilter, parseRadarDays, readDomainCt, readPortfolioCt, readSeen, seenText,
  spotterBudget, updateSeen
} from '../lib/ctwatch.js';
import { createLimiter, mergeSignals, onceAsync } from '../lib/util.js';
import { buildCalendar } from '../lib/ics.js';
import { toCsv } from '../lib/export.js';
import { sourceStatus } from '../lib/sourcestatus.js';
import { NaMark, RetryButton, setRetryBusy } from './source-status.js';
import { downloadText, timestampedName } from './download.js';
import { registerRunning } from './jobs.js';
import { ProblemReporting, RevokedLine, generatedKeys as revocationKeys } from './revocation.js';
import { state as stateSingleton } from '../state.js';
import { WAIVERS_I18N, readWaivers } from '../lib/waivers.js';
import { storageErrorText } from './workspace-ui.js';

/** ui/waivers.js: the "Known certificate…" dialog, on its first click. */
const loadWaivers = onceAsync(() => import('./waivers.js'));

registerStrings('en', WAIVERS_I18N.en);
registerStrings('tr', WAIVERS_I18N.tr);

/** The tiles above the table, each a filter of lib/ctwatch.js CT_WATCH_FILTERS. */
export const CT_TILES = Object.freeze(['current', 'expiring', 'new', 'unexpected', 'wildcard', 'precert']);
/** The PRODID of the calendar this tab exports. */
export const CT_ICS_PRODID = '-//DomainScope//CT watch//EN';

registerStrings('en', {
  'ctw.title': 'Certificates in Certificate Transparency',
  'ctw.intro': 'Every certificate a public CA issues is logged in Certificate Transparency (CT). For each domain of the portfolio and every name under it, this tab lists the unexpired certificates logged there: the newest of each name set, those that expire soon, those logged since the last check, those from a CA this workspace does not expect, wildcards and issuances logged only as a precertificate.',
  'ctw.publicOnly': 'CT shows publicly trusted certificates only: a certificate from a private or internal CA, a self-signed one, or one a CA never logged is not here. Check those on the servers (SSL Targets).',
  'ctw.sends': 'Nothing is sent until you press Check CT. Then each domain goes to Cert Spotter (api.certspotter.com), one request at a time while its hourly quota lasts, and to crt.sh after that; both are public CT search services and learn only the domain.',
  'ctw.domains': { one: '{count} domain from the portfolio list', other: '{count} domains from the portfolio list' },
  'ctw.capped': { one: 'Only the first {max} domains are checked: {count} more is left out.', other: 'Only the first {max} domains are checked: {count} more are left out.' },
  'ctw.noDomains': 'Enter domains in the box above: this tab reads the certificates of the portfolio’s domains.',
  'ctw.days': 'Expiry radar (days left)',
  'ctw.daysHint': 'Up to {max} thresholds such as 30, 14, 7. The calendar reminds you on the same days.',
  'ctw.daysBad': 'Enter whole days from 1 to {days}, separated by commas (for example 30, 14, 7).',
  'ctw.run': 'Check CT',
  'ctw.running': 'Certificate Transparency check of the portfolio',
  'ctw.progress': { one: 'Reading CT for {count} domain', other: 'Reading CT for {count} domains' },
  'ctw.progressCount': '{done} of {total} domains',
  'ctw.quota': 'Cert Spotter: {used} of {limit} subdomain searches of the last hour sent from this page. A domain takes two at least, and the quota counts every request from your IP address.',
  'ctw.quotaOut': 'Cert Spotter’s hourly quota is used up until about {time}: domains go to crt.sh until then.',
  'ctw.emptyBody': 'New issuance, an expiry radar and unexpected CAs for every domain of the list. Nothing has been sent yet.',
  'ctw.resultsTitle': { one: 'Certificates of {count} domain', other: 'Certificates of {count} domains' },
  'ctw.checkedAt': 'Checked {time}',
  'ctw.stoppedAt': 'Stopped {time}: the domains read until then are shown',
  'ctw.comparedWith': 'Compared with the check of {time}',
  'ctw.firstAll': 'First check of these domains in this workspace: nothing is marked new. The next check marks what was logged after this one.',
  'ctw.firstSome': { one: '{count} domain is checked for the first time in this workspace ({list}): none of its certificates is marked new.', other: '{count} domains are checked for the first time in this workspace ({list}): none of their certificates is marked new.' },
  'ctw.noExpected': 'This workspace has no expected CAs, so no issuer is marked unexpected. Add them under Workspaces › Expected CAs.',
  'ctw.done': { one: 'CT check finished: {count} certificate', other: 'CT check finished: {count} certificates' },
  'ctw.stopped': 'CT check stopped: the domains read until then are shown',
  'ctw.failedTitle': { one: '{count} domain could not be read', other: '{count} domains could not be read' },
  'ctw.sourcesTitle': 'How each domain was read',
  'ctw.src.certspotter': 'Cert Spotter',
  'ctw.src.crtsh': 'crt.sh',
  'ctw.pending': 'waiting…',
  'ctw.read.count': { zero: 'no unexpired certificate', one: '{count} certificate', other: '{count} certificates' },
  'ctw.note.spotter-quota': 'crt.sh answered: Cert Spotter’s quota was used up',
  'ctw.note.spotter-failed': 'crt.sh answered: Cert Spotter failed',
  'ctw.note.crtsh-partial': 'crt.sh answered with its lighter search only: names may be missing',
  'ctw.note.truncated': 'more than 500 certificates are logged: the list stops there',
  'ctw.note.first': 'first check: nothing compared',
  'ctw.crtshPrecert': 'crt.sh does not say which entries are precertificates: “Precertificate only” comes from Cert Spotter’s answers.',
  'ctw.retried': '{domain}: read again',
  'ctw.tile.current': 'Current certificates',
  'ctw.tile.expiring': 'Expire ≤ {days} days',
  'ctw.tile.new': 'New since the last check',
  'ctw.tile.unexpected': 'Unexpected CA',
  'ctw.tile.wildcard': 'Wildcard',
  'ctw.tile.precert': 'Precertificate only',
  'ctw.tile.label': 'The certificates in numbers',
  'ctw.status.expiring': { one: '{count} expires within {days} days', other: '{count} expire within {days} days' },
  'ctw.status.unexpected': { one: '{count} from an unexpected CA', other: '{count} from unexpected CAs' },
  'ctw.status.precert': { one: '{count} precertificate only', other: '{count} precertificates only' },
  'ctw.status.new': { one: '{count} new since the last check', other: '{count} new since the last check' },
  'ctw.status.current': { one: '{count} current certificate', other: '{count} current certificates' },
  'ctw.filter.label': 'Show',
  'ctw.filter.current': 'Newest of each name set ({count})',
  'ctw.filter.all': 'Every unexpired certificate ({count})',
  'ctw.filter.new': 'New since the last check ({count})',
  'ctw.filter.expiring': 'Expire within {days} days ({count})',
  'ctw.filter.unexpected': 'Unexpected CA ({count})',
  'ctw.filter.wildcard': 'Wildcard ({count})',
  'ctw.filter.precert': 'Precertificate only ({count})',
  'ctw.search': 'Filter names, CAs…',
  'ctw.caption': 'Certificates in CT',
  'ctw.col.domain': 'Domain',
  'ctw.col.names': 'Names',
  'ctw.col.ca': 'CA',
  'ctw.col.from': 'Valid from',
  'ctw.col.expires': 'Expires',
  'ctw.col.flags': 'Flags',
  'ctw.flag.new': 'New',
  'ctw.flag.unexpected': 'Unexpected CA',
  'ctw.flag.precert': 'Precertificate only',
  'ctw.flag.wildcard': 'Wildcard',
  'ctw.flag.revoked': 'Revoked',
  'ctw.flag.superseded': 'Superseded',
  'ctw.flag.known': 'Known',
  'ctw.flagTitle.new': 'Not logged at the last check of this domain.',
  'ctw.flagTitle.unexpected': 'Not one of this workspace’s expected CAs. Change them under Workspaces › Expected CAs.',
  'ctw.flagTitle.precert': 'Only the precertificate is logged: the CA issued this certificate, but its final form was never logged. Names, dates and serial are the same; the fingerprint differs.',
  'ctw.flagTitle.wildcard': 'Holds a wildcard name: valid for every name one label below it.',
  'ctw.flagTitle.revoked': 'Revoked by its CA (Cert Spotter).',
  'ctw.flagTitle.superseded': 'Every name of it is on a certificate that expires later.',
  'ctw.flagTitle.known': 'A known certificate: its key was accepted as expected (Workspaces › Accepted risks), so it is never flagged new or from an unexpected CA. Its expiry and revocation are still watched.',
  'ctw.daysLeft': { zero: 'today', one: '{count} day left', other: '{count} days left' },
  'ctw.moreNames': { one: '+{count} name', other: '+{count} names' },
  'ctw.openCrtsh': 'crt.sh',
  'ctw.openCrtshTitle': 'This certificate on crt.sh',
  'ctw.export.csv': 'CSV',
  'ctw.export.ics': 'Expiry calendar (.ics)',
  'ctw.export.title': 'The rows shown',
  'ctw.export.icsTitle': 'One event per name set on the day its newest certificate expires, with reminders on the radar’s days',
  'ctw.exported': 'Saved {file}',
  'ctw.ics.none': 'No current certificate among the rows shown.',
  'ctw.ics.name': 'DomainScope: certificate expiries',
  'ctw.ics.summary': { zero: 'Certificate expires: {name}', one: 'Certificate expires: {name} (+{count} name)', other: 'Certificate expires: {name} (+{count} names)' },
  'ctw.ics.description': 'CA: {ca}\nNames: {names}\nRenew it before then, or check that its automatic renewal runs.',
  'ctw.ics.alarm': 'The certificate of {name} expires on {date}'
});

registerStrings('tr', {
  'ctw.title': 'Certificate Transparency’deki sertifikalar',
  'ctw.intro': 'Herkesçe güvenilen bir CA’nın verdiği her sertifika Certificate Transparency’ye (CT) kaydedilir. Bu sekme, portföydeki her alan adı ve altındaki her ad için orada kayıtlı, süresi dolmamış sertifikaları listeler: her ad kümesinin en yenisi, süresi yakında dolanlar, son kontrolden beri kaydedilenler, bu çalışma alanının beklemediği bir CA’dan gelenler, Wildcard’lar ve yalnızca ön sertifikası (precertificate) kaydedilmiş olanlar.',
  'ctw.publicOnly': 'CT yalnızca herkesçe güvenilen sertifikaları gösterir: özel ya da kurum içi bir CA’nın sertifikası, kendinden imzalı bir sertifika ya da CA’nın hiç kaydetmediği bir sertifika burada yoktur. Bunları sunucuların üzerinde kontrol edin (SSL Hedefleri).',
  'ctw.sends': '“CT’yi kontrol et”e basana kadar hiçbir şey gönderilmez. Sonra her alan adı, saatlik kotası yettiği sürece tek tek Cert Spotter’a (api.certspotter.com), ardından crt.sh’e gider; ikisi de herkese açık CT arama hizmetleridir ve yalnızca alan adını öğrenir.',
  'ctw.domains': { other: 'Portföy listesinden {count} alan adı' },
  'ctw.capped': { other: 'Yalnızca ilk {max} alan adı kontrol edilir: {count} alan adı dışarıda kalır.' },
  'ctw.noDomains': 'Yukarıdaki kutuya alan adlarını girin: bu sekme portföydeki alan adlarının sertifikalarını okur.',
  'ctw.days': 'Süre radarı (kalan gün)',
  'ctw.daysHint': 'En çok {max} eşik, örneğin 30, 14, 7. Takvim de aynı günlerde hatırlatır.',
  'ctw.daysBad': '1 ile {days} arasında tam gün sayıları girin, aralarına virgül koyun (örneğin 30, 14, 7).',
  'ctw.run': 'CT’yi kontrol et',
  'ctw.running': 'Portföyün Certificate Transparency kontrolü',
  'ctw.progress': { other: '{count} alan adı için CT okunuyor' },
  'ctw.progressCount': '{done} / {total} alan adı',
  'ctw.quota': 'Cert Spotter: son bir saatte bu sayfadan {limit} alt alan adı aramasının {used} tanesi gönderildi. Bir alan adı en az iki tane kullanır ve kota IP adresinizden giden her isteği sayar.',
  'ctw.quotaOut': 'Cert Spotter’ın saatlik kotası yaklaşık {time} saatine kadar doldu: o zamana kadar alan adları crt.sh’e gider.',
  'ctw.emptyBody': 'Listedeki her alan adı için yeni verilen sertifikalar, bir süre radarı ve beklenmeyen CA’lar. Henüz hiçbir şey gönderilmedi.',
  'ctw.resultsTitle': { other: '{count} alan adının sertifikaları' },
  'ctw.checkedAt': 'Kontrol: {time}',
  'ctw.stoppedAt': 'Durduruldu ({time}): o zamana kadar okunan alan adları gösteriliyor',
  'ctw.comparedWith': 'Karşılaştırılan kontrol: {time}',
  'ctw.firstAll': 'Bu alan adlarının bu çalışma alanındaki ilk kontrolü: hiçbir sertifika yeni olarak işaretlenmez. Sonraki kontrol, bundan sonra kaydedilenleri işaretler.',
  'ctw.firstSome': { other: '{count} alan adı bu çalışma alanında ilk kez kontrol ediliyor ({list}): bunların hiçbir sertifikası yeni olarak işaretlenmez.' },
  'ctw.noExpected': 'Bu çalışma alanında beklenen CA yok, bu yüzden hiçbir sertifika veren beklenmeyen olarak işaretlenmez. Çalışma alanları › Beklenen CA’lar bölümünden ekleyin.',
  'ctw.done': { other: 'CT kontrolü tamamlandı: {count} sertifika' },
  'ctw.stopped': 'CT kontrolü durduruldu: o zamana kadar okunan alan adları gösteriliyor',
  'ctw.failedTitle': { other: '{count} alan adı okunamadı' },
  'ctw.sourcesTitle': 'Her alan adı nasıl okundu',
  'ctw.src.certspotter': 'Cert Spotter',
  'ctw.src.crtsh': 'crt.sh',
  'ctw.pending': 'bekliyor…',
  'ctw.read.count': { zero: 'süresi dolmamış sertifika yok', other: '{count} sertifika' },
  'ctw.note.spotter-quota': 'crt.sh yanıtladı: Cert Spotter’ın kotası dolmuştu',
  'ctw.note.spotter-failed': 'crt.sh yanıtladı: Cert Spotter’a ulaşılamadı',
  'ctw.note.crtsh-partial': 'crt.sh yalnızca hafif aramasıyla yanıtladı: bazı adlar eksik olabilir',
  'ctw.note.truncated': '500’den fazla sertifika kayıtlı: liste orada kesilir',
  'ctw.note.first': 'ilk kontrol: karşılaştırılacak bir şey yok',
  'ctw.crtshPrecert': 'crt.sh hangi kaydın ön sertifika olduğunu söylemez: “Yalnızca ön sertifika” işareti Cert Spotter’ın yanıtlarından gelir.',
  'ctw.retried': '{domain}: yeniden okundu',
  'ctw.tile.current': 'Geçerli sertifikalar',
  'ctw.tile.expiring': 'Süresi ≤ {days} günde dolan',
  'ctw.tile.new': 'Son kontrolden beri yeni',
  'ctw.tile.unexpected': 'Beklenmeyen CA',
  'ctw.tile.wildcard': 'Wildcard',
  'ctw.tile.precert': 'Yalnızca ön sertifika',
  'ctw.tile.label': 'Sayılarla sertifikalar',
  'ctw.status.expiring': '{count} sertifikanın süresi {days} gün içinde doluyor',
  'ctw.status.unexpected': '{count} sertifika beklenmeyen bir CA’dan',
  'ctw.status.precert': '{count} sertifika yalnızca ön sertifika olarak kayıtlı',
  'ctw.status.new': '{count} sertifika son kontrolden beri yeni',
  'ctw.status.current': '{count} geçerli sertifika',
  'ctw.filter.label': 'Göster',
  'ctw.filter.current': 'Her ad kümesinin en yenisi ({count})',
  'ctw.filter.all': 'Süresi dolmamış her sertifika ({count})',
  'ctw.filter.new': 'Son kontrolden beri yeni ({count})',
  'ctw.filter.expiring': 'Süresi {days} gün içinde dolan ({count})',
  'ctw.filter.unexpected': 'Beklenmeyen CA ({count})',
  'ctw.filter.wildcard': 'Wildcard ({count})',
  'ctw.filter.precert': 'Yalnızca ön sertifika ({count})',
  'ctw.search': 'Adları, CA’ları filtrele…',
  'ctw.caption': 'CT’deki sertifikalar',
  'ctw.col.domain': 'Alan adı',
  'ctw.col.names': 'Adlar',
  'ctw.col.ca': 'CA',
  'ctw.col.from': 'Geçerlilik başlangıcı',
  'ctw.col.expires': 'Bitiş',
  'ctw.col.flags': 'İşaretler',
  'ctw.flag.new': 'Yeni',
  'ctw.flag.unexpected': 'Beklenmeyen CA',
  'ctw.flag.precert': 'Yalnızca ön sertifika',
  'ctw.flag.wildcard': 'Wildcard',
  'ctw.flag.revoked': 'İptal edilmiş',
  'ctw.flag.superseded': 'Yenisiyle değiştirilmiş',
  'ctw.flag.known': 'Bilinen',
  'ctw.flagTitle.new': 'Bu alan adının son kontrolünde kayıtlı değildi.',
  'ctw.flagTitle.unexpected': 'Bu çalışma alanının beklenen CA’larından biri değil. Çalışma alanları › Beklenen CA’lar bölümünden değiştirin.',
  'ctw.flagTitle.precert': 'Yalnızca ön sertifika kayıtlı: CA bu sertifikayı verdi, ancak son hâli hiç kaydedilmedi. Adlar, tarihler ve seri numarası aynıdır; parmak izi farklıdır.',
  'ctw.flagTitle.wildcard': 'Wildcard bir ad taşır: bir etiket altındaki her ad için geçerlidir.',
  'ctw.flagTitle.revoked': 'CA’sı tarafından iptal edilmiş (Cert Spotter).',
  'ctw.flagTitle.superseded': 'Her adı, süresi daha geç dolan bir sertifikada da var.',
  'ctw.flagTitle.known': 'Bilinen bir sertifika: anahtarı beklenen olarak kabul edildi (Çalışma alanları › Kabul edilen riskler), bu yüzden hiçbir zaman yeni ya da beklenmeyen bir CA’dan diye işaretlenmez. Bitiş tarihi ve iptal durumu izlenmeye devam eder.',
  'ctw.daysLeft': { zero: 'bugün', other: '{count} gün kaldı' },
  'ctw.moreNames': { other: '+{count} ad' },
  'ctw.openCrtsh': 'crt.sh',
  'ctw.openCrtshTitle': 'Bu sertifika crt.sh’te',
  'ctw.export.csv': 'CSV',
  'ctw.export.ics': 'Bitiş takvimi (.ics)',
  'ctw.export.title': 'Gösterilen satırlar',
  'ctw.export.icsTitle': 'Her ad kümesi için en yeni sertifikasının süresinin dolduğu günde bir etkinlik, radarın günlerinde hatırlatmalarla',
  'ctw.exported': '{file} kaydedildi',
  'ctw.ics.none': 'Gösterilen satırlar arasında geçerli sertifika yok.',
  'ctw.ics.name': 'DomainScope: sertifika bitişleri',
  'ctw.ics.summary': { zero: 'Sertifikanın süresi doluyor: {name}', other: 'Sertifikanın süresi doluyor: {name} (+{count} ad)' },
  'ctw.ics.description': 'CA: {ca}\nAdlar: {names}\nO tarihten önce yenileyin ya da otomatik yenilemenin çalıştığını kontrol edin.',
  'ctw.ics.alarm': '{name} sertifikasının süresi {date} tarihinde doluyor'
});

/**
 * Every i18n key this panel builds from a library code (the i18n coverage test reads them).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...CT_WATCH_FLAGS.flatMap((f) => [`ctw.flag.${f}`, `ctw.flagTitle.${f}`]),
    ...CT_WATCH_FILTERS.map((f) => `ctw.filter.${f}`),
    ...CT_WATCH_NOTES.map((n) => `ctw.note.${n}`),
    ...CT_TILES.map((k) => `ctw.tile.${k}`),
    'ctw.src.certspotter', 'ctw.src.crtsh',
    ...revocationKeys()
  ];
}

/* ------------------------------------------------------------------------ */
/* The last check (module state: it outlives a re-mount)                   */
/* ------------------------------------------------------------------------ */

const blank = () => ({ reads: new Map(), order: [], at: null, startedAt: null, seenBefore: null, stopped: false, run: null, retrying: new Set() });
/** The last check, the field and the filter. */
const S = { ...blank(), days: CT_WATCH_DEFAULT_DAYS.join(', '), filter: 'current' };
/** Cert Spotter's requests of this panel, one at a time (a check and a Retry share it). */
const spotterQueue = createLimiter(1);
/** The panels on screen (one per mount), told when the module state changes. */
const panels = new Set();
const notify = (type = 'change') => {
  for (const fn of [...panels]) fn(type);
};

registerRunning('ctw.running', () => !!S.run);

// Another workspace (another customer's domains) or "Delete all local data": the check goes.
stateSingleton.subscribe(({ key }) => {
  if (key !== 'cleared' && key !== 'workspace') return;
  if (S.run) S.run.controller.abort();
  Object.assign(S, blank(), { filter: 'current' });
  notify('reset');
});

/** The reads that landed go into the workspace's baseline, added to what it held. */
function saveSeen(reads) {
  const landed = reads.filter((r) => r && r.state !== 'failed');
  if (!landed.length) return;
  const next = updateSeen(readSeen(stateSingleton.workspaceData('ctSeen')), landed, { now: Date.now() });
  Promise.resolve(stateSingleton.setWorkspaceData('ctSeen', seenText(next))).catch(() => {});
}

/** Run a check of `domains` (module state); resolves when it ends. */
async function runCheck(domains) {
  const controller = new AbortController();
  const run = { controller };
  Object.assign(S, blank(), { order: domains, startedAt: new Date(), seenBefore: readSeen(stateSingleton.workspaceData('ctSeen')), run });
  notify('start');
  try {
    await readPortfolioCt(domains, {
      signal: controller.signal,
      spotterQueue,
      onRead: (r) => {
        if (S.run !== run) return;
        S.reads.set(r.domain, r);
        notify();
      }
    });
  } catch (err) {
    if (!err || err.name !== 'AbortError') throw err;
  } finally {
    if (S.run === run) {
      S.run = null;
      S.at = new Date();
      S.stopped = controller.signal.aborted;
      saveSeen([...S.reads.values()]);
      notify(S.stopped ? 'stopped' : 'done');
    }
  }
}

/* ------------------------------------------------------------------------ */
/* The panel                                                                */
/* ------------------------------------------------------------------------ */

/**
 * Mount the CT tab's panel.
 * @param {HTMLElement} host
 * @param {{ ctx: import('../app.js').ViewContext, domains: () => string[] }} opts `domains`: the
 *   portfolio's domains now (the check on screen, else the box)
 * @returns {{ destroy(): void, refresh(): void }}
 */
export function mountCtWatch(host, { ctx, domains }) {
  const { t } = ctx;
  const listDomains = () => (domains() || []).slice();

  /* --- the form ------------------------------------------------------------------------ */
  const domainsLine = h('p', { class: 'text-sm pf-ct-domains', attrs: { 'aria-live': 'polite' } });
  const daysField = textInput({
    label: t('ctw.days'),
    value: S.days,
    hint: t('ctw.daysHint', { max: CT_WATCH_MAX_THRESHOLDS }),
    inputmode: 'numeric',
    className: 'pf-ct-days',
    attrs: { 'data-role': 'ct-days' },
    onInput: (v) => {
      S.days = v;
      daysField.setError(null);
    }
  });
  // The panel's own run (DESIGN §5.1, region 3: Check CT is the primary button inside the tab; Stop
  // takes its slot while a check runs, and the keyboard focus goes with it).
  const runBtn = Button({ label: t('ctw.run'), icon: 'play', variant: 'primary', className: 'run-bar-run', dataset: { action: 'ct-run' }, onClick: () => start() });
  const stopBtn = Button({
    label: t('common.stop'), icon: 'stop', variant: 'secondary', className: 'run-bar-stop', dataset: { action: 'ct-stop' },
    onClick: () => { if (S.run) S.run.controller.abort(); }
  });
  const quotaLine = h('p', { class: 'pf-ct-quota', dataset: { role: 'ct-quota' }, attrs: { 'aria-live': 'polite' } });
  const formCard = h('div', { class: 'card pf-ct-form' },
    h('div', { class: 'card-body stack' },
      h('h2', { class: 'pf-ct-title' }, t('ctw.title')),
      h('p', { class: 'text-sm' }, t('ctw.intro')),
      Alert({ variant: 'info', compact: true, message: t('ctw.publicOnly') }),
      domainsLine,
      h('div', { class: 'pf-ct-fields' }, daysField.el, h('div', { class: 'run-bar pf-ct-run' }, runBtn, stopBtn)),
      h('div', { class: 'pf-ct-foot' }, PrivacyNote({ text: t('ctw.sends'), className: 'pf-sends' }), quotaLine)));

  /* --- the result: its header (region 4), notes, metric strip (region 6, read-only), table ------ */
  const progress = ProgressBar({ format: (v, max) => t('ctw.progressCount', { done: formatNumber(v), total: formatNumber(max) }) });
  const emptyEl = h('div', { class: 'pf-ct-empty' }, EmptyState({
    icon: 'certificate',
    message: t('ctw.emptyBody'),
    checks: CT_TILES.map((k) => t(`ctw.tile.${k}`, { days: (parseRadarDays(S.days) || CT_WATCH_DEFAULT_DAYS)[0] }))
  }));
  const notesEl = h('div', { class: 'stack pf-ct-notes' });
  // A heading under the panel's own (h2): the note over a kept check is the portfolio's, never here.
  const head = ResultHeader({ className: 'pf-ct-head pf-head', level: 3, kept: false });
  const status = StatusSummary({ items: [] });
  head.set('status', status.el);
  /** Export ▾: the CSV and the calendar of the rows shown (no Copy summary: the portfolio's has the check). */
  const actions = ResultActions({
    exports: [
      { label: t('ctw.export.csv'), title: t('ctw.export.title'), dataset: { action: 'ct-csv' }, onSelect: () => exportCsv() },
      { label: t('ctw.export.ics'), icon: 'calendar', title: t('ctw.export.icsTitle'), dataset: { action: 'ct-ics' }, onSelect: () => exportCalendar() }
    ]
  });
  head.set('actions', actions.el);
  const tiles = MetricStrip({ className: 'pf-ct-tiles', label: t('ctw.tile.label') });
  const tilesEl = tiles.el;
  const filterSelect = select({ label: t('ctw.filter.label'), options: [], value: S.filter, size: 'sm', className: 'pf-filter', onChange: (v) => setFilter(v) });
  filterSelect.input.dataset.role = 'ct-filter';

  let analysis = { rows: [], counts: {}, first: [] };
  let days = parseRadarDays(S.days) || [...CT_WATCH_DEFAULT_DAYS];
  const radar = () => days[0];

  const mono = (text) => h('span', { class: 'mono pf-break' }, text);
  const cellOf = (...children) => h('span', { class: 'pf-cell' }, children.filter(Boolean));
  const flagBadge = (f) => {
    const variant = { new: 'info', unexpected: 'warn', precert: 'warn', wildcard: 'neutral', revoked: 'error', superseded: 'neutral', known: 'ok' }[f];
    const el = Badge(t(`ctw.flag.${f}`), { variant, icon: f === 'known' ? 'shield' : null, title: t(`ctw.flagTitle.${f}`) });
    el.dataset.flag = f;
    return el;
  };
  /** The key a known-certificate waiver names: the public key's SHA-256, else the certificate's. */
  const keyOf = (r) => r.spkiSha256 || r.sha256 || null;
  /** Where the focus goes once the table is drawn again: the row a click marked known. */
  let knownFocus = null;
  /**
   * A known certificate's line (its waiver), or, on a row flagged new or unexpected that has a key,
   * "Known certificate…" — after the line that says its acceptance is over, when it was known.
   */
  const knownPart = (r) => {
    if (r.known) {
      const w = r.known;
      return h('span', { class: 'text-xs pf-known', dataset: { role: 'ct-known-line', cert: r.id }, attrs: { tabindex: '-1' } },
        t(w.owner ? 'wvr.lineOwner' : 'wvr.line', { date: w.expires, owner: w.owner, reason: w.reason }));
    }
    if (!(r.isNew || r.unexpected)) return null;
    const ended = r.knownExpired
      ? h('span', { class: 'text-xs pf-known-expired', dataset: { role: 'ct-known-expired', cert: r.id } }, Icon('clock', { size: 12 }), ' ', t('wvr.knownExpiredLine', { date: r.knownExpired.expires }))
      : null;
    const button = keyOf(r) ? Button({
      label: t('wvr.known'), icon: 'shield', size: 'sm', variant: 'ghost', title: t('wvr.knownTitle'), className: 'pf-known-btn',
      dataset: { action: 'ct-known', cert: r.id, domain: r.domain }, onClick: () => markKnown(r)
    }) : null;
    return ended || button ? [ended, button] : null;
  };
  const expiryBadge = (r) => {
    if (!r.current) return null;
    const variant = r.band === null ? 'ok' : r.band === days.length - 1 ? 'error' : 'warn';
    return Badge(t('ctw.daysLeft', { count: Math.max(0, r.daysLeft) }), { variant, icon: 'clock' });
  };
  const namesCell = (r) => {
    const shown = r.names.slice(0, 3);
    return cellOf(...shown.map((n) => mono(n)), r.names.length > 3 ? h('span', { class: 'muted text-xs' }, t('ctw.moreNames', { count: r.names.length - 3 })) : null);
  };
  // A revoked certificate: when and why (Cert Spotter); revoked or from an unexpected CA: the CA's
  // problem-reporting contact, as the CA wrote it (text, never markup).
  const flagsCell = (r) => cellOf(
    ...r.flags.map(flagBadge),
    r.revoked ? RevokedLine(r.revocation, { className: 'pf-ct-revoked text-xs' }) : null,
    (r.revoked || r.unexpected) && r.problemReporting ? ProblemReporting(r.problemReporting, { className: 'pf-ct-report' }) : null,
    knownPart(r)
  );
  const caCell = (r) => cellOf(
    h('span', null, r.ca),
    r.intermediate && r.intermediate !== r.ca ? h('span', { class: 'muted text-xs' }, r.intermediate) : null,
    r.url ? ExternalLink(r.url, t('ctw.openCrtsh'), { title: t('ctw.openCrtshTitle'), className: 'text-xs' }) : null
  );
  const table = DataTable({
    columns: [
      { key: 'domain', label: t('ctw.col.domain'), sortable: true, sortValue: (r) => r.domain, searchable: false, render: (r) => mono(r.domain), className: 'pf-col-domain' },
      { key: 'names', label: t('ctw.col.names'), sortable: true, sortValue: (r) => r.names[0], searchValue: (r) => `${r.names.join(' ')} ${r.ca} ${r.intermediate || ''}`, render: namesCell, className: 'pf-ct-names' },
      { key: 'ca', label: t('ctw.col.ca'), sortable: true, sortValue: (r) => r.ca, searchable: false, render: caCell },
      { key: 'from', label: t('ctw.col.from'), sortable: true, sortValue: (r) => r.notBefore.getTime(), searchable: false, render: (r) => h('span', { class: 'pf-nowrap', title: formatDateTime(r.notBefore) }, formatDate(r.notBefore)) },
      { key: 'expires', label: t('ctw.col.expires'), sortable: true, sortValue: (r) => r.notAfter.getTime(), searchable: false, render: (r) => cellOf(h('span', { class: 'pf-nowrap', title: formatDateTime(r.notAfter) }, formatDate(r.notAfter)), expiryBadge(r)) },
      { key: 'flags', label: t('ctw.col.flags'), sortable: false, searchable: false, render: flagsCell, className: 'pf-flags' }
    ],
    rowKey: (r) => `${r.domain}|${r.id}`,
    search: { placeholder: t('ctw.search') },
    sort: { key: 'expires', dir: 'asc' },
    toolbar: filterSelect.el,
    filter: (r) => matchesCtFilter(r, S.filter, { radar: radar() }),
    export: false,
    cellLabels: true,
    pageSize: 100,
    maxHeight: null,
    caption: t('ctw.caption'),
    className: 'pf-table pf-ct-table',
    rowClass: (r) => (r.current && r.band !== null ? `pf-ct-band-${r.band === days.length - 1 ? 'last' : 'near'}` : null)
  });
  table.el.dataset.role = 'ct-table';

  const results = h('div', { class: 'pf-ct-results' }, head.el, notesEl, tilesEl, table.el);
  const root = h('div', { class: 'pf-ct', dataset: { shortcutScope: 'ct' } }, formCard, emptyEl, results);
  host.append(root);

  /* --- rendering ---------------------------------------------------------------------- */
  function renderForm() {
    const list = listDomains();
    clear(domainsLine);
    if (!list.length) {
      domainsLine.append(h('span', { class: 'muted', dataset: { note: 'no-domains' } }, t('ctw.noDomains')));
    } else {
      domainsLine.append(h('span', { class: 'pf-count' }, t('ctw.domains', { count: Math.min(list.length, CT_WATCH_MAX_DOMAINS) })));
      if (list.length > CT_WATCH_MAX_DOMAINS) domainsLine.append(' · ', h('span', { class: 'pf-invalid', dataset: { issue: 'capped' } }, t('ctw.capped', { max: CT_WATCH_MAX_DOMAINS, count: list.length - CT_WATCH_MAX_DOMAINS })));
    }
    const on = !!S.run;
    // The keyboard focus follows the button it was on (Check CT ⇄ Stop), never falling to <body>.
    const from = document.activeElement === (on ? runBtn : stopBtn);
    runBtn.hidden = on;
    stopBtn.hidden = !on;
    if (from) (on ? stopBtn : runBtn).focus();
    daysField.input.readOnly = on;
    renderQuota();
  }

  function renderQuota() {
    clear(quotaLine);
    const reset = spotterBudget.resetAt();
    quotaLine.append(t('ctw.quota', { used: spotterBudget.used(), limit: spotterBudget.limit }));
    if (spotterBudget.left() < 2 && reset) quotaLine.append(' ', h('strong', { dataset: { quota: 'out' } }, t('ctw.quotaOut', { time: formatDateTime(reset) })));
  }

  /** The check's header: what was read and when, compared with which check; the progress while it runs. */
  function renderHead() {
    if (!S.startedAt) return;
    const runningNow = !!S.run;
    head.el.dataset.status = runningNow ? 'running' : S.stopped ? 'stopped' : 'done';
    head.setState(runningNow ? 'running' : 'done');
    head.set('title', ResultTitle({ running: runningNow, text: t(runningNow ? 'ctw.progress' : 'ctw.resultsTitle', { count: S.order.length }) }));
    const before = S.seenBefore ? S.order.map((d) => S.seenBefore.domains[d]).filter(Boolean).map((e) => e.at).sort().at(-1) : null;
    const compared = before ? RelativeTime(new Date(before), { className: 'pf-ct-compared', text: t('ctw.comparedWith', { time: formatRelative(new Date(before)) }) }) : null;
    if (compared) compared.dataset.note = 'compared';
    head.set('meta', [
      !runningNow && S.at ? RelativeTime(S.at, { text: S.stopped ? t('ctw.stoppedAt', { time: formatRelative(S.at) }) : t('ctw.checkedAt', { time: formatRelative(S.at) }) }) : null,
      compared
    ]);
    head.set('progress', runningNow ? progress.el : null);
    actions.setExportsDisabled(runningNow || !analysis.rows.length);
  }

  function readLine(domain) {
    const r = S.reads.get(domain);
    const busy = S.retrying.has(domain);
    const item = h('li', { class: 'pf-ct-read', dataset: { domain, state: r ? r.state : 'pending' } }, mono(domain), ' — ');
    if (!r) {
      item.append(h('span', { class: 'muted' }, t('ctw.pending')));
      return item;
    }
    if (r.state === 'failed') {
      const btn = RetryButton({ sources: [...new Set(r.failures.map((f) => f.source))], target: domain, dataset: { domain }, onClick: (e) => retry(domain, e.currentTarget) });
      if (busy) setRetryBusy(btn);
      item.append(h('span', { class: 'pf-na', dataset: { failed: r.failures.map((f) => f.source).join(' ') } }, NaMark(r.failures.map((f) => sourceStatus(f))), btn));
      return item;
    }
    const count = (analysis.rows || []).filter((x) => x.domain === domain).length;
    item.append(t(`ctw.src.${r.source}`), ' · ', t('ctw.read.count', { count }));
    const notes = [...r.notes, ...(analysis.first.includes(domain) ? ['first'] : [])];
    for (const n of notes) item.append(' · ', h('span', { class: 'muted', dataset: { note: n } }, t(`ctw.note.${n}`)));
    return item;
  }

  function renderNotes() {
    clear(notesEl);
    if (!S.startedAt) return;
    const failed = S.order.filter((d) => S.reads.has(d) && S.reads.get(d).state === 'failed');
    if (failed.length) {
      notesEl.append(Alert({ variant: 'warn', title: t('ctw.failedTitle', { count: failed.length }), children: h('ul', { class: 'pf-ct-reads', dataset: { role: 'ct-failed' } }, failed.map(readLine)) }));
    }
    if (!S.run && analysis.first.length) {
      const all = analysis.first.length === S.order.filter((d) => S.reads.has(d) && S.reads.get(d).state !== 'failed').length;
      const el = Alert({ variant: 'info', compact: true, message: all ? t('ctw.firstAll') : t('ctw.firstSome', { count: analysis.first.length, list: analysis.first.slice(0, 5).join(', ') + (analysis.first.length > 5 ? ` ${t('common.moreCount', { count: analysis.first.length - 5 })}` : '') }) });
      el.dataset.note = 'first';
      notesEl.append(el);
    }
    if (!(stateSingleton.workspaceData('expectedCas') || []).length && analysis.rows.length) {
      const el = Alert({ variant: 'info', compact: true, message: t('ctw.noExpected') });
      el.dataset.note = 'no-expected';
      notesEl.append(el);
    }
    const viaCrtsh = [...S.reads.values()].some((r) => r.source === 'crtsh');
    notesEl.append(Disclosure({
      summary: t('ctw.sourcesTitle'),
      className: 'pf-ct-sources',
      children: [h('ul', { class: 'pf-ct-reads', dataset: { role: 'ct-reads' } }, S.order.map(readLine)), viaCrtsh ? h('p', { class: 'muted text-sm' }, t('ctw.crtshPrecert')) : null]
    }));
  }

  /** The status item that stands for the table's filter (pressed while it applies): none for the default. */
  const statusOfFilter = (f) => (f !== 'current' && ctWatchStatus(null).some((x) => x.filter === f) ? f : null);

  /** The counts: the head's status summary (each a filter), the metric strip (read-only), the Show select. */
  function renderTiles() {
    const c = analysis.counts || {};
    const items = ctWatchStatus(c);
    const severity = Object.fromEntries(items.map((x) => [x.key, x.severity]));
    // While the check goes on no zero folds into the sentence: every count may still grow.
    tiles.update(CT_TILES.map((k) => ({
      id: k, label: t(`ctw.tile.${k}`, { days: radar() }), value: c[k] || 0,
      severity: c[k] && (severity[k] === 'warn' || severity[k] === 'error') ? severity[k] : null
    })), { foldable: S.run ? [] : CT_TILES.filter((k) => k !== 'current') });
    status.update(items.map((item) => ({
      ...item,
      text: t(`ctw.status.${item.key}`, { count: item.count, days: radar() }),
      // the current certificates are the table's default: a press shows them again
      filter: item.key !== 'current',
      onPress: () => setFilter(S.filter === item.filter ? 'current' : item.filter)
    })), { pressed: statusOfFilter(S.filter) });
    filterSelect.setOptions(CT_WATCH_FILTERS.map((f) => ({ value: f, label: t(`ctw.filter.${f}`, { count: c[f] || 0, days: radar() }) })));
    filterSelect.value = S.filter;
  }

  function setFilter(f) {
    S.filter = CT_WATCH_FILTERS.includes(f) ? f : 'current';
    table.setFilter((r) => matchesCtFilter(r, S.filter, { radar: radar() }));
    renderTiles();
  }

  function recompute() {
    const reads = S.order.map((d) => S.reads.get(d)).filter(Boolean);
    // the known certificates are read and matched now, not at the read: one whose end date is over
    // since is flagged again (the days left stay those of the read)
    const knownAt = Date.now();
    const known = readWaivers(stateSingleton.workspaceData('waivers'), { now: knownAt });
    analysis = analyzeCt(reads, { now: S.at || new Date(), knownAt, days, expected: stateSingleton.workspaceData('expectedCas') || [], seen: S.seenBefore || readSeen(''), known });
  }

  /** "Known certificate…": the dialog, then the waiver into the workspace (the subscription below draws the rows again). */
  async function markKnown(r) {
    let ui;
    try {
      ui = await loadWaivers();
    } catch (err) {
      ctx.checkOutdated();
      ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      return;
    }
    const subject = `${r.names.slice(0, 3).join(', ')}${r.names.length > 3 ? ` ${t('ctw.moreNames', { count: r.names.length - 3 })}` : ''} · ${r.ca}`;
    const input = await ui.openWaiverDialog({ kind: 'cert', domain: r.domain, ref: keyOf(r), subject });
    if (!input) return;
    try {
      knownFocus = r.id;
      const { waiver, persisted } = await ui.acceptRisk(input, stateSingleton);
      announce(t('wvr.saved', { date: waiver.expires, subject: r.names[0] }));
      if (!persisted) toast(t('wvr.notSaved', { reason: storageErrorText(stateSingleton.workspaceError) }), { type: 'warn' });
    } catch (err) {
      knownFocus = null;
      toast(err && err.code ? ui.waiverErrorText(err.code) : String(err && err.message ? err.message : err), { type: 'error' });
    }
  }

  function render() {
    recompute();
    renderForm();
    const has = !!S.startedAt;
    emptyEl.hidden = has;
    results.hidden = !has;
    if (S.run) progress.set(S.reads.size, S.order.length);
    renderHead();
    renderNotes();
    renderTiles();
    table.setRows(analysis.rows);
    table.setFilter((r) => matchesCtFilter(r, S.filter, { radar: radar() }));
  }

  let timer = null;
  const schedule = () => {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      render();
    }, 120);
  };
  const onState = (type) => {
    if (type === 'change') {
      schedule();
      return;
    }
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    render();
    if (type === 'done') announce(t('ctw.done', { count: analysis.rows.length }));
    if (type === 'stopped' && !ctx.signal.aborted) announce(t('ctw.stopped'));
  };
  panels.add(onState);

  /* --- actions ------------------------------------------------------------------------- */
  async function start() {
    if (S.run) return;
    const list = listDomains().slice(0, CT_WATCH_MAX_DOMAINS);
    if (!list.length) {
      renderForm();
      return;
    }
    const parsed = parseRadarDays(daysField.value);
    if (!parsed) {
      daysField.setError(t('ctw.daysBad', { days: CT_WATCH_MAX_DAYS }));
      daysField.focus();
      return;
    }
    if (!ctx.requireOnline()) return;
    days = parsed;
    S.days = parsed.join(', ');
    daysField.value = S.days;
    try {
      await runCheck(list);
    } catch (err) {
      ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    }
  }

  async function retry(domain, btn) {
    if (S.run || S.retrying.has(domain)) return;
    if (!ctx.requireOnline()) return;
    S.retrying.add(domain);
    if (btn) setRetryBusy(btn);
    try {
      const r = await readDomainCt(domain, { signal: mergeSignals(ctx.signal), spotterQueue });
      if (!S.order.includes(domain)) return;
      S.reads.set(domain, r);
      saveSeen([r]);
      announce(t('ctw.retried', { domain }));
    } catch (err) {
      if (!err || err.name !== 'AbortError') ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    } finally {
      S.retrying.delete(domain);
      render();
    }
  }

  const subject = () => (S.order.length === 1 ? S.order[0] : `${S.order.length}-domains`);
  const saved = (file) => toast(t('ctw.exported', { file }), { type: 'success', timeout: 2500 });

  function exportCsv() {
    const list = table.getVisibleRows().map(exportCtRow);
    saved(downloadText(timestampedName('ct-watch', 'csv', subject()), toCsv(list, CT_EXPORT_COLUMNS.map((key) => ({ key }))), 'text/csv;charset=utf-8'));
  }

  function exportCalendar() {
    const entries = expiryEntries(table.getVisibleRows());
    if (!entries.length) {
      toast(t('ctw.ics.none'), { type: 'info' });
      return;
    }
    const events = entries.map((e) => {
      const day = `${e.date.getFullYear()}-${String(e.date.getMonth() + 1).padStart(2, '0')}-${String(e.date.getDate()).padStart(2, '0')}`;
      return {
        uid: e.uid,
        date: e.date,
        summary: t('ctw.ics.summary', { name: e.names[0], count: e.names.length - 1 }),
        description: t('ctw.ics.description', { ca: e.intermediate ? `${e.ca} (${e.intermediate})` : e.ca, names: e.names.join(', ') }),
        alarm: t('ctw.ics.alarm', { name: e.names[0], date: day })
      };
    });
    const text = buildCalendar(events, { now: new Date(), name: t('ctw.ics.name'), prodId: CT_ICS_PRODID, alarmDays: days });
    saved(downloadText(timestampedName('ct-expiry', 'ics', subject()), text, 'text/calendar;charset=utf-8'));
  }

  // The expected CAs or the known certificates changed (Workspaces dialog, another tab, a click here): the flags follow.
  const unsubscribe = stateSingleton.subscribe(({ key, value }) => {
    if (key !== 'workspaceData' || !value || !Array.isArray(value.parts) || !value.parts.some((p) => p === 'expectedCas' || p === 'waivers')) return;
    render();
    if (knownFocus) {
      const id = knownFocus;
      knownFocus = null;
      // the table draws its rows on the next frame
      requestAnimationFrame(() => requestAnimationFrame(() => {
        const line = [...root.querySelectorAll('[data-role="ct-known-line"]')].find((el) => el.dataset.cert === id);
        if (line) line.focus();
      }));
    }
  });

  render();

  return {
    destroy() {
      panels.delete(onState);
      unsubscribe();
      // the actions follow the phone layout: their listener would keep this panel alive
      actions.dispose();
      if (timer) clearTimeout(timer);
      // Leaving the view stops a check: what was read so far is kept (and goes into the baseline).
      if (S.run) S.run.controller.abort();
    },
    refresh() {
      renderForm();
    }
  };
}

export default { mountCtWatch, generatedKeys, CT_TILES };
