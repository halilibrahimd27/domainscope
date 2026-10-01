/**
 * views/estate.js — "Certificate estate": open one or more JSON reports of the companion CLI
 * (`ssl_origin_scan.py --estate --json`, or any `--json` report) and see every certificate the
 * scanned servers serve, what needs a look first, and a CSV of it.
 *
 * - The reports are read in the browser and kept in this module's memory only: nothing is
 *   uploaded or stored, the route carries nothing, and a reload, Forget, another workspace or
 *   "Delete all local data" drops them. Nothing here touches the network.
 * - lib/estate.js does the work: readEstateReport (what is not a report says why), mergeReports
 *   (on an ip:port in several reports each name takes the newest report's answer; a note says
 *   so) and estateOf (the CLI's estate: expiry buckets, kinds, one name served with different
 *   certificates, one key on several hosts (addresses) or certificates, weak keys or signatures,
 *   certificates covering none of the names asked). Days left count from now.
 * - The page: the import card (a drop zone for .json files, the command that makes a report, the
 *   reports read so far), the numbers as tiles that filter the table (each counts certificates;
 *   its hint the names or keys behind them), the kinds, and three tabs:
 *   Certificates (filter, search, a row's details: fingerprints and where it is served; CSV of
 *   what the filter shows, the CLI's --estate --csv columns), Same name, different certificates,
 *   and Shared keys. "Copy summary" (lib/summary.js estateSummary) above the numbers: the counts,
 *   what expires first and what needs a look, by certificate name only — never an address or a
 *   server of the reports — and a link to the view without them.
 *
 * Pure helpers are exported for the unit tests (tests/js/estate-view.test.js); the module is
 * DOM-free at import time.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, DataTable, Disclosure, EmptyState, FileDrop, IconButton, StatCard, Tabs,
  TruncatedList, announce, select, textarea, toast
} from '../ui/components.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { SummaryButton } from '../ui/summary-button.js';
import { permalinkParams } from '../ui/view-summaries.js';
import { formatDate, formatDateTime, formatNumber, registerStrings } from '../i18n.js';
import {
  ESTATE_BUCKETS, ESTATE_FILTERS, ESTATE_KINDS, ESTATE_MAX_BYTES, ESTATE_MAX_REPORTS, SHARED_KEY_WIDE_HOSTS, estateCsv,
  estateFilterCounts, estateMatches, estateOf, mergeReports, readEstateReport, sharedKeyNeedsLook
} from '../lib/estate.js';

/** Route id (`#/estate`). */
export const id = 'estate';
/** i18n key of the page title. */
export const titleKey = 'nav.estate';
/** Nav/page icon. */
export const icon = 'certificate';

/** The result tabs, in display order. */
export const ESTATE_TABS = Object.freeze(['certificates', 'conflicts', 'keys']);
/** The CLI command the import card offers. */
export const CLI_EXAMPLE = 'python3 ssl_origin_scan.py -t hosts.ini -n names.txt --estate --json estate.json';
/** Files the drop zone offers. */
const ACCEPT = '.json';
/** At most this many endpoints of a certificate are listed in its table row (its details list all). */
const ROW_ENDPOINTS = 2;

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'estate.privacyTitle': 'Read in your browser',
  'estate.privacy': 'The reports are read here and kept only in this tab: nothing is uploaded or stored, and a reload, Forget, another workspace or “Delete all local data” clears them.',
  'estate.drop.title': 'Drop the CLI’s JSON reports here',
  'estate.drop.hint': 'or click to choose · several at once (one per site or jump host) · the file written by --json',
  'estate.paste.summary': 'Paste a report',
  'estate.paste.label': 'Report (JSON, as --json - prints it)',
  'estate.paste.read': 'Read report',
  'estate.how.summary': 'How to make a report',
  'estate.how.body': 'Run the CLI from a machine that reaches your servers. --estate asks every address without SNI and for every name you give with -n and every host name among the targets; no certificate file is needed. Any --json report of the CLI opens here too.',
  'estate.reports.title': 'Reports',
  'estate.reports.count': { one: '{count} report', other: '{count} reports' },
  'estate.reports.meta': 'scanned {when} · {servers} · {endpoints} · {certs}',
  'estate.reports.servers': { one: '{count} server', other: '{count} servers' },
  'estate.reports.endpoints': { one: '{count} endpoint', other: '{count} endpoints' },
  'estate.reports.certs': { one: '{count} certificate', other: '{count} certificates' },
  'estate.reports.estate': '--estate',
  'estate.reports.estateTitle': 'Written with --estate: the host names among the targets were asked too',
  'estate.reports.plain': 'without --estate',
  'estate.reports.plainTitle': 'A report without --estate: only the names given with -n (and the --cert names) were asked',
  'estate.reports.remove': 'Remove {name}',
  'estate.reports.removed': '{name} removed',
  'estate.forget': 'Forget all',
  'estate.forgotten': 'Reports forgotten',
  'estate.imported': { one: '{count} report read: {certs}', other: '{count} reports read: {certs}' },
  'estate.duplicate': '{name}: the same report is already open',
  'estate.tooMany': 'At most {max} reports at once: the rest were not read.',
  'estate.errorsTitle': 'Not read',
  'estate.error.too-large': '{name}: larger than {max} — not a report of the CLI',
  'estate.error.not-json': '{name}: not JSON. Choose the file the CLI wrote with --json (the --csv file does not open here).',
  'estate.error.not-report': '{name}: not a report of ssl_origin_scan.py',
  'estate.error.version': '{name}: written by version {detail} of the CLI, which this page cannot read',
  'estate.error.no-results': '{name}: a report without result rows',
  'estate.emptyTitle': 'No report open yet',
  'estate.emptyBody': 'Drop one or more JSON reports of the CLI above: the certificates they found are listed here with their expiry, kind and key, and what needs a look first.',
  'estate.note.overlap': { one: '{sample} was scanned by more than one report: for each name, the newest report’s answer is used.', other: '{sample} and {more} more endpoints were scanned by more than one report: for each name, the newest report’s answer is used.' },
  'estate.note.overlapPrivate': 'Reports of separate networks that reuse the same private addresses should be opened one at a time.',
  'estate.note.noKeys': { one: '{names} was written by an older CLI without public-key hashes: key reuse is not checked for its certificates.', other: '{names} were written by an older CLI without public-key hashes: key reuse is not checked for their certificates.' },
  'estate.note.noNames': 'No names were asked, only each address without SNI: which certificate covers which name cannot be told. Give your host names to the CLI with -n.',
  'estate.stat.certs': 'Certificates',
  'estate.stat.certsHint': { one: 'on {count} endpoint', other: 'on {count} endpoints' },
  'estate.stat.expiring': 'Expiring',
  'estate.stat.expiringHint': 'expired, or within 30 days',
  'estate.stat.conflicts': 'In a name conflict',
  'estate.stat.conflictsHint': { one: '{count} name, several certificates', other: '{count} names, several certificates' },
  'estate.stat.shared': 'With a shared key',
  'estate.stat.sharedHint': { one: '{count} key in several certificates or on {hosts}+ addresses', other: '{count} keys in several certificates or on {hosts}+ addresses' },
  'estate.stat.weak': 'Weak',
  'estate.stat.weakHint': 'RSA < 2048, SHA-1, MD5',
  'estate.stat.coversNone': 'Covering no name',
  'estate.stat.coversNoneHint': 'of the names asked',
  'estate.stat.noNames': 'no names asked',
  'estate.stat.filterTitle': 'Show these in the certificate list',
  'estate.kinds': 'Kinds',
  'estate.kind.origin-ca': 'Cloudflare Origin CA',
  'estate.kind.self-signed': 'self-signed',
  'estate.kind.private-ca': 'private CA',
  'estate.kind.other': 'other CA',
  'estate.expiryLine': 'Expiry',
  'estate.bucket.expired': 'expired',
  'estate.bucket.7d': '< 7 days',
  'estate.bucket.30d': '< 30 days',
  'estate.bucket.90d': '< 90 days',
  'estate.bucket.later': 'later',
  'estate.tab.certificates': 'Certificates',
  'estate.tab.conflicts': 'Name conflicts',
  'estate.tab.keys': 'Shared keys',
  'estate.tabsLabel': 'Estate results',
  'estate.filter.label': 'Show',
  'estate.filter.all': 'All ({count})',
  'estate.filter.attention': 'Needs a look ({count})',
  'estate.filter.expiring': 'Expired or within 30 days ({count})',
  'estate.filter.name-conflict': 'Name served with different certificates ({count})',
  'estate.filter.shared-key': 'Key in several certificates or on {hosts}+ addresses ({count})',
  'estate.filter.weak': 'Weak key or signature ({count})',
  'estate.filter.covers-none': 'Covers none of the names asked ({count})',
  'estate.filter.private': 'Self-signed or private CA ({count})',
  'estate.filter.origin-ca': 'Cloudflare Origin CA ({count})',
  'estate.col.cert': 'Certificate',
  'estate.col.expires': 'Expires',
  'estate.col.issuer': 'Issuer',
  'estate.col.key': 'Key',
  'estate.col.served': 'Served on',
  'estate.col.findings': 'Findings',
  'estate.names': { one: '{count} name', other: '{count} names' },
  'estate.noSubject': '(no subject)',
  'estate.days': { one: '{count} day', other: '{count} days' },
  'estate.expiredAgo': { one: 'expired {count} day ago', other: 'expired {count} days ago' },
  'estate.expiresToday': 'less than a day left',
  'estate.endpoints': { one: '{count} endpoint', other: '{count} endpoints' },
  'estate.moreEndpoints': '+{count} more',
  'estate.default': 'default',
  'estate.defaultTitle': 'Served without SNI (the certificate this address falls back to)',
  'estate.flag.name-conflict': 'name conflict',
  'estate.flag.stale': 'older',
  'estate.flag.shared-key': 'shared key',
  'estate.flag.weak': 'weak',
  'estate.flag.covers-none': 'covers no name',
  'estate.flagTitle.name-conflict': 'A name it covers is served with another certificate elsewhere',
  'estate.flagTitle.stale': 'Another certificate of the same key type and kind (Origin CA, private, other CA) was issued after it: the endpoints serving it were left behind',
  'estate.flagTitle.shared-key': 'Its public key is in several certificates, or on {hosts} or more addresses',
  'estate.flagTitle.weak': 'A weak key or signature',
  'estate.flagTitle.covers-none': 'It covers none of the names asked: a fallback or forgotten certificate',
  'estate.weak.rsa-short': 'RSA key under 2048 bits',
  'estate.weak.sha1': 'SHA-1 signature',
  'estate.weak.md5': 'MD5 / MD2 signature',
  'estate.weakShort.rsa-short': 'RSA < 2048',
  'estate.weakShort.sha1': 'SHA-1',
  'estate.weakShort.md5': 'MD5',
  'estate.noMatch': 'No certificate passes this filter.',
  'estate.search': 'Filter certificates',
  'estate.d.sha256': 'SHA-256',
  'estate.d.spki': 'Public key SHA-256',
  'estate.d.spkiNone': 'not in this report (an older CLI)',
  'estate.d.serial': 'Serial',
  'estate.d.validity': 'Valid',
  'estate.d.validityValue': '{from} → {to}',
  'estate.d.signature': 'Signature',
  'estate.d.names': 'Names',
  'estate.d.covers': 'Names asked it covers',
  'estate.d.coversNone': 'none',
  'estate.d.privateCa': 'Private CA',
  'estate.d.weak': 'Weak',
  'estate.d.servedTitle': 'Where it is served',
  'estate.d.servedFor': 'when asked for {names}',
  'estate.d.report': 'report {name}',
  'estate.conflicts.intro': 'These names are served with different certificates on different endpoints: a load-balancer member or a server the last renewal left out. “older” marks a certificate another one of the same key type and kind (Origin CA, private, other CA) replaces.',
  'estate.conflicts.none': 'No name is served with different certificates.',
  'estate.conflicts.noNames': 'No names were asked, so none can be compared.',
  'estate.conflicts.cert': '{name} · expires {date} · {issuer}',
  'estate.keys.intro': 'The same public key on several hosts (addresses), or in several certificates: one stolen key opens all of them, and a renewal that keeps the key removes none of that risk. One certificate on the members of a load-balancer pool is the usual case; “needs a look” marks a key in several certificates or on {hosts} or more addresses.',
  'estate.keys.none': 'No key is on more than one host or in more than one certificate.',
  'estate.keys.noHashes': 'Key reuse cannot be checked: the reports hold no public-key hashes (an older CLI).',
  'estate.keys.noCerts': 'No server returned a certificate: there is no key to compare.',
  'estate.keys.look': 'needs a look',
  'estate.keys.hosts': { one: '{count} address', other: '{count} addresses' },
  'estate.keys.certs': { one: '{count} certificate', other: '{count} certificates' },
  'estate.keys.spki': 'Public key SHA-256',
  'estate.keys.servers': 'Servers',
  'estate.keys.certsLabel': 'Certificates',
  'estate.csv': 'CSV',
  'estate.csvTitle': 'The certificates this filter shows, one row per certificate, endpoint and server (the CLI’s --estate --csv columns)',
  'estate.csvDone': '{file} downloaded'
});

registerStrings('tr', {
  'estate.privacyTitle': 'Tarayıcınızda okunur',
  'estate.privacy': 'Raporlar burada okunur ve yalnızca bu sekmede tutulur: hiçbir yere yüklenmez ya da kaydedilmez; sayfayı yenilemek, Unut, başka bir çalışma alanı ya da “Tüm yerel verileri sil” onları siler.',
  'estate.drop.title': 'CLI’nin JSON raporlarını buraya bırakın',
  'estate.drop.hint': 'ya da seçmek için tıklayın · aynı anda birkaç dosya (her konum ya da atlama sunucusu için bir tane) · --json ile yazılan dosya',
  'estate.paste.summary': 'Bir raporu yapıştırın',
  'estate.paste.label': 'Rapor (JSON, --json - çıktısı gibi)',
  'estate.paste.read': 'Raporu oku',
  'estate.how.summary': 'Rapor nasıl hazırlanır',
  'estate.how.body': 'CLI’yi sunucularınıza erişen bir makineden çalıştırın. --estate her adrese SNI olmadan ve -n ile verdiğiniz her ad ile hedefler arasındaki her host adı için sorar; sertifika dosyası gerekmez. CLI’nin her --json raporu da burada açılır.',
  'estate.reports.title': 'Raporlar',
  'estate.reports.count': { one: '{count} rapor', other: '{count} rapor' },
  'estate.reports.meta': '{when} tarandı · {servers} · {endpoints} · {certs}',
  'estate.reports.servers': { one: '{count} sunucu', other: '{count} sunucu' },
  'estate.reports.endpoints': { one: '{count} uç nokta', other: '{count} uç nokta' },
  'estate.reports.certs': { one: '{count} sertifika', other: '{count} sertifika' },
  'estate.reports.estate': '--estate',
  'estate.reports.estateTitle': '--estate ile yazıldı: hedefler arasındaki host adları da soruldu',
  'estate.reports.plain': '--estate olmadan',
  'estate.reports.plainTitle': '--estate olmadan yazılmış bir rapor: yalnızca -n ile verilen adlar (ve --cert adları) soruldu',
  'estate.reports.remove': '{name} raporunu kaldır',
  'estate.reports.removed': '{name} kaldırıldı',
  'estate.forget': 'Tümünü unut',
  'estate.forgotten': 'Raporlar unutuldu',
  'estate.imported': { one: '{count} rapor okundu: {certs}', other: '{count} rapor okundu: {certs}' },
  'estate.duplicate': '{name}: aynı rapor zaten açık',
  'estate.tooMany': 'Aynı anda en fazla {max} rapor: kalanlar okunmadı.',
  'estate.errorsTitle': 'Okunmadı',
  'estate.error.too-large': '{name}: {max} boyutundan büyük — CLI’nin bir raporu değil',
  'estate.error.not-json': '{name}: JSON değil. CLI’nin --json ile yazdığı dosyayı seçin (--csv dosyası burada açılmaz).',
  'estate.error.not-report': '{name}: ssl_origin_scan.py’nin bir raporu değil',
  'estate.error.version': '{name}: CLI’nin bu sayfanın okuyamadığı {detail} sürümüyle yazılmış',
  'estate.error.no-results': '{name}: sonuç satırı olmayan bir rapor',
  'estate.emptyTitle': 'Henüz açık rapor yok',
  'estate.emptyBody': 'CLI’nin bir ya da birkaç JSON raporunu yukarı bırakın: bulduğu sertifikalar süre dolumu, türü ve anahtarıyla burada listelenir; önce bakılması gerekenler en üstte.',
  'estate.note.overlap': { one: '{sample} birden çok raporda tarandı: her ad için en yeni raporun yanıtı kullanıldı.', other: '{sample} ve {more} uç nokta daha birden çok raporda tarandı: her ad için en yeni raporun yanıtı kullanıldı.' },
  'estate.note.overlapPrivate': 'Aynı özel adresleri kullanan ayrı ağların raporlarını tek tek açın.',
  'estate.note.noKeys': { one: '{names}, açık anahtar özetleri olmayan eski bir CLI ile yazılmış: sertifikalarında anahtarın yeniden kullanımı denetlenmez.', other: '{names}, açık anahtar özetleri olmayan eski bir CLI ile yazılmış: sertifikalarında anahtarın yeniden kullanımı denetlenmez.' },
  'estate.note.noNames': 'Hiçbir ad sorulmadı, her adres yalnızca SNI olmadan soruldu: hangi sertifikanın hangi adı kapsadığı söylenemez. Host adlarınızı CLI’ye -n ile verin.',
  'estate.stat.certs': 'Sertifikalar',
  'estate.stat.certsHint': { one: '{count} uç noktada', other: '{count} uç noktada' },
  'estate.stat.expiring': 'Süresi dolan',
  'estate.stat.expiringHint': 'dolmuş ya da 30 gün içinde dolacak',
  'estate.stat.conflicts': 'Ad çakışmasında',
  'estate.stat.conflictsHint': { one: '{count} ad, birden çok sertifika', other: '{count} ad, birden çok sertifika' },
  'estate.stat.shared': 'Paylaşılan anahtarlı',
  'estate.stat.sharedHint': { one: 'birden çok sertifikada ya da {hosts}+ adreste {count} anahtar', other: 'birden çok sertifikada ya da {hosts}+ adreste {count} anahtar' },
  'estate.stat.weak': 'Zayıf',
  'estate.stat.weakHint': 'RSA < 2048, SHA-1, MD5',
  'estate.stat.coversNone': 'Hiçbir adı kapsamayan',
  'estate.stat.coversNoneHint': 'sorulan adlardan',
  'estate.stat.noNames': 'ad sorulmadı',
  'estate.stat.filterTitle': 'Sertifika listesinde bunları göster',
  'estate.kinds': 'Türler',
  'estate.kind.origin-ca': 'Cloudflare Origin CA',
  'estate.kind.self-signed': 'kendinden imzalı',
  'estate.kind.private-ca': 'özel CA',
  'estate.kind.other': 'diğer CA',
  'estate.expiryLine': 'Süre dolumu',
  'estate.bucket.expired': 'dolmuş',
  'estate.bucket.7d': '< 7 gün',
  'estate.bucket.30d': '< 30 gün',
  'estate.bucket.90d': '< 90 gün',
  'estate.bucket.later': 'daha sonra',
  'estate.tab.certificates': 'Sertifikalar',
  'estate.tab.conflicts': 'Ad çakışmaları',
  'estate.tab.keys': 'Paylaşılan anahtarlar',
  'estate.tabsLabel': 'Envanter sonuçları',
  'estate.filter.label': 'Göster',
  'estate.filter.all': 'Tümü ({count})',
  'estate.filter.attention': 'Bakılması gerekenler ({count})',
  'estate.filter.expiring': 'Süresi dolmuş ya da 30 gün içinde dolacak ({count})',
  'estate.filter.name-conflict': 'Farklı sertifikalarla sunulan ad ({count})',
  'estate.filter.shared-key': 'Anahtarı birden çok sertifikada ya da {hosts}+ adreste olanlar ({count})',
  'estate.filter.weak': 'Zayıf anahtar ya da imza ({count})',
  'estate.filter.covers-none': 'Sorulan adların hiçbirini kapsamıyor ({count})',
  'estate.filter.private': 'Kendinden imzalı ya da özel CA ({count})',
  'estate.filter.origin-ca': 'Cloudflare Origin CA ({count})',
  'estate.col.cert': 'Sertifika',
  'estate.col.expires': 'Bitiş',
  'estate.col.issuer': 'Veren',
  'estate.col.key': 'Anahtar',
  'estate.col.served': 'Sunulduğu yer',
  'estate.col.findings': 'Bulgular',
  'estate.names': { one: '{count} ad', other: '{count} ad' },
  'estate.noSubject': '(konu yok)',
  'estate.days': { one: '{count} gün', other: '{count} gün' },
  'estate.expiredAgo': { one: '{count} gün önce doldu', other: '{count} gün önce doldu' },
  'estate.expiresToday': '1 günden az kaldı',
  'estate.endpoints': { one: '{count} uç nokta', other: '{count} uç nokta' },
  'estate.moreEndpoints': '+{count} daha',
  'estate.default': 'varsayılan',
  'estate.defaultTitle': 'SNI olmadan sunuluyor (bu adresin başka ad bilmediğinde verdiği sertifika)',
  'estate.flag.name-conflict': 'ad çakışması',
  'estate.flag.stale': 'eski',
  'estate.flag.shared-key': 'paylaşılan anahtar',
  'estate.flag.weak': 'zayıf',
  'estate.flag.covers-none': 'ad kapsamıyor',
  'estate.flagTitle.name-conflict': 'Kapsadığı bir ad başka bir yerde başka bir sertifikayla sunuluyor',
  'estate.flagTitle.stale': 'Aynı anahtar tipinde ve aynı sınıfta (Origin CA, özel, diğer CA) başka bir sertifika ondan sonra verilmiş: onu sunan uç noktalar geride kalmış',
  'estate.flagTitle.shared-key': 'Açık anahtarı birden çok sertifikada ya da {hosts} ya da daha çok adreste',
  'estate.flagTitle.weak': 'Zayıf bir anahtar ya da imza',
  'estate.flagTitle.covers-none': 'Sorulan adların hiçbirini kapsamıyor: bir yedek ya da unutulmuş sertifika',
  'estate.weak.rsa-short': '2048 bitten kısa RSA anahtarı',
  'estate.weak.sha1': 'SHA-1 imzası',
  'estate.weak.md5': 'MD5 / MD2 imzası',
  'estate.weakShort.rsa-short': 'RSA < 2048',
  'estate.weakShort.sha1': 'SHA-1',
  'estate.weakShort.md5': 'MD5',
  'estate.noMatch': 'Bu süzgece uyan sertifika yok.',
  'estate.search': 'Sertifikaları süz',
  'estate.d.sha256': 'SHA-256',
  'estate.d.spki': 'Açık anahtar SHA-256',
  'estate.d.spkiNone': 'bu raporda yok (eski bir CLI)',
  'estate.d.serial': 'Seri numarası',
  'estate.d.validity': 'Geçerlilik',
  'estate.d.validityValue': '{from} → {to}',
  'estate.d.signature': 'İmza',
  'estate.d.names': 'Adlar',
  'estate.d.covers': 'Kapsadığı sorulan adlar',
  'estate.d.coversNone': 'hiçbiri',
  'estate.d.privateCa': 'Özel CA',
  'estate.d.weak': 'Zayıf',
  'estate.d.servedTitle': 'Sunulduğu yerler',
  'estate.d.servedFor': '{names} sorulduğunda',
  'estate.d.report': '{name} raporu',
  'estate.conflicts.intro': 'Bu adlar farklı uç noktalarda farklı sertifikalarla sunuluyor: yük dengeleyicinin bir üyesi ya da son yenilemede atlanan bir sunucu. “eski”, aynı anahtar tipinde ve aynı sınıfta (Origin CA, özel, diğer CA) başka bir sertifikanın yerini aldığı sertifikayı gösterir.',
  'estate.conflicts.none': 'Hiçbir ad farklı sertifikalarla sunulmuyor.',
  'estate.conflicts.noNames': 'Hiçbir ad sorulmadığı için karşılaştırılacak ad yok.',
  'estate.conflicts.cert': '{name} · bitiş {date} · {issuer}',
  'estate.keys.intro': 'Birden çok sunucuda (adreste) ya da birden çok sertifikada aynı açık anahtar: çalınan tek bir anahtar hepsini açar ve anahtarı koruyan bir yenileme bu riski ortadan kaldırmaz. Tek bir sertifikanın bir yük dengeleyici havuzunun üyelerinde olması olağandır; “bakılmalı”, birden çok sertifikada ya da {hosts} ya da daha çok adreste olan bir anahtarı gösterir.',
  'estate.keys.none': 'Hiçbir anahtar birden çok sunucuda ya da sertifikada değil.',
  'estate.keys.noHashes': 'Anahtarın yeniden kullanımı denetlenemiyor: raporlarda açık anahtar özetleri yok (eski bir CLI).',
  'estate.keys.noCerts': 'Hiçbir sunucu sertifika döndürmedi: karşılaştırılacak anahtar yok.',
  'estate.keys.look': 'bakılmalı',
  'estate.keys.hosts': { one: '{count} adres', other: '{count} adres' },
  'estate.keys.certs': { one: '{count} sertifika', other: '{count} sertifika' },
  'estate.keys.spki': 'Açık anahtar SHA-256',
  'estate.keys.servers': 'Sunucular',
  'estate.keys.certsLabel': 'Sertifikalar',
  'estate.csv': 'CSV',
  'estate.csvTitle': 'Bu süzgecin gösterdiği sertifikalar; her sertifika, uç nokta ve sunucu için bir satır (CLI’nin --estate --csv sütunları)',
  'estate.csvDone': '{file} indirildi'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Read dropped files into the list of open reports: each file through lib/estate.js
 * readEstateReport; the same report again (its id) is a duplicate, never a second copy; at most
 * {@link ESTATE_MAX_REPORTS} stay open.
 * @param {import('../lib/estate.js').EstateReport[]} open the reports open so far
 * @param {Array<{ name: string, text: string }>} files
 * @returns {{ reports: import('../lib/estate.js').EstateReport[], added: number,
 *   errors: Array<{ name: string, error: string, detail?: string }>, duplicates: string[], capped: boolean }}
 */
export function importReports(open, files) {
  const reports = [...(open || [])];
  const errors = [];
  const duplicates = [];
  let added = 0;
  let capped = false;
  for (const file of files || []) {
    const name = String((file && file.name) || '');
    const read = readEstateReport(file && file.text, { name });
    if (!read.ok) {
      errors.push({ name, error: read.error, ...(read.detail ? { detail: read.detail } : {}) });
      continue;
    }
    if (reports.some((r) => r.id === read.report.id)) {
      duplicates.push(name);
      continue;
    }
    if (reports.length >= ESTATE_MAX_REPORTS) {
      capped = true;
      continue;
    }
    reports.push(read.report);
    added += 1;
  }
  return { reports, added, errors, duplicates, capped };
}

/**
 * The estate of the open reports, days counted from `now`.
 * @param {import('../lib/estate.js').EstateReport[]} reports
 * @param {number} [now]
 * @returns {{ merged: import('../lib/estate.js').MergedReports, estate: object }|null}
 */
export function estateOfReports(reports, now = Date.now()) {
  if (!reports || !reports.length) return null;
  const merged = mergeReports(reports);
  return { merged, estate: estateOf(merged.doc, { now }) };
}

/**
 * The Copy summary's facts (lib/summary.js estateSummary): the counts, the certificates that expire
 * first (expired or within 30 days, soonest first, by name), the names served with different
 * certificates and what needs a look; never an address or a server name of the reports.
 * @param {object} estate lib/estate.js estateOf
 * @param {Array<{ finishedAt?: Date|null }>} reports the reports read (the newest scan dates the summary)
 * @returns {object}
 */
export function estateSummaryFacts(estate, reports) {
  const counts = estateFilterCounts(estate);
  const name = (c) => c.subjectCN || (c.hostnames && c.hostnames[0]) || c.sha256.slice(0, 16);
  const times = (reports || []).map((r) => r && r.finishedAt).filter((d) => d instanceof Date && !Number.isNaN(d.getTime()));
  return {
    reports: (reports || []).length,
    certificates: estate.counts.certificates,
    endpoints: estate.counts.endpointsWithCertificate,
    expiry: { ...estate.counts.expiry },
    first: estate.certificates.filter((c) => estateMatches(c, 'expiring')).map((c) => ({ name: name(c), daysLeft: c.daysLeft })),
    conflicts: estate.nameConflicts.map((c) => c.name),
    stale: estate.certificates.filter((c) => c.flags.includes('stale')).length,
    sharedKeys: estate.sharedKeys.filter((g) => sharedKeyNeedsLook(g)).length,
    weak: counts.weak,
    coversNone: estate.namesAsked.length ? counts['covers-none'] : null,
    at: times.length ? new Date(Math.max(...times.map((d) => d.getTime()))) : null
  };
}

/**
 * Badge variant of an expiry bucket.
 * @param {string} bucket
 * @returns {'error'|'warn'|'info'|'ok'}
 */
export function bucketVariant(bucket) {
  if (bucket === 'expired' || bucket === '7d') return 'error';
  if (bucket === '30d') return 'warn';
  if (bucket === '90d') return 'info';
  return 'ok';
}

/** `ip:port`, IPv6 in brackets. */
export function endpointLabel(ip, port) {
  return String(ip).includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/** Page-session state (module memory only; see the module comment). */
const S = { reports: [], errors: [], paste: '', filter: 'all', tab: 'certificates', view: null };
let subscribed = false;
let rerender = null;

function forgetAll() {
  S.reports = [];
  S.errors = [];
  S.paste = '';
  S.filter = 'all';
  S.tab = 'certificates';
  S.view = null;
}

/**
 * Mount the view.
 * @param {HTMLElement} container
 * @param {object} ctx view context (app.js)
 */
export function mount(container, ctx) {
  const { t, state } = ctx;
  if (!subscribed && state && typeof state.subscribe === 'function') {
    subscribed = true;
    state.subscribe(({ key }) => {
      // The reports are the customer's: another workspace forgets them like "Delete all local data".
      if (key === 'cleared' || key === 'workspace') {
        forgetAll();
        if (rerender) rerender();
      }
    });
  }
  const root = h('div', { class: 'estate-page stack' });
  container.append(
    Alert({ variant: 'ok', icon: 'lock', title: t('estate.privacyTitle'), message: t('estate.privacy'), compact: true }),
    root);
  rerender = () => render();
  ctx.onCleanup(() => {
    rerender = null;
  });

  // several reports: the ones whose answers put this certificate on this endpoint
  const reportName = (endpoint, cert) => {
    if (!S.view || S.reports.length < 2) return '';
    const list = S.view.merged.sources.get(`${endpoint.ip}|${endpoint.port}|${cert.sha256}`) || [];
    return list.map((i) => S.reports[i].name).join(', ');
  };

  function recompute() {
    S.view = estateOfReports(S.reports);
    if (!S.view) S.filter = 'all';
  }

  function importFiles(files, { pasted = null } = {}) {
    const result = importReports(S.reports, files);
    S.reports = result.reports;
    S.errors = result.errors;
    // a pasted text that is not a report stays in its box, open, to be fixed
    S.paste = pasted !== null && !result.added ? pasted : '';
    for (const name of result.duplicates) toast(t('estate.duplicate', { name }), { type: 'info' });
    if (result.capped) toast(t('estate.tooMany', { max: ESTATE_MAX_REPORTS }), { type: 'warn' });
    if (result.added) {
      recompute();
      const msg = t('estate.imported', { count: result.added, certs: t('estate.reports.certs', { count: S.view.estate.counts.certificates }) });
      announce(msg);
      toast(msg, { type: 'success', timeout: 2500 });
    }
    render();
    // The page is drawn again: the focus goes to the numbers of what was read, else back to where
    // the text or the file came from (never to <body>).
    const target = result.added ? root.querySelector('.estate-stats [data-filter="all"]')
      : pasted !== null ? root.querySelector('[data-role="estate-paste"]') : root.querySelector('.estate-drop');
    if (target) target.focus();
  }

  function removeReport(report) {
    S.reports = S.reports.filter((r) => r !== report);
    recompute();
    toast(t('estate.reports.removed', { name: report.name }), { type: 'info' });
    render();
    const target = root.querySelector('.filedrop');
    if (target) target.focus({ preventScroll: true });
  }

  function forget() {
    forgetAll();
    toast(t('estate.forgotten'), { type: 'info' });
    render();
    const target = root.querySelector('.filedrop');
    if (target) target.focus({ preventScroll: true });
  }

  function setFilter(filter) {
    S.filter = S.filter === filter && filter !== 'all' ? 'all' : filter;
    S.tab = 'certificates';
    render();
    // the tiles are drawn again: the focus stays on the one pressed
    const tile = root.querySelector(`.estate-stats [data-filter="${filter}"]`);
    if (tile) tile.focus({ preventScroll: true });
  }

  /* --- render ------------------------------------------------------------ */
  function render() {
    clear(root);
    root.append(importCard());
    if (!S.view) {
      root.append(EmptyState({ icon: 'certificate', title: t('estate.emptyTitle'), message: t('estate.emptyBody') }));
      return;
    }
    const { estate, merged } = S.view;
    const notes = notesOf(estate, merged);
    // A scope without a submit: Ctrl/Cmd+Enter in the table's filter never re-reads a report.
    const summary = SummaryButton({
      kind: 'estate',
      facts: () => (S.view ? estateSummaryFacts(S.view.estate, S.reports) : null),
      // the view's bare link: the reports never go into a URL
      url: () => ctx.shareUrl(permalinkParams('estate', {}))
    });
    root.append(h('div', { class: 'stack estate-results', dataset: { shortcutScope: 'results' } },
      notes.length ? h('div', { class: 'stack-sm estate-notes' }, notes) : null,
      h('div', { class: 'cluster estate-summary' }, summary.el),
      statTiles(estate), overviewLine(estate), resultTabs(estate)));
  }

  function importCard() {
    const drop = FileDrop({
      accept: ACCEPT,
      multiple: true,
      compact: S.reports.length > 0,
      icon: 'upload',
      title: t('estate.drop.title'),
      hint: t('estate.drop.hint'),
      maxBytes: ESTATE_MAX_BYTES,
      className: 'estate-drop',
      paste: true,
      onFiles: (files) => importFiles(files)
    });
    drop.el.dataset.shortcut = 'focus';
    const how = Disclosure({
      summary: t('estate.how.summary'),
      className: 'estate-how',
      open: !S.reports.length,
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm' }, t('estate.how.body')),
        CodeBlock(CLI_EXAMPLE, { label: 'CLI', wrap: true }))
    });
    const errors = S.errors.length ? Alert({
      variant: 'warn',
      title: t('estate.errorsTitle'),
      children: h('ul', { class: 'estate-errors' }, S.errors.map((e) => h('li', null, t(`estate.error.${e.error}`, {
        name: e.name, detail: e.detail || '?', max: `${Math.round(ESTATE_MAX_BYTES / 1048576)} MB`
      }))))
    }) : null;
    const list = S.reports.length ? h('ul', { class: 'estate-reports' }, S.reports.map((report) => reportItem(report))) : null;
    // `--json -` prints the report: it can be pasted as well (the drop zone takes Ctrl+V too).
    const pasteArea = textarea({ label: t('estate.paste.label'), rows: 6, mono: true, value: S.paste, attrs: { 'data-role': 'estate-paste' } });
    const pasteBtn = Button({
      label: t('estate.paste.read'),
      icon: 'arrow-down',
      variant: 'primary',
      size: 'sm',
      dataset: { action: 'estate-paste-read', shortcut: 'submit' },
      onClick: () => {
        const text = pasteArea.value;
        if (text.trim()) importFiles([{ name: t('file.pasted'), text }], { pasted: text });
      }
    });
    const paste = Disclosure({
      summary: t('estate.paste.summary'),
      className: 'estate-paste',
      open: !!S.paste,
      children: h('div', { class: 'stack-sm', dataset: { shortcutScope: 'estate-paste' } }, pasteArea.el, h('div', { class: 'cluster' }, pasteBtn))
    });
    return Card({
      title: t('estate.reports.title'),
      subtitle: S.reports.length ? t('estate.reports.count', { count: S.reports.length }) : null,
      icon: 'file-text',
      className: 'estate-import',
      actions: S.reports.length ? Button({ label: t('estate.forget'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'estate-forget' }, onClick: forget }) : null,
      children: h('div', { class: 'stack-sm' }, drop.el, errors, list, paste, how)
    });
  }

  function reportItem(report) {
    const { doc } = report;
    const summary = doc.summary && typeof doc.summary === 'object' ? doc.summary : {};
    const certs = doc.certificates && typeof doc.certificates === 'object' ? Object.keys(doc.certificates).length : 0;
    const endpoints = Array.isArray(doc.endpoints) ? doc.endpoints.length : (Number(summary.endpoints) || 0);
    const servers = Array.isArray(doc.servers) ? doc.servers.length : (Number(summary.servers) || 0);
    return h('li', { class: 'estate-report', dataset: { report: report.name } },
      h('div', { class: 'estate-report-text' },
        h('span', { class: 'estate-report-name mono' }, report.name || '—'),
        h('span', { class: 'estate-report-meta muted text-sm' }, t('estate.reports.meta', {
          when: report.finishedAt ? formatDateTime(report.finishedAt, { utc: true }) : '—',
          servers: t('estate.reports.servers', { count: servers }),
          endpoints: t('estate.reports.endpoints', { count: endpoints }),
          certs: t('estate.reports.certs', { count: certs })
        }))),
      h('div', { class: 'estate-report-badges cluster' },
        report.estate
          ? Badge(t('estate.reports.estate'), { variant: 'accent', title: t('estate.reports.estateTitle'), mono: true })
          : Badge(t('estate.reports.plain'), { variant: 'neutral', title: t('estate.reports.plainTitle') }),
        IconButton({ icon: 'x', label: t('estate.reports.remove', { name: report.name }), size: 'sm', onClick: () => removeReport(report) })));
  }

  function notesOf(estate, merged) {
    const out = [];
    if (merged.overlaps.length) {
      const [ip, port] = merged.overlaps[0].split('|');
      out.push(Alert({
        variant: 'info',
        compact: true,
        message: `${t('estate.note.overlap', { count: merged.overlaps.length, sample: endpointLabel(ip, port), more: merged.overlaps.length - 1 })} ${t('estate.note.overlapPrivate')}`
      }));
    }
    const noKeys = S.reports.filter((r) => !r.keyHashes).map((r) => r.name);
    if (noKeys.length) out.push(Alert({ variant: 'info', compact: true, message: t('estate.note.noKeys', { count: noKeys.length, names: noKeys.join(', ') }) }));
    if (!estate.namesAsked.length) out.push(Alert({ variant: 'warn', compact: true, message: t('estate.note.noNames') }));
    return out;
  }

  function statTiles(estate) {
    const counts = estateFilterCounts(estate);
    const noNames = !estate.namesAsked.length;
    const tile = (filter, label, value, hint, variant) => {
      const card = StatCard({
        label,
        value,
        hint,
        variant: value ? variant : 'default',
        pressed: S.filter === filter,
        onClick: () => setFilter(filter)
      });
      card.el.dataset.filter = filter;
      card.el.title = t('estate.stat.filterTitle');
      return card.el;
    };
    return h('div', { class: 'stat-grid estate-stats' },
      tile('all', t('estate.stat.certs'), estate.counts.certificates, t('estate.stat.certsHint', { count: estate.counts.endpointsWithCertificate }), 'accent'),
      tile('expiring', t('estate.stat.expiring'), counts.expiring, t('estate.stat.expiringHint'), 'error'),
      tile('name-conflict', t('estate.stat.conflicts'), counts['name-conflict'], t('estate.stat.conflictsHint', { count: estate.nameConflicts.length }), 'warn'),
      tile('shared-key', t('estate.stat.shared'), counts['shared-key'], t('estate.stat.sharedHint', {
        count: estate.sharedKeys.filter((g) => sharedKeyNeedsLook(g)).length, hosts: SHARED_KEY_WIDE_HOSTS
      }), 'warn'),
      tile('weak', t('estate.stat.weak'), counts.weak, t('estate.stat.weakHint'), 'error'),
      tile('covers-none', t('estate.stat.coversNone'), noNames ? '—' : counts['covers-none'], noNames ? t('estate.stat.noNames') : t('estate.stat.coversNoneHint'), 'warn'));
  }

  function overviewLine(estate) {
    const part = (label, items) => h('div', { class: 'estate-line' },
      h('span', { class: 'estate-line-label' }, label),
      h('span', { class: 'estate-line-items' }, items));
    return h('div', { class: 'estate-overview' },
      part(t('estate.expiryLine'), ESTATE_BUCKETS.map((b) => Badge(`${t(`estate.bucket.${b}`)} ${formatNumber(estate.counts.expiry[b])}`, {
        variant: estate.counts.expiry[b] ? bucketVariant(b) : 'neutral'
      }))),
      part(t('estate.kinds'), ESTATE_KINDS.map((k) => Badge(`${t(`estate.kind.${k}`)} ${formatNumber(estate.counts.kinds[k])}`, {
        variant: 'neutral', className: `estate-kind estate-kind-${k}`
      }))));
  }

  function resultTabs(estate) {
    const tabs = Tabs([
      { id: 'certificates', label: t('estate.tab.certificates'), icon: 'certificate', badge: estate.counts.certificates, content: () => certificatesPanel(estate) },
      { id: 'conflicts', label: t('estate.tab.conflicts'), icon: 'git-branch', badge: estate.nameConflicts.length, content: () => conflictsPanel(estate) },
      { id: 'keys', label: t('estate.tab.keys'), icon: 'key', badge: estate.sharedKeys.length, content: () => keysPanel(estate) }
    ], {
      selected: S.tab,
      label: t('estate.tabsLabel'),
      className: 'estate-tabs',
      onChange: (tab) => {
        S.tab = tab;
      }
    });
    return tabs.el;
  }

  /* --- Certificates --------------------------------------------------------- */
  function certificatesPanel(estate) {
    const counts = estateFilterCounts(estate);
    const filter = select({
      label: t('estate.filter.label'),
      className: 'estate-filter',
      size: 'sm',
      value: S.filter,
      options: ESTATE_FILTERS.map((f) => ({ value: f, label: t(`estate.filter.${f}`, { count: formatNumber(counts[f]), hosts: SHARED_KEY_WIDE_HOSTS }) })),
      onChange: (v) => {
        S.filter = v;
        table.setFilter((c) => estateMatches(c, S.filter));
        root.querySelectorAll('.estate-stats .stat-button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.filter === v)));
      }
    });
    const table = DataTable({
      caption: t('estate.tab.certificates'),
      rows: estate.certificates,
      rowKey: (c) => c.sha256,
      search: { placeholder: t('estate.search'), label: t('estate.search') },
      filter: (c) => estateMatches(c, S.filter),
      noMatch: t('estate.noMatch'),
      toolbar: filter.el,
      cellLabels: true,
      maxHeight: null,
      className: 'estate-table',
      rowClass: (c) => ({ 'estate-row-attention': estateMatches(c, 'attention') }),
      details: (c) => certDetails(c),
      export: {
        formats: ['csv'],
        onExport: (_format, rows) => {
          const file = downloadText(timestampedName('estate', 'csv'), estateCsv(estate, {
            certificates: rows, reportName: S.reports.length > 1 ? reportName : null
          }), 'text/csv;charset=utf-8');
          toast(t('estate.csvDone', { file }), { type: 'success', timeout: 2500 });
        }
      },
      columns: [
        {
          key: 'cert', label: t('estate.col.cert'), sortable: true, wrap: true,
          sortValue: (c) => c.subjectCN || c.subjectDN || c.sha256,
          searchValue: (c) => [c.subjectCN, c.subjectDN, c.issuer, c.sha256, c.spkiSha256, ...c.hostnames,
            ...c.endpoints.flatMap((e) => [e.ip, ...e.servers])].filter(Boolean).join(' '),
          render: (c) => h('div', { class: 'estate-cert' },
            h('span', { class: 'estate-cert-name mono' }, c.subjectCN || c.subjectDN || t('estate.noSubject')),
            c.hostnames.length ? h('span', { class: 'muted text-xs' }, t('estate.names', { count: c.hostnames.length })) : null)
        },
        {
          key: 'expires', label: t('estate.col.expires'), sortable: true, sortValue: (c) => c.daysLeft,
          render: (c) => h('div', { class: 'estate-expires' },
            h('span', { class: 'nowrap' }, c.notAfter ? formatDate(new Date(c.notAfter), { utc: true }) : '—'),
            Badge(daysText(c.daysLeft), { variant: bucketVariant(c.expiry), className: 'estate-days' }))
        },
        {
          key: 'issuer', label: t('estate.col.issuer'), sortable: true, wrap: true, sortValue: (c) => c.issuer || '',
          render: (c) => h('div', { class: 'estate-issuer' },
            h('span', null, c.issuer || '—'),
            c.kind !== 'other' ? kindBadge(c.kind) : null)
        },
        {
          key: 'key', label: t('estate.col.key'), sortable: true, sortValue: (c) => c.key,
          render: (c) => h('div', { class: 'estate-key' },
            h('span', { class: 'nowrap' }, c.key),
            c.weak.map((w) => Badge(t(`estate.weakShort.${w}`), { variant: 'error', title: t(`estate.weak.${w}`) })))
        },
        {
          key: 'served', label: t('estate.col.served'), sortable: true, wrap: true, sortValue: (c) => c.endpoints.length,
          render: (c) => h('div', { class: 'estate-served' },
            c.endpoints.slice(0, ROW_ENDPOINTS).map((e) => h('span', { class: 'estate-endpoint mono' }, endpointText(e))),
            c.endpoints.length > ROW_ENDPOINTS ? h('span', { class: 'muted text-xs' }, t('estate.moreEndpoints', { count: c.endpoints.length - ROW_ENDPOINTS })) : null)
        },
        {
          key: 'findings', label: t('estate.col.findings'), wrap: true, sortable: true,
          sortValue: (c) => -c.flags.length,
          searchValue: (c) => c.flags.map((f) => t(`estate.flag.${f}`)).join(' '),
          render: (c) => (c.flags.length ? h('div', { class: 'estate-flags cluster' }, c.flags.map((f) => flagBadge(f))) : null)
        }
      ]
    });
    return h('div', { class: 'stack-sm' }, table.el);
  }

  function kindBadge(kind) {
    return Badge(t(`estate.kind.${kind}`), { variant: kind === 'origin-ca' ? 'cloudflare' : 'private' });
  }

  function flagBadge(flag, label = null) {
    const variant = flag === 'weak' || flag === 'stale' ? 'error' : flag === 'covers-none' ? 'neutral' : 'warn';
    return Badge(label || t(`estate.flag.${flag}`), { variant, title: t(`estate.flagTitle.${flag}`, { hosts: SHARED_KEY_WIDE_HOSTS }), className: `estate-flag estate-flag-${flag}` });
  }

  function daysText(days) {
    if (days < 0) return t('estate.expiredAgo', { count: -days });
    if (days === 0) return t('estate.expiresToday'); // under 24 hours: maybe tomorrow on the calendar
    return t('estate.days', { count: days });
  }

  function endpointText(e) {
    const servers = e.servers.filter((s) => s !== e.ip);
    const where = endpointLabel(e.ip, e.port);
    return servers.length ? `${servers.join(', ')} ${where}` : where;
  }

  function certDetails(c) {
    const row = (label, value, mono = false) => h('div', { class: 'estate-d-row' },
      h('dt', { class: 'estate-d-key' }, label), h('dd', { class: ['estate-d-value', { mono }] }, value));
    return h('div', { class: 'estate-details stack-sm' },
      h('dl', { class: 'estate-d' },
        row(t('estate.d.sha256'), c.sha256, true),
        row(t('estate.d.spki'), c.spkiSha256 || t('estate.d.spkiNone'), !!c.spkiSha256),
        row(t('estate.d.serial'), c.serialHex || '—', true),
        row(t('estate.d.validity'), t('estate.d.validityValue', {
          from: c.notBefore ? formatDate(new Date(c.notBefore), { utc: true }) : '—',
          to: c.notAfter ? formatDate(new Date(c.notAfter), { utc: true }) : '—'
        })),
        row(t('estate.d.signature'), c.signatureAlgorithm || '—'),
        c.privateCa ? row(t('estate.d.privateCa'), c.privateCa) : null,
        c.weak.length ? row(t('estate.d.weak'), c.weak.map((w) => t(`estate.weak.${w}`)).join(' · ')) : null,
        row(t('estate.d.names'), c.hostnames.length ? TruncatedList(c.hostnames, { max: 8, inline: true }) : '—'),
        row(t('estate.d.covers'), c.coversAsked.length ? TruncatedList(c.coversAsked, { max: 8, inline: true }) : t('estate.d.coversNone'))),
      h('div', { class: 'estate-d-served' },
        h('div', { class: 'field-label' }, t('estate.d.servedTitle')),
        h('ul', { class: 'estate-d-endpoints' }, c.endpoints.map((e) => {
          const report = reportName(e, c);
          return h('li', null,
            h('span', { class: 'mono' }, endpointText(e)),
            e.defaultCert ? Badge(t('estate.default'), { variant: 'neutral', title: t('estate.defaultTitle') }) : null,
            e.names.length ? h('span', { class: 'muted text-sm' }, t('estate.d.servedFor', { names: e.names.join(', ') })) : null,
            report ? h('span', { class: 'muted text-xs' }, t('estate.d.report', { name: report })) : null);
        }))));
  }

  /* --- Same name, different certificates ------------------------------------ */
  function conflictsPanel(estate) {
    if (!estate.namesAsked.length) return EmptyState({ compact: true, icon: 'git-branch', message: t('estate.conflicts.noNames') });
    if (!estate.nameConflicts.length) return EmptyState({ compact: true, icon: 'check-circle', message: t('estate.conflicts.none') });
    const certs = new Map(estate.certificates.map((c) => [c.sha256, c]));
    return h('div', { class: 'stack-sm estate-conflicts' },
      h('p', { class: 'text-sm muted' }, t('estate.conflicts.intro')),
      estate.nameConflicts.map((conflict) => h('section', { class: 'estate-conflict' },
        h('h3', { class: 'estate-conflict-name mono' }, conflict.name),
        h('ul', { class: 'estate-conflict-certs' }, conflict.certificates.map((item) => {
          const cert = certs.get(item.sha256);
          return h('li', { class: ['estate-conflict-cert', { 'is-stale': item.stale }], dataset: { sha: item.sha256 } },
            h('div', { class: 'estate-conflict-head' },
              h('span', { class: 'estate-cert-name mono' }, cert.subjectCN || cert.subjectDN || t('estate.noSubject')),
              Badge(daysText(cert.daysLeft), { variant: bucketVariant(cert.expiry) }),
              cert.kind !== 'other' ? kindBadge(cert.kind) : null,
              item.stale ? flagBadge('stale') : null),
            h('div', { class: 'muted text-sm' }, t('estate.conflicts.cert', {
              name: cert.key,
              date: cert.notAfter ? formatDate(new Date(cert.notAfter), { utc: true }) : '—',
              issuer: cert.issuer || '—'
            })),
            h('div', { class: 'estate-conflict-where' }, item.endpoints.map((e) => h('span', { class: 'estate-endpoint mono' }, endpointText({ ...e, names: [] })))));
        })))));
  }

  /* --- Shared keys ------------------------------------------------------------ */
  function keysPanel(estate) {
    if (!estate.certificates.length) return EmptyState({ compact: true, icon: 'key', message: t('estate.keys.noCerts') });
    if (!estate.certificates.some((c) => c.spkiSha256)) return EmptyState({ compact: true, icon: 'key', message: t('estate.keys.noHashes') });
    if (!estate.sharedKeys.length) return EmptyState({ compact: true, icon: 'check-circle', message: t('estate.keys.none') });
    const certs = new Map(estate.certificates.map((c) => [c.sha256, c]));
    return h('div', { class: 'stack-sm estate-keys' },
      h('p', { class: 'text-sm muted' }, t('estate.keys.intro', { hosts: SHARED_KEY_WIDE_HOSTS })),
      estate.sharedKeys.map((group) => h('section', { class: 'estate-key-group', dataset: { spki: group.spkiSha256, look: String(sharedKeyNeedsLook(group)) } },
        h('div', { class: 'estate-key-head' },
          h('h3', { class: 'estate-key-title' }, group.key),
          Badge(t('estate.keys.hosts', { count: group.hosts }), { variant: group.hosts >= SHARED_KEY_WIDE_HOSTS ? 'warn' : 'neutral' }),
          Badge(t('estate.keys.certs', { count: group.certificates.length }), { variant: group.certificates.length > 1 ? 'warn' : 'neutral' }),
          sharedKeyNeedsLook(group) ? flagBadge('shared-key', t('estate.keys.look')) : null),
        h('dl', { class: 'estate-d' },
          h('div', { class: 'estate-d-row' }, h('dt', { class: 'estate-d-key' }, t('estate.keys.spki')), h('dd', { class: 'estate-d-value mono' }, group.spkiSha256)),
          h('div', { class: 'estate-d-row' }, h('dt', { class: 'estate-d-key' }, t('estate.keys.certsLabel')),
            h('dd', { class: 'estate-d-value' }, TruncatedList(group.certificates.map((sha) => certs.get(sha).subjectCN || sha.slice(0, 16)), { max: 6, inline: true }))),
          h('div', { class: 'estate-d-row' }, h('dt', { class: 'estate-d-key' }, t('estate.keys.servers')),
            h('dd', { class: 'estate-d-value' }, TruncatedList(group.servers, { max: 8, inline: true })))))));
  }

  // The last result in this page session, shown again when the view is opened again.
  if (S.reports.length && !S.view) recompute();
  render();
}

/** Stop re-rendering for state changes of an unmounted view. */
export function unmount() {
  rerender = null;
}

export default { id, titleKey, icon, mount, unmount };
