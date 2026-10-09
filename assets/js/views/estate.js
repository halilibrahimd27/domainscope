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
 * - The page template (ui/template.js; docs/DESIGN.md §5.5 "File", phase 3): the file input (a
 *   drop zone for .json files, paste, the command that makes a report; once reports are read one
 *   row — "2 reports loaded" with the reports behind it · Add files · Forget all — over the privacy
 *   note), the result header `.estate-overview` ("Certificate estate · 9 certificates on 7
 *   endpoints", when the newest report was scanned, the counts — expired, expiring within 30 days,
 *   in a name conflict, with a shared key, weak — as filters of the certificate list, Copy summary
 *   and Export ▾ with the CSV of what the list shows and Print), the notes as a finding list, and
 *   three tabs: Certificates (the expiry buckets and kinds as figures, then filter, search, a row's
 *   details: fingerprints and where it is served; the CLI's --estate --csv columns in the CSV; a
 *   report made with --ari or --revocation adds a renewal-window (ARI) or a revocation column, its
 *   counts in the figures and its records in the details, ui/revocation.js; a report whose scan
 *   checked trust flags the certificates an endpoint serves with an untrusted chain, a filter of
 *   their own, and says why per endpoint in the details, OpenSSL's verify code in the page's
 *   words), Same name, different certificates, and Shared keys. "Copy summary" (lib/summary.js
 *   estateSummary): the counts, what expires first and what needs a look, by certificate name only
 *   — never an address or a server of the reports — and a link to the view without them.
 *
 * Pure helpers are exported for the unit tests (tests/js/estate-view.test.js); the module is
 * DOM-free at import time.
 */

import { h, clear, scrollBehavior } from '../ui/dom.js';
import {
  Alert, Badge, Button, CodeBlock, DataTable, Disclosure, EmptyState, FileDrop, IconButton, Tabs,
  TruncatedList, announce, select, textarea, toast
} from '../ui/components.js';
// The page template (docs/DESIGN.md §5; phase 3): the file input, the result header, the figures, the notes.
import {
  EmptyState as ToolEmptyState, FileInput, FindingList, MetricStrip, PrivacyNote, ResultActions, ResultHeader, ResultTitle, StatusSummary
} from '../ui/template.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { SummaryButton } from '../ui/summary-button.js';
import { permalinkParams } from '../ui/view-summaries.js';
import { AriCell, RevocationCell, statusDetails } from '../ui/revocation.js';
import { formatDate, formatDateTime, formatNumber, registerStrings } from '../i18n.js';
import {
  ESTATE_ARI_STATES, ESTATE_BUCKETS, ESTATE_FILTERS, ESTATE_KINDS, ESTATE_MAX_BYTES, ESTATE_MAX_REPORTS, ESTATE_REVOCATION_STATES,
  SHARED_KEY_WIDE_HOSTS, estateCsv, estateMatches, estateOf, estateStatus, estateStatusCounts, estateFilterCounts, mergeReports, readEstateReport,
  sharedKeyNeedsLook, trustDetailCode
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
  'estate.privacy': 'The reports are read here and kept only in this tab: nothing is uploaded or stored, and a reload, Forget, another workspace or “Delete all local data” clears them.',
  'estate.reportsSub': 'The JSON files ssl_origin_scan.py writes with --json',
  'estate.loaded': { one: '{count} report loaded', other: '{count} reports loaded' },
  'estate.addFiles': 'Add files',
  'estate.emptyLine': 'Every certificate the scanned servers serve, what needs a look first, and a CSV of it.',
  'estate.headTitle': 'Certificate estate · {certs} on {endpoints}',
  'estate.scannedAt': 'Scanned {when}',
  'estate.st.expired': { one: '{count} expired', other: '{count} expired' },
  'estate.st.soon': { one: '{count} expires within 30 days', other: '{count} expire within 30 days' },
  'estate.st.name-conflict': { one: '{count} in a name conflict', other: '{count} in a name conflict' },
  'estate.st.shared-key': { one: '{count} with a shared key', other: '{count} with a shared key' },
  'estate.st.weak': { one: '{count} weak', other: '{count} weak' },
  'estate.metrics': 'Certificates by expiry and kind',
  'estate.filter.expired': 'Expired ({count})',
  'estate.filter.soon': 'Expiring within 30 days ({count})',
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
  'estate.note.overlap': { one: '{sample} was scanned by more than one report: for each name, the newest report’s answer is used.', other: '{sample} and {more} more endpoints were scanned by more than one report: for each name, the newest report’s answer is used.' },
  'estate.note.overlapPrivate': 'Reports of separate networks that reuse the same private addresses should be opened one at a time.',
  'estate.note.noKeys': { one: '{names} was written by an older CLI without public-key hashes: key reuse is not checked for its certificates.', other: '{names} were written by an older CLI without public-key hashes: key reuse is not checked for their certificates.' },
  'estate.note.noNames': 'No names were asked, only each address without SNI: which certificate covers which name cannot be told. Give your host names to the CLI with -n.',
  'estate.stat.weak': 'Weak',
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
  'estate.filter.untrusted': 'Served with an untrusted chain ({count})',
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
  'estate.flag.untrusted': 'untrusted',
  'estate.flagTitle.untrusted': 'An endpoint serves it with a chain the CLI’s machine does not trust: a missing intermediate, a private CA or a self-signed certificate',
  'estate.trust.code20': 'missing intermediate or private CA',
  'estate.trust.code21': 'missing intermediate',
  'estate.trust.code18': 'self-signed',
  'estate.trust.code19': 'a root the machine does not trust',
  'estate.trust.code10': 'expired',
  'estate.trust.code9': 'not yet valid',
  'estate.trust.code62': 'issued for another name',
  'estate.trust.withCode': '{reason} (code {code})',
  'estate.trust.unknown': 'not trusted',
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
  'estate.privacy': 'Raporlar burada okunur ve yalnızca bu sekmede tutulur: hiçbir yere yüklenmez ya da kaydedilmez; sayfayı yenilemek, Unut, başka bir çalışma alanı ya da “Tüm yerel verileri sil” onları siler.',
  'estate.reportsSub': 'ssl_origin_scan.py’nin --json ile yazdığı JSON dosyaları',
  'estate.loaded': '{count} rapor yüklendi',
  'estate.addFiles': 'Dosya ekle',
  'estate.emptyLine': 'Taranan sunucuların sunduğu her sertifika, önce bakılması gerekenler ve bunların CSV dosyası.',
  'estate.headTitle': 'Sertifika envanteri · {endpoints} üzerinde {certs}',
  'estate.scannedAt': 'Tarama: {when}',
  'estate.st.expired': '{count} sertifikanın süresi doldu',
  'estate.st.soon': '{count} sertifikanın süresi 30 gün içinde doluyor',
  'estate.st.name-conflict': '{count} sertifika ad çakışmasında',
  'estate.st.shared-key': '{count} sertifika anahtarını paylaşıyor',
  'estate.st.weak': '{count} zayıf sertifika',
  'estate.metrics': 'Bitişe ve türe göre sertifikalar',
  'estate.filter.expired': 'Süresi dolmuş ({count})',
  'estate.filter.soon': '30 gün içinde dolacak ({count})',
  'estate.drop.title': 'CLI’nin JSON raporlarını buraya bırakın',
  'estate.drop.hint': 'ya da seçmek için tıklayın · aynı anda birkaç dosya (her konum ya da atlama sunucusu için bir tane) · --json ile yazılan dosya',
  'estate.paste.summary': 'Bir raporu yapıştırın',
  'estate.paste.label': 'Rapor (JSON, --json - çıktısı gibi)',
  'estate.paste.read': 'Raporu oku',
  'estate.how.summary': 'Rapor nasıl hazırlanır',
  'estate.how.body': 'CLI’yi sunucularınıza erişen bir makineden çalıştırın. --estate her adrese SNI olmadan ve -n ile verdiğiniz her ad ile hedefler arasındaki her host adı için sorar; sertifika dosyası gerekmez. CLI’nin her --json raporu da burada açılır.',
  'estate.reports.title': 'Raporlar',
  'estate.reports.count': { one: '{count} rapor', other: '{count} rapor' },
  'estate.reports.meta': 'Tarama: {when} · {servers} · {endpoints} · {certs}',
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
  'estate.note.overlap': { one: '{sample} birden çok raporda tarandı: her ad için en yeni raporun yanıtı kullanıldı.', other: '{sample} ve {more} uç nokta daha birden çok raporda tarandı: her ad için en yeni raporun yanıtı kullanıldı.' },
  'estate.note.overlapPrivate': 'Aynı özel adresleri kullanan ayrı ağların raporlarını tek tek açın.',
  'estate.note.noKeys': { one: '{names}, açık anahtar özetleri olmayan eski bir CLI ile yazılmış: sertifikalarında anahtarın yeniden kullanımı denetlenmez.', other: '{names}, açık anahtar özetleri olmayan eski bir CLI ile yazılmış: sertifikalarında anahtarın yeniden kullanımı denetlenmez.' },
  'estate.note.noNames': 'Hiçbir ad sorulmadı, her adres yalnızca SNI olmadan soruldu: hangi sertifikanın hangi adı kapsadığı söylenemez. Host adlarınızı CLI’ye -n ile verin.',
  'estate.stat.weak': 'Zayıf',
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
  'estate.filter.untrusted': 'Güvenilmeyen bir zincirle sunulan ({count})',
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
  'estate.flag.untrusted': 'güvenilmeyen',
  'estate.flagTitle.untrusted': 'Bir uç nokta onu, CLI’nin çalıştığı makinenin güvenmediği bir zincirle sunuyor: eksik ara sertifika, özel CA ya da kendinden imzalı sertifika',
  'estate.trust.code20': 'eksik ara sertifika ya da özel CA',
  'estate.trust.code21': 'eksik ara sertifika',
  'estate.trust.code18': 'kendinden imzalı',
  'estate.trust.code19': 'makinenin güvenmediği bir kök',
  'estate.trust.code10': 'süresi dolmuş',
  'estate.trust.code9': 'henüz geçerli değil',
  'estate.trust.code62': 'başka bir ad için verilmiş',
  'estate.trust.withCode': '{reason} (kod {code})',
  'estate.trust.unknown': 'güvenilmiyor',
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

/**
 * Page-session state (module memory only; see the module comment). `importOpen`: the compact
 * input's "n reports loaded" disclosure is open (kept over a redraw).
 */
const S = { reports: [], errors: [], paste: '', filter: 'all', tab: 'certificates', view: null, importOpen: false };
let subscribed = false;
let rerender = null;

function forgetAll() {
  S.reports = [];
  S.errors = [];
  S.paste = '';
  S.filter = 'all';
  S.tab = 'certificates';
  S.view = null;
  S.importOpen = false;
}

/** The status items that are filters of the certificate list ({@link estateStatus}): their key is the filter. */
const STATUS_FILTERS = Object.freeze(['expired', 'soon', 'name-conflict', 'shared-key', 'weak']);

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
  const root = h('div', { class: 'estate-page' });
  container.append(root);
  rerender = () => render();
  /** The result header's actions (they follow the phone layout), taken back with the header. */
  let actions = null;
  const disposeActions = () => {
    if (actions) actions.dispose();
    actions = null;
  };
  /** The header's status summary (its pressed item follows the list's filter), and the certificate table, while they are on screen. */
  let status = null;
  let table = null;
  ctx.onCleanup(() => {
    rerender = null;
    disposeActions();
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
    // A text to fix, or a file that was not read: the compact input opens on it; a clean import folds it.
    S.importOpen = !!(S.paste || S.errors.length);
    render();
    // The page is drawn again: the focus goes to the result's title once something was read, else
    // back to where the text or the file came from (never to <body>).
    const target = result.added ? root.querySelector('.estate-overview .result-title')
      : pasted !== null ? root.querySelector('[data-role="estate-paste"]') : root.querySelector('.estate-drop');
    if (target) target.focus();
  }

  function removeReport(report) {
    S.reports = S.reports.filter((r) => r !== report);
    recompute();
    toast(t('estate.reports.removed', { name: report.name }), { type: 'info' });
    render();
    // The list the Remove was in is drawn again: its first Remove left, else the drop zone (both
    // in the open "n reports loaded" disclosure, or in the whole card once none is left).
    const target = root.querySelector('.estate-report .btn-icon') || root.querySelector('.filedrop');
    if (target) target.focus({ preventScroll: true });
  }

  function forget() {
    forgetAll();
    toast(t('estate.forgotten'), { type: 'info' });
    render();
    const target = root.querySelector('.filedrop');
    if (target) target.focus({ preventScroll: true });
  }

  /** A filter of the certificate list (a pressed count of the header, or the Show select): the status and the select follow. */
  function setFilter(filter, { fromStatus = false } = {}) {
    S.filter = ESTATE_FILTERS.includes(filter) ? filter : 'all';
    if (status) status.setPressed(STATUS_FILTERS.includes(S.filter) ? S.filter : null);
    if (table) table.setFilter((c) => estateMatches(c, S.filter));
    const sel = root.querySelector('.estate-filter select');
    if (sel && sel.value !== S.filter) sel.value = S.filter;
    if (!fromStatus) return;
    // A count opens the tab that lists what it counts (docs/DESIGN.md §5.4).
    if (S.tab !== 'certificates' && tabs) tabs.select('certificates');
    const panel = root.querySelector('.estate-tabs');
    if (panel) panel.scrollIntoView({ block: 'nearest', behavior: scrollBehavior() });
  }

  /* --- render ------------------------------------------------------------ */
  /** The result's tabs on screen (a count of the header opens Certificates). */
  let tabs = null;

  function render() {
    disposeActions();
    status = null;
    table = null;
    tabs = null;
    clear(root);
    root.append(importCard());
    if (!S.view) {
      // The empty result region (docs/DESIGN.md §5.2): what the tool gives, the chips of what it reads.
      root.append(h('div', { class: 'estate-empty' }, ToolEmptyState({
        icon: 'certificate',
        message: t('estate.emptyLine'),
        checks: [t('estate.expiryLine'), t('estate.kinds'), t('estate.tab.conflicts'), t('estate.tab.keys'), t('estate.stat.weak')]
      })));
      return;
    }
    const { estate, merged } = S.view;
    root.append(resultHead(estate).el);
    // What the reports need said (region 7: they concern the whole estate, so they come before the tabs).
    root.append(FindingList({ className: 'estate-notes', findings: notesOf(estate, merged) }).el);
    // A scope without a submit: Ctrl/Cmd+Enter in the table's filter never re-reads a report.
    root.append(h('div', { class: 'stack estate-results', dataset: { shortcutScope: 'results' } }, resultTabs(estate)));
  }

  /**
   * The result header (region 4; docs/DESIGN.md §5.6): "Certificate estate · 9 certificates on 7
   * endpoints", when the newest report was scanned, the counts as filters of the certificate list,
   * then Copy summary and Export ▾ (CSV of what the list shows, Print). No Copy link: the reports
   * never go into a URL.
   * @param {object} estate
   */
  function resultHead(estate) {
    const head = ResultHeader({ className: 'estate-overview' });
    head.setState('done');
    head.set('title', ResultTitle({
      text: t('estate.headTitle', {
        certs: t('estate.reports.certs', { count: estate.counts.certificates }),
        endpoints: t('estate.reports.endpoints', { count: estate.counts.endpointsWithCertificate })
      })
    }));
    const times = S.reports.map((r) => r.finishedAt).filter((d) => d instanceof Date && !Number.isNaN(d.getTime()));
    const newest = times.length ? new Date(Math.max(...times.map((d) => d.getTime()))) : null;
    head.set('meta', [
      newest ? h('span', { class: 'estate-scanned', title: newest.toISOString() }, t('estate.scannedAt', { when: formatDateTime(newest, { utc: true }) })) : null,
      h('span', null, t('estate.reports.count', { count: S.reports.length }))
    ]);
    status = StatusSummary({
      className: 'estate-status',
      pressed: STATUS_FILTERS.includes(S.filter) ? S.filter : null,
      items: estateStatus(estate).map((item) => ({
        ...item,
        text: t(`estate.st.${item.key}`, { count: item.count }),
        filter: true,
        onPress: (key) => setFilter(S.filter === key ? 'all' : key, { fromStatus: true })
      }))
    });
    head.set('status', status.el);
    actions = ResultActions({
      summary: SummaryButton({
        kind: 'estate',
        plainLabel: t('result.plainTitle'),
        facts: () => (S.view ? estateSummaryFacts(S.view.estate, S.reports) : null),
        // the view's bare link: the reports never go into a URL
        url: () => ctx.shareUrl(permalinkParams('estate', {}))
      }),
      exports: [{ label: t('estate.csv'), title: t('estate.csvTitle'), icon: 'download', dataset: { export: 'csv' }, onSelect: () => exportCsv(estate) }],
      print: true
    });
    head.set('actions', actions.el);
    return head;
  }

  /** The certificates the list shows (its filter and search), the CLI's --estate --csv rows. */
  function exportCsv(estate) {
    const rows = table ? table.getVisibleRows() : estate.certificates.filter((c) => estateMatches(c, S.filter));
    const file = downloadText(timestampedName('estate', 'csv'), estateCsv(estate, {
      certificates: rows, reportName: S.reports.length > 1 ? reportName : null
    }), 'text/csv;charset=utf-8');
    toast(t('estate.csvDone', { file }), { type: 'success', timeout: 2500 });
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
    // Region 2 (docs/DESIGN.md §5.5, "File"): the drop zone, paste and how to make a report; once
    // reports are read, one row — "2 reports loaded" (the list and the rest behind it) · Add files ·
    // Forget all — over the privacy note, which stays.
    const privacy = PrivacyNote({ text: t('estate.privacy'), className: 'estate-privacy' });
    if (!S.reports.length) {
      return FileInput({
        title: t('estate.reports.title'),
        subtitle: t('estate.reportsSub'),
        icon: 'file-text',
        className: 'estate-import',
        label: t('nav.estate'),
        body: [drop.el, errors, paste, how],
        privacy
      }).el;
    }
    const input = FileInput({
      loaded: true,
      className: 'estate-import',
      label: t('nav.estate'),
      more: t('estate.loaded', { count: S.reports.length }),
      moreClass: 'estate-import-more',
      moreOpen: S.importOpen,
      body: [list, drop.el, errors, paste, how],
      actions: [
        Button({ label: t('estate.addFiles'), icon: 'plus', size: 'sm', dataset: { action: 'estate-add' }, onClick: () => drop.open() }),
        Button({ label: t('estate.forget'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'estate-forget' }, onClick: forget })
      ],
      privacy
    });
    input.more.addEventListener('toggle', () => { S.importOpen = input.more.open; });
    return input.el;
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

  /** What the reports need said, as findings (they were stacked alerts). */
  function notesOf(estate, merged) {
    const out = [];
    if (merged.overlaps.length) {
      const [ip, port] = merged.overlaps[0].split('|');
      out.push({
        key: 'overlap', severity: 'info',
        text: `${t('estate.note.overlap', { count: merged.overlaps.length, sample: endpointLabel(ip, port), more: merged.overlaps.length - 1 })} ${t('estate.note.overlapPrivate')}`
      });
    }
    const noKeys = S.reports.filter((r) => !r.keyHashes).map((r) => r.name);
    if (noKeys.length) out.push({ key: 'no-keys', severity: 'info', text: t('estate.note.noKeys', { count: noKeys.length, names: noKeys.join(', ') }) });
    if (!estate.namesAsked.length) out.push({ key: 'no-names', severity: 'warn', text: t('estate.note.noNames') });
    return out;
  }

  /**
   * The figures of the certificate list (region 6, read-only; docs/DESIGN.md §5.6: "expiry/kind
   * chips → metric strip"): the expiry buckets — each shown, a distribution —, the kinds (a zero
   * folds into one sentence), and the CLI's --ari / --revocation states when a report has them.
   */
  function metricsOf(estate) {
    const st = estateStatusCounts(estate);
    const row = (id, label, metrics, foldable = []) => h('div', { class: 'estate-metric-row', dataset: { metrics: id } },
      h('span', { class: 'estate-metric-title' }, label),
      MetricStrip({ label, metrics, foldable, className: `estate-metrics-${id}` }).el);
    const severityOf = (bucket, n) => (!n ? null : bucket === 'expired' || bucket === '7d' ? 'error' : bucket === '30d' ? 'warn' : null);
    return h('div', { class: 'estate-metrics', attrs: { role: 'group', 'aria-label': t('estate.metrics') } },
      row('expiry', t('estate.expiryLine'), ESTATE_BUCKETS.map((b) => ({
        id: b, label: t(`estate.bucket.${b}`), value: estate.counts.expiry[b], severity: severityOf(b, estate.counts.expiry[b])
      }))),
      row('kinds', t('estate.kinds'), ESTATE_KINDS.map((k) => ({ id: k, label: t(`estate.kind.${k}`), value: estate.counts.kinds[k] })), [...ESTATE_KINDS]),
      // the CLI's --ari / --revocation, when a report has them
      st.ari ? row('ari', t('rev.col.ari'), ESTATE_ARI_STATES.map((s) => ({
        id: s, label: t(`rev.sum.ari.${s}`), value: st.ari[s], severity: st.ari[s] && (s === 'open' || s === 'past') ? 'error' : null
      })), [...ESTATE_ARI_STATES]) : null,
      st.revocation ? row('revocation', t('rev.col.revocation'), ESTATE_REVOCATION_STATES.map((s) => ({
        id: s, label: t(`rev.sum.rev.${s}`), value: st.revocation[s], severity: st.revocation[s] && s === 'revoked' ? 'error' : null
      })), [...ESTATE_REVOCATION_STATES]) : null);
  }

  function resultTabs(estate) {
    // Text and count only (docs/DESIGN.md §7 Tabs).
    tabs = Tabs([
      { id: 'certificates', label: t('estate.tab.certificates'), badge: estate.counts.certificates, content: () => certificatesPanel(estate) },
      { id: 'conflicts', label: t('estate.tab.conflicts'), badge: estate.nameConflicts.length, content: () => conflictsPanel(estate) },
      { id: 'keys', label: t('estate.tab.keys'), badge: estate.sharedKeys.length, content: () => keysPanel(estate) }
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
    // the CLI's --ari / --revocation: a column each, next to the expiry, when a report has them
    const hasAri = estate.certificates.some((c) => c.ari);
    const hasRevocation = estate.certificates.some((c) => c.revocation);
    const filter = select({
      label: t('estate.filter.label'),
      className: 'estate-filter',
      size: 'sm',
      value: S.filter,
      options: ESTATE_FILTERS.map((f) => ({ value: f, label: t(`estate.filter.${f}`, { count: formatNumber(counts[f]), hosts: SHARED_KEY_WIDE_HOSTS }) })),
      // The Show select and the header's counts are the same filter (docs/DESIGN.md §5.1, region 6).
      onChange: (v) => setFilter(v)
    });
    // The CSV of what the list shows is the result header's Export (exportCsv reads this table).
    table = DataTable({
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
        ...(hasAri ? [{
          key: 'ari', label: t('rev.col.ari'), sortable: true, searchable: false, className: 'estate-col-ari',
          sortValue: (c) => (c.ariWindow ? Date.parse(c.ari.start) : Number.MAX_SAFE_INTEGER),
          render: (c) => AriCell(c.ari, c.ariWindow)
        }] : []),
        ...(hasRevocation ? [{
          key: 'revocation', label: t('rev.col.revocation'), sortable: true, searchable: false, className: 'estate-col-revocation',
          sortValue: (c) => ({ revoked: 0, unknown: 1, good: 2 })[c.revocation && c.revocation.status] ?? 3,
          render: (c) => RevocationCell(c.revocation)
        }] : []),
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
    return h('div', { class: 'stack' }, metricsOf(estate), table.el);
  }

  function kindBadge(kind) {
    return Badge(t(`estate.kind.${kind}`), { variant: kind === 'origin-ca' ? 'cloudflare' : 'private' });
  }

  function flagBadge(flag, label = null) {
    const variant = flag === 'weak' || flag === 'stale' || flag === 'untrusted' ? 'error' : flag === 'covers-none' ? 'neutral' : 'warn';
    return Badge(label || t(`estate.flag.${flag}`), { variant, title: t(`estate.flagTitle.${flag}`, { hosts: SHARED_KEY_WIDE_HOSTS }), className: `estate-flag estate-flag-${flag}` });
  }

  /** Why the CLI's machine does not trust an endpoint's chain, in the page's language when the CLI named a verify code. */
  function trustText(detail) {
    const code = trustDetailCode(detail);
    if (code === null) return detail || t('estate.trust.unknown');
    return t('estate.trust.withCode', { reason: t(`estate.trust.code${code}`), code });
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
        row(t('estate.d.covers'), c.coversAsked.length ? TruncatedList(c.coversAsked, { max: 8, inline: true }) : t('estate.d.coversNone')),
        statusDetails(c).map(([label, value, mono]) => row(label, value, mono))),
      h('div', { class: 'estate-d-served' },
        h('div', { class: 'field-label' }, t('estate.d.servedTitle')),
        h('ul', { class: 'estate-d-endpoints' }, c.endpoints.map((e) => {
          const report = reportName(e, c);
          return h('li', null,
            h('span', { class: 'mono' }, endpointText(e)),
            e.defaultCert ? Badge(t('estate.default'), { variant: 'neutral', title: t('estate.defaultTitle') }) : null,
            e.names.length ? h('span', { class: 'muted text-sm' }, t('estate.d.servedFor', { names: e.names.join(', ') })) : null,
            // the CLI's trust check: why its machine does not trust the chain served here
            e.trusted === false ? h('span', { class: 'estate-untrusted cluster' },
              flagBadge('untrusted'), h('span', { class: 'text-sm' }, trustText(e.trustDetail))) : null,
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
