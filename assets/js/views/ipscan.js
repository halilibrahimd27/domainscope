/**
 * views/ipscan.js — "IP Scan": which addresses of an IPv4 range are used and which are free,
 * before a new server gets one. A browser can neither ping nor reach an internal network, so the
 * probing is the companion CLI's (`cli/ip_scan.py`: ping, a few TCP ports, the ARP table and
 * reverse DNS, run from a machine on that network); this view reads its --json reports and draws
 * the range as a map, with the workspace's server list on top.
 *
 * - Nothing is sent: the range, the reports and the server list are read here. The reports are
 *   kept in this module's memory only (a reload, Forget, another workspace or "Delete all local
 *   data" drops them); the route carries the range, never a report.
 * - lib/ipscan.js does the work: parseScanRange (networks, ranges, addresses; at most a /20),
 *   readScanReport / mergeScanReports (the newest report answers for an address), addressMap
 *   (used, claimed, free, reserved, not scanned; the inventory's servers claim their addresses),
 *   suggestFree / freeRuns, the CSV rows and the free list.
 * - The page template (ui/template.js): the input card (the range; Show map draws it at once),
 *   the reports' file input (drop zone, paste, how to scan with the command for the range and the
 *   CLI to download), the result header (the range and its size, when the newest scan ran, the
 *   states as filters, Copy summary and Export ▾ with the CSV and the free addresses), the free
 *   addresses to use (confirmed first, each copied with a click, and the longest free runs), and
 *   two tabs: Map (one grid of 16 columns per /24, arrow keys move between the cells, a cell's
 *   details below its grid) and List (the table: ping, open ports, MAC, names, web server).
 *
 * Pure helpers are exported for the unit tests (tests/js/ipscan-view.test.js); the module is
 * DOM-free at import time.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Button, ButtonLink, CodeBlock, CopyButton, DataTable, Disclosure, FileDrop, Icon, IconButton, Tabs, Tag,
  announce, ipSortValue, select, textarea, toast
} from '../ui/components.js';
import {
  EmptyState, ExampleChips, FileInput, PrivacyNote, ResultActions, ResultHeader, ResultTitle, RunBar, StatusSummary, ToolInput
} from '../ui/template.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { SummaryButton } from '../ui/summary-button.js';
import { CliSteps } from '../ui/cli-steps.js';
import { formatDateTime, formatNumber, registerStrings } from '../i18n.js';
import { permalinkParams, registerSummaryBuilder } from '../lib/summarycore.js';
import { toCsv } from '../lib/export.js';
import { ipscanSummary, IPSCAN_SUMMARY_I18N } from '../lib/ipscansummary.js';
import {
  CLI_FILE, CLI_PATH, IPSCAN_CSV_COLUMNS, IPSCAN_FILTERS, IPSCAN_MAX_ADDRESSES, IPSCAN_MAX_BYTES, IPSCAN_MAX_REPORTS, IPSCAN_STATES,
  addressMap, cliCommand, freeListText, freeRuns, ipscanCsvRows, ipscanMatches, ipscanSummaryFacts, parseScanRange, readScanReport,
  reportsRange, suggestFree
} from '../lib/ipscan.js';

/** Route id (`#/ipscan`). */
export const id = 'ipscan';
/** i18n key of the page title. */
export const titleKey = 'nav.ipscan';
/** Nav/page icon. */
export const icon = 'map-pin';

/** The result tabs, in display order. */
export const IPSCAN_TABS = Object.freeze(['map', 'list']);
/** The example the input offers (a private /24: the ranges this tool is for). */
export const EXAMPLE_RANGE = '10.0.5.0/24';
/** Free addresses offered as one-click copies. */
const SUGGEST_COUNT = 8;
/** Columns of a map row. */
export const GRID_COLUMNS = 16;
/** The states the header counts as filters (unscanned and reserved are facts the legend shows). */
const STATUS_FILTERS = Object.freeze(['used', 'claimed', 'free', 'unscanned']);

// Copy summary's builder and texts load with this view, not on the start route (lib/ipscansummary.js).
registerSummaryBuilder('ipscan', ipscanSummary);
registerStrings('en', IPSCAN_SUMMARY_I18N.en);
registerStrings('tr', IPSCAN_SUMMARY_I18N.tr);

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'ipscan.range.label': 'Range',
  'ipscan.range.placeholder': '10.0.5.0/24 · 10.0.5.10-60 · 192.168.1.20',
  'ipscan.range.hint': 'IPv4 networks, ranges and addresses, at most {max} addresses (a /20). Private ranges welcome.',
  'ipscan.run': 'Show map',
  'ipscan.privacy': 'Nothing is sent: the map is drawn from the reports you open and your server list. The scan itself runs on your network, with ip_scan.py.',
  'ipscan.exampleTitle': 'A private /24',
  'ipscan.parsed': { one: '{count} address', other: '{count} addresses' },
  'ipscan.issue.invalid': { one: 'Not an IPv4 address, range or network: {items}', other: 'Not IPv4 addresses, ranges or networks: {items}' },
  'ipscan.issue.v6': 'IPv6 is not mapped (a /64 alone holds 2^64 addresses): {items}',
  'ipscan.issue.reversed': 'The range ends before it starts: {items}',
  'ipscan.issue.too-large': '{count} addresses is more than one map shows ({max}).',
  'ipscan.issue.use': 'Map {suggestion}',
  'ipscan.issue.host-bits': '{input} is read as the network {cidr}.',
  'ipscan.issue.nothing': 'Type a network (10.0.5.0/24), a range (10.0.5.10-60) or an address.',

  'ipscan.reports.title': 'Scan results',
  'ipscan.reports.sub': 'The JSON files ip_scan.py writes with --json',
  'ipscan.reports.privacy': 'The reports are read here and kept only in this tab: nothing is uploaded or stored, and a reload, Forget, another workspace or “Delete all local data” clears them.',
  'ipscan.drop.title': 'Drop the reports of ip_scan.py here',
  'ipscan.drop.hint': 'or click to choose · several at once (one per jump host, or last week and today) · the file written by --json',
  'ipscan.paste.summary': 'Paste a report',
  'ipscan.paste.label': 'Report (JSON, as --json - prints it)',
  'ipscan.paste.read': 'Read report',
  'ipscan.steps.title': 'The scan does not run in the browser',
  'ipscan.steps.why': 'A web page can neither ping nor reach your internal network, so the scan runs on a machine on that network, with ip_scan.py from this site. This page then reads its report and draws the map; nothing is sent from here.',
  'ipscan.steps.cannot.ping': 'ping an address',
  'ipscan.steps.cannot.ports': 'try the TCP ports of a machine on your network',
  'ipscan.steps.cannot.arp': 'read the ARP table, the one place an address is confirmed free',
  'ipscan.steps.can.map': 'draws the range as a map: used, claimed, free',
  'ipscan.steps.can.servers': 'puts your server list on top',
  'ipscan.steps.can.pick': 'picks the free addresses to use',
  'ipscan.steps.s1': 'Download ip_scan.py',
  'ipscan.steps.s1Text': 'One Python 3 file, nothing to install. Copy it to a machine on the network you scan.',
  'ipscan.steps.s2': 'Run it on that network',
  'ipscan.steps.s2Text': 'From a machine on the same network as the range: only there can an address be confirmed free.',
  'ipscan.steps.s3': 'Open the report here',
  'ipscan.steps.s3Text': 'Drop scan.json on the page or choose it: the map fills in, and nothing leaves the browser.',
  'ipscan.steps.s3Open': 'Open the report',
  'ipscan.steps.tips': 'Also from the command line',
  'ipscan.steps.summary': { one: 'Scanned on your network with ip_scan.py · {count} report open', other: 'Scanned on your network with ip_scan.py · {count} reports open' },
  'ipscan.how.download': 'Download ip_scan.py',
  'ipscan.how.free': 'Only the free addresses, one a line:',
  'ipscan.how.check': 'Before you assign one address (exit code 1 when it is taken):',
  'ipscan.loaded': { one: '{count} report loaded', other: '{count} reports loaded' },
  'ipscan.addFiles': 'Add files',
  'ipscan.forget': 'Forget all',
  'ipscan.forgotten': 'Reports forgotten',
  'ipscan.imported': { one: '{count} report read: {addresses}', other: '{count} reports read: {addresses}' },
  'ipscan.duplicate': '{name}: the same report is already open',
  'ipscan.tooMany': 'At most {max} reports at once: the rest were not read.',
  'ipscan.removed': '{name} removed',
  'ipscan.remove': 'Remove {name}',
  'ipscan.errorsTitle': 'Not read',
  'ipscan.error.too-large': '{name}: larger than {max} — not a report of ip_scan.py',
  'ipscan.error.not-json': '{name}: not JSON. Choose the file ip_scan.py wrote with --json (the --csv file does not open here).',
  'ipscan.error.not-report': '{name}: not a report of ip_scan.py',
  'ipscan.error.version': '{name}: written by version {detail} of ip_scan.py, which this page cannot read',
  'ipscan.error.no-results': '{name}: a report without addresses',
  'ipscan.report.meta': 'scanned {when} · {addresses} · {targets}',
  'ipscan.report.addresses': { one: '{count} address', other: '{count} addresses' },
  'ipscan.report.noPing': 'no ping',
  'ipscan.report.noPingTitle': 'This scan could not ping (not allowed on its machine): a machine that answers no TCP port looks free',
  'ipscan.report.noArp': 'no ARP',
  'ipscan.report.noArpTitle': 'This scan could not read the ARP table: no address is confirmed free',

  'ipscan.emptyLine': 'Which addresses of a range are taken, which are free, and the ones to use.',
  'ipscan.check.ping': 'Ping',
  'ipscan.check.ports': 'TCP ports',
  'ipscan.check.arp': 'ARP table',
  'ipscan.check.dns': 'Reverse DNS',
  'ipscan.check.servers': 'Your servers',

  'ipscan.headTitle': '{range} · {addresses}',
  'ipscan.scannedAt': 'Scanned {when}',
  'ipscan.noScanMeta': 'not scanned yet',
  'ipscan.reportsCount': { one: '{count} report', other: '{count} reports' },
  'ipscan.state.used': 'Used',
  'ipscan.state.claimed': 'Claimed',
  'ipscan.state.free': 'Free',
  'ipscan.state.reserved': 'Reserved',
  'ipscan.state.unscanned': 'Not scanned',
  'ipscan.stateHelp.used': 'Something answered: a ping, a TCP port or the ARP table.',
  'ipscan.stateHelp.claimed': 'Nothing answered, but your server list or a reverse DNS name claims it: check before you use it.',
  'ipscan.stateHelp.free': 'Nothing answered and nothing claims it.',
  'ipscan.stateHelp.freeConfirmed': 'Nothing answered, nothing claims it, and no device answered ARP for it (or a router called it unreachable): free.',
  'ipscan.stateHelp.freeUnconfirmed': 'Nothing answered and nothing claims it. Not confirmed: a machine that drops every packet looks the same.',
  'ipscan.stateHelp.reserved': 'The network or broadcast address of the network: never a host’s.',
  'ipscan.stateHelp.unscanned': 'No open report covers it.',
  'ipscan.st.used': { one: '{count} used', other: '{count} used' },
  'ipscan.st.claimed': { one: '{count} claimed', other: '{count} claimed' },
  'ipscan.st.free': { one: '{count} free', other: '{count} free' },
  'ipscan.st.unscanned': { one: '{count} not scanned', other: '{count} not scanned' },
  'ipscan.st.freeTitle': '{confirmed} of them confirmed: no device answered ARP',
  'ipscan.csv': 'CSV',
  'ipscan.csvTitle': 'The addresses this filter shows, with the evidence',
  'ipscan.freeTxt': 'Free addresses (.txt)',
  'ipscan.freeTxtTitle': 'The free addresses, one a line',
  'ipscan.downloaded': '{file} downloaded',
  'ipscan.noneToExport': 'No free address to export',

  'ipscan.noScan.title': 'Not scanned yet',
  'ipscan.noScan.body': 'Follow the steps above: run ip_scan.py on this network and open its report here. Until then the map marks only the addresses your server list claims.',
  'ipscan.outside': { one: '{count} address of the reports is outside this range.', other: '{count} addresses of the reports are outside this range.' },
  'ipscan.outsideUse': 'Map the reports’ range',
  'ipscan.unscannedNote': { one: '{count} address of the range is in no report: scan it too.', other: '{count} addresses of the range are in no report: scan them too.' },
  'ipscan.noConfirm': 'No scan could confirm an address free (no ARP table, or not run on this network): a machine that drops every packet looks free. Check before you use one.',
  'ipscan.pick.title': 'Free to use',
  'ipscan.pick.confirmed': 'Confirmed free first: no device answered ARP for them. A click copies the address.',
  'ipscan.pick.unconfirmed': 'Nothing answered and nothing claims them. A click copies the address.',
  'ipscan.pick.copyTitle': 'Copy {ip}',
  'ipscan.pick.copied': '{ip} copied',
  'ipscan.pick.all': 'Copy all free ({count})',
  'ipscan.pick.allCopied': { one: '{count} free address copied', other: '{count} free addresses copied' },
  'ipscan.pick.runs': 'Longest free runs',
  'ipscan.pick.run': '{first} – {last} ({count})',
  'ipscan.pick.none': 'No free address in this range.',

  'ipscan.tab.map': 'Map',
  'ipscan.tab.list': 'List',
  'ipscan.tabsLabel': 'IP Scan results',
  'ipscan.legend': 'Legend',
  'ipscan.confirmedMark': 'confirmed',
  'ipscan.gridLabel': 'Addresses of {label}',
  'ipscan.cellLabel': '{ip}: {state}',
  'ipscan.cellConfirmed': 'free, confirmed',
  'ipscan.detail.close': 'Close the details',
  'ipscan.detail.copy': 'Copy address',
  'ipscan.detail.ping': 'Ping',
  'ipscan.detail.pingValue': '{ms} ms',
  'ipscan.detail.open': 'Open ports',
  'ipscan.detail.refused': 'Closed ports that answered',
  'ipscan.detail.mac': 'MAC address',
  'ipscan.detail.names': 'Reverse DNS',
  'ipscan.detail.template': 'a provider’s template (spells the address out): claims nothing',
  'ipscan.detail.web': 'Web server',
  'ipscan.detail.servers': 'In your server list',
  'ipscan.detail.report': 'Report',
  'ipscan.detail.evidence': 'Why',
  'ipscan.detail.none': '—',
  'ipscan.reason.icmp': 'answered a ping',
  'ipscan.reason.tcp-open': 'a TCP port is open',
  'ipscan.reason.tcp-refused': 'a closed TCP port answered',
  'ipscan.reason.arp': 'in the ARP table',
  'ipscan.reason.ptr': 'has a reverse DNS name',
  'ipscan.reason.inventory': 'in your server list',
  'ipscan.reason.arp-incomplete': 'no device answered ARP',
  'ipscan.reason.unreachable': 'a router said: unreachable',
  'ipscan.filter.label': 'Show',
  'ipscan.filter.all': 'All ({count})',
  'ipscan.filter.taken': 'Used or claimed ({count})',
  'ipscan.filter.used': 'Used ({count})',
  'ipscan.filter.claimed': 'Claimed ({count})',
  'ipscan.filter.free': 'Free ({count})',
  'ipscan.filter.confirmed': 'Free, confirmed ({count})',
  'ipscan.filter.unscanned': 'Not scanned ({count})',
  'ipscan.filter.reserved': 'Reserved ({count})',
  'ipscan.col.ip': 'Address',
  'ipscan.col.state': 'State',
  'ipscan.col.ping': 'Ping',
  'ipscan.col.ports': 'Open ports',
  'ipscan.col.mac': 'MAC',
  'ipscan.col.name': 'Name',
  'ipscan.col.web': 'Web server',
  'ipscan.col.why': 'Why',
  'ipscan.closedPorts': 'closed: {ports}',
  'ipscan.search': 'Filter addresses',
  'ipscan.noMatch': 'No address passes this filter.'
});

registerStrings('tr', {
  'ipscan.range.label': 'Aralık',
  'ipscan.range.placeholder': '10.0.5.0/24 · 10.0.5.10-60 · 192.168.1.20',
  'ipscan.range.hint': 'IPv4 ağları, aralıkları ve adresleri; en fazla {max} adres (bir /20). Özel aralıklar da olur.',
  'ipscan.run': 'Haritayı göster',
  'ipscan.privacy': 'Hiçbir şey gönderilmez: harita açtığınız raporlardan ve sunucu listenizden çizilir. Taramanın kendisi ağınızda, ip_scan.py ile çalışır.',
  'ipscan.exampleTitle': 'Özel bir /24',
  'ipscan.parsed': '{count} adres',
  'ipscan.issue.invalid': 'IPv4 adresi, aralığı ya da ağı değil: {items}',
  'ipscan.issue.v6': 'IPv6 haritalanmaz (tek bir /64 bile 2^64 adres içerir): {items}',
  'ipscan.issue.reversed': 'Aralık başladığı yerden önce bitiyor: {items}',
  'ipscan.issue.too-large': '{count} adres, tek bir haritanın gösterebileceğinden ({max}) fazla.',
  'ipscan.issue.use': '{suggestion} haritasını göster',
  'ipscan.issue.host-bits': '{input}, {cidr} ağı olarak okundu.',
  'ipscan.issue.nothing': 'Bir ağ (10.0.5.0/24), bir aralık (10.0.5.10-60) ya da bir adres yazın.',

  'ipscan.reports.title': 'Tarama sonuçları',
  'ipscan.reports.sub': 'ip_scan.py’nin --json ile yazdığı JSON dosyaları',
  'ipscan.reports.privacy': 'Raporlar burada okunur ve yalnızca bu sekmede tutulur: hiçbir yere yüklenmez ya da kaydedilmez; sayfayı yenilemek, Unut, başka bir çalışma alanı ya da “Tüm yerel verileri sil” onları siler.',
  'ipscan.drop.title': 'ip_scan.py raporlarını buraya bırakın',
  'ipscan.drop.hint': 'ya da seçmek için tıklayın · aynı anda birkaç dosya (her atlama sunucusu için bir tane, ya da geçen hafta ve bugün) · --json ile yazılan dosya',
  'ipscan.paste.summary': 'Bir raporu yapıştırın',
  'ipscan.paste.label': 'Rapor (JSON, --json - çıktısı gibi)',
  'ipscan.paste.read': 'Raporu oku',
  'ipscan.steps.title': 'Tarama tarayıcıda çalışmaz',
  'ipscan.steps.why': 'Bir web sayfası ping atamaz ve iç ağınıza erişemez; bu yüzden tarama o ağdaki bir makinede, bu sitedeki ip_scan.py ile yapılır. Bu sayfa sonra raporunu okur ve haritayı çizer; buradan hiçbir şey gönderilmez.',
  'ipscan.steps.cannot.ping': 'bir adrese ping atmak',
  'ipscan.steps.cannot.ports': 'ağınızdaki bir makinenin TCP portlarını denemek',
  'ipscan.steps.cannot.arp': 'bir adresin boş olduğunun doğrulandığı tek yer olan ARP tablosunu okumak',
  'ipscan.steps.can.map': 'aralığı harita olarak çizer: dolu, kayıtlı, boş',
  'ipscan.steps.can.servers': 'sunucu listenizi üstüne koyar',
  'ipscan.steps.can.pick': 'kullanılabilecek boş adresleri seçer',
  'ipscan.steps.s1': 'ip_scan.py’yi indirin',
  'ipscan.steps.s1Text': 'Tek bir Python 3 dosyası, kurulum yok. Taradığınız ağdaki bir makineye kopyalayın.',
  'ipscan.steps.s2': 'O ağda çalıştırın',
  'ipscan.steps.s2Text': 'Aralıkla aynı ağdaki bir makineden: bir adresin boş olduğu yalnızca orada doğrulanabilir.',
  'ipscan.steps.s3': 'Raporu burada açın',
  'ipscan.steps.s3Text': 'scan.json’u sayfaya bırakın ya da seçin: harita dolar ve hiçbir şey tarayıcıdan çıkmaz.',
  'ipscan.steps.s3Open': 'Raporu aç',
  'ipscan.steps.tips': 'Komut satırından ayrıca',
  'ipscan.steps.summary': '{count} rapor açık · ağınızda ip_scan.py ile tarandı',
  'ipscan.how.download': 'ip_scan.py’yi indir',
  'ipscan.how.free': 'Yalnızca boş adresler, her satırda bir tane:',
  'ipscan.how.check': 'Tek bir adresi vermeden önce (doluysa çıkış kodu 1):',
  'ipscan.loaded': '{count} rapor yüklendi',
  'ipscan.addFiles': 'Dosya ekle',
  'ipscan.forget': 'Tümünü unut',
  'ipscan.forgotten': 'Raporlar unutuldu',
  'ipscan.imported': { one: '{count} rapor okundu: {addresses}', other: '{count} rapor okundu: {addresses}' },
  'ipscan.duplicate': '{name}: aynı rapor zaten açık',
  'ipscan.tooMany': 'Aynı anda en fazla {max} rapor: kalanlar okunmadı.',
  'ipscan.removed': '{name} kaldırıldı',
  'ipscan.remove': '{name} raporunu kaldır',
  'ipscan.errorsTitle': 'Okunmadı',
  'ipscan.error.too-large': '{name}: {max} boyutundan büyük — ip_scan.py’nin bir raporu değil',
  'ipscan.error.not-json': '{name}: JSON değil. ip_scan.py’nin --json ile yazdığı dosyayı seçin (--csv dosyası burada açılmaz).',
  'ipscan.error.not-report': '{name}: ip_scan.py’nin bir raporu değil',
  'ipscan.error.version': '{name}: ip_scan.py’nin bu sayfanın okuyamadığı {detail} sürümüyle yazılmış',
  'ipscan.error.no-results': '{name}: adres içermeyen bir rapor',
  'ipscan.report.meta': 'Tarama: {when} · {addresses} · {targets}',
  'ipscan.report.addresses': { one: '{count} adres', other: '{count} adres' },
  'ipscan.report.noPing': 'ping yok',
  'ipscan.report.noPingTitle': 'Bu tarama ping atamadı (makinesinde izin yok): hiçbir TCP portuna yanıt vermeyen bir makine boş görünür',
  'ipscan.report.noArp': 'ARP yok',
  'ipscan.report.noArpTitle': 'Bu tarama ARP tablosunu okuyamadı: hiçbir adres boş olarak doğrulanmadı',

  'ipscan.emptyLine': 'Bir aralıktaki hangi adreslerin dolu, hangilerinin boş olduğu ve kullanılabilecek olanlar.',
  'ipscan.check.ping': 'Ping',
  'ipscan.check.ports': 'TCP portları',
  'ipscan.check.arp': 'ARP tablosu',
  'ipscan.check.dns': 'Ters DNS',
  'ipscan.check.servers': 'Sunucularınız',

  'ipscan.headTitle': '{range} · {addresses}',
  'ipscan.scannedAt': 'Tarama: {when}',
  'ipscan.noScanMeta': 'henüz taranmadı',
  'ipscan.reportsCount': { one: '{count} rapor', other: '{count} rapor' },
  'ipscan.state.used': 'Dolu',
  'ipscan.state.claimed': 'Kayıtlı',
  'ipscan.state.free': 'Boş',
  'ipscan.state.reserved': 'Ayrılmış',
  'ipscan.state.unscanned': 'Taranmadı',
  'ipscan.stateHelp.used': 'Bir şey yanıt verdi: ping, bir TCP portu ya da ARP tablosu.',
  'ipscan.stateHelp.claimed': 'Hiçbir şey yanıt vermedi, ama sunucu listeniz ya da bir ters DNS adı onu sahipleniyor: kullanmadan önce kontrol edin.',
  'ipscan.stateHelp.free': 'Hiçbir şey yanıt vermedi ve hiçbir şey onu sahiplenmiyor.',
  'ipscan.stateHelp.freeConfirmed': 'Hiçbir şey yanıt vermedi, hiçbir şey sahiplenmiyor ve ARP’ye hiçbir cihaz yanıt vermedi (ya da bir yönlendirici ulaşılamaz dedi): boş.',
  'ipscan.stateHelp.freeUnconfirmed': 'Hiçbir şey yanıt vermedi ve hiçbir şey sahiplenmiyor. Doğrulanmadı: her paketi düşüren bir makine de böyle görünür.',
  'ipscan.stateHelp.reserved': 'Ağın ağ ya da yayın (broadcast) adresi: hiçbir zaman bir sunucunun değil.',
  'ipscan.stateHelp.unscanned': 'Açık raporların hiçbiri onu kapsamıyor.',
  'ipscan.st.used': '{count} dolu',
  'ipscan.st.claimed': '{count} kayıtlı',
  'ipscan.st.free': '{count} boş',
  'ipscan.st.unscanned': '{count} taranmadı',
  'ipscan.st.freeTitle': 'Bunların {confirmed} tanesi doğrulandı: ARP’ye hiçbir cihaz yanıt vermedi',
  'ipscan.csv': 'CSV',
  'ipscan.csvTitle': 'Bu süzgecin gösterdiği adresler, kanıtlarıyla',
  'ipscan.freeTxt': 'Boş adresler (.txt)',
  'ipscan.freeTxtTitle': 'Boş adresler, her satırda bir tane',
  'ipscan.downloaded': '{file} indirildi',
  'ipscan.noneToExport': 'Dışa aktarılacak boş adres yok',

  'ipscan.noScan.title': 'Henüz taranmadı',
  'ipscan.noScan.body': 'Yukarıdaki adımları izleyin: ip_scan.py’yi bu ağda çalıştırın ve raporunu burada açın. O zamana kadar harita yalnızca sunucu listenizin sahiplendiği adresleri işaretler.',
  'ipscan.outside': '{count} rapor adresi bu aralığın dışında.',
  'ipscan.outsideUse': 'Raporların aralığını göster',
  'ipscan.unscannedNote': 'Aralıktaki {count} adres hiçbir raporda yok: onları da tarayın.',
  'ipscan.noConfirm': 'Hiçbir tarama bir adresin boş olduğunu doğrulayamadı (ARP tablosu yok ya da bu ağda çalıştırılmadı): her paketi düşüren bir makine boş görünür. Kullanmadan önce kontrol edin.',
  'ipscan.pick.title': 'Kullanılabilir',
  'ipscan.pick.confirmed': 'Önce doğrulanmış boş adresler: ARP’ye hiçbir cihaz yanıt vermedi. Tıklamak adresi kopyalar.',
  'ipscan.pick.unconfirmed': 'Hiçbir şey yanıt vermedi ve hiçbir şey onları sahiplenmiyor. Tıklamak adresi kopyalar.',
  'ipscan.pick.copyTitle': '{ip} adresini kopyala',
  'ipscan.pick.copied': '{ip} kopyalandı',
  'ipscan.pick.all': 'Tüm boş adresleri kopyala ({count})',
  'ipscan.pick.allCopied': '{count} boş adres kopyalandı',
  'ipscan.pick.runs': 'En uzun boş diziler',
  'ipscan.pick.run': '{first} – {last} ({count})',
  'ipscan.pick.none': 'Bu aralıkta boş adres yok.',

  'ipscan.tab.map': 'Harita',
  'ipscan.tab.list': 'Liste',
  'ipscan.tabsLabel': 'IP Tarama sonuçları',
  'ipscan.legend': 'Açıklama',
  'ipscan.confirmedMark': 'doğrulandı',
  'ipscan.gridLabel': '{label} adresleri',
  'ipscan.cellLabel': '{ip}: {state}',
  'ipscan.cellConfirmed': 'boş, doğrulandı',
  'ipscan.detail.close': 'Ayrıntıları kapat',
  'ipscan.detail.copy': 'Adresi kopyala',
  'ipscan.detail.ping': 'Ping',
  'ipscan.detail.pingValue': '{ms} ms',
  'ipscan.detail.open': 'Açık portlar',
  'ipscan.detail.refused': 'Yanıt veren kapalı portlar',
  'ipscan.detail.mac': 'MAC adresi',
  'ipscan.detail.names': 'Ters DNS',
  'ipscan.detail.template': 'bir sağlayıcının şablonu (adresi açıkça yazıyor): hiçbir şeyi sahiplenmez',
  'ipscan.detail.web': 'Web sunucusu',
  'ipscan.detail.servers': 'Sunucu listenizde',
  'ipscan.detail.report': 'Rapor',
  'ipscan.detail.evidence': 'Neden',
  'ipscan.detail.none': '—',
  'ipscan.reason.icmp': 'ping’e yanıt verdi',
  'ipscan.reason.tcp-open': 'bir TCP portu açık',
  'ipscan.reason.tcp-refused': 'kapalı bir TCP portu yanıt verdi',
  'ipscan.reason.arp': 'ARP tablosunda',
  'ipscan.reason.ptr': 'bir ters DNS adı var',
  'ipscan.reason.inventory': 'sunucu listenizde',
  'ipscan.reason.arp-incomplete': 'ARP’ye hiçbir cihaz yanıt vermedi',
  'ipscan.reason.unreachable': 'bir yönlendirici ulaşılamaz dedi',
  'ipscan.filter.label': 'Göster',
  'ipscan.filter.all': 'Tümü ({count})',
  'ipscan.filter.taken': 'Dolu ya da kayıtlı ({count})',
  'ipscan.filter.used': 'Dolu ({count})',
  'ipscan.filter.claimed': 'Kayıtlı ({count})',
  'ipscan.filter.free': 'Boş ({count})',
  'ipscan.filter.confirmed': 'Boş, doğrulanmış ({count})',
  'ipscan.filter.unscanned': 'Taranmamış ({count})',
  'ipscan.filter.reserved': 'Ayrılmış ({count})',
  'ipscan.col.ip': 'Adres',
  'ipscan.col.state': 'Durum',
  'ipscan.col.ping': 'Ping',
  'ipscan.col.ports': 'Açık portlar',
  'ipscan.col.mac': 'MAC',
  'ipscan.col.name': 'Ad',
  'ipscan.col.web': 'Web sunucusu',
  'ipscan.col.why': 'Neden',
  'ipscan.closedPorts': 'kapalı: {ports}',
  'ipscan.search': 'Adresleri süz',
  'ipscan.noMatch': 'Bu süzgece uyan adres yok.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Read dropped files into the list of open reports: each through lib/ipscan.js readScanReport;
 * the same scan again (its id) is a duplicate; at most {@link IPSCAN_MAX_REPORTS} stay open.
 * @param {import('../lib/ipscan.js').ScanReport[]} open
 * @param {Array<{ name: string, text: string }>} files
 * @returns {{ reports: object[], added: number, errors: Array<{ name: string, error: string, detail?: string }>, duplicates: string[], capped: boolean }}
 */
export function importReports(open, files) {
  const reports = [...(open || [])];
  const errors = [];
  const duplicates = [];
  let added = 0;
  let capped = false;
  for (const file of files || []) {
    const name = String((file && file.name) || '');
    const read = readScanReport(file && file.text, { name });
    if (!read.ok) {
      errors.push({ name, error: read.error, ...(read.detail ? { detail: read.detail } : {}) });
      continue;
    }
    if (reports.some((r) => r.id === read.report.id)) {
      duplicates.push(name);
      continue;
    }
    if (reports.length >= IPSCAN_MAX_REPORTS) {
      capped = true;
      continue;
    }
    reports.push(read.report);
    added += 1;
  }
  return { reports, added, errors, duplicates, capped };
}

/** The Tag variant of a state (docs/DESIGN.md §6.2: free is fine, claimed needs a look, used is a fact). */
export function stateVariant(state) {
  if (state === 'free') return 'ok';
  if (state === 'claimed') return 'warn';
  return 'neutral';
}

/**
 * Empty cells before the first address of a /24 group, so that a column is the same last octet
 * mod 16 in every group (a range that starts at .10 starts in the 11th column).
 * @param {number} firstOctet
 * @returns {number}
 */
export function leadingCells(firstOctet) {
  return ((Number(firstOctet) % GRID_COLUMNS) + GRID_COLUMNS) % GRID_COLUMNS;
}

/**
 * The cell index an arrow key moves to in a grid of `count` cells (16 a row), or null.
 * @param {string} key
 * @param {number} index
 * @param {number} count
 * @param {number} [lead] the empty cells before the first one ({@link leadingCells})
 * @returns {number|null}
 */
export function moveIndex(key, index, count, lead = 0) {
  let next = null;
  if (key === 'ArrowRight') next = index + 1;
  else if (key === 'ArrowLeft') next = index - 1;
  else if (key === 'ArrowDown') next = index + GRID_COLUMNS;
  else if (key === 'ArrowUp') next = index - GRID_COLUMNS;
  else if (key === 'Home') next = Math.floor((index + lead) / GRID_COLUMNS) * GRID_COLUMNS - lead;
  else if (key === 'End') next = Math.floor((index + lead) / GRID_COLUMNS) * GRID_COLUMNS - lead + GRID_COLUMNS - 1;
  if (next === null) return null;
  return Math.min(count - 1, Math.max(0, next));
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Page-session state (module memory only; see the module comment). `text`: the range field;
 * `range`: the range on screen (parsed when Show map was pressed); `selected`: the address whose
 * details are open.
 */
const S = { text: '', range: null, reports: [], errors: [], paste: '', filter: 'all', tab: 'map', selected: null, importOpen: false, stepsOpen: false };
let subscribed = false;
let rerender = null;

function forgetReports() {
  S.reports = [];
  S.errors = [];
  S.paste = '';
  S.importOpen = false;
  S.selected = null;
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
        forgetReports();
        if (key === 'cleared') {
          S.text = '';
          S.range = null;
        }
        if (rerender) rerender();
      } else if (key === 'inventory' && rerender) {
        rerender();
      }
    });
  }
  const fromRoute = typeof ctx.params.range === 'string' ? ctx.params.range.trim() : '';
  if (fromRoute && fromRoute !== S.text) {
    S.text = fromRoute;
    S.range = null;
  }
  if (S.text && !S.range) {
    const parsed = parseScanRange(S.text);
    if (parsed.ok) S.range = parsed;
  }

  let actions = null;
  let status = null;
  let table = null;
  let tabs = null;
  const disposeActions = () => {
    if (actions) actions.dispose();
    actions = null;
  };
  rerender = () => renderResults();
  ctx.onCleanup(() => {
    rerender = null;
    disposeActions();
  });

  /* --- region 2: the range ------------------------------------------------ */
  const rangeField = textarea({
    label: t('ipscan.range.label'),
    value: S.text,
    rows: 2,
    mono: true,
    placeholder: t('ipscan.range.placeholder'),
    hint: t('ipscan.range.hint', { max: formatNumber(IPSCAN_MAX_ADDRESSES) }),
    className: 'ipscan-range',
    attrs: { 'data-role': 'ipscan-range', 'data-shortcut': 'focus' },
    onInput: (v) => {
      S.text = v;
      rangeField.setError(null);
      renderParsed();
      runBar.refresh();
    }
  });
  const parsedEl = h('div', { class: 'ipscan-parsed text-sm', attrs: { 'aria-live': 'polite' } });
  const issuesEl = h('div', { class: 'stack-sm ipscan-issues' });
  const runBar = RunBar({
    label: t('ipscan.run'),
    icon: 'map-pin',
    dataset: { action: 'ipscan-run', shortcut: 'submit' },
    onRun: () => show(),
    hasValue: () => !!rangeField.value.trim()
  });
  const example = ExampleChips({
    className: 'ipscan-examples',
    examples: [{ value: EXAMPLE_RANGE, title: t('ipscan.exampleTitle') }],
    onPick: (value) => {
      rangeField.value = value;
      S.text = value;
      renderParsed();
      runBar.refresh();
    },
    focus: () => runBar.run
  });
  const tool = ToolInput({
    className: 'ipscan-form-card',
    label: t('nav.ipscan'),
    primary: rangeField.el,
    run: runBar,
    notes: [parsedEl, issuesEl],
    extras: [example],
    privacy: PrivacyNote({ text: t('ipscan.privacy'), className: 'ipscan-privacy' })
  });

  const stepsHost = h('div', { class: 'ipscan-steps-host' });
  const reportsHost = h('div', { class: 'ipscan-reports-host' });
  const resultsHost = h('div', { class: 'ipscan-results-host stack', dataset: { shortcutScope: 'results' } });
  container.append(h('div', { class: 'ipscan-view' }, stepsHost, tool.el, reportsHost, resultsHost, runBar.float));

  function issueText(issue) {
    return t(`ipscan.issue.${issue.code}`, { ...issue.params, max: formatNumber(issue.params.max ?? IPSCAN_MAX_ADDRESSES) });
  }

  function renderParsed() {
    const parsed = parseScanRange(rangeField.value);
    clear(parsedEl);
    clear(issuesEl);
    if (parsed.ok) parsedEl.append(Tag(t('ipscan.parsed', { count: parsed.total }), { variant: 'ok', icon: 'check' }));
    for (const issue of parsed.issues) {
      if (issue.code === 'nothing' && !rangeField.value.trim()) continue;
      const suggestion = issue.code === 'too-large' && issue.params.suggestion ? issue.params.suggestion : null;
      const alert = Alert({
        variant: issue.severity === 'error' ? 'error' : issue.severity === 'warn' ? 'warn' : 'info',
        compact: true,
        message: issueText(issue),
        actions: suggestion ? [Button({
          label: t('ipscan.issue.use', { suggestion }), size: 'sm', dataset: { action: 'ipscan-use-suggestion' },
          onClick: () => setRange(suggestion, { focus: true })
        })] : null
      });
      alert.dataset.issue = issue.code;
      issuesEl.append(alert);
    }
    // step 2's command follows the range typed
    renderSteps();
    return parsed;
  }

  function setRange(text, { focus = false, draw = true } = {}) {
    rangeField.value = text;
    S.text = text;
    renderParsed();
    runBar.refresh();
    if (draw) show({ focusResult: false });
    if (focus) rangeField.focus();
  }

  /** Show map: the range on screen, at once (nothing is sent); the route carries the range. */
  function show({ focusResult = true } = {}) {
    const parsed = renderParsed();
    if (!parsed.ok) {
      const first = parsed.issues.find((i) => i.severity === 'error');
      rangeField.setError(first ? issueText(first) : t('ipscan.issue.nothing'));
      rangeField.focus();
      return;
    }
    S.range = parsed;
    S.selected = null;
    ctx.setParams({ range: parsed.blocks.map((b) => b.label).join(' ') });
    ctx.runStarted(null);
    renderResults();
    runBar.setRerun(true);
    announce(t('ipscan.headTitle', { range: parsed.label, addresses: t('ipscan.parsed', { count: parsed.total }) }));
    if (focusResult) {
      const title = resultsHost.querySelector('.ipscan-head .result-title');
      if (title) title.focus({ preventScroll: true });
    }
  }

  /* --- the reports' file input -------------------------------------------- */
  function importFiles(files, { pasted = null } = {}) {
    const result = importReports(S.reports, files);
    S.reports = result.reports;
    S.errors = result.errors;
    S.paste = pasted !== null && !result.added ? pasted : '';
    for (const name of result.duplicates) toast(t('ipscan.duplicate', { name }), { type: 'info' });
    if (result.capped) toast(t('ipscan.tooMany', { max: IPSCAN_MAX_REPORTS }), { type: 'warn' });
    if (result.added) {
      const addresses = new Set(S.reports.flatMap((r) => [...r.rows.keys()])).size;
      const msg = t('ipscan.imported', { count: result.added, addresses: t('ipscan.report.addresses', { count: addresses }) });
      announce(msg);
      toast(msg, { type: 'success', timeout: 2500 });
      // No range typed yet: the reports' own targets become the range.
      if (!S.range) {
        const text = reportsRange(S.reports);
        if (text && parseScanRange(text).ok) {
          rangeField.value = text;
          S.text = text;
          renderParsed();
          runBar.refresh();
          S.range = parseScanRange(text);
          ctx.setParams({ range: S.range.blocks.map((b) => b.label).join(' ') });
          runBar.setRerun(true);
        }
      }
    }
    S.importOpen = !!(S.paste || S.errors.length);
    renderReports();
    renderResults();
    const target = result.added && S.range ? resultsHost.querySelector('.ipscan-head .result-title')
      : pasted !== null ? reportsHost.querySelector('[data-role="ipscan-paste"]') : reportsHost.querySelector('.ipscan-drop');
    if (target) target.focus({ preventScroll: true });
  }

  function removeReport(report) {
    S.reports = S.reports.filter((r) => r !== report);
    toast(t('ipscan.removed', { name: report.name }), { type: 'info' });
    renderReports();
    renderResults();
    const target = reportsHost.querySelector('.ipscan-report .btn-icon') || reportsHost.querySelector('.filedrop');
    if (target) target.focus({ preventScroll: true });
  }

  function forget() {
    forgetReports();
    toast(t('ipscan.forgotten'), { type: 'info' });
    renderReports();
    renderResults();
    const target = reportsHost.querySelector('.filedrop');
    if (target) target.focus({ preventScroll: true });
  }

  /** The drop zone's file picker (step 3's button). */
  let openPicker = null;

  /**
   * "The scan does not run in the browser" (ui/cli-steps.js): the steps — download, run on that
   * network (the command for the range typed), open the report here — in full while no report is
   * open, folded into one line once one is (unfolded on a click; kept over a redraw).
   */
  function renderSteps() {
    clear(stepsHost);
    const target = S.range || parseScanRange(rangeField.value);
    const ok = target && target.ok;
    const label = ok ? target.blocks.map((b) => b.label).join(' ') : EXAMPLE_RANGE;
    const one = ok ? target.addresses.find((ip, i) => i > 0) || target.addresses[0] : '10.0.5.37';
    // more commands, folded: the steps stay one screen high
    const tips = Disclosure({
      summary: t('ipscan.steps.tips'),
      className: 'ipscan-steps-tips',
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm muted' }, t('ipscan.how.free')),
        CodeBlock(`python3 ${CLI_FILE} ${label} --free`, { label: 'CLI', wrap: true }),
        h('p', { class: 'text-sm muted' }, t('ipscan.how.check')),
        CodeBlock(`python3 ${CLI_FILE} ${one} --expect-free`, { label: 'CLI', wrap: true }))
    });
    stepsHost.append(CliSteps({
      className: 'ipscan-steps',
      compact: S.reports.length > 0,
      open: S.stepsOpen,
      onToggle: (open) => { S.stepsOpen = open; },
      summary: t('ipscan.steps.summary', { count: S.reports.length }),
      title: t('ipscan.steps.title'),
      why: t('ipscan.steps.why'),
      cannot: ['ping', 'ports', 'arp'].map((k) => t(`ipscan.steps.cannot.${k}`)),
      can: ['map', 'servers', 'pick'].map((k) => t(`ipscan.steps.can.${k}`)),
      steps: [
        { place: 'browser', icon: 'download', title: t('ipscan.steps.s1'), text: t('ipscan.steps.s1Text'),
          action: ButtonLink({ href: CLI_PATH, label: t('ipscan.how.download'), icon: 'download', variant: 'secondary', size: 'sm', download: CLI_FILE }) },
        { place: 'machine', icon: 'terminal', title: t('ipscan.steps.s2'), text: t('ipscan.steps.s2Text'), code: cliCommand(ok ? target : null) },
        { place: 'browser', icon: 'upload', title: t('ipscan.steps.s3'), text: t('ipscan.steps.s3Text'),
          action: Button({ label: t('ipscan.steps.s3Open'), icon: 'upload', size: 'sm', dataset: { action: 'ipscan-open-report' }, onClick: () => { if (openPicker) openPicker(); } }) }
      ],
      footer: tips
    }));
  }

  function renderReports() {
    renderSteps();
    clear(reportsHost);
    const drop = FileDrop({
      accept: '.json',
      multiple: true,
      compact: S.reports.length > 0,
      icon: 'upload',
      title: t('ipscan.drop.title'),
      hint: t('ipscan.drop.hint'),
      maxBytes: IPSCAN_MAX_BYTES,
      className: 'ipscan-drop',
      paste: true,
      onFiles: (files) => importFiles(files)
    });
    openPicker = () => drop.open();
    const errors = S.errors.length ? Alert({
      variant: 'warn',
      title: t('ipscan.errorsTitle'),
      children: h('ul', { class: 'ipscan-errors' }, S.errors.map((e) => h('li', null, t(`ipscan.error.${e.error}`, {
        name: e.name, detail: e.detail || '?', max: `${Math.round(IPSCAN_MAX_BYTES / 1048576)} MB`
      }))))
    }) : null;
    const list = S.reports.length ? h('ul', { class: 'ipscan-reports' }, S.reports.map((report) => reportItem(report))) : null;
    const pasteArea = textarea({ label: t('ipscan.paste.label'), rows: 6, mono: true, value: S.paste, attrs: { 'data-role': 'ipscan-paste' } });
    const pasteBtn = Button({
      label: t('ipscan.paste.read'),
      icon: 'arrow-down',
      variant: 'primary',
      size: 'sm',
      dataset: { action: 'ipscan-paste-read', shortcut: 'submit' },
      onClick: () => {
        const text = pasteArea.value;
        if (text.trim()) importFiles([{ name: t('file.pasted'), text }], { pasted: text });
      }
    });
    const paste = Disclosure({
      summary: t('ipscan.paste.summary'),
      className: 'ipscan-paste',
      open: !!S.paste,
      children: h('div', { class: 'stack-sm', dataset: { shortcutScope: 'ipscan-paste' } }, pasteArea.el, h('div', { class: 'cluster' }, pasteBtn))
    });
    const privacy = PrivacyNote({ text: t('ipscan.reports.privacy'), className: 'ipscan-reports-privacy' });
    if (!S.reports.length) {
      reportsHost.append(FileInput({
        title: t('ipscan.reports.title'),
        subtitle: t('ipscan.reports.sub'),
        icon: 'file-text',
        className: 'ipscan-import',
        label: t('ipscan.reports.title'),
        body: [drop.el, errors, paste],
        privacy
      }).el);
      return;
    }
    const input = FileInput({
      loaded: true,
      className: 'ipscan-import',
      label: t('ipscan.reports.title'),
      more: t('ipscan.loaded', { count: S.reports.length }),
      moreClass: 'ipscan-import-more',
      moreOpen: S.importOpen,
      body: [list, drop.el, errors, paste],
      actions: [
        Button({ label: t('ipscan.addFiles'), icon: 'plus', size: 'sm', dataset: { action: 'ipscan-add' }, onClick: () => drop.open() }),
        Button({ label: t('ipscan.forget'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'ipscan-forget' }, onClick: forget })
      ],
      privacy
    });
    input.more.addEventListener('toggle', () => { S.importOpen = input.more.open; });
    reportsHost.append(input.el);
  }

  function reportItem(report) {
    const noPing = report.methods.icmp === 'off' || report.methods.icmp === 'unavailable';
    const noArp = report.methods.arp === 'off' || report.methods.arp === 'unavailable';
    return h('li', { class: 'ipscan-report', dataset: { report: report.name } },
      h('div', { class: 'ipscan-report-text' },
        h('span', { class: 'ipscan-report-name mono' }, report.name || '—'),
        h('span', { class: 'ipscan-report-meta muted text-sm' }, t('ipscan.report.meta', {
          when: report.finishedAt ? formatDateTime(report.finishedAt, { utc: true }) : '—',
          addresses: t('ipscan.report.addresses', { count: report.rows.size }),
          targets: report.targets.slice(0, 3).join(', ') + (report.targets.length > 3 ? ' …' : '')
        }))),
      h('div', { class: 'ipscan-report-badges cluster' },
        noPing ? Tag(t('ipscan.report.noPing'), { variant: 'warn', title: t('ipscan.report.noPingTitle') }) : null,
        noArp ? Tag(t('ipscan.report.noArp'), { variant: 'neutral', title: t('ipscan.report.noArpTitle') }) : null,
        IconButton({ icon: 'x', label: t('ipscan.remove', { name: report.name }), size: 'sm', onClick: () => removeReport(report) })));
  }

  /* --- the result ----------------------------------------------------------- */
  /** The map on screen (recomputed on every draw: the inventory or the reports may have changed). */
  let map = null;

  function setFilter(filter) {
    S.filter = IPSCAN_FILTERS.includes(filter) ? filter : 'all';
    if (status) status.setPressed(STATUS_FILTERS.includes(S.filter) ? S.filter : null);
    if (table) table.setFilter((row) => ipscanMatches(row, S.filter));
    const sel = resultsHost.querySelector('.ipscan-filter select');
    if (sel && sel.value !== S.filter) sel.value = S.filter;
    for (const cell of resultsHost.querySelectorAll('.ipscan-cell')) {
      const row = map && map.rows.find((r) => r.ip === cell.dataset.ip);
      cell.classList.toggle('is-dimmed', !!row && !ipscanMatches(row, S.filter));
    }
  }

  function renderResults() {
    disposeActions();
    status = null;
    table = null;
    tabs = null;
    clear(resultsHost);
    if (!S.range || !S.range.ok) {
      map = null;
      resultsHost.append(h('div', { class: 'ipscan-empty' }, EmptyState({
        icon: 'map-pin',
        message: t('ipscan.emptyLine'),
        checks: ['ping', 'ports', 'arp', 'dns', 'servers'].map((c) => t(`ipscan.check.${c}`))
      })));
      return;
    }
    const index = typeof ctx.getInventoryIndex === 'function' ? ctx.getInventoryIndex() : null;
    map = addressMap({ range: S.range, reports: S.reports, index });
    resultsHost.append(resultHead(map).el);
    for (const note of notesOf(map)) resultsHost.append(note);
    if (S.reports.length) resultsHost.append(pickCard(map));
    resultsHost.append(resultTabs(map));
    setFilter(S.filter);
  }

  function resultHead(m) {
    const head = ResultHeader({ className: 'ipscan-head' });
    head.setState('done');
    head.set('title', ResultTitle({ text: t('ipscan.headTitle', { range: S.range.label, addresses: t('ipscan.parsed', { count: m.counts.total }) }) }));
    const times = S.reports.map((r) => r.finishedAt).filter((d) => d instanceof Date);
    const newest = times.length ? new Date(Math.max(...times.map((d) => d.getTime()))) : null;
    head.set('meta', [
      newest ? h('span', { class: 'ipscan-scanned', title: newest.toISOString() }, t('ipscan.scannedAt', { when: formatDateTime(newest, { utc: true }) }))
        : h('span', { class: 'ipscan-scanned' }, t('ipscan.noScanMeta')),
      S.reports.length ? h('span', null, t('ipscan.reportsCount', { count: S.reports.length })) : null
    ]);
    const severity = { used: 'neutral', claimed: 'warn', free: 'ok', unscanned: 'neutral' };
    status = StatusSummary({
      className: 'ipscan-status',
      pressed: STATUS_FILTERS.includes(S.filter) ? S.filter : null,
      items: STATUS_FILTERS.filter((k) => m.counts[k] > 0).map((key) => ({
        key,
        severity: severity[key],
        count: m.counts[key],
        text: t(`ipscan.st.${key}`, { count: m.counts[key] }),
        title: key === 'free' && m.counts.freeConfirmed ? t('ipscan.st.freeTitle', { confirmed: m.counts.freeConfirmed }) : t(`ipscan.stateHelp.${key}`),
        filter: true,
        onPress: (k) => setFilter(S.filter === k ? 'all' : k)
      }))
    });
    head.set('status', status.el);
    actions = ResultActions({
      summary: SummaryButton({
        kind: 'ipscan',
        plainLabel: t('result.plainTitle'),
        inventory: 'count',
        facts: () => (map ? ipscanSummaryFacts({ range: S.range, map, reports: S.reports }) : null),
        url: () => ctx.shareUrl(permalinkParams('ipscan', { range: S.range.blocks.map((b) => b.label).join(' ') }))
      }),
      exports: [
        { label: t('ipscan.csv'), title: t('ipscan.csvTitle'), icon: 'download', dataset: { export: 'csv' }, onSelect: () => exportCsv() },
        { label: t('ipscan.freeTxt'), title: t('ipscan.freeTxtTitle'), icon: 'download', dataset: { export: 'free' }, onSelect: () => exportFree() }
      ],
      print: true,
      link: () => ctx.shareUrl({ range: S.range.blocks.map((b) => b.label).join(' ') })
    });
    head.set('actions', actions.el);
    return head;
  }

  function exportCsv() {
    const rows = table ? table.getVisibleRows() : map.rows.filter((r) => ipscanMatches(r, S.filter));
    const file = downloadText(timestampedName('ipscan', 'csv'),
      toCsv(ipscanCsvRows(rows), IPSCAN_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
    toast(t('ipscan.downloaded', { file }), { type: 'success', timeout: 2500 });
  }

  function exportFree() {
    const text = freeListText(map.rows);
    if (!text) {
      toast(t('ipscan.noneToExport'), { type: 'info' });
      return;
    }
    const file = downloadText(timestampedName('free-addresses', 'txt'), text, 'text/plain;charset=utf-8');
    toast(t('ipscan.downloaded', { file }), { type: 'success', timeout: 2500 });
  }

  /** An Alert with the view's hook class (Alert takes none). */
  function note(cls, opts) {
    const el = Alert(opts);
    el.classList.add(cls);
    return el;
  }

  function notesOf(m) {
    const out = [];
    if (!S.reports.length) {
      out.push(note('ipscan-noscan', {
        variant: 'info',
        title: t('ipscan.noScan.title'),
        message: t('ipscan.noScan.body')
      }));
      return out;
    }
    if (m.counts.unscanned) out.push(note('ipscan-unscanned-note', { variant: 'warn', compact: true, message: t('ipscan.unscannedNote', { count: m.counts.unscanned }) }));
    if (m.outside) {
      out.push(note('ipscan-outside-note', {
        variant: 'info', compact: true, message: t('ipscan.outside', { count: m.outside }),
        actions: [Button({ label: t('ipscan.outsideUse'), size: 'sm', dataset: { action: 'ipscan-reports-range' }, onClick: () => setRange(reportsRange(S.reports)) })]
      }));
    }
    if (m.counts.free && !m.counts.freeConfirmed) out.push(note('ipscan-noconfirm', { variant: 'warn', compact: true, message: t('ipscan.noConfirm') }));
    return out;
  }

  /** The free addresses to use: one-click copies, confirmed first; Copy all; the longest runs. */
  function pickCard(m) {
    const picks = suggestFree(m.rows, { count: SUGGEST_COUNT });
    const card = h('section', { class: 'card ipscan-pick', attrs: { 'aria-labelledby': 'ipscan-pick-title' } },
      h('h3', { class: 'ipscan-pick-title', id: 'ipscan-pick-title' }, Icon('check-circle', { size: 16 }), t('ipscan.pick.title')));
    if (!picks.length) {
      card.append(h('p', { class: 'muted text-sm' }, t('ipscan.pick.none')));
      return card;
    }
    card.append(h('p', { class: 'muted text-sm' }, t(m.counts.freeConfirmed ? 'ipscan.pick.confirmed' : 'ipscan.pick.unconfirmed')));
    card.append(h('div', { class: 'ipscan-picks cluster' },
      picks.map((row) => CopyButton(row.ip, {
        label: row.ip,
        icon: row.confirmed ? 'check' : 'copy',
        variant: 'secondary',
        size: 'sm',
        title: t('ipscan.pick.copyTitle', { ip: row.ip }),
        toastOnCopy: t('ipscan.pick.copied', { ip: row.ip }),
        className: ['ipscan-pick-ip', 'mono', row.confirmed ? 'is-confirmed' : ''].join(' ')
      })),
      CopyButton(() => freeListText(m.rows), {
        label: t('ipscan.pick.all', { count: formatNumber(m.counts.free) }),
        variant: 'ghost',
        size: 'sm',
        toastOnCopy: t('ipscan.pick.allCopied', { count: m.counts.free }),
        className: 'ipscan-pick-all'
      })));
    const runs = freeRuns(m.rows, { min: 3, max: 4 });
    if (runs.length) {
      card.append(h('p', { class: 'ipscan-runs text-sm' }, h('span', { class: 'muted' }, `${t('ipscan.pick.runs')}: `),
        runs.map((r, i) => [i ? ', ' : '', h('span', { class: 'mono' }, t('ipscan.pick.run', { first: r.first, last: r.last, count: formatNumber(r.length) }))])));
    }
    return card;
  }

  function resultTabs(m) {
    tabs = Tabs([
      { id: 'map', label: t('ipscan.tab.map'), content: () => mapPanel(m) },
      { id: 'list', label: t('ipscan.tab.list'), badge: m.counts.total, content: () => listPanel(m) }
    ], {
      selected: S.tab,
      label: t('ipscan.tabsLabel'),
      className: 'ipscan-tabs',
      onChange: (tab) => {
        S.tab = tab;
        setFilter(S.filter);
      }
    });
    return tabs.el;
  }

  /* --- Map -------------------------------------------------------------------- */
  function stateText(row) {
    return row.state === 'free' && row.confirmed ? t('ipscan.cellConfirmed') : t(`ipscan.state.${row.state}`).toLowerCase();
  }

  function mapPanel(m) {
    const legend = h('ul', { class: 'ipscan-legend', attrs: { 'aria-label': t('ipscan.legend') } },
      IPSCAN_STATES.filter((s) => m.counts[s]).map((s) => h('li', { title: t(`ipscan.stateHelp.${s}`) },
        h('span', { class: ['ipscan-swatch', `is-${s}`], attrs: { 'aria-hidden': 'true' } }),
        `${t(`ipscan.state.${s}`)} `, h('span', { class: 'muted' }, formatNumber(m.counts[s])))),
      m.counts.freeConfirmed ? h('li', { title: t('ipscan.stateHelp.freeConfirmed') },
        h('span', { class: 'ipscan-swatch is-free is-confirmed', attrs: { 'aria-hidden': 'true' } }),
        `${t('ipscan.confirmedMark')} `, h('span', { class: 'muted' }, formatNumber(m.counts.freeConfirmed))) : null);
    return h('div', { class: 'ipscan-map stack' }, legend, m.groups.map((g) => groupEl(g)));
  }

  function groupEl(group) {
    const n = (state) => group.rows.filter((r) => r.state === state).length;
    const lead = leadingCells(group.rows[0].octet);
    const detail = h('div', { class: 'ipscan-detail-host' });
    const cells = group.rows.map((row, i) => {
      const cell = h('button', {
        type: 'button',
        class: ['ipscan-cell', `is-${row.state}`, { 'is-confirmed': row.confirmed, 'is-selected': row.ip === S.selected }],
        dataset: { ip: row.ip, state: row.state },
        title: `${row.ip} · ${stateText(row)}${row.names.length ? ` · ${row.names[0]}` : row.servers.length ? ` · ${row.servers[0].name}` : ''}`,
        attrs: {
          tabindex: (S.selected ? row.ip === S.selected : i === 0) ? '0' : '-1',
          'aria-label': t('ipscan.cellLabel', { ip: row.ip, state: stateText(row) }),
          'aria-pressed': String(row.ip === S.selected)
        },
        on: {
          click: () => pick(row, cell),
          keydown: (event) => {
            const next = moveIndex(event.key, i, cells.length, lead);
            if (next === null || next === i) return;
            event.preventDefault();
            cell.tabIndex = -1;
            cells[next].tabIndex = 0;
            cells[next].focus();
          }
        }
      }, String(row.octet));
      return cell;
    });
    function pick(row, cell) {
      const same = S.selected === row.ip;
      S.selected = same ? null : row.ip;
      for (const c of resultsHost.querySelectorAll('.ipscan-cell.is-selected')) {
        c.classList.remove('is-selected');
        c.setAttribute('aria-pressed', 'false');
      }
      for (const host of resultsHost.querySelectorAll('.ipscan-detail-host')) clear(host);
      if (same) return;
      cell.classList.add('is-selected');
      cell.setAttribute('aria-pressed', 'true');
      detail.append(detailEl(row, () => {
        S.selected = null;
        cell.classList.remove('is-selected');
        cell.setAttribute('aria-pressed', 'false');
        clear(detail);
        cell.focus();
      }));
    }
    const grid = h('div', { class: 'ipscan-grid', attrs: { role: 'group', 'aria-label': t('ipscan.gridLabel', { label: group.label }) } },
      Array.from({ length: lead }, () => h('span', { class: 'ipscan-cell-pad', attrs: { 'aria-hidden': 'true' } })),
      cells);
    const selectedRow = group.rows.find((r) => r.ip === S.selected);
    if (selectedRow) detail.append(detailEl(selectedRow, () => { S.selected = null; renderResults(); }));
    return h('section', { class: 'ipscan-group', dataset: { group: group.label } },
      h('h3', { class: 'ipscan-group-title text-sm' }, h('span', { class: 'mono' }, group.label), h('span', { class: 'muted' },
        ['used', 'claimed', 'free'].filter((st) => st !== 'claimed' || n(st)).map((st) => ` · ${t(`ipscan.st.${st}`, { count: n(st) })}`).join(''))),
      grid, detail);
  }

  function detailEl(row, onClose) {
    const scan = row.scan;
    const dash = t('ipscan.detail.none');
    const item = (label, value, cls = '') => h('div', { class: ['ipscan-detail-item', cls] }, h('dt', null, label), h('dd', null, value));
    const helpKey = row.state === 'free' ? (row.confirmed ? 'freeConfirmed' : 'freeUnconfirmed') : row.state;
    const names = scan && scan.ptr.length
      ? [h('span', { class: 'mono' }, scan.ptr.join(', ')), scan.ptrTemplated ? h('span', { class: 'muted text-xs' }, ` (${t('ipscan.detail.template')})`) : null]
      : dash;
    const web = scan && Object.keys(scan.web).length ? Object.entries(scan.web).map(([p, s], i) => [i ? ' · ' : '', h('span', { class: 'mono' }, `${p}: ${s}`)]) : dash;
    return h('div', { class: 'ipscan-detail card', dataset: { ip: row.ip }, attrs: { role: 'region', 'aria-label': row.ip } },
      h('div', { class: 'ipscan-detail-head' },
        h('span', { class: 'ipscan-detail-ip mono' }, row.ip),
        Tag(t(`ipscan.state.${row.state}`), { variant: stateVariant(row.state), icon: row.confirmed ? 'check' : null }),
        h('span', { class: 'ipscan-detail-actions cluster' },
          CopyButton(row.ip, { label: t('ipscan.detail.copy'), size: 'sm', toastOnCopy: t('ipscan.pick.copied', { ip: row.ip }) }),
          IconButton({ icon: 'x', label: t('ipscan.detail.close'), size: 'sm', onClick: onClose }))),
      h('p', { class: 'text-sm muted' }, t(`ipscan.stateHelp.${helpKey}`)),
      h('dl', { class: 'ipscan-detail-list' },
        row.reasons.length ? item(t('ipscan.detail.evidence'), h('span', { class: 'cluster' }, row.reasons.map((r) => Tag(t(`ipscan.reason.${r}`), { variant: 'neutral' })))) : null,
        row.servers.length ? item(t('ipscan.detail.servers'), h('span', { class: 'cluster' }, row.servers.map((s) => h('a', { href: ctx.href('inventory', {}), class: 'mono' }, s.name)))) : null,
        scan ? item(t('ipscan.detail.ping'), scan.rttMs !== null ? t('ipscan.detail.pingValue', { ms: formatNumber(scan.rttMs) }) : dash) : null,
        scan ? item(t('ipscan.detail.open'), scan.open.length ? h('span', { class: 'mono' }, scan.open.join(', ')) : dash) : null,
        scan && scan.refused.length ? item(t('ipscan.detail.refused'), h('span', { class: 'mono' }, scan.refused.join(', '))) : null,
        scan ? item(t('ipscan.detail.mac'), scan.mac ? h('span', { class: 'mono' }, scan.mac) : dash) : null,
        scan ? item(t('ipscan.detail.names'), names) : null,
        scan && Object.keys(scan.web).length ? item(t('ipscan.detail.web'), web) : null,
        scan && S.reports.length > 1 && row.report !== null ? item(t('ipscan.detail.report'), h('span', { class: 'mono' }, S.reports[row.report].name)) : null));
  }

  /* --- List ------------------------------------------------------------------- */
  function listPanel(m) {
    const counts = Object.fromEntries(IPSCAN_FILTERS.map((f) => [f, m.rows.filter((r) => ipscanMatches(r, f)).length]));
    const filterSel = select({
      label: t('ipscan.filter.label'),
      value: S.filter,
      options: IPSCAN_FILTERS.filter((f) => f === 'all' || counts[f] > 0 || f === S.filter)
        .map((f) => ({ value: f, label: t(`ipscan.filter.${f}`, { count: formatNumber(counts[f]) }) })),
      className: 'ipscan-filter',
      onChange: (v) => setFilter(v)
    });
    table = DataTable({
      className: 'ipscan-table dt-cards',
      rowKey: (r) => r.ip,
      rows: m.rows,
      pageSize: 256,
      dense: true,
      cellLabels: true,
      search: { label: t('ipscan.search'), placeholder: t('ipscan.search') },
      filter: (r) => ipscanMatches(r, S.filter),
      noMatch: t('ipscan.noMatch'),
      toolbar: filterSel.el,
      export: false,
      rowClass: (r) => (r.state === 'claimed' ? 'is-claimed' : null),
      columns: [
        { key: 'ip', label: t('ipscan.col.ip'), sortable: true, sortValue: (r) => ipSortValue(r.ip), exportValue: (r) => r.ip, mono: true },
        {
          key: 'state', label: t('ipscan.col.state'), sortable: true,
          sortValue: (r) => IPSCAN_STATES.indexOf(r.state) * 2 + (r.confirmed ? 0 : 1),
          searchValue: (r) => `${t(`ipscan.state.${r.state}`)} ${r.state}`,
          render: (r) => Tag(t(`ipscan.state.${r.state}`), { variant: stateVariant(r.state), icon: r.confirmed ? 'check' : null, title: r.confirmed ? t('ipscan.cellConfirmed') : null })
        },
        { key: 'ping', label: t('ipscan.col.ping'), sortable: true, align: 'end', sortValue: (r) => (r.scan ? r.scan.rttMs : null), render: (r) => (r.scan && r.scan.rttMs !== null ? `${formatNumber(r.scan.rttMs)} ms` : '') },
        {
          key: 'ports', label: t('ipscan.col.ports'), mono: true,
          searchValue: (r) => (r.scan ? r.scan.open.join(' ') : ''),
          render: (r) => (!r.scan ? '' : r.scan.open.length ? r.scan.open.join(', ')
            : r.scan.refused.length ? h('span', { class: 'muted' }, t('ipscan.closedPorts', { ports: r.scan.refused.slice(0, 3).join(', ') + (r.scan.refused.length > 3 ? ' …' : '') })) : '')
        },
        { key: 'mac', label: t('ipscan.col.mac'), mono: true, searchValue: (r) => (r.scan && r.scan.mac) || '', render: (r) => (r.scan && r.scan.mac) || '' },
        {
          key: 'name', label: t('ipscan.col.name'), wrap: true,
          searchValue: (r) => [...(r.scan ? r.scan.ptr : []), ...r.servers.map((s) => s.name)].join(' '),
          render: (r) => {
            const parts = [];
            if (r.servers.length) parts.push(h('span', { class: 'ipscan-servers' }, Icon('server', { size: 12 }), ' ', r.servers.map((s) => s.name).join(', ')));
            if (r.scan && r.scan.ptr.length) parts.push(h('span', { class: ['mono', { muted: r.scan.ptrTemplated }] }, r.scan.ptr.join(', ')));
            return parts.length ? h('span', { class: 'ipscan-name-cell' }, parts) : '';
          }
        },
        { key: 'web', label: t('ipscan.col.web'), wrap: true, searchValue: (r) => (r.scan ? Object.values(r.scan.web).join(' ') : ''), render: (r) => (r.scan ? Object.values(r.scan.web).join(' · ') : '') },
        { key: 'why', label: t('ipscan.col.why'), wrap: true, searchValue: (r) => r.reasons.map((x) => t(`ipscan.reason.${x}`)).join(' '), render: (r) => h('span', { class: 'muted text-xs' }, r.reasons.map((x) => t(`ipscan.reason.${x}`)).join(', ')) }
      ]
    });
    return h('div', { class: 'ipscan-list stack-sm' }, table.el);
  }

  renderParsed();
  renderReports();
  renderResults();
  if (S.range) runBar.setRerun(true);
}
