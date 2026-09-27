/**
 * views/ptr.js — "Reverse DNS": the reverse DNS (PTR) of every address of an IPv4 network up to
 * a /22, a range, a list of addresses or the prefixes an AS announces, with forward
 * confirmation (FCrDNS): does each PTR name resolve back to its address?
 *
 * - Input: lib/ptrsweep.parseSweepTarget (the cap, IPv6 exact addresses only, private addresses
 *   left out). An AS number lists its announced prefixes first (one RIPEstat request, on the
 *   click), and the user ticks the ones to sweep.
 * - The sweep (lib/ptrsweep.runPtrSweep) goes through the shared DohClient, whose limiter keeps
 *   the HTTP requests at the Settings value; rows stream in, Stop ends it. Like Bulk Resolve,
 *   the job belongs to this module: it keeps running while another tool is open and is shown
 *   again on return.
 * - Results: names under the focus domain first and highlighted; provider-generated names
 *   (the address written into the name, pool words) collapsed into one row per template;
 *   the operator (netinfo ranges, or a PTR name under a provider's domain) and the matching
 *   server of the inventory. CSV / JSON and names.txt.
 * - Hand-offs, never silent: "Add names to a scan" opens Subdomains with the names
 *   (state.session.namesScanIntent, exact mode preset, the user presses Scan); "Add to Servers"
 *   writes the forward-confirmed hosts into the Servers editor in the list's own format
 *   (state.session.inventoryDraft, the user reviews and saves), or, for a format it does not
 *   write, shows them to copy and leaves the editor alone.
 *
 * Shareable: `#/ptr?target=192.0.2.0/24&focus=example.com` pre-fills the form and waits for a
 * click (a link never starts a thousand DNS queries by itself).
 */

import { h, clear, debounce, uid } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, CopyButton, DataTable, EmptyState, ErrorBanner, Icon, KeyValueList, KindBadge,
  Modal, ProgressBar, StatCard, TruncatedList, announce, checkbox, ipSortValue, normalizeSearch, select, textInput, textarea, toast
} from '../ui/components.js';
import {
  t, registerStrings, formatNumber, formatDuration, formatDateTime
} from '../i18n.js';
import {
  SWEEP_MAX_ADDRESSES, SWEEP_MAX_CONCURRENCY, SWEEP_FILTERS, SWEEP_CSV_COLUMNS, FCRDNS_STATUSES, parseSweepTarget, announcedPrefixes,
  prefixSelection, runPtrSweep, sweepRows, sweepRowMatches, sweepRowResults, sweepSummary, sweepExportRows, sweepExportJson,
  sweepNames, inventoryAdditions, inventoryDraft, scanHandoff, isFocusName
} from '../lib/ptrsweep.js';
import { normalizeHostname } from '../lib/domain.js';
import { parseInventory } from '../lib/inventory.js';
import { toCsv, toJson } from '../lib/export.js';
import { getResolver } from '../lib/resolvers.js';
import { errorKind, splitList } from '../lib/util.js';
import { downloadText, timestampedName } from '../ui/download.js';

/** Route id (`#/ptr`). */
export const id = 'ptr';
/** i18n key of the page title. */
export const titleKey = 'nav.ptr';
/** Icon name (ui/components.js Icon). */
export const icon = 'swap';

/** The target text goes into a shared link only up to this length. */
export const LINK_MAX_CHARS = 400;
/** The example the form offers: RIPE NCC's AS, one RIPEstat request that lists its prefixes. */
const EXAMPLE_ASN = 'AS3333';
/** The server-list formats (inventory.inventoryFormat) lib/ptrsweep.inventoryDraft may not write, by name. */
const INVENTORY_FORMAT_NAMES = Object.freeze({ json: 'JSON', yaml: 'YAML', csv: 'CSV' });

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'ptr.target.label': 'Network, range, addresses or AS number',
  'ptr.target.placeholder': '192.0.2.0/24\n198.51.100.10-198.51.100.40\n2001:db8::25\nAS64496',
  'ptr.target.hint': 'An IPv4 network up to /22 ({max} addresses), a range, single IPv4 / IPv6 addresses, or an AS number to pick from its announced prefixes. IPv6: exact addresses only.',
  'ptr.focus.label': 'Your domain',
  'ptr.focus.placeholder': 'example.com',
  'ptr.focus.hint': 'Names under it are highlighted, listed first and never folded into a pattern.',
  'ptr.focus.invalid': 'Enter a domain name such as example.com, or leave it empty.',
  'ptr.run': 'Sweep',
  'ptr.list': 'List prefixes',
  'ptr.stop': 'Stop',
  'ptr.example': 'Example:',
  'ptr.exampleTitle': 'RIPE NCC’s AS: lists its announced prefixes (one request to RIPEstat)',
  'ptr.concurrency': 'Parallel queries: {n} (Settings)',
  'ptr.privacy': 'The reverse (PTR) lookups and the forward (A / AAAA) checks go to your DoH resolvers (Settings); the network’s own name servers see them coming from those resolvers. Listing an AS’s prefixes sends only the AS number to RIPEstat. Private addresses are never sent anywhere.',
  'ptr.parsed.addresses': { one: '{count} address', other: '{count} addresses' },
  'ptr.parsed.lookups': { one: '{count} PTR lookup, plus one forward lookup per name found', other: '{count} PTR lookups, plus one forward lookup per name found' },
  'ptr.parsed.asn': 'AS{asn}: list its announced prefixes first (one request to RIPEstat), then pick what to sweep.',
  'ptr.required': 'Enter a network, a range, addresses or an AS number.',

  'ptr.issue.invalid': 'Ignored (not an address, range, network or AS number): {items}',
  'ptr.issue.v6-range': 'IPv6 networks are not swept: even a /64 holds 18 quintillion addresses, and nothing in DNS lists which of them have a reverse record. Enter exact IPv6 addresses instead. Ignored: {items}',
  'ptr.issue.reversed': 'Ignored (the range ends before it starts): {items}',
  'ptr.issue.too-large': '{input} has {count} addresses; one sweep looks up at most {max} (a /22). Split it: start with {suggestion}, for example.',
  'ptr.issue.too-large.range': '{input} has {count} addresses; one sweep looks up at most {max} (a /22). Shorten the range.',
  'ptr.issue.too-large.split': '{input} has {count} addresses; one sweep looks up at most {max} (a /22). Split it into smaller networks.',
  'ptr.issue.too-large.private': '{input} is private address space: public resolvers cannot see its reverse zone, so it is not swept (ask your own DNS server).',
  'ptr.issue.too-large.reserved': '{input} is multicast or reserved space: it holds no host addresses to sweep.',
  'ptr.issue.over-cap': 'Together that is {count} addresses to look up (private and reserved ones not counted); one sweep looks up at most {max}. Remove some.',
  'ptr.issue.asn-many': 'One AS number at a time: {items}.',
  'ptr.issue.asn-mixed': 'Enter {asn} on its own: its prefixes are listed to pick from.',
  'ptr.issue.private': { one: '{count} private address left out: public resolvers cannot see an internal reverse zone (ask your own DNS server).', other: '{count} private addresses left out: public resolvers cannot see an internal reverse zone (ask your own DNS server).' },
  'ptr.issue.reserved': { one: '{count} multicast or reserved address left out.', other: '{count} multicast or reserved addresses left out.' },
  'ptr.issue.host-bits': '{input} is read as the network {cidr}.',
  'ptr.issue.nothing': 'Nothing to sweep.',
  'ptr.issue.use': 'Use {suggestion}',

  'ptr.link.prompt': { one: 'Opened from a link: press Sweep to look up the reverse DNS of {target} ({count} address). Nothing has been sent yet.', other: 'Opened from a link: press Sweep to look up the reverse DNS of {target} ({count} addresses). Nothing has been sent yet.' },
  'ptr.link.promptAsn': 'Opened from a link: press List prefixes to see what {asn} announces. Nothing has been sent yet.',

  'ptr.asn.title': 'Prefixes announced by AS{asn}',
  'ptr.asn.loading': 'Asking RIPEstat for the prefixes of AS{asn}…',
  'ptr.asn.failed': 'Could not list the prefixes of AS{asn}',
  'ptr.asn.v4': { one: '{count} IPv4 prefix', other: '{count} IPv4 prefixes' },
  'ptr.asn.v4Addresses': { one: '{count} address', other: '{count} addresses' },
  'ptr.asn.v6': { one: '{count} IPv6 prefix', other: '{count} IPv6 prefixes' },
  'ptr.asn.window': 'announced over the last two weeks (RIPEstat)',
  'ptr.asn.none': 'RIPEstat lists no prefix announced by AS{asn} over the last two weeks.',
  'ptr.asn.pick': 'Tick the prefixes to sweep: at most {max} addresses together. A larger prefix can be swept a /22 at a time.',
  'ptr.asn.col.pick': 'Sweep',
  'ptr.asn.col.prefix': 'Prefix',
  'ptr.asn.col.size': 'Addresses',
  'ptr.asn.col.notes': 'Notes',
  'ptr.asn.select': 'Sweep {prefix}',
  'ptr.asn.tooLarge': 'larger than a /22',
  'ptr.asn.part': 'Use {part}',
  'ptr.asn.partTitle': 'Put its first /22 into the form; change the third number to pick another part',
  'ptr.asn.v6only': 'IPv6: not swept',
  'ptr.asn.private': 'private space: not swept',
  'ptr.asn.privateTitle': 'Public resolvers cannot see the reverse zone of private address space, so it is not swept.',
  'ptr.asn.reserved': 'reserved space: not swept',
  'ptr.asn.reservedTitle': 'Multicast or reserved space holds no host addresses to sweep.',
  'ptr.asn.gone': 'no longer announced',
  'ptr.asn.goneTitle': 'Seen in the last two weeks, but not at the end of that window.',
  'ptr.asn.selected': { zero: 'Nothing selected yet', one: 'Selected: {count} prefix · {addresses} of at most {max} addresses', other: 'Selected: {count} prefixes · {addresses} of at most {max} addresses' },
  'ptr.asn.over': 'Over the limit: untick some prefixes.',
  'ptr.asn.sweep': 'Sweep selected',
  'ptr.asn.clear': 'Clear selection',
  'ptr.asn.label': 'AS{asn}: {prefixes}',

  'ptr.progress': 'Looking up reverse DNS',
  'ptr.progress.done': 'Done',
  'ptr.progress.stopped': 'Stopped',
  'ptr.meta.running': '{done} of {total} addresses · {time}',
  'ptr.meta.done': { one: 'Swept {count} address in {time} · finished {when}', other: 'Swept {count} addresses in {time} · finished {when}' },
  'ptr.stoppedNote': 'Stopped — {done} of {total} addresses were looked up.',
  'ptr.failed': 'The sweep failed',
  'ptr.doneToast': { one: 'Reverse DNS sweep finished: {count} address', other: 'Reverse DNS sweep finished: {count} addresses' },
  'ptr.showResults': 'Show results',
  'ptr.busy': 'Sweeping…',
  'ptr.busyAsn': 'Listing prefixes…',
  'ptr.results': 'Reverse DNS of {target}',

  'ptr.stat.addresses': 'Addresses',
  'ptr.stat.addressesHint': '{v4} IPv4 · {v6} IPv6',
  'ptr.stat.named': 'With a PTR name',
  'ptr.stat.namedHint': { zero: 'no generated names', one: '{count} generated by a provider', other: '{count} generated by a provider' },
  'ptr.stat.confirmed': 'Forward-confirmed',
  'ptr.stat.confirmedHint': { one: '{count} does not resolve back', other: '{count} do not resolve back' },
  'ptr.stat.confirmedAll': 'every name resolves back',
  'ptr.stat.confirmedNone': 'no PTR name to check',
  'ptr.stat.confirmedFailed': { one: '{count} could not be checked', other: '{count} could not be checked' },
  'ptr.stat.none': 'No reverse DNS',
  'ptr.stat.noneHint': '{nx} NXDOMAIN · {empty} empty',
  'ptr.stat.failed': 'Lookup failed',
  'ptr.stat.failedHint': '{count} SERVFAIL',
  'ptr.stat.focus': 'Under {domain}',
  'ptr.stat.servers': 'Your servers',
  'ptr.stat.serversNone': 'no inventory saved',

  'ptr.col.ip': 'Address',
  'ptr.col.ptr': 'Reverse DNS (PTR)',
  'ptr.col.check': 'Forward check',
  'ptr.col.operator': 'Operator',
  'ptr.col.server': 'Your server',
  'ptr.st.confirmed': 'confirmed',
  'ptr.st.confirmed.title': 'The PTR name resolves back to this address (forward-confirmed reverse DNS).',
  'ptr.st.mismatch': 'does not resolve back',
  'ptr.st.mismatch.title': 'The PTR name resolves to other addresses, or to none.',
  'ptr.st.no-ptr': 'no PTR',
  'ptr.st.no-ptr.title': 'The reverse name exists but holds no PTR record.',
  'ptr.st.nxdomain': 'NXDOMAIN',
  'ptr.st.nxdomain.title': 'No reverse DNS record exists for this address.',
  'ptr.st.servfail': 'SERVFAIL',
  'ptr.st.servfail.title': 'The reverse zone did not answer: usually a broken or lame delegation at the network’s owner.',
  'ptr.st.error': 'lookup failed',
  'ptr.st.error.title': 'No answer from the resolvers (a timeout or a network error).',
  'ptr.fwd.match': 'resolves back',
  'ptr.fwd.other': 'other addresses',
  'ptr.fwd.nodata': 'no address record',
  'ptr.fwd.nxdomain': 'name does not exist',
  'ptr.fwd.error': 'lookup failed',
  'ptr.pattern.count': { one: '{count} address', other: '{count} addresses' },
  'ptr.pattern.badge': 'pattern',
  'ptr.pattern.embedded': 'The address is written into the name: the provider generates one for every address.',
  'ptr.pattern.generic': 'A provider’s pool name (dynamic, static, DSL, customer …) with a number.',
  'ptr.pattern.title': 'Names a provider generates carry no information about who runs the host, so {count} addresses are folded into this row. “Expand patterns” lists them one by one.',
  'ptr.pattern.check': '{confirmed} of {count} confirm',
  'ptr.pattern.matching': { one: '{count} of {total} matches', other: '{count} of {total} match' },
  'ptr.pattern.matchingTitle': 'The filter or the search keeps only these addresses of the pattern; an export writes only them.',
  'ptr.templated': 'generated',
  'ptr.templatedTitle': 'This name follows a provider template (the address is written into it, or a dynamic / pool word).',
  'ptr.focusBadge': 'your domain',
  'ptr.op.cloudflare': 'The PTR name is under {provider}’s domain.',
  'ptr.op.cdn': 'The PTR name is under {provider}’s domain.',
  'ptr.op.waf': 'The PTR name is under {provider}’s domain.',
  'ptr.op.platform': 'The PTR name is under {provider}’s domain.',
  'ptr.op.loadbalancer': 'The PTR name is under {provider}’s domain.',
  'ptr.op.hosting': 'The PTR name is under {provider}’s domain.',
  'ptr.d.query': 'Reverse name',
  'ptr.d.names': 'PTR names',
  'ptr.d.forward': 'Forward check',
  'ptr.d.unchecked': { one: '{count} more name not checked', other: '{count} more names not checked' },
  'ptr.d.delegated': 'Delegated (RFC 2317) to',
  'ptr.d.resolver': 'Answered by',
  'ptr.d.error': 'Error',
  'ptr.d.template': 'Template',
  'ptr.d.operator': 'Operator',
  'ptr.d.members': 'Addresses',
  'ptr.d.links': 'Open in',

  'ptr.filter.label': 'Show',
  'ptr.filter.all': 'All addresses',
  'ptr.filter.ptr': 'With a PTR name',
  'ptr.filter.focus': 'Under your domain',
  'ptr.filter.confirmed': 'Forward-confirmed',
  'ptr.filter.mismatch': 'Not resolving back',
  'ptr.filter.none': 'No reverse DNS',
  'ptr.filter.failed': 'Lookup failed',
  'ptr.expand': 'Expand patterns',
  'ptr.noMatch': 'No address matches this filter.',
  'ptr.empty.running': 'Results appear here as the addresses are looked up.',
  'ptr.names': 'names.txt',
  'ptr.namesTitle': 'Download the PTR names (provider-generated names left out)',
  'ptr.toScan': 'Add names to a scan',
  'ptr.toScanTitle': { one: 'Open a Subdomains scan with the {count} PTR name (you press Scan)', other: 'Open a Subdomains scan with the {count} PTR names (you press Scan)' },
  'ptr.toInventory': 'Add to Servers',
  'ptr.toInventoryTitle': { one: 'Add the {count} forward-confirmed host that is not in your server list yet to the Servers editor (you review and save)', other: 'Add the {count} forward-confirmed hosts that are not in your server list yet to the Servers editor (you review and save)' },
  'ptr.inv.added': { one: '{count} host added to the Servers editor — review it and press Save.', other: '{count} hosts added to the Servers editor — review them and press Save.' },
  'ptr.inv.addedGroup': { one: '{count} host added to the Servers editor, in a new {group} group — review it and press Save.', other: '{count} hosts added to the Servers editor, in a new {group} group — review them and press Save.' },
  'ptr.inv.addedToGroup': { one: '{count} host added to the Servers editor, under your {group} group — review it and press Save.', other: '{count} hosts added to the Servers editor, under your {group} group — review them and press Save.' },
  'ptr.inv.none': 'Every forward-confirmed host is already in your server list.',
  'ptr.inv.inDraft': 'Every forward-confirmed host is already in the Servers editor (not saved yet).',
  'ptr.inv.manualTitle': 'Add the hosts to your server list yourself',
  'ptr.inv.manualFormat': 'Your server list is {format} in a shape this page does not add hosts to, so the Servers editor was left as it is. Copy these hosts into it in that shape, or download them.',
  'ptr.inv.manualCheck': 'Adding these lines would change how the rest of your server list is read, so the Servers editor was left as it is. Copy the hosts into it yourself, or download them.',
  'ptr.inv.manualLines': { one: '{count} host: name and address', other: '{count} hosts: name and addresses' },
  'ptr.inv.openServers': 'Open Servers',
  'ptr.scan.none': 'No PTR name to scan.',
  'ptr.emptyTitle': 'Who is behind a block of addresses?',
  'ptr.emptyBody': 'Look up the reverse DNS of a whole network, an address range or the prefixes of an AS, check that each name resolves back (forward-confirmed reverse DNS) and spot the hosts that are not in your inventory yet.'
});

registerStrings('tr', {
  'ptr.target.label': 'Ağ, aralık, adresler ya da AS numarası',
  'ptr.target.placeholder': '192.0.2.0/24\n198.51.100.10-198.51.100.40\n2001:db8::25\nAS64496',
  'ptr.target.hint': '/22’ye kadar bir IPv4 ağı ({max} adres), bir aralık, tek tek IPv4 / IPv6 adresleri ya da duyurduğu öneklerden seçmek için bir AS numarası. IPv6: yalnızca tam adresler.',
  'ptr.focus.label': 'Alan adınız',
  'ptr.focus.placeholder': 'example.com',
  'ptr.focus.hint': 'Altındaki adlar vurgulanır, en üstte listelenir ve hiçbir zaman bir şablon satırında toplanmaz.',
  'ptr.focus.invalid': 'example.com gibi bir alan adı girin ya da boş bırakın.',
  'ptr.run': 'Tara',
  'ptr.list': 'Önekleri listele',
  'ptr.stop': 'Durdur',
  'ptr.example': 'Örnek:',
  'ptr.exampleTitle': 'RIPE NCC’nin AS’i: duyurduğu önekleri listeler (RIPEstat’a tek istek)',
  'ptr.concurrency': 'Paralel sorgu: {n} (Ayarlar)',
  'ptr.privacy': 'Ters (PTR) sorgular ve ileri (A / AAAA) doğrulamalar DoH çözümleyicilerinize (Ayarlar) gider; ağın kendi ad sunucuları bunları o çözümleyicilerden gelmiş olarak görür. Bir AS’in öneklerini listelemek RIPEstat’a yalnızca AS numarasını gönderir. Özel (private) adresler hiçbir yere gönderilmez.',
  'ptr.parsed.addresses': '{count} adres',
  'ptr.parsed.lookups': '{count} PTR sorgusu, ayrıca bulunan her ad için bir ileri sorgu',
  'ptr.parsed.asn': 'AS{asn}: önce duyurduğu önekleri listeleyin (RIPEstat’a tek istek), sonra neyin taranacağını seçin.',
  'ptr.required': 'Bir ağ, aralık, adresler ya da bir AS numarası girin.',

  'ptr.issue.invalid': 'Yok sayıldı (adres, aralık, ağ ya da AS numarası değil): {items}',
  'ptr.issue.v6-range': 'IPv6 ağları taranmaz: tek bir /64 bile 18 kentilyon adres içerir ve DNS’te hangilerinin ters kaydı olduğunu listeleyen bir şey yoktur. Bunun yerine tam IPv6 adreslerini girin. Yok sayıldı: {items}',
  'ptr.issue.reversed': 'Yok sayıldı (aralık başladığı yerden önce bitiyor): {items}',
  'ptr.issue.too-large': '{input} ağında {count} adres var; bir tarama en çok {max} adrese (bir /22) bakar. Bölün: örneğin {suggestion} ile başlayın.',
  'ptr.issue.too-large.range': '{input} aralığında {count} adres var; bir tarama en çok {max} adrese (bir /22) bakar. Aralığı kısaltın.',
  'ptr.issue.too-large.split': '{input} ağında {count} adres var; bir tarama en çok {max} adrese (bir /22) bakar. Daha küçük ağlara bölün.',
  'ptr.issue.too-large.private': '{input} özel (private) adres alanı: genel çözümleyiciler ters bölgesini göremez, bu yüzden taranmaz (kendi DNS sunucunuza sorun).',
  'ptr.issue.too-large.reserved': '{input} multicast ya da ayrılmış adres alanı: taranacak host adresi içermez.',
  'ptr.issue.over-cap': 'Toplam {count} adrese bakılacak (özel ve ayrılmış adresler sayılmadan); bir tarama en çok {max} adrese bakar. Bir kısmını çıkarın.',
  'ptr.issue.asn-many': 'Aynı anda tek bir AS numarası: {items}.',
  'ptr.issue.asn-mixed': '{asn} değerini tek başına girin: önekleri seçmeniz için listelenir.',
  'ptr.issue.private': '{count} özel adres dışarıda bırakıldı: genel çözümleyiciler iç ağdaki ters bölgeyi göremez (kendi DNS sunucunuza sorun).',
  'ptr.issue.reserved': '{count} multicast ya da ayrılmış adres dışarıda bırakıldı.',
  'ptr.issue.host-bits': '{input}, {cidr} ağı olarak okundu.',
  'ptr.issue.nothing': 'Taranacak bir şey yok.',
  'ptr.issue.use': '{suggestion} kullan',

  'ptr.link.prompt': 'Bir bağlantıdan açıldı: {target} ({count} adres) ters DNS’ine bakmak için Tara’ya basın. Henüz hiçbir şey gönderilmedi.',
  'ptr.link.promptAsn': 'Bir bağlantıdan açıldı: {asn} numarasının neleri duyurduğunu görmek için Önekleri listele’ye basın. Henüz hiçbir şey gönderilmedi.',

  'ptr.asn.title': 'AS{asn} tarafından duyurulan önekler',
  'ptr.asn.loading': 'AS{asn} önekleri RIPEstat’a soruluyor…',
  'ptr.asn.failed': 'AS{asn} önekleri listelenemedi',
  'ptr.asn.v4': '{count} IPv4 öneki',
  'ptr.asn.v4Addresses': '{count} adres',
  'ptr.asn.v6': '{count} IPv6 öneki',
  'ptr.asn.window': 'son iki haftada duyurulanlar (RIPEstat)',
  'ptr.asn.none': 'RIPEstat, AS{asn} tarafından son iki haftada duyurulan bir önek listelemiyor.',
  'ptr.asn.pick': 'Taranacak önekleri işaretleyin: toplam en çok {max} adres. Daha büyük bir önek /22’lik parçalar hâlinde taranabilir.',
  'ptr.asn.col.pick': 'Tara',
  'ptr.asn.col.prefix': 'Önek',
  'ptr.asn.col.size': 'Adres',
  'ptr.asn.col.notes': 'Notlar',
  'ptr.asn.select': '{prefix} taransın',
  'ptr.asn.tooLarge': 'bir /22’den büyük',
  'ptr.asn.part': '{part} kullan',
  'ptr.asn.partTitle': 'İlk /22’sini forma koyar; başka bir parçayı seçmek için üçüncü sayıyı değiştirin',
  'ptr.asn.v6only': 'IPv6: taranmaz',
  'ptr.asn.private': 'özel adres alanı: taranmaz',
  'ptr.asn.privateTitle': 'Genel çözümleyiciler özel adres alanının ters bölgesini göremez, bu yüzden taranmaz.',
  'ptr.asn.reserved': 'ayrılmış adres alanı: taranmaz',
  'ptr.asn.reservedTitle': 'Multicast ya da ayrılmış adres alanında taranacak host adresi yoktur.',
  'ptr.asn.gone': 'artık duyurulmuyor',
  'ptr.asn.goneTitle': 'Son iki haftada görüldü, ama o sürenin sonunda görülmedi.',
  'ptr.asn.selected': { zero: 'Henüz bir şey seçilmedi', other: 'Seçilen: {count} önek · en çok {max} adresten {addresses} adres' },
  'ptr.asn.over': 'Sınırın üstünde: bazı öneklerin işaretini kaldırın.',
  'ptr.asn.sweep': 'Seçilenleri tara',
  'ptr.asn.clear': 'Seçimi temizle',
  'ptr.asn.label': 'AS{asn}: {prefixes}',

  'ptr.progress': 'Ters DNS sorgulanıyor',
  'ptr.progress.done': 'Tamamlandı',
  'ptr.progress.stopped': 'Durduruldu',
  'ptr.meta.running': '{total} adresten {done} tanesi · {time}',
  'ptr.meta.done': '{count} adres {time} içinde tarandı · {when} tamamlandı',
  'ptr.stoppedNote': 'Durduruldu — {total} adresten {done} tanesi sorgulandı.',
  'ptr.failed': 'Tarama başarısız oldu',
  'ptr.doneToast': 'Ters DNS taraması bitti: {count} adres',
  'ptr.showResults': 'Sonuçları göster',
  'ptr.busy': 'Taranıyor…',
  'ptr.busyAsn': 'Önekler listeleniyor…',
  'ptr.results': '{target} ters DNS’i',

  'ptr.stat.addresses': 'Adres',
  'ptr.stat.addressesHint': '{v4} IPv4 · {v6} IPv6',
  'ptr.stat.named': 'PTR adı olan',
  'ptr.stat.namedHint': { zero: 'sağlayıcı adı yok', other: '{count} tanesi sağlayıcının ürettiği ad' },
  'ptr.stat.confirmed': 'İleri doğrulanan',
  'ptr.stat.confirmedHint': '{count} tanesi adresine geri çözülmüyor',
  'ptr.stat.confirmedAll': 'her ad adresine geri çözülüyor',
  'ptr.stat.confirmedNone': 'kontrol edilecek PTR adı yok',
  'ptr.stat.confirmedFailed': '{count} tanesi kontrol edilemedi',
  'ptr.stat.none': 'Ters DNS yok',
  'ptr.stat.noneHint': '{nx} NXDOMAIN · {empty} boş',
  'ptr.stat.failed': 'Sorgu başarısız',
  'ptr.stat.failedHint': '{count} SERVFAIL',
  'ptr.stat.focus': '{domain} altında',
  'ptr.stat.servers': 'Sunucularınız',
  'ptr.stat.serversNone': 'kayıtlı envanter yok',

  'ptr.col.ip': 'Adres',
  'ptr.col.ptr': 'Ters DNS (PTR)',
  'ptr.col.check': 'İleri doğrulama',
  'ptr.col.operator': 'İşleten',
  'ptr.col.server': 'Sunucunuz',
  'ptr.st.confirmed': 'doğrulandı',
  'ptr.st.confirmed.title': 'PTR adı yine bu adrese çözülüyor (ileri doğrulanmış ters DNS).',
  'ptr.st.mismatch': 'adrese geri çözülmüyor',
  'ptr.st.mismatch.title': 'PTR adı başka adreslere çözülüyor ya da hiçbir adrese çözülmüyor.',
  'ptr.st.no-ptr': 'PTR yok',
  'ptr.st.no-ptr.title': 'Ters ad var ama bir PTR kaydı içermiyor.',
  'ptr.st.nxdomain': 'NXDOMAIN',
  'ptr.st.nxdomain.title': 'Bu adres için bir ters DNS kaydı yok.',
  'ptr.st.servfail': 'SERVFAIL',
  'ptr.st.servfail.title': 'Ters bölge yanıt vermedi: genellikle ağ sahibindeki bozuk ya da hatalı bir yetkilendirme.',
  'ptr.st.error': 'sorgu başarısız',
  'ptr.st.error.title': 'Çözümleyicilerden yanıt gelmedi (zaman aşımı ya da ağ hatası).',
  'ptr.fwd.match': 'adrese geri çözülüyor',
  'ptr.fwd.other': 'başka adresler',
  'ptr.fwd.nodata': 'adres kaydı yok',
  'ptr.fwd.nxdomain': 'ad mevcut değil',
  'ptr.fwd.error': 'sorgu başarısız',
  'ptr.pattern.count': '{count} adres',
  'ptr.pattern.badge': 'şablon',
  'ptr.pattern.embedded': 'Adres adın içine yazılmış: sağlayıcı her adres için bir ad üretiyor.',
  'ptr.pattern.generic': 'Sağlayıcının havuz adı (dynamic, static, DSL, customer …) ve bir sayı.',
  'ptr.pattern.title': 'Sağlayıcının ürettiği adlar, host’u kimin çalıştırdığı hakkında bilgi vermez; bu yüzden {count} adres bu satırda toplandı. “Şablonları aç” hepsini tek tek listeler.',
  'ptr.pattern.check': '{count} adresten {confirmed} tanesi doğrulandı',
  'ptr.pattern.matching': '{total} adresten {count} tanesi uyuyor',
  'ptr.pattern.matchingTitle': 'Filtre ya da arama bu şablondan yalnızca bu adresleri tutuyor; dışa aktarma da yalnızca onları yazar.',
  'ptr.templated': 'üretilmiş',
  'ptr.templatedTitle': 'Bu ad bir sağlayıcı şablonuna uyuyor (adres adın içine yazılmış ya da dynamic / pool gibi bir sözcük var).',
  'ptr.focusBadge': 'alan adınız',
  'ptr.op.cloudflare': 'PTR adı {provider} alan adının altında.',
  'ptr.op.cdn': 'PTR adı {provider} alan adının altında.',
  'ptr.op.waf': 'PTR adı {provider} alan adının altında.',
  'ptr.op.platform': 'PTR adı {provider} alan adının altında.',
  'ptr.op.loadbalancer': 'PTR adı {provider} alan adının altında.',
  'ptr.op.hosting': 'PTR adı {provider} alan adının altında.',
  'ptr.d.query': 'Ters ad',
  'ptr.d.names': 'PTR adları',
  'ptr.d.forward': 'İleri doğrulama',
  'ptr.d.unchecked': '{count} ad daha kontrol edilmedi',
  'ptr.d.delegated': 'Yetkilendirildiği ad (RFC 2317)',
  'ptr.d.resolver': 'Yanıtlayan',
  'ptr.d.error': 'Hata',
  'ptr.d.template': 'Şablon',
  'ptr.d.operator': 'İşleten',
  'ptr.d.members': 'Adresler',
  'ptr.d.links': 'Şurada aç',

  'ptr.filter.label': 'Göster',
  'ptr.filter.all': 'Tüm adresler',
  'ptr.filter.ptr': 'PTR adı olanlar',
  'ptr.filter.focus': 'Alan adınızın altındakiler',
  'ptr.filter.confirmed': 'İleri doğrulananlar',
  'ptr.filter.mismatch': 'Geri çözülmeyenler',
  'ptr.filter.none': 'Ters DNS’i olmayanlar',
  'ptr.filter.failed': 'Sorgusu başarısız olanlar',
  'ptr.expand': 'Şablonları aç',
  'ptr.noMatch': 'Bu filtreye uyan adres yok.',
  'ptr.empty.running': 'Adresler sorgulandıkça sonuçlar burada görünür.',
  'ptr.names': 'names.txt',
  'ptr.namesTitle': 'PTR adlarını indir (sağlayıcının ürettiği adlar hariç)',
  'ptr.toScan': 'Adları taramaya ekle',
  'ptr.toScanTitle': '{count} PTR adıyla bir Subdomain taraması aç (Tara’ya siz basarsınız)',
  'ptr.toInventory': 'Sunuculara ekle',
  'ptr.toInventoryTitle': 'Sunucu listenizde henüz olmayan {count} ileri doğrulanmış host’u Sunucular düzenleyicisine ekle (siz kontrol edip kaydedersiniz)',
  'ptr.inv.added': '{count} host Sunucular düzenleyicisine eklendi — kontrol edip Kaydet’e basın.',
  'ptr.inv.addedGroup': '{count} host Sunucular düzenleyicisine, yeni bir {group} grubuna eklendi — kontrol edip Kaydet’e basın.',
  'ptr.inv.addedToGroup': '{count} host Sunucular düzenleyicisine, {group} grubunuzun altına eklendi — kontrol edip Kaydet’e basın.',
  'ptr.inv.none': 'İleri doğrulanan her host zaten sunucu listenizde.',
  'ptr.inv.inDraft': 'İleri doğrulanan her host zaten Sunucular düzenleyicisinde (henüz kaydedilmedi).',
  'ptr.inv.manualTitle': 'Host’ları sunucu listenize kendiniz ekleyin',
  'ptr.inv.manualFormat': 'Sunucu listeniz, bu sayfanın host ekleyemediği bir {format} yapısında; bu yüzden Sunucular düzenleyicisine dokunulmadı. Bu host’ları aynı yapıda kendiniz ekleyin ya da indirin.',
  'ptr.inv.manualCheck': 'Bu satırları eklemek sunucu listenizin geri kalanının okunuşunu değiştirirdi; bu yüzden Sunucular düzenleyicisine dokunulmadı. Host’ları kendiniz ekleyin ya da indirin.',
  'ptr.inv.manualLines': '{count} host: ad ve adres',
  'ptr.inv.openServers': 'Sunucuları aç',
  'ptr.scan.none': 'Taranacak PTR adı yok.',
  'ptr.emptyTitle': 'Bir adres bloğunun arkasında kim var?',
  'ptr.emptyBody': 'Bütün bir ağın, bir adres aralığının ya da bir AS’in öneklerinin ters DNS’ine bakın, her adın yine o adrese çözüldüğünü doğrulayın (ileri doğrulanmış ters DNS) ve envanterinizde henüz olmayan sunucuları görün.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/**
 * The i18n key of a target issue. A network too large for the cap: its first /22 to start
 * with, or (wholly private or reserved) why it is not swept at all, or (its first /22 has
 * nothing to sweep) a plain "split it"; a range too large has no network to suggest.
 * @param {{ code: string, params?: object }} issue lib/ptrsweep SweepIssue
 * @returns {string}
 */
export function issueKey(issue) {
  if (issue.code !== 'too-large') return `ptr.issue.${issue.code}`;
  const p = issue.params || {};
  if (p.skipped === 'private' || p.skipped === 'reserved') return `ptr.issue.too-large.${p.skipped}`;
  if (p.suggestion) return 'ptr.issue.too-large';
  return p.kind === 'cidr' ? 'ptr.issue.too-large.split' : 'ptr.issue.too-large.range';
}

/**
 * The one-shot hand-off to Subdomains (`state.session.namesScanIntent`).
 * @param {{ names: string[], domains: string[], label?: string, now?: number }} o
 * @returns {{ v: 1, target: 'subdomains', source: 'ptr', names: string[], domains: string[], label: string, mode: 'exact', at: number }}
 */
export function buildNamesIntent({ names, domains, label = '', now = Date.now() }) {
  return {
    v: 1, target: 'subdomains', source: 'ptr', names: [...names], domains: [...domains], label: String(label || ''), mode: 'exact', at: now
  };
}

/**
 * The hint under the Forward-confirmed card: what the count leaves out. "Every name resolves
 * back" only when there are PTR names and each of them does; none before the first result.
 * @param {{ done: number, withPtr: number, byStatus: Record<string, number>, forwardFailed: number }} s lib/ptrsweep sweepSummary
 * @returns {string|null}
 */
export function confirmedHint(s) {
  if (!s || !s.done) return null;
  if (!s.withPtr) return t('ptr.stat.confirmedNone');
  const parts = [];
  if (s.byStatus.mismatch) parts.push(t('ptr.stat.confirmedHint', { count: s.byStatus.mismatch }));
  if (s.forwardFailed) parts.push(t('ptr.stat.confirmedFailed', { count: s.forwardFailed }));
  return parts.length ? parts.join(' · ') : t('ptr.stat.confirmedAll');
}

/**
 * The route params of a sweep's share link, or null when the target is too long for a URL.
 * @param {string} target the form text
 * @param {string} [focus]
 * @returns {{ target: string, focus: string|null }|null}
 */
export function shareParams(target, focus = '') {
  const tokens = splitList(target);
  const text = tokens.join(',');
  if (!text || text.length > LINK_MAX_CHARS) return null;
  const f = normalizeHostname(String(focus || ''));
  return { target: text, focus: f || null };
}

/* ------------------------------------------------------------------------ */
/* Jobs (module-owned: they outlive a mounted view)                         */
/* ------------------------------------------------------------------------ */

/**
 * The form, the current / last sweep and AS lookup, the table's filter, kept for the page session.
 * `routeTarget`: the target in the URL that is already in the form (a link applied, or the last
 * run's); `prompt`: a link pre-filled the form and waits for a click. Each sweep starts at the
 * 'ptr' filter; `filterChosen`: the user picked one for this sweep (else a sweep that ends
 * without any PTR name shows all its addresses).
 */
const session = {
  text: '', focus: '', job: null, asn: null, filter: 'ptr', filterChosen: false, expand: false, prompt: false, routeTarget: null
};
let jobCounter = 0;
let active = null;

function emit(job, type, payload) {
  for (const fn of [...job.listeners]) {
    try {
      fn(type, payload);
    } catch (err) {
      setTimeout(() => {
        throw err;
      }, 0);
    }
  }
}

/**
 * Start a sweep job: every address through lib/ptrsweep.runPtrSweep; results are kept on the
 * job and streamed to listeners ('result', then 'done' | 'cancelled' | 'error').
 */
function startJob({ addresses, label, target, dns, concurrency }) {
  jobCounter += 1;
  const job = {
    id: jobCounter,
    label,
    target,
    planned: addresses.length,
    addresses,
    results: [],
    status: 'running',
    startedAt: new Date(),
    finishedAt: null,
    controller: new AbortController(),
    listeners: new Set(),
    error: null
  };
  runPtrSweep(addresses, {
    dns,
    signal: job.controller.signal,
    concurrency,
    onResult: (r) => {
      job.results.push(r);
      emit(job, 'result', r);
    }
  }).then(({ aborted }) => {
    job.finishedAt = new Date();
    job.results.sort((a, b) => a.index - b.index);
    job.status = aborted ? 'cancelled' : 'done';
    emit(job, job.status, null);
    if (job.status === 'done' && !active && session.job === job) {
      toast(t('ptr.doneToast', { count: job.results.length }), {
        type: 'success',
        timeout: 10000,
        action: { label: t('ptr.showResults'), onClick: () => { globalThis.location.hash = '#/ptr'; } }
      });
    }
  }, (err) => {
    job.finishedAt = new Date();
    job.status = errorKind(err) === 'abort' ? 'cancelled' : 'error';
    job.error = err;
    emit(job, job.status, err);
  });
  return job;
}

/** Call `fn` at most every `ms` (trailing call guaranteed). */
function throttle(fn, ms) {
  let timer = null;
  let last = 0;
  return () => {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      last = Date.now();
      fn();
    }, Math.max(0, ms - (Date.now() - last)));
  };
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mount the Reverse DNS view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { state } = ctx;
  const cleanups = [];
  applyRoute(ctx.params);

  /* --- form ---------------------------------------------------------------- */
  const targetField = textarea({
    label: t('ptr.target.label'),
    value: session.text,
    rows: 3,
    placeholder: t('ptr.target.placeholder'),
    hint: t('ptr.target.hint', { max: formatNumber(SWEEP_MAX_ADDRESSES) }),
    className: 'ptr-target',
    attrs: { 'data-role': 'ptr-target' },
    onInput: (v) => {
      session.text = v;
      targetField.setError(null);
      hidePrompt();
      renderParsedSoon();
    }
  });
  targetField.input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      start();
    }
  });
  const focusField = textInput({
    label: t('ptr.focus.label'),
    value: session.focus,
    placeholder: t('ptr.focus.placeholder'),
    hint: t('ptr.focus.hint'),
    optional: true,
    mono: true,
    className: 'ptr-focus',
    attrs: { 'data-role': 'ptr-focus', inputmode: 'url' },
    onInput: (v) => {
      session.focus = v;
      focusField.setError(null);
      if (ui) ui.refocus();
    },
    onEnter: () => start()
  });
  const parsedEl = h('div', { class: 'ptr-parsed text-sm', attrs: { 'aria-live': 'polite' } });
  const issuesEl = h('div', { class: 'stack-sm ptr-issues' });
  const promptEl = h('div', { class: 'ptr-prompt', hidden: true });
  const runBtn = Button({ label: t('ptr.run'), icon: 'play', variant: 'primary', dataset: { action: 'ptr-run' }, onClick: () => start() });
  const stopBtn = Button({ label: t('ptr.stop'), icon: 'stop', dataset: { action: 'ptr-stop' }, onClick: () => stop() });
  stopBtn.hidden = true;
  const concurrencyNote = h('span', { class: 'muted text-xs ptr-concurrency' });
  const renderConcurrency = () => {
    concurrencyNote.textContent = t('ptr.concurrency', { n: formatNumber(state.settings.concurrency) });
  };
  const example = h('div', { class: 'cluster text-sm ptr-examples' },
    h('span', { class: 'muted' }, t('ptr.example')),
    h('button', {
      type: 'button', class: 'link-btn mono', title: t('ptr.exampleTitle'), dataset: { example: EXAMPLE_ASN },
      on: {
        click: () => {
          if (isRunning()) return;
          targetField.value = EXAMPLE_ASN;
          session.text = EXAMPLE_ASN;
          hidePrompt();
          renderParsed();
          targetField.focus();
        }
      }
    }, EXAMPLE_ASN));

  const formCard = Card({
    className: 'ptr-form-card',
    children: h('div', { class: 'stack' },
      h('div', { class: 'ptr-form' }, targetField.el, focusField.el),
      parsedEl,
      issuesEl,
      promptEl,
      h('div', { class: 'ptr-actions' },
        h('div', { class: 'cluster' }, example, concurrencyNote),
        h('div', { class: 'cluster ptr-run' }, stopBtn, runBtn)),
      h('p', { class: 'muted text-xs ptr-privacy' }, Icon('lock', { size: 12 }), h('span', null, t('ptr.privacy'))))
  });

  const asnHost = h('div', { class: 'ptr-asn-host' });
  const resultsHost = h('div', { class: 'ptr-results-host' });
  const emptyEl = Card({
    padded: false,
    className: 'ptr-empty',
    children: EmptyState({ icon: 'swap', title: t('ptr.emptyTitle'), message: t('ptr.emptyBody') })
  });
  container.append(h('div', { class: 'stack-lg ptr-view' }, formCard, asnHost, emptyEl, resultsHost));

  /* --- parsing ------------------------------------------------------------- */
  let parsed = parseSweepTarget(session.text);

  function focusValue() {
    const raw = focusField.value.trim();
    return raw ? normalizeHostname(raw) : null;
  }

  function renderParsed() {
    parsed = parseSweepTarget(targetField.value);
    // An AS lookup belongs to the AS in the form: typing something else drops it (no stale list later).
    if (isListing() && !(parsed.kind === 'asn' && parsed.asn === session.asn.asn)) session.asn.controller.abort();
    clear(parsedEl);
    clear(issuesEl);
    runBtn.querySelector('.btn-label').textContent = parsed.kind === 'asn' ? t('ptr.list') : t('ptr.run');
    if (parsed.kind === 'asn' && parsed.ok) {
      parsedEl.append(Icon('info', { size: 13 }), h('span', null, t('ptr.parsed.asn', { asn: parsed.asn })));
    } else if (parsed.kind === 'addresses' && parsed.addresses.length) {
      parsedEl.append(Badge(t('ptr.parsed.addresses', { count: parsed.addresses.length }), { variant: 'ok', icon: 'check' }),
        h('span', { class: 'muted' }, t('ptr.parsed.lookups', { count: parsed.addresses.length })));
    }
    for (const issue of parsed.issues) {
      // "Nothing to sweep" adds nothing next to another error that already says why.
      if (issue.code === 'nothing' && parsed.issues.some((i) => i !== issue && i.severity === 'error')) continue;
      const suggestion = issue.code === 'too-large' && issue.params.suggestion ? issue.params.suggestion : null;
      const alert = Alert({
        variant: issue.severity === 'error' ? 'error' : issue.severity === 'warn' ? 'warn' : 'info',
        compact: true,
        message: issueText(issue),
        actions: suggestion ? [Button({
          label: t('ptr.issue.use', { suggestion }), size: 'sm', dataset: { action: 'ptr-use-suggestion' },
          onClick: () => {
            targetField.value = suggestion;
            session.text = suggestion;
            renderParsed();
            targetField.focus();
          }
        })] : null
      });
      alert.dataset.issue = issue.code;
      issuesEl.append(alert);
    }
  }
  const renderParsedSoon = debounce(renderParsed, 150);

  /** The message of a parseSweepTarget issue (t() groups a numeric {count} itself and picks its plural form). */
  function issueText(issue) {
    const params = { ...issue.params };
    if (typeof params.max === 'number') params.max = formatNumber(params.max);
    return t(issueKey(issue), params);
  }

  /* --- link prompt ----------------------------------------------------------- */
  function showPrompt() {
    clear(promptEl);
    promptEl.hidden = false;
    const message = parsed.kind === 'asn'
      ? t('ptr.link.promptAsn', { asn: `AS${parsed.asn}` })
      : t('ptr.link.prompt', { target: parsed.label, count: parsed.addresses.length });
    const alert = Alert({ variant: 'info', icon: 'link', compact: true, message });
    alert.dataset.prompt = 'link';
    promptEl.append(alert);
  }
  function hidePrompt() {
    session.prompt = false;
    clear(promptEl);
    promptEl.hidden = true;
  }

  /* --- run ------------------------------------------------------------------- */
  let ui = null;
  let starting = false;
  /** The prefix picker's "Sweep selected" state, re-derived when a sweep starts or ends. */
  let syncPicker = null;
  const isRunning = () => !!(session.job && session.job.status === 'running');
  const isListing = () => !!(session.asn && session.asn.status === 'loading' && session.asn.controller);

  /**
   * Sweep ⇄ Stop and the page's busy state follow what runs: a sweep, or an AS lookup (Stop
   * cancels either). Derived from both each time, so the end of one never clears the other's.
   */
  function syncControls() {
    const sweeping = isRunning();
    const listing = isListing();
    const stoppable = sweeping || listing;
    // Keyboard focus follows Sweep ⇄ Stop instead of falling to <body> when one is hidden.
    const doc = globalThis.document;
    const moveFocus = doc && doc.activeElement === (stoppable ? runBtn : stopBtn);
    runBtn.hidden = stoppable;
    stopBtn.hidden = !stoppable;
    targetField.input.readOnly = sweeping;
    if (moveFocus) (stoppable ? stopBtn : runBtn).focus({ preventScroll: true });
    ctx.setBusy(sweeping ? t('ptr.busy') : listing ? t('ptr.busyAsn') : false);
    renderHeaderActions();
    if (syncPicker) syncPicker();
  }

  function stop() {
    if (isRunning()) session.job.controller.abort();
    else if (isListing()) session.asn.controller.abort();
  }

  async function start() {
    if (starting || isRunning()) return;
    renderParsed();
    hidePrompt();
    focusField.setError(null);
    if (focusField.value.trim() && !focusValue()) {
      focusField.setError(t('ptr.focus.invalid'));
      focusField.focus();
      return;
    }
    if (parsed.kind === 'empty') {
      targetField.setError(t('ptr.required'));
      targetField.focus();
      return;
    }
    if (!parsed.ok) {
      targetField.focus();
      return;
    }
    if (parsed.kind === 'asn') {
      if (!(isListing() && session.asn.asn === parsed.asn)) listPrefixes(parsed.asn);
      return;
    }
    // A typed network replaces an earlier AS's prefix list (it no longer belongs to the form).
    if (session.asn) {
      if (session.asn.controller) session.asn.controller.abort();
      session.asn = null;
      renderAsn();
    }
    await sweep(parsed.addresses, parsed.label, targetField.value);
  }

  /** Start a sweep of `addresses` (the form's, or the picked prefixes'). */
  async function sweep(addresses, label, target) {
    let dns;
    starting = true;
    try {
      dns = await ctx.getDns();
    } catch (err) {
      clear(resultsHost);
      resultsHost.append(ErrorBanner(err, { title: t('ptr.failed') }));
      return;
    } finally {
      starting = false;
    }
    if (ctx.signal.aborted) return;
    setRouteTarget(target);
    // Every sweep starts at the default filter (one picked for an earlier sweep does not carry over).
    session.filter = 'ptr';
    session.filterChosen = false;
    const job = startJob({
      addresses,
      label,
      target,
      dns,
      concurrency: Math.min(SWEEP_MAX_CONCURRENCY, Math.max(1, state.settings.concurrency * 2))
    });
    session.job = job;
    attach(job);
    const r = resultsHost.getBoundingClientRect();
    if (r.top > globalThis.innerHeight - 120) resultsHost.scrollIntoView({ block: 'start' });
  }

  function attach(job) {
    if (ui) ui.dispose();
    clear(resultsHost);
    emptyEl.hidden = true;
    ui = buildJobUI(job, ctx, {
      focus: focusValue,
      onFinish: () => syncControls()
    });
    resultsHost.append(ui.el);
    syncControls();
  }

  /**
   * The URL carries what was last run (a reload or a re-mount pre-fills the form, never runs).
   * Remembered, so a re-mount does not take it for a new link and overwrite the form.
   */
  function setRouteTarget(target) {
    const params = shareParams(target, focusField.value);
    session.routeTarget = params ? params.target : null;
    ctx.setParams(params ? { target: params.target, focus: params.focus } : {});
  }

  function renderHeaderActions() {
    const job = session.job;
    const params = job ? shareParams(job.target, focusField.value) : null;
    if (!params) {
      ctx.setActions();
      return;
    }
    ctx.setActions(CopyButton(() => ctx.shareUrl({ target: params.target, focus: params.focus }), { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }));
  }

  /* --- an AS's prefixes ------------------------------------------------------ */
  function listPrefixes(asn) {
    if (session.asn && session.asn.controller) session.asn.controller.abort();
    const controller = new AbortController();
    const entry = { asn, status: 'loading', result: null, error: null, selected: new Set(), controller, promise: null };
    session.asn = entry;
    setRouteTarget(`AS${asn}`);
    // The lookup belongs to the module (like a sweep): a re-mount while it runs follows it.
    entry.promise = announcedPrefixes(asn, { signal: controller.signal }).then((result) => {
      entry.result = result;
      entry.status = 'done';
    }, (err) => {
      entry.status = errorKind(err) === 'abort' ? 'cancelled' : 'error';
      entry.error = err;
    }).finally(() => {
      entry.controller = null;
    });
    followAsn(entry);
  }

  /**
   * Show an AS lookup (running or finished) and follow it to its end; its result is announced
   * once, when it arrives (never again on a re-mount).
   */
  function followAsn(entry) {
    renderAsn();
    syncControls();
    if (entry.status !== 'loading') return;
    entry.promise.then(() => {
      if (ctx.signal.aborted) return;
      syncControls();
      if (session.asn !== entry) return;
      renderAsn();
      if (entry.status === 'done') announce(t('ptr.asn.title', { asn: entry.asn }));
      else if (entry.status === 'error') announce(t('ptr.asn.failed', { asn: entry.asn }));
    });
  }

  function renderAsn() {
    clear(asnHost);
    syncPicker = null;
    const entry = session.asn;
    if (!entry || entry.status === 'cancelled') {
      emptyEl.hidden = !!session.job;
      return;
    }
    emptyEl.hidden = true;
    if (entry.status === 'loading') {
      asnHost.append(Card({
        className: 'ptr-asn', title: t('ptr.asn.title', { asn: entry.asn }), icon: 'network',
        children: h('p', { class: 'muted text-sm' }, t('ptr.asn.loading', { asn: entry.asn }))
      }));
      return;
    }
    if (entry.status === 'error') {
      asnHost.append(ErrorBanner(entry.error, { title: t('ptr.asn.failed', { asn: entry.asn }), onRetry: () => listPrefixes(entry.asn) }));
      return;
    }
    asnHost.append(prefixPicker(entry));
  }

  function prefixPicker(entry) {
    const r = entry.result;
    const summary = h('p', { class: 'text-sm ptr-asn-summary' },
      [t('ptr.asn.v4', { count: r.v4 }), `(${t('ptr.asn.v4Addresses', { count: formatNumber(r.v4Addresses) })})`, '·', t('ptr.asn.v6', { count: r.v6 }), '—', t('ptr.asn.window')].join(' '));
    if (!r.prefixes.length) {
      return Card({
        className: 'ptr-asn', title: t('ptr.asn.title', { asn: entry.asn }), icon: 'network',
        children: h('p', { class: 'muted text-sm', dataset: { role: 'ptr-asn-none' } }, t('ptr.asn.none', { asn: entry.asn }))
      });
    }
    const selectedEl = h('div', { class: 'text-sm ptr-asn-selected', attrs: { 'aria-live': 'polite' } });
    // Why "Sweep selected" did not start (the picked prefixes hold nothing to sweep).
    const pickIssues = h('div', { class: 'stack-sm ptr-asn-issues' });
    const sweepBtn = Button({ label: t('ptr.asn.sweep'), icon: 'play', variant: 'primary', size: 'sm', dataset: { action: 'ptr-asn-sweep' }, onClick: () => sweepSelected() });
    const clearBtn = Button({
      label: t('ptr.asn.clear'), variant: 'ghost', size: 'sm', dataset: { action: 'ptr-asn-clear' },
      onClick: () => {
        entry.selected.clear();
        table.refresh();
        renderSelection();
      }
    });
    function renderSelection() {
      const s = prefixSelection(r.prefixes, entry.selected);
      clear(selectedEl);
      clear(pickIssues);
      selectedEl.append(h('span', null, t('ptr.asn.selected', { count: s.count, addresses: formatNumber(s.addresses), max: formatNumber(s.max) })));
      if (s.over) selectedEl.append(h('span', { class: 'ptr-asn-over' }, Icon('alert', { size: 13 }), ' ', t('ptr.asn.over')));
      selectedEl.dataset.over = s.over ? '1' : '0';
      sweepBtn.disabled = !s.count || s.over || isRunning();
      clearBtn.disabled = !s.count;
    }
    /**
     * Why a prefix cannot be ticked (IPv6, private or reserved space, larger than a /22 — with
     * "Use <its first /22>", which fills the form) and whether it is still announced.
     */
    function prefixNotes(p) {
      const bits = [];
      if (p.version === 6) bits.push(Badge(t('ptr.asn.v6only'), { title: t('ptr.issue.v6-range', { items: p.prefix }) }));
      else if (p.skipped) bits.push(Badge(t(`ptr.asn.${p.skipped}`), { title: t(`ptr.asn.${p.skipped}Title`), className: 'ptr-asn-skipped' }));
      else if (!p.sweepable) {
        bits.push(Badge(t('ptr.asn.tooLarge'), { variant: 'warn' }));
        if (p.part) {
          bits.push(h('button', {
            type: 'button', class: 'link-btn text-sm', title: t('ptr.asn.partTitle'), dataset: { action: 'ptr-asn-part', part: p.part },
            on: {
              click: () => {
                targetField.value = p.part;
                session.text = p.part;
                renderParsed();
                targetField.focus();
                targetField.input.scrollIntoView({ block: 'nearest' });
              }
            }
          }, t('ptr.asn.part', { part: p.part })));
        }
      }
      if (!p.current) bits.push(Badge(t('ptr.asn.gone'), { title: t('ptr.asn.goneTitle') }));
      return bits.length ? h('div', { class: 'cluster' }, bits) : null;
    }

    function sweepSelected() {
      const s = prefixSelection(r.prefixes, entry.selected);
      if (!s.count || s.over || isRunning()) return;
      const target = parseSweepTarget(s.cidrs.join('\n'));
      clear(pickIssues);
      if (!target.ok) {
        for (const issue of target.issues.filter((i) => i.severity === 'error')) {
          const alert = Alert({ variant: 'error', compact: true, message: issueText(issue) });
          alert.dataset.issue = issue.code;
          pickIssues.append(alert);
        }
        return;
      }
      const label = t('ptr.asn.label', { asn: entry.asn, prefixes: target.label });
      sweep(target.addresses, label, s.cidrs.join('\n'));
    }
    const table = DataTable({
      caption: t('ptr.asn.title', { asn: entry.asn }),
      rows: r.prefixes,
      rowKey: (p) => p.prefix,
      search: r.prefixes.length > 10,
      dense: true,
      pageSize: 100,
      className: 'ptr-asn-table',
      export: false,
      columns: [
        {
          key: 'pick', label: t('ptr.asn.col.pick'), searchable: false, export: false,
          render: (p) => h('input', {
            type: 'checkbox',
            class: 'check-input',
            checked: entry.selected.has(p.prefix),
            disabled: !p.sweepable,
            dataset: { prefix: p.prefix },
            attrs: { 'aria-label': t('ptr.asn.select', { prefix: p.prefix }) },
            on: {
              change: (e) => {
                if (e.target.checked) entry.selected.add(p.prefix);
                else entry.selected.delete(p.prefix);
                renderSelection();
              }
            }
          })
        },
        {
          key: 'prefix', label: t('ptr.asn.col.prefix'), sortable: true, sortValue: (p) => ipSortValue(p.prefix.split('/')[0]), searchValue: (p) => p.prefix,
          // On a phone the notes (why a box cannot be ticked) sit under the prefix; their own column is hidden.
          render: (p) => {
            const notes = prefixNotes(p);
            return h('div', { class: 'ptr-asn-prefix' }, h('span', { class: 'mono' }, p.prefix),
              notes ? h('div', { class: 'ptr-asn-notes-inline' }, notes) : null);
          }
        },
        {
          key: 'size', label: t('ptr.asn.col.size'), sortable: true, align: 'end', className: 'num',
          sortValue: (p) => p.size, render: (p) => (p.version === 4 ? formatNumber(p.size) : `/${p.length}`)
        },
        { key: 'notes', label: t('ptr.asn.col.notes'), searchable: false, className: 'ptr-asn-notes', render: (p) => prefixNotes(p) }
      ]
    });
    renderSelection();
    syncPicker = renderSelection;
    return Card({
      className: 'ptr-asn', title: t('ptr.asn.title', { asn: entry.asn }), icon: 'network',
      children: h('div', { class: 'stack-sm' },
        summary,
        h('p', { class: 'muted text-sm' }, t('ptr.asn.pick', { max: formatNumber(SWEEP_MAX_ADDRESSES) })),
        table.el,
        h('div', { class: 'ptr-asn-foot' }, selectedEl, h('div', { class: 'cluster' }, clearBtn, sweepBtn)),
        pickIssues)
    });
  }

  /* --- initial state ------------------------------------------------------- */
  renderParsed();
  renderConcurrency();
  if (session.asn) followAsn(session.asn);
  if (session.job) attach(session.job);
  else renderHeaderActions();
  if (session.prompt && parsed.ok) showPrompt();

  cleanups.push(state.subscribe(({ key }) => {
    if (key === 'settings') renderConcurrency();
    if (key === 'inventory' && ui) ui.refocus();
  }));

  active = {
    applyParams(params) {
      if (applyRoute(params)) {
        targetField.value = session.text;
        focusField.value = session.focus;
        renderParsed();
        if (parsed.ok) showPrompt();
      }
      return true;
    }
  };

  return () => {
    cleanups.forEach((fn) => fn());
    if (ui) ui.dispose();
    ui = null;
    active = null;
  };
}

/**
 * Pre-fill the form from route params (`target`, `focus`); a link waits for a click. The target
 * this page put into the URL itself (the last run, `session.routeTarget`) is not a new link:
 * a reload or a re-mount keeps what the form holds.
 * @returns {boolean} whether the params carried a new target
 */
function applyRoute(params) {
  const raw = params && typeof params.target === 'string' ? params.target : '';
  const target = splitList(raw).join('\n');
  if (!target || splitList(raw).join(',') === session.routeTarget) return false;
  session.routeTarget = splitList(raw).join(',');
  session.text = target;
  session.focus = params.focus ? String(params.focus) : '';
  session.prompt = true;
  return true;
}

/**
 * Take new route params (`#/ptr?target=…`) without re-mounting.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.applyParams(params) : false;
}

/** Nothing else to clean up (a running sweep continues in the background). */
export function unmount() {}

export default { id, titleKey, icon, mount, unmount, update };

/* ------------------------------------------------------------------------ */
/* Job UI                                                                   */
/* ------------------------------------------------------------------------ */

const STATUS_VARIANT = { confirmed: 'ok', mismatch: 'warn', 'no-ptr': 'neutral', nxdomain: 'neutral', servfail: 'error', error: 'error' };
const STATUS_ICON = { confirmed: 'check', mismatch: 'alert', servfail: 'x-circle', error: 'x-circle' };

/** A template with its placeholders as chips: `{ip}.isp.example.net`. */
function templateEl(template) {
  const parts = String(template).split(/(\{ip\}|\{n\})/);
  return h('span', { class: 'ptr-template mono' }, parts.filter(Boolean).map((p) => (p === '{ip}' || p === '{n}'
    ? h('span', { class: 'ptr-ph' }, p === '{ip}' ? 'IP' : 'n')
    : p)));
}

function statusBadge(status) {
  return Badge(t(`ptr.st.${status}`), { variant: STATUS_VARIANT[status] || 'neutral', icon: STATUS_ICON[status] || null, title: t(`ptr.st.${status}.title`) });
}

function buildJobUI(job, ctx, { focus, onFinish }) {
  const { state } = ctx;

  /* progress */
  const progress = ProgressBar({ label: t('ptr.progress') });
  const meta = h('div', { class: 'ptr-meta text-sm muted' });
  const notice = h('div');
  const progressCard = h('div', { class: 'card ptr-progress', dataset: { status: job.status } },
    h('div', { class: 'stack-sm' }, progress, meta), notice);

  /* stats */
  const inv = () => state.inventory.servers.length > 0;
  const pick = (f) => () => setFilter(f, { chosen: true });
  const stat = {
    addresses: StatCard({ label: t('ptr.stat.addresses'), icon: 'network', variant: 'accent', onClick: pick('all') }),
    named: StatCard({ label: t('ptr.stat.named'), icon: 'swap', variant: 'info', onClick: pick('ptr') }),
    confirmed: StatCard({ label: t('ptr.stat.confirmed'), icon: 'check-circle', variant: 'ok', onClick: pick('confirmed') }),
    none: StatCard({ label: t('ptr.stat.none'), icon: 'minus-circle', variant: 'unresolved', onClick: pick('none') }),
    failed: StatCard({ label: t('ptr.stat.failed'), icon: 'x-circle', variant: 'nxdomain', onClick: pick('failed') }),
    // The sixth card: names under the focus domain, or (without one) the matched servers.
    focus: StatCard({ label: t('ptr.stat.focus', { domain: '' }), icon: 'target', variant: 'accent', onClick: pick('focus') }),
    servers: StatCard({ label: t('ptr.stat.servers'), icon: 'server', variant: 'direct' })
  };
  const statFilters = { addresses: 'all', named: 'ptr', confirmed: 'confirmed', none: 'none', failed: 'failed', focus: 'focus' };
  const statsGrid = h('div', { class: 'stat-grid ptr-stats' });
  Object.entries(stat).forEach(([k, s]) => {
    s.el.dataset.stat = k;
    statsGrid.append(s.el);
  });

  /* table */
  const filterSel = select({
    label: t('ptr.filter.label'),
    size: 'sm',
    value: session.filter,
    className: 'ptr-filter',
    options: SWEEP_FILTERS.map((f) => ({ value: f, label: t(`ptr.filter.${f}`) })),
    onChange: (v) => setFilter(v, { chosen: true })
  });
  filterSel.input.dataset.role = 'ptr-filter';
  const expandBox = checkbox({
    label: t('ptr.expand'),
    checked: session.expand,
    className: 'ptr-expand',
    onChange: (on) => {
      session.expand = on;
      syncRows();
    }
  });
  expandBox.input.dataset.role = 'ptr-expand';
  const namesBtn = Button({ label: t('ptr.names'), icon: 'download', size: 'sm', variant: 'ghost', title: t('ptr.namesTitle'), dataset: { action: 'ptr-names' }, onClick: () => downloadNames() });
  const scanBtn = Button({ label: t('ptr.toScan'), icon: 'layers', size: 'sm', dataset: { action: 'ptr-to-scan' }, onClick: () => handOffToScan() });
  const invBtn = Button({ label: t('ptr.toInventory'), icon: 'server', size: 'sm', dataset: { action: 'ptr-to-inventory' }, onClick: () => addToInventory() });

  const hostLink = (name, type = 'A,AAAA') => h('a', { class: 'mono', href: ctx.href('lookup', { name, type }) }, name);
  const serversCell = (servers) => (servers.length
    ? h('div', { class: 'cluster' }, servers.map((s) => Badge(s.name, { variant: 'direct', icon: 'server', title: s.ip })))
    : null);

  // A pattern row's search text holds every member's (addresses, names, statuses, operators,
  // servers), so a member that matches on its own never sits in a row the search hides.
  const providerName = (c) => (c && c.provider ? c.provider.name : '');
  const columns = [
    {
      key: 'ip', label: t('ptr.col.ip'), sortable: true, sortValue: (r) => r.sortKey,
      searchValue: (r) => (r.type === 'pattern' ? r.members.map((m) => m.ip).join(' ') : r.result.ip),
      render: (r) => (r.type === 'pattern'
        ? h('div', { class: 'ptr-ipcell' },
          h('span', { class: 'ptr-count' }, t('ptr.pattern.count', { count: r.members.length })),
          h('span', { class: 'muted text-xs mono' }, `${r.members[0].ip} – ${r.members[r.members.length - 1].ip}`))
        : h('span', { class: 'mono ptr-ip' }, r.result.ip))
    },
    {
      key: 'ptr', label: t('ptr.col.ptr'), sortable: true,
      sortValue: (r) => (r.type === 'pattern' ? r.template : r.result.names[0] || null),
      searchValue: (r) => (r.type === 'pattern' ? `${r.template} ${r.members.flatMap((m) => m.names).join(' ')}` : r.result.names.join(' ')),
      render: (r) => {
        if (r.type === 'pattern') {
          return h('div', { class: 'ptr-pattern', title: t('ptr.pattern.title', { count: r.members.length }) },
            templateEl(r.template), Badge(t('ptr.pattern.badge'), { variant: 'info', icon: 'layers' }));
        }
        const res = r.result;
        if (!res.names.length) return null;
        const f = focus();
        return h('div', { class: 'ptr-names' },
          TruncatedList(res.names, {
            max: 2,
            render: (n) => h('span', { class: ['ptr-name', { 'is-focus': isFocusName(n, f) }] }, hostLink(n))
          }),
          r.focus ? Badge(t('ptr.focusBadge'), { variant: 'accent' }) : null,
          res.template && !r.focus ? Badge(t('ptr.templated'), { title: t('ptr.templatedTitle') }) : null);
      }
    },
    {
      key: 'check', label: t('ptr.col.check'), sortable: true,
      sortValue: (r) => (r.type === 'pattern' ? 'confirmed' : r.result.status),
      searchValue: (r) => (r.type === 'pattern'
        ? FCRDNS_STATUSES.filter((s) => r.counts[s]).map((s) => `${s} ${t(`ptr.st.${s}`)}`).join(' ')
        : `${r.result.status} ${t(`ptr.st.${r.result.status}`)}`),
      render: (r) => {
        if (r.type === 'pattern') {
          const all = r.counts.confirmed === r.members.length;
          const badge = Badge(t('ptr.pattern.check', { confirmed: formatNumber(r.counts.confirmed), count: r.members.length }), { variant: all ? 'ok' : 'warn', icon: all ? 'check' : 'alert' });
          // The filter or the search keeps only some of the pattern's addresses (and so does an export).
          const kept = narrowed() ? rowResults(r).length : r.members.length;
          return kept < r.members.length
            ? h('div', { class: 'ptr-check' }, badge, h('span', { class: 'ptr-matching text-xs muted', title: t('ptr.pattern.matchingTitle'), dataset: { kept: String(kept) } },
              t('ptr.pattern.matching', { count: kept, total: formatNumber(r.members.length) })))
            : badge;
        }
        const el = statusBadge(r.result.status);
        el.dataset.status = r.result.status;
        return el;
      }
    },
    {
      key: 'operator', label: t('ptr.col.operator'), sortable: true,
      sortValue: (r) => (r.type === 'address' && r.result.classification.provider ? r.result.classification.provider.name : null),
      searchValue: (r) => (r.type === 'pattern' ? [...new Set(r.members.map((m) => providerName(m.classification)))].join(' ') : providerName(r.result.classification)),
      render: (r) => {
        const c = r.type === 'pattern' ? r.classification : r.result.classification;
        return c && c.provider ? KindBadge(c) : null;
      }
    },
    {
      key: 'server', label: t('ptr.col.server'), sortable: true,
      sortValue: (r) => (r.servers[0] ? r.servers[0].name : null),
      searchValue: (r) => r.servers.map((s) => s.name).join(' '),
      render: (r) => serversCell(r.servers)
    }
  ];
  /** The search text the table last filtered pattern rows by (a new one re-applies the filter). */
  let appliedSearch = '';
  let table = null;
  table = DataTable({
    caption: t('ptr.results', { target: job.label }),
    search: true,
    pageSize: 200,
    empty: t('ptr.empty.running'),
    noMatch: t('ptr.noMatch'),
    rowKey: (r) => r.key,
    sort: { key: 'ip', dir: 'asc' },
    className: 'ptr-table',
    rowClass: (r) => ['ptr-row', `ptr-row-${r.type}`, { 'is-focus': r.focus }],
    toolbar: h('div', { class: 'ptr-toolbar' }, filterSel.el, expandBox.el, namesBtn, scanBtn, invBtn),
    details: (r) => (r.type === 'pattern' ? patternDetails(r) : addressDetails(r)),
    export: { formats: ['csv', 'json'], onExport: (format, rows) => exportRows(format, rows) },
    columns,
    onChange: () => {
      if (table && table.getSearch() !== appliedSearch) applyFilter();
    }
  });

  /* the filter and the search judge a pattern row's addresses one by one */
  const searchable = columns.filter((c) => c.searchable !== false && c.searchValue);
  /** The search box's terms, normalised and split as the table does. */
  const searchTerms = () => normalizeSearch(table ? table.getSearch() : '').split(/\s+/).filter(Boolean);
  const narrowed = () => session.filter !== 'all' || searchTerms().length > 0;
  /**
   * A pattern member against the search terms, as its own row would be (what "Expand patterns"
   * lists): its address, names, status, operator and matched server.
   */
  const memberMatch = (row, terms) => (terms.length ? (m) => {
    const own = { type: 'address', key: m.ip, result: m, focus: false, servers: row.servers.filter((s) => s.ip === m.ip) };
    const text = normalizeSearch(searchable.map((c) => String(c.searchValue(own) ?? '')).join('\u0001'));
    return terms.every((term) => text.includes(term));
  } : null);
  /** The addresses a shown row stands for under the current filter and search (what an export writes). */
  const rowResults = (row, terms = searchTerms()) => sweepRowResults(row, session.filter, { match: row.type === 'pattern' ? memberMatch(row, terms) : null });

  /**
   * Apply the filter and the search: an address row by lib/ptrsweep sweepRowMatches (the table
   * applies the search), a pattern row while one of its addresses passes both on its own. The
   * pattern rows are re-rendered for their "N of M match" note.
   */
  function applyFilter() {
    appliedSearch = table.getSearch();
    const terms = searchTerms();
    table.setFilter(narrowed()
      ? (row) => (row.type === 'pattern' ? rowResults(row, terms).length > 0 : sweepRowMatches(row, session.filter))
      : null);
    for (const row of table.getRows()) if (row.type === 'pattern') table.updateRow(row);
  }
  applyFilter();

  const resultsTitleId = uid('ptr-results');
  const el = h('section', { class: 'stack ptr-results', attrs: { 'aria-labelledby': resultsTitleId }, dataset: { job: job.id } },
    h('h2', { class: 'section-title ptr-results-title', id: resultsTitleId }, t('ptr.results', { target: job.label })),
    progressCard, statsGrid, table.el);

  /* rows, kept stable per key so an expanded row stays open while results stream in */
  const rowCache = new Map();
  function syncRows() {
    const rows = sweepRows(job.results, { focus: focus(), collapse: !session.expand, index: ctx.getInventoryIndex() }).map((r) => {
      const prev = rowCache.get(r.key);
      if (prev && prev.type === r.type) {
        for (const k of Object.keys(prev)) if (!(k in r)) delete prev[k];
        return Object.assign(prev, r);
      }
      rowCache.set(r.key, r);
      return r;
    });
    table.setRows(rows);
    table.refresh();
    renderStats();
    renderActions();
  }
  const syncSoon = throttle(syncRows, 250);

  /** Show `f` ({@link SWEEP_FILTERS}); `chosen`: the user picked it (the select or a stat card). */
  function setFilter(f, { chosen = false } = {}) {
    if (chosen) session.filterChosen = true;
    session.filter = SWEEP_FILTERS.includes(f) ? f : 'all';
    filterSel.value = session.filter;
    applyFilter();
    for (const [k, v] of Object.entries(statFilters)) stat[k].set({ pressed: v === session.filter });
  }

  function renderStats() {
    const f = focus();
    const s = sweepSummary(job.results, { focus: f });
    stat.addresses.set({ value: job.planned, hint: t('ptr.stat.addressesHint', { v4: formatNumber(job.planned - job.addresses.filter((ip) => ip.includes(':')).length), v6: formatNumber(job.addresses.filter((ip) => ip.includes(':')).length) }) });
    stat.named.set({ value: s.withPtr, hint: t('ptr.stat.namedHint', { count: s.templated }) });
    stat.confirmed.set({ value: s.byStatus.confirmed, hint: confirmedHint(s) });
    stat.none.set({ value: s.noReverse, hint: t('ptr.stat.noneHint', { nx: formatNumber(s.byStatus.nxdomain), empty: formatNumber(s.byStatus['no-ptr']) }) });
    stat.failed.set({ value: s.failed, hint: t('ptr.stat.failedHint', { count: s.byStatus.servfail }), variant: s.failed ? 'error' : 'nxdomain' });
    stat.focus.el.hidden = !f;
    stat.servers.el.hidden = !!f;
    if (f) stat.focus.set({ label: t('ptr.stat.focus', { domain: f }), value: s.focus });
    else {
      const servers = new Set(sweepRows(job.results, { collapse: false, index: ctx.getInventoryIndex() }).flatMap((r) => r.servers.map((x) => x.serverId)));
      stat.servers.set({ value: inv() ? servers.size : '—', hint: inv() ? null : t('ptr.stat.serversNone') });
    }
    for (const [k, v] of Object.entries(statFilters)) stat[k].set({ pressed: v === session.filter });
  }

  function renderActions() {
    const f = focus();
    const names = scanHandoff(job.results, { focus: f }).names;
    const adds = inventoryAdditions(job.results, { servers: state.inventory.servers, index: ctx.getInventoryIndex(), focus: f });
    namesBtn.disabled = !sweepNames(job.results, { focus: f }).length;
    scanBtn.disabled = !names.length || job.status === 'running';
    scanBtn.title = t('ptr.toScanTitle', { count: names.length });
    invBtn.disabled = !adds.length || job.status === 'running';
    invBtn.title = adds.length ? t('ptr.toInventoryTitle', { count: adds.length }) : t('ptr.inv.none');
    expandBox.el.hidden = !job.results.some((r) => r.template);
  }

  const renderProgress = throttle(() => {
    if (job.status === 'running') {
      progress.set(job.results.length, job.planned);
      meta.textContent = t('ptr.meta.running', { done: formatNumber(job.results.length), total: formatNumber(job.planned), time: formatDuration(Date.now() - job.startedAt) });
    } else {
      meta.textContent = t('ptr.meta.done', { count: job.results.length, time: formatDuration((job.finishedAt || new Date()) - job.startedAt), when: formatDateTime(job.finishedAt || new Date()) });
    }
  }, 100);

  /* details */
  function addressDetails(r) {
    const res = r.result;
    const f = focus();
    const resolver = res.resolver ? (getResolver(res.resolver) || { name: res.resolver }).name : null;
    const c = res.classification;
    return KeyValueList([
      { key: t('ptr.d.query'), value: res.query, mono: true, copy: true },
      res.names.length ? { key: t('ptr.d.names'), value: h('div', { class: 'cluster' }, res.names.map((n) => h('span', { class: ['ptr-name', { 'is-focus': isFocusName(n, f) }] }, hostLink(n)))) } : null,
      res.forward.length ? {
        key: t('ptr.d.forward'),
        value: h('ul', { class: 'ptr-forward' }, res.forward.map((fw) => h('li', { dataset: { state: fw.state } },
          h('span', { class: 'mono' }, fw.name), ' — ',
          h('span', { class: `ptr-fwd ptr-fwd-${fw.state}` }, t(`ptr.fwd.${fw.state}`)),
          fw.addresses.length ? h('span', { class: 'mono muted' }, ` (${fw.addresses.join(', ')})`) : null)),
        res.unchecked ? h('li', { class: 'muted' }, t('ptr.d.unchecked', { count: res.unchecked })) : null)
      } : null,
      res.delegated ? { key: t('ptr.d.delegated'), value: res.delegated, mono: true } : null,
      res.template ? { key: t('ptr.d.template'), value: h('div', { class: 'stack-sm' }, templateEl(res.template.template), h('span', { class: 'muted text-xs' }, t(`ptr.pattern.${res.template.kind}`))) } : null,
      c && c.provider ? { key: t('ptr.d.operator'), value: t(c.reasonKey, { provider: c.provider.name }) } : null,
      resolver ? { key: t('ptr.d.resolver'), value: resolver } : null,
      res.error ? { key: t('ptr.d.error'), value: res.error, mono: true } : null,
      {
        key: t('ptr.d.links'),
        value: h('div', { class: 'cluster' },
          h('a', { href: ctx.href('ip', { ips: res.ip }) }, t('nav.ip')),
          h('a', { href: ctx.href('lookup', { name: res.query, type: 'PTR' }) }, t('nav.lookup')))
      }
    ], { className: 'ptr-details' });
  }

  function patternDetails(r) {
    return KeyValueList([
      { key: t('ptr.d.template'), value: h('div', { class: 'stack-sm' }, templateEl(r.template), h('span', { class: 'muted text-xs' }, t(`ptr.pattern.${r.kind}`))) },
      {
        key: t('ptr.d.members'),
        value: TruncatedList(r.members, {
          max: 12,
          render: (m) => h('span', { class: 'ptr-member' }, h('span', { class: 'mono' }, m.ip), ' → ', h('span', { class: 'mono' }, m.names[0]), ' ',
            m.status === 'confirmed' ? null : statusBadge(m.status))
        })
      }
    ], { className: 'ptr-details' });
  }

  /* exports and hand-offs */
  /** The export writes the addresses the shown rows stand for: of a pattern row, the members that pass on their own. */
  function exportRows(format, rows) {
    const terms = searchTerms();
    const results = rows.flatMap((r) => rowResults(r, terms)).sort((a, b) => a.index - b.index);
    const f = focus();
    const subject = job.label.replace(/[^0-9a-z.:-]+/gi, '_').slice(0, 40);
    const name = timestampedName('reverse-dns', format, subject);
    let file;
    if (format === 'csv') {
      file = downloadText(name, toCsv(sweepExportRows(results, { focus: f, index: ctx.getInventoryIndex() }), SWEEP_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
    } else {
      // The summary counts the whole sweep; the filter and search that hid the other rows are recorded.
      file = downloadText(name, `${toJson(sweepExportJson(job.results, {
        exported: results, filter: { show: session.filter, search: table.getSearch() }, target: job.target, focus: f,
        startedAt: job.startedAt, finishedAt: job.finishedAt, planned: job.planned, aborted: job.status === 'cancelled',
        index: ctx.getInventoryIndex(), version: ctx.version
      }))}\n`, 'application/json;charset=utf-8');
    }
    toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
  }

  function downloadNames() {
    const names = sweepNames(job.results, { focus: focus() });
    if (!names.length) return;
    const file = downloadText('names.txt', `${names.join('\n')}\n`);
    toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
  }

  function handOffToScan() {
    const ho = scanHandoff(job.results, { focus: focus() });
    if (!ho.names.length || !ho.domains.length) {
      toast(t('ptr.scan.none'), { type: 'info' });
      return;
    }
    state.setSession('namesScanIntent', buildNamesIntent({ names: ho.names, domains: ho.domains, label: job.label }));
    ctx.navigate('subdomains', { domain: ho.domains.join(',') });
  }

  function addToInventory() {
    // An unsaved draft of the Servers editor is kept, never replaced by the saved text; what
    // it already holds (an earlier click included) is not added again.
    const draft = state.getSession('inventoryDraft');
    const base = draft ?? state.inventory.text;
    const adds = inventoryAdditions(job.results, { servers: parseInventory(base).servers, focus: focus() });
    if (!adds.length) {
      toast(t(typeof draft === 'string' && draft !== state.inventory.text ? 'ptr.inv.inDraft' : 'ptr.inv.none'), { type: 'info' });
      return;
    }
    const out = inventoryDraft(base, adds, { label: job.label, date: new Date() });
    if (out.text === null) {
      manualAdd(out);
      return;
    }
    state.setSession('inventoryDraft', out.text);
    const message = out.group
      ? t(out.newGroup ? 'ptr.inv.addedGroup' : 'ptr.inv.addedToGroup', { count: adds.length, group: out.group })
      : t('ptr.inv.added', { count: adds.length });
    toast(message, { type: 'info', timeout: 8000 });
    ctx.navigate('inventory');
  }

  /**
   * The server list is in a format this view does not write (or the addition would not read
   * back as expected): the editor is left alone and the hosts are offered as lines to copy.
   */
  function manualAdd(out) {
    const text = `${out.lines.join('\n')}\n`;
    const why = out.reason === 'format'
      ? t('ptr.inv.manualFormat', { format: INVENTORY_FORMAT_NAMES[out.format] || out.format })
      : t('ptr.inv.manualCheck');
    Modal({
      title: t('ptr.inv.manualTitle'),
      className: 'ptr-inv-manual',
      content: h('div', { class: 'stack-sm' },
        h('p', { class: 'modal-message', dataset: { reason: out.reason, format: out.format } }, why),
        CodeBlock(text, { label: t('ptr.inv.manualLines', { count: out.lines.length }), maxHeight: '16rem' })),
      actions: [
        { label: t('common.close'), value: null },
        {
          label: t('common.download'),
          icon: 'download',
          onClick: () => {
            const file = downloadText(timestampedName('reverse-dns-servers', 'txt'), text);
            toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
            return false;
          }
        },
        { label: t('ptr.inv.openServers'), icon: 'server', variant: 'primary', value: 'open', autofocus: true }
      ]
    }).open().then((value) => {
      if (value === 'open') ctx.navigate('inventory');
    });
  }

  /* lifecycle */
  /** Show the job's end; `live`: it just ended (announced), else a re-mount shows a finished job. */
  function finish(live) {
    clear(notice);
    progressCard.dataset.status = job.status;
    // A re-mounted view shows the real count, not the bar's default scale.
    progress.set(job.results.length, job.planned);
    if (job.status === 'done') {
      progress.done(t('ptr.progress.done'));
      progress.setVariant('ok');
      if (live) announce(t('ptr.doneToast', { count: job.results.length }));
    } else if (job.status === 'cancelled') {
      progress.setVariant('warn');
      progress.setLabel(t('ptr.progress.stopped'));
      notice.append(Alert({ variant: 'warn', compact: true, message: t('ptr.stoppedNote', { done: formatNumber(job.results.length), total: formatNumber(job.planned) }) }));
    } else if (job.status === 'error') {
      progress.setVariant('error');
      notice.append(ErrorBanner(job.error, { title: t('ptr.failed') }));
    }
    table.setLoading(false);
    syncRows();
    // The default filter would hide every row of a sweep that found no PTR name: show them all.
    if (!session.filterChosen && session.filter === 'ptr' && job.results.length && !job.results.some((r) => r.names.length)) setFilter('all');
    renderProgress();
    stopTicker();
    onFinish();
  }

  let ticker = null;
  function stopTicker() {
    if (ticker) clearInterval(ticker);
    ticker = null;
  }

  const listener = (type) => {
    if (type === 'result') {
      syncSoon();
      renderProgress();
    } else if (type === 'done' || type === 'cancelled' || type === 'error') {
      finish(true);
    }
  };

  syncRows();
  renderProgress();
  if (job.status === 'running') {
    table.setLoading(true);
    ticker = setInterval(renderProgress, 1000);
    job.listeners.add(listener);
  } else {
    finish(false);
  }

  return {
    el,
    /** The focus domain or the inventory changed: re-rank and re-match the rows. */
    refocus: debounce(() => syncRows(), 150),
    dispose() {
      job.listeners.delete(listener);
      stopTicker();
    }
  };
}
