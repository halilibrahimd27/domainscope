/**
 * views/retire.js — "Retire an IP": before a server is switched off or renumbered, what still
 * points at its address? Every DNS record, CNAME chain, SPF mechanism, MX / NS host, HTTPS hint and
 * zone-file record (proxied origins included) that reaches it, checked live over DoH, as a change
 * list grouped by domain, worst first (lib/retire.js).
 *
 * - Input: addresses and networks up to a /24 (lib/retire.parseRetireTargets), and the domains to
 *   check. An empty domain box is filled in from what this page session already knows — the last
 *   Subdomains / SSL Targets scan (`state.session.scanHosts`) and the imported zone
 *   (`state.session.zone`) — and says so; a target carried over from another tool goes into its
 *   box (an address into the addresses, a domain into the domains) while the box holds no draft.
 * - Evidence, each with its status chip (the Subdomains source-chip pattern): public DNS (each
 *   domain's own name, its known host names, MX and NS hosts, the HTTPS record), SPF (the include
 *   tree, lib/health.js), the imported zone (its records, each verified live), the server list
 *   (which server owns the address), and a passive reverse-IP lookup (HackerTarget and ip.thc.org,
 *   only on a click: a small free quota) whose names stay "unverified until checked" — "Check these
 *   too" adds their domains and checks them. Known host names come from the page session's last scan
 *   or the zone; a domain without any gets a quick Small-wordlist discovery OFFERED, never run by itself.
 * - Output: one card per domain (the zone's origin, other zones reached, passive hits), each record
 *   with its severity, current value, what to change and the evidence; CSV / JSON and Copy summary.
 *
 * The job belongs to this module (like Reverse DNS): it keeps running while another tool is open,
 * and a language switch keeps it. Shareable: `#/retire?ips=192.0.2.10&domains=example.com` fills the
 * form and waits for a click (a check sends hundreds of DNS queries; a link never starts one).
 */

import { h, clear, debounce } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CopyButton, Disclosure, EmptyState, ErrorBanner, Icon, ProgressBar, StatCard, announce, textarea, toast
} from '../ui/components.js';
import { t, registerStrings, formatNumber, formatDateTime, getLang } from '../i18n.js';
import {
  parseRetireTargets, parseDomainList, retireTokens, knownHostsFor, zoneCandidates, runRetireCheck, buildChanges, breakingChanges,
  inventoryOwners, passiveNewNames, retireExportRows, retireExportJson, RETIRE_CSV_COLUMNS, RETIRE_MAX_DOMAINS,
  RETIRE_MAX_HOSTS, PASSIVE_MAX_ADDRESSES, PASSIVE_SOURCES
} from '../lib/retire.js';
import { createIpIntel } from '../lib/ipintel.js';
import { estimateQueries } from '../lib/scanplan.js';
import { isPrivateIP } from '../lib/netinfo.js';
import { isSubdomainOf, registrableDomain } from '../lib/domain.js';
import { fillReplaces, isFillOnly } from '../lib/session.js';
import { errorKind } from '../lib/util.js';
import { toCsv, toJson } from '../lib/export.js';
import { permalinkParams } from '../lib/summary.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { SummaryButton } from '../ui/summary-button.js';
import { state as stateSingleton } from '../state.js';

/** Route id (`#/retire`). */
export const id = 'retire';
/** i18n key of the page title. */
export const titleKey = 'nav.retire';
/** Icon name (ui/components.js Icon). */
export const icon = 'unlink';

/** The form goes into a shared link only up to this many characters. */
export const LINK_MAX_CHARS = 400;
/** Records shown per group before "Show all". */
export const GROUP_PAGE = 100;
/** Domains checked side by side (each one's lookups go through the DohClient's own limiter). */
const DOMAIN_CONCURRENCY = 2;

const SEVERITY_VARIANT = Object.freeze({ mail: 'error', ns: 'error', live: 'warn', origin: 'warn', chain: 'warn', file: 'info', stale: 'neutral', unknown: 'neutral' });
const VERIFIED_VARIANT = Object.freeze({ live: 'ok', file: 'neutral', hidden: 'info', internal: 'neutral', unverified: 'neutral', unknown: 'neutral' });

registerStrings('en', {
  'retire.ips.label': 'Addresses to retire',
  'retire.ips.placeholder': '192.0.2.10\n2001:db8::10\n192.0.2.0/28',
  'retire.ips.hint': 'The server’s addresses: one address or network per line, up to a /24 (IPv6: a /120). # starts a comment.',
  'retire.domains.label': 'Domains to check',
  'retire.domains.placeholder': 'example.com\nexample.net',
  'retire.domains.hint': 'Every domain whose DNS may still point at the addresses. For each one: its own name, the host names this page session knows, MX, NS, SPF and the HTTPS record.',
  'retire.run': 'Check references',
  'retire.stop': 'Stop',
  'retire.busy': 'Checking what points at the address',
  'retire.busyDiscover': 'Discovering host names',
  'retire.busyPassive': 'Asking passive reverse-IP services',
  'retire.privacy': 'Sends DNS queries (names and types) to your DoH resolvers; the addresses are only compared in this browser. Nothing else leaves it unless you ask for a discovery or the passive lookup.',
  'retire.required': 'Enter at least one address to retire.',
  'retire.noDomains': 'Enter at least one domain to check (or import its zone under Zone File).',
  'retire.domainsInvalid': 'Not a domain, left out: {items}',
  'retire.domainsTruncated': { one: 'Only the first {max} domains are checked ({count} more left out).', other: 'Only the first {max} domains are checked ({count} more left out).' },
  'retire.parsed': { one: '{count} address', other: '{count} addresses' },
  'retire.parsedDomains': { one: '{count} domain', other: '{count} domains' },
  'retire.issue.invalid': { one: 'Not an address or network, left out: {items}', other: 'Not addresses or networks, left out: {items}' },
  'retire.issue.too-large': '{input} is wider than a /{prefix}: retire at most {max} addresses at a time.',
  'retire.issue.host-bits': '{input} has host bits set: read as {network}.',
  'retire.issue.over-cap': 'That is {count} addresses: retire at most {max} at a time.',
  'retire.issue.private': 'Private space ({items}): public resolvers do not see internal (split-horizon) records, so only public DNS and the zone file are checked.',
  'retire.issue.nothing': 'Nothing to retire: enter an address or a network.',
  'retire.filled': 'Domains filled in from {sources}.',
  'retire.filled.scan': 'the last scan',
  'retire.filled.zone': 'the imported zone',
  'retire.filled.target': 'the current target',
  'retire.link.prompt': 'Filled in from a link. Nothing has been sent yet: press Check references.',
  'retire.hosts.title': 'Host names checked besides each domain’s own records',
  'retire.hosts.from': '{domain}: {list}',
  'retire.hosts.none': '{domain}: none known — only its own name, MX, NS, SPF and HTTPS record are checked',
  'retire.hosts.scan': { one: '{count} from the last scan', other: '{count} from the last scan' },
  'retire.hosts.zone': { one: '{count} from the imported zone', other: '{count} from the imported zone' },
  'retire.hosts.passive': { one: '{count} passive hit', other: '{count} passive hits' },
  'retire.hosts.discovered': { one: '{count} discovered', other: '{count} discovered' },
  'retire.hosts.capped': 'Only the first {max} host names are resolved.',
  'retire.discover.offer': { one: '{count} domain has no known host names: its A records and CNAMEs under it are not found without them.', other: '{count} domains have no known host names: their A records and CNAMEs are not found without them.' },
  'retire.discover.button': 'Discover host names (Small wordlist)',
  'retire.discover.title': 'Tries the Small wordlist (159 common names) under each of these domains, then checks again. About {min}–{max} DNS queries; no passive source is asked.',
  'retire.discover.running': 'Discovering host names under {domain}…',
  'retire.discover.failed': 'Discovery failed',

  'retire.chip.dns': 'Public DNS',
  'retire.chip.spf': 'SPF',
  'retire.chip.zone': 'Zone file',
  'retire.chip.servers': 'Your servers',
  'retire.chip.passive': 'Passive reverse IP',
  'retire.chip.pending': 'asking…',
  'retire.chip.dnsOk': { one: '{count} name checked', other: '{count} names checked' },
  'retire.chip.dnsFailed': { one: '{count} lookup failed', other: '{count} lookups failed' },
  'retire.chip.spfOk': { one: '{count} policy walked', other: '{count} policies walked' },
  'retire.chip.spfNone': 'no SPF record',
  'retire.chip.spfFailed': { one: '{count} could not be read', other: '{count} could not be read' },
  'retire.chip.zoneNone': 'none imported',
  'retire.chip.zoneOk': { zero: 'nothing in {zone} reaches it', one: '{count} record in {zone} reaches it', other: '{count} records in {zone} reach it' },
  'retire.chip.serversNone': 'no list saved',
  'retire.chip.serversOwner': { one: '{names} owns it', other: '{names} own it' },
  'retire.chip.serversNot': 'not in your list',
  'retire.chip.passiveIdle': 'not asked',
  'retire.chip.passiveOk': { zero: 'no names', one: '{count} name', other: '{count} names' },
  'retire.chip.passiveFailed': 'failed: {reason}',
  'retire.chip.passiveOther': 'asked for other addresses',

  'retire.passive.button': 'Find other names on the address',
  'retire.passive.title': 'Asks HackerTarget and ip.thc.org which names they saw on each address: {count} request(s) to each. HackerTarget allows about 50 free lookups a day from your address (shared with the Subdomains scan).',
  'retire.passive.tooMany': 'The passive lookup runs per address: retire at most {max} addresses to use it.',
  'retire.passive.private': 'Private addresses are never sent to a passive service.',
  'retire.passive.limited': 'daily free quota used up',
  'retire.passive.truncated': 'ip.thc.org lists {total} names for {address}; the first {count} are shown.',
  'retire.passive.src.hackertarget': 'HackerTarget',
  'retire.passive.src.thc': 'ip.thc.org',
  'retire.passive.checkToo': 'Check these too',
  'retire.passive.checkTooTitle': 'Adds {domains} to the domains and checks every passive name over DNS.',
  'retire.passive.checkNames': 'Check these names',
  'retire.passive.gone': { one: '{count} passive name no longer points here', other: '{count} passive names no longer point here' },
  'retire.passive.now': 'now {list}',
  'retire.passive.nowNone': 'no address now',

  'retire.progress': 'Checking {domain} ({done} of {total} domains)',
  'retire.progressZone': 'Verifying the zone file’s records',
  'retire.progressDone': { one: 'Checked {count} domain', other: 'Checked {count} domains' },
  'retire.stopped': 'Stopped — the domains that were not finished are not listed.',
  'retire.failed': 'The check failed',
  'retire.domainFailed': '{domain} could not be checked: {error}',
  'retire.doneToast': { one: 'Retire an IP: {count} record to change', other: 'Retire an IP: {count} records to change' },
  'retire.showResults': 'Show',

  'retire.head.title': 'What still points at {label}',
  'retire.head.checked': 'checked {time}',
  'retire.head.breaking': { one: '{count} record breaks something once {label} is gone', other: '{count} records break something once {label} is gone' },
  'retire.head.cleanup': { one: 'Nothing breaks: {count} record to clean up', other: 'Nothing breaks: {count} records to clean up' },
  'retire.head.none': 'Nothing in the checked domains points at {label}',
  'retire.head.scope': 'Not covered: internal (split-horizon) DNS and domains that are not in the list. A record found only in the zone file is not live, but a restore of the file brings it back.',
  'retire.stat.breaking': 'Must change',
  'retire.stat.mail': 'Breaks mail',
  'retire.stat.file': 'Zone file only',
  'retire.stat.unknown': 'Cannot tell',
  'retire.stat.unverified': 'Unverified',
  'retire.owners.title': 'Owned by',
  'retire.owners.others': 'also {list}',
  'retire.owners.hint': 'From your server list. Its other addresses are where a renumbered service may already live.',

  'retire.group.domain': '{domain}',
  'retire.group.zone': 'Zone file · {origin}',
  'retire.group.other': 'Other zones',
  'retire.group.otherHint': 'Records outside the checked domains that they lead to: a CNAME target, a provider’s SPF include.',
  'retire.group.passive': 'Passive reverse IP — unverified until checked',
  'retire.group.passiveHint': 'Names a passive service saw on the address at some point. Nothing here was checked: they may point elsewhere by now.',
  'retire.group.empty': 'Nothing in {domain} points at the address ({count} names checked).',
  'retire.group.failed': '{domain} could not be checked.',
  'retire.group.count': { one: '{count} record', other: '{count} records' },
  'retire.group.more': 'Show all {count}',

  'retire.col.severity': 'Severity',
  'retire.col.record': 'Record',
  'retire.col.value': 'Current value',
  'retire.col.change': 'What to change',
  'retire.col.evidence': 'Evidence',
  'retire.line': 'zone file, line {line}',
  'retire.reaches': 'reaches {list}',

  'retire.sev.mail': 'Breaks mail',
  'retire.sev.ns': 'Breaks DNS',
  'retire.sev.live': 'Address record',
  'retire.sev.origin': 'Proxy origin',
  'retire.sev.chain': 'CNAME chain',
  'retire.sev.file': 'Zone file only',
  'retire.sev.stale': 'Stale',
  'retire.sev.unknown': 'Cannot tell',
  'retire.sevTitle.mail': 'An SPF mechanism that lets the address send mail as the domain, or an MX host on it: mail breaks — and whoever gets the address next can send as you.',
  'retire.sevTitle.ns': 'A name server of the domain answers from the address: the zone stops resolving for resolvers that ask it.',
  'retire.sevTitle.live': 'An A / AAAA record or an HTTPS address hint that answers with the address (the Evidence column says whether public DNS served it).',
  'retire.sevTitle.origin': 'A proxied record’s origin: visitors never see the address, the proxy connects to it.',
  'retire.sevTitle.chain': 'A CNAME whose chain ends at the address.',
  'retire.sevTitle.file': 'Only in the imported zone file: public DNS no longer serves it.',
  'retire.sevTitle.stale': 'Points at the address but breaks nothing: an SPF term that does not authorize it, or a passive hit.',
  'retire.sevTitle.unknown': 'Cannot be told from here.',

  'retire.ver.live': 'Seen live',
  'retire.ver.file': 'Not in live DNS',
  'retire.ver.hidden': 'Behind the proxy',
  'retire.ver.internal': 'Internal name: not asked',
  'retire.ver.unverified': 'Unverified',
  'retire.ver.unknown': 'Cannot tell',
  'retire.verTitle.live': 'Public DNS served this record during the check.',
  'retire.verTitle.file': 'The zone file has it; public DNS did not serve it during the check.',
  'retire.verTitle.hidden': 'The proxy answers with its own addresses: the origin cannot be seen over DNS.',
  'retire.verTitle.internal': 'The name looks internal, so it was never sent to a public resolver.',
  'retire.verTitle.unverified': 'Not checked yet.',
  'retire.verTitle.unknown': 'The lookup failed or depends on the sender.',

  'retire.act.remove.a': 'Point it at the new address, or delete it if the service goes away.',
  'retire.act.remove.https': 'Replace the address hint with the new address, or remove it.',
  'retire.act.remove.spf': 'Replace {term} with the new address, or remove it. Left in place, whoever gets the address next can send mail as {domain}.',
  'retire.act.remove.spfStale': 'No longer needed once the address is gone: remove {term}.',
  'retire.act.narrow': '{range} still covers {address}: split it so it no longer does — or keep it if the whole range stays yours — and cover the new address.',
  'retire.act.follow.spf': 'Follows the addresses of {host}: change those records and this term follows. Nothing to edit in the SPF record.',
  'retire.act.follow.cname': 'Follows {target}: change the record that holds the address ({holder}), or point this CNAME elsewhere.',
  'retire.act.repoint.mx': 'Point the MX at a mail server that stays, or give {host} its new address first. Senders queue mail for a few days, then bounce it.',
  'retire.act.repoint.ns': 'Delegate to name servers that stay (at the registrar), or give {host} its new address first.',
  'retire.act.repoint.other': 'Point it at a host that stays, or give {host} its new address first.',
  'retire.act.glue': '{host} is inside the zone: change its address here and its glue record at the registrar (the parent zone keeps a copy).',
  'retire.act.provider': 'A record of {holder}, not yours: nothing to change there. If this server’s mail moves to a new address, make sure that service (or your own SPF record) covers it; stop using the service, and remove its include.',
  'retire.act.origin': 'Proxied: change the origin in the proxy’s DNS before switching the server off, or visitors get errors 521 / 522.',
  'retire.act.check.macro': 'Depends on the sending server (a macro such as %{i}): cannot be told from here. Check {term} by hand.',
  'retire.act.check.ptr': 'The ptr mechanism depends on the reverse DNS of the sending server: check it by hand (RFC 7208 discourages ptr).',
  'retire.act.check.lookup-failed': 'A lookup failed: check again.',
  'retire.act.check.include-failed': 'The included policy could not be read: check again later.',
  'retire.act.check.skipped': 'Not evaluated: the SPF tree needs more lookups than the check makes.',
  'retire.act.check.multiple': 'The domain publishes several SPF records (receivers treat that as an error): merge them first.',
  'retire.act.check.passive': 'Seen on the address by {sources}. Check it before changing anything.',

  'retire.ev.via': 'via {chain}',
  'retire.ev.spf': 'in the SPF policy of {holder}',
  'retire.ev.path': 'include path {path}',
  'retire.ev.qualifier': 'qualifier {qualifier}',
  'retire.ev.inert': 'passed on as no match (the include does not pass it)',
  'retire.ev.foundFor': 'found through {list}',
  'retire.ev.src.dns': 'public DNS',
  'retire.ev.src.spf': 'SPF',
  'retire.ev.src.zone': 'zone file',
  'retire.ev.src.passive': 'passive reverse IP',
  'retire.ev.src.scan': 'the last scan',
  'retire.ev.src.discovered': 'discovery',
  'retire.ev.roles.mx': 'an MX host',
  'retire.ev.roles.ns': 'a name server',
  'retire.ev.roles.spf': 'named in SPF',
  'retire.ev.proxied': 'proxied',

  'retire.emptyTitle': 'What still points at this address?',
  'retire.emptyBody': 'Before you switch a server off or give it a new address: DNS records, CNAME chains, SPF, MX and NS hosts and your zone file, checked live. A forgotten SPF ip4 breaks mail a week later.'
});

registerStrings('tr', {
  'retire.ips.label': 'Emekliye ayrılacak adresler',
  'retire.ips.placeholder': '192.0.2.10\n2001:db8::10\n192.0.2.0/28',
  'retire.ips.hint': 'Sunucunun adresleri: her satıra bir adres ya da ağ, en fazla bir /24 (IPv6: /120). # yorum başlatır.',
  'retire.domains.label': 'Kontrol edilecek alan adları',
  'retire.domains.placeholder': 'example.com\nexample.net',
  'retire.domains.hint': 'DNS’i hâlâ bu adresleri gösteriyor olabilecek her alan adı. Her biri için: kendi adı, bu oturumun bildiği host adları, MX, NS, SPF ve HTTPS kaydı.',
  'retire.run': 'Referansları kontrol et',
  'retire.stop': 'Durdur',
  'retire.busy': 'Adresi gösteren kayıtlar kontrol ediliyor',
  'retire.busyDiscover': 'Host adları keşfediliyor',
  'retire.busyPassive': 'Pasif ters IP servislerine soruluyor',
  'retire.privacy': 'DoH çözümleyicilerinize DNS sorguları (ad ve tür) gönderilir; adresler yalnızca bu tarayıcıda karşılaştırılır. Keşif ya da pasif sorgu istemediğiniz sürece başka hiçbir şey dışarı çıkmaz.',
  'retire.required': 'Emekliye ayrılacak en az bir adres girin.',
  'retire.noDomains': 'Kontrol edilecek en az bir alan adı girin (ya da zone’unu Zone Dosyası’nda içe aktarın).',
  'retire.domainsInvalid': 'Alan adı değil, dışarıda bırakıldı: {items}',
  'retire.domainsTruncated': 'Yalnızca ilk {max} alan adı kontrol edilir ({count} tanesi dışarıda bırakıldı).',
  'retire.parsed': '{count} adres',
  'retire.parsedDomains': '{count} alan adı',
  'retire.issue.invalid': 'Adres ya da ağ değil, dışarıda bırakıldı: {items}',
  'retire.issue.too-large': '{input} bir /{prefix}’ten geniş: tek seferde en fazla {max} adres emekliye ayrılabilir.',
  'retire.issue.host-bits': '{input} içinde host bitleri var: {network} olarak okundu.',
  'retire.issue.over-cap': 'Bu {count} adres ediyor: tek seferde en fazla {max} adres emekliye ayrılabilir.',
  'retire.issue.private': 'Özel (private) adres alanı ({items}): genel çözümleyiciler iç (split-horizon) kayıtları görmez; yalnızca genel DNS ve zone dosyası kontrol edilir.',
  'retire.issue.nothing': 'Emekliye ayrılacak bir şey yok: bir adres ya da ağ girin.',
  'retire.filled': 'Alan adları şuradan dolduruldu: {sources}.',
  'retire.filled.scan': 'son tarama',
  'retire.filled.zone': 'içe aktarılan zone',
  'retire.filled.target': 'geçerli hedef',
  'retire.link.prompt': 'Bir bağlantıdan dolduruldu. Henüz hiçbir şey gönderilmedi: Referansları kontrol et’e basın.',
  'retire.hosts.title': 'Her alan adının kendi kayıtlarının yanında kontrol edilen host adları',
  'retire.hosts.from': '{domain}: {list}',
  'retire.hosts.none': '{domain}: bilinen yok — yalnızca kendi adı, MX, NS, SPF ve HTTPS kaydı kontrol edilir',
  'retire.hosts.scan': 'son taramadan {count}',
  'retire.hosts.zone': 'içe aktarılan zone’dan {count}',
  'retire.hosts.passive': '{count} pasif sonuç',
  'retire.hosts.discovered': '{count} keşfedildi',
  'retire.hosts.capped': 'Yalnızca ilk {max} host adı çözümlenir.',
  'retire.discover.offer': '{count} alan adının bilinen host adı yok: onlar olmadan altındaki A kayıtları ve CNAME’ler bulunamaz.',
  'retire.discover.button': 'Host adlarını keşfet (Küçük kelime listesi)',
  'retire.discover.title': 'Bu alan adlarının her birinin altında Küçük kelime listesini (159 yaygın ad) dener, sonra yeniden kontrol eder. Yaklaşık {min}–{max} DNS sorgusu; hiçbir pasif kaynağa sorulmaz.',
  'retire.discover.running': '{domain} altındaki host adları keşfediliyor…',
  'retire.discover.failed': 'Keşif başarısız',

  'retire.chip.dns': 'Genel DNS',
  'retire.chip.spf': 'SPF',
  'retire.chip.zone': 'Zone dosyası',
  'retire.chip.servers': 'Sunucularınız',
  'retire.chip.passive': 'Pasif ters IP',
  'retire.chip.pending': 'soruluyor…',
  'retire.chip.dnsOk': '{count} ad kontrol edildi',
  'retire.chip.dnsFailed': '{count} sorgu başarısız',
  'retire.chip.spfOk': '{count} politika izlendi',
  'retire.chip.spfNone': 'SPF kaydı yok',
  'retire.chip.spfFailed': '{count} tanesi okunamadı',
  'retire.chip.zoneNone': 'içe aktarılmadı',
  'retire.chip.zoneOk': { zero: '{zone} içinde ona ulaşan kayıt yok', other: '{zone} içinde {count} kayıt ona ulaşıyor' },
  'retire.chip.serversNone': 'kayıtlı liste yok',
  'retire.chip.serversOwner': 'sahibi: {names}',
  'retire.chip.serversNot': 'listenizde yok',
  'retire.chip.passiveIdle': 'sorulmadı',
  'retire.chip.passiveOk': { zero: 'ad yok', other: '{count} ad' },
  'retire.chip.passiveFailed': 'başarısız: {reason}',
  'retire.chip.passiveOther': 'başka adresler için soruldu',

  'retire.passive.button': 'Adresteki diğer adları bul',
  'retire.passive.title': 'Her adreste hangi adları gördüklerini HackerTarget ve ip.thc.org’a sorar: her birine {count} istek. HackerTarget adresinizden günde yaklaşık 50 ücretsiz sorguya izin verir (Subdomain taramasıyla ortak).',
  'retire.passive.tooMany': 'Pasif sorgu adres başına çalışır: kullanmak için en fazla {max} adres emekliye ayırın.',
  'retire.passive.private': 'Özel (private) adresler hiçbir pasif servise gönderilmez.',
  'retire.passive.limited': 'günlük ücretsiz kota doldu',
  'retire.passive.truncated': 'ip.thc.org {address} için {total} ad listeliyor; ilk {count} tanesi gösteriliyor.',
  'retire.passive.src.hackertarget': 'HackerTarget',
  'retire.passive.src.thc': 'ip.thc.org',
  'retire.passive.checkToo': 'Bunları da kontrol et',
  'retire.passive.checkTooTitle': '{domains} alan adlarını listeye ekler ve her pasif adı DNS üzerinden kontrol eder.',
  'retire.passive.checkNames': 'Bu adları kontrol et',
  'retire.passive.gone': '{count} pasif ad artık bu adresi göstermiyor',
  'retire.passive.now': 'şimdi {list}',
  'retire.passive.nowNone': 'şimdi adresi yok',

  'retire.progress': '{domain} kontrol ediliyor ({total} alan adının {done} tanesi)',
  'retire.progressZone': 'Zone dosyasının kayıtları doğrulanıyor',
  'retire.progressDone': '{count} alan adı kontrol edildi',
  'retire.stopped': 'Durduruldu — bitmeyen alan adları listelenmiyor.',
  'retire.failed': 'Kontrol başarısız',
  'retire.domainFailed': '{domain} kontrol edilemedi: {error}',
  'retire.doneToast': 'IP emekliye ayırma: değiştirilecek {count} kayıt',
  'retire.showResults': 'Göster',

  'retire.head.title': '{label} adresini hâlâ gösterenler',
  'retire.head.checked': 'kontrol edildi: {time}',
  'retire.head.breaking': '{label} kalkınca {count} kayıt bir şeyi bozar',
  'retire.head.cleanup': 'Hiçbir şey bozulmaz: temizlenecek {count} kayıt',
  'retire.head.none': 'Kontrol edilen alan adlarında {label} adresini gösteren bir şey yok',
  'retire.head.scope': 'Kapsam dışı: iç (split-horizon) DNS ve listede olmayan alan adları. Yalnızca zone dosyasında bulunan bir kayıt canlı değildir, ama dosya geri yüklenirse geri gelir.',
  'retire.stat.breaking': 'Değişmeli',
  'retire.stat.mail': 'E-postayı bozar',
  'retire.stat.file': 'Yalnızca zone’da',
  'retire.stat.unknown': 'Anlaşılamıyor',
  'retire.stat.unverified': 'Doğrulanmadı',
  'retire.owners.title': 'Sahibi',
  'retire.owners.others': 'ayrıca {list}',
  'retire.owners.hint': 'Sunucu listenizden. Diğer adresleri, adresi değişen bir servisin zaten bulunabileceği yerlerdir.',

  'retire.group.domain': '{domain}',
  'retire.group.zone': 'Zone dosyası · {origin}',
  'retire.group.other': 'Diğer zone’lar',
  'retire.group.otherHint': 'Kontrol edilen alan adlarının dışında kalıp onların yönlendirdiği kayıtlar: bir CNAME hedefi, bir sağlayıcının SPF include’u.',
  'retire.group.passive': 'Pasif ters IP — kontrol edilene kadar doğrulanmamış',
  'retire.group.passiveHint': 'Bir pasif servisin bir zamanlar bu adreste gördüğü adlar. Hiçbiri kontrol edilmedi: şimdiye kadar başka bir yeri gösteriyor olabilirler.',
  'retire.group.empty': '{domain} içinde bu adresi gösteren bir şey yok ({count} ad kontrol edildi).',
  'retire.group.failed': '{domain} kontrol edilemedi.',
  'retire.group.count': '{count} kayıt',
  'retire.group.more': '{count} kaydın tümünü göster',

  'retire.col.severity': 'Önem',
  'retire.col.record': 'Kayıt',
  'retire.col.value': 'Şu anki değer',
  'retire.col.change': 'Ne değişmeli',
  'retire.col.evidence': 'Kanıt',
  'retire.line': 'zone dosyası, {line}. satır',
  'retire.reaches': '{list} adresine ulaşıyor',

  'retire.sev.mail': 'E-postayı bozar',
  'retire.sev.ns': 'DNS’i bozar',
  'retire.sev.live': 'Adres kaydı',
  'retire.sev.origin': 'Proxy asıl sunucusu',
  'retire.sev.chain': 'CNAME zinciri',
  'retire.sev.file': 'Yalnızca zone dosyasında',
  'retire.sev.stale': 'Eskimiş',
  'retire.sev.unknown': 'Anlaşılamıyor',
  'retire.sevTitle.mail': 'Adresin alan adı adına e-posta göndermesine izin veren bir SPF mekanizması ya da adresteki bir MX sunucusu: e-posta bozulur — ve adresi sonra kim alırsa sizin adınıza gönderebilir.',
  'retire.sevTitle.ns': 'Alan adının bir ad sunucusu bu adresten yanıt veriyor: ona soran çözümleyiciler için zone çözümlenmez olur.',
  'retire.sevTitle.live': 'Bu adresle yanıt veren bir A / AAAA kaydı ya da HTTPS adres ipucu (genel DNS’in onu sunup sunmadığını Kanıt sütunu söyler).',
  'retire.sevTitle.origin': 'Proxy’li bir kaydın asıl sunucusu: ziyaretçiler adresi görmez, proxy ona bağlanır.',
  'retire.sevTitle.chain': 'Zinciri bu adreste biten bir CNAME.',
  'retire.sevTitle.file': 'Yalnızca içe aktarılan zone dosyasında: genel DNS artık onu sunmuyor.',
  'retire.sevTitle.stale': 'Adresi gösteriyor ama bir şeyi bozmuyor: adrese izin vermeyen bir SPF terimi ya da bir pasif sonuç.',
  'retire.sevTitle.unknown': 'Buradan anlaşılamıyor.',

  'retire.ver.live': 'Canlı görüldü',
  'retire.ver.file': 'Canlı DNS’te yok',
  'retire.ver.hidden': 'Proxy arkasında',
  'retire.ver.internal': 'İç ad: sorulmadı',
  'retire.ver.unverified': 'Doğrulanmadı',
  'retire.ver.unknown': 'Anlaşılamıyor',
  'retire.verTitle.live': 'Kontrol sırasında genel DNS bu kaydı sundu.',
  'retire.verTitle.file': 'Zone dosyasında var; kontrol sırasında genel DNS onu sunmadı.',
  'retire.verTitle.hidden': 'Proxy kendi adresleriyle yanıt verir: asıl sunucu DNS üzerinden görülemez.',
  'retire.verTitle.internal': 'Ad dahili görünüyor; bu yüzden hiçbir genel çözümleyiciye gönderilmedi.',
  'retire.verTitle.unverified': 'Henüz kontrol edilmedi.',
  'retire.verTitle.unknown': 'Sorgu başarısız oldu ya da gönderene bağlı.',

  'retire.act.remove.a': 'Yeni adrese yönlendirin ya da servis kalkıyorsa silin.',
  'retire.act.remove.https': 'Adres ipucunu yeni adresle değiştirin ya da kaldırın.',
  'retire.act.remove.spf': '{term} terimini yeni adresle değiştirin ya da kaldırın. Yerinde kalırsa adresi sonra alan kişi {domain} adına e-posta gönderebilir.',
  'retire.act.remove.spfStale': 'Adres kalkınca gereksiz: {term} terimini kaldırın.',
  'retire.act.narrow': '{range} hâlâ {address} adresini kapsıyor: artık kapsamayacak şekilde bölün — tüm aralık sizde kalıyorsa olduğu gibi bırakın — ve yeni adresi ekleyin.',
  'retire.act.follow.spf': '{host} adreslerini izler: o kayıtları değiştirin, bu terim de izler. SPF kaydında düzenlenecek bir şey yok.',
  'retire.act.follow.cname': '{target} adresini izler: adresi tutan kaydı ({holder}) değiştirin ya da bu CNAME’i başka yere yönlendirin.',
  'retire.act.repoint.mx': 'MX’i kalacak bir e-posta sunucusuna yönlendirin ya da önce {host} için yeni adresi verin. Gönderenler e-postayı birkaç gün kuyrukta tutar, sonra geri çevirir.',
  'retire.act.repoint.ns': 'Kalacak ad sunucularına devredin (kayıt firmasında) ya da önce {host} için yeni adresi verin.',
  'retire.act.repoint.other': 'Kalacak bir host’a yönlendirin ya da önce {host} için yeni adresi verin.',
  'retire.act.glue': '{host} zone’un içinde: adresini burada ve glue kaydını kayıt firmasında değiştirin (üst zone bir kopyasını tutar).',
  'retire.act.provider': '{holder} kaydı, sizin değil: orada değiştirilecek bir şey yok. Bu sunucunun e-postası yeni bir adrese taşınırsa o servisin (ya da kendi SPF kaydınızın) yeni adresi kapsadığından emin olun; servisi bırakırsanız include’unu kaldırın.',
  'retire.act.origin': 'Proxy’li: sunucuyu kapatmadan önce asıl sunucuyu proxy’nin DNS’inde değiştirin, yoksa ziyaretçiler 521 / 522 hatası alır.',
  'retire.act.check.macro': 'Gönderen sunucuya bağlı (%{i} gibi bir makro): buradan anlaşılamaz. {term} terimini elle kontrol edin.',
  'retire.act.check.ptr': 'ptr mekanizması gönderen sunucunun ters DNS’ine bağlı: elle kontrol edin (RFC 7208 ptr kullanılmamasını önerir).',
  'retire.act.check.lookup-failed': 'Bir sorgu başarısız oldu: yeniden kontrol edin.',
  'retire.act.check.include-failed': 'Dahil edilen politika okunamadı: daha sonra yeniden kontrol edin.',
  'retire.act.check.skipped': 'Değerlendirilmedi: SPF ağacı, kontrolün yaptığından fazla sorgu gerektiriyor.',
  'retire.act.check.multiple': 'Alan adı birden fazla SPF kaydı yayınlıyor (alıcılar bunu hata sayar): önce birleştirin.',
  'retire.act.check.passive': '{sources} bu adreste görmüş. Bir şeyi değiştirmeden önce kontrol edin.',

  'retire.ev.via': 'üzerinden: {chain}',
  'retire.ev.spf': '{holder} SPF politikasında',
  'retire.ev.path': 'include yolu {path}',
  'retire.ev.qualifier': 'niteleyici {qualifier}',
  'retire.ev.inert': 'eşleşme yok olarak aktarılır (include onu geçirmez)',
  'retire.ev.foundFor': '{list} üzerinden bulundu',
  'retire.ev.src.dns': 'genel DNS',
  'retire.ev.src.spf': 'SPF',
  'retire.ev.src.zone': 'zone dosyası',
  'retire.ev.src.passive': 'pasif ters IP',
  'retire.ev.src.scan': 'son tarama',
  'retire.ev.src.discovered': 'keşif',
  'retire.ev.roles.mx': 'bir MX sunucusu',
  'retire.ev.roles.ns': 'bir ad sunucusu',
  'retire.ev.roles.spf': 'SPF’te geçiyor',
  'retire.ev.proxied': 'proxy’li',

  'retire.emptyTitle': 'Bu adresi hâlâ ne gösteriyor?',
  'retire.emptyBody': 'Bir sunucuyu kapatmadan ya da ona yeni bir adres vermeden önce: DNS kayıtları, CNAME zincirleri, SPF, MX ve NS sunucuları ve zone dosyanız, canlı kontrol edilmiş. Unutulan bir SPF ip4 bir hafta sonra e-postayı bozar.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for the tests)                                    */
/* ------------------------------------------------------------------------ */

/**
 * The route params of the form: the address tokens and the domains, comma-joined; null when
 * either is empty or the link would be longer than {@link LINK_MAX_CHARS}.
 * @param {string} ipsText
 * @param {string} domainsText
 * @returns {{ ips: string, domains?: string }|null}
 */
export function shareParams(ipsText, domainsText) {
  const ips = retireTokens(ipsText).join(',');
  if (!ips) return null;
  const domains = parseDomainList(domainsText).domains.join(',');
  if (ips.length + domains.length > LINK_MAX_CHARS) return null;
  return domains ? { ips, domains } : { ips };
}

/** The form text of a route param: one token per line. */
export function linkText(raw) {
  return retireTokens(String(raw ?? '')).join('\n');
}

/**
 * What an empty domain box is filled in with: the last scan's domains, then the imported zone's
 * origin — de-duplicated; `sources` names only the ones that added a domain. (A target carried
 * over from another tool goes into its box through the route, lib/session.js.)
 * @param {{ scanHosts?: { domains?: string[] }|null, zone?: { origin?: string|null }|null }} ctx
 * @returns {{ domains: string[], sources: Array<'scan'|'zone'> }}
 */
export function prefillDomains({ scanHosts = null, zone = null } = {}) {
  const domains = [];
  const sources = [];
  const add = (list, source) => {
    let added = false;
    for (const d of list) {
      const name = parseDomainList(String(d ?? '')).domains[0];
      if (name && !domains.includes(name)) {
        domains.push(name);
        added = true;
      }
    }
    if (added) sources.push(source);
  };
  if (scanHosts && Array.isArray(scanHosts.domains)) add(scanHosts.domains, 'scan');
  if (zone && zone.origin) add([zone.origin], 'zone');
  return { domains: domains.slice(0, RETIRE_MAX_DOMAINS), sources };
}

/**
 * The known host names of each domain (lib/retire.knownHostsFor) from the page session: the last
 * scan's names, the imported zone's names, passive hits the user asked to check and discovered
 * names; capped at {@link RETIRE_MAX_HOSTS} together.
 * @param {string[]} domains
 * @param {{ scanHosts?: object|null, zone?: object|null, passive?: Map<string, string[]>, discovered?: Map<string, string[]> }} sources
 * @returns {{ hosts: Map<string, Array<{ name: string, source: string }>>, capped: boolean }}
 */
export function hostsForDomains(domains, { scanHosts = null, zone = null, passive = new Map(), discovered = new Map() } = {}) {
  const scanNames = scanHosts && Array.isArray(scanHosts.names) ? scanHosts.names : [];
  const zoneNames = zone && Array.isArray(zone.names) ? zone.names : [];
  const hosts = new Map();
  let left = RETIRE_MAX_HOSTS;
  let capped = false;
  for (const d of domains) {
    const list = knownHostsFor(d, {
      scan: scanNames, zone: zoneNames, passive: [...passive.values()].flat(), discovered: discovered.get(d) || []
    });
    if (list.length > left) capped = true;
    hosts.set(d, list.slice(0, Math.max(0, left)));
    left -= Math.min(left, list.length);
  }
  return { hosts, capped };
}

/**
 * The "what to change" text of a change: an i18n key and its params.
 * @param {import('../lib/retire.js').Change} c
 * @returns {{ key: string, params: object }}
 */
export function changeText(c) {
  const spf = c.spf || {};
  const firstHost = (c.via && c.via[0]) || c.value.split(' ').pop();
  switch (c.action) {
    case 'remove':
      if (c.type === 'TXT') return { key: c.severity === 'mail' || c.severity === 'file' ? 'retire.act.remove.spf' : 'retire.act.remove.spfStale', params: { term: c.value, domain: (c.foundFor && c.foundFor[0]) || c.name } };
      if (c.type === 'HTTPS' || c.type === 'SVCB') return { key: 'retire.act.remove.https', params: {} };
      return { key: 'retire.act.remove.a', params: {} };
    case 'narrow':
      return { key: 'retire.act.narrow', params: { range: spf.range || c.value, address: c.addresses.join(', ') } };
    case 'follow':
      if (c.type === 'TXT') return { key: 'retire.act.follow.spf', params: { host: spf.host || c.name } };
      return { key: 'retire.act.follow.cname', params: { target: c.value, holder: c.via.length ? c.via[c.via.length - 1] : c.value } };
    case 'repoint': {
      const host = c.type === 'MX' ? c.value.split(' ').pop() : c.type === 'NS' ? c.value : firstHost;
      const key = c.type === 'MX' ? 'retire.act.repoint.mx' : c.type === 'NS' ? 'retire.act.repoint.ns' : 'retire.act.repoint.other';
      return { key, params: { host } };
    }
    case 'glue':
      return { key: 'retire.act.glue', params: { host: c.value } };
    case 'provider':
      return { key: 'retire.act.provider', params: { holder: spf.holder || c.name } };
    case 'origin':
      return { key: 'retire.act.origin', params: {} };
    case 'check':
    default:
      if (c.sources.includes('passive') && !c.reason) return { key: 'retire.act.check.passive', params: { sources: '' } };
      return { key: `retire.act.check.${c.reason || 'lookup-failed'}`, params: { term: c.value } };
  }
}

/**
 * The facts of Copy summary (lib/summary.js retireSummary) for a finished or stopped job.
 * @param {object} job
 * @param {object} built lib/retire.buildChanges output
 * @param {{ owners: number|null, passive: boolean }} extra
 * @returns {object}
 */
export function summaryFacts(job, built, { owners = null, passive = false } = {}) {
  const failed = [...job.checks.values()].reduce((n, c) => n + c.failures.length, 0) + job.errors.length;
  return {
    label: job.label,
    domains: [...job.domains],
    zone: job.zoneOrigin && job.zoneRefs.length ? job.zoneOrigin : null,
    passive,
    counts: built.counts,
    top: breakingChanges(built.changes).map((c) => ({ severity: c.severity, name: c.name, type: c.type === 'TXT' && c.spf ? 'SPF' : c.type, value: c.value })),
    owners,
    unverified: built.counts.byVerified.unverified || 0,
    failed,
    stopped: job.status === 'cancelled',
    at: job.finishedAt || job.startedAt
  };
}

/* ------------------------------------------------------------------------ */
/* Module state: the job survives navigation and a language switch          */
/* ------------------------------------------------------------------------ */

/**
 * `ips` / `domains`: the boxes' text; `carriedIps` / `carriedDomains`: what a box last took from a
 * carried target (lib/session.js fillReplaces); `filled`: where an empty domain box was filled in
 * from; `prompt`: a link filled the form and waits for a click; `job`: the last check;
 * `discovery`: a running / finished discovery; `discovered`: names found per domain;
 * `passive`: the passive lookup ({ key, status, results }); `extraHosts`: passive names to check;
 * `route`: the `ips` / `domains` params this page wrote for its last check (its own URL is no new link);
 * `hostsOpen`: the host-names disclosure as the user left it (null: open while a domain has none).
 */
const session = {
  ips: null, domains: null, carriedIps: null, carriedDomains: null, filled: null, prompt: false, route: null, hostsOpen: null,
  job: null, discovery: null, discovered: new Map(), passive: null, extraHosts: new Map()
};
let jobCounter = 0;
let active = null;
let intel = null;

const checkRunning = () => !!(session.job && session.job.status === 'running');
const discoveryRunning = () => !!(session.discovery && session.discovery.status === 'running');
const passiveRunning = () => !!(session.passive && session.passive.status === 'running');

// "Delete all local data" forgets the boxes, the last check and what the passive lookup and the
// discovery found; the shell opens the view again when it is on screen.
stateSingleton.subscribe(({ key }) => {
  if (key !== 'cleared') return;
  if (checkRunning()) session.job.controller.abort();
  if (discoveryRunning()) session.discovery.controller.abort();
  if (passiveRunning()) session.passive.controller.abort();
  Object.assign(session, {
    ips: null, domains: null, carriedIps: null, carriedDomains: null, filled: null, prompt: false, route: null, hostsOpen: null,
    job: null, discovery: null, discovered: new Map(), passive: null, extraHosts: new Map()
  });
  if (intel) intel.clearCache();
});

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
 * Start a check: lib/retire.runRetireCheck over the shared DohClient; each finished domain and the
 * zone's verified records are kept on the job and streamed to its listeners.
 */
function startJob({ parsed, domains, hosts, capped, zone, dns }) {
  jobCounter += 1;
  const zoneRefs = zone ? zoneCandidates(zone.records, parsed.blocks) : [];
  const job = {
    id: jobCounter,
    label: parsed.label,
    blocks: parsed.blocks,
    addresses: parsed.addresses,
    domains,
    hosts,
    capped,
    zoneOrigin: zone ? zone.origin || null : null,
    zoneRefs,
    zoneVerified: false,
    checks: new Map(),
    progress: new Map(),
    current: null,
    errors: [],
    status: 'running',
    startedAt: new Date(),
    finishedAt: null,
    controller: new AbortController(),
    listeners: new Set(),
    error: null
  };
  runRetireCheck({
    blocks: parsed.blocks,
    domains,
    hosts,
    zoneRefs,
    dns,
    signal: job.controller.signal,
    concurrency: DOMAIN_CONCURRENCY,
    onEvent: (e) => {
      if (e.type === 'start') job.current = e.domain;
      else if (e.type === 'progress') job.progress.set(e.domain, { done: e.done, total: e.total });
      else if (e.type === 'domain' && e.check) job.checks.set(e.domain, e.check);
      else if (e.type === 'domain') job.errors.push({ domain: e.domain, error: String((e.error && e.error.message) || e.error) });
      else if (e.type === 'zone') {
        job.zoneRefs = e.refs;
        job.zoneVerified = true;
      }
      emit(job, e.type, e);
    }
  }).then((r) => {
    job.finishedAt = new Date();
    job.status = r.aborted ? 'cancelled' : 'done';
    if (r.zone && r.zone.length && !job.zoneVerified && !r.aborted) job.zoneRefs = r.zone;
    emit(job, job.status, null);
    if (job.status === 'done' && !active && session.job === job) {
      const built = buildFor(job);
      toast(t('retire.doneToast', { count: built.counts.breaking }), {
        type: built.counts.breaking ? 'warn' : 'success',
        timeout: 10000,
        action: { label: t('retire.showResults'), onClick: () => { globalThis.location.hash = '#/retire'; } }
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

/** The passive results that belong to a job's addresses (null when none were asked for them). */
function passiveFor(job) {
  const p = session.passive;
  if (!p || !job || !p.results.length) return null;
  const mine = p.results.filter((r) => job.addresses.includes(r.address));
  return mine.length ? mine : null;
}

/** The names a passive result found, per address (both services together). */
function passiveNames(results) {
  return (results || []).map((r) => ({
    address: r.address,
    names: [...new Set([...(r.hackertarget && r.hackertarget.ok ? r.hackertarget.domains : []), ...(r.thc && r.thc.ok ? r.thc.domains : [])])]
  }));
}

/** The change list of a job, with the zone and the passive hits that belong to it. */
function buildFor(job) {
  return buildChanges({
    blocks: job.blocks,
    checks: job.domains.filter((d) => job.checks.has(d)).map((d) => job.checks.get(d)),
    zone: job.zoneOrigin && job.zoneRefs.length && (job.zoneVerified || job.status !== 'running') ? { origin: job.zoneOrigin, refs: job.zoneRefs } : null,
    passive: passiveNames(passiveFor(job))
  });
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mount the Retire an IP view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { state } = ctx;
  const cleanups = [];
  // The last check's entries, as each box is read (blocks as CIDRs, domains normalized).
  const lastRun = () => (session.job ? { ips: session.job.blocks.map((b) => b.cidr), domains: session.job.domains } : null);
  const ipEntries = (text) => parseRetireTargets(text).blocks.map((b) => b.cidr);
  const domainEntries = (text) => parseDomainList(text).domains;
  applyRoute(ctx.params, { fromMount: true });
  if (session.ips === null) session.ips = '';
  if (session.domains === null) session.domains = '';
  if (!session.domains.trim() && !checkRunning()) prefill();

  /* --- form ---------------------------------------------------------------- */
  const ipsField = textarea({
    label: t('retire.ips.label'),
    value: session.ips,
    rows: 3,
    placeholder: t('retire.ips.placeholder'),
    hint: t('retire.ips.hint'),
    className: 'retire-ips',
    attrs: { 'data-role': 'retire-ips', 'data-shortcut': 'focus' },
    onInput: (v) => {
      session.ips = v;
      ipsField.setError(null);
      hidePrompt();
      renderParsedSoon();
    }
  });
  const domainsField = textarea({
    label: t('retire.domains.label'),
    value: session.domains,
    rows: 3,
    placeholder: t('retire.domains.placeholder'),
    hint: t('retire.domains.hint'),
    className: 'retire-domains',
    attrs: { 'data-role': 'retire-domains', inputmode: 'url' },
    onInput: (v) => {
      session.domains = v;
      session.filled = null;
      domainsField.setError(null);
      hidePrompt();
      renderParsedSoon();
    }
  });
  const parsedEl = h('div', { class: 'retire-parsed text-sm', attrs: { 'aria-live': 'polite' } });
  const issuesEl = h('div', { class: 'stack-sm retire-issues' });
  const hostsEl = h('div', { class: 'retire-hosts text-sm' });
  const promptEl = h('div', { class: 'retire-prompt', hidden: true });
  const runBtn = Button({ label: t('retire.run'), icon: 'search', variant: 'primary', dataset: { action: 'retire-run', shortcut: 'submit' }, onClick: () => start() });
  const stopBtn = Button({ label: t('retire.stop'), icon: 'stop', dataset: { action: 'retire-stop', shortcut: 'cancel' }, onClick: () => stop() });
  stopBtn.hidden = true;
  const formCard = Card({
    className: 'retire-form-card',
    children: h('div', { class: 'stack' },
      h('div', { class: 'retire-form' }, ipsField.el, domainsField.el),
      parsedEl,
      issuesEl,
      hostsEl,
      promptEl,
      h('div', { class: 'retire-actions' },
        h('p', { class: 'muted text-xs retire-privacy' }, Icon('lock', { size: 12 }), h('span', null, t('retire.privacy'))),
        h('div', { class: 'cluster retire-run' }, stopBtn, runBtn)))
  });
  const resultsHost = h('div', { class: 'retire-results-host stack', dataset: { shortcutScope: 'results' } });
  const emptyEl = Card({
    padded: false,
    className: 'retire-empty',
    children: EmptyState({ icon: 'unlink', title: t('retire.emptyTitle'), message: t('retire.emptyBody') })
  });
  container.append(h('div', { class: 'stack-lg retire-view' }, formCard, emptyEl, resultsHost));

  /* --- parsing ------------------------------------------------------------- */
  let parsed = parseRetireTargets(ipsField.value);
  let domainList = parseDomainList(domainsField.value);

  function issueText(issue) {
    const params = { ...issue.params };
    if (typeof params.max === 'number') params.max = formatNumber(params.max);
    return t(`retire.issue.${issue.code}`, params);
  }

  function renderParsed() {
    parsed = parseRetireTargets(ipsField.value);
    domainList = parseDomainList(domainsField.value);
    clear(parsedEl);
    clear(issuesEl);
    const bits = [];
    if (parsed.ok) bits.push(Badge(t('retire.parsed', { count: parsed.total }), { variant: 'ok', icon: 'check' }));
    if (domainList.domains.length) bits.push(Badge(t('retire.parsedDomains', { count: domainList.domains.length }), { variant: 'ok', icon: 'check' }));
    if (session.filled && session.filled.length) {
      bits.push(h('span', { class: 'muted retire-filled', dataset: { filled: session.filled.join(' ') } },
        t('retire.filled', { sources: session.filled.map((s) => t(`retire.filled.${s}`)).join(', ') })));
    }
    parsedEl.append(...bits);
    for (const issue of parsed.issues) {
      if (issue.code === 'nothing' && parsed.issues.some((i) => i !== issue && i.severity === 'error')) continue;
      const alert = Alert({ variant: issue.severity === 'error' ? 'error' : issue.severity === 'warn' ? 'warn' : 'info', compact: true, message: issueText(issue) });
      alert.dataset.issue = issue.code;
      issuesEl.append(alert);
    }
    if (domainList.invalid.length) {
      const alert = Alert({ variant: 'warn', compact: true, message: t('retire.domainsInvalid', { items: domainList.invalid.slice(0, 5).join(', ') }) });
      alert.dataset.issue = 'domains-invalid';
      issuesEl.append(alert);
    }
    if (domainList.truncated) {
      issuesEl.append(Alert({ variant: 'warn', compact: true, message: t('retire.domainsTruncated', { max: formatNumber(RETIRE_MAX_DOMAINS), count: domainList.truncated }) }));
    }
    renderHosts();
  }
  const renderParsedSoon = debounce(renderParsed, 150);

  /** Which host names each domain gets besides its own records, and the discovery offer. */
  function renderHosts() {
    clear(hostsEl);
    const domains = domainList.domains;
    if (!domains.length) return;
    const { hosts, capped } = currentHosts(domains);
    const lines = domains.map((d) => {
      const list = hosts.get(d) || [];
      if (!list.length) return h('li', { dataset: { domain: d, hosts: '0' } }, t('retire.hosts.none', { domain: d }));
      const bySource = {};
      for (const x of list) bySource[x.source] = (bySource[x.source] || 0) + 1;
      const parts = ['scan', 'zone', 'passive', 'discovered'].filter((s) => bySource[s]).map((s) => t(`retire.hosts.${s}`, { count: bySource[s] }));
      return h('li', { dataset: { domain: d, hosts: String(list.length) } }, t('retire.hosts.from', { domain: d, list: parts.join(' · ') }));
    });
    const bare = domains.filter((d) => !(hosts.get(d) || []).length);
    const children = [h('ul', { class: 'retire-hosts-list' }, lines)];
    if (capped) children.push(h('p', { class: 'muted text-xs' }, t('retire.hosts.capped', { max: formatNumber(RETIRE_MAX_HOSTS) })));
    if (bare.length) {
      const est = estimateQueries({ bruteforce: 'small', domains: bare, locales: [], permutationBudget: 0, recursive: false, originHints: false, resolverLeak: false });
      const running = discoveryRunning();
      const btn = Button({
        label: t('retire.discover.button'), icon: 'layers', size: 'sm', variant: 'secondary',
        title: t('retire.discover.title', { min: formatNumber(est.min), max: formatNumber(est.max) }),
        disabled: running || checkRunning(),
        dataset: { action: 'retire-discover' },
        onClick: () => discover(bare)
      });
      children.push(h('div', { class: 'retire-discover' },
        h('p', { class: 'text-sm' }, Icon('info', { size: 13 }), ' ', t('retire.discover.offer', { count: bare.length })),
        running ? h('p', { class: 'muted text-sm', dataset: { role: 'retire-discovering' } }, t('retire.discover.running', { domain: session.discovery.current || bare[0] })) : btn));
    }
    if (session.discovery && session.discovery.status === 'error') {
      children.push(ErrorBanner(session.discovery.error, { title: t('retire.discover.failed'), compact: true }));
    }
    // Open while a domain has no host names (the discovery offer is in it), unless the user closed it.
    const box = Disclosure({
      summary: t('retire.hosts.title'), open: session.hostsOpen ?? bare.length > 0, className: 'retire-hosts-box', children: h('div', { class: 'stack-sm' }, children)
    });
    box.addEventListener('toggle', () => { session.hostsOpen = box.open; });
    hostsEl.append(box);
  }

  function currentHosts(domains) {
    return hostsForDomains(domains, {
      scanHosts: state.getSession('scanHosts') || null,
      zone: state.getSession('zone') || null,
      passive: session.extraHosts,
      discovered: session.discovered
    });
  }

  /* --- prompt ---------------------------------------------------------------- */
  function showPrompt() {
    clear(promptEl);
    promptEl.hidden = false;
    const alert = Alert({ variant: 'info', icon: 'link', compact: true, message: t('retire.link.prompt') });
    alert.dataset.prompt = 'link';
    promptEl.append(alert);
  }

  function hidePrompt() {
    session.prompt = false;
    clear(promptEl);
    promptEl.hidden = true;
  }

  /* --- run ----------------------------------------------------------------- */
  let ui = null;
  let starting = false;

  function syncControls() {
    const busy = checkRunning() || discoveryRunning() || passiveRunning();
    const doc = globalThis.document;
    const moveFocus = doc && doc.activeElement === (busy ? runBtn : stopBtn);
    runBtn.hidden = busy;
    stopBtn.hidden = !busy;
    ipsField.input.readOnly = checkRunning() || discoveryRunning();
    domainsField.input.readOnly = checkRunning() || discoveryRunning();
    if (moveFocus) (busy ? stopBtn : runBtn).focus({ preventScroll: true });
    ctx.setBusy(checkRunning() ? t('retire.busy') : discoveryRunning() ? t('retire.busyDiscover') : passiveRunning() ? t('retire.busyPassive') : false);
    renderHeaderActions();
  }

  function stop() {
    if (checkRunning()) session.job.controller.abort();
    if (discoveryRunning()) session.discovery.controller.abort();
    if (passiveRunning()) session.passive.controller.abort();
  }

  async function start() {
    if (starting || checkRunning() || discoveryRunning()) return;
    renderParsed();
    hidePrompt();
    if (parsed.kind === 'empty') {
      ipsField.setError(t('retire.required'));
      ipsField.focus();
      return;
    }
    if (!parsed.ok) {
      ipsField.focus();
      return;
    }
    const zone = state.getSession('zone') || null;
    if (!domainList.domains.length && !(zone && zone.records && zone.records.length)) {
      domainsField.setError(t('retire.noDomains'));
      domainsField.focus();
      return;
    }
    // Offline: a toast says the check needs the network, and nothing is sent.
    if (!ctx.requireOnline()) return;
    let dns;
    starting = true;
    try {
      dns = await ctx.getDns();
    } catch (err) {
      clear(resultsHost);
      resultsHost.append(ErrorBanner(err, { title: t('retire.failed') }));
      return;
    } finally {
      starting = false;
    }
    if (ctx.signal.aborted) return;
    const domains = [...domainList.domains];
    // The zone's candidates are verified live even when its domain is not in the list.
    const { hosts, capped } = currentHosts(domains);
    const params = shareParams(ipsField.value, domainsField.value);
    session.route = params ? { ips: params.ips, domains: params.domains || '' } : null;
    ctx.setParams(params || {});
    session.carriedIps = null;
    session.carriedDomains = null;
    const single = parsed.blocks.length === 1 && parsed.blocks[0].single ? parsed.blocks[0].first : null;
    ctx.runStarted(single);
    const job = startJob({ parsed, domains, hosts, capped, zone: zone && Array.isArray(zone.records) ? zone : null, dns });
    session.job = job;
    attach(job);
    const r = resultsHost.getBoundingClientRect();
    if (r.top > globalThis.innerHeight - 120) resultsHost.scrollIntoView({ block: 'start' });
  }

  /** Discover host names of domains without any (the Small wordlist through the discovery engine), then check again. */
  async function discover(domains) {
    if (discoveryRunning() || checkRunning() || !ctx.requireOnline()) return;
    let runScan;
    let dns;
    try {
      ({ runScan } = await import('../lib/scanner.js'));
      dns = await ctx.getDns();
    } catch (err) {
      ctx.checkOutdated();
      session.discovery = { status: 'error', error: err, controller: null, current: null };
      renderHosts();
      return;
    }
    const controller = new AbortController();
    const disc = { status: 'running', error: null, controller, current: domains[0], domains };
    session.discovery = disc;
    syncControls();
    renderHosts();
    try {
      for (const d of domains) {
        disc.current = d;
        if (active) active.refreshHosts();
        const result = await runScan({
          domains: [d], dns, signal: controller.signal, sources: [], bruteforce: 'small', permutationBudget: 0, recursive: false,
          originHints: false, resolverLeak: false, locales: [], maxConcurrency: state.settings.concurrency
        });
        session.discovered.set(d, result.hosts.filter((x) => !x.wildcardSuspect).map((x) => x.name));
      }
      disc.status = 'done';
    } catch (err) {
      disc.status = errorKind(err) === 'abort' ? 'cancelled' : 'error';
      disc.error = err;
    }
    disc.controller = null;
    if (!active) return;
    active.afterDiscovery(disc);
  }

  /** Ask the passive services about each address (a click; the addresses must be few and public). */
  async function lookupPassive() {
    const job = session.job;
    if (!job || passiveRunning() || !ctx.requireOnline()) return;
    const addresses = job.addresses.filter((a) => !isPrivateIP(a));
    if (!addresses.length || job.addresses.length > PASSIVE_MAX_ADDRESSES) return;
    if (!intel) intel = createIpIntel();
    const controller = new AbortController();
    const p = { key: addresses.join(','), status: 'running', results: [], controller };
    session.passive = p;
    syncControls();
    if (ui) ui.render();
    try {
      for (const address of addresses) {
        const [hackertarget, thc] = await Promise.all([
          intel.reverseIp(address, { signal: controller.signal }),
          intel.reverseIpThc(address, { signal: controller.signal })
        ]);
        p.results.push({ address, hackertarget, thc });
        if (ui) ui.render();
      }
      p.status = 'done';
    } catch (err) {
      p.status = errorKind(err) === 'abort' ? 'cancelled' : 'error';
      p.error = err;
    }
    p.controller = null;
    if (active) active.afterPassive();
  }

  /** "Check these too": the passive names' domains join the list, the names become known hosts, and the check runs again. */
  function checkPassiveToo() {
    const job = session.job;
    if (!job || checkRunning()) return;
    const resolved = [...job.checks.values()].flatMap((c) => c.names.map((n) => n.name));
    const fresh = passiveNewNames(passiveNames(passiveFor(job)), { checked: job.domains, resolved });
    if (!fresh.names.length) return;
    for (const name of fresh.names) {
      const home = job.domains.find((d) => isSubdomainOf(name, d)) || registrableDomain(name) || name;
      const list = session.extraHosts.get(home) || [];
      if (!list.includes(name)) list.push(name);
      session.extraHosts.set(home, list);
    }
    if (fresh.domains.length) {
      const add = fresh.domains.filter((d) => !domainList.domains.includes(d));
      const text = domainsField.value.replace(/\s+$/, '');
      domainsField.value = `${text}${text ? '\n' : ''}${add.join('\n')}`;
      session.domains = domainsField.value;
    }
    renderParsed();
    start();
  }

  function attach(job) {
    if (ui) ui.dispose();
    clear(resultsHost);
    emptyEl.hidden = true;
    ui = buildJobUI(job, ctx, {
      onPassive: () => lookupPassive(),
      onCheckToo: () => checkPassiveToo(),
      onFinish: () => {
        syncControls();
        renderHosts();
      }
    });
    resultsHost.append(ui.el);
    syncControls();
  }

  function renderHeaderActions() {
    const job = session.job;
    const params = job ? shareParams(job.addresses.length === job.blocks.length ? job.addresses.join('\n') : job.blocks.map((b) => b.cidr).join('\n'), job.domains.join('\n')) : null;
    if (!params) {
      ctx.setActions();
      return;
    }
    ctx.setActions(CopyButton(() => ctx.shareUrl(params), { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }));
  }

  /** Fill an empty domain box from what the page session knows (the last scan, the imported zone). */
  function prefill() {
    const p = prefillDomains({ scanHosts: state.getSession('scanHosts') || null, zone: state.getSession('zone') || null });
    if (!p.domains.length) return;
    session.domains = p.domains.join('\n');
    session.filled = p.sources;
    session.carriedDomains = session.domains;
  }

  /* --- initial state --------------------------------------------------------- */
  renderParsed();
  if (session.job) attach(session.job);
  else renderHeaderActions();
  if (session.prompt) showPrompt();
  if (discoveryRunning()) syncControls();

  cleanups.push(state.subscribe(({ key, value }) => {
    if (key === 'inventory' && ui) ui.render();
    if (key === 'session' && value && (value.name === 'scanHosts' || value.name === 'zone')) renderHosts();
  }));

  active = {
    refreshHosts: () => renderHosts(),
    afterDiscovery(disc) {
      syncControls();
      renderHosts();
      if (disc.status === 'done') start();
    },
    afterPassive() {
      syncControls();
      if (ui) ui.render();
    },
    applyParams(params) {
      if (applyRoute(params, { fromMount: false })) {
        ipsField.value = session.ips;
        domainsField.value = session.domains;
        ipsField.setError(null);
        domainsField.setError(null);
        renderParsed();
        if (session.prompt) showPrompt();
        else hidePrompt();
      }
      return true;
    }
  };

  /**
   * Route params into the boxes. A shared link fills both and waits for a click (never a run); a
   * carried target (`run=0`) goes into its box only while that box is empty or still holds the last
   * check or what it took from a carry before (lib/session.js fillReplaces) — never over a draft.
   * @returns {boolean} whether a box changed
   */
  function applyRoute(params, { fromMount }) {
    const ips = linkText(params && params.ips);
    const domains = linkText(params && params.domains);
    if (!ips && !domains) return false;
    if (checkRunning() || discoveryRunning()) return false;
    const fill = isFillOnly(params);
    // The URL this page wrote for its last check (a language re-mount, Back to it) is no new link.
    const own = session.route && (params.ips || '') === session.route.ips && (params.domains || '') === session.route.domains;
    if (own && !fill) return false;
    const run = lastRun();
    let changed = false;
    if (ips && (!fill || fillReplaces(session.ips || '', run && run.ips, ipEntries, session.carriedIps))) {
      if (ips !== session.ips) changed = true;
      session.ips = ips;
      session.carriedIps = fill ? ips : null;
    }
    if (domains && (!fill || fillReplaces(session.domains || '', run && run.domains, domainEntries, session.carriedDomains))) {
      if (domains !== session.domains) changed = true;
      session.domains = domains;
      session.carriedDomains = fill ? domains : null;
      session.filled = fill ? ['target'] : null;
    }
    // A link (not a carried target) fills the form and says it waits for a click.
    if (!fill && (changed || fromMount)) session.prompt = true;
    return changed || !fill;
  }

  return () => {
    cleanups.forEach((fn) => fn());
    if (ui) ui.dispose();
    ui = null;
    active = null;
  };
}

/**
 * Take new route params (`#/retire?ips=…&domains=…`) without re-mounting.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.applyParams(params) : false;
}

/** Nothing else to clean up (a running check continues in the background). */
export function unmount() {}

export default { id, titleKey, icon, mount, unmount, update };

/* ------------------------------------------------------------------------ */
/* Job UI                                                                   */
/* ------------------------------------------------------------------------ */

/** Call `fn` at most every `ms` (trailing call guaranteed). */
function throttle(fn, ms) {
  let timer = null;
  let last = 0;
  const run = () => {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      last = Date.now();
      fn();
    }, Math.max(0, ms - (Date.now() - last)));
  };
  run.cancel = () => {
    if (timer) clearTimeout(timer);
    timer = null;
  };
  return run;
}

/** A status chip (the `.src-chip` look of ui/source-status.js) with its own words. */
function chip(idChip, name, stateName, value, action = null) {
  const icons = { ok: 'check-circle', failed: 'alert', idle: 'minus-circle' };
  const iconEl = icons[stateName] ? Icon(icons[stateName], { size: 14 }) : h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } });
  return h('span', { class: 'src-chip', dataset: { source: idChip, state: stateName } },
    iconEl, h('span', { class: 'src-chip-name' }, name), h('span', { class: 'src-chip-value' }, value), action);
}

function buildJobUI(job, ctx, { onPassive, onCheckToo, onFinish }) {
  const { state } = ctx;
  const chipsEl = h('div', { class: 'src-chips retire-chips', attrs: { role: 'group', 'aria-label': t('retire.hosts.title') } });
  const progress = ProgressBar({ label: t('retire.busy'), value: 0, max: 1, showCount: false });
  progress.el.classList.add('retire-progress');
  const statusEl = h('p', { class: 'muted text-sm retire-status', attrs: { 'aria-live': 'polite' } });
  const headEl = h('div', { class: 'retire-head' });
  const statsEl = h('div', { class: 'stat-grid retire-stats' });
  const ownersEl = h('div', { class: 'retire-owners text-sm' });
  const groupsEl = h('div', { class: 'stack retire-groups' });
  const goneEl = h('div', { class: 'retire-gone' });
  const expanded = new Set();
  const summary = SummaryButton({
    kind: 'retire',
    inventory: 'count',
    facts: () => (job.status === 'running' ? null : summaryFacts(job, buildFor(job), { owners: ownersCount(), passive: !!passiveFor(job) })),
    url: () => ctx.shareUrl(permalinkParams('retire', shareParams(job.blocks.map((b) => b.label).join('\n'), job.domains.join('\n')) || {},
      { exclude: [...ctx.getInventoryIndex().keys()] })),
    disabled: job.status === 'running'
  });
  const exportCsv = Button({ label: t('common.exportCsv'), icon: 'download', size: 'sm', dataset: { export: 'csv' }, onClick: () => doExport('csv') });
  const exportJson = Button({ label: t('common.exportJson'), icon: 'download', size: 'sm', dataset: { export: 'json' }, onClick: () => doExport('json') });
  const el = h('div', { class: 'stack retire-job', dataset: { job: String(job.id) } },
    Card({
      className: 'retire-head-card',
      children: h('div', { class: 'stack-sm' }, headEl, h('div', { class: 'retire-tools cluster' }, summary.el, exportCsv, exportJson), progress.el, statusEl, chipsEl, ownersEl)
    }),
    statsEl, groupsEl, goneEl);

  function ownersCount() {
    const servers = state.inventory.servers;
    return servers && servers.length ? inventoryOwners(job.blocks, servers).length : null;
  }

  function doExport(format) {
    const built = buildFor(job);
    const subject = job.label.replace(/[^0-9a-z.:-]+/gi, '_').slice(0, 40);
    const name = timestampedName('ip-retire', format, subject);
    let file;
    if (format === 'csv') {
      file = downloadText(name, toCsv(retireExportRows(built.changes), RETIRE_CSV_COLUMNS.map((key) => ({ key, header: key }))), 'text/csv;charset=utf-8');
    } else {
      const failures = [...job.checks.values()].flatMap((c) => c.failures.map((f) => ({ domain: c.domain, ...f })));
      file = downloadText(name, `${toJson(retireExportJson({
        blocks: job.blocks, domains: job.domains, changes: built.changes, counts: built.counts, gone: built.gone,
        owners: state.inventory.servers.length ? inventoryOwners(job.blocks, state.inventory.servers) : [],
        failures: [...failures, ...job.errors], startedAt: job.startedAt, finishedAt: job.finishedAt, aborted: job.status === 'cancelled',
        zone: job.zoneOrigin, version: ctx.version
      }))}\n`, 'application/json;charset=utf-8');
    }
    toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
  }

  /* chips: every evidence source with its status */
  function renderChips(built) {
    clear(chipsEl);
    const running = job.status === 'running';
    const checks = [...job.checks.values()];
    const names = checks.reduce((n, c) => n + c.names.length, 0);
    const failed = checks.reduce((n, c) => n + c.failures.filter((f) => f.what !== 'spf').length, 0) + job.errors.length;
    chipsEl.append(chip('dns', t('retire.chip.dns'), running ? 'pending' : failed ? 'failed' : 'ok',
      running ? t('retire.chip.pending') : `${t('retire.chip.dnsOk', { count: names })}${failed ? ` · ${t('retire.chip.dnsFailed', { count: failed })}` : ''}`));
    const spfOk = checks.filter((c) => c.spf.status === 'ok' || c.spf.status === 'multiple').length;
    const spfFailed = checks.filter((c) => c.spf.status === 'failed').length;
    let spfValue;
    if (running && !checks.length) spfValue = t('retire.chip.pending');
    else if (!spfOk && !spfFailed) spfValue = t('retire.chip.spfNone');
    else spfValue = `${spfOk ? t('retire.chip.spfOk', { count: spfOk }) : ''}${spfOk && spfFailed ? ' · ' : ''}${spfFailed ? t('retire.chip.spfFailed', { count: spfFailed }) : ''}`;
    chipsEl.append(chip('spf', t('retire.chip.spf'), running && !checks.length ? 'pending' : spfFailed ? 'failed' : spfOk ? 'ok' : 'idle', spfValue));
    if (job.zoneOrigin) {
      const reached = built.changes.filter((c) => c.sources.includes('zone')).length;
      chipsEl.append(chip('zone', t('retire.chip.zone'), running && !job.zoneVerified ? 'pending' : 'ok',
        running && !job.zoneVerified ? t('retire.chip.pending') : t('retire.chip.zoneOk', { count: reached, zone: job.zoneOrigin })));
    } else {
      chipsEl.append(chip('zone', t('retire.chip.zone'), 'idle', t('retire.chip.zoneNone')));
    }
    const servers = state.inventory.servers;
    if (!servers || !servers.length) chipsEl.append(chip('servers', t('retire.chip.servers'), 'idle', t('retire.chip.serversNone')));
    else {
      const owners = inventoryOwners(job.blocks, servers);
      chipsEl.append(chip('servers', t('retire.chip.servers'), 'ok', owners.length
        ? t('retire.chip.serversOwner', { count: owners.length, names: owners.slice(0, 3).map((o) => o.name).join(', ') + (owners.length > 3 ? ` ${t('common.moreCount', { count: owners.length - 3 })}` : '') })
        : t('retire.chip.serversNot')));
    }
    chipsEl.append(passiveChip());
  }

  function passiveChip() {
    const p = session.passive;
    const mine = passiveFor(job);
    const publicAddresses = job.addresses.filter((a) => !isPrivateIP(a));
    const tooMany = job.addresses.length > PASSIVE_MAX_ADDRESSES;
    const button = () => {
      const btn = Button({
        label: t('retire.passive.button'), icon: 'search', size: 'sm', variant: 'ghost', dataset: { action: 'retire-passive' },
        title: t('retire.passive.title', { count: publicAddresses.length }), disabled: job.status === 'running' || passiveRunning(), onClick: onPassive
      });
      return btn;
    };
    if (p && p.status === 'running' && p.key === publicAddresses.join(',')) {
      return chip('passive', t('retire.chip.passive'), 'pending', t('retire.chip.pending'));
    }
    if (mine) {
      const failures = [];
      for (const r of mine) {
        for (const src of PASSIVE_SOURCES) {
          const res = r[src];
          if (res && !res.ok) failures.push(`${t(`retire.passive.src.${src}`)}: ${res.limited ? t('retire.passive.limited') : res.error || ''}`);
        }
      }
      const count = new Set(passiveNames(mine).flatMap((x) => x.names)).size;
      const value = `${t('retire.chip.passiveOk', { count })}${failures.length ? ` · ${t('retire.chip.passiveFailed', { reason: failures.join('; ') })}` : ''}`;
      return chip('passive', t('retire.chip.passive'), failures.length === mine.length * PASSIVE_SOURCES.length ? 'failed' : 'ok', value);
    }
    if (tooMany) return chip('passive', t('retire.chip.passive'), 'idle', t('retire.passive.tooMany', { max: PASSIVE_MAX_ADDRESSES }));
    if (!publicAddresses.length) return chip('passive', t('retire.chip.passive'), 'idle', t('retire.passive.private'));
    return chip('passive', t('retire.chip.passive'), 'idle', t('retire.chip.passiveIdle'), button());
  }

  /* the headline, the stat cards and the owners */
  let headKey = null;
  function renderHead(built) {
    // Drawn again only when what it says changes: its verdict is an alert a screen reader announces.
    const key = JSON.stringify([job.status, job.finishedAt && job.finishedAt.getTime(), built.counts, getLang()]);
    if (key === headKey) return;
    headKey = key;
    clear(headEl);
    const title = h('h2', { class: 'retire-head-title' }, t('retire.head.title', { label: job.label }));
    const when = job.finishedAt ? h('span', { class: 'muted text-sm' }, t('retire.head.checked', { time: formatDateTime(job.finishedAt) })) : null;
    headEl.append(h('div', { class: 'retire-head-row' }, title, when));
    if (job.status === 'running') return;
    const { breaking, total } = built.counts;
    const listed = total - (built.counts.byVerified.unverified || 0) - (built.counts.bySeverity.unknown || 0);
    let alert;
    if (job.status === 'error') alert = ErrorBanner(job.error, { title: t('retire.failed') });
    else if (breaking) alert = Alert({ variant: built.counts.bySeverity.mail || built.counts.bySeverity.ns ? 'error' : 'warn', title: t('retire.head.breaking', { count: breaking, label: job.label }), message: t('retire.head.scope') });
    else if (listed > 0) alert = Alert({ variant: 'info', title: t('retire.head.cleanup', { count: listed }), message: t('retire.head.scope') });
    else alert = Alert({ variant: 'ok', title: t('retire.head.none', { label: job.label }), message: t('retire.head.scope') });
    alert.dataset.role = 'retire-verdict';
    headEl.append(alert);
    if (job.status === 'cancelled') headEl.append(Alert({ variant: 'warn', compact: true, message: t('retire.stopped') }));
  }

  function renderStats(built) {
    clear(statsEl);
    if (job.status === 'running' && !job.checks.size) return;
    const c = built.counts;
    const cards = [
      ['breaking', c.breaking, c.breaking ? 'error' : 'ok', 'alert'],
      ['mail', c.bySeverity.mail || 0, c.bySeverity.mail ? 'error' : 'ok', 'mail'],
      ['file', c.bySeverity.file || 0, 'info', 'file-text'],
      ['unknown', c.bySeverity.unknown || 0, c.bySeverity.unknown ? 'warn' : 'default', 'help'],
      ['unverified', c.byVerified.unverified || 0, 'default', 'eye']
    ];
    for (const [key, value, variant, iconName] of cards) {
      if (!value && key !== 'breaking') continue;
      const card = StatCard({ label: t(`retire.stat.${key}`), value, variant, icon: iconName });
      card.el.dataset.stat = key;
      statsEl.append(card.el);
    }
  }

  function renderOwners() {
    clear(ownersEl);
    const servers = state.inventory.servers;
    if (!servers || !servers.length) return;
    const owners = inventoryOwners(job.blocks, servers);
    if (!owners.length) return;
    ownersEl.append(Icon('server', { size: 14 }), h('span', { class: 'retire-owners-title' }, `${t('retire.owners.title')}:`),
      h('ul', { class: 'retire-owner-list', title: t('retire.owners.hint') }, owners.map((o) => h('li', { dataset: { server: o.name } },
        h('span', { class: 'retire-owner-name' }, o.name), ' ',
        h('span', { class: 'mono' }, o.addresses.join(', ')),
        o.others.length ? h('span', { class: 'muted' }, ` · ${t('retire.owners.others', { list: o.others.join(', ') })}`) : null))));
  }

  /* the change list, one card per group */
  function severityBadge(c) {
    const b = Badge(t(`retire.sev.${c.severity}`), { variant: SEVERITY_VARIANT[c.severity] || 'neutral', title: t(`retire.sevTitle.${c.severity}`) });
    b.dataset.severity = c.severity;
    return b;
  }

  function verifiedBadge(c) {
    const b = Badge(t(`retire.ver.${c.verified}`), { variant: VERIFIED_VARIANT[c.verified] || 'neutral', icon: c.verified === 'live' ? 'check' : null, title: t(`retire.verTitle.${c.verified}`) });
    b.dataset.verified = c.verified;
    return b;
  }

  function evidence(c) {
    const lines = [verifiedBadge(c)];
    const add = (text) => lines.push(h('div', { class: 'muted text-xs retire-ev' }, text));
    if (c.spf && c.spf.holder && c.type === 'TXT') {
      add(t('retire.ev.spf', { holder: c.spf.holder }));
      if (c.via.length > 1) add(t('retire.ev.path', { path: c.via.join(' → ') }));
      if (c.spf.qualifier && c.spf.qualifier !== '+') add(t('retire.ev.qualifier', { qualifier: c.spf.qualifier }));
      if (c.spf.effective === null && c.spf.relation && c.severity === 'stale') add(t('retire.ev.inert'));
    } else if (c.via.length > 1) {
      add(t('retire.ev.via', { chain: c.via.join(' → ') }));
    }
    const roles = c.roles.map((r) => t(`retire.ev.roles.${r}`));
    if (c.proxied === true) roles.push(t('retire.ev.proxied'));
    if (roles.length) add(roles.join(' · '));
    const hasLine = c.line !== null && c.line !== undefined;
    const srcs = c.sources.filter((s) => ['dns', 'spf', 'zone', 'passive', 'scan', 'discovered'].includes(s))
      .map((s) => (s === 'zone' && hasLine ? t('retire.line', { line: c.line }) : t(`retire.ev.src.${s}`)));
    if (srcs.length) add(srcs.join(' · '));
    if (c.groupKind === 'other' && c.foundFor.length) add(t('retire.ev.foundFor', { list: c.foundFor.join(', ') }));
    return h('div', { class: 'retire-evidence' }, lines);
  }

  function changeCell(c) {
    const { key, params } = changeText(c);
    if (key === 'retire.act.check.passive') params.sources = passiveSourcesOf(c.name).join(', ') || t('retire.ev.src.passive');
    return h('span', { class: 'retire-change', dataset: { action: c.action } }, t(key, params));
  }

  function passiveSourcesOf(name) {
    const out = new Set();
    for (const r of passiveFor(job) || []) {
      for (const src of PASSIVE_SOURCES) if (r[src] && r[src].ok && r[src].domains.includes(name)) out.add(t(`retire.passive.src.${src}`));
    }
    return [...out];
  }

  function recordCell(c) {
    return h('div', { class: 'retire-record' },
      h('span', { class: 'mono retire-name' }, c.name),
      Badge(c.type === 'TXT' && c.spf ? 'SPF' : c.type, { mono: true, className: 'retire-type' }));
  }

  function valueCell(c) {
    const reach = c.addresses.filter((a) => !c.value.includes(a));
    return h('div', { class: 'retire-value' },
      h('span', { class: 'mono' }, c.value || '—'),
      reach.length ? h('div', { class: 'muted text-xs' }, t('retire.reaches', { list: reach.join(', ') })) : null);
  }

  function changeTable(changes, groupKey) {
    const headers = [t('retire.col.severity'), t('retire.col.record'), t('retire.col.value'), t('retire.col.change'), t('retire.col.evidence')];
    const all = expanded.has(groupKey);
    const shown = all ? changes : changes.slice(0, GROUP_PAGE);
    const rows = shown.map((c) => {
      const cells = [severityBadge(c), recordCell(c), valueCell(c), changeCell(c), evidence(c)];
      // On a phone each row is a card whose lines carry the column headers as labels (data-label).
      return h('tr', { class: 'dt-row', dataset: { key: c.key, severity: c.severity, type: c.type, verified: c.verified } },
        cells.map((cell, i) => h('td', { dataset: { label: headers[i] } }, cell)));
    });
    const table = h('div', { class: ['dt-scroll', 'dt-scroll-free', 'retire-table'], attrs: { tabindex: 0 } },
      h('table', { class: 'dt-table dt-dense' },
        h('thead', null, h('tr', null, headers.map((x) => h('th', { attrs: { scope: 'col' } }, x)))),
        h('tbody', null, rows)));
    const more = changes.length > shown.length ? Button({
      label: t('retire.group.more', { count: formatNumber(changes.length) }), size: 'sm', variant: 'secondary', icon: 'chevron-down',
      onClick: () => {
        expanded.add(groupKey);
        render();
      }
    }) : null;
    return h('div', { class: 'stack-sm' }, table, more);
  }

  function groupCard(g) {
    const count = g.changes.length;
    let title;
    let subtitle = null;
    let checkToo = null;
    if (g.kind === 'zone') title = t('retire.group.zone', { origin: g.key });
    else if (g.kind === 'other') {
      title = t('retire.group.other');
      subtitle = t('retire.group.otherHint');
    } else if (g.kind === 'passive') {
      title = t('retire.group.passive');
      subtitle = t('retire.group.passiveHint');
      const resolved = [...job.checks.values()].flatMap((c) => c.names.map((n) => n.name));
      const fresh = passiveNewNames(passiveNames(passiveFor(job)), { checked: job.domains, resolved });
      if (fresh.names.length) {
        // In the body, not the card head: on a phone the head keeps its width for the title.
        checkToo = h('div', { class: 'retire-check-too' }, Button({
          label: fresh.domains.length ? t('retire.passive.checkToo') : t('retire.passive.checkNames'), icon: 'search', size: 'sm', variant: 'primary',
          title: fresh.domains.length ? t('retire.passive.checkTooTitle', { domains: fresh.domains.join(', ') }) : null,
          disabled: job.status === 'running', dataset: { action: 'retire-check-too' }, onClick: onCheckToo
        }));
      }
    } else title = h('span', { class: 'mono' }, g.key);
    const body = [checkToo];
    if (!count && g.kind === 'domain') {
      const check = job.checks.get(g.key);
      const failedDomain = job.errors.find((e) => e.domain === g.key);
      if (failedDomain) body.push(Alert({ variant: 'error', compact: true, message: t('retire.domainFailed', { domain: g.key, error: failedDomain.error }) }));
      else if (check) {
        const a = Alert({ variant: 'ok', compact: true, message: t('retire.group.empty', { domain: g.key, count: check.names.length }) });
        a.dataset.role = 'retire-clean';
        body.push(a);
      } else body.push(h('p', { class: 'muted text-sm' }, t('retire.progress', { domain: g.key, done: job.checks.size, total: job.domains.length })));
    } else body.push(changeTable(g.changes, g.key));
    const card = Card({
      className: ['retire-group', `retire-group-${g.kind}`].join(' '),
      title,
      subtitle,
      actions: count ? Badge(t('retire.group.count', { count }), { variant: g.changes.some((c) => c.severity === 'mail' || c.severity === 'ns') ? 'error' : 'neutral' }) : null,
      children: h('div', { class: 'stack-sm' }, body)
    });
    card.dataset.group = g.key;
    card.dataset.kind = g.kind;
    return card;
  }

  function renderGroups(built) {
    clear(groupsEl);
    // While a check runs, a domain's card appears once it is finished.
    const groups = built.groups.filter((g) => g.kind !== 'domain' || job.status !== 'running' || job.checks.has(g.key) || job.errors.some((e) => e.domain === g.key));
    groupsEl.append(...groups.map((g) => groupCard(g)));
  }

  function renderGone(built) {
    clear(goneEl);
    if (!built.gone.length) return;
    goneEl.append(Disclosure({
      summary: t('retire.passive.gone', { count: built.gone.length }),
      className: 'retire-gone-box',
      children: h('ul', { class: 'retire-gone-list' }, built.gone.map((g) => h('li', null,
        h('span', { class: 'mono' }, g.name), ' ',
        h('span', { class: 'muted text-sm' }, g.now.length ? t('retire.passive.now', { list: g.now.join(', ') }) : t('retire.passive.nowNone')))))
    }));
  }

  function renderProgress() {
    if (job.status !== 'running') {
      progress.el.hidden = true;
      statusEl.textContent = job.status === 'done' ? t('retire.progressDone', { count: job.checks.size }) : '';
      el.dataset.status = job.status;
      return;
    }
    progress.el.hidden = false;
    let done = 0;
    for (const d of job.domains) {
      if (job.checks.has(d) || job.errors.some((e) => e.domain === d)) done += 1;
      else {
        const p = job.progress.get(d);
        if (p && p.total) done += Math.min(0.95, p.done / p.total);
      }
    }
    const total = job.domains.length + (job.zoneRefs.length ? 0.5 : 0);
    progress.set(done, Math.max(1, total));
    const finishedDomains = job.domains.every((d) => job.checks.has(d) || job.errors.some((e) => e.domain === d));
    progress.setLabel(finishedDomains && job.zoneRefs.length
      ? t('retire.progressZone')
      : t('retire.progress', { domain: job.current || job.domains[0] || '', done: job.checks.size, total: job.domains.length }));
    statusEl.textContent = '';
    el.dataset.status = 'running';
  }

  function render() {
    const built = buildFor(job);
    renderHead(built);
    renderProgress();
    renderChips(built);
    renderStats(built);
    renderOwners();
    renderGroups(built);
    renderGone(built);
    summary.setDisabled(job.status === 'running');
    exportCsv.disabled = job.status === 'running';
    exportJson.disabled = job.status === 'running';
  }

  const renderSoon = throttle(render, 250);
  const renderProgressSoon = throttle(renderProgress, 150);
  const listener = (type) => {
    if (type === 'progress' || type === 'start') renderProgressSoon();
    else if (type === 'domain' || type === 'zone') renderSoon();
    else {
      renderSoon.cancel();
      render();
      if (type === 'done') {
        const built = buildFor(job);
        announce(t('retire.head.title', { label: job.label }));
        el.dataset.breaking = String(built.counts.breaking);
      }
      onFinish();
    }
  };
  job.listeners.add(listener);
  render();
  if (job.status !== 'running') el.dataset.breaking = String(buildFor(job).counts.breaking);

  return {
    el,
    render,
    dispose() {
      job.listeners.delete(listener);
      renderSoon.cancel();
      renderProgressSoon.cancel();
    }
  };
}
