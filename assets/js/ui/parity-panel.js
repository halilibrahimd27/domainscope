/**
 * ui/parity-panel.js — the Zone File's "New name servers" tab: before the NS records change at the
 * registrar, do the NEW provider's name servers serve what the file says? The logic is
 * lib/nsparity.js; this module only renders it.
 *
 * - Nothing is sent until "Compare" is clicked. Then, behind the shared Globalping gate
 *   (ui/globalping-gate.js: the free quota read, the consent + cost dialog on the first send of
 *   the page session and again for a batch of more than {@link PARITY_CONFIRM_ABOVE} probes),
 *   one DNS measurement per record set goes to Globalping with the new server as the resolver,
 *   and one DS query of the zone's name to the DoH resolvers of the settings. Names and types
 *   only: never a value of the file or an origin address, never an internal-looking name
 *   (unless its switch is turned off), never the hidden target of a proxied record.
 * - The job lives on the holder the Zone File view owns (`P`, its module session): it keeps
 *   running while another tab or tool is shown, and "Forget", a new import or another workspace
 *   drop it with the zone (the view calls {@link stopParity}).
 * - The CLI card hands the whole zone to cli/dns_parity.py (the zone as canonical BIND text,
 *   written by lib/zoneparse.js toBindText): free, every record, every server, CAA included.
 * - Every string is rendered through h() / text nodes: record values are DNS data.
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, DataTable, Disclosure, ErrorBanner, Icon, ProgressBar, SegmentedControl, SeverityIcon,
  announce, checkbox, radioGroup, textarea, toast
} from './components.js';
import { downloadText } from './download.js';
import { gateProbes, noteQuota, whenText, measurementUrl } from './globalping-gate.js';
import { t, registerStrings, formatNumber, formatDateTime } from '../i18n.js';
import {
  parseNameservers, fileNameservers, planParity, runParity, paritySummary, parityRunbook, parityZoneFile, buildParityCommand, extraQueries,
  PARITY_STATUSES, PARITY_SEVERITY, PARITY_REASONS, PARITY_MAX_PROBES, PARITY_MAX_NAMESERVERS, NS_STATES, NS_ISSUES,
  RUNBOOK_STEPS, RUNBOOK_STATES, PARITY_CLI
} from '../lib/nsparity.js';
import { privateLookingNames } from '../lib/zoneorigins.js';
import { toBindText } from '../lib/zoneparse.js';
import { errorKind } from '../lib/util.js';

/** Consent purpose of the gate (one per feature: each sends different data). */
export const PARITY_PURPOSE = 'ns-parity';
/** A batch of more probes than this asks for confirmation again, as Verify does. */
export const PARITY_CONFIRM_ABOVE = 50;
/** Where the site serves the CLI (document-relative, like cli/ssl_origin_scan.py). */
export const PARITY_CLI_PATH = 'cli/dns_parity.py';
/** Drift reasons worded for the new name servers (`par.reason.<r>`); the rest read as the live check's. */
export const PARITY_WORDED = Object.freeze(['nxdomain', 'nodata', 'cname-live', 'proxy-on-live', 'proxy-off-live', 'not-cloudflare',
  'servfail', 'refused', 'transport', 'timeout', 'budget', 'wildcard', 'private', 'not-queryable']);

const STATE_ICON = Object.freeze({ ok: 'ok', todo: 'info', warn: 'warn', blocked: 'error', info: 'info' });
const SEV_VARIANT = Object.freeze({ ok: 'ok', info: 'info', warn: 'warn', error: 'error', unknown: 'neutral' });

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'zone.tab.parity': 'New name servers',
  'par.title': 'Compare with the new name servers',
  'par.lead': 'Before you change the NS records at the registrar: are the new provider’s name servers ready? Each record set of this file is asked of the new servers themselves, through Globalping probes, and compared with the file: what is missing or different there, what they have that the file does not, and the TTLs.',
  'par.ns.label': 'The new name servers',
  'par.ns.placeholder': 'ns1.example.net\nns2.example.net',
  'par.ns.hint': 'The host names the new provider gave you (their addresses work too), one per line or separated by spaces. Up to {max}.',
  'par.nsIssue.invalid': 'Not a name server: {value}',
  'par.nsIssue.private': '{value} is a private or documentation address: a probe cannot reach it. The CLI below can.',
  'par.nsIssue.too-many': 'Only {max} name servers are compared; {value} is left out.',
  'par.nsIssue.in-file': '{value} is one of this file’s own name servers: that is the current provider, whose answers the Live check compares.',
  'par.nsNeeded': 'Enter the new provider’s name servers first.',
  'par.mode.legend': 'What to ask',
  'par.mode.first': 'Every record set on the first server, the SOA serial on the others',
  'par.mode.firstHint': 'A provider’s name servers serve one copy of the zone; the serial shows each one serves the same version.',
  'par.mode.all': 'Every record set on every server',
  'par.mode.allHint': { one: '{count} probe.', other: '{count} probes.' },
  'par.mode.allOver': 'Over the {max}-probe limit of one check: use the CLI.',
  'par.extras': 'Look for records the file does not have, at the apex and www ({count} more per server)',
  'par.skipPrivate': 'Skip names that look internal ({count})',
  'par.plan': {
    one: '{rrsets} record sets → {probes} Globalping probe (at most {max} per check).',
    other: '{rrsets} record sets → {probes} Globalping probes (at most {max} per check).'
  },
  'par.notQueryable': {
    one: '{count} record set of a type Globalping cannot ask (CAA, TLSA …) is left to the CLI.',
    other: '{count} record sets of types Globalping cannot ask (CAA, TLSA …) are left to the CLI.'
  },
  'par.capped': 'This zone needs {needed} probes; one check stops at {max}, so {checked} of {rrsets} record sets are compared and the rest are marked “Not compared”. The CLI below compares every record, for free.',
  'par.run': { one: 'Compare {count} record set', other: 'Compare {count} record sets' },
  'par.rerun': 'Compare again',
  'par.stop': 'Stop',
  'par.privacy': 'Sends to Globalping only the names and record types asked ({probes} DNS queries) and the name servers’ host names; one DS query of {origin} goes to your DNS-over-HTTPS resolvers. The values of the file, the origin addresses and the names that look internal stay here. Anyone with a measurement ID can read its result for about six months: the answers of your new name servers, which anyone can already ask them for.',
  'par.running': 'Asking the new name servers…',
  'par.progress': '{done} / {total} probes',
  'par.failed': 'The comparison failed',
  'par.quota': 'Not enough Globalping probes left this hour. More are available {when}; the CLI below needs none.',
  'par.stopped.quota': 'The hourly Globalping quota ran out: the comparison stopped. What was answered is shown; compare again {when}, or use the CLI.',
  'par.stopped.unreachable': 'Globalping could not be reached: the comparison stopped. What was answered is shown.',
  'par.stopped.abort': 'Stopped: what was answered is shown.',
  'par.finished': 'New name servers: {count} to fix',
  'par.checkedAt': 'Compared {time} · {probes} probes',

  'par.head.ready': 'The new name servers serve every compared record set of this file.',
  'par.head.fix': 'Fix the new provider’s zone before you switch: {missing} missing, {different} different{servers}.',
  'par.head.fixServers': { one: ', {count} name server that does not serve it', other: ', {count} name servers that do not serve it' },
  'par.head.check': 'Nothing is missing or different. Check the rest before you switch: {extra} extra, {unproxied} not proxied, {ttl} TTL differences.',
  'par.head.partial': 'Nothing is missing or different so far, but not everything was compared: {unchecked} record sets were not (the CLI compares every record).',
  'par.head.blocked': 'No new name server serves {origin} yet: create the zone at the new provider (import this file there), then compare again.',
  'par.serials.differ': 'The name servers serve different SOA serials: they are not in sync yet.',

  'par.role.full': 'every record',
  'par.role.serial': 'serial',
  'par.ns.ok': 'Serves the zone · serial {serial}',
  'par.ns.refused': 'Refuses the zone: it does not serve {origin} (yet)',
  'par.ns.not-authoritative': 'Answers without authority: it is not {origin}’s name server (yet)',
  'par.ns.no-zone': 'Has no SOA for {origin}',
  'par.ns.servfail': 'Answers SERVFAIL for {origin}',
  'par.ns.unreachable': 'Could not be reached from the probe: its name does not resolve, or it does not answer',
  'par.ns.failed': 'The measurement failed',
  'par.ns.not-run': 'Not asked: the comparison stopped',
  'par.ns.probe': 'asked from {where}',
  'par.ns.measurement': 'measurement',

  'par.status.same': 'Same',
  'par.status.different': 'Different',
  'par.status.missing': 'Missing there',
  'par.status.unproxied': 'Not proxied there',
  'par.status.extra': 'Extra there',
  'par.status.skipped': 'Not compared',
  'par.status.error': 'No answer',
  'par.allStatuses': 'All',
  'par.col.status': 'Status',
  'par.col.ns': 'Name server',
  'par.col.name': 'Name',
  'par.col.type': 'Type',
  'par.col.file': 'In the file',
  'par.col.new': 'At the new server',
  'par.col.ttl': 'TTL (file → new)',
  'par.col.note': 'Note',
  'par.includeOrigins': 'Include origin addresses in exports',

  'par.reason.nxdomain': 'The name does not exist at the new name server.',
  'par.reason.nodata': 'The new name server has the name, but no record of this type.',
  'par.reason.cname-live': 'The new name server answers with a CNAME instead.',
  'par.reason.proxy-on-live': 'DNS-only in the file, but the new name server answers Cloudflare addresses: the proxy is on there.',
  'par.reason.proxy-off-live': 'The new name server answers the origin itself: at the switch this name stops being proxied, and its server’s address becomes public.',
  'par.reason.not-cloudflare': 'Proxied in the file, but the new name server answers other addresses.',
  'par.reason.servfail': 'The name server answered SERVFAIL.',
  'par.reason.refused': 'The name server refused the question.',
  'par.reason.transport': 'The probe got no answer from the name server (or the measurement failed).',
  'par.reason.timeout': 'No result in time.',
  'par.reason.budget': 'Not compared: the probe limit of one check was reached.',
  'par.reason.wildcard': 'Asked through a random name under the wildcard.',
  'par.reason.private': 'Not asked: the name looks internal.',
  'par.reason.not-queryable': 'Globalping cannot ask this record type: the CLI compares it.',
  'par.reason.ttl-differs': 'The TTL differs from the file’s.',
  'par.reason.ns-new': 'The new provider’s own name servers, as expected: the file lists the current provider’s.',
  'par.reason.ns-mismatch': 'The new provider’s zone names other name servers than the ones entered: check the delegation you are about to set.',
  'par.reason.ns-by-address': 'Name servers entered as addresses: which names the NS records should hold is not known here.',
  'par.reason.extra-record': 'Not in the file: a provider’s default record (a parking address, a default MX) would start answering at the switch.',
  'par.reason.cname-kept': 'Flattened at the current provider; the new one serves the CNAME itself. Resolvers get the same answer.',
  'par.reason.below-cut': 'Below a delegation: the child zone’s name servers answer it, not the new provider’s.',

  'par.steps.title': 'The move, step by step',
  'par.step.ttl.todo': 'Lower the TTLs at the current provider before the switch: the NS records at the apex ({nsTtl} now) and every record you will change (the longest in this file: {maxTtl}), to {low} or less, then wait for the old values to run out. The TLD’s own NS TTL (often one or two days) cannot be lowered: plan for it.',
  'par.step.ttl.ok': 'The TTLs in this file are {low} or less (apex NS: {nsTtl}): resolvers pick up the switch quickly. The TLD’s own NS TTL (often one or two days) still applies.',
  'par.step.fix.info': 'Compare the new name servers with this file (above). Fix what is missing or different at the new provider, then compare again until nothing is left.',
  'par.step.fix.todo': 'Fix at the new provider: {missing} missing, {different} different. Then compare again.',
  'par.step.fix.todoServers': {
    one: '{count} of the name servers does not serve the zone yet: create it there, or check the name you entered.',
    other: '{count} of the name servers do not serve the zone yet: create it there, or check the names you entered.'
  },
  'par.unproxied': {
    one: '{count} proxied record is answered with its origin at the new provider: at the switch it stops being proxied, and its server’s address becomes public. Protect the origin (a firewall that admits only the new proxy) or keep the proxy.',
    other: '{count} proxied records are answered with their origins at the new provider: at the switch they stop being proxied, and their servers’ addresses become public. Protect the origins (a firewall that admits only the new proxy) or keep the proxy.'
  },
  'par.step.fix.warn': 'Nothing is missing or different. Check the rest: {extra} extra, {unproxied} not proxied, {unchecked} not compared here (the CLI compares every record, CAA included).',
  'par.step.fix.ok': 'The new name servers serve every compared record set of this file.',
  'par.step.fix.blocked': 'No new name server serves this zone yet: create it at the new provider (import this file there) and compare again.',
  'par.step.dnssec.todo': 'The zone is signed (a DS record at the registrar, or DNSSEC records in this file). Before the switch, either remove the DS record at the registrar and wait until its TTL has passed (up to two days), or, only if both providers support multi-signer DNSSEC (RFC 8901), publish the new provider’s DNSKEY in the old zone and its DS at the registrar first. Switching with only the old DS in place makes validating resolvers answer SERVFAIL. Sign at the new provider and add its DS once the old delegation has run out.',
  'par.step.dnssec.ok': 'No DS record at the registrar: there is no DNSSEC order to keep. Sign at the new provider after the move if you want DNSSEC.',
  'par.step.dnssec.info': 'If the registrar has a DS record for the zone, remove it (and wait for its TTL) or pre-publish the new provider’s DNSKEY before the switch. The comparison looks the DS up.',
  'par.step.switch.todo': 'Switch the NS records at the registrar to {nameservers}. Change nothing at the current provider meanwhile.',
  'par.step.switch.blocked': 'Do not switch yet: fix the differences above first.',
  'par.step.wait.todo': 'Keep the old provider’s zone answering, unchanged, for at least {hours} hours: resolvers that cached the old delegation keep asking the old servers until it runs out. A record you change in that time must change at both providers.',
  'par.step.after.todo': 'Then check from outside: the Live check of this page and Global DNS should show the new servers’ answers everywhere. Restore the TTLs you lowered.',
  'par.state.ok': 'Done',
  'par.state.todo': 'To do',
  'par.state.warn': 'Check',
  'par.state.blocked': 'Blocked',
  'par.state.info': 'Before the switch',
  'par.ttlUnknown': 'unknown',
  'par.step.nsUnknown': 'the new provider’s name servers',

  'par.cli.title': 'Every record, from your own machine (CLI)',
  'par.cli.lead': 'dns_parity.py asks each new name server directly (UDP / TCP port 53), for every record set of the file, CAA and TLSA included, and every name server: no probes, no limit. Python 3.8+, no packages.',
  'par.cli.zone': 'Download the zone (BIND)',
  'par.cli.script': 'dns_parity.py',
  'par.cli.shell': 'Shell',
  'par.cli.posix': 'Linux / macOS',
  'par.cli.powershell': 'Windows PowerShell',
  'par.cli.needNs': 'Enter the new name servers above to get the command.',
  'par.cli.dropped': { one: '{count} entry is not a host name or an address and is left out of the command.', other: '{count} entries are not host names or addresses and are left out of the command.' }
});

registerStrings('tr', {
  'zone.tab.parity': 'Yeni ad sunucuları',
  'par.title': 'Yeni ad sunucularıyla karşılaştırın',
  'par.lead': 'Kayıt kuruluşundaki NS kayıtlarını değiştirmeden önce: yeni sağlayıcının ad sunucuları hazır mı? Bu dosyadaki her kayıt kümesi Globalping ölçümleriyle doğrudan yeni sunuculara sorulur ve dosyayla karşılaştırılır: orada eksik ya da farklı olanlar, dosyada olmayıp onlarda olanlar ve TTL’ler.',
  'par.ns.label': 'Yeni ad sunucuları',
  'par.ns.placeholder': 'ns1.example.net\nns2.example.net',
  'par.ns.hint': 'Yeni sağlayıcının verdiği host adları (adresleri de olur), her satıra bir tane ya da boşlukla ayrılmış. En fazla {max}.',
  'par.nsIssue.invalid': 'Bir ad sunucusu değil: {value}',
  'par.nsIssue.private': '{value} özel ya da dokümantasyon adresi: ölçüm noktası ona ulaşamaz. Aşağıdaki CLI ulaşır.',
  'par.nsIssue.too-many': 'Yalnızca {max} ad sunucusu karşılaştırılır; {value} dışarıda kaldı.',
  'par.nsIssue.in-file': '{value} bu dosyanın kendi ad sunucularından biri: bu, mevcut sağlayıcı; onun yanıtlarını Canlı kontrol karşılaştırır.',
  'par.nsNeeded': 'Önce yeni sağlayıcının ad sunucularını girin.',
  'par.mode.legend': 'Ne sorulsun',
  'par.mode.first': 'İlk sunucuya her kayıt kümesi, diğerlerine SOA seri numarası',
  'par.mode.firstHint': 'Bir sağlayıcının ad sunucuları zone’un tek bir kopyasını sunar; seri numarası her birinin aynı sürümü sunduğunu gösterir.',
  'par.mode.all': 'Her sunucuya her kayıt kümesi',
  'par.mode.allHint': '{count} ölçüm.',
  'par.mode.allOver': 'Bir kontrolün {max} ölçüm sınırını aşıyor: CLI’ı kullanın.',
  'par.extras': 'Dosyada olmayan kayıtları apex ve www’da arayın (sunucu başına {count} ölçüm daha)',
  'par.skipPrivate': 'İç ağa ait görünen adları atla ({count})',
  'par.plan': '{rrsets} kayıt kümesi → {probes} Globalping ölçümü (kontrol başına en fazla {max}).',
  'par.notQueryable': '{count} kayıt kümesi Globalping’in soramadığı bir türde (CAA, TLSA …): CLI’a kalır.',
  'par.capped': 'Bu zone {needed} ölçüm istiyor; bir kontrol {max} ölçümde durur, bu yüzden {rrsets} kayıt kümesinin {checked} tanesi karşılaştırılır, kalanlar “Karşılaştırılmadı” olarak işaretlenir. Aşağıdaki CLI her kaydı ücretsiz karşılaştırır.',
  'par.run': '{count} kayıt kümesini karşılaştır',
  'par.rerun': 'Yeniden karşılaştır',
  'par.stop': 'Durdur',
  'par.privacy': 'Globalping’e yalnızca sorulan adlar ve kayıt türleri ({probes} DNS sorgusu) ile ad sunucularının host adları gider; {origin} için bir DS sorgusu DNS-over-HTTPS çözümleyicilerinize gider. Dosyadaki değerler, origin adresleri ve iç ağa ait görünen adlar burada kalır. Ölçüm kimliğini bilen herkes sonucu yaklaşık altı ay okuyabilir: yeni ad sunucularınızın yanıtları, ki bunları herkes zaten onlara sorabilir.',
  'par.running': 'Yeni ad sunucularına soruluyor…',
  'par.progress': '{done} / {total} ölçüm',
  'par.failed': 'Karşılaştırma başarısız oldu',
  'par.quota': 'Bu saat için yeterli Globalping ölçümü kalmadı. {when} yeniden kullanılabilir; aşağıdaki CLI ölçüm harcamaz.',
  'par.stopped.quota': 'Saatlik Globalping kotası doldu: karşılaştırma durdu. Yanıtlananlar gösteriliyor; {when} yeniden karşılaştırın ya da CLI’ı kullanın.',
  'par.stopped.unreachable': 'Globalping’e ulaşılamadı: karşılaştırma durdu. Yanıtlananlar gösteriliyor.',
  'par.stopped.abort': 'Durduruldu: yanıtlananlar gösteriliyor.',
  'par.finished': 'Yeni ad sunucuları: düzeltilecek {count} şey',
  'par.checkedAt': '{time} karşılaştırıldı · {probes} ölçüm',

  'par.head.ready': 'Yeni ad sunucuları bu dosyanın karşılaştırılan her kayıt kümesini sunuyor.',
  'par.head.fix': 'Geçişten önce yeni sağlayıcıdaki zone’u düzeltin: {missing} eksik, {different} farklı{servers}.',
  'par.head.fixServers': ', zone’u sunmayan {count} ad sunucusu',
  'par.head.check': 'Eksik ya da farklı bir şey yok. Geçişten önce kalanlara bakın: {extra} fazladan, {unproxied} proxy’siz, {ttl} TTL farkı.',
  'par.head.partial': 'Şimdiye kadar eksik ya da farklı bir şey yok, ama her şey karşılaştırılmadı: {unchecked} kayıt kümesi karşılaştırılmadı (CLI her kaydı karşılaştırır).',
  'par.head.blocked': 'Henüz hiçbir yeni ad sunucusu {origin} zone’unu sunmuyor: zone’u yeni sağlayıcıda oluşturun (bu dosyayı oraya aktarın), sonra yeniden karşılaştırın.',
  'par.serials.differ': 'Ad sunucuları farklı SOA seri numaraları sunuyor: henüz eşitlenmemişler.',

  'par.role.full': 'her kayıt',
  'par.role.serial': 'seri no',
  'par.ns.ok': 'Zone’u sunuyor · seri no {serial}',
  'par.ns.refused': 'Zone’u reddediyor: {origin} zone’unu (henüz) sunmuyor',
  'par.ns.not-authoritative': 'Yetkisiz yanıt veriyor: (henüz) {origin} zone’unun ad sunucusu değil',
  'par.ns.no-zone': '{origin} için SOA kaydı yok',
  'par.ns.servfail': '{origin} için SERVFAIL döndürüyor',
  'par.ns.unreachable': 'Ölçüm noktasından ulaşılamadı: adı çözümlenmiyor ya da yanıt vermiyor',
  'par.ns.failed': 'Ölçüm başarısız oldu',
  'par.ns.not-run': 'Sorulmadı: karşılaştırma durdu',
  'par.ns.probe': '{where} üzerinden soruldu',
  'par.ns.measurement': 'ölçüm',

  'par.status.same': 'Aynı',
  'par.status.different': 'Farklı',
  'par.status.missing': 'Orada eksik',
  'par.status.unproxied': 'Orada proxy’siz',
  'par.status.extra': 'Orada fazladan',
  'par.status.skipped': 'Karşılaştırılmadı',
  'par.status.error': 'Yanıt yok',
  'par.allStatuses': 'Tümü',
  'par.col.status': 'Durum',
  'par.col.ns': 'Ad sunucusu',
  'par.col.name': 'Ad',
  'par.col.type': 'Tür',
  'par.col.file': 'Dosyada',
  'par.col.new': 'Yeni sunucuda',
  'par.col.ttl': 'TTL (dosya → yeni)',
  'par.col.note': 'Not',
  'par.includeOrigins': 'Dışa aktarımlara origin adreslerini ekle',

  'par.reason.nxdomain': 'Ad yeni ad sunucusunda yok.',
  'par.reason.nodata': 'Yeni ad sunucusunda ad var, ama bu türde kaydı yok.',
  'par.reason.cname-live': 'Yeni ad sunucusu bunun yerine bir CNAME ile yanıt veriyor.',
  'par.reason.proxy-on-live': 'Dosyada yalnızca DNS, ama yeni ad sunucusu Cloudflare adresleri döndürüyor: orada proxy açık.',
  'par.reason.proxy-off-live': 'Yeni ad sunucusu origin’in kendisini döndürüyor: geçişte bu ad proxy’den çıkar ve sunucusunun adresi herkese açık olur.',
  'par.reason.not-cloudflare': 'Dosyada proxy’li, ama yeni ad sunucusu başka adresler döndürüyor.',
  'par.reason.servfail': 'Ad sunucusu SERVFAIL döndürdü.',
  'par.reason.refused': 'Ad sunucusu soruyu reddetti.',
  'par.reason.transport': 'Ölçüm noktası ad sunucusundan yanıt alamadı (ya da ölçüm başarısız oldu).',
  'par.reason.timeout': 'Sonuç zamanında gelmedi.',
  'par.reason.budget': 'Karşılaştırılmadı: bir kontrolün ölçüm sınırına ulaşıldı.',
  'par.reason.wildcard': 'Joker kaydın altındaki rastgele bir adla soruldu.',
  'par.reason.private': 'Sorulmadı: ad iç ağa ait görünüyor.',
  'par.reason.not-queryable': 'Globalping bu kayıt türünü soramaz: CLI karşılaştırır.',
  'par.reason.ttl-differs': 'TTL dosyadakinden farklı.',
  'par.reason.ns-new': 'Beklendiği gibi yeni sağlayıcının kendi ad sunucuları: dosya mevcut sağlayıcınınkileri listeler.',
  'par.reason.ns-mismatch': 'Yeni sağlayıcıdaki zone, girilenlerden başka ad sunucuları listeliyor: ayarlamak üzere olduğunuz yetki devrini kontrol edin.',
  'par.reason.ns-by-address': 'Ad sunucuları adres olarak girildi: NS kayıtlarında hangi adların olması gerektiği burada bilinmiyor.',
  'par.reason.extra-record': 'Dosyada yok: sağlayıcının varsayılan bir kaydı (park adresi, varsayılan MX) geçişte yanıt vermeye başlar.',
  'par.reason.cname-kept': 'Mevcut sağlayıcıda düzleştirilmiş; yenisi CNAME’in kendisini sunuyor. Çözümleyiciler aynı yanıtı alır.',
  'par.reason.below-cut': 'Bir yetki devrinin altında: onu yeni sağlayıcınınkiler değil, alt zone’un ad sunucuları yanıtlar.',

  'par.steps.title': 'Adım adım taşıma',
  'par.step.ttl.todo': 'Geçişten önce mevcut sağlayıcıda TTL’leri düşürün: apex’teki NS kayıtları (şu an {nsTtl}) ve değiştireceğiniz her kayıt (bu dosyadaki en uzunu: {maxTtl}), {low} ya da daha azına; sonra eski değerlerin dolmasını bekleyin. TLD’nin kendi NS TTL’i (çoğu zaman bir iki gün) düşürülemez: bunu hesaba katın.',
  'par.step.ttl.ok': 'Bu dosyadaki TTL’ler {low} ya da daha az (apex NS: {nsTtl}): çözümleyiciler geçişi çabuk görür. TLD’nin kendi NS TTL’i (çoğu zaman bir iki gün) yine geçerlidir.',
  'par.step.fix.info': 'Yeni ad sunucularını bu dosyayla karşılaştırın (yukarıda). Yeni sağlayıcıda eksik ya da farklı olanı düzeltin, hiçbir şey kalmayana kadar yeniden karşılaştırın.',
  'par.step.fix.todo': 'Yeni sağlayıcıda düzeltin: {missing} eksik, {different} farklı. Sonra yeniden karşılaştırın.',
  'par.step.fix.todoServers': 'Ad sunucularından {count} tanesi zone’u henüz sunmuyor: zone’u orada oluşturun ya da girdiğiniz adları kontrol edin.',
  'par.unproxied': '{count} proxy’li kayıt yeni sağlayıcıda origin’iyle yanıtlanıyor: geçişte proxy’den çıkar ve sunucu adresleri herkese açık olur. Origin’leri koruyun (yalnızca yeni proxy’ye izin veren bir güvenlik duvarı) ya da proxy’yi koruyun.',
  'par.step.fix.warn': 'Eksik ya da farklı bir şey yok. Kalanlara bakın: {extra} fazladan, {unproxied} proxy’siz, burada karşılaştırılmayan {unchecked} (CLI her kaydı, CAA dahil, karşılaştırır).',
  'par.step.fix.ok': 'Yeni ad sunucuları bu dosyanın karşılaştırılan her kayıt kümesini sunuyor.',
  'par.step.fix.blocked': 'Henüz hiçbir yeni ad sunucusu bu zone’u sunmuyor: zone’u yeni sağlayıcıda oluşturun (bu dosyayı oraya aktarın) ve yeniden karşılaştırın.',
  'par.step.dnssec.todo': 'Zone imzalı (kayıt kuruluşunda bir DS kaydı ya da bu dosyada DNSSEC kayıtları var). Geçişten önce ya kayıt kuruluşundaki DS kaydını silin ve TTL’i dolana kadar bekleyin (iki güne kadar), ya da yalnızca iki sağlayıcı da çok imzacılı DNSSEC’i (RFC 8901) destekliyorsa, önce yeni sağlayıcının DNSKEY’ini eski zone’a, DS’ini kayıt kuruluşuna ekleyin. Yalnızca eski DS yerindeyken geçiş yapmak, doğrulayan çözümleyicilerin SERVFAIL döndürmesine yol açar. Eski yetki devrinin süresi dolunca yeni sağlayıcıda imzalayıp DS’ini ekleyin.',
  'par.step.dnssec.ok': 'Kayıt kuruluşunda DS kaydı yok: korunacak bir DNSSEC sırası yok. DNSSEC isterseniz taşımadan sonra yeni sağlayıcıda imzalayın.',
  'par.step.dnssec.info': 'Kayıt kuruluşunda zone için bir DS kaydı varsa, geçişten önce silin (ve TTL’ini bekleyin) ya da yeni sağlayıcının DNSKEY’ini önceden yayımlayın. Karşılaştırma DS kaydına bakar.',
  'par.step.switch.todo': 'Kayıt kuruluşundaki NS kayıtlarını {nameservers} olarak değiştirin. Bu sırada mevcut sağlayıcıda hiçbir şeyi değiştirmeyin.',
  'par.step.switch.blocked': 'Henüz geçiş yapmayın: önce yukarıdaki farkları düzeltin.',
  'par.step.wait.todo': 'Eski sağlayıcıdaki zone’u en az {hours} saat değiştirmeden yanıt verir durumda tutun: eski yetki devrini önbelleğe alan çözümleyiciler, süresi dolana kadar eski sunuculara sormaya devam eder. Bu sürede değiştirdiğiniz bir kaydı iki sağlayıcıda da değiştirin.',
  'par.step.after.todo': 'Sonra dışarıdan kontrol edin: bu sayfanın Canlı kontrolü ve Global DNS her yerde yeni sunucuların yanıtlarını göstermeli. Düşürdüğünüz TTL’leri geri yükseltin.',
  'par.state.ok': 'Tamam',
  'par.state.todo': 'Yapılacak',
  'par.state.warn': 'Kontrol edin',
  'par.state.blocked': 'Engelli',
  'par.state.info': 'Geçişten önce',
  'par.ttlUnknown': 'bilinmiyor',
  'par.step.nsUnknown': 'yeni sağlayıcının ad sunucuları',

  'par.cli.title': 'Her kayıt, kendi makinenizden (CLI)',
  'par.cli.lead': 'dns_parity.py dosyadaki her kayıt kümesini (CAA ve TLSA dahil) her yeni ad sunucusuna doğrudan sorar (UDP / TCP 53. port): ölçüm yok, sınır yok. Python 3.8+, ek paket gerekmez.',
  'par.cli.zone': 'Zone’u indir (BIND)',
  'par.cli.script': 'dns_parity.py',
  'par.cli.shell': 'Kabuk',
  'par.cli.posix': 'Linux / macOS',
  'par.cli.powershell': 'Windows PowerShell',
  'par.cli.needNs': 'Komutu görmek için yukarıya yeni ad sunucularını girin.',
  'par.cli.dropped': '{count} girdi host adı ya da adres değil; komuta alınmadı.'
});

/**
 * Every i18n key this panel builds from a library code (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  const keys = [];
  for (const s of PARITY_STATUSES) keys.push(`par.status.${s}`);
  for (const r of [...PARITY_REASONS, ...PARITY_WORDED]) keys.push(`par.reason.${r}`);
  for (const s of NS_STATES) keys.push(`par.ns.${s}`);
  for (const c of NS_ISSUES) keys.push(`par.nsIssue.${c}`);
  for (const step of RUNBOOK_STEPS) {
    for (const st of RUNBOOK_STATES) if (stepKeyExists(step, st)) keys.push(`par.step.${step}.${st}`);
  }
  for (const st of RUNBOOK_STATES) keys.push(`par.state.${st}`);
  for (const v of ['ready', 'fix', 'check', 'partial', 'blocked']) keys.push(`par.head.${v}`);
  for (const s of ['quota', 'unreachable', 'abort']) keys.push(`par.stopped.${s}`);
  return keys;
}

/** The runbook states each step can be in (lib/nsparity.js parityRunbook). */
const STEP_STATES = Object.freeze({
  ttl: ['todo', 'ok'], fix: ['info', 'todo', 'warn', 'ok', 'blocked'], dnssec: ['todo', 'ok', 'info'], switch: ['todo', 'blocked'],
  wait: ['todo'], after: ['todo']
});
const stepKeyExists = (step, state) => (STEP_STATES[step] || []).includes(state);

/** The text key of a row's reason: worded for the new name servers, else the live check's. */
export function reasonKey(r) {
  return PARITY_REASONS.includes(r) || PARITY_WORDED.includes(r) ? `par.reason.${r}` : `zone.reason.${r}`;
}

/* ------------------------------------------------------------------------ */
/* The job holder                                                           */
/* ------------------------------------------------------------------------ */

/**
 * A fresh holder for the tab (the Zone File view keeps it in its module session).
 * @returns {object}
 */
export function freshParity() {
  return {
    nsText: '', mode: 'first', extras: true, skipPrivate: true, status: 'idle', result: null, rows: [], servers: [],
    done: 0, total: 0, spent: 0, error: null, resetAt: null, controller: null, filter: 'all', shell: 'posix',
    includeOrigins: false, finishedAt: null, hook: null
  };
}

/**
 * Stop a running comparison (a new import, Forget, another workspace): nothing more is sent.
 * @param {object|null} P
 */
export function stopParity(P) {
  if (P && P.controller) P.controller.abort();
}

const ttlText = (v) => (Number.isFinite(v) ? `${formatNumber(v)} s` : t('par.ttlUnknown'));
const relName = (name, origin) => (name === origin ? '@' : origin && name.endsWith(`.${origin}`) ? name.slice(0, -origin.length - 1) : name);

/* ------------------------------------------------------------------------ */
/* The tab                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * The "New name servers" tab body.
 * @param {{ ctx: object, zone: object, P: object, redact?: (values: string[], include: boolean) => string[],
 *   onDone?: (result: object) => void }} opts
 *   `redact`: the Zone File's export redaction of origin addresses (views/zone.js redactValues)
 * @returns {HTMLElement}
 */
export function ParityTab({ ctx, zone, P, redact = (values) => values, onDone = null }) {
  const box = h('div', { class: 'stack zone-parity', dataset: { shortcutScope: 'zone-parity' } });
  const fileNs = fileNameservers(zone);
  const internal = privateLookingNames(zone).size;
  let progressBar = null;

  const parsed = () => parseNameservers(P.nsText, { fileNs });
  const planFor = (list, mode = P.mode) => planParity(zone, { nameservers: list, mode, extras: P.extras, skipPrivate: P.skipPrivate });
  const running = () => !!P.controller;

  function render() {
    if (!box.isConnected && box.childElementCount) return;
    const focusRole = document.activeElement && box.contains(document.activeElement) ? document.activeElement.dataset.role || document.activeElement.dataset.action : null;
    clear(box);
    box.append(formCard());
    if (P.status === 'running' || P.status === 'gate') {
      progressBar = ProgressBar({ label: t('par.progress', { done: formatNumber(P.done), total: formatNumber(P.total) }), value: P.done, max: Math.max(1, P.total) });
      box.append(h('div', { class: 'par-progress', attrs: { role: 'status' } }, h('p', { class: 'text-sm muted' }, t('par.running')), progressBar.el || progressBar));
    } else {
      progressBar = null;
    }
    if (P.status === 'failed' && P.error) box.append(ErrorBanner(P.error, { title: t('par.failed'), compact: true }));
    if (P.status === 'quota') box.append(Alert({ variant: 'warn', compact: true, icon: 'clock', message: t('par.quota', { when: whenText(P.resetAt) }) }));
    if (P.result) box.append(results());
    box.append(runbookCard(), cliCard());
    if (focusRole) {
      const again = box.querySelector(`[data-role="${focusRole}"], [data-action="${focusRole}"]`);
      if (again && !again.disabled) again.focus();
    }
  }

  function progress() {
    if (!progressBar || !box.isConnected) return;
    progressBar.setLabel(t('par.progress', { done: formatNumber(P.done), total: formatNumber(P.total) }));
    progressBar.set(P.done, Math.max(1, P.total));
  }

  /* --- the form ------------------------------------------------------------ */
  function formCard() {
    const { list, issues } = parsed();
    const planAll = planFor(list, 'all');
    // Every record on every server stops fitting the probe limit: back to the batched mode.
    if (P.mode === 'all' && list.length && !planAll.ok) P.mode = 'first';
    const plan = planFor(list);
    const nsField = textarea({
      label: t('par.ns.label'),
      value: P.nsText,
      rows: 2,
      placeholder: t('par.ns.placeholder'),
      hint: t('par.ns.hint', { max: PARITY_MAX_NAMESERVERS }),
      className: 'par-ns',
      attrs: { 'data-role': 'par-ns', inputmode: 'url' },
      onInput: (v) => {
        P.nsText = v;
        renderSoon();
      }
    });
    const issueList = issues.length ? h('ul', { class: 'par-issues text-sm', dataset: { role: 'par-issues' } },
      issues.map((i) => h('li', { dataset: { code: i.code } }, SeverityIcon(i.code === 'in-file' || i.code === 'too-many' ? 'info' : 'warn'), ' ',
        t(`par.nsIssue.${i.code}`, { value: i.value, max: PARITY_MAX_NAMESERVERS })))) : null;
    const allLabel = h('span', null, t('par.mode.all'), ' ', h('span', { class: 'muted' },
      planAll.ok ? t('par.mode.allHint', { count: planAll.probes }) : planAll.why === 'over-cap' ? t('par.mode.allOver', { max: PARITY_MAX_PROBES }) : ''));
    const mode = radioGroup({
      legend: t('par.mode.legend'),
      value: P.mode,
      className: 'par-mode',
      options: [
        { value: 'first', label: t('par.mode.first'), hint: t('par.mode.firstHint') },
        { value: 'all', label: allLabel, disabled: list.length > 0 && !planAll.ok }
      ],
      onChange: (v) => {
        P.mode = v === 'all' ? 'all' : 'first';
        render();
      }
    });
    mode.inputs.forEach((i) => { i.dataset.role = `par-mode-${i.value}`; });
    // Nothing to look for (a CNAME or a proxied apex, a wildcard over www): no switch to show.
    const extraCount = extraQueries(zone, { skipPrivate: P.skipPrivate }).length;
    const extras = checkbox({
      label: t('par.extras', { count: formatNumber(extraCount) }),
      checked: P.extras,
      onChange: (on) => {
        P.extras = !!on;
        render();
      }
    });
    extras.input.dataset.role = 'par-extras';
    const priv = checkbox({
      label: t('par.skipPrivate', { count: formatNumber(internal) }),
      checked: P.skipPrivate,
      onChange: (on) => {
        P.skipPrivate = !!on;
        render();
      }
    });
    priv.input.dataset.role = 'par-skip-private';
    const planLine = list.length && plan.ok
      ? h('p', { class: 'par-plan', dataset: { role: 'par-plan', probes: String(plan.probes) } },
        t('par.plan', { count: plan.probes, rrsets: formatNumber(plan.rrsets), probes: formatNumber(plan.probes), max: PARITY_MAX_PROBES }))
      : h('p', { class: 'par-plan muted', dataset: { role: 'par-plan', probes: '0' } }, t('par.nsNeeded'));
    const runBtn = Button({
      label: P.result ? t('par.rerun') : t('par.run', { count: plan.ok ? plan.checked || plan.rrsets : 0 }),
      icon: 'globe',
      variant: 'primary',
      disabled: running() || !plan.ok,
      dataset: { action: 'par-run', shortcut: 'submit' },
      onClick: () => start()
    });
    const stopBtn = running() ? Button({ label: t('par.stop'), icon: 'stop', variant: 'secondary', dataset: { action: 'par-stop', shortcut: 'cancel' }, onClick: () => stopParity(P) }) : null;
    const card = Card({
      title: t('par.title'),
      icon: 'server',
      className: 'par-card',
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm' }, t('par.lead')),
        nsField.el,
        issueList,
        mode.el,
        h('div', { class: 'cluster par-options' }, extraCount ? extras.el : null, internal ? priv.el : null),
        planLine,
        list.length && plan.skipped.type ? h('p', { class: 'text-sm muted', dataset: { role: 'par-not-queryable' } }, t('par.notQueryable', { count: plan.skipped.type })) : null,
        list.length && plan.capped && plan.ok ? Alert({ variant: 'info', compact: true, message: t('par.capped', {
          needed: formatNumber(plan.needed), max: PARITY_MAX_PROBES, checked: formatNumber(plan.checked), rrsets: formatNumber(plan.rrsets)
        }) }) : null,
        h('div', { class: 'cluster par-actions' }, runBtn, stopBtn),
        h('p', { class: 'muted text-xs par-privacy' }, Icon('lock', { size: 12 }), ' ',
          t('par.privacy', { probes: formatNumber(plan.probes || 0), origin: zone.origin })))
    });
    return card;
  }

  let renderTimer = null;
  function renderSoon() {
    clearTimeout(renderTimer);
    renderTimer = setTimeout(() => {
      // Typing in the box: rebuild the rest, keep the caret where it is.
      const ta = box.querySelector('[data-role="par-ns"]');
      const sel = ta && document.activeElement === ta ? [ta.selectionStart, ta.selectionEnd] : null;
      render();
      if (sel) {
        const again = box.querySelector('[data-role="par-ns"]');
        again.focus();
        again.setSelectionRange(sel[0], sel[1]);
      }
    }, 250);
  }

  /* --- the run ------------------------------------------------------------- */
  async function start() {
    if (running() || !ctx.requireOnline()) return;
    const { list } = parsed();
    const plan = planFor(list);
    if (!plan.ok) return;
    const ac = new AbortController();
    const prev = { status: P.status, result: P.result, rows: P.rows, servers: P.servers };
    Object.assign(P, { controller: ac, status: 'gate', error: null, done: 0, total: plan.probes });
    ctx.setBusy(true);
    render();
    try {
      const gate = await gateProbes(ctx, {
        purpose: PARITY_PURPOSE, probes: plan.probes, signal: ac.signal, confirmAbove: PARITY_CONFIRM_ABOVE, className: 'par-confirm',
        privacy: t('par.privacy', { probes: formatNumber(plan.probes), origin: zone.origin })
      });
      if (P.controller !== ac) return;
      if (gate.status === 'cancelled') {
        Object.assign(P, prev);
        return;
      }
      if (gate.status === 'quota') {
        Object.assign(P, prev, { status: 'quota', resetAt: gate.resetAt });
        announce(t('par.quota', { when: whenText(gate.resetAt) }));
        return;
      }
      if (gate.status === 'unreachable') throw gate.error;
      Object.assign(P, { status: 'running', result: null, rows: [], servers: [], spent: 0 });
      render();
      let dns = null;
      try {
        dns = await ctx.getDns();
      } catch {
        dns = null; // the DS question is optional
      }
      const result = await runParity(zone, {
        client: gate.client,
        nameservers: list,
        mode: P.mode,
        extras: P.extras,
        skipPrivate: P.skipPrivate,
        dns,
        signal: ac.signal,
        onRow: (row) => { if (P.controller === ac) P.rows.push(row); },
        onServer: (s) => { if (P.controller === ac) P.servers.push(s); },
        onProgress: ({ done, total, spent }) => {
          if (P.controller !== ac) return;
          Object.assign(P, { done, total, spent });
          progress();
        },
        onQuota: (q) => noteQuota(q)
      });
      if (P.controller !== ac) return;
      Object.assign(P, { status: 'done', result, rows: result.rows, servers: result.nameservers, spent: result.spent, resetAt: result.resetAt, finishedAt: new Date(), filter: 'all' });
      const sum = paritySummary(result);
      const count = (sum.counts.missing || 0) + (sum.counts.different || 0) + sum.badServers;
      announce(t(`par.head.${sum.verdict}`, headParams(result, sum)));
      if (!box.isConnected) {
        toast(t('par.finished', { count }), { type: count ? 'warn' : 'success', action: { label: t('zone.tab.parity'), onClick: () => ctx.navigate('zone', { tab: 'parity' }) } });
      }
      if (onDone) onDone(result);
    } catch (err) {
      if (P.controller !== ac) return;
      if (errorKind(err) === 'abort' || ac.signal.aborted) Object.assign(P, prev);
      else Object.assign(P, { status: 'failed', error: err });
    } finally {
      if (P.controller === ac) P.controller = null;
      ctx.setBusy(false);
      if (P.hook) P.hook.render();
    }
  }

  function headParams(result, sum) {
    const c = sum.counts;
    return {
      missing: formatNumber(c.missing || 0), different: formatNumber(c.different || 0), extra: formatNumber(c.extra || 0),
      unproxied: formatNumber(c.unproxied || 0), ttl: formatNumber(sum.ttl), unchecked: formatNumber(sum.unchecked), origin: result.origin,
      servers: sum.badServers ? t('par.head.fixServers', { count: sum.badServers }) : ''
    };
  }

  /* --- results ------------------------------------------------------------- */
  function results() {
    const result = P.result;
    const sum = paritySummary(result);
    const out = h('div', { class: 'stack-sm par-results', dataset: { status: P.status, verdict: sum.verdict } });
    const variant = { ready: 'ok', fix: 'error', check: 'warn', partial: 'info', blocked: 'error' }[sum.verdict];
    out.append(Alert({ variant, message: t(`par.head.${sum.verdict}`, headParams(result, sum)) }));
    if (result.stoppedBy) {
      out.append(Alert({ variant: result.stoppedBy === 'abort' ? 'info' : 'warn', compact: true,
        message: t(`par.stopped.${result.stoppedBy}`, { when: whenText(result.resetAt) }) }));
    }
    if (result.serials === 'differ') out.append(Alert({ variant: 'warn', compact: true, message: t('par.serials.differ') }));
    if (sum.counts.unproxied) out.append(Alert({ variant: 'warn', compact: true, message: t('par.unproxied', { count: sum.counts.unproxied }) }));
    out.append(h('p', { class: 'muted text-sm' }, t('par.checkedAt', { time: formatDateTime(P.finishedAt || result.finishedAt), probes: formatNumber(result.spent) })));
    out.append(serverList(result));
    if (P.rows.length) out.append(rowTable(result));
    return out;
  }

  function serverList(result) {
    return h('ul', { class: 'par-servers', dataset: { role: 'par-servers' } }, result.nameservers.map((s) => {
      const sev = s.state === 'ok' ? 'ok' : s.state === 'not-run' ? 'info' : 'error';
      const where = s.probe ? [s.probe.city, s.probe.country].filter(Boolean).join(', ') + (s.probe.asn ? ` (AS${s.probe.asn})` : '') : null;
      const link = s.measurementId ? measurementUrl(s.measurementId) : null;
      return h('li', { class: 'par-server', dataset: { ns: s.ns, state: s.state, role: s.role } },
        SeverityIcon(sev),
        h('span', { class: 'par-server-body' },
          h('strong', { class: 'mono' }, s.ns), ' ',
          Badge(t(`par.role.${s.role}`), { variant: 'neutral' }), ' ',
          h('span', null, t(`par.ns.${s.state}`, { serial: s.serial ?? '', origin: result.origin })),
          where ? h('span', { class: 'muted text-sm' }, ` · ${t('par.ns.probe', { where })}`) : null,
          link ? h('span', { class: 'text-sm' }, ' · ', h('a', { href: link, class: 'link', attrs: { target: '_blank', rel: 'noopener noreferrer' } }, t('par.ns.measurement'))) : null));
    }));
  }

  function valueLines(values) {
    return h('span', { class: 'zone-values' }, values.map((v) => h('span', null, v)));
  }

  function rowTable(result) {
    const counts = {};
    for (const r of P.rows) counts[r.status] = (counts[r.status] || 0) + 1;
    const several = result.nameservers.filter((s) => s.role === 'full' && s.state === 'ok').length > 1;
    const sevVariant = (s) => SEV_VARIANT[PARITY_SEVERITY[s]] || 'neutral';
    const columns = [
      { key: 'status', label: t('par.col.status'), sortable: true, exportValue: (r) => r.status,
        render: (r) => h('span', { dataset: { status: r.status } }, Badge(t(`par.status.${r.status}`), { variant: sevVariant(r.status) })) },
      several ? { key: 'ns', label: t('par.col.ns'), sortable: true, mono: true, render: (r) => r.ns } : null,
      { key: 'name', label: t('par.col.name'), sortable: true, render: (r) => h('strong', null, relName(r.name, result.origin)), exportValue: (r) => r.name },
      { key: 'type', label: t('par.col.type'), sortable: true, render: (r) => Badge(r.type, { variant: 'neutral', mono: true }) },
      { key: 'file', label: t('par.col.file'), mono: true, wrap: true, searchValue: (r) => r.file.join(' '),
        exportValue: (r) => redact(r.file, P.includeOrigins).join(' '), render: (r) => valueLines(r.file) },
      { key: 'live', label: t('par.col.new'), mono: true, wrap: true, searchValue: (r) => r.live.join(' '),
        exportValue: (r) => redact(r.live, P.includeOrigins).join(' '),
        render: (r) => (r.status === 'different' && (r.added.length || r.removed.length)
          ? h('span', { class: 'zone-diff' }, r.removed.map((v) => h('span', { class: 'zone-diff-del' }, `− ${v}`)), r.added.map((v) => h('span', { class: 'zone-diff-add' }, `+ ${v}`)))
          : valueLines(r.live)) },
      { key: 'ttl', label: t('par.col.ttl'), mono: true, exportValue: (r) => (r.fileTtl ?? '') + (r.liveTtl !== null && r.liveTtl !== undefined ? ` ${r.liveTtl}` : ''),
        render: (r) => (Number.isFinite(r.fileTtl) || Number.isFinite(r.liveTtl)
          ? h('span', { class: ['par-ttl', { 'par-ttl-differs': r.reasons.includes('ttl-differs') }] }, `${r.fileTtl ?? '–'} → ${r.liveTtl ?? '–'}`) : '') },
      { key: 'note', label: t('par.col.note'), wrap: true, exportValue: (r) => r.reasons.join(' '),
        render: (r) => h('span', { class: 'text-sm' }, r.reasons.map((x) => t(reasonKey(x))).join(' ')) }
    ].filter(Boolean);
    const table = DataTable({
      caption: t('zone.tab.parity'),
      rowKey: (r) => r.key,
      pageSize: 200,
      search: true,
      className: 'par-table',
      cellLabels: true,
      filter: (r) => P.filter === 'all' || r.status === P.filter,
      export: { filename: `${result.origin}-ns-parity`, formats: ['csv', 'json'] },
      columns
    });
    table.setRows(P.rows);
    const chips = h('div', { class: 'zone-chips cluster', attrs: { role: 'group', 'aria-label': t('par.col.status') } });
    const chip = (value, label, n) => h('button', {
      type: 'button',
      class: 'zone-chip',
      dataset: { filter: value },
      attrs: { 'aria-pressed': String(P.filter === value) },
      on: {
        click: () => {
          P.filter = value;
          chips.querySelectorAll('.zone-chip').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.filter === value)));
          table.setFilter((r) => P.filter === 'all' || r.status === P.filter);
        }
      }
    }, value === 'all' ? null : SeverityIcon(PARITY_SEVERITY[value] === 'unknown' ? 'info' : PARITY_SEVERITY[value]), `${label} (${formatNumber(n)})`);
    chips.append(chip('all', t('par.allStatuses'), P.rows.length));
    for (const s of PARITY_STATUSES) if (counts[s]) chips.append(chip(s, t(`par.status.${s}`), counts[s]));
    const inc = checkbox({
      label: t('par.includeOrigins'),
      checked: P.includeOrigins,
      onChange: (on) => { P.includeOrigins = !!on; }
    });
    inc.input.dataset.role = 'par-include-origins';
    return h('div', { class: 'stack-sm' }, chips, inc.el, table.el);
  }

  /* --- runbook ------------------------------------------------------------- */
  function runbookCard() {
    const { list } = parsed();
    const steps = parityRunbook(zone, P.result, { nameservers: P.result ? P.result.nameservers.map((s) => s.ns) : list });
    const items = steps.map((s) => {
      const p = { ...s.params };
      const params = {
        nsTtl: ttlText(p.nsTtl), maxTtl: ttlText(p.maxTtl), low: ttlText(p.low), hours: p.hours,
        missing: formatNumber(p.missing || 0), different: formatNumber(p.different || 0), extra: formatNumber(p.extra || 0),
        unproxied: formatNumber(p.unproxied || 0), unchecked: formatNumber(p.unchecked || 0), servers: formatNumber(p.servers || 0),
        nameservers: p.nameservers || t('par.step.nsUnknown')
      };
      return h('li', { class: 'par-step', dataset: { step: s.id, state: s.state } },
        h('span', { class: 'par-step-icon' }, SeverityIcon(STATE_ICON[s.state] || 'info')),
        h('span', { class: 'par-step-body' },
          h('span', { class: 'par-step-state text-xs' }, t(`par.state.${s.state}`)),
          h('span', null, t(`par.step.${s.id}.${s.state}`, params)),
          s.id === 'fix' && s.state === 'todo' && p.servers ? h('span', null, t('par.step.fix.todoServers', { count: p.servers })) : null));
    });
    return Card({
      title: t('par.steps.title'),
      icon: 'list',
      className: 'par-steps-card',
      children: h('ol', { class: 'par-steps', dataset: { role: 'par-steps' } }, items)
    });
  }

  /* --- CLI ------------------------------------------------------------------ */
  function cliCard() {
    const { list } = parsed();
    const file = parityZoneFile(zone.origin);
    const cmd = buildParityCommand({ file, nameservers: list, shell: P.shell });
    const shell = SegmentedControl({
      label: t('par.cli.shell'), size: 'sm', value: P.shell, className: 'par-shell',
      options: [{ value: 'posix', label: t('par.cli.posix') }, { value: 'powershell', label: t('par.cli.powershell') }],
      onChange: (v) => {
        P.shell = v === 'powershell' ? 'powershell' : 'posix';
        render();
      }
    });
    return Disclosure({
      summary: t('par.cli.title'),
      className: 'par-cli',
      open: !!(P.result && (P.result.capped || paritySummary(P.result).unchecked)),
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm' }, t('par.cli.lead')),
        h('div', { class: 'cluster' },
          Button({ label: t('par.cli.zone'), icon: 'download', size: 'sm', dataset: { action: 'par-zone-file' }, onClick: () => downloadText(file, toBindText(zone)) }),
          h('a', { class: 'btn btn-ghost btn-sm', href: PARITY_CLI_PATH, download: PARITY_CLI }, Icon('download', { size: 14 }), h('span', { class: 'btn-label' }, t('par.cli.script')))),
        shell.el,
        cmd.command ? CodeBlock(cmd.command, { wrap: true, className: 'zone-command par-command' })
          : h('p', { class: 'muted text-sm', dataset: { role: 'par-cli-empty' } }, t('par.cli.needNs')),
        cmd.dropped ? h('p', { class: 'muted text-sm' }, t('par.cli.dropped', { count: cmd.dropped })) : null)
    });
  }

  P.hook = { render, progress };
  render();
  return box;
}
