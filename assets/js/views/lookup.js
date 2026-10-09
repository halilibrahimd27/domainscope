/**
 * views/lookup.js — "DNS Lookup": query one name for many record types through the shared
 * DoH client (automatic failover chain) or one specific resolver, with optional DNSSEC (DO)
 * and CD bits. Every type gets a card with the records parsed into readable fields (SOA
 * timers, MX by preference, CAA tags, SVCB/HTTPS parameters, DNSKEY key tags, RRSIG
 * validity …), the header flags (AA/TC/RD/RA/AD/CD), RCODE, Extended DNS Errors and the raw
 * dig-style presentation text with a copy button. Host names and IP addresses in the
 * results link to this view / IP Intel.
 *
 * The page template (ui/template.js): the input card (compact once a lookup runs) and the summary
 * as the result header `.lkp-sum` — who answered, the counts, Copy summary, Export (the answers
 * in dig format) and Copy link, the next steps, "Also check:".
 *
 * "Copy summary" in the summary: the answer in one line for Jira / Slack (lib/summary.js),
 * with the link of that query and the time its last answer arrived.
 *
 * "DNSSEC chain" among the summary's next steps (ui/dnssec-panel.js over lib/dnssec.js, loaded on its first
 * click): the chain of trust of the name and one of the looked-up types, validated in this browser
 * from the IANA root trust anchors down, zone by zone; a new lookup closes it.
 *
 * "Explain" among the summary's next steps (ui/explain-panel.js over lib/records.js and lib/spfexplain.js,
 * loaded on its first click; not for a reverse name or the root): the name's SPF term by term with
 * "Does an address pass?" and a flatten preview, the DMARC and CAA that apply tag by tag, and its
 * HTTPS / SVCB parameters with the ECH configuration decoded; the lookup's answers are reused, a
 * new lookup closes it.
 *
 * Shareable: `#/lookup?name=example.com&type=MX` (type may repeat or be comma-separated;
 * optional `resolver=<id>`, `dnssec=1`, `cd=1`). An IP address as name becomes a PTR query.
 * With `run=0` (a name carried over from another tool, lib/session.js) the form is only filled
 * in. The finished answers are kept for the page session (`result()` / `snapshot()`).
 *
 * Density (lib/density.js lookupLayout): plain NODATA types get no card but a place in one "No
 * records: AAAA, CAA, …" line of the summary; the resolver that answered, its PoP and the header
 * flags are said once in the summary, and a card repeats only what differs; on wide screens the
 * cards flow in CSS columns and keep the column they settled in (opening a raw answer grows its
 * own column only). A query that got no answer keeps its card, says which resolver failed and
 * why (lib/sourcestatus.js), and its Retry asks that type again.
 */

import { h, clear, scrollBehavior } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, CopyButton, Disclosure, Icon, KeyValueList, KindBadge,
  Spinner, announce, checkbox, checkboxGroup, select, setButtonBusy, textInput
} from '../ui/components.js';
import { registerStrings, hasString, formatNumber, formatDuration, formatDateTime, formatDate } from '../i18n.js';
import {
  EmptyState, ExampleChips, NextSteps, PrivacyNote, RelatedLinks, ResultActions, ResultHeader, ResultTitle, RunBar, StatusSummary, ToolInput
} from '../ui/template.js';
import { inputCompact, optionsSummary, templateState } from '../lib/template.js';
import { downloadText, timestampedName } from '../ui/download.js';
import { RESOLVERS, getResolver } from '../lib/resolvers.js';
import { typeToNumber, typeToName, DNSSEC_ALGORITHMS, DS_DIGEST_TYPES } from '../lib/dnswire.js';
import { followCnames } from '../lib/doh.js';
import { classifyResolution, ipVersion, normalizeIP, reversePtrName } from '../lib/netinfo.js';
import { normalizeHostname } from '../lib/domain.js';
import { lookupServers } from '../lib/inventory.js';
import { CAA_ISSUERS } from '../lib/health.js';
import { mergeSignals, onceAsync } from '../lib/util.js';
import { fillReplaces, isFillOnly } from '../lib/session.js';
import { permalinkParams } from '../ui/view-summaries.js';
import { SummaryButton } from '../ui/summary-button.js';
import { lookupLayout, lookupStatus, LOOKUP_FLAGS } from '../lib/density.js';
import { dohStatus } from '../lib/sourcestatus.js';
import { RetryButton, statusText } from '../ui/source-status.js';

/** Route id (`#/lookup`). */
export const id = 'lookup';
/** i18n key of the page title. */
export const titleKey = 'nav.lookup';
/** Icon name (ui/components.js Icon). */
export const icon = 'search';

/** Record types offered as checkboxes, in display order. */
export const LOOKUP_TYPES = Object.freeze([
  'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'HTTPS', 'SVCB', 'SRV', 'PTR', 'NAPTR',
  'DS', 'DNSKEY', 'TLSA', 'SSHFP'
]);

/** Type presets. */
export const TYPE_PRESETS = Object.freeze({
  common: Object.freeze(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'HTTPS']),
  web: Object.freeze(['A', 'AAAA', 'CNAME', 'HTTPS', 'CAA']),
  mail: Object.freeze(['MX', 'TXT', 'SPF']),
  dnssec: Object.freeze(['DS', 'DNSKEY', 'SOA'])
});

/** Types that cannot be asked for directly (meta / pseudo types). */
const UNQUERYABLE = new Set(['OPT', 'TKEY', 'TSIG', 'IXFR', 'AXFR']);
const MAX_TYPES = 24;

const TLSA_USAGE = { 0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE' };
const TLSA_SELECTOR = { 0: 'Cert', 1: 'SPKI' };
const TLSA_MATCHING = { 0: 'Full', 1: 'SHA-256', 2: 'SHA-512' };
const SSHFP_ALG = { 1: 'RSA', 2: 'DSA', 3: 'ECDSA', 4: 'Ed25519', 6: 'Ed448' };
const SSHFP_TYPE = { 1: 'SHA-1', 2: 'SHA-256' };

registerStrings('en', {
  'lkp.name': 'Name or IP address',
  'lkp.namePlaceholder': 'example.com',
  'lkp.resolver': 'Resolver',
  'lkp.resolverAuto': 'Automatic ({chain})',
  'lkp.run': 'Look up',
  'lkp.types': 'Record types',
  'lkp.preset.common': 'All common',
  'lkp.preset.web': 'Web',
  'lkp.preset.mail': 'Mail',
  'lkp.preset.dnssec': 'DNSSEC',
  'lkp.preset.none': 'None',
  'lkp.otherTypes': 'Other types',
  'lkp.otherTypesHint': 'Any type mnemonic or number, comma-separated (e.g. URI, CDS, TYPE65).',
  'lkp.dnssec': 'DNSSEC (DO bit): include signatures (RRSIG) and proofs',
  'lkp.cd': 'Checking disabled (CD): skip DNSSEC validation',
  'lkp.cdHint': 'Useful to see the data of a zone whose DNSSEC is broken (validating resolvers answer SERVFAIL).',
  'lkp.invalidName': 'Enter a domain name (e.g. example.com) or an IP address.',
  'lkp.noTypes': 'Choose at least one record type.',
  'lkp.badTypes': 'Unknown record types: {types}',
  'lkp.tooManyTypes': 'At most {max} types per lookup.',
  'lkp.ptrNote': 'IP address detected: asking for its reverse DNS name (PTR {name}).',
  'lkp.emptyLine': 'Each record type parsed into readable fields, with its TTL, the header flags and the raw answer in dig format.',
  'lkp.privacy': 'Each question goes to your DoH resolvers, or to the one resolver you pick here.',
  'lkp.count.failed': { one: '{count} query failed', other: '{count} queries failed' },
  'lkp.count.nodata': { one: '{count} type has no records', other: '{count} types have no records' },
  'lkp.optResolver': 'resolver: {name}',
  'lkp.exportDigTitle': 'Download every answer as text, in dig format',

  'lkp.sum.title': '{name}',
  'lkp.sum.via': 'via {resolver}',
  'lkp.sum.types': { one: '{count} type', other: '{count} types' },
  'lkp.sum.records': { zero: 'no records', one: '{count} record', other: '{count} records' },
  'lkp.sum.time': 'in {time}',
  'lkp.sum.stopped': { one: 'Stopped: {count} type not answered', other: 'Stopped: {count} types not answered' },
  'lkp.sum.answeredBy': 'answered by {resolver}',
  'lkp.noRecords': 'No records:',
  'lkp.noRecordsBody': 'The name exists but has no records of these types (NODATA).',
  'lkp.dnssecChain': 'DNSSEC chain',
  'lkp.dnssecChainTitle': 'Validate the chain of trust of this answer from the root trust anchors down, in this browser',
  'lkp.explain': 'Explain',
  'lkp.explainTitle': 'The SPF, DMARC, CAA and HTTPS records of this name in plain words, with an SPF check for any address',
  'lkp.links': 'More about this name:',

  'lkp.card.records': { zero: 'No records', one: '{count} record', other: '{count} records' },
  'lkp.card.pop': 'PoP {id}',
  'lkp.card.failover': 'answered after trying {tried}',
  'lkp.card.querying': 'Querying…',
  'lkp.card.stopped': 'Stopped before an answer came.',
  'lkp.card.raw': 'Raw answer (dig format)',
  'lkp.card.failed': 'The query failed',
  'lkp.card.attempts': 'Resolvers tried',
  'lkp.card.allResolvers': 'Every resolver tried',
  'lkp.card.cached': 'from cache',

  'lkp.flag.aa': 'Authoritative answer',
  'lkp.flag.tc': 'Truncated',
  'lkp.flag.rd': 'Recursion desired',
  'lkp.flag.ra': 'Recursion available',
  'lkp.flag.ad': 'Authentic data: validated with DNSSEC',
  'lkp.flag.cd': 'Checking disabled',
  'lkp.flags': 'Flags',
  'lkp.ede': 'Extended DNS error {code}: {name}',

  'lkp.status.nxdomain': 'The name does not exist (NXDOMAIN).',
  'lkp.status.nodata': 'The name exists but has no {type} records (NODATA).',
  'lkp.status.servfail': 'The resolver could not get an answer (SERVFAIL) — often broken DNSSEC or unreachable name servers. Try again with “Checking disabled”.',
  'lkp.status.refused': 'The resolver refused the query (REFUSED).',
  'lkp.status.other': 'The resolver answered {rcode}.',
  'lkp.status.aliasOnly': 'The name is an alias; its target has no {type} records.',
  'lkp.negTtl': 'Negative answer cached for {time} (SOA minimum of {zone}).',

  'lkp.chain': 'Alias chain (CNAME)',
  'lkp.col.address': 'Address',
  'lkp.col.operator': 'Operator',
  'lkp.col.server': 'Your server',
  'lkp.col.ttl': 'TTL',
  'lkp.col.preference': 'Preference',
  'lkp.col.mailServer': 'Mail server',
  'lkp.col.nameServer': 'Name server',
  'lkp.col.target': 'Target',
  'lkp.col.priority': 'Priority',
  'lkp.col.weight': 'Weight',
  'lkp.col.port': 'Port',
  'lkp.col.flags': 'Flags',
  'lkp.col.tag': 'Tag',
  'lkp.col.value': 'Value',
  'lkp.col.meaning': 'Meaning',
  'lkp.col.params': 'Parameters',
  'lkp.col.keyTag': 'Key tag',
  'lkp.col.algorithm': 'Algorithm',
  'lkp.col.digestType': 'Digest type',
  'lkp.col.digest': 'Digest',
  'lkp.col.role': 'Role',
  'lkp.col.key': 'Public key',
  'lkp.col.covers': 'Covers',
  'lkp.col.signer': 'Signer',
  'lkp.col.validity': 'Validity',
  'lkp.col.next': 'Next name',
  'lkp.col.types': 'Types',
  'lkp.col.usage': 'Usage',
  'lkp.col.selector': 'Selector',
  'lkp.col.matching': 'Matching',
  'lkp.col.data': 'Data',
  'lkp.col.order': 'Order',
  'lkp.col.services': 'Services',
  'lkp.col.regexp': 'Regexp',
  'lkp.col.replacement': 'Replacement',
  'lkp.col.fingerprint': 'Fingerprint',
  'lkp.col.type': 'Type',
  'lkp.col.name': 'Name',

  'lkp.nullMx': 'Null MX (RFC 7505): this domain accepts no email.',
  'lkp.txt.strings': { one: '{count} string', other: '{count} strings' },
  'lkp.txt.chars': '{count} characters',
  'lkp.txt.verification': '{service} verification',
  'lkp.txt.split': 'Split into {count} strings of at most 255 characters — receivers join them without spaces.',
  'lkp.txt.analyse': 'Check SPF/DMARC in Domain Health',
  'lkp.soa.mname': 'Primary name server',
  'lkp.soa.rname': 'Responsible mailbox',
  'lkp.soa.serial': 'Serial',
  'lkp.soa.serialDate': 'date format: {date}, change {rev}',
  'lkp.soa.refresh': 'Refresh',
  'lkp.soa.refreshHint': 'how often secondaries check for changes',
  'lkp.soa.retry': 'Retry',
  'lkp.soa.retryHint': 'retry interval after a failed check',
  'lkp.soa.expire': 'Expire',
  'lkp.soa.expireHint': 'secondaries stop answering after this long without the primary',
  'lkp.soa.minimum': 'Negative TTL',
  'lkp.soa.minimumHint': 'how long “does not exist” answers are cached',
  'lkp.caa.critical': 'critical',
  'lkp.caa.issue': 'May issue certificates: {ca}',
  'lkp.caa.issuewild': 'May issue wildcard certificates: {ca}',
  'lkp.caa.deny': 'No CA may issue (empty value)',
  'lkp.caa.iodef': 'Violation reports go here',
  'lkp.caa.other': 'Other property',
  'lkp.svcb.alias': 'Alias mode',
  'lkp.svcb.sameName': 'same name',
  'lkp.svcb.ech': 'Encrypted Client Hello key ({bytes} bytes)',
  'lkp.dnskey.ksk': 'KSK',
  'lkp.dnskey.zsk': 'ZSK',
  'lkp.dnskey.revoked': 'Revoked',
  'lkp.dnskey.kskTitle': 'Key-signing key (SEP flag): signs the DNSKEY set; its hash is the DS record at the parent.',
  'lkp.dnskey.zskTitle': 'Zone-signing key: signs the zone’s other records.',
  'lkp.rrsig.title': 'Signatures (RRSIG)',
  'lkp.rrsig.valid': 'valid until {date}',
  'lkp.rrsig.expired': 'expired {date}',
  'lkp.rrsig.future': 'valid from {date}',
  'lkp.rrsig.validShort': 'Valid',
  'lkp.rrsig.expiredShort': 'Expired',
  'lkp.rrsig.futureShort': 'Not yet valid',
  'lkp.rrsig.allValid': 'all valid',
  'lkp.rrsig.problems': { one: '{count} problem', other: '{count} problems' },
  'lkp.authority': 'Authority section',
  'lkp.otherRecords': 'Other records in the answer',
  'lkp.dur.s': '{n} s',
  'lkp.dur.m': '{n} min',
  'lkp.dur.h': '{n} h',
  'lkp.dur.d': '{n} d'
});

registerStrings('tr', {
  'lkp.name': 'Ad veya IP adresi',
  'lkp.namePlaceholder': 'ornek.com.tr',
  'lkp.resolver': 'Çözümleyici',
  'lkp.resolverAuto': 'Otomatik ({chain})',
  'lkp.run': 'Sorgula',
  'lkp.types': 'Kayıt türleri',
  'lkp.preset.common': 'Yaygın olanların hepsi',
  'lkp.preset.web': 'Web',
  'lkp.preset.mail': 'E-posta',
  'lkp.preset.dnssec': 'DNSSEC',
  'lkp.preset.none': 'Hiçbiri',
  'lkp.otherTypes': 'Diğer türler',
  'lkp.otherTypesHint': 'Herhangi bir tür adı ya da numarası, virgülle ayırın (ör. URI, CDS, TYPE65).',
  'lkp.dnssec': 'DNSSEC (DO biti): imzaları (RRSIG) ve kanıtları da getir',
  'lkp.cd': 'Doğrulama kapalı (CD): DNSSEC doğrulamasını atla',
  'lkp.cdHint': 'DNSSEC’i bozuk bir bölgenin verisini görmek için kullanışlıdır (doğrulayan çözümleyiciler SERVFAIL döndürür).',
  'lkp.invalidName': 'Bir alan adı (ör. ornek.com.tr) ya da IP adresi girin.',
  'lkp.noTypes': 'En az bir kayıt türü seçin.',
  'lkp.badTypes': 'Bilinmeyen kayıt türleri: {types}',
  'lkp.tooManyTypes': 'Bir sorguda en fazla {max} tür seçilebilir.',
  'lkp.ptrNote': 'IP adresi algılandı: ters DNS adı soruluyor (PTR {name}).',
  'lkp.emptyLine': 'Her kayıt türü okunur alanlara ayrılmış olarak: TTL’i, başlık bayrakları ve dig biçiminde ham yanıtıyla.',
  'lkp.privacy': 'Her soru DoH çözümleyicilerinize ya da burada seçtiğiniz tek çözümleyiciye gider.',
  'lkp.count.failed': '{count} sorgu başarısız oldu',
  'lkp.count.nodata': '{count} türde kayıt yok',
  'lkp.optResolver': 'çözümleyici: {name}',
  'lkp.exportDigTitle': 'Tüm yanıtları dig biçiminde metin olarak indir',

  'lkp.sum.title': '{name}',
  'lkp.sum.via': '{resolver} üzerinden',
  'lkp.sum.types': '{count} tür',
  'lkp.sum.records': { zero: 'kayıt yok', other: '{count} kayıt' },
  'lkp.sum.time': '{time} içinde',
  'lkp.sum.stopped': 'Durduruldu: {count} tür yanıtlanmadı',
  'lkp.sum.answeredBy': '{resolver} yanıtladı',
  'lkp.noRecords': 'Kayıt yok:',
  'lkp.noRecordsBody': 'Ad mevcut ama bu türlerde kaydı yok (NODATA).',
  'lkp.dnssecChain': 'DNSSEC zinciri',
  'lkp.dnssecChainTitle': 'Bu yanıtın güven zincirini kök güven çapalarından başlayarak tarayıcınızda doğrular',
  'lkp.explain': 'Açıkla',
  'lkp.explainTitle': 'Bu adın SPF, DMARC, CAA ve HTTPS kayıtlarını sade bir dille açıklar; SPF’i herhangi bir adres için kontrol eder',
  'lkp.links': 'Bu ad hakkında daha fazlası:',

  'lkp.card.records': { zero: 'Kayıt yok', other: '{count} kayıt' },
  'lkp.card.pop': 'PoP {id}',
  'lkp.card.failover': '{tried} denendikten sonra yanıtlandı',
  'lkp.card.querying': 'Sorgulanıyor…',
  'lkp.card.stopped': 'Yanıt gelmeden durduruldu.',
  'lkp.card.raw': 'Ham yanıt (dig biçimi)',
  'lkp.card.failed': 'Sorgu başarısız oldu',
  'lkp.card.attempts': 'Denenen çözümleyiciler',
  'lkp.card.allResolvers': 'Denenen tüm çözümleyiciler',
  'lkp.card.cached': 'önbellekten',

  'lkp.flag.aa': 'Yetkili yanıt (authoritative)',
  'lkp.flag.tc': 'Kesilmiş (truncated)',
  'lkp.flag.rd': 'Özyineleme istendi',
  'lkp.flag.ra': 'Özyineleme destekleniyor',
  'lkp.flag.ad': 'Doğrulanmış veri: DNSSEC ile doğrulandı',
  'lkp.flag.cd': 'Doğrulama kapalı',
  'lkp.flags': 'Bayraklar',
  'lkp.ede': 'Genişletilmiş DNS hatası {code}: {name}',

  'lkp.status.nxdomain': 'Bu ad mevcut değil (NXDOMAIN).',
  'lkp.status.nodata': 'Ad mevcut ama {type} kaydı yok (NODATA).',
  'lkp.status.servfail': 'Çözümleyici yanıt alamadı (SERVFAIL) — genellikle bozuk DNSSEC ya da erişilemeyen ad sunucuları. “Doğrulama kapalı” ile tekrar deneyin.',
  'lkp.status.refused': 'Çözümleyici sorguyu reddetti (REFUSED).',
  'lkp.status.other': 'Çözümleyici {rcode} döndürdü.',
  'lkp.status.aliasOnly': 'Bu ad bir takma ad; hedefinde {type} kaydı yok.',
  'lkp.negTtl': 'Olumsuz yanıt {time} boyunca önbellekte tutulur ({zone} bölgesinin SOA minimum değeri).',

  'lkp.chain': 'Takma ad zinciri (CNAME)',
  'lkp.col.address': 'Adres',
  'lkp.col.operator': 'İşleten',
  'lkp.col.server': 'Sunucunuz',
  'lkp.col.ttl': 'TTL',
  'lkp.col.preference': 'Öncelik',
  'lkp.col.mailServer': 'E-posta sunucusu',
  'lkp.col.nameServer': 'Ad sunucusu',
  'lkp.col.target': 'Hedef',
  'lkp.col.priority': 'Öncelik',
  'lkp.col.weight': 'Ağırlık',
  'lkp.col.port': 'Port',
  'lkp.col.flags': 'Bayraklar',
  'lkp.col.tag': 'Etiket',
  'lkp.col.value': 'Değer',
  'lkp.col.meaning': 'Anlamı',
  'lkp.col.params': 'Parametreler',
  'lkp.col.keyTag': 'Anahtar etiketi',
  'lkp.col.algorithm': 'Algoritma',
  'lkp.col.digestType': 'Özet türü',
  'lkp.col.digest': 'Özet',
  'lkp.col.role': 'Rol',
  'lkp.col.key': 'Genel anahtar',
  'lkp.col.covers': 'Kapsadığı tür',
  'lkp.col.signer': 'İmzalayan',
  'lkp.col.validity': 'Geçerlilik',
  'lkp.col.next': 'Sonraki ad',
  'lkp.col.types': 'Türler',
  'lkp.col.usage': 'Kullanım',
  'lkp.col.selector': 'Seçici',
  'lkp.col.matching': 'Eşleştirme',
  'lkp.col.data': 'Veri',
  'lkp.col.order': 'Sıra',
  'lkp.col.services': 'Hizmetler',
  'lkp.col.regexp': 'Düzenli ifade',
  'lkp.col.replacement': 'Yerine geçen',
  'lkp.col.fingerprint': 'Parmak izi',
  'lkp.col.type': 'Tür',
  'lkp.col.name': 'Ad',

  'lkp.nullMx': 'Null MX (RFC 7505): bu alan adı hiç e-posta kabul etmiyor.',
  'lkp.txt.strings': '{count} parça',
  'lkp.txt.chars': '{count} karakter',
  'lkp.txt.verification': '{service} doğrulaması',
  'lkp.txt.split': 'En fazla 255 karakterlik {count} parçaya bölünmüş — alıcılar parçaları boşluksuz birleştirir.',
  'lkp.txt.analyse': 'SPF/DMARC’ı Alan Adı Sağlığı’nda incele',
  'lkp.soa.mname': 'Birincil ad sunucusu',
  'lkp.soa.rname': 'Sorumlu e-posta',
  'lkp.soa.serial': 'Seri numarası',
  'lkp.soa.serialDate': 'tarih biçimi: {date}, {rev}. değişiklik',
  'lkp.soa.refresh': 'Yenileme (refresh)',
  'lkp.soa.refreshHint': 'ikincil sunucuların değişiklikleri kontrol etme sıklığı',
  'lkp.soa.retry': 'Yeniden deneme (retry)',
  'lkp.soa.retryHint': 'başarısız kontrolden sonra tekrar deneme aralığı',
  'lkp.soa.expire': 'Sona erme (expire)',
  'lkp.soa.expireHint': 'birincile bu süre ulaşamayan ikinciller yanıt vermeyi keser',
  'lkp.soa.minimum': 'Negatif TTL',
  'lkp.soa.minimumHint': '“mevcut değil” yanıtlarının önbellekte kalma süresi',
  'lkp.caa.critical': 'kritik',
  'lkp.caa.issue': 'Sertifika verebilir: {ca}',
  'lkp.caa.issuewild': 'Joker (wildcard) sertifika verebilir: {ca}',
  'lkp.caa.deny': 'Hiçbir CA sertifika veremez (boş değer)',
  'lkp.caa.iodef': 'İhlal bildirimleri buraya gider',
  'lkp.caa.other': 'Diğer özellik',
  'lkp.svcb.alias': 'Takma ad modu',
  'lkp.svcb.sameName': 'aynı ad',
  'lkp.svcb.ech': 'Encrypted Client Hello anahtarı ({bytes} bayt)',
  'lkp.dnskey.ksk': 'KSK',
  'lkp.dnskey.zsk': 'ZSK',
  'lkp.dnskey.revoked': 'İptal edilmiş',
  'lkp.dnskey.kskTitle': 'Anahtar imzalama anahtarı (SEP bayrağı): DNSKEY kümesini imzalar; özeti üst bölgedeki DS kaydıdır.',
  'lkp.dnskey.zskTitle': 'Bölge imzalama anahtarı: bölgenin diğer kayıtlarını imzalar.',
  'lkp.rrsig.title': 'İmzalar (RRSIG)',
  'lkp.rrsig.valid': '{date} tarihine kadar geçerli',
  'lkp.rrsig.expired': '{date} tarihinde süresi doldu',
  'lkp.rrsig.future': '{date} tarihinden itibaren geçerli',
  'lkp.rrsig.validShort': 'Geçerli',
  'lkp.rrsig.expiredShort': 'Süresi dolmuş',
  'lkp.rrsig.futureShort': 'Henüz geçerli değil',
  'lkp.rrsig.allValid': 'hepsi geçerli',
  'lkp.rrsig.problems': '{count} sorun',
  'lkp.authority': 'Yetki (authority) bölümü',
  'lkp.otherRecords': 'Yanıttaki diğer kayıtlar',
  'lkp.dur.s': '{n} sn',
  'lkp.dur.m': '{n} dk',
  'lkp.dur.h': '{n} sa',
  'lkp.dur.d': '{n} gün'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/**
 * Normalise a list of record types from a URL param / text box: mnemonics (any case),
 * RFC 3597 'TYPE123' or numbers; comma/space separated strings or arrays. Unknown and
 * meta types go to `invalid`. Order is kept, duplicates removed. Preset names expand to
 * their types, so shared links like `type=ALL` work: 'ALL' / 'COMMON' → the "All common"
 * preset; 'WEB', 'MAIL' and 'DNSSEC' → those presets (none of them is a type mnemonic).
 * @param {string|string[]|null|undefined} input
 * @returns {{ types: string[], invalid: string[] }}
 */
export function parseTypes(input) {
  const tokens = (Array.isArray(input) ? input : [input])
    .flatMap((v) => String(v ?? '').split(/[\s,;+]+/))
    .map((s) => s.trim())
    .filter(Boolean)
    .flatMap((s) => {
      const preset = s.toLowerCase() === 'all' ? 'common' : s.toLowerCase();
      return Object.hasOwn(TYPE_PRESETS, preset) ? TYPE_PRESETS[preset] : [s];
    });
  const types = [];
  const invalid = [];
  for (const token of tokens) {
    const num = typeToNumber(token);
    const name = num === null ? null : typeToName(num);
    if (!name || UNQUERYABLE.has(name) || num === 0) {
      if (!invalid.includes(token)) invalid.push(token);
    } else if (!types.includes(name)) {
      types.push(name);
    }
  }
  return { types, invalid };
}

/**
 * Interpret the name box: an IP address becomes its reverse (PTR) name; anything else is
 * normalised as a host name (URLs, trailing dots, IDNs accepted; single labels such as a TLD
 * are allowed). '.' is the root zone.
 * @param {string} raw
 * @returns {{ name: string, ptrFor: string|null }|null}
 */
export function parseLookupName(raw) {
  const text = String(raw ?? '').trim();
  if (!text) return null;
  if (text === '.') return { name: '.', ptrFor: null };
  const ip = normalizeIP(text);
  if (ip) return { name: reversePtrName(ip), ptrFor: ip };
  const host = normalizeHostname(text, { allowSingleLabel: true });
  return host ? { name: host, ptrFor: null } : null;
}

/**
 * A SOA serial in the common YYYYMMDDnn convention → { date: 'YYYY-MM-DD', rev }, else null.
 * @param {number} serial
 * @returns {{ date: string, rev: number }|null}
 */
export function soaSerialDate(serial) {
  const s = String(serial);
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})$/.exec(s);
  if (!m) return null;
  const [, y, mo, d, rev] = m.map(Number);
  if (y < 1990 || y > 2100 || mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  const date = new Date(Date.UTC(y, mo - 1, d));
  if (date.getUTCMonth() !== mo - 1) return null;
  return { date: `${m[1]}-${m[2]}-${m[3]}`, rev };
}

/**
 * Validity of an RRSIG at `now`.
 * @param {{ inception: Date, expiration: Date }} data
 * @param {number} [now=Date.now()]
 * @returns {'valid'|'expired'|'future'|'unknown'}
 */
export function rrsigStatus(data, now = Date.now()) {
  const inc = data && data.inception instanceof Date ? data.inception.getTime() : NaN;
  const exp = data && data.expiration instanceof Date ? data.expiration.getTime() : NaN;
  if (!Number.isFinite(inc) || !Number.isFinite(exp)) return 'unknown';
  if (now > exp) return 'expired';
  if (now < inc) return 'future';
  return 'valid';
}

const VERIFICATIONS = [
  [/^google-site-verification=/i, 'Google'],
  [/^MS=ms\d+/i, 'Microsoft 365'],
  [/^facebook-domain-verification=/i, 'Facebook'],
  [/^apple-domain-verification=/i, 'Apple'],
  [/^atlassian-domain-verification=/i, 'Atlassian'],
  [/^docusign=/i, 'DocuSign'],
  [/^adobe-idp-site-verification=/i, 'Adobe'],
  [/^yandex-verification:/i, 'Yandex'],
  [/^zoom-domain-verification/i, 'Zoom'],
  [/^(?:_)?globalsign-domain-verification=/i, 'GlobalSign'],
  [/^stripe-verification=/i, 'Stripe'],
  [/^openai-domain-verification=/i, 'OpenAI'],
  [/^hubspot-developer-verification=/i, 'HubSpot'],
  [/^cisco-ci-domain-verification=/i, 'Cisco'],
  [/^zoom[_-]verify[_=]/i, 'Zoom'],
  [/^([a-z0-9]+(?:-[a-z0-9]+)*?)(?:-site|-domain|-developer)?-verification[=:]/i, null]
];

/**
 * Recognise well-known TXT record kinds (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI and
 * domain-verification tokens).
 * @param {string} text joined TXT value
 * @returns {Array<{ kind: 'spf'|'dmarc'|'dkim'|'mta-sts'|'tls-rpt'|'bimi'|'verification', service?: string }>}
 */
export function txtKinds(text) {
  const s = String(text ?? '').trim();
  const out = [];
  if (/^v=spf1(?:\s|$)/i.test(s)) out.push({ kind: 'spf' });
  if (/^v\s*=\s*DMARC1\s*(?:;|$)/i.test(s)) out.push({ kind: 'dmarc' });
  if (/^v\s*=\s*DKIM1\s*(?:;|$)/i.test(s) || (/(?:^|;)\s*k\s*=\s*(?:rsa|ed25519)/i.test(s) && /(?:^|;)\s*p\s*=/i.test(s))) out.push({ kind: 'dkim' });
  if (/^v=STSv1\s*(?:;|$)/i.test(s)) out.push({ kind: 'mta-sts' });
  if (/^v=TLSRPTv1\s*(?:;|$)/i.test(s)) out.push({ kind: 'tls-rpt' });
  if (/^v=BIMI1\s*(?:;|$)/i.test(s)) out.push({ kind: 'bimi' });
  for (const [re, service] of VERIFICATIONS) {
    const m = re.exec(s);
    if (m) {
      out.push({ kind: 'verification', service: service || m[1].replace(/(^|-)([a-z])/g, (_, a, b) => `${a ? ' ' : ''}${b.toUpperCase()}`) });
      break;
    }
  }
  return out;
}

/**
 * dig-style line for a resource record: `owner. TTL CLASS TYPE rdata`.
 * @param {{ name: string, ttl: number, className?: string, type: string, text: string }} rr
 * @returns {string}
 */
export function digLine(rr) {
  const owner = !rr.name || rr.name === '.' ? '.' : `${rr.name}.`;
  return `${owner}\t${rr.ttl}\t${rr.className || 'IN'}\t${rr.type}\t${rr.text}`;
}

/**
 * Presentation text of a whole response (header comment, answer and authority sections).
 * @param {object} response DnsResponse
 * @returns {string}
 */
export function responseText(response) {
  if (!response) return '';
  const lines = [];
  const f = response.flags || {};
  const flags = ['qr', 'aa', 'tc', 'rd', 'ra', 'ad', 'cd'].filter((k) => f[k]).join(' ');
  lines.push(`;; ${response.name === '.' ? '.' : `${response.name}.`} ${response.type} @${response.resolver || '?'}`
    + (response.ok ? ` status: ${response.rcode}, flags: ${flags}` : ` error: ${response.error || 'failed'}`)
    + (Number.isFinite(response.elapsedMs) ? `, ${response.elapsedMs} ms` : ''));
  for (const e of response.ede || []) lines.push(`;; EDE ${e.code} (${e.name})${e.text ? `: ${e.text}` : ''}`);
  if (response.nsid) lines.push(`;; NSID: ${response.nsid}`);
  if (response.answers && response.answers.length) {
    lines.push('', ';; ANSWER SECTION:', ...response.answers.map(digLine));
  }
  if (response.authorities && response.authorities.length) {
    lines.push('', ';; AUTHORITY SECTION:', ...response.authorities.map(digLine));
  }
  return lines.join('\n');
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

let active = null;

/**
 * Mount the DNS Lookup view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const restored = ctx.restored && typeof ctx.restored === 'object' ? ctx.restored : null;

  /* --- helpers --------------------------------------------------------------- */
  const hostLink = (host, types = 'A,AAAA') => (host && host !== '.'
    ? h('a', { class: 'lkp-host mono', href: ctx.href('lookup', { name: host, type: types }) }, host)
    : h('span', { class: 'mono muted' }, '.'));
  const ipLink = (ip) => h('a', { class: 'lkp-ip mono', href: ctx.href('ip', { ips: ip }) }, ip);
  const duration = (sec) => {
    const n = Number(sec);
    if (!Number.isFinite(n)) return '—';
    if (n === 0) return t('lkp.dur.s', { n: 0 });
    const parts = [];
    let rest = n;
    for (const [unit, size] of [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]]) {
      if (rest >= size) {
        const q = Math.floor(rest / size);
        parts.push(t(`lkp.dur.${unit}`, { n: formatNumber(q) }));
        rest -= q * size;
      }
      if (parts.length === 2) break;
    }
    return parts.join(' ');
  };
  const ttlCell = (ttl) => h('span', { class: 'num lkp-ttl', title: duration(ttl) }, formatNumber(ttl));
  const simpleTable = (headers, rows, className = '') => h('div', { class: ['dt-scroll', 'dt-scroll-free', 'lkp-table', className], attrs: { tabindex: 0 } },
    h('table', { class: 'dt-table dt-dense' },
      h('thead', null, h('tr', null, headers.map((x) => h('th', { attrs: { scope: 'col' } }, x)))),
      h('tbody', null, rows.map((cells) => h('tr', { class: 'dt-row' }, cells.map((c) => {
        if (c && typeof c === 'object' && !c.nodeType && 'cell' in c) return h('td', { class: c.className || null }, c.cell ?? h('span', { class: 'dt-null' }, '—'));
        return h('td', null, c === null || c === undefined || c === '' ? h('span', { class: 'dt-null' }, '—') : c);
      }))))));
  const algName = (n) => (DNSSEC_ALGORITHMS[n] ? `${DNSSEC_ALGORITHMS[n]} (${n})` : String(n));
  const caName = (issuer) => {
    const ca = CAA_ISSUERS.find((x) => x.domains.includes(String(issuer).toLowerCase()));
    return ca ? ca.name : issuer;
  };
  // The CNAME chain of the answer counts too: CDNs such as Akamai are recognised by CNAME only.
  const classifyIp = (ip, cnames = []) => classifyResolution({ status: 'NOERROR', ipv4: ipVersion(ip) === 4 ? [ip] : [], ipv6: ipVersion(ip) === 6 ? [ip] : [], cnames });
  const resolverName = (rid) => (getResolver(rid) ? getResolver(rid).name : rid || '?');

  /* --- form -------------------------------------------------------------------- */
  const params = restored?.form || ctx.params;
  const initialTypes = (() => {
    const fromUrl = parseTypes(restored?.form?.types ?? ctx.searchParams.getAll('type')).types;
    return fromUrl.length ? fromUrl : [...TYPE_PRESETS.common];
  })();

  const nameField = textInput({
    label: t('lkp.name'),
    value: params.name || '',
    placeholder: t('lkp.namePlaceholder'),
    mono: true,
    className: 'lkp-name',
    attrs: { 'data-role': 'lookup-name', 'data-shortcut': 'focus', inputmode: 'url', enterkeyhint: 'search' },
    onEnter: () => start()
  });
  const chainNames = ctx.state.settings.chain.map(resolverName).join(' → ');
  const resolverField = select({
    label: t('lkp.resolver'),
    className: 'lkp-resolver',
    options: [
      { value: '', label: t('lkp.resolverAuto', { chain: chainNames }) },
      ...RESOLVERS.map((r) => ({ value: r.id, label: `${r.name}${r.filtering ? ` · ${t(`settings.filter.${r.filtering}`)}` : ''}` }))
    ],
    value: getResolver(params.resolver) ? params.resolver : ''
  });
  resolverField.input.dataset.role = 'lookup-resolver';
  // Stop (Esc) while a lookup asks: the answers in so far stay, each type still asked offers its Retry.
  const runBar = RunBar({
    label: t('lkp.run'),
    dataset: { action: 'run', shortcut: 'submit' },
    stopDataset: { action: 'lkp-stop', shortcut: 'cancel' },
    onRun: () => start(),
    onStop: () => stop(),
    hasValue: () => !!nameField.value.trim()
  });
  const runBtn = runBar.run;

  const known = new Set(LOOKUP_TYPES);
  const typeGroup = checkboxGroup({
    legend: t('lkp.types'),
    name: 'lkp-types',
    inline: true,
    options: LOOKUP_TYPES.map((x) => ({ value: x, label: x })),
    values: initialTypes.filter((x) => known.has(x)),
    className: 'lkp-types'
  });
  const otherField = textInput({
    label: t('lkp.otherTypes'),
    value: initialTypes.filter((x) => !known.has(x)).join(', '),
    placeholder: 'URI, CDS',
    mono: true,
    className: 'lkp-other',
    attrs: { 'data-role': 'lookup-other-types' },
    onEnter: () => start()
  });
  otherField.setHint(t('lkp.otherTypesHint'));
  const presetBar = h('div', { class: 'lkp-presets cluster' },
    ['common', 'web', 'mail', 'dnssec'].map((key) => Button({
      label: t(`lkp.preset.${key}`), size: 'sm', variant: 'secondary', dataset: { preset: key },
      onClick: () => {
        const list = TYPE_PRESETS[key];
        typeGroup.values = list.filter((x) => known.has(x));
        otherField.value = list.filter((x) => !known.has(x)).join(', ');
        syncRunBar();
      }
    })),
    Button({
      label: t('lkp.preset.none'), size: 'sm', variant: 'ghost', dataset: { preset: 'none' },
      onClick: () => {
        typeGroup.values = [];
        otherField.value = '';
        syncRunBar();
      }
    }));
  const dnssecField = checkbox({ label: t('lkp.dnssec'), checked: params.dnssec === '1' || params.dnssec === true, switch: true });
  dnssecField.input.dataset.role = 'lookup-dnssec';
  const cdField = checkbox({ label: t('lkp.cd'), hint: t('lkp.cdHint'), checked: params.cd === '1' || params.cd === true, switch: true });
  cdField.input.dataset.role = 'lookup-cd';

  // An example fills the form and leaves the keyboard on Look up: nothing is sent before that click.
  const examples = [
    { name: 'cloudflare.com', types: ['A', 'AAAA', 'HTTPS', 'CAA'] },
    { name: 'github.com', types: ['MX', 'TXT'] },
    { name: 'ietf.org', types: ['DS', 'DNSKEY'], dnssec: true },
    { name: '8.8.8.8', types: ['PTR'] }
  ];
  const examplesEl = ExampleChips({
    className: 'lkp-examples',
    examples: examples.map((ex) => ({ value: ex.name, label: `${ex.name} ${ex.types.join(',')}`, ex })),
    onPick: (value, { ex }) => {
      nameField.value = ex.name;
      typeGroup.values = ex.types;
      otherField.value = '';
      dnssecField.checked = !!ex.dnssec;
      cdField.checked = false;
      nameField.setError(null);
      syncRunBar();
    },
    focus: () => runBtn
  });

  /** The compact row's summary: the choices that are not the defaults (the common types, automatic, no DO / CD bit). */
  const optionsLine = () => {
    const types = [...typeGroup.values, ...parseTypes(otherField.value).types];
    const common = types.length === TYPE_PRESETS.common.length && TYPE_PRESETS.common.every((x) => types.includes(x));
    return optionsSummary([
      { label: types.join(', '), isDefault: common || !types.length },
      { label: t('lkp.optResolver', { name: resolverName(resolverField.value) }), isDefault: !resolverField.value },
      { label: 'DNSSEC (DO)', isDefault: !dnssecField.checked },
      { label: 'CD', isDefault: !cdField.checked }
    ]);
  };
  const formError = h('div', { class: 'field-error lkp-form-error', hidden: true, attrs: { 'aria-live': 'polite' } });
  const input = ToolInput({
    className: 'lkp-form-card',
    fieldsClass: 'lkp-form',
    label: t('nav.lookup'),
    primary: nameField.el,
    inline: [resolverField.el],
    run: runBar,
    notes: [formError],
    more: [
      h('div', { class: 'lkp-types-wrap' }, typeGroup.el, presetBar),
      h('div', { class: 'lkp-options' }, otherField.el, h('div', { class: 'stack-sm' }, dnssecField.el, cdField.el))
    ],
    extras: [examplesEl],
    privacy: PrivacyNote({ text: t('lkp.privacy') }),
    summary: optionsLine
  });
  // Any change of the form (a type ticked, another resolver, a name typed) makes Look up the primary button again.
  input.el.addEventListener('input', () => syncRunBar());
  input.el.addEventListener('change', () => syncRunBar());

  /* --- results area ------------------------------------------------------------------ */
  /** The result header (region 4): the name, who answered, the counts, the actions and the next steps. */
  const head = ResultHeader({ className: 'lkp-sum' });
  /** The "No records" line lives in the header: its node is kept while its types stay the same. */
  const nodataHost = h('div', { class: 'lkp-nodata-host' });
  const summaryEl = h('div', { class: 'lkp-summary' });
  const noteEl = h('div', { class: 'lkp-note' });
  const cardsEl = h('div', { class: 'lkp-cards' });
  // Explain (ui/explain-panel.js) and the DNSSEC chain (ui/dnssec-panel.js), each loaded on the first click of its next-step button.
  const explainEl = h('div', { class: 'lkp-explain' });
  const dnssecEl = h('div', { class: 'lkp-dnssec' });
  const emptyEl = h('div', { class: 'lkp-empty' }, EmptyState({
    icon: 'search',
    message: t('lkp.emptyLine'),
    checks: ['A · AAAA', 'MX', 'TXT · SPF', 'CAA', 'HTTPS · SVCB', 'DS · DNSKEY']
  }));
  // No part of the form: Ctrl/Cmd+Enter in a field here starts no new lookup.
  const results = h('div', { class: 'stack lkp-results', hidden: true, dataset: { shortcutScope: 'results' } }, summaryEl, noteEl, explainEl, dnssecEl, cardsEl);
  container.append(h('div', { class: 'lkp-view' }, input.el, emptyEl, results, runBar.float));
  ctx.onCleanup(() => runBar.dispose());

  /** The form as a query (no validation, nothing marked): what Run would ask now. */
  function formQuery() {
    const parsed = parseLookupName(nameField.value);
    const other = parseTypes(otherField.value).types;
    return {
      input: parsed ? parsed.ptrFor || parsed.name : null,
      types: [...typeGroup.values, ...other.filter((x) => !typeGroup.values.includes(x))].join(','),
      resolver: resolverField.value || null,
      dnssec: dnssecField.checked,
      cd: cdField.checked
    };
  }

  /** The run bar and the input follow the state: compact once a lookup runs, "Run again" while the form asks for the answers on screen. */
  function syncRunBar() {
    const running = !!(current && current.controller);
    const state = templateState({ running, result: !!current });
    let same = false;
    if (state === 'done') {
      const f = formQuery();
      const q = current.q;
      same = f.input === q.input && (f.types === q.types.join(',') || !!q.ptrFor) && f.resolver === (q.resolver || null) && f.dnssec === !!q.dnssec && f.cd === !!q.cd;
    }
    runBar.setState(state);
    runBar.setRerun(same);
    input.setCompact(inputCompact(state));
    input.refresh();
  }

  /*
   * Balanced CSS columns move cards between columns whenever one grows (a raw answer opened).
   * Once every answer is in, the first card of each further column is pinned there
   * (`break-before: column`): a card that grows then lengthens its own column only. The pins
   * are made again when an answer changes (a Retry) or the width fits another number of columns.
   */
  const raf = globalThis.requestAnimationFrame || ((cb) => setTimeout(cb, 16));
  const cancelRaf = globalThis.cancelAnimationFrame || clearTimeout;
  let pinnedFor = 0; // the column count the pins were made for (0: none made)
  let pinFrame = 0;
  const settled = () => !!current && current.responses.every(Boolean);

  /** How many columns the card area fits (the multi-column rule: column-width, column-gap). */
  function columnCount() {
    const width = cardsEl.clientWidth;
    const cs = globalThis.getComputedStyle ? globalThis.getComputedStyle(cardsEl) : null;
    const col = cs ? parseFloat(cs.columnWidth) : NaN;
    const gap = cs ? parseFloat(cs.columnGap) || 0 : 0;
    if (!width || !(col > 0)) return 1;
    return Math.max(1, Math.floor((width + gap) / (col + gap)));
  }

  function unpinColumns() {
    if (pinFrame) cancelRaf(pinFrame);
    pinFrame = 0;
    pinnedFor = 0;
    for (const el of cardsEl.querySelectorAll('.lkp-col-start')) el.classList.remove('lkp-col-start');
  }

  /** Pin the balanced layout the settled cards have now (next frame: after they are drawn). */
  function pinColumns() {
    unpinColumns();
    pinFrame = raf(() => {
      pinFrame = 0;
      if (!settled() || !cardsEl.isConnected) return;
      const n = columnCount();
      pinnedFor = n;
      if (n < 2) return;
      const cards = [...cardsEl.children];
      const lefts = cards.map((el) => Math.round(el.getBoundingClientRect().left));
      cards.forEach((el, i) => { if (i > 0 && lefts[i] !== lefts[i - 1]) el.classList.add('lkp-col-start'); });
    });
  }

  // A width that fits another number of columns (the pins would break the layout), or settled
  // cards first drawn now (a restored lookup mounted before it was shown): pin them again.
  const columnObserver = typeof globalThis.ResizeObserver === 'function'
    ? new globalThis.ResizeObserver(() => {
      if (settled() && !pinFrame && columnCount() !== pinnedFor) pinColumns();
    })
    : null;
  if (columnObserver) columnObserver.observe(cardsEl);

  /* --- record renderers ---------------------------------------------------------------- */

  function renderAddresses(rrs, cnames = []) {
    const index = ctx.getInventoryIndex();
    return simpleTable([t('lkp.col.address'), t('lkp.col.operator'), t('lkp.col.server'), t('lkp.col.ttl')], rrs.map((rr) => {
      const ip = normalizeIP(rr.data) || String(rr.data);
      const servers = lookupServers([ip], index).map((m) => m.server);
      return [
        ipLink(ip),
        KindBadge(classifyIp(ip, cnames)),
        servers.length ? h('div', { class: 'cluster' }, servers.map((s) => Badge(s.name, { variant: 'direct', icon: 'server' }))) : null,
        { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
      ];
    }));
  }

  function renderMx(rrs) {
    const sorted = [...rrs].sort((a, b) => a.data.preference - b.data.preference || String(a.data.exchange).localeCompare(String(b.data.exchange)));
    const nullMx = sorted.length === 1 && sorted[0].data.exchange === '.';
    return h('div', { class: 'stack-sm' },
      nullMx ? Alert({ variant: 'info', compact: true, icon: 'mail', message: t('lkp.nullMx') }) : null,
      simpleTable([t('lkp.col.preference'), t('lkp.col.mailServer'), t('lkp.col.ttl')], sorted.map((rr) => [
        { cell: h('span', { class: 'num' }, String(rr.data.preference)), className: 'dt-align-end' },
        hostLink(rr.data.exchange),
        { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
      ])));
  }

  function renderNames(rrs, label) {
    const sorted = [...rrs].sort((a, b) => String(a.data).localeCompare(String(b.data)));
    return simpleTable([label, t('lkp.col.ttl')], sorted.map((rr) => [hostLink(rr.data), { cell: ttlCell(rr.ttl), className: 'dt-align-end' }]));
  }

  function renderTxt(rrs, qname) {
    const KIND_ORDER = { spf: 0, dmarc: 1, dkim: 2, 'mta-sts': 3, 'tls-rpt': 4, bimi: 5, verification: 7 };
    const rank = (rr) => {
      const kinds = txtKinds(Array.isArray(rr.data) ? rr.data.join('') : String(rr.data ?? ''));
      return kinds.length ? Math.min(...kinds.map((k) => KIND_ORDER[k.kind] ?? 6)) : 8;
    };
    const sorted = rrs.map((rr, i) => ({ rr, i, r: rank(rr) })).sort((a, b) => a.r - b.r || a.i - b.i).map((x) => x.rr);
    // SPF / DMARC / DKIM … come first; on a phone four records, then "+N more" (each is a tall block there).
    const LIMIT = globalThis.matchMedia && globalThis.matchMedia('(max-width: 600px)').matches ? 4 : 8;
    const list = h('ul', { class: 'lkp-txt-list' }, sorted.slice(0, LIMIT).map((rr) => txtItem(rr, qname)));
    if (sorted.length <= LIMIT) return list;
    const more = Button({
      label: t('common.moreCount', { count: formatNumber(sorted.length - LIMIT) }), size: 'sm', variant: 'secondary', icon: 'chevron-down',
      onClick: () => {
        list.append(...sorted.slice(LIMIT).map((rr) => txtItem(rr, qname)));
        more.remove();
      }
    });
    return h('div', { class: 'stack-sm' }, list, h('div', null, more));
  }

  function txtItem(rr, qname) {
    const strings = Array.isArray(rr.data) ? rr.data : [String(rr.data ?? '')];
    const joined = strings.join('');
    const kinds = txtKinds(joined);
    return h('li', { class: 'lkp-txt' },
      h('div', { class: 'lkp-txt-head cluster' },
        kinds.map((k) => Badge(k.kind === 'verification' ? t('lkp.txt.verification', { service: k.service }) : k.kind.toUpperCase(), {
          variant: k.kind === 'verification' ? 'neutral' : 'accent', icon: k.kind === 'verification' ? 'check' : 'mail'
        })),
        h('span', { class: 'muted text-xs' }, t('lkp.txt.chars', { count: joined.length })),
        strings.length > 1 ? h('span', { class: 'muted text-xs', title: t('lkp.txt.split', { count: strings.length }) }, t('lkp.txt.strings', { count: strings.length })) : null,
        h('span', { class: 'muted text-xs' }, 'TTL ', ttlCell(rr.ttl)),
        kinds.some((k) => k.kind === 'spf' || k.kind === 'dmarc')
          ? h('a', { class: 'text-xs', href: ctx.href('health', { domain: qname.replace(/^_dmarc\./, '') }) }, t('lkp.txt.analyse')) : null,
        CopyButton(joined, { iconOnly: true, size: 'sm' })),
      h('div', { class: 'lkp-txt-value mono' }, joined),
      strings.length > 1 ? Disclosure({
        summary: t('lkp.txt.strings', { count: strings.length }),
        className: 'lkp-txt-split',
        children: h('ol', { class: 'lkp-txt-parts mono' }, strings.map((s) => h('li', null, s)))
      }) : null);
  }

  function renderSoa(rr) {
    const d = rr.data;
    const serialDate = soaSerialDate(d.serial);
    return KeyValueList([
      { key: t('lkp.soa.mname'), value: hostLink(d.mname) },
      { key: t('lkp.soa.rname'), value: d.email || d.rname, mono: true, copy: d.email || d.rname },
      { key: t('lkp.soa.serial'), value: h('span', null, h('span', { class: 'num mono' }, String(d.serial)), serialDate ? h('span', { class: 'muted text-xs' }, ` · ${t('lkp.soa.serialDate', { date: serialDate.date, rev: serialDate.rev })}`) : null) },
      { key: t('lkp.soa.refresh'), hint: t('lkp.soa.refreshHint'), value: `${formatNumber(d.refresh)} s · ${duration(d.refresh)}` },
      { key: t('lkp.soa.retry'), hint: t('lkp.soa.retryHint'), value: `${formatNumber(d.retry)} s · ${duration(d.retry)}` },
      { key: t('lkp.soa.expire'), hint: t('lkp.soa.expireHint'), value: `${formatNumber(d.expire)} s · ${duration(d.expire)}` },
      { key: t('lkp.soa.minimum'), hint: t('lkp.soa.minimumHint'), value: `${formatNumber(d.minimum)} s · ${duration(d.minimum)}` },
      { key: t('lkp.col.ttl'), value: `${formatNumber(rr.ttl)} s · ${duration(rr.ttl)}` }
    ], { className: 'lkp-soa' });
  }

  function caaMeaning(d) {
    const tag = String(d.tag).toLowerCase();
    if (tag === 'issue' || tag === 'issuewild') {
      const issuer = String(d.value).split(';')[0].trim();
      if (!issuer) return h('span', { class: 'lkp-caa-deny' }, t('lkp.caa.deny'));
      return t(tag === 'issue' ? 'lkp.caa.issue' : 'lkp.caa.issuewild', { ca: caName(issuer) });
    }
    if (tag === 'iodef') return t('lkp.caa.iodef');
    return t('lkp.caa.other');
  }

  function renderCaa(rrs) {
    return simpleTable([t('lkp.col.flags'), t('lkp.col.tag'), t('lkp.col.value'), t('lkp.col.meaning'), t('lkp.col.ttl')], rrs.map((rr) => [
      h('span', { class: 'cluster' }, h('span', { class: 'num' }, String(rr.data.flags)), rr.data.critical ? Badge(t('lkp.caa.critical'), { variant: 'warn' }) : null),
      Badge(rr.data.tag, { mono: true, variant: 'accent' }),
      { cell: h('span', { class: 'mono lkp-wrap' }, rr.data.value || '""'), className: 'dt-wrap' },
      { cell: caaMeaning(rr.data), className: 'dt-wrap' },
      { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
    ]));
  }

  function svcParams(params) {
    const items = [];
    for (const [key, value] of Object.entries(params || {})) {
      let shown;
      if (key === 'ipv4hint' || key === 'ipv6hint') shown = h('span', { class: 'cluster' }, (value || []).map((ip) => ipLink(ip)));
      else if (key === 'alpn') shown = h('span', { class: 'cluster' }, (value || []).map((a) => Badge(a, { mono: true })));
      else if (key === 'ech') {
        const bytes = Math.floor((String(value).replace(/=+$/, '').length * 3) / 4);
        shown = Badge(t('lkp.svcb.ech', { bytes: formatNumber(bytes) }), { variant: 'ok', icon: 'lock', title: String(value) });
      } else if (value === true) shown = Badge(key, { mono: true });
      else shown = h('span', { class: 'mono' }, Array.isArray(value) ? value.join(',') : String(value));
      items.push(h('div', { class: 'lkp-svc-param' }, h('span', { class: 'lkp-svc-key mono' }, key), shown));
    }
    return items.length ? h('div', { class: 'lkp-svc-params' }, items) : null;
  }

  function renderSvcb(rrs) {
    const sorted = [...rrs].sort((a, b) => a.data.priority - b.data.priority);
    return simpleTable([t('lkp.col.priority'), t('lkp.col.target'), t('lkp.col.params'), t('lkp.col.ttl')], sorted.map((rr) => [
      rr.data.priority === 0 ? Badge(t('lkp.svcb.alias'), { variant: 'info' }) : h('span', { class: 'num' }, String(rr.data.priority)),
      rr.data.target === '.' ? h('span', { class: 'muted' }, t('lkp.svcb.sameName')) : hostLink(rr.data.target),
      { cell: svcParams(rr.data.params), className: 'dt-wrap' },
      { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
    ]));
  }

  function renderSrv(rrs) {
    const sorted = [...rrs].sort((a, b) => a.data.priority - b.data.priority || b.data.weight - a.data.weight);
    return simpleTable([t('lkp.col.priority'), t('lkp.col.weight'), t('lkp.col.port'), t('lkp.col.target'), t('lkp.col.ttl')], sorted.map((rr) => [
      h('span', { class: 'num' }, String(rr.data.priority)), h('span', { class: 'num' }, String(rr.data.weight)),
      h('span', { class: 'num mono' }, String(rr.data.port)), hostLink(rr.data.target), { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
    ]));
  }

  function renderDs(rrs) {
    return simpleTable([t('lkp.col.keyTag'), t('lkp.col.algorithm'), t('lkp.col.digestType'), t('lkp.col.digest'), t('lkp.col.ttl')], rrs.map((rr) => [
      h('span', { class: 'num mono' }, String(rr.data.keyTag)),
      algName(rr.data.algorithm),
      DS_DIGEST_TYPES[rr.data.digestType] ? `${DS_DIGEST_TYPES[rr.data.digestType]} (${rr.data.digestType})` : String(rr.data.digestType),
      { cell: h('span', { class: 'mono lkp-wrap lkp-hex' }, String(rr.data.digest).toUpperCase()), className: 'dt-wrap' },
      { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
    ]));
  }

  function renderDnskey(rrs) {
    const sorted = [...rrs].sort((a, b) => (b.data.sep ? 1 : 0) - (a.data.sep ? 1 : 0) || a.data.keyTag - b.data.keyTag);
    return simpleTable([t('lkp.col.keyTag'), t('lkp.col.role'), t('lkp.col.algorithm'), t('lkp.col.key'), t('lkp.col.ttl')], sorted.map((rr) => {
      const d = rr.data;
      const role = d.revoked ? Badge(t('lkp.dnskey.revoked'), { variant: 'error' })
        : d.sep ? Badge(t('lkp.dnskey.ksk'), { variant: 'accent', icon: 'key', title: t('lkp.dnskey.kskTitle') })
          : Badge(t('lkp.dnskey.zsk'), { variant: 'neutral', icon: 'key', title: t('lkp.dnskey.zskTitle') });
      const key = String(d.publicKey || '');
      return [
        h('span', { class: 'num mono' }, String(d.keyTag)),
        h('span', { class: 'cluster' }, role, h('span', { class: 'muted text-xs mono' }, String(d.flags))),
        algName(d.algorithm),
        h('span', { class: 'lkp-keycell' }, h('span', { class: 'mono lkp-key', title: key }, key.length > 22 ? `${key.slice(0, 10)}…${key.slice(-8)}` : key), CopyButton(key, { iconOnly: true, size: 'sm' })),
        { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
      ];
    }));
  }

  function renderRrsigs(rrs) {
    return simpleTable([t('lkp.col.covers'), t('lkp.col.algorithm'), t('lkp.col.keyTag'), t('lkp.col.signer'), t('lkp.col.validity')], rrs.map((rr) => {
      const d = rr.data;
      const st = rrsigStatus(d);
      const title = `${formatDateTime(d.inception, { utc: true })} → ${formatDateTime(d.expiration, { utc: true })}`;
      const badge = st === 'valid' ? Badge(t('lkp.rrsig.validShort'), { variant: 'ok', icon: 'check', title: t('lkp.rrsig.valid', { date: formatDateTime(d.expiration, { utc: true }) }) })
        : st === 'expired' ? Badge(t('lkp.rrsig.expiredShort'), { variant: 'error', icon: 'x-circle', title: t('lkp.rrsig.expired', { date: formatDateTime(d.expiration, { utc: true }) }) })
          : st === 'future' ? Badge(t('lkp.rrsig.futureShort'), { variant: 'warn', icon: 'clock', title: t('lkp.rrsig.future', { date: formatDateTime(d.inception, { utc: true }) }) })
            : null;
      return [
        Badge(d.typeCovered, { mono: true }),
        algName(d.algorithm),
        h('span', { class: 'num mono' }, String(d.keyTag)),
        hostLink(d.signerName, 'DNSKEY'),
        h('div', { class: 'lkp-rrsig-validity', title }, badge,
          h('span', { class: 'muted text-xs' }, `${formatDate(d.inception, { utc: true })} → ${formatDate(d.expiration, { utc: true })}`))
      ];
    }), 'lkp-rrsigs');
  }

  function renderNsec(rrs) {
    return simpleTable([t('lkp.col.name'), t('lkp.col.next'), t('lkp.col.types')], rrs.map((rr) => [
      h('span', { class: 'mono' }, rr.name),
      h('span', { class: 'mono' }, rr.type === 'NSEC3' ? String(rr.data.nextHashedOwner || '').toUpperCase() : rr.data.nextDomain),
      { cell: h('span', { class: 'cluster lkp-nsec-types' }, (rr.data.types || []).map((x) => Badge(x, { mono: true }))), className: 'dt-wrap' }
    ]));
  }

  function renderTlsa(rrs) {
    return simpleTable([t('lkp.col.usage'), t('lkp.col.selector'), t('lkp.col.matching'), t('lkp.col.data'), t('lkp.col.ttl')], rrs.map((rr) => [
      `${TLSA_USAGE[rr.data.usage] || '?'} (${rr.data.usage})`,
      `${TLSA_SELECTOR[rr.data.selector] || '?'} (${rr.data.selector})`,
      `${TLSA_MATCHING[rr.data.matchingType] || '?'} (${rr.data.matchingType})`,
      { cell: h('span', { class: 'mono lkp-wrap lkp-hex' }, String(rr.data.data).toUpperCase()), className: 'dt-wrap' },
      { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
    ]));
  }

  function renderSshfp(rrs) {
    return simpleTable([t('lkp.col.algorithm'), t('lkp.col.type'), t('lkp.col.fingerprint'), t('lkp.col.ttl')], rrs.map((rr) => [
      `${SSHFP_ALG[rr.data.algorithm] || '?'} (${rr.data.algorithm})`,
      `${SSHFP_TYPE[rr.data.fpType] || '?'} (${rr.data.fpType})`,
      { cell: h('span', { class: 'mono lkp-wrap lkp-hex' }, String(rr.data.fingerprint).toUpperCase()), className: 'dt-wrap' },
      { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
    ]));
  }

  function renderNaptr(rrs) {
    const sorted = [...rrs].sort((a, b) => a.data.order - b.data.order || a.data.preference - b.data.preference);
    return simpleTable([t('lkp.col.order'), t('lkp.col.preference'), t('lkp.col.flags'), t('lkp.col.services'), t('lkp.col.regexp'), t('lkp.col.replacement')], sorted.map((rr) => [
      h('span', { class: 'num' }, String(rr.data.order)), h('span', { class: 'num' }, String(rr.data.preference)),
      h('span', { class: 'mono' }, rr.data.flags || '""'), h('span', { class: 'mono' }, rr.data.services || '""'),
      { cell: h('span', { class: 'mono lkp-wrap' }, rr.data.regexp || '""'), className: 'dt-wrap' },
      rr.data.replacement && rr.data.replacement !== '.' ? hostLink(rr.data.replacement) : h('span', { class: 'mono muted' }, '.')
    ]));
  }

  function renderGeneric(rrs) {
    return simpleTable([t('lkp.col.name'), t('lkp.col.type'), t('lkp.col.data'), t('lkp.col.ttl')], rrs.map((rr) => [
      h('span', { class: 'mono' }, rr.name), Badge(rr.type, { mono: true }),
      { cell: h('span', { class: 'mono lkp-wrap' }, rr.text), className: 'dt-wrap' },
      { cell: ttlCell(rr.ttl), className: 'dt-align-end' }
    ]));
  }

  /**
   * Parsed view of the records of one type. RDATA the parser could not read (lib/dnswire's
   * RFC 3597 form, `rr.error`) has no fields, so it goes to the generic table as text.
   */
  function renderRecords(type, rrs, qname, cnames = []) {
    const unread = rrs.filter((rr) => rr.error);
    if (!unread.length) return renderParsed(type, rrs, qname, cnames);
    const read = rrs.filter((rr) => !rr.error);
    if (!read.length) return renderGeneric(unread);
    return h('div', { class: 'stack-sm' }, renderParsed(type, read, qname, cnames), renderGeneric(unread));
  }

  function renderParsed(type, rrs, qname, cnames) {
    switch (type) {
      case 'A':
      case 'AAAA':
        return renderAddresses(rrs, cnames);
      case 'MX':
        return renderMx(rrs);
      case 'NS':
        return renderNames(rrs, t('lkp.col.nameServer'));
      case 'CNAME':
      case 'PTR':
      case 'DNAME':
        return renderNames(rrs, t('lkp.col.target'));
      case 'TXT':
      case 'SPF':
        return renderTxt(rrs, qname);
      case 'SOA':
        return h('div', { class: 'stack-sm' }, rrs.map(renderSoa));
      case 'CAA':
        return renderCaa(rrs);
      case 'HTTPS':
      case 'SVCB':
        return renderSvcb(rrs);
      case 'SRV':
        return renderSrv(rrs);
      case 'DS':
      case 'CDS':
        return renderDs(rrs);
      case 'DNSKEY':
      case 'CDNSKEY':
        return renderDnskey(rrs);
      case 'RRSIG':
        return renderRrsigs(rrs);
      case 'NSEC':
      case 'NSEC3':
        return renderNsec(rrs);
      case 'TLSA':
      case 'SMIMEA':
        return renderTlsa(rrs);
      case 'SSHFP':
        return renderSshfp(rrs);
      case 'NAPTR':
        return renderNaptr(rrs);
      default:
        return renderGeneric(rrs);
    }
  }

  /* --- per-type cards ---------------------------------------------------------------- */

  /** The header flags (AA TC RD RA AD CD), set ones highlighted. */
  function flagsRow(flags) {
    const f = flags || {};
    return h('div', { class: 'lkp-flags', attrs: { role: 'list', 'aria-label': t('lkp.flags') } },
      LOOKUP_FLAGS.map((k) => h('span', {
        class: ['lkp-flag', `lkp-flag-${k}`, { 'is-set': !!f[k] }],
        title: `${t(`lkp.flag.${k}`)}: ${f[k] ? t('common.yes') : t('common.no')}`,
        attrs: { role: 'listitem' },
        dataset: { flag: k, set: f[k] ? '1' : '0' }
      }, f[k] ? Icon('check', { size: 11, strokeWidth: 2.6 }) : null, k.toUpperCase(),
      h('span', { class: 'sr-only' }, `: ${f[k] ? t('common.yes') : t('common.no')}`))));
  }

  function rcodeBadge(response) {
    if (!response.ok) return Badge(t('lkp.card.failed'), { variant: 'error', icon: 'x-circle' });
    const rc = response.rcode;
    return Badge(rc, { variant: rc === 'NOERROR' ? 'ok' : rc === 'NXDOMAIN' ? 'nxdomain' : 'error', mono: true });
  }

  function statusMessage(response, type, hasChain) {
    const rc = response.rcode;
    if (rc === 'NXDOMAIN') return { variant: 'warn', text: t('lkp.status.nxdomain') };
    if (rc === 'SERVFAIL') return { variant: 'error', text: t('lkp.status.servfail') };
    if (rc === 'REFUSED') return { variant: 'error', text: t('lkp.status.refused') };
    if (rc !== 'NOERROR') return { variant: 'error', text: t('lkp.status.other', { rcode: rc }) };
    return { variant: 'info', text: hasChain ? t('lkp.status.aliasOnly', { type }) : t('lkp.status.nodata', { type }) };
  }

  function negativeTtl(response) {
    const soa = (response.authorities || []).find((rr) => rr.type === 'SOA');
    if (!soa || !soa.data) return null;
    const ttl = Math.min(soa.ttl, Number(soa.data.minimum) || soa.ttl);
    return t('lkp.negTtl', { time: duration(ttl), zone: soa.name === '.' ? '.' : soa.name });
  }

  /**
   * What a card says about its own answer: the resolver, PoP and flags only where they differ
   * from what the summary says for every answer (`own`), plus a failover and a cache hit.
   * Null when there is nothing of its own to say.
   */
  function cardStatus(response, own) {
    const o = own || { resolver: true, nsid: true, flags: true };
    const bits = [];
    if (o.resolver && response.resolver) {
      bits.push(h('span', null, t('lkp.sum.via', { resolver: resolverName(response.resolver) })));
    }
    if (o.nsid && response.nsid) bits.push(h('span', { class: 'mono lkp-pop', title: response.nsid }, t('lkp.card.pop', { id: response.nsid })));
    if (response.cached) bits.push(h('span', { class: 'muted' }, t('lkp.card.cached')));
    const failed = (response.attempts || []).filter((a) => !a.ok || (a.rcode && a.rcode !== response.rcode));
    if (failed.length) {
      bits.push(h('span', { class: 'lkp-failover', title: failed.map((a) => `${resolverName(a.resolver)}: ${a.error || a.rcode}`).join('\n') },
        Icon('refresh', { size: 12 }), ' ', t('lkp.card.failover', { tried: failed.map((a) => resolverName(a.resolver)).join(', ') })));
    }
    if (!o.flags && !bits.length) return null;
    return h('div', { class: 'lkp-card-status' }, o.flags ? flagsRow(response.flags) : null, bits.length ? h('div', { class: 'lkp-meta' }, bits) : null);
  }

  /**
   * Card content for one finished query. A query that got no DNS answer says which resolver
   * failed and why, with a Retry of this type (`onRetry`).
   */
  function renderResult(type, response, { own = null, onRetry = null } = {}) {
    const body = [];
    if (!response.ok) {
      const st = dohStatus(response);
      // Which resolver failed: the one asked, or every one of the failover chain.
      // The same answer from the same resolver (a retry) is listed once, with how often.
      const attempts = [];
      for (const a of response.attempts || []) {
        const text = a.error || a.rcode || '';
        const same = attempts.find((x) => x.resolver === a.resolver && x.text === text);
        if (same) same.times += 1;
        else attempts.push({ resolver: a.resolver, text, times: 1 });
      }
      const who = new Set(attempts.map((a) => a.resolver)).size > 1 ? t('lkp.card.allResolvers') : response.resolver ? resolverName(response.resolver) : null;
      body.push(Alert({
        variant: 'error',
        title: t('lkp.card.failed'),
        message: st ? statusText(st, { name: who })
          : response.errorKind && response.errorKind !== 'unknown' && hasString(`error.kind.${response.errorKind}`, 'en') ? t(`error.kind.${response.errorKind}`) : response.error,
        children: attempts.length ? h('div', { class: 'stack-sm lkp-attempts' },
          h('div', { class: 'text-sm' }, t('lkp.card.attempts')),
          h('ul', { class: 'lkp-attempt-list text-sm' }, attempts.map((a) => h('li', null,
            h('strong', null, resolverName(a.resolver)), ': ', h('span', { class: 'mono' }, a.text), a.times > 1 ? ` (×${a.times})` : null)))) : null,
        actions: onRetry ? [RetryButton({ sources: ['doh'], target: type, onClick: onRetry, variant: 'secondary', dataset: { type } })] : null
      }));
      return body;
    }
    body.push(cardStatus(response, own));
    for (const e of response.ede || []) {
      body.push(Alert({ variant: 'warn', compact: true, title: t('lkp.ede', { code: e.code, name: e.name }), message: e.text || null }));
    }
    const answers = response.answers || [];
    const { records: chainRecords, cnames } = followCnames(answers, response.name);
    const main = answers.filter((rr) => rr.type === type);
    const sigs = answers.filter((rr) => rr.type === 'RRSIG');
    const used = new Set([...main, ...sigs, ...(type === 'CNAME' ? [] : chainRecords)]);
    const others = answers.filter((rr) => !used.has(rr));

    if (type !== 'CNAME' && cnames.length) {
      body.push(h('div', { class: 'lkp-chain' },
        h('span', { class: 'lkp-chain-label' }, Icon('link', { size: 13 }), ' ', t('lkp.chain')),
        h('span', { class: 'lkp-chain-hops' }, hostLink(response.name === '.' ? '.' : response.name),
          chainRecords.map((rr) => [h('span', { class: 'lkp-chain-arrow', title: `TTL ${rr.ttl}` }, '→'), hostLink(rr.data)]))));
    }
    if (main.length) {
      body.push(renderRecords(type, main, response.name, cnames));
    } else {
      const msg = statusMessage(response, type, cnames.length > 0);
      const neg = negativeTtl(response);
      body.push(Alert({ variant: msg.variant, compact: true, message: [msg.text, neg].filter(Boolean).join(' ') }));
    }
    if (others.length) {
      body.push(h('div', { class: 'stack-sm' }, h('div', { class: 'lkp-subtitle' }, t('lkp.otherRecords')), renderGeneric(others)));
    }
    if (sigs.length) {
      const states = sigs.map((rr) => rrsigStatus(rr.data));
      const bad = states.filter((x) => x === 'expired' || x === 'future').length;
      body.push(Disclosure({
        summary: h('span', { class: 'lkp-sig-summary' }, Icon('shield', { size: 13 }), ` ${t('lkp.rrsig.title')} · ${formatNumber(sigs.length)} `,
          bad ? Badge(t('lkp.rrsig.problems', { count: bad }), { variant: 'error', icon: 'alert' }) : Badge(t('lkp.rrsig.allValid'), { variant: 'ok', icon: 'check' })),
        className: 'lkp-sigs',
        open: bad > 0,
        children: renderRrsigs(sigs)
      }));
    }
    const nsecAuth = (response.authorities || []).filter((rr) => rr.type === 'NSEC' || rr.type === 'NSEC3');
    if (!main.length && nsecAuth.length) {
      body.push(h('div', { class: 'stack-sm' }, h('div', { class: 'lkp-subtitle' }, t('lkp.authority')), renderNsec(nsecAuth)));
    }
    body.push(Disclosure({ summary: t('lkp.card.raw'), className: 'lkp-raw', children: CodeBlock(responseText(response), { wrap: true }) }));
    return body;
  }

  function makeCard(type, { onRetry = null } = {}) {
    const countEl = h('span', { class: 'lkp-count' });
    const statusEl = h('span', { class: 'lkp-rcode' });
    const copyWrap = h('span', { class: 'lkp-card-copy' });
    const querying = () => h('div', { class: 'lkp-querying' }, Spinner({ size: 'sm' }), h('span', { class: 'muted text-sm' }, t('lkp.card.querying')));
    const body = h('div', { class: 'stack lkp-card-body' }, querying());
    const card = Card({
      title: h('span', { class: 'lkp-card-title' }, Badge(type, { variant: 'accent', mono: true, className: 'lkp-type-badge' }), countEl),
      actions: [statusEl, copyWrap],
      className: 'lkp-card',
      children: body
    });
    card.dataset.type = type;
    card.dataset.state = 'pending';
    let shown = null;
    let shownOwn = null;
    return {
      el: card,
      /** Show an answer; `own` says which of its resolver / PoP / flags differ from the summary's. */
      set(response, own = null) {
        shown = response;
        shownOwn = own ? { ...own } : null;
        const main = (response.answers || []).filter((rr) => rr.type === type);
        card.dataset.state = response.ok ? response.rcode.toLowerCase() : 'error';
        card.dataset.count = String(main.length);
        countEl.textContent = response.ok ? t('lkp.card.records', { count: main.length }) : '';
        clear(statusEl);
        statusEl.append(rcodeBadge(response));
        clear(copyWrap);
        copyWrap.append(CopyButton(() => responseText(response), { iconOnly: true, title: t('lkp.card.raw') }));
        clear(body);
        body.append(...renderResult(type, response, { own, onRetry }).filter(Boolean));
      },
      /** A later answer changed what every answer shares: redraw only this card's own status line. */
      setOwn(own) {
        if (!shown || !shown.ok || JSON.stringify(own || null) === JSON.stringify(shownOwn)) return;
        shownOwn = own ? { ...own } : null;
        const next = cardStatus(shown, own);
        const cur = body.querySelector(':scope > .lkp-card-status');
        if (cur && next) cur.replaceWith(next);
        else if (cur) cur.remove();
        else if (next) body.prepend(next);
      },
      /** A Retry is on its way. */
      setQuerying() {
        card.dataset.state = 'pending';
        clear(body);
        body.append(querying());
      },
      /** Stopped before it answered: its Retry asks this type alone. */
      setStopped() {
        card.dataset.state = 'stopped';
        clear(body);
        body.append(Alert({
          variant: 'info', compact: true, icon: 'stop', message: t('lkp.card.stopped'),
          actions: onRetry ? [RetryButton({ sources: ['doh'], target: type, onClick: onRetry, variant: 'secondary', dataset: { type } })] : null
        }));
      }
    };
  }

  /**
   * The "No records: AAAA, CAA, …" line of the summary: the NODATA types in one place (their
   * negative-caching time and raw answers one click away), instead of a card each.
   */
  function noRecordsLine(q, responses, types, { open = false, rawOpen = false } = {}) {
    const list = types.map((type) => responses[q.types.indexOf(type)]).filter(Boolean);
    const neg = list.length ? negativeTtl(list[0]) : null;
    return h('div', { class: 'lkp-nodata', dataset: { types: types.join(' ') } },
      Disclosure({
        // The label in the text font, the type mnemonics in mono (spaced by the summary's gap).
        summary: h('span', { class: 'lkp-nodata-summary' }, Icon('minus-circle', { size: 14 }), h('span', null, t('lkp.noRecords')), ' ',
          h('span', { class: 'mono lkp-nodata-types' }, types.join(', '))),
        className: 'lkp-nodata-box',
        open,
        children: h('div', { class: 'stack-sm' },
          h('p', { class: 'text-sm lkp-nodata-body' }, [t('lkp.noRecordsBody'), neg].filter(Boolean).join(' ')),
          Disclosure({ summary: t('lkp.card.raw'), className: 'lkp-raw', open: rawOpen, children: CodeBlock(list.map(responseText).join('\n\n'), { wrap: true }) }))
      }));
  }

  /** The keyboard-reachable elements of `root`, in document order. */
  const focusablesOf = (root) => [...root.querySelectorAll('summary, button, a[href], [tabindex]')];

  /* --- run --------------------------------------------------------------------------- */
  let current = null;

  function readForm() {
    formError.hidden = true;
    nameField.setError(null);
    otherField.setError(null);
    const parsed = parseLookupName(nameField.value);
    if (!parsed) {
      nameField.setError(t('lkp.invalidName'));
      nameField.focus();
      return null;
    }
    const other = parseTypes(otherField.value);
    if (other.invalid.length) {
      otherField.setError(t('lkp.badTypes', { types: other.invalid.join(', ') }));
      return null;
    }
    let types = [...typeGroup.values, ...other.types.filter((x) => !typeGroup.values.includes(x))];
    if (parsed.ptrFor && !types.includes('PTR')) types = ['PTR'];
    if (!types.length) {
      formError.textContent = t('lkp.noTypes');
      formError.hidden = false;
      return null;
    }
    if (types.length > MAX_TYPES) {
      formError.textContent = t('lkp.tooManyTypes', { max: MAX_TYPES });
      formError.hidden = false;
      return null;
    }
    return {
      name: parsed.name,
      ptrFor: parsed.ptrFor,
      input: parsed.ptrFor || parsed.name,
      types,
      resolver: resolverField.value || null,
      dnssec: dnssecField.checked,
      cd: cdField.checked
    };
  }

  /**
   * Run the form's query. `auto`: a shared link's run on arrival — offline it only fills the form
   * (the page's offline note says why), with no "needs the network" toast for a click nobody made.
   */
  function start({ auto = false } = {}) {
    const q = readForm();
    if (!q) return;
    carried = null;
    if (!q.ptrFor) nameField.value = q.name;
    else if (q.types.length === 1 && q.types[0] === 'PTR') {
      // Keep the form honest: an IP address is looked up as PTR only.
      typeGroup.values = ['PTR'];
      otherField.value = '';
    }
    if (!ctx.requireOnline({ quiet: auto })) return;
    ctx.setParams(queryParams(q));
    ctx.runStarted(q.input);
    run(q);
  }

  /** The route params of a query (what a shared link runs). */
  function queryParams(q) {
    return { name: q.input, type: q.types.join(','), resolver: q.resolver, dnssec: q.dnssec ? '1' : null, cd: q.cd ? '1' : null };
  }

  /** The names the box holds, as a query reads them (what a carried name may replace). */
  const boxNames = (text) => {
    const parsed = parseLookupName(text);
    return [parsed ? parsed.ptrFor || parsed.name : String(text).trim()];
  };

  /**
   * The name the box last took from a carried target: a newer one replaces it while the box still
   * holds it (lib/session.js fillReplaces). A re-mount keeps it (snapshot); a query forgets it.
   */
  let carried = restored ? (typeof restored.carried === 'string' ? restored.carried : null)
    : (isFillOnly(ctx.params) && ctx.params.name) || null;

  /**
   * A name carried over from another tool (`run=0`) goes into the box while it is empty or still
   * holds the finished query's name or the name carried before — never over a draft — and nothing
   * is queried; the answers stay.
   */
  function takeCarried(name) {
    const last = current && !current.controller ? [current.q.input] : null;
    if (fillReplaces(nameField.value, last, boxNames, carried)) {
      nameField.value = name;
      nameField.setError(null);
      carried = name;
    }
    syncRunBar();
  }

  /** The result header's parts of the current lookup, updated in place by {@link renderSummary}. */
  let summaryParts = null;
  // The actions' phone-layout listener would keep this page alive once it is left.
  ctx.onCleanup(() => {
    if (summaryParts && summaryParts.actions) summaryParts.actions.dispose();
  });

  /**
   * Draw the result header (region 4), again on every answer and Retry. In place: the title, the
   * meta line (who answered, its PoP, the time, a Stop) and the status summary are redrawn, while
   * the actions, the next steps and the related links — the same for the whole lookup; Copy summary
   * and Export are enabled once every type has answered — and a "No records" line whose types did
   * not change are kept as they are, so what the user opened there (the raw answer inside it too)
   * and the keyboard focus stay. A line whose types changed is drawn anew with the same open state
   * and focus.
   * @param {object} q the query ({@link readForm})
   * @param {Array<object|null>} responses
   * @param {number|null} elapsed
   * @param {Date|null} at when the last answer arrived (the summary's time)
   * @param {object} [layout] lib/density.js lookupLayout of the answers
   */
  function renderSummary(q, responses, elapsed, at, layout = lookupLayout(q.types, responses)) {
    clear(noteEl);
    if (q.ptrFor) noteEl.append(Alert({ variant: 'info', compact: true, icon: 'info', message: t('lkp.ptrNote', { name: q.name }) }));
    const total = responses.reduce((n, r) => n + (r && r.ok ? r.answers.filter((rr) => rr.type === r.type).length : 0), 0);
    const failed = responses.filter((r) => r && !r.ok).length;
    const done = responses.filter(Boolean).length;
    const running = !!(current && current.q === q && current.controller);
    const resolverLabel = q.resolver ? resolverName(q.resolver) : t('lkp.resolverAuto', { chain: chainNames });
    // A stopped lookup with types still unanswered: said here, and its Copy summary says which.
    const stopped = !!(current && current.q === q && current.stopped) && done < q.types.length;
    // Said once for every answer (lib/density.js): who answered, its PoP and the header flags.
    const shared = layout.shared;
    head.setState(running ? 'running' : 'done');
    head.set('title', ResultTitle({ running, text: h('span', { class: 'lkp-sum-name mono' }, q.input) }));
    head.set('meta', [
      h('div', { class: 'lkp-sum-meta' },
        shared.resolver
          ? h('span', { class: 'lkp-sum-resolver', dataset: { resolver: shared.resolver } }, t('lkp.sum.answeredBy', { resolver: resolverName(shared.resolver) }))
          : h('span', null, t('lkp.sum.via', { resolver: resolverLabel })),
        shared.nsid ? h('span', { class: 'mono lkp-pop', title: shared.nsid }, t('lkp.card.pop', { id: shared.nsid })) : null,
        Number.isFinite(elapsed) && done === q.types.length ? h('span', null, t('lkp.sum.time', { time: formatDuration(elapsed) })) : null,
        stopped
          ? h('span', { class: 'lkp-sum-stopped', dataset: { role: 'lkp-stopped' } }, Icon('stop', { size: 13 }), ' ', t('lkp.sum.stopped', { count: q.types.length - done })) : null,
        q.dnssec ? Badge('DO', { variant: 'accent', title: t('lkp.dnssec') }) : null,
        q.cd ? Badge('CD', { variant: 'warn', title: t('lkp.cd') }) : null),
      shared.flags ? h('div', { class: 'lkp-sum-flags' }, flagsRow(shared.flags)) : null
    ]);
    // The counts: a failed query opens its card, the types with no records their line.
    head.set('status', StatusSummary({
      items: lookupStatus({ types: q.types.length, records: total, noRecords: layout.noRecords, failed }).map((item) => ({
        ...item,
        text: item.key === 'failed' ? t('lkp.count.failed', { count: item.count })
          : item.key === 'nodata' ? t('lkp.count.nodata', { count: item.count })
            : t(`lkp.sum.${item.key}`, { count: item.count }),
        title: item.key === 'nodata' ? `${t('lkp.noRecords')} ${item.types.join(', ')}` : null,
        onPress: item.key === 'failed' ? () => focusFailedCard()
          : item.key === 'nodata' ? () => openNoRecords() : null
      }))
    }).el);
    const types = layout.noRecords.join(' ');

    const prev = summaryParts && summaryParts.q === q && head.el.isConnected ? summaryParts : null;
    if (!prev) {
      // A new lookup: its actions, next steps and links drawn anew, its "No records" line closed.
      const allText = () => responses.filter(Boolean).map(responseText).join('\n\n');
      if (summaryParts && summaryParts.actions) summaryParts.actions.dispose();
      // Reads the facts at click time: the answers, and the time the last one arrived (or the Stop).
      const actions = ResultActions({
        summary: SummaryButton({
          kind: 'lookup',
          plainLabel: t('result.plainTitle'),
          facts: () => ({
            name: q.name, ptrFor: q.ptrFor, types: q.types, responses, dnssec: q.dnssec, at: summaryParts ? summaryParts.at : at,
            stopped: !!(current && current.q === q && current.stopped)
          }),
          url: () => ctx.shareUrl(permalinkParams('lookup', { name: q.input, type: q.types.join(','), resolver: q.resolver, dnssec: q.dnssec ? '1' : null, cd: q.cd ? '1' : null }))
        }),
        // The one file of a lookup: every answer as dig-style text (a plain button, not a one-item menu).
        exports: [{
          label: t('result.export'), title: t('lkp.exportDigTitle'), icon: 'download', dataset: { export: 'dig' },
          onSelect: () => downloadText(timestampedName('dns-lookup', 'txt', q.input), `${allText()}\n`, 'text/plain;charset=utf-8')
        }],
        // Copy link: the query on screen, not the box, which may hold a carried name.
        link: () => ctx.shareUrl(queryParams(q))
      });
      actions.setDisabled(done !== q.types.length && !stopped);
      head.set('actions', actions.el);
      const named = !q.ptrFor && q.name !== '.';
      head.set('next', NextSteps({
        steps: [
          named ? { label: t('lkp.explain'), icon: 'book', title: t('lkp.explainTitle'), dataset: { action: 'explain' }, onClick: () => openExplain(q) } : null,
          { label: t('lkp.dnssecChain'), icon: 'shield', title: t('lkp.dnssecChainTitle'), dataset: { action: 'dnssec-chain' }, onClick: () => openDnssec(q) }
        ]
      }));
      head.set('related', RelatedLinks({
        self: 'lookup',
        links: [
          q.ptrFor ? { view: 'ip', icon: 'network', label: t('nav.ip'), href: ctx.href('ip', { ips: q.ptrFor }) } : null,
          named ? {
            view: 'global', icon: 'globe', label: t('nav.global'),
            href: ctx.href('global', { name: q.name, type: ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'HTTPS', 'SOA'].includes(q.types[0]) ? q.types[0] : 'A' })
          } : null,
          named && q.name.includes('.') ? { view: 'health', icon: 'activity', label: t('nav.health'), href: ctx.href('health', { domain: q.name.replace(/^_dmarc\./, '') }) } : null
        ].filter(Boolean)
      }));
      const line = layout.noRecords.length ? noRecordsLine(q, responses, layout.noRecords) : null;
      clear(nodataHost);
      if (line) nodataHost.append(line);
      head.set('notes', nodataHost.firstChild ? nodataHost : null);
      if (!head.el.isConnected) summaryEl.append(head.el);
      summaryParts = { q, line, types, actions, at };
      return;
    }
    prev.at = at;
    prev.actions.setDisabled(done !== q.types.length && !stopped);
    if (prev.types === types) return;
    const old = prev.line;
    const doc = globalThis.document;
    const focusAt = old && doc && old.contains(doc.activeElement) ? focusablesOf(old).indexOf(doc.activeElement) : -1;
    const line = layout.noRecords.length ? noRecordsLine(q, responses, layout.noRecords, {
      open: !!old?.querySelector('.lkp-nodata-box[open]'),
      rawOpen: !!old?.querySelector('.lkp-raw[open]')
    }) : null;
    if (old && line) old.replaceWith(line);
    else if (old) old.remove();
    else if (line) nodataHost.append(line);
    // The host stays the same node: the notes part is set again only when it appears or goes.
    if (!old !== !line) head.set('notes', line ? nodataHost : null);
    if (line && focusAt >= 0) (focusablesOf(line)[focusAt] || focusablesOf(line)[0])?.focus({ preventScroll: true });
    prev.line = line;
    prev.types = types;
  }

  /** The status summary's "n queries failed": the first card that got no answer, in view with the focus on its Retry. */
  function focusFailedCard() {
    const card = cardsEl.querySelector('.lkp-card[data-state="error"]');
    if (!card) return;
    card.scrollIntoView({ block: 'start', behavior: scrollBehavior() });
    const retry = card.querySelector('[data-action="retry-source"]');
    if (retry) retry.focus({ preventScroll: true });
    else {
      card.setAttribute('tabindex', '-1');
      card.focus({ preventScroll: true });
    }
  }

  /** The status summary's "n types have no records": the line opened, the focus on it. */
  function openNoRecords() {
    const box = nodataHost.querySelector('.lkp-nodata-box');
    if (!box) return;
    box.open = true;
    box.querySelector('summary')?.focus({ preventScroll: true });
  }

  /** The DNSSEC chain of the lookup on screen: { q, panel } (ui/dnssec-panel.js). */
  let dnssec = null;
  const loadDnssec = onceAsync(() => import('../ui/dnssec-panel.js'));

  async function openDnssec(q) {
    if (dnssec && dnssec.q === q) {
      dnssec.panel.el.scrollIntoView({ block: 'nearest' });
      return;
    }
    let mod;
    try {
      mod = await loadDnssec();
    } catch (err) {
      ctx.checkOutdated();
      ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      return;
    }
    if (!current || current.q !== q || ctx.signal.aborted) return;
    closeDnssec();
    dnssec = { q, panel: mod.DnssecPanel({ ctx, name: q.name, types: q.types, resolver: q.resolver }) };
    dnssecEl.append(dnssec.panel.el);
    dnssec.panel.run();
  }

  function closeDnssec() {
    if (dnssec) dnssec.panel.destroy();
    dnssec = null;
  }

  /** The Explain panel of the lookup on screen: { q, panel } (ui/explain-panel.js). */
  let explain = null;
  const loadExplain = onceAsync(() => import('../ui/explain-panel.js'));

  /**
   * Explain the records of the lookup on screen. The lookup's answers in so far are handed over
   * (the panel asks only what they lack); a second click brings the open panel into view.
   */
  async function openExplain(q) {
    if (explain && explain.q === q) {
      explain.panel.el.scrollIntoView({ block: 'nearest' });
      return;
    }
    let mod;
    try {
      mod = await loadExplain();
    } catch (err) {
      ctx.checkOutdated();
      ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      return;
    }
    if (!current || current.q !== q || ctx.signal.aborted) return;
    closeExplain();
    explain = { q, panel: mod.ExplainPanel({ ctx, name: q.name, types: q.types, responses: current.responses.slice(), resolver: q.resolver }) };
    explainEl.append(explain.panel.el);
    explain.panel.run();
  }

  function closeExplain() {
    if (explain) explain.panel.destroy();
    explain = null;
  }

  /** Ask one type of the current lookup (a run, or the Retry of a query that got no answer). */
  async function queryType(state, type, signal) {
    const dns = await ctx.getDns();
    const q = state.q;
    return dns.query(q.name, type, { resolver: q.resolver || undefined, dnssec: q.dnssec, cd: q.cd, signal, noCache: true });
  }

  /**
   * Query every type of `q`, or show `preset` answers (a kept or re-mounted run: no network) with
   * the time the run finished and took.
   */
  async function run(q, preset = null, { at = null, elapsed = null } = {}) {
    if (current && current.controller) current.controller.abort();
    if (current) current.life.abort();
    closeDnssec();
    closeExplain();
    const controller = new AbortController();
    // `life` ends with this lookup (a new one, or the view going away): it cancels Retries too.
    const life = new AbortController();
    const state = { q, controller, life, responses: new Array(q.types.length).fill(null), startedAt: performance.now(), elapsed: null, finishedAt: null };
    current = state;
    emptyEl.hidden = true;
    results.hidden = false;
    unpinColumns();
    clear(cardsEl);
    summaryParts = null; // a new lookup starts with its "No records" line closed
    const cards = q.types.map((type, i) => makeCard(type, { onRetry: () => retry(i) }));
    cardsEl.append(...cards.map((c) => c.el));
    renderSummary(q, state.responses, null, null);
    // True while `preset` fills the cards in (its kept times apply), never for a later Retry.
    let filling = !!preset;

    const finish = (i, response) => {
      if (current !== state) return;
      state.responses[i] = response;
      const layout = lookupLayout(q.types, state.responses);
      cards[i].set(response, layout.own[q.types[i]] || null);
      // Plain NODATA folds into the summary's "No records" line; the other cards follow what is shared.
      q.types.forEach((type, j) => {
        if (layout.noRecords.includes(type)) cards[j].el.remove();
        else if (j !== i) cards[j].setOwn(layout.own[type] || null);
      });
      if (state.responses.every(Boolean) && state.elapsed === null) {
        // The kept times while the preset fills in; a stopped lookup its Retries complete: now, and no duration.
        state.elapsed = filling ? elapsed : preset || state.stopped ? null : performance.now() - state.startedAt;
        state.finishedAt = filling && at ? new Date(at) : new Date();
      }
      renderSummary(q, state.responses, state.elapsed, state.finishedAt || state.stoppedAt, layout);
      if (state.responses.every(Boolean)) pinColumns();
      else unpinColumns();
    };

    /**
     * Retry of a query that got no answer: that type alone, the old answer kept until the new one.
     * Offered as soon as the query fails, also while other types of the lookup still run (`life`
     * cancels it with the lookup).
     */
    async function retry(i) {
      if (current !== state || life.signal.aborted) return;
      cards[i].setQuerying();
      let response;
      try {
        response = await queryType(state, q.types[i], mergeSignals(ctx.signal, life.signal));
      } catch (err) {
        if (err && err.name === 'AbortError') return;
        response = state.responses[i];
      }
      finish(i, response);
      const btn = cards[i].el.querySelector('[data-action="retry-source"]');
      if (btn) btn.focus();
      else if (cards[i].el.isConnected) {
        cards[i].el.setAttribute('tabindex', '-1');
        cards[i].el.focus({ preventScroll: true });
      } else nodataHost.querySelector('.lkp-nodata summary')?.focus();
    }

    if (preset) {
      state.stopped = preset.some((resp) => !resp);
      // A stopped lookup kept the time of its Stop (snapshot `at`).
      if (state.stopped && at) state.stoppedAt = new Date(at);
      preset.forEach((resp, i) => { if (resp) finish(i, resp); });
      filling = false;
      state.controller = null;
      // Drawn once more as a finished lookup (the answers above were drawn while it filled in).
      renderSummary(q, state.responses, state.elapsed, state.finishedAt || state.stoppedAt);
      markStopped();
      syncRunBar();
      return;
    }

    setButtonState(true);
    try {
      const signal = mergeSignals(ctx.signal, controller.signal, life.signal);
      await Promise.all(q.types.map(async (type, i) => {
        finish(i, await queryType(state, type, signal));
      }));
    } catch (err) {
      if (!(err && err.name === 'AbortError') && current === state) {
        ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      }
    } finally {
      if (current === state) {
        state.controller = null;
        if (!ctx.signal.aborted) {
          // Drawn once more as a finished lookup, then said once (the status summary is no live region).
          renderSummary(q, state.responses, state.elapsed, state.finishedAt || state.stoppedAt);
          markStopped();
          setButtonState(false);
          announceTotals(q, state.responses);
        }
      }
    }

    /** After a Stop: each type not answered says so, with its Retry; the summary counts them. */
    function markStopped() {
      if (!state.stopped || current !== state) return;
      state.responses.forEach((resp, i) => { if (!resp) cards[i].setStopped(); });
      renderSummary(q, state.responses, state.elapsed, state.finishedAt || state.stoppedAt);
    }
  }

  /** Stop the lookup that asks now (the Stop button, Esc): what came in stays. */
  function stop() {
    if (!current || !current.controller) return;
    current.stopped = true;
    current.stoppedAt = new Date();
    current.controller.abort();
  }

  function setButtonState(busy) {
    // The keyboard focus follows the button that takes the other's place (the run bar moves it
    // before Look up turns busy, which a focused button would not survive).
    if (busy) {
      runBar.setRunning(true);
      setButtonBusy(runBtn, true);
    } else {
      setButtonBusy(runBtn, false);
      runBar.setRunning(false);
    }
    ctx.setBusy(busy);
    syncRunBar();
  }

  /** The totals of a finished lookup, said once: "example.com: 8 types · 9 records · 1 query failed". */
  function announceTotals(q, responses) {
    const layout = lookupLayout(q.types, responses);
    const total = responses.reduce((n, r) => n + (r && r.ok ? r.answers.filter((rr) => rr.type === r.type).length : 0), 0);
    const failed = responses.filter((r) => r && !r.ok).length;
    const parts = [t('lkp.sum.types', { count: q.types.length }), t('lkp.sum.records', { count: total }),
      failed ? t('lkp.count.failed', { count: failed }) : null,
      layout.noRecords.length ? t('lkp.count.nodata', { count: layout.noRecords.length }) : null].filter(Boolean);
    announce(`${q.input}: ${parts.join(' · ')}`);
  }

  /* --- initial state ------------------------------------------------------------------ */
  if (restored && restored.q && Array.isArray(restored.responses)) {
    run(restored.q, restored.responses, { at: restored.at, elapsed: restored.elapsed });
    // The kept answers under a name carried over from another tool: the box takes the name.
    if (isFillOnly(ctx.params) && ctx.params.name) takeCarried(ctx.params.name);
  } else if (!restored && params.name && !isFillOnly(ctx.params)) {
    // Shared link: run immediately. A re-mounted draft (typed, never run) or a name carried over
    // from another tool (`run=0`) only fills the form.
    Promise.resolve().then(() => start({ auto: true }));
  }
  syncRunBar();

  /** Fill the form from route-style params (`name`, `type`, `resolver`, `dnssec`, `cd`). */
  function fillForm(next) {
    nameField.value = next.name;
    const types = parseTypes(String(next.type || '').split(',')).types;
    if (types.length) {
      typeGroup.values = types.filter((x) => known.has(x));
      otherField.value = types.filter((x) => !known.has(x)).join(', ');
    }
    resolverField.value = getResolver(next.resolver) ? next.resolver : '';
    dnssecField.checked = next.dnssec === '1';
    cdField.checked = next.cd === '1';
  }

  active = {
    teardown() {
      if (current && current.controller) current.controller.abort();
      if (current) current.life.abort();
      closeExplain();
      unpinColumns();
      if (columnObserver) columnObserver.disconnect();
    },
    snapshot() {
      const form = {
        name: nameField.value,
        types: [...typeGroup.values, ...parseTypes(otherField.value).types],
        resolver: resolverField.value,
        dnssec: dnssecField.checked,
        cd: cdField.checked
      };
      if (!current || current.controller) return { form, carried };
      return { form, carried, q: current.q, responses: current.responses, at: current.finishedAt || current.stoppedAt || null, elapsed: current.elapsed };
    },
    result() {
      if (!current || current.controller || !current.finishedAt) return null;
      return { subject: current.q.input, at: current.finishedAt, params: queryParams(current.q) };
    },
    rerun() {
      if (current && current.q) fillForm(queryParams(current.q));
      start();
    },
    update(next) {
      if (!next.name) return false;
      if (isFillOnly(next)) {
        takeCarried(next.name);
        return true;
      }
      fillForm(next);
      start();
      return true;
    }
  };
}

/** Abort running queries. */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * Form + finished results carried over a language re-mount and kept for the next visit.
 * @returns {object|null}
 */
export function snapshot() {
  return active ? active.snapshot() : null;
}

/**
 * The finished answers on screen (kept by the shell when the view is left), or null.
 * @returns {{ subject: string, at: Date }|null}
 */
export function result() {
  return active ? active.result() : null;
}

/** "Run again" of the kept-result note: the same query again. */
export function rerun() {
  if (active) active.rerun();
}

/**
 * Take new route params (e.g. a link to another name) without a re-mount.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, snapshot, result, rerun, update };
