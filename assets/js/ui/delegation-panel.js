/**
 * ui/delegation-panel.js — Domain Health's "Delegation" card: is the zone's delegation sound?
 * The logic is lib/delegation.js; this module only renders it. The Health view loads it on the
 * first "Check the delegation" click (views/health.js keeps only the card and the holder).
 *
 * - Nothing is sent before the click. Then: the zone's NS set and the name servers' addresses
 *   from the DoH resolvers of the settings (free), and, behind the shared Globalping gate
 *   (ui/globalping-gate.js: the free quota read, the consent + cost dialog on this purpose's
 *   first send of the page session), one DNS measurement per question: SOA and NS at every name
 *   server, an unrelated name at every server (the recursion test, a switch) and the zone's NS at
 *   one server of the parent zone (the referral and its glue, a switch).
 * - The job lives on a holder the view keeps with the report on screen: a re-render of the report
 *   (RDAP Retry, the expected CAs) mounts a new panel on the same holder, a new check stops it,
 *   leaving the view aborts it; a finished result survives a language switch (the view's snapshot).
 * - Failures are statuses: a server that did not answer says why, a stopped run says so, the quota
 *   says when it comes back. Every string goes through h() / text nodes: answers are DNS data.
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, Disclosure, ErrorBanner, ExternalLink, KeyValueList, ProgressBar, SeverityIcon, announce, checkbox, CodeBlock } from './components.js';
import { registerRunning } from './jobs.js';
import { gateProbes, noteQuota, sharedQuota, liveQuota, whenText, measurementUrl } from './globalping-gate.js';
import { t, registerStrings, formatNumber, formatRelative, formatDateTime } from '../i18n.js';
import {
  prepareDelegation, runDelegation, delegationSummary, SERVER_STATES, LAME_STATES, TAKEOVER_STATES, NS_SET_STATES, RECURSION_STATES, PARENT_STATES, GLUE_STATES,
  DELEGATION_FINDINGS, DELEGATION_STOPS, PLAN_FAILURES, TAKEOVER_RISKS, SITTING_DUCKS_PROVIDERS, SITTING_DUCKS_REFERENCES
} from '../lib/delegation.js';
import { errorKind, mergeSignals } from '../lib/util.js';

/** Consent purpose of the gate (one per feature: each sends different data). */
export const DELEGATION_PURPOSE = 'delegation';
/** The CLI that tries a zone transfer at every name server (TCP, from your own network). */
export const DELEGATION_CLI = 'dns_parity.py';
/** The verdicts of a run (lib/delegation.js delegationSummary). */
const VERDICTS = Object.freeze(['ok', 'warn', 'error', 'partial']);
const VERDICT_VARIANT = Object.freeze({ ok: 'ok', warn: 'warn', error: 'error', partial: 'info' });

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'dlg.optParent': 'Ask a server of the parent zone (the delegation and its glue, 1 probe)',
  'dlg.optRecursion': 'Test every server for open recursion (1 probe each)',
  'dlg.run': 'Check the delegation',
  'dlg.again': 'Check again',
  'dlg.cost': { one: 'At most {count} Globalping probe.', other: 'At most {count} Globalping probes.' },
  'dlg.preparing': 'Reading the delegation from the resolvers…',
  'dlg.progress': 'Asking the name servers · {done} of {total} probes',
  'dlg.privacy': 'The check runs through Globalping, a free probe network run by jsDelivr and volunteers. The zone’s name {zone} and the host names of its name servers go to Globalping; each probe sends one DNS query (SOA or NS) to one of those servers. Anyone who has a measurement ID can read its result for about six months. The NS and address lookups before it go to the DNS-over-HTTPS resolvers of the settings; nothing else is sent.',
  'dlg.privacyRecursion': 'For the recursion test, the unrelated name {other} is asked at every server too.',
  'dlg.privacyParent': 'One server of the parent zone, {server}, is asked for the zone’s NS records (the referral).',
  'dlg.quota': 'This hour’s free Globalping quota cannot cover the check; it resets {when}. No probe was used.',
  'dlg.failed': 'The delegation check failed',
  'dlg.why.not-queryable': '{zone} cannot be asked through Globalping.',
  'dlg.why.lookup-failed': 'The resolvers did not answer the NS query of {zone}: try again.',
  'dlg.why.no-ns': '{zone} has no NS records: it is not a delegated zone.',
  'dlg.why.nothing-to-ask': 'No name server of {zone} can be asked through Globalping.',
  'dlg.head.ok': 'The delegation is consistent.',
  'dlg.head.warn': { one: '{count} thing to check in the delegation.', other: '{count} things to check in the delegation.' },
  'dlg.head.error': { one: '{count} problem in the delegation.', other: '{count} problems in the delegation.' },
  'dlg.head.partial': 'Not every question got an answer: the check is incomplete.',
  'dlg.stopped.quota': 'Stopped: this hour’s Globalping quota ran out (it resets {when}).',
  'dlg.stopped.unreachable': 'Stopped: Globalping could not be reached.',
  'dlg.stopped.abort': 'Stopped before every server was asked.',
  'dlg.state.ok': 'Authoritative',
  'dlg.state.refused': 'Refused (REFUSED)',
  'dlg.state.servfail': 'Server failure (SERVFAIL)',
  'dlg.state.not-authoritative': 'Not authoritative',
  'dlg.state.no-zone': 'Does not serve the zone',
  'dlg.state.timeout': 'No answer (timeout)',
  'dlg.state.unreachable': 'Unreachable',
  'dlg.state.no-address': 'Its name has no address',
  'dlg.state.ipv6-only': 'IPv6 only: not asked (a probe asks over IPv4)',
  'dlg.state.not-probeable': 'Not asked: Globalping cannot ask this name',
  'dlg.state.failed': 'No answer from Globalping',
  'dlg.state.not-run': 'Not asked',
  'dlg.nsState.same': 'Same as the delegation',
  'dlg.nsState.differs': 'Differs',
  'dlg.nsState.unknown': 'Not known',
  'dlg.rec.closed': 'Closed',
  'dlg.rec.open': 'Open resolver',
  'dlg.rec.unknown': 'Not known',
  'dlg.rec.not-run': 'Not asked',
  'dlg.parent.ok': 'Delegates',
  'dlg.parent.no-delegation': 'No delegation',
  'dlg.parent.refused': 'Refused (REFUSED)',
  'dlg.parent.servfail': 'Server failure (SERVFAIL)',
  'dlg.parent.timeout': 'No answer (timeout)',
  'dlg.parent.unreachable': 'Unreachable',
  'dlg.parent.failed': 'No answer from Globalping',
  'dlg.parent.not-run': 'Not asked',
  'dlg.glue.ok': 'Matches',
  'dlg.glue.missing': 'Missing',
  'dlg.glue.differs': 'Stale',
  'dlg.glue.partial': 'Partial',
  'dlg.glue.unknown': 'Not known',
  'dlg.find.lame.title': 'Lame delegation: {count} of {total} name servers',
  'dlg.find.lame.detail': 'These servers are in the delegation but do not answer for the zone authoritatively: resolvers that pick them wait, retry or fail. Fix the zone at that provider, or remove the server from the NS records at the registrar and in the zone.',
  'dlg.find.sitting-ducks.title': 'Sitting Ducks risk: a lame server at {providers}',
  'dlg.find.sitting-ducks.detail': 'The domain is delegated to a DNS provider that does not know the zone. At this provider, by public research, someone else with an account could create the zone and answer for the domain, mail and certificates included. Create the zone in your own account now, or remove these name servers at the registrar.',
  'dlg.find.glue-missing.title': { one: 'Missing glue for {count} name server inside the zone', other: 'Missing glue for {count} name servers inside the zone' },
  'dlg.find.glue-missing.detail': 'A name server inside the zone it serves needs its address at the parent (glue): without it, resolvers cannot find the server. Add the address at the registrar (“child name servers” or “host records”).',
  'dlg.find.serial-drift.title': 'SOA serials differ: {serials}',
  'dlg.find.serial-drift.detail': 'Servers of the same primary serve different versions of the zone: a secondary has not picked up the latest change (a failed or blocked zone transfer, a NOTIFY not sent). Visitors get old or new answers depending on the server.',
  'dlg.find.ns-mismatch.title': { one: '{count} server serves another NS set', other: '{count} servers serve another NS set' },
  'dlg.find.ns-mismatch.detail': 'The NS records these servers serve differ from the delegation the resolvers return. The zone’s own NS set should list the same servers as the registrar; a server that answers for another customer’s zone of the same name shows up here too.',
  'dlg.find.parent-child.title': 'The parent zone {parent} delegates to another set',
  'dlg.find.parent-child.detail': 'Only at the parent: {parentOnly}. Only in the zone: {childOnly}. Resolvers start from the parent’s list: change the NS records at the registrar or in the zone so that both say the same.',
  'dlg.find.glue-differs.title': { one: 'Stale glue for {count} name server', other: 'Stale glue for {count} name servers' },
  'dlg.find.glue-differs.detail': 'The parent hands out an address the zone no longer serves for this server: resolvers that use the glue reach the old address. Update the host record at the registrar.',
  'dlg.find.open-recursion.title': { one: '{count} name server is an open resolver', other: '{count} name servers are open resolvers' },
  'dlg.find.open-recursion.detail': 'It answered an unrelated name ({name}) from outside its own zones: anyone can use it for recursive queries, a tool for DNS amplification and cache poisoning (RFC 5358). Turn recursion off on authoritative servers, or limit it to your own networks.',
  'dlg.find.glue-partial.title': { one: 'Partial glue for {count} name server', other: 'Partial glue for {count} name servers' },
  'dlg.find.glue-partial.detail': 'The parent has only some of the addresses the zone serves for this server (often the IPv6 address is missing). Not wrong, but resolvers use only those addresses.',
  'dlg.find.multi-provider.title': 'Several primaries: {primaries}',
  'dlg.find.multi-provider.detail': 'The servers name different primaries in their SOA: a multi-provider setup, where each provider keeps its own serial. Serials are compared only among the servers of one primary.',
  'dlg.find.not-asked.title': { one: '{count} name server not fully asked', other: '{count} name servers not fully asked' },
  'dlg.find.not-asked.detail': 'An IPv6-only server (a probe asks over IPv4), a name Globalping cannot ask, a ninth server or more, a stop or the probe budget: what these servers serve is not known.',
  'dlg.find.consistent.title': 'Every name server answers authoritatively, with one serial and one NS set',
  'dlg.find.consistent.detail': 'Asked directly, each server serves the zone the delegation points to.',
  'dlg.risk.claimable': 'any account',
  'dlg.risk.purchase': 'an account with a paid plan',
  'dlg.risk.edge': 'only when the same name servers are handed out again',
  'dlg.ref.infoblox': 'Infoblox: Who knew domain hijacking is so easy?',
  'dlg.ref.eclypsium': 'Eclypsium: Ducks Now Sitting (DNS)',
  'dlg.ref.list': 'can-i-take-over-dns (the provider list)',
  'dlg.col.server': 'Name server',
  'dlg.col.state': 'SOA answer',
  'dlg.col.serial': 'Serial',
  'dlg.col.ns': 'NS set',
  'dlg.col.recursion': 'Recursion',
  'dlg.col.probe': 'Asked from',
  'dlg.col.results': 'Results',
  'dlg.col.glueHost': 'Name server in the zone',
  'dlg.col.glue': 'Glue at the parent',
  'dlg.col.child': 'The zone serves',
  'dlg.col.glueState': 'Glue',
  'dlg.delegation': 'Delegation (resolvers)',
  'dlg.parentAt': 'Parent zone {zone}, asked at {server}',
  'dlg.parentNs': 'Delegates to',
  'dlg.truncated': 'The referral was truncated: the glue may be incomplete.',
  'dlg.spent': { one: '{count} probe used', other: '{count} probes used' },
  'dlg.left': '{remaining} left this hour',
  'dlg.checkedAt': 'Checked {time}',
  'dlg.providersTitle': 'Providers known for the Sitting Ducks risk',
  'dlg.providersNote': 'A lame delegation to one of these providers is a takeover risk, by the public list (statuses read on 2026-10-08). A provider can fix this at any time: a match is a reason to check, not a verdict.',
  'dlg.cli': 'A zone transfer (AXFR) runs over TCP, from your own network: the CLI tries one at every name server and says whether anyone can download the whole zone.',
  'dlg.na': 'n/a',
  'dlg.missingNs': 'missing: {names}',
  'dlg.extraNs': 'extra: {names}',
  'dlg.rtt': '{ms} ms',
  'dlg.measurement': 'Measurement {id}',
  'dlg.switchRunning': 'The delegation check on Globalping (the probes it has used stay used)'
});

registerStrings('tr', {
  'dlg.optParent': 'Üst zone’un bir sunucusunu sor (delegasyon ve glue kayıtları, 1 ölçüm)',
  'dlg.optRecursion': 'Her sunucuyu açık özyineleme için test et (her biri 1 ölçüm)',
  'dlg.run': 'Delegasyonu kontrol et',
  'dlg.again': 'Yeniden kontrol et',
  'dlg.cost': 'En fazla {count} Globalping ölçümü.',
  'dlg.preparing': 'Delegasyon çözümleyicilerden okunuyor…',
  'dlg.progress': 'Ad sunucuları soruluyor · {total} ölçümden {done} tanesi',
  'dlg.privacy': 'Kontrol, jsDelivr ve gönüllülerin işlettiği ücretsiz bir ölçüm ağı olan Globalping üzerinden yapılır. Zone’un adı {zone} ve ad sunucularının host adları Globalping’e gider; her ölçüm noktası bu sunuculardan birine tek bir DNS sorgusu (SOA ya da NS) gönderir. Ölçüm kimliğini bilen herkes sonucu yaklaşık altı ay okuyabilir. Öncesindeki NS ve adres sorguları ayarlardaki DNS-over-HTTPS çözümleyicilerine gider; başka hiçbir şey gönderilmez.',
  'dlg.privacyRecursion': 'Özyineleme testi için alakasız {other} adı da her sunucuya sorulur.',
  'dlg.privacyParent': 'Üst zone’un bir sunucusuna ({server}) zone’un NS kayıtları (yönlendirme) sorulur.',
  'dlg.quota': 'Bu saatin ücretsiz Globalping kotası kontrolü karşılamıyor; {when} sıfırlanır. Hiçbir ölçüm harcanmadı.',
  'dlg.failed': 'Delegasyon kontrolü başarısız oldu',
  'dlg.why.not-queryable': '{zone} Globalping üzerinden sorulamaz.',
  'dlg.why.lookup-failed': 'Çözümleyiciler {zone} için NS sorgusunu yanıtlamadı: yeniden deneyin.',
  'dlg.why.no-ns': '{zone} için NS kaydı yok: delege edilmiş bir zone değil.',
  'dlg.why.nothing-to-ask': '{zone} zone’unun hiçbir ad sunucusu Globalping üzerinden sorulamaz.',
  'dlg.head.ok': 'Delegasyon tutarlı.',
  'dlg.head.warn': 'Delegasyonda kontrol edilecek {count} konu var.',
  'dlg.head.error': 'Delegasyonda {count} sorun var.',
  'dlg.head.partial': 'Her soru yanıt almadı: kontrol eksik.',
  'dlg.stopped.quota': 'Durduruldu: bu saatin Globalping kotası doldu ({when} sıfırlanır).',
  'dlg.stopped.unreachable': 'Durduruldu: Globalping’e ulaşılamadı.',
  'dlg.stopped.abort': 'Her sunucu sorulmadan durduruldu.',
  'dlg.state.ok': 'Yetkili',
  'dlg.state.refused': 'Reddetti (REFUSED)',
  'dlg.state.servfail': 'Sunucu hatası (SERVFAIL)',
  'dlg.state.not-authoritative': 'Yetkili değil',
  'dlg.state.no-zone': 'Zone’u sunmuyor',
  'dlg.state.timeout': 'Yanıt yok (zaman aşımı)',
  'dlg.state.unreachable': 'Ulaşılamadı',
  'dlg.state.no-address': 'Adının adresi yok',
  'dlg.state.ipv6-only': 'Yalnızca IPv6: sorulmadı (ölçüm noktası IPv4 üzerinden sorar)',
  'dlg.state.not-probeable': 'Sorulmadı: Globalping bu adı soramaz',
  'dlg.state.failed': 'Globalping’den yanıt alınamadı',
  'dlg.state.not-run': 'Sorulmadı',
  'dlg.nsState.same': 'Delegasyonla aynı',
  'dlg.nsState.differs': 'Farklı',
  'dlg.nsState.unknown': 'Bilinmiyor',
  'dlg.rec.closed': 'Kapalı',
  'dlg.rec.open': 'Açık çözümleyici',
  'dlg.rec.unknown': 'Bilinmiyor',
  'dlg.rec.not-run': 'Sorulmadı',
  'dlg.parent.ok': 'Delege ediyor',
  'dlg.parent.no-delegation': 'Delegasyon yok',
  'dlg.parent.refused': 'Reddetti (REFUSED)',
  'dlg.parent.servfail': 'Sunucu hatası (SERVFAIL)',
  'dlg.parent.timeout': 'Yanıt yok (zaman aşımı)',
  'dlg.parent.unreachable': 'Ulaşılamadı',
  'dlg.parent.failed': 'Globalping’den yanıt alınamadı',
  'dlg.parent.not-run': 'Sorulmadı',
  'dlg.glue.ok': 'Eşleşiyor',
  'dlg.glue.missing': 'Eksik',
  'dlg.glue.differs': 'Eskimiş',
  'dlg.glue.partial': 'Kısmi',
  'dlg.glue.unknown': 'Bilinmiyor',
  'dlg.find.lame.title': 'Bozuk delegasyon: {total} ad sunucusundan {count} tanesi',
  'dlg.find.lame.detail': 'Bu sunucular delegasyonda yer alıyor ama zone için yetkili yanıt vermiyor: onları seçen çözümleyiciler bekler, yeniden dener ya da başarısız olur. Zone’u o sağlayıcıda düzeltin ya da sunucuyu kayıt firmasındaki ve zone’daki NS kayıtlarından çıkarın.',
  'dlg.find.sitting-ducks.title': 'Sitting Ducks riski: {providers} sağlayıcısında bozuk bir sunucu',
  'dlg.find.sitting-ducks.detail': 'Alan adı, zone’u tanımayan bir DNS sağlayıcısına delege edilmiş. Kamuya açık araştırmalara göre bu sağlayıcıda hesabı olan başka biri zone’u oluşturup alan adı adına yanıt verebilir; e-posta ve sertifikalar da buna dahildir. Zone’u hemen kendi hesabınızda oluşturun ya da bu ad sunucularını kayıt firmasında kaldırın.',
  'dlg.find.glue-missing.title': 'Zone içindeki {count} ad sunucusu için glue kaydı eksik',
  'dlg.find.glue-missing.detail': 'Sunduğu zone’un içindeki bir ad sunucusunun adresi üst zone’da (glue) bulunmalıdır; yoksa çözümleyiciler sunucuyu bulamaz. Adresi kayıt firmasında ekleyin (“alt ad sunucuları” ya da “host kayıtları”).',
  'dlg.find.serial-drift.title': 'SOA seri numaraları farklı: {serials}',
  'dlg.find.serial-drift.detail': 'Aynı birincil sunucuya bağlı sunucular zone’un farklı sürümlerini sunuyor: bir ikincil sunucu son değişikliği almamış (başarısız ya da engellenmiş bir zone aktarımı, gönderilmemiş bir NOTIFY). Ziyaretçiler sunucuya göre eski ya da yeni yanıt alır.',
  'dlg.find.ns-mismatch.title': '{count} sunucu başka bir NS kümesi sunuyor',
  'dlg.find.ns-mismatch.detail': 'Bu sunucuların sunduğu NS kayıtları, çözümleyicilerin döndürdüğü delegasyondan farklı. Zone’un kendi NS kümesi kayıt firmasındakiyle aynı sunucuları listelemelidir; aynı adlı başka bir müşteri zone’u için yanıt veren bir sunucu da burada görünür.',
  'dlg.find.parent-child.title': 'Üst zone ({parent}) başka bir kümeye delege ediyor',
  'dlg.find.parent-child.detail': 'Yalnızca üst zone’da: {parentOnly}. Yalnızca zone’da: {childOnly}. Çözümleyiciler üst zone’daki listeden başlar: ikisi aynı olsun diye kayıt firmasındaki ya da zone’daki NS kayıtlarını değiştirin.',
  'dlg.find.glue-differs.title': '{count} ad sunucusu için glue kaydı eskimiş',
  'dlg.find.glue-differs.detail': 'Üst zone, zone’un bu sunucu için artık sunmadığı bir adres veriyor: glue kullanan çözümleyiciler eski adrese gider. Kayıt firmasındaki host kaydını güncelleyin.',
  'dlg.find.open-recursion.title': '{count} ad sunucusu açık çözümleyici',
  'dlg.find.open-recursion.detail': 'Alakasız bir adı ({name}) kendi zone’ları dışından yanıtladı: herkes onu özyinelemeli sorgular için kullanabilir; bu, DNS yükseltme saldırılarına ve önbellek zehirlemeye açık kapıdır (RFC 5358). Yetkili sunucularda özyinelemeyi kapatın ya da kendi ağlarınızla sınırlayın.',
  'dlg.find.glue-partial.title': '{count} ad sunucusu için glue kaydı kısmi',
  'dlg.find.glue-partial.detail': 'Üst zone, zone’un bu sunucu için sunduğu adreslerin yalnızca bir kısmına sahip (çoğunlukla IPv6 adresi eksik). Hata değil, ama çözümleyiciler yalnızca bu adresleri kullanır.',
  'dlg.find.multi-provider.title': 'Birden fazla birincil sunucu: {primaries}',
  'dlg.find.multi-provider.detail': 'Sunucular SOA kayıtlarında farklı birincil sunucular gösteriyor: her sağlayıcının kendi seri numarasını tuttuğu çok sağlayıcılı bir yapı. Seri numaraları yalnızca aynı birincil sunucuya bağlı sunucular arasında karşılaştırılır.',
  'dlg.find.not-asked.title': '{count} ad sunucusu tam olarak sorulmadı',
  'dlg.find.not-asked.detail': 'Yalnızca IPv6 adresi olan bir sunucu (ölçüm noktası IPv4 üzerinden sorar), Globalping’in soramadığı bir ad, dokuzuncu ve sonraki sunucular, bir durdurma ya da ölçüm bütçesi: bu sunucuların ne sunduğu bilinmiyor.',
  'dlg.find.consistent.title': 'Her ad sunucusu tek bir seri numarası ve tek bir NS kümesiyle yetkili yanıt veriyor',
  'dlg.find.consistent.detail': 'Doğrudan sorulan her sunucu, delegasyonun gösterdiği zone’u sunuyor.',
  'dlg.risk.claimable': 'herhangi bir hesap',
  'dlg.risk.purchase': 'ücretli planı olan bir hesap',
  'dlg.risk.edge': 'yalnızca aynı ad sunucuları yeniden verilirse',
  'dlg.ref.infoblox': 'Infoblox: Who knew domain hijacking is so easy?',
  'dlg.ref.eclypsium': 'Eclypsium: Ducks Now Sitting (DNS)',
  'dlg.ref.list': 'can-i-take-over-dns (sağlayıcı listesi)',
  'dlg.col.server': 'Ad sunucusu',
  'dlg.col.state': 'SOA yanıtı',
  'dlg.col.serial': 'Seri no',
  'dlg.col.ns': 'NS kümesi',
  'dlg.col.recursion': 'Özyineleme',
  'dlg.col.probe': 'Sorulduğu yer',
  'dlg.col.results': 'Sonuçlar',
  'dlg.col.glueHost': 'Zone içindeki ad sunucusu',
  'dlg.col.glue': 'Üst zone’daki glue',
  'dlg.col.child': 'Zone’un sunduğu',
  'dlg.col.glueState': 'Glue',
  'dlg.delegation': 'Delegasyon (çözümleyiciler)',
  'dlg.parentAt': 'Üst zone {zone}, sorulan sunucu: {server}',
  'dlg.parentNs': 'Delege ettiği sunucular',
  'dlg.truncated': 'Yönlendirme yanıtı kesildi: glue kayıtları eksik olabilir.',
  'dlg.spent': '{count} ölçüm harcandı',
  'dlg.left': 'bu saat {remaining} kaldı',
  'dlg.checkedAt': '{time} kontrol edildi',
  'dlg.providersTitle': 'Sitting Ducks riskiyle bilinen sağlayıcılar',
  'dlg.providersNote': 'Kamuya açık listeye göre (durumlar 2026-10-08 tarihinde okundu) bu sağlayıcılardan birine bozuk bir delegasyon, ele geçirme riskidir. Sağlayıcı bunu her an düzeltebilir: eşleşme bir kontrol nedenidir, kesin hüküm değil.',
  'dlg.cli': 'Zone aktarımı (AXFR) kendi ağınızdan TCP ile yapılır: CLI her ad sunucusunda bir aktarım dener ve zone’un tamamını herkesin indirip indiremeyeceğini söyler.',
  'dlg.na': 'alınamadı',
  'dlg.missingNs': 'eksik: {names}',
  'dlg.extraNs': 'fazladan: {names}',
  'dlg.rtt': '{ms} ms',
  'dlg.measurement': 'Ölçüm {id}',
  'dlg.switchRunning': 'Globalping’de delegasyon kontrolü (kullandığı ölçümler geri gelmez)'
});

/**
 * Every i18n key this panel builds from a library code (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  const keys = [];
  for (const s of SERVER_STATES) keys.push(`dlg.state.${s}`);
  for (const s of NS_SET_STATES) keys.push(`dlg.nsState.${s}`);
  for (const s of RECURSION_STATES) keys.push(`dlg.rec.${s}`);
  for (const s of PARENT_STATES) keys.push(`dlg.parent.${s}`);
  for (const s of GLUE_STATES) keys.push(`dlg.glue.${s}`);
  for (const f of DELEGATION_FINDINGS) keys.push(`dlg.find.${f}.title`, `dlg.find.${f}.detail`);
  for (const s of DELEGATION_STOPS) keys.push(`dlg.stopped.${s}`);
  for (const w of PLAN_FAILURES) keys.push(`dlg.why.${w}`);
  for (const r of TAKEOVER_RISKS) keys.push(`dlg.risk.${r}`);
  for (const r of SITTING_DUCKS_REFERENCES) keys.push(`dlg.ref.${r.id}`);
  for (const v of VERDICTS) keys.push(`dlg.head.${v}`);
  return keys;
}

/* ------------------------------------------------------------------------ */
/* The job holder                                                           */
/* ------------------------------------------------------------------------ */

/**
 * A fresh holder for one report's zone (the Health view keeps it with the report on screen).
 * @param {string} zone
 * @returns {object}
 */
export function freshDelegation(zone) {
  return {
    zone, status: 'idle', result: null, error: null, why: null, resetAt: null, controller: null, done: 0, total: 0, spent: 0,
    recursion: true, parent: true, finishedAt: null, view: null, userStop: false
  };
}

/** Holders whose check runs now: a switch to another workspace names it (ui/jobs.js). */
const runningHolders = new Set();
registerRunning('dlg.switchRunning', () => [...runningHolders].some((H) => !!H.controller));

const sevVariant = (sev) => ({ ok: 'ok', info: 'info', warn: 'warn', error: 'error' }[sev] || 'neutral');
const stateVariant = (state) => (state === 'ok' ? 'ok' : LAME_STATES.includes(state) ? 'error' : 'neutral');

/* ------------------------------------------------------------------------ */
/* The panel                                                                */
/* ------------------------------------------------------------------------ */

/**
 * The card body: options, the run and its result. `start`: run at once (the view's first click).
 * @param {{ ctx: object, holder: object, start?: boolean }} opts
 * @returns {HTMLElement}
 */
export function DelegationPanel({ ctx, holder, start = false }) {
  const box = h('div', { class: 'stack-sm dlg-panel', dataset: { delegation: 'panel' } });
  const progress = ProgressBar({ label: t('dlg.preparing') });
  const view = { render, progress: renderProgress, connected: () => box.isConnected };
  holder.view = view;
  const shown = () => (holder.view && holder.view.connected() ? holder.view : view);

  function renderProgress() {
    if (holder.status === 'running') {
      progress.setLabel(t('dlg.progress', { done: formatNumber(holder.done), total: formatNumber(holder.total) }));
      progress.set(holder.done, Math.max(1, holder.total));
    }
  }

  function render() {
    clear(box);
    box.dataset.state = holder.status;
    const busy = !!holder.controller;
    const opts = h('div', { class: 'cluster dlg-options' },
      checkbox({ label: t('dlg.optParent'), checked: holder.parent, disabled: busy, onChange: (v) => { holder.parent = v; } }).el,
      checkbox({ label: t('dlg.optRecursion'), checked: holder.recursion, disabled: busy, onChange: (v) => { holder.recursion = v; } }).el);
    if (busy) {
      progress.el.hidden = false;
      if (holder.status !== 'running') {
        progress.setLabel(t('dlg.preparing'));
        progress.set(0, 1);
      } else renderProgress();
      box.append(progress.el, h('div', { class: 'dlg-actions' },
        Button({
          label: t('common.stop'), icon: 'stop', size: 'sm', dataset: { action: 'dlg-stop' },
          onClick: () => {
            if (!holder.controller) return;
            holder.userStop = true;
            holder.controller.abort();
          }
        })));
      return;
    }
    if (holder.status === 'quota') box.append(Alert({ variant: 'warn', compact: true, icon: 'clock', message: t('dlg.quota', { when: whenText(holder.resetAt) }) }));
    else if (holder.status === 'failed') box.append(ErrorBanner(holder.error, { title: t('dlg.failed'), compact: true }));
    else if (holder.status === 'nothing') box.append(Alert({ variant: 'info', compact: true, message: t(`dlg.why.${holder.why}`, { zone: holder.zone }) }));
    else if (holder.status === 'done' && holder.result) box.append(...results(holder.result));
    box.append(opts, h('div', { class: 'dlg-actions' },
      Button({
        label: t(holder.status === 'done' ? 'dlg.again' : 'dlg.run'), icon: 'globe', size: 'sm', variant: holder.status === 'done' ? 'secondary' : 'primary',
        dataset: { action: 'dlg-run' }, onClick: () => run()
      })));
  }

  /* --- the run ------------------------------------------------------------- */
  async function run() {
    if (holder.controller || !ctx.requireOnline()) return;
    const ac = new AbortController();
    const signal = mergeSignals(ctx.signal, ac.signal);
    const prev = { status: holder.status, result: holder.result, error: holder.error, why: holder.why, resetAt: holder.resetAt };
    const focusHere = box.contains(globalThis.document && globalThis.document.activeElement);
    Object.assign(holder, { controller: ac, status: 'preparing', error: null, done: 0, total: 0, spent: 0, userStop: false });
    runningHolders.add(holder);
    shown().render();
    // Stopped by a new check or by leaving the view (not by its Stop button): back to what was shown.
    const live = () => holder.controller === ac && (!signal.aborted || holder.userStop);
    try {
      const dns = await ctx.getDns();
      const opts = { recursion: holder.recursion, parent: holder.parent };
      const prep = await prepareDelegation(holder.zone, { dns, signal, ...opts });
      if (!live()) return;
      if (!prep.ok) {
        Object.assign(holder, { status: 'nothing', why: prep.why });
        announce(t(`dlg.why.${prep.why}`, { zone: holder.zone }));
        return;
      }
      holder.status = 'gate';
      const gate = await gateProbes(ctx, { purpose: DELEGATION_PURPOSE, probes: prep.probes, signal, privacy: privacyText(prep, opts), className: 'dlg-confirm' });
      if (!live()) return;
      if (gate.status === 'cancelled') {
        Object.assign(holder, prev);
        return;
      }
      if (gate.status === 'quota') {
        Object.assign(holder, { status: 'quota', resetAt: gate.resetAt });
        announce(t('dlg.quota', { when: whenText(gate.resetAt) }));
        return;
      }
      if (gate.status === 'unreachable') throw gate.error;
      Object.assign(holder, { status: 'running', total: prep.probes });
      shown().render();
      const result = await runDelegation(prep, {
        client: gate.client, signal, ...opts, maxProbes: prep.probes,
        onProgress: ({ done, total, spent }) => {
          if (!live()) return;
          Object.assign(holder, { done, total, spent });
          shown().progress();
        },
        onQuota: (q) => noteQuota(q)
      });
      if (!live()) return;
      Object.assign(holder, { status: 'done', result, spent: result.spent, resetAt: result.resetAt, finishedAt: new Date() });
      announce(headline(result));
    } catch (err) {
      if (holder.controller !== ac) return;
      if (errorKind(err) === 'abort' || signal.aborted) Object.assign(holder, prev);
      else Object.assign(holder, { status: 'failed', error: err });
    } finally {
      if (holder.controller === ac) {
        // Ended before a result (a cancelled dialog, a new check, the view left): what was shown before.
        if (['preparing', 'gate', 'running'].includes(holder.status)) Object.assign(holder, prev);
        holder.controller = null;
      }
      runningHolders.delete(holder);
      const v = shown();
      v.render();
      if (focusHere && v.connected()) {
        const btn = v === view ? box.querySelector('[data-action="dlg-run"]') : null;
        if (btn) btn.focus({ preventScroll: true });
      }
    }
  }

  function privacyText(prep, opts) {
    const parts = [t('dlg.privacy', { zone: prep.zone })];
    if (opts.recursion && prep.recursionName) parts.push(t('dlg.privacyRecursion', { other: prep.recursionName }));
    if (opts.parent && prep.parent && prep.parent.server) parts.push(t('dlg.privacyParent', { server: prep.parent.server }));
    parts.push(t('dlg.cost', { count: prep.probes }));
    return parts.join(' ');
  }

  /* --- results ------------------------------------------------------------- */
  function headline(result) {
    const sum = delegationSummary(result);
    return t(`dlg.head.${sum.verdict}`, { count: sum.verdict === 'error' ? sum.errors : sum.warnings });
  }

  function results(result) {
    const sum = delegationSummary(result);
    const out = [];
    out.push(h('div', { dataset: { dlgVerdict: sum.verdict } }, Alert({ variant: VERDICT_VARIANT[sum.verdict], compact: true, message: headline(result) })));
    if (result.stoppedBy) {
      out.push(Alert({ variant: result.stoppedBy === 'abort' ? 'info' : 'warn', compact: true, message: t(`dlg.stopped.${result.stoppedBy}`, { when: whenText(result.resetAt) }) }));
    }
    out.push(h('ul', { class: 'hlt-findings dlg-findings' }, result.findings.map((f) => finding(f, result))));
    out.push(serverTable(result));
    if (result.parent) out.push(parentBlock(result));
    if (result.glue.length) out.push(glueTable(result));
    out.push(providersBlock());
    out.push(cliBlock(result.zone));
    out.push(metaLine(result));
    return out;
  }

  function finding(f, result) {
    const params = { ...f.params, name: result.recursionName || '' };
    const refs = f.code === 'sitting-ducks'
      ? h('div', { class: 'cluster text-sm dlg-refs' }, SITTING_DUCKS_REFERENCES.map((r) => ExternalLink(r.url, t(`dlg.ref.${r.id}`))))
      : null;
    return h('li', { class: ['hlt-finding', `hlt-sev-${f.severity}`], dataset: { finding: f.code, severity: f.severity } },
      h('span', { class: 'hlt-check-icon' }, SeverityIcon(f.severity, { size: 16 })),
      h('div', { class: 'hlt-check-body' },
        h('div', { class: 'hlt-finding-title' }, t(`dlg.find.${f.code}.title`, params)),
        h('div', { class: 'hlt-check-detail' }, t(`dlg.find.${f.code}.detail`, params)),
        f.servers.length ? h('div', { class: 'cluster dlg-servers' }, f.servers.map((ns) => h('span', { class: 'mono text-sm' }, ns))) : null,
        refs));
  }

  const na = () => h('span', { class: 'muted text-sm' }, t('dlg.na'));
  const table = (className, headers, rows) => h('div', { class: ['dt-scroll', 'dt-scroll-free', 'hlt-table', className], attrs: { tabindex: 0 } },
    h('table', { class: 'dt-table dt-dense' },
      h('thead', null, h('tr', null, headers.map((x) => h('th', { attrs: { scope: 'col' } }, x)))),
      h('tbody', null, rows)));

  function serverTable(result) {
    const rows = result.servers.map((s) => {
      const nsCell = s.nsSet
        ? h('div', { class: 'stack-xs' }, Badge(t(`dlg.nsState.${s.nsState}`), { variant: s.nsState === 'same' ? 'ok' : 'warn' }),
          s.missing.length ? h('span', { class: 'mono text-xs' }, t('dlg.missingNs', { names: s.missing.join(', ') })) : null,
          s.extra.length ? h('span', { class: 'mono text-xs' }, t('dlg.extraNs', { names: s.extra.join(', ') })) : null)
        : Badge(t(`dlg.nsState.${s.nsState}`), { variant: 'neutral' });
      const probe = s.probe ? [s.probe.city, s.probe.country].filter(Boolean).join(', ') + (s.probe.network ? ` · ${s.probe.network}` : '') : '';
      const links = s.measurementIds.map((id, i) => {
        const url = measurementUrl(id);
        return url ? h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', attrs: { 'aria-label': t('dlg.measurement', { id }) } }, String(i + 1)) : null;
      }).filter(Boolean);
      return h('tr', { class: 'dt-row', dataset: { ns: s.ns, state: s.state } },
        h('td', null, h('div', { class: 'stack-xs' }, h('span', { class: 'mono' }, s.ns),
          s.provider ? Badge(s.provider.name, { variant: TAKEOVER_STATES.includes(s.state) ? 'error' : 'neutral', title: t(`dlg.risk.${s.provider.risk}`) }) : null,
          s.nsid ? h('span', { class: 'muted text-xs mono' }, `NSID ${s.nsid}`) : null)),
        h('td', null, Badge(t(`dlg.state.${s.state}`), { variant: stateVariant(s.state) })),
        h('td', { class: 'num' }, Number.isFinite(s.serial) ? String(s.serial) : na()),
        h('td', null, nsCell),
        h('td', null, Badge(t(`dlg.rec.${s.recursion}`), { variant: s.recursion === 'open' ? 'warn' : s.recursion === 'closed' ? 'ok' : 'neutral' })),
        h('td', { class: 'text-sm' }, probe ? h('span', null, probe, Number.isFinite(s.rttMs) ? h('span', { class: 'muted' }, ` · ${t('dlg.rtt', { ms: formatNumber(s.rttMs) })}`) : null) : na()),
        h('td', null, links.length ? h('span', { class: 'cluster text-sm' }, links) : na()));
    });
    return table('dlg-table dlg-servers-table', [t('dlg.col.server'), t('dlg.col.state'), t('dlg.col.serial'), t('dlg.col.ns'), t('dlg.col.recursion'),
      t('dlg.col.probe'), t('dlg.col.results')], rows);
  }

  function parentBlock(result) {
    const p = result.parent;
    const items = [
      { key: t('dlg.delegation'), value: h('span', { class: 'mono text-sm' }, result.delegation.join(', ')) },
      { key: t('dlg.parentAt', { zone: p.zone, server: p.server || '—' }), value: Badge(t(`dlg.parent.${p.state}`), { variant: p.state === 'ok' ? 'ok' : p.state === 'not-run' ? 'neutral' : 'error' }) }
    ];
    if (p.ns.length) items.push({ key: t('dlg.parentNs'), value: h('span', { class: 'mono text-sm' }, p.ns.join(', ')) });
    return h('div', { class: 'stack-xs dlg-parent', dataset: { parent: p.state } }, KeyValueList(items, { className: 'hlt-kv' }),
      p.truncated ? h('p', { class: 'muted text-sm' }, t('dlg.truncated')) : null);
  }

  function glueTable(result) {
    const list = (g) => [...g.a, ...g.aaaa];
    const rows = result.glue.map((g) => h('tr', { class: 'dt-row', dataset: { glue: g.state, host: g.host } },
      h('td', { class: 'mono' }, g.host),
      h('td', { class: 'mono text-sm' }, list(g.glue).length ? list(g.glue).join(', ') : na()),
      h('td', { class: 'mono text-sm' }, list(g.child).length ? list(g.child).join(', ') : na()),
      h('td', null, Badge(t(`dlg.glue.${g.state}`), { variant: g.state === 'ok' ? 'ok' : g.state === 'missing' ? 'error' : g.state === 'unknown' ? 'neutral' : g.state === 'partial' ? 'info' : 'warn' }))));
    return table('dlg-table dlg-glue-table', [t('dlg.col.glueHost'), t('dlg.col.glue'), t('dlg.col.child'), t('dlg.col.glueState')], rows);
  }

  function providersBlock() {
    return Disclosure({
      summary: t('dlg.providersTitle'),
      className: 'dlg-providers',
      children: h('div', { class: 'stack-xs' },
        h('p', { class: 'muted text-sm' }, t('dlg.providersNote')),
        h('ul', { class: 'dlg-provider-list text-sm' }, SITTING_DUCKS_PROVIDERS.map((p) => h('li', { dataset: { provider: p.id } },
          h('strong', null, p.name), ' · ', h('span', { class: 'mono' }, p.hosts), ' · ', t(`dlg.risk.${p.risk}`)))),
        h('div', { class: 'cluster text-sm dlg-refs' }, SITTING_DUCKS_REFERENCES.map((r) => ExternalLink(r.url, t(`dlg.ref.${r.id}`)))))
    });
  }

  function cliBlock(zone) {
    return h('div', { class: 'stack-xs dlg-cli' },
      h('p', { class: 'muted text-sm' }, t('dlg.cli')),
      CodeBlock(`python3 ${DELEGATION_CLI} --axfr ${zone}`, { label: 'AXFR' }));
  }

  function metaLine(result) {
    const q = liveQuota(sharedQuota());
    return h('p', { class: 'muted text-xs dlg-meta' },
      h('span', { title: formatDateTime(result.finishedAt) }, t('dlg.checkedAt', { time: formatRelative(result.finishedAt) })),
      ' · ', t('dlg.spent', { count: result.spent }),
      q && Number.isFinite(q.remaining) ? ` · ${t('dlg.left', { remaining: formatNumber(q.remaining) })}` : null);
  }

  render();
  if (start) Promise.resolve().then(() => run());
  return box;
}
