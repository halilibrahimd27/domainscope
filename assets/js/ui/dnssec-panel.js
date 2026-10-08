/**
 * ui/dnssec-panel.js — DNS Lookup › "DNSSEC chain" (ROADMAP P1.14): the chain of trust of the
 * looked-up name and type, validated in this browser by lib/dnssec.js from the IANA root trust
 * anchors down.
 *
 * - Loaded on the first click of the lookup summary's "DNSSEC chain" button (views/lookup.js);
 *   that click is the go-ahead: it asks the shared DoH client (the lookup's resolver, or its
 *   failover chain) with the DO and CD bits, nothing else, and only while online.
 * - The verdict comes first: secure / insecure / bogus / indeterminate, the reason of the first
 *   break and what to fix (a DS that matches no DNSKEY after a rollover names both key tags).
 *   Then one card per zone, the root first: its DS at the parent (or the trust anchors) with the
 *   key each one matches, its DNSKEY set (key tag, KSK / ZSK, algorithm, size), and the
 *   signatures over both with their validity windows; then the answer with its signatures or its
 *   NSEC / NSEC3 proof; a CNAME's target gets its own chain below.
 * - A question that got no answer is a status ("⚠ n/a" wording of lib/sourcestatus.js) with a
 *   Retry that validates again without the cache; the run is aborted when the view goes away or
 *   a new lookup starts ({@link DnssecPanel} `destroy`).
 * - Every value from the network (names, key data, error text) is rendered as text.
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, Spinner, select, announce } from './components.js';
import { registerStrings, formatDateTime, formatDate, formatNumber } from '../i18n.js';
import { validateChain, DNSSEC_STATUSES, DNSSEC_REASONS, SIG_RESULTS, MAX_ALIASES, MAX_NSEC3_ITERATIONS } from '../lib/dnssec.js';
import { DNSSEC_ALGORITHMS, DS_DIGEST_TYPES } from '../lib/dnswire.js';
import { getResolver } from '../lib/resolvers.js';
import { mergeSignals } from '../lib/util.js';
import { dohStatus } from '../lib/sourcestatus.js';
import { RetryButton, statusText } from './source-status.js';

const STATUS_VARIANT = Object.freeze({ secure: 'ok', insecure: 'warn', bogus: 'error', indeterminate: 'neutral' });
const STATUS_ICON = Object.freeze({ secure: 'check-circle', insecure: 'alert', bogus: 'x-circle', indeterminate: 'help' });
const SIG_VARIANT = Object.freeze({ valid: 'ok', expired: 'error', 'not-yet-valid': 'warn', 'unsupported-algorithm': 'warn' });

registerStrings('en', {
  'dsec.title': 'DNSSEC chain of trust',
  'dsec.intro': 'Each zone from the root down is checked in this browser: its DS at the parent, its keys and the signatures over them, then the answer. The resolver only carries the records (DO and CD bits); the verdict is this browser’s.',
  'dsec.type': 'Record type',
  'dsec.run': 'Validate chain',
  'dsec.rerun': 'Validate again',
  'dsec.running': 'Checking {zone}…',
  'dsec.status.secure': 'Secure',
  'dsec.status.insecure': 'Insecure',
  'dsec.status.bogus': 'Bogus',
  'dsec.status.indeterminate': 'Indeterminate',
  'dsec.verdict.secure': '{name} {type} is secure: every link from the root trust anchor down to the answer checks out.',
  'dsec.verdict.insecure': '{name} {type} is insecure: the signatures end at {zone}, so everything below it is unsigned — not necessarily wrong, but not protected.',
  'dsec.verdict.bogus': '{name} {type} is bogus: the chain breaks at {zone}. A validating resolver refuses this answer (SERVFAIL).',
  'dsec.verdict.indeterminate': 'The chain of {name} {type} could not be followed to the end: a question at {zone} got no answer.',
  'dsec.reason.anchor-mismatch': 'The root keys match neither IANA trust anchor (KSK-2017, KSK-2024).',
  'dsec.reason.no-dnskey': 'The parent publishes a DS for this zone, but the zone serves no DNSKEY.',
  'dsec.reason.ds-no-match': 'No DNSKEY of the zone matches its DS at the parent (DS key tags {ds}; the zone serves {keys}).',
  'dsec.reason.dnskey-unsigned': 'No key the DS vouches for signs the DNSKEY set.',
  'dsec.reason.no-rrsig': 'The records carry no signature, though the zone is signed.',
  'dsec.reason.no-key': 'The signatures name keys the zone does not publish (key tags {tags}).',
  'dsec.reason.sig-expired': 'The signatures expired on {date}.',
  'dsec.reason.sig-not-yet-valid': 'The signatures are valid only from {date}.',
  'dsec.reason.sig-invalid': 'A signature does not verify: the records differ from what was signed, or another key signed them.',
  'dsec.reason.signer-mismatch': 'A signature names another zone as its signer.',
  'dsec.reason.bad-labels': 'A signature claims more labels than its owner name has.',
  'dsec.reason.unsupported-algorithm': 'Signed with algorithm {alg}, which this browser cannot check: treated as unsigned (RFC 4035 §5.2), not as bogus.',
  'dsec.reason.unsupported-digest': 'The DS uses a digest type this browser cannot check: treated as unsigned.',
  'dsec.reason.no-ds': 'The parent has no DS for this zone, and its signed {kind} record proves it: the delegation is unsigned.',
  'dsec.reason.no-ds-unproven': 'The parent has no DS for this zone; the resolver sent no NSEC or NSEC3 proof, so that is not proven here.',
  'dsec.reason.denial-missing': 'The zone says the answer does not exist but sends no NSEC or NSEC3 proof of it.',
  'dsec.reason.denial-invalid': 'The NSEC or NSEC3 proof does not verify ({sig}).',
  'dsec.reason.nsec3-iterations': 'NSEC3 uses more than {max} hash iterations: not computed, treated as unsigned (RFC 9276).',
  'dsec.reason.opt-out': 'An opt-out NSEC3 covers the name: an unsigned delegation could be there, so the denial is not proven.',
  'dsec.reason.query-failed': 'The question {qname} {qtype} got no answer.',
  'dsec.reason.rcode': 'The resolver answered {qname} {qtype} with {rcode}.',
  'dsec.reason.alias-loop': 'The CNAME chain loops or is longer than {max} hops.',
  'dsec.reason.chain-broken': 'The chain of the alias target is not secure.',
  'dsec.fixTitle': 'What to fix',
  'dsec.fix.anchor-mismatch': 'Check the network: something between this browser and the resolver may be rewriting DNS answers. Try another resolver.',
  'dsec.fix.no-dnskey': 'Sign {zone} again on its name servers, or remove its DS at the registrar if DNSSEC was turned off on purpose.',
  'dsec.fix.ds-no-match': 'After a key rollover the DS at the registrar must follow: publish a DS for the current KSK (key tag {ksk}) and remove the one for {ds}, or put the old key back until the parent has the new DS.',
  'dsec.fix.dnskey-unsigned': 'Sign the DNSKEY set of {zone} with the key the DS names (key tag {ds}).',
  'dsec.fix.no-rrsig': 'Re-sign {zone} and check that its name servers send RRSIG records when asked with the DO bit.',
  'dsec.fix.no-key': 'Publish the signing key again, or re-sign {zone} with the keys it serves.',
  'dsec.fix.sig-expired': 'Re-sign {zone} now and check why the signer stopped (a cron job, a stopped signer, a hidden primary that no longer transfers).',
  'dsec.fix.sig-not-yet-valid': 'Check the clock of the signer: its signatures start in the future.',
  'dsec.fix.sig-invalid': 'Re-sign {zone}: a record was changed after signing, or a name server serves an old copy.',
  'dsec.fix.signer-mismatch': 'Re-sign the records with the keys of {zone}.',
  'dsec.fix.bad-labels': 'Re-sign {zone}: the signer wrote a wrong label count.',
  'dsec.fix.unsupported-algorithm': 'To be checked by every validator, sign with algorithm 13 (ECDSA P-256) or 8 (RSA/SHA-256).',
  'dsec.fix.unsupported-digest': 'Publish a SHA-256 (digest type 2) DS at the registrar.',
  'dsec.fix.no-ds': 'To secure {zone}: sign it, then publish its DS at the registrar.',
  'dsec.fix.no-ds-unproven': 'To secure {zone}: sign it, then publish its DS at the registrar. Validate again through another resolver to see the proof.',
  'dsec.fix.denial-missing': 'Check that the name servers of {zone} send NSEC or NSEC3 records with negative answers when asked with the DO bit.',
  'dsec.fix.denial-invalid': 'Re-sign {zone}: its NSEC or NSEC3 chain is out of date.',
  'dsec.fix.nsec3-iterations': 'Use NSEC3 with 0 extra iterations and no salt (RFC 9276).',
  'dsec.fix.opt-out': 'Usually nothing: opt-out is common in large TLDs. Turn it off if every delegation is signed.',
  'dsec.fix.query-failed': 'Retry; if it keeps failing, choose another resolver in the lookup form.',
  'dsec.fix.rcode': 'A SERVFAIL even with checking disabled usually means the name servers of {zone} do not answer: check them.',
  'dsec.fix.alias-loop': 'Point the CNAME at a name that does not lead back to it.',
  'dsec.fix.chain-broken': 'Fix the chain of the alias target, shown below.',
  'dsec.sig.valid': 'Valid',
  'dsec.sig.expired': 'Expired',
  'dsec.sig.not-yet-valid': 'Not yet valid',
  'dsec.sig.bad-signature': 'Does not verify',
  'dsec.sig.no-key': 'Key not published',
  'dsec.sig.unsupported-algorithm': 'Algorithm not supported',
  'dsec.sig.signer-mismatch': 'Wrong signer',
  'dsec.sig.bad-labels': 'Bad label count',
  'dsec.root': 'Root zone',
  'dsec.ds': 'DS at the parent ({parent})',
  'dsec.anchors': 'Trust anchors (IANA root-anchors.xml)',
  'dsec.keys': 'DNSKEY set',
  'dsec.sigs': 'Signatures (RRSIG {type})',
  'dsec.col.keyTag': 'Key tag',
  'dsec.col.algorithm': 'Algorithm',
  'dsec.col.digest': 'Digest',
  'dsec.col.match': 'Matches',
  'dsec.col.role': 'Role',
  'dsec.col.size': 'Size',
  'dsec.col.validity': 'Valid',
  'dsec.col.result': 'Result',
  'dsec.match.key': 'DNSKEY {tag}',
  'dsec.match.none': 'no key',
  'dsec.match.unchecked': 'not checked',
  'dsec.role.ksk': 'KSK',
  'dsec.role.zsk': 'ZSK',
  'dsec.key.ds': 'matches the DS',
  'dsec.key.signs': 'signs the key set',
  'dsec.key.revoked': 'revoked',
  'dsec.bits': '{bits} bits',
  'dsec.none.sigs': 'No signatures.',
  'dsec.none.keys': 'No DNSKEY records.',
  'dsec.answer': 'The answer: {name} {type}',
  'dsec.answer.records': { one: '{count} record', other: '{count} records' },
  'dsec.answer.nodata': 'No {type} records (NODATA).',
  'dsec.answer.nxdomain': 'The name does not exist (NXDOMAIN).',
  'dsec.answer.unsigned': 'Shown unchecked: {zone} is not signed.',
  'dsec.answer.skipped': 'Not checked: the chain broke above.',
  'dsec.denial.ok': 'Proof of absence: {kind}, signed and checked.',
  'dsec.denial.none': 'No proof of absence was sent.',
  'dsec.denial.bad': 'Proof of absence: {kind}, does not verify.',
  'dsec.denial.optOut': 'Proof of absence: {kind} with opt-out.',
  'dsec.wildcard': 'Expanded from a wildcard (*): the proof that the name itself does not exist was checked.',
  'dsec.alias': 'Alias (CNAME) to {target}: its own chain follows.',
  'dsec.foot': { one: 'Asked {count} question through {resolver} with the DO and CD bits; signatures checked against this browser’s clock at {time}.', other: 'Asked {count} questions through {resolver} with the DO and CD bits; signatures checked against this browser’s clock at {time}.' },
  'dsec.resolverAuto': 'the lookup’s resolver chain'
});

registerStrings('tr', {
  'dsec.title': 'DNSSEC güven zinciri',
  'dsec.intro': 'Kökten aşağı her zone bu tarayıcıda kontrol edilir: üst zone’daki DS kaydı, anahtarları ve onların üzerindeki imzalar, ardından yanıt. Çözümleyici yalnızca kayıtları taşır (DO ve CD bitleri); karar bu tarayıcınındır.',
  'dsec.type': 'Kayıt türü',
  'dsec.run': 'Zinciri doğrula',
  'dsec.rerun': 'Yeniden doğrula',
  'dsec.running': '{zone} kontrol ediliyor…',
  'dsec.status.secure': 'Güvenli',
  'dsec.status.insecure': 'Güvensiz',
  'dsec.status.bogus': 'Bozuk',
  'dsec.status.indeterminate': 'Belirsiz',
  'dsec.verdict.secure': '{name} adının {type} yanıtı güvenli: kök güven çapasından yanıta kadar her halka doğrulandı.',
  'dsec.verdict.insecure': '{name} adının {type} yanıtı güvensiz: imzalar {zone} zone’unda bitiyor, altındaki her şey imzasız — yanlış olmak zorunda değil ama korumasız.',
  'dsec.verdict.bogus': '{name} adının {type} yanıtı bozuk: zincir {zone} zone’unda kırılıyor. Doğrulama yapan bir çözümleyici bu yanıtı reddeder (SERVFAIL).',
  'dsec.verdict.indeterminate': '{name} adının {type} zinciri sonuna kadar izlenemedi: {zone} zone’undaki bir soru yanıtsız kaldı.',
  'dsec.reason.anchor-mismatch': 'Kök anahtarları IANA güven çapalarının (KSK-2017, KSK-2024) hiçbiriyle eşleşmiyor.',
  'dsec.reason.no-dnskey': 'Üst zone bu zone için DS yayımlıyor ama zone hiç DNSKEY sunmuyor.',
  'dsec.reason.ds-no-match': 'Zone’un hiçbir DNSKEY kaydı üst zone’daki DS ile eşleşmiyor (DS anahtar etiketleri: {ds}; zone’un sunduğu: {keys}).',
  'dsec.reason.dnskey-unsigned': 'DS’in onayladığı anahtarlardan hiçbiri DNSKEY kümesini imzalamıyor.',
  'dsec.reason.no-rrsig': 'Zone imzalı olduğu hâlde kayıtlarda imza yok.',
  'dsec.reason.no-key': 'İmzalar zone’un yayımlamadığı anahtarları gösteriyor (anahtar etiketleri: {tags}).',
  'dsec.reason.sig-expired': 'İmzaların süresi {date} tarihinde doldu.',
  'dsec.reason.sig-not-yet-valid': 'İmzalar ancak {date} tarihinden itibaren geçerli.',
  'dsec.reason.sig-invalid': 'Bir imza doğrulanamıyor: kayıtlar imzalanandan farklı ya da onları başka bir anahtar imzalamış.',
  'dsec.reason.signer-mismatch': 'Bir imza, imzalayan olarak başka bir zone’u gösteriyor.',
  'dsec.reason.bad-labels': 'Bir imza, sahibinin adında olandan daha fazla etiket bildiriyor.',
  'dsec.reason.unsupported-algorithm': 'İmza, bu tarayıcının kontrol edemediği {alg} algoritmasıyla atılmış: imzasız sayılır (RFC 4035 §5.2), bozuk sayılmaz.',
  'dsec.reason.unsupported-digest': 'DS, bu tarayıcının kontrol edemediği bir özet türü kullanıyor: imzasız sayılır.',
  'dsec.reason.no-ds': 'Üst zone’da bu zone için DS yok ve imzalı {kind} kaydı bunu kanıtlıyor: yetki devri imzasız.',
  'dsec.reason.no-ds-unproven': 'Üst zone’da bu zone için DS yok; çözümleyici NSEC ya da NSEC3 kanıtı göndermedi, bu yüzden burada kanıtlanamadı.',
  'dsec.reason.denial-missing': 'Zone yanıtın var olmadığını söylüyor ama bunun NSEC ya da NSEC3 kanıtını göndermiyor.',
  'dsec.reason.denial-invalid': 'NSEC ya da NSEC3 kanıtı doğrulanamıyor ({sig}).',
  'dsec.reason.nsec3-iterations': 'NSEC3, {max} karma yinelemesinden fazlasını kullanıyor: hesaplanmadı, imzasız sayılır (RFC 9276).',
  'dsec.reason.opt-out': 'Adı bir opt-out NSEC3 kaydı kapsıyor: orada imzasız bir yetki devri olabilir, bu yüzden yokluk kanıtlanmış sayılmaz.',
  'dsec.reason.query-failed': '{qname} {qtype} sorusu yanıtsız kaldı.',
  'dsec.reason.rcode': 'Çözümleyici {qname} {qtype} sorusunu {rcode} ile yanıtladı.',
  'dsec.reason.alias-loop': 'CNAME zinciri döngüye giriyor ya da {max} adımdan uzun.',
  'dsec.reason.chain-broken': 'Takma adın hedefinin zinciri güvenli değil.',
  'dsec.fixTitle': 'Ne düzeltilmeli',
  'dsec.fix.anchor-mismatch': 'Ağı kontrol edin: bu tarayıcı ile çözümleyici arasında DNS yanıtlarını değiştiren bir şey olabilir. Başka bir çözümleyici deneyin.',
  'dsec.fix.no-dnskey': '{zone} zone’unu ad sunucularında yeniden imzalayın ya da DNSSEC bilerek kapatıldıysa kayıt firmasındaki DS kaydını kaldırın.',
  'dsec.fix.ds-no-match': 'Anahtar değişiminden (rollover) sonra kayıt firmasındaki DS de güncellenmeli: mevcut KSK için (anahtar etiketi {ksk}) bir DS yayımlayın ve {ds} etiketli DS’i kaldırın ya da üst zone yeni DS’i alana kadar eski anahtarı geri koyun.',
  'dsec.fix.dnskey-unsigned': '{zone} zone’unun DNSKEY kümesini DS’in gösterdiği anahtarla (anahtar etiketi {ds}) imzalayın.',
  'dsec.fix.no-rrsig': '{zone} zone’unu yeniden imzalayın ve ad sunucularının DO biti ile sorulduğunda RRSIG kayıtlarını gönderdiğini kontrol edin.',
  'dsec.fix.no-key': 'İmzalayan anahtarı yeniden yayımlayın ya da {zone} zone’unu sunduğu anahtarlarla yeniden imzalayın.',
  'dsec.fix.sig-expired': '{zone} zone’unu hemen yeniden imzalayın ve imzalayıcının neden durduğunu kontrol edin (bir cron görevi, duran bir imzalayıcı, artık aktarım yapmayan gizli bir birincil sunucu).',
  'dsec.fix.sig-not-yet-valid': 'İmzalayıcının saatini kontrol edin: imzaları gelecekte başlıyor.',
  'dsec.fix.sig-invalid': '{zone} zone’unu yeniden imzalayın: bir kayıt imzalandıktan sonra değiştirilmiş ya da bir ad sunucusu eski bir kopyayı sunuyor.',
  'dsec.fix.signer-mismatch': 'Kayıtları {zone} zone’unun anahtarlarıyla yeniden imzalayın.',
  'dsec.fix.bad-labels': '{zone} zone’unu yeniden imzalayın: imzalayıcı yanlış bir etiket sayısı yazmış.',
  'dsec.fix.unsupported-algorithm': 'Her doğrulayıcının kontrol edebilmesi için 13 (ECDSA P-256) ya da 8 (RSA/SHA-256) algoritmasıyla imzalayın.',
  'dsec.fix.unsupported-digest': 'Kayıt firmasında SHA-256 (özet türü 2) bir DS yayımlayın.',
  'dsec.fix.no-ds': '{zone} zone’unu güvenceye almak için önce imzalayın, sonra DS kaydını kayıt firmasında yayımlayın.',
  'dsec.fix.no-ds-unproven': '{zone} zone’unu güvenceye almak için önce imzalayın, sonra DS kaydını kayıt firmasında yayımlayın. Kanıtı görmek için başka bir çözümleyiciyle yeniden doğrulayın.',
  'dsec.fix.denial-missing': '{zone} ad sunucularının DO biti ile sorulduğunda olumsuz yanıtlarla birlikte NSEC ya da NSEC3 kayıtları gönderdiğini kontrol edin.',
  'dsec.fix.denial-invalid': '{zone} zone’unu yeniden imzalayın: NSEC ya da NSEC3 zinciri güncel değil.',
  'dsec.fix.nsec3-iterations': 'NSEC3’ü ek yineleme olmadan (0) ve tuzsuz (salt olmadan) kullanın (RFC 9276).',
  'dsec.fix.opt-out': 'Genellikle bir şey gerekmez: opt-out büyük TLD’lerde yaygındır. Her yetki devri imzalıysa kapatın.',
  'dsec.fix.query-failed': 'Yeniden deneyin; sürekli başarısız olursa sorgu formunda başka bir çözümleyici seçin.',
  'dsec.fix.rcode': 'Doğrulama kapalıyken bile alınan SERVFAIL genellikle {zone} ad sunucularının yanıt vermediği anlamına gelir: onları kontrol edin.',
  'dsec.fix.alias-loop': 'CNAME kaydını kendisine geri dönmeyen bir ada yönlendirin.',
  'dsec.fix.chain-broken': 'Takma ad hedefinin aşağıda gösterilen zincirini düzeltin.',
  'dsec.sig.valid': 'Geçerli',
  'dsec.sig.expired': 'Süresi dolmuş',
  'dsec.sig.not-yet-valid': 'Henüz geçerli değil',
  'dsec.sig.bad-signature': 'Doğrulanamıyor',
  'dsec.sig.no-key': 'Anahtar yayımlanmamış',
  'dsec.sig.unsupported-algorithm': 'Algoritma desteklenmiyor',
  'dsec.sig.signer-mismatch': 'Yanlış imzalayan',
  'dsec.sig.bad-labels': 'Hatalı etiket sayısı',
  'dsec.root': 'Kök zone',
  'dsec.ds': 'Üst zone’daki DS ({parent})',
  'dsec.anchors': 'Güven çapaları (IANA root-anchors.xml)',
  'dsec.keys': 'DNSKEY kümesi',
  'dsec.sigs': 'İmzalar (RRSIG {type})',
  'dsec.col.keyTag': 'Anahtar etiketi',
  'dsec.col.algorithm': 'Algoritma',
  'dsec.col.digest': 'Özet',
  'dsec.col.match': 'Eşleşme',
  'dsec.col.role': 'Rol',
  'dsec.col.size': 'Boyut',
  'dsec.col.validity': 'Geçerlilik',
  'dsec.col.result': 'Sonuç',
  'dsec.match.key': 'DNSKEY {tag}',
  'dsec.match.none': 'anahtar yok',
  'dsec.match.unchecked': 'kontrol edilmedi',
  'dsec.role.ksk': 'KSK',
  'dsec.role.zsk': 'ZSK',
  'dsec.key.ds': 'DS ile eşleşiyor',
  'dsec.key.signs': 'anahtar kümesini imzalıyor',
  'dsec.key.revoked': 'iptal edilmiş',
  'dsec.bits': '{bits} bit',
  'dsec.none.sigs': 'İmza yok.',
  'dsec.none.keys': 'DNSKEY kaydı yok.',
  'dsec.answer': 'Yanıt: {name} {type}',
  'dsec.answer.records': { one: '{count} kayıt', other: '{count} kayıt' },
  'dsec.answer.nodata': '{type} kaydı yok (NODATA).',
  'dsec.answer.nxdomain': 'Bu ad mevcut değil (NXDOMAIN).',
  'dsec.answer.unsigned': 'Kontrol edilmeden gösteriliyor: {zone} imzalı değil.',
  'dsec.answer.skipped': 'Kontrol edilmedi: zincir yukarıda kırıldı.',
  'dsec.denial.ok': 'Yokluk kanıtı: {kind}, imzalı ve doğrulandı.',
  'dsec.denial.none': 'Yokluk kanıtı gönderilmedi.',
  'dsec.denial.bad': 'Yokluk kanıtı: {kind}, doğrulanamıyor.',
  'dsec.denial.optOut': 'Yokluk kanıtı: opt-out ile {kind}.',
  'dsec.wildcard': 'Bir Wildcard (*) kaydından üretildi: adın kendisinin var olmadığına dair kanıt kontrol edildi.',
  'dsec.alias': '{target} adına takma ad (CNAME): onun zinciri aşağıda.',
  'dsec.foot': { one: '{resolver} üzerinden DO ve CD bitleriyle {count} soru soruldu; imzalar {time} itibarıyla bu tarayıcının saatine göre kontrol edildi.', other: '{resolver} üzerinden DO ve CD bitleriyle {count} soru soruldu; imzalar {time} itibarıyla bu tarayıcının saatine göre kontrol edildi.' },
  'dsec.resolverAuto': 'sorgunun çözümleyici zinciri'
});

/**
 * Every key this module builds from a code (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...DNSSEC_STATUSES.flatMap((s) => [`dsec.status.${s}`, `dsec.verdict.${s}`]),
    ...DNSSEC_REASONS.flatMap((r) => [`dsec.reason.${r}`, `dsec.fix.${r}`]),
    ...SIG_RESULTS.map((r) => `dsec.sig.${r}`),
    'dsec.role.ksk', 'dsec.role.zsk'
  ];
}

const algText = (n) => (DNSSEC_ALGORITHMS[n] ? `${n} · ${DNSSEC_ALGORITHMS[n]}` : String(n));
const digestText = (n) => (DS_DIGEST_TYPES[n] ? `${n} · ${DS_DIGEST_TYPES[n]}` : String(n));
const day = (ms) => (Number.isFinite(ms) ? formatDate(new Date(ms), { utc: true }) : '—');
const stamp = (ms) => (Number.isFinite(ms) ? formatDateTime(new Date(ms), { utc: true }) : '—');
const tags = (list) => [...new Set(list)].join(', ') || '—';

function statusBadge(t, status) {
  return Badge(t(`dsec.status.${status}`), { variant: STATUS_VARIANT[status] || 'neutral', icon: STATUS_ICON[status] || null, className: 'dsec-status' });
}

function table(headers, rows, className) {
  return h('div', { class: ['dt-scroll', 'dt-scroll-free', 'dsec-table', className], attrs: { tabindex: 0 } },
    h('table', { class: 'dt-table dt-dense' },
      h('thead', null, h('tr', null, headers.map((x) => h('th', { attrs: { scope: 'col' } }, x)))),
      h('tbody', null, rows.map((cells) => h('tr', { class: 'dt-row' }, cells.map((c) => h('td', null, c ?? '—')))))));
}

/** The step (zone or answer) where the chain first stops being secure. */
function breakStep(result) {
  if (!result.breakAt) return null;
  if (result.breakAt === 'answer') return result.answer;
  return result.zones.find((z) => z.zone === result.breakAt) || null;
}

/** The deepest failing alias result (a CNAME target's chain), or the result itself. */
function rootCause(result) {
  let r = result;
  while (r.reason === 'chain-broken' && r.answer && r.answer.alias) r = r.answer.alias.result;
  return r;
}

/**
 * Words for a reason: the params of `dsec.reason.<code>` and `dsec.fix.<code>`.
 * @param {object} step ZoneStep or AnswerStep
 * @param {string} zone
 * @param {Function} t
 */
function reasonParams(step, zone, t) {
  const sigs = [...(step.keySigs || []), ...(step.dsSigs || []), ...(step.sigs || [])];
  const firstOf = (r) => sigs.find((s) => s.result === r);
  // The key the zone signs its key set with (what a new DS must name), else its KSKs.
  const signing = (step.keys || []).filter((k) => k.signsKeys).map((k) => k.keyTag);
  const ksk = signing.length ? signing : (step.keys || []).filter((k) => k.role === 'ksk').map((k) => k.keyTag);
  const f = step.failure || {};
  const d = step.denial || {};
  return {
    zone,
    ds: tags((step.ds || []).map((x) => x.keyTag)),
    keys: tags((step.keys || []).map((k) => k.keyTag)),
    ksk: tags(ksk.length ? ksk : (step.keys || []).map((k) => k.keyTag)),
    tags: tags(sigs.filter((s) => s.result === 'no-key').map((s) => s.keyTag)),
    date: stamp((firstOf('expired') || {}).expiration ?? (firstOf('not-yet-valid') || {}).inception),
    alg: tags([...(step.ds || []).map((x) => x.algorithm), ...sigs.map((s) => s.algorithm)].map(algText)),
    kind: d.kind === 'nsec3' ? (d.optOut ? 'NSEC3 (opt-out)' : 'NSEC3') : 'NSEC',
    sig: t(`dsec.sig.${d.sigResult || 'bad-signature'}`),
    max: formatNumber(step.reason === 'alias-loop' ? MAX_ALIASES : MAX_NSEC3_ITERATIONS),
    qname: f.qname || zone,
    qtype: f.qtype || '',
    rcode: f.rcode || ''
  };
}

/**
 * The DNSSEC chain panel of one lookup.
 * @param {{ ctx: object, name: string, types: string[], resolver?: string|null }} opts
 * @returns {{ el: HTMLElement, run: (opts?: { noCache?: boolean }) => Promise<void>, destroy: () => void }}
 */
export function DnssecPanel({ ctx, name, types, resolver = null }) {
  const { t } = ctx;
  let controller = null;
  let destroyed = false;
  const offered = [...new Set(types.length ? types : ['A'])];
  const typeField = select({
    label: t('dsec.type'), size: 'sm', value: offered[0], className: 'dsec-type',
    options: offered.map((x) => ({ value: x, label: x })), onChange: () => run()
  });
  const runBtn = Button({ label: t('dsec.rerun'), icon: 'refresh', size: 'sm', variant: 'secondary', dataset: { action: 'dnssec-run' }, onClick: () => run({ noCache: true }) });
  const body = h('div', { class: 'dsec-body stack', attrs: { 'aria-live': 'polite' } });
  const el = h('section', { class: 'card dsec-panel', dataset: { name }, attrs: { 'aria-label': t('dsec.title') } },
    h('div', { class: 'dsec-head cluster' },
      h('h2', { class: 'dsec-title' }, t('dsec.title')),
      h('span', { class: 'dsec-name mono' }, name),
      h('div', { class: 'dsec-controls cluster' }, typeField.el, runBtn)),
    h('p', { class: 'dsec-intro muted text-sm' }, t('dsec.intro')),
    body);

  const resolverLabel = () => {
    if (!resolver) return t('dsec.resolverAuto');
    const r = getResolver(resolver);
    return r ? r.name : resolver;
  };

  function sigTable(checks, type) {
    if (!checks.length) return h('p', { class: 'dsec-none muted text-sm' }, t('dsec.none.sigs'));
    return h('div', { class: 'dsec-sigs' },
      h('h4', { class: 'dsec-sub' }, t('dsec.sigs', { type })),
      table([t('dsec.col.keyTag'), t('dsec.col.algorithm'), t('dsec.col.validity'), t('dsec.col.result')], checks.map((c) => [
        h('span', { class: 'mono num' }, String(c.keyTag)),
        algText(c.algorithm),
        h('span', { class: 'dsec-window', title: `${stamp(c.inception)} → ${stamp(c.expiration)}` }, `${day(c.inception)} → ${day(c.expiration)}`),
        h('span', { class: 'dsec-sig', dataset: { result: c.result } },
          Badge(t(`dsec.sig.${c.result}`), { variant: SIG_VARIANT[c.result] || 'error' }))
      ]), 'dsec-sig-table'));
  }

  function dsTable(z) {
    const rows = z.ds.map((d) => [
      h('span', { class: 'mono num' }, String(d.keyTag)),
      algText(d.algorithm),
      digestText(d.digestType),
      d.matches !== null && d.matches !== undefined
        ? Badge(t('dsec.match.key', { tag: d.matches }), { variant: 'ok', icon: 'check' })
        : Badge(t(d.supported && z.keys.length ? 'dsec.match.none' : 'dsec.match.unchecked'), { variant: d.supported && z.keys.length ? 'error' : 'neutral' })
    ]);
    return h('div', { class: 'dsec-ds' },
      h('h4', { class: 'dsec-sub' }, z.dsSource === 'anchor' ? t('dsec.anchors') : t('dsec.ds', { parent: z.parent || '.' })),
      table([t('dsec.col.keyTag'), t('dsec.col.algorithm'), t('dsec.col.digest'), t('dsec.col.match')], rows, 'dsec-ds-table'),
      z.dsSource === 'parent' && z.dsSigs.length ? sigTable(z.dsSigs, 'DS') : null);
  }

  function keyTable(z) {
    if (!z.keys.length) return h('p', { class: 'dsec-none muted text-sm' }, t('dsec.none.keys'));
    return h('div', { class: 'dsec-keys' },
      h('h4', { class: 'dsec-sub' }, t('dsec.keys')),
      table([t('dsec.col.keyTag'), t('dsec.col.role'), t('dsec.col.algorithm'), t('dsec.col.size')], z.keys.map((k) => [
        h('span', { class: 'mono num' }, String(k.keyTag)),
        h('span', { class: 'dsec-role cluster' },
          Badge(t(`dsec.role.${k.role}`), { variant: k.role === 'ksk' ? 'accent' : 'neutral', mono: true }),
          k.matchesDs ? Badge(t('dsec.key.ds'), { variant: 'ok' }) : null,
          k.signsKeys ? Badge(t('dsec.key.signs'), { variant: 'ok' }) : null,
          k.revoked ? Badge(t('dsec.key.revoked'), { variant: 'warn' }) : null),
        algText(k.algorithm),
        k.bits ? t('dsec.bits', { bits: formatNumber(k.bits) }) : null
      ]), 'dsec-key-table'),
      sigTable(z.keySigs, 'DNSKEY'));
  }

  function denialText(d) {
    if (!d || !d.kind) return t('dsec.denial.none');
    const kind = d.kind === 'nsec3' ? 'NSEC3' : 'NSEC';
    if (!d.signed) return t('dsec.denial.bad', { kind });
    if (d.optOut) return t('dsec.denial.optOut', { kind });
    return t('dsec.denial.ok', { kind });
  }

  function zoneCard(z) {
    const showKeys = z.keys.length || (z.ds.length && z.status !== 'indeterminate');
    return h('li', { class: ['dsec-zone', `dsec-${z.status}`], dataset: { zone: z.zone, status: z.status, reason: z.reason || '' } },
      h('div', { class: 'dsec-zone-head cluster' },
        h('span', { class: 'dsec-zone-name mono' }, z.zone === '.' ? '.' : z.zone),
        z.zone === '.' ? h('span', { class: 'muted text-sm' }, t('dsec.root')) : null,
        statusBadge(t, z.status)),
      z.status !== 'secure' && z.reason ? h('p', { class: 'dsec-zone-reason text-sm' }, t(`dsec.reason.${z.reason}`, reasonParams(z, z.zone, t))) : null,
      z.ds.length ? dsTable(z) : null,
      z.denial && z.status !== 'secure' ? h('p', { class: 'dsec-denial muted text-sm' }, denialText(z.denial)) : null,
      showKeys ? keyTable(z) : null);
  }

  function answerCard(result) {
    const a = result.answer;
    const head = h('div', { class: 'dsec-zone-head cluster' },
      h('span', { class: 'dsec-zone-name mono' }, t('dsec.answer', { name: result.name, type: result.type })),
      a ? statusBadge(t, a.status) : null);
    if (!a) return h('li', { class: 'dsec-zone dsec-answer dsec-skipped', dataset: { zone: 'answer', status: 'skipped' } }, head, h('p', { class: 'muted text-sm' }, t('dsec.answer.skipped')));
    const lines = [];
    if (a.records.length) {
      lines.push(h('p', { class: 'text-sm' }, t('dsec.answer.records', { count: a.records.length })),
        h('ul', { class: 'dsec-records mono text-sm' }, a.records.slice(0, 12).map((rr) => h('li', null, `${rr.type} ${rr.text ?? ''}`))));
    } else if (a.rcode === 'NXDOMAIN') lines.push(h('p', { class: 'text-sm' }, t('dsec.answer.nxdomain')));
    else if (a.rcode === 'NOERROR') lines.push(h('p', { class: 'text-sm' }, t('dsec.answer.nodata', { type: result.type })));
    const unsigned = result.status === 'insecure' && result.breakAt !== 'answer' && a.status === 'insecure';
    if (unsigned) lines.push(h('p', { class: 'muted text-sm' }, t('dsec.answer.unsigned', { zone: result.breakAt })));
    else if (a.status !== 'secure' && a.reason && a.reason !== 'chain-broken') lines.push(h('p', { class: 'dsec-zone-reason text-sm' }, t(`dsec.reason.${a.reason}`, reasonParams(a, a.zone || result.name, t))));
    if (!unsigned && a.sigs.length) lines.push(sigTable(a.sigs, a.records[0] ? a.records[0].type : result.type));
    if (!unsigned && !a.records.length && a.rcode) lines.push(h('p', { class: 'dsec-denial muted text-sm' }, denialText(a.denial)));
    if (a.wildcard) lines.push(h('p', { class: 'muted text-sm' }, t('dsec.wildcard')));
    const card = h('li', { class: ['dsec-zone', 'dsec-answer', `dsec-${a.status}`], dataset: { zone: 'answer', status: a.status, reason: a.reason || '' } }, head, ...lines);
    if (a.alias) {
      card.append(h('div', { class: 'dsec-alias' },
        h('p', { class: 'text-sm' }, t('dsec.alias', { target: a.alias.target })),
        chainList(a.alias.result)));
    }
    return card;
  }

  function chainList(result) {
    return h('ol', { class: 'dsec-chain' }, result.zones.map(zoneCard), answerCard(result));
  }

  function verdict(result) {
    const cause = rootCause(result);
    const step = breakStep(cause);
    const zone = cause.breakAt === 'answer' ? (cause.answer && cause.answer.zone) || cause.name : cause.breakAt || '.';
    const params = step ? reasonParams(step, zone, t) : { zone };
    const children = [h('p', { class: 'dsec-verdict-text' }, t(`dsec.verdict.${result.status}`, { name: result.name, type: result.type, zone }))];
    if (step && cause.reason) {
      children.push(h('p', { class: 'dsec-reason', dataset: { reason: cause.reason } }, t(`dsec.reason.${cause.reason}`, params)));
      children.push(h('p', { class: 'dsec-fix' }, h('strong', null, `${t('dsec.fixTitle')}: `), t(`dsec.fix.${cause.reason}`, params)));
    }
    const failure = step && step.failure;
    let retry = null;
    if (failure) {
      const st = dohStatus({ ...failure, ok: false });
      if (st) children.push(h('p', { class: 'dsec-na text-sm' }, `⚠ ${statusText(st)}`));
      retry = RetryButton({ sources: ['doh'], target: `${result.name} ${result.type}`, onClick: () => run({ noCache: true }) });
    }
    return h('div', { class: ['dsec-verdict', `dsec-${result.status}`], dataset: { status: result.status, reason: cause.reason || '', breakAt: cause.breakAt || '' } },
      h('div', { class: 'dsec-verdict-head cluster' }, statusBadge(t, result.status), retry),
      ...children);
  }

  function render(result) {
    clear(body);
    body.append(verdict(result), chainList(result),
      h('p', { class: 'dsec-foot muted text-xs' }, t('dsec.foot', { count: result.queries, resolver: resolverLabel(), time: stamp(result.at) })));
    announce(t(`dsec.verdict.${result.status}`, { name: result.name, type: result.type, zone: result.breakAt === 'answer' ? result.name : result.breakAt || '.' }));
  }

  /**
   * Validate the chain of the selected type (the panel's own Retry and "Validate again" skip the cache).
   * @param {{ noCache?: boolean }} [opts]
   */
  async function run({ noCache = false } = {}) {
    if (destroyed) return;
    if (controller) controller.abort();
    if (!ctx.requireOnline()) return;
    controller = new AbortController();
    const mine = controller;
    const type = typeField.input ? typeField.input.value : offered[0];
    const progress = h('span', { class: 'dsec-progress text-sm' }, t('dsec.running', { zone: '.' }));
    clear(body);
    body.append(h('div', { class: 'dsec-running cluster' }, Spinner({ size: 'sm' }), progress));
    runBtn.setAttribute('aria-busy', 'true');
    el.dataset.state = 'running';
    try {
      const dns = await ctx.getDns();
      const result = await validateChain(name, type, {
        dns, signal: mergeSignals(ctx.signal, mine.signal), resolver: resolver || undefined, noCache,
        onProgress: ({ zone }) => { progress.textContent = t('dsec.running', { zone }); }
      });
      if (destroyed || controller !== mine) return;
      render(result);
      el.dataset.state = 'done';
      el.dataset.status = result.status;
    } catch (err) {
      if (err && err.name === 'AbortError') return;
      if (destroyed || controller !== mine) return;
      clear(body);
      body.append(Alert({ variant: 'error', compact: true, message: `${t('error.title')}: ${err && err.message ? err.message : String(err)}` }));
      el.dataset.state = 'error';
    } finally {
      if (controller === mine) {
        controller = null;
        runBtn.removeAttribute('aria-busy');
      }
    }
  }

  function destroy() {
    destroyed = true;
    if (controller) controller.abort();
    controller = null;
    el.remove();
  }

  return { el, run, destroy };
}
