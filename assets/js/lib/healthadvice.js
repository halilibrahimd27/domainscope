/**
 * healthadvice.js — what to do about each Domain Health problem (SPEC §5.78): one short line of
 * advice, in English and Turkish, for every error or warning check that has no "Show the fix"
 * (lib/fixes.js HEALTH_FIX_IDS: those show the records that fix them instead). The "problems
 * first" list of ui/health-v2.js shows it under the check. Keys: `hadv.<check id>`.
 * DOM-free; runs in browsers and Node 22.
 */

// [check id, en, tr]
const ADVICE = [
  // DNS
  ['domain.nxdomain', 'Register or renew the domain, or check its spelling: nothing else works until the name exists.',
    'Alan adını kaydedin ya da yenileyin veya yazımını kontrol edin: ad var olmadan başka hiçbir şey çalışmaz.'],
  ['domain.dangling-cname', 'Remove the CNAME or recreate its target, before someone else claims the target.',
    'CNAME kaydını kaldırın ya da hedefini yeniden oluşturun; hedefi başkası üstlenmeden önce.'],
  ['domain.name-missing', 'Add the name to its zone (an A, AAAA or CNAME record), or stop using it.',
    'Adı zone’a ekleyin (A, AAAA ya da CNAME kaydı) ya da kullanmayı bırakın.'],
  ['soa.error', 'Run the check again; if it keeps failing, ask your DNS provider why the name servers do not answer for SOA.',
    'Kontrolü yeniden çalıştırın; hata sürerse ad sunucularının SOA sorgusuna neden yanıt vermediğini DNS sağlayıcınıza sorun.'],
  ['soa.not-apex', 'Run the check on the zone apex for the NS, SOA and DNSSEC results; the email checks here are this name’s own.',
    'NS, SOA ve DNSSEC sonuçları için kontrolü zone’un tepesinde (apex) çalıştırın; buradaki e-posta kontrolleri bu adın kendisine aittir.'],
  ['soa.zone-unknown', 'Make sure the parent zone is delegated and answers, then run the check on the zone apex.',
    'Üst zone’un yetkilendirildiğinden ve yanıt verdiğinden emin olun; ardından kontrolü zone’un tepesinde çalıştırın.'],
  ['soa.retry', 'Set the SOA retry below its refresh (for example refresh 3600, retry 900).',
    'SOA retry değerini refresh değerinin altına çekin (örneğin refresh 3600, retry 900).'],
  ['soa.expire', 'Raise the SOA expire to at least 604800 seconds (one week; 1209600 is common).',
    'SOA expire değerini en az 604800 saniyeye (bir hafta; yaygın değer 1209600) yükseltin.'],
  ['ns.error', 'Run the check again; if NS lookups keep failing, the delegation or the name servers are down: contact your DNS provider.',
    'Kontrolü yeniden çalıştırın; NS sorguları başarısız olmaya devam ederse yetkilendirme ya da ad sunucuları çalışmıyordur: DNS sağlayıcınızla görüşün.'],
  ['ns.none', 'Publish NS records in the zone that match the delegation at your registrar.',
    'Zone’da, kayıt firmanızdaki yetkilendirmeyle aynı NS kayıtlarını yayınlayın.'],
  ['ns.single', 'Add a second name server, ideally on another network (RFC 2182 asks for at least two).',
    'İkinci bir ad sunucusu ekleyin, tercihen başka bir ağda (RFC 2182 en az iki tane ister).'],
  ['ns.unresolvable', 'Fix or remove the name servers that have no address, at the registrar and in the zone.',
    'Adresi olmayan ad sunucularını kayıt firmasında ve zone’da düzeltin ya da kaldırın.'],
  ['ns.private-ip', 'Give the name servers public addresses: private ones cannot be reached from the Internet.',
    'Ad sunucularına genel adresler verin: özel adreslere İnternet’ten ulaşılamaz.'],
  ['ns.same-subnet', 'Spread the name servers over different networks, so that one outage cannot take them all down.',
    'Ad sunucularını farklı ağlara dağıtın; tek bir kesinti hepsini birden düşürmesin.'],
  ['ns.rdap-mismatch', 'Make the name servers at the registrar and the NS records in the zone the same list.',
    'Kayıt firmasındaki ad sunucularıyla zone’daki NS kayıtlarını aynı liste yapın.'],
  ['apex.private-ip', 'Publish public addresses in public DNS, and keep internal ones in an internal zone.',
    'Genel DNS’te genel adresler yayınlayın; iç adresleri iç bir zone’da tutun.'],
  // Email
  ['mx.error', 'Run the check again; if MX lookups keep failing, ask your DNS provider.',
    'Kontrolü yeniden çalıştırın; MX sorguları başarısız olmaya devam ederse DNS sağlayıcınıza sorun.'],
  ['mx.ip-literal', 'Point MX at a host name with A / AAAA records, never at an IP address.',
    'MX kaydını IP adresine değil, A / AAAA kaydı olan bir host adına yönlendirin.'],
  ['mx.unresolvable', 'Fix the MX host names (a typo, a deleted host) or remove those MX records: mail to them bounces.',
    'MX host adlarını düzeltin (yazım hatası, silinmiş host) ya da bu MX kayıtlarını kaldırın: onlara giden e-postalar geri döner.'],
  ['mx.cname', 'Point MX at the canonical host name (the CNAME’s target), not at an alias.',
    'MX kaydını takma ada değil, CNAME’in hedefi olan asıl host adına yönlendirin.'],
  ['mx.private-ip', 'Give the MX hosts public addresses, or remove them from public DNS.',
    'MX hostlarına genel adresler verin ya da onları genel DNS’ten kaldırın.'],
  ['mail-identity.fcrdns-missing', 'Ask whoever runs the server’s addresses (your host or ISP) for a PTR record whose name resolves back to the address.',
    'Sunucunun adreslerini yöneten taraftan (barındırma firmanız ya da İSS) adı aynı adrese geri çözülen bir PTR kaydı isteyin.'],
  ['mail-identity.fcrdns-mismatch', 'Make the PTR name and its A / AAAA record point at each other: change the PTR, or add the address to that name.',
    'PTR adıyla A / AAAA kaydının birbirini göstermesini sağlayın: PTR’ı değiştirin ya da adresi o ada ekleyin.'],
  ['spf.error', 'Run the check again; if the TXT lookup keeps failing, ask your DNS provider.',
    'Kontrolü yeniden çalıştırın; TXT sorgusu başarısız olmaya devam ederse DNS sağlayıcınıza sorun.'],
  ['spf.syntax', 'Correct or remove the invalid terms: receivers ignore an SPF record they cannot parse.',
    'Geçersiz terimleri düzeltin ya da kaldırın: alıcılar çözümleyemedikleri SPF kaydını yok sayar.'],
  ['spf.include-error', 'Fix or remove the include or redirect whose target has no single valid SPF record.',
    'Hedefinde tek ve geçerli bir SPF kaydı bulunmayan include ya da redirect terimini düzeltin veya kaldırın.'],
  ['spf.dns-error', 'Run the check again; if the included names keep failing, fix or remove them.',
    'Kontrolü yeniden çalıştırın; dahil edilen adlar başarısız olmaya devam ederse onları düzeltin ya da kaldırın.'],
  ['spf.void', 'Remove the include, a, mx and exists terms that point to names without records.',
    'Kaydı olmayan adlara işaret eden include, a, mx ve exists terimlerini kaldırın.'],
  ['spf.too-long', 'Shorten the record: drop unused includes or merge ranges.',
    'Kaydı kısaltın: kullanılmayan include terimlerini çıkarın ya da aralıkları birleştirin.'],
  ['spf.broad', 'Replace the huge ranges with your senders’ own addresses or the include they publish.',
    'Çok geniş aralıkları gönderen sunucularınızın kendi adresleriyle ya da yayınladıkları include ile değiştirin.'],
  ['spf.nested-pass', 'Fix the policy that ends in +all, or stop referencing it, and end your own record with -all or ~all.',
    '+all ile biten politikayı düzeltin ya da ona başvurmayı bırakın; kendi kaydınızı -all veya ~all ile bitirin.'],
  ['spf.nested-neutral', 'End the referenced policy, or your own record, with -all or ~all.',
    'Başvurulan politikayı ya da kendi kaydınızı -all veya ~all ile bitirin.'],
  ['dmarc.error', 'Run the check again; if the _dmarc lookup keeps failing, ask your DNS provider.',
    'Kontrolü yeniden çalıştırın; _dmarc sorgusu başarısız olmaya devam ederse DNS sağlayıcınıza sorun.'],
  ['dmarc.invalid', 'Rewrite the record as “v=DMARC1; p=none; rua=mailto:…” (or p=quarantine / reject) and fix the problems listed.',
    'Kaydı “v=DMARC1; p=none; rua=mailto:…” (ya da p=quarantine / reject) biçiminde yeniden yazın ve listelenen sorunları giderin.'],
  ['dmarc.rua-unauthorized', 'Ask each report domain to publish a _report._dmarc authorization record for your domain, or send reports to an address in your own domain.',
    'Her rapor alan adından alan adınız için bir _report._dmarc yetki kaydı yayınlamasını isteyin ya da raporları kendi alan adınızdaki bir adrese gönderin.'],
  ['dmarc.testing', 'Remove t=y once the reports show that every legitimate sender passes.',
    'Raporlar tüm meşru gönderenlerin geçtiğini gösterdiğinde t=y etiketini kaldırın.'],
  ['dkim.weak', 'Generate a 2048-bit key at the sending service, publish it under a new selector and retire the old one.',
    'Gönderim hizmetinde 2048 bitlik bir anahtar oluşturun, yeni bir seçicide yayınlayın ve eskisini kaldırın.'],
  ['mta-sts.invalid', 'Keep exactly one record: “v=STSv1; id=” followed by 1–32 letters and digits (a new id with every policy change).',
    'Tek bir kayıt bırakın: “v=STSv1; id=” ve ardından 1–32 harf ve rakam (politika her değiştiğinde yeni bir id).'],
  ['tls-rpt.invalid', 'Keep exactly one record: “v=TLSRPTv1; rua=mailto:…” with an address that reads the reports.',
    'Tek bir kayıt bırakın: raporları okuyan bir adresle “v=TLSRPTv1; rua=mailto:…”.'],
  ['bimi.dmarc-weak', 'Move DMARC to p=quarantine or p=reject (at pct=100) before relying on BIMI.',
    'BIMI’ye güvenmeden önce DMARC’ı p=quarantine ya da p=reject (pct=100) düzeyine yükseltin.'],
  // Certificates and DNSSEC
  ['caa.error', 'Run the check again; if CAA lookups keep failing, your DNS provider must fix them, or CAs refuse to issue.',
    'Kontrolü yeniden çalıştırın; CAA sorguları başarısız olmaya devam ederse DNS sağlayıcınız bunu düzeltmelidir, yoksa CA’lar sertifika vermez.'],
  ['caa.invalid', 'Correct the values to the CA’s documented CAA domain (for example letsencrypt.org) or remove them.',
    'Değerleri CA’nın belgelediği CAA alan adıyla (örneğin letsencrypt.org) düzeltin ya da kaldırın.'],
  ['caa.unsatisfiable', 'Fix or remove the accounturi and validationmethods parameters, so that the value authorizes its CA.',
    'accounturi ve validationmethods parametrelerini düzeltin ya da kaldırın; değer CA’sına gerçekten izin versin.'],
  ['caa.deny-all', 'If the domain needs certificates, add an issue record for your CA; keep the empty set only on names that must never have one.',
    'Alan adının sertifikaya ihtiyacı varsa CA’nız için bir issue kaydı ekleyin; boş kümeyi yalnızca hiç sertifika almaması gereken adlarda tutun.'],
  ['caa.distrusted', 'Remove the distrusted CA from CAA and move your certificates to a trusted CA.',
    'Güvenilmeyen CA’yı CAA’dan çıkarın ve sertifikalarınızı güvenilen bir CA’ya taşıyın.'],
  ['caa.cert-blocked', 'Add an issue (or issuewild) record for the CA you renew with, before the next renewal.',
    'Bir sonraki yenilemeden önce yenileme yaptığınız CA için bir issue (ya da issuewild) kaydı ekleyin.'],
  ['caa.cert-unusable', 'Correct the malformed value for this CA, so that it authorizes the renewal.',
    'Bu CA için hatalı değeri düzeltin; değer yenilemeye izin versin.'],
  ['dnssec.error', 'Run the check again; if DS / DNSKEY lookups keep failing, ask your DNS provider.',
    'Kontrolü yeniden çalıştırın; DS / DNSKEY sorguları başarısız olmaya devam ederse DNS sağlayıcınıza sorun.'],
  ['dnssec.broken', 'Urgent: re-sign the zone, or remove the DS record at the registrar until the zone is signed correctly.',
    'Acil: zone’u yeniden imzalayın ya da zone doğru imzalanana kadar kayıt firmasındaki DS kaydını kaldırın.'],
  ['dnssec.ds-mismatch', 'Update the DS record at the registrar to the zone’s current key-signing key.',
    'Kayıt firmasındaki DS kaydını zone’un güncel anahtar imzalama anahtarına (KSK) göre güncelleyin.'],
  ['dnssec.ds-no-dnskey', 'Sign the zone again, or remove the DS record at the registrar.',
    'Zone’u yeniden imzalayın ya da kayıt firmasındaki DS kaydını kaldırın.'],
  ['dnssec.no-ds', 'Add the DS record your DNS provider shows at your registrar, or stop signing the zone.',
    'DNS sağlayıcınızın gösterdiği DS kaydını kayıt firmanıza ekleyin ya da zone’u imzalamayı bırakın.'],
  ['dnssec.not-validated', 'Check the RRSIG expiry dates and the chain of keys from the DS down.',
    'RRSIG bitiş tarihlerini ve DS’ten aşağı anahtar zincirini kontrol edin.'],
  ['dnssec.algorithm-deprecated', 'Roll the keys over to algorithm 13 (ECDSAP256SHA256) or 15 (ED25519).',
    'Anahtarları algoritma 13 (ECDSAP256SHA256) ya da 15 (ED25519) ile değiştirin.'],
  // Registration
  ['rdap.expired', 'Renew the domain at the registrar now: it may still be in its grace period.',
    'Alan adını hemen kayıt firmasında yenileyin: hâlâ ek süre (grace period) içinde olabilir.'],
  ['rdap.expiring', 'Renew now and turn on auto-renew at the registrar.',
    'Hemen yenileyin ve kayıt firmasında otomatik yenilemeyi açın.'],
  ['rdap.expiring-soon', 'Renew, or make sure auto-renew is on and the payment method is valid.',
    'Yenileyin ya da otomatik yenilemenin açık ve ödeme yönteminin geçerli olduğundan emin olun.'],
  ['rdap.hold', 'Contact the registrar: a hold usually means an unpaid renewal, a pending verification or a dispute.',
    'Kayıt firmasıyla görüşün: askıya alma genellikle ödenmemiş bir yenileme, bekleyen bir doğrulama ya da bir anlaşmazlık demektir.'],
  ['rdap.pending-delete', 'Ask the registrar to restore the domain (redemption) before it is released.',
    'Alan adı serbest bırakılmadan önce kayıt firmasından geri yüklemesini (redemption) isteyin.'],
  ['rdap.not-found', 'Check the spelling; if the domain is yours, ask the registrar why the registry has no record of it.',
    'Yazımı kontrol edin; alan adı sizinse kayıt kuruluşunda neden kaydı olmadığını kayıt firmanıza sorun.'],
  // Web
  ['www.missing', 'Add www as a CNAME of the bare domain (or with the same A / AAAA records), and redirect one to the other.',
    'www adını çıplak alan adının CNAME’i olarak (ya da aynı A / AAAA kayıtlarıyla) ekleyin ve birini diğerine yönlendirin.'],
  ['www.apex-missing', 'Give the bare domain an address (A / AAAA, or your provider’s ALIAS / ANAME) that redirects to www.',
    'Çıplak alan adına, www adına yönlendiren bir adres verin (A / AAAA ya da sağlayıcınızın ALIAS / ANAME kaydı).'],
  ['www.dangling', 'Remove the www CNAME or recreate its target now: a dangling alias can be taken over.',
    'www CNAME kaydını kaldırın ya da hedefini hemen yeniden oluşturun: sahipsiz bir takma ad ele geçirilebilir.'],
  ['www.private-ip', 'Publish public addresses for www in public DNS, and keep internal ones in an internal zone.',
    'Genel DNS’te www için genel adresler yayınlayın; iç adresleri iç bir zone’da tutun.'],
  ['observatory.grade', 'Open the full report for the failing tests; most grades rise with HSTS, a Content-Security-Policy and “X-Content-Type-Options: nosniff”.',
    'Başarısız testler için tam raporu açın; not çoğunlukla HSTS, bir Content-Security-Policy ve “X-Content-Type-Options: nosniff” ile yükselir.']
];

/** Check ids with a line of advice. */
export const HEALTH_ADVICE_IDS = Object.freeze(ADVICE.map(([id]) => id));

/** English and Turkish advice, `hadv.<check id>` (the view registers them). */
export const HEALTH_ADVICE_I18N = Object.freeze({
  en: Object.freeze(Object.fromEntries(ADVICE.map(([id, en]) => [`hadv.${id}`, en]))),
  tr: Object.freeze(Object.fromEntries(ADVICE.map(([id, , tr]) => [`hadv.${id}`, tr])))
});

/**
 * The i18n key of a check's advice, or null when it has none.
 * @param {string} id
 * @returns {string|null}
 */
export function adviceKey(id) {
  return HEALTH_ADVICE_IDS.includes(id) ? `hadv.${id}` : null;
}
