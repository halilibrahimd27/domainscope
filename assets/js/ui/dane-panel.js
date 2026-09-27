/**
 * ui/dane-panel.js — the "DANE / TLSA" check: will the new certificate break DANE?
 *
 * Used by the Certificate view (a tab of its own) and by SSL Targets (a tab after the scan, which
 * also checks the concrete hosts the scan found under the certificate's wildcard names). The logic
 * is lib/dane.js; this module only renders it.
 *
 * - Nothing is sent until "Check TLSA records" is clicked: then MX and TLSA queries (names only,
 *   with the DNSSEC OK bit) go to the DoH resolvers of the settings. The certificate never leaves
 *   the browser; its TLSA values below the table are computed locally.
 * - The job lives on a holder object owned by the host view (`holder.dane`: one per certificate
 *   in the Certificate view, the scan run in SSL Targets), so a result survives navigation and
 *   language re-mounts, and a check keeps running while another view is open.
 * - Every string is rendered through h() / text nodes: MX host names and TLSA data are DNS data.
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, DataTable, Disclosure, EmptyState, ErrorBanner, Icon, KeyValueList, ProgressBar,
  TruncatedList, toast
} from './components.js';
import { downloadText, timestampedName } from './download.js';
import { t, registerStrings, formatNumber, formatDateTime } from '../i18n.js';
import { toCsv, toJson } from '../lib/export.js';
import { errorKind } from '../lib/util.js';
import {
  DANE_STATUSES, DANE_SEVERITY, DANE_NOTES, DANE_ACTION_STATUSES, TLSA_USAGES, TLSA_SELECTORS, TLSA_MATCHING,
  certAssociations, checkDane, daneExportJson, daneSummary, issuedBy, planDane
} from '../lib/dane.js';

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'dane.tab': 'DANE / TLSA',
  'dane.tabShort': 'DANE',
  'dane.intro': 'DANE pins a certificate or its key in DNS (TLSA records). A mail server that validates DNSSEC does not deliver to a host whose certificate no TLSA record matches: the mail waits in its queue, silently. DANE-aware HTTPS clients refuse the connection (browsers do not use DANE). Check before you install the new certificate.',
  'dane.introCompact': 'Before you install this certificate: do TLSA records at the mail servers and names of its domains pin another certificate?',
  'dane.plan': {
    one: 'Sends MX and TLSA queries (names only, with DNSSEC) to your DNS-over-HTTPS resolvers: the mail servers of {domains} (port 25) and {count} name (port 443). Nothing is sent until you click.',
    other: 'Sends MX and TLSA queries (names only, with DNSSEC) to your DNS-over-HTTPS resolvers: the mail servers of {domains} (port 25) and {count} names (port 443). Nothing is sent until you click.'
  },
  'dane.planScan': {
    one: '{count} of them is a host this scan found under a wildcard name of the certificate.',
    other: '{count} of them are hosts this scan found under the wildcard names of the certificate.'
  },
  'dane.skipped.wildcard': 'Wildcard names are not looked up ({list}): a TLSA record lives at a concrete host name such as {example}.',
  'dane.skipped.wildcardScan': 'Wildcard names are not looked up ({list}); the covered hosts this scan found under them are checked instead.',
  'dane.skipped.cap': { one: '{count} more name is not checked (limit).', other: '{count} more names are not checked (limit).' },
  'dane.skipped.invalid': { one: '{count} certificate name is not a valid host name and is not looked up.', other: '{count} certificate names are not valid host names and are not looked up.' },
  'dane.skipped.domainsCap': { one: 'The mail servers of {count} more domain are not checked (limit).', other: 'The mail servers of {count} more domains are not checked (limit).' },
  'dane.skipped.mxCap': { one: '{count} more mail server is not checked (limit).', other: '{count} more mail servers are not checked (limit).' },
  'dane.mxFailed': 'The MX lookup failed for {list}: those mail servers were not checked. Check again.',
  'dane.nullMx': '{list} accepts no mail (null MX): no mail server to check.',
  'dane.noNames': 'The certificate has no DNS names to check.',
  'dane.run': 'Check TLSA records',
  'dane.rerun': 'Check again',
  'dane.running': 'Looking up MX and TLSA records…',
  'dane.progress.mx': 'Mail servers (MX)',
  'dane.progress.tlsa': 'TLSA records',
  'dane.failed': 'The DANE check failed',
  'dane.noCrypto': 'This check needs the browser’s WebCrypto, which is available only on HTTPS pages and on localhost.',
  'dane.cancelled': 'The check was cancelled.',
  'dane.checkedAt': 'Checked {time} · {count} DNS queries',

  'dane.head.danger': {
    one: '{count} endpoint would reject the new certificate. Publish the TLSA record below first, wait 2 × TTL, then install the certificate.',
    other: '{count} endpoints would reject the new certificate. Publish the TLSA records below first, wait 2 × TTL, then install the certificate.'
  },
  'dane.head.servfail': {
    one: 'The TLSA lookup fails at {count} endpoint (SERVFAIL). DANE senders and clients already fail there, whatever the certificate.',
    other: 'The TLSA lookup fails at {count} endpoints (SERVFAIL). DANE senders and clients already fail there, whatever the certificate.'
  },
  'dane.head.warn': {
    one: '{count} endpoint needs a closer look before you install the new certificate.',
    other: '{count} endpoints need a closer look before you install the new certificate.'
  },
  'dane.head.error': { one: '{count} lookup failed. Check again.', other: '{count} lookups failed. Check again.' },
  'dane.head.safe': 'Every TLSA record set in use matches the new certificate: installing it does not break DANE.',
  'dane.head.clear': 'No TLSA record in use applies to this certificate, so installing it breaks nothing.',
  'dane.head.unused': 'No TLSA records: DANE is not used at these mail servers and names. Nothing to do.',
  'dane.more.insecure': {
    one: '{count} TLSA record set is not in use: DANE clients ignore TLSA that DNSSEC does not validate (and senders ignore it at a mail server whose MX records are not validated).',
    other: '{count} TLSA record sets are not in use: DANE clients ignore TLSA that DNSSEC does not validate (and senders ignore it at a mail server whose MX records are not validated).'
  },
  'dane.more.notCovered': {
    one: '{count} mail server is not named in this certificate: its TLSA records pin that server’s own certificate and matter only if you install this one there.',
    other: '{count} mail servers are not named in this certificate: their TLSA records pin those servers’ own certificates and matter only if you install this one there.'
  },

  'dane.st.danger': 'Will break',
  'dane.st.servfail': 'Lookup fails',
  'dane.st.ta-mismatch': 'Trust anchor not in chain',
  'dane.st.ta-unchecked': 'Needs the chain',
  'dane.st.pkix': 'PKIX record mismatch',
  'dane.st.error': 'Lookup failed',
  'dane.st.insecure': 'Ignored: no DNSSEC',
  'dane.st.not-covered': 'Another certificate',
  'dane.st.unusable': 'No usable record',
  'dane.st.safe': 'Safe',
  'dane.st.none': 'DANE not used',

  'dane.why.danger.smtp': 'A DANE-EE record (usage 3) pins another certificate or key. Once the new certificate is installed, DANE senders queue mail for this server until a record matches.',
  'dane.why.danger.https': 'A DANE-EE record (usage 3) pins another certificate or key. Once the new certificate is installed, DANE-aware clients refuse the connection.',
  'dane.why.servfail': 'The TLSA lookup returns SERVFAIL, so DANE clients cannot tell whether records exist: senders defer mail, clients refuse to connect.',
  'dane.why.ta-mismatch': 'No record matches, and the trust-anchor records (usage 2) match no certificate of the loaded chain. If the new certificate comes from another CA certificate, publish its record first. If the server sends the pinned CA certificate in its chain anyway, nothing changes.',
  'dane.why.ta-unchecked': 'Trust-anchor records (usage 2 / 0) pin a CA certificate, and the loaded file holds only the leaf. Load the full chain (fullchain.pem) to check them, or publish the DANE-EE record below as well.',
  'dane.why.pkix': 'Only PKIX records (usage 0 / 1) are published and none matches: DANE-aware clients would reject the new certificate. Browsers ignore them.',
  'dane.why.error': 'No DNS answer. Check again.',
  'dane.why.insecure': 'The TLSA records are not DNSSEC-validated, so DANE clients ignore them.',
  'dane.why.insecure.mx': 'The MX records of {list} are not DNSSEC-validated, so senders do not look up TLSA for this server (RFC 7672).',
  'dane.why.not-covered': 'This certificate does not name {host}: the records pin that server’s own certificate. They matter only if you install this certificate there.',
  'dane.why.unusable.smtp': 'The records use parameters SMTP senders cannot use (PKIX usages 0 / 1 or unknown values), so they are ignored: senders still require TLS but do not authenticate it.',
  'dane.why.unusable.https': 'The records use unknown parameters or a digest of the wrong length, so clients ignore them.',
  'dane.why.safe': 'A TLSA record matches the new certificate.',
  'dane.why.none': 'No TLSA record: this host does not use DANE.',
  'dane.would.safe': 'Once DNSSEC validates them, they match the new certificate.',
  'dane.would.break': 'Once DNSSEC validates them, they would reject the new certificate: publish the record in the details first.',

  'dane.note.stale-records': { one: '{count} other record no longer matches: remove it once every server serves the new certificate.', other: '{count} other records no longer match: remove them once every server serves the new certificate.' },
  'dane.note.spki-match': 'The match is on the public key (selector 1): a renewed certificate with the same key keeps matching; a new key needs a new record first.',
  'dane.note.mx-insecure': 'The MX records naming this server are not DNSSEC-validated.',
  'dane.note.ad-unknown': 'The resolver that answered ({resolver}) is not known to validate DNSSEC, so its AD flag was not judged.',
  'dane.note.bogus': 'With DNSSEC checking disabled (CD) the records resolve: their signatures are broken (bogus DNSSEC).',
  'dane.note.cname': 'The TLSA name is an alias (CNAME) of {target}.',
  'dane.note.implicit-mx': '{domain} has no MX record, so mail goes to the domain itself.',
  'dane.note.ttl-remaining': 'The answer carried no signature, so the TTL is what the resolver had left: the real TTL may be longer.',

  'dane.col.endpoint': 'TLSA name',
  'dane.col.dnssec': 'DNSSEC',
  'dane.col.records': 'TLSA records',
  'dane.col.result': 'Result',
  'dane.caption': 'TLSA records of the mail servers and names',
  'dane.svc.smtp': 'SMTP',
  'dane.svc.https': 'HTTPS',
  'dane.via.mx': 'MX of {list}',
  'dane.via.implicit': 'Mail for {domain} (no MX)',
  'dane.via.cert': 'Name in the certificate',
  'dane.via.extra': 'Host found by the scan',
  'dane.ad.yes': 'Validated',
  'dane.ad.no': 'Not validated',
  'dane.ad.unknown': 'Unknown',
  'dane.rec.match': 'Matches the new certificate',
  'dane.rec.matchChain': 'Matches {name} in the chain',
  'dane.rec.noMatch': 'Does not match the new certificate',
  'dane.rec.unknown': 'Pins a CA certificate: load the chain to compare',
  'dane.issue.bad-usage': 'Unknown usage: ignored',
  'dane.issue.bad-selector': 'Unknown selector: ignored',
  'dane.issue.bad-matching': 'Unknown matching type: ignored',
  'dane.issue.bad-length': 'Digest of the wrong length: ignored',
  'dane.issue.pkix-smtp': 'PKIX usage: ignored by SMTP senders',

  'dane.det.qname': 'TLSA name',
  'dane.det.answer': 'Answer',
  'dane.det.ttl': 'TTL',
  'dane.det.ttl.rrsig': '{ttl} (original TTL, from the signature)',
  'dane.det.ttl.answer': '{ttl} (left in the resolver’s cache)',
  'dane.det.records': 'Published records',
  'dane.det.add': 'Records to add',
  'dane.det.notes': 'Notes',

  'dane.publish.title': 'Publish before you install',
  'dane.publish.step1': 'Add these records next to the current ones. Keep the old records for now.',
  'dane.publish.step2': 'Wait at least 2 × TTL ({wait}) so that every resolver has dropped the old record set.',
  'dane.publish.step2NoTtl': 'Wait at least twice the TTL of the TLSA records so that every resolver has dropped the old record set.',
  'dane.publish.step3': 'Install the new certificate, then check again here.',
  'dane.publish.step4': 'Once every server serves the new certificate, remove the old records.',
  'dane.publish.label': 'TLSA records to add',

  'dane.values.title': 'TLSA values of this certificate',
  'dane.values.hint': 'Computed in this browser. 3 1 1 (DANE-EE, public key, SHA-256) is the usual choice (RFC 7671): it keeps matching a renewed certificate with the same key.',
  'dane.values.leaf': 'DANE-EE (usage 3): this certificate',
  'dane.values.issuer': 'DANE-TA (usage 2): {name}',

  'dane.dur.d': '{n} d',
  'dane.dur.h': '{n} h',
  'dane.dur.min': '{n} min',
  'dane.dur.s': '{n} s',
  'dane.exported': '{file} downloaded'
});

registerStrings('tr', {
  'dane.tab': 'DANE / TLSA',
  'dane.tabShort': 'DANE',
  'dane.intro': 'DANE, bir sertifikayı veya anahtarını DNS’te (TLSA kayıtları) sabitler. DNSSEC doğrulayan bir e-posta sunucusu, sertifikası hiçbir TLSA kaydıyla eşleşmeyen sunucuya e-posta teslim etmez: e-postalar kuyrukta sessizce bekler. DANE destekli HTTPS istemcileri de bağlantıyı reddeder (tarayıcılar DANE kullanmaz). Yeni sertifikayı kurmadan önce kontrol edin.',
  'dane.introCompact': 'Bu sertifikayı kurmadan önce: alan adlarının e-posta sunucularındaki ve adlarındaki TLSA kayıtları başka bir sertifikayı mı sabitliyor?',
  'dane.plan': {
    one: 'DNS-over-HTTPS çözümleyicilerinize MX ve TLSA sorguları (yalnızca adlar, DNSSEC ile) gönderir: {domains} e-posta sunucuları (port 25) ve {count} ad (port 443). Siz tıklayana kadar hiçbir şey gönderilmez.',
    other: 'DNS-over-HTTPS çözümleyicilerinize MX ve TLSA sorguları (yalnızca adlar, DNSSEC ile) gönderir: {domains} e-posta sunucuları (port 25) ve {count} ad (port 443). Siz tıklayana kadar hiçbir şey gönderilmez.'
  },
  'dane.planScan': {
    one: 'Bunlardan {count} tanesi, bu taramanın sertifikadaki bir joker adın altında bulduğu bir sunucu.',
    other: 'Bunlardan {count} tanesi, bu taramanın sertifikadaki joker adların altında bulduğu sunucular.'
  },
  'dane.skipped.wildcard': 'Joker adlar sorgulanmaz ({list}): TLSA kaydı {example} gibi somut bir sunucu adında bulunur.',
  'dane.skipped.wildcardScan': 'Joker adlar sorgulanmaz ({list}); onların yerine bu taramanın altlarında bulduğu kapsanan sunucular kontrol edilir.',
  'dane.skipped.cap': { one: '{count} ad daha kontrol edilmedi (sınır).', other: '{count} ad daha kontrol edilmedi (sınır).' },
  'dane.skipped.invalid': { one: 'Sertifikadaki {count} ad geçerli bir sunucu adı değil, sorgulanmaz.', other: 'Sertifikadaki {count} ad geçerli bir sunucu adı değil, sorgulanmaz.' },
  'dane.skipped.domainsCap': { one: '{count} alan adının daha e-posta sunucuları kontrol edilmedi (sınır).', other: '{count} alan adının daha e-posta sunucuları kontrol edilmedi (sınır).' },
  'dane.skipped.mxCap': { one: '{count} e-posta sunucusu daha kontrol edilmedi (sınır).', other: '{count} e-posta sunucusu daha kontrol edilmedi (sınır).' },
  'dane.mxFailed': '{list} için MX sorgusu başarısız oldu: bu e-posta sunucuları kontrol edilmedi. Yeniden kontrol edin.',
  'dane.nullMx': '{list} e-posta kabul etmiyor (null MX): kontrol edilecek e-posta sunucusu yok.',
  'dane.noNames': 'Sertifikada kontrol edilecek DNS adı yok.',
  'dane.run': 'TLSA kayıtlarını kontrol et',
  'dane.rerun': 'Yeniden kontrol et',
  'dane.running': 'MX ve TLSA kayıtları sorgulanıyor…',
  'dane.progress.mx': 'E-posta sunucuları (MX)',
  'dane.progress.tlsa': 'TLSA kayıtları',
  'dane.failed': 'DANE kontrolü başarısız oldu',
  'dane.noCrypto': 'Bu kontrol tarayıcının WebCrypto özelliğine ihtiyaç duyar; bu özellik yalnızca HTTPS sayfalarında ve localhost’ta vardır.',
  'dane.cancelled': 'Kontrol iptal edildi.',
  'dane.checkedAt': '{time} kontrol edildi · {count} DNS sorgusu',

  'dane.head.danger': {
    one: '{count} uç nokta yeni sertifikayı reddeder. Önce aşağıdaki TLSA kaydını yayınlayın, TTL’nin 2 katı kadar bekleyin, sonra sertifikayı kurun.',
    other: '{count} uç nokta yeni sertifikayı reddeder. Önce aşağıdaki TLSA kayıtlarını yayınlayın, TTL’nin 2 katı kadar bekleyin, sonra sertifikayı kurun.'
  },
  'dane.head.servfail': {
    one: '{count} uç noktada TLSA sorgusu başarısız (SERVFAIL). DANE gönderenler ve istemciler, sertifikadan bağımsız olarak orada şimdiden başarısız oluyor.',
    other: '{count} uç noktada TLSA sorgusu başarısız (SERVFAIL). DANE gönderenler ve istemciler, sertifikadan bağımsız olarak orada şimdiden başarısız oluyor.'
  },
  'dane.head.warn': {
    one: '{count} uç nokta, yeni sertifikayı kurmadan önce daha yakından incelenmeli.',
    other: '{count} uç nokta, yeni sertifikayı kurmadan önce daha yakından incelenmeli.'
  },
  'dane.head.error': { one: '{count} sorgu başarısız oldu. Yeniden kontrol edin.', other: '{count} sorgu başarısız oldu. Yeniden kontrol edin.' },
  'dane.head.safe': 'Kullanımdaki her TLSA kayıt kümesi yeni sertifikayla eşleşiyor: kurmak DANE’i bozmaz.',
  'dane.head.clear': 'Kullanımdaki hiçbir TLSA kaydı bu sertifikayı ilgilendirmiyor; onu kurmak hiçbir şeyi bozmaz.',
  'dane.head.unused': 'TLSA kaydı yok: bu e-posta sunucularında ve adlarda DANE kullanılmıyor. Yapılacak bir şey yok.',
  'dane.more.insecure': {
    one: '{count} TLSA kayıt kümesi kullanımda değil: DANE istemcileri DNSSEC’in doğrulamadığı TLSA’yı yok sayar (gönderenler, MX kayıtları doğrulanmayan bir e-posta sunucusundaki TLSA’yı da yok sayar).',
    other: '{count} TLSA kayıt kümesi kullanımda değil: DANE istemcileri DNSSEC’in doğrulamadığı TLSA’yı yok sayar (gönderenler, MX kayıtları doğrulanmayan bir e-posta sunucusundaki TLSA’yı da yok sayar).'
  },
  'dane.more.notCovered': {
    one: '{count} e-posta sunucusu bu sertifikada adıyla geçmiyor: TLSA kayıtları o sunucunun kendi sertifikasını sabitler ve yalnızca bu sertifikayı oraya kurarsanız önemlidir.',
    other: '{count} e-posta sunucusu bu sertifikada adıyla geçmiyor: TLSA kayıtları o sunucuların kendi sertifikalarını sabitler ve yalnızca bu sertifikayı oraya kurarsanız önemlidir.'
  },

  'dane.st.danger': 'Bozulacak',
  'dane.st.servfail': 'Sorgu başarısız',
  'dane.st.ta-mismatch': 'Güven çapası zincirde yok',
  'dane.st.ta-unchecked': 'Zincir gerekli',
  'dane.st.pkix': 'PKIX kaydı uyuşmuyor',
  'dane.st.error': 'Sorgulanamadı',
  'dane.st.insecure': 'Yok sayılır: DNSSEC yok',
  'dane.st.not-covered': 'Başka bir sertifika',
  'dane.st.unusable': 'Kullanılabilir kayıt yok',
  'dane.st.safe': 'Güvenli',
  'dane.st.none': 'DANE kullanılmıyor',

  'dane.why.danger.smtp': 'Bir DANE-EE kaydı (kullanım 3) başka bir sertifikayı veya anahtarı sabitliyor. Yeni sertifika kurulunca DANE gönderenler, bir kayıt eşleşene kadar bu sunucunun e-postalarını kuyrukta bekletir.',
  'dane.why.danger.https': 'Bir DANE-EE kaydı (kullanım 3) başka bir sertifikayı veya anahtarı sabitliyor. Yeni sertifika kurulunca DANE destekli istemciler bağlantıyı reddeder.',
  'dane.why.servfail': 'TLSA sorgusu SERVFAIL döndürüyor; DANE istemcileri kayıt olup olmadığını anlayamaz: gönderenler e-postayı erteler, istemciler bağlanmayı reddeder.',
  'dane.why.ta-mismatch': 'Hiçbir kayıt eşleşmiyor ve güven çapası kayıtları (kullanım 2) yüklenen zincirdeki hiçbir sertifikayla eşleşmiyor. Yeni sertifika başka bir CA sertifikasından geliyorsa önce onun kaydını yayınlayın. Sunucu sabitlenen CA sertifikasını zincirinde yine gönderiyorsa bir şey değişmez.',
  'dane.why.ta-unchecked': 'Güven çapası kayıtları (kullanım 2 / 0) bir CA sertifikasını sabitliyor ve yüklenen dosyada yalnızca uç sertifika var. Kontrol için tam zinciri (fullchain.pem) yükleyin ya da aşağıdaki DANE-EE kaydını da yayınlayın.',
  'dane.why.pkix': 'Yalnızca PKIX kayıtları (kullanım 0 / 1) yayınlanmış ve hiçbiri eşleşmiyor: DANE destekli istemciler yeni sertifikayı reddeder. Tarayıcılar bu kayıtları yok sayar.',
  'dane.why.error': 'DNS yanıtı alınamadı. Yeniden kontrol edin.',
  'dane.why.insecure': 'TLSA kayıtları DNSSEC ile doğrulanmıyor; DANE istemcileri bu kayıtları yok sayar.',
  'dane.why.insecure.mx': '{list} MX kayıtları DNSSEC ile doğrulanmıyor; gönderenler bu sunucu için TLSA sorgulamaz (RFC 7672).',
  'dane.why.not-covered': 'Bu sertifika {host} adını içermiyor: kayıtlar o sunucunun kendi sertifikasını sabitler. Yalnızca bu sertifikayı oraya kurarsanız önemlidir.',
  'dane.why.unusable.smtp': 'Kayıtlar SMTP gönderenlerin kullanamadığı değerler taşıyor (PKIX kullanımları 0 / 1 ya da bilinmeyen değerler), bu yüzden yok sayılır: gönderenler yine TLS ister ama doğrulamaz.',
  'dane.why.unusable.https': 'Kayıtlar bilinmeyen değerler ya da yanlış uzunlukta özet taşıyor; istemciler bu kayıtları yok sayar.',
  'dane.why.safe': 'Bir TLSA kaydı yeni sertifikayla eşleşiyor.',
  'dane.why.none': 'TLSA kaydı yok: bu sunucu DANE kullanmıyor.',
  'dane.would.safe': 'DNSSEC bunları doğruladığında yeni sertifikayla eşleşirler.',
  'dane.would.break': 'DNSSEC bunları doğruladığında yeni sertifikayı reddederler: önce ayrıntılardaki kaydı yayınlayın.',

  'dane.note.stale-records': { one: '{count} kayıt artık eşleşmiyor: her sunucu yeni sertifikayı sunduğunda onu kaldırın.', other: '{count} kayıt artık eşleşmiyor: her sunucu yeni sertifikayı sunduğunda bunları kaldırın.' },
  'dane.note.spki-match': 'Eşleşme açık anahtar üzerinden (seçici 1): aynı anahtarla yenilenen bir sertifika eşleşmeye devam eder; yeni bir anahtar için önce yeni bir kayıt gerekir.',
  'dane.note.mx-insecure': 'Bu sunucuyu gösteren MX kayıtları DNSSEC ile doğrulanmıyor.',
  'dane.note.ad-unknown': 'Yanıt veren çözümleyicinin ({resolver}) DNSSEC doğruladığı bilinmiyor; AD bayrağı değerlendirilmedi.',
  'dane.note.bogus': 'DNSSEC denetimi kapatılınca (CD) kayıtlar çözümleniyor: imzaları bozuk (bogus DNSSEC).',
  'dane.note.cname': 'TLSA adı {target} adının takma adı (CNAME).',
  'dane.note.implicit-mx': '{domain} alan adının MX kaydı yok; e-posta doğrudan alan adının kendisine gider.',
  'dane.note.ttl-remaining': 'Yanıtta imza yoktu; TTL, çözümleyicide kalan süredir: gerçek TTL daha uzun olabilir.',

  'dane.col.endpoint': 'TLSA adı',
  'dane.col.dnssec': 'DNSSEC',
  'dane.col.records': 'TLSA kayıtları',
  'dane.col.result': 'Sonuç',
  'dane.caption': 'E-posta sunucularının ve adların TLSA kayıtları',
  'dane.svc.smtp': 'SMTP',
  'dane.svc.https': 'HTTPS',
  'dane.via.mx': '{list} MX kaydı',
  'dane.via.implicit': '{domain} e-postası (MX yok)',
  'dane.via.cert': 'Sertifikadaki ad',
  'dane.via.extra': 'Taramanın bulduğu sunucu',
  'dane.ad.yes': 'Doğrulandı',
  'dane.ad.no': 'Doğrulanmadı',
  'dane.ad.unknown': 'Bilinmiyor',
  'dane.rec.match': 'Yeni sertifikayla eşleşiyor',
  'dane.rec.matchChain': 'Zincirdeki {name} ile eşleşiyor',
  'dane.rec.noMatch': 'Yeni sertifikayla eşleşmiyor',
  'dane.rec.unknown': 'Bir CA sertifikasını sabitliyor: karşılaştırmak için zinciri yükleyin',
  'dane.issue.bad-usage': 'Bilinmeyen kullanım: yok sayılır',
  'dane.issue.bad-selector': 'Bilinmeyen seçici: yok sayılır',
  'dane.issue.bad-matching': 'Bilinmeyen eşleştirme türü: yok sayılır',
  'dane.issue.bad-length': 'Özet uzunluğu yanlış: yok sayılır',
  'dane.issue.pkix-smtp': 'PKIX kullanımı: SMTP gönderenler yok sayar',

  'dane.det.qname': 'TLSA adı',
  'dane.det.answer': 'Yanıt',
  'dane.det.ttl': 'TTL',
  'dane.det.ttl.rrsig': '{ttl} (özgün TTL, imzadan)',
  'dane.det.ttl.answer': '{ttl} (çözümleyicinin önbelleğinde kalan)',
  'dane.det.records': 'Yayınlanan kayıtlar',
  'dane.det.add': 'Eklenecek kayıtlar',
  'dane.det.notes': 'Notlar',

  'dane.publish.title': 'Kurmadan önce yayınlayın',
  'dane.publish.step1': 'Bu kayıtları mevcut kayıtların yanına ekleyin. Eski kayıtları şimdilik silmeyin.',
  'dane.publish.step2': 'Her çözümleyicinin eski kayıt kümesini bırakması için en az TTL’nin 2 katı ({wait}) bekleyin.',
  'dane.publish.step2NoTtl': 'Her çözümleyicinin eski kayıt kümesini bırakması için en az TLSA kayıtlarının TTL’sinin iki katı kadar bekleyin.',
  'dane.publish.step3': 'Yeni sertifikayı kurun, sonra burada yeniden kontrol edin.',
  'dane.publish.step4': 'Her sunucu yeni sertifikayı sunduğunda eski kayıtları kaldırın.',
  'dane.publish.label': 'Eklenecek TLSA kayıtları',

  'dane.values.title': 'Bu sertifikanın TLSA değerleri',
  'dane.values.hint': 'Bu tarayıcıda hesaplandı. Genel tercih 3 1 1’dir (DANE-EE, açık anahtar, SHA-256; RFC 7671): aynı anahtarla yenilenen sertifikayla eşleşmeye devam eder.',
  'dane.values.leaf': 'DANE-EE (kullanım 3): bu sertifika',
  'dane.values.issuer': 'DANE-TA (kullanım 2): {name}',

  'dane.dur.d': '{n} gün',
  'dane.dur.h': '{n} sa',
  'dane.dur.min': '{n} dk',
  'dane.dur.s': '{n} sn',
  'dane.exported': '{file} indirildi'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/**
 * A wait in seconds as '2 h', '1 h 30 min', '10 min', '2 d 12 h', '45 s'.
 * @param {number} seconds
 * @returns {string}
 */
export function waitText(seconds) {
  const v = Number(seconds);
  if (!Number.isFinite(v) || v < 0) return '—';
  const s = Math.round(v);
  const part = (key, n) => t(`dane.dur.${key}`, { n: formatNumber(n) });
  if (s < 60) return part('s', s);
  if (s < 3600) return part('min', Math.round(s / 60));
  if (s < 86400) {
    const hours = Math.floor(s / 3600);
    const min = Math.round((s % 3600) / 60);
    return min ? `${part('h', hours)} ${part('min', min)}` : part('h', hours);
  }
  const days = Math.floor(s / 86400);
  const hours = Math.round((s % 86400) / 3600);
  return hours ? `${part('d', days)} ${part('h', hours)}` : part('d', days);
}

/**
 * A TLSA record in a table cell: '3 1 1 A1B2C3D4…E5F6', long data shortened.
 * @param {{ usage: number, selector: number, matchingType: number, data: string }} rec
 * @returns {string}
 */
export function shortRecord(rec) {
  const data = String(rec.data || '').toUpperCase();
  const shown = data.length > 20 ? `${data.slice(0, 8)}…${data.slice(-6)}` : data;
  return `${rec.usage} ${rec.selector} ${rec.matchingType} ${shown}`;
}

/**
 * The RFC 7218 mnemonics of a record's fields: 'DANE-EE · SPKI · SHA2-256'.
 * @param {{ usage: number, selector: number, matchingType: number }} rec
 * @returns {string}
 */
export function recordMnemonic(rec) {
  return [TLSA_USAGES[rec.usage], TLSA_SELECTORS[rec.selector], TLSA_MATCHING[rec.matchingType]]
    .map((x) => x || '?').join(' · ');
}

/**
 * The i18n key of the sentence explaining an endpoint's status.
 * @param {{ status: string, service: string, notes?: Array<{ code: string }> }} ep
 * @returns {string}
 */
export function whyKey(ep) {
  if (ep.status === 'danger' || ep.status === 'unusable') return `dane.why.${ep.status}.${ep.service === 'https' ? 'https' : 'smtp'}`;
  if (ep.status === 'insecure' && (ep.notes || []).some((n) => n.code === 'mx-insecure')) return 'dane.why.insecure.mx';
  return `dane.why.${DANE_STATUSES.includes(ep.status) ? ep.status : 'error'}`;
}

/**
 * The i18n key of a record's state in the table: match, match in the chain, no match, unknown or an issue.
 * @param {{ usable: boolean, matches: boolean|null, matchedBy: string|null, issue: string|null }} r
 * @returns {string}
 */
export function recordStateKey(r) {
  if (!r.usable) return `dane.issue.${r.issue || 'bad-usage'}`;
  if (r.matches === null) return 'dane.rec.unknown';
  if (!r.matches) return 'dane.rec.noMatch';
  return r.matchedBy === 'chain' ? 'dane.rec.matchChain' : 'dane.rec.match';
}

/**
 * The tab badge of a finished check: the endpoints to act on (error: would break or lookup
 * fails; warn: a closer look), else null.
 * @param {object|null} holder
 * @returns {{ value: number, variant: 'error'|'warn' }|null}
 */
export function daneTabBadge(holder) {
  const job = holder && holder.dane;
  if (!job || job.status !== 'done' || !job.report) return null;
  const s = daneSummary(job.report);
  const bad = s.counts.danger + s.counts.servfail;
  if (bad) return { value: bad, variant: 'error' };
  return s.warn ? { value: s.warn, variant: 'warn' } : null;
}

/**
 * The DANE block of an export (null until a check finished).
 * @param {object|null} holder
 * @param {string} version app version
 * @returns {object|null}
 */
export function daneExport(holder, version) {
  const job = holder && holder.dane;
  return job && job.status === 'done' && job.report ? daneExportJson(job.report, { version }) : null;
}

/** CSV columns of the table export (lib/export.toCsv). */
export const DANE_CSV_COLUMNS = Object.freeze([
  { key: 'qname', header: 'tlsa_name' },
  { key: 'service', header: 'service' },
  { key: 'port', header: 'port' },
  { key: 'host', header: 'host' },
  { key: 'via', header: 'via', get: (ep) => ep.via.join(' ') },
  { key: 'status', header: 'status' },
  { key: 'dnssec', header: 'dnssec', get: (ep) => (ep.lookup.authenticated === null ? '' : String(ep.lookup.authenticated)) },
  { key: 'records', header: 'records', get: (ep) => ep.records.map((r) => `${r.usage} ${r.selector} ${r.matchingType} ${r.data}`).join(' | ') },
  { key: 'add', header: 'add_records', get: (ep) => ep.suggestions.map((s) => s.text).join(' | ') },
  { key: 'wait', header: 'wait_seconds', get: (ep) => ep.waitSeconds ?? '' }
]);

/* ------------------------------------------------------------------------ */
/* The job (owned by the host view's holder)                                */
/* ------------------------------------------------------------------------ */

const watchers = new WeakMap();

function emit(holder) {
  for (const fn of [...(watchers.get(holder) || [])]) {
    try {
      fn();
    } catch (err) {
      setTimeout(() => {
        throw err;
      }, 0);
    }
  }
}

function watch(holder, fn) {
  if (!watchers.has(holder)) watchers.set(holder, new Set());
  watchers.get(holder).add(fn);
  return () => watchers.get(holder)?.delete(fn);
}

/**
 * Start a check (or join the running one). The job is kept on `holder.dane`.
 * @param {object} holder
 * @param {{ certs: { leaf: object, chain?: object[] }, ctx: object, extraNames?: string[] }} opts
 * @returns {object} the job
 */
export function startDane(holder, { certs, ctx, extraNames = [] }) {
  const prev = holder.dane;
  if (prev && prev.status === 'running') return prev;
  const job = { status: 'running', report: null, error: null, progress: null, controller: new AbortController(), shown: false };
  holder.dane = job;
  emit(holder);
  (async () => {
    try {
      const dns = await ctx.getDns();
      job.report = await checkDane(certs, {
        dns,
        extraNames,
        // Fresh answers: a check right after publishing a record must not read the client's cache.
        noCache: true,
        signal: job.controller.signal,
        onProgress: (p) => {
          job.progress = p;
          emit(holder);
        }
      });
      job.status = 'done';
    } catch (err) {
      job.status = errorKind(err) === 'abort' ? 'cancelled' : 'error';
      job.error = err;
    }
    if (holder.dane === job) emit(holder);
  })();
  return job;
}

/* ------------------------------------------------------------------------ */
/* Rendering                                                                */
/* ------------------------------------------------------------------------ */

function viaText(ep) {
  if (ep.service === 'smtp') {
    return ep.implicit ? t('dane.via.implicit', { domain: ep.via[0] || ep.host }) : t('dane.via.mx', { list: ep.via.join(', ') });
  }
  return t(ep.source === 'extra' ? 'dane.via.extra' : 'dane.via.cert');
}

function adBadge(value) {
  if (value === true) return Badge(t('dane.ad.yes'), { variant: 'ok', icon: 'lock' });
  if (value === false) return Badge(t('dane.ad.no'), { variant: 'warn', icon: 'unlock' });
  return Badge(t('dane.ad.unknown'), { variant: 'neutral' });
}

const REC_ICONS = { match: 'check-circle', no: 'x-circle', unknown: 'help', unusable: 'minus-circle' };

function recordState(r) {
  if (!r.usable) return 'unusable';
  if (r.matches === null) return 'unknown';
  return r.matches ? 'match' : 'no';
}

function recordText(r, anchors) {
  const name = r.matchedBy === 'chain' && anchors[r.anchor] ? anchors[r.anchor].subjectCN || anchors[r.anchor].subjectDN : '';
  return t(recordStateKey(r), { name });
}

function recordChip(r, anchors) {
  const state = recordState(r);
  return h('span', { class: ['dane-rec', `dane-rec-${state}`], title: `${recordMnemonic(r)} — ${recordText(r, anchors)}`, dataset: { rec: state } },
    Icon(REC_ICONS[state], { size: 13 }),
    h('span', { class: 'mono' }, shortRecord(r)),
    h('span', { class: 'sr-only' }, recordText(r, anchors)));
}

function statusBadge(ep) {
  const sev = DANE_SEVERITY[ep.status] || 'neutral';
  const icon = { error: 'x-circle', warn: 'alert', info: 'info', ok: 'check-circle', neutral: 'minus-circle' }[sev];
  const b = Badge(t(`dane.st.${ep.status}`), { variant: sev, icon });
  b.dataset.daneStatus = ep.status;
  return b;
}

function whySentence(ep) {
  const parts = [t(whyKey(ep), { host: ep.host, list: ep.via.join(', ') })];
  // Records DNSSEC does not validate are ignored today; say what they would do once it does.
  if (ep.status === 'insecure' && ep.wouldBe === 'safe') parts.push(t('dane.would.safe'));
  else if (ep.status === 'insecure' && DANE_ACTION_STATUSES.includes(ep.wouldBe)) parts.push(t('dane.would.break'));
  return parts.join(' ');
}

function noteText(n) {
  return DANE_NOTES.includes(n.code) ? t(`dane.note.${n.code}`, n.params || {}) : n.code;
}

function endpointDetails(ep, anchors) {
  const items = [{ key: t('dane.det.qname'), value: h('span', { class: 'mono' }, ep.qname) }];
  const answer = [ep.lookup.rcode || ep.lookup.error || '—', ep.lookup.resolver].filter(Boolean).join(' · ');
  items.push({ key: t('dane.det.answer'), value: h('span', { class: 'mono' }, answer) });
  if (ep.ttl !== null) {
    items.push({ key: t('dane.det.ttl'), value: t(ep.ttlSource === 'rrsig' ? 'dane.det.ttl.rrsig' : 'dane.det.ttl.answer', { ttl: waitText(ep.ttl) }) });
  }
  if (ep.records.length) {
    items.push({
      key: t('dane.det.records'),
      value: h('ul', { class: 'dane-det-recs' }, ep.records.map((r) => h('li', null,
        recordChip(r, anchors), ' ', h('span', { class: 'text-sm muted' }, `${recordMnemonic(r)} — ${recordText(r, anchors)}`))))
    });
  }
  if (ep.notes.length) {
    items.push({ key: t('dane.det.notes'), value: h('ul', { class: 'dane-det-notes' }, ep.notes.map((n) => h('li', null, noteText(n)))) });
  }
  // The explanation sits in the result cell; phones hide it there (dane.css) and read it here.
  const box = h('div', { class: 'stack-sm dane-details' }, h('p', { class: 'dane-det-why text-sm' }, whySentence(ep)), KeyValueList(items));
  if (ep.suggestions.length) {
    box.append(CodeBlock(ep.suggestions.map((s) => s.text).join('\n'), { label: t('dane.det.add'), wrap: true }));
  }
  return box;
}

/** The steps to publish first: error styling when an endpoint would break, warn styling otherwise. */
function publishCard(summary) {
  const lines = [];
  for (const ep of summary.action) for (const s of ep.suggestions) if (!lines.includes(s.text)) lines.push(s.text);
  const code = CodeBlock(lines.join('\n'), { label: t('dane.publish.label'), wrap: true });
  code.dataset.dane = 'publish';
  const wait = summary.waitSeconds !== null ? t('dane.publish.step2', { wait: waitText(summary.waitSeconds) }) : t('dane.publish.step2NoTtl');
  const card = Card({
    title: t('dane.publish.title'),
    icon: 'alert',
    className: ['dane-publish', { 'dane-publish-warn': !summary.counts.danger }],
    children: h('ol', { class: 'dane-steps' },
      h('li', null, h('p', null, t('dane.publish.step1')), code),
      h('li', { dataset: { dane: 'wait' } }, wait),
      h('li', null, t('dane.publish.step3')),
      h('li', null, t('dane.publish.step4')))
  });
  card.dataset.danePublish = summary.counts.danger ? 'error' : 'warn';
  return card;
}

function valuesBlock(certs) {
  const body = h('div', { class: 'stack-sm' }, h('p', { class: 'muted text-sm' }, t('dane.values.hint')));
  const lines = (assoc, usage) => [[1, 1], [0, 1], [1, 2], [0, 2]].map(([s, m]) => `${usage} ${s} ${m} ${assoc[s][m].toUpperCase()}`).join('\n');
  const leaf = certs.leaf;
  const chain = (certs.chain || []).filter((c) => c && c !== leaf);
  const issuer = chain.find((c) => issuedBy(leaf, c)) || null;
  Promise.all([certAssociations(leaf), issuer ? certAssociations(issuer) : null]).then(([a, b]) => {
    body.append(CodeBlock(lines(a, 3), { label: t('dane.values.leaf'), wrap: true }));
    if (b) body.append(CodeBlock(lines(b, 2), { label: t('dane.values.issuer', { name: issuer.subjectCN || issuer.subjectDN }), wrap: true }));
  }, (err) => {
    body.append(err && err.code === 'no-crypto'
      ? Alert({ variant: 'info', compact: true, message: t('dane.noCrypto') })
      : ErrorBanner(err, { compact: true }));
  });
  const d = Disclosure({ summary: t('dane.values.title'), className: 'dane-values', children: body });
  d.dataset.dane = 'values';
  return d;
}

/**
 * The DANE / TLSA panel.
 * @param {{ certs: { leaf: object|null, chain?: object[] }, ctx: import('../app.js').ViewContext, holder: object,
 *   extraNames?: string[], compact?: boolean, subject?: string, onChange?: () => void }} opts
 *   `holder` keeps the job across re-mounts (`holder.dane`); `extraNames`: concrete names the
 *   certificate covers to check on port 443 too (SSL Targets: the covered hosts of the scan);
 *   `onChange` runs when the job changes (the host's tab badge)
 * @returns {{ el: HTMLElement, dispose(): void }}
 */
export function DanePanel({ certs, ctx, holder, extraNames = [], compact = false, subject = '', onChange = null }) {
  const el = h('div', { class: 'dane-panel', dataset: { dane: 'panel' } });
  const leaf = certs && certs.leaf;
  if (!leaf) {
    el.append(EmptyState({ compact: true, icon: 'key', message: t('dane.noNames') }));
    return { el, dispose() {} };
  }
  const plan = planDane(leaf, { extraNames });
  const fromScan = plan.https.filter((x) => x.source === 'extra').length;
  const infoHost = h('div', { class: 'dane-info' });
  const actions = h('div', { class: 'dane-actions' });
  const statusHost = h('div', { class: 'dane-status', attrs: { 'aria-live': 'polite' } });
  const resultHost = h('div', { class: 'dane-result' });
  el.append(h('p', { class: 'dane-intro' }, t(compact ? 'dane.introCompact' : 'dane.intro')), infoHost, actions, statusHost, resultHost, valuesBlock(certs));

  // What a click sends, and what is left out.
  if (!plan.domains.length && !plan.https.length) {
    infoHost.append(EmptyState({ compact: true, icon: 'key', message: t('dane.noNames') }));
  } else {
    infoHost.append(h('p', { class: 'dane-plan', dataset: { dane: 'plan' } },
      t('dane.plan', { domains: plan.domains.join(', ') || '—', count: plan.https.length }),
      fromScan ? ` ${t('dane.planScan', { count: fromScan })}` : ''));
  }
  const notes = [];
  if (plan.skipped.wildcard.length) {
    const base = plan.skipped.wildcard[0].slice(2);
    notes.push(fromScan
      ? t('dane.skipped.wildcardScan', { list: plan.skipped.wildcard.join(', ') })
      : t('dane.skipped.wildcard', { list: plan.skipped.wildcard.join(', '), example: `_443._tcp.www.${base}` }));
  }
  if (plan.skipped.invalid.length) notes.push(t('dane.skipped.invalid', { count: plan.skipped.invalid.length }));
  if (plan.skipped.httpsOverCap) notes.push(t('dane.skipped.cap', { count: plan.skipped.httpsOverCap }));
  if (plan.skipped.domainsOverCap) notes.push(t('dane.skipped.domainsCap', { count: plan.skipped.domainsOverCap }));
  for (const n of notes) infoHost.append(h('p', { class: 'dane-note' }, Icon('info', { size: 14 }), h('span', null, n)));

  const runBtn = Button({
    label: t('dane.run'), icon: 'play', variant: 'primary', size: 'sm', dataset: { action: 'dane-run' },
    disabled: !plan.domains.length && !plan.https.length,
    onClick: () => startDane(holder, { certs, ctx, extraNames })
  });
  const progress = ProgressBar({ label: t('dane.running'), indeterminate: true, showCount: false });
  progress.el.hidden = true;
  actions.append(runBtn, progress.el);

  let lastStatus = null;
  function render() {
    const job = holder.dane || null;
    const running = !!job && job.status === 'running';
    runBtn.disabled = running || (!plan.domains.length && !plan.https.length);
    runBtn.querySelector('.btn-label').textContent = job && !running ? t('dane.rerun') : t('dane.run');
    runBtn.classList.toggle('btn-primary', !job);
    runBtn.classList.toggle('btn-secondary', !!job);
    progress.el.hidden = !running;
    el.dataset.state = job ? job.status : 'idle';
    if (running) {
      const p = job.progress;
      if (p && p.total) {
        progress.set(p.done, p.total);
        progress.setLabel(t(p.phase === 'mx' ? 'dane.progress.mx' : 'dane.progress.tlsa'));
      } else {
        progress.setIndeterminate(true);
        progress.setLabel(t('dane.running'));
      }
    }
    // The result area is rebuilt only when the job changes state, not on every progress tick.
    const key = job ? `${job.status}|${job.report ? job.report.finishedAt.getTime() : ''}` : 'idle';
    if (key === lastStatus) return;
    lastStatus = key;
    clear(statusHost);
    clear(resultHost);
    if (!job || running) return;
    if (job.status === 'cancelled') {
      statusHost.append(Alert({ variant: 'info', compact: true, message: t('dane.cancelled') }));
      return;
    }
    if (job.status === 'error') {
      statusHost.append(job.error && job.error.code === 'no-crypto'
        ? Alert({ variant: 'warn', compact: true, message: t('dane.noCrypto') })
        : ErrorBanner(job.error, { title: t('dane.failed'), onRetry: () => startDane(holder, { certs, ctx, extraNames }) }));
      return;
    }
    renderReport(job.report);
  }

  function renderReport(report) {
    const s = daneSummary(report);
    if (s.headline) {
      const head = Alert({ variant: s.variant, message: t(`dane.head.${s.headline}`, { count: s.count }) });
      head.dataset.daneHead = s.headline;
      statusHost.append(head);
    }
    if (s.counts.insecure) statusHost.append(Alert({ variant: 'info', compact: true, message: t('dane.more.insecure', { count: s.counts.insecure }) }));
    if (s.counts['not-covered']) statusHost.append(Alert({ variant: 'info', compact: true, message: t('dane.more.notCovered', { count: s.counts['not-covered'] }) }));
    // Mail domains without a row: a failed MX lookup (never "DANE not used"), a null MX, the cap.
    if (s.mxFailed.length) {
      const a = Alert({ variant: 'warn', compact: true, message: t('dane.mxFailed', { list: s.mxFailed.join(', ') }) });
      a.dataset.dane = 'mx-failed';
      statusHost.append(a);
    }
    if (s.nullMx.length) statusHost.append(Alert({ variant: 'info', compact: true, message: t('dane.nullMx', { list: s.nullMx.join(', ') }) }));
    if (report.skipped.mxHostsOverCap) {
      statusHost.append(Alert({ variant: 'info', compact: true, message: t('dane.skipped.mxCap', { count: report.skipped.mxHostsOverCap }) }));
    }
    if (s.action.length) resultHost.append(publishCard(s));
    const anchors = report.associations.anchors;
    const saveFile = (ext, text, mime) => {
      const file = downloadText(timestampedName('dane', ext, subject), text, mime);
      toast(t('dane.exported', { file }), { type: 'success', timeout: 2500 });
    };
    const rank = (ep) => DANE_STATUSES.indexOf(ep.status);
    const table = DataTable({
      caption: t('dane.caption'),
      rows: report.endpoints,
      rowKey: (ep) => ep.key,
      dense: true,
      sort: { key: 'result', dir: 'asc' },
      details: (ep) => endpointDetails(ep, anchors),
      rowClass: (ep) => `dane-row-${DANE_SEVERITY[ep.status] || 'neutral'}`,
      className: 'dane-table',
      export: {
        filename: 'dane',
        subject,
        onExport: (format, rows) => {
          if (format === 'csv') saveFile('csv', toCsv(rows, DANE_CSV_COLUMNS), 'text/csv;charset=utf-8');
          else saveFile('json', `${toJson(daneExportJson(report, { version: ctx.version }))}\n`, 'application/json;charset=utf-8');
        }
      },
      columns: [
        {
          key: 'result', label: t('dane.col.result'), sortable: true, wrap: true, sortValue: rank,
          searchValue: (ep) => t(`dane.st.${ep.status}`),
          // Phones hide the name column and show the name here instead (dane.css).
          render: (ep) => h('div', { class: 'dane-verdict' }, statusBadge(ep),
            h('span', { class: 'dane-verdict-ep' }, h('span', { class: 'mono' }, ep.qname), h('span', { class: 'text-sm muted' }, viaText(ep))),
            h('span', { class: 'dane-why text-sm muted' }, whySentence(ep)))
        },
        {
          key: 'endpoint', label: t('dane.col.endpoint'), sortable: true, className: 'dane-col-ep',
          sortValue: (ep) => `${ep.port === 25 ? 0 : 1}|${ep.host.split('.').reverse().join('.')}`,
          searchValue: (ep) => `${ep.qname} ${ep.via.join(' ')}`,
          render: (ep) => h('div', { class: 'dane-ep' },
            h('div', { class: 'dane-ep-name' },
              Badge(t(`dane.svc.${ep.service}`), { variant: 'neutral', icon: ep.service === 'smtp' ? 'mail' : 'globe' }),
              h('span', { class: 'mono dane-qname' }, ep.qname)),
            h('div', { class: 'dane-ep-via text-sm muted' }, viaText(ep)))
        },
        {
          key: 'dnssec', label: t('dane.col.dnssec'), sortable: true,
          sortValue: (ep) => (ep.lookup.authenticated === true ? 0 : ep.lookup.authenticated === false ? 1 : 2),
          render: (ep) => adBadge(ep.lookup.authenticated)
        },
        {
          key: 'records', label: t('dane.col.records'),
          searchValue: (ep) => ep.records.map((r) => `${r.usage} ${r.selector} ${r.matchingType} ${r.data}`).join(' '),
          render: (ep) => TruncatedList(ep.records, { max: 3, mono: false, render: (r) => recordChip(r, anchors) })
        }
      ]
    });
    resultHost.append(table.el);
    resultHost.append(h('p', { class: 'dane-meta text-sm muted' }, t('dane.checkedAt', {
      time: formatDateTime(report.finishedAt, { seconds: true }), count: formatNumber(report.queries)
    })));
  }

  // A panel its view dropped (a re-render, an unmount) stops listening at the next change.
  const off = watch(holder, () => {
    if (!el.isConnected) {
      off();
      return;
    }
    render();
    if (onChange) onChange();
  });
  render();
  return {
    el,
    dispose() {
      off();
    }
  };
}
