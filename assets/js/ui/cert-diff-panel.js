/**
 * ui/cert-diff-panel.js — Certificate › Compare: the certificate on screen against the one it
 * replaces or the one replacing it (lib/certdiff.js), loaded on the tab's first use.
 *
 * The other certificate comes from a file or pasted text (the view's own loader, PKCS#12 included)
 * or from Certificate Transparency: the newest certificate of a host name (lib/ctcert.js; only the
 * name is sent, only on a click, aborted when the view goes). The one issued first is the old one;
 * "Swap old and new" turns that round (a rollback). The answer: a one-line verdict ("Safe to
 * deploy everywhere the old one is", or the blockers), both certificates side by side (validity,
 * days left, the overlap to switch over in, key and its SPKI SHA-256, signature, names, SCTs,
 * must-staple, OCSP, the intermediates of each file), then every difference with what it means
 * for the rollout, most serious first, and what did not change. "Copy as text" gives the same for
 * a change ticket.
 *
 * The other certificate, the host name field and its last outcome stay in this tab's memory for
 * the page session (another tab, a language switch, another certificate on screen); "Delete all
 * local data" and a switch to another workspace forget them and stop a lookup.
 */

import { h, clear } from './dom.js';
import {
  Alert, Badge, Button, ButtonLink, CopyButton, Disclosure, ErrorBanner, ExternalLink, Spinner, announce, textInput, toast
} from './components.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import {
  diffCertificates, keyLabel, olderOf, CERTDIFF_AREAS, CERTDIFF_CODES, CERTDIFF_SEVERITIES, CERTDIFF_VERDICTS
} from '../lib/certdiff.js';
import { lookupCtCertificate, normalizeCtHost } from '../lib/ctcert.js';
import { errorKind, mergeSignals } from '../lib/util.js';
import { state as stateSingleton } from '../state.js';

registerStrings('en', {
  'cdiff.title': 'Compare with another certificate',
  'cdiff.intro': 'Load the certificate this one replaces, or the one replacing it: every difference is listed with what it means for the rollout, most serious first. Files are read in your browser; a lookup sends only the host name.',
  'cdiff.other': 'The other certificate',
  'cdiff.dropTitle': 'Drop the other certificate here',
  'cdiff.another': 'Load another one',
  'cdiff.ct.label': 'Or the newest certificate of a host name in Certificate Transparency',
  'cdiff.ct.load': 'Look up',
  'cdiff.ct.hint': 'Sends only the host name to Cert Spotter (to crt.sh when it cannot answer). The newest certificate may already be the new one.',
  'cdiff.ct.searching': 'Looking up {host} in Certificate Transparency…',
  'cdiff.ct.invalid': 'Enter a host name, such as www.example.com.',
  'cdiff.ct.failed': 'Certificate Transparency did not answer',
  'cdiff.ct.manualTitle': 'Found on crt.sh: download it and drop the file above',
  'cdiff.ct.download': 'Download #{id}',
  'cdiff.ct.open': 'Open on crt.sh',
  'cdiff.noLeaf': 'No server certificate in {name}: load a file that holds the certificate itself.',
  'cdiff.comparing': 'Comparing…',
  'cdiff.old': 'Old',
  'cdiff.new': 'New',
  'cdiff.this': 'this certificate',
  'cdiff.order': 'The one issued first is the old one.',
  'cdiff.orderSwapped': 'Swapped: the one issued later is the old one (a rollback).',
  'cdiff.swap': 'Swap old and new',
  'cdiff.remove': 'Remove',
  'cdiff.removed': 'The other certificate was removed',
  'cdiff.copy': 'Copy as text',
  'cdiff.report': 'Certificate comparison: {old} → {new}',
  'cdiff.row.cert': 'Certificate',
  'cdiff.row.issuer': 'Issued by',
  'cdiff.row.valid': 'Valid',
  'cdiff.row.lifetime': 'Lifetime',
  'cdiff.row.left': 'Days left',
  'cdiff.row.key': 'Key',
  'cdiff.row.spki': 'Key SHA-256 (SPKI)',
  'cdiff.row.sig': 'Signature',
  'cdiff.row.names': 'Names',
  'cdiff.row.scts': 'SCTs',
  'cdiff.row.staple': 'Must-staple',
  'cdiff.row.ocsp': 'OCSP',
  'cdiff.row.chain': 'Intermediates in the file',
  'cdiff.days': { one: '{count} day', other: '{count} days' },
  'cdiff.left': { one: '{count} day left', other: '{count} days left' },
  'cdiff.leftExpired': { one: 'expired {count} day ago', other: 'expired {count} days ago' },
  'cdiff.leftNotYet': 'valid from {date}',
  'cdiff.overlap': {
    one: 'Both are valid from {from} to {to}: {count} day to switch over in.',
    other: 'Both are valid from {from} to {to}: {count} days to switch over in.'
  },
  'cdiff.noOverlap': 'They are never valid at the same time.',
  'cdiff.still': 'Still covered by name:',
  'cdiff.coveredBy': 'by {by}',
  'cdiff.added': 'Added:',
  'cdiff.removedList': 'Removed:',
  'cdiff.newChain': 'The new file brings: {list}.',
  'cdiff.missingChain': 'The new file holds no intermediate: get it from the CA, or open the new file in this view, whose Chain tab finds a missing intermediate.',
  'cdiff.openDane': 'Open the DANE / TLSA tab',
  'cdiff.unchanged': 'Unchanged: {list}.',
  'cdiff.none': 'none',
  'cdiff.inFile': 'none in the file',

  'cdiff.sev.blocker': 'Blocker',
  'cdiff.sev.action': 'Step',
  'cdiff.sev.check': 'Check',
  'cdiff.sev.info': 'Info',
  'cdiff.group.blocker': 'Blockers',
  'cdiff.group.action': 'Steps on the servers',
  'cdiff.group.check': 'Check before the switch',
  'cdiff.group.info': 'Other differences',
  'cdiff.area.names': 'names',
  'cdiff.area.key': 'key',
  'cdiff.area.chain': 'issuer and chain',
  'cdiff.area.signature': 'signature',
  'cdiff.area.usage': 'key usage',
  'cdiff.area.ct': 'SCTs',
  'cdiff.area.revocation': 'OCSP and CRL',
  'cdiff.area.subject': 'subject',

  'cdiff.verdict.identical': 'The same certificate',
  'cdiff.verdict.identical.body': 'Both hold this certificate: nothing changes. Load the other one from a file, or look up another host name.',
  'cdiff.verdict.blocked': { one: 'Not a drop-in replacement: {count} blocker', other: 'Not a drop-in replacement: {count} blockers' },
  'cdiff.verdict.blocked.body': 'Deployed everywhere the old one is, it breaks something that works today. Fix the blockers below, or keep the old one where they matter.',
  'cdiff.verdict.steps': {
    one: 'Safe to deploy everywhere the old one is, with {count} change on the servers',
    other: 'Safe to deploy everywhere the old one is, with {count} changes on the servers'
  },
  'cdiff.verdict.steps.body': 'Nothing breaks if the servers get the changes below with it.',
  'cdiff.verdict.check': {
    one: 'Safe to deploy everywhere the old one is; {count} thing to check first',
    other: 'Safe to deploy everywhere the old one is; {count} things to check first'
  },
  'cdiff.verdict.check.body': 'The certificates hold no blocker; what they cannot show is listed below.',
  'cdiff.verdict.safe': 'Safe to deploy everywhere the old one is',
  'cdiff.verdict.safe.body': 'Nothing that works with the old one breaks with the new one.',

  'cdiff.c.precert.title': 'A precertificate, not the certificate',
  'cdiff.c.precert.body': 'This is the precertificate a CA logs before it issues the certificate (CT poison extension): no client accepts it. Deploy the certificate the CA delivered.',
  'cdiff.c.new-is-ca.title': 'A CA certificate, not a server certificate',
  'cdiff.c.new-is-ca.body': 'The new file’s certificate is a CA certificate: servers cannot use it for their names. Load the server certificate of the new file.',
  'cdiff.c.self-signed.title': 'Self-signed',
  'cdiff.c.self-signed.body': 'No CA issued it: clients that trust the old one’s CA reject it unless it is added to their trust store one by one.',
  'cdiff.c.expired.title': 'Already expired',
  'cdiff.c.expired.body': 'It expired on {date}: every client rejects it.',
  'cdiff.c.not-yet-valid.title': 'Not valid yet',
  'cdiff.c.not-yet-valid.body': 'It is valid only from {date}: deployed before then, every client rejects it until that date.',
  'cdiff.c.gap.title': 'No overlap with the old one',
  'cdiff.c.gap.body': {
    one: 'The old one expires on {from} and the new one is valid only from {to}: for {count} day neither works.',
    other: 'The old one expires on {from} and the new one is valid only from {to}: for {count} days neither works.'
  },
  'cdiff.c.name-removed.title': { one: '{count} name no longer covered', other: '{count} names no longer covered' },
  'cdiff.c.name-removed.body': 'Servers that serve these names with the old certificate break with the new one: keep the old one there, or get a certificate that covers them.',
  'cdiff.c.wildcard-removed.title': 'Wildcard {name} goes',
  'cdiff.c.wildcard-removed.body': 'Hosts directly under {domain} that the new certificate does not name one by one break on the servers that serve them with it.',
  'cdiff.c.no-san.title': 'No subjectAltName',
  'cdiff.c.no-san.body': 'It names its host only in the common name, which browsers ignore: they reject it for every name.',
  'cdiff.c.eku-server-dropped.title': 'Not for TLS servers',
  'cdiff.c.eku-server-dropped.body': 'Its extended key usage leaves out serverAuth: browsers and other TLS clients reject it as a server certificate.',
  'cdiff.c.eku-client-dropped.title': 'clientAuth dropped',
  'cdiff.c.eku-client-dropped.body': 'Servers that present this certificate as a TLS client — mutual TLS to partners or APIs, SMTP relays, VPN or cluster peers — fail with it. Public CAs stop issuing clientAuth in 2026 (the Chrome Root Program wants TLS hierarchies for servers only): take client certificates from a private CA.',
  'cdiff.c.ku-signature-dropped.title': 'digitalSignature dropped',
  'cdiff.c.ku-signature-dropped.body': 'Its key usage leaves out digitalSignature: ECDHE and TLS 1.3 handshakes, which sign with the key, fail in clients that check key usage.',
  'cdiff.c.key-unsupported.title': '{key} key',
  'cdiff.c.key-unsupported.body': 'Browsers do not accept {key} server certificates: keep an RSA or EC (P-256, P-384) certificate for them.',
  'cdiff.c.key-weak.title': 'Weak key: {key}',
  'cdiff.c.key-weak.body': 'Current browsers and public CAs refuse RSA keys under 2048 bits.',
  'cdiff.c.key-curve.title': 'Curve {curve}',
  'cdiff.c.key-curve.body': 'Browsers accept P-256 and P-384 server keys; a {curve} key fails in at least one of them.',
  'cdiff.c.sig-weak.title': 'Weak signature: {alg}',
  'cdiff.c.sig-weak.body': 'Browsers reject certificates signed with SHA-1 or MD5.',
  'cdiff.c.sct-none.title': 'No SCTs',
  'cdiff.c.sct-none.body': {
    one: 'The old one carried {count} SCT, the new one none: Chrome and Safari reject a public certificate without SCTs unless every server sends them in the TLS handshake or a stapled OCSP response.',
    other: 'The old one carried {count} SCTs, the new one none: Chrome and Safari reject a public certificate without SCTs unless every server sends them in the TLS handshake or a stapled OCSP response.'
  },
  'cdiff.c.staple-no-ocsp.title': 'Must-staple without OCSP',
  'cdiff.c.staple-no-ocsp.body': 'It demands a stapled OCSP response but names no OCSP responder: no server can staple one, and Firefox rejects it everywhere.',
  'cdiff.c.issuer-changed.title': 'Another issuer: {from} → {to}',
  'cdiff.c.issuer-changed.body': 'The intermediate the servers send must change with it: deploy the new chain (fullchain), not the leaf alone. A server that keeps the old intermediate sends a broken chain: browsers may repair it, apps, Java, curl and other clients fail.',
  'cdiff.c.issuer-rekeyed.title': 'Same issuer name, another key',
  'cdiff.c.issuer-rekeyed.body': '{issuer} signed it with another key (a re-issued intermediate): the old intermediate does not verify it. Deploy the new chain with it.',
  'cdiff.c.chain-changed.title': 'Other intermediates in the file',
  'cdiff.c.chain-changed.body': 'The same issuer, but the new file’s chain differs: deploy it as it comes.',
  'cdiff.c.key-type.title': 'Key type: {from} → {to}',
  'cdiff.c.key-type.bodyEc': 'Servers whose TLS 1.2 cipher list has only RSA suites (ECDHE-RSA-…) cannot use an EC key: add the ECDSA suites (TLS 1.3 needs nothing). Some appliances take an EC key in a setting of its own; clients without ECDSA support (very old ones) fail.',
  'cdiff.c.key-type.bodyRsa': 'Servers whose TLS 1.2 cipher list has only ECDSA suites (ECDHE-ECDSA-…) cannot use an RSA key: add the RSA suites (ECDHE-RSA-…; TLS 1.3 needs nothing).',
  'cdiff.c.staple-added.title': 'OCSP must-staple added',
  'cdiff.c.staple-added.body': 'Every server must staple OCSP responses (nginx ssl_stapling on, Apache SSLUseStapling on, …): Firefox refuses it from a server that does not.',
  'cdiff.c.key-new.title': 'A new key',
  'cdiff.c.key-new.body': 'Install its own private key with it. TLSA 3 1 1 records and key pins made from the old key stop matching at the switch: publish the new key’s hash first (the DANE / TLSA tab checks the records).',
  'cdiff.c.root-changed.title': 'Another root: {from} → {to}',
  'cdiff.c.root-changed.body': 'The chain ends at another root: clients whose trust store lacks it — old Android, Java or embedded devices, pinned stores — fail.',
  'cdiff.c.sct-few.title': 'Fewer SCTs than the CT policies ask for',
  'cdiff.c.sct-few.body': {
    one: '{count} SCT: Chrome and Safari ask for {need} for a certificate of this lifetime; unless the servers send the rest (TLS extension or stapled OCSP), they may reject it.',
    other: '{count} SCTs: Chrome and Safari ask for {need} for a certificate of this lifetime; unless the servers send the rest (TLS extension or stapled OCSP), they may reject it.'
  },
  'cdiff.c.ku-encipher-dropped.title': 'keyEncipherment dropped',
  'cdiff.c.ku-encipher-dropped.body': 'TLS 1.2 RSA key exchange (TLS_RSA_… suites, without ECDHE) stops working with it; ECDHE and TLS 1.3 are not affected. Only old clients still use RSA key exchange.',
  'cdiff.c.ocsp-changed.title': 'Another OCSP responder',
  'cdiff.c.ocsp-changed.body': 'Servers that staple OCSP fetch responses from {hosts} now: let them reach it through outbound firewalls and proxies.',
  'cdiff.c.ocsp-changed.bodySameHost': 'Servers that staple OCSP fetch responses from the new URL, on the same host.',
  'cdiff.c.old-expired.title': 'The old one has expired',
  'cdiff.c.old-expired.body': 'It expired on {date}: the switch is overdue.',
  'cdiff.c.name-added.title': { one: '{count} name added', other: '{count} names added' },
  'cdiff.c.name-added.body': 'The new certificate also covers these: servers can serve them with it.',
  'cdiff.c.name-covered.title': { one: '{count} name now covered by a wildcard', other: '{count} names now covered by a wildcard' },
  'cdiff.c.name-covered.body': 'The new certificate no longer names these one by one, but a wildcard covers them.',
  'cdiff.c.key-reused.title': 'The same key',
  'cdiff.c.key-reused.body': 'The servers’ private key works with it, and TLSA 3 1 1 records and key pins keep matching. If the old key may have leaked, this renewal does not replace it.',
  'cdiff.c.key-size.title': 'Key size: {from} → {to}',
  'cdiff.c.key-size.body': 'Both are sizes browsers accept; a larger key costs more CPU per handshake.',
  'cdiff.c.lifetime.title': 'Lifetime: {from} → {to} days',
  'cdiff.c.lifetime.bodyShorter': 'Renewals come more often: public certificates are capped at 200 days from 2026-03-15, 100 days from 2027-03-15 and 47 days from 2029-03-15 (CA/Browser Forum ballot SC-081). Automate the renewal.',
  'cdiff.c.lifetime.bodyLonger': 'The new one lasts longer: monitoring and reminders follow its date.',
  'cdiff.c.expires-sooner.title': 'Expires before the old one',
  'cdiff.c.expires-sooner.body': 'The new one expires on {new}, the old one on {old}: renewal reminders and monitoring must follow the new date.',
  'cdiff.c.sig-changed.title': 'Signature: {from} → {to}',
  'cdiff.c.sig-changed.body': 'The CA signs with another algorithm; current clients verify both.',
  'cdiff.c.eku-changed.title': 'Extended key usage changes',
  'cdiff.c.eku-changed.body': 'Usages other than TLS server and client: no effect on HTTPS.',
  'cdiff.c.ku-changed.title': 'Key usage changes',
  'cdiff.c.ku-changed.body': 'The other key usage bits do not affect TLS handshakes with this key.',
  'cdiff.c.sct-count.title': 'SCTs: {from} → {to}',
  'cdiff.c.sct-count.body': 'The number of embedded SCTs (Certificate Transparency logs’ promises to publish the certificate) changes.',
  'cdiff.c.old-precert.title': 'The old one is a precertificate',
  'cdiff.c.old-precert.body': 'It came from Certificate Transparency as a precertificate, which carries no SCTs: SCTs are not compared.',
  'cdiff.c.staple-removed.title': 'OCSP must-staple removed',
  'cdiff.c.staple-removed.body': 'Servers no longer have to staple OCSP responses for it.',
  'cdiff.c.ocsp-removed.title': 'No OCSP responder',
  'cdiff.c.ocsp-removed.body': 'OCSP stapling stops with it (turn it off to silence the servers’ warnings); clients check revocation by CRL, if at all. Some CAs no longer run OCSP.',
  'cdiff.c.ocsp-added.title': 'An OCSP responder',
  'cdiff.c.ocsp-added.body': 'Servers can staple OCSP responses for it, fetched from {to}.',
  'cdiff.c.crl-changed.title': 'CRL URLs change',
  'cdiff.c.crl-changed.body': 'Clients that check revocation by CRL fetch it from the new URL.',
  'cdiff.c.aia-changed.title': 'CA Issuers URLs change',
  'cdiff.c.aia-changed.body': 'Clients that fetch a missing intermediate (AIA) follow the new URL.',
  'cdiff.c.level-changed.title': 'Validation level: {from} → {to}',
  'cdiff.c.level-changed.body': 'What the CA checked about the subject changes; browsers show no difference.',
  'cdiff.c.subject-changed.title': 'Subject changes',
  'cdiff.c.subject-changed.body': '{from} → {to}. Clients match the names, not the subject.'
});

registerStrings('tr', {
  'cdiff.title': 'Başka bir sertifikayla karşılaştır',
  'cdiff.intro': 'Bunun yerini aldığı ya da yerine geçecek sertifikayı yükleyin: her fark, geçiş için ne anlama geldiğiyle birlikte, en ciddisi başta olmak üzere listelenir. Dosyalar tarayıcınızda okunur; sorgu yalnızca host adını gönderir.',
  'cdiff.other': 'Diğer sertifika',
  'cdiff.dropTitle': 'Diğer sertifikayı buraya bırakın',
  'cdiff.another': 'Başka birini yükle',
  'cdiff.ct.label': 'Ya da bir host adının Certificate Transparency’deki en yeni sertifikası',
  'cdiff.ct.load': 'Sorgula',
  'cdiff.ct.hint': 'Yalnızca host adını Cert Spotter’a (yanıt veremezse crt.sh’e) gönderir. En yeni sertifika zaten yenisi olabilir.',
  'cdiff.ct.searching': 'Certificate Transparency’de sorgulanıyor: {host}…',
  'cdiff.ct.invalid': 'www.example.com gibi bir host adı girin.',
  'cdiff.ct.failed': 'Certificate Transparency yanıt vermedi',
  'cdiff.ct.manualTitle': 'crt.sh’de bulundu: indirip dosyayı yukarıya bırakın',
  'cdiff.ct.download': '#{id} indir',
  'cdiff.ct.open': 'crt.sh’de aç',
  'cdiff.noLeaf': '{name} dosyasında sunucu sertifikası yok: sertifikanın kendisini içeren bir dosya yükleyin.',
  'cdiff.comparing': 'Karşılaştırılıyor…',
  'cdiff.old': 'Eski',
  'cdiff.new': 'Yeni',
  'cdiff.this': 'bu sertifika',
  'cdiff.order': 'Önce verilen eski sayılır.',
  'cdiff.orderSwapped': 'Yer değiştirildi: sonra verilen eski sayılıyor (geri dönüş).',
  'cdiff.swap': 'Eski ile yeniyi değiştir',
  'cdiff.remove': 'Kaldır',
  'cdiff.removed': 'Diğer sertifika kaldırıldı',
  'cdiff.copy': 'Metin olarak kopyala',
  'cdiff.report': 'Sertifika karşılaştırması: {old} → {new}',
  'cdiff.row.cert': 'Sertifika',
  'cdiff.row.issuer': 'Veren',
  'cdiff.row.valid': 'Geçerlilik',
  'cdiff.row.lifetime': 'Ömür',
  'cdiff.row.left': 'Kalan',
  'cdiff.row.key': 'Anahtar',
  'cdiff.row.spki': 'Anahtar SHA-256 (SPKI)',
  'cdiff.row.sig': 'İmza',
  'cdiff.row.names': 'Adlar',
  'cdiff.row.scts': 'SCT',
  'cdiff.row.staple': 'Must-staple',
  'cdiff.row.ocsp': 'OCSP',
  'cdiff.row.chain': 'Dosyadaki ara sertifikalar',
  'cdiff.days': { one: '{count} gün', other: '{count} gün' },
  'cdiff.left': { one: '{count} gün kaldı', other: '{count} gün kaldı' },
  'cdiff.leftExpired': { one: '{count} gün önce doldu', other: '{count} gün önce doldu' },
  'cdiff.leftNotYet': '{date} tarihinden itibaren geçerli',
  'cdiff.overlap': {
    one: 'İkisi de {from} – {to} arasında geçerli: geçiş için {count} gün var.',
    other: 'İkisi de {from} – {to} arasında geçerli: geçiş için {count} gün var.'
  },
  'cdiff.noOverlap': 'İkisi hiçbir zaman aynı anda geçerli değil.',
  'cdiff.still': 'Adıyla kapsanmaya devam edenler:',
  'cdiff.coveredBy': '{by} ile',
  'cdiff.added': 'Eklenen:',
  'cdiff.removedList': 'Kaldırılan:',
  'cdiff.newChain': 'Yeni dosyadaki ara sertifikalar: {list}.',
  'cdiff.missingChain': 'Yeni dosyada ara sertifika yok: CA’dan alın ya da yeni dosyayı bu görünümde açın; Zincir sekmesi eksik ara sertifikayı bulur.',
  'cdiff.openDane': 'DANE / TLSA sekmesini aç',
  'cdiff.unchanged': 'Değişmeyenler: {list}.',
  'cdiff.none': 'yok',
  'cdiff.inFile': 'dosyada yok',

  'cdiff.sev.blocker': 'Engel',
  'cdiff.sev.action': 'Adım',
  'cdiff.sev.check': 'Kontrol',
  'cdiff.sev.info': 'Bilgi',
  'cdiff.group.blocker': 'Engeller',
  'cdiff.group.action': 'Sunucularda yapılacaklar',
  'cdiff.group.check': 'Geçişten önce kontrol edin',
  'cdiff.group.info': 'Diğer farklar',
  'cdiff.area.names': 'adlar',
  'cdiff.area.key': 'anahtar',
  'cdiff.area.chain': 'veren ve zincir',
  'cdiff.area.signature': 'imza',
  'cdiff.area.usage': 'anahtar kullanımı',
  'cdiff.area.ct': 'SCT’ler',
  'cdiff.area.revocation': 'OCSP ve CRL',
  'cdiff.area.subject': 'konu',

  'cdiff.verdict.identical': 'Aynı sertifika',
  'cdiff.verdict.identical.body': 'İkisinde de bu sertifika var: hiçbir şey değişmiyor. Diğerini bir dosyadan yükleyin ya da başka bir host adını sorgulayın.',
  'cdiff.verdict.blocked': { one: 'Doğrudan yerine konamaz: {count} engel', other: 'Doğrudan yerine konamaz: {count} engel' },
  'cdiff.verdict.blocked.body': 'Eskisinin olduğu her yere kurulursa bugün çalışan bir şeyi bozar. Aşağıdaki engelleri giderin ya da önemli oldukları yerlerde eskisini tutun.',
  'cdiff.verdict.steps': {
    one: 'Eskisinin olduğu her yere kurulabilir; sunucularda {count} değişiklikle',
    other: 'Eskisinin olduğu her yere kurulabilir; sunucularda {count} değişiklikle'
  },
  'cdiff.verdict.steps.body': 'Sunucular aşağıdaki değişiklikleri onunla birlikte alırsa hiçbir şey bozulmaz.',
  'cdiff.verdict.check': {
    one: 'Eskisinin olduğu her yere kurulabilir; önce kontrol edilecek {count} konu var',
    other: 'Eskisinin olduğu her yere kurulabilir; önce kontrol edilecek {count} konu var'
  },
  'cdiff.verdict.check.body': 'Sertifikalarda engel yok; sertifikaların gösteremediği şeyler aşağıda.',
  'cdiff.verdict.safe': 'Eskisinin olduğu her yere güvenle kurulabilir',
  'cdiff.verdict.safe.body': 'Eskisiyle çalışan hiçbir şey yenisiyle bozulmaz.',

  'cdiff.c.precert.title': 'Sertifika değil, ön sertifika',
  'cdiff.c.precert.body': 'Bu, CA’nın sertifikayı vermeden önce CT kayıtlarına yazdığı ön sertifika (CT poison uzantısı): hiçbir istemci kabul etmez. CA’nın teslim ettiği sertifikayı kurun.',
  'cdiff.c.new-is-ca.title': 'Sunucu sertifikası değil, CA sertifikası',
  'cdiff.c.new-is-ca.body': 'Yeni dosyadaki sertifika bir CA sertifikası: sunucular bunu kendi adları için kullanamaz. Yeni dosyanın sunucu sertifikasını yükleyin.',
  'cdiff.c.self-signed.title': 'Kendinden imzalı',
  'cdiff.c.self-signed.body': 'Hiçbir CA vermemiş: eskisinin CA’sına güvenen istemciler, güven depolarına tek tek eklenmedikçe bunu reddeder.',
  'cdiff.c.expired.title': 'Süresi dolmuş',
  'cdiff.c.expired.body': '{date} tarihinde süresi doldu: her istemci reddeder.',
  'cdiff.c.not-yet-valid.title': 'Henüz geçerli değil',
  'cdiff.c.not-yet-valid.body': 'Ancak {date} tarihinden itibaren geçerli: daha önce kurulursa o tarihe kadar her istemci reddeder.',
  'cdiff.c.gap.title': 'Eskisiyle çakışan süre yok',
  'cdiff.c.gap.body': {
    one: 'Eskisinin süresi {from} tarihinde doluyor, yenisi ancak {to} tarihinde geçerli oluyor: {count} gün boyunca hiçbiri çalışmaz.',
    other: 'Eskisinin süresi {from} tarihinde doluyor, yenisi ancak {to} tarihinde geçerli oluyor: {count} gün boyunca hiçbiri çalışmaz.'
  },
  'cdiff.c.name-removed.title': { one: 'Artık kapsanmayan {count} ad', other: 'Artık kapsanmayan {count} ad' },
  'cdiff.c.name-removed.body': 'Bu adları eski sertifikayla sunan sunucular yenisiyle bozulur: oralarda eskisini tutun ya da bu adları kapsayan bir sertifika alın.',
  'cdiff.c.wildcard-removed.title': 'Wildcard {name} kalkıyor',
  'cdiff.c.wildcard-removed.body': '{domain} alan adının hemen altındaki, yeni sertifikanın tek tek adlandırmadığı host’lar, onları bu sertifikayla sunan sunucularda bozulur.',
  'cdiff.c.no-san.title': 'subjectAltName yok',
  'cdiff.c.no-san.body': 'Host adını yalnızca ortak adda (CN) veriyor; tarayıcılar bunu yok sayar ve sertifikayı her ad için reddeder.',
  'cdiff.c.eku-server-dropped.title': 'TLS sunucuları için değil',
  'cdiff.c.eku-server-dropped.body': 'Genişletilmiş anahtar kullanımında serverAuth yok: tarayıcılar ve diğer TLS istemcileri bunu sunucu sertifikası olarak reddeder.',
  'cdiff.c.eku-client-dropped.title': 'clientAuth kaldırıldı',
  'cdiff.c.eku-client-dropped.body': 'Bu sertifikayı TLS istemcisi olarak sunan sunucular — iş ortaklarına ya da API’lere karşılıklı TLS, SMTP aktarıcıları, VPN ya da küme eşleri — onunla başarısız olur. Herkese açık CA’lar 2026’da clientAuth vermeyi bırakıyor (Chrome Root Program, TLS hiyerarşilerinin yalnızca sunuculara ayrılmasını istiyor): istemci sertifikalarını özel bir CA’dan alın.',
  'cdiff.c.ku-signature-dropped.title': 'digitalSignature kaldırıldı',
  'cdiff.c.ku-signature-dropped.body': 'Anahtar kullanımında digitalSignature yok: anahtarla imza atan ECDHE ve TLS 1.3 el sıkışmaları, anahtar kullanımını denetleyen istemcilerde başarısız olur.',
  'cdiff.c.key-unsupported.title': '{key} anahtarı',
  'cdiff.c.key-unsupported.body': 'Tarayıcılar {key} sunucu sertifikalarını kabul etmez: onlar için bir RSA ya da EC (P-256, P-384) sertifikası tutun.',
  'cdiff.c.key-weak.title': 'Zayıf anahtar: {key}',
  'cdiff.c.key-weak.body': 'Güncel tarayıcılar ve herkese açık CA’lar 2048 bitten kısa RSA anahtarlarını reddeder.',
  'cdiff.c.key-curve.title': '{curve} eğrisi',
  'cdiff.c.key-curve.body': 'Tarayıcılar P-256 ve P-384 sunucu anahtarlarını kabul eder; {curve} eğrisindeki bir anahtar en az birinde başarısız olur.',
  'cdiff.c.sig-weak.title': 'Zayıf imza: {alg}',
  'cdiff.c.sig-weak.body': 'Tarayıcılar SHA-1 ya da MD5 ile imzalanmış sertifikaları reddeder.',
  'cdiff.c.sct-none.title': 'SCT yok',
  'cdiff.c.sct-none.body': {
    one: 'Eskisinde {count} SCT vardı, yenisinde hiç yok: Chrome ve Safari, her sunucu SCT’leri TLS el sıkışmasında ya da zımbalanmış OCSP yanıtında göndermedikçe SCT’siz herkese açık bir sertifikayı reddeder.',
    other: 'Eskisinde {count} SCT vardı, yenisinde hiç yok: Chrome ve Safari, her sunucu SCT’leri TLS el sıkışmasında ya da zımbalanmış OCSP yanıtında göndermedikçe SCT’siz herkese açık bir sertifikayı reddeder.'
  },
  'cdiff.c.staple-no-ocsp.title': 'OCSP’siz must-staple',
  'cdiff.c.staple-no-ocsp.body': 'Zımbalanmış bir OCSP yanıtı istiyor ama hiçbir OCSP sunucusu belirtmiyor: hiçbir sunucu yanıt zımbalayamaz ve Firefox onu her yerde reddeder.',
  'cdiff.c.issuer-changed.title': 'Başka bir veren: {from} → {to}',
  'cdiff.c.issuer-changed.body': 'Sunucuların gönderdiği ara sertifika da onunla birlikte değişmeli: yalnızca uç sertifikayı değil, yeni zinciri (fullchain) kurun. Eski ara sertifikayı tutan bir sunucu bozuk bir zincir gönderir: tarayıcılar bunu kendileri onarabilir, uygulamalar, Java, curl ve diğer istemciler başarısız olur.',
  'cdiff.c.issuer-rekeyed.title': 'Aynı veren adı, başka anahtar',
  'cdiff.c.issuer-rekeyed.body': '{issuer} adlı CA onu başka bir anahtarla imzaladı (yeniden verilmiş bir ara sertifika): eski ara sertifika onu doğrulamaz. Yeni zinciri onunla birlikte kurun.',
  'cdiff.c.chain-changed.title': 'Dosyada başka ara sertifikalar',
  'cdiff.c.chain-changed.body': 'Veren aynı ama yeni dosyanın zinciri farklı: onu geldiği gibi kurun.',
  'cdiff.c.key-type.title': 'Anahtar türü: {from} → {to}',
  'cdiff.c.key-type.bodyEc': 'TLS 1.2 şifre listesinde yalnızca RSA takımları (ECDHE-RSA-…) olan sunucular EC anahtarı kullanamaz: ECDSA takımlarını ekleyin (TLS 1.3 için bir şey gerekmez). Bazı cihazlar EC anahtarını ayrı bir ayarda ister; ECDSA desteklemeyen (çok eski) istemciler başarısız olur.',
  'cdiff.c.key-type.bodyRsa': 'TLS 1.2 şifre listesinde yalnızca ECDSA takımları (ECDHE-ECDSA-…) olan sunucular RSA anahtarı kullanamaz: RSA takımlarını (ECDHE-RSA-…) ekleyin (TLS 1.3 için bir şey gerekmez).',
  'cdiff.c.staple-added.title': 'OCSP must-staple eklendi',
  'cdiff.c.staple-added.body': 'Her sunucu OCSP yanıtlarını zımbalamalı (nginx ssl_stapling on, Apache SSLUseStapling on, …): Firefox, zımbalamayan bir sunucudan gelen sertifikayı reddeder.',
  'cdiff.c.key-new.title': 'Yeni bir anahtar',
  'cdiff.c.key-new.body': 'Onunla birlikte kendi özel anahtarını kurun. Eski anahtardan yapılmış TLSA 3 1 1 kayıtları ve anahtar sabitlemeleri (pin) geçişte eşleşmez olur: önce yeni anahtarın özetini yayımlayın (DANE / TLSA sekmesi kayıtları kontrol eder).',
  'cdiff.c.root-changed.title': 'Başka bir kök: {from} → {to}',
  'cdiff.c.root-changed.body': 'Zincir başka bir kökte bitiyor: güven deposunda bu kök olmayan istemciler — eski Android, Java ya da gömülü cihazlar, sabitlenmiş depolar — başarısız olur.',
  'cdiff.c.sct-few.title': 'CT politikalarının istediğinden az SCT',
  'cdiff.c.sct-few.body': {
    one: '{count} SCT var: Chrome ve Safari bu ömürdeki bir sertifika için {need} SCT ister; sunucular gerisini (TLS uzantısı ya da zımbalanmış OCSP ile) göndermezse reddedebilirler.',
    other: '{count} SCT var: Chrome ve Safari bu ömürdeki bir sertifika için {need} SCT ister; sunucular gerisini (TLS uzantısı ya da zımbalanmış OCSP ile) göndermezse reddedebilirler.'
  },
  'cdiff.c.ku-encipher-dropped.title': 'keyEncipherment kaldırıldı',
  'cdiff.c.ku-encipher-dropped.body': 'TLS 1.2 RSA anahtar değişimi (ECDHE’siz TLS_RSA_… takımları) onunla çalışmaz; ECDHE ve TLS 1.3 etkilenmez. RSA anahtar değişimini yalnızca eski istemciler kullanır.',
  'cdiff.c.ocsp-changed.title': 'Başka bir OCSP sunucusu',
  'cdiff.c.ocsp-changed.body': 'OCSP zımbalayan sunucular yanıtları artık şu host’tan alır: {hosts}. Giden trafik güvenlik duvarlarında ve proxy’lerde ona izin verin.',
  'cdiff.c.ocsp-changed.bodySameHost': 'OCSP zımbalayan sunucular yanıtları aynı host’taki yeni adresten alır.',
  'cdiff.c.old-expired.title': 'Eskisinin süresi dolmuş',
  'cdiff.c.old-expired.body': '{date} tarihinde süresi doldu: geçiş gecikti.',
  'cdiff.c.name-added.title': { one: '{count} ad eklendi', other: '{count} ad eklendi' },
  'cdiff.c.name-added.body': 'Yeni sertifika bunları da kapsıyor: sunucular bunları onunla sunabilir.',
  'cdiff.c.name-covered.title': { one: 'Artık Wildcard ile kapsanan {count} ad', other: 'Artık Wildcard ile kapsanan {count} ad' },
  'cdiff.c.name-covered.body': 'Yeni sertifika bunları artık tek tek adlandırmıyor ama bir Wildcard onları kapsıyor.',
  'cdiff.c.key-reused.title': 'Aynı anahtar',
  'cdiff.c.key-reused.body': 'Sunuculardaki özel anahtar onunla çalışır; TLSA 3 1 1 kayıtları ve anahtar sabitlemeleri eşleşmeye devam eder. Eski anahtar sızmış olabilirse bu yenileme onu değiştirmez.',
  'cdiff.c.key-size.title': 'Anahtar boyutu: {from} → {to}',
  'cdiff.c.key-size.body': 'İkisi de tarayıcıların kabul ettiği boyutlar; büyük anahtar el sıkışma başına daha çok işlemci harcar.',
  'cdiff.c.lifetime.title': 'Ömür: {from} → {to} gün',
  'cdiff.c.lifetime.bodyShorter': 'Yenilemeler daha sık gelir: herkese açık sertifikaların ömrü 2026-03-15’ten itibaren en çok 200, 2027-03-15’ten itibaren 100, 2029-03-15’ten itibaren 47 gün (CA/Browser Forum SC-081 kararı). Yenilemeyi otomatikleştirin.',
  'cdiff.c.lifetime.bodyLonger': 'Yenisi daha uzun ömürlü: izleme ve hatırlatmalar onun tarihini izler.',
  'cdiff.c.expires-sooner.title': 'Eskisinden önce sona eriyor',
  'cdiff.c.expires-sooner.body': 'Yenisinin süresi {new} tarihinde, eskisininki {old} tarihinde doluyor: yenileme hatırlatmaları ve izleme yeni tarihi izlemeli.',
  'cdiff.c.sig-changed.title': 'İmza: {from} → {to}',
  'cdiff.c.sig-changed.body': 'CA başka bir algoritmayla imzalıyor; güncel istemciler ikisini de doğrular.',
  'cdiff.c.eku-changed.title': 'Genişletilmiş anahtar kullanımı değişiyor',
  'cdiff.c.eku-changed.body': 'TLS sunucusu ve istemcisi dışındaki kullanımlar: HTTPS’e etkisi yok.',
  'cdiff.c.ku-changed.title': 'Anahtar kullanımı değişiyor',
  'cdiff.c.ku-changed.body': 'Diğer anahtar kullanımı bitleri bu anahtarla TLS el sıkışmalarını etkilemez.',
  'cdiff.c.sct-count.title': 'SCT: {from} → {to}',
  'cdiff.c.sct-count.body': 'Gömülü SCT sayısı (Certificate Transparency kayıtlarının sertifikayı yayımlama sözü) değişiyor.',
  'cdiff.c.old-precert.title': 'Eskisi bir ön sertifika',
  'cdiff.c.old-precert.body': 'Certificate Transparency’den ön sertifika olarak geldi; ön sertifikada SCT olmaz: SCT’ler karşılaştırılmadı.',
  'cdiff.c.staple-removed.title': 'OCSP must-staple kaldırıldı',
  'cdiff.c.staple-removed.body': 'Sunucuların onun için OCSP yanıtı zımbalaması artık gerekmiyor.',
  'cdiff.c.ocsp-removed.title': 'OCSP sunucusu yok',
  'cdiff.c.ocsp-removed.body': 'Onunla OCSP zımbalama durur (sunucuların uyarılarını susturmak için kapatın); istemciler iptal durumuna, bakarlarsa, CRL ile bakar. Bazı CA’lar artık OCSP çalıştırmıyor.',
  'cdiff.c.ocsp-added.title': 'Bir OCSP sunucusu',
  'cdiff.c.ocsp-added.body': 'Sunucular onun için OCSP yanıtı zımbalayabilir; yanıtlar şu adresten alınır: {to}.',
  'cdiff.c.crl-changed.title': 'CRL adresleri değişiyor',
  'cdiff.c.crl-changed.body': 'İptal durumuna CRL ile bakan istemciler onu yeni adresten alır.',
  'cdiff.c.aia-changed.title': 'CA Issuers adresleri değişiyor',
  'cdiff.c.aia-changed.body': 'Eksik ara sertifikayı AIA ile indiren istemciler yeni adresi izler.',
  'cdiff.c.level-changed.title': 'Doğrulama düzeyi: {from} → {to}',
  'cdiff.c.level-changed.body': 'CA’nın sahip hakkında doğruladıkları değişiyor; tarayıcılar fark göstermez.',
  'cdiff.c.subject-changed.title': 'Konu (subject) değişiyor',
  'cdiff.c.subject-changed.body': '{from} → {to}. İstemciler konuyu değil adları eşleştirir.'
});

/** Badge variant per severity. */
const SEVERITY_VARIANT = Object.freeze({ blocker: 'error', action: 'warn', check: 'info', info: 'neutral' });
/** Alert variant per verdict. */
const VERDICT_VARIANT = Object.freeze({ identical: 'info', blocked: 'error', steps: 'warn', check: 'info', safe: 'success' });
/** The codes whose body has variants, by the key suffixes they use. */
const BODY_VARIANTS = Object.freeze({ 'key-type': ['bodyEc', 'bodyRsa'], lifetime: ['bodyShorter', 'bodyLonger'], 'ocsp-changed': ['body', 'bodySameHost'] });
/** The codes whose added / removed lists are shown under them. */
const LIST_CODES = Object.freeze(['chain-changed', 'eku-changed', 'ku-changed', 'crl-changed', 'aia-changed']);

/**
 * What the tab holds for the page session: the other certificate, whether old and new are swapped,
 * the host name field, the last lookup outcome that is not a certificate, the lookup that runs, why
 * the last file could not be compared, and the panel on screen (the newest one).
 */
const memory = { other: null, swapped: false, host: null, outcome: null, job: null, problem: null, view: null };

/** Forget everything (Delete all local data, another workspace), stopping a lookup. */
function forget() {
  if (memory.job) memory.job.ctl.abort();
  Object.assign(memory, { other: null, swapped: false, host: null, outcome: null, job: null, problem: null });
}
stateSingleton.subscribe(({ key }) => {
  if (key === 'cleared' || key === 'workspace') forget();
});

/**
 * Every i18n key the panel builds from a library code (for the i18n coverage test).
 * @returns {string[]}
 */
export function generatedKeys() {
  const keys = [];
  for (const code of CERTDIFF_CODES) {
    keys.push(`cdiff.c.${code}.title`);
    for (const v of BODY_VARIANTS[code] || ['body']) keys.push(`cdiff.c.${code}.${v}`);
  }
  for (const s of CERTDIFF_SEVERITIES) keys.push(`cdiff.sev.${s}`, `cdiff.group.${s}`);
  for (const v of CERTDIFF_VERDICTS) keys.push(`cdiff.verdict.${v}`, `cdiff.verdict.${v}.body`);
  for (const a of CERTDIFF_AREAS) if (a !== 'identity' && a !== 'validity') keys.push(`cdiff.area.${a}`);
  return keys;
}

/** The i18n key of a change's explanation. */
function bodyKey(c) {
  if (c.code === 'key-type') return `cdiff.c.key-type.${c.params.ec ? 'bodyEc' : 'bodyRsa'}`;
  if (c.code === 'lifetime') return `cdiff.c.lifetime.${c.params.shorter ? 'bodyShorter' : 'bodyLonger'}`;
  if (c.code === 'ocsp-changed') return `cdiff.c.ocsp-changed.${c.params.hosts && c.params.hosts.length ? 'body' : 'bodySameHost'}`;
  return `cdiff.c.${c.code}.body`;
}

/** A change's values as its strings take them: dates and numbers formatted, lists joined, `count` for the plurals. */
function words(c) {
  const out = {};
  for (const [k, v] of Object.entries(c.params || {})) {
    if (v instanceof Date) out[k] = formatDate(v);
    else if (Array.isArray(v)) out[k] = v.join(', ');
    else if (typeof v === 'number') out[k] = formatNumber(v);
    else if (v === null || v === undefined) out[k] = t('cdiff.none');
    else out[k] = String(v);
  }
  if (c.code === 'wildcard-removed') out.domain = String(c.params.name || '').replace(/^\*\./, '');
  if (c.items && c.items.length) out.count = c.items.length;
  if (c.code === 'gap') out.count = c.params.days;
  if (c.code === 'sct-none') out.count = c.params.from;
  if (c.code === 'sct-few') out.count = c.params.count;
  return out;
}

/** The title of a change. */
const changeTitle = (c) => t(`cdiff.c.${c.code}.title`, words(c));
/** The explanation of a change. */
const changeBody = (c) => t(bodyKey(c), words(c));
/** One item of a change's list as text: a name, or a name and the wildcard that covers it. */
const itemText = (x) => (typeof x === 'string' ? x : `${x.name} (${t('cdiff.coveredBy', { by: x.by })})`);

/** The verdict line. */
function verdictTitle(diff) {
  const count = diff.verdict === 'blocked' ? diff.counts.blocker : diff.verdict === 'steps' ? diff.counts.action : diff.counts.check;
  return t(`cdiff.verdict.${diff.verdict}`, { count });
}

/** Days left as words: left, expired, or not valid yet. */
function leftText(days, cert, now) {
  if (cert.notBefore.getTime() > now) return t('cdiff.leftNotYet', { date: formatDate(cert.notBefore) });
  return days < 0 ? t('cdiff.leftExpired', { count: -days }) : t('cdiff.left', { count: days });
}

/**
 * The comparison as plain text, for a change ticket: both certificates, the verdict, every
 * change with its explanation.
 * @param {import('../lib/certdiff.js').CertDiff} diff
 * @param {{ cert: object }} o the old side
 * @param {{ cert: object }} n the new side
 * @param {{ certName: (c: object) => string, issuerName: (c: object) => string }} kit
 * @returns {string}
 */
export function diffReport(diff, o, n, kit) {
  const side = (label, s, days) => `${label}: ${kit.certName(s.cert)} · ${kit.issuerName(s.cert)} · ${formatDate(s.cert.notBefore)} – ${formatDate(s.cert.notAfter)}`
    + ` (${leftText(days, s.cert, diff.validity.now.getTime())}) · ${keyLabel(s.cert)}`;
  const lines = [
    t('cdiff.report', { old: kit.certName(o.cert), new: kit.certName(n.cert) }),
    side(t('cdiff.old'), o, diff.validity.oldDaysLeft),
    side(t('cdiff.new'), n, diff.validity.newDaysLeft),
    '',
    verdictTitle(diff)
  ];
  for (const sev of CERTDIFF_SEVERITIES) {
    const group = diff.changes.filter((c) => c.severity === sev);
    if (!group.length) continue;
    lines.push('', `${t(`cdiff.group.${sev}`)}:`);
    for (const c of group) {
      const items = c.items.length ? `: ${c.items.map(itemText).join(', ')}` : '';
      lines.push(`- ${changeTitle(c)}${items} — ${changeBody(c)}`);
    }
  }
  if (diff.unchanged.length) lines.push('', t('cdiff.unchanged', { list: diff.unchanged.map((a) => t(`cdiff.area.${a}`)).join(', ') }));
  return `${lines.join('\n')}\n`;
}

/** A labelled list of names or URLs in code spans; null when empty. */
function codeList(label, values) {
  if (!values || !values.length) return null;
  return h('p', { class: 'cdiff-list-line text-sm' }, label ? h('span', { class: 'muted' }, `${label} `) : null,
    ...values.flatMap((v, i) => [i ? ', ' : null, h('code', null, v)]).filter((x) => x !== null));
}

/**
 * The "Compare" tab of the Certificate view.
 * @param {{ ctx: import('../app.js').ViewContext, load: object, kit: { CertLoader: Function, ctCertLoad: Function,
 *   ctOutcomeMessage: Function, certName: (c: object) => string, issuerName: (c: object) => string },
 *   onOpenTab?: ((id: string) => void)|null }} opts load: the view's CertLoad (its leaf is compared); kit: the
 *   view's helpers (loader, CT load, outcome wording, display names); onOpenTab: switch the view to another tab
 * @returns {HTMLElement}
 */
export function CertDiffPanel({ ctx, load, kit, onOpenTab = null }) {
  const loaderHost = h('div', { class: 'stack-sm cdiff-loader' });
  const resultHost = h('div', { class: 'stack cdiff-result' });
  const el = h('div', { class: 'stack cdiff', dataset: { role: 'cert-diff' } },
    h('div', { class: 'stack-sm' }, h('h3', { class: 'cdiff-title' }, t('cdiff.title')), h('p', { class: 'muted text-sm cdiff-intro' }, t('cdiff.intro'))),
    loaderHost, resultHost);
  let token = 0;
  const view = { el, render: () => render() };
  memory.view = view;
  const onScreen = () => memory.view === view;
  const thisCert = load && load.result && load.result.leaf;

  function render() {
    renderLoader();
    renderResult();
  }

  /** The other certificate is chosen: compared at once (a file without a server certificate says so). */
  function setOther(l) {
    memory.outcome = null;
    if (!l || !l.result || !l.result.leaf) {
      memory.problem = t('cdiff.noLeaf', { name: (l && l.name) || t('file.pasted') });
      if (onScreen()) renderLoader();
      return;
    }
    memory.problem = null;
    memory.other = l;
    memory.swapped = false;
    if (onScreen()) render();
  }

  function defaultHost() {
    const names = (thisCert && thisCert.hostnames) || [];
    return names.find((n) => !n.startsWith('*.')) || names[0] || '';
  }

  /** The host name row: the newest certificate of a name in CT (only on a click). */
  function ctRow() {
    const running = memory.job;
    const field = textInput({
      value: memory.host ?? defaultHost(),
      placeholder: 'www.example.com',
      mono: true,
      className: 'cdiff-ct-field',
      attrs: { 'data-role': 'cdiff-host', enterkeyhint: 'search' },
      onInput: (v) => {
        memory.host = v;
        field.setError(null);
      },
      onEnter: () => {
        if (!memory.job) lookup(field);
      }
    });
    const btn = Button({
      label: running ? t('common.cancel') : t('cdiff.ct.load'),
      icon: running ? 'x' : 'search',
      dataset: { action: 'cdiff-ct', shortcut: running ? 'cancel' : 'submit', state: running ? 'running' : 'idle' },
      onClick: () => (memory.job ? memory.job.ctl.abort() : lookup(field))
    });
    const status = h('div', { class: 'cdiff-ct-status', attrs: { 'aria-live': 'polite' } });
    if (running) status.append(Spinner({ label: t('cdiff.ct.searching', { host: running.host }), showLabel: true }));
    else if (memory.outcome) status.append(outcomeBox(memory.outcome, field));
    return h('div', { class: 'stack-sm cdiff-ct', dataset: { shortcutScope: 'cdiff-ct' } },
      h('label', { class: 'field-label', for: field.input.id }, t('cdiff.ct.label')),
      h('div', { class: 'cdiff-ct-row' }, field.el, btn),
      h('p', { class: 'muted text-sm' }, t('cdiff.ct.hint')),
      status);
  }

  /** What a lookup that loaded nothing found: crt.sh download links, nothing current, or an error with Retry. */
  function outcomeBox(r, field) {
    let box;
    const retry = () => Button({ label: t('common.retry'), icon: 'refresh', size: 'sm', dataset: { action: 'cdiff-ct-retry' }, onClick: () => lookup(field) });
    if (r.status === 'manual' && r.crtsh && r.crtsh.entry) {
      const e = r.crtsh.entry;
      box = Alert({
        variant: 'warn', compact: true, icon: 'download', title: t('cdiff.ct.manualTitle'), message: kit.ctOutcomeMessage(r),
        actions: [
          ...e.downloads.map((d) => ButtonLink({ href: d.url, label: t('cdiff.ct.download', { id: d.id }), icon: 'download', size: 'sm', external: true })),
          ExternalLink(e.pageUrl, t('cdiff.ct.open'), { className: 'text-sm' })
        ]
      });
    } else if (r.status === 'not-found') {
      box = Alert({ variant: 'info', compact: true, icon: 'search', message: kit.ctOutcomeMessage(r), actions: [retry()] });
    } else {
      box = Alert({ variant: 'error', compact: true, title: t('cdiff.ct.failed'), message: kit.ctOutcomeMessage(r), actions: [retry()] });
    }
    box.dataset.cdiffCt = r.status;
    return box;
  }

  async function lookup(field) {
    const host = normalizeCtHost(field.value);
    if (!host) {
      field.setError(t('cdiff.ct.invalid'));
      field.focus();
      return;
    }
    field.setError(null);
    if (!ctx.requireOnline()) return;
    const ctl = new AbortController();
    const job = { host, ctl };
    memory.job = job;
    memory.outcome = null;
    memory.problem = null;
    ctx.setBusy(true);
    renderLoader();
    let r = null;
    try {
      r = await lookupCtCertificate(host, { signal: mergeSignals(ctx.signal, ctl.signal) });
    } catch (err) {
      if (errorKind(err) !== 'abort') r = { host, status: 'error', error: String((err && err.message) || err), errorKind: errorKind(err) };
    }
    if (memory.job === job) memory.job = null;
    ctx.setBusy(false);
    const shown = memory.view;
    if (r && r.status === 'found') {
      setOther(kit.ctCertLoad(r));
      if (shown && shown !== view && shown.el.isConnected) shown.render();
      return;
    }
    if (r) memory.outcome = r;
    if (shown && shown.el.isConnected) shown.render();
    else if (onScreen()) renderLoader();
  }

  function renderLoader() {
    clear(loaderHost);
    const loader = kit.CertLoader({
      onLoad: (l) => setOther(l),
      compact: true,
      title: t('cdiff.dropTitle'),
      focusTarget: () => resultHost
    });
    loader.el.classList.add('cdiff-drop');
    const problem = memory.problem ? Alert({ variant: 'error', compact: true, message: memory.problem }) : null;
    if (problem) problem.dataset.cdiffProblem = '1';
    const parts = h('div', { class: 'stack-sm' }, loader.el, ctRow(), problem);
    if (!memory.other) {
      loaderHost.append(h('section', { class: 'cdiff-box stack-sm' }, h('h3', { class: 'cdiff-box-title' }, t('cdiff.other')), parts));
      return;
    }
    loaderHost.append(Disclosure({ summary: t('cdiff.another'), className: 'cdiff-reload', open: !!(memory.job || memory.outcome || memory.problem), children: parts }));
  }

  /** The two sides: the one issued first is the old one, unless swapped. */
  function sides() {
    const cur = { cert: thisCert, chain: load.result.certificates, isThis: true, load };
    const oth = { cert: memory.other.result.leaf, chain: memory.other.result.certificates, isThis: false, load: memory.other };
    return olderOf(cur.cert, oth.cert, { swap: memory.swapped }) === 'x' ? [cur, oth] : [oth, cur];
  }

  async function renderResult() {
    const mine = ++token;
    clear(resultHost);
    if (!memory.other || !thisCert) return;
    const [o, n] = sides();
    resultHost.append(Spinner({ label: t('cdiff.comparing'), showLabel: true }));
    let diff;
    try {
      diff = await diffCertificates(o, n);
    } catch (err) {
      if (mine !== token) return;
      clear(resultHost);
      resultHost.append(ErrorBanner(err, { compact: true }));
      return;
    }
    if (mine !== token) return;
    clear(resultHost);
    resultHost.append(...resultParts(diff, o, n));
    announce(verdictTitle(diff));
  }

  function resultParts(diff, o, n) {
    const verdict = Alert({
      variant: VERDICT_VARIANT[diff.verdict],
      title: verdictTitle(diff),
      message: t(`cdiff.verdict.${diff.verdict}.body`)
    });
    verdict.classList.add('cdiff-verdict');
    verdict.dataset.verdict = diff.verdict;
    const swapBtn = Button({
      label: t('cdiff.swap'), icon: 'swap', size: 'sm', dataset: { action: 'cdiff-swap' },
      onClick: () => {
        memory.swapped = !memory.swapped;
        renderResult();
      }
    });
    const removeBtn = Button({
      label: t('cdiff.remove'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'cdiff-remove' },
      onClick: () => {
        memory.other = null;
        memory.swapped = false;
        render();
        toast(t('cdiff.removed'), { type: 'info', timeout: 2000 });
      }
    });
    const copyBtn = CopyButton(() => diffReport(diff, o, n, kit), { label: t('cdiff.copy'), size: 'sm', variant: 'secondary', className: 'cdiff-copy' });
    const bar = h('div', { class: 'cluster cdiff-bar' },
      h('span', { class: 'muted text-sm' }, t(memory.swapped ? 'cdiff.orderSwapped' : 'cdiff.order')), swapBtn, copyBtn, removeBtn);
    const parts = [verdict, bar, sideTable(diff, o, n), overlapLine(diff)];
    for (const sev of CERTDIFF_SEVERITIES) {
      const group = diff.changes.filter((c) => c.severity === sev);
      if (!group.length) continue;
      parts.push(h('section', { class: 'cdiff-group', dataset: { severity: sev } },
        h('h3', { class: 'cdiff-group-title' }, `${t(`cdiff.group.${sev}`)} (${formatNumber(group.length)})`),
        h('ul', { class: 'cdiff-list' }, group.map(changeItem))));
    }
    if (diff.unchanged.length) {
      parts.push(h('p', { class: 'muted text-sm cdiff-unchanged' }, t('cdiff.unchanged', { list: diff.unchanged.map((a) => t(`cdiff.area.${a}`)).join(', ') })));
    }
    return parts;
  }

  function overlapLine(diff) {
    const o = diff.validity.overlap;
    if (diff.identical) return null;
    return h('p', { class: 'text-sm cdiff-overlap' }, o
      ? t('cdiff.overlap', { from: formatDate(o.from), to: formatDate(o.to), count: o.days })
      : t('cdiff.noOverlap'));
  }

  function sideTable(diff, o, n) {
    const now = diff.validity.now.getTime();
    const who = (s) => h('div', { class: 'muted text-sm cdiff-who' }, s.isThis ? t('cdiff.this') : s.load.name || '');
    const yesNo = (v) => t(v ? 'common.yes' : 'common.no');
    const rows = [
      ['cert', (s) => [h('div', { class: 'mono cdiff-cn' }, kit.certName(s.cert)), who(s)]],
      ['issuer', (s) => kit.issuerName(s.cert)],
      ['valid', (s) => `${formatDate(s.cert.notBefore)} – ${formatDate(s.cert.notAfter)}`],
      ['lifetime', (s) => t('cdiff.days', { count: s === o ? diff.validity.oldLifetimeDays : diff.validity.newLifetimeDays })],
      ['left', (s) => leftText(s === o ? diff.validity.oldDaysLeft : diff.validity.newDaysLeft, s.cert, now)],
      ['key', (s) => keyLabel(s.cert)],
      ['spki', (s) => {
        const hex = s === o ? diff.key.old : diff.key.new;
        return hex ? h('code', { class: 'cdiff-hash' }, hex) : t('cdiff.none');
      }],
      ['sig', (s) => s.cert.signatureAlgorithm],
      ['names', (s) => formatNumber(s.cert.dnsNames.length + s.cert.ipAddresses.length)],
      ['scts', (s) => formatNumber(s.cert.sctCount || 0)],
      ['staple', (s) => yesNo(s.cert.mustStaple)],
      ['ocsp', (s) => (s.cert.ocspUrls.length ? s.cert.ocspUrls.map((u) => h('div', { class: 'mono cdiff-url' }, u)) : t('cdiff.none'))],
      ['chain', (s) => {
        const names = s === o ? diff.chain.old : diff.chain.new;
        return names.length ? names.map((x) => h('div', null, x)) : t('cdiff.inFile');
      }]
    ];
    const cell = (v) => h('td', null, ...(Array.isArray(v) ? v : [v]));
    return h('div', { class: 'cdiff-table-wrap' },
      h('table', { class: 'cdiff-table' },
        h('thead', null, h('tr', null, h('th', { attrs: { scope: 'col' } }, h('span', { class: 'sr-only' }, t('cdiff.row.cert'))),
          h('th', { attrs: { scope: 'col' } }, Badge(t('cdiff.old'), { variant: 'neutral' })),
          h('th', { attrs: { scope: 'col' } }, Badge(t('cdiff.new'), { variant: 'accent' })))),
        h('tbody', null, rows.map(([key, fn]) => h('tr', { dataset: { row: key } },
          h('th', { attrs: { scope: 'row' } }, t(`cdiff.row.${key}`)), cell(fn(o)), cell(fn(n)))))));
  }

  function changeItem(c) {
    const extra = [];
    if (c.items.length) extra.push(codeList(null, c.items.map(itemText)));
    if (c.code === 'wildcard-removed') extra.push(codeList(t('cdiff.still'), c.params.kept));
    if (c.code === 'issuer-changed' || c.code === 'issuer-rekeyed') {
      if (c.params.chain && c.params.chain.length) extra.push(h('p', { class: 'text-sm' }, t('cdiff.newChain', { list: c.params.chain.join(', ') })));
      else if (c.params.missing) extra.push(h('p', { class: 'text-sm' }, t('cdiff.missingChain')));
    }
    if (LIST_CODES.includes(c.code)) {
      extra.push(codeList(t('cdiff.added'), c.params.added), codeList(t('cdiff.removedList'), c.params.removed));
    }
    if (c.code === 'ocsp-changed') {
      extra.push(codeList(t('cdiff.added'), c.params.to.filter((u) => !c.params.from.includes(u))),
        codeList(t('cdiff.removedList'), c.params.from.filter((u) => !c.params.to.includes(u))));
    }
    if (c.code === 'key-new' && onOpenTab) {
      extra.push(h('div', null, Button({ label: t('cdiff.openDane'), icon: 'key', size: 'sm', variant: 'ghost', dataset: { action: 'cdiff-dane' }, onClick: () => onOpenTab('dane') })));
    }
    return h('li', { class: ['cdiff-item', `cdiff-item-${c.severity}`], dataset: { code: c.code, severity: c.severity } },
      h('div', { class: 'cdiff-item-head' },
        Badge(t(`cdiff.sev.${c.severity}`), { variant: SEVERITY_VARIANT[c.severity] }),
        h('span', { class: 'cdiff-item-title' }, changeTitle(c))),
      h('p', { class: 'cdiff-item-body text-sm' }, changeBody(c)),
      ...extra.filter(Boolean));
  }

  render();
  return el;
}
