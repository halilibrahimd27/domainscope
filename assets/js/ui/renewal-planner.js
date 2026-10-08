/**
 * ui/renewal-planner.js — the Plan panel of Renewal readiness (lib/renewalplan.js drawn).
 *
 *   - the CA/Browser Forum schedule (ballot SC-081v3): the longest validity and the domain
 *     validation reuse period by issuance date, the step in force today marked;
 *   - the certificate loaded in the view's certificate block (a file, Certificate Transparency or
 *     the sample): its lifetime and the limit it was issued under, its renewal window — Let's
 *     Encrypt's ARI window after a click (the only request this panel sends), otherwise two thirds
 *     of its lifetime — the next renewals, and the renewals and domain validations a year each step
 *     means until 2030, with the renewals by calendar year;
 *   - the coverage planner: names typed, taken from the form, the certificate or the last SSL
 *     Targets scan; its groupings as tabs (one SAN list, wildcards with what they leave uncovered,
 *     one certificate per environment), and for each certificate of the grouping on screen the
 *     OpenSSL `req -config` file and the Windows certreq INF, with the command that makes the key on
 *     the user's machine. No key is ever made or seen here.
 *
 * Loaded by views/renew.js on the first open of its Plan panel; the view hands in what only it
 * knows (its certificate, its names box, its CA). Names come from users, certificates and DNS:
 * every string goes through h() / text nodes.
 */

import { h, clear } from './dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, Disclosure, Icon, KeyValueList, Spinner, Tabs, TruncatedList, announce, select, textarea
} from './components.js';
import { NaMark, RetryButton, statusText } from './source-status.js';
import { downloadText } from './download.js';
import { t, registerStrings, formatDate, formatDateTime, formatNumber } from '../i18n.js';
import {
  LIFETIME_SCHEDULE, PLAN_HORIZON_YEAR, PLAN_STATES, SAN_LIMIT, CSR_KEY_TYPES, GROUPINGS, GROUPING_NOTES, UNCOVERED_REASONS,
  ENVIRONMENTS, ARI_DIRECTORIES, planRenewals, ariSupported, ariCertId, fetchRenewalInfo, coveragePlan, opensslConfig, certreqInf
} from '../lib/renewalplan.js';
import { caForIssuer, renewalCa } from '../lib/renewal.js';
import { sourceStatus } from '../lib/sourcestatus.js';
import { mergeSignals } from '../lib/util.js';

/** The ballot's page (a link the user opens). */
const BALLOT_URL = 'https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/';

registerStrings('en', {
  'rpl.intro': 'When a certificate must be renewed and how often from now on, under the CA/Browser Forum’s shrinking lifetimes — and which names go on which certificate, with the CSR configuration to request each. Nothing here is sent anywhere, except a request to Let’s Encrypt for its renewal window when you ask for it.',
  'rpl.sched.title': 'Certificate lifetimes (CA/Browser Forum ballot SC-081)',
  'rpl.sched.from': 'Issued from',
  'rpl.sched.max': 'Longest validity',
  'rpl.sched.dcv': 'Domain validation reused for',
  'rpl.sched.before': 'Before {date}',
  'rpl.sched.now': 'in force now',
  'rpl.days': { one: '{count} day', other: '{count} days' },
  'rpl.sched.source': 'Baseline Requirements §6.3.2 and §4.2.1, as ballot SC-081v3 amended them (adopted {date}). A validation older than its reuse period is done again at the next renewal: from {last}, every renewal validates the names anew, so the ACME challenge must pass every time.',
  'rpl.sched.link': 'Ballot SC-081v3',
  'rpl.cert.title': 'This certificate’s renewals',
  'rpl.cert.none': 'Load a certificate above — a file, or a host name’s current certificate from Certificate Transparency — to see when it must be renewed and how often from now on.',
  'rpl.cert.unreadable': 'The validity dates of this certificate could not be read.',
  'rpl.cert.names': 'Names',
  'rpl.cert.issued': 'Issued',
  'rpl.cert.expires': 'Expires',
  'rpl.cert.expiresLeft': { one: '{date} · {count} day left', other: '{date} · {count} days left' },
  'rpl.cert.lifetime': 'Lifetime',
  'rpl.cert.lifetimeValue': '{days} · the limit when it was issued: {max}',
  'rpl.cert.overMax': 'Longer than the {max} the Baseline Requirements allowed when it was issued: no publicly trusted CA can have issued it (a private CA’s certificate?). The renewals below keep to the limits.',
  'rpl.cert.window': 'Renewal window',
  'rpl.cert.windowAri': '{start} – {end}, suggested by {ca} (asked {time})',
  'rpl.cert.windowThirds': 'From {start} (two thirds of its lifetime) until it expires',
  'rpl.cert.renewBy': 'Must be renewed by',
  'rpl.cert.renewByValue': '{date}, when it expires — leave time to deploy the new one',
  'rpl.state.not-yet-valid': 'Not valid yet',
  'rpl.state.before-window': 'Not due yet',
  'rpl.state.in-window': 'Due: renew now',
  'rpl.state.past-window': 'Overdue: renew now',
  'rpl.state.expired': 'Expired',
  'rpl.ari.ask': 'Ask {ca} for its renewal window (ARI)',
  'rpl.ari.again': 'Ask {ca} again',
  'rpl.ari.asking': 'Asking {ca}…',
  'rpl.ari.privacy': 'Sends this certificate’s identifier — the issuer’s key identifier and the serial number, both public in Certificate Transparency — to {host}, after reading its ACME directory. Nothing else is sent.',
  'rpl.ari.done': 'Renewal window from {ca}: {start} – {end}.',
  'rpl.ari.otherCa': 'This page can ask only Let’s Encrypt for a renewal window (ACME ARI), so the window is two thirds of the lifetime.',
  'rpl.ari.noKeyId': 'The certificate has no authority key identifier, so ARI cannot name it: the window is two thirds of the lifetime.',
  'rpl.ari.failed': 'The window from {ca} could not be read. The window shown is two thirds of the lifetime.',
  'rpl.ari.notFound': '{ca} does not know this certificate (HTTP 404): another CA issued it, or it is too old. The window shown is two thirds of the lifetime.',
  'rpl.ari.badWindow': '{ca} answered without a usable window. The window shown is two thirds of the lifetime.',
  'rpl.ari.explain': 'Why, according to the CA: {url}',
  'rpl.ari.retryAfter': 'The CA asks to be asked again after {time}: it may move the window, for example after an incident.',
  'rpl.next.title': 'Next renewals',
  'rpl.next.intro': 'The first at the window’s start (now, once that has passed), each one after at two thirds of the new certificate’s lifetime: as long as this one, cut to the limit in force on its issuance day.',
  'rpl.next.at': 'Renewal',
  'rpl.next.lifetime': 'Lifetime',
  'rpl.next.expires': 'Expires',
  'rpl.rate.title': 'Renewals a year until {year}',
  'rpl.rate.step': 'Issued from',
  'rpl.rate.every': 'Renewed every',
  'rpl.rate.perYear': 'Renewals a year',
  'rpl.rate.validations': 'Domain validations a year',
  'rpl.rate.hint': 'With certificates as long as this one, cut to each limit, renewed at two thirds of their lifetime. Validations: at least that many — a CA may reuse a validation for less than the limit allows.',
  'rpl.rate.each': '{count} · every renewal',
  'rpl.years.title': 'Renewals by calendar year',
  'rpl.years.count': { one: '{count} renewal', other: '{count} renewals' },
  'rpl.cov.title': 'Coverage planner',
  'rpl.cov.intro': 'Which names go on which certificate — one SAN list, wildcards, or one certificate per environment — and the CSR configuration of each, for OpenSSL or Windows certreq.',
  'rpl.cov.names': 'Names to cover',
  'rpl.cov.namesHint': 'One per line, or separated by spaces or commas; *.example.com for a wildcard.',
  'rpl.cov.fromForm': 'Use the names above',
  'rpl.cov.fromCert': 'Use the certificate’s names',
  'rpl.cov.fromScan': 'Use the {count} names of the last scan',
  'rpl.cov.fromScanTitle': 'Hosts found by the SSL Targets scan of {domains}',
  'rpl.cov.invalid': { one: 'Not a name a CA can certify, left out: {list}', other: 'Not names a CA can certify, left out: {list}' },
  'rpl.cov.empty': 'Enter the names to cover, or take them from the form, the certificate or the last scan.',
  'rpl.cov.groupings': 'Groupings',
  'rpl.g.san': 'One SAN list',
  'rpl.g.wildcard': 'Wildcards',
  'rpl.g.environment': 'Per environment',
  'rpl.g.certs': { one: '{count} certificate', other: '{count} certificates' },
  'rpl.g.entries': { one: '{count} name to validate at each renewal', other: '{count} names to validate at each renewal' },
  'rpl.g.desc.san': 'Every name on one certificate: one key and one renewal, but a lost key or a revocation touches every name, and everyone who reads the certificate sees them all.',
  'rpl.g.desc.wildcard': 'A wildcard covers the names exactly one label below it, so fewer names to validate; the same key then serves every host it covers.',
  'rpl.g.desc.environment': 'One certificate per environment: the key of a test server never unlocks production. Names without an environment label count as production.',
  'rpl.note.dns-01': 'A wildcard can be validated only with the DNS-01 challenge.',
  'rpl.note.split': 'More than {max} names: split into several certificates (Let’s Encrypt’s limit).',
  'rpl.note.mixed-domains': 'A certificate holds names of several registrable domains.',
  'rpl.note.no-prod-wildcard': 'No wildcard for production: it would also cover the other environments’ names.',
  'rpl.unc.title': 'What a wildcard leaves uncovered',
  'rpl.unc.apex': '{name}: the apex itself, which {wildcard} does not cover — it stays on the certificate as a name of its own.',
  'rpl.unc.deeper': '{name}: two levels or more below, which {wildcard} does not cover — it stays on the certificate as a name of its own.',
  'rpl.env.prod': 'Production',
  'rpl.env.staging': 'Staging',
  'rpl.env.test': 'Test',
  'rpl.env.dev': 'Development',
  'rpl.c.title': 'Certificate {n} · {name}',
  'rpl.c.part': 'part {part} of {parts}',
  'rpl.c.serves': { one: 'serves {count} name', other: 'serves {count} names' },
  'rpl.csr.title': 'CSR configuration',
  'rpl.csr.keyType': 'Key type of the CSRs',
  'rpl.key.ec-p256': 'ECDSA P-256 (recommended)',
  'rpl.key.ec-p384': 'ECDSA P-384',
  'rpl.key.rsa-2048': 'RSA 2048',
  'rpl.key.rsa-3072': 'RSA 3072',
  'rpl.key.rsa-4096': 'RSA 4096',
  'rpl.csr.noKey': 'No key is made in this page: each command makes the private key on your machine, next to the CSR.',
  'rpl.csr.openssl': 'OpenSSL (openssl req -config)',
  'rpl.csr.certreq': 'Windows (certreq -new)',
  'rpl.csr.run': 'Then run:',
  'rpl.csr.download': 'Download {file}'
});

registerStrings('tr', {
  'rpl.intro': 'CA/Browser Forum’un kısalan sertifika ömürlerine göre bir sertifikanın ne zamana kadar ve bundan sonra ne sıklıkla yenilenmesi gerektiği; hangi adların hangi sertifikaya gireceği ve her biri için CSR yapılandırması. Buradan hiçbir şey gönderilmez; yalnızca siz istediğinizde Let’s Encrypt’e yenileme aralığı sorulur.',
  'rpl.sched.title': 'Sertifika ömürleri (CA/Browser Forum oylaması SC-081)',
  'rpl.sched.from': 'Veriliş tarihi',
  'rpl.sched.max': 'En uzun geçerlilik',
  'rpl.sched.dcv': 'Alan adı doğrulamasının yeniden kullanım süresi',
  'rpl.sched.before': '{date} öncesi',
  'rpl.sched.now': 'şu an yürürlükte',
  'rpl.days': '{count} gün',
  'rpl.sched.source': 'Baseline Requirements §6.3.2 ve §4.2.1, SC-081v3 oylamasıyla değiştirildiği haliyle (kabul: {date}). Yeniden kullanım süresini aşan bir doğrulama bir sonraki yenilemede tekrarlanır: {last} itibarıyla her yenilemede adlar yeniden doğrulanır; ACME doğrulamasının her seferinde geçmesi gerekir.',
  'rpl.sched.link': 'SC-081v3 oylaması',
  'rpl.cert.title': 'Bu sertifikanın yenilemeleri',
  'rpl.cert.none': 'Ne zamana kadar ve bundan sonra ne sıklıkla yenilenmesi gerektiğini görmek için yukarıda bir sertifika yükleyin: bir dosya ya da bir host adının Certificate Transparency’deki geçerli sertifikası.',
  'rpl.cert.unreadable': 'Bu sertifikanın geçerlilik tarihleri okunamadı.',
  'rpl.cert.names': 'Adlar',
  'rpl.cert.issued': 'Veriliş',
  'rpl.cert.expires': 'Bitiş',
  'rpl.cert.expiresLeft': '{date} · {count} gün kaldı',
  'rpl.cert.lifetime': 'Ömür',
  'rpl.cert.lifetimeValue': '{days} · verildiği tarihteki sınır: {max}',
  'rpl.cert.overMax': 'Verildiği tarihte Baseline Requirements’ın izin verdiği {max} süresinden uzun: hiçbir genel güvenilir otorite bunu vermiş olamaz (özel bir otoritenin sertifikası mı?). Aşağıdaki yenilemeler sınırlara uyar.',
  'rpl.cert.window': 'Yenileme aralığı',
  'rpl.cert.windowAri': '{start} – {end}; öneren: {ca} (sorgu: {time})',
  'rpl.cert.windowThirds': '{start} tarihinden (ömrünün üçte ikisi) süresi dolana kadar',
  'rpl.cert.renewBy': 'En geç yenilenmesi gereken tarih',
  'rpl.cert.renewByValue': '{date}, süresinin dolduğu an — yenisini kurmak için zaman bırakın',
  'rpl.state.not-yet-valid': 'Henüz geçerli değil',
  'rpl.state.before-window': 'Henüz zamanı gelmedi',
  'rpl.state.in-window': 'Zamanı geldi: şimdi yenileyin',
  'rpl.state.past-window': 'Gecikti: şimdi yenileyin',
  'rpl.state.expired': 'Süresi doldu',
  'rpl.ari.ask': '{ca} yenileme aralığını sor (ARI)',
  'rpl.ari.again': '{ca} için yeniden sor',
  'rpl.ari.asking': '{ca} sorgulanıyor…',
  'rpl.ari.privacy': 'ACME dizini okunduktan sonra bu sertifikanın kimliği — veren otoritenin anahtar kimliği ve seri numarası; ikisi de Certificate Transparency’de herkese açık — {host} adresine gönderilir. Başka hiçbir şey gönderilmez.',
  'rpl.ari.done': '{ca} yenileme aralığı: {start} – {end}.',
  'rpl.ari.otherCa': 'Bu sayfa yenileme aralığını (ACME ARI) yalnızca Let’s Encrypt’e sorabilir; aralık, ömrün üçte ikisinden hesaplanır.',
  'rpl.ari.noKeyId': 'Sertifikada otorite anahtar kimliği yok, bu yüzden ARI onu adlandıramaz: aralık, ömrün üçte ikisinden hesaplanır.',
  'rpl.ari.failed': '{ca} yenileme aralığı okunamadı. Gösterilen aralık ömrün üçte ikisinden hesaplandı.',
  'rpl.ari.notFound': '{ca} bu sertifikayı tanımıyor (HTTP 404): başka bir otorite vermiş ya da çok eski. Gösterilen aralık ömrün üçte ikisinden hesaplandı.',
  'rpl.ari.badWindow': '{ca} yanıt verdi ama kullanılabilir bir aralık vermedi. Gösterilen aralık ömrün üçte ikisinden hesaplandı.',
  'rpl.ari.explain': 'Otoritenin açıklaması: {url}',
  'rpl.ari.retryAfter': 'Otorite {time} sonrasında yeniden sorulmasını istiyor: aralığı, örneğin bir olaydan sonra, değiştirebilir.',
  'rpl.next.title': 'Sonraki yenilemeler',
  'rpl.next.intro': 'İlki aralığın başında (o an geçtiyse hemen), sonrakiler yeni sertifikanın ömrünün üçte ikisinde: bu sertifika kadar uzun, verildiği gün yürürlükteki sınıra kısaltılmış.',
  'rpl.next.at': 'Yenileme',
  'rpl.next.lifetime': 'Ömür',
  'rpl.next.expires': 'Bitiş',
  'rpl.rate.title': '{year} yılına kadar yıllık yenileme sayısı',
  'rpl.rate.step': 'Veriliş tarihi',
  'rpl.rate.every': 'Yenileme sıklığı',
  'rpl.rate.perYear': 'Yılda yenileme',
  'rpl.rate.validations': 'Yılda alan adı doğrulaması',
  'rpl.rate.hint': 'Bu sertifika kadar uzun, her sınıra kısaltılmış ve ömürlerinin üçte ikisinde yenilenen sertifikalarla. Doğrulamalar en az bu kadardır: bir otorite bir doğrulamayı sınırın izin verdiğinden daha kısa süre kullanabilir.',
  'rpl.rate.each': '{count} · her yenilemede',
  'rpl.years.title': 'Takvim yılına göre yenilemeler',
  'rpl.years.count': '{count} yenileme',
  'rpl.cov.title': 'Kapsam planlayıcı',
  'rpl.cov.intro': 'Hangi adların hangi sertifikaya gireceği — tek bir SAN listesi, Wildcard’lar ya da her ortama bir sertifika — ve her biri için OpenSSL ya da Windows certreq CSR yapılandırması.',
  'rpl.cov.names': 'Kapsanacak adlar',
  'rpl.cov.namesHint': 'Her satıra bir tane ya da boşluk veya virgülle ayırarak; Wildcard için *.example.com.',
  'rpl.cov.fromForm': 'Yukarıdaki adları kullan',
  'rpl.cov.fromCert': 'Sertifikanın adlarını kullan',
  'rpl.cov.fromScan': 'Son taramadaki {count} adı kullan',
  'rpl.cov.fromScanTitle': '{domains} için SSL Hedefleri taramasında bulunan host’lar',
  'rpl.cov.invalid': 'Bir otoritenin sertifika veremeyeceği ad, dışarıda bırakıldı: {list}',
  'rpl.cov.empty': 'Kapsanacak adları girin ya da formdan, sertifikadan veya son taramadan alın.',
  'rpl.cov.groupings': 'Gruplamalar',
  'rpl.g.san': 'Tek SAN listesi',
  'rpl.g.wildcard': 'Wildcard’lar',
  'rpl.g.environment': 'Ortama göre',
  'rpl.g.certs': '{count} sertifika',
  'rpl.g.entries': 'Her yenilemede doğrulanacak {count} ad',
  'rpl.g.desc.san': 'Bütün adlar tek bir sertifikada: tek anahtar ve tek yenileme; ama kaybolan bir anahtar ya da bir iptal her adı etkiler ve sertifikayı okuyan herkes bütün adları görür.',
  'rpl.g.desc.wildcard': 'Bir Wildcard tam olarak bir etiket altındaki adları kapsar; doğrulanacak ad sayısı azalır, ama aynı anahtar kapsadığı her host’ta kullanılır.',
  'rpl.g.desc.environment': 'Her ortama bir sertifika: bir test sunucusunun anahtarı üretim ortamını hiçbir zaman açmaz. Ortam etiketi olmayan adlar üretim sayılır.',
  'rpl.note.dns-01': 'Bir Wildcard yalnızca DNS-01 doğrulamasıyla doğrulanabilir.',
  'rpl.note.split': '{max} addan fazlası birkaç sertifikaya bölündü (Let’s Encrypt’in sınırı).',
  'rpl.note.mixed-domains': 'Bir sertifikada birden fazla kayıtlı alan adının adları var.',
  'rpl.note.no-prod-wildcard': 'Üretim için Wildcard önerilmedi: diğer ortamların adlarını da kapsardı.',
  'rpl.unc.title': 'Wildcard’ın kapsamadıkları',
  'rpl.unc.apex': '{name}: ana alan adının kendisi; {wildcard} onu kapsamaz — sertifikada ayrı bir ad olarak kalır.',
  'rpl.unc.deeper': '{name}: iki ya da daha fazla düzey aşağıda; {wildcard} onu kapsamaz — sertifikada ayrı bir ad olarak kalır.',
  'rpl.env.prod': 'Üretim',
  'rpl.env.staging': 'Hazırlık (staging)',
  'rpl.env.test': 'Test',
  'rpl.env.dev': 'Geliştirme',
  'rpl.c.title': 'Sertifika {n} · {name}',
  'rpl.c.part': 'bölüm {part}/{parts}',
  'rpl.c.serves': '{count} ada hizmet eder',
  'rpl.csr.title': 'CSR yapılandırması',
  'rpl.csr.keyType': 'CSR’lerin anahtar türü',
  'rpl.key.ec-p256': 'ECDSA P-256 (önerilen)',
  'rpl.key.ec-p384': 'ECDSA P-384',
  'rpl.key.rsa-2048': 'RSA 2048',
  'rpl.key.rsa-3072': 'RSA 3072',
  'rpl.key.rsa-4096': 'RSA 4096',
  'rpl.csr.noKey': 'Bu sayfada hiçbir anahtar üretilmez: her komut özel anahtarı CSR’nin yanında, sizin bilgisayarınızda üretir.',
  'rpl.csr.openssl': 'OpenSSL (openssl req -config)',
  'rpl.csr.certreq': 'Windows (certreq -new)',
  'rpl.csr.run': 'Sonra çalıştırın:',
  'rpl.csr.download': '{file} dosyasını indir'
});

/**
 * The keys this module builds from lib/renewalplan.js codes (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...PLAN_STATES.map((s) => `rpl.state.${s}`),
    ...GROUPINGS.flatMap((g) => [`rpl.g.${g}`, `rpl.g.desc.${g}`]),
    ...GROUPING_NOTES.map((n) => `rpl.note.${n}`),
    ...UNCOVERED_REASONS.map((r) => `rpl.unc.${r}`),
    ...ENVIRONMENTS.map((e) => `rpl.env.${e}`),
    ...CSR_KEY_TYPES.map((k) => `rpl.key.${k}`)
  ];
}

/** The day count of a lifetime, in words. */
const days = (n) => t('rpl.days', { count: Math.round(n) });
/** A schedule date (UTC, as the Baseline Requirements give them). */
const utcDate = (iso) => formatDate(Date.parse(`${iso}T00:00:00Z`), { utc: true });
/** A rate with one decimal. */
const rate = (x) => formatNumber(x, { maximumFractionDigits: 1, minimumFractionDigits: 1 });
/** The CA's display name. */
const caName = (id) => (renewalCa(id) ? renewalCa(id).name : id);

/** A small table: a header row and body rows of cells (Nodes or text). */
function table(className, head, rows) {
  return h('div', { class: 'rpl-table-wrap' },
    h('table', { class: ['rpl-table', className] },
      h('thead', null, h('tr', null, head.map((c) => h('th', { attrs: { scope: 'col' } }, c)))),
      h('tbody', null, rows.map((r) => h('tr', { class: r.className || null, dataset: r.dataset || {} }, r.cells.map((c, i) => (i === 0 ? h('th', { attrs: { scope: 'row' } }, c) : h('td', null, c))))))));
}

/**
 * The Plan panel.
 * @param {{ ctx: import('../app.js').ViewContext, cert?: () => object|null, names?: () => string, ca?: () => string }} opts
 *   `cert`: the view's certificate load (`{ result: { leaf } }`); `names`: its names box; `ca`: its CA id
 * @returns {{ el: HTMLElement, refresh(): void, destroy(): void }}
 */
export function RenewalPlanner({ ctx, cert = () => null, names = () => '', ca = () => '' }) {
  const el = h('div', { class: 'stack-lg rpl-panel', dataset: { role: 'renewal-planner' } });
  const schedHost = h('div', { class: 'rpl-sched-host' });
  const certHost = h('div', { class: 'rpl-cert-host' });
  const covHost = h('div', { class: 'rpl-cov-host' });
  /** ARI lookups by certificate (issuer DN + serial): `{ status: 'running'|'done', result, controller }`. */
  const ari = new Map();
  let destroyed = false;
  let keyType = CSR_KEY_TYPES[0];
  let grouping = GROUPINGS[0];
  let covTimer = null;

  el.append(h('p', { class: 'muted rpl-intro' }, t('rpl.intro')), schedHost, certHost, covHost);

  const leafOf = () => {
    const load = cert();
    return load && load.result && load.result.leaf ? load.result.leaf : null;
  };
  const certKey = (leaf) => `${leaf.issuerDN || ''}|${leaf.serialHex || ''}`;
  /** The CA to ask: the certificate's issuer when the list knows it, else the CA chosen in the form. */
  const caOf = (leaf) => caForIssuer(leaf.issuer && Object.keys(leaf.issuer).length ? leaf.issuer : leaf.issuerDN) || ca() || null;

  /* --- the schedule ----------------------------------------------------------------- */
  function renderSchedule() {
    clear(schedHost);
    const now = Date.now();
    const current = planRenewals({ notBefore: now, notAfter: now + 1000 }, { now }).issuedUnder.id;
    const rows = LIFETIME_SCHEDULE.map((s, i) => ({
      className: s.id === current ? 'rpl-now' : null,
      dataset: { step: s.id },
      cells: [
        h('span', null, s.from ? utcDate(s.from) : t('rpl.sched.before', { date: utcDate(LIFETIME_SCHEDULE[i + 1].from) }),
          s.id === current ? [' ', Badge(t('rpl.sched.now'), { variant: 'info' })] : null),
        days(s.maxDays),
        days(s.dcvDays)
      ]
    }));
    const last = LIFETIME_SCHEDULE[LIFETIME_SCHEDULE.length - 1];
    schedHost.append(Card({
      title: t('rpl.sched.title'),
      icon: 'calendar',
      className: 'rpl-sched',
      children: h('div', { class: 'stack-sm' },
        table('rpl-sched-table', [t('rpl.sched.from'), t('rpl.sched.max'), t('rpl.sched.dcv')], rows),
        h('p', { class: 'text-sm muted' }, t('rpl.sched.source', { date: utcDate('2025-04-11'), last: utcDate(last.from) }), ' ',
          h('a', { class: 'rpl-link', attrs: { href: BALLOT_URL, target: '_blank', rel: 'noopener noreferrer' } }, t('rpl.sched.link'))))
    }));
  }

  /* --- this certificate ------------------------------------------------------------- */
  function ariBlock(leaf, caId) {
    const box = h('div', { class: 'stack-sm rpl-ari', dataset: { role: 'rpl-ari' } });
    if (!ariSupported(caId)) {
      box.append(h('p', { class: 'text-sm muted', dataset: { ari: 'other-ca' } }, Icon('info', { size: 14 }), ' ', t('rpl.ari.otherCa')));
      return box;
    }
    if (!ariCertId(leaf)) {
      box.append(h('p', { class: 'text-sm muted', dataset: { ari: 'no-key-id' } }, Icon('info', { size: 14 }), ' ', t('rpl.ari.noKeyId')));
      return box;
    }
    const entry = ari.get(certKey(leaf));
    const name = caName(caId);
    const running = !!(entry && entry.status === 'running');
    const result = entry && entry.status === 'done' ? entry.result : null;
    const btn = Button({
      label: running ? t('rpl.ari.asking', { ca: name }) : t(result ? 'rpl.ari.again' : 'rpl.ari.ask', { ca: name }),
      icon: running ? null : 'refresh',
      size: 'sm',
      variant: result && result.ok ? 'ghost' : 'secondary',
      dataset: { action: 'rpl-ari' },
      attrs: running ? { 'aria-busy': 'true' } : {},
      onClick: () => askAri(leaf, caId)
    });
    if (running) btn.prepend(Spinner({ size: 'sm' }));
    if (result && !result.ok) {
      const status = sourceStatus({
        source: 'ari', error: result.error, status: result.status, retryAfterMs: result.retryAfterMs, at: result.at,
        errorKind: ['bad-window', 'no-renewal-info'].includes(result.code) ? 'parse' : result.errorKind
      });
      const key = result.code === 'not-found' ? 'rpl.ari.notFound' : ['bad-window', 'no-renewal-info'].includes(result.code) ? 'rpl.ari.badWindow' : 'rpl.ari.failed';
      box.append(h('div', { class: 'rpl-ari-failed', dataset: { ari: result.code } },
        NaMark([status]), ' ', h('span', { class: 'text-sm' }, t(key, { ca: name }), ' ', h('span', { class: 'muted' }, statusText(status))),
        ' ', RetryButton({ sources: ['ari'], onClick: () => askAri(leaf, caId), dataset: { role: 'rpl-ari-retry' } })));
    }
    if (result && result.ok) {
      if (result.explanationUrl) box.append(h('p', { class: 'text-sm' }, t('rpl.ari.explain', { url: result.explanationUrl })));
      if (result.retryAfterMs) box.append(h('p', { class: 'text-sm muted' }, t('rpl.ari.retryAfter', { time: formatDateTime(result.at.getTime() + result.retryAfterMs) })));
    }
    box.append(h('div', { class: 'rpl-ari-row' }, btn),
      h('p', { class: 'text-sm muted rpl-ari-privacy' }, Icon('lock', { size: 14 }), ' ',
        t('rpl.ari.privacy', { host: new URL(ARI_DIRECTORIES[caId]).host })));
    return box;
  }

  async function askAri(leaf, caId) {
    const key = certKey(leaf);
    const prev = ari.get(key);
    if ((prev && prev.status === 'running') || !ctx.requireOnline()) return;
    const controller = new AbortController();
    const entry = { status: 'running', result: null, controller };
    ari.set(key, entry);
    renderCert({ focus: 'rpl-ari' });
    let result;
    try {
      result = await fetchRenewalInfo(leaf, { ca: caId, signal: mergeSignals(ctx.signal, controller.signal) });
    } catch {
      // Stopped (the view was left): nothing to show.
      if (ari.get(key) === entry) ari.delete(key);
      return;
    }
    if (destroyed || ari.get(key) !== entry) return;
    entry.status = 'done';
    entry.result = result;
    entry.controller = null;
    renderCert({ focus: result.ok ? 'rpl-ari' : 'retry-source' });
    announce(result.ok
      ? t('rpl.ari.done', { ca: caName(caId), start: formatDateTime(result.start), end: formatDateTime(result.end) })
      : t(result.code === 'not-found' ? 'rpl.ari.notFound' : 'rpl.ari.failed', { ca: caName(caId) }));
  }

  function renderCert({ focus = null } = {}) {
    const hadFocus = focus || (el.contains(document.activeElement) && certHost.contains(document.activeElement) ? document.activeElement.dataset.action : null);
    clear(certHost);
    const leaf = leafOf();
    const body = h('div', { class: 'stack' });
    certHost.append(Card({ title: t('rpl.cert.title'), icon: 'clock', className: 'rpl-cert', children: body }));
    if (!leaf) {
      body.append(h('p', { class: 'muted rpl-cert-none' }, t('rpl.cert.none')));
      return;
    }
    const caId = caOf(leaf);
    const entry = ari.get(certKey(leaf));
    const ariResult = entry && entry.status === 'done' && entry.result && entry.result.ok ? entry.result : null;
    const plan = planRenewals(leaf, { now: Date.now(), ari: ariResult });
    if (!plan) {
      body.append(Alert({ variant: 'warn', message: t('rpl.cert.unreadable') }));
      return;
    }
    const names = leaf.hostnames && leaf.hostnames.length ? leaf.hostnames : leaf.dnsNames || [];
    const stateVariant = { 'not-yet-valid': 'info', 'before-window': 'ok', 'in-window': 'warn', 'past-window': 'error', expired: 'error' }[plan.state];
    body.append(h('div', { class: 'rpl-state', dataset: { state: plan.state, source: plan.window.source } }, Badge(t(`rpl.state.${plan.state}`), { variant: stateVariant })));
    body.append(KeyValueList([
      [t('rpl.cert.names'), names.length ? TruncatedList(names, { max: 4, inline: true }) : '—'],
      [t('rpl.cert.issued'), formatDateTime(leaf.notBefore)],
      [t('rpl.cert.expires'), t('rpl.cert.expiresLeft', { date: formatDateTime(plan.expires), count: plan.daysLeft })],
      [t('rpl.cert.lifetime'), t('rpl.cert.lifetimeValue', { days: days(plan.lifetimeDays), max: days(plan.issuedUnder.maxDays) })],
      [t('rpl.cert.window'), h('span', { dataset: { role: 'rpl-window' } }, plan.window.source === 'ari'
        ? t('rpl.cert.windowAri', { start: formatDateTime(plan.window.start), end: formatDateTime(plan.window.end), ca: caName(caId), time: formatDateTime(ariResult.at) })
        : t('rpl.cert.windowThirds', { start: formatDateTime(plan.window.start) }))],
      [t('rpl.cert.renewBy'), t('rpl.cert.renewByValue', { date: formatDateTime(plan.expires) })]
    ], { className: 'rpl-kv' }));
    if (plan.overMax) body.append(Alert({ variant: 'warn', message: t('rpl.cert.overMax', { max: days(plan.issuedUnder.maxDays) }) }));
    body.append(ariBlock(leaf, caId));

    body.append(h('section', { class: 'stack-sm rpl-next' },
      h('h3', { class: 'rpl-h' }, t('rpl.next.title')),
      h('p', { class: 'text-sm muted' }, t('rpl.next.intro')),
      table('rpl-next-table', [t('rpl.next.at'), t('rpl.next.lifetime'), t('rpl.next.expires')],
        plan.next.map((n) => ({ dataset: { step: n.step }, cells: [formatDate(n.at), days(n.lifetimeDays), formatDate(n.expires)] })))));

    body.append(h('section', { class: 'stack-sm rpl-rate' },
      h('h3', { class: 'rpl-h' }, t('rpl.rate.title', { year: PLAN_HORIZON_YEAR })),
      table('rpl-rate-table', [t('rpl.rate.step'), t('rpl.rate.every'), t('rpl.rate.perYear'), t('rpl.rate.validations')],
        plan.steps.map((s) => ({
          className: s.current ? 'rpl-now' : null,
          dataset: { step: s.step },
          cells: [
            s.from ? utcDate(s.from) : t('rpl.sched.before', { date: utcDate(LIFETIME_SCHEDULE[1].from) }),
            days(s.intervalDays),
            rate(s.perYear),
            s.revalidateEach ? t('rpl.rate.each', { count: rate(s.validationsPerYear) }) : rate(s.validationsPerYear)
          ]
        }))),
      h('p', { class: 'text-sm muted' }, t('rpl.rate.hint')),
      h('h3', { class: 'rpl-h' }, t('rpl.years.title')),
      h('ul', { class: 'rpl-years' }, plan.years.map((y) => h('li', { dataset: { year: String(y.year), count: String(y.renewals) } },
        h('span', { class: 'rpl-year' }, String(y.year)), ' ', t('rpl.years.count', { count: y.renewals }))))));

    if (hadFocus) {
      const again = certHost.querySelector(`[data-action="${hadFocus}"]`) || certHost.querySelector('[data-action="rpl-ari"]');
      if (again) again.focus();
    }
  }

  /* --- the coverage planner --------------------------------------------------------- */
  const namesField = textarea({
    label: t('rpl.cov.names'),
    rows: 5,
    value: names(),
    placeholder: 'example.com\nwww.example.com\napi.dev.example.com',
    hint: t('rpl.cov.namesHint'),
    attrs: { 'data-role': 'rpl-names' },
    onInput: () => {
      clearTimeout(covTimer);
      covTimer = setTimeout(renderPlan, 150);
    }
  });
  const sourcesRow = h('div', { class: 'rpl-sources' });
  const keyField = select({
    label: t('rpl.csr.keyType'),
    options: CSR_KEY_TYPES.map((k) => ({ value: k, label: t(`rpl.key.${k}`) })),
    value: keyType,
    className: 'rpl-key',
    onChange: () => {
      keyType = keyField.value;
      renderPlan();
    }
  });
  keyField.input.dataset.role = 'rpl-keytype';
  const planEl = h('div', { class: 'stack rpl-plan', attrs: { 'aria-live': 'off' } });
  covHost.append(Card({
    title: t('rpl.cov.title'),
    icon: 'layers',
    className: 'rpl-cov',
    children: h('div', { class: 'stack' },
      h('p', { class: 'text-sm muted' }, t('rpl.cov.intro')),
      namesField.el, sourcesRow, keyField.el,
      h('p', { class: 'text-sm muted rpl-nokey' }, Icon('key', { size: 14 }), ' ', t('rpl.csr.noKey')),
      planEl)
  }));

  const useNames = (list) => {
    namesField.value = `${list.join('\n')}`;
    renderPlan();
  };

  function renderSources() {
    clear(sourcesRow);
    const formText = names();
    if (formText.trim()) {
      sourcesRow.append(Button({ label: t('rpl.cov.fromForm'), icon: 'arrow-down', size: 'sm', variant: 'ghost', dataset: { action: 'rpl-from-form' }, onClick: () => useNames(formText.split(/[\s,;]+/).filter(Boolean)) }));
    }
    const leaf = leafOf();
    const certNames = leaf ? (leaf.hostnames && leaf.hostnames.length ? leaf.hostnames : leaf.dnsNames || []) : [];
    if (certNames.length) {
      sourcesRow.append(Button({ label: t('rpl.cov.fromCert'), icon: 'certificate', size: 'sm', variant: 'ghost', dataset: { action: 'rpl-from-cert' }, onClick: () => useNames(certNames) }));
    }
    const last = ctx.state.getSession('scanHosts');
    if (last && Array.isArray(last.names) && last.names.length) {
      sourcesRow.append(Button({
        label: t('rpl.cov.fromScan', { count: formatNumber(last.names.length) }),
        icon: 'target',
        size: 'sm',
        variant: 'ghost',
        title: t('rpl.cov.fromScanTitle', { domains: (last.domains || []).join(', ') }),
        dataset: { action: 'rpl-from-scan' },
        onClick: () => useNames(last.names)
      }));
    }
    sourcesRow.hidden = !sourcesRow.childNodes.length;
  }

  function certCard(c, i) {
    const o = opensslConfig(c, { keyType });
    const w = certreqInf(c, { keyType });
    const label = c.env ? t(`rpl.env.${c.env}`) : c.commonName || c.names[0];
    const meta = [t('rpl.c.serves', { count: c.covers.length })];
    if (c.part) meta.push(t('rpl.c.part', { part: c.part, parts: c.parts }));
    const download = (file, text) => Button({
      label: t('rpl.csr.download', { file }), icon: 'download', size: 'sm', variant: 'ghost',
      dataset: { action: 'rpl-download', file }, onClick: () => downloadText(file, text)
    });
    return h('article', { class: 'rpl-c stack-sm', dataset: { env: c.env || '', names: c.names.join(' ') } },
      h('h4', { class: 'rpl-c-title' }, t('rpl.c.title', { n: i + 1, name: label })),
      h('p', { class: 'text-sm muted' }, meta.join(' · ')),
      TruncatedList(c.names, { max: 12, inline: true }),
      Disclosure({
        summary: t('rpl.csr.title'),
        className: 'rpl-csr',
        open: i === 0,
        children: h('div', { class: 'stack-sm' },
          h('h5', { class: 'rpl-csr-h' }, t('rpl.csr.openssl')),
          h('div', { dataset: { role: 'rpl-openssl' } }, CodeBlock(o.config, { label: o.file, maxHeight: 280 })),
          h('p', { class: 'text-sm' }, t('rpl.csr.run')),
          h('div', { dataset: { role: 'rpl-openssl-cmd' } }, CodeBlock(o.command, { wrap: true })),
          download(o.file, o.config),
          h('h5', { class: 'rpl-csr-h' }, t('rpl.csr.certreq')),
          h('div', { dataset: { role: 'rpl-certreq' } }, CodeBlock(w.inf.replace(/\r\n/g, '\n'), { label: w.file, maxHeight: 280 })),
          h('p', { class: 'text-sm' }, t('rpl.csr.run')),
          h('div', { dataset: { role: 'rpl-certreq-cmd' } }, CodeBlock(w.command, { wrap: true })),
          download(w.file, w.inf))
      }));
  }

  function groupingPanel(g) {
    const box = h('div', { class: 'stack rpl-g', dataset: { grouping: g.id, certs: String(g.certs.length), entries: String(g.entries) } });
    box.append(h('p', { class: 'rpl-g-sum' },
      h('strong', null, t('rpl.g.certs', { count: g.certs.length })), ' · ',
      t('rpl.g.entries', { count: g.entries })));
    box.append(h('p', { class: 'text-sm muted' }, t(`rpl.g.desc.${g.id}`)));
    for (const note of g.notes) {
      box.append(h('p', { class: 'text-sm rpl-note', dataset: { note } }, Icon('info', { size: 14 }), ' ', t(`rpl.note.${note}`, { max: formatNumber(SAN_LIMIT) })));
    }
    if (g.uncovered.length) {
      box.append(h('section', { class: 'stack-sm rpl-unc' },
        h('h4', { class: 'rpl-h' }, t('rpl.unc.title')),
        h('ul', { class: 'rpl-unc-list' }, g.uncovered.map((u) => h('li', { dataset: { name: u.name, reason: u.reason } },
          t(`rpl.unc.${u.reason}`, { name: u.name, wildcard: u.wildcard }))))));
    }
    box.append(...g.certs.map((c, i) => certCard(c, i)));
    return box;
  }

  function renderPlan() {
    clearTimeout(covTimer);
    clear(planEl);
    const plan = coveragePlan(namesField.value);
    if (plan.invalid.length) {
      planEl.append(h('p', { class: 'text-sm rpl-invalid' }, Icon('alert', { size: 14 }), ' ',
        t('rpl.cov.invalid', { count: plan.invalid.length, list: plan.invalid.slice(0, 6).join(', ') + (plan.invalid.length > 6 ? ' …' : '') })));
    }
    if (!plan.groupings.length) {
      planEl.append(h('p', { class: 'muted rpl-cov-empty' }, t('rpl.cov.empty')));
      return;
    }
    if (!plan.groupings.some((g) => g.id === grouping)) grouping = plan.groupings[0].id;
    const tabs = Tabs(plan.groupings.map((g) => ({
      id: g.id,
      label: t(`rpl.g.${g.id}`),
      badge: g.certs.length,
      content: () => groupingPanel(g)
    })), { selected: grouping, label: t('rpl.cov.groupings'), className: 'rpl-tabs', onChange: (id) => { grouping = id; } });
    planEl.append(tabs.el);
  }

  function refresh() {
    if (destroyed) return;
    renderCert();
    renderSources();
  }

  renderSchedule();
  renderCert();
  renderSources();
  renderPlan();

  return {
    el,
    refresh,
    destroy() {
      destroyed = true;
      clearTimeout(covTimer);
      for (const entry of ari.values()) if (entry.controller) entry.controller.abort();
    }
  };
}
