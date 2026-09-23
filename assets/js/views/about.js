/**
 * views/about.js — how the toolkit works, data sources & quotas, privacy, the companion
 * CLI (download + usage), self-hosting on GitHub Pages, credits and license.
 */

import { h } from '../ui/dom.js';
import {
  Alert, Badge, ButtonLink, Button, CodeBlock, Disclosure, ExternalLink, Icon, Section, confirmDialog, toast
} from '../ui/components.js';
import { registerStrings, formatDate, formatNumber, formatRegion } from '../i18n.js';
import { RESOLVERS, RESOLVERS_VERIFIED, GEO_VANTAGES } from '../lib/resolvers.js';
import { RANGES_UPDATED, PROVIDERS } from '../lib/netinfo.js';

/** Route id. */
export const id = 'about';
/** i18n key of the page title. */
export const titleKey = 'nav.about';
/** Nav/page icon. */
export const icon = 'info';

/** Path of the CLI relative to the site root (published by the Pages workflow). */
export const CLI_PATH = 'cli/ssl_origin_scan.py';

registerStrings('en', {
  'about.heroTitle': 'SSL & DNS toolkit for people who run many servers',
  'about.heroBody': 'A customer sends a renewed certificate for *.example.com.tr and you have to install it everywhere it is used. DomainScope finds every name the certificate covers, resolves them, recognises Cloudflare and other proxies, and matches the answers to your own server inventory — so you know exactly which machines need the new certificate.',
  'about.heroStatic': 'Everything runs in your browser against public, CORS-enabled APIs. There is no backend and nothing to install; the companion CLI covers the one thing a browser cannot do.',
  'about.start': 'Find SSL targets',
  'about.downloadCli': 'Download the CLI',
  'about.source': 'Source code',
  'about.onThisPage': 'On this page',
  'about.toc.how': 'How it works',
  'about.toc.cloudflare': 'Cloudflare & CDNs',
  'about.toc.sources': 'Sources & quotas',
  'about.toc.privacy': 'Privacy',
  'about.toc.cli': 'CLI',
  'about.toc.selfhost': 'Self-hosting',
  'about.toc.license': 'License',

  'about.howTitle': 'How it works',
  'about.howDesc': 'Five steps, each of which you can also use on its own through the other tools.',
  'about.step1Title': 'Collect names',
  'about.step1Body': 'Certificate Transparency logs (crt.sh, Cert Spotter), passive DNS (HackerTarget, Anubis, AlienVault OTX), the names inside your certificate and — optionally — a wordlist. Sources disagree, so they are merged.',
  'about.step2Title': 'Resolve over HTTPS',
  'about.step2Body': 'Your browser asks public DNS-over-HTTPS resolvers directly (Cloudflare, Google, Quad9 …), with automatic failover. Global DNS repeats a query from 12 resolvers and 30+ locations.',
  'about.step3Title': 'Classify',
  'about.step3Body': 'Answer IPs and CNAME chains are compared with the official ranges of Cloudflare, Fastly, CloudFront and others, and with platform domains, so proxies are never mistaken for your servers.',
  'about.step4Title': 'Match your servers',
  'about.step4Body': 'Direct IPs are looked up in your inventory: the result is the list of servers that need the certificate, plus IPs you do not know yet.',
  'about.step5Title': 'Confirm from inside',
  'about.step5Body': 'For names behind a proxy, the CLI connects to your servers’ own IPs with SNI and reads the certificate each one serves — including whether it is already the new one.',

  'about.cfTitle': 'Why Cloudflare hides your servers',
  'about.cfBody1': 'With Cloudflare’s proxy (the orange cloud) — or any CDN/WAF — public DNS answers with the proxy’s addresses, not yours. Every DNS-based tool therefore sees the same edge IPs, and online scanners disagree about the rest.',
  'about.cfBody2': 'The certificate still has to be installed on the origin servers behind the proxy (unless the proxy terminates TLS with its own certificate). The only reliable way to find them is to ask them: connect to each server IP and request the hostname via SNI.',
  'about.cfBody3': 'The browser cannot open raw TLS connections, so this last step is done by the companion CLI, run from a machine inside your network. The web app prepares its input: names.txt and targets.txt.',
  'about.flowPublic': 'What public DNS shows',
  'about.flowCli': 'What the CLI checks',
  'about.flowVisitor': 'Visitor',
  'about.flowEdge': 'Cloudflare edge',
  'about.flowOrigin': 'Your server',
  'about.flowHidden': 'hidden',
  'about.flowJump': 'Jump host',
  'about.flowSni': 'TLS, SNI = name',
  'about.flowCert': 'serves cert ✓',
  'about.cfHints': 'The scan also collects origin hints that often leak the real IPs: SPF records, MX hosts, non-proxied sibling names and historical DNS from before Cloudflare was enabled.',

  'about.sourcesTitle': 'Data sources & quotas',
  'about.sourcesDesc': 'Only services that allow browser access (CORS) are used. Free tiers have limits — when one is reached the tool says so and continues with the others.',
  'about.col.source': 'Source',
  'about.col.provides': 'Provides',
  'about.col.limits': 'Limits & notes',
  'about.src.crtsh': 'Certificate Transparency search: every name that appeared in a public certificate.',
  'about.src.crtshLimit': 'Free. Can be slow (a minute or more) or briefly unavailable under load; retried once.',
  'about.src.certspotter': 'Certificate Transparency issuances with names and fingerprints.',
  'about.src.certspotterLimit': 'Small anonymous hourly quota (HTTP 429 when used up).',
  'about.src.hackertarget': 'Host search (names + current IPs) and reverse IP lookup.',
  'about.src.hackertargetLimit': 'About 50 requests per day per IP address, shared by both endpoints.',
  'about.src.anubis': 'Subdomain database.',
  'about.src.anubisLimit': 'Free, no key.',
  'about.src.otx': 'Passive DNS including historical IPs — often the pre-Cloudflare origin.',
  'about.src.otxLimit': 'Anonymous access is frequently rate-limited.',
  'about.src.doh': 'All DNS answers; EDNS Client Subnet for the geographic view.',
  'about.src.dohLimit': 'Public resolvers; parallelism is capped in Settings.',
  'about.src.ripe': 'ASN, prefix, holder, geolocation and reverse DNS of IP addresses.',
  'about.src.ripeLimit': 'Free, fair use.',
  'about.src.ipwho': 'Fallback geolocation and ASN.',
  'about.src.ipwhoLimit': 'Free tiers with daily limits.',
  'about.src.rdap': 'Domain registration: registrar, dates, name servers, DNSSEC.',
  'about.src.rdapLimit': 'IANA bootstrap + registries, rdap.org fallback. .tr has no public RDAP service.',
  'about.resolversTitle': 'The {count} DNS-over-HTTPS resolvers (verified {date})',
  'about.res.name': 'Resolver',
  'about.res.location': 'Location',
  'about.res.features': 'Features',
  'about.rangesNote': 'CDN IP ranges from official sources, updated {date} ({count} providers recognised by IP range or CNAME).',
  'about.vantagesNote': 'Global DNS compares {count} vantage points in {countries} countries via EDNS Client Subnet.',

  'about.privacyTitle': 'Privacy',
  'about.privacyDesc': 'Designed so sensitive data never leaves your machine.',
  'about.priv1': 'No backend, no analytics, no cookies, no tracking.',
  'about.priv2': 'Certificates are parsed in your browser. Private keys are never needed; if a file contains one it is ignored and never displayed.',
  'about.priv3': 'Your server inventory stays in this browser’s local storage (keys starting with “ssds.”) and can be deleted at any time.',
  'about.priv4': 'What third parties see: domain names you scan go to the CT / passive-DNS services and DoH resolvers; IP addresses you inspect go to RIPEstat and ipwho.is. As with any website, they also see your IP address.',
  'about.priv5': 'Requests carry no referrer, so services do not learn which page you used.',
  'about.clearData': 'Delete all local data',
  'about.clearConfirm': 'Delete the saved server inventory and all settings from this browser? This cannot be undone.',
  'about.cleared': 'Local data deleted',

  'about.cliTitle': 'Companion CLI: ssl_origin_scan.py',
  'about.cliDesc': 'Maps hostnames to servers by TLS-probing your inventory IPs with SNI — sees through Cloudflare because it talks to your servers directly. Run it from a machine inside your network (e.g. a jump host).',
  'about.cliReq': 'Python 3.8+, standard library only, a single file. Linux, macOS and Windows.',
  'about.viewSource': 'View source',
  'about.ex1': 'Renewal day — which servers still serve the old certificate?',
  'about.ex2': 'Names and targets exported from this app, ports 443 and 8443',
  'about.ex3': 'Reports for scripts (JSON) and Excel (CSV)',
  'about.ex4': 'A subnet and two names, no certificate (“who hosts these?”)',
  'about.ex5': 'CI / cron — exit code 1 while any server still needs the new certificate',
  'about.statusesTitle': 'Result statuses',
  'about.st.UPDATED': 'Serves the new certificate for the name.',
  'about.st.NEEDS_UPDATE': 'Serves a certificate that covers the name, but not the new one — install it here.',
  'about.st.NOT_HOSTED': 'Answers, but not for this name (only a default certificate).',
  'about.st.TLS_ERROR': 'The TLS handshake failed.',
  'about.st.TIMEOUT': 'No answer within the timeout.',
  'about.st.CLOSED': 'The port is closed.',

  'about.selfhostTitle': 'Run it yourself',
  'about.selfhostBody': 'It is a static site with no build step. Fork the repository and enable GitHub Pages (the included workflow publishes it), or serve the folder locally:',

  'about.licenseTitle': 'Credits & license',
  'about.licenseBody': 'Open source under the MIT license. Contributions and issue reports are welcome.',
  'about.thanks': 'Thanks to the operators of the free services listed above, which make a backend-free tool like this possible.',
  'about.version': 'Version {version}'
});

registerStrings('tr', {
  'about.heroTitle': 'Çok sayıda sunucu yönetenler için SSL & DNS araç kutusu',
  'about.heroBody': 'Müşteri *.example.com.tr için yenilenmiş bir sertifika gönderdi ve bunu kullanıldığı her yere kurmanız gerekiyor. DomainScope sertifikanın kapsadığı tüm adları bulur, çözümler, Cloudflare ve diğer proxy’leri tanır ve yanıtları kendi sunucu envanterinizle eşleştirir — böylece yeni sertifikanın tam olarak hangi makinelere kurulacağını bilirsiniz.',
  'about.heroStatic': 'Her şey tarayıcınızda, CORS destekli genel API’lere karşı çalışır. Sunucu yok, kurulacak bir şey yok; tarayıcının yapamadığı tek işi yardımcı CLI aracı üstlenir.',
  'about.start': 'SSL hedeflerini bul',
  'about.downloadCli': 'CLI aracını indir',
  'about.source': 'Kaynak kod',
  'about.onThisPage': 'Bu sayfada',
  'about.toc.how': 'Nasıl çalışır',
  'about.toc.cloudflare': 'Cloudflare ve CDN’ler',
  'about.toc.sources': 'Kaynaklar ve kotalar',
  'about.toc.privacy': 'Gizlilik',
  'about.toc.cli': 'CLI',
  'about.toc.selfhost': 'Kendin barındır',
  'about.toc.license': 'Lisans',

  'about.howTitle': 'Nasıl çalışır',
  'about.howDesc': 'Beş adım; her biri diğer araçlar üzerinden tek başına da kullanılabilir.',
  'about.step1Title': 'Adları topla',
  'about.step1Body': 'Certificate Transparency kayıtları (crt.sh, Cert Spotter), pasif DNS (HackerTarget, Anubis, AlienVault OTX), sertifikanızdaki adlar ve — isteğe bağlı — bir kelime listesi. Kaynaklar birbirini tutmaz; bu yüzden birleştirilir.',
  'about.step2Title': 'HTTPS üzerinden çözümle',
  'about.step2Body': 'Tarayıcınız genel DNS-over-HTTPS çözümleyicilerine (Cloudflare, Google, Quad9 …) doğrudan, otomatik yedeklemeyle sorar. Global DNS aynı sorguyu 12 çözümleyiciden ve 30’dan fazla konumdan tekrarlar.',
  'about.step3Title': 'Sınıflandır',
  'about.step3Body': 'Yanıttaki IP’ler ve CNAME zincirleri Cloudflare, Fastly, CloudFront ve diğerlerinin resmî IP aralıkları ve platform alan adlarıyla karşılaştırılır; böylece proxy’ler asla sizin sunucunuz sanılmaz.',
  'about.step4Title': 'Sunucularınızla eşleştir',
  'about.step4Body': 'Doğrudan IP’ler envanterinizde aranır: sonuç, sertifikanın kurulması gereken sunucuların listesi ve henüz tanımadığınız IP’lerdir.',
  'about.step5Title': 'İçeriden doğrula',
  'about.step5Body': 'Proxy arkasındaki adlar için CLI aracı sunucularınızın kendi IP’lerine SNI ile bağlanır ve her birinin sunduğu sertifikayı okur — yeni sertifikanın kurulup kurulmadığı dahil.',

  'about.cfTitle': 'Cloudflare sunucularınızı neden gizler',
  'about.cfBody1': 'Cloudflare proxy’si (turuncu bulut) — ya da herhangi bir CDN/WAF — açıkken genel DNS sizin değil, proxy’nin adreslerini döndürür. Bu yüzden DNS tabanlı her araç aynı uç (edge) IP’leri görür ve çevrimiçi tarayıcılar gerisinde birbirini tutmaz.',
  'about.cfBody2': 'Sertifikanın yine de proxy’nin arkasındaki asıl (origin) sunuculara kurulması gerekir (proxy TLS’i kendi sertifikasıyla sonlandırmıyorsa). Bunları bulmanın tek güvenilir yolu onlara sormaktır: her sunucu IP’sine bağlanıp host adını SNI ile istemek.',
  'about.cfBody3': 'Tarayıcı ham TLS bağlantısı açamaz; bu son adımı ağınızın içindeki bir makinede çalışan yardımcı CLI aracı yapar. Web uygulaması girdisini hazırlar: names.txt ve targets.txt.',
  'about.flowPublic': 'Genel DNS’in gösterdiği',
  'about.flowCli': 'CLI aracının kontrol ettiği',
  'about.flowVisitor': 'Ziyaretçi',
  'about.flowEdge': 'Cloudflare uç sunucusu',
  'about.flowOrigin': 'Sizin sunucunuz',
  'about.flowHidden': 'gizli',
  'about.flowJump': 'Atlama sunucusu',
  'about.flowSni': 'TLS, SNI = ad',
  'about.flowCert': 'sertifikayı sunar ✓',
  'about.cfHints': 'Tarama ayrıca gerçek IP’leri çoğu zaman ele veren ipuçlarını da toplar: SPF kayıtları, MX sunucuları, proxy’lenmeyen kardeş adlar ve Cloudflare açılmadan önceki geçmiş DNS kayıtları.',

  'about.sourcesTitle': 'Veri kaynakları ve kotalar',
  'about.sourcesDesc': 'Yalnızca tarayıcıdan erişime (CORS) izin veren hizmetler kullanılır. Ücretsiz katmanların sınırları vardır — biri dolduğunda araç bunu söyler ve diğerleriyle devam eder.',
  'about.col.source': 'Kaynak',
  'about.col.provides': 'Sağladığı',
  'about.col.limits': 'Sınırlar ve notlar',
  'about.src.crtsh': 'Certificate Transparency araması: genel bir sertifikada geçmiş her ad.',
  'about.src.crtshLimit': 'Ücretsiz. Yoğunlukta yavaş (bir dakika veya daha uzun) ya da kısa süre erişilemez olabilir; bir kez yeniden denenir.',
  'about.src.certspotter': 'Adları ve parmak izleriyle Certificate Transparency kayıtları.',
  'about.src.certspotterLimit': 'Anonim kullanımda küçük saatlik kota (dolunca HTTP 429).',
  'about.src.hackertarget': 'Host araması (adlar + güncel IP’ler) ve ters IP sorgusu.',
  'about.src.hackertargetLimit': 'IP adresi başına günde yaklaşık 50 istek; iki uç nokta aynı kotayı paylaşır.',
  'about.src.anubis': 'Alt alan adı veritabanı.',
  'about.src.anubisLimit': 'Ücretsiz, anahtar gerekmez.',
  'about.src.otx': 'Geçmiş IP’ler dahil pasif DNS — çoğu zaman Cloudflare öncesi asıl sunucu.',
  'about.src.otxLimit': 'Anonim erişim sık sık hız sınırına takılır.',
  'about.src.doh': 'Tüm DNS yanıtları; coğrafi görünüm için EDNS Client Subnet.',
  'about.src.dohLimit': 'Genel çözümleyiciler; paralellik Ayarlar’dan sınırlanır.',
  'about.src.ripe': 'IP adreslerinin ASN, önek, sahip, konum ve ters DNS bilgisi.',
  'about.src.ripeLimit': 'Ücretsiz, adil kullanım.',
  'about.src.ipwho': 'Yedek konum ve ASN bilgisi.',
  'about.src.ipwhoLimit': 'Günlük sınırlı ücretsiz katmanlar.',
  'about.src.rdap': 'Alan adı kaydı: kayıt kuruluşu, tarihler, ad sunucuları, DNSSEC.',
  'about.src.rdapLimit': 'IANA bootstrap + kayıt kuruluşları, yedek olarak rdap.org. .tr için genel RDAP hizmeti yok.',
  'about.resolversTitle': '{count} DNS-over-HTTPS çözümleyicisi ({date} tarihinde doğrulandı)',
  'about.res.name': 'Çözümleyici',
  'about.res.location': 'Konum',
  'about.res.features': 'Özellikler',
  'about.rangesNote': 'CDN IP aralıkları resmî kaynaklardan, {date} tarihinde güncellendi (IP aralığı veya CNAME ile tanınan {count} sağlayıcı).',
  'about.vantagesNote': 'Global DNS, EDNS Client Subnet ile {countries} ülkedeki {count} gözlem noktasını karşılaştırır.',

  'about.privacyTitle': 'Gizlilik',
  'about.privacyDesc': 'Hassas verilerin makinenizden hiç çıkmaması için tasarlandı.',
  'about.priv1': 'Sunucu yok, analitik yok, çerez yok, izleme yok.',
  'about.priv2': 'Sertifikalar tarayıcınızda ayrıştırılır. Özel anahtar hiçbir zaman gerekmez; dosyada varsa yok sayılır ve asla gösterilmez.',
  'about.priv3': 'Sunucu envanteriniz bu tarayıcının yerel depolamasında (“ssds.” ile başlayan anahtarlar) kalır ve istediğiniz an silinebilir.',
  'about.priv4': 'Üçüncü tarafların gördükleri: taradığınız alan adları CT / pasif DNS hizmetlerine ve DoH çözümleyicilerine; incelediğiniz IP adresleri RIPEstat ve ipwho.is’e gider. Her web sitesinde olduğu gibi IP adresinizi de görürler.',
  'about.priv5': 'İstekler referrer bilgisi taşımaz; hizmetler hangi sayfayı kullandığınızı öğrenmez.',
  'about.clearData': 'Tüm yerel verileri sil',
  'about.clearConfirm': 'Kayıtlı sunucu envanteri ve tüm ayarlar bu tarayıcıdan silinsin mi? Bu işlem geri alınamaz.',
  'about.cleared': 'Yerel veriler silindi',

  'about.cliTitle': 'Yardımcı CLI aracı: ssl_origin_scan.py',
  'about.cliDesc': 'Envanterinizdeki IP’lere SNI ile TLS bağlantısı yaparak host adlarını sunuculara eşler — sunucularınızla doğrudan konuştuğu için Cloudflare’in arkasını görür. Ağınızın içindeki bir makineden (ör. atlama sunucusu) çalıştırın.',
  'about.cliReq': 'Python 3.8+, yalnızca standart kütüphane, tek dosya. Linux, macOS ve Windows.',
  'about.viewSource': 'Kaynağı görüntüle',
  'about.ex1': 'Yenileme günü — hangi sunucular hâlâ eski sertifikayı sunuyor?',
  'about.ex2': 'Bu uygulamadan dışa aktarılan adlar ve hedefler, 443 ve 8443 portları',
  'about.ex3': 'Betikler (JSON) ve Excel (CSV) için raporlar',
  'about.ex4': 'Bir alt ağ ve iki ad, sertifikasız (“bunları kim barındırıyor?”)',
  'about.ex5': 'CI / cron — yeni sertifikaya ihtiyaç duyan sunucu kaldıkça çıkış kodu 1',
  'about.statusesTitle': 'Sonuç durumları',
  'about.st.UPDATED': 'Bu ad için yeni sertifikayı sunuyor.',
  'about.st.NEEDS_UPDATE': 'Adı kapsayan bir sertifika sunuyor ama yenisi değil — buraya kurun.',
  'about.st.NOT_HOSTED': 'Yanıt veriyor ama bu ad için değil (yalnızca varsayılan sertifika).',
  'about.st.TLS_ERROR': 'TLS el sıkışması başarısız oldu.',
  'about.st.TIMEOUT': 'Zaman aşımı süresinde yanıt yok.',
  'about.st.CLOSED': 'Port kapalı.',

  'about.selfhostTitle': 'Kendiniz çalıştırın',
  'about.selfhostBody': 'Derleme adımı olmayan statik bir sitedir. Depoyu çatallayıp (fork) GitHub Pages’i açın (içerideki iş akışı yayınlar) ya da klasörü yerelde sunun:',

  'about.licenseTitle': 'Katkılar ve lisans',
  'about.licenseBody': 'MIT lisansıyla açık kaynak. Katkılar ve hata bildirimleri memnuniyetle karşılanır.',
  'about.thanks': 'Böyle sunucusuz bir aracı mümkün kılan, yukarıda listelenen ücretsiz hizmetlerin işletmecilerine teşekkürler.',
  'about.version': 'Sürüm {version}'
});

/** Data sources table rows (static; mirrors spec §3). */
const SOURCES = [
  { name: 'crt.sh', url: 'https://crt.sh/', key: 'crtsh' },
  { name: 'Cert Spotter (SSLMate)', url: 'https://sslmate.com/certspotter/', key: 'certspotter' },
  { name: 'HackerTarget', url: 'https://hackertarget.com/', key: 'hackertarget' },
  { name: 'Anubis', url: 'https://anubisdb.com/', key: 'anubis' },
  { name: 'AlienVault OTX', url: 'https://otx.alienvault.com/', key: 'otx' },
  { name: 'DNS-over-HTTPS', url: 'https://datatracker.ietf.org/doc/html/rfc8484', key: 'doh' },
  { name: 'RIPEstat', url: 'https://stat.ripe.net/', key: 'ripe' },
  { name: 'ipwho.is · ipinfo.io', url: 'https://ipwho.is/', key: 'ipwho' },
  { name: 'RDAP', url: 'https://about.rdap.org/', key: 'rdap' }
];

const CLI_EXAMPLES = [
  { key: 'about.ex1', cmd: 'python3 ssl_origin_scan.py -t servers.txt --cert new-cert.pem' },
  { key: 'about.ex2', cmd: 'python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem -p 443,8443' },
  { key: 'about.ex3', cmd: 'python3 ssl_origin_scan.py -t targets.txt --cert new.pem --json report.json --csv report.csv' },
  { key: 'about.ex4', cmd: 'python3 ssl_origin_scan.py -t 10.0.0.0/24 -n www.example.com api.example.com' },
  { key: 'about.ex5', cmd: 'python3 ssl_origin_scan.py -t hosts.ini --cert new.pem --fail-on-needs-update --no-color' }
];

const CLI_STATUSES = [
  { code: 'UPDATED', variant: 'ok', icon: 'check-circle' },
  { code: 'NEEDS_UPDATE', variant: 'warn', icon: 'alert' },
  { code: 'NOT_HOSTED', variant: 'neutral', icon: 'minus-circle' },
  { code: 'TLS_ERROR', variant: 'error', icon: 'x-circle' },
  { code: 'TIMEOUT', variant: 'error', icon: 'clock' },
  { code: 'CLOSED', variant: 'unresolved', icon: 'lock' }
];

function simpleTable(headers, rows, className = '') {
  return h('div', { class: ['dt-scroll', 'dt-scroll-free', 'about-table', className], attrs: { tabindex: 0 } },
    h('table', { class: 'dt-table' },
      h('thead', null, h('tr', null, headers.map((x) => h('th', { attrs: { scope: 'col' } }, x)))),
      h('tbody', null, rows.map((cells) => h('tr', { class: 'dt-row' }, cells.map((c) => h('td', null, c)))))));
}

function flowNode(iconName, label, sub = null, variant = '') {
  return h('div', { class: ['about-flow-node', variant ? `about-flow-${variant}` : null] },
    h('span', { class: 'about-flow-icon' }, Icon(iconName, { size: 18 })),
    h('span', { class: 'about-flow-text' }, h('span', { class: 'about-flow-label' }, label), sub ? h('span', { class: 'about-flow-sub mono' }, sub) : null));
}

function flowArrow(label = null) {
  return h('div', { class: ['about-flow-arrow', { 'about-flow-arrow-wide': !!label }], attrs: { 'aria-hidden': label ? null : 'true' } },
    label ? h('span', { class: 'about-flow-arrow-label' }, label) : null, h('span', { class: 'about-flow-line' }));
}

/**
 * Mount the About view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const sections = {};
  const section = (key, opts) => {
    sections[key] = Section({ id: `about-${key}`, ...opts });
    return sections[key];
  };

  /* Hero */
  const hero = h('div', { class: 'about-hero card' },
    h('div', { class: 'about-hero-text' },
      h('h2', { class: 'about-hero-title' }, t('about.heroTitle')),
      h('p', null, t('about.heroBody')),
      h('p', { class: 'muted' }, t('about.heroStatic')),
      h('div', { class: 'cluster about-hero-actions' },
        h('a', { class: 'btn btn-primary', href: ctx.href('scan') }, Icon('target'), h('span', { class: 'btn-label' }, t('about.start'))),
        ButtonLink({ href: CLI_PATH, label: t('about.downloadCli'), icon: 'download', download: 'ssl_origin_scan.py' }),
        ButtonLink({ href: ctx.repoUrl, label: t('about.source'), icon: 'code', variant: 'ghost', external: true }))),
    h('img', { class: 'about-hero-logo', src: 'favicon.svg', alt: '', attrs: { width: 96, height: 96 } }));

  /* On this page (buttons, not #anchors — the hash is the router's) */
  const tocItems = ['how', 'cloudflare', 'sources', 'privacy', 'cli', 'selfhost', 'license'];
  const toc = h('nav', { class: 'about-toc', attrs: { 'aria-label': t('about.onThisPage') } },
    h('span', { class: 'about-toc-label' }, t('about.onThisPage')),
    tocItems.map((key) => h('button', {
      type: 'button',
      class: 'about-toc-link',
      on: {
        click: () => {
          const target = sections[key];
          if (!target) return;
          target.scrollIntoView({ block: 'start' });
          const heading = target.querySelector('.section-title');
          if (heading) {
            heading.setAttribute('tabindex', '-1');
            heading.focus({ preventScroll: true });
          }
        }
      }
    }, t(`about.toc.${key}`))));

  /* How it works */
  const steps = [
    ['search', 'about.step1Title', 'about.step1Body'],
    ['globe', 'about.step2Title', 'about.step2Body'],
    ['layers', 'about.step3Title', 'about.step3Body'],
    ['server', 'about.step4Title', 'about.step4Body'],
    ['terminal', 'about.step5Title', 'about.step5Body']
  ];
  const how = section('how', {
    title: t('about.howTitle'),
    description: t('about.howDesc'),
    children: h('ol', { class: 'about-steps' }, steps.map(([ic, title, body], i) => h('li', { class: 'about-step card' },
      h('div', { class: 'about-step-head' },
        h('span', { class: 'about-step-num num' }, String(i + 1)),
        h('span', { class: 'about-step-icon' }, Icon(ic, { size: 18 }))),
      h('h3', { class: 'about-step-title' }, t(title)),
      h('p', { class: 'about-step-body' }, t(body)))))
  });

  /* Cloudflare */
  const cloudflare = section('cloudflare', {
    title: t('about.cfTitle'),
    children: h('div', { class: 'about-cf' },
      h('div', { class: 'about-cf-text' },
        h('p', null, t('about.cfBody1')),
        h('p', null, t('about.cfBody2')),
        h('p', null, t('about.cfBody3'))),
      h('div', { class: 'about-flows' },
        h('figure', { class: 'about-flow card' },
          h('figcaption', { class: 'about-flow-caption' }, Badge(t('kind.cloudflare'), { variant: 'cloudflare', icon: 'cloud' }), ' ', t('about.flowPublic')),
          h('div', { class: 'about-flow-row' },
            flowNode('users', t('about.flowVisitor')),
            flowArrow(),
            flowNode('cloud', t('about.flowEdge'), '104.21.x.x', 'edge'),
            flowArrow(),
            flowNode('server', t('about.flowOrigin'), `10.0.1.11 · ${t('about.flowHidden')}`, 'hidden'))),
        h('figure', { class: 'about-flow card' },
          h('figcaption', { class: 'about-flow-caption' }, Badge('CLI', { variant: 'accent', icon: 'terminal' }), ' ', t('about.flowCli')),
          h('div', { class: 'about-flow-row' },
            flowNode('terminal', t('about.flowJump'), 'ssl_origin_scan.py'),
            flowArrow(t('about.flowSni')),
            flowNode('server', t('about.flowOrigin'), `10.0.1.11 · ${t('about.flowCert')}`, 'ok')))))
  });
  cloudflare.querySelector('.section-body').append(Alert({ variant: 'info', icon: 'lightbulb', message: t('about.cfHints'), compact: true }));

  /* Sources & quotas */
  const sources = section('sources', {
    title: t('about.sourcesTitle'),
    description: t('about.sourcesDesc'),
    children: h('div', { class: 'stack' },
      simpleTable(
        [t('about.col.source'), t('about.col.provides'), t('about.col.limits')],
        SOURCES.map((s) => [
          ExternalLink(s.url, s.name, { className: 'about-src-name' }),
          t(`about.src.${s.key}`),
          h('span', { class: 'muted' }, t(`about.src.${s.key}Limit`))
        ])),
      Disclosure({
        summary: t('about.resolversTitle', { count: RESOLVERS.length, date: formatDate(`${RESOLVERS_VERIFIED}T12:00:00Z`) }),
        children: simpleTable(
          [t('about.res.name'), t('about.res.location'), t('about.res.features')],
          RESOLVERS.map((r) => [
            h('div', null, h('div', { class: 'about-res-name' }, r.name), h('div', { class: 'muted text-xs' }, r.operator)),
            r.countryCode ? formatRegion(r.countryCode, r.location) : t('settings.anycast'),
            h('div', { class: 'cluster' },
              r.dnssecValidating ? Badge('DNSSEC', { variant: 'ok', icon: 'shield' }) : null,
              r.ecs ? Badge('ECS', { variant: 'info', icon: 'map-pin' }) : null,
              r.filtering ? Badge(t(`settings.filter.${r.filtering}`), { variant: 'neutral', icon: 'filter' }) : null,
              r.browserReliable === false ? Badge('HTTP/3', { variant: 'warn', icon: 'alert', title: t('settings.unreliable') }) : null)
          ]), 'about-resolvers')
      }),
      h('p', { class: 'muted text-sm' },
        t('about.rangesNote', { date: formatDate(`${RANGES_UPDATED}T12:00:00Z`), count: formatNumber(PROVIDERS.length) }),
        ' ',
        t('about.vantagesNote', {
          count: formatNumber(GEO_VANTAGES.length),
          countries: formatNumber(new Set(GEO_VANTAGES.map((g) => g.countryCode)).size)
        })))
  });

  /* Privacy */
  const privacyItems = [
    ['x-circle', 'about.priv1'],
    ['file-text', 'about.priv2'],
    ['server', 'about.priv3'],
    ['eye', 'about.priv4'],
    ['link', 'about.priv5']
  ];
  const privacy = section('privacy', {
    title: t('about.privacyTitle'),
    description: t('about.privacyDesc'),
    children: h('div', { class: 'stack' },
      h('ul', { class: 'about-privacy' }, privacyItems.map(([ic, key]) => h('li', null,
        h('span', { class: 'about-privacy-icon' }, Icon(ic, { size: 16 })), h('span', null, t(key))))),
      h('div', null, Button({
        label: t('about.clearData'),
        icon: 'trash',
        variant: 'secondary',
        dataset: { action: 'clear-data' },
        onClick: async () => {
          const ok = await confirmDialog({ message: t('about.clearConfirm'), confirmLabel: t('common.delete'), danger: true });
          if (!ok) return;
          ctx.state.clearAll();
          toast(t('about.cleared'), { type: 'success' });
        }
      })))
  });

  /* CLI */
  const cli = section('cli', {
    title: t('about.cliTitle'),
    description: t('about.cliDesc'),
    children: h('div', { class: 'stack' },
      h('div', { class: 'about-cli-bar card' },
        h('span', { class: 'about-cli-icon' }, Icon('terminal', { size: 20 })),
        h('div', { class: 'about-cli-text' },
          h('div', { class: 'about-cli-file mono' }, 'ssl_origin_scan.py'),
          h('div', { class: 'muted text-sm' }, t('about.cliReq'))),
        h('div', { class: 'cluster' },
          ButtonLink({ href: CLI_PATH, label: t('common.download'), icon: 'download', variant: 'primary', download: 'ssl_origin_scan.py' }),
          ButtonLink({ href: CLI_PATH, label: t('about.viewSource'), icon: 'eye', variant: 'ghost', external: true }))),
      h('div', { class: 'about-examples' }, CLI_EXAMPLES.map((ex) => CodeBlock(ex.cmd, { label: t(ex.key), wrap: true }))),
      h('h3', { class: 'about-subtitle' }, t('about.statusesTitle')),
      simpleTable([t('common.status'), t('common.details')], CLI_STATUSES.map((s) => [
        Badge(s.code, { variant: s.variant, icon: s.icon, mono: true }),
        t(`about.st.${s.code}`)
      ]), 'about-statuses'))
  });

  /* Self-hosting */
  const selfhost = section('selfhost', {
    title: t('about.selfhostTitle'),
    children: h('div', { class: 'stack-sm' },
      h('p', { class: 'text-2' }, t('about.selfhostBody')),
      CodeBlock('git clone https://github.com/halilibrahimd27/domainscope.git\ncd domainscope\nnpm run serve      # or: python -m http.server 8080', { label: 'shell' }))
  });

  /* License */
  const license = section('license', {
    title: t('about.licenseTitle'),
    children: h('div', { class: 'stack-sm' },
      h('p', null, t('about.licenseBody')),
      h('p', { class: 'muted' }, t('about.thanks')),
      h('div', { class: 'cluster' },
        Badge('MIT', { variant: 'accent', icon: 'book' }),
        Badge(t('about.version', { version: ctx.version }), { variant: 'neutral' }),
        ExternalLink(ctx.repoUrl, 'GitHub')))
  });

  container.append(hero, toc, how, cloudflare, sources, privacy, cli, selfhost, license);
}

/** Nothing to clean up. */
export function unmount() {}

export default { id, titleKey, icon, mount, unmount };
