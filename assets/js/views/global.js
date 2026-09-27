/**
 * views/global.js — "Global DNS": ask one question to every public DNS-over-HTTPS resolver
 * and — through EDNS Client Subnet (ECS) — on behalf of ~30 locations around the world.
 *
 * - Results stream in (lib/propagation.checkPropagation `onResult`) into two tables that are
 *   pre-filled with "querying…" rows, so the user sees every source from the start.
 * - Identical answers are grouped; every group gets a letter (A, B, C …) and a colour, so the
 *   information never depends on colour alone, and shows who operates its addresses. Clicking a
 *   group filters both tables.
 * - The summary says why answers differ (lib/propagation.propagationVerdict): CDN / GeoDNS edges
 *   differ by design; NXDOMAIN, SERVFAIL, private or direct addresses among CDN edges and a CNAME
 *   that differs before the CDN are named as propagation or a misconfiguration.
 * - "IP addresses worldwide" lists every address any source returned, who operates it
 *   (Cloudflare / CDN / platform / direct / private) and whether it is one of the user's
 *   servers (inventory) — the "Global DNS should give us the IPs too" request.
 * - Shareable: `#/global?name=www.example.com&type=A` (optional `geo=0`) runs on open.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CopyButton, DataTable, Disclosure, EmptyState, Icon, KindBadge, ProgressBar,
  Section, StatCard, TruncatedList, checkbox, ipSortValue, select, setButtonBusy, textInput
} from '../ui/components.js';
import { registerStrings, hasString, formatNumber, formatDuration, formatRegion } from '../i18n.js';
import { RESOLVERS, GEO_VANTAGES } from '../lib/resolvers.js';
import { Flag } from '../ui/flag.js';
import { checkPropagation, propagationVerdict, splitChain } from '../lib/propagation.js';
import { classifyResolution, ipVersion, isPrivateIP, normalizeIP } from '../lib/netinfo.js';
import { normalizeHostname } from '../lib/domain.js';
import { lookupServers } from '../lib/inventory.js';
import { mergeSignals } from '../lib/util.js';

/** Route id (`#/global`). */
export const id = 'global';
/** i18n key of the page title. */
export const titleKey = 'nav.global';
/** Icon name (ui/components.js Icon). */
export const icon = 'globe';

/** Record types offered (spec §6.3). */
export const GLOBAL_TYPES = Object.freeze(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'HTTPS', 'SOA']);

/** Number of distinct group colours defined in global.css (.glb-g0 … .glb-g7). */
export const GROUP_COLORS = 8;

/** Per-request timeout of the comparison queries (each source is asked once, no retry). */
export const QUERY_TIMEOUT_MS = 5000;

/** Example queries shown under the form. */
const EXAMPLES = [
  { name: 'www.amazon.com', type: 'A' },
  { name: 'www.microsoft.com', type: 'A' },
  { name: 'github.com', type: 'MX' },
  { name: 'cloudflare.com', type: 'NS' }
];

registerStrings('en', {
  'glb.formTitle': 'Query',
  'glb.name': 'Host name',
  'glb.namePlaceholder': 'www.example.com',
  'glb.type': 'Record type',
  'glb.geo': 'Also ask on behalf of {count} locations (EDNS Client Subnet)',
  'glb.run': 'Check worldwide',
  'glb.examples': 'Try:',
  'glb.invalidName': 'Enter a valid host name, e.g. www.example.com.',
  'glb.ipGiven': 'That is an IP address. Use IP Intel for addresses, or enter a host name here.',
  'glb.progress': 'Asking resolvers and locations',
  'glb.progressDone': 'All answers received',
  'glb.cancelled': 'Stopped — showing the answers received so far.',
  'glb.how.title': 'Why can answers differ?',
  'glb.how.ecs': 'Locations use EDNS Client Subnet (ECS): Google Public DNS is asked on behalf of a typical home-internet subnet in each place, so the authoritative server answers as if a user there had asked.',
  'glb.how.geo': 'CDNs and GeoDNS services (Cloudflare, Akamai, CloudFront …) deliberately hand out different, nearby servers per region — different IPs per location are normal for them.',
  'glb.how.anycast': 'Public resolvers are anycast: you reach the nearest point of presence (PoP, shown when the resolver reports its NSID). Each PoP has its own cache and its own view of GeoDNS.',
  'glb.how.ttl': 'Right after a DNS change, resolvers keep the old answer until its TTL expires — that is what “DNS propagation” means.',
  'glb.how.filter': 'Filtering resolvers (Quad9, Cloudflare Family, CleanBrowsing) may block a name on purpose; that is shown as “Blocked”, not as a different answer.',
  'glb.how.browser': 'A web page can only read resolvers that send a CORS header. Quad9 leaves it out over HTTP/3 — which Chrome, Edge and other browsers use for Quad9 — so its rows usually show “Not readable in browsers” instead of an answer.',
  'glb.emptyTitle': 'Compare DNS answers around the world',
  'glb.emptyBody': 'Enter a host name to ask 12 public resolvers and {count} locations at once — after a DNS change, to check CDN/GeoDNS steering, or to collect every IP address a name uses.',

  'glb.sum.running': 'Collecting answers…',
  'glb.sum.stoppedTitle': 'Stopped',
  'glb.sum.agreeTitle': 'All answers agree',
  'glb.sum.agreeBody': { one: 'The source returned this answer.', other: 'All {count} resolvers and locations returned the same answer.' },
  'glb.sum.geoTitle': 'Resolvers agree — locations differ',
  'glb.sum.geoBody': 'The locations see {groups} different answers. That is normal for CDNs and GeoDNS: every region is sent to nearby servers.',
  'glb.sum.designTitle': 'Differs by design: CDN / GeoDNS edges ({operators})',
  'glb.sum.designBody': 'Every answer is an edge of a known CDN, platform or DNS steering service, and the CNAME chains agree up to it. Such operators hand out different, nearby servers per region and resolver — this is not propagation.',
  'glb.sum.designMulti': 'More than one operator answers (multi-CDN steering). If you are moving from one to the other, answers that point to the old one stay cached until their TTL expires.',
  'glb.sum.designPart': 'The differences between {operators} edges are by design; these are not:',
  'glb.sum.differTitle': 'Answers differ',
  'glb.sum.differBody': 'The sources return {groups} different answers.',
  'glb.sum.failedTitle': 'No answers',
  'glb.sum.failedBody': 'Every query failed. Check your connection, or whether a browser extension or firewall blocks DNS-over-HTTPS.',
  'glb.sum.errors': { one: '{count} query failed (not counted as a difference).', other: '{count} queries failed (not counted as a difference).' },
  'glb.sum.blocked': { one: '{count} answer was blocked by a filtering resolver.', other: '{count} answers were blocked by filtering resolvers.' },
  'glb.sum.rewritten': '{names}: an answer only filtering resolvers give — usually a deliberate rewrite (SafeSearch, a content filter), so it is not counted as a difference.',
  'glb.sum.unavailable': '{names}: not readable from a browser (HTTP/3 without a CORS header) — not counted as a failure.',

  'glb.find.rcode': '{sources}: {rcode} — no answer at all, typically a DNSSEC validation failure or name servers that resolver cannot reach. A fault, not a propagation delay.',
  'glb.find.nxdomain': '{sources}: NXDOMAIN (the name does not exist), unlike the other answers. The name was created or deleted recently — each answer stays cached until its TTL expires (for NXDOMAIN, the zone’s SOA minimum) — or its name servers disagree.',
  'glb.find.nodata': '{sources}: an empty answer (no {type} records). A record added or removed recently (the empty answer stays cached for the zone’s SOA minimum), or a CNAME target without {type} records there.',
  'glb.find.private': '{sources}: private addresses ({ips}) — an internal (split-horizon) answer or a mistake in the record; nobody on the internet can reach them.',
  'glb.find.mixed': {
    one: 'Group {groups} has a direct address ({ips}) that is not on {operators}. If the name moved onto or off the CDN recently, one side is an old answer that stays cached until its TTL expires; otherwise these sources are steered around the CDN.',
    other: 'Groups {groups} have direct addresses ({ips}) that are not on {operators}. If the name moved onto or off the CDN recently, one side is an old answer that stays cached until its TTL expires; otherwise these sources are steered around the CDN.'
  },
  'glb.find.cname': 'The record at {owner} differs between sources: {targets}. It changed recently and the old answer stays cached until its TTL expires, or its name servers disagree.',
  'glb.find.addressRecords': '{type} records',
  'glb.find.direct': 'Different addresses, none on a CDN, platform or steering service this tool knows: typically a recent change that is still propagating (old answers stay cached until their TTL expires), or GeoDNS / round-robin by an operator it does not recognise.',
  'glb.find.records': 'Different records: typically a recent change that is still propagating (old answers stay cached until their TTL expires), or name servers that disagree.',
  'glb.find.more': '+{count} more',

  'glb.stat.answered': 'Answered',
  'glb.stat.failed': '{count} failed',
  'glb.stat.unavailable': '{count} not readable in browsers',
  'glb.stat.groups': 'Distinct answers',
  'glb.stat.ips': 'IP addresses',
  'glb.stat.latency': 'Median latency',
  'glb.stat.latencyHint': 'resolvers only',
  'glb.stat.inventory': { zero: 'none of your servers', one: '{count} of your servers', other: '{count} of your servers' },

  'glb.groups.title': 'Answer groups',
  'glb.groups.desc': 'Identical answers share a letter and a colour. Click a group to show only its rows.',
  'glb.group.label': 'Group {letter}',
  'glb.group.members': { one: '{count} source', other: '{count} sources' },
  'glb.group.error': 'Failed',
  'glb.group.blocked': 'Blocked',
  'glb.group.filterOn': 'Showing group {letter} only',
  'glb.group.showAll': 'Show all',

  'glb.ips.title': 'IP addresses worldwide',
  'glb.ips.desc': 'Every address any resolver or location returned — who operates it and whether it is one of your servers.',
  'glb.ips.col.ip': 'IP address',
  'glb.ips.col.owner': 'Operator',
  'glb.ips.col.seen': 'Returned by',
  'glb.ips.col.where': 'Where',
  'glb.ips.col.server': 'Your server',
  'glb.ips.seen': '{count} of {total}',
  'glb.ips.resolvers': { one: '{count} resolver', other: '{count} resolvers' },
  'glb.ips.intel': 'Open in IP Intel',
  'glb.ips.copy': 'Copy IPs',
  'glb.ips.none': 'No A/AAAA addresses in these answers.',

  'glb.res.title': 'Public resolvers',
  'glb.res.desc': '{count} DNS-over-HTTPS resolvers, each asked directly (no failover). Anycast resolvers answer from the PoP nearest to you.',
  'glb.geo.title': 'Locations — GeoDNS via EDNS Client Subnet',
  'glb.geo.desc': 'Google Public DNS asked on behalf of a home-internet subnet in {count} locations: roughly what users there get.',
  'glb.col.resolver': 'Resolver',
  'glb.col.location': 'Location',
  'glb.col.filtering': 'Filtering',
  'glb.col.group': 'Group',
  'glb.col.answer': 'Answer',
  'glb.col.ttl': 'TTL',
  'glb.col.status': 'Status',
  'glb.col.dnssec': 'DNSSEC',
  'glb.col.latency': 'Latency',
  'glb.col.isp': 'ISP',
  'glb.col.subnet': 'Client subnet',
  'glb.col.scope': 'Scope',
  'glb.col.operator': 'Operator',
  'glb.anycast': 'Anycast',
  'glb.pop': 'PoP {id}',
  'glb.popTitle': 'Point of presence that answered (NSID)',
  'glb.adYes': 'Validated',
  'glb.adTitle': 'The resolver validated this answer with DNSSEC (AD flag).',
  'glb.adNo': 'Not validated (unsigned zone, or the resolver did not set AD).',
  'glb.pending': 'Querying…',
  'glb.value.nodata': 'No records',
  'glb.value.nodataTitle': 'The name exists but has no records of this type (NODATA).',
  'glb.value.failed': 'Query failed',
  'glb.value.blocked': 'Blocked',
  'glb.value.blockedTitle': 'This filtering resolver blocks the name (malware or content filter).',
  'glb.value.unavailable': 'Not readable in browsers',
  'glb.value.unavailableShort': 'HTTP/3 without CORS',
  'glb.value.unavailableTitle': '{name} answers browsers over HTTP/3 without a CORS header, so the browser discards the reply. This says nothing about the name — ask {name} from a terminal to see its answer.',
  'glb.value.terminal': 'In a terminal:',
  'glb.value.aliasOf': 'alias',
  'glb.scopeTitle': 'ECS scope returned by the authoritative server: /24 means the answer is specific to this subnet, /0 means everyone gets the same answer.',
  'glb.scopeNone': 'Not reported',
  'glb.links': 'More about this name:',
  'glb.ttlTitle': 'Cached for {human}'
});

registerStrings('tr', {
  'glb.formTitle': 'Sorgu',
  'glb.name': 'Host adı',
  'glb.namePlaceholder': 'www.ornek.com.tr',
  'glb.type': 'Kayıt türü',
  'glb.geo': '{count} konum adına da sor (EDNS Client Subnet)',
  'glb.run': 'Dünya genelinde kontrol et',
  'glb.examples': 'Deneyin:',
  'glb.invalidName': 'Geçerli bir host adı girin, ör. www.ornek.com.tr.',
  'glb.ipGiven': 'Bu bir IP adresi. Adresler için IP Bilgisi aracını kullanın ya da buraya bir host adı girin.',
  'glb.progress': 'Çözümleyicilere ve konumlara soruluyor',
  'glb.progressDone': 'Tüm yanıtlar alındı',
  'glb.cancelled': 'Durduruldu — o ana kadar gelen yanıtlar gösteriliyor.',
  'glb.how.title': 'Yanıtlar neden farklı olabilir?',
  'glb.how.ecs': 'Konumlar EDNS Client Subnet (ECS) kullanır: Google Public DNS’e her yerdeki tipik bir ev interneti alt ağı adına sorulur; yetkili sunucu, oradaki bir kullanıcı sormuş gibi yanıt verir.',
  'glb.how.geo': 'CDN’ler ve GeoDNS hizmetleri (Cloudflare, Akamai, CloudFront …) her bölgeye bilerek farklı ve yakın sunucular verir — konuma göre farklı IP’ler onlar için normaldir.',
  'glb.how.anycast': 'Genel çözümleyiciler anycast’tir: size en yakın erişim noktasına (PoP; çözümleyici NSID bildiriyorsa gösterilir) bağlanırsınız. Her PoP’un kendi önbelleği ve kendi GeoDNS görünümü vardır.',
  'glb.how.ttl': 'Bir DNS değişikliğinden hemen sonra çözümleyiciler eski yanıtı TTL süresi dolana kadar tutar — “DNS yayılması” (propagation) budur.',
  'glb.how.filter': 'Filtreleyen çözümleyiciler (Quad9, Cloudflare Family, CleanBrowsing) bir adı bilerek engelleyebilir; bu farklı bir yanıt olarak değil “Engellendi” olarak gösterilir.',
  'glb.how.browser': 'Bir web sayfası yalnızca CORS başlığı gönderen çözümleyicileri okuyabilir. Quad9 bu başlığı HTTP/3’te göndermiyor — Chrome, Edge ve diğer tarayıcılar Quad9 için HTTP/3 kullanıyor — bu yüzden satırlarında genellikle yanıt yerine “Tarayıcıda okunamıyor” görünür.',
  'glb.emptyTitle': 'DNS yanıtlarını dünya genelinde karşılaştırın',
  'glb.emptyBody': 'Bir host adı girin; 12 genel çözümleyiciye ve {count} konuma aynı anda sorulsun — DNS değişikliğinden sonra, CDN/GeoDNS yönlendirmesini kontrol etmek ya da bir adın kullandığı tüm IP adreslerini toplamak için.',

  'glb.sum.running': 'Yanıtlar toplanıyor…',
  'glb.sum.stoppedTitle': 'Durduruldu',
  'glb.sum.agreeTitle': 'Tüm yanıtlar aynı',
  'glb.sum.agreeBody': { one: 'Kaynak bu yanıtı döndürdü.', other: '{count} çözümleyici ve konumun hepsi aynı yanıtı döndürdü.' },
  'glb.sum.geoTitle': 'Çözümleyiciler aynı — konumlar farklı',
  'glb.sum.geoBody': 'Konumlar {groups} farklı yanıt görüyor. CDN ve GeoDNS için bu normaldir: her bölge yakınındaki sunuculara yönlendirilir.',
  'glb.sum.designTitle': 'Tasarım gereği farklı: CDN / GeoDNS uç sunucuları ({operators})',
  'glb.sum.designBody': 'Her yanıt bilinen bir CDN’in, platformun ya da DNS yönlendirme hizmetinin uç sunucusu ve CNAME zincirleri ona kadar aynı. Bu işletenler her bölgeye ve çözümleyiciye farklı, yakın sunucular verir — bu bir yayılma (propagation) sorunu değil.',
  'glb.sum.designMulti': 'Birden fazla işleten yanıt veriyor (çoklu CDN yönlendirmesi). Birinden diğerine geçiyorsanız, eskisini gösteren yanıtlar TTL süresi dolana kadar önbellekte kalır.',
  'glb.sum.designPart': '{operators} uç sunucuları arasındaki farklar tasarım gereği; şunlar öyle değil:',
  'glb.sum.differTitle': 'Yanıtlar farklı',
  'glb.sum.differBody': 'Kaynaklar {groups} farklı yanıt döndürüyor.',
  'glb.sum.failedTitle': 'Yanıt alınamadı',
  'glb.sum.failedBody': 'Tüm sorgular başarısız oldu. Bağlantınızı ya da bir tarayıcı eklentisinin veya güvenlik duvarının DNS-over-HTTPS’i engelleyip engellemediğini kontrol edin.',
  'glb.sum.errors': '{count} sorgu başarısız oldu (farklılık sayılmadı).',
  'glb.sum.blocked': '{count} yanıt filtreleyen çözümleyiciler tarafından engellendi.',
  'glb.sum.rewritten': '{names}: yalnızca filtreleyen çözümleyicilerin verdiği bir yanıt — genellikle bilinçli bir yeniden yazma (SafeSearch, içerik filtresi), bu yüzden farklılık sayılmadı.',
  'glb.sum.unavailable': '{names}: tarayıcıdan okunamıyor (HTTP/3’te CORS başlığı yok) — başarısız sayılmadı.',

  'glb.find.rcode': '{sources}: {rcode} — hiç yanıt yok; genellikle DNSSEC doğrulama hatası ya da o çözümleyicinin ulaşamadığı ad sunucuları. Bu bir arıza, yayılma gecikmesi değil.',
  'glb.find.nxdomain': '{sources}: NXDOMAIN (ad mevcut değil), diğer yanıtlardan farklı olarak. Ad yakın zamanda oluşturuldu ya da silindi — her yanıt TTL süresi dolana kadar önbellekte kalır (NXDOMAIN için bölgenin SOA minimum değeri) — ya da ad sunucuları birbiriyle çelişiyor.',
  'glb.find.nodata': '{sources}: boş yanıt ({type} kaydı yok). Yakın zamanda eklenen ya da silinen bir kayıt (boş yanıt, bölgenin SOA minimum süresi boyunca önbellekte kalır) ya da orada {type} kaydı olmayan bir CNAME hedefi.',
  'glb.find.private': '{sources}: özel adresler ({ips}) — iç ağa ait bir yanıt (split-horizon) ya da kayıtta bir hata; internetten kimse bu adreslere ulaşamaz.',
  'glb.find.mixed': {
    one: '{groups} grubunda {operators} üzerinde olmayan doğrudan bir adres var ({ips}). Ad yakın zamanda CDN’e taşındıysa ya da CDN’den çıkarıldıysa taraflardan biri, TTL süresi dolana kadar önbellekte kalan eski yanıttır; değilse bu kaynaklar CDN’i atlayacak şekilde yönlendiriliyor.',
    other: '{groups} gruplarında {operators} üzerinde olmayan doğrudan adresler var ({ips}). Ad yakın zamanda CDN’e taşındıysa ya da CDN’den çıkarıldıysa taraflardan biri, TTL süresi dolana kadar önbellekte kalan eski yanıttır; değilse bu kaynaklar CDN’i atlayacak şekilde yönlendiriliyor.'
  },
  'glb.find.cname': '{owner} kaydı kaynaklara göre farklı: {targets}. Kayıt yakın zamanda değişti ve eski yanıt TTL süresi dolana kadar önbellekte kalıyor ya da ad sunucuları birbiriyle çelişiyor.',
  'glb.find.addressRecords': '{type} kayıtları',
  'glb.find.direct': 'Farklı adresler; hiçbiri bu aracın tanıdığı bir CDN’de, platformda ya da yönlendirme hizmetinde değil: genellikle hâlâ yayılmakta olan yeni bir değişiklik (eski yanıtlar TTL dolana kadar önbellekte kalır) ya da tanımadığı bir işletenin GeoDNS / round-robin dağıtımı.',
  'glb.find.records': 'Farklı kayıtlar: genellikle hâlâ yayılmakta olan yeni bir değişiklik (eski yanıtlar TTL dolana kadar önbellekte kalır) ya da birbiriyle çelişen ad sunucuları.',
  'glb.find.more': '+{count} tane daha',

  'glb.stat.answered': 'Yanıtlanan',
  'glb.stat.failed': '{count} başarısız',
  'glb.stat.unavailable': '{count} tanesi tarayıcıda okunamıyor',
  'glb.stat.groups': 'Farklı yanıt',
  'glb.stat.ips': 'IP adresi',
  'glb.stat.latency': 'Ortanca gecikme',
  'glb.stat.latencyHint': 'yalnızca çözümleyiciler',
  'glb.stat.inventory': { zero: 'sunucularınızdan hiçbiri değil', other: '{count} tanesi sizin sunucunuz' },

  'glb.groups.title': 'Yanıt grupları',
  'glb.groups.desc': 'Aynı yanıtlar aynı harfi ve rengi paylaşır. Yalnızca o grubun satırlarını görmek için gruba tıklayın.',
  'glb.group.label': '{letter} grubu',
  'glb.group.members': '{count} kaynak',
  'glb.group.error': 'Başarısız',
  'glb.group.blocked': 'Engellendi',
  'glb.group.filterOn': 'Yalnızca {letter} grubu gösteriliyor',
  'glb.group.showAll': 'Tümünü göster',

  'glb.ips.title': 'Dünya genelindeki IP adresleri',
  'glb.ips.desc': 'Herhangi bir çözümleyicinin ya da konumun döndürdüğü tüm adresler — kimin işlettiği ve sizin sunucularınızdan biri olup olmadığı.',
  'glb.ips.col.ip': 'IP adresi',
  'glb.ips.col.owner': 'İşleten',
  'glb.ips.col.seen': 'Döndüren',
  'glb.ips.col.where': 'Nerede',
  'glb.ips.col.server': 'Sunucunuz',
  'glb.ips.seen': '{total} kaynaktan {count}',
  'glb.ips.resolvers': '{count} çözümleyici',
  'glb.ips.intel': 'IP Bilgisi’nde aç',
  'glb.ips.copy': 'IP’leri kopyala',
  'glb.ips.none': 'Bu yanıtlarda A/AAAA adresi yok.',

  'glb.res.title': 'Genel çözümleyiciler',
  'glb.res.desc': '{count} DNS-over-HTTPS çözümleyicisi; her birine doğrudan (yedeğe geçmeden) soruldu. Anycast çözümleyiciler size en yakın PoP’tan yanıt verir.',
  'glb.geo.title': 'Konumlar — EDNS Client Subnet ile GeoDNS',
  'glb.geo.desc': 'Google Public DNS’e {count} konumdaki bir ev interneti alt ağı adına soruldu: oradaki kullanıcıların aldığı yanıta yakındır.',
  'glb.col.resolver': 'Çözümleyici',
  'glb.col.location': 'Konum',
  'glb.col.filtering': 'Filtreleme',
  'glb.col.group': 'Grup',
  'glb.col.answer': 'Yanıt',
  'glb.col.ttl': 'TTL',
  'glb.col.status': 'Durum',
  'glb.col.dnssec': 'DNSSEC',
  'glb.col.latency': 'Gecikme',
  'glb.col.isp': 'İnternet sağlayıcı',
  'glb.col.subnet': 'İstemci alt ağı',
  'glb.col.scope': 'Kapsam',
  'glb.col.operator': 'İşleten',
  'glb.anycast': 'Anycast',
  'glb.pop': 'PoP {id}',
  'glb.popTitle': 'Yanıt veren erişim noktası (NSID)',
  'glb.adYes': 'Doğrulandı',
  'glb.adTitle': 'Çözümleyici bu yanıtı DNSSEC ile doğruladı (AD bayrağı).',
  'glb.adNo': 'Doğrulanmadı (imzasız bölge ya da çözümleyici AD bayrağını koymadı).',
  'glb.pending': 'Sorgulanıyor…',
  'glb.value.nodata': 'Kayıt yok',
  'glb.value.nodataTitle': 'Ad mevcut ama bu türde kaydı yok (NODATA).',
  'glb.value.failed': 'Sorgu başarısız',
  'glb.value.blocked': 'Engellendi',
  'glb.value.blockedTitle': 'Bu filtreleyen çözümleyici adı engelliyor (zararlı yazılım ya da içerik filtresi).',
  'glb.value.unavailable': 'Tarayıcıda okunamıyor',
  'glb.value.unavailableShort': 'HTTP/3’te CORS yok',
  'glb.value.unavailableTitle': '{name}, tarayıcılara HTTP/3 üzerinden CORS başlığı olmadan yanıt veriyor; tarayıcı da bu yüzden yanıtı atıyor. Bu, sorgulanan adla ilgili bir sorun değil — {name} yanıtını görmek için terminalden sorun.',
  'glb.value.terminal': 'Terminalde:',
  'glb.value.aliasOf': 'takma ad',
  'glb.scopeTitle': 'Yetkili sunucunun döndürdüğü ECS kapsamı: /24 yanıtın bu alt ağa özel olduğunu, /0 herkesin aynı yanıtı aldığını gösterir.',
  'glb.scopeNone': 'Bildirilmedi',
  'glb.links': 'Bu ad hakkında daha fazlası:',
  'glb.ttlTitle': '{human} boyunca önbellekte tutulur'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/**
 * Spreadsheet-style group letter: 0 → 'A', 25 → 'Z', 26 → 'AA', 27 → 'AB' …
 * @param {number} index
 * @returns {string}
 */
export function groupLetter(index) {
  let n = Math.max(0, Math.floor(Number(index) || 0));
  let out = '';
  do {
    out = String.fromCharCode(65 + (n % 26)) + out;
    n = Math.floor(n / 26) - 1;
  } while (n >= 0);
  return out;
}

const isErrorValues = (values) => Array.isArray(values) && values.length === 1 && values[0] === 'ERROR';

/** Classic-DNS address of the resolvers browsers cannot read, for a copyable terminal command. */
const TERMINAL_DNS = Object.freeze({ quad9: '9.9.9.9', 'quad9-ecs': '9.9.9.11' });

/**
 * Is a finished row a resolver that browsers cannot read (resolvers.js `browserReliable: false`;
 * Quad9 answers over HTTP/3 without a CORS header) whose query failed at transport level?
 * Such rows are shown muted as "Not readable in browsers": they are not failures, get no answer
 * group and are not counted as errors. When such a resolver does answer (e.g. on a network that
 * blocks QUIC, so the browser falls back to HTTP/2), the row is an ordinary answer.
 * @param {{ kind?: string, pending?: boolean, values?: string[]|null, resolver?: object|null }|null} row
 * @returns {boolean}
 */
export function isBrowserBlocked(row) {
  return !!row && !row.pending && row.kind !== 'geo' && !!row.resolver
    && row.resolver.browserReliable === false && isErrorValues(row.values);
}

/**
 * `dig` command that asks a browser-unreadable resolver over classic DNS (null when unknown).
 * @param {string} resolverId
 * @param {string} name
 * @param {string} [type='A']
 * @returns {string|null}
 */
export function terminalCommand(resolverId, name, type = 'A') {
  const ip = TERMINAL_DNS[resolverId];
  return ip && name ? `dig @${ip} ${name} ${type}` : null;
}

/**
 * Group finished rows by identical answer values. Real answers come first (largest group
 * first, ties by first appearance) and get letters A, B, C … and a colour index; failed and
 * blocked groups come last and get no letter.
 * @param {Array<{ key: string, pending?: boolean, values?: string[], filtered?: boolean }>} rows
 * @returns {Array<{ key: string, values: string[], members: string[], error: boolean, filtered: boolean,
 *   letter: string|null, color: number|null }>}
 */
export function groupAnswers(rows) {
  const map = new Map();
  let order = 0;
  for (const row of rows) {
    if (!row || row.pending || !Array.isArray(row.values)) continue;
    const key = row.values.join('\n');
    let g = map.get(key);
    if (!g) {
      g = { key, values: row.values, members: [], error: isErrorValues(row.values), filtered: true, order: order++ };
      map.set(key, g);
    }
    g.members.push(row.key);
    if (!row.filtered) g.filtered = false;
  }
  const rank = (g) => (g.error ? 2 : g.filtered ? 1 : 0);
  const list = [...map.values()].sort((a, b) => rank(a) - rank(b) || b.members.length - a.members.length || a.order - b.order);
  let next = 0;
  return list.map(({ order: _o, ...g }) => {
    if (g.error || g.filtered) return { ...g, letter: null, color: null };
    const idx = next;
    next += 1;
    return { ...g, letter: groupLetter(idx), color: idx % GROUP_COLORS };
  });
}

/** Split answer values into record values and the CNAME chain (lib/propagation.js). */
export { splitChain };

/**
 * Median of finite numbers (null for an empty list).
 * @param {number[]} values
 * @returns {number|null}
 */
export function median(values) {
  const list = values.filter((v) => Number.isFinite(v)).sort((a, b) => a - b);
  if (!list.length) return null;
  const mid = Math.floor(list.length / 2);
  return list.length % 2 ? list[mid] : Math.round((list[mid - 1] + list[mid]) / 2);
}

/**
 * Minimum TTL of a response's answer records (null when there are none).
 * @param {object|null} response DnsResponse
 * @returns {number|null}
 */
export function minAnswerTtl(response) {
  let min = null;
  for (const rr of (response && Array.isArray(response.answers) ? response.answers : [])) {
    if (rr && Number.isFinite(rr.ttl) && (min === null || rr.ttl < min)) min = rr.ttl;
  }
  return min;
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

let active = null;

/**
 * Mount the Global DNS view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const lang = ctx.lang;
  const restored = ctx.restored && typeof ctx.restored === 'object' ? ctx.restored : null;

  /* --- small render helpers ----------------------------------------------- */
  const ms = (v) => (Number.isFinite(v) ? formatDuration(v) : '—');
  const humanTtl = (s) => {
    if (!Number.isFinite(s)) return '—';
    if (s < 120) return t('time.s', { n: formatNumber(s) });
    if (s < 7200) return `${formatNumber(Math.round(s / 60))} min`;
    if (s < 172800) return `${formatNumber(Math.round(s / 3600))} h`;
    return `${formatNumber(Math.round(s / 86400))} d`;
  };
  const hostLink = (host) => h('a', { class: 'glb-host mono', href: ctx.href('lookup', { name: host }) }, host);
  const ipLink = (ip) => h('a', { class: 'glb-ip mono', href: ctx.href('ip', { ips: ip }) }, ip);
  const flag = (cc, title = null) => Flag(cc, { className: 'glb-flag', title });
  const vantageName = (v) => (lang === 'tr' ? v.nameTr : v.nameEn);
  /**
   * Operator of one answer address. The CNAME chain of the same answer is taken into account,
   * so CDNs recognised by CNAME only (Akamai: *.akamaiedge.net …) are not shown as "Direct".
   */
  const classifyIp = (ip, chain = []) => classifyResolution({
    status: 'NOERROR',
    ipv4: ipVersion(ip) === 4 ? [ip] : [],
    ipv6: ipVersion(ip) === 6 ? [ip] : [],
    cnames: chain
  });

  /* --- form -------------------------------------------------------------- */
  const initialName = restored?.name ?? ctx.params.name ?? '';
  const initialType = GLOBAL_TYPES.includes(String(restored?.type ?? ctx.params.type ?? '').toUpperCase())
    ? String(restored?.type ?? ctx.params.type).toUpperCase() : 'A';
  const initialGeo = restored ? restored.geo !== false : ctx.params.geo !== '0';

  const nameField = textInput({
    label: t('glb.name'),
    value: initialName,
    placeholder: t('glb.namePlaceholder'),
    mono: true,
    className: 'glb-name',
    attrs: { 'data-role': 'global-name', inputmode: 'url', enterkeyhint: 'go' },
    onEnter: () => start()
  });
  const typeField = select({
    label: t('glb.type'),
    options: GLOBAL_TYPES,
    value: initialType,
    className: 'glb-type'
  });
  typeField.input.dataset.role = 'global-type';
  const geoField = checkbox({ label: t('glb.geo', { count: formatNumber(GEO_VANTAGES.length) }), checked: initialGeo });
  geoField.input.dataset.role = 'global-geo';
  const runBtn = Button({ label: t('glb.run'), icon: 'play', variant: 'primary', className: 'glb-run', dataset: { action: 'run' }, onClick: () => start() });
  const stopBtn = Button({ label: t('common.stop'), icon: 'stop', variant: 'secondary', className: 'glb-stop', dataset: { action: 'stop' }, onClick: () => stop() });
  stopBtn.hidden = true;

  const examples = h('div', { class: 'glb-examples cluster text-sm' },
    h('span', { class: 'muted' }, t('glb.examples')),
    EXAMPLES.map((ex) => h('button', {
      type: 'button',
      class: 'link-btn mono',
      dataset: { example: ex.name },
      on: {
        click: () => {
          nameField.value = ex.name;
          typeField.value = ex.type;
          start();
        }
      }
    }, `${ex.name} ${ex.type}`)));

  const how = Disclosure({
    summary: t('glb.how.title'),
    className: 'glb-how',
    children: h('ul', { class: 'glb-how-list' },
      ['ecs', 'geo', 'anycast', 'ttl', 'filter', 'browser'].map((k) => h('li', null, t(`glb.how.${k}`))))
  });

  const formCard = Card({
    className: 'glb-form-card',
    children: h('div', { class: 'stack' },
      h('div', { class: 'glb-form' }, nameField.el, typeField.el, h('div', { class: 'glb-buttons' }, runBtn, stopBtn)),
      h('div', { class: 'glb-form-foot' }, geoField.el, examples),
      how)
  });

  /* --- results skeleton ------------------------------------------------- */
  const progress = ProgressBar({ label: t('glb.progress') });
  progress.el.classList.add('glb-progress');
  progress.el.hidden = true;
  const summaryEl = h('div', { class: 'glb-summary', attrs: { 'aria-live': 'polite' } });
  const stats = {
    answered: StatCard({ label: t('glb.stat.answered'), icon: 'check-circle', variant: 'accent' }),
    groups: StatCard({ label: t('glb.stat.groups'), icon: 'layers' }),
    ips: StatCard({ label: t('glb.stat.ips'), icon: 'network' }),
    latency: StatCard({ label: t('glb.stat.latency'), icon: 'clock', hint: t('glb.stat.latencyHint') })
  };
  const legendEl = h('div', { class: 'glb-legend', attrs: { role: 'group', 'aria-label': t('glb.groups.title') } });
  const filterNote = h('div', { class: 'glb-filter-note', hidden: true });
  const linksEl = h('div', { class: 'glb-links cluster text-sm' });

  let filterKey = null;
  let groups = [];
  let groupByKey = new Map();
  /** propagationVerdict of the finished rows, and its groups (operators) by answer key. */
  let verdict = null;
  let verdictByKey = new Map();

  const groupClass = (g) => {
    if (!g) return null;
    if (g.error) return 'glb-gerr';
    if (g.filtered) return 'glb-gblk';
    return `glb-g${g.color}`;
  };
  const unavailableMark = () => h('span', { class: 'glb-mark-wrap', title: t('glb.value.unavailable') },
    h('span', { class: 'glb-mark glb-mark-pending', attrs: { 'aria-hidden': 'true' } }, '–'),
    h('span', { class: 'sr-only' }, t('glb.value.unavailable')));
  const groupMark = (g, { withLabel = false } = {}) => {
    if (!g) return h('span', { class: 'glb-mark glb-mark-pending', attrs: { 'aria-hidden': 'true' } }, '·');
    const text = g.letter || (g.error ? '!' : '⊘');
    const label = g.letter ? t('glb.group.label', { letter: g.letter }) : t(g.error ? 'glb.group.error' : 'glb.group.blocked');
    return h('span', { class: ['glb-mark-wrap', groupClass(g)], title: label },
      h('span', { class: 'glb-mark', attrs: { 'aria-hidden': 'true' } }, text),
      withLabel ? h('span', { class: 'glb-mark-label' }, label) : h('span', { class: 'sr-only' }, label));
  };
  const rowGroup = (row) => (row.pending || isBrowserBlocked(row) ? null : groupByKey.get(row.values.join('\n')) || null);
  const operatorName = (op) => op.name || t(`kind.${op.kind}`);
  /** Who operates an answer group's addresses ("Amazon CloudFront", "Direct" …), at most two labels. */
  function operatorLabels(ops) {
    const shown = ops.slice(0, 2).map((op) => h('span', {
      class: ['glb-prov', `glb-prov-${op.kind}`],
      title: t(op.reasonKey, { provider: op.name || t('common.unknown') })
    }, operatorName(op)));
    if (ops.length > 2) shown.push(h('span', { class: 'glb-prov', title: ops.slice(2).map(operatorName).join(', ') }, `+${ops.length - 2}`));
    return h('span', { class: 'glb-chip-ops' }, shown);
  }

  /** One compact line for the CNAME chain: "alias → a.example.net → b.cdn.net". */
  function chainLine(chain) {
    const parts = [h('span', { class: 'glb-chain-label' }, t('glb.value.aliasOf'))];
    chain.forEach((target) => parts.push(h('span', { class: 'glb-chain-arrow', attrs: { 'aria-hidden': 'true' } }, '→'), hostLink(target)));
    return h('div', { class: 'glb-chain', title: chain.join(' → ') }, parts);
  }

  /** Render one answer value (IP, host name, text record or status marker). */
  function renderValue(value, chain = []) {
    if (value.startsWith('CNAME ')) return chainLine([value.slice(6)]);
    const ip = normalizeIP(value);
    if (ip) {
      const cls = classifyIp(ip, chain);
      return h('span', { class: 'glb-ipval' }, ipLink(ip),
        cls.provider && cls.kind !== 'direct' ? h('span', { class: ['glb-prov', `glb-prov-${cls.kind}`], title: t(cls.reasonKey, { provider: cls.provider.name }) }, cls.provider.name) : null,
        cls.kind === 'private' ? h('span', { class: 'glb-prov glb-prov-private' }, t('kind.private')) : null);
    }
    // NS / CNAME / PTR targets ('ns1.example.com.') and MX ('10 mx.example.com.') become lookup links.
    const fqdn = /^([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)\.$/i.exec(value);
    if (fqdn) return hostLink(fqdn[1].toLowerCase());
    const mx = /^(\d+) ([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)\.$/i.exec(value);
    if (mx) return h('span', { class: 'glb-mx' }, h('span', { class: 'muted num' }, mx[1]), ' ', hostLink(mx[2].toLowerCase()));
    return h('span', { class: 'glb-text mono' }, value);
  }

  /** Answer cell: values, or a status badge for failures / markers. */
  function renderAnswer(row) {
    if (row.pending) {
      // A stopped run leaves unanswered rows: say so instead of spinning forever.
      if (current && current.cancelled) return h('span', { class: 'dt-null', title: t('glb.cancelled') }, '—');
      return h('span', { class: 'glb-pending' }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), t('glb.pending'));
    }
    const v = row.values;
    if (isBrowserBlocked(row)) {
      // Not an error: the browser cannot read this resolver (HTTP/3 without CORS). Say so calmly
      // and give a way to get its answer anyway.
      const res = row.response || {};
      const cmd = current ? terminalCommand(row.resolver.id, current.name, current.type) : null;
      return h('div', { class: 'glb-skip', title: [t('glb.value.unavailableTitle', { name: row.resolver.name }), res.error].filter(Boolean).join('\n') },
        h('span', { class: 'cluster' },
          Badge(t('glb.value.unavailable'), { variant: 'neutral', icon: 'minus-circle' }),
          h('span', { class: 'muted text-xs' }, t('glb.value.unavailableShort'))),
        cmd ? h('span', { class: 'glb-skip-cmd text-xs' },
          Icon('terminal', { size: 12 }), h('span', { class: 'muted' }, t('glb.value.terminal')), h('code', { class: 'mono' }, cmd)) : null);
    }
    if (isErrorValues(v)) {
      const res = row.response || {};
      const kind = res.errorKind && res.errorKind !== 'unknown' && hasString(`error.kind.${res.errorKind}`, 'en') ? t(`error.kind.${res.errorKind}`) : '';
      const unreliable = row.resolver && row.resolver.browserReliable === false;
      const tip = [res.error, unreliable ? t('settings.unreliable') : null].filter(Boolean).join('\n') || null;
      return h('div', { class: 'glb-fail', title: tip },
        h('span', { class: 'cluster' },
          Badge(t('glb.value.failed'), { variant: 'error', icon: 'x-circle' }),
          unreliable ? Badge('HTTP/3', { variant: 'warn', icon: 'alert', title: t('settings.unreliable') }) : null),
        kind ? h('span', { class: 'muted text-xs glb-fail-text' }, kind) : null);
    }
    const parts = [];
    if (row.filtered) parts.push(Badge(t('glb.value.blocked'), { variant: 'warn', icon: 'filter', title: t('glb.value.blockedTitle') }));
    if (v.length === 1 && v[0] === 'NXDOMAIN') parts.push(Badge('NXDOMAIN', { variant: 'nxdomain', icon: 'x-circle', title: t('class.nxdomain') }));
    else if (v.length === 1 && v[0] === 'NODATA') parts.push(Badge(t('glb.value.nodata'), { variant: 'unresolved', title: t('glb.value.nodataTitle') }));
    else if (v.length === 1 && /^[A-Z]+\d*$/.test(v[0]) && !normalizeIP(v[0])) parts.push(Badge(v[0], { variant: 'error', icon: 'alert' }));
    else {
      const { plain, chain } = splitChain(v);
      if (plain.length) parts.push(TruncatedList(plain, { max: 3, render: (value) => renderValue(value, chain), mono: false }));
      if (chain.length) parts.push(chainLine(chain));
    }
    return h('div', { class: 'glb-answer' }, parts);
  }

  function renderStatus(row) {
    if (row.pending) return null;
    const res = row.response;
    if (!res || !res.ok) return null; // the answer cell explains the failure
    const rc = res.rcode;
    const variant = rc === 'NOERROR' ? 'ok' : rc === 'NXDOMAIN' ? 'nxdomain' : 'error';
    return Badge(rc, { variant, mono: true, title: (res.ede || []).map((e) => `EDE ${e.code} ${e.name}${e.text ? `: ${e.text}` : ''}`).join('\n') || null });
  }

  function renderAd(row) {
    if (row.pending || !row.response || !row.response.ok) return null;
    return row.response.ad
      ? Badge(t('glb.adYes'), { variant: 'ok', icon: 'shield', title: t('glb.adTitle') })
      : h('span', { class: 'dt-null', title: t('glb.adNo') }, '—');
  }

  function renderLatency(row) {
    if (row.pending || !row.response || isBrowserBlocked(row)) return null;
    const v = row.response.ok ? row.response.elapsedMs : row.response.totalMs;
    if (!Number.isFinite(v)) return null;
    const speed = v < 120 ? 'fast' : v < 400 ? 'ok' : v < 1500 ? 'slow' : 'very-slow';
    return h('span', { class: ['glb-ms', `glb-ms-${speed}`, 'num'] }, ms(v));
  }

  function renderTtl(row) {
    if (row.pending) return null;
    const ttl = minAnswerTtl(row.response);
    return ttl === null ? null : h('span', { class: 'num', title: t('glb.ttlTitle', { human: humanTtl(ttl) }) }, formatNumber(ttl));
  }

  // Export options are read at export time, so the subject (queried name) is filled in per run.
  const exportOpts = {
    resolvers: { filename: 'global-dns-resolvers', subject: '' },
    geo: { filename: 'global-dns-locations', subject: '' },
    ips: { filename: 'global-dns-ips', subject: '' }
  };
  const latencyValue = (row) => (row.pending || !row.response ? null : (row.response.ok ? row.response.elapsedMs : row.response.totalMs));
  const groupSort = (row) => {
    if (isBrowserBlocked(row)) return '3';
    const g = rowGroup(row);
    if (!g) return null;
    return g.letter ? `0${g.letter.padStart(3, ' ')}` : g.filtered ? '1' : '2';
  };
  const answerText = (row) => (row.pending ? '' : isBrowserBlocked(row) ? 'UNAVAILABLE' : row.values.join(' '));
  const rowClass = (row) => ['glb-row', groupClass(rowGroup(row)), { 'is-pending': row.pending, 'is-unavailable': isBrowserBlocked(row) }];

  /* --- resolvers table ------------------------------------------------------ */
  const resolverTable = DataTable({
    caption: t('glb.res.title'),
    rowKey: (r) => r.key,
    rowClass,
    dense: true,
    maxHeight: null,
    export: exportOpts.resolvers,
    columns: [
      {
        key: 'group', label: t('glb.col.group'), sortable: true, sortValue: groupSort, width: '4rem',
        render: (r) => (isBrowserBlocked(r) ? unavailableMark() : groupMark(rowGroup(r))),
        exportValue: (r) => rowGroup(r)?.letter || (r.pending ? '' : isBrowserBlocked(r) ? 'UNAVAILABLE' : rowGroup(r)?.error ? 'ERROR' : 'BLOCKED')
      },
      {
        key: 'resolver', label: t('glb.col.resolver'), sortable: true, sortValue: (r) => r.resolver.name,
        exportValue: (r) => r.resolver.name,
        render: (r) => h('div', { class: 'glb-res' },
          h('span', { class: 'glb-res-name' }, r.resolver.name),
          h('span', { class: 'muted text-xs' }, r.resolver.operator))
      },
      {
        key: 'location', label: t('glb.col.location'), sortable: true,
        sortValue: (r) => r.resolver.countryCode || '',
        exportValue: (r) => [r.resolver.countryCode ? formatRegion(r.resolver.countryCode, r.resolver.location) : t('glb.anycast'), r.response?.nsid || ''].filter(Boolean).join(' '),
        render: (r) => h('div', { class: 'glb-loc' },
          h('span', null, flag(r.resolver.countryCode), ' ', r.resolver.countryCode ? formatRegion(r.resolver.countryCode, r.resolver.location) : t('glb.anycast')),
          r.response && r.response.nsid ? h('span', { class: 'glb-pop mono text-xs', title: `${t('glb.popTitle')}: ${r.response.nsid}` }, t('glb.pop', { id: r.response.nsid })) : null)
      },
      {
        key: 'filtering', label: t('glb.col.filtering'), sortable: true, sortValue: (r) => r.resolver.filtering || '',
        exportValue: (r) => r.resolver.filtering || '',
        render: (r) => (r.resolver.filtering ? Badge(t(`settings.filter.${r.resolver.filtering}`), { icon: 'filter' }) : null)
      },
      { key: 'ttl', label: t('glb.col.ttl'), sortable: true, align: 'end', sortValue: (r) => (r.pending ? null : minAnswerTtl(r.response)), render: renderTtl },
      { key: 'status', label: t('glb.col.status'), sortable: true, sortValue: (r) => (r.pending ? null : r.response?.rcode || 'ERROR'), render: renderStatus, exportValue: (r) => (r.pending ? '' : r.response?.rcode || (isBrowserBlocked(r) ? 'UNAVAILABLE' : 'ERROR')) },
      { key: 'ad', label: t('glb.col.dnssec'), sortable: true, sortValue: (r) => (r.pending || !r.response?.ok ? null : r.response.ad), render: renderAd, exportValue: (r) => (r.response?.ad ? 'AD' : '') },
      { key: 'latency', label: t('glb.col.latency'), sortable: true, align: 'end', sortValue: latencyValue, render: renderLatency, exportValue: latencyValue },
      { key: 'answer', label: t('glb.col.answer'), render: renderAnswer, searchValue: answerText, exportValue: answerText }
    ]
  });

  /* --- geo table --------------------------------------------------------------- */
  const geoTable = DataTable({
    caption: t('glb.geo.title'),
    rowKey: (r) => r.key,
    rowClass,
    dense: true,
    maxHeight: null,
    export: exportOpts.geo,
    columns: [
      {
        key: 'group', label: t('glb.col.group'), sortable: true, sortValue: groupSort, width: '4rem',
        render: (r) => groupMark(rowGroup(r)), exportValue: (r) => rowGroup(r)?.letter || ''
      },
      {
        key: 'location', label: t('glb.col.location'), sortable: true,
        sortValue: (r) => `${r.vantage.countryCode} ${r.vantage.city || ''}`,
        exportValue: (r) => vantageName(r.vantage),
        render: (r) => h('span', { class: 'glb-loc-geo' }, flag(r.vantage.countryCode, formatRegion(r.vantage.countryCode)), ' ', vantageName(r.vantage))
      },
      {
        key: 'isp', label: t('glb.col.isp'), sortable: true, sortValue: (r) => r.vantage.isp,
        exportValue: (r) => `${r.vantage.isp} AS${r.vantage.asn}`,
        render: (r) => h('div', { class: 'glb-isp' }, h('span', null, r.vantage.isp), h('span', { class: 'muted text-xs mono' }, `AS${r.vantage.asn}`))
      },
      { key: 'subnet', label: t('glb.col.subnet'), mono: true, sortable: true, sortValue: (r) => ipSortValue(r.vantage.subnet.split('/')[0]), render: (r) => r.vantage.subnet, exportValue: (r) => r.vantage.subnet },
      {
        key: 'scope', label: t('glb.col.scope'), sortable: true, align: 'end',
        title: t('glb.scopeTitle'),
        sortValue: (r) => (r.pending ? null : r.scopePrefix),
        exportValue: (r) => (Number.isFinite(r.scopePrefix) ? `/${r.scopePrefix}` : ''),
        render: (r) => (r.pending ? null : Number.isFinite(r.scopePrefix)
          ? h('span', { class: ['mono', { muted: r.scopePrefix === 0 }], title: t('glb.scopeTitle') }, `/${r.scopePrefix}`)
          : h('span', { class: 'dt-null', title: t('glb.scopeNone') }, '—'))
      },
      { key: 'latency', label: t('glb.col.latency'), sortable: true, align: 'end', sortValue: latencyValue, render: renderLatency, exportValue: latencyValue },
      {
        key: 'operator', label: t('glb.col.operator'),
        exportValue: (r) => operatorsOf(r).map((c) => c.provider?.name || c.kind).join(' '),
        render: (r) => {
          const kinds = operatorsOf(r);
          return kinds.length ? h('div', { class: 'cluster glb-ops' }, kinds.map((c) => KindBadge(c))) : null;
        }
      },
      { key: 'answer', label: t('glb.col.answer'), render: renderAnswer, searchValue: answerText, exportValue: answerText }
    ]
  });

  /** Operators of a row's answer IPs (Cloudflare, CDN · X, Direct …): those of its verdict group. */
  function operatorsOf(row) {
    if (row.pending || row.filtered || !Array.isArray(row.values)) return [];
    const g = verdictByKey.get(row.values.join('\n'));
    return g ? g.operators : [];
  }

  /* --- IP table ----------------------------------------------------------------- */
  const ipIntelBtn = Button({
    label: t('glb.ips.intel'), icon: 'network', size: 'sm', dataset: { action: 'ip-intel' },
    onClick: () => {
      const ips = ipTable.getVisibleRows().map((r) => r.ip).slice(0, 100);
      if (ips.length) ctx.navigate('ip', { ips: ips.join(',') });
    }
  });
  const ipCopyBtn = CopyButton(() => ipTable.getVisibleRows().map((r) => r.ip).join('\n'), { label: t('glb.ips.copy'), size: 'sm', variant: 'secondary' });
  const ipTable = DataTable({
    caption: t('glb.ips.title'),
    rowKey: (r) => r.ip,
    dense: true,
    maxHeight: null,
    pageSize: 15,
    search: true,
    sort: { key: 'seen', dir: 'desc' },
    toolbar: [ipIntelBtn, ipCopyBtn],
    empty: t('glb.ips.none'),
    export: exportOpts.ips,
    columns: [
      { key: 'ip', label: t('glb.ips.col.ip'), sortable: true, sortValue: (r) => ipSortValue(r.ip), searchValue: (r) => r.ip, exportValue: (r) => r.ip, render: (r) => ipLink(r.ip) },
      { key: 'version', label: 'IPv', sortable: true, align: 'center', render: (r) => h('span', { class: 'muted text-xs' }, `v${r.version}`), exportValue: (r) => r.version },
      {
        key: 'owner', label: t('glb.ips.col.owner'), sortable: true,
        sortValue: (r) => r.classification.kind,
        searchValue: (r) => `${r.classification.kind} ${r.classification.provider ? r.classification.provider.name : ''}`,
        exportValue: (r) => (r.classification.provider ? r.classification.provider.name : t(`kind.${r.classification.kind}`)),
        render: (r) => KindBadge(r.classification)
      },
      {
        key: 'seen', label: t('glb.ips.col.seen'), sortable: true, defaultDir: 'desc', sortValue: (r) => r.members.size,
        exportValue: (r) => r.members.size,
        render: (r) => {
          const total = Math.max(1, answeredCount());
          const pct = Math.min(100, Math.round((r.members.size / total) * 100));
          return h('div', { class: 'glb-seen' },
            h('span', { class: 'num' }, t('glb.ips.seen', { count: formatNumber(r.members.size), total: formatNumber(total) })),
            h('span', { class: 'glb-bar', attrs: { 'aria-hidden': 'true' } }, h('span', { class: 'glb-bar-fill', style: { width: `${pct}%` } })));
        }
      },
      {
        key: 'where', label: t('glb.ips.col.where'),
        searchValue: (r) => whereOf(r).countries.join(' '),
        exportValue: (r) => [...whereOf(r).vantages.map((v) => v.id), ...whereOf(r).resolvers].join(' '),
        render: (r) => {
          const w = whereOf(r);
          // One flag per country; its tooltip lists the locations (several vantages share a country).
          const byCountry = new Map();
          for (const v of w.vantages) byCountry.set(v.countryCode, [...(byCountry.get(v.countryCode) || []), vantageName(v)]);
          const countries = [...byCountry.entries()];
          return h('div', { class: 'glb-where' },
            countries.length ? h('span', { class: 'glb-flags' }, countries.slice(0, 16).map(([cc, names]) => flag(cc, names.join(' · '))),
              countries.length > 16 ? h('span', { class: 'muted text-xs' }, ` +${countries.length - 16}`) : null) : null,
            w.resolvers.length ? h('span', { class: 'muted text-xs' }, t('glb.ips.resolvers', { count: w.resolvers.length })) : null);
        }
      },
      {
        key: 'server', label: t('glb.ips.col.server'), sortable: true,
        sortValue: (r) => (r.servers.length ? r.servers[0].name : null),
        searchValue: (r) => r.servers.map((s) => s.name).join(' '),
        exportValue: (r) => r.servers.map((s) => s.name).join(' '),
        render: (r) => (r.servers.length ? h('div', { class: 'cluster' }, r.servers.map((s) => Badge(s.name, { variant: 'direct', icon: 'server' }))) : null)
      }
    ]
  });

  const vantageById = new Map(GEO_VANTAGES.map((v) => [v.id, v]));
  function whereOf(ipRow) {
    const vantages = [];
    const resolvers = [];
    for (const key of ipRow.members) {
      if (key.startsWith('geo:')) {
        const v = vantageById.get(key.slice(4));
        if (v) vantages.push(v);
      } else {
        resolvers.push(key.slice(9));
      }
    }
    return { vantages, resolvers, countries: [...new Set(vantages.map((v) => v.countryCode))] };
  }

  /* --- sections ----------------------------------------------------------- */
  const statsGrid = h('div', { class: 'stat-grid glb-stats' }, stats.answered, stats.groups, stats.ips, stats.latency);
  const legendCard = Card({
    title: t('glb.groups.title'), subtitle: t('glb.groups.desc'), icon: 'layers', className: 'glb-legend-card',
    children: h('div', { class: 'stack-sm' }, legendEl, filterNote)
  });
  const ipSection = Section({ title: t('glb.ips.title'), description: t('glb.ips.desc'), className: 'glb-ips', children: ipTable });
  const resSection = Section({
    title: t('glb.res.title'),
    description: t('glb.res.desc', { count: formatNumber(RESOLVERS.length) }),
    className: 'glb-resolvers',
    children: resolverTable
  });
  const geoSection = Section({
    title: t('glb.geo.title'),
    description: t('glb.geo.desc', { count: formatNumber(GEO_VANTAGES.length) }),
    className: 'glb-geo',
    children: geoTable
  });
  const emptyEl = EmptyState({
    icon: 'globe',
    title: t('glb.emptyTitle'),
    message: t('glb.emptyBody', { count: formatNumber(GEO_VANTAGES.length) })
  });
  const results = h('div', { class: 'stack-lg glb-results', hidden: true },
    h('div', { class: 'stack' }, progress, summaryEl, statsGrid, linksEl),
    legendCard, ipSection, resSection, geoSection);

  container.append(h('div', { class: 'stack-lg glb-view' }, formCard, h('div', { class: 'glb-empty card' }, emptyEl), results));
  const emptyWrap = container.querySelector('.glb-empty');

  /* --- run state ----------------------------------------------------------------- */
  /** @type {null|{ name: string, type: string, geo: boolean, rows: object[], rowByKey: Map, ips: Map,
   *   controller: AbortController|null, done: boolean, cancelled: boolean, total: number }} */
  let current = null;
  let renderTimer = null;

  function answeredCount() {
    return current ? current.rows.filter((r) => !r.pending && !isErrorValues(r.values)).length : 0;
  }

  function makeRows(geo) {
    const res = RESOLVERS.map((r) => ({ kind: 'resolver', key: `resolver:${r.id}`, resolver: r, vantage: null, pending: true, values: null, response: null, filtered: false, addresses: [], scopePrefix: null }));
    const g = geo ? GEO_VANTAGES.map((v) => ({ kind: 'geo', key: `geo:${v.id}`, resolver: null, vantage: v, pending: true, values: null, response: null, filtered: false, addresses: [], scopePrefix: null })) : [];
    return [...res, ...g];
  }

  function applyItem(item) {
    if (!current) return;
    const row = current.rowByKey.get(item.key);
    if (!row) return;
    row.pending = false;
    row.response = item.response;
    row.values = item.values;
    row.filtered = !!item.filtered;
    row.addresses = Array.isArray(item.addresses) ? item.addresses : [];
    row.scopePrefix = Number.isFinite(item.scopePrefix) ? item.scopePrefix : null;
    if (!row.filtered) {
      const index = ctx.getInventoryIndex();
      const { chain } = splitChain(row.values);
      for (const ip of row.addresses) {
        let entry = current.ips.get(ip);
        const classification = classifyIp(ip, chain);
        if (entry && entry.classification.kind === 'direct' && classification.kind !== 'direct') {
          entry.classification = classification; // a later answer revealed the CDN via its CNAME chain
        }
        if (!entry) {
          entry = {
            ip,
            version: ipVersion(ip),
            classification,
            private: isPrivateIP(ip),
            members: new Set(),
            servers: lookupServers([ip], index).map((m) => m.server)
          };
          current.ips.set(ip, entry);
          ipTable.addRows([entry]);
        }
        entry.members.add(row.key);
      }
    }
    scheduleRender();
  }

  function scheduleRender() {
    if (renderTimer) return;
    renderTimer = setTimeout(() => {
      renderTimer = null;
      renderAll();
    }, 120);
  }

  /** Recompute groups and refresh every derived piece of UI (cheap: ≤ 43 rows). */
  function renderAll() {
    if (!current) return;
    const readable = current.rows.filter((r) => !isBrowserBlocked(r));
    groups = groupAnswers(readable);
    groupByKey = new Map(groups.map((g) => [g.key, g]));
    verdict = propagationVerdict(readable, { type: current.type });
    verdictByKey = new Map(verdict.groups.map((g) => [g.key, g]));
    if (filterKey && !groupByKey.has(filterKey)) setFilter(null);
    resolverTable.refresh();
    geoTable.refresh();
    ipTable.refresh();
    renderLegend();
    renderStats();
    renderSummary();
    const done = current.rows.filter((r) => !r.pending).length;
    if (!current.done) progress.set(done, current.rows.length);
  }

  function renderLegend() {
    clear(legendEl);
    if (!groups.length) {
      legendEl.append(h('span', { class: 'muted text-sm' }, t('glb.sum.running')));
      return;
    }
    for (const g of groups) {
      const ops = g.filtered ? [] : verdictByKey.get(g.key)?.operators || [];
      const { plain, chain } = splitChain(g.values);
      const values = g.error ? [t('glb.value.failed')] : (plain.length ? plain : chain.map((c) => `→ ${c}`));
      const shown = values.slice(0, 3).join(', ') + (values.length > 3 ? ` +${values.length - 3}` : '') + (plain.length && chain.length ? ' ↪' : '');
      legendEl.append(h('button', {
        type: 'button',
        class: ['glb-chip', groupClass(g), { 'is-active': filterKey === g.key }],
        title: g.values.join('\n'),
        dataset: { group: g.letter || (g.error ? 'error' : 'blocked') },
        attrs: { 'aria-pressed': String(filterKey === g.key) },
        on: { click: () => setFilter(filterKey === g.key ? null : g.key) }
      },
      groupMark(g, { withLabel: !g.letter }),
      g.error ? null : h('span', { class: 'glb-chip-values mono' }, g.values.length === 1 && g.values[0] === 'NODATA' ? t('glb.value.nodata') : shown),
      ops.length ? operatorLabels(ops) : null,
      h('span', { class: 'glb-chip-count' }, t('glb.group.members', { count: g.members.length }))));
    }
  }

  function setFilter(key) {
    filterKey = key;
    const g = key ? groupByKey.get(key) : null;
    const fn = g ? (row) => !row.pending && !isBrowserBlocked(row) && row.values.join('\n') === key : null;
    resolverTable.setFilter(fn);
    geoTable.setFilter(fn);
    ipTable.setFilter(g ? (ipRow) => [...ipRow.members].some((k) => g.members.includes(k)) : null);
    clear(filterNote);
    filterNote.hidden = !g;
    if (g) {
      filterNote.append(
        Icon('filter', { size: 14 }),
        h('span', null, g.letter ? t('glb.group.filterOn', { letter: g.letter }) : t(g.error ? 'glb.group.error' : 'glb.group.blocked')),
        Button({ label: t('glb.group.showAll'), size: 'sm', variant: 'ghost', onClick: () => setFilter(null) }));
    }
    legendEl.querySelectorAll('.glb-chip').forEach((b) => {
      const on = b.title === (g ? g.values.join('\n') : null) && !!g;
      b.setAttribute('aria-pressed', String(on));
      b.classList.toggle('is-active', on);
    });
  }

  function renderStats() {
    const rows = current.rows;
    const finished = rows.filter((r) => !r.pending);
    const unavailable = finished.filter(isBrowserBlocked).length;
    const failed = finished.filter((r) => isErrorValues(r.values)).length - unavailable;
    stats.answered.set({
      value: `${formatNumber(finished.length - failed - unavailable)} / ${formatNumber(rows.length)}`,
      hint: [
        failed ? t('glb.stat.failed', { count: failed }) : null,
        unavailable ? t('glb.stat.unavailable', { count: unavailable }) : null
      ].filter(Boolean).join(' · ') || null,
      variant: failed && failed + unavailable === finished.length && current.done ? 'error' : 'accent'
    });
    const answerGroups = groups.filter((g) => g.letter).length;
    // Several answers are a warning only when they are not explained (by design, GeoDNS, or a
    // filtering resolver's own answer next to answers that agree).
    const explained = verdict && ['agree', 'by-design', 'geo'].includes(verdict.state);
    stats.groups.set({ value: answerGroups, variant: answerGroups > 1 ? (explained ? 'info' : 'warn') : answerGroups === 1 ? 'ok' : 'default' });
    const ipRows = [...current.ips.values()];
    const mine = ipRows.filter((r) => r.servers.length).length;
    const kinds = new Map();
    for (const r of ipRows) {
      const label = r.classification.kind === 'cloudflare' ? 'Cloudflare' : r.classification.provider ? r.classification.provider.name : t(`kind.${r.classification.kind}`);
      kinds.set(label, (kinds.get(label) || 0) + 1);
    }
    const hint = [...kinds.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, n]) => `${formatNumber(n)} ${k}`).join(' · ');
    stats.ips.set({ value: ipRows.length, hint: mine ? `${hint} · ${t('glb.stat.inventory', { count: mine })}` : (hint || null) });
    const lat = median(rows.filter((r) => r.kind === 'resolver' && !r.pending && r.response && r.response.ok).map((r) => r.response.elapsedMs));
    stats.latency.set({ value: lat === null ? '—' : ms(lat) });
  }

  function renderSummary() {
    clear(summaryEl);
    const rows = current.rows;
    const finished = rows.filter((r) => !r.pending);
    if (!current.done && !current.cancelled) {
      if (!finished.length) return;
    }
    const unavailable = finished.filter(isBrowserBlocked);
    const failed = finished.filter((r) => isErrorValues(r.values)).length - unavailable.length;
    const blocked = finished.filter((r) => r.filtered).length;
    const usable = finished.filter((r) => !r.filtered && !isErrorValues(r.values));
    const distinct = (list) => new Set(list.map((r) => r.values.join('\n'))).size;
    const extra = [
      failed ? t('glb.sum.errors', { count: failed }) : null,
      blocked ? t('glb.sum.blocked', { count: blocked }) : null,
      verdict.rewritten.length ? t('glb.sum.rewritten', { names: sourceNames(verdict.rewritten) }) : null,
      unavailable.length ? t('glb.sum.unavailable', { names: unavailable.map((r) => r.resolver.name).join(', ') }) : null,
      current.cancelled ? t('glb.cancelled') : null
    ].filter(Boolean).join(' ');
    const state = !current.done && !current.cancelled ? 'running'
      : !usable.length ? (current.cancelled ? 'stopped' : 'failed')
        : verdict.state;
    const operators = shortList(verdict.operators.map((op) => op.name));
    let alert;
    if (state === 'running') {
      alert = Alert({ variant: 'info', icon: 'activity', compact: true, title: t('glb.sum.running'), message: null });
    } else if (state === 'stopped') {
      alert = Alert({ variant: 'info', icon: 'stop', compact: true, title: t('glb.sum.stoppedTitle'), message: extra || null });
    } else if (state === 'failed') {
      alert = failed
        ? Alert({ variant: 'error', title: t('glb.sum.failedTitle'), message: [t('glb.sum.failedBody'), extra].filter(Boolean).join(' ') })
        : Alert({ variant: 'warn', title: t('glb.sum.differTitle'), message: extra || null });
    } else if (state === 'agree') {
      const agreeing = usable.length - verdict.rewritten.length;
      alert = Alert({ variant: 'ok', title: t('glb.sum.agreeTitle'), message: [t('glb.sum.agreeBody', { count: agreeing }), extra].filter(Boolean).join(' ') });
    } else if (state === 'by-design') {
      alert = Alert({
        variant: 'info',
        icon: 'globe',
        title: t('glb.sum.designTitle', { operators }),
        message: [t('glb.sum.designBody'), verdict.multiOperator ? t('glb.sum.designMulti') : null, extra].filter(Boolean).join(' ')
      });
    } else if (state === 'geo') {
      const geoGroups = distinct(usable.filter((r) => r.kind === 'geo'));
      alert = Alert({ variant: 'info', icon: 'map-pin', title: t('glb.sum.geoTitle'), message: [t('glb.sum.geoBody', { groups: formatNumber(geoGroups) }), extra].filter(Boolean).join(' ') });
    } else {
      alert = Alert({
        variant: 'warn',
        title: t('glb.sum.differTitle'),
        message: [
          t('glb.sum.differBody', { groups: formatNumber(verdict.groups.filter((g) => !g.rewritten).length) }),
          verdict.designPart ? t('glb.sum.designPart', { operators }) : null
        ].filter(Boolean).join(' '),
        children: [
          verdict.findings.length ? h('ul', { class: 'glb-findings' }, verdict.findings.map(renderFinding)) : null,
          extra ? h('div', { class: 'alert-message' }, extra) : null
        ]
      });
    }
    alert.dataset.state = state;
    summaryEl.append(alert);
  }

  /** "a, b, c +2 more" — the first `max` entries of a list. */
  function shortList(list, max = 3) {
    return list.length > max ? `${list.slice(0, max).join(', ')} ${t('glb.find.more', { count: list.length - max })}` : list.join(', ');
  }

  /** Display names of answer sources (resolver names, location names), de-duplicated. */
  function sourceNames(keys) {
    const names = keys.map((key) => {
      const row = current.rowByKey.get(key);
      if (!row) return key;
      return row.kind === 'geo' ? vantageName(row.vantage) : row.resolver.name;
    });
    return shortList([...new Set(names)]);
  }

  /** One verdict finding: the groups it is about (letter marks) and what it most likely means. */
  function renderFinding(f) {
    const letters = f.groups.map((key) => groupByKey.get(key)?.letter).filter(Boolean);
    let text;
    switch (f.code) {
      case 'rcode': text = t('glb.find.rcode', { sources: sourceNames(f.members), rcode: f.rcode }); break;
      case 'nxdomain': text = t('glb.find.nxdomain', { sources: sourceNames(f.members) }); break;
      case 'nodata': text = t('glb.find.nodata', { sources: sourceNames(f.members), type: current.type }); break;
      case 'private': text = t('glb.find.private', { sources: sourceNames(f.members), ips: shortList(f.ips) }); break;
      case 'mixed':
        text = t('glb.find.mixed', {
          count: letters.length, groups: letters.join(', '), ips: shortList(f.ips), operators: shortList(verdict.operators.map((op) => op.name))
        });
        break;
      case 'cname':
        text = t('glb.find.cname', {
          owner: f.owner || current.name,
          targets: f.targets.map((x) => (x === null ? t('glb.find.addressRecords', { type: current.type }) : `CNAME ${x}`)).join(' · ')
        });
        break;
      default: text = t(`glb.find.${f.code}`);
    }
    // Marks in legend order; none when the finding is about every answer group ('direct',
    // 'records', a CNAME that differs everywhere), where they would only repeat the legend.
    const keys = groups.filter((g) => f.groups.includes(g.key)).map((g) => g.key);
    const everyGroup = f.code === 'direct' || f.code === 'records' || keys.length === groups.filter((g) => g.letter).length;
    const marks = everyGroup ? [] : keys.slice(0, 4).map((key) => groupMark(groupByKey.get(key)));
    if (!everyGroup && keys.length > 4) marks.push(h('span', { class: 'glb-finding-more' }, `+${keys.length - 4}`));
    return h('li', { class: 'glb-finding', dataset: { finding: f.code } },
      marks.length ? h('span', { class: 'glb-finding-marks' }, marks) : null,
      h('span', null, text));
  }

  function renderLinks(name, type) {
    clear(linksEl);
    linksEl.append(
      h('span', { class: 'muted' }, t('glb.links')),
      h('a', { href: ctx.href('lookup', { name, type }) }, Icon('search', { size: 14 }), ' ', t('nav.lookup')),
      h('a', { href: ctx.href('health', { domain: name }) }, Icon('activity', { size: 14 }), ' ', t('nav.health')));
  }

  function setRunning(on) {
    runBtn.hidden = on;
    stopBtn.hidden = !on;
    setButtonBusy(stopBtn, false);
    nameField.input.readOnly = on;
    typeField.input.disabled = on;
    geoField.input.disabled = on;
    ctx.setBusy(on ? t('glb.progress') : false);
  }

  function setHeaderActions() {
    if (!current) {
      ctx.setActions();
      return;
    }
    const params = { name: current.name, type: current.type, geo: current.geo ? null : '0' };
    ctx.setActions(
      CopyButton(() => ctx.shareUrl(params), { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }),
      Button({ label: t('common.rerun'), icon: 'refresh', size: 'sm', dataset: { action: 'rerun' }, onClick: () => start() }));
  }

  /** Validate the form and run a new check. */
  async function start() {
    const raw = nameField.value.trim();
    nameField.setError(null);
    if (normalizeIP(raw)) {
      nameField.setError(t('glb.ipGiven'));
      nameField.focus();
      return;
    }
    const name = normalizeHostname(raw, { allowSingleLabel: true });
    if (!name) {
      nameField.setError(t('glb.invalidName'));
      nameField.focus();
      return;
    }
    nameField.value = name;
    const type = GLOBAL_TYPES.includes(typeField.value) ? typeField.value : 'A';
    const geo = geoField.checked;
    ctx.setParams({ name, type, geo: geo ? null : '0' });
    await runCheck(name, type, geo);
  }

  function stop() {
    if (current && current.controller) {
      current.cancelled = true;
      current.controller.abort();
    }
  }

  function prepare(name, type, geo) {
    if (current && current.controller) current.controller.abort();
    if (renderTimer) {
      clearTimeout(renderTimer);
      renderTimer = null;
    }
    const rows = makeRows(geo);
    current = { name, type, geo, rows, rowByKey: new Map(rows.map((r) => [r.key, r])), ips: new Map(), controller: null, done: false, cancelled: false };
    filterKey = null;
    groups = [];
    groupByKey = new Map();
    resolverTable.setFilter(null);
    geoTable.setFilter(null);
    ipTable.setFilter(null);
    ipTable.setSearch('');
    resolverTable.setRows(rows.filter((r) => r.kind === 'resolver'));
    geoTable.setRows(rows.filter((r) => r.kind === 'geo'));
    ipTable.setRows([]);
    geoSection.hidden = !geo;
    for (const o of Object.values(exportOpts)) o.subject = name;
    emptyWrap.hidden = true;
    results.hidden = false;
    renderLinks(name, type);
    setHeaderActions();
  }

  async function runCheck(name, type, geo) {
    prepare(name, type, geo);
    const run = current;
    const controller = new AbortController();
    run.controller = controller;
    progress.el.hidden = false;
    progress.setVariant('default');
    progress.setLabel(t('glb.progress'));
    progress.set(0, run.rows.length);
    renderAll();
    setRunning(true);
    try {
      const shared = await ctx.getDns();
      // A one-shot comparison: ask every source once, with a short timeout, so an unreachable
      // resolver costs seconds instead of two full app timeouts (a resolver unreachable from the
      // user's network: ~16 s → 5 s). Healthy DoH answers arrive well under 1.5 s (browser-doh-matrix).
      const dns = { query: (qname, qtype, opts = {}) => shared.query(qname, qtype, { ...opts, timeoutMs: QUERY_TIMEOUT_MS, retries: 0 }) };
      await checkPropagation(name, type, {
        dns,
        vantages: geo ? GEO_VANTAGES : [],
        signal: mergeSignals(ctx.signal, controller.signal),
        onResult: (item) => {
          if (current === run) applyItem(item);
        }
      });
      if (current !== run) return;
      run.done = true;
    } catch (err) {
      if (current !== run) return;
      if (!(err && err.name === 'AbortError')) {
        run.cancelled = true;
        ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      }
      if (ctx.signal.aborted) return;
    } finally {
      if (current === run) {
        run.controller = null;
        if (!ctx.signal.aborted) setRunning(false);
      }
    }
    if (ctx.signal.aborted || current !== run) return;
    if (renderTimer) {
      clearTimeout(renderTimer);
      renderTimer = null;
    }
    if (run.done) progress.done(t('glb.progressDone'));
    else progress.setVariant('warn');
    renderAll();
    if (run.done) setTimeout(() => { if (current === run && run.done) progress.el.hidden = true; }, 900);
  }

  /** Re-render a finished run kept across a language re-mount (no network). */
  function restore(snap) {
    prepare(snap.name, snap.type, snap.geo);
    for (const item of snap.items) applyItem(item);
    current.done = !!snap.done;
    current.cancelled = !snap.done;
    if (renderTimer) {
      clearTimeout(renderTimer);
      renderTimer = null;
    }
    progress.el.hidden = true;
    renderAll();
  }

  /* --- initial state --------------------------------------------------------- */
  if (restored && Array.isArray(restored.items) && restored.items.length && restored.name) {
    restore(restored);
  } else if (!restored && initialName) {
    // Shared link: run immediately. A re-mounted draft (typed, never run) only refills the form.
    Promise.resolve().then(() => start());
  }

  active = {
    teardown() {
      if (renderTimer) clearTimeout(renderTimer);
      renderTimer = null;
      if (current && current.controller) current.controller.abort();
    },
    snapshot() {
      if (!current) return { name: nameField.value, type: typeField.value, geo: geoField.checked };
      const items = current.rows.filter((r) => !r.pending).map((r) => ({
        key: r.key, response: r.response, values: r.values, filtered: r.filtered, addresses: r.addresses, scopePrefix: r.scopePrefix
      }));
      return { name: current.name, type: current.type, geo: current.geo, items, done: current.done };
    },
    update(params) {
      const name = params.name || '';
      if (!name) return false;
      nameField.value = name;
      const type = String(params.type || 'A').toUpperCase();
      typeField.value = GLOBAL_TYPES.includes(type) ? type : 'A';
      geoField.checked = params.geo !== '0';
      start();
      return true;
    }
  };
}

/** Abort a running check and drop timers. */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * State carried over a language re-mount: the query and the answers received (no re-query).
 * @returns {object|null}
 */
export function snapshot() {
  return active ? active.snapshot() : null;
}

/**
 * Take new route params (e.g. a pasted share link) without a re-mount.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, snapshot, update };
