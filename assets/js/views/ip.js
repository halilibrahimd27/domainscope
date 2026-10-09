/**
 * views/ip.js — "IP Intel": paste IP addresses (and/or host names, which are resolved first)
 * and get, per address: reverse DNS (PTR), origin ASN and AS holder, announced prefix,
 * country / city, the CDN / platform that operates it (Cloudflare, Fastly …), whether it is
 * private, and which of the user's servers (inventory) owns it. A per-row "Find domains" opens
 * Domains on this IP (ui/reverse-ip-panel.js over lib/reverseip.js, loaded on first use): every
 * name tied to the address from passive DNS, reverse DNS and the workspace, checked in DNS now;
 * the row's cell keeps the count and the first names.
 *
 * Data: lib/ipintel.js (RIPEstat + ipwho.is fallback + DoH PTR). Private addresses never
 * leave the browser. Results stream into the table. A plain direct address on a well-known network
 * is named in the operator cell (lib/networklabel.js): from the weekly provider list's network tier
 * at once ("Cloudflare network · not necessarily proxied", "AWS network"), with its origin AS once
 * RIPEstat names the same operator, else from the AS alone.
 *
 * The page template (ui/template.js; docs/DESIGN.md §5, §8 phase 5), a batch tool: the input card
 * holds the box, Look up on its row, the example chips (they only fill the box), "My servers' IPs",
 * Clear and the privacy note, and turns compact from the first lookup. The result header
 * (`.ipi-results-bar`) says how many addresses (one by itself), when, the status summary (sources
 * failed, behind a CDN, networks, countries, your servers, private: lib/netresults.js ipStatus; a
 * press on the ones that filter lists their rows only), Copy summary with ¶, Export ▾ (CSV, JSON:
 * what the table lists) and Copy link, the next step "Domains on these addresses" and a chip per
 * service. The metric strip (zero counts folded into one sentence) and the table (a card per row on
 * a phone) are the body.
 *
 * "Copy summary": one line for Jira / Slack (lib/summary.js) with the time the lookup ended; it
 * says how many addresses are in the server list (never a server's name, the tooltip says so), how
 * many lookups failed (rows whose every source failed) and how many addresses a stopped lookup
 * never reached, and its link leaves out private and inventory addresses.
 *
 * No silent dashes (lib/sourcestatus.js, ui/source-status.js): a cell that a failed source left
 * empty says "⚠ n/a" with the source and the reason, a chip per service sums the failures up,
 * and Retry (per row, or per chip for every row it failed on) asks only those sources again.
 *
 * Shareable: `#/ip?ips=8.8.8.8,1.1.1.1` (also `ip=` / `q=`; host names allowed) runs on open;
 * with `run=0` (an address carried over from another tool, lib/session.js) it is only filled in.
 * The finished rows are kept for the page session (`result()` / `snapshot()`); coming back
 * matches them against the servers as they are then.
 */

import { h, clear, scrollBehavior } from '../ui/dom.js';
import {
  Alert, Badge, Button, DataTable, ErrorBanner, ExternalLink, Icon, KeyValueList, KindBadge, ProgressBar, RelativeTime,
  TruncatedList, announce, ipSortValue, setButtonBusy, textarea
} from '../ui/components.js';
import { registerStrings, formatNumber, formatRegion, formatRelative, localeTag } from '../i18n.js';
import { createIpIntel, networkHint } from '../lib/ipintel.js';
import { ipFieldStatus, ipRetrySources, ipSourceChips, sourceStatus, IP_FIELDS, EXPORT_NA } from '../lib/sourcestatus.js';
import { addressLines } from '../lib/density.js';
import { NaMark, RetryButton, SourceChip, setRetryBusy, statusText } from '../ui/source-status.js';
import { classifyResolution, ipVersion, isPrivateIP, loadRanges, normalizeIP, rangesInfo } from '../lib/netinfo.js';
import { networkLabel } from '../lib/networklabel.js';
import { normalizeHostname } from '../lib/domain.js';
import { lookupServers } from '../lib/inventory.js';
import { Flag } from '../ui/flag.js';
import { mergeSignals, onceAsync, splitList } from '../lib/util.js';
import { originIndex } from '../lib/originmap.js';
import { commonTarget, fillReplaces, isFillOnly } from '../lib/session.js';
import { permalinkParams } from '../ui/view-summaries.js';
import { SummaryButton } from '../ui/summary-button.js';
import {
  EmptyState, ExampleChips, MetricStrip, NextSteps, PrivacyNote, ResultActions, ResultHeader, ResultTitle, RunBar, StatusSummary, ToolInput
} from '../ui/template.js';
import { inputCompact, statusItems, templateState } from '../lib/template.js';
import { IP_FOLDABLE, exportColumns, ipFigures, ipMetricIds, ipRowMatches, ipStatus } from '../lib/netresults.js';
import { toCsv, toJson } from '../lib/export.js';
import { downloadText, timestampedName } from '../ui/download.js';

/** Route id (`#/ip`). */
export const id = 'ip';
/** i18n key of the page title. */
export const titleKey = 'nav.ip';
/** Icon name (ui/components.js Icon). */
export const icon = 'network';

/** Maximum addresses per run (RIPEstat fair use: ~2 requests per address). */
export const MAX_IPS = 250;
/** Maximum host names resolved per run. */
export const MAX_HOSTS = 100;

/** The example chips: two public resolvers, an IPv6 address, a host name (resolved first). */
const IP_EXAMPLES = Object.freeze([['8.8.8.8', '1.1.1.1'], ['2606:4700:4700::1111'], ['github.com']]);

/** A row's routing, RPKI, abuse contact and CIDR breadcrumb panel, loaded when a row's details first open. */
const loadEnrich = onceAsync(() => import('../ui/ip-enrich-panel.js'));

registerStrings('en', {
  'ipi.inputLabel': 'IP addresses or host names',
  'ipi.placeholder': '8.8.8.8\n1.1.1.1\n2606:4700::1111\nwww.example.com   ← host names are resolved first',
  'ipi.inputHint': 'One per line, or separated by spaces/commas. Ports and [brackets] are fine; # starts a comment.',
  'ipi.run': 'Look up',
  'ipi.stop': 'Stop',
  'ipi.fromInventory': 'My servers’ IPs',
  'ipi.fromInventoryTitle': 'Load every IP address from the saved server inventory',
  'ipi.clear': 'Clear',
  'ipi.parsedIps': { one: '{count} address', other: '{count} addresses' },
  'ipi.parsedHosts': { one: '{count} host name', other: '{count} host names' },
  'ipi.invalid': 'Ignored (not an IP address or host name): {items}',
  'ipi.cidr': 'Ranges such as {range} are not expanded — enter single addresses.',
  'ipi.nothing': 'Enter at least one IP address or host name.',
  'ipi.truncated': 'Only the first {max} addresses are looked up.',
  'ipi.hostsTruncated': 'Only the first {max} host names are resolved.',
  'ipi.resolving': 'Resolving host names',
  'ipi.looking': 'Looking up addresses',
  'ipi.done': 'Done',
  'ipi.stopped': 'Stopped — rows without data were not looked up.',
  'ipi.hostFailed': 'Could not resolve: {items}',
  'ipi.privacy': 'Addresses are sent to RIPEstat and ipwho.is (and reverse DNS to your DoH resolver). Private addresses are never sent anywhere.',
  'ipi.emptyLine': 'Up to {max} addresses or host names at once: who runs each address and where it is.',
  'ipi.check.ptr': 'Reverse DNS',
  'ipi.check.asn': 'Network owner (ASN)',
  'ipi.check.location': 'Location',
  'ipi.check.cdn': 'CDN or cloud',
  'ipi.check.server': 'Your servers',
  'ipi.check.reverse': 'Other domains on the address',
  'ipi.resultsTitle': { one: '{count} address', other: '{count} addresses' },
  'ipi.lookingCount': { one: 'Looking up {count} address…', other: 'Looking up {count} addresses…' },
  'ipi.resolvingTitle': 'Resolving the host names…',
  'ipi.checkedAt': 'Looked up {time}',
  'ipi.status.cdn': '{count} behind a CDN',
  'ipi.status.nets': { one: '{count} network', other: '{count} networks' },
  'ipi.status.countries': { one: '{count} country', other: '{count} countries' },
  'ipi.status.mine': '{count} in your server list',
  'ipi.status.priv': '{count} private',

  'ipi.stat.ips': 'Addresses',
  'ipi.stat.ipsHint': '{v4} IPv4 · {v6} IPv6',
  'ipi.stat.cdn': 'Behind a CDN / proxy',
  'ipi.stat.mine': 'Your servers',
  'ipi.stat.private': 'Private',
  'ipi.stat.networks': 'Networks (ASN)',
  'ipi.stat.countries': 'Countries',
  'ipi.zero': { one: 'This address is not {list}.', other: 'None of these addresses is {list}.' },
  'ipi.zero.cdn': 'behind a CDN / proxy',
  'ipi.zero.mine': 'one of your servers',
  'ipi.zero.priv': 'private',
  'ipi.retried': { one: 'Asked again for {count} address.', other: 'Asked again for {count} addresses.' },

  'ipi.col.ip': 'IP address',
  'ipi.col.ptr': 'Reverse DNS (PTR)',
  'ipi.col.holder': 'Network (ASN · owner)',
  'ipi.col.prefix': 'Prefix',
  'ipi.col.location': 'Location',
  'ipi.col.operator': 'Operator',
  'ipi.col.server': 'Your server',
  'ipi.col.reverse': 'Other domains on this IP',
  'ipi.fromHost': 'from {host}',
  'ipi.pending': 'Looking up…',
  'ipi.notAnnounced': 'not announced',
  'ipi.notAnnouncedTitle': 'No route is announced for this address on the Internet (unused or reserved space).',

  'ipi.rev.button': 'Find domains',
  'ipi.rev.count': { zero: 'No domains found', one: '{count} domain', other: '{count} domains' },
  'ipi.rev.failed': 'Failed',
  'ipi.rev.failedTitle': 'No source answered: the chips of Domains on this IP say why.',
  'ipi.rev.private': 'your workspace only',
  'ipi.rev.all': 'Domains on these addresses',
  'ipi.rev.loadFailed': 'Domains on this IP could not be loaded.',
  'ipi.quota': 'Find domains asks HackerTarget (about 50 lookups a day from your IP address, shared with the SSL Targets scan), ip.thc.org, AlienVault OTX, Robtex and Shodan InternetDB about the address. Use it only where you need it.',

  'ipi.det.rir': 'Registry (RIR)',
  'ipi.det.announced': 'Announced on the Internet',
  'ipi.det.asns': 'Origin AS',
  'ipi.det.sources': 'Data sources',
  'ipi.det.errors': 'Problems',
  'ipi.det.provider': 'Provider',
  'ipi.det.links': 'Open elsewhere',
  'ipi.det.hosts': 'Host names you entered',
  'ipi.det.network': 'Network',
  'ipi.det.blocklists': 'Blocklists',

  'ipi.net.badge': '{name} network',
  'ipi.net.short.outside-proxy-ranges': 'AS{asn} · not a proxied-site range',
  'ipi.net.short.cdn-edge': 'AS{asn} · probably a CDN edge',
  'ipi.net.short.hosted': 'AS{asn} · {category}',
  'ipi.net.long.outside-proxy-ranges': 'This address is on {name}’s own network (AS{asn}) but outside the ranges {name} publishes for the websites it proxies — so it is one of {name}’s own services (1.1.1.1, for example, is a DNS resolver), not a website hidden behind {name}.',
  'ipi.net.long.cdn-edge': 'Announced by {name} (AS{asn}), a CDN / security proxy that publishes no list of its edge addresses — most likely an edge server in front of a website whose own server is hidden.',
  'ipi.net.long.hosted': 'Announced by {name} (AS{asn}): a server or service on {name}’s network, reached directly with no CDN in front.',
  'ipi.net.short.ranges.outside-proxy-ranges': 'not necessarily proxied',
  'ipi.net.short.ranges.hosted': '{category} · published range',
  'ipi.net.long.ranges.outside-proxy-ranges': 'This address is in {name}’s network (the provider list of {updated}) but outside the ranges {name} proxies websites from, so it is not necessarily proxied: one of {name}’s own services (1.1.1.1, for example, is a DNS resolver), a customer’s own address block or a TCP / UDP proxy — not a website hidden behind {name}.',
  'ipi.net.long.ranges.hosted': 'This address is in the address space {name} publishes (the provider list of {updated}): a server or service on {name}’s network, reached directly with no CDN in front.',
  'ipi.net.asOrigin': 'Origin AS: AS{asn}.',
  'ipi.net.cat.cdn': 'CDN',
  'ipi.net.cat.waf': 'CDN / WAF',
  'ipi.net.cat.cloud': 'cloud',
  'ipi.net.cat.hosting': 'hosting',
  'ipi.net.cat.platform': 'platform'
});

registerStrings('tr', {
  'ipi.inputLabel': 'IP adresleri veya host adları',
  'ipi.placeholder': '8.8.8.8\n1.1.1.1\n2606:4700::1111\nwww.example.com   ← host adları önce çözümlenir',
  'ipi.inputHint': 'Her satıra bir tane ya da boşluk/virgülle ayırarak. Port ve [köşeli parantez] sorun değil; # yorum başlatır.',
  'ipi.run': 'Sorgula',
  'ipi.stop': 'Durdur',
  'ipi.fromInventory': 'Sunucularımın IP’leri',
  'ipi.fromInventoryTitle': 'Kayıtlı sunucu envanterindeki tüm IP adreslerini yükle',
  'ipi.clear': 'Temizle',
  'ipi.parsedIps': '{count} adres',
  'ipi.parsedHosts': '{count} host adı',
  'ipi.invalid': 'Yok sayıldı (IP adresi ya da host adı değil): {items}',
  'ipi.cidr': '{range} gibi aralıklar açılmaz — tek tek adres girin.',
  'ipi.nothing': 'En az bir IP adresi ya da host adı girin.',
  'ipi.truncated': 'Yalnızca ilk {max} adres sorgulanır.',
  'ipi.hostsTruncated': 'Yalnızca ilk {max} host adı çözümlenir.',
  'ipi.resolving': 'Host adları çözümleniyor',
  'ipi.looking': 'Adresler sorgulanıyor',
  'ipi.done': 'Tamamlandı',
  'ipi.stopped': 'Durduruldu — verisi olmayan satırlar sorgulanmadı.',
  'ipi.hostFailed': 'Çözümlenemedi: {items}',
  'ipi.privacy': 'Adresler RIPEstat ve ipwho.is’e (ters DNS ise DoH çözümleyicinize) gönderilir. Özel (private) adresler hiçbir yere gönderilmez.',
  'ipi.emptyLine': 'Tek seferde {max} adrese ya da host adına kadar: her adresi kimin işlettiği ve nerede olduğu.',
  'ipi.check.ptr': 'Ters DNS',
  'ipi.check.asn': 'Ağ sahibi (ASN)',
  'ipi.check.location': 'Konum',
  'ipi.check.cdn': 'CDN ya da bulut',
  'ipi.check.server': 'Sunucularınız',
  'ipi.check.reverse': 'Adresteki diğer alan adları',
  'ipi.resultsTitle': '{count} adres',
  'ipi.lookingCount': '{count} adres sorgulanıyor…',
  'ipi.resolvingTitle': 'Host adları çözümleniyor…',
  'ipi.checkedAt': '{time} sorgulandı',
  'ipi.status.cdn': '{count} tanesi CDN arkasında',
  'ipi.status.nets': '{count} ağ',
  'ipi.status.countries': '{count} ülke',
  'ipi.status.mine': '{count} tanesi sunucu listenizde',
  'ipi.status.priv': '{count} tanesi özel',

  'ipi.stat.ips': 'Adres',
  'ipi.stat.ipsHint': '{v4} IPv4 · {v6} IPv6',
  'ipi.stat.cdn': 'CDN / proxy',
  'ipi.stat.mine': 'Sizin sunucularınız',
  'ipi.stat.private': 'Özel',
  'ipi.stat.networks': 'Ağ (ASN)',
  'ipi.stat.countries': 'Ülke',
  'ipi.zero': { one: 'Bu adres {list} değil.', other: 'Bu adreslerin hiçbiri {list} değil.' },
  'ipi.zero.cdn': 'CDN / proxy arkasında',
  'ipi.zero.mine': 'sunucularınızdan biri',
  'ipi.zero.priv': 'özel (private)',
  'ipi.retried': '{count} adres yeniden soruldu.',

  'ipi.col.ip': 'IP adresi',
  'ipi.col.ptr': 'Ters DNS (PTR)',
  'ipi.col.holder': 'Ağ (ASN · sahibi)',
  'ipi.col.prefix': 'Önek (prefix)',
  'ipi.col.location': 'Konum',
  'ipi.col.operator': 'İşleten',
  'ipi.col.server': 'Sunucunuz',
  'ipi.col.reverse': 'Bu IP’deki diğer alan adları',
  'ipi.fromHost': '{host} adından',
  'ipi.pending': 'Sorgulanıyor…',
  'ipi.notAnnounced': 'duyurulmuyor',
  'ipi.notAnnouncedTitle': 'Bu adres için İnternet’te duyurulan bir rota yok (kullanılmayan ya da ayrılmış alan).',

  'ipi.rev.button': 'Alan adlarını bul',
  'ipi.rev.count': { zero: 'Alan adı bulunamadı', other: '{count} alan adı' },
  'ipi.rev.failed': 'Başarısız',
  'ipi.rev.failedTitle': 'Hiçbir kaynak yanıt vermedi: nedenini Bu IP’deki alan adları bölümündeki kaynak etiketleri söyler.',
  'ipi.rev.private': 'yalnızca çalışma alanınız',
  'ipi.rev.all': 'Bu adreslerdeki alan adları',
  'ipi.rev.loadFailed': 'Bu IP’deki alan adları bölümü yüklenemedi.',
  'ipi.quota': 'Alan adlarını bul, adresi HackerTarget’a (IP adresiniz başına günde yaklaşık 50 sorgu, SSL Hedefleri taramasıyla ortak), ip.thc.org’a, AlienVault OTX’e, Robtex’e ve Shodan InternetDB’ye sorar. Yalnızca gerektiğinde kullanın.',

  'ipi.det.rir': 'Kayıt kuruluşu (RIR)',
  'ipi.det.announced': 'İnternet’te duyuruluyor',
  'ipi.det.asns': 'Kaynak AS',
  'ipi.det.sources': 'Veri kaynakları',
  'ipi.det.errors': 'Sorunlar',
  'ipi.det.provider': 'Sağlayıcı',
  'ipi.det.links': 'Başka yerde aç',
  'ipi.det.hosts': 'Girdiğiniz host adları',
  'ipi.det.network': 'Ağ',
  'ipi.det.blocklists': 'Kara listeler',

  'ipi.net.badge': '{name} ağı',
  'ipi.net.short.outside-proxy-ranges': 'AS{asn} · proxy’li site aralığı değil',
  'ipi.net.short.cdn-edge': 'AS{asn} · büyük olasılıkla CDN kenar sunucusu',
  'ipi.net.short.hosted': 'AS{asn} · {category}',
  'ipi.net.long.outside-proxy-ranges': 'Bu adres {name} ağına (AS{asn}) ait, ancak {name} tarafından proxy’lenen web siteleri için yayımlanan aralıkların dışında — yani bir {name} hizmeti (örneğin 1.1.1.1 bir DNS çözümleyicisidir), arkasına gizlenmiş bir web sitesi değil.',
  'ipi.net.long.cdn-edge': '{name} (AS{asn}) tarafından duyuruluyor: kenar sunucu adreslerini yayımlamayan bir CDN / güvenlik proxy’si — büyük olasılıkla, asıl sunucusu gizlenmiş bir web sitesinin önündeki kenar sunucusu.',
  'ipi.net.long.hosted': '{name} (AS{asn}) tarafından duyuruluyor: {name} ağında, önünde CDN olmadan doğrudan erişilen bir sunucu ya da hizmet.',
  'ipi.net.short.ranges.outside-proxy-ranges': 'proxy’li olmayabilir',
  'ipi.net.short.ranges.hosted': '{category} · yayımlanan aralık',
  'ipi.net.long.ranges.outside-proxy-ranges': 'Bu adres {name} ağında ({updated} tarihli sağlayıcı listesi), ancak {name} tarafından proxy’lenen web sitelerinin aralıklarının dışında; yani proxy’li olmayabilir: bir {name} hizmeti (örneğin 1.1.1.1 bir DNS çözümleyicisidir), bir müşterinin kendi adres bloğu ya da bir TCP / UDP proxy’si — {name} arkasına gizlenmiş bir web sitesi değil.',
  'ipi.net.long.ranges.hosted': 'Bu adres {name} tarafından yayımlanan adres alanında ({updated} tarihli sağlayıcı listesi): {name} ağında, önünde CDN olmadan doğrudan erişilen bir sunucu ya da hizmet.',
  'ipi.net.asOrigin': 'Kaynak AS: AS{asn}.',
  'ipi.net.cat.cdn': 'CDN',
  'ipi.net.cat.waf': 'CDN / WAF',
  'ipi.net.cat.cloud': 'bulut',
  'ipi.net.cat.hosting': 'barındırma',
  'ipi.net.cat.platform': 'platform'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/**
 * Split pasted text into IP addresses, host names and rejected tokens.
 * Accepts `1.2.3.4:443`, `[2001:db8::1]:443`, URLs (host part), IDNs. CIDR ranges are
 * reported separately (not expanded). Duplicates are removed; input order is kept.
 * @param {string} text
 * @returns {{ ips: string[], hosts: string[], invalid: string[], cidrs: string[] }}
 */
export function parseIpInput(text) {
  const ips = [];
  const hosts = [];
  const invalid = [];
  const cidrs = [];
  const add = (list, v) => {
    if (!list.includes(v)) list.push(v);
  };
  for (const token of splitList(text)) {
    let candidate = token.replace(/^["'<(]+|[>"')]+$/g, '');
    const bracket = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(candidate);
    if (bracket) candidate = bracket[1];
    const v4port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(candidate);
    if (v4port) candidate = v4port[1];
    const ip = normalizeIP(candidate);
    if (ip) {
      add(ips, ip);
      continue;
    }
    if (/^[0-9a-f:.]+\/\d{1,3}$/i.test(candidate)) {
      add(cidrs, candidate);
      continue;
    }
    const host = normalizeHostname(candidate);
    if (host) add(hosts, host);
    else add(invalid, token);
  }
  return { ips, hosts, invalid, cidrs };
}

/**
 * Classification (Cloudflare / CDN / platform / direct / private) of a single address.
 * `cnames` (the alias chain of the host name it came from) lets CNAME-only CDNs such as
 * Akamai be recognised.
 * @param {string} ip
 * @param {string[]} [cnames]
 * @returns {object} lib/netinfo classifyResolution result
 */
export function classifyIp(ip, cnames = []) {
  const v = ipVersion(ip);
  return classifyResolution({ status: 'NOERROR', ipv4: v === 4 ? [ip] : [], ipv6: v === 6 ? [ip] : [], cnames });
}

/* ------------------------------------------------------------------------ */
/* Shared intel service (cache survives navigation between views)           */
/* ------------------------------------------------------------------------ */

let intelService = null;
let intelDns = null;
/** ui/reverse-ip-panel.js (Domains on this IP), loaded on the first "Find domains". */
const loadReversePanel = onceAsync(() => import('../ui/reverse-ip-panel.js'));
/** Addresses handed to Domains on this IP at most (lib/reverseip.js MAX_REVERSE_IPS). */
const MAX_REVERSE = 10;

function getIntel(dns) {
  if (!intelService || intelDns !== dns) {
    intelService = createIpIntel({ dns, concurrency: 4 });
    intelDns = dns;
  }
  return intelService;
}

/** The Blocklists panel of a row's details (ui/dnsbl-panel.js), loaded when details first open. */
let dnsblModule = null;
const loadDnsbl = () => (dnsblModule ||= import('../ui/dnsbl-panel.js').catch((err) => { dnsblModule = null; throw err; }));

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

let active = null;

/**
 * Mount the IP Intel view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t } = ctx;
  const restored = ctx.restored && typeof ctx.restored === 'object' ? ctx.restored : null;
  const paramText = [ctx.params.ips, ctx.params.ip, ctx.params.q].filter(Boolean).join('\n');
  const initialText = restored?.text ?? (paramText ? splitList(paramText).join('\n') : '');

  /* --- helpers ----------------------------------------------------------------- */
  const hostLink = (host) => h('a', { class: 'ipi-host mono', href: ctx.href('lookup', { name: host, type: 'A,AAAA' }) }, host);
  const flag = (cc) => Flag(cc, { className: 'ipi-flag' });
  /**
   * The provider network of a plain 'direct' address (display only, lib/networklabel.js): the range
   * dataset's network tier (offline, at once: "Cloudflare network, not necessarily proxied", "AWS
   * network"), with the origin AS once RIPEstat named the same operator — else the AS-based hint
   * alone (ipintel.networkHint: Akamai, Hetzner …).
   */
  const hintOf = (r) => networkLabel({ classification: r.classification, ip: r.ip, hint: r.info ? networkHint(r.info, r.classification) : null });
  const hintText = (hint) => {
    const category = t(`ipi.net.cat.${hint.category}`);
    const short = hint.asn !== null ? t(`ipi.net.short.${hint.relation}`, { asn: hint.asn, category })
      : t(`ipi.net.short.ranges.${hint.relation}`, { category });
    const long = hint.source === 'asn' ? t(`ipi.net.long.${hint.relation}`, { name: hint.name, asn: hint.asn })
      : [t(`ipi.net.long.ranges.${hint.relation}`, { name: hint.name, updated: rangesInfo().updated }), hint.asn !== null ? t('ipi.net.asOrigin', { asn: hint.asn }) : null]
        .filter(Boolean).join(' ');
    return { badge: t('ipi.net.badge', { name: hint.name }), short, long };
  };
  const hasInventory = () => ctx.state.inventory.servers.length > 0;

  /* --- region 2: the input (ui/template.js ToolInput) ------------------------------- */
  const input = textarea({
    label: t('ipi.inputLabel'),
    value: initialText,
    rows: 6,
    placeholder: t('ipi.placeholder'),
    hint: t('ipi.inputHint'),
    className: 'ipi-input',
    // Ctrl/Cmd+Enter in it clicks Run: the shell's shortcut finds the buttons by data-shortcut.
    attrs: { 'data-role': 'ip-input', 'data-shortcut': 'focus' }
  });
  const parsedEl = h('div', { class: 'ipi-parsed muted text-sm', attrs: { 'aria-live': 'polite' } });
  const runBar = RunBar({
    label: t('ipi.run'),
    dataset: { action: 'run', shortcut: 'submit' },
    stopLabel: t('ipi.stop'),
    stopDataset: { action: 'stop', shortcut: 'cancel' },
    onRun: () => start(),
    onStop: () => stop(),
    hasValue: () => !!input.value.trim()
  });
  // An example fills the box and leaves the keyboard on Look up: nothing is sent before that click.
  const examplesEl = ExampleChips({
    className: 'ipi-examples',
    examples: IP_EXAMPLES.map((list) => ({ value: list.join('\n'), label: list.join(' ') })),
    onPick: (value) => {
      input.value = `${value}\n`;
      input.setError(null);
      updateParsed();
    },
    focus: () => runBar.run
  });
  const inventoryIps = () => [...new Set(ctx.state.inventory.servers.flatMap((s) => s.ips))];
  const inventoryBtn = Button({
    label: t('ipi.fromInventory'), icon: 'server', variant: 'ghost', size: 'sm', title: t('ipi.fromInventoryTitle'), dataset: { action: 'inventory' },
    onClick: () => {
      input.value = `${inventoryIps().join('\n')}\n`;
      input.setError(null);
      updateParsed();
    }
  });
  inventoryBtn.hidden = inventoryIps().length === 0;
  const clearBtn = Button({
    label: t('ipi.clear'), icon: 'trash', variant: 'ghost', size: 'sm', dataset: { action: 'ipi-clear' },
    onClick: () => {
      input.value = '';
      updateParsed();
      input.focus();
    }
  });

  function updateParsed() {
    const p = parseIpInput(input.value);
    parsedEl.textContent = p.ips.length || p.hosts.length
      ? `${t('ipi.parsedIps', { count: p.ips.length })} · ${t('ipi.parsedHosts', { count: p.hosts.length })}` : '';
    syncRunBar();
  }
  input.input.addEventListener('input', updateParsed);

  const tool = ToolInput({
    className: 'ipi-form-card',
    label: t('nav.ip'),
    primary: input.el,
    run: runBar,
    notes: [parsedEl],
    extras: [examplesEl, h('div', { class: 'cluster ipi-fill' }, inventoryBtn, clearBtn)],
    privacy: PrivacyNote({ text: t('ipi.privacy'), className: 'ipi-privacy' })
  });

  /* --- regions 4, 6 and 8: the result header, the metric strip, the table ----------------- */
  const progress = ProgressBar({ label: t('ipi.looking') });
  const notesEl = h('div', { class: 'stack-sm ipi-notes' });
  const sourcesEl = h('div', { class: 'src-chips ipi-sources', hidden: true, attrs: { role: 'group', 'aria-label': t('ipi.det.sources'), tabindex: -1 } });
  /** The result header (`.ipi-results-bar`, the old bar's hook): there from a run's start. */
  const head = ResultHeader({ className: 'ipi-results-bar' });
  head.set('notes', notesEl);
  head.set('sources', sourcesEl);
  /** The status items' table filter, pressed (lib/netresults.js IP_FILTERS by item key), or null. */
  let pressed = null;
  const status = StatusSummary({ items: [] });
  head.set('status', status.el);
  // Zero counts fold into one sentence ("None of these addresses is behind a CDN / proxy"): the
  // folded metrics' phrases and the row count of the last drawing, read by zeroText.
  let zeroPhrases = new Map();
  let zeroCount = 0;
  const metrics = MetricStrip({
    className: 'ipi-stats',
    zeroText: (labels) => t('ipi.zero', { count: zeroCount, list: listText(labels.map((l) => zeroPhrases.get(l)).filter(Boolean)) })
  });
  const quotaNote = h('p', { class: 'ipi-quota' }, Icon('info', { size: 13 }), h('span', null, t('ipi.quota')));

  const exportJson = (rows) => rows.map((r) => ({
    ip: r.ip,
    version: ipVersion(r.ip),
    hosts: r.hosts,
    private: isPrivateIP(r.ip),
    operator: r.classification.provider ? r.classification.provider.name : r.classification.kind,
    network: (() => {
      const hint = hintOf(r);
      return hint ? { id: hint.id, name: hint.name, asn: hint.asn, category: hint.category, relation: hint.relation, source: hint.source } : null;
    })(),
    ptr: r.info ? r.info.ptr : [],
    asn: r.info ? r.info.asn : null,
    asName: r.info ? r.info.asName : null,
    holder: r.info ? r.info.holder : null,
    prefix: r.info ? r.info.prefix : null,
    country: r.info ? r.info.country : null,
    city: r.info ? r.info.city : null,
    rir: r.info ? r.info.rir : null,
    announced: r.info ? r.info.announced : null,
    servers: r.servers.map((s) => s.name),
    reverseIp: r.reverse && r.reverse.result && r.reverse.result.ok ? r.reverse.result.domains : null,
    error: r.info ? r.info.error : null,
    // Fields a failed source left empty (not "none"), and why.
    unavailable: Object.fromEntries(IP_FIELDS.map((f) => [f, ipFieldStatus(r.info, f)]).filter(([, st]) => st).map(([f, st]) => [f, st.sources])),
    sourceErrors: r.info ? r.info.errors.map((e) => ({ source: e.source, error: e.error, errorKind: e.errorKind, status: e.status ?? null })) : []
  }));
  /** CSV text of a cell: its value, or "n/a" ({@link EXPORT_NA}) when a failed source left it empty. */
  const csvValue = (r, field, value) => (value ? value : ipFieldStatus(r.info, field) ? EXPORT_NA : '');

  const columns = [
    {
      key: 'ip', label: t('ipi.col.ip'), sortable: true, sortValue: (r) => ipSortValue(r.ip),
      searchValue: (r) => [r.ip, ...r.hosts].join(' '), exportValue: (r) => r.ip,
      render: (r) => h('div', { class: 'ipi-ipcell' },
        // A full IPv6 address may break in two on a phone (lib/density.js addressLines).
        h('span', { class: 'mono ipi-ip' }, addressLines(r.ip).flatMap((part, i) => (i ? [h('wbr'), part] : [part]))),
        r.hosts.length ? h('span', { class: 'muted text-xs' }, t('ipi.fromHost', { host: r.hosts.slice(0, 2).join(', ') + (r.hosts.length > 2 ? ` +${r.hosts.length - 2}` : '') })) : null,
        rowRetry(r))
    },
    {
      key: 'operator', label: t('ipi.col.operator'), sortable: true, sortValue: (r) => r.classification.kind,
      searchValue: (r) => {
        const hint = hintOf(r);
        return `${r.classification.kind} ${r.classification.provider ? r.classification.provider.name : ''} ${hint ? hintText(hint).badge : ''}`;
      },
      exportValue: (r) => {
        const base = r.classification.provider ? r.classification.provider.name : t(`kind.${r.classification.kind}`);
        const hint = hintOf(r);
        return hint ? `${base} · ${hintText(hint).badge}${hint.asn !== null ? ` (AS${hint.asn})` : ''}` : base;
      },
      render: renderOperator
    },
    {
      key: 'server', label: t('ipi.col.server'), sortable: true,
      sortValue: (r) => (r.servers.length ? r.servers[0].name : null),
      searchValue: (r) => r.servers.map((s) => s.name).join(' '),
      exportValue: (r) => r.servers.map((s) => s.name).join(' '),
      render: (r) => (r.servers.length ? h('div', { class: 'cluster' }, r.servers.map((s) => Badge(s.name, { variant: 'direct', icon: 'server' }))) : null)
    },
    {
      key: 'ptr', label: t('ipi.col.ptr'), sortable: true, className: 'ipi-col-ptr', sortValue: (r) => (r.info && r.info.ptr[0]) || null,
      searchValue: (r) => (r.info ? r.info.ptr.join(' ') : ''), exportValue: (r) => csvValue(r, 'ptr', r.info ? r.info.ptr.join(' ') : ''),
      render: (r) => (r.pending ? pendingCell() : r.info && r.info.ptr.length ? TruncatedList(r.info.ptr, { max: 2, render: hostLink }) : naCell(r, 'ptr'))
    },
    {
      key: 'network', label: t('ipi.col.holder'), sortable: true, className: 'ipi-col-network',
      sortValue: (r) => (r.info ? r.info.asn : null),
      searchValue: (r) => (r.info ? `AS${r.info.asn || ''} ${r.info.asName || ''} ${r.info.holder || ''}` : ''),
      exportValue: (r) => csvValue(r, 'network', r.info ? [r.info.asn ? `AS${r.info.asn}` : '', [r.info.asName, r.info.holder].filter((x, i, arr) => x && arr.indexOf(x) === i).join(' - ')].filter(Boolean).join(' ') : ''),
      render: (r) => {
        if (r.pending || !r.info) return null;
        if (!r.info.asn && !r.info.holder) {
          return naCell(r, 'network') || (r.info.announced === false ? Badge(t('ipi.notAnnounced'), { title: t('ipi.notAnnouncedTitle') }) : null);
        }
        const same = !r.info.holder || r.info.asName === r.info.holder;
        return h('div', { class: 'ipi-holder' },
          h('span', { class: 'ipi-holder-name' },
            r.info.asn ? ExternalLink(`https://stat.ripe.net/AS${r.info.asn}`, `AS${r.info.asn}`, { className: 'mono ipi-asn', icon: false }) : null,
            r.info.asn ? ' ' : null,
            r.info.asName || r.info.holder),
          !same ? h('span', { class: 'muted text-xs ipi-holder-org' }, r.info.holder) : null);
      }
    },
    {
      key: 'prefix', label: t('ipi.col.prefix'), sortable: true, mono: true, className: 'ipi-col-prefix',
      sortValue: (r) => (r.info && r.info.prefix ? ipSortValue(r.info.prefix.split('/')[0]) : null),
      exportValue: (r) => csvValue(r, 'prefix', r.info ? r.info.prefix || '' : ''),
      render: (r) => (r.info && r.info.prefix ? r.info.prefix : naCell(r, 'prefix'))
    },
    {
      key: 'location', label: t('ipi.col.location'), sortable: true, className: 'ipi-col-location',
      sortValue: (r) => (r.info && r.info.country ? `${formatRegion(r.info.country)} ${r.info.city || ''}` : null),
      searchValue: (r) => (r.info && r.info.country ? `${r.info.country} ${formatRegion(r.info.country)} ${r.info.city || ''}` : ''),
      exportValue: (r) => csvValue(r, 'location', r.info && r.info.country ? [r.info.country, r.info.city].filter(Boolean).join(' ') : ''),
      render: (r) => (r.info && r.info.country ? h('div', { class: 'ipi-loc' },
        h('span', null, flag(r.info.country), ' ', formatRegion(r.info.country)),
        r.info.city ? h('span', { class: 'muted text-xs' }, r.info.city) : null) : naCell(r, 'location'))
    },
    {
      key: 'reverse', label: t('ipi.col.reverse'), searchable: true,
      searchValue: (r) => (r.reverse && r.reverse.result && r.reverse.result.ok ? r.reverse.result.domains.join(' ') : ''),
      exportValue: (r) => (r.reverse && r.reverse.result && r.reverse.result.ok ? r.reverse.result.domains.join(' ') : ''),
      render: renderReverse
    }
  ];

  // The table's files are the result header's Export ▾ (it writes what the table lists); on a
  // phone each row is a card of labelled lines (style.css .dt-cards).
  const table = DataTable({
    caption: t('nav.ip'),
    rowKey: (r) => r.ip,
    search: true,
    dense: true,
    pageSize: 100,
    export: false,
    cellLabels: true,
    className: 'ipi-table dt-cards',
    rowClass: (r) => ['ipi-row', { 'is-pending': r.pending }],
    details: (r) => renderDetails(r),
    columns
  });

  /** The rows the table lists (filter and search applied, in its order) as a CSV or JSON file. */
  function exportTable(format) {
    const rows = table.getVisibleRows();
    const name = timestampedName('ip-intel', format);
    const file = format === 'csv'
      ? downloadText(name, toCsv(rows, exportColumns(columns)), 'text/csv;charset=utf-8')
      : downloadText(name, `${toJson(exportJson(rows))}\n`, 'application/json;charset=utf-8');
    ctx.toast(t('table.exported', { file }), { type: 'success', timeout: 2500 });
  }

  const emptyEl = h('div', { class: 'ipi-empty' }, EmptyState({
    icon: 'network',
    message: t('ipi.emptyLine', { max: formatNumber(MAX_IPS) }),
    checks: ['ptr', 'asn', 'location', 'cdn', 'server', 'reverse'].map((c) => t(`ipi.check.${c}`))
  }));
  // Domains on this IP: the panel loads on the first "Find domains" (ui/reverse-ip-panel.js).
  const reverseHost = h('div', { class: 'ipi-reverse-host', hidden: true });
  // No part of the form: Ctrl/Cmd+Enter in the table's filter starts no new run.
  const results = h('div', { class: 'ipi-results', hidden: true, dataset: { shortcutScope: 'results' } }, head.el, metrics.el, quotaNote, table.el);
  container.append(h('div', { class: 'ipi-view' }, tool.el, emptyEl, results, reverseHost, runBar.float));

  /** The link a share button copies for a run's params: private and inventory addresses left out. */
  const permalink = (params) => ctx.shareUrl(permalinkParams('ip', params, {
    exclude: [...ctx.getInventoryIndex().keys(), ...(current ? current.rows.filter((r) => r.servers.length).map((r) => r.ip) : [])]
  }));

  /** The run's actions (ResultActions), drawn for each run: its Copy link exists only when a link can carry its addresses. */
  let actions = null;
  ctx.onCleanup(() => {
    runBar.dispose();
    if (actions) actions.dispose();
  });

  /* --- cell renderers ----------------------------------------------------------------- */
  /** "⚠ n/a" when a failed source left `field` empty (null for a real "none" or a pending row). */
  function naCell(r, field) {
    if (r.pending || !r.info) return null;
    const st = ipFieldStatus(r.info, field);
    return st ? NaMark(st.statuses) : null;
  }

  /** The row's Retry: asks again only the sources whose failure left a field empty. */
  function rowRetry(r) {
    if (r.pending || !r.info) return null;
    const sources = ipRetrySources(r.info);
    if (!sources.length) return null;
    const btn = RetryButton({ sources, target: r.ip, onClick: () => retryRows([r]), dataset: { ip: r.ip } });
    btn.classList.add('ipi-retry');
    if (r.retrying) setRetryBusy(btn);
    return btn;
  }

  /** Operator cell: the classification badge, or for plain 'direct' addresses on a well-known
   *  network (1.1.1.1 → Cloudflare's, an EC2 address → AWS's) a badge naming that network plus a
   *  one-line explanation; `data-source` says where the label comes from (ranges, asn, both). */
  function renderOperator(r) {
    const hint = hintOf(r);
    if (!hint) return KindBadge(r.classification);
    const text = hintText(hint);
    const edge = hint.relation === 'cdn-edge';
    const badge = Badge(text.badge, { variant: edge ? 'cdn' : 'direct', icon: edge ? 'zap' : (hint.category === 'hosting' ? 'server' : 'cloud'), title: text.long });
    badge.dataset.kind = r.classification.kind;
    return h('div', { class: 'ipi-op', dataset: { network: hint.id, relation: hint.relation, source: hint.source } },
      badge, h('span', { class: 'muted text-xs ipi-op-note' }, text.short));
  }

  function pendingCell() {
    return h('span', { class: 'ipi-pending' }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), t('ipi.pending'));
  }

  /**
   * "Other domains on this IP": Find domains (Domains on this IP below the table, for this address),
   * then the count and the first names its sources gave. A private address is answered from the
   * workspace alone (the panel says so); nothing about it is sent.
   */
  function renderReverse(r) {
    const rev = r.reverse;
    const local = isPrivateIP(r.ip) ? h('span', { class: 'muted text-xs' }, t('ipi.rev.private')) : null;
    if (!rev || rev.state === 'loading') {
      const btn = Button({
        label: t('ipi.rev.button'), icon: 'search', size: 'sm', variant: local ? 'ghost' : 'secondary', dataset: { action: 'reverse', ip: r.ip },
        onClick: () => openReverse([r.ip])
      });
      if (rev && rev.state === 'loading') setButtonBusy(btn, true);
      return local ? h('div', { class: 'ipi-rev', dataset: { state: 'button' } }, btn, local) : btn;
    }
    const res = rev.result;
    if (res.ok) {
      return h('div', { class: 'ipi-rev', dataset: { state: 'done', count: res.domains.length } },
        Badge(t('ipi.rev.count', { count: res.domains.length }), { variant: res.domains.length ? 'accent' : 'neutral', icon: 'globe' }),
        res.domains.length ? TruncatedList(res.domains, { max: 5, render: hostLink }) : null, local);
    }
    return h('div', { class: 'ipi-rev', dataset: { state: 'error' } },
      Badge(t('ipi.rev.failed'), { variant: 'error', icon: 'x-circle', title: t('ipi.rev.failedTitle') }),
      RetryButton({ sources: ['hackertarget', 'thc', 'otx', 'robtex', 'internetdb'], target: r.ip, onClick: () => openReverse([r.ip]) }));
  }

  function renderDetails(r) {
    const info = r.info;
    const items = [];
    if (r.hosts.length) items.push({ key: t('ipi.det.hosts'), value: h('div', { class: 'cluster' }, r.hosts.map(hostLink)) });
    if (r.classification.provider) items.push({ key: t('ipi.det.provider'), value: t(r.classification.reasonKey, { provider: r.classification.provider.name }) });
    const hint = hintOf(r);
    if (hint) items.push({ key: t('ipi.det.network'), value: `${hintText(hint).badge} — ${hintText(hint).long}` });
    if (info) {
      if (info.ptr.length) items.push({ key: t('ipi.col.ptr'), value: h('div', { class: 'cluster' }, info.ptr.map(hostLink)) });
      if (info.asns.length) {
        items.push({
          key: t('ipi.det.asns'),
          value: h('div', { class: 'stack-sm' }, info.asns.map((a) => h('span', null, ExternalLink(`https://stat.ripe.net/AS${a.asn}`, `AS${a.asn}`, { className: 'mono' }), a.holder ? ` ${a.holder}` : '')))
        });
      }
      if (info.rir) items.push({ key: t('ipi.det.rir'), value: info.rir });
      if (info.announced !== null && info.announced !== undefined) items.push({ key: t('ipi.det.announced'), value: info.announced ? t('common.yes') : t('common.no') });
      if (info.sources.length) items.push({ key: t('ipi.det.sources'), value: info.sources.join(', ') });
      if (info.errors.length) {
        items.push({
          key: t('ipi.det.errors'),
          value: h('div', { class: 'stack-sm' }, info.errors.map((e) => {
            const st = sourceStatus(e);
            return h('span', { class: 'ipi-problem', dataset: { source: e.source } }, statusText(st),
              st.detail ? h('span', { class: 'mono text-xs muted' }, ` · ${st.detail}`) : null);
          }))
        });
      }
    }
    if (!isPrivateIP(r.ip)) {
      items.push({
        key: t('ipi.det.links'),
        value: h('div', { class: 'cluster' },
          ExternalLink(`https://stat.ripe.net/${encodeURIComponent(r.ip)}`, 'RIPEstat'),
          ExternalLink(`https://bgp.he.net/ip/${encodeURIComponent(r.ip)}`, 'bgp.he.net'),
          h('a', { href: ctx.href('lookup', { name: r.ip }) }, t('nav.lookup')))
      });
    }
    if (!isPrivateIP(r.ip)) items.push({ key: t('ipi.det.blocklists'), value: blocklistSlot(r) });
    const list = KeyValueList(items, { className: 'ipi-details' });
    if (r.pending || !ipVersion(r.ip)) return list;
    const slot = h('section', { class: 'ipi-enrich' });
    loadEnrich().then((m) => m.mountIpEnrich(slot, r, ctx), (err) => {
      ctx.checkOutdated();
      slot.append(ErrorBanner(err, { compact: true }));
    });
    return h('div', { class: 'stack' }, list, slot);
  }

  /** A row's Blocklists panel: nothing is asked before its button; the same panel across re-renders. */
  function blocklistSlot(r) {
    const slot = h('div', { class: 'ipi-bl-slot' });
    loadDnsbl().then((m) => slot.append(m.dnsblPanel(r, ctx)), () => {
      ctx.checkOutdated();
      slot.append(Alert({ variant: 'error', compact: true, message: t('error.title') }));
    });
    return slot;
  }

  /* --- run -------------------------------------------------------------------------------- */
  let current = null;

  /** The user's servers with this address (the inventory as it is now). */
  const serversOf = (ip) => lookupServers([ip], ctx.getInventoryIndex()).map((m) => m.server);

  function makeRow(ip) {
    return {
      ip,
      hosts: [],
      info: null,
      pending: true,
      classification: classifyIp(ip),
      servers: serversOf(ip),
      reverse: null
    };
  }

  /** The metric strip's figure of each id (lib/netresults.js IP_METRICS), with its hint. */
  const METRIC_OF = {
    ips: (f) => ({ label: t('ipi.stat.ips'), value: f.ips, hint: t('ipi.stat.ipsHint', { v4: formatNumber(f.v4), v6: formatNumber(f.v6) }) }),
    cdn: (f) => ({ label: t('ipi.stat.cdn'), value: f.cdn, hint: f.providers.slice(0, 3).join(', ') || null }),
    mine: (f) => ({ label: t('ipi.stat.mine'), value: f.mine, hint: f.servers.slice(0, 3).join(', ') || null }),
    priv: (f) => ({ label: t('ipi.stat.private'), value: f.priv }),
    nets: (f) => ({ label: t('ipi.stat.networks'), value: f.nets }),
    countries: (f) => ({ label: t('ipi.stat.countries'), value: f.countries.length, hint: f.countries.slice(0, 6).join(' ') || null })
  };

  /** The status summary's words of each item (lib/netresults.js ipStatus). */
  const statusWords = (key, count) => (key === 'sources' ? t('result.sourcesFailed', { count }) : t(`ipi.status.${key}`, { count }));
  /** What the status summary shows now, in words: announced once when a lookup ends. */
  let statusLine = [];

  /** The metric strip, the status summary and the source chips of the rows on screen. */
  function renderStats(rows) {
    const figures = ipFigures(rows);
    const inventory = hasInventory();
    const list = ipMetricIds({ inventory }).map((id) => ({ id, ...METRIC_OF[id](figures) }));
    zeroPhrases = new Map(list.filter((m) => IP_FOLDABLE.includes(m.id)).map((m) => [m.label, t(`ipi.zero.${m.id}`)]));
    zeroCount = rows.length;
    metrics.update(list, { foldable: rows.length ? [...IP_FOLDABLE] : [] });
    const chips = ipSourceChips(rows);
    renderSources(rows, chips);
    const items = ipStatus({ figures, failedSources: chips.filter((c) => c.state === 'failed').length, inventory }).map((item) => ({
      ...item,
      text: statusWords(item.key, item.count),
      onPress: item.filter ? () => setFilter(pressed === item.key ? null : item.key)
        : item.key === 'sources' ? () => focusSources() : null
    }));
    status.update(items, { pressed });
    statusLine = statusItems(items).map((x) => x.text);
  }

  /** A status item pressed: the table lists only its rows (pressed again: every row). */
  function setFilter(key) {
    const item = key ? ipStatus().find((x) => x.key === key) : null;
    pressed = item && item.filter ? key : null;
    table.setFilter(pressed ? (row) => ipRowMatches(row, item.filter) : null);
    status.setPressed(pressed);
  }

  /** "1 source failed": the keyboard focus goes to the chips, whose Retry asks it again. */
  function focusSources() {
    if (sourcesEl.hidden) return;
    sourcesEl.scrollIntoView({ block: 'nearest', behavior: scrollBehavior() });
    (sourcesEl.querySelector('[data-action="retry-source"]') || sourcesEl).focus({ preventScroll: true });
  }

  /** "a, b or c" in the UI language. */
  function listText(parts) {
    try {
      return new Intl.ListFormat(localeTag(), { type: 'disjunction' }).format(parts);
    } catch {
      return parts.join(', ');
    }
  }

  /**
   * One chip per service: where its failures left fields empty, with a Retry of those rows. No
   * chips while nothing was asked (a run stopped before its first answer: the note says so).
   */
  function renderSources(rows, chips = ipSourceChips(rows)) {
    const looked = rows.some((r) => !isPrivateIP(r.ip) && (r.pending || r.info));
    // A chip's Retry that had the keyboard focus gets it back, or the group when that Retry is gone.
    const focused = sourcesEl.contains(globalThis.document.activeElement) ? globalThis.document.activeElement.dataset.chip || '' : null;
    sourcesEl.hidden = !looked;
    clear(sourcesEl);
    if (!looked) return;
    for (const chip of chips) {
      const failedRows = rows.filter((r) => chip.ips.includes(r.ip));
      sourcesEl.append(SourceChip(chip, {
        onRetry: () => retryRows(failedRows, chip.sources),
        busy: failedRows.some((r) => r.retrying)
      }));
    }
    if (focused !== null) (sourcesEl.querySelector(`[data-chip="${focused}"]`) || sourcesEl).focus();
  }

  /**
   * The result header of the run on screen: while it runs, what it does and its progress; once it
   * ended, its count ("3 addresses", one address by itself), when, the actions and the next step.
   */
  function renderHead() {
    const state = current;
    if (!state) return;
    const running = !!state.controller;
    const count = state.rows.length;
    head.setState(running ? 'running' : 'done');
    let title;
    if (running) title = state.resolving ? t('ipi.resolvingTitle') : t('ipi.lookingCount', { count });
    else if (count === 1) title = h('span', { class: 'mono result-subject' }, state.rows[0].ip);
    else title = t('ipi.resultsTitle', { count });
    head.set('title', ResultTitle({ running, text: title }));
    head.set('meta', !running && state.finishedAt
      ? RelativeTime(state.finishedAt, { className: 'ipi-at', text: t('ipi.checkedAt', { time: formatRelative(state.finishedAt) }) }) : null);
    head.set('progress', running ? progress.el : null);
    if (actions) actions.setDisabled(running || !count);
    head.set('next', !running && count ? NextSteps({
      steps: [{ label: t('ipi.rev.all'), icon: 'globe', dataset: { action: 'reverse-all' }, onClick: () => openReverse(state.rows.map((r) => r.ip), { run: false }) }]
    }) : null);
  }

  /**
   * The actions of a run (ResultActions): Copy summary with ¶, Export ▾ (CSV, JSON: what the table
   * lists) and Copy link when a link can carry the run's addresses (at most 40 of them): the run on
   * screen, not the box, which may hold a carried address. Like Copy summary's link, it leaves out
   * private and inventory addresses (the address bar keeps them: a reload runs the same lookup).
   */
  function renderActions(params) {
    if (actions) actions.dispose();
    actions = ResultActions({
      summary: SummaryButton({
        kind: 'ip',
        inventory: 'count',
        plainLabel: t('result.plainTitle'),
        facts: () => (current && !current.controller && current.rows.length ? { rows: current.rows, at: current.finishedAt, stopped: current.stopped } : null),
        url: () => (current ? permalink(lookupParams(current.text)) : null)
      }),
      exports: [
        { label: t('common.exportCsv'), icon: 'download', dataset: { export: 'csv' }, onSelect: () => exportTable('csv') },
        { label: t('common.exportJson'), icon: 'download', dataset: { export: 'json' }, onSelect: () => exportTable('json') }
      ],
      link: params.ips ? () => permalink(params) : null
    });
    head.set('actions', actions.el);
    actions.setDisabled(!!(current && current.controller));
  }

  /** The run bar and the input follow the state: compact once a lookup starts, "Run again" while the box asks for the rows on screen. */
  function syncRunBar() {
    const running = !!(current && current.controller);
    const state = templateState({ running, result: !!(current && current.rows.length) });
    runBar.setState(state);
    runBar.setRerun(state === 'done' && entriesOf(input.value).join('\n') === entriesOf(current.text).join('\n'));
    tool.setCompact(inputCompact(state));
    runBar.refresh();
  }

  /**
   * Ask again, for each row, only the sources that failed there (and are in `sources`, when a
   * chip's Retry names them); the rows re-render as their answers arrive. A Retry belongs to its
   * run: a new lookup, Stop or leaving the view cancels it (`state.life`), and once its run is
   * replaced it never touches the table again (the new run's row for the same address is not its
   * to draw).
   */
  async function retryRows(list, sources = null) {
    const state = current;
    const rows = list.filter((r) => r.info && !r.retrying);
    if (!state || !rows.length) return;
    const signal = mergeSignals(ctx.signal, state.life.signal);
    const live = () => current === state && !ctx.signal.aborted;
    for (const r of rows) {
      r.retrying = true;
      table.updateRow(r);
    }
    renderSources(state.rows);
    let intel = null;
    try {
      intel = getIntel(await ctx.getDns());
    } catch (err) {
      if (live()) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    }
    await Promise.all(rows.map(async (r) => {
      try {
        if (!intel || !live()) return;
        const want = ipRetrySources(r.info).filter((s) => !sources || sources.includes(s));
        const next = await intel.retry(r.info, { sources: want, signal });
        if (live()) r.info = next;
      } catch (err) {
        if (!(err && err.name === 'AbortError') && live()) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      } finally {
        r.retrying = false;
        if (live()) table.updateRow(r);
      }
    }));
    if (!live()) return;
    renderStats(state.rows);
    // A Retry that Stop cancelled asked nothing again.
    if (!signal.aborted) announce(t('ipi.retried', { count: rows.length }));
  }

  function note(variant, message) {
    notesEl.append(Alert({ variant, compact: true, message }));
  }

  function setRunning(on) {
    // The keyboard focus follows the button it was on (Look up ⇄ Stop).
    runBar.setRunning(on);
    input.input.readOnly = on;
    if (actions) actions.setDisabled(on || !(current && current.rows.length));
    ctx.setBusy(on ? t('ipi.looking') : false);
    syncRunBar();
  }

  function stop() {
    if (current && current.controller) {
      current.stopped = true;
      current.controller.abort();
      // Retries in flight stop too; a later Retry of this run gets a new controller.
      current.life.abort();
      current.life = new AbortController();
    }
  }

  /** Look the addresses up. `auto`: a shared link's run on arrival (offline: no toast, see lookup.js). */
  function start({ auto = false } = {}) {
    const parsed = parseIpInput(input.value);
    input.setError(null);
    if (!parsed.ips.length && !parsed.hosts.length) {
      input.setError(parsed.cidrs.length ? t('ipi.cidr', { range: parsed.cidrs[0] }) : t('ipi.nothing'));
      input.focus();
      return;
    }
    carried = null;
    if (!ctx.requireOnline({ quiet: auto })) return;
    const tokens = [...parsed.ips, ...parsed.hosts];
    const params = lookupParams(input.value);
    ctx.setParams(params);
    const one = commonTarget(tokens);
    ctx.runStarted(one ? one.value : null);
    run(parsed, null, { text: input.value });
  }

  /** The addresses and host names of an input, as a run reads them. */
  const entriesOf = (text) => {
    const p = parseIpInput(text);
    return [...p.ips, ...p.hosts];
  };

  /** The route params of a run's input: its addresses and host names, at most 40 (else none). */
  function lookupParams(text) {
    const tokens = entriesOf(text);
    return { ips: tokens.length && tokens.length <= 40 ? tokens.join(',') : null };
  }

  /**
   * The address the box last took from a carried target: a newer one replaces it while the box
   * still holds it (lib/session.js fillReplaces). A re-mount keeps it (snapshot); a run forgets it.
   */
  let carried = restored ? (typeof restored.carried === 'string' ? restored.carried : null)
    : (isFillOnly(ctx.params) && initialText) || null;

  /**
   * An address carried over from another tool (`run=0`) goes into the box while it is empty or
   * still holds the finished run's entries or the address carried before — never over a draft —
   * and nothing is looked up; the rows stay.
   */
  function takeCarried(text) {
    const last = current && !current.controller ? entriesOf(current.text) : null;
    if (fillReplaces(input.value, last, entriesOf, carried)) {
      input.value = text;
      input.setError(null);
      updateParsed();
      carried = text;
    }
  }

  /**
   * Look up every address of `parsed`, or show `preset` rows (a kept or re-mounted run: no
   * network, the servers matched again). `text`: the input the run was made from; `at`: when a
   * preset run finished (the summary's time); `stopped`: a preset run was stopped.
   */
  async function run(parsed, preset = null, { text = '', at = null, stopped = false } = {}) {
    if (current && current.controller) current.controller.abort();
    if (current) current.life.abort();
    const controller = new AbortController();
    // `life` cancels this run's Retries (a new run, Stop, the view going away).
    const state = { controller, life: new AbortController(), rows: [], stopped: false, text, finishedAt: null, resolving: false };
    current = state;
    emptyEl.hidden = true;
    results.hidden = false;
    clear(notesEl);
    sourcesEl.hidden = true;
    setFilter(null);
    if (parsed.invalid.length) note('warn', t('ipi.invalid', { items: parsed.invalid.slice(0, 12).join(', ') + (parsed.invalid.length > 12 ? ' …' : '') }));
    if (parsed.cidrs.length) note('info', t('ipi.cidr', { range: parsed.cidrs[0] }));
    table.setRows([]);
    renderActions(lookupParams(text));

    if (preset) {
      state.rows = preset.map((r) => ({ ...r, servers: serversOf(r.ip) }));
      table.setRows(state.rows);
      state.controller = null;
      state.finishedAt = at ? new Date(at) : new Date();
      // A lookup stopped before a re-mount still says so (its summary does too).
      state.stopped = !!stopped;
      if (state.stopped) note('info', t('ipi.stopped'));
      renderStats(state.rows);
      renderHead();
      syncRunBar();
      return;
    }

    const signal = mergeSignals(ctx.signal, controller.signal);
    progress.setVariant('default');
    progress.setLabel(t('ipi.looking'));
    progress.set(0, 1);
    renderStats([]);
    renderHead();
    setRunning(true);
    try {
      // The range dataset's network tier names the operator of a direct address at once (lib/networklabel.js):
      // wait for its one load per page. A failed load leaves the built-in table, and only the AS-based hint.
      await loadRanges({ signal });
      const dns = await ctx.getDns();
      const byIp = new Map();
      const addIp = (ip, host = null, cnames = []) => {
        if (byIp.size >= MAX_IPS && !byIp.has(ip)) return false;
        let row = byIp.get(ip);
        if (!row) {
          row = makeRow(ip);
          byIp.set(ip, row);
        }
        if (host && !row.hosts.includes(host)) row.hosts.push(host);
        if (cnames.length && row.classification.kind === 'direct') row.classification = classifyIp(ip, cnames);
        return true;
      };
      let truncated = false;
      for (const ip of parsed.ips) if (!addIp(ip)) truncated = true;

      // 1) host names → addresses
      const hosts = parsed.hosts.slice(0, MAX_HOSTS);
      if (parsed.hosts.length > MAX_HOSTS) note('warn', t('ipi.hostsTruncated', { max: MAX_HOSTS }));
      if (hosts.length) {
        state.resolving = true;
        renderHead();
        progress.setLabel(t('ipi.resolving'));
        progress.set(0, hosts.length);
        let done = 0;
        const failed = [];
        await Promise.all(hosts.map(async (host) => {
          const res = await dns.resolveHost(host, { signal });
          done += 1;
          progress.set(done, hosts.length);
          const addrs = [...res.ipv4, ...res.ipv6];
          if (!addrs.length) failed.push(`${host} (${res.status === 'NOERROR' ? 'NODATA' : res.status})`);
          for (const ip of addrs) if (!addIp(ip, host, res.cnames)) truncated = true;
        }));
        if (failed.length) note('warn', t('ipi.hostFailed', { items: failed.join(', ') }));
        state.resolving = false;
      }
      if (truncated) note('warn', t('ipi.truncated', { max: MAX_IPS }));

      // 2) intel per address (the service limits concurrency and caches)
      state.rows = [...byIp.values()];
      table.setRows(state.rows);
      renderStats(state.rows);
      renderHead();
      const intel = getIntel(dns);
      progress.setLabel(t('ipi.looking'));
      progress.set(0, state.rows.length);
      let done = 0;
      let lastStats = 0;
      await Promise.all(state.rows.map(async (row) => {
        const info = await intel.info(row.ip, { signal });
        if (current !== state) return;
        row.info = info;
        row.pending = false;
        table.updateRow(row);
        done += 1;
        progress.set(done, state.rows.length);
        if (Date.now() - lastStats > 250 || done === state.rows.length) {
          lastStats = Date.now();
          renderStats(state.rows);
        }
      }));
      if (current === state) progress.done(t('ipi.done'));
    } catch (err) {
      if (current !== state) return;
      if (err && err.name === 'AbortError') {
        if (state.stopped) note('info', t('ipi.stopped'));
      } else {
        ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      }
    } finally {
      if (current === state) {
        state.controller = null;
        state.resolving = false;
        state.finishedAt = new Date();
        for (const row of state.rows) {
          if (row.pending) {
            row.pending = false;
            table.updateRow(row);
          }
        }
        renderStats(state.rows);
        renderHead();
        if (!ctx.signal.aborted) setRunning(false);
        // The totals, said once (the status summary is not a live region).
        if (!ctx.signal.aborted && state.rows.length && !state.stopped) announce([t('ipi.resultsTitle', { count: state.rows.length }), ...statusLine].join(' · '));
      }
    }
  }

  /* --- Domains on this IP (ui/reverse-ip-panel.js, loaded on first use) ------------------ */
  let reversePanel = null;

  /** What the workspace knows of an address: the servers holding it, the origin map entries at it. */
  function workspaceFor(ip) {
    const servers = serversOf(ip).map((s) => s.name);
    const { map } = originIndex(ctx.state.workspaceData('origins'));
    const origins = (map ? map.entries : []).filter((e) => e.ip === ip && !e.stale).map((e) => ({ name: e.name, first: e.firstSeen, last: e.lastConfirmed }));
    return { servers, origins };
  }

  /** An address's names as the panel found them, into its row's cell (and the export). */
  function onNames(ip, names, st) {
    if (!current) return;
    for (const row of current.rows.filter((x) => x.ip === ip)) {
      row.reverse = st === 'idle' ? null : st === 'loading' ? { state: 'loading', result: null }
        : { state: 'done', result: { ok: st === 'done', domains: names || [], error: st === 'done' ? null : 'failed', limited: false } };
      table.updateRow(row);
    }
  }

  /** The panel, created once (null when the view went away while it loaded). */
  async function ensureReversePanel() {
    if (reversePanel) return reversePanel;
    // A failed import (a tab left open across a deploy): the shell offers a reload (views/subdomains.js loadOnFirstUse).
    const mod = await loadReversePanel().catch((err) => {
      ctx.checkOutdated();
      throw err;
    });
    if (ctx.signal.aborted) return null;
    if (!reversePanel) {
      reversePanel = mod.ReverseIpPanel({ ctx, getIntel: async () => getIntel(await ctx.getDns()), workspaceFor, onNames });
      reverseHost.append(reversePanel.el);
    }
    return reversePanel;
  }

  /** Domains on this IP for `ips`, scrolled to; `run`: look them up, else only fill them in. */
  async function openReverse(ips, { run = true } = {}) {
    let panel;
    try {
      panel = await ensureReversePanel();
    } catch {
      ctx.toast(t('ipi.rev.loadFailed'), { type: 'error' });
      return;
    }
    if (!panel) return;
    reverseHost.hidden = false;
    reverseHost.scrollIntoView({ block: 'start', behavior: scrollBehavior() });
    panel.focus();
    if (run) await panel.lookup(ips.slice(0, MAX_REVERSE));
    else panel.fill(ips.slice(0, MAX_REVERSE));
  }

  /* --- initial state ---------------------------------------------------------------- */
  updateParsed();
  if (restored && restored.reverse) {
    // Domains on this IP as it was before a re-mount: shown again, nothing sent.
    ensureReversePanel().then((panel) => {
      if (!panel) return;
      panel.restore(restored.reverse);
      reverseHost.hidden = false;
    }).catch(() => {});
  }
  if (restored && Array.isArray(restored.rows) && restored.rows.length) {
    const text = restored.query ?? restored.text ?? '';
    run(parseIpInput(text), restored.rows, { text, at: restored.at, stopped: restored.stopped });
    // The kept rows under an address carried over from another tool: the box takes the address.
    if (isFillOnly(ctx.params) && paramText) takeCarried(splitList(paramText).join('\n'));
  } else if (paramText && !isFillOnly(ctx.params)) {
    // Shared link: run immediately; an address carried over from another tool (`run=0`) only
    // fills the box.
    Promise.resolve().then(() => start({ auto: true })); // a shared link: run on arrival
  }

  active = {
    teardown() {
      if (current && current.controller) current.controller.abort();
      if (current) current.life.abort();
    },
    snapshot() {
      // A reverse lookup still running belongs to this view and is cancelled with it: the
      // re-mounted row offers the button again instead of a spinner nothing would ever stop.
      // A Retry in flight is cancelled the same way: the re-mounted row offers it again.
      const rows = current && !current.controller
        ? current.rows.map((r) => ({ ...r, retrying: false, reverse: r.reverse && r.reverse.state === 'loading' ? null : r.reverse }))
        : null;
      return {
        text: input.value, carried, rows, query: rows ? current.text : null, at: rows ? current.finishedAt : null, stopped: !!(rows && current.stopped),
        // Domains on this IP: its finished lookup (never a typed key).
        reverse: reversePanel ? reversePanel.snapshot() : null
      };
    },
    result() {
      if (!current || current.controller || !current.finishedAt || !current.rows.length) return null;
      const one = commonTarget(current.rows.map((r) => r.ip));
      return { subject: one ? one.value : current.rows[0].ip, at: current.finishedAt, params: lookupParams(current.text) };
    },
    rerun() {
      if (current && current.text) {
        input.value = current.text;
        updateParsed();
      }
      start();
    },
    update(params) {
      const text = [params.ips, params.ip, params.q].filter(Boolean).join('\n');
      if (!text) return false;
      if (isFillOnly(params)) {
        takeCarried(splitList(text).join('\n'));
        return true;
      }
      input.value = splitList(text).join('\n');
      updateParsed();
      start();
      return true;
    }
  };
}

/** Abort running lookups. */
export function unmount() {
  if (active) active.teardown();
  active = null;
}

/**
 * Input text and finished rows carried over a language re-mount and kept for the next visit.
 * @returns {object|null}
 */
export function snapshot() {
  return active ? active.snapshot() : null;
}

/**
 * The finished rows on screen (kept by the shell when the view is left), or null.
 * @returns {{ subject: string, at: Date }|null}
 */
export function result() {
  return active ? active.result() : null;
}

/** "Run again" of the kept-result note: the same addresses again. */
export function rerun() {
  if (active) active.rerun();
}

/**
 * Take new route params (e.g. `#/ip?ips=…` from another view) without a re-mount.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, snapshot, result, rerun, update };
