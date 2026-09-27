/**
 * views/ip.js — "IP Intel": paste IP addresses (and/or host names, which are resolved first)
 * and get, per address: reverse DNS (PTR), origin ASN and AS holder, announced prefix,
 * country / city, the CDN / platform that operates it (Cloudflare, Fastly …), whether it is
 * private, and which of the user's servers (inventory) owns it. A per-row "reverse IP"
 * button lists other domains on the address (HackerTarget; small shared daily quota).
 *
 * Data: lib/ipintel.js (RIPEstat + ipwho.is fallback + DoH PTR). Private addresses never
 * leave the browser. Results stream into the table; CSV/JSON export.
 *
 * "Copy summary" above the stat cards: one line for Jira / Slack (lib/summary.js) with the time the
 * lookup ended; it says how many addresses are in the server list (never a server's name, the
 * tooltip says so), how many lookups failed (the rows showing "Lookup failed") and how many
 * addresses a stopped lookup never reached, and its link leaves out private and inventory addresses.
 *
 * No silent dashes (lib/sourcestatus.js, ui/source-status.js): a cell that a failed source left
 * empty says "⚠ n/a" with the source and the reason, a chip per service sums the failures up,
 * and Retry (per row, or per chip for every row it failed on) asks only those sources again.
 * Stat cards whose count is zero fold into one sentence (lib/density.js).
 *
 * Shareable: `#/ip?ips=8.8.8.8,1.1.1.1` (also `ip=` / `q=`; host names allowed) runs on open;
 * with `run=0` (an address carried over from another tool, lib/session.js) it is only filled in.
 * The finished rows are kept for the page session (`result()` / `snapshot()`); coming back
 * matches them against the servers as they are then.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CopyButton, DataTable, EmptyState, ExternalLink, KeyValueList, KindBadge, ProgressBar, StatCard,
  TruncatedList, announce, ipSortValue, setButtonBusy, textarea
} from '../ui/components.js';
import { registerStrings, formatNumber, formatRegion, localeTag } from '../i18n.js';
import { createIpIntel, networkHint } from '../lib/ipintel.js';
import { ipFieldStatus, ipRetrySources, ipSourceChips, sourceStatus, IP_FIELDS } from '../lib/sourcestatus.js';
import { foldZeroStats } from '../lib/density.js';
import { NaMark, RetryButton, SourceChip, setRetryBusy, statusText } from '../ui/source-status.js';
import { classifyResolution, ipVersion, isPrivateIP, normalizeIP } from '../lib/netinfo.js';
import { normalizeHostname } from '../lib/domain.js';
import { lookupServers } from '../lib/inventory.js';
import { Flag } from '../ui/flag.js';
import { mergeSignals, splitList } from '../lib/util.js';
import { commonTarget, fillReplaces, isFillOnly } from '../lib/session.js';
import { permalinkParams } from '../lib/summary.js';
import { SummaryButton } from '../ui/summary-button.js';

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

const EXAMPLE = '8.8.8.8\n1.1.1.1\n2606:4700:4700::1111\n9.9.9.9\ngithub.com\n';

registerStrings('en', {
  'ipi.inputLabel': 'IP addresses or host names',
  'ipi.placeholder': '8.8.8.8\n1.1.1.1\n2606:4700::1111\nwww.example.com   ← host names are resolved first',
  'ipi.inputHint': 'One per line, or separated by spaces/commas. Ports and [brackets] are fine; # starts a comment.',
  'ipi.run': 'Look up',
  'ipi.stop': 'Stop',
  'ipi.example': 'Example',
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
  'ipi.emptyTitle': 'Who is behind an IP address?',
  'ipi.emptyBody': 'Reverse DNS, network owner (ASN), location, CDN/cloud detection and your own servers — for up to {max} addresses at once.',

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
  'ipi.rev.limited': 'Daily quota used up',
  'ipi.rev.limitedTitle': 'HackerTarget’s free quota (about 50 lookups a day, shared with the SSL Targets scan) is used up. Try again tomorrow.',
  'ipi.rev.failed': 'Failed',
  'ipi.rev.private': 'not for private IPs',
  'ipi.quota': 'Reverse IP lookups use HackerTarget’s free API: about 50 per day from your IP address, shared with the SSL Targets scan. Use the button only where you need it.',

  'ipi.det.rir': 'Registry (RIR)',
  'ipi.det.announced': 'Announced on the Internet',
  'ipi.det.asns': 'Origin AS',
  'ipi.det.sources': 'Data sources',
  'ipi.det.errors': 'Problems',
  'ipi.det.provider': 'Provider',
  'ipi.det.links': 'Open elsewhere',
  'ipi.det.hosts': 'Host names you entered',
  'ipi.det.network': 'Network',

  'ipi.net.badge': '{name} network',
  'ipi.net.short.outside-proxy-ranges': 'AS{asn} · not a proxied-site range',
  'ipi.net.short.cdn-edge': 'AS{asn} · probably a CDN edge',
  'ipi.net.short.hosted': 'AS{asn} · {category}',
  'ipi.net.long.outside-proxy-ranges': 'This address is on {name}’s own network (AS{asn}) but outside the ranges {name} publishes for the websites it proxies — so it is one of {name}’s own services (1.1.1.1, for example, is a DNS resolver), not a website hidden behind {name}.',
  'ipi.net.long.cdn-edge': 'Announced by {name} (AS{asn}), a CDN / security proxy that publishes no list of its edge addresses — most likely an edge server in front of a website whose own server is hidden.',
  'ipi.net.long.hosted': 'Announced by {name} (AS{asn}): a server or service on {name}’s network, reached directly with no CDN in front.',
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
  'ipi.example': 'Örnek',
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
  'ipi.emptyTitle': 'Bir IP adresinin arkasında kim var?',
  'ipi.emptyBody': 'Ters DNS, ağ sahibi (ASN), konum, CDN/bulut tespiti ve kendi sunucularınız — tek seferde {max} adrese kadar.',

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
  'ipi.rev.limited': 'Günlük kota doldu',
  'ipi.rev.limitedTitle': 'HackerTarget’ın ücretsiz kotası (günde yaklaşık 50 sorgu, SSL Hedefleri taramasıyla ortak) doldu. Yarın tekrar deneyin.',
  'ipi.rev.failed': 'Başarısız',
  'ipi.rev.private': 'özel IP’ler için yapılmaz',
  'ipi.quota': 'Ters IP sorguları HackerTarget’ın ücretsiz API’sini kullanır: IP adresiniz başına günde yaklaşık 50 sorgu, SSL Hedefleri taramasıyla ortak. Düğmeyi yalnızca gerektiğinde kullanın.',

  'ipi.det.rir': 'Kayıt kuruluşu (RIR)',
  'ipi.det.announced': 'İnternet’te duyuruluyor',
  'ipi.det.asns': 'Kaynak AS',
  'ipi.det.sources': 'Veri kaynakları',
  'ipi.det.errors': 'Sorunlar',
  'ipi.det.provider': 'Sağlayıcı',
  'ipi.det.links': 'Başka yerde aç',
  'ipi.det.hosts': 'Girdiğiniz host adları',
  'ipi.det.network': 'Ağ',

  'ipi.net.badge': '{name} ağı',
  'ipi.net.short.outside-proxy-ranges': 'AS{asn} · proxy’li site aralığı değil',
  'ipi.net.short.cdn-edge': 'AS{asn} · büyük olasılıkla CDN kenar sunucusu',
  'ipi.net.short.hosted': 'AS{asn} · {category}',
  'ipi.net.long.outside-proxy-ranges': 'Bu adres {name} ağına (AS{asn}) ait, ancak {name} tarafından proxy’lenen web siteleri için yayımlanan aralıkların dışında — yani bir {name} hizmeti (örneğin 1.1.1.1 bir DNS çözümleyicisidir), arkasına gizlenmiş bir web sitesi değil.',
  'ipi.net.long.cdn-edge': '{name} (AS{asn}) tarafından duyuruluyor: kenar sunucu adreslerini yayımlamayan bir CDN / güvenlik proxy’si — büyük olasılıkla, asıl sunucusu gizlenmiş bir web sitesinin önündeki kenar sunucusu.',
  'ipi.net.long.hosted': '{name} (AS{asn}) tarafından duyuruluyor: {name} ağında, önünde CDN olmadan doğrudan erişilen bir sunucu ya da hizmet.',
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

function getIntel(dns) {
  if (!intelService || intelDns !== dns) {
    intelService = createIpIntel({ dns, concurrency: 4 });
    intelDns = dns;
  }
  return intelService;
}

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
  /** Well-known network behind a plain 'direct' address (display only, see ipintel.networkHint). */
  const hintOf = (r) => (r.info ? networkHint(r.info, r.classification) : null);
  const hintText = (hint) => ({
    badge: t('ipi.net.badge', { name: hint.name }),
    short: t(`ipi.net.short.${hint.relation}`, { asn: hint.asn, category: t(`ipi.net.cat.${hint.category}`) }),
    long: t(`ipi.net.long.${hint.relation}`, { name: hint.name, asn: hint.asn })
  });

  /* --- input ----------------------------------------------------------------------- */
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
  const runBtn = Button({ label: t('ipi.run'), icon: 'search', variant: 'primary', dataset: { action: 'run', shortcut: 'submit' }, onClick: () => start() });
  const stopBtn = Button({ label: t('ipi.stop'), icon: 'stop', dataset: { action: 'stop', shortcut: 'cancel' }, onClick: () => stop() });
  stopBtn.hidden = true;
  const exampleBtn = Button({
    label: t('ipi.example'), icon: 'file-text', variant: 'ghost', size: 'sm', dataset: { action: 'example' },
    onClick: () => {
      input.value = EXAMPLE;
      updateParsed();
    }
  });
  const inventoryIps = () => [...new Set(ctx.state.inventory.servers.flatMap((s) => s.ips))];
  const inventoryBtn = Button({
    label: t('ipi.fromInventory'), icon: 'server', variant: 'ghost', size: 'sm', title: t('ipi.fromInventoryTitle'), dataset: { action: 'inventory' },
    onClick: () => {
      input.value = `${inventoryIps().join('\n')}\n`;
      updateParsed();
    }
  });
  inventoryBtn.hidden = inventoryIps().length === 0;
  const clearBtn = Button({
    label: t('ipi.clear'), icon: 'trash', variant: 'ghost', size: 'sm',
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
  }
  input.input.addEventListener('input', updateParsed);
  updateParsed();

  const formCard = Card({
    className: 'ipi-form-card',
    children: h('div', { class: 'stack' },
      input.el,
      h('div', { class: 'ipi-actions' },
        h('div', { class: 'cluster' }, exampleBtn, inventoryBtn, clearBtn, parsedEl),
        h('div', { class: 'cluster ipi-run' }, stopBtn, runBtn)),
      h('p', { class: 'muted text-xs ipi-privacy' }, t('ipi.privacy')))
  });

  /* --- results ------------------------------------------------------------------------- */
  const progress = ProgressBar({ label: t('ipi.looking') });
  progress.el.hidden = true;
  const notesEl = h('div', { class: 'stack-sm ipi-notes' });
  const stats = {
    ips: StatCard({ label: t('ipi.stat.ips'), icon: 'network', variant: 'accent' }),
    cdn: StatCard({ label: t('ipi.stat.cdn'), icon: 'cloud', variant: 'cloudflare' }),
    mine: StatCard({ label: t('ipi.stat.mine'), icon: 'server', variant: 'direct' }),
    priv: StatCard({ label: t('ipi.stat.private'), icon: 'lock', variant: 'private' }),
    nets: StatCard({ label: t('ipi.stat.networks'), icon: 'layers' }),
    countries: StatCard({ label: t('ipi.stat.countries'), icon: 'map-pin' })
  };

  const exportOpts = {
    filename: 'ip-intel',
    json: (rows) => rows.map((r) => ({
      ip: r.ip,
      version: ipVersion(r.ip),
      hosts: r.hosts,
      private: isPrivateIP(r.ip),
      operator: r.classification.provider ? r.classification.provider.name : r.classification.kind,
      network: (() => {
        const hint = hintOf(r);
        return hint ? { id: hint.id, name: hint.name, asn: hint.asn, category: hint.category, relation: hint.relation } : null;
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
    }))
  };
  /** CSV text of a cell: its value, or "n/a" when a failed source left it empty. */
  const csvValue = (r, field, value) => (value ? value : ipFieldStatus(r.info, field) ? t('srcst.na') : '');

  const table = DataTable({
    caption: t('nav.ip'),
    rowKey: (r) => r.ip,
    search: true,
    dense: true,
    pageSize: 100,
    export: exportOpts,
    rowClass: (r) => ['ipi-row', { 'is-pending': r.pending }],
    details: (r) => renderDetails(r),
    columns: [
      {
        key: 'ip', label: t('ipi.col.ip'), sortable: true, sortValue: (r) => ipSortValue(r.ip),
        searchValue: (r) => [r.ip, ...r.hosts].join(' '), exportValue: (r) => r.ip,
        render: (r) => h('div', { class: 'ipi-ipcell' },
          h('span', { class: 'mono ipi-ip' }, r.ip),
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
          return hint ? `${base} · ${hintText(hint).badge} (AS${hint.asn})` : base;
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
    ]
  });

  const quotaNote = Alert({ variant: 'info', compact: true, icon: 'info', message: t('ipi.quota') });
  for (const [key, card] of Object.entries(stats)) card.el.dataset.stat = key;
  const statsGrid = h('div', { class: 'stat-grid ipi-stats' }, stats.ips, stats.cdn, stats.mine, stats.priv, stats.nets, stats.countries);
  // Zero counts of these fold into one sentence (ipi.zero); networks and countries grow while lookups run.
  const zeroNote = h('p', { class: 'muted text-sm ipi-zero', hidden: true });
  const sourcesEl = h('div', { class: 'src-chips ipi-sources', hidden: true, attrs: { role: 'group', 'aria-label': t('ipi.det.sources'), tabindex: -1 } });
  const emptyEl = h('div', { class: 'card ipi-empty' }, EmptyState({ icon: 'network', title: t('ipi.emptyTitle'), message: t('ipi.emptyBody', { max: formatNumber(MAX_IPS) }) }));
  // No part of the form: Ctrl/Cmd+Enter in the table's filter starts no new run.
  // "Copy summary": one line (lib/summary.js); the link leaves out private and inventory addresses.
  const summary = SummaryButton({
    kind: 'ip',
    disabled: true,
    inventory: 'count',
    facts: () => (current && !current.controller && current.rows.length ? { rows: current.rows, at: current.finishedAt, stopped: current.stopped } : null),
    url: () => ctx.shareUrl(permalinkParams('ip', ctx.params, {
      exclude: [...ctx.getInventoryIndex().keys(), ...(current ? current.rows.filter((r) => r.servers.length).map((r) => r.ip) : [])]
    }))
  });
  const results = h('div', { class: 'stack ipi-results', hidden: true, dataset: { shortcutScope: 'results' } },
    progress, notesEl, h('div', { class: 'ipi-results-bar' }, summary.el), statsGrid, zeroNote, quotaNote, sourcesEl, table);
  container.append(h('div', { class: 'stack-lg ipi-view' }, formCard, emptyEl, results));

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
    const btn = RetryButton({ sources, onClick: () => retryRows([r]), dataset: { ip: r.ip } });
    btn.classList.add('ipi-retry');
    if (r.retrying) setRetryBusy(btn);
    return btn;
  }

  /** Operator cell: the classification badge, or for plain 'direct' addresses on a well-known
   *  network (1.1.1.1 → AS13335) a badge naming that network plus a one-line explanation. */
  function renderOperator(r) {
    const hint = hintOf(r);
    if (!hint) return KindBadge(r.classification);
    const text = hintText(hint);
    const edge = hint.relation === 'cdn-edge';
    const badge = Badge(text.badge, { variant: edge ? 'cdn' : 'direct', icon: edge ? 'zap' : (hint.category === 'hosting' ? 'server' : 'cloud'), title: text.long });
    badge.dataset.kind = r.classification.kind;
    return h('div', { class: 'ipi-op', dataset: { network: hint.id, relation: hint.relation } },
      badge, h('span', { class: 'muted text-xs ipi-op-note' }, text.short));
  }

  function pendingCell() {
    return h('span', { class: 'ipi-pending' }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), t('ipi.pending'));
  }

  function renderReverse(r) {
    if (isPrivateIP(r.ip)) return h('span', { class: 'muted text-xs' }, t('ipi.rev.private'));
    const rev = r.reverse;
    if (!rev || rev.state === 'loading') {
      const btn = Button({
        label: t('ipi.rev.button'), icon: 'search', size: 'sm', variant: 'secondary', dataset: { action: 'reverse', ip: r.ip },
        onClick: () => reverseLookup(r)
      });
      if (rev && rev.state === 'loading') setButtonBusy(btn, true);
      return btn;
    }
    const res = rev.result;
    if (res.ok) {
      return h('div', { class: 'ipi-rev', dataset: { state: 'done', count: res.domains.length } },
        Badge(t('ipi.rev.count', { count: res.domains.length }), { variant: res.domains.length ? 'accent' : 'neutral', icon: 'globe' }),
        res.domains.length ? TruncatedList(res.domains, { max: 5, render: hostLink }) : null);
    }
    if (res.limited) {
      return h('div', { class: 'ipi-rev', dataset: { state: 'limited' } }, Badge(t('ipi.rev.limited'), { variant: 'warn', icon: 'alert', title: t('ipi.rev.limitedTitle') }));
    }
    const st = sourceStatus({ source: 'hackertarget', error: res.error, errorKind: res.errorKind });
    return h('div', { class: 'ipi-rev', dataset: { state: 'error' } },
      Badge(t('ipi.rev.failed'), { variant: 'error', icon: 'x-circle', title: statusText(st) }),
      RetryButton({ sources: ['hackertarget'], onClick: () => reverseLookup(r) }));
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
    return KeyValueList(items, { className: 'ipi-details' });
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

  function renderStats(rows) {
    const v6 = rows.filter((r) => ipVersion(r.ip) === 6).length;
    stats.ips.set({ value: rows.length, hint: t('ipi.stat.ipsHint', { v4: formatNumber(rows.length - v6), v6: formatNumber(v6) }) });
    const cdn = rows.filter((r) => r.classification.hidesOrigin);
    const names = [...new Set(cdn.map((r) => r.classification.provider.name))];
    stats.cdn.set({ value: cdn.length, hint: names.slice(0, 3).join(', ') || null });
    const mine = rows.filter((r) => r.servers.length);
    stats.mine.set({ value: mine.length, hint: mine.length ? [...new Set(mine.flatMap((r) => r.servers.map((s) => s.name)))].slice(0, 3).join(', ') : null });
    stats.priv.set({ value: rows.filter((r) => isPrivateIP(r.ip)).length });
    const asns = new Set(rows.map((r) => r.info && r.info.asn).filter(Boolean));
    stats.nets.set({ value: asns.size });
    const countries = [...new Set(rows.map((r) => r.info && r.info.country).filter(Boolean))];
    stats.countries.set({ value: countries.length, hint: countries.slice(0, 6).join(' ') || null });
    // Zero counts fold into one muted sentence (never the address count, nor the networks and
    // countries, which are still growing while lookups run).
    const { folded } = foldZeroStats([
      { id: 'ips', value: rows.length }, { id: 'cdn', value: cdn.length }, { id: 'mine', value: mine.length },
      { id: 'priv', value: rows.filter((r) => isPrivateIP(r.ip)).length }
    ], { foldable: rows.length ? ['cdn', 'mine', 'priv'] : [] });
    for (const [key, card] of Object.entries(stats)) card.el.hidden = folded.includes(key);
    // "one of your servers" only when there is a server list to match against.
    const parts = folded.filter((id) => id !== 'mine' || ctx.state.inventory.servers.length).map((id) => t(`ipi.zero.${id}`));
    zeroNote.hidden = !parts.length;
    zeroNote.textContent = parts.length ? t('ipi.zero', { count: rows.length, list: listText(parts) }) : '';
    renderSources(rows);
  }

  /** "a, b or c" in the UI language. */
  function listText(parts) {
    try {
      return new Intl.ListFormat(localeTag(), { type: 'disjunction' }).format(parts);
    } catch {
      return parts.join(', ');
    }
  }

  /** One chip per service: where its failures left fields empty, with a Retry of those rows. */
  function renderSources(rows) {
    const looked = rows.some((r) => !isPrivateIP(r.ip));
    // A chip's Retry that had the keyboard focus gets it back, or the group when that Retry is gone.
    const focused = sourcesEl.contains(globalThis.document.activeElement) ? globalThis.document.activeElement.dataset.chip || '' : null;
    sourcesEl.hidden = !looked;
    clear(sourcesEl);
    if (!looked) return;
    for (const chip of ipSourceChips(rows)) {
      const failedRows = rows.filter((r) => chip.ips.includes(r.ip));
      sourcesEl.append(SourceChip(chip, {
        onRetry: () => retryRows(failedRows, chip.sources),
        busy: failedRows.some((r) => r.retrying)
      }));
    }
    if (focused !== null) (sourcesEl.querySelector(`[data-chip="${focused}"]`) || sourcesEl).focus();
  }

  /**
   * Ask again, for each row, only the sources that failed there (and are in `sources`, when a
   * chip's Retry names them); the rows re-render as their answers arrive.
   */
  async function retryRows(list, sources = null) {
    const state = current;
    const rows = list.filter((r) => r.info && !r.retrying);
    if (!state || !rows.length) return;
    for (const r of rows) {
      r.retrying = true;
      table.updateRow(r);
    }
    renderSources(state.rows);
    let intel = null;
    try {
      intel = getIntel(await ctx.getDns());
    } catch (err) {
      ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    }
    await Promise.all(rows.map(async (r) => {
      try {
        if (!intel) return;
        const want = ipRetrySources(r.info).filter((s) => !sources || sources.includes(s));
        r.info = await intel.retry(r.info, { sources: want, signal: ctx.signal });
      } catch (err) {
        if (!(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      } finally {
        r.retrying = false;
        if (!ctx.signal.aborted) table.updateRow(r);
      }
    }));
    if (ctx.signal.aborted || current !== state) return;
    renderStats(state.rows);
    announce(t('ipi.retried', { count: rows.length }));
  }

  function note(variant, message) {
    notesEl.append(Alert({ variant, compact: true, message }));
  }

  function setRunning(on) {
    runBtn.hidden = on;
    stopBtn.hidden = !on;
    input.input.readOnly = on;
    summary.setDisabled(on || !(current && current.rows.length));
    ctx.setBusy(on ? t('ipi.looking') : false);
  }

  function stop() {
    if (current && current.controller) {
      current.stopped = true;
      current.controller.abort();
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
    setShareAction(params);
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
   * "Copy link" in the page header when a link can carry the run's addresses (at most 40 of
   * them), after a run and again for a run restored by a re-mount: the run on screen, not the box,
   * which may hold a carried address.
   */
  function setShareAction(params) {
    if (params.ips) ctx.setActions(CopyButton(() => ctx.shareUrl(params), { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }));
    else ctx.setActions();
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
    const controller = new AbortController();
    const state = { controller, rows: [], stopped: false, text, finishedAt: null };
    current = state;
    emptyEl.hidden = true;
    results.hidden = false;
    clear(notesEl);
    zeroNote.hidden = true;
    sourcesEl.hidden = true;
    if (parsed.invalid.length) note('warn', t('ipi.invalid', { items: parsed.invalid.slice(0, 12).join(', ') + (parsed.invalid.length > 12 ? ' …' : '') }));
    if (parsed.cidrs.length) note('info', t('ipi.cidr', { range: parsed.cidrs[0] }));
    table.setRows([]);

    if (preset) {
      state.rows = preset.map((r) => ({ ...r, servers: serversOf(r.ip) }));
      table.setRows(state.rows);
      renderStats(state.rows);
      state.controller = null;
      state.finishedAt = at ? new Date(at) : new Date();
      // A lookup stopped before a re-mount still says so (its summary does too).
      state.stopped = !!stopped;
      if (state.stopped) note('info', t('ipi.stopped'));
      summary.setDisabled(!preset.length);
      return;
    }

    const signal = mergeSignals(ctx.signal, controller.signal);
    setRunning(true);
    progress.el.hidden = false;
    progress.setVariant('default');
    try {
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
      }
      if (truncated) note('warn', t('ipi.truncated', { max: MAX_IPS }));

      // 2) intel per address (the service limits concurrency and caches)
      state.rows = [...byIp.values()];
      table.setRows(state.rows);
      renderStats(state.rows);
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
        if (state.stopped) {
          note('info', t('ipi.stopped'));
          progress.setVariant('warn');
        }
      } else {
        ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      }
    } finally {
      if (current === state) {
        state.controller = null;
        state.finishedAt = new Date();
        for (const row of state.rows) {
          if (row.pending) {
            row.pending = false;
            table.updateRow(row);
          }
        }
        renderStats(state.rows);
        if (!ctx.signal.aborted) setRunning(false);
        setTimeout(() => { if (current === state && !state.controller && !state.stopped) progress.el.hidden = true; }, 900);
      }
    }
  }

  async function reverseLookup(row) {
    if (!ctx.requireOnline()) return;
    row.reverse = { state: 'loading', result: null };
    table.updateRow(row);
    try {
      const dns = await ctx.getDns();
      const result = await getIntel(dns).reverseIp(row.ip, { signal: ctx.signal });
      row.reverse = { state: 'done', result };
    } catch (err) {
      if (err && err.name === 'AbortError') {
        row.reverse = null; // cancelled with the view: the button is offered again
        return;
      }
      row.reverse = { state: 'done', result: { ok: false, domains: [], error: err && err.message ? err.message : String(err), limited: false } };
    }
    table.updateRow(row);
  }

  /* --- initial state ---------------------------------------------------------------- */
  if (restored && Array.isArray(restored.rows) && restored.rows.length) {
    const text = restored.query ?? restored.text ?? '';
    run(parseIpInput(text), restored.rows, { text, at: restored.at, stopped: restored.stopped });
    setShareAction(lookupParams(text));
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
    },
    snapshot() {
      // A reverse lookup still running belongs to this view and is cancelled with it: the
      // re-mounted row offers the button again instead of a spinner nothing would ever stop.
      // A Retry in flight is cancelled the same way: the re-mounted row offers it again.
      const rows = current && !current.controller
        ? current.rows.map((r) => ({ ...r, retrying: false, reverse: r.reverse && r.reverse.state === 'loading' ? null : r.reverse }))
        : null;
      return { text: input.value, carried, rows, query: rows ? current.text : null, at: rows ? current.finishedAt : null, stopped: !!(rows && current.stopped) };
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
