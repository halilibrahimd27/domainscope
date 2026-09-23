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
 * Shareable: `#/ip?ips=8.8.8.8,1.1.1.1` (also `ip=` / `q=`; host names allowed) runs on open.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CopyButton, DataTable, EmptyState, ExternalLink, KeyValueList, KindBadge, ProgressBar, StatCard,
  TruncatedList, ipSortValue, setButtonBusy, textarea
} from '../ui/components.js';
import { registerStrings, hasString, formatNumber, formatRegion } from '../i18n.js';
import { createIpIntel } from '../lib/ipintel.js';
import { classifyResolution, ipVersion, isPrivateIP, normalizeIP } from '../lib/netinfo.js';
import { normalizeHostname } from '../lib/domain.js';
import { lookupServers } from '../lib/inventory.js';
import { flagEmoji } from '../lib/resolvers.js';
import { mergeSignals, splitList } from '../lib/util.js';

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

const EXAMPLE = '8.8.8.8\n1.1.1.1\n2606:4700:4700::1111\n85.105.1.1\ngithub.com\n';

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
  'ipi.parsed': '{ips} addresses · {hosts} host names',
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
  'ipi.failed': 'Lookup failed',
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
  'ipi.det.hosts': 'Host names you entered'
});

registerStrings('tr', {
  'ipi.inputLabel': 'IP adresleri veya host adları',
  'ipi.placeholder': '8.8.8.8\n1.1.1.1\n2606:4700::1111\nwww.ornek.com.tr   ← host adları önce çözümlenir',
  'ipi.inputHint': 'Her satıra bir tane ya da boşluk/virgülle ayırarak. Port ve [köşeli parantez] sorun değil; # yorum başlatır.',
  'ipi.run': 'Sorgula',
  'ipi.stop': 'Durdur',
  'ipi.example': 'Örnek',
  'ipi.fromInventory': 'Sunucularımın IP’leri',
  'ipi.fromInventoryTitle': 'Kayıtlı sunucu envanterindeki tüm IP adreslerini yükle',
  'ipi.clear': 'Temizle',
  'ipi.parsed': '{ips} adres · {hosts} host adı',
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
  'ipi.failed': 'Sorgu başarısız',
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
  'ipi.det.hosts': 'Girdiğiniz host adları'
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
  const flag = (cc) => h('span', { class: 'ipi-flag', attrs: { 'aria-hidden': 'true' } }, flagEmoji(cc));

  /* --- input ----------------------------------------------------------------------- */
  const input = textarea({
    label: t('ipi.inputLabel'),
    value: initialText,
    rows: 6,
    placeholder: t('ipi.placeholder'),
    hint: t('ipi.inputHint'),
    className: 'ipi-input',
    attrs: { 'data-role': 'ip-input' }
  });
  input.input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      start();
    }
  });
  const parsedEl = h('div', { class: 'ipi-parsed muted text-sm', attrs: { 'aria-live': 'polite' } });
  const runBtn = Button({ label: t('ipi.run'), icon: 'search', variant: 'primary', dataset: { action: 'run' }, onClick: () => start() });
  const stopBtn = Button({ label: t('ipi.stop'), icon: 'stop', dataset: { action: 'stop' }, onClick: () => stop() });
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
    parsedEl.textContent = p.ips.length || p.hosts.length ? t('ipi.parsed', { ips: formatNumber(p.ips.length), hosts: formatNumber(p.hosts.length) }) : '';
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
      error: r.info ? r.info.error : null
    }))
  };

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
          r.hosts.length ? h('span', { class: 'muted text-xs' }, t('ipi.fromHost', { host: r.hosts.slice(0, 2).join(', ') + (r.hosts.length > 2 ? ` +${r.hosts.length - 2}` : '') })) : null)
      },
      {
        key: 'operator', label: t('ipi.col.operator'), sortable: true, sortValue: (r) => r.classification.kind,
        searchValue: (r) => `${r.classification.kind} ${r.classification.provider ? r.classification.provider.name : ''}`,
        exportValue: (r) => (r.classification.provider ? r.classification.provider.name : t(`kind.${r.classification.kind}`)),
        render: (r) => KindBadge(r.classification)
      },
      {
        key: 'server', label: t('ipi.col.server'), sortable: true,
        sortValue: (r) => (r.servers.length ? r.servers[0].name : null),
        searchValue: (r) => r.servers.map((s) => s.name).join(' '),
        exportValue: (r) => r.servers.map((s) => s.name).join(' '),
        render: (r) => (r.servers.length ? h('div', { class: 'cluster' }, r.servers.map((s) => Badge(s.name, { variant: 'direct', icon: 'server' }))) : null)
      },
      {
        key: 'ptr', label: t('ipi.col.ptr'), sortable: true, sortValue: (r) => (r.info && r.info.ptr[0]) || null,
        searchValue: (r) => (r.info ? r.info.ptr.join(' ') : ''), exportValue: (r) => (r.info ? r.info.ptr.join(' ') : ''),
        render: (r) => (r.pending ? pendingCell() : r.info && r.info.ptr.length ? TruncatedList(r.info.ptr, { max: 2, render: hostLink }) : null)
      },
      {
        key: 'network', label: t('ipi.col.holder'), sortable: true,
        sortValue: (r) => (r.info ? r.info.asn : null),
        searchValue: (r) => (r.info ? `AS${r.info.asn || ''} ${r.info.asName || ''} ${r.info.holder || ''}` : ''),
        exportValue: (r) => (r.info ? [r.info.asn ? `AS${r.info.asn}` : '', [r.info.asName, r.info.holder].filter((x, i, arr) => x && arr.indexOf(x) === i).join(' - ')].filter(Boolean).join(' ') : ''),
        render: (r) => {
          if (r.pending || !r.info) return null;
          if (!r.info.asn && !r.info.holder) {
            if (r.info.error) return failedCell(r.info);
            return r.info.announced === false ? Badge(t('ipi.notAnnounced'), { title: t('ipi.notAnnouncedTitle') }) : null;
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
        key: 'prefix', label: t('ipi.col.prefix'), sortable: true, mono: true,
        sortValue: (r) => (r.info && r.info.prefix ? ipSortValue(r.info.prefix.split('/')[0]) : null),
        exportValue: (r) => (r.info ? r.info.prefix || '' : ''),
        render: (r) => (r.info ? r.info.prefix : null)
      },
      {
        key: 'location', label: t('ipi.col.location'), sortable: true,
        sortValue: (r) => (r.info && r.info.country ? `${formatRegion(r.info.country)} ${r.info.city || ''}` : null),
        searchValue: (r) => (r.info && r.info.country ? `${r.info.country} ${formatRegion(r.info.country)} ${r.info.city || ''}` : ''),
        exportValue: (r) => (r.info && r.info.country ? [r.info.country, r.info.city].filter(Boolean).join(' ') : ''),
        render: (r) => (r.info && r.info.country ? h('div', { class: 'ipi-loc' },
          h('span', null, flag(r.info.country), ' ', formatRegion(r.info.country)),
          r.info.city ? h('span', { class: 'muted text-xs' }, r.info.city) : null) : null)
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
  const statsGrid = h('div', { class: 'stat-grid ipi-stats' }, stats.ips, stats.cdn, stats.mine, stats.priv, stats.nets, stats.countries);
  const emptyEl = h('div', { class: 'card ipi-empty' }, EmptyState({ icon: 'network', title: t('ipi.emptyTitle'), message: t('ipi.emptyBody', { max: formatNumber(MAX_IPS) }) }));
  const results = h('div', { class: 'stack ipi-results', hidden: true }, progress, notesEl, statsGrid, quotaNote, table);
  container.append(h('div', { class: 'stack-lg ipi-view' }, formCard, emptyEl, results));

  /* --- cell renderers ----------------------------------------------------------------- */
  function pendingCell() {
    return h('span', { class: 'ipi-pending' }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), t('ipi.pending'));
  }

  function failedCell(info) {
    const kind = info.errorKind && info.errorKind !== 'unknown' && hasString(`error.kind.${info.errorKind}`, 'en') ? t(`error.kind.${info.errorKind}`) : '';
    return h('span', { class: 'ipi-failed', title: info.error || '' }, Badge(t('ipi.failed'), { variant: 'error', icon: 'x-circle' }), kind ? h('span', { class: 'muted text-xs' }, ` ${kind}`) : null);
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
    return h('div', { class: 'ipi-rev', dataset: { state: 'error' } },
      Badge(t('ipi.rev.failed'), { variant: 'error', icon: 'x-circle', title: res.error || '' }),
      Button({ label: t('common.retry'), icon: 'refresh', size: 'sm', variant: 'ghost', onClick: () => reverseLookup(r) }));
  }

  function renderDetails(r) {
    const info = r.info;
    const items = [];
    if (r.hosts.length) items.push({ key: t('ipi.det.hosts'), value: h('div', { class: 'cluster' }, r.hosts.map(hostLink)) });
    if (r.classification.provider) items.push({ key: t('ipi.det.provider'), value: t(r.classification.reasonKey, { provider: r.classification.provider.name }) });
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
      if (info.errors.length) items.push({ key: t('ipi.det.errors'), value: h('div', { class: 'stack-sm' }, info.errors.map((e) => h('span', { class: 'mono text-xs' }, `${e.source}: ${e.error}`))) });
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

  function makeRow(ip) {
    return {
      ip,
      hosts: [],
      info: null,
      pending: true,
      classification: classifyIp(ip),
      servers: lookupServers([ip], ctx.getInventoryIndex()).map((m) => m.server),
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
  }

  function note(variant, message) {
    notesEl.append(Alert({ variant, compact: true, message }));
  }

  function setRunning(on) {
    runBtn.hidden = on;
    stopBtn.hidden = !on;
    input.input.readOnly = on;
    ctx.setBusy(on ? t('ipi.looking') : false);
  }

  function stop() {
    if (current && current.controller) {
      current.stopped = true;
      current.controller.abort();
    }
  }

  function start() {
    const parsed = parseIpInput(input.value);
    input.setError(null);
    if (!parsed.ips.length && !parsed.hosts.length) {
      input.setError(parsed.cidrs.length ? t('ipi.cidr', { range: parsed.cidrs[0] }) : t('ipi.nothing'));
      input.focus();
      return;
    }
    const tokens = [...parsed.ips, ...parsed.hosts];
    ctx.setParams({ ips: tokens.length <= 40 ? tokens.join(',') : null });
    if (tokens.length <= 40) ctx.setActions(CopyButton(() => ctx.shareUrl(), { label: t('common.copyLink'), size: 'sm', variant: 'secondary' }));
    else ctx.setActions();
    run(parsed);
  }

  async function run(parsed, preset = null) {
    if (current && current.controller) current.controller.abort();
    const controller = new AbortController();
    const state = { controller, rows: [], stopped: false };
    current = state;
    emptyEl.hidden = true;
    results.hidden = false;
    clear(notesEl);
    if (parsed.invalid.length) note('warn', t('ipi.invalid', { items: parsed.invalid.slice(0, 12).join(', ') + (parsed.invalid.length > 12 ? ' …' : '') }));
    if (parsed.cidrs.length) note('info', t('ipi.cidr', { range: parsed.cidrs[0] }));
    table.setRows([]);

    if (preset) {
      state.rows = preset;
      table.setRows(preset);
      renderStats(preset);
      state.controller = null;
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
    row.reverse = { state: 'loading', result: null };
    table.updateRow(row);
    try {
      const dns = await ctx.getDns();
      const result = await getIntel(dns).reverseIp(row.ip, { signal: ctx.signal });
      row.reverse = { state: 'done', result };
    } catch (err) {
      if (err && err.name === 'AbortError') return;
      row.reverse = { state: 'done', result: { ok: false, domains: [], error: err && err.message ? err.message : String(err), limited: false } };
    }
    table.updateRow(row);
  }

  /* --- initial state ---------------------------------------------------------------- */
  if (restored && Array.isArray(restored.rows) && restored.rows.length) {
    run(parseIpInput(restored.text || ''), restored.rows);
  } else if (paramText) {
    Promise.resolve().then(() => start());
  }

  active = {
    teardown() {
      if (current && current.controller) current.controller.abort();
    },
    snapshot() {
      const rows = current && !current.controller ? current.rows : null;
      return { text: input.value, rows };
    },
    update(params) {
      const text = [params.ips, params.ip, params.q].filter(Boolean).join('\n');
      if (!text) return false;
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
 * Input text and finished rows carried over a language re-mount.
 * @returns {object|null}
 */
export function snapshot() {
  return active ? active.snapshot() : null;
}

/**
 * Take new route params (e.g. `#/ip?ips=…` from another view) without a re-mount.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  return active ? active.update(params) : false;
}

export default { id, titleKey, icon, mount, unmount, snapshot, update };
