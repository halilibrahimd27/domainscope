/**
 * ui/reverse-ip-panel.js — IP Intel › Domains on this IP (reverse IP v2, lib/reverseip.js).
 *
 * Give an address (or up to {@link MAX_REVERSE_IPS}) and get every name tied to it: one chip per
 * source (how many names, "⚠ n/a" with the reason and a Retry, quota and lockout notes), one table
 * row per name (status now, registrable domain, sources, first / last seen, what it resolves to),
 * filters by status and source, search, CSV / JSON export, and hand-offs to Subdomains, SSL
 * Targets and Retire an IP. The first {@link VERIFY_BATCH} names are checked in DNS at once, the
 * rest on "Check more".
 *
 * Loaded on first use by views/ip.js (the row's "Find domains"); the view passes its ipintel
 * service (shared caches), what the workspace knows of an address, and hears each address's
 * names for its table cell. A typed API key stays in its field (this tab): it is never saved,
 * logged, put in a link, a snapshot or an export. Every string is rendered as text.
 */

import { h, clear, append } from './dom.js';
import { Alert, Badge, Button, Card, DataTable, Disclosure, Icon, TruncatedList, announce, select, textInput } from './components.js';
import { t, registerStrings, formatNumber, formatDate, formatDateTime } from '../i18n.js';
import {
  createReverseIp, mergeNames, reverseCounts, reverseExportRows, isLocalOnly, REVERSE_SOURCES, KEYED_SOURCES, NAME_STATUSES,
  VERIFY_BATCH, MAX_REVERSE_IPS
} from '../lib/reverseip.js';
import { THC_REVERSE_LIMIT } from '../lib/ipintel.js';
import { sourceStatus } from '../lib/sourcestatus.js';
import { RetryButton, reasonText, setRetryBusy, sourceName, statusText } from './source-status.js';
import { normalizeIP } from '../lib/ip.js';
import { mergeSignals, splitList } from '../lib/util.js';

registerStrings('en', {
  'rip.title': 'Domains on this IP',
  'rip.subtitle': 'Every name tied to an address — passive DNS, reverse DNS and your workspace — checked in DNS as it is now.',
  'rip.addresses': 'Addresses',
  'rip.addressesHint': 'Up to {max} addresses, one per line or separated by commas.',
  'rip.run': 'Find domains',
  'rip.stop': 'Stop',
  'rip.keys': 'API keys (optional): Shodan, WhoisXML',
  'rip.keyShodan': 'Shodan API key',
  'rip.keyWhoisxml': 'WhoisXML API key',
  'rip.keysNote': 'A key goes only to its own service, with each address of the lookup. It stays in this field: never saved, logged, put in a link or exported, and leaving the page forgets it. WhoisXML charges one credit per address.',
  'rip.privacy': 'A public address goes to HackerTarget, ip.thc.org, AlienVault OTX, Robtex and Shodan InternetDB (with a key also to the Shodan API or WhoisXML), and its reverse name to your DNS resolver; the names found go to your DNS resolver to be checked. Private and reserved addresses, names that look internal and names only your workspace knows are never sent.',
  'rip.nothing': 'Enter at least one IP address.',
  'rip.invalid': 'Not an IP address: {items}',
  'rip.truncated': 'Only the first {max} addresses are looked up.',
  'rip.local': '{ip} is a private or reserved address: only what your workspace knows is shown, and nothing was sent.',
  'rip.asking': 'Asking the sources…',
  'rip.checking': 'Checking names in DNS: {done} of {total}',
  'rip.stopped': 'Stopped — the names not reached are not checked.',
  'rip.found': { one: '{count} name on {ips}', other: '{count} names on {ips}' },
  'rip.none': 'No source knows a name on {ips}.',
  'rip.left': { one: '{count} name is not checked yet: the first {batch} are checked at once.', other: '{count} names are not checked yet: the first {batch} are checked at once.' },
  'rip.checkMore': { one: 'Check {count} more name', other: 'Check {count} more names' },
  'rip.retried': { one: 'Asked {source} again for {count} address.', other: 'Asked {source} again for {count} addresses.' },
  'rip.keyRefused': '{source} refused the key (HTTP {status}): check the key and its credits.',
  'rip.locked': 'Shodan InternetDB locked this browser out after a burst of requests: it is not asked again before {time}.',
  'rip.servers': 'Your servers on {ip}: {names}',
  'rip.extra': '{ip} · Shodan InternetDB: {facts}',
  'rip.extra.ports': 'open ports {list}',
  'rip.extra.tags': 'tags {list}',
  'rip.extra.vulns': { one: '{count} known vulnerability', other: '{count} known vulnerabilities' },
  'rip.extra.nothing': 'nothing known',
  'rip.col.name': 'Name',
  'rip.col.status': 'Now',
  'rip.col.domain': 'Registrable domain',
  'rip.col.sources': 'Sources',
  'rip.col.first': 'First seen',
  'rip.col.last': 'Last seen',
  'rip.col.resolves': 'Resolves to',
  'rip.col.found': 'Found on',
  'rip.filter.status': 'Status',
  'rip.filter.source': 'Source',
  'rip.filter.all': 'All',
  'rip.st.pending': 'checking…',
  'rip.st.here': 'here now',
  'rip.st.moved': 'moved elsewhere',
  'rip.st.cdn': 'behind a CDN',
  'rip.st.none': 'does not resolve',
  'rip.st.failed': 'lookup failed',
  'rip.st.internal': 'looks internal',
  'rip.st.workspace': 'workspace only',
  'rip.st.unchecked': 'not checked yet',
  'rip.stTitle.pending': 'Its A / AAAA lookup is on its way.',
  'rip.stTitle.here': 'It resolves to this address now (a reverse DNS name: forward-confirmed).',
  'rip.stTitle.moved': 'It resolves to other addresses now.',
  'rip.stTitle.cdn': 'It resolves to a CDN / proxy now, which hides the server behind it: DNS cannot tell whether this address is still its origin.',
  'rip.stTitle.none': 'The name does not resolve now (NXDOMAIN or no address).',
  'rip.stTitle.failed': 'The DNS lookup got no usable answer: check again later.',
  'rip.stTitle.internal': 'A name that looks internal is never sent to a public resolver.',
  'rip.stTitle.workspace': 'Only your workspace knows this name, and the workspace is never sent, so it is not checked.',
  'rip.stTitle.unchecked': 'Not checked in DNS yet.',
  'rip.cdnBy': 'behind {provider}',
  'rip.chip.names': { one: '{count} name', other: '{count} names' },
  'rip.chip.of': '{count} of {total}',
  'rip.chip.asking': 'asking…',
  'rip.chip.noKey': 'add a key to ask',
  'rip.chip.local': 'not asked (private address)',
  'rip.chip.idle': 'not asked',
  'rip.quota.workspace': 'The origin map and the server list of this workspace: read here, never sent.',
  'rip.quota.ptr': 'The reverse DNS name, through your DNS resolver.',
  'rip.quota.hackertarget': 'About 50 lookups a day from your IP address, shared with the SSL Targets scan.',
  'rip.quota.thc': 'One page of up to {limit} names; its quota is shared with the Subdomains source.',
  'rip.quota.otx': 'Anonymous access is often rate-limited, and a busy address can take a while.',
  'rip.quota.robtex': 'Free API, rate-limited.',
  'rip.quota.internetdb': 'Free for non-commercial use. Asked once per address: a burst of requests locks it for about an hour.',
  'rip.quota.shodan': 'With your key, one request a second.',
  'rip.quota.whoisxml': 'With your key, one credit per address.',
  'rip.handoff': 'Next',
  'rip.toSubdomains': 'Subdomains of {domain}',
  'rip.toScan': 'SSL Targets for these domains',
  'rip.toRetire': 'Retire this IP',
  'rip.toRetireMany': 'Retire these IPs'
});

registerStrings('tr', {
  'rip.title': 'Bu IP’deki alan adları',
  'rip.subtitle': 'Bir adrese bağlı her ad — pasif DNS, ters DNS ve çalışma alanınız — DNS’te şu anki durumuyla kontrol edilir.',
  'rip.addresses': 'Adresler',
  'rip.addressesHint': 'En fazla {max} adres; her satıra bir tane ya da virgülle ayırarak.',
  'rip.run': 'Alan adlarını bul',
  'rip.stop': 'Durdur',
  'rip.keys': 'API anahtarları (isteğe bağlı): Shodan, WhoisXML',
  'rip.keyShodan': 'Shodan API anahtarı',
  'rip.keyWhoisxml': 'WhoisXML API anahtarı',
  'rip.keysNote': 'Bir anahtar yalnızca kendi hizmetine, sorgudaki her adresle birlikte gider. Bu alanda kalır: hiçbir yere kaydedilmez, günlüğe yazılmaz, bir bağlantıya konmaz ya da dışa aktarılmaz; sayfadan çıkınca unutulur. WhoisXML adres başına bir kredi düşer.',
  'rip.privacy': 'Genel bir adres HackerTarget, ip.thc.org, AlienVault OTX, Robtex ve Shodan InternetDB’ye (anahtarla Shodan API’ye ya da WhoisXML’e de), ters adı DNS çözümleyicinize gider; bulunan adlar kontrol için DNS çözümleyicinize gönderilir. Özel ve ayrılmış adresler, iç ağa ait görünen adlar ve yalnızca çalışma alanınızın bildiği adlar asla gönderilmez.',
  'rip.nothing': 'En az bir IP adresi girin.',
  'rip.invalid': 'IP adresi değil: {items}',
  'rip.truncated': 'Yalnızca ilk {max} adres sorgulanır.',
  'rip.local': '{ip} özel ya da ayrılmış bir adres: yalnızca çalışma alanınızın bildikleri gösterilir ve hiçbir şey gönderilmedi.',
  'rip.asking': 'Kaynaklar sorgulanıyor…',
  'rip.checking': 'Adlar DNS’te kontrol ediliyor: {total} addan {done} tanesi',
  'rip.stopped': 'Durduruldu — sıra gelmeyen adlar kontrol edilmedi.',
  'rip.found': '{ips} üzerinde {count} ad',
  'rip.none': 'Hiçbir kaynak {ips} üzerinde bir ad bilmiyor.',
  'rip.left': '{count} ad henüz kontrol edilmedi: ilk {batch} ad tek seferde kontrol edilir.',
  'rip.checkMore': '{count} ad daha kontrol et',
  'rip.retried': '{source} {count} adres için yeniden soruldu.',
  'rip.keyRefused': '{source} anahtarı reddetti (HTTP {status}): anahtarı ve kredisini kontrol edin.',
  'rip.locked': 'Shodan InternetDB, art arda gelen istekler yüzünden bu tarayıcıyı engelledi: {time} saatinden önce yeniden sorulmaz.',
  'rip.servers': '{ip} üzerindeki sunucularınız: {names}',
  'rip.extra': '{ip} · Shodan InternetDB: {facts}',
  'rip.extra.ports': 'açık portlar {list}',
  'rip.extra.tags': 'etiketler {list}',
  'rip.extra.vulns': '{count} bilinen güvenlik açığı',
  'rip.extra.nothing': 'bilinen bir şey yok',
  'rip.col.name': 'Ad',
  'rip.col.status': 'Şu an',
  'rip.col.domain': 'Kayıtlı alan adı',
  'rip.col.sources': 'Kaynaklar',
  'rip.col.first': 'İlk görülme',
  'rip.col.last': 'Son görülme',
  'rip.col.resolves': 'Çözümlendiği adres',
  'rip.col.found': 'Bulunduğu adres',
  'rip.filter.status': 'Durum',
  'rip.filter.source': 'Kaynak',
  'rip.filter.all': 'Tümü',
  'rip.st.pending': 'kontrol ediliyor…',
  'rip.st.here': 'şu an burada',
  'rip.st.moved': 'başka yere taşınmış',
  'rip.st.cdn': 'CDN arkasında',
  'rip.st.none': 'çözümlenmiyor',
  'rip.st.failed': 'sorgu başarısız',
  'rip.st.internal': 'iç ağa ait görünüyor',
  'rip.st.workspace': 'yalnızca çalışma alanında',
  'rip.st.unchecked': 'henüz kontrol edilmedi',
  'rip.stTitle.pending': 'A / AAAA sorgusu yolda.',
  'rip.stTitle.here': 'Şu an bu adrese çözümleniyor (ters DNS adıysa ileri yönde de doğrulandı).',
  'rip.stTitle.moved': 'Şu an başka adreslere çözümleniyor.',
  'rip.stTitle.cdn': 'Şu an arkasındaki sunucuyu gizleyen bir CDN’e / proxy’ye çözümleniyor: DNS, bu adresin hâlâ asıl (origin) sunucusu olup olmadığını söyleyemez.',
  'rip.stTitle.none': 'Ad şu an çözümlenmiyor (NXDOMAIN ya da adres yok).',
  'rip.stTitle.failed': 'DNS sorgusu kullanılabilir bir yanıt alamadı: daha sonra yeniden kontrol edin.',
  'rip.stTitle.internal': 'İç ağa ait görünen bir ad hiçbir zaman genel bir çözümleyiciye gönderilmez.',
  'rip.stTitle.workspace': 'Bu adı yalnızca çalışma alanınız biliyor ve çalışma alanı hiçbir yere gönderilmez; bu yüzden kontrol edilmez.',
  'rip.stTitle.unchecked': 'Henüz DNS’te kontrol edilmedi.',
  'rip.cdnBy': '{provider} arkasında',
  'rip.chip.names': '{count} ad',
  'rip.chip.of': '{total} addan {count} tanesi',
  'rip.chip.asking': 'soruluyor…',
  'rip.chip.noKey': 'sormak için anahtar ekleyin',
  'rip.chip.local': 'sorulmadı (özel adres)',
  'rip.chip.idle': 'sorulmadı',
  'rip.quota.workspace': 'Bu çalışma alanının origin haritası ve sunucu listesi: burada okunur, hiçbir yere gönderilmez.',
  'rip.quota.ptr': 'Ters DNS adı, DNS çözümleyiciniz üzerinden.',
  'rip.quota.hackertarget': 'IP adresiniz başına günde yaklaşık 50 sorgu, SSL Hedefleri taramasıyla ortak.',
  'rip.quota.thc': 'En fazla {limit} adlık tek sayfa; kotası Subdomain kaynağıyla ortaktır.',
  'rip.quota.otx': 'Anonim erişim sık sık hız sınırına takılır; yoğun bir adres biraz sürebilir.',
  'rip.quota.robtex': 'Ücretsiz API, hız sınırlı.',
  'rip.quota.internetdb': 'Ticari olmayan kullanım için ücretsiz. Adres başına bir kez sorulur: art arda istekler onu yaklaşık bir saat kilitler.',
  'rip.quota.shodan': 'Anahtarınızla, saniyede bir istek.',
  'rip.quota.whoisxml': 'Anahtarınızla, adres başına bir kredi.',
  'rip.handoff': 'Sonraki adım',
  'rip.toSubdomains': '{domain} alan adının subdomain’leri',
  'rip.toScan': 'Bu alan adları için SSL Hedefleri',
  'rip.toRetire': 'Bu IP’yi emekliye ayır',
  'rip.toRetireMany': 'Bu IP’leri emekliye ayır'
});

/** The status filter's choices: every status a row can have. */
const FILTER_STATUSES = NAME_STATUSES;
/** Registrable domains offered as Subdomains hand-offs at most. */
const MAX_HANDOFF_DOMAINS = 6;

/**
 * Every i18n key this panel builds from a code (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...NAME_STATUSES.flatMap((s) => [`rip.st.${s}`, `rip.stTitle.${s}`]),
    ...REVERSE_SOURCES.flatMap((s) => [`rip.quota.${s}`, `srcst.source.${s}`])
  ];
}

/**
 * Parse the address box: canonical addresses (deduplicated, input order), what is not one, and
 * whether the list was cut at {@link MAX_REVERSE_IPS}.
 * @param {string} text
 * @returns {{ ips: string[], invalid: string[], truncated: boolean }}
 */
export function parseAddresses(text) {
  const ips = [];
  const invalid = [];
  let truncated = false;
  for (const token of splitList(String(text ?? ''))) {
    const raw = token.replace(/^\[|\](?::\d{1,5})?$/g, '').replace(/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/, '$1');
    const ip = normalizeIP(raw);
    if (!ip) {
      if (!invalid.includes(token)) invalid.push(token);
      continue;
    }
    if (ips.includes(ip)) continue;
    if (ips.length >= MAX_REVERSE_IPS) {
      truncated = true;
      continue;
    }
    ips.push(ip);
  }
  return { ips, invalid, truncated };
}

/**
 * The panel.
 * @param {{ ctx: object, getIntel: () => Promise<object>, workspaceFor: (ip: string) => { servers: string[], origins: object[] },
 *   onNames?: (ip: string, names: string[]|null, state: 'loading'|'done'|'error'|'idle') => void }} opts
 *   getIntel: the view's lib/ipintel.js service; workspaceFor: what the workspace knows of an address;
 *   onNames: an address's names once its sources answered (null while asking or when nothing answered)
 * @returns {{ el: HTMLElement, lookup: (ips: string[]) => Promise<void>, fill: (ips: string[]) => void,
 *   snapshot: () => object|null, restore: (snap: object|null) => void, focus: () => void, running: () => boolean }}
 */
export function ReverseIpPanel({ ctx, getIntel, workspaceFor, onNames = null }) {
  let svc = null;
  /** @type {Map<string, object>} ip → IpReverse (results so far) */
  let lookups = new Map();
  /** @type {Map<string, Set<string>>} ip → sources still asked */
  const asking = new Map();
  let rows = [];
  let run = null;
  let lastIps = [];

  /* --- form ----------------------------------------------------------------------- */
  const addresses = textInput({
    label: t('rip.addresses'), hint: t('rip.addressesHint', { max: formatNumber(MAX_REVERSE_IPS) }), mono: true, className: 'rip-addresses',
    attrs: { 'data-role': 'rip-addresses' }, onEnter: () => start()
  });
  const keyField = (label, role) => textInput({
    label, type: 'password', autocomplete: 'off', mono: true, optional: true,
    // A password field: never echoed, never autofilled or offered for saving (ui/zone-fetch.js).
    attrs: { 'data-role': role, 'data-1p-ignore': 'true', 'data-lpignore': 'true', 'data-form-type': 'other' }
  });
  const shodanKey = keyField(t('rip.keyShodan'), 'rip-key-shodan');
  const whoisKey = keyField(t('rip.keyWhoisxml'), 'rip-key-whoisxml');
  const keys = () => ({ shodan: shodanKey.input.value.trim(), whoisxml: whoisKey.input.value.trim() });
  const runBtn = Button({ label: t('rip.run'), icon: 'search', variant: 'primary', dataset: { action: 'rip-run' }, onClick: () => start() });
  const stopBtn = Button({ label: t('rip.stop'), icon: 'stop', dataset: { action: 'rip-stop' }, onClick: () => stop() });
  stopBtn.hidden = true;

  /* --- results ---------------------------------------------------------------------- */
  const notesEl = h('div', { class: 'stack-sm rip-notes', attrs: { 'aria-live': 'polite' } });
  const progressEl = h('p', { class: 'muted text-sm rip-progress', hidden: true, attrs: { role: 'status' } });
  const chipsEl = h('div', { class: 'src-chips rip-chips', hidden: true, attrs: { role: 'group', 'aria-label': t('rip.col.sources') } });
  const factsEl = h('div', { class: 'stack-sm rip-facts' });
  const moreBtn = Button({ label: t('rip.checkMore', { count: VERIFY_BATCH }), icon: 'check-circle', size: 'sm', variant: 'secondary', dataset: { action: 'rip-more' }, onClick: () => checkMore() });
  const moreEl = h('div', { class: 'rip-more', hidden: true }, h('p', { class: 'muted text-sm rip-left' }), moreBtn);
  const handoffEl = h('div', { class: 'rip-handoff', hidden: true });

  let statusFilter = '';
  let sourceFilter = '';
  const statusSelect = select({
    label: t('rip.filter.status'), size: 'sm', className: 'rip-filter',
    options: [{ value: '', label: t('rip.filter.all') }, ...FILTER_STATUSES.map((s) => ({ value: s, label: t(`rip.st.${s}`) }))],
    onChange: (v) => {
      statusFilter = v;
      applyFilter();
    }
  });
  statusSelect.input.dataset.role = 'rip-filter-status';
  const sourceSelect = select({
    label: t('rip.filter.source'), size: 'sm', className: 'rip-filter',
    options: [{ value: '', label: t('rip.filter.all') }, ...REVERSE_SOURCES.map((s) => ({ value: s, label: sourceName(s) }))],
    onChange: (v) => {
      sourceFilter = v;
      applyFilter();
    }
  });
  sourceSelect.input.dataset.role = 'rip-filter-source';

  const date = (ms) => (ms === null || ms === undefined ? null : h('time', { attrs: { datetime: new Date(ms).toISOString() }, title: formatDateTime(ms) }, formatDate(ms)));
  const table = DataTable({
    caption: t('rip.title'),
    rowKey: (r) => r.name,
    search: true,
    dense: true,
    pageSize: 100,
    cellLabels: true,
    className: 'rip-table',
    toolbar: h('div', { class: 'cluster rip-filters' }, statusSelect.el, sourceSelect.el),
    rowClass: (r) => ['rip-row', `rip-st-${r.status}`],
    export: { filename: 'reverse-ip', json: (list) => reverseExportRows(list) },
    columns: [
      {
        key: 'name', label: t('rip.col.name'), sortable: true, mono: true, className: 'rip-col-name',
        render: (r) => h('a', { class: 'mono rip-name', href: ctx.href('lookup', { name: r.name, type: 'A,AAAA' }) }, r.name)
      },
      {
        key: 'status', label: t('rip.col.status'), sortable: true, className: 'rip-col-status',
        sortValue: (r) => NAME_STATUSES.indexOf(r.status), searchValue: (r) => t(`rip.st.${r.status}`),
        exportValue: (r) => r.status, render: renderStatus
      },
      {
        key: 'domain', label: t('rip.col.domain'), sortable: true, mono: true, className: 'rip-col-domain',
        exportValue: (r) => r.domain || '', render: (r) => r.domain || ''
      },
      {
        key: 'sources', label: t('rip.col.sources'), sortable: true, className: 'rip-col-sources',
        sortValue: (r) => r.sources.length, searchValue: (r) => r.sources.map(sourceName).join(' '),
        exportValue: (r) => r.sources.join(' '),
        render: (r) => h('span', { class: 'rip-sources', dataset: { sources: r.sources.join(' ') } }, r.sources.map(sourceName).join(' · '))
      },
      {
        key: 'first', label: t('rip.col.first'), sortable: true, className: 'rip-col-first',
        sortValue: (r) => r.first, exportValue: (r) => (r.first === null ? '' : new Date(r.first).toISOString()), render: (r) => date(r.first)
      },
      {
        key: 'last', label: t('rip.col.last'), sortable: true, className: 'rip-col-last',
        sortValue: (r) => r.last, exportValue: (r) => (r.last === null ? '' : new Date(r.last).toISOString()), render: (r) => date(r.last)
      },
      {
        key: 'resolves', label: t('rip.col.resolves'), className: 'rip-col-resolves',
        searchValue: (r) => r.resolvesTo.join(' '), exportValue: (r) => r.resolvesTo.join(' '),
        render: (r) => (r.resolvesTo.length ? TruncatedList(r.resolvesTo, { max: 2, mono: true }) : null)
      },
      {
        key: 'found', label: t('rip.col.found'), className: 'rip-col-found',
        searchValue: (r) => r.ips.join(' '), exportValue: (r) => r.ips.join(' '),
        render: (r) => TruncatedList(r.ips, { max: 2, mono: true })
      }
    ]
  });
  const resultsEl = h('div', { class: 'stack rip-results', hidden: true }, chipsEl, factsEl, table, moreEl, handoffEl);

  const el = Card({
    className: 'rip-panel',
    title: h('span', { attrs: { tabindex: '-1' }, dataset: { role: 'rip-title' } }, t('rip.title')),
    subtitle: t('rip.subtitle'),
    icon: 'globe',
    children: h('div', { class: 'stack', dataset: { shortcutScope: 'rip' } },
      h('div', { class: 'rip-form' }, addresses.el, h('div', { class: 'cluster rip-run' }, stopBtn, runBtn)),
      Disclosure({
        summary: t('rip.keys'), className: 'rip-keys',
        children: h('div', { class: 'stack-sm' }, h('div', { class: 'rip-keyfields' }, shodanKey.el, whoisKey.el), h('p', { class: 'muted text-xs' }, t('rip.keysNote')))
      }),
      h('p', { class: 'muted text-xs rip-privacy' }, t('rip.privacy')),
      notesEl, progressEl, resultsEl)
  });
  el.dataset.panel = 'reverse-ip';

  /* --- rendering ---------------------------------------------------------------------- */
  function renderStatus(r) {
    const variant = { here: 'ok', moved: 'warn', cdn: 'cdn', none: 'neutral', failed: 'error', pending: 'neutral' }[r.status] || 'neutral';
    const icon = { here: 'check-circle', moved: 'swap', cdn: 'cloud', none: 'minus-circle', failed: 'alert', internal: 'lock', workspace: 'lock' }[r.status] || null;
    let title = t(`rip.stTitle.${r.status}`);
    if (r.status === 'failed' && r.rcode) title += ` (${r.rcode})`;
    const badge = Badge(t(`rip.st.${r.status}`), { variant, icon, title });
    badge.dataset.status = r.status;
    const extra = r.status === 'cdn' && r.provider ? h('span', { class: 'muted text-xs' }, t('rip.cdnBy', { provider: r.provider })) : null;
    return h('div', { class: 'rip-status' }, badge, extra);
  }

  function applyFilter() {
    const st = statusFilter;
    const src = sourceFilter;
    table.setFilter(st || src ? (r) => (!st || r.status === st) && (!src || r.sources.includes(src)) : null);
  }

  /** One chip per source over every address of the lookup. */
  function chipOf(source) {
    const list = [...lookups.values()];
    const results = list.map((l) => l.results[source]).filter(Boolean);
    const busy = [...asking.values()].some((set) => set.has(source));
    const failedIps = list.filter((l) => l.results[source] && l.results[source].state === 'failed').map((l) => l.ip);
    const failures = results.filter((r) => r.state === 'failed' && r.failure).sort((a, b) => b.at - a.at);
    const names = new Set(results.filter((r) => r.state === 'ok').flatMap((r) => r.names.map((n) => n.name)));
    let state = 'idle';
    if (busy) state = 'pending';
    else if (failedIps.length) state = 'failed';
    else if (results.some((r) => r.state === 'ok')) state = 'ok';
    const skip = results.length && results.every((r) => r.state === 'skipped') ? results[0].skip : null;
    const total = results.reduce((n, r) => (Number.isFinite(r.total) ? n + r.total : n), 0);
    const truncated = results.some((r) => r.truncated);
    return { source, state, names: names.size, failedIps, status: failures.length ? sourceStatus(failures[0].failure) : null, skip, total, truncated };
  }

  function renderChips() {
    clear(chipsEl);
    chipsEl.hidden = !lookups.size;
    const focused = chipsEl.contains(globalThis.document.activeElement) ? globalThis.document.activeElement.dataset.chip || '' : null;
    for (const source of REVERSE_SOURCES) {
      const c = chipOf(source);
      let value;
      if (c.state === 'pending') value = t('rip.chip.asking');
      else if (c.state === 'failed') value = `${t('srcst.na')} · ${c.status ? reasonText(c.status) : ''}`;
      else if (c.state === 'ok') value = c.truncated && c.total > c.names ? t('rip.chip.of', { count: formatNumber(c.names), total: formatNumber(c.total) }) : t('rip.chip.names', { count: c.names });
      else value = t(c.skip === 'no-key' ? 'rip.chip.noKey' : c.skip === 'local' ? 'rip.chip.local' : 'rip.chip.idle');
      const icon = { ok: 'check-circle', failed: 'alert', idle: 'minus-circle' }[c.state];
      // A locked-out InternetDB sends nothing on a Retry before the lock ends: no button then.
      const locked = source === 'internetdb' && svc && svc.lockedUntil();
      const retry = c.state === 'failed' && !locked
        ? RetryButton({ sources: [source], onClick: () => retrySource(source), target: c.failedIps.length === 1 ? c.failedIps[0] : null, dataset: { chip: source } })
        : null;
      if (retry && run && run.retrying && run.retrying.has(source)) setRetryBusy(retry);
      const title = [c.status ? statusText(c.status) : null, t(`rip.quota.${source}`, { limit: formatNumber(THC_REVERSE_LIMIT) })].filter(Boolean).join('\n');
      chipsEl.append(h('span', { class: 'src-chip rip-chip', title, dataset: { source, state: c.state, skip: c.skip || '' } },
        icon ? Icon(icon, { size: 14 }) : h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }),
        h('span', { class: 'src-chip-name' }, sourceName(source)),
        h('span', { class: 'src-chip-value' }, value),
        retry));
    }
    if (focused !== null) (chipsEl.querySelector(`[data-chip="${focused}"]`) || chipsEl).focus();
  }

  /** The workspace's servers and InternetDB's facts per address, and the notes (key refused, lockout). */
  function renderFacts() {
    clear(factsEl);
    for (const l of lookups.values()) {
      const ws = l.results.workspace;
      if (ws && ws.extra && ws.extra.servers.length) {
        factsEl.append(h('p', { class: 'text-sm rip-servers', dataset: { ip: l.ip } }, Icon('server', { size: 14 }), ' ', t('rip.servers', { ip: l.ip, names: ws.extra.servers.join(', ') })));
      }
      const idb = l.results.internetdb;
      if (idb && idb.state === 'ok' && idb.extra) {
        const facts = [];
        if (idb.extra.ports.length) facts.push(t('rip.extra.ports', { list: idb.extra.ports.join(', ') }));
        if (idb.extra.tags.length) facts.push(t('rip.extra.tags', { list: idb.extra.tags.join(', ') }));
        if (idb.extra.vulns.length) facts.push(t('rip.extra.vulns', { count: idb.extra.vulns.length }));
        const p = h('p', { class: 'muted text-sm rip-extra', dataset: { ip: l.ip }, title: idb.extra.vulns.join(' ') || null },
          t('rip.extra', { ip: l.ip, facts: facts.length ? facts.join(' · ') : t('rip.extra.nothing') }));
        factsEl.append(p);
      }
      for (const source of KEYED_SOURCES) {
        const r = l.results[source];
        const status = r && r.state === 'failed' && r.failure ? r.failure.status : null;
        if (status === 401 || status === 403) {
          factsEl.append(Alert({ variant: 'warn', compact: true, message: t('rip.keyRefused', { source: sourceName(source), status }) }));
        }
      }
    }
    const until = svc ? svc.lockedUntil() : null;
    if (until) factsEl.append(Alert({ variant: 'warn', compact: true, message: t('rip.locked', { time: formatDateTime(until) }) }));
  }

  function renderMore() {
    const left = rows.filter((r) => r.status === 'unchecked').length;
    moreEl.hidden = !left || !!(run && run.controller);
    moreEl.firstChild.textContent = left ? t('rip.left', { count: left, batch: formatNumber(VERIFY_BATCH) }) : '';
    const label = moreBtn.querySelector('.btn-label');
    const text = t('rip.checkMore', { count: Math.min(left, VERIFY_BATCH) });
    if (label) label.textContent = text;
    else moreBtn.textContent = text;
  }

  function renderHandoffs() {
    clear(handoffEl);
    const { domains } = reverseCounts(rows);
    const ips = [...lookups.keys()];
    const publicDomains = domains.filter((d) => !rows.find((r) => r.domain === d && (r.status === 'internal' || r.status === 'workspace')));
    handoffEl.hidden = !rows.length;
    if (!rows.length) return;
    const links = publicDomains.slice(0, MAX_HANDOFF_DOMAINS).map((d) => h('a', {
      class: 'btn btn-ghost btn-sm', href: ctx.href('subdomains', { domain: d, run: '0' }), dataset: { handoff: 'subdomains', domain: d }
    }, t('rip.toSubdomains', { domain: d })));
    const scan = publicDomains.length ? h('a', {
      class: 'btn btn-ghost btn-sm', href: ctx.href('scan', { domains: publicDomains.slice(0, 25).join(','), run: '0' }), dataset: { handoff: 'scan' }
    }, t('rip.toScan')) : null;
    const retire = h('a', {
      class: 'btn btn-ghost btn-sm', href: ctx.href('retire', { ips: ips.join(','), domains: publicDomains.slice(0, 25).join(','), run: '0' }), dataset: { handoff: 'retire' }
    }, t(ips.length > 1 ? 'rip.toRetireMany' : 'rip.toRetire'));
    append(handoffEl, h('span', { class: 'muted text-sm rip-handoff-label' }, t('rip.handoff')), ...links, scan, retire);
  }

  function renderAll() {
    renderChips();
    renderFacts();
    renderMore();
    renderHandoffs();
  }

  function note(variant, message) {
    notesEl.append(Alert({ variant, compact: true, message }));
  }

  function setProgress(text) {
    progressEl.hidden = !text;
    progressEl.textContent = text || '';
  }

  function setRunning(on) {
    runBtn.hidden = on;
    stopBtn.hidden = !on;
    addresses.input.readOnly = on;
  }

  /** Tell the view what an address's sources found (its table cell). */
  function report(ip) {
    if (!onNames) return;
    const l = lookups.get(ip);
    if (!l) return onNames(ip, null, 'idle');
    const answered = REVERSE_SOURCES.some((s) => l.results[s] && l.results[s].state === 'ok' && s !== 'workspace');
    const names = rows.filter((r) => r.ips.includes(ip)).map((r) => r.name);
    onNames(ip, names, answered || l.local || names.length ? 'done' : 'error');
  }

  /* --- running ------------------------------------------------------------------------- */
  async function service() {
    if (!svc) svc = createReverseIp({ dns: await ctx.getDns(), intel: await getIntel() });
    return svc;
  }

  function stop() {
    if (run && run.controller) {
      run.stopped = true;
      run.controller.abort();
    }
  }

  /** Look up the addresses in the box. */
  function start() {
    const parsed = parseAddresses(addresses.input.value);
    addresses.setError(null);
    if (!parsed.ips.length) {
      addresses.setError(t('rip.nothing'));
      addresses.focus();
      return Promise.resolve();
    }
    return go(parsed);
  }

  async function go(parsed) {
    // Nothing is sent for an address that stays here: only a public one needs the network.
    if (parsed.ips.some((ip) => !isLocalOnly(ip)) && !ctx.requireOnline()) return;
    if (run && run.controller) run.controller.abort();
    const controller = new AbortController();
    const mine = { controller, stopped: false, retrying: new Set() };
    run = mine;
    const live = () => run === mine && !ctx.signal.aborted;
    const signal = mergeSignals(ctx.signal, controller.signal);
    clear(notesEl);
    if (parsed.invalid.length) note('warn', t('rip.invalid', { items: parsed.invalid.slice(0, 8).join(', ') }));
    if (parsed.truncated) note('warn', t('rip.truncated', { max: formatNumber(MAX_REVERSE_IPS) }));
    for (const ip of parsed.ips) if (isLocalOnly(ip)) note('info', t('rip.local', { ip }));
    lastIps = parsed.ips;
    lookups = new Map();
    asking.clear();
    rows = [];
    table.setRows([]);
    resultsEl.hidden = false;
    setRunning(true);
    setProgress(t('rip.asking'));
    const typed = keys();
    try {
      const s = await service();
      for (const ip of parsed.ips) {
        lookups.set(ip, { ip, local: isLocalOnly(ip), results: {}, at: Date.now() });
        asking.set(ip, new Set(REVERSE_SOURCES));
        if (onNames) onNames(ip, null, 'loading');
      }
      renderAll();
      await Promise.all(parsed.ips.map(async (ip) => {
        const res = await s.lookup(ip, {
          keys: typed, workspace: workspaceFor(ip), signal,
          onSource: (r) => {
            if (!live()) return;
            lookups.get(ip).results[r.source] = r;
            asking.get(ip).delete(r.source);
            renderChips();
          }
        });
        if (!live()) return;
        lookups.set(ip, res);
        asking.delete(ip);
        rows = mergeNames([...lookups.values()], { previous: rows });
        table.setRows(rows);
        renderAll();
        report(ip);
      }));
      if (!live()) return;
      await verifyBatch(signal, live);
      if (live()) finish();
    } catch (err) {
      if (!live()) return;
      if (err && err.name === 'AbortError') {
        if (mine.stopped) note('info', t('rip.stopped'));
      } else {
        ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      }
      finish();
    } finally {
      if (run === mine) {
        mine.controller = null;
        asking.clear();
        if (!ctx.signal.aborted) {
          setRunning(false);
          renderAll();
        }
      }
    }
  }

  /** Check the next batch of names in DNS; the progress line counts them. */
  async function verifyBatch(signal, live) {
    const s = await service();
    const total = Math.min(VERIFY_BATCH, rows.filter((r) => r.status === 'unchecked').length);
    let done = 0;
    if (total) setProgress(t('rip.checking', { done: formatNumber(0), total: formatNumber(total) }));
    await s.verify(rows, {
      signal,
      onRow: (r) => {
        if (!live()) return;
        done += 1;
        table.updateRow(r);
        setProgress(t('rip.checking', { done: formatNumber(done), total: formatNumber(total) }));
      }
    });
    if (live()) table.updateRows(rows);
  }

  function finish() {
    setProgress('');
    const ips = [...lookups.keys()].join(', ');
    if (!ctx.signal.aborted) announce(rows.length ? t('rip.found', { count: rows.length, ips }) : t('rip.none', { ips }));
    if (!rows.length && lookups.size) note('info', t('rip.none', { ips }));
    for (const ip of lookups.keys()) report(ip);
  }

  /** "Check more": the next batch of unchecked names. */
  async function checkMore() {
    if (run && run.controller) return;
    if (!ctx.requireOnline()) return;
    const controller = new AbortController();
    const mine = { controller, stopped: false, retrying: new Set() };
    run = mine;
    const live = () => run === mine && !ctx.signal.aborted;
    setRunning(true);
    moreEl.hidden = true;
    try {
      await verifyBatch(mergeSignals(ctx.signal, controller.signal), live);
    } catch (err) {
      if (live() && !(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
      if (live() && mine.stopped) note('info', t('rip.stopped'));
    } finally {
      if (run === mine) {
        mine.controller = null;
        setProgress('');
        if (!ctx.signal.aborted) {
          setRunning(false);
          renderAll();
        }
      }
    }
  }

  /** A chip's Retry: that source again (past the cache) for every address it failed on; then check the new names. */
  async function retrySource(source) {
    if (run && run.controller) return;
    if (!ctx.requireOnline()) return;
    const failedOn = [...lookups.values()].filter((l) => l.results[source] && l.results[source].state === 'failed');
    if (!failedOn.length) return;
    const controller = new AbortController();
    const mine = { controller, stopped: false, retrying: new Set([source]) };
    run = mine;
    const live = () => run === mine && !ctx.signal.aborted;
    const signal = mergeSignals(ctx.signal, controller.signal);
    setRunning(true);
    renderChips();
    try {
      const s = await service();
      await Promise.all(failedOn.map(async (l) => {
        const next = await s.retry(l, { sources: [source], keys: keys(), workspace: workspaceFor(l.ip), signal });
        if (live()) lookups.set(l.ip, next);
      }));
      if (!live()) return;
      rows = mergeNames([...lookups.values()], { previous: rows });
      table.setRows(rows);
      renderAll();
      announce(t('rip.retried', { source: sourceName(source), count: failedOn.length }));
      await verifyBatch(signal, live);
      if (live()) for (const ip of lookups.keys()) report(ip);
    } catch (err) {
      if (live() && !(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
    } finally {
      if (run === mine) {
        mine.controller = null;
        mine.retrying.clear();
        setProgress('');
        if (!ctx.signal.aborted) {
          setRunning(false);
          renderAll();
        }
      }
    }
  }

  return {
    el,
    /** Put addresses in the box and look them up. */
    lookup(ips) {
      addresses.input.value = ips.join('\n');
      return start();
    },
    /** Put addresses in the box (nothing is sent). */
    fill(ips) {
      if (run && run.controller) return;
      addresses.input.value = ips.join('\n');
    },
    focus() {
      const title = el.querySelector('[data-role="rip-title"]');
      if (title) title.focus();
    },
    running: () => !!(run && run.controller),
    /** The finished lookup as plain data (never a key), for a language re-mount. */
    snapshot() {
      if (!lookups.size || (run && run.controller)) return null;
      return { text: addresses.input.value, ips: lastIps, lookups: [...lookups.values()], rows: rows.map((r) => ({ ...r, ips: [...r.ips], sources: [...r.sources], resolvesTo: [...r.resolvesTo] })) };
    },
    /** Show a snapshot again (no request). */
    restore(snap) {
      if (!snap || !Array.isArray(snap.lookups)) return;
      addresses.input.value = typeof snap.text === 'string' ? snap.text : '';
      lastIps = Array.isArray(snap.ips) ? snap.ips : [];
      lookups = new Map(snap.lookups.map((l) => [l.ip, l]));
      rows = Array.isArray(snap.rows) ? snap.rows.map((r) => ({ ...r, status: r.status === 'pending' ? 'unchecked' : r.status })) : [];
      table.setRows(rows);
      resultsEl.hidden = false;
      for (const ip of lookups.keys()) if (isLocalOnly(ip)) note('info', t('rip.local', { ip }));
      renderAll();
    }
  };
}
