/**
 * ui/egress-panel.js — About › What this page sent: the page session's ledger of requests.
 *
 * One row per host this page contacted since it was opened (or since Clear), measured by the
 * browser (ui/egress-meter.js over lib/egresslog.js) and named by the registry (lib/egress.js):
 * the service and its role, how many requests, and what kind of data it received — per endpoint,
 * so crt.sh reads "Domain and host names (2) · A public-key SHA-256 (1)" when both were sent. A
 * host the registry does not know comes first with a warning. Below: what this page never sends,
 * how the counts are made, and the deploy the page runs (its version file, Pages bundle only).
 * The table follows the log live, at most once a second; nothing is stored.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, DataTable, ExternalLink, Icon, announce } from './components.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import { egressLog, egressMeterStatus } from './egress-meter.js';
import { ledgerRows, ledgerTotals, NEVER_SENT } from '../lib/egress.js';
import { versionFileUrl, parseVersionFile, bundleInfo } from '../lib/pwa.js';
import { fetchJson } from '../lib/util.js';

registerStrings('en', {
  'egress.title': 'What this page sent',
  'egress.desc': 'Every request this page has made since you opened it, counted live by your browser, and what each service received — so “everything runs in your browser” can be checked without developer tools. Nothing here is saved: a reload starts from zero.',
  'egress.clear': 'Clear',
  'egress.cleared': 'Cleared. The ledger counts on from now.',
  'egress.since': 'Since {time}',
  'egress.sum.requests': { one: '{count} request to third parties', other: '{count} requests to third parties' },
  'egress.sum.hosts': { one: 'on {count} host', other: 'on {count} hosts' },
  'egress.sum.self': { one: '{count} file from this site', other: '{count} files from this site' },
  'egress.sum.none': 'nothing to a third party',
  'egress.col.service': 'Service',
  'egress.col.requests': 'Requests',
  'egress.col.received': 'What it received',
  'egress.col.last': 'Last',
  'egress.empty': 'No request yet.',
  'egress.self': 'This site',
  'egress.unknown': 'Not in the registry',
  'egress.unknownTitle': 'DomainScope’s code never sends to this host',
  'egress.unknownAlert': {
    one: '{count} host is not a service DomainScope uses, and its code never sends to it. A browser extension may have added the request to this page.',
    other: '{count} hosts are not services DomainScope uses, and its code never sends to them. A browser extension may have added the requests to this page.'
  },
  'egress.failed': { one: '{count} got no answer', other: '{count} got no answer' },
  'egress.role.site': 'The app’s own files',
  'egress.role.dns': 'DNS resolver',
  'egress.role.ct': 'Certificate Transparency',
  'egress.role.passive': 'Subdomain and passive DNS data',
  'egress.role.ip': 'IP address data',
  'egress.role.registration': 'Registration data (RDAP)',
  'egress.role.probes': 'Checks from the internet',
  'egress.role.dnsHosting': 'Your DNS provider, with your token',
  'egress.kind.appFiles': 'Nothing of yours: the app’s own files',
  'egress.kind.nothing': 'Nothing of yours: a public list or the free quota',
  'egress.kind.dnsQuestions': 'DNS names and record types',
  'egress.kind.nameServers': 'Name servers to ask',
  'egress.kind.domains': 'Domain and host names',
  'egress.kind.hostnames': 'Host names to check',
  'egress.kind.ipNamePairs': 'Public IP, host name and port',
  'egress.kind.ipAddresses': 'IP addresses or networks',
  'egress.kind.asNumbers': 'AS numbers',
  'egress.kind.certSerial': 'A certificate serial number',
  'egress.kind.keyHash': 'A public-key SHA-256',
  'egress.kind.measurementIds': 'Measurement IDs, to read results',
  'egress.kind.apiToken': 'Your API token, for that one fetch',
  'egress.neverTitle': 'Never sent',
  'egress.never.certificates': 'Certificate files: read in this tab, never uploaded. A Certificate Transparency lookup sends only what you look up with — a host name, a serial number or a public-key hash.',
  'egress.never.keys': 'Private keys, passwords and API tokens: a private key is never needed or shown, and a PFX / P12 or hand-over file password is used in this tab only, never stored or sent. A DNS provider token you paste into Zone File goes only to that provider, for that one fetch, and is never stored.',
  'egress.never.zone': 'The imported zone file: never uploaded or saved; a zone fetched from deSEC or DigitalOcean is only read from them. Its Live check sends record names and types to your DNS resolvers, and the comparison with new name servers sends them to Globalping with the servers you name — never values; an origin address from it leaves only through Verify’s opt-in origin check.',
  'egress.never.inventory': 'Your server inventory: never uploaded, and server names are never sent. An address from it leaves only when you look it up: through Verify’s opt-in origin check, or in IP Intel with “My servers’ IPs” and “Look up” (to RIPEstat and ipwho.is; private addresses are never sent).',
  'egress.never.workspace': 'Workspaces: notes, expected CAs and the stored lists stay in this browser, and a workspace leaves only as a hand-over file you export. Custom and learned names are tried as DNS lookups under the domains you scan.',
  'egress.never.tracking': 'Analytics, cookies and tracking: there are none, and requests carry no referrer. Like any website, each service sees your IP address.',
  'egress.how': 'How it is counted: each request the page’s code starts and each one your browser reports (Resource Timing), whichever is higher, so a request that got no answer counts too. What a service received comes from DomainScope’s registry of endpoints, which a test keeps in step with the code, and where the address alone cannot tell (which kind of Globalping check) from what the page’s code says about the request. Requests your browser makes on its own behalf (its updates, safe-browsing checks) and links you open yourself are not the page’s and are not listed.',
  'egress.noResourceTiming': 'This browser does not report Resource Timing, so only the requests the page’s code starts are counted.',
  'egress.version.bundle': 'This page runs deploy {version}',
  'egress.version.commit': 'commit {commit}',
  'egress.version.noCommit': 'built without a commit name',
  'egress.version.unread': 'its version file could not be read',
  'egress.version.dev': 'Development copy: served from the repository as it is, so there is no deploy version.'
});

registerStrings('tr', {
  'egress.title': 'Bu sayfa ne gönderdi',
  'egress.desc': 'Bu sayfanın açıldığından beri yaptığı her istek, tarayıcınız tarafından canlı sayılır; her hizmetin ne aldığı da yanında yazar. Böylece “her şey tarayıcınızda çalışır” sözü geliştirici araçları olmadan denetlenebilir. Burada hiçbir şey kaydedilmez: sayfayı yenilemek sıfırdan başlatır.',
  'egress.clear': 'Temizle',
  'egress.cleared': 'Temizlendi. Kayıt bundan sonrasını sayıyor.',
  'egress.since': '{time} itibarıyla',
  'egress.sum.requests': { other: 'üçüncü taraflara {count} istek' },
  'egress.sum.hosts': { other: '({count} sunucu)' },
  'egress.sum.self': { other: 'bu siteden {count} dosya' },
  'egress.sum.none': 'üçüncü taraflara hiçbir şey',
  'egress.col.service': 'Hizmet',
  'egress.col.requests': 'İstek',
  'egress.col.received': 'Ne aldı',
  'egress.col.last': 'Son',
  'egress.empty': 'Henüz istek yok.',
  'egress.self': 'Bu site',
  'egress.unknown': 'Kayıtta yok',
  'egress.unknownTitle': 'DomainScope’un kodu bu sunucuya hiçbir şey göndermez',
  'egress.unknownAlert': {
    one: '{count} sunucu DomainScope’un kullandığı bir hizmet değil ve kodu ona hiçbir şey göndermez. İsteği bu sayfaya bir tarayıcı eklentisi eklemiş olabilir.',
    other: '{count} sunucu DomainScope’un kullandığı bir hizmet değil ve kodu bunlara hiçbir şey göndermez. İstekleri bu sayfaya bir tarayıcı eklentisi eklemiş olabilir.'
  },
  'egress.failed': { other: '{count} tanesi yanıt almadı' },
  'egress.role.site': 'Uygulamanın kendi dosyaları',
  'egress.role.dns': 'DNS çözümleyici',
  'egress.role.ct': 'Certificate Transparency',
  'egress.role.passive': 'Alt alan adı ve pasif DNS verisi',
  'egress.role.ip': 'IP adresi verisi',
  'egress.role.registration': 'Kayıt verisi (RDAP)',
  'egress.role.probes': 'İnternetten kontroller',
  'egress.role.dnsHosting': 'DNS sağlayıcınız, sizin anahtarınızla',
  'egress.kind.appFiles': 'Size ait hiçbir şey: uygulamanın kendi dosyaları',
  'egress.kind.nothing': 'Size ait hiçbir şey: herkese açık bir liste ya da ücretsiz kota',
  'egress.kind.dnsQuestions': 'DNS adları ve kayıt türleri',
  'egress.kind.nameServers': 'Sorulacak ad sunucuları',
  'egress.kind.domains': 'Alan adları ve host adları',
  'egress.kind.hostnames': 'Kontrol edilecek host adları',
  'egress.kind.ipNamePairs': 'Genel IP, host adı ve port',
  'egress.kind.ipAddresses': 'IP adresleri ya da ağlar',
  'egress.kind.asNumbers': 'AS numaraları',
  'egress.kind.certSerial': 'Bir sertifika seri numarası',
  'egress.kind.keyHash': 'Bir açık anahtar SHA-256 değeri',
  'egress.kind.measurementIds': 'Sonuçları okumak için ölçüm kimlikleri',
  'egress.kind.apiToken': 'API anahtarınız, yalnızca o tek okuma için',
  'egress.neverTitle': 'Asla gönderilmeyenler',
  'egress.never.certificates': 'Sertifika dosyaları: bu sekmede okunur, hiçbir yere yüklenmez. Bir Certificate Transparency sorgusu yalnızca sorguladığınız şeyi gönderir — bir host adı, bir seri numarası ya da bir açık anahtar özeti.',
  'egress.never.keys': 'Özel anahtarlar, parolalar ve API anahtarları: özel anahtar hiçbir zaman gerekmez ve gösterilmez; PFX / P12 ya da devir dosyası parolası yalnızca bu sekmede kullanılır, saklanmaz ve gönderilmez. Zone Dosyası’na yapıştırdığınız DNS sağlayıcısı anahtarı yalnızca o sağlayıcıya, yalnızca o tek okuma için gider ve saklanmaz.',
  'egress.never.zone': 'İçe aktarılan zone dosyası: hiçbir yere yüklenmez ya da kaydedilmez; deSEC ya da DigitalOcean’dan alınan bir zone yalnızca onlardan okunur. Canlı kontrolü kayıt adlarını ve türlerini DNS çözümleyicilerinize, yeni ad sunucularıyla karşılaştırma ise bunları belirttiğiniz sunucularla birlikte Globalping’e gönderir — değerleri asla; içindeki bir origin adresi yalnızca Doğrula’nın isteğe bağlı asıl sunucu kontrolüyle çıkar.',
  'egress.never.inventory': 'Sunucu envanteriniz: hiçbir yere yüklenmez, sunucu adları asla gönderilmez. İçindeki bir adres yalnızca siz sorguladığınızda çıkar: Doğrula’nın isteğe bağlı asıl sunucu kontrolüyle ya da IP Bilgisi’nde “Sunucularımın IP’leri” ve “Sorgula” düğmeleriyle (RIPEstat ve ipwho.is’e; özel adresler asla gönderilmez).',
  'egress.never.workspace': 'Çalışma alanları: notlar, beklenen CA’lar ve saklanan listeler bu tarayıcıda kalır; bir çalışma alanı yalnızca sizin dışa aktardığınız devir dosyası olarak çıkar. Özel ve öğrenilen adlar, taradığınız alan adlarının altında DNS sorgusu olarak denenir.',
  'egress.never.tracking': 'Analitik, çerez ve izleme: hiçbiri yok; istekler referrer bilgisi taşımaz. Her web sitesinde olduğu gibi her hizmet IP adresinizi görür.',
  'egress.how': 'Nasıl sayılır: sayfanın kodunun başlattığı her istek ve tarayıcınızın bildirdiği her istek (Resource Timing), hangisi çoksa; yanıt almayan bir istek de sayılır. Bir hizmetin ne aldığı, bir testin kodla uyumlu tuttuğu DomainScope uç nokta kaydından gelir; adresin tek başına söyleyemediği durumda (Globalping kontrolünün türü) ise sayfanın kodunun istek hakkında söylediğinden gelir. Tarayıcınızın kendi adına yaptığı istekler (güncellemeleri, güvenli tarama kontrolleri) ve sizin açtığınız bağlantılar sayfaya ait değildir, listelenmez.',
  'egress.noResourceTiming': 'Bu tarayıcı Resource Timing bildirmiyor; yalnızca sayfanın kodunun başlattığı istekler sayılıyor.',
  'egress.version.bundle': 'Bu sayfa {version} sürümünü çalıştırıyor',
  'egress.version.commit': 'commit {commit}',
  'egress.version.noCommit': 'commit adı olmadan derlendi',
  'egress.version.unread': 'sürüm dosyası okunamadı',
  'egress.version.dev': 'Geliştirme kopyası: depodan olduğu gibi sunuluyor, bu yüzden bir yayın sürümü yok.'
});

/** Icons of the never-sent list, in {@link NEVER_SENT} order. */
const NEVER_ICONS = Object.freeze({
  certificates: 'certificate', keys: 'key', zone: 'file-text', inventory: 'server', workspace: 'briefcase', tracking: 'eye'
});
/** The table follows the log at most this often. */
const REFRESH_MS = 1000;

/** The page's own origin ('' outside a browser). */
const pageOrigin = () => (globalThis.location ? globalThis.location.origin : '');
const timeOf = (ms) => formatDate(ms, { timeStyle: 'medium' });

/**
 * "Domain and host names (2) · A public-key SHA-256 (1)" for a row: its kinds, with the requests
 * of each when the row has more than one endpoint.
 * @param {import('../lib/egress.js').LedgerRow} row
 * @returns {Array<{ kind: string, requests: number|null }>}
 */
export function receivedParts(row) {
  const counted = row.endpoints.filter((e) => e.id !== null || e.sends.length);
  if (counted.length < 2) return row.sends.map((kind) => ({ kind, requests: null }));
  const byKind = new Map();
  for (const e of counted) for (const kind of e.sends) byKind.set(kind, (byKind.get(kind) || 0) + e.requests);
  return row.sends.map((kind) => ({ kind, requests: byKind.get(kind) || 0 }));
}

function serviceCell(row) {
  const name = row.kind === 'self' ? t('egress.self') : row.kind === 'unknown' ? row.host : row.name;
  return h('div', { class: 'egress-service' },
    h('div', { class: 'egress-name' }, name,
      row.kind === 'unknown' ? [' ', Badge(t('egress.unknown'), { variant: 'warn', icon: 'alert', title: t('egress.unknownTitle') })] : null),
    row.kind !== 'unknown' ? h('div', { class: 'egress-host mono' }, row.host) : null,
    row.role ? h('div', { class: 'egress-role' }, t(`egress.role.${row.role}`)) : null);
}

function requestsCell(row) {
  return h('div', { class: 'egress-count' },
    h('span', { class: 'num' }, formatNumber(row.requests)),
    row.failed ? h('span', { class: 'egress-failed' }, t('egress.failed', { count: row.failed })) : null);
}

function receivedCell(row) {
  const parts = receivedParts(row);
  if (!parts.length) return h('span', { class: 'muted' }, '—');
  return h('ul', { class: 'egress-kinds' }, parts.map((p) => h('li', { dataset: { kind: p.kind } },
    t(`egress.kind.${p.kind}`), p.requests !== null ? h('span', { class: 'egress-kind-count num' }, ` (${formatNumber(p.requests)})`) : null)));
}

/**
 * The ledger panel.
 * @param {{ repoUrl: string, signal?: AbortSignal }} opts repoUrl: the commit link's repository
 * @returns {{ el: HTMLElement, dispose: () => void }}
 */
export function EgressPanel({ repoUrl, signal = null }) {
  const summary = h('p', { class: 'egress-summary', dataset: { role: 'egress-summary' } });
  const unknownHost = h('div', { class: 'egress-unknown' });
  const table = DataTable({
    caption: t('egress.title'),
    rows: [],
    rowKey: (r) => r.origin,
    dense: true,
    cellLabels: true,
    // a session contacts a few dozen hosts at most: the whole ledger shows, no inner scroll
    maxHeight: null,
    className: 'egress-table',
    empty: t('egress.empty'),
    rowClass: (r) => [`egress-row-${r.kind}`],
    columns: [
      { key: 'host', label: t('egress.col.service'), render: serviceCell, searchValue: (r) => `${r.name} ${r.host}` },
      { key: 'requests', label: t('egress.col.requests'), render: requestsCell },
      { key: 'sends', label: t('egress.col.received'), render: receivedCell, wrap: true },
      { key: 'last', label: t('egress.col.last'), render: (r) => h('span', { class: 'num' }, timeOf(r.last)) }
    ]
  });
  const clearBtn = Button({
    label: t('egress.clear'),
    icon: 'trash',
    size: 'sm',
    variant: 'secondary',
    dataset: { action: 'egress-clear' },
    onClick: () => {
      egressLog.clear();
      render();
      announce(t('egress.cleared'));
    }
  });
  const status = egressMeterStatus();
  const version = h('p', { class: 'egress-version text-sm', dataset: { role: 'egress-version' } });

  function render() {
    timer = null;
    const snap = egressLog.snapshot();
    const rows = ledgerRows(snap, { origin: pageOrigin() });
    const totals = ledgerTotals(rows);
    const pieces = [t('egress.since', { time: timeOf(snap.since) })];
    pieces.push(totals.requests
      ? `${t('egress.sum.requests', { count: totals.requests })} ${t('egress.sum.hosts', { count: totals.hosts })}`
      : t('egress.sum.none'));
    if (totals.self) pieces.push(t('egress.sum.self', { count: totals.self }));
    summary.textContent = pieces.join(' · ');
    summary.dataset.requests = String(totals.requests);
    clear(unknownHost);
    if (totals.unknown) unknownHost.append(Alert({ variant: 'warn', compact: true, message: t('egress.unknownAlert', { count: totals.unknown }) }));
    table.setRows(rows);
  }
  let timer = null;
  const off = egressLog.subscribe(() => {
    if (timer === null) timer = setTimeout(render, REFRESH_MS);
  });
  render();
  renderVersion(version, { repoUrl, signal });

  const el = h('div', { class: 'stack egress-panel' },
    h('div', { class: 'egress-head' }, summary, clearBtn),
    unknownHost,
    table.el,
    status.resourceTiming ? null : Alert({ variant: 'info', compact: true, message: t('egress.noResourceTiming') }),
    h('p', { class: 'muted text-sm egress-how' }, t('egress.how')),
    h('h3', { class: 'about-subtitle' }, t('egress.neverTitle')),
    h('ul', { class: 'about-privacy egress-never' }, NEVER_SENT.map((id) => h('li', { dataset: { never: id } },
      h('span', { class: 'about-privacy-icon' }, Icon(NEVER_ICONS[id] || 'x-circle', { size: 16 })), h('span', null, t(`egress.never.${id}`))))),
    version);
  return {
    el,
    dispose() {
      off();
      clearTimeout(timer);
      timer = null;
    }
  };
}

/**
 * The deploy line: the version the page's URL names, and the commit its version file gives (a
 * link to it). Only a page of the Pages bundle asks for the file; the repository has none. Until
 * the file answers the line names the deploy alone (`data-state="reading"`), so it never says
 * "no commit" of a bundle that has one.
 * @param {HTMLElement} host
 * @param {{ repoUrl: string, signal?: AbortSignal|null, moduleUrl?: string }} opts
 */
async function renderVersion(host, { repoUrl, signal, moduleUrl = import.meta.url }) {
  const info = bundleInfo(moduleUrl);
  if (!info) {
    host.textContent = t('egress.version.dev');
    host.dataset.version = '';
    return;
  }
  /** @param {'reading'|'read'|'unread'} state */
  const show = (file, state) => {
    clear(host);
    host.dataset.version = info.version;
    host.dataset.state = state;
    host.append(Icon('git-branch', { size: 14 }), ' ', t('egress.version.bundle', { version: info.version }));
    if (state === 'reading') return;
    host.append(' · ');
    if (file && file.commit) {
      host.append(ExternalLink(`${String(repoUrl).replace(/\/+$/, '')}/commit/${file.commit}`, t('egress.version.commit', { commit: file.commit.slice(0, 12) }), { className: 'mono' }));
    } else {
      host.append(t(state === 'unread' ? 'egress.version.unread' : 'egress.version.noCommit'));
    }
  };
  show(null, 'reading');
  let file = null;
  try {
    // A file of another version (a cache serving a newer deploy's) names nothing about this page:
    // it counts as unread, never as a deploy "built without a commit name".
    file = parseVersionFile(await fetchJson(versionFileUrl(moduleUrl), { signal: signal || undefined, timeoutMs: 8000, headers: { accept: 'application/json' } }),
      { version: info.version });
  } catch {
    file = null;
  }
  if (signal && signal.aborted) return;
  show(file, file ? 'read' : 'unread');
}
