/**
 * views/bulk.js — "Bulk Resolve": paste hundreds (or thousands) of hostnames and resolve
 * them all over DNS-over-HTTPS.
 *
 * Per hostname: DNS status, CNAME chain, IPv4 / IPv6, TTL, classification (Cloudflare /
 * CDN / platform / direct / private / NXDOMAIN / dangling CNAME), the matching servers of
 * the saved inventory and — optionally — reverse DNS (PTR) and ASN / owner (RIPEstat) of
 * its IPs. A second table turns the answer around: every IP address with the hostnames
 * that point to it, its owner and whether it is one of your servers.
 *
 * Like the SSL Targets scan, a running job belongs to this module: it keeps going when
 * another tool is opened and its results are shown again on return. Rows stream into the
 * tables (DataTable batches the rendering), so thousands of names stay responsive.
 *
 * Route params: `#/bulk?names=a.example.com,b.example.com` pre-fills the list; with `run=0` (a
 * name carried over from another tool, lib/session.js) only an empty list or one that still holds
 * the last job's names takes it. "Delete all local data" forgets the list and the last job (a
 * running one is stopped), whether or not the view is mounted.
 */

import { h, clear } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, DataTable, EmptyState, ErrorBanner, FileDrop, Icon, KeyValueList, KindBadge,
  ProgressBar, StatCard, Tabs, TruncatedList, announce, checkbox, copyText, ipSortValue, select, textarea, toast
} from '../ui/components.js';
import {
  t, registerStrings, formatNumber, formatDuration, formatDateTime, formatRegion
} from '../i18n.js';
import { normalizeHostname } from '../lib/domain.js';
import { classifyResolution, normalizeIP, isPrivateIP, ipVersion, matchProviderByIP } from '../lib/netinfo.js';
import { lookupServers } from '../lib/inventory.js';
import { createIpIntel } from '../lib/ipintel.js';
import { RESOLVERS, getResolver } from '../lib/resolvers.js';
import { errorKind, splitList } from '../lib/util.js';
import { commonTarget, fillReplaces, isFillOnly } from '../lib/session.js';
import { state as stateSingleton } from '../state.js';

/** Route id. */
export const id = 'bulk';
/** i18n key of the page title. */
export const titleKey = 'nav.bulk';
/** Nav/page icon. */
export const icon = 'list';

/** Most hostnames resolved in one run (a public-resolver courtesy limit). */
export const MAX_NAMES = 10000;
/** localStorage key for the options (a per-browser convenience). */
export const OPTIONS_KEY = 'ssds.bulk.options';
/** Simultaneous PTR lookups (on top of the DohClient's own limiter). */
const PTR_CONCURRENCY = 8;
/** Accepted list files. */
const ACCEPT = '.txt,.csv,.tsv,.list,.lst,.log,.json';
/** Host filter values of the "Show" select. */
export const BULK_FILTERS = Object.freeze(['all', 'resolving', 'hidden', 'direct', 'mine', 'unknown', 'unresolved', 'errors', 'dangling']);
/** IP filter values. */
export const IP_FILTERS = Object.freeze(['all', 'mine', 'unknown', 'cdn', 'private']);

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'bulk.inputTitle': 'Hostnames',
  'bulk.inputSubtitle': 'Paste a list, import a file, or reuse the names of the last scan',
  'bulk.inputLabel': 'Hostnames to resolve',
  'bulk.placeholder': 'www.example.com.tr\napi.example.com.tr\nmail.example.com.tr\n\n# one per line, or separated by spaces / commas; URLs are fine',
  'bulk.dropTitle': 'Import a list',
  'bulk.dropHint': 'text, CSV or JSON · drop, click or paste',
  'bulk.fromScan': 'Use the {count} names of the last scan',
  'bulk.fromScanTitle': 'Hosts found by the SSL Targets scan of {domains}',
  'bulk.clear': 'Clear',
  'bulk.parsed': { zero: 'No valid hostname yet', one: '{count} hostname', other: '{count} hostnames' },
  'bulk.duplicates': { one: '{count} duplicate removed', other: '{count} duplicates removed' },
  'bulk.invalid': { one: '{count} invalid entry', other: '{count} invalid entries' },
  'bulk.ipsIgnored': { one: '{count} IP address ignored — use IP Intel for addresses', other: '{count} IP addresses ignored — use IP Intel for addresses' },
  'bulk.tooMany': 'Only the first {max} hostnames are resolved.',
  'bulk.showInvalid': 'Show invalid entries',
  'bulk.optionsTitle': 'Options',
  'bulk.opt.ptr': 'Reverse DNS (PTR) of every IP',
  'bulk.opt.ptrHint': 'One extra DNS query per unique IP address.',
  'bulk.opt.asn': 'ASN, owner and country (RIPEstat)',
  'bulk.opt.asnHint': 'Looks up every unique public IP at stat.ripe.net (fallback ipwho.is). Slower for many IPs.',
  'bulk.opt.noCache': 'Bypass the cache',
  'bulk.opt.noCacheHint': 'Ask the resolvers again even for names looked up a moment ago (after a DNS change).',
  'bulk.opt.resolver': 'Resolver',
  'bulk.opt.chain': 'Failover chain from Settings ({chain})',
  'bulk.opt.concurrency': 'Parallel queries: {n} (Settings)',
  'bulk.run': 'Resolve',
  'bulk.runAgain': 'Resolve again',
  'bulk.cancel': 'Cancel',
  'bulk.required': 'Enter at least one valid hostname.',
  'bulk.busy': 'Resolving…',

  'bulk.progress.resolve': 'Resolving hostnames',
  'bulk.progress.done': 'Done',
  'bulk.progress.cancelled': 'Cancelled',
  'bulk.enrich': 'IP details: {done} / {total}',
  'bulk.finished': 'Resolved {count} in {time}',
  'bulk.finishedAt': 'finished {when}',
  'bulk.cancelledNote': 'Cancelled — {done} of {total} hostnames were resolved.',
  'bulk.failed': 'Resolving failed',
  'bulk.doneToast': { one: 'Bulk resolve finished: {count} hostname', other: 'Bulk resolve finished: {count} hostnames' },
  'bulk.showResults': 'Show results',

  'bulk.stat.names': 'Hostnames',
  'bulk.stat.namesHint': '{count} resolving',
  'bulk.stat.hidden': 'Behind CDN / proxy',
  'bulk.stat.hiddenHint': '{count} Cloudflare',
  'bulk.stat.direct': 'Direct IP',
  'bulk.stat.directHint': { zero: 'none on your servers', one: '{count} on your servers', other: '{count} on your servers' },
  'bulk.stat.unresolved': 'Not resolving',
  'bulk.stat.unresolvedHint': { zero: 'no lookup errors', one: '{count} lookup error', other: '{count} lookup errors' },
  'bulk.stat.ips': 'Unique IPs',
  'bulk.stat.ipsHint': '{v4} IPv4 · {v6} IPv6',
  'bulk.stat.servers': 'Your servers',
  'bulk.stat.serversHint': 'matched by IP',
  'bulk.stat.serversNone': 'no inventory saved',

  'bulk.tab.hosts': 'Hostnames',
  'bulk.tab.ips': 'IP addresses',
  'bulk.col.name': 'Hostname',
  'bulk.col.status': 'Status',
  'bulk.col.cname': 'CNAME chain',
  'bulk.col.ipv4': 'IPv4',
  'bulk.col.ipv6': 'IPv6',
  'bulk.col.ttl': 'TTL',
  'bulk.col.ptr': 'PTR',
  'bulk.col.asn': 'ASN / owner',
  'bulk.col.servers': 'Your servers',
  'bulk.col.ip': 'IP address',
  'bulk.col.type': 'Type',
  'bulk.col.hosts': 'Hostnames',
  'bulk.col.count': 'Names',
  'bulk.col.country': 'Country',
  'bulk.col.prefix': 'Prefix',
  'bulk.filter.show': 'Show',
  'bulk.filter.all': 'All',
  'bulk.filter.resolving': 'Resolving',
  'bulk.filter.hidden': 'Behind CDN / proxy',
  'bulk.filter.direct': 'Direct IP',
  'bulk.filter.mine': 'On my servers',
  'bulk.filter.unknown': 'Public IP, not my server',
  'bulk.filter.unresolved': 'Not resolving',
  'bulk.filter.errors': 'Lookup errors',
  'bulk.filter.dangling': 'Dangling CNAME',
  'bulk.filter.cdn': 'CDN / platform',
  'bulk.filter.private': 'Private IP',
  'bulk.ip.private': 'private',
  'bulk.ip.public': 'public',
  'bulk.pending': 'looking up…',
  'bulk.skipped': 'not looked up',
  'bulk.skippedTitle': 'The run was cancelled before this address was looked up',
  'bulk.copyIps': 'Copy IPs',
  'bulk.copyResolving': 'Copy resolving names',
  'bulk.copied': { one: '{count} line copied', other: '{count} lines copied' },
  'bulk.hosts.empty': 'Results appear here as the names are resolved.',
  'bulk.ips.empty': 'IP addresses appear here as the names are resolved.',
  'bulk.hosts.caption': 'Resolved hostnames',
  'bulk.ips.caption': 'IP addresses and the names pointing to them',
  'bulk.ips.intro': 'Every address the names resolved to, with the names that point to it — handy to spot shared servers and IPs that are not in your inventory.',
  'bulk.d.dns': 'DNS answer',
  'bulk.d.dnsValue': '{status} · {resolver} · TTL {ttl}',
  'bulk.d.reason': 'Why',
  'bulk.d.error': 'Error',
  'bulk.d.tools': 'Open in',
  'bulk.d.ede': 'Extended DNS error',
  'bulk.emptyTitle': 'Resolve many hostnames at once',
  'bulk.emptyBody': 'Paste the list on the left: every name is resolved in your browser over DNS-over-HTTPS, classified (Cloudflare, CDN, direct …) and matched to your saved servers.'
});

registerStrings('tr', {
  'bulk.inputTitle': 'Host adları',
  'bulk.inputSubtitle': 'Liste yapıştırın, dosya içe aktarın ya da son taramanın adlarını kullanın',
  'bulk.inputLabel': 'Çözümlenecek host adları',
  'bulk.placeholder': 'www.example.com.tr\napi.example.com.tr\nmail.example.com.tr\n\n# her satıra bir ad, ya da boşluk / virgülle ayrılmış; URL de olur',
  'bulk.dropTitle': 'Liste içe aktar',
  'bulk.dropHint': 'metin, CSV veya JSON · bırakın, tıklayın ya da yapıştırın',
  'bulk.fromScan': 'Son taramadaki {count} adı kullan',
  'bulk.fromScanTitle': '{domains} için SSL Hedefleri taramasında bulunan host’lar',
  'bulk.clear': 'Temizle',
  'bulk.parsed': { zero: 'Henüz geçerli host adı yok', one: '{count} host adı', other: '{count} host adı' },
  'bulk.duplicates': { one: '{count} tekrar kaldırıldı', other: '{count} tekrar kaldırıldı' },
  'bulk.invalid': { one: '{count} geçersiz girdi', other: '{count} geçersiz girdi' },
  'bulk.ipsIgnored': { one: '{count} IP adresi yok sayıldı — adresler için IP Bilgisi’ni kullanın', other: '{count} IP adresi yok sayıldı — adresler için IP Bilgisi’ni kullanın' },
  'bulk.tooMany': 'Yalnızca ilk {max} host adı çözümlenir.',
  'bulk.showInvalid': 'Geçersiz girdileri göster',
  'bulk.optionsTitle': 'Seçenekler',
  'bulk.opt.ptr': 'Her IP’nin ters DNS (PTR) kaydı',
  'bulk.opt.ptrHint': 'Her benzersiz IP adresi için bir ek DNS sorgusu.',
  'bulk.opt.asn': 'ASN, sahip ve ülke (RIPEstat)',
  'bulk.opt.asnHint': 'Her benzersiz genel IP’yi stat.ripe.net’te sorgular (yedek: ipwho.is). Çok sayıda IP’de daha yavaştır.',
  'bulk.opt.noCache': 'Önbelleği atla',
  'bulk.opt.noCacheHint': 'Az önce sorgulanan adlar için bile çözümleyicilere yeniden sorar (DNS değişikliğinden sonra).',
  'bulk.opt.resolver': 'Çözümleyici',
  'bulk.opt.chain': 'Ayarlar’daki yedekleme zinciri ({chain})',
  'bulk.opt.concurrency': 'Paralel sorgu: {n} (Ayarlar)',
  'bulk.run': 'Çözümle',
  'bulk.runAgain': 'Yeniden çözümle',
  'bulk.cancel': 'İptal et',
  'bulk.required': 'En az bir geçerli host adı girin.',
  'bulk.busy': 'Çözümleniyor…',

  'bulk.progress.resolve': 'Host adları çözümleniyor',
  'bulk.progress.done': 'Tamamlandı',
  'bulk.progress.cancelled': 'İptal edildi',
  'bulk.enrich': 'IP ayrıntıları: {done} / {total}',
  'bulk.finished': '{count} ad {time} içinde çözümlendi',
  'bulk.finishedAt': '{when} tamamlandı',
  'bulk.cancelledNote': 'İptal edildi — {total} host adından {done} tanesi çözümlendi.',
  'bulk.failed': 'Çözümleme başarısız oldu',
  'bulk.doneToast': { one: 'Toplu çözümleme bitti: {count} host adı', other: 'Toplu çözümleme bitti: {count} host adı' },
  'bulk.showResults': 'Sonuçları göster',

  'bulk.stat.names': 'Host adları',
  'bulk.stat.namesHint': '{count} tanesi çözümleniyor',
  'bulk.stat.hidden': 'CDN / proxy arkasında',
  'bulk.stat.hiddenHint': '{count} tanesi Cloudflare',
  'bulk.stat.direct': 'Doğrudan IP',
  'bulk.stat.directHint': { zero: 'hiçbiri sunucularınızda değil', one: '{count} tanesi sunucularınızda', other: '{count} tanesi sunucularınızda' },
  'bulk.stat.unresolved': 'Çözümlenmeyen',
  'bulk.stat.unresolvedHint': { zero: 'sorgu hatası yok', one: '{count} sorgu hatası', other: '{count} sorgu hatası' },
  'bulk.stat.ips': 'Benzersiz IP',
  'bulk.stat.ipsHint': '{v4} IPv4 · {v6} IPv6',
  'bulk.stat.servers': 'Sunucularınız',
  'bulk.stat.serversHint': 'IP ile eşleşen',
  'bulk.stat.serversNone': 'kayıtlı envanter yok',

  'bulk.tab.hosts': 'Host adları',
  'bulk.tab.ips': 'IP adresleri',
  'bulk.col.name': 'Host adı',
  'bulk.col.status': 'Durum',
  'bulk.col.cname': 'CNAME zinciri',
  'bulk.col.ipv4': 'IPv4',
  'bulk.col.ipv6': 'IPv6',
  'bulk.col.ttl': 'TTL',
  'bulk.col.ptr': 'PTR',
  'bulk.col.asn': 'ASN / sahip',
  'bulk.col.servers': 'Sunucularınız',
  'bulk.col.ip': 'IP adresi',
  'bulk.col.type': 'Tür',
  'bulk.col.hosts': 'Host adları',
  'bulk.col.count': 'Ad',
  'bulk.col.country': 'Ülke',
  'bulk.col.prefix': 'Önek',
  'bulk.filter.show': 'Göster',
  'bulk.filter.all': 'Tümü',
  'bulk.filter.resolving': 'Çözümlenenler',
  'bulk.filter.hidden': 'CDN / proxy arkasındakiler',
  'bulk.filter.direct': 'Doğrudan IP',
  'bulk.filter.mine': 'Sunucularımdakiler',
  'bulk.filter.unknown': 'Genel IP, sunucum değil',
  'bulk.filter.unresolved': 'Çözümlenmeyenler',
  'bulk.filter.errors': 'Sorgu hataları',
  'bulk.filter.dangling': 'Sahipsiz CNAME',
  'bulk.filter.cdn': 'CDN / platform',
  'bulk.filter.private': 'Özel IP',
  'bulk.ip.private': 'özel',
  'bulk.ip.public': 'genel',
  'bulk.pending': 'sorgulanıyor…',
  'bulk.skipped': 'sorgulanmadı',
  'bulk.skippedTitle': 'Çalıştırma bu adres sorgulanmadan iptal edildi',
  'bulk.copyIps': 'IP’leri kopyala',
  'bulk.copyResolving': 'Çözümlenen adları kopyala',
  'bulk.copied': { one: '{count} satır kopyalandı', other: '{count} satır kopyalandı' },
  'bulk.hosts.empty': 'Adlar çözümlendikçe sonuçlar burada görünür.',
  'bulk.ips.empty': 'Adlar çözümlendikçe IP adresleri burada görünür.',
  'bulk.hosts.caption': 'Çözümlenen host adları',
  'bulk.ips.caption': 'IP adresleri ve onlara işaret eden adlar',
  'bulk.ips.intro': 'Adların çözümlendiği her adres ve ona işaret eden adlar — ortak sunucuları ve envanterinizde olmayan IP’leri görmek için kullanışlı.',
  'bulk.d.dns': 'DNS yanıtı',
  'bulk.d.dnsValue': '{status} · {resolver} · TTL {ttl}',
  'bulk.d.reason': 'Neden',
  'bulk.d.error': 'Hata',
  'bulk.d.tools': 'Şurada aç',
  'bulk.d.ede': 'Genişletilmiş DNS hatası',
  'bulk.emptyTitle': 'Çok sayıda host adını tek seferde çözümleyin',
  'bulk.emptyBody': 'Listeyi soldaki alana yapıştırın: her ad tarayıcınızda DNS-over-HTTPS ile çözümlenir, sınıflandırılır (Cloudflare, CDN, doğrudan …) ve kayıtlı sunucularınızla eşleştirilir.'
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for the E2E checks)                               */
/* ------------------------------------------------------------------------ */

/** Object keys whose string values are host names in JSON input (API and tool output). */
const JSON_NAME_KEY = /^(?:names?|hosts?|host_?names?|domains?|fqdns?|subdomains?|dns_?names?|common_?name|name_value)$/i;

/**
 * Host-name tokens of a parsed JSON value: every string of an array, and of an object only the
 * values of name-like keys ({@link JSON_NAME_KEY}) — `type`, `ttl`, `source` … are not names.
 * @param {any} node
 * @param {string|null} [key] the object key `node` is the value of (null: a list item / the top)
 * @param {string[]} [out]
 * @returns {string[]}
 */
function jsonTokens(node, key = null, out = []) {
  const named = key === null || JSON_NAME_KEY.test(key);
  if (typeof node === 'string') {
    if (named) out.push(...splitList(node));
  } else if (Array.isArray(node)) {
    for (const item of node) jsonTokens(item, named ? null : key, out);
  } else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) jsonTokens(v, k, out);
  }
  return out;
}

/** Every string of a parsed JSON value, whatever its key. */
function jsonStrings(node, out = []) {
  if (typeof node === 'string') out.push(...splitList(node));
  else if (node && typeof node === 'object') for (const v of Object.values(node)) jsonStrings(v, out);
  return out;
}

/**
 * Tokens of the pasted text or imported file. A JSON document (`jq -c`, JSON.stringify, API
 * output) or JSON lines (one object per line) are read with {@link jsonTokens}, so brackets,
 * quotes and field names never end up as "invalid entries"; anything else is a plain list. A
 * JSON value with no name-like key (`{"results": [...]}`) gives every string instead, so the
 * user sees names or invalid entries rather than nothing.
 * @param {string} text
 * @returns {string[]}
 */
function inputTokens(text) {
  const json = (s) => {
    const trimmed = s.trim();
    if (!/^[[{]/.test(trimmed)) return null;
    try {
      const doc = JSON.parse(trimmed);
      const tokens = jsonTokens(doc);
      return tokens.length ? tokens : jsonStrings(doc);
    } catch {
      return null;
    }
  };
  return json(text) ?? text.split(/\r\n|\r|\n/).flatMap((line) => json(line) ?? splitList(line));
}

/**
 * Parse the pasted list: hostnames (normalized, de-duplicated, input order), invalid
 * tokens, IP addresses (reported separately — they belong in IP Intel) and duplicates.
 * JSON (an array, an object, or JSON lines) is accepted too.
 * @param {string} text
 * @param {{ max?: number }} [opts]
 * @returns {{ names: string[], invalid: string[], ips: string[], duplicates: number, truncated: boolean, total: number }}
 */
export function parseBulkInput(text, { max = MAX_NAMES } = {}) {
  const names = [];
  const seen = new Set();
  const invalid = new Set();
  const ips = new Set();
  let duplicates = 0;
  for (const tok of inputTokens(String(text ?? ''))) {
    const host = normalizeHostname(tok);
    if (host) {
      if (seen.has(host)) duplicates += 1;
      else {
        seen.add(host);
        names.push(host);
      }
    } else if (normalizeIP(tok)) {
      ips.add(tok);
    } else {
      invalid.add(tok);
    }
  }
  return {
    names: names.slice(0, max),
    invalid: [...invalid],
    ips: [...ips],
    duplicates,
    truncated: names.length > max,
    total: names.length
  };
}

/**
 * Validate stored options.
 * @param {any} input
 * @returns {{ ptr: boolean, asn: boolean, noCache: boolean, resolver: string }}
 */
export function sanitizeBulkOptions(input) {
  const src = input && typeof input === 'object' ? input : {};
  const resolver = typeof src.resolver === 'string' && RESOLVERS.some((r) => r.id === src.resolver) ? src.resolver : '';
  return { ptr: src.ptr === true, asn: src.asn === true, noCache: src.noCache === true, resolver };
}

/**
 * Does a bulk row match a "Show" filter?
 * @param {{ resolution: object, classification: object, servers: object[], ips: string[] }} row
 * @param {string} filter one of {@link BULK_FILTERS}
 * @returns {boolean}
 */
export function bulkRowMatches(row, filter) {
  const c = row.classification || {};
  const res = row.resolution || {};
  switch (filter) {
    case 'resolving': return row.ips.length > 0;
    case 'hidden': return !!c.hidesOrigin;
    case 'direct': return c.kind === 'direct' || c.kind === 'private';
    case 'mine': return row.servers.length > 0;
    case 'unknown': return (c.kind === 'direct') && row.servers.length === 0;
    case 'unresolved': return row.ips.length === 0;
    case 'errors': return res.status !== 'NOERROR' && res.status !== 'NXDOMAIN';
    case 'dangling': return !!c.dangling;
    default: return true;
  }
}

/**
 * Does an IP row match an IP filter?
 * @param {{ private: boolean, provider: object|null, servers: object[] }} row
 * @param {string} filter one of {@link IP_FILTERS}
 * @returns {boolean}
 */
export function ipRowMatches(row, filter) {
  switch (filter) {
    case 'mine': return row.servers.length > 0;
    case 'unknown': return !row.private && !row.provider && row.servers.length === 0;
    case 'cdn': return !!row.provider;
    case 'private': return row.private;
    default: return true;
  }
}

/**
 * Statistics over bulk rows and IP rows.
 * @param {object[]} rows
 * @param {Map<string, object>|object[]} ipRows
 * @returns {{ total: number, resolved: number, hidden: number, cloudflare: number, direct: number, onServers: number,
 *   unresolved: number, errors: number, ips: number, v4: number, v6: number, servers: number }}
 */
export function bulkStats(rows, ipRows) {
  const s = { total: 0, resolved: 0, hidden: 0, cloudflare: 0, direct: 0, onServers: 0, unresolved: 0, errors: 0, ips: 0, v4: 0, v6: 0, servers: 0 };
  const servers = new Set();
  for (const r of rows || []) {
    s.total += 1;
    const c = r.classification || {};
    if (r.ips.length) s.resolved += 1;
    else s.unresolved += 1;
    if (c.hidesOrigin) s.hidden += 1;
    if (c.kind === 'cloudflare') s.cloudflare += 1;
    if (c.kind === 'direct' || c.kind === 'private') {
      s.direct += 1;
      if (r.servers.length) s.onServers += 1;
    }
    if (r.resolution.status !== 'NOERROR' && r.resolution.status !== 'NXDOMAIN') s.errors += 1;
    for (const m of r.servers) servers.add(m.serverId);
  }
  const ips = ipRows instanceof Map ? [...ipRows.values()] : ipRows || [];
  for (const ip of ips) {
    s.ips += 1;
    if (ip.version === 6) s.v6 += 1;
    else s.v4 += 1;
  }
  s.servers = servers.size;
  return s;
}

/* ------------------------------------------------------------------------ */
/* Jobs (module-owned: they outlive a mounted view)                         */
/* ------------------------------------------------------------------------ */

const session = { text: null, job: null };
let jobCounter = 0;
let active = null;

/** The names of the page's last job, or null (what a carried name may replace, lib/session.js). */
const lastJobNames = () => (session.job ? session.job.names : null);
/** The names a list holds, as a job would resolve them. */
const listNames = (text) => parseBulkInput(text).names;

// "Delete all local data" (About, or Settings on any view) forgets the pasted list and the last
// job, stopping one that runs; the shell opens the view again when it is on screen.
stateSingleton.subscribe(({ key }) => {
  if (key !== 'cleared') return;
  const job = session.job;
  if (job && job.status === 'running') job.controller.abort();
  session.job = null;
  session.text = null;
});

function loadOptions() {
  try {
    const raw = globalThis.localStorage && globalThis.localStorage.getItem(OPTIONS_KEY);
    return sanitizeBulkOptions(raw ? JSON.parse(raw) : null);
  } catch {
    return sanitizeBulkOptions(null);
  }
}

function saveOptions(o) {
  try {
    if (globalThis.localStorage) globalThis.localStorage.setItem(OPTIONS_KEY, JSON.stringify(sanitizeBulkOptions(o)));
  } catch {
    // not remembered — fine
  }
}

function emit(job, type, payload) {
  for (const fn of [...job.listeners]) {
    try {
      fn(type, payload);
    } catch (err) {
      setTimeout(() => {
        throw err;
      }, 0);
    }
  }
}

function newIpRow(ip, index) {
  const priv = isPrivateIP(ip);
  return {
    ip,
    version: ipVersion(ip),
    private: priv,
    provider: matchProviderByIP(ip),
    hosts: [],
    servers: lookupServers([ip], index).map(({ server }) => ({ serverId: server.id, name: server.name })),
    ptr: null,
    info: null,
    enriching: false,
    enrichError: null,
    skipped: false
  };
}

/** Run `fn` over items with at most `limit` in flight; rejects on the first error (e.g. AbortError). */
async function pool(items, limit, fn, signal) {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      if (signal && signal.aborted) throw new DOMException('Aborted', 'AbortError');
      const i = next;
      next += 1;
      await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
}

/**
 * @typedef {object} BulkJob
 * @property {number} id
 * @property {string[]} names
 * @property {{ ptr: boolean, asn: boolean, noCache: boolean, resolver: string }} options
 * @property {AbortController} controller
 * @property {'running'|'done'|'cancelled'|'error'} status
 * @property {object[]} rows resolved rows (completion order)
 * @property {Map<string, object>} ips IP rows by address
 * @property {number} done
 * @property {number} ipTotal IPs queued for PTR / ASN lookups
 * @property {number} ipDone
 * @property {Date} startedAt
 * @property {Date|null} finishedAt
 * @property {unknown} error
 * @property {Set<Function>} listeners
 */

/**
 * A new job (not started). Internal: exported for the tests only.
 * @param {string[]} names
 * @param {BulkJob['options']} options
 * @returns {BulkJob}
 */
export function createJob(names, options) {
  jobCounter += 1;
  return {
    id: jobCounter,
    names,
    options,
    controller: new AbortController(),
    status: 'running',
    rows: [],
    ips: new Map(),
    done: 0,
    ipTotal: 0,
    ipDone: 0,
    startedAt: new Date(),
    finishedAt: null,
    error: null,
    listeners: new Set()
  };
}

/**
 * Resolve every name, then enrich each new IP (PTR, or ASN / owner with its PTR); rejects with
 * AbortError when the job's controller aborts. Internal: exported for the tests only.
 * @param {BulkJob} job
 * @param {{ dns: object, index: object|null, concurrency: number, fetchImpl?: typeof fetch }} deps
 *   fetchImpl: for the intel APIs (tests)
 * @returns {Promise<void>}
 */
export async function runJob(job, { dns, index, concurrency, fetchImpl }) {
  const { signal } = job.controller;
  const opts = job.options;
  const resolver = opts.resolver || undefined;
  // The intel service looks the PTR up itself: send it to the resolver chosen for this run too.
  const intelDns = resolver ? { ptr: (ip, o = {}) => dns.ptr(ip, { ...o, resolver }) } : dns;
  const intel = opts.asn ? createIpIntel({ dns: intelDns, concurrency: 4, fetchImpl }) : null;
  const enrichQueue = [];
  let enrichRunning = 0;
  let enrichIdle = null;
  let idleResolve = null;

  const enrichOne = async (row) => {
    row.enriching = true;
    try {
      if (intel && !row.private) {
        const info = await intel.info(row.ip, { signal });
        row.info = info;
        row.ptr = info.ptr || [];
        if (info.error) row.enrichError = info.error;
      } else if (opts.ptr && !row.private) {
        row.ptr = await dns.ptr(row.ip, { signal, resolver });
      } else {
        row.ptr = [];
      }
    } catch (err) {
      if (errorKind(err) === 'abort') throw err;
      row.enrichError = String((err && err.message) || err);
      row.ptr = row.ptr || [];
    } finally {
      row.enriching = false;
    }
  };
  const pump = () => {
    const limit = intel ? 4 : PTR_CONCURRENCY;
    while (enrichRunning < limit && enrichQueue.length && !signal.aborted) {
      const row = enrichQueue.shift();
      enrichRunning += 1;
      // Only a finished lookup counts as done (a cancelled one rejects with AbortError).
      enrichOne(row).then(() => { job.ipDone += 1; }, () => {}).then(() => {
        enrichRunning -= 1;
        emit(job, 'ip', row);
        if (!enrichQueue.length && !enrichRunning && idleResolve) idleResolve();
        pump();
      });
    }
  };
  // Cancel: IPs still queued or in flight are never looked up. Mark them `skipped` so the tables
  // say "not looked up" instead of "looking up…" for good (an answer that still arrives wins).
  const skip = (row) => {
    if (row.private || row.ptr !== null) return;
    row.ptr = [];
    row.skipped = true;
    row.enriching = false;
  };
  if (opts.ptr || opts.asn) signal.addEventListener('abort', () => job.ips.forEach(skip), { once: true });
  const enrich = (row) => {
    if (!opts.ptr && !opts.asn) return;
    job.ipTotal += 1;
    if (signal.aborted) {
      skip(row);
      return;
    }
    enrichQueue.push(row);
    pump();
  };

  // Each name costs two queries (A + AAAA); the shared DohClient's limiter still caps the
  // HTTP requests in flight at the Settings value, so keep twice as many names queued.
  await pool(job.names, Math.max(2, concurrency * 2), async (name) => {
    const resolution = await dns.resolveHost(name, { signal, resolver, noCache: opts.noCache });
    const ips = [...resolution.ipv4, ...resolution.ipv6];
    const row = {
      name,
      resolution,
      classification: classifyResolution(resolution),
      ips,
      servers: lookupServers(ips, index).map(({ server, ip }) => ({ serverId: server.id, name: server.name, ip }))
    };
    job.rows.push(row);
    job.done += 1;
    for (const ip of ips) {
      let ipRow = job.ips.get(ip);
      const fresh = !ipRow;
      if (fresh) {
        ipRow = newIpRow(ip, index);
        job.ips.set(ip, ipRow);
      }
      if (!ipRow.hosts.includes(name)) ipRow.hosts.push(name);
      emit(job, fresh ? 'ip-new' : 'ip', ipRow);
      if (fresh) enrich(ipRow);
    }
    emit(job, 'row', row);
  }, signal);

  if (enrichQueue.length || enrichRunning) {
    enrichIdle = new Promise((resolve) => { idleResolve = resolve; });
    const onAbort = () => idleResolve && idleResolve();
    signal.addEventListener('abort', onAbort, { once: true });
    await enrichIdle;
    signal.removeEventListener('abort', onAbort);
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
  }
}

function startJob(job, deps) {
  runJob(job, deps).then(() => {
    job.status = 'done';
    job.finishedAt = new Date();
    emit(job, 'done', null);
    if (!active) {
      toast(t('bulk.doneToast', { count: job.rows.length }), {
        type: 'success',
        timeout: 10000,
        action: {
          label: t('bulk.showResults'),
          onClick: () => {
            globalThis.location.hash = '#/bulk';
          }
        }
      });
    }
  }, (err) => {
    job.finishedAt = new Date();
    if (errorKind(err) === 'abort') {
      job.status = 'cancelled';
      emit(job, 'cancelled', null);
    } else {
      job.status = 'error';
      job.error = err;
      emit(job, 'error', err);
    }
  });
}

/** Call `fn` at most every `ms` (trailing call guaranteed). */
function throttle(fn, ms) {
  let timer = null;
  let last = 0;
  return () => {
    const wait = Math.max(0, ms - (Date.now() - last));
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      last = Date.now();
      fn();
    }, wait);
  };
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mount the Bulk Resolve view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { state } = ctx;
  let options = loadOptions();
  const cleanups = [];

  // ctx.params.names is the last of the (possibly repeated) ?names= values, so read either
  // every value or that one — never both (that listed each name twice → "N duplicates removed").
  const routeNames = ctx.searchParams && ctx.searchParams.getAll ? ctx.searchParams.getAll('names') : [ctx.params.names || ''];
  const fromRoute = splitList(routeNames.join('\n'));
  // A name carried over from another tool (`run=0`, lib/session.js) never replaces a pasted list:
  // only an empty one or the last job's names.
  if (fromRoute.length && (!isFillOnly(ctx.params) || fillReplaces(session.text, lastJobNames(), listNames))) {
    session.text = fromRoute.join('\n');
  }
  if (session.text === null) session.text = '';

  /* --- input ------------------------------------------------------------------------ */
  const area = textarea({
    label: t('bulk.inputLabel'),
    rows: 12,
    value: session.text,
    placeholder: t('bulk.placeholder'),
    attrs: { 'data-role': 'bulk-input', 'data-shortcut': 'focus' },
    className: 'bulk-input-field',
    onInput: (v) => {
      session.text = v;
      area.setError(null);
      renderParse();
    }
  });
  area.el.querySelector('.field-label').classList.add('sr-only');
  const parseInfo = h('div', { class: 'bulk-parse text-sm', attrs: { 'aria-live': 'polite' } });
  const drop = FileDrop({
    accept: ACCEPT,
    multiple: true,
    compact: true,
    icon: 'upload',
    title: t('bulk.dropTitle'),
    hint: t('bulk.dropHint'),
    maxBytes: 8 * 1024 * 1024,
    onFiles: (files) => {
      const text = files.map((f) => f.text.replace(/\s+$/, '')).join('\n');
      area.value = area.value.trim() ? `${area.value.replace(/\s+$/, '')}\n${text}\n` : `${text}\n`;
      session.text = area.value;
      renderParse();
    }
  });
  const scanNames = h('div', { class: 'bulk-from-scan' });
  const clearBtn = Button({
    label: t('bulk.clear'), icon: 'trash', variant: 'ghost', size: 'sm', dataset: { action: 'bulk-clear' },
    onClick: () => {
      area.value = '';
      session.text = '';
      renderParse();
      area.focus();
    }
  });

  function renderScanNames() {
    clear(scanNames);
    const last = state.getSession('scanHosts');
    if (!last || !Array.isArray(last.names) || !last.names.length) return;
    scanNames.append(Button({
      label: t('bulk.fromScan', { count: formatNumber(last.names.length) }),
      icon: 'target',
      size: 'sm',
      variant: 'secondary',
      title: t('bulk.fromScanTitle', { domains: (last.domains || []).join(', ') }),
      dataset: { action: 'bulk-from-scan' },
      onClick: () => {
        area.value = `${last.names.join('\n')}\n`;
        session.text = area.value;
        renderParse();
      }
    }));
  }

  let parsed = parseBulkInput(area.value);
  function renderParse() {
    parsed = parseBulkInput(area.value);
    clear(parseInfo);
    const bits = [Badge(t('bulk.parsed', { count: parsed.names.length }), { variant: parsed.names.length ? 'ok' : 'neutral', icon: parsed.names.length ? 'check' : null })];
    if (parsed.duplicates) bits.push(Badge(t('bulk.duplicates', { count: parsed.duplicates }), { variant: 'neutral' }));
    if (parsed.invalid.length) bits.push(Badge(t('bulk.invalid', { count: parsed.invalid.length }), { variant: 'warn', icon: 'alert', title: parsed.invalid.slice(0, 20).join(' ') }));
    if (parsed.ips.length) bits.push(Badge(t('bulk.ipsIgnored', { count: parsed.ips.length }), { variant: 'info', icon: 'info' }));
    if (parsed.truncated) bits.push(Badge(t('bulk.tooMany', { max: formatNumber(MAX_NAMES) }), { variant: 'warn', icon: 'alert' }));
    parseInfo.append(h('div', { class: 'cluster' }, bits));
    if (parsed.invalid.length) {
      parseInfo.append(h('details', { class: 'bulk-invalid' },
        h('summary', null, t('bulk.showInvalid')),
        h('div', { class: 'mono text-sm bulk-invalid-list' }, parsed.invalid.slice(0, 200).join('\n'))));
    }
    runBtn.disabled = !parsed.names.length || !!(session.job && session.job.status === 'running');
  }

  /* --- options ---------------------------------------------------------------------------- */
  const ptrBox = checkbox({ label: t('bulk.opt.ptr'), hint: t('bulk.opt.ptrHint'), checked: options.ptr, onChange: (on) => setOption('ptr', on) });
  const asnBox = checkbox({ label: t('bulk.opt.asn'), hint: t('bulk.opt.asnHint'), checked: options.asn, onChange: (on) => setOption('asn', on) });
  const cacheBox = checkbox({ label: t('bulk.opt.noCache'), hint: t('bulk.opt.noCacheHint'), checked: options.noCache, onChange: (on) => setOption('noCache', on) });
  ptrBox.input.dataset.option = 'ptr';
  asnBox.input.dataset.option = 'asn';
  cacheBox.input.dataset.option = 'noCache';
  const chainLabel = () => state.settings.chain.map((rid) => (getResolver(rid) || { name: rid }).name).join(' → ');
  const resolverSelect = select({
    label: t('bulk.opt.resolver'),
    value: options.resolver,
    options: [{ value: '', label: t('bulk.opt.chain', { chain: chainLabel() }) }, ...RESOLVERS.map((r) => ({ value: r.id, label: r.name }))],
    onChange: (v) => setOption('resolver', v)
  });
  resolverSelect.input.dataset.role = 'bulk-resolver';
  const concurrencyNote = h('p', { class: 'muted text-sm' });
  const renderConcurrency = () => {
    concurrencyNote.textContent = t('bulk.opt.concurrency', { n: formatNumber(state.settings.concurrency) });
  };
  function setOption(key, value) {
    options = { ...options, [key]: value };
    saveOptions(options);
  }

  const runBtn = Button({ label: t('bulk.run'), icon: 'play', variant: 'primary', dataset: { action: 'bulk-run', shortcut: 'submit' }, onClick: () => start() });
  const cancelBtn = Button({ label: t('bulk.cancel'), icon: 'stop', dataset: { action: 'bulk-cancel', shortcut: 'cancel' }, onClick: () => cancel() });
  cancelBtn.hidden = true;

  const inputCard = Card({
    title: t('bulk.inputTitle'),
    subtitle: t('bulk.inputSubtitle'),
    icon: 'list',
    className: 'bulk-input',
    children: h('div', { class: 'bulk-input-grid' },
      h('div', { class: 'stack bulk-input-main' },
        drop,
        h('div', { class: 'bulk-input-tools' }, scanNames, clearBtn),
        area.el,
        parseInfo),
      h('div', { class: 'stack bulk-side' },
        h('div', { class: 'field-label' }, t('bulk.optionsTitle')),
        h('div', { class: 'stack-sm' }, ptrBox.el, asnBox.el, cacheBox.el),
        h('div', { class: 'stack-sm' }, resolverSelect.el, concurrencyNote),
        h('div', { class: 'bulk-actions' }, runBtn, cancelBtn)))
  });

  // The results are no part of the form: Ctrl/Cmd+Enter in a filter there starts no new run.
  const resultsHost = h('div', { class: 'bulk-results-host', dataset: { shortcutScope: 'results' } });
  container.append(h('div', { class: 'bulk-layout' }, inputCard, resultsHost));

  renderScanNames();
  renderParse();
  renderConcurrency();

  cleanups.push(state.subscribe(({ key, value }) => {
    if (key === 'settings') {
      renderConcurrency();
      resolverSelect.setOptions([{ value: '', label: t('bulk.opt.chain', { chain: chainLabel() }) }, ...RESOLVERS.map((r) => ({ value: r.id, label: r.name }))]);
    }
    if (key === 'session' && value && value.name === 'scanHosts') renderScanNames();
  }));

  /* --- jobs ---------------------------------------------------------------------------------- */
  let ui = null;

  function setRunning(on) {
    runBtn.hidden = on;
    cancelBtn.hidden = !on;
    runBtn.querySelector('.btn-label').textContent = session.job && !on ? t('bulk.runAgain') : t('bulk.run');
    runBtn.disabled = !parsed.names.length;
    ctx.setBusy(on ? t('bulk.busy') : false);
  }

  let starting = false;
  async function start() {
    // `starting` covers the await below, so a double click cannot start two jobs.
    if (starting || (session.job && session.job.status === 'running')) return;
    renderParse();
    if (!parsed.names.length) {
      area.setError(t('bulk.required'));
      area.focus();
      return;
    }
    let dns;
    starting = true;
    try {
      dns = await ctx.getDns();
    } catch (err) {
      clear(resultsHost);
      resultsHost.append(ErrorBanner(err, { title: t('bulk.failed') }));
      return;
    } finally {
      starting = false;
    }
    if (ctx.signal.aborted) return;
    const one = commonTarget(parsed.names);
    ctx.runStarted(one ? one.value : null);
    const job = createJob(parsed.names.slice(), { ...options });
    job.inventoryServers = state.inventory.servers.length;
    session.job = job;
    attach(job);
    startJob(job, { dns, index: ctx.getInventoryIndex(), concurrency: state.settings.concurrency });
  }

  function cancel() {
    if (session.job && session.job.status === 'running') session.job.controller.abort();
  }

  function attach(job) {
    if (ui) ui.dispose();
    clear(resultsHost);
    ui = buildJobUI(job, ctx, { onFinish: () => setRunning(false) });
    resultsHost.append(ui.el);
    setRunning(job.status === 'running');
  }

  if (session.job) attach(session.job);
  else {
    resultsHost.append(Card({
      padded: false,
      className: 'bulk-intro',
      children: EmptyState({ icon: 'list', title: t('bulk.emptyTitle'), message: t('bulk.emptyBody') })
    }));
  }

  active = {
    // "Run again" of the kept-result note: the last job's names (with the options as set now).
    rerun() {
      const job = session.job;
      if (job && job.status !== 'running') {
        area.value = job.names.join('\n');
        session.text = area.value;
        area.setError(null);
      }
      start();
    },
    applyParams(p) {
      const list = splitList(p.names || '');
      if (!list.length) return;
      if (isFillOnly(p) && !fillReplaces(area.value, lastJobNames(), listNames)) return;
      area.value = list.join('\n');
      session.text = area.value;
      renderParse();
    }
  };

  return () => {
    cleanups.forEach((fn) => fn());
    if (ui) ui.dispose();
    ui = null;
    active = null;
  };
}

/**
 * Take new route params (`#/bulk?names=…`) without re-mounting.
 * @param {Record<string, string>} params
 * @returns {boolean}
 */
export function update(params) {
  if (!active) return false;
  active.applyParams(params);
  return true;
}

/** Nothing else to clean up (a running job continues in the background). */
export function unmount() {}

/**
 * The page's last job once it has ended, or null while none has or one runs. It stays in this
 * module, so the shell keeps only the fact (lib/session.js).
 * @returns {{ subject: string|null, at: Date }|null}
 */
export function result() {
  const job = session.job;
  if (!job || job.status === 'running' || !job.finishedAt) return null;
  const one = commonTarget(job.names);
  return { subject: one ? one.value : job.names[0] || null, at: job.finishedAt };
}

/** "Run again" of the kept-result note: resolve the last job's names again. */
export function rerun() {
  if (active) active.rerun();
}

export default { id, titleKey, icon, mount, unmount, update, result, rerun };

/* ------------------------------------------------------------------------ */
/* Job UI                                                                   */
/* ------------------------------------------------------------------------ */

function buildJobUI(job, ctx, { onFinish }) {
  const opts = job.options;
  const showPtr = opts.ptr || opts.asn;
  const showAsn = opts.asn;

  /* progress */
  const progress = ProgressBar({ label: t('bulk.progress.resolve') });
  const meta = h('div', { class: 'bulk-meta text-sm muted' });
  const enrichLine = h('div', { class: 'bulk-enrich text-sm muted' });
  const notice = h('div');

  /* stats */
  const inv = job.inventoryServers > 0;
  const stat = {
    names: StatCard({ label: t('bulk.stat.names'), icon: 'list', variant: 'accent', onClick: () => setHostFilter('all'), pressed: true }),
    hidden: StatCard({ label: t('bulk.stat.hidden'), icon: 'cloud', variant: 'cloudflare', onClick: () => setHostFilter('hidden'), pressed: false }),
    direct: StatCard({ label: t('bulk.stat.direct'), icon: 'server', variant: 'direct', onClick: () => setHostFilter('direct'), pressed: false }),
    unresolved: StatCard({ label: t('bulk.stat.unresolved'), icon: 'x-circle', variant: 'nxdomain', onClick: () => setHostFilter('unresolved'), pressed: false }),
    ips: StatCard({ label: t('bulk.stat.ips'), icon: 'network', variant: 'info', onClick: () => tabs.select('ips', { focus: true }) }),
    servers: StatCard({ label: t('bulk.stat.servers'), icon: 'server', variant: 'warn', onClick: () => (inv ? setHostFilter('mine') : null) })
  };
  const statFilters = { names: 'all', hidden: 'hidden', direct: 'direct', unresolved: 'unresolved', servers: 'mine' };
  const statsGrid = h('div', { class: 'stat-grid bulk-stats' });
  Object.entries(stat).forEach(([k, s]) => {
    s.el.dataset.stat = k;
    statsGrid.append(s.el);
  });

  const renderStats = throttle(() => {
    const s = bulkStats(job.rows, job.ips);
    stat.names.set({ value: s.total, hint: t('bulk.stat.namesHint', { count: formatNumber(s.resolved) }) });
    stat.hidden.set({ value: s.hidden, hint: t('bulk.stat.hiddenHint', { count: formatNumber(s.cloudflare) }) });
    stat.direct.set({ value: s.direct, hint: inv ? t('bulk.stat.directHint', { count: s.onServers }) : null });
    stat.unresolved.set({ value: s.unresolved, hint: t('bulk.stat.unresolvedHint', { count: s.errors }), variant: s.errors ? 'error' : 'nxdomain' });
    stat.ips.set({ value: s.ips, hint: t('bulk.stat.ipsHint', { v4: formatNumber(s.v4), v6: formatNumber(s.v6) }) });
    stat.servers.set({ value: inv ? s.servers : '—', hint: inv ? t('bulk.stat.serversHint') : t('bulk.stat.serversNone') });
  }, 120);

  /* hosts table */
  const hostFilterSel = select({
    label: t('bulk.filter.show'),
    size: 'sm',
    value: 'all',
    className: 'bulk-filter',
    options: BULK_FILTERS.map((f) => ({ value: f, label: t(`bulk.filter.${f}`) })),
    onChange: (v) => setHostFilter(v, false)
  });
  hostFilterSel.input.dataset.role = 'bulk-filter';
  let hostFilter = 'all';
  function setHostFilter(f, selectTab = true) {
    hostFilter = f;
    hostFilterSel.value = f;
    hostsTable.setFilter(f === 'all' ? null : (row) => bulkRowMatches(row, f));
    for (const [k, v] of Object.entries(statFilters)) stat[k].set({ pressed: v === f });
    if (selectTab) tabs.select('hosts');
  }

  const ipOf = (ip) => job.ips.get(ip);
  const ptrText = (row) => {
    const out = [];
    for (const ip of row.ips) {
      const r = ipOf(ip);
      if (r && Array.isArray(r.ptr)) out.push(...r.ptr);
    }
    return [...new Set(out)];
  };
  const asnText = (row) => {
    const out = [];
    for (const ip of row.ips) {
      const r = ipOf(ip);
      if (r && r.info && r.info.asn) {
        const label = `AS${r.info.asn}${r.info.holder ? ` ${r.info.holder}` : ''}`;
        if (!out.includes(label)) out.push(label);
      }
    }
    return out;
  };
  const enrichPending = (row) => row.ips.some((ip) => {
    const r = ipOf(ip);
    return r && !r.private && (r.enriching || r.ptr === null);
  });
  /** Cells of IPs a cancelled run never looked up (`skipped`, see runJob). */
  const enrichSkipped = (row) => row.ips.some((ip) => ipOf(ip)?.skipped);
  const pendingCell = () => h('span', { class: 'muted text-sm' }, t('bulk.pending'));
  const skippedCell = () => h('span', { class: 'muted text-sm', title: t('bulk.skippedTitle') }, t('bulk.skipped'));

  const copyBtn = (labelKey, getLines, action) => Button({
    label: t(labelKey),
    icon: 'copy',
    size: 'sm',
    variant: 'ghost',
    dataset: { action },
    onClick: async () => {
      const lines = getLines();
      const ok = await copyText(lines.join('\n'));
      toast(ok ? t('bulk.copied', { count: lines.length }) : t('common.copyFailed'), { type: ok ? 'success' : 'error', timeout: 2500 });
    }
  });

  const hostsTable = DataTable({
    caption: t('bulk.hosts.caption'),
    search: true,
    pageSize: 200,
    empty: t('bulk.hosts.empty'),
    rowKey: (r) => r.name,
    className: 'bulk-hosts',
    rowClass: (r) => ({ 'bulk-row-error': r.resolution.status !== 'NOERROR' && r.resolution.status !== 'NXDOMAIN' }),
    toolbar: h('div', { class: 'bulk-toolbar' }, hostFilterSel.el,
      copyBtn('bulk.copyResolving', () => hostsTable.getVisibleRows().filter((r) => r.ips.length).map((r) => r.name), 'bulk-copy-names')),
    details: (r) => rowDetails(r, ctx),
    export: { filename: 'bulk-resolve', subject: job.names[0] },
    // Most useful first (the table scrolls horizontally on narrow screens).
    columns: [
      { key: 'name', label: t('bulk.col.name'), sortable: true, mono: true, sortValue: (r) => r.name.split('.').reverse().join('.'), searchValue: (r) => r.name, exportValue: (r) => r.name },
      {
        key: 'status', label: t('bulk.col.status'), sortable: true,
        sortValue: (r) => `${r.classification.dangling ? 'a' : 'b'}${r.classification.kind}`,
        searchValue: (r) => `${r.resolution.status} ${t(`kind.${r.classification.dangling ? 'dangling' : r.classification.kind}`)} ${r.classification.provider ? r.classification.provider.name : ''}`,
        exportValue: (r) => `${r.resolution.status}${r.classification.kind ? ` ${r.classification.dangling ? 'dangling' : r.classification.kind}` : ''}${r.classification.provider ? ` ${r.classification.provider.name}` : ''}`,
        render: (r) => h('div', { class: 'cluster bulk-status' }, KindBadge(r.classification),
          r.resolution.status !== 'NOERROR' && r.resolution.status !== 'NXDOMAIN'
            ? Badge(r.resolution.status, { variant: 'error', mono: true, title: r.resolution.error || '' }) : null)
      },
      {
        key: 'ipv4', label: t('bulk.col.ipv4'), sortable: true, mono: true,
        sortValue: (r) => ipSortValue(r.resolution.ipv4[0]),
        searchValue: (r) => r.resolution.ipv4.join(' '),
        exportValue: (r) => r.resolution.ipv4.join(' '),
        render: (r) => (r.resolution.ipv4.length ? TruncatedList(r.resolution.ipv4, { max: 2 }) : null)
      },
      {
        key: 'servers', label: t('bulk.col.servers'), sortable: true,
        sortValue: (r) => (r.servers[0] ? r.servers[0].name : ''),
        searchValue: (r) => r.servers.map((s) => `${s.name} ${s.ip}`).join(' '),
        exportValue: (r) => r.servers.map((s) => `${s.name} (${s.ip})`).join(' '),
        render: (r) => (r.servers.length
          ? TruncatedList(r.servers, { max: 2, mono: false, render: (s) => h('span', { class: 'bulk-server', title: s.ip }, Icon('server', { size: 12 }), ' ', s.name) })
          : null)
      },
      showPtr ? {
        key: 'ptr', label: t('bulk.col.ptr'), mono: true, sortable: true,
        sortValue: (r) => ptrText(r)[0] || '',
        searchValue: (r) => ptrText(r).join(' '),
        exportValue: (r) => ptrText(r).join(' '),
        render: (r) => {
          const list = ptrText(r);
          if (list.length) return TruncatedList(list, { max: 2 });
          return enrichPending(r) ? pendingCell() : enrichSkipped(r) ? skippedCell() : null;
        }
      } : null,
      showAsn ? {
        key: 'asn', label: t('bulk.col.asn'), sortable: true, wrap: true,
        sortValue: (r) => asnText(r)[0] || '',
        searchValue: (r) => asnText(r).join(' '),
        exportValue: (r) => asnText(r).join(' | '),
        render: (r) => {
          const list = asnText(r);
          if (list.length) return TruncatedList(list, { max: 2, mono: false });
          return enrichPending(r) ? pendingCell() : enrichSkipped(r) ? skippedCell() : null;
        }
      } : null,
      {
        key: 'cname', label: t('bulk.col.cname'), sortable: true, mono: true,
        sortValue: (r) => r.resolution.cnames[r.resolution.cnames.length - 1] || '',
        searchValue: (r) => r.resolution.cnames.join(' '),
        exportValue: (r) => r.resolution.cnames.join(' > '),
        // The final target tells where the name really lives; the full chain is in the details / export.
        render: (r) => {
          const chain = r.resolution.cnames;
          if (!chain.length) return null;
          return h('span', { class: 'bulk-cname', title: chain.join(' → ') }, chain[chain.length - 1],
            chain.length > 1 ? h('span', { class: 'muted' }, ` (+${chain.length - 1})`) : null);
        }
      },
      {
        key: 'ipv6', label: t('bulk.col.ipv6'), sortable: true, mono: true,
        sortValue: (r) => ipSortValue(r.resolution.ipv6[0]),
        searchValue: (r) => r.resolution.ipv6.join(' '),
        exportValue: (r) => r.resolution.ipv6.join(' '),
        render: (r) => (r.resolution.ipv6.length ? TruncatedList(r.resolution.ipv6, { max: 1 }) : null)
      },
      {
        key: 'ttl', label: t('bulk.col.ttl'), sortable: true, align: 'end', className: 'num',
        sortValue: (r) => (Number.isFinite(r.resolution.ttl) ? r.resolution.ttl : null),
        exportValue: (r) => (Number.isFinite(r.resolution.ttl) ? r.resolution.ttl : ''),
        render: (r) => (Number.isFinite(r.resolution.ttl) ? formatNumber(r.resolution.ttl) : null)
      }
    ].filter(Boolean)
  });

  /* IP table */
  const ipFilterSel = select({
    label: t('bulk.filter.show'),
    size: 'sm',
    value: 'all',
    className: 'bulk-filter',
    options: IP_FILTERS.map((f) => ({ value: f, label: t(`bulk.filter.${f}`) })),
    onChange: (v) => ipTable.setFilter(v === 'all' ? null : (row) => ipRowMatches(row, v))
  });
  ipFilterSel.input.dataset.role = 'bulk-ip-filter';
  const ipTable = DataTable({
    caption: t('bulk.ips.caption'),
    search: true,
    pageSize: 200,
    empty: t('bulk.ips.empty'),
    rowKey: (r) => r.ip,
    sort: { key: 'count', dir: 'desc' },
    className: 'bulk-ips',
    toolbar: h('div', { class: 'bulk-toolbar' }, ipFilterSel.el,
      copyBtn('bulk.copyIps', () => ipTable.getVisibleRows().map((r) => r.ip), 'bulk-copy-ips')),
    export: { filename: 'bulk-ips', subject: job.names[0] },
    columns: [
      { key: 'ip', label: t('bulk.col.ip'), sortable: true, mono: true, sortValue: (r) => ipSortValue(r.ip) },
      {
        key: 'type', label: t('bulk.col.type'), sortable: true,
        sortValue: (r) => (r.private ? 'a' : r.provider ? `b${r.provider.name}` : 'c'),
        searchValue: (r) => (r.private ? t('bulk.ip.private') : r.provider ? r.provider.name : t('bulk.ip.public')),
        exportValue: (r) => (r.private ? 'private' : r.provider ? r.provider.name : 'public'),
        render: (r) => (r.private ? Badge(t('bulk.ip.private'), { variant: 'private', icon: 'lock' })
          : r.provider ? Badge(r.provider.name, { variant: r.provider.id === 'cloudflare' ? 'cloudflare' : r.provider.hidesOrigin ? 'cdn' : 'platform' })
            : Badge(t('bulk.ip.public'), { variant: 'direct', icon: 'server' }))
      },
      {
        key: 'count', label: t('bulk.col.count'), sortable: true, align: 'end', className: 'num', defaultDir: 'desc',
        sortValue: (r) => r.hosts.length,
        exportValue: (r) => r.hosts.length,
        render: (r) => formatNumber(r.hosts.length)
      },
      {
        key: 'hosts', label: t('bulk.col.hosts'), mono: true,
        searchValue: (r) => r.hosts.join(' '),
        exportValue: (r) => r.hosts.join(' '),
        render: (r) => TruncatedList(r.hosts, { max: 3 })
      },
      {
        key: 'servers', label: t('bulk.col.servers'), sortable: true,
        sortValue: (r) => (r.servers[0] ? r.servers[0].name : ''),
        searchValue: (r) => r.servers.map((s) => s.name).join(' '),
        exportValue: (r) => r.servers.map((s) => s.name).join(' '),
        render: (r) => (r.servers.length ? h('div', { class: 'cluster' }, r.servers.map((s) => Badge(s.name, { variant: 'direct', icon: 'server' }))) : null)
      },
      showPtr ? {
        key: 'ptr', label: t('bulk.col.ptr'), sortable: true, mono: true,
        sortValue: (r) => (r.ptr && r.ptr[0]) || '',
        searchValue: (r) => (r.ptr || []).join(' '),
        exportValue: (r) => (r.ptr || []).join(' '),
        render: (r) => (r.ptr && r.ptr.length ? TruncatedList(r.ptr, { max: 2 })
          : (!r.private && (r.enriching || r.ptr === null) ? pendingCell() : r.skipped ? skippedCell() : null))
      } : null,
      showAsn ? {
        key: 'asn', label: t('bulk.col.asn'), sortable: true, wrap: true,
        sortValue: (r) => (r.info && r.info.asn) || null,
        searchValue: (r) => (r.info ? `AS${r.info.asn || ''} ${r.info.holder || ''}` : ''),
        exportValue: (r) => (r.info && r.info.asn ? `AS${r.info.asn} ${r.info.holder || ''}`.trim() : ''),
        render: (r) => (r.info && r.info.asn
          ? h('span', null, h('span', { class: 'mono' }, `AS${r.info.asn}`), r.info.holder ? ` ${r.info.holder}` : '')
          : (!r.private && (r.enriching || r.ptr === null) ? pendingCell()
            : r.skipped ? skippedCell()
              : (r.enrichError ? Badge(t('common.error'), { variant: 'error', title: r.enrichError }) : null)))
      } : null,
      showAsn ? {
        key: 'country', label: t('bulk.col.country'), sortable: true,
        sortValue: (r) => (r.info && r.info.country) || '',
        searchValue: (r) => (r.info && r.info.country ? `${r.info.country} ${formatRegion(r.info.country)}` : ''),
        exportValue: (r) => (r.info && r.info.country) || '',
        render: (r) => (r.info && r.info.country
          ? h('span', { title: r.info.city || '' }, `${formatRegion(r.info.country, r.info.country)}`)
          : null)
      } : null,
      showAsn ? {
        key: 'prefix', label: t('bulk.col.prefix'), sortable: true, mono: true,
        sortValue: (r) => (r.info && r.info.prefix) || '',
        exportValue: (r) => (r.info && r.info.prefix) || '',
        render: (r) => (r.info && r.info.prefix ? r.info.prefix : null)
      } : null
    ].filter(Boolean)
  });

  const tabs = Tabs([
    { id: 'hosts', label: t('bulk.tab.hosts'), icon: 'list', content: hostsTable.el },
    {
      id: 'ips', label: t('bulk.tab.ips'), icon: 'network',
      content: h('div', { class: 'stack-sm' }, h('p', { class: 'muted text-sm' }, t('bulk.ips.intro')), ipTable.el)
    }
  ], { label: t('nav.bulk'), className: 'bulk-tabs' });

  const progressCard = h('div', { class: 'card bulk-progress', dataset: { status: job.status } },
    h('div', { class: 'stack-sm' }, progress, h('div', { class: 'bulk-progress-foot' }, meta, enrichLine)), notice);
  const el = h('div', { class: 'stack bulk-results', dataset: { job: job.id } }, progressCard, statsGrid, tabs);

  /* live rendering */
  const refreshHosts = throttle(() => hostsTable.refresh(), 300);
  const refreshIps = throttle(() => ipTable.refresh(), 300);
  const renderBadges = throttle(() => {
    tabs.setBadge('hosts', job.rows.length);
    tabs.setBadge('ips', job.ips.size || null);
  }, 150);
  const renderProgress = throttle(() => {
    if (job.status === 'running') progress.set(job.done, job.names.length);
    meta.textContent = job.status === 'running'
      ? formatDuration(Date.now() - job.startedAt)
      : `${t('bulk.finished', { count: formatNumber(job.done), time: formatDuration((job.finishedAt || new Date()) - job.startedAt) })} · ${t('bulk.finishedAt', { when: formatDateTime(job.finishedAt || new Date()) })}`;
    enrichLine.textContent = job.ipTotal ? t('bulk.enrich', { done: formatNumber(job.ipDone), total: formatNumber(job.ipTotal) }) : '';
  }, 100);

  function finish() {
    clear(notice);
    progressCard.dataset.status = job.status;
    if (job.status === 'done') {
      progress.done(t('bulk.progress.done'));
      progress.setVariant('ok');
      announce(t('bulk.doneToast', { count: job.rows.length }));
    } else if (job.status === 'cancelled') {
      progress.setVariant('warn');
      progress.setLabel(t('bulk.progress.cancelled'));
      notice.append(Alert({ variant: 'warn', compact: true, message: t('bulk.cancelledNote', { done: formatNumber(job.done), total: formatNumber(job.names.length) }) }));
    } else if (job.status === 'error') {
      progress.setVariant('error');
      notice.append(ErrorBanner(job.error, { title: t('bulk.failed') }));
    }
    hostsTable.setLoading(false);
    hostsTable.refresh();
    ipTable.refresh();
    renderStats();
    renderBadges();
    renderProgress();
    stopTicker();
    onFinish();
  }

  let ticker = null;
  function stopTicker() {
    if (ticker) clearInterval(ticker);
    ticker = null;
  }

  const listener = (type, payload) => {
    switch (type) {
      case 'row':
        hostsTable.addRows([payload]);
        renderStats();
        renderBadges();
        renderProgress();
        break;
      case 'ip-new':
        ipTable.addRows([payload]);
        renderBadges();
        renderStats();
        break;
      case 'ip':
        refreshIps();
        if (showPtr) refreshHosts();
        renderProgress();
        break;
      case 'done':
      case 'cancelled':
      case 'error':
        finish();
        break;
      default:
        break;
    }
  };

  // Replay, then follow.
  if (job.rows.length) hostsTable.setRows(job.rows);
  if (job.ips.size) ipTable.setRows([...job.ips.values()]);
  hostsTable.setLoading(job.status === 'running');
  renderStats();
  renderBadges();
  renderProgress();
  if (job.status === 'running') {
    ticker = setInterval(renderProgress, 1000);
    job.listeners.add(listener);
  } else {
    finish();
  }

  return {
    el,
    dispose() {
      job.listeners.delete(listener);
      stopTicker();
    }
  };
}

/** Expanded row: full DNS answer, reason, links to the other tools. */
function rowDetails(row, ctx) {
  const res = row.resolution;
  const c = row.classification;
  const resolver = res.resolver ? (getResolver(res.resolver) || { name: res.resolver }).name : '—';
  return KeyValueList([
    { key: t('bulk.d.dns'), value: t('bulk.d.dnsValue', { status: res.status, resolver, ttl: Number.isFinite(res.ttl) ? formatNumber(res.ttl) : '—' }) },
    { key: t('bulk.d.reason'), value: t(c.reasonKey, { provider: c.provider ? c.provider.name : t('common.unknown') }) },
    res.cnames.length ? { key: t('bulk.col.cname'), value: res.cnames.join(' → '), mono: true, copy: true } : null,
    res.ipv4.length ? { key: t('bulk.col.ipv4'), value: res.ipv4.join(', '), mono: true, copy: true } : null,
    res.ipv6.length ? { key: t('bulk.col.ipv6'), value: res.ipv6.join(', '), mono: true, copy: true } : null,
    res.ede && res.ede.length ? { key: t('bulk.d.ede'), value: res.ede.map((e) => `${e.code} ${e.name || ''}${e.text ? `: ${e.text}` : ''}`).join('; ') } : null,
    res.error ? { key: t('bulk.d.error'), value: res.error, mono: true } : null,
    {
      key: t('bulk.d.tools'),
      value: h('div', { class: 'cluster' },
        h('a', { class: 'btn btn-ghost btn-sm', href: ctx.href('global', { name: row.name, type: 'A' }) }, Icon('globe', { size: 14 }), h('span', { class: 'btn-label' }, t('nav.global'))),
        h('a', { class: 'btn btn-ghost btn-sm', href: ctx.href('lookup', { name: row.name, type: 'A' }) }, Icon('search', { size: 14 }), h('span', { class: 'btn-label' }, t('nav.lookup'))))
    }
  ], { className: 'bulk-details' });
}
