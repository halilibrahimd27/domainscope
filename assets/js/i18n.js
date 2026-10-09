/**
 * i18n.js — tiny translation layer (Turkish + English) and locale-aware formatting.
 *
 * - `t(key, params)` looks the key up in the current language, then English, then
 *   returns the key itself (and records it in {@link getMissingKeys}).
 * - `{name}` placeholders are replaced from `params`; unknown placeholders stay as-is.
 * - A string can be a plural object `{ zero?, one, other, … }`: the form is picked with
 *   `Intl.PluralRules` from `params.count` (`zero` is an explicit override for 0).
 *   A numeric `{count}` is rendered with locale digit grouping in plain strings and plural
 *   forms alike ('5,000' / '5.000').
 * - Views register their own strings at module load:
 *     registerStrings('en', { 'lookup.run': 'Look up', 'lookup.records': { one: '{count} record', other: '{count} records' } });
 *     registerStrings('tr', { 'lookup.run': 'Sorgula', 'lookup.records': '{count} kayıt' });
 *   Nested objects are flattened with dots ({ lookup: { run: 'x' } } → 'lookup.run').
 *
 * DOM-free at import time (no document/localStorage access), so it is unit-testable in Node.
 */

/** Supported UI languages, in toggle order. */
export const LANGS = Object.freeze(['tr', 'en']);

/** Fallback language for missing strings. */
export const DEFAULT_LANG = 'en';

/** BCP 47 tags used for Intl formatting. */
const LOCALE_TAGS = { tr: 'tr-TR', en: 'en-US' };

const PLURAL_CATEGORIES = new Set(['zero', 'one', 'two', 'few', 'many', 'other']);

/** @type {Record<string, Map<string, string|object>>} */
const dictionaries = { tr: new Map(), en: new Map() };
/** @type {Set<(lang: string, prev: string) => void>} */
const listeners = new Set();
/** @type {Map<string, { lang: string, key: string }>} */
const missing = new Map();

let currentLang = DEFAULT_LANG;

/**
 * Normalize a language tag to a supported language ('tr-TR' → 'tr'), or null.
 * @param {unknown} value
 * @returns {'tr'|'en'|null}
 */
export function normalizeLang(value) {
  if (typeof value !== 'string') return null;
  const base = value.trim().toLowerCase().split(/[-_]/)[0];
  return LANGS.includes(base) ? /** @type {'tr'|'en'} */ (base) : null;
}

/**
 * Pick the initial language: an explicitly saved choice wins; otherwise the browser's
 * first preferred language ('tr*' → Turkish, anything else → English).
 * @param {{ saved?: string|null, languages?: string[]|readonly string[], language?: string }} [opts]
 * @returns {'tr'|'en'}
 */
export function detectLang({ saved = null, languages, language } = {}) {
  const fromSaved = normalizeLang(saved);
  if (fromSaved) return fromSaved;
  const first = (Array.isArray(languages) && languages.length ? languages[0] : language) || '';
  return normalizeLang(first) === 'tr' ? 'tr' : 'en';
}

function isPluralForms(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length > 0 && keys.includes('other') && keys.every((k) => PLURAL_CATEGORIES.has(k));
}

function flatten(dict, prefix, out) {
  for (const [k, v] of Object.entries(dict || {})) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'string' || isPluralForms(v)) out.set(key, v);
    else if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
  }
  return out;
}

/**
 * Add (or override) strings for a language. Later registrations win per key.
 * @param {'tr'|'en'} lang
 * @param {Record<string, string|object>} dict flat dotted keys and/or nested objects;
 *   values are strings or plural objects `{ zero?, one?, other }`.
 * @returns {number} number of keys registered
 */
export function registerStrings(lang, dict) {
  const l = normalizeLang(lang);
  if (!l) throw new RangeError(`i18n: unsupported language "${lang}"`);
  const flat = flatten(dict, '', new Map());
  for (const [k, v] of flat) {
    dictionaries[l].set(k, v);
    missing.delete(`${l}:${k}`);
  }
  return flat.size;
}

/**
 * Does `key` exist for `lang` (default: current) — without falling back?
 * @param {string} key
 * @param {'tr'|'en'} [lang]
 * @returns {boolean}
 */
export function hasString(key, lang = currentLang) {
  const l = normalizeLang(lang) || currentLang;
  return dictionaries[l].has(key);
}

/** `key` as stored for `lang`, with no fallback, or undefined (the palette searches both languages). */
export const stringIn = (lang, key) => dictionaries[normalizeLang(lang) || currentLang].get(key);

/** @returns {'tr'|'en'} the current language */
export function getLang() {
  return /** @type {'tr'|'en'} */ (currentLang);
}

/**
 * BCP 47 locale for Intl APIs ('tr-TR' / 'en-US').
 * @param {'tr'|'en'} [lang]
 * @returns {string}
 */
export function localeTag(lang = currentLang) {
  return LOCALE_TAGS[normalizeLang(lang) || currentLang];
}

/**
 * Switch language. Listeners run only when it actually changes.
 * @param {string} lang
 * @returns {boolean} true when the language changed
 */
export function setLang(lang) {
  const l = normalizeLang(lang);
  if (!l || l === currentLang) return false;
  const prev = currentLang;
  currentLang = l;
  for (const fn of [...listeners]) {
    try {
      fn(l, prev);
    } catch (err) {
      // A faulty listener must not stop the others; surface it asynchronously.
      setTimeout(() => {
        throw err;
      }, 0);
    }
  }
  return true;
}

/**
 * Subscribe to language changes.
 * @param {(lang: 'tr'|'en', prev: 'tr'|'en') => void} fn
 * @returns {() => void} unsubscribe
 */
export function onLangChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function stringifyParam(value) {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return formatDateTime(value);
  if (Array.isArray(value)) return value.map(stringifyParam).join(', ');
  return String(value);
}

/**
 * Replace `{name}` placeholders. Placeholders without a matching param are left intact
 * (so a missing param is visible instead of silently empty); null/undefined params → ''.
 * Date params are formatted with {@link formatDateTime}; arrays are joined with ', '.
 * @param {string} template
 * @param {Record<string, unknown>} [params]
 * @returns {string}
 */
export function interpolate(template, params) {
  const str = String(template ?? '');
  if (!params || typeof params !== 'object') return str;
  return str.replace(/\{([A-Za-z0-9_.-]+)\}/g, (whole, name) => (
    Object.prototype.hasOwnProperty.call(params, name) ? stringifyParam(params[name]) : whole
  ));
}

/**
 * Choose a plural form. `zero` (if present) is used for exactly 0; otherwise the
 * CLDR category for `count` in `lang`, falling back to `other`.
 * @param {number} count
 * @param {{ zero?: string, one?: string, two?: string, few?: string, many?: string, other: string }} forms
 * @param {'tr'|'en'} [lang]
 * @returns {string}
 */
export function plural(count, forms, lang = currentLang) {
  if (!forms || typeof forms !== 'object') return '';
  const n = Number(count);
  if (n === 0 && typeof forms.zero === 'string') return forms.zero;
  let cat = 'other';
  if (Number.isFinite(n)) {
    try {
      cat = new Intl.PluralRules(localeTag(lang)).select(n);
    } catch {
      cat = n === 1 ? 'one' : 'other';
    }
  }
  return typeof forms[cat] === 'string' ? forms[cat] : (forms.other ?? '');
}

function lookup(key) {
  if (dictionaries[currentLang].has(key)) return dictionaries[currentLang].get(key);
  if (!missing.has(`${currentLang}:${key}`)) missing.set(`${currentLang}:${key}`, { lang: currentLang, key });
  if (currentLang !== DEFAULT_LANG && dictionaries[DEFAULT_LANG].has(key)) return dictionaries[DEFAULT_LANG].get(key);
  return undefined;
}

/**
 * Translate `key` with `{name}` interpolation and plural support. A numeric `count` param is
 * locale-grouped ({@link formatNumber}) in plain strings and plural forms alike.
 * Fallback: current language → English → the key itself.
 * @param {string} key
 * @param {Record<string, unknown>} [params]
 * @returns {string}
 */
export function t(key, params) {
  const value = lookup(key);
  if (value === undefined) return String(key);
  if (typeof value === 'string') {
    // A numeric {count} is locale-grouped in plain strings too ('5.000 varyasyon'), exactly like
    // the plural branch below. Only real numbers: an already formatted string is left alone.
    const c = params && params.count;
    return interpolate(value, typeof c === 'number' && Number.isFinite(c) ? { ...params, count: formatNumber(c) } : params);
  }
  // Plural object.
  const count = params && Number(params.count);
  const form = plural(Number.isFinite(count) ? count : NaN, value);
  const shown = params && Number.isFinite(count) ? { ...params, count: formatNumber(count) } : params;
  return interpolate(form, shown);
}

/**
 * Keys requested by `t()` that were missing in the language active at the time
 * (including ones that fell back to English). Useful for tests and E2E checks.
 * @returns {Array<{ lang: string, key: string }>}
 */
export function getMissingKeys() {
  return [...missing.values()];
}

/** Forget recorded missing keys. */
export function clearMissingKeys() {
  missing.clear();
}

/**
 * Every registered key for a language (sorted) — used to diff TR vs EN coverage.
 * @param {'tr'|'en'} lang
 * @returns {string[]}
 */
export function listKeys(lang) {
  const l = normalizeLang(lang);
  return l ? [...dictionaries[l].keys()].sort() : [];
}

/* ------------------------------------------------------------------------ */
/* Locale-aware formatting                                                  */
/* ------------------------------------------------------------------------ */

function toDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === 'number' || typeof value === 'string') {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

/**
 * Locale number ('1.234' in Turkish, '1,234' in English). Non-numbers → String(value).
 * @param {number} n
 * @param {Intl.NumberFormatOptions} [opts]
 * @returns {string}
 */
export function formatNumber(n, opts) {
  const v = Number(n);
  if (typeof n === 'boolean' || n === null || n === undefined || !Number.isFinite(v)) return String(n ?? '');
  return new Intl.NumberFormat(localeTag(), opts).format(v);
}

/**
 * Locale percent from a ratio (0.42 → '42%' / '%42').
 * @param {number} ratio
 * @param {number} [digits=0]
 * @returns {string}
 */
export function formatPercent(ratio, digits = 0) {
  return formatNumber(ratio, { style: 'percent', minimumFractionDigits: digits, maximumFractionDigits: digits });
}

/**
 * Locale date ('23 Eyl 2026' / 'Sep 23, 2026'). Invalid → '—'.
 * @param {Date|number|string} value
 * @param {{ utc?: boolean } & Intl.DateTimeFormatOptions} [opts]
 * @returns {string}
 */
export function formatDate(value, { utc = false, ...opts } = {}) {
  const d = toDate(value);
  if (!d) return '—';
  const options = Object.keys(opts).length ? opts : { dateStyle: 'medium' };
  return new Intl.DateTimeFormat(localeTag(), { ...options, ...(utc ? { timeZone: 'UTC' } : {}) }).format(d);
}

/**
 * Locale date + time ('23 Eyl 2026 14:05' / 'Sep 23, 2026, 2:05 PM'); `utc` appends ' UTC'.
 * @param {Date|number|string} value
 * @param {{ utc?: boolean, seconds?: boolean }} [opts]
 * @returns {string}
 */
export function formatDateTime(value, { utc = false, seconds = false } = {}) {
  const d = toDate(value);
  if (!d) return '—';
  const fmt = new Intl.DateTimeFormat(localeTag(), {
    dateStyle: 'medium',
    timeStyle: seconds ? 'medium' : 'short',
    ...(utc ? { timeZone: 'UTC' } : {})
  });
  return utc ? `${fmt.format(d)} UTC` : fmt.format(d);
}

/**
 * Human duration: '850 ms', '4.2 s', '12 s', '3 min 5 s'.
 * @param {number} ms
 * @returns {string}
 */
export function formatDuration(ms) {
  const v = Number(ms);
  if (!Number.isFinite(v) || v < 0) return '—';
  if (v < 1000) return t('time.ms', { n: formatNumber(Math.round(v)) });
  if (v < 60000) {
    const s = v / 1000;
    return t('time.s', { n: formatNumber(s, { maximumFractionDigits: s < 10 ? 1 : 0 }) });
  }
  const totalS = Math.round(v / 1000);
  return t('time.min', { m: formatNumber(Math.floor(totalS / 60)), s: formatNumber(totalS % 60) });
}

/**
 * Bytes → '512 B', '1,5 KB', '2.3 MB' (1024-based).
 * @param {number} n
 * @returns {string}
 */
export function formatBytes(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return '—';
  if (v < 1024) return `${formatNumber(v)} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i += 1;
  }
  return `${formatNumber(x, { maximumFractionDigits: x < 10 ? 1 : 0 })} ${units[i]}`;
}

/**
 * Whole days from `now` until `date`, rounded down (negative when in the past;
 * something expiring in 20 hours → 0). Invalid → null.
 * @param {Date|number|string} date
 * @param {Date|number} [now=Date.now()]
 * @returns {number|null}
 */
export function daysUntil(date, now = Date.now()) {
  const d = toDate(date);
  const n = now instanceof Date ? now.getTime() : Number(now);
  if (!d || !Number.isFinite(n)) return null;
  return Math.floor((d.getTime() - n) / 86400000);
}

/**
 * Localized country/region name for an ISO 3166-1 alpha-2 code ('JP' → 'Japan' / 'Japonya').
 * Falls back to `fallback` (or the code) when Intl.DisplayNames is unavailable or the code is unknown.
 * @param {string|null|undefined} code
 * @param {string} [fallback]
 * @returns {string}
 */
export function formatRegion(code, fallback) {
  if (typeof code !== 'string' || !/^[A-Za-z]{2}$/.test(code)) return fallback ?? String(code ?? '');
  try {
    const name = new Intl.DisplayNames([localeTag()], { type: 'region' }).of(code.toUpperCase());
    return name && name.toUpperCase() !== code.toUpperCase() ? name : (fallback ?? code.toUpperCase());
  } catch {
    return fallback ?? code.toUpperCase();
  }
}

/**
 * Relative time ('3 days ago', 'in 2 hours' / '3 gün önce', '2 saat sonra').
 * @param {Date|number|string} date
 * @param {Date|number} [now=Date.now()]
 * @returns {string}
 */
export function formatRelative(date, now = Date.now()) {
  const d = toDate(date);
  const n = now instanceof Date ? now.getTime() : Number(now);
  if (!d || !Number.isFinite(n)) return '—';
  const diffS = (d.getTime() - n) / 1000;
  const abs = Math.abs(diffS);
  const rtf = new Intl.RelativeTimeFormat(localeTag(), { numeric: 'auto' });
  if (abs < 45) return rtf.format(Math.round(diffS), 'second');
  if (abs < 2700) return rtf.format(Math.round(diffS / 60), 'minute');
  if (abs < 64800) return rtf.format(Math.round(diffS / 3600), 'hour');
  if (abs < 86400 * 45) return rtf.format(Math.round(diffS / 86400), 'day');
  if (abs < 86400 * 320) return rtf.format(Math.round(diffS / (86400 * 30.44)), 'month');
  return rtf.format(Math.round(diffS / (86400 * 365.25)), 'year');
}

/* ------------------------------------------------------------------------ */
/* Shell + common strings (views register their own namespaces)             */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'app.name': 'DomainScope',
  'app.subtitle': 'SSL & DNS toolkit',
  'app.tagline': 'Find the subdomains, IPs and servers a certificate belongs on — in your browser.',

  'lang.tr': 'Türkçe',
  'lang.en': 'English',

  'nav.label': 'Tools',
  'nav.groupDiscover': 'Discover',
  'nav.groupSsl': 'Certificates',
  'nav.groupDns': 'DNS tools',
  'nav.groupIp': 'IP addresses',
  'nav.groupMail': 'Mail & domain',
  'nav.groupData': 'Setup & info',
  'nav.groupOther': 'More tools',
  'nav.subdomains': 'Subdomains',
  'nav.subdomains.desc': 'Discover the subdomains of a domain from DNS, CT logs and passive DNS, and see where each one points: its IP addresses, Cloudflare / CDN or your own server.',
  'nav.domain': 'Domain overview',
  'nav.domain.desc': 'One page per domain for a migration or a takeover: registration, DNS hosting, mail, web, certificates, the services its TXT records verify, and its health score — each with a link to the tool that goes deeper.',
  'nav.zone': 'Zone File',
  'nav.zone.desc': 'Import your DNS zone export (Cloudflare, Route 53, BIND, cPanel, octoDNS…): every name without guessing, the real server behind each proxied record, mistakes in the zone and drift from live DNS. The file never leaves your browser.',
  'nav.scan': 'SSL Targets',
  'nav.scan.desc': 'Find the subdomains, IP addresses and servers a certificate must be installed on.',
  'nav.cert': 'Certificate',
  'nav.cert.desc': 'Inspect a certificate: names, validity, key, fingerprints, chain, CAA and CT logs.',
  'nav.renew': 'Renewal readiness',
  'nav.renew.desc': 'Will the next ACME renewal validate? CAA and the CA’s validation methods, CAA on several resolvers, _acme-challenge delegation, DNSSEC, the DNS provider’s DNS-01 plugin and HTTP-01 prerequisites, per name.',
  'nav.estate': 'Certificate estate',
  'nav.estate.desc': 'Open the JSON reports of the companion CLI (ssl_origin_scan.py --estate) and see every certificate your servers serve: what expires, which name is served with different certificates, which key sits on many hosts, what is weak — with a CSV of it all. The reports never leave your browser.',
  'nav.global': 'Global DNS',
  'nav.global.desc': 'Compare answers and IPs from 12 public resolvers and 30+ locations worldwide.',
  'nav.lookup': 'DNS Lookup',
  'nav.lookup.desc': 'Query any record type with DNSSEC status, parsed fields and raw output.',
  'nav.bulk': 'Bulk Resolve',
  'nav.bulk.desc': 'Resolve hundreds of hostnames at once and match the IPs to your servers.',
  'nav.change': 'DNS change request',
  'nav.change.desc': 'Write a DNS change for the admin in English and Turkish and as BIND, Route 53, Cloudflare API, octoDNS or Terraform, with a link that shows when it is live.',
  'nav.ip': 'IP Intel',
  'nav.ip.desc': 'Reverse DNS, ASN, owner, location and CDN detection for IP addresses.',
  'nav.ptr': 'Reverse DNS',
  'nav.ptr.desc': 'Look up the reverse DNS (PTR) of every address in a network or an AS’s prefixes, check that each name resolves back, and find the hosts you did not know about.',
  'nav.retire': 'Retire an IP',
  'nav.retire.desc': 'Before you switch off or renumber a server: every DNS record, CNAME chain, SPF mechanism, MX and NS host and zone-file record that still points at its address, checked live, as a change list.',
  'nav.health': 'Domain Health',
  'nav.health.desc': 'NS, SOA, MX, SPF, DMARC, DKIM, CAA, DNSSEC and registration checks.',
  'nav.reports': 'DMARC & TLS reports',
  'nav.reports.desc': 'Drop the DMARC aggregate (rua) and SMTP TLS (TLS-RPT) reports your domain receives: who sends mail as it, what passes, what stands between it and p=reject, and which TLS sessions to your MX hosts fail. The files are read in this browser and never uploaded.',
  'nav.portfolio': 'Domain portfolio',
  'nav.portfolio.desc': 'Many domains, one row each: the expiry with a countdown, registry status flags read for risk, the registrar, DNSSEC, the name servers’ own domains and their expiry, CAA and the mail posture — with an expiry calendar and a policy audit of this workspace.',
  'nav.monitor': 'Monitoring',
  'nav.monitor.desc': 'Open the results of the nightly runner (tools/ds.mjs) — the results folder of your repository, or the repository itself with a read-only token — and see each domain in one row: its trend, the certificates under 21 days, the checks that did not complete and every night’s changes.',
  'nav.inventory': 'Servers',
  'nav.inventory.desc': 'Your server inventory, used to match IP addresses to machines. It never leaves your browser.',
  'nav.about': 'About',
  'nav.about.desc': 'Where to start, how it works, data sources and quotas, privacy and the companion CLI.',

  'shell.skip': 'Skip to content',
  'shell.language': 'Language',
  'shell.theme': 'Theme',
  'shell.themeAuto': 'Auto (system)',
  'shell.themeLight': 'Light',
  'shell.themeDark': 'Dark',
  'shell.settings': 'Settings',
  'shell.github': 'Source code on GitHub',
  'shell.loadingView': 'Loading tool…',
  'shell.viewLoadFailed': 'This tool could not be loaded.',
  'shell.viewCrashed': 'Something went wrong while showing this tool.',
  'shell.reload': 'Reload page',
  'shell.viewOutdated': 'DomainScope has probably been updated since this page was opened. Reload the page to get the current version.',
  'shell.viewStuck': 'The server can be reached again, but the browser does not retry a download that failed in this page. Reload the page to load it.',
  'shell.underConstruction': 'This tool is being built',
  'shell.underConstructionBody': '“{title}” will be available in an upcoming version. The other tools already work.',
  'shell.langDeferred': 'This page will switch language when the current operation finishes.',
  'shell.unexpectedError': 'Unexpected error: {message}',
  'shell.privacyShort': 'Runs entirely in your browser',
  'shell.privacyLong': 'No backend: certificates and your workspaces (inventories included) stay in this browser; only what you choose to check is sent (for example an address to Globalping).',
  'shell.footer': 'Open source · MIT license',
  'shell.version': 'Version {version}',
  'shell.sent': 'What this page sent',
  'shell.sentCount': { zero: 'nothing to third parties yet', one: '{count} request to third parties', other: '{count} requests to third parties' },
  'shell.sentTitle': 'Every request this page made in this session, and what each service received (About)',
  'shell.inventoryStatus': { zero: 'No servers saved', one: '{count} server saved', other: '{count} servers saved' },
  'shell.dohStatus': 'DoH: {chain}',
  'shell.busy': 'Working…',
  'shell.offline': 'You appear to be offline — live lookups will fail until the connection is back.',
  'shell.offlineTitle': 'You are offline',
  'shell.offlineView': '{tool} needs the network: it asks DNS resolvers and public services straight from your browser. It works again as soon as the connection is back.',
  'shell.offlineTools': 'These tools work offline:',
  'shell.offlineAction': 'You are offline — this needs the network. Try again once the connection is back.',
  'shell.storageUnavailable': 'Browser storage is unavailable (private mode or blocked). Your data lasts until this tab is closed.',
  'shell.storageFull': 'Browser storage is full — the change is kept for this session only.',
  'shell.printed': 'Printed {time}',

  'start.title': 'New here? Pick a job to start with',
  'start.lead': 'Each card opens the tool that does it.',
  'start.hide': 'Hide these suggestions',
  'start.hidden': 'Hidden. You can find these jobs again under {where}.',
  'start.aboutTitle': 'Where to start',
  'start.aboutDesc': 'The jobs the start page suggests to a first-time visitor. Each card opens the tool that does it.',
  'start.task.subdomains': 'Find every subdomain',
  'start.task.certificate': 'Where must this certificate go?',
  'start.task.health': 'Check a domain’s health',
  'start.task.propagation': 'Is my DNS change live everywhere?',
  'start.task.zone': 'Import a zone file',

  'keys.title': 'Keyboard shortcuts',
  'keys.submit': 'Run the tool from the field you are in',
  'keys.cancel': 'Cancel what is running; close a dialog or the Tools menu',
  'keys.focus': 'Jump to the tool’s main field',
  'keys.palette': 'Search the tools, or act on a domain or an IP address',
  'keys.help': 'Show this list',
  'keys.note': 'While you type in a field, only {submit}, {palette} and Esc act there (in a search box with text, Esc first clears it); / and ? are typed as usual. Fields among the results, such as a table’s filter, start nothing with {submit}.',

  'settings.title': 'Settings',
  'settings.dohChain': 'DNS-over-HTTPS resolvers',
  'settings.dohChainHint': 'Lookups ask them in this order; when one fails, times out or rate-limits, the next one is used. Subdomain scans spread their many guesses over the resolvers of this list (Cloudflare, Google and DNS.SB when present) — a resolver you remove is not used by scans.',
  'settings.concurrency': 'Parallel DNS queries',
  'settings.concurrencyHint': 'Higher is faster; lower is gentler on the public resolvers. Subdomain scans spread their guesses over several resolvers and may run up to twice this many at once (at most 24).',
  'settings.resetDefaults': 'Restore defaults',
  'settings.clearData': 'Delete all local data',
  'settings.clearDataHint': 'Deletes every workspace from this browser (its IndexedDB database with the server inventories, learned subdomain names, custom wordlists, expected CAs, notes, recent domains and origin maps), all settings and remembered options, and forgets the current target and the results kept in this tab.',
  'settings.clearDataConfirm': 'Delete every workspace (the IndexedDB database with all their servers, learned names, custom wordlists, expected CAs, notes, recent domains and origin maps) and all settings from this browser, and forget the current target and the kept results? This cannot be undone: export a workspace first to keep a copy.',
  'settings.saved': 'Settings saved',
  'settings.atLeastOne': 'Keep at least one resolver.',
  'settings.flagDnssec': 'DNSSEC',
  'settings.flagEcs': 'ECS',
  'settings.flagFilter': 'Filtering',
  'settings.filter.malware': 'malware',
  'settings.filter.security': 'security',
  'settings.filter.family': 'family',
  'settings.unreliable': 'Browsers may fail to read its answers (HTTP/3 without CORS); the next resolver is used then.',
  'settings.flagBrowser': 'Not readable in browsers',
  'settings.flagReach': 'May time out',
  'settings.note.h3NoCors': 'It answers browsers over HTTP/3 without the CORS header a web page needs, so every query falls through to the next resolver. It works fine from dig and other command-line tools.',
  'settings.note.unreachable': 'Unreachable from some networks: connections from them timed out in our tests. While that happens, each query waits for the timeout before the next resolver is tried.',
  'settings.anycast': 'Anycast',
  'settings.position': 'Position {n}',

  'common.ok': 'OK',
  'common.cancel': 'Cancel',
  'common.close': 'Close',
  'common.save': 'Save',
  'common.saved': 'Saved',
  'common.clear': 'Clear',
  'common.delete': 'Delete',
  'common.remove': 'Remove',
  'common.add': 'Add',
  'common.edit': 'Edit',
  'common.copy': 'Copy',
  'common.copied': 'Copied',
  'common.copyFailed': 'Could not copy — select the text and press Ctrl+C.',
  'common.download': 'Download',
  'common.upload': 'Upload',
  'common.import': 'Import',
  'common.export': 'Export',
  'common.exportCsv': 'CSV',
  'common.exportJson': 'JSON',
  'common.run': 'Run',
  'common.start': 'Start',
  'common.stop': 'Stop',
  'common.retry': 'Try again',
  'common.reset': 'Reset',
  'common.refresh': 'Refresh',
  'common.rerun': 'Run again',
  'common.search': 'Search',
  'common.filter': 'Filter',
  'common.filters': 'Filters',
  'common.clearFilters': 'Clear filters',
  'common.loading': 'Loading…',
  'common.working': 'Working…',
  'common.done': 'Done',
  'common.yes': 'Yes',
  'common.no': 'No',
  'common.none': 'None',
  'common.unknown': 'Unknown',
  'common.all': 'All',
  'common.show': 'Show',
  'common.hide': 'Hide',
  'common.showMore': 'Show more',
  'common.showLess': 'Show less',
  'common.moreCount': '+{count} more',
  'common.details': 'Details',
  'common.optional': 'optional',
  'common.required': 'required',
  'common.example': 'Example',
  'common.examples': 'Examples',
  'common.learnMore': 'Learn more',
  'common.newTab': '(opens in a new tab)',
  'common.share': 'Share',
  'common.copyLink': 'Copy link',
  'common.linkCopied': 'Link copied',
  'common.selectAll': 'Select all',
  'common.selectNone': 'Select none',
  'common.moveUp': 'Move up',
  'common.moveDown': 'Move down',
  'common.or': 'or',
  'common.name': 'Name',
  'common.value': 'Value',
  'common.type': 'Type',
  'common.status': 'Status',
  'common.total': 'Total',
  'common.line': 'Line',
  'common.source': 'Source',
  'common.sources': 'Sources',
  'common.ipAddresses': 'IP addresses',
  'common.servers': 'Servers',
  'common.hosts': 'Hosts',
  'common.never': 'Never',
  'common.notAvailable': '—',
  'common.error': 'Error',
  'common.warning': 'Warning',
  'common.info': 'Info',
  'common.success': 'Success',
  'common.confirm': 'Are you sure?',

  'kind.cloudflare': 'Cloudflare',
  'kind.cdn': 'CDN',
  'kind.platform': 'Platform',
  'kind.direct': 'Direct',
  'kind.private': 'Private IP',
  'kind.unresolved': 'Unresolved',
  'kind.nxdomain': 'NXDOMAIN',
  'kind.dangling': 'Dangling CNAME',

  'category.cdn': 'CDN',
  'category.waf': 'WAF',
  'category.platform': 'Platform',
  'category.loadbalancer': 'Load balancer',
  'category.hosting': 'Hosting',

  'class.nxdomain': 'The name does not exist (NXDOMAIN).',
  'class.dangling.nxdomain': 'The CNAME points to a name that does not exist — possible subdomain takeover risk.',
  'class.dangling.noaddress': 'The CNAME chain ends without any IP address.',
  'class.dangling.error': 'The CNAME target could not be resolved.',
  'class.nodata': 'The name exists but has no A/AAAA records.',
  'class.error': 'The lookup failed.',
  'class.cloudflare.ip': 'Proxied by Cloudflare (orange cloud): these IPs belong to Cloudflare and the origin server is hidden.',
  'class.cloudflare.cname': 'CNAME to Cloudflare: the origin server is hidden behind the proxy.',
  'class.cdn.ip': 'Served by the {provider} CDN: the origin server is hidden behind it.',
  'class.cdn.cname': 'CNAME to the {provider} CDN: the origin server is hidden behind it.',
  'class.waf.ip': 'Behind the {provider} web application firewall: the origin server is hidden.',
  'class.waf.cname': 'CNAME to the {provider} firewall: the origin server is hidden.',
  'class.platform.ip': 'Hosted on {provider}: the certificate is usually managed by the platform.',
  'class.platform.cname': 'CNAME to {provider}: the certificate is usually managed by the platform.',
  'class.loadbalancer.ip': 'Behind a {provider} load balancer: the certificate belongs on the load balancer.',
  'class.loadbalancer.cname': 'CNAME to a {provider} load balancer: the certificate belongs on the load balancer.',
  'class.hosting.ip': 'Hosted by {provider}.',
  'class.hosting.cname': 'CNAME to {provider} hosting.',
  'class.private': 'Resolves only to private (internal) IP addresses.',
  'class.direct': 'Resolves directly to a public IP address — most likely your own server.',

  'severity.ok': 'OK',
  'severity.info': 'Info',
  'severity.warn': 'Warning',
  'severity.error': 'Error',

  'table.rows': { zero: 'No rows', one: '{count} row', other: '{count} rows' },
  'table.count': 'Showing {shown} of {total}',
  'table.countFiltered': 'Showing {shown} of {matched} matching ({total} total)',
  'table.showMore': 'Show {count} more',
  'table.showAll': 'Show all ({count})',
  'table.empty': 'Nothing to show yet.',
  'table.noMatch': 'No rows match the current filter.',
  'table.searchPlaceholder': 'Filter rows…',
  'table.searchLabel': 'Filter table rows',
  'table.sortBy': 'Sort by {column}',
  'table.expandRow': 'Show details',
  'table.collapseRow': 'Hide details',
  'table.exported': '{file} downloaded',
  'table.exportLabel': 'Export visible rows',

  'file.dropTitle': 'Drop a file here',
  'file.dropHint': 'or click to choose · you can also paste (Ctrl+V)',
  'file.dropActive': 'Release to load the file',
  'file.choose': 'Choose file',
  'file.tooLarge': '{name} is too large ({size}). Maximum: {max}.',
  'file.readError': 'Could not read {name}.',
  'file.folderNone': 'No file of an accepted type in this folder.',
  'file.capped': 'Only the first {max} of {count} files were read.',
  'file.pasted': 'Pasted text',
  'file.loaded': '{name} loaded ({size})',
  'file.loadedMany': { one: '{count} file loaded ({size})', other: '{count} files loaded ({size})' },
  'file.accepts': 'Accepted: {types}',

  'error.title': 'Something went wrong',
  'error.details': 'Technical details',
  'error.kind.abort': 'Cancelled.',
  'error.kind.timeout': 'The request timed out.',
  'error.kind.rate-limit': 'Rate limited: this service’s free quota is used up. Try again later.',
  'error.kind.http': 'The service returned an error.',
  'error.kind.network': 'Network error — offline, blocked by an extension or firewall, or the service is down.',
  'error.kind.parse': 'The response could not be understood.',
  'error.kind.unknown': 'Unexpected error.',
  'error.kind.unavailable': 'The service is temporarily down: it answered every retry with a server error.',

  'source.quota.day': 'The daily free quota for your IP address is used up; it resets within 24 hours.',
  'source.quota.hour': 'The hourly free quota for your IP address is used up; try again in about an hour.',
  'source.quota.minutes': 'Rate limit reached; try again in a few minutes.',
  'source.quota.later': 'Anonymous access is limited for your IP address right now; try again later.',
  'source.state.ok': 'OK',
  'source.state.empty': 'No results',
  'source.state.partial': 'Partial',
  'source.state.rate-limited': 'Quota used up',
  'source.state.unavailable': 'Temporarily down',
  'source.state.timeout': 'Timed out',
  'source.state.error': 'Failed',
  'source.fallback': '{name} was used instead.',

  'time.ms': '{n} ms',
  'time.s': '{n} s',
  'time.min': '{m} min {s} s',
  'time.daysLeft': { zero: 'expires today', one: '{count} day left', other: '{count} days left' },
  'time.daysAgo': { zero: 'today', one: '{count} day ago', other: '{count} days ago' },

  'progress.label': 'Progress',
  'progress.count': '{done} / {total}',

  'modal.close': 'Close dialog',
  'toast.dismiss': 'Dismiss notification',
  'tabs.label': 'Sections',
  'tabs.more': 'More tabs'
});

registerStrings('tr', {
  'app.name': 'DomainScope',
  'app.subtitle': 'SSL & DNS araç kutusu',
  'app.tagline': 'Bir sertifikanın ait olduğu alt alan adlarını, IP’leri ve sunucuları tarayıcınızda bulun.',

  'lang.tr': 'Türkçe',
  'lang.en': 'English',

  'nav.label': 'Araçlar',
  'nav.groupDiscover': 'Keşif',
  'nav.groupSsl': 'Sertifikalar',
  'nav.groupDns': 'DNS araçları',
  'nav.groupIp': 'IP adresleri',
  'nav.groupMail': 'E-posta ve alan adı',
  'nav.groupData': 'Kurulum ve bilgi',
  'nav.groupOther': 'Diğer araçlar',
  'nav.subdomains': 'Subdomain Tarama',
  'nav.subdomains.desc': 'Bir alan adının subdomain’lerini DNS, CT kayıtları ve pasif DNS ile keşfedin ve her birinin nereye işaret ettiğini görün: IP adresleri, Cloudflare / CDN ya da kendi sunucunuz.',
  'nav.domain': 'Alan adı özeti',
  'nav.domain.desc': 'Taşıma ya da devralma için her alan adına tek sayfa: kayıt bilgisi, DNS barındırma, e-posta, web, sertifikalar, TXT kayıtlarının doğruladığı hizmetler ve sağlık puanı — her biri daha ayrıntılı araca bağlantıyla.',
  'nav.zone': 'Zone Dosyası',
  'nav.zone.desc': 'DNS zone dışa aktarımınızı (Cloudflare, Route 53, BIND, cPanel, octoDNS…) içe aktarın: tüm adlar tahminsiz, proxy’li her kaydın arkasındaki gerçek sunucu, zone’daki hatalar ve canlı DNS ile farklar. Dosya tarayıcınızdan hiç çıkmaz.',
  'nav.scan': 'SSL Hedefleri',
  'nav.scan.desc': 'Bir sertifikanın kurulması gereken alt alan adlarını, IP adreslerini ve sunucuları bulun.',
  'nav.cert': 'Sertifika',
  'nav.cert.desc': 'Sertifikayı inceleyin: adlar, geçerlilik, anahtar, parmak izleri, zincir, CAA ve CT kayıtları.',
  'nav.renew': 'Yenileme hazırlığı',
  'nav.renew.desc': 'Bir sonraki ACME yenilemesi doğrulanacak mı? Ad başına CAA ve otoritenin doğrulama yöntemleri, birkaç çözümleyicide CAA, _acme-challenge devri, DNSSEC, DNS sağlayıcısının DNS-01 eklentisi ve HTTP-01 önkoşulları.',
  'nav.estate': 'Sertifika envanteri',
  'nav.estate.desc': 'Yardımcı CLI’nin (ssl_origin_scan.py --estate) JSON raporlarını açın ve sunucularınızın sunduğu her sertifikayı görün: süresi dolanlar, farklı sertifikalarla sunulan adlar, birçok sunucudaki aynı anahtar, zayıf olanlar — hepsinin CSV’siyle. Raporlar tarayıcınızdan hiç çıkmaz.',
  'nav.global': 'Global DNS',
  'nav.global.desc': '12 genel çözümleyiciden ve dünya genelinde 30’dan fazla konumdan gelen yanıtları ve IP’leri karşılaştırın.',
  'nav.lookup': 'DNS Sorgulama',
  'nav.lookup.desc': 'Her kayıt türünü DNSSEC durumu, ayrıştırılmış alanlar ve ham çıktıyla sorgulayın.',
  'nav.bulk': 'Toplu Çözümleme',
  'nav.bulk.desc': 'Yüzlerce host adını tek seferde çözümleyin ve IP’leri sunucularınızla eşleştirin.',
  'nav.change': 'DNS değişiklik talebi',
  'nav.change.desc': 'DNS değişikliğini yönetici için Türkçe ve İngilizce, ayrıca BIND, Route 53, Cloudflare API, octoDNS ya da Terraform olarak yazın; ne zaman yayında olduğunu gösteren bir bağlantıyla.',
  'nav.ip': 'IP Bilgisi',
  'nav.ip.desc': 'IP adresleri için ters DNS, ASN, sahip, konum ve CDN tespiti.',
  'nav.ptr': 'Ters DNS',
  'nav.ptr.desc': 'Bir ağdaki ya da bir AS’in öneklerindeki her adresin ters DNS (PTR) kaydına bakın, her adın yine o adrese çözüldüğünü doğrulayın ve bilmediğiniz sunucuları bulun.',
  'nav.retire': 'IP emekliye ayırma',
  'nav.retire.desc': 'Bir sunucuyu kapatmadan ya da adresini değiştirmeden önce: adresini hâlâ gösteren her DNS kaydı, CNAME zinciri, SPF mekanizması, MX ve NS sunucusu ve zone dosyası kaydı — canlı kontrol edilmiş, bir değişiklik listesi olarak.',
  'nav.health': 'Alan Adı Sağlığı',
  'nav.health.desc': 'NS, SOA, MX, SPF, DMARC, DKIM, CAA, DNSSEC ve kayıt (whois) kontrolleri.',
  'nav.reports': 'DMARC ve TLS raporları',
  'nav.reports.desc': 'Alan adınıza gelen DMARC toplu (rua) ve SMTP TLS (TLS-RPT) raporlarını bırakın: adınıza kimlerin e-posta gönderdiği, neyin geçtiği, p=reject’in önünde ne durduğu ve MX sunucularınıza hangi TLS oturumlarının başarısız olduğu. Dosyalar bu tarayıcıda okunur, hiçbir yere yüklenmez.',
  'nav.portfolio': 'Alan adı portföyü',
  'nav.portfolio.desc': 'Çok sayıda alan adı, her biri tek satırda: geri sayımlı bitiş tarihi, risk açısından okunan kayıt durumu işaretleri, kayıt firması, DNSSEC, ad sunucularının kendi alan adları ve bitişleri, CAA ve e-posta ayarları — bitiş takvimi ve bu çalışma alanının politika denetimiyle.',
  'nav.monitor': 'İzleme',
  'nav.monitor.desc': 'Gece çalışan kontrollerin (tools/ds.mjs) sonuçlarını açın — deponuzdaki results klasörünü ya da salt okunur bir anahtarla deponun kendisini — ve her alan adını tek satırda görün: eğilimi, 21 günden az kalan sertifikalar, tamamlanmayan kontroller ve her gecenin değişiklikleri.',
  'nav.inventory': 'Sunucular',
  'nav.inventory.desc': 'IP adreslerini makinelerle eşleştirmek için kullanılan sunucu envanteriniz. Tarayıcınızdan hiç çıkmaz.',
  'nav.about': 'Hakkında',
  'nav.about.desc': 'Nereden başlamalı, nasıl çalışır, veri kaynakları ve kotalar, gizlilik ve yardımcı CLI aracı.',

  'shell.skip': 'İçeriğe geç',
  'shell.language': 'Dil',
  'shell.theme': 'Tema',
  'shell.themeAuto': 'Otomatik (sistem)',
  'shell.themeLight': 'Açık',
  'shell.themeDark': 'Koyu',
  'shell.settings': 'Ayarlar',
  'shell.github': 'GitHub’da kaynak kod',
  'shell.loadingView': 'Araç yükleniyor…',
  'shell.viewLoadFailed': 'Bu araç yüklenemedi.',
  'shell.viewCrashed': 'Bu araç gösterilirken bir sorun oluştu.',
  'shell.reload': 'Sayfayı yenile',
  'shell.viewOutdated': 'DomainScope bu sayfa açıldıktan sonra büyük olasılıkla güncellendi. Güncel sürümü almak için sayfayı yenileyin.',
  'shell.viewStuck': 'Sunucuya yeniden ulaşılabiliyor, ancak tarayıcı bu sayfada başarısız olan bir indirmeyi yeniden denemiyor. Yüklemek için sayfayı yenileyin.',
  'shell.underConstruction': 'Bu araç hazırlanıyor',
  'shell.underConstructionBody': '“{title}” yakında kullanıma sunulacak. Diğer araçlar şimdiden çalışıyor.',
  'shell.langDeferred': 'Bu sayfanın dili, devam eden işlem bitince değişecek.',
  'shell.unexpectedError': 'Beklenmeyen hata: {message}',
  'shell.privacyShort': 'Tamamen tarayıcınızda çalışır',
  'shell.privacyLong': 'Sunucu yok: sertifikalar ve çalışma alanlarınız (envanterler dahil) bu tarayıcıda kalır; yalnızca kontrol etmeyi seçtiğiniz şey gönderilir (örneğin bir adres Globalping’e).',
  'shell.footer': 'Açık kaynak · MIT lisansı',
  'shell.version': 'Sürüm {version}',
  'shell.sent': 'Bu sayfa ne gönderdi',
  'shell.sentCount': { zero: 'üçüncü taraflara henüz bir şey gitmedi', other: 'üçüncü taraflara {count} istek' },
  'shell.sentTitle': 'Bu sayfanın bu oturumda yaptığı her istek ve her hizmetin ne aldığı (Hakkında)',
  'shell.inventoryStatus': { zero: 'Kayıtlı sunucu yok', other: '{count} sunucu kayıtlı' },
  'shell.dohStatus': 'DoH: {chain}',
  'shell.busy': 'Çalışıyor…',
  'shell.offline': 'Çevrimdışı görünüyorsunuz — bağlantı gelene kadar canlı sorgular başarısız olur.',
  'shell.offlineTitle': 'Çevrimdışısınız',
  'shell.offlineView': '{tool} ağ bağlantısı gerektirir: DNS çözümleyicilerine ve herkese açık hizmetlere doğrudan tarayıcınızdan sorar. Bağlantı gelir gelmez yeniden çalışır.',
  'shell.offlineTools': 'Bağlantı olmadan da çalışan araçlar:',
  'shell.offlineAction': 'Çevrimdışısınız — bunun için ağ bağlantısı gerekiyor. Bağlantı gelince yeniden deneyin.',
  'shell.storageUnavailable': 'Tarayıcı depolaması kullanılamıyor (gizli mod veya engelli). Verileriniz bu sekme kapanana kadar tutulur.',
  'shell.storageFull': 'Tarayıcı depolaması dolu — değişiklik yalnızca bu oturum için tutuluyor.',
  'shell.printed': 'Yazdırıldı: {time}',

  'start.title': 'İlk kez mi geliyorsunuz? Başlamak için bir iş seçin',
  'start.lead': 'Her kart o işi yapan aracı açar.',
  'start.hide': 'Bu önerileri gizle',
  'start.hidden': 'Gizlendi. Bu işleri {where} bölümünde yeniden bulabilirsiniz.',
  'start.aboutTitle': 'Nereden başlamalı',
  'start.aboutDesc': 'Başlangıç sayfasının ilk kez gelen ziyaretçiye önerdiği işler. Her kart o işi yapan aracı açar.',
  'start.task.subdomains': 'Tüm subdomain’leri bul',
  'start.task.certificate': 'Bu sertifika nereye kurulmalı?',
  'start.task.health': 'Bir alan adının sağlığını kontrol et',
  'start.task.propagation': 'DNS değişikliğim her yerde yayıldı mı?',
  'start.task.zone': 'Bir zone dosyasını içe aktar',

  'keys.title': 'Klavye kısayolları',
  'keys.submit': 'İçinde bulunduğunuz alandan aracı çalıştır',
  'keys.cancel': 'Çalışan işi iptal et; bir pencereyi ya da Araçlar menüsünü kapat',
  'keys.focus': 'Aracın ana alanına git',
  'keys.palette': 'Araçlarda ara ya da bir alan adı veya IP adresiyle işlem yap',
  'keys.help': 'Bu listeyi göster',
  'keys.note': 'Bir alana yazarken orada yalnızca {submit}, {palette} ve Esc çalışır (içinde metin olan bir arama kutusunda Esc önce onu temizler); / ve ? her zamanki gibi yazılır. Sonuçlardaki alanlarda (örneğin bir tablonun filtresinde) {submit} hiçbir şeyi başlatmaz.',

  'settings.title': 'Ayarlar',
  'settings.dohChain': 'DNS-over-HTTPS çözümleyicileri',
  'settings.dohChainHint': 'Sorgular bu sırayla yapılır; bir çözümleyici hata verir, zaman aşımına uğrar veya sınırlama yaparsa sıradaki kullanılır. Subdomain taramaları çok sayıdaki tahmini bu listedeki çözümleyicilere dağıtır (listedeyse Cloudflare, Google ve DNS.SB) — çıkardığınız bir çözümleyici taramalarda kullanılmaz.',
  'settings.concurrency': 'Paralel DNS sorgusu',
  'settings.concurrencyHint': 'Yüksek değer daha hızlıdır; düşük değer genel çözümleyicileri daha az yorar. Subdomain taramaları tahminlerini birkaç çözümleyiciye dağıttığı için aynı anda bunun en fazla iki katını (en çok 24) çalıştırabilir.',
  'settings.resetDefaults': 'Varsayılanları geri yükle',
  'settings.clearData': 'Tüm yerel verileri sil',
  'settings.clearDataHint': 'Tüm çalışma alanlarını bu tarayıcıdan siler (sunucu envanterleri, öğrenilen subdomain adları, özel kelime listeleri, beklenen CA’lar, notlar, son alan adları ve origin haritalarıyla birlikte IndexedDB veritabanını), tüm ayarları ve hatırlanan seçenekleri kaldırır; geçerli hedefi ve bu sekmede tutulan sonuçları da unutur.',
  'settings.clearDataConfirm': 'Tüm çalışma alanları (sunucuları, öğrenilen adları, özel kelime listeleri, beklenen CA’ları, notları, son alan adları ve origin haritalarıyla birlikte IndexedDB veritabanı) ve tüm ayarlar bu tarayıcıdan silinsin; geçerli hedef ve tutulan sonuçlar da unutulsun mu? Bu işlem geri alınamaz: bir kopyasını saklamak için önce çalışma alanını dışa aktarın.',
  'settings.saved': 'Ayarlar kaydedildi',
  'settings.atLeastOne': 'En az bir çözümleyici kalmalı.',
  'settings.flagDnssec': 'DNSSEC',
  'settings.flagEcs': 'ECS',
  'settings.flagFilter': 'Filtreli',
  'settings.filter.malware': 'zararlı yazılım',
  'settings.filter.security': 'güvenlik',
  'settings.filter.family': 'aile',
  'settings.unreliable': 'Tarayıcılar yanıtını okuyamayabilir (HTTP/3’te CORS yok); bu durumda sıradaki çözümleyici kullanılır.',
  'settings.flagBrowser': 'Tarayıcıda okunamıyor',
  'settings.flagReach': 'Zaman aşımı olabilir',
  'settings.note.h3NoCors': 'Tarayıcılara HTTP/3 üzerinden, bir web sayfasının ihtiyaç duyduğu CORS başlığı olmadan yanıt veriyor; bu yüzden her sorgu sıradaki çözümleyiciye düşer. dig ve diğer komut satırı araçlarından sorunsuz çalışır.',
  'settings.note.unreachable': 'Bazı ağlardan erişilemiyor: testlerimizde bu ağlardan yapılan bağlantılar zaman aşımına uğradı. Bu durumda her sorgu, sıradaki çözümleyici denenmeden önce zaman aşımını bekler.',
  'settings.anycast': 'Anycast',
  'settings.position': '{n}. sıra',

  'common.ok': 'Tamam',
  'common.cancel': 'Vazgeç',
  'common.close': 'Kapat',
  'common.save': 'Kaydet',
  'common.saved': 'Kaydedildi',
  'common.clear': 'Temizle',
  'common.delete': 'Sil',
  'common.remove': 'Kaldır',
  'common.add': 'Ekle',
  'common.edit': 'Düzenle',
  'common.copy': 'Kopyala',
  'common.copied': 'Kopyalandı',
  'common.copyFailed': 'Kopyalanamadı — metni seçip Ctrl+C’ye basın.',
  'common.download': 'İndir',
  'common.upload': 'Yükle',
  'common.import': 'İçe aktar',
  'common.export': 'Dışa aktar',
  'common.exportCsv': 'CSV',
  'common.exportJson': 'JSON',
  'common.run': 'Çalıştır',
  'common.start': 'Başlat',
  'common.stop': 'Durdur',
  'common.retry': 'Tekrar dene',
  'common.reset': 'Sıfırla',
  'common.refresh': 'Yenile',
  'common.rerun': 'Yeniden çalıştır',
  'common.search': 'Ara',
  'common.filter': 'Filtrele',
  'common.filters': 'Filtreler',
  'common.clearFilters': 'Filtreleri temizle',
  'common.loading': 'Yükleniyor…',
  'common.working': 'Çalışıyor…',
  'common.done': 'Tamamlandı',
  'common.yes': 'Evet',
  'common.no': 'Hayır',
  'common.none': 'Yok',
  'common.unknown': 'Bilinmiyor',
  'common.all': 'Tümü',
  'common.show': 'Göster',
  'common.hide': 'Gizle',
  'common.showMore': 'Daha fazla göster',
  'common.showLess': 'Daha az göster',
  'common.moreCount': '+{count} tane daha',
  'common.details': 'Ayrıntılar',
  'common.optional': 'isteğe bağlı',
  'common.required': 'zorunlu',
  'common.example': 'Örnek',
  'common.examples': 'Örnekler',
  'common.learnMore': 'Daha fazla bilgi',
  'common.newTab': '(yeni sekmede açılır)',
  'common.share': 'Paylaş',
  'common.copyLink': 'Bağlantıyı kopyala',
  'common.linkCopied': 'Bağlantı kopyalandı',
  'common.selectAll': 'Tümünü seç',
  'common.selectNone': 'Hiçbirini seçme',
  'common.moveUp': 'Yukarı taşı',
  'common.moveDown': 'Aşağı taşı',
  'common.or': 'veya',
  'common.name': 'Ad',
  'common.value': 'Değer',
  'common.type': 'Tür',
  'common.status': 'Durum',
  'common.total': 'Toplam',
  'common.line': 'Satır',
  'common.source': 'Kaynak',
  'common.sources': 'Kaynaklar',
  'common.ipAddresses': 'IP adresleri',
  'common.servers': 'Sunucular',
  'common.hosts': 'Host’lar',
  'common.never': 'Hiç',
  'common.notAvailable': '—',
  'common.error': 'Hata',
  'common.warning': 'Uyarı',
  'common.info': 'Bilgi',
  'common.success': 'Başarılı',
  'common.confirm': 'Emin misiniz?',

  'kind.cloudflare': 'Cloudflare',
  'kind.cdn': 'CDN',
  'kind.platform': 'Platform',
  'kind.direct': 'Doğrudan',
  'kind.private': 'Özel IP',
  'kind.unresolved': 'Çözümlenmedi',
  'kind.nxdomain': 'NXDOMAIN',
  'kind.dangling': 'Sahipsiz CNAME',

  'category.cdn': 'CDN',
  'category.waf': 'WAF',
  'category.platform': 'Platform',
  'category.loadbalancer': 'Yük dengeleyici',
  'category.hosting': 'Barındırma',

  'class.nxdomain': 'Bu ad mevcut değil (NXDOMAIN).',
  'class.dangling.nxdomain': 'CNAME var olmayan bir ada işaret ediyor — olası alt alan adı ele geçirme (takeover) riski.',
  'class.dangling.noaddress': 'CNAME zinciri hiçbir IP adresine ulaşmadan bitiyor.',
  'class.dangling.error': 'CNAME hedefi çözümlenemedi.',
  'class.nodata': 'Ad mevcut ama A/AAAA kaydı yok.',
  'class.error': 'Sorgu başarısız oldu.',
  'class.cloudflare.ip': 'Cloudflare proxy’si arkasında (turuncu bulut): bu IP’ler Cloudflare’e ait, asıl sunucu gizli.',
  'class.cloudflare.cname': 'Cloudflare’e CNAME: asıl sunucu proxy’nin arkasında gizli.',
  'class.cdn.ip': '{provider} CDN’i üzerinden sunuluyor: asıl sunucu onun arkasında gizli.',
  'class.cdn.cname': '{provider} CDN’ine CNAME: asıl sunucu onun arkasında gizli.',
  'class.waf.ip': '{provider} web uygulama güvenlik duvarının arkasında: asıl sunucu gizli.',
  'class.waf.cname': '{provider} güvenlik duvarına CNAME: asıl sunucu gizli.',
  'class.platform.ip': '{provider} üzerinde barındırılıyor: sertifika genellikle platform tarafından yönetilir.',
  'class.platform.cname': '{provider} platformuna CNAME: sertifika genellikle platform tarafından yönetilir.',
  'class.loadbalancer.ip': '{provider} yük dengeleyicisinin arkasında: sertifika yük dengeleyiciye kurulur.',
  'class.loadbalancer.cname': '{provider} yük dengeleyicisine CNAME: sertifika yük dengeleyiciye kurulur.',
  'class.hosting.ip': '{provider} tarafından barındırılıyor.',
  'class.hosting.cname': '{provider} barındırma hizmetine CNAME.',
  'class.private': 'Yalnızca özel (iç ağ) IP adreslerine çözümleniyor.',
  'class.direct': 'Doğrudan genel bir IP adresine çözümleniyor — büyük olasılıkla kendi sunucunuz.',

  'severity.ok': 'Sorun yok',
  'severity.info': 'Bilgi',
  'severity.warn': 'Uyarı',
  'severity.error': 'Hata',

  'table.rows': { zero: 'Satır yok', other: '{count} satır' },
  'table.count': '{total} satırdan {shown} tanesi gösteriliyor',
  'table.countFiltered': 'Eşleşen {matched} satırdan {shown} tanesi gösteriliyor (toplam {total})',
  'table.showMore': '{count} tane daha göster',
  'table.showAll': 'Tümünü göster ({count})',
  'table.empty': 'Henüz gösterilecek bir şey yok.',
  'table.noMatch': 'Geçerli filtreyle eşleşen satır yok.',
  'table.searchPlaceholder': 'Satırları filtrele…',
  'table.searchLabel': 'Tablo satırlarını filtrele',
  'table.sortBy': '{column} sütununa göre sırala',
  'table.expandRow': 'Ayrıntıları göster',
  'table.collapseRow': 'Ayrıntıları gizle',
  'table.exported': '{file} indirildi',
  'table.exportLabel': 'Görünen satırları dışa aktar',

  'file.dropTitle': 'Dosyayı buraya bırakın',
  'file.dropHint': 'veya seçmek için tıklayın · yapıştırabilirsiniz de (Ctrl+V)',
  'file.dropActive': 'Yüklemek için bırakın',
  'file.choose': 'Dosya seç',
  'file.tooLarge': '{name} çok büyük ({size}). En fazla: {max}.',
  'file.readError': '{name} okunamadı.',
  'file.folderNone': 'Bu klasörde kabul edilen türde dosya yok.',
  'file.capped': '{count} dosyanın yalnızca ilk {max} tanesi okundu.',
  'file.pasted': 'Yapıştırılan metin',
  'file.loaded': '{name} yüklendi ({size})',
  'file.loadedMany': '{count} dosya yüklendi ({size})',
  'file.accepts': 'Kabul edilenler: {types}',

  'error.title': 'Bir sorun oluştu',
  'error.details': 'Teknik ayrıntılar',
  'error.kind.abort': 'İptal edildi.',
  'error.kind.timeout': 'İstek zaman aşımına uğradı.',
  'error.kind.rate-limit': 'Hız sınırı: bu hizmetin ücretsiz kotası doldu. Daha sonra tekrar deneyin.',
  'error.kind.http': 'Hizmet bir hata döndürdü.',
  'error.kind.network': 'Ağ hatası — çevrimdışısınız, bir eklenti ya da güvenlik duvarı engelliyor veya hizmet çalışmıyor.',
  'error.kind.parse': 'Yanıt anlaşılamadı.',
  'error.kind.unknown': 'Beklenmeyen hata.',
  'error.kind.unavailable': 'Hizmet geçici olarak çalışmıyor: her denemede sunucu hatası döndürdü.',

  'source.quota.day': 'IP adresinizin günlük ücretsiz kotası doldu; 24 saat içinde sıfırlanır.',
  'source.quota.hour': 'IP adresinizin saatlik ücretsiz kotası doldu; yaklaşık bir saat sonra tekrar deneyin.',
  'source.quota.minutes': 'Hız sınırına ulaşıldı; birkaç dakika sonra tekrar deneyin.',
  'source.quota.later': 'IP adresiniz için anonim erişim şu an sınırlı; daha sonra tekrar deneyin.',
  'source.state.ok': 'Tamam',
  'source.state.empty': 'Sonuç yok',
  'source.state.partial': 'Kısmi',
  'source.state.rate-limited': 'Kota doldu',
  'source.state.unavailable': 'Geçici olarak çalışmıyor',
  'source.state.timeout': 'Zaman aşımı',
  'source.state.error': 'Başarısız',
  'source.fallback': 'Yerine {name} kullanıldı.',

  'time.ms': '{n} ms',
  'time.s': '{n} sn',
  'time.min': '{m} dk {s} sn',
  'time.daysLeft': { zero: 'bugün sona eriyor', other: '{count} gün kaldı' },
  'time.daysAgo': { zero: 'bugün', other: '{count} gün önce' },

  'progress.label': 'İlerleme',
  'progress.count': '{done} / {total}',

  'modal.close': 'Pencereyi kapat',
  'toast.dismiss': 'Bildirimi kapat',
  'tabs.label': 'Bölümler',
  'tabs.more': 'Diğer sekmeler'
});
