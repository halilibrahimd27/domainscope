/**
 * summarycore.js — "Copy summary", the part on the start route: the document model, the text
 * helpers, {@link permalinkParams}, rendering, the builder registry and the builder of the default
 * view (Subdomains) with its texts. Every other view's builder and texts are in lib/summary.js,
 * which registers them when it loads (with the first of those views, never on the start route);
 * DMARC & TLS reports keeps its own in lib/reportsummary.js.
 *
 * - {@link renderMarkdown} / {@link renderPlainText} turn a doc into text. Untrusted values
 *   (host names, record data, certificate subjects and issuers, inventory server names, a network's
 *   AS name and place, the names and lines of a zone file a problem quotes) are code spans in
 *   Markdown (no link, mention or formatting survives inside one) and every other text is
 *   Markdown-escaped; control and bidi characters never reach the output.
 * - {@link permalinkParams} keeps only a view's own shareable route params (never inventory data
 *   or zone contents; IP Intel and Retire an IP drop private and inventory addresses), for `ctx.shareUrl()`.
 *
 * Texts come from an injected `t(key, params)` (i18n.js): the `sum.*` keys of
 * {@link SUMMARY_CORE_I18N} (lib/summary.js SUMMARY_I18N holds them and every other view's) plus a
 * few the shell always has (`nav.<view>`, `severity.*`, `kind.*`, `common.moreCount`).
 * DOM-free and dependency-light (the shell loads it); runs in browsers and Node 22.
 */

import { isPrivateIP, normalizeIP } from './netinfo.js';

/** Views with a summary, in navigation order. */
export const SUMMARY_KINDS = Object.freeze(['subdomains', 'domain', 'zone', 'scan', 'cert', 'renew', 'estate', 'global', 'lookup', 'change', 'ip', 'retire',
  'health', 'reports']);

/** Output formats of {@link renderSummary}. */
export const SUMMARY_FORMATS = Object.freeze(['markdown', 'text']);

/** At most this many problems / findings / names are listed in one summary line group. */
export const SUMMARY_MAX_PROBLEMS = 5;
/** Longest value shown in a code span (longer ones end with '…'). */
export const SUMMARY_MAX_VALUE = 96;

/**
 * Route params a view's permalink may carry (app.js buildRoute keys). Zone File, Certificate,
 * Certificate estate and DMARC & TLS reports carry none: the file never goes into a URL. The DNS
 * change request's summary links its check page (the check link itself), never its form.
 */
export const PERMALINK_PARAMS = Object.freeze({
  subdomains: Object.freeze(['domain', 'run']),
  domain: Object.freeze(['name']),
  zone: Object.freeze([]),
  scan: Object.freeze(['domain', 'run']),
  cert: Object.freeze([]),
  renew: Object.freeze(['names', 'ca', 'challenge']),
  estate: Object.freeze([]),
  global: Object.freeze(['name', 'type', 'geo']),
  lookup: Object.freeze(['name', 'type', 'resolver', 'dnssec', 'cd']),
  change: Object.freeze([]),
  ip: Object.freeze(['ips']),
  retire: Object.freeze(['ips', 'domains']),
  health: Object.freeze(['domain', 'selectors']),
  reports: Object.freeze([])
});

/* ------------------------------------------------------------------------ */
/* Scores shared with views/health.js                                       */
/* ------------------------------------------------------------------------ */

/**
 * Health score: 100 − 20 per error − 6 per warning, clamped to 0…100.
 * @param {{ ok?: number, info?: number, warn?: number, error?: number }} summary
 * @returns {number}
 */
export function healthScore(summary) {
  const s = summary || {};
  const score = 100 - 20 * (Number(s.error) || 0) - 6 * (Number(s.warn) || 0);
  return Math.max(0, Math.min(100, score));
}

/**
 * Traffic-light state for a summary: any error → 'error', any warning → 'warn', else 'ok'.
 * @param {{ warn?: number, error?: number }} summary
 * @returns {'error'|'warn'|'ok'}
 */
export function trafficLight(summary) {
  const s = summary || {};
  if (Number(s.error) > 0) return 'error';
  if (Number(s.warn) > 0) return 'warn';
  return 'ok';
}

/* ------------------------------------------------------------------------ */
/* Text helpers                                                             */
/* ------------------------------------------------------------------------ */

// Control characters, bidi embeddings / overrides / isolates and line / paragraph separators:
// a pasted summary must not reorder, hide or break lines.
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]+/g;

/**
 * One line of safe text: control / bidi characters become a space, runs of spaces collapse.
 * @param {unknown} value
 * @returns {string}
 */
export function cleanText(value) {
  return String(value ?? '').replace(UNSAFE_CHARS, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * Escape Markdown syntax in running text (CommonMark + the chat dialects): backslash, backtick,
 * `* [ ] < > ~ |`, and `_` unless it sits between two letters or digits (`a_b` is never emphasis).
 * @param {unknown} value
 * @returns {string}
 */
export function mdEscape(value) {
  return cleanText(value)
    .replace(/[\\`*[\]<>~|]/g, (c) => `\\${c}`)
    .replace(/_/g, (c, i, s) => (/[\p{L}\p{N}]/u.test(s[i - 1] || '') && /[\p{L}\p{N}]/u.test(s[i + 1] || '') ? c : '\\_'));
}

/**
 * A value as a Markdown code span: cleaned, cut at {@link SUMMARY_MAX_VALUE} characters, a
 * backtick inside becomes ' (a code span cannot hold its own delimiter in every chat dialect).
 * @param {unknown} value
 * @returns {string}
 */
export function mdCode(value) {
  return `\`${shortValue(value).replace(/`/g, '\'')}\``;
}

function shortValue(value) {
  const s = cleanText(value);
  return s.length > SUMMARY_MAX_VALUE ? `${s.slice(0, SUMMARY_MAX_VALUE - 1)}…` : s;
}

/**
 * 'YYYY-MM-DD HH:MM UTC' (language-neutral), or '' for an invalid date.
 * @param {Date|number|string} value
 * @returns {string}
 */
export function utcStamp(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
}

/** 'YYYY-MM-DD' in UTC, or '' for an invalid date. */
function isoDay(value) {
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10);
}

/* ------------------------------------------------------------------------ */
/* Permalinks                                                               */
/* ------------------------------------------------------------------------ */

/**
 * The route params of a view's permalink: only the keys in {@link PERMALINK_PARAMS}, never an
 * empty value. IP Intel keeps the pasted host names and the public addresses that are not in
 * `exclude` (the inventory's addresses): a private or inventory address is inventory data. Retire
 * an IP does the same with its addresses (a private network too).
 * @param {string} view
 * @param {Record<string, unknown>} [params] the view's route params (ctx.params)
 * @param {{ exclude?: Iterable<string> }} [opts]
 * @returns {Record<string, string>}
 */
export function permalinkParams(view, params = {}, { exclude = [] } = {}) {
  const keys = PERMALINK_PARAMS[view] || [];
  const out = {};
  for (const key of keys) {
    const raw = params && params[key];
    if (raw === null || raw === undefined || raw === '' || raw === false) continue;
    let value = Array.isArray(raw) ? raw.join(',') : String(raw);
    if ((view === 'ip' || view === 'retire') && key === 'ips') {
      const skip = new Set([...exclude].map((ip) => normalizeIP(ip) || String(ip)));
      value = value.split(/[\s,;]+/).filter((token) => {
        if (!token) return false;
        const ip = normalizeIP(token);
        if (!ip && view === 'retire') {
          // A network: its first address says whether it is private space.
          const net = normalizeIP(token.split('/')[0]);
          return !net || !isPrivateIP(net);
        }
        return !ip || (!isPrivateIP(ip) && !skip.has(ip));
      }).join(',');
      if (!value) continue;
    }
    out[key] = value;
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Document model                                                           */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {string|{ code: string }|{ strong: string }} SummaryPart
 *   text (escaped in Markdown), an untrusted value (a code span) or a bold label
 * @typedef {{ kind: string, title: SummaryPart[], lines: SummaryPart[][], inline: boolean,
 *   footer: { when: string, url: string|null } }} SummaryDoc
 *   `inline`: the one line follows the title on the same line (DNS Lookup, IP Intel)
 */

const code = (value) => ({ code: String(value ?? '') });
const strong = (value) => ({ strong: String(value ?? '') });

/**
 * Shared context of one build: translation, number formatting, lists.
 * @param {{ t: Function, lang?: string }} opts
 */
function kit({ t, lang = 'en' }) {
  if (typeof t !== 'function') throw new TypeError('summary: opts.t (translate) is required');
  const nf = new Intl.NumberFormat(lang === 'tr' ? 'tr-TR' : 'en-US');
  const num = (n) => (Number.isFinite(Number(n)) ? nf.format(Number(n)) : String(n ?? ''));
  /** Values as code spans joined with ', ', at most `max`, then "+N more". */
  const values = (list, max = 3) => {
    const items = [...new Set((list || []).map((v) => cleanText(v)).filter(Boolean))];
    const parts = [];
    items.slice(0, max).forEach((v, i) => {
      if (i) parts.push(', ');
      parts.push(code(v));
    });
    if (items.length > max) parts.push(` ${t('common.moreCount', { count: items.length - max })}`);
    return parts;
  };
  /** Domains as code spans: three, then "+N more". */
  const domains = (list) => values(list, 3);
  /** Plural count texts joined with ' · ', zeros left out. */
  const counts = (pairs) => pairs.filter(([, n]) => Number(n) > 0).map(([key, n]) => t(key, { count: Number(n) })).join(' · ');
  const title = (view, subject) => [`${t(`nav.${view}`)} · `, ...(Array.isArray(subject) ? subject : [String(subject ?? '')])];
  /** A line's parts with its first letter capitalised (a text that also sits mid-line lower-case). */
  const cap = (parts) => parts.map((p, i) => (i === 0 && typeof p === 'string' ? p.charAt(0).toLocaleUpperCase(lang === 'tr' ? 'tr-TR' : 'en-US') + p.slice(1) : p));
  return { t, num, values, domains, counts, title, cap };
}

function doc(kind, title, lines, { inline = false, when, url = null }) {
  return { kind, title, lines: lines.filter((l) => l && l.length), inline, footer: { when, url: url || null } };
}

function whenText(t, key, at, now) {
  const stamp = utcStamp(at instanceof Date || typeof at === 'number' || typeof at === 'string' ? at : now) || utcStamp(now);
  return t(key, { time: stamp });
}

// Private-use marks around a param's index while a text is translated ({@link textParts}).
const MARK_OPEN = String.fromCharCode(0xe000);
const MARK_CLOSE = String.fromCharCode(0xe001);
const MARKED = new RegExp(`${MARK_OPEN}(\\d+)${MARK_CLOSE}`);

/**
 * A translated text as parts with its quoted values as code spans: every string param that is
 * not a plain number (a name, a record value, a line of the file; each item of a list) goes
 * through `t` as a mark and is split back out, so the sentence stays translated and the value
 * stays inert. Numbers stay numbers (plural forms). Also used by the headless runner's
 * "Changes since the baseline" (tools/ds), whose finding titles quote the same values.
 * @param {Function} t
 * @param {string} key
 * @param {Record<string, unknown>} [params]
 * @returns {SummaryPart[]}
 */
export function textParts(t, key, params) {
  const values = [];
  const mark = (v) => {
    if (typeof v !== 'string' || !v.trim() || /^\d+$/.test(v.trim())) return v;
    values.push(v);
    return `${MARK_OPEN}${values.length - 1}${MARK_CLOSE}`;
  };
  const marked = {};
  for (const [name, v] of Object.entries(params || {})) {
    marked[name] = Array.isArray(v) ? v.map((x) => String(mark(x) ?? '')).join(', ') : mark(v);
  }
  return String(t(key, marked)).split(MARKED).map((s, i) => (i % 2 ? code(values[Number(s)]) : s)).filter((p) => p !== '');
}

/**
 * The first severity-sorted problems as "Error: title" lines, then "+N more". A problem is
 * `{ severity, key, params }` (translated here with {@link textParts}) or `{ severity, title }`.
 */
function problemLines(k, problems, max = SUMMARY_MAX_PROBLEMS) {
  const rank = { error: 0, warn: 1, info: 2 };
  const list = (problems || []).filter((p) => p && (p.severity === 'error' || p.severity === 'warn'))
    .map((p, i) => ({ p, i })).sort((a, b) => rank[a.p.severity] - rank[b.p.severity] || a.i - b.i).map((x) => x.p);
  const title = (p) => (p.key ? textParts(k.t, p.key, p.params) : [cleanText(p.title)]);
  const lines = list.slice(0, max).map((p) => [strong(`${k.t(`severity.${p.severity}`)}:`), ' ', ...title(p)]);
  if (list.length > max) lines.push([k.t('sum.moreProblems', { count: list.length - max })]);
  return lines;
}

/* ------------------------------------------------------------------------ */
/* The default view's builder                                               */
/* ------------------------------------------------------------------------ */

/**
 * Subdomains: found / resolving, the classes of the stat cards, proxied hosts with their origin
 * candidates, dangling CNAMEs by name, wildcard matches left out, failed sources. A cancelled
 * scan never says "no proxied host" or "no dangling CNAME".
 * @param {{ domains: string[], status: string, counts: { found: number, resolving: number, cloudflare: number,
 *   cdn: number, direct: number, private?: number, unresolved: number, dangling: number, wildcard?: number },
 *   proxied?: number, withCandidates?: number, networks?: number, dangling?: string[], failedSources?: number,
 *   at?: Date }} facts the stat cards (views/subdomains countHosts) and the ORIGIN panel's numbers
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function subdomainsSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const c = facts.counts || {};
  const found = Number(c.found) || 0;
  // A cancelled scan says what it found, never that something is absent: the rest was not looked at.
  const complete = facts.status !== 'cancelled';
  const lines = [];
  if (!found) {
    lines.push([t(facts.status === 'cancelled' ? 'sum.sub.noneCancelled' : 'sum.sub.none')]);
  } else {
    lines.push([t(facts.status === 'cancelled' ? 'sum.sub.foundCancelled' : 'sum.sub.found', { count: found }), ' · ', t('sum.sub.resolving', { count: Number(c.resolving) || 0 })]);
    const direct = c.direct > 0 ? `${t('sum.class.direct', { count: c.direct })}${c.private > 0 ? ` ${t('sum.class.private', { count: c.private })}` : ''}` : '';
    const classes = [k.counts([['sum.class.cloudflare', c.cloudflare], ['sum.class.cdn', c.cdn]]), direct, k.counts([['sum.class.unresolved', c.unresolved]])].filter(Boolean);
    if (classes.length) lines.push([classes.join(' · ')]);
    const proxied = Number(facts.proxied) || 0;
    if (proxied) {
      const bits = [t('sum.sub.proxied', { count: proxied })];
      if (facts.withCandidates > 0) bits.push(t('sum.sub.candidates', { count: facts.withCandidates }));
      if (facts.networks > 0) bits.push(t('sum.sub.networks', { count: facts.networks }));
      lines.push([bits.join(' · ')]);
    } else if (complete) {
      lines.push([t('sum.sub.proxiedNone')]);
    }
    const dangling = facts.dangling || [];
    if (dangling.length) lines.push([t('sum.sub.dangling', { count: dangling.length }), ': ', ...k.values(dangling)]);
    else if (complete) lines.push([t('sum.sub.danglingNone')]);
    if (c.wildcard > 0) lines.push([t('sum.sub.wildcard', { count: c.wildcard })]);
  }
  if (facts.failedSources > 0) lines.push([t('sum.sub.sourcesFailed', { count: facts.failedSources })]);
  return doc('subdomains', k.title('subdomains', k.domains(facts.domains)), lines,
    { when: whenText(t, 'sum.at.scanned', facts.at, opts.now || new Date()), url: opts.url });
}

const BUILDERS = {
  subdomains: subdomainsSummary
};

/**
 * What a builder outside this module works with (lib/summary.js, lib/reportsummary.js): the build context
 * (`kit(opts)`: `t`, `num`, `values`, `title` …), the document (`doc(kind, title, lines, { when, url })`),
 * the parts (`code`, `strong`), `isoDay`, the footer's `whenText(t, key, at, now)` and the "Error: title"
 * lines of `problemLines(k, problems, max)`.
 */
export const BUILDER_KIT = Object.freeze({ kit, doc, code, strong, isoDay, whenText, problemLines });

/**
 * Add the builder of a view whose summary loads with the view instead of the start route: every
 * view but Subdomains (lib/summary.js registers them when it loads) and DMARC & TLS reports
 * (lib/reportsummary.js, registered by views/reports.js with its strings).
 * @param {string} kind one of {@link SUMMARY_KINDS}
 * @param {(facts: object, opts: object) => SummaryDoc} build
 */
export function registerSummaryBuilder(kind, build) {
  if (!SUMMARY_KINDS.includes(kind)) throw new RangeError(`summary: unknown view "${kind}"`);
  if (typeof build !== 'function') throw new TypeError('summary: a builder is a function');
  BUILDERS[kind] = build;
}

/**
 * Build the summary of a view.
 * @param {string} kind one of {@link SUMMARY_KINDS}
 * @param {object} facts the builder's facts
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc} a RangeError for another view, or one whose builder has not loaded yet (lib/summary.js,
 *   or DMARC & TLS reports before its view)
 */
export function buildSummary(kind, facts, opts) {
  const fn = Object.hasOwn(BUILDERS, kind) ? BUILDERS[kind] : null;
  if (!fn) throw new RangeError(`summary: unknown view "${kind}"`);
  return fn(facts || {}, opts || {});
}

/* ------------------------------------------------------------------------ */
/* Rendering                                                                */
/* ------------------------------------------------------------------------ */

function partMarkdown(p) {
  if (p === null || p === undefined || p === '') return '';
  if (typeof p === 'object' && 'code' in p) return mdCode(p.code);
  if (typeof p === 'object' && 'strong' in p) return `**${mdEscape(p.strong)}**`;
  // Keep the spaces around separators (mdEscape trims): ' · ', ': '.
  const s = String(p);
  const lead = /^\s/.test(s) ? ' ' : '';
  const trail = /\s$/.test(s) ? ' ' : '';
  const body = mdEscape(s);
  return body ? `${lead}${body}${trail}` : (lead || trail);
}

function partText(p) {
  if (p === null || p === undefined || p === '') return '';
  if (typeof p === 'object' && 'code' in p) return shortValue(p.code);
  if (typeof p === 'object' && 'strong' in p) return cleanText(p.strong);
  const s = String(p);
  const body = cleanText(s);
  return body ? `${/^\s/.test(s) ? ' ' : ''}${body}${/\s$/.test(s) ? ' ' : ''}` : (/\s/.test(s) ? ' ' : '');
}

function joinParts(parts, fn) {
  return parts.map(fn).join('').replace(/ {2,}/g, ' ').trim();
}

function footerLine(footer, esc) {
  const bits = ['DomainScope', esc(footer.when)];
  // A bare URL: every chat and tracker links it, and it survives a paste into plain text.
  if (footer.url) bits.push(String(footer.url).replace(/\s/g, ''));
  return bits.join(' · ');
}

/**
 * The summary as Markdown: a bold title, one "- " line per fact, an empty line, the footer. The
 * empty line makes the footer its own paragraph: right after a list item (or the one-line
 * paragraph of DNS Lookup and IP Intel) CommonMark would continue that item with it.
 * @param {SummaryDoc} summary
 * @returns {string} with a trailing newline
 */
export function renderMarkdown(summary) {
  const title = `**${joinParts(summary.title, (p) => (typeof p === 'object' && p && 'code' in p ? mdCode(p.code) : partMarkdown(p)))}**`;
  const lines = summary.lines.map((l) => joinParts(l, partMarkdown));
  const body = summary.inline ? [`${title}: ${lines.join(' · ')}`] : [title, ...lines.map((l) => `- ${l}`)];
  return `${[...body, '', footerLine(summary.footer, mdEscape)].join('\n')}\n`;
}

/**
 * The same summary as plain text (no Markdown syntax), for tools that do not render it.
 * @param {SummaryDoc} summary
 * @returns {string} with a trailing newline
 */
export function renderPlainText(summary) {
  const title = joinParts(summary.title, partText);
  const lines = summary.lines.map((l) => joinParts(l, partText));
  const body = summary.inline ? [`${title}: ${lines.join(' · ')}`] : [title, ...lines.map((l) => `- ${l}`)];
  return `${[...body, footerLine(summary.footer, cleanText)].join('\n')}\n`;
}

/**
 * One line of parts in one of {@link SUMMARY_FORMATS}, by the rule of {@link renderMarkdown} /
 * {@link renderPlainText} (code spans for untrusted values, the rest escaped or cleaned). Used by
 * the headless runner (tools/ds) for its "Changes since the baseline" lines.
 * @param {SummaryPart[]} parts
 * @param {'markdown'|'text'} [format='markdown']
 * @returns {string}
 */
export function renderParts(parts, format = 'markdown') {
  return joinParts(Array.isArray(parts) ? parts : [], format === 'text' ? partText : partMarkdown);
}

/**
 * Render a summary in one of {@link SUMMARY_FORMATS}.
 * @param {SummaryDoc} summary
 * @param {'markdown'|'text'} [format='markdown']
 * @returns {string}
 */
export function renderSummary(summary, format = 'markdown') {
  return format === 'text' ? renderPlainText(summary) : renderMarkdown(summary);
}

/* ------------------------------------------------------------------------ */
/* i18n                                                                     */
/* ------------------------------------------------------------------------ */

const STRINGS = [
  ['sum.at.checked', ['checked {time}', 'kontrol edildi: {time}']],
  ['sum.at.scanned', ['scanned {time}', 'tarandı: {time}']],
  ['sum.at.asOf', ['as of {time}', '{time} itibarıyla']],
  ['sum.moreProblems', [{ one: '+{count} more warning or error', other: '+{count} more warnings and errors' }, '+{count} uyarı ya da hata daha']],
  ['sum.moreFindings', [{ one: '+{count} more finding', other: '+{count} more findings' }, '+{count} bulgu daha']],
  ['sum.count.error', [{ one: '{count} error', other: '{count} errors' }, '{count} hata']],
  ['sum.count.warn', [{ one: '{count} warning', other: '{count} warnings' }, '{count} uyarı']],
  ['sum.count.info', [{ one: '{count} note', other: '{count} notes' }, '{count} bilgi']],
  ['sum.count.ok', ['{count} passed', '{count} başarılı']],

  ['sum.sub.found', [{ one: '{count} subdomain found', other: '{count} subdomains found' }, '{count} subdomain bulundu']],
  ['sum.sub.foundCancelled', [{ one: '{count} subdomain found before the scan was cancelled', other: '{count} subdomains found before the scan was cancelled' },
    'Tarama iptal edilmeden önce {count} subdomain bulundu']],
  ['sum.sub.none', ['No subdomains found', 'Subdomain bulunamadı']],
  ['sum.sub.noneCancelled', ['The scan was cancelled before any subdomain was found', 'Tarama, subdomain bulunmadan iptal edildi']],
  ['sum.sub.resolving', [{ one: '{count} resolves', other: '{count} resolve' }, '{count} tanesi çözümleniyor']],
  ['sum.class.cloudflare', ['{count} Cloudflare', '{count} Cloudflare']],
  ['sum.class.cdn', ['{count} other CDN / platform', '{count} diğer CDN / platform']],
  ['sum.class.direct', [{ one: '{count} direct IP', other: '{count} direct IPs' }, '{count} doğrudan IP']],
  ['sum.class.private', ['({count} of them private)', '({count} tanesi özel IP)']],
  ['sum.class.unresolved', ['{count} not resolving', '{count} çözümlenmiyor']],
  ['sum.sub.proxied', [{ one: '{count} host hides its origin behind a proxy', other: '{count} hosts hide their origin behind a proxy' },
    '{count} host asıl sunucusunu bir proxy arkasında gizliyor']],
  ['sum.sub.proxiedNone', ['No host hides its origin behind a proxy', 'Asıl sunucusunu proxy arkasında gizleyen host yok']],
  ['sum.sub.candidates', [{ one: 'an origin candidate for {count} of them', other: 'origin candidates for {count} of them' }, '{count} tanesi için asıl sunucu adayı']],
  ['sum.sub.networks', [{ one: '{count} origin network to sweep', other: '{count} origin networks to sweep' }, 'taranacak {count} asıl sunucu ağı']],
  ['sum.sub.dangling', [{ one: '{count} dangling CNAME (possible takeover)', other: '{count} dangling CNAMEs (possible takeover)' },
    '{count} sahipsiz CNAME (olası ele geçirme)']],
  ['sum.sub.danglingNone', ['No dangling CNAMEs', 'Sahipsiz CNAME yok']],
  ['sum.sub.wildcard', [{ one: '{count} wildcard match left out', other: '{count} wildcard matches left out' }, '{count} joker (wildcard) eşleşme dışarıda bırakıldı']],
  ['sum.sub.sourcesFailed', [{ one: '{count} passive source failed: the list may be incomplete', other: '{count} passive sources failed: the list may be incomplete' },
    '{count} pasif kaynak başarısız: liste eksik olabilir']]
];

function buildStrings(lang) {
  return Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));
}

/**
 * English and Turkish texts of the `sum.*` keys the core and the Subdomains builder use (lib/summary.js
 * SUMMARY_I18N has them too, with every other view's). Placeholders: `{param}`; a text that shows a
 * number is a plural object `{ zero?, one?, other }`. ui/summary-button.js registers them.
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const SUMMARY_CORE_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
