/**
 * report.js — the customer report: a Domain overview (views/domain.js) or a Domain Health result
 * (views/health.js) as ONE self-contained HTML file, to send to a customer or print to PDF.
 *
 * - One file that loads nothing: the CSS is inline ({@link REPORT_CSS}, a light, print-friendly
 *   design in the app's look), there is no script at all, and a strict CSP meta
 *   ({@link REPORT_CSP}) refuses everything else (`style-src 'unsafe-inline'` only because the
 *   file stands alone, `img-src data:`). The document asks for no referrer.
 * - ONE escaping helper: the document is a tree of nodes ({@link el}); the serializer
 *   ({@link renderHtml}) writes every text node and every attribute value through
 *   {@link escapeHtml}, refuses element and attribute names outside its allow-lists, keeps an
 *   `href` only for an http(s) URL and writes no stylesheet but {@link REPORT_CSS}. No builder
 *   writes markup by hand: the file is opened outside the app, where an unescaped DNS, RDAP or
 *   Certificate Transparency value would run as script.
 * - Content ({@link ReportDoc}): the problems with their advice first, then the result's facts
 *   (the overview's cards: {@link domainReport}; Health's notes, passed checks and the records it
 *   read: {@link healthReport}), the time of the result and of the report, the tool version, what
 *   was checked, and on request the result's permalink — its inputs only ({@link reportLinkParams},
 *   lib/summarycore.js PERMALINK_PARAMS), never a result — so the recipient runs it again.
 * - Words come from the injected `t` in the UI language: the overview's own strings for its cards
 *   (`dov.*`, views/domain.js), lib/health.js HEALTH_I18N for the checks and {@link REPORT_I18N}
 *   (`crep.*`) for the rest. A lookup that failed is a status ("⚠ n/a — reason", the injected
 *   `statusText`), never an empty cell. Dates are UTC (`2026-10-08 13:47 UTC`), the same for every
 *   reader of the file. Never a TXT verification token, the inventory or workspace data.
 * - The app prints the same body (ui/report.js: a shadow root with REPORT_CSS as a constructed
 *   stylesheet, which the app's own CSP allows).
 *
 * DOM-free; runs in browsers and Node 22.
 */

/** The kinds of report: the view each one comes from. */
export const REPORT_KINDS = Object.freeze(['domain', 'health']);

/** Severities, worst first (lib/health.js HealthCheck.severity). */
export const REPORT_SEVERITIES = Object.freeze(['error', 'warn', 'info', 'ok']);

/** The report file's Content-Security-Policy: its own inline styles and data: images, nothing else. */
export const REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'";

/** File name stems (ui/download.js timestampedName adds the domain and the time). */
export const REPORT_FILE_BASES = Object.freeze({ domain: 'domain-overview-report', health: 'domain-health-report' });

/** The Domain overview's cards in their order (lib/passport.js PASSPORT_CARDS; a unit test keeps them equal). */
const DOMAIN_CARDS = Object.freeze(['registration', 'dns', 'mail', 'web', 'certs', 'saas', 'health']);

/** Domain Health's check groups in their order (views/health.js HEALTH_GROUPS). */
const HEALTH_GROUPS = Object.freeze(['dns', 'email', 'security', 'registration']);

/** lib/health.js LOOKUP_FAILED_PARAM: a check parameter that stands for a failed lookup. */
const LOOKUP_FAILED = 'lookup failed';

/** The glyph next to each severity's word, so the colour is never the only signal. */
const SEVERITY_GLYPHS = Object.freeze({ error: '✗', warn: '!', info: 'i', ok: '✓' });

/* ------------------------------------------------------------------------ */
/* Escaping and the document tree                                           */
/* ------------------------------------------------------------------------ */

/** The characters HTML gives a meaning, as entities. */
const ENTITIES = Object.freeze({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' });

// C0 / C1 controls (tab, newline and carriage return kept) and every bidi control: shown as
// U+FFFD, so a value can neither hide text nor reorder what the reader sees.
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]/g;

/**
 * THE escaping helper of the report: a value as HTML text or as a quoted attribute value.
 * `& < > " ' \`` become entities; control and bidi characters become U+FFFD; null and undefined
 * are empty. Every text node and attribute value of a report goes through it ({@link renderHtml}).
 * @param {unknown} value
 * @returns {string}
 */
export function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(UNSAFE_CHARS, '\ufffd').replace(/[&<>"'`]/g, (c) => ENTITIES[c]);
}

/**
 * @typedef {object} ReportNode
 * @property {string} tag
 * @property {Record<string, string|number|boolean|null|undefined>} attrs
 * @property {Array<ReportNode|string>} children
 */

/**
 * A node of the report tree. Children: nodes and text (numbers become text); null, undefined,
 * false and '' are dropped and arrays flattened.
 * @param {string} tag
 * @param {Record<string, unknown>|null} [attrs]
 * @param {...unknown} children
 * @returns {ReportNode}
 */
export function el(tag, attrs, ...children) {
  return {
    tag,
    attrs: attrs || {},
    children: children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false && c !== '')
      .map((c) => (typeof c === 'object' ? c : String(c)))
  };
}

/** The elements a report is made of. */
const TAGS = new Set(['html', 'head', 'meta', 'title', 'style', 'body', 'header', 'main', 'section', 'footer', 'div', 'h1', 'h2', 'h3',
  'p', 'ul', 'ol', 'li', 'table', 'tbody', 'tr', 'th', 'td', 'span', 'strong', 'code', 'a', 'time']);
/** Elements without an end tag. */
const VOID_TAGS = new Set(['meta']);
/** The attributes a report uses (and data-*). */
const ATTRS = new Set(['class', 'lang', 'charset', 'name', 'content', 'http-equiv', 'href', 'rel', 'title', 'scope', 'datetime']);
const DATA_ATTR = /^data-[a-z][a-z0-9-]*$/;

/**
 * Is `value` an absolute http(s) URL (the only kind of link a report keeps)?
 * @param {unknown} value
 * @returns {boolean}
 */
export function isWebUrl(value) {
  try {
    const u = new URL(String(value));
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

/**
 * Serialize a report tree. Text and attribute values always go through {@link escapeHtml}; an
 * element or attribute name outside the allow-lists throws (they come from code, never from
 * data); an `href` that is not http(s) is dropped; `<style>` takes {@link REPORT_CSS} and nothing
 * else.
 * @param {ReportNode|string} node
 * @returns {string}
 */
export function renderHtml(node) {
  if (typeof node === 'string') return escapeHtml(node);
  if (!node || typeof node !== 'object' || !TAGS.has(node.tag)) throw new TypeError(`report: element not allowed: ${node && node.tag}`);
  let out = `<${node.tag}`;
  for (const [name, value] of Object.entries(node.attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (!ATTRS.has(name) && !DATA_ATTR.test(name)) throw new TypeError(`report: attribute not allowed: ${name}`);
    if (name === 'href' && !isWebUrl(value)) continue;
    out += value === true ? ` ${name}` : ` ${name}="${escapeHtml(value)}"`;
  }
  out += '>';
  if (VOID_TAGS.has(node.tag)) return out;
  if (node.tag === 'style') {
    if (node.children.length !== 1 || node.children[0] !== REPORT_CSS) throw new TypeError('report: a stylesheet other than REPORT_CSS');
    return `${out}${REPORT_CSS}</style>`;
  }
  return `${out}${node.children.map(renderHtml).join('')}</${node.tag}>`;
}

/* ------------------------------------------------------------------------ */
/* The stylesheet                                                           */
/* ------------------------------------------------------------------------ */

/**
 * The report's CSS: the app's light palette and type, one column, severity colours with a glyph
 * and a word, and a print layout (no background, sections kept whole). Selectors start at `.crep`
 * (the file's body, or the app's print host), so the sheet styles nothing else.
 */
export const REPORT_CSS = [
  '.crep{--text:#14171c;--text-2:#464d5b;--muted:#5d6675;--border:#e2e5ea;--surface:#fff;--surface-2:#f6f7f9;--accent:#1d4ed8;',
  '--ok:#157a3d;--ok-bg:#ebf7ef;--ok-border:#bfe4cb;--info:#1d4ed8;--info-bg:#edf3ff;--info-border:#cadbfd;',
  '--warn:#975a06;--warn-bg:#fdf5e6;--warn-border:#f1d9a8;--error:#b9232a;--error-bg:#fdeeee;--error-border:#f4c4c6;',
  'margin:0;padding:32px 16px 48px;background:#f4f5f7;color:var(--text);',
  'font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue","Noto Sans",Arial,sans-serif;',
  '-webkit-print-color-adjust:exact;print-color-adjust:exact;overflow-wrap:anywhere}',
  '.crep *{box-sizing:border-box}',
  '.crep-page{max-width:860px;margin:0 auto;display:flex;flex-direction:column;gap:16px}',
  '.crep code,.crep .crep-mono{font-family:ui-monospace,"SFMono-Regular","SF Mono","Cascadia Mono","Segoe UI Mono",Menlo,Consolas,monospace;font-size:.92em}',
  '.crep h1,.crep h2,.crep h3,.crep p{margin:0}',
  '.crep a{color:var(--accent)}',
  '.crep-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 20px}',
  '.crep-head{display:flex;flex-direction:column;gap:10px}',
  '.crep-kicker{color:var(--muted);font-size:12px;font-weight:600;letter-spacing:.04em;text-transform:uppercase}',
  '.crep h1.crep-subject{font-size:26px;line-height:1.2;font-weight:700}',
  '.crep-sub{color:var(--text-2)}',
  '.crep-meta{align-self:flex-start;border-collapse:collapse;font-size:13px}',
  '.crep-meta th{color:var(--muted);font-weight:500;text-align:left;padding:2px 16px 2px 0;vertical-align:top;white-space:nowrap}',
  '.crep-meta td{padding:2px 0}',
  '.crep-verdict{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;border:1px solid var(--border);border-left-width:4px;border-radius:8px;padding:12px 14px}',
  '.crep-light-ok{border-color:var(--ok-border);border-left-color:var(--ok);background:var(--ok-bg)}',
  '.crep-light-warn{border-color:var(--warn-border);border-left-color:var(--warn);background:var(--warn-bg)}',
  '.crep-light-error{border-color:var(--error-border);border-left-color:var(--error);background:var(--error-bg)}',
  '.crep-score{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums}',
  '.crep-verdict-label{font-weight:600}',
  '.crep-verdict-body{flex-basis:100%;color:var(--text-2)}',
  '.crep-counts{display:flex;flex-wrap:wrap;gap:6px;list-style:none;margin:0;padding:0}',
  '.crep-section{display:flex;flex-direction:column;gap:10px;break-inside:avoid-page}',
  '.crep-section h2{font-size:16px;font-weight:650}',
  '.crep-facts{width:100%;border-collapse:collapse}',
  '.crep-facts th,.crep-facts td{border-top:1px solid var(--border);padding:7px 0;text-align:left;vertical-align:top}',
  '.crep-facts tr:first-child th,.crep-facts tr:first-child td{border-top:0}',
  '.crep-facts th{width:32%;padding-right:16px;color:var(--text-2);font-weight:500}',
  '.crep-values{list-style:none;margin:0;padding:0}',
  '.crep-badge{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:0 8px;font-size:12px;font-weight:600;white-space:nowrap;background:var(--surface-2)}',
  '.crep-sev-ok .crep-badge,.crep-badge.crep-sev-ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-border)}',
  '.crep-sev-info .crep-badge,.crep-badge.crep-sev-info{color:var(--info);background:var(--info-bg);border-color:var(--info-border)}',
  '.crep-sev-warn .crep-badge,.crep-badge.crep-sev-warn{color:var(--warn);background:var(--warn-bg);border-color:var(--warn-border)}',
  '.crep-sev-error .crep-badge,.crep-badge.crep-sev-error{color:var(--error);background:var(--error-bg);border-color:var(--error-border)}',
  'td.crep-sev-warn,td.crep-sev-error{font-weight:600}',
  'td.crep-sev-warn{color:var(--warn)}td.crep-sev-error{color:var(--error)}td.crep-sev-ok{color:var(--ok)}',
  '.crep-note{border-left:3px solid var(--border);padding:2px 0 2px 10px;color:var(--text-2)}',
  '.crep-note.crep-sev-warn{border-left-color:var(--warn)}.crep-note.crep-sev-error{border-left-color:var(--error)}.crep-note.crep-sev-info{border-left-color:var(--info)}',
  '.crep-items{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:10px}',
  '.crep-item{border:1px solid var(--border);border-left-width:4px;border-radius:8px;padding:10px 12px;break-inside:avoid}',
  '.crep-item.crep-sev-error{border-left-color:var(--error)}.crep-item.crep-sev-warn{border-left-color:var(--warn)}.crep-item.crep-sev-info{border-left-color:var(--info)}',
  '.crep-item-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 8px}',
  '.crep-item-group{color:var(--muted);font-size:12px}',
  '.crep-item-detail{margin-top:4px;color:var(--text-2)}',
  '.crep-passed{margin:0;padding-left:18px;columns:2;column-gap:24px;color:var(--text-2)}',
  '.crep-group{font-size:13px;font-weight:600;color:var(--muted)}',
  '.crep-muted{color:var(--muted)}',
  '.crep-method ul{margin:0;padding-left:18px;color:var(--text-2)}',
  '.crep-foot{color:var(--muted);font-size:12px;display:flex;flex-direction:column;gap:4px;padding:0 4px}',
  '@media (max-width:640px){.crep{padding:16px 12px 32px}.crep-card{padding:14px}.crep-facts th{width:40%}.crep-passed{columns:1}}',
  '@page{margin:14mm 12mm}',
  '@media print{.crep{background:#fff;padding:0;font-size:12px}.crep-page{max-width:none;gap:10px}',
  '.crep-card{border-radius:0;border-width:0 0 1px;padding:10px 0}.crep a{color:inherit}.crep h2{break-after:avoid}}'
].join('');

/* ------------------------------------------------------------------------ */
/* The report document                                                      */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ReportItem a check: a problem with its advice, a note, a passed check
 * @property {'error'|'warn'|'info'|'ok'} severity
 * @property {string} title
 * @property {string} [detail] the explanation and what to do
 * @property {string} [group] the check group's name
 */

/**
 * @typedef {object} ReportRow one fact
 * @property {string} label
 * @property {string|string[]} value a list is one value a line
 * @property {'error'|'warn'|'info'|'ok'} [severity]
 * @property {boolean} [mono] host names, records: monospace
 */

/**
 * @typedef {object} ReportSection
 * @property {string} id
 * @property {string} title
 * @property {ReportRow[]} [rows]
 * @property {Array<{ severity?: string|null, text: string, href?: string|null }>} [notes]
 * @property {ReportItem[]} [items]
 * @property {Array<{ group: string, titles: string[] }>} [passed]
 */

/**
 * @typedef {object} ReportDoc
 * @property {'domain'|'health'} kind
 * @property {string} subject the domain
 * @property {string|null} subtitle
 * @property {Date|null} at when the result was made
 * @property {{ light: 'ok'|'warn'|'error', score: number, label: string, body?: string|null,
 *   counts: Array<{ severity: string, text: string }> }|null} verdict
 * @property {ReportItem[]} problems errors and warnings with their advice, worst first
 * @property {boolean} problemsKnown false when the health checks did not run (no problem list)
 * @property {ReportSection[]} sections
 * @property {string[]} method what was checked
 */

const two = (n) => String(n).padStart(2, '0');
const asDate = (v) => {
  const d = v instanceof Date ? v : v === null || v === undefined || v === '' ? null : new Date(v);
  return d && !Number.isNaN(d.getTime()) ? d : null;
};

/**
 * A day in UTC (`2026-10-08`), or '' for no date.
 * @param {Date|string|number|null} value
 * @returns {string}
 */
export function utcDay(value) {
  const d = asDate(value);
  return d ? `${d.getUTCFullYear()}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())}` : '';
}

/**
 * A time in UTC (`2026-10-08 13:47 UTC`), or '' for no date.
 * @param {Date|string|number|null} value
 * @returns {string}
 */
export function utcTime(value) {
  const d = asDate(value);
  return d ? `${utcDay(d)} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())} UTC` : '';
}

/** The text helpers a builder uses: `t`, `say` (a key that may be missing → fallback), `na` (a failure). */
function words(opts = {}) {
  const t = opts.t;
  if (typeof t !== 'function') throw new TypeError('report: opts.t is required');
  const has = typeof opts.has === 'function' ? opts.has : () => true;
  const statusText = typeof opts.statusText === 'function' ? opts.statusText : (f) => (f && (f.reason || f.error)) || '';
  const say = (key, params, fallback) => (key && has(key) ? t(key, params) : fallback);
  const na = (failure) => t('crep.na', { reason: statusText(failure) || t('crep.lookupFailed') });
  // lib/health passes booleans as the English words 'yes' / 'no' and a failed lookup as 'lookup failed'.
  const local = { yes: 'common.yes', no: 'common.no', [LOOKUP_FAILED]: 'crep.lookupFailed' };
  const params = (p) => Object.fromEntries(Object.entries(p || {})
    .map(([k, v]) => [k, typeof v === 'string' && Object.hasOwn(local, v) ? t(local[v]) : v]));
  return { t, say, na, params, statusText };
}

/** A check as a report item: its title and its explanation (the advice) in the UI language. */
function checkItem(c, w) {
  const p = w.params(c.params);
  const fallback = Object.entries(c.params || {}).map(([k, v]) => `${k}: ${v}`).join(' · ');
  return {
    severity: REPORT_SEVERITIES.includes(c.severity) ? c.severity : 'info',
    title: w.say(c.titleKey, p, c.id),
    detail: w.say(c.detailKey, p, fallback),
    group: c.group ? w.say(`health.group.${c.group}`, null, c.group) : null
  };
}

/** Errors, then warnings, in Health's group order, then in check order. */
function problemsOf(checks, w) {
  const rank = (c) => REPORT_SEVERITIES.indexOf(c.severity);
  const group = (c) => {
    const i = HEALTH_GROUPS.indexOf(c.group || 'dns');
    return i === -1 ? HEALTH_GROUPS.length : i;
  };
  return (Array.isArray(checks) ? checks : []).map((c, i) => ({ c, i }))
    .filter(({ c }) => c.severity === 'error' || c.severity === 'warn')
    .sort((a, b) => rank(a.c) - rank(b.c) || group(a.c) - group(b.c) || a.i - b.i)
    .map(({ c }) => checkItem(c, w));
}

/**
 * The score, the traffic light and the counts of a Health summary. `waived`: the accepted risks
 * left out of the counts (and so of the score), said as their own count.
 */
function verdictOf(summary, w, { body = true, waived = null } = {}) {
  const s = summary || {};
  const less = (k) => (waived && waived[k]) || 0;
  const n = (k) => Math.max(0, (Number(s[k]) || 0) - less(k));
  const light = n('error') ? 'error' : n('warn') ? 'warn' : 'ok';
  const score = Math.max(0, Math.min(100, 100 - 20 * n('error') - 6 * n('warn')));
  const total = n('ok') + n('info') + n('warn') + n('error');
  const accepted = less('error') + less('warn');
  return {
    light,
    score,
    label: w.t(`crep.light.${light}`),
    body: body ? w.t(`crep.light.${light}Body`, { count: total }) : null,
    counts: [
      ...REPORT_SEVERITIES.filter((k) => n(k)).map((k) => ({ severity: k, text: w.t(`crep.count.${k}`, { count: n(k) }) })),
      ...(accepted ? [{ severity: 'info', text: w.t('crep.waived', { count: accepted }) }] : [])
    ]
  };
}

const row = (label, value, extra = {}) => ({ label, value, ...extra });
const note = (severity, text, href = null) => ({ severity, text, href });
const hasValue = (r) => r && r.value !== null && r.value !== undefined && r.value !== '' && !(Array.isArray(r.value) && !r.value.length);

/* --- the Domain overview ------------------------------------------------------------ */

/**
 * The Domain overview's report: its seven cards as sections (what each card shows, in its words),
 * the health card's problems with their advice first, its score as the verdict. A card not looked
 * up (a stopped build) says so; a failed lookup is "⚠ n/a" with the reason. The CT issuers appear
 * when they were asked for. Never a TXT token.
 * @param {{ cards: Record<string, object>, domain: string, host?: string|null, at?: Date|null }} input
 *   lib/passport.js passportCards() and the overview's domain, its host when reduced, its time
 * @param {{ t: Function, has?: (key: string) => boolean, statusText?: (status: object) => string }} opts
 * @returns {ReportDoc}
 */
export function domainReport(input, opts) {
  const w = words(opts);
  const { t, na } = w;
  const cards = (input && input.cards) || {};
  const d = String((input && input.domain) || '');
  const host = input && input.host ? String(input.host) : null;
  const failureFor = (card, lookup) => (card.failures || []).find((f) => f.lookup === lookup) || null;
  const more = (list, n = 3) => (list.length > n ? [...list.slice(0, n), t('common.moreCount', { count: list.length - n })] : list);
  const nx = () => ({ notes: [note('error', t('dov.nxdomain'))] });

  const BODIES = {
    registration(card) {
      if (card.outcome === 'unsupported') {
        const wh = card.whois;
        return {
          notes: [note('info', t('dov.reg.unsupported', { tld: card.tld || '' })),
            wh ? note(null, wh.iana ? t('dov.reg.iana', { tld: card.tld || '' }) : t('dov.reg.whois', { registry: wh.name }), wh.url) : null].filter(Boolean)
        };
      }
      if (card.outcome === 'not-found') return { notes: [note('warn', t('dov.reg.notFound', { domain: card.domain || d }))] };
      if (card.outcome === 'invalid') return { notes: [note('info', t('dov.reg.invalid'))] };
      if (card.outcome === 'failed') {
        const f = (card.failures || [])[0] || null;
        return { rows: ['dov.reg.registrar', 'dov.reg.expires', 'dov.reg.status', 'dov.reg.nameservers'].map((k) => row(t(k), na(f), { severity: 'warn' })) };
      }
      const days = card.daysLeft === null || card.daysLeft === undefined ? null
        : card.daysLeft < 0 ? t('dov.reg.daysAgo', { count: -card.daysLeft }) : t('dov.reg.daysLeft', { count: card.daysLeft });
      const expirySeverity = { expired: 'error', error: 'error', warn: 'warn', ok: 'ok' }[card.expiry] || null;
      const notes = [];
      if (card.transferLock === false) notes.push(note('warn', t('dov.reg.lockOffNote')));
      return {
        rows: [
          card.domain && card.domain !== d ? row(t('dov.reg.registryDomain'), card.domain, { mono: true }) : null,
          row(t('dov.reg.registrar'), card.registrar ? `${card.registrar}${card.ianaId ? ` · ${t('dov.reg.ianaId', { id: card.ianaId })}` : ''}` : null),
          row(t('dov.reg.created'), utcDay(card.created)),
          row(t('dov.reg.expires'), card.expires ? [utcDay(card.expires), days].filter(Boolean).join(' · ') : null, { severity: expirySeverity }),
          row(t('dov.reg.lock'), card.transferLock === true ? t('dov.reg.lockOn') : card.transferLock === false ? t('dov.reg.lockOff') : t('dov.reg.lockUnknown'),
            { severity: card.transferLock === true ? 'ok' : card.transferLock === false ? 'warn' : null }),
          row(t('dov.reg.status'), (card.flags || []).map((x) => x.code).join(', ')),
          row(t('dov.reg.dnssec'), card.dnssec === null || card.dnssec === undefined ? null : t(card.dnssec ? 'dov.reg.signed' : 'dov.reg.unsigned')),
          row(t('dov.reg.nameservers'), card.nameservers || [], { mono: true })
        ],
        notes
      };
    },
    dns(card) {
      if (card.exists === false) return nx();
      const hosting = card.hosting || { providers: [], self: [], other: [] };
      const nsFailure = failureFor(card, 'ns');
      const soaFailure = failureFor(card, 'soa');
      const dsFailure = failureFor(card, 'ds') || (card.dnssec === 'failing' ? null : failureFor(card, 'dnskey'));
      const who = [...hosting.providers.map((p) => p.name), hosting.self.length ? t('dov.dns.own') : null,
        hosting.other.length ? `${t('dov.dns.other')} (${hosting.other.length})` : null].filter(Boolean);
      const soa = card.soa;
      const notes = [];
      if (hosting.providers.length > 1) notes.push(note('info', t('dov.dns.multi', { count: hosting.providers.length })));
      if (card.delegation) notes.push(note('warn', t('dov.dns.delegation', { registry: card.delegation.registry.join(', '), zone: (card.nameservers || []).join(', ') })));
      if (!nsFailure && card.noNs) notes.push(note('info', t('dov.dns.noNs')));
      return {
        rows: [
          row(t('dov.dns.provider'), nsFailure ? na(nsFailure) : who.join(', '), { severity: nsFailure ? 'warn' : null }),
          row(t('dov.dns.nameservers'), nsFailure ? na(nsFailure) : card.nameservers || [], { mono: !nsFailure, severity: nsFailure ? 'warn' : null }),
          row(t('dov.dns.soa'), soaFailure ? na(soaFailure) : soa ? [t('dov.dns.soaValue', { mname: soa.mname, serial: String(soa.serial) }),
            soa.serialDate ? t('dov.dns.serialDate', { date: soa.serialDate }) : null].filter(Boolean) : null, { severity: soaFailure ? 'warn' : null }),
          soa && soa.email ? row(t('dov.dns.contact'), soa.email, { mono: true }) : null,
          row(t('dov.dns.dnssec'), card.dnssec ? t(`dov.dns.dnssec.${card.dnssec}`) : dsFailure ? na(dsFailure) : null,
            { severity: card.dnssec === 'validated' ? 'ok' : card.dnssec === 'failing' ? 'error' : dsFailure ? 'warn' : null })
        ],
        notes
      };
    },
    mail(card) {
      if (card.exists === false) return nx();
      const mxFailure = failureFor(card, 'mx');
      const txtFailure = failureFor(card, 'txt');
      const dmarcFailure = failureFor(card, 'dmarc');
      const mx = card.mx;
      let receives = null;
      if (mxFailure) receives = na(mxFailure);
      else if (mx && mx.state === 'none') receives = t('dov.mail.noMx');
      else if (mx && mx.state === 'null') receives = t('dov.mail.nullMx');
      else if (mx) {
        receives = [...mx.platforms.map((p) => (p.kind === 'mailbox' ? p.name : `${p.name} · ${t(`dov.mail.kind.${p.kind}`)}`)),
          mx.other.length ? `${t('dov.dns.other')} (${mx.other.length})` : null].filter(Boolean).join(', ');
      }
      const spf = card.spf;
      let spfLine = null;
      let spfSeverity = null;
      if (txtFailure) [spfLine, spfSeverity] = [na(txtFailure), 'warn'];
      else if (spf && spf.state === 'ok') {
        spfLine = spf.all ? t(`dov.mail.spf.${spf.all}`) : spf.redirect ? t('dov.mail.spf.redirect', { domain: spf.redirect }) : t('dov.mail.spf.noAll');
        spfSeverity = spf.all === '-' ? 'ok' : spf.all === '+' ? 'error' : null;
      } else if (spf) [spfLine, spfSeverity] = [t(`dov.mail.spf.${spf.state}`, { count: spf.count }), spf.state === 'none' ? 'warn' : 'error'];
      const senders = spf && spf.state === 'ok' ? more([...spf.senders.map((s) => s.name), ...spf.other]) : [];
      const dm = card.dmarc;
      let dmarcLine = null;
      let dmarcSeverity = null;
      if (dmarcFailure) [dmarcLine, dmarcSeverity] = [na(dmarcFailure), 'warn'];
      else if (dm && dm.state === 'ok') {
        dmarcLine = [t(`dov.mail.dmarc.${dm.policy || 'none'}`), dm.pct < 100 ? t('dov.mail.dmarc.pct', { pct: dm.pct }) : null,
          dm.reports ? t('dov.mail.dmarc.reports', { count: dm.reports }) : null].filter(Boolean).join(' · ');
        dmarcSeverity = dm.policy === 'reject' ? 'ok' : dm.policy === 'quarantine' ? null : 'warn';
      } else if (dm) [dmarcLine, dmarcSeverity] = [t(dm.state === 'none' ? 'dov.mail.dmarc.missing' : `dov.mail.dmarc.${dm.state}`, { count: dm.count }), 'warn'];
      return {
        rows: [
          row(t('dov.mail.receives'), receives, { severity: mxFailure ? 'warn' : null }),
          mx && mx.hosts.length ? row(t('dov.mail.hosts'), mx.hosts.map((m) => `${m.preference} ${m.exchange}${m.own ? ` · ${t('dov.mail.own')}` : ''}`), { mono: true }) : null,
          row(t('dov.mail.spf'), spfLine, { severity: spfSeverity }),
          senders.length ? row(t('dov.mail.senders'), senders.join(', ')) : null,
          row(t('dov.mail.dmarc'), dmarcLine, { severity: dmarcSeverity })
        ]
      };
    },
    web(card) {
      if (card.exists === false) return nx();
      const kindName = (c) => {
        const kind = c && c.kind ? c.kind : 'unresolved';
        const label = w.say(`kind.${kind}`, null, kind);
        return c && c.provider && c.provider.name && kind !== 'cloudflare' ? `${label} · ${c.provider.name}` : label;
      };
      const hostValue = (x) => {
        if (x.state === 'failed') return na(x.failure);
        if (x.state === 'pending') return t('dov.notLooked');
        if (x.state === 'nxdomain') return t('dov.web.nxdomain');
        if (x.state === 'nodata') return t('dov.web.nodata');
        const ips = [...(x.ipv4 || []), ...(x.ipv6 || [])];
        const target = x.cnames && x.cnames.length ? x.cnames[x.cnames.length - 1] : null;
        return [
          [kindName(x.classification), x.aliasOfApex ? t('dov.web.alias', { domain: d }) : x.sameAsApex ? t('dov.web.same', { domain: d }) : null].filter(Boolean).join(' · '),
          target && !x.aliasOfApex ? `CNAME → ${target}` : null,
          ips.length ? more(ips).join(', ') : null
        ].filter(Boolean);
      };
      const https = (x, failure) => {
        if (failure) return na(failure);
        if (!x) return null;
        return x.present ? [t('common.yes'), ...(x.alpn || [])].join(' · ') : t('dov.web.httpsNone');
      };
      const hosts = card.hosts || [];
      const rows = hosts.map((x) => row(x.name, hostValue(x), { severity: x.state === 'failed' ? 'warn' : null }));
      const [apex, www] = hosts;
      if (apex) rows.push(row(`${t('dov.web.https')} · ${apex.name}`, https(card.https && card.https.apex, failureFor(card, 'https'))));
      if (www) rows.push(row(`${t('dov.web.https')} · ${www.name}`, https(card.https && card.https.www, failureFor(card, 'wwwHttps'))));
      return { rows };
    },
    certs(card) {
      const caa = card.caa;
      const caaFailure = failureFor(card, 'caa');
      const rows = [];
      const notes = [];
      const caName = (e) => `${e.ca ? e.ca.name : e.issuer}${e.restricted ? ` (${t('dov.certs.restricted')})` : ''}`;
      if (card.exists === false) notes.push(note('error', t('dov.nxdomain')));
      else if (caaFailure) rows.push(row(t('dov.certs.caa'), na(caaFailure), { severity: 'warn' }));
      else if (caa && caa.state === 'none') notes.push(note('info', t('dov.certs.caaNone')));
      else if (caa && caa.state === 'critical') notes.push(note('error', t('dov.certs.caaCritical', { tags: caa.criticalTags.join(', '), count: caa.criticalTags.length })));
      else if (caa && caa.state === 'deny-all') notes.push(note('error', t('dov.certs.caaDeny')));
      else if (caa) {
        rows.push(row(t('dov.certs.allowed'), caa.state === 'unrestricted' ? t('dov.certs.anyCa') : caa.issue.length ? caa.issue.map(caName).join(', ') : t('dov.certs.wildNone')));
        if (caa.wildcardOnly) rows.push(row(t('dov.certs.wildcard'), caa.issuewild.length ? caa.issuewild.map(caName).join(', ') : t('dov.certs.wildNone')));
      }
      if (caa && caa.foundAt && caa.foundAt !== d) notes.push(note(null, t('dov.certs.inherited', { name: caa.foundAt })));
      const ct = card.ct;
      const verdicts = { allowed: 'dov.certs.ctAllowed', restricted: 'dov.certs.ctRestricted', denied: 'dov.certs.ctDenied', unknown: 'dov.certs.ctUnknown' };
      if (!ct) rows.push(row(t('dov.certs.ct'), t('crep.ctNotAsked')));
      else if (ct.state === 'failed') rows.push(row(t('dov.certs.ct'), (ct.failures || []).map(na).join(' · ') || na(null), { severity: 'warn' }));
      else if (ct.state === 'ok') {
        rows.push(row(t('dov.certs.ct'), ct.issuers.length ? ct.issuers.map((i) => [i.name, t('dov.certs.ctCount', { count: i.count }),
          i.newest ? t('dov.certs.ctNewest', { date: utcDay(i.newest) }) : null, verdicts[i.verdict] ? t(verdicts[i.verdict]) : null].filter(Boolean).join(' · '))
          : t('dov.certs.ctEmpty', { domain: d }), { severity: ct.notAllowed.length ? 'warn' : null }));
        if (ct.notAllowed.length) {
          const key = caa && caa.state === 'critical' ? 'dov.certs.ctCriticalNote'
            : caa && caa.state === 'present' && !caa.issue.length && caa.issuewild.length ? 'dov.certs.ctIssueNote' : 'dov.certs.ctDeniedNote';
          notes.push(note('warn', t(key, { list: ct.notAllowed.join(', '), count: ct.notAllowed.length, domain: d })));
        }
        notes.push(note(null, ct.provider === 'crtsh' ? t('dov.certs.ctCrtsh', { count: ct.certificates }) : t('dov.certs.ctFirstPage', { count: ct.certificates })));
      }
      return { rows, notes };
    },
    saas(card) {
      if (card.exists === false) return nx();
      const txtFailure = failureFor(card, 'txt');
      if (txtFailure) return { rows: [row('TXT', na(txtFailure), { severity: 'warn' })] };
      const s = card.saas;
      if (!s) return {};
      return {
        rows: [row(t('crep.services'), s.vendors.length ? s.vendors.map((v) => (v.count > 1 ? t('dov.saas.chip', { name: v.name, count: v.count }) : v.name)).join(', ') : t('dov.saas.none'))],
        notes: [s.other ? note(null, t('dov.saas.other', { count: s.other })) : null, note(null, t('dov.saas.note'))].filter(Boolean)
      };
    },
    health(card) {
      if ((card.failures || []).length) return { notes: [note('error', t('dov.health.failed')), ...card.failures.map((f) => note('warn', na(f)))] };
      if (!card.summary) return {};
      const v = verdictOf(card.summary, w, { body: false });
      return {
        rows: [row(t('crep.verdict'), `${v.label} · ${t('dov.health.score', { score: v.score })}`, { severity: v.light }),
          v.counts.length ? row(t('crep.counts'), v.counts.map((c) => c.text).join(' · ')) : null]
      };
    }
  };

  const sections = DOMAIN_CARDS.map((id) => {
    const card = cards[id];
    const title = t(`dov.card.${id}`);
    if (!card) return { id, title, notes: [note('info', t('dov.notLooked'))] };
    if (card.state === 'pending') {
      return { id, title, notes: [note('info', t('dov.notLooked')), ...(card.failures || []).map((f) => note('warn', na(f)))] };
    }
    const body = BODIES[id](card);
    const rows = (body.rows || []).filter(hasValue);
    return { id, title, rows, notes: body.notes || [] };
  });

  const health = cards.health && cards.health.state === 'ready' && !(cards.health.failures || []).length ? cards.health : null;
  return {
    kind: 'domain',
    subject: d,
    subtitle: host ? t('dov.reduced', { domain: d, host }) : null,
    at: asDate(input && input.at),
    verdict: health && health.summary ? verdictOf(health.summary, w) : null,
    problems: health && health.report ? problemsOf(health.report.checks, w) : [],
    problemsKnown: !!(health && health.report),
    sections,
    method: ['crep.method.domain.dns', 'crep.method.domain.rdap', 'crep.method.domain.ct', 'crep.method.domain.health', 'crep.method.when', 'crep.method.private'].map((k) => t(k))
  };
}

/* --- Domain Health ------------------------------------------------------------------ */

/**
 * Domain Health's report: the verdict (light, score, counts), the errors and warnings with their
 * advice first, then the notes, the passed checks by group and the records the checks read (a
 * lookup that failed says so). The DKIM selectors added to the check are named in "what was
 * checked". The accepted risks (`waived`, lib/waivers.js healthWaivers: each check's waiver) are
 * left out of the problems and the counts, said as "N accepted risks excluded", and listed in a
 * section of their own with their reason, owner and end date.
 * @param {{ report: object, selectors?: string[], waived?: { applied: Array<{ id: string, reason: string, owner?: string, expires: string }> }|null }} input
 *   lib/health.js domainHealth(), the extra selectors and the accepted risks (by check id)
 * @param {{ t: Function, has?: (key: string) => boolean, statusText?: (status: object) => string }} opts
 * @returns {ReportDoc}
 */
export function healthReport(input, opts) {
  const w = words(opts);
  const { t } = w;
  const r = (input && input.report) || {};
  const waivers = new Map(((input && input.waived && input.waived.applied) || []).filter((x) => x && typeof x.id === 'string').map((x) => [x.id, x]));
  const accepted = (c) => waivers.has(c.id) && (c.severity === 'error' || c.severity === 'warn');
  const all = Array.isArray(r.checks) ? r.checks : [];
  const waivedChecks = all.filter(accepted);
  const checks = all.filter((c) => !accepted(c));
  const selectors = Array.isArray(input && input.selectors) ? input.selectors.filter(Boolean).map(String) : [];
  const failed = new Set(Array.isArray(r.failedLookups) ? r.failedLookups : []);
  const rec = r.records || {};
  const groupName = (g) => w.say(`health.group.${g}`, null, g);
  const byGroup = (sev) => HEALTH_GROUPS.map((g) => ({ g, list: checks.filter((c) => c.severity === sev && (c.group || 'dns') === g) })).filter((x) => x.list.length);

  const notesItems = byGroup('info').flatMap(({ list }) => list.map((c) => checkItem(c, w)));
  const passed = byGroup('ok').map(({ g, list }) => ({ group: groupName(g), titles: list.map((c) => checkItem(c, w).title) }));
  const failedText = t('crep.na', { reason: t('crep.lookupFailed') });
  const known = (key, value) => (failed.has(key) ? failedText : value);
  const list = (xs) => (Array.isArray(xs) && xs.length ? xs.map(String) : t('crep.none'));
  const reg = r.rdap && typeof r.rdap === 'object' ? r.rdap : null;
  const dnssec = r.dnssec || null;
  const records = [
    row('NS', known('ns', list(rec.ns)), { mono: true }),
    row('SOA', known('soa', rec.soa ? `${rec.soa.mname || ''} · ${rec.soa.serial ?? ''}` : t('crep.none')), { mono: true }),
    row('MX', known('mx', Array.isArray(rec.mx) && rec.mx.length ? rec.mx.map((m) => `${m.preference} ${m.exchange}`) : t('crep.none')), { mono: true }),
    row('A', known('a', list(rec.a)), { mono: true }),
    row('AAAA', known('aaaa', list(rec.aaaa)), { mono: true }),
    row('SPF', known('txt', rec.spf || t('crep.none')), { mono: true }),
    row('DMARC', rec.dmarc || (r.dmarc && r.dmarc.record) || t('crep.none'), { mono: true }),
    row('DKIM', Array.isArray(rec.dkim) && rec.dkim.length ? rec.dkim.map((k) => `${k.selector} · ${k.keyType || ''}${k.keyBits ? ` ${k.keyBits}` : ''}`.trim()) : t('crep.none'), { mono: true }),
    row('CAA', Array.isArray(rec.caa) && rec.caa.length ? rec.caa.map((c) => `${c.flags} ${c.tag} "${c.value}"`) : t('crep.none'), { mono: true }),
    row('MTA-STS', known('mtaSts', rec.mtaSts || t('crep.none')), { mono: true }),
    row('TLS-RPT', known('tlsRpt', rec.tlsRpt || t('crep.none')), { mono: true }),
    row('BIMI', known('bimi', rec.bimi || t('crep.none')), { mono: true }),
    dnssec ? row('DNSSEC', t(dnssec.validated ? 'crep.dnssec.validated' : dnssec.signed ? 'crep.dnssec.signed' : dnssec.signed === false ? 'crep.dnssec.unsigned' : 'crep.dnssec.unknown'),
      { severity: dnssec.broken ? 'error' : dnssec.validated ? 'ok' : null }) : null,
    reg && reg.registrar ? row(t('crep.registrar'), String(reg.registrar)) : null,
    reg && reg.expires ? row(t('crep.expires'), utcDay(reg.expires)) : null
  ].filter(hasValue);

  const sections = [];
  if (waivedChecks.length) {
    // what was accepted, why, by whom and until when: the customer sees it was left out on purpose
    const items = waivedChecks.map((c) => {
      const item = checkItem(c, w);
      const x = waivers.get(c.id);
      const line = t(x.owner ? 'crep.waivedLineOwner' : 'crep.waivedLine', { date: String(x.expires || ''), owner: String(x.owner || ''), reason: String(x.reason || '') });
      return { ...item, detail: item.detail ? `${line} — ${item.detail}` : line };
    });
    sections.push({ id: 'accepted', title: t('crep.accepted', { count: items.length }), items });
  }
  if (notesItems.length) sections.push({ id: 'notes', title: t('crep.notes'), items: notesItems });
  if (passed.length) sections.push({ id: 'passed', title: t('crep.passed'), passed });
  sections.push({ id: 'records', title: t('crep.records'), rows: records });
  const zone = r.zone && r.zone !== r.domain ? t('crep.zone', { zone: r.zone }) : null;
  const less = { error: waivedChecks.filter((c) => c.severity === 'error').length, warn: waivedChecks.filter((c) => c.severity === 'warn').length };
  return {
    kind: 'health',
    subject: String(r.domain || ''),
    subtitle: zone,
    at: asDate(r.checkedAt),
    verdict: verdictOf(r.summary, w, { waived: waivedChecks.length ? less : null }),
    problems: problemsOf(checks, w),
    problemsKnown: true,
    sections,
    method: [t('crep.method.health.checks'), selectors.length ? t('crep.method.health.dkim', { list: selectors.join(', ') }) : null,
      t('crep.method.health.score'), t('crep.method.when'), t('crep.method.private')].filter(Boolean)
  };
}

/**
 * The permalink inputs of a report's result — what the recipient's link runs again, never a
 * result: the overview's domain, Health's domain and extra DKIM selectors (lib/summarycore.js
 * permalinkParams keeps only PERMALINK_PARAMS keys).
 * @param {'domain'|'health'} kind
 * @param {object} input the builder's input
 * @returns {Record<string, string>}
 */
export function reportLinkParams(kind, input) {
  const i = input || {};
  if (kind === 'domain') return i.domain ? { name: String(i.domain) } : {};
  if (kind === 'health') {
    const domain = i.report && i.report.domain ? String(i.report.domain) : '';
    const selectors = Array.isArray(i.selectors) ? i.selectors.filter(Boolean).map(String) : [];
    return domain ? { domain, ...(selectors.length ? { selectors: selectors.join(',') } : {}) } : {};
  }
  return {};
}

/* ------------------------------------------------------------------------ */
/* Rendering                                                                */
/* ------------------------------------------------------------------------ */

/** A severity's badge: glyph and word. */
const badge = (sev, t) => el('span', { class: `crep-badge crep-sev-${sev}` }, `${SEVERITY_GLYPHS[sev] || ''} ${t(`crep.sev.${sev}`)}`.trim());

/** One fact's value cell. */
function valueCell(r) {
  const cls = [r.severity ? `crep-sev-${r.severity}` : null, r.mono ? 'crep-mono' : null].filter(Boolean).join(' ') || null;
  const value = Array.isArray(r.value) ? el('ul', { class: 'crep-values' }, r.value.map((v) => el('li', null, v))) : r.value;
  return el('td', { class: cls }, value);
}

/** A list of checks (problems, notes). */
const itemList = (items, t) => el('ol', { class: 'crep-items' }, items.map((i) => el('li', { class: `crep-item crep-sev-${i.severity}` },
  el('div', { class: 'crep-item-head' }, badge(i.severity, t), el('strong', null, i.title), i.group ? el('span', { class: 'crep-item-group' }, i.group) : null),
  i.detail ? el('p', { class: 'crep-item-detail' }, i.detail) : null)));

/** A section of facts, notes, checks or passed checks. */
function sectionNode(s, t) {
  return el('section', { class: 'crep-card crep-section', 'data-section': s.id },
    el('h2', null, s.title),
    s.rows && s.rows.length ? el('table', { class: 'crep-facts' }, el('tbody', null, s.rows.map((r) => el('tr', null, el('th', { scope: 'row' }, r.label), valueCell(r))))) : null,
    (s.notes || []).map((n) => el('p', { class: `crep-note${n.severity ? ` crep-sev-${n.severity}` : ''}` }, n.text,
      n.href && isWebUrl(n.href) ? [' — ', el('a', { href: n.href, rel: 'noreferrer' }, n.href)] : null)),
    s.items && s.items.length ? itemList(s.items, t) : null,
    (s.passed || []).map((p) => [el('h3', { class: 'crep-group' }, p.group), el('ul', { class: 'crep-passed' }, p.titles.map((x) => el('li', null, x)))]));
}

/**
 * The report's `<body>`: the head (kind, domain, times, tool, verdict), the problems with their
 * advice, the sections, what was checked, and the footer with the re-run link when given.
 * @param {ReportDoc} doc
 * @param {{ t: Function, version?: string, generatedAt?: Date, link?: string|null }} opts
 * @returns {ReportNode}
 */
export function reportBody(doc, opts) {
  const { t } = words(opts);
  const version = String(opts.version || '');
  const generated = asDate(opts.generatedAt) || new Date();
  const v = doc.verdict;
  const link = opts.link && isWebUrl(opts.link) ? String(opts.link) : null;
  const head = el('header', { class: 'crep-card crep-head' },
    el('p', { class: 'crep-kicker' }, t(`crep.kind.${doc.kind}`)),
    el('h1', { class: 'crep-subject crep-mono' }, doc.subject),
    doc.subtitle ? el('p', { class: 'crep-sub' }, doc.subtitle) : null,
    el('table', { class: 'crep-meta' }, el('tbody', null,
      doc.at ? el('tr', null, el('th', { scope: 'row' }, t('crep.resultAt')), el('td', null, el('time', { datetime: doc.at.toISOString() }, utcTime(doc.at)))) : null,
      el('tr', null, el('th', { scope: 'row' }, t('crep.generatedAt')), el('td', null, el('time', { datetime: generated.toISOString() }, utcTime(generated)))),
      el('tr', null, el('th', { scope: 'row' }, t('crep.tool')), el('td', null, t('crep.toolValue', { version }))))),
    v ? el('div', { class: `crep-verdict crep-light-${v.light}`, 'data-light': v.light, 'data-score': v.score },
      el('span', { class: 'crep-score' }, `${v.score}/100`),
      el('span', { class: 'crep-verdict-label' }, v.label),
      el('ul', { class: 'crep-counts' }, v.counts.map((c) => el('li', { class: `crep-sev-${c.severity}` }, el('span', { class: 'crep-badge' }, `${SEVERITY_GLYPHS[c.severity]} ${c.text}`)))),
      v.body ? el('p', { class: 'crep-verdict-body' }, v.body) : null) : null);
  const problems = el('section', { class: 'crep-card crep-section crep-problems', 'data-section': 'problems' },
    el('h2', null, t('crep.problems')),
    doc.problems.length ? itemList(doc.problems, t) : el('p', { class: 'crep-muted' }, t(doc.problemsKnown === false ? 'crep.problemsUnknown' : 'crep.noProblems')));
  const method = el('section', { class: 'crep-card crep-section crep-method', 'data-section': 'method' },
    el('h2', null, t('crep.method')),
    el('ul', null, doc.method.map((m) => el('li', null, m))));
  const foot = el('footer', { class: 'crep-foot' },
    link ? el('p', null, `${t('crep.rerun')}: `, el('a', { href: link, rel: 'noreferrer' }, link)) : null,
    link ? el('p', null, t('crep.rerunNote')) : null,
    el('p', null, t('crep.foot', { version })));
  return el('body', { class: `crep crep-${doc.kind}` },
    el('div', { class: 'crep-page' }, head, problems, doc.sections.map((s) => sectionNode(s, t)), method, foot));
}

/**
 * The report's title: "<kind> · <domain>".
 * @param {ReportDoc} doc
 * @param {{ t: Function }} opts
 * @returns {string}
 */
export function reportTitle(doc, opts) {
  const { t } = words(opts);
  return t('crep.title', { kind: t(`crep.kind.${doc.kind}`), domain: doc.subject });
}

/**
 * The whole report file: `<!doctype html>`, the CSP, referrer and colour-scheme metas, the title,
 * {@link REPORT_CSS} and {@link reportBody}. No script anywhere.
 * @param {ReportDoc} doc
 * @param {{ t: Function, lang?: 'en'|'tr', version?: string, generatedAt?: Date, link?: string|null }} opts
 * @returns {string}
 */
export function reportHtml(doc, opts) {
  const lang = opts.lang === 'tr' ? 'tr' : 'en';
  const tree = el('html', { lang },
    el('head', null,
      el('meta', { charset: 'utf-8' }),
      el('meta', { 'http-equiv': 'Content-Security-Policy', content: REPORT_CSP }),
      el('meta', { name: 'referrer', content: 'no-referrer' }),
      el('meta', { name: 'viewport', content: 'width=device-width, initial-scale=1' }),
      el('meta', { name: 'color-scheme', content: 'light' }),
      el('meta', { name: 'generator', content: `DomainScope ${opts.version || ''}`.trim() }),
      el('title', null, reportTitle(doc, opts)),
      el('style', null, REPORT_CSS)),
    reportBody(doc, opts));
  return `<!doctype html>\n${renderHtml(tree)}\n`;
}

/**
 * Build a report of a view's result.
 * @param {'domain'|'health'} kind
 * @param {object} input {@link domainReport} or {@link healthReport} input
 * @param {{ t: Function, lang?: 'en'|'tr', has?: Function, statusText?: Function, version?: string,
 *   generatedAt?: Date, link?: string|null }} opts
 * @returns {{ doc: ReportDoc, html: string }}
 */
export function buildReport(kind, input, opts) {
  if (!REPORT_KINDS.includes(kind)) throw new TypeError(`report: unknown kind ${kind}`);
  const doc = kind === 'domain' ? domainReport(input, opts) : healthReport(input, opts);
  return { doc, html: reportHtml(doc, opts) };
}

/* ------------------------------------------------------------------------ */
/* Texts                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * English and Turkish texts of the report (`crep.*`) and of its panel (ui/report.js). Register with
 * `registerStrings('en', REPORT_I18N.en)` / `registerStrings('tr', REPORT_I18N.tr)`.
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const REPORT_I18N = Object.freeze({
  en: Object.freeze({
    'crep.kind.domain': 'Domain overview',
    'crep.kind.health': 'Domain Health report',
    'crep.title': '{kind} · {domain}',
    'crep.resultAt': 'Result from',
    'crep.generatedAt': 'Report made',
    'crep.tool': 'Tool',
    'crep.toolValue': 'DomainScope {version}',
    'crep.problems': 'Problems and advice',
    'crep.noProblems': 'No errors or warnings.',
    'crep.problemsUnknown': 'The health checks did not run, so problems are not known.',
    'crep.sev.error': 'Error',
    'crep.sev.warn': 'Warning',
    'crep.sev.info': 'Note',
    'crep.sev.ok': 'Passed',
    'crep.light.error': 'Problems found',
    'crep.light.warn': 'Needs attention',
    'crep.light.ok': 'Healthy',
    'crep.light.errorBody': 'Fix the errors first — they break mail delivery, resolution or security for real users.',
    'crep.light.warnBody': 'Nothing is broken, but some settings are weak or risky.',
    'crep.light.okBody': { one: 'No problems found in {count} check.', other: 'No problems found in {count} checks.' },
    'crep.count.error': { one: '{count} error', other: '{count} errors' },
    'crep.count.warn': { one: '{count} warning', other: '{count} warnings' },
    'crep.count.info': { one: '{count} note', other: '{count} notes' },
    'crep.count.ok': { one: '{count} passed', other: '{count} passed' },
    'crep.counts': 'Checks',
    'crep.verdict': 'Verdict',
    'crep.services': 'Verified by TXT',
    'crep.na': '⚠ n/a — {reason}',
    'crep.lookupFailed': 'the lookup failed',
    'crep.none': 'none',
    'crep.ctNotAsked': 'Not looked up: Certificate Transparency is asked only on its own button.',
    'crep.notes': 'Notes',
    'crep.passed': 'Passed checks',
    'crep.waived': { one: '{count} accepted risk excluded', other: '{count} accepted risks excluded' },
    'crep.accepted': { one: 'Accepted risk ({count})', other: 'Accepted risks ({count})' },
    'crep.waivedLine': 'Accepted until {date}: {reason}',
    'crep.waivedLineOwner': 'Accepted until {date} by {owner}: {reason}',
    'crep.records': 'Records read',
    'crep.registrar': 'Registrar',
    'crep.expires': 'Expires',
    'crep.zone': 'Checked in the zone {zone}.',
    'crep.dnssec.validated': 'Signed and validated',
    'crep.dnssec.signed': 'Signed, not validated',
    'crep.dnssec.unsigned': 'Not signed',
    'crep.dnssec.unknown': 'Not known',
    'crep.method': 'What was checked',
    'crep.method.domain.dns': 'DNS: NS, SOA, DS and DNSKEY, MX, TXT (SPF and service verifications), DMARC, the A, AAAA and HTTPS records of the domain and of its www name, and CAA, asked over DNS-over-HTTPS from the browser.',
    'crep.method.domain.rdap': 'Registration: the registry’s RDAP service (registrar, dates, status flags, DNSSEC delegation).',
    'crep.method.domain.ct': 'Certificate issuers: Certificate Transparency (Cert Spotter, or crt.sh when it cannot answer), only when they were asked for.',
    'crep.method.domain.health': 'Problems and the score: Domain Health’s checks on the same answers. The score starts at 100 and loses 20 points per error and 6 per warning.',
    'crep.method.health.checks': 'NS, SOA, MX, SPF with its 10-lookup limit, DMARC, DKIM, CAA, DNSSEC, wildcard records, MTA-STS, TLS-RPT, BIMI, IPv6, HTTPS records and the RDAP registration, asked over DNS-over-HTTPS from the browser.',
    'crep.method.health.dkim': 'DKIM: the common selectors and the ones added to the check: {list}.',
    'crep.method.health.score': 'The score starts at 100 and loses 20 points per error and 6 per warning; notes cost nothing.',
    'crep.method.when': 'The answers are those the resolvers and registries gave at the time of the result; caches elsewhere may still hold older ones.',
    'crep.method.private': 'Not in this report: TXT verification tokens, server inventories and workspace data.',
    'crep.rerun': 'Run it again',
    'crep.rerunNote': 'The link carries only the domain and the options, never a result: opening it runs the check again in the browser.',
    'crep.foot': 'Made in the browser with DomainScope {version}. This file has no scripts and loads nothing from the network.',

    'crep.panel.title': 'Customer report',
    'crep.panel.body': 'One HTML file with this result — the problems and their advice first, then the facts, when and how it was checked — in a light, print-friendly design and in the interface language. It has no scripts and loads nothing, so it can go to a customer as it is. It is made in your browser: nothing is sent.',
    'crep.panel.link': 'Add a link that runs it again',
    'crep.panel.linkHint': 'The link carries only the inputs ({inputs}), never a result or anything from your workspace: whoever opens it runs the check with their own requests.',
    'crep.panel.copyLink': 'Copy the link',
    'crep.panel.download': 'Download HTML',
    'crep.panel.print': 'Print / save as PDF',
    'crep.panel.saved': 'Report saved as {name}',
    'crep.panel.noPrint': 'This browser cannot print the report from here: download it and print the file.',
    'crep.panel.failed': 'The report could not be made: {error}'
  }),
  tr: Object.freeze({
    'crep.kind.domain': 'Alan adı özeti',
    'crep.kind.health': 'Alan adı sağlığı raporu',
    'crep.title': '{kind} · {domain}',
    'crep.resultAt': 'Sonucun zamanı',
    'crep.generatedAt': 'Raporun hazırlandığı zaman',
    'crep.tool': 'Araç',
    'crep.toolValue': 'DomainScope {version}',
    'crep.problems': 'Sorunlar ve öneriler',
    'crep.noProblems': 'Hata ya da uyarı yok.',
    'crep.problemsUnknown': 'Sağlık kontrolleri çalışmadı; sorunlar bilinmiyor.',
    'crep.sev.error': 'Hata',
    'crep.sev.warn': 'Uyarı',
    'crep.sev.info': 'Not',
    'crep.sev.ok': 'Geçti',
    'crep.light.error': 'Sorun bulundu',
    'crep.light.warn': 'İlgilenilmesi gerekiyor',
    'crep.light.ok': 'Sağlıklı',
    'crep.light.errorBody': 'Önce hataları giderin — gerçek kullanıcılar için e-posta teslimini, çözümlemeyi ya da güvenliği bozuyorlar.',
    'crep.light.warnBody': 'Bozuk bir şey yok ama bazı ayarlar zayıf ya da riskli.',
    'crep.light.okBody': '{count} kontrolde sorun bulunmadı.',
    'crep.count.error': '{count} hata',
    'crep.count.warn': '{count} uyarı',
    'crep.count.info': '{count} not',
    'crep.count.ok': '{count} geçti',
    'crep.counts': 'Kontroller',
    'crep.verdict': 'Sonuç',
    'crep.services': 'TXT ile doğrulayanlar',
    'crep.na': '⚠ alınamadı — {reason}',
    'crep.lookupFailed': 'sorgu başarısız oldu',
    'crep.none': 'yok',
    'crep.ctNotAsked': 'Sorgulanmadı: Certificate Transparency yalnızca kendi düğmesiyle sorgulanır.',
    'crep.notes': 'Notlar',
    'crep.passed': 'Geçen kontroller',
    'crep.waived': '{count} kabul edilen risk hariç tutuldu',
    'crep.accepted': 'Kabul edilen riskler ({count})',
    'crep.waivedLine': '{date} tarihine kadar kabul edildi: {reason}',
    'crep.waivedLineOwner': '{date} tarihine kadar {owner} tarafından kabul edildi: {reason}',
    'crep.records': 'Okunan kayıtlar',
    'crep.registrar': 'Kayıt firması',
    'crep.expires': 'Bitiş tarihi',
    'crep.zone': '{zone} zone’unda kontrol edildi.',
    'crep.dnssec.validated': 'İmzalı ve doğrulandı',
    'crep.dnssec.signed': 'İmzalı, doğrulanmadı',
    'crep.dnssec.unsigned': 'İmzalı değil',
    'crep.dnssec.unknown': 'Bilinmiyor',
    'crep.method': 'Neler kontrol edildi',
    'crep.method.domain.dns': 'DNS: NS, SOA, DS ve DNSKEY, MX, TXT (SPF ve hizmet doğrulamaları), DMARC, alan adının ve www adının A, AAAA ve HTTPS kayıtları ile CAA; tarayıcıdan DNS-over-HTTPS ile soruldu.',
    'crep.method.domain.rdap': 'Kayıt bilgileri: kayıt kuruluşunun RDAP hizmeti (kayıt firması, tarihler, durum bayrakları, DNSSEC yetkilendirmesi).',
    'crep.method.domain.ct': 'Sertifika sağlayıcıları: Certificate Transparency (Cert Spotter; yanıt veremezse crt.sh), yalnızca istendiğinde.',
    'crep.method.domain.health': 'Sorunlar ve puan: aynı yanıtlar üzerinde Alan adı sağlığı kontrolleri. Puan 100’den başlar; her hata 20, her uyarı 6 puan düşürür.',
    'crep.method.health.checks': 'NS, SOA, MX, 10 sorgu sınırıyla SPF, DMARC, DKIM, CAA, DNSSEC, Wildcard kayıtlar, MTA-STS, TLS-RPT, BIMI, IPv6, HTTPS kayıtları ve RDAP kayıt bilgileri; tarayıcıdan DNS-over-HTTPS ile soruldu.',
    'crep.method.health.dkim': 'DKIM: yaygın seçiciler ve kontrole eklenenler: {list}.',
    'crep.method.health.score': 'Puan 100’den başlar; her hata 20, her uyarı 6 puan düşürür; notlar puan düşürmez.',
    'crep.method.when': 'Yanıtlar, çözümleyicilerin ve kayıt kuruluşlarının sonucun zamanında verdikleridir; başka yerlerdeki önbellekler daha eski yanıtları tutuyor olabilir.',
    'crep.method.private': 'Bu raporda olmayanlar: TXT doğrulama belirteçleri, sunucu envanterleri ve çalışma alanı verileri.',
    'crep.rerun': 'Yeniden çalıştır',
    'crep.rerunNote': 'Bağlantı yalnızca alan adını ve seçenekleri taşır, hiçbir sonucu taşımaz: açıldığında kontrol tarayıcıda yeniden çalışır.',
    'crep.foot': 'Tarayıcıda DomainScope {version} ile hazırlandı. Bu dosyada betik yoktur ve ağdan hiçbir şey yüklemez.',

    'crep.panel.title': 'Müşteri raporu',
    'crep.panel.body': 'Bu sonucu içeren tek bir HTML dosyası — önce sorunlar ve öneriler, ardından bulgular, ne zaman ve nasıl kontrol edildiği — açık renkli, yazdırmaya uygun bir tasarımda ve arayüz dilinde. Betik içermez ve hiçbir şey yüklemez; olduğu gibi müşteriye gönderilebilir. Tarayıcınızda hazırlanır: hiçbir şey gönderilmez.',
    'crep.panel.link': 'Yeniden çalıştıran bir bağlantı ekle',
    'crep.panel.linkHint': 'Bağlantı yalnızca girdileri ({inputs}) taşır; hiçbir sonucu ya da çalışma alanınızdan bir şeyi taşımaz: açan kişi kontrolü kendi sorgularıyla çalıştırır.',
    'crep.panel.copyLink': 'Bağlantıyı kopyala',
    'crep.panel.download': 'HTML indir',
    'crep.panel.print': 'Yazdır / PDF olarak kaydet',
    'crep.panel.saved': 'Rapor kaydedildi: {name}',
    'crep.panel.noPrint': 'Bu tarayıcı raporu buradan yazdıramıyor: indirip dosyayı yazdırın.',
    'crep.panel.failed': 'Rapor hazırlanamadı: {error}'
  })
});
