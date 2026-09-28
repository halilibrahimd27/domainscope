/**
 * summary.js — "Copy summary": a view's finished result as a few lines of Markdown (or plain
 * text) for a Jira ticket or a Slack thread, in the UI language.
 *
 * - Each builder takes the facts a view already shows ({@link healthSummary}, {@link globalSummary},
 *   {@link subdomainsSummary}, {@link scanSummary}, {@link zoneSummary}, {@link certSummary},
 *   {@link renewSummary}, {@link lookupSummary}, {@link ipSummary}, {@link retireSummary}; {@link buildSummary} dispatches by view id) and
 *   returns a {@link SummaryDoc}: a title, 3–10 content lines (one line for DNS Lookup and IP
 *   Intel) and a footer with the view's permalink and a UTC timestamp.
 * - {@link renderMarkdown} / {@link renderPlainText} turn a doc into text. Untrusted values
 *   (host names, record data, certificate subjects and issuers, inventory server names, a network's
 *   AS name and place, the names and lines of a zone file a problem quotes) are code spans in
 *   Markdown (no link, mention or formatting survives inside one) and every other text is
 *   Markdown-escaped; control and bidi characters never reach the output.
 * - {@link permalinkParams} keeps only a view's own shareable route params (never inventory data
 *   or zone contents; IP Intel and Retire an IP drop private and inventory addresses), for `ctx.shareUrl()`.
 * - A summary holds only what the result on screen shows. Inventory data in it: SSL Targets names
 *   the servers that need the certificate, as its Servers tab lists them; IP Intel says whether
 *   (or how many of) its addresses are in the server list, never a server's name.
 * - The footer's time is when the result was made where the view knows it ("checked" /
 *   "scanned"); Zone File and Certificate say "as of" the copy time.
 *
 * Texts come from an injected `t(key, params)` (i18n.js): the `sum.*` keys of {@link SUMMARY_I18N}
 * plus a few the shell always has (`nav.<view>`, `severity.*`, `kind.*`, `common.moreCount`) and
 * the keys a fact carries itself (a health check's `titleKey`, a Verify headline key).
 * DOM-free and dependency-light (every view loads it); runs in browsers and Node 22.
 */

import { isPrivateIP, normalizeIP } from './netinfo.js';

/** Views with a summary, in navigation order. */
export const SUMMARY_KINDS = Object.freeze(['subdomains', 'zone', 'scan', 'cert', 'renew', 'global', 'lookup', 'ip', 'retire', 'health']);

/** Output formats of {@link renderSummary}. */
export const SUMMARY_FORMATS = Object.freeze(['markdown', 'text']);

/** At most this many problems / findings / names are listed in one summary line group. */
export const SUMMARY_MAX_PROBLEMS = 5;
/** Longest value shown in a code span (longer ones end with '…'). */
export const SUMMARY_MAX_VALUE = 96;

/**
 * Route params a view's permalink may carry (app.js buildRoute keys). Zone File and Certificate
 * carry none: the file never goes into a URL.
 */
export const PERMALINK_PARAMS = Object.freeze({
  subdomains: Object.freeze(['domain', 'run']),
  zone: Object.freeze([]),
  scan: Object.freeze(['domain', 'run']),
  cert: Object.freeze([]),
  renew: Object.freeze(['names', 'ca', 'challenge']),
  global: Object.freeze(['name', 'type', 'geo']),
  lookup: Object.freeze(['name', 'type', 'resolver', 'dnssec', 'cd']),
  ip: Object.freeze(['ips']),
  retire: Object.freeze(['ips', 'domains']),
  health: Object.freeze(['domain', 'selectors'])
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
 * stays inert. Numbers stay numbers (plural forms).
 * @param {Function} t
 * @param {string} key
 * @param {Record<string, unknown>} [params]
 * @returns {SummaryPart[]}
 */
function textParts(t, key, params) {
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
/* Builders                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * Domain Health: the verdict and score, the counts, the worst problems (errors, then warnings).
 * @param {{ report: { domain: string, checkedAt?: Date, summary: object, checks: Array<{ severity: string,
 *   titleKey: string, params?: object, id?: string }> } }} facts a lib/health.domainHealth report
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function healthSummary({ report }, opts) {
  const k = kit(opts);
  const { t } = k;
  const s = report.summary || {};
  const light = trafficLight(s);
  // lib/health passes booleans as the English words 'yes' / 'no' (the view shows them translated too).
  const local = (params) => Object.fromEntries(Object.entries(params || {}).map(([key, v]) => [key, v === 'yes' ? t('common.yes') : v === 'no' ? t('common.no') : v]));
  const problems = (report.checks || []).map((c) => ({ severity: c.severity, key: c.titleKey, params: local(c.params) }));
  const tally = k.counts([['sum.count.error', s.error], ['sum.count.warn', s.warn], ['sum.count.info', s.info], ['sum.count.ok', s.ok]]);
  const listed = problemLines(k, problems);
  return doc('health', k.title('health', [code(report.domain)]), [
    [t('sum.health.verdict', { verdict: t(`sum.health.light.${light}`), score: healthScore(s) })],
    tally ? [tally] : null,
    ...(listed.length ? listed : [[t('sum.health.noProblems')]])
  ], { when: whenText(t, 'sum.at.checked', report.checkedAt, opts.now || new Date()), url: opts.url });
}

/**
 * Global DNS: why the answers agree or differ (lib/propagation.propagationVerdict), how many
 * answers from how many sources (with none, only how many failed), who operates them, the
 * findings and the addresses seen.
 * @param {{ name: string, type: string, verdict: object|null, total: number, answered: number,
 *   failed?: number, cancelled?: boolean, addresses?: number, at?: Date }} facts `at`: when the check ended
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function globalSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const v = facts.verdict || { state: 'none', groups: [], operators: [], findings: [] };
  const answered = Number(facts.answered) || 0;
  const operators = (v.operators || []).map((op) => op.name).filter(Boolean);
  const opList = operators.slice(0, 3).join(', ') + (operators.length > 3 ? ` ${t('common.moreCount', { count: operators.length - 3 })}` : '');
  let state;
  if (!answered) state = facts.cancelled ? t('sum.global.stopped') : t('sum.global.failed');
  else if (v.state === 'by-design') state = v.noRecords ? t('sum.global.nodata', { type: facts.type, operators: opList }) : t('sum.global.design', { operators: opList });
  else if (['agree', 'geo', 'unresolved', 'differ'].includes(v.state)) state = t(`sum.global.${v.state}`);
  else state = t('sum.global.differ');
  if (facts.cancelled && answered) state = `${state} ${t('sum.global.partial')}`;
  const groups = (v.groups || []).filter((g) => !g.rewritten).length;
  // No answer: the state says so; only how many sources failed is left to tell.
  const sources = answered ? [t('sum.global.answers', { count: groups, answered: k.num(answered), total: k.num(facts.total) })] : [];
  if (facts.failed > 0) sources.push(`${sources.length ? ' · ' : ''}${t('sum.global.errors', { count: facts.failed })}`);
  const findings = (v.state === 'differ' || v.state === 'unresolved') ? (v.findings || []) : [];
  const findingLines = findings.slice(0, 3).map((f) => [t(`sum.global.find.${f.code}`, {
    count: (f.members || []).length, rcode: f.rcode || '', type: facts.type
  })]);
  if (findings.length > 3) findingLines.push([t('sum.moreFindings', { count: findings.length - 3 })]);
  return doc('global', k.title('global', [code(facts.name), ` ${cleanText(facts.type)}`]), [
    [state],
    sources,
    operators.length && v.state !== 'by-design' ? [t('sum.global.operators', { list: opList })] : null,
    ...findingLines,
    [t('sum.global.addresses', { count: Number(facts.addresses) || 0 })]
  ], { when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

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

/**
 * SSL Targets: the scanned domains (the title), the certificate, hosts found and covered, passive
 * sources that failed (the host list may be incomplete, so the lines after it may miss a host),
 * the inventory servers that need the certificate (by name, as the Servers tab lists them), hosts
 * behind a CDN and the Verify state.
 * @param {{ domains: string[], cert: { name: string, issuer: string, notBefore?: Date,
 *   notAfter: Date }|null, hosts: number, covered?: number, failedSources?: number, inventory: number,
 *   needsCert?: string[], matched?: number, hiddenOrigin?: number, networks?: number,
 *   verify?: { key: string, params?: object }|null, dangling?: string[], at?: Date,
 *   sets?: Array<{ id: string, name: string, names: number, keyTypes: string[], servers?: number|null }>|null }} facts of a
 *   finished scan (SSL Targets keeps no result of a cancelled one)
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function scanSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const now = opts.now || new Date();
  const cert = facts.cert;
  // Several certificates (a renewal of certificate sets): each set by its first name and key
  // types, and how many of your servers need it, in place of the one certificate.
  const sets = Array.isArray(facts.sets) && facts.sets.length ? facts.sets : null;
  const lines = [];
  if (sets) {
    const parts = [t('sum.scan.sets', { count: sets.length }), ' '];
    sets.forEach((s, i) => {
      if (i) parts.push(' · ');
      parts.push(`${s.id}: `, code(s.name), s.names > 1 ? ` +${k.num(s.names - 1)}` : '', ` (${(s.keyTypes || []).join(', ')})`,
        Number.isFinite(s.servers) && facts.inventory > 0 ? ` ${t('sum.scan.setServers', { count: s.servers })}` : '');
    });
    lines.push(parts.filter((p) => p !== ''));
  } else {
    lines.push(cert
      ? [t('sum.scan.cert'), ' ', code(cert.name), ' · ', ...issuedBy(t, cert.issuer), ' · ', validityText(k, cert, now)]
      : [t('sum.scan.noCert')]);
  }
  const hosts = [t('sum.scan.hosts', { count: Number(facts.hosts) || 0 })];
  if (cert) hosts.push(' · ', t('sum.scan.covered', { count: Number(facts.covered) || 0 }));
  lines.push(hosts);
  // Right under the host count: every line after it is built from that (maybe incomplete) list.
  if (facts.failedSources > 0) lines.push([t('sum.sub.sourcesFailed', { count: facts.failedSources })]);
  if (!(facts.inventory > 0)) lines.push([t('sum.scan.noInventory')]);
  else if (cert) {
    const needs = facts.needsCert || [];
    lines.push(needs.length ? [t('sum.scan.needs', { count: needs.length }), ': ', ...k.values(needs, SUMMARY_MAX_PROBLEMS)] : [t('sum.scan.needsNone')]);
  } else {
    lines.push([t('sum.scan.matched', { count: Number(facts.matched) || 0 })]);
  }
  if (facts.hiddenOrigin > 0) {
    lines.push([[t('sum.scan.hidden', { count: facts.hiddenOrigin }), facts.networks > 0 ? t('sum.sub.networks', { count: facts.networks }) : null].filter(Boolean).join(' · ')]);
  }
  if (cert) lines.push(facts.verify && facts.verify.key ? [`${t('sum.scan.verify')} `, t(facts.verify.key, facts.verify.params || {})] : [t('sum.scan.verifyNone')]);
  const dangling = facts.dangling || [];
  if (dangling.length) lines.push([t('sum.sub.dangling', { count: dangling.length }), ': ', ...k.values(dangling)]);
  // The title names what was scanned, as the results title does (the certificate is line 1: its
  // name may be another domain's).
  const scanned = k.domains(facts.domains);
  const subject = scanned.length ? scanned : cert ? [code(cert.name)] : [];
  return doc('scan', k.title('scan', subject), lines, { when: whenText(t, 'sum.at.scanned', facts.at, now), url: opts.url });
}

/**
 * Zone File: records / names / proxied, the problems by severity and the worst of them. The zone
 * itself never goes into the permalink, and the summary says so.
 * @param {{ origin: string|null, format?: string, counts: { records: number, names: number, proxied: number,
 *   errors: number, warnings: number, info: number }, problems?: Array<{ severity: string, key: string, params?: object }> }} facts
 *   `problems`: views/zone.js problemList, each with its text key and params (the names and lines it quotes become code spans)
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function zoneSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const c = facts.counts || {};
  const counts = [t('sum.zone.records', { count: Number(c.records) || 0 }), t('sum.zone.names', { count: Number(c.names) || 0 }), t('sum.zone.proxied', { count: Number(c.proxied) || 0 })].join(' · ');
  const tally = k.counts([['sum.count.error', c.errors], ['sum.count.warn', c.warnings], ['sum.count.info', c.info]]);
  return doc('zone', k.title('zone', facts.origin ? [code(facts.origin)] : t('sum.zone.noOrigin')), [
    [facts.format ? `${cleanText(facts.format)}: ` : '', counts],
    [tally ? t('sum.zone.problems', { list: tally }) : t('sum.zone.noProblems')],
    ...problemLines(k, facts.problems, 3),
    [t('sum.zone.private')]
  ], { when: whenText(t, 'sum.at.asOf', null, opts.now || new Date()), url: opts.url });
}

/**
 * "issued by `Example CA`": the issuer is whatever the certificate says (a self-signed one says
 * anything), so it is a code span like the subject. Lower-case mid-line (SSL Targets); a line of
 * its own capitalises it ({@link certSummary}).
 */
function issuedBy(t, issuer) {
  return textParts(t, 'sum.cert.issuedBy', { issuer: String(issuer ?? '') });
}

/** "valid until 2026-12-01 (65 days left)" / "expired on …" / "not valid before …". */
function validityText(k, cert, now) {
  const at = now instanceof Date ? now.getTime() : Number(now);
  const na = cert.notAfter instanceof Date ? cert.notAfter.getTime() : new Date(cert.notAfter).getTime();
  const nb = cert.notBefore ? new Date(cert.notBefore).getTime() : null;
  if (Number.isFinite(nb) && at < nb) return k.t('sum.cert.notYet', { date: isoDay(nb) });
  if (at > na) return k.t('sum.cert.expired', { date: isoDay(na), count: Math.floor((at - na) / 86400000) });
  return k.t('sum.cert.until', { date: isoDay(na), count: Math.floor((na - at) / 86400000) });
}

/** Certificate warnings {@link certSummary} words (`sum.cert.warn.<code>`). */
export const CERT_SUMMARY_WARNINGS = Object.freeze(['SELF_SIGNED', 'CA', 'NO_SAN', 'PRECERT', 'WEAK']);

/**
 * Certificate: who issued it, its names, its validity and what is wrong with it; loaded from CT
 * or the sample, it says so. The file never goes into the permalink, and the summary says so.
 * @param {{ name: string, issuer: string, dnsNames: string[], notBefore: Date, notAfter: Date,
 *   warnings?: string[], source?: 'file'|'ct'|'sample' }} facts `warnings`: {@link CERT_SUMMARY_WARNINGS} codes
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function certSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const now = opts.now || new Date();
  const names = facts.dnsNames || [];
  const warnings = (facts.warnings || []).filter((w) => CERT_SUMMARY_WARNINGS.includes(w));
  return doc('cert', k.title('cert', [code(facts.name)]), [
    k.cap(issuedBy(t, facts.issuer)),
    names.length ? [t('sum.cert.names', { count: names.length }), ': ', ...k.values(names, 4)] : [t('sum.cert.noNames')],
    k.cap([validityText(k, facts, now)]),
    ...warnings.map((w) => [strong(`${t('severity.warn')}:`), ' ', t(`sum.cert.warn.${w}`)]),
    facts.source === 'ct' ? [t('sum.cert.fromCt')] : facts.source === 'sample' ? [t('sum.cert.sample')] : null,
    [t('sum.cert.private')]
  ], { when: whenText(t, 'sum.at.asOf', null, now), url: opts.url });
}

/**
 * Renewal readiness: how many names will fail, could not be checked, have warnings or are ready,
 * the CA and challenge checked against, then the worst problems as "Error: `name` — title"
 * (lib/renewal.js finding titles, `renew.f.<id>.title`, which the view registers), and whether
 * HTTP-01 reachability was tested from Globalping.
 * @param {{ names: Array<{ name: string, verdict: 'ready'|'warnings'|'unknown'|'fail',
 *   problems?: Array<{ severity: string, key: string, params?: object }> }>, ca?: string|null, challenge?: string,
 *   tested?: number, at?: Date }} facts `ca`: the CA's name (null: not chosen); `at`: when the check ended
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function renewSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const list = (facts.names || []).filter((n) => n && n.name);
  const count = (verdict) => list.filter((n) => n.verdict === verdict).length;
  const tally = k.counts([['sum.renew.fail', count('fail')], ['sum.renew.unknown', count('unknown')],
    ['sum.renew.warnings', count('warnings')], ['sum.renew.ready', count('ready')]]);
  const rank = { error: 0, warn: 1 };
  const problems = list.flatMap((n) => (n.problems || []).filter((p) => p && rank[p.severity] !== undefined).map((p) => ({ n, p })))
    .map((x, i) => ({ ...x, i })).sort((a, b) => rank[a.p.severity] - rank[b.p.severity] || a.i - b.i);
  const lines = problems.slice(0, SUMMARY_MAX_PROBLEMS)
    .map(({ n, p }) => [strong(`${t(`severity.${p.severity}`)}:`), ' ', code(n.name), ' — ', ...textParts(t, p.key, p.params)]);
  if (problems.length > SUMMARY_MAX_PROBLEMS) lines.push([t('sum.moreProblems', { count: problems.length - SUMMARY_MAX_PROBLEMS })]);
  const challenge = t(`renew.ch.${facts.challenge || 'unknown'}`);
  return doc('renew', k.title('renew', k.domains(list.map((n) => n.name))), [
    tally ? [tally] : [t('sum.renew.none')],
    facts.ca ? [t('sum.renew.setup', { ca: cleanText(facts.ca), challenge })] : [t('sum.renew.setupNoCa', { challenge })],
    ...(lines.length ? lines : list.length ? [[t('sum.renew.noProblems')]] : []),
    facts.tested ? [t('sum.renew.tested', { count: Number(facts.tested) })] : null
  ], { when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

/** Presentation text of a record's data, or null when it has no short form. */
function recordValue(rr) {
  const d = rr && rr.data;
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) return d.join('');
  if (d && typeof d === 'object' && d.exchange !== undefined) return `${d.preference} ${d.exchange}`;
  return null;
}

/**
 * DNS Lookup (one line): per type the number of records (or the rcode), the values when there
 * are three or fewer, and the DNSSEC AD bit when it was asked for and every answer has it.
 * @param {{ name: string, ptrFor?: string|null, types: string[], responses: Array<object|null>, dnssec?: boolean, at?: Date }} facts
 *   `responses`: DohClient responses in `types` order; `at`: when the last one arrived
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function lookupSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const rows = (facts.types || []).map((type, i) => ({ type, r: (facts.responses || [])[i] || null }));
  const answered = rows.filter((x) => x.r && x.r.ok);
  const parts = [];
  if (answered.length && answered.every((x) => x.r.rcode === 'NXDOMAIN')) {
    parts.push(t('sum.lookup.nxdomain'));
  } else {
    const records = rows.map((x) => ({ ...x, rrs: x.r && x.r.ok ? (x.r.answers || []).filter((rr) => rr.type === x.type) : [] }));
    const total = records.reduce((n, x) => n + x.rrs.length, 0);
    const vals = records.flatMap((x) => x.rrs.map(recordValue));
    const showValues = total > 0 && total <= 3 && vals.every((v) => v !== null && cleanText(v).length <= 64);
    records.forEach((x, i) => {
      if (i) parts.push(' · ');
      parts.push(`${x.type}: `);
      if (!x.r) parts.push(t('sum.lookup.pending'));
      else if (!x.r.ok) parts.push(t('sum.lookup.failed'));
      else if (x.r.rcode !== 'NOERROR') parts.push(cleanText(x.r.rcode));
      else if (!x.rrs.length) parts.push(t('sum.lookup.noRecords'));
      else if (showValues) parts.push(...k.values(x.rrs.map(recordValue), 3));
      else parts.push(t('sum.lookup.records', { count: x.rrs.length }));
    });
  }
  if (facts.dnssec && answered.length && answered.every((x) => x.r.flags && x.r.flags.ad)) parts.push(` · ${t('sum.lookup.ad')}`);
  return doc('lookup', k.title('lookup', [code(facts.ptrFor || facts.name)]), [parts],
    { inline: true, when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

/**
 * IP Intel (one line): for one address its network, country, reverse name and operator; for
 * several, how many sit behind a CDN, are private, are in the server list, and how many networks
 * and countries. No inventory server name is included: only whether (or how many) are in the list.
 * A lookup that failed (lib/ipintel `info.error`: every source failed or was rate-limited) is
 * counted as failed, and a stopped lookup says how many addresses it never looked up (the rows
 * without data); "no network data" is said only of an address that was looked up and answered.
 * @param {{ rows: Array<{ ip: string, info?: object|null, classification?: object, servers?: object[] }>, at?: Date,
 *   stopped?: boolean }} facts `at`: when the lookup ended; `stopped`: the user stopped it
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function ipSummary({ rows = [], at = null, stopped = false }, opts) {
  const k = kit(opts);
  const { t } = k;
  const list = rows.filter((r) => r && r.ip);
  const parts = [];
  const operator = (r) => {
    const c = r.classification || {};
    if (c.provider && c.provider.name) return c.provider.name;
    return c.kind ? t(`kind.${c.kind}`) : null;
  };
  // views/ip leaves `info` null on a row it never reached: a stopped lookup's, else one whose
  // lookup ended without a result (counted as failed, like a row whose every source failed).
  const failedRow = (r) => (r.info ? !!r.info.error : !stopped);
  const failed = list.filter(failedRow).length;
  const notLooked = stopped ? list.filter((r) => !r.info).length : 0;
  // Only an address that was looked up and answered can have "no network data".
  const answered = list.length - failed - notLooked;
  let subject;
  if (list.length === 1) {
    const r = list[0];
    const info = r.info || {};
    subject = [code(r.ip)];
    const bits = [];
    // The AS name and the place come from registry / geolocation data anyone can word: code spans.
    if (info.asn) bits.push([`AS${cleanText(info.asn)}`, ...(info.asName || info.holder ? [' ', code(info.asName || info.holder)] : [])]);
    if (info.country) bits.push([code(info.city ? `${info.city}, ${info.country}` : info.country)]);
    if (info.ptr && info.ptr.length) bits.push(k.values(info.ptr, 1));
    const op = operator(r);
    if (op) bits.push([op]);
    if (r.servers && r.servers.length) bits.push([t('sum.ip.mineOne')]);
    if (!bits.length && answered) bits.push([t('sum.ip.noData')]);
    if (failed) bits.push([t('sum.ip.failedOne')]);
    if (notLooked) bits.push([t('sum.ip.stoppedOne')]);
    bits.forEach((b, i) => parts.push(...(i ? [' · '] : []), ...b));
  } else {
    subject = t('sum.ip.addresses', { count: list.length });
    const cdn = list.filter((r) => r.classification && r.classification.hidesOrigin);
    const names = [...new Set(cdn.map((r) => r.classification.provider && r.classification.provider.name).filter(Boolean))];
    const bits = [];
    if (cdn.length) bits.push(`${t('sum.ip.cdn', { count: cdn.length })}${names.length ? ` (${names.slice(0, 3).join(', ')})` : ''}`);
    const priv = list.filter((r) => isPrivateIP(r.ip)).length;
    if (priv) bits.push(t('sum.ip.private', { count: priv }));
    const mine = list.filter((r) => r.servers && r.servers.length).length;
    if (mine) bits.push(t('sum.ip.mine', { count: mine }));
    const asns = new Set(list.map((r) => r.info && r.info.asn).filter(Boolean)).size;
    if (asns) bits.push(t('sum.ip.networks', { count: asns }));
    const countries = new Set(list.map((r) => r.info && r.info.country).filter(Boolean)).size;
    if (countries) bits.push(t('sum.ip.countries', { count: countries }));
    if (!bits.length && (answered || !list.length)) bits.push(t('sum.ip.noData'));
    if (failed) bits.push(t('sum.ip.failed', { count: failed }));
    if (notLooked) bits.push(t('sum.ip.stopped', { count: notLooked }));
    parts.push(bits.join(' · '));
  }
  return doc('ip', k.title('ip', subject), [parts], { inline: true, when: whenText(t, 'sum.at.checked', at, opts.now || new Date()), url: opts.url });
}

/** Severities of lib/retire.js whose records break something, worst first (`sum.retire.sev.<id>` labels them). */
export const RETIRE_BREAKING_SEVERITIES = Object.freeze(['mail', 'ns', 'live', 'origin', 'chain']);
/** Records a Retire an IP summary lists by name (the 12-line budget holds four next to its other lines). */
const RETIRE_MAX_RECORDS = 4;

/**
 * Retire an IP: how many records still point at the addresses and how many of them break
 * something, what was checked, the worst records (≤ 4, then "+N more"), what the check could not
 * settle — SPF terms it cannot tell, passive hits nobody checked, failed lookups, a stop — and what
 * it never covers (internal DNS, domains not in the list). The server list only as a count, never a name.
 * @param {{ label: string, domains?: string[], notChecked?: string[], zone?: string|null, passive?: boolean,
 *   counts: { total: number, breaking: number, bySeverity: Record<string, number>, byVerified?: Record<string, number> },
 *   top?: Array<{ severity: string, name: string, type: string, value: string }>, owners?: number|null,
 *   unverified?: number, failed?: number, stopped?: boolean, at?: Date }} facts lib/retire.js buildChanges counts and
 *   changes (worst first); `domains`: the domains whose check finished, `notChecked`: the ones it did not reach
 *   (a stop) or could not check; `zone`: the imported zone's origin when its records were compared; `passive`: a
 *   passive reverse-IP lookup was made; `owners`: servers of the list that own an address (null: no list loaded);
 *   `unverified`: rows of the passive group (nobody checked them, or their lookup failed); `failed`: lookups that got
 *   no answer
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function retireSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const c = facts.counts || { total: 0, breaking: 0, bySeverity: {} };
  const sev = c.bySeverity || {};
  // What cannot be told and what nobody checked is said on lines of its own, never counted as pointing here.
  const total = Math.max(0, (Number(c.total) || 0) - (Number(sev.unknown) || 0) - (Number(facts.unverified) || 0));
  const breaking = Number(c.breaking) || 0;
  // A failed lookup or a "cannot tell" leaves the list open: never "nothing points at it" then.
  const open = (Number(facts.failed) || 0) > 0 || (Number(sev.unknown) || 0) > 0;
  let verdict;
  if (!total) verdict = facts.stopped ? t('sum.retire.noneStopped') : open ? t('sum.retire.noneOpen') : t('sum.retire.none');
  else verdict = `${t('sum.retire.records', { count: total })} · ${breaking ? t('sum.retire.breaking', { count: breaking }) : t('sum.retire.breakingNone')}`;
  if (facts.stopped && total) verdict = `${verdict} ${t('sum.retire.partial')}`;
  const domains = facts.domains || [];
  const checked = domains.length ? [`${t('sum.retire.domains', { count: domains.length })} `, ...k.domains(domains)] : [t('sum.retire.noDomains')];
  if (facts.notChecked && facts.notChecked.length) checked.push(` · ${t('sum.retire.notChecked')} `, ...k.domains(facts.notChecked));
  if (facts.zone) checked.push(' · ', ...textParts(t, 'sum.retire.lookedZone', { zone: facts.zone }));
  if (facts.passive) checked.push(' · ', t('sum.retire.lookedPassive'));
  const top = (facts.top || []).filter((r) => r && RETIRE_BREAKING_SEVERITIES.includes(r.severity));
  const topLines = top.slice(0, RETIRE_MAX_RECORDS).map((r) => [
    strong(`${t(`sum.retire.sev.${r.severity}`)}:`), ' ', code(r.name), ` ${cleanText(r.type)} `, code(r.value)
  ]);
  if (top.length > RETIRE_MAX_RECORDS) topLines.push([t('sum.retire.more', { count: top.length - RETIRE_MAX_RECORDS })]);
  const owners = facts.owners;
  // What the check could not settle, on one line: the budget is 12 lines with the worst records.
  const unsettled = k.counts([['sum.retire.unknown', sev.unknown], ['sum.retire.unverified', facts.unverified], ['sum.retire.failed', facts.failed]]);
  return doc('retire', k.title('retire', [code(facts.label)]), [
    [verdict],
    checked,
    owners === null || owners === undefined ? null : [owners > 0 ? t('sum.retire.owners', { count: owners }) : t('sum.retire.ownersNone')],
    ...topLines,
    unsettled ? [strong(`${t('sum.retire.open')}:`), ' ', unsettled] : null,
    [t('sum.retire.scope')]
  ], { when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

const BUILDERS = {
  subdomains: subdomainsSummary,
  zone: zoneSummary,
  scan: scanSummary,
  cert: certSummary,
  renew: renewSummary,
  global: globalSummary,
  lookup: lookupSummary,
  ip: ipSummary,
  retire: retireSummary,
  health: healthSummary
};

/**
 * Build the summary of a view.
 * @param {string} kind one of {@link SUMMARY_KINDS}
 * @param {object} facts the builder's facts
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function buildSummary(kind, facts, opts) {
  const fn = BUILDERS[kind];
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

  ['sum.health.verdict', ['{verdict} · score {score}/100', '{verdict} · puan {score}/100']],
  ['sum.health.light.ok', ['Healthy', 'Sağlıklı']],
  ['sum.health.light.warn', ['Needs attention', 'İlgilenilmesi gerekiyor']],
  ['sum.health.light.error', ['Problems found', 'Sorun bulundu']],
  ['sum.health.noProblems', ['No errors or warnings', 'Hata ya da uyarı yok']],

  // The verdicts word what the Global DNS summary shows (glb.sum.*Title).
  ['sum.global.agree', ['All answers agree', 'Tüm yanıtlar aynı']],
  ['sum.global.design', ['Differs by design: CDN / GeoDNS edges ({operators})', 'Tasarım gereği farklı: CDN / GeoDNS uç sunucuları ({operators})']],
  ['sum.global.nodata', ['No {type} records anywhere — the CNAME chains differ by design ({operators})', 'Hiçbir kaynakta {type} kaydı yok — CNAME zincirleri tasarım gereği farklı ({operators})']],
  ['sum.global.geo', ['Resolvers agree — locations differ (GeoDNS)', 'Çözümleyiciler aynı — konumlar farklı (GeoDNS)']],
  ['sum.global.unresolved', ['No source could resolve the name', 'Hiçbir kaynak adı çözümleyemedi']],
  ['sum.global.differ', ['Answers differ', 'Yanıtlar farklı']],
  ['sum.global.failed', ['No answers', 'Yanıt alınamadı']],
  ['sum.global.stopped', ['Stopped before any source answered', 'Hiçbir kaynak yanıt vermeden durduruldu']],
  ['sum.global.partial', ['(stopped early: not every source answered)', '(erken durduruldu: her kaynak yanıt vermedi)']],
  ['sum.global.answers', [{ one: '{count} answer from {answered} of {total} sources', other: '{count} different answers from {answered} of {total} sources' },
    { one: '{total} kaynağın {answered} tanesi aynı yanıtı verdi', other: '{total} kaynağın {answered} tanesinden {count} farklı yanıt' }]],
  ['sum.global.errors', [{ one: '{count} source failed', other: '{count} sources failed' }, '{count} kaynak başarısız']],
  ['sum.global.operators', ['Operated by {list}', 'İşleten: {list}']],
  ['sum.global.addresses', [{ zero: 'No addresses', one: '{count} address seen worldwide', other: '{count} addresses seen worldwide' },
    { zero: 'Adres yok', other: 'Dünya genelinde {count} adres görüldü' }]],
  ['sum.global.find.rcode', [{ one: '{rcode} from {count} source', other: '{rcode} from {count} sources' }, '{count} kaynaktan {rcode}']],
  ['sum.global.find.nxdomain', [{ one: 'NXDOMAIN from {count} source', other: 'NXDOMAIN from {count} sources' }, '{count} kaynaktan NXDOMAIN']],
  ['sum.global.find.nodata', [{ one: 'No {type} records at {count} source', other: 'No {type} records at {count} sources' }, '{count} kaynakta {type} kaydı yok']],
  ['sum.global.find.private', [{ one: 'A private address from {count} source', other: 'Private addresses from {count} sources' }, '{count} kaynaktan özel (private) adres']],
  ['sum.global.find.mixed', [{ one: 'Direct addresses next to CDN edges ({count} source)', other: 'Direct addresses next to CDN edges ({count} sources)' },
    'CDN uç noktalarının yanında doğrudan adresler ({count} kaynak)']],
  ['sum.global.find.cname', [{ one: 'The CNAME differs ({count} source)', other: 'The CNAME differs ({count} sources)' }, 'CNAME farklı ({count} kaynak)']],
  ['sum.global.find.operators', [{ one: 'The name points to different providers ({count} source)', other: 'The name points to different providers ({count} sources)' },
    'Ad farklı sağlayıcılara işaret ediyor ({count} kaynak)']],
  ['sum.global.find.direct', [{ one: 'Different direct addresses ({count} source)', other: 'Different direct addresses ({count} sources)' }, 'Farklı doğrudan adresler ({count} kaynak)']],
  ['sum.global.find.records', [{ one: 'Different records ({count} source)', other: 'Different records ({count} sources)' }, 'Farklı kayıtlar ({count} kaynak)']],

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
    '{count} pasif kaynak başarısız: liste eksik olabilir']],

  ['sum.scan.cert', ['Certificate', 'Sertifika']],
  ['sum.scan.sets', [{ one: '{count} certificate set:', other: '{count} certificate sets:' }, '{count} sertifika seti:']],
  ['sum.scan.setServers', [{ one: '— {count} server', other: '— {count} servers' }, '— {count} sunucu']],
  ['sum.scan.noCert', ['No certificate loaded: names and servers only', 'Sertifika yüklenmedi: yalnızca adlar ve sunucular']],
  ['sum.scan.hosts', [{ one: '{count} host found', other: '{count} hosts found' }, '{count} host bulundu']],
  ['sum.scan.covered', [{ one: '{count} covered by the certificate', other: '{count} covered by the certificate' }, '{count} tanesi sertifikanın kapsamında']],
  ['sum.scan.needs', [{ one: '{count} server in your list needs the certificate', other: '{count} servers in your list need the certificate' },
    'Listenizdeki {count} sunucunun sertifikaya ihtiyacı var']],
  ['sum.scan.needsNone', ['No server in your list needs the certificate', 'Listenizdeki hiçbir sunucunun sertifikaya ihtiyacı yok']],
  ['sum.scan.matched', [{ one: '{count} server in your list serves these names', other: '{count} servers in your list serve these names' },
    'Listenizdeki {count} sunucu bu adlara hizmet veriyor']],
  ['sum.scan.noInventory', ['No server list loaded: which servers need the certificate is not known', 'Sunucu listesi yüklenmedi: sertifikanın hangi sunuculara gerektiği bilinmiyor']],
  ['sum.scan.hidden', [{ one: '{count} host behind a CDN (origin hidden)', other: '{count} hosts behind a CDN (origin hidden)' }, '{count} host CDN arkasında (asıl sunucu gizli)']],
  ['sum.scan.verify', ['Verify:', 'Doğrulama:']],
  ['sum.scan.verifyNone', ['Verify: not checked from the internet yet', 'Doğrulama: henüz internetten kontrol edilmedi']],

  ['sum.zone.noOrigin', ['zone name not known', 'zone adı bilinmiyor']],
  ['sum.zone.records', [{ one: '{count} record', other: '{count} records' }, '{count} kayıt']],
  ['sum.zone.names', [{ one: '{count} name', other: '{count} names' }, '{count} ad']],
  ['sum.zone.proxied', ['{count} proxied', '{count} proxy’li']],
  ['sum.zone.problems', ['Problems: {list}', 'Sorunlar: {list}']],
  ['sum.zone.noProblems', ['No problems found in the zone', 'Zone’da sorun bulunmadı']],
  ['sum.zone.private', ['The zone file stays in this browser: the link opens Zone File without it', 'Zone dosyası bu tarayıcıda kalır: bağlantı Zone Dosyası aracını dosya olmadan açar']],

  ['sum.cert.issuedBy', ['issued by {issuer}', 'veren: {issuer}']],
  ['sum.cert.names', [{ one: '{count} DNS name', other: '{count} DNS names' }, '{count} DNS adı']],
  ['sum.cert.noNames', ['No DNS names', 'DNS adı yok']],
  ['sum.cert.until', [{ zero: 'valid until {date} (expires today)', one: 'valid until {date} ({count} day left)', other: 'valid until {date} ({count} days left)' },
    { zero: '{date} tarihine kadar geçerli (bugün sona eriyor)', other: '{date} tarihine kadar geçerli ({count} gün kaldı)' }]],
  ['sum.cert.expired', [{ zero: 'expired on {date} (today)', one: 'expired on {date} ({count} day ago)', other: 'expired on {date} ({count} days ago)' },
    { zero: '{date} tarihinde sona erdi (bugün)', other: '{date} tarihinde sona erdi ({count} gün önce)' }]],
  ['sum.cert.notYet', ['not valid before {date}', '{date} tarihinden önce geçerli değil']],
  ['sum.cert.warn.SELF_SIGNED', ['self-signed: browsers do not trust it', 'kendinden imzalı: tarayıcılar güvenmez']],
  ['sum.cert.warn.CA', ['a CA certificate, not a server certificate', 'bir CA sertifikası, sunucu sertifikası değil']],
  ['sum.cert.warn.NO_SAN', ['no DNS names: browsers reject it for a host name', 'DNS adı yok: tarayıcılar bir host adı için kabul etmez']],
  ['sum.cert.warn.PRECERT', ['a precertificate: no server serves this exact certificate', 'bir ön sertifika (precertificate): hiçbir sunucu tam olarak bunu sunmaz']],
  ['sum.cert.warn.WEAK', ['weak key or signature algorithm', 'zayıf anahtar ya da imza algoritması']],
  ['sum.cert.fromCt', ['Loaded from Certificate Transparency: a server may serve a different one', 'Certificate Transparency kayıtlarından yüklendi: bir sunucu farklı bir sertifika sunuyor olabilir']],
  ['sum.cert.sample', ['This is the built-in sample certificate', 'Bu, uygulamadaki örnek sertifika']],
  ['sum.cert.private', ['The certificate file stays in this browser: the link opens the Certificate tool without it', 'Sertifika dosyası bu tarayıcıda kalır: bağlantı Sertifika aracını dosya olmadan açar']],

  ['sum.renew.fail', ['{count} will fail', '{count} tanesi başarısız olacak']],
  ['sum.renew.unknown', ['{count} could not be checked', '{count} tanesi kontrol edilemedi']],
  ['sum.renew.warnings', ['{count} with warnings', '{count} tanesi uyarılı']],
  ['sum.renew.ready', ['{count} ready', '{count} tanesi hazır']],
  ['sum.renew.none', ['No names checked', 'Hiçbir ad kontrol edilmedi']],
  ['sum.renew.setup', ['CA: {ca} · challenge: {challenge}', 'Otorite: {ca} · doğrulama: {challenge}']],
  ['sum.renew.setupNoCa', ['CA not chosen · challenge: {challenge}', 'Otorite seçilmedi · doğrulama: {challenge}']],
  ['sum.renew.noProblems', ['No errors or warnings', 'Hata ya da uyarı yok']],
  ['sum.renew.tested', [{ one: 'HTTP-01 reachability tested for {count} name from three continents (Globalping)', other: 'HTTP-01 reachability tested for {count} names from three continents (Globalping)' },
    'HTTP-01 erişilebilirliği {count} ad için üç kıtadan test edildi (Globalping)']],

  ['sum.lookup.records', [{ one: '{count} record', other: '{count} records' }, '{count} kayıt']],
  ['sum.lookup.noRecords', ['none', 'yok']],
  ['sum.lookup.failed', ['lookup failed', 'sorgu başarısız']],
  ['sum.lookup.pending', ['no answer yet', 'henüz yanıt yok']],
  ['sum.lookup.nxdomain', ['the name does not exist (NXDOMAIN)', 'ad mevcut değil (NXDOMAIN)']],
  ['sum.lookup.ad', ['DNSSEC validated (AD)', 'DNSSEC doğrulandı (AD)']],

  ['sum.ip.addresses', [{ one: '{count} address', other: '{count} addresses' }, '{count} adres']],
  ['sum.ip.cdn', [{ one: '{count} behind a CDN', other: '{count} behind a CDN' }, '{count} tanesi CDN arkasında']],
  ['sum.ip.private', [{ one: '{count} private', other: '{count} private' }, '{count} tanesi özel (private)']],
  ['sum.ip.mine', ['{count} in your server list', '{count} tanesi sunucu listenizde']],
  ['sum.ip.mineOne', ['in your server list', 'sunucu listenizde']],
  ['sum.ip.networks', [{ one: '{count} network', other: '{count} networks' }, '{count} ağ']],
  ['sum.ip.countries', [{ one: '{count} country', other: '{count} countries' }, '{count} ülke']],
  ['sum.ip.noData', ['no network data', 'ağ bilgisi yok']],
  ['sum.ip.failed', [{ one: '{count} lookup failed', other: '{count} lookups failed' }, '{count} adreste sorgu başarısız']],
  ['sum.ip.failedOne', ['lookup failed', 'sorgu başarısız']],
  ['sum.ip.stopped', [{ one: 'stopped: {count} address not looked up', other: 'stopped: {count} addresses not looked up' }, 'durduruldu: {count} adres sorgulanmadı']],
  ['sum.ip.stoppedOne', ['stopped before it was looked up', 'sorgulanmadan durduruldu']],

  ['sum.retire.records', [{ one: '{count} record still points at it', other: '{count} records still point at it' }, '{count} kayıt hâlâ bu adresi gösteriyor']],
  ['sum.retire.breaking', [{ one: '{count} breaks something once it is gone', other: '{count} break something once it is gone' }, 'adres kalkınca {count} tanesi bir şeyi bozar']],
  ['sum.retire.breakingNone', ['none of them breaks anything once it is gone', 'adres kalkınca hiçbiri bir şeyi bozmaz']],
  ['sum.retire.none', ['Nothing in the checked domains points at it', 'Kontrol edilen alan adlarında bu adresi gösteren bir şey yok']],
  ['sum.retire.noneStopped', ['Stopped before anything pointing at it was found', 'Bu adresi gösteren bir şey bulunmadan durduruldu']],
  ['sum.retire.noneOpen', ['Nothing found pointing at it, but not everything could be checked (below)', 'Bu adresi gösteren bir şey bulunmadı, ama her şey kontrol edilemedi (aşağıda)']],
  ['sum.retire.notChecked', ['not checked:', 'kontrol edilmedi:']],
  ['sum.retire.partial', ['(stopped early: not every domain was checked)', '(erken durduruldu: her alan adı kontrol edilmedi)']],
  ['sum.retire.domains', [{ one: 'Checked {count} domain over public DNS:', other: 'Checked {count} domains over public DNS:' }, 'Genel DNS üzerinden {count} alan adı kontrol edildi:']],
  ['sum.retire.noDomains', ['No domain checked', 'Hiçbir alan adı kontrol edilmedi']],
  ['sum.retire.lookedZone', ['the zone file of {zone}', '{zone} zone dosyası']],
  ['sum.retire.lookedPassive', ['passive reverse IP', 'pasif ters IP']],
  ['sum.retire.owners', [{ one: 'Owned by {count} server in your list', other: 'Owned by {count} servers in your list' }, 'Listenizdeki {count} sunucuya ait']],
  ['sum.retire.ownersNone', ['Not in your server list', 'Sunucu listenizde yok']],
  ['sum.retire.sev.mail', ['Mail', 'E-posta']],
  ['sum.retire.sev.ns', ['Name server', 'Ad sunucusu']],
  ['sum.retire.sev.live', ['Address record', 'Adres kaydı']],
  ['sum.retire.sev.origin', ['Proxy origin', 'Proxy asıl sunucusu']],
  ['sum.retire.sev.chain', ['CNAME chain', 'CNAME zinciri']],
  ['sum.retire.more', [{ one: '+{count} more record to change', other: '+{count} more records to change' }, 'değiştirilecek +{count} kayıt daha']],
  ['sum.retire.open', ['Not settled', 'Belirsiz kalanlar']],
  ['sum.retire.scope', ['Not covered: internal (split-horizon) DNS and domains that are not in the list', 'Kapsam dışı: iç (split-horizon) DNS ve listede olmayan alan adları']],
  ['sum.retire.unknown', [{ one: '{count} SPF term that cannot be told from here', other: '{count} SPF terms that cannot be told from here' },
    'buradan anlaşılamayan {count} SPF terimi']],
  ['sum.retire.unverified', [{ one: '{count} passive hit not checked yet', other: '{count} passive hits not checked yet' }, 'henüz kontrol edilmemiş {count} pasif sonuç']],
  ['sum.retire.failed', [{ one: '{count} failed lookup (the list may be incomplete)', other: '{count} failed lookups (the list may be incomplete)' },
    '{count} başarısız sorgu (liste eksik olabilir)']]
];

function buildStrings(lang) {
  return Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));
}

/**
 * English and Turkish texts of every `sum.*` key the builders use. Placeholders: `{param}`;
 * a text that shows a number is a plural object `{ zero?, one?, other }`. Register with
 * `registerStrings('en', SUMMARY_I18N.en)` / `registerStrings('tr', SUMMARY_I18N.tr)`.
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const SUMMARY_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
