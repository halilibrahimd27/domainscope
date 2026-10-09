/**
 * tools/ds/render.mjs — what the headless runner prints and writes, in English: the app's own
 * strings (i18n.js with the lib/summary.js, lib/health.js and lib/renewal.js dictionaries),
 * SummaryDoc parts, the "Changes since the baseline" block in the Python CLI's words
 * (cli/ssl_origin_scan.py render_monitor), the stdout summary and the Markdown file.
 *
 * Untrusted values (host names, record data, certificate names and issuers) travel as code
 * parts and are rendered by lib/summary.js' rules: a code span in Markdown, so no mention
 * (`@team`), link or formatting survives into a GitHub issue; control and bidi characters out.
 */

import { t, registerStrings } from '../../assets/js/i18n.js';
import { SUMMARY_I18N, renderMarkdown, renderPlainText, renderParts, utcStamp, mdCode } from '../../assets/js/lib/summary.js';
import { HEALTH_I18N } from '../../assets/js/lib/health.js';
import { RENEWAL_I18N } from '../../assets/js/lib/renewal.js';
import { POLICY_I18N } from '../../assets/js/lib/policy.js';
import { SECURITY_I18N } from '../../assets/js/lib/secscore.js';

/** A code part: an untrusted value. */
export const code = (value) => ({ code: String(value ?? '') });
/** A bold label part. */
export const strong = (value) => ({ strong: String(value ?? '') });

/** Source names for a sentence ('crt.sh', 'Cert Spotter'). */
const SOURCE_NAMES = Object.freeze({ crtsh: 'crt.sh', certspotter: 'Cert Spotter' });
/** A passive source's name for a sentence: 'crt.sh', 'Cert Spotter', else its id. */
export const sourceName = (id) => SOURCE_NAMES[id] || id;
/** "1 current certificate", "3 current certificates". */
export const certCount = (n) => `${n} current certificate${n === 1 ? '' : 's'}`;

/** 'YYYY-MM-DD' in UTC, or '' for an invalid date. */
export function isoDay(value) {
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10);
}

/** An ISO string, or null for no (or an invalid) date. */
export function isoTime(value) {
  if (value === null || value === undefined) return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Register the dictionaries the runner's texts come from (English) and return `t`: the libs'
 * own, and the Zone File view's and the DANE panel's (drift and DANE statuses as the app words
 * them), which register theirs when imported (DOM-free at import, tests/js/i18n-coverage.test.js).
 * @returns {Promise<(key: string, params?: object) => string>}
 */
export async function setupStrings() {
  registerStrings('en', SUMMARY_I18N.en);
  registerStrings('en', HEALTH_I18N.en);
  registerStrings('en', RENEWAL_I18N.en);
  // audit: the policy's rule names and the evidence of each cell, the security score's measures
  registerStrings('en', POLICY_I18N.en);
  registerStrings('en', SECURITY_I18N.en);
  await import('../../assets/js/views/zone.js');
  await import('../../assets/js/ui/dane-panel.js');
  // takeover: the record kinds, reasons and fixes as the app's Takeover risks words them
  await import('../../assets/js/ui/takeover-panel.js');
  return t;
}

/** lib/health passes booleans as the words 'yes' / 'no': the words of the language, as lib/summary.js does. */
export function localYesNo(tr, params) {
  return Object.fromEntries(Object.entries(params || {})
    .map(([key, v]) => [key, v === 'yes' ? tr('common.yes') : v === 'no' ? tr('common.no') : v]));
}

/**
 * A SummaryDoc (lib/summary.js) for a check the app has no summary builder for.
 * @param {string} kind
 * @param {Array} title parts
 * @param {Array<Array|null>} lines parts per line (empty / null lines dropped)
 * @param {{ t: Function, at?: Date|string|null, now?: Date }} opts
 * @returns {object}
 */
export function summaryDoc(kind, title, lines, { t: tr, at = null, now = new Date() }) {
  const stamp = utcStamp(at || now) || utcStamp(now);
  return { kind, title, lines: lines.filter((l) => l && l.length), inline: false, footer: { when: tr('sum.at.checked', { time: stamp }), url: null } };
}

/**
 * Values as code parts joined with ', ', at most `max`, then "+N more" (lib/summary.js' rule).
 * @param {Function} tr
 * @param {Array} list
 * @param {number} [max=3]
 */
export function valueParts(tr, list, max = 3) {
  const items = [...new Set((list || []).filter((v) => v !== null && v !== undefined && String(v) !== '').map(String))];
  const parts = [];
  items.slice(0, max).forEach((v, i) => {
    if (i) parts.push(', ');
    parts.push(code(v));
  });
  if (items.length > max) parts.push(` ${tr('common.moreCount', { count: items.length - max })}`);
  return parts;
}

/* ------------------------------------------------------------------------ */
/* Changes since the baseline                                               */
/* ------------------------------------------------------------------------ */

/** What is listed but never counted (diff.mjs `counts: false`), for the note under the changes. */
const NOT_COUNTED = 'sources that could not be read, moves between failure states, what a failed lookup or source may hide, renewed certificates, '
  + 'certificates in the expiry radar while their automatic renewal is not overdue';
/** The audit's (diff.mjs diffAudit): a rule not checked this run, what comes in meeting the policy, a rule taken out of it. */
const NOT_COUNTED_AUDIT = 'rules that could not be checked this run, a domain or rule added that meets the policy, a rule taken out of it';
/** tls's (tools/ds/tlsdiff.mjs): what DNS moves and a renewal are, and an outage that compared nothing. */
const NOT_COUNTED_TLS = 'moves between failure states, a DNS lookup that failed, addresses a name gained or lost, renewed certificates';
/** The takeover watch's (tools/ds/takeover.mjs diffTakeover): what stays below medium severity. */
const NOT_COUNTED_TAKEOVER = 'risks of low severity and the ones only the page can tell (to check in the app), and their moves';
/** What is listed but not counted, for the run's command; the accepted risks named when a change listed is about one. */
const notCounted = (command, changes = []) => (command === 'audit' ? NOT_COUNTED_AUDIT : command === 'tls' ? NOT_COUNTED_TLS
  : command === 'takeover' ? NOT_COUNTED_TAKEOVER : NOT_COUNTED)
  + (changes.some((c) => c && !c.counts && c.accepted) ? ', accepted risks (--waivers)' : '');

/** Change lines in the summary without --show-all (the CLI's MAX_SUMMARY_CHANGES). */
export const MAX_SUMMARY_CHANGES = 50;
/** Every tag a change can carry. */
export const CHANGE_TAGS = Object.freeze(['NEW', 'GONE', 'WORSE', 'BETTER', 'CHANGED', 'FAILED', 'RECOVERED', 'FAILING', 'SCORE',
  'ISSUER', 'NAME', 'CERT', 'CA', 'EXPIRING', 'REVOKED', 'EXPOSED', 'DANGLING', 'RENEW-NOW', 'MOVED-UP', 'CA-NOTICE', 'RISK', 'WAIVED', 'WAIVER-EXPIRED']);
/**
 * The tag column's width: 9, every tag but WAIVER-EXPIRED fits it; a summary that shows that one
 * widens its column (the others stay as they always were).
 */
export const TAG_WIDTH = 9;
const tagWidth = (changes) => Math.max(TAG_WIDTH, ...changes.map((c) => String(c.tag).length));

const ANSI = { red: '31', green: '32', yellow: '33', cyan: '36', dim: '2', bold: '1' };
/** The colours of a change's tone (bad red, good green, info cyan, quiet dim). */
const TONE_STYLES = Object.freeze({ bad: ['red', 'bold'], good: ['green'], info: ['cyan'], quiet: ['dim'] });

/**
 * ANSI styling, or none.
 * @param {boolean} color
 * @returns {(text: string, ...styles: string[]) => string}
 */
export function painter(color) {
  return (text, ...styles) => {
    const codes = styles.map((s) => ANSI[s]).filter(Boolean);
    return color && codes.length ? `\u001b[${codes.join(';')}m${text}\u001b[0m` : text;
  };
}

/** One change as a plain line ("target: what", the tag apart). */
export function changeText(change) {
  return renderParts(change.parts, 'text');
}

/** When the baseline run ended, as the CLI says it ('2026-09-27 03:02 UTC', or 'an unknown time'). */
function baselineWhen(info) {
  const at = info && typeof info.finishedAt === 'string' ? info.finishedAt : null;
  return (at && utcStamp(at)) || 'an unknown time';
}

/** The base name of a path (the report says which file, never where it lives). */
export function baseName(file) {
  return String(file || '').split(/[\\/]/).pop() || String(file || '');
}

/**
 * The "Changes since the baseline" lines of the stdout summary, each ending with a blank line.
 * @param {{ command: string, baseline: object, changes: object[], notes?: string[] }} run
 * @param {{ paint: Function, showAll?: boolean }} opts
 * @returns {string[]}
 */
export function renderChangesText(run, { paint, showAll = false }) {
  const info = run.baseline || {};
  const source = baseName(info.file) || 'baseline';
  if (info.missing) {
    return [paint(`Baseline ${source} does not exist yet: nothing to compare (first run). This run's --json report is the next run's baseline.`, 'yellow'), ''];
  }
  const changes = run.changes || [];
  const counted = changes.filter((c) => c.counts);
  const colors = !counted.length ? ['green', 'bold'] : counted.some((c) => c.tone === 'bad') ? ['red', 'bold'] : ['yellow', 'bold'];
  const lines = [paint(`Changes since the baseline (${source}, run of ${baselineWhen(info)}): ${changes.length || 'none'}`, ...colors)];
  const shown = showAll ? changes : changes.slice(0, MAX_SUMMARY_CHANGES);
  const width = tagWidth(shown);
  for (const c of shown) {
    const style = c.counts ? TONE_STYLES[c.tone] || [] : TONE_STYLES.quiet;
    lines.push(`  ${paint(c.tag.padEnd(width), ...style)}  ${changeText(c)}`);
  }
  if (shown.length < changes.length) {
    lines.push(paint(`  ... and ${changes.length - shown.length} more - use --show-all or the --json report to list them.`, 'dim'));
  }
  const quiet = changes.length - counted.length;
  if (quiet) {
    lines.push(paint(`  Not counted: ${quiet} (${notCounted(run.command, changes)}) - listed only, never counted by --fail-on-change.`, 'dim'));
  }
  for (const note of run.notes || []) lines.push(paint(`  ${note}`, 'dim'));
  lines.push('');
  return lines;
}

/** Change lines in the Markdown file (a GitHub issue body holds 65,536 characters). */
export const MAX_MARKDOWN_CHANGES = 200;

/**
 * The same block in Markdown, for the `--md` file (and the nightly issue): at most
 * {@link MAX_MARKDOWN_CHANGES} lines, the ones that count first.
 * @param {{ command: string, baseline: object, changes: object[], notes?: string[] }} run
 * @returns {string} with a trailing newline
 */
export function renderChangesMarkdown(run) {
  const info = run.baseline || {};
  if (info.missing) return `**${run.command}: first run** — no baseline to compare yet; this run's report is the next run's baseline.\n`;
  const changes = run.changes || [];
  const counted = changes.filter((c) => c.counts).length;
  const head = `**${run.command}: changes since the baseline (run of ${baselineWhen(info)}): ${changes.length || 'none'}**`;
  const lines = changes.slice(0, MAX_MARKDOWN_CHANGES).map((c) => `- **${c.tag}**${c.counts ? '' : ' (not counted)'} ${renderParts(c.parts, 'markdown')}`);
  if (changes.length > MAX_MARKDOWN_CHANGES) lines.push(`- … and ${changes.length - MAX_MARKDOWN_CHANGES} more: the JSON report lists them all`);
  if (changes.length > counted) {
    lines.push(`- ${changes.length - counted} listed only (${notCounted(run.command, changes)}): never counted by --fail-on-change`);
  }
  for (const note of run.notes || []) lines.push(`- ${renderParts([note], 'markdown')}`);
  return `${[head, ...(lines.length ? ['', ...lines] : [])].join('\n')}\n`;
}

/* ------------------------------------------------------------------------ */
/* Tables (the audit's security score)                                      */
/* ------------------------------------------------------------------------ */

/** One cell's parts in Markdown, by lib/summary.js' rule; a `|` inside a code span is escaped too, as a GFM table cell needs. */
function tableCellMarkdown(parts) {
  return parts.map((p) => (p && typeof p === 'object' && 'code' in p ? mdCode(p.code).replace(/\|/g, '\\|') : renderParts([p], 'markdown'))).join('');
}

/**
 * A table doc (commands.mjs securityDoc: `{ title, table: { columns, align, rows }, lines }`, a
 * cell a list of parts) in Markdown: the bold title, a GFM table, then its lines as a list.
 * @param {{ title: Array, table: { columns: string[], align?: string[], rows: Array<Array<Array>> }, lines?: Array<Array> }} doc
 * @returns {string} with a trailing newline
 */
export function renderTableMarkdown(doc) {
  const { columns, align = [], rows } = doc.table;
  const rule = (i) => (align[i] === 'right' ? '---:' : align[i] === 'center' ? ':-:' : '---');
  const lines = [
    `**${renderParts(doc.title, 'markdown')}**`,
    '',
    `| ${columns.map((c) => renderParts([c], 'markdown')).join(' | ')} |`,
    `| ${columns.map((_, i) => rule(i)).join(' | ')} |`,
    ...rows.map((r) => `| ${r.map(tableCellMarkdown).join(' | ')} |`)
  ];
  const notes = (doc.lines || []).map((l) => `- ${renderParts(l, 'markdown')}`);
  return `${[...lines, ...(notes.length ? ['', ...notes] : [])].join('\n')}\n`;
}

/**
 * The same table as plain text: the title, the columns aligned with spaces (each as wide as its
 * widest cell), then the lines.
 * @param {{ title: Array, table: { columns: string[], align?: string[], rows: Array<Array<Array>> }, lines?: Array<Array> }} doc
 * @returns {string} with a trailing newline
 */
export function renderTableText(doc) {
  const { columns, align = [], rows } = doc.table;
  const cells = [columns.map((c) => renderParts([c], 'text')), ...rows.map((r) => r.map((p) => renderParts(p, 'text')))];
  const width = (s) => [...s].length;
  const widths = columns.map((_, i) => Math.max(...cells.map((r) => width(r[i] || ''))));
  const pad = (s, i) => {
    const gap = widths[i] - width(s);
    if (align[i] === 'right') return `${' '.repeat(gap)}${s}`;
    if (align[i] === 'center') return `${' '.repeat(Math.floor(gap / 2))}${s}${' '.repeat(gap - Math.floor(gap / 2))}`;
    return `${s}${' '.repeat(gap)}`;
  };
  const out = [
    renderParts(doc.title, 'text'),
    ...cells.map((r) => `  ${r.map(pad).join('  ')}`.trimEnd()),
    ...(doc.lines || []).map((l) => `- ${renderParts(l, 'text')}`)
  ];
  return `${out.join('\n')}\n`;
}

/* ------------------------------------------------------------------------ */
/* The whole summary                                                        */
/* ------------------------------------------------------------------------ */

/**
 * The stdout summary: the changes (with --baseline), then each target's summary.
 * @param {{ command: string, baseline?: object|null, changes?: object[], notes?: string[] }} run
 * @param {object[]} docs SummaryDocs
 * @param {{ color?: boolean, showAll?: boolean }} [opts]
 * @returns {string} with a trailing newline
 */
export function renderRunText(run, docs, { color = false, showAll = false } = {}) {
  const paint = painter(color);
  const out = [];
  if (run.baseline) out.push(...renderChangesText(run, { paint, showAll }));
  docs.forEach((d, i) => {
    if (i) out.push('');
    out.push((d.table ? renderTableText(d) : renderPlainText(d)).replace(/\n$/, ''));
  });
  return `${out.join('\n')}\n`;
}

/**
 * The `--md` file: the changes block (with --baseline), then each target's summary as the app's
 * "Copy summary" writes it (a table doc — the audit's security score — as a Markdown table).
 * @param {{ command: string, baseline?: object|null, changes?: object[], notes?: string[] }} run
 * @param {object[]} docs SummaryDocs
 * @returns {string} with a trailing newline
 */
export function renderRunMarkdown(run, docs) {
  const parts = [];
  if (run.baseline) parts.push(renderChangesMarkdown(run));
  for (const d of docs) parts.push(d.table ? renderTableMarkdown(d) : renderMarkdown(d));
  return parts.join('\n');
}
