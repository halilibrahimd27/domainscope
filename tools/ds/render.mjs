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
import { SUMMARY_I18N, renderMarkdown, renderPlainText, renderParts, utcStamp } from '../../assets/js/lib/summary.js';
import { HEALTH_I18N } from '../../assets/js/lib/health.js';
import { RENEWAL_I18N } from '../../assets/js/lib/renewal.js';

/** A code part: an untrusted value. */
export const code = (value) => ({ code: String(value ?? '') });
/** A bold label part. */
export const strong = (value) => ({ strong: String(value ?? '') });

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
  await import('../../assets/js/views/zone.js');
  await import('../../assets/js/ui/dane-panel.js');
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

/** Change lines in the summary without --show-all (the CLI's MAX_SUMMARY_CHANGES). */
export const MAX_SUMMARY_CHANGES = 50;
/** Every tag a change can carry, widest first for the column. */
export const CHANGE_TAGS = Object.freeze(['NEW', 'GONE', 'WORSE', 'BETTER', 'CHANGED', 'FAILED', 'RECOVERED', 'FAILING', 'SCORE',
  'ISSUER', 'NAME', 'CERT', 'EXPOSED', 'DANGLING']);
const TAG_WIDTH = Math.max(...CHANGE_TAGS.map((tag) => tag.length));

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
  for (const c of shown) {
    const style = c.counts ? TONE_STYLES[c.tone] || [] : TONE_STYLES.quiet;
    lines.push(`  ${paint(c.tag.padEnd(TAG_WIDTH), ...style)}  ${changeText(c)}`);
  }
  if (shown.length < changes.length) {
    lines.push(paint(`  ... and ${changes.length - shown.length} more - use --show-all or the --json report to list them.`, 'dim'));
  }
  const quiet = changes.length - counted.length;
  if (quiet) {
    lines.push(paint(`  Not counted: ${quiet} (moves between failure states, what a failed lookup or source may hide, renewed certificates) - listed only, never counted by --fail-on-change.`, 'dim'));
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
    lines.push(`- ${changes.length - counted} listed only (moves between failure states, what a failed lookup or source may hide, renewed certificates): never counted by --fail-on-change`);
  }
  for (const note of run.notes || []) lines.push(`- ${renderParts([note], 'markdown')}`);
  return `${[head, ...(lines.length ? ['', ...lines] : [])].join('\n')}\n`;
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
    out.push(renderPlainText(d).replace(/\n$/, ''));
  });
  return `${out.join('\n')}\n`;
}

/**
 * The `--md` file: the changes block (with --baseline), then each target's summary as the app's
 * "Copy summary" writes it.
 * @param {{ command: string, baseline?: object|null, changes?: object[], notes?: string[] }} run
 * @param {object[]} docs SummaryDocs
 * @returns {string} with a trailing newline
 */
export function renderRunMarkdown(run, docs) {
  const parts = [];
  if (run.baseline) parts.push(renderChangesMarkdown(run));
  for (const d of docs) parts.push(renderMarkdown(d));
  return parts.join('\n');
}
