/**
 * lib/template.js — the page template as data (docs/DESIGN.md §5): which items a result's status
 * summary shows and in which order, where a result's four standard actions go (in the row, behind
 * the Export menu or, on a phone, behind "⋯"), the "Also check" row, the compact input's one-line
 * summary, the template states and when the phone's floating run bar shows.
 *
 * Pure: no DOM, no i18n (labels come in resolved, or as keys), no clock. ui/template.js draws what
 * these decide; the views map their own results onto the status items (lib/passport.js,
 * lib/healthscore.js, lib/subtabs.js, lib/density.js).
 */

/** The severities of a status summary, in their order (DESIGN §5.4): error → warn → info → ok → neutral. */
export const STATUS_SEVERITIES = Object.freeze(['error', 'warn', 'info', 'ok', 'neutral']);

/** A status summary shows at most this many items (DESIGN §5.4). */
export const STATUS_MAX = 5;

/** The template's states (DESIGN §5.2): nothing yet, a shared link waiting for a click, a run, a result. */
export const TEMPLATE_STATES = Object.freeze(['empty', 'ready', 'running', 'done']);

/** The standard actions of a result header, in their fixed order (DESIGN §5.3). */
export const RESULT_ACTIONS = Object.freeze(['summary', 'plain', 'report', 'export', 'link']);

/** The "Also check" row names at most this many tools (DESIGN §3.5). */
export const RELATED_MAX = 4;

/** Below this width (px) the phone layout applies: the "⋯" menu, the floating run bar (DESIGN §3.4). */
export const PHONE_MAX_WIDTH = 719;

const rank = (severity) => STATUS_SEVERITIES.indexOf(severity);
const countOf = (item) => Number(item.count);

/**
 * The items a status summary shows (DESIGN §5.4): ordered error → warn → info → ok → neutral, the
 * caller's order kept within a severity; zero counts left out, except the error count of a
 * verdict tool, where "0 errors" is the good news; at most `max`. Items without a known severity,
 * a key or a count of 0 or more are dropped.
 * @template {{ key: string, severity: string, count: number }} T
 * @param {T[]} items
 * @param {{ verdict?: boolean, max?: number }} [opts]
 * @returns {T[]} the items kept (the same objects)
 */
export function statusItems(items, { verdict = false, max = STATUS_MAX } = {}) {
  const valid = (Array.isArray(items) ? items : []).filter((x) => x && typeof x.key === 'string' && x.key
    && rank(x.severity) >= 0 && Number.isFinite(countOf(x)) && countOf(x) >= 0);
  const kept = valid.filter((x) => countOf(x) > 0 || (verdict && x.severity === 'error'));
  return kept
    .map((x, i) => ({ x, i }))
    .sort((a, b) => rank(a.x.severity) - rank(b.x.severity) || a.i - b.i)
    .slice(0, Math.max(0, Math.floor(Number(max) || 0)))
    .map(({ x }) => x);
}

/**
 * The item a press leaves pressed: pressing the pressed item again clears the filter (null).
 * @param {string|null} pressed the key pressed now
 * @param {string} key the key pressed
 * @returns {string|null}
 */
export function toggleStatus(pressed, key) {
  return pressed === key ? null : key;
}

/**
 * Where a result's standard actions go (DESIGN §5.3). In the fixed order: Copy summary with ¶
 * (copy as plain text), Report, Export, Copy link. Export is a plain button for one file (Print
 * counts as one) and the Export ▾ menu for more; on a phone only Copy summary stays in the row and
 * everything else goes into the "⋯" menu.
 * @param {{ summary?: boolean, report?: boolean, files?: number, print?: boolean, link?: boolean, phone?: boolean }} offer
 * @returns {{ row: string[], more: string[], exportAs: 'menu'|'file'|null }} action ids (RESULT_ACTIONS) in the row and in "⋯"
 */
export function actionPlan({ summary = false, report = false, files = 0, print = false, link = false, phone = false } = {}) {
  const items = Math.max(0, Math.floor(Number(files) || 0)) + (print ? 1 : 0);
  const exportAs = items > 1 ? 'menu' : items === 1 ? 'file' : null;
  const all = [summary && 'summary', summary && 'plain', report && 'report', exportAs && 'export', link && 'link'].filter(Boolean);
  if (!phone) return { row: all, more: [], exportAs };
  return { row: all.filter((a) => a === 'summary'), more: all.filter((a) => a !== 'summary'), exportAs };
}

/**
 * The "Also check" row (DESIGN §3.5): up to `max` tools, each once, never the tool itself; links
 * without a view are dropped.
 * @template {{ view: string }} T
 * @param {T[]} links in the order the tool gives them
 * @param {{ self?: string|null, max?: number }} [opts]
 * @returns {T[]}
 */
export function relatedLinks(links, { self = null, max = RELATED_MAX } = {}) {
  const seen = new Set();
  const out = [];
  for (const link of Array.isArray(links) ? links : []) {
    if (!link || typeof link.view !== 'string' || !link.view || link.view === self || seen.has(link.view)) continue;
    seen.add(link.view);
    out.push(link);
    if (out.length >= max) break;
  }
  return out;
}

/**
 * The compact input's one-line summary (DESIGN §5.1, region 2): the labels of the choices that
 * differ from their default, in order, joined with " · ". Empty when every choice is the default.
 * @param {Array<{ label: string, isDefault?: boolean }|string|null|false>} choices a string is always shown
 * @returns {string}
 */
export function optionsSummary(choices) {
  return (Array.isArray(choices) ? choices : [])
    .map((c) => (typeof c === 'string' ? c : c && !c.isDefault ? c.label : ''))
    .map((s) => String(s || '').trim())
    .filter(Boolean)
    .join(' · ');
}

/**
 * The template's state (DESIGN §5.2) from what a view knows: a run going on wins, then a result on
 * screen, then a shared link that waits for one click, else empty.
 * @param {{ running?: boolean, result?: boolean, ready?: boolean }} facts
 * @returns {'empty'|'ready'|'running'|'done'}
 */
export function templateState({ running = false, result = false, ready = false } = {}) {
  if (running) return 'running';
  if (result) return 'done';
  return ready ? 'ready' : 'empty';
}

/**
 * Whether the input is compact (DESIGN §5.1, region 2): from the moment a run starts, and while a
 * result (a kept one too) is on screen; full while nothing has run, a link waits, or a run failed
 * before any result.
 * @param {'empty'|'ready'|'running'|'done'} state
 * @returns {boolean}
 */
export function inputCompact(state) {
  return state === 'running' || state === 'done';
}

/**
 * Whether the phone's floating run bar shows (DESIGN §3.4): on a phone, when the inline Run is out
 * of view while the input holds a value — not once a result is on screen (it would cover it), and
 * while a run goes on it carries Stop.
 * @param {{ phone?: boolean, inlineVisible?: boolean, hasValue?: boolean, state?: string }} facts
 * @returns {boolean}
 */
export function runBarFloats({ phone = false, inlineVisible = true, hasValue = false, state = 'empty' } = {}) {
  if (!phone || inlineVisible) return false;
  if (state === 'running') return true;
  if (state === 'done') return false;
  return !!hasValue;
}

/**
 * A translated sentence split around its subject, so the subject can be drawn on its own (mono, a
 * link) inside the words the language puts around it: "Overview of {domain}" / "{domain} özeti".
 * @param {string} text the sentence with `marker` where the subject goes
 * @param {string} marker a string the sentence holds once (ui/template.js passes a control character)
 * @returns {[string, string]|null} the text before and after the subject; null without the marker
 */
export function splitAtSubject(text, marker) {
  const s = String(text ?? '');
  const at = marker ? s.indexOf(marker) : -1;
  if (at < 0) return null;
  return [s.slice(0, at), s.slice(at + marker.length)];
}
