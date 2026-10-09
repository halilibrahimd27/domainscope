/**
 * digests.js — the workspace part `digests` (lib/workspace.js): what a tool found, in counts, for
 * Home (docs/DESIGN.md §4.2). A tool whose results live in memory only writes its digest here, so
 * Home can still say there is something to look at after a reload. JSON text of at most
 * {@link DIGESTS_MAX_CHARS} characters, counts and times only — never a name, an address or the
 * text of a finding:
 *
 *   { "monitor": { "at", "imported", "targets", "bad", "expiring", "incomplete" } }
 *
 * - `monitor` (views/monitor.js, after an import): `at`, when the newest check of the results ran
 *   (ISO); `imported`, when they were opened in this browser; then the Monitoring view's tiles
 *   (lib/monitor.js monitorTiles): the targets, the targets with a bad change in the last
 *   MONITOR_RECENT_DAYS days, the certificates with under MONITOR_WARN_DAYS days left and the
 *   checks that did not complete. "Forget" in Monitoring removes it.
 *
 * A digest that does not check, or an unknown kind, is left out when the text is read: the text may
 * come from another tab or an imported workspace file. Pure: no DOM, clock, storage or i18n.
 */

/** The longest digests text the workspace keeps (characters; lib/workspace.js WORKSPACE_LIMITS.digests). */
export const DIGESTS_MAX_CHARS = 16384;
/** The kinds of digest, in the order the text holds them. */
export const DIGEST_KINDS = Object.freeze(['monitor']);
/** The counts of a Monitoring digest. */
export const MONITOR_DIGEST_COUNTS = Object.freeze(['targets', 'bad', 'expiring', 'incomplete']);
/**
 * The days its counts look at, as Home says them: `bad`, a bad change in the last 7 days
 * (lib/monitor.js MONITOR_RECENT_DAYS); `expiring`, under 21 days left (MONITOR_WARN_DAYS). Kept
 * here so Home does not load lib/monitor.js; a unit test keeps them equal.
 */
export const MONITOR_DIGEST_DAYS = Object.freeze({ bad: 7, expiring: 21 });

/** The largest count kept (a bound for a hand-edited file). */
const COUNT_MAX = 10000000;

const isoOf = (v) => {
  const t = v instanceof Date ? v.getTime() : typeof v === 'string' && v.length <= 40 ? Date.parse(v) : typeof v === 'number' ? v : NaN;
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
};
const countOf = (v) => (Number.isInteger(v) && v >= 0 && v <= COUNT_MAX ? v : null);

/**
 * A Monitoring digest checked: both times and the four counts, else null.
 * @param {{ at: Date|string|number, imported: Date|string|number, targets: number, bad: number, expiring: number, incomplete: number }} value
 * @returns {{ at: string, imported: string, targets: number, bad: number, expiring: number, incomplete: number }|null}
 */
export function monitorDigest(value) {
  if (!value || typeof value !== 'object') return null;
  const at = isoOf(value.at);
  const imported = isoOf(value.imported);
  if (!at || !imported) return null;
  const out = { at, imported };
  for (const key of MONITOR_DIGEST_COUNTS) {
    const n = countOf(value[key]);
    if (n === null) return null;
    out[key] = n;
  }
  return out;
}

const CHECKS = { monitor: monitorDigest };

/**
 * The digests in the workspace's text: each kind that checks; {} for anything else (broken JSON,
 * a stray value, an empty part).
 * @param {unknown} text
 * @returns {{ monitor?: ReturnType<typeof monitorDigest> }}
 */
export function readDigests(text) {
  let data = null;
  try {
    data = typeof text === 'string' && text.trim() && text.length <= DIGESTS_MAX_CHARS ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  const out = {};
  if (!data || typeof data !== 'object' || Array.isArray(data)) return out;
  for (const kind of DIGEST_KINDS) {
    const value = CHECKS[kind](data[kind]);
    if (value) out[kind] = value;
  }
  return out;
}

/**
 * The digests as the workspace keeps them: JSON text, '' when there is none (an empty part is not
 * stored), '' too for one that would not fit (never a cut text).
 * @param {object} digests
 * @returns {string}
 */
export function digestsText(digests) {
  const clean = {};
  for (const kind of DIGEST_KINDS) {
    const value = digests && CHECKS[kind](digests[kind]);
    if (value) clean[kind] = value;
  }
  if (!Object.keys(clean).length) return '';
  const text = JSON.stringify(clean);
  return text.length <= DIGESTS_MAX_CHARS ? text : '';
}

/**
 * The workspace's digests text with one kind's digest replaced, or removed with null (or a digest
 * that does not check); the other kinds stay as they were.
 * @param {unknown} text the part as stored
 * @param {string} kind one of {@link DIGEST_KINDS}
 * @param {object|null} value
 * @returns {string}
 */
export function withDigest(text, kind, value) {
  if (!DIGEST_KINDS.includes(kind)) return digestsText(readDigests(text));
  const next = { ...readDigests(text) };
  delete next[kind];
  const checked = value ? CHECKS[kind](value) : null;
  if (checked) next[kind] = checked;
  return digestsText(next);
}
