/**
 * healthscore.js — the Domain Health score (v2, SPEC §5.78): a number from 0 to 100 and a letter
 * from A to F, computed from the checks of a lib/health.js report (and the Web checks of
 * lib/healthweb.js) weighted by category, plus the report's problems grouped for the "problems
 * first" list: errors, then warnings, each by category with counts.
 *
 * The formula:
 * 1. Every group g (dns, email, security, registration, web) that has at least one check scores
 *    s_g = max(0, 100 − 40·E_g − 15·W_g), E_g and W_g being its errors and warnings. Info and ok
 *    checks cost nothing.
 * 2. The raw score is the weighted mean Σ w_g·s_g / Σ w_g over the groups the report has, with the
 *    weights of {@link HEALTH_SCORE_WEIGHTS} (a group the table does not know weighs
 *    {@link DEFAULT_GROUP_WEIGHT}). A group with no check is left out, never counted as perfect.
 * 3. Caps: any error caps the score at 79 (a C at best), any warning at 89 (a B at best), so a
 *    problem in a light group still shows in the letter. A name that does not exist
 *    ({@link FATAL_CHECKS}) scores 0.
 * 4. score = min(round(raw), cap); the letter is A from 90, B from 80, C from 70, D from 60,
 *    E from 50 and F below ({@link HEALTH_GRADES}).
 *
 * Accepted risks (lib/waivers.js): the errors and warnings a waiver accepts are scored by the same
 * formula as if they cost nothing — their group stays, no cap comes from them — and the result
 * says how many were left out and what the score would be with them (`full`). The what-if planner
 * ({@link whatIfHealth}) scores the findings one plans to fix the same way. A check that says the
 * name does not exist ({@link FATAL_CHECKS}) is never left out.
 *
 * DOM-free; runs in browsers and Node 22.
 */

/** Groups in display order (lib/health HEALTH_CATEGORIES values, plus the Web group). */
export const HEALTH_SCORE_GROUPS = Object.freeze(['dns', 'email', 'security', 'registration', 'web']);

/** Weight of each group in the overall score (they add up to 100). */
export const HEALTH_SCORE_WEIGHTS = Object.freeze({ dns: 30, email: 25, security: 20, web: 15, registration: 10 });

/** Weight of a group that {@link HEALTH_SCORE_WEIGHTS} does not list (a newer category). */
export const DEFAULT_GROUP_WEIGHT = 10;

/** Points a group loses per check of each severity. */
export const SEVERITY_COST = Object.freeze({ error: 40, warn: 15, info: 0, ok: 0 });

/** Highest score a report with an error, or (without one) with a warning, can have. */
export const SCORE_CAPS = Object.freeze({ error: 79, warn: 89 });

/** Checks that mean the name does not exist at all: the score is 0. */
export const FATAL_CHECKS = Object.freeze(['domain.dangling-cname', 'domain.name-missing', 'domain.nxdomain']);

/** Letters and the lowest score of each, best first. */
export const HEALTH_GRADES = Object.freeze([
  Object.freeze({ grade: 'A', min: 90 }), Object.freeze({ grade: 'B', min: 80 }), Object.freeze({ grade: 'C', min: 70 }),
  Object.freeze({ grade: 'D', min: 60 }), Object.freeze({ grade: 'E', min: 50 }), Object.freeze({ grade: 'F', min: 0 })
]);

/** Why the score is lower than its weighted mean: a fatal check, an error cap or a warning cap. */
export const SCORE_CAP_REASONS = Object.freeze(['fatal', 'error', 'warn']);

const SEVERITIES = ['error', 'warn', 'info', 'ok'];

/**
 * @typedef {object} GroupScore
 * @property {string} group
 * @property {number} weight
 * @property {number} score 0…100
 * @property {number} error
 * @property {number} warn
 * @property {number} info
 * @property {number} ok
 * @property {number} waived errors and warnings of the group left out
 */

/**
 * @typedef {object} HealthGrade
 * @property {number} score 0…100, an integer
 * @property {string} grade 'A' … 'F'
 * @property {number} raw the weighted mean before the caps (unrounded)
 * @property {'fatal'|'error'|'warn'|null} cap the cap that lowered the score, if any
 * @property {GroupScore[]} groups the groups the checks have, in display order
 * @property {number} waived the errors and warnings left out (accepted risks, or planned fixes)
 * @property {{ score: number, grade: string, raw: number, cap: string|null }|null} full the score
 *   with them, when any was left out
 */

/** The group of a check, as lib/health makeCheck files it ('dns' when it has none). */
const groupOf = (c) => (c && typeof c.group === 'string' && c.group ? c.group : 'dns');
const severityOf = (c) => (c && SEVERITIES.includes(c.severity) ? c.severity : 'info');

/**
 * The weight of a group in the overall score.
 * @param {string} group
 * @returns {number}
 */
export function groupWeight(group) {
  return Object.hasOwn(HEALTH_SCORE_WEIGHTS, group) ? HEALTH_SCORE_WEIGHTS[group] : DEFAULT_GROUP_WEIGHT;
}

/**
 * The letter of a score.
 * @param {number} score
 * @returns {string} 'A' … 'F'
 */
export function gradeFor(score) {
  const s = Number(score);
  const n = Number.isFinite(s) ? s : 0;
  return (HEALTH_GRADES.find((g) => n >= g.min) || HEALTH_GRADES[HEALTH_GRADES.length - 1]).grade;
}

/** Display order of groups: the known ones first, then the others as they first appear. */
function orderGroups(names) {
  const known = HEALTH_SCORE_GROUPS.filter((g) => names.includes(g));
  return [...known, ...names.filter((g) => !HEALTH_SCORE_GROUPS.includes(g))];
}

/**
 * Which checks a `waived` option leaves out: none, check ids (an iterable), or a predicate.
 * @param {Iterable<string>|((check: object) => boolean)|null|undefined} waived
 * @returns {(check: object) => boolean}
 */
function waivedTest(waived) {
  if (typeof waived === 'function') return waived;
  if (!waived || typeof waived === 'string' || typeof waived[Symbol.iterator] !== 'function') return () => false;
  const ids = new Set(waived);
  return (c) => ids.has(c.id);
}

/** Can a check be left out of the score: an error or a warning that does not say the name is gone. */
const leavable = (c) => (c.severity === 'error' || c.severity === 'warn') && !FATAL_CHECKS.includes(c.id);

/**
 * The score and letter of a list of checks (a report's `checks`), with each group's part.
 * `waived` leaves errors and warnings out (lib/waivers.js healthWaivers `ids`): they cost nothing
 * and cap nothing, their group stays; `full` is the score with them.
 * @param {Array<{ id?: string, severity: string, group?: string }>|null|undefined} checks
 * @param {{ waived?: Iterable<string>|((check: object) => boolean)|null }} [opts]
 * @returns {HealthGrade}
 */
export function scoreHealth(checks, { waived = null } = {}) {
  const list = Array.isArray(checks) ? checks.filter((c) => c && typeof c === 'object') : [];
  const isWaived = waivedTest(waived);
  const tally = new Map();
  let left = 0;
  for (const c of list) {
    const g = groupOf(c);
    if (!tally.has(g)) tally.set(g, { error: 0, warn: 0, info: 0, ok: 0, waived: 0 });
    if (leavable(c) && isWaived(c)) {
      tally.get(g).waived += 1;
      left += 1;
    } else {
      tally.get(g)[severityOf(c)] += 1;
    }
  }
  const groups = orderGroups([...tally.keys()]).map((group) => {
    const n = tally.get(group);
    const score = Math.max(0, 100 - SEVERITY_COST.error * n.error - SEVERITY_COST.warn * n.warn);
    return { group, weight: groupWeight(group), score, ...n };
  });
  const weights = groups.reduce((sum, g) => sum + g.weight, 0);
  const raw = weights ? groups.reduce((sum, g) => sum + g.weight * g.score, 0) / weights : 100;
  const errors = groups.some((g) => g.error > 0);
  const warns = groups.some((g) => g.warn > 0);
  let score = Math.round(raw);
  let cap = null;
  if (list.some((c) => FATAL_CHECKS.includes(c.id))) {
    score = 0;
    cap = 'fatal';
  } else if (errors && score > SCORE_CAPS.error) {
    score = SCORE_CAPS.error;
    cap = 'error';
  } else if (!errors && warns && score > SCORE_CAPS.warn) {
    score = SCORE_CAPS.warn;
    cap = 'warn';
  }
  let full = null;
  if (left) {
    const all = scoreHealth(list);
    full = { score: all.score, grade: all.grade, raw: all.raw, cap: all.cap };
  }
  return { score, grade: gradeFor(score), raw, cap, groups, waived: left, full };
}

/**
 * The what-if planner: the score now (accepted risks left out) and with the ticked findings fixed
 * too, by the same formula ({@link scoreHealth}).
 * @param {Array<{ id?: string, severity: string, group?: string }>} checks
 * @param {Iterable<string>} fixed check ids one plans to fix
 * @param {{ waived?: Iterable<string>|null }} [opts] the accepted risks
 * @returns {{ now: HealthGrade, then: HealthGrade, gain: number, fixed: number }} `fixed`: how many
 *   errors and warnings the ticked ids stand for
 */
export function whatIfHealth(checks, fixed, { waived = null } = {}) {
  const accepted = new Set(waived && typeof waived !== 'string' && typeof waived[Symbol.iterator] === 'function' ? waived : []);
  const planned = [...(fixed || [])].filter((id) => !accepted.has(id));
  const now = scoreHealth(checks, { waived: accepted });
  const then = scoreHealth(checks, { waived: new Set([...accepted, ...planned]) });
  return { now, then, gain: then.score - now.score, fixed: then.waived - now.waived };
}

/**
 * @typedef {object} ProblemGroup
 * @property {string} group
 * @property {object[]} checks the group's problems of this severity, in report order
 */

/**
 * The problems of a report for the "problems first" list: the errors, then the warnings, each
 * split by group (display order) with their checks in report order. `waived` leaves the accepted
 * risks out (they are listed apart).
 * @param {Array<{ severity: string, group?: string }>|null|undefined} checks
 * @param {{ waived?: Iterable<string>|((check: object) => boolean)|null }} [opts]
 * @returns {{ total: number, sections: Array<{ severity: 'error'|'warn', count: number, groups: ProblemGroup[] }> }}
 */
export function problemsFirst(checks, { waived = null } = {}) {
  const isWaived = waivedTest(waived);
  const list = Array.isArray(checks) ? checks.filter((c) => c && typeof c === 'object' && !(leavable(c) && isWaived(c))) : [];
  const sections = ['error', 'warn'].map((severity) => {
    const mine = list.filter((c) => c.severity === severity);
    const names = orderGroups([...new Set(mine.map(groupOf))]);
    return { severity, count: mine.length, groups: names.map((group) => ({ group, checks: mine.filter((c) => groupOf(c) === group) })) };
  }).filter((s) => s.count > 0);
  return { total: sections.reduce((sum, s) => sum + s.count, 0), sections };
}

/**
 * Severity counts of a list of checks, as lib/health's report `summary`; `waived` leaves the
 * accepted risks out of the error and warning counts.
 * @param {Array<{ severity: string }>} checks
 * @param {{ waived?: Iterable<string>|((check: object) => boolean)|null }} [opts]
 * @returns {{ ok: number, info: number, warn: number, error: number }}
 */
export function countSeverities(checks, { waived = null } = {}) {
  const isWaived = waivedTest(waived);
  const summary = { ok: 0, info: 0, warn: 0, error: 0 };
  for (const c of Array.isArray(checks) ? checks : []) {
    if (c && Object.hasOwn(summary, c.severity) && !(leavable(c) && isWaived(c))) summary[c.severity] += 1;
  }
  return summary;
}
