/**
 * expiry.js — the expiry bands, in one place (docs/DESIGN.md §6.2): how few days left make a
 * domain's registration or a certificate an error or a warning. Home and the Domain portfolio's
 * registration column read them here, and every view's days-left tag moves to them with its phase
 * of the redesign.
 *
 * | Object        | error                 | warn       | ok        |
 * | registration  | expired or < 30 days  | < 60 days  | later     |
 * | certificate   | expired or < 7 days   | < 30 days  | later     |
 *
 * The certificate warning is 30 days for the UI (decision C1); the headless runner keeps its own
 * `--warn-days`. Pure: no DOM, clock, storage or i18n (`now` is passed in).
 */

/** Days left under which an object is an error, and under which a warning. */
export const EXPIRY_BANDS = Object.freeze({
  registration: Object.freeze({ error: 30, warn: 60 }),
  certificate: Object.freeze({ error: 7, warn: 30 })
});

/** The kinds of object with an expiry band. */
export const EXPIRY_KINDS = Object.freeze(Object.keys(EXPIRY_BANDS));

const DAY_MS = 86400000;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * The severity of `daysLeft` days left for an object of `kind`: 'error' (expired, or under the
 * error band), 'warn' (under the warn band), 'ok' (later); null for an unknown kind or a days left
 * that is not a number.
 * @param {'registration'|'certificate'} kind
 * @param {number} daysLeft whole days (negative: expired)
 * @returns {'error'|'warn'|'ok'|null}
 */
export function expirySeverity(kind, daysLeft) {
  const band = Object.prototype.hasOwnProperty.call(EXPIRY_BANDS, kind) ? EXPIRY_BANDS[kind] : null;
  if (!band || typeof daysLeft !== 'number' || !Number.isFinite(daysLeft)) return null;
  if (daysLeft < band.error) return 'error';
  return daysLeft < band.warn ? 'warn' : 'ok';
}

/**
 * The time of `when` in ms: a Date, a number of ms, an ISO time, or a day (YYYY-MM-DD: its start,
 * UTC). Null for anything else.
 * @param {Date|number|string} when
 * @returns {number|null}
 */
function timeOf(when) {
  if (when instanceof Date) return Number.isFinite(when.getTime()) ? when.getTime() : null;
  if (typeof when === 'number') return Number.isFinite(when) ? when : null;
  if (typeof when !== 'string' || !when) return null;
  const t = Date.parse(DAY_RE.test(when) ? `${when}T00:00:00Z` : when);
  return Number.isFinite(t) ? t : null;
}

/**
 * Whole days from `now` until `when` (rounded down; negative once it is past), as the views count
 * a countdown. A day (YYYY-MM-DD) counts from its start, UTC: a registration that ends on a day
 * says one day fewer rather than one too many.
 * @param {Date|number|string} when
 * @param {Date|number} now
 * @returns {number|null}
 */
export function daysUntil(when, now) {
  const t = timeOf(when);
  const n = now instanceof Date ? now.getTime() : Number(now);
  if (t === null || !Number.isFinite(n)) return null;
  return Math.floor((t - n) / DAY_MS);
}

/**
 * The days left and their severity of an object of `kind` that ends at `when`, or null when the
 * end is not known.
 * @param {'registration'|'certificate'} kind
 * @param {Date|number|string} when
 * @param {Date|number} now
 * @returns {{ daysLeft: number, severity: 'error'|'warn'|'ok' }|null}
 */
export function expiryOf(kind, when, now) {
  const daysLeft = daysUntil(when, now);
  const severity = daysLeft === null ? null : expirySeverity(kind, daysLeft);
  return severity ? { daysLeft, severity } : null;
}
