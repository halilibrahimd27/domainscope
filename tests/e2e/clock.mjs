/**
 * clock.mjs — the clock of a browser page (and of a Node process) under test.
 *
 * Fixture certificates and reports carry fixed dates, so a page that reads the clock shows a
 * different result one day: the estate suite's expiry tiles broke when its fixture certificate
 * expired. A suite therefore either starts the page's clock at the instant its expectations were
 * written for ({@link pinnedClockScript}, installed with CDP's Page.addScriptToEvaluateOnNewDocument
 * on every load), or runs on a moved clock for a time-travel check ({@link skewedClockScript}: the
 * harness installs it on every page when {@link SKEW_ENV} is set, see tests/time-travel.mjs, and
 * tests/time-travel/clock.mjs does the same for a Node process).
 *
 * All of them move Date.now() and `new Date()` and then let them run on; timers and
 * performance.now() are untouched, so the waits take as long as they do. One function,
 * {@link shiftClock}, does it: the page gets its source, a Node process calls it. A clock is
 * moved from the real one, not from a moved one: the last shift stands.
 */

/** The environment variable that moves every clock of a run (the pages, the Node processes, Python): milliseconds. */
export const SKEW_ENV = 'DS_TIME_SKEW_MS';

/**
 * Move the clock of `scope` (a global object): Date.now() and `new Date()` with no argument. A
 * date made from arguments, Date.UTC and Date.parse are not touched. Either `by` (milliseconds,
 * forward or back) or `to` (the instant, in ms since the epoch, the clock has now; it runs on
 * from there). Calling it again moves the clock again from the real one. Self-contained on
 * purpose: the page runs this function's source.
 * @param {{ Date: DateConstructor }} scope
 * @param {{ by?: number, to?: number }} move
 */
export function shiftClock(scope, { by = 0, to = null } = {}) {
  const KEY = Symbol.for('domainscope.shiftedClock');
  const RealDate = scope.Date;
  let state = RealDate[KEY];
  if (!state) {
    state = { native: RealDate.now.bind(RealDate), skew: 0 };
    const shiftedNow = () => state.native() + state.skew;
    // on the real Date itself: a test that swaps Date.now for its own function swaps this one
    RealDate.now = shiftedNow;
    Object.defineProperty(RealDate, KEY, { value: state });
    scope.Date = new Proxy(RealDate, {
      construct(real, args) {
        return args.length === 0 ? new real(shiftedNow()) : new real(...args);
      },
      apply(real) {
        return new real(shiftedNow()).toString();
      }
    });
  }
  state.skew = to === null ? by : to - state.native();
}

/**
 * Source of a script that moves the page's clock forward (or back) by `skewMs`.
 * @param {number} skewMs
 * @returns {string}
 */
export function skewedClockScript(skewMs) {
  if (!Number.isFinite(skewMs)) throw new TypeError(`skewedClockScript: not a number of milliseconds: ${String(skewMs)}`);
  return `(${shiftClock.toString()})(globalThis, { by: ${Math.trunc(skewMs)} });`;
}

/**
 * Source of a script that starts the page's clock at `instantMs` (ms since the epoch) when it runs,
 * on every load, and lets it run on.
 * @param {number} instantMs
 * @returns {string}
 */
export function pinnedClockScript(instantMs) {
  if (!Number.isFinite(instantMs)) throw new TypeError(`pinnedClockScript: not an instant: ${String(instantMs)}`);
  return `(${shiftClock.toString()})(globalThis, { to: ${Math.trunc(instantMs)} });`;
}

/**
 * The shift {@link SKEW_ENV} asks for, in ms; null when it is unset, empty or not a number.
 * @param {Record<string, string|undefined>} [env]
 * @returns {number|null}
 */
export function skewFromEnv(env = process.env) {
  const raw = env[SKEW_ENV];
  if (raw === undefined || raw.trim() === '') return null;
  const skew = Number(raw);
  return Number.isFinite(skew) ? Math.trunc(skew) : null;
}
