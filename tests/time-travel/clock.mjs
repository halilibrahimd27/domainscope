/**
 * Preload of a time-travel run (tests/time-travel.mjs puts it in NODE_OPTIONS as
 * `--import=<this file>`): when DS_TIME_SKEW_MS is set, this Node process's Date.now() and
 * `new Date()` are moved by that many milliseconds and run on from there. Timers and
 * performance.now() are not touched. Without the variable it does nothing.
 */
import { shiftClock, skewFromEnv } from '../e2e/clock.mjs';

const skew = skewFromEnv();
if (skew !== null) shiftClock(globalThis, { by: skew });
