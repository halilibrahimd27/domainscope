/**
 * perf.mjs — the headroom the unit tests' complexity guards allow on a busy machine (not a test file).
 *
 * A guard such as "20,000 rows refresh under 200 ms" exists to catch an algorithm turning quadratic
 * or exponential, which costs orders of magnitude, not a few percent. CI runners run several test
 * files at once on shared CPUs, so a guard measured at 1× fails now and then on a healthy build.
 * Three times the budget keeps every guard meaningful; PERF_STRICT=1 (or the older
 * ZONE_PERF_STRICT=1) measures at 1× on a quiet machine.
 */
export const PERF_FACTOR = process.env.PERF_STRICT === '1' || process.env.ZONE_PERF_STRICT === '1' ? 1 : 3;
