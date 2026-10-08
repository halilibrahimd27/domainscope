/**
 * A virtual clock for the tests of code that waits or reads the time.
 *
 * Date.now(), `new Date()`, setTimeout and clearTimeout run on a clock that starts at a fixed
 * instant and moves only when the test moves it. A pause of 80 ms, a Retry-After of a minute or
 * a cache that is fresh for 12 hours then costs no real time, and what a test asserts never
 * depends on how busy the machine is: a real timer can fire a few milliseconds before
 * Date.now() says it is due (or late), which is how an "at least 75 ms apart" check flips
 * between pass and fail, and a fixed instant cannot run into the expiry date of a fixture.
 *
 * It is node:test's mock timers plus what the code under test needs: promise continuations run
 * between two moves of the clock (so a lookup that sleeps, wakes and sleeps again behaves as it
 * does in real time), the clock jumps from one timer to the next instead of ticking through the
 * quiet stretches, and a test can see what is waiting and run the clock on until something has
 * settled.
 *
 *   test('a paced lookup', async (t) => {
 *     const clock = fakeClock(t);
 *     const lookup = pacedLookup();       // starts waiting, on the fake clock
 *     await clock.advance(79);            // 79 ms later it is still waiting
 *     await clock.advance(1);             // at 80 ms its timer fired and what follows has run
 *     assert.equal(await clock.settle(lookup), 'done');   // or: move on until it has settled
 *     assert.equal(clock.elapsed(), 160);
 *   });
 *
 * The real clock is back when the test ends. performance.now(), setImmediate, setInterval and
 * AbortSignal.timeout are not part of it and stay real (an AbortSignal.timeout(3000) is a fine
 * safety net around a test of a fake-clock wait). The clock is the process's: a test that uses it
 * must not run beside another test of its file (node:test runs a file's tests one after the other
 * unless asked to run them concurrently), and a file's tests run in a process of their own.
 */

/** The instant a fake clock starts at unless a test says otherwise: 2026-10-08 12:00:00 UTC. */
export const FAKE_CLOCK_START = Date.UTC(2026, 9, 8, 12, 0, 0);

/** How far ahead, at most, `settle` runs the clock to see a promise settle (ms). */
export const FAKE_CLOCK_SETTLE_LIMIT_MS = 60_000;

/** The longest delay a timer keeps (2^31 - 1 ms); a longer one fires at once, as in Node. */
const TIMEOUT_MAX = 2 ** 31 - 1;

/** Let every promise continuation that can run without time passing run: two turns of the event loop. */
export async function flush() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

/**
 * Switch the test's Date and timers over to a fake clock.
 * @param {import('node:test').TestContext} t the test (or suite) it lasts for
 * @param {{ start?: number|Date|string }} [options] the instant it starts at (default {@link FAKE_CLOCK_START})
 * @returns {{
 *   start: number,
 *   now: () => number,
 *   elapsed: () => number,
 *   pending: () => number,
 *   waits: () => number[],
 *   flush: () => Promise<void>,
 *   advance: (ms: number) => Promise<void>,
 *   settle: <T>(promise: Promise<T>, options?: { limitMs?: number }) => Promise<T>
 * }}
 */
export function fakeClock(t, { start = FAKE_CLOCK_START } = {}) {
  const startMs = new Date(start).getTime();
  if (!Number.isFinite(startMs)) throw new TypeError(`fakeClock: not a date: ${String(start)}`);
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: startMs });
  t.after(() => t.mock.timers.reset());

  // When each timer is due, so the clock can jump to the next one instead of ticking every millisecond.
  const due = new Map();
  const mockedSetTimeout = globalThis.setTimeout;
  const mockedClearTimeout = globalThis.clearTimeout;
  globalThis.setTimeout = (callback, delay, ...args) => {
    const wait = Number(delay) >= 1 && Number(delay) <= TIMEOUT_MAX ? Math.trunc(Number(delay)) : 1;
    const handle = mockedSetTimeout((...fired) => {
      due.delete(handle);
      return callback(...fired);
    }, delay, ...args);
    due.set(handle, Date.now() + wait);
    return handle;
  };
  globalThis.clearTimeout = (handle) => {
    due.delete(handle);
    return mockedClearTimeout(handle);
  };

  const now = () => Date.now();
  const nextDue = () => (due.size ? Math.min(...due.values()) : null);
  /** Move to the instant `to` (at least a millisecond on): the timers due by then fire. */
  const moveTo = async (to) => {
    t.mock.timers.tick(Math.max(1, to - now()));
    await flush();
  };

  return {
    /** The instant it started at (ms since the epoch). */
    start: startMs,
    /** Date.now() on the fake clock. */
    now,
    /** The milliseconds that have passed on it since it started. */
    elapsed: () => now() - startMs,
    /** How many timers are waiting. */
    pending: () => due.size,
    /** The timers waiting, as the milliseconds from now until each is due, soonest first. */
    waits: () => [...due.values()].map((at) => at - now()).sort((a, b) => a - b),
    flush,
    /**
     * Move the clock on by `ms`, stopping at each timer that falls due on the way with the promise
     * continuations run there, so a timer set by a continuation at some instant fires at that
     * instant plus its delay, as in real time.
     */
    async advance(ms) {
      if (!Number.isInteger(ms) || ms < 0) throw new RangeError(`advance: whole milliseconds, not ${String(ms)}`);
      const target = now() + ms;
      await flush();
      while (now() < target) {
        const next = nextDue();
        await moveTo(next === null ? target : Math.min(next, target));
      }
    },
    /**
     * Run the clock on, timer by timer, until the promise has settled; then its value, or its
     * rejection. It throws when the next timer is more than `limitMs` of fake time away (60 s by
     * default), and when the promise has not settled and no timer is waiting: nothing the clock
     * moves is what it waits for.
     */
    async settle(promise, { limitMs = FAKE_CLOCK_SETTLE_LIMIT_MS } = {}) {
      let settled = false;
      promise.then(() => { settled = true; }, () => { settled = true; });
      await flush();
      const limit = now() + limitMs;
      while (!settled) {
        let next = nextDue();
        // nothing waits on the clock yet: a continuation may still need a few more turns of the event loop
        for (let turn = 0; next === null && !settled && turn < 5; turn += 1) {
          await flush();
          next = nextDue();
        }
        if (settled) break;
        if (next === null) throw new Error('fakeClock: the promise has not settled and no timer is waiting');
        if (next > limit) throw new Error(`fakeClock: still waiting after ${limitMs} ms of fake time (the next timer is ${next - now()} ms away)`);
        await moveTo(next);
      }
      return promise;
    }
  };
}
