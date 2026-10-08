/**
 * The virtual clock the paced and time-dependent tests run on (tests/js/fake-clock.mjs): it starts
 * at a fixed instant, moves only when a test moves it, fires timers at exactly their instant,
 * lets chains of waits unfold as in real time, jumps over the quiet stretches, shows what is
 * waiting, and gives the real clock back afterwards.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fakeClock, flush, FAKE_CLOCK_START, FAKE_CLOCK_SETTLE_LIMIT_MS } from './fake-clock.mjs';

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

describe('fakeClock: the instant and the real clock', () => {
  test('starts at a fixed instant that Date.now() and new Date() agree on, and stands still until it is moved', async (t) => {
    const clock = fakeClock(t);
    assert.equal(FAKE_CLOCK_START, Date.parse('2026-10-08T12:00:00Z'));
    assert.equal(clock.start, FAKE_CLOCK_START);
    assert.equal(Date.now(), FAKE_CLOCK_START);
    assert.equal(new Date().toISOString(), '2026-10-08T12:00:00.000Z');
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(clock.now(), FAKE_CLOCK_START, 'real time passing moves nothing');
    assert.equal(clock.elapsed(), 0);
  });

  test('another instant: a number, a Date or an ISO string; a date that is none is refused', async (t) => {
    for (const start of [Date.UTC(2051, 0, 1), new Date('2051-01-01T00:00:00Z'), '2051-01-01T00:00:00Z']) {
      await t.test(`${typeof start}`, async (inner) => {
        const clock = fakeClock(inner, { start });
        assert.equal(new Date().toISOString(), '2051-01-01T00:00:00.000Z');
        assert.equal(clock.start, Date.UTC(2051, 0, 1));
      });
    }
    const before = Date.now();
    assert.throws(() => fakeClock(t, { start: 'next week' }), /not a date: next week/);
    assert.ok(Math.abs(Date.now() - before) < 5000, 'a refused start leaves the real clock alone');
  });

  test('the real clock and timers are back when the test is over', async (t) => {
    const realSetTimeout = globalThis.setTimeout;
    const realClearTimeout = globalThis.clearTimeout;
    const RealDate = globalThis.Date;
    const before = Date.now();
    await t.test('inside', async (inner) => {
      fakeClock(inner);
      assert.notEqual(globalThis.setTimeout, realSetTimeout);
      assert.equal(Date.now(), FAKE_CLOCK_START);
    });
    assert.equal(globalThis.setTimeout, realSetTimeout);
    assert.equal(globalThis.clearTimeout, realClearTimeout);
    assert.equal(globalThis.Date, RealDate);
    assert.ok(Math.abs(Date.now() - before) < 5000, 'the running clock again');
    await wait(5); // a real timer works
  });
});

describe('fakeClock: moving it', () => {
  test('advance fires a timer at exactly its instant, not before', async (t) => {
    const clock = fakeClock(t);
    const fired = [];
    wait(80).then(() => fired.push(clock.elapsed()));
    await clock.advance(79);
    assert.deepEqual(fired, [], 'not at 79 ms');
    await clock.advance(1);
    assert.deepEqual(fired, [80], 'at 80 ms, and what follows the timer has run');
    assert.equal(clock.elapsed(), 80);
  });

  test('advance lets a chain of waits unfold: a timer set by a continuation fires at that instant plus its delay', async (t) => {
    const clock = fakeClock(t);
    const at = [];
    (async () => {
      await wait(80);
      at.push(clock.elapsed());
      await wait(80);
      at.push(clock.elapsed());
      await wait(5);
      at.push(clock.elapsed());
    })();
    await clock.advance(1000);
    assert.deepEqual(at, [80, 160, 165]);
    assert.equal(clock.elapsed(), 1000);
  });

  test('timers fire in the order of their instants, equal ones in the order they were set; a cleared timer never fires', async (t) => {
    const clock = fakeClock(t);
    const order = [];
    setTimeout(() => order.push('c@30'), 30);
    setTimeout(() => order.push('a@10'), 10);
    setTimeout(() => order.push('b@10'), 10);
    clearTimeout(setTimeout(() => order.push('never'), 20));
    await clock.advance(50);
    assert.deepEqual(order, ['a@10', 'b@10', 'c@30']);
  });

  test('a timer gets the arguments it was set with, and its handle can be unref\'d like Node\'s', async (t) => {
    const clock = fakeClock(t);
    const got = [];
    const handle = setTimeout((a, b) => got.push([a, b]), 5, 'x', 'y');
    assert.equal(typeof handle.unref, 'function');
    await clock.advance(5);
    assert.deepEqual(got, [['x', 'y']]);
  });

  test('a wait of zero (or less, or past the largest delay) fires on the first millisecond, as Node does', async (t) => {
    const clock = fakeClock(t);
    const fired = [];
    for (const ms of [0, -5, NaN, 2 ** 31]) wait(ms).then(() => fired.push(ms));
    await flush();
    assert.deepEqual(fired, [], 'not before the clock moves');
    assert.deepEqual(clock.waits(), [1, 1, 1, 1]);
    await clock.advance(1);
    assert.equal(fired.length, 4);
  });

  test('a wait of an hour costs nothing: the clock jumps to the timer and Date.now() moves with it', async (t) => {
    const clock = fakeClock(t);
    const lookup = wait(3600e3).then(() => new Date().toISOString());
    await clock.advance(3600e3 - 1);
    assert.equal(clock.elapsed(), 3600e3 - 1);
    assert.equal(await clock.settle(lookup), '2026-10-08T13:00:00.000Z');
    assert.equal(clock.elapsed(), 3600e3);
  });

  test('advance takes whole, non-negative milliseconds', async (t) => {
    const clock = fakeClock(t);
    await assert.rejects(clock.advance(-1), RangeError);
    await assert.rejects(clock.advance(1.5), RangeError);
    await assert.rejects(clock.advance('5'), RangeError);
    await clock.advance(0);
    assert.equal(clock.elapsed(), 0);
  });
});

describe('fakeClock: what is waiting', () => {
  test('pending counts the timers that are set and not yet fired or cleared; waits says when each is due', async (t) => {
    const clock = fakeClock(t);
    assert.equal(clock.pending(), 0);
    assert.deepEqual(clock.waits(), []);
    const first = setTimeout(() => {}, 300);
    setTimeout(() => {}, 100);
    setTimeout(() => {}, 200);
    assert.equal(clock.pending(), 3);
    assert.deepEqual(clock.waits(), [100, 200, 300]);
    await clock.advance(150);
    assert.deepEqual(clock.waits(), [50, 150], 'one fired; the others are nearer');
    clearTimeout(first);
    assert.deepEqual(clock.waits(), [50]);
    await clock.advance(50);
    assert.equal(clock.pending(), 0);
  });

  test('a timer set while others wait is counted from now, not from the start', async (t) => {
    const clock = fakeClock(t);
    await clock.advance(40);
    setTimeout(() => {}, 100);
    assert.deepEqual(clock.waits(), [100]);
    await clock.advance(30);
    assert.deepEqual(clock.waits(), [70]);
  });
});

describe('fakeClock: settle', () => {
  test('runs the clock on until the promise has settled, and gives its value', async (t) => {
    const clock = fakeClock(t);
    const stages = [];
    const job = (async () => {
      await wait(250);
      stages.push(clock.elapsed());
      await wait(750);
      stages.push(clock.elapsed());
      return 'finished';
    })();
    assert.equal(await clock.settle(job), 'finished');
    assert.deepEqual(stages, [250, 1000]);
    assert.equal(clock.elapsed(), 1000, 'it stops the instant the promise settled');
  });

  test('gives a rejection as it is, and a promise that is settled already costs no time', async (t) => {
    const clock = fakeClock(t);
    const boom = new Error('boom');
    await assert.rejects(clock.settle(wait(40).then(() => { throw boom; })), (err) => err === boom);
    assert.equal(clock.elapsed(), 40);
    assert.equal(await clock.settle(Promise.resolve(7)), 7);
    assert.equal(clock.elapsed(), 40);
  });

  test('settles several waits that overlap, each at its own instant', async (t) => {
    const clock = fakeClock(t);
    const at = {};
    const all = Promise.all(['a', 'b', 'c'].map((name, i) => wait(80 * i).then(() => { at[name] = clock.elapsed(); })));
    await clock.settle(all);
    assert.deepEqual(at, { a: 1, b: 80, c: 160 });
  });

  test('says so when nothing is waiting on the clock, and when the next timer is past the limit', async (t) => {
    const clock = fakeClock(t);
    assert.equal(FAKE_CLOCK_SETTLE_LIMIT_MS, 60_000);
    await assert.rejects(clock.settle(new Promise(() => {})), /has not settled and no timer is waiting/);
    assert.equal(clock.elapsed(), 0);
    const far = wait(3600e3);
    await assert.rejects(clock.settle(far), /still waiting after 60000 ms of fake time \(the next timer is 3600000 ms away\)/);
    await assert.rejects(clock.settle(far, { limitMs: 25 }), /still waiting after 25 ms/);
    assert.equal(clock.elapsed(), 0, 'a refusal moves nothing');
    await clock.settle(far, { limitMs: 3600e3 });
    assert.equal(clock.elapsed(), 3600e3);
  });

  test('a continuation that needs more than one turn of the event loop is waited for', async (t) => {
    const clock = fakeClock(t);
    const job = (async () => {
      await wait(10);
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));
      await wait(10);
      return clock.elapsed();
    })();
    assert.equal(await clock.settle(job), 20);
  });
});
