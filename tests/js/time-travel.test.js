/**
 * The time-travel check (tests/time-travel.mjs): a command run with the clock moved, for Node
 * (tests/time-travel/clock.mjs), the e2e pages (tests/e2e/clock.mjs, installed by cdp.mjs) and
 * Python (tests/time-travel/sitecustomize.py). The clock script of a page is run in a separate
 * V8 context here; no browser is needed. The tests hold on a moved clock too (the whole suite is
 * run that way): what they compare with is the real time, not this process's Date.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import vm from 'node:vm';

import { parseWhen, parseArgs, timeTravelEnv, realNow } from '../time-travel.mjs';
import { SKEW_ENV, shiftClock, skewedClockScript, pinnedClockScript, skewFromEnv } from '../e2e/clock.mjs';
import { Page } from '../e2e/cdp.mjs';

const TESTS = join(dirname(fileURLToPath(import.meta.url)), '..');
const DRIVER = join(TESTS, 'time-travel.mjs');
const PRELOAD_URL = pathToFileURL(join(TESTS, 'time-travel', 'clock.mjs')).href;
const DAY = 864e5;

/** A V8 context of its own (its own Date), so a clock moved in it leaves this process's alone. */
const realm = () => vm.createContext({});

/** Let `ms` of real time pass without a timer (a timer may fire a few milliseconds before the clock says it is due). */
const spin = (ms) => {
  const end = performance.now() + ms;
  while (performance.now() < end);
};

describe('time-travel: which instant', () => {
  test('a day is that day at 12:00 UTC; an instant needs its Z or offset', () => {
    assert.equal(parseWhen('2036-01-02'), Date.UTC(2036, 0, 2, 12));
    assert.equal(parseWhen(' 2036-01-02 '), Date.UTC(2036, 0, 2, 12));
    assert.equal(parseWhen('2034-05-26T08:30:00Z'), Date.UTC(2034, 4, 26, 8, 30));
    assert.equal(parseWhen('2034-05-26T08:30Z'), Date.UTC(2034, 4, 26, 8, 30));
    assert.equal(parseWhen('2034-05-26T08:30:15.250+03:00'), Date.UTC(2034, 4, 26, 5, 30, 15, 250));
    assert.equal(parseWhen('2034-05-26t08:30:00z'), Date.UTC(2034, 4, 26, 8, 30), 'case does not matter');
  });

  test('anything else is refused, and so is a year the clocks of Node and Python cannot both keep', () => {
    for (const bad of ['', undefined, 'soon', '2036-1-2', '2036-01-32', '2036-02-30', '2037-02-29', '2036-02-30T00:00:00Z', '2036-13-01', '2036-01-02T08:30:00', '20360102', '1970-12-31', '2101-01-01']) {
      assert.throws(() => parseWhen(bad), /not a day or an instant|the clock can be moved to 1971-2100/, String(bad));
    }
    assert.equal(parseWhen('2036-02-29'), Date.UTC(2036, 1, 29, 12), 'a leap day is a day');
    assert.equal(parseWhen('1971-01-01'), Date.UTC(1971, 0, 1, 12));
    assert.equal(parseWhen('2100-12-31'), Date.UTC(2100, 11, 31, 12));
  });
});

describe('time-travel: the command line and the environment', () => {
  test('<when> -- <command> [args...]; the command keeps its own dashes', () => {
    assert.deepEqual(parseArgs(['2036-01-02', '--', 'node', '--test', 'tests/js/*.test.js']), { when: Date.UTC(2036, 0, 2, 12), command: ['node', '--test', 'tests/js/*.test.js'] });
    assert.deepEqual(parseArgs(['2036-01-02', '--', 'python', '-m', 'unittest', '--', 'x']).command, ['python', '-m', 'unittest', '--', 'x']);
  });

  test('usage when the instant, the dashes or the command is missing, or there are two instants', () => {
    for (const argv of [[], ['2036-01-02'], ['2036-01-02', '--'], ['--', 'node'], ['2036-01-02', '2036-01-03', '--', 'node']]) {
      assert.throws(() => parseArgs(argv), /usage: node tests\/time-travel\.mjs/, JSON.stringify(argv));
    }
    assert.throws(() => parseArgs(['soon', '--', 'node']), /not a day or an instant/);
  });

  test('the shift, the Node preload and the Python folder are added to what the environment already has', () => {
    const base = { PATH: '/bin', NODE_OPTIONS: '--max-old-space-size=512', PYTHONPATH: '/lib/py' };
    const env = timeTravelEnv(base, 3 * DAY + 0.9);
    assert.equal(env[SKEW_ENV], String(3 * DAY));
    assert.equal(env.PATH, '/bin');
    assert.equal(env.NODE_OPTIONS, `--max-old-space-size=512 --import=${PRELOAD_URL}`);
    const folders = env.PYTHONPATH.split(process.platform === 'win32' ? ';' : ':');
    assert.equal(folders.length, 2);
    assert.ok(folders[0].replaceAll('\\', '/').endsWith('/tests/time-travel'), folders[0]);
    assert.equal(folders[1], '/lib/py');
    assert.deepEqual(base, { PATH: '/bin', NODE_OPTIONS: '--max-old-space-size=512', PYTHONPATH: '/lib/py' }, 'the environment given is left alone');
    const bare = timeTravelEnv({}, -DAY);
    assert.equal(bare[SKEW_ENV], String(-DAY));
    assert.equal(bare.NODE_OPTIONS, `--import=${PRELOAD_URL}`);
    assert.ok(!bare.PYTHONPATH.includes(process.platform === 'win32' ? ';' : ':'), 'just the one folder');
  });

  test('a run inside a run: the preload and the folder are in the environment once, and the shift is the new one', () => {
    const inner = timeTravelEnv(timeTravelEnv({ NODE_OPTIONS: '--no-warnings', PYTHONPATH: '/lib/py' }, 5 * DAY), -2 * DAY);
    assert.equal(inner[SKEW_ENV], String(-2 * DAY));
    assert.equal(inner.NODE_OPTIONS, `--no-warnings --import=${PRELOAD_URL}`);
    const folders = inner.PYTHONPATH.split(process.platform === 'win32' ? ';' : ':');
    assert.equal(folders.length, 2);
    assert.equal(folders[1], '/lib/py');
  });

  test('skewFromEnv reads whole milliseconds and nothing else', () => {
    assert.equal(skewFromEnv({}), null);
    assert.equal(skewFromEnv({ [SKEW_ENV]: '' }), null);
    assert.equal(skewFromEnv({ [SKEW_ENV]: '  ' }), null);
    assert.equal(skewFromEnv({ [SKEW_ENV]: 'tomorrow' }), null);
    assert.equal(skewFromEnv({ [SKEW_ENV]: 'Infinity' }), null);
    assert.equal(skewFromEnv({ [SKEW_ENV]: '86400000' }), DAY);
    assert.equal(skewFromEnv({ [SKEW_ENV]: '-1500.9' }), -1500);
    assert.equal(skewFromEnv({ [SKEW_ENV]: '0' }), 0);
  });
});

describe('time-travel: the clock of a page and of a Node process (shiftClock)', () => {
  test('Date.now() and new Date() move and run on; a date made from arguments, Date.UTC and Date.parse do not', () => {
    const context = realm();
    const run = (code) => vm.runInContext(code, context);
    const before = run('Date.now()');
    shiftClock(run('globalThis'), { by: 100 * DAY });
    const a = run('Date.now()');
    assert.ok(a - before >= 100 * DAY && a - before < 100 * DAY + 5000, `${a - before}`);
    assert.ok(Math.abs(run('new Date().getTime()') - a) < 5000, 'new Date() agrees');
    spin(25);
    assert.ok(run('Date.now()') >= a + 20, 'it runs on');
    assert.equal(run('new Date(2020, 0, 1, 12).getFullYear()'), 2020);
    assert.equal(run('new Date("2020-02-03T04:05:06Z").toISOString()'), '2020-02-03T04:05:06.000Z');
    assert.equal(run('new Date(86400000).toISOString()'), '1970-01-02T00:00:00.000Z');
    assert.equal(run('Date.UTC(2020, 1, 3)'), Date.UTC(2020, 1, 3));
    assert.equal(run('Date.parse("2020-02-03T04:05:06Z")'), Date.parse('2020-02-03T04:05:06Z'));
  });

  test('it stays a Date: instanceof both ways, Date() as a function, the prototype, a date made before', () => {
    const context = realm();
    const run = (code) => vm.runInContext(code, context);
    const earlier = run('new Date(1e12)');
    shiftClock(run('globalThis'), { by: 5 * DAY });
    assert.equal(run('new Date() instanceof Date'), true);
    assert.equal(run('new Date(1e12) instanceof Date'), true);
    assert.equal(run('typeof Date()'), 'string');
    assert.match(run('Date()'), /^[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{4}/);
    assert.equal(run('Object.prototype.toString.call(new Date())'), '[object Date]');
    assert.equal(run('Date.prototype === Object.getPrototypeOf(new Date())'), true);
    context.earlier = earlier;
    assert.equal(run('earlier instanceof Date'), true, 'a Date made before the shift is still one');
    assert.equal(run('Date.length'), 7);
    assert.equal(run('Date.name'), 'Date');
  });

  test('a test that swaps Date.now for its own function still gets its own; swapping it back gives the shifted clock', () => {
    const context = realm();
    const run = (code) => vm.runInContext(code, context);
    shiftClock(run('globalThis'), { by: 2 * DAY });
    const real = run('Date.now');
    run('globalThis.__shifted = Date.now; Date.now = () => 42');
    assert.equal(run('Date.now()'), 42);
    run('Date.now = globalThis.__shifted');
    assert.ok(run('Date.now()') > realNow() + DAY);
    assert.equal(typeof real, 'function');
  });

  test('`to` starts the clock at an instant; a second shift moves it again from the real clock, it does not add to the first', () => {
    const context = realm();
    const run = (code) => vm.runInContext(code, context);
    const at = Date.UTC(2034, 4, 26, 8, 30);
    shiftClock(run('globalThis'), { to: at });
    assert.ok(Math.abs(run('Date.now()') - at) < 5000);
    assert.equal(run('new Date().toISOString().slice(0, 16)'), '2034-05-26T08:30');
    shiftClock(run('globalThis'), { by: 10 * DAY });
    const moved = run('Date.now()') - realNow();
    assert.ok(moved > 10 * DAY - 5000 && moved < 10 * DAY + 5000, `${moved}: 10 days from the real clock, not from 2034`);
    shiftClock(run('globalThis'), { to: at });
    assert.ok(Math.abs(run('Date.now()') - at) < 5000, 'pinned again');
    shiftClock(run('globalThis'), { by: 0 });
    assert.ok(Math.abs(run('Date.now()') - realNow()) < 5000, 'no shift: the real clock');
    assert.equal(run('new Date() instanceof Date'), true);
  });

  test('skewedClockScript is the same thing as source for a page: shifted by the skew', () => {
    const context = realm();
    const before = vm.runInContext('Date.now()', context);
    vm.runInContext(skewedClockScript(7 * DAY + 0.9), context);
    const shifted = vm.runInContext('Date.now()', context);
    assert.ok(shifted - before >= 7 * DAY && shifted - before < 7 * DAY + 5000, `${shifted - before}`);
    assert.throws(() => skewedClockScript(NaN), /not a number of milliseconds/);
    assert.throws(() => skewedClockScript('7'), /not a number of milliseconds/);
  });

  test('pinnedClockScript starts the page\'s clock at an instant, on every load, and lets it run on', () => {
    const at = Date.UTC(2026, 9, 1, 12);
    for (const run of [0, 1]) { // two loads: two contexts, the same start
      const context = realm();
      vm.runInContext(pinnedClockScript(at), context);
      const first = vm.runInContext('Date.now()', context);
      assert.ok(first >= at && first < at + 5000, `load ${run}: ${first - at} ms after the instant`);
      assert.equal(vm.runInContext('new Date().toISOString().slice(0, 13)', context), '2026-10-01T12');
      spin(25);
      assert.ok(vm.runInContext('Date.now()', context) >= first + 20, 'it runs on');
    }
    assert.throws(() => pinnedClockScript(Number.NaN), /not an instant/);
    assert.throws(() => pinnedClockScript(undefined), /not an instant/);
  });
});

describe('time-travel: the E2E harness', () => {
  /** The scripts a page installs on every load, when its harness starts it with `skew` in the environment (null: none). */
  async function installedScripts(skew) {
    const sent = [];
    const conn = { on() {}, send: async (method, params) => { sent.push({ method, params }); return {}; } };
    const saved = process.env[SKEW_ENV];
    try {
      if (skew === null) delete process.env[SKEW_ENV];
      else process.env[SKEW_ENV] = String(skew);
      await new Page(conn, 'target-1', 'session-1', { width: 800, height: 600 })._init();
    } finally {
      if (saved === undefined) delete process.env[SKEW_ENV];
      else process.env[SKEW_ENV] = saved;
    }
    return sent.filter((m) => m.method === 'Page.addScriptToEvaluateOnNewDocument').map((m) => m.params.source);
  }

  test('a page opened in a time-travel run gets the moved clock after the own script of the harness; otherwise only that script', async () => {
    const plain = await installedScripts(null);
    assert.equal(plain.length, 1);
    assert.match(plain[0], /__cspViolations/);
    const moved = await installedScripts(3 * DAY);
    assert.equal(moved.length, 2);
    assert.equal(moved[0], plain[0]);
    assert.equal(moved[1], skewedClockScript(3 * DAY));
    assert.equal((await installedScripts(0)).length, 2, 'a shift of nothing is still a time-travel run');
    assert.equal((await installedScripts(-DAY))[1], skewedClockScript(-DAY));
  });

  test('a suite that pins the clock of its page after that wins: the last shift stands, whatever the run moved', () => {
    const context = realm();
    const at = Date.UTC(2026, 9, 1, 12);
    vm.runInContext(skewedClockScript(900 * DAY), context);   // the harness's, on every page of a time-travel run
    vm.runInContext(pinnedClockScript(at), context);          // the suite's own
    const first = vm.runInContext('Date.now()', context);
    assert.ok(first >= at && first < at + 5000, `${first - at} ms after the instant`);
  });
});

describe('time-travel: a command run on the moved clock', () => {
  const when = '2040-06-02';

  test('Node: the driver moves Date.now() and new Date() of the command and of its children, and says so', () => {
    const code = 'console.log(new Date().toISOString().slice(0, 10), new Date(Date.now()).getUTCFullYear(), new Date(2020, 5, 1).getFullYear())';
    const run = spawnSync(process.execPath, [DRIVER, when, '--', process.execPath, '-e', code], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout.trim(), '2040-06-02 2040 2020');
    assert.match(run.stderr, /time-travel: the clock starts at 2040-06-02T12:00:00\.000Z \([+-]?\d+ days\)/); // minus once 2040 has come
    const child = 'console.log(require("node:child_process").execFileSync(process.execPath, ["-e", "console.log(new Date().getUTCFullYear())"], { encoding: "utf8" }).trim())';
    const nested = spawnSync(process.execPath, [DRIVER, when, '--', process.execPath, '-e', child], { encoding: 'utf8' });
    assert.equal(nested.stdout.trim(), '2040', nested.stderr);
  });

  test('Node: a driver inside a driver sets the clock from the real one: the inner day, exactly', () => {
    const code = `console.log(require("node:child_process").execFileSync(process.execPath, [${JSON.stringify(DRIVER)}, "2045-03-04", "--", process.execPath, "-e", "console.log(new Date().toISOString().slice(0, 10))"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim())`;
    const run = spawnSync(process.execPath, [DRIVER, when, '--', process.execPath, '-e', code], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout.trim(), '2045-03-04');
  });

  test('Node: the exit code of the command is the driver\'s; a command that cannot start, bad input and a missing command are exit 2', () => {
    assert.equal(spawnSync(process.execPath, [DRIVER, when, '--', process.execPath, '-e', 'process.exit(7)']).status, 7);
    const missing = spawnSync(process.execPath, [DRIVER, when, '--', 'no-such-program-for-the-time-travel-test'], { encoding: 'utf8' });
    assert.equal(missing.status, 2);
    assert.match(missing.stderr, /could not run no-such-program/);
    assert.equal(spawnSync(process.execPath, [DRIVER, 'soon', '--', 'node'], { encoding: 'utf8' }).status, 2);
    assert.equal(spawnSync(process.execPath, [DRIVER], { encoding: 'utf8' }).status, 2);
  });

  test('Node: without the variable the preload leaves the clock alone', () => {
    const env = { ...process.env, NODE_OPTIONS: `--import=${PRELOAD_URL}` };
    delete env[SKEW_ENV];
    const run = spawnSync(process.execPath, ['-e', 'console.log(Math.abs(Date.now() - ' + realNow() + ') < 60000, Date.now.name)'], { encoding: 'utf8', env });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout.trim(), 'true now');
  });

  test('Python: time.time(), datetime.now() / utcnow() / today(), date.today() and gmtime() are moved; datetime stays a datetime', (t) => {
    const python = ['python3', 'python'].find((name) => spawnSync(name, ['-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)']).status === 0);
    if (!python) {
      t.skip('no Python 3.8+ on this machine');
      return;
    }
    const code = [
      'import datetime, time',
      'from datetime import datetime as D, timezone, timedelta',
      'now = D.now(timezone.utc)',
      'print(now.strftime("%Y-%m-%d"), D.utcnow().year, D.now().year, datetime.date.today().year, time.gmtime().tm_year, time.localtime().tm_year,',
      '      int(time.time()) // 86400 == int(now.timestamp()) // 86400, time.time_ns() // 10**9 // 86400 == int(now.timestamp()) // 86400,',
      '      isinstance(now + timedelta(days=1), D), isinstance(D(2020, 1, 1), D), isinstance(now, datetime.datetime), issubclass(D, datetime.datetime),',
      '      D(2020, 1, 1).year, D.strptime("2021-03-04", "%Y-%m-%d").year, D.fromisoformat("2022-05-06T07:08:09+00:00").year)'
    ].join('\n');
    const run = spawnSync(process.execPath, [DRIVER, when, '--', python, '-c', code], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout.trim(), '2040-06-02 2040 2040 2040 2040 2040 True True True True True True 2020 2021 2022');
  });

  test('Python: without the variable the folder leaves the clock alone', (t) => {
    const python = ['python3', 'python'].find((name) => spawnSync(name, ['-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)']).status === 0);
    if (!python) {
      t.skip('no Python 3.8+ on this machine');
      return;
    }
    const env = { ...process.env, PYTHONPATH: join(TESTS, 'time-travel') };
    delete env[SKEW_ENV];
    const run = spawnSync(python, ['-c', `import time, datetime; print(abs(time.time() - ${realNow() / 1000}) < 60, time.time.__name__, datetime.datetime.__name__)`], { encoding: 'utf8', env });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout.trim(), 'True time datetime');
  });
});
