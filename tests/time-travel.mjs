#!/usr/bin/env node
/**
 * time-travel.mjs — run a command with the clock moved, to find the tests a date will break.
 *
 *   node tests/time-travel.mjs <when> -- <command> [args...]
 *
 *   node tests/time-travel.mjs 2036-01-02 -- node --test "tests/js/*.test.js"
 *   node tests/time-travel.mjs 2034-05-26T12:00:00Z -- python -m unittest discover -s tests/python
 *   node tests/time-travel.mjs 2026-12-05 -- node tests/e2e/run-all.mjs --only estate,cert --offline --no-shots
 *
 * <when> is a day (then 12:00 UTC of it) or an instant (ISO 8601, with Z or an offset), from 1971 to
 * 2100. The command runs with Date.now() and `new Date()` of every Node process in it (the unit
 * tests, a suite, the servers), of every browser page the e2e harness opens (tests/e2e/cdp.mjs),
 * and time.time(), datetime.now() and the like of every Python process, moved by one shift (so they
 * agree with each other) to start at <when> and run on from there. Timers, performance.now(),
 * time.monotonic() and time.sleep() are not touched, so a wait takes as long as it does.
 *
 * What it finds: a test that goes red on a date without any change, because a fixture certificate
 * has expired by then or a deadline has passed (the fixtures expire from 2026-11-29 to 2052).
 * What it is not: the C library's clock stays real, so a TLS handshake that checks a certificate's
 * dates still sees today's, and a file's modification time stays what the file system says (a test
 * that writes a file and then compares its time with the clock has to set the time itself, as the
 * cache tests of tools/build-*.mjs do). For the first, run the command under libfaketime in Linux:
 *   FAKETIME_DONT_FAKE_MONOTONIC=1 faketime -f '@2050-01-02 12:00:00' <command>
 * (the monotonic clocks have to stay real, or sockets and threads hang).
 *
 * The command's own exit code is passed on. Standard library only; Node 22+.
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { SKEW_ENV } from './e2e/clock.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PRELOAD = path.join(HERE, 'time-travel', 'clock.mjs');
const PYTHON_FOLDER = path.join(HERE, 'time-travel');
const FIRST_YEAR = 1971;
const LAST_YEAR = 2100;

/**
 * The instant a <when> names, in ms since the epoch.
 * @param {string} text a day (`2036-01-02`, then 12:00 UTC) or an ISO 8601 instant with Z or an offset
 * @returns {number}
 * @throws {Error} when it is none, or outside 1971-2100
 */
export function parseWhen(text) {
  const value = String(text ?? '').trim();
  let ms = NaN;
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) ms = Date.parse(`${value}T12:00:00Z`);
  else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/i.test(value)) ms = Date.parse(value);
  // V8 reads 2037-02-29 as March 1st: the day has to be one the month has
  const [y, m, d] = value.slice(0, 10).split('-').map(Number);
  if (Number.isFinite(ms) && new Date(Date.UTC(y, m - 1, d)).getUTCDate() !== d) ms = NaN;
  if (!Number.isFinite(ms)) throw new Error(`not a day or an instant: ${value || '(nothing)'} (try 2036-01-02 or 2036-01-02T08:30:00Z)`);
  const year = new Date(ms).getUTCFullYear();
  if (year < FIRST_YEAR || year > LAST_YEAR) throw new Error(`${value}: the clock can be moved to ${FIRST_YEAR}-${LAST_YEAR}`);
  return ms;
}

/**
 * Split the command line into the instant and the command.
 * @param {string[]} argv
 * @returns {{ when: number, command: string[] }}
 * @throws {Error} with the usage when something is missing
 */
export function parseArgs(argv) {
  const dashes = argv.indexOf('--');
  const head = dashes === -1 ? argv : argv.slice(0, dashes);
  const command = dashes === -1 ? [] : argv.slice(dashes + 1);
  if (head.length !== 1 || !command.length) throw new Error('usage: node tests/time-travel.mjs <day or instant> -- <command> [args...]');
  return { when: parseWhen(head[0]), command };
}

/**
 * The environment of the command: the shift, the Node preload and the Python folder added to what
 * the environment already has (and once only: a run inside a time-travel run moves the clock
 * again from the real one, it does not add its shift to the first).
 * @param {Record<string, string|undefined>} env
 * @param {number} skewMs
 * @returns {Record<string, string|undefined>}
 */
export function timeTravelEnv(env, skewMs) {
  const preload = `--import=${pathToFileURL(PRELOAD).href}`;
  const options = String(env.NODE_OPTIONS ?? '').split(preload).join(' ').trim();
  const folders = String(env.PYTHONPATH ?? '').split(path.delimiter).filter((folder) => folder && folder !== PYTHON_FOLDER);
  return {
    ...env,
    [SKEW_ENV]: String(Math.trunc(skewMs)),
    NODE_OPTIONS: [options, preload].filter(Boolean).join(' '),
    PYTHONPATH: [PYTHON_FOLDER, ...folders].join(path.delimiter)
  };
}

/** The real time now, in ms since the epoch, even in a process whose own Date has been moved. */
export const realNow = () => performance.timeOrigin + performance.now();

function main() {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${err.message}\n`);
    process.exit(2);
  }
  const skew = Math.round(parsed.when - realNow());
  const days = Math.round(skew / 864e5);
  process.stderr.write(`time-travel: the clock starts at ${new Date(parsed.when).toISOString()} (${days >= 0 ? '+' : ''}${days} days) for Node, Python and the e2e pages\n`);
  const [file, ...args] = parsed.command;
  const child = spawn(file, args, { env: timeTravelEnv(process.env, skew), stdio: 'inherit' });
  child.on('error', (err) => {
    process.stderr.write(`time-travel: could not run ${file}: ${err.message}\n`);
    process.exit(2);
  });
  child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
