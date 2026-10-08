/**
 * Unit tests for the test harness itself (no network, no browser):
 *   tests/live/replay-cache.mjs   — passive-source record / replay cache of the benchmark
 *   tests/live/targets.mjs        — positional-argument parsing of the live scripts
 *   tests/e2e/run-all.mjs         — suite ordering, result counting, leftover-profile sweep
 *   tests/e2e/cdp.mjs             — launched-browser cleanup, resolver-failure tolerance, key events, launch flags
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createReplayCache, isFinalAnswer } from '../live/replay-cache.mjs';
import { positionalArgs, PUBLIC_FALLBACK_DOMAINS } from '../live/targets.mjs';
import { parseArgs, orderSuites, countResults, profileDirsOf } from '../e2e/run-all.mjs';
import { resolverProblemFilter, registerBrowserProcess, killLaunchedBrowsers, launchBrowser, Page } from '../e2e/cdp.mjs';
import { RESOLVERS, DEFAULT_CHAIN } from '../../assets/js/lib/resolvers.js';

/* ---- replay cache --------------------------------------------------------------- */

/** A fake upstream that answers from a script of { status, body } | Error, one step per call. */
function upstream(script) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push(url);
    const step = script[Math.min(calls.length - 1, script.length - 1)];
    if (step instanceof Error) throw step;
    if (init.signal && init.signal.aborted) throw init.signal.reason;
    return new Response(step.body ?? '', { status: step.status, headers: { 'content-type': 'application/json' } });
  };
  return { fetchImpl, calls };
}

function withCacheDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'ds-replay-'));
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const URL_A = 'https://crt.sh/?q=example.net&output=json';

test('replay cache: isFinalAnswer — only 2xx data answers are final', () => {
  assert.equal(isFinalAnswer({ status: 200, body: '[{"name_value":"www.example.net"}]' }), true);
  assert.equal(isFinalAnswer({ status: 200, body: '["ratelimit.example.net"]' }), true, 'a JSON array is data even if a name looks like a notice');
  assert.equal(isFinalAnswer({ status: 204, body: '' }), true);
  assert.equal(isFinalAnswer({ status: 200, body: 'API count exceeded - Increase Quota with Membership' }), false, 'HackerTarget quota text');
  assert.equal(isFinalAnswer({ status: 200, body: '{"error":"rate limit exceeded"}' }), false, 'JSON error object');
  for (const status of [404, 429, 500, 502, 503]) assert.equal(isFinalAnswer({ status, body: '' }), false, `HTTP ${status}`);
  assert.equal(isFinalAnswer({ error: 'fetch failed' }), false);
  assert.equal(isFinalAnswer(null), false);
});

test('replay cache: a failed first attempt is not replayed to the retry; the retry goes live and its answer is cached', () => withCacheDir(async (dir) => {
  const up = upstream([{ status: 502, body: 'Bad Gateway' }, { status: 200, body: '[1,2]' }]);
  const cache = createReplayCache({ dir, fetchImpl: up.fetchImpl, replayDelay: false });
  const r1 = await cache.fetch(URL_A);
  assert.equal(r1.status, 502);
  assert.equal(existsSync(cache.fileFor(URL_A)), false, 'the failure is not written');
  const r2 = await cache.fetch(URL_A); // the source's retry
  assert.equal(r2.status, 200);
  assert.equal(await r2.text(), '[1,2]');
  assert.equal(up.calls.length, 2, 'the retry reached the network');
  // a later run replays the final answer without any network call
  const later = createReplayCache({ dir, fetchImpl: upstream([new Error('must not be called')]).fetchImpl, replayDelay: false });
  const r3 = await later.fetch(URL_A);
  assert.equal(r3.status, 200);
  assert.equal(await r3.text(), '[1,2]');
  assert.deepEqual([later.stats.live, later.stats.replayed], [0, 1]);
  assert.deepEqual([cache.stats.live, cache.stats.liveFailures, cache.stats.replayed], [2, 1, 0]);
}));

test('replay cache: network errors and quota notices are never frozen into later runs', () => withCacheDir(async (dir) => {
  const events = [];
  const up = upstream([new TypeError('fetch failed'), { status: 200, body: 'API count exceeded - Increase Quota with Membership' }, { status: 200, body: '[]' }]);
  const cache = createReplayCache({ dir, fetchImpl: up.fetchImpl, replayDelay: false, onEvent: (e) => events.push(e.kind) });
  await assert.rejects(cache.fetch(URL_A), TypeError);
  const quota = await cache.fetch(URL_A);
  assert.equal(await quota.text(), 'API count exceeded - Increase Quota with Membership', 'the caller still sees the notice');
  const ok = await cache.fetch(URL_A);
  assert.equal(await ok.text(), '[]');
  assert.equal(up.calls.length, 3);
  assert.deepEqual(events, ['live-failure', 'live-failure', 'live']);
}));

test('replay cache: a legacy file holding only a failure is ignored and replaced; --fresh never replays', () => withCacheDir(async (dir) => {
  const probe = createReplayCache({ dir, fetchImpl: upstream([{ status: 200, body: '[]' }]).fetchImpl, replayDelay: false });
  const file = probe.fileFor(URL_A);
  writeFileSync(file, JSON.stringify([{ status: 404, headers: {}, body: '<html>404 Not Found</html>', elapsedMs: 5 }]));
  const up = upstream([{ status: 200, body: '["a.example.net"]' }]);
  const cache = createReplayCache({ dir, fetchImpl: up.fetchImpl, replayDelay: false });
  const r = await cache.fetch(URL_A);
  assert.equal(await r.text(), '["a.example.net"]');
  assert.equal(up.calls.length, 1, 'went live instead of replaying the stale 404');
  assert.equal(cache.stats.staleIgnored, 1);
  const fresh = upstream([{ status: 200, body: '["b.example.net"]' }]);
  const freshCache = createReplayCache({ dir, fresh: true, fetchImpl: fresh.fetchImpl, replayDelay: false });
  assert.equal(await (await freshCache.fetch(URL_A)).text(), '["b.example.net"]');
  assert.equal(fresh.calls.length, 1, 'fresh = live');
  const replay = createReplayCache({ dir, fetchImpl: upstream([new Error('offline')]).fetchImpl, replayDelay: false });
  assert.equal(await (await replay.fetch(URL_A)).text(), '["b.example.net"]', 'fresh still recorded its final answer');
}));

test('replay cache: POST bodies are part of the key; a caller abort is rethrown and not recorded', () => withCacheDir(async (dir) => {
  const up = upstream([{ status: 200, body: '{"domains":[]}' }]);
  const cache = createReplayCache({ dir, fetchImpl: up.fetchImpl, replayDelay: false });
  const post = (page) => ({ method: 'POST', body: JSON.stringify({ domain: 'example.net', page_state: page }) });
  assert.notEqual(cache.fileFor('https://ip.thc.org/api/v1/lookup/subdomains', post('')), cache.fileFor('https://ip.thc.org/api/v1/lookup/subdomains', post('p2')));
  const ctl = new AbortController();
  const err = new Error('The operation was aborted');
  err.name = 'AbortError';
  ctl.abort(err);
  await assert.rejects(cache.fetch(URL_A, { signal: ctl.signal }), { name: 'AbortError' });
  assert.equal(cache.stats.liveFailures, 0, 'an abort by the caller is not a source failure');
  assert.equal(existsSync(cache.fileFor(URL_A)), false);
}));

/* ---- live-script arguments --------------------------------------------------------- */

test('positionalArgs: option values are never taken as the domain', () => {
  const opts = ['--level', '--concurrency', '--pool'];
  assert.deepEqual(positionalArgs(['--pool', 'cloudflare,google,dnssb'], opts), []);
  assert.deepEqual(positionalArgs(['--level', 'small', '--pool', 'cloudflare,google'], opts), []);
  assert.deepEqual(positionalArgs(['example.com', '--pool', 'google'], opts), ['example.com']);
  assert.deepEqual(positionalArgs(['--level', 'smart', 'example.org', '--no-perms'], opts), ['example.org']);
  // index-based: a value equal to a positional elsewhere on the line is judged by its own position
  assert.deepEqual(positionalArgs(['example.com', '--pool', 'example.com'], opts), ['example.com']);
  assert.deepEqual(positionalArgs([], opts), []);
});

test('public fallback domains are global, well-known zones', () => {
  assert.deepEqual([...PUBLIC_FALLBACK_DOMAINS], ['github.com', 'cloudflare.com', 'wikipedia.org']);
  assert.ok(Object.isFrozen(PUBLIC_FALLBACK_DOMAINS));
});

/* ---- run-all.mjs --------------------------------------------------------------------- */

test('run-all: options, suite order and PASS/FAIL counting', () => {
  const o = parseArgs(['--only', 'shell,scan.e2e.mjs', '--timeout-min', '5', '--bail', '--headed']);
  assert.deepEqual(o, { only: ['shell', 'scan'], skip: [], timeoutMin: 5, bail: true, passThrough: ['--headed'] });
  const files = ['zeta.e2e.mjs', 'integration.e2e.mjs', 'scan.e2e.mjs', 'shell.e2e.mjs', 'cdp.mjs', 'run-all.mjs'];
  assert.deepEqual(orderSuites(files), ['shell', 'scan', 'integration', 'zeta']);
  assert.deepEqual(orderSuites(files, { skip: ['scan'] }), ['shell', 'integration', 'zeta']);
  assert.deepEqual(countResults('  PASS  a\n  FAIL  b step\nnoise\n    PASS  c'), { pass: 2, fail: 1, failed: ['b step'] });
});

test('run-all: leftover browser profiles are matched per suite process only', () => {
  const entries = ['.profile-123-1', '.profile-123-12', '.profile-1234-1', '.profile-123-x', '.profile-12-3', 'screenshots', 'cdp.mjs'];
  assert.deepEqual(profileDirsOf(entries, 123), ['.profile-123-1', '.profile-123-12']);
  assert.deepEqual(profileDirsOf(entries, 99), []);
});

/* ---- cdp.mjs ------------------------------------------------------------------------- */

test('cdp: killLaunchedBrowsers kills a registered browser process and removes its profile', async () => {
  const profile = mkdtempSync(join(tmpdir(), 'ds-profile-'));
  mkdirSync(join(profile, 'Default'), { recursive: true });
  writeFileSync(join(profile, 'Default', 'Preferences'), '{}');
  // stand-in for a headless browser: a process that would otherwise run for a minute
  const proc = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'ignore' });
  const exited = new Promise((resolve) => proc.once('exit', () => resolve(true)));
  registerBrowserProcess(proc, profile);
  assert.equal(killLaunchedBrowsers(), 1);
  assert.equal(await Promise.race([exited, new Promise((r) => setTimeout(() => r(false), 10000))]), true, 'process was killed');
  assert.equal(existsSync(profile), false, 'profile removed');
  assert.equal(killLaunchedBrowsers(), 0, 'registry emptied');
  if (existsSync(profile)) rmSync(profile, { recursive: true, force: true });
});

test('cdp: resolverProblemFilter — optional resolvers tolerated, default-chain HTTP/CORS failures are issues', () => {
  const resolvers = [
    { id: 'a', url: 'https://doh-a.example/dns-query', browserReliable: true },
    { id: 'b', url: 'https://doh-b.example/dns-query', browserReliable: true },
    { id: 'q', url: 'https://doh-q.example/dns-query', browserReliable: false },
    { id: 'x', url: 'https://doh-x.example/dns-query', browserReliable: true }
  ];
  const judge = resolverProblemFilter({ resolvers, defaultChain: ['a', 'b', 'q'], maxNetworkErrorsPerHost: 2 });
  assert.equal(judge('Failed to load resource: net::ERR_FAILED https://app.example/x.js'), null, 'not about a resolver');
  assert.equal(judge('status of 400 https://doh-x.example/dns-query?dns=AAAB').tolerated, true, 'not in the default chain');
  assert.equal(judge('net::ERR_FAILED https://doh-q.example/dns-query?dns=AAAB').tolerated, true, 'browserReliable:false');
  assert.equal(judge('Failed to load resource: the server responded with a status of 400 () https://doh-a.example/dns-query?dns=AA').tolerated, false);
  assert.equal(judge("Access to fetch at 'https://doh-b.example/dns-query?dns=AA' from origin 'http://127.0.0.1:8080' has been blocked by CORS policy").tolerated, false);
  assert.equal(judge('net::ERR_ABORTED https://doh-a.example/dns-query?dns=AA').tolerated, true, 'client-side cancel');
  const timeouts = [1, 2, 3].map(() => judge('net::ERR_TIMED_OUT https://doh-a.example/dns-query?dns=AA'));
  assert.deepEqual(timeouts.map((v) => v.tolerated), [true, true, false], 'network failures capped per host');
  assert.equal(judge('net::ERR_CONNECTION_RESET https://doh-b.example/dns-query?dns=AA').tolerated, true, 'the cap is per host');
  assert.equal(judge('something odd https://doh-b.example/dns-query').tolerated, false, 'unknown failures of a default-chain resolver are issues');
});

test('cdp: with the shipped resolver list, every DEFAULT_CHAIN host is strict and the rest are tolerated', () => {
  const judge = resolverProblemFilter({ resolvers: RESOLVERS, defaultChain: DEFAULT_CHAIN });
  for (const r of RESOLVERS) {
    const host = new URL(r.url).hostname;
    const v = judge(`Failed to load resource: the server responded with a status of 400 () https://${host}/dns-query?dns=AA`);
    assert.ok(v, `${r.id} recognised`);
    const strict = DEFAULT_CHAIN.includes(r.id) && r.browserReliable !== false;
    assert.equal(v.tolerated, !strict, `${r.id}: ${v.reason}`);
  }
});

test('cdp: press() sends no native key code, so Chrome on macOS does not also act on a key the page leaves alone', async () => {
  // With nativeVirtualKeyCode set, an unhandled Escape, arrow, Home, End or Backspace made Chrome on macOS
  // open chrome://settings/help in front of the page under test, which hid it (no rAF, throttled timers).
  const sent = [];
  const conn = { send: async (method, params, sessionId) => { sent.push({ method, params, sessionId }); return {}; } };
  const page = new Page(conn, 'target-1', 'session-1', {});
  const keys = ['Escape', 'ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight', 'Home', 'End', 'Backspace', 'Tab', 'Enter', 'Space', 'a'];
  for (const key of keys) await page.press(key);
  await page.press('Enter', { ctrl: true });
  assert.equal(sent.length, 2 * (keys.length + 1));
  for (const { method, params, sessionId } of sent) {
    assert.equal(method, 'Input.dispatchKeyEvent');
    assert.equal(sessionId, 'session-1');
    assert.equal('nativeVirtualKeyCode' in params, false, `${params.type} ${params.key}`);
  }
  // the page still gets the same key, code and (Windows) key code
  const brief = ({ params: p }) => [p.type, p.key, p.code, p.windowsVirtualKeyCode, p.text, p.modifiers];
  assert.deepEqual(sent.slice(0, 2).map(brief), [['rawKeyDown', 'Escape', 'Escape', 27, undefined, 0], ['keyUp', 'Escape', 'Escape', 27, undefined, 0]]);
  assert.deepEqual(brief(sent.at(-2)), ['keyDown', 'Enter', 'Enter', 13, '\r', 2]);
  assert.deepEqual(brief(sent.at(-4)), ['keyDown', 'a', 'KeyA', 65, 'a', 0]);
});

test('cdp: launchBrowser gives the page language as --lang and as --accept-lang (Chrome on macOS ignores --lang)', { skip: process.platform === 'win32' && 'the stand-in browser is a POSIX shell script' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ds-browser-'));
  const argsFile = join(dir, 'args.txt');
  const exe = join(dir, 'fake-chrome');
  // stand-in for a browser that writes its command line and refuses to start
  writeFileSync(exe, `#!/bin/sh\nprintf '%s\\n' "$@" > '${argsFile}'\nexit 3\n`, { mode: 0o755 });
  try {
    await assert.rejects(launchBrowser({ executablePath: exe, profileRoot: dir, timeout: 10000 }), /exited early \(code 3\)/);
    let args = readFileSync(argsFile, 'utf8').split('\n');
    assert.ok(args.includes('--lang=en-US'), args.join(' '));
    assert.ok(args.includes('--accept-lang=en-US'), 'navigator.languages follows --accept-lang on every OS');
    await assert.rejects(launchBrowser({ executablePath: exe, profileRoot: dir, timeout: 10000, lang: 'tr-TR' }), /exited early/);
    args = readFileSync(argsFile, 'utf8').split('\n');
    assert.deepEqual(args.filter((a) => /^--(accept-)?lang=/.test(a)), ['--lang=tr-TR', '--accept-lang=tr-TR']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
