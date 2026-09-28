import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AbortError, TimeoutError, HttpError, RateLimitError, ParseError,
  sleep, createLimiter, fetchWithTimeout, fetchAndRead, fetchJson, fetchText, retry,
  defaultShouldRetry, errorKind, uniq, chunk, randomLabel, createCache,
  mergeSignals, splitList, parseRetryAfter, throwIfAborted, abortReasonToError, onceAsync, sharePercent
} from '../../assets/js/lib/util.js';

/** A Response-like object for the fetch mocks (no real network). */
function mockResponse(body, { status = 200, statusText = '', headers = {}, url = 'https://x/' } = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    url,
    headers: { get: (k) => (k.toLowerCase() in lower ? lower[k.toLowerCase()] : null) },
    async text() { return typeof body === 'string' ? body : JSON.stringify(body); }
  };
}

/* -------------------------------------------------------------------- */
/* Errors                                                               */
/* -------------------------------------------------------------------- */

test('error classes carry names and fields', () => {
  assert.equal(new AbortError().name, 'AbortError');
  assert.equal(new TimeoutError().name, 'TimeoutError');
  const h = new HttpError(429, 'https://x', 'body', { statusText: 'Too Many', retryAfterMs: 2000 });
  assert.equal(h.name, 'HttpError');
  assert.equal(h.status, 429);
  assert.equal(h.url, 'https://x');
  assert.equal(h.body, 'body');
  assert.equal(h.retryAfterMs, 2000);
  assert.equal(new HttpError(500, 'u', 'x'.repeat(999)).body.length, 500);
  assert.equal(new HttpError(500, 'u', '', { retryAfterMs: -5 }).retryAfterMs, null);
  assert.ok(new ParseError() instanceof SyntaxError);
});

/* -------------------------------------------------------------------- */
/* sleep                                                                */
/* -------------------------------------------------------------------- */

test('sleep resolves after the delay', async () => {
  const t = Date.now();
  await sleep(20);
  assert.ok(Date.now() - t >= 15);
});

test('sleep rejects immediately when the signal is already aborted', async () => {
  const ctl = new AbortController();
  ctl.abort();
  await assert.rejects(sleep(1000, ctl.signal), (e) => e.name === 'AbortError');
});

test('sleep rejects when aborted mid-flight and clears its timer', async () => {
  const ctl = new AbortController();
  const p = sleep(1000, ctl.signal);
  setTimeout(() => ctl.abort(), 5);
  await assert.rejects(p, (e) => e.name === 'AbortError');
});

test('sleep surfaces a timeout reason as TimeoutError', async () => {
  const ctl = new AbortController();
  const p = sleep(1000, ctl.signal);
  ctl.abort(new TimeoutError('nope'));
  await assert.rejects(p, (e) => e.name === 'TimeoutError');
});

/* -------------------------------------------------------------------- */
/* createLimiter                                                        */
/* -------------------------------------------------------------------- */

test('limiter never exceeds its concurrency and runs everything', async () => {
  const limiter = createLimiter(3);
  let active = 0;
  let peak = 0;
  const results = await Promise.all(
    Array.from({ length: 30 }, (_, i) => limiter.run(async () => {
      active += 1;
      peak = Math.max(peak, active);
      await sleep(5);
      active -= 1;
      return i;
    }))
  );
  assert.equal(peak, 3);
  assert.deepEqual(results, Array.from({ length: 30 }, (_, i) => i));
  assert.equal(limiter.active, 0);
  assert.equal(limiter.pending, 0);
});

test('limiter preserves FIFO start order', async () => {
  const limiter = createLimiter(1);
  const order = [];
  const jobs = [];
  for (let i = 0; i < 6; i += 1) jobs.push(limiter.run(async () => { order.push(i); await sleep(1); }));
  await Promise.all(jobs);
  assert.deepEqual(order, [0, 1, 2, 3, 4, 5]);
});

test('limiter keeps flowing after a task throws', async () => {
  const limiter = createLimiter(2);
  const outcomes = await Promise.allSettled([
    limiter.run(() => { throw new Error('sync'); }),
    limiter.run(() => Promise.reject(new Error('async'))),
    limiter.run(() => 'ok'),
    limiter.run(async () => { await sleep(2); return 'later'; })
  ]);
  assert.deepEqual(outcomes.map((o) => o.status), ['rejected', 'rejected', 'fulfilled', 'fulfilled']);
  assert.equal(outcomes[2].value, 'ok');
  assert.equal(limiter.active, 0);
});

test('limiter reports pending accurately and clear() rejects the queue', async () => {
  const limiter = createLimiter(1);
  let release;
  const gate = new Promise((r) => { release = r; });
  const running = limiter.run(() => gate);
  const queued = [limiter.run(() => 1), limiter.run(() => 2)];
  assert.equal(limiter.active, 1);
  assert.equal(limiter.pending, 2);
  const cleared = limiter.clear();
  assert.equal(cleared, 2);
  await Promise.all(queued.map((p) => assert.rejects(p, (e) => e.name === 'AbortError')));
  release('done');
  assert.equal(await running, 'done');
});

test('limiter.run rejects a queued task when its own signal aborts (queue keeps flowing)', async () => {
  const limiter = createLimiter(1);
  let release;
  const gate = new Promise((r) => { release = r; });
  const running = limiter.run(() => gate);
  const ctl = new AbortController();
  const cancellable = limiter.run(() => 'never', { signal: ctl.signal });
  const after = limiter.run(() => 'after');
  ctl.abort();
  await assert.rejects(cancellable, (e) => e.name === 'AbortError');
  release('x');
  assert.equal(await running, 'x');
  assert.equal(await after, 'after');
});

test('limiter setConcurrency raises the ceiling immediately', async () => {
  const limiter = createLimiter(1);
  let active = 0;
  let peak = 0;
  const jobs = Array.from({ length: 10 }, () => limiter.run(async () => {
    active += 1; peak = Math.max(peak, active); await sleep(10); active -= 1;
  }));
  limiter.setConcurrency(5);
  await Promise.all(jobs);
  assert.equal(peak, 5);
});

test('limiter.run rejects non-functions', async () => {
  const limiter = createLimiter(2);
  await assert.rejects(limiter.run(42), (e) => e instanceof TypeError);
});

/* -------------------------------------------------------------------- */
/* fetchWithTimeout / fetchJson / fetchText                             */
/* -------------------------------------------------------------------- */

test('fetchWithTimeout returns the response and passes through init + signal', async () => {
  let seen;
  const fetchImpl = async (url, init) => { seen = { url, init }; return mockResponse('hi'); };
  const res = await fetchWithTimeout('https://x/', { fetchImpl, method: 'POST', headers: { a: '1' } });
  assert.equal(await res.text(), 'hi');
  assert.equal(seen.init.method, 'POST');
  assert.ok(seen.init.signal instanceof AbortSignal);
});

test('fetchWithTimeout throws TimeoutError and aborts the underlying request', async () => {
  let innerAborted = false;
  const fetchImpl = (url, { signal }) => new Promise((_, reject) => {
    signal.addEventListener('abort', () => { innerAborted = true; reject(abortReasonToError(signal.reason)); });
  });
  await assert.rejects(fetchWithTimeout('https://x/', { fetchImpl, timeoutMs: 10 }), (e) => e.name === 'TimeoutError');
  assert.equal(innerAborted, true);
});

test('fetchWithTimeout honours the caller signal over the timeout', async () => {
  const ctl = new AbortController();
  const fetchImpl = (url, { signal }) => new Promise((_, reject) => {
    signal.addEventListener('abort', () => reject(abortReasonToError(signal.reason)));
  });
  const p = fetchWithTimeout('https://x/', { fetchImpl, timeoutMs: 1000, signal: ctl.signal });
  ctl.abort();
  await assert.rejects(p, (e) => e.name === 'AbortError');
});

test('fetchWithTimeout rejects a pre-aborted caller signal without calling fetch', async () => {
  const ctl = new AbortController();
  ctl.abort();
  let called = false;
  await assert.rejects(
    fetchWithTimeout('https://x/', { fetchImpl: () => { called = true; return mockResponse('x'); }, signal: ctl.signal }),
    (e) => e.name === 'AbortError'
  );
  assert.equal(called, false);
});

test('fetchWithTimeout wraps a missing fetch as TypeError', async () => {
  await assert.rejects(fetchWithTimeout('https://x/', { fetchImpl: undefined }), (e) => e instanceof TypeError);
});

test('fetchAndRead: read() gets any status, and the timeout covers a body that stalls after the headers', async () => {
  const out = await fetchAndRead('https://x/', { fetchImpl: async () => mockResponse('slow down', { status: 429 }) },
    async (res) => [res.status, await res.text()]);
  assert.deepEqual(out, [429, 'slow down']);
  const stalled = { ...mockResponse(''), text: () => new Promise(() => {}) }; // headers arrived, body never ends
  await assert.rejects(fetchAndRead('https://x/', { fetchImpl: async () => stalled, timeoutMs: 20 }, (res) => res.text()),
    (e) => e.name === 'TimeoutError');
  await assert.rejects(fetchAndRead('https://x/', { fetchImpl: async () => stalled }, null), TypeError);
});

test('fetchJson parses, and maps non-2xx to HttpError with Retry-After', async () => {
  const ok = await fetchJson('https://x/', { fetchImpl: async () => mockResponse({ a: 1 }) });
  assert.deepEqual(ok, { a: 1 });
  await assert.rejects(
    fetchJson('https://x/', { fetchImpl: async () => mockResponse('nope', { status: 429, headers: { 'Retry-After': '3' } }) }),
    (e) => e instanceof HttpError && e.status === 429 && e.retryAfterMs === 3000
  );
});

test('fetchJson raises ParseError on invalid JSON and returns null for 204', async () => {
  await assert.rejects(
    fetchJson('https://x/', { fetchImpl: async () => mockResponse('not json') }),
    (e) => e instanceof ParseError
  );
  assert.equal(await fetchJson('https://x/', { fetchImpl: async () => mockResponse('', { status: 204 }) }), null);
});

test('fetchText returns the body and maps non-2xx to HttpError', async () => {
  assert.equal(await fetchText('https://x/', { fetchImpl: async () => mockResponse('plain') }), 'plain');
  await assert.rejects(
    fetchText('https://x/', { fetchImpl: async () => mockResponse('boom', { status: 500 }) }),
    (e) => e instanceof HttpError && e.status === 500
  );
});

/* -------------------------------------------------------------------- */
/* retry                                                                */
/* -------------------------------------------------------------------- */

test('retry succeeds after transient failures', async () => {
  let n = 0;
  const value = await retry(async () => { n += 1; if (n < 3) throw new TimeoutError(); return 'ok'; },
    { retries: 5, baseDelayMs: 1, maxDelayMs: 5 });
  assert.equal(value, 'ok');
  assert.equal(n, 3);
});

test('retry gives up after exhausting attempts and rethrows the last error', async () => {
  let n = 0;
  await assert.rejects(
    retry(async () => { n += 1; throw new HttpError(503, 'u', ''); }, { retries: 2, baseDelayMs: 1, maxDelayMs: 2 }),
    (e) => e instanceof HttpError && e.status === 503
  );
  assert.equal(n, 3); // initial + 2 retries
});

test('retry never retries AbortError', async () => {
  let n = 0;
  await assert.rejects(
    retry(async () => { n += 1; throw new AbortError(); }, { retries: 5, baseDelayMs: 1 }),
    (e) => e.name === 'AbortError'
  );
  assert.equal(n, 1);
});

test('retry does not retry non-retryable errors', async () => {
  let n = 0;
  await assert.rejects(
    retry(async () => { n += 1; throw new HttpError(404, 'u', ''); }, { retries: 5, baseDelayMs: 1 }),
    (e) => e.status === 404
  );
  assert.equal(n, 1);
});

test('retry honours Retry-After exactly and bails when it exceeds the cap', async () => {
  let n = 0;
  const t = Date.now();
  await retry(async () => { n += 1; if (n < 2) throw new HttpError(429, 'u', '', { retryAfterMs: 30 }); },
    { retries: 3, baseDelayMs: 1, maxDelayMs: 1000 });
  assert.ok(Date.now() - t >= 25);

  n = 0;
  await assert.rejects(
    retry(async () => { n += 1; throw new HttpError(429, 'u', '', { retryAfterMs: 60000 }); },
      { retries: 3, baseDelayMs: 1, maxDelayMs: 5000 }),
    (e) => e.status === 429
  );
  assert.equal(n, 1); // did not wait 60s; bailed at once
});

test('retry stops once the signal aborts', async () => {
  const ctl = new AbortController();
  let n = 0;
  const p = retry(async () => { n += 1; if (n === 1) ctl.abort(); throw new TimeoutError(); },
    { retries: 5, baseDelayMs: 1, signal: ctl.signal });
  await assert.rejects(p, (e) => e.name === 'TimeoutError' || e.name === 'AbortError');
  assert.equal(n, 1);
});

/* -------------------------------------------------------------------- */
/* defaultShouldRetry / errorKind                                       */
/* -------------------------------------------------------------------- */

test('defaultShouldRetry policy', () => {
  assert.equal(defaultShouldRetry(new TimeoutError()), true);
  assert.equal(defaultShouldRetry(new HttpError(429, 'u', '')), true);
  assert.equal(defaultShouldRetry(new HttpError(503, 'u', '')), true);
  assert.equal(defaultShouldRetry(new HttpError(404, 'u', '')), false);
  assert.equal(defaultShouldRetry(new TypeError('fetch failed')), true);
  assert.equal(defaultShouldRetry(new AbortError()), false);
  assert.equal(defaultShouldRetry(new ParseError()), false);
  assert.equal(defaultShouldRetry({ retryable: true }), true);
});

test('errorKind classification', () => {
  assert.equal(errorKind(new AbortError()), 'abort');
  assert.equal(errorKind(new TimeoutError()), 'timeout');
  assert.equal(errorKind(new RateLimitError()), 'rate-limit');
  assert.equal(errorKind(new HttpError(429, 'u', '')), 'rate-limit');
  assert.equal(errorKind(new HttpError(500, 'u', '')), 'http');
  assert.equal(errorKind(new TypeError('fetch failed')), 'network');
  assert.equal(errorKind(new ParseError()), 'parse');
  assert.equal(errorKind(new SyntaxError('bad')), 'parse');
  assert.equal(errorKind({ kind: 'timeout' }), 'timeout');
  assert.equal(errorKind(null), 'unknown');
  assert.equal(errorKind(new Error('x')), 'unknown');
});

/* -------------------------------------------------------------------- */
/* uniq / chunk / randomLabel / splitList / parseRetryAfter             */
/* -------------------------------------------------------------------- */

test('uniq preserves first-seen order', () => {
  assert.deepEqual(uniq([3, 1, 3, 2, 1]), [3, 1, 2]);
  assert.deepEqual(uniq(null), []);
  assert.deepEqual(uniq(new Set(['a', 'b'])), ['a', 'b']);
});

test('chunk splits and validates size', () => {
  assert.deepEqual(chunk([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
  assert.deepEqual(chunk([], 3), []);
  assert.throws(() => chunk([1], 0), RangeError);
});

test('sharePercent: one decimal, never 100 or 0 unless it is exactly that', () => {
  assert.equal(sharePercent(0.9487), 94.9);
  assert.equal(sharePercent(0.95), 95);
  assert.equal(sharePercent(1), 100);
  assert.equal(sharePercent(0), 0);
  assert.equal(sharePercent(0.99996), 99.9, 'almost all is not all');
  assert.equal(sharePercent(0.00004), 0.1, 'a few is not none');
  assert.equal(sharePercent(Number.NaN), 0);
});

test('randomLabel yields lowercase alphanumerics of the requested length', () => {
  for (const len of [1, 12, 30]) {
    const s = randomLabel(len);
    assert.equal(s.length, len);
    assert.match(s, /^[a-z0-9]+$/);
  }
  // Distribution sanity: two calls should almost never collide.
  assert.notEqual(randomLabel(16), randomLabel(16));
});

test('randomLabel works without WebCrypto (Math.random fallback)', () => {
  const s = randomLabel(10, { crypto: null });
  assert.match(s, /^[a-z0-9]{10}$/);
});

test('splitList splits on separators and drops comments', () => {
  assert.deepEqual(splitList('a b,c;d\ne'), ['a', 'b', 'c', 'd', 'e']);
  assert.deepEqual(splitList('# comment\nkeep\n  # indented\nx y'), ['keep', 'x', 'y']);
  assert.deepEqual(splitList('host # inline'), ['host']);
  assert.deepEqual(splitList('https://x/#frag'), ['https://x/#frag']);
  assert.deepEqual(splitList(['a', 'b c']), ['a', 'b', 'c']);
  assert.deepEqual(splitList(null), []);
});

test('parseRetryAfter handles seconds and HTTP-dates', () => {
  assert.equal(parseRetryAfter('5'), 5000);
  assert.equal(parseRetryAfter('  0 '), 0);
  assert.equal(parseRetryAfter(null), null);
  assert.equal(parseRetryAfter('garbage'), null);
  const now = Date.UTC(2026, 0, 1, 0, 0, 0);
  assert.equal(parseRetryAfter(new Date(now + 10000).toUTCString(), now), 10000);
});

/* -------------------------------------------------------------------- */
/* createCache                                                          */
/* -------------------------------------------------------------------- */

test('createCache is bounded and LRU', () => {
  const cache = createCache({ maxEntries: 3 });
  cache.set('a', 1); cache.set('b', 2); cache.set('c', 3);
  assert.equal(cache.get('a'), 1); // 'a' now most-recent
  cache.set('d', 4); // evicts LRU = 'b'
  assert.equal(cache.has('b'), false);
  assert.equal(cache.has('a'), true);
  assert.equal(cache.get('d'), 4);
  assert.equal(cache.size, 3);
  cache.delete('a');
  assert.equal(cache.has('a'), false);
  cache.clear();
  assert.equal(cache.size, 0);
});

test('createCache honours TTL', () => {
  let now = 1000;
  const cache = createCache({ maxEntries: 10, ttlMs: 100, now: () => now });
  cache.set('a', 1);
  assert.equal(cache.get('a'), 1);
  now += 150;
  assert.equal(cache.get('a'), undefined);
  assert.equal(cache.has('a'), false);
});

/* -------------------------------------------------------------------- */
/* mergeSignals / throwIfAborted                                        */
/* -------------------------------------------------------------------- */

test('mergeSignals aborts when any input aborts, with its reason', () => {
  const a = new AbortController();
  const b = new AbortController();
  const merged = mergeSignals(a.signal, null, b.signal);
  assert.equal(merged.aborted, false);
  b.abort(new TimeoutError('t'));
  assert.equal(merged.aborted, true);
  assert.equal(merged.reason.name, 'TimeoutError');
});

test('mergeSignals returns an already-aborted signal when an input is aborted', () => {
  const a = new AbortController();
  a.abort(new Error('pre'));
  const merged = mergeSignals(a.signal, new AbortController().signal);
  assert.equal(merged.aborted, true);
});

test('mergeSignals with no real signals yields a non-aborted signal', () => {
  const merged = mergeSignals(null, undefined);
  assert.equal(merged.aborted, false);
});

test('throwIfAborted throws the mapped reason', () => {
  const ctl = new AbortController();
  assert.doesNotThrow(() => throwIfAborted(ctl.signal));
  ctl.abort();
  assert.throws(() => throwIfAborted(ctl.signal), (e) => e.name === 'AbortError');
});

test('onceAsync shares one load while pending and after it resolved', async () => {
  let calls = 0;
  let release;
  const load = onceAsync(() => {
    calls += 1;
    return new Promise((resolve) => { release = resolve; });
  });
  const a = load();
  const b = load();
  assert.equal(a, b, 'the same promise while pending');
  await Promise.resolve(); // the loader runs on the next microtask
  release({ ready: true });
  assert.deepEqual(await a, { ready: true });
  assert.equal(await load(), await a);
  assert.equal(calls, 1);
});

test('onceAsync forgets a failed load (sync throw or rejection) so the next call retries', async () => {
  let calls = 0;
  const load = onceAsync(() => {
    calls += 1;
    if (calls === 1) throw new TypeError('Failed to fetch dynamically imported module');
    if (calls === 2) return Promise.reject(new TypeError('offline'));
    return 'module';
  });
  await assert.rejects(load(), /dynamically imported/);
  await assert.rejects(load(), /offline/);
  assert.equal(await load(), 'module');
  assert.equal(await load(), 'module');
  assert.equal(calls, 3);
});
