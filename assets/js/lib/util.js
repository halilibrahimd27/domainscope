/**
 * util.js — small, dependency-free helpers shared by every library module.
 *
 * DOM-free: runs unchanged in browsers and Node 22. Network helpers take an
 * injectable `fetchImpl` so they can be unit-tested with mocks.
 */

/* ------------------------------------------------------------------------ */
/* Error types                                                              */
/* ------------------------------------------------------------------------ */

/** Raised when an operation is cancelled through an AbortSignal. */
export class AbortError extends Error {
  /**
   * @param {string} [message]
   * @param {{ cause?: unknown }} [options]
   */
  constructor(message = 'The operation was aborted', options) {
    super(message, options);
    this.name = 'AbortError';
  }
}

/** Raised when an operation exceeds its time budget. */
export class TimeoutError extends Error {
  /**
   * @param {string} [message]
   * @param {{ cause?: unknown, timeoutMs?: number }} [options]
   */
  constructor(message = 'The operation timed out', options = {}) {
    super(message, options);
    this.name = 'TimeoutError';
    /** @type {number|null} */
    this.timeoutMs = Number.isFinite(options?.timeoutMs) ? options.timeoutMs : null;
  }
}

/** Raised for non-2xx HTTP responses by {@link fetchJson} / {@link fetchText}. */
export class HttpError extends Error {
  /**
   * @param {number} status HTTP status code.
   * @param {string} url Request URL.
   * @param {string} [body] Response body (truncated to 500 chars).
   * @param {{ statusText?: string, retryAfterMs?: number|null, cause?: unknown }} [options]
   */
  constructor(status, url, body = '', { statusText = '', retryAfterMs = null, cause } = {}) {
    super(`HTTP ${status}${statusText ? ` ${statusText}` : ''}`, cause === undefined ? undefined : { cause });
    this.name = 'HttpError';
    /** @type {number} */
    this.status = status;
    /** @type {string} */
    this.url = String(url ?? '');
    /** @type {string} First 500 characters of the response body. */
    this.body = String(body ?? '').slice(0, 500);
    /** @type {string} */
    this.statusText = statusText;
    /** @type {number|null} Parsed `Retry-After` header in ms (null when absent/invalid). */
    this.retryAfterMs = Number.isFinite(retryAfterMs) && retryAfterMs >= 0 ? retryAfterMs : null;
  }
}

/**
 * Raised when a service signals quota exhaustion inside a successful response
 * (e.g. HackerTarget's `API count exceeded` 200 text). Classified as
 * 'rate-limit' by {@link errorKind} and NOT retried by {@link defaultShouldRetry}
 * (daily quotas do not recover within a retry window).
 */
export class RateLimitError extends Error {
  /**
   * @param {string} [message]
   * @param {{ retryAfterMs?: number|null, cause?: unknown }} [options]
   */
  constructor(message = 'Rate limit exceeded', { retryAfterMs = null, cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'RateLimitError';
    /** @type {number|null} */
    this.retryAfterMs = Number.isFinite(retryAfterMs) && retryAfterMs >= 0 ? retryAfterMs : null;
  }
}

/** Raised when a response body cannot be parsed (invalid JSON etc.). */
export class ParseError extends SyntaxError {
  /**
   * @param {string} [message]
   * @param {{ cause?: unknown, body?: string }} [options]
   */
  constructor(message = 'Could not parse response', { cause, body = '' } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'ParseError';
    /** @type {string} First 500 characters of the offending input. */
    this.body = String(body ?? '').slice(0, 500);
  }
}

/* ------------------------------------------------------------------------ */
/* Abort helpers                                                            */
/* ------------------------------------------------------------------------ */

/**
 * Convert an AbortSignal reason into one of our error classes.
 * A reason named 'TimeoutError' (our own or the DOMException produced by
 * `AbortSignal.timeout()`) becomes a {@link TimeoutError}; anything else an
 * {@link AbortError}.
 * @param {unknown} reason
 * @returns {AbortError|TimeoutError}
 */
export function abortReasonToError(reason) {
  if (reason instanceof AbortError || reason instanceof TimeoutError) return reason;
  const name = reason && typeof reason === 'object' ? reason.name : undefined;
  const message = reason && typeof reason === 'object' && typeof reason.message === 'string' && reason.message
    ? reason.message : undefined;
  if (name === 'TimeoutError') return new TimeoutError(message, { cause: reason });
  return new AbortError(message, reason === undefined ? undefined : { cause: reason });
}

/**
 * Throw (AbortError/TimeoutError) if the signal is already aborted.
 * @param {AbortSignal|null|undefined} signal
 */
export function throwIfAborted(signal) {
  if (signal && signal.aborted) throw abortReasonToError(signal.reason);
}

function isAbortLike(err) {
  return !!err && typeof err === 'object' && err.name === 'AbortError';
}

/**
 * Link several signals into one. Returns the combined signal plus a dispose()
 * that removes listeners installed by the manual fallback (no-op otherwise).
 * @param {Array<AbortSignal|null|undefined>} list
 * @returns {{ signal: AbortSignal, dispose: () => void }}
 */
function linkSignals(list) {
  const signals = list.flat(Infinity).filter((s) => s && typeof s.aborted === 'boolean');
  const noop = () => {};
  if (signals.length === 0) return { signal: new AbortController().signal, dispose: noop };
  if (signals.length === 1) return { signal: signals[0], dispose: noop };
  const already = signals.find((s) => s.aborted);
  if (already) {
    const ctl = new AbortController();
    ctl.abort(already.reason);
    return { signal: ctl.signal, dispose: noop };
  }
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
    return { signal: AbortSignal.any(signals), dispose: noop };
  }
  // Manual fallback for engines without AbortSignal.any (Safari < 17.4 etc.).
  const ctl = new AbortController();
  const listeners = [];
  const dispose = () => {
    for (const [s, fn] of listeners) s.removeEventListener('abort', fn);
    listeners.length = 0;
  };
  for (const s of signals) {
    const onAbort = () => {
      dispose();
      ctl.abort(s.reason);
    };
    listeners.push([s, onAbort]);
    s.addEventListener('abort', onAbort, { once: true });
  }
  return { signal: ctl.signal, dispose };
}

/**
 * Combine signals: the result aborts as soon as any input aborts (with that
 * input's reason). null/undefined entries are ignored; arrays are flattened.
 * Uses `AbortSignal.any` when available, otherwise a listener-based fallback.
 * @param {...(AbortSignal|null|undefined|Array<AbortSignal|null|undefined>)} signals
 * @returns {AbortSignal}
 */
export function mergeSignals(...signals) {
  return linkSignals(signals).signal;
}

/**
 * Promise that rejects (AbortError/TimeoutError) when `signal` aborts, used to
 * race work that may ignore signals (e.g. a mocked fetch).
 * @returns {{ promise: Promise<never>, dispose: () => void }}
 */
function abortPromise(signal) {
  let onAbort = null;
  const promise = new Promise((_, reject) => {
    onAbort = () => reject(abortReasonToError(signal.reason));
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  });
  promise.catch(() => {}); // never an unhandled rejection
  return { promise, dispose: () => signal.removeEventListener('abort', onAbort) };
}

/* ------------------------------------------------------------------------ */
/* Timing                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * Wait `ms` milliseconds. Rejects with AbortError when `signal` aborts (or a
 * TimeoutError when the signal's reason is a timeout).
 * @param {number} ms
 * @param {AbortSignal} [signal]
 * @returns {Promise<void>}
 */
export function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortReasonToError(signal.reason));
      return;
    }
    const delay = Number.isFinite(ms) && ms > 0 ? ms : 0;
    let timer = null;
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortReasonToError(signal.reason));
    };
    timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, delay);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/* ------------------------------------------------------------------------ */
/* Concurrency limiter                                                      */
/* ------------------------------------------------------------------------ */

function sanitizeConcurrency(n) {
  if (n === Infinity) return Infinity;
  const v = Math.floor(Number(n));
  return Number.isFinite(v) && v >= 1 ? v : 1;
}

/**
 * FIFO concurrency limiter.
 *
 * - `run(fn, { signal })` queues `fn` (sync or async) and resolves/rejects with
 *   its result. A thrown/rejected task never blocks the queue.
 * - An optional `signal` removes a still-queued task (rejecting AbortError);
 *   tasks already running are not interrupted (pass the signal to them too).
 * - `setConcurrency(n)` takes effect immediately for queued work; lowering it
 *   lets running tasks finish.
 * - `clear(reason?)` rejects every queued (not yet started) task with
 *   AbortError (or `reason` when it is an Error) and returns how many.
 *
 * @param {number} [concurrency=4] Positive integer (or Infinity).
 * @returns {{ run: <T>(fn: () => T|Promise<T>, opts?: { signal?: AbortSignal }) => Promise<T>,
 *   setConcurrency: (n: number) => void, readonly active: number, readonly pending: number,
 *   readonly concurrency: number, clear: (reason?: unknown) => number }}
 */
export function createLimiter(concurrency = 4) {
  let limit = sanitizeConcurrency(concurrency);
  let active = 0;
  let waiting = 0; // queued jobs that are still live (not aborted/cleared)
  // Array + head index: O(1) dequeue even with tens of thousands of jobs.
  let queue = [];
  let head = 0;

  function dequeue() {
    const job = queue[head];
    queue[head] = undefined;
    head += 1;
    if (head > 1024 && head * 2 > queue.length) {
      queue = queue.slice(head);
      head = 0;
    }
    return job;
  }

  function pump() {
    while (active < limit && head < queue.length) {
      const job = dequeue();
      if (!job || job.settled) continue; // removed by abort / clear
      start(job);
    }
  }

  function start(job) {
    job.settled = true;
    job.detach();
    waiting -= 1;
    active += 1;
    let result;
    try {
      result = Promise.resolve(job.fn());
    } catch (err) {
      result = Promise.reject(err);
    }
    // Free the slot *before* settling so `active` is accurate inside callers'
    // continuations and the next job starts in FIFO order.
    result.then(
      (value) => { active -= 1; pump(); job.resolve(value); },
      (err) => { active -= 1; pump(); job.reject(err); }
    );
  }

  return {
    run(fn, { signal } = {}) {
      return new Promise((resolve, reject) => {
        if (typeof fn !== 'function') {
          reject(new TypeError('limiter.run expects a function'));
          return;
        }
        if (signal?.aborted) {
          reject(abortReasonToError(signal.reason));
          return;
        }
        const job = { fn, resolve, reject, settled: false, detach: () => {} };
        if (signal) {
          const onAbort = () => {
            if (job.settled) return;
            job.settled = true; // stays in the array; skipped by pump()
            waiting -= 1;
            reject(abortReasonToError(signal.reason));
          };
          signal.addEventListener('abort', onAbort, { once: true });
          job.detach = () => signal.removeEventListener('abort', onAbort);
        }
        queue.push(job);
        waiting += 1;
        pump();
      });
    },
    setConcurrency(n) {
      limit = sanitizeConcurrency(n);
      pump();
    },
    get active() {
      return active;
    },
    get pending() {
      return waiting;
    },
    get concurrency() {
      return limit;
    },
    clear(reason) {
      const err = reason instanceof Error ? reason : new AbortError(reason ? String(reason) : 'Limiter queue cleared');
      const jobs = queue.slice(head);
      queue = [];
      head = 0;
      let cleared = 0;
      for (const job of jobs) {
        if (job && !job.settled) {
          job.settled = true;
          job.detach();
          job.reject(err);
          cleared += 1;
        }
      }
      waiting = 0;
      return cleared;
    }
  };
}

/* ------------------------------------------------------------------------ */
/* HTTP                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Parse a `Retry-After` header (delta-seconds or HTTP-date) into milliseconds.
 * @param {string|null|undefined} value
 * @param {number} [now=Date.now()]
 * @returns {number|null}
 */
export function parseRetryAfter(value, now = Date.now()) {
  if (value === null || value === undefined) return null;
  const s = String(value).trim();
  if (!s) return null;
  if (/^\d+(\.\d+)?$/.test(s)) return Math.round(Number(s) * 1000);
  const t = Date.parse(s);
  if (Number.isNaN(t)) return null;
  return Math.max(0, t - now);
}

/**
 * Core of fetchWithTimeout: the timer and the combined signal stay active
 * while `consume(response)` runs, so body reads are covered by the timeout too.
 */
async function timedFetch(url, options, consume) {
  const { timeoutMs = 15000, signal, fetchImpl = globalThis.fetch, ...init } = options || {};
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch is not available in this environment');
  throwIfAborted(signal);

  const timeoutCtl = new AbortController();
  let timedOut = false;
  let timer = null;
  if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
    timer = setTimeout(() => {
      timedOut = true;
      timeoutCtl.abort(new TimeoutError(`Request timed out after ${timeoutMs} ms`, { timeoutMs }));
    }, timeoutMs);
  }
  const linked = linkSignals([signal, timeoutCtl.signal]);
  // Race against the combined signal so a fetchImpl that ignores `signal`
  // still honours timeouts and cancellation.
  const aborted = abortPromise(linked.signal);
  try {
    const work = (async () => {
      const response = await fetchImpl(url, { ...init, signal: linked.signal });
      return consume ? await consume(response) : response;
    })();
    work.catch(() => {}); // the race below may settle first
    return await Promise.race([work, aborted.promise]);
  } catch (err) {
    if (timedOut) {
      throw err instanceof TimeoutError ? err : new TimeoutError(`Request timed out after ${timeoutMs} ms`, { cause: err, timeoutMs });
    }
    if (signal?.aborted) throw abortReasonToError(signal.reason);
    if (isAbortLike(err)) throw abortReasonToError(err);
    throw err;
  } finally {
    clearTimeout(timer);
    aborted.dispose();
    linked.dispose();
  }
}

/**
 * `fetch` with a timeout and caller-signal support.
 * The timeout covers the time until response headers arrive (the caller owns
 * the body afterwards; use fetchJson/fetchText for full coverage).
 * @param {string|URL} url
 * @param {{ timeoutMs?: number, signal?: AbortSignal, fetchImpl?: typeof fetch } & RequestInit} [opts]
 * @returns {Promise<Response>}
 * @throws {TimeoutError|AbortError|TypeError}
 */
export async function fetchWithTimeout(url, opts = {}) {
  return timedFetch(url, opts, null);
}

/**
 * {@link fetchWithTimeout} for callers that read the body themselves: `read(response)`
 * runs while the timer and the caller's signal are still armed, so a body that stalls
 * after the headers ends in a TimeoutError too. Any status is passed to `read`.
 * @template T
 * @param {string|URL} url
 * @param {{ timeoutMs?: number, signal?: AbortSignal, fetchImpl?: typeof fetch } & RequestInit} opts
 * @param {(response: Response) => T|Promise<T>} read
 * @returns {Promise<T>}
 * @throws {TimeoutError|AbortError|TypeError}
 */
export async function fetchAndRead(url, opts, read) {
  if (typeof read !== 'function') throw new TypeError('fetchAndRead expects a read(response) function');
  return timedFetch(url, opts || {}, read);
}

async function readBodySnippet(response) {
  try {
    return (await response.text()).slice(0, 500);
  } catch {
    return '';
  }
}

async function ensureOk(response, url) {
  if (response.ok) return;
  const body = await readBodySnippet(response);
  const retryAfter = response.headers && typeof response.headers.get === 'function'
    ? parseRetryAfter(response.headers.get('retry-after'))
    : null;
  throw new HttpError(response.status, response.url || String(url), body, {
    statusText: response.statusText || '',
    retryAfterMs: retryAfter
  });
}

/**
 * Fetch and parse JSON. Non-2xx → HttpError (with body snippet and
 * `retryAfterMs`); invalid JSON → ParseError; 204/empty-204 → null.
 * The timeout covers the body read as well.
 * @param {string|URL} url
 * @param {object} [opts] Same as {@link fetchWithTimeout}.
 * @returns {Promise<any>}
 */
export async function fetchJson(url, opts = {}) {
  return timedFetch(url, opts, async (response) => {
    await ensureOk(response, url);
    if (response.status === 204 || response.status === 205) return null;
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch (err) {
      throw new ParseError(`Invalid JSON response: ${err.message}`, { cause: err, body: text });
    }
  });
}

/**
 * Fetch a response body as text. Non-2xx → HttpError.
 * @param {string|URL} url
 * @param {object} [opts] Same as {@link fetchWithTimeout}.
 * @returns {Promise<string>}
 */
export async function fetchText(url, opts = {}) {
  return timedFetch(url, opts, async (response) => {
    await ensureOk(response, url);
    return response.text();
  });
}

/* ------------------------------------------------------------------------ */
/* Retry + error classification                                             */
/* ------------------------------------------------------------------------ */

/**
 * Default retry policy: network TypeError, TimeoutError, HttpError 429/5xx.
 * Never AbortError. An explicit boolean `err.retryable` wins.
 * @param {unknown} err
 * @returns {boolean}
 */
export function defaultShouldRetry(err) {
  if (!err || typeof err !== 'object') return false;
  if (err.name === 'AbortError') return false;
  if (typeof err.retryable === 'boolean') return err.retryable;
  if (err.name === 'TimeoutError') return true;
  if (err instanceof HttpError) return err.status === 429 || (err.status >= 500 && err.status <= 599);
  if (err instanceof TypeError) return true;
  return false;
}

/**
 * Run `fn` with retries, exponential backoff (base·2^n, capped) and jitter.
 *
 * - Never retries AbortError, nor anything once `signal` is aborted.
 * - When the error carries `retryAfterMs` (HttpError 429 from a `Retry-After`
 *   header) that delay is used exactly; if it exceeds `maxDelayMs` the error
 *   is thrown instead of waiting (or retrying too early).
 *
 * @template T
 * @param {() => Promise<T>|T} fn
 * @param {{ retries?: number, baseDelayMs?: number, maxDelayMs?: number, signal?: AbortSignal,
 *   shouldRetry?: (err: unknown) => boolean,
 *   onRetry?: (err: unknown, attempt: number, delayMs: number) => void }} [opts]
 * @returns {Promise<T>}
 */
export async function retry(fn, {
  retries = 2,
  baseDelayMs = 500,
  maxDelayMs = 8000,
  signal,
  shouldRetry = defaultShouldRetry,
  onRetry
} = {}) {
  const maxRetries = Number.isFinite(retries) && retries > 0 ? Math.floor(retries) : 0;
  for (let attempt = 0; ; attempt += 1) {
    throwIfAborted(signal);
    try {
      return await fn();
    } catch (err) {
      if (attempt >= maxRetries) throw err;
      if (isAbortLike(err) || signal?.aborted) throw err;
      let retryable = false;
      try {
        retryable = !!shouldRetry(err);
      } catch {
        retryable = false;
      }
      if (!retryable) throw err;
      const delay = backoffDelay(err, attempt, baseDelayMs, maxDelayMs);
      if (delay === null) throw err;
      if (typeof onRetry === 'function') {
        try { onRetry(err, attempt + 1, delay); } catch { /* observer errors are ignored */ }
      }
      await sleep(delay, signal);
    }
  }
}

function backoffDelay(err, attempt, baseDelayMs, maxDelayMs) {
  const cap = Number.isFinite(maxDelayMs) && maxDelayMs >= 0 ? maxDelayMs : 8000;
  const retryAfter = err && typeof err === 'object' ? err.retryAfterMs : null;
  if (Number.isFinite(retryAfter) && retryAfter >= 0) {
    return retryAfter <= cap ? retryAfter : null;
  }
  const base = Number.isFinite(baseDelayMs) && baseDelayMs >= 0 ? baseDelayMs : 500;
  const exp = Math.min(cap, base * 2 ** attempt);
  // "Equal jitter": half fixed, half random — spreads bursts without
  // collapsing the delay towards zero.
  return Math.round(exp / 2 + Math.random() * (exp / 2));
}

const ERROR_KINDS = new Set(['abort', 'timeout', 'rate-limit', 'http', 'network', 'parse', 'unknown']);

/**
 * Classify an error for UI display / retry decisions.
 * An error may self-classify via a valid `err.kind` string.
 * @param {unknown} err
 * @returns {'abort'|'timeout'|'rate-limit'|'http'|'network'|'parse'|'unknown'}
 */
export function errorKind(err) {
  if (!err || typeof err !== 'object') return 'unknown';
  if (typeof err.kind === 'string' && ERROR_KINDS.has(err.kind)) return err.kind;
  const name = typeof err.name === 'string' ? err.name : '';
  if (name === 'AbortError') return 'abort';
  if (name === 'TimeoutError') return 'timeout';
  if (name === 'RateLimitError') return 'rate-limit';
  if (err instanceof HttpError || name === 'HttpError') return err.status === 429 ? 'rate-limit' : 'http';
  if (name === 'SyntaxError' || name === 'ParseError' || /(?:ParseError|WireError)$/.test(name)) return 'parse';
  if (err instanceof TypeError || name === 'TypeError' || name === 'NetworkError') return 'network';
  return 'unknown';
}

/* ------------------------------------------------------------------------ */
/* Collections                                                              */
/* ------------------------------------------------------------------------ */

/**
 * Unique values in first-seen order.
 * @template T
 * @param {Iterable<T>|null|undefined} arr
 * @returns {T[]}
 */
export function uniq(arr) {
  if (arr === null || arr === undefined) return [];
  return [...new Set(arr)];
}

/**
 * Split into chunks of `n` (last chunk may be shorter).
 * @template T
 * @param {T[]} arr
 * @param {number} n Positive integer.
 * @returns {T[][]}
 */
export function chunk(arr, n) {
  const size = Math.floor(Number(n));
  if (!Number.isFinite(size) || size < 1) throw new RangeError('chunk size must be a positive integer');
  const list = Array.isArray(arr) ? arr : arr ? [...arr] : [];
  const out = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

const LABEL_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

/**
 * Random DNS-safe label of `[a-z0-9]` using crypto.getRandomValues (rejection
 * sampling → no modulo bias). Falls back to Math.random without WebCrypto.
 * @param {number} [len=12]
 * @param {{ crypto?: { getRandomValues: (a: Uint8Array) => Uint8Array } }} [opts]
 * @returns {string}
 */
export function randomLabel(len = 12, { crypto = globalThis.crypto } = {}) {
  const n = Math.max(1, Math.min(63, Math.floor(Number(len)) || 12));
  const alpha = LABEL_ALPHABET.length; // 36
  const limit = 256 - (256 % alpha); // 252: bytes >= limit are rejected
  let out = '';
  if (crypto && typeof crypto.getRandomValues === 'function') {
    const buf = new Uint8Array(n * 2);
    while (out.length < n) {
      crypto.getRandomValues(buf);
      for (let i = 0; i < buf.length && out.length < n; i += 1) {
        if (buf[i] < limit) out += LABEL_ALPHABET[buf[i] % alpha];
      }
    }
    return out;
  }
  while (out.length < n) out += LABEL_ALPHABET[Math.floor(Math.random() * alpha)];
  return out;
}

/**
 * Bounded LRU-ish cache. `get` refreshes recency; inserting beyond
 * `maxEntries` evicts the least recently used entry. Optional TTL per cache
 * (`ttlMs`) or per entry (`set(k, v, ttlMs)`); 0 = no expiry.
 * @param {{ maxEntries?: number, ttlMs?: number, now?: () => number }} [opts]
 */
export function createCache({ maxEntries = 5000, ttlMs = 0, now = Date.now } = {}) {
  const max = Math.max(1, Math.floor(Number(maxEntries)) || 5000);
  /** @type {Map<any, { v: any, exp: number }>} */
  const map = new Map();

  const alive = (entry) => !entry.exp || entry.exp > now();

  return {
    get(key) {
      const entry = map.get(key);
      if (!entry) return undefined;
      map.delete(key);
      if (!alive(entry)) return undefined;
      map.set(key, entry);
      return entry.v;
    },
    set(key, value, entryTtlMs) {
      const ttl = Number.isFinite(entryTtlMs) ? entryTtlMs : ttlMs;
      map.delete(key);
      map.set(key, { v: value, exp: ttl > 0 ? now() + ttl : 0 });
      while (map.size > max) map.delete(map.keys().next().value);
      return this;
    },
    has(key) {
      const entry = map.get(key);
      if (!entry) return false;
      if (!alive(entry)) {
        map.delete(key);
        return false;
      }
      return true;
    },
    delete(key) {
      return map.delete(key);
    },
    clear() {
      map.clear();
    },
    get size() {
      return map.size;
    }
  };
}

/**
 * Split free text into items on whitespace, commas, semicolons and newlines.
 * Whole-line comments (`#...`) and inline comments (` # ...`) are dropped.
 * @param {string|string[]|null|undefined} text
 * @returns {string[]}
 */
export function splitList(text) {
  if (text === null || text === undefined) return [];
  const source = Array.isArray(text) ? text.join('\n') : String(text);
  const out = [];
  for (const rawLine of source.split(/\r\n|\r|\n/)) {
    // '#' starts a comment only at line start or after whitespace, so URL
    // fragments like https://x/#a survive.
    const line = rawLine.replace(/(^|\s)#.*$/, '$1').trim();
    if (!line) continue;
    for (const item of line.split(/[\s,;]+/)) {
      if (item) out.push(item);
    }
  }
  return out;
}
