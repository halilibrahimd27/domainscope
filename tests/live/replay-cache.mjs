/**
 * Record / replay cache for passive-source HTTP answers (crt.sh, Cert Spotter,
 * Anubis, ip.thc.org …) used by the live benchmark, so repeated runs share
 * one live fetch and cost no third-party quota.
 *
 * Only FINAL answers are recorded: a 2xx response whose body is not a quota /
 * rate-limit notice. Failures (network errors, 4xx, 5xx, 429, "API count
 * exceeded" texts) are never written, so
 *   - a retry by the source's own backoff logic reaches the network again
 *     instead of replaying the failed first attempt, and
 *   - a transient outage never becomes a permanent failure for later runs.
 * An old cache file that holds only failures (written by an earlier version of
 * this cache) is ignored and replaced by the next final answer.
 *
 * Node 22, no dependencies; DOM-free so the unit suite can exercise it.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** Short bodies that report a quota / throttle instead of data (HTTP 200 included). */
const NOT_AN_ANSWER_RE = /api count exceeded|increase quota|too many requests|rate.?limit|throttl|quota (?:exceeded|used)/i;
/** Bodies longer than this are treated as data even if a word above occurs in them. */
const NOTICE_MAX_CHARS = 400;

/**
 * Is a recorded entry a final answer worth replaying?
 * @param {{ status?: number, body?: string, error?: string }|null|undefined} entry
 * @returns {boolean}
 */
export function isFinalAnswer(entry) {
  if (!entry || entry.error) return false;
  const status = Number(entry.status);
  if (!(status >= 200 && status < 300)) return false;
  const body = String(entry.body ?? '').trim();
  if (body.startsWith('[')) return true; // a JSON array of names / certificates is data
  return !(body.length <= NOTICE_MAX_CHARS && NOT_AN_ANSWER_RE.test(body));
}

function abortError(signal) {
  const reason = signal && signal.reason;
  if (reason instanceof Error) return reason;
  const err = new Error('The operation was aborted');
  err.name = 'AbortError';
  return err;
}

function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) { reject(abortError(signal)); return; }
    const onAbort = () => { clearTimeout(t); reject(abortError(signal)); };
    const t = setTimeout(() => { if (signal) signal.removeEventListener('abort', onAbort); resolve(); }, ms);
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * @param {{ dir: string, fresh?: boolean, fetchImpl?: typeof fetch, replayDelay?: boolean,
 *   onEvent?: (e: { kind: 'live'|'replay'|'live-failure'|'stale', url: string, status?: number, error?: string }) => void }} opts
 *   fresh: never replay (still records final answers); replayDelay: wait the recorded latency on replay (default true)
 * @returns {{ fetch: (url: string, init?: RequestInit) => Promise<Response>,
 *   stats: { live: number, replayed: number, liveFailures: number, staleIgnored: number },
 *   fileFor: (url: string, init?: RequestInit) => string }}
 */
export function createReplayCache({ dir, fresh = false, fetchImpl = globalThis.fetch, replayDelay = true, onEvent = () => {} } = {}) {
  if (!dir) throw new TypeError('createReplayCache: dir is required');
  mkdirSync(dir, { recursive: true });
  const stats = { live: 0, replayed: 0, liveFailures: 0, staleIgnored: 0 };
  const staleSeen = new Set();

  const fileFor = (url, init = {}) => {
    const key = `${String(init.method || 'GET').toUpperCase()} ${url} ${init.body ? String(init.body) : ''}`;
    return join(dir, `${createHash('sha256').update(key).digest('hex').slice(0, 24)}.json`);
  };

  /** The recorded final answer, or null (no file, unreadable, or failures only). */
  function cached(file, url) {
    if (!existsSync(file)) return null;
    let entries;
    try { entries = JSON.parse(readFileSync(file, 'utf8')); } catch { return null; }
    const list = Array.isArray(entries) ? entries : [entries];
    const final = [...list].reverse().find(isFinalAnswer) || null;
    if (!final && !staleSeen.has(file)) {
      staleSeen.add(file);
      stats.staleIgnored += 1;
      onEvent({ kind: 'stale', url });
    }
    return final;
  }

  const toResponse = (e) => new Response([101, 204, 205, 304].includes(e.status) ? null : e.body, { status: e.status, headers: e.headers });

  async function replayFetch(url, init = {}) {
    const file = fileFor(url, init);
    const hit = fresh ? null : cached(file, url);
    if (hit) {
      stats.replayed += 1;
      onEvent({ kind: 'replay', url, status: hit.status });
      if (replayDelay) await delay(hit.elapsedMs || 0, init.signal);
      else if (init.signal && init.signal.aborted) throw abortError(init.signal);
      return toResponse(hit);
    }
    stats.live += 1;
    const started = Date.now();
    let entry;
    try {
      const res = await fetchImpl(url, init);
      const body = await res.text();
      entry = { status: res.status, headers: Object.fromEntries(res.headers.entries()), body, elapsedMs: Date.now() - started };
    } catch (err) {
      if (init.signal && init.signal.aborted) throw err; // the caller's own timeout / abort
      entry = { error: String((err && err.message) || err), elapsedMs: Date.now() - started };
    }
    if (isFinalAnswer(entry)) {
      writeFileSync(file, JSON.stringify([entry]));
      onEvent({ kind: 'live', url, status: entry.status });
    } else {
      stats.liveFailures += 1;
      onEvent({ kind: 'live-failure', url, status: entry.status, error: entry.error });
    }
    if (entry.error) throw new TypeError(entry.error);
    return toResponse(entry);
  }

  return { fetch: replayFetch, stats, fileFor };
}
