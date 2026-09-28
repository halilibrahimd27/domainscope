/**
 * egresslog.js — what this page sent, counted while it happens (About › What this page sent).
 *
 * ui/egress-meter.js feeds it from two witnesses: the page's own fetch calls and the browser's
 * Resource Timing entries. A request is kept as its {@link requestSignature} (origin, path shape,
 * query parameter names — never a value), so a scan of 100,000 names makes a handful of entries
 * and nothing the user typed is held. Page session only: nothing is stored. What each host is
 * and what it received is lib/egress.js, loaded with the ledger; this module is on the start
 * route and stays small.
 *
 * DOM-free, no I/O.
 */

/** How a request was seen: started by a fetch, reported by Resource Timing, reached through a redirect, or a fetch without an answer. */
export const EGRESS_VIA = Object.freeze(['fetch', 'resource', 'redirect', 'failed']);
/** Distinct signatures kept; later new ones share one overflow entry per origin. */
export const MAX_SIGNATURES = 400;
/** The path of an overflow entry, and the end of a path cut after 8 segments. */
export const OVERFLOW_PATH = '/…';

const WORD_RE = /^[a-z][a-z_-]{0,39}$/;
const PARAM_RE = /^[a-z][a-z0-9_-]{0,31}$/;

/**
 * Where a request went and the shape of what it asked, without any value: plain lower-case
 * words of the path are kept, every other segment (an address, a name, an id) is '*', and the
 * query is its sorted parameter names. `https://crt.sh/?q=%25.example.com&output=json` →
 * `{ key: 'https://crt.sh/?output&q', path: '/', query: 'output&q', … }`.
 * @param {string|URL} url absolute, or relative to `base`
 * @param {string} [base]
 * @returns {{ key: string, origin: string, host: string, path: string, query: string }|null}
 *   null for anything but http(s) or an unparseable URL
 */
export function requestSignature(url, base = undefined) {
  let u;
  try {
    u = base === undefined ? new URL(String(url)) : new URL(String(url), base);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  const parts = u.pathname.split('/').slice(1);
  const segments = parts.slice(0, 8).map((s) => {
    const low = s.toLowerCase();
    return low === '' || WORD_RE.test(low) ? low : '*';
  });
  const path = `/${segments.join('/')}${parts.length > 8 ? OVERFLOW_PATH : ''}`;
  const names = [...new Set([...u.searchParams.keys()].map((n) => (PARAM_RE.test(n.toLowerCase()) ? n.toLowerCase() : '*')))].sort();
  const query = names.slice(0, 10).join('&') + (names.length > 10 ? '&…' : '');
  return { key: `${u.origin}${path}${query ? `?${query}` : ''}`, origin: u.origin, host: u.host, path, query };
}

/**
 * The requests an entry stands for: a completed fetch is seen by both witnesses, so the larger
 * count wins (Resource Timing misses a request that got no answer, the wrapper one not started
 * by fetch); requests reached through a redirect add up.
 * @param {{ fetch?: number, resource?: number, redirect?: number }} entry
 * @returns {number}
 */
export function requestCount(entry) {
  return entry ? Math.max(entry.fetch || 0, entry.resource || 0) + (entry.redirect || 0) : 0;
}

/**
 * Requests to other origins than the page's (and the distinct hosts), and to its own.
 * @param {object[]} entries a snapshot's entries
 * @param {string} pageOrigin
 * @returns {{ thirdParty: number, self: number, hosts: number }}
 */
export function countRequests(entries, pageOrigin) {
  const out = { thirdParty: 0, self: 0, hosts: 0 };
  const hosts = new Set();
  for (const e of Array.isArray(entries) ? entries : []) {
    const n = requestCount(e);
    if (e.origin === pageOrigin) out.self += n;
    else if (n) {
      out.thirdParty += n;
      hosts.add(e.host);
    }
  }
  out.hosts = hosts.size;
  return out;
}

/**
 * The page session's request log. `record(url, { via, base })` counts one sighting ('failed'
 * marks a fetch counted before as unanswered; never throws); `snapshot()` → `{ since, at,
 * entries }` (copies of `{ key, origin, host, path, query, fetch, resource, redirect, failed,
 * first, last }`, first seen first); `clear()` starts over; `subscribe(fn)` → unsubscribe, `fn`
 * runs once per burst of records (a microtask), never per request.
 * @param {{ now?: () => number, maxSignatures?: number }} [opts]
 */
export function createEgressLog({ now = () => Date.now(), maxSignatures = MAX_SIGNATURES } = {}) {
  let entries = new Map();
  let since = now();
  const listeners = new Set();
  let queued = false;
  const notify = () => {
    if (queued || !listeners.size) return;
    queued = true;
    queueMicrotask(() => {
      queued = false;
      for (const fn of [...listeners]) {
        try {
          fn();
        } catch {
          // a listener's failure is its own
        }
      }
    });
  };
  const entryFor = (sig, at) => {
    const full = !entries.has(sig.key) && entries.size >= maxSignatures;
    const key = full ? `${sig.origin}${OVERFLOW_PATH}` : sig.key;
    let entry = entries.get(key);
    if (!entry) {
      entry = {
        key, origin: sig.origin, host: sig.host, path: full ? OVERFLOW_PATH : sig.path, query: full ? '' : sig.query,
        fetch: 0, resource: 0, redirect: 0, failed: 0, first: at, last: at
      };
      entries.set(key, entry);
    }
    return entry;
  };
  return {
    record(url, { via = 'fetch', base = undefined } = {}) {
      const sig = EGRESS_VIA.includes(via) ? requestSignature(url, base) : null;
      if (!sig) return false;
      const at = now();
      const entry = entryFor(sig, at);
      entry[via] += 1;
      entry.last = at;
      notify();
      return true;
    },
    snapshot() {
      return { since, at: now(), entries: [...entries.values()].map((e) => ({ ...e })) };
    },
    clear() {
      entries = new Map();
      since = now();
      notify();
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    }
  };
}
