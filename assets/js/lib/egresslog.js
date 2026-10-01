/**
 * egresslog.js — what this page sent, counted while it happens (About › What this page sent).
 *
 * ui/egress-meter.js feeds it from two witnesses: the page's own fetch calls and the browser's
 * Resource Timing entries. A request is kept as its {@link requestSignature}, so a scan of 100,000
 * names makes a handful of entries; what a URL cannot say, the sender adds ({@link noteRequest}).
 * Page session only. lib/egress.js names the hosts; this module is on the start route: keep it small.
 *
 * DOM-free, no I/O.
 */

/** How a request was seen: started by a fetch, reported by Resource Timing, reached through a redirect, or a fetch without an answer. */
export const EGRESS_VIA = Object.freeze(['fetch', 'resource', 'redirect', 'failed']);
/** Distinct signatures kept; later new ones share one overflow entry per origin. */
export const MAX_SIGNATURES = 400;
/** The path of an overflow entry, and the end of a path cut after 8 segments. */
export const OVERFLOW_PATH = '/…';
/** Notes kept per signature at most. */
export const MAX_NOTES = 8;

const WORD_RE = /^[a-z][a-z_-]{0,39}$/;
const PARAM_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const NOTE_RE = /^[a-z][a-z0-9-]{0,31}$/;
/** Path words an API puts a value after (domain/<name>, domains/<zone>, measurements/<id> …): the next segment is '*'. */
const VALUE_AFTER = new Set(['domain', 'domains', 'ip', 'autnum', 'entity', 'nameserver', 'measurements', 'subdomains']);

/**
 * Where a request went and the shape of what it asked: the path's plain lower-case words (an
 * API's fixed parts) are kept, any other segment and the one after a {@link VALUE_AFTER} word is
 * '*', the query is its sorted parameter names. A value that is a plain word elsewhere in a path
 * stays (tab memory only; the ledger shows no path). `https://crt.sh/?q=%25.example.com&output=json`
 * → key `https://crt.sh/?output&q`.
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
  const segments = [];
  for (const s of parts.slice(0, 8)) {
    const low = s.toLowerCase();
    const afterValueWord = segments.length > 0 && VALUE_AFTER.has(segments[segments.length - 1]);
    segments.push(low === '' || (WORD_RE.test(low) && !afterValueWord) ? low : '*');
  }
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

const noteListeners = new Set();

/**
 * Say what a request is about to carry when its URL cannot (lib/globalping.js: 'ip-target',
 * 'host-target' or 'dns-query'; lib/rdap.js: 'rdap', a registry's server), just before the fetch; the meter
 * attaches it to the signature. A fixed word, never a value: anything else is dropped.
 * @param {string|URL} url
 * @param {string} note
 */
export function noteRequest(url, note) {
  if (typeof note !== 'string' || !NOTE_RE.test(note)) return;
  for (const fn of [...noteListeners]) {
    try {
      fn(String(url), note);
    } catch {
      // a listener's failure is its own
    }
  }
}

/**
 * Hear every {@link noteRequest} (ui/egress-meter.js).
 * @param {(url: string, note: string) => void} fn
 * @returns {() => void} unsubscribe
 */
export function onRequestNote(fn) {
  noteListeners.add(fn);
  return () => noteListeners.delete(fn);
}

/**
 * The page session's request log. `record(url, { via, base, from })` counts one sighting ('failed'
 * marks a fetch counted before as unanswered; a 'redirect' takes the notes of its request `from`;
 * never throws); `note(url, note, { base })` adds a {@link noteRequest} word to the signature;
 * `snapshot()` → `{ since, at, entries }` (copies of `{ key, origin, host, path, query, notes,
 * fetch, resource, redirect, failed, first, last }`); `clear()`; `subscribe(fn)` → unsubscribe,
 * `fn` runs once per burst of records (a microtask).
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
  // a signature's own entry, or its origin's overflow entry once the log is full
  const keyOf = (sig) => (entries.has(sig.key) || entries.size < maxSignatures ? sig.key : `${sig.origin}${OVERFLOW_PATH}`);
  const entryFor = (sig, at) => {
    const key = keyOf(sig);
    let entry = entries.get(key);
    if (!entry) {
      const full = key !== sig.key;
      entry = {
        key, origin: sig.origin, host: sig.host, path: full ? OVERFLOW_PATH : sig.path, query: full ? '' : sig.query, notes: [],
        fetch: 0, resource: 0, redirect: 0, failed: 0, first: at, last: at
      };
      entries.set(key, entry);
    }
    return entry;
  };
  const addNote = (entry, note) => {
    if (entry.notes.includes(note) || entry.notes.length >= MAX_NOTES) return;
    entry.notes.push(note);
    entry.notes.sort();
  };
  return {
    record(url, { via = 'fetch', base = undefined, from = undefined } = {}) {
      const sig = EGRESS_VIA.includes(via) ? requestSignature(url, base) : null;
      if (!sig) return false;
      const at = now();
      const entry = entryFor(sig, at);
      entry[via] += 1;
      entry.last = at;
      if (via === 'redirect' && from !== undefined) {
        // the server a redirect reached got what the request carried (rdap.org → a registry's server)
        const src = requestSignature(from, base);
        const prev = src ? entries.get(keyOf(src)) : null;
        if (prev && prev !== entry) for (const n of prev.notes) addNote(entry, n);
      }
      notify();
      return true;
    },
    note(url, note, { base = undefined } = {}) {
      const sig = typeof note === 'string' && NOTE_RE.test(note) ? requestSignature(url, base) : null;
      if (!sig) return false;
      addNote(entryFor(sig, now()), note);
      return true;
    },
    snapshot() {
      return { since, at: now(), entries: [...entries.values()].map((e) => ({ ...e, notes: [...e.notes] })) };
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
