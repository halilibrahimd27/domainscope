/**
 * learned.js — a private, per-browser store of subdomain labels discovered in
 * earlier scans, so a later scan of a related domain tries the same naming
 * convention first. Opt-in (the views keep it off by default) and a local
 * adaptation only: the store itself lives only in the viewer's browser storage
 * and is never written to the repo — but a later scan that uses it sends each
 * label as a DNS lookup (`label.<that domain>`), so resolvers and that domain's
 * name servers see the labels. It is never used at wordlist level Off.
 *
 * PRIVACY: the store keeps only bare, left-most DNS labels (the naming
 * vocabulary — e.g. `billing`, `dev`, `portal`), never full hostnames and
 * never IP addresses. `record(names, apex)` strips each name down to its label(s)
 * relative to the apex before storing, and refuses anything that looks like an
 * IP, a wildcard, or the apex itself — including an IP written INTO a label the
 * reverse-DNS way (`198-51-100-7`, `ip-192-0-2-10`, `2001-db8--1`), which would
 * otherwise be tried under every other domain later.
 *
 * DOM-free and storage-injected: pass a `localStorage`-like object (with
 * `getItem`/`setItem`) or `null`. Every storage access is guarded, so a private
 * window (where storage throws), a disabled store, or corrupt JSON all degrade
 * to an empty, in-memory store rather than throwing.
 *
 * Used by views/subdomains.js and views/scan.js through learnedStore(),
 * rememberLearned() and the learned-names switch; the scanner tries the labels
 * as `learnedLabels` (loadWordlist `extra`) and shares {@link isStorableLabel}
 * for learnedLabelsFromScan. Kept separate from `wordlist.js` so the wordlist
 * module stays pure/static.
 */

const DEFAULT_KEY = 'ssds.learned.labels';
const DEFAULT_MAX = 5000;

// A bare DNS label: [a-z0-9-], 1–63, no leading/trailing '-'.
const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/** Is `s` an IP address (v4 or v6)? Such names must never be stored. */
function looksLikeIp(s) {
  if (IPV4_RE.test(s)) return true;
  // IPv6: hex groups and colons, optionally bracketed / zoned.
  const bare = s.replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  return bare.includes(':') && /^[0-9a-f:]+$/.test(bare);
}

// An IPv4 address written into a label (reverse-DNS style): four 1–3 digit
// groups joined by '-' (or '_'), optionally with a prefix / suffix —
// `198-51-100-7`, `ip-192-0-2-10`, `203-0-113-9-static`.
const IPV4_LABEL_RE = /(^|[^0-9])\d{1,3}(?:[-_]\d{1,3}){3}(?![0-9])/;
const HEX_GROUP_RE = /^[0-9a-f]{0,4}$/;

/**
 * An IPv6 address written into a label with '-' for ':' (`2001-db8--1`,
 * `ip6-2001-db8-0-0-0-0-0-1`): a run of dash-separated hex groups (≤ 4 hex
 * digits) holding a digit that is either compressed (`--` between ≥ 2 groups)
 * or ≥ 6 groups long. Punycode (`xn--…`) never matches: `xn` is not hex.
 */
function looksLikeIpv6Label(label) {
  const groups = label.split('-');
  let run = [];
  const check = () => {
    const filled = run.filter(Boolean);
    const ok = filled.some((g) => /\d/.test(g))
      && ((filled.length >= 2 && run.slice(1, -1).includes('')) || filled.length >= 6);
    run = [];
    return ok;
  };
  for (const g of groups) {
    if (HEX_GROUP_RE.test(g)) { run.push(g); continue; }
    if (check()) return true;
  }
  return check();
}

/**
 * Does a single label encode an IP address (v4 or v6)? Such a label names one
 * server of one estate — never naming vocabulary — so it is never learned.
 * @param {string} label
 * @returns {boolean}
 */
export function looksLikeIpLabel(label) {
  const s = String(label ?? '').toLowerCase();
  return IPV4_LABEL_RE.test(s) || looksLikeIpv6Label(s);
}

/**
 * A storable label: a valid lowercase DNS label, not purely numeric and not an
 * IP address written as a label. Shared with scanner.learnedLabelsFromScan so
 * the scanner only ever emits labels this store keeps.
 * @param {string} label
 * @returns {boolean}
 */
export function isStorableLabel(label) {
  if (!label || !LABEL_RE.test(label)) return false;
  if (/^\d+$/.test(label)) return false; // pure numbers carry no convention signal
  if (looksLikeIpLabel(label)) return false; // an address, not a naming convention
  return true;
}

/**
 * Extract the bare label(s) a name contributes, relative to `apex`.
 *  - `api.example.com`      + `example.com` → ['api']
 *  - `dev.api.example.com`  + `example.com` → ['dev', 'api']
 *  - `example.com`          + `example.com` → []            (apex itself)
 *  - `*.example.com`                        → []            (wildcard)
 *  - no/`unrelated` apex → the name's first label only.
 * @param {string} name
 * @param {string} [apex]
 * @returns {string[]}
 */
function labelsOf(name, apex) {
  let host = String(name ?? '').trim().toLowerCase().replace(/\.+$/, '');
  if (!host || host.includes('*') || looksLikeIp(host)) return [];
  const a = String(apex ?? '').trim().toLowerCase().replace(/\.+$/, '');
  let prefix;
  if (a && host === a) return [];
  if (a && host.endsWith('.' + a)) {
    prefix = host.slice(0, host.length - a.length - 1);
  } else {
    // No apex relationship: keep only the left-most label of the name.
    const dot = host.indexOf('.');
    prefix = dot === -1 ? host : host.slice(0, dot);
  }
  return prefix.split('.').filter((l) => isStorableLabel(l));
}

/**
 * Create a learned-labels store.
 * @param {{ getItem(k:string):(string|null), setItem(k:string,v:string):void }|null} storage
 *   a localStorage-like object, or null to run purely in memory.
 * @param {{ key?: string, max?: number }} [opts]
 * @returns {{
 *   labels(): string[], record(names: string|string[], apex?: string): number,
 *   size(): number, clear(): void, export(): object, import(data: object): void
 * }}
 */
export function createLearnedStore(storage, { key = DEFAULT_KEY, max = DEFAULT_MAX } = {}) {
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : DEFAULT_MAX;
  /** label → { hits, last } ; `seq` is a monotonic recency counter. */
  let map = new Map();
  let seq = 0;

  const canStore = storage && typeof storage.getItem === 'function' && typeof storage.setItem === 'function';

  function ingest(raw) {
    if (!raw || typeof raw !== 'object') return;
    const entries = raw.labels;
    if (!entries || typeof entries !== 'object') return;
    if (Number.isFinite(raw.seq)) seq = Math.max(seq, raw.seq);
    for (const [label, val] of Object.entries(entries)) {
      if (!isStorableLabel(label)) continue;
      let hits = 0;
      let last = 0;
      if (Array.isArray(val)) { hits = +val[0] || 0; last = +val[1] || 0; }
      else if (val && typeof val === 'object') { hits = +val.hits || 0; last = +val.last || 0; }
      else if (Number.isFinite(+val)) { hits = +val; }
      if (hits <= 0) hits = 1;
      const prev = map.get(label);
      if (prev) { prev.hits += hits; prev.last = Math.max(prev.last, last); }
      else map.set(label, { hits, last });
      seq = Math.max(seq, last);
    }
  }

  // Load existing state (guarded against throwing / corrupt JSON).
  if (canStore) {
    try {
      const rawStr = storage.getItem(key);
      if (rawStr) ingest(JSON.parse(rawStr));
    } catch { /* private mode / corrupt data → start empty */ }
  }

  function evictIfNeeded() {
    if (map.size <= cap) return;
    // Keep the most useful: highest hits, then most recent.
    const ordered = [...map.entries()].sort((a, b) =>
      (b[1].hits - a[1].hits) || (b[1].last - a[1].last));
    map = new Map(ordered.slice(0, cap));
  }

  function persist() {
    if (!canStore) return;
    try {
      const labels = {};
      for (const [label, v] of map) labels[label] = [v.hits, v.last];
      storage.setItem(key, JSON.stringify({ v: 1, seq, labels }));
    } catch { /* quota / private mode → keep in-memory only */ }
  }

  function labels() {
    return [...map.entries()]
      .sort((a, b) => (b[1].hits - a[1].hits) || (b[1].last - a[1].last) || (a[0] < b[0] ? -1 : 1))
      .map(([label]) => label);
  }

  function record(names, apex) {
    const list = Array.isArray(names) ? names : [names];
    let added = 0;
    for (const name of list) {
      for (const label of labelsOf(name, apex)) {
        seq += 1;
        const prev = map.get(label);
        if (prev) { prev.hits += 1; prev.last = seq; }
        else { map.set(label, { hits: 1, last: seq }); added += 1; }
      }
    }
    evictIfNeeded();
    persist();
    return added;
  }

  function size() { return map.size; }

  function clear() {
    map = new Map();
    seq = 0;
    if (canStore) {
      try { storage.setItem(key, JSON.stringify({ v: 1, seq: 0, labels: {} })); } catch { /* ignore */ }
    }
  }

  function exportData() {
    const labelsObj = {};
    for (const [label, v] of map) labelsObj[label] = [v.hits, v.last];
    return { v: 1, seq, labels: labelsObj };
  }

  function importData(data) {
    ingest(data);
    evictIfNeeded();
    persist();
  }

  return { labels, record, size, clear, export: exportData, import: importData };
}
