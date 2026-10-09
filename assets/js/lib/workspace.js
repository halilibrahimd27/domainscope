/**
 * lib/workspace.js — customer workspaces: named, separate sets of what belongs to one customer
 * (the server inventory, the learned names, the custom wordlist, the expected CAs, free-text
 * notes, the domains worked on, the domain policy of the portfolio audit (lib/policy.js), the
 * origin map of its proxied names, the certificates its CT watch has seen (lib/ctwatch.js), what the
 * registries last said of its domains (lib/regwatch.js), the Rollout board, the accepted risks
 * (lib/waivers.js) and the DMARC report history (lib/dmarchistory.js)), so a DUPLICATE_IP never mixes
 * two customers' servers and a label
 * learned from one customer's scans is never tried under another customer's domains.
 * Settings about the tool itself (theme, language, resolvers, parallelism) stay global (state.js).
 *
 * DOM-free and storage-injected. The persistence is a small async key-value backend
 * ({@link WorkspaceBackend}): IndexedDB in the browser (assets/js/workspace-db.js), memory in the
 * tests and wherever the browser refuses storage ({@link createMemoryBackend}). The store keeps
 * the active workspace in memory, so the tools read it synchronously; every change is written
 * through, and a write that fails leaves the page working on its memory copy (`lastError`).
 *
 * Records (keys of the backend; values are plain JSON):
 *   'meta'                 { v, createdAt, migrated: string[] }: the store is initialised
 *   'wsmeta/<id>'          { id, name, createdAt, updatedAt }: one per workspace (Default: name null)
 *   'wsdata/<id>/<part>'   the value of one {@link WORKSPACE_PARTS} entry (absent: empty)
 *
 * First run: what the app kept before workspaces existed (the inventory and the learned names in
 * localStorage, the custom wordlist in this tab's sessionStorage: {@link LEGACY_KEYS}) moves into
 * Default in one transaction, together with the 'meta' record. The old keys are removed only once
 * that transaction has committed, so an interrupted migration loses nothing: it goes with the page's
 * next write that commits, or runs again on the next load. Without persistent storage the old data
 * is read into memory and left where it is.
 *
 * Several tabs: a BroadcastChannel-like `channel` tells the other tabs what changed, and a tab
 * re-reads a part of its active workspace that another tab wrote ({@link WorkspaceStore}
 * `subscribe` reports those external changes only). Each tab keeps its own active workspace; the
 * localStorage pointer ({@link ACTIVE_WORKSPACE_KEY}) only decides where a new page starts.
 *
 * @example
 *   const store = createWorkspaceStore({ backend: createMemoryBackend() });
 *   await store.open();
 *   const { meta } = await store.create('Acme');
 *   await store.switchTo(meta.id);
 *   await store.save('expectedCas', ["Let's Encrypt"]);
 *   store.data.expectedCas;                                   // ["Let's Encrypt"]
 */

import { isStorableLabel } from './learned.js';
import { sanitizeOriginMap } from './originmap.js';
import { parseTarget } from './session.js';
import { randomLabel } from './util.js';

/** The workspace that always exists (it cannot be renamed or deleted). */
export const DEFAULT_WORKSPACE_ID = 'default';

/** What one workspace holds. */
export const WORKSPACE_PARTS = Object.freeze(['inventory', 'learned', 'wordlist', 'expectedCas', 'notes', 'recent', 'policy', 'origins', 'ctSeen', 'rdapSeen', 'rollout', 'waivers', 'reportHistory', 'digests']);

/** Bounds: workspaces, name and notes length (characters), list lengths, stored text sizes. */
export const WORKSPACE_LIMITS = Object.freeze({
  count: 100,
  name: 60,
  notes: 20000,
  recent: 20,
  expectedCas: 30,
  expectedCa: 120,
  learned: 5000,
  inventory: 16 * 1024 * 1024,
  wordlist: 8 * 1024 * 1024,
  policy: 16384,
  ctSeen: 1048576,
  rdapSeen: 524288,
  waivers: 65536,
  reportHistory: 4194304,
  digests: 16384
});

/** localStorage key of the pointer to the active workspace (the id, as a plain string). */
export const ACTIVE_WORKSPACE_KEY = 'ssds.workspace';

/** Where the data lived before workspaces: localStorage (inventory, learned) and sessionStorage (wordlist). */
export const LEGACY_KEYS = Object.freeze({
  inventory: 'ssds.inventory',
  learned: 'ssds.learned.labels',
  wordlist: 'ssds.wordlist.custom'
});

/** Schema version of the store's records. */
export const STORE_VERSION = 1;

const META_KEY = 'meta';
const META_PREFIX = 'wsmeta/';
const DATA_PREFIX = 'wsdata/';
const metaKey = (id) => `${META_PREFIX}${id}`;
const dataKey = (id, part) => `${DATA_PREFIX}${id}/${part}`;
const slotKey = (id, part) => `${id}\n${part}`;

/**
 * A refused workspace operation. `code`: 'name-empty' | 'name-taken' | 'default' (Default cannot
 * be renamed or deleted) | 'not-found' (also the `lastError` of a write that found its workspace
 * deleted in another tab) | 'limit' (too many workspaces) | 'part' (unknown part).
 */
export class WorkspaceError extends Error {
  /**
   * @param {string} code
   * @param {string} [message]
   */
  constructor(code, message) {
    super(message || code);
    this.name = 'WorkspaceError';
    this.code = code;
  }
}

/* ------------------------------------------------------------------------ */
/* Values                                                                   */
/* ------------------------------------------------------------------------ */

// C0 / C1 controls, zero-width characters, line / paragraph separators and bidi overrides: never
// part of a name shown in the header or a file name.
// eslint-disable-next-line no-control-regex
const NAME_JUNK_RE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;
// eslint-disable-next-line no-control-regex
const TEXT_JUNK_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

/** At most `max` characters (code points) of `s`. */
function cut(s, max) {
  if (s.length <= max) return s;
  return [...s].slice(0, max).join('');
}

/** An ISO timestamp, or null for anything that is not a valid date. */
function isoOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** A deep copy of a JSON value. */
function copy(value) {
  if (value === undefined) return undefined;
  if (typeof structuredClone === 'function') return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
}

/**
 * A workspace name as it is stored and shown: NFC, controls and invisible characters removed,
 * whitespace collapsed, trimmed, at most {@link WORKSPACE_LIMITS}.name characters.
 * @param {unknown} input
 * @returns {string} '' when nothing usable is left
 */
export function normalizeWorkspaceName(input) {
  if (typeof input !== 'string') return '';
  const s = input.normalize('NFC').replace(NAME_JUNK_RE, ' ').replace(/\s+/g, ' ').trim();
  return cut(s, WORKSPACE_LIMITS.name).trim();
}

/** Names compared the way a person reads them: normalized, case-insensitive. */
function nameKey(name) {
  return normalizeWorkspaceName(name).toLowerCase();
}

/**
 * `name`, or the first free "name (2)", "name (3)" … when a workspace is already called that
 * (case-insensitive). A trailing " (n)" of `name` itself is dropped before numbering, so
 * importing "Acme (2)" next to Acme and Acme (2) gives "Acme (3)".
 * @param {string} name
 * @param {Iterable<string>} taken the names in use
 * @returns {string} '' when `name` is empty after normalizing
 */
export function uniqueWorkspaceName(name, taken) {
  const clean = normalizeWorkspaceName(name);
  if (!clean) return '';
  const used = new Set([...(taken || [])].map(nameKey));
  if (!used.has(nameKey(clean))) return clean;
  const base = clean.replace(/\s*\(\d+\)$/, '') || clean;
  for (let n = 2; ; n += 1) {
    const suffix = ` (${n})`;
    const candidate = `${cut(base, WORKSPACE_LIMITS.name - suffix.length).trim()}${suffix}`;
    if (!used.has(nameKey(candidate))) return candidate;
  }
}

/**
 * The saved inventory: `{ text, updatedAt }` (the raw text; servers are parsed again on load, as
 * state.js always did), or null when there is no text.
 */
function sanitizeInventory(value) {
  const src = typeof value === 'string' ? { text: value } : value;
  if (!src || typeof src !== 'object' || typeof src.text !== 'string') return null;
  const text = src.text.slice(0, WORKSPACE_LIMITS.inventory);
  if (!text.trim()) return null;
  return { text, updatedAt: isoOrNull(src.updatedAt) };
}

/**
 * Learned names in lib/learned.js's export shape `{ v: 1, seq, labels: { label: [hits, last] } }`:
 * only storable labels (never a full name or an address), at most WORKSPACE_LIMITS.learned (the
 * most hits first, then the most recent); null when none is left.
 */
function sanitizeLearned(value) {
  if (!value || typeof value !== 'object' || !value.labels || typeof value.labels !== 'object' || Array.isArray(value.labels)) return null;
  const rows = [];
  for (const [label, entry] of Object.entries(value.labels)) {
    if (!isStorableLabel(label)) continue;
    const pair = Array.isArray(entry) ? entry : [entry && entry.hits, entry && entry.last];
    const hits = Math.max(1, Math.floor(Number(pair[0])) || 1);
    const last = Math.max(0, Math.floor(Number(pair[1])) || 0);
    rows.push([label, hits, last]);
  }
  if (!rows.length) return null;
  rows.sort((a, b) => (b[1] - a[1]) || (b[2] - a[2]));
  const labels = {};
  let seq = Math.max(0, Math.floor(Number(value.seq)) || 0);
  for (const [label, hits, last] of rows.slice(0, WORKSPACE_LIMITS.learned)) {
    labels[label] = [hits, last];
    seq = Math.max(seq, last);
  }
  return { v: 1, seq, labels };
}

/**
 * Expected CAs: one entry per CA — a CA name ("Let's Encrypt"), a CAA identifier
 * ("letsencrypt.org") or part of a private CA's name — trimmed, whitespace collapsed, at most
 * WORKSPACE_LIMITS.expectedCa characters each, duplicates (case-insensitive) dropped, at most
 * WORKSPACE_LIMITS.expectedCas entries. A string is read one entry per line.
 * @param {unknown} value
 * @returns {string[]}
 */
export function sanitizeExpectedCas(value) {
  const list = typeof value === 'string' ? value.split(/\r?\n/) : (Array.isArray(value) ? value : []);
  const out = [];
  const seen = new Set();
  for (const raw of list) {
    if (typeof raw !== 'string') continue;
    const entry = cut(raw.normalize('NFC').replace(NAME_JUNK_RE, ' ').replace(/\s+/g, ' ').trim(), WORKSPACE_LIMITS.expectedCa).trim();
    const key = entry.toLowerCase();
    if (!entry || seen.has(key)) continue;
    seen.add(key);
    out.push(entry);
    if (out.length >= WORKSPACE_LIMITS.expectedCas) break;
  }
  return out;
}

/**
 * The recent list: `[{ value, at }]`, most recent first, one entry per domain or host name
 * (lib/session.parseTarget; an IP address, a public suffix or junk is dropped), at most
 * WORKSPACE_LIMITS.recent. A bare string counts as an entry without a time.
 * @param {unknown} value
 * @returns {Array<{ value: string, at: string|null }>}
 */
export function sanitizeRecent(value) {
  const out = [];
  const seen = new Set();
  for (const item of Array.isArray(value) ? value : []) {
    const raw = typeof item === 'string' ? item : (item && typeof item.value === 'string' ? item.value : null);
    const target = raw ? parseTarget(raw) : null;
    if (!target || target.kind === 'ip' || seen.has(target.value)) continue;
    seen.add(target.value);
    out.push({ value: target.value, at: isoOrNull(item && item.at) });
    if (out.length >= WORKSPACE_LIMITS.recent) break;
  }
  return out;
}

/**
 * A part's value as the store keeps it (every value from storage, another tab or an imported file
 * goes through here). Unknown parts are refused.
 * @param {string} part one of {@link WORKSPACE_PARTS}
 * @param {unknown} value
 * @returns {any}
 */
export function sanitizePart(part, value) {
  switch (part) {
    case 'inventory': return sanitizeInventory(value);
    case 'learned': return sanitizeLearned(value);
    case 'wordlist': return typeof value === 'string' ? value.slice(0, WORKSPACE_LIMITS.wordlist) : '';
    case 'expectedCas': return sanitizeExpectedCas(value);
    case 'notes': return typeof value === 'string' ? cut(value.replace(/\r\n?/g, '\n').replace(TEXT_JUNK_RE, ''), WORKSPACE_LIMITS.notes) : '';
    case 'recent': return sanitizeRecent(value);
    // JSON text, checked where it is read (lib/policy.js, which keeps a draft with a mistake as
    // typed; lib/rollout.js).
    case 'policy': return typeof value === 'string' ? cut(value.replace(/\r\n?/g, '\n').replace(TEXT_JUNK_RE, ''), WORKSPACE_LIMITS.policy) : '';
    case 'rollout': return typeof value === 'string' && value.length <= 262144 ? value : '';
    case 'origins': return sanitizeOriginMap(value);
    // The CT watch's baseline: JSON text too, read by lib/ctwatch.js.
    case 'ctSeen': return typeof value === 'string' ? cut(value, WORKSPACE_LIMITS.ctSeen) : '';
    // The registration watch's baseline: JSON text too, read by lib/regwatch.js.
    case 'rdapSeen': return typeof value === 'string' ? cut(value, WORKSPACE_LIMITS.rdapSeen) : '';
    // The accepted risks: JSON text, read by lib/waivers.js; never cut (a cut text is no JSON).
    case 'waivers': return typeof value === 'string' && value.length <= WORKSPACE_LIMITS.waivers ? value : '';
    // The DMARC report history (lib/dmarchistory.js): its JSON text, kept whole or not at all (a cut
    // text is no JSON; its own prune() keeps it under the cap), read and checked by readHistory.
    case 'reportHistory': return typeof value === 'string' && value.length <= WORKSPACE_LIMITS.reportHistory ? value : '';
    // What a tool found, in counts, for Home (lib/digests.js): JSON text, kept whole or not at all.
    case 'digests': return typeof value === 'string' && value.length <= WORKSPACE_LIMITS.digests ? value : '';
    default: throw new WorkspaceError('part', `unknown workspace part: ${part}`);
  }
}

/** Every part of a workspace, empty. */
export function emptyWorkspaceData() {
  return Object.fromEntries(WORKSPACE_PARTS.map((part) => [part, sanitizePart(part)]));
}

/**
 * Every part sanitized; missing parts are empty.
 * @param {object} [data]
 * @returns {ReturnType<typeof emptyWorkspaceData>}
 */
export function sanitizeWorkspaceData(data) {
  const src = data && typeof data === 'object' ? data : {};
  const out = emptyWorkspaceData();
  for (const part of WORKSPACE_PARTS) if (part in src) out[part] = sanitizePart(part, src[part]);
  return out;
}

/** Is this (sanitized) value the empty value of its part? Empty parts are not stored. */
function isEmptyPart(value) {
  return value === null || value === '' || (Array.isArray(value) && value.length === 0);
}

/** Same JSON value? */
function sameValue(a, b) {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/**
 * The recent list after working on `value` (a domain or host name; anything else leaves it as
 * it is): the entry moves to the top, unless it is there already (then nothing changes).
 * @param {unknown} list the current list
 * @param {string} value
 * @param {Date} [at]
 * @returns {Array<{ value: string, at: string|null }>}
 */
export function addRecent(list, value, at = new Date()) {
  const current = sanitizeRecent(list);
  const target = parseTarget(String(value ?? ''));
  if (!target || target.kind === 'ip') return current;
  if (current.length && current[0].value === target.value) return current;
  return [{ value: target.value, at: isoOrNull(at) }, ...current.filter((r) => r.value !== target.value)]
    .slice(0, WORKSPACE_LIMITS.recent);
}

/* ------------------------------------------------------------------------ */
/* Before workspaces: the legacy keys                                       */
/* ------------------------------------------------------------------------ */

/** getItem that never throws (private mode, a blocked or broken storage). */
function readItem(storage, key) {
  if (!storage || typeof storage.getItem !== 'function') return null;
  try {
    const v = storage.getItem(key);
    return typeof v === 'string' ? v : null;
  } catch {
    return null;
  }
}

/** JSON.parse that never throws. */
function parseJson(text) {
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * What the app stored before workspaces existed, read without changing anything: the inventory
 * and the learned names from `local` (localStorage), the custom wordlist from `session` (this
 * tab's sessionStorage). `present`: the keys that exist, usable or not (all of them go once the
 * data is safely in Default); `data`: the parts with content.
 * @param {{ local?: object|null, session?: object|null }} [storages] localStorage-like objects
 * @returns {{ data: Partial<ReturnType<typeof emptyWorkspaceData>>, present: Array<{ area: 'local'|'session', key: string }> }}
 */
export function readLegacyData({ local = null, session = null } = {}) {
  const data = {};
  const present = [];
  const inventoryRaw = readItem(local, LEGACY_KEYS.inventory);
  if (inventoryRaw !== null) {
    present.push({ area: 'local', key: LEGACY_KEYS.inventory });
    const inventory = sanitizeInventory(parseJson(inventoryRaw));
    if (inventory) data.inventory = inventory;
  }
  const learnedRaw = readItem(local, LEGACY_KEYS.learned);
  if (learnedRaw !== null) {
    present.push({ area: 'local', key: LEGACY_KEYS.learned });
    const learned = sanitizeLearned(parseJson(learnedRaw));
    if (learned) data.learned = learned;
  }
  const wordlist = readItem(session, LEGACY_KEYS.wordlist);
  if (wordlist !== null) {
    present.push({ area: 'session', key: LEGACY_KEYS.wordlist });
    if (wordlist.trim()) data.wordlist = sanitizePart('wordlist', wordlist);
  }
  return { data, present };
}

/** Remove the migrated legacy keys (guarded: a storage that throws keeps them, harmlessly). */
function removeLegacy({ local = null, session = null } = {}, present) {
  for (const { area, key } of present) {
    const storage = area === 'session' ? session : local;
    try {
      if (storage && typeof storage.removeItem === 'function') storage.removeItem(key);
    } catch {
      // nothing more to do: the 'meta' record keeps the migration from running again
    }
  }
}

/* ------------------------------------------------------------------------ */
/* Backends                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} WorkspaceBackend
 * @property {boolean} persistent  true when the data outlives the page (IndexedDB)
 * @property {() => Promise<boolean|null>} exists  does the database exist? (null: cannot tell);
 *   false lets the store start empty without creating it
 * @property {(keys: string[]) => Promise<any[]>} get  values in key order (undefined: missing)
 * @property {(prefix: string) => Promise<Array<[string, any]>>} list  every record under a key prefix
 * @property {(puts: Array<[string, any]>, deletes?: string[], opts?: { guard?: WriteGuard|null }) => Promise<boolean>} write
 *   one atomic transaction; false when its guard wrote nothing
 * @property {() => Promise<void>} destroy  delete everything (IndexedDB: the whole database)
 */

/**
 * A record read and written back in the same transaction as a write, so the write never works
 * from another tab's stale copy of it: `update(stored)` gets the stored value (undefined: none)
 * and returns the value to store, or undefined to write nothing at all (the puts and deletes
 * included).
 * @typedef {{ key: string, update: (stored: any) => any }} WriteGuard
 */

/**
 * A backend in memory: the tests' stand-in for IndexedDB (`persistent: true` makes the store
 * treat it as real storage) and the page's fallback where the browser refuses storage.
 * `fail` (tests) makes the named operations reject.
 * @param {Array<[string, any]>} [entries]
 * @param {{ persistent?: boolean, exists?: boolean|null }} [opts]
 * @returns {WorkspaceBackend & { entries(): Array<[string, any]>, fail: Set<string> }}
 */
export function createMemoryBackend(entries = [], { persistent = false, exists = undefined } = {}) {
  const map = new Map(entries.map(([k, v]) => [k, copy(v)]));
  const fail = new Set();
  const check = (op) => {
    if (fail.has(op)) {
      const err = new Error(`memory backend: ${op} refused`);
      err.name = op === 'write' ? 'QuotaExceededError' : 'UnknownError';
      throw err;
    }
  };
  return {
    persistent,
    fail,
    async exists() {
      check('exists');
      return exists === undefined ? map.size > 0 : exists;
    },
    async get(keys) {
      check('get');
      return keys.map((k) => (map.has(k) ? copy(map.get(k)) : undefined));
    },
    async list(prefix) {
      check('list');
      return [...map].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k, copy(v)]);
    },
    async write(puts = [], deletes = [], { guard = null } = {}) {
      check('write');
      let next;
      if (guard) {
        next = guard.update(map.has(guard.key) ? copy(map.get(guard.key)) : undefined);
        if (next === undefined) return false;
      }
      for (const k of deletes) map.delete(k);
      for (const [k, v] of puts) map.set(k, copy(v));
      if (guard) map.set(guard.key, copy(next));
      return true;
    },
    async destroy() {
      check('destroy');
      map.clear();
    },
    entries: () => [...map].map(([k, v]) => [k, copy(v)])
  };
}

/* ------------------------------------------------------------------------ */
/* The store                                                                */
/* ------------------------------------------------------------------------ */

/**
 * Whether a backend's failure to open says a database is there: one of a later schema version
 * (VersionError), one without the expected object store (NotFoundError) or an open that did not
 * finish in time (the IndexedDB backend's 'idb-timeout'). A refusal (UnknownError, SecurityError,
 * InvalidStateError) says nothing either way.
 * @param {Error|null} err
 * @returns {boolean}
 */
export function impliesDatabase(err) {
  return !!err && (err.name === 'VersionError' || err.name === 'NotFoundError' || err.code === 'idb-timeout');
}

/**
 * @typedef {object} WorkspaceMeta
 * @property {string} id
 * @property {string|null} name   null for Default (the UI names it in the page's language)
 * @property {string|null} createdAt   ISO; null only for a Default nothing was ever written to
 * @property {string|null} updatedAt   ISO (the last write to any of its parts); null as createdAt
 */

/** A stored meta record, checked; null when it is not one. */
function sanitizeMeta(value) {
  if (!value || typeof value !== 'object' || typeof value.id !== 'string' || !/^[a-z0-9-]{1,64}$/.test(value.id)) return null;
  const isDefault = value.id === DEFAULT_WORKSPACE_ID;
  const name = isDefault ? null : normalizeWorkspaceName(value.name);
  if (!isDefault && !name) return null;
  const createdAt = isoOrNull(value.createdAt) || new Date(0).toISOString();
  return { id: value.id, name, createdAt, updatedAt: isoOrNull(value.updatedAt) || createdAt };
}

/**
 * @typedef {object} WorkspaceStore
 * @property {() => Promise<{ active: WorkspaceMeta, list: WorkspaceMeta[], migrated: string[], persistent: boolean }>} open
 *   read the store once (later calls share the first); runs the first-run migration
 * @property {boolean} persistent  false: memory only (no IndexedDB, or it failed to open)
 * @property {boolean} database  there is persistent storage: `persistent`, or one that failed to
 *   open, which destroy() deletes all the same
 * @property {Error|null} lastError  the last failed read or write (null after a successful write)
 * @property {WorkspaceMeta} active
 * @property {ReturnType<typeof emptyWorkspaceData>} data  the active workspace's parts (treat as read-only)
 * @property {() => WorkspaceMeta[]} list  Default first, then by name
 * @property {(part: string, value: any) => Promise<boolean>} save  write one part of the active workspace
 *   (false while its parts could not be read)
 * @property {(value: string, at?: Date) => Promise<boolean>} recordRecent
 * @property {(id: string) => Promise<WorkspaceMeta>} switchTo  rejects when its parts could not be read
 * @property {(name: string, data?: object) => Promise<{ meta: WorkspaceMeta, persisted: boolean }>} create
 * @property {(id: string, name: string) => Promise<{ meta: WorkspaceMeta, persisted: boolean }>} rename
 * @property {(id: string) => Promise<{ switched: boolean, persisted: boolean }>} remove
 * @property {(id: string, data: object) => Promise<{ meta: WorkspaceMeta, persisted: boolean }>} replace
 * @property {(id: string) => Promise<ReturnType<typeof emptyWorkspaceData>>} load  a workspace's parts (a copy; rejects unread)
 * @property {() => Promise<boolean>} destroy  delete everything; memory is reset at once
 *   (`lastError` null once it succeeded)
 * @property {() => Promise<void>} idle  every write started so far has settled (before a reload, an export)
 * @property {(fn: (e: { type: 'data'|'list'|'switch'|'destroyed', parts?: string[] }) => void) => () => void} subscribe
 *   changes made by ANOTHER tab (local changes are the caller's own)
 */

/**
 * Create the workspace store.
 * @param {{ backend?: WorkspaceBackend|null, pointer?: { get(): (string|null), set(id: string): void }|null,
 *   legacy?: { local?: object|null, session?: object|null }|null,
 *   channel?: { postMessage(msg: any): void, addEventListener(type: string, fn: Function): void }|null,
 *   now?: () => Date, newId?: () => string }} [opts]
 *   `backend` null: memory; `pointer`: where the active id is remembered (null: nowhere);
 *   `legacy`: the storages to migrate from; `channel`: the other tabs
 * @returns {WorkspaceStore}
 */
export function createWorkspaceStore({
  backend = null, pointer = null, legacy = null, channel = null, now = () => new Date(),
  newId = () => `ws-${randomLabel(12)}`
} = {}) {
  let db = backend || createMemoryBackend();
  let persistent = !!db.persistent;
  /** @type {Error|null} */
  let lastError = null;
  /** @type {Map<string, WorkspaceMeta>} */
  let metas = new Map();
  let activeId = DEFAULT_WORKSPACE_ID;
  let data = emptyWorkspaceData();
  /** The 'meta' record is in the backend (every write adds it until it is). */
  let initialised = false;
  /** Default's legacy data while its migration could not be written (overlaid on every load of Default). */
  let pendingLegacy = null;
  /** A migration whose write failed (persistent store): the next write that commits carries it. */
  let unmigrated = null;
  /** Workspaces whose parts could not be read (id → error): never saved over until read. */
  const unread = new Map();
  let opening = null;
  const listeners = new Set();
  /** Writes not settled yet. */
  const inflight = new Set();
  /** The saves of each part: `${id}\n${part}` → { gen, value, pending, chain } (see schedule). */
  const slots = new Map();
  /** Bumped by "Delete all local data": a save from before it is never written after it. */
  let generation = 0;
  /** The parts (slot keys) whose last write failed: saving the same value again retries it. */
  const unwritten = new Set();
  /**
   * Workspaces created in this tab whose first write failed (a full disk for a moment, an open
   * that timed out): id → every part saved to it since, newest values. The next write to one of
   * them stores its meta as this tab has it, with these parts, so it is not lost once storage
   * works again (a missing meta means "deleted in another tab" only for a workspace that was stored).
   */
  const uncreated = new Map();
  /** The persistent backend this store fell back from ({@link degrade}): destroy() deletes it all the same. */
  let fallenBack = null;

  /** Default before anything is written to it: no dates (it was neither created nor changed yet). */
  const defaultMeta = () => ({ id: DEFAULT_WORKSPACE_ID, name: null, createdAt: null, updatedAt: null });
  const metaCopy = (m) => ({ ...m });

  function emit(event) {
    for (const fn of [...listeners]) {
      try {
        fn(event);
      } catch (err) {
        setTimeout(() => {
          throw err;
        }, 0);
      }
    }
  }

  function post(message, force = false) {
    if (!channel || !(persistent || force)) return;
    try {
      channel.postMessage(message);
    } catch {
      // a closed channel: the other tabs see the change on their next load
    }
  }

  function readPointer() {
    try {
      const id = pointer ? pointer.get() : null;
      return typeof id === 'string' ? id : null;
    } catch {
      return null;
    }
  }

  function writePointer(id) {
    try {
      if (pointer) pointer.set(id);
    } catch {
      // the pointer only decides where the next page starts
    }
  }

  /**
   * The metas of the backend, checked; Default always there (in memory until something is
   * written), and so are the workspaces of this tab not stored yet ({@link uncreated}).
   */
  async function readMetas() {
    const next = new Map();
    for (const [, value] of await db.list(META_PREFIX)) {
      const meta = sanitizeMeta(value);
      if (meta) next.set(meta.id, meta);
    }
    if (!next.has(DEFAULT_WORKSPACE_ID)) next.set(DEFAULT_WORKSPACE_ID, metas.get(DEFAULT_WORKSPACE_ID) || defaultMeta());
    for (const id of uncreated.keys()) if (!next.has(id) && metas.has(id)) next.set(id, metas.get(id));
    return next;
  }

  /** What could not be written yet, over what was read: Default's legacy data, an {@link uncreated} workspace's parts. */
  function withPending(id, out) {
    if (id === DEFAULT_WORKSPACE_ID && pendingLegacy) {
      for (const [part, value] of Object.entries(pendingLegacy)) if (isEmptyPart(out[part])) out[part] = copy(value);
    }
    for (const [part, value] of Object.entries(uncreated.get(id) || {})) out[part] = copy(value);
    return out;
  }

  /** A workspace's parts from the backend (every value sanitized); a failed read is empty ({@link unread}). */
  async function loadData(id) {
    const out = emptyWorkspaceData();
    try {
      const values = await db.get(WORKSPACE_PARTS.map((part) => dataKey(id, part)));
      WORKSPACE_PARTS.forEach((part, i) => {
        if (values[i] !== undefined) out[part] = sanitizePart(part, values[i]);
      });
      unread.delete(id);
    } catch (err) {
      lastError = err;
      unread.set(id, err);
    }
    return withPending(id, out);
  }

  /** Keep a write in `inflight` until it settles ({@link WorkspaceStore} `idle`). */
  function track(promise) {
    inflight.add(promise);
    const done = () => inflight.delete(promise);
    promise.then(done, done);
    return promise;
  }

  /**
   * Write parts of workspace `id` (empty values delete their record) and a new `updatedAt` on its
   * meta, in one transaction; tell the other tabs. Never throws.
   *
   * The meta is read and written back inside that transaction ({@link WriteGuard}), never from
   * this tab's memory: a write never undoes a rename another tab made meanwhile, and a workspace
   * another tab deleted is not written at all (it would come back; `lastError` 'not-found').
   * `create`: a new workspace, whose meta is written as this tab has it (so is the meta of an
   * {@link uncreated} one, with every part saved to it so far); `name`: a rename.
   * @returns {Promise<boolean>} written
   */
  function persist(id, parts, { list = false, create = false, name = null } = {}) {
    const at = isoOrNull(now());
    const mine = metas.get(id);
    if (mine) metas.set(id, { ...mine, createdAt: mine.createdAt || at, updatedAt: at });
    if (uncreated.has(id)) {
      parts = { ...uncreated.get(id), ...parts };
      uncreated.set(id, parts);
      create = true;
      list = true;
    }
    // Its 'meta' record ends a migration not written yet: Default's parts as this tab has them go too.
    const migration = unmigrated;
    if (migration && id === DEFAULT_WORKSPACE_ID) {
      pendingLegacy = { ...pendingLegacy, ...parts };
      parts = pendingLegacy;
    }
    const puts = create ? [[metaKey(id), metas.get(id)]] : [];
    const deletes = [];
    for (const [part, value] of Object.entries(parts)) {
      if (isEmptyPart(value)) deletes.push(dataKey(id, part));
      else puts.push([dataKey(id, part), value]);
    }
    if (migration && id !== DEFAULT_WORKSPACE_ID) {
      const def = metas.get(DEFAULT_WORKSPACE_ID);
      metas.set(DEFAULT_WORKSPACE_ID, { ...def, createdAt: def.createdAt || at, updatedAt: at });
      puts.push([metaKey(DEFAULT_WORKSPACE_ID), metas.get(DEFAULT_WORKSPACE_ID)]);
      for (const [part, value] of Object.entries(pendingLegacy || {})) if (!isEmptyPart(value)) puts.push([dataKey(DEFAULT_WORKSPACE_ID, part), value]);
    }
    if (!initialised) puts.push([META_KEY, { v: STORE_VERSION, createdAt: at, migrated: migration ? migration.migrated : [] }]);
    const guard = create ? null : {
      key: metaKey(id),
      update: (stored) => {
        // Default always exists: its first write stores its meta.
        const base = sanitizeMeta(stored) || (id === DEFAULT_WORKSPACE_ID ? defaultMeta() : null);
        if (!base) return undefined;
        return { ...base, ...(name ? { name } : {}), createdAt: base.createdAt || at, updatedAt: at };
      }
    };
    const written = Object.keys(parts).map((part) => slotKey(id, part));
    return track((async () => {
      try {
        if ((await db.write(puts, deletes, { guard })) === false) {
          throw new WorkspaceError('not-found', 'the workspace was deleted in another tab');
        }
        initialised = true;
        lastError = null;
        if (uncreated.get(id) === parts) uncreated.delete(id);
        for (const key of written) unwritten.delete(key);
        if (migration) {
          if (unmigrated === migration) unmigrated = null;
          removeLegacy(legacy || {}, migration.present);
        }
        if ((id === DEFAULT_WORKSPACE_ID || migration) && pendingLegacy) pendingLegacy = null;
        post(list ? { type: 'list' } : { type: 'data', id, parts: Object.keys(parts) });
        return true;
      } catch (err) {
        lastError = err;
        for (const key of written) unwritten.add(key);
        // Its creation is not stored: the next write to it stores the workspace (not 'not-found').
        if (create && metas.has(id) && !uncreated.has(id)) uncreated.set(id, parts);
        return false;
      }
    })());
  }

  /**
   * Write the newest value of one part: one write per part at a time, and the values saved while
   * it runs are written once after it, as the latest of them (typing into a long custom wordlist
   * writes it once per write, not once per keystroke). A write still waiting when "Delete all
   * local data" runs is dropped: it would bring the deleted database back.
   * @returns {Promise<boolean>} written
   */
  function schedule(id, part, value) {
    const key = slotKey(id, part);
    let slot = slots.get(key);
    if (!slot || slot.gen !== generation) {
      slot = { gen: generation, value, pending: null, chain: Promise.resolve(true) };
      slots.set(key, slot);
    }
    slot.value = value;
    if (!slot.pending) {
      const s = slot;
      s.pending = track(s.chain.then(() => {
        s.pending = null;
        // Never after "Delete all local data" or the workspace's deletion: it would come back.
        return s.gen === generation && metas.has(id) ? persist(id, { [part]: s.value }) : false;
      }));
      s.chain = s.pending;
    }
    return slot.pending;
  }

  /**
   * Fall back to memory for the rest of the page (the backend could not be read: a database of a
   * later schema version, a broken one, an open that timed out, or storage refused). The backend
   * is kept for "Delete all local data", which must still delete what it holds, when there is a
   * database to delete: it was listed (`exists` true), or the failure is one only a database
   * causes ({@link impliesDatabase}). A refusal is not: a browser that blocks storage for the page
   * (Chrome's "Don't allow sites to save data") answers every call, the deletion too, with an
   * UnknownError, and nothing was ever stored.
   * @param {Error} err
   * @param {boolean|null} exists what the backend's `exists()` said
   */
  function degrade(err, exists = null) {
    lastError = err;
    if (db.persistent && (exists === true || impliesDatabase(err))) fallenBack = db;
    db = createMemoryBackend();
    persistent = false;
  }

  async function doOpen() {
    const at = now();
    let meta;
    let exists = null;
    try {
      exists = await db.exists();
      if (exists !== false) [meta] = await db.get([META_KEY]);
      metas = exists === false ? new Map([[DEFAULT_WORKSPACE_ID, defaultMeta()]]) : await readMetas();
    } catch (err) {
      degrade(err, exists);
      meta = undefined;
      metas = new Map([[DEFAULT_WORKSPACE_ID, defaultMeta()]]);
    }
    initialised = !!meta;
    let migrated = [];
    if (!initialised) {
      const old = readLegacyData(legacy || {});
      migrated = Object.keys(old.data);
      if (old.present.length) {
        const stamp = isoOrNull(at);
        const known = metas.get(DEFAULT_WORKSPACE_ID);
        const def = { ...known, createdAt: known.createdAt || stamp, updatedAt: stamp };
        const puts = [[metaKey(DEFAULT_WORKSPACE_ID), def], [META_KEY, { v: STORE_VERSION, createdAt: stamp, migrated }]];
        for (const [part, value] of Object.entries(old.data)) puts.push([dataKey(DEFAULT_WORKSPACE_ID, part), value]);
        try {
          await db.write(puts, []);
          metas.set(DEFAULT_WORKSPACE_ID, def);
          initialised = true;
          // Committed: the old keys can go. In memory they stay, so the next load migrates again.
          if (persistent) removeLegacy(legacy || {}, old.present);
          else pendingLegacy = old.data;
        } catch (err) {
          lastError = err;
          pendingLegacy = old.data;
          if (persistent) unmigrated = { migrated, present: old.present };
        }
      }
    }
    const wanted = readPointer();
    activeId = wanted && metas.has(wanted) ? wanted : DEFAULT_WORKSPACE_ID;
    // No database and nothing written to one: nothing to read either (a read would create it).
    data = exists === false && !initialised ? withPending(activeId, emptyWorkspaceData()) : await loadData(activeId);
    if (unread.has(activeId) && activeId !== DEFAULT_WORKSPACE_ID) {
      // Unread: Default instead (see switchTo).
      activeId = DEFAULT_WORKSPACE_ID;
      data = await loadData(activeId);
    }
    if (channel && typeof channel.addEventListener === 'function') {
      channel.addEventListener('message', (event) => {
        onMessage(event && 'data' in event ? event.data : event).catch((err) => {
          lastError = err;
        });
      });
    }
    return { active: metaCopy(metas.get(activeId)), list: api.list(), migrated, persistent };
  }

  /** Another tab changed the store. */
  async function onMessage(msg) {
    if (!msg || typeof msg !== 'object') return;
    if (msg.type === 'destroyed') {
      reset();
      emit({ type: 'destroyed' });
      return;
    }
    // Another tab wrote: the store holds the migrated data, and this tab's copy would undo newer saves.
    unmigrated = null;
    if (msg.type === 'data' && msg.id === activeId && Array.isArray(msg.parts)) {
      const id = activeId;
      const parts = msg.parts.filter((p) => WORKSPACE_PARTS.includes(p));
      const values = await db.get(parts.map((p) => dataKey(id, p)));
      if (id !== activeId) return;
      const next = { ...data };
      parts.forEach((part, i) => {
        next[part] = values[i] === undefined ? emptyWorkspaceData()[part] : sanitizePart(part, values[i]);
      });
      data = next;
      emit({ type: 'data', parts });
      return;
    }
    if (msg.type === 'list') {
      metas = await readMetas();
      if (!metas.has(activeId)) {
        // The active workspace was deleted in another tab: this one goes on in Default.
        activeId = DEFAULT_WORKSPACE_ID;
        data = await loadData(activeId);
        emit({ type: 'switch' });
      }
      emit({ type: 'list' });
    }
  }

  /** Memory back to a fresh store: Default only, empty. */
  function reset() {
    metas = new Map([[DEFAULT_WORKSPACE_ID, defaultMeta()]]);
    activeId = DEFAULT_WORKSPACE_ID;
    data = emptyWorkspaceData();
    initialised = false;
    pendingLegacy = null;
    unmigrated = null;
    unread.clear();
    generation += 1;
    slots.clear();
    unwritten.clear();
    uncreated.clear();
  }

  function requireNamed(id) {
    if (id === DEFAULT_WORKSPACE_ID) throw new WorkspaceError('default');
    if (!metas.has(id)) throw new WorkspaceError('not-found');
  }

  function checkName(name, exceptId = null) {
    const clean = normalizeWorkspaceName(name);
    if (!clean) throw new WorkspaceError('name-empty');
    const key = nameKey(clean);
    for (const m of metas.values()) {
      if (m.id !== exceptId && m.name && nameKey(m.name) === key) throw new WorkspaceError('name-taken');
    }
    return clean;
  }

  const api = {
    open() {
      if (!opening) opening = doOpen();
      return opening;
    },

    get persistent() {
      return persistent;
    },

    get database() {
      return persistent || !!fallenBack;
    },

    get lastError() {
      return lastError;
    },

    get active() {
      return metaCopy(metas.get(activeId) || defaultMeta());
    },

    get data() {
      return data;
    },

    list() {
      const all = [...metas.values()].map(metaCopy);
      const named = all.filter((m) => m.id !== DEFAULT_WORKSPACE_ID)
        .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }) || a.id.localeCompare(b.id));
      return [...all.filter((m) => m.id === DEFAULT_WORKSPACE_ID), ...named];
    },

    async save(part, value) {
      const clean = sanitizePart(part, value);
      const key = slotKey(activeId, part);
      if (sameValue(data[part], clean)) {
        // Nothing new: its write is done or on its way — unless the last write of this value
        // failed (a full disk), which saving it again retries.
        const slot = slots.get(key);
        if (slot && slot.pending && slot.gen === generation) return slot.pending;
        if (!unwritten.has(key)) return true;
      } else {
        data = { ...data, [part]: clean };
      }
      if (unread.has(activeId)) {
        // It would replace what could not be read: memory only.
        lastError = unread.get(activeId);
        return false;
      }
      return schedule(activeId, part, clean);
    },

    recordRecent(value, at = now()) {
      const next = addRecent(data.recent, value, at);
      return api.save('recent', next);
    },

    async switchTo(id) {
      if (!metas.has(id)) throw new WorkspaceError('not-found');
      const next = await loadData(id);
      // Its saves would replace what is stored.
      if (unread.has(id)) throw unread.get(id);
      activeId = id;
      data = next;
      writePointer(id);
      return api.active;
    },

    async create(name, parts = null) {
      const clean = checkName(name);
      if (metas.size >= WORKSPACE_LIMITS.count + 1) throw new WorkspaceError('limit');
      const at = isoOrNull(now());
      let id = newId();
      while (metas.has(id) || !/^[a-z0-9-]{1,64}$/.test(id)) id = newId();
      const meta = { id, name: clean, createdAt: at, updatedAt: at };
      metas.set(id, meta);
      const persisted = await persist(id, parts ? sanitizeWorkspaceData(parts) : {}, { list: true, create: true });
      return { meta: metaCopy(metas.get(id)), persisted };
    },

    async rename(id, name) {
      requireNamed(id);
      const clean = checkName(name, id);
      metas.set(id, { ...metas.get(id), name: clean });
      const persisted = await persist(id, {}, { list: true, name: clean });
      return { meta: metaCopy(metas.get(id)), persisted };
    },

    async remove(id) {
      requireNamed(id);
      metas.delete(id);
      // A save still waiting for it would write the workspace back.
      for (const part of WORKSPACE_PARTS) {
        const slot = slots.get(slotKey(id, part));
        if (slot) slot.gen = -1;
        slots.delete(slotKey(id, part));
        unwritten.delete(slotKey(id, part));
      }
      uncreated.delete(id);
      unread.delete(id);
      let persisted = true;
      try {
        await track(db.write([], [metaKey(id), ...WORKSPACE_PARTS.map((part) => dataKey(id, part))]));
        post({ type: 'list' });
      } catch (err) {
        lastError = err;
        persisted = false;
      }
      const switched = activeId === id;
      if (switched) {
        // Read or not (then never saved over).
        data = await loadData(DEFAULT_WORKSPACE_ID);
        activeId = DEFAULT_WORKSPACE_ID;
        writePointer(DEFAULT_WORKSPACE_ID);
      }
      return { switched, persisted };
    },

    async replace(id, parts) {
      if (!metas.has(id)) throw new WorkspaceError('not-found');
      const clean = sanitizeWorkspaceData(parts);
      if (id === activeId) data = clean;
      unread.delete(id);
      // A save still waiting for this workspace writes the new value, not the one it replaced.
      for (const part of WORKSPACE_PARTS) {
        const slot = slots.get(slotKey(id, part));
        if (slot) slot.value = clean[part];
      }
      const persisted = await persist(id, clean);
      return { meta: metaCopy(metas.get(id)), persisted };
    },

    async load(id) {
      if (!metas.has(id)) throw new WorkspaceError('not-found');
      const out = copy(id === activeId ? data : await loadData(id));
      if (unread.has(id)) throw unread.get(id);
      return out;
    },

    destroy() {
      // The pointer is left alone: "Delete all local data" removes it with the other 'ssds.*'
      // keys, and a pointer to a workspace that is gone opens Default anyway.
      reset();
      return (async () => {
        try {
          await db.destroy();
          // Storage this page could not read (it works in memory) is deleted all the same: the
          // other customers' data must not stay behind in it. IndexedDB deletes a database of
          // any version without opening it.
          if (fallenBack) await fallenBack.destroy();
          lastError = null;
          post({ type: 'destroyed' }, !!fallenBack);
          return true;
        } catch (err) {
          lastError = err;
          return false;
        }
      })();
    },

    async idle() {
      while (inflight.size) await Promise.allSettled([...inflight]);
    },

    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    }
  };

  return api;
}
