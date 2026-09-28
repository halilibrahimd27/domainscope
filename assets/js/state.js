/**
 * state.js — shared application state: the active customer workspace (lib/workspace.js, kept in
 * IndexedDB), the tool's global settings (localStorage) and a memory-only session.
 *
 * Slices:
 *   - inventory (the active workspace's): { text, servers, warnings, stats, updatedAt }
 *       Only `text` + `updatedAt` are stored; servers/warnings are re-derived with
 *       lib/inventory.parseInventory on load, so a parser upgrade never meets stale data.
 *   - the active workspace's other parts (lib/workspace.js WORKSPACE_PARTS: learned names, custom
 *       wordlist, expected CAs, notes, recent domains): `workspaceData(part)` / `setWorkspaceData()`;
 *       the learned names also through `learnedStorage`, a Storage-like view for lib/learned.js.
 *   - settings (localStorage, the same in every workspace): { lang, theme, chain, concurrency, startTasks }
 *   - session (memory only): free-form key/value for handing data between views,
 *       e.g. the cert view stores `pendingCert` and the scan view `takeSession('pendingCert')`s it.
 *
 * Workspaces: `ready` resolves once the workspace store is open (the first-run migration of the
 * data kept before workspaces included); the shell waits for it before the first view mounts.
 * `switchWorkspace()` loads another workspace, forgets the session (it belonged to the other
 * customer) and emits 'inventory' then 'workspace'; the views that keep a customer's results in
 * module state drop them on 'workspace', as they do on 'cleared'.
 *
 * Every storage access is wrapped in try/catch: private mode, disabled storage or a
 * full quota degrade to in-memory state (see `persistence`, `workspacePersistence`,
 * `lastPersistError`, `workspaceError`). localStorage keys are prefixed 'ssds.'. Other tabs'
 * settings arrive via the `storage` event, their workspace writes via the store's channel.
 *
 * Stored records carry a schema version `v`. Settings are at v2: loading an older record runs
 * {@link migrateSettings} once (a resolver chain still equal to a former built-in default
 * becomes today's DEFAULT_CHAIN; customised chains are kept) and writes it back as v2.
 *
 * @example
 *   import { state } from './state.js';
 *   await state.ready;
 *   const off = state.subscribe(({ key, value }) => { if (key === 'inventory') redraw(value); });
 *   state.setInventory('web01 10.0.0.5\nweb02 10.0.0.6');
 *   const index = state.getInventoryIndex();           // Map<ip, Server[]> (memoized)
 *   state.updateSettings({ concurrency: 16 });
 *   await state.switchWorkspace((await state.createWorkspace('Acme')).meta.id);
 */

import { parseInventory, buildIpIndex } from './lib/inventory.js';
import { RESOLVERS, DEFAULT_CHAIN } from './lib/resolvers.js';
import {
  createWorkspaceStore, DEFAULT_WORKSPACE_ID, ACTIVE_WORKSPACE_KEY, WORKSPACE_PARTS
} from './lib/workspace.js';
import { createIdbBackend, WORKSPACE_DB_NAME } from './workspace-db.js';

/** Prefix for every localStorage key owned by the app. */
export const STORAGE_PREFIX = 'ssds.';
const KEY_SETTINGS = `${STORAGE_PREFIX}settings`;
/** Schema version of the stored settings record (2: DEFAULT_CHAIN without Quad9, 2026-09-23). */
export const SETTINGS_VERSION = 2;

/**
 * Resolver chains that used to be the built-in default. A settings record older than
 * {@link SETTINGS_VERSION} whose chain is exactly one of these was never customised (the whole
 * settings object is saved on any change, e.g. of the theme), so it follows the new default.
 */
export const LEGACY_DEFAULT_CHAINS = Object.freeze([
  // v1.0.0 until 2026-09-23. Quad9 left the default: browsers cannot read its HTTP/3 answers
  // (no CORS header), so every lookup it was asked first had to fail over.
  Object.freeze(['cloudflare', 'google', 'quad9', 'dnssb'])
]);

/** Valid theme values. */
export const THEMES = Object.freeze(['auto', 'light', 'dark']);
/** Allowed DoH concurrency range. */
export const CONCURRENCY_RANGE = Object.freeze({ min: 1, max: 32 });

/**
 * Default settings (lang null = follow the browser). `startTasks`: the start page still offers
 * its first-visit task picker (app.js turns it off once it is dismissed or the visitor ran something).
 */
export const DEFAULT_SETTINGS = Object.freeze({
  lang: null,
  theme: 'auto',
  chain: Object.freeze([...DEFAULT_CHAIN]),
  concurrency: 12,
  startTasks: true
});

const RESOLVER_IDS = new Set(RESOLVERS.map((r) => r.id));

/**
 * Validate/normalize a settings object; unknown or invalid fields fall back to defaults.
 * @param {object} input
 * @returns {{ lang: 'tr'|'en'|null, theme: 'auto'|'light'|'dark', chain: string[], concurrency: number, startTasks: boolean }}
 */
export function sanitizeSettings(input) {
  const src = input && typeof input === 'object' ? input : {};
  const lang = src.lang === 'tr' || src.lang === 'en' ? src.lang : null;
  const theme = THEMES.includes(src.theme) ? src.theme : DEFAULT_SETTINGS.theme;
  let chain = Array.isArray(src.chain) ? [...new Set(src.chain.filter((id) => RESOLVER_IDS.has(id)))] : [];
  if (!chain.length) chain = [...DEFAULT_SETTINGS.chain];
  let concurrency = Math.round(Number(src.concurrency));
  if (!Number.isFinite(concurrency)) concurrency = DEFAULT_SETTINGS.concurrency;
  concurrency = Math.min(CONCURRENCY_RANGE.max, Math.max(CONCURRENCY_RANGE.min, concurrency));
  // Only an explicit false turns the picker off: records written before it existed keep it.
  const startTasks = src.startTasks !== false;
  return { lang, theme, chain, concurrency, startTasks };
}

/**
 * Bring a stored settings record up to {@link SETTINGS_VERSION} (pure; the input is not changed).
 * v1 → v2: a chain exactly equal to one of {@link LEGACY_DEFAULT_CHAINS} becomes DEFAULT_CHAIN;
 * any other chain (reordered, trimmed, extended — a user's choice) is kept as it is.
 * Records without `v` are treated as v1; current or newer records are returned unchanged.
 * @param {object|null} data raw record as read from storage (may include `v`)
 * @returns {{ data: object, migrated: boolean }} `migrated` is true when the record was older
 *   (it should then be written back so the migration runs only once)
 */
export function migrateSettings(data) {
  const src = data && typeof data === 'object' ? data : {};
  const version = Number.isInteger(src.v) && src.v > 0 ? src.v : 1;
  if (version >= SETTINGS_VERSION) return { data: src, migrated: false };
  const out = { ...src, v: SETTINGS_VERSION };
  const chain = Array.isArray(src.chain) ? src.chain : null;
  if (chain && LEGACY_DEFAULT_CHAINS.some((old) => old.length === chain.length && old.every((id, i) => id === chain[i]))) {
    out.chain = [...DEFAULT_CHAIN];
  }
  return { data: out, migrated: true };
}

/** Resolve the browser's localStorage without throwing (SecurityError in some sandboxes). */
function defaultStorage() {
  try {
    const s = globalThis.localStorage;
    if (!s) return null;
    const probe = `${STORAGE_PREFIX}probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

/** Resolve the browser's sessionStorage without throwing (it held this tab's custom wordlist before workspaces). */
function defaultSessionStorage() {
  try {
    return globalThis.sessionStorage || null;
  } catch {
    return null;
  }
}

/** The other tabs of this origin (a page only: never in Node, where a channel would keep the process alive). */
function defaultChannel() {
  if (typeof globalThis.document === 'undefined' || typeof globalThis.BroadcastChannel !== 'function') return null;
  try {
    return new globalThis.BroadcastChannel(WORKSPACE_DB_NAME);
  } catch {
    return null;
  }
}

/** The active-workspace pointer in localStorage (lib/workspace.js guards every access). */
function storagePointer(storage) {
  if (!storage) return null;
  return {
    get: () => storage.getItem(ACTIVE_WORKSPACE_KEY),
    set: (id) => storage.setItem(ACTIVE_WORKSPACE_KEY, id)
  };
}

/** Remove every 'ssds.*' key of a Storage (collected first: removing shifts the indexes). */
function removePrefixed(store) {
  const keys = [];
  for (let i = 0; i < store.length; i += 1) {
    const k = store.key(i);
    if (k && k.startsWith(STORAGE_PREFIX)) keys.push(k);
  }
  keys.forEach((k) => store.removeItem(k));
}

function emptyInventory() {
  return { text: '', servers: [], warnings: [], stats: { lines: 0, servers: 0, ips: 0 }, updatedAt: null };
}

/**
 * @typedef {object} StateChange
 * @property {'inventory'|'settings'|'session'|'cleared'|'workspace'|'workspaces'|'workspaceData'} key
 *   'cleared': "Delete all local data" ran (views drop what they keep outside the slices);
 *   'workspace': another workspace is active (the session was cleared; views drop the previous
 *   customer's results); 'workspaces': the list or a name changed; 'workspaceData': parts of the
 *   active workspace other than the inventory changed (value `{ parts }`)
 * @property {any} value the new slice value (for 'session': { name, value }; for 'cleared': true;
 *   'workspace': the active workspace; 'workspaces': the list)
 * @property {'local'|'external'|'load'} origin 'external' when another tab changed storage; 'load'
 *   when the workspace store has just opened
 */

/**
 * @typedef {object} ActiveWorkspace
 * @property {string} id
 * @property {string|null} name  null for Default (the UI names it in the page's language)
 * @property {boolean} isDefault
 * @property {string|null} createdAt  null (as updatedAt) only for a Default nothing was written to yet
 * @property {string|null} updatedAt
 */

/**
 * Create an isolated app state (the app uses the {@link state} singleton; tests inject storage and
 * a workspace store over an in-memory backend). `sessionStore` is used by {@link clearAll}, which
 * removes this tab's 'ssds.*' session keys, and by the first-run migration (the custom wordlist
 * this tab kept before workspaces).
 * @param {{ storage?: Storage|null, sessionStore?: Storage|null, parse?: typeof parseInventory, now?: () => Date,
 *   listenStorageEvents?: boolean, workspaces?: import('./lib/workspace.js').WorkspaceStore|null }} [opts]
 */
export function createState({
  storage = defaultStorage(),
  sessionStore = defaultSessionStorage(),
  parse = parseInventory,
  now = () => new Date(),
  listenStorageEvents = true,
  workspaces = null
} = {}) {
  /** @type {Set<(change: StateChange) => void>} */
  const listeners = new Set();
  const store = workspaces || createWorkspaceStore({
    backend: createIdbBackend(),
    pointer: storagePointer(storage),
    legacy: { local: storage, session: sessionStore },
    channel: defaultChannel(),
    now
  });
  let inventory = emptyInventory();
  let settings = { ...DEFAULT_SETTINGS, chain: [...DEFAULT_SETTINGS.chain] };
  let index = null;
  /** @type {Error|null} */
  let lastPersistError = null;
  /** The parts the first-run migration moved into Default (empty when there was nothing). */
  let migrated = [];
  /** The workspace this page shows (to notice when another tab's change moved it). */
  let activeId = DEFAULT_WORKSPACE_ID;
  /** Plain mutable object: `state.session.pendingCert = cert` works; setSession also notifies. */
  const session = Object.create(null);

  function read(key) {
    if (!storage) return null;
    try {
      const raw = storage.getItem(key);
      if (raw === null || raw === undefined) return null;
      const data = JSON.parse(raw);
      return data && typeof data === 'object' ? data : null;
    } catch {
      return null; // corrupt JSON or storage error → defaults
    }
  }

  function write(key, value) {
    if (!storage) return false;
    try {
      if (value === null) storage.removeItem(key);
      else storage.setItem(key, JSON.stringify({ v: SETTINGS_VERSION, ...value }));
      lastPersistError = null;
      return true;
    } catch (err) {
      lastPersistError = err instanceof Error ? err : new Error(String(err));
      return false;
    }
  }

  function emit(key, value, origin = 'local') {
    for (const fn of [...listeners]) {
      try {
        fn({ key, value, origin });
      } catch (err) {
        setTimeout(() => {
          throw err;
        }, 0);
      }
    }
  }

  function deriveInventory(text, updatedAt) {
    const src = typeof text === 'string' ? text : '';
    if (!src.trim()) return { ...emptyInventory(), text: src, updatedAt };
    const parsed = parse(src);
    return {
      text: src,
      servers: parsed.servers,
      warnings: parsed.warnings,
      stats: parsed.stats,
      updatedAt
    };
  }

  /** The inventory slice of a stored inventory part ({ text, updatedAt } or null). */
  function inventoryOf(part) {
    if (!part || typeof part.text !== 'string') return emptyInventory();
    const at = part.updatedAt ? new Date(part.updatedAt) : null;
    return deriveInventory(part.text, at && !Number.isNaN(at.getTime()) ? at : null);
  }

  /** The active workspace as the app shows it. */
  function activeOf(meta) {
    return { ...meta, isDefault: meta.id === DEFAULT_WORKSPACE_ID };
  }

  /**
   * Another workspace is active (a switch, a deletion, or another tab): its inventory, a fresh
   * session, then 'inventory' and 'workspace'.
   */
  function applyActive(origin) {
    activeId = store.active.id;
    inventory = inventoryOf(store.data.inventory);
    index = null;
    for (const k of Object.keys(session)) delete session[k];
    emit('inventory', inventory, origin);
    emit('workspace', api.workspace, origin);
  }

  /**
   * @param {{ persistMigration?: boolean }} [opts] write a migrated record back (at start-up
   *   only: re-reading another tab's change must not start a write ping-pong with an older
   *   version of the app still open in that tab)
   */
  function loadSettings({ persistMigration = false } = {}) {
    const raw = read(KEY_SETTINGS);
    if (!raw) return sanitizeSettings({});
    const { data, migrated: older } = migrateSettings(raw);
    const next = sanitizeSettings(data);
    if (older && persistMigration) write(KEY_SETTINGS, next);
    return next;
  }

  settings = loadSettings({ persistMigration: true });

  // Changes another tab made to the workspaces.
  store.subscribe((e) => {
    if (e.type === 'data') {
      if (e.parts.includes('inventory')) {
        inventory = inventoryOf(store.data.inventory);
        index = null;
        emit('inventory', inventory, 'external');
      }
      const rest = e.parts.filter((p) => p !== 'inventory');
      if (rest.length) emit('workspaceData', { parts: rest }, 'external');
    } else if (e.type === 'list') {
      emit('workspaces', api.workspaces, 'external');
    } else if (e.type === 'switch') {
      applyActive('external');
    } else if (e.type === 'destroyed') {
      emit('workspaces', api.workspaces, 'external');
      if (activeId !== DEFAULT_WORKSPACE_ID) {
        applyActive('external');
      } else {
        inventory = emptyInventory();
        index = null;
        emit('inventory', inventory, 'external');
        emit('workspaceData', { parts: WORKSPACE_PARTS.filter((p) => p !== 'inventory') }, 'external');
      }
    }
  });

  const ready = store.open().then((opened) => {
    migrated = opened.migrated;
    activeId = store.active.id;
    inventory = inventoryOf(store.data.inventory);
    index = null;
    emit('inventory', inventory, 'load');
    emit('workspaces', api.workspaces, 'load');
    return opened;
  });

  const api = {
    /** Resolves once the workspace store is open and the active workspace loaded. */
    ready,

    /** Current inventory (treat as read-only). */
    get inventory() {
      return inventory;
    },

    /** Current settings (a copy; change them with updateSettings). */
    get settings() {
      return { ...settings, chain: [...settings.chain] };
    },

    /** True when localStorage works (settings); false → settings live only in this tab. */
    get persistence() {
      return !!storage;
    },

    /** True when the workspaces are stored (IndexedDB); false → they last until the tab closes. */
    get workspacePersistence() {
      return store.persistent;
    },

    /** Error from the last failed settings write (e.g. QuotaExceededError), or null. */
    get lastPersistError() {
      return lastPersistError;
    },

    /** Error from the last failed workspace read or write, or null after a successful write. */
    get workspaceError() {
      return store.lastError;
    },

    /** The parts the first-run migration moved into Default ([] when there was nothing to move). */
    get migrated() {
      return [...migrated];
    },

    /** @returns {ActiveWorkspace} the workspace this page works in */
    get workspace() {
      return activeOf(store.active);
    },

    /** @returns {ActiveWorkspace[]} every workspace, Default first */
    get workspaces() {
      return store.list().map(activeOf);
    },

    /**
     * A copy of one part of the active workspace (lib/workspace.js WORKSPACE_PARTS).
     * @param {string} part
     * @returns {any}
     */
    workspaceData(part) {
      if (!WORKSPACE_PARTS.includes(part)) throw new RangeError(`unknown workspace part: ${part}`);
      const value = store.data[part];
      return value && typeof value === 'object' ? structuredClone(value) : value;
    },

    /**
     * Change one part of the active workspace (not the inventory: {@link setInventory}); emits
     * 'workspaceData' when it really changed.
     * @param {string} part
     * @param {any} value
     * @returns {Promise<boolean>} written to storage
     */
    setWorkspaceData(part, value) {
      if (part === 'inventory' || !WORKSPACE_PARTS.includes(part)) throw new RangeError(`not a workspace part here: ${part}`);
      const before = store.data[part];
      const done = store.save(part, value);
      if (store.data[part] !== before) emit('workspaceData', { parts: [part] });
      return done;
    },

    /**
     * A domain or host name the user worked on goes to the top of the workspace's recent list.
     * @param {string} value
     * @returns {Promise<boolean>}
     */
    recordRecent(value) {
      const before = store.data.recent;
      const done = store.recordRecent(value, now());
      if (store.data.recent !== before) emit('workspaceData', { parts: ['recent'] });
      return done;
    },

    /**
     * The learned names of the active workspace as a Storage-like object for
     * lib/learned.js createLearnedStore (its key is ignored: there is one list per workspace).
     */
    learnedStorage: {
      getItem() {
        const value = store.data.learned;
        return value ? JSON.stringify(value) : null;
      },
      setItem(_key, value) {
        let parsed = null;
        try {
          parsed = JSON.parse(value);
        } catch {
          parsed = null;
        }
        api.setWorkspaceData('learned', parsed);
      }
    },

    /**
     * Work in another workspace: its data is loaded, the session is cleared, then 'inventory'
     * and 'workspace' are emitted.
     * @param {string} id
     * @returns {Promise<ActiveWorkspace>}
     */
    async switchWorkspace(id) {
      await store.switchTo(id);
      applyActive('local');
      return api.workspace;
    },

    /**
     * A new, empty workspace (or one holding `data`: an imported file). It does not become active.
     * @param {string} name
     * @param {object} [data]
     * @returns {Promise<{ meta: ActiveWorkspace, persisted: boolean }>}
     * @throws {import('./lib/workspace.js').WorkspaceError} name-empty, name-taken, limit
     */
    async createWorkspace(name, data = null) {
      const res = await store.create(name, data);
      emit('workspaces', api.workspaces);
      return { meta: activeOf(res.meta), persisted: res.persisted };
    },

    /**
     * @param {string} id
     * @param {string} name
     * @returns {Promise<{ meta: ActiveWorkspace, persisted: boolean }>}
     */
    async renameWorkspace(id, name) {
      const res = await store.rename(id, name);
      emit('workspaces', api.workspaces);
      return { meta: activeOf(res.meta), persisted: res.persisted };
    },

    /**
     * Delete a workspace and everything in it; deleting the active one switches to Default.
     * @param {string} id
     * @returns {Promise<{ switched: boolean, persisted: boolean }>}
     */
    async deleteWorkspace(id) {
      const res = await store.remove(id);
      emit('workspaces', api.workspaces);
      if (res.switched) applyActive('local');
      return res;
    },

    /**
     * Replace every part of a workspace (an imported file over an existing workspace).
     * @param {string} id
     * @param {object} data
     * @returns {Promise<{ meta: ActiveWorkspace, persisted: boolean }>}
     */
    async replaceWorkspace(id, data) {
      const res = await store.replace(id, data);
      if (id === store.active.id) {
        inventory = inventoryOf(store.data.inventory);
        index = null;
        emit('inventory', inventory);
        emit('workspaceData', { parts: WORKSPACE_PARTS.filter((p) => p !== 'inventory') });
      }
      emit('workspaces', api.workspaces);
      return { meta: activeOf(res.meta), persisted: res.persisted };
    },

    /**
     * A copy of every part of a workspace (for the hand-over file).
     * @param {string} id
     * @returns {Promise<object>}
     */
    loadWorkspace(id) {
      return store.load(id);
    },

    /** Resolves once every workspace write started so far has settled (before a reload, say). */
    whenSaved() {
      return store.idle();
    },

    /**
     * Replace the active workspace's inventory, parse it and persist it.
     * @param {string|{ text: string }} input raw inventory text
     * @returns {{ persisted: boolean, inventory: object, done: Promise<boolean> }} `persisted`: the
     *   workspaces are stored at all (false: memory only); `done`: whether this write succeeded
     */
    setInventory(input) {
      const text = typeof input === 'string' ? input : (input && typeof input.text === 'string' ? input.text : '');
      const at = now();
      inventory = deriveInventory(text, text.trim() ? at : null);
      index = null;
      const done = store.save('inventory', text.trim() ? { text, updatedAt: at.toISOString() } : null);
      emit('inventory', inventory);
      return { persisted: store.persistent, inventory, done };
    },

    /** Remove the active workspace's inventory. @returns {boolean} the workspaces are stored */
    clearInventory() {
      inventory = emptyInventory();
      index = null;
      store.save('inventory', null);
      emit('inventory', inventory);
      return store.persistent;
    },

    /**
     * Memoized IP → servers index of the current inventory (lib/inventory.buildIpIndex).
     * Use with lookupServers(ips, index).
     * @returns {Map<string, object[]>}
     */
    getInventoryIndex() {
      if (!index) index = buildIpIndex(inventory.servers);
      return index;
    },

    /**
     * Merge and persist settings (validated with {@link sanitizeSettings}).
     * @param {Partial<{ lang: 'tr'|'en'|null, theme: string, chain: string[], concurrency: number, startTasks: boolean }>} patch
     * @returns {{ lang, theme, chain, concurrency, startTasks }} the new settings
     */
    updateSettings(patch) {
      const next = sanitizeSettings({ ...settings, ...(patch || {}) });
      const changed = JSON.stringify(next) !== JSON.stringify(settings);
      settings = next;
      if (changed) {
        write(KEY_SETTINGS, settings);
        emit('settings', api.settings);
      }
      return api.settings;
    },

    /** Restore default settings (language/theme included). */
    resetSettings() {
      settings = sanitizeSettings({});
      write(KEY_SETTINGS, null);
      emit('settings', api.settings);
      return api.settings;
    },

    /**
     * Store a non-persisted session value (e.g. 'pendingCert') and notify subscribers.
     * @param {string} name
     * @param {any} value undefined deletes
     */
    setSession(name, value) {
      if (value === undefined) delete session[name];
      else session[name] = value;
      emit('session', { name, value });
    },

    /** @param {string} name @returns {any} */
    getSession(name) {
      return session[name];
    },

    /**
     * Read and remove a session value in one step (one-shot hand-over between views).
     * @param {string} name
     * @returns {any}
     */
    takeSession(name) {
      const value = session[name];
      delete session[name];
      return value;
    },

    /**
     * The live session object (not persisted). Direct writes work but do not notify
     * subscribers; prefer setSession() when other views should react.
     */
    get session() {
      return session;
    },

    /**
     * Subscribe to changes.
     * @param {(change: StateChange) => void} fn
     * @returns {() => void} unsubscribe
     */
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },

    /**
     * "Delete all local data": delete every workspace (the IndexedDB database included), every
     * 'ssds.*' key from localStorage (settings, remembered view options, the active-workspace
     * pointer) and from this tab's session storage, reset all slices (session too) and notify:
     * 'inventory', 'settings', 'workspaces', then 'cleared'. Memory is reset at once; the promise
     * says whether the storage was really emptied.
     * @returns {Promise<boolean>} true when localStorage was cleaned and the database deleted
     */
    clearAll() {
      let ok = !!storage;
      if (storage) {
        try {
          removePrefixed(storage);
        } catch (err) {
          lastPersistError = err instanceof Error ? err : new Error(String(err));
          ok = false;
        }
      }
      if (sessionStore && sessionStore !== storage) {
        try {
          removePrefixed(sessionStore);
        } catch {
          // a blocked session storage holds nothing of ours
        }
      }
      const destroyed = store.destroy();
      activeId = DEFAULT_WORKSPACE_ID;
      inventory = emptyInventory();
      index = null;
      settings = sanitizeSettings({});
      for (const k of Object.keys(session)) delete session[k];
      emit('inventory', inventory);
      emit('settings', api.settings);
      emit('workspaces', api.workspaces);
      emit('cleared', true);
      return destroyed.then((deleted) => ok && deleted);
    },

    /**
     * Re-read the settings after another tab changed them (wired to the `storage` event). The
     * workspaces tell each other through their own channel.
     * @param {string|null} key storage key, or null when the other tab cleared storage
     */
    handleExternalChange(key) {
      if (key === null || key === KEY_SETTINGS) {
        settings = loadSettings();
        emit('settings', api.settings, 'external');
      }
    }
  };

  if (listenStorageEvents && storage && typeof globalThis.addEventListener === 'function') {
    globalThis.addEventListener('storage', (event) => {
      if (event.storageArea && event.storageArea !== storage) return;
      if (event.key === null || (typeof event.key === 'string' && event.key.startsWith(STORAGE_PREFIX))) {
        api.handleExternalChange(event.key);
      }
    });
  }

  return api;
}

/** The app-wide state singleton (views receive it as `ctx.state`). */
export const state = createState();
