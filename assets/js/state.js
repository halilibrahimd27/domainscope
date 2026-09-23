/**
 * state.js — shared application state with localStorage persistence.
 *
 * Three slices:
 *   - inventory (persisted): { text, servers, warnings, stats, updatedAt }
 *       Only `text` + `updatedAt` are stored; servers/warnings are re-derived with
 *       lib/inventory.parseInventory on load, so a parser upgrade never meets stale data.
 *   - settings (persisted):  { lang, theme, chain, concurrency }
 *   - session (memory only): free-form key/value for handing data between views,
 *       e.g. the cert view stores `pendingCert` and the scan view `takeSession('pendingCert')`s it.
 *
 * Every storage access is wrapped in try/catch: private mode, disabled storage or a
 * full quota degrade to in-memory state (see `persistence` / `lastPersistError`).
 * Keys are prefixed 'ssds.'. Other tabs' changes arrive via the `storage` event.
 *
 * @example
 *   import { state } from './state.js';
 *   const off = state.subscribe(({ key, value }) => { if (key === 'inventory') redraw(value); });
 *   state.setInventory('web01 10.0.0.5\nweb02 10.0.0.6');
 *   const index = state.getInventoryIndex();           // Map<ip, Server[]> (memoized)
 *   state.updateSettings({ concurrency: 16 });
 */

import { parseInventory, buildIpIndex } from './lib/inventory.js';
import { RESOLVERS, DEFAULT_CHAIN } from './lib/resolvers.js';

/** Prefix for every localStorage key owned by the app. */
export const STORAGE_PREFIX = 'ssds.';
const KEY_INVENTORY = `${STORAGE_PREFIX}inventory`;
const KEY_SETTINGS = `${STORAGE_PREFIX}settings`;
const SCHEMA_VERSION = 1;

/** Valid theme values. */
export const THEMES = Object.freeze(['auto', 'light', 'dark']);
/** Allowed DoH concurrency range. */
export const CONCURRENCY_RANGE = Object.freeze({ min: 1, max: 32 });

/** Default settings (lang null = follow the browser). */
export const DEFAULT_SETTINGS = Object.freeze({
  lang: null,
  theme: 'auto',
  chain: Object.freeze([...DEFAULT_CHAIN]),
  concurrency: 12
});

const RESOLVER_IDS = new Set(RESOLVERS.map((r) => r.id));

/**
 * Validate/normalize a settings object; unknown or invalid fields fall back to defaults.
 * @param {object} input
 * @returns {{ lang: 'tr'|'en'|null, theme: 'auto'|'light'|'dark', chain: string[], concurrency: number }}
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
  return { lang, theme, chain, concurrency };
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

function emptyInventory() {
  return { text: '', servers: [], warnings: [], stats: { lines: 0, servers: 0, ips: 0 }, updatedAt: null };
}

/**
 * @typedef {object} StateChange
 * @property {'inventory'|'settings'|'session'} key
 * @property {any} value the new slice value (for 'session': { name, value })
 * @property {'local'|'external'} origin 'external' when another tab changed storage
 */

/**
 * Create an isolated app state (the app uses the {@link state} singleton; tests inject storage).
 * @param {{ storage?: Storage|null, parse?: typeof parseInventory, now?: () => Date,
 *   listenStorageEvents?: boolean }} [opts]
 */
export function createState({
  storage = defaultStorage(),
  parse = parseInventory,
  now = () => new Date(),
  listenStorageEvents = true
} = {}) {
  /** @type {Set<(change: StateChange) => void>} */
  const listeners = new Set();
  let inventory = emptyInventory();
  let settings = { ...DEFAULT_SETTINGS, chain: [...DEFAULT_SETTINGS.chain] };
  let index = null;
  /** @type {Error|null} */
  let lastPersistError = null;
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
      else storage.setItem(key, JSON.stringify({ v: SCHEMA_VERSION, ...value }));
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

  function loadInventory() {
    const data = read(KEY_INVENTORY);
    if (!data || typeof data.text !== 'string') return emptyInventory();
    const at = data.updatedAt ? new Date(data.updatedAt) : null;
    return deriveInventory(data.text, at && !Number.isNaN(at.getTime()) ? at : null);
  }

  function loadSettings() {
    return sanitizeSettings(read(KEY_SETTINGS) || {});
  }

  inventory = loadInventory();
  settings = loadSettings();

  const api = {
    /** Current inventory (treat as read-only). */
    get inventory() {
      return inventory;
    },

    /** Current settings (a copy; change them with updateSettings). */
    get settings() {
      return { ...settings, chain: [...settings.chain] };
    },

    /** True when localStorage works; false → state lives only in this tab. */
    get persistence() {
      return !!storage;
    },

    /** Error from the last failed write (e.g. QuotaExceededError), or null. */
    get lastPersistError() {
      return lastPersistError;
    },

    /**
     * Replace the inventory, parse it and persist it.
     * @param {string|{ text: string }} input raw inventory text
     * @returns {{ persisted: boolean, inventory: object }}
     */
    setInventory(input) {
      const text = typeof input === 'string' ? input : (input && typeof input.text === 'string' ? input.text : '');
      const at = now();
      inventory = deriveInventory(text, text.trim() ? at : null);
      index = null;
      const persisted = text.trim()
        ? write(KEY_INVENTORY, { text, updatedAt: at.toISOString() })
        : write(KEY_INVENTORY, null);
      emit('inventory', inventory);
      return { persisted, inventory };
    },

    /** Remove the saved inventory. @returns {boolean} persisted */
    clearInventory() {
      inventory = emptyInventory();
      index = null;
      const persisted = write(KEY_INVENTORY, null);
      emit('inventory', inventory);
      return persisted;
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
     * @param {Partial<{ lang: 'tr'|'en'|null, theme: string, chain: string[], concurrency: number }>} patch
     * @returns {{ lang, theme, chain, concurrency }} the new settings
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
     * Delete every 'ssds.*' key from storage and reset all slices (session too).
     * @returns {boolean} true when storage was cleaned
     */
    clearAll() {
      let ok = !!storage;
      if (storage) {
        try {
          const keys = [];
          for (let i = 0; i < storage.length; i += 1) {
            const k = storage.key(i);
            if (k && k.startsWith(STORAGE_PREFIX)) keys.push(k);
          }
          keys.forEach((k) => storage.removeItem(k));
        } catch (err) {
          lastPersistError = err instanceof Error ? err : new Error(String(err));
          ok = false;
        }
      }
      inventory = emptyInventory();
      index = null;
      settings = sanitizeSettings({});
      for (const k of Object.keys(session)) delete session[k];
      emit('inventory', inventory);
      emit('settings', api.settings);
      return ok;
    },

    /**
     * Re-read a key after another tab changed it (wired to the `storage` event).
     * @param {string|null} key storage key, or null when the other tab cleared storage
     */
    handleExternalChange(key) {
      if (key === null || key === KEY_INVENTORY) {
        inventory = loadInventory();
        index = null;
        emit('inventory', inventory, 'external');
      }
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
