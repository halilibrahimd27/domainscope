/**
 * workspace-db.js — the IndexedDB backend of the workspaces (lib/workspace.js WorkspaceBackend):
 * one database of this origin, {@link WORKSPACE_DB_NAME}, holding one object store of JSON
 * records under string keys. Browser only; state.js falls back to memory where it returns null.
 *
 * - The database is opened on first use and created only by a write: `exists()` asks
 *   `indexedDB.databases()` (where the browser has it) first, so a visitor who never saves
 *   anything, or who deleted all local data, gets no database.
 * - Opening that does not finish within a few seconds fails (lib/workspace.js then works in memory).
 * - Another tab deleting the database ("Delete all local data") fires `versionchange` here: the
 *   connection closes at once so the deletion is not blocked, and the next access opens it again.
 * - `destroy()` closes this tab's connection and deletes the whole database.
 */

/** The database's name (the app's 'ssds.' namespace, as in localStorage). */
export const WORKSPACE_DB_NAME = 'ssds.workspaces';
const STORE = 'records';
const DB_VERSION = 1;
const TIMEOUT_MS = 5000;

/** A request as a promise. */
function done(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
  });
}

/**
 * A transaction's end as a promise (a write is on disk only once it completes). It is marked
 * handled: a method that fails on a request first never leaves it as an unhandled rejection.
 */
function finished(tx) {
  const end = new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error('IndexedDB transaction failed'));
    tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
  });
  end.catch(() => {});
  return end;
}

/**
 * The IndexedDB backend, or null where the browser has no usable IndexedDB (Node, a sandbox that
 * throws on access).
 * @param {{ indexedDB?: IDBFactory, name?: string, timeoutMs?: number }} [opts]
 * @returns {import('./lib/workspace.js').WorkspaceBackend|null}
 */
export function createIdbBackend({ indexedDB: factory = undefined, name = WORKSPACE_DB_NAME, timeoutMs = TIMEOUT_MS } = {}) {
  let idb = factory;
  if (idb === undefined) {
    try {
      idb = globalThis.indexedDB;
    } catch {
      idb = null; // SecurityError: storage blocked for this page
    }
  }
  if (!idb || typeof idb.open !== 'function') return null;
  /** @type {Promise<IDBDatabase>|null} */
  let connection = null;

  function open() {
    if (connection) return connection;
    const pending = new Promise((resolve, reject) => {
      let settled = false;
      let request;
      const timer = setTimeout(() => {
        settled = true;
        reject(new Error('IndexedDB did not open in time'));
      }, timeoutMs);
      try {
        request = idb.open(name, DB_VERSION);
      } catch (err) {
        clearTimeout(timer);
        reject(err);
        return;
      }
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      };
      request.onsuccess = () => {
        clearTimeout(timer);
        const db = request.result;
        if (settled) {
          db.close(); // too late: the page went on in memory
          return;
        }
        settled = true;
        const forget = () => {
          if (connection === pending) connection = null;
        };
        db.onversionchange = () => {
          db.close();
          forget();
        };
        db.onclose = forget;
        resolve(db);
      };
      request.onerror = () => {
        clearTimeout(timer);
        settled = true;
        reject(request.error || new Error('IndexedDB did not open'));
      };
    });
    connection = pending;
    pending.catch(() => {
      if (connection === pending) connection = null;
    });
    return pending;
  }

  /** A transaction on the one store; a connection closed under us (versionchange) is opened again once. */
  async function transaction(mode) {
    for (let attempt = 0; ; attempt += 1) {
      const db = await open();
      try {
        return db.transaction(STORE, mode);
      } catch (err) {
        if (attempt || !err || err.name !== 'InvalidStateError') throw err;
        connection = null;
      }
    }
  }

  return {
    persistent: true,

    async exists() {
      if (connection) return true;
      if (typeof idb.databases !== 'function') return null;
      try {
        const list = await idb.databases();
        return list.some((d) => d && d.name === name);
      } catch {
        return null;
      }
    },

    // Each method listens for the transaction's end before it waits for anything: a transaction
    // commits as soon as its last request is answered, possibly before a later listener exists.
    async get(keys) {
      const tx = await transaction('readonly');
      const end = finished(tx);
      const store = tx.objectStore(STORE);
      const values = await Promise.all(keys.map((k) => done(store.get(k))));
      await end;
      return values;
    },

    async list(prefix) {
      const tx = await transaction('readonly');
      const end = finished(tx);
      const store = tx.objectStore(STORE);
      const range = IDBKeyRange.bound(prefix, `${prefix}\uffff`);
      const [keys, values] = await Promise.all([done(store.getAllKeys(range)), done(store.getAll(range))]);
      await end;
      return keys.map((k, i) => [String(k), values[i]]);
    },

    async write(puts = [], deletes = []) {
      const tx = await transaction('readwrite');
      const end = finished(tx);
      const store = tx.objectStore(STORE);
      for (const k of deletes) store.delete(k);
      for (const [k, v] of puts) store.put(v, k);
      await end;
    },

    async destroy() {
      if (connection) {
        try {
          (await connection).close();
        } catch {
          // it never opened
        }
        connection = null;
      }
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('IndexedDB deletion is blocked by another tab')), timeoutMs);
        const request = idb.deleteDatabase(name);
        request.onsuccess = () => {
          clearTimeout(timer);
          resolve();
        };
        request.onerror = () => {
          clearTimeout(timer);
          reject(request.error || new Error('IndexedDB deletion failed'));
        };
        // onblocked: another tab still holds a connection; it closes on versionchange and the
        // deletion then goes on (or the timer gives up).
      });
    }
  };
}
