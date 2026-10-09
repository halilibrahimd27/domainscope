/**
 * state.js migrations: the settings (v1 → v2, 2026-09-23: a stored resolver chain that is exactly
 * the old built-in default (cloudflare, google, quad9, dnssb) follows the new DEFAULT_CHAIN;
 * customised chains stay; the migration runs once and is written back), and the data kept before
 * workspaces (2026-09-28: the inventory and learned names in localStorage, this tab's custom
 * wordlist in sessionStorage move into the Default workspace without loss, over an in-memory
 * workspace backend standing in for IndexedDB). No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  createState, migrateSettings, sanitizeSettings, SETTINGS_VERSION, LEGACY_DEFAULT_CHAINS
} from '../../assets/js/state.js';
import { DEFAULT_CHAIN, getResolver } from '../../assets/js/lib/resolvers.js';
import {
  createWorkspaceStore, createMemoryBackend, LEGACY_KEYS, DEFAULT_WORKSPACE_ID
} from '../../assets/js/lib/workspace.js';
import { createLearnedStore } from '../../assets/js/lib/learned.js';

const OLD_DEFAULT = ['cloudflare', 'google', 'quad9', 'dnssb'];

/** Web Storage stub that records writes. */
class MemoryStorage {
  constructor(entries = {}) {
    this.map = new Map(Object.entries(entries));
    this.writes = 0;
  }

  get length() {
    return this.map.size;
  }

  key(i) {
    return [...this.map.keys()][i] ?? null;
  }

  getItem(k) {
    return this.map.has(k) ? this.map.get(k) : null;
  }

  setItem(k, v) {
    this.writes += 1;
    this.map.set(k, String(v));
  }

  removeItem(k) {
    this.map.delete(k);
  }
}

const make = (storage) => createState({ storage, listenStorageEvents: false });
const stored = (storage) => JSON.parse(storage.getItem('ssds.settings'));
const v1 = (settings) => new MemoryStorage({ 'ssds.settings': JSON.stringify({ v: 1, ...settings }) });

describe('settings migration', () => {
  test('the new default chain is browser-readable and differs from the old one', () => {
    assert.equal(SETTINGS_VERSION, 2);
    assert.deepEqual(LEGACY_DEFAULT_CHAINS.map((c) => [...c]), [OLD_DEFAULT]);
    assert.notDeepEqual([...DEFAULT_CHAIN], OLD_DEFAULT);
    for (const id of DEFAULT_CHAIN) assert.notEqual(getResolver(id).browserReliable, false, id);
  });

  test('migrateSettings: old default chain → DEFAULT_CHAIN, other fields untouched, input not mutated', () => {
    const input = { v: 1, lang: 'tr', theme: 'dark', chain: [...OLD_DEFAULT], concurrency: 8 };
    const { data, migrated } = migrateSettings(input);
    assert.equal(migrated, true);
    assert.deepEqual(data, { v: 2, lang: 'tr', theme: 'dark', chain: [...DEFAULT_CHAIN], concurrency: 8 });
    assert.deepEqual(input.chain, OLD_DEFAULT, 'input not mutated');
    assert.equal(input.v, 1);
  });

  test('migrateSettings: records without v count as v1', () => {
    const { data, migrated } = migrateSettings({ theme: 'light', chain: [...OLD_DEFAULT] });
    assert.equal(migrated, true);
    assert.deepEqual(data.chain, [...DEFAULT_CHAIN]);
    assert.equal(data.v, 2);
  });

  test('migrateSettings: customised chains are kept (reordered, trimmed, extended, Quad9-only)', () => {
    const custom = [
      ['google', 'cloudflare', 'quad9', 'dnssb'],
      ['cloudflare', 'google', 'quad9'],
      ['cloudflare', 'google', 'quad9', 'dnssb', 'cznic'],
      ['quad9'],
      ['controld', 'cloudflare'],
      ['cloudflare', 'google', 'dnssb', 'cznic']
    ];
    for (const chain of custom) {
      const { data, migrated } = migrateSettings({ v: 1, chain });
      assert.equal(migrated, true, 'version still bumped');
      assert.deepEqual(data.chain, chain, chain.join(','));
    }
  });

  test('migrateSettings: current (v2) and newer records are left alone — a deliberate choice of the old chain sticks', () => {
    const current = { v: 2, chain: [...OLD_DEFAULT] };
    assert.deepEqual(migrateSettings(current), { data: current, migrated: false });
    const future = { v: 7, chain: [...OLD_DEFAULT] };
    assert.equal(migrateSettings(future).migrated, false);
  });

  test('migrateSettings: junk input is tolerated', () => {
    for (const bad of [null, undefined, 42, 'x']) {
      const { data, migrated } = migrateSettings(bad);
      assert.equal(migrated, true);
      assert.deepEqual(sanitizeSettings(data).chain, [...DEFAULT_CHAIN]);
    }
    assert.deepEqual(migrateSettings({ v: 1, chain: 'cloudflare,google,quad9,dnssb' }).data.chain, 'cloudflare,google,quad9,dnssb',
      'non-array chains are left to sanitizeSettings');
  });

  test('createState migrates a stored v1 record once and writes it back as v2', () => {
    const storage = v1({ lang: 'en', theme: 'dark', chain: [...OLD_DEFAULT], concurrency: 16 });
    const s = make(storage);
    assert.deepEqual(s.settings, { lang: 'en', theme: 'dark', chain: [...DEFAULT_CHAIN], concurrency: 16, startTasks: true, density: 'comfortable' });
    const saved = stored(storage);
    assert.equal(saved.v, 2);
    assert.deepEqual(saved.chain, [...DEFAULT_CHAIN]);
    assert.equal(storage.writes, 1);

    // Second start: nothing to migrate, nothing written.
    const again = make(storage);
    assert.deepEqual(again.settings.chain, [...DEFAULT_CHAIN]);
    assert.equal(storage.writes, 1);
  });

  test('createState keeps a customised v1 chain (and still marks the record as migrated)', () => {
    const storage = v1({ chain: ['google', 'quad9'], theme: 'light' });
    const s = make(storage);
    assert.deepEqual(s.settings.chain, ['google', 'quad9']);
    assert.equal(stored(storage).v, 2);
    assert.deepEqual(stored(storage).chain, ['google', 'quad9']);
  });

  test('after migration the user can pick the old chain on purpose and it survives a reload', () => {
    const storage = v1({ chain: [...OLD_DEFAULT] });
    const s = make(storage);
    assert.deepEqual(s.settings.chain, [...DEFAULT_CHAIN]);
    s.updateSettings({ chain: [...OLD_DEFAULT] });
    assert.equal(stored(storage).v, 2);
    assert.deepEqual(make(storage).settings.chain, OLD_DEFAULT);
  });

  test('an old record written by another (older) tab is migrated in memory without writing back', () => {
    const storage = new MemoryStorage();
    const s = make(storage);
    const events = [];
    s.subscribe((e) => events.push(e));
    storage.setItem('ssds.settings', JSON.stringify({ v: 1, theme: 'dark', chain: [...OLD_DEFAULT] }));
    const writes = storage.writes;
    s.handleExternalChange('ssds.settings');
    assert.deepEqual(s.settings.chain, [...DEFAULT_CHAIN]);
    assert.equal(s.settings.theme, 'dark');
    assert.equal(storage.writes, writes, 'no write-back from a storage event');
    assert.equal(events.at(-1).origin, 'external');
  });

  test('settings writes use version 2; the inventory goes to the workspace, never to localStorage', async () => {
    const storage = new MemoryStorage();
    const s = make(storage);
    await s.ready;
    s.setInventory('web01 10.0.0.5');
    s.updateSettings({ theme: 'dark' });
    assert.equal(storage.getItem('ssds.inventory'), null);
    assert.equal(stored(storage).v, 2);
    assert.deepEqual(s.workspaceData('inventory').text, 'web01 10.0.0.5');
  });

  test('empty storage: defaults, nothing written at start-up', () => {
    const storage = new MemoryStorage();
    const s = make(storage);
    assert.deepEqual(s.settings.chain, [...DEFAULT_CHAIN]);
    assert.equal(storage.writes, 0);
  });

  test('a failing write-back (full quota) still yields the migrated settings', () => {
    const storage = v1({ chain: [...OLD_DEFAULT] });
    storage.setItem = () => {
      const err = new Error('The quota has been exceeded.');
      err.name = 'QuotaExceededError';
      throw err;
    };
    const s = make(storage);
    assert.deepEqual(s.settings.chain, [...DEFAULT_CHAIN]);
    assert.equal(s.lastPersistError.name, 'QuotaExceededError');
  });
});

describe('the data before workspaces moves into Default', () => {
  const INVENTORY = 'web01 192.0.2.10\nweb02 192.0.2.11 2001:db8::11';
  /** A browser as the app left it before workspaces: localStorage + this tab's sessionStorage. */
  const before = () => ({
    local: new MemoryStorage({
      [LEGACY_KEYS.inventory]: JSON.stringify({ v: 1, text: INVENTORY, updatedAt: '2026-09-20T08:00:00Z' }),
      [LEGACY_KEYS.learned]: JSON.stringify({ v: 1, seq: 3, labels: { billing: [2, 1], intranet: [1, 3] } }),
      'ssds.settings': JSON.stringify({ v: 2, theme: 'dark', chain: [...DEFAULT_CHAIN] }),
      'ssds.subdomains.options': JSON.stringify({ learned: true })
    }),
    session: new MemoryStorage({ [LEGACY_KEYS.wordlist]: 'portal\nticket', other: 'keep' })
  });
  const open = ({ local, session }, backend) => {
    const s = createState({
      storage: local, sessionStore: session, listenStorageEvents: false,
      workspaces: createWorkspaceStore({ backend, legacy: { local, session } })
    });
    return s.ready.then(() => s);
  };

  test('servers, learned names and the custom wordlist are in Default after the first load', async () => {
    const storages = before();
    const backend = createMemoryBackend([], { persistent: true });
    const events = [];
    const s = createState({
      storage: storages.local, sessionStore: storages.session, listenStorageEvents: false,
      workspaces: createWorkspaceStore({ backend, legacy: storages })
    });
    s.subscribe((e) => events.push([e.key, e.origin]));
    await s.ready;
    assert.equal(s.workspace.id, DEFAULT_WORKSPACE_ID);
    assert.deepEqual(s.migrated.sort(), ['inventory', 'learned', 'wordlist']);
    assert.deepEqual(s.inventory.servers.map((x) => x.name), ['web01', 'web02']);
    assert.equal(s.inventory.updatedAt.toISOString(), '2026-09-20T08:00:00.000Z');
    assert.deepEqual(createLearnedStore(s.learnedStorage).labels(), ['billing', 'intranet']);
    assert.equal(s.workspaceData('wordlist'), 'portal\nticket');
    assert.deepEqual(events, [['inventory', 'load'], ['workspaces', 'load']]);
    // The old keys went only after the data was written; settings and view options stay.
    assert.deepEqual([...storages.local.map.keys()].sort(), ['ssds.settings', 'ssds.subdomains.options']);
    assert.deepEqual([...storages.session.map.keys()], ['other']);
    assert.equal(s.settings.theme, 'dark', 'settings are not workspace data');
  });

  test('the next load reads Default from the workspace store and migrates nothing again', async () => {
    const storages = before();
    const backend = createMemoryBackend([], { persistent: true });
    await open(storages, backend);
    const again = await open(storages, backend);
    assert.deepEqual(again.migrated, []);
    assert.equal(again.inventory.servers.length, 2);
    assert.equal(again.workspaceData('wordlist'), 'portal\nticket');
  });

  test('a failed write keeps the old keys, and this page still works with the data', async () => {
    const storages = before();
    const backend = createMemoryBackend([], { persistent: true });
    backend.fail.add('write');
    const s = await open(storages, backend);
    assert.equal(s.inventory.servers.length, 2);
    assert.equal(s.workspaceError.name, 'QuotaExceededError');
    assert.ok(storages.local.getItem(LEGACY_KEYS.inventory), 'nothing lost: the next load tries again');
    backend.fail.delete('write');
    const next = await open(storages, backend);
    assert.deepEqual(next.migrated.sort(), ['inventory', 'learned', 'wordlist']);
    assert.equal(storages.local.getItem(LEGACY_KEYS.inventory), null);
  });

  test('without IndexedDB (private mode): the data is read into memory and the old keys stay', async () => {
    const storages = before();
    const s = await open(storages, createMemoryBackend());
    assert.equal(s.workspacePersistence, false);
    assert.equal(s.inventory.servers.length, 2);
    assert.ok(storages.local.getItem(LEGACY_KEYS.learned));
    assert.ok(storages.session.getItem(LEGACY_KEYS.wordlist));
  });

  test('a browser with nothing to migrate starts with an empty Default', async () => {
    const local = new MemoryStorage({ 'ssds.settings': JSON.stringify({ v: 2, lang: 'tr' }) });
    const backend = createMemoryBackend([], { persistent: true });
    const s = await open({ local, session: new MemoryStorage() }, backend);
    assert.deepEqual(s.migrated, []);
    assert.equal(s.inventory.text, '');
    assert.deepEqual(backend.entries(), [], 'no database written');
    assert.equal(s.settings.lang, 'tr');
  });
});
