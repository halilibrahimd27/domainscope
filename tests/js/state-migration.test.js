/**
 * state.js settings migration (v1 → v2, 2026-09-23): a stored resolver chain that is exactly
 * the old built-in default (cloudflare, google, quad9, dnssb) follows the new DEFAULT_CHAIN;
 * customised chains stay; the migration runs once and is written back. No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  createState, migrateSettings, sanitizeSettings, SETTINGS_VERSION, LEGACY_DEFAULT_CHAINS
} from '../../assets/js/state.js';
import { DEFAULT_CHAIN, getResolver } from '../../assets/js/lib/resolvers.js';

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
    assert.deepEqual(s.settings, { lang: 'en', theme: 'dark', chain: [...DEFAULT_CHAIN], concurrency: 16 });
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

  test('inventory records keep schema version 1; settings writes use version 2', () => {
    const storage = new MemoryStorage();
    const s = make(storage);
    s.setInventory('web01 10.0.0.5');
    s.updateSettings({ theme: 'dark' });
    assert.equal(JSON.parse(storage.getItem('ssds.inventory')).v, 1);
    assert.equal(stored(storage).v, 2);
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
