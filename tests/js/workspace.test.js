/**
 * lib/workspace.js — customer workspaces: names, part values, the recent list, the first-run
 * migration of the pre-workspace data into Default, and the store over an in-memory backend
 * (IndexedDB has its own E2E suite, tests/e2e/workspaces.e2e.mjs): separate data per workspace,
 * the active-workspace pointer, degraded storage, "Delete all local data" and the other tabs.
 * No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_WORKSPACE_ID, WORKSPACE_PARTS, WORKSPACE_LIMITS, LEGACY_KEYS, ACTIVE_WORKSPACE_KEY, STORE_VERSION,
  WorkspaceError, normalizeWorkspaceName, uniqueWorkspaceName, sanitizePart, sanitizeExpectedCas, sanitizeRecent,
  sanitizeWorkspaceData, emptyWorkspaceData, addRecent, readLegacyData, createMemoryBackend, createWorkspaceStore, impliesDatabase
} from '../../assets/js/lib/workspace.js';
import { parseInventory, buildIpIndex, lookupServers } from '../../assets/js/lib/inventory.js';
import { createLearnedStore } from '../../assets/js/lib/learned.js';

/** Web Storage stub (localStorage / sessionStorage) that can refuse writes. */
class MemoryStorage {
  constructor(entries = {}) {
    this.map = new Map(Object.entries(entries));
    this.failRemove = false;
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
    this.map.set(k, String(v));
  }

  removeItem(k) {
    if (this.failRemove) throw new Error('SecurityError');
    this.map.delete(k);
  }
}

/** The active-workspace pointer over a Web Storage stub, as state.js builds it. */
const pointerOf = (storage) => ({
  get: () => storage.getItem(ACTIVE_WORKSPACE_KEY),
  set: (id) => storage.setItem(ACTIVE_WORKSPACE_KEY, id)
});

let ids = 0;
const nextId = () => `ws-test${(ids += 1)}`;
const clock = (iso = '2026-09-28T10:00:00Z') => {
  let t = Date.parse(iso);
  return () => new Date((t += 1000));
};

/** A store over `backend` (a persistent in-memory one by default) with a deterministic clock and ids. */
function makeStore({ backend = createMemoryBackend([], { persistent: true }), pointer = null, legacy = null, channel = null } = {}) {
  return createWorkspaceStore({ backend, pointer, legacy, channel, now: clock(), newId: nextId });
}

/** A pair of BroadcastChannel-like objects: a message posted on one reaches the other's listeners. */
function channelPair() {
  const deliveries = [];
  const make = () => ({
    listeners: [],
    peer: null,
    postMessage(msg) {
      const data = structuredClone(msg);
      for (const fn of this.peer.listeners) deliveries.push(Promise.resolve().then(() => fn({ data })));
    },
    addEventListener(type, fn) {
      if (type === 'message') this.listeners.push(fn);
    }
  });
  const a = make();
  const b = make();
  a.peer = b;
  b.peer = a;
  /** Wait until every message so far has been handled (and what the handlers awaited). */
  const flush = async () => {
    for (let i = 0; i < 5; i += 1) {
      await Promise.all(deliveries.splice(0));
      await new Promise((r) => setImmediate(r));
    }
  };
  return { a, b, flush };
}

const INVENTORY_A = 'web01 192.0.2.10\nweb02 192.0.2.11';
const INVENTORY_B = 'mail 192.0.2.10\nvpn 198.51.100.7';

describe('names', () => {
  test('normalizeWorkspaceName: NFC, controls and invisible characters out, whitespace collapsed, capped', () => {
    assert.equal(normalizeWorkspaceName('  Acme   Corp \n'), 'Acme Corp');
    assert.equal(normalizeWorkspaceName('Ac\u0000me\u202eX\u200b'), 'Ac me X');
    assert.equal(normalizeWorkspaceName('Cafe\u0301'), 'Café', 'NFC');
    assert.equal(normalizeWorkspaceName('x'.repeat(200)).length, WORKSPACE_LIMITS.name);
    assert.equal([...normalizeWorkspaceName('🙂'.repeat(100))].length, WORKSPACE_LIMITS.name, 'counted in characters, never a broken surrogate');
    for (const bad of [null, undefined, 42, {}, '   ', '\u200b']) assert.equal(normalizeWorkspaceName(bad), '');
  });

  test('uniqueWorkspaceName: the name when free, else the first free "(n)", case-insensitive', () => {
    assert.equal(uniqueWorkspaceName('Acme', ['Other']), 'Acme');
    assert.equal(uniqueWorkspaceName('Acme', ['acme']), 'Acme (2)');
    assert.equal(uniqueWorkspaceName('Acme', ['Acme', 'Acme (2)']), 'Acme (3)');
    assert.equal(uniqueWorkspaceName('Acme (2)', ['Acme', 'Acme (2)']), 'Acme (3)', 'a trailing (n) is not doubled');
    assert.equal(uniqueWorkspaceName('   ', []), '');
    const long = uniqueWorkspaceName('y'.repeat(80), ['y'.repeat(60)]);
    assert.ok(long.endsWith(' (2)') && long.length === WORKSPACE_LIMITS.name, long);
  });
});

describe('part values', () => {
  test('every part has an empty value and a sanitizer; an unknown part is refused', () => {
    const empty = emptyWorkspaceData();
    assert.deepEqual(Object.keys(empty), [...WORKSPACE_PARTS]);
    for (const part of WORKSPACE_PARTS) assert.deepEqual(sanitizePart(part, undefined), empty[part], part);
    assert.throws(() => sanitizePart('settings', {}), (err) => err instanceof WorkspaceError && err.code === 'part');
  });

  test('inventory: the raw text and when it was saved; no text is no inventory', () => {
    assert.deepEqual(sanitizePart('inventory', { text: INVENTORY_A, updatedAt: '2026-09-28T10:00:00Z', servers: [1] }),
      { text: INVENTORY_A, updatedAt: '2026-09-28T10:00:00.000Z' });
    assert.deepEqual(sanitizePart('inventory', INVENTORY_A), { text: INVENTORY_A, updatedAt: null });
    assert.equal(sanitizePart('inventory', { text: '  \n ' }), null);
    assert.equal(sanitizePart('inventory', { text: 42 }), null);
    assert.equal(sanitizePart('inventory', { text: 'a', updatedAt: 'yesterday' }).updatedAt, null);
  });

  test('learned: only storable labels (never an address or a full name), capped by hits', () => {
    const clean = sanitizePart('learned', {
      v: 1, seq: 3, labels: { api: [5, 3], '198-51-100-7': [9, 1], 'a.b': [1, 1], vpn: { hits: 2, last: 9 }, panel: 'x', '-bad': [1, 1] }
    });
    assert.deepEqual(clean, { v: 1, seq: 9, labels: { api: [5, 3], vpn: [2, 9], panel: [1, 0] } });
    assert.equal(sanitizePart('learned', { labels: {} }), null);
    assert.equal(sanitizePart('learned', { labels: ['api'] }), null);
    const many = { labels: Object.fromEntries(Array.from({ length: WORKSPACE_LIMITS.learned + 10 }, (_, i) => [`n${i}x`, [i + 1, i]])) };
    const capped = sanitizePart('learned', many);
    assert.equal(Object.keys(capped.labels).length, WORKSPACE_LIMITS.learned);
    assert.ok(!('n0x' in capped.labels), 'the fewest hits go first');
  });

  test('expected CAs: one per line or array entry, trimmed, de-duplicated without case, capped', () => {
    assert.deepEqual(sanitizeExpectedCas("Let's Encrypt\n  digicert.com \n\nLET'S ENCRYPT\r\nExample  Internal CA"),
      ["Let's Encrypt", 'digicert.com', 'Example Internal CA']);
    assert.deepEqual(sanitizeExpectedCas(['Sectigo', 7, null, '', 'sectigo']), ['Sectigo']);
    assert.equal(sanitizeExpectedCas(Array.from({ length: 50 }, (_, i) => `CA ${i}`)).length, WORKSPACE_LIMITS.expectedCas);
    assert.equal(sanitizeExpectedCas(['x'.repeat(500)])[0].length, WORKSPACE_LIMITS.expectedCa);
    assert.deepEqual(sanitizePart('expectedCas', { a: 1 }), []);
  });

  test('the portfolio policy: its JSON text as the editor holds it (a draft with a mistake too), capped; anything else empty', () => {
    assert.equal(sanitizePart('policy', '{\r\n  "expiryDays": ">= 30"\u0000\r\n}'), '{\n  "expiryDays": ">= 30"\n}');
    assert.equal(sanitizePart('policy', '{ "expiryDays": '), '{ "expiryDays": ', 'kept as typed');
    assert.equal(sanitizePart('policy', 'p'.repeat(WORKSPACE_LIMITS.policy + 9)).length, WORKSPACE_LIMITS.policy);
    assert.equal(sanitizePart('policy', { rules: {} }), '');
  });

  test('the CT watch baseline: the JSON text lib/ctwatch.js writes, kept as it is (it checks it when it reads it), capped; anything else empty', () => {
    const text = '{"v":1,"domains":{"example.com":{"at":"2026-10-08T12:00:00.000Z","ids":{"00000000000000aa":"2026-12-01"}}}}';
    assert.equal(sanitizePart('ctSeen', text), text);
    assert.equal(sanitizePart('ctSeen', 'c'.repeat(WORKSPACE_LIMITS.ctSeen + 3)).length, WORKSPACE_LIMITS.ctSeen);
    assert.equal(sanitizePart('ctSeen', { v: 1, domains: {} }), '');
    assert.equal(sanitizePart('ctSeen', null), '');
  });

  test('the accepted risks: the JSON text lib/waivers.js writes, kept as it is up to 64 KiB (it checks every entry when it reads it), never cut; anything else empty', () => {
    const text = '{"format":"domainscope-waivers","v":1,"waivers":[{"id":"w-0123456789abcdef","kind":"finding","domain":"example.com","ref":"dmarc.policy-none","reason":"Q1","owner":"","created":null,"expires":"2026-12-31"}]}';
    assert.ok(WORKSPACE_PARTS.includes('waivers'));
    assert.equal(WORKSPACE_LIMITS.waivers, 65536);
    assert.equal(sanitizePart('waivers', text), text);
    assert.equal(sanitizePart('waivers', 'w'.repeat(WORKSPACE_LIMITS.waivers)).length, WORKSPACE_LIMITS.waivers);
    assert.equal(sanitizePart('waivers', 'w'.repeat(WORKSPACE_LIMITS.waivers + 1)), '', 'a cut JSON text would be no JSON: too long is nothing');
    assert.equal(sanitizePart('waivers', [{ kind: 'finding' }]), '');
    assert.equal(sanitizePart('waivers', null), '');
    assert.equal(sanitizeWorkspaceData({ waivers: text }).waivers, text);
    assert.equal(emptyWorkspaceData().waivers, '');
  });

  test('the registration watch baseline: the JSON text lib/regwatch.js writes, kept as it is (it checks it when it reads it), capped at 512 KiB; anything else empty', () => {
    const text = '{"v":1,"domains":{"example.com":{"at":"2026-10-08T12:00:00.000Z","state":"ok","registrar":"Example Registrar, Inc.","ianaId":"9999","statuses":[],"expires":"2027-11-13","nameservers":[],"ds":[]}}}';
    assert.ok(WORKSPACE_PARTS.includes('rdapSeen'));
    assert.equal(WORKSPACE_LIMITS.rdapSeen, 512 * 1024);
    assert.equal(sanitizePart('rdapSeen', text), text);
    assert.equal(sanitizePart('rdapSeen', 'r'.repeat(WORKSPACE_LIMITS.rdapSeen + 3)).length, WORKSPACE_LIMITS.rdapSeen);
    assert.equal(sanitizePart('rdapSeen', { v: 1, domains: {} }), '');
    assert.equal(sanitizePart('rdapSeen', null), '');
    assert.equal(emptyWorkspaceData().rdapSeen, '');
    assert.equal(sanitizeWorkspaceData({ rdapSeen: text }).rdapSeen, text);
  });

  test('the DMARC report history: the JSON text lib/dmarchistory.js writes, kept whole or not at all (a cut text is no JSON); anything else empty', () => {
    assert.ok(WORKSPACE_PARTS.includes('reportHistory'));
    assert.equal(WORKSPACE_LIMITS.reportHistory, 4 * 1024 * 1024);
    const text = '{"v":1,"keep":true,"updatedAt":null,"domains":{}}';
    assert.equal(sanitizePart('reportHistory', text), text);
    assert.equal(sanitizePart('reportHistory', 'h'.repeat(WORKSPACE_LIMITS.reportHistory)).length, WORKSPACE_LIMITS.reportHistory);
    assert.equal(sanitizePart('reportHistory', 'h'.repeat(WORKSPACE_LIMITS.reportHistory + 1)), '', 'never cut');
    assert.equal(sanitizePart('reportHistory', { v: 1, domains: {} }), '');
    assert.equal(sanitizePart('reportHistory', null), '');
    assert.equal(emptyWorkspaceData().reportHistory, '', 'empty until the switch is turned on');
  });

  test('the digests for Home: the JSON text lib/digests.js writes, at most 16 KB, kept whole or not at all; anything else empty', () => {
    assert.ok(WORKSPACE_PARTS.includes('digests'));
    assert.equal(WORKSPACE_PARTS.at(-1), 'digests', 'a new part goes last: an older reader drops it harmlessly');
    assert.equal(WORKSPACE_LIMITS.digests, 16384);
    const text = '{"monitor":{"at":"2026-10-08T03:00:00.000Z","imported":"2026-10-08T09:00:00.000Z","targets":4,"bad":1,"expiring":0,"incomplete":2}}';
    assert.equal(sanitizePart('digests', text), text);
    assert.equal(sanitizePart('digests', 'd'.repeat(WORKSPACE_LIMITS.digests)).length, WORKSPACE_LIMITS.digests);
    assert.equal(sanitizePart('digests', 'd'.repeat(WORKSPACE_LIMITS.digests + 1)), '', 'never cut');
    assert.equal(sanitizePart('digests', { monitor: {} }), '');
    assert.equal(emptyWorkspaceData().digests, '');
    assert.equal(sanitizeWorkspaceData({ digests: text }).digests, text);
  });

  test('notes: free text with its line breaks; controls other than tab / newline dropped; capped', () => {
    assert.equal(sanitizePart('notes', 'Renewal:\r\n\tcall ops\u0007 first'), 'Renewal:\n\tcall ops first');
    assert.equal(sanitizePart('notes', 'n'.repeat(WORKSPACE_LIMITS.notes + 5)).length, WORKSPACE_LIMITS.notes);
    assert.equal(sanitizePart('notes', 5), '');
  });

  test('recent: domains and host names only, normalized, one entry each, most recent first, capped', () => {
    assert.deepEqual(sanitizeRecent([
      { value: 'https://WWW.Example.com/login', at: '2026-09-28T10:00:00Z' },
      'example.net',
      { value: '192.0.2.10', at: '2026-09-28T09:00:00Z' },
      { value: 'www.example.com', at: '2026-09-27T09:00:00Z' },
      { value: 'com' },
      { value: 42 }
    ]), [
      { value: 'www.example.com', at: '2026-09-28T10:00:00.000Z' },
      { value: 'example.net', at: null }
    ]);
    assert.equal(sanitizeRecent(Array.from({ length: 40 }, (_, i) => `h${i}.example.com`)).length, WORKSPACE_LIMITS.recent);
  });

  test('addRecent: the entry moves to the top; the top entry again changes nothing; IPs never enter', () => {
    const at = new Date('2026-09-28T12:00:00Z');
    let list = addRecent([], 'example.com', at);
    list = addRecent(list, 'shop.example.net', at);
    assert.deepEqual(list.map((r) => r.value), ['shop.example.net', 'example.com']);
    list = addRecent(list, 'EXAMPLE.com.', at);
    assert.deepEqual(list.map((r) => r.value), ['example.com', 'shop.example.net']);
    assert.deepEqual(addRecent(list, 'example.com', new Date('2026-09-29T00:00:00Z')), list, 'already on top');
    assert.deepEqual(addRecent(list, '203.0.113.9', at), list);
    assert.deepEqual(addRecent(list, 'not a name', at), list);
  });

  test('sanitizeWorkspaceData: every part checked, the missing ones empty, unknown keys dropped', () => {
    const data = sanitizeWorkspaceData({ notes: 'n', expectedCas: 'Sectigo', settings: { theme: 'dark' } });
    assert.deepEqual(data, { ...emptyWorkspaceData(), notes: 'n', expectedCas: ['Sectigo'] });
    assert.deepEqual(sanitizeWorkspaceData(null), emptyWorkspaceData());
  });
});

describe('the data before workspaces', () => {
  test('readLegacyData reads the inventory, learned names and this tab\'s custom wordlist without changing them', () => {
    const local = new MemoryStorage({
      [LEGACY_KEYS.inventory]: JSON.stringify({ v: 1, text: INVENTORY_A, updatedAt: '2026-09-01T08:00:00Z' }),
      [LEGACY_KEYS.learned]: JSON.stringify({ v: 1, seq: 2, labels: { api: [3, 1], vpn: [1, 2] } }),
      'ssds.settings': '{"v":2}'
    });
    const session = new MemoryStorage({ [LEGACY_KEYS.wordlist]: 'billing\nportal' });
    const { data, present } = readLegacyData({ local, session });
    assert.deepEqual(data, {
      inventory: { text: INVENTORY_A, updatedAt: '2026-09-01T08:00:00.000Z' },
      learned: { v: 1, seq: 2, labels: { api: [3, 1], vpn: [1, 2] } },
      wordlist: 'billing\nportal'
    });
    assert.deepEqual(present.map((p) => `${p.area}:${p.key}`), [`local:${LEGACY_KEYS.inventory}`, `local:${LEGACY_KEYS.learned}`, `session:${LEGACY_KEYS.wordlist}`]);
    assert.equal(local.map.size, 3, 'nothing removed');
  });

  test('corrupt or empty legacy values are present (to be removed) but carry no data', () => {
    const local = new MemoryStorage({ [LEGACY_KEYS.inventory]: '{not json', [LEGACY_KEYS.learned]: JSON.stringify({ v: 1, seq: 0, labels: {} }) });
    const { data, present } = readLegacyData({ local, session: new MemoryStorage({ [LEGACY_KEYS.wordlist]: '   ' }) });
    assert.deepEqual(data, {});
    assert.equal(present.length, 3);
    const hostile = { getItem() { throw new Error('SecurityError'); } };
    assert.deepEqual(readLegacyData({ local: hostile, session: hostile }), { data: {}, present: [] });
    assert.deepEqual(readLegacyData(), { data: {}, present: [] });
  });
});

describe('the store', () => {
  test('a first visit: Default only, empty, and no database written until something is saved', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    const opened = await store.open();
    assert.equal(opened.active.id, DEFAULT_WORKSPACE_ID);
    assert.equal(opened.active.name, null, 'the UI names Default in the page language');
    assert.deepEqual(opened.list.map((m) => m.id), [DEFAULT_WORKSPACE_ID]);
    assert.deepEqual(opened.migrated, []);
    assert.equal(opened.persistent, true);
    assert.deepEqual(store.data, emptyWorkspaceData());
    assert.deepEqual(backend.entries(), [], 'nothing written');
    assert.equal(store.open(), store.open(), 'one open for all callers');

    // Opening read nothing either: with IndexedDB a read would create the database.
    const reads = createMemoryBackend([], { persistent: true, exists: false });
    reads.fail.add('get');
    reads.fail.add('list');
    const quiet = makeStore({ backend: reads });
    await quiet.open();
    assert.equal(quiet.lastError, null, 'no read was tried');

    assert.equal(await store.save('notes', 'first note'), true);
    const keys = backend.entries().map(([k]) => k).sort();
    assert.deepEqual(keys, ['meta', 'wsdata/default/notes', 'wsmeta/default']);
    assert.equal(backend.entries().find(([k]) => k === 'meta')[1].v, STORE_VERSION);
  });

  test('Default has no dates until something is written to it (the dialog shows no "changed" for it)', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    const opened = await store.open();
    assert.deepEqual([opened.active.createdAt, opened.active.updatedAt], [null, null]);
    // Another workspace written, Default not: a new page still gives Default no made-up date.
    await store.create('Acme');
    const later = makeStore({ backend });
    await later.open();
    assert.deepEqual([later.active.createdAt, later.active.updatedAt], [null, null]);
    assert.equal(later.list()[1].name, 'Acme');
    assert.ok(later.list()[1].updatedAt, 'a named workspace always has its dates');
    // The first write to Default gives it both, stored.
    await store.save('notes', 'first');
    const stored = new Map(backend.entries()).get('wsmeta/default');
    assert.ok(stored.createdAt && stored.updatedAt);
    assert.deepEqual([store.active.createdAt, store.active.updatedAt], [stored.createdAt, stored.updatedAt]);
    // The first-run migration is a write too.
    const legacy = { local: new MemoryStorage({ [LEGACY_KEYS.learned]: JSON.stringify({ v: 1, seq: 1, labels: { api: [1, 1] } }) }) };
    const migratedStore = makeStore({ backend: createMemoryBackend([], { persistent: true }), legacy });
    assert.ok((await migratedStore.open()).active.updatedAt);
  });

  test('two customers keep separate inventories: the same address in both is no DUPLICATE_IP', async () => {
    const store = makeStore();
    await store.open();
    const { meta: a } = await store.create('Acme');
    const { meta: b } = await store.create('Globex');
    await store.switchTo(a.id);
    await store.save('inventory', { text: INVENTORY_A, updatedAt: new Date() });
    await store.switchTo(b.id);
    assert.equal(store.data.inventory, null, 'a new workspace starts empty');
    await store.save('inventory', { text: INVENTORY_B, updatedAt: new Date() });

    const parsedB = parseInventory(store.data.inventory.text);
    assert.deepEqual(parsedB.warnings.filter((w) => w.code === 'DUPLICATE_IP'), []);
    assert.deepEqual(lookupServers(['192.0.2.10'], buildIpIndex(parsedB.servers)).map((m) => m.server.name), ['mail']);
    await store.switchTo(a.id);
    assert.deepEqual(parseInventory(store.data.inventory.text).servers.map((s) => s.name), ['web01', 'web02']);
    // All the text in one workspace would have been a DUPLICATE_IP: that is the noise workspaces remove.
    const mixed = parseInventory(`${INVENTORY_A}\n${INVENTORY_B}`);
    assert.ok(mixed.warnings.some((w) => w.code === 'DUPLICATE_IP'));
  });

  test('learned names stay in the workspace whose scans taught them (lib/learned.js over the store)', async () => {
    const store = makeStore();
    await store.open();
    const { meta: acme } = await store.create('Acme');
    const adapter = () => ({
      getItem: () => (store.data.learned ? JSON.stringify(store.data.learned) : null),
      setItem: (_k, v) => { store.save('learned', JSON.parse(v)); }
    });
    await store.switchTo(acme.id);
    createLearnedStore(adapter()).record(['billing.example.com', 'intranet.example.com'], 'example.com');
    assert.deepEqual(createLearnedStore(adapter()).labels().sort(), ['billing', 'intranet']);
    await store.switchTo(DEFAULT_WORKSPACE_ID);
    assert.equal(createLearnedStore(adapter()).size(), 0, 'Default never saw them');
  });

  test('list: Default first, then the names in order; create refuses empty, taken and too many names', async () => {
    const store = makeStore();
    await store.open();
    await store.create('globex');
    await store.create('Acme 10');
    await store.create('Acme 9');
    assert.deepEqual(store.list().map((m) => m.name), [null, 'Acme 9', 'Acme 10', 'globex']);
    await assert.rejects(store.create('  '), (e) => e.code === 'name-empty');
    await assert.rejects(store.create('ACME 9'), (e) => e.code === 'name-taken');
    const many = makeStore();
    await many.open();
    for (let i = 0; i < WORKSPACE_LIMITS.count; i += 1) await many.create(`c${i}`);
    await assert.rejects(many.create('one more'), (e) => e.code === 'limit');
  });

  test('rename and delete: never Default; a taken name is refused; deleting the active one goes back to Default', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    await store.open();
    const { meta: a } = await store.create('Acme');
    const { meta: b } = await store.create('Globex');
    await assert.rejects(store.rename(DEFAULT_WORKSPACE_ID, 'Mine'), (e) => e.code === 'default');
    await assert.rejects(store.remove(DEFAULT_WORKSPACE_ID), (e) => e.code === 'default');
    await assert.rejects(store.rename(a.id, 'globex'), (e) => e.code === 'name-taken');
    await assert.rejects(store.rename('ws-nope', 'x'), (e) => e.code === 'not-found');
    assert.equal((await store.rename(a.id, 'Acme Corp')).meta.name, 'Acme Corp');
    assert.equal((await store.rename(a.id, 'acme corp')).meta.name, 'acme corp', 'its own name in another case');

    await store.switchTo(b.id);
    await store.save('notes', 'Globex notes');
    const removed = await store.remove(b.id);
    assert.deepEqual(removed, { switched: true, persisted: true });
    assert.equal(store.active.id, DEFAULT_WORKSPACE_ID);
    assert.equal(store.data.notes, '');
    assert.ok(!backend.entries().some(([k]) => k.includes(b.id)), 'its records are gone');
    assert.equal((await store.remove(a.id)).switched, false);
  });

  test('the pointer: a new page opens the workspace used last; a pointer to a deleted one opens Default', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const local = new MemoryStorage();
    const first = makeStore({ backend, pointer: pointerOf(local) });
    await first.open();
    const { meta } = await first.create('Acme');
    await first.switchTo(meta.id);
    await first.save('expectedCas', ["Let's Encrypt"]);
    assert.equal(local.getItem(ACTIVE_WORKSPACE_KEY), meta.id);

    const second = makeStore({ backend, pointer: pointerOf(local) });
    const opened = await second.open();
    assert.equal(opened.active.id, meta.id);
    assert.deepEqual(second.data.expectedCas, ["Let's Encrypt"]);

    local.setItem(ACTIVE_WORKSPACE_KEY, 'ws-gone');
    const third = makeStore({ backend, pointer: pointerOf(local) });
    assert.equal((await third.open()).active.id, DEFAULT_WORKSPACE_ID);
  });

  test('save writes only a real change; an empty value removes its record', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    let writes = 0;
    const write = backend.write;
    backend.write = async (...args) => {
      writes += 1;
      return write(...args);
    };
    const store = makeStore({ backend });
    await store.open();
    await store.save('wordlist', 'billing');
    await store.save('wordlist', 'billing');
    assert.equal(writes, 1);
    await store.save('wordlist', '');
    assert.equal(writes, 2);
    assert.ok(!backend.entries().some(([k]) => k === 'wsdata/default/wordlist'));
    await store.save('expectedCas', []);
    assert.equal(writes, 2, 'empty was empty already');
  });

  test('saving the same value again retries a write that failed; a value written already is not written again', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    let writes = 0;
    const write = backend.write;
    backend.write = async (...args) => {
      writes += 1;
      return write(...args);
    };
    const store = makeStore({ backend });
    await store.open();
    backend.fail.add('write');
    assert.equal(await store.save('expectedCas', ["Let's Encrypt"]), false, 'a full disk');
    backend.fail.delete('write');
    assert.equal(await store.save('expectedCas', ["Let's Encrypt"]), true, 'the same value, written this time');
    assert.deepEqual(new Map(backend.entries()).get('wsdata/default/expectedCas'), ["Let's Encrypt"]);
    const before = writes;
    assert.equal(await store.save('expectedCas', ["Let's Encrypt"]), true);
    assert.equal(writes, before, 'nothing new: no write');
    // A save of the value a write is busy with shares that write's result.
    backend.fail.add('write');
    const first = store.save('notes', 'n');
    const again = store.save('notes', 'n');
    assert.deepEqual(await Promise.all([first, again]), [false, false]);
  });

  test('a burst of saves writes once, the latest value; idle() waits for every write', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const written = [];
    const write = backend.write;
    backend.write = async (puts, ...rest) => {
      written.push(puts.filter(([k]) => k.startsWith('wsdata/')).map(([, v]) => v));
      return write(puts, ...rest);
    };
    const store = makeStore({ backend });
    await store.open();
    const saves = ['a', 'ab', 'abc'].map((v) => store.save('wordlist', v));
    assert.equal(store.data.wordlist, 'abc', 'memory follows every keystroke');
    assert.deepEqual(await Promise.all(saves), [true, true, true]);
    assert.deepEqual(written, [['abc']], 'one write, the newest text');
    // A save while a write runs follows it, once, with the newest value.
    written.length = 0;
    store.save('notes', 'one');
    await Promise.resolve();
    store.save('notes', 'two');
    store.save('notes', 'three');
    await store.idle();
    assert.deepEqual(written, [['one'], ['three']]);
    assert.equal(new Map(backend.entries()).get('wsdata/default/notes'), 'three');
  });

  test('a save still waiting is dropped by "Delete all local data" and by deleting its workspace', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    await store.open();
    store.save('notes', 'typed just before');
    await store.destroy();
    await store.idle();
    assert.deepEqual(backend.entries(), [], 'the database does not come back');

    const { meta } = await store.create('Acme');
    await store.switchTo(meta.id);
    store.save('notes', 'typed in Acme');
    await store.remove(meta.id);
    await store.idle();
    assert.ok(!backend.entries().some(([k]) => k.includes(meta.id)), 'the workspace does not come back');

    const { meta: other } = await store.create('Globex');
    await store.switchTo(other.id);
    store.save('notes', 'old text');
    await store.replace(other.id, { notes: 'from the file' });
    await store.idle();
    assert.equal(new Map(backend.entries()).get(`wsdata/${other.id}/notes`), 'from the file', 'a waiting save writes the replacing value');
  });

  test('recordRecent keeps the domains worked on, newest first', async () => {
    const store = makeStore();
    await store.open();
    await store.recordRecent('example.com');
    await store.recordRecent('https://shop.example.net/');
    await store.recordRecent('198.51.100.7');
    assert.deepEqual(store.data.recent.map((r) => r.value), ['shop.example.net', 'example.com']);
  });

  test('replace and load: another workspace\'s data without switching to it; copies, never the store\'s own objects', async () => {
    const store = makeStore();
    await store.open();
    const { meta } = await store.create('Acme');
    await store.replace(meta.id, { notes: 'imported', expectedCas: ['Sectigo'], inventory: { text: INVENTORY_A } });
    assert.equal(store.active.id, DEFAULT_WORKSPACE_ID);
    const loaded = await store.load(meta.id);
    assert.deepEqual([loaded.notes, loaded.expectedCas, loaded.inventory.text], ['imported', ['Sectigo'], INVENTORY_A]);
    loaded.expectedCas.push('changed');
    assert.deepEqual((await store.load(meta.id)).expectedCas, ['Sectigo']);
    await store.replace(DEFAULT_WORKSPACE_ID, { notes: 'default notes' });
    assert.equal(store.data.notes, 'default notes', 'the active workspace changes in memory at once');
    await assert.rejects(store.load('ws-nope'), (e) => e.code === 'not-found');
    await assert.rejects(store.switchTo('ws-nope'), (e) => e.code === 'not-found');
  });

  test('create with data: an imported workspace in one write', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    await store.open();
    const { meta, persisted } = await store.create('Imported', { notes: 'from a colleague', recent: ['example.com'] });
    assert.equal(persisted, true);
    assert.deepEqual((await store.load(meta.id)).recent.map((r) => r.value), ['example.com']);
  });
});

describe('the first-run migration into Default', () => {
  const legacyStorages = () => ({
    local: new MemoryStorage({
      [LEGACY_KEYS.inventory]: JSON.stringify({ v: 1, text: INVENTORY_A, updatedAt: '2026-09-01T08:00:00Z' }),
      [LEGACY_KEYS.learned]: JSON.stringify({ v: 1, seq: 4, labels: { api: [3, 1], vpn: [1, 4] } }),
      'ssds.settings': JSON.stringify({ v: 2, theme: 'dark' }),
      'ssds.subdomains.options': '{}'
    }),
    session: new MemoryStorage({ [LEGACY_KEYS.wordlist]: 'billing\nportal', other: 'keep' })
  });

  test('moves the inventory, learned names and custom wordlist into Default, then removes the old keys', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const legacy = legacyStorages();
    const store = makeStore({ backend, legacy });
    const opened = await store.open();
    assert.deepEqual(opened.migrated.sort(), ['inventory', 'learned', 'wordlist']);
    assert.equal(opened.active.id, DEFAULT_WORKSPACE_ID);
    assert.deepEqual(store.data.inventory, { text: INVENTORY_A, updatedAt: '2026-09-01T08:00:00.000Z' });
    assert.deepEqual(Object.keys(store.data.learned.labels), ['api', 'vpn']);
    assert.equal(store.data.wordlist, 'billing\nportal');
    // Not lost: the same values are in the backend …
    const records = new Map(backend.entries());
    assert.equal(records.get('wsdata/default/inventory').text, INVENTORY_A);
    assert.equal(records.get('wsdata/default/wordlist'), 'billing\nportal');
    assert.deepEqual(records.get('meta').migrated.sort(), ['inventory', 'learned', 'wordlist']);
    // … and only the migrated keys left the old storages.
    assert.deepEqual([...legacy.local.map.keys()].sort(), ['ssds.settings', 'ssds.subdomains.options']);
    assert.deepEqual([...legacy.session.map.keys()], ['other']);
  });

  test('runs once: a later load reads the store and never takes a legacy key again', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const legacy = legacyStorages();
    await makeStore({ backend, legacy }).open();
    // An old tab (a page from before the update) writes the old key again.
    legacy.local.setItem(LEGACY_KEYS.inventory, JSON.stringify({ v: 1, text: 'old-tab 203.0.113.1' }));
    const again = makeStore({ backend, legacy });
    const opened = await again.open();
    assert.deepEqual(opened.migrated, []);
    assert.equal(again.data.inventory.text, INVENTORY_A);
  });

  test('a failed write loses nothing: the data is in memory, the old keys stay, the next load migrates', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    backend.fail.add('write');
    const legacy = legacyStorages();
    const store = makeStore({ backend, legacy });
    const opened = await store.open();
    assert.deepEqual(opened.migrated.sort(), ['inventory', 'learned', 'wordlist']);
    assert.equal(store.data.inventory.text, INVENTORY_A, 'this page works with it');
    assert.equal(store.lastError.name, 'QuotaExceededError');
    assert.ok(legacy.local.getItem(LEGACY_KEYS.inventory), 'kept for the next try');
    assert.ok(legacy.session.getItem(LEGACY_KEYS.wordlist));

    backend.fail.delete('write');
    const next = makeStore({ backend, legacy });
    assert.deepEqual((await next.open()).migrated.sort(), ['inventory', 'learned', 'wordlist']);
    assert.equal(legacy.local.getItem(LEGACY_KEYS.inventory), null);
  });

  test('a failed write goes with the next write that commits (a recent domain, a new workspace): the old data is stored, then the old keys go', async () => {
    for (const write of [(store) => store.recordRecent('example.com'), (store) => store.create('Acme')]) {
      const backend = createMemoryBackend([], { persistent: true });
      backend.fail.add('write');
      const legacy = legacyStorages();
      const store = makeStore({ backend, legacy });
      await store.open();
      backend.fail.delete('write');
      await write(store);
      await store.idle();
      assert.equal(store.lastError, null);
      const records = new Map(backend.entries());
      assert.equal(records.get('wsdata/default/inventory').text, INVENTORY_A);
      assert.deepEqual(records.get('meta').migrated.sort(), ['inventory', 'learned', 'wordlist']);
      assert.ok(records.get('wsmeta/default').createdAt, 'Default has its dates, as after the migration');
      assert.equal(legacy.local.getItem(LEGACY_KEYS.inventory), null, 'removed once stored');
      assert.equal(legacy.session.getItem(LEGACY_KEYS.wordlist), null);
      // This tab: Default still holds it after a trip to another workspace …
      const other = store.list().find((m) => m.id !== DEFAULT_WORKSPACE_ID) || (await store.create('Beta')).meta;
      await store.switchTo(other.id);
      await store.switchTo(DEFAULT_WORKSPACE_ID);
      assert.equal(store.data.inventory.text, INVENTORY_A);
      // … and so does the next load, which migrates nothing again.
      const next = makeStore({ backend, legacy });
      assert.deepEqual((await next.open()).migrated, []);
      assert.equal(next.data.inventory.text, INVENTORY_A);
      assert.deepEqual(Object.keys(next.data.learned.labels), ['api', 'vpn']);
      assert.equal(next.data.wordlist, 'billing\nportal');
    }
  });

  test('a Default part saved while the migration is not written is stored as saved, by whichever write commits', async () => {
    for (const failFirst of [true, false]) {
      const backend = createMemoryBackend([], { persistent: true });
      backend.fail.add('write');
      const legacy = legacyStorages();
      const store = makeStore({ backend, legacy });
      await store.open();
      if (failFirst) {
        await store.save('inventory', { text: INVENTORY_B });
        backend.fail.delete('write');
        await store.recordRecent('example.com');
      } else {
        // Two writes in flight at once: the second must not carry the old inventory over the new one.
        backend.fail.delete('write');
        store.save('inventory', { text: INVENTORY_B });
        store.recordRecent('example.com');
      }
      await store.idle();
      const next = makeStore({ backend, legacy });
      await next.open();
      assert.equal(next.data.inventory.text, INVENTORY_B, `failFirst ${failFirst}`);
      assert.equal(next.data.wordlist, 'billing\nportal');
      assert.deepEqual(next.data.recent.map((r) => r.value), ['example.com']);
    }
  });

  test('once another tab has written, the store holds the old data: this tab no longer carries its copy over it', async () => {
    const { a, b, flush } = channelPair();
    const backend = createMemoryBackend([], { persistent: true });
    backend.fail.add('write');
    const legacy = legacyStorages();
    const one = makeStore({ backend, legacy, channel: a });
    await one.open();
    backend.fail.delete('write');
    const two = makeStore({ backend, legacy: { local: legacy.local, session: new MemoryStorage() }, channel: b });
    await two.open();
    await two.save('inventory', { text: INVENTORY_B });
    await flush();
    await one.recordRecent('example.com');
    await one.idle();
    assert.equal(new Map(backend.entries()).get('wsdata/default/inventory').text, INVENTORY_B);
  });

  test('Default\'s migrated data survives a trip to another workspace while it could not be written', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend, legacy: legacyStorages() });
    backend.fail.add('write');
    await store.open();
    const { meta } = await store.create('Acme');
    await store.switchTo(meta.id);
    await store.switchTo(DEFAULT_WORKSPACE_ID);
    assert.equal(store.data.inventory.text, INVENTORY_A);
  });

  test('without persistent storage the old data is read into memory and left where it is', async () => {
    const legacy = legacyStorages();
    const store = makeStore({ backend: createMemoryBackend(), legacy });
    const opened = await store.open();
    assert.equal(opened.persistent, false);
    assert.equal(store.data.inventory.text, INVENTORY_A);
    assert.ok(legacy.local.getItem(LEGACY_KEYS.inventory), 'nothing removed: nothing was saved');
  });

  test('a storage that refuses removeItem keeps its keys; the "meta" record still stops a second migration', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const legacy = legacyStorages();
    legacy.local.failRemove = true;
    await makeStore({ backend, legacy }).open();
    assert.ok(legacy.local.getItem(LEGACY_KEYS.inventory));
    const again = makeStore({ backend, legacy });
    assert.deepEqual((await again.open()).migrated, []);
  });

  test('nothing to migrate: no database is created', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    await makeStore({ backend, legacy: { local: new MemoryStorage({ 'ssds.settings': '{}' }), session: new MemoryStorage() } }).open();
    assert.deepEqual(backend.entries(), []);
  });
});

describe('degraded storage', () => {
  test('a backend that cannot be read: the page works in memory and says so', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    backend.fail.add('exists');
    const store = makeStore({ backend });
    const opened = await store.open();
    assert.equal(opened.persistent, false);
    assert.equal(store.persistent, false);
    assert.ok(store.lastError);
    const { meta } = await store.create('Acme');
    await store.switchTo(meta.id);
    assert.equal(await store.save('notes', 'kept in memory'), true);
    assert.equal(store.data.notes, 'kept in memory');
  });

  test('a failing write keeps the change in memory and reports it', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    await store.open();
    backend.fail.add('write');
    assert.equal(await store.save('notes', 'unsaved'), false);
    assert.equal(store.data.notes, 'unsaved');
    assert.equal(store.lastError.name, 'QuotaExceededError');
    const created = await store.create('Acme');
    assert.equal(created.persisted, false);
    assert.ok(store.list().some((m) => m.name === 'Acme'), 'usable for this page');
    backend.fail.delete('write');
    assert.equal(await store.save('notes', 'saved'), true);
    assert.equal(store.lastError, null);
  });

  test('a workspace whose creation could not be written is stored by its next write once storage works', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    await store.open();
    backend.fail.add('write');
    const acme = await store.create('Acme', { notes: 'imported', expectedCas: ['DigiCert'] });
    const globex = await store.create('Globex');
    assert.deepEqual([acme.persisted, globex.persisted], [false, false]);
    await store.switchTo(acme.meta.id);
    assert.equal(store.data.notes, 'imported', 'the imported parts are kept in this tab');
    // Still failing: the next write fails for the storage's reason, never "deleted in another tab".
    assert.equal(await store.save('notes', 'typed'), false);
    assert.equal(store.lastError.name, 'QuotaExceededError');

    backend.fail.delete('write');
    assert.equal(await store.save('notes', 'typed again'), true);
    assert.equal(store.lastError, null);
    const stored = () => new Map(backend.entries());
    assert.equal(stored().get(`wsmeta/${acme.meta.id}`).name, 'Acme');
    assert.equal(stored().get(`wsdata/${acme.meta.id}/notes`), 'typed again');
    assert.deepEqual(stored().get(`wsdata/${acme.meta.id}/expectedCas`), ['DigiCert'], 'with what it was created with');
    // A rename stores the other one, under its new name.
    assert.equal((await store.rename(globex.meta.id, 'Globex Corp')).persisted, true);
    assert.equal(stored().get(`wsmeta/${globex.meta.id}`).name, 'Globex Corp');
    // Stored now: a next page lists both, with their data.
    const next = makeStore({ backend });
    const opened = await next.open();
    assert.deepEqual(opened.list.map((m) => m.name), [null, 'Acme', 'Globex Corp']);
    assert.equal((await next.load(acme.meta.id)).notes, 'typed again');
    // And a workspace stored before and deleted since is still refused ('not-found').
    await next.remove(globex.meta.id);
    assert.equal((await store.rename(globex.meta.id, 'Globex Again')).persisted, false);
    assert.equal(store.lastError.code, 'not-found');
    assert.equal(stored().get(`wsmeta/${globex.meta.id}`), undefined);
  });

  test('a workspace not stored yet is replaced or deleted like any other; another tab\'s list keeps it', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const { a, b, flush } = channelPair();
    const tab1 = makeStore({ backend, channel: a });
    const tab2 = makeStore({ backend, channel: b });
    await tab1.open();
    await tab2.open();
    backend.fail.add('write');
    const { meta } = await tab1.create('Acme');
    backend.fail.delete('write');
    await tab2.create('Globex');
    await flush();
    assert.deepEqual(tab1.list().map((m) => m.name), [null, 'Acme', 'Globex'], 'Acme is still listed here');
    assert.equal((await tab1.replace(meta.id, { inventory: { text: INVENTORY_A } })).persisted, true);
    assert.equal(new Map(backend.entries()).get(`wsmeta/${meta.id}`).name, 'Acme');
    await flush();
    assert.ok(tab2.list().some((m) => m.name === 'Acme'), 'the other tab hears of it once stored');

    backend.fail.add('write');
    const later = await tab1.create('Initech');
    backend.fail.delete('write');
    await tab1.remove(later.meta.id);
    await tab1.save('notes', 'Default');
    assert.equal(new Map(backend.entries()).get(`wsmeta/${later.meta.id}`), undefined, 'a deleted one is not stored afterwards');
  });

  test('a failed read of one workspace fails the switch: the page stays in its workspace, nothing is written over it', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    await store.open();
    await store.save('notes', 'Default notes');
    const { meta } = await store.create('Acme', { inventory: 'web01 192.0.2.5', notes: 'Acme notes' });
    backend.fail.add('get');
    await assert.rejects(store.switchTo(meta.id), { name: 'UnknownError' });
    assert.equal(store.active.id, DEFAULT_WORKSPACE_ID);
    assert.equal(store.data.notes, 'Default notes');
    assert.equal(store.lastError.name, 'UnknownError');
    await assert.rejects(store.load(meta.id), { name: 'UnknownError' }, 'never an empty copy for the hand-over file');
    backend.fail.delete('get');
    await store.switchTo(meta.id);
    assert.equal(store.data.inventory.text, 'web01 192.0.2.5');
    assert.equal(store.data.notes, 'Acme notes');
  });

  test('a workspace whose parts cannot be read is never saved over: the page opens in Default, and a Default it must enter keeps its saves in memory', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const first = makeStore({ backend });
    await first.open();
    await first.recordRecent('example.org');
    const { meta } = await first.create('Acme', { inventory: 'web01 192.0.2.5', notes: 'Acme notes' });
    await first.switchTo(meta.id);
    await first.recordRecent('shop.example.com');
    await first.recordRecent('example.com');
    const stored = (id, part) => new Map(backend.entries()).get(`wsdata/${id}/${part}`);
    const snapshot = (id) => ['inventory', 'notes', 'recent'].map((part) => stored(id, part));
    const acme = snapshot(meta.id);
    const def = snapshot(DEFAULT_WORKSPACE_ID);
    /** The backend, with the reads of these workspaces' parts failing. */
    const flaky = (...broken) => ({
      ...backend,
      async get(keys) {
        if (keys.some((k) => broken.some((id) => k.startsWith(`wsdata/${id}/`)))) {
          const err = new Error('read failed');
          err.name = 'UnknownError';
          throw err;
        }
        return backend.get(keys);
      }
    });
    const pointer = { get: () => meta.id, set() {} };

    // The page was in Acme: it opens in Default rather than in an empty-looking Acme.
    const store = makeStore({ backend: flaky(meta.id), pointer });
    await store.open();
    assert.equal(store.active.id, DEFAULT_WORKSPACE_ID);
    assert.deepEqual(store.data.recent.map((r) => r.value), ['example.org']);
    await assert.rejects(store.switchTo(meta.id), { name: 'UnknownError' });
    assert.equal(await store.recordRecent('example.net'), true, 'Default was read: it is written');
    assert.deepEqual(snapshot(meta.id), acme);

    // Default cannot be read either: it is entered, and what is saved to it stays in memory.
    const both = makeStore({ backend: flaky(meta.id, DEFAULT_WORKSPACE_ID), pointer });
    await both.open();
    assert.equal(both.active.id, DEFAULT_WORKSPACE_ID);
    const defNow = snapshot(DEFAULT_WORKSPACE_ID);
    assert.equal(await both.recordRecent('example.com'), false, 'not written over what could not be read');
    assert.equal(await both.save('notes', 'typed here'), false);
    assert.equal(both.data.notes, 'typed here', 'kept in memory');
    assert.equal(both.lastError.name, 'UnknownError');
    await assert.rejects(both.load(DEFAULT_WORKSPACE_ID), { name: 'UnknownError' }, 'never an empty hand-over file');
    assert.deepEqual(snapshot(DEFAULT_WORKSPACE_ID), defNow);
    assert.deepEqual(snapshot(meta.id), acme);

    // Deleting the active workspace enters Default all the same, read or not.
    const deleting = makeStore({ backend: flaky(DEFAULT_WORKSPACE_ID), pointer });
    await deleting.open();
    assert.equal(deleting.active.id, meta.id);
    const { meta: initech } = await deleting.create('Initech');
    await deleting.switchTo(initech.id);
    assert.equal((await deleting.remove(initech.id)).switched, true);
    assert.equal(deleting.active.id, DEFAULT_WORKSPACE_ID);
    assert.equal(await deleting.recordRecent('example.com'), false);
    assert.deepEqual(snapshot(DEFAULT_WORKSPACE_ID), defNow);
    assert.notDeepEqual(defNow, def, 'the first store wrote Default meanwhile');
  });
});

describe('"Delete all local data"', () => {
  test('destroy empties the backend and resets memory at once, before the deletion finishes', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    await store.open();
    const { meta } = await store.create('Acme');
    await store.switchTo(meta.id);
    await store.save('notes', 'secret');
    const pending = store.destroy();
    assert.equal(store.active.id, DEFAULT_WORKSPACE_ID);
    assert.deepEqual(store.data, emptyWorkspaceData());
    assert.deepEqual(store.list().map((m) => m.id), [DEFAULT_WORKSPACE_ID]);
    assert.equal(await pending, true);
    assert.deepEqual(backend.entries(), []);
    // Saving the empty values the views put back writes nothing (no database comes back by itself).
    await store.save('wordlist', '');
    assert.deepEqual(backend.entries(), []);
    // A real save later starts a fresh store (with its 'meta' record, so nothing is migrated again).
    await store.save('notes', 'new');
    assert.ok(backend.entries().some(([k]) => k === 'meta'));
  });

  test('a deletion that fails reports false; memory is reset anyway', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = makeStore({ backend });
    await store.open();
    await store.save('notes', 'x');
    backend.fail.add('destroy');
    assert.equal(await store.destroy(), false);
    assert.equal(store.data.notes, '');
    assert.ok(store.lastError);
    // A deletion that works clears the error: it is no reason of anything any more.
    backend.fail.delete('destroy');
    assert.equal(await store.destroy(), true);
    assert.equal(store.lastError, null);
  });

  test('storage the page could not read at open (it works in memory) is deleted all the same', async () => {
    // A database of a later schema version, a broken one, an open that timed out: the page
    // worked around it in memory, but every customer's data is still in it.
    const entries = [
      ['meta', { v: STORE_VERSION, createdAt: '2026-09-01T00:00:00Z', migrated: [] }],
      ['wsmeta/ws-acme', { id: 'ws-acme', name: 'Acme', createdAt: '2026-09-01T00:00:00Z', updatedAt: '2026-09-01T00:00:00Z' }],
      ['wsdata/ws-acme/notes', 'Acme contacts']
    ];
    const backend = createMemoryBackend(entries, { persistent: true });
    backend.fail.add('list');
    const store = makeStore({ backend });
    const opened = await store.open();
    assert.deepEqual([opened.persistent, store.persistent, store.database], [false, false, true]);
    assert.deepEqual(store.list().map((m) => m.id), [DEFAULT_WORKSPACE_ID]);
    assert.equal(await store.destroy(), true);
    assert.deepEqual(backend.entries(), [], 'nothing stays behind');
    assert.equal(store.lastError, null);
    // Its deletion failing is reported, never passed over.
    const stuck = createMemoryBackend(entries, { persistent: true });
    stuck.fail.add('list');
    const other = makeStore({ backend: stuck });
    await other.open();
    stuck.fail.add('destroy');
    assert.equal(await other.destroy(), false);
    assert.equal(stuck.entries().length, entries.length);
    // A store that never had persistent storage has no database to speak of.
    const memory = makeStore({ backend: createMemoryBackend() });
    await memory.open();
    assert.equal(memory.database, false);
  });

  test('storage the browser refuses altogether is no database: Delete all local data succeeds', async () => {
    // Chrome's "Don't allow sites to save data": databases() rejects (exists() cannot tell), and
    // open() and deleteDatabase() fail with an UnknownError. Nothing was ever stored.
    const refused = createMemoryBackend([], { persistent: true, exists: null });
    for (const op of ['get', 'list', 'write', 'destroy']) refused.fail.add(op);
    const store = makeStore({ backend: refused });
    const opened = await store.open();
    assert.deepEqual([opened.persistent, store.persistent, store.database], [false, false, false]);
    assert.equal(store.lastError.name, 'UnknownError');
    assert.equal(await store.destroy(), true, 'nothing to delete is no failure');
    assert.equal(store.lastError, null);
    // A failure only a database causes keeps it for the deletion, even where exists() cannot tell.
    for (const name of ['VersionError', 'NotFoundError']) {
      const later = createMemoryBackend([], { persistent: true, exists: null });
      later.get = async () => {
        throw Object.assign(new Error('cannot open'), { name });
      };
      const other = makeStore({ backend: later });
      await other.open();
      assert.deepEqual([other.persistent, other.database], [false, true], name);
      later.fail.add('destroy');
      assert.equal(await other.destroy(), false, `${name}: its deletion failing is reported`);
    }
    assert.equal(impliesDatabase(Object.assign(new Error('late'), { code: 'idb-timeout' })), true);
    for (const name of ['UnknownError', 'SecurityError', 'InvalidStateError']) {
      assert.equal(impliesDatabase(Object.assign(new Error('refused'), { name })), false, name);
    }
    assert.equal(impliesDatabase(null), false);
  });
});

describe('several tabs', () => {
  async function twoTabs() {
    const backend = createMemoryBackend([], { persistent: true });
    const { a, b, flush } = channelPair();
    const tab1 = makeStore({ backend, channel: a });
    const tab2 = makeStore({ backend, channel: b });
    await tab1.open();
    await tab2.open();
    const events = [];
    tab2.subscribe((e) => events.push(e));
    return { tab1, tab2, events, flush };
  }

  test('a part written in one tab is read again by the other tab working in the same workspace', async () => {
    const { tab1, tab2, events, flush } = await twoTabs();
    await tab1.save('inventory', { text: INVENTORY_A });
    await flush();
    assert.deepEqual(events, [{ type: 'data', parts: ['inventory'] }]);
    assert.equal(tab2.data.inventory.text, INVENTORY_A);
    await tab1.save('inventory', null);
    await flush();
    assert.equal(tab2.data.inventory, null);
  });

  test('a write to another workspace is no concern of a tab in Default', async () => {
    const { tab1, tab2, events, flush } = await twoTabs();
    const { meta } = await tab1.create('Acme');
    await tab1.switchTo(meta.id);
    await tab1.save('notes', 'Acme only');
    await flush();
    assert.deepEqual(events.map((e) => e.type), ['list']);
    assert.equal(tab2.data.notes, '');
    assert.ok(tab2.list().some((m) => m.name === 'Acme'), 'the list follows');
  });

  test('the workspace a tab works in, deleted in another tab: it goes on in Default', async () => {
    const { tab1, tab2, events, flush } = await twoTabs();
    const { meta } = await tab1.create('Acme');
    await flush();
    await tab2.switchTo(meta.id);
    events.length = 0;
    await tab1.remove(meta.id);
    await flush();
    assert.deepEqual(events.map((e) => e.type), ['switch', 'list']);
    assert.equal(tab2.active.id, DEFAULT_WORKSPACE_ID);
  });

  test('"Delete all local data" in one tab resets the other', async () => {
    const { tab1, tab2, events, flush } = await twoTabs();
    await tab1.save('notes', 'shared');
    await flush();
    assert.equal(tab2.data.notes, 'shared');
    await tab1.destroy();
    await flush();
    assert.equal(events.at(-1).type, 'destroyed');
    assert.equal(tab2.data.notes, '');
  });

  test('a tab that could not read the database still tells the others it deleted it', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const { a, b, flush } = channelPair();
    const tab2 = makeStore({ backend, channel: b });
    await tab2.open();
    await tab2.save('notes', 'stored');
    backend.fail.add('list');
    const tab1 = makeStore({ backend, channel: a });
    await tab1.open();
    backend.fail.delete('list');
    assert.equal(tab1.persistent, false);
    const events = [];
    tab2.subscribe((e) => events.push(e.type));
    assert.equal(await tab1.destroy(), true);
    await flush();
    assert.deepEqual(events, ['destroyed']);
    assert.equal(tab2.data.notes, '');
  });

  test('a write from a tab that has not heard of a rename or a deletion yet never undoes it', async () => {
    // Two tabs whose messages have not arrived yet (no channel): tab 1 keeps the old list.
    const backend = createMemoryBackend([], { persistent: true });
    const tab1 = makeStore({ backend });
    const tab2 = makeStore({ backend });
    await tab1.open();
    const { meta } = await tab1.create('Acme');
    await tab2.open();
    await tab1.switchTo(meta.id);
    await tab2.rename(meta.id, 'Acme Corp');
    assert.equal(tab1.active.name, 'Acme', 'tab 1 still has the old name');
    assert.equal(await tab1.save('notes', 'typed in tab 1'), true);
    const record = () => new Map(backend.entries()).get(`wsmeta/${meta.id}`);
    assert.equal(record().name, 'Acme Corp', 'the rename stands');
    assert.equal(new Map(backend.entries()).get(`wsdata/${meta.id}/notes`), 'typed in tab 1');

    await tab2.remove(meta.id);
    assert.equal(await tab1.save('notes', 'still typing'), false);
    assert.equal(tab1.lastError.code, 'not-found');
    assert.deepEqual(backend.entries().filter(([k]) => k.includes(meta.id)), [], 'the workspace does not come back');
    // A rename from the stale tab does not bring it back either.
    assert.equal((await tab1.rename(meta.id, 'Acme Again')).persisted, false);
    assert.equal(record(), undefined);
  });

  test('createMemoryBackend: a guarded write reads and writes its record with the others, or writes nothing', async () => {
    const backend = createMemoryBackend([['m', { n: 1 }]]);
    const bump = { key: 'm', update: (m) => ({ n: m.n + 1 }) };
    assert.equal(await backend.write([['a', 1]], [], { guard: bump }), true);
    assert.deepEqual(backend.entries(), [['m', { n: 2 }], ['a', 1]]);
    const none = { key: 'gone', update: (v) => (v === undefined ? undefined : v) };
    assert.equal(await backend.write([['b', 2]], ['a'], { guard: none }), false);
    assert.deepEqual(backend.entries(), [['m', { n: 2 }], ['a', 1]], 'nothing written, nothing deleted');
    assert.equal(await backend.write([['b', 2]]), true, 'no guard: a plain write');
  });

  test('a memory-only store tells no other tab anything', async () => {
    const { a, b, flush } = channelPair();
    const tab1 = makeStore({ backend: createMemoryBackend(), channel: a });
    const tab2 = makeStore({ backend: createMemoryBackend(), channel: b });
    await tab1.open();
    await tab2.open();
    const events = [];
    tab2.subscribe((e) => events.push(e));
    await tab1.save('notes', 'mine');
    await flush();
    assert.deepEqual(events, []);
  });
});
