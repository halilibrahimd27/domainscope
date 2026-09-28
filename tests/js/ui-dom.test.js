/**
 * Unit tests for the UI layer's pure parts: i18n, state, the safe DOM builder (against a
 * minimal fake document), download helpers, component helpers (sorting, CSV, decoding),
 * route helpers, the view interface, and repository-wide security invariants (CSP meta,
 * no HTML-injection sinks). No network, no browser.
 */

import { test, describe, mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import * as i18n from '../../assets/js/i18n.js';
import { createState, sanitizeSettings, DEFAULT_SETTINGS, STORAGE_PREFIX } from '../../assets/js/state.js';
import { createWorkspaceStore, createMemoryBackend } from '../../assets/js/lib/workspace.js';
import * as dom from '../../assets/js/ui/dom.js';
import { sanitizeFilename, timestampedName, jsonReplacer } from '../../assets/js/ui/download.js';
import {
  compareValues, ipSortValue, normalizeSearch, csvCell, rowsToCsv, decodeText, describeError, ICON_NAMES, KINDS, CliText
} from '../../assets/js/ui/components.js';
import {
  parseRoute, buildRoute, sameParams, sameSearch, hasRepeatedKeys, VIEWS, REPO_URL, DEFAULT_VIEW
} from '../../assets/js/app.js';
import { DEFAULT_CHAIN } from '../../assets/js/lib/resolvers.js';
import { HttpError } from '../../assets/js/lib/util.js';
import { WORDLIST_SMALL } from '../../assets/js/lib/wordlist.js';
import { NAV_GROUPS } from '../../assets/js/lib/shellnav.js';
import { clearedMessage } from '../../assets/js/ui/workspace-ui.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SPEC_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https:; base-uri 'none'; form-action 'none'; manifest-src 'self'";
const VIEW_IDS = ['subdomains', 'domain', 'zone', 'scan', 'cert', 'renew', 'global', 'lookup', 'bulk', 'ip', 'ptr', 'retire', 'health', 'inventory', 'about'];

/* ------------------------------------------------------------------------ */
/* Minimal fake DOM (just enough for dom.js)                                */
/* ------------------------------------------------------------------------ */

class FakeNode {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this.childNodes = [];
    this.parentNode = null;
  }

  appendChild(child) {
    if (child.nodeType === 11) {
      for (const c of [...child.childNodes]) this.appendChild(c);
      child.childNodes = [];
      return child;
    }
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }

  removeChild(child) {
    this.childNodes = this.childNodes.filter((c) => c !== child);
    child.parentNode = null;
    return child;
  }

  replaceChildren(...nodes) {
    for (const c of [...this.childNodes]) this.removeChild(c);
    nodes.forEach((n) => this.appendChild(n));
  }

  get firstChild() {
    return this.childNodes[0] || null;
  }

  get textContent() {
    return this.childNodes.map((c) => c.textContent).join('');
  }

  set textContent(v) {
    this.replaceChildren(new FakeText(String(v)));
  }
}

class FakeText extends FakeNode {
  constructor(data) {
    super(3);
    this.data = data;
  }

  get textContent() {
    return this.data;
  }
}

class FakeElement extends FakeNode {
  constructor(tag, ns = null) {
    super(1);
    this.tagName = tag.toUpperCase();
    this.namespaceURI = ns;
    this.attributes = new Map();
    this.listeners = [];
    this.dataset = {};
    this.styleProps = new Map();
    this.style = { setProperty: (k, v) => this.styleProps.set(k, v) };
    this.valueSetWithChildren = null;
    this._value = '';
  }

  set value(v) {
    this.valueSetWithChildren = this.childNodes.length;
    this._value = v;
  }

  get value() {
    return this._value;
  }

  setAttribute(k, v) {
    this.attributes.set(k, String(v));
  }

  setAttributeNS(_ns, k, v) {
    this.attributes.set(k, String(v));
  }

  getAttribute(k) {
    return this.attributes.has(k) ? this.attributes.get(k) : null;
  }

  hasAttribute(k) {
    return this.attributes.has(k);
  }

  removeAttribute(k) {
    this.attributes.delete(k);
  }

  addEventListener(type, fn, opts) {
    this.listeners.push({ type, fn, opts });
  }

  removeEventListener(type, fn) {
    this.listeners = this.listeners.filter((l) => !(l.type === type && l.fn === fn));
  }

  dispatch(type, event = {}) {
    for (const l of this.listeners.filter((x) => x.type === type)) l.fn({ type, ...event });
  }
}

class FakeFragment extends FakeNode {
  constructor() {
    super(11);
  }
}

const fakeDocument = {
  createElement: (tag) => new FakeElement(tag),
  createElementNS: (ns, tag) => new FakeElement(tag, ns),
  createTextNode: (s) => new FakeText(s),
  createDocumentFragment: () => new FakeFragment()
};

function withFakeDocument(fn) {
  const prev = globalThis.document;
  globalThis.document = fakeDocument;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete globalThis.document;
    else globalThis.document = prev;
  }
}

/** Storage stub with the Web Storage API surface used by state.js. */
class MemoryStorage {
  constructor(entries = {}) {
    this.map = new Map(Object.entries(entries));
    this.failWrites = false;
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
    if (this.failWrites) {
      const err = new Error('The quota has been exceeded.');
      err.name = 'QuotaExceededError';
      throw err;
    }
    this.map.set(k, String(v));
  }

  removeItem(k) {
    this.map.delete(k);
  }
}

/* ------------------------------------------------------------------------ */
/* i18n                                                                     */
/* ------------------------------------------------------------------------ */

describe('i18n', () => {
  test('interpolate replaces {name}, keeps unknown placeholders, stringifies values', () => {
    assert.equal(i18n.interpolate('Hello {name}!', { name: 'Ayşe' }), 'Hello Ayşe!');
    assert.equal(i18n.interpolate('{a} and {b}', { a: 1 }), '1 and {b}');
    assert.equal(i18n.interpolate('[{x}]', { x: null }), '[]');
    assert.equal(i18n.interpolate('{list}', { list: ['a', 'b'] }), 'a, b');
    assert.equal(i18n.interpolate('{n}', { n: 0 }), '0');
    assert.equal(i18n.interpolate('no params'), 'no params');
    assert.equal(i18n.interpolate('{constructor}', {}), '{constructor}', 'prototype keys are not params');
    assert.equal(i18n.interpolate(null, {}), '');
  });

  test('t() falls back current → English → key, and records missing keys', () => {
    i18n.setLang('en');
    i18n.registerStrings('en', { 'test.onlyEn': 'Only English {x}' });
    i18n.clearMissingKeys();
    i18n.setLang('tr');
    assert.equal(i18n.t('test.onlyEn', { x: 1 }), 'Only English 1');
    assert.equal(i18n.t('test.nowhere'), 'test.nowhere');
    const missing = i18n.getMissingKeys();
    assert.ok(missing.some((m) => m.lang === 'tr' && m.key === 'test.onlyEn'));
    assert.ok(missing.some((m) => m.key === 'test.nowhere'));
    i18n.registerStrings('tr', { 'test.onlyEn': 'Sadece {x}' });
    assert.equal(i18n.t('test.onlyEn', { x: 2 }), 'Sadece 2');
    assert.ok(!i18n.getMissingKeys().some((m) => m.lang === 'tr' && m.key === 'test.onlyEn'), 'registering clears the record');
    i18n.setLang('en');
  });

  test('registerStrings flattens nested objects, rejects unknown languages', () => {
    const n = i18n.registerStrings('en', { testNest: { a: 'A', b: { c: 'C' }, p: { one: '1', other: 'n' } } });
    assert.equal(n, 3);
    assert.equal(i18n.t('testNest.a'), 'A');
    assert.equal(i18n.t('testNest.b.c'), 'C');
    assert.equal(i18n.t('testNest.p', { count: 5 }), 'n');
    assert.throws(() => i18n.registerStrings('de', { x: 'y' }), RangeError);
    assert.equal(i18n.hasString('testNest.a', 'en'), true);
    assert.equal(i18n.hasString('testNest.a', 'tr'), false);
  });

  test('plural forms: CLDR categories, explicit zero, locale-grouped {count}', () => {
    i18n.registerStrings('en', { 'test.rows': { zero: 'No rows', one: '{count} row', other: '{count} rows' } });
    i18n.registerStrings('tr', { 'test.rows': { zero: 'Satır yok', other: '{count} satır' } });
    i18n.setLang('en');
    assert.equal(i18n.t('test.rows', { count: 0 }), 'No rows');
    assert.equal(i18n.t('test.rows', { count: 1 }), '1 row');
    assert.equal(i18n.t('test.rows', { count: 1234 }), '1,234 rows');
    assert.equal(i18n.t('test.rows'), '{count} rows', 'no count → other');
    i18n.setLang('tr');
    assert.equal(i18n.t('test.rows', { count: 1 }), '1 satır', 'Turkish "one" falls back to other');
    assert.equal(i18n.t('test.rows', { count: 1234 }), '1.234 satır');
    assert.equal(i18n.t('test.rows', { count: 0 }), 'Satır yok');
    i18n.setLang('en');
    assert.equal(i18n.plural(2, { one: 'a', other: 'b' }), 'b');
    assert.equal(i18n.plural(1, { one: 'a', other: 'b' }, 'en'), 'a');
    assert.equal(i18n.plural(0, { other: 'b' }), 'b');
    assert.equal(i18n.plural(3, null), '');
  });

  test('a numeric {count} is locale-grouped in plain strings too (Turkish entries are often plain)', async () => {
    i18n.registerStrings('en', { 'test.plainCount': '{count} names' });
    i18n.registerStrings('tr', { 'test.plainCount': '{count} ad' });
    // Real view strings whose Turkish form is a plain string.
    await import('../../assets/js/views/subdomains.js');
    await import('../../assets/js/views/scan.js');
    i18n.setLang('tr');
    try {
      assert.equal(i18n.t('test.plainCount', { count: 12345 }), '12.345 ad');
      assert.equal(i18n.t('test.plainCount', { count: 12 }), '12 ad');
      assert.equal(i18n.t('test.plainCount', { count: '1.234' }), '1.234 ad', 'an already formatted string is left alone');
      assert.equal(i18n.t('sub.opt.permBudgetValue', { count: 5000 }), '5.000 varyasyon');
      assert.equal(i18n.t('scan.opt.permBudgetValue', { count: 5000 }), '5.000 varyasyon');
      assert.equal(i18n.t('sub.stage.candidates', { count: 12345 }), '12.345 ad');
      assert.equal(i18n.t('sub.doneToast', { count: 1234 }), 'Subdomain taraması bitti: 1.234 ad');
      assert.equal(i18n.t('sub.org.net.hosts', { count: 1500 }), '1.500 gri bulut kaydı');
      i18n.setLang('en');
      assert.equal(i18n.t('test.plainCount', { count: 12345 }), '12,345 names');
      assert.equal(i18n.t('sub.opt.permBudgetValue', { count: 5000 }), '5,000 variations');
    } finally {
      i18n.setLang('en');
    }
  });

  test('detectLang / normalizeLang', () => {
    assert.equal(i18n.detectLang({ saved: 'tr', languages: ['en-US'] }), 'tr');
    assert.equal(i18n.detectLang({ saved: 'en', languages: ['tr-TR'] }), 'en');
    assert.equal(i18n.detectLang({ saved: 'de', languages: ['tr-TR'] }), 'tr');
    assert.equal(i18n.detectLang({ languages: ['en-US', 'tr'] }), 'en', 'first preference wins');
    assert.equal(i18n.detectLang({ language: 'TR' }), 'tr');
    assert.equal(i18n.detectLang({ language: 'tr_TR' }), 'tr');
    assert.equal(i18n.detectLang({ languages: [] , language: 'fr-FR' }), 'en');
    assert.equal(i18n.detectLang(), 'en');
    assert.equal(i18n.normalizeLang(' en-GB '), 'en');
    assert.equal(i18n.normalizeLang(42), null);
  });

  test('setLang notifies listeners only on change; unsubscribe works', () => {
    i18n.setLang('en');
    const calls = [];
    const off = i18n.onLangChange((lang, prev) => calls.push([lang, prev]));
    assert.equal(i18n.setLang('en'), false);
    assert.equal(i18n.setLang('xx'), false);
    assert.equal(i18n.setLang('tr-TR'), true);
    assert.equal(i18n.getLang(), 'tr');
    off();
    i18n.setLang('en');
    assert.deepEqual(calls, [['tr', 'en']]);
    assert.equal(i18n.localeTag('tr'), 'tr-TR');
  });

  test('locale-aware formatting helpers', () => {
    i18n.setLang('en');
    assert.equal(i18n.formatNumber(1234567), '1,234,567');
    assert.equal(i18n.formatNumber(null), '');
    assert.equal(i18n.formatNumber('abc'), 'abc');
    assert.equal(i18n.formatPercent(0.42), '42%');
    assert.equal(i18n.formatDuration(850), '850 ms');
    assert.equal(i18n.formatDuration(4200), '4.2 s');
    assert.equal(i18n.formatDuration(12500), '13 s');
    assert.equal(i18n.formatDuration(185000), '3 min 5 s');
    assert.equal(i18n.formatDuration(-1), '—');
    assert.equal(i18n.formatBytes(512), '512 B');
    assert.equal(i18n.formatBytes(1536), '1.5 KB');
    assert.equal(i18n.formatBytes(10 * 1024 * 1024), '10 MB');
    assert.equal(i18n.formatDate('not a date'), '—');
    assert.match(i18n.formatDateTime(new Date(Date.UTC(2026, 8, 23, 12, 5)), { utc: true }), /2026.*12:05 PM UTC/);
    i18n.setLang('tr');
    assert.equal(i18n.formatNumber(1234567), '1.234.567');
    assert.equal(i18n.formatPercent(0.42), '%42');
    assert.equal(i18n.formatDuration(4200), '4,2 sn');
    assert.equal(i18n.formatBytes(1536), '1,5 KB');
    assert.match(i18n.formatDate(new Date(Date.UTC(2026, 8, 23, 12)), { utc: true }), /23 Eyl 2026/);
    i18n.setLang('en');
  });

  test('formatRegion localizes ISO country codes with a fallback', () => {
    i18n.setLang('en');
    assert.equal(i18n.formatRegion('JP'), 'Japan');
    assert.equal(i18n.formatRegion('tr'), 'Türkiye');
    i18n.setLang('tr');
    assert.equal(i18n.formatRegion('JP'), 'Japonya');
    assert.equal(i18n.formatRegion('DE'), 'Almanya');
    i18n.setLang('en');
    assert.equal(i18n.formatRegion(null, 'Anycast'), 'Anycast');
    assert.equal(i18n.formatRegion('XYZ', 'n/a'), 'n/a');
    assert.equal(i18n.formatRegion(''), '');
  });

  test('daysUntil rounds down and handles the past and invalid input', () => {
    const now = Date.UTC(2026, 0, 1, 12);
    assert.equal(i18n.daysUntil(new Date(now + 20 * 3600e3), now), 0);
    assert.equal(i18n.daysUntil(new Date(now + 30 * 86400e3 + 1), now), 30);
    assert.equal(i18n.daysUntil(new Date(now - 3600e3), now), -1);
    assert.equal(i18n.daysUntil('2026-01-11T12:00:00Z', new Date(now)), 10);
    assert.equal(i18n.daysUntil('garbage', now), null);
    assert.equal(i18n.daysUntil(new Date(), NaN), null);
  });

  test('formatRelative picks sensible units', () => {
    i18n.setLang('en');
    const now = Date.UTC(2026, 0, 1);
    assert.equal(i18n.formatRelative(now - 3 * 86400e3, now), '3 days ago');
    assert.equal(i18n.formatRelative(now + 2 * 3600e3, now), 'in 2 hours');
    assert.equal(i18n.formatRelative(now, now), 'now');
    i18n.setLang('tr');
    assert.equal(i18n.formatRelative(now - 3 * 86400e3, now), '3 gün önce');
    i18n.setLang('en');
  });

  test('shell strings: every key exists in both languages, placeholders match', async () => {
    // View modules register their own strings too — check the ones owned by the shell.
    await import('../../assets/js/views/inventory.js');
    await import('../../assets/js/views/about.js');
    const en = i18n.listKeys('en').filter((k) => !k.startsWith('test'));
    const tr = i18n.listKeys('tr').filter((k) => !k.startsWith('test'));
    assert.deepEqual(en.filter((k) => !tr.includes(k)), [], 'keys missing in Turkish');
    assert.deepEqual(tr.filter((k) => !en.includes(k)), [], 'keys missing in English');
    const placeholders = (lang, key) => {
      i18n.setLang(lang);
      const raw = i18n.t(key, { count: 7 });
      // Unique set, like i18n-coverage: one language may use a placeholder twice.
      return [...new Set(raw.match(/\{[A-Za-z0-9_.-]+\}/g) || [])].sort();
    };
    const mismatched = en.filter((k) => JSON.stringify(placeholders('en', k)) !== JSON.stringify(placeholders('tr', k)));
    i18n.setLang('en');
    assert.deepEqual(mismatched, [], 'placeholder sets differ between TR and EN');
  });

  test('every classification reasonKey from netinfo has a translation', async () => {
    const src = await readFile(path.join(ROOT, 'assets/js/lib/netinfo.js'), 'utf8');
    const keys = [...new Set(src.match(/class\.[a-z]+(?:\.[a-z]+)?/g))].filter((k) => k.split('.').length >= 2);
    assert.ok(keys.length >= 15, 'found reason keys in netinfo.js');
    for (const lang of ['en', 'tr']) {
      for (const key of keys) assert.ok(i18n.hasString(key, lang), `${lang}: ${key}`);
    }
    for (const kind of KINDS) {
      assert.ok(i18n.hasString(`kind.${kind}`, 'en') && i18n.hasString(`kind.${kind}`, 'tr'), `kind.${kind}`);
    }
  });
});

/* ------------------------------------------------------------------------ */
/* state                                                                    */
/* ------------------------------------------------------------------------ */

describe('state', () => {
  const make = (storage, now = () => new Date('2026-09-23T10:00:00Z')) => createState({ storage, now, listenStorageEvents: false });

  test('defaults with empty storage', () => {
    const s = make(new MemoryStorage());
    assert.deepEqual(s.settings, { lang: null, theme: 'auto', chain: [...DEFAULT_CHAIN], concurrency: 12, startTasks: true });
    assert.equal(s.inventory.text, '');
    assert.deepEqual(s.inventory.servers, []);
    assert.equal(s.inventory.updatedAt, null);
    assert.equal(s.persistence, true);
    assert.equal(STORAGE_PREFIX, 'ssds.');
  });

  test('inventory round-trips through the workspace store (text only; servers re-parsed)', async () => {
    const storage = new MemoryStorage();
    const backend = createMemoryBackend([], { persistent: true });
    const a = createState({ storage, listenStorageEvents: false, now: () => new Date('2026-09-23T10:00:00Z'), workspaces: createWorkspaceStore({ backend }) });
    await a.ready;
    const res = a.setInventory('web01 10.0.0.5\nweb02 10.0.0.6 2001:db8::6\nbroken');
    assert.equal(res.persisted, true);
    assert.equal(await res.done, true);
    assert.equal(res.inventory.servers.length, 2);
    const raw = new Map(backend.entries()).get('wsdata/default/inventory');
    assert.equal(raw.text.startsWith('web01'), true);
    assert.equal(raw.servers, undefined, 'derived data is not stored');
    assert.equal(storage.getItem('ssds.inventory'), null, 'not in localStorage');
    const b = createState({ storage, listenStorageEvents: false, workspaces: createWorkspaceStore({ backend }) });
    await b.ready;
    assert.equal(b.inventory.servers.length, 2);
    assert.deepEqual(b.inventory.servers[1].ips, ['10.0.0.6', '2001:db8::6']);
    assert.equal(b.inventory.warnings.length, 1);
    assert.ok(b.inventory.updatedAt instanceof Date);
    assert.equal(b.inventory.updatedAt.toISOString(), '2026-09-23T10:00:00.000Z');
  });

  test('corrupt or foreign storage values fall back to defaults', async () => {
    const storage = new MemoryStorage({
      'ssds.inventory': '{not json',
      'ssds.settings': JSON.stringify({ theme: 'neon', lang: 'de', chain: ['nope', 'google', 'google', 'cloudflare'], concurrency: 1000 })
    });
    const s = make(storage);
    await s.ready;
    assert.equal(s.inventory.text, '');
    assert.deepEqual(s.settings, { lang: null, theme: 'auto', chain: ['google', 'cloudflare'], concurrency: 32, startTasks: true });
  });

  test('sanitizeSettings validates each field', () => {
    assert.deepEqual(sanitizeSettings(null), { ...DEFAULT_SETTINGS, chain: [...DEFAULT_CHAIN] });
    assert.equal(sanitizeSettings({ concurrency: 0 }).concurrency, 1);
    assert.equal(sanitizeSettings({ concurrency: '8' }).concurrency, 8);
    assert.equal(sanitizeSettings({ concurrency: 'x' }).concurrency, 12);
    assert.equal(sanitizeSettings({ concurrency: 7.6 }).concurrency, 8);
    assert.deepEqual(sanitizeSettings({ chain: [] }).chain, [...DEFAULT_CHAIN]);
    assert.deepEqual(sanitizeSettings({ chain: 'cloudflare' }).chain, [...DEFAULT_CHAIN]);
    assert.equal(sanitizeSettings({ theme: 'dark', lang: 'tr' }).theme, 'dark');
    assert.equal(sanitizeSettings({ lang: 'tr' }).lang, 'tr');
    assert.equal(sanitizeSettings({}).startTasks, true, 'a record from before the task picker keeps it');
    assert.equal(sanitizeSettings({ startTasks: false }).startTasks, false);
    assert.equal(sanitizeSettings({ startTasks: 'no' }).startTasks, true, 'only an explicit false turns it off');
  });

  test('write failures (quota / disabled storage) keep state in memory and report it', async () => {
    const storage = new MemoryStorage();
    storage.failWrites = true;
    const backend = createMemoryBackend([], { persistent: true });
    const s = createState({ storage, listenStorageEvents: false, workspaces: createWorkspaceStore({ backend }) });
    await s.ready;
    backend.fail.add('write');
    const res = s.setInventory('web01 10.0.0.5');
    assert.equal(await res.done, false);
    assert.equal(s.inventory.servers.length, 1, 'in-memory state still updated');
    assert.equal(s.workspaceError.name, 'QuotaExceededError');
    s.updateSettings({ theme: 'dark' });
    assert.equal(s.lastPersistError.name, 'QuotaExceededError', 'settings too');
    const none = make(null);
    await none.ready;
    assert.equal(none.persistence, false);
    assert.equal(none.workspacePersistence, false, 'no IndexedDB in Node: memory only');
    assert.equal(none.setInventory('a 10.0.0.1').persisted, false);
    assert.equal(none.updateSettings({ theme: 'dark' }).theme, 'dark');
  });

  test('a storage whose getItem throws (SecurityError) degrades to defaults', async () => {
    const hostile = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('no'); }, removeItem() {}, length: 0, key: () => null };
    const s = make(hostile);
    await s.ready;
    assert.equal(s.settings.theme, 'auto');
    assert.equal(await s.clearAll(), true);
  });

  test('updateSettings merges, persists and notifies only on real changes', () => {
    const storage = new MemoryStorage();
    const s = make(storage);
    const events = [];
    const off = s.subscribe((e) => events.push(e));
    s.updateSettings({ theme: 'dark' });
    s.updateSettings({ theme: 'dark' });
    s.updateSettings({ concurrency: 4, chain: ['quad9'] });
    off();
    s.updateSettings({ theme: 'light' });
    assert.equal(events.length, 2);
    assert.equal(events[0].key, 'settings');
    assert.equal(events[0].origin, 'local');
    assert.deepEqual(JSON.parse(storage.getItem('ssds.settings')).chain, ['quad9']);
    const copy = s.settings;
    copy.chain.push('google');
    assert.deepEqual(s.settings.chain, ['quad9'], 'settings getter returns a copy');
    s.resetSettings();
    assert.equal(storage.getItem('ssds.settings'), null);
    assert.equal(s.settings.theme, 'auto');
  });

  test('session: setSession notifies, takeSession is one-shot, direct writes work', () => {
    const s = make(new MemoryStorage());
    const seen = [];
    s.subscribe((e) => seen.push(e));
    s.setSession('pendingCert', { serialHex: '01' });
    assert.deepEqual(s.getSession('pendingCert'), { serialHex: '01' });
    assert.deepEqual(s.takeSession('pendingCert'), { serialHex: '01' });
    assert.equal(s.takeSession('pendingCert'), undefined);
    s.session.draft = 'x';
    assert.equal(s.getSession('draft'), 'x');
    s.setSession('draft', undefined);
    assert.equal('draft' in s.session, false);
    assert.equal(seen[0].key, 'session');
    assert.deepEqual(seen[0].value, { name: 'pendingCert', value: { serialHex: '01' } });
  });

  test('getInventoryIndex is memoized and rebuilt after changes', () => {
    const s = make(new MemoryStorage());
    s.setInventory('web01 10.0.0.5\nweb02 10.0.0.6');
    const idx = s.getInventoryIndex();
    assert.equal(idx, s.getInventoryIndex());
    assert.equal(idx.get('10.0.0.5')[0].name, 'web01');
    s.setInventory('db01 10.0.0.9');
    const idx2 = s.getInventoryIndex();
    assert.notEqual(idx2, idx);
    assert.equal(idx2.has('10.0.0.5'), false);
    s.clearInventory();
    assert.equal(s.getInventoryIndex().size, 0);
  });

  test('clearAll removes only ssds.* keys, every workspace, and resets every slice', async () => {
    const storage = new MemoryStorage({ other: 'keep', 'ssds.extra': '1' });
    const backend = createMemoryBackend([], { persistent: true });
    const s = createState({ storage, listenStorageEvents: false, workspaces: createWorkspaceStore({ backend }) });
    await s.ready;
    const { meta } = await s.createWorkspace('Acme');
    await s.switchWorkspace(meta.id);
    await s.setInventory('web01 10.0.0.5').done;
    await s.setWorkspaceData('notes', 'Acme notes');
    s.updateSettings({ theme: 'dark' });
    s.setSession('x', 1);
    const pending = s.clearAll();
    // Memory is reset at once, before the database is gone.
    assert.equal(s.inventory.servers.length, 0);
    assert.equal(s.workspace.isDefault, true);
    assert.deepEqual(s.workspaces.map((w) => w.id), ['default']);
    assert.equal(s.workspaceData('notes'), '');
    assert.equal(await pending, true);
    assert.deepEqual([...storage.map.keys()], ['other']);
    assert.deepEqual(backend.entries(), [], 'the workspace database is empty');
    assert.equal(s.settings.theme, 'auto');
    assert.equal(s.getSession('x'), undefined);
  });

  test('clearAll also removes the learned names and the custom wordlist, then emits "cleared"', async () => {
    const storage = new MemoryStorage({ 'ssds.subdomains.options': '{}' });
    const sessionStore = new MemoryStorage({ other: 'keep', 'ssds.x': '1' });
    const backend = createMemoryBackend([], { persistent: true });
    const s = createState({ storage, sessionStore, listenStorageEvents: false, workspaces: createWorkspaceStore({ backend }) });
    await s.ready;
    await s.setWorkspaceData('learned', { v: 1, seq: 1, labels: { api: [1, 1] } });
    await s.setWorkspaceData('wordlist', 'api\nvpn');
    const events = [];
    s.subscribe((e) => events.push(e.key));
    assert.equal(await s.clearAll(), true);
    assert.equal(storage.map.size, 0, 'remembered options gone');
    assert.deepEqual([...sessionStore.map.keys()], ['other'], 'only our session keys removed');
    assert.equal(s.workspaceData('learned'), null);
    assert.equal(s.workspaceData('wordlist'), '');
    assert.deepEqual(events, ['inventory', 'settings', 'workspaces', 'cleared']);
    // A broken session storage never breaks "Delete all local data".
    const broken = { get length() { throw new Error('SecurityError'); } };
    assert.equal(await createState({ storage: new MemoryStorage(), sessionStore: broken, listenStorageEvents: false }).clearAll(), true);
    // A database that cannot be deleted is reported.
    const stuck = createMemoryBackend([], { persistent: true });
    const t2 = createState({ storage: new MemoryStorage(), listenStorageEvents: false, workspaces: createWorkspaceStore({ backend: stuck }) });
    await t2.ready;
    stuck.fail.add('destroy');
    assert.equal(await t2.clearAll(), false);
    assert.ok(t2.workspaceError);
  });

  test('clearAll with storage blocked: nothing was stored, so nothing failed, and the message says so', async () => {
    // Safari "Block all cookies": no localStorage, no sessionStorage, the workspaces in memory.
    const s = createState({ storage: null, sessionStore: null, listenStorageEvents: false, workspaces: createWorkspaceStore({ backend: createMemoryBackend() }) });
    await s.ready;
    s.setInventory('web01 10.0.0.5');
    const ok = await s.clearAll();
    assert.equal(ok, true);
    assert.equal(s.inventory.servers.length, 0);
    const blocked = clearedMessage(s, ok);
    assert.deepEqual(blocked, { type: 'success', text: i18n.t('ws.clearedMemory') });
    assert.ok(!/IndexedDB/.test(blocked.text), 'no database is claimed');
    // localStorage works, IndexedDB does not: the workspaces were in this tab only.
    const noDb = createState({ storage: new MemoryStorage(), listenStorageEvents: false, workspaces: createWorkspaceStore({ backend: createMemoryBackend() }) });
    await noDb.ready;
    assert.deepEqual(clearedMessage(noDb, await noDb.clearAll()), { type: 'success', text: i18n.t('ws.clearedNoDb') });
    // Both stored: the database is named.
    const full = createState({ storage: new MemoryStorage(), listenStorageEvents: false, workspaces: createWorkspaceStore({ backend: createMemoryBackend([], { persistent: true }) }) });
    await full.ready;
    const cleared = clearedMessage(full, await full.clearAll());
    assert.equal(cleared.text, i18n.t('ws.cleared'));
    assert.ok(/IndexedDB/.test(cleared.text));
    // A localStorage that throws on removal is a real failure, with its reason in words.
    const stuck = new MemoryStorage({ 'ssds.settings': '{}' });
    stuck.removeItem = () => {
      throw Object.assign(new Error('The operation is insecure.'), { name: 'SecurityError' });
    };
    const failing = createState({ storage: stuck, listenStorageEvents: false, workspaces: createWorkspaceStore({ backend: createMemoryBackend([], { persistent: true }) }) });
    await failing.ready;
    const failed = clearedMessage(failing, await failing.clearAll());
    assert.equal(failed.type, 'error');
    assert.equal(failed.text, i18n.t('ws.clearFailed', { reason: i18n.t('ws.why.denied') }));
  });

  test('clearAll deletes a database the page could not open (it worked in memory), and says the database went', async () => {
    // A database of a later version (a rollback, an old cached build), a broken one, a slow open.
    const backend = createMemoryBackend([
      ['meta', { v: 1, createdAt: '2026-09-01T00:00:00Z', migrated: [] }],
      ['wsmeta/ws-acme', { id: 'ws-acme', name: 'Acme', createdAt: '2026-09-01T00:00:00Z', updatedAt: '2026-09-01T00:00:00Z' }],
      ['wsdata/ws-acme/inventory', { text: 'web01 192.0.2.10', updatedAt: '2026-09-01T00:00:00Z' }]
    ], { persistent: true });
    backend.fail.add('list');
    const s = createState({ storage: new MemoryStorage(), listenStorageEvents: false, workspaces: createWorkspaceStore({ backend }) });
    await s.ready;
    assert.deepEqual([s.workspacePersistence, s.workspaceDatabase], [false, true]);
    const ok = await s.clearAll();
    assert.equal(ok, true);
    assert.deepEqual(backend.entries(), [], 'nothing of Acme stays behind');
    const said = clearedMessage(s, ok);
    assert.deepEqual(said, { type: 'success', text: i18n.t('ws.cleared') });
    assert.ok(!/only in this tab/.test(said.text), said.text);
    // Its deletion failing is an error, with its reason.
    const stuck = createMemoryBackend([['wsmeta/ws-acme', { id: 'ws-acme', name: 'Acme' }]], { persistent: true });
    stuck.fail.add('list');
    const t2 = createState({ storage: new MemoryStorage(), listenStorageEvents: false, workspaces: createWorkspaceStore({ backend: stuck }) });
    await t2.ready;
    stuck.fail.add('destroy');
    const failed = clearedMessage(t2, await t2.clearAll());
    assert.equal(failed.type, 'error');
    assert.equal(stuck.entries().length, 1);
  });

  test('clearAll\'s message gives the reason of the step that failed, not an older write\'s', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const stuck = new MemoryStorage({ 'ssds.settings': '{}' });
    const s = createState({ storage: stuck, listenStorageEvents: false, workspaces: createWorkspaceStore({ backend }) });
    await s.ready;
    // An earlier workspace write failed: the storage was full then.
    backend.fail.add('write');
    await s.setWorkspaceData('notes', 'x');
    assert.equal(s.workspaceError.name, 'QuotaExceededError');
    backend.fail.delete('write');
    // Now only localStorage's removal fails; the database is deleted.
    stuck.removeItem = () => {
      throw Object.assign(new Error('The operation is insecure.'), { name: 'SecurityError' });
    };
    const ok = await s.clearAll();
    assert.equal(ok, false);
    assert.equal(s.workspaceError, null, 'the deletion worked: no workspace error left');
    assert.equal(clearedMessage(s, ok).text, i18n.t('ws.clearFailed', { reason: i18n.t('ws.why.denied') }));
    // And the other way round: localStorage is emptied, the database's deletion fails.
    const other = createMemoryBackend([], { persistent: true });
    const storage = new MemoryStorage();
    const t2 = createState({ storage, listenStorageEvents: false, workspaces: createWorkspaceStore({ backend: other }) });
    await t2.ready;
    storage.setItem = () => {
      throw Object.assign(new Error('full'), { name: 'QuotaExceededError' });
    };
    t2.updateSettings({ theme: 'dark' });
    assert.equal(t2.lastPersistError.name, 'QuotaExceededError');
    other.fail.add('destroy');
    const ok2 = await t2.clearAll();
    assert.equal(ok2, false);
    assert.equal(t2.lastPersistError, null, 'localStorage was emptied');
    assert.equal(clearedMessage(t2, ok2).text, i18n.t('ws.clearFailed', { reason: i18n.t('ws.why.other', { detail: 'memory backend: destroy refused' }) }));
  });

  test('handleExternalChange re-reads the settings another tab wrote (workspaces tell each other themselves)', async () => {
    const storage = new MemoryStorage();
    const s = make(storage);
    await s.ready;
    const events = [];
    s.subscribe((e) => events.push(e));
    storage.setItem('ssds.inventory', JSON.stringify({ v: 1, text: 'web09 10.9.9.9', updatedAt: '2026-01-01T00:00:00Z' }));
    storage.setItem('ssds.settings', JSON.stringify({ v: 1, theme: 'dark' }));
    s.handleExternalChange(null);
    assert.equal(s.inventory.servers.length, 0, 'an old tab\'s inventory key is not today\'s inventory');
    assert.equal(s.settings.theme, 'dark');
    assert.deepEqual(events.map((e) => [e.key, e.origin]), [['settings', 'external']]);
  });

  test('workspaces: separate inventories, a switch clears the session and says so, the recent list', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const s = createState({ storage: new MemoryStorage(), listenStorageEvents: false, workspaces: createWorkspaceStore({ backend }) });
    await s.ready;
    await s.setInventory('web01 192.0.2.10').done;
    const { meta } = await s.createWorkspace('Acme');
    assert.equal(s.workspace.isDefault, true, 'a new workspace does not become active by itself');
    s.setSession('zone', { origin: 'example.com' });
    const events = [];
    s.subscribe((e) => events.push(e.key));
    const active = await s.switchWorkspace(meta.id);
    assert.deepEqual([active.name, active.isDefault], ['Acme', false]);
    assert.deepEqual(events, ['inventory', 'workspace']);
    assert.equal(s.inventory.servers.length, 0);
    assert.equal(s.getSession('zone'), undefined, 'the other customer\'s zone is forgotten');
    await s.setInventory('mail 192.0.2.10').done;
    assert.deepEqual(s.getInventoryIndex().get('192.0.2.10').map((x) => x.name), ['mail'], 'no DUPLICATE_IP across customers');
    await s.recordRecent('https://shop.example.com/');
    assert.deepEqual(s.workspaceData('recent').map((r) => r.value), ['shop.example.com']);
    await s.switchWorkspace('default');
    assert.deepEqual(s.inventory.servers.map((x) => x.name), ['web01']);
    assert.deepEqual(s.workspaceData('recent'), []);
    assert.throws(() => s.workspaceData('settings'), RangeError);
    assert.throws(() => s.setWorkspaceData('inventory', 'x'), RangeError);
  });
});

/* ------------------------------------------------------------------------ */
/* dom.js                                                                   */
/* ------------------------------------------------------------------------ */

describe('dom.js', () => {
  test('isSafeUrl allows relative/http(s)/mailto/tel/blob, blocks script-capable schemes', () => {
    for (const ok of ['#/scan', 'cli/ssl_origin_scan.py', '/abs', 'https://crt.sh/?q=%25.x', 'http://a', 'mailto:a@b.c', 'tel:+90', 'blob:https://x/1', '?q=1']) {
      assert.equal(dom.isSafeUrl(ok), true, ok);
    }
    for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', ' javascript:x', 'java\nscript:alert(1)', 'java\tscript:x', 'vbscript:x', 'data:text/html,<b>', 'file:///etc/passwd', null, 42]) {
      assert.equal(dom.isSafeUrl(bad), false, String(bad));
    }
  });

  test('classNames accepts strings, arrays and maps', () => {
    assert.equal(dom.classNames(['a  b', { c: true, d: false }, null, ['e', ['a']]]), 'a b c e');
    assert.equal(dom.classNames(''), '');
  });

  test('h() builds elements with props, text, attrs, dataset, events and CSSOM styles', () => withFakeDocument(() => {
    const onClick = () => {};
    const el = dom.h('button', {
      class: ['btn', { active: true, hidden: false }],
      id: 'x',
      type: 'button',
      title: 'Hello',
      'aria-label': 'Say hi',
      attrs: { 'data-extra': 'y', disabled: true, removed: false, gone: null },
      dataset: { view: 'scan', skip: null, zero: 0 },
      style: { marginTop: '4px', '--accent': 'red', skip: null },
      on: { click: onClick, keydown: [onClick, { passive: true }] },
      onMouseenter: onClick,
      hidden: true,
      text: 'Hi'
    });
    assert.equal(el.tagName, 'BUTTON');
    assert.equal(el.getAttribute('class'), 'btn active');
    assert.equal(el.getAttribute('id'), 'x');
    assert.equal(el.getAttribute('aria-label'), 'Say hi');
    assert.equal(el.getAttribute('disabled'), '');
    assert.equal(el.hasAttribute('removed'), false);
    assert.equal(el.hasAttribute('gone'), false);
    assert.deepEqual(el.dataset, { view: 'scan', zero: '0' });
    assert.equal(el.styleProps.get('margin-top'), '4px');
    assert.equal(el.styleProps.get('--accent'), 'red');
    assert.equal(el.styleProps.has('skip'), false);
    assert.deepEqual(el.listeners.map((l) => l.type), ['click', 'keydown', 'mouseenter']);
    assert.deepEqual(el.listeners[1].opts, { passive: true });
    assert.equal(el.hidden, true);
    assert.equal(el.textContent, 'Hi');
  }));

  test('children: strings/numbers → text, null/false/true skipped, arrays/iterables flattened, component objects', () => withFakeDocument(() => {
    const inner = dom.h('b', null, 'bold');
    const component = { el: dom.h('i', null, 'comp'), set() {} };
    const el = dom.h('p', null, 'a', 1, null, undefined, false, true, [inner, ['c', [2]]], new Set(['s']), component, 0);
    assert.equal(el.textContent, 'a1boldc2scomp0');
    assert.equal(el.childNodes[2], inner);
    assert.equal(el.childNodes.find((c) => c.tagName === 'I'), component.el);
  }));

  test('the props argument may be omitted (string, node, array or component)', () => withFakeDocument(() => {
    assert.equal(dom.h('span', 'text').textContent, 'text');
    const b = dom.h('b', null, 'x');
    assert.equal(dom.h('span', b).childNodes[0], b);
    assert.equal(dom.h('span', ['a', 'b']).textContent, 'ab');
    const comp = { el: dom.h('i', null, 'c') };
    assert.equal(dom.h('span', comp).textContent, 'c', 'objects with .el are children, not props');
  }));

  test('untrusted strings are never parsed as HTML', () => withFakeDocument(() => {
    const evil = '<img src=x onerror=alert(1)>';
    const el = dom.h('div', { title: evil }, evil);
    assert.equal(el.childNodes[0].nodeType, 3);
    assert.equal(el.textContent, evil);
    assert.equal(el.getAttribute('title'), evil);
  }));

  test('dangerous props/attributes are refused', () => withFakeDocument(() => {
    assert.throws(() => dom.h('div', { innerHTML: '<b>x</b>' }), /not allowed/);
    assert.throws(() => dom.h('div', { outerHTML: 'x' }), /not allowed/);
    assert.throws(() => dom.h('iframe', { srcdoc: 'x' }), /not allowed/);
    assert.throws(() => dom.h('div', { attrs: { onclick: 'alert(1)' } }), /event handler/);
    assert.throws(() => dom.h('div', { onclick: 'alert(1)' }), /event handler/);
    assert.throws(() => dom.h('div', { attrs: { style: 'color:red' } }), /style/);
    assert.throws(() => dom.h('div', { style: 'color:red' }), /style must be an object/);
    const a = dom.h('a', { href: 'javascript:alert(1)' }, 'x');
    assert.equal(a.hasAttribute('href'), false, 'script URL dropped');
    const img = dom.h('img', { src: 'data:image/svg+xml,<svg onload=alert(1)>' });
    assert.equal(img.hasAttribute('src'), false);
    assert.equal(dom.h('a', { href: 'https://crt.sh/' }).getAttribute('href'), 'https://crt.sh/');
    assert.equal(dom.h('a', { href: '#/lookup?name=x' }).getAttribute('href'), '#/lookup?name=x');
  }));

  test('value is applied after children (so <select value> finds its options)', () => withFakeDocument(() => {
    const sel = dom.h('select', { value: 'b' }, dom.h('option', { value: 'a' }), dom.h('option', { value: 'b' }));
    assert.equal(sel.value, 'b');
    assert.equal(sel.valueSetWithChildren, 2);
    const cb = dom.h('input', { type: 'checkbox', checked: 1, disabled: 0 });
    assert.equal(cb.checked, true);
    assert.equal(cb.disabled, false);
    const alias = dom.h('label', { htmlFor: 'f', className: 'l', tabIndex: 0 });
    assert.equal(alias.getAttribute('for'), 'f');
    assert.equal(alias.getAttribute('class'), 'l');
    assert.equal(alias.getAttribute('tabindex'), '0');
  }));

  test('ref callback receives the finished element', () => withFakeDocument(() => {
    let got = null;
    const el = dom.h('div', { ref: (e) => { got = e; } }, 'x');
    assert.equal(got, el);
    assert.equal(got.textContent, 'x');
  }));

  test('svg() uses the SVG namespace; frag/text/clear/mount work', () => withFakeDocument(() => {
    const s = dom.svg('svg', { attrs: { viewBox: '0 0 24 24' } }, dom.svg('path', { attrs: { d: 'M0 0' } }));
    assert.equal(s.namespaceURI, 'http://www.w3.org/2000/svg');
    assert.equal(s.childNodes[0].namespaceURI, 'http://www.w3.org/2000/svg');
    const f = dom.frag('a', dom.h('b', null, 'c'));
    const host = dom.h('div');
    host.appendChild(f);
    assert.equal(host.textContent, 'ac');
    dom.clear(host);
    assert.equal(host.childNodes.length, 0);
    dom.mount(host, 'x', dom.text('y'), dom.text(null));
    assert.equal(host.textContent, 'xy');
    assert.equal(dom.clear(null), null);
  }));

  test('on() returns an unsubscribe function; uid() is unique', () => withFakeDocument(() => {
    const el = dom.h('div');
    const off = dom.on(el, 'click', () => {});
    assert.equal(el.listeners.length, 1);
    off();
    assert.equal(el.listeners.length, 0);
    assert.notEqual(dom.uid('a'), dom.uid('a'));
    assert.match(dom.uid(), /^ui-\d+$/);
  }));

  test('isPlainObject distinguishes props bags from nodes and components', () => withFakeDocument(() => {
    assert.equal(dom.isPlainObject({}), true);
    assert.equal(dom.isPlainObject(Object.create(null)), true);
    assert.equal(dom.isPlainObject({ el: dom.h('i') }), false);
    assert.equal(dom.isPlainObject(dom.h('i')), false);
    assert.equal(dom.isPlainObject([]), false);
    assert.equal(dom.isPlainObject('x'), false);
    assert.equal(dom.isNode(dom.text('x')), true);
  }));

  test('debounce delays, coalesces, cancels and flushes', () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    try {
      const calls = [];
      const d = dom.debounce((v) => calls.push(v), 100);
      d(1);
      d(2);
      mock.timers.tick(99);
      assert.deepEqual(calls, []);
      mock.timers.tick(1);
      assert.deepEqual(calls, [2]);
      d(3);
      d.cancel();
      mock.timers.tick(200);
      assert.deepEqual(calls, [2]);
      d(4);
      d.flush();
      assert.deepEqual(calls, [2, 4]);
      d.flush();
      assert.deepEqual(calls, [2, 4], 'flush without pending call is a no-op');
    } finally {
      mock.timers.reset();
    }
  });

  test('h() without a document fails loudly (never silently)', () => {
    const prev = globalThis.document;
    delete globalThis.document;
    try {
      assert.throws(() => dom.h('div'), /no document/);
    } finally {
      if (prev !== undefined) globalThis.document = prev;
    }
  });

  test('scrollBehavior: smooth, or a jump when the user asked for reduced motion', () => {
    const prev = Object.getOwnPropertyDescriptor(globalThis, 'matchMedia');
    const queries = [];
    try {
      for (const [reduce, expected] of [[true, 'auto'], [false, 'smooth']]) {
        globalThis.matchMedia = (q) => {
          queries.push(q);
          return { matches: reduce };
        };
        assert.equal(dom.scrollBehavior(), expected);
      }
      assert.deepEqual(queries, ['(prefers-reduced-motion: reduce)', '(prefers-reduced-motion: reduce)']);
      globalThis.matchMedia = () => {
        throw new Error('unsupported');
      };
      assert.equal(dom.scrollBehavior(), 'smooth');
      delete globalThis.matchMedia;
      assert.equal(dom.scrollBehavior(), 'smooth', 'no matchMedia (Node): smooth');
    } finally {
      if (prev) Object.defineProperty(globalThis, 'matchMedia', prev);
      else delete globalThis.matchMedia;
    }
  });
});

/* ------------------------------------------------------------------------ */
/* download.js                                                              */
/* ------------------------------------------------------------------------ */

describe('download.js', () => {
  test('sanitizeFilename keeps Turkish letters and removes path/reserved characters', () => {
    assert.equal(sanitizeFilename('hosts-örnek.com.tr.csv'), 'hosts-örnek.com.tr.csv');
    assert.equal(sanitizeFilename('a/b:c*?.txt'), 'a-b-c-.txt');
    assert.equal(sanitizeFilename('..\\..\\evil'), 'evil');
    assert.equal(sanitizeFilename('  my report  .json'), 'my-report-.json');
    assert.equal(sanitizeFilename('CON.txt'), '_CON.txt');
    assert.equal(sanitizeFilename('lpt1'), '_lpt1');
    assert.equal(sanitizeFilename(''), 'download');
    assert.equal(sanitizeFilename('...', 'x'), 'x');
    assert.equal(sanitizeFilename(null), 'download');
    const long = sanitizeFilename(`${'a'.repeat(300)}.csv`);
    assert.equal(long.length, 150);
    assert.ok(long.endsWith('.csv'));
  });

  test('timestampedName formats local time and includes the subject', () => {
    const d = new Date(2026, 8, 3, 7, 5);
    assert.equal(timestampedName('hosts', 'csv', 'example.com', d), 'hosts-example.com-20260903-0705.csv');
    assert.equal(timestampedName('scan', '.json', null, d), 'scan-20260903-0705.json');
    assert.equal(timestampedName('names', '', '', d), 'names-20260903-0705');
    assert.match(timestampedName('x', 'txt', undefined, new Date('bad')), /^x-\d{8}-\d{4}\.txt$/);
  });

  test('jsonReplacer converts Map/Set, drops binary, stringifies bigint', () => {
    const value = { m: new Map([['a', 1]]), s: new Set([1, 2]), der: new Uint8Array([1]), buf: new ArrayBuffer(2), big: 12n, d: new Date(Date.UTC(2026, 0, 1)) };
    assert.equal(JSON.stringify(value, jsonReplacer), '{"m":{"a":1},"s":[1,2],"big":"12","d":"2026-01-01T00:00:00.000Z"}');
  });
});

/* ------------------------------------------------------------------------ */
/* components.js (pure helpers)                                             */
/* ------------------------------------------------------------------------ */

describe('components.js helpers', () => {
  const collator = new Intl.Collator('en', { numeric: true, sensitivity: 'base' });

  test('compareValues: numbers, bigints, dates, booleans, arrays and natural strings', () => {
    assert.ok(compareValues(2, 10) < 0);
    assert.ok(compareValues(10n, 2) > 0);
    assert.equal(compareValues(5n, 5), 0);
    assert.ok(compareValues(new Date(1), new Date(2)) < 0);
    assert.ok(compareValues(false, true) < 0);
    assert.ok(compareValues([3, 1], [2, 9]) > 0);
    assert.ok(compareValues('web2', 'web10', collator) < 0, 'natural order');
    assert.equal(compareValues('ABC', 'abc', collator), 0, 'case-insensitive');
    assert.ok(compareValues('b', 'a') > 0, 'works without a collator');
  });

  test('ipSortValue orders IPv4 numerically before IPv6; invalid → null', () => {
    const ips = ['2001:db8::1', '10.0.0.10', '10.0.0.9', '9.255.255.255', '::1', '10.0.0.9'];
    const sorted = ips.slice().sort((a, b) => compareValues(ipSortValue(a), ipSortValue(b)));
    assert.deepEqual(sorted, ['9.255.255.255', '10.0.0.9', '10.0.0.9', '10.0.0.10', '::1', '2001:db8::1']);
    assert.equal(ipSortValue('not-an-ip'), null);
    assert.equal(ipSortValue(undefined), null);
  });

  test('normalizeSearch folds case and diacritics (Turkish İ/ı handled)', () => {
    assert.equal(normalizeSearch('İSTANBUL'), 'istanbul');
    assert.equal(normalizeSearch('Örnek A.Ş.'), 'ornek a.s.');
    assert.equal(normalizeSearch(null), '');
    assert.equal(normalizeSearch(42), '42');
  });

  test('csvCell quotes per RFC 4180 and neutralises spreadsheet formulas', () => {
    assert.equal(csvCell('plain'), 'plain');
    assert.equal(csvCell('a,b'), '"a,b"');
    assert.equal(csvCell('say "hi"'), '"say ""hi"""');
    assert.equal(csvCell('line1\nline2'), '"line1\nline2"');
    assert.equal(csvCell('semi;colon'), '"semi;colon"', 'Excel TR uses ; as separator');
    assert.equal(csvCell(' padded'), '" padded"');
    assert.equal(csvCell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"');
    assert.equal(csvCell('+1'), "'+1");
    assert.equal(csvCell('@SUM(A1)'), "'@SUM(A1)");
    assert.equal(csvCell('-cmd'), "'-cmd");
    assert.equal(csvCell('-12.5'), '-12.5', 'negative numbers stay numeric');
    assert.equal(csvCell(-3), '-3');
    assert.equal(csvCell(null), '');
    assert.equal(csvCell(true), 'true');
    assert.equal(csvCell(new Date(Date.UTC(2026, 0, 1))), '2026-01-01T00:00:00.000Z');
    assert.equal(csvCell(['a', 'b']), 'a b');
  });

  test('rowsToCsv writes a BOM, header and CRLF lines', () => {
    const csv = rowsToCsv([{ n: 'web01', ip: '10.0.0.1' }, { n: 'şube', ip: null }], [
      { header: 'Name', get: (r) => r.n },
      { header: 'IP', get: (r) => r.ip }
    ]);
    assert.equal(csv, '﻿Name,IP\r\nweb01,10.0.0.1\r\nşube,\r\n');
    assert.equal(rowsToCsv([], [{ header: 'A', get: () => 1 }], { bom: false }), 'A\r\n');
  });

  test('decodeText honours UTF-8/UTF-16 BOMs', () => {
    const enc = new TextEncoder();
    assert.equal(decodeText(enc.encode('web01 10.0.0.1')), 'web01 10.0.0.1');
    assert.equal(decodeText(new Uint8Array([0xef, 0xbb, 0xbf, ...enc.encode('şube')]).buffer), 'şube');
    const le = new Uint8Array([0xff, 0xfe, 0x41, 0x00, 0x15, 0x01]); // "Aĕ"
    assert.equal(decodeText(le), 'Aĕ');
    const be = new Uint8Array([0xfe, 0xff, 0x00, 0x41]);
    assert.equal(decodeText(be), 'A');
    assert.equal(decodeText(new Uint8Array([0xff, 0x41])), '�A', 'invalid UTF-8 is replaced, not thrown');
    assert.equal(decodeText(undefined), '');
  });

  test('describeError maps error kinds to translated messages with details', () => {
    i18n.setLang('en');
    const net = describeError(Object.assign(new TypeError('Failed to fetch'), { url: 'https://x.test/' }));
    assert.equal(net.kind, 'network');
    assert.match(net.message, /Network error/);
    assert.match(net.detail, /Failed to fetch · https:\/\/x\.test\//);
    const http = describeError(new HttpError(503, 'https://crt.sh/', 'busy', { statusText: 'Service Unavailable' }));
    assert.equal(http.kind, 'http');
    assert.match(http.detail, /HTTP 503 Service Unavailable/);
    const rl = describeError(new HttpError(429, 'https://a.test/'));
    assert.equal(rl.kind, 'rate-limit');
    assert.deepEqual(describeError('plain message'), { kind: 'unknown', message: 'plain message', detail: '' });
    assert.equal(describeError(undefined).kind, 'unknown');
  });

  test('CliText keeps each CLI option in one unbreakable code element, the rest as text', () => withFakeDocument(() => {
    const el = CliText('a --strict-public b');
    assert.equal(el.tagName, 'SPAN');
    assert.deepEqual(el.childNodes.map((c) => [c.nodeType, c.tagName ?? null, c.textContent]), [
      [3, null, 'a '], [1, 'CODE', '--strict-public'], [3, null, ' b']
    ]);
    assert.equal(el.childNodes[1].getAttribute('class'), 'nowrap');
    // options at the edges and side by side leave no empty text nodes
    const edges = CliText('--private-ca FILE and --fail-on-needs-update');
    assert.deepEqual(edges.childNodes.map((c) => c.textContent), ['--private-ca', ' FILE and ', '--fail-on-needs-update']);
    assert.deepEqual(CliText('--a --b').childNodes.map((c) => c.tagName ?? c.textContent), ['CODE', ' ', 'CODE']);
    // no option (a lone dash, an en dash, 2-3): text only, never a code element
    for (const text of ['Not counted as old - see below', 'port 1–65535', '']) {
      const plain = CliText(text);
      assert.ok(plain.childNodes.every((c) => c.nodeType === 3), text);
      assert.equal(plain.textContent, text);
    }
    assert.equal(CliText(null).textContent, '');
    assert.equal(CliText('<b>--x</b>').textContent, '<b>--x</b>', 'text, never parsed as HTML');
  }));

  test('icon set covers every navigation and kind icon', () => {
    for (const v of VIEWS) assert.ok(ICON_NAMES.includes(v.icon), v.icon);
    for (const name of ['cloud', 'zap', 'box', 'server', 'lock', 'help', 'x-circle', 'unlink', 'check-circle', 'alert', 'info', 'copy', 'download', 'upload']) {
      assert.ok(ICON_NAMES.includes(name), name);
    }
    assert.deepEqual([...KINDS].sort(), ['cdn', 'cloudflare', 'dangling', 'direct', 'nxdomain', 'platform', 'private', 'unresolved']);
  });
});

/* ------------------------------------------------------------------------ */
/* app.js route helpers + view interface                                    */
/* ------------------------------------------------------------------------ */

describe('routing', () => {
  test('parseRoute handles views, params, case, repeats and non-route anchors', () => {
    const r = parseRoute('#/lookup?name=example.com&type=MX');
    assert.equal(r.view, 'lookup');
    assert.deepEqual(r.params, { name: 'example.com', type: 'MX' });
    assert.equal(r.isRoute, true);
    assert.equal(parseRoute('#/LOOKUP').view, 'lookup');
    assert.equal(parseRoute('#/global/extra?x=1').view, 'global');
    const multi = parseRoute('#/lookup?type=A&type=MX');
    assert.equal(multi.params.type, 'MX');
    assert.deepEqual(multi.searchParams.getAll('type'), ['A', 'MX']);
    assert.deepEqual(parseRoute('#/nope'), { ...parseRoute('#/nope'), view: null, isRoute: true });
    assert.equal(parseRoute('#main').isRoute, false);
    assert.equal(parseRoute('').isRoute, false);
    assert.equal(parseRoute(undefined).view, null);
    assert.equal(parseRoute('#/%E0%A4%A').view, null, 'malformed escapes do not throw');
    assert.equal(parseRoute('#/').view, null);
    assert.equal(parseRoute('#/scan?q=a%20b+c').params.q, 'a b c');
  });

  test('buildRoute skips empty values, encodes, and round-trips', () => {
    assert.equal(buildRoute('lookup', { name: 'example.com', type: 'MX', empty: '', none: null, off: false, on: true }), '#/lookup?name=example.com&type=MX&on=1');
    assert.equal(buildRoute('lookup', { type: ['A', '', 'AAAA'] }), '#/lookup?type=A&type=AAAA');
    assert.equal(buildRoute('scan'), '#/scan');
    assert.equal(buildRoute(''), `#/${DEFAULT_VIEW}`);
    const params = { name: 'örnek.com.tr', q: 'a&b=c #x', n: '5' };
    assert.deepEqual(parseRoute(buildRoute('global', params)).params, params);
  });

  test('sameParams compares shallowly as strings', () => {
    assert.equal(sameParams({ a: '1' }, { a: 1 }), true);
    assert.equal(sameParams({}, {}), true);
    assert.equal(sameParams({ a: '1' }, { a: '1', b: '2' }), false);
    assert.equal(sameParams(null, {}), true);
  });

  test('sameSearch compares whole queries: repeated keys count, the order of different keys does not', () => {
    const q = (s) => parseRoute(`#/scan?${s}`).searchParams;
    assert.equal(sameSearch(q('domain=a.example.com&domain=b.example.com'), q('domain=b.example.com')), false,
      'flattened params (last wins) would call these equal');
    assert.equal(sameSearch(q('domain=x.example.com&domain=b.example.com'), q('domain=a.example.com&domain=b.example.com')), false);
    assert.equal(sameSearch(q('name=example.com&type=MX'), q('type=MX&name=example.com')), true);
    assert.equal(sameSearch(q('type=A&type=MX'), q('type=MX&type=A')), false, 'the values of one key keep their order');
    assert.equal(sameSearch(new URLSearchParams(), q('')), true);
  });

  test('hasRepeatedKeys spots a query that view.update() params would flatten', () => {
    assert.equal(hasRepeatedKeys(parseRoute('#/scan?domain=a.example.com&domain=b.example.com').searchParams), true);
    assert.equal(hasRepeatedKeys(parseRoute('#/lookup?name=example.com&type=MX').searchParams), false);
    assert.equal(hasRepeatedKeys(new URLSearchParams()), false);
  });

  test('VIEWS follow the spec order; REPO_URL is a placeholder https URL', () => {
    assert.deepEqual(VIEWS.map((v) => v.id), VIEW_IDS);
    assert.ok(VIEWS.every((v) => typeof v.load === 'function' && NAV_GROUPS.some((g) => g.id === v.group)), 'every view in a known nav group');
    assert.match(REPO_URL, /^https:\/\/github\.com\//);
  });

  test('every view module exports the view interface and a title string', async () => {
    for (const id of VIEW_IDS) {
      const mod = await import(`../../assets/js/views/${id}.js`);
      const view = mod.default && typeof mod.default.mount === 'function' ? mod.default : mod;
      assert.equal(view.id, id, `${id}: id`);
      assert.equal(typeof view.mount, 'function', `${id}: mount`);
      assert.equal(typeof view.titleKey, 'string', `${id}: titleKey`);
      assert.ok(i18n.hasString(view.titleKey, 'en') && i18n.hasString(view.titleKey, 'tr'), `${id}: title translated`);
      assert.ok(ICON_NAMES.includes(view.icon), `${id}: icon "${view.icon}" exists`);
      if (view.unmount !== undefined) assert.equal(typeof view.unmount, 'function', `${id}: unmount`);
    }
  });

  test('inventory view helpers: lineRange and targetsText', async () => {
    const { lineRange, targetsText } = await import('../../assets/js/views/inventory.js');
    const text = 'a\nbb\n\nccc';
    assert.deepEqual(lineRange(text, 1), [0, 1]);
    assert.deepEqual(lineRange(text, 2), [2, 4]);
    assert.deepEqual(lineRange(text, 3), [5, 5]);
    assert.deepEqual(lineRange(text, 4), [6, 9]);
    assert.deepEqual(lineRange(text, 99), [6, 9], 'clamped to the last line');
    assert.deepEqual(lineRange(text, 0), [0, 1], 'clamped to the first line');
    assert.equal(targetsText([{ name: 'web01', ips: ['10.0.0.1', '2001:db8::1'] }, { name: 'x', ips: [] }]), 'web01 10.0.0.1 2001:db8::1\n');
    assert.equal(targetsText([]), '');
    // Names with spaces, '#', '//', ';' or '=' (CSV columns, AWS Name tags) stay one CLI token per
    // server; tests/python/test_inventory_targets.py parses the same file with the CLI.
    const expected = await readFile(path.join(ROOT, 'tests/fixtures/inventory-targets.txt'), 'utf8');
    assert.equal(targetsText([
      { name: 'Web Server 1', ips: ['192.0.2.11'] },
      { name: 'Web Server 2', ips: ['192.0.2.12'] },
      { name: '#bastion', ips: ['192.0.2.13'] },
      { name: '[prod] api', ips: ['192.0.2.14'] },
      { name: 'Web #2', ips: ['198.51.100.2'] },
      { name: '// legacy', ips: ['198.51.100.3'] },
      { name: 'db;backup', ips: ['198.51.100.4'] },
      { name: 'role=web', ips: ['198.51.100.5'] },
      { name: 'db primary', ips: ['203.0.113.1', '2001:db8::1'] },
      { name: 'db replica', ips: ['203.0.113.2'] },
      { name: 'rack\u001cweb', ips: ['203.0.113.3'] },
      { name: '203.0.113.9', ips: ['203.0.113.9'] },
      { name: '192.0.2.50-60', ips: ['192.0.2.15'] },
      { name: 'ansible_host: web', ips: ['192.0.2.16'] }
    ]), expected);
    // Addresses written with a port keep it: tests/python/test_inventory_targets.py reads this file back with the CLI.
    const { parseInventory } = await import('../../assets/js/lib/inventory.js');
    const inventory = parseInventory(await readFile(path.join(ROOT, 'tests/fixtures/inventory-ports.txt'), 'utf8'));
    assert.equal(targetsText(inventory.servers), await readFile(path.join(ROOT, 'tests/fixtures/inventory-ports-targets.txt'), 'utf8'));
  });
});

/* ------------------------------------------------------------------------ */
/* Discovery engine v2 in the Subdomains / SSL Targets views                */
/* ------------------------------------------------------------------------ */

describe('subdomains / scan view helpers (discovery engine v2)', () => {
  const load = async () => ({
    S: await import('../../assets/js/views/subdomains.js'),
    C: await import('../../assets/js/views/scan.js'),
    src: await import('../../assets/js/lib/sources.js')
  });
  const inLang = (lang, fn) => {
    const prev = i18n.getLang();
    i18n.setLang(lang);
    try {
      return fn();
    } finally {
      i18n.setLang(prev);
    }
  };
  const host = (name, origins, extra = {}) => ({
    name,
    origins,
    wildcardSuspect: !!extra.wildcard,
    classification: { kind: extra.kind || 'direct', hidesOrigin: extra.kind === 'cloudflare', dangling: false, provider: extra.kind === 'cloudflare' ? { name: 'Cloudflare' } : null },
    resolution: { ipv4: extra.ips || [], ipv6: [], cnames: [], status: 'NOERROR' },
    candidateNetworks: extra.networks || [],
    servers: []
  });

  test('sanitizeOptions (Subdomains): smart by default, legacy medium → smart, budgets validated, new sources surfaced once', async () => {
    const { S, src } = await load();
    const ids = src.SOURCES.map((s) => s.id);
    const d = S.sanitizeOptions(null);
    assert.equal(d.bruteforce, 'smart');
    assert.equal(d.permutations, true);
    assert.equal(d.permutationBudget, 1500);
    assert.equal(d.originHints, true);
    assert.deepEqual(d.knownSources, ids);
    assert.equal(S.sanitizeOptions({ bruteforce: 'medium' }).bruteforce, 'smart', 'a saved medium level still loads');
    assert.equal(S.sanitizeOptions({ bruteforce: 'large' }).bruteforce, 'large');
    assert.equal(S.sanitizeOptions({ bruteforce: 'off' }).bruteforce, 'off');
    assert.equal(S.sanitizeOptions({ bruteforce: 'huge' }).bruteforce, 'huge', 'huge is now a real level');
    assert.equal(S.sanitizeOptions({ bruteforce: 'nonsense' }).bruteforce, 'smart', 'an unknown level falls back to smart');
    assert.equal(S.sanitizeOptions({ permutationBudget: 5000 }).permutationBudget, 5000);
    assert.equal(S.sanitizeOptions({ permutationBudget: 123 }).permutationBudget, 1500);
    assert.equal(S.sanitizeOptions({ permutations: false, originHints: false }).permutations, false);
    // Languages / learned: auto (null) + learned names OFF by default (opt-in: they are sent as
    // DNS lookups under every later target); explicit values validated / kept.
    assert.equal(d.locales, null, 'languages default to automatic (from the TLD)');
    assert.equal(d.learned, false, 'learned names are opt-in');
    assert.equal(S.sanitizeOptions({ learned: true }).learned, true, 'an explicit opt-in is kept');
    assert.equal(S.sanitizeOptions({ learned: 'yes' }).learned, false, 'only a real true opts in');
    assert.deepEqual(S.sanitizeOptions({ locales: ['de', 'nope', 'tr', 'de'] }).locales, ['tr', 'de'], 'unknown packs dropped, deduped, pack order');
    assert.deepEqual(S.sanitizeOptions({ locales: [] }).locales, [], 'none is kept distinct from auto');
    assert.equal(S.sanitizeOptions({ learned: false }).learned, false);
    // No knownSources (never saved by an older version of this view): the selection is kept as is.
    assert.deepEqual(S.sanitizeOptions({ sources: [] }).sources, []);
    // A source added after the save (not in knownSources) is switched on once; an unticked known one stays off.
    const known = ids.filter((x) => x !== 'thc');
    assert.deepEqual(S.sanitizeOptions({ sources: ['crtsh'], knownSources: known }).sources, ['crtsh', 'thc']);
    assert.deepEqual(S.sanitizeOptions({ sources: ['crtsh'], knownSources: ids }).sources, ['crtsh']);
  });

  test('sanitizeOptions (SSL Targets): legacy saves gain only the sources added later', async () => {
    const { C } = await load();
    assert.deepEqual(C.BRUTEFORCE_MODES, ['off', 'small', 'smart', 'large', 'huge']);
    const legacy = C.sanitizeOptions({ sources: ['crtsh', 'nope', 'crtsh'], bruteforce: 'medium', includeExpired: 'yes', originHints: false });
    assert.deepEqual(legacy.sources, ['crtsh', 'thc'], 'unticked legacy sources stay off; ip.thc.org is new');
    assert.equal(legacy.bruteforce, 'smart');
    assert.equal(legacy.includeExpired, false);
    assert.equal(legacy.originHints, false);
    assert.equal(legacy.permutationBudget, 1500);
    const again = C.sanitizeOptions({ ...legacy, sources: ['crtsh'] });
    assert.deepEqual(again.sources, ['crtsh'], 'once known, an unticked source stays unticked');
  });

  test('estimateText / wordlistCount give rough, localized numbers (build-time counts, sweep-aware)', async () => {
    const { S } = await load();
    inLang('en', () => {
      assert.equal(S.estimateText(5760), '≈ 50 s');
      assert.equal(S.estimateText(159), '≈ 10 s');
      assert.equal(S.estimateText(20500), '≈ 3 min');
      assert.equal(S.estimateText(5760, 2), '≈ 100 s', 'two domains take twice as long');
      // A lower sweep width (a gentler Settings value) takes proportionally longer.
      assert.equal(S.estimateText(5760, 1, 12), '≈ 100 s', 'half the sweep width, twice the time');
      assert.equal(S.wordlistCount('small').count, WORDLIST_SMALL.length);
      // Counts are exact build-time constants now — no "≈".
      assert.equal(S.wordlistCount('large').text, S.wordlistCount('large').count.toLocaleString('en-US'));
      assert.ok(S.wordlistCount('large').count > S.wordlistCount('smart').count);
      assert.ok(S.wordlistCount('huge').count > S.wordlistCount('large').count, 'huge is the largest tier');
    });
    inLang('tr', () => assert.equal(S.estimateText(5760), '≈ 50 sn'));
    const n = await S.ensureSmartCount();
    assert.ok(n > 5000, `smart list size ${n}`);
    assert.equal(S.wordlistCount('smart').count, n);
    assert.equal(S.levelCount('off'), 0, 'off has no candidates');
    assert.match(S.levelSize('large'), /\bKB\b|\bMB\b/, 'large advertises a download size');
    assert.equal(S.levelSize('small'), '', 'the built-in small list has no download');
  });

  test('wordlistPlan: per-domain candidate counts, locale packs and the per-domain / total caps', async () => {
    const { S } = await load();
    const off = S.wordlistPlan({ level: 'off', domains: ['example.com'] });
    assert.equal(off.total, 0);
    assert.deepEqual(off.perDomain, []);
    // Smart + auto Turkish pack for a .com.tr domain; custom/learned add on top.
    const smart = S.wordlistPlan({ level: 'smart', domains: ['example.com.tr'], custom: 3, learned: 5 });
    const pd = smart.perDomain[0];
    assert.deepEqual(pd.packs.map((p) => p.code), ['tr'], 'auto pack from the ccSLD');
    assert.equal(pd.total, S.levelCount('smart') + pd.packs[0].count + 3 + 5);
    assert.equal(pd.capped, false);
    assert.equal(smart.total, pd.total, 'one domain');
    // Small is language-neutral: no packs even for a .de domain.
    assert.deepEqual(S.wordlistPlan({ level: 'small', domains: ['example.de'] }).perDomain[0].packs, []);
    // Explicit locales override the auto pick; [] means the global list only.
    assert.deepEqual(S.wordlistPlan({ level: 'smart', domains: ['example.com.tr'], locales: ['de'] }).perDomain[0].packs.map((p) => p.code), ['de']);
    assert.deepEqual(S.wordlistPlan({ level: 'smart', domains: ['example.com.tr'], locales: [] }).perDomain[0].packs, []);
    // Huge is capped per domain, and the whole scan is capped at the total.
    const huge = S.wordlistPlan({ level: 'huge', domains: ['a.com', 'b.com'], custom: 300000 });
    assert.equal(huge.perDomain[0].total, S.BRUTEFORCE_CAPS.huge, 'per-domain cap');
    assert.equal(huge.perDomain[0].capped, true);
    assert.equal(huge.total, S.BRUTEFORCE_TOTAL_CAP, 'multi-domain total cap');
  });

  test('locale helpers: auto pick from the TLD, a readable summary and the effective packs', async () => {
    const { S } = await load();
    assert.deepEqual(S.autoLocales(['example.com.tr']).map((p) => ({ suffix: p.suffix, codes: p.codes })), [{ suffix: '.com.tr', codes: ['tr'] }]);
    assert.deepEqual(S.autoLocales(['example.ch'])[0].codes, ['de', 'fr', 'it'], 'Switzerland → several packs');
    assert.deepEqual(S.autoLocales(['example.com'])[0].codes, [], '.com has no market pack');
    assert.deepEqual(S.effectiveLocales(null, 'example.de'), ['de'], 'auto for a domain');
    assert.deepEqual(S.effectiveLocales(['tr'], 'example.de'), ['tr'], 'explicit wins');
    assert.deepEqual(S.effectiveLocales([], 'example.de'), [], 'none');
    inLang('en', () => {
      assert.equal(S.localeSummary(null, ['example.com.tr']), 'Auto: Turkish (.com.tr)');
      assert.equal(S.localeSummary(null, ['example.com']), 'Auto: none — .com has no market pack, so the global list is used');
      assert.equal(S.localeSummary(['de', 'fr'], []), 'Chosen: German, French');
      assert.equal(S.localeSummary([], []), 'None: the global list only');
    });
    inLang('tr', () => {
      assert.equal(S.localeSummary(null, ['example.com.tr']), 'Otomatik: Türkçe (.com.tr)');
      assert.equal(S.localeSummary([], []), 'Hiçbiri: yalnızca küresel liste');
    });
  });

  test('wordlistScanConfig maps options + labels to a runScan config (locales auto vs explicit)', async () => {
    const { S } = await load();
    const auto = S.wordlistScanConfig({ bruteforce: 'smart', locales: null, learned: true }, { custom: ['api'], learned: ['vpn'] });
    assert.equal(auto.bruteforce, 'smart');
    assert.ok(!('locales' in auto), 'auto: locales left undefined so the scanner picks per domain');
    assert.deepEqual(auto.customWordlist, ['api']);
    assert.deepEqual(auto.learnedLabels, ['vpn']);
    const manual = S.wordlistScanConfig({ bruteforce: 'huge', locales: ['tr', 'nope'], learned: false }, { custom: [], learned: ['vpn'] });
    assert.deepEqual(manual.locales, ['tr'], 'explicit packs validated');
    assert.ok(!('customWordlist' in manual), 'no custom labels → field omitted');
    assert.ok(!('learnedLabels' in manual), 'learned off → labels not passed');
    // Opt-in only: a missing switch (older saved options, a caller that forgot it) passes nothing.
    assert.ok(!('learnedLabels' in S.wordlistScanConfig({ bruteforce: 'smart', locales: null }, { learned: ['vpn'] })), 'no explicit opt-in → none');
    // Level Off: the scanner would still feed learned labels to the permutation words and the
    // recursive round — another target's vocabulary must not go out when nothing is to be guessed.
    const off = S.wordlistScanConfig({ bruteforce: 'off', locales: null, learned: true }, { custom: ['api'], learned: ['erp-prod', 'vpn-ist'] });
    assert.equal(off.bruteforce, 'off');
    assert.ok(!('learnedLabels' in off), 'level Off → learned labels never passed');
    assert.deepEqual(off.customWordlist, ['api'], 'the scan\'s own custom list still seeds permutations');
  });

  test('wordlist caps and the probe rate: one constant each, in step with lib/scanplan', async () => {
    const { S } = await load();
    const plan = await import('../../assets/js/lib/scanplan.js');
    assert.deepEqual({ ...plan.MAX_BRUTEFORCE_PER_BASE }, { ...S.BRUTEFORCE_CAPS }, 'per-domain caps mirror the scanner');
    assert.equal(plan.MAX_BRUTEFORCE_TOTAL, S.BRUTEFORCE_TOTAL_CAP, 'multi-domain cap mirrors the scanner');
    // lib/scanner.js declares no cap of its own: it imports these.
    const src = await readFile(new URL('../../assets/js/lib/scanner.js', import.meta.url), 'utf8');
    assert.doesNotMatch(src, /const (?:MAX_BRUTEFORCE_PER_BASE|MAX_BRUTEFORCE_TOTAL) =/);
    assert.ok(S.BRUTEFORCE_CAPS.huge >= S.levelCount('huge'), 'one huge scan can try the whole huge tier');
    // Every estimate derives from PROBE_RATE_QPS at the full sweep width.
    assert.equal(S.probeRate(), S.PROBE_RATE_QPS);
    assert.equal(S.probeRate(S.MAX_SWEEP_CONCURRENCY / 2), S.PROBE_RATE_QPS / 2);
    const hugeMinutes = S.levelCount('huge') / S.PROBE_RATE_QPS / 60;
    inLang('en', () => assert.equal(S.estimateText(S.levelCount('huge')), `≈ ${Math.round(hugeMinutes)} min`));
    assert.ok(hugeMinutes > 5, 'huge really is "many minutes"');
  });

  test('wordlistPlanText: one honest sentence per plan (per-domain breakdown for several domains)', async () => {
    const { S } = await load();
    inLang('en', () => {
      const one = S.wordlistPlan({ level: 'smart', domains: ['example.com.tr'], custom: 2 });
      const tr = one.perDomain[0].packs[0].count;
      const total = S.levelCount('smart') + tr + 2;
      assert.equal(S.wordlistPlanText(one),
        `≈ ${total.toLocaleString('en-US')} DNS queries for 1 domain (${S.levelCount('smart').toLocaleString('en-US')} smart, +${tr} Turkish, +2 yours) · ${S.estimateText(total)}`);
      const two = S.wordlistPlan({ level: 'smart', domains: ['example.de', 'example.fr'] });
      assert.match(S.wordlistPlanText(two), /for 2 domains \(per domain: [\d,]+ smart, \+[\d,]+ German, \+[\d,]+ French\)/);
      assert.match(S.wordlistPlanText(S.wordlistPlan({ level: 'huge', domains: ['example.org'], learned: 999999 })), /capped at 160,000 per domain/);
      assert.equal(S.wordlistPlanText(S.wordlistPlan({ level: 'off', domains: ['example.org'] })), '');
    });
    // The level labels add the packs the typed domains get (each once), from Smart up.
    assert.deepEqual(S.levelPacks('small', ['example.com.tr'], null), [], 'small is language-neutral');
    assert.deepEqual(S.levelPacks('smart', ['example.com.tr', 'shop.example.com.tr'], null).map((p) => p.code), ['tr']);
    assert.deepEqual(S.levelPacks('huge', ['example.ch'], null).map((p) => p.code), ['de', 'fr', 'it']);
    assert.deepEqual(S.levelPacks('large', [], ['pl']).map((p) => p.code), ['pl'], 'a manual choice applies before a domain is typed');
    assert.deepEqual(S.levelPacks('off', ['example.de'], null), []);
    inLang('tr', () => {
      assert.match(S.wordlistPlanText(S.wordlistPlan({ level: 'small', domains: ['example.org'] })), /^1 alan adı için ≈ [\d.]+ DNS sorgusu \([\d.]+ küçük\) · ≈ \d+ sn$/);
    });
  });

  test('planQueryRange / queryRangeText: the honest whole-scan estimate (perms + recursive + hints), not the wordlist size', async () => {
    const { S } = await load();
    const smart = S.planQueryRange({ level: 'smart', domains: ['example.com'] });
    assert.ok(smart.min > S.levelCount('smart'), 'the floor already exceeds the wordlist (mining + wildcard + resolve)');
    assert.ok(smart.max > smart.min, 'the ceiling adds the permutation / recursive / hint budgets');
    // Turning permutations and origin hints off lowers both ends.
    const lean = S.planQueryRange({ level: 'smart', domains: ['example.com'], permutations: false, originHints: false });
    assert.ok(lean.max < smart.max, 'no variations / hints → a smaller ceiling');
    // A .com.tr adds the Turkish pack, so the floor rises.
    const tr = S.planQueryRange({ level: 'smart', domains: ['example.com.tr'] });
    assert.ok(tr.min > smart.min, 'the auto Turkish pack lifts the floor');
    // A real smart+TR run measured 8,664–8,952 DNS queries; the range must bracket it.
    assert.ok(tr.min <= 8664 && tr.max >= 8952, `range ${tr.min}-${tr.max} brackets a real run`);
    inLang('en', () => {
      assert.equal(S.queryRangeText({ min: 7000, max: 7000 }), '7,000', 'a single number when the ends coincide');
      assert.equal(S.queryRangeText({ min: 7300, max: 11500 }), '7,300–11,500');
    });
    inLang('tr', () => assert.equal(S.queryRangeText({ min: 7300, max: 11500 }), '7.300–11.500'));
    // wordlistPlanText uses the range when given, and the plan total as a fallback otherwise.
    inLang('en', () => {
      const plan = S.wordlistPlan({ level: 'smart', domains: ['example.com'] });
      assert.match(S.wordlistPlanText(plan, S.MAX_SWEEP_CONCURRENCY, { min: 7000, max: 9000 }), /^≈ 7,000–9,000 DNS queries for 1 domain \(/);
      assert.match(S.wordlistPlanText(plan), new RegExp(`^≈ ${plan.total.toLocaleString('en-US')} DNS queries for 1 domain \\(`), 'fallback: the plan total');
    });
  });

  test('streaming partials: partialHostRecord is table-shaped and marked _partial; liveHosts merges, full wins', async () => {
    const { S } = await load();
    const p = S.partialHostRecord({ name: 'api.x.com', origin: 'wordlist', ipv4: ['203.0.113.5'], cnames: [], classification: { kind: 'direct', provider: null, dangling: false, hidesOrigin: false, reasonKey: 'class.direct' } });
    assert.equal(p._partial, true);
    assert.deepEqual(p.resolution.ipv4, ['203.0.113.5']);
    assert.deepEqual(p.resolution.ipv6, [], 'AAAA arrives with the full record');
    assert.deepEqual(p.origins, ['wordlist']);
    assert.ok(Array.isArray(p.servers) && Array.isArray(p.originCandidates), 'shaped like a HostRecord');
    assert.equal(p.resolution.status, 'NOERROR', 'NOERROR when the partial carries no status');
    const dangling = S.partialHostRecord({ name: 'blog.x.com', origin: 'wordlist', status: 'NXDOMAIN', ipv4: [], cnames: ['x.ghost.example.net'], classification: { kind: 'unresolved', provider: null, dangling: true, hidesOrigin: false, reasonKey: 'class.dangling.nxdomain' } });
    assert.equal(dangling.resolution.status, 'NXDOMAIN', 'a dangling alias keeps its rcode');
    // liveHosts: partials show while running; a full record of the same name supersedes its partial.
    const run = { result: null, hosts: [], found: new Map([['api.x.com', p]]) };
    assert.deepEqual(S.liveHosts(run).map((x) => x.name), ['api.x.com']);
    const full = { name: 'api.x.com', _partial: false };
    run.hosts = [full];
    assert.deepEqual(S.liveHosts(run), [full], 'the full record wins; the partial is not double-counted');
    run.result = { hosts: [full, { name: 'www.x.com' }] };
    assert.equal(S.liveHosts(run).length, 2, 'once finished, the result hosts are authoritative');
  });

  test('originSweep --exclude: an octet drops from the /24, a fully-covered network drops out, invalid / unused reported', async () => {
    const { S } = await load();
    const result = {
      hosts: [host('www.x.com', ['wordlist'], { kind: 'cloudflare', ips: ['104.21.1.1'], networks: ['203.0.113.0/24'] })],
      originNetworks: [{ cidr: '203.0.113.0/24', ips: ['203.0.113.5'], hosts: ['api.x.com'], provider: null, shared: false, sweep: 'cidr' }],
      cliTargets: ['203.0.113.0/24'],
      cliNames: ['www.x.com']
    };
    const networks = [{ cidr: '203.0.113.0/24', ips: ['203.0.113.5'], hosts: ['api.x.com'], provider: null, shared: false, sweep: 'cidr' }];
    // No exclude → the old shape exactly.
    assert.deepEqual(S.originSweep(result, { names: ['www.x.com'], networks }), {
      command: 'python3 ssl_origin_scan.py -t 203.0.113.0/24 -n www.x.com', namesFile: null, namesText: '', count: 1
    });
    // Excluding an address inside the /24 emits --exclude and keeps the target.
    const ex = S.originSweep(result, { names: ['www.x.com'], networks, exclude: ['203.0.113.9'] });
    assert.match(ex.command, /-t 203\.0\.113\.0\/24 --exclude 203\.0\.113\.9 -n www\.x\.com$/);
    assert.deepEqual(ex.emitted, ['203.0.113.9'], 'the exclude is written as --exclude');
    assert.deepEqual(ex.excluded, [], 'no whole target was removed');
    assert.equal(ex.droppedTargets, 0);
    // Excluding the whole /24 removes it from -t → no command left.
    const gone = S.originSweep(result, { names: ['www.x.com'], networks, exclude: ['203.0.113.0/24'] });
    assert.equal(gone.command, null);
    assert.equal(gone.droppedTargets, 1, 'the fully-covered network dropped out of the sweep');
    // An invalid token and one that touches nothing are reported, not emitted.
    const rep = S.originSweep(result, { names: ['www.x.com'], networks, exclude: ['not-an-ip', '198.51.100.0/24'] });
    assert.deepEqual(rep.excludeDropped, ['not-an-ip']);
    assert.deepEqual(rep.excludeUnused, ['198.51.100.0/24']);
    assert.match(rep.command, /^python3 ssl_origin_scan\.py -t 203\.0\.113\.0\/24 -n www\.x\.com$/, 'no --exclude when nothing overlaps');
  });

  test('the JSON export carries the ORIGIN panel command with its exclusions (originSweepFor / originExport)', async () => {
    const { S } = await load();
    const result = {
      hosts: [host('www.x.com', ['wordlist'], { kind: 'cloudflare', ips: ['104.21.1.1'], networks: ['203.0.113.0/24'] })],
      originNetworks: [{ cidr: '203.0.113.0/24', ips: ['203.0.113.5'], hosts: ['api.x.com'], provider: null, shared: false, sweep: 'cidr' }],
      originHints: [],
      cliTargets: ['203.0.113.0/24', '198.51.100.25'],
      cliNames: ['www.x.com']
    };
    // Without exclusions the panel's command is originOverview's, byte for byte, in both shells.
    const o = S.originOverview(result);
    assert.equal(S.originSweepFor(result).command, o.command);
    assert.equal(S.originSweepFor(result, { shell: 'powershell' }).command, o.commands.powershell);
    // A fully-covered target drops out of -t; an address inside the /24 becomes --exclude.
    const gone = S.originSweepFor(result, { exclude: ['198.51.100.25'] });
    assert.equal(gone.command, 'python3 ssl_origin_scan.py -t 203.0.113.0/24 -n www.x.com');
    assert.deepEqual(gone.excluded, ['198.51.100.25']);
    assert.match(S.originSweepFor(result, { exclude: ['203.0.113.9'] }).command, / --exclude 203\.0\.113\.9 -n /);
    // The export: the same networks and command, and what the exclusions did.
    const plain = S.originExport(result);
    assert.deepEqual(plain, { networks: o.networks, hints: [], cliSuggestion: o.command, exclude: null });
    const ex = S.originExport(result, ['198.51.100.25', 'not-an-ip']);
    assert.equal(ex.cliSuggestion, gone.command, 'whoever runs the exported command never probes the excluded address');
    assert.deepEqual(ex.exclude, { requested: ['198.51.100.25', 'not-an-ip'], emitted: [], excluded: ['198.51.100.25'], unused: [], invalid: ['not-an-ip'] });
    // Wiring: the panel and the export read the same helper and the run's exclusions, which are kept
    // per run at module level (a re-mount — another view and back, a language switch — keeps them).
    const src = await readFile(path.join(ROOT, 'assets/js/views/subdomains.js'), 'utf8');
    assert.match(src, /origin: run\.result \? originExport\(run\.result, originExclude\.tokens\) : null/, 'the export reads the panel exclusions');
    assert.match(src, /const currentSweep = \(shell\) => originSweepFor\(r, \{/, 'the panel reads the same helper');
    assert.match(src, /let originExclude = originExcludes\.get\(run\);/, 'the exclusions outlive the mounted panel');
    assert.doesNotMatch(src, /const originExclude = \{ tokens: \[\] \};/);
  });

  test('originOverview: sibling-domain candidates (engine v3) and the shared-space flag', async () => {
    const { S } = await load();
    const proxied = host('ticket.a.com', ['wordlist'], { kind: 'cloudflare', ips: ['104.21.1.1'], networks: ['203.0.113.0/24'] });
    // Engine v3: the host carries ordered originCandidates including a cross-brand sibling.
    proxied.originCandidates = [
      { ip: '203.0.113.20', kind: 'sibling-domain', score: 95, evidence: { sibling: 'ticket.b.com' } },
      { cidr: '203.0.113.0/24', kind: 'network', score: 60, evidence: { relation: 'main-cluster' } }
    ];
    const result = {
      hosts: [proxied, host('ticket.b.com', ['wordlist'], { ips: ['203.0.113.20'] })],
      originHints: [],
      originNetworks: [{ cidr: '203.0.113.0/24', ips: ['203.0.113.20'], hosts: ['ticket.b.com'], provider: null, shared: false, sweep: 'cidr' }],
      cliTargets: ['203.0.113.0/24'],
      cliNames: ['ticket.a.com']
    };
    const o = S.originOverview(result);
    assert.deepEqual(o.proxied[0].siblings, [{ ip: '203.0.113.20', sibling: 'ticket.b.com' }], 'sibling candidate surfaced from originCandidates');
    assert.equal(o.siblingCount, 1);
    assert.equal(o.shared, false, 'no shared network here');
    // A shared provider network raises the flag (offline: the network entry says shared).
    const sharedResult = {
      ...result,
      originNetworks: [{ cidr: '198.51.100.0/24', ips: ['198.51.100.5'], hosts: ['api.a.com'], provider: { name: 'Fastly', category: 'cdn' }, shared: true, sweep: 'ips' }],
      hosts: [host('www.a.com', ['wordlist'], { kind: 'cloudflare', ips: ['104.21.1.2'], networks: ['198.51.100.0/24'] }), host('api.a.com', ['wordlist'], { ips: ['198.51.100.5'] })],
      cliNames: ['www.a.com']
    };
    assert.equal(S.originOverview(sharedResult).shared, true, 'a shared cloud / hosting network flags the panel');
  });

  test('custom wordlist: kept in the active workspace, parsed with accepted / rejected counts', async () => {
    const { S } = await load();
    const { state: singleton } = await import('../../assets/js/state.js');
    await singleton.ready;
    let other = null;
    try {
      S.saveCustomWordlist('');
      assert.deepEqual(S.customWordlist().labels, [], 'empty by default');
      // Node has no IndexedDB: the workspace lives in memory, and the view says so.
      assert.equal(S.saveCustomWordlist('api\nbilling, dev.api\n-bad-\n'), 'memory');
      assert.equal(singleton.workspaceData('wordlist'), 'api\nbilling, dev.api\n-bad-\n', 'the raw text is the workspace\'s');
      const cw = S.customWordlist();
      assert.deepEqual(cw.labels, ['api', 'billing', 'dev.api']);
      assert.deepEqual(cw.rejected, ['-bad-']);
      assert.equal(cw.stored, 'memory');
      S.resetCustomWordlist();
      assert.deepEqual(S.customWordlist().labels, ['api', 'billing', 'dev.api'], 'the workspace is the truth, not a module copy');
      // Another customer has a list of its own.
      other = (await singleton.createWorkspace('Wordlist test')).meta;
      await singleton.switchWorkspace(other.id);
      assert.deepEqual(S.customWordlist().labels, [], 'another workspace, another list');
      S.saveCustomWordlist('portal');
      assert.deepEqual(S.sharedVocabulary().custom, ['portal']);
      await singleton.switchWorkspace('default');
      assert.deepEqual(S.customWordlist().labels, ['api', 'billing', 'dev.api']);
    } finally {
      if (other) await singleton.deleteWorkspace(other.id);
      S.saveCustomWordlist('');
    }
  });

  test('learned names: only bare labels of resolving, non-suspect names are recorded — and only when switched on', async () => {
    const { S } = await load();
    const { createLearnedStore } = await import('../../assets/js/lib/learned.js');
    const storage = new MemoryStorage();
    const store = createLearnedStore(storage);
    const result = {
      domains: ['example.com'],
      hosts: [
        host('api.example.com', ['wordlist'], { ips: ['192.0.2.10'] }),
        host('dev.panel.example.com', ['crtsh'], { ips: ['192.0.2.12'] }),
        host('gone.example.com', ['crtsh']), // not resolving
        host('fake.example.com', ['wordlist'], { ips: ['192.0.2.13'], wildcard: true }),
        host('203.example.com', ['wordlist'], { ips: ['192.0.2.14'] }), // numeric: no convention signal
        // Another organisation's names (a certificate SAN, an extra hostname): outside every
        // scanned domain, so neither the brand label nor its subdomain labels are learned.
        host('acmebrand.org', ['input'], { ips: ['192.0.2.2'] }),
        host('portal.acmebrand.org', ['cert'], { ips: ['192.0.2.3'] })
      ]
    };
    assert.equal(S.rememberLearned(result, false, () => store), 0, 'switch off: nothing is saved');
    assert.equal(store.size(), 0);
    assert.equal(S.rememberLearned(result, true, () => store), 3);
    assert.deepEqual(store.labels().sort(), ['api', 'dev', 'panel'], 'no acmebrand / portal from out-of-scope names');
    const raw = storage.getItem('ssds.learned.labels');
    assert.ok(raw && !/example|192\.0\.2|\./.test(Object.keys(JSON.parse(raw).labels).join(' ')), `labels only: ${raw}`);
    assert.equal(S.rememberLearned(null, true, () => store), 0, 'no result, no change');
    assert.equal(S.rememberLearned(result, true, () => { throw new Error('storage gone'); }), 0, 'never throws');
    // The runScan config takes the learned labels only while the switch is on (most frequent first, capped).
    const many = Array.from({ length: S.LEARNED_TRY_MAX + 5 }, (_, i) => `n${i}x`);
    assert.equal(S.wordlistScanConfig({ bruteforce: 'smart', locales: null, learned: true }, { learned: many }).learnedLabels.length, S.LEARNED_TRY_MAX);
  });

  test('sharedVocabulary: SSL Targets reuses the Subdomains languages and the workspace\'s custom list and learned names', async () => {
    const { S } = await load();
    const { state: singleton } = await import('../../assets/js/state.js');
    await singleton.ready;
    const prevL = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
    const local = new MemoryStorage({ [S.OPTIONS_KEY]: JSON.stringify({ locales: ['de'], learned: true }) });
    Object.defineProperty(globalThis, 'localStorage', { value: local, configurable: true, writable: true });
    try {
      await singleton.setWorkspaceData('learned', { v: 1, seq: 2, labels: { vpn: [3, 1], shop: [1, 2] } });
      S.saveCustomWordlist('kunden\nportal');
      assert.deepEqual(S.sharedVocabulary(), { locales: ['de'], learnedOn: true, custom: ['kunden', 'portal'], learned: ['vpn', 'shop'] });
      // The learned store the scans record into is the workspace's too.
      S.learnedStore().record(['intranet.example.com'], 'example.com');
      assert.ok(singleton.workspaceData('learned').labels.intranet, 'recorded into the active workspace');
      local.setItem(S.OPTIONS_KEY, JSON.stringify({ learned: false }));
      const off = S.sharedVocabulary();
      assert.equal(off.locales, null, 'automatic languages');
      assert.deepEqual([off.learnedOn, off.learned], [false, []], 'learned names switched off in Subdomains');
    } finally {
      await singleton.setWorkspaceData('learned', null);
      S.saveCustomWordlist('');
      if (prevL) Object.defineProperty(globalThis, 'localStorage', prevL);
      else delete globalThis.localStorage;
    }
  });

  test('"Delete all local data" drops the workspace\'s custom wordlist and learned names with no Subdomains view mounted', async () => {
    const { S } = await load();
    const { state: singleton } = await import('../../assets/js/state.js');
    await singleton.ready;
    S.saveCustomWordlist('billing\nintranet');
    await singleton.setWorkspaceData('learned', { v: 1, seq: 1, labels: { vpn: [1, 1] } });
    assert.deepEqual(S.customWordlist().labels, ['billing', 'intranet']);
    // About / Settings wipe it from any view.
    await singleton.clearAll();
    assert.equal(S.loadCustomWordlist(), '', 'the textarea of a later mount starts empty');
    assert.deepEqual(S.customWordlist().labels, [], 'the next scan probes nothing stale');
    assert.deepEqual(S.sharedVocabulary().custom, [], 'SSL Targets sees it gone too');
    assert.equal(S.learnedStore().size(), 0);
  });

  test('learned names never reach another target when the wordlist level is Off (view config → real runScan)', async () => {
    const { S } = await load();
    const { runScan } = await import('../../assets/js/lib/scanner.js');
    const { DohClient } = await import('../../assets/js/lib/doh.js');
    const { RESOLVERS } = await import('../../assets/js/lib/resolvers.js');
    const { decodeMessage, encodeMessage, base64UrlDecode } = await import('../../assets/js/lib/dnswire.js');
    // Customer B's zone; api.B has children, so the permutation and the deeper (recursive) rounds run.
    const B = 'customer-b.example';
    const zone = { [B]: '203.0.113.1', [`api.${B}`]: '203.0.113.2', [`v1.api.${B}`]: '203.0.113.3', [`v2.api.${B}`]: '203.0.113.4' };
    const queried = [];
    const fetchImpl = async (url) => {
      if (!RESOLVERS.some((r) => url.startsWith(`${r.url}?`))) throw new TypeError(`unexpected URL ${url}`);
      const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
      queried.push(q.name);
      const exists = !!zone[q.name] || Object.keys(zone).some((k) => k.endsWith(`.${q.name}`));
      const answers = q.type === 'A' && zone[q.name] ? [{ name: q.name, type: 'A', ttl: 300, data: zone[q.name] }] : [];
      return new Response(encodeMessage({
        id: 0, flags: { qr: true, rd: true, ra: true }, rcode: exists ? 'NOERROR' : 'NXDOMAIN',
        questions: [{ name: q.name, type: q.type }], answers, authorities: [], edns: {}
      }));
    };
    const dns = new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 });
    // Labels learned from customer A, switched on, but the level is Off ("guess nothing").
    const options = S.sanitizeOptions({ sources: [], bruteforce: 'off', learned: true });
    const cfg = S.wordlistScanConfig(options, { custom: [], learned: ['erp-prod', 'vpn-ist'] });
    const scan = await runScan({
      domains: [B], extraNames: [`api.${B}`, `v1.api.${B}`], sources: [], ...cfg,
      permutationBudget: 200, recursive: true, mine: false, originHints: false, balance: false, dns, fetchImpl
    });
    assert.ok(queried.length > 0, 'the scan did query');
    assert.ok(scan.hosts.some((x) => x.name === `v2.api.${B}`), 'the permutation / recursive rounds ran');
    assert.deepEqual(queried.filter((n) => /erp-prod|vpn-ist/.test(n)), [], 'no learned label was sent under customer B');
    assert.equal(scan.options.wordlist.learnedTried || 0, 0);
  });

  test('bruteforceBases: the wordlist plan counts every base the scanner brute-forces', async () => {
    const { S } = await load();
    // A certificate with nested wildcards: the scanner runs the level list under each wildcard base too.
    const certNames = ['example.com', '*.example.com', '*.api.example.com', '*.shop.example.com', 'www.example.com'];
    assert.deepEqual(S.bruteforceBases(['example.com'], certNames), ['example.com', 'api.example.com', 'shop.example.com']);
    // Nothing typed: the registrable domains of the names (as the scanner derives its targets) + wildcard bases.
    assert.deepEqual(S.bruteforceBases([], ['www.example.org', '*.cdn.example.org']), ['example.org', 'cdn.example.org']);
    assert.deepEqual(S.bruteforceBases([], ['*.com.tr']), [], 'a public suffix is never a base');
    assert.deepEqual(S.bruteforceBases(['example.net'], null), ['example.net']);
    assert.deepEqual(S.bruteforceBases(['example.net', 'example.net'], ['*.example.net']), ['example.net'], 'deduplicated');
    const plan = S.wordlistPlan({ level: 'smart', domains: S.bruteforceBases(['example.com'], certNames) });
    assert.equal(plan.perDomain.length, 3);
    assert.equal(plan.total, 3 * plan.perDomain[0].total, 'three full lists, not one');
    inLang('en', () => assert.match(S.wordlistPlanText(plan), /DNS queries for 3 domains \(per domain: /));
  });

  test('live refresh hooks: SSL Targets defines refreshVocab (startRun calls it); Forget re-renders the Advanced summary', async () => {
    // The views cannot be mounted on the minimal fake DOM; these guard the wiring (the E2E runs check the behaviour).
    const scanSrc = await readFile(new URL('../../assets/js/views/scan.js', import.meta.url), 'utf8');
    assert.match(scanSrc, /active && active\.refreshVocab\) active\.refreshVocab\(\)/, 'startRun calls the hook after learning');
    const activeBlock = /\n {2}active = \{([\s\S]*?)\n {2}\};/.exec(scanSrc);
    assert.ok(activeBlock && /\n {4}refreshVocab\(\) \{\s*renderVocab\(\);/.test(activeBlock[1]), 'the mounted view defines it');
    const subSrc = await readFile(new URL('../../assets/js/views/subdomains.js', import.meta.url), 'utf8');
    const forget = /dataset: \{ action: 'sub-learned-clear' \},\s*onClick: \(\) => \{([\s\S]*?)\n {4}\}\n {2}\}\);/.exec(subSrc);
    assert.ok(forget, 'Forget handler found');
    for (const fn of ['renderLearned()', 'renderPlan()', 'renderAdvSummary()']) assert.ok(forget[1].includes(fn), `Forget calls ${fn}`);
    // The summary counts what a scan tries (capped like the plan line), not the whole store.
    const adv = /function renderAdvSummary\(\) \{([\s\S]*?)\n {2}\}/.exec(subSrc);
    assert.ok(adv && /learnedTryCount\(\)/.test(adv[1]) && !/learnedStore\(\)\.size\(\)/.test(adv[1]), 'summary uses the capped count');
  });

  test('reasonHost / reasonText read the structured fields only — `detail` is never parsed', async () => {
    const { S, C } = await load();
    assert.deepEqual(S.reasonHost({ kind: 'resolver-leak', host: 'a.x.com', resolver: 'google' }), { host: 'a.x.com', resolver: 'google', source: null, lastSeen: null });
    assert.deepEqual(S.reasonHost({ kind: 'history', host: 'b.x.com', source: 'otx', lastSeen: '2024-01-02' }), { host: 'b.x.com', resolver: null, source: 'otx', lastSeen: '2024-01-02' });
    // A detail-only reason has no host: the text is display-only, never read back.
    assert.deepEqual(S.reasonHost({ kind: 'resolver-leak', detail: 'c.x.com via cloudflare' }), { host: null, resolver: null, source: null, lastSeen: null });
    assert.equal(S.reasonHost({ kind: 'history', host: 42, source: {} }).host, null, 'non-string fields are ignored');
    inLang('en', () => {
      assert.equal(S.reasonText({ kind: 'resolver-leak', host: 'a.x.com', resolver: 'google', detail: 'ignored' }), 'a.x.com answered by Google Public DNS');
      assert.equal(S.reasonText({ kind: 'history', host: 'b.x.com', source: 'otx', lastSeen: '2024-01-02' }), 'b.x.com · seen by AlienVault OTX · last Jan 2, 2024');
      assert.equal(S.reasonText({ kind: 'history', host: 'b.x.com', source: 'thc' }), 'b.x.com · seen by ip.thc.org');
      assert.equal(S.reasonText({ kind: 'mx', detail: 'x.com: MX 10 mail.x.com' }), 'x.com: MX 10 mail.x.com', 'SPF / MX / sibling keep their detail');
      assert.equal(S.reasonText({ kind: 'resolver-leak', detail: 'c.x.com via cloudflare' }), 'c.x.com via cloudflare', 'no host → the detail as given');
      assert.equal(S.dayText('2024-01-02'), 'Jan 2, 2024');
      assert.equal(S.dayText('last week'), 'last week', 'anything but a day is shown as given');
    });
    inLang('tr', () => {
      assert.equal(S.reasonText({ kind: 'history', host: 'b.x.com', source: 'otx', lastSeen: '2024-01-02' }), 'b.x.com · AlienVault OTX gördü · son 2 Oca 2024');
    });
    // SSL Targets renders its hint table with the same helper (no raw scanner detail in the cell).
    assert.ok(!/scan-hint-detail' \}, x\.detail/.test(await readFile(new URL('../../assets/js/views/scan.js', import.meta.url), 'utf8')), 'scan.js shows reasonText(x)');
    assert.equal(typeof C.id, 'string');
  });

  test('techniqueCounts separates DNS discovery from passive sources (wildcard suspects left out)', async () => {
    const { S } = await load();
    const c = S.techniqueCounts([
      host('a.x.com', ['input']),
      host('mail.x.com', ['dns-mine:MX', 'crtsh']),
      host('ns1.x.com', ['dns-mine:NS', 'dns-mine:SOA']),
      host('api.x.com', ['wordlist']),
      host('app.x.com', ['bruteforce', 'thc']),
      host('api2.x.com', ['permutation']),
      host('v2.api.x.com', ['recursive']),
      host('old.x.com', ['otx', 'hackertarget']),
      host('fake.x.com', ['wordlist'], { wildcard: true })
    ]);
    assert.equal(c.total, 8);
    assert.equal(c.dns, 6);
    assert.equal(c.sources, 3);
    assert.equal(c.dnsOnly, 4, 'ns1, api, api2, v2.api');
    assert.deepEqual([c.mine, c.wordlist, c.permutation, c.recursive], [2, 2, 1, 1]);
    assert.deepEqual(c.byRecord, { MX: 1, NS: 1, SOA: 1 });
    assert.deepEqual(c.bySource, { crtsh: 1, thc: 1, otx: 1, hackertarget: 1 });
  });

  test('origin labels are readable and localized in both views', async () => {
    const { S, C } = await load();
    inLang('en', () => {
      assert.equal(S.originLabel('dns-mine:MX'), 'MX record');
      assert.equal(S.originLabel('wordlist'), 'Wordlist');
      assert.equal(S.originLabel('permutation'), 'Permutation');
      assert.equal(S.originLabel('recursive'), 'Deeper level');
      assert.equal(S.originLabel('thc'), 'ip.thc.org');
      assert.equal(C.originLabel('dns-mine:SPF'), 'SPF record');
      assert.equal(C.originLabel('permutation'), 'Permutation');
    });
    inLang('tr', () => {
      assert.equal(S.originLabel('dns-mine:MX'), 'MX kaydı');
      assert.equal(S.originLabel('permutation'), 'Varyasyon');
      assert.equal(C.originLabel('recursive'), 'Alt seviye');
    });
  });

  test('sourceHealthText: quota, outage with the CT fallback, page limit, plain results', async () => {
    const { S, src } = await load();
    const r = (source, ok, extra = {}) => ({
      source, ok, domain: 'x.com', names: [], ipHints: [], certs: [], partial: false, error: ok ? null : 'x', errorKind: null, attempts: 1, elapsedMs: 5, ...extra
    });
    const health = src.sourceHealthSummary([
      r('crtsh', false, { errorKind: 'unavailable', error: 'HTTP 502' }),
      r('certspotter', true, { names: ['a.x.com'] }),
      r('hackertarget', false, { errorKind: 'rate-limit', error: 'API count exceeded', quota: { limited: true, period: 'day', hintKey: 'source.quota.day' } }),
      r('thc', true, { names: ['a.x.com', 'b.x.com'], truncated: true, available: 4293 }),
      r('anubis', true)
    ]);
    const by = Object.fromEntries(health.map((x) => [x.source, x]));
    inLang('en', () => {
      const crt = S.sourceHealthText(by.crtsh);
      assert.equal(crt.tone, 'error');
      assert.equal(crt.short, 'Temporarily down');
      assert.equal(crt.detail, 'crt.sh is temporarily down. Cert Spotter was used instead.');
      const ht = S.sourceHealthText(by.hackertarget);
      assert.equal(ht.tone, 'limited');
      assert.equal(ht.short, 'Quota used up');
      assert.match(ht.detail, /^HackerTarget: The daily free quota .* resets within 24 hours\.$/);
      assert.equal(S.sourceHealthText(by.thc).detail, 'ip.thc.org: the first 2 of 4,293 names (page limit)');
      assert.equal(S.sourceHealthText(by.anubis).detail, 'Anubis DB: no names for this domain');
      assert.equal(S.sourceHealthText(by.certspotter).short, '1 name');
    });
    inLang('tr', () => {
      assert.equal(S.sourceHealthText(by.crtsh).detail, 'crt.sh geçici olarak çalışmıyor. Yerine Cert Spotter kullanıldı.');
      assert.match(S.sourceHealthText(by.hackertarget).detail, /^HackerTarget: IP adresinizin günlük ücretsiz kotası doldu; 24 saat içinde sıfırlanır\.$/);
    });
  });

  test('originOverview: resolver leaks and history per proxied host, networks, CLI command for the downloaded file', async () => {
    const { S } = await load();
    const result = {
      hosts: [
        host('shopapi.x.com', ['permutation'], { kind: 'cloudflare', ips: ['104.21.1.1'], networks: ['203.0.113.0/24'] }),
        host('www.x.com', ['wordlist'], { kind: 'cloudflare', ips: ['104.21.1.2'], networks: ['203.0.113.0/24'] }),
        host('api.x.com', ['wordlist'], { ips: ['203.0.113.14'] }),
        host('ghost.x.com', ['wordlist'], { kind: 'cloudflare', wildcard: true })
      ],
      // engine v2 reasons: structured fields (host / resolver / source / lastSeen), no parsing.
      originHints: [
        { ip: '203.0.113.77', reasons: [{ kind: 'resolver-leak', host: 'shopapi.x.com', resolver: 'google', detail: 'shopapi.x.com via google' }], hosts: ['shopapi.x.com'], servers: [], provider: null },
        { ip: '203.0.113.9', reasons: [{ kind: 'history', host: 'www.x.com', source: 'otx', lastSeen: '2024-01-02', detail: 'otx: www.x.com (last seen 2024-01-02)' }], hosts: ['www.x.com'], servers: [], provider: null },
        { ip: '203.0.113.14', reasons: [{ kind: 'direct-sibling', detail: 'api.x.com' }], hosts: ['api.x.com'], servers: [], provider: null },
        { ip: '10.0.0.7', reasons: [{ kind: 'direct-sibling', detail: 'intranet.x.com' }], hosts: ['intranet.x.com'], servers: [], provider: null },
        { ip: '203.0.113.9', reasons: [{ kind: 'mx', detail: 'x.com: MX 10 mail.x.com' }, { kind: 'direct-sibling', detail: 'mail.x.com' }], hosts: [], servers: [], provider: null }
      ],
      originNetworks: [{ cidr: '203.0.113.0/24', ips: ['203.0.113.14', '203.0.113.77'], hosts: ['api.x.com'], provider: null }],
      // Structured v2 output: targets + names go straight to lib/cmdline (no string parsing).
      cliTargets: ['203.0.113.0/24'],
      cliNames: ['shopapi.x.com', 'www.x.com'],
      cliSuggestion: 'python3 cli/ssl_origin_scan.py -t 203.0.113.0/24 -n shopapi.x.com www.x.com'
    };
    const o = S.originOverview(result);
    assert.deepEqual(o.proxied.map((p) => p.name), ['shopapi.x.com', 'www.x.com'], 'wildcard suspects left out');
    assert.deepEqual(o.proxied[0].leaks, [{ ip: '203.0.113.77', resolver: 'Google Public DNS' }]);
    assert.deepEqual(o.proxied[1].history, [{ ip: '203.0.113.9', source: 'otx', lastSeen: '2024-01-02' }], 'structured history fields');
    assert.deepEqual(o.proxied[0].networks, ['203.0.113.0/24']);
    assert.equal(o.leakCount, 1);
    assert.equal(o.historyCount, 1);
    // A sibling already listed by its origin network is not repeated; a private sibling and an MX host are.
    assert.deepEqual(o.general.map((x) => x.ip), ['10.0.0.7', '203.0.113.9']);
    assert.equal(o.networks.length, 1);
    assert.equal(o.command, 'python3 ssl_origin_scan.py -t 203.0.113.0/24 -n shopapi.x.com www.x.com');
    assert.equal(o.commands.posix, o.command, 'command is the POSIX one');
    assert.equal(o.commands.powershell, 'python ssl_origin_scan.py -t 203.0.113.0/24 -n shopapi.x.com www.x.com', 'PowerShell variant uses python');
    assert.equal(o.droppedCount, 0, 'every token is a valid IP/CIDR or hostname');
    assert.equal(S.originOverview(null).proxied.length, 0);
    assert.equal(S.originOverview({ hosts: [], cliSuggestion: null }).command, null);
    // The cliSuggestion string is display text: without cliTargets / cliNames there is no command.
    assert.equal(S.originOverview({ ...result, cliTargets: undefined, cliNames: undefined }).command, null, 'never parsed from cliSuggestion');
  });

  test('originOverview ignores detail-only reasons and drops a hostile CLI token', async () => {
    const { S } = await load();
    const result = {
      hosts: [host('www.x.com', ['wordlist'], { kind: 'cloudflare', ips: ['104.21.1.9'], networks: ['198.51.100.0/24'] })],
      originHints: [
        { ip: '198.51.100.9', reasons: [{ kind: 'resolver-leak', host: 'www.x.com', resolver: 'cloudflare', detail: 'www.x.com via cloudflare' }], hosts: ['www.x.com'], servers: [], provider: null },
        // No structured host: the detail text is never parsed, so it is no candidate for www.
        { ip: '198.51.100.8', reasons: [{ kind: 'resolver-leak', detail: 'www.x.com via google' }], hosts: [], servers: [], provider: null }
      ],
      originNetworks: [{ cidr: '198.51.100.0/24', ips: ['198.51.100.9'], hosts: [], provider: null }],
      // A hostile / malformed token must never reach the command: cmdline drops and reports it.
      cliTargets: ['198.51.100.0/24', '; rm -rf /'],
      cliNames: ['www.x.com', '$(whoami)']
    };
    const o = S.originOverview(result);
    assert.deepEqual(o.proxied[0].leaks, [{ ip: '198.51.100.9', resolver: 'Cloudflare' }], 'structured leak only');
    assert.equal(o.command, 'python3 ssl_origin_scan.py -t 198.51.100.0/24 -n www.x.com');
    assert.equal(o.droppedCount, 2, 'the injection tokens were dropped and counted');
    assert.doesNotMatch(o.commands.powershell, /rm -rf|whoami/, 'nothing hostile in either shell');
  });

  test('originOverview: a large proxied estate reads its names from proxied-names.txt, offered as a download', async () => {
    const { S } = await load();
    const names = Array.from({ length: 250 }, (_, i) => `shop${String(i).padStart(3, '0')}.x.com`);
    const result = {
      hosts: names.map((n, i) => host(n, ['wordlist'], { kind: 'cloudflare', ips: [`104.21.1.${(i % 200) + 1}`], networks: ['203.0.113.0/24'] })),
      originHints: [],
      originNetworks: [{ cidr: '203.0.113.0/24', ips: ['203.0.113.14'], hosts: [], provider: null }],
      cliTargets: ['203.0.113.0/24'],
      cliNames: names
    };
    const o = S.originOverview(result);
    assert.equal(o.command, 'python3 ssl_origin_scan.py -t 203.0.113.0/24 -n proxied-names.txt');
    assert.equal(o.commands.powershell, 'python ssl_origin_scan.py -t 203.0.113.0/24 -n proxied-names.txt');
    for (const sh of ['posix', 'powershell']) {
      const nf = o.namesFiles[sh];
      assert.equal(nf.file, 'proxied-names.txt');
      assert.equal(nf.count, 250);
      assert.equal(nf.text, `${names.join('\n')}\n`, 'the file holds exactly the proxied names, one per line');
    }
    // A small estate keeps the names inline and offers no file.
    const small = S.originOverview({ ...result, hosts: result.hosts.slice(0, 3), cliNames: names.slice(0, 3) });
    assert.match(small.command, /-n shop000\.x\.com shop001\.x\.com shop002\.x\.com$/);
    assert.deepEqual(small.namesFiles, { posix: null, powershell: null });
    const sweep = S.originSweep(result, { shell: 'powershell' });
    assert.equal(sweep.namesFile, 'proxied-names.txt');
    assert.equal(sweep.count, 250);
    assert.deepEqual(S.originSweep(null), { command: null, namesFile: null, namesText: '', count: 0 });
  });

  test('originSweep: a target list too long even with the names file goes to proxied-targets.txt too', async () => {
    const { S } = await load();
    // 1,400 exact IPv6 origins: far over 8,000 characters inline, whatever the names.
    const ips = Array.from({ length: 1400 }, (_, i) => `2001:db8:${(i + 1).toString(16)}::1`);
    const result = {
      hosts: [host('www.x.com', ['wordlist'], { kind: 'cloudflare', ips: ['104.21.1.1'], networks: [] })],
      originHints: [],
      originNetworks: [],
      cliTargets: ips,
      cliNames: ['www.x.com']
    };
    for (const [shell, python] of [['posix', 'python3'], ['powershell', 'python']]) {
      const sweep = S.originSweep(result, { names: ['www.x.com'], shell });
      assert.equal(sweep.command, `${python} ssl_origin_scan.py -t proxied-targets.txt -n proxied-names.txt`, shell);
      assert.deepEqual([sweep.targetsFile, sweep.targetCount, sweep.namesFile], ['proxied-targets.txt', 1400, 'proxied-names.txt'], shell);
      assert.equal(sweep.targetsText, `${ips.join('\n')}\n`, 'the file holds exactly the targets, one per line');
      assert.equal(sweep.overLength, undefined, shell);
    }
    // Thousands of exclusions keep even the file form too long: flagged for a warning.
    const exclude = ips.map((_, i) => `2001:db8:1::${(i + 1).toString(16)}`);
    const over = S.originSweep({ ...result, cliTargets: ['2001:db8:1::/112'] }, { names: ['www.x.com'], exclude });
    assert.equal(over.overLength, true);
    assert.ok(over.command.length > 8000);
    // A command that fits carries none of the new fields.
    const small = S.originSweep({ ...result, cliTargets: ips.slice(0, 3) }, { names: ['www.x.com'] });
    assert.deepEqual(Object.keys(small).sort(), ['command', 'count', 'namesFile', 'namesText']);
  });

  test('origin CLI command: an IPv6 /48 becomes its known addresses (the CLI refuses the /48 and scans nothing)', async () => {
    const { S } = await load();
    for (const ok of ['192.0.2.0/24', '198.51.100.0/16', '2001:db8:1::/112', '2001:db8:1::25', '203.0.113.9']) assert.ok(S.sweepableTarget(ok), ok);
    for (const bad of ['2001:db8:1::/48', '2001:db8::/64', '10.0.0.0/8', '198.51.100.0/15', 'example.com', '', '2001:db8::/129']) assert.ok(!S.sweepableTarget(bad), bad);
    const mail = host('mail.x.com', ['dns-mine:MX'], { ips: ['198.51.100.6'] });
    mail.resolution.ipv6 = ['2001:db8:1::25'];
    const result = {
      hosts: [
        host('www.x.com', ['wordlist'], { kind: 'cloudflare', ips: ['104.16.1.1'], networks: ['198.51.100.0/24', '2001:db8:1::/48'] }),
        host('x.com', ['input'], { ips: ['198.51.100.5'] }),
        mail
      ],
      originHints: [],
      originNetworks: [
        { cidr: '198.51.100.0/24', ips: ['198.51.100.5', '198.51.100.6'], hosts: ['mail.x.com', 'x.com'], provider: null },
        { cidr: '2001:db8:1::/48', ips: ['2001:db8:1::25'], hosts: ['mail.x.com'], provider: null }
      ],
      cliTargets: ['198.51.100.0/24', '2001:db8:1::/48'],
      cliNames: ['www.x.com']
    };
    const o = S.originOverview(result);
    assert.equal(o.command, 'python3 ssl_origin_scan.py -t 198.51.100.0/24 2001:db8:1::25 -n www.x.com');
    assert.ok(!/\/48/.test(o.command), 'no /48 reaches the command');
    assert.equal(o.networks.length, 2, 'the /48 is still shown as context');
    // A scanner that already lists the IPv6 addresses is left as it is.
    assert.equal(S.originCliCommand({ cliTargets: ['198.51.100.0/24', '2001:db8:1::25'], cliNames: ['www.x.com'] }),
      'python3 ssl_origin_scan.py -t 198.51.100.0/24 2001:db8:1::25 -n www.x.com');
    assert.equal(S.originCliCommand({ cliTargets: ['198.51.100.0/24'], cliNames: ['www.x.com'] }, { shell: 'powershell' }),
      'python ssl_origin_scan.py -t 198.51.100.0/24 -n www.x.com', 'PowerShell launches python');
    // Nothing sweepable left → no command (never a command the CLI rejects).
    assert.equal(S.originCliCommand({ cliTargets: ['2001:db8:9::/48'], cliNames: ['www.x.com'] }), null);
  });

  test('origin CLI command and networks leave wildcard suspects out', async () => {
    const { S } = await load();
    const ghosts = ['retired0.x.com', 'retired1.x.com', 'retired2.x.com'];
    const result = {
      hosts: [
        host('www.x.com', ['crtsh'], { kind: 'cloudflare', ips: ['104.16.1.1'], networks: ['198.51.100.0/24', '192.0.2.0/24'] }),
        ...ghosts.map((n) => host(n, ['crtsh'], { kind: 'cloudflare', ips: ['104.16.9.9'], wildcard: true, networks: ['198.51.100.0/24', '192.0.2.0/24'] })),
        host('api.x.com', ['wordlist'], { ips: ['198.51.100.6'] }),
        host('ghost-direct.x.com', ['otx'], { ips: ['198.51.100.99'], wildcard: true }),
        host('only-ghost.x.com', ['otx'], { ips: ['192.0.2.50'], wildcard: true })
      ],
      originHints: [],
      originNetworks: [
        { cidr: '198.51.100.0/24', ips: ['198.51.100.6', '198.51.100.99'], hosts: ['api.x.com', 'ghost-direct.x.com'], provider: null },
        { cidr: '192.0.2.0/24', ips: ['192.0.2.50'], hosts: ['only-ghost.x.com'], provider: null }
      ],
      cliTargets: ['198.51.100.0/24', '192.0.2.0/24'],
      cliNames: [...ghosts, 'www.x.com']
    };
    const o = S.originOverview(result);
    assert.deepEqual(o.proxied.map((p) => p.name), ['www.x.com']);
    assert.equal(o.command, 'python3 ssl_origin_scan.py -t 198.51.100.0/24 -n www.x.com', 'no suspect names, no suspect-only network');
    assert.deepEqual(o.networks.map((n) => n.cidr), ['198.51.100.0/24']);
    assert.deepEqual(o.networks[0].hosts, ['api.x.com'], 'the card counts real DNS-only hosts only');
    assert.deepEqual(o.networks[0].ips, ['198.51.100.6']);
    assert.deepEqual(o.proxied[0].networks, ['198.51.100.0/24']);
    assert.equal(result.originNetworks[0].hosts.length, 2, 'the ScanResult itself is not changed');
  });

  test('stage pills: mining next to the sources, cumulative permutation rounds, a cancelled run stops its stage', async () => {
    const { S } = await load();
    const scanner = await import('../../assets/js/lib/scanner.js');
    const mk = () => {
      const stages = {};
      for (const s of scanner.SCAN_STAGES) stages[s] = { state: 'pending', info: null };
      return { stages, progress: { stage: null, done: 0, total: 0 }, config: { bruteforce: 'off' }, sourcePlan: null, miningProgress: null, rounds: null };
    };
    const run = mk();
    S.applyStage(run, 'sources', { domains: ['x.com'], sources: ['crtsh'] });
    assert.deepEqual(run.sourcePlan, { domains: ['x.com'], sources: ['crtsh'] });
    // Mining finishes while crt.sh is still pending: the bar keeps showing the sources.
    assert.equal(S.applyProgress(run, { stage: 'sources', done: 1, total: 3 }), false);
    assert.equal(S.applyProgress(run, { stage: 'mining', done: 1, total: 1 }), true, 'the mining pill changed');
    assert.deepEqual(run.progress, { stage: 'sources', done: 1, total: 3 });
    assert.equal(run.stages.mining.state, 'done');
    assert.equal(run.stages.sources.state, 'active');
    S.applyStage(run, 'mining', { domains: 1 });
    assert.equal(run.stages.sources.state, 'done');
    assert.equal(run.stages.mining.state, 'done', 'mining that finished early is not restarted');
    S.applyStage(run, 'wildcard', {});
    S.applyStage(run, 'bruteforce', { skipped: true });
    assert.equal(run.stages.bruteforce.state, 'skipped');
    // Permutations, then the deeper round reporting from 0 again: the bar never runs backwards.
    S.applyStage(run, 'permutations', { budget: 1500, recursive: true });
    assert.equal(S.applyProgress(run, { stage: 'permutations', done: 0, total: 1500 }), true, 'candidate count learned');
    assert.equal(run.stages.permutations.candidates, 1500);
    S.applyProgress(run, { stage: 'permutations', done: 1500, total: 1500 });
    S.applyProgress(run, { stage: 'permutations', done: 10, total: 300 });
    assert.deepEqual(run.progress, { stage: 'permutations', done: 1510, total: 1800 });
    assert.equal(run.stages.permutations.candidates, 1800);
    // Cancel: the running stage is stopped, never left active (pulsing, aria-current).
    S.stopStages(run);
    assert.equal(run.stages.permutations.state, 'stopped');
    assert.ok(!Object.values(run.stages).some((s) => s.state === 'active'));
    assert.equal(run.stages.resolve.state, 'pending');
    // Mining still running when the sources finish stays active and keeps its progress.
    const r2 = mk();
    S.applyStage(r2, 'sources', {});
    S.applyProgress(r2, { stage: 'mining', done: 1, total: 2 });
    assert.equal(r2.stages.mining.state, 'active');
    S.applyStage(r2, 'mining', {});
    assert.equal(r2.stages.mining.state, 'active');
    assert.deepEqual(r2.progress, { stage: 'mining', done: 1, total: 2 });
    S.applyProgress(r2, { stage: 'mining', done: 2, total: 2 });
    assert.deepEqual(r2.progress, { stage: 'mining', done: 2, total: 2 });
  });

  test('table filter: wildcard suspects streaming in after a filter was chosen stay hidden', async () => {
    const { S } = await load();
    const prefs = { showWildcard: false };
    const real = host('api.x.com', ['wordlist'], { ips: ['203.0.113.1'] });
    const ghost = host('ghost.x.com', ['crtsh'], { ips: ['203.0.113.2'], wildcard: true });
    assert.equal(S.hostTableFilter('all', prefs, [real]), null, 'nothing to hide');
    const resolving = S.hostTableFilter('resolving', prefs, [real]);
    assert.equal(resolving(real), true);
    assert.equal(resolving(ghost), false, 'a suspect arriving later is hidden');
    prefs.showWildcard = true;
    assert.equal(resolving(ghost), true, 'the toggle is read live');
    prefs.showWildcard = false;
    const all = S.hostTableFilter('all', prefs, [real, ghost]);
    assert.equal(all(ghost), false);
    assert.equal(S.hostTableFilter('bogus', { showWildcard: true }, [ghost]), null, 'unknown filter → all');
  });

  test('"only through DNS" is claimed only when every selected source answered completely', async () => {
    const { S, src } = await load();
    const r = (source, ok, extra = {}) => ({ source, ok, domain: 'x.com', names: [], ipHints: [], certs: [], partial: false, error: ok ? null : 'x', errorKind: null, ...extra });
    const allOk = src.sourceHealthSummary([r('crtsh', true, { names: ['a.x.com'] }), r('anubis', true)]);
    assert.equal(S.dnsOnlyNoteKey(4, ['crtsh', 'anubis'], allOk), 'sub.tech.dnsOnly');
    assert.equal(S.dnsOnlyNoteKey(0, ['crtsh', 'anubis'], allOk), null, 'nothing found only by DNS');
    assert.equal(S.dnsOnlyNoteKey(4, [], []), null, 'no passive source was queried: no claim at all');
    const limited = src.sourceHealthSummary([r('crtsh', true), r('hackertarget', false, { errorKind: 'rate-limit', quota: { limited: true, period: 'day', hintKey: 'source.quota.day' } })]);
    assert.equal(S.dnsOnlyNoteKey(4, ['crtsh', 'hackertarget'], limited), 'sub.tech.dnsOnlyIncomplete');
    const truncated = src.sourceHealthSummary([r('thc', true, { names: ['a.x.com'], truncated: true, available: 5000 })]);
    assert.equal(S.dnsOnlyNoteKey(4, ['thc'], truncated), 'sub.tech.dnsOnlyIncomplete', 'page limit');
    assert.equal(S.dnsOnlyNoteKey(4, ['crtsh', 'otx'], allOk), 'sub.tech.dnsOnlyIncomplete', 'a source that never answered');
    inLang('en', () => {
      assert.doesNotMatch(i18n.t('sub.tech.dnsOnly', { count: 2 }), /no online database/);
      assert.match(i18n.t('sub.tech.dnsOnly', { count: 2 }), /passive sources queried in this scan/);
      assert.doesNotMatch(i18n.t('sub.origin.dnsTitle'), /database/);
    });
  });

  test('scan parallelism follows Settings (up to twice the value, at most 24)', async () => {
    const { S } = await load();
    assert.equal(S.scanConcurrency(12), 24, 'the default keeps the tested sweep speed');
    assert.equal(S.scanConcurrency(4), 8);
    assert.equal(S.scanConcurrency(1), 2);
    assert.equal(S.scanConcurrency(32), 24);
    assert.equal(S.scanConcurrency(NaN), 24);
  });

  test('a shared run=1 link asks for one click; it never scans on its own', async () => {
    const { S } = await load();
    const run = (domains, status = 'done') => ({ status, config: { domains } });
    assert.equal(S.linkAction({ domain: 'example.com', run: '1' }, ['example.com'], null), 'prompt');
    assert.equal(S.linkAction({ domain: 'example.com' }, ['example.com'], null), null, 'without run=1 the box is only pre-filled');
    assert.equal(S.linkAction({ run: '1' }, [], null), null, 'nothing to scan');
    assert.equal(S.linkAction({ run: '1' }, ['example.com'], run(['example.com'])), null, 'this page already has that scan');
    assert.equal(S.linkAction({ run: '1' }, ['example.org'], run(['example.com'], 'running')), null, 'a scan is running');
    assert.equal(S.linkAction({ run: '1' }, ['example.org'], run(['example.com'])), 'prompt');
    // start() writes only `domain` (a reload pre-fills instead of re-scanning) — checked in the source.
    const srcText = await readFile(path.join(ROOT, 'assets/js/views/subdomains.js'), 'utf8');
    assert.match(srcText, /ctx\.setParams\(\{ domain: v\.domains\.join\(','\) \}\);/);
    assert.doesNotMatch(srcText, /ctx\.setParams\([^)]*run: '1'/);
    assert.doesNotMatch(srcText, /queueMicrotask\(\(\) => \{\s*if \(!ctx\.signal\.aborted\) start\(\);/, 'no automatic start');
    // The one exception: the Zone File view's in-app "Scan now" click (a one-shot, in-memory intent,
    // validated for this view and still fresh). Every queued start must go through that path.
    const queued = [...srcText.matchAll(/queueMicrotask\(([^;]*)\);/g)].map((m) => m[1]).filter((body) => /start/i.test(body));
    assert.deepEqual(queued, ['startFromZoneClick'], 'only the zone-intent start is queued');
    assert.match(srcText, /if \(intentOk && zoneIntent\.autostart === true\) queueMicrotask\(startFromZoneClick\);/, 'gated by a valid autostart intent');
    assert.match(srcText, /const intentOk = validZoneIntent\(zoneIntent, 'subdomains', state\.getSession\('zone'\)\);/, 'the intent is validated for Subdomains');
    assert.match(srcText, /const zoneIntent = state\.takeSession\('zoneScanIntent'\);/, 'the intent is one-shot (taken)');
    // A scan still running when the intent arrives: the zone scan waits for it (a prompt, never a
    // silent drop) and starts from the run's onFinish; hiding the prompt drops the request.
    const zoneStart = /const startFromZoneClick = \(\) => \{([\s\S]*?)\n {2}\};/.exec(srcText);
    assert.ok(zoneStart, 'startFromZoneClick found');
    assert.match(zoneStart[1], /zoneStartAction\(session\.run, [^\n]*\);\s*if \(action === 'wait'\) showZoneBusyPrompt\(zone\);\s*else if \(action === 'start'\) start\(\);/, 'asks zoneStartAction before start()');
    assert.match(srcText, /onFinish: \(\) => \{\s*setRunning\(false\);\s*startWaitingZoneScan\(\);/, 'the waiting zone scan starts when the run ends');
    assert.match(srcText, /function hideLinkPrompt\(\) \{\s*zoneStartAfter = null;/, 'hiding the prompt drops the waiting zone scan');
    const scanText = await readFile(path.join(ROOT, 'assets/js/views/scan.js'), 'utf8');
    assert.doesNotMatch(scanText, /p\.run === '1'\) start\(\)|if \(!ctx\.signal\.aborted\) start\(\)/, 'SSL Targets neither');
    assert.doesNotMatch(scanText, /queueMicrotask\([^;]*start/i, 'SSL Targets never queues a start (the zone intent only pre-fills)');
  });

  test('Zone File "Scan now" while a scan runs: it waits (with a prompt) instead of being dropped', async () => {
    const { S } = await load();
    const run = (domains, status, zoneMode = null) => ({ status, config: { domains, zoneMode } });
    assert.equal(S.zoneStartAction(null, ['example.com'], 'exact'), 'start');
    assert.equal(S.zoneStartAction(run(['example.org'], 'done'), ['example.com'], 'exact'), 'start', 'a finished run is replaced');
    assert.equal(S.zoneStartAction(run(['example.org'], 'cancelled'), ['example.com'], 'exact'), 'start');
    assert.equal(S.zoneStartAction(run(['example.org'], 'running'), ['example.com'], 'exact'), 'wait', 'another domain is being scanned');
    assert.equal(S.zoneStartAction(run(['example.com'], 'running'), ['example.com'], 'exact'), 'wait', 'the same domain without the zone');
    assert.equal(S.zoneStartAction(run(['example.com'], 'running', 'discover'), ['example.com'], 'exact'), 'wait', 'the same domain in another zone mode');
    assert.equal(S.zoneStartAction(run(['example.com'], 'running', 'exact'), ['example.com'], 'exact'), null, 'that very zone scan is running');
    assert.equal(S.zoneStartAction(run(['example.com'], 'running'), ['example.com'], 'off'), null);
    // a zone file imported again is another zone object: the scan of the old one is not that scan
    const v1 = { v: 1, origin: 'example.com' };
    const v2 = { v: 1, origin: 'example.com' };
    const zoneRun = { ...run(['example.com'], 'running', 'exact'), zone: v1 };
    assert.equal(S.zoneStartAction(zoneRun, ['example.com'], 'exact', v1), null);
    assert.equal(S.zoneStartAction(zoneRun, ['example.com'], 'exact', v2), 'wait', 'the updated export waits for the old scan');
    const src = await readFile(path.join(ROOT, 'assets/js/views/subdomains.js'), 'utf8');
    assert.match(src, /run\.zone = zoneCfg\.zone \|\| null;/, 'start() keeps the zone on the run');
    inLang('en', () => assert.equal(i18n.t('sub.zone.busy', { running: 'example.org', domain: 'example.com' }),
      'A scan of example.org is still running. The scan of your zone file (example.com) starts when it ends.'));
    inLang('tr', () => assert.equal(i18n.t('sub.zone.busy', { running: 'example.org', domain: 'example.com' }),
      'example.org taraması hâlâ sürüyor. Zone dosyanızın taraması (example.com) o bitince başlar.'));
  });

  test('live runs: skipped stages are not announced; a partial row says "resolving…" only while the run lives', async () => {
    // Wiring guards (the views cannot be mounted on the fake DOM; the E2E cancel steps check the behaviour).
    const subSrc = await readFile(path.join(ROOT, 'assets/js/views/subdomains.js'), 'utf8');
    const scanSrc = await readFile(path.join(ROOT, 'assets/js/views/scan.js'), 'utf8');
    for (const [name, src, prefix] of [['subdomains', subSrc, 'sub'], ['scan', scanSrc, 'scan']]) {
      const announces = [...src.matchAll(/announce\(t\(`(?:sub|scan)\.progress\.\$\{payload\.stage\}`\)\)/g)];
      assert.equal(announces.length, 1, `${name}: one stage announcement`);
      const before = src.slice(Math.max(0, announces[0].index - 260), announces[0].index);
      assert.match(before, /run\.stages\[payload\.stage\]\.state === 'active'/, `${name}: only an active (not skipped) stage is announced`);
      assert.match(src, new RegExp(`x\\._partial && run\\.status === 'running' \\? Badge\\(t\\('sub\\.host\\.resolving'\\)[^\\n]*${prefix}-mini-badge`), `${name}: the badge needs a running run`);
      assert.match(src, /\} else if \(run\.found && run\.found\.size\) \{\s*\/\/ Cancelled \/ failed: redraw the streamed partials[^\n]*\n[^\n]*\n\s*for \(const partial of run\.found\.values\(\)\) (?:table|hostsTable)\.updateRow\(partial\);/, `${name}: cancel / failure re-renders each partial row (updateRow, not the cached setRows)`);
      // Thousands of streamed hits: a full record replaces its partial in place, any other one is
      // batch-appended (no per-row table scan), and the stage pills re-render once per frame.
      assert.match(src, /if \(partialShown\.delete\(payload\.name\)\) (?:table|hostsTable)\.upsertRow\(payload\);\s*else (?:table|hostsTable)\.addRows\(\[payload\]\);/, `${name}: host rows batched unless replacing a partial`);
      assert.match(src, /const renderStagesSoon = frameThrottle\(renderStages\);/, `${name}: stage pills throttled per frame`);
      assert.doesNotMatch(src.slice(src.indexOf("case 'found':"), src.indexOf("case 'done':")), /\brenderStages\(\);/, `${name}: no unthrottled pill render per hit`);
    }
  });

  test('hostNameNodes: a host name wraps only after a dot, and reads (and copies) unchanged', async () => {
    const { S } = await load();
    withFakeDocument(() => {
      const box = dom.h('a', null, S.hostNameNodes('old-shop.eu-west-1.example.net'));
      assert.equal(box.textContent, 'old-shop.eu-west-1.example.net');
      assert.deepEqual(box.childNodes.map((c) => [c.tagName ?? null, c.textContent]), [
        ['SPAN', 'old-shop.'], ['WBR', ''], ['SPAN', 'eu-west-1.'], ['WBR', ''], ['SPAN', 'example.'], ['WBR', ''], ['SPAN', 'net']
      ]);
      assert.ok(box.childNodes.filter((c) => c.tagName === 'SPAN').every((c) => c.getAttribute('class') === 'sub-seg'), 'each label is one unbreakable run');
      // A freak label longer than a phone's line stays breakable (plain text, no nowrap run).
      const long = `${'x'.repeat(40)}.example.com`;
      const freak = dom.h('a', null, S.hostNameNodes(long));
      assert.equal(freak.textContent, long);
      assert.deepEqual([freak.childNodes[0].nodeType, freak.childNodes[2].tagName], [3, 'SPAN']);
      assert.equal(dom.h('a', null, S.hostNameNodes('<b>x</b>.example.com')).textContent, '<b>x</b>.example.com', 'text, never HTML');
      assert.deepEqual(S.hostNameNodes(''), []);
    });
  });

  test('Subdomains results are tabs: the route and the page session keep a chosen tab, a new run starts on the automatic one', async () => {
    // Wiring guards (the view cannot be mounted on the fake DOM; the Subdomains E2E drives the tabs).
    await load();
    const src = await readFile(path.join(ROOT, 'assets/js/views/subdomains.js'), 'utf8');
    for (const [lang, labels] of [['en', ['Overview', 'Hosts', 'Origins', 'Sources']], ['tr', ['Genel bakış', 'Host’lar', 'Origin’ler', 'Kaynaklar']]]) {
      inLang(lang, () => assert.deepEqual(['overview', 'hosts', 'origins', 'sources'].map((id) => i18n.t(`sub.tab.${id}`)), labels, lang));
    }
    assert.match(src, /const tabs = Tabs\(SUB_TABS\.map\(\(tabId\) => \(\{ id: tabId, label: t\(`sub\.tab\.\$\{tabId\}`\) \}\)\), \{/, 'one tab per SUB_TABS id');
    // Every panel is built up front, so a live run updates the hidden ones too.
    assert.match(src, /for \(const tabId of SUB_TABS\) tabs\.panel\(tabId\)\.append\(panels\[tabId\]\);/);
    assert.match(src, /const opening = initialSubTab\(\{\s*route: ctx\.params\.tab,\s*chosen: session\.tab,/, 'route first, then the page session');
    // A choice goes into the URL (merged, so `domain` stays; the run's domains when the route has
    // none, lib/subtabs.subTabParams); an automatic move never does.
    assert.match(src, /function remember\(tabId\) \{\s*session\.tab = tabId;\s*const named = routeTargets\(ctx\.searchParams, ctx\.params\)\.length > 0;\s*ctx\.setParams\(subTabParams\(tabId, \{ named, domains: run\.config\.domains \}\), \{ merge: true \}\);/);
    assert.match(src, /if \(next\) tabs\.select\(next, \{ silent: true \}\);/);
    // start(): a new run is automatic again, and its setParams drops `tab=`.
    const start = src.slice(src.indexOf('async function start()'), src.indexOf('function cancel()'));
    assert.ok(start.indexOf('session.tab = null;') !== -1 && start.indexOf('session.tab = null;') < start.indexOf("ctx.setParams({ domain: v.domains.join(',') });"));
    // update(): an edited `tab=` opens that tab without a re-mount.
    assert.match(src, /const tab = parseSubTab\(params\.tab\);\s*if \(tab && ui\) ui\.showTab\(tab\);/);
    // A stat card filters the hosts and hands the focus to the Hosts tab (the card hides with its panel).
    assert.match(src, /function pickFilter\(f\) \{\s*setFilter\(f\);\s*showTab\('hosts', \{ focus: true \}\);/);
    // A click on the tab already shown is a choice (the component fires onChange only for a change) …
    assert.match(src, /tabs\.el\.querySelector\('\[role="tablist"\]'\)\.addEventListener\('click', \(event\) => \{[^}]*if \(tab && session\.tab === null\) remember\(tab\.dataset\.tab\);/);
    // … and an automatic move held back under the focus happens once the focus has left the tabs.
    assert.match(src, /tabs\.el\.addEventListener\('focusout', \(\) => \{\s*setTimeout\(\(\) => \{\s*if \(root\.isConnected\) followRun\(lastCounts \? lastCounts\.found : 0\);/);
  });

  test('Subdomains source news is spoken from the run header, since the Sources panel is hidden under another tab', async () => {
    // Wiring guard: a live region inside a hidden tab panel says nothing, so the one that speaks
    // the wait note and the per-source lines sits in the always-visible run header.
    const src = await readFile(path.join(ROOT, 'assets/js/views/subdomains.js'), 'utf8');
    assert.match(src, /const sourceLive = h\('div', \{ class: 'sr-only sub-src-live', attrs: \{ 'aria-live': 'polite' \} \}\);/);
    assert.match(src, /h\('div', \{ class: 'sub-run-titles' \}, title, meta\),\s*summary\.el,\s*NotifyButton\(\(\) => run\.job \|\| null\)\),\s*progress, zoneBanner, handoffBanner, notice, sourceLive\);/, 'in the run header');
    assert.match(src, /const sourceWaitNote = h\('div', \{ class: 'sub-src-wait', hidden: true \}\);/, 'the note in the panel is no live region of its own');
    assert.match(src, /const sourceNotes = h\('div', \{ class: 'sub-src-notes' \}\);/);
    // Each line once: every source event redraws the panel's lines.
    assert.match(src, /function speakSource\(text\) \{\s*if \(!text \|\| spoken\.has\(text\)\) return;\s*spoken\.add\(text\);\s*sourceLive\.append\(h\('p', null, text\)\);/);
    for (const call of ['speakSource(text);', 'speakSource(text.detail);', 'speakSource(tail.textContent);']) assert.ok(src.includes(call), call);
  });

  test('on a phone a host name still breaks inside a label too long for its card (subdomains.css)', async () => {
    const css = (await readFile(path.join(ROOT, 'assets/css/views/subdomains.css'), 'utf8')).replace(/\/\*[\s\S]*?\*\//g, '');
    const start = css.indexOf('@media (max-width: 640px) {');
    const phone = css.slice(css.indexOf('{', start) + 1, css.indexOf('@media (max-width: 480px)', start));
    const rules = [...phone.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map(([, sel, body]) => ({ sel: sel.split(',').map((x) => x.trim()), body }));
    const wrap = (selector) => rules.filter((r) => r.sel.includes(selector) && /overflow-wrap:/.test(r.body)).map((r) => /overflow-wrap:\s*([\w-]+)/.exec(r.body)[1]);
    // Each label is one nowrap run (hostNameNodes), so only a label too long for the line (plain
    // text) breaks inside; `normal` there would push the card and the page sideways.
    assert.match(css, /\.sub-seg \{\s*white-space: nowrap;\s*\}/);
    assert.deepEqual(wrap('.sub-table .sub-host-name'), ['anywhere'], 'host table cards');
    assert.deepEqual(wrap('.sub-org-table td:first-child'), ['anywhere'], 'proxied-hosts table');
    assert.deepEqual(wrap('.sub-org-name'), [], 'the ORIGIN lists keep their base rule');
    assert.match(css, /\.sub-org-name \{\s*font-weight: 600;\s*overflow-wrap: anywhere;\s*\}/);
  });

  test('a finished Subdomains run redraws its streamed rows, so the "origin?" badge follows the ORIGIN panel', async () => {
    // Wiring guard (the view cannot be mounted on the fake DOM; the Zone File hand-off E2E counts the badges).
    const src = await readFile(path.join(ROOT, 'assets/js/views/subdomains.js'), 'utf8');
    const done = /\n {4}if \(run\.status === 'done'\) \{([\s\S]*?)\n {4}\}/.exec(src);
    assert.ok(done, "finish()'s done branch");
    const at = (s) => done[1].indexOf(s);
    assert.ok(at('renderOrigin();') !== -1 && at('renderOrigin();') < at('table.setRows(run.result.hosts);'), 'the panel fills originCandidates first');
    // setRows keeps the rows drawn while resolving (cached per object, before any badge existed).
    assert.ok(at('table.setRows(run.result.hosts);') < at('table.refresh();'), 'then every cached row is drawn again');
  });

  test('Subdomains plan line: exact zone mode describes the zone run, not the stored wordlist', async () => {
    await load();
    inLang('en', () => assert.equal(i18n.t('sub.plan.zoneExact', { count: 6 }), 'Exact mode: only the 6 names from your zone file are resolved; the wordlist, variations and passive sources are not used for this scan.'));
    inLang('tr', () => assert.equal(i18n.t('sub.plan.zoneExact', { count: 6 }), 'Kesin mod: yalnızca zone dosyanızdaki 6 ad çözümlenir; bu taramada kelime listesi, varyasyonlar ve pasif kaynaklar kullanılmaz.'));
    const src = await readFile(path.join(ROOT, 'assets/js/views/subdomains.js'), 'utf8');
    const plan = /function renderPlan\(\) \{([\s\S]*?)\n {2}\}/.exec(src);
    assert.ok(plan, 'renderPlan found');
    assert.match(plan[1], /zone && zoneModes\.get\(zone\) === 'exact'/, 'the exact branch reads the chosen zone mode');
    assert.ok(plan[1].indexOf("sub.plan.zoneExact") < plan[1].indexOf("options.bruteforce === 'off'"), 'checked before the wordlist options');
    assert.match(src, /onMode: \(m\) => \{\s*zoneModes\.set\(zone, m\);\s*renderPlan\(\);/, 'a mode change refreshes the plan');
  });

  test('owner lookup buttons: each names its network for screen readers; the answer lands in a live region', async () => {
    await load();
    inLang('en', () => assert.equal(i18n.t('sub.org.owner.lookupFor', { cidr: '203.0.113.0/24' }), 'Look up the owner of 203.0.113.0/24 (asks RIPEstat)'));
    inLang('tr', () => assert.equal(i18n.t('sub.org.owner.lookupFor', { cidr: '203.0.113.0/24' }), '203.0.113.0/24 ağının sahibini bul (RIPEstat’a sorar)'));
    for (const file of ['subdomains.js', 'scan.js']) {
      const src = await readFile(path.join(ROOT, 'assets/js/views', file), 'utf8');
      assert.match(src, /ariaLabel: t\('sub\.org\.owner\.lookupFor', \{ cidr: net\.cidr \}\)/, `${file}: distinct accessible name`);
      assert.match(src, /class: '(?:sub-org-owner|scan-net-owner)', attrs: \{ 'aria-live': 'polite' \}/, `${file}: polite live region`);
    }
  });

  test('SSL Targets discovery summary names the zone file when the run used one', async () => {
    await load();
    inLang('en', () => {
      assert.equal(i18n.t('scan.sum.discoveryZone', { dns: '0', sources: '0', zone: '6' }), 'Found through DNS: 0 · from passive sources: 0 · from your zone file: 6');
    });
    inLang('tr', () => {
      assert.equal(i18n.t('scan.sum.discoveryZone', { dns: '0', sources: '0', zone: '6' }), 'DNS ile bulunan: 0 · pasif kaynaklardan: 0 · zone dosyanızdan: 6');
    });
    const scanSrc = await readFile(path.join(ROOT, 'assets/js/views/scan.js'), 'utf8');
    assert.match(scanSrc, /t\(tech\.zone \? 'scan\.sum\.discoveryZone' : 'scan\.sum\.discovery', found\)/);
  });

  test('scanner warnings never show a raw key in either view', async () => {
    const { S, C } = await load();
    const codes = [...(await readFile(path.join(ROOT, 'assets/js/lib/scanner.js'), 'utf8')).matchAll(/code: '([A-Z_]+)'/g)].map((m) => m[1]);
    assert.ok(codes.includes('WILDCARD_PARENTS_TRUNCATED'));
    for (const code of new Set(codes)) {
      assert.ok(S.WARNING_CODES.includes(code), `WARNING_CODES lists ${code}`);
      for (const lang of ['en', 'tr']) {
        inLang(lang, () => {
          for (const prefix of ['sub', 'scan']) {
            const text = i18n.t(`${prefix}.warn.${code}`, { detail: '80' });
            assert.notEqual(text, `${prefix}.warn.${code}`, `${lang} ${prefix}.warn.${code}`);
            assert.ok(!text.includes('{detail}'));
          }
        });
      }
    }
    assert.ok(C);
  });

  test('sanitizeOptions (SSL Targets): a v1.0 save gets the Smart default once; a later deliberate Off stays', async () => {
    const { C, src } = await load();
    const ids = src.SOURCES.map((s) => s.id);
    assert.equal(C.sanitizeOptions({ sources: ['crtsh'], bruteforce: 'off' }).bruteforce, 'smart', 'v1.0 stored its default off');
    assert.equal(C.sanitizeOptions({ sources: ['crtsh'], knownSources: ids, bruteforce: 'off' }).bruteforce, 'off');
    assert.equal(C.sanitizeOptions({ sources: ['crtsh'], bruteforce: 'large' }).bruteforce, 'large');
    const migrated = C.sanitizeOptions({ sources: ['crtsh'], bruteforce: 'off' });
    assert.equal(C.sanitizeOptions({ ...migrated, bruteforce: 'off' }).bruteforce, 'off', 'once saved again, off is a choice');
  });

  test('resolver chain from Settings bounds the bulk balance pool (a removed resolver gets no scan queries)', async () => {
    const app = await import('../../assets/js/app.js');
    assert.deepEqual(app.balancePoolFor(DEFAULT_CHAIN), ['cloudflare', 'google', 'dnssb'], 'defaults unchanged');
    assert.deepEqual(app.balancePoolFor(['cloudflare', 'cznic']), ['cloudflare']);
    assert.deepEqual(app.balancePoolFor(['cznic']), ['cznic']);
    assert.deepEqual(app.balancePoolFor(['quad9', 'cznic']), ['cznic'], 'browser-unreadable resolvers are not the rotating pool');
    assert.deepEqual(app.balancePoolFor(['quad9']), ['quad9'], 'last resort: the chain itself');
    // End to end with the real client: balance mode only contacts resolvers of the chain.
    const { DohClient } = await import('../../assets/js/lib/doh.js');
    const { decodeMessage, encodeMessage, base64UrlDecode } = await import('../../assets/js/lib/dnswire.js');
    const hosts = new Set();
    const fetchImpl = async (url) => {
      const u = new URL(url);
      hosts.add(u.host);
      const q = decodeMessage(base64UrlDecode(u.searchParams.get('dns'))).questions[0];
      const bytes = encodeMessage({ id: 0, flags: { qr: true, rd: true, ra: true }, rcode: 'NXDOMAIN', questions: [q], answers: [], authorities: [], edns: {} });
      return new Response(bytes, { status: 200, headers: { 'content-type': 'application/dns-message' } });
    };
    const chain = ['cloudflare', 'cznic'];
    const dns = new DohClient({ chain, balancePool: app.balancePoolFor(chain), fetchImpl, cache: false, retries: 0 });
    for (let i = 0; i < 6; i += 1) await dns.query(`n${i}.example.com`, 'A', { balance: true });
    assert.deepEqual([...hosts], ['cloudflare-dns.com']);
  });

  test('About names the resolvers of the default chain (no stale Quad9)', async () => {
    const about = await import('../../assets/js/views/about.js');
    const names = about.defaultChainNames();
    assert.doesNotMatch(names, /Quad9/);
    assert.match(names, /Cloudflare/);
    inLang('en', () => {
      const text = i18n.t('about.step2Body', { resolvers: names, count: 12 });
      assert.ok(text.includes(names));
      assert.doesNotMatch(text, /Quad9/);
    });
  });

  test('user-facing text is global and honest (no local ISP, no completeness promise)', async () => {
    await load();
    await import('../../assets/js/views/about.js');
    for (const lang of ['en', 'tr']) {
      inLang(lang, () => {
        assert.doesNotMatch(i18n.t('settings.note.unreachable'), /Turkish|Türk/);
        for (const k of ['app.tagline', 'nav.subdomains.desc', 'nav.scan.desc', 'about.start', 'about.heroBody', 'scan.step.domainsDesc']) {
          assert.doesNotMatch(i18n.t(k), /\bevery (subdomain|name)\b|tüm (subdomain|alt alan|adlar)/i, `${lang} ${k}`);
        }
        assert.doesNotMatch(i18n.t('sub.opt.bfHint'), /never to the customer|müşterinin sunucularına asla/);
        for (const k of ['sub.org.networksHint', 'sub.org.lead', 'sub.intro.cf', 'scan.cdn.netDesc']) {
          assert.doesNotMatch(i18n.t(k, { count: 2 }), /usually|very likely|strong candidates|büyük olasılıkla|genellikle|güçlü adaylar/, `${lang} ${k}`);
        }
        assert.doesNotMatch(i18n.t('scan.sum.networks', { count: 2, list: '192.0.2.0/24' }), /very likely|büyük olasılıkla/);
      });
    }
    inLang('en', () => {
      assert.match(i18n.t('sub.progress.sources'), /a few minutes/);
      assert.match(i18n.t('source.quota.day'), /within 24 hours/);
      assert.match(i18n.t('sub.org.cliHint'), /authorised/);
    });
    const html = await readFile(path.join(ROOT, 'index.html'), 'utf8');
    assert.doesNotMatch(html, /every subdomain/i);
  });

  test('SSL Targets: streamed hits carry certificate coverage, and a cancelled run exports them', async () => {
    const { S, C } = await load();
    const { namesForCli, scanHostRows } = await import('../../assets/js/lib/export.js');
    const cert = { hostnames: ['*.example.net', 'example.net'] };
    const www = C.partialScanRecord({ name: 'www.example.net', origin: 'wordlist', ipv4: ['203.0.113.5'] }, cert);
    assert.equal(www._partial, true);
    assert.deepEqual(www.cert, { covered: true, by: '*.example.net' }, 'the coverage lib/scanner gives the full record');
    const mail = C.partialScanRecord({ name: 'mail.example.org', origin: 'wordlist', ipv4: ['203.0.113.6'] }, cert);
    assert.deepEqual(mail.cert, { covered: false, by: null });
    assert.equal(C.partialScanRecord({ name: 'www.example.net' }, null).cert, null, 'no certificate, no coverage');
    // Cancelled before the resolve stage: no full record yet, only the streamed hits.
    const run = { result: null, hosts: [], found: new Map([[www.name, www], [mail.name, mail]]) };
    assert.equal(namesForCli({ hosts: S.liveHosts(run) }, { onlyCovered: true }), 'www.example.net\n', 'names.txt: the covered hit');
    assert.equal(namesForCli({ hosts: S.liveHosts(run) }), 'www.example.net\nmail.example.org\n');
    assert.equal(scanHostRows({ hosts: S.liveHosts(run) }).length, 2, 'hosts CSV rows');
    // The export bar reads the same list as the Hosts table (the views cannot be mounted here).
    const src = await readFile(path.join(ROOT, 'assets/js/views/scan.js'), 'utf8');
    assert.match(src, /const exportScan = \(\) => \(\{ hosts: liveHosts\(run\) \}\);/);
    assert.match(src, /const namesText = \(\) => namesForCli\(run\.result \|\| \{ hosts: liveHosts\(run\) \}, \{ onlyCovered \}\);/);
    const sync = /function syncExports\(\) \{([\s\S]*?)\n {2}\}/.exec(src);
    assert.ok(sync && /const anyHosts = liveHosts\(run\)\.length > 0;/.test(sync[1]), 'syncExports counts the streamed hits');
    assert.match(src, /const record = partialScanRecord\(partial, coverCert\);/, 'startRun streams covered partials');
    // Several certificates: a streamed hit is covered by the union of their names, one certificate by its own.
    assert.match(src, /const coverCert = Array\.isArray\(scanConfig\.certs\) && scanConfig\.certs\.length\s*\? \{ hostnames: \[\.\.\.new Set\(scanConfig\.certs\.flatMap\(\(c\) => c\.hostnames \|\| \[\]\)\)\] \} : scanConfig\.cert;/);
  });

  test('SSL Targets Servers tab: one entry per name, the strongest match (DNS, then zone file, then hint)', async () => {
    const { C } = await load();
    const pick = (hosts) => C.strongestPerName(hosts).map((x) => `${x.name}:${x.via}`);
    // lib/scanner orders a server's hosts dns < zone < hint.
    assert.deepEqual(pick([
      { name: 'www.example.com', ip: '192.0.2.10', via: 'dns' },
      { name: 'api.example.com', ip: '192.0.2.10', via: 'dns' },
      { name: 'shop.example.com', ip: '192.0.2.12', via: 'zone' },
      { name: 'www.example.com', ip: '192.0.2.12', via: 'hint' },
      { name: 'shop.example.com', ip: '192.0.2.10', via: 'hint' },
      { name: 'old.example.com', ip: '192.0.2.10', via: 'hint' }
    ]), ['www.example.com:dns', 'api.example.com:dns', 'shop.example.com:zone', 'old.example.com:hint']);
    assert.deepEqual(C.strongestPerName([]), []);
    const src = await readFile(path.join(ROOT, 'assets/js/views/scan.js'), 'utf8');
    assert.match(src, /render: \(g\) => TruncatedList\(strongestPerName\(g\.hosts\), \{/);
  });

  test('SSL Targets plan line follows the variation budget and origin hints at once', async () => {
    const { S } = await load();
    const base = { level: 'smart', domains: ['example.com'], permutations: true, permutationBudget: 1500, originHints: true };
    assert.ok(S.planQueryRange({ ...base, permutationBudget: 5000 }).max > S.planQueryRange(base).max, 'the budget moves the estimate');
    assert.ok(S.planQueryRange({ ...base, originHints: false }).max < S.planQueryRange(base).max, 'so do the origin hints');
    const src = await readFile(path.join(ROOT, 'assets/js/views/scan.js'), 'utf8');
    assert.match(src, /options = \{ \.\.\.options, permutationBudget: Number\(v\) \};\s*saveOptions\(options\);\s*renderVocab\(\);/, 'budget select');
    assert.match(src, /options = \{ \.\.\.options, originHints: on \};\s*saveOptions\(options\);\s*renderVocab\(\);/, 'origin hints box');
  });

  test('SSL Targets: Start and Cancel hand the keyboard focus to each other as they hide', async () => {
    const src = await readFile(path.join(ROOT, 'assets/js/views/scan.js'), 'utf8');
    const running = /function setRunning\(on\) \{([\s\S]*?)\n {2}\}/.exec(src);
    assert.ok(running, 'setRunning found');
    assert.match(running[1], /const hadFocus = [^\n]*activeElement === runBtn \|\| [^\n]*activeElement === cancelBtn/);
    assert.match(running[1], /if \(hadFocus\) \(on \? cancelBtn : runBtn\)\.focus\(\{ preventScroll: true \}\);/);
  });

  test('SSL Targets Behind CDN: one shell choice for the sweep, step 3 and the Verify card', async () => {
    const src = await readFile(path.join(ROOT, 'assets/js/views/scan.js'), 'utf8');
    // Step 3 of the CLI card is launched with the interpreter of the chosen shell (not always python3).
    // (Several certificates: one --cert file each, lib/certsets cliCertFiles.)
    assert.match(src, /cliCommand\(\{ certFile: certFiles \|\| \(cert \? 'new-cert\.pem' : null\), python: PYTHON_FOR_SHELL\[cdnShell\(\)\] \}\)/);
    assert.match(src, /const certFiles = sets \? cliCertFiles\(sets\)\.map\(\(f\) => f\.file\) : null;/);
    // A change in either card re-renders the other one's control and commands.
    assert.match(src, /setShell: \(sh\) => \{\s*session\.cdnShell = sh;\s*syncCdnShell\(\);/, 'Verify → Behind CDN');
    const sync = /function syncCdnShell\(\) \{([\s\S]*?)\n {2}\}/.exec(src);
    assert.ok(sync, 'syncCdnShell found');
    assert.match(sync[1], /cdnShellCtl\.setValue\(cdnShell\(\)\)/, 'the pressed segment follows the shared choice');
    assert.match(sync[1], /for \(const fn of cdnShellRenders\) fn\(\);/, 'the quick sweep and step 3 are redrawn');
    assert.match(src, /cdnShellRenders\.push\(renderQuick\);/);
    assert.match(src, /cdnShellRenders\.push\(renderCommand\);/);
    assert.match(src, /session\.cdnShell = SHELLS\.includes\(sh\) \? sh : 'posix';\s*syncCdnShell\(\);[^\n]*\n[^\n]*\n\s*if \(verifyUi && verifyUi\.refreshShell\) verifyUi\.refreshShell\(\);/, 'Behind CDN → Verify');
    const vfy = await readFile(path.join(ROOT, 'assets/js/ui/verify-panel.js'), 'utf8');
    assert.match(vfy, /refreshShell\(\) \{\s*if \(!disposed\) renderCli\(\);/, 'the Verify card re-reads getShell()');
  });
});

/* ------------------------------------------------------------------------ */
/* Repository invariants (spec §1, §8)                                      */
/* ------------------------------------------------------------------------ */

async function listFiles(dir, pred) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await listFiles(full, pred));
    else if (pred(entry.name)) out.push(full);
  }
  return out;
}

/**
 * Index of the bracket closing the one at `open` in JavaScript source (strings, template
 * literals and comments skipped), or -1. `onComma` sees the commas directly inside it.
 */
function closingIndex(src, open, onComma = null) {
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    const c = src[i];
    if (c === '/' && (src[i + 1] === '/' || src[i + 1] === '*')) {
      i = src[i + 1] === '/' ? src.indexOf('\n', i) : src.indexOf('*/', i) + 1;
      if (i <= 0) return -1;
    } else if (c === '\'' || c === '"' || c === '`') {
      for (i += 1; i < src.length && src[i] !== c; i += 1) {
        if (src[i] === '\\') i += 1;
        else if (c === '`' && src[i] === '$' && src[i + 1] === '{') {
          i = closingIndex(src, i + 1);
          if (i === -1) return -1;
        }
      }
    } else if ('([{'.includes(c)) {
      depth += 1;
    } else if (')]}'.includes(c)) {
      depth -= 1;
      if (!depth) return i;
    } else if (c === ',' && depth === 1 && onComma) {
      onComma(i);
    }
  }
  return -1;
}

/** The top-level argument texts of the call whose `(` is at `open`. */
function callArgs(src, open) {
  const cuts = [];
  const close = closingIndex(src, open, (i) => cuts.push(i));
  if (close === -1) return null;
  const bounds = [open, ...cuts, close];
  return bounds.slice(1).map((end, k) => src.slice(bounds[k] + 1, end).trim()).filter(Boolean);
}

describe('security & shell invariants', () => {
  test('callArgs splits a call at its own commas only', () => {
    const src = "el.append(a(1, 2), `x ${t(`k.${b}`, { n: 1 })}`, 'c, d', // e, f\n  ok ? h('i', null, ')') : null)";
    assert.deepEqual(callArgs(src, src.indexOf('(')), ['a(1, 2)', '`x ${t(`k.${b}`, { n: 1 })}`', "'c, d'", "// e, f\n  ok ? h('i', null, ')') : null"]);
  });

  test('a native append / prepend / replaceChildren never gets a nullable child (the DOM prints "null")', async () => {
    // dom.js append() and h() skip null; Element.append(null) inserts the text "null".
    const files = (await listFiles(path.join(ROOT, 'assets/js'), (n) => n.endsWith('.js'))).filter((f) => !f.includes(`${path.sep}lib${path.sep}`));
    const hits = [];
    for (const file of files) {
      const src = await readFile(file, 'utf8');
      for (const m of src.matchAll(/\.(?:append|prepend|replaceChildren)\(/g)) {
        const where = `${path.relative(ROOT, file)}:${src.slice(0, m.index).split('\n').length}`;
        const args = callArgs(src, m.index + m[0].length - 1);
        // a call this reader cannot split (a regex literal holding a quote or a bracket) fails
        // the guard instead of passing unread
        if (!args) {
          hits.push(`${where} (unreadable)`);
          continue;
        }
        const code = (a) => a.replace(/^(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/)\s*/g, '');
        if (args.some((a) => /^(?:null|undefined)$|\?[\s\S]*:\s*(?:null|undefined)$/.test(code(a)))) hits.push(where);
      }
    }
    assert.deepEqual(hits, [], 'use dom.js append(parent, …) for nullable children');
  });

  test('scripted smooth scrolls honour reduced motion (dom.js scrollBehavior)', async () => {
    // An explicit behavior: 'smooth' overrides the stylesheet's reduced-motion guard.
    const files = await listFiles(path.join(ROOT, 'assets/js'), (n) => n.endsWith('.js'));
    const hits = [];
    for (const file of files) {
      const src = await readFile(file, 'utf8');
      src.split('\n').forEach((line, i) => {
        if (/behavior: 'smooth'/.test(line)) hits.push(`${path.relative(ROOT, file)}:${i + 1}`);
      });
    }
    assert.deepEqual(hits, []);
  });

  test('index.html carries exactly the spec CSP and no inline script/style', async () => {
    const html = await readFile(path.join(ROOT, 'index.html'), 'utf8');
    const m = html.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i);
    assert.ok(m, 'CSP meta present');
    assert.equal(m[1], SPEC_CSP);
    assert.ok(html.indexOf(m[0]) < html.indexOf('<script'), 'CSP comes before any script');
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    assert.ok(scripts.length >= 1);
    for (const [, attrs, body] of scripts) {
      assert.match(attrs, /\bsrc="assets\/js\/[^"]+\.js"/, 'scripts are external, relative');
      assert.equal(body.trim(), '', 'no inline script body');
    }
    assert.doesNotMatch(html, /<style\b/i);
    assert.doesNotMatch(html, /\sstyle\s*=/i);
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, 'no inline event handlers');
    assert.doesNotMatch(html, /(?:href|src)="\/(?!\/)/, 'no root-absolute URLs (GitHub Pages project sites live under /<repo>/)');
    assert.match(html, /<script type="module" src="assets\/js\/app\.js"><\/script>/);
  });

  test('every view stylesheet exists and comes with its view, not with index.html', async () => {
    const html = await readFile(path.join(ROOT, 'index.html'), 'utf8');
    const linked = [...html.matchAll(/<link rel="stylesheet" href="([^"]+)">/g)].map((m) => m[1]);
    assert.deepEqual(linked, ['assets/css/style.css'], 'index.html links the global stylesheet only');
    for (const id of VIEW_IDS) {
      await readFile(path.join(ROOT, `assets/css/views/${id}.css`), 'utf8');
      assert.ok(VIEWS.find((v) => v.id === id).css.includes(`views/${id}.css`), `${id}.css loads with #/${id}`);
    }
  });

  test('no HTML-injection sinks anywhere in assets/js', async () => {
    const files = await listFiles(path.join(ROOT, 'assets/js'), (n) => n.endsWith('.js'));
    const sinks = [/\.(?:innerHTML|outerHTML)\s*\+?=/, /\binsertAdjacentHTML\s*\(/, /\bdocument\.write(?:ln)?\s*\(/, /\bnew\s+Function\s*\(/, /\beval\s*\(/];
    const hits = [];
    for (const file of files) {
      const src = await readFile(file, 'utf8');
      src.split('\n').forEach((line, i) => {
        if (sinks.some((re) => re.test(line))) hits.push(`${path.relative(ROOT, file)}:${i + 1}: ${line.trim()}`);
      });
    }
    assert.deepEqual(hits, []);
  });

  test('stylesheets define both themes and the design tokens views rely on', async () => {
    const css = await readFile(path.join(ROOT, 'assets/css/style.css'), 'utf8');
    // The dark palette is screen-only: printing from dark mode gets the light tokens (dark text on paper).
    assert.match(css, /@media screen and \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme="light"\]\)/);
    assert.match(css, /@media screen \{\s*:root\[data-theme="dark"\] \{/);
    assert.equal((css.match(/color-scheme: dark;/g) || []).length, 2, 'dark only in the two screen-only token blocks');
    assert.match(css, /@media print \{/);
    assert.match(css, /body \{[^}]*background: var\(--bg\)/);
    assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
    for (const token of ['--surface', '--border', '--text', '--accent', '--ok', '--warn', '--error', '--k-cloudflare', '--k-dangling', '--font-mono']) {
      assert.ok(css.includes(`${token}:`), token);
    }
    for (const kind of KINDS) assert.ok(css.includes(`.badge-${kind}`), `.badge-${kind}`);
  });

  test('a status count on a tab keeps its colour when the tab is selected (not the accent of a plain count)', async () => {
    const css = await readFile(path.join(ROOT, 'assets/css/style.css'), 'utf8');
    assert.match(css, /\.tab\.is-selected \.tab-badge \{\s*background: var\(--accent-soft\);/);
    for (const v of ['warn', 'error', 'ok']) {
      assert.match(css, new RegExp(`\\.tab-badge-${v},\\s*\\.tab\\.is-selected \\.tab-badge-${v} \\{\\s*background: var\\(--${v}-bg\\);\\s*color: var\\(--${v}\\);`), v);
    }
  });
});

describe('renewal-panel: the scan summary line about certificate sets', () => {
  test('one set is named by its key types and needs "it"; several sets need "one of them"; zero says none', async () => {
    const { renewalSummaryText } = await import('../../assets/js/ui/renewal-panel.js');
    const pair = [{ id: 'A', keyTypes: ['RSA 2048', 'ECDSA P-256'] }];
    const two = [...pair, { id: 'B', keyTypes: ['RSA 2048'] }];
    const prev = i18n.getLang();
    try {
      i18n.setLang('en');
      assert.equal(renewalSummaryText({ sets: pair, inventory: true, need: 1 }),
        '1 certificate set (RSA 2048 + ECDSA P-256): 1 server needs it — see “Renewal plan”.');
      assert.equal(renewalSummaryText({ sets: pair, inventory: true, need: 3 }),
        '1 certificate set (RSA 2048 + ECDSA P-256): 3 servers need it — see “Renewal plan”.');
      assert.equal(renewalSummaryText({ sets: two, inventory: true, need: 1 }), '2 certificate sets: 1 server needs one of them — see “Renewal plan”.');
      assert.equal(renewalSummaryText({ sets: two, inventory: true, need: 0 }), '2 certificate sets: none of your servers needs one of them — see “Renewal plan”.');
      assert.match(renewalSummaryText({ sets: pair, inventory: false, need: 0 }), /^1 certificate set \(RSA 2048 \+ ECDSA P-256\): the Renewal plan lists the addresses/);
      assert.match(renewalSummaryText({ sets: two, inventory: false, need: 0 }), /^2 certificate sets: the Renewal plan lists which set/);
      i18n.setLang('tr');
      assert.equal(renewalSummaryText({ sets: pair, inventory: true, need: 1 }),
        '1 sertifika seti (RSA 2048 + ECDSA P-256): 1 sunucunun buna ihtiyacı var — “Yenileme planı”na bakın.');
      assert.equal(renewalSummaryText({ sets: two, inventory: true, need: 2 }), '2 sertifika seti: 2 sunucunun bunlardan birine ihtiyacı var — “Yenileme planı”na bakın.');
    } finally {
      i18n.setLang(prev);
    }
  });
});
