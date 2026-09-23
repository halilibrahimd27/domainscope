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
import * as dom from '../../assets/js/ui/dom.js';
import { sanitizeFilename, timestampedName, jsonReplacer } from '../../assets/js/ui/download.js';
import {
  compareValues, ipSortValue, normalizeSearch, csvCell, rowsToCsv, decodeText, describeError, ICON_NAMES, KINDS
} from '../../assets/js/ui/components.js';
import { parseRoute, buildRoute, sameParams, VIEWS, REPO_URL, DEFAULT_VIEW } from '../../assets/js/app.js';
import { DEFAULT_CHAIN } from '../../assets/js/lib/resolvers.js';
import { HttpError } from '../../assets/js/lib/util.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SPEC_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src https:; base-uri 'none'; form-action 'none'; manifest-src 'self'";
const VIEW_IDS = ['scan', 'cert', 'global', 'lookup', 'bulk', 'ip', 'health', 'inventory', 'about'];

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
      return (raw.match(/\{[A-Za-z0-9_.-]+\}/g) || []).sort();
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
    assert.deepEqual(s.settings, { lang: null, theme: 'auto', chain: [...DEFAULT_CHAIN], concurrency: 12 });
    assert.equal(s.inventory.text, '');
    assert.deepEqual(s.inventory.servers, []);
    assert.equal(s.inventory.updatedAt, null);
    assert.equal(s.persistence, true);
    assert.equal(STORAGE_PREFIX, 'ssds.');
  });

  test('inventory round-trips through storage (text only; servers re-parsed)', () => {
    const storage = new MemoryStorage();
    const a = make(storage);
    const res = a.setInventory('web01 10.0.0.5\nweb02 10.0.0.6 2001:db8::6\nbroken');
    assert.equal(res.persisted, true);
    assert.equal(res.inventory.servers.length, 2);
    const raw = JSON.parse(storage.getItem('ssds.inventory'));
    assert.equal(raw.v, 1);
    assert.equal(raw.text.startsWith('web01'), true);
    assert.equal(raw.servers, undefined, 'derived data is not stored');
    const b = make(storage);
    assert.equal(b.inventory.servers.length, 2);
    assert.deepEqual(b.inventory.servers[1].ips, ['10.0.0.6', '2001:db8::6']);
    assert.equal(b.inventory.warnings.length, 1);
    assert.ok(b.inventory.updatedAt instanceof Date);
    assert.equal(b.inventory.updatedAt.toISOString(), '2026-09-23T10:00:00.000Z');
  });

  test('corrupt or foreign storage values fall back to defaults', () => {
    const storage = new MemoryStorage({
      'ssds.inventory': '{not json',
      'ssds.settings': JSON.stringify({ theme: 'neon', lang: 'de', chain: ['nope', 'google', 'google', 'cloudflare'], concurrency: 1000 })
    });
    const s = make(storage);
    assert.equal(s.inventory.text, '');
    assert.deepEqual(s.settings, { lang: null, theme: 'auto', chain: ['google', 'cloudflare'], concurrency: 32 });
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
  });

  test('write failures (quota / disabled storage) keep state in memory and report it', () => {
    const storage = new MemoryStorage();
    storage.failWrites = true;
    const s = make(storage);
    const res = s.setInventory('web01 10.0.0.5');
    assert.equal(res.persisted, false);
    assert.equal(s.inventory.servers.length, 1, 'in-memory state still updated');
    assert.equal(s.lastPersistError.name, 'QuotaExceededError');
    const none = make(null);
    assert.equal(none.persistence, false);
    assert.equal(none.setInventory('a 10.0.0.1').persisted, false);
    assert.equal(none.updateSettings({ theme: 'dark' }).theme, 'dark');
  });

  test('a storage whose getItem throws (SecurityError) degrades to defaults', () => {
    const hostile = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('no'); }, removeItem() {}, length: 0, key: () => null };
    const s = make(hostile);
    assert.equal(s.settings.theme, 'auto');
    assert.equal(s.clearAll(), true);
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

  test('clearAll removes only ssds.* keys and resets every slice', () => {
    const storage = new MemoryStorage({ other: 'keep', 'ssds.extra': '1' });
    const s = make(storage);
    s.setInventory('web01 10.0.0.5');
    s.updateSettings({ theme: 'dark' });
    s.setSession('x', 1);
    assert.equal(s.clearAll(), true);
    assert.deepEqual([...storage.map.keys()], ['other']);
    assert.equal(s.inventory.servers.length, 0);
    assert.equal(s.settings.theme, 'auto');
    assert.equal(s.getSession('x'), undefined);
  });

  test('handleExternalChange re-reads storage written by another tab', () => {
    const storage = new MemoryStorage();
    const s = make(storage);
    const events = [];
    s.subscribe((e) => events.push(e));
    storage.setItem('ssds.inventory', JSON.stringify({ v: 1, text: 'web09 10.9.9.9', updatedAt: '2026-01-01T00:00:00Z' }));
    storage.setItem('ssds.settings', JSON.stringify({ v: 1, theme: 'dark' }));
    s.handleExternalChange(null);
    assert.equal(s.inventory.servers[0].name, 'web09');
    assert.equal(s.settings.theme, 'dark');
    assert.deepEqual(events.map((e) => [e.key, e.origin]), [['inventory', 'external'], ['settings', 'external']]);
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

  test('VIEWS follow the spec order; REPO_URL is a placeholder https URL', () => {
    assert.deepEqual(VIEWS.map((v) => v.id), VIEW_IDS);
    assert.ok(VIEWS.every((v) => typeof v.load === 'function' && ['ssl', 'dns', 'data'].includes(v.group)));
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

describe('security & shell invariants', () => {
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

  test('all nine view stylesheets exist and are linked', async () => {
    const html = await readFile(path.join(ROOT, 'index.html'), 'utf8');
    for (const id of VIEW_IDS) {
      await readFile(path.join(ROOT, `assets/css/views/${id}.css`), 'utf8');
      assert.ok(html.includes(`href="assets/css/views/${id}.css"`), `${id}.css linked`);
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
    assert.match(css, /@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme="light"\]\)/);
    assert.match(css, /:root\[data-theme="dark"\] \{/);
    assert.match(css, /body \{[^}]*background: var\(--bg\)/);
    assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
    for (const token of ['--surface', '--border', '--text', '--accent', '--ok', '--warn', '--error', '--k-cloudflare', '--k-dangling', '--font-mono']) {
      assert.ok(css.includes(`${token}:`), token);
    }
    for (const kind of KINDS) assert.ok(css.includes(`.badge-${kind}`), `.badge-${kind}`);
  });
});
