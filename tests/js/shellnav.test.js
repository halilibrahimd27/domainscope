// Unit tests for the shell's navigation model (assets/js/lib/shellnav.js): the tool groups the
// sidebar and the phone Tools menu share, the first-visit task picker's jobs and "has run
// something" signals, and the keyboard shortcuts — which key press means what, and which marked
// control answers it. Pure: no DOM (elements are plain objects), no storage.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  NAV_GROUPS, OTHER_GROUP, groupViews, START_TASKS, startTasks, RUN_SESSION_KEYS, isRunSignal, RUN_STORAGE_KEYS, hasUsedBefore,
  SHORTCUTS, SHORTCUT_COMMANDS, isApplePlatform, keyCaps, isTypingTarget, isFormField, shortcutFor,
  pickShortcutTarget
} from '../../assets/js/lib/shellnav.js';
import { VIEWS, DEFAULT_VIEW } from '../../assets/js/app.js';
import { hasString } from '../../assets/js/i18n.js';
import { createState } from '../../assets/js/state.js';
import { createLearnedStore } from '../../assets/js/lib/learned.js';

const ids = (list) => list.map((x) => x.id);

/** Web Storage stub: just enough for state.js and lib/learned.js. */
class MemoryStorage {
  constructor() {
    this.map = new Map();
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
    this.map.delete(k);
  }
}
const el = (tagName, extra = {}) => ({ tagName: tagName.toUpperCase(), ...extra });
const key = (k, extra = {}) => ({ key: k, target: el('body'), ...extra });

describe('groupViews — the tool groups', () => {
  test('NAV_GROUPS: Discover, SSL, DNS, IP, Mail & domain, Data, each translated', () => {
    assert.deepEqual(ids(NAV_GROUPS), ['discover', 'ssl', 'dns', 'ip', 'mail', 'data']);
    for (const g of [...NAV_GROUPS, OTHER_GROUP]) {
      assert.ok(hasString(g.labelKey, 'en') && hasString(g.labelKey, 'tr'), g.labelKey);
    }
    assert.ok(Object.isFrozen(NAV_GROUPS) && NAV_GROUPS.every(Object.isFrozen));
  });

  test('the registry: every view listed exactly once, in group order, registry order inside a group', () => {
    const groups = groupViews(VIEWS);
    assert.deepEqual(ids(groups), ['discover', 'ssl', 'dns', 'ip', 'mail', 'data']);
    assert.deepEqual(groups.map((g) => ids(g.views)), [
      ['subdomains', 'zone'], ['scan', 'cert'], ['global', 'lookup', 'bulk'], ['ip'], ['health'], ['inventory', 'about']
    ]);
    assert.deepEqual(groups.flatMap((g) => ids(g.views)).sort(), ids(VIEWS).sort());
    assert.equal(groups[0].labelKey, 'nav.groupDiscover');
  });

  test('a view added to the registry appears on its own (e.g. a Reverse DNS view in the IP group)', () => {
    const views = [...VIEWS.slice(0, 8), { id: 'ptr', group: 'ip', icon: 'network' }, ...VIEWS.slice(8)];
    const ip = groupViews(views).find((g) => g.id === 'ip');
    assert.deepEqual(ids(ip.views), ['ip', 'ptr']);
  });

  test('a missing or unknown group lands in a trailing "More tools" group, never dropped', () => {
    const groups = groupViews([
      { id: 'a', group: 'nope' }, { id: 'b', group: 'dns' }, { id: 'c' }, { id: 'd', group: 'discover' }
    ]);
    assert.deepEqual(groups.map((g) => [g.id, ids(g.views)]), [['discover', ['d']], ['dns', ['b']], ['other', ['a', 'c']]]);
    assert.equal(groups.at(-1).labelKey, OTHER_GROUP.labelKey);
  });

  test('empty groups are left out; junk entries are skipped; a custom group table is honoured', () => {
    assert.deepEqual(groupViews([]), []);
    assert.deepEqual(groupViews(null), []);
    assert.deepEqual(ids(groupViews([null, { group: 'dns' }, { id: 'x', group: 'dns' }])), ['dns']);
    const custom = [{ id: 'b', labelKey: 'k.b' }, { id: 'a', labelKey: 'k.a' }];
    assert.deepEqual(groupViews([{ id: '1', group: 'a' }, { id: '2', group: 'b' }], custom).map((g) => [g.id, g.labelKey]),
      [['b', 'k.b'], ['a', 'k.a']]);
  });
});

describe('first-visit task picker', () => {
  test('five jobs, each done by a view of the registry and translated in both languages', () => {
    assert.deepEqual(START_TASKS.map((x) => [x.id, x.view]), [
      ['subdomains', 'subdomains'], ['certificate', 'scan'], ['health', 'health'], ['propagation', 'global'], ['zone', 'zone']
    ]);
    const known = new Set(ids(VIEWS));
    for (const task of START_TASKS) {
      assert.ok(known.has(task.view), task.view);
      assert.ok(hasString(`start.task.${task.id}`, 'en') && hasString(`start.task.${task.id}`, 'tr'), task.id);
    }
    assert.equal(START_TASKS[0].view, DEFAULT_VIEW, 'the start page\'s own job comes first');
  });

  test('startTasks takes the tool\'s icon and leaves out a job whose tool is missing', () => {
    const tasks = startTasks(VIEWS);
    assert.deepEqual(tasks.map((x) => [x.id, x.icon]), [
      ['subdomains', 'layers'], ['certificate', 'target'], ['health', 'activity'], ['propagation', 'globe'], ['zone', 'file-text']
    ]);
    assert.deepEqual(ids(startTasks(VIEWS.filter((v) => v.id !== 'zone'))), ['subdomains', 'certificate', 'health', 'propagation']);
    assert.deepEqual(startTasks([{ id: 'global' }]), [{ id: 'propagation', view: 'global', icon: null }]);
    assert.deepEqual(startTasks(null), []);
  });

  test('isRunSignal: saved servers, an imported zone or a loaded certificate', () => {
    assert.deepEqual(RUN_SESSION_KEYS, ['zone', 'currentCert']);
    assert.equal(isRunSignal({ key: 'inventory', value: { servers: [{ name: 'web01' }] } }), true);
    assert.equal(isRunSignal({ key: 'inventory', value: { servers: [] } }), false, 'cleared inventory');
    assert.equal(isRunSignal({ key: 'session', value: { name: 'zone', value: { origin: 'example.com' } } }), true);
    assert.equal(isRunSignal({ key: 'session', value: { name: 'currentCert', value: { cert: {} } } }), true);
    assert.equal(isRunSignal({ key: 'session', value: { name: 'zone', value: undefined } }), false, 'Forget');
    assert.equal(isRunSignal({ key: 'session', value: { name: 'inventoryDraft', value: 'web01 192.0.2.1' } }), false, 'a draft is no run');
    assert.equal(isRunSignal({ key: 'settings', value: { startTasks: false } }), false);
    assert.equal(isRunSignal({ key: 'cleared', value: true }), false);
    assert.equal(isRunSignal(null), false);
  });

  test('hasUsedBefore: only what a run or a save leaves stored (saved servers, learned names)', () => {
    assert.deepEqual(RUN_STORAGE_KEYS, ['ssds.inventory', 'ssds.learned.labels']);
    assert.equal(hasUsedBefore([]), false);
    assert.equal(hasUsedBefore(['ssds.settings']), false, 'a theme change alone');
    assert.equal(hasUsedBefore(['ssds.settings', 'other.app']), false, 'another app on the origin');
    assert.equal(hasUsedBefore(['ssds.inventory']), true);
    assert.equal(hasUsedBefore(['ssds.settings', 'ssds.learned.labels']), true);
    // A switch flipped or a language pack opened on the start page writes the view's options: no run.
    for (const k of ['ssds.subdomains.options', 'ssds.scan.options', 'ssds.bulk.options', 'ssds.wordlist.custom', 'ssds.probe']) {
      assert.equal(hasUsedBefore(['ssds.settings', k]), false, k);
    }
    assert.equal(hasUsedBefore(new Set([null, 1, 'ssds.inventory'])), true);
    assert.equal(hasUsedBefore(['x.y'], ['x.y']), true);
    assert.equal(hasUsedBefore(null), false);
  });

  test('RUN_STORAGE_KEYS are the keys state.js and lib/learned.js really write', () => {
    const storage = new MemoryStorage();
    const s = createState({ storage, listenStorageEvents: false });
    s.updateSettings({ theme: 'dark' });
    assert.equal(hasUsedBefore([...storage.map.keys()]), false, 'settings only');
    s.setInventory('web01 192.0.2.10');
    assert.ok([...storage.map.keys()].includes(RUN_STORAGE_KEYS[0]), 'saved servers');
    const learned = new MemoryStorage();
    createLearnedStore(learned).record(['api.example.com', 'shop.example.com'], 'example.com');
    assert.deepEqual([...learned.map.keys()], [RUN_STORAGE_KEYS[1]], 'learned names');
  });
});

describe('keyboard shortcuts — which key means what', () => {
  test('SHORTCUTS: Mod+Enter, Esc, /, ?, each described in both languages', () => {
    assert.deepEqual(SHORTCUTS.map((s) => [s.id, s.keys.join('+')]), [['submit', 'Mod+Enter'], ['cancel', 'Esc'], ['focus', '/'], ['help', '?']]);
    assert.deepEqual(SHORTCUT_COMMANDS, ['submit', 'cancel', 'focus', 'help']);
    for (const s of SHORTCUTS) assert.ok(hasString(`keys.${s.id}`, 'en') && hasString(`keys.${s.id}`, 'tr'), s.id);
    for (const k of ['keys.title', 'keys.note']) assert.ok(hasString(k, 'en') && hasString(k, 'tr'), k);
  });

  test('key caps: ⌘ on Apple platforms, Ctrl elsewhere', () => {
    for (const p of ['MacIntel', 'macOS', 'iPhone', 'iPad']) assert.equal(isApplePlatform(p), true, p);
    for (const p of ['Win32', 'Windows', 'Linux x86_64', 'Android', '', undefined]) assert.equal(isApplePlatform(p), false, String(p));
    assert.deepEqual(keyCaps(['Mod', 'Enter'], { apple: true }), ['⌘', 'Enter']);
    assert.deepEqual(keyCaps(['Mod', 'Enter']), ['Ctrl', 'Enter']);
    assert.deepEqual(keyCaps(['Esc']), ['Esc']);
    assert.deepEqual(keyCaps(null), []);
  });

  test('typing targets: text inputs, textareas, selects, editable elements', () => {
    for (const type of [undefined, '', 'text', 'search', 'url', 'email', 'number', 'password', 'tel', 'TEXT']) {
      assert.equal(isTypingTarget(el('input', { type })), true, `input ${type}`);
    }
    for (const type of ['checkbox', 'radio', 'button', 'submit', 'file', 'range', 'color']) {
      assert.equal(isTypingTarget(el('input', { type })), false, `input ${type}`);
      assert.equal(isFormField(el('input', { type })), true, `input ${type} is a field`);
    }
    assert.equal(isTypingTarget(el('textarea')), true);
    assert.equal(isTypingTarget(el('select')), true, 'type-ahead picks an option');
    assert.equal(isTypingTarget(el('div', { isContentEditable: true })), true);
    assert.equal(isTypingTarget(el('button')), false);
    assert.equal(isTypingTarget(el('a')), false);
    assert.equal(isTypingTarget(null), false);
    assert.equal(isFormField(el('textarea')), true);
    assert.equal(isFormField(el('select')), true);
    assert.equal(isFormField(el('button')), false);
    assert.equal(isFormField(el('div', { isContentEditable: true })), false);
    assert.equal(isFormField(null), false);
  });

  test('Ctrl/Cmd+Enter submits from any form field, and only there', () => {
    for (const target of [el('input'), el('textarea'), el('select'), el('input', { type: 'checkbox' })]) {
      assert.equal(shortcutFor(key('Enter', { ctrlKey: true, target })), 'submit', target.tagName);
      assert.equal(shortcutFor(key('Enter', { metaKey: true, target })), 'submit', `${target.tagName} ⌘`);
    }
    assert.equal(shortcutFor(key('Enter', { target: el('textarea') })), null, 'plain Enter types a new line');
    assert.equal(shortcutFor(key('Enter', { ctrlKey: true, shiftKey: true, target: el('input') })), null);
    assert.equal(shortcutFor(key('Enter', { ctrlKey: true, altKey: true, target: el('input') })), null);
    assert.equal(shortcutFor(key('Enter', { ctrlKey: true, target: el('button') })), null, 'a button is no field');
    assert.equal(shortcutFor(key('Enter', { ctrlKey: true })), null, 'nothing focused');
  });

  test('Esc cancels from anywhere, a field included', () => {
    assert.equal(shortcutFor(key('Escape')), 'cancel');
    assert.equal(shortcutFor(key('Esc')), 'cancel', 'old key name');
    assert.equal(shortcutFor(key('Escape', { target: el('input') })), 'cancel');
    assert.equal(shortcutFor(key('Escape', { target: el('textarea') })), 'cancel');
    assert.equal(shortcutFor(key('Escape', { shiftKey: true })), null);
    assert.equal(shortcutFor(key('Escape', { ctrlKey: true })), null);
  });

  test('/ and ? act only while not typing; Shift and AltGr are fine, Ctrl / Alt / ⌘ alone are not', () => {
    assert.equal(shortcutFor(key('/')), 'focus');
    assert.equal(shortcutFor(key('?', { shiftKey: true })), 'help');
    assert.equal(shortcutFor(key('/', { shiftKey: true })), 'focus', 'Shift+7 on a Turkish Q layout');
    assert.equal(shortcutFor(key('/', { ctrlKey: true, altKey: true })), 'focus', 'AltGr');
    assert.equal(shortcutFor(key('/', { target: el('button') })), 'focus');
    assert.equal(shortcutFor(key('/', { target: el('input', { type: 'checkbox' }) })), 'focus');
    for (const target of [el('input'), el('textarea'), el('select'), el('div', { isContentEditable: true })]) {
      assert.equal(shortcutFor(key('/', { target })), null, `/ typed in ${target.tagName}`);
      assert.equal(shortcutFor(key('?', { target, shiftKey: true })), null, `? typed in ${target.tagName}`);
    }
    assert.equal(shortcutFor(key('/', { ctrlKey: true })), null);
    assert.equal(shortcutFor(key('/', { altKey: true })), null);
    assert.equal(shortcutFor(key('/', { metaKey: true })), null);
    assert.equal(shortcutFor(key('?', { metaKey: true })), null);
  });

  test('held keys, IME composition and other keys mean nothing', () => {
    assert.equal(shortcutFor(key('/', { repeat: true })), null);
    assert.equal(shortcutFor(key('Enter', { ctrlKey: true, target: el('input'), isComposing: true })), null);
    assert.equal(shortcutFor(key('Enter', { ctrlKey: true, target: el('input'), keyCode: 229 })), null);
    assert.equal(shortcutFor(key('Escape', { repeat: true })), null);
    for (const k of ['a', 'k', 'Tab', ' ', 'F1', 'ArrowDown']) assert.equal(shortcutFor(key(k)), null, k);
    assert.equal(shortcutFor(key('k', { ctrlKey: true })), null);
    assert.equal(shortcutFor(null), null);
  });
});

describe('pickShortcutTarget — which marked control answers', () => {
  // A tiny tree: scopes are plain objects, `members` lists the candidates inside each.
  const make = (name, extra = {}) => ({ name, usable: true, ...extra });
  const tree = (spec) => {
    const members = new Map(Object.entries(spec));
    return (scope, candidate) => (members.get(scope.name) || []).includes(candidate);
  };

  test('the nearest scope with a candidate wins (a paste box\'s Read, not the page\'s Run)', () => {
    const read = make('read');
    const run = make('run');
    const contains = tree({ pasteBlock: [read], form: [read, run], root: [read, run] });
    const scopes = [make('field'), make('pasteBlock'), make('form'), make('root')];
    assert.equal(pickShortcutTarget({ candidates: [read, run], scopes, contains, usable: (c) => c.usable }), read);
    // From a field outside the paste block: the form's first usable one.
    assert.equal(pickShortcutTarget({ candidates: [read, run], scopes: [make('other'), make('form')], contains, usable: (c) => c.usable }), read);
  });

  test('strict (submit): a scope whose action is unavailable stops the search', () => {
    const run = make('run', { usable: false }); // hidden while the scan runs
    const other = make('other');
    const contains = tree({ form: [run], root: [run, other] });
    const scopes = [make('form'), make('root')];
    const usable = (c) => c.usable;
    assert.equal(pickShortcutTarget({ candidates: [run, other], scopes, contains, usable, strict: true }), null);
    assert.equal(pickShortcutTarget({ candidates: [run, other], scopes, contains, usable }), other, 'lenient (cancel) goes on');
  });

  test('lenient (cancel): the Stop button of whatever runs, nearest first', () => {
    const stopA = make('stopA', { usable: false }); // idle panel next to the focus
    const stopB = make('stopB');
    const contains = tree({ panelA: [stopA], root: [stopA, stopB] });
    assert.equal(pickShortcutTarget({
      candidates: [stopA, stopB], scopes: [make('panelA'), make('root')], contains, usable: (c) => c.usable
    }), stopB);
  });

  test('nothing marked, nothing usable, no scopes: null', () => {
    const contains = () => true;
    assert.equal(pickShortcutTarget({ candidates: [], scopes: [make('root')], contains }), null);
    assert.equal(pickShortcutTarget({ candidates: [make('x', { usable: false })], scopes: [make('root')], contains, usable: (c) => c.usable }), null);
    assert.equal(pickShortcutTarget({ candidates: [make('x')], scopes: [], contains }), null);
    assert.equal(pickShortcutTarget({ candidates: null, scopes: null, contains }), null);
  });

  test('usable defaults to every candidate; document order decides inside a scope', () => {
    const a = make('a');
    const b = make('b');
    assert.equal(pickShortcutTarget({ candidates: [b, a], scopes: [make('root')], contains: () => true }), b);
  });
});
