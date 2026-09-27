// Unit tests for the shell's navigation model (assets/js/lib/shellnav.js): the tool groups the
// sidebar and the phone Tools menu share, the first-visit task picker's jobs and "has run
// something" signals, and the keyboard shortcuts — which key press means what, which marked
// control answers it, and (read from the sources) that the views keep their results out of their
// forms. Pure: no DOM (elements are plain objects), no storage.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  NAV_GROUPS, OTHER_GROUP, groupViews, isPlainClick, START_TASKS, startTasks, RUN_SESSION_KEYS, isRunSignal, RUN_STORAGE_KEYS, hasUsedBefore,
  SHORTCUTS, SHORTCUT_COMMANDS, isApplePlatform, keyCaps, isTypingTarget, isFormField, escClearsField, isSearchClear,
  shortcutFor, pickShortcutTarget
} from '../../assets/js/lib/shellnav.js';
import { VIEWS, DEFAULT_VIEW } from '../../assets/js/app.js';
import { hasString } from '../../assets/js/i18n.js';
import { createState } from '../../assets/js/state.js';
import { createLearnedStore } from '../../assets/js/lib/learned.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
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
      ['subdomains', 'zone'], ['scan', 'cert'], ['global', 'lookup', 'bulk'], ['ip', 'ptr'], ['health'], ['inventory', 'about']
    ]);
    assert.deepEqual(groups.flatMap((g) => ids(g.views)).sort(), ids(VIEWS).sort());
    assert.equal(groups[0].labelKey, 'nav.groupDiscover');
  });

  test('a view added to the registry appears on its own (e.g. another tool in the IP group)', () => {
    const at = VIEWS.findIndex((v) => v.id === 'ptr') + 1;
    const views = [...VIEWS.slice(0, at), { id: 'whois', group: 'ip', icon: 'network' }, ...VIEWS.slice(at)];
    const ip = groupViews(views).find((g) => g.id === 'ip');
    assert.deepEqual(ids(ip.views), ['ip', 'ptr', 'whois']);
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

  test('isPlainClick: only a plain main-button click is the app\'s; a new tab or window is the browser\'s', () => {
    assert.equal(isPlainClick({ button: 0 }), true);
    assert.equal(isPlainClick({}), true, 'a synthetic click (element.click()) has no button set');
    for (const mod of ['ctrlKey', 'metaKey', 'shiftKey', 'altKey']) {
      assert.equal(isPlainClick({ button: 0, [mod]: true }), false, mod);
    }
    assert.equal(isPlainClick({ button: 1 }), false, 'middle button');
    assert.equal(isPlainClick(null), false);
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

  test('Esc in a search field with text clears it; in the emptied field it cancels', () => {
    const search = (value) => el('input', { type: 'search', value });
    assert.equal(escClearsField(search('www')), true);
    assert.equal(escClearsField(el('input', { type: 'SEARCH', value: ' ' })), true);
    assert.equal(escClearsField(search('')), false);
    assert.equal(escClearsField(search(undefined)), false);
    assert.equal(escClearsField(el('input', { type: 'text', value: 'www' })), false, 'a plain text field has no Esc of its own');
    assert.equal(escClearsField(el('textarea', { value: 'www' })), false);
    assert.equal(escClearsField(null), false);
    assert.equal(shortcutFor(key('Escape', { target: search('www') })), null, 'the filter clears, the job goes on');
    assert.equal(shortcutFor(key('Escape', { target: search('') })), 'cancel', 'the next Esc cancels');
    assert.equal(shortcutFor(key('Escape', { target: el('input', { type: 'text', value: 'example.com' }) })), 'cancel');
  });

  test('the shell clears the search field itself (Firefox does not on Esc): plain Esc only', () => {
    const search = (value) => el('input', { type: 'search', value });
    assert.equal(isSearchClear(key('Escape', { target: search('www') })), true);
    assert.equal(isSearchClear(key('Esc', { target: search('www') })), true, 'old key name');
    assert.equal(isSearchClear(key('Escape', { target: search('') })), false, 'empty: that Esc cancels instead');
    assert.equal(isSearchClear(key('Escape', { target: el('input', { type: 'text', value: 'www' }) })), false);
    for (const mod of ['ctrlKey', 'metaKey', 'altKey', 'shiftKey', 'repeat', 'isComposing']) {
      assert.equal(isSearchClear(key('Escape', { [mod]: true, target: search('www') })), false, mod);
    }
    assert.equal(isSearchClear(key('Escape', { keyCode: 229, target: search('www') })), false, 'an input method at work');
    assert.equal(isSearchClear(key('Enter', { target: search('www') })), false);
    assert.equal(isSearchClear(key('Escape')), false, 'nothing focused');
    assert.equal(isSearchClear(null), false);
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

  test('the nearest scope with a candidate wins', () => {
    const save = make('save');
    const run = make('run');
    const contains = tree({ card: [save], root: [save, run] });
    const usable = (c) => c.usable;
    assert.equal(pickShortcutTarget({ candidates: [run, save], scopes: [make('field'), make('card'), make('root')], contains, usable }), save);
    assert.equal(pickShortcutTarget({ candidates: [run, save], scopes: [make('other'), make('root')], contains, usable }), run, 'document order at the root');
  });

  test('sub-forms: a paste box\'s Read answers the paste box only, the view\'s Run every other field', () => {
    // SSL Targets: step 1 holds a paste box (a sub-form, earlier in the page than Run) and a CT lookup.
    const read = make('read');
    const load = make('load');
    const run = make('run');
    const pasteBox = make('pasteBox');
    const ctLookup = make('ctLookup');
    const pasteField = make('pasteField');
    const ctField = make('ctField');
    const domains = make('domains');
    const within = { pasteField: pasteBox, read: pasteBox, ctField: ctLookup, load: ctLookup };
    const localOf = (node) => within[node.name] || null;
    const contains = tree({ pasteBox: [read], ctLookup: [load], certStep: [read, load], root: [read, load, run] });
    const usable = (c) => c.usable;
    const pick = (from, scopes, extra = {}) => pickShortcutTarget({
      candidates: [read, load, run], scopes: [from, ...scopes], contains, usable, strict: true, from, localOf, ...extra
    });
    assert.equal(pick(domains, [make('stepDomains'), make('root')]), run, 'the domains field runs the scan');
    assert.equal(pick(pasteField, [pasteBox, make('certStep'), make('root')]), read, 'the paste box reads the certificate');
    assert.equal(pick(ctField, [ctLookup, make('certStep'), make('root')]), load, 'the host field loads from CT');
    // Without sub-forms the paste box's Read, first in the page, would answer the domains field.
    assert.equal(pick(domains, [make('stepDomains'), make('root')], { localOf: null }), read, 'what sub-forms prevent');
    // A running lookup turns its button into a Cancel: its field then submits nothing, never the view's Run.
    assert.equal(pickShortcutTarget({
      candidates: [read, run], scopes: [ctField, ctLookup, make('root')], contains, usable, strict: true, from: ctField, localOf
    }), null);
    // A run in progress hides Run: nothing, and a sub-form's action does not stand in.
    const hiddenRun = make('run', { usable: false });
    assert.equal(pickShortcutTarget({
      candidates: [read, hiddenRun], scopes: [domains, make('root')], contains: tree({ root: [read, hiddenRun] }), usable, strict: true,
      from: domains, localOf
    }), null);
    // Nothing focused: the view's own form.
    assert.equal(pickShortcutTarget({ candidates: [read, run], scopes: [make('root')], contains, usable, localOf }), run);
  });

  test('a sub-form without a submit (a results area, a table) answers nothing; Esc from there still cancels', () => {
    // Bulk Resolve after a run: the view's Run is shown again, the results area (a data-shortcut-scope
    // without a submit) holds a table whose filter has the focus, and an option of its own.
    const run = make('run');
    const stop = make('stop');
    const results = make('results');
    const table = make('table');
    const filter = make('filter');
    const option = make('option');
    const textarea = make('textarea');
    const within = { filter: table, option: results }; // the nearest data-shortcut-scope
    const localOf = (node) => within[node.name] || null;
    const contains = tree({ root: [run, stop] });
    const usable = (c) => c.usable;
    const submit = (from, scopes) => pickShortcutTarget({
      candidates: [run], scopes: [from, ...scopes, make('root')], contains, usable, strict: true, from, localOf
    });
    assert.equal(submit(filter, [table, results]), null, 'the table\'s filter starts no new run');
    assert.equal(submit(option, [results]), null, 'nor does an option of the results');
    assert.equal(submit(textarea, [make('card')]), run, 'a field of the form runs the tool');
    // Esc takes no localOf: the Stop button of the run answers from the results too.
    assert.equal(pickShortcutTarget({
      candidates: [stop], scopes: [filter, table, results, make('root')], contains, usable
    }), stop);
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

describe('the controls the views mark for the shortcuts', () => {
  const source = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');

  test('every view but About marks its run, its main input and its results (a new view cannot miss the shortcuts)', () => {
    // Without the markers Ctrl/Cmd+Enter and '/' do nothing there, silently. The results sit in a
    // scope without a submit: Ctrl/Cmd+Enter in a results filter once started the view's run again,
    // dropping the results on screen.
    const tools = VIEWS.filter((v) => v.id !== 'about');
    assert.ok(tools.length >= 10, `views: ${ids(tools)}`);
    for (const v of tools) {
      const src = source(`assets/js/views/${v.id}.js`);
      assert.match(src, /shortcut: 'submit'/, `${v.id}: mark the run button with data-shortcut="submit"`);
      assert.match(src, /(?:'data-shortcut': |shortcut: |dataset\.shortcut = )'focus'/, `${v.id}: mark the main input with data-shortcut="focus"`);
      assert.match(src, /shortcutScope(?::|\s*=)\s*'results'/, `${v.id}: mark the results container with data-shortcut-scope="results"`);
    }
  });

  test('every DataTable is a form of its own without a submit (its search box never runs the view)', () => {
    assert.match(source('assets/js/ui/components.js'), /class: \['dt', className\], dataset: \{ shortcutScope: 'table' \}/);
  });
});
