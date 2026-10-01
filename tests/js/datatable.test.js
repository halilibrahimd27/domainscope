/**
 * ui/components.js DataTable — row updates against a small fake document: `updateRows` replaces
 * many rows (by identity or `rowKey`) with one index of the table and one render, keeps an open
 * row open and skips rows it does not hold; 20,000 fresh rows take milliseconds, not the
 * seconds a search of the table per row takes. Pure Node, no browser.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { DataTable } from '../../assets/js/ui/components.js';

/* ---- a fake document: just enough for DataTable ------------------------------------------ */

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
    const i = this.childNodes.indexOf(child);
    if (i !== -1) this.childNodes.splice(i, 1);
    child.parentNode = null;
    return child;
  }

  append(...nodes) {
    for (const n of nodes) this.appendChild(typeof n === 'string' ? new FakeText(n) : n);
  }

  prepend(...nodes) {
    const rest = this.childNodes.splice(0);
    this.append(...nodes);
    for (const n of rest) this.appendChild(n);
  }

  replaceChildren(...nodes) {
    for (const c of this.childNodes.splice(0)) c.parentNode = null;
    this.append(...nodes);
  }

  get firstChild() {
    return this.childNodes[0] || null;
  }

  contains(node) {
    for (let n = node; n; n = n.parentNode) if (n === this) return true;
    return false;
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
  constructor(tag) {
    super(1);
    this.tagName = tag.toUpperCase();
    this.attributes = new Map();
    this.dataset = {};
    this.style = { setProperty() {} };
    this.hidden = false;
    this.disabled = false;
    this.value = '';
    this.listeners = {};
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

  removeAttribute(k) {
    this.attributes.delete(k);
  }

  addEventListener(type, fn) {
    (this.listeners[type] ||= []).push(fn);
  }

  removeEventListener(type, fn) {
    this.listeners[type] = (this.listeners[type] || []).filter((x) => x !== fn);
  }

  click() {
    for (const fn of this.listeners.click || []) fn({ type: 'click', target: this, stopPropagation() {} });
  }

  focus() {}

  get classList() {
    const get = () => (this.getAttribute('class') || '').split(/\s+/).filter(Boolean);
    const set = (list) => this.setAttribute('class', list.join(' '));
    return {
      contains: (c) => get().includes(c),
      add: (c) => { if (!get().includes(c)) set([...get(), c]); },
      remove: (c) => set(get().filter((x) => x !== c)),
      toggle: (c, on = !get().includes(c)) => {
        set(on ? [...get().filter((x) => x !== c), c] : get().filter((x) => x !== c));
        return on;
      }
    };
  }

  /** `.class` or a tag name, one or several separated by commas. */
  matches(selector) {
    return selector.split(',').map((s) => s.trim()).some((s) => (s.startsWith('.') ? this.classList.contains(s.slice(1)) : this.tagName === s.toUpperCase()));
  }

  querySelectorAll(selector) {
    const out = [];
    const walk = (n) => {
      for (const c of n.childNodes) {
        if (c.nodeType !== 1) continue;
        if (c.matches(selector)) out.push(c);
        walk(c);
      }
    };
    walk(this);
    return out;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
}

const fakeDocument = {
  activeElement: null,
  createElement: (tag) => new FakeElement(tag),
  createElementNS: (_ns, tag) => new FakeElement(tag),
  createTextNode: (s) => new FakeText(s),
  createDocumentFragment: () => new FakeNode(11)
};

let previous;
before(() => {
  previous = globalThis.document;
  globalThis.document = fakeDocument;
});
after(() => {
  if (previous === undefined) delete globalThis.document;
  else globalThis.document = previous;
});

/** Long enough for the table's scheduled render (a frame, up to 160 ms on a big table). */
const rendered = () => new Promise((resolve) => setTimeout(resolve, 400));
const bodyRows = (table) => table.el.querySelector('tbody').childNodes.filter((tr) => tr.matches('.dt-row'));

const COLUMNS = [
  { key: 'ip', label: 'Address', sortable: true },
  { key: 'messages', label: 'Messages', sortable: true, defaultDir: 'desc' },
  { key: 'cls', label: 'Class', sortable: true }
];
const makeRows = (n) => Array.from({ length: n }, (_, i) => ({ ip: `192.0.2.${i % 250}#${i}`, messages: n - i, cls: 'unknown' }));

/* ---- updateRows ----------------------------------------------------------------------------- */

describe('DataTable.updateRows — many rows at once', () => {
  test('fresh objects replace their rows by rowKey, the table\'s own objects are drawn again, an unknown row is skipped; one render', async () => {
    const rows = makeRows(5);
    let renders = 0;
    const table = DataTable({ columns: COLUMNS, rows, rowKey: (r) => r.ip, sort: { key: 'messages', dir: 'desc' }, onChange: () => { renders += 1; } });
    assert.match(bodyRows(table)[0].textContent, /#0.*unknown/);
    renders = 0;
    const fresh = { ...rows[0], cls: 'yours' };
    rows[3].cls = 'forwarder';
    const found = table.updateRows([fresh, rows[3], { ip: '203.0.113.9#x', messages: 1, cls: 'yours' }]);
    assert.equal(found, 2, 'the row it does not hold is skipped, not added');
    assert.equal(table.size, 5);
    assert.equal(table.getRows()[0], fresh, 'replaced in place, by rowKey');
    assert.equal(table.getRows()[3], rows[3]);
    await rendered();
    assert.equal(renders, 1, 'one render for the batch');
    const shown = bodyRows(table).map((tr) => tr.textContent);
    assert.match(shown[0], /#0.*yours/, 'the fresh row drawn');
    assert.match(shown[3], /#3.*forwarder/, 'the mutated row drawn again, not its cached <tr>');
    assert.equal(table.updateRows([]), 0, 'nothing to do');
  });

  test('an open row stays open when a fresh object replaces it, with the new object\'s details', async () => {
    const rows = makeRows(3);
    const table = DataTable({ columns: COLUMNS, rows, rowKey: (r) => r.ip, details: (r) => `details: ${r.cls}` });
    table.el.querySelector('.dt-expand-btn').click();
    const details = () => table.el.querySelector('tbody').childNodes.filter((tr) => tr.matches('.dt-details')).map((tr) => tr.textContent);
    assert.deepEqual(details(), ['details: unknown']);
    assert.equal(table.updateRows([{ ...rows[0], cls: 'yours' }]), 1);
    await rendered();
    assert.deepEqual(details(), ['details: yours']);
  });

  test('20,000 fresh rows are refreshed well under 200 ms: one index of the table, not a search of it per row', async () => {
    const n = 20000;
    const rows = makeRows(n);
    const table = DataTable({ columns: COLUMNS, rows, rowKey: (r) => r.ip, sort: { key: 'messages', dir: 'desc' } });
    const fresh = rows.map((r, i) => ({ ...r, cls: i % 2 ? 'yours' : 'third-party' }));
    const t0 = performance.now();
    const found = table.updateRows(fresh);
    // The sort of the render that follows (the visible rows are what it draws).
    const visible = table.getVisibleRows();
    const ms = performance.now() - t0;
    assert.equal(found, n);
    assert.equal(visible[0], fresh[0]);
    assert.ok(ms < 200, `${n} rows took ${ms.toFixed(0)} ms`);
    await rendered();
    assert.match(bodyRows(table)[0].textContent, /third-party/);
  });
});
