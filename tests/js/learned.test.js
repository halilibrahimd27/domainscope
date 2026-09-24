// Unit tests for the per-browser learned-labels store (assets/js/lib/learned.js).
// No network, no real localStorage: storage is injected as a small in-memory
// mock (and, for the failure cases, a throwing / corrupt one).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createLearnedStore, isStorableLabel, looksLikeIpLabel } from '../../assets/js/lib/learned.js';

/** Minimal localStorage-like mock. */
function memStorage(initial = {}) {
  const m = new Map(Object.entries(initial));
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    _dump: () => Object.fromEntries(m)
  };
}

describe('createLearnedStore — recording & privacy', () => {
  test('records only the left-most label(s) relative to the apex', () => {
    const s = createLearnedStore(memStorage());
    s.record(['api.example.com', 'dev.api.example.com'], 'example.com');
    const labels = s.labels();
    assert.ok(labels.includes('api') && labels.includes('dev'));
    // never the full hostname
    assert.ok(!labels.some((l) => l.includes('.')), labels.join(','));
    assert.ok(!labels.includes('example') && !labels.includes('com'), 'apex labels not stored');
  });

  test('skips the apex itself, wildcards, empties', () => {
    const s = createLearnedStore(memStorage());
    s.record(['example.com', '*.example.com', '', '   '], 'example.com');
    assert.equal(s.size(), 0);
  });

  test('never stores IP addresses (v4 or v6)', () => {
    const s = createLearnedStore(memStorage());
    s.record(['203.0.113.10', '2001:db8::1', '[2001:db8::2]', 'api.example.com'], 'example.com');
    assert.deepEqual(s.labels(), ['api']);
  });

  test('never stores an IP written into a label (reverse-DNS style, v4 and v6)', () => {
    const s = createLearnedStore(memStorage());
    s.record([
      '198-51-100-7.example.com', 'ip-192-0-2-10.example.com', '203-0-113-9-static.example.com',
      'host-198-51-100-20.example.com',
      '2001-db8--1.example.com', 'ip6-2001-db8-0-0-0-0-0-1.example.com',
      'api.example.com', 'web-01.example.com', 'build-2024-01-02.example.com', 'xn--mnchen-3ya.example.com'
    ], 'example.com');
    assert.deepEqual([...s.labels()].sort(), ['api', 'build-2024-01-02', 'web-01', 'xn--mnchen-3ya'].sort());
  });

  test('looksLikeIpLabel / isStorableLabel: the shared rule', () => {
    for (const ipish of ['198-51-100-7', 'ip-192-0-2-10', '203-0-113-9-static', 'static-203-0-113-9', '2001-db8--1', '2001-db8-85a3-0-0-8a2e-370-7334']) {
      assert.equal(looksLikeIpLabel(ipish), true, ipish);
      assert.equal(isStorableLabel(ipish), false, ipish);
    }
    for (const ok of ['api', 'web-01', 'db-01-02', 'v1-2-3', 'cafe-babe', 'xn--80ak6aa92e', 'mail2']) {
      assert.equal(looksLikeIpLabel(ok), false, ok);
      assert.equal(isStorableLabel(ok), true, ok);
    }
    assert.equal(isStorableLabel('123'), false, 'pure numbers');
    assert.equal(isStorableLabel('-bad'), false);
  });

  test('IP-like labels already in storage are dropped on load', () => {
    const storage = memStorage({ 'ssds.learned.labels': JSON.stringify({ v: 1, seq: 2, labels: { '198-51-100-7': [3, 1], api: [1, 2] } }) });
    assert.deepEqual(createLearnedStore(storage).labels(), ['api']);
  });

  test('falls back to the first label when the name is unrelated to the apex', () => {
    const s = createLearnedStore(memStorage());
    s.record(['shop.other-site.net'], 'example.com');
    assert.deepEqual(s.labels(), ['shop']);
  });

  test('skips pure-numeric labels', () => {
    const s = createLearnedStore(memStorage());
    s.record(['10.example.com', 'api.example.com'], 'example.com');
    assert.deepEqual(s.labels(), ['api']);
  });

  test('accepts a single name (not just arrays)', () => {
    const s = createLearnedStore(memStorage());
    s.record('vpn.example.com', 'example.com');
    assert.deepEqual(s.labels(), ['vpn']);
  });
});

describe('createLearnedStore — ranking & caps', () => {
  test('labels() orders by hit count, then recency', () => {
    const s = createLearnedStore(memStorage());
    s.record(['a.example.com'], 'example.com'); // a:1
    s.record(['b.example.com'], 'example.com'); // b:1 (more recent)
    s.record(['a.example.com'], 'example.com'); // a:2
    s.record(['c.example.com'], 'example.com'); // c:1 (most recent)
    // a has most hits; then c (newer) before b (older), both 1 hit
    assert.deepEqual(s.labels(), ['a', 'c', 'b']);
  });

  test('honours the max cap by evicting the least useful entries', () => {
    const s = createLearnedStore(memStorage(), { max: 2 });
    s.record(['keep.example.com'], 'example.com');
    s.record(['keep.example.com'], 'example.com'); // hits 2
    s.record(['mid.example.com'], 'example.com');  // hits 1, older
    s.record(['drop.example.com'], 'example.com'); // hits 1, newest
    // Evict lowest hits first; ties go to the least recent: mid (1 hit, older) goes.
    assert.equal(s.size(), 2);
    assert.deepEqual(s.labels(), ['keep', 'drop']);
  });
});

describe('createLearnedStore — persistence & robustness', () => {
  test('persists across store instances sharing the same storage', () => {
    const storage = memStorage();
    const a = createLearnedStore(storage);
    a.record(['billing.example.com', 'billing.example.com', 'crm.example.com'], 'example.com');
    const b = createLearnedStore(storage);
    assert.deepEqual(b.labels(), ['billing', 'crm'], 'reloaded, ranked by hits');
    assert.equal(b.size(), 2);
  });

  test('a null storage works purely in memory', () => {
    const s = createLearnedStore(null);
    assert.equal(s.record(['api.example.com'], 'example.com'), 1);
    assert.deepEqual(s.labels(), ['api']);
  });

  test('a storage that throws on read → empty store, still records in memory', () => {
    const throwing = {
      getItem: () => { throw new Error('SecurityError'); },
      setItem: () => { throw new Error('SecurityError'); }
    };
    const s = createLearnedStore(throwing);
    assert.doesNotThrow(() => s.record(['api.example.com'], 'example.com'));
    assert.deepEqual(s.labels(), ['api']);
  });

  test('corrupt stored JSON → starts empty rather than throwing', () => {
    const storage = memStorage({ 'ssds.learned.labels': '{not json' });
    let s;
    assert.doesNotThrow(() => { s = createLearnedStore(storage); });
    assert.equal(s.size(), 0);
    s.record(['ok.example.com'], 'example.com');
    assert.deepEqual(s.labels(), ['ok']);
  });

  test('a custom key is honoured', () => {
    const storage = memStorage();
    const s = createLearnedStore(storage, { key: 'my.key' });
    s.record(['api.example.com'], 'example.com');
    assert.ok('my.key' in storage._dump());
  });
});

describe('createLearnedStore — clear / export / import', () => {
  test('clear empties the store and persisted data', () => {
    const storage = memStorage();
    const s = createLearnedStore(storage);
    s.record(['api.example.com'], 'example.com');
    s.clear();
    assert.equal(s.size(), 0);
    assert.deepEqual(createLearnedStore(storage).labels(), []);
  });

  test('export/import round-trips and merges hit counts', () => {
    const a = createLearnedStore(memStorage());
    a.record(['api.example.com', 'api.example.com', 'dev.example.com'], 'example.com');
    const dump = a.export();
    assert.ok(dump.labels.api, 'export shape has labels map');

    const b = createLearnedStore(memStorage());
    b.record(['api.example.com'], 'example.com'); // api:1
    b.import(dump);                                // + api:2, dev:1 → api:3
    assert.deepEqual(b.labels(), ['api', 'dev']);
  });

  test('import tolerates garbage without throwing', () => {
    const s = createLearnedStore(memStorage());
    assert.doesNotThrow(() => s.import(null));
    assert.doesNotThrow(() => s.import({ labels: 'nope' }));
    assert.doesNotThrow(() => s.import({ labels: { 'BAD LABEL': 5, ok: 2 } }));
    assert.deepEqual(s.labels(), ['ok'], 'only the valid label survives');
  });
});
