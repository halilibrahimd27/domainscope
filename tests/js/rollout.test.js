// lib/rollout.js — board rows from a scan or a renewal plan, the stored checklist, the Verify
// tab's confirmations, progress and the CSV. Documentation names and addresses only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  ROLLOUT_STEPS, ROLLOUT_STAGES, ROLLOUT_VERIFY, ROLLOUT_LIMITS, ROLLOUT_CSV_COLUMNS, boardId, setKey, rolloutRows,
  emptyRollout, parseRollout, serializeRollout, findBoard, setStep, resetBoard, verifyStatus, applyVerify, boardRows,
  rolloutProgress, rolloutCsvRows
} from '../../assets/js/lib/rollout.js';
import { sanitizePart } from '../../assets/js/lib/workspace.js';
import { toCsv } from '../../assets/js/lib/export.js';

const FP_A = 'aa'.repeat(32);
const FP_B = 'bb'.repeat(32);
const FP_C = 'cc'.repeat(32);
const ID = boardId([FP_A]);
const BOARD = { id: ID, label: '*.example.com' };
const clock = (iso) => () => Date.parse(iso);

/** A finished single-certificate scan: web01 and web02 need it, db01 only by an origin hint. */
const RESULT = {
  hosts: [
    { name: 'www.example.com', cert: { covered: true } },
    { name: 'api.example.com', cert: { covered: true } },
    { name: 'old.example.org', cert: { covered: false } },
    { name: 'shop.example.com', cert: { covered: true } },
    { name: 'look.example.com', cert: { covered: true }, wildcardSuspect: true }
  ],
  servers: [
    { server: { id: 'web01', name: 'web01', ips: ['192.0.2.10', '2001:db8::10'], ports: { '192.0.2.10': [443, 8443] } }, needsCert: true,
      hosts: [{ name: 'www.example.com', ip: '192.0.2.10', covered: true, via: 'dns' }, { name: 'www.example.com', ip: '2001:db8::10', covered: true, via: 'dns' },
        { name: 'old.example.org', ip: '192.0.2.10', covered: false, via: 'dns' }] },
    { server: { id: 'web02', name: 'web02', ips: ['192.0.2.20'], tlsPorts: [9443] }, needsCert: true,
      hosts: [{ name: 'api.example.com', ip: '192.0.2.20', covered: true, via: 'zone' }, { name: 'api.example.com', ip: '192.0.2.20', port: 4443, covered: true, via: 'known' }] },
    { server: { id: 'db01', name: 'db01', ips: ['192.0.2.30'] }, needsCert: false, maybeNeedsCert: true,
      hosts: [{ name: 'www.example.com', ip: '192.0.2.30', covered: true, via: 'hint' }] },
    { server: { id: 'app01', name: 'app01', ips: ['192.0.2.40'], terminatesTls: false }, needsCert: true,
      hosts: [{ name: 'shop.example.com', ip: '192.0.2.40', covered: true, via: 'dns' }] }
  ],
  unmatchedIps: [
    { ip: '198.51.100.7', hosts: ['shop.example.com'], private: false },
    { ip: '198.51.100.8', hosts: ['old.example.org', 'look.example.com'], private: false }
  ]
};

describe('board and set ids', () => {
  test('the leaf fingerprints, lowercase, sorted, unique; nothing valid → null', () => {
    assert.equal(boardId([FP_B, FP_A.toUpperCase(), FP_B]), `${FP_A},${FP_B}`);
    assert.equal(boardId(['AA:'.repeat(31) + 'AA']), FP_A);
    assert.equal(boardId(['nope']), null);
    assert.equal(boardId(null), null);
    assert.equal(setKey([FP_B, FP_A]), `${FP_A.slice(0, 16)}+${FP_B.slice(0, 16)}`);
  });
});

describe('rolloutRows', () => {
  test('one certificate: the servers that need it (no hint-only, no terminates_tls=no), then covered addresses outside the inventory', () => {
    const rows = rolloutRows(RESULT);
    assert.deepEqual(rows.map((r) => r.key), ['s:web01', 's:web02', 'ip:198.51.100.7']);
    assert.deepEqual(rows[0].names, ['www.example.com'], 'only the covered names');
    assert.deepEqual(rows[0].targets, [{ ip: '192.0.2.10', port: 443 }, { ip: '192.0.2.10', port: 8443 }, { ip: '2001:db8::10', port: 443 }],
      'the address ports from the inventory, 443 otherwise');
    assert.deepEqual(rows[1].targets, [{ ip: '192.0.2.20', port: 9443 }, { ip: '192.0.2.20', port: 4443 }], 'tls ports; a remembered origin keeps its port');
    assert.deepEqual(rows[2], { key: 'ip:198.51.100.7', server: null, ip: '198.51.100.7', private: false, set: null, names: ['shop.example.com'], targets: [{ ip: '198.51.100.7', port: 443 }] });
    assert.deepEqual(rolloutRows(null), []);
  });

  test('several certificates: one row per server and set of the plan, keyed by the set fingerprints, hints left out', () => {
    const plan = {
      sets: [{ id: 'A' }, { id: 'B' }],
      rows: [
        { key: 's:web01', server: { id: 'web01', name: 'web01', ips: ['192.0.2.10'] }, ip: null, private: false, needsCert: true,
          cells: { A: [{ name: 'www.example.com', ips: ['192.0.2.10'], via: 'dns' }], B: [{ name: 'www.example.net', ips: ['192.0.2.10'], via: 'dns' }] } },
        { key: 'ip:198.51.100.9', server: null, ip: '198.51.100.9', private: false, needsCert: true,
          cells: { A: [], B: [{ name: 'api.example.net', ips: ['198.51.100.9'], via: 'dns' }, { name: 'x.example.net', ips: ['198.51.100.9'], via: 'hint' }] } },
        { key: 's:db01', server: { id: 'db01', name: 'db01', ips: ['192.0.2.30'] }, needsCert: false, cells: { A: [{ name: 'a.example.com', ips: ['192.0.2.30'], via: 'hint' }] } }
      ]
    };
    const keys = new Map([['A', setKey([FP_A])], ['B', setKey([FP_B, FP_C])]]);
    const rows = rolloutRows({}, { plan, setKeys: keys });
    assert.deepEqual(rows.map((r) => [r.key, r.set]), [[`s:web01#${keys.get('A')}`, 'A'], [`s:web01#${keys.get('B')}`, 'B'], [`ip:198.51.100.9#${keys.get('B')}`, 'B']]);
    assert.deepEqual(rows[2].names, ['api.example.net']);
    assert.equal(rows[2].server, null);
    assert.equal(rows[2].ip, '198.51.100.9');
  });
});

describe('the stored checklist', () => {
  const rows = rolloutRows(RESULT);

  test('a tick ticks the earlier steps, an untick the later ones; the board is created on the first tick', () => {
    let s = setStep(emptyRollout(), BOARD, rows[0], 'reloaded', true, { now: clock('2026-10-08T09:00:00Z') });
    const b = findBoard(s, ID);
    assert.equal(b.label, '*.example.com');
    assert.deepEqual(b.rows, [{ k: 's:web01', n: 'web01', s: null, i: '2026-10-08T09:00:00.000Z', r: '2026-10-08T09:00:00.000Z', v: null, a: null, m: '2026-10-08T09:00:00.000Z' }]);
    s = setStep(s, BOARD, rows[0], 'verified', true, { now: clock('2026-10-08T10:00:00Z') });
    assert.equal(findBoard(s, ID).rows[0].i, '2026-10-08T09:00:00.000Z', 'an earlier tick keeps its time');
    assert.equal(findBoard(s, ID).rows[0].v, '2026-10-08T10:00:00.000Z');
    s = setStep(s, BOARD, rows[0], 'installed', false, { now: clock('2026-10-08T11:00:00Z') });
    const r = findBoard(s, ID).rows[0];
    assert.deepEqual([r.i, r.r, r.v], [null, null, null]);
    assert.equal(setStep(emptyRollout(), BOARD, rows[0], 'installed', false).boards.length, 0, 'an untick creates nothing');
    assert.equal(setStep(emptyRollout(), BOARD, rows[0], 'shipped', true).boards.length, 0, 'unknown step');
    assert.equal(setStep(emptyRollout(), { id: 'nope' }, rows[0], 'installed', true).boards.length, 0, 'no valid board id');
  });

  test('serialize → parse is lossless; the workspace part keeps the text whole or not at all', () => {
    let s = setStep(emptyRollout(), BOARD, rows[0], 'installed', true, { now: clock('2026-10-08T09:00:00Z') });
    s = setStep(s, BOARD, rows[2], 'verified', true, { now: clock('2026-10-08T09:05:00Z') });
    const text = serializeRollout(s);
    assert.deepEqual(parseRollout(text), s);
    assert.equal(sanitizePart('rollout', text), text);
    assert.equal(sanitizePart('rollout', 'x'.repeat(ROLLOUT_LIMITS.chars)).length, ROLLOUT_LIMITS.chars);
    assert.equal(sanitizePart('rollout', 'x'.repeat(ROLLOUT_LIMITS.chars + 1)), '', 'too long: dropped, never cut into broken JSON');
    assert.equal(sanitizePart('rollout', { v: 1 }), '');
    assert.equal(serializeRollout(emptyRollout()), '', 'no board: an empty part (not stored)');
  });

  test('parse checks every field: junk, other versions, bad ids, bad dates and duplicate rows are left out', () => {
    assert.deepEqual(parseRollout('{'), emptyRollout());
    assert.deepEqual(parseRollout('{"v":2,"boards":[]}'), emptyRollout());
    assert.deepEqual(parseRollout(null), emptyRollout());
    const s = parseRollout(JSON.stringify({
      v: 1,
      boards: [
        { id: 'not-a-fingerprint', rows: [{ k: 'x' }] },
        { id: ID, label: 'L\u0000abel', created: 'yesterday', updated: '2026-10-08T09:00:00Z',
          rows: [{ k: 's:web01', n: 'web01', i: '2026-10-08T09:00:00Z', r: 'soon', v: null, a: 'verify', m: 7 }, { k: 's:web01', i: '2026-10-08T10:00:00Z' }, { n: 'no key' }, 'row'] }
      ]
    }));
    assert.equal(s.boards.length, 1);
    assert.equal(s.boards[0].label, 'L abel');
    assert.equal(s.boards[0].created, '2026-10-08T09:00:00.000Z', 'an unreadable created date takes the updated one');
    assert.deepEqual(s.boards[0].rows, [{ k: 's:web01', n: 'web01', s: null, i: '2026-10-08T09:00:00.000Z', r: null, v: null, a: null, m: null }]);
  });

  test('at most ROLLOUT_LIMITS.boards boards, the most recently changed first; the stored text fits the limit', () => {
    let s = emptyRollout();
    for (let i = 0; i < ROLLOUT_LIMITS.boards + 3; i++) {
      const fp = i.toString(16).padStart(2, '0').repeat(32);
      s = setStep(s, { id: fp }, rows[0], 'installed', true, { now: () => Date.parse('2026-10-01T00:00:00Z') + i * 1000 });
    }
    assert.equal(s.boards.length, ROLLOUT_LIMITS.boards);
    assert.equal(s.boards[0].id, (ROLLOUT_LIMITS.boards + 2).toString(16).padStart(2, '0').repeat(32), 'the newest first');
    // One huge board: its last rows are cut so the text fits.
    const big = { v: 1, boards: [{ id: ID, label: '', created: '2026-10-01T00:00:00.000Z', updated: '2026-10-01T00:00:00.000Z',
      rows: Array.from({ length: ROLLOUT_LIMITS.rows }, (_, i) => ({ k: `s:${'n'.repeat(200)}${i}`, n: 'n'.repeat(200), i: '2026-10-01T00:00:00.000Z' })) }] };
    const text = serializeRollout(big);
    assert.ok(text.length <= ROLLOUT_LIMITS.chars && text.length > ROLLOUT_LIMITS.chars / 2, `${text.length}`);
    assert.ok(parseRollout(text).boards[0].rows.length < ROLLOUT_LIMITS.rows);
  });

  test('reset removes the board', () => {
    const s = setStep(emptyRollout(), BOARD, rows[0], 'installed', true);
    assert.deepEqual(resetBoard(s, ID), emptyRollout());
  });
});

describe('the Verify tab', () => {
  const rows = rolloutRows(RESULT);
  const vrow = (server, ip, status, at, extra = {}) => ({ server: server ? { id: server, name: server } : null, alsoServers: [], ip, port: 443,
    state: 'done', status, checkedAt: new Date(at), ...extra });

  test('verifyStatus: confirmed only when every check of the server saw the new certificate', () => {
    const st = verifyStatus([
      vrow('web01', '192.0.2.10', 'UPDATED', '2026-10-08T12:00:00Z'), vrow('web01', '2001:db8::10', 'UPDATED', '2026-10-08T12:01:00Z'),
      vrow('web02', '192.0.2.20', 'UPDATED', '2026-10-08T12:00:00Z'), vrow('web02', '192.0.2.20', 'NEEDS_UPDATE', '2026-10-08T12:00:00Z'),
      vrow(null, '198.51.100.7', 'NEEDS_UPDATE', '2026-10-08T12:00:00Z'),
      { ...vrow('web01', '192.0.2.10', null, '2026-10-08T12:00:00Z'), state: 'pending' }
    ], rows);
    assert.deepEqual(st.get('s:web01'), { status: 'confirmed', at: '2026-10-08T12:01:00.000Z', updated: 2, checked: 2 });
    assert.equal(st.get('s:web02').status, 'mixed');
    assert.equal(st.get('ip:198.51.100.7').status, 'old');
    assert.equal(verifyStatus([vrow('web01', '192.0.2.10', 'TLS_ERROR', '2026-10-08T12:00:00Z')], rows).get('s:web01').status, 'other');
    assert.equal(verifyStatus([], rows).get('s:web01').status, 'unchecked');
    // The server shares the address with another one: alsoServers counts too.
    const shared = verifyStatus([vrow('web09', '192.0.2.10', 'UPDATED', '2026-10-08T12:00:00Z', { alsoServers: [{ id: 'web01', name: 'web01' }] })], rows);
    assert.equal(shared.get('s:web01').status, 'confirmed');
    for (const v of st.values()) assert.ok(ROLLOUT_VERIFY.includes(v.status));
  });

  test('verifyStatus with sets: only the checks of the row\'s set', () => {
    const setRows = [{ key: 's:web01#a', server: { id: 'web01', name: 'web01', ips: [] }, ip: null, set: 'A', names: [], targets: [] }];
    const st = verifyStatus([vrow('web01', '192.0.2.10', 'UPDATED', '2026-10-08T12:00:00Z', { setId: 'A' }),
      vrow('web01', '192.0.2.10', 'NEEDS_UPDATE', '2026-10-08T12:00:00Z', { setId: 'B' })], setRows);
    assert.equal(st.get('s:web01#a').status, 'confirmed');
  });

  test('applyVerify: a confirmed row is marked verified (with the earlier steps), unless the user changed it after the check', () => {
    let s = setStep(emptyRollout(), BOARD, rows[1], 'installed', true, { now: clock('2026-10-08T13:00:00Z') });
    const st = new Map([
      ['s:web01', { status: 'confirmed', at: '2026-10-08T12:00:00.000Z' }],
      ['s:web02', { status: 'confirmed', at: '2026-10-08T12:00:00.000Z' }]
    ]);
    const out = applyVerify(s, BOARD, rows, st);
    assert.deepEqual(out.marked, ['s:web01'], 'web02 was ticked by the user after that check');
    const web01 = findBoard(out.state, ID).rows.find((r) => r.k === 's:web01');
    assert.deepEqual(web01, { k: 's:web01', n: 'web01', s: null, i: '2026-10-08T12:00:00.000Z', r: '2026-10-08T12:00:00.000Z', v: '2026-10-08T12:00:00.000Z', a: 'verify', m: null });
    // Applying the same statuses again changes nothing.
    assert.deepEqual(applyVerify(out.state, BOARD, rows, st).marked, []);
    // The user unticks it: a check from before stays ignored, a newer one marks it again.
    s = setStep(out.state, BOARD, rows[0], 'verified', false, { now: clock('2026-10-08T14:00:00Z') });
    assert.deepEqual(applyVerify(s, BOARD, rows, st).marked, []);
    assert.deepEqual(applyVerify(s, BOARD, rows, new Map([['s:web01', { status: 'confirmed', at: '2026-10-08T15:00:00.000Z' }]])).marked, ['s:web01']);
  });

  test('applyVerify: a newer check that sees the old certificate unmarks what Verify marked, never a tick of the user', () => {
    const first = applyVerify(emptyRollout(), BOARD, rows, new Map([['s:web01', { status: 'confirmed', at: '2026-10-08T12:00:00.000Z' }]])).state;
    const s = setStep(first, BOARD, rows[1], 'verified', true, { now: clock('2026-10-08T12:30:00Z') });
    const old = new Map([['s:web01', { status: 'old', at: '2026-10-08T13:00:00.000Z' }], ['s:web02', { status: 'old', at: '2026-10-08T13:00:00.000Z' }]]);
    const out = applyVerify(s, BOARD, rows, old);
    assert.deepEqual(out.unmarked, ['s:web01']);
    const b = findBoard(out.state, ID);
    assert.equal(b.rows.find((r) => r.k === 's:web01').v, null);
    assert.equal(b.rows.find((r) => r.k === 's:web01').i, '2026-10-08T12:00:00.000Z', 'installed and reloaded stay');
    assert.equal(b.rows.find((r) => r.k === 's:web02').v, '2026-10-08T12:30:00.000Z', 'the user\'s tick stays');
  });
});

describe('the board as shown', () => {
  const rows = rolloutRows(RESULT);

  test('boardRows: the scan rows with their ticks, then stored rows the scan did not find; progress counts', () => {
    let s = setStep(emptyRollout(), BOARD, rows[0], 'verified', true, { now: clock('2026-10-08T09:00:00Z') });
    s = setStep(s, BOARD, { key: 's:web07', name: 'web07' }, 'installed', true, { now: clock('2026-10-08T09:10:00Z') });
    s = applyVerify(s, BOARD, rows, new Map([['s:web02', { status: 'confirmed', at: '2026-10-08T09:20:00.000Z' }]])).state;
    const view = boardRows(s, ID, rows, new Map([['s:web02', { status: 'confirmed', at: '2026-10-08T09:20:00.000Z' }]]));
    assert.deepEqual(view.map((r) => [r.key, r.stage, r.verifiedBy, r.saved]), [
      ['s:web01', 'verified', 'manual', false], ['s:web02', 'verified', 'verify', false], ['ip:198.51.100.7', 'todo', null, false], ['s:web07', 'installed', null, true]
    ]);
    assert.equal(view[3].name, 'web07');
    assert.equal(view[1].verify.status, 'confirmed');
    assert.deepEqual(rolloutProgress(view), { total: 4, installed: 3, reloaded: 2, verified: 2, auto: 1, todo: 1 });
    for (const r of view) assert.ok(ROLLOUT_STAGES.includes(r.stage));
    assert.deepEqual(boardRows(emptyRollout(), null, rows).map((r) => r.stage), ['todo', 'todo', 'todo']);
  });

  test('CSV: one line per row, the columns in order, values from DNS made safe for spreadsheets', () => {
    const s = setStep(emptyRollout(), BOARD, rows[0], 'reloaded', true, { now: clock('2026-10-08T09:00:00Z') });
    const view = boardRows(s, ID, [...rows, { key: 'ip:198.51.100.99', server: null, ip: '198.51.100.99', set: null, names: ['=cmd|x.example.com'], targets: [] }]);
    const csv = toCsv(rolloutCsvRows(view), ROLLOUT_CSV_COLUMNS, { bom: false });
    const lines = csv.trim().split('\r\n');
    assert.equal(lines[0], ROLLOUT_CSV_COLUMNS.map((c) => c.header).join(','));
    assert.equal(lines[1], 'web01,,,192.0.2.10:443 192.0.2.10:8443 [2001:db8::10]:443,www.example.com,reloaded,2026-10-08T09:00:00.000Z,2026-10-08T09:00:00.000Z,,,');
    assert.ok(lines[4].includes("'=cmd|x.example.com"), lines[4]);
    assert.equal(lines.length, 5);
    assert.deepEqual(ROLLOUT_STEPS, ['installed', 'reloaded', 'verified']);
  });
});
