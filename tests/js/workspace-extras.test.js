/**
 * Workspace extras: the `watchlist` part (lib/watchlist.js), the workspace colour (lib/wscolor.js,
 * `color` in the meta) and the switcher's attention count (lib/wsattention.js). No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { sanitizeWatchlist, watchlistCoverage, WATCHLIST_MAX } from '../../assets/js/lib/watchlist.js';
import { WORKSPACE_COLORS, WORKSPACE_COLOR_IDS, sanitizeColor } from '../../assets/js/lib/wscolor.js';
import { attentionCount } from '../../assets/js/lib/wsattention.js';
import { emptyRdapSeen, updateRdapSeen, rdapSeenText, registrationSnapshot } from '../../assets/js/lib/regwatch.js';
import { addWaiver, waiversPartText } from '../../assets/js/lib/waivers.js';
import {
  WORKSPACE_PARTS, sanitizePart, sanitizeWorkspaceData, createWorkspaceStore, createMemoryBackend
} from '../../assets/js/lib/workspace.js';
import { exportWorkspaceFile, openWorkspaceFile, workspacePayload } from '../../assets/js/lib/handover.js';
import { MIN_ITERATIONS } from '../../assets/js/lib/cryptobox.js';

const NOW = Date.parse('2026-10-15T10:00:00Z');
const DAY = 86400000;

describe('watchlist part', () => {
  test('domains only: hosts reduce to their domain, addresses and junk drop, duplicates go, order stays', () => {
    assert.deepEqual(sanitizeWatchlist('example.com\nwww.example.org, example.com ; 192.0.2.1 # note\nnot a name'), ['example.com', 'example.org']);
    assert.deepEqual(sanitizeWatchlist(['EXAMPLE.net', 7, null, 'example.net', 'mail.example.com']), ['example.net', 'example.com']);
    assert.deepEqual(sanitizeWatchlist(undefined), []);
    assert.deepEqual(sanitizeWatchlist({}), []);
  });

  test('capped', () => {
    const many = Array.from({ length: WATCHLIST_MAX + 20 }, (_, i) => `site${i}.example`);
    assert.equal(sanitizeWatchlist(many).length, WATCHLIST_MAX);
  });

  test('it is a workspace part, last, empty by default, and travels in the hand-over file (older files without it still open)', async () => {
    assert.equal(WORKSPACE_PARTS.at(-1), 'watchlist');
    assert.deepEqual(sanitizePart('watchlist'), []);
    const data = sanitizeWorkspaceData({ watchlist: ['example.com', 'example.org'], notes: 'n' });
    assert.deepEqual(data.watchlist, ['example.com', 'example.org']);
    const payload = workspacePayload({ name: 'Acme', data });
    assert.deepEqual(payload.parts.watchlist, ['example.com', 'example.org']);
    const text = await exportWorkspaceFile({ name: 'Acme', data }, { password: 'a long enough pass', iterations: MIN_ITERATIONS });
    const back = await openWorkspaceFile(text, { password: 'a long enough pass' });
    assert.deepEqual(back.data.watchlist, ['example.com', 'example.org']);
    // a file from before the part existed
    const old = JSON.stringify({ format: 'domainscope-workspace', v: 1, encrypted: false, workspace: { name: 'Old', default: false, parts: { notes: 'x' } } });
    assert.deepEqual((await openWorkspaceFile(old)).data.watchlist, []);
  });

  test('it is saved and loaded by the store like the other parts', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = createWorkspaceStore({ backend });
    await store.open();
    await store.save('watchlist', 'example.com\nexample.org');
    await store.idle();
    assert.deepEqual(store.data.watchlist, ['example.com', 'example.org']);
    const again = createWorkspaceStore({ backend });
    await again.open();
    assert.deepEqual(again.data.watchlist, ['example.com', 'example.org']);
  });

  test('coverage: the listed domains the baseline checked in the last 7 days', () => {
    const snap = registrationSnapshot({ registration: { state: 'ok', registrar: 'R', ianaId: '1', expires: '2028-01-01T00:00:00Z', statuses: [], nameservers: [] } });
    let seen = updateRdapSeen(emptyRdapSeen(), [{ domain: 'example.com', snapshot: snap }, { domain: 'example.net', snapshot: snap }], { now: NOW - 2 * DAY });
    seen = updateRdapSeen(seen, [{ domain: 'example.org', snapshot: snap }], { now: NOW - 20 * DAY });
    const list = ['example.com', 'example.org', 'example.edu', 'example.net'];
    seen = rdapSeenText(seen);
    assert.deepEqual(watchlistCoverage(list, seen, NOW), { total: 4, checked: 2, days: 7 });
    assert.deepEqual(watchlistCoverage([], seen, NOW), { total: 0, checked: 0, days: 7 });
    assert.deepEqual(watchlistCoverage(list, 'not json', NOW), { total: 4, checked: 0, days: 7 });
  });
});

describe('workspace colour', () => {
  const lum = (hex) => {
    const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
  };
  const ratio = (a, b) => {
    const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
    return (hi + 0.05) / (lo + 0.05);
  };

  test('a fixed palette: every colour has 3:1 against its surface in light and in dark', () => {
    assert.equal(WORKSPACE_COLORS.length, 8);
    for (const c of WORKSPACE_COLORS) {
      assert.ok(ratio(c.light, '#ffffff') >= 3, `${c.id} light`);
      assert.ok(ratio(c.dark, '#151a21') >= 3, `${c.id} dark`);
    }
  });

  test('style.css carries the same values as --wsc-<id> in light and in both dark blocks', () => {
    const css = readFileSync(new URL('../../assets/css/style.css', import.meta.url), 'utf8');
    for (const c of WORKSPACE_COLORS) {
      assert.equal(css.split(`--wsc-${c.id}: ${c.light};`).length - 1, 1, `${c.id} light`);
      assert.equal(css.split(`--wsc-${c.id}: ${c.dark};`).length - 1, 2, `${c.id} dark`);
    }
  });

  test('only a palette id is a colour', () => {
    assert.equal(sanitizeColor('blue'), 'blue');
    for (const bad of ['#fff', 'red; x', 'Blue', '', null, 5, undefined]) assert.equal(sanitizeColor(bad), null);
    assert.deepEqual([...WORKSPACE_COLOR_IDS], WORKSPACE_COLORS.map((c) => c.id));
  });

  test('the store keeps it in the meta: set, cleared, kept through renames and writes, ignored when invalid, set at create', async () => {
    const backend = createMemoryBackend([], { persistent: true });
    const store = createWorkspaceStore({ backend });
    await store.open();
    const { meta } = await store.create('Acme', null, 'teal');
    assert.equal(meta.color, 'teal');
    await store.rename(meta.id, 'Acme Ltd');
    await store.switchTo(meta.id);
    await store.save('notes', 'x');
    await store.idle();
    assert.equal(store.list().find((m) => m.id === meta.id).color, 'teal');
    let reopened = createWorkspaceStore({ backend });
    await reopened.open();
    assert.equal(reopened.list().find((m) => m.id === meta.id).color, 'teal');
    assert.equal(reopened.list().find((m) => m.id === meta.id).name, 'Acme Ltd');
    await store.setColor(meta.id, 'nonsense');
    assert.equal('color' in store.list().find((m) => m.id === meta.id), false);
    await store.setColor(meta.id, 'red');
    await store.setColor('default', 'gray');
    reopened = createWorkspaceStore({ backend });
    await reopened.open();
    assert.equal(reopened.list().find((m) => m.id === meta.id).color, 'red');
    assert.equal(reopened.list().find((m) => m.id === 'default').color, 'gray');
    await assert.rejects(() => store.setColor('ws-missing', 'red'));
  });

  test('older records have no colour; the hand-over file carries it when set and an older file imports without it', async () => {
    const p = workspacePayload({ name: 'Acme', color: 'blue', data: {} });
    assert.equal(p.color, 'blue');
    assert.equal('color' in workspacePayload({ name: 'Acme', data: {} }), false);
    const text = await exportWorkspaceFile({ name: 'Acme', color: 'blue', data: {} });
    assert.equal((await openWorkspaceFile(text)).color, 'blue');
    const old = JSON.stringify({ format: 'domainscope-workspace', v: 1, encrypted: false, workspace: { name: 'Old', parts: {} } });
    assert.equal((await openWorkspaceFile(old)).color, null);
  });
});

describe('attention count', () => {
  const snap = (expires) => registrationSnapshot({ registration: { state: 'ok', registrar: 'R', ianaId: '1', expires, statuses: ['client transfer prohibited'], nameservers: ['ns1.example.net'] } });
  const rdap = (...rows) => rdapSeenText(updateRdapSeen(emptyRdapSeen(), rows.map(([domain, expires]) => ({ domain, snapshot: snap(expires) })), { now: NOW - DAY }));

  test('a calm or empty workspace counts 0', () => {
    assert.equal(attentionCount({}, NOW), 0);
    assert.equal(attentionCount(null, NOW), 0);
    assert.equal(attentionCount({ rdapSeen: rdap(['example.com', '2028-01-01T00:00:00Z']) }, NOW), 0);
  });

  test('registrations running out and waivers ending count, as Home counts them; the result is a number, never a name', () => {
    const rdapSeen = rdap(['example.com', '2026-10-25T00:00:00Z'], ['example.org', '2026-10-20T00:00:00Z'], ['example.net', '2028-01-01T00:00:00Z']);
    assert.equal(attentionCount({ rdapSeen }, NOW), 2);
    const { list } = addWaiver([], { kind: 'rule', domain: 'example.net', ref: 'dnssec', reason: 'next quarter', expires: '2026-10-18' }, { now: NOW });
    const n = attentionCount({ rdapSeen, waivers: waiversPartText(list) }, NOW);
    assert.equal(typeof n, 'number');
    assert.ok(n >= 3);
  });

  test('ignores the parts it does not read', () => {
    assert.equal(attentionCount({ notes: 'example.com is on fire', watchlist: ['example.com'], rollout: 'x' }, NOW), 0);
  });
});
