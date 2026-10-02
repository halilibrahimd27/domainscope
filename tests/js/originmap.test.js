/**
 * The origin map (lib/originmap.js, the model, and lib/originfill.js, its merge rules): what an
 * entry may hold, the caps, the opt-in (nothing written while it is off), confirmations, entries
 * added only for proxied names, stale marks from a later contradicting run (CLI JSON, Verify, a
 * zone) and never from an older one, a comparison or a manual entry; edits by hand; the scan's
 * known origins; and the map as a workspace part (the store, the hand-over file, "Delete all
 * local data"). Example names and documentation addresses only. No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  sanitizeOriginMap, originsFor, knownForScan, originKey, originTarget, originName, originPort,
  ORIGIN_MAP_LIMITS, ORIGIN_SOURCES, STALE_REASONS
} from '../../assets/js/lib/originmap.js';
import { applyObservations, addManualOrigin, removeOrigins, setRemember } from '../../assets/js/lib/originfill.js';
import { createWorkspaceStore, createMemoryBackend, WORKSPACE_PARTS, sanitizePart } from '../../assets/js/lib/workspace.js';
import { exportWorkspaceFile, openWorkspaceFile } from '../../assets/js/lib/handover.js';
import { MIN_ITERATIONS } from '../../assets/js/lib/cryptobox.js';

const DAY1 = '2026-09-20T08:00:00.000Z';
const DAY2 = '2026-09-25T08:00:00.000Z';
const DAY3 = '2026-10-01T08:00:00.000Z';
const ON = setRemember(null, true);
const hosted = (name, ip, port = 443, server = null) => ({ name, ip, port, outcome: 'hosted', server });
const notHosted = (name, ip, port = 443) => ({ name, ip, port, outcome: 'not-hosted' });
const unknown = (name, ip, port = 443) => ({ name, ip, port, outcome: 'unknown' });
const keys = (map) => map.entries.map(originKey);
const entry = (map, key) => map.entries.find((e) => originKey(e) === key);

describe('the model', () => {
  test('an empty map with remembering off is no part at all; switched on, it is stored', () => {
    assert.equal(sanitizeOriginMap(null), null);
    assert.equal(sanitizeOriginMap({ v: 1, remember: false, entries: [] }), null, 'off and empty: nothing to store');
    assert.equal(sanitizeOriginMap([]), null);
    assert.deepEqual(ON, { v: 1, remember: true, entries: [] });
    assert.equal(setRemember(ON, false), null, 'off again, nothing left');
  });

  test('every entry is checked: names, addresses, ports, sources, dates, server names, stale marks', () => {
    const map = sanitizeOriginMap({
      remember: true,
      entries: [
        { name: 'Shop.Example.COM.', ip: '203.0.113.10', port: 443, source: 'cli-json', lastConfirmed: DAY2, firstSeen: DAY1, server: ` web03${String.fromCharCode(7)} ` },
        { name: '*.apps.example.com', ip: '2001:DB8::0:10', port: '8443', source: 'nope', lastConfirmed: DAY2 },
        { name: 'bad name!', ip: '203.0.113.11', lastConfirmed: DAY2 },
        { name: 'www.example.com', ip: 'not-an-ip', lastConfirmed: DAY2 },
        { name: 'www.example.com', ip: '203.0.113.12', port: 70000, lastConfirmed: DAY2 },
        { name: 'www.example.com', ip: '203.0.113.13', lastConfirmed: 'yesterday' },
        { name: 'api.example.com', ip: '203.0.113.14', lastConfirmed: DAY1, firstSeen: DAY3, stale: { reason: 'made-up', at: DAY2 } },
        { name: 'cdn.example.com', ip: '203.0.113.15', lastConfirmed: DAY1, stale: { reason: 'cli-elsewhere', at: DAY2, ip: '203.0.113.16', port: 8443 } }
      ]
    });
    const by = (name) => map.entries.find((e) => e.name === name);
    assert.deepEqual(map.entries.map((e) => e.name), ['*.apps.example.com', 'api.example.com', 'cdn.example.com', 'shop.example.com']);
    assert.deepEqual(by('shop.example.com'), {
      name: 'shop.example.com', ip: '203.0.113.10', port: 443, source: 'cli-json', firstSeen: DAY1, lastConfirmed: DAY2, server: 'web03', stale: null
    }, 'name normalised, controls removed from the server name');
    const a = by('*.apps.example.com');
    assert.deepEqual([a.ip, a.port, a.source, a.firstSeen], ['2001:db8::10', 8443, 'manual', DAY2], 'canonical address, numeric port, unknown source: manual');
    assert.equal(by('api.example.com').stale, null, 'an unknown stale reason is dropped');
    assert.equal(by('api.example.com').firstSeen, DAY1, 'first seen never after last confirmed');
    assert.deepEqual(by('cdn.example.com').stale, { reason: 'cli-elsewhere', at: DAY2, ip: '203.0.113.16', port: 8443 });
  });

  test('one entry per name, address and port: the latest confirmation wins', () => {
    const map = sanitizeOriginMap({
      remember: true,
      entries: [
        { name: 'shop.example.com', ip: '203.0.113.10', lastConfirmed: DAY1, source: 'zone' },
        { name: 'shop.example.com', ip: '203.0.113.10', port: 443, lastConfirmed: DAY3, source: 'verify' },
        { name: 'shop.example.com', ip: '203.0.113.10', port: 8443, lastConfirmed: DAY2, source: 'manual' }
      ]
    });
    assert.deepEqual(map.entries.map((e) => `${originTarget(e)} ${e.source}`), ['203.0.113.10 verify', '203.0.113.10:8443 manual']);
  });

  test('caps: per name and in all, active and recent entries are kept first', () => {
    const many = [];
    for (let i = 0; i < ORIGIN_MAP_LIMITS.perName + 4; i += 1) {
      many.push({ name: 'pool.example.com', ip: `198.51.100.${i + 1}`, lastConfirmed: new Date(Date.parse(DAY1) + i * 1000).toISOString(),
        stale: i === 30 ? { reason: 'cli-not-hosted', at: DAY3 } : null });
    }
    many[ORIGIN_MAP_LIMITS.perName + 3].stale = { reason: 'cli-not-hosted', at: DAY3 };
    const pool = sanitizeOriginMap({ remember: true, entries: many });
    assert.equal(pool.entries.length, ORIGIN_MAP_LIMITS.perName);
    assert.ok(pool.entries.every((e) => !e.stale), 'the stale one went first, although it is the newest');
    assert.ok(!pool.entries.some((e) => e.ip === '198.51.100.1'), 'then the oldest');
    const all = [];
    for (let i = 0; i < ORIGIN_MAP_LIMITS.entries + 50; i += 1) all.push({ name: `h${i}.example.com`, ip: '203.0.113.10', lastConfirmed: DAY2 });
    assert.equal(sanitizeOriginMap({ remember: true, entries: all }).entries.length, ORIGIN_MAP_LIMITS.entries);
  });

  test('a name, a port and a target as the map writes them', () => {
    assert.equal(originName('https://Shop.Example.com:8443/x'), 'shop.example.com');
    assert.equal(originName('*.example.com'), '*.example.com');
    assert.equal(originName('203.0.113.10'), null);
    assert.equal(originPort(''), 443);
    assert.equal(originPort(' 8443 '), 8443);
    assert.equal(originPort('0'), null);
    assert.equal(originPort('443x'), null);
    assert.equal(originTarget({ ip: '203.0.113.10', port: 443 }), '203.0.113.10');
    assert.equal(originTarget({ ip: '203.0.113.10', port: 8443 }), '203.0.113.10:8443');
    assert.equal(originTarget({ ip: '2001:db8::10', port: 8443 }), '[2001:db8::10]:8443');
    assert.deepEqual([...ORIGIN_SOURCES], ['cli-json', 'zone', 'verify', 'compare', 'manual']);
    assert.ok(STALE_REASONS.includes('zone-other'));
  });
});

describe('the merge rules (lib/originfill.js applyObservations)', () => {
  test('remembering off: nothing is added, confirmed or marked stale', () => {
    const off = sanitizeOriginMap({ remember: false, entries: [{ name: 'shop.example.com', ip: '203.0.113.10', lastConfirmed: DAY1 }] });
    const res = applyObservations(off, [hosted('shop.example.com', '198.51.100.20'), hosted('api.example.com', '203.0.113.11')], { source: 'cli-json', at: DAY3 });
    assert.equal(res.off, true);
    assert.deepEqual([res.added, res.confirmed, res.staled], [[], [], []]);
    assert.deepEqual(res.map, off);
    assert.equal(applyObservations(null, [hosted('shop.example.com', '198.51.100.20')], { source: 'zone', at: DAY3 }).map, null);
  });

  test('a run adds what it saw hosted and confirms what the map has', () => {
    let { map, added } = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10', 443, 'web03')], { source: 'cli-json', at: DAY1 });
    assert.deepEqual(added, ['shop.example.com|203.0.113.10|443']);
    assert.deepEqual(map.entries[0], {
      name: 'shop.example.com', ip: '203.0.113.10', port: 443, source: 'cli-json', firstSeen: DAY1, lastConfirmed: DAY1, server: 'web03', stale: null
    });
    let res = applyObservations(map, [hosted('shop.example.com', '203.0.113.10')], { source: 'verify', at: DAY2 });
    assert.deepEqual([res.added, res.confirmed], [[], ['shop.example.com|203.0.113.10|443']]);
    ({ map } = res);
    assert.deepEqual([map.entries[0].source, map.entries[0].firstSeen, map.entries[0].lastConfirmed, map.entries[0].server], ['verify', DAY1, DAY2, 'web03']);
    // An older report still confirms (and moves first seen back), but never moves last confirmed back.
    res = applyObservations(map, [hosted('shop.example.com', '203.0.113.10')], { source: 'cli-json', at: '2026-09-01T00:00:00Z' });
    assert.deepEqual([res.map.entries[0].firstSeen, res.map.entries[0].lastConfirmed, res.map.entries[0].source], ['2026-09-01T00:00:00.000Z', DAY2, 'verify']);
  });

  test('a server name comes from the observation, else the inventory lookup', () => {
    const res = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10')], {
      source: 'zone', at: DAY1, serverOf: (ip) => (ip === '203.0.113.10' ? 'web03' : null)
    });
    assert.equal(res.map.entries[0].server, 'web03');
  });

  test('only names known to be behind a CDN are added; the map\'s own names always count', () => {
    let { map } = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10')], { source: 'cli-json', at: DAY1 });
    const proxied = (name) => name === 'api.example.com';
    const res = applyObservations(map, [
      hosted('shop.example.com', '203.0.113.20'), hosted('api.example.com', '203.0.113.11'), hosted('mail.example.com', '203.0.113.12')
    ], { source: 'cli-json', at: DAY2, proxied });
    assert.deepEqual(res.added.sort(), ['api.example.com|203.0.113.11|443', 'shop.example.com|203.0.113.20|443']);
    assert.deepEqual(res.skipped, ['mail.example.com']);
    ({ map } = res);
    assert.ok(!map.entries.some((e) => e.name === 'mail.example.com'));
  });

  test('stale: the CLI found the name on another server, or no longer at the remembered address', () => {
    let { map } = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10'), hosted('api.example.com', '203.0.113.11')], { source: 'zone', at: DAY1 });
    const res = applyObservations(map, [
      hosted('shop.example.com', '198.51.100.20', 443, 'web05'), notHosted('shop.example.com', '203.0.113.10'),
      notHosted('api.example.com', '203.0.113.11')
    ], { source: 'cli-json', at: DAY3 });
    ({ map } = res);
    assert.deepEqual(res.staled.sort(), ['api.example.com|203.0.113.11|443', 'shop.example.com|203.0.113.10|443']);
    assert.deepEqual(entry(map, 'shop.example.com|203.0.113.10|443').stale, { reason: 'cli-elsewhere', at: DAY3, ip: '198.51.100.20', port: 443 },
      'found elsewhere wins over "not hosted" for the same entry: one mark, the first that applies');
    assert.deepEqual(entry(map, 'api.example.com|203.0.113.11|443').stale, { reason: 'cli-not-hosted', at: DAY3 });
    assert.equal(entry(map, 'shop.example.com|198.51.100.20|443').stale, null);
    assert.equal(entry(map, 'shop.example.com|198.51.100.20|443').server, 'web05');
    // Stale entries are shown (originsFor), never a known origin.
    assert.deepEqual(originsFor(map, 'shop.example.com').map((e) => [e.ip, !!e.stale]), [['198.51.100.20', false], ['203.0.113.10', true]]);
    assert.deepEqual(knownForScan(map).map((k) => `${k.name} ${k.ip}`), ['shop.example.com 198.51.100.20']);
  });

  test('both addresses confirmed by one run (a pool) mark nothing; an unanswered address says nothing', () => {
    let { map } = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10'), hosted('shop.example.com', '203.0.113.20')], { source: 'zone', at: DAY1 });
    let res = applyObservations(map, [hosted('shop.example.com', '203.0.113.10'), hosted('shop.example.com', '203.0.113.20')], { source: 'cli-json', at: DAY2 });
    assert.deepEqual(res.staled, []);
    ({ map } = res);
    res = applyObservations(map, [{ name: 'shop.example.com', ip: '203.0.113.10', port: 443, outcome: 'unknown' }], { source: 'cli-json', at: DAY3 });
    assert.deepEqual([res.added, res.confirmed, res.staled], [[], [], []], 'TIMEOUT / CLOSED / TLS_ERROR change nothing');
  });

  test('a run older than the entry\'s last confirmation never marks it; a newer confirmation clears a mark', () => {
    let { map } = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10')], { source: 'manual', at: DAY2 });
    let res = applyObservations(map, [hosted('shop.example.com', '198.51.100.20')], { source: 'cli-json', at: DAY1 });
    assert.deepEqual(res.staled, [], 'an old report does not overrule a newer confirmation');
    ({ map } = applyObservations(map, [notHosted('shop.example.com', '203.0.113.10')], { source: 'verify', at: DAY3 }));
    assert.equal(entry(map, 'shop.example.com|203.0.113.10|443').stale.reason, 'verify-not-hosted');
    res = applyObservations(map, [hosted('shop.example.com', '203.0.113.10')], { source: 'verify', at: '2026-10-02T08:00:00Z' });
    assert.equal(entry(res.map, 'shop.example.com|203.0.113.10|443').stale, null, 'confirmed again after the mark');
  });

  test('a zone file names no port: the address known on another port gets no 443 entry; another origin there marks the rest zone-other', () => {
    let { map } = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10', 8443), hosted('shop.example.com', '203.0.113.30')], { source: 'cli-json', at: DAY1 });
    const res = applyObservations(map, [{ name: 'shop.example.com', ip: '203.0.113.10', port: null, outcome: 'hosted' }], { source: 'zone', at: DAY2 });
    assert.deepEqual(res.added, [], 'the address is known on 8443: no new 443 entry');
    assert.deepEqual(res.confirmed, [], 'the zone says nothing about port 8443');
    assert.equal(entry(res.map, 'shop.example.com|203.0.113.10|8443').source, 'cli-json');
    assert.deepEqual(res.staled, ['shop.example.com|203.0.113.30|443']);
    ({ map } = res);
    assert.deepEqual(entry(map, 'shop.example.com|203.0.113.30|443').stale, { reason: 'zone-other', at: DAY2, ip: '203.0.113.10', port: 443 });
    const fresh = applyObservations(ON, [{ name: 'www.example.com', ip: '192.0.2.10', port: null, outcome: 'hosted' }], { source: 'zone', at: DAY2 });
    assert.deepEqual(fresh.added, ['www.example.com|192.0.2.10|443'], 'a new zone origin gets port 443');
  });

  test('an entry the run did not ask is never marked "elsewhere" (a pool); one it asked without an answer is', () => {
    let { map } = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10'), hosted('shop.example.com', '203.0.113.30')], { source: 'cli-json', at: DAY1 });
    let res = applyObservations(map, [hosted('shop.example.com', '198.51.100.20')], { source: 'cli-json', at: DAY2 });
    assert.deepEqual([res.added, res.staled], [['shop.example.com|198.51.100.20|443'], []], 'the other two were not asked: still active');
    ({ map } = res);
    res = applyObservations(map, [hosted('shop.example.com', '198.51.100.20'), unknown('shop.example.com', '203.0.113.30')], { source: 'cli-json', at: DAY3 });
    assert.deepEqual(res.staled, ['shop.example.com|203.0.113.30|443']);
    assert.deepEqual(entry(res.map, 'shop.example.com|203.0.113.30|443').stale, { reason: 'cli-elsewhere', at: DAY3, ip: '198.51.100.20', port: 443 });
    assert.equal(entry(res.map, 'shop.example.com|203.0.113.10|443').stale, null, 'still not asked');
  });

  test('found on another port of the same address: the same server, not marked "elsewhere"', () => {
    // Asked on 443 and on 8443: hosted on 443 adds that entry and leaves the 8443 one alone (no
    // answer there); another address of the name asked without an answer is marked.
    let { map } = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10', 8443), hosted('shop.example.com', '203.0.113.30')], { source: 'cli-json', at: DAY1 });
    const res = applyObservations(map, [
      hosted('shop.example.com', '203.0.113.10', 443), unknown('shop.example.com', '203.0.113.10', 8443), unknown('shop.example.com', '203.0.113.30')
    ], { source: 'verify', at: DAY2 });
    assert.deepEqual(res.added, ['shop.example.com|203.0.113.10|443']);
    assert.deepEqual(res.staled, ['shop.example.com|203.0.113.30|443']);
    ({ map } = res);
    assert.equal(entry(map, 'shop.example.com|203.0.113.10|8443').stale, null);
    assert.deepEqual(entry(map, 'shop.example.com|203.0.113.30|443').stale, { reason: 'verify-elsewhere', at: DAY2, ip: '203.0.113.10', port: 443 });
  });

  test('a zone file (no port) never clears what a probe of one port found; a newer zone revives its own zone-other mark', () => {
    const N = 'www.example.com';
    const A = '203.0.113.10';
    const zone = (ip, at) => (map) => applyObservations(map, [{ name: N, ip, port: null, outcome: 'hosted' }], { source: 'zone', at }).map;
    let map = zone(A, DAY1)(ON);
    ({ map } = applyObservations(map, [hosted(N, A, 8443), notHosted(N, A, 443)], { source: 'cli-json', at: DAY2 }));
    assert.deepEqual(entry(map, `${N}|${A}|443`).stale, { reason: 'cli-not-hosted', at: DAY2 });
    const res = applyObservations(map, [{ name: N, ip: A, port: null, outcome: 'hosted' }], { source: 'zone', at: DAY3 });
    assert.deepEqual([res.added, res.confirmed, res.staled], [[], [], []]);
    assert.deepEqual(entry(res.map, `${N}|${A}|443`).stale, { reason: 'cli-not-hosted', at: DAY2 }, 'the port-443 answer stands');
    assert.deepEqual([entry(res.map, `${N}|${A}|8443`).source, entry(res.map, `${N}|${A}|8443`).lastConfirmed], ['cli-json', DAY2], 'port 8443 unchanged');
    // Zone files alone: the newer one decides.
    map = zone('198.51.100.20', DAY2)(zone(A, DAY1)(ON));
    assert.equal(entry(map, `${N}|${A}|443`).stale.reason, 'zone-other');
    map = zone(A, DAY3)(map);
    assert.equal(entry(map, `${N}|${A}|443`).stale, null);
    assert.equal(entry(map, `${N}|198.51.100.20|443`).stale.reason, 'zone-other');
  });

  test('the newest contradiction is kept, and only a newer confirmation clears it: an older report imported late changes nothing', () => {
    const N = 'shop.example.com';
    const [A, B, C] = ['203.0.113.10', '198.51.100.20', '198.51.100.21'];
    let { map } = applyObservations(ON, [{ name: N, ip: A, port: null, outcome: 'hosted' }], { source: 'zone', at: '2026-09-01T00:00:00Z' });
    ({ map } = applyObservations(map, [hosted(N, B), unknown(N, A)], { source: 'verify', at: '2026-09-10T00:00:00Z' }));
    assert.deepEqual(entry(map, `${N}|${A}|443`).stale, { reason: 'verify-elsewhere', at: '2026-09-10T00:00:00.000Z', ip: B, port: 443 });
    // Later the CLI found the name on C, and A answered without it: the newer mark replaces the first.
    let res = applyObservations(map, [hosted(N, C), notHosted(N, A)], { source: 'cli-json', at: '2026-09-30T00:00:00Z' });
    ({ map } = res);
    assert.deepEqual(entry(map, `${N}|${A}|443`).stale, { reason: 'cli-elsewhere', at: '2026-09-30T00:00:00.000Z', ip: C, port: 443 });
    // A report from before that (A served the name on 09-20), imported last: A stays stale.
    res = applyObservations(map, [hosted(N, A)], { source: 'cli-json', at: '2026-09-20T00:00:00Z' });
    ({ map } = res);
    assert.deepEqual(res.confirmed, [`${N}|${A}|443`]);
    assert.equal(entry(map, `${N}|${A}|443`).lastConfirmed, '2026-09-20T00:00:00.000Z');
    assert.equal(entry(map, `${N}|${A}|443`).stale.at, '2026-09-30T00:00:00.000Z', 'the NOT_HOSTED of 09-30 is not undone');
    assert.deepEqual(knownForScan(map).map((k) => k.ip).sort(), [B, C]);
  });

  test('the order reports are imported in does not matter: an entry added from an older run is stale when a newer one found the name elsewhere', () => {
    const N = 'shop.example.com';
    const [A, B] = ['203.0.113.10', '198.51.100.20'];
    const newer = (map) => applyObservations(map, [hosted(N, B), notHosted(N, A)], { source: 'cli-json', at: '2026-10-02T00:00:00Z' }).map;
    const older = (map) => applyObservations(map, [hosted(N, A)], { source: 'cli-json', at: '2026-09-01T00:00:00Z' }).map;
    const newThenOld = older(newer(ON));
    const oldThenNew = newer(older(ON));
    assert.deepEqual(newThenOld, oldThenNew);
    assert.deepEqual(entry(newThenOld, `${N}|${A}|443`).stale, { reason: 'cli-elsewhere', at: '2026-10-02T00:00:00.000Z', ip: B, port: 443 });
    assert.deepEqual(knownForScan(newThenOld).map((k) => k.ip), [B]);
    // A confirmation and a contradiction of the same moment: active, whichever came first.
    const base = applyObservations(ON, [hosted(N, A)], { source: 'cli-json', at: DAY1 }).map;
    const confirm = (map) => applyObservations(map, [hosted(N, A)], { source: 'verify', at: DAY2 }).map;
    const contradict = (map) => applyObservations(map, [hosted(N, B), notHosted(N, A)], { source: 'cli-json', at: DAY2 }).map;
    const one = confirm(contradict(base));
    const two = contradict(confirm(base));
    assert.equal(entry(one, `${N}|${A}|443`).stale, null);
    assert.equal(entry(two, `${N}|${A}|443`).stale, null);
  });

  test('a report dated in the future (a fast clock, an edited file) is applied as now: it pins nothing against today\'s checks', () => {
    const now = Date.parse('2026-10-02T12:00:00.000Z');
    const iso = (ms) => new Date(ms).toISOString();
    const [A, B] = ['203.0.113.10', '198.51.100.20'];
    let { map } = applyObservations(ON, [hosted('api.example.com', A)], { source: 'zone', at: '2026-09-01T00:00:00Z', now });
    ({ map } = applyObservations(map, [hosted('api.example.com', B), notHosted('api.example.com', A)], { source: 'cli-json', at: '2099-01-01T00:00:00Z', now }));
    assert.equal(entry(map, `api.example.com|${B}|443`).lastConfirmed, iso(now));
    assert.equal(entry(map, `api.example.com|${A}|443`).stale.at, iso(now));
    // An hour later Verify finds it on A again, and B answering without it.
    const later = now + 3600e3;
    const res = applyObservations(map, [hosted('api.example.com', A), notHosted('api.example.com', B)], { source: 'verify', at: iso(later - 60e3), now: later });
    assert.deepEqual([res.confirmed, res.staled], [[`api.example.com|${A}|443`], [`api.example.com|${B}|443`]]);
    assert.deepEqual(knownForScan(res.map).map((k) => k.ip), [A]);
  });

  test('stored dates from the future (a hand-over file) are clamped to now', () => {
    const now = Date.parse('2026-10-02T12:00:00.000Z');
    const iso = new Date(now).toISOString();
    const map = sanitizeOriginMap({
      remember: true,
      entries: [
        { name: 'www.example.com', ip: '192.0.2.10', source: 'cli-json', firstSeen: '2099-01-01T00:00:00Z', lastConfirmed: '2099-01-01T00:00:00Z' },
        { name: 'www.example.com', ip: '192.0.2.11', source: 'zone', firstSeen: DAY1, lastConfirmed: DAY1, stale: { reason: 'cli-elsewhere', at: '2099-01-01T00:00:00Z', ip: '192.0.2.10', port: 443 } }
      ]
    }, { now });
    const by = (ip) => map.entries.find((e) => e.ip === ip);
    assert.deepEqual([by('192.0.2.10').firstSeen, by('192.0.2.10').lastConfirmed], [iso, iso]);
    assert.equal(by('192.0.2.11').stale.at, iso);
    // The workspace store reads a part the same way, with the real clock.
    const stored = sanitizePart('origins', { remember: true, entries: [{ name: 'www.example.com', ip: '192.0.2.10', lastConfirmed: '2099-01-01T00:00:00Z' }] });
    assert.ok(Date.parse(stored.entries[0].lastConfirmed) <= Date.now(), stored.entries[0].lastConfirmed);
  });

  test('a stored mark not newer than the last confirmation is dropped', () => {
    const map = sanitizeOriginMap({
      remember: true,
      entries: [
        { name: 'shop.example.com', ip: '203.0.113.10', lastConfirmed: DAY2, stale: { reason: 'cli-not-hosted', at: DAY1 } },
        { name: 'shop.example.com', ip: '203.0.113.11', lastConfirmed: DAY2, stale: { reason: 'cli-not-hosted', at: DAY2 } },
        { name: 'shop.example.com', ip: '203.0.113.12', lastConfirmed: DAY1, stale: { reason: 'cli-not-hosted', at: DAY2 } }
      ]
    });
    assert.deepEqual(map.entries.map((e) => `${e.ip} ${e.stale ? e.stale.reason : '-'}`).sort(), [
      '203.0.113.10 -', '203.0.113.11 -', '203.0.113.12 cli-not-hosted'
    ]);
  });

  test('a comparison or a manual entry never marks another entry stale', () => {
    const { map } = applyObservations(ON, [hosted('shop.example.com', '203.0.113.10')], { source: 'zone', at: DAY1 });
    for (const source of ['compare', 'manual']) {
      const res = applyObservations(map, [hosted('shop.example.com', '198.51.100.20'), notHosted('shop.example.com', '203.0.113.10')], { source, at: DAY3 });
      assert.deepEqual(res.staled, [], source);
      assert.deepEqual(res.added, ['shop.example.com|198.51.100.20|443'], source);
    }
  });

  test('junk observations, an unknown source or no date change nothing', () => {
    const junk = [null, { name: 'bad name', ip: '203.0.113.10', outcome: 'hosted' }, { name: 'a.example.com', ip: 'x', outcome: 'hosted' },
      { name: 'a.example.com', ip: '203.0.113.10', port: 99999, outcome: 'hosted' }, { name: 'a.example.com', ip: '203.0.113.10', outcome: 'maybe' }];
    assert.deepEqual(applyObservations(ON, junk, { source: 'cli-json', at: DAY1 }).added, []);
    assert.deepEqual(applyObservations(ON, [hosted('a.example.com', '203.0.113.10')], { source: 'rumour', at: DAY1 }).added, []);
    assert.deepEqual(applyObservations(ON, [hosted('a.example.com', '203.0.113.10')], { source: 'zone', at: 'soon' }).added, []);
  });
});

describe('edits by hand', () => {
  test('add, confirm, change and delete; refused while off and for bad input', () => {
    assert.equal(addManualOrigin(null, { name: 'shop.example.com', ip: '203.0.113.10' }, { at: DAY1 }).error, 'off');
    for (const [input, error] of [
      [{ name: '', ip: '203.0.113.10' }, 'name'], [{ name: 'shop.example.com', ip: '203.0.113' }, 'ip'],
      [{ name: 'shop.example.com', ip: '203.0.113.10', port: '0' }, 'port']
    ]) assert.equal(addManualOrigin(ON, input, { at: DAY1 }).error, error);
    let res = addManualOrigin(ON, { name: ' Shop.example.com ', ip: '203.0.113.10', port: '' }, { at: DAY1, serverOf: () => 'web03' });
    assert.equal(res.error, null);
    assert.equal(res.key, 'shop.example.com|203.0.113.10|443');
    let { map } = res;
    assert.deepEqual([map.entries[0].source, map.entries[0].server], ['manual', 'web03']);
    // The same key again confirms it (and clears a stale mark).
    ({ map } = applyObservations(map, [hosted('shop.example.com', '198.51.100.20'), notHosted('shop.example.com', '203.0.113.10')], { source: 'cli-json', at: DAY2 }));
    assert.ok(entry(map, res.key).stale);
    ({ map } = addManualOrigin(map, { name: 'shop.example.com', ip: '203.0.113.10' }, { at: DAY3 }));
    assert.equal(entry(map, res.key).stale, null);
    assert.equal(entry(map, res.key).lastConfirmed, DAY3);
    // Change: the replaced entry goes, the new one keeps its own key.
    res = addManualOrigin(map, { name: 'shop.example.com', ip: '203.0.113.10', port: 8443, server: 'web03b' }, { at: DAY3, replace: res.key });
    ({ map } = res);
    assert.deepEqual(keys(map).sort(), ['shop.example.com|198.51.100.20|443', 'shop.example.com|203.0.113.10|8443']);
    assert.equal(entry(map, res.key).server, 'web03b');
    // Delete works with remembering off too.
    map = setRemember(map, false);
    assert.deepEqual(keys(removeOrigins(map, [res.key])), ['shop.example.com|198.51.100.20|443']);
    assert.equal(removeOrigins(map, keys(map)), null, 'off and empty: no part left');
  });

  test('the per-name cap refuses one more by hand', () => {
    let map = ON;
    for (let i = 1; i <= ORIGIN_MAP_LIMITS.perName; i += 1) ({ map } = addManualOrigin(map, { name: 'pool.example.com', ip: `198.51.100.${i}` }, { at: DAY1 }));
    assert.equal(addManualOrigin(map, { name: 'pool.example.com', ip: '198.51.100.200' }, { at: DAY1 }).error, 'limit');
    assert.equal(addManualOrigin(map, { name: 'other.example.com', ip: '198.51.100.200' }, { at: DAY1 }).error, null);
  });
});

describe('reading the map', () => {
  test('a wildcard entry covers one label under it; the scan gets active entries only', () => {
    const map = sanitizeOriginMap({
      remember: true,
      entries: [
        { name: '*.apps.example.com', ip: '203.0.113.40', lastConfirmed: DAY1 },
        { name: 'x.apps.example.com', ip: '203.0.113.41', lastConfirmed: DAY2 },
        { name: 'y.apps.example.com', ip: '203.0.113.42', lastConfirmed: DAY2, stale: { reason: 'verify-not-hosted', at: DAY3 } }
      ]
    });
    assert.deepEqual(originsFor(map, 'x.apps.example.com').map((e) => e.ip), ['203.0.113.41', '203.0.113.40']);
    assert.deepEqual(originsFor(map, 'a.b.apps.example.com'), []);
    assert.deepEqual(knownForScan(map).map((k) => k.ip), ['203.0.113.40', '203.0.113.41']);
    assert.deepEqual(Object.keys(knownForScan(map)[0]).sort(), ['ip', 'lastConfirmed', 'name', 'port', 'server', 'source']);
    assert.deepEqual(knownForScan(null), []);
  });
});

describe('the map is a workspace part', () => {
  const MAP = {
    v: 1,
    remember: true,
    entries: [{ name: 'shop.example.com', ip: '203.0.113.10', port: 443, source: 'cli-json', firstSeen: DAY1, lastConfirmed: DAY2, server: 'web03', stale: null }]
  };

  test('stored per workspace, sanitized on the way in, gone with "Delete all local data"', async () => {
    assert.ok(WORKSPACE_PARTS.includes('origins'));
    assert.deepEqual(sanitizePart('origins', MAP), MAP);
    assert.equal(sanitizePart('origins', { remember: false, entries: [] }), null);
    const backend = createMemoryBackend([], { persistent: true });
    const store = createWorkspaceStore({ backend });
    await store.open();
    assert.equal(store.data.origins, null, 'off by default: nothing stored');
    await store.save('origins', MAP);
    assert.deepEqual(store.data.origins, MAP);
    assert.ok(backend.entries().some(([k]) => k === 'wsdata/default/origins'));
    const { meta } = await store.create('Acme');
    await store.switchTo(meta.id);
    assert.equal(store.data.origins, null, 'another customer, another map');
    await store.switchTo('default');
    assert.deepEqual(store.data.origins, MAP);
    // A fresh page reads it back.
    const again = createWorkspaceStore({ backend });
    await again.open();
    assert.deepEqual(again.data.origins, MAP);
    await again.destroy();
    assert.deepEqual(backend.entries(), [], 'Delete all local data: nothing left');
    assert.equal(again.data.origins, null);
  });

  test('the hand-over file carries it, plain and sealed, and an import sanitizes it', async () => {
    const data = { origins: { ...MAP, entries: [...MAP.entries, { name: 'bad name', ip: '203.0.113.11', lastConfirmed: DAY1 }] } };
    const plain = await openWorkspaceFile(await exportWorkspaceFile({ name: 'Acme', data }));
    assert.deepEqual(plain.data.origins, MAP);
    const sealedText = await exportWorkspaceFile({ name: 'Acme', data }, { password: 'origin map pass 2026', iterations: MIN_ITERATIONS });
    assert.ok(!sealedText.includes('203.0.113.10') && !sealedText.includes('shop.example.com'), 'nothing of the map shows outside a sealed file');
    const sealed = await openWorkspaceFile(sealedText, { password: 'origin map pass 2026' });
    assert.deepEqual(sealed.data.origins, MAP);
  });
});
