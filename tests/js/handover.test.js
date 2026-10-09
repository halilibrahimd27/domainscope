/**
 * lib/handover.js — the workspace hand-over file: plain and sealed round trips (the DMARC report
 * history among the parts, encrypted with the rest), what a sealed file
 * shows (nothing but its parameters), the clear errors (not JSON, another format, a newer
 * version, a damaged file, a missing or wrong password, a changed file) and the sanitizing of
 * every imported value. Sealed at MIN_ITERATIONS for speed. No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  exportWorkspaceFile, readWorkspaceFile, openWorkspaceFile, workspacePayload, HandoverError,
  HANDOVER_FORMAT, HANDOVER_VERSION, HANDOVER_MAX_BYTES
} from '../../assets/js/lib/handover.js';
import { MIN_ITERATIONS, DEFAULT_ITERATIONS } from '../../assets/js/lib/cryptobox.js';
import { emptyWorkspaceData } from '../../assets/js/lib/workspace.js';

const PASSWORD = 'hand-over pass 2026';
const FAST = { password: PASSWORD, iterations: MIN_ITERATIONS };
const AT = new Date('2026-09-28T09:30:00Z');
const code = (c) => (err) => err instanceof HandoverError && err.code === c;

const DATA = {
  inventory: { text: 'web01 192.0.2.10\nweb02 192.0.2.11', updatedAt: '2026-09-27T12:00:00Z' },
  learned: { v: 1, seq: 3, labels: { billing: [2, 3], intranet: [1, 1] } },
  wordlist: 'billing\nintranet',
  expectedCas: ["Let's Encrypt", 'Example Internal CA'],
  notes: 'Renewal every March.\nCall the NOC first.',
  recent: [{ value: 'example.com', at: '2026-09-28T09:00:00Z' }, { value: 'www.example.net', at: null }],
  // the portfolio audit's policy (lib/policy.js), as its editor holds it
  policy: '{ "expiryDays": ">= 30", "transferLock": true }',
  // The origin map (lib/originmap.js): remembering on, one active and one stale entry.
  origins: {
    v: 1,
    remember: true,
    entries: [
      { name: 'shop.example.com', ip: '203.0.113.10', port: 443, source: 'cli-json', firstSeen: '2026-09-20T08:00:00.000Z', lastConfirmed: '2026-09-27T08:00:00.000Z', server: 'web03', stale: null },
      { name: 'shop.example.com', ip: '192.0.2.40', port: 8443, source: 'zone', firstSeen: '2026-09-01T08:00:00.000Z', lastConfirmed: '2026-09-01T08:00:00.000Z', server: null,
        stale: { reason: 'cli-elsewhere', at: '2026-09-27T08:00:00.000Z', ip: '203.0.113.10', port: 443 } }
    ]
  },
  // The CT watch's baseline (lib/ctwatch.js): its JSON text, carried as it is (with the current certificates' `due` days).
  ctSeen: '{"v":1,"domains":{"example.com":{"at":"2026-09-27T12:00:00.000Z","ids":{"00000000000000aa":"2026-12-01"},"due":["2026-12-01"]}}}',
  // The registration watch's baseline (lib/regwatch.js): its JSON text, carried as it is.
  rdapSeen: '{"v":1,"domains":{"example.com":{"at":"2026-09-27T12:00:00.000Z","state":"ok","registrar":"Example Registrar, Inc.","ianaId":"9999",'
    + '"statuses":["client transfer prohibited"],"expires":"2027-11-13","nameservers":["ns1.example.net"],"ds":["12345 13 2"]}}}',
  // The Rollout board (lib/rollout.js): its JSON text, one board with web01 installed.
  rollout: '{"v":1,"boards":[{"id":"abababababababababababababababababababababababababababababababab","label":"*.example.com","created":"2026-09-28T09:00:00.000Z","updated":"2026-09-28T09:10:00.000Z","rows":[{"k":"s:web01","n":"web01","s":null,"i":"2026-09-28T09:10:00.000Z","r":null,"v":null,"a":null,"m":"2026-09-28T09:10:00.000Z"}],"total":2}]}',
  // The accepted risks (lib/waivers.js): their JSON text, carried as it is.
  waivers: '{"format":"domainscope-waivers","v":1,"waivers":[{"id":"w-0123456789abcdef","kind":"finding","domain":"example.com","ref":"dmarc.policy-none","reason":"Moving to quarantine in Q1","owner":"Mail team","created":"2026-09-28T09:00:00.000Z","expires":"2026-12-31"}]}',
  // The DMARC report history (lib/dmarchistory.js): its JSON text, one domain kept with the switch on.
  reportHistory: '{"v":1,"keep":true,"updatedAt":"2026-09-28T09:00:00.000Z","domains":{"example.com":{"days":{"2026-09-27":{"msgs":12,"dmarcPass":10,"spfAligned":10,"dkimAligned":9,"quarantine":0,"reject":0,"unknownMsgs":2,"knownFail":0}},"sources":{"192.0.2.10":{"first":"2026-09-27","last":"2026-09-27","msgs":10,"passMsgs":10,"cls":"yours","service":null,"type":null,"checked":true},"203.0.113.9":{"first":"2026-09-27","last":"2026-09-27","msgs":2,"passMsgs":0,"cls":"unknown","service":null,"type":null}},"recent":{"2026-09-27":{"192.0.2.10":[10,10,10,9,0,0],"203.0.113.9":[2,0,0,0,0,0]}},"policy":{"p":"none","sp":"none","pct":100,"seenAt":"2026-09-27T23:59:59.000Z"},"seen":{"2026-09-27":["00000000000000aa"]},"cut":null,"checked":"2026-09-28"}}}',
  // What Home counts of the nightly results (lib/digests.js): counts only.
  digests: '{"monitor":{"at":"2026-09-28T03:00:00.000Z","imported":"2026-09-28T09:00:00.000Z","targets":4,"bad":1,"expiring":0,"incomplete":0}}'
};
const WS = { name: 'Acme', data: DATA, app: 'DomainScope 1.0.0', exportedAt: AT };

describe('the plain file', () => {
  test('a readable, versioned JSON file; empty parts are left out', async () => {
    const text = await exportWorkspaceFile({ ...WS, data: { ...DATA, notes: '', learned: null, policy: '' } });
    const file = JSON.parse(text);
    assert.equal(file.format, HANDOVER_FORMAT);
    assert.equal(file.v, HANDOVER_VERSION);
    assert.equal(file.encrypted, false);
    assert.equal(file.workspace.name, 'Acme');
    assert.equal(file.workspace.default, false);
    assert.equal(file.workspace.exportedAt, '2026-09-28T09:30:00.000Z');
    assert.equal(file.workspace.app, 'DomainScope 1.0.0');
    assert.deepEqual(Object.keys(file.workspace.parts), ['inventory', 'wordlist', 'expectedCas', 'recent', 'origins', 'ctSeen', 'rdapSeen', 'rollout', 'waivers', 'reportHistory', 'digests']);
    assert.equal(file.workspace.parts.digests, DATA.digests, 'Home\'s digest of the nightly results goes too');
    assert.equal(file.workspace.parts.reportHistory, DATA.reportHistory, 'the DMARC report history goes with the workspace');
    assert.equal(file.workspace.parts.origins.entries.length, 2, 'the origin map goes with the workspace');
    assert.equal(file.workspace.parts.ctSeen, DATA.ctSeen, 'the CT watch baseline too');
    assert.equal(file.workspace.parts.rdapSeen, DATA.rdapSeen, 'and the registration watch baseline');
    assert.equal(file.workspace.parts.waivers, DATA.waivers, 'and the accepted risks');
    assert.ok(text.endsWith('\n') && text.includes('\n  "format"'), 'indented');
  });

  test('round trip: the same workspace comes back', async () => {
    const ws = await openWorkspaceFile(await exportWorkspaceFile({ ...WS, isDefault: true }));
    assert.equal(ws.name, 'Acme');
    assert.equal(ws.isDefault, true);
    assert.equal(ws.encrypted, false);
    assert.equal(ws.app, 'DomainScope 1.0.0');
    assert.equal(ws.exportedAt.toISOString(), AT.toISOString());
    assert.deepEqual(ws.data, {
      ...DATA,
      inventory: { ...DATA.inventory, updatedAt: '2026-09-27T12:00:00.000Z' },
      recent: [{ value: 'example.com', at: '2026-09-28T09:00:00.000Z' }, { value: 'www.example.net', at: null }]
    });
  });

  test('an empty workspace is a valid file too', async () => {
    const ws = await openWorkspaceFile(await exportWorkspaceFile({ name: null, isDefault: true, data: emptyWorkspaceData() }));
    assert.equal(ws.name, null);
    assert.deepEqual(ws.data, emptyWorkspaceData());
  });

  test('a byte-order mark in front (an editor saved it) is fine', async () => {
    const text = await exportWorkspaceFile(WS);
    assert.equal((await openWorkspaceFile(`\ufeff${text}`)).name, 'Acme');
  });
});

describe('the sealed file', () => {
  test('shows only its format and parameters: no name, no inventory, no password', async () => {
    const text = await exportWorkspaceFile(WS, FAST);
    const file = JSON.parse(text);
    assert.deepEqual(Object.keys(file), ['format', 'v', 'encrypted', 'kdf', 'cipher', 'data']);
    assert.equal(file.encrypted, true);
    assert.equal(file.kdf.name, 'PBKDF2');
    assert.equal(file.kdf.hash, 'SHA-256');
    assert.equal(file.kdf.iterations, MIN_ITERATIONS);
    assert.equal(file.cipher.name, 'AES-GCM');
    for (const secret of ['Acme', 'web01', '192.0.2.10', '203.0.113.9', 'billing', 'Renewal', 'example.com', 'dmarcPass', PASSWORD]) {
      assert.ok(!text.includes(secret), `the file shows "${secret}"`);
    }
    const { encrypted } = readWorkspaceFile(text);
    assert.equal(encrypted, true);
  });

  test('sealed by default with the default iteration count', async () => {
    const file = JSON.parse(await exportWorkspaceFile(WS, { password: PASSWORD }));
    assert.equal(file.kdf.iterations, DEFAULT_ITERATIONS);
  });

  test('round trip with the password', async () => {
    const ws = await openWorkspaceFile(await exportWorkspaceFile(WS, FAST), { password: PASSWORD });
    assert.equal(ws.encrypted, true);
    assert.equal(ws.name, 'Acme');
    assert.deepEqual(ws.data.expectedCas, DATA.expectedCas);
    assert.equal(ws.data.inventory.text, DATA.inventory.text);
    assert.equal(ws.data.reportHistory, DATA.reportHistory, 'the report history, sealed with the rest');
  });

  test('no password, a wrong one, or a changed file: clear errors', async () => {
    const text = await exportWorkspaceFile(WS, FAST);
    await assert.rejects(openWorkspaceFile(text), code('password-required'));
    await assert.rejects(openWorkspaceFile(text, { password: 'hand-over pass 2025' }), code('wrong-password'));
    const file = JSON.parse(text);
    const i = file.data.length - 10;
    const swapped = file.data[i] === 'A' ? 'B' : 'A';
    const changed = JSON.stringify({ ...file, data: `${file.data.slice(0, i)}${swapped}${file.data.slice(i + 1)}` });
    await assert.rejects(openWorkspaceFile(changed, { password: PASSWORD }), code('wrong-password'), 'one character of the ciphertext');
    const fewer = JSON.stringify({ ...file, kdf: { ...file.kdf, iterations: file.kdf.iterations + 1000 } });
    await assert.rejects(openWorkspaceFile(fewer, { password: PASSWORD }), code('wrong-password'), 'the parameters are authenticated');
    const cut = JSON.stringify({ ...file, data: file.data.slice(0, 8) });
    await assert.rejects(openWorkspaceFile(cut, { password: PASSWORD }), code('damaged'), 'too short to hold a tag');
  });

  test('a weak password is refused before anything is written', async () => {
    await assert.rejects(exportWorkspaceFile(WS, { password: 'short', iterations: MIN_ITERATIONS }), code('password-short'));
  });
});

describe('what is not a hand-over file', () => {
  test('not JSON, another JSON, a newer version, a damaged file, a file too large', async () => {
    await assert.rejects(openWorkspaceFile('web01 192.0.2.10'), code('not-json'));
    await assert.rejects(openWorkspaceFile(42), code('not-json'));
    for (const other of ['[]', 'null', '{"format":"something-else","v":1}', '{"inventory":"x"}']) {
      await assert.rejects(openWorkspaceFile(other), code('not-workspace'), other);
    }
    const newer = JSON.stringify({ format: HANDOVER_FORMAT, v: HANDOVER_VERSION + 1, encrypted: false, workspace: { parts: {} } });
    await assert.rejects(openWorkspaceFile(newer), code('newer'));
    for (const broken of [
      { format: HANDOVER_FORMAT, encrypted: false, workspace: { parts: {} } },
      { format: HANDOVER_FORMAT, v: 0, encrypted: false, workspace: { parts: {} } },
      { format: HANDOVER_FORMAT, v: 1, encrypted: false },
      { format: HANDOVER_FORMAT, v: 1, encrypted: false, workspace: [] },
      { format: HANDOVER_FORMAT, v: 1, encrypted: false, workspace: { name: 'x' } },
      { format: HANDOVER_FORMAT, v: 1, encrypted: 'yes', workspace: { parts: {} } },
      { format: HANDOVER_FORMAT, v: 1, encrypted: true, kdf: {}, cipher: {} }
    ]) {
      await assert.rejects(openWorkspaceFile(JSON.stringify(broken)), code('damaged'), JSON.stringify(broken));
    }
    assert.throws(() => readWorkspaceFile('x'.repeat(HANDOVER_MAX_BYTES + 1)), code('too-large'));
  });
});

describe('every imported value is checked', () => {
  test('names, learned labels, recent entries and expected CAs are sanitized; unknown parts dropped', async () => {
    const hostile = JSON.stringify({
      format: HANDOVER_FORMAT,
      v: 1,
      encrypted: false,
      workspace: {
        name: '  Acme\u202e\u0000  Corp ',
        default: 'yes',
        exportedAt: 'not a date',
        app: 42,
        parts: {
          learned: { v: 1, labels: { api: [1, 1], '203-0-113-9': [9, 9], 'x.y': [1, 1] } },
          recent: ['192.0.2.1', 'https://Shop.Example.com/', { value: 'com' }],
          expectedCas: ['Sectigo', 'SECTIGO', '', 'x'.repeat(300)],
          inventory: { text: 'db01 192.0.2.20' },
          settings: { theme: 'dark' },
          notes: 7
        }
      }
    });
    const ws = await openWorkspaceFile(hostile);
    assert.equal(ws.name, 'Acme Corp');
    assert.equal(ws.isDefault, false);
    assert.equal(ws.exportedAt, null);
    assert.equal(ws.app, null);
    assert.deepEqual(Object.keys(ws.data.learned.labels), ['api']);
    assert.deepEqual(ws.data.recent.map((r) => r.value), ['shop.example.com']);
    assert.equal(ws.data.expectedCas.length, 2);
    assert.equal(ws.data.expectedCas[0], 'Sectigo');
    assert.deepEqual(ws.data.inventory, { text: 'db01 192.0.2.20', updatedAt: null });
    assert.equal(ws.data.notes, '');
    assert.ok(!('settings' in ws.data), 'tool settings are never part of a workspace');
  });

  test('workspacePayload: the object that goes into the file', () => {
    const p = workspacePayload({ name: ' Acme ', data: { notes: 'n' }, exportedAt: new Date('invalid') });
    assert.deepEqual(p, { name: 'Acme', default: false, exportedAt: null, app: 'DomainScope', parts: { notes: 'n' } });
  });
});
