/**
 * ui/globalping-gate.js — the page-session Globalping gate shared by SSL Targets › Verify and
 * Domain Health › MTA-STS: consent per purpose, the shared quota, and the one-click flow
 * (free /limits read → quota check → dialog → go). No DOM (the dialog is replaced), no network.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { setLang } from '../../assets/js/i18n.js';
import { state } from '../../assets/js/state.js';
import {
  gateProbes, hasConsent, grantConsent, sharedQuota, noteQuota, liveQuota, whenText, measurementUrl, GP_MEASUREMENT_URL
} from '../../assets/js/ui/globalping-gate.js';
import { liveQuota as panelLiveQuota } from '../../assets/js/ui/verify-panel.js';

setLang('en');

const HOUR = 3600000;
const T0 = Date.parse('2026-09-27T12:00:00Z');

/** A fake Globalping client: `limits()` answers from the script (a quota, an Error, or a promise). */
function fakeClient(limits, quota = null) {
  const calls = [];
  return {
    calls,
    quota,
    limits: async ({ signal } = {}) => {
      calls.push({ signal });
      const step = typeof limits === 'function' ? limits(signal) : limits;
      if (step instanceof Error) throw step;
      return step;
    }
  };
}
const ctxFor = (client) => ({ getGlobalping: async () => client });
const q = (remaining, resetAt = new Date(T0 + HOUR), limit = 250) => ({ limit, remaining, consumed: limit - remaining, resetAt, cost: null, type: 'ip', source: 'limits', at: new Date(T0) });

test('the first send of a purpose asks (privacy + cost); the next one does not; each purpose asks once', async () => {
  state.clearAll();
  const asked = [];
  const confirm = async (o) => { asked.push(o); return true; };
  const client = fakeClient(q(120));
  let r = await gateProbes(ctxFor(client), { purpose: 'mta-sts', probes: 1, privacy: 'P', confirm, now: () => T0 });
  assert.equal(r.status, 'go');
  assert.equal(r.client, client);
  assert.equal(asked.length, 1);
  assert.deepEqual([asked[0].privacy, asked[0].probes, asked[0].remaining, asked[0].limit, asked[0].unknown], ['P', 1, 120, 250, false]);
  assert.equal(hasConsent('mta-sts'), true);
  assert.equal(client.calls.length, 1, 'one free /limits read per click');
  r = await gateProbes(ctxFor(client), { purpose: 'mta-sts', privacy: 'P', confirm });
  assert.deepEqual([r.status, asked.length, client.calls.length], ['go', 1, 2], 'consent kept for the page session; /limits read again');
  // Verify's consent does not cover another purpose, and the other way round
  assert.equal(hasConsent('verify'), false);
  grantConsent('verify');
  assert.equal(hasConsent('verify'), true);
  await gateProbes(ctxFor(client), { purpose: 'other', privacy: 'O', confirm });
  assert.equal(asked.length, 2);
});

test('cancel sends nothing and grants nothing; "Delete all local data" resets consent and the shared quota', async () => {
  state.clearAll();
  assert.equal(sharedQuota(), null);
  const client = fakeClient(q(10));
  let r = await gateProbes(ctxFor(client), { purpose: 'mta-sts', privacy: 'P', confirm: async () => false });
  assert.equal(r.status, 'cancelled');
  assert.equal(hasConsent('mta-sts'), false);
  assert.equal(sharedQuota().remaining, 10, 'the free reading is shared even when cancelled');
  r = await gateProbes(ctxFor(client), { purpose: 'mta-sts', privacy: 'P', confirm: async () => true });
  assert.equal(hasConsent('mta-sts'), true);
  state.clearAll();
  assert.deepEqual([hasConsent('mta-sts'), sharedQuota()], [false, null]);
});

test('a quota that cannot cover the probes: nothing asked, nothing sent, the reset time returned', async () => {
  state.clearAll();
  let asked = 0;
  const confirm = async () => { asked += 1; return true; };
  const resetAt = new Date(T0 + 20 * 60000);
  let r = await gateProbes(ctxFor(fakeClient(q(0, resetAt))), { purpose: 'mta-sts', probes: 1, privacy: 'P', confirm });
  assert.deepEqual([r.status, r.resetAt, asked], ['quota', resetAt, 0]);
  r = await gateProbes(ctxFor(fakeClient(q(2))), { purpose: 'mta-sts', probes: 3, privacy: 'P', confirm });
  assert.equal(r.status, 'quota');
});

test('a failed /limits read is not fatal: the last reading of the open window or the anonymous limit, and the dialog says so', async () => {
  state.clearAll();
  const asked = [];
  const confirm = async (o) => { asked.push(o); return true; };
  let r = await gateProbes(ctxFor(fakeClient(new TypeError('Failed to fetch'))), { purpose: 'a', privacy: 'P', confirm, now: () => T0 });
  assert.deepEqual([r.status, asked[0].unknown, asked[0].remaining, asked[0].limit], ['go', true, 250, 250]);
  r = await gateProbes(ctxFor(fakeClient(new TypeError('x'), q(0, new Date(T0 + HOUR)))), { purpose: 'b', privacy: 'P', confirm, now: () => T0 });
  assert.equal(r.status, 'quota', 'the client\'s own reading of the open window stands in');
  r = await gateProbes(ctxFor(fakeClient(new TypeError('x'), q(0, new Date(T0 - 1)))), { purpose: 'c', privacy: 'P', confirm, now: () => T0 });
  assert.equal(r.status, 'go', 'a reading whose window has passed is not used');
});

test('abort and an unloadable client', async () => {
  state.clearAll();
  const ac = new AbortController();
  const slow = fakeClient((signal) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true });
  }));
  const pending = gateProbes(ctxFor(slow), { purpose: 'x', privacy: 'P', signal: ac.signal, confirm: async () => true });
  ac.abort();
  assert.equal((await pending).status, 'cancelled');
  assert.equal(hasConsent('x'), false);
  const ac2 = new AbortController();
  const r = await gateProbes(ctxFor(fakeClient(q(5))), {
    purpose: 'y', privacy: 'P', signal: ac2.signal, confirm: async () => { ac2.abort(); return true; }
  });
  assert.equal(r.status, 'cancelled', 'aborted while the dialog was open');
  assert.equal(hasConsent('y'), false);
  const boom = new Error('module failed to load');
  const out = await gateProbes({ getGlobalping: async () => { throw boom; } }, { purpose: 'z', privacy: 'P', confirm: async () => true });
  assert.deepEqual(out, { status: 'unreachable', error: boom });
});

test('noteQuota / liveQuota / whenText; verify-panel re-exports liveQuota', () => {
  state.clearAll();
  noteQuota(null);
  assert.equal(sharedQuota(), null);
  noteQuota(q(7));
  assert.equal(sharedQuota().remaining, 7);
  assert.equal(liveQuota(q(1, new Date(T0 - 1)), T0), null);
  assert.equal(liveQuota(q(1, null), T0).remaining, 1);
  assert.equal(panelLiveQuota, liveQuota);
  assert.equal(whenText(new Date(T0 + 42 * 60000), T0), whenText(new Date(T0 + 42 * 60000), T0));
  assert.match(whenText(new Date(T0 + 42 * 60000), T0), /42/);
  assert.equal(whenText(new Date(T0 - HOUR), T0), whenText(new Date(T0), T0), 'a past reset reads "now"');
  assert.equal(whenText(null, T0), whenText(new Date(T0 + HOUR), T0), 'no window: an hour from now');
});

test('measurementUrl: the API link for a measurement id, nothing for anything else', () => {
  assert.equal(GP_MEASUREMENT_URL, 'https://api.globalping.io/v1/measurements/');
  assert.equal(measurementUrl('2IuWbVoKnaKkYjabJ00021DDq'), 'https://api.globalping.io/v1/measurements/2IuWbVoKnaKkYjabJ00021DDq');
  for (const bad of ['', 'short', '../limits', 'abc/def12345', 'a'.repeat(65), null, undefined, 42]) assert.equal(measurementUrl(bad), null, String(bad));
});
