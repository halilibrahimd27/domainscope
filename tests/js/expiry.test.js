/**
 * tests/js/expiry.test.js — lib/expiry.js, the expiry bands in one place (docs/DESIGN.md §6.2),
 * and lib/regstatus.js, the registry status rules split out of lib/portfolio.js and
 * lib/passport.js (which re-export them unchanged). No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { EXPIRY_BANDS, EXPIRY_KINDS, expirySeverity, daysUntil, expiryOf } from '../../assets/js/lib/expiry.js';
import * as regstatus from '../../assets/js/lib/regstatus.js';
import * as portfolio from '../../assets/js/lib/portfolio.js';
import * as passport from '../../assets/js/lib/passport.js';

const NOW = Date.parse('2026-10-09T12:00:00Z');

describe('the expiry bands', () => {
  test('registration: error under 30 days (or expired), warn under 60; certificate: error under 7, warn under 30 (decision C1)', () => {
    assert.deepEqual(EXPIRY_BANDS, { registration: { error: 30, warn: 60 }, certificate: { error: 7, warn: 30 } });
    assert.deepEqual(EXPIRY_KINDS, ['registration', 'certificate']);
    assert.ok(Object.isFrozen(EXPIRY_BANDS) && Object.isFrozen(EXPIRY_BANDS.certificate));
    const reg = (d) => expirySeverity('registration', d);
    assert.deepEqual([-1, 0, 29, 30, 59, 60, 400].map(reg), ['error', 'error', 'error', 'warn', 'warn', 'ok', 'ok']);
    const cert = (d) => expirySeverity('certificate', d);
    assert.deepEqual([-3, 0, 6, 7, 29, 30, 90].map(cert), ['error', 'error', 'error', 'warn', 'warn', 'ok', 'ok']);
  });

  test('an unknown kind or a days left that is not a number has no severity', () => {
    for (const [kind, days] of [['domain', 5], ['registration', NaN], ['certificate', '5'], ['certificate', null], ['toString', 1], ['certificate', Infinity]]) {
      assert.equal(expirySeverity(kind, days), null, `${kind} ${days}`);
    }
  });

  test('daysUntil: a time in whole days, rounded down; a day (YYYY-MM-DD) in whole UTC calendar days — today is 0, past from the day after', () => {
    assert.equal(daysUntil('2026-10-12', NOW), 3, 'three days from today');
    assert.equal(daysUntil('2026-10-09', NOW), 0, 'today, after noon: it ends today, it has not ended');
    assert.equal(daysUntil('2026-10-08', NOW), -1, 'yesterday: past');
    assert.equal(daysUntil('2026-10-10', Date.parse('2026-10-09T23:59:59Z')), 1, 'tomorrow, a second before midnight');
    assert.equal(daysUntil('2026-10-09', Date.parse('2026-10-09T00:00:00Z')), 0, 'today, at midnight');
    assert.equal(daysUntil('2027-10-09', NOW), 365);
    assert.equal(daysUntil(new Date('2026-10-19T12:00:00Z'), NOW), 10);
    assert.equal(daysUntil(Date.parse('2026-10-09T11:00:00Z'), NOW), -1, 'an hour ago');
    assert.equal(daysUntil('2026-11-08T12:00:00Z', new Date(NOW)), 30);
    for (const bad of ['', 'soon', null, undefined, NaN, {}, new Date('x')]) assert.equal(daysUntil(bad, NOW), null, String(bad));
    assert.equal(daysUntil('2026-10-12', 'now'), null);
  });

  test('daysUntil on the last day (now 10:00 UTC): a day ending at 20:00 is 0 days left, as its time says — never expired before it is', () => {
    const now = Date.parse('2026-10-09T10:00:00Z');
    const ends = Date.parse('2026-10-09T20:00:00Z');
    assert.equal(daysUntil(ends, now), 0, 'the time: 10 hours left');
    assert.equal(daysUntil('2026-10-09', now), daysUntil(ends, now), 'its day says the same');
    assert.equal(daysUntil('2026-10-10', now), daysUntil(Date.parse('2026-10-10T23:00:00Z'), now), 'in 37 hours: 1 day, by its day as by its time');
    assert.deepEqual(expiryOf('certificate', '2026-10-09', now), { daysLeft: 0, severity: 'error' });
    assert.deepEqual(expiryOf('registration', '2026-10-09', now + 86400000), { daysLeft: -1, severity: 'error' }, 'the day after: expired');
  });

  test('expiryOf: the days left and their severity, or null when the end is not known', () => {
    assert.deepEqual(expiryOf('certificate', '2026-10-12', NOW), { daysLeft: 3, severity: 'error' });
    assert.deepEqual(expiryOf('registration', '2026-11-28', NOW), { daysLeft: 50, severity: 'warn' });
    assert.deepEqual(expiryOf('registration', '2027-10-09', NOW), { daysLeft: 365, severity: 'ok' });
    assert.equal(expiryOf('registration', null, NOW), null);
    assert.equal(expiryOf('mailbox', '2026-11-28', NOW), null);
  });

  test('the Domain portfolio\'s registration column reads the same bands (expired is its own)', () => {
    assert.equal(portfolio.expiryBand(-1), 'expired');
    assert.equal(portfolio.expiryBand(0), 'error');
    assert.equal(portfolio.expiryBand(29), 'error');
    assert.equal(portfolio.expiryBand(30), 'warn');
    assert.equal(portfolio.expiryBand(59), 'warn');
    assert.equal(portfolio.expiryBand(60), 'ok');
  });
});

describe('lib/regstatus.js', () => {
  test('lib/portfolio.js and lib/passport.js re-export the same functions (one copy of each rule)', () => {
    for (const name of ['CRITICAL_STATUSES', 'LOCK_LEVELS', 'lockLevel', 'statusRisk']) assert.equal(portfolio[name], regstatus[name], name);
    assert.equal(passport.rdapStatusFlags, regstatus.rdapStatusFlags);
  });

  test('statusRisk: a hold is critical, a pending transfer next, no transfer prohibition a hijack risk, a registry lock fine', () => {
    assert.equal(regstatus.statusRisk(['server hold', 'client transfer prohibited']).risk, 'critical');
    assert.equal(regstatus.statusRisk(['pendingTransfer', 'clientTransferProhibited']).risk, 'pending-transfer');
    assert.equal(regstatus.statusRisk(['client delete prohibited']).risk, 'hijack');
    const lock = regstatus.statusRisk(['server transfer prohibited', 'server update prohibited', 'server delete prohibited']);
    assert.deepEqual([lock.risk, lock.registryLock, lock.lockLevel], ['ok', true, 'registry']);
    assert.equal(regstatus.statusRisk([]).risk, null, 'no status at all: not known');
    assert.equal(regstatus.statusName('clientHold'), 'client hold');
  });
});
