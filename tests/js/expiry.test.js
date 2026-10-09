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

  test('daysUntil: whole days, rounded down; a day (YYYY-MM-DD) counts from its start, UTC', () => {
    assert.equal(daysUntil('2026-10-12', NOW), 2, '2.5 days: 2');
    assert.equal(daysUntil('2026-10-09', NOW), -1, 'today, after noon: past its start');
    assert.equal(daysUntil(new Date('2026-10-19T12:00:00Z'), NOW), 10);
    assert.equal(daysUntil(Date.parse('2026-10-09T11:00:00Z'), NOW), -1, 'an hour ago');
    assert.equal(daysUntil('2026-11-08T12:00:00Z', new Date(NOW)), 30);
    for (const bad of ['', 'soon', null, undefined, NaN, {}, new Date('x')]) assert.equal(daysUntil(bad, NOW), null, String(bad));
    assert.equal(daysUntil('2026-10-12', 'now'), null);
  });

  test('expiryOf: the days left and their severity, or null when the end is not known', () => {
    assert.deepEqual(expiryOf('certificate', '2026-10-12', NOW), { daysLeft: 2, severity: 'error' });
    assert.deepEqual(expiryOf('registration', '2026-11-28', NOW), { daysLeft: 49, severity: 'warn' });
    assert.deepEqual(expiryOf('registration', '2027-10-09', NOW), { daysLeft: 364, severity: 'ok' });
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
