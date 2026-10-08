/**
 * lib/registrars.js — a registrar's class by its IANA Registrar ID: the corporate registrars
 * (each ID as IANA's registrar-ids-1.csv had it on 2026-10-08), IANA's reserved IDs, and what an
 * RDAP identifier can look like. Pure Node, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  CORPORATE_REGISTRARS, RESERVED_REGISTRAR_IDS, REGISTRAR_CLASSES, corporateRegistrar, registrarClass, registrarId
} from '../../assets/js/lib/registrars.js';

describe('registrars', () => {
  test('the corporate registrars by IANA ID, each once, frozen', () => {
    assert.deepEqual(CORPORATE_REGISTRARS.map((r) => r.id).sort((a, b) => a - b), [292, 299, 447, 470, 642, 1011, 1251, 1466, 1639, 1750, 3786, 3838]);
    assert.deepEqual(Object.fromEntries(CORPORATE_REGISTRARS.map((r) => [r.id, r.brand])), {
      292: 'MarkMonitor', 299: 'CSC', 447: 'Safenames', 470: 'Com Laude', 642: 'Corsearch', 1011: '101domain', 1251: 'Nameshield',
      1466: 'Lexsynergy', 1639: 'EBRAND', 1750: 'Authentic Web', 3786: 'GoDaddy Corporate Domains', 3838: 'MarkMonitor'
    });
    assert.equal(new Set(CORPORATE_REGISTRARS.map((r) => r.id)).size, CORPORATE_REGISTRARS.length);
    assert.ok(Object.isFrozen(CORPORATE_REGISTRARS) && CORPORATE_REGISTRARS.every((r) => Object.isFrozen(r) && r.name && r.brand));
    assert.ok(CORPORATE_REGISTRARS.every((r) => !RESERVED_REGISTRAR_IDS.includes(r.id)), 'no corporate ID is a reserved one');
    assert.deepEqual(REGISTRAR_CLASSES, ['corporate', 'retail', 'unknown']);
  });

  test('an IANA ID as RDAP gives it: a string of digits (spaces trimmed) or a number; anything else none', () => {
    assert.deepEqual(['292', ' 3838 ', 1639, '0001750'].map(registrarId), [292, 3838, 1639, 1750]);
    for (const bad of [null, undefined, '', 'N/A', 'not given', '0', 0, '-5', -5, '12a', '1.5', 1.5, '1e3', true, {}, '1234567890']) {
      assert.equal(registrarId(bad), null, JSON.stringify(bad));
    }
  });

  test('registrarClass: corporate, retail, unknown (no ID, as for a country-code registry\'s own registrars, or a reserved one)', () => {
    for (const r of CORPORATE_REGISTRARS) {
      assert.equal(registrarClass(String(r.id)), 'corporate', r.name);
      assert.equal(registrarClass(r.id), 'corporate', `${r.name} as a number`);
    }
    for (const id of ['1068', '146', '625', 2, '48']) assert.equal(registrarClass(id), 'retail', String(id));
    for (const id of [null, undefined, '', 'N/A']) assert.equal(registrarClass(id), 'unknown', String(id));
    // the registry acting as registrar, test and SLA IDs, IANA's own: who holds the domain is not said
    for (const id of RESERVED_REGISTRAR_IDS) assert.equal(registrarClass(String(id)), 'unknown', String(id));
    assert.deepEqual([9994, 9995, 9996, 9997, 9998, 9999, 8888888].every((id) => RESERVED_REGISTRAR_IDS.includes(id)), true);
  });

  test('corporateRegistrar: the entry of a corporate ID, null for any other', () => {
    assert.deepEqual(corporateRegistrar('299'), { id: 299, brand: 'CSC', name: 'CSC Corporate Domains, Inc.' });
    assert.equal(corporateRegistrar('3838').brand, 'MarkMonitor');
    assert.equal(corporateRegistrar('1068'), null);
    assert.equal(corporateRegistrar('9999'), null);
    assert.equal(corporateRegistrar(null), null);
  });
});
