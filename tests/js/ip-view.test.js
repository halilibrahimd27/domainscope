/**
 * views/ip.js strings: the live "N addresses · N host names" line under the input agrees in
 * number in English. Pure Node (the view is DOM-free at import time).
 */
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';

import { setLang, t } from '../../assets/js/i18n.js';
import '../../assets/js/views/ip.js'; // registers the ipi.* strings

describe('IP Intel view: parsed-input summary', () => {
  after(() => setLang('en'));

  test('English uses the singular for one address / host name', () => {
    setLang('en');
    const line = (ips, hosts) => `${t('ipi.parsedIps', { count: ips })} · ${t('ipi.parsedHosts', { count: hosts })}`;
    assert.equal(line(1, 1), '1 address · 1 host name');
    assert.equal(line(2, 0), '2 addresses · 0 host names');
    assert.equal(line(1200, 3), '1,200 addresses · 3 host names');
  });

  test('Turkish keeps the noun singular after a number', () => {
    setLang('tr');
    assert.equal(`${t('ipi.parsedIps', { count: 1 })} · ${t('ipi.parsedHosts', { count: 5 })}`, '1 adres · 5 host adı');
  });
});
