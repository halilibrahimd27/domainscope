// The DNS change request view's pure parts (views/change.js, ui/fix-panel.js): the route of a form
// and back, the field a carried domain fills. DOM-free at import; no network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { routeForm, subjectField, errorLabel, checkInProgress, globalCheckSet } from '../../assets/js/views/change.js';
import { builderParams, checkHash, problemText } from '../../assets/js/ui/fix-panel.js';
import { TEMPLATE_IDS, templateInput, buildChange } from '../../assets/js/lib/fixes.js';
import { t, setLang, hasString } from '../../assets/js/i18n.js';

describe('the form in the route', () => {
  test('builderParams keeps the template and what differs from the defaults; routeForm reads it back', () => {
    const input = { domain: 'example.com', cas: ['google'], wild: 'none', methods: ['dns-01', 'http-01'], iodef: '' };
    const params = builderParams('caa', input);
    assert.deepEqual(params, { t: 'caa', domain: 'example.com', cas: 'google', wild: 'none', methods: 'dns-01,http-01' });
    assert.deepEqual(routeForm(params), { template: 'caa', input: templateInput('caa', input) });
  });

  test('an emptied list and a switched-off box survive the round trip', () => {
    const params = builderParams('parked', { domain: 'example.org', caa: false });
    assert.deepEqual(params, { t: 'parked', domain: 'example.org', caa: '0' });
    assert.equal(routeForm(params).input.caa, false);
    const none = builderParams('caa', { domain: 'example.com', cas: [] });
    assert.equal(none.cas, '-');
    assert.deepEqual(routeForm(none).input.cas, []);
  });

  test('every template round-trips its defaults, and builds the same change from its route', () => {
    for (const id of TEMPLATE_IDS) {
      const form = templateInput(id, { domain: 'example.com', name: 'www.example.com' });
      const back = routeForm(builderParams(id, form));
      assert.deepEqual(back, { template: id, input: form }, id);
      assert.deepEqual(buildChange(id, back.input), buildChange(id, form), id);
    }
    assert.equal(routeForm({ t: 'nope' }), null);
    assert.equal(routeForm({}), null);
    assert.deepEqual(builderParams('nope', {}), {});
  });

  test('a carried domain fills the domain, else the name', () => {
    assert.equal(subjectField('caa'), 'domain');
    assert.equal(subjectField('acme-txt'), 'name');
    assert.equal(subjectField('record'), 'name');
    assert.equal(subjectField('nope'), null);
  });

  test('"Check propagation (Global DNS)" names the first record set Global DNS can ask for: never a wildcard, which it cannot', () => {
    const pick = (list) => {
      const set = globalCheckSet(list.map(([name, type]) => ({ name, type })));
      return set ? `${set.name} ${set.type}` : null;
    };
    assert.equal(pick([['*.example.com', 'A'], ['www.example.com', 'AAAA']]), 'www.example.com AAAA');
    assert.equal(pick([['example.com', 'NS'], ['_acme-challenge.example.com', 'TXT']]), '_acme-challenge.example.com TXT', 'a type Global DNS asks for');
    assert.equal(pick([['*.example.com', 'A']]), null);
    assert.equal(pick([]), null);
    const wildcard = buildChange('record', templateInput('record', { name: '*.example.com', type: 'A', values: '192.0.2.10' }));
    assert.ok(wildcard.rrsets.length && wildcard.rrsets.every((r) => r.name.startsWith('*.')), 'the fixture builds a wildcard set');
    assert.equal(globalCheckSet(wildcard.rrsets), null, 'no step that opens an error page');
    assert.equal(globalCheckSet(buildChange('acme-txt', templateInput('acme-txt', { name: '*.example.com', tokens: 'x' })).rrsets).name, '_acme-challenge.example.com');
  });

  test('the views that load the fix panel on first use list exactly the fixable checks and findings', async () => {
    const [{ FIXABLE_CHECKS }, { FIXABLE_LINT }, { HEALTH_FIX_IDS, LINT_FIX_CODES }] = await Promise.all([
      import('../../assets/js/views/health.js'), import('../../assets/js/views/zone.js'), import('../../assets/js/lib/fixes.js')
    ]);
    assert.deepEqual([...FIXABLE_CHECKS].sort(), [...HEALTH_FIX_IDS]);
    assert.deepEqual([...FIXABLE_LINT].sort(), [...LINT_FIX_CODES]);
  });

  test('a resolver without an answer: the error kind in words, a DNS rcode as it is, never an internal code', () => {
    setLang('en');
    assert.equal(errorLabel('http', t), 'No answer (server error)');
    assert.equal(errorLabel('unavailable', t), 'No answer (server error)');
    assert.equal(errorLabel('rate-limit', t), 'No answer (rate limited)');
    assert.equal(errorLabel('timeout', t), 'No answer (timed out)');
    assert.equal(errorLabel('SERVFAIL', t), 'No answer (SERVFAIL)');
    assert.equal(errorLabel('unknown', t), 'No answer');
    assert.equal(errorLabel(null, t), 'No answer');
    setLang('tr');
    assert.equal(errorLabel('network', t), 'Yanıt yok (ağ hatası)');
    assert.equal(errorLabel('REFUSED', t), 'Yanıt yok (REFUSED)');
    setLang('en');
  });

  test('the check link and problem texts', () => {
    assert.equal(checkHash('z=example.com&r=is+www+A+192.0.2.1'), '#/change/check?z=example.com&r=is+www+A+192.0.2.1');
    setLang('en');
    assert.equal(problemText({ key: 'zone.lint.CNAME_AND_OTHER_DATA', params: { name: 'www.example.com', types: ['A', 'TXT'] } }), t('zone.lint.CNAME_AND_OTHER_DATA', { name: 'www.example.com', types: 'A, TXT' }));
    assert.equal(problemText({ key: 'fix.p.cname-one' }), 'A name has at most one CNAME.');
    setLang('tr');
    assert.equal(problemText({ key: 'fix.p.cname-one' }), 'Bir adın en fazla bir CNAME kaydı olur.');
    setLang('en');
  });

  test('a check in progress (a round asking, the next one due, or waiting for the connection) on the page on screen; a switch names it', () => {
    const memo = (extra) => ({ mounted: true, stop: null, running: false, timer: null, offline: null, ...extra });
    assert.equal(checkInProgress(null), false);
    assert.equal(checkInProgress(memo({ running: true })), true, 'a round asking now');
    assert.equal(checkInProgress(memo({ timer: 7 })), true, 'the next round due');
    assert.equal(checkInProgress(memo({ offline: { only: null } })), true, 'waiting for the connection');
    assert.equal(checkInProgress(memo({})), false, 'between a failed round and Check now');
    assert.equal(checkInProgress(memo({ timer: 7, stop: 'done' })), false, 'stopped by itself');
    assert.equal(checkInProgress(memo({ running: true, stop: 'user' })), false, 'stopped by Stop');
    assert.equal(checkInProgress(memo({ offline: { only: null }, mounted: false })), false, 'the page left: nothing runs');
    for (const lang of ['en', 'tr']) assert.ok(hasString('chg.switchRunning', lang), lang);
  });
});
