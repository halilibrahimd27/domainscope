// The DNS change request view's pure parts (views/change.js, ui/fix-panel.js): the route of a form
// and back, the field a carried domain fills. DOM-free at import; no network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { routeForm, subjectField } from '../../assets/js/views/change.js';
import { builderParams, checkHash, problemText } from '../../assets/js/ui/fix-panel.js';
import { TEMPLATE_IDS, templateInput, buildChange } from '../../assets/js/lib/fixes.js';
import { t, setLang } from '../../assets/js/i18n.js';

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

  test('the views that load the fix panel on first use list exactly the fixable checks and findings', async () => {
    const [{ FIXABLE_CHECKS }, { FIXABLE_LINT }, { HEALTH_FIX_IDS, LINT_FIX_CODES }] = await Promise.all([
      import('../../assets/js/views/health.js'), import('../../assets/js/views/zone.js'), import('../../assets/js/lib/fixes.js')
    ]);
    assert.deepEqual([...FIXABLE_CHECKS].sort(), [...HEALTH_FIX_IDS]);
    assert.deepEqual([...FIXABLE_LINT].sort(), [...LINT_FIX_CODES]);
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
});
