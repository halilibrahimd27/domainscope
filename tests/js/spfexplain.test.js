/**
 * lib/spfexplain.js — an SPF policy in plain words for DNS Lookup › Explain: the steps of a record
 * and of the policies it includes, the lookup meter, TXT strings that join badly and the flatten
 * preview, over trees lib/health.js spfLookupCount expands from a fake zone. Documentation data only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  spfPolicy, spfMeter, spfStringIssues, spfFlatten, macroLetters,
  SPF_STEP_KINDS, SPF_STEP_STATES, SPF_POLICY_STATES, SPF_FLATTEN_NOTES, SPF_UDP_SAFE_LENGTH
} from '../../assets/js/lib/spfexplain.js';
import { spfLookupCount } from '../../assets/js/lib/health.js';
import { zoneDns } from './zone-dns.mjs';

const RECORD = 'v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.7 ip6:2001:db8:1::/48 a mx/24 include:_spf.example.net ~include:soft.example.net '
  + 'exists:%{i}._x.example.com ptr ?all -ip4:203.0.113.1 redirect=r.example.org exp=explain.example.com foo=bar';
const ZONE = {
  'example.com': { TXT: RECORD, A: '192.0.2.10', MX: [{ preference: 10, exchange: 'mx1.example.com' }] },
  'mx1.example.com': { A: '203.0.113.25' },
  '_spf.example.net': { TXT: 'v=spf1 ip4:198.51.100.128/25 -ip4:198.51.100.200 include:_inner.example.net -all' },
  '_inner.example.net': { TXT: 'v=spf1 ip6:2001:db8:ff::/48 ~all' },
  'soft.example.net': { TXT: 'v=spf1 a:relay.example.net -all' },
  'relay.example.net': { A: '192.0.2.77' }
};
const tree = async (zone = ZONE, name = 'example.com') => spfLookupCount(name, { dns: zoneDns(zone) });

describe('spfPolicy', () => {
  test('every term in order: what it does, its result here and at the checked domain, its cost', async () => {
    const r = await tree();
    const p = spfPolicy(r.tree);
    assert.equal(p.state, 'ok');
    assert.deepEqual(p.steps.map((s) => s.kind), ['ip4-range', 'ip4', 'ip6-range', 'a', 'mx', 'include', 'include', 'exists', 'ptr', 'all']);
    const [range, one, v6, a, mx, inc, soft, exists, ptr, all] = p.steps;
    assert.deepEqual(range.params, { range: '192.0.2.0/24', first: '192.0.2.0', last: '192.0.2.255', size: 256, prefix: 24, hostBits: false });
    assert.equal(one.params.range, '198.51.100.7');
    assert.deepEqual([v6.params.range, v6.params.size], ['2001:db8:1::/48', null], 'an IPv6 network is named by its prefix');
    assert.deepEqual([a.params.host, a.addresses, a.cost, a.state], ['example.com', ['192.0.2.10'], 1, 'ok']);
    assert.deepEqual([mx.params.cidr4, mx.hosts], [24, ['mx1.example.com']]);
    assert.deepEqual([inc.target, inc.cost, inc.result, inc.effective], ['_spf.example.net', 2, 'pass', 'pass']);
    assert.deepEqual([soft.result, soft.effective], ['softfail', 'softfail']);
    assert.deepEqual([exists.state, exists.macros, exists.missing, exists.target], ['macro', ['i'], ['i'], null]);
    assert.deepEqual([ptr.params.target, ptr.state], ['example.com', 'ok']);
    assert.deepEqual([all.result, all.n], ['neutral', 10]);
    assert.deepEqual(p.ignored, ['-ip4:203.0.113.1'], 'after all: never read');
    assert.deepEqual([p.redirect, p.redirectIgnored, p.exp, p.modifiers, p.implicitNeutral], ['r.example.org', true, 'explain.example.com', [['foo', 'bar']], false]);
    assert.deepEqual(p.warnings.map((w) => w.code).sort(), ['ptr', 'redirect-ignored', 'terms-after-all']);
    assert.equal(p.count, r.count);
  });

  test('inside an include only a pass counts; a ~include gives its own result to what its policy passes', async () => {
    const p = spfPolicy((await tree()).tree);
    const inc = p.steps[5].child;
    assert.deepEqual([inc.domain, inc.scope], ['_spf.example.net', 'include']);
    assert.deepEqual(inc.steps.map((s) => [s.term, s.result, s.effective]), [
      ['ip4:198.51.100.128/25', 'pass', 'pass'],
      ['-ip4:198.51.100.200', 'fail', null],
      ['include:_inner.example.net', 'pass', 'pass'],
      ['-all', 'fail', null]
    ]);
    assert.deepEqual(inc.steps[2].child.steps.map((s) => [s.term, s.effective]), [['ip6:2001:db8:ff::/48', 'pass'], ['~all', null]]);
    const soft = p.steps[6].child;
    assert.deepEqual(soft.steps.map((s) => [s.term, s.effective]), [['a:relay.example.net', 'softfail'], ['-all', null]]);
  });

  test('what could not be read: a domain without SPF, two records, a loop, a void lookup, a failed lookup, host bits', async () => {
    const zone = {
      'example.org': { TXT: 'v=spf1 include:none.example.org include:two.example.org include:loop.example.org a:gone.example.org mx:down.example.org ip4:192.0.2.9/24 -all' },
      'none.example.org': { TXT: 'hello' },
      'two.example.org': { TXT: ['v=spf1 -all', 'v=spf1 ~all'] },
      'loop.example.org': { TXT: 'v=spf1 include:example.org -all' }
    };
    const r = await spfLookupCount('example.org', { dns: zoneDns(zone, { fail: { 'down.example.org|MX': 'timeout' } }) });
    const p = spfPolicy(r.tree);
    assert.deepEqual(p.steps.map((s) => s.state), ['no-record', 'multiple-records', 'ok', 'void', 'dns-error', 'ok', 'ok']);
    assert.equal(p.steps[0].child.state, 'no-record');
    assert.equal(p.steps[2].child.steps[0].state, 'loop');
    assert.equal(p.steps[4].detail, 'timeout');
    assert.deepEqual([p.steps[5].params.range, p.steps[5].params.hostBits], ['192.0.2.0/24', true], 'written with host bits: the whole /24');
    assert.equal(spfPolicy(null), null);
    const none = spfPolicy({ domain: 'example.net', record: null, terms: [], errors: [{ code: 'dns-error', domain: 'example.net', target: 'example.net', detail: 'SERVFAIL' }] });
    assert.deepEqual([none.state, none.detail], ['dns-error', 'SERVFAIL']);
    const implicit = spfPolicy((await spfLookupCount('example.net', { dns: zoneDns({}), record: 'v=spf1 ip4:192.0.2.1' })).tree);
    assert.equal(implicit.implicitNeutral, true, 'no all and no redirect: neutral');
    for (const list of [SPF_STEP_KINDS, SPF_STEP_STATES, SPF_POLICY_STATES, SPF_FLATTEN_NOTES]) assert.ok(Object.isFrozen(list));
  });

  test('macroLetters', () => {
    assert.deepEqual(macroLetters('exists:%{ir}.%{v}.%{I}._spf.%{d2}'), ['i', 'v', 'd']);
    assert.deepEqual(macroLetters('include:_spf.example.net'), []);
  });
});

describe('spfMeter', () => {
  test('the budget and the branches that spend it, costliest first', async () => {
    const m = spfMeter(await tree());
    assert.deepEqual([m.count, m.limit, m.voidLimit, m.exceeded], [8, 10, 2, false]);
    assert.deepEqual(m.branches, [
      { term: 'include:_spf.example.net', cost: 2 },
      { term: '~include:soft.example.net', cost: 2 },
      { term: 'a', cost: 1 }, { term: 'mx/24', cost: 1 }, { term: 'exists:%{i}._x.example.com', cost: 1 }, { term: 'ptr', cost: 1 }
    ]);
    const many = spfMeter({ count: 12, voidCount: 3, tree: { terms: [] } });
    assert.deepEqual([many.exceeded, many.high, many.voidExceeded], [true, false, true]);
    assert.equal(spfMeter({ count: 9, voidCount: 0, tree: null }).high, true);
  });
});

describe('spfStringIssues', () => {
  test('a join that breaks a term is reported; one inside a term on purpose is not', () => {
    assert.deepEqual(spfStringIssues(['v=spf1 ip4:192.0.2.0/24', 'include:_spf.example.net -all']), [
      { after: 1, left: 'ip4:192.0.2.0/24', right: 'include:_spf.example.net', joined: 'ip4:192.0.2.0/24include:_spf.example.net' }
    ]);
    assert.deepEqual(spfStringIssues(['v=spf1 ip4:192.0.2.0/24 inclu', 'de:_spf.example.net -all']), [], 'split inside a term');
    assert.deepEqual(spfStringIssues(['v=spf1 ip4:192.0.2.0/24 ', 'include:_spf.example.net -all']), [], 'a space at the end');
    assert.equal(spfStringIssues(['v=spf1', 'include:_spf.example.net -all']).length, 1, 'the version glued to the first term');
    assert.deepEqual(spfStringIssues(['v=spf1 -all']), []);
    assert.deepEqual(spfStringIssues(null), []);
  });
});

describe('spfFlatten', () => {
  const mxAddresses = new Map([['mx1.example.com', { addresses: ['203.0.113.25'], error: null }]]);

  test('a, mx and includes become addresses; sender terms stay; exceptions inside an include make it inexact', async () => {
    const f = spfFlatten((await tree()).tree, { mxAddresses });
    assert.deepEqual(f.terms, [
      'ip4:192.0.2.0/24', 'ip4:198.51.100.7', 'ip6:2001:db8:1::/48',
      // a: 192.0.2.10 is inside 192.0.2.0/24 already; mx/24: its host's /24
      'ip4:203.0.113.0/24',
      // include:_spf.example.net: its passes, its own include's too
      'ip4:198.51.100.128/25', 'ip6:2001:db8:ff::/48',
      // ~include:soft.example.net: what it passes, as softfail
      '~ip4:192.0.2.77',
      'exists:%{i}._x.example.com', 'ptr', '?all', 'exp=explain.example.com', 'foo=bar'
    ]);
    assert.equal(f.lookups, 2, 'the exists and the ptr');
    assert.equal(f.exact, false, '-ip4:198.51.100.200 inside the include cannot be said in a flat list');
    assert.deepEqual(f.notes.map((n) => [n.code, n.term]), [['exceptions', '-ip4:198.51.100.200'], ['sender', 'exists:%{i}._x.example.com'], ['sender', 'ptr']]);
    assert.equal(f.record, `v=spf1 ${f.terms.join(' ')}`);
    assert.deepEqual([f.length, f.strings, f.fits, f.addressTerms], [f.record.length, 1, true, 7]);
  });

  test('a redirect hands over its policy; an include that cannot be flattened is kept by the name it expanded to', async () => {
    const zone = {
      'example.org': { TXT: 'v=spf1 include:%{d}.vendor.example.net mx redirect=_spf.example.org', MX: [{ preference: 10, exchange: 'mx.example.org' }] },
      'example.org.vendor.example.net': { TXT: 'v=spf1 exists:%{i}.allow.example.net -all' },
      '_spf.example.org': { TXT: 'v=spf1 ip4:192.0.2.0/25 -all' }
    };
    const r = await spfLookupCount('example.org', { dns: zoneDns(zone) });
    const f = spfFlatten(r.tree, { mxAddresses: new Map() });
    assert.deepEqual(f.terms, ['include:%{d}.vendor.example.net', 'mx', 'ip4:192.0.2.0/25', '-all']);
    assert.deepEqual(f.notes.map((n) => n.code), ['kept-include', 'failed']);
    assert.equal(f.lookups, 3, 'the kept include (with its exists) and the mx whose hosts are not known');
    assert.equal(f.exact, true);
  });

  test('an include that passes everyone ends the record; a large record needs several strings and does not fit', async () => {
    const open = {
      'example.net': { TXT: 'v=spf1 include:open.example.net ip4:192.0.2.1 -all' },
      'open.example.net': { TXT: 'v=spf1 +all' }
    };
    const f = spfFlatten((await spfLookupCount('example.net', { dns: zoneDns(open) })).tree);
    assert.deepEqual([f.terms, f.exact, f.notes[0].code], [['all'], false, 'passes-all']);
    const many = Array.from({ length: 40 }, (_, i) => `ip4:198.51.100.${i * 4}/30`).join(' ');
    const big = spfFlatten((await spfLookupCount('example.net', { dns: zoneDns({}), record: `v=spf1 ${many} -all` })).tree);
    assert.ok(big.length > SPF_UDP_SAFE_LENGTH && !big.fits && big.strings === Math.ceil(big.length / 255), `${big.length}`);
    assert.equal(spfFlatten(null), null);
  });
});
