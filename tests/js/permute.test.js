// Unit tests for assets/js/lib/permute.js — pure, no network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { permutations, DEFAULT_ENVS, DEFAULT_WORDS, DEFAULT_REGIONS, DEFAULT_SUFFIXES } from '../../assets/js/lib/permute.js';

const LABELS_RE = /^(?!-)[a-z0-9_-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$/;

describe('permutations', () => {
  test('numbers, env dash, env dot, word swaps from a single seed', () => {
    const out = permutations(['api.example.com'], 'example.com', { budget: 300 });
    const set = new Set(out);
    // numbers
    assert.ok(set.has('api2.example.com'));
    assert.ok(set.has('api3.example.com'));
    // env dash prefix + suffix
    assert.ok(set.has('dev-api.example.com'));
    assert.ok(set.has('api-dev.example.com'));
    // env as a new dot-label (level insertion)
    assert.ok(set.has('dev.api.example.com'));
    assert.ok(set.has('api.dev.example.com'));
    // sibling word swaps (api ∈ DEFAULT_WORDS)
    assert.ok(set.has('app.example.com'));
    assert.ok(set.has('admin.example.com'));
    // every candidate is a valid hostname under the domain and never the apex
    for (const name of out) {
      assert.ok(name.endsWith('.example.com'), name);
      const sub = name.slice(0, -'.example.com'.length);
      assert.match(sub, LABELS_RE, name);
      assert.notEqual(name, 'example.com');
    }
  });

  test('numeric labels increment/decrement preserving zero-pad width', () => {
    const out = new Set(permutations(['web01.example.com'], 'example.com', { budget: 50 }));
    assert.ok(out.has('web02.example.com'));
    assert.ok(out.has('web00.example.com'));
    assert.ok(out.has('web03.example.com'));
    assert.ok(!out.has('web0-1.example.com'));

    const out2 = new Set(permutations(['api2.example.com'], 'example.com', { budget: 50 }));
    assert.ok(out2.has('api3.example.com'));
    assert.ok(out2.has('api1.example.com'));
    assert.ok(out2.has('api4.example.com'));
  });

  test('multi-label seeds mutate the left-most label, keeping the rest', () => {
    const out = new Set(permutations(['stg.api.example.com'], 'example.com', { budget: 200 }));
    assert.ok(out.has('stg2.api.example.com'));
    assert.ok(out.has('dev-stg.api.example.com'));
    assert.ok(out.has('stg-dev.api.example.com'));
    assert.ok(out.has('dev.stg.api.example.com'));
  });

  test('already-known names (and the apex) are excluded', () => {
    const found = ['api.example.com', 'api2.example.com'];
    const out = permutations(found, 'example.com', { budget: 500 });
    assert.ok(!out.includes('api2.example.com'), 'known api2 excluded');
    assert.ok(!out.includes('example.com'));
    assert.ok(out.includes('api3.example.com'));
  });

  test('respects the budget exactly and is deterministic', () => {
    const found = ['api.example.com', 'web.example.com', 'panel.example.com'];
    const a = permutations(found, 'example.com', { budget: 40 });
    const b = permutations(found, 'example.com', { budget: 40 });
    assert.equal(a.length, 40);
    assert.deepEqual(a, b);
    assert.equal(new Set(a).size, a.length, 'no duplicates');
  });

  test('ranking: numbers come before regions', () => {
    const out = permutations(['api.example.com'], 'example.com', { budget: 400 });
    const iNum = out.indexOf('api2.example.com');
    const iRegion = out.indexOf('us-api.example.com');
    assert.ok(iNum >= 0 && iRegion >= 0);
    assert.ok(iNum < iRegion, 'number variants rank above region variants');
  });

  test('service-suffix tier: base → baseapi / baseadmin (the base→baseX pattern)', () => {
    // Pattern backed by the public lists: billing → billingapi, shop → shopweb / shopadmin,
    // app → appws. Such plain-HTTP endpoints rarely appear in CT logs.
    const out = new Set(permutations(
      ['billing.example.com', 'shop.example.com', 'app.example.com'], 'example.com', { budget: 800 }
    ));
    assert.ok(out.has('billingapi.example.com'));
    assert.ok(out.has('billingws.example.com'));
    assert.ok(out.has('shopweb.example.com'));
    assert.ok(out.has('shopadmin.example.com'));
    assert.ok(out.has('shopapi.example.com'));
    assert.ok(out.has('appws.example.com'));
    // multi-label seed appends to the left-most label, keeping the rest
    const deep = new Set(permutations(['billing.internal.example.com'], 'example.com', { budget: 200 }));
    assert.ok(deep.has('billingapi.internal.example.com'));
  });

  test('service-suffix tier ranks above env/region variants and skips redundant suffixes', () => {
    const out = permutations(['billing.example.com'], 'example.com', { budget: 400 });
    const iSuffix = out.indexOf('billingapi.example.com');
    const iEnvDash = out.indexOf('dev-billing.example.com');
    const iRegion = out.indexOf('us-billing.example.com');
    assert.ok(iSuffix >= 0 && iEnvDash >= 0 && iRegion >= 0);
    assert.ok(iSuffix < iEnvDash && iSuffix < iRegion, 'suffix tier ranks above env/region tiers');
    // a label already ending in the suffix is not doubled (api → apiapi is skipped)
    const fromApi = new Set(permutations(['api.example.com'], 'example.com', { budget: 400 }));
    assert.ok(!fromApi.has('apiapi.example.com'), 'no api → apiapi');
  });

  test('budget is shared fairly: a seed listed last still gets its service-suffix variants', () => {
    // 300 prior names then billing last, at the default budget — billingapi must
    // still be generated (previously the number tier of the first seeds ate the
    // whole budget and later seeds never reached the service-suffix tier).
    const found = [];
    for (let i = 0; i < 300; i += 1) found.push(`host${i}.example.com`);
    found.push('billing.example.com');
    const out = permutations(found, 'example.com', { budget: 1500 });
    assert.ok(out.length <= 1500);
    assert.ok(out.includes('billingapi.example.com'), 'the trailing seed still reaches the service-suffix tier');
  });

  test('custom suffixes override the default service set', () => {
    const out = new Set(permutations(['base.example.com'], 'example.com', {
      budget: 200, suffixes: ['xyz']
    }));
    assert.ok(out.has('basexyz.example.com'));
    assert.ok(!out.has('baseapi.example.com'), 'default suffixes not used when overridden');
  });

  test('custom words / envs / regions', () => {
    const out = new Set(permutations(['api.example.com'], 'example.com', {
      budget: 500, envs: ['x'], words: ['api', 'zzz'], regions: ['q']
    }));
    assert.ok(out.has('x-api.example.com'));
    assert.ok(out.has('api-x.example.com'));
    assert.ok(out.has('zzz.example.com'), 'word swap api → zzz');
    assert.ok(out.has('q-api.example.com'));
    assert.ok(!out.has('dev-api.example.com'), 'default envs not used');
  });

  test('edge cases: no seeds, apex-only, wildcard, non-subdomain, zero budget', () => {
    assert.deepEqual(permutations([], 'example.com'), []);
    assert.deepEqual(permutations(['example.com'], 'example.com'), []);
    assert.deepEqual(permutations(['*.api.example.com'], 'example.com'), []);
    assert.deepEqual(permutations(['api.other.com'], 'example.com'), []);
    assert.deepEqual(permutations(['api.example.com'], 'example.com', { budget: 0 }), []);
    assert.deepEqual(permutations(['api.example.com'], 'not a domain'), []);
  });

  test('default token sets are non-empty and frozen', () => {
    assert.ok(DEFAULT_ENVS.length >= 15 && Object.isFrozen(DEFAULT_ENVS));
    assert.ok(DEFAULT_WORDS.length >= 10 && Object.isFrozen(DEFAULT_WORDS));
    assert.ok(DEFAULT_REGIONS.includes('eu') && Object.isFrozen(DEFAULT_REGIONS));
    for (const local of ['tr', 'ist', 'ank', 'izm']) assert.ok(!DEFAULT_REGIONS.includes(local), `global defaults: ${local}`);
    assert.ok(DEFAULT_SUFFIXES.includes('api') && DEFAULT_SUFFIXES.includes('web') && Object.isFrozen(DEFAULT_SUFFIXES));
  });

  test('service suffixes are ranked by public-list frequency (wordlist-huge), never tuned to one zone', async () => {
    const { loadWordlist } = await import('../../assets/js/lib/wordlist.js');
    const huge = await loadWordlist('huge', { locales: [] });
    const set = new Set(huge);
    // `<label><suffix>` in the public list where `<label>` is itself a listed label.
    const freq = (suf) => huge.filter((l) => l !== suf && l.endsWith(suf) && l.length - suf.length > 1 && set.has(l.slice(0, -suf.length))).length;
    const counts = DEFAULT_SUFFIXES.map(freq);
    for (let i = 1; i < counts.length; i += 1) {
      assert.ok(counts[i - 1] >= counts[i], `${DEFAULT_SUFFIXES[i - 1]} (${counts[i - 1]}) ranks at or above ${DEFAULT_SUFFIXES[i]} (${counts[i]})`);
    }
    assert.ok(counts.every((c) => c >= 5), `every default suffix is common in the public list: ${counts.join(',')}`);
  });

  test('exclude: excluded names are never emitted and do not use up the budget', () => {
    const seeds = ['api.example.com', 'shop.example.com'];
    const plain = permutations(seeds, 'example.com', { budget: 60 });
    const excluded = new Set(plain.slice(0, 20));
    const out = permutations(seeds, 'example.com', { budget: 60, exclude: excluded });
    assert.equal(out.length, 60, 'the budget is still filled');
    assert.ok(!out.some((n) => excluded.has(n)), 'no excluded name emitted');
    const outSet = new Set(out);
    assert.ok(plain.slice(20).every((n) => outSet.has(n)), 'every non-excluded name of the plain run is still there');
  });
});
