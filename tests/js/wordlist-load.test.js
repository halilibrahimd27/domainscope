// Unit tests for loadWordlist() in assets/js/lib/wordlist.js.
//
// The vendored data files are read from disk (Node fs path) for the default
// cases. The browser fetch / gzip-decode / graceful-degrade branches are driven
// under Node with `preferFetch: true` and a mock `fetchImpl` (no network).
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import {
  loadWordlist, clearWordlistCache, WORDLIST_SMALL, WORDLIST_LEVELS, localesForDomain
} from '../../assets/js/lib/wordlist.js';

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const resp = (body, status = 200) => new Response(body, { status });

beforeEach(() => clearWordlistCache());

describe('loadWordlist — levels (fs path)', () => {
  test('small returns extra? + WORDLIST_SMALL, no I/O, fresh copy', async () => {
    const s = await loadWordlist('small');
    assert.deepEqual(s, [...WORDLIST_SMALL]);
    s.push('mutation');
    assert.equal((await loadWordlist('small')).length, WORDLIST_SMALL.length, 'callers cannot corrupt the source');
  });

  test('smart = small → base (~7k), ordered, deduped, all valid labels', async () => {
    const smart = await loadWordlist('smart');
    assert.ok(smart.length >= 6500 && smart.length <= 8000, `len=${smart.length}`);
    WORDLIST_SMALL.forEach((w, i) => assert.equal(smart[i], w, 'small block leads, in order'));
    assert.equal(new Set(smart).size, smart.length, 'deduped');
    for (const w of smart) assert.match(w, LABEL_RE, w);
  });

  test('levels nest: small ⊂ smart ⊂ large ⊂ huge (strict prefixes of one ranking)', async () => {
    const smart = await loadWordlist('smart');
    const large = await loadWordlist('large');
    const huge = await loadWordlist('huge');
    assert.ok(large.length > smart.length && huge.length > large.length);
    smart.forEach((w, i) => assert.equal(large[i], w, 'smart is a prefix of large'));
    large.forEach((w, i) => assert.equal(huge[i], w, 'large is a prefix of huge'));
    assert.equal(new Set(huge).size, huge.length, 'huge deduped');
  });

  test('tiers are cached; each call returns its own array', async () => {
    const a = await loadWordlist('large');
    const b = await loadWordlist('large');
    assert.deepEqual(a, b);
    assert.notEqual(a, b);
  });

  test('unknown level behaves like small', async () => {
    assert.deepEqual(await loadWordlist('gigantic'), [...WORDLIST_SMALL]);
    assert.deepEqual(await loadWordlist(), [...WORDLIST_SMALL]);
  });

  test('WORDLIST_LEVELS is the documented ordered set', () => {
    assert.deepEqual([...WORDLIST_LEVELS], ['small', 'smart', 'large', 'huge']);
  });
});

describe('loadWordlist — extra (learned/custom) first', () => {
  test('valid extra labels lead, deduped and normalised; invalid dropped', async () => {
    const smart = await loadWordlist('smart', { extra: ['zzcustom', 'dev.api', 'ZZCUSTOM', 'bad label', '', 'www'] });
    assert.equal(smart[0], 'zzcustom', 'first extra leads');
    assert.equal(smart[1], 'dev.api', 'multi-label prefix kept');
    // 'www' is both extra and in small — appears once, at the extra position.
    assert.equal(smart.indexOf('www'), 2, 'dedupe keeps the earliest (extra) slot');
    assert.equal(new Set(smart).size, smart.length);
    assert.ok(!smart.includes('bad label'));
  });
});

describe('loadWordlist — locale packs', () => {
  test('localesForDomain maps TLD / ccSLD / ccTLD', () => {
    assert.deepEqual(localesForDomain('example-test.com.tr'), ['tr']);
    assert.deepEqual(localesForDomain('example-test.tr'), ['tr']);
    assert.deepEqual(localesForDomain('beispiel.de'), ['de']);
    assert.deepEqual(localesForDomain('x.ch'), ['de', 'fr', 'it']);
    assert.deepEqual(localesForDomain('y.br'), ['pt']);
    assert.deepEqual(localesForDomain('z.io'), [], 'unknown TLD → none');
    assert.deepEqual(localesForDomain(''), []);
  });

  test('localesForDomain reads the last label (ccTLD) only', () => {
    assert.deepEqual(localesForDomain('example.com.co'), ['es'], 'a ccSLD maps through its ccTLD');
    assert.deepEqual(localesForDomain('example.co.uk'), []);
    assert.deepEqual(localesForDomain('tr.example.com'), [], 'a country-looking first label is ignored');
    assert.deepEqual(localesForDomain('example.tr.com'), [], 'so is a second-level one');
    assert.deepEqual(localesForDomain('EXAMPLE.DE.'), ['de'], 'case and a trailing dot are normalised');
  });

  test('auto-selected locale pack is inserted between small and base', async () => {
    const plain = await loadWordlist('smart');
    const withTr = await loadWordlist('smart', { domain: 'example-test.com.tr' });
    assert.ok(withTr.length > plain.length, 'tr adds labels');
    // 'yonetimpanel' is a tr-only label (not in small or the global base)
    assert.ok(withTr.includes('yonetimpanel'), 'a tr-only label is present');
    assert.ok(!plain.includes('yonetimpanel'), 'and it is not in the plain base');
    // locale labels sit after the small block, before the base-only tail
    assert.ok(withTr.indexOf('yonetimpanel') >= WORDLIST_SMALL.length);
  });

  test('explicit locales override the domain; [] disables', async () => {
    const forced = await loadWordlist('smart', { domain: 'x.io', locales: ['de'] });
    assert.ok(forced.includes('rechnung'), 'forced de pack');
    const none = await loadWordlist('smart', { domain: 'example-test.com.tr', locales: [] });
    assert.ok(!none.includes('yonetimpanel'), '[] disables locale packs');
  });
});

describe('loadWordlist — browser fetch / gzip / degrade (mock fetchImpl)', () => {
  const baseTxt = 'alpha\nbeta\n# comment\n\ngamma\n';
  const makeFetch = (over = {}) => async (url) => {
    const u = String(url);
    if ('base' in over && u.endsWith('wordlist-base.txt')) return over.base(u);
    if ('large' in over && u.endsWith('wordlist-large.txt.gz')) return over.large(u);
    if ('huge' in over && u.endsWith('wordlist-huge.txt.gz')) return over.huge(u);
    if (u.endsWith('wordlist-base.txt')) return resp(baseTxt);
    if (u.endsWith('wordlist-large.txt.gz')) return resp(gzipSync(Buffer.from('largeone\nlargetwo\n')));
    if (u.endsWith('wordlist-huge.txt.gz')) return resp(gzipSync(Buffer.from('hugeone\n')));
    if (u.includes('/locale/')) return resp('', 404);
    return resp('', 404);
  };

  test('gzip tier decoded via the fetch path (gzip magic detected)', async () => {
    const large = await loadWordlist('large', { preferFetch: true, fetchImpl: makeFetch() });
    assert.ok(large.includes('largeone') && large.includes('largetwo'));
    WORDLIST_SMALL.forEach((w, i) => assert.equal(large[i], w));
  });

  test('a non-gzip body (Pages already decompressed) is read as text', async () => {
    const fetchImpl = makeFetch({ large: () => resp('plainone\nplaintwo\n') });
    const large = await loadWordlist('large', { preferFetch: true, fetchImpl });
    assert.ok(large.includes('plainone') && large.includes('plaintwo'));
  });

  test('degrade: a failing tier falls back to the next smaller one and reports it', async () => {
    let info = null;
    const fetchImpl = makeFetch({ huge: () => { throw new TypeError('offline'); } });
    const list = await loadWordlist('huge', {
      preferFetch: true, fetchImpl, onInfo: (i) => { if (i.type === 'degrade') info = i; }
    });
    assert.ok(info && info.requested === 'huge' && info.served === 'large', JSON.stringify(info));
    assert.ok(list.includes('largeone'), 'served the large tier');
  });

  test('a stalled response or body ends in a timeout: the tier degrades instead of hanging the scan', async () => {
    let info = null;
    const onInfo = (i) => { if (i.type === 'degrade') info = i; };
    // No answer at all (a fetch that ignores its signal too).
    const silent = makeFetch({ huge: () => new Promise(() => {}) });
    const list = await loadWordlist('huge', { preferFetch: true, fetchImpl: silent, timeoutMs: 50, onInfo });
    assert.ok(info && info.requested === 'huge' && info.served === 'large', JSON.stringify(info));
    assert.ok(list.includes('largeone'), 'served the large tier');
    // Headers, then a body that never ends.
    clearWordlistCache();
    info = null;
    const stuck = makeFetch({ large: () => new Response(new ReadableStream({ start() {} }), { status: 200 }) });
    const smart = await loadWordlist('large', { preferFetch: true, fetchImpl: stuck, timeoutMs: 50, onInfo });
    assert.ok(info && info.requested === 'large' && info.served === 'smart', JSON.stringify(info));
    assert.ok(smart.includes('gamma'), 'served the base tier');
  });

  test('degrade all the way to small when every tier fails', async () => {
    const fail = () => { throw new TypeError('offline'); };
    const fetchImpl = makeFetch({ base: fail, large: fail, huge: fail });
    let served = null;
    const list = await loadWordlist('huge', {
      preferFetch: true, fetchImpl, onInfo: (i) => { if (i.type === 'degrade') served = i.served; }
    });
    assert.equal(served, 'small');
    assert.deepEqual(list, [...WORDLIST_SMALL], 'usable small list returned');
  });

  test('a failing locale pack is skipped (non-fatal), tier still loads', async () => {
    const fetchImpl = makeFetch();
    let missing = null;
    const list = await loadWordlist('large', {
      preferFetch: true, fetchImpl, domain: 'example-test.com.tr', onInfo: (i) => { if (i.type === 'locale-missing') missing = i.locale; }
    });
    assert.equal(missing, 'tr', 'reported the missing pack');
    assert.ok(list.includes('largeone'), 'tier still loaded');
  });

  test('an aborted signal propagates (never swallowed as a degrade)', async () => {
    const ctl = new AbortController();
    ctl.abort();
    const abortingFetch = async () => { const e = new Error('aborted'); e.name = 'AbortError'; throw e; };
    await assert.rejects(
      loadWordlist('large', { preferFetch: true, signal: ctl.signal, fetchImpl: abortingFetch }),
      (e) => e.name === 'AbortError'
    );
  });
});
