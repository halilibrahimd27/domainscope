// Data-quality + privacy tests for the shipped wordlist tiers (assets/data).
// These read the files tools/build-wordlists.mjs produced and assert the junk /
// spam / offensive filter did its job and that no private-denylist term leaked
// into the gzipped tiers (the one repo data the git hooks / `git grep` cannot
// see inside). No network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { GAMBLING_SEO_RE, KEYBOARD_MASH, CONTENT_DENYLIST, isBannedLabel } from '../../tools/build-wordlists.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DATA = join(ROOT, 'assets', 'data');
const labelsOf = (buf) => buf.toString('utf8').split(/\r?\n/).filter(Boolean);

const base = labelsOf(readFileSync(join(DATA, 'wordlist-base.txt')));
const large = labelsOf(gunzipSync(readFileSync(join(DATA, 'wordlist-large.txt.gz'))));
const huge = labelsOf(gunzipSync(readFileSync(join(DATA, 'wordlist-huge.txt.gz'))));

describe('wordlist data quality', () => {
  test('no gambling / SEO spam, keyboard mash, cf-protected or banned content in any tier', () => {
    for (const [name, list] of [['base', base], ['large', large], ['huge', huge]]) {
      const bad = list.filter((l) => isBannedLabel(l));
      assert.equal(bad.length, 0, `${name} still ships banned labels: ${bad.slice(0, 10).join(', ')}`);
      // spot-check the categories directly too
      assert.ok(!list.some((l) => GAMBLING_SEO_RE.test(l)), `${name} has gambling/SEO spam`);
      assert.ok(!list.some((l) => KEYBOARD_MASH.has(l)), `${name} has keyboard mash`);
      assert.ok(!list.some((l) => CONTENT_DENYLIST.has(l)), `${name} has denylisted content`);
      assert.ok(!list.some((l) => l.startsWith('cf-protected')), `${name} has cf-protected*`);
    }
  });

  test('the dependable head is intact: common service labels are in the smart base', () => {
    const set = new Set(base);
    for (const w of ['cert', 'api', 'vpn', 'www', 'mail', 'admin', 'dev', 'staging']) {
      assert.ok(set.has(w), `smart base missing ${w}`);
    }
  });

  test('tiers are strict prefixes: base ⊂ large ⊂ huge', () => {
    assert.deepEqual(large.slice(0, base.length), base);
    assert.deepEqual(huge.slice(0, large.length), large);
  });
});

describe('private-data guard covers the gzipped tiers', () => {
  const denylistPath = join(ROOT, '.private-denylist');
  // .private-denylist is gitignored (local only). Skip in CI where it is absent.
  test('no shipped label matches .private-denylist', { skip: !existsSync(denylistPath) }, () => {
    const patterns = readFileSync(denylistPath, 'utf8')
      .split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
      .map((p) => new RegExp(p, 'i'));
    const locales = ['tr', 'de', 'fr', 'es', 'pt', 'it', 'nl', 'pl', 'ru', 'ar', 'ja', 'zh']
      .flatMap((cc) => labelsOf(readFileSync(join(DATA, 'locale', `${cc}.txt`))));
    let matches = 0;
    for (const list of [base, large, huge, locales]) {
      for (const label of list) if (patterns.some((re) => re.test(label))) matches += 1;
    }
    assert.equal(matches, 0, 'a private-denylist term leaked into the shipped wordlist data');
  });
});
