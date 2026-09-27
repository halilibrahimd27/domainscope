// Unit tests for wordlistInfo() and parseCustomWordlist() in wordlist.js.
// wordlistInfo counts/bytes are build-time constants embedded in the module;
// these tests assert they match the actual data files on disk, so the constants
// can never silently drift from what tools/build-wordlists.mjs produced.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { wordlistInfo, parseCustomWordlist, LOCALE_PACK_CODES } from '../../assets/js/lib/wordlist.js';
import { fileDigest } from '../../tools/build-wordlists.mjs';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'assets', 'data');
const linesOf = (buf) => buf.toString('utf8').split(/\r?\n/).filter(Boolean).length;

describe('wordlistInfo', () => {
  const info = wordlistInfo();

  test('every level exposes { id, approxCount, bytes, sources, licence }', () => {
    for (const id of ['small', 'smart', 'large', 'huge']) {
      const lv = info.levels[id];
      assert.equal(lv.id, id);
      assert.ok(Number.isFinite(lv.approxCount) && lv.approxCount > 0);
      assert.ok(Array.isArray(lv.sources) && lv.sources.length);
      assert.ok(typeof lv.licence === 'string' && lv.licence.length);
    }
  });

  test('embedded counts match the actual data files', () => {
    const base = linesOf(readFileSync(join(DATA, 'wordlist-base.txt')));
    const large = linesOf(gunzipSync(readFileSync(join(DATA, 'wordlist-large.txt.gz'))));
    const huge = linesOf(gunzipSync(readFileSync(join(DATA, 'wordlist-huge.txt.gz'))));
    assert.equal(info.levels.smart.approxCount, base, 'smart count == base.txt lines');
    assert.equal(info.levels.large.approxCount, large);
    assert.equal(info.levels.huge.approxCount, huge);
  });

  test('embedded byte sizes match the files on disk', () => {
    assert.equal(info.levels.smart.bytes, statSync(join(DATA, 'wordlist-base.txt')).size);
    assert.equal(info.levels.large.bytes, statSync(join(DATA, 'wordlist-large.txt.gz')).size);
    assert.equal(info.levels.huge.bytes, statSync(join(DATA, 'wordlist-huge.txt.gz')).size);
  });

  test('wordlist-manifest.json carries the SHA-256 of every tier and locale pack (the service worker\'s cache key)', () => {
    const manifest = JSON.parse(readFileSync(join(DATA, 'wordlist-manifest.json'), 'utf8'));
    const digest = (rel) => createHash('sha256').update(readFileSync(join(DATA, rel))).digest('hex');
    const files = Object.values(manifest.tiers).filter((tier) => tier.file);
    assert.deepEqual(files.map((tier) => tier.file), ['wordlist-base.txt', 'wordlist-large.txt.gz', 'wordlist-huge.txt.gz']);
    for (const tier of files) assert.equal(tier.sha256, digest(tier.file), tier.file);
    assert.deepEqual(Object.keys(manifest.locales).sort(), [...LOCALE_PACK_CODES].sort());
    for (const [cc, info] of Object.entries(manifest.locales)) assert.equal(info.sha256, digest(`locale/${cc}.txt`), cc);
    // the builder writes the same digest it reports
    assert.deepEqual(fileDigest(Buffer.from('api\nwww\n')), { bytes: 8, sha256: createHash('sha256').update('api\nwww\n').digest('hex') });
  });

  test('gz tiers stay comfortably under 1.5 MiB', () => {
    assert.ok(info.levels.large.bytes < 1.5 * 1024 * 1024, `large=${info.levels.large.bytes}`);
    assert.ok(info.levels.huge.bytes < 1.5 * 1024 * 1024, `huge=${info.levels.huge.bytes}`);
  });

  test('every locale pack count/bytes match its file', () => {
    for (const cc of LOCALE_PACK_CODES) {
      const path = join(DATA, 'locale', `${cc}.txt`);
      const buf = readFileSync(path);
      assert.equal(info.locales[cc].approxCount, linesOf(buf), `${cc} count`);
      assert.equal(info.locales[cc].bytes, statSync(path).size, `${cc} bytes`);
      assert.ok(info.locales[cc].licence.includes('MIT'), `${cc} licence`);
    }
  });
});

describe('parseCustomWordlist', () => {
  test('accepts bare labels and multi-label prefixes, split on lines/commas/space', () => {
    const { labels, rejected } = parseCustomWordlist('api, admin\ndev.api  billing\nSHOP');
    assert.deepEqual(labels, ['api', 'admin', 'dev.api', 'billing', 'shop']);
    assert.deepEqual(rejected, []);
  });

  test('lowercases, strips a trailing dot, dedupes, skips comment lines/blank', () => {
    const { labels } = parseCustomWordlist('API\napi.\n# a whole-line comment\n\nApi');
    assert.deepEqual(labels, ['api']);
  });

  test('rejects invalid tokens but keeps the valid ones', () => {
    const { labels, rejected } = parseCustomWordlist('good\n-bad-\nlead-.trail\nok2');
    assert.ok(labels.includes('good') && labels.includes('ok2'));
    assert.ok(rejected.includes('-bad-'));
  });

  test('IDN labels are converted to punycode (and dedupe with their ASCII form)', () => {
    const { labels, rejected } = parseCustomWordlist('şube\nBücher\nxn--ube-rza\ndev.şube\n_dmarc\ndev_api');
    assert.deepEqual(labels, ['xn--ube-rza', 'xn--bcher-kva', 'dev.xn--ube-rza', '_dmarc', 'dev_api']);
    assert.deepEqual(rejected, []);
    // still rejected: too long once converted, or not a label at all
    const bad = parseCustomWordlist(`${'ş'.repeat(60)}\nşu/be\nş@x`);
    assert.deepEqual(bad.labels, []);
    assert.deepEqual(bad.rejected, [`${'ş'.repeat(60)}`, 'şu/be', 'ş@x']);
  });

  test('caps at 200k labels', () => {
    const many = Array.from({ length: 200050 }, (_, i) => `l${i}`).join('\n');
    const { labels } = parseCustomWordlist(many);
    assert.equal(labels.length, 200000);
  });

  test('empty / non-string input yields empty result', () => {
    assert.deepEqual(parseCustomWordlist(''), { labels: [], rejected: [] });
    assert.deepEqual(parseCustomWordlist(undefined), { labels: [], rejected: [] });
  });
});
