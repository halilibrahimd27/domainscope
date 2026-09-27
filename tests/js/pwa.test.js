/**
 * The installable app's pure parts (lib/pwa.js) and its static files: where a page of the Pages
 * bundle finds the service worker, what the worker of a deploy precaches (the real repository's
 * list too: every module and stylesheet, never a wordlist), the hash keys of the wordlist cache,
 * and the two web app manifests with their icons. No network, no browser.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CACHE_PREFIX, WORDLIST_CACHE, MANIFEST_FILES, PRECACHE_SKIP, UPDATE_CHECK_MS,
  bundleInfo, buildSwManifest, manifestFor, shellCacheName, updateCheckDue, wordlistCacheKey, wordlistFiles
} from '../../assets/js/lib/pwa.js';
import { listFiles, SHELL_ROOT_FILES } from '../../tools/assemble-site.mjs';
import { VIEWS } from '../../assets/js/app.js';
import { t, setLang, getLang } from '../../assets/js/i18n.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const MANIFEST = {
  tiers: {
    small: { id: 'small', file: null },
    smart: { id: 'smart', file: 'wordlist-base.txt', sha256: HASH_A },
    large: { id: 'large', file: 'wordlist-large.txt.gz', sha256: HASH_B }
  },
  locales: { tr: { count: 3, sha256: HASH_A } }
};
const ASSET_FILES = ['css/style.css', 'data/README.md', 'data/locale/tr.txt', 'data/sample-cert.pem', 'data/wordlist-base.txt',
  'data/wordlist-large.txt.gz', 'data/wordlist-manifest.json', 'js/app.js', 'js/views/cert.js'];

describe('bundleInfo', () => {
  test('finds the site root, version and service worker of a Pages bundle module', () => {
    assert.deepEqual(bundleInfo('https://example.github.io/domainscope/v/0123456789ab/assets/js/ui/pwa.js'), {
      root: 'https://example.github.io/domainscope/',
      version: '0123456789ab',
      assets: 'https://example.github.io/domainscope/v/0123456789ab/assets/',
      serviceWorker: 'https://example.github.io/domainscope/sw.js'
    });
    assert.equal(bundleInfo('http://127.0.0.1:8080/v/e2e-one/assets/js/app.js').root, 'http://127.0.0.1:8080/');
    assert.equal(bundleInfo('https://example.com/a/v/1.2/assets/js/app.js?x=1#y').version, '1.2');
  });

  test('is null in the repository (development) and for anything else', () => {
    for (const url of [
      'http://127.0.0.1:8080/domainscope/assets/js/app.js', // npm run serve
      'file:///repo/v/abc/assets/js/app.js',
      'https://example.com/v/../assets/js/app.js',
      'https://example.com/v/a b/assets/js/app.js',
      'https://example.com/v/abc/assets/css/style.css',
      'https://example.com/v/../../assets/js/app.js',
      'not a url', '', null, undefined
    ]) {
      assert.equal(bundleInfo(url), null, String(url));
    }
  });
});

describe('cache names and keys', () => {
  test('one shell cache per version, every name under the prefix', () => {
    assert.equal(shellCacheName('0123456789ab'), 'domainscope-shell-0123456789ab');
    assert.ok(WORDLIST_CACHE.startsWith(CACHE_PREFIX) && shellCacheName('x').startsWith(CACHE_PREFIX));
    for (const bad of ['', '..', 'a/b', 'a b', null]) assert.throws(() => shellCacheName(bad), /Invalid version/);
  });

  test('a wordlist is keyed by its content hash and file name, the same in every deploy', () => {
    assert.equal(wordlistCacheKey(HASH_A, 'locale/tr.txt'), `wordlists/${HASH_A}/tr.txt`);
    assert.equal(wordlistCacheKey(HASH_B, 'wordlist-large.txt.gz'), `wordlists/${HASH_B}/wordlist-large.txt.gz`);
    for (const bad of [undefined, '', 'A'.repeat(64), 'a'.repeat(63), `${'a'.repeat(63)}g`]) {
      assert.throws(() => wordlistCacheKey(bad, 'wordlist-base.txt'), /Invalid SHA-256/, String(bad));
    }
    assert.throws(() => wordlistCacheKey(HASH_A, 'x/'), /Invalid wordlist file/);
  });

  test('wordlistFiles lists the tier files and the locale packs', () => {
    assert.deepEqual(wordlistFiles(MANIFEST), [
      { file: 'wordlist-base.txt', sha256: HASH_A },
      { file: 'wordlist-large.txt.gz', sha256: HASH_B },
      { file: 'locale/tr.txt', sha256: HASH_A }
    ]);
    assert.deepEqual(wordlistFiles(null), []);
  });
});

describe('buildSwManifest', () => {
  const build = buildSwManifest({
    version: 'v1', rootFiles: ['favicon.svg', 'index.html', 'manifest.webmanifest'], assetFiles: ASSET_FILES, wordlistManifest: MANIFEST
  });

  test('precaches index.html as ./ first, the root files, then the app shell of this version', () => {
    assert.deepEqual(build.precache, [
      './', 'favicon.svg', 'manifest.webmanifest',
      'v/v1/assets/css/style.css', 'v/v1/assets/data/sample-cert.pem', 'v/v1/assets/js/app.js', 'v/v1/assets/js/views/cert.js'
    ]);
    assert.equal(build.shellCache, 'domainscope-shell-v1');
    assert.equal(build.wordlistCache, WORDLIST_CACHE);
    assert.equal(build.cachePrefix, CACHE_PREFIX);
  });

  test('keeps the wordlists out of the precache and keys them by hash', () => {
    assert.deepEqual(build.wordlists, {
      'v/v1/assets/data/wordlist-base.txt': `wordlists/${HASH_A}/wordlist-base.txt`,
      'v/v1/assets/data/wordlist-large.txt.gz': `wordlists/${HASH_B}/wordlist-large.txt.gz`,
      'v/v1/assets/data/locale/tr.txt': `wordlists/${HASH_A}/tr.txt`
    });
    assert.ok(!build.precache.some((p) => /wordlist|locale|README|manifest\.json/.test(p)));
  });

  test('refuses a wordlist without a hash, a listed file that is missing and an unlisted wordlist file', () => {
    const noHash = { tiers: { smart: { file: 'wordlist-base.txt' } }, locales: {} };
    assert.throws(() => buildSwManifest({ version: 'v1', assetFiles: ['data/wordlist-base.txt'], wordlistManifest: noHash }), /Invalid SHA-256/);
    assert.throws(() => buildSwManifest({ version: 'v1', assetFiles: ['js/app.js'], wordlistManifest: MANIFEST }), /not in assets\/data/);
    assert.throws(() => buildSwManifest({
      version: 'v1', assetFiles: [...ASSET_FILES, 'data/locale/xx.txt'], wordlistManifest: MANIFEST
    }), /missing from wordlist-manifest\.json: data\/locale\/xx\.txt/);
    assert.throws(() => buildSwManifest({ version: '../x', assetFiles: [], wordlistManifest: {} }), /Invalid version/);
  });
});

const assetFiles = await listFiles(join(ROOT, 'assets'));

describe('the repository\'s service worker manifest', () => {
  const wordlistManifest = JSON.parse(readFileSync(join(ROOT, 'assets', 'data', 'wordlist-manifest.json'), 'utf8'));
  const build = buildSwManifest({ version: 'x', rootFiles: [...SHELL_ROOT_FILES], assetFiles, wordlistManifest });
  const shell = new Set(build.precache);

  test('precaches every module and stylesheet (every view opens offline), the sample and the licences', () => {
    for (const f of assetFiles.filter((f) => /\.(?:js|css)$/.test(f))) assert.ok(shell.has(`v/x/assets/${f}`), f);
    for (const v of VIEWS) {
      assert.ok(shell.has(`v/x/assets/js/views/${v.id}.js`), v.id);
      for (const css of v.css) assert.ok(shell.has(`v/x/assets/css/${css}`), css);
    }
    for (const f of ['data/sample-cert.pem', 'data/THIRD_PARTY_LICENSES.txt']) assert.ok(shell.has(`v/x/assets/${f}`), f);
    for (const f of ['./', 'favicon.svg', 'manifest.webmanifest', 'manifest.tr.webmanifest']) assert.ok(shell.has(f), f);
  });

  test('every wordlist tier and locale pack is hash-keyed, none precached, and nothing is left out by accident', () => {
    const words = Object.keys(build.wordlists);
    assert.equal(words.length, 3 + Object.keys(wordlistManifest.locales).length);
    assert.ok(words.every((p) => !shell.has(p)));
    const accounted = new Set([...build.precache, ...words].map((p) => p.replace('v/x/assets/', '')));
    assert.deepEqual(assetFiles.filter((f) => !accounted.has(f)), [...PRECACHE_SKIP].sort());
    // The Huge tier alone is larger than the whole precache would be without it.
    assert.ok(!build.precache.some((p) => p.endsWith('.gz')));
  });

  test('the files the app reads through import.meta.url are precached', () => {
    const refs = [];
    for (const f of assetFiles.filter((f) => f.endsWith('.js'))) {
      const src = readFileSync(join(ROOT, 'assets', ...f.split('/')), 'utf8');
      for (const m of src.matchAll(/new URL\(\s*'(\.\.\/\.\.\/data\/[^'$]+)'\s*,\s*import\.meta\.url\s*\)/g)) {
        refs.push(new URL(m[1], `https://example.com/v/x/assets/${f}`).pathname.slice(1));
      }
    }
    assert.ok(refs.length >= 2, refs.join(', '));
    for (const r of refs) assert.ok(shell.has(r), r);
  });
});

describe('web app manifests', () => {
  const read = (file) => JSON.parse(readFileSync(join(ROOT, file), 'utf8'));
  const en = read(MANIFEST_FILES.en);
  const tr = read(MANIFEST_FILES.tr);
  /** Width and height from a PNG's IHDR chunk. */
  const pngSize = (file) => {
    const buf = readFileSync(join(ROOT, file));
    assert.equal(buf.subarray(1, 4).toString('latin1'), 'PNG', `${file} is a PNG`);
    return `${buf.readUInt32BE(16)}x${buf.readUInt32BE(20)}`;
  };

  /**
   * The app's identity as a browser computes it (W3C Web App Manifest, "processing the id member"):
   * start_url resolves against the manifest's URL, but `id` against start_url's origin — so an id
   * of './' would be the origin root, not the project path. Without `id` it is start_url.
   */
  const appId = (m, manifestUrl) => {
    const start = new URL(m.start_url ?? '', manifestUrl);
    const id = typeof m.id === 'string' ? new URL(m.id, start.origin) : start;
    id.hash = '';
    return id.href;
  };

  test('the app\'s identity is its /<repo>/ path, not the origin, and the same in both languages', () => {
    for (const site of ['https://example.github.io/domainscope/', 'https://example.github.io/a-fork/', 'https://example.com/']) {
      for (const m of [en, tr]) {
        const url = new URL(MANIFEST_FILES.en, site).href;
        assert.equal(appId(m, url), site, `${m.lang} at ${site}`);
        assert.ok(appId(m, url).startsWith(new URL(m.scope, url).href), 'inside the scope');
      }
    }
    // What `"id": "./"` did: every app of the origin would share the identity of its root.
    assert.equal(appId({ ...en, id: './' }, 'https://example.github.io/domainscope/manifest.webmanifest'), 'https://example.github.io/');
  });

  test('one app (same start_url and scope for the /<repo>/ subpath), installable icons in both languages', () => {
    for (const m of [en, tr]) {
      assert.equal(m.id, undefined, 'no id: it defaults to start_url (see above)');
      assert.equal(m.start_url, './');
      assert.equal(m.scope, './');
      assert.equal(m.display, 'standalone');
      assert.equal(m.short_name, 'DomainScope');
      assert.match(m.theme_color, /^#[0-9a-f]{6}$/);
      assert.match(m.background_color, /^#[0-9a-f]{6}$/);
      assert.deepEqual(m.icons, en.icons, 'the same icons');
      for (const icon of m.icons) {
        assert.ok(existsSync(join(ROOT, icon.src)), icon.src);
        assert.ok(!icon.src.startsWith('/') && !icon.src.startsWith('assets/'), `${icon.src}: stable, site-relative`);
        if (icon.type === 'image/png') assert.equal(pngSize(icon.src), icon.sizes, icon.src);
      }
      assert.ok(m.icons.some((i) => i.sizes === '192x192') && m.icons.some((i) => i.sizes === '512x512' && !i.purpose));
      assert.ok(m.icons.some((i) => i.purpose === 'maskable'));
    }
    assert.equal(en.lang, 'en');
    assert.equal(tr.lang, 'tr');
    assert.equal(pngSize('icons/apple-touch-icon.png'), '180x180');
  });

  test('the colours are the light theme\'s (index.html\'s meta theme-color follows the dark one)', () => {
    const html = readFileSync(join(ROOT, 'index.html'), 'utf8');
    const light = /<meta name="theme-color" content="(#[0-9a-f]{6})" media="\(prefers-color-scheme: light\)">/.exec(html)[1];
    assert.match(html, /<meta name="theme-color" content="#[0-9a-f]{6}" media="\(prefers-color-scheme: dark\)">/);
    for (const m of [en, tr]) assert.equal(m.theme_color, light);
  });

  test('names, description and shortcuts are in the manifest\'s language; shortcuts open real views', () => {
    const prev = getLang();
    try {
      for (const [m, lang] of [[en, 'en'], [tr, 'tr']]) {
        setLang(lang);
        assert.equal(m.name, `${t('app.name')} — ${t('app.subtitle')}`);
        for (const s of m.shortcuts) {
          const id = /^\.\/#\/([a-z]+)$/.exec(s.url)?.[1];
          assert.ok(VIEWS.some((v) => v.id === id), s.url);
          assert.equal(s.name, t(`nav.${id}`), s.url);
        }
      }
      assert.notEqual(en.description, tr.description);
      assert.deepEqual(en.shortcuts.map((s) => s.url), tr.shortcuts.map((s) => s.url));
    } finally {
      setLang(prev);
    }
  });

  test('the texts that name the offline tools name exactly VIEWS[].offline', async () => {
    await import('../../assets/js/views/about.js'); // registers about.privOffline
    const offline = VIEWS.filter((v) => v.offline).map((v) => v.id);
    assert.deepEqual(offline, ['zone', 'cert', 'inventory', 'about']);
    const prev = getLang();
    try {
      for (const [m, lang] of [[en, 'en'], [tr, 'tr']]) {
        setLang(lang);
        for (const id of offline) {
          assert.ok(m.description.includes(t(`nav.${id}`)), `${lang} manifest description: ${id}`);
          assert.ok(t('about.privOffline').includes(t(`nav.${id}`)), `${lang} About: ${id}`);
        }
      }
    } finally {
      setLang(prev);
    }
  });

  test('index.html links the English manifest; boot.js and manifestFor pick the Turkish one', () => {
    const html = readFileSync(join(ROOT, 'index.html'), 'utf8');
    assert.match(html, /<link rel="manifest" href="manifest\.webmanifest">/);
    assert.ok(html.indexOf('rel="manifest"') < html.indexOf('assets/js/boot.js'), 'boot.js runs after the link');
    assert.ok(readFileSync(join(ROOT, 'assets', 'js', 'boot.js'), 'utf8').includes(`'${MANIFEST_FILES.tr}'`));
    assert.equal(manifestFor('tr'), MANIFEST_FILES.tr);
    for (const lang of ['en', 'de', '', undefined]) assert.equal(manifestFor(lang), MANIFEST_FILES.en);
  });
});

test('updateCheckDue: at most once per interval', () => {
  assert.equal(updateCheckDue(1000, 1000 + UPDATE_CHECK_MS - 1), false);
  assert.equal(updateCheckDue(1000, 1000 + UPDATE_CHECK_MS), true);
  assert.equal(updateCheckDue(NaN, 5), true);
  assert.equal(updateCheckDue(0, 10, 5), true);
});
