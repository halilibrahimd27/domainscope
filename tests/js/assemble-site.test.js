/**
 * The GitHub Pages bundle (tools/assemble-site.mjs): assets/ goes under v/<version>/ so each
 * deploy has new module URLs, index.html points there, the CLI stays at its old URL, and nothing
 * in assets/ reaches outside assets/ (else the prefix would break it). No network; the bundle is
 * assembled into a temporary directory.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import {
  REPO_ROOT, assembleSite, localUrls, versionIndexHtml, versionedAssetsPath
} from '../../tools/assemble-site.mjs';

const ASSETS = join(REPO_ROOT, 'assets');
const walk = (d) => readdirSync(d).flatMap((f) => {
  const p = join(d, f);
  return statSync(p).isDirectory() ? walk(p) : [p];
});
/** Source lines without comment-only lines (JSDoc mentions paths such as `assets/data/README.md`). */
const codeOf = (file) => readFileSync(file, 'utf8').split('\n').map((line) => (/^\s*(?:\/\*|\*|\/\/)/.test(line) ? '' : line));
const inside = (child, parent) => {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
};

describe('versionIndexHtml / versionedAssetsPath', () => {
  test('rewrites every href / src under assets/ and nothing else', () => {
    const html = '<link rel="icon" href="favicon.svg"><link rel="stylesheet" href="assets/css/style.css">'
      + '<link rel="modulepreload" href="assets/js/app.js"><script src="assets/js/boot.js"></script>'
      + '<img src="favicon.svg"><a href="#main">x</a><a href="https://example.com/assets/x.js">y</a>'
      + '<p>assets/js/app.js stays text</p><a data-href="assets/x">z</a>';
    const r = versionIndexHtml(html, 'abc123');
    assert.equal(r.count, 3);
    assert.match(r.html, / href="v\/abc123\/assets\/css\/style\.css"/);
    assert.match(r.html, / href="v\/abc123\/assets\/js\/app\.js"/);
    assert.match(r.html, / src="v\/abc123\/assets\/js\/boot\.js"/);
    assert.match(r.html, / href="favicon\.svg"/);
    assert.match(r.html, /https:\/\/example\.com\/assets\/x\.js/);
    assert.match(r.html, /<p>assets\/js\/app\.js stays text<\/p>/);
    assert.match(r.html, /data-href="assets\/x"/);
  });

  test('any attribute spelling is rewritten (quotes kept): single-quoted, unquoted, upper-case, spaced, ./', () => {
    const html = `<link href='assets/a.css'><script src=assets/b.js></script><LINK HREF="assets/c.css">`
      + `<link href = "assets/d.css"><script src="./assets/e.js"></script><a href='https://example.com/assets/f'>x</a>`;
    const r = versionIndexHtml(html, 'v1');
    assert.equal(r.count, 5);
    assert.equal(r.html, `<link href='v/v1/assets/a.css'><script src=v/v1/assets/b.js></script><LINK HREF="v/v1/assets/c.css">`
      + `<link href = "v/v1/assets/d.css"><script src="v/v1/assets/e.js"></script><a href='https://example.com/assets/f'>x</a>`);
    assert.deepEqual(localUrls(html), ['assets/a.css', 'assets/b.js', 'assets/c.css', 'assets/d.css', 'assets/e.js']);
  });

  test('refuses versions that are not a plain path segment', () => {
    assert.equal(versionedAssetsPath('0123456789ab'), 'v/0123456789ab/assets/');
    for (const bad of ['', '.', '..', 'a/b', 'a b', '../x', 'x?y', 'é', 'a'.repeat(65), null, 12]) {
      assert.throws(() => versionedAssetsPath(bad), /Invalid version/, String(bad));
    }
  });

  test('localUrls skips fragments, schemes and protocol-relative URLs', () => {
    const html = '<a href="#x"></a><a href="https://example.com/"></a><a href="//example.net/x"></a>'
      + '<img src="data:image/png;base64,AA"><a href="cli/ssl_origin_scan.py?download=1"></a><link href="v/1/assets/a.css">';
    assert.deepEqual(localUrls(html), ['cli/ssl_origin_scan.py', 'v/1/assets/a.css']);
  });
});

describe('assembleSite', () => {
  let tmp;
  let out;
  let result;
  before(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'ds-site-'));
    out = join(tmp, 'site');
    result = await assembleSite({ out, version: 'abc123' });
  });
  after(() => rmSync(tmp, { recursive: true, force: true }));

  test('index.html loads everything from v/<version>/assets/, and every target exists', () => {
    const html = readFileSync(join(out, 'index.html'), 'utf8');
    const urls = localUrls(html);
    assert.ok(result.rewritten >= 10, `rewritten ${result.rewritten}`);
    assert.ok(urls.length >= result.rewritten);
    for (const u of urls) {
      if (u !== 'favicon.svg') assert.ok(u.startsWith('v/abc123/assets/'), u);
      assert.ok(existsSync(join(out, ...u.split('/'))), `missing ${u}`);
    }
    assert.doesNotMatch(html, /(?:href|src)="assets\//);
    assert.match(html, /<script type="module" src="v\/abc123\/assets\/js\/app\.js">/);
  });

  test('the CLI stays at the site root; assets/ exists only under the version; no local clutter', () => {
    assert.ok(existsSync(join(out, 'cli', 'ssl_origin_scan.py')));
    assert.ok(existsSync(join(out, '.nojekyll')));
    assert.ok(existsSync(join(out, 'favicon.svg')));
    assert.ok(!existsSync(join(out, 'assets')));
    assert.deepEqual(readdirSync(join(out, 'v')), ['abc123']);
    const files = walk(out).map((f) => relative(out, f).split(sep).join('/'));
    assert.deepEqual(files.filter((f) => /__pycache__|\.pyc$/.test(f)), []);
    const assetFiles = walk(ASSETS).map((f) => relative(ASSETS, f).split(sep).join('/')).sort();
    assert.deepEqual(files.filter((f) => f.startsWith('v/abc123/assets/')).map((f) => f.slice('v/abc123/assets/'.length)).sort(), assetFiles);
    assert.deepEqual(readFileSync(join(out, 'v', 'abc123', 'assets', 'js', 'app.js')), readFileSync(join(ASSETS, 'js', 'app.js')), 'copied as is');
  });

  test('a second deploy replaces the previous version directory', async () => {
    const other = join(tmp, 'again');
    await assembleSite({ out: other, version: 'one' });
    await assembleSite({ out: other, version: 'two' });
    assert.deepEqual(readdirSync(join(other, 'v')), ['two']);
    assert.match(readFileSync(join(other, 'index.html'), 'utf8'), /src="v\/two\/assets\/js\/app\.js"/);
  });

  test('checks every attribute spelling for missing files, and refuses an assets/ URL it cannot rewrite', async () => {
    const root = join(tmp, 'repo');
    const write = (rel, text = '') => {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    };
    for (const f of ['favicon.svg', '.nojekyll', 'cli/ssl_origin_scan.py', 'assets/js/app.js', 'assets/css/a.css']) write(f);
    const site = join(tmp, 'edge');
    write('index.html', `<link rel=stylesheet href='assets/css/a.css'><script type=module SRC=assets/js/app.js></script>`);
    assert.equal((await assembleSite({ out: site, version: 'e1', root })).rewritten, 2);
    assert.equal(readFileSync(join(site, 'index.html'), 'utf8'),
      `<link rel=stylesheet href='v/e1/assets/css/a.css'><script type=module SRC=v/e1/assets/js/app.js></script>`);
    write('index.html', `<link rel=stylesheet href='assets/css/gone.css'><script type=module src="assets/js/app.js"></script>`);
    await assert.rejects(assembleSite({ out: site, version: 'e1', root }), /not in the bundle: v\/e1\/assets\/css\/gone\.css/);
    write('index.html', `<img srcset="assets/css/a.css 1x"><script type=module src="assets/js/app.js"></script>`);
    await assert.rejects(assembleSite({ out: site, version: 'e1', root }), /does not rewrite: srcset="assets\//);
  });

  test('refuses to delete the repository or to copy a directory into itself', async () => {
    await assert.rejects(assembleSite({ out: REPO_ROOT, version: 'x' }), /contains the repository/);
    await assert.rejects(assembleSite({ out: dirname(REPO_ROOT), version: 'x' }), /contains the repository/);
    await assert.rejects(assembleSite({ out: join(ASSETS, 'site'), version: 'x' }), /inside assets\//);
    await assert.rejects(assembleSite({ out: join(REPO_ROOT, 'cli', 'site'), version: 'x' }), /inside cli\//);
    await assert.rejects(assembleSite({ out: join(tmp, 'bad'), version: '../x' }), /Invalid version/);
  });
});

describe('assets/ is self-contained (it is served from v/<version>/assets/)', () => {
  const jsFiles = walk(join(ASSETS, 'js')).filter((f) => f.endsWith('.js'));

  test('no document-relative "assets/…" URL in the code (it would miss the version directory)', () => {
    const hits = [];
    for (const file of jsFiles) {
      codeOf(file).forEach((line, i) => {
        if (/['"`]\.?\/?assets\//.test(line)) hits.push(`${relative(REPO_ROOT, file)}:${i + 1}`);
      });
    }
    assert.deepEqual(hits, [], 'resolve it from import.meta.url instead');
  });

  test('every relative import and import.meta.url reference resolves to a file inside assets/', () => {
    const bad = [];
    let checked = 0;
    const res = [
      /\bfrom\s*(['"])(\.{1,2}\/[^'"]+)\1/g,
      /\bimport\s*(['"])(\.{1,2}\/[^'"]+)\1/g,
      /\bimport\(\s*(['"`])(\.{1,2}\/[^'"`$]+)\1\s*\)/g,
      /\bnew URL\(\s*(['"`])(\.{1,2}\/[^'"`$]+)\1\s*,\s*import\.meta\.url\s*\)/g
    ];
    for (const file of jsFiles) {
      const code = codeOf(file).join('\n');
      for (const re of res) {
        for (const m of code.matchAll(re)) {
          checked += 1;
          const target = resolve(dirname(file), m[2]);
          if (!inside(target, ASSETS) || !existsSync(target)) bad.push(`${relative(REPO_ROOT, file)} → ${m[2]}`);
        }
      }
    }
    assert.ok(checked > 100, `checked ${checked}`);
    assert.deepEqual(bad, []);
  });

  test('document-relative URLs in the code (the CLI, the favicon) exist at the site root of the bundle', () => {
    const rootRefs = new Set();
    for (const file of jsFiles) {
      for (const m of codeOf(file).join('\n').matchAll(/['"`]((?:cli\/[\w./-]+)|favicon\.svg)['"`]/g)) rootRefs.add(m[1]);
    }
    assert.ok(rootRefs.has('cli/ssl_origin_scan.py') && rootRefs.has('favicon.svg'), [...rootRefs].join(', '));
    for (const ref of rootRefs) assert.ok(existsSync(join(REPO_ROOT, ...ref.split('/'))), ref);
  });

  test('stylesheets only use data: URLs or files inside assets/', () => {
    for (const file of walk(join(ASSETS, 'css')).filter((f) => f.endsWith('.css'))) {
      for (const m of readFileSync(file, 'utf8').matchAll(/url\(\s*(['"]?)([^'")]+)\1\s*\)/g)) {
        if (m[2].startsWith('data:')) continue;
        const target = resolve(dirname(file), m[2].split(/[?#]/)[0]);
        assert.ok(inside(target, ASSETS) && existsSync(target), `${relative(REPO_ROOT, file)}: ${m[2]}`);
      }
    }
  });
});
