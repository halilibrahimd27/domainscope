#!/usr/bin/env node
/**
 * assemble-site.mjs — the GitHub Pages bundle, assembled from the repository by copying files.
 *
 * No dependencies (Node 22 stdlib only) and no build: nothing is compiled, bundled or minified.
 *
 *   <out>/index.html              index.html with its `assets/…` URLs pointing at v/<version>/assets/
 *   <out>/sw.js                   the service worker, with this deploy's manifest written into it
 *   <out>/favicon.svg, manifest.webmanifest, manifest.tr.webmanifest, icons/, .nojekyll
 *   <out>/cli/                    the CLI, at the URL the README tells people to `curl -O`
 *   <out>/v/<version>/assets/     assets/ as it is, plus version.json: { version, commit, digest } (About › What this
 *                                 page sent names the deploy and links its commit; the page asks for it only in a bundle)
 *
 * Why a version directory: GitHub Pages serves every file with `Cache-Control: max-age=600` and
 * the views are imported lazily, so with fixed URLs a browser can link a module of the new deploy
 * against a still-fresh cached module of the previous one ("does not provide an export named …").
 * Every import inside assets/ is relative (data files too, through import.meta.url), so the whole
 * module graph moves with the prefix and each deploy gets new module URLs. A tab left open across
 * a deploy then fails to fetch v/<old>/…; app.js confirms that its own v/<old>/ is gone (404,
 * `confirmStaleModule`) and offers a page reload. The repository itself stays build-free:
 * `npm run serve` serves it as is.
 *
 * The service worker (the installable app and its offline tools) is the one file written rather
 * than copied: sw.js gets the deploy's manifest (lib/pwa.js buildSwManifest — the app shell of
 * v/<version>/ to precache, the wordlists keyed by the SHA-256 of wordlist-manifest.json, the
 * version and the content digest) in place of its `const BUILD = null;` line. In the repository
 * BUILD stays null and the worker does nothing.
 *
 * A browser installs a new worker only when sw.js changes byte for byte, and until then the
 * installed one answers from its cache. So the bundle's identity is its content: the digest
 * (contentDigest: every file the worker precaches, and sw.js) is in BUILD and in the shell cache's
 * name, and a bundle assembled without a version (no commit to name it: a local preview, a manual
 * deploy) is `dev-<12 hex digits of the digest>` — any change gives new v/<version>/ URLs, a new
 * sw.js and "Update ready". A version given by hand should name one set of files: reused for other
 * files the worker still updates (the digest), but the browser's HTTP cache may hold the old files
 * at those URLs for a while.
 *
 * Usage:
 *   node tools/assemble-site.mjs <out> [version]   # version: [A-Za-z0-9._-]{1,64};
 *                                                  # default: $GITHUB_SHA (12 chars), else dev-<digest>;
 *                                                  # version.json's commit: $GITHUB_SHA when set (40 hex digits)
 *   node tests/e2e/serve.mjs --root <out>          # preview the bundle
 *
 * <out> is deleted first; it must not be the repository or contain it, and an existing <out> must
 * hold only what a bundle does (ROOT_FILES, ROOT_DIRS, v/).
 */

import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildSwManifest, buildVersionFile, wordlistFiles, VERSION_FILE } from '../assets/js/lib/pwa.js';

/** Repository root (one level above tools/). */
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
/** Files copied to the site root as they are (index.html and sw.js are rewritten). */
export const ROOT_FILES = Object.freeze([
  'index.html', 'sw.js', 'favicon.svg', 'manifest.webmanifest', 'manifest.tr.webmanifest', '.nojekyll'
]);
/** Directories copied to the site root as they are. */
export const ROOT_DIRS = Object.freeze(['cli', 'icons']);
/**
 * Site-root files the service worker precaches with the app shell: what the page itself loads.
 * The PNG icons and the CLI are not: the browser fetches icons for its own install UI, and the
 * CLI is a download.
 */
export const SHELL_ROOT_FILES = Object.freeze(['index.html', 'favicon.svg', 'manifest.webmanifest', 'manifest.tr.webmanifest']);
/** The line of sw.js that receives the deploy's manifest. */
const SW_BUILD_RE = /^const BUILD = null;.*$/m;
/** The directory that moves under v/<version>/. */
export const VERSIONED_DIR = 'assets';
/** Allowed version strings (a URL path segment). */
export const VERSION_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** Local clutter never published. */
const SKIP_NAMES = new Set(['__pycache__', '.DS_Store', 'Thumbs.db']);
/** What an earlier bundle holds at its root; an existing <out> with anything else is not deleted. */
const BUNDLE_ENTRIES = new Set([...ROOT_FILES, ...ROOT_DIRS, 'v']);

/**
 * Is this path local clutter the bundle leaves out (__pycache__, .DS_Store, Thumbs.db, *.pyc)?
 * @param {string} file
 * @returns {boolean}
 */
export function isLocalClutter(file) {
  return SKIP_NAMES.has(path.basename(file)) || file.endsWith('.pyc');
}

/**
 * An href / src attribute in any HTML spelling: any case, spaces around '=', and a double-quoted,
 * single-quoted or unquoted value (groups: lead, "value", 'value', value).
 */
const URL_ATTR_RE = /(\s(?:href|src)\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi;
/** A page-relative assets/ URL the rewrite does not cover (srcset, imagesrcset) — refused. */
const UNVERSIONED_RE = /\s(?:href|src)\s*=\s*["']?(?:\.\/)?assets\//i;
/** A srcset / imagesrcset attribute (groups: lead, "value", 'value', value); refused with any assets/ candidate. */
const SRCSET_ATTR_RE = /(\s(?:srcset|imagesrcset)\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi;

/**
 * The first srcset / imagesrcset attribute with an assets/ URL in any of its candidates, or null.
 * @param {string} html
 * @returns {string|null}
 */
function unversionedSrcset(html) {
  for (const m of String(html).matchAll(SRCSET_ATTR_RE)) {
    const value = m[2] ?? m[3] ?? m[4];
    if (value.split(',').some((c) => /^(?:\.\/)?assets\//i.test(c.trim()))) return m[0].trim();
  }
  return null;
}

/**
 * Site-relative prefix of the versioned assets.
 * @param {string} version
 * @returns {string} e.g. 'v/0123456789ab/assets/'
 */
export function versionedAssetsPath(version) {
  if (typeof version !== 'string' || !VERSION_RE.test(version) || /^\.+$/.test(version)) {
    throw new Error(`Invalid version ${JSON.stringify(version)} (allowed: ${VERSION_RE.source})`);
  }
  return `v/${version}/${VERSIONED_DIR}/`;
}

/**
 * Point every `href="assets/…"` / `src="assets/…"` of index.html (also `./assets/…`, single-quoted,
 * unquoted or upper-case) at the versioned directory, keeping the attribute's quotes.
 * @param {string} html
 * @param {string} version
 * @returns {{ html: string, count: number }} count: URLs rewritten
 */
export function versionIndexHtml(html, version) {
  const prefix = versionedAssetsPath(version);
  let count = 0;
  const out = String(html).replace(URL_ATTR_RE, (whole, lead, dq, sq, bare) => {
    const value = dq ?? sq ?? bare;
    const local = /^(?:\.\/)?assets\//.exec(value);
    if (!local) return whole;
    count += 1;
    const quote = dq !== undefined ? '"' : sq !== undefined ? "'" : '';
    return `${lead}${quote}${prefix}${value.slice(local[0].length)}${quote}`;
  });
  return { html: out, count };
}

/**
 * Relative URLs in href / src attributes, in any spelling versionIndexHtml rewrites (no scheme,
 * no fragment-only, no protocol-relative).
 * @param {string} html
 * @returns {string[]}
 */
export function localUrls(html) {
  const urls = [];
  for (const m of String(html).matchAll(URL_ATTR_RE)) {
    const u = m[2] ?? m[3] ?? m[4];
    if (!u || u.startsWith('#') || u.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(u)) continue;
    urls.push(u.split(/[?#]/)[0].replace(/^\.\//, ''));
  }
  return urls;
}

/** Is `child` the same as `parent` or inside it? */
function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Every file under `dir` (local clutter left out), relative to it with '/' separators, sorted.
 * @param {string} dir
 * @returns {Promise<string[]>}
 */
export async function listFiles(dir) {
  const out = [];
  const walk = async (sub) => {
    for (const entry of await readdir(path.join(dir, sub), { withFileTypes: true })) {
      const rel = sub ? `${sub}/${entry.name}` : entry.name;
      if (isLocalClutter(rel)) continue;
      if (entry.isDirectory()) await walk(rel);
      else out.push(rel);
    }
  };
  await walk('');
  return out.sort();
}

/**
 * sw.js with a deploy's manifest in place of its `const BUILD = null;` line.
 * @param {string} source sw.js of the repository
 * @param {object} build lib/pwa.js buildSwManifest() result
 * @returns {string}
 * @throws unless the line is there exactly once
 */
export function injectSwBuild(source, build) {
  const found = String(source).match(new RegExp(SW_BUILD_RE.source, 'gm')) || [];
  if (found.length !== 1) throw new Error(`sw.js must have one "const BUILD = null;" line, found ${found.length}`);
  return String(source).replace(SW_BUILD_RE, () => `const BUILD = ${JSON.stringify(build, null, 2)}; // written by tools/assemble-site.mjs`);
}

/**
 * The content digest of a bundle: SHA-256 over the path and SHA-256 of each file the service
 * worker precaches (SHELL_ROOT_FILES as in the repository, everything under assets/) and of sw.js
 * itself, in path order. The same files give the same digest wherever and whenever they are
 * assembled; any changed, added, removed or renamed file gives another. (The CLI and the PNG
 * icons are not in it: the worker does not serve them.)
 * @param {string} [src] repository root
 * @returns {Promise<string>} 64 hex digits
 */
export async function contentDigest(src = REPO_ROOT) {
  const assets = (await listFiles(path.join(src, VERSIONED_DIR))).map((f) => `${VERSIONED_DIR}/${f}`);
  const files = [...SHELL_ROOT_FILES, 'sw.js', ...assets].sort();
  const all = createHash('sha256');
  for (const file of files) {
    const bytes = await readFile(path.join(src, ...file.split('/')));
    all.update(`${file}\0${createHash('sha256').update(bytes).digest('hex')}\n`);
  }
  return all.digest('hex');
}

/**
 * The version of a bundle assembled without one: `dev-` and the first 12 hex digits of its
 * content digest.
 * @param {string} digest {@link contentDigest}
 * @returns {string}
 */
export function contentVersion(digest) {
  return `dev-${String(digest).slice(0, 12)}`;
}

/**
 * The service worker of this deploy: its manifest from the files of assets/ and the SHA-256 of
 * wordlist-manifest.json, which must match the files (the worker reuses a cached tier as long
 * as its hash is unchanged, so a stale hash would keep serving an old list).
 * @param {string} src repository root
 * @param {string} version
 * @param {string} digest {@link contentDigest} of `src`
 * @returns {Promise<{ source: string, build: object }>}
 * @throws when wordlist-manifest.json does not match the wordlist files
 */
export async function serviceWorkerFor(src, version, digest) {
  const assets = path.join(src, VERSIONED_DIR);
  // version.json is written into the bundle's assets/ (assembleSite): precached with the shell, so
  // the installed app names its version offline too.
  const assetFiles = [...await listFiles(assets), VERSION_FILE].sort();
  const wordlistManifest = JSON.parse(await readFile(path.join(assets, 'data', 'wordlist-manifest.json'), 'utf8'));
  for (const { file, sha256 } of wordlistFiles(wordlistManifest)) {
    const actual = createHash('sha256').update(await readFile(path.join(assets, 'data', ...file.split('/')))).digest('hex');
    if (actual !== sha256) throw new Error(`wordlist-manifest.json has another SHA-256 for ${file}: run tools/build-wordlists.mjs`);
  }
  const build = buildSwManifest({ version, digest, rootFiles: [...SHELL_ROOT_FILES], assetFiles, wordlistManifest });
  return { source: injectSwBuild(await readFile(path.join(src, 'sw.js'), 'utf8'), build), build };
}

/**
 * Assemble the Pages bundle into `out` (deleted first).
 * @param {{ out: string, version?: string, root?: string, commit?: string|null }} opts version: default
 *   {@link contentVersion} (`dev-<digest>`); commit: the full commit (40 hex digits) the bundle is built
 *   from, written into version.json (null: not known)
 * @returns {Promise<{ out: string, version: string, digest: string, assetsPath: string, rewritten: number, precached: number,
 *   versionFile: { version: string, commit: string|null, digest: string } }>}
 * @throws when `out` is the repository, contains it, lies inside a copied directory or holds
 *   anything an earlier bundle does not; when index.html references no assets/ URL, or one the
 *   rewrite does not cover (srcset); when a local URL of the new index.html is missing; when
 *   wordlist-manifest.json does not match the wordlist files
 */
export async function assembleSite({ out, version: given, root = REPO_ROOT, commit = null }) {
  if (given !== undefined) versionedAssetsPath(given); // a bad version is refused before anything is read
  if (commit !== null && !/^[0-9a-f]{40}$/.test(String(commit))) throw new Error(`Invalid commit ${JSON.stringify(commit)} (40 lower-case hex digits)`);
  const target = path.resolve(out);
  const src = path.resolve(root);
  if (isInside(src, target)) throw new Error(`Refusing to assemble into ${target}: it contains the repository`);
  for (const dir of [VERSIONED_DIR, ...ROOT_DIRS]) {
    if (isInside(target, path.join(src, dir))) throw new Error(`Refusing to assemble into ${target}: it is inside ${dir}/`);
  }
  const digest = await contentDigest(src);
  const version = given === undefined ? contentVersion(digest) : given;
  const assetsPath = versionedAssetsPath(version);

  const index = versionIndexHtml(await readFile(path.join(src, 'index.html'), 'utf8'), version);
  if (!index.count) throw new Error('index.html references no assets/ URL; nothing to version');
  const unversioned = UNVERSIONED_RE.exec(index.html)?.[0].trim() ?? unversionedSrcset(index.html);
  if (unversioned) throw new Error(`index.html has an assets/ URL this tool does not rewrite: ${unversioned}`);
  if (existsSync(path.join(src, VERSIONED_DIR, VERSION_FILE))) throw new Error(`${VERSIONED_DIR}/${VERSION_FILE} is written by this tool; remove it from the repository`);
  const versionFile = buildVersionFile({ version, commit, digest });
  const sw = await serviceWorkerFor(src, version, digest);
  // A typo such as `docs` must not wipe a directory that is not an earlier bundle.
  const existing = await stat(target).catch(() => null);
  if (existing) {
    const foreign = existing.isDirectory() ? (await readdir(target)).filter((n) => !BUNDLE_ENTRIES.has(n)) : [path.basename(target)];
    if (foreign.length) throw new Error(`Refusing to delete ${target}: it is not an earlier bundle (${foreign.slice(0, 3).join(', ')})`);
  }

  await rm(target, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  await mkdir(target, { recursive: true });
  const filter = (from) => !isLocalClutter(from);
  for (const file of ROOT_FILES) {
    if (file === 'index.html') await writeFile(path.join(target, file), index.html);
    else if (file === 'sw.js') await writeFile(path.join(target, file), sw.source);
    else await cp(path.join(src, file), path.join(target, file));
  }
  for (const dir of ROOT_DIRS) await cp(path.join(src, dir), path.join(target, dir), { recursive: true, filter });
  await cp(path.join(src, VERSIONED_DIR), path.join(target, ...assetsPath.split('/').filter(Boolean)), { recursive: true, filter });
  await writeFile(path.join(target, ...assetsPath.split('/').filter(Boolean), VERSION_FILE), `${JSON.stringify(versionFile, null, 2)}
`);

  const missing = [...localUrls(index.html), ...sw.build.precache.map((p) => (p === './' ? 'index.html' : p))]
    .filter((u) => !existsSync(path.join(target, ...u.split('/'))));
  if (missing.length) throw new Error(`index.html or sw.js reference files that are not in the bundle: ${missing.join(', ')}`);
  return { out: target, version, digest, assetsPath, rewritten: index.count, precached: sw.build.precache.length, versionFile };
}

/** Default version: the commit being deployed, else none (assembleSite names it by its content). */
function defaultVersion() {
  const sha = String(process.env.GITHUB_SHA || '').trim();
  return /^[0-9a-f]{12,}$/i.test(sha) ? sha.slice(0, 12).toLowerCase() : undefined;
}

/** The full commit being deployed (GitHub Actions' GITHUB_SHA), else null. */
function defaultCommit() {
  const sha = String(process.env.GITHUB_SHA || '').trim().toLowerCase();
  return /^[0-9a-f]{40}$/.test(sha) ? sha : null;
}

async function main(argv) {
  const [out, version = defaultVersion()] = argv;
  if (!out || out === '-h' || out === '--help') {
    process.stdout.write('Usage: node tools/assemble-site.mjs <out> [version]\n');
    process.exitCode = out ? 0 : 2;
    return;
  }
  const r = await assembleSite({ out, version, commit: defaultCommit() });
  process.stdout.write(`Assembled ${r.out}: assets under ${r.assetsPath} (${r.rewritten} URLs in index.html, ${r.precached} files precached by sw.js)\n`);
}

// Only when run directly; importing the module (unit and E2E tests) must not assemble anything.
if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`assemble-site: ${err.message || err}\n`);
    process.exitCode = 1;
  });
}
