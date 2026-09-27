#!/usr/bin/env node
/**
 * assemble-site.mjs — the GitHub Pages bundle, assembled from the repository by copying files.
 *
 * No dependencies (Node 22 stdlib only) and no build: nothing is compiled, bundled or minified.
 *
 *   <out>/index.html              index.html with its `assets/…` URLs pointing at v/<version>/assets/
 *   <out>/favicon.svg, .nojekyll
 *   <out>/cli/                    the CLI, at the URL the README tells people to `curl -O`
 *   <out>/v/<version>/assets/     assets/ as it is
 *
 * Why a version directory: GitHub Pages serves every file with `Cache-Control: max-age=600` and
 * the views are imported lazily, so with fixed URLs a browser can link a module of the new deploy
 * against a still-fresh cached module of the previous one ("does not provide an export named …").
 * Every import inside assets/ is relative (data files too, through import.meta.url), so the whole
 * module graph moves with the prefix and each deploy gets new module URLs. A tab left open across
 * a deploy then fails to fetch v/<old>/…; app.js offers a page reload for that
 * (`isStaleModuleError`). The repository itself stays build-free: `npm run serve` serves it as is.
 *
 * Usage:
 *   node tools/assemble-site.mjs <out> [version]   # version: [A-Za-z0-9._-]{1,64};
 *                                                  # default: $GITHUB_SHA (12 chars), else 'dev'
 *   node tests/e2e/serve.mjs --root <out>          # preview the bundle
 *
 * <out> is deleted first; it must not be the repository or contain it.
 */

import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/** Repository root (one level above tools/). */
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
/** Files copied to the site root as they are (index.html is rewritten). */
export const ROOT_FILES = Object.freeze(['index.html', 'favicon.svg', '.nojekyll']);
/** Directories copied to the site root as they are. */
export const ROOT_DIRS = Object.freeze(['cli']);
/** The directory that moves under v/<version>/. */
export const VERSIONED_DIR = 'assets';
/** Allowed version strings (a URL path segment). */
export const VERSION_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** Local clutter never published. */
const SKIP_NAMES = new Set(['__pycache__', '.DS_Store', 'Thumbs.db']);

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
 * Point every `href="assets/…"` / `src="assets/…"` of index.html at the versioned directory.
 * @param {string} html
 * @param {string} version
 * @returns {{ html: string, count: number }} count: URLs rewritten
 */
export function versionIndexHtml(html, version) {
  const prefix = versionedAssetsPath(version);
  let count = 0;
  const out = String(html).replace(/(\s(?:href|src)=")assets\//g, (_, attr) => {
    count += 1;
    return `${attr}${prefix}`;
  });
  return { html: out, count };
}

/**
 * Relative URLs in href="…" / src="…" attributes (no scheme, no fragment-only, no protocol-relative).
 * @param {string} html
 * @returns {string[]}
 */
export function localUrls(html) {
  const urls = [];
  for (const m of String(html).matchAll(/\s(?:href|src)="([^"]*)"/g)) {
    const u = m[1];
    if (!u || u.startsWith('#') || u.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(u)) continue;
    urls.push(u.split(/[?#]/)[0]);
  }
  return urls;
}

/** Is `child` the same as `parent` or inside it? */
function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Assemble the Pages bundle into `out` (deleted first).
 * @param {{ out: string, version: string, root?: string }} opts
 * @returns {Promise<{ out: string, version: string, assetsPath: string, rewritten: number }>}
 * @throws when `out` is the repository, contains it or lies inside a copied directory; when
 *   index.html references no assets/ URL; when a local URL of the new index.html is missing
 */
export async function assembleSite({ out, version, root = REPO_ROOT }) {
  const assetsPath = versionedAssetsPath(version);
  const target = path.resolve(out);
  const src = path.resolve(root);
  if (isInside(src, target)) throw new Error(`Refusing to assemble into ${target}: it contains the repository`);
  for (const dir of [VERSIONED_DIR, ...ROOT_DIRS]) {
    if (isInside(target, path.join(src, dir))) throw new Error(`Refusing to assemble into ${target}: it is inside ${dir}/`);
  }

  const index = versionIndexHtml(await readFile(path.join(src, 'index.html'), 'utf8'), version);
  if (!index.count) throw new Error('index.html references no assets/ URL; nothing to version');

  await rm(target, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  await mkdir(target, { recursive: true });
  const filter = (from) => !SKIP_NAMES.has(path.basename(from)) && !from.endsWith('.pyc');
  for (const file of ROOT_FILES) {
    if (file === 'index.html') await writeFile(path.join(target, file), index.html);
    else await cp(path.join(src, file), path.join(target, file));
  }
  for (const dir of ROOT_DIRS) await cp(path.join(src, dir), path.join(target, dir), { recursive: true, filter });
  await cp(path.join(src, VERSIONED_DIR), path.join(target, ...assetsPath.split('/').filter(Boolean)), { recursive: true, filter });

  const missing = localUrls(index.html).filter((u) => !existsSync(path.join(target, ...u.split('/'))));
  if (missing.length) throw new Error(`index.html references files that are not in the bundle: ${missing.join(', ')}`);
  return { out: target, version, assetsPath, rewritten: index.count };
}

/** Default version: the commit being deployed, else 'dev'. */
function defaultVersion() {
  const sha = String(process.env.GITHUB_SHA || '').trim();
  return /^[0-9a-f]{12,}$/i.test(sha) ? sha.slice(0, 12).toLowerCase() : 'dev';
}

async function main(argv) {
  const [out, version = defaultVersion()] = argv;
  if (!out || out === '-h' || out === '--help') {
    process.stdout.write('Usage: node tools/assemble-site.mjs <out> [version]\n');
    process.exitCode = out ? 0 : 2;
    return;
  }
  const r = await assembleSite({ out, version });
  process.stdout.write(`Assembled ${r.out}: assets under ${r.assetsPath} (${r.rewritten} URLs in index.html)\n`);
}

// Only when run directly; importing the module (unit and E2E tests) must not assemble anything.
if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`assemble-site: ${err.message || err}\n`);
    process.exitCode = 1;
  });
}
