#!/usr/bin/env node
/**
 * blocklist-check.mjs — does a public ad or tracker filter list block one of the site's own files?
 *
 * An ad blocker matches URLs, not intent: EasyPrivacy's rule `/netresults.js` (an old Nielsen
 * tracker's file name) blocked assets/js/lib/netresults.js for every uBlock Origin, AdGuard, Brave
 * or Ghostery user, and with it the four views that import it (IP Intel, Bulk Resolve, Reverse
 * DNS, Servers): "Failed to fetch dynamically imported module", in their browser only, however
 * often they reloaded. The module is lib/ipresults.js now; this check keeps any file of the site
 * from carrying such a name again.
 *
 * It lists every URL a deploy serves (tools/assemble-site.mjs: the site-root files, cli/ and
 * icons/, and assets/ under v/<version>/), downloads the lists most blockers turn on by default
 * ({@link LISTS}: uBlock Origin's defaults, EasyList and EasyPrivacy, AdGuard's base, tracking
 * and Turkish lists) and matches each URL as the request it is (a module is a script, a data
 * file a fetch) against their network filters — anchors, wildcards, separators, regex filters,
 * $third-party, $domain=, resource types and @@ exceptions ({@link parseFilter}). Cosmetic and
 * scriptlet filters, and filters that only modify a request, block nothing and are left out.
 *
 * Exit code: 1 when a list blocks a file (each one printed with the list and the filter), 0 when
 * none does — also when no list could be downloaded (a network problem says so and does not fail
 * the build: the next run checks again), 2 on a usage error. CI runs it (.github/workflows/ci.yml),
 * and so the Pages deploy, which runs CI first.
 *
 * Usage:
 *   node tools/blocklist-check.mjs                    # download the lists (60 s at most each), check
 *   node tools/blocklist-check.mjs --lists <dir>      # read the lists from <dir>/*.txt instead
 *   node tools/blocklist-check.mjs --base https://example.github.io/domainscope/
 *
 * No dependencies (Node 22 stdlib).
 */

import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { REPO_ROOT, ROOT_DIRS, ROOT_FILES, VERSIONED_DIR, isLocalClutter } from './assemble-site.mjs';

/** The lists checked: what uBlock Origin, AdGuard and Brave turn on by default (Turkish too). */
export const LISTS = Object.freeze([
  { name: 'EasyList', url: 'https://easylist.to/easylist/easylist.txt' },
  { name: 'EasyPrivacy', url: 'https://easylist.to/easylist/easyprivacy.txt' },
  { name: 'uBlock filters', url: 'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt' },
  { name: 'uBlock filters – Privacy', url: 'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt' },
  { name: 'uBlock filters – Badware risks', url: 'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt' },
  { name: 'AdGuard Base', url: 'https://filters.adtidy.org/extension/ublock/filters/2.txt' },
  { name: 'AdGuard Tracking Protection', url: 'https://filters.adtidy.org/extension/ublock/filters/3.txt' },
  { name: 'AdGuard Turkish', url: 'https://filters.adtidy.org/extension/ublock/filters/13.txt' }
]);

/** The version segment the check puts in a versioned URL (any one will do: the file names matter). */
const VERSION = '0123456789ab';
const DOWNLOAD_TIMEOUT_MS = 60000;

const TYPE_ALIASES = { js: 'script', css: 'stylesheet', xhr: 'xmlhttprequest', img: 'image', doc: 'document', frame: 'subdocument' };
const TYPES = new Set(['script', 'xmlhttprequest', 'stylesheet', 'image', 'font', 'media', 'object', 'subdocument', 'document', 'websocket', 'ping', 'other', 'popup', 'popunder']);
/**
 * Options of a filter that changes a request or the page rather than blocking it — and, on an @@
 * exception, that lifts something other than a network block: `@@||github.io^$generichide` turns
 * off generic cosmetic filters on every GitHub Pages site, it does not unblock a single request.
 */
const MODIFIERS = new Set(['removeparam', 'queryprune', 'csp', 'header', 'permissions', 'urlskip', 'replace', 'redirect-rule', 'cname',
  'uritransform', 'urltransform', 'jsonprune', 'json-prune', 'xmlprune', 'hls', 'referrerpolicy', 'stealth', 'cookie',
  'elemhide', 'ehide', 'generichide', 'ghide', 'specifichide', 'shide', 'genericblock', 'content', 'extension', 'jsinject']);
/** A cosmetic, scriptlet or HTML filter: never a network block. */
const COSMETIC_RE = /#[@$%?]?#|#@?[$?]#|\$\$|#\+js|##\^/;

/**
 * The request type a file of the site is loaded as (what a filter's type options are matched with).
 * @param {string} url
 * @returns {string}
 */
export function requestType(url) {
  const p = new URL(url).pathname;
  if (p.endsWith('/') || /\.html?$/.test(p)) return 'document';
  if (/\.m?js$/.test(p)) return 'script';
  if (/\.css$/.test(p)) return 'stylesheet';
  if (/\.(png|svg|ico|webp|jpe?g|gif|avif)$/.test(p)) return 'image';
  if (/\.(woff2?|ttf|otf)$/.test(p)) return 'font';
  if (/\.(json|txt|gz|csv|webmanifest|pem|md)$/.test(p)) return 'xmlhttprequest';
  return 'other';
}

/** A filter's URL pattern as a regular expression (ABP syntax: ||, |, ^, *). */
function patternRegex(pattern, matchCase) {
  let p = pattern;
  let re = '';
  if (p.startsWith('||')) {
    re = '^[a-z][a-z0-9+.-]*:\\/\\/(?:[^/?#]*\\.)?';
    p = p.slice(2);
  } else if (p.startsWith('|')) {
    re = '^';
    p = p.slice(1);
  }
  let end = '';
  if (p.endsWith('|')) {
    end = '$';
    p = p.slice(0, -1);
  }
  for (const c of p) {
    if (c === '*') re += '.*';
    else if (c === '^') re += '(?:[^a-zA-Z0-9_\\-.%]|$)';
    else re += c.replace(/[.+?${}()|[\]\\/]/g, '\\$&');
  }
  return new RegExp(re + end, matchCase ? '' : 'i');
}

/** Does a `domain=` entry name this host (a parent domain counts; `name.*` is any TLD)? */
function domainMatches(entry, host) {
  const d = entry.toLowerCase();
  if (d.endsWith('.*')) {
    const stem = d.slice(0, -2);
    return host.split('.').some((_, i, labels) => labels.slice(i, -1).join('.') === stem);
  }
  return host === d || host.endsWith(`.${d}`);
}

/**
 * One line of a filter list as a network filter, or null when it is none (a comment, a cosmetic
 * or scriptlet filter, a filter that modifies rather than blocks, one only for third-party
 * requests — the site's files are first-party —, or one too broad to mean a file).
 * @param {string} line
 * @returns {{ text: string, exception: boolean, re: RegExp, literal: string, types: Set<string>,
 *   notTypes: Set<string>, domains: { pos: string[], neg: string[] }|null }|null}
 */
export function parseFilter(line) {
  const text = String(line).trim();
  if (!text || text[0] === '!' || text[0] === '[' || COSMETIC_RE.test(text)) return null;
  let body = text;
  const exception = body.startsWith('@@');
  if (exception) body = body.slice(2);
  let pattern = body;
  let opts = '';
  const regexFilter = /^\/.+\/(?:\$[^/]*)?$/.test(body);
  if (regexFilter) {
    const m = /^(\/.+\/)(?:\$([^/]*))?$/.exec(body);
    pattern = m[1];
    opts = m[2] || '';
  } else {
    const at = body.lastIndexOf('$');
    if (at > 0) {
      pattern = body.slice(0, at);
      opts = body.slice(at + 1);
    }
  }
  const options = opts ? opts.split(',').map((o) => o.trim()).filter(Boolean) : [];
  const types = new Set();
  const notTypes = new Set();
  let domains = null;
  let matchCase = false;
  for (const raw of options) {
    const neg = raw.startsWith('~');
    const [nameRaw, value] = (neg ? raw.slice(1) : raw).split('=');
    const name = nameRaw.toLowerCase();
    if (['third-party', '3p', 'strict3p', 'strict-third-party'].includes(name) && !neg) return null; // first-party files only
    // A $badfilter line cancels another filter; neither is modelled (the check may then report one
    // a list has switched off: the safe side).
    if (name === 'badfilter') return null;
    if (MODIFIERS.has(name) && !neg) return null;
    if (name === 'match-case') matchCase = true;
    else if (name === 'urlblock' && exception) types.add('document'); // AdGuard: no network block on the page
    else if (name === 'domain' || name === 'from') {
      const list = String(value || '').split('|').filter(Boolean);
      domains = { pos: list.filter((d) => !d.startsWith('~')), neg: list.filter((d) => d.startsWith('~')).map((d) => d.slice(1)) };
    } else if (name === 'all') ['script', 'xmlhttprequest', 'stylesheet', 'image', 'font', 'media', 'other', 'document'].forEach((t) => types.add(t));
    else {
      const type = TYPE_ALIASES[name] || name;
      if (TYPES.has(type)) (neg ? notTypes : types).add(type);
    }
  }
  let re;
  let literal = '';
  if (regexFilter) {
    try {
      re = new RegExp(pattern.slice(1, -1), matchCase ? '' : 'i');
    } catch {
      return null;
    }
  } else {
    if (!pattern || /^[|*^]*$/.test(pattern)) return null; // matches everything: a type-only filter, not a file
    literal = pattern.replace(/^\|\|?/, '').split(/[*^|]/).sort((a, b) => b.length - a.length)[0].toLowerCase();
    re = patternRegex(pattern, matchCase);
  }
  return { text, exception, re, literal, types, notTypes, domains };
}

/** Does a filter apply to this request of a page on `host`? */
function applies(filter, url, type, host) {
  if (filter.types.size && !filter.types.has(type)) return false;
  if (filter.notTypes.has(type)) return false;
  if (filter.domains) {
    if (filter.domains.neg.some((d) => domainMatches(d, host))) return false;
    if (filter.domains.pos.length && !filter.domains.pos.some((d) => domainMatches(d, host))) return false;
  }
  return filter.re.test(url);
}

/**
 * The URLs the lists block, each with the filters that block it. An @@ exception that matches the
 * request, or one for the whole page ($document) on the site, unblocks it.
 * @param {string[]} urls
 * @param {Array<{ name: string, text: string }>} lists
 * @returns {Array<{ url: string, type: string, hits: Array<{ list: string, filter: string }> }>}
 */
export function blockedUrls(urls, lists) {
  const host = new URL(urls[0]).hostname.toLowerCase();
  const site = urls.find((u) => requestType(u) === 'document') || urls[0];
  const corpus = urls.join('\n').toLowerCase();
  const blocks = new Map(urls.map((u) => [u, []]));
  const unblocked = new Set();
  let wholeSite = false;
  for (const { name, text } of lists) {
    for (const line of String(text).split(/\r?\n/)) {
      const f = parseFilter(line);
      if (!f || (f.literal && !corpus.includes(f.literal))) continue; // its text is in no URL of the site
      if (f.exception && f.types.has('document') && applies(f, site, 'document', host)) wholeSite = true;
      for (const url of urls) {
        const type = requestType(url);
        if (!applies(f, url, type, host)) continue;
        if (f.exception) unblocked.add(url);
        else blocks.get(url).push({ list: name, filter: f.text });
      }
    }
  }
  if (wholeSite) return [];
  return [...blocks].filter(([url, hits]) => hits.length && !unblocked.has(url))
    .map(([url, hits]) => ({ url, type: requestType(url), hits }));
}

/** Every file under `dir` (relative to it, '/'-separated), local clutter left out. */
async function filesUnder(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile()) continue;
    const rel = path.relative(dir, path.join(entry.parentPath ?? entry.path, entry.name)).split(path.sep).join('/');
    if (!rel.split('/').some((part) => isLocalClutter(part)) && !isLocalClutter(rel)) out.push(rel);
  }
  return out.sort();
}

/**
 * Every URL a deploy of this checkout serves, the site root first (as tools/assemble-site.mjs lays
 * it out: the site-root files, cli/ and icons/ as they are, assets/ under v/<version>/).
 * @param {string} base the site's URL, ending in '/'
 * @param {string} [root] the checkout
 * @returns {Promise<string[]>}
 */
export async function siteUrls(base, root = REPO_ROOT) {
  const urls = [base];
  for (const f of ROOT_FILES) if (f !== '.nojekyll') urls.push(base + f);
  for (const dir of ROOT_DIRS) for (const f of await filesUnder(path.join(root, dir))) urls.push(`${base}${dir}/${f}`);
  for (const f of await filesUnder(path.join(root, VERSIONED_DIR))) urls.push(`${base}v/${VERSION}/${VERSIONED_DIR}/${f}`);
  return urls;
}

/** The site's URL: GitHub Pages of the repository CI runs in, else of app.js's REPO_URL. */
async function defaultBase() {
  const repo = process.env.GITHUB_REPOSITORY
    || (await import(pathToFileURL(path.join(REPO_ROOT, 'assets/js/app.js')).href)).REPO_URL.replace(/^https:\/\/github\.com\//, '');
  const [owner, name] = repo.split('/');
  return `https://${owner.toLowerCase()}.github.io/${name}/`;
}

async function loadLists(dir) {
  if (dir) {
    const names = (await readdir(dir)).filter((f) => f.endsWith('.txt')).sort();
    return { lists: await Promise.all(names.map(async (f) => ({ name: f, text: await readFile(path.join(dir, f), 'utf8') }))), missing: [] };
  }
  const settled = await Promise.all(LISTS.map(async ({ name, url }) => {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return { name, text: await res.text() };
    } catch (err) {
      return { name, error: `${url}: ${err.message || err}` };
    }
  }));
  return { lists: settled.filter((l) => !l.error), missing: settled.filter((l) => l.error) };
}

async function main(argv) {
  let listsDir = null;
  let base = null;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--lists') listsDir = argv[++i];
    else if (argv[i] === '--base') base = argv[++i];
    else {
      console.error(`usage: node tools/blocklist-check.mjs [--lists <dir>] [--base <site url>] (unknown argument ${argv[i]})`);
      return 2;
    }
  }
  if (base && !/^https?:\/\/[^/]+\/(?:.*\/)?$/.test(base)) {
    console.error(`--base must be the site's URL ending in '/': ${base}`);
    return 2;
  }
  base = base || await defaultBase();
  const urls = await siteUrls(base);
  const { lists, missing } = await loadLists(listsDir);
  for (const m of missing) console.warn(`warning: could not download ${m.name} (${m.error}); it is not checked`);
  if (!lists.length) {
    console.warn('warning: no filter list could be read, so nothing was checked (a network problem; the next run checks again)');
    return 0;
  }
  const blocked = blockedUrls(urls, lists);
  const checked = `${urls.length} URLs of ${base} against ${lists.length} list${lists.length === 1 ? '' : 's'} (${lists.map((l) => l.name).join(', ')})`;
  if (!blocked.length) {
    console.log(`No file of the site is blocked: ${checked}.`);
    return 0;
  }
  console.error(`${blocked.length} file${blocked.length === 1 ? ' is' : 's are'} blocked by an ad or tracker filter list — rename ${blocked.length === 1 ? 'it' : 'them'} (${checked}):`);
  for (const b of blocked) {
    console.error(`\n  ${b.url.replace(base, '')} (${b.type})`);
    for (const h of b.hits.slice(0, 5)) console.error(`    ${h.list}: ${h.filter}`);
  }
  return 1;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (err) => {
    console.error(err && err.stack ? err.stack : err);
    process.exitCode = 2;
  });
}
