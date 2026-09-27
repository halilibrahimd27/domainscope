/**
 * pwa.js — the pure parts of the installable app (web app manifest + service worker, sw.js at the
 * site root): where a page of the Pages bundle finds its site root and service worker, what the
 * worker of one deploy precaches, how it keys the wordlist cache, and which manifest suits the UI
 * language.
 *
 * tools/assemble-site.mjs calls buildSwManifest() at deploy time and writes the result into
 * sw.js, so the worker itself decides nothing: it precaches `precache`, answers `wordlists` from
 * the hash-keyed cache and leaves every other request to the network. ui/pwa.js registers the
 * worker only from a versioned page (bundleInfo), never from the repository in development.
 *
 * DOM-free, no I/O.
 */

/** Prefix of every Cache Storage name the service worker owns (it never touches other caches). */
export const CACHE_PREFIX = 'domainscope-';
/** The wordlist cache, shared by every deploy: entries are keyed by content hash, not by URL. */
export const WORDLIST_CACHE = `${CACHE_PREFIX}wordlists`;
/** The service worker script, relative to the site root (its scope is the whole site). */
export const SERVICE_WORKER_FILE = 'sw.js';
/** Web app manifests by UI language (the English one is linked from index.html). */
export const MANIFEST_FILES = Object.freeze({ en: 'manifest.webmanifest', tr: 'manifest.tr.webmanifest' });
/** How often an open page asks the browser to look for a new service worker (a deploy). */
export const UPDATE_CHECK_MS = 60 * 60 * 1000;
/**
 * Files under assets/ the app never requests, left out of the precache: the wordlist manifest
 * (build-time data; lib/wordlist.js embeds its counts) and the data README.
 */
export const PRECACHE_SKIP = Object.freeze(['data/README.md', 'data/wordlist-manifest.json']);

/** A deploy version as tools/assemble-site.mjs allows it (one URL path segment). */
const VERSION_RE = /^[A-Za-z0-9._-]{1,64}$/;
/** A module of the Pages bundle: <root>v/<version>/assets/js/… */
const BUNDLE_PATH_RE = /^(.*\/)v\/([A-Za-z0-9._-]{1,64})\/assets\/js\//;
const SHA256_RE = /^[0-9a-f]{64}$/;

/**
 * The app shell cache of one deploy.
 * @param {string} version
 * @returns {string} e.g. 'domainscope-shell-0123456789ab'
 */
export function shellCacheName(version) {
  if (!isVersion(version)) throw new Error(`Invalid version ${JSON.stringify(version)}`);
  return `${CACHE_PREFIX}shell-${version}`;
}

function isVersion(version) {
  return typeof version === 'string' && VERSION_RE.test(version) && !/^\.+$/.test(version);
}

/**
 * Where a module of the app runs from. In the Pages bundle (…/v/<version>/assets/js/…): the
 * site root, the version, its assets directory and the service worker URL. In the repository
 * (`npm run serve`, a checkout served as is) or anywhere else: null, and no service worker is
 * registered — development never runs behind a cache.
 * @param {string} moduleUrl import.meta.url of a module under assets/js/
 * @returns {{ root: string, version: string, assets: string, serviceWorker: string }|null}
 */
export function bundleInfo(moduleUrl) {
  let url;
  try {
    url = new URL(String(moduleUrl));
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  const m = BUNDLE_PATH_RE.exec(url.pathname);
  if (!m || !isVersion(m[2])) return null;
  const root = `${url.origin}${m[1]}`;
  return {
    root,
    version: m[2],
    assets: `${root}v/${m[2]}/assets/`,
    serviceWorker: `${root}${SERVICE_WORKER_FILE}`
  };
}

/**
 * The cache key (relative to the service worker's scope) of a wordlist file with this content.
 * A tier keeps its key across deploys until its bytes change, so it is downloaded once.
 * @param {string} sha256 lowercase hex SHA-256 of the file (wordlist-manifest.json)
 * @param {string} file its path, e.g. 'wordlist-large.txt.gz' or 'locale/tr.txt'
 * @returns {string} e.g. 'wordlists/9d72…/wordlist-large.txt.gz'
 */
export function wordlistCacheKey(sha256, file) {
  if (typeof sha256 !== 'string' || !SHA256_RE.test(sha256)) throw new Error(`Invalid SHA-256 for ${file}: ${JSON.stringify(sha256)}`);
  const name = String(file).split('/').pop();
  if (!name || !/^[\w.-]+$/.test(name)) throw new Error(`Invalid wordlist file ${JSON.stringify(file)}`);
  return `wordlists/${sha256}/${name}`;
}

/**
 * The wordlist files of wordlist-manifest.json (tiers and locale packs), relative to assets/data/.
 * @param {object} manifest parsed assets/data/wordlist-manifest.json
 * @returns {Array<{ file: string, sha256: string }>}
 */
export function wordlistFiles(manifest) {
  const out = [];
  for (const tier of Object.values((manifest && manifest.tiers) || {})) {
    if (tier && tier.file) out.push({ file: String(tier.file), sha256: tier.sha256 });
  }
  for (const [cc, info] of Object.entries((manifest && manifest.locales) || {})) {
    out.push({ file: `locale/${cc}.txt`, sha256: info && info.sha256 });
  }
  return out;
}

/**
 * What the service worker of one deploy does, decided at deploy time (tools/assemble-site.mjs
 * writes it into sw.js):
 * - `precache`: the app shell of this version, relative to the site root — './' (index.html,
 *   what a navigation to the app loads), the other site-root files the app uses (favicon, web
 *   app manifests, icons) and every file under v/<version>/assets/ except the wordlists and
 *   {@link PRECACHE_SKIP}. Every module is in it, so every view opens offline (the ones that need
 *   the network then say so).
 * - `wordlists`: each tier and locale pack's versioned path → its hash-keyed cache key; they are
 *   cached on first use only (a Huge tier is 575 KB).
 * @param {{ version: string, rootFiles: string[], assetFiles: string[], wordlistManifest: object }} input
 *   rootFiles: site-root files, relative ('index.html', 'favicon.svg', 'icons/icon-192.png', …);
 *   assetFiles: every file under assets/, relative to it ('js/app.js', 'data/wordlist-base.txt', …)
 * @returns {{ version: string, cachePrefix: string, shellCache: string, wordlistCache: string,
 *   precache: string[], wordlists: Record<string, string> }}
 * @throws when a wordlist file of the manifest has no valid SHA-256 or is not in assets/data/,
 *   or when assets/data/ holds a wordlist file the manifest does not list (it would be precached)
 */
export function buildSwManifest({ version, rootFiles = [], assetFiles = [], wordlistManifest }) {
  const shellCache = shellCacheName(version);
  const assets = `v/${version}/assets/`;
  const lists = wordlistFiles(wordlistManifest);
  const listed = new Set(lists.map((w) => `data/${w.file}`));
  const present = new Set(assetFiles);
  const wordlists = {};
  for (const { file, sha256 } of lists) {
    if (!present.has(`data/${file}`)) throw new Error(`wordlist-manifest.json lists ${file}, which is not in assets/data/`);
    wordlists[`${assets}data/${file}`] = wordlistCacheKey(sha256, file);
  }
  const stray = assetFiles.filter((f) => !listed.has(f) && /^data\/(?:locale\/[^/]+\.txt|wordlist-[^/]+\.txt(?:\.gz)?)$/.test(f));
  if (stray.length) throw new Error(`wordlist files missing from wordlist-manifest.json: ${stray.join(', ')}`);

  const root = [...new Set(rootFiles.map((f) => (f === 'index.html' ? './' : f)))];
  root.sort((a, b) => (a === './' ? -1 : b === './' ? 1 : a < b ? -1 : a > b ? 1 : 0));
  const shell = assetFiles.filter((f) => !listed.has(f) && !PRECACHE_SKIP.includes(f)).sort().map((f) => `${assets}${f}`);
  return {
    version,
    cachePrefix: CACHE_PREFIX,
    shellCache,
    wordlistCache: WORDLIST_CACHE,
    precache: [...root, ...shell],
    wordlists
  };
}

/**
 * The web app manifest for a UI language (English for anything but Turkish).
 * @param {string} lang
 * @returns {string} relative to the site root
 */
export function manifestFor(lang) {
  return lang === 'tr' ? MANIFEST_FILES.tr : MANIFEST_FILES.en;
}

/**
 * Is it time to ask the browser for a new service worker again?
 * @param {number} lastCheckAt ms timestamp of the last check (registration counts as one)
 * @param {number} now
 * @param {number} [everyMs]
 * @returns {boolean}
 */
export function updateCheckDue(lastCheckAt, now, everyMs = UPDATE_CHECK_MS) {
  return !Number.isFinite(lastCheckAt) || now - lastCheckAt >= everyMs;
}
