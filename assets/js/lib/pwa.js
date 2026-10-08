/**
 * pwa.js — the pure parts of the installable app (web app manifest + service worker, sw.js at the
 * site root): where a page of the Pages bundle finds its site root and service worker, what the
 * worker of one deploy precaches, how it names its caches and keys the wordlist cache, and which
 * manifest suits the UI language.
 *
 * tools/assemble-site.mjs calls buildSwManifest() at deploy time and writes the result into
 * sw.js, so the worker itself decides nothing: it precaches `precache`, answers `wordlists` from
 * the hash-keyed cache and leaves every other request to the network. ui/pwa.js registers the
 * worker only from a versioned page (bundleInfo), never from the repository in development.
 *
 * DOM-free, no I/O.
 */

/** Start of every Cache Storage name the service worker owns ({@link cacheNames}). */
export const CACHE_PREFIX = 'domainscope-';
/** The service worker script, relative to the site root (its scope is the whole site). */
export const SERVICE_WORKER_FILE = 'sw.js';
/** Web app manifests by UI language (the English one is linked from index.html). */
export const MANIFEST_FILES = Object.freeze({ en: 'manifest.webmanifest', tr: 'manifest.tr.webmanifest' });
/** How often an open page asks the browser to look for a new service worker (a deploy). */
export const UPDATE_CHECK_MS = 60 * 60 * 1000;
/**
 * Files under assets/ the app never requests, left out of the precache: the wordlist manifest
 * (build-time data; lib/wordlist.js embeds its counts), the data README, and the provider-range
 * network tier (tools/build-ranges.mjs, about 130 KB of display-only operator space). The range
 * manifest and the small edge tier stay precached; offline, lib/netinfo.js falls back to its
 * built-in table when the whole dataset is not cached, so the network tier adds no offline weight.
 */
export const PRECACHE_SKIP = Object.freeze(['data/README.md', 'data/ranges/networks.json', 'data/wordlist-manifest.json']);
/**
 * Directories under assets/ left out of the precache: the intermediate certificate shards of
 * lib/chainfix.js (256 + 16 files, about 4.2 MB; a repair reads the few it needs, usually one or
 * two, over the network). The dataset's manifest and roots table are precached, so the lifecycle warnings of a
 * complete chain work offline.
 */
export const PRECACHE_SKIP_DIRS = Object.freeze(['data/intermediates/ski/', 'data/intermediates/dn/']);

/** A deploy version as tools/assemble-site.mjs allows it (one URL path segment). */
const VERSION_RE = /^[A-Za-z0-9._-]{1,64}$/;
/** A module of the Pages bundle: <root>v/<version>/assets/js/… */
const BUNDLE_PATH_RE = /^(.*\/)v\/([A-Za-z0-9._-]{1,64})\/assets\/js\//;
const SHA256_RE = /^[0-9a-f]{64}$/;
/** Hex digits of the content digest in a shell cache name. */
const DIGEST_IN_NAME = 12;

/**
 * A short tag for a service worker scope: FNV-1a (32 bits) over its path, 8 hex digits. GitHub
 * Pages project sites share one origin (<user>.github.io), so two copies of the app there
 * (/domainscope/ and /domainscope-staging/) share one Cache Storage; the tag in every cache name
 * keeps each copy to its own caches. sw.js has the same function (tests/js/sw.test.js compares).
 * @param {string} scopePath e.g. '/domainscope/'
 * @returns {string} e.g. '5f0e2a91'
 */
export function scopeTag(scopePath) {
  const s = String(scopePath);
  let hash = 0x811c9dc5;
  for (let i = 0; i < s.length; i += 1) {
    hash ^= s.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

/**
 * The Cache Storage names of the service worker at one scope; sw.js computes the same ones.
 * - `prefix`: every name it owns starts with it, and it deletes no cache without it;
 * - `wordlists`: shared by every deploy at the scope (entries keyed by content hash, not URL);
 * - `shell`: one deploy's app shell, named by its version and its content digest — a bundle
 *   assembled again under the same version with other files gets a new cache (and a new sw.js),
 *   never an update in place of the one the running version answers from. null without `build`.
 * @param {string} scopePath the scope's path, e.g. '/domainscope/'
 * @param {{ version: string, digest: string }|null} [build] a deploy (buildSwManifest)
 * @returns {{ prefix: string, wordlists: string, shell: string|null }}
 *   e.g. shell 'domainscope-5f0e2a91-shell-0123456789ab-9d72c0e14b3a'
 */
export function cacheNames(scopePath, build = null) {
  const prefix = `${CACHE_PREFIX}${scopeTag(scopePath)}-`;
  let shell = null;
  if (build) {
    if (!isVersion(build.version)) throw new Error(`Invalid version ${JSON.stringify(build.version)}`);
    if (!isDigest(build.digest)) throw new Error(`Invalid content digest ${JSON.stringify(build.digest)}`);
    shell = `${prefix}shell-${build.version}-${build.digest.slice(0, DIGEST_IN_NAME)}`;
  }
  return { prefix, wordlists: `${prefix}wordlists`, shell };
}

function isDigest(digest) {
  return typeof digest === 'string' && SHA256_RE.test(digest);
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

/** The deploy's version file, written by tools/assemble-site.mjs into v/<version>/assets/ (the repository has none). */
export const VERSION_FILE = 'version.json';

/**
 * What a deploy says about itself (About › What this page sent): its version, the full commit it
 * was built from when the deploy knew it, and its content digest.
 * @param {{ version: string, commit?: string|null, digest: string }} input
 * @returns {{ version: string, commit: string|null, digest: string }}
 * @throws on an invalid version, commit (40 hex digits) or digest
 */
export function buildVersionFile({ version, commit = null, digest }) {
  cacheNames('/', { version, digest }); // validates both
  if (commit !== null && !/^[0-9a-f]{40}$/.test(String(commit))) throw new Error(`Invalid commit ${JSON.stringify(commit)}`);
  return { version, commit, digest };
}

/**
 * The version file of the bundle a module runs from, or null in the repository (no file to ask for).
 * @param {string} moduleUrl import.meta.url of a module under assets/js/
 * @returns {string|null}
 */
export function versionFileUrl(moduleUrl) {
  const info = bundleInfo(moduleUrl);
  return info ? `${info.assets}${VERSION_FILE}` : null;
}

/**
 * A version file as served, checked: anything malformed is null (the page then shows only the
 * version its URL names), and so is the file of another deploy than `version` (a cache that
 * served a newer deploy's file says nothing about this page's commit).
 * @param {unknown} json
 * @param {{ version?: string|null }} [opts] version: the deploy the page runs (lib/pwa.js bundleInfo)
 * @returns {{ version: string, commit: string|null, digest: string|null }|null}
 */
export function parseVersionFile(json, { version = null } = {}) {
  if (!json || typeof json !== 'object' || !isVersion(json.version)) return null;
  if (version !== null && json.version !== version) return null;
  const commit = typeof json.commit === 'string' && /^[0-9a-f]{40}$/.test(json.commit) ? json.commit : null;
  return { version: json.version, commit, digest: isDigest(json.digest) ? json.digest : null };
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
 *   app manifests, icons) and every file under v/<version>/assets/ except the wordlists,
 *   {@link PRECACHE_SKIP} and the intermediate shards ({@link PRECACHE_SKIP_DIRS}). Every module
 *   is in it, so every view opens offline (the ones that need the network then say so).
 * - `wordlists`: each tier and locale pack's versioned path → its hash-keyed cache key; they are
 *   cached on first use only (a Huge tier is 575 KB).
 * - `version` and `digest` (the SHA-256 of the deploy's files, tools/assemble-site.mjs
 *   contentDigest): they name the shell cache ({@link cacheNames}), and the digest makes sw.js
 *   differ whenever the files do, even under a version used before — a byte-identical sw.js is
 *   never installed again, so the old files would be served for good.
 * The cache names themselves depend on the scope, which only the worker knows: it derives them.
 * @param {{ version: string, digest: string, rootFiles: string[], assetFiles: string[], wordlistManifest: object }} input
 *   rootFiles: site-root files, relative ('index.html', 'favicon.svg', 'icons/icon-192.png', …);
 *   assetFiles: every file under assets/, relative to it ('js/app.js', 'data/wordlist-base.txt', …)
 * @returns {{ version: string, digest: string, precache: string[], wordlists: Record<string, string> }}
 * @throws on an invalid version or digest; when a wordlist file of the manifest has no valid
 *   SHA-256 or is not in assets/data/, or when assets/data/ holds a wordlist file the manifest
 *   does not list (it would be precached)
 */
export function buildSwManifest({ version, digest, rootFiles = [], assetFiles = [], wordlistManifest }) {
  cacheNames('/', { version, digest }); // validates both
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
  const skipped = (f) => PRECACHE_SKIP.includes(f) || PRECACHE_SKIP_DIRS.some((dir) => f.startsWith(dir));
  const shell = assetFiles.filter((f) => !listed.has(f) && !skipped(f)).sort().map((f) => `${assets}${f}`);
  return { version, digest, precache: [...root, ...shell], wordlists };
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
