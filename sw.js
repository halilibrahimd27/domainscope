/*
 * sw.js — DomainScope's service worker: a classic script at the site root, so its scope is the
 * whole app. It decides nothing itself: tools/assemble-site.mjs writes the deploy's manifest into
 * BUILD below (assets/js/lib/pwa.js buildSwManifest — the version, the app shell to precache and
 * the wordlist files with their hash keys). In the repository BUILD stays null: the worker answers
 * no request, so everything goes to the network as if it were not there (the app registers it
 * only from the Pages bundle anyway). The one thing it does there: when a checkout is served where
 * a bundle was (`serve.mjs --root _site`, then `npm run serve` on the same port), the browser's
 * update check installs this file over the bundle's worker, and it takes over at once and deletes
 * the bundle's caches, so the next load is the checkout rather than a cached deploy.
 *
 * - install: precache this version's app shell into domainscope-shell-<version>, past the HTTP
 *   cache. The index.html fetched must be this version's: a CDN still serving the previous one
 *   fails the install, and the browser tries again at its next update check.
 * - activate: delete the shell caches of other versions and the wordlists this version does not
 *   list, then take control of the open pages (the tab that installed it keeps working offline).
 * - fetch, same-origin GETs inside the scope only:
 *     a navigation to the app (the site root or index.html)  → the cached index.html;
 *     a file of the app shell                                 → the cache, else the network;
 *     a wordlist tier or locale pack                          → the cache under its content hash,
 *                                                               else the network (then cached);
 *   anything else — every third-party API (DoH resolvers, CT logs, RDAP, RIPEstat, Globalping),
 *   a URL with a query string, a HEAD or POST — is not intercepted and never cached.
 * - message { type: 'skip-waiting' }: the page's "Update ready — Reload" activates this version.
 *
 * Must stay a plain script (no modules: every browser runs a classic worker) and never cache
 * anything the page computed or the user typed.
 */
'use strict';

const BUILD = null; // tools/assemble-site.mjs writes the deploy's manifest here

/** The scope's path, e.g. '/domainscope/'. */
function scopePath() {
  return new URL(self.registration.scope).pathname;
}

/** The path of a same-origin URL inside the scope, relative to it; null outside it. */
function scopeRelative(url) {
  if (url.origin !== self.location.origin) return null;
  const base = scopePath();
  return url.pathname.startsWith(base) ? url.pathname.slice(base.length) : null;
}

/** A cache key (a path relative to the scope) as an absolute URL. */
function keyUrl(path) {
  return new URL(path, self.registration.scope).href;
}

/** A response that was redirected cannot answer a navigation: keep its body and headers only. */
async function unredirected(res) {
  if (!res.redirected) return res;
  return new Response(await res.blob(), { status: res.status, statusText: res.statusText, headers: res.headers });
}

async function precache(build) {
  const cache = await caches.open(build.shellCache);
  const marker = `v/${build.version}/assets/`;
  await Promise.all(build.precache.map(async (path) => {
    const res = await fetch(new Request(keyUrl(path), { cache: 'reload', credentials: 'same-origin' }));
    if (!res.ok) throw new Error(`precache ${path}: HTTP ${res.status}`);
    if (path === './' && !(await res.clone().text()).includes(marker)) {
      throw new Error(`precache: index.html is not version ${build.version} yet`);
    }
    await cache.put(keyUrl(path), await unredirected(res));
  }));
}

async function cleanUp(build) {
  const keep = [build.shellCache, build.wordlistCache];
  for (const name of await caches.keys()) {
    if (name.startsWith(build.cachePrefix) && !keep.includes(name)) await caches.delete(name);
  }
  const wanted = new Set(Object.values(build.wordlists).map(keyUrl));
  const words = await caches.open(build.wordlistCache);
  for (const req of await words.keys()) {
    if (!wanted.has(req.url)) await words.delete(req);
  }
  await self.clients.claim();
}

/** Cache first: the entry under `key`, else the network (not stored). */
async function cacheFirst(cacheName, key, request) {
  const hit = await (await caches.open(cacheName)).match(key);
  return hit || fetch(request);
}

/** A wordlist: the copy under its content hash, else the network, stored once it arrived whole. */
async function wordlist(build, key, event) {
  const cache = await caches.open(build.wordlistCache);
  const hit = await cache.match(key);
  if (hit) return hit;
  const res = await fetch(event.request);
  if (res.status === 200 && res.type === 'basic') event.waitUntil(cache.put(key, res.clone()));
  return res;
}

/**
 * How to answer a request, or null to leave it to the network.
 * @returns {(() => Promise<Response>)|null}
 */
function route(build, event) {
  const request = event.request;
  if (request.method !== 'GET') return null;
  const url = new URL(request.url);
  const path = scopeRelative(url);
  if (path === null) return null;
  // The app never reads its query string: a navigation with one still gets the app.
  if (request.mode === 'navigate' && (path === '' || path === 'index.html')) {
    return () => cacheFirst(build.shellCache, keyUrl('./'), request);
  }
  if (url.search) return null;
  if (Object.prototype.hasOwnProperty.call(build.wordlists, path)) {
    const key = keyUrl(build.wordlists[path]);
    return () => wordlist(build, key, event);
  }
  if (build.precache.includes(path)) return () => cacheFirst(build.shellCache, keyUrl(path), request);
  return null;
}

if (BUILD) {
  self.addEventListener('install', (event) => {
    event.waitUntil(precache(BUILD));
  });
  self.addEventListener('activate', (event) => {
    event.waitUntil(cleanUp(BUILD));
  });
  self.addEventListener('fetch', (event) => {
    const answer = route(BUILD, event);
    if (answer) event.respondWith(answer());
  });
  self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'skip-waiting') self.skipWaiting();
  });
} else {
  // The repository's copy replacing a deployed worker: no fetch handler, the deploy's caches gone.
  self.addEventListener('install', () => self.skipWaiting());
  self.addEventListener('activate', (event) => {
    event.waitUntil(caches.keys().then((names) => Promise.all(names
      .filter((name) => name.startsWith('domainscope-'))
      .map((name) => caches.delete(name)))));
  });
}
