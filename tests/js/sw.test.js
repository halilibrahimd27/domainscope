/**
 * sw.js, the service worker, run in a node:vm context with a fake Cache Storage, fetch and
 * worker scope: as the repository ships it (no manifest: it answers nothing, and only clears a
 * deploy's caches when it replaces one) and as tools/assemble-site.mjs writes it for a deploy —
 * the precache at install (past the HTTP cache,
 * refusing a stale index.html), the clean-up at activation (earlier versions, dropped wordlists,
 * nothing it does not own), the routing (the app shell cache first, wordlists by content hash)
 * and above all what it must leave alone: third-party APIs, query strings, other methods and
 * anything outside the app are never answered from or put into a cache. No network, no browser.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSwManifest, CACHE_PREFIX } from '../../assets/js/lib/pwa.js';
import { injectSwBuild } from '../../tools/assemble-site.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SOURCE = readFileSync(join(ROOT, 'sw.js'), 'utf8');
const SCOPE = 'https://example.github.io/domainscope/';
const HASH = 'c'.repeat(64);
const OLD_HASH = 'd'.repeat(64);

/** A small deploy: two modules, a stylesheet, the sample certificate and two wordlists. */
function deploy(version) {
  return buildSwManifest({
    version,
    rootFiles: ['index.html', 'favicon.svg'],
    assetFiles: ['css/style.css', 'data/locale/tr.txt', 'data/sample-cert.pem', 'data/wordlist-base.txt', 'js/app.js', 'js/views/cert.js'],
    wordlistManifest: { tiers: { smart: { file: 'wordlist-base.txt', sha256: HASH } }, locales: { tr: { sha256: HASH } } }
  });
}

/** Cache Storage in memory: cache name → (URL → Response). */
class FakeCaches {
  constructor() {
    this.store = new Map();
  }

  async open(name) {
    if (!this.store.has(name)) {
      const entries = new Map();
      const key = (k) => (typeof k === 'string' ? k : k.url);
      this.store.set(name, {
        entries,
        match: async (k) => entries.get(key(k))?.clone(), // like the Cache API: a fresh Response each time
        put: async (k, res) => { entries.set(key(k), res); },
        keys: async () => [...entries.keys()].map((url) => ({ url })),
        delete: async (k) => entries.delete(key(k))
      });
    }
    return this.store.get(name);
  }

  async keys() {
    return [...this.store.keys()];
  }

  async delete(name) {
    return this.store.delete(name);
  }

  urls(name) {
    return this.store.has(name) ? [...this.store.get(name).entries.keys()].sort() : [];
  }
}

/** A same-origin network response, typed like a browser's. */
function served(body, { status = 200 } = {}) {
  const res = new Response(body, { status });
  Object.defineProperty(res, 'type', { value: 'basic' });
  return res;
}

/**
 * Load sw.js (optionally with a deploy's manifest) into a fresh worker-like global.
 * `network(url, request)` answers fetch(); every request the worker sends is recorded.
 */
function loadWorker({ build = null, network, caches = new FakeCaches() } = {}) {
  const listeners = {};
  const sent = [];
  const state = { claimed: false, skipped: false };
  const self = {
    registration: { scope: SCOPE },
    location: { origin: new URL(SCOPE).origin },
    clients: { claim: async () => { state.claimed = true; } },
    skipWaiting: () => { state.skipped = true; },
    addEventListener: (type, fn) => { listeners[type] = fn; }
  };
  const fetch = async (input) => {
    const url = typeof input === 'string' ? input : input.url;
    sent.push({ url, cache: input.cache ?? null });
    const res = await network(url, input);
    if (!res) throw new TypeError('Failed to fetch');
    return res;
  };
  const context = vm.createContext({ self, caches, fetch, Request, Response, URL, Blob, console });
  vm.runInContext(build ? injectSwBuild(SOURCE, build) : SOURCE, context, { filename: 'sw.js' });
  return { listeners, sent, state, caches };
}

/** Dispatch an extendable event; resolves once every waitUntil promise has settled. */
async function extendable(fn, extra = {}) {
  const waits = [];
  fn({ ...extra, waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
}

/** Dispatch a fetch event: the Response the worker answers with, or null when it lets it pass. */
async function request(worker, url, { method = 'GET', mode = 'cors' } = {}) {
  let answer = null;
  const waits = [];
  worker.listeners.fetch({
    request: { url, method, mode },
    respondWith: (p) => { answer = p; },
    waitUntil: (p) => waits.push(p)
  });
  const res = answer ? await answer : null;
  await Promise.all(waits);
  return res;
}

/** The deploy's files on a fake server: index.html of `version`, every other file its own path. */
function site(version, { index = `<script type="module" src="v/${version}/assets/js/app.js"></script>` } = {}) {
  return (url) => {
    const path = url.slice(SCOPE.length);
    if (!url.startsWith(SCOPE)) return served(`third party ${url}`);
    if (path === '') return served(index);
    return served(`file ${path}`);
  };
}

async function installed(version = 'one', caches = new FakeCaches()) {
  const build = deploy(version);
  const worker = loadWorker({ build, caches, network: site(version) });
  await extendable(worker.listeners.install);
  await extendable(worker.listeners.activate);
  worker.sent.length = 0;
  return { worker, build };
}

describe('sw.js in the repository (no build)', () => {
  test('answers no request: no fetch handler, every request goes to the network', () => {
    const worker = loadWorker({ network: () => served('x') });
    assert.deepEqual(Object.keys(worker.listeners).sort(), ['activate', 'install']);
  });

  test('replacing a deployed worker (a checkout served where a bundle was) it takes over and drops the deploy\'s caches', async () => {
    const caches = new FakeCaches();
    await (await caches.open('domainscope-shell-one')).put(`${SCOPE}index.html`, served('cached deploy'));
    await (await caches.open('domainscope-wordlists')).put(`${SCOPE}wordlists/${HASH}/tr.txt`, served('tr'));
    await (await caches.open('another-app')).put('https://example.github.io/other/x', served('x'));
    const worker = loadWorker({ caches, network: () => served('x') });
    await extendable(worker.listeners.install);
    assert.equal(worker.state.skipped, true, 'takes over at once');
    await extendable(worker.listeners.activate);
    assert.deepEqual(await caches.keys(), ['another-app']);
    assert.deepEqual(worker.sent, []);
    assert.ok(SOURCE.includes(`name.startsWith('${CACHE_PREFIX}')`), 'the prefix of lib/pwa.js');
  });

  test('has exactly one BUILD line for tools/assemble-site.mjs to fill', () => {
    assert.equal(SOURCE.match(/^const BUILD = null;/gm).length, 1);
    assert.throws(() => injectSwBuild('const x = 1;', deploy('one')), /one "const BUILD = null;" line, found 0/);
    assert.throws(() => injectSwBuild(`${SOURCE}\nconst BUILD = null;`, deploy('one')), /found 2/);
    const filled = injectSwBuild(SOURCE, { version: '$&$1' });
    assert.match(filled, /^const BUILD = \{\n {2}"version": "\$&\$1"\n\}; \/\/ written by tools\/assemble-site\.mjs$/m, 'no replacement patterns');
  });
});

describe('install', () => {
  test('precaches the app shell of this version past the HTTP cache, index.html as ./', async () => {
    const build = deploy('one');
    const worker = loadWorker({ build, network: site('one') });
    await extendable(worker.listeners.install);
    const urls = build.precache.map((p) => new URL(p, SCOPE).href).sort();
    assert.deepEqual(worker.caches.urls('domainscope-shell-one'), urls);
    assert.ok(worker.sent.every((r) => r.cache === 'reload'), 'past the HTTP cache');
    assert.ok(!worker.sent.some((r) => /wordlist|locale/.test(r.url)), 'no wordlist downloaded at install');
    assert.match(await (await worker.caches.store.get('domainscope-shell-one').match(SCOPE)).text(), /v\/one\/assets\/js\/app\.js/);
  });

  test('fails while the server still sends the previous index.html, or any file fails', async () => {
    const stale = loadWorker({ build: deploy('two'), network: site('one') });
    await assert.rejects(extendable(stale.listeners.install), /index\.html is not version two yet/);
    const broken = loadWorker({
      build: deploy('two'),
      network: (url) => (url.endsWith('cert.js') ? served('gone', { status: 404 }) : site('two')(url))
    });
    await assert.rejects(extendable(broken.listeners.install), /precache v\/two\/assets\/js\/views\/cert\.js: HTTP 404/);
  });
});

describe('activate', () => {
  test('deletes the other versions\' shell caches and dropped wordlists, keeps what is not its own, claims the pages', async () => {
    const caches = new FakeCaches();
    await (await caches.open('domainscope-shell-zero')).put(`${SCOPE}v/zero/assets/js/app.js`, served('old'));
    await (await caches.open('another-app')).put('https://example.github.io/other/x', served('x'));
    const words = await caches.open('domainscope-wordlists');
    await words.put(`${SCOPE}wordlists/${HASH}/wordlist-base.txt`, served('kept'));
    await words.put(`${SCOPE}wordlists/${OLD_HASH}/wordlist-base.txt`, served('dropped'));
    const { worker } = await installed('one', caches);
    assert.deepEqual((await caches.keys()).sort(), ['another-app', 'domainscope-shell-one', 'domainscope-wordlists']);
    assert.deepEqual(caches.urls('domainscope-wordlists'), [`${SCOPE}wordlists/${HASH}/wordlist-base.txt`]);
    assert.equal(worker.state.claimed, true);
    assert.equal(worker.state.skipped, false, 'an update waits for the page to ask');
  });

  test('"skip-waiting" from the page activates a waiting version; other messages do nothing', async () => {
    const { worker } = await installed('one');
    worker.listeners.message({ data: { type: 'hello' } });
    worker.listeners.message({ data: null });
    assert.equal(worker.state.skipped, false);
    worker.listeners.message({ data: { type: 'skip-waiting' } });
    assert.equal(worker.state.skipped, true);
  });
});

describe('fetch', () => {
  test('a navigation to the app gets the cached index.html, whatever its query; offline too', async () => {
    const { worker } = await installed('one');
    for (const url of [SCOPE, `${SCOPE}index.html`, `${SCOPE}?utm_source=pwa`]) {
      const res = await request(worker, url, { mode: 'navigate' });
      assert.match(await res.text(), /v\/one\/assets\/js\/app\.js/, url);
    }
    assert.deepEqual(worker.sent, [], 'answered from the cache');
  });

  test('a shell file comes from the cache; one missing from it from the network, not stored', async () => {
    const caches = new FakeCaches();
    const { worker } = await installed('one', caches);
    assert.equal(await (await request(worker, `${SCOPE}v/one/assets/js/views/cert.js`)).text(), 'file v/one/assets/js/views/cert.js');
    assert.deepEqual(worker.sent, []);
    await (await caches.open('domainscope-shell-one')).delete(`${SCOPE}v/one/assets/css/style.css`);
    assert.equal(await (await request(worker, `${SCOPE}v/one/assets/css/style.css`)).text(), 'file v/one/assets/css/style.css');
    assert.equal(worker.sent.length, 1);
    assert.ok(!caches.urls('domainscope-shell-one').includes(`${SCOPE}v/one/assets/css/style.css`), 'not stored again');
  });

  test('a wordlist is fetched once, stored under its content hash and reused by the next deploy', async () => {
    const caches = new FakeCaches();
    const { worker } = await installed('one', caches);
    const first = await request(worker, `${SCOPE}v/one/assets/data/wordlist-base.txt`);
    assert.equal(await first.text(), 'file v/one/assets/data/wordlist-base.txt');
    assert.equal(worker.sent.length, 1);
    assert.deepEqual(caches.urls('domainscope-wordlists'), [`${SCOPE}wordlists/${HASH}/wordlist-base.txt`]);
    await request(worker, `${SCOPE}v/one/assets/data/wordlist-base.txt`);
    assert.equal(worker.sent.length, 1, 'the second request is answered from the cache');
    // Deploy two: same content, new URL — no download.
    const next = await installed('two', caches);
    const again = await request(next.worker, `${SCOPE}v/two/assets/data/wordlist-base.txt`);
    assert.equal(await again.text(), 'file v/one/assets/data/wordlist-base.txt');
    assert.deepEqual(next.worker.sent, []);
  });

  test('a failed wordlist download is passed on, never stored', async () => {
    const caches = new FakeCaches();
    const build = deploy('one');
    const worker = loadWorker({ build, caches, network: (url) => (/tr\.txt$/.test(url) ? served('nope', { status: 404 }) : site('one')(url)) });
    await extendable(worker.listeners.install);
    const res = await request(worker, `${SCOPE}v/one/assets/data/locale/tr.txt`);
    assert.equal(res.status, 404);
    assert.deepEqual(caches.urls('domainscope-wordlists'), []);
  });

  test('never answers or caches third-party APIs, query strings, other methods or anything outside the app', async () => {
    const caches = new FakeCaches();
    const { worker } = await installed('one', caches);
    const before = JSON.stringify([...caches.store.keys()].map((n) => [n, caches.urls(n)]));
    const untouched = [
      ['https://cloudflare-dns.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE'],
      ['https://crt.sh/?q=%25.example.com&output=json'],
      ['https://api.globalping.io/v1/measurements', { method: 'POST' }],
      ['https://stat.ripe.net/data/prefix-overview/data.json?resource=192.0.2.1'],
      [`${SCOPE}v/one/assets/js/app.js`, { method: 'HEAD' }], // the shell's "is this version still there?" probe
      [`${SCOPE}v/one/assets/js/app.js?x=1`],
      [`${SCOPE}v/one/assets/data/wordlist-base.txt?nocache`],
      [`${SCOPE}cli/ssl_origin_scan.py`],
      [`${SCOPE}v/zero/assets/js/app.js`], // another version's file
      ['https://example.github.io/other-site/index.html', { mode: 'navigate' }],
      [`${SCOPE}v/one/assets/js/app.js`, { method: 'POST' }]
    ];
    for (const [url, opts] of untouched) assert.equal(await request(worker, url, opts), null, url);
    assert.deepEqual(worker.sent, []);
    assert.equal(JSON.stringify([...caches.store.keys()].map((n) => [n, caches.urls(n)])), before);
  });
});
