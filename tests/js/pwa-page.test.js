/**
 * ui/pwa.js against a fake navigator.serviceWorker: the worker is registered from the Pages
 * bundle only (never in development, without service workers or outside a secure context), an
 * update is announced only when a new version installed next to a running one, and a reload
 * goes through a waiting version (it takes control first). Also the manifest language switch.
 * No DOM, no browser.
 */
import { test, describe, mock } from 'node:test';
import assert from 'node:assert/strict';
import { registerServiceWorker, reloadPage, setManifestLang } from '../../assets/js/ui/pwa.js';
import { hasString } from '../../assets/js/i18n.js';

const BUNDLE = 'https://example.github.io/domainscope/v/0123456789ab/assets/js/ui/pwa.js';

/** A tiny EventTarget stand-in that records listeners and can fire them. */
function emitter(extra = {}) {
  const listeners = {};
  return Object.assign({
    addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
    fire: (type) => (listeners[type] || []).forEach((fn) => fn({ type })),
    listeners
  }, extra);
}

/** A window-like object: counts reloads, runs timers on demand. */
function fakeWindow() {
  const timers = [];
  return emitter({
    isSecureContext: true,
    reloads: 0,
    location: { reload() { this.owner.reloads += 1; } },
    document: emitter({ visibilityState: 'visible' }),
    setTimeout: (fn, ms) => timers.push({ fn, ms }),
    timers
  });
}

/** navigator.serviceWorker with a registration whose state the test sets. */
function fakeNavigator({ controller = null, waiting = null, fail = null, saveData = false } = {}) {
  const reg = emitter({ waiting, installing: null, updates: 0, update() { this.updates += 1; return Promise.resolve(); } });
  const container = emitter({
    controller,
    calls: [],
    register(url, opts) {
      this.calls.push([url, opts]);
      return fail ? Promise.reject(fail) : Promise.resolve(reg);
    }
  });
  return { nav: { serviceWorker: container, connection: { saveData } }, container, reg };
}

function setup(opts) {
  const win = fakeWindow();
  win.location.owner = win;
  const sw = fakeNavigator(opts);
  const notices = [];
  const env = { moduleUrl: BUNDLE, nav: sw.nav, win, notify: () => notices.push('update') };
  return { win, ...sw, notices, env };
}

describe('registerServiceWorker', () => {
  test('registers sw.js at the site root, with the site root as scope, from the Pages bundle', async () => {
    const s = setup();
    const reg = await registerServiceWorker(s.env);
    assert.equal(reg, s.reg);
    assert.deepEqual(s.container.calls, [['https://example.github.io/domainscope/sw.js', { scope: 'https://example.github.io/domainscope/' }]]);
    assert.deepEqual(s.notices, [], 'nothing to announce on a first install');
  });

  test('registers nothing in development, without service workers or outside a secure context', async () => {
    const dev = setup();
    assert.equal(await registerServiceWorker({ ...dev.env, moduleUrl: 'http://127.0.0.1:8080/domainscope/assets/js/ui/pwa.js' }), null);
    assert.deepEqual(dev.container.calls, []);
    const none = setup();
    assert.equal(await registerServiceWorker({ ...none.env, nav: {} }), null);
    const insecure = setup();
    insecure.win.isSecureContext = false;
    assert.equal(await registerServiceWorker(insecure.env), null);
    assert.deepEqual(insecure.container.calls, []);
  });

  test('Save-Data: no offline copy unasked, but an installed version keeps its worker', async () => {
    const fresh = setup({ saveData: true });
    assert.equal(await registerServiceWorker(fresh.env), null);
    assert.deepEqual(fresh.container.calls, []);
    const installed = setup({ saveData: true, controller: {} });
    assert.equal(await registerServiceWorker(installed.env), installed.reg);
    assert.equal(installed.container.calls.length, 1);
  });

  test('a refused registration is not an app failure: null and a console warning', async () => {
    const s = setup({ fail: new DOMException('The operation is insecure.', 'SecurityError') });
    const warn = mock.method(console, 'warn', () => {});
    try {
      assert.equal(await registerServiceWorker(s.env), null);
      assert.equal(warn.mock.callCount(), 1);
    } finally {
      warn.mock.restore();
    }
  });

  test('announces an update: a version already waiting, or one that installs while another runs the page', async () => {
    const waiting = setup({ controller: {}, waiting: { postMessage() {} } });
    await registerServiceWorker(waiting.env);
    assert.deepEqual(waiting.notices, ['update']);

    const later = setup({ controller: {} });
    await registerServiceWorker(later.env);
    const worker = emitter({ state: 'installing' });
    later.reg.installing = worker;
    later.reg.fire('updatefound');
    worker.fire('statechange');
    assert.deepEqual(later.notices, [], 'still installing');
    worker.state = 'installed';
    worker.fire('statechange');
    assert.deepEqual(later.notices, ['update']);

    // The very first install has no controller yet: nothing to announce.
    const first = setup();
    await registerServiceWorker(first.env);
    const w = emitter({ state: 'installed' });
    first.reg.installing = w;
    first.reg.fire('updatefound');
    w.fire('statechange');
    assert.deepEqual(first.notices, []);
  });

  test('another tab took the update: this page, whose version it dropped, offers the reload too', async () => {
    const s = setup({ controller: {} });
    await registerServiceWorker(s.env);
    s.reg.active = { state: 'activated' };
    s.container.fire('controllerchange'); // "Reload" clicked in another tab
    assert.deepEqual(s.notices, ['update']);
    assert.equal(s.win.reloads, 0, 'nothing reloads by itself');
    // Its Reload goes straight to the version now in control: no update check, no waiting.
    await reloadPage({ win: s.win });
    assert.equal(s.reg.updates, 0);
    assert.equal(s.win.reloads, 1);

    // A first install claims a page nothing controlled: not an update.
    const first = setup();
    await registerServiceWorker(first.env);
    first.container.fire('controllerchange');
    assert.deepEqual(first.notices, []);
    first.container.fire('controllerchange'); // later, another tab's update
    assert.deepEqual(first.notices, ['update']);
  });

  test('an open page asks for a new version when it becomes visible or comes online, at most hourly', async () => {
    mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
    try {
      const s = setup();
      await registerServiceWorker(s.env);
      s.win.document.fire('visibilitychange');
      s.win.fire('online');
      assert.equal(s.reg.updates, 0, 'registration just checked');
      mock.timers.tick(60 * 60 * 1000);
      s.win.document.visibilityState = 'hidden';
      s.win.document.fire('visibilitychange');
      assert.equal(s.reg.updates, 0, 'not while hidden');
      s.win.document.visibilityState = 'visible';
      s.win.document.fire('visibilitychange');
      s.win.fire('online');
      assert.equal(s.reg.updates, 1, 'once per hour');
    } finally {
      mock.timers.reset();
    }
  });
});

describe('reloadPage', () => {
  test('without a service worker in control it is a plain reload', async () => {
    const s = setup();
    await registerServiceWorker(s.env);
    await reloadPage({ win: s.win });
    assert.equal(s.win.reloads, 1);
  });

  test('with nothing newer on the server it is a plain reload after one update check', async () => {
    const s = setup({ controller: {} });
    await registerServiceWorker(s.env);
    s.reg.active = { state: 'activated' };
    await reloadPage({ win: s.win });
    assert.equal(s.reg.updates, 1);
    assert.equal(s.win.reloads, 1);
  });

  test('"this page is older than the site": it asks for the new version, waits for its install, then goes through it', async () => {
    const messages = [];
    const s = setup({ controller: {} });
    await registerServiceWorker(s.env);
    s.reg.active = { state: 'activated' };
    const worker = emitter({ state: 'installing', postMessage: (m) => messages.push(m), removeEventListener() {} });
    s.reg.update = () => {
      s.reg.installing = worker; // the browser found a new sw.js and is precaching its app shell
      return Promise.resolve();
    };
    const reloading = reloadPage({ win: s.win });
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(messages, [], 'not before it has installed');
    worker.state = 'installed';
    worker.fire('statechange');
    await reloading;
    assert.deepEqual(messages, [{ type: 'skip-waiting' }]);
    assert.equal(s.win.reloads, 0, 'not before the new version controls the page');
    s.container.fire('controllerchange');
    assert.equal(s.win.reloads, 1);
  });

  test('a second click while it waits for the new version joins the first: one update check, one takeover', async () => {
    const messages = [];
    const s = setup({ controller: {} });
    await registerServiceWorker(s.env);
    s.reg.active = { state: 'activated' };
    const worker = emitter({ state: 'installing', postMessage: (m) => messages.push(m), removeEventListener() {} });
    s.reg.update = () => {
      s.reg.updates = (s.reg.updates || 0) + 1;
      s.reg.installing = worker;
      return Promise.resolve();
    };
    const one = reloadPage({ win: s.win });
    const two = reloadPage({ win: s.win });
    assert.equal(one, two);
    await new Promise((r) => setImmediate(r));
    worker.state = 'installed';
    worker.fire('statechange');
    await Promise.all([one, two]);
    assert.equal(s.reg.updates, 1);
    assert.deepEqual(messages, [{ type: 'skip-waiting' }]);
    s.container.fire('controllerchange');
    assert.equal(s.win.reloads, 1);
  });

  test('with a waiting version it asks it to take over and reloads once it controls the page', async () => {
    const messages = [];
    const s = setup({ controller: {}, waiting: { state: 'installed', postMessage: (m) => messages.push(m) } });
    await registerServiceWorker(s.env);
    const before = s.win.timers.length;
    await reloadPage({ win: s.win });
    assert.deepEqual(messages, [{ type: 'skip-waiting' }]);
    assert.equal(s.win.reloads, 0, 'not before the new version controls the page');
    s.container.fire('controllerchange');
    assert.equal(s.win.reloads, 1);
    // should the takeover never come, the fallback timer reloads anyway
    const fallback = s.win.timers.slice(before);
    assert.equal(fallback.length, 1);
    assert.ok(fallback[0].ms > 0 && fallback[0].ms <= 5000);
  });
});

describe('setManifestLang', () => {
  const doc = () => {
    const link = { href: 'manifest.webmanifest', getAttribute() { return this.href; }, setAttribute(_, v) { this.href = v; } };
    return { link, querySelector: (sel) => (sel === 'link[rel="manifest"]' ? link : null) };
  };

  test('links the Turkish manifest for Turkish and the English one otherwise', () => {
    const d = doc();
    setManifestLang('tr', d);
    assert.equal(d.link.href, 'manifest.tr.webmanifest');
    setManifestLang('en', d);
    assert.equal(d.link.href, 'manifest.webmanifest');
    assert.doesNotThrow(() => setManifestLang('tr', { querySelector: () => null }));
  });
});

test('the update notice is translated', () => {
  for (const key of ['pwa.updateReady', 'pwa.reload', 'pwa.loading']) {
    assert.ok(hasString(key, 'en') && hasString(key, 'tr'), key);
  }
});
