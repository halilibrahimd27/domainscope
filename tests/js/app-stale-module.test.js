/**
 * app.js after a deploy: a lazy import that fails because this page's modules belong to an
 * earlier deploy (a missing export, or the old version directory gone from the Pages bundle) is
 * recognised in Chrome, Firefox and Safari wording, so the shell offers a page reload instead of
 * a Retry that re-imports into the same module map. A fetch failure is only taken for a deploy
 * when the browser is online and the page's own module answers 404: offline or on a dropped
 * connection the same error must keep the plain network banner. No DOM, no network.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { isStaleModuleError, confirmStaleModule, pageIsOutdated, moduleReloadReason, getGlobalping } from '../../assets/js/app.js';
import { wordlistFellShort } from '../../assets/js/views/subdomains.js';
import { hasString, t, setLang } from '../../assets/js/i18n.js';

const named = (Ctor, message) => new Ctor(message);

test('link errors of a module graph from two deploys (Chrome, Firefox, Safari)', () => {
  for (const message of [
    "The requested module './netinfo.js' does not provide an export named 'isSharedProvider'",
    "The requested module '../lib/ipintel.js' doesn't provide an export named: 'describeNetwork'",
    'import not found: describeNetwork',
    "Importing binding name 'describeNetwork' is not found."
  ]) {
    assert.equal(isStaleModuleError(named(SyntaxError, message)), true, message);
  }
});

test('fetch errors of a lazily imported module (the old version directory is gone)', () => {
  for (const message of [
    'Failed to fetch dynamically imported module: https://example.com/app/v/0123456789ab/assets/js/views/ip.js',
    'error loading dynamically imported module: https://example.com/app/v/0123456789ab/assets/js/views/ip.js',
    'Importing a module script failed.'
  ]) {
    assert.equal(isStaleModuleError(named(TypeError, message)), true, message);
  }
});

test('ordinary failures are not taken for a stale page', () => {
  assert.equal(isStaleModuleError(new TypeError('Failed to fetch')), false, 'a plain network error');
  assert.equal(isStaleModuleError(new DOMException('View unmounted', 'AbortError')), false);
  assert.equal(isStaleModuleError(new Error('does not provide an export named x')), false, 'wrong error type');
  assert.equal(isStaleModuleError(new SyntaxError('Unexpected token < in JSON at position 0')), false);
  assert.equal(isStaleModuleError(new TypeError("Cannot read properties of undefined (reading 'mount')")), false);
  for (const v of [null, undefined, '', 'Failed to fetch dynamically imported module', 42, {}]) {
    assert.equal(isStaleModuleError(v), false, String(v));
  }
});

const FETCH_FAILED = 'Failed to fetch dynamically imported module: https://example.com/app/v/0123456789ab/assets/js/views/ip.js';

/** A probe that records its calls and answers with `status` (or rejects with an Error). */
function probeOf(status) {
  const probe = async () => {
    probe.calls += 1;
    if (status instanceof Error) throw status;
    return status;
  };
  probe.calls = 0;
  return probe;
}

test('a fetch failure is a deploy only when online and the page module itself is gone (404)', async () => {
  const err = new TypeError(FETCH_FAILED);
  const gone = probeOf(404);
  assert.equal(await confirmStaleModule(err, { online: true, probe: gone }), true);
  assert.equal(gone.calls, 1);
  // navigator.onLine unknown (undefined): the probe decides
  assert.equal(await confirmStaleModule(err, { probe: probeOf(404) }), true);
  for (const status of [200, 304, 500, 503]) {
    assert.equal(await confirmStaleModule(err, { online: true, probe: probeOf(status) }), false, `HTTP ${status}`);
  }
  assert.equal(await confirmStaleModule(err, { online: true, probe: probeOf(new TypeError('Failed to fetch')) }), false, 'network error');
  assert.equal(await confirmStaleModule(err, { online: true, probe: probeOf(new DOMException('timed out', 'TimeoutError')) }), false, 'timeout');
});

test('offline, a failed import is never taken for a deploy (and nothing is probed)', async () => {
  const probe = probeOf(404);
  assert.equal(await confirmStaleModule(new TypeError(FETCH_FAILED), { online: false, probe }), false);
  assert.equal(await pageIsOutdated({ online: false, probe }), false);
  assert.equal(probe.calls, 0);
});

test('a link error needs no probe; an unrelated error is not probed either', async () => {
  const probe = probeOf(new Error('must not be called'));
  const link = new SyntaxError("The requested module './netinfo.js' does not provide an export named 'isSharedProvider'");
  assert.equal(await confirmStaleModule(link, { online: true, probe }), true);
  assert.equal(await confirmStaleModule(new TypeError('Failed to fetch'), { online: true, probe }), false);
  assert.equal(await confirmStaleModule(null, { online: true, probe }), false);
  assert.equal(probe.calls, 0);
});

test('a module whose download failed but that answers now is stuck in this page: only a reload loads it', async () => {
  const VIEW = 'https://example.com/app/v/0123456789ab/assets/js/views/ip.js';
  /** Answers the page's own module (no URL) with `own`, the failed module's URL with `failed`. */
  const probeBy = (own, failed) => {
    const probe = async (url) => {
      probe.urls.push(url ?? 'own');
      const status = url === undefined ? own : failed;
      if (status instanceof Error) throw status;
      return status;
    };
    probe.urls = [];
    return probe;
  };
  // Chrome and Firefox name the module: it answers again, yet the browser keeps the failed fetch.
  for (const message of [`Failed to fetch dynamically imported module: ${VIEW}`, `error loading dynamically imported module: ${VIEW}`]) {
    const probe = probeBy(200, 200);
    assert.equal(await moduleReloadReason(new TypeError(message), { online: true, probe }), 'stuck', message);
    assert.deepEqual(probe.urls, ['own', VIEW]);
  }
  // Still unreachable, missing or failing: a network problem, Retry stays.
  for (const failed of [new TypeError('Failed to fetch'), 404, 500, 304]) {
    assert.equal(await moduleReloadReason(new TypeError(FETCH_FAILED), { online: true, probe: probeBy(200, failed) }), null, String(failed));
  }
  // Safari names no URL; offline nothing is probed; an earlier deploy is 'outdated', as before.
  assert.equal(await moduleReloadReason(new TypeError('Importing a module script failed.'), { online: true, probe: probeBy(200, 200) }), null);
  const offline = probeBy(200, 200);
  assert.equal(await moduleReloadReason(new TypeError(FETCH_FAILED), { online: false, probe: offline }), null);
  assert.deepEqual(offline.urls, []);
  const gone = probeBy(404, 404);
  assert.equal(await moduleReloadReason(new TypeError(FETCH_FAILED), { online: true, probe: gone }), 'outdated');
  assert.deepEqual(gone.urls, ['own']);
  const link = new SyntaxError("The requested module './netinfo.js' does not provide an export named 'isSharedProvider'");
  assert.equal(await moduleReloadReason(link, { online: true, probe: probeBy(new Error('no probe'), 200) }), 'outdated');
  assert.equal(await moduleReloadReason(new TypeError('Failed to fetch'), { online: true, probe: probeBy(200, 200) }), null, 'not an import');
});

test('a scan whose wordlist fell short asks the shell to check for a newer deploy', () => {
  assert.equal(wordlistFellShort({ warnings: [{ code: 'WORDLIST_DEGRADED', detail: 'large→smart' }] }), true);
  assert.equal(wordlistFellShort({ warnings: [{ code: 'TRUNCATED' }] }), false);
  for (const v of [null, undefined, {}, { warnings: null }]) assert.equal(wordlistFellShort(v), false, String(v));
});

test('the outdated-page hint exists in English and Turkish and differs', () => {
  for (const key of ['shell.viewOutdated', 'shell.viewStuck', 'shell.reload']) {
    assert.ok(hasString(key, 'en') && hasString(key, 'tr'), key);
  }
  try {
    setLang('en');
    const en = t('shell.viewOutdated');
    assert.match(en, /updated/i);
    assert.match(en, /reload/i);
    setLang('tr');
    const tr = t('shell.viewOutdated');
    assert.match(tr, /güncellen/i);
    assert.match(tr, /yenile/i);
    assert.notEqual(en, tr);
  } finally {
    setLang('en');
  }
});

test('a stale Globalping module still rejects to the caller (and is not cached)', async () => {
  const stale = new TypeError('Failed to fetch dynamically imported module: https://example.com/v/old/assets/js/lib/globalping.js');
  await assert.rejects(getGlobalping(() => Promise.reject(stale)), (err) => err === stale);
  const client = { id: 'fresh' };
  assert.equal(await getGlobalping(() => Promise.resolve({ createGlobalping: () => client })), client, 'the next call loads again');
});
