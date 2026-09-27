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

import { isStaleModuleError, confirmStaleModule, pageIsOutdated, getGlobalping } from '../../assets/js/app.js';
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

test('the outdated-page hint exists in English and Turkish and differs', () => {
  for (const key of ['shell.viewOutdated', 'shell.reload']) {
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
