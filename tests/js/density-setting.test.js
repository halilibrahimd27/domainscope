/**
 * The Density setting (DESIGN §6.6): saved in the global settings, applied by boot.js before the
 * first paint, never compact on a touch screen, and named in both languages.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';
import { effectiveDensity, DENSITIES, DEFAULT_SETTINGS, sanitizeSettings } from '../../assets/js/state.js';
import { stringIn } from '../../assets/js/i18n.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BOOT = readFileSync(path.join(ROOT, 'assets', 'js', 'boot.js'), 'utf8');
const APP = readFileSync(path.join(ROOT, 'assets', 'js', 'app.js'), 'utf8');

/** Run boot.js against a fake page; returns the attributes it put on <html>. */
function runBoot({ settings, coarse = false, matchMedia = true }) {
  const attrs = {};
  const root = { setAttribute: (k, v) => { attrs[k] = v; }, hasAttribute: (k) => k in attrs };
  const win = {
    localStorage: { getItem: (k) => (k === 'ssds.settings' && settings !== undefined ? JSON.stringify(settings) : null) },
    navigator: { language: 'en', languages: ['en'] },
    setTimeout: () => 0
  };
  if (matchMedia) win.matchMedia = (q) => ({ matches: coarse && q === '(pointer: coarse)' });
  const doc = {
    documentElement: root, readyState: 'complete',
    querySelector: () => null, getElementById: () => null, addEventListener: () => {},
    createElement: () => ({})
  };
  win.document = doc;
  vm.runInNewContext(BOOT, { window: win, document: doc, navigator: win.navigator });
  return attrs;
}

test('compact is a valid value and comfortable is the default', () => {
  assert.deepEqual([...DENSITIES], ['comfortable', 'compact']);
  assert.equal(DEFAULT_SETTINGS.density, 'comfortable');
  assert.equal(sanitizeSettings({ density: 'compact' }).density, 'compact');
  assert.equal(sanitizeSettings({ density: 'tiny' }).density, 'comfortable');
});

test('effectiveDensity: compact only when chosen and the pointer is not coarse', () => {
  assert.equal(effectiveDensity('compact', false), 'compact');
  assert.equal(effectiveDensity('compact', true), 'comfortable');
  assert.equal(effectiveDensity('comfortable', false), 'comfortable');
  assert.equal(effectiveDensity(undefined, false), 'comfortable');
});

test('boot.js sets data-density before first paint, ignores it on touch and without a choice', () => {
  assert.equal(runBoot({ settings: { density: 'compact' } })['data-density'], 'compact');
  assert.equal(runBoot({ settings: { density: 'compact' }, coarse: true })['data-density'], undefined, 'touch screens stay comfortable');
  assert.equal(runBoot({ settings: { density: 'comfortable' } })['data-density'], undefined);
  assert.equal(runBoot({ settings: null })['data-density'], undefined);
  assert.equal(runBoot({ settings: { density: 'compact' }, matchMedia: false })['data-density'], 'compact', 'no matchMedia: not a touch screen we can tell');
  assert.equal(runBoot({ settings: { theme: 'dark', density: 'compact' } })['data-theme'], 'dark', 'the theme still applies');
});

test('the Settings dialog offers the choice and app.js keeps <html> in step', () => {
  assert.match(APP, /label: t\('shell\.density'\)[\s\S]{0,400}state\.updateSettings\(\{ density: v \}\)/);
  assert.match(APP, /applyDensity\(settings\.density\)/);
  assert.match(APP, /applyDensity\(value\.density\)/, 'other tabs and "delete all data" follow');
});

test('the density strings exist in both languages', () => {
  for (const key of ['shell.density', 'shell.densityComfortable', 'shell.densityCompact', 'settings.densityHint']) {
    assert.ok(stringIn('en', key), `${key} (en)`);
    assert.ok(stringIn('tr', key), `${key} (tr)`);
    assert.notEqual(stringIn('en', key), stringIn('tr', key), `${key} is translated`);
  }
});
