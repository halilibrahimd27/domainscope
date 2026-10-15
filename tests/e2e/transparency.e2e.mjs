#!/usr/bin/env node
/**
 * transparency.e2e.mjs — end-to-end test of Certificate › Transparency (ui/sct-panel.js over
 * lib/sct.js) in a real headless Chrome/Edge. OFFLINE: Google's CT log list is answered inside the
 * page with tests/fixtures/sct/log_list.json (any other request to a CT host fails there).
 *
 *   node tests/e2e/transparency.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * What is checked:
 *   - nothing reads the log list before the tab is opened, and a certificate without SCTs (a
 *     precertificate) never reads it at all;
 *   - sct_compliant.pem: one row per embedded SCT with the log name, operator, time, "Embedded in
 *     the certificate" and whether it counts; Chrome and Apple both "looks compliant"; the list is
 *     read once (a second certificate and a second open reuse it);
 *   - sct_one_operator.pem: Chrome and Apple do not meet the policy, the reason in plain language;
 *   - the precertificate says so and the list is not read;
 *   - Turkish; 375 px without horizontal scroll; no missing i18n keys; no console errors.
 */

import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { pinnedClockScript } from './clock.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions,
  createRunner, gotoRoute, setLangUi, shot, waitReady
} from './scan.e2e.mjs';
import { certificateScts } from '../../assets/js/lib/sct.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';

const SCT_DIR = path.join(FIXTURES, 'sct');
const NOW = Date.parse('2026-10-01T12:00:00Z');

const fakeListScript = (list) => `(() => {
  const LIST = ${JSON.stringify(list)};
  window.__logList = { calls: 0 };
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url === 'https://www.gstatic.com/ct/log_list/v3/log_list.json') {
      window.__logList.calls += 1;
      return new Response(JSON.stringify(LIST), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return realFetch(input, init);
  };
})();`;

async function load(page, file) {
  // The old result goes first, so the wait below is for the new one.
  await page.evaluate(() => document.querySelectorAll('.cert-overview').forEach((el) => el.remove()));
  const hasReload = await page.evaluate(() => !!document.querySelector('.cert-reload'));
  if (hasReload) await page.evaluate(() => { document.querySelector('.cert-reload').open = true; });
  await page.setFileInput(hasReload ? '.cert-reload .filedrop-input' : '.cert-loader-card .filedrop-input', [path.join(SCT_DIR, file)]);
  await page.waitFor(() => document.querySelector('.cert-overview') && document.querySelector('.cert-tabs [data-tab="sct"]'), { message: `result for ${file}` });
}

const panelInfo = (page) => page.evaluate(() => {
  const panel = document.querySelector('[data-role="sct-panel"]');
  return {
    rows: panel ? [...panel.querySelectorAll('tbody tr')].map((tr) => [...tr.children].map((td) => td.textContent)) : [],
    alerts: panel ? [...panel.querySelectorAll('.alert')].map((a) => ({ title: a.querySelector('.alert-title')?.textContent || '', text: a.textContent })) : [],
    list: panel?.querySelector('[data-sct-list]')?.dataset.sctList || null,
    calls: window.__logList.calls
  };
});

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  const listJson = JSON.parse(await readFile(path.join(SCT_DIR, 'log_list.json'), 'utf8'));
  const sctCount = (file) => certificateScts(parseCertificates(readFileSync(path.join(SCT_DIR, file))).certificates[0]).scts.length;

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: pinnedClockScript(NOW) });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeListScript(listJson) });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/cert`);
    await waitReady(page);
    if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');

    run.group('Certificate › Transparency (offline, fixture log list)');
    await run.step('a compliant certificate: the list is read on the first open only, one row per SCT, both policies met', async () => {
      await load(page, 'sct_compliant.pem');
      assertEqual((await panelInfo(page)).rows.length, 0, 'tab not opened yet');
      assertEqual(await page.evaluate(() => window.__logList.calls), 0, 'no log list before the tab opens');
      await page.click('.cert-tabs [data-tab="sct"]');
      await page.waitFor(() => document.querySelector('[data-role="sct-panel"] [data-sct-list]'), { message: 'panel ready' });
      const info = await panelInfo(page);
      assertEqual(info.calls, 1, 'one read of the list');
      assertEqual(info.list, 'live', 'the live (fixture) list');
      assertEqual(info.rows.length, sctCount('sct_compliant.pem'), `rows: ${JSON.stringify(info.rows)}`);
      assert(info.rows.every((r) => /Embedded in the certificate/.test(r[3]) && r[0].length > 3 && r[1].length > 1), `row cells: ${JSON.stringify(info.rows)}`);
      const verdicts = info.alerts.filter((a) => /^(Chrome|Apple)/.test(a.title)).map((a) => a.title);
      assertEqual(verdicts.length, 2, `two policy verdicts: ${JSON.stringify(info.alerts)}`);
      assert(verdicts.every((v) => /looks compliant/.test(v)), `verdicts: ${verdicts}`);
      await assertNoHorizontalScroll(page, 'transparency desktop');
      await shot(page, opts, 'transparency-desktop-light-en');
    });

    await run.step('a second certificate and a second open reuse the list', async () => {
      await load(page, 'sct_one_operator.pem');
      await page.click('.cert-tabs [data-tab="sct"]');
      await page.waitFor(() => document.querySelector('[data-role="sct-panel"] [data-sct-list]'), { message: 'panel ready' });
      const info = await panelInfo(page);
      assertEqual(info.calls, 1, 'still one read');
      const verdicts = info.alerts.filter((a) => /^(Chrome|Apple)/.test(a.title));
      assertEqual(verdicts.length, 2, 'two verdicts');
      assert(verdicts.every((v) => /does not meet the policy/.test(v.title)), `verdicts: ${verdicts.map((v) => v.title)}`);
      assert(verdicts.every((v) => /one operator/.test(v.text)), `reason in plain words: ${verdicts.map((v) => v.text)}`);
    });

    await run.step('a precertificate says so and reads no list', async () => {
      await page.evaluate(() => { window.__logList.calls = 0; });
      await load(page, 'sct_precert.pem');
      await page.click('.cert-tabs [data-tab="sct"]');
      await page.waitFor(() => document.querySelector('[data-role="sct-panel"] .alert'), { message: 'panel ready' });
      const info = await panelInfo(page);
      assert(info.alerts.some((a) => /precertificate/i.test(a.title)), `alerts: ${JSON.stringify(info.alerts)}`);
      assertEqual(info.calls, 0, 'no list read');
    });

    await run.step('Turkish at 375 px, dark: the words, no horizontal scroll', async () => {
      await load(page, 'sct_compliant.pem');
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await page.click('.cert-tabs [data-tab="sct"]');
      await page.waitFor(() => document.querySelector('[data-role="sct-panel"] [data-sct-list]'), { message: 'panel ready' });
      const info = await panelInfo(page);
      assert(info.alerts.filter((a) => /uygun görünüyor/.test(a.title)).length === 2, `Turkish verdicts: ${JSON.stringify(info.alerts)}`);
      assert(info.rows.every((r) => /Sertifikaya gömülü/.test(r[3])), 'Turkish delivery');
      await assertNoHorizontalScroll(page, 'transparency phone');
      await shot(page, opts, 'transparency-mobile-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await page.setViewport({ width: 1440, height: 900 });
    });

    run.group('Quality');
    await run.step('i18n: no missing keys', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'transparency', origin));
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
