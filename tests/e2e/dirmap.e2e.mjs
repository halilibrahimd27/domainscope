#!/usr/bin/env node
/**
 * dirmap.e2e.mjs — end-to-end test of the Endpoint map view (views/dirmap.js over lib/dirmap.js)
 * in a real headless Chrome/Edge. OFFLINE: the reports are tests/fixtures/dirmap/report-*.json
 * (what cli/dir_scan.py writes); a network-level guard (CDP Fetch) fails and records any https
 * request — the suite asserts none.
 *
 *   node tests/e2e/dirmap.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * What is checked:
 *   - navigation: Endpoint map is in "Investigate a domain", marked CLI; the empty page opens with
 *     the steps schema (download → run → open) and the command, not a folded "how to";
 *   - report-a.json: the result header ("2 hosts · 10 paths"), the counts as filters, the answered
 *     paths ready to copy (a click copies one), the path list (found / listing / protected /
 *     redirect), a count filters the list; the CSV and the answered-paths .txt; Copy summary names
 *     hosts and paths only; the steps fold into one line;
 *   - report-b.json joins and the newest report answers for a host; a non-report says why; Forget;
 *   - Turkish + dark, a 375 px and a 320 px phone: no horizontal scroll;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; no request sent.
 */

import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import {
  BASE, FIXTURES, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  csvHeader, gotoRoute, installDownloadCapture, resultAction, setLangUi, shot, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';
import { DIRMAP_CSV_COLUMNS } from '../../assets/js/lib/dirmap.js';

const REPORT_A = path.join(FIXTURES, 'dirmap', 'report-a.json');
const REPORT_B = path.join(FIXTURES, 'dirmap', 'report-b.json');
const VIEW = '.dirmap-view';

async function networkGuard(page) {
  const hits = [];
  page.conn.on('Fetch.requestPaused', (p) => {
    hits.push(p.request.url);
    page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://*' }] });
  return hits;
}

const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
const removeToasts = (page) => page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));

const info = (page) => page.evaluate(() => ({
  title: document.querySelector('.dirmap-head .result-title')?.textContent || '',
  status: Object.fromEntries([...document.querySelectorAll('.dirmap-head .status-item')].map((b) => [b.dataset.status, Number(b.dataset.count)])),
  pressed: [...document.querySelectorAll('.dirmap-head .status-item[aria-pressed="true"]')].map((b) => b.dataset.status),
  found: [...document.querySelectorAll('.dirmap-found-path')].map((b) => b.textContent.trim()),
  rows: [...document.querySelectorAll('.dirmap-table tbody tr.dt-row')].length,
  reports: [...document.querySelectorAll('.dirmap-report')].map((li) => li.dataset.report),
  errors: [...document.querySelectorAll('.dirmap-errors li')].map((li) => li.textContent),
  empty: !!document.querySelector('.dirmap-empty'),
  stepsCompact: document.querySelector('.dirmap-steps')?.classList.contains('is-compact') ?? null
}));

async function choose(page, files, until, message) {
  await page.setFileInput(`${VIEW} .dirmap-drop .filedrop-input`, files);
  return page.waitFor(until, { message, timeout: 15000 });
}

const openImport = (page) => page.evaluate(() => {
  const more = document.querySelector('.dirmap-import-more');
  if (more && !more.open) more.open = true;
});

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-dirmap-e2e-'));
  const notReport = path.join(tmp, 'map.csv');
  await writeFile(notReport, 'host,path\nweb.example.com,/api\n');

  run.group('Node: harness');
  await run.step('run-all orders the dirmap suite with the investigate tools', () => {
    assertEqual(orderSuites(['locales.e2e.mjs', 'dirmap.e2e.mjs', 'domain.e2e.mjs']), ['domain', 'dirmap', 'locales'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: fixture reports only\n`);
  let page = null;
  let netHits = [];
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    netHits = await networkGuard(page);
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/dirmap`);
    await waitReady(page);
    // After the navigation, not before it: page.goto loads a fresh document that would wipe the stub.
    await stubClipboard(page);
    await setLangUi(page, 'en');
    await gotoRoute(page, 'dirmap');

    run.group('Endpoint map (desktop 1440×900, English, light)');
    await run.step('Investigate a domain, marked CLI; the empty page opens with the steps and the command', async () => {
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/subdomains"]'));
        return {
          ids: group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '')) : [],
          tag: document.querySelector('.nav-link[data-view="dirmap"] .nav-cli')?.textContent
        };
      });
      assertEqual(nav.ids, ['domain', 'health', 'subdomains', 'lookup', 'dirmap'], 'the investigate group');
      assertEqual(nav.tag, 'CLI', 'the nav marks a tool that needs the command line');
      const steps = await page.evaluate(() => ({
        first: document.querySelector('.dirmap-view > :first-child')?.classList.contains('dirmap-steps-host'),
        compact: document.querySelector('.dirmap-steps')?.classList.contains('is-compact'),
        title: document.querySelector('.dirmap-steps .cli-steps-title')?.textContent,
        places: [...document.querySelectorAll('.dirmap-steps .cli-step')].map((li) => li.dataset.place),
        code: [...document.querySelectorAll('.dirmap-steps .cli-step[data-place="machine"] pre, .dirmap-steps .cli-step[data-place="machine"] code')].map((c) => c.textContent).join('\n'),
        download: document.querySelector('.dirmap-steps a[download]')?.getAttribute('href'),
        drop: !!document.querySelector('.dirmap-import .dirmap-drop')
      }));
      assertEqual([steps.first, steps.compact, steps.title], [true, false, 'The scan does not run in the browser'], 'the steps, in full, first');
      assertEqual(steps.places, ['browser', 'machine', 'browser'], 'download here, run on your network, open here');
      assert(steps.code.includes('python3 dir_scan.py www.example.com --json map.json'), `the command: ${steps.code}`);
      assertEqual(steps.download, 'cli/dir_scan.py', 'the CLI to download');
      assert(steps.drop, 'the drop zone');
    });

    await run.step('report-a.json: the counts, the answered paths to copy, the list; the steps fold', async () => {
      await choose(page, [REPORT_A], () => document.querySelectorAll('.dirmap-report').length === 1, 'report read');
      await frames(page);
      const v = await info(page);
      assertEqual(v.title, '2 hosts · 10 paths', 'title');
      assertEqual([v.status.found, v.status.listing, v.status.protected, v.status.redirect, v.status.unchecked], [3, 1, 1, 1, 1], 'counts');
      assertEqual(v.found, ['web.example.com/api', 'web.example.com/health', 'web.example.com/files', 'app.example.net/graphql'], 'the answered paths');
      assertEqual(v.stepsCompact, true, 'the steps fold once a report is open');
      assertEqual(v.rows, 6, 'the list shows the answered paths (the default filter)');
      await removeToasts(page);
      await page.click('.dirmap-found-path');
      assertEqual(await takeClipboard(page), ['https://web.example.com/api'], 'a found path copies its URL');
      await shot(page, opts, 'dirmap-desktop');
    });

    await run.step('a count filters the list; the CSV and the answered-paths .txt; Copy summary', async () => {
      await page.click('.dirmap-head .status-item[data-status="protected"]');
      const v = await info(page);
      assertEqual([v.pressed, v.rows], [['protected'], 1], 'the protected filter');
      await page.click('.dirmap-head .status-item[data-status="protected"]');  // off again
      // Copy summary first (before an Export menu is opened over the header).
      await removeToasts(page);
      await page.click('[data-summary="dirmap"] [data-action="copy-summary"]');
      await page.waitFor(() => !!document.querySelector('.toast'), { message: 'copied' });
      const md = (await takeClipboard(page)).join('\n');
      assert(md.includes('Endpoint map · 2 hosts') && md.includes('3 found'), `summary: ${md}`);
      for (const secret of ['application/json', 'cdn.example.net', '42']) assert(!md.includes(secret), `summary leaks ${secret}`);
      await resultAction(page, '[data-export="csv"]', '.dirmap-head');
      await resultAction(page, '[data-export="found"]', '.dirmap-head');
      const files = await takeDownloads(page);
      const csv = files.find((f) => f.name.endsWith('.csv'));
      const txt = files.find((f) => f.name.endsWith('.txt'));
      assertEqual(csvHeader(csv.text), [...DIRMAP_CSV_COLUMNS], 'CSV header');
      assertEqual(txt.text, 'https://web.example.com/api\nhttps://web.example.com/health\nhttps://web.example.com/files\nhttps://app.example.net/graphql\n', 'answered.txt');
    });

    await run.step('report-b.json joins, the newest answers for a host; a non-report says why; Forget', async () => {
      await openImport(page);
      await choose(page, [REPORT_B, notReport], () => document.querySelectorAll('.dirmap-report').length === 2, 'second report');
      await frames(page);
      let v = await info(page);
      assertEqual(v.title, '2 hosts · 10 paths', 'report A (newer) still answers for web.example.com');
      assertEqual(v.errors.length, 1, 'one file not read');
      assert(v.errors[0].includes('map.csv: not JSON'), v.errors[0]);
      await page.click('[data-action="dirmap-forget"]');
      await frames(page);
      v = await info(page);
      assert(v.empty, 'back to the empty state');
      assertEqual(v.reports, [], 'no report');
    });

    run.group('Turkish, dark, phones');
    await run.step('Turkish and dark at 375 and 320 px: the words, no horizontal scroll', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await gotoRoute(page, 'dirmap');
      await choose(page, [REPORT_A], () => document.querySelectorAll('.dirmap-report').length === 1, 'report read');
      await frames(page);
      assert((await info(page)).title.includes('host'), 'Turkish title');
      for (const width of [375, 320]) {
        await page.setViewport({ width, height: 800, mobile: true });
        await frames(page);
        await assertNoHorizontalScroll(page, `${width} px`);
      }
      await shot(page, opts, 'dirmap-phone-tr-dark');
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    run.group('Quality');
    await run.step('i18n: no missing keys', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations; nothing sent', async () => {
      await assertClean(page, 'Endpoint map', origin);
      assertEqual(netHits, [], 'https requests');
    });
  } finally {
    if (page) await page.close().catch(() => {});
    await browser.close();
    await server.close();
    await rm(tmp, { recursive: true, force: true });
  }
  run.finish();
}

main().catch((err) => {
  process.stderr.write(`${(err && err.stack) || err}\n`);
  process.exit(1);
});
