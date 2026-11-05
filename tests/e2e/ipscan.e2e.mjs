#!/usr/bin/env node
/**
 * ipscan.e2e.mjs — end-to-end test of the IP Scan view (views/ipscan.js over lib/ipscan.js) in a
 * real headless Chrome/Edge. OFFLINE: the reports are tests/fixtures/ipscan/report-*.json (what
 * cli/ip_scan.py writes, over faked probes of a documentation range); a network-level guard (CDP
 * Fetch) fails and records any https request — the suite asserts none.
 *
 *   node tests/e2e/ipscan.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * What is checked:
 *   - navigation: IP Scan is the last tool of the network group; the empty page offers the range,
 *     the reports' drop zone and how to scan (the command, the CLI to download);
 *   - Show map draws the range at once (nothing is sent): the result header ("192.0.2.0/28 · 16
 *     addresses"), the "not scanned yet" note, the network and broadcast addresses reserved, the
 *     server list's address claimed; the route carries the range and a reload draws it again;
 *   - report-a.json: the counts as filters (5 used, 2 claimed, 7 free), the free addresses to use
 *     (confirmed first; a click copies one), a cell's details (ports, MAC, web server, why), the
 *     arrow keys moving between cells; a count filters the map (the rest dimmed) and the list; the
 *     CSV and the free list; Copy summary names addresses and states only;
 *   - report-b.json: "5 addresses of the reports are outside this range" and the button that maps
 *     the reports' range; a file that is not a report says why; Forget all;
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
import { IPSCAN_CSV_COLUMNS } from '../../assets/js/lib/ipscan.js';

const REPORT_A = path.join(FIXTURES, 'ipscan', 'report-a.json');
const REPORT_B = path.join(FIXTURES, 'ipscan', 'report-b.json');
const VIEW = '.ipscan-view';

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

/** What the page shows: the header, the counts, the cells by state, the notes, the picks. */
const info = (page) => page.evaluate(() => ({
  title: document.querySelector('.ipscan-head .result-title')?.textContent || '',
  status: Object.fromEntries([...document.querySelectorAll('.ipscan-head .status-item')].map((b) => [b.dataset.status, Number(b.dataset.count)])),
  pressed: [...document.querySelectorAll('.ipscan-head .status-item[aria-pressed="true"]')].map((b) => b.dataset.status),
  cells: Object.fromEntries([...document.querySelectorAll('.ipscan-cell')].map((c) => [c.dataset.ip, c.dataset.state + (c.classList.contains('is-confirmed') ? '*' : '')])),
  dimmed: [...document.querySelectorAll('.ipscan-cell.is-dimmed')].length,
  noScan: !!document.querySelector('.ipscan-noscan'),
  outside: document.querySelector('.ipscan-outside-note')?.textContent || '',
  picks: [...document.querySelectorAll('.ipscan-pick-ip')].map((b) => b.textContent.trim()),
  reports: [...document.querySelectorAll('.ipscan-report')].map((li) => li.dataset.report),
  errors: [...document.querySelectorAll('.ipscan-errors li')].map((li) => li.textContent),
  empty: !!document.querySelector('.ipscan-empty'),
  range: document.querySelector('[data-role="ipscan-range"] textarea, textarea[data-role="ipscan-range"], [data-role="ipscan-range"]')?.value ?? null,
  hash: location.hash
}));

async function typeRange(page, text) {
  await page.evaluate((v) => {
    const box = document.querySelector('textarea[data-role="ipscan-range"]') || document.querySelector('[data-role="ipscan-range"] textarea');
    box.value = v;
    box.dispatchEvent(new Event('input', { bubbles: true }));
  }, text);
  await page.click('[data-action="ipscan-run"]');
  await page.waitFor(() => !!document.querySelector('.ipscan-head .result-title'), { message: 'the map' });
  await frames(page);
}

async function choose(page, files, until, message) {
  await page.setFileInput(`${VIEW} .ipscan-drop .filedrop-input`, files);
  return page.waitFor(until, { message, timeout: 15000 });
}

const openImport = (page) => page.evaluate(() => {
  const more = document.querySelector('.ipscan-import-more');
  if (more && !more.open) more.open = true;
});

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-ipscan-e2e-'));
  const notReport = path.join(tmp, 'scan.csv');
  await writeFile(notReport, 'ip,state\n192.0.2.1,used\n');

  run.group('Node: harness');
  await run.step('run-all orders the ipscan suite right after ptr', () => {
    assertEqual(orderSuites(['retire.e2e.mjs', 'ipscan.e2e.mjs', 'ptr.e2e.mjs']), ['ptr', 'ipscan', 'retire'], 'order');
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
    await stubClipboard(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/ipscan`);
    await waitReady(page);
    await setLangUi(page, 'en');
    await page.evaluate(async () => (await import('./assets/js/state.js')).state.setInventory('db1 192.0.2.3\nweb1 192.0.2.2').done);
    await gotoRoute(page, 'ipscan');

    run.group('IP Scan (desktop 1440×900, English, light)');
    await run.step('the last tool of the network group; the empty page offers the range, the drop zone and how to scan', async () => {
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/ptr"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '')) : [];
      });
      assertEqual(nav, ['ip', 'bulk', 'ptr', 'ipscan'], 'the network group');
      const page0 = await info(page);
      assert(page0.empty, 'the empty state');
      const how = await page.evaluate(() => ({
        drop: !!document.querySelector('.ipscan-import .ipscan-drop'),
        first: document.querySelector('.ipscan-view > :first-child')?.classList.contains('ipscan-steps-host'),
        compact: document.querySelector('.ipscan-steps')?.classList.contains('is-compact'),
        title: document.querySelector('.ipscan-steps .cli-steps-title')?.textContent,
        places: [...document.querySelectorAll('.ipscan-steps .cli-step')].map((li) => li.dataset.place),
        code: [...document.querySelectorAll('.ipscan-steps .cli-step[data-place="machine"] pre, .ipscan-steps .cli-step[data-place="machine"] code')].map((c) => c.textContent).join('\n'),
        download: document.querySelector('.ipscan-steps a[download]')?.getAttribute('href'),
        navTag: document.querySelector('.nav-link[data-view="ipscan"] .nav-cli')?.textContent,
        navLabel: document.querySelector('.nav-link[data-view="ipscan"] .nav-label')?.textContent
      }));
      assert(how.drop, 'the drop zone');
      assertEqual([how.first, how.compact, how.title], [true, false, 'The scan does not run in the browser'], 'the steps, in full, first on the page');
      assertEqual(how.places, ['browser', 'machine', 'browser'], 'download here, run on your network, open here');
      assert(how.code.includes('python3 ip_scan.py 10.0.5.0/24 --json scan.json'), `the command: ${how.code}`);
      assertEqual(how.download, 'cli/ip_scan.py', 'the CLI to download');
      assertEqual([how.navTag, how.navLabel], ['CLI', 'IP Scan'], 'the nav marks a tool that needs the command line');
    });

    await run.step('Show map: the range at once, not scanned yet; reserved and claimed addresses; the route keeps the range', async () => {
      await typeRange(page, '192.0.2.0/28');
      const v = await info(page);
      assertEqual(v.title, '192.0.2.0/28 · 16 addresses', 'title');
      assert(v.noScan, 'the not-scanned note');
      const cmd = await page.evaluate(() => document.querySelector('.ipscan-steps .cli-step[data-place="machine"] pre, .ipscan-steps .cli-step[data-place="machine"] code')?.textContent || '');
      assert(cmd.includes('python3 ip_scan.py 192.0.2.0/28 --json scan.json'), `step 2 follows the range: ${cmd}`);
      assertEqual([v.cells['192.0.2.0'], v.cells['192.0.2.15'], v.cells['192.0.2.3'], v.cells['192.0.2.2'], v.cells['192.0.2.4']],
        ['reserved', 'reserved', 'claimed', 'claimed', 'unscanned'], 'cells');
      assertEqual(v.status, { claimed: 2, unscanned: 12 }, 'counts');
      assert(decodeURIComponent(v.hash).includes('range=192.0.2.0/28'), `route ${v.hash}`);
      await page.evaluate(() => location.reload());
      await waitReady(page);
      await page.waitFor(() => !!document.querySelector('.ipscan-head .result-title'), { message: 'the map after a reload' });
      assertEqual((await info(page)).title, '192.0.2.0/28 · 16 addresses', 'after a reload');
      await installDownloadCapture(page);
      await stubClipboard(page);
    });

    await run.step('report-a.json: the counts, the free addresses to use (confirmed first), the input folds', async () => {
      await choose(page, [REPORT_A], () => document.querySelectorAll('.ipscan-report').length === 1, 'report read');
      await frames(page);
      const v = await info(page);
      assertEqual(v.status, { claimed: 2, free: 7, used: 5 }, 'counts');
      assertEqual(v.picks.slice(0, 3), ['192.0.2.4', '192.0.2.5', '192.0.2.7'], 'picks: confirmed first (.3 is db1’s)');
      assertEqual(v.picks[v.picks.length - 1], '192.0.2.12', 'the unconfirmed one last');
      assertEqual([v.cells['192.0.2.1'], v.cells['192.0.2.3'], v.cells['192.0.2.4'], v.cells['192.0.2.9'], v.cells['192.0.2.12']],
        ['used', 'claimed', 'free*', 'claimed', 'free'], 'cells');
      assert(!v.noScan, 'no not-scanned note');
      const steps = await page.evaluate(() => ({
        compact: document.querySelector('.ipscan-steps')?.classList.contains('is-compact'),
        open: document.querySelector('.ipscan-steps details')?.open,
        line: document.querySelector('.ipscan-steps .cli-steps-summary-text')?.textContent
      }));
      assertEqual(steps, { compact: true, open: false, line: 'Scanned on your network with ip_scan.py · 1 report open' }, 'the steps fold into one line');
      await removeToasts(page);
      await page.click('.ipscan-pick-ip');
      assertEqual(await takeClipboard(page), ['192.0.2.4'], 'a pick copies its address');
      await shot(page, opts, 'ipscan-desktop');
    });

    await run.step('a cell’s details; the arrow keys move between the cells', async () => {
      await page.click('.ipscan-cell[data-ip="192.0.2.1"]');
      await page.waitFor(() => !!document.querySelector('.ipscan-detail[data-ip="192.0.2.1"]'), { message: 'details' });
      const text = await page.evaluate(() => document.querySelector('.ipscan-detail').textContent);
      for (const want of ['22, 443', '00:00:5e:00:53:01', 'gw.example.net', '443: Apache', 'answered a ping']) assert(text.includes(want), `details: ${want} in ${text}`);
      await page.press('ArrowRight');
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.ip), '192.0.2.2', 'ArrowRight');
      await page.press('ArrowDown');
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.ip), '192.0.2.15', 'ArrowDown (stays in the group)');
      await page.click('.ipscan-detail [aria-label="Close the details"]');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.ipscan-detail').length), 0, 'closed');
    });

    await run.step('a count filters the map and the list; the CSV and the free list; Copy summary', async () => {
      await page.click('.ipscan-head .status-item[data-status="free"]');
      let v = await info(page);
      assertEqual(v.pressed, ['free'], 'pressed');
      assertEqual(v.dimmed, 9, 'everything but the 7 free addresses dimmed');
      await page.click('.ipscan-tabs .tab[data-tab="list"]');
      await frames(page);
      assertEqual(await page.evaluate(() => document.querySelectorAll('.ipscan-table tbody tr.dt-row').length), 7, 'the list');
      await resultAction(page, '[data-export="csv"]', '.ipscan-head');
      await resultAction(page, '[data-export="free"]', '.ipscan-head');
      const files = await takeDownloads(page);
      const csv = files.find((f) => f.name.endsWith('.csv'));
      const txt = files.find((f) => f.name.endsWith('.txt'));
      assertEqual(csvHeader(csv.text), [...IPSCAN_CSV_COLUMNS], 'CSV header');
      assertEqual(csv.text.trim().split(/\r?\n/).length, 8, 'the 7 free rows and the header');
      assertEqual(txt.text, '192.0.2.4\n192.0.2.5\n192.0.2.7\n192.0.2.8\n192.0.2.12\n192.0.2.13\n192.0.2.14\n', 'free.txt');
      await page.click('.ipscan-head .status-item[data-status="free"]');
      v = await info(page);
      assertEqual([v.pressed, v.dimmed], [[], 0], 'the filter off');
      await page.click('[data-summary="ipscan"] [data-action="copy-summary"]');
      await page.waitFor(() => !!document.querySelector('.toast'), { message: 'copied' });
      const md = (await takeClipboard(page)).join('\n');
      assert(md.includes('IP Scan · `192.0.2.0/28`') && md.includes('7 free (6 confirmed)'), `summary: ${md}`);
      for (const secret of ['db1', 'web1', 'gw.example.net', '00:00:5e']) assert(!md.includes(secret), `summary leaks ${secret}`);
      await page.click('.ipscan-tabs .tab[data-tab="map"]');
    });

    await run.step('report-b.json: addresses outside the range, and the button that maps the reports’ range; a non-report says why', async () => {
      await openImport(page);
      await choose(page, [REPORT_B, notReport], () => document.querySelectorAll('.ipscan-report').length === 2, 'second report');
      await frames(page);
      let v = await info(page);
      assert(v.outside.includes('5 addresses of the reports are outside this range'), `note: ${v.outside}`);
      assertEqual(v.errors.length, 1, 'one file not read');
      assert(v.errors[0].includes('scan.csv: not JSON'), v.errors[0]);
      await page.click('[data-action="ipscan-reports-range"]');
      await page.waitFor(() => (document.querySelector('.ipscan-head .result-title')?.textContent || '').includes('21 addresses'), { message: 'the reports’ range' });
      v = await info(page);
      assertEqual(v.cells['192.0.2.16'], 'used', 'from report B');
      assertEqual(v.cells['192.0.2.9'], 'claimed', 'report A is newer for .9');
      assertEqual(v.outside, '', 'nothing outside now');
    });

    await run.step('Forget all: back to the server list only', async () => {
      await page.click('[data-action="ipscan-forget"]');
      await frames(page);
      const v = await info(page);
      assert(v.noScan, 'the not-scanned note again');
      assertEqual(v.reports, [], 'no report');
    });

    run.group('Turkish, dark, phones');
    await run.step('Turkish and dark at 375 and 320 px: the words, no horizontal scroll', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await gotoRoute(page, 'ipscan');
      await choose(page, [REPORT_A], () => document.querySelectorAll('.ipscan-report').length === 1, 'report read');
      await frames(page);
      const title = (await info(page)).title;
      assert(title.includes('adres'), `Turkish title: ${title}`);
      for (const width of [375, 320]) {
        await page.setViewport({ width, height: 800, mobile: true });
        await frames(page);
        await assertNoHorizontalScroll(page, `${width} px`);
      }
      await shot(page, opts, 'ipscan-phone-tr-dark');
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    run.group('Quality');
    await run.step('i18n: no missing keys', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations; nothing sent', async () => {
      await assertClean(page, 'IP Scan', origin);
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
