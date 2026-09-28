#!/usr/bin/env node
/**
 * estate.e2e.mjs — end-to-end test of the Certificate estate view (views/estate.js over
 * lib/estate.js) and of the Certificate view's "Does this CSR match?" check, in a real headless
 * Chrome/Edge. OFFLINE: the reports are tests/fixtures/estate/*.json (written by the CLI over a
 * made-up network), the CSRs tests/fixtures/bundle_*; a network-level guard (CDP Fetch) fails and
 * records any https request — the suite asserts none.
 *
 *   node tests/e2e/estate.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - navigation: Certificate estate is the last tool of the Certificates group; the empty page
 *     offers the drop zone (focused by '/') and the command that makes a report;
 *   - a file that is not a report is listed with the reason; report-a.json gives the tiles (9
 *     certificates, 3 expiring, 5 in name conflicts, 2 with a shared key, 2 weak, 3 covering no
 *     name), the expiry and kind lines and a row per certificate; a tile filters the table and
 *     keeps the focus, the select does too; a row's details show the fingerprints and where it is
 *     served; the CSV holds the CLI's --estate --csv columns, the rows of the filter only;
 *   - the conflicts tab names both names and marks the old wildcard "older", the keys tab the
 *     RSA 1024 key on two addresses in two certificates ("needs a look") and two certificates on
 *     a web01 / web02 pair (listed only);
 *   - report-b.json joins: the overlap note (192.0.2.11:443, the newest report's answers), the
 *     report of each endpoint in the details and a `report` column in the CSV; the same report
 *     again is a duplicate; pasting a report works, a pasted non-report says why; removing one
 *     report and Forget all; "Delete all local data" forgets the reports, with the view on screen
 *     or not, and so does a switch to another workspace;
 *   - Certificate view › PEM & OpenSSL › Does this CSR match?: the certificate's own CSR matches
 *     (Ctrl+Enter in the box), another key's does not (with the names it asked for), a pasted
 *     private key is refused and the box emptied at once, without Compare (and it does not come
 *     back after another tab or tool, while a CSR does), a certificate is named as one; "Delete
 *     all local data" empties the box;
 *   - Turkish + dark, a 375 px and a 320 px phone: no horizontal scroll, the table as cards;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; no request sent.
 */

import { readFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  csvHeader, gotoRoute, installDownloadCapture, setLangUi, takeDownloads, waitReady
} from './scan.e2e.mjs';
import { ESTATE_CSV_COLUMNS } from '../../assets/js/lib/estate.js';

const REPORT_A = path.join(FIXTURES, 'estate', 'report-a.json');
const REPORT_B = path.join(FIXTURES, 'estate', 'report-b.json');
const fixture = (name) => path.join(FIXTURES, name);
const PAGE = '.estate-page';

/** Fail every https request that reaches the network; returns the list it records. */
async function networkGuard(page) {
  const hits = [];
  page.conn.on('Fetch.requestPaused', (p) => {
    hits.push(p.request.url);
    page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://*' }] });
  return hits;
}

/** Element screenshot (beyond the viewport if needed); no-op with --no-shots. */
async function shotEl(page, opts, name, selector) {
  if (!opts.shots) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    window.scrollTo(0, 0);
    const r = el.getBoundingClientRect();
    return { x: Math.max(0, r.left + window.scrollX - 8), y: Math.max(0, r.top + window.scrollY - 8), width: r.width + 16, height: r.height + 16 };
  }, selector);
  if (!box || !box.width || !box.height) return;
  await mkdir(opts.shotsDir, { recursive: true });
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.min(Math.ceil(box.height), 9000), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(opts.shotsDir, `${name}.png`), Buffer.from(data, 'base64'));
}

/** Full-page screenshot; no-op with --no-shots. */
async function shotPage(page, opts, name) {
  if (!opts.shots) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  await mkdir(opts.shotsDir, { recursive: true });
  await page.screenshot(path.join(opts.shotsDir, `${name}.png`), { fullPage: true });
}

/** Elements under `selector` sticking out of the viewport (code blocks and table scrollers scroll inside). */
const overflowingIn = (page, selector) => page.evaluate((sel) => {
  const root = document.querySelector(sel);
  if (!root) return ['(missing)'];
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of root.querySelectorAll('*')) {
    if (el.closest('pre, .codeblock, .tablist-scroll')) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
}, selector);

/** The reports open in the view, with the rows the certificate table shows. */
const viewInfo = (page) => page.evaluate(() => {
  const tile = (f) => document.querySelector(`.estate-stats [data-filter="${f}"]`);
  const stat = (f) => tile(f)?.querySelector('.stat-value')?.textContent ?? null;
  return {
    reports: [...document.querySelectorAll('.estate-report')].map((li) => li.dataset.report),
    stats: Object.fromEntries(['all', 'expiring', 'name-conflict', 'shared-key', 'weak', 'covers-none'].map((f) => [f, stat(f)])),
    pressed: [...document.querySelectorAll('.estate-stats .stat-button[aria-pressed="true"]')].map((b) => b.dataset.filter),
    rows: [...document.querySelectorAll('.estate-table tbody tr.dt-row')].length,
    names: [...document.querySelectorAll('.estate-table tbody tr.dt-row .estate-cert-name')].map((e) => e.textContent),
    notes: [...document.querySelectorAll('.estate-notes .alert')].map((a) => a.textContent),
    errors: [...document.querySelectorAll('.estate-errors li')].map((li) => li.textContent),
    tabs: [...document.querySelectorAll('.estate-tabs .tab')].map((b) => `${b.dataset.tab}:${b.querySelector('.tab-badge')?.textContent}`),
    empty: !!document.querySelector('.estate-page > .empty')
  };
});

/** Choose files in the view's drop zone and wait until `until` holds. */
async function choose(page, files, until, message) {
  await page.setFileInput(`${PAGE} .estate-drop .filedrop-input`, files);
  return page.waitFor(until, { message, timeout: 15000 });
}

const removeToasts = (page) => page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
/** Wait for the DataTable's next frame: its rows render on requestAnimationFrame. */
const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));

/** Settings › "Delete all local data", confirmed (carry.e2e.mjs's helper). */
async function deleteAllLocalData(page) {
  await page.click('[data-control="settings"]');
  try {
    await page.waitForSelector('dialog.modal[open] .settings-danger');
    await page.click('dialog.modal[open] .settings-danger .btn-danger');
    await page.waitFor(() => document.querySelectorAll('dialog.modal[open]').length === 2, { message: 'confirmation' });
    await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open]')].find((d) => !d.querySelector('.settings-danger')).querySelector('.btn-danger').click());
    await page.waitFor(() => !document.querySelector('dialog.modal[open]'), { message: 'dialogs closed' });
  } finally {
    await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
  }
  // The tool on screen opens again once every listener has forgotten.
  await page.waitFor(() => document.querySelector('#page-body')?.childElementCount > 0
    && !document.querySelector('#page-body .page-loading'), { message: 'the tool opened again' });
  await frames(page);
}

/** Open the Certificate view with bundle_leaf.pem on its PEM & OpenSSL tab. */
async function certPemTab(page) {
  await gotoRoute(page, 'cert');
  if (!(await page.evaluate(() => document.querySelector('.cert-overview-cn')?.textContent === 'www.example.com'))) {
    await page.setFileInput('.cert-view .filedrop-input', [fixture('bundle_leaf.pem')]);
    await page.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === 'www.example.com', { message: 'certificate loaded' });
  }
  await removeToasts(page);
  await page.click('.cert-tabs .tab[data-tab="pem"]');
  await page.waitForSelector('[data-role="cert-csr"]');
}

const csrBox = (page) => page.evaluate(() => document.querySelector('[data-role="cert-csr"]')?.value ?? null);

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-estate-e2e-'));
  const notJson = path.join(tmp, 'estate.csv');
  await writeFile(notJson, 'sha256,subject_cn\n');

  run.group('Node: harness');
  await run.step('run-all orders the estate suite right after renew', () => {
    assertEqual(orderSuites(['global.e2e.mjs', 'estate.e2e.mjs', 'renew.e2e.mjs', 'pfx.e2e.mjs']), ['pfx', 'renew', 'estate', 'global'], 'order');
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
    await page.goto(`${server.url}#/estate`);
    await waitReady(page);
    await setLangUi(page, 'en');
    await gotoRoute(page, 'estate');

    run.group('Certificate estate (desktop 1440×900, English, light)');
    await run.step('the last tool of the Certificates group; the empty page offers the drop zone and the command', async () => {
      const info = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/scan"]'));
        return {
          nav: group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '')) : [],
          title: document.querySelector('h1')?.textContent,
          drop: !!document.querySelector('.estate-drop'),
          how: document.querySelector('.estate-how')?.open,
          cmd: document.querySelector('.estate-how pre, .estate-how code')?.textContent || '',
          empty: document.querySelector('.estate-page .empty')?.textContent || ''
        };
      });
      assertEqual(info.nav, ['scan', 'cert', 'renew', 'estate'], 'Certificates group');
      assertEqual(info.title, 'Certificate estate', 'title');
      assert(info.drop, 'drop zone');
      assert(info.how, 'the command is shown while nothing is open');
      assert(info.cmd.includes('--estate --json estate.json'), `command: ${info.cmd}`);
      assert(info.empty.includes('No report open yet'), 'empty state');
      await page.evaluate(() => document.activeElement && document.activeElement.blur());
      await page.press('/');
      assert(await page.evaluate(() => document.activeElement?.classList.contains('estate-drop')), '/ focuses the drop zone');
      await shotPage(page, opts, 'estate-empty-desktop-light-en');
    });

    await run.step('a file that is not a report is listed with the reason', async () => {
      const info = await choose(page, [notJson], () => document.querySelectorAll('.estate-errors li').length > 0, 'error list');
      assert(info, 'error');
      const { errors, reports } = await viewInfo(page);
      assertEqual(reports, [], 'nothing opened');
      assert(/^estate\.csv: not JSON\. Choose the file the CLI wrote with --json/.test(errors[0]), errors[0]);
      await removeToasts(page);
    });

    await run.step('report-a.json: the tiles, the lines, a row per certificate', async () => {
      await choose(page, [REPORT_A], () => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, '9 rows');
      const info = await viewInfo(page);
      assertEqual(info.reports, ['report-a.json'], 'report list');
      assertEqual(info.errors, [], 'the error of the earlier file is gone');
      assertEqual(info.stats, { all: '9', expiring: '3', 'name-conflict': '5', 'shared-key': '2', weak: '2', 'covers-none': '3' }, 'tiles');
      assertEqual(info.pressed, ['all'], 'All pressed');
      assertEqual(info.tabs, ['certificates:9', 'conflicts:2', 'keys:3'], 'tab badges');
      const hints = await page.evaluate(() => Object.fromEntries(['name-conflict', 'shared-key'].map((f) => {
        const el = document.querySelector(`.estate-stats [data-filter="${f}"]`);
        return [f, `${el.querySelector('.stat-label')?.textContent} | ${el.querySelector('.stat-hint')?.textContent}`];
      })));
      assertEqual(hints, {
        'name-conflict': 'In a name conflict | 2 names, several certificates',
        'shared-key': 'With a shared key | 1 key in several certificates or on 5+ addresses'
      }, 'the tiles count certificates, the hints the names and keys behind them');
      assertEqual(info.names[0], 'old.example.net', 'soonest expiry first');
      assert(await page.evaluate(() => document.activeElement?.dataset.filter === 'all'), 'the focus on the Certificates tile, not <body>');
      const lines = await page.evaluate(() => [...document.querySelectorAll('.estate-line')].map((l) => l.textContent));
      assert(lines[0].includes('expired 1') && lines[0].includes('< 7 days 1') && lines[0].includes('later 6'), `expiry line: ${lines[0]}`);
      assert(lines[1].includes('Cloudflare Origin CA 1') && lines[1].includes('self-signed 6') && lines[1].includes('private CA 1'), `kinds: ${lines[1]}`);
      await removeToasts(page);
      await shotPage(page, opts, 'estate-report-desktop-light-en');
    });

    await run.step('a tile filters the table and keeps the focus; the select filters too', async () => {
      await page.click('.estate-stats [data-filter="weak"]');
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 2, { message: 'weak rows' });
      let info = await viewInfo(page);
      assertEqual(info.pressed, ['weak'], 'Weak pressed');
      assert(await page.evaluate(() => document.activeElement?.dataset.filter === 'weak'), 'focus stays on the tile');
      assertEqual(await page.evaluate(() => document.querySelector('.estate-filter select').value), 'weak', 'the select follows');
      await page.evaluate(() => {
        const s = document.querySelector('.estate-filter select');
        s.value = 'covers-none';
        s.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 3, { message: 'covers-none rows' });
      info = await viewInfo(page);
      assertEqual(info.pressed, ['covers-none'], 'the tile follows the select');
      assertEqual(info.names.sort(), ['legacy.example.net', 'legacy.example.org', 'old.example.net'], 'covering no name');
    });

    await run.step('a row\'s details: fingerprints and where it is served', async () => {
      await page.click('.estate-table tbody tr.dt-row .dt-expand-btn');
      const details = await page.waitFor(() => document.querySelector('.estate-table .estate-details')?.textContent, { message: 'details' });
      assert(details.includes('SHA-256') && details.includes('Public key SHA-256'), 'fingerprints');
      assert(details.includes('Where it is served'), 'served');
      await shotEl(page, opts, 'estate-details-desktop-light-en', '.estate-table');
    });

    await run.step('CSV: the CLI\'s --estate --csv columns, the rows of the filter', async () => {
      await takeDownloads(page);
      await page.click('.estate-table [data-export="csv"]');
      const [file] = await takeDownloads(page);
      assert(file && /^estate-\d{8}-\d{4}\.csv$/.test(file.name), `file name: ${file && file.name}`);
      assert(file.bom, 'BOM for Excel');
      assertEqual(csvHeader(file.text), ESTATE_CSV_COLUMNS.map((c) => c.key), 'columns');
      const rows = file.text.trim().split(/\r?\n/).slice(1);
      assertEqual(rows.length, 6, 'legacy.example.org on web01 and web02, legacy.example.net and old.example.net each on legacy-a and legacy-b');
      await removeToasts(page);
    });

    await run.step('conflicts: both names, the old wildcard older; keys: RSA 1024 on two addresses in two certificates', async () => {
      await page.click('.estate-tabs .tab[data-tab="conflicts"]');
      const conflicts = await page.waitFor(() => {
        const s = [...document.querySelectorAll('.estate-conflict')];
        return s.length ? s.map((c) => ({ name: c.querySelector('.estate-conflict-name').textContent, certs: c.querySelectorAll('.estate-conflict-cert').length, stale: c.querySelectorAll('.is-stale').length })) : false;
      }, { message: 'conflicts' });
      assertEqual(conflicts, [{ name: 'www.example-test.com.tr', certs: 2, stale: 0 }, { name: 'a.wild.example.net', certs: 3, stale: 1 }], 'conflicts');
      await shotEl(page, opts, 'estate-conflicts-desktop-light-en', '.estate-tabs');
      await page.click('.estate-tabs .tab[data-tab="keys"]');
      const keys = await page.waitFor(() => {
        const g = [...document.querySelectorAll('.estate-key-group')];
        return g.length ? g.map((k) => ({ head: k.querySelector('.estate-key-head').textContent, look: k.dataset.look })) : false;
      }, { message: 'keys' });
      assertEqual(keys.map((k) => k.look), ['true', 'false', 'false'], 'three shared keys, one needs a look');
      assert(keys[0].head.includes('RSA 1024') && keys[0].head.includes('2 addresses') && keys[0].head.includes('2 certificates')
        && keys[0].head.includes('needs a look'), keys[0].head);
      assert(keys[1].head.includes('2 addresses') && keys[1].head.includes('1 certificate') && !keys[1].head.includes('needs a look'), keys[1].head);
      await page.click('.estate-tabs .tab[data-tab="certificates"]');
    });

    await run.step('report-b.json joins: the overlap note, the report of each endpoint, a report column', async () => {
      await page.click('.estate-stats [data-filter="all"]');
      await choose(page, [REPORT_B], () => document.querySelectorAll('.estate-report').length === 2, 'two reports');
      await frames(page);
      const info = await viewInfo(page);
      assertEqual(info.reports, ['report-a.json', 'report-b.json'], 'two reports');
      assert(info.notes.some((n) => n.includes('192.0.2.11:443 was scanned by more than one report')), `notes: ${info.notes}`);
      assertEqual(info.stats.all, '9', 'still nine certificates (report B has none of its own)');
      await takeDownloads(page);
      await page.click('.estate-table [data-export="csv"]');
      const [file] = await takeDownloads(page);
      assertEqual(csvHeader(file.text), [...ESTATE_CSV_COLUMNS.map((c) => c.key), 'report'], 'report column');
      assert(/,report-b\.json\r?\n/.test(file.text) && /,report-a\.json\r?\n/.test(file.text), 'rows name their report');
      await removeToasts(page);
    });

    await run.step('the same report again is a duplicate; a pasted report opens, a pasted non-report says why', async () => {
      await page.setFileInput(`${PAGE} .estate-drop .filedrop-input`, [REPORT_A]);
      const toast = await page.waitFor(() => [...document.querySelectorAll('.toast')].map((t) => t.textContent).find((t) => t.includes('already open')), { message: 'duplicate toast' });
      assert(toast.includes('report-a.json: the same report is already open'), toast);
      assertEqual((await viewInfo(page)).reports.length, 2, 'still two');
      await page.evaluate(() => { document.querySelector('.estate-paste').open = true; });
      await page.type('[data-role="estate-paste"]', '{"tool":"other"}');
      await page.press('Enter', { ctrl: true });
      await page.waitFor(() => document.querySelectorAll('.estate-errors li').length === 1, { message: 'pasted non-report' });
      assert((await viewInfo(page)).errors[0].includes('not a report of ssl_origin_scan.py'), 'reason');
      const box = await page.evaluate(() => ({ focused: document.activeElement?.dataset.role, text: document.querySelector('[data-role="estate-paste"]').value }));
      assertEqual(box, { focused: 'estate-paste', text: '{"tool":"other"}' }, 'the pasted text stays, focused, to be fixed');
      await removeToasts(page);
      await shotEl(page, opts, 'estate-import-desktop-light-en', '.estate-import');
    });

    await run.step('removing a report, then Forget all', async () => {
      await page.click('.estate-report[data-report="report-b.json"] .btn-icon');
      await page.waitFor(() => document.querySelectorAll('.estate-report').length === 1, { message: 'one report left' });
      assertEqual((await viewInfo(page)).notes.filter((n) => n.includes('more than one report')), [], 'no overlap note');
      await page.click('[data-action="estate-forget"]');
      await page.waitFor(() => !document.querySelector('.estate-report') && document.querySelector('.estate-page .empty'), { message: 'forgotten' });
      await removeToasts(page);
    });

    await run.step('"Delete all local data" forgets the reports, the view on screen or not', async () => {
      await choose(page, [REPORT_A], () => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, 'report read');
      await removeToasts(page);
      await deleteAllLocalData(page);
      await page.waitFor(() => document.querySelector('.estate-page .empty') && !document.querySelector('.estate-report'), { message: 'emptied on screen' });
      assertEqual((await viewInfo(page)).reports, [], 'nothing open after the deletion');
      await setLangUi(page, 'en');
      await choose(page, [REPORT_A, REPORT_B], () => document.querySelectorAll('.estate-report').length === 2, 'two reports');
      await removeToasts(page);
      await gotoRoute(page, 'about');
      await deleteAllLocalData(page);
      await setLangUi(page, 'en');
      await gotoRoute(page, 'estate');
      const info = await viewInfo(page);
      assertEqual([info.reports, info.empty], [[], true], 'forgotten while another tool was open');
    });

    await run.step('another workspace forgets the reports too', async () => {
      await choose(page, [REPORT_A], () => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, 'report read');
      await removeToasts(page);
      const id = await page.evaluate(() => import('./assets/js/state.js').then(async ({ state }) => {
        const { meta } = await state.createWorkspace('Estate e2e');
        await state.switchWorkspace(meta.id);
        return meta.id;
      }));
      await page.waitFor(() => document.querySelector('.estate-page .empty') && !document.querySelector('.estate-report'), { message: 'emptied by the switch' });
      await page.evaluate((wsId) => import('./assets/js/state.js').then(async ({ state }) => {
        await state.switchWorkspace(state.workspaces.find((w) => w.isDefault).id);
        await state.deleteWorkspace(wsId);
      }), id);
      await page.waitFor(() => document.querySelector('.estate-page .empty'), { message: 'back in Default, still empty' });
      assertEqual((await viewInfo(page)).reports, [], 'nothing came back with Default');
    });

    run.group('Certificate › PEM & OpenSSL › Does this CSR match?');
    await run.step('its own CSR matches (Ctrl+Enter in the box), another key\'s does not', async () => {
      await gotoRoute(page, 'cert');
      await page.setFileInput('.cert-view .filedrop-input', [fixture('bundle_leaf.pem')]);
      await page.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === 'www.example.com', { message: 'certificate loaded' });
      await removeToasts(page);
      await page.click('.cert-tabs .tab[data-tab="pem"]');
      await page.waitForSelector('[data-role="cert-csr"]');
      await page.type('[data-role="cert-csr"]', await readFile(fixture('bundle_leaf.csr'), 'utf8'));
      await page.press('Enter', { ctrl: true });
      const ok = await page.waitFor(() => {
        const v = document.querySelector('.cert-csr-verdict');
        return v ? { match: v.dataset.match, text: v.textContent } : false;
      }, { message: 'match verdict' });
      assertEqual(ok.match, 'true', 'match');
      assert(ok.text.includes('The CSR matches this certificate') && ok.text.includes('RSA 2048'), ok.text);
      await shotEl(page, opts, 'cert-csr-match-desktop-light-en', '.cert-csr');
      await page.type('[data-role="cert-csr"]', await readFile(fixture('bundle_other.csr'), 'utf8'));
      await page.click('[data-action="cert-csr-compare"]');
      const no = await page.waitFor(() => {
        const v = document.querySelector('.cert-csr-verdict[data-match="false"]');
        return v ? v.textContent : false;
      }, { message: 'mismatch verdict' });
      assert(no.includes('The CSR does not match') && no.includes('shop.example.com'), no);
    });

    await run.step('a pasted private key is refused and the box emptied at once, without Compare; a certificate is named as one', async () => {
      await page.type('[data-role="cert-csr"]', await readFile(fixture('bundle_leaf.key'), 'utf8'));
      const key = await page.waitFor(() => {
        const v = document.querySelector('.cert-csr-verdict[data-error="private-key"]');
        return v ? { text: v.textContent, box: document.querySelector('[data-role="cert-csr"]').value } : false;
      }, { message: 'private key verdict' });
      assert(key.text.startsWith('That is a private key. It was not read or kept'), key.text);
      assertEqual(key.box, '', 'the box is emptied');
      assert(!(await page.evaluate(() => /PRIVATE KEY-----/.test(document.body.innerHTML))), 'no key left in the page');
      await page.type('[data-role="cert-csr"]', await readFile(fixture('bundle_leaf.pem'), 'utf8'));
      await page.click('[data-action="cert-csr-compare"]');
      await page.waitFor(() => document.querySelector('.cert-csr-verdict[data-error="certificate"]'), { message: 'certificate verdict' });
    });

    await run.step('a key pasted without Compare does not come back after another tab or tool; a CSR does', async () => {
      await page.type('[data-role="cert-csr"]', await readFile(fixture('bundle_leaf.rsa.key'), 'utf8'));
      await page.click('.cert-tabs .tab[data-tab="names"]');
      await page.click('.cert-tabs .tab[data-tab="pem"]');
      await page.waitForSelector('[data-role="cert-csr"]');
      assertEqual(await csrBox(page), '', 'empty after another tab');
      await gotoRoute(page, 'estate');
      await certPemTab(page);
      assertEqual(await csrBox(page), '', 'empty after another tool');
      const csr = await readFile(fixture('bundle_leaf.csr'), 'utf8');
      await page.type('[data-role="cert-csr"]', csr);
      await gotoRoute(page, 'estate');
      await certPemTab(page);
      assertEqual(await csrBox(page), csr, 'a CSR stays for this page session');
    });

    await run.step('"Delete all local data" empties the CSR box', async () => {
      await deleteAllLocalData(page);
      await setLangUi(page, 'en');
      await certPemTab(page);
      assertEqual(await csrBox(page), '', 'the pasted CSR is forgotten');
      await removeToasts(page);
    });

    run.group('Languages, themes, phones');
    await run.step('Turkish + dark, 375 px: both reports fit, the table reads as cards', async () => {
      await gotoRoute(page, 'estate');
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await choose(page, [REPORT_A, REPORT_B], () => document.querySelectorAll('.estate-report').length === 2, 'two reports (TR)');
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 375, { message: 'phone viewport' });
      await frames(page);
      const title = await page.evaluate(() => document.querySelector('h1')?.textContent);
      assertEqual(title, 'Sertifika envanteri', 'Turkish title');
      assert((await viewInfo(page)).notes.some((n) => n.includes('birden çok raporda tarandı')), 'Turkish overlap note');
      const header = await page.evaluate(() => getComputedStyle(document.querySelector('.estate-table thead')).display);
      assertEqual(header, 'none', 'no table header on a phone (cards)');
      await assertNoHorizontalScroll(page, 'estate phone dark TR');
      assertEqual(await overflowingIn(page, PAGE), [], 'the page inside 375 px');
      await removeToasts(page);
      await shotPage(page, opts, 'estate-report-phone-dark-tr');
      await page.click('.estate-tabs .tab[data-tab="conflicts"]');
      await assertNoHorizontalScroll(page, 'estate conflicts phone');
      assertEqual(await overflowingIn(page, '.estate-tabs'), [], 'conflicts inside 375 px');
      await shotEl(page, opts, 'estate-conflicts-phone-dark-tr', '.estate-tabs');
      await page.click('.estate-tabs .tab[data-tab="keys"]');
      assertEqual(await overflowingIn(page, '.estate-tabs'), [], 'keys inside 375 px');
      await page.click('.estate-tabs .tab[data-tab="certificates"]');
    });

    await run.step('320 px, English, light: still no horizontal scroll', async () => {
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport({ width: 320, height: 720, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 320 && document.querySelector('.estate-stats'), { message: '320 px' });
      await frames(page);
      await removeToasts(page);
      await assertNoHorizontalScroll(page, 'estate 320 light EN');
      assertEqual(await overflowingIn(page, PAGE), [], 'the page inside 320 px');
      await shotPage(page, opts, 'estate-report-phone-light-en');
      await page.setViewport({ width: 1440, height: 900 });
    });

    await run.step('desktop dark, Turkish: the report and the CSR check', async () => {
      await page.setViewport({ width: 1440, height: 900 }); // also after a failed phone step
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.waitFor(() => document.querySelector('.estate-stats'), { message: 'stats' });
      await assertNoHorizontalScroll(page, 'estate desktop dark TR');
      await shotPage(page, opts, 'estate-report-desktop-dark-tr');
      await gotoRoute(page, 'cert');
      await page.click('.cert-tabs .tab[data-tab="pem"]');
      await page.type('[data-role="cert-csr"]', await readFile(fixture('bundle_leaf.csr'), 'utf8'));
      await page.click('[data-action="cert-csr-compare"]');
      const text = await page.waitFor(() => document.querySelector('.cert-csr-verdict[data-match="true"]')?.textContent, { message: 'Turkish match' });
      assert(text.includes('CSR bu sertifikayla eşleşiyor'), text);
      await shotEl(page, opts, 'cert-csr-match-desktop-dark-tr', '.cert-csr');
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 375, { message: 'phone' });
      await assertNoHorizontalScroll(page, 'cert CSR phone dark TR');
      assertEqual(await overflowingIn(page, '.cert-csr'), [], 'CSR card inside 375 px');
      await shotEl(page, opts, 'cert-csr-match-phone-dark-tr', '.cert-csr');
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Quality');
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations; nothing sent to the network', async () => {
      await assertClean(page, 'estate', origin);
      assertEqual(netHits, [], 'https requests that reached the network');
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
  process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
