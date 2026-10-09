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
 *   - a file that is not a report is listed with the reason; report-a.json gives the result header
 *     (docs/DESIGN.md §5.6: "Certificate estate · 9 certificates on 7 endpoints", the counts — 1
 *     expired, 2 expiring within 30 days, 5 in name conflicts, 2 with a shared key, 2 weak — as
 *     filters of the list), the expiry and kind figures and a row per certificate, and the input
 *     folds to one row ("1 report loaded · Add files · Forget all"); a count filters the table
 *     (pressed, the focus kept), the Show select does too and the count follows; a row's details
 *     show the fingerprints and where it is served; the CSV (the header's Export ▾) holds the CLI's
 *     --estate --csv columns (the trust check's two last: report A's
 *     scan checked trust), the rows of the filter only; the untrusted filter lists the three
 *     certificates an endpoint serves with a chain the CLI's machine does not trust, each flagged,
 *     and a row's details say why per endpoint (self-signed (code 18); in Turkish "eksik ara
 *     sertifika ya da özel CA (kod 20)");
 *   - the conflicts tab names both names and marks the old wildcard "older", the keys tab the
 *     RSA 1024 key on two addresses in two certificates ("needs a look") and two certificates on
 *     a web01 / web02 pair (listed only);
 *   - report-b.json joins: the overlap note (192.0.2.11:443, the newest report's answers), the
 *     report of each endpoint in the details and a `report` column in the CSV; the same report
 *     again is a duplicate; pasting a report works, a pasted non-report says why; removing one
 *     report and Forget all; "Delete all local data" forgets the reports, with the view on screen
 *     or not, and so does a switch to another workspace; a report where no server returned a
 *     certificate says so in the keys tab (not "an older CLI");
 *   - Certificate view › PEM & OpenSSL › Does this CSR match?: the certificate's own CSR matches
 *     (Ctrl+Enter in the box), another key's does not (with the names it asked for), a pasted
 *     private key is refused and the box emptied at once, without Compare (the first line of its
 *     base64 alone too; it does not come back after another tab or tool, while a CSR does), a
 *     certificate is named as one; "Delete all local data" empties the box;
 *   - Turkish + dark, a 375 px and a 320 px phone: no horizontal scroll, the table as cards;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; no request sent.
 */

import { readFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { pinnedClockScript } from './clock.mjs';
import { orderSuites } from './run-all.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  csvHeader, gotoRoute, installDownloadCapture, resultAction, setLangUi, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';
import { ESTATE_CSV_COLUMNS, ESTATE_TRUST_COLUMNS } from '../../assets/js/lib/estate.js';

/** The CLI's --estate --csv columns of report-a.json: its scan checked trust, so the two trust columns come last. */
const CSV_A = [...ESTATE_CSV_COLUMNS, ...ESTATE_TRUST_COLUMNS].map((c) => c.key);

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

/**
 * The reports open in the view, the result header (its title and counts: `status`, by key; the
 * pressed one), the rows the certificate table shows, the notes and the empty state.
 */
const viewInfo = (page) => page.evaluate(() => ({
  reports: [...document.querySelectorAll('.estate-report')].map((li) => li.dataset.report),
  title: document.querySelector('.estate-overview .result-title')?.textContent || '',
  status: Object.fromEntries([...document.querySelectorAll('.estate-overview .status-item')].map((b) => [b.dataset.status, Number(b.dataset.count)])),
  pressed: [...document.querySelectorAll('.estate-overview .status-item[aria-pressed="true"]')].map((b) => b.dataset.status),
  rows: [...document.querySelectorAll('.estate-table tbody tr.dt-row')].length,
  names: [...document.querySelectorAll('.estate-table tbody tr.dt-row .estate-cert-name')].map((e) => e.textContent),
  notes: [...document.querySelectorAll('.estate-notes .finding')].map((a) => a.textContent),
  errors: [...document.querySelectorAll('.estate-errors li')].map((li) => li.textContent),
  tabs: [...document.querySelectorAll('.estate-tabs .tab')].map((b) => `${b.dataset.tab}:${b.querySelector('.tab-badge')?.textContent}`),
  empty: !!document.querySelector('.estate-page > .estate-empty')
}));

/** Open the compact input's "n reports loaded" disclosure (the reports, the drop zone, paste), when reports are loaded. */
const openImport = (page) => page.evaluate(() => {
  const more = document.querySelector('.estate-import-more');
  if (more && !more.open) more.open = true;
});

/** Pick a value of the certificate list's Show select. */
const showFilter = (page, value) => page.evaluate((v) => {
  const s = document.querySelector('.estate-filter select');
  s.value = v;
  s.dispatchEvent(new Event('change', { bubbles: true }));
}, value);

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

/**
 * bundle_leaf.pem in the Certificate view, settled: the leaf shown and the missing-intermediate
 * lookup it starts over (ui/chain-repair.js `data-chainfix`), whose note above the tabs grows when
 * it ends — a click measured before that lands below the tab (the "its own CSR matches" flake on a
 * busy machine).
 */
async function certLoaded(page) {
  await page.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === 'www.example.com'
    && !document.querySelector('.cert-view [data-chainfix="running"]'), { message: 'certificate loaded, its chain lookup done' });
  await removeToasts(page);
}

/** The PEM & OpenSSL tab selected and its CSR box on screen. */
async function openPemTab(page) {
  await page.click('.cert-tabs .tab[data-tab="pem"]');
  await page.waitFor(() => document.querySelector('.cert-tabs .tab[data-tab="pem"]')?.getAttribute('aria-selected') === 'true'
    && document.querySelector('.cert-tabs .tabpanel[data-tab="pem"]:not([hidden]) [data-role="cert-csr"]'), { message: 'PEM & OpenSSL tab' });
}

/** Type into the CSR box, then wait until it holds the text and has the focus (what Ctrl+Enter acts on). */
async function typeCsr(page, text) {
  await page.type('[data-role="cert-csr"]', text);
  await page.waitFor((want) => {
    const box = document.querySelector('.cert-tabs .tabpanel[data-tab="pem"]:not([hidden]) [data-role="cert-csr"]');
    return !!box && document.activeElement === box && box.value.replace(/\r\n/g, '\n').trim() === want;
  }, { args: [text.replace(/\r\n/g, '\n').trim()], message: 'the CSR in the focused box' });
}

/** Open the Certificate view with bundle_leaf.pem on its PEM & OpenSSL tab. */
async function certPemTab(page) {
  await gotoRoute(page, 'cert');
  if (!(await page.evaluate(() => document.querySelector('.cert-overview-cn')?.textContent === 'www.example.com'))) {
    await page.setFileInput('.cert-view .filedrop-input', [fixture('bundle_leaf.pem')]);
  }
  await certLoaded(page);
  await openPemTab(page);
}

const csrBox = (page) => page.evaluate(() => document.querySelector('[data-role="cert-csr"]')?.value ?? null);

/** The instant the expectations were written for; the page's clock starts here on every load. */
const ESTATE_NOW = Date.parse('2026-10-01T12:00:00Z');
const ESTATE_CLOCK_SCRIPT = pinnedClockScript(ESTATE_NOW);

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
    // The fixture reports carry fixed expiry dates (one on 2026-10-03, one on 2026-10-20) and the
    // view buckets them against Date.now(), so the page runs on a clock that starts at the
    // suite's reference date and keeps moving: the expiry counts and figures never drift with today.
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: ESTATE_CLOCK_SCRIPT });
    netHits = await networkGuard(page);
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/estate`);
    await waitReady(page);
    await setLangUi(page, 'en');
    await gotoRoute(page, 'estate');

    run.group('Certificate estate (desktop 1440×900, English, light)');
    await run.step('the last tool of Deploy & renew certificates; the empty page offers the drop zone and the command', async () => {
      const info = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/scan"]'));
        return {
          nav: group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '')) : [],
          title: document.querySelector('h1')?.textContent,
          drop: !!document.querySelector('.estate-import .estate-drop'),
          how: document.querySelector('.estate-how')?.open,
          cmd: document.querySelector('.estate-how pre, .estate-how code')?.textContent || '',
          privacy: document.querySelector('.estate-import .tool-input-foot .privacy-note')?.textContent || '',
          alert: !!document.querySelector('#page-body .alert-ok'),
          empty: document.querySelector('.estate-page > .estate-empty .tool-empty-message')?.textContent || '',
          checks: document.querySelectorAll('.estate-empty .tool-empty-check').length,
          head: !!document.querySelector('.estate-overview')
        };
      });
      assertEqual(info.nav, ['scan', 'cert', 'renew', 'estate'], 'Deploy & renew certificates group');
      assertEqual(info.title, 'Certificate estate', 'title');
      assert(info.drop, 'drop zone in the input card');
      assert(info.how, 'the command is shown while nothing is open');
      assert(info.cmd.includes('--estate --json estate.json'), `command: ${info.cmd}`);
      // The privacy note is one quiet line in the card's footer, not a green alert (docs/DESIGN.md §5.6).
      assert(/^The reports are read here and kept only in this tab/.test(info.privacy) && !info.alert, `privacy note: ${info.privacy}`);
      assert(info.empty.startsWith('Every certificate the scanned servers serve') && info.checks === 5 && !info.head, `empty state: ${JSON.stringify(info)}`);
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

    await run.step('report-a.json: the result header and its counts, the figures, a row per certificate; the input folds to one row', async () => {
      await choose(page, [REPORT_A], () => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, '9 rows');
      const info = await viewInfo(page);
      assertEqual(info.reports, ['report-a.json'], 'report list');
      assertEqual(info.errors, [], 'the error of the earlier file is gone');
      assert(/^Certificate estate · 9 certificates on \d+ endpoints$/.test(info.title), `title: ${info.title}`);
      assertEqual(info.status, { expired: 1, soon: 2, 'name-conflict': 5, 'shared-key': 2, weak: 2 }, 'the counts, worst first');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.estate-overview .status-item .status-text')].map((b) => b.textContent)),
        ['1 expired', '2 expire within 30 days', '5 in a name conflict', '2 with a shared key', '2 weak'], 'their words');
      assertEqual(info.pressed, [], 'nothing pressed: every certificate listed');
      assertEqual(info.tabs, ['certificates:9', 'conflicts:2', 'keys:3'], 'tab badges');
      assertEqual(info.names[0], 'old.example.net', 'soonest expiry first');
      assert(await page.evaluate(() => document.activeElement === document.querySelector('.estate-overview .result-title')), 'the focus on the result, not <body>');
      // The figures (region 6) of the list: the expiry buckets, the kinds — read-only.
      const figures = await page.evaluate(() => Object.fromEntries(['expiry', 'kinds'].map((id) => [id, [...document.querySelectorAll(`.estate-metrics-${id} .metric`)]
        .map((m) => `${m.querySelector('.metric-label').textContent} ${m.querySelector('.metric-value').textContent}`)])));
      assertEqual(figures.expiry, ['expired 1', '< 7 days 1', '< 30 days 1', '< 90 days 0', 'later 6'], 'expiry figures');
      assert(['Cloudflare Origin CA 1', 'self-signed 6', 'private CA 1'].every((x) => figures.kinds.includes(x)), `kinds: ${figures.kinds}`);
      assertEqual(await page.evaluate(() => document.querySelectorAll('.estate-metrics button, .estate-metrics a').length), 0, 'figures, not controls');
      // Region 2 once a report is read: "1 report loaded" (a disclosure), Add files, Forget all; the privacy note stays.
      const input = await page.evaluate(() => ({
        more: document.querySelector('.estate-import .estate-import-more > summary')?.textContent.trim(),
        open: document.querySelector('.estate-import-more')?.open,
        actions: [...document.querySelectorAll('.estate-import .file-input-actions button')].map((b) => b.dataset.action),
        privacy: !!document.querySelector('.estate-import .tool-input-foot .privacy-note')
      }));
      assertEqual(input, { more: '1 report loaded', open: false, actions: ['estate-add', 'estate-forget'], privacy: true }, 'the compact input');
      await removeToasts(page);
      await shotPage(page, opts, 'estate-report-desktop-light-en');
    });

    await run.step('a count filters the table (pressed, the focus kept), a second press shows every row; the Show select filters too', async () => {
      await page.click('.estate-overview .status-item[data-status="weak"]');
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 2, { message: 'weak rows' });
      let info = await viewInfo(page);
      assertEqual(info.pressed, ['weak'], 'Weak pressed');
      assert(await page.evaluate(() => document.activeElement?.dataset.status === 'weak'), 'focus stays on the count');
      assertEqual(await page.evaluate(() => document.querySelector('.estate-filter select').value), 'weak', 'the select follows');
      await page.click('.estate-overview .status-item[data-status="weak"]');
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, { message: 'every row again' });
      assertEqual([(await viewInfo(page)).pressed, await page.evaluate(() => document.querySelector('.estate-filter select').value)], [[], 'all'], 'nothing pressed, All');
      await showFilter(page, 'expired');
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 1, { message: 'expired rows' });
      assertEqual((await viewInfo(page)).pressed, ['expired'], 'the count follows the select');
      await showFilter(page, 'covers-none');
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 3, { message: 'covers-none rows' });
      info = await viewInfo(page);
      assertEqual(info.pressed, [], 'no count for covering no name');
      assertEqual(info.names.sort(), ['legacy.example.net', 'legacy.example.org', 'old.example.net'], 'covering no name');
    });

    await run.step('a row\'s details: fingerprints and where it is served', async () => {
      await page.click('.estate-table tbody tr.dt-row .dt-expand-btn');
      const details = await page.waitFor(() => document.querySelector('.estate-table .estate-details')?.textContent, { message: 'details' });
      assert(details.includes('SHA-256') && details.includes('Public key SHA-256'), 'fingerprints');
      assert(details.includes('Where it is served'), 'served');
      await shotEl(page, opts, 'estate-details-desktop-light-en', '.estate-table');
    });

    await run.step('CSV (the header\'s Export ▾, with Print): the CLI\'s --estate --csv columns, the rows of the filter', async () => {
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.estate-overview .result-actions [data-menu="export"] ~ .menu-popover .menu-item')]
        .map((i) => i.dataset.export || i.dataset.action)), ['csv', 'print'], 'Export ▾: the CSV, then Print');
      assert(await page.evaluate(() => !document.querySelector('.estate-overview [data-action="copy-link"]') && !document.querySelector('.estate-table [data-export]')),
        'no Copy link (the reports never go into a URL), no CSV button of the table');
      await takeDownloads(page);
      await resultAction(page, '[data-export="csv"]', '.estate-overview');
      const [file] = await takeDownloads(page);
      assert(file && /^estate-\d{8}-\d{4}\.csv$/.test(file.name), `file name: ${file && file.name}`);
      assert(file.bom, 'BOM for Excel');
      assertEqual(csvHeader(file.text), CSV_A, 'columns');
      const rows = file.text.trim().split(/\r?\n/).slice(1);
      assertEqual(rows.length, 6, 'legacy.example.org on web01 and web02, legacy.example.net and old.example.net each on legacy-a and legacy-b');
      await removeToasts(page);
    });

    await run.step('the CLI\'s trust check: the untrusted filter, the flag, each endpoint\'s verdict in its own words', async () => {
      await showFilter(page, 'untrusted');
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 3, { message: 'untrusted rows' });
      const info = await page.evaluate(() => ({
        option: [...document.querySelectorAll('.estate-filter option')].find((o) => o.value === 'untrusted')?.textContent,
        flagged: [...document.querySelectorAll('.estate-table tbody tr.dt-row')].map((tr) => !!tr.querySelector('.estate-flag-untrusted'))
      }));
      assertEqual(info.option, 'Served with an untrusted chain (3)', 'the filter and its count');
      assertEqual(info.flagged, [true, true, true], 'each row carries the flag');
      assertEqual((await viewInfo(page)).names.sort(), ['*.wild.example.net', 'CloudFlare Origin Certificate', 'www.example-test.com.tr'], 'untrusted');
      // the old wildcard web01 still sends: self-signed
      await page.evaluate(() => [...document.querySelectorAll('.estate-table tbody tr.dt-row')]
        .find((tr) => tr.querySelector('.estate-cert-name')?.textContent === '*.wild.example.net').querySelector('.dt-expand-btn').click());
      const served = await page.waitFor(() => {
        const li = [...document.querySelectorAll('.estate-table .estate-d-endpoints li')].find((x) => x.querySelector('.estate-untrusted'));
        return li ? { text: li.textContent, title: li.querySelector('.estate-flag-untrusted')?.title } : false;
      }, { message: 'the endpoint\'s verdict' });
      assert(served.text.includes('192.0.2.10') && served.text.includes('untrusted') && served.text.includes('self-signed (code 18)'), served.text);
      assert(served.title.includes('a missing intermediate, a private CA or a self-signed certificate'), served.title);
      await removeToasts(page);
      await shotEl(page, opts, 'estate-untrusted-desktop-light-en', '.estate-table');
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
      await showFilter(page, 'all');
      await choose(page, [REPORT_B], () => document.querySelectorAll('.estate-report').length === 2, 'two reports');
      await frames(page);
      const info = await viewInfo(page);
      assertEqual(info.reports, ['report-a.json', 'report-b.json'], 'two reports');
      assert(info.notes.some((n) => n.includes('192.0.2.11:443 was scanned by more than one report')), `notes: ${info.notes}`);
      assert(info.title.includes('· 9 certificates on'), `still nine certificates (report B has none of its own): ${info.title}`);
      assertEqual(await page.evaluate(() => document.querySelector('.estate-import-more > summary').textContent.trim()), '2 reports loaded', 'the compact input counts both');
      await takeDownloads(page);
      await resultAction(page, '[data-export="csv"]', '.estate-overview');
      const [file] = await takeDownloads(page);
      assertEqual(csvHeader(file.text), [...CSV_A, 'report'], 'report column');
      assert(/,report-b\.json\r?\n/.test(file.text) && /,report-a\.json\r?\n/.test(file.text), 'rows name their report');
      await removeToasts(page);
    });

    await run.step('Copy summary: the counts, what expires first and the conflicts by name, never an address; a bare #/estate link', async () => {
      await stubClipboard(page);
      const tip = await page.evaluate(() => document.querySelector('[data-summary="estate"] [data-action="copy-summary"]').title);
      assert(/nothing from your server list/.test(tip) && /without any file contents/.test(tip), `tooltip: ${tip}`);
      await page.click('[data-summary="estate"] [data-action="copy-summary"]');
      await page.click('[data-summary="estate"] [data-action="copy-summary-text"]');
      await page.waitFor(() => window.__clip.length === 2, { message: 'two copies' });
      const [md, plain] = await takeClipboard(page);
      const lines = md.trim().split('\n');
      assertEqual(lines[0], '**Certificate estate · 2 reports**', 'title');
      assert(/^- 9 certificates · served on \d+ endpoints$/.test(lines[1]), `counts: ${lines[1]}`);
      assert(lines.some((l) => /^- \*\*\d+ names? served with different certificates:\*\* `/.test(l)), `the conflicts by name:\n${md}`);
      assert(!/192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:db8:/.test(md), `no address:\n${md}`);
      assert(new RegExp(`^DomainScope · scanned \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2} UTC · ${origin}${BASE}#/estate$`).test(lines[lines.length - 1]), `footer: ${lines[lines.length - 1]}`);
      assertEqual(plain, md.replace(/\*\*|`/g, '').replace('\n\nDomainScope · ', '\nDomainScope · '), 'the same lines in plain text');
      await removeToasts(page);
    });

    await run.step('the same report again is a duplicate; a pasted report opens, a pasted non-report says why', async () => {
      await page.setFileInput(`${PAGE} .estate-drop .filedrop-input`, [REPORT_A]);
      const toast = await page.waitFor(() => [...document.querySelectorAll('.toast')].map((t) => t.textContent).find((t) => t.includes('already open')), { message: 'duplicate toast' });
      assert(toast.includes('report-a.json: the same report is already open'), toast);
      assertEqual((await viewInfo(page)).reports.length, 2, 'still two');
      // Reports are loaded: the paste box is behind "2 reports loaded".
      await openImport(page);
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

    await run.step('removing a report (the focus on the next Remove), then Forget all', async () => {
      await openImport(page);
      await page.click('.estate-report[data-report="report-b.json"] .btn-icon');
      await page.waitFor(() => document.querySelectorAll('.estate-report').length === 1, { message: 'one report left' });
      assertEqual((await viewInfo(page)).notes.filter((n) => n.includes('more than one report')), [], 'no overlap note');
      assert(await page.evaluate(() => document.activeElement === document.querySelector('.estate-report .btn-icon')), 'the focus on the Remove left, not <body>');
      await page.click('[data-action="estate-forget"]');
      await page.waitFor(() => !document.querySelector('.estate-report') && document.querySelector('.estate-page > .estate-empty'), { message: 'forgotten' });
      assert(await page.evaluate(() => document.activeElement?.classList.contains('estate-drop')), 'the focus on the drop zone of the whole card');
      await removeToasts(page);
    });

    await run.step('"Delete all local data" forgets the reports, the view on screen or not', async () => {
      await choose(page, [REPORT_A], () => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, 'report read');
      await removeToasts(page);
      await deleteAllLocalData(page);
      await page.waitFor(() => document.querySelector('.estate-page > .estate-empty') && !document.querySelector('.estate-report'), { message: 'emptied on screen' });
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
      await page.waitFor(() => document.querySelector('.estate-page > .estate-empty') && !document.querySelector('.estate-report'), { message: 'emptied by the switch' });
      await page.evaluate((wsId) => import('./assets/js/state.js').then(async ({ state }) => {
        await state.switchWorkspace(state.workspaces.find((w) => w.isDefault).id);
        await state.deleteWorkspace(wsId);
      }), id);
      await page.waitFor(() => document.querySelector('.estate-page > .estate-empty'), { message: 'back in Default, still empty' });
      assertEqual((await viewInfo(page)).reports, [], 'nothing came back with Default');
    });

    await run.step('a report where no server returned a certificate: no key to compare, not "an older CLI"', async () => {
      const doc = JSON.parse(await readFile(REPORT_A, 'utf8'));
      doc.results = doc.results.map((r) => ({ ...r, certSha256: null }));
      doc.certificates = {};
      delete doc.estate;
      await page.evaluate(() => { document.querySelector('.estate-paste').open = true; });
      await page.type('[data-role="estate-paste"]', JSON.stringify(doc));
      await page.press('Enter', { ctrl: true });
      await page.waitFor(() => document.querySelectorAll('.estate-report').length === 1, { message: 'the report read' });
      const info = await viewInfo(page);
      assertEqual(info.title, 'Certificate estate · 0 certificates on 0 endpoints', 'no certificate');
      assert(!info.notes.some((n) => n.includes('older CLI')), `notes: ${info.notes}`);
      await page.click('.estate-tabs .tab[data-tab="keys"]');
      const text = await page.waitFor(() => document.querySelector('.estate-tabs .tabpanel[data-tab="keys"]:not([hidden]) .empty')?.textContent, { message: 'keys tab' });
      assert(text.includes('No server returned a certificate') && !text.includes('older CLI'), text);
      await page.click('.estate-tabs .tab[data-tab="certificates"]');
      await page.click('[data-action="estate-forget"]');
      await page.waitFor(() => !document.querySelector('.estate-report'), { message: 'forgotten' });
      await removeToasts(page);
    });

    run.group('Certificate › PEM & OpenSSL › Does this CSR match?');
    await run.step('its own CSR matches (Ctrl+Enter in the box), another key\'s does not', async () => {
      await gotoRoute(page, 'cert');
      await page.setFileInput('.cert-view .filedrop-input', [fixture('bundle_leaf.pem')]);
      await certLoaded(page);
      await openPemTab(page);
      await typeCsr(page, await readFile(fixture('bundle_leaf.csr'), 'utf8'));
      await page.press('Enter', { ctrl: true });
      const ok = await page.waitFor(() => {
        const v = document.querySelector('.cert-csr-verdict');
        return v ? { match: v.dataset.match, text: v.textContent } : false;
      }, { message: 'match verdict' });
      assertEqual(ok.match, 'true', 'match');
      assert(ok.text.includes('The CSR matches this certificate') && ok.text.includes('RSA 2048'), ok.text);
      await shotEl(page, opts, 'cert-csr-match-desktop-light-en', '.cert-csr');
      await typeCsr(page, await readFile(fixture('bundle_other.csr'), 'utf8'));
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
      await typeCsr(page, await readFile(fixture('bundle_leaf.pem'), 'utf8'));
      await page.click('[data-action="cert-csr-compare"]');
      await page.waitFor(() => document.querySelector('.cert-csr-verdict[data-error="certificate"]'), { message: 'certificate verdict' });
      // only the first line of a key's base64: refused all the same
      const firstLine = (await readFile(fixture('bundle_leaf.key'), 'utf8')).replace(/-----[^-]+-----/g, '').trim().split(/\r?\n/)[0];
      await page.type('[data-role="cert-csr"]', firstLine);
      await page.waitFor(() => document.querySelector('.cert-csr-verdict[data-error="private-key"]')
        && document.querySelector('[data-role="cert-csr"]').value === '', { message: 'a partial key refused' });
    });

    await run.step('a key pasted without Compare does not come back after another tab or tool; a CSR does', async () => {
      await page.type('[data-role="cert-csr"]', await readFile(fixture('bundle_leaf.rsa.key'), 'utf8'));
      await page.click('.cert-tabs .tab[data-tab="names"]');
      await openPemTab(page);
      assertEqual(await csrBox(page), '', 'empty after another tab');
      await gotoRoute(page, 'estate');
      await certPemTab(page);
      assertEqual(await csrBox(page), '', 'empty after another tool');
      const csr = await readFile(fixture('bundle_leaf.csr'), 'utf8');
      await typeCsr(page, csr);
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
      // the CLI's trust check in Turkish: the filter, and the verify code in the page's words
      await page.waitFor(() => document.querySelector('.estate-filter select'), { message: 'filter (TR)' });
      await page.evaluate(() => {
        const s = document.querySelector('.estate-filter select');
        s.value = 'untrusted';
        s.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 3, { message: 'untrusted rows (TR)' });
      await page.evaluate(() => [...document.querySelectorAll('.estate-table tbody tr.dt-row')]
        .find((tr) => tr.querySelector('.estate-cert-name')?.textContent === 'CloudFlare Origin Certificate').querySelector('.dt-expand-btn').click());
      const verdict = await page.waitFor(() => document.querySelector('.estate-table .estate-untrusted')?.textContent, { message: 'the verdict (TR)' });
      assert(verdict.includes('güvenilmeyen') && verdict.includes('eksik ara sertifika ya da özel CA (kod 20)'), verdict);
      await assertNoHorizontalScroll(page, 'estate untrusted phone dark TR');
      assertEqual(await overflowingIn(page, PAGE), [], 'the details inside 375 px');
      await removeToasts(page);
      await shotEl(page, opts, 'estate-untrusted-phone-dark-tr', '.estate-table');
      await page.evaluate(() => {
        const s = document.querySelector('.estate-filter select');
        s.value = 'all';
        s.dispatchEvent(new Event('change', { bubbles: true }));
      });
    });

    await run.step('320 px, English, light: still no horizontal scroll', async () => {
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport({ width: 320, height: 720, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 320 && document.querySelector('.estate-overview'), { message: '320 px' });
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
      await page.waitFor(() => document.querySelector('.estate-overview'), { message: 'the result header' });
      await assertNoHorizontalScroll(page, 'estate desktop dark TR');
      await shotPage(page, opts, 'estate-report-desktop-dark-tr');
      await gotoRoute(page, 'cert');
      await certLoaded(page);
      await openPemTab(page);
      await typeCsr(page, await readFile(fixture('bundle_leaf.csr'), 'utf8'));
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
