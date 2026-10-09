#!/usr/bin/env node
/**
 * monitor.e2e.mjs — end-to-end test of the Monitoring view (views/monitor.js over lib/monitor.js
 * and lib/monitorfetch.js) in a real headless Chrome/Edge. OFFLINE: the results folder is
 * tests/js/monitor-fixture.mjs written to a temporary folder (made up, documentation names only);
 * GitHub's API is answered inside the page (installed before the app, so the ledger counts the
 * requests); a network-level guard (CDP Fetch) fails and records any https request — the suite
 * asserts none.
 *
 *   node tests/e2e/monitor.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - navigation: Monitoring is the first tool of Setup & info; the empty page offers the drop
 *     zone (focused by '/'), the folder picker and where the results come from;
 *   - the folder: five reports, three months of history (two bad lines skipped and said), the
 *     Markdown summaries left alone, a stray file named; the tiles (5 targets, 3 with bad changes
 *     in 7 days, 2 certificates under 21 days, 2 checks that did not complete), worst rows first,
 *     each row's sparklines, grade, certificates, takeover and audit, and its checks (a button to
 *     its changes only when it has some); a tile filters the table and keeps the focus; a row's
 *     details list every check;
 *   - the timeline newest first (times in UTC) with the runs' own words, filtered by tone and by a
 *     row's target, and its CSV; Copy summary (names only, a bare #/monitor link); the links to the
 *     nightly issues and the latest run;
 *   - GitHub: a missing token said before anything is sent; the token read once and emptied, sent
 *     only in the Authorization header to api.github.com (no cookies, no referrer, no redirects),
 *     kept nowhere (the DOM, storage, IndexedDB); the ledger names GitHub with the repository and
 *     the token; the open issue linked; a refused token in the page's words;
 *   - Forget, "Delete all local data" and another workspace forget the results;
 *   - Turkish + dark at 375 px and English at 320 px: no horizontal scroll, the table as cards;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; no request sent.
 */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { pinnedClockScript } from './clock.mjs';
import { orderSuites } from './run-all.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner, csvHeader, gotoRoute,
  installDownloadCapture, setLangUi, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';
import { monitorFixture, MONITOR_NOW } from '../js/monitor-fixture.mjs';
import { TIMELINE_CSV_COLUMNS } from '../../assets/js/lib/monitor.js';

const PAGE = '.mon-page';
/** A made-up token, built from pieces (no file holds anything token-shaped). */
const TOKEN = ['github', 'pat', 'e2e', 'made', 'up', 'token', '42'].join('_');

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

/**
 * GitHub's API for example-org/nightly, answered inside the page: the contents listings and raw
 * files of results/, the open issues. Only the fixture token is accepted; every request is logged
 * with what it carried — whether the token was in the header, never its value.
 */
const fakeGithubScript = (files, token) => `(() => {
  const FILES = ${JSON.stringify(files)};
  const TOKEN = ${JSON.stringify(token)};
  const G = window.__gh = { calls: [] };
  const prevFetch = window.fetch;
  const res = (status, body, headers = {}) => new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status, headers: { 'content-type': 'application/json', 'x-ratelimit-remaining': '4990', 'x-ratelimit-reset': '1791510624', ...headers }
  });
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!url.startsWith('https://api.github.com/')) return prevFetch(input, init);
    const headers = init.headers || {};
    const auth = String(headers.authorization || '');
    G.calls.push({ url, tokenOk: auth === 'Bearer ' + TOKEN, tokenInUrl: url.includes(TOKEN), credentials: init.credentials, redirect: init.redirect, referrerPolicy: init.referrerPolicy });
    if (auth !== 'Bearer ' + TOKEN) return res(401, { message: 'Bad credentials' });
    const u = new URL(url);
    const base = '/repos/example-org/nightly/';
    if (!u.pathname.startsWith(base)) return res(404, { message: 'Not Found' });
    const rest = decodeURIComponent(u.pathname.slice(base.length));
    if (rest === 'issues') {
      return res(200, [{ number: 12, title: 'DomainScope: changes since the last nightly run', html_url: 'https://github.com/example-org/nightly/issues/12', updated_at: '2026-10-09T03:45:00Z', comments: 3 }]);
    }
    if (!rest.startsWith('contents/results')) return res(404, { message: 'Not Found' });
    const sub = rest.slice('contents/results'.length).replace(/^\\//, '');
    if (sub === '' || sub === 'history') {
      const seen = new Map();
      for (const p of Object.keys(FILES)) {
        if (sub && !p.startsWith(sub + '/')) continue;
        const name = (sub ? p.slice(sub.length + 1) : p).split('/');
        seen.set(name[0], name.length > 1 ? { name: name[0], type: 'dir', size: 0 } : { name: name[0], type: 'file', size: FILES[p].length });
      }
      return res(200, [...seen.values()]);
    }
    if (!(sub in FILES)) return res(404, { message: 'Not Found' });
    return res(200, FILES[sub], { 'content-type': 'application/vnd.github.raw+json; charset=utf-8' });
  };
})();`;

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
    if (el.closest('pre, .codeblock, .tablist-scroll, .mon-details')) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
}, selector);

/** What the view shows: the tiles, the rows, the timeline, the notes. */
const viewInfo = (page) => page.evaluate(() => {
  const stat = (f) => document.querySelector(`.mon-stats [data-filter="${f}"] .stat-value`)?.textContent ?? null;
  return {
    stats: Object.fromEntries(['all', 'bad', 'expiring', 'incomplete'].map((f) => [f, stat(f)])),
    pressed: [...document.querySelectorAll('.mon-stats .stat-button[aria-pressed="true"]')].map((b) => b.dataset.filter),
    rows: [...document.querySelectorAll('.mon-table tbody tr.dt-row .mon-target-name')].map((e) => e.textContent),
    read: document.querySelector('[data-role="mon-read"]')?.textContent || '',
    errors: [...document.querySelectorAll('.mon-errors li')].map((li) => li.textContent),
    notes: [...document.querySelectorAll('.mon-results > .alert')].map((a) => a.textContent),
    entries: [...document.querySelectorAll('.mon-tl-entry')].map((li) => `${li.dataset.tag} ${li.querySelector('.mon-tl-target')?.textContent}`),
    empty: !!document.querySelector('.mon-page > .empty')
  };
});

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
  await page.waitFor(() => document.querySelector('#page-body')?.childElementCount > 0
    && !document.querySelector('#page-body .page-loading'), { message: 'the tool opened again' });
  await frames(page);
}

/** Everything this page keeps where the token must never be: the DOM, the URL, storage, every IndexedDB store. */
const keptAnywhere = (page) => page.evaluate(async () => {
  const parts = [document.documentElement.outerHTML, location.href];
  for (const st of [localStorage, sessionStorage]) for (let i = 0; i < st.length; i += 1) parts.push(st.key(i), st.getItem(st.key(i)));
  for (const info of (indexedDB.databases ? await indexedDB.databases() : [])) {
    const db = await new Promise((res, rej) => { const r = indexedDB.open(info.name); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    for (const name of db.objectStoreNames) {
      const all = await new Promise((res) => { const r = db.transaction(name).objectStore(name).getAll(); r.onsuccess = () => res(r.result); r.onerror = () => res([]); });
      parts.push(JSON.stringify(all));
    }
    db.close();
  }
  return parts.join('\n');
});

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const fx = monitorFixture();
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-monitor-e2e-'));
  const folder = path.join(tmp, 'results');
  await mkdir(path.join(folder, 'history'), { recursive: true });
  const ghFiles = {};
  const paths = [];
  for (const f of fx.files) {
    const rel = /\.jsonl$/.test(f.name) ? `history/${f.name}` : f.name;
    await writeFile(path.join(folder, ...rel.split('/')), f.text);
    paths.push(path.join(folder, ...rel.split('/')));
    if (!/\.md$/.test(f.name)) ghFiles[rel] = f.text;
  }
  const stray = path.join(folder, 'notes.txt');
  await writeFile(stray, 'not a result\n');
  const choose = async (page, files) => {
    await page.setFileInput(`${PAGE} .mon-drop .filedrop-input`, files);
    await page.waitFor(() => document.querySelectorAll('.mon-table tbody tr.dt-row').length === 5, { message: 'five rows', timeout: 15000 });
    await frames(page);
  };

  run.group('Node: harness');
  await run.step('run-all orders the monitor suite right after revocation', () => {
    assertEqual(orderSuites(['carry.e2e.mjs', 'monitor.e2e.mjs', 'revocation.e2e.mjs']), ['revocation', 'monitor', 'carry'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: fixture results and a fake GitHub API only\n`);
  let page = null;
  let netHits = [];
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    // The fixture's nights end on 2026-10-09: the page runs on a clock that starts then and keeps moving.
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: pinnedClockScript(MONITOR_NOW) });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeGithubScript(ghFiles, TOKEN) });
    netHits = await networkGuard(page);
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/monitor`);
    await waitReady(page);
    await setLangUi(page, 'en');
    await gotoRoute(page, 'monitor');

    run.group('Monitoring (desktop 1440×900, English, light)');
    await run.step('the first tool of Setup & info; the empty page offers the drop zone, the folder picker and where the results come from', async () => {
      const info = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/about"]'));
        return {
          nav: group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '')) : [],
          title: document.querySelector('h1')?.textContent,
          drop: !!document.querySelector('.mon-drop'),
          folder: !!document.querySelector('[data-action="mon-folder"]'),
          how: document.querySelector('.mon-how')?.open,
          cmd: document.querySelector('.mon-how pre, .mon-how code')?.textContent || '',
          empty: document.querySelector('.mon-page .empty')?.textContent || ''
        };
      });
      assertEqual(info.nav, ['monitor', 'inventory', 'about'], 'Setup & info group');
      assertEqual(info.title, 'Monitoring', 'title');
      assert(info.drop && info.folder, 'drop zone and folder picker');
      assert(info.how, 'where the results come from, open while nothing is');
      assert(info.cmd.includes('--history results/history'), `command: ${info.cmd}`);
      assert(info.empty.includes('No results open yet'), 'empty state');
      await page.evaluate(() => document.activeElement && document.activeElement.blur());
      await page.press('/');
      assert(await page.evaluate(() => document.activeElement?.classList.contains('mon-drop')), '/ focuses the drop zone');
      await shotPage(page, opts, 'monitor-empty-desktop-light-en');
    });

    await run.step('the results folder: five reports, three months of history, the summaries left alone, a stray file named', async () => {
      await choose(page, [...paths, stray]);
      const info = await viewInfo(page);
      assertEqual(info.read, 'Read: 5 reports · 3 months of history · 415 lines', 'what was read');
      assertEqual(info.errors, ['notes.txt: neither a report (.json) nor a history file (.jsonl)'], 'the stray file');
      assertEqual(info.notes, ['2 lines of the history were not ones the runner writes and were skipped.'], 'the skipped lines');
      assertEqual(info.stats, { all: '5', bad: '3', expiring: '2', incomplete: '2' }, 'tiles');
      assertEqual(info.pressed, ['all'], 'All pressed');
      assertEqual(info.rows, ['example.com', 'example.org', 'mail.example.net', 'www.example.com', 'example.net'], 'worst first');
      assert(await page.evaluate(() => document.activeElement?.dataset.filter === 'all'), 'the focus on the Targets tile, not <body>');
      const hint = await page.evaluate(() => document.querySelector('.mon-stats [data-filter="expiring"] .stat-hint')?.textContent);
      assertEqual(hint, 'soonest: mail.example.net (expired 4 days ago)', 'the soonest certificate');
      await removeToasts(page);
      await shotPage(page, opts, 'monitor-results-desktop-light-en');
    });

    await run.step('each row: the sparklines, the grade, the certificates, the takeover and the audit, the checks', async () => {
      const com = await page.evaluate(() => {
        const row = [...document.querySelectorAll('.mon-table tbody tr.dt-row')][0];
        return {
          sparks: [...row.querySelectorAll('.mon-spark')].map((s) => `${s.classList[1]} ${s.querySelectorAll('polyline').length} ${s.querySelector('svg')?.getAttribute('aria-label')}`),
          text: row.textContent
        };
      });
      assertEqual(com.sparks, [
        'mon-spark-score 1 Health score over 51 nights: 90 → 82',
        'mon-spark-days 1 Soonest certificate expiry over 51 nights: 65 → 15 days'
      ], 'two sparklines with their words');
      for (const want of ['B', '82/100', '15 days left', '1 new issuer', '1 takeover risk', '1 rule fails', 'security 5/8', '3 bad changes', 'Takeover: not run since']) {
        assert(com.text.includes(want), `example.com row: ${want} in ${com.text}`);
      }
      const mail = await page.evaluate(() => [...document.querySelectorAll('.mon-table tbody tr.dt-row')][2].textContent);
      assert(mail.includes('expired 4 days ago') && mail.includes('expired') && mail.includes('1 bad change'), mail);
      const org = await page.evaluate(() => [...document.querySelectorAll('.mon-table tbody tr.dt-row')][1].textContent);
      assert(org.includes('E') && org.includes('58/100') && org.includes('Health: did not complete'), org);
      const net = await page.evaluate(() => [...document.querySelectorAll('.mon-table tbody tr.dt-row')][4].textContent);
      assert(net.includes('A') && net.includes('95/100') && net.includes('no bad change') && net.includes('completed'), net);
      const filters = await page.evaluate(() => [...document.querySelectorAll('.mon-table tbody tr.dt-row')].map((tr) => !!tr.querySelector('.mon-target-filter')));
      assertEqual(filters, [true, true, true, true, false], 'a button to its changes only on a row that has some (example.net has none)');
    });

    await run.step('a tile filters the table and keeps the focus; pressed again it shows all', async () => {
      await page.click('.mon-stats [data-filter="expiring"]');
      await page.waitFor(() => document.querySelectorAll('.mon-table tbody tr.dt-row').length === 2, { message: 'expiring rows' });
      let info = await viewInfo(page);
      assertEqual([info.rows, info.pressed], [['example.com', 'mail.example.net'], ['expiring']], 'certificates under 21 days');
      assert(await page.evaluate(() => document.activeElement?.dataset.filter === 'expiring'), 'focus stays on the tile');
      await page.click('.mon-stats [data-filter="incomplete"]');
      await page.waitFor(() => document.querySelector('.mon-stats [data-filter="incomplete"]')?.getAttribute('aria-pressed') === 'true', { message: 'incomplete pressed' });
      await frames(page);
      info = await viewInfo(page);
      assertEqual(info.rows, ['example.com', 'example.org'], 'checks that did not complete');
      await page.click('.mon-stats [data-filter="incomplete"]');
      await page.waitFor(() => document.querySelectorAll('.mon-table tbody tr.dt-row').length === 5, { message: 'all again' });
      assertEqual((await viewInfo(page)).pressed, ['all'], 'the same tile again: all');
    });

    await run.step('a row\'s details: every check with its last run, its state and what it found', async () => {
      await page.click('.mon-table tbody tr.dt-row .dt-expand-btn');
      const rows = await page.waitFor(() => {
        const list = [...document.querySelectorAll('.mon-table .mon-d-table tbody tr')];
        return list.length ? list.map((tr) => `${tr.dataset.command}: ${tr.textContent}`) : false;
      }, { message: 'details' });
      assertEqual(rows.map((r) => r.split(':')[0]), ['health', 'ct', 'takeover', 'audit'], 'every check of example.com');
      assert(rows[2].includes('not run since') && rows[2].includes('1 takeover risk'), rows[2]);
      assert(rows[0].includes('report health.json') && rows[0].includes('0 bad · 0 other'), rows[0]);
      await shotEl(page, opts, 'monitor-details-desktop-light-en', '.mon-table');
      await page.click('.mon-table tbody tr.dt-row .dt-expand-btn');
    });

    await run.step('the timeline: newest first with the runs\' words, filtered by tone and by a row\'s target; its CSV', async () => {
      let info = await viewInfo(page);
      assertEqual(info.entries.slice(0, 3), ['ISSUER example.com', 'NEW example.org', 'SCORE example.org'], 'newest first');
      assertEqual(info.entries.length, 8, 'every change');
      const first = await page.evaluate(() => ({
        time: document.querySelector('.mon-tl-entry .mon-tl-time')?.textContent,
        text: document.querySelector('.mon-tl-entry .mon-tl-text')?.textContent,
        run: document.querySelector('.mon-tl-entry .mon-tl-run')?.getAttribute('href'),
        tip: document.querySelector('.mon-tl-entry .mon-tl-tag')?.title
      }));
      assertEqual(first, {
        time: '03:25 UTC',
        text: 'example.com: new issuer Google Trust Services (1 certificate)',
        run: 'https://github.com/example-org/nightly/actions/runs/4069',
        tip: 'A certificate issuer new to Certificate Transparency for the domain'
      }, 'the first entry');
      await page.click('.mon-tl-tone .seg-btn[data-value="bad"]');
      await page.waitFor(() => document.querySelectorAll('.mon-tl-entry').length === 5, { message: 'bad changes' });
      await page.click('.mon-table tbody tr.dt-row .mon-target-filter');
      await page.waitFor(() => document.querySelectorAll('.mon-tl-entry').length === 3, { message: 'the bad changes of example.com' });
      info = await viewInfo(page);
      assertEqual(info.entries, ['ISSUER example.com', 'WORSE example.com', 'RISK example.com'], 'filtered by the row');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="mon-tl-target"]').value), 'example.com', 'the target filter follows');
      await takeDownloads(page);
      await page.click('[data-action="mon-csv"]');
      const [file] = await takeDownloads(page);
      assert(file && /^monitor-changes-\d{8}-\d{4}\.csv$/.test(file.name), `file name: ${file && file.name}`);
      assert(file.bom, 'BOM for Excel');
      assertEqual(csvHeader(file.text), TIMELINE_CSV_COLUMNS.map((c) => c.key), 'columns');
      assertEqual(file.text.trim().split(/\r?\n/).length, 4, 'a header and the three changes shown');
      await removeToasts(page);
      await shotEl(page, opts, 'monitor-timeline-desktop-light-en', '.mon-timeline');
      await page.click('.mon-tl-tone .seg-btn[data-value="all"]');
      await page.evaluate(() => {
        const s = document.querySelector('[data-role="mon-tl-target"]');
        s.value = '';
        s.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => document.querySelectorAll('.mon-tl-entry').length === 8, { message: 'every change again' });
    });

    await run.step('Copy summary: the tiles by name, never an address; a bare #/monitor link', async () => {
      await stubClipboard(page);
      await page.click('[data-summary="monitor"] [data-action="copy-summary"]');
      await page.waitFor(() => window.__clip.length === 1, { message: 'copied' });
      const [md] = await takeClipboard(page);
      const lines = md.trim().split('\n');
      assertEqual(lines[0], '**Monitoring · 5 targets**', 'title');
      assert(lines.some((l) => l.startsWith('- **2 certificates under 21 days:** `mail.example.net` expired 4 days ago')), md);
      assert(!/192\.0\.2\.|198\.51\.100\.|2001:db8:/.test(md), `no address:\n${md}`);
      assertEqual(lines[lines.length - 1], `DomainScope · checked 2026-10-09 03:40 UTC · ${origin}${BASE}#/monitor`, 'footer');
      await removeToasts(page);
    });

    await run.step('links: the open nightly issues and the latest run the history names', async () => {
      const links = await page.evaluate(() => ({
        issues: document.querySelector('a.mon-link-issues')?.getAttribute('href'),
        run: document.querySelector('a.mon-link-run')?.getAttribute('href')
      }));
      assertEqual(links, {
        issues: 'https://github.com/example-org/nightly/issues?q=is%3Aissue%20is%3Aopen%20label%3Adomainscope',
        run: 'https://github.com/example-org/nightly/actions/runs/4069'
      }, 'links');
    });

    run.group('GitHub (a fake API inside the page)');
    await run.step('the token only in a header to api.github.com, the field emptied, kept nowhere; the results and the open issue read', async () => {
      await page.click('.mon-source .seg-btn[data-value="github"]');
      await page.waitForSelector('[data-role="mon-gh-repo"]');
      const ui = await page.evaluate(() => ({
        privacy: document.querySelector('.mon-gh .alert')?.textContent || '',
        links: [...document.querySelectorAll('.mon-gh-links a')].map((a) => a.getAttribute('href'))
      }));
      assert(/only to api\.github\.com/.test(ui.privacy) && /never saved/.test(ui.privacy) && /emptied/.test(ui.privacy), ui.privacy);
      assertEqual(ui.links[0], 'https://github.com/settings/personal-access-tokens/new', 'where a token is made');
      await page.type('[data-role="mon-gh-repo"]', 'https://github.com/example-org/nightly');
      // no token yet: said at once, no read started, nothing sent, nothing said to have been emptied
      await page.evaluate(() => { window.__gh.calls = []; });
      await page.click('[data-action="mon-gh-load"]');
      const missing = await page.waitFor(() => {
        const el = document.querySelector('[data-role="mon-gh-status"][data-state="error"]');
        return el ? { code: el.dataset.code, text: el.textContent, focus: document.activeElement?.dataset.role || '' } : false;
      }, { message: 'the missing token said' });
      assertEqual([missing.code, missing.focus], ['token', 'mon-gh-token'], 'the token\'s error, the focus on its field');
      assert(missing.text.includes('Paste the token') && !missing.text.includes('emptied'), missing.text);
      assertEqual(await page.evaluate(() => window.__gh.calls.length), 0, 'nothing sent without a token');
      await page.type('[data-role="mon-gh-token"]', TOKEN);
      await page.click('.mon-gh-issue .check-input');
      await page.evaluate(() => { window.__gh.calls = []; });
      await page.click('[data-action="mon-gh-load"]');
      await page.waitFor(() => document.querySelector('[data-role="mon-gh-status"]')?.dataset.state === 'notice', { message: 'read', timeout: 15000 });
      const status = await page.evaluate(() => document.querySelector('[data-role="mon-gh-status"]').textContent);
      assert(status.includes('8 files read from example-org/nightly.') && status.includes('4,990 GitHub API requests left this hour.'), status);
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="mon-gh-token"]').value), '', 'the token field emptied');
      const calls = await page.evaluate(() => window.__gh.calls);
      assertEqual(calls.length, 11, 'two listings, eight files and the issues');
      for (const c of calls) {
        assert(c.url.startsWith('https://api.github.com/repos/example-org/nightly/'), c.url);
        assertEqual([c.tokenOk, c.tokenInUrl, c.credentials, c.redirect, c.referrerPolicy], [true, false, 'omit', 'error', 'no-referrer'], c.url);
      }
      const info = await viewInfo(page);
      assertEqual([info.read, info.stats.all, info.errors], ['Read: 5 reports · 3 months of history · 415 lines', '5', []], 'the repository\'s results, the stray file gone with the old ones');
      const issue = await page.evaluate(() => {
        const a = document.querySelector('a.mon-link-issue');
        return { text: a?.firstChild?.textContent, title: a?.title, href: a?.getAttribute('href') };
      });
      assertEqual(issue, { text: 'Nightly issue #12', title: 'DomainScope: changes since the last nightly run', href: 'https://github.com/example-org/nightly/issues/12' }, 'the open issue');
      assert(!(await keptAnywhere(page)).includes(TOKEN), 'the token is kept nowhere');
      const ledger = await page.evaluate(async () => {
        const { egressLog } = await import('./assets/js/ui/egress-meter.js');
        const { ledgerRows } = await import('./assets/js/lib/egress.js');
        const row = ledgerRows(egressLog.snapshot(), { origin: location.origin }).find((r) => r.serviceId === 'github');
        return row ? { name: row.name, sends: row.sends, requests: row.requests } : null;
      });
      assertEqual(ledger, { name: 'GitHub', sends: ['repository', 'apiToken'], requests: 11 }, 'About › What this page sent');
      await removeToasts(page);
      await shotEl(page, opts, 'monitor-github-desktop-light-en', '.mon-source-card');
    });

    await run.step('a refused token: GitHub\'s 401 in the page\'s words, the field emptied, paste it again', async () => {
      await page.type('[data-role="mon-gh-token"]', `${TOKEN}-wrong`);
      await page.press('Enter');
      const err = await page.waitFor(() => {
        const el = document.querySelector('[data-role="mon-gh-status"][data-state="error"]');
        return el ? { code: el.dataset.code, text: el.textContent } : false;
      }, { message: 'the refusal', timeout: 15000 });
      assertEqual(err.code, 'auth', 'code');
      assert(err.text.includes('GitHub did not accept the token (HTTP 401)') && err.text.includes('GitHub said: “Bad credentials”') && err.text.includes('paste the token again'), err.text);
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="mon-gh-token"]').value), '', 'emptied');
      assertEqual((await viewInfo(page)).stats.all, '5', 'the results read before stay');
      await page.click('.mon-source .seg-btn[data-value="files"]');
    });

    await run.step('Forget, "Delete all local data" and another workspace forget the results', async () => {
      await page.click('[data-action="mon-forget"]');
      await page.waitFor(() => document.querySelector('.mon-page > .empty') && !document.querySelector('.mon-stats'), { message: 'forgotten' });
      await removeToasts(page);
      await choose(page, paths);
      await removeToasts(page);
      await gotoRoute(page, 'about');
      await deleteAllLocalData(page);
      await setLangUi(page, 'en');
      await gotoRoute(page, 'monitor');
      assert((await viewInfo(page)).empty, 'forgotten while another tool was open');
      await choose(page, paths);
      await removeToasts(page);
      const id = await page.evaluate(() => import('./assets/js/state.js').then(async ({ state }) => {
        const { meta } = await state.createWorkspace('Monitor e2e');
        await state.switchWorkspace(meta.id);
        return meta.id;
      }));
      await page.waitFor(() => document.querySelector('.mon-page > .empty') && !document.querySelector('.mon-stats'), { message: 'emptied by the switch' });
      await page.evaluate((wsId) => import('./assets/js/state.js').then(async ({ state }) => {
        await state.switchWorkspace(state.workspaces.find((w) => w.isDefault).id);
        await state.deleteWorkspace(wsId);
      }), id);
      await page.waitFor(() => document.querySelector('.mon-page > .empty'), { message: 'back in Default, still empty' });
    });

    run.group('Languages, themes, phones');
    await run.step('Turkish + dark, 375 px: the tiles, the table as cards and the timeline fit', async () => {
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await gotoRoute(page, 'monitor');
      await choose(page, paths);
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 375, { message: 'phone viewport' });
      await frames(page);
      await removeToasts(page);
      const tr = await page.evaluate(() => ({
        title: document.querySelector('h1')?.textContent,
        read: document.querySelector('[data-role="mon-read"]')?.textContent,
        header: getComputedStyle(document.querySelector('.mon-table thead')).display
      }));
      assertEqual(tr, { title: 'İzleme', read: 'Okunan: 5 rapor · 3 aylık geçmiş · 415 satır', header: 'none' }, 'Turkish, the table as cards');
      await assertNoHorizontalScroll(page, 'monitor phone dark TR');
      assertEqual(await overflowingIn(page, PAGE), [], 'the page inside 375 px');
      await shotPage(page, opts, 'monitor-results-phone-dark-tr');
      await shotEl(page, opts, 'monitor-table-phone-dark-tr', '.mon-table');
    });

    await run.step('320 px, English, light: still no horizontal scroll; the GitHub form fits', async () => {
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport({ width: 320, height: 720, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 320 && document.querySelector('.mon-stats'), { message: '320 px' });
      await frames(page);
      await removeToasts(page);
      await assertNoHorizontalScroll(page, 'monitor 320 light EN');
      assertEqual(await overflowingIn(page, PAGE), [], 'the page inside 320 px');
      await shotPage(page, opts, 'monitor-results-phone-light-en');
      await page.click('.mon-source .seg-btn[data-value="github"]');
      await page.waitForSelector('[data-role="mon-gh-repo"]');
      await assertNoHorizontalScroll(page, 'monitor GitHub form 320');
      assertEqual(await overflowingIn(page, '.mon-source-card'), [], 'the GitHub form inside 320 px');
      await shotEl(page, opts, 'monitor-github-phone-light-en', '.mon-source-card');
      await page.click('.mon-source .seg-btn[data-value="files"]');
    });

    await run.step('desktop dark, Turkish', async () => {
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.waitFor(() => document.querySelector('.mon-stats'), { message: 'stats' });
      await frames(page);
      await assertNoHorizontalScroll(page, 'monitor desktop dark TR');
      await removeToasts(page);
      await shotPage(page, opts, 'monitor-results-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Quality');
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations; nothing sent to the network', async () => {
      await assertClean(page, 'monitor', origin);
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
