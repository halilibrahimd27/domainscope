#!/usr/bin/env node
/**
 * watch.e2e.mjs — end-to-end test of the page template (ui/template.js, lib/template.js;
 * docs/DESIGN.md §5 and §8 phase 6) on the three tools of "Watch & report": Domain portfolio (a
 * "Batch" tool with tabs that are tools of their own), Monitoring and DMARC & TLS reports (two
 * "File" tools), in a real headless Chrome/Edge. OFFLINE: the portfolio's DNS, RDAP and CT are
 * answered inside the page (portfolio.e2e.mjs fakeScript; the reports' SPF lookups too), the
 * Monitoring results are tests/js/monitor-fixture.mjs written to a temporary folder (its page on a
 * clock pinned to the fixture's night), the reports tests/fixtures/mailreports; a network-level
 * guard fails and records any https request that would still go out — the suite asserts none.
 *
 *   node tests/e2e/watch.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - the empty template of each tool: Domain portfolio's input card (role search) with its list,
 *     Run on the list's row (primary) and the privacy note; the file input of Monitoring and of the
 *     reports (a drop zone, Choose files the primary button, the privacy note in its footer), no
 *     Run; the empty state with the chips of what each tool checks; no result header;
 *   - Domain portfolio: a check folds the input (the list two lines high, Edit unfolds the DKIM
 *     option and folds it again), the result header starts high, Run reads "Run again" and is
 *     secondary while the list and the option ask for the check on screen; the status summary
 *     filters the Domains table (pressed again: every domain; the Show select follows it and it the
 *     select); the metric strip is read-only; the actions in order — Copy summary with ¶, Export ▾
 *     (CSV, JSON, the calendar), Copy link —, Esc closes the menu on its button, Copy link copies
 *     the check's own link; the CT tab leads with its own Check CT (Run steps back to secondary
 *     while it is open), its own privacy note and quota line, and sends nothing before its click;
 *     the kept-result note in the result header after a visit elsewhere;
 *   - Monitoring: the source card folds to one row (what was read, Add files, the folder picker,
 *     Forget); the result header (the targets and the last check, the status summary that filters
 *     the Targets tab, Copy summary with ¶ and its one file as a plain Export button, no Copy link,
 *     the links); the Changes tab counts what it shows;
 *   - DMARC & TLS reports: the file input folds to one row (the files read, Add reports, Choose a
 *     folder, Forget reports) and keeps its switch; the result header (Copy summary with ¶, Report,
 *     Print, no Copy link); a status item opens the tab that lists what it counts; the kept note in
 *     the result header;
 *   - a tool that is left takes back its phone-layout listeners (its run bar's and its actions');
 *   - phones: at 375×812 (Turkish, dark) only Copy summary stays in the row and the rest is behind
 *     "⋯", in Turkish words; at 320 px no horizontal scroll on the three tools, empty or with a result;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; nothing sent.
 */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { pinnedClockScript } from './clock.mjs';
import { orderSuites } from './run-all.mjs';
import { fakeScript as portfolioFakes } from './portfolio.e2e.mjs';
import { monitorFixture, MONITOR_NOW } from '../js/monitor-fixture.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner, gotoRoute,
  installDownloadCapture, openResultMenu, resultAction, setLangUi, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';

const DOMAINS = ['example.com', 'example.org', 'example-test.com.tr'];
const MAILBOX = path.join(FIXTURES, 'mailreports', 'reports-2026-09.zip');
const STAMP = /\d{8}-\d{4}/;
/** Each tool: its result header's hook. */
const HEADS = { portfolio: '.pf-head', monitor: '.mon-summary', reports: '.rpt-results-head' };

/**
 * Counts the 'change' listeners on the phone layout's media query (lib/template.js PHONE_MAX_WIDTH):
 * the run bar and the actions of a tool add one each, and a tool that is left must take them back
 * (a MediaQueryList with a listener keeps the page it drew alive).
 */
const PHONE_LISTENERS = `(() => {
  const real = window.matchMedia.bind(window);
  window.__phoneListeners = 0;
  window.matchMedia = (query) => {
    const mql = real(query);
    if (!/max-width:\\s*719px/.test(query)) return mql;
    const add = mql.addEventListener.bind(mql);
    const remove = mql.removeEventListener.bind(mql);
    const live = new Set();
    mql.addEventListener = (type, fn, opts) => {
      if (type === 'change' && !live.has(fn)) { live.add(fn); window.__phoneListeners += 1; }
      return add(type, fn, opts);
    };
    mql.removeEventListener = (type, fn, opts) => {
      if (type === 'change' && live.delete(fn)) window.__phoneListeners -= 1;
      return remove(type, fn, opts);
    };
    return mql;
  };
})();`;

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

/** A page with the given scripts before the app, the phone listeners counted, downloads captured, the network guarded. */
async function openPage(browser, server, viewport, scripts) {
  const page = await browser.newPage('about:blank', viewport);
  const hits = await networkGuard(page);
  for (const source of [...scripts, PHONE_LISTENERS]) await page.send('Page.addScriptToEvaluateOnNewDocument', { source });
  await installDownloadCapture(page);
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  return { page, hits };
}

const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
/** The page in front: a tab in the background gets no animation frame (the routes and the tables wait for one). */
const front = (page) => page.send('Page.bringToFront');
const removeToasts = (page) => page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));

/** The input card of the view on screen: its role, the compact state, the field, Run, the privacy note, the empty state, the result header. */
const templateInfo = (page, head) => page.evaluate((sel) => {
  const card = document.querySelector('#page-body .tool-input');
  const run = card?.querySelector('.tool-input-fields > .run-bar .run-bar-run');
  const field = card?.querySelector('.tool-input-primary [data-shortcut="focus"]');
  const top = (el) => (el ? Math.round(el.getBoundingClientRect().top + window.scrollY) : null);
  const resultHead = document.querySelector(sel);
  return {
    cards: document.querySelectorAll('#page-body .tool-input').length,
    file: !!card?.classList.contains('file-input'),
    role: card?.getAttribute('role') || null,
    compact: !!card?.classList.contains('is-compact'),
    editing: !!card?.classList.contains('is-editing'),
    field: !!field,
    run: run ? { label: run.querySelector('.btn-label').textContent, primary: run.classList.contains('btn-primary'), shortcut: run.dataset.shortcut || null, sameRow: Math.abs(top(run) - top(field)) <= 1 } : null,
    privacy: !!card?.querySelector('.tool-input-foot .privacy-note'),
    empty: !!document.querySelector('#page-body .tool-empty'),
    checks: document.querySelectorAll('#page-body .tool-empty-check').length,
    head: resultHead && resultHead.isConnected ? { top: top(resultHead) } : null
  };
}, head);

/** The result header's actions row, by kind, in order. */
const actionsRow = (page, head) => page.evaluate((sel) => [...document.querySelectorAll(`${sel} .result-actions > *`)].map((el) => {
  if (el.classList.contains('sum-actions')) return el.querySelector('[data-action="copy-summary-text"]:not([hidden])') ? 'summary+plain' : 'summary';
  if (el.classList.contains('menu-wrap')) return `menu:${el.querySelector('.menu-button').dataset.menu}`;
  return el.dataset.action || el.dataset.export || el.tagName.toLowerCase();
}), head);

/** The status summary of a result header: each item's key, severity, kind (toggle / button / fact) and pressed state. */
const statusOf = (page, head) => page.evaluate((sel) => [...document.querySelectorAll(`${sel} .status-item`)].map((b) => ({
  key: b.dataset.status,
  severity: b.dataset.severity,
  kind: b.tagName !== 'BUTTON' ? 'fact' : b.hasAttribute('aria-pressed') ? 'toggle' : 'button',
  pressed: b.getAttribute('aria-pressed') === 'true'
})), head);

/** The visible primary buttons of the page body (one at a time, DESIGN §5.1). */
const primaries = (page) => page.evaluate(() => [...document.querySelectorAll('#page-body .btn-primary')].filter((b) => b.checkVisibility())
  .map((b) => b.dataset.action || b.textContent.trim()));

/** Each kept-result note on the page: the result header it sits in, shown or not. */
const keptNotes = (page) => page.evaluate((heads) => [...document.querySelectorAll('.kept-note')].map((n) => ({
  head: heads.find((c) => n.closest(c)) || null,
  shown: n.checkVisibility(),
  text: n.querySelector('.kept-note-text')?.textContent || '',
  rerun: !!n.querySelector('[data-action="kept-rerun"]')
})), Object.values(HEADS));

/** Domain portfolio's check is done and its rows filled. */
const portfolioDone = (page, message = 'portfolio checked') => page.waitFor(() => !!document.querySelector('.pf-head[data-status="done"], .pf-head[data-status="stopped"]')
  && !document.querySelector('[data-action="pf-run"]').hidden && !document.querySelector('.pf-pending'), { timeout: 40000, message });
const pfRows = (page) => page.evaluate(() => [...document.querySelectorAll('.pf-table tbody tr.dt-row .pf-domain')].map((d) => d.textContent));

/** The reports are read and the DMARC tab's sources classified. */
const reportsDone = (page) => page.waitFor(() => /^Reports for/.test(document.querySelector('.rpt-results-title')?.textContent || '')
  && document.querySelectorAll('.rpt-sources tbody tr.dt-row').length > 0 && document.querySelector('.rpt-spf')?.dataset.state !== 'loading'
  && !document.querySelector('[data-role="rpt-busy"]'), { timeout: 30000, message: 'the reports read' });

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const shot = async (page, name) => {
    if (!opts.shots) return;
    await removeToasts(page);
    await mkdir(opts.shotsDir, { recursive: true });
    await page.screenshot(path.join(opts.shotsDir, `${name}.png`), { fullPage: true });
  };

  run.group('Node: harness');
  await run.step('run-all orders the Watch & report template suite right after the Investigate one, before the tools\' own suites', () => {
    assertEqual(orderSuites(['portfolio.e2e.mjs', 'watch.e2e.mjs', 'investigate.e2e.mjs', 'home.e2e.mjs']), ['home', 'investigate', 'watch', 'portfolio'], 'order');
  });

  // The Monitoring results folder (made up, documentation names only).
  const fx = monitorFixture();
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-watch-e2e-'));
  const folder = path.join(tmp, 'results');
  await mkdir(path.join(folder, 'history'), { recursive: true });
  const monitorFiles = [];
  for (const f of fx.files) {
    const rel = /\.jsonl$/.test(f.name) ? `history/${f.name}` : f.name;
    await writeFile(path.join(folder, ...rel.split('/')), f.text);
    monitorFiles.push(path.join(folder, ...rel.split('/')));
  }

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: DNS, RDAP and CT answered in the page, the results and the reports from files\n`);
  const pages = [];
  try {
    // Domain portfolio and the reports: the real clock (the fakes' dates are relative to it).
    const desk = await openPage(browser, server, { width: 1440, height: 900 }, [portfolioFakes()]);
    pages.push({ ...desk, where: 'desktop' });
    const { page } = desk;
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await setLangUi(page, 'en');
    // Monitoring: the fixture's night (its 7-day window and the days left are counted from it).
    const mon = await openPage(browser, server, { width: 1440, height: 900 }, [pinnedClockScript(MONITOR_NOW)]);
    pages.push({ ...mon, where: 'monitoring' });
    const mpage = mon.page;
    await mpage.emulateMedia({ 'prefers-color-scheme': 'light' });
    await setLangUi(mpage, 'en');

    run.group('The empty template (desktop 1440×900, English, light)');
    await run.step('Domain portfolio: one input card with the list, Run on its row and the privacy note; the empty state with its chips; no result header', async () => {
      await front(page);
      await gotoRoute(page, '#/portfolio');
      const info = await templateInfo(page, HEADS.portfolio);
      assertEqual([info.cards, info.file, info.role, info.compact, info.field, info.privacy, info.empty, info.head], [1, false, 'search', false, true, true, true, null],
        'the input card and the empty state');
      assert(info.run && info.run.primary && info.run.shortcut === 'submit' && info.run.sameRow && info.run.label === 'Check portfolio', `Run: ${JSON.stringify(info.run)}`);
      assert(info.checks >= 6, `the chips of what it checks (${info.checks})`);
      assertEqual(await page.evaluate(() => document.querySelector('.pf-form-card .privacy-note-link')?.dataset.view), 'about', 'the rest of what is sent, one click away');
      await assertNoHorizontalScroll(page, 'portfolio empty');
      await shot(page, 'watch-portfolio-empty-desktop-light-en');
    });

    await run.step('Monitoring and the reports: a file input (the drop zone, Choose files primary, the privacy note), no Run; the empty state; no result header', async () => {
      for (const [p, id, choose] of [[mpage, 'monitor', 'mon-choose'], [page, 'reports', 'rpt-choose']]) {
        await front(p);
        await gotoRoute(p, `#/${id}`);
        const info = await templateInfo(p, HEADS[id]);
        assertEqual([info.cards, info.file, info.compact, info.run, info.privacy, info.empty, info.head], [1, true, false, null, true, true, null], `${id}: the file input and the empty state`);
        assert(info.checks >= 4, `${id}: the chips of what it checks (${info.checks})`);
        const card = await p.evaluate((action) => ({
          drop: !!document.querySelector('#page-body .tool-input .filedrop[data-shortcut="focus"]'),
          primaries: [...document.querySelectorAll('#page-body .btn-primary')].filter((b) => b.checkVisibility()).map((b) => b.dataset.action),
          choose: !!document.querySelector(`[data-action="${action}"]`)
        }), choose);
        assertEqual(card, { drop: true, primaries: [choose], choose: true }, `${id}: the drop zone ('/' focuses it), Choose files the one primary button`);
        await assertNoHorizontalScroll(p, `${id} empty`);
      }
      await shot(page, 'watch-reports-empty-desktop-light-en');
    });

    run.group('Domain portfolio (desktop)');
    await run.step('a check: the input folds (the list two lines high), the result header starts high, Run reads "Run again" until the list changes', async () => {
      await front(page);
      await gotoRoute(page, `#/portfolio?domains=${DOMAINS.join(',')}`);
      await page.waitFor(() => !!document.querySelector('.pf-prompt [data-prompt="link"]'), { message: 'the link prompt' });
      assertEqual(await primaries(page), ['pf-run'], 'one primary button: Check portfolio (the prompt says to press it)');
      await page.click('[data-action="pf-run"]');
      await portfolioDone(page);
      const info = await templateInfo(page, HEADS.portfolio);
      assert(info.compact && !info.editing, 'compact');
      assert(info.head && info.head.top < 400, `the result header near the top: ${JSON.stringify(info.head)}`);
      assertEqual([info.run.label, info.run.primary, info.run.sameRow], ['Run again', false, true], 'Run again, secondary, on the list\'s row');
      const box = await page.evaluate(() => Math.round(document.querySelector('[data-role="pf-domains"]').getBoundingClientRect().height));
      assert(box <= 64, `the list two lines high: ${box} px`);
      assertEqual(await page.evaluate(() => !!document.querySelector('.pf-prompt-slot:not([hidden])')), false, 'the prompt gone once the check is on screen');
      await page.type('[data-role="pf-domains"]', `${DOMAINS.join('\n')}\nexample.net`);
      assertEqual(await page.evaluate(() => [document.querySelector('[data-action="pf-run"] .btn-label').textContent, document.querySelector('[data-action="pf-run"]').classList.contains('btn-primary')]),
        ['Check portfolio', true], 'another list: the verb, primary');
      await page.type('[data-role="pf-domains"]', DOMAINS.join('\n'));
      assertEqual((await templateInfo(page, HEADS.portfolio)).run.label, 'Run again', 'the check\'s list again');
      await shot(page, 'watch-portfolio-result-desktop-light-en');
    });

    await run.step('Edit unfolds the DKIM option (aria-expanded) and folds it again; turning DKIM off makes Run the verb, the summary line says so', async () => {
      const edit = '.pf-form-card [data-action="tool-input-edit"]';
      const state = () => page.evaluate((sel) => ({
        expanded: document.querySelector(sel).getAttribute('aria-expanded'),
        dkim: document.querySelector('.pf-dkim')?.checkVisibility() || false,
        summary: document.querySelector('.pf-form-card .tool-input-summary-text')?.textContent || ''
      }), edit);
      assertEqual(await state(), { expanded: 'false', dkim: false, summary: '' }, 'folded; every option at its default');
      await page.click(edit);
      assertEqual((await state()).expanded, 'true', 'unfolded');
      assert((await state()).dkim, 'the DKIM option shows');
      await page.click('.pf-dkim .check-input');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-action="pf-run"] .btn-label').textContent, document.querySelector('[data-action="pf-run"]').classList.contains('btn-primary')]),
        ['Check portfolio', true], 'DKIM off: another check, primary');
      assertEqual((await state()).summary, 'DKIM not checked', 'the option off its default, in the summary line');
      await page.click('.pf-dkim .check-input');
      assertEqual((await templateInfo(page, HEADS.portfolio)).run.label, 'Run again', 'back as the check had it');
      await page.click(edit);
      assertEqual(await state(), { expanded: 'false', dkim: false, summary: '' }, 'folded again');
    });

    await run.step('the status summary filters the Domains table, a second press shows every domain; the Show select follows; the metric strip is read-only', async () => {
      const items = await statusOf(page, HEADS.portfolio);
      assertEqual(items.map((x) => [x.key, x.severity, x.kind, x.pressed]), [
        ['expiring', 'error', 'toggle', false], ['unlocked', 'warn', 'toggle', false], ['ns', 'warn', 'toggle', false]
      ], 'errors first, then warnings; zeros left out');
      await page.click('.pf-head .status-item[data-status="unlocked"]');
      assertEqual(await pfRows(page), ['example.org'], 'no transfer lock');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="pf-filter"]').value, document.activeElement?.dataset.status]), ['unlocked', 'unlocked'],
        'the select follows; the focus stays on the item');
      await page.click('.pf-head .status-item[data-status="unlocked"]');
      assertEqual((await pfRows(page)).length, 3, 'every domain again');
      await page.evaluate(() => { const s = document.querySelector('[data-role="pf-filter"]'); s.value = 'expiring'; s.dispatchEvent(new Event('change', { bubbles: true })); });
      assertEqual((await statusOf(page, HEADS.portfolio)).filter((x) => x.pressed).map((x) => x.key), ['expiring'], 'the select\'s filter pressed in the summary');
      await page.evaluate(() => { const s = document.querySelector('[data-role="pf-filter"]'); s.value = 'all'; s.dispatchEvent(new Event('change', { bubbles: true })); });
      const strip = await page.evaluate(() => ({
        metrics: [...document.querySelectorAll('.pf-tiles .metric')].map((m) => m.dataset.metric),
        controls: document.querySelectorAll('.pf-tiles button, .pf-tiles a, .pf-tiles [tabindex]').length,
        zero: document.querySelector('.pf-tiles .metric-zero')?.textContent || ''
      }));
      assertEqual([strip.metrics, strip.controls], [['domains', 'expiring', 'unlocked', 'ns'], 0], 'read-only figures');
      assert(/^None: /.test(strip.zero) && /Critical status/.test(strip.zero), `the zeros in one sentence: ${strip.zero}`);
    });

    await run.step('the actions in order: Copy summary with ¶, Export ▾ (CSV, JSON, the calendar), Copy link; Esc closes the menu on its button; Copy link copies the check\'s link', async () => {
      assertEqual(await actionsRow(page, HEADS.portfolio), ['summary+plain', 'menu:export', 'copy-link'], 'Copy summary + ¶, Export ▾, Copy link');
      assertEqual(await openResultMenu(page, 'export', HEADS.portfolio), ['CSV', 'JSON', 'Calendar (.ics)'], 'the three files');
      await page.press('Escape');
      await page.waitFor(() => document.querySelector('.pf-head [data-menu="export"]').getAttribute('aria-expanded') === 'false'
        && document.activeElement === document.querySelector('.pf-head [data-menu="export"]'), { message: 'closed, the focus on Export' });
      await takeDownloads(page);
      await resultAction(page, '[data-action="pf-ics"]', HEADS.portfolio);
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the calendar' });
      const [ics] = await takeDownloads(page);
      assertEqual(ics.name.replace(STAMP, 'STAMP'), 'domain-expiry-3-domains-STAMP.ics', 'the calendar file');
      await stubClipboard(page);
      await resultAction(page, '[data-action="copy-link"]', HEADS.portfolio);
      await page.waitFor(() => window.__clip.length === 1, { message: 'Copy link' });
      const [link] = await takeClipboard(page);
      assert(/#\/portfolio\?domains=example\.com(%2C|,)example\.org(%2C|,)example-test\.com\.tr$/.test(link), `the check's own link: ${link}`);
      assertEqual(await page.evaluate(() => !!document.querySelector('#page-actions [data-action="copy-link"], .page-actions .btn')), false, 'no Copy link left in the page header');
    });

    await run.step('the CT tab leads with its own Check CT: Run steps back to secondary while it is open; its privacy note and quota line; nothing sent', async () => {
      await page.type('[data-role="pf-domains"]', `${DOMAINS.join('\n')}\nexample.net`);
      assertEqual(await primaries(page), ['pf-run'], 'another list: Check portfolio leads');
      await page.click('.pf-results .tab[data-tab="ct"]');
      await page.waitFor(() => !!document.querySelector('[data-action="ct-run"]'), { message: 'the CT panel' });
      assertEqual(await primaries(page), ['ct-run'], 'the CT tab open: Check CT leads, one primary button');
      const ct = await page.evaluate(() => ({
        privacy: document.querySelector('.pf-ct-form .privacy-note')?.textContent || '',
        quota: document.querySelector('[data-role="ct-quota"]')?.textContent || '',
        run: document.querySelector('.pf-ct-run [data-action="ct-run"]')?.classList.contains('run-bar-run') || false,
        sent: window.__ctLog.length
      }));
      assert(/^Nothing is sent until you press Check CT/.test(ct.privacy), ct.privacy);
      assert(/^Cert Spotter: 0 of 10 /.test(ct.quota), ct.quota);
      assertEqual([ct.run, ct.sent], [true, 0], 'its run in a run slot of its own; nothing sent');
      await page.click('.pf-results .tab[data-tab="domains"]');
      assertEqual(await primaries(page), ['pf-run'], 'the Domains tab again: Check portfolio leads');
      await page.type('[data-role="pf-domains"]', DOMAINS.join('\n'));
    });

    await run.step('the kept result: back through the navigation, the note sits in the result header, once', async () => {
      await gotoRoute(page, '#/about');
      await page.click('a.nav-link[data-view="portfolio"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'portfolio' && !!document.querySelector('.pf-head .page-kept:not([hidden]) .kept-note'), { message: 'the kept note' });
      const notes = await keptNotes(page);
      assertEqual(notes.map(({ head, shown, rerun }) => ({ head, shown, rerun })), [{ head: '.pf-head', shown: true, rerun: true }], `one note, in the head: ${JSON.stringify(notes)}`);
      assert(/^Result from /.test(notes[0].text), notes[0].text);
    });

    run.group('Monitoring (desktop; the fixture\'s night)');
    await run.step('the results folder: the source card folds to one row; the result header with its status summary, its one file and no Copy link', async () => {
      await front(mpage);
      await gotoRoute(mpage, 'monitor');
      await mpage.setFileInput('.mon-page .mon-drop .filedrop-input', monitorFiles);
      await mpage.waitFor(() => document.querySelectorAll('.mon-table tbody tr.dt-row').length === 5, { message: 'five rows', timeout: 15000 });
      await frames(mpage);
      const card = await mpage.evaluate(() => {
        const c = document.querySelector('.mon-source-card');
        return {
          compact: c.classList.contains('is-compact'),
          row: [...c.querySelectorAll('.file-input-row .file-input-actions > *')].map((el) => el.dataset.action || (el.classList.contains('filedrop') ? `drop:${el.querySelector('.filedrop-title').textContent}` : el.tagName)),
          read: c.querySelector('.file-input-summary [data-role="mon-read"]')?.textContent || '',
          choose: !!c.querySelector('[data-action="mon-choose"]'),
          privacy: !!c.querySelector('.tool-input-foot .privacy-note')
        };
      });
      assertEqual(card, { compact: true, row: ['drop:Add files', 'mon-folder', 'mon-forget'], read: 'Read: 5 reports · 3 months of history · 415 lines', choose: false, privacy: true },
        'one row: what was read, Add files, the folder, Forget; the privacy note stays');
      const info = await templateInfo(mpage, HEADS.monitor);
      assert(info.head && info.head.top < 400, `the result header near the top: ${JSON.stringify(info.head)}`);
      assertEqual(await mpage.evaluate(() => document.querySelector('.mon-summary .result-title').textContent), 'Nightly results · 5 targets', 'the title');
      assertEqual(await actionsRow(mpage, HEADS.monitor), ['summary+plain', 'mon-csv'], 'Copy summary + ¶ and one file, no Copy link');
      assertEqual(await mpage.evaluate(() => document.querySelector('.mon-summary [data-action="mon-csv"]').textContent.trim()), 'Export', 'a plain Export button');
      assertEqual((await statusOf(mpage, HEADS.monitor)).map((x) => [x.key, x.severity, x.kind]), [
        ['bad', 'error', 'toggle'], ['expiring', 'warn', 'toggle'], ['incomplete', 'warn', 'toggle'], ['targets', 'neutral', 'button']
      ], 'the counts: three filters and the targets');
      await mpage.click('.mon-summary .status-item[data-status="bad"]');
      await mpage.waitFor(() => document.querySelectorAll('.mon-table tbody tr.dt-row').length === 3, { message: 'the targets with bad changes' });
      await mpage.click('.mon-summary .status-item[data-status="bad"]');
      await mpage.waitFor(() => document.querySelectorAll('.mon-table tbody tr.dt-row').length === 5, { message: 'every target again' });
      assertEqual(await mpage.evaluate(() => [...document.querySelectorAll('.mon-tabs .tab')].map((b) => `${b.dataset.tab} ${b.querySelector('.tab-badge').textContent}`)),
        ['targets 5', 'changes 8'], 'the tabs and what they count');
      await takeDownloads(mpage);
      await mpage.click('.mon-summary [data-action="mon-csv"]');
      await mpage.waitFor(() => (window.__downloads || []).length === 1, { message: 'the CSV' });
      assertEqual((await takeDownloads(mpage)).map((f) => f.name.replace(STAMP, 'STAMP')), ['monitor-changes-STAMP.csv'], 'the changes, as the Changes tab shows them');
      await shot(mpage, 'watch-monitor-result-desktop-light-en');
    });

    run.group('DMARC & TLS reports (desktop)');
    await run.step('a dropped zip: the file input folds to one row and keeps its switch; the result header (Copy summary with ¶, Report, Print; no Copy link)', async () => {
      await front(page);
      await gotoRoute(page, 'reports');
      await page.setFileInput('.rpt-load .filedrop-input', [MAILBOX]);
      await reportsDone(page);
      const card = await page.evaluate(() => {
        const c = document.querySelector('.rpt-load');
        return {
          compact: c.classList.contains('is-compact'),
          row: [...c.querySelectorAll('.file-input-row .file-input-actions > *')].map((el) => el.dataset.action || (el.classList.contains('filedrop') ? `drop:${el.querySelector('.filedrop-title').textContent}` : el.tagName)),
          files: c.querySelector('.file-input-summary [data-role="rpt-files"]')?.textContent || '',
          keep: !!c.querySelector('[data-role="rpt-keep"]'),
          privacy: !!c.querySelector('.tool-input-foot .privacy-note')
        };
      });
      assertEqual(card, {
        compact: true, row: ['drop:Add reports', 'rpt-folder', 'rpt-forget'], files: '1 file · 3 DMARC reports · 2 TLS reports · 1 could not be used', keep: true, privacy: true
      }, 'one row: the files read, Add reports, the folder, Forget; the switch and the privacy note stay');
      const info = await templateInfo(page, HEADS.reports);
      assert(info.head && info.head.top < 420, `the result header near the top: ${JSON.stringify(info.head)}`);
      assertEqual(await actionsRow(page, HEADS.reports), ['summary+plain', 'report', 'print'], 'Copy summary + ¶, Report, Print; no Copy link');
      assertEqual(await page.evaluate(() => document.querySelector('.rpt-results-head [data-action="print"]').textContent.trim()), 'Print / save as PDF', 'Print, a plain button');
      await shot(page, 'watch-reports-result-desktop-light-en');
    });

    await run.step('the status summary: what fails first; an item opens the tab that lists what it counts', async () => {
      assertEqual((await statusOf(page, HEADS.reports)).map((x) => [x.key, x.severity, x.kind]), [
        ['failing', 'error', 'button'], ['tlsFailed', 'error', 'button'], ['messages', 'neutral', 'button'], ['senders', 'neutral', 'button'], ['sessions', 'neutral', 'button']
      ], 'the reports in numbers');
      const selected = () => page.evaluate(() => document.querySelector('.rpt-tabs .tab[aria-selected="true"]')?.dataset.tab);
      assertEqual(await selected(), 'dmarc', 'the DMARC tab first');
      await page.click('.rpt-results-head .status-item[data-status="tlsFailed"]');
      await page.waitFor(() => document.querySelector('.rpt-tabs .tab[aria-selected="true"]')?.dataset.tab === 'tls', { message: 'the TLS-RPT tab' });
      await page.click('.rpt-results-head .status-item[data-status="senders"]');
      assertEqual(await selected(), 'dmarc', 'the DMARC tab again');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.rpt-tabs .tab .icon').length), 0, 'the tabs: text and a count, no icons');
    });

    await run.step('the kept reports: back through the navigation, the note sits in the result header', async () => {
      await gotoRoute(page, '#/about');
      await page.click('a.nav-link[data-view="reports"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'reports' && !!document.querySelector('.rpt-results-head .page-kept:not([hidden]) .kept-note'), { message: 'the kept note' });
      const notes = await keptNotes(page);
      assertEqual(notes.map(({ head, shown, rerun }) => ({ head, shown, rerun })), [{ head: '.rpt-results-head', shown: true, rerun: false }], `one note, in the head: ${JSON.stringify(notes)}`);
      assert(/^Reports read at /.test(notes[0].text), notes[0].text);
    });

    await run.step('a tool that is left takes back its phone-layout listeners (its run bar\'s and its actions\'): nothing keeps its page alive', async () => {
      for (const [p, id, min] of [[page, 'portfolio', 2], [page, 'reports', 1], [mpage, 'monitor', 1]]) {
        await front(p);
        await gotoRoute(p, '#/about');
        const base = await p.evaluate(() => window.__phoneListeners);
        await gotoRoute(p, `#/${id}`);
        await p.waitFor((sel) => !!document.querySelector(`${sel} .result-actions`), { args: [HEADS[id]], timeout: 10000, message: `${id}: the kept result` });
        const on = await p.evaluate(() => window.__phoneListeners);
        assert(on >= base + min, `${id}: it follows the phone layout (${base} → ${on})`);
        await gotoRoute(p, '#/about');
        assertEqual(await p.evaluate(() => window.__phoneListeners), base, `${id}: none left once it is left`);
      }
    });

    run.group('Phones');
    await run.step('375×812 (Turkish, dark): Copy summary alone in the row, the rest behind "⋯", in Turkish words', async () => {
      for (const p of [page, mpage]) {
        await front(p);
        await p.setViewport({ width: 375, height: 812, mobile: true });
        await p.emulateMedia({ 'prefers-color-scheme': 'dark' });
        await setLangUi(p, 'tr');
      }
      const more = { portfolio: ['Düz metin olarak kopyala', 'CSV', 'JSON', 'Takvim (.ics)', 'Bağlantıyı kopyala'], reports: ['Düz metin olarak kopyala', 'Rapor', 'Yazdır / PDF olarak kaydet'],
        monitor: ['Düz metin olarak kopyala', 'Dışa aktar'] };
      for (const [p, id] of [[page, 'portfolio'], [page, 'reports'], [mpage, 'monitor']]) {
        await front(p);
        await gotoRoute(p, `#/${id}`);
        await p.waitFor((sel) => !!document.querySelector(`${sel} .result-actions`), { args: [HEADS[id]], timeout: 10000, message: `${id}: the kept result` });
        assertEqual(await actionsRow(p, HEADS[id]), ['summary', 'menu:more'], `${id}: Copy summary, ⋯`);
        assertEqual(await openResultMenu(p, 'more', HEADS[id]), more[id], `${id}: the rest, in order`);
        await p.press('Escape');
        await assertNoHorizontalScroll(p, `${id} 375 tr dark`);
        await shot(p, `watch-${id}-result-375-dark-tr`);
      }
      assertEqual(await page.evaluate(() => document.querySelector('.rpt-results-head .result-title').textContent), '2 alan adının raporları', 'the reports\' title in Turkish');
    });

    await run.step('320 px (English, light): no horizontal scroll on the three tools, empty or with a result', async () => {
      for (const p of [page, mpage]) {
        await front(p);
        await p.setViewport({ width: 320, height: 700, mobile: true });
        await p.emulateMedia({ 'prefers-color-scheme': 'light' });
        await setLangUi(p, 'en');
      }
      for (const [p, id] of [[page, 'portfolio'], [page, 'reports'], [mpage, 'monitor']]) {
        await front(p);
        await gotoRoute(p, `#/${id}`);
        await p.waitFor((sel) => !!document.querySelector(`${sel} .result-actions`), { args: [HEADS[id]], timeout: 10000, message: `${id}: the kept result` });
        await frames(p);
        await assertNoHorizontalScroll(p, `${id} 320 result`);
      }
      await shot(mpage, 'watch-monitor-result-320-light-en');
      // the empty templates, in a fresh page
      const fresh = await openPage(browser, server, { width: 320, height: 700, mobile: true }, [portfolioFakes()]);
      pages.push({ ...fresh, where: 'phone 320' });
      await fresh.page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(fresh.page, 'en');
      for (const id of ['portfolio', 'monitor', 'reports']) {
        await gotoRoute(fresh.page, `#/${id}`);
        await assertNoHorizontalScroll(fresh.page, `${id} 320 empty`);
      }
      await shot(fresh.page, 'watch-reports-empty-320-light-en');
    });

    await run.step('no missing keys; no console errors, exceptions or CSP violations; nothing sent', async () => {
      for (const p of pages) {
        await assertNoMissingKeys(p.page);
        await assertClean(p.page, p.where, origin);
      }
      assertEqual(pages.map((p) => p.hits), pages.map(() => []), 'no request reached the network');
    });
  } finally {
    for (const p of pages) await p.page.close().catch(() => {});
    await browser.close();
    await server.close();
    await rm(tmp, { recursive: true, force: true });
  }
  run.finish();
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stdout.write(`\n${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  });
}
export { main };
