#!/usr/bin/env node
/**
 * investigate.e2e.mjs — end-to-end test of the page template (ui/template.js, lib/template.js;
 * docs/DESIGN.md §5 and §8 phase 2) on the four tools of "Investigate a domain": Domain overview,
 * Domain Health, Subdomains and DNS Lookup, in a real headless Chrome/Edge. OFFLINE: the DNS of
 * example.com is answered inside the page (scan.e2e.mjs zoneHandoffScript), every other request
 * that leaves the page fails there, and a network-level guard fails and records any https request
 * that would still go out — the suite asserts none.
 *
 *   node tests/e2e/investigate.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - the empty template of each tool: one input card (`.tool-input`, role search) with the primary
 *     field, Run (primary, on the field's row) and the privacy note; the empty state with the chips
 *     of what the tool checks; no result header; an example chip fills the box and runs nothing;
 *   - a run (Domain Health): the input turns compact (the field, the summary line with Edit, Run),
 *     Edit unfolds the rest (aria-expanded) and folds it again; the result header starts above
 *     300 px at 1440×900; Run reads "Run again" and is secondary while the box asks for the report
 *     on screen, primary again once the box changes;
 *   - the status summary: a toggle per severity that filters the checks, a second press shows them
 *     all again;
 *   - the standard actions in order (Copy summary with ¶, Report, Export, Copy link): Export ▾ is
 *     a menu button whose items download the files (Print last), Esc closes it with the focus back
 *     on the button; one file is a plain Export button (DNS Lookup's dig file); Copy link copies the
 *     result's own link; the next steps and "Also check:";
 *   - the kept result: leaving the view and coming back through the navigation shows the note
 *     ("Result from …") inside the result header, once;
 *   - a shared link's ready prompt leads (Subdomains: Run steps back to secondary until Start);
 *     the metric strip is read-only;
 *   - phones: at 375×812 (Turkish, dark) only Copy summary stays in the row and the rest is behind
 *     "⋯" (Copy link from there), in Turkish words; the floating run bar shows while the inline
 *     Run is out of view, keeps a focused field clear of it and runs the tool; 320 px: no
 *     horizontal scroll on the four tools, empty or with a result;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; nothing sent.
 */

import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner, gotoRoute,
  installDownloadCapture, openResultMenu, resultAction, setLangUi, sleep, stubClipboard, takeClipboard, takeDownloads, waitReady,
  zoneHandoffScript
} from './scan.e2e.mjs';

const APEX = 'example.com';
/** The DNS of example.com, answered in the page (documentation addresses only). */
const ZONE = {
  'example.com': {
    A: ['203.0.113.10'],
    AAAA: ['2001:db8::10'],
    MX: [{ preference: 10, exchange: 'mail.example.com' }],
    NS: ['ns1.example.com', 'ns2.example.com'],
    TXT: [['v=spf1 mx -all']],
    SOA: [{ mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026100901, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }],
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }]
  },
  'www.example.com': { A: ['203.0.113.20'] },
  'api.example.com': { A: ['203.0.113.14'] },
  'mail.example.com': { A: ['203.0.113.12'] },
  'ns1.example.com': { A: ['198.51.100.53'] },
  'ns2.example.com': { A: ['198.51.100.54'] },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
};
/** Subdomains' stored options: no passive source, the small wordlist, nothing else. */
const SUB_OPTIONS = JSON.stringify({ sources: [], bruteforce: 'small', permutations: false, originHints: false });

/** Each tool: its route with a result, its result header, the field, and when its result is in. */
const TOOLS = {
  domain: { head: '.dov-head', field: 'dov-name', run: 'dov-run' },
  health: { head: '.hlt-hero', field: 'health-domain', run: 'run' },
  subdomains: { head: '.sub-run', field: 'sub-domain', run: 'sub-run' },
  lookup: { head: '.lkp-sum', field: 'lookup-name', run: 'run' }
};
const HEALTH_DONE = (d) => `document.querySelector('.hlt-hero-domain')?.textContent === '${d}' && !document.querySelector('[data-action="run"]').hidden`;
const LOOKUP_DONE = "!!document.querySelector('.lkp-sum') && !document.querySelector('.lkp-card[data-state=\"pending\"]') && !document.querySelector('[data-action=\"run\"]').hidden";
const SUB_DONE = "(() => { const p = document.querySelector('.sub-run-ui .sub-run'); return !!p && p.dataset.status !== 'running'; })()";
const DOMAIN_DONE = "!!document.querySelector('.dov-head') && !document.querySelector('[data-action=\"dov-run\"]').hidden && [...document.querySelectorAll('.dov-card')].every((c) => c.dataset.state !== 'pending')";
const STAMP = /\d{8}-\d{4}/;

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

/** A page with example.com's DNS in it, downloads captured, the network guarded. */
async function openPage(browser, server, viewport) {
  const page = await browser.newPage('about:blank', viewport);
  const hits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(APEX, ZONE) });
  await installDownloadCapture(page);
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  await page.evaluate((o) => localStorage.setItem('ssds.subdomains.options', o), SUB_OPTIONS);
  return { page, hits };
}

/** Run a tool on example.com and wait for its result (Subdomains and the overview through their ready prompt). */
async function runTool(page, id) {
  if (id === 'health') {
    await gotoRoute(page, `#/health?domain=${APEX}`);
    await page.waitFor(HEALTH_DONE(APEX), { timeout: 30000, message: 'health report' });
  } else if (id === 'lookup') {
    await gotoRoute(page, `#/lookup?name=${APEX}&type=A,AAAA,MX,TXT`);
    await page.waitFor(LOOKUP_DONE, { timeout: 30000, message: 'lookup answered' });
  } else if (id === 'subdomains') {
    await gotoRoute(page, `#/subdomains?domain=${APEX}&run=1`);
    await page.waitFor(() => document.querySelector('[data-action="sub-link-start"]'), { timeout: 15000, message: 'link prompt' });
    await page.click('[data-action="sub-link-start"]');
    await page.waitFor(() => document.querySelector('.sub-run-ui'), { timeout: 15000, message: 'scan started' });
    await page.waitFor(SUB_DONE, { timeout: 60000, message: 'scan done' });
  } else {
    await gotoRoute(page, `#/domain?name=${APEX}`);
    await page.waitFor(() => document.querySelector('[data-action="dov-run"]') && !document.querySelector('[data-action="dov-run"]').hidden, { message: 'the overview form' });
    await page.click('[data-action="dov-run"]');
    await page.waitFor(DOMAIN_DONE, { timeout: 30000, message: 'overview built' });
  }
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

/** The template on screen: the input card, Run, the empty state, the result header. */
const templateInfo = (page, head) => page.evaluate((sel) => {
  const card = document.querySelector('#page-body .tool-input');
  const field = card?.querySelector('.tool-input-primary [data-shortcut="focus"]');
  const run = card?.querySelector('.tool-input-fields > .run-bar .run-bar-run');
  const top = (el) => (el ? Math.round(el.getBoundingClientRect().top + window.scrollY) : null);
  const resultHead = document.querySelector(sel);
  return {
    cards: document.querySelectorAll('#page-body .tool-input').length,
    role: card?.getAttribute('role') || null,
    compact: !!card?.classList.contains('is-compact'),
    editing: !!card?.classList.contains('is-editing'),
    field: !!field,
    run: run ? { label: run.querySelector('.btn-label').textContent, primary: run.classList.contains('btn-primary'), shortcut: run.dataset.shortcut || null, sameRow: Math.abs(top(run) - top(field)) <= 1 } : null,
    privacy: !!card?.querySelector('.tool-input-foot .privacy-note'),
    empty: !!document.querySelector('#page-body .tool-empty'),
    checks: document.querySelectorAll('#page-body .tool-empty-check').length,
    head: resultHead ? { connected: resultHead.isConnected, top: top(resultHead) } : null
  };
}, head);

/** The result header's actions row, by kind, in order. */
const actionsRow = (page, head) => page.evaluate((sel) => [...document.querySelectorAll(`${sel} .result-actions > *`)].map((el) => {
  if (el.classList.contains('sum-actions')) return el.querySelector('[data-action="copy-summary-text"]:not([hidden])') ? 'summary+plain' : 'summary';
  if (el.classList.contains('menu-wrap')) return `menu:${el.querySelector('.menu-button').dataset.menu}`;
  return el.dataset.action || el.dataset.export || el.tagName.toLowerCase();
}), head);

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const shot = async (page, name) => {
    if (!opts.shots) return;
    await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
    await mkdir(opts.shotsDir, { recursive: true });
    await page.screenshot(path.join(opts.shotsDir, `${name}.png`), { fullPage: true });
  };

  run.group('Node: harness');
  await run.step('run-all orders the template suite right after home, before the tools\' own suites', () => {
    assertEqual(orderSuites(['subdomains.e2e.mjs', 'investigate.e2e.mjs', 'home.e2e.mjs', 'shell.e2e.mjs']), ['shell', 'home', 'investigate', 'subdomains'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: example.com answered in the page\n`);
  const pages = [];
  try {
    const { page, hits } = await openPage(browser, server, { width: 1440, height: 900 });
    pages.push({ page, hits, where: 'desktop' });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await setLangUi(page, 'en');

    run.group('The empty template (desktop 1440×900, English, light)');
    await run.step('each tool: one input card with its field, Run on the field\'s row and the privacy note; the empty state with its chips; no result header', async () => {
      for (const [id, tool] of Object.entries(TOOLS)) {
        await gotoRoute(page, `#/${id}`);
        const info = await templateInfo(page, tool.head);
        assertEqual([info.cards, info.role, info.compact, info.field, info.privacy, info.empty], [1, 'search', false, true, true, true], `${id}: the input card and the empty state`);
        assert(info.run && info.run.primary && info.run.shortcut === 'submit' && info.run.sameRow, `${id}: Run, primary, on the field's row: ${JSON.stringify(info.run)}`);
        assert(info.checks >= 2, `${id}: the chips of what it checks (${info.checks})`);
        assert(!info.head || !info.head.connected, `${id}: no result header before a run`);
        await assertNoHorizontalScroll(page, `${id} empty`);
      }
      await shot(page, 'investigate-health-empty-desktop-light-en');
    });

    await run.step('an example chip fills the box, sends nothing and leaves the focus on Run', async () => {
      await gotoRoute(page, '#/health');
      const before = await page.evaluate(() => window.__zoneDnsQueries);
      const chip = await page.evaluate(() => document.querySelector('#page-body [data-example]').dataset.example);
      await page.click('#page-body [data-example]');
      const info = await page.evaluate(() => ({
        value: document.querySelector('[data-role="health-domain"]').value,
        focus: document.activeElement?.dataset.action || null,
        head: !!document.querySelector('.hlt-hero'),
        queries: window.__zoneDnsQueries
      }));
      assertEqual(info, { value: chip, focus: 'run', head: false, queries: before }, 'filled, focused, nothing sent');
      await page.type('[data-role="health-domain"]', '');
    });

    run.group('A result (Domain Health, desktop)');
    await run.step('a run: the input turns compact, the result header starts above 300 px, Run reads "Run again" until the box changes', async () => {
      await page.type('[data-role="health-domain"]', APEX);
      await page.press('Enter');
      await page.waitFor(HEALTH_DONE(APEX), { timeout: 30000, message: 'health report' });
      const info = await templateInfo(page, '.hlt-hero');
      assert(info.compact && !info.editing, 'compact');
      assert(info.head && info.head.connected && info.head.top < 300, `the result header near the top: ${JSON.stringify(info.head)}`);
      assertEqual([info.run.label, info.run.primary, info.run.sameRow], ['Run again', false, true], 'Run again, secondary, on the field\'s row');
      await page.type('[data-role="health-domain"]', 'example.org');
      assertEqual((await templateInfo(page, '.hlt-hero')).run.label, 'Check health', 'another domain in the box: the verb again');
      assert((await templateInfo(page, '.hlt-hero')).run.primary, 'and primary');
      await page.type('[data-role="health-domain"]', APEX);
      assertEqual((await templateInfo(page, '.hlt-hero')).run.label, 'Run again', 'the report\'s domain again');
      await shot(page, 'investigate-health-result-desktop-light-en');
    });

    await run.step('Edit unfolds the rest of the form (aria-expanded) and folds it again; the summary line stays', async () => {
      const edit = '.hlt-form-card [data-action="tool-input-edit"]';
      const state = () => page.evaluate((sel) => {
        const btn = document.querySelector(sel);
        const more = document.getElementById(btn.getAttribute('aria-controls').split(' ')[0]);
        return { expanded: btn.getAttribute('aria-expanded'), moreShown: !!more && more.getClientRects().length > 0, summary: !!document.querySelector('.hlt-form-card .tool-input-summary:not([hidden])') };
      }, edit);
      assertEqual(await state(), { expanded: 'false', moreShown: false, summary: true }, 'folded');
      await page.click(edit);
      assertEqual(await state(), { expanded: 'true', moreShown: true, summary: true }, 'unfolded');
      await page.click(edit);
      assertEqual(await state(), { expanded: 'false', moreShown: false, summary: true }, 'folded again');
    });

    await run.step('the status summary: one toggle per severity filters the checks; a second press shows them all', async () => {
      const items = await page.evaluate(() => [...document.querySelectorAll('.hlt-hero .status-item')].map((b) => ({
        key: b.dataset.status, count: Number(b.dataset.count), button: b.tagName === 'BUTTON', pressed: b.getAttribute('aria-pressed')
      })));
      assert(items.length >= 2 && items.every((x) => x.button && x.pressed === 'false'), `toggles: ${JSON.stringify(items)}`);
      assert(items.some((x) => x.key === 'error'), 'a verdict tool always says its errors ("0 errors" is the good news)');
      const order = ['error', 'warn', 'info', 'ok'];
      assertEqual(items.map((x) => x.key), order.filter((k) => items.some((x) => x.key === k)), 'error → warn → info → ok');
      const total = await page.evaluate(() => document.querySelectorAll('.hlt-check').length);
      const pick = items.find((x) => x.count > 0 && x.key !== 'ok') || items.find((x) => x.count > 0);
      await page.click(`.hlt-hero .status-item[data-status="${pick.key}"]`);
      const filtered = await page.evaluate(() => ({
        pressed: [...document.querySelectorAll('.hlt-hero .status-item[aria-pressed="true"]')].map((b) => b.dataset.status),
        severities: [...new Set([...document.querySelectorAll('.hlt-check')].map((c) => c.dataset.severity))]
      }));
      assertEqual(filtered, { pressed: [pick.key], severities: [pick.key] }, `filtered to ${pick.key}`);
      await page.click(`.hlt-hero .status-item[data-status="${pick.key}"]`);
      assertEqual(await page.evaluate(() => [document.querySelectorAll('.hlt-hero .status-item[aria-pressed="true"]').length, document.querySelectorAll('.hlt-check').length]),
        [0, total], 'every check again');
    });

    await run.step('the actions in order; Export ▾ holds the JSON report and Print, Esc closes it on its button; Copy link; Also check', async () => {
      assertEqual(await actionsRow(page, '.hlt-hero'), ['summary+plain', 'report', 'menu:export', 'copy-link'], 'Copy summary + ¶, Report, Export ▾, Copy link');
      const button = await page.evaluate(() => {
        const b = document.querySelector('.hlt-hero [data-menu="export"]');
        return { popup: b.getAttribute('aria-haspopup'), expanded: b.getAttribute('aria-expanded'), text: b.textContent.trim() };
      });
      assertEqual(button, { popup: 'menu', expanded: 'false', text: 'Export' }, 'a menu button that says Export');
      assertEqual(await openResultMenu(page, 'export', '.hlt-hero'), ['Report (JSON)', 'Print / save as PDF'], 'its items, Print last');
      await page.press('Escape');
      await page.waitFor(() => document.querySelector('.hlt-hero [data-menu="export"]').getAttribute('aria-expanded') === 'false'
        && document.activeElement === document.querySelector('.hlt-hero [data-menu="export"]'), { message: 'closed, the focus on Export' });
      await takeDownloads(page);
      await resultAction(page, '[data-action="download"]', '.hlt-hero');
      const files = await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the JSON report' }).then(() => takeDownloads(page));
      assertEqual(files.map((f) => f.name.replace(STAMP, 'STAMP')), [`domain-health-${APEX}-STAMP.json`], 'the file');
      assertEqual(JSON.parse(files[0].text).domain, APEX, 'its domain');
      await stubClipboard(page);
      await resultAction(page, '[data-action="copy-link"]', '.hlt-hero');
      await page.waitFor(() => window.__clip.length === 1, { message: 'Copy link' });
      assert((await takeClipboard(page))[0].endsWith(`#/health?domain=${APEX}`), 'the report\'s own link');
      const related = await page.evaluate(() => ({
        label: document.querySelector('.hlt-hero .result-related-label')?.textContent,
        views: [...document.querySelectorAll('.hlt-hero .result-related a')].map((a) => a.dataset.view)
      }));
      assertEqual(related, { label: 'Also check:', views: ['lookup', 'global', 'scan'] }, 'Also check');
    });

    await run.step('the kept result: back through the navigation, the note sits in the result header, once', async () => {
      await gotoRoute(page, '#/about');
      await page.click('a.nav-link[data-view="health"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'health' && !!document.querySelector('.hlt-hero .page-kept:not([hidden]) .kept-note'), { message: 'kept note' });
      const info = await page.evaluate(() => ({
        notes: document.querySelectorAll('.kept-note').length,
        inHead: !!document.querySelector('.hlt-hero .result-kept .kept-note'),
        rerun: !!document.querySelector('.hlt-hero .page-kept [data-action="kept-rerun"]')
      }));
      assertEqual(info, { notes: 1, inHead: true, rerun: true }, 'one note, in the head, with its Run again');
    });

    run.group('The other three (desktop)');
    await run.step('DNS Lookup: one file is a plain Export button (the dig answers); the counts; Explain and the DNSSEC chain; Also check', async () => {
      await runTool(page, 'lookup');
      assertEqual(await actionsRow(page, '.lkp-sum'), ['summary+plain', 'dig', 'copy-link'], 'Copy summary + ¶, Export, Copy link');
      assertEqual(await page.evaluate(() => [document.querySelector('.lkp-sum [data-export="dig"]').textContent.trim(), !!document.querySelector('.lkp-sum [data-menu="export"]')]),
        ['Export', false], 'one file: a button, no menu');
      await takeDownloads(page);
      await resultAction(page, '[data-export="dig"]', '.lkp-sum');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the dig file' });
      const [file] = await takeDownloads(page);
      assert(/^dns-lookup-.*\.txt$/.test(file.name) && file.text.includes('example.com.') && /\bMX\b/.test(file.text), `${file.name}: ${file.text.slice(0, 200)}`);
      const head = await page.evaluate(() => ({
        status: [...document.querySelectorAll('.lkp-sum .status-item')].map((x) => x.dataset.status),
        next: [...document.querySelectorAll('.lkp-sum .result-next .next-step')].map((b) => b.dataset.action),
        related: [...document.querySelectorAll('.lkp-sum .result-related a')].map((a) => a.dataset.view),
        top: Math.round(document.querySelector('.lkp-sum').getBoundingClientRect().top + window.scrollY)
      }));
      assertEqual([head.status.slice(0, 2), head.next, head.related], [['types', 'records'], ['explain', 'dnssec-chain'], ['global', 'health']], 'the head');
      assert(head.top < 300, `the result header near the top: ${head.top}`);
    });

    await run.step('Subdomains: a shared link\'s prompt leads (Run steps back), Start scans; Export ▾ holds names.txt, CSV and JSON; the metric strip is read-only', async () => {
      await gotoRoute(page, `#/subdomains?domain=${APEX}&run=1`);
      await page.waitFor(() => document.querySelector('[data-action="sub-link-start"]'), { timeout: 15000, message: 'link prompt' });
      const prompt = await page.evaluate(() => ({
        start: document.querySelector('[data-action="sub-link-start"]').classList.contains('btn-primary'),
        run: document.querySelector('[data-action="sub-run"]').classList.contains('btn-primary'),
        primaries: [...document.querySelectorAll('#page-body .btn-primary')].filter((b) => b.getClientRects().length).length
      }));
      assertEqual(prompt, { start: true, run: false, primaries: 1 }, 'one primary button: Start');
      await page.click('[data-action="sub-link-start"]');
      await page.waitFor(SUB_DONE, { timeout: 60000, message: 'scan done' });
      assertEqual(await actionsRow(page, '.sub-run'), ['summary+plain', 'menu:export', 'copy-link'], 'Copy summary + ¶, Export ▾, Copy link');
      assertEqual(await openResultMenu(page, 'export', '.sub-run'), ['names.txt', 'CSV', 'JSON'], 'the three files');
      await page.press('Escape');
      await takeDownloads(page);
      await resultAction(page, '[data-export="csv"]', '.sub-run');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the CSV' });
      assertEqual((await takeDownloads(page)).map((f) => f.name.replace(STAMP, 'STAMP')), [`subdomains-${APEX}-STAMP.csv`], 'the CSV');
      const info = await page.evaluate(() => ({
        metrics: document.querySelectorAll('.sub-stats .metric').length,
        controls: document.querySelectorAll('.sub-stats button, .sub-stats a, .sub-stats [tabindex]').length,
        next: [...document.querySelectorAll('.sub-run .result-next .next-step')].map((b) => b.dataset.action || b.getAttribute('href')),
        top: Math.round(document.querySelector('.sub-run').getBoundingClientRect().top + window.scrollY)
      }));
      assert(info.metrics >= 2 && info.controls === 0, `read-only figures: ${JSON.stringify(info)}`);
      assertEqual(info.next, ['sub-cta', '#/bulk'], 'next steps: certificate targets, Bulk Resolve');
      assert(info.top < 300, `the result header near the top: ${info.top}`);
    });

    await run.step('Domain overview: the prompt, Build, the result header with its status and links', async () => {
      await runTool(page, 'domain');
      const head = await page.evaluate(() => ({
        top: Math.round(document.querySelector('.dov-head').getBoundingClientRect().top + window.scrollY),
        title: document.querySelector('.dov-head .result-title').textContent,
        actions: !!document.querySelector('.dov-head [data-action="copy-summary"]') && !!document.querySelector('.dov-head [data-action="report"]'),
        related: [...document.querySelectorAll('.dov-head .result-related a')].map((a) => a.dataset.view)
      }));
      assert(head.top < 300, `the result header near the top: ${head.top}`);
      assert(head.title.includes(APEX) && head.actions, `the head: ${JSON.stringify(head)}`);
      assertEqual(head.related, ['health', 'lookup', 'subdomains'], 'Also check');
      await assertNoHorizontalScroll(page, 'overview');
    });

    await run.step('desktop: no missing keys; no console errors, exceptions or CSP violations', async () => {
      await assertNoMissingKeys(page);
      await assertClean(page, 'desktop', origin);
    });

    run.group('Phones');
    await run.step('375×812 (Turkish, dark): Copy summary alone in the row, the rest behind "⋯"; Copy link from there', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await gotoRoute(page, '#/health');
      await page.waitFor(HEALTH_DONE(APEX), { timeout: 10000, message: 'the kept report' });
      assertEqual(await actionsRow(page, '.hlt-hero'), ['summary', 'menu:more'], 'Copy summary, ⋯');
      const words = await page.evaluate(() => ({
        run: document.querySelector('[data-action="run"] .btn-label').textContent,
        edit: document.querySelector('.hlt-form-card [data-action="tool-input-edit"]').textContent,
        related: document.querySelector('.hlt-hero .result-related-label').textContent
      }));
      assertEqual(words, { run: 'Yeniden çalıştır', edit: 'Düzenle', related: 'Ayrıca bakın:' }, 'the template in Turkish');
      const items = await openResultMenu(page, 'more', '.hlt-hero');
      assertEqual(items.slice(-3), ['Rapor (JSON)', 'Yazdır / PDF olarak kaydet', 'Bağlantıyı kopyala'], `the rest, in order: ${items.join(' | ')}`);
      assertEqual(items[0], 'Düz metin olarak kopyala', 'plain text first');
      await page.press('Escape');
      await stubClipboard(page);
      await resultAction(page, '[data-action="copy-link"]', '.hlt-hero');
      await page.waitFor(() => window.__clip.length === 1, { message: 'Copy link from ⋯' });
      assert((await takeClipboard(page))[0].endsWith(`#/health?domain=${APEX}`), 'the report\'s own link');
      await assertNoHorizontalScroll(page, 'health 375 tr dark');
      await shot(page, 'investigate-health-result-375-dark-tr');
      for (const id of ['lookup', 'subdomains', 'domain']) {
        await gotoRoute(page, `#/${id}`);
        await page.waitFor((sel) => !!document.querySelector(`${sel} .result-actions`), { args: [TOOLS[id].head], timeout: 10000, message: `${id} kept` });
        const row = await actionsRow(page, TOOLS[id].head);
        assertEqual(row, ['summary', 'menu:more'], `${id}: Copy summary, ⋯`);
        await assertNoHorizontalScroll(page, `${id} 375 tr dark`);
      }
    });

    const fresh = await openPage(browser, server, { width: 375, height: 812, mobile: true });
    pages.push({ ...fresh, where: 'phone' });
    const phone = fresh.page;
    await phone.emulateMedia({ 'prefers-color-scheme': 'light' });
    await setLangUi(phone, 'en');

    await run.step('375 (English, light): the floating run bar while the inline Run is out of view; it clears a focused field and runs the tool', async () => {
      await gotoRoute(phone, '#/lookup');
      assert(await phone.evaluate(() => document.querySelector('.run-bar-float').hidden), 'no floating bar while the inline Run is in view');
      await phone.type('[data-role="lookup-name"]', APEX);
      await phone.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
      const bar = await phone.waitFor(() => {
        const float = document.querySelector('.run-bar-float');
        if (!float || float.hidden) return null;
        const r = float.getBoundingClientRect();
        return {
          fixed: getComputedStyle(float).position === 'fixed',
          bottom: Math.round(r.bottom) === window.innerHeight,
          label: float.textContent.trim(),
          padding: getComputedStyle(document.documentElement).scrollPaddingBottom === `${Math.ceil(r.height)}px`
        };
      }, { message: 'the floating bar' });
      assertEqual(bar, { fixed: true, bottom: true, label: 'Look up', padding: true }, 'at the bottom, its height kept clear');
      await shot(phone, 'investigate-lookup-float-375-light-en');
      await phone.click('[data-role="run-bar-float"]');
      await phone.waitFor(LOOKUP_DONE, { timeout: 30000, message: 'the float ran the lookup' });
      await phone.waitFor(() => document.querySelector('.run-bar-float').hidden, { message: 'gone once a result is on screen' });
      assertEqual(await phone.evaluate(() => getComputedStyle(document.documentElement).scrollPaddingBottom), '0px', 'nothing kept clear any more');
    });

    await run.step('320 px (English, light): no horizontal scroll on the four tools, empty or with a result', async () => {
      await phone.setViewport({ width: 320, height: 700, mobile: true });
      for (const id of Object.keys(TOOLS)) {
        if (id !== 'lookup') {
          await gotoRoute(phone, `#/${id}`);
          await assertNoHorizontalScroll(phone, `${id} 320 empty`);
        }
        await runTool(phone, id);
        await assertNoHorizontalScroll(phone, `${id} 320 result`);
        assertEqual(await actionsRow(phone, TOOLS[id].head), ['summary', 'menu:more'], `${id}: Copy summary, ⋯ at 320`);
      }
      await shot(phone, 'investigate-subdomains-result-320-light-en');
    });

    await run.step('phone: no missing keys; no console errors, exceptions or CSP violations; nothing sent', async () => {
      await assertNoMissingKeys(phone);
      for (const p of pages) await assertClean(p.page, p.where, origin);
      assertEqual(pages.map((p) => p.hits), [[], []], 'no request reached the network');
    });
  } finally {
    for (const p of pages) await p.page.close().catch(() => {});
    await browser.close();
    await server.close();
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
