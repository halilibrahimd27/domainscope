#!/usr/bin/env node
/**
 * migrate.e2e.mjs — end-to-end test of the page template (ui/template.js, lib/template.js;
 * docs/DESIGN.md §5 and §8 phase 4) on the four tools of "Change & migrate DNS": DNS change
 * request (and its check page, #/change/check), Global DNS, Zone File and Retire an IP (and its
 * comparison of the old and the new server, #/retire/compare), in a real headless Chrome/Edge.
 * OFFLINE: the DNS of example.com is answered inside the page (scan.e2e.mjs zoneHandoffScript),
 * every other request that leaves the page fails there, and a network-level guard fails and
 * records any https request that would still go out — the suite asserts none.
 *
 *   node tests/e2e/migrate.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - the empty template of each page: one input card (`.tool-input`, role search) with its field
 *     and the privacy note in its footer; Run on the field's row (the editor's Read under its
 *     fields; a file tool has none: the drop zone is its input); the empty state with the chips of
 *     what the tool checks; no result header;
 *   - Retire's compare tool is a page of its own: the old anchor (#/retire?section=compare) opens
 *     #/retire/compare, its heading names it and it links back;
 *   - a result of each: the result header starts above 300 px at 1440×900 (a global check, a
 *     retire check, the zone's, the change check's); the input turns compact (the field, the
 *     summary line with Edit, Run) while the change request's editor stays whole; a shared link's
 *     ready prompt leads (Retire: Run steps back until Start);
 *   - the status summaries: Global DNS's failed queries filter the tables on the Resolvers &
 *     locations tab (a second press shows every source); Zone File's errors open the Problems tab
 *     filtered, its names the Records tab; Retire's "breaks mail" filters the change list; the
 *     change request's warnings bring its problems into view;
 *   - the standard actions in order: Global DNS and Retire an IP: Copy summary with ¶, Export ▾,
 *     Copy link; Zone File: Copy summary with ¶ and Export ▾ (Convert, Print, Forget last); the
 *     change request and its check page: Copy summary with ¶ and Copy link (the check link);
 *   - Global DNS's tabs keep every section in the page (`.glb-summary`, `.glb-resolvers`): only the
 *     other panels hide; the kept result's note sits in its result header once it is opened again;
 *   - a page that is left takes back its phone-layout listeners (its run bar's and its actions');
 *   - phones: at 375×812 (Turkish, dark) only Copy summary stays in the row and the rest is behind
 *     "⋯" (Zone File's Forget last); 320 px: no horizontal scroll on the six pages, empty or with
 *     a result;
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
  installDownloadCapture, openResultMenu, resultAction, setLangUi, stubClipboard, takeClipboard, takeDownloads, waitReady, zoneHandoffScript
} from './scan.e2e.mjs';

const APEX = 'example.com';
const OLD_IP = '203.0.113.10';
/** The DNS of example.com, answered in the page (documentation addresses only). */
const ZONE = {
  'example.com': {
    A: [OLD_IP],
    MX: [{ preference: 10, exchange: 'mail.example.com' }],
    NS: ['ns1.example.com', 'ns2.example.com'],
    TXT: [[`v=spf1 ip4:${OLD_IP} mx -all`]],
    SOA: [{ mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026100901, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }]
  },
  'www.example.com': { A: [OLD_IP] },
  'mail.example.com': { A: ['203.0.113.12'] },
  'ns1.example.com': { A: ['198.51.100.53'] },
  'ns2.example.com': { A: ['198.51.100.54'] }
};
const CHECK_LINK = `#/change/check?z=${APEX}&r=is+www+A+${OLD_IP}`;
const CHANGE_LINK = `#/change?t=acme-txt&name=*.${APEX}&tokens=not-a-token`;
const GLOBAL_LINK = `#/global?name=www.${APEX}&type=A`;
const RETIRE_LINK = `#/retire?ips=${OLD_IP}&domains=${APEX}`;

/** Each page: its route, its input card and field, its Run (data-action) and where it sits, its empty state and result header. */
const PAGES = {
  change: { route: '#/change', card: '.chg-form-card', field: '[data-role="change-template"]', run: 'change-read', row: false, empty: '.chg-empty', head: '.chg-result' },
  global: { route: '#/global', card: '.glb-form-card', field: '[data-role="global-name"]', run: 'run', row: true, empty: '.glb-empty', head: '.glb-summary' },
  zone: { route: '#/zone', card: '.zone-import', field: '.zone-drop', run: null, row: false, empty: '.zone-empty', head: '.zone-summary' },
  retire: { route: '#/retire', card: '.retire-form-card', field: '[data-role="retire-ips"]', run: 'retire-run', row: true, empty: '.retire-empty', head: '.retire-head' },
  compare: { route: '#/retire/compare', card: '.oc-card', field: '[data-role="oc-host"]', run: 'oc-run', row: true, empty: '.oc-empty', head: '.oc-head' }
};
const GLOBAL_DONE = "document.querySelector('.glb-summary')?.dataset.state === 'done'";
const RETIRE_DONE = "document.querySelector('.retire-job')?.dataset.status === 'done' && !document.querySelector('[data-action=\"retire-run\"]').hidden";
const CHECK_DONE = "document.querySelector('[data-page=\"check\"]')?.dataset.state === 'done'";

/**
 * Counts the 'change' listeners on the phone layout's media query (lib/template.js PHONE_MAX_WIDTH):
 * the run bar and the actions of a page add one each, and a page that is left must take them back
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

/** A page with example.com's DNS in it, downloads captured, the network guarded. */
async function openPage(browser, server, viewport) {
  const page = await browser.newPage('about:blank', viewport);
  const hits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(APEX, ZONE) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: PHONE_LISTENERS });
  await installDownloadCapture(page);
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  return { page, hits };
}

/** Open a route that is a sub-page or carries params (gotoRoute waits for the view's id). */
async function open(page, route) {
  await page.evaluate((r) => { window.location.hash = r; }, route);
  const view = route.replace(/^#\//, '').split(/[/?]/)[0];
  await page.waitFor((v) => document.documentElement.dataset.view === v && document.querySelector('#page-body')?.childElementCount > 0
    && !document.querySelector('#page-body .page-loading'), { args: [view], message: `route ${route}`, timeout: 15000 });
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

/** The template on screen: the input card, its field and Run, the empty state, the result header. */
const templateInfo = (page, cfg) => page.evaluate((c) => {
  const card = document.querySelector(`#page-body ${c.card}`);
  const field = card?.querySelector(c.field);
  const run = c.run ? card?.querySelector(`[data-action="${c.run}"]`) : null;
  const f = field?.getBoundingClientRect();
  const r = run?.getBoundingClientRect();
  const head = document.querySelector(c.head);
  const empty = document.querySelector(c.empty);
  return {
    cards: document.querySelectorAll('#page-body .tool-input').length,
    role: card?.getAttribute('role') || null,
    compact: !!card?.classList.contains('is-compact'),
    field: !!field,
    focus: !!card?.querySelector('[data-shortcut="focus"]'),
    run: run ? {
      label: run.querySelector('.btn-label')?.textContent || '', primary: run.classList.contains('btn-primary'), shortcut: run.dataset.shortcut || null,
      row: !!f && !!r && r.top < f.bottom && r.bottom > f.top
    } : null,
    privacy: !!card?.querySelector('.tool-input-foot .privacy-note'),
    empty: !!empty && empty.checkVisibility() && !!empty.querySelector('.tool-empty'),
    checks: document.querySelectorAll(`${c.empty} .tool-empty-check`).length,
    head: head && head.checkVisibility() ? Math.round(head.getBoundingClientRect().top + window.scrollY) : null
  };
}, cfg);

/** The result header's actions row, by kind, in order. */
const actionsRow = (page, head) => page.evaluate((sel) => [...document.querySelectorAll(`${sel} .result-actions > *`)].map((el) => {
  if (el.classList.contains('sum-actions')) return el.querySelector('[data-action="copy-summary-text"]:not([hidden])') ? 'summary+plain' : 'summary';
  if (el.classList.contains('menu-wrap')) return `menu:${el.querySelector('.menu-button').dataset.menu}`;
  return el.dataset.action || el.dataset.export || el.tagName.toLowerCase();
}), head);

/** The items of a result's menu, by their data-action / data-export, in order (the menu is opened and closed). */
async function menuKeys(page, which, head) {
  await openResultMenu(page, which, head);
  const keys = await page.evaluate(([w, sel]) => [...document.querySelector(`${sel} .result-actions [data-menu="${w}"]`).closest('.menu-wrap').querySelectorAll('.menu-item')]
    .map((x) => x.dataset.action || x.dataset.export || x.textContent.trim()), [which, head]);
  await page.press('Escape');
  return keys;
}

/** The status summary of a result header: [key, count, pressed] per item. */
const statusOf = (page, head) => page.evaluate((sel) => [...document.querySelectorAll(`${sel} .status-item`)].map((x) => [x.dataset.status, Number(x.dataset.count), x.getAttribute('aria-pressed')]), head);

/** Every source row the Global DNS tables show (resolvers, locations, mainland China). */
const globalRows = (page) => page.evaluate(() => [...document.querySelectorAll('.glb-resolvers tbody tr.dt-row, .glb-geo tbody tr.dt-row')].map((tr) => !!tr.querySelector('.glb-fail')));

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
  await run.step('run-all orders the template suite of Change & migrate DNS right after the one of Investigate a domain', () => {
    assertEqual(orderSuites(['zone.e2e.mjs', 'migrate.e2e.mjs', 'investigate.e2e.mjs', 'home.e2e.mjs']), ['home', 'investigate', 'migrate', 'zone'], 'order');
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
    await run.step('each page: one input card with its field and the privacy note, Run where its variant puts it; the empty state with its chips; no result header', async () => {
      for (const [id, cfg] of Object.entries(PAGES)) {
        await open(page, cfg.route);
        const info = await templateInfo(page, cfg);
        assertEqual([info.cards, info.role, info.compact, info.field, info.focus, info.privacy, info.empty], [1, 'search', false, true, true, true, true], `${id}: the input card and the empty state`);
        assert(info.checks >= 3, `${id}: the chips of what it checks (${info.checks})`);
        assertEqual(info.head, null, `${id}: no result header before a run`);
        if (!cfg.run) assertEqual(info.run, null, `${id}: a file tool has no Run: the drop zone is its input`);
        else {
          assert(info.run.primary && info.run.shortcut === 'submit', `${id}: Run is the primary button and takes Ctrl+Enter: ${JSON.stringify(info.run)}`);
          assertEqual(info.run.row, cfg.row, `${id}: Run ${cfg.row ? 'on the field\'s row' : 'under the editor\'s fields'}`);
        }
        await assertNoHorizontalScroll(page, `${id} empty`);
      }
      assertEqual(await page.evaluate(() => [document.querySelector('h1.page-title').textContent, new URL(document.querySelector('[data-role="compare-back"]').href).hash]),
        ['Compare the old and the new server', '#/retire'], 'the compare page: its own heading, the way back');
      await shot(page, 'migrate-compare-empty-desktop-light-en');
    });

    await run.step('the old anchor of Retire\'s compare card opens #/retire/compare; the empty state links there', async () => {
      await open(page, '#/retire?section=compare');
      await page.waitFor(() => location.hash === '#/retire/compare' && !!document.querySelector('.retire-compare .oc-page'), { message: 'redirected' });
      await open(page, '#/retire');
      assertEqual(await page.evaluate(() => new URL(document.querySelector('.retire-empty [data-role="compare-open"]').href).hash), '#/retire/compare', 'the link');
    });

    run.group('Results (desktop)');
    await run.step('Global DNS: a shared link runs; compact input with "Run again"; the result header above 300 px; three tabs, every section kept in the page', async () => {
      await open(page, GLOBAL_LINK);
      await page.waitFor(GLOBAL_DONE, { timeout: 30000, message: 'global check done' });
      const info = await templateInfo(page, PAGES.global);
      assert(info.compact, 'compact');
      assertEqual([info.run.label, info.run.primary, info.run.row], ['Run again', false, true], 'Run again, secondary, on the field\'s row');
      assert(info.head !== null && info.head < 300, `the result header near the top: ${info.head}`);
      const head = await page.evaluate(() => ({
        title: document.querySelector('.glb-summary .result-title').textContent,
        tabs: [...document.querySelectorAll('.glb-tabs .tab')].map((t) => t.dataset.tab),
        selected: document.querySelector('.glb-tabs .tab[aria-selected="true"]').dataset.tab,
        resolvers: !!document.querySelector('.glb-tabs .glb-resolvers') && !document.querySelector('.glb-resolvers').checkVisibility(),
        metrics: document.querySelectorAll('.glb-stats .metric').length,
        controls: document.querySelectorAll('.glb-stats button, .glb-stats a, .glb-stats [tabindex]').length,
        related: [...document.querySelectorAll('.glb-summary .result-related a')].map((a) => a.dataset.view)
      }));
      assert(head.title.includes(`www.${APEX}`), `the title names the check: ${head.title}`);
      assertEqual([head.tabs, head.selected, head.resolvers], [['groups', 'ips', 'resolvers'], 'groups', true], 'the tabs: the resolver table in the page, its panel hidden');
      assert(head.metrics >= 3 && head.controls === 0, `a read-only metric strip: ${JSON.stringify(head)}`);
      assertEqual(head.related, ['lookup', 'health'], 'Also check');
      await shot(page, 'migrate-global-result-desktop-light-en');
    });

    await run.step('Global DNS: the failed queries filter the tables on the Resolvers & locations tab; a second press shows every source', async () => {
      const status = await statusOf(page, '.glb-summary');
      const failed = status.find(([k]) => k === 'failed');
      // AliDNS's JSON questions (mainland China) never leave the page: they fail there.
      assert(failed && failed[1] === 3 && failed[2] === 'false', `the failed queries: ${JSON.stringify(status)}`);
      assertEqual(status[0][0], 'failed', 'errors first');
      const all = (await globalRows(page)).length;
      await page.click('.glb-summary .status-item[data-status="failed"]');
      await page.waitFor(() => document.querySelector('.glb-tabs .tab[aria-selected="true"]')?.dataset.tab === 'resolvers' && !document.querySelector('.glb-filter-note').hidden,
        { message: 'the Resolvers & locations tab, filtered' });
      const rows = await globalRows(page);
      assertEqual([rows.length, rows.every(Boolean)], [3, true], 'only the sources that failed');
      assertEqual((await statusOf(page, '.glb-summary')).find(([k]) => k === 'failed')[2], 'true', 'pressed');
      await page.click('.glb-summary .status-item[data-status="failed"]');
      await page.waitFor(() => document.querySelector('.glb-filter-note').hidden, { message: 'every source again' });
      assertEqual((await globalRows(page)).length, all, 'every row back');
    });

    await run.step('Global DNS: Copy summary with ¶, Export ▾ (the IP addresses), Copy link (the check\'s own link)', async () => {
      assertEqual(await actionsRow(page, '.glb-summary'), ['summary+plain', 'menu:export', 'copy-link'], 'the actions, in order');
      assertEqual(await menuKeys(page, 'export', '.glb-summary'), ['ips-csv', 'ips-json'], 'Export ▾');
      await takeDownloads(page);
      await resultAction(page, '[data-export="ips-csv"]', '.glb-summary');
      const [file] = await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the CSV' }).then(() => takeDownloads(page));
      assert(/\.csv$/.test(file.name) && file.text.includes(OLD_IP), `${file.name}: ${file.text.slice(0, 120)}`);
      await stubClipboard(page);
      await resultAction(page, '[data-action="copy-link"]', '.glb-summary');
      await page.waitFor(() => window.__clip.length === 1, { message: 'Copy link' });
      assert((await takeClipboard(page))[0].endsWith(GLOBAL_LINK), 'the check\'s own link');
    });

    await run.step('Global DNS kept: back through the navigation, the note sits in the result header, once', async () => {
      await gotoRoute(page, '#/about');
      await page.click('a.nav-link[data-view="global"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'global' && !!document.querySelector('.glb-summary .page-kept:not([hidden]) .kept-note'), { message: 'kept note' });
      assertEqual(await page.evaluate(() => [document.querySelectorAll('.kept-note').length, !!document.querySelector('.glb-summary .result-kept [data-action="kept-rerun"]')]),
        [1, true], 'one note, in the head, with its Run again');
    });

    await run.step('Retire an IP: a shared link\'s prompt leads; Start checks; compact input; the verdict as the title above 300 px', async () => {
      await open(page, RETIRE_LINK);
      await page.waitFor(() => !!document.querySelector('.retire-prompt[data-prompt="link"]'), { message: 'the ready prompt' });
      const prompt = await page.evaluate(() => ({
        start: document.querySelector('[data-action="retire-link-start"]').classList.contains('btn-primary'),
        run: document.querySelector('[data-action="retire-run"]').classList.contains('btn-primary'),
        primaries: [...document.querySelectorAll('#page-body .btn-primary')].filter((b) => b.getClientRects().length).length,
        empty: document.querySelector('.retire-empty').checkVisibility()
      }));
      assertEqual(prompt, { start: true, run: false, primaries: 1, empty: false }, 'one primary button: Start');
      await page.click('[data-action="retire-link-start"]');
      await page.waitFor(RETIRE_DONE, { timeout: 30000, message: 'retire check done' });
      const info = await templateInfo(page, PAGES.retire);
      assert(info.compact, 'compact');
      assertEqual([info.run.label, info.run.primary], ['Run again', false], 'Run again, secondary');
      assert(info.head !== null && info.head < 300, `the result header near the top: ${info.head}`);
      const head = await page.evaluate(() => ({
        severity: document.querySelector('.retire-head .result-title').dataset.severity,
        title: document.querySelector('.retire-head .result-title-text').textContent,
        next: [...document.querySelectorAll('.retire-head .result-next .next-step')].map((b) => b.dataset.action || b.dataset.role)
      }));
      assertEqual(head.severity, 'error', 'mail breaks: an error');
      assert(new RegExp(`break something once ${OLD_IP.replace(/\./g, '\\.')} is gone$`).test(head.title), head.title);
      assertEqual(head.next, ['retire-discover-next', 'retire-passive', 'compare-open'], 'next steps: discovery, the passive lookup, the comparison');
      await shot(page, 'migrate-retire-result-desktop-light-en');
    });

    await run.step('Retire an IP: "breaks mail" filters the change list; Copy summary with ¶, Export ▾ (CSV, JSON), Copy link', async () => {
      const status = await statusOf(page, '.retire-head');
      assertEqual(status.map(([k]) => k), ['mail', 'breaking'], `the status summary: ${JSON.stringify(status)}`);
      const rows = () => page.evaluate(() => [...document.querySelectorAll('.retire-group tbody tr')].map((tr) => tr.dataset.severity));
      const every = (await rows()).length;
      await page.click('.retire-head .status-item[data-status="mail"]');
      await page.waitFor(() => !document.querySelector('.retire-filter-note').hidden, { message: 'filtered' });
      assertEqual(await rows(), ['mail'], 'only what breaks mail');
      await page.click('.retire-head .status-item[data-status="mail"]');
      await page.waitFor(() => document.querySelector('.retire-filter-note').hidden, { message: 'every row again' });
      assertEqual((await rows()).length, every, 'every row');
      assertEqual(await actionsRow(page, '.retire-head'), ['summary+plain', 'menu:export', 'copy-link'], 'the actions, in order');
      assertEqual(await menuKeys(page, 'export', '.retire-head'), ['csv', 'json'], 'Export ▾');
      await stubClipboard(page);
      await resultAction(page, '[data-action="copy-link"]', '.retire-head');
      await page.waitFor(() => window.__clip.length === 1, { message: 'Copy link' });
      assert((await takeClipboard(page))[0].endsWith(`#/retire?ips=${OLD_IP}&domains=${APEX}`), 'the check\'s own link');
    });

    await run.step('the comparison page: the retired address and the first domain filled in; a private new address gets the CLI command, no Run', async () => {
      await open(page, '#/retire/compare');
      await page.waitFor((ip) => document.querySelector('[data-role="oc-oldIp"]')?.value === ip, { args: [OLD_IP], message: 'filled from the check' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="oc-host"]').value), APEX, 'the first domain');
      await page.type('[data-role="oc-newIp"]', '10.0.0.20');
      await page.waitFor(() => !!document.querySelector('.oc-card [data-role="oc-cli"] code'), { message: 'the CLI command' });
      assertEqual(await page.evaluate(() => [document.querySelector('[data-action="oc-run"]').closest('.run-bar').hidden, !!document.querySelector('.oc-card .tool-input-notes [data-role="oc-cli"]')]),
        [true, true], 'no Run; the command under the fields');
      await page.type('[data-role="oc-newIp"]', '');
    });

    await run.step('Zone File: a sample; the import card one row; the zone\'s result header above 300 px; errors open the Problems tab filtered, names the Records tab', async () => {
      await open(page, '#/zone');
      await page.click('[data-sample="bind"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary .zone-status'), { message: 'the zone' });
      const info = await templateInfo(page, PAGES.zone);
      assert(info.compact && info.run === null, 'compact, no Run');
      assert(info.head !== null && info.head < 300, `the result header near the top: ${info.head}`);
      assertEqual(await page.evaluate(() => [document.querySelector('.zone-import .tool-input-summary-text').textContent.split(' · ')[0], !!document.querySelector('[data-sample]')]),
        ['db.example.com', false], 'the file on its line; no samples once a zone is on screen');
      const status = await statusOf(page, '.zone-summary');
      assertEqual(status.slice(0, 2).map(([k]) => k), ['error', 'warn'], `errors first: ${JSON.stringify(status)}`);
      await page.click('.zone-summary .status-item[data-status="error"]');
      await page.waitFor(() => document.querySelector('.zone-tabs .tab[aria-selected="true"]')?.dataset.tab === 'problems', { message: 'the Problems tab' });
      const problems = await page.evaluate(() => ({
        severities: [...new Set([...document.querySelectorAll('.zone-problems-all .zone-problem')].map((p) => p.dataset.severity))],
        pressed: document.querySelector('.zone-summary .status-item[data-status="error"]').getAttribute('aria-pressed'),
        hash: location.hash
      }));
      assertEqual(problems, { severities: ['error'], pressed: 'true', hash: '#/zone?tab=problems' }, 'the errors only');
      await page.click('.zone-summary .status-item[data-status="error"]');
      await page.waitFor(() => document.querySelectorAll('.zone-problems-all .zone-problem[data-severity="warn"]').length > 0, { message: 'every problem again' });
      await page.click('.zone-summary .status-item[data-status="names"]');
      await page.waitFor(() => document.querySelector('.zone-tabs .tab[aria-selected="true"]')?.dataset.tab === 'records', { message: 'the Records tab' });
      await shot(page, 'migrate-zone-result-desktop-light-en');
    });

    await run.step('Zone File: Copy summary with ¶ and Export ▾ — Convert, Print, then Forget, last', async () => {
      assertEqual(await actionsRow(page, '.zone-summary'), ['summary+plain', 'menu:export'], 'no Copy link: nothing of a file goes into a URL');
      assertEqual(await menuKeys(page, 'export', '.zone-summary'), ['zone-open-convert-menu', 'print', 'zone-forget'], 'Export ▾, Forget last');
    });

    await run.step('DNS change request: the editor stays whole; a warning in the status summary brings the problems into view; Copy summary with ¶, Copy link', async () => {
      await open(page, CHANGE_LINK);
      await page.waitFor(() => !!document.querySelector('.chg-result .status-item[data-status="warn"]'), { message: 'the change and its warning' });
      const info = await templateInfo(page, PAGES.change);
      assert(!info.compact, 'an editor\'s form stays whole');
      const head = await page.evaluate(() => ({
        title: document.querySelector('.chg-result .result-title').textContent,
        next: document.querySelector('.chg-result [data-role="change-global"]')?.getAttribute('href') || null
      }));
      assert(head.title.includes(`_acme-challenge.${APEX}`), head.title);
      assertEqual(head.next, `#/global?name=_acme-challenge.${APEX}&type=TXT`, 'next step: Global DNS for the record');
      assertEqual(await actionsRow(page, '.chg-result'), ['summary+plain', 'copy-link'], 'the actions, in order');
      await page.click('.chg-result .status-item[data-status="warn"]');
      await page.waitFor(() => document.activeElement?.classList.contains('chg-problems-card'), { message: 'the problems, focused' });
      await stubClipboard(page);
      await resultAction(page, '[data-action="copy-link"]', '.chg-result');
      await page.waitFor(() => window.__clip.length === 1, { message: 'Copy link' });
      assert(/#\/change\/check\?z=example\.com&r=has\+_acme-challenge\+TXT\+/.test((await takeClipboard(page))[0]), 'the change\'s check link');
    });

    await run.step('the check page: its heading; the headline as the title above 300 px with the sets live; Copy summary with ¶, Copy link', async () => {
      await open(page, CHECK_LINK);
      await page.waitFor(CHECK_DONE, { timeout: 20000, message: 'the check done' });
      const head = await page.evaluate(() => ({
        h1: document.querySelector('h1.page-title').textContent,
        headline: document.querySelector('.chg-hero .chg-check-head-wrap').dataset.headline,
        key: document.querySelector('.chg-hero .result-key').textContent,
        top: Math.round(document.querySelector('.chg-hero').getBoundingClientRect().top + window.scrollY)
      }));
      assertEqual([head.h1, head.headline, head.key], ['Is the change live?', 'done', '1/1'], 'the heading, the headline, the sets live');
      assert(head.top < 300, `the result header near the top: ${head.top}`);
      assertEqual(await actionsRow(page, '.chg-hero'), ['summary+plain', 'copy-link'], 'the actions, in order');
      await stubClipboard(page);
      await resultAction(page, '[data-action="copy-link"]', '.chg-hero');
      await page.waitFor(() => window.__clip.length === 1, { message: 'Copy link' });
      assert((await takeClipboard(page))[0].endsWith(CHECK_LINK), 'the check\'s own link');
    });

    await run.step('a page that is left takes back its phone-layout listeners (its run bar\'s and its actions\'): nothing keeps it alive', async () => {
      await gotoRoute(page, '#/about');
      const base = await page.evaluate(() => window.__phoneListeners);
      // The results stay with their pages (the check page reopens on its link).
      for (const [route, head, least] of [['#/global', '.glb-summary', 2], ['#/retire', '.retire-head', 2], ['#/zone', '.zone-summary', 1],
        ['#/change', '.chg-result', 2], [CHECK_LINK, '.chg-hero', 1], ['#/retire/compare', '.oc-card', 1]]) {
        await open(page, route);
        await page.waitFor((sel) => !!document.querySelector(sel), { args: [head], timeout: 10000, message: `${route}: its result` });
        const on = await page.evaluate(() => window.__phoneListeners);
        assert(on >= base + least, `${route}: its run bar and its actions follow the phone layout (${base} → ${on})`);
        await gotoRoute(page, '#/about');
        assertEqual(await page.evaluate(() => window.__phoneListeners), base, `${route}: none left once it is left`);
      }
    });

    await run.step('desktop: no missing keys; no console errors, exceptions or CSP violations', async () => {
      await assertNoMissingKeys(page);
      await assertClean(page, 'desktop', origin);
    });

    run.group('Phones');
    await run.step('375×812 (Turkish, dark): Copy summary alone in the row, the rest behind "⋯" — Zone File\'s Forget last; no horizontal scroll', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      for (const [route, head] of [['#/global', '.glb-summary'], ['#/retire', '.retire-head'], ['#/zone', '.zone-summary'], ['#/change', '.chg-result'], [CHECK_LINK, '.chg-hero']]) {
        await open(page, route);
        await page.waitFor((sel) => !!document.querySelector(`${sel} .result-actions`), { args: [head], timeout: 10000, message: `${route}: its result` });
        assertEqual(await actionsRow(page, head), ['summary', 'menu:more'], `${route}: Copy summary, ⋯`);
        await assertNoHorizontalScroll(page, `${route} 375 tr dark`);
      }
      await open(page, '#/zone');
      await page.waitFor(() => !!document.querySelector('.zone-summary .result-actions'), { message: 'the zone' });
      const items = await openResultMenu(page, 'more', '.zone-summary');
      assertEqual([items[0], items[items.length - 1]], ['Düz metin olarak kopyala', 'Unut'], `plain text first, Forget last: ${items.join(' | ')}`);
      await page.press('Escape');
      await shot(page, 'migrate-zone-result-375-dark-tr');
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    const fresh = await openPage(browser, server, { width: 320, height: 700, mobile: true });
    pages.push({ ...fresh, where: 'phone' });
    const phone = fresh.page;
    await phone.emulateMedia({ 'prefers-color-scheme': 'light' });
    await setLangUi(phone, 'en');

    await run.step('320 px (English, light): no horizontal scroll on the six pages, empty or with a result', async () => {
      for (const route of ['#/change', '#/global', '#/zone', '#/retire', '#/retire/compare']) {
        await open(phone, route);
        await assertNoHorizontalScroll(phone, `${route} 320 empty`);
      }
      await open(phone, GLOBAL_LINK);
      await phone.waitFor(GLOBAL_DONE, { timeout: 30000, message: 'global check done' });
      await assertNoHorizontalScroll(phone, 'global 320 result');
      await phone.click('.glb-tabs .tab[data-tab="resolvers"]');
      await assertNoHorizontalScroll(phone, 'global 320 resolvers tab');
      await open(phone, RETIRE_LINK);
      await phone.waitFor(() => !!document.querySelector('[data-action="retire-link-start"]'), { message: 'the ready prompt' });
      await assertNoHorizontalScroll(phone, 'retire 320 prompt');
      await phone.click('[data-action="retire-link-start"]');
      await phone.waitFor(RETIRE_DONE, { timeout: 30000, message: 'retire check done' });
      await assertNoHorizontalScroll(phone, 'retire 320 result');
      await open(phone, '#/retire/compare');
      await assertNoHorizontalScroll(phone, 'compare 320 filled');
      await open(phone, '#/zone');
      await phone.click('[data-sample="cloudflare"]');
      await phone.waitFor(() => !!document.querySelector('.zone-summary .zone-status'), { message: 'the zone' });
      await assertNoHorizontalScroll(phone, 'zone 320 result');
      await open(phone, CHANGE_LINK);
      await phone.waitFor(() => !!document.querySelector('.chg-result .result-actions'), { message: 'the change' });
      await assertNoHorizontalScroll(phone, 'change 320 result');
      await open(phone, CHECK_LINK);
      await phone.waitFor(CHECK_DONE, { timeout: 20000, message: 'the check done' });
      await assertNoHorizontalScroll(phone, 'check 320 result');
      await shot(phone, 'migrate-check-320-light-en');
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
