#!/usr/bin/env node
/**
 * carry.e2e.mjs — the page session in a real headless browser, OFFLINE: the current target that
 * the tools carry to each other and the result each tool keeps (lib/session.js, app.js).
 *
 *   node tests/e2e/carry.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * example.com is answered inside the page (scan.e2e.mjs zoneHandoffScript: every other request
 * is blocked) and a CDP network guard proves that nothing leaves it. On a 1440 px desktop:
 *   - Domain Health runs for example.com: the header chip shows it and every nav link that takes
 *     a domain carries it (`run=0`);
 *   - DNS Lookup opens with example.com filled in and sends nothing; so do Global DNS,
 *     Subdomains, SSL Targets, Bulk Resolve and the Certificate view's "No file?" field; IP Intel
 *     and the Zone File URL get nothing;
 *   - back on Domain Health, the report is still there with "Result from <time>" and no new
 *     query; a language switch keeps both; "Run again" checks again and the note goes;
 *   - a lookup of www.example.com makes that the target, while Domain Health keeps its own
 *     result; the lookup comes back after a trip too (also in Turkish);
 *   - the chip's × clears the target (focus stays on the page); "Delete all local data" forgets
 *     the target and the kept results;
 *   - a carried link opened in a new tab only fills the form.
 * Then at 375 px (light / dark, English / Turkish): the chip in place of the brand name, the note
 * under the title, no horizontal scroll. Fails on console errors, exceptions, CSP violations
 * and missing i18n keys.
 */

import path from 'node:path';
import { mkdir } from 'node:fs/promises';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  cliOptions, createRunner, assert, assertEqual, sleep, waitReady, gotoRoute, setLangUi, assertNoHorizontalScroll,
  shot, assertClean, assertNoMissingKeys, zoneHandoffScript, BASE, SHOTS
} from './scan.e2e.mjs';

const opts = cliOptions();
const run = createRunner();

const APEX = 'example.com';
const SOA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026092701, refresh: 3600, retry: 900, expire: 1209600, minimum: 300 };
/** example.com as the page sees it (documentation addresses only). */
const ZONE = {
  'example.com': {
    A: ['192.0.2.80'], SOA: [SOA], NS: ['ns1.example.com', 'ns2.example.com'],
    MX: [{ preference: 10, exchange: 'mx.example.com' }],
    TXT: [['v=spf1 mx -all']]
  },
  'www.example.com': { A: ['192.0.2.81'] },
  'ns1.example.com': { A: ['192.0.2.53'] },
  'ns2.example.com': { A: ['198.51.100.53'] },
  'mx.example.com': { A: ['192.0.2.25'] },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
};

const HEALTH_DONE = "!!document.querySelector('.hlt-hero') && !document.querySelector('[data-action=\"run\"]').hidden";

/** Fail (and record) every https request that would leave the page (the fake DNS answers in-page). */
async function networkGuard(page) {
  const hits = [];
  page.conn.on('Fetch.requestPaused', (p) => {
    hits.push(p.request.url);
    page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://*' }] });
  return hits;
}

/** What the shell shows: the chip, the kept-result note, the nav links' hrefs, the route. */
function shellInfo() {
  const chip = document.querySelector('[data-role="target-chip"]');
  const note = document.querySelector('.page-kept:not([hidden]) .kept-note');
  const hrefs = {};
  document.querySelectorAll('#app-nav a.nav-link[data-view]').forEach((a) => { hrefs[a.dataset.view] = a.getAttribute('href'); });
  return {
    chip: chip && !chip.closest('[hidden]') ? chip.querySelector('.target-chip-value').textContent : null,
    chipKind: chip ? chip.dataset.kind : null,
    note: note ? note.textContent.replace(/\s+/g, ' ').trim() : null,
    noteKind: note ? note.dataset.kept : null,
    rerun: !!(note && note.querySelector('[data-action="kept-rerun"]')),
    hrefs,
    hash: location.hash,
    view: document.documentElement.dataset.view
  };
}

const dnsCount = (page) => page.evaluate(() => window.__zoneDnsQueries);

/** Follow a nav link (a real click) and wait for its view. */
async function clickNav(page, view) {
  await page.click(`#app-nav a.nav-link[data-view="${view}"]`);
  await page.waitFor((v) => document.documentElement.dataset.view === v
    && document.querySelector('#page-body')?.dataset.view === v
    && document.querySelector('#page-body').childElementCount > 0
    && !document.querySelector('#page-body .page-loading'), { args: [view], message: `view ${view}`, timeout: 15000 });
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

/** Nothing more is sent for a while (in-page DNS count unchanged). */
async function assertQuiet(page, before, where) {
  await sleep(600);
  assertEqual(await dnsCount(page), before, `${where}: no DNS query`);
}

async function desktop(browser, server) {
  run.group('Carry the target, keep the result (1440 px, offline)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const netHits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(APEX, ZONE) });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  try {
    await run.step('a fresh page has no target, and the nav links are bare', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      const s = await page.evaluate(shellInfo);
      assertEqual([s.chip, s.note], [null, null], 'no chip, no note');
      assertEqual([s.hrefs.lookup, s.hrefs.health, s.hrefs.zone], ['#/lookup', '#/health', '#/zone'], 'bare links');
    });

    let queries = 0;
    await run.step('Domain Health runs: the chip shows the domain and the links carry it (run=0)', async () => {
      await gotoRoute(page, `#/health?domain=${APEX}`);
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'health report' });
      queries = await dnsCount(page);
      assert(queries > 5, `the check asked DNS (${queries})`);
      const s = await page.evaluate(shellInfo);
      assertEqual([s.chip, s.chipKind, s.note], [APEX, 'domain', null], 'chip, no note for a fresh result');
      assertEqual(s.hrefs.lookup, `#/lookup?name=${APEX}&run=0`, 'DNS Lookup link');
      assertEqual(s.hrefs.global, `#/global?name=${APEX}&run=0`, 'Global DNS link');
      assertEqual(s.hrefs.subdomains, `#/subdomains?domain=${APEX}&run=0`, 'Subdomains link');
      assertEqual(s.hrefs.scan, `#/scan?domain=${APEX}&run=0`, 'SSL Targets link');
      assertEqual(s.hrefs.bulk, `#/bulk?names=${APEX}&run=0`, 'Bulk Resolve link');
      assertEqual(s.hrefs.cert, `#/cert?host=${APEX}&run=0`, 'Certificate link');
      assertEqual([s.hrefs.ip, s.hrefs.zone, s.hrefs.inventory], ['#/ip', '#/zone', '#/inventory'], 'no domain for IP Intel, Zone File, Servers');
      assertEqual(s.hrefs.health, `#/health?domain=${APEX}`, 'the tool on screen links to itself');
      const chipTitle = await page.evaluate(() => document.querySelector('[data-role="target-chip"]').title);
      assert(/nothing runs until you press/.test(chipTitle), `chip title: ${chipTitle}`);
      await shot(page, opts, 'carry-desktop-light-en-health');
    });

    await run.step('DNS Lookup opens with the domain filled in and queries nothing', async () => {
      await clickNav(page, 'lookup');
      const info = await page.evaluate(() => ({
        name: document.querySelector('[data-role="lookup-name"]').value,
        results: !document.querySelector('.lkp-results').hidden,
        focus: document.activeElement?.id
      }));
      assertEqual([info.name, info.results, info.focus], [APEX, false, 'page-title'], 'filled in, no results, focus on the title');
      const s = await page.evaluate(shellInfo);
      assertEqual([s.hash, s.note, s.chip], [`#/lookup?name=${APEX}&run=0`, null, APEX], 'route, no note');
      await assertQuiet(page, queries, 'DNS Lookup');
      await shot(page, opts, 'carry-desktop-light-en-lookup-filled');
    });

    await run.step('back on Domain Health: the kept report and "Result from <time>", no new query', async () => {
      await clickNav(page, 'health');
      await page.waitFor(HEALTH_DONE, { timeout: 5000, message: 'kept report' });
      const s = await page.evaluate(shellInfo);
      assertEqual(s.hash, `#/health?domain=${APEX}`, 'the URL shows the kept result');
      assert(/^Result from \d{1,2}:\d{2}(\s[AP]M)?\s*·\s*Run again$/.test(s.note), `note: ${s.note}`);
      assertEqual([s.noteKind, s.rerun], ['result', true], 'note kind + Run again');
      const hero = await page.evaluate(() => document.querySelector('.hlt-hero-domain').textContent);
      assertEqual(hero, APEX, 'the report of example.com');
      await page.waitFor(() => [...document.querySelectorAll('body > .sr-only[aria-live="polite"]')]
        .some((r) => /^Domain Health · Result from /.test(r.textContent)), { timeout: 3000, message: 'the kept result is announced with the tool' });
      await assertQuiet(page, queries, 'kept report');
      await assertNoHorizontalScroll(page, 'health kept');
      await shot(page, opts, 'carry-desktop-light-en-health-kept');
    });

    await run.step('a language switch keeps the report and the note', async () => {
      await setLangUi(page, 'tr');
      await page.waitFor(HEALTH_DONE, { timeout: 5000, message: 'report after the switch' });
      const s = await page.evaluate(shellInfo);
      assert(/^Önceki sonuç: \d{1,2}:\d{2}\s*·\s*Yeniden çalıştır$/.test(s.note), `TR note: ${s.note}`);
      assertEqual(s.chip, APEX, 'chip kept');
      await assertQuiet(page, queries, 'language switch');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await shot(page, opts, 'carry-desktop-dark-tr-health-kept');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      assert((await page.evaluate(shellInfo)).note, 'note after switching back');
    });

    await run.step('"Run again" checks again; the note goes and the focus stays on the page', async () => {
      await page.click('[data-action="kept-rerun"]');
      await page.waitFor((n) => window.__zoneDnsQueries > n, { args: [queries], message: 'new queries' });
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'report again' });
      const s = await page.evaluate(shellInfo);
      assertEqual(s.note, null, 'note gone');
      const focus = await page.evaluate(() => (document.activeElement === document.body ? 'body' : document.activeElement.id || document.activeElement.className));
      assert(focus !== 'body', `focus not lost to <body> (${focus})`);
      queries = await dnsCount(page);
    });

    await run.step('the other tools that take a domain get it filled in and send nothing', async () => {
      const fields = {
        global: '[data-role="global-name"]',
        subdomains: '[data-role="sub-domain"]',
        scan: '[data-role="scan-domains"]',
        bulk: '[data-role="bulk-input"]',
        cert: '[data-role="ct-host"]'
      };
      for (const [view, sel] of Object.entries(fields)) {
        await clickNav(page, view);
        const value = await page.evaluate((s) => document.querySelector(s)?.value.trim(), sel);
        assertEqual(value, APEX, `${view} filled in`);
        const hash = await page.evaluate(() => location.hash);
        assert(hash.endsWith('run=0'), `${view}: ${hash}`);
      }
      assertEqual(await page.evaluate(() => !!document.querySelector('.sub-link-prompt:not([hidden])')), false, 'Subdomains: no start prompt either');
      await assertQuiet(page, queries, 'the other tools');
      await clickNav(page, 'ip');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="ip-input"]').value), '', 'IP Intel takes no domain');
      await clickNav(page, 'zone');
      assertEqual(await page.evaluate(() => location.hash), '#/zone', 'nothing in the Zone File URL');
    });

    await run.step('a lookup makes its name the target; Domain Health keeps its own result', async () => {
      await clickNav(page, 'lookup');
      await page.type('[data-role="lookup-name"]', `www.${APEX}`);
      await page.click('.lkp-form [data-action="run"]');
      await page.waitFor(() => document.querySelectorAll('.lkp-cards [data-state]:not([data-state="pending"])').length > 0
        && !document.querySelector('.lkp-cards [data-state="pending"]'), { timeout: 15000, message: 'lookup done' });
      const s = await page.evaluate(shellInfo);
      assertEqual([s.chip, s.chipKind], [`www.${APEX}`, 'host'], 'chip follows the lookup');
      assertEqual(s.hrefs.health, `#/health?domain=${APEX}&run=0`, 'Domain Health: back to its kept result');
      assertEqual(s.hrefs.global, `#/global?name=www.${APEX}&run=0`, 'Global DNS: the new target');
      await shot(page, opts, 'carry-desktop-light-en-lookup-run');
      queries = await dnsCount(page);
      await clickNav(page, 'health');
      await page.waitFor(HEALTH_DONE, { timeout: 5000, message: 'kept report' });
      assertEqual(await page.evaluate(() => document.querySelector('.hlt-hero-domain').textContent), APEX, 'still example.com');
      assert((await page.evaluate(shellInfo)).note, 'with the note');
      await assertQuiet(page, queries, 'health kept again');
    });

    await run.step('the lookup comes back too (Turkish), and a same-URL Back restores it without a query', async () => {
      await setLangUi(page, 'tr');
      await clickNav(page, 'lookup');
      const info = await page.evaluate(() => ({
        name: document.querySelector('[data-role="lookup-name"]').value,
        cards: document.querySelectorAll('.lkp-cards .card').length,
        hash: location.hash
      }));
      assertEqual(info.name, `www.${APEX}`, 'form');
      assert(info.cards > 0, 'answers kept');
      assert(info.hash.startsWith(`#/lookup?name=www.${APEX}&type=`) && !info.hash.includes('run=0'), `hash: ${info.hash}`);
      assert(/^Önceki sonuç/.test((await page.evaluate(shellInfo)).note || ''), 'TR note');
      await assertQuiet(page, queries, 'lookup kept');
      await shot(page, opts, 'carry-desktop-light-tr-lookup-kept');
      await setLangUi(page, 'en');
    });

    await run.step('the chip × clears the target: bare links again (kept results stay), focus on the page', async () => {
      await page.evaluate(() => document.querySelector('[data-action="target-clear"]').focus());
      await page.press('Enter');
      await page.waitFor(() => !document.querySelector('[data-role="target-chip"]'), { message: 'chip gone' });
      const s = await page.evaluate(shellInfo);
      assertEqual(s.hrefs.global, '#/global', 'Global DNS bare');
      assertEqual(s.hrefs.health, `#/health?domain=${APEX}&run=0`, 'Domain Health keeps its result');
      const focus = await page.evaluate(() => document.activeElement?.id);
      assertEqual(focus, 'page-title', 'focus on the page title, not <body>');
    });

    await run.step('"Delete all local data" forgets the target and every kept result', async () => {
      await gotoRoute(page, `#/lookup?name=${APEX}&type=A`);
      await page.waitFor(() => document.querySelectorAll('.lkp-cards .card').length > 0 && !document.querySelector('.lkp-cards [data-state="pending"]'), { timeout: 15000, message: 'lookup' });
      assertEqual((await page.evaluate(shellInfo)).chip, APEX, 'target set');
      await page.click('[data-control="settings"]');
      try {
        await page.waitForSelector('dialog.modal[open] .settings-danger');
        const hint = await page.evaluate(() => document.querySelector('dialog.modal[open] .settings-danger .field-hint').textContent);
        assert(/forgets the current target and the results kept in this tab/.test(hint), `hint: ${hint}`);
        await page.click('dialog.modal[open] .settings-danger .btn-danger');
        await page.waitFor(() => document.querySelectorAll('dialog.modal[open]').length === 2, { message: 'confirmation' });
        await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open]')].find((d) => !d.querySelector('.settings-danger')).querySelector('.btn-danger').click());
        await page.waitFor(() => !document.querySelector('dialog.modal[open]'), { message: 'dialogs closed' });
      } finally {
        await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
      }
      const s = await page.evaluate(shellInfo);
      assertEqual(s.chip, null, 'no chip');
      assertEqual([s.hrefs.health, s.hrefs.global, s.hrefs.subdomains], ['#/health', '#/global', '#/subdomains'], 'bare links');
      queries = await dnsCount(page);
      await clickNav(page, 'health');
      assertEqual(await page.evaluate(() => !!document.querySelector('.hlt-hero')), false, 'no kept report');
      await assertQuiet(page, queries, 'after deleting');
    });

    await run.step('nothing left the page; no console errors, CSP violations or missing keys', async () => {
      assertEqual(netHits, [], 'network guard');
      await assertClean(page, 'carry desktop', server.url);
      await assertNoMissingKeys(page);
    });
  } finally {
    await page.close();
  }

  run.group('A carried link opened in a new tab');
  const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const tabHits = await networkGuard(tab);
  await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(APEX, ZONE) });
  try {
    await run.step('#/lookup?name=…&run=0 and #/health?domain=…&run=0 only fill the form', async () => {
      await tab.goto(`${server.url}#/lookup?name=${APEX}&run=0`);
      await waitReady(tab);
      assertEqual(await tab.evaluate(() => document.querySelector('[data-role="lookup-name"]').value), APEX, 'lookup filled');
      await gotoRoute(tab, `#/health?domain=${APEX}&run=0`);
      assertEqual(await tab.evaluate(() => document.querySelector('[data-role="health-domain"]').value), APEX, 'health filled');
      await sleep(600);
      assertEqual(await tab.evaluate(() => window.__zoneDnsQueries), 0, 'no DNS query at all');
      assertEqual(await tab.evaluate(shellInfo).then((s) => s.chip), null, 'no target until something runs');
      assertEqual(tabHits, [], 'network guard');
      await assertClean(tab, 'new tab', server.url);
    });
  } finally {
    await tab.close();
  }
}

async function phone(browser, server) {
  run.group('Phone (375 px): the chip, the note, no horizontal scroll');
  const page = await browser.newPage('about:blank', { width: 375, height: 812, mobile: true });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(APEX, ZONE) });
  try {
    await page.goto(`${server.url}#/about`);
    await waitReady(page);
    for (const lang of ['en', 'tr']) {
      for (const scheme of ['light', 'dark']) {
        await run.step(`${lang} ${scheme}: chip in place of the brand name, the kept note under the title`, async () => {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await setLangUi(page, lang);
          await gotoRoute(page, `#/health?domain=${APEX}`);
          await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'health report' });
          await gotoRoute(page, '#/about');
          await clickNav(page, 'health');
          await page.waitFor(HEALTH_DONE, { timeout: 5000, message: 'kept report' });
          const layout = await page.evaluate(() => {
            const r = (sel) => document.querySelector(sel)?.getBoundingClientRect();
            const chip = r('[data-role="target-chip"]');
            const actions = r('#header-actions');
            return {
              brandText: getComputedStyle(document.querySelector('.brand-text')).display,
              chip: chip && { left: Math.round(chip.left), right: Math.round(chip.right), width: Math.round(chip.width) },
              actionsLeft: Math.round(actions.left),
              value: document.querySelector('.target-chip-value').textContent,
              note: !!document.querySelector('.page-kept:not([hidden]) .kept-note'),
              vw: document.documentElement.clientWidth
            };
          });
          assertEqual(layout.brandText, 'none', 'brand name hidden while a target shows');
          assert(layout.chip && layout.chip.width > 80 && layout.chip.right <= layout.actionsLeft, `chip fits before the controls: ${JSON.stringify(layout)}`);
          assertEqual([layout.value, layout.note], [APEX, true], 'chip value + note');
          await assertNoHorizontalScroll(page, `phone ${lang} ${scheme}`);
          await page.evaluate(() => window.scrollTo(0, 0));
          await shot(page, opts, `carry-phone-${scheme}-${lang}-health-kept`);
        });
      }
    }
    await run.step('phone: no console errors, CSP violations or missing keys', async () => {
      await assertClean(page, 'carry phone', server.url);
      await assertNoMissingKeys(page);
    });
  } finally {
    await page.close();
  }
}

async function main() {
  if (opts.shots) await mkdir(SHOTS, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`Serving ${server.url} — ${version.product}\n`);
  try {
    await desktop(browser, server);
    await phone(browser, server);
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
