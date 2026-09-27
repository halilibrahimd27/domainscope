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
 *   - back on Domain Health, the report is still there with "Result from <time>" (the URL with
 *     `run=0`) and no new query; a language switch keeps both; "Run again" checks again and the
 *     note goes;
 *   - a certificate loaded in SSL Targets shows in the Certificate view without a note until that
 *     view kept it, and then without "Run again" (a file);
 *   - a lookup of www.example.com makes that the target: Domain Health gets it filled in over its
 *     kept report of example.com, which shows with its note (Copy link shares the report, and a
 *     bare route later brings it back under its own params); the lookup comes back after a trip
 *     too (also in Turkish);
 *   - the second round: after Domain Health for shop.example.com, DNS Lookup and Bulk Resolve get
 *     it filled in over their kept results, which still show with the note; Bulk's "Run again"
 *     resolves the kept job's names;
 *     the same target run again (after a Bulk job about several names) is newer than that job,
 *     and the Bulk Resolve link says so at once;
 *   - the chip's × clears the target (focus stays on the page); "Delete all local data" forgets
 *     the target and the kept results, Bulk Resolve's list and job too (also with Bulk Resolve
 *     on screen: the tool opens again, bare);
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
const LOOKUP_DONE = "document.querySelectorAll('.lkp-cards [data-state]:not([data-state=\"pending\"])').length > 0 && !document.querySelector('.lkp-cards [data-state=\"pending\"]')";

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

/**
 * What the shell shows: the chip, the kept-result note (its text and its "Run again", or null),
 * the nav links' hrefs, the route.
 */
function shellInfo() {
  const chip = document.querySelector('[data-role="target-chip"]');
  const note = document.querySelector('.page-kept:not([hidden]) .kept-note');
  const rerun = note ? note.querySelector('[data-action="kept-rerun"]') : null;
  const hrefs = {};
  document.querySelectorAll('#app-nav a.nav-link[data-view]').forEach((a) => { hrefs[a.dataset.view] = a.getAttribute('href'); });
  return {
    chip: chip && !chip.closest('[hidden]') ? chip.querySelector('.target-chip-value').textContent : null,
    chipKind: chip ? chip.dataset.kind : null,
    note: note ? note.querySelector('.kept-note-text').textContent.replace(/\s+/g, ' ').trim() : null,
    noteKind: note ? note.dataset.kept : null,
    rerun: rerun ? rerun.textContent : null,
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

/** Press the page header's "Copy link" and return the hash it copied (the clipboard is stubbed in the page). */
async function copiedLink(page) {
  await page.evaluate(() => {
    window.__copied = null;
    Object.defineProperty(navigator.clipboard, 'writeText', { configurable: true, value: async (text) => { window.__copied = text; } });
  });
  await page.click('.page-actions .copy-btn');
  await page.waitFor(() => window.__copied !== null, { message: 'Copy link' });
  return page.evaluate(() => new URL(window.__copied).hash);
}

/** Wait for a Bulk Resolve job other than `prevId` to end. */
async function waitJobDone(page, prevId) {
  await page.waitFor((prev) => {
    const el = document.querySelector('.bulk-results');
    return el && el.dataset.job !== prev && ['done', 'cancelled', 'error'].includes(el.querySelector('.bulk-progress').dataset.status);
  }, { args: [prevId || ''], timeout: 30000, message: 'bulk job finished' });
}

/** Settings › "Delete all local data", confirmed; `hint`: check that the hint names the page session. */
async function deleteAllLocalData(page, { hint = false } = {}) {
  await page.click('[data-control="settings"]');
  try {
    await page.waitForSelector('dialog.modal[open] .settings-danger');
    if (hint) {
      const text = await page.evaluate(() => document.querySelector('dialog.modal[open] .settings-danger .field-hint').textContent);
      assert(/forgets the current target and the results kept in this tab/.test(text), `hint: ${text}`);
    }
    await page.click('dialog.modal[open] .settings-danger .btn-danger');
    await page.waitFor(() => document.querySelectorAll('dialog.modal[open]').length === 2, { message: 'confirmation' });
    await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open]')].find((d) => !d.querySelector('.settings-danger')).querySelector('.btn-danger').click());
    await page.waitFor(() => !document.querySelector('dialog.modal[open]'), { message: 'dialogs closed' });
  } finally {
    await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
  }
  // The tool on screen opens again on its bare route once every listener has forgotten.
  await page.waitFor(() => !location.hash.includes('?') && document.querySelector('#page-body')?.childElementCount > 0
    && !document.querySelector('#page-body .page-loading'), { message: 'the tool opened again' });
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
      assertEqual(s.hash, `#/health?domain=${APEX}&run=0`, 'the URL shows the kept result, and a reload only fills the form');
      assert(/^Result from \d{1,2}:\d{2}(\s[AP]M)?$/.test(s.note), `note: ${s.note}`);
      assertEqual([s.noteKind, s.rerun], ['result', 'Run again'], 'note kind + Run again');
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
      assert(/^Önceki sonuç: \d{1,2}:\d{2}$/.test(s.note), `TR note: ${s.note}`);
      assertEqual(s.rerun, 'Yeniden çalıştır', 'TR Run again');
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

    await run.step('a certificate loaded in SSL Targets: the Certificate view has no note until it kept it (a file: no Run again)', async () => {
      await clickNav(page, 'scan');
      await page.click('[data-action="cert-sample"]');
      await page.waitFor(() => !!document.querySelector('[data-action="cert-details"]'), { message: 'sample certificate in SSL Targets' });
      await clickNav(page, 'cert');
      await page.waitFor(() => !!document.querySelector('.cert-content .cert-source-note'), { message: 'the shared certificate' });
      assertEqual((await page.evaluate(shellInfo)).note, null, 'first visit with it: no "Result from"');
      await clickNav(page, 'lookup');
      await clickNav(page, 'cert');
      const s = await page.evaluate(shellInfo);
      assert(/^Result from /.test(s.note || ''), `kept on leave: ${s.note}`);
      assertEqual([s.rerun, s.hash], [null, '#/cert'], 'a file has nothing to run again; its link is bare');
      await assertQuiet(page, queries, 'certificate');
    });

    await run.step('a lookup makes its name the target: Domain Health gets it filled in over its kept report, which still shows', async () => {
      await clickNav(page, 'lookup');
      await page.type('[data-role="lookup-name"]', `www.${APEX}`);
      await page.click('.lkp-form [data-action="run"]');
      await page.waitFor(LOOKUP_DONE, { timeout: 15000, message: 'lookup done' });
      const s = await page.evaluate(shellInfo);
      assertEqual([s.chip, s.chipKind], [`www.${APEX}`, 'host'], 'chip follows the lookup');
      assertEqual(s.hrefs.health, `#/health?domain=www.${APEX}&run=0`, 'Domain Health: the newer target, not its older report');
      assertEqual(s.hrefs.global, `#/global?name=www.${APEX}&run=0`, 'Global DNS: the new target');
      assertEqual(s.hrefs.cert, `#/cert?host=www.${APEX}&run=0`, 'the Certificate view: the newer target for its "No file?" field');
      await shot(page, opts, 'carry-desktop-light-en-lookup-run');
      queries = await dnsCount(page);
      await clickNav(page, 'health');
      await page.waitFor(HEALTH_DONE, { timeout: 5000, message: 'kept report' });
      const carried = await page.evaluate(() => ({
        domain: document.querySelector('[data-role="health-domain"]').value,
        report: document.querySelector('.hlt-hero-domain')?.textContent || null
      }));
      assertEqual(carried, { domain: `www.${APEX}`, report: APEX }, 'the new target in the box, the kept report of example.com under it');
      const s2 = await page.evaluate(shellInfo);
      assertEqual(s2.hash, `#/health?domain=www.${APEX}&run=0`, 'the URL keeps the target (a reload only fills the form)');
      assert(/^Result from /.test(s2.note || '') && s2.rerun === 'Run again', `note: ${JSON.stringify(s2)}`);
      assertEqual(await copiedLink(page), `#/health?domain=${APEX}`, 'Copy link shares the report on screen, not the box');
      await assertQuiet(page, queries, 'health under the carried target');
      await shot(page, opts, 'carry-desktop-light-en-health-carried');
      // Left without a run, the report is kept under its own params, not the box's.
      await clickNav(page, 'lookup');
      await gotoRoute(page, '#/health');
      await page.waitFor(HEALTH_DONE, { timeout: 5000, message: 'kept report' });
      const back = await page.evaluate(shellInfo);
      assertEqual(back.hash, `#/health?domain=${APEX}&run=0`, 'the bare route brings it back under example.com');
      assertEqual(await page.evaluate(() => document.querySelector('.hlt-hero-domain').textContent), APEX, 'still example.com');
      assert(back.note, 'with the note');
      await assertQuiet(page, queries, 'health kept again');
    });

    await run.step('the lookup comes back too (Turkish), with run=0 in its URL and no query', async () => {
      await setLangUi(page, 'tr');
      await clickNav(page, 'lookup');
      const info = await page.evaluate(() => ({
        name: document.querySelector('[data-role="lookup-name"]').value,
        cards: document.querySelectorAll('.lkp-cards .card').length,
        hash: location.hash
      }));
      assertEqual(info.name, `www.${APEX}`, 'form');
      assert(info.cards > 0, 'answers kept');
      assert(info.hash.startsWith(`#/lookup?name=www.${APEX}&type=`) && info.hash.endsWith('&run=0'), `hash: ${info.hash}`);
      assert(/^Önceki sonuç/.test((await page.evaluate(shellInfo)).note || ''), 'TR note');
      await assertQuiet(page, queries, 'lookup kept');
      await shot(page, opts, 'carry-desktop-light-tr-lookup-kept');
      await setLangUi(page, 'en');
    });

    await run.step('the second round: after shop.example.com, DNS Lookup and Bulk Resolve get it over their kept results, still shown', async () => {
      await clickNav(page, 'bulk');
      await page.type('[data-role="bulk-input"]', APEX);
      await page.click('[data-action="bulk-run"]');
      await waitJobDone(page, '');
      const firstJob = await page.evaluate(() => document.querySelector('.bulk-results').dataset.job);
      await gotoRoute(page, `#/health?domain=shop.${APEX}`);
      await page.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d && !document.querySelector('[data-action="run"]').hidden,
        { args: [`shop.${APEX}`], timeout: 30000, message: 'health report of shop' });
      const s = await page.evaluate(shellInfo);
      assertEqual(s.chip, `shop.${APEX}`, 'chip');
      assertEqual(s.hrefs.lookup, `#/lookup?name=shop.${APEX}&run=0`, 'DNS Lookup: the new target over its kept answers');
      assertEqual(s.hrefs.bulk, `#/bulk?names=shop.${APEX}&run=0`, 'Bulk Resolve: the new target over its kept job');
      queries = await dnsCount(page);
      await clickNav(page, 'lookup');
      const lk = await page.evaluate(() => ({ name: document.querySelector('[data-role="lookup-name"]').value, results: !document.querySelector('.lkp-results').hidden }));
      assertEqual(lk, { name: `shop.${APEX}`, results: true }, 'DNS Lookup: the new name in the box over its kept answers, nothing run');
      const lks = await page.evaluate(shellInfo);
      assertEqual(lks.hash, `#/lookup?name=shop.${APEX}&run=0`, 'the URL keeps the target');
      assert(/^Result from /.test(lks.note || '') && lks.rerun === 'Run again', `lookup note: ${JSON.stringify(lks)}`);
      assert((await copiedLink(page)).startsWith(`#/lookup?name=www.${APEX}&type=`), 'Copy link shares the kept answers');
      await clickNav(page, 'bulk');
      const bk = await page.evaluate(() => ({
        text: document.querySelector('[data-role="bulk-input"]').value.trim(),
        job: document.querySelector('.bulk-results')?.dataset.job || null
      }));
      assertEqual(bk.text, `shop.${APEX}`, 'the box held the last job\'s names, so it takes the new target');
      assertEqual(bk.job, firstJob, 'the kept job is still shown');
      const note = await page.evaluate(shellInfo);
      assert(/^Result from /.test(note.note || '') && note.rerun === 'Run again', `note: ${JSON.stringify(note)}`);
      await assertQuiet(page, queries, 'second round');
      await page.click('[data-action="kept-rerun"]');
      await waitJobDone(page, firstJob);
      const again = await page.evaluate(() => document.querySelector('[data-role="bulk-input"]').value.trim());
      assertEqual(again, APEX, '"Run again" resolves the kept job\'s names, not the box');
      assertEqual((await page.evaluate(shellInfo)).note, null, 'note gone');
      queries = await dnsCount(page);
    });

    await run.step('the chip × clears the target: bare links again (kept results stay), focus on the page', async () => {
      await page.evaluate(() => document.querySelector('[data-action="target-clear"]').focus());
      await page.press('Enter');
      await page.waitFor(() => !document.querySelector('[data-role="target-chip"]'), { message: 'chip gone' });
      const s = await page.evaluate(shellInfo);
      assertEqual(s.hrefs.global, '#/global', 'Global DNS bare');
      assertEqual(s.hrefs.health, `#/health?domain=shop.${APEX}&run=0`, 'Domain Health keeps its result');
      const focus = await page.evaluate(() => document.activeElement?.id);
      assertEqual(focus, 'page-title', 'focus on the page title, not <body>');
    });

    await run.step('"Delete all local data" forgets the target and every kept result, Bulk Resolve\'s too', async () => {
      await gotoRoute(page, `#/lookup?name=${APEX}&type=A`);
      await page.waitFor(LOOKUP_DONE, { timeout: 15000, message: 'lookup' });
      assertEqual((await page.evaluate(shellInfo)).chip, APEX, 'target set');
      await deleteAllLocalData(page, { hint: true });
      const s = await page.evaluate(shellInfo);
      assertEqual(s.chip, null, 'no chip');
      assertEqual([s.hrefs.health, s.hrefs.global, s.hrefs.subdomains, s.hrefs.bulk], ['#/health', '#/global', '#/subdomains', '#/bulk'], 'bare links');
      assertEqual([s.hash, s.note], ['#/lookup', null], 'the tool on screen opens again, bare');
      assertEqual(await page.evaluate(() => document.querySelector('.lkp-results').hidden), true, 'its answers are gone');
      queries = await dnsCount(page);
      await clickNav(page, 'health');
      assertEqual(await page.evaluate(() => !!document.querySelector('.hlt-hero')), false, 'no kept report');
      await clickNav(page, 'bulk');
      const bk = await page.evaluate(() => ({
        text: document.querySelector('[data-role="bulk-input"]').value,
        results: !!document.querySelector('.bulk-results'),
        intro: !!document.querySelector('.bulk-intro')
      }));
      assertEqual(bk, { text: '', results: false, intro: true }, 'Bulk Resolve: no list, no job');
      assertEqual((await page.evaluate(shellInfo)).note, null, 'no note');
      await assertQuiet(page, queries, 'after deleting');
    });

    await run.step('"Delete all local data" with Bulk Resolve on screen: its job and note go at once', async () => {
      await page.type('[data-role="bulk-input"]', `www.${APEX}`);
      await page.click('[data-action="bulk-run"]');
      await waitJobDone(page, '');
      await clickNav(page, 'lookup');
      await clickNav(page, 'bulk');
      assert((await page.evaluate(shellInfo)).note, 'kept job with its note');
      await deleteAllLocalData(page);
      await page.waitFor(() => !document.querySelector('.bulk-results') && !!document.querySelector('.bulk-intro'), { message: 'job gone' });
      const s = await page.evaluate(shellInfo);
      assertEqual([s.note, s.hash, s.chip], [null, '#/bulk', null], 'no note, bare route, no chip');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="bulk-input"]').value), '', 'no list');
      await assertQuiet(page, await dnsCount(page), 'after deleting on Bulk Resolve');
    });

    await run.step('the same target run again is newer than a job about several names: the Bulk Resolve link follows at once', async () => {
      await gotoRoute(page, `#/lookup?name=${APEX}&type=A`);
      await page.waitFor(LOOKUP_DONE, { timeout: 15000, message: 'lookup' });
      await clickNav(page, 'bulk');
      await page.type('[data-role="bulk-input"]', `www.${APEX}\nexample.net`);
      await page.click('[data-action="bulk-run"]');
      await waitJobDone(page, '');
      const job = await page.evaluate(() => document.querySelector('.bulk-results').dataset.job);
      assertEqual((await page.evaluate(shellInfo)).chip, APEX, 'two names without one domain: the target stays');
      await clickNav(page, 'health');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="health-domain"]').value), APEX, 'Domain Health filled in');
      assertEqual((await page.evaluate(shellInfo)).hrefs.bulk, '#/bulk', 'the job is newer than the target: back to it');
      // Run on the tool on screen (no route change follows that would redraw the nav).
      await page.click('[data-action="run"]');
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'health report' });
      const s = await page.evaluate(shellInfo);
      assertEqual(s.chip, APEX, 'the same target');
      assertEqual(s.hrefs.bulk, `#/bulk?names=${APEX}&run=0`, 'the target is newer now: the link carries it without a reload of the nav');
      queries = await dnsCount(page);
      await clickNav(page, 'bulk');
      const bk = await page.evaluate(() => ({
        text: document.querySelector('[data-role="bulk-input"]').value.trim(),
        job: document.querySelector('.bulk-results')?.dataset.job || null
      }));
      assertEqual(bk, { text: APEX, job }, 'filled in over the last job\'s names; the job still shown');
      await assertQuiet(page, queries, 'same target again');
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
              noteRight: Math.round(r('.page-kept .kept-note')?.right || 0),
              vw: document.documentElement.clientWidth
            };
          });
          assertEqual(layout.brandText, 'none', 'brand name hidden while a target shows');
          assert(layout.chip && layout.chip.width > 80 && layout.chip.right <= layout.actionsLeft, `chip fits before the controls: ${JSON.stringify(layout)}`);
          assertEqual([layout.value, layout.note], [APEX, true], 'chip value + note');
          assert(layout.noteRight <= layout.vw, `the note fits: ${JSON.stringify(layout)}`);
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
