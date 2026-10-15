#!/usr/bin/env node
/**
 * wsextras.e2e.mjs — the workspace extras in a real headless browser, OFFLINE (docs/DESIGN.md
 * Appendix C, decisions C6, C5, C7):
 *   - C6: the per-workspace watchlist. Domain portfolio's box starts from it and "Save as this
 *     workspace's watchlist" keeps the box; Home counts it against the registration baseline
 *     ("2 of 4 domains checked in the last 7 days"); it travels in the hand-over file, and a file
 *     from before the part existed still opens;
 *   - C5: the workspace colour, picked in the dialog: a dot in the header, the list and Home, with
 *     3:1 against its surface in light and in dark;
 *   - C7: the attention count on each workspace's row when the dialog opens: a number, never a
 *     domain name (the text of the whole list holds none).
 *
 *   node tests/e2e/wsextras.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 */

import { mkdir } from 'node:fs/promises';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  cliOptions, createRunner, assert, assertEqual, waitReady, setLangUi, shot, assertClean, assertNoMissingKeys, BASE, SHOTS
} from './scan.e2e.mjs';

const opts = cliOptions();
const run = createRunner();

/** Fail (and record) every https request that would leave the page. */
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
 * Seed the workspaces in the page: the registration baseline of `fresh` domains (valid for a year)
 * and `soon` ones (ending in 10 days), both checked a day ago. mode 'default': into the active
 * workspace, with its watchlist; 'beta': into a new workspace "Beta Customer" (red).
 */
const seedWorkspace = (page, mode, fresh, soon) => page.evaluate(async (m, f, so) => {
  const { state } = await import('./assets/js/state.js');
  const reg = await import('./assets/js/lib/regwatch.js');
  const day = 86400000;
  const snap = (days) => reg.registrationSnapshot({ registration: { state: 'ok', registrar: 'Example Registrar', ianaId: '9999', expires: new Date(Date.now() + days * day).toISOString(), statuses: ['client transfer prohibited'], nameservers: ['ns1.example.net'] } });
  const seen = reg.rdapSeenText(reg.updateRdapSeen(reg.emptyRdapSeen(), [
    ...f.map((domain) => ({ domain, snapshot: snap(400) })),
    ...so.map((domain) => ({ domain, snapshot: snap(10) }))
  ], { now: Date.now() - day }));
  if (m === 'default') {
    await state.setWorkspaceData('rdapSeen', seen);
    await state.setWorkspaceData('watchlist', ['example.com', 'example.org', 'example.net']);
  } else {
    await state.createWorkspace('Beta Customer', { rdapSeen: seen, watchlist: ['example.org'] }, 'red');
  }
}, mode, fresh, soon);

async function openDialog(page) {
  await page.click('[data-control="workspace"]');
  await page.waitFor(() => document.querySelector('dialog.ws-modal[open] .ws-list li'), { message: 'workspaces dialog', timeout: 15000 });
}

async function closeDialog(page) {
  await page.click('dialog.ws-modal[open] .modal-head .btn');
  await page.waitFor(() => !document.querySelector('dialog.ws-modal'), { message: 'dialog closed' });
}

/** The contrast of an element's background against the surface it sits on (WCAG ratio). */
const dotContrast = (page, selector) => page.evaluate((sel) => {
  const lum = ([r, g, b]) => {
    const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const rgb = (css) => (css.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
  const dot = document.querySelector(sel);
  let surface = dot;
  let bg = [0, 0, 0, 0];
  while (surface) {
    const m = getComputedStyle(surface).backgroundColor.match(/[\d.]+/g) || [];
    if (m.length >= 3 && (m.length < 4 || Number(m[3]) > 0.99) && surface !== dot) { bg = m.slice(0, 3).map(Number); break; }
    surface = surface.parentElement;
  }
  const a = lum(rgb(getComputedStyle(dot).backgroundColor));
  const b = lum(bg);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}, selector);

async function desktop(browser, server) {
  run.group('Workspace extras (1440 px, offline)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const netHits = await networkGuard(page);
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  try {
    await run.step('C6: Portfolio starts from the watchlist and saves its box to it; Home counts against it', async () => {
      await page.goto(`${server.url}#/home`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await seedWorkspace(page, 'default', ['example.com', 'example.org'], []);
      await page.goto(`${server.url}#/portfolio`);
      await page.reload();
      await waitReady(page);
      await page.waitFor(() => document.querySelector('[data-role="pf-domains"]'), { message: 'portfolio box' });
      const box = await page.evaluate(() => document.querySelector('[data-role="pf-domains"]').value);
      assertEqual(box.split('\n'), ['example.com', 'example.org', 'example.net'], 'the box starts from the watchlist');
      const note = await page.evaluate(() => document.querySelector('[data-note="prefilled"]')?.textContent || '');
      assert(/watchlist/i.test(note), note);
      await page.evaluate(() => {
        const el = document.querySelector('[data-role="pf-domains"]');
        el.value += '\nexample.edu';
        el.dispatchEvent(new Event('input', { bubbles: true }));
      });
      await page.click('[data-action="pf-watch-save"]');
      await page.waitFor(() => /Saved 4 domains/.test(document.querySelector('[data-role="pf-watch-status"]')?.textContent || ''), { message: 'saved' });
      const saved = await page.evaluate(async () => (await import('./assets/js/state.js')).state.workspaceData('watchlist'));
      assertEqual(saved, ['example.com', 'example.org', 'example.net', 'example.edu'], 'saved list');
      await page.goto(`${server.url}#/home`);
      await waitReady(page);
      const line = await page.waitFor(() => document.querySelector('[data-role="home-ws-watch"]')?.textContent, { message: 'Home watchlist line' });
      assertEqual(line, '2 of 4 domains checked in the last 7 days', 'Home counts against the watchlist');
      await shot(page, opts, 'wsextras-home');
    });

    await run.step('C6: the watchlist travels in the hand-over file; a file from before it still imports', async () => {
      const out = await page.evaluate(async () => {
        const { state } = await import('./assets/js/state.js');
        const h = await import('./assets/js/lib/handover.js');
        const data = await state.loadWorkspace(state.workspace.id);
        const text = await h.exportWorkspaceFile({ name: 'Copy', data });
        const back = await h.openWorkspaceFile(text);
        const old = await h.openWorkspaceFile(JSON.stringify({ format: 'domainscope-workspace', v: 1, encrypted: false, workspace: { name: 'Old', parts: { notes: 'x' } } }));
        return { carried: back.data.watchlist, old: old.data.watchlist, plainFile: text.includes('"watchlist"') };
      });
      assertEqual(out, { carried: ['example.com', 'example.org', 'example.net', 'example.edu'], old: [], plainFile: true }, 'hand-over');
    });

    await run.step('C5: the colour is picked in the dialog and shows in the header, the list and Home', async () => {
      await openDialog(page);
      await page.click('dialog.ws-modal [data-action="ws-color"][data-color="blue"]');
      await page.waitFor(() => document.querySelector('[data-role="ws-color-status"]')?.textContent === 'Colour: Blue', { message: 'colour said' });
      const where = await page.evaluate(() => ({
        header: document.querySelector('[data-control="workspace"] .ws-dot')?.dataset.color,
        list: document.querySelector('dialog.ws-modal .ws-list li[data-ws-id="default"] .ws-dot')?.dataset.color,
        checked: document.querySelector('dialog.ws-modal [data-action="ws-color"][aria-checked="true"]')?.dataset.color
      }));
      assertEqual(where, { header: 'blue', list: 'blue', checked: 'blue' }, 'the dots');
      await closeDialog(page);
      await page.goto(`${server.url}#/inventory`);
      await page.goto(`${server.url}#/home`);
      await page.waitFor(() => document.querySelector('[data-role="home-ws-name"] .ws-dot'), { message: 'Home dot' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="home-ws-name"] .ws-dot').dataset.color), 'blue', 'Home dot');
      const light = await dotContrast(page, '[data-role="home-ws-name"] .ws-dot');
      assert(light >= 3, `light contrast ${light}`);
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      const dark = await dotContrast(page, '[data-role="home-ws-name"] .ws-dot');
      assert(dark >= 3, `dark contrast ${dark}`);
      await shot(page, opts, 'wsextras-home-dark');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      // the choice is kept across a reload
      await page.reload();
      await waitReady(page);
      assertEqual(await page.evaluate(() => document.querySelector('[data-control="workspace"] .ws-dot')?.dataset.color), 'blue', 'kept after a reload');
    });

    await run.step('C7: each workspace row shows a count when the dialog opens, and the list names no domain', async () => {
      await seedWorkspace(page, 'beta', ['example.net'], ['example.org', 'example.edu']);
      await openDialog(page);
      await page.waitFor(() => document.querySelector('dialog.ws-modal .ws-list li:not([data-ws-id="default"]) .ws-item-attn'), { message: 'attention badge', timeout: 15000 });
      const rows = await page.evaluate(() => [...document.querySelectorAll('dialog.ws-modal .ws-list li')].map((li) => ({
        name: li.querySelector('.ws-item-label').textContent,
        attn: li.querySelector('.ws-item-attn')?.textContent || null
      })));
      const beta = rows.find((r) => r.name === 'Beta Customer');
      assertEqual(beta.attn, '2 to look at', 'Beta Customer: two registrations running out');
      assertEqual(rows.find((r) => r.name !== 'Beta Customer').attn, null, 'Default: nothing to look at');
      const listText = await page.evaluate(() => document.querySelector('dialog.ws-modal .ws-list').textContent);
      assert(!/example\.(com|org|net|edu)/.test(listText), `the switcher names no domain: ${listText}`);
      await shot(page, opts, 'wsextras-dialog');
      await closeDialog(page);
    });

    await run.step('no console errors, CSP violations, missing keys or requests leaving the page', async () => {
      await assertClean(page, 'wsextras', server.url);
      await assertNoMissingKeys(page);
      assertEqual(netHits, [], 'nothing left the page');
    });
  } finally {
    await page.close();
  }
}

async function phone(browser, server) {
  run.group('Workspace extras (375 px, Turkish, dark, offline)');
  const page = await browser.newPage('about:blank', { width: 375, height: 800, mobile: true });
  await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
  try {
    await run.step('the dialog with colour, watchlist and counts fits without horizontal scrolling', async () => {
      await page.goto(`${server.url}#/home`);
      await waitReady(page);
      await setLangUi(page, 'tr');
      await page.click('[data-control="nav-menu"]');
      await page.waitFor(() => document.querySelector('dialog.navmenu-modal[open] [data-control="workspace-menu"]'), { message: 'tools menu' });
      await page.click('[data-control="workspace-menu"]');
      await page.waitFor(() => document.querySelector('dialog.ws-modal[open] [data-role="ws-color"]'), { message: 'dialog', timeout: 15000 });
      const names = await page.evaluate(() => [...document.querySelectorAll('dialog.ws-modal [data-action="ws-color"]')].map((b) => b.getAttribute('aria-label')));
      assertEqual(names.slice(0, 3), ['Renk yok', 'Kırmızı', 'Turuncu'], 'Turkish colour names');
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
      assert(!overflow, 'horizontal scroll at 375 px');
      await shot(page, opts, 'wsextras-phone');
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
  run.finish(opts.shots ? ` — screenshots in ${SHOTS}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
