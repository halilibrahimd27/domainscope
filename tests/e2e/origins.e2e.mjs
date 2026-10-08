#!/usr/bin/env node
/**
 * origins.e2e.mjs — the workspace's origin map (lib/originmap.js, lib/originfill.js,
 * ui/origin-map.js, Servers › Origin map) in a real headless Chrome/Edge, OFFLINE: example.net is
 * answered inside the page (scan.e2e.mjs zoneHandoffScript, which blocks every other request) and
 * a CDP guard fails any https request that would still leave it — the suite asserts none.
 *
 *   node tests/e2e/origins.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked, on a 1440 px desktop:
 *   - Servers has two tabs, Inventory and Origin map (`tab=origins`); remembering is off by
 *     default, the tab says nothing is written, and nothing is: the workspace has no map;
 *   - Zone File › Origins & servers says remembering is off (no button); once it is switched on,
 *     "Remember these 2 origins" puts the file's exact origins into the map (source zone);
 *   - a Subdomains scan of example.net (the zone forgotten) lists the remembered origins first
 *     ("Remembered origins", a "Remembered" candidate above the network) and its command probes
 *     them exactly; SSL Targets › Behind CDN shows them too;
 *   - Servers › Origin map imports a CLI --json report that finds www.example.net on another
 *     server and not at its remembered address: the new server is remembered, the old entry is
 *     marked stale with the reason ("the CLI found this name on another server … on <date>");
 *     a file that is not a report is named; the next scan shows the stale entry but leaves it out
 *     of the command; Remove the stale entry;
 *   - an origin added and changed by hand from the keyboard (Enter), one deleted; switching
 *     remembering off asks first and keeps the entries; "Delete all local data" removes the map;
 *   - Turkish and dark, 375 px and 320 px: no horizontal scroll; screenshots of each state;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; nothing sent.
 */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, setLangUi, sleep, waitReady, zoneHandoffScript, ZONE_HANDOFF_APEX, ZONE_HANDOFF_DNS
} from './scan.e2e.mjs';
import { SOURCES } from '../../assets/js/lib/sources.js';

const APEX = ZONE_HANDOFF_APEX; // example.net: www and shop proxied (Cloudflare), the rest in 203.0.113.0/24
/** The zone export: the real origins of the two proxied names. */
const ZONE_TEXT = [
  ';; Domain:     example.net.',
  'example.net.\t3600\tIN\tSOA\tada.ns.cloudflare.com. dns.cloudflare.com. 2051234567 10000 2400 604800 3600',
  'example.net.\t86400\tIN\tNS\tada.ns.cloudflare.com.',
  'example.net.\t86400\tIN\tNS\tbob.ns.cloudflare.com.',
  'example.net.\t1\tIN\tA\t203.0.113.10 ; cf_tags=cf-proxied:false',
  'www.example.net.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:true',
  'shop.example.net.\t1\tIN\tA\t192.0.2.20 ; cf_tags=cf-proxied:true',
  'api.example.net.\t1\tIN\tA\t203.0.113.14 ; cf_tags=cf-proxied:false',
  'mail.example.net.\t1\tIN\tA\t203.0.113.12 ; cf_tags=cf-proxied:false',
  ''
].join('\n');
/** A CLI --json report: www.example.net is served by web05 now, no longer by its remembered origin. */
const cliReport = (finishedAt) => ({
  tool: 'ssl_origin_scan', version: '1.0.0', startedAt: finishedAt, finishedAt,
  names: [{ name: `www.${APEX}`, sni: `www.${APEX}`, wildcard: false }],
  results: [
    { server: 'web03', ip: '192.0.2.10', port: 443, probe: 'sni', name: `www.${APEX}`, sni: `www.${APEX}`, status: 'NOT_HOSTED' },
    { server: 'web05', ip: '198.51.100.30', port: 443, probe: 'sni', name: `www.${APEX}`, sni: `www.${APEX}`, status: 'UPDATED' },
    { server: 'web05', ip: '198.51.100.30', port: 443, probe: 'sni', name: `mail.${APEX}`, sni: `mail.${APEX}`, status: 'UPDATED' }
  ],
  certificates: {}
});

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

const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
const removeToasts = (page) => page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));

/** Full-page screenshot into the shots directory; no-op with --no-shots. */
async function shotPage(page, opts, name) {
  if (!opts.shots) return;
  await removeToasts(page);
  await mkdir(opts.shotsDir, { recursive: true });
  await page.screenshot(path.join(opts.shotsDir, `${name}.png`), { fullPage: true });
}

/** The workspace's origin map as state.js has it. */
const mapOf = (page) => page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.workspaceData('origins')));

/** The rows of the Origin map table: name, origin, server, source text, stale reason (or null). */
const mapRows = (page) => page.evaluate(() => [...document.querySelectorAll('.om-table tbody tr.dt-row')].map((tr) => {
  const cells = [...tr.querySelectorAll('td')].map((td) => td.textContent.trim());
  return { name: cells[0], origin: cells[1], server: cells[2], source: cells[3], stale: tr.querySelector('[data-stale]')?.dataset.stale || null, why: tr.querySelector('.om-why')?.textContent || null };
}));

async function openOriginMap(page) {
  await gotoRoute(page, 'inventory?tab=origins');
  await page.waitFor(() => document.querySelector('.inv-tabs .tab[data-tab="origins"]')?.getAttribute('aria-selected') === 'true'
    && document.querySelector('[data-role="origin-map"]'), { message: 'Origin map tab' });
}

async function toggleRemember(page) {
  await page.click('.om-remember .check-label');
}

/** Zone File › Origins & servers of the imported file. */
async function zoneOrigins(page) {
  await gotoRoute(page, 'zone');
  await page.click('.zone-tabs .tab[data-tab="origins"]');
  await page.waitFor(() => !document.querySelector('.zone-tabs .tabpanel[data-tab="origins"]')?.hidden
    && document.querySelector('[data-role="zone-remember"]'), { message: 'Origins tab' });
}

/** A Subdomains scan of example.net (options seeded: no passive source, the small list), done. */
async function subdomainsScan(page) {
  await gotoRoute(page, 'subdomains');
  const before = await page.evaluate(() => document.querySelector('.sub-run-ui')?.dataset.run || null);
  await page.evaluate((d) => {
    const input = document.querySelector('[data-role="sub-domain"]');
    input.value = d;
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }, APEX);
  await page.click('[data-action="sub-run"]');
  await page.waitFor((b) => {
    const ui = document.querySelector('.sub-run-ui');
    return ui && ui.dataset.run !== b && ui.querySelector('.sub-run')?.dataset.status === 'done';
  }, { args: [before], timeout: 60000, message: 'subdomains scan done' });
  await page.click('.sub-tabs .tab[data-tab="origins"]');
  await page.waitFor(() => document.querySelector('.sub-org [data-block]'), { message: 'origin panel' });
}

/** The ORIGIN panel: the remembered block, each host's first candidate kind, the POSIX command. */
const originPanel = (page) => page.evaluate(() => ({
  known: [...document.querySelectorAll('.sub-org [data-block="known"] li')].map((li) => `${li.dataset.kind} ${li.dataset.host} ${li.dataset.ip}`),
  first: Object.fromEntries([...document.querySelectorAll('.sub-org-table tbody tr.dt-row')].map((tr) => [
    tr.querySelector('td')?.textContent.trim(), tr.querySelector('.sub-org-cand')?.dataset.kind || null])),
  command: document.querySelector('.sub-org-command code')?.textContent || null,
  blocks: [...document.querySelectorAll('.sub-org [data-block]')].map((b) => b.dataset.block)
}));

/** Settings › "Delete all local data", confirmed. */
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

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-origins-e2e-'));
  const zoneFile = path.join(tmp, 'example.net.txt');
  const reportFile = path.join(tmp, 'report.json');
  const notReport = path.join(tmp, 'notes.json');
  await writeFile(zoneFile, ZONE_TEXT);
  await writeFile(notReport, '{"tool":"something else"}\n');

  run.group('Node: harness');
  await run.step('run-all orders the origins suite right after workspaces', () => {
    assertEqual(orderSuites(['privacy.e2e.mjs', 'origins.e2e.mjs', 'workspaces.e2e.mjs', 'carry.e2e.mjs']), ['carry', 'workspaces', 'origins', 'privacy'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: ${APEX} answered in the page\n`);
  let page = null;
  let netHits = [];
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    netHits = await networkGuard(page);
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(APEX, ZONE_HANDOFF_DNS) });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/about`);
    await waitReady(page);
    await setLangUi(page, 'en');
    await page.evaluate((known) => {
      localStorage.setItem('ssds.subdomains.options', JSON.stringify({ sources: [], bruteforce: 'small', permutations: false, originHints: true }));
      localStorage.setItem('ssds.scan.options', JSON.stringify({ sources: [], knownSources: known, bruteforce: 'small', permutations: false, originHints: true }));
    }, SOURCES.map((s) => s.id));

    run.group('Servers › Origin map, off by default (desktop 1440×900, English, light)');
    await run.step('two tabs; remembering is off, the tab says so, and the workspace holds no map', async () => {
      await gotoRoute(page, 'inventory');
      const tabs = await page.evaluate(() => [...document.querySelectorAll('.inv-tabs > .tablist-scroll .tab')].map((b) => `${b.dataset.tab}:${b.getAttribute('aria-selected')}`));
      assertEqual(tabs, ['inventory:true', 'origins:false'], 'tabs');
      assert(await page.evaluate(() => !!document.querySelector('[data-role="inventory-text"]')), 'the inventory editor is the first tab');
      await page.click('.inv-tabs .tab[data-tab="origins"]');
      await page.waitFor(() => /[?&]tab=origins/.test(location.hash) && document.querySelector('[data-role="origin-map"]'), { message: 'tab=origins in the route' });
      const info = await page.evaluate(() => ({
        on: document.querySelector('[data-role="om-remember"]')?.checked,
        off: document.querySelector('[data-role="om-off"]')?.textContent || '',
        count: document.querySelector('[data-role="om-count"]')?.textContent,
        add: document.querySelector('[data-action="om-add"]')?.disabled,
        name: document.querySelector('[data-role="om-name"]')?.disabled,
        drop: !!document.querySelector('.om-import-card .filedrop')
      }));
      assertEqual([info.on, info.add, info.name, info.drop], [false, true, true, false], 'switch off, form and import disabled');
      assert(/write nothing here/.test(info.off), info.off);
      assertEqual(info.count, 'No origins remembered yet.', 'count');
      assertEqual(await mapOf(page), null, 'nothing written');
      await shotPage(page, opts, 'origins-map-off-desktop-light-en');
    });

    await run.step('Zone File › Origins & servers: remembering off, so no button, and the note links to the switch', async () => {
      await gotoRoute(page, 'zone');
      await page.setFileInput('.zone-drop .filedrop-input', [zoneFile]);
      await page.waitFor(() => document.querySelector('.zone-tabs'), { message: 'zone imported', timeout: 15000 });
      await zoneOrigins(page);
      const info = await page.evaluate(() => ({
        button: !!document.querySelector('[data-action="zone-remember"]'),
        note: document.querySelector('[data-role="zone-remember"] [data-role="om-off"]')?.textContent || '',
        href: document.querySelector('[data-role="zone-remember"] a')?.getAttribute('href') || ''
      }));
      assertEqual(info.button, false, 'no Remember button while off');
      assert(/Remembering origins is off/.test(info.note), info.note);
      assert(/#\/inventory\?tab=origins$/.test(info.href), info.href);
      assertEqual(await mapOf(page), null, 'still nothing written');
    });

    run.group('Remember, use, contradict');
    await run.step('switched on in Servers; Zone File remembers the two exact origins', async () => {
      await openOriginMap(page);
      await toggleRemember(page);
      await page.waitFor(() => document.querySelector('[data-role="om-remember"]')?.checked && !document.querySelector('[data-role="om-off"]'), { message: 'on' });
      assertEqual(await mapOf(page), { v: 1, remember: true, entries: [] }, 'the setting is stored');
      const lead = await page.evaluate(() => document.querySelector('[data-role="origin-map"]')?.textContent || '');
      assert(lead.includes('Verify checks the remembered origins (and a zone file’s) again; a mere candidate is never remembered.'), 'the lead says a candidate is never remembered');
      await zoneOrigins(page);
      const label = await page.evaluate(() => document.querySelector('[data-action="zone-remember"]')?.textContent);
      assertEqual(label, 'Remember these 2 origins', 'button');
      await page.click('[data-action="zone-remember"]');
      const said = await page.waitFor(() => document.querySelector('[data-role="zone-remember"] .alert')?.textContent, { message: 'result' });
      assert(/Origin map: 2 added, 0 confirmed, 0 marked stale\./.test(said), said);
      const map = await mapOf(page);
      assertEqual(map.entries.map((e) => `${e.name} ${e.ip}:${e.port} ${e.source}`), [`shop.${APEX} 192.0.2.20:443 zone`, `www.${APEX} 192.0.2.10:443 zone`], 'entries');
      await shotPage(page, opts, 'origins-zone-remembered-desktop-light-en');
      // Forget the file: the scans below see the origin map only, not the zone.
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-tabs'), { message: 'zone forgotten' });
    });

    await run.step('Subdomains: the remembered origins come first and the command probes them exactly', async () => {
      await subdomainsScan(page);
      const panel = await originPanel(page);
      assertEqual(panel.blocks[0], 'known', `the remembered block first (${panel.blocks.join(', ')})`);
      assertEqual(panel.known, [`known shop.${APEX} 192.0.2.20`, `known www.${APEX} 192.0.2.10`], 'remembered origins');
      assertEqual([panel.first[`shop.${APEX}`], panel.first[`www.${APEX}`]], ['known', 'known'], 'a "Remembered" candidate first');
      assertEqual(panel.command, `python3 ssl_origin_scan.py -t 203.0.113.0/24 192.0.2.10 192.0.2.20 -n shop.${APEX} www.${APEX}`, 'command');
      await page.evaluate(() => document.querySelector('.sub-org').scrollIntoView());
      await shotPage(page, opts, 'origins-subdomains-known-desktop-light-en');
    });

    await run.step('SSL Targets › Behind CDN: the remembered origins table', async () => {
      await gotoRoute(page, 'scan');
      await page.type('[data-role="scan-domains"]', APEX);
      await page.click('[data-action="scan-run"]');
      await page.waitFor(() => document.querySelector('.scan-run-ui .scan-run')?.dataset.status === 'done', { timeout: 60000, message: 'scan done' });
      await sleep(400);
      await page.click('.scan-tabs [data-tab="cdn"]');
      const rows = await page.waitFor(() => {
        const trs = [...document.querySelectorAll('.scan-known-origins tbody tr.dt-row')];
        return trs.length ? trs.map((tr) => [...tr.querySelectorAll('td')].slice(0, 2).map((td) => td.textContent.trim()).join(' | ')) : false;
      }, { message: 'remembered origins table' });
      assertEqual(rows, [`shop.${APEX} | Remembered192.0.2.20`, `www.${APEX} | Remembered192.0.2.10`], 'rows');
      const cmd = await page.evaluate(() => document.querySelector('.scan-cli-quick code')?.textContent || '');
      assert(cmd.includes('192.0.2.10 192.0.2.20'), `Behind CDN command: ${cmd}`);
      await page.evaluate(() => document.querySelector('.scan-known-origins')?.scrollIntoView());
      await shotPage(page, opts, 'origins-scan-cdn-desktop-light-en');
    });

    await run.step('a CLI report that finds www on another server: remembered, and the old origin marked stale', async () => {
      await writeFile(reportFile, `${JSON.stringify(cliReport(new Date().toISOString()), null, 2)}\n`);
      await openOriginMap(page);
      await page.setFileInput('.om-import-card .filedrop-input', [reportFile, notReport]);
      const lines = await page.waitFor(() => {
        const els = [...document.querySelectorAll('[data-role="om-import-result"] .alert')];
        return els.length === 2 ? els.map((a) => a.textContent) : false;
      }, { message: 'import result' });
      assert(lines.some((l) => /^notes\.json: not read \(not a report of ssl_origin_scan\.py\)\./.test(l)), lines.join(' / '));
      const ok = lines.find((l) => l.startsWith('report.json'));
      assert(/Origin map: 1 added, 0 confirmed, 1 marked stale\. Not remembered: mail\.example\.net \(not known to be behind a CDN\)\./.test(ok), ok);
      const rows = await mapRows(page);
      const www = rows.filter((r) => r.name === `www.${APEX}`);
      assertEqual(www.map((r) => `${r.origin} ${r.server} ${r.source} ${r.stale}`), ['198.51.100.30 web05 CLI report null', '192.0.2.10 — Zone file cli-elsewhere'], 'www entries');
      const why = www[1].why;
      assert(/^the CLI found this name on another server \(198\.51\.100\.30\) on \w+ \d+, \d{4}$/.test(why), why);
      const count = await page.evaluate(() => document.querySelector('[data-role="om-count"]')?.textContent);
      assertEqual(count, '3 origins · 1 stale', 'count');
      await shotPage(page, opts, 'origins-map-stale-desktop-light-en');
    });

    await run.step('the results already on screen follow the map: the stale origin once, in place, and out of the command', async () => {
      await gotoRoute(page, 'subdomains');
      await page.click('.sub-tabs .tab[data-tab="origins"]');
      await page.waitFor(() => document.querySelector('.sub-org [data-block]'), { message: 'origin panel' });
      const panel = await originPanel(page);
      assertEqual(panel.known, [`known shop.${APEX} 192.0.2.20`, `known-stale www.${APEX} 192.0.2.10`], 'one row each, www stale in place');
      assertEqual(panel.first[`www.${APEX}`] === 'known', false, 'no longer ranked first for www');
      assertEqual(panel.command, `python3 ssl_origin_scan.py -t 203.0.113.0/24 192.0.2.20 -n shop.${APEX} www.${APEX}`, 'command');
      await gotoRoute(page, 'scan');
      await page.click('.scan-tabs [data-tab="cdn"]');
      const rows = await page.waitFor(() => {
        const trs = [...document.querySelectorAll('.scan-known-origins tbody tr.dt-row')];
        return trs.length ? trs.map((tr) => [...tr.querySelectorAll('td')].slice(0, 2).map((td) => td.textContent.trim()).join(' | ')) : false;
      }, { message: 'remembered origins table' });
      assertEqual(rows, [`shop.${APEX} | Remembered192.0.2.20`, `www.${APEX} | Stale192.0.2.10`], 'rows');
      const cmd = await page.evaluate(() => document.querySelector('.scan-cli-quick code')?.textContent || '');
      assert(!cmd.includes('192.0.2.10') && cmd.includes('192.0.2.20'), `Behind CDN command: ${cmd}`);
    });

    await run.step('a map change while results are open (a Verify batch, another tab): Behind CDN and the Subdomains block follow at once', async () => {
      // SSL Targets › Behind CDN is open: shop's origin goes stale as a Verify batch would mark it.
      const before = await mapOf(page);
      const setMap = (map) => page.evaluate(async (m) => { await (await import('./assets/js/state.js')).state.setWorkspaceData('origins', m); }, map);
      const at = new Date().toISOString();
      await setMap({ ...before, entries: before.entries.map((e) => (e.ip === '192.0.2.20' ? { ...e, stale: { reason: 'verify-not-hosted', at } } : e)) });
      const rows = await page.waitFor(() => {
        const trs = [...document.querySelectorAll('.scan-known-origins tbody tr.dt-row')];
        const text = trs.map((tr) => [...tr.querySelectorAll('td')].slice(0, 2).map((td) => td.textContent.trim()).join(' | '));
        return text.some((x) => x.includes('Stale192.0.2.20')) ? text : false;
      }, { message: 'Behind CDN follows the map' });
      assertEqual(rows, [`shop.${APEX} | Stale192.0.2.20`, `www.${APEX} | Stale192.0.2.10`], 'rows');
      const cmd = await page.evaluate(() => document.querySelector('.scan-cli-quick code')?.textContent || '');
      assert(!cmd.includes('192.0.2.20') && !cmd.includes('192.0.2.10'), `Behind CDN command: ${cmd}`);
      // Subdomains › Origins is open: the map comes back (another tab, say).
      await gotoRoute(page, 'subdomains');
      await page.click('.sub-tabs .tab[data-tab="origins"]');
      await page.waitFor(() => document.querySelector('.sub-org [data-kind="known-stale"][data-ip="192.0.2.20"]'), { message: 'shop stale in the block' });
      await setMap(before);
      await page.waitFor(() => document.querySelector('.sub-org [data-kind="known"][data-ip="192.0.2.20"]'), { message: 'the block follows the map' });
      const panel = await originPanel(page);
      assertEqual(panel.known, [`known shop.${APEX} 192.0.2.20`, `known-stale www.${APEX} 192.0.2.10`], 'block');
      assertEqual(panel.command, `python3 ssl_origin_scan.py -t 203.0.113.0/24 192.0.2.20 -n shop.${APEX} www.${APEX}`, 'command');
    });

    await run.step('the next scan shows the stale entry but leaves it out of the ranking and the command', async () => {
      await subdomainsScan(page);
      const panel = await originPanel(page);
      assertEqual(panel.known, [`known shop.${APEX} 192.0.2.20`, `known www.${APEX} 198.51.100.30`, `known-stale www.${APEX} 192.0.2.10`], 'known + stale');
      assertEqual(panel.command, `python3 ssl_origin_scan.py -t 203.0.113.0/24 192.0.2.20 198.51.100.30 -n shop.${APEX} www.${APEX}`, 'command');
      await page.evaluate(() => document.querySelector('.sub-org').scrollIntoView());
      await shotPage(page, opts, 'origins-subdomains-stale-desktop-light-en');
    });

    run.group('Edits');
    await run.step('Remove the stale entry; add one by hand from the keyboard, change it, delete it', async () => {
      await openOriginMap(page);
      await page.click('[data-action="om-remove-stale"]');
      await page.waitFor(() => !document.querySelector('[data-action="om-remove-stale"]'), { message: 'stale removed' });
      assertEqual((await mapRows(page)).map((r) => `${r.name} ${r.origin}`), [`shop.${APEX} 192.0.2.20`, `www.${APEX} 198.51.100.30`], 'after removing');
      // An invalid address: the error is said and the focus goes to the field.
      await page.type('[data-role="om-name"]', `api.${APEX}`);
      await page.type('[data-role="om-ip"]', '203.0.113');
      await page.press('Enter');
      const err = await page.waitFor(() => document.querySelector('[data-role="om-outcome"] .alert')?.textContent, { message: 'error' });
      assert(/Not an IP address/.test(err), err);
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.role), 'om-ip', 'focus on the address');
      await page.type('[data-role="om-ip"]', '203.0.113.60');
      await page.type('[data-role="om-port"]', '8443');
      await page.press('Enter');
      await page.waitFor(() => /Remembered api\.example\.net → 203\.0\.113\.60:8443\./.test(document.querySelector('[data-role="om-outcome"] .alert')?.textContent || ''), { message: 'added' });
      let rows = await mapRows(page);
      assertEqual(rows.find((r) => r.name === `api.${APEX}`)?.source, 'Added by hand', 'manual source');
      // Change it: Edit fills the form, Save replaces the entry.
      await page.evaluate((n) => [...document.querySelectorAll('.om-table tbody tr.dt-row')].find((tr) => tr.textContent.includes(n)).querySelector('.om-actions .btn').click(), `api.${APEX}`);
      await page.waitFor(() => document.querySelector('[data-action="om-add"]')?.textContent === 'Save', { message: 'edit mode' });
      await page.type('[data-role="om-port"]', '443');
      await page.click('[data-action="om-add"]');
      await page.waitFor(() => document.querySelector('[data-action="om-add"]')?.textContent === 'Add', { message: 'saved' });
      rows = await mapRows(page);
      assertEqual(rows.filter((r) => r.name === `api.${APEX}`).map((r) => r.origin), ['203.0.113.60'], 'changed in place');
      await page.evaluate((n) => [...document.querySelectorAll('.om-table tbody tr.dt-row')].find((tr) => tr.textContent.includes(n)).querySelectorAll('.om-actions .btn')[1].click(), `api.${APEX}`);
      await page.waitFor((n) => ![...document.querySelectorAll('.om-table tbody tr.dt-row')].some((tr) => tr.textContent.includes(n)), { args: [`api.${APEX}`], message: 'deleted' });
      const badge = await page.evaluate(() => document.querySelector('.inv-tabs .tab[data-tab="origins"] .tab-badge')?.textContent);
      assertEqual(badge, '2', 'tab badge');
    });

    await run.step('Edit, then Cancel from the keyboard: the focus goes back to that row\'s Edit button; each message is said once', async () => {
      await openOriginMap(page);
      const label = await page.evaluate(() => {
        const button = document.querySelector('.om-table tbody tr.dt-row .om-actions .btn');
        button.click();
        return button.getAttribute('aria-label');
      });
      await page.waitFor(() => document.querySelector('[data-action="om-cancel"]'), { message: 'edit mode' });
      await page.evaluate(() => document.querySelector('[data-action="om-cancel"]').focus());
      await page.press('Enter');
      await page.waitFor(() => !document.querySelector('[data-action="om-cancel"]'), { message: 'cancelled' });
      assertEqual(await page.evaluate(() => document.activeElement?.getAttribute('aria-label')), label, 'focus on the row\'s Edit button');
      // announce() says each message; the lines that show them are no live regions of their own.
      assertEqual(await page.evaluate(() => ['om-outcome', 'om-import-result'].map((r) => document.querySelector(`[data-role="${r}"]`)?.getAttribute('aria-live') ?? null)),
        [null, null], 'no second live region');
    });

    await run.step('switching remembering off asks first and keeps the entries, also one written while it asks; the form is disabled', async () => {
      await toggleRemember(page);
      await page.waitFor(() => document.querySelector('dialog.modal[open] .modal-foot .btn-primary'), { message: 'confirmation' });
      const text = await page.evaluate(() => document.querySelector('dialog.modal[open] .modal-message')?.textContent);
      assert(/The 2 origins it holds stay and are still used/.test(text), text);
      // A Verify batch ends while the dialog is open (the call its panel makes): its entry stays.
      await page.evaluate(() => import('./assets/js/ui/origin-map.js').then(({ recordOrigins }) => recordOrigins(
        [{ name: 'verify-batch.example.net', ip: '192.0.2.77', port: 443, outcome: 'hosted' }], { source: 'verify', at: new Date().toISOString() }).done));
      await page.click('dialog.modal[open] .modal-foot .btn-primary');
      await page.waitFor(() => !document.querySelector('dialog.modal[open]') && document.querySelector('[data-role="om-off"]'), { message: 'off' });
      const map = await mapOf(page);
      assertEqual([map.remember, map.entries.length], [false, 3], 'off, entries kept');
      assert(map.entries.some((e) => e.name === 'verify-batch.example.net'), 'the entry written meanwhile is kept');
      assert(/still used for hints until you delete them/.test(await page.evaluate(() => document.querySelector('[data-role="om-off"]').textContent)), 'the note says the entries stay');
      assertEqual(await page.evaluate(() => document.querySelector('[data-action="om-add"]').disabled), true, 'Add disabled');
      await toggleRemember(page);
      await page.waitFor(() => document.querySelector('[data-role="om-remember"]')?.checked, { message: 'on again' });
    });

    run.group('Phones, Turkish, dark');
    for (const [width, lang, scheme] of [[375, 'tr', 'dark'], [375, 'en', 'light'], [320, 'tr', 'light'], [320, 'en', 'dark']]) {
      await run.step(`${width} px, ${lang === 'tr' ? 'Turkish' : 'English'}, ${scheme}: the Origin map tab has no horizontal scroll`, async () => {
        await page.setViewport({ width, height: 800, mobile: true });
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await setLangUi(page, lang);
        await openOriginMap(page);
        await page.waitFor((w) => document.documentElement.clientWidth === w, { args: [width], message: `${width} px` });
        await frames(page);
        await assertNoHorizontalScroll(page, `origin map ${width} ${lang} ${scheme}`);
        await shotPage(page, opts, `origins-map-phone${width}-${scheme}-${lang}`);
      });
    }
    await run.step('375 px Turkish dark: the zone button and the Subdomains block', async () => {
      await page.setViewport({ width: 375, height: 800, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await gotoRoute(page, 'zone');
      await page.setFileInput('.zone-drop .filedrop-input', [zoneFile]);
      await page.waitFor(() => document.querySelector('.zone-tabs'), { message: 'zone imported', timeout: 15000 });
      await zoneOrigins(page);
      const label = await page.evaluate(() => document.querySelector('[data-action="zone-remember"]')?.textContent);
      assertEqual(label, 'Bu 2 origin’i hatırla', 'Turkish button');
      await assertNoHorizontalScroll(page, 'zone origins 375 tr dark');
      await page.evaluate(() => document.querySelector('[data-role="zone-remember"]').scrollIntoView());
      await shotPage(page, opts, 'origins-zone-phone375-dark-tr');
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-tabs'), { message: 'zone forgotten' });
      await subdomainsScan(page);
      const panel = await originPanel(page);
      assertEqual(panel.blocks[0], 'known', 'remembered block first');
      assert(await page.evaluate(() => document.querySelector('.sub-org [data-block="known"] h4')?.textContent === 'Hatırlanan origin’ler'), 'Turkish heading');
      await assertNoHorizontalScroll(page, 'subdomains origins 375 tr dark');
      await page.evaluate(() => document.querySelector('.sub-org').scrollIntoView());
      await shotPage(page, opts, 'origins-subdomains-phone375-dark-tr');
      await page.setViewport({ width: 1440, height: 900 });
      await openOriginMap(page);
      await shotPage(page, opts, 'origins-map-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Delete all local data');
    await run.step('removes the origin map with the workspaces', async () => {
      await page.setViewport({ width: 1440, height: 900 });
      await deleteAllLocalData(page);
      assertEqual(await mapOf(page), null, 'no map left');
      await setLangUi(page, 'en');
      await openOriginMap(page);
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="om-remember"]')?.checked, document.querySelector('[data-role="om-count"]')?.textContent]),
        [false, 'No origins remembered yet.'], 'off and empty again');
    });

    run.group('Storage: a write that fails, browser storage refused');
    await run.step('a write that fails (the storage is full): a warning says the origin map was not saved', async () => {
      await openOriginMap(page);
      await removeToasts(page);
      await page.evaluate(() => {
        const transaction = IDBDatabase.prototype.transaction;
        window.__restorePut = () => {
          IDBDatabase.prototype.transaction = transaction;
        };
        IDBDatabase.prototype.transaction = function full() {
          throw new DOMException('The quota has been exceeded.', 'QuotaExceededError');
        };
      });
      try {
        await toggleRemember(page);
        const toast = await page.waitFor(() => [...document.querySelectorAll('.toast')].map((el) => el.textContent).find((x) => /origin map could not be saved/.test(x)) || false,
          { message: 'the warning', timeout: 10000 });
        assert(/lasts until you close this tab/.test(toast), toast);
      } finally {
        await page.evaluate(() => window.__restorePut());
      }
      await removeToasts(page);
    });

    await run.step('browser storage refused: the tab says the map lives in this tab only, and so does a remembered origin', async () => {
      const memory = await browser.newPage('about:blank', { width: 1024, height: 800 });
      try {
        await networkGuard(memory);
        await memory.send('Page.addScriptToEvaluateOnNewDocument', {
          source: '(() => { IDBFactory.prototype.open = function () { throw new DOMException(\'refused (test)\', \'UnknownError\'); }; })();'
        });
        await memory.goto(`${server.url}#/about`);
        await waitReady(memory);
        await setLangUi(memory, 'en');
        await openOriginMap(memory);
        const privacy = await memory.evaluate(() => document.querySelector('.om-panel > .alert')?.textContent || '');
        assert(/in this tab only/.test(privacy) && !/IndexedDB/.test(privacy), privacy);
        await toggleRemember(memory);
        await memory.waitFor(() => document.querySelector('[data-role="om-remember"]')?.checked, { message: 'on' });
        await memory.type('[data-role="om-name"]', `www.${APEX}`);
        await memory.type('[data-role="om-ip"]', '192.0.2.10');
        await memory.press('Enter');
        const said = await memory.waitFor(() => document.querySelector('[data-role="om-outcome"] .alert')?.textContent || false, { message: 'outcome' });
        assert(/^Remembered www\.example\.net → 192\.0\.2\.10\./.test(said) && /in this tab only/.test(said), said);
        await assertNoMissingKeys(memory);
      } finally {
        await memory.close();
      }
    });

    run.group('Quality');
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations; nothing sent to the network', async () => {
      await assertClean(page, 'origins', origin);
      assertEqual(netHits, [], 'https requests that reached the network');
      assertEqual(await page.evaluate(() => window.__zoneBlocked), [], 'requests the page script blocked');
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
