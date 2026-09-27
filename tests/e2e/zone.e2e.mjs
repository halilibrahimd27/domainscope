#!/usr/bin/env node
/**
 * zone.e2e.mjs — end-to-end test of the "Zone File" view in a real headless Chrome/Edge.
 * OFFLINE: every DoH query is answered in the page by a fake resolver built from the fixture
 * (window.fetch wrapped before the app loads; no pass-through), every other https:// request is
 * blocked, and every request that leaves the page's origin is counted through CDP.
 *
 *   node tests/e2e/zone.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry, the empty state, the import of the Cloudflare export (format, origin,
 * counts), the Records filters, the proxied-origin map with the inventory (also servers added
 * or renamed after the import), the exact sweep
 * command (no /24, host target, wildcard name, PowerShell), the zone-targets.txt download, the
 * Problems → Records jump, the live check (nothing sent before the click, planned query count,
 * hidden targets / internal names never queried, statuses, redacted export, cancel), the
 * exact-mode hand-off contract, Route 53 (incomplete export) and cPanel imports, a certificate
 * pasted by mistake, two API pages, Forget, "Delete all local data", nothing persisted, TR/EN,
 * light/dark, 390 px, zero console errors / CSP violations / missing i18n keys.
 *
 * Fixtures are documentation data only (example.com, 192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32,
 * the fake Cloudflare edge 104.16.1.1).
 */

import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, sleep, takeDownloads, waitReady
} from './scan.e2e.mjs';

const ZONES = path.join(FIXTURES, 'zones');
const CF_FILE = path.join(ZONES, 'cloudflare-export.txt');
const CF_EDGE_V4 = '104.16.1.1';
const CF_EDGE_V6 = '2606:4700::6810:101';

/**
 * The fake live zone: the fixture's own records (dnswire data shape), with every proxied name
 * answering the Cloudflare edge, except www which answers its origin (proxy switched off live →
 * origin-exposed), and a newer SOA serial.
 */
async function fakeTable() {
  const P = await import('../../assets/js/lib/zoneparse.js');
  const z = P.parseZone(await readFile(CF_FILE, 'utf8'), { filename: 'example.com.txt' });
  const table = {};
  const proxied = new Set();
  for (const r of z.records) {
    if (r.data === null || r.data === undefined || r.duplicateOf !== undefined) continue;
    if (r.name.endsWith('.dev.example.com')) continue; // below the delegation: served by the child zone
    const node = table[r.name] || (table[r.name] = {});
    (node[r.type] || (node[r.type] = [])).push(r.data);
    if (r.proxied === true) proxied.add(r.name);
  }
  for (const name of proxied) {
    const node = table[name];
    delete node.CNAME;
    node.A = [CF_EDGE_V4];
    if (name === 'www.example.com' || node.AAAA) node.AAAA = [CF_EDGE_V6];
  }
  table['www.example.com'].A = ['192.0.2.10'];
  const soa = table['example.com'].SOA[0];
  table['example.com'].SOA = [{ ...soa, serial: Number(soa.serial) + 1 }];
  return table;
}

/** In-page DoH stub: answers EVERY DoH query from the table (NXDOMAIN outside it), logs it. */
const fakeDnsScript = (table) => `(() => {
  const T = ${JSON.stringify(table)};
  const APEX = 'example.com';
  const SOA = T[APEX].SOA[0];
  window.__fakeDnsLog = [];
  window.__fakeDnsDelay = 0;
  const hasBelow = (name) => Object.keys(T).some((k) => k.endsWith('.' + name));
  const nodeOf = (name) => {
    if (T[name]) return T[name];
    const parent = name.split('.').slice(1).join('.');
    if (T['*.' + parent] && !hasBelow(name)) return T['*.' + parent];
    return null;
  };
  const answer = (qname, type) => {
    const answers = [];
    let name = qname;
    for (let hop = 0; hop < 8; hop += 1) {
      const node = nodeOf(name);
      if (!node) return { rcode: hop || hasBelow(name) ? 'NOERROR' : 'NXDOMAIN', answers };
      if (node[type]) {
        for (const data of node[type]) answers.push({ name, type, ttl: 300, data });
        return { rcode: 'NOERROR', answers };
      }
      if (node.CNAME && type !== 'CNAME') {
        const target = String(node.CNAME[0]).replace(/[.]$/, '');
        answers.push({ name, type: 'CNAME', ttl: 300, data: target });
        if (target !== APEX && !target.endsWith('.' + APEX)) return { rcode: 'NOERROR', answers };
        name = target;
        continue;
      }
      return { rcode: 'NOERROR', answers };
    }
    return { rcode: 'NOERROR', answers };
  };
  let wire = null;
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__fakeDnsLog.push({ name, type: q.type });
    if (window.__fakeDnsDelay) await new Promise((r) => setTimeout(r, window.__fakeDnsDelay));
    const out = (name === APEX || name.endsWith('.' + APEX)) ? answer(name, q.type) : { rcode: 'NXDOMAIN', answers: [] };
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers,
      authorities: out.answers.length ? [] : [{ name: APEX, type: 'SOA', ttl: 300, data: SOA }], edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

async function nodeChecks(run) {
  const V = await import('../../assets/js/views/zone.js');
  const O = await import('../../assets/js/lib/zoneorigins.js');
  run.group('Node: views/zone.js helpers');
  await run.step('the Cloudflare fixture: exact sweep command, no /24', async () => {
    const z = V.parseFiles([{ name: 'example.com.txt', text: await readFile(CF_FILE, 'utf8') }]);
    const cmd = V.sweepCommand(O.zoneSweep(z, { scope: 'proxied', shell: 'posix' }));
    assert(cmd.command.includes(' origin-lb.example.net ') && cmd.command.includes("'*.apps.example.com'"), cmd.command);
    assert(!/\/2[0-9]\b/.test(cmd.command), 'no CIDR');
  });
}

const count = (page, sel) => page.evaluate((s) => document.querySelectorAll(s).length, sel);
const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent || '', sel);
const clickTab = async (page, tab) => {
  await page.click(`.zone-tabs .tab[data-tab="${tab}"]`);
  await page.waitFor((t) => !document.querySelector(`.zone-tabs .tabpanel[data-tab="${t}"]`)?.hidden
    && document.querySelector(`.zone-tabs .tabpanel[data-tab="${t}"]`).childElementCount > 0, { args: [tab], message: `tab ${tab}` });
};
const jsClick = (page, sel) => page.evaluate((s) => { const el = document.querySelector(s); if (!el) throw new Error(`no ${s}`); el.click(); }, sel);
const noZoneStorage = (page) => page.evaluate(() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)].filter((k) => /zone/i.test(k)));

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  await nodeChecks(run);
  const table = await fakeTable();

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}\n`);
  const external = [];
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    page.conn.on('Network.requestWillBeSent', (p) => {
      const u = String((p.request && p.request.url) || '');
      if (!u.startsWith(origin) && !/^(data|blob|about|chrome-extension):/.test(u)) external.push(u);
    }, page.sessionId);
    await page.send('Network.enable');
    await page.send('Network.setBlockedURLs', { urls: ['https://*'] });
    await browser.conn.send('Browser.grantPermissions', { origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] }).catch(() => {});
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeDnsScript(table) });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/zone: nav entry, empty state, nothing sent', async () => {
      await page.goto(`${server.url}#/zone`);
      await waitReady(page);
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.setInventory('web01 192.0.2.10'));
      await page.reload();
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'zone');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/subdomains"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '')) : [];
      });
      assertEqual(nav.slice(0, 2), ['subdomains', 'zone'], 'Zone File is the 2nd Discover item');
      assert(/Zone File/.test(await text(page, 'h1')), 'title');
      const ui = await page.evaluate(() => ({
        drop: !!document.querySelector('.zone-drop'),
        origin: !!document.querySelector('[data-role="zone-origin"]'),
        samples: document.querySelectorAll('[data-sample]').length,
        howto: !!document.querySelector('.zone-howto'),
        paste: !!document.querySelector('.zone-paste'),
        privacy: /never|nothing is uploaded/i.test(document.querySelector('#page-body .alert')?.textContent || '')
      }));
      assertEqual(ui, { drop: true, origin: true, samples: 3, howto: true, paste: true, privacy: true }, 'empty state');
      assertEqual(await page.evaluate(() => window.__fakeDnsLog.length), 0, 'no DNS query');
      assertEqual(external, [], 'no external request');
      await shot(page, opts, 'zone-empty-desktop-light-en');
    });

    await run.step('import the Cloudflare export: format, origin, counts, focus; still nothing sent', async () => {
      await page.setFileInput('.zone-drop .filedrop-input', [CF_FILE]);
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'summary' });
      assertEqual(await text(page, '.zone-format-badge'), 'Cloudflare export (BIND)', 'format');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="zone-origin"]').value), 'example.com', 'origin');
      assert(/header/.test(await text(page, '.zone-origin-field')), 'origin source hint');
      assert(/^39 records · 26 names · 10 proxied$/.test((await text(page, '[data-role="zone-counts"]')).trim()), await text(page, '[data-role="zone-counts"]'));
      assert(await page.evaluate(() => document.activeElement?.classList.contains('zone-summary-title')), 'focus on the summary heading');
      const badge = await page.evaluate(() => document.querySelector('.zone-tabs .tab[data-tab="problems"] .tab-badge'));
      assert(badge !== undefined, 'problems badge');
      assertEqual(await page.evaluate(() => window.__fakeDnsLog.length), 0, 'no DNS query');
      assertEqual(external, [], 'no external request');
      const session = await page.evaluate(async () => {
        const s = (await import('./assets/js/state.js')).state.getSession('zone');
        return s ? { v: s.v, origin: s.origin, www: s.names.includes('www.example.com'), intranet: s.names.includes('intranet.example.com') } : null;
      });
      assertEqual(session, { v: 1, origin: 'example.com', www: true, intranet: false }, 'state.session.zone');
      assertEqual(await noZoneStorage(page), [], 'nothing persisted');
      await shot(page, opts, 'zone-overview-desktop-light-en');
    });

    await run.step('Records: 39 rows, Proxied only → 10, CNAME filter, search, tags in details', async () => {
      await clickTab(page, 'records');
      const rows = () => count(page, '.zone-records tbody tr.dt-row');
      assertEqual(await rows(), 39, 'all rows');
      await jsClick(page, '[data-role="zone-proxied-only"]');
      await page.waitFor(() => document.querySelectorAll('.zone-records tbody tr.dt-row').length === 10, { message: 'proxied only' });
      await jsClick(page, '[data-role="zone-proxied-only"]');
      await page.click('.zone-type-filter [data-value="CNAME"]');
      const cnames = await rows();
      assert(cnames >= 4 && cnames < 39, `CNAME rows ${cnames}`);
      await page.click('.zone-type-filter [data-value="all"]');
      await page.type('.zone-records .dt-search-input', 'mixed');
      await page.waitFor(() => document.querySelectorAll('.zone-records tbody tr.dt-row').length === 2, { message: 'search mixed' });
      await page.type('.zone-records .dt-search-input', 'tagged');
      await page.waitFor(() => document.querySelectorAll('.zone-records tbody tr.dt-row').length === 1, { message: 'search tagged' });
      await page.click('.zone-records tbody tr.dt-row .dt-expander button');
      await page.waitFor(() => /ops, eu/.test(document.querySelector('.zone-records .dt-details')?.textContent || ''), { message: 'tag chip' });
      await page.type('.zone-records .dt-search-input', '');
    });

    await run.step('Origins: 10 rows, web01 behind @ / www / docs, skipped provider + tunnel, exact command', async () => {
      await clickTab(page, 'origins');
      assertEqual(await count(page, '.zone-origins-table tbody tr.dt-row'), 10, 'origin rows');
      const rows = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.zone-origins-table tbody tr.dt-row')]
        .map((tr) => [tr.querySelector('td:not(.dt-expander) strong')?.textContent, tr.textContent])));
      for (const n of ['@', 'www', 'docs']) assert(/web01/.test(rows[n] || ''), `${n} → web01: ${rows[n]}`);
      assert(/Shopify|shopify/.test(rows.shop || ''), `shop: ${rows.shop}`);
      assert(/Tunnel/.test(rows.tunnel || ''), `tunnel: ${rows.tunnel}`);
      const cmd = await text(page, '.zone-command code');
      assert(cmd.startsWith('python3 ssl_origin_scan.py -t 192.0.2.10 '), cmd);
      assert(cmd.includes(' origin-lb.example.net ') && cmd.includes("'*.apps.example.com'"), cmd);
      assert(!/192\.0\.2\.0\/24/.test(cmd) && !/\/24\b/.test(cmd), 'never a /24');
      assert(/Skipped: shop \(/.test(await text(page, '[data-role="zone-skipped"]')), 'skipped line');
      const est1 = await text(page, '[data-role="zone-estimate"]');
      assert(/9 SNI names × 8 targets = at least 72/.test(est1), est1);
      await page.click('.zone-shell [data-value="powershell"]');
      await page.waitFor(() => (document.querySelector('.zone-command code')?.textContent || '').startsWith('python ssl_origin_scan.py'), { message: 'PowerShell' });
      await page.click('.zone-scope [data-value="all"]');
      await page.waitFor((e) => (document.querySelector('[data-role="zone-estimate"]')?.textContent || '') !== e, { args: [est1.replace('8 names', '8 names')], message: 'scope all' });
      await page.click('.zone-scope [data-value="proxied"]');
      await page.click('.zone-shell [data-value="posix"]');
      await takeDownloads(page);
      await page.click('[data-action="zone-targets-file"]');
      await page.waitFor(() => (window.__downloads || []).length === 1);
      const [dl] = await takeDownloads(page);
      // The same hand-off computed in Node from the same fixture (the zones-analysis goldens use their own inputs).
      const V = await import('../../assets/js/views/zone.js');
      const O = await import('../../assets/js/lib/zoneorigins.js');
      const sw = O.zoneSweep(V.parseFiles([{ name: 'example.com.txt', text: await readFile(CF_FILE, 'utf8') }]), { scope: 'proxied' });
      const expected = [...sw.targets, ...sw.hostTargets];
      const got = dl.text.split('\n').filter((l) => l && !l.startsWith('#'));
      assertEqual(dl.name, 'zone-targets.txt', 'file name');
      assertEqual(got.map((l) => l.split(' ').pop()), expected.map((l) => l.split(' ').pop()), 'targets');
      assert(got.includes('web01 192.0.2.10'), 'inventory name in the targets file');
      assertEqual(external, [], 'no external request');
      await shot(page, opts, 'zone-origins-desktop-light-en');
    });

    await run.step('servers added or renamed after the import update the Origins and Records server columns', async () => {
      const setInv = (inv) => page.evaluate(async (s) => { (await import('./assets/js/state.js')).state.setInventory(s); }, inv);
      const originRows = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.zone-origins-table tbody tr.dt-row')]
        .map((tr) => [tr.querySelector('td:not(.dt-expander) strong')?.textContent, tr.textContent])));
      await setInv('');
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'forgotten' });
      await page.setFileInput('.zone-drop .filedrop-input', [CF_FILE]);
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'summary' });
      await clickTab(page, 'origins');
      assert(await count(page, '.zone-origins-table a[href$="#/inventory"]') > 0, '"Add your servers" links');
      await gotoRoute(page, 'inventory');
      await setInv('web01 192.0.2.10');
      await gotoRoute(page, 'zone');
      await clickTab(page, 'origins');
      let rows = await originRows();
      for (const n of ['@', 'www', 'docs']) assert(/web01/.test(rows[n] || ''), `${n} → web01 after adding the server: ${rows[n]}`);
      await clickTab(page, 'records');
      const cells = await page.evaluate(() => [...document.querySelectorAll('.zone-records tbody tr.dt-row')]
        .filter((tr) => [...tr.cells].some((td) => td.textContent.trim() === '192.0.2.10')).map((tr) => tr.textContent));
      assert(cells.length > 0 && cells.every((c) => /web01/.test(c)), `Records server cell: ${cells}`);
      // renamed while the view is shown (another tab, or a script): the columns follow without navigating
      await clickTab(page, 'origins');
      await setInv('web-a 192.0.2.10');
      await page.waitFor(() => /web-a/.test(document.querySelector('.zone-origins-table')?.textContent || ''), { message: 'renamed server' });
      rows = await originRows();
      assert(!/web01/.test(rows.www || '') && /web-a/.test(rows.www || ''), `www → web-a: ${rows.www}`);
      await setInv('web01 192.0.2.10');
    });

    await run.step('Problems: rollup, Errors filter, ftp → Records filtered with the line highlighted', async () => {
      await clickTab(page, 'problems');
      assert(await count(page, '.zone-problems-all .zone-problem') >= 5, 'problems listed');
      await page.click('.zone-prob-filter [data-value="error"]');
      assert(await page.evaluate(() => [...document.querySelectorAll('.zone-problems-all .zone-problem')].every((li) => li.dataset.severity === 'error')), 'errors only');
      await page.evaluate(() => [...document.querySelectorAll('.zone-problem-link')].find((b) => b.dataset.name === 'ftp.example.com').click());
      await page.waitFor(() => !document.querySelector('.zone-tabs .tabpanel[data-tab="records"]')?.hidden
        && document.querySelector('.zone-records .dt-search-input')?.value === 'ftp.example.com', { message: 'records filtered' });
      assert(await count(page, '.zone-records tr.zone-row-hit') >= 1, 'line highlighted');
      assert(/tab=records/.test(await page.evaluate(() => location.hash)), 'hash tab');
    });

    await run.step('Live check: disclosure first, nothing sent before Run; planned queries; hidden names never sent', async () => {
      await clickTab(page, 'live');
      const lead = await page.evaluate(() => {
        const el = document.querySelector('[data-role="zone-live-lead"]');
        return { text: el.textContent, queries: Number(el.dataset.queries) };
      });
      assert(/record sets → \d+ DNS queries through /.test(lead.text), lead.text);
      assert(/Skip names that look internal \(1\)/.test(await text(page, '.zone-live-card')), 'skip internal (1)');
      assertEqual(await page.evaluate(() => window.__fakeDnsLog.length), 0, 'no DNS query before Run');
      await page.click('[data-action="zone-live-run"]');
      await page.waitFor(() => document.querySelector('.zone-drift')?.dataset.status === 'done', { timeout: 30000, message: 'drift done' });
      const log = await page.evaluate(() => window.__fakeDnsLog);
      const keys = new Set(log.map((q) => `${q.name}|${q.type}`));
      assertEqual(keys.size, lead.queries, 'unique queries = planned');
      for (const hidden of ['origin-lb.example.net', 'intranet.example.com', 'old.dev.example.com']) {
        assert(!log.some((q) => q.name === hidden), `${hidden} never queried`);
      }
      const statuses = await page.evaluate(() => [...new Set([...document.querySelectorAll('.zone-drift-table [data-status]')].map((e) => e.dataset.status))]);
      for (const s of ['proxied-ok', 'origin-exposed', 'match']) assert(statuses.includes(s), `${s} in ${statuses}`);
      assert(/newer than the file/.test(await text(page, '.zone-drift')), 'serial banner');
      await page.click('.zone-chip[data-filter="origin-exposed"]');
      const shown = await page.evaluate(() => [...document.querySelectorAll('.zone-drift-table tbody tr.dt-row [data-status]')].map((e) => e.dataset.status));
      assert(shown.length >= 1 && shown.every((s) => s === 'origin-exposed'), `chip filter: ${shown}`);
      await page.click('.zone-chip[data-filter="all"]');
      await takeDownloads(page);
      await page.click('.zone-drift-table .dt-export button');
      await page.waitFor(() => (window.__downloads || []).length === 1);
      const [csv] = await takeDownloads(page);
      for (const ip of ['192.0.2.10', '192.0.2.14', '192.0.2.40', '2001:db8::10', 'origin-lb.example.net']) assert(!csv.text.includes(ip), `${ip} redacted`);
      assert(csv.text.includes('[origin hidden]'), 'redaction marker');
      await jsClick(page, '[data-role="zone-include-origins"]');
      await page.click('.zone-drift-table .dt-export button');
      await page.waitFor(() => (window.__downloads || []).length === 1);
      const [csv2] = await takeDownloads(page);
      assert(csv2.text.includes('192.0.2.10'), 'origins included on opt-in');
      assertEqual(external, [], 'no external request (DoH answered in the page)');
      await shot(page, opts, 'zone-live-desktop-light-en');
    });

    await run.step('Live check: Cancel stops a slow run; Re-run completes', async () => {
      await page.evaluate(() => { window.__fakeDnsDelay = 400; });
      await page.click('[data-action="zone-live-run"]');
      await page.waitFor(() => !!document.querySelector('[data-action="zone-live-cancel"]'), { message: 'running' });
      await sleep(300);
      await page.click('[data-action="zone-live-cancel"]');
      await page.waitFor(() => /Stopped: \d+ of \d+ record sets checked/.test(document.querySelector('.zone-live')?.textContent || ''), { timeout: 15000, message: 'stopped' });
      await page.evaluate(() => { window.__fakeDnsDelay = 0; });
      await page.click('[data-action="zone-live-run"]');
      await page.waitFor(() => document.querySelector('.zone-drift')?.dataset.status === 'done', { timeout: 30000, message: 're-run done' });
    });

    await run.step('Scan these names (exact): publishes the zone + one-shot intent and opens Subdomains', async () => {
      await clickTab(page, 'overview');
      const before = await page.evaluate(() => localStorage.getItem('ssds.subdomains.options'));
      const extBefore = external.length;
      await page.evaluate(async () => {
        // Observe the hand-off without depending on how Subdomains consumes it.
        const { state } = await import('./assets/js/state.js');
        window.__intents = [];
        state.subscribe(({ key, value }) => { if (key === 'session' && value.name === 'zoneScanIntent' && value.value) window.__intents.push(value.value); });
      });
      await page.click('[data-action="zone-scan"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'subdomains', { message: 'Subdomains opened' });
      assert(/domain=example\.com/.test(await page.evaluate(() => location.hash)), 'domain param');
      const intent = await page.evaluate(() => window.__intents[0]);
      assertEqual({ v: intent.v, target: intent.target, domain: intent.domain, mode: intent.mode, autostart: intent.autostart },
        { v: 1, target: 'subdomains', domain: 'example.com', mode: 'exact', autostart: true }, 'intent');
      await sleep(500);
      await page.evaluate(() => document.querySelector('[data-action="sub-cancel"]:not([disabled])')?.click());
      assertEqual(await page.evaluate(() => localStorage.getItem('ssds.subdomains.options')), before, 'Subdomains options unchanged');
      await gotoRoute(page, 'zone');
      // Requests Subdomains made (its own sources, blocked here) are not the zone view's.
      if (external.length > extBefore) process.stdout.write(`        note: Subdomains tried ${external.length - extBefore} external request(s) (blocked)
`);
      external.length = extBefore;
      assert(await page.evaluate(() => !!document.querySelector('.zone-summary')), 'zone kept in memory across views');
    });

    await run.step('Find certificate targets: SSL Targets opens with the domain, no auto-start intent', async () => {
      await page.evaluate(() => { window.__intents = []; });
      await page.click('[data-action="zone-cert"]');
      const extBefore = external.length;
      await page.waitFor(() => document.documentElement.dataset.view === 'scan', { message: 'SSL Targets opened' });
      const intent = await page.evaluate(() => window.__intents[0]);
      assertEqual([intent.target, intent.autostart, intent.domain], ['scan', false, 'example.com'], 'cert intent');
      await gotoRoute(page, 'zone');
      external.length = extBefore;
    });

    await run.step('Route 53 JSON pasted: incomplete export alert; cPanel: missing-dot error', async () => {
      const r53 = await readFile(path.join(ZONES, 'route53.json'), 'utf8');
      await page.evaluate(() => { document.querySelectorAll('.zone-import-folded, .zone-paste').forEach((d) => { d.open = true; }); });
      await page.type('[data-role="zone-paste"]', r53);
      await page.click('[data-action="zone-paste-import"]');
      await page.waitFor(() => /AWS Route 53/.test(document.querySelector('.zone-format-badge')?.textContent || ''), { message: 'route53' });
      assert(/incomplete/i.test(await text(page, '.zone-partial')), 'incomplete export alert');
      await page.setFileInput('.zone-drop .filedrop-input', [path.join(ZONES, 'cpanel-example.com.db.txt')]);
      await page.waitFor(() => /cPanel/.test(document.querySelector('.zone-format-badge')?.textContent || ''), { message: 'cpanel' });
      await clickTab(page, 'problems');
      assert(await page.evaluate(() => !!document.querySelector('.zone-problem[data-code="OWNER_MISSING_TRAILING_DOT"]')), 'OWNER_MISSING_TRAILING_DOT');
    });

    await run.step('a certificate by mistake → NOT_A_ZONE with a Certificate link; two API pages → one zone', async () => {
      await page.setFileInput('.zone-drop .filedrop-input', [path.join(ZONES, 'bad', 'cert.pem.txt')]);
      await page.waitFor(() => document.querySelector('.zone-fatal')?.dataset.code === 'NOT_A_ZONE', { message: 'fatal' });
      assert(await page.evaluate(() => !!document.querySelector('.zone-fatal a[href*="#/cert"]')), 'Certificate link');
      await page.setFileInput('.zone-drop .filedrop-input', [path.join(ZONES, 'cloudflare-api-page1.json'), path.join(ZONES, 'cloudflare-api-page2.json')]);
      await page.waitFor(() => /Cloudflare API/.test(document.querySelector('.zone-format-badge')?.textContent || ''), { message: 'API pages' });
      assert(/cloudflare-api-page1\.json, cloudflare-api-page2\.json/.test(await text(page, '.zone-files')), 'both files');
    });

    await run.step('Forget → empty state, toast, session cleared; nothing persisted; hash only tab=', async () => {
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary') && document.querySelectorAll('[data-sample]').length === 3, { message: 'empty' });
      assert(await page.evaluate(() => [...document.querySelectorAll('.toast')].some((t) => /Zone forgotten/.test(t.textContent))), 'toast');
      assertEqual(await page.evaluate(async () => (await import('./assets/js/state.js')).state.getSession('zone')), undefined, 'session cleared');
      assertEqual(await noZoneStorage(page), [], 'no zone key in storage');
      assert(/^#\/zone(\?tab=\w+)?$/.test(await page.evaluate(() => location.hash)), 'hash');
    });

    await run.step('"Delete all local data" drops a loaded zone; a reload forgets it', async () => {
      await page.click('[data-sample="cloudflare"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'));
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.clearAll());
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'cleared' });
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.setInventory('web01 192.0.2.10'));
      await page.click('[data-sample="bind"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'));
      await page.reload();
      await waitReady(page);
      await gotoRoute(page, 'zone');
      assert(!await page.evaluate(() => !!document.querySelector('.zone-summary')), 'reload forgets');
    });

    run.group('Phone 390×844 and Turkish / dark');
    await run.step('TR/EN × light/dark at 390 px on Overview, Origins and Live: no horizontal scroll', async () => {
      await page.setFileInput('.zone-drop .filedrop-input', [CF_FILE]);
      await page.waitFor(() => !!document.querySelector('.zone-summary'));
      await page.setViewport({ width: 390, height: 844, mobile: true });
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'zone kept after the language switch' });
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          for (const tab of ['overview', 'origins', 'live']) {
            await clickTab(page, tab);
            await page.evaluate(() => window.scrollTo(0, 0));
            await assertNoHorizontalScroll(page, `${tab} ${scheme} ${lang}`);
            await shot(page, opts, `zone-${tab}-mobile-${scheme}-${lang}`);
          }
        }
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'en');
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'zone', origin));
    await page.close();
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
