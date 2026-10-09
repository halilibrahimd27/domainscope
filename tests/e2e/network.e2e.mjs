#!/usr/bin/env node
/**
 * network.e2e.mjs — end-to-end test of the page template (ui/template.js, lib/template.js;
 * docs/DESIGN.md §5 and §8 phase 5) on "Map IPs to servers" — IP Intel, Bulk Resolve, Reverse DNS —
 * and the workspace pages, Servers and About, in a real headless Chrome/Edge. OFFLINE: the DNS of
 * example.com and of the documentation networks' reverse zones, RIPEstat and ipwho.is are answered
 * inside the page; every other request that leaves the page fails there, and a network-level guard
 * fails and records any https request that would still go out — the suite asserts none.
 *
 *   node tests/e2e/network.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - the empty template of the three batch tools: one input card (role search) with the primary
 *     field, Run (primary, Ctrl+Enter) and the privacy note in its foot; the empty state with the
 *     chips of what the tool checks; no result header. Servers: its three tabs above the editor's
 *     card (role form, Save as its run, the privacy note), the result header from the start. About:
 *     the hero without a gradient, "On this page" as chips, the section ids, a hint that is no alert;
 *   - IP Intel: an example chip fills the box and sends nothing; a lookup turns the input compact,
 *     its result header ("4 addresses") starts above 300 px with the status summary (behind a CDN,
 *     networks, countries, in your servers, private — "in your servers" filters the table), the
 *     actions in order (Copy summary + ¶, Export ▾ with CSV and JSON, Copy link without the private
 *     and the inventory addresses) and the next step; the metric strip is read-only;
 *   - Bulk Resolve: Run sits under the list, right-aligned; the result header "5 host names
 *     resolved" with its status summary, Copy summary (new: the builder of lib/summary.js), Export ▾
 *     (both tables, CSV and JSON), Copy link (`names=`) and "Use in IP Intel" (a fill-only link);
 *   - Reverse DNS: the result header "Reverse DNS of 192.0.2.0/29" with its status summary, Copy
 *     summary (new), Export ▾ (names.txt, CSV, JSON), Copy link with the focus domain, the next
 *     steps; the compact input names the focus domain in its summary line;
 *   - Servers: the result header counts the servers, its status summary (warnings, addresses) takes
 *     the focus to the first warning, Export ▾ writes targets.txt; the Origin map and Exposure audit
 *     tabs say where things stay in a privacy note, not a green alert;
 *   - phones, 375×812 in Turkish and dark: Copy summary alone in the row and the rest behind "⋯";
 *     every table of the five pages is a card per row (no header row, the first cell heads the card,
 *     the others are lines, each value beside its column's label) with no sideways scroll; 320 px in
 *     Turkish: the same cards with each label above its value, none wider than its card; none of the
 *     five pages scrolls sideways, empty or with a result;
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
  installDownloadCapture, openResultMenu, resultAction, setLangUi, sleep, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';

/** The DNS the page asks (documentation names and addresses; one Cloudflare edge address). */
const ZONE = {
  'www.example.com': { A: ['192.0.2.1'] },
  'shop.example.com': { A: ['104.16.5.5'] },
  'mail.example.com': { A: ['203.0.113.12'] },
  'db.example.com': { A: ['10.0.0.5'] },
  'host.example.net': { A: ['192.0.2.3'] },
  // 192.0.2.0/29: two names that resolve back, one that does not, a broken delegation, four without a PTR.
  '1.2.0.192.in-addr.arpa': { PTR: ['www.example.com'] },
  '2.2.0.192.in-addr.arpa': { PTR: ['mail.example.com'] },
  '3.2.0.192.in-addr.arpa': { PTR: ['host.example.net'] },
  '5.2.0.192.in-addr.arpa': { RCODE: { PTR: 'SERVFAIL' } },
  '7.113.0.203.in-addr.arpa': { PTR: ['web.example.com'] },
  '20.100.51.198.in-addr.arpa': { PTR: ['mail.example.net'] }
};
/** The workspace's servers: www's address, db's private one and one IP Intel address. */
const SERVERS = 'web01 192.0.2.1\ndb01 10.0.0.5\nmail01 198.51.100.20';
const BULK_NAMES = ['www.example.com', 'shop.example.com', 'mail.example.com', 'db.example.com', 'missing.example.com'];
const IPS = ['203.0.113.7', '198.51.100.20', '10.0.0.1', '104.16.5.5'];
const STAMP = /\d{8}-\d{4}/;

/**
 * A page script (installed before the app loads): DoH answered from {@link ZONE} (a name it does
 * not hold is NXDOMAIN; `RCODE` answers a type with that rcode), RIPEstat's prefix overview and
 * location answered for every address (AS64500, a /24, NL), ipwho.is out of quota; any other
 * request that leaves the page origin fails and is recorded in window.__netBlocked.
 */
const FAKE_SCRIPT = `(() => {
  const ZONE = ${JSON.stringify(ZONE)};
  const SOA = { mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
  const answer = (name, type) => {
    const node = ZONE[name];
    if (!node) {
      const exists = Object.keys(ZONE).some((k) => k.endsWith('.' + name));
      return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers: [], authorities: [{ name: 'example.com', type: 'SOA', ttl: 300, data: SOA }] };
    }
    if (node.RCODE && node.RCODE[type]) return { rcode: node.RCODE[type], answers: [], authorities: [] };
    const answers = (node[type] || []).map((data) => ({ name, type, ttl: 300, data }));
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: 'example.com', type: 'SOA', ttl: 300, data: SOA }] };
  };
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.__netDns = 0;
  window.__netCalls = [];
  window.__netBlocked = [];
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const u = new URL(url, location.href);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (m) {
      wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
      const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
      const out = answer(String(q.name).toLowerCase().replace(/[.]$/, ''), q.type);
      window.__netDns += 1;
      return new Response(wire.encodeMessage({
        id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
        questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities, edns: {}
      }), { headers: { 'content-type': 'application/dns-message' } });
    }
    if (u.hostname === 'stat.ripe.net') {
      const ip = u.searchParams.get('resource');
      const call = u.pathname.split('/')[2];
      window.__netCalls.push(call + ' ' + ip);
      if (call === 'prefix-overview') {
        return json({ status: 'ok', data: { announced: true, asns: [{ asn: 64500, holder: 'EXAMPLE-NET - Example Networks B.V.' }],
          resource: ip.split('.').slice(0, 3).join('.') + '.0/24', block: { desc: 'Administered by RIPE NCC' } } });
      }
      if (call === 'maxmind-geo-lite') return json({ status: 'ok', data: { located_resources: [{ locations: [{ country: 'NL', city: 'Amsterdam', covered_percentage: 100 }] }] } });
      return json({ status: 'error', messages: [['error', 'unknown call']] }, 400);
    }
    if (u.hostname === 'ipwho.is') {
      window.__netCalls.push('ipwhois ' + u.pathname.slice(1));
      return json({ success: false, message: 'You have exceeded the rate limit' });
    }
    if (u.origin === location.origin) return realFetch(input, init);
    window.__netBlocked.push(url);
    throw new TypeError('blocked by the E2E (network.e2e.mjs)');
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

/** A page with the fakes in it, downloads captured, the network guarded, the workspace's servers saved. */
async function openPage(browser, server, viewport) {
  const page = await browser.newPage('about:blank', viewport);
  const hits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: FAKE_SCRIPT });
  await installDownloadCapture(page);
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  await page.evaluate(async (text) => {
    localStorage.removeItem('ssds.bulk.options');
    await (await import('./assets/js/state.js')).state.setInventory(text).done;
  }, SERVERS);
  return { page, hits };
}

/** Put text in a field as typing does (one input event). */
const fill = (page, role, value) => page.evaluate(([r, v]) => {
  const el = document.querySelector(`[data-role="${r}"]`);
  el.value = v;
  el.dispatchEvent(new Event('input', { bubbles: true }));
}, [role, value]);

/** The template on screen: the input card, Run, the empty state and the result header `head`. */
const templateInfo = (page, head) => page.evaluate((sel) => {
  const card = document.querySelector('#page-body .tool-input');
  const field = card?.querySelector('.tool-input-primary [data-shortcut="focus"]');
  const run = card?.querySelector('.tool-input-fields > .run-bar .run-bar-run');
  const box = (el) => {
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { top: Math.round(r.top + window.scrollY), bottom: Math.round(r.bottom + window.scrollY), right: Math.round(r.right) };
  };
  const resultHead = document.querySelector(sel);
  return {
    cards: document.querySelectorAll('#page-body .tool-input').length,
    role: card?.getAttribute('role') || null,
    compact: !!card?.classList.contains('is-compact'),
    field: box(field),
    run: run ? { ...box(run), label: run.querySelector('.btn-label').textContent, primary: run.classList.contains('btn-primary'), shortcut: run.dataset.shortcut || null } : null,
    privacy: !!card?.querySelector('.tool-input-foot .privacy-note'),
    empty: !!document.querySelector('#page-body .tool-empty'),
    checks: document.querySelectorAll('#page-body .tool-empty-check').length,
    head: resultHead && resultHead.isConnected && resultHead.getClientRects().length ? box(resultHead) : null
  };
}, head);

/** The result header's actions row, by kind, in order. */
const actionsRow = (page, head) => page.evaluate((sel) => [...document.querySelectorAll(`${sel} .result-actions > *`)].map((el) => {
  if (el.classList.contains('sum-actions')) return el.querySelector('[data-action="copy-summary-text"]:not([hidden])') ? 'summary+plain' : 'summary';
  if (el.classList.contains('menu-wrap')) return `menu:${el.querySelector('.menu-button').dataset.menu}`;
  return el.dataset.action || el.dataset.export || el.tagName.toLowerCase();
}), head);

/** The status summary of `head`: "key:count" per item, in order. */
const statusOf = (page, head) => page.evaluate((sel) => [...document.querySelectorAll(`${sel} .status-item`)].map((b) => `${b.dataset.status}:${b.dataset.count}`), head);

/** The first line of the Markdown Copy summary of `kind` (and its last line, the link). */
async function summaryOf(page, kind) {
  await stubClipboard(page);
  await page.click(`[data-summary="${kind}"] [data-action="copy-summary"]`);
  await page.waitFor(() => window.__clip.length === 1, { message: `${kind} summary copied` });
  const [md] = await takeClipboard(page);
  const lines = md.trim().split('\n');
  return { lines, link: lines[lines.length - 1] };
}

/** Copy link of `head`'s result: its hash, decoded. */
async function linkOf(page, head) {
  await stubClipboard(page);
  await resultAction(page, '[data-action="copy-link"]', head);
  await page.waitFor(() => window.__clip.length === 1, { message: 'Copy link' });
  return decodeURIComponent(new URL((await takeClipboard(page))[0]).hash);
}

/**
 * A table in card mode (style.css .dt-cards, DataTable({ cellLabels: true })): no header row,
 * each row a grid, its first cell unlabelled at the top, the others lines labelled by their
 * column — each value beside its label, or under it below 360 px (`labels`: where the values of
 * the first row's labelled cells start, every one of them) —; nothing wider than its scroller.
 */
const cardMode = (page, sel) => page.evaluate((s) => {
  const root = document.querySelector(s);
  const table = root?.querySelector('.dt-table');
  const row = table?.querySelector('tbody tr.dt-row');
  if (!row) return null;
  const cells = [...row.children].filter((td) => !td.classList.contains('dt-expander') && getComputedStyle(td).display !== 'none');
  const label = (td) => getComputedStyle(td, '::before').content;
  const scroller = root.matches('.dt-scroll') ? root : root.querySelector('.dt-scroll');
  // The label is the cell's ::before: its value (the cell's own nodes) starts to its right, or on the next line at the cell's left edge.
  const place = (td) => {
    const range = document.createRange();
    range.selectNodeContents(td);
    const value = range.getBoundingClientRect();
    const cell = td.getBoundingClientRect();
    if (value.left - cell.left >= 24 && value.top - cell.top < 8) return 'beside';
    if (Math.abs(value.left - cell.left) <= 1 && value.top - cell.top >= 8) return 'above';
    return `${Math.round(value.left - cell.left)},${Math.round(value.top - cell.top)}`;
  };
  return {
    head: getComputedStyle(table.querySelector('thead')).display,
    row: getComputedStyle(row).display,
    first: label(cells[0]),
    labelled: cells.slice(1).every((td) => !!td.dataset.label && label(td) === JSON.stringify(td.dataset.label)),
    labels: [...new Set(cells.slice(1).map(place))].join(' '),
    fits: scroller.scrollWidth <= scroller.clientWidth + 1
  };
}, sel);
const CARDS = { head: 'none', row: 'grid', first: 'none', labelled: true, labels: 'beside', fits: true };

const IP_DONE = "document.querySelectorAll('.ipi-row').length > 0 && !document.querySelector('.ipi-row.is-pending') && !document.querySelector('[data-action=\"run\"]').hidden";
const BULK_DONE = "document.querySelector('.bulk-progress')?.dataset.status === 'done' && !document.querySelector('[data-action=\"bulk-run\"]').hidden";
const PTR_DONE = "document.querySelector('.ptr-progress')?.dataset.status === 'done' && !document.querySelector('[data-action=\"ptr-run\"]').hidden";
/** The five pages' card tables on a phone, and when the kept result is on screen again. */
const CARD_TABLES = [['ip', '.ipi-table', IP_DONE], ['bulk', '.bulk-hosts', BULK_DONE], ['ptr', '.ptr-table', PTR_DONE], ['inventory', '.inv-table', null], ['about', '#about-sources .about-table', null]];

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
  await run.step('run-all orders this suite right after investigate, before the tools\' own suites', () => {
    assertEqual(orderSuites(['ip.e2e.mjs', 'network.e2e.mjs', 'investigate.e2e.mjs', 'shell.e2e.mjs']), ['shell', 'investigate', 'network', 'ip'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: DNS, RIPEstat and ipwho.is answered in the page\n`);
  const pages = [];
  try {
    const { page, hits } = await openPage(browser, server, { width: 1440, height: 900 });
    pages.push({ page, hits, where: 'desktop' });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await setLangUi(page, 'en');

    run.group('The empty template (desktop 1440×900, English, light)');
    await run.step('IP Intel, Bulk Resolve, Reverse DNS: one input card with its field, Run and the privacy note; the empty state with its chips; no result header', async () => {
      for (const [id, head] of [['ip', '.ipi-results-bar'], ['bulk', '.bulk-progress'], ['ptr', '.ptr-progress']]) {
        await gotoRoute(page, `#/${id}`);
        const info = await templateInfo(page, head);
        assertEqual([info.cards, info.role, info.compact, !!info.field, info.privacy, info.empty, info.head], [1, 'search', false, true, true, true, null], `${id}: the input card, the empty state, no result header`);
        assert(info.run && info.run.primary && info.run.shortcut === 'submit', `${id}: Run, primary, Ctrl+Enter: ${JSON.stringify(info.run)}`);
        assert(info.checks >= 4, `${id}: the chips of what it checks (${info.checks})`);
        await assertNoHorizontalScroll(page, `${id} empty`);
      }
      await shot(page, 'network-bulk-empty-desktop-light-en');
    });

    await run.step('Servers: the three tabs above the editor\'s card (a form, Save its run, the privacy note); the result header from the start', async () => {
      await gotoRoute(page, '#/inventory');
      const info = await templateInfo(page, '.inv-head');
      const tabs = await page.evaluate(() => {
        const list = document.querySelector('.inv-tabs [role="tablist"]');
        return { ids: [...list.querySelectorAll('[role="tab"]')].map((b) => b.dataset.tab), above: list.getBoundingClientRect().bottom <= document.querySelector('.inv-editor').getBoundingClientRect().top };
      });
      assertEqual(tabs, { ids: ['inventory', 'origins', 'exposure'], above: true }, 'the tabs, right under the page header');
      assertEqual([info.cards, info.role, info.privacy, info.run && info.run.label, info.run && info.run.primary], [1, 'form', true, 'Save inventory', true], 'the editor\'s card');
      assert(info.head, 'the result header');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-action="save"]').disabled, document.querySelector('.inv-head').dataset.servers, !!document.querySelector('.inv-stats, .stat-card')]),
        [true, '3', false], 'Save waits for a change; the saved list counted; no stat cards');
      assertEqual(await statusOf(page, '.inv-head'), ['ips:3'], 'the status summary');
    });

    await run.step('About: the hero without a gradient, "On this page" as chips, the section ids, a hint that is not an alert', async () => {
      await gotoRoute(page, '#/about');
      const info = await page.evaluate(() => ({
        gradient: getComputedStyle(document.querySelector('.about-hero')).backgroundImage,
        chips: [...document.querySelectorAll('.about-toc button')].map((b) => (b.classList.contains('chip') ? b.dataset.toc : `!${b.dataset.toc}`)),
        ids: [...document.querySelectorAll('#page-body .section[id^="about-"]')].map((s) => s.id),
        alerts: document.querySelectorAll('#about-cloudflare .alert').length,
        hint: !!document.querySelector('#about-cloudflare .about-cf-hint')
      }));
      assertEqual(info.gradient, 'none', 'no gradient');
      assertEqual(info.chips, ['start', 'how', 'cloudflare', 'sources', 'privacy', 'sent', 'cli', 'selfhost', 'license'], 'chips');
      assertEqual(info.ids, ['about-start', 'about-how', 'about-cloudflare', 'about-sources', 'about-privacy', 'about-sent', 'about-cli', 'about-selfhost', 'about-license'], 'section ids');
      assertEqual([info.alerts, info.hint], [0, true], 'the hint is muted text');
      await page.click('.about-toc [data-toc="sent"]');
      await page.waitFor(() => document.activeElement?.closest('#about-sent'), { message: 'a chip takes the focus to its section' });
    });

    run.group('IP Intel (desktop)');
    await run.step('an example chip fills the box, sends nothing and leaves the focus on Look up', async () => {
      await gotoRoute(page, '#/ip');
      const before = await page.evaluate(() => [window.__netDns, window.__netCalls.length]);
      await page.click('.ipi-examples [data-example]');
      const info = await page.evaluate(() => ({
        value: document.querySelector('[data-role="ip-input"]').value.trim(),
        focus: document.activeElement?.dataset.action || null,
        sent: [window.__netDns, window.__netCalls.length],
        head: !!document.querySelector('.ipi-results:not([hidden])')
      }));
      assertEqual(info, { value: '8.8.8.8\n1.1.1.1', focus: 'run', sent: before, head: false }, 'filled, focused, nothing sent');
      await fill(page, 'ip-input', '');
    });

    await run.step('a lookup: compact input, the result header above 300 px, its status summary, actions and next step; "in your servers" filters', async () => {
      await fill(page, 'ip-input', IPS.join('\n'));
      await page.click('[data-action="run"]');
      await page.waitFor(IP_DONE, { timeout: 30000, message: 'rows looked up' });
      const info = await templateInfo(page, '.ipi-results-bar');
      assert(info.compact, 'compact');
      assert(info.head && info.head.top < 300, `the result header near the top: ${JSON.stringify(info.head)}`);
      assertEqual([info.run.label, info.run.primary], ['Run again', false], 'Run again while the box asks for these rows');
      assertEqual(await page.evaluate(() => document.querySelector('.ipi-results-bar .result-title').textContent), '4 addresses', 'the title');
      assertEqual(await statusOf(page, '.ipi-results-bar'), ['cdn:1', 'nets:1', 'countries:1', 'mine:1', 'priv:1'], 'the status summary');
      assertEqual(await actionsRow(page, '.ipi-results-bar'), ['summary+plain', 'menu:export', 'copy-link'], 'Copy summary + ¶, Export ▾, Copy link');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.ipi-results-bar .result-next .next-step')].map((b) => b.dataset.action)), ['reverse-all'], 'next: Domains on these addresses');
      const metrics = await page.evaluate(() => ({
        ids: [...document.querySelectorAll('.ipi-stats .metric')].map((m) => m.dataset.metric),
        controls: document.querySelectorAll('.ipi-stats button, .ipi-stats a, .ipi-stats [tabindex]').length
      }));
      assertEqual(metrics, { ids: ['ips', 'cdn', 'mine', 'priv', 'nets', 'countries'], controls: 0 }, 'the read-only metric strip');
      await page.click('.ipi-results-bar .status-item[data-status="mine"]');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.ipi-row .ipi-ip')].map((e) => e.textContent)), ['198.51.100.20'], 'in your servers only');
      await page.click('.ipi-results-bar .status-item[data-status="mine"]');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.ipi-row').length), 4, 'every row again');
      await shot(page, 'network-ip-result-desktop-light-en');
    });

    await run.step('Export ▾ (CSV, JSON), Copy summary and Copy link (without the private and the inventory addresses)', async () => {
      assertEqual(await openResultMenu(page, 'export', '.ipi-results-bar'), ['CSV', 'JSON'], 'the files');
      await page.press('Escape');
      await takeDownloads(page);
      await resultAction(page, '[data-export="csv"]', '.ipi-results-bar');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the CSV' });
      const [csv] = await takeDownloads(page);
      assertEqual(csv.name.replace(STAMP, 'STAMP'), 'ip-intel-STAMP.csv', 'its name');
      assert(IPS.every((ip) => csv.text.includes(ip)), `every address: ${csv.text.slice(0, 300)}`);
      const sum = await summaryOf(page, 'ip');
      assert(sum.lines[0].startsWith('**IP Intel · 4 addresses**'), sum.lines[0]);
      assertEqual(await linkOf(page, '.ipi-results-bar'), '#/ip?ips=203.0.113.7,104.16.5.5', 'Copy link');
    });

    run.group('Bulk Resolve (desktop)');
    await run.step('Run under the list, right-aligned; a job: the result header, its status summary and actions; the metric strip', async () => {
      await gotoRoute(page, '#/bulk');
      await fill(page, 'bulk-input', BULK_NAMES.join('\n'));
      const form = await templateInfo(page, '.bulk-progress');
      assert(form.run.top >= form.field.bottom && Math.abs(form.run.right - form.field.right) <= 2, `Run under the list, at its right: ${JSON.stringify(form)}`);
      await page.click('[data-action="bulk-run"]');
      await page.waitFor(BULK_DONE, { timeout: 30000, message: 'job done' });
      const info = await templateInfo(page, '.bulk-progress');
      assert(info.compact && info.head && info.head.top < 300, `compact, the result header near the top: ${JSON.stringify(info)}`);
      assertEqual(await page.evaluate(() => document.querySelector('.bulk-progress .result-title').textContent), '5 host names resolved', 'the title');
      // The counts are drawn a moment after the last answer (a throttled redraw).
      await page.waitFor(() => document.querySelectorAll('.bulk-progress .status-item').length === 5, { message: 'the status summary' });
      const status = await statusOf(page, '.bulk-progress');
      assertEqual(status.map((s) => s.split(':')[0]), ['unresolved', 'hidden', 'resolving', 'direct', 'mine'], 'the status summary');
      assertEqual([status[0], status[1], status[2], status[4]], ['unresolved:1', 'hidden:1', 'resolving:4', 'mine:2'], 'its counts');
      assertEqual(await actionsRow(page, '.bulk-progress'), ['summary+plain', 'menu:export', 'copy-link'], 'Copy summary + ¶, Export ▾, Copy link');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.bulk-stats .metric')].map((m) => m.dataset.metric)), ['names', 'hidden', 'direct', 'unresolved'], 'the metric strip');
      await page.click('.bulk-progress .status-item[data-status="unresolved"]');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="bulk-filter"]').value, document.querySelectorAll('.bulk-hosts tbody tr.dt-row').length]), ['unresolved', 1], 'a status item sets the Show select');
      await page.click('.bulk-progress .status-item[data-status="unresolved"]');
      await shot(page, 'network-bulk-result-desktop-light-en');
    });

    await run.step('Export ▾ holds both tables; Copy summary (new) and Copy link; "Use in IP Intel" only fills IP Intel\'s box', async () => {
      assertEqual(await openResultMenu(page, 'export', '.bulk-progress'), ['Host names (CSV)', 'Host names (JSON)', 'IP addresses (CSV)', 'IP addresses (JSON)'], 'the files');
      await page.press('Escape');
      await takeDownloads(page);
      await resultAction(page, '[data-export="ips-csv"]', '.bulk-progress');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the IP addresses CSV' });
      const [csv] = await takeDownloads(page);
      assertEqual(csv.name.replace(STAMP, 'STAMP'), 'bulk-ips-www.example.com-STAMP.csv', 'its name');
      assert(['192.0.2.1', '104.16.5.5', '203.0.113.12', '10.0.0.5'].every((ip) => csv.text.includes(ip)), csv.text.slice(0, 300));
      const sum = await summaryOf(page, 'bulk');
      assertEqual(sum.lines.slice(0, 2), ['**Bulk Resolve · 5 host names**', '- 4 resolve · 1 not resolving'], 'Copy summary');
      assert(sum.lines.includes('- Not resolving: `missing.example.com`'), sum.lines.join('\n'));
      assertEqual(await linkOf(page, '.bulk-progress'), `#/bulk?names=${BULK_NAMES.join(',')}`, 'Copy link');
      const href = await page.evaluate(() => document.querySelector('.bulk-progress [data-action="bulk-to-ip"]').getAttribute('href'));
      const params = new URLSearchParams(href.split('?')[1]);
      assertEqual([href.split('?')[0], params.get('run'), params.get('ips').split(',').sort()], ['#/ip', '0', ['10.0.0.5', '104.16.5.5', '192.0.2.1', '203.0.113.12']], 'a fill-only link');
    });

    run.group('Reverse DNS (desktop)');
    await run.step('a sweep: the result header, its status summary, actions and next steps; the compact input names the focus domain', async () => {
      await gotoRoute(page, '#/ptr');
      await fill(page, 'ptr-target', '192.0.2.0/29');
      await fill(page, 'ptr-focus', 'example.com');
      await sleep(250);
      await page.click('[data-action="ptr-run"]');
      await page.waitFor(PTR_DONE, { timeout: 30000, message: 'sweep done' });
      const info = await templateInfo(page, '.ptr-progress');
      assert(info.compact && info.head && info.head.top < 300, `compact, the result header near the top: ${JSON.stringify(info)}`);
      const head = await page.evaluate(() => ({
        title: document.querySelector('.ptr-progress .result-title').textContent,
        summary: document.querySelector('.ptr-form-card .tool-input-summary')?.textContent || '',
        next: [...document.querySelectorAll('.ptr-progress .result-next .next-step')].map((b) => b.dataset.action)
      }));
      assertEqual([head.title, head.next], ['Reverse DNS of 192.0.2.0/29', ['ptr-to-scan', 'ptr-to-inventory']], 'the title, the next steps');
      assert(/your domain: example\.com/.test(head.summary), `the summary line: ${head.summary}`);
      assertEqual(await statusOf(page, '.ptr-progress'), ['failed:1', 'mismatch:1', 'confirmed:2', 'named:3', 'none:4'], 'the status summary');
      assertEqual(await actionsRow(page, '.ptr-progress'), ['summary+plain', 'menu:export', 'copy-link'], 'Copy summary + ¶, Export ▾, Copy link');
      assertEqual(await openResultMenu(page, 'export', '.ptr-progress'), ['names.txt', 'CSV', 'JSON'], 'the files');
      await page.press('Escape');
      await takeDownloads(page);
      await resultAction(page, '[data-export="names"]', '.ptr-progress');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'names.txt' });
      const [names] = await takeDownloads(page);
      assertEqual([names.name, names.text], ['names.txt', 'mail.example.com\nwww.example.com\nhost.example.net\n'], 'names.txt');
      const sum = await summaryOf(page, 'ptr');
      assertEqual(sum.lines.slice(0, 2), ['**Reverse DNS · `192.0.2.0/29`**', '- 8 addresses swept · 3 with a PTR name · 4 without reverse DNS · 1 lookup failed'], 'Copy summary');
      assertEqual(await linkOf(page, '.ptr-progress'), '#/ptr?target=192.0.2.0/29&focus=example.com', 'Copy link');
      await shot(page, 'network-ptr-result-desktop-light-en');
    });

    run.group('Servers (desktop)');
    await run.step('typing: the result header counts the servers; "1 warning" takes the focus to it; Export ▾ writes targets.txt', async () => {
      await gotoRoute(page, '#/inventory');
      await fill(page, 'inventory-text', `${SERVERS}\nweb02 192.0.2.1`);
      await page.waitFor(() => document.querySelector('.inv-head')?.dataset.servers === '4', { message: 'parsed' });
      assertEqual(await page.evaluate(() => [document.querySelector('.inv-head .result-title').textContent, document.querySelector('[data-action="save"]').disabled]), ['4 servers', false], 'the title; Save ready');
      assertEqual(await statusOf(page, '.inv-head'), ['warnings:1', 'ips:4'], 'the status summary');
      await page.click('.inv-head .status-item[data-status="warnings"]');
      assert(await page.evaluate(() => document.activeElement?.classList.contains('inv-warning')), 'the focus on the first warning');
      assertEqual(await actionsRow(page, '.inv-head'), ['menu:export'], 'Export ▾ only');
      assertEqual(await openResultMenu(page, 'export', '.inv-head'), ['targets.txt', 'CSV', 'JSON'], 'the files');
      await page.press('Escape');
      await takeDownloads(page);
      await resultAction(page, '[data-export="targets"]', '.inv-head');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'targets.txt' });
      const [targets] = await takeDownloads(page);
      assertEqual(targets.name, 'targets.txt', 'its name');
      assert(/192\.0\.2\.1/.test(targets.text) && /10\.0\.0\.5/.test(targets.text), targets.text);
      await shot(page, 'network-inventory-desktop-light-en');
    });

    await run.step('Origin map and Exposure audit: where things stay is a privacy note, not a green alert', async () => {
      await page.click('.inv-tabs [data-tab="origins"]');
      await page.waitFor(() => !!document.querySelector('.om-panel'), { message: 'Origin map' });
      assertEqual(await page.evaluate(() => [!!document.querySelector('.om-card .privacy-note'), document.querySelectorAll('.om-panel .alert-ok, .om-panel > .alert').length]), [true, 0], 'Origin map');
      await page.click('.inv-tabs [data-tab="exposure"]');
      await page.waitFor(() => !!document.querySelector('.exp-panel'), { message: 'Exposure audit' });
      assertEqual(await page.evaluate(() => [!!document.querySelector('.exp-lead .privacy-note'), document.querySelectorAll('.exp-panel .alert-ok').length]), [true, 0], 'Exposure audit');
      await page.click('.inv-tabs [data-tab="inventory"]');
    });

    await run.step('desktop: no missing keys; no console errors, exceptions or CSP violations', async () => {
      await assertNoMissingKeys(page);
      await assertClean(page, 'desktop', origin);
    });

    run.group('Phones');
    await run.step('375×812 (Turkish, dark): Copy summary alone in the row, the rest behind "⋯"; every table a card per row, nothing scrolls sideways', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      for (const [id, head, table, done] of [
        ['ip', '.ipi-results-bar', '.ipi-table', IP_DONE], ['bulk', '.bulk-progress', '.bulk-hosts', BULK_DONE], ['ptr', '.ptr-progress', '.ptr-table', PTR_DONE]
      ]) {
        await gotoRoute(page, `#/${id}`);
        await page.waitFor(done, { timeout: 15000, message: `${id}: the kept result` });
        assertEqual(await actionsRow(page, head), ['summary', 'menu:more'], `${id}: Copy summary, ⋯`);
        assertEqual(await cardMode(page, table), CARDS, `${id}: cards`);
        await assertNoHorizontalScroll(page, `${id} 375 tr dark`);
        await shot(page, `network-${id}-result-375-dark-tr`);
      }
      const items = await openResultMenu(page, 'more', '.ptr-progress');
      assertEqual(items.slice(-4), ['names.txt', 'CSV', 'JSON', 'Bağlantıyı kopyala'], `the rest, in order: ${items.join(' | ')}`);
      await page.press('Escape');
      await gotoRoute(page, '#/inventory');
      assertEqual(await cardMode(page, '.inv-table'), CARDS, 'Servers: cards');
      await assertNoHorizontalScroll(page, 'inventory 375 tr dark');
      await gotoRoute(page, '#/about');
      assertEqual(await cardMode(page, '#about-sources .about-table'), CARDS, 'About: cards');
      await assertNoHorizontalScroll(page, 'about 375 tr dark');
      await shot(page, 'network-about-375-dark-tr');
    });

    await run.step('320 px (Turkish, light): every table a card per row, each label above its value, none wider than its card; no page scrolls sideways, empty or with a result', async () => {
      await page.setViewport({ width: 320, height: 700, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'tr');
      for (const [id, table, done] of CARD_TABLES) {
        await gotoRoute(page, `#/${id}`);
        if (done) await page.waitFor(done, { timeout: 15000, message: `${id}: the kept result` });
        await sleep(150);
        // IP Intel's "Alan adlarını bul" is the widest value a card holds.
        assertEqual(await cardMode(page, table), { ...CARDS, labels: 'above' }, `${id}: cards at 320 px`);
        await assertNoHorizontalScroll(page, `${id} 320 tr with a result`);
        await shot(page, `network-${id}-result-320-light-tr`);
      }
      await setLangUi(page, 'en');
      const fresh = await openPage(browser, server, { width: 320, height: 700, mobile: true });
      pages.push({ ...fresh, where: 'phone' });
      await setLangUi(fresh.page, 'en');
      for (const id of ['ip', 'bulk', 'ptr']) {
        await gotoRoute(fresh.page, `#/${id}`);
        await assertNoHorizontalScroll(fresh.page, `${id} 320 empty`);
      }
      await shot(fresh.page, 'network-ptr-empty-320-light-en');
    });

    await run.step('no missing keys; no console errors, exceptions or CSP violations; nothing sent', async () => {
      await assertNoMissingKeys(page);
      for (const p of pages) await assertClean(p.page, p.where, origin);
      assertEqual(pages.map((p) => p.hits), pages.map(() => []), 'no request reached the network');
      for (const p of pages) assertEqual(await p.page.evaluate(() => window.__netBlocked.slice()), [], `${p.where}: no request the page script had to block`);
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
