#!/usr/bin/env node
/**
 * ptr.e2e.mjs — end-to-end test of the "Reverse DNS" view (and its hand-offs) in a real headless
 * Chrome/Edge. OFFLINE: every DoH query is answered in the page by a fake resolver built from the
 * table below (window.fetch wrapped before the app loads), RIPEstat's announced-prefixes and the
 * RDAP bootstrap are answered by the same wrapper, every other https:// request is blocked, and
 * every request that leaves the page's origin is counted through CDP.
 *
 *   node tests/e2e/ptr.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry (DNS group, after IP Intel), the empty state, input issues (an IPv6
 * network, a network over the /22 cap with its suggestion, private space), a /28 sweep with a
 * focus domain (focus rows first, a collapsed pattern, the forward-check statuses, the operator
 * from a PTR name, the inventory match, stats, filters, "Expand patterns", row details), the
 * CSV / JSON / names.txt exports, "Add to Servers" (the Servers editor gets a draft, nothing is
 * saved), "Add names to a scan" (Subdomains gets the names in exact mode, the user presses Scan,
 * the scan's origin panel links an IPv4 network back to a sweep that waits for a click), an AS
 * (one RIPEstat request, the prefix picker, the cap, a sweep of the picked prefixes), a shared
 * link that pre-fills and waits, keyboard focus Sweep ⇄ Stop and a stopped sweep, Domain
 * Health's mail identity (FCrDNS) rows, TR / EN × light / dark at 375 px, zero console errors /
 * CSP violations / missing i18n keys, nothing sent outside the page.
 *
 * Data is documentation space only (example.com / .net / .org, 192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24, 198.18.0.0/15, 2001:db8::/32, AS64496) plus the Cloudflare edge 104.16.1.1.
 */

import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, sleep, takeDownloads, waitReady
} from './scan.e2e.mjs';

const CF_EDGE = '104.16.1.1';
const rev = (ip) => `${ip.split('.').reverse().join('.')}.in-addr.arpa`;

/** The fake DNS: name → { TYPE: [data…] }; `{}` = the name exists without that type. */
function fakeTable() {
  const T = {};
  const add = (name, type, ...data) => {
    const node = T[name] || (T[name] = {});
    (node[type] || (node[type] = [])).push(...data);
  };
  add(rev('192.0.2.1'), 'PTR', 'mail.example.com');
  add('mail.example.com', 'A', '192.0.2.1');
  add(rev('192.0.2.2'), 'PTR', 'www.example.com');
  add('www.example.com', 'A', CF_EDGE);
  add(rev('192.0.2.3'), 'PTR', 'host.example.net');
  add('host.example.net', 'A', '192.0.2.3');
  T[rev('192.0.2.6')] = {};
  for (let i = 7; i <= 14; i += 1) {
    const name = `192-0-2-${i}.dyn.isp.example.net`;
    add(rev(`192.0.2.${i}`), 'PTR', name);
    add(name, 'A', `192.0.2.${i}`);
  }
  add(rev('192.0.2.15'), 'PTR', 'server-192-0-2-15.fra50.r.cloudfront.net');
  add('server-192-0-2-15.fra50.r.cloudfront.net', 'A', '192.0.2.15');
  add(rev('198.51.100.1'), 'PTR', 'ns1.example.org');
  add('ns1.example.org', 'A', '198.51.100.1');
  add('example.com', 'MX', { preference: 10, exchange: 'mail.example.com' }, { preference: 20, exchange: 'mx2.example.com' });
  add('mx2.example.com', 'A', '192.0.2.4');
  return T;
}

/** Fixed rcodes (name|TYPE → rcode). */
const RCODES = { [`${rev('192.0.2.5')}|PTR`]: 'SERVFAIL' };

const WINDOW = { query_starttime: '2026-09-13T08:00:00', query_endtime: '2026-09-27T08:00:00' };
const RIPE = {
  status: 'ok',
  messages: [['info', 'Results exclude routes with very low visibility.']],
  data: {
    resource: '64496', ...WINDOW, latest_time: WINDOW.query_endtime,
    prefixes: [
      ['192.0.2.0/24', WINDOW.query_endtime], ['198.51.100.0/24', WINDOW.query_endtime], ['203.0.113.0/24', '2026-09-20T08:00:00'],
      ['198.18.0.0/15', WINDOW.query_endtime], ['2001:db8::/32', WINDOW.query_endtime]
    ].map(([prefix, endtime]) => ({ prefix, timelines: [{ starttime: WINDOW.query_starttime, endtime }] }))
  }
};

/** In-page stubs: DoH from the table (NXDOMAIN outside it), RIPEstat announced-prefixes, the RDAP bootstrap. */
const fakeScript = (table, rcodes, ripe) => `(() => {
  const T = ${JSON.stringify(table)};
  const R = ${JSON.stringify(rcodes)};
  const RIPE = ${JSON.stringify(ripe)};
  window.__fakeDnsLog = [];
  window.__ripeLog = [];
  window.__fakeDnsDelay = 0;
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://stat.ripe.net/data/announced-prefixes/')) {
      window.__ripeLog.push(url);
      return json(RIPE);
    }
    if (url.startsWith('https://data.iana.org/rdap/')) return json({ services: [] });
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__fakeDnsLog.push({ name, type: q.type });
    if (window.__fakeDnsDelay) {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, window.__fakeDnsDelay);
        init?.signal?.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
      });
    }
    const node = T[name];
    const rcode = R[name + '|' + q.type] || (node ? 'NOERROR' : 'NXDOMAIN');
    const answers = rcode === 'NOERROR' && node && node[q.type] ? node[q.type].map((data) => ({ name, type: q.type, ttl: 300, data })) : [];
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode,
      questions: [{ name: q.name, type: q.type }], answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

async function nodeChecks(run) {
  const V = await import('../../assets/js/views/ptr.js');
  const S = await import('../../assets/js/views/subdomains.js');
  run.group('Node: views/ptr.js and the Subdomains hand-off helpers');
  await run.step('share params, issue keys, the names intent round trip', () => {
    assertEqual(V.shareParams('192.0.2.0/24\n198.51.100.7', 'Example.COM'), { target: '192.0.2.0/24,198.51.100.7', focus: 'example.com' }, 'share');
    assertEqual(V.shareParams('x'.repeat(500)), null, 'too long for a link');
    assertEqual(V.issueKey({ code: 'too-large', params: { suggestion: '' } }), 'ptr.issue.too-large.range', 'range key');
    const intent = V.buildNamesIntent({ names: ['mail.example.com'], domains: ['example.com'], label: '192.0.2.0/28', now: 1000 });
    assertEqual(S.namesFromIntent(intent, 2000), { names: ['mail.example.com'], domains: ['example.com'], label: '192.0.2.0/28', source: 'ptr', mode: 'exact' }, 'round trip');
    assertEqual(S.namesFromIntent(intent, 1000 + S.NAMES_INTENT_MAX_AGE + 1), null, 'stale');
    assertEqual(S.namesFromIntent({ ...intent, target: 'scan' }, 2000), null, 'another view');
  });
}

const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent || '', sel);
const jsClick = (page, sel) => page.evaluate((s) => { const el = document.querySelector(s); if (!el) throw new Error(`no ${s}`); el.click(); }, sel);
const setSelect = (page, sel, value) => page.evaluate(([s, v]) => {
  const el = document.querySelector(s);
  el.value = v;
  el.dispatchEvent(new Event('change', { bubbles: true }));
}, [sel, value]);
const typeTarget = (page, value) => page.evaluate((v) => {
  const ta = document.querySelector('[data-role="ptr-target"]');
  ta.value = v;
  ta.dispatchEvent(new Event('input', { bubbles: true }));
}, value);
const issues = (page) => page.evaluate(() => [...document.querySelectorAll('.ptr-issues .alert')].map((a) => a.dataset.issue));
const dnsCount = (page) => page.evaluate(() => window.__fakeDnsLog.length);
/** Table rows: [key cell text, PTR text, status] in display order. */
const rows = (page) => page.evaluate(() => [...document.querySelectorAll('.ptr-table tbody tr.dt-row')].map((tr) => {
  const cells = [...tr.cells].slice(1);
  return {
    ip: cells[0].textContent.trim(),
    ptr: cells[1].textContent.trim(),
    status: cells[2].querySelector('[data-status]')?.dataset.status || cells[2].textContent.trim(),
    operator: cells[3].textContent.trim(),
    server: cells[4].textContent.trim(),
    focus: tr.classList.contains('is-focus'),
    pattern: tr.classList.contains('ptr-row-pattern')
  };
}));
const waitDone = (page, message = 'sweep done') => page.waitFor(() => ['done', 'cancelled'].includes(document.querySelector('.ptr-progress')?.dataset.status)
  && !document.querySelector('[data-action="ptr-run"]').hidden, { timeout: 30000, message });

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  await nodeChecks(run);

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
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript(fakeTable(), RCODES, RIPE) });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/ptr: nav entry after IP Intel in the DNS group, empty state, nothing sent', async () => {
      await page.goto(`${server.url}#/ptr`);
      await waitReady(page);
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.setInventory('web01 192.0.2.1'));
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'ptr');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/ip"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '')) : [];
      });
      assertEqual(nav, ['global', 'lookup', 'bulk', 'ip', 'ptr', 'health'], 'DNS group');
      assertEqual(await text(page, 'h1'), 'Reverse DNS', 'title');
      assert(await page.evaluate(() => !!document.querySelector('.ptr-empty .empty')), 'empty state');
      assertEqual(await dnsCount(page), 0, 'no DNS query');
      await shot(page, opts, 'ptr-empty-desktop-light-en');
    });

    await run.step('input issues: an IPv6 network is explained, a /16 is over the cap with a /22 to use, private space is left out', async () => {
      await typeTarget(page, '2001:db8::/64');
      await page.waitFor(() => !!document.querySelector('.ptr-issues [data-issue="v6-range"]'), { message: 'v6 issue' });
      assert(/18 quintillion/.test(await text(page, '.ptr-issues [data-issue="v6-range"]')), 'why no IPv6 sweep');
      await typeTarget(page, '198.18.0.0/16');
      await page.waitFor(() => !!document.querySelector('.ptr-issues [data-issue="too-large"]'), { message: 'too large' });
      assert(/65,536 addresses.*1,024/.test(await text(page, '.ptr-issues [data-issue="too-large"]')), 'counts');
      await page.click('[data-action="ptr-use-suggestion"]');
      await page.waitFor(() => document.querySelector('[data-role="ptr-target"]').value === '198.18.0.0/22', { message: 'suggestion used' });
      assertEqual(await issues(page), ['private', 'nothing'], 'benchmark space is private');
      await typeTarget(page, '10.0.0.0/24');
      await sleep(250);
      await page.click('[data-action="ptr-run"]');
      await sleep(150);
      assertEqual(await dnsCount(page), 0, 'nothing sent for private space');
      assert(!await page.evaluate(() => !!document.querySelector('.ptr-results')), 'no results');
    });

    await run.step('sweep 192.0.2.0/28 with focus example.com: focus rows first, one pattern, statuses, operator, server', async () => {
      await typeTarget(page, '192.0.2.0/28');
      await page.type('[data-role="ptr-focus"]', 'example.com');
      await sleep(200);
      assert(/16 addresses/.test(await text(page, '.ptr-parsed')), 'parsed count');
      await page.click('[data-action="ptr-run"]');
      await waitDone(page);
      assertEqual(await page.evaluate(() => document.querySelector('.ptr-progress').dataset.status), 'done', 'finished');
      await setSelect(page, '[data-role="ptr-filter"]', 'all');
      await sleep(150);
      const r = await rows(page);
      assertEqual(r.map((x) => x.ip), ['192.0.2.1', '192.0.2.2', '192.0.2.3', '8 addresses192.0.2.7 – 192.0.2.14', '192.0.2.15', '192.0.2.0', '192.0.2.4', '192.0.2.6', '192.0.2.5'], 'order');
      assertEqual(r.map((x) => x.status).slice(0, 3), ['confirmed', 'mismatch', 'confirmed'], 'statuses');
      assertEqual([r[0].focus, r[1].focus, r[2].focus], [true, true, false], 'focus rows');
      assert(r[3].pattern && /IP\.dyn\.isp\.example\.net/.test(r[3].ptr), `pattern row: ${r[3].ptr}`);
      assert(/Amazon CloudFront/.test(r[4].operator), `operator from the PTR name: ${r[4].operator}`);
      assert(/web01/.test(r[0].server), 'inventory match');
      assertEqual(r.slice(5).map((x) => x.status), ['nxdomain', 'nxdomain', 'no-ptr', 'servfail'], 'no name, then failures');
      const stats = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.ptr-stats .stat')].filter((s) => !s.hidden).map((s) => [s.dataset.stat, s.querySelector('.stat-value').textContent])));
      assertEqual(stats, { addresses: '16', named: '12', confirmed: '11', none: '3', failed: '1', focus: '2' }, 'stats');
      assert(/Under example\.com/.test(await text(page, '.ptr-stats [data-stat="focus"]')), 'focus card');
      const queried = await page.evaluate(() => new Set(window.__fakeDnsLog.filter((q) => q.type === 'PTR').map((q) => q.name)).size);
      assertEqual(queried, 16, 'one reverse name per address');
      assert(/target=192\.0\.2\.0%2F28&focus=example\.com$/.test(await page.evaluate(() => location.hash)), 'the URL carries the run');
      await shot(page, opts, 'ptr-results-desktop-light-en');
    });

    await run.step('filters, stat cards, "Expand patterns" and row details', async () => {
      await setSelect(page, '[data-role="ptr-filter"]', 'failed');
      await sleep(120);
      assertEqual((await rows(page)).map((x) => x.ip), ['192.0.2.5'], 'failed only');
      await page.click('.ptr-stats [data-stat="named"]');
      await sleep(120);
      assertEqual((await rows(page)).length, 5, 'with a PTR name (pattern collapsed)');
      await jsClick(page, '[data-role="ptr-expand"]');
      await page.waitFor(() => document.querySelectorAll('.ptr-table tbody tr.dt-row').length === 12, { message: 'expanded' });
      await jsClick(page, '[data-role="ptr-expand"]');
      await page.waitFor(() => document.querySelectorAll('.ptr-table tbody tr.dt-row').length === 5, { message: 'collapsed again' });
      await page.evaluate(() => [...document.querySelectorAll('.ptr-table tbody tr.dt-row')][1].querySelector('.dt-expand-btn').click());
      await page.waitFor(() => !!document.querySelector('.ptr-table .dt-details .ptr-forward'), { message: 'details' });
      const det = await text(page, '.ptr-table .dt-details');
      assert(/2\.2\.0\.192\.in-addr\.arpa/.test(det) && /other addresses/.test(det) && new RegExp('104\\.16\\.1\\.1').test(det), `details: ${det}`);
      await shot(page, opts, 'ptr-details-desktop-light-en');
    });

    await run.step('exports: CSV one line per address, JSON, names.txt without generated names', async () => {
      await setSelect(page, '[data-role="ptr-filter"]', 'all');
      await sleep(100);
      await takeDownloads(page);
      await page.click('.ptr-table [data-export="csv"]');
      await page.click('.ptr-table [data-export="json"]');
      await page.click('[data-action="ptr-names"]');
      await sleep(150);
      const files = await takeDownloads(page);
      const csv = files.find((f) => f.name.endsWith('.csv'));
      const lines = csv.text.trim().split(/\r?\n/);
      assertEqual(lines[0], 'ip,status,ptr,confirmed,forward,template,operator,servers,focus,error', 'CSV header');
      assertEqual(lines.length, 17, 'header + 16 addresses');
      assert(csv.bom, 'BOM');
      const j = JSON.parse(files.find((f) => f.name.endsWith('.json')).text);
      assertEqual([j.schema, j.results.length, j.focus, j.summary.byStatus.confirmed], ['domainscope.ptr-sweep/1', 16, 'example.com', 11], 'JSON');
      assertEqual(files.find((f) => f.name === 'names.txt').text, 'mail.example.com\nwww.example.com\nhost.example.net\n', 'names.txt');
    });

    await run.step('Add to Servers: the Servers editor gets a draft with the confirmed hosts; nothing is saved', async () => {
      await page.click('[data-action="ptr-to-inventory"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'inventory' && !!document.querySelector('[data-role="inventory-text"]'), { message: 'Servers view' });
      const editor = await page.evaluate(() => document.querySelector('[data-role="inventory-text"]').value);
      assert(/^web01 192\.0\.2\.1\n\n# reverse DNS sweep of 192\.0\.2\.0\/28 \(\d{4}-\d{2}-\d{2}\): forward-confirmed hosts\nhost\.example\.net 192\.0\.2\.3\n$/.test(editor), `editor: ${JSON.stringify(editor)}`);
      assert(await page.evaluate(() => /Unsaved changes/.test(document.querySelector('.inv-status')?.textContent || '')), 'unsaved');
      assertEqual(await page.evaluate(async () => (await import('./assets/js/state.js')).state.inventory.text), 'web01 192.0.2.1', 'saved inventory unchanged');
      await shot(page, opts, 'ptr-inventory-draft-desktop-light-en');
    });

    await run.step('back on #/ptr the results are kept; Add names to a scan → Subdomains in exact mode, the user presses Scan', async () => {
      await gotoRoute(page, 'ptr');
      await page.waitFor(() => document.querySelector('.ptr-progress')?.dataset.status === 'done', { message: 'results kept' });
      const before = await dnsCount(page);
      await page.click('[data-action="ptr-to-scan"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'subdomains' && !!document.querySelector('[data-role="names-chip"]'), { message: 'names chip' });
      const chip = await page.evaluate(() => ({
        count: document.querySelector('[data-role="names-chip"]').dataset.count,
        title: document.querySelector('[data-role="names-chip"] .sub-zone-title').textContent,
        mode: document.querySelector('[data-role="names-chip"] .seg-btn[aria-pressed="true"]')?.dataset.value || '',
        domain: document.querySelector('[data-role="sub-domain"]').value,
        plan: document.querySelector('.sub-wl-plan')?.dataset.handoffExact
      }));
      assertEqual([chip.count, chip.domain, chip.mode, chip.plan], ['2', 'example.com', 'exact', '1'], 'chip');
      assert(/2 names from the reverse DNS sweep of 192\.0\.2\.0\/28/.test(chip.title), chip.title);
      await sleep(200);
      assertEqual(await dnsCount(page), before, 'nothing starts by itself');
      await shot(page, opts, 'ptr-subdomains-chip-desktop-light-en');
      await page.click('[data-action="sub-run"]');
      await page.waitFor(() => !!document.querySelector('.sub-zone-banner[data-handoff-mode="exact"]')
        && [...document.querySelectorAll('.sub-results tbody tr')].some((tr) => /www\.example\.com/.test(tr.textContent))
        && !!document.querySelector('.sub-org'), { timeout: 30000, message: 'exact scan with an origin panel' });
      const asked = await page.evaluate(() => [...new Set(window.__fakeDnsLog.map((q) => q.name))]);
      assert(asked.includes('mail.example.com') && asked.includes('www.example.com'), 'the names were resolved');
    });

    await run.step('the origin panel links an IPv4 network to a Reverse DNS sweep that waits for a click', async () => {
      const href = await page.evaluate(() => document.querySelector('.sub-org-net[data-cidr="192.0.2.0/24"] [data-action="sub-org-ptr"]')?.getAttribute('href'));
      assertEqual(href, '#/ptr?target=192.0.2.0%2F24&focus=example.com', 'link');
      await shot(page, opts, 'ptr-subdomains-origin-link-desktop-light-en');
      const before = await dnsCount(page);
      await page.click('.sub-org-net[data-cidr="192.0.2.0/24"] [data-action="sub-org-ptr"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'ptr' && !!document.querySelector('.ptr-prompt [data-prompt="link"]'), { message: 'prompt' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="ptr-target"]').value), '192.0.2.0/24', 'pre-filled');
      assert(/256 addresses/.test(await text(page, '.ptr-prompt')), 'prompt count');
      await sleep(200);
      assertEqual(await dnsCount(page), before, 'a link never sweeps by itself');
      await shot(page, opts, 'ptr-link-prompt-desktop-light-en');
    });

    await run.step('keyboard: Enter on Sweep moves focus to Stop, Enter on Stop stops and returns focus', async () => {
      await page.evaluate(() => { window.__fakeDnsDelay = 150; });
      await page.evaluate(() => document.querySelector('[data-action="ptr-run"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.activeElement?.dataset.action === 'ptr-stop', { message: 'focus on Stop' });
      assert(!await page.evaluate(() => !!document.querySelector('.ptr-prompt [data-prompt="link"]')), 'prompt gone');
      await sleep(400);
      await page.press('Enter');
      await page.waitFor(() => document.activeElement?.dataset.action === 'ptr-run', { message: 'focus back on Sweep' });
      await waitDone(page, 'stopped');
      assertEqual(await page.evaluate(() => document.querySelector('.ptr-progress').dataset.status), 'cancelled', 'cancelled');
      assert(/Stopped — \d+ of 256 addresses were looked up/.test(await text(page, '.ptr-progress')), 'stopped note');
      await page.evaluate(() => { window.__fakeDnsDelay = 0; });
    });

    await run.step('an AS: one RIPEstat request, the prefix picker, the cap, a sweep of the picked prefixes', async () => {
      await typeTarget(page, 'AS64496');
      await page.waitFor(() => /List prefixes/.test(document.querySelector('[data-action="ptr-run"]').textContent), { message: 'button label' });
      await page.click('[data-action="ptr-run"]');
      await page.waitFor(() => document.querySelectorAll('.ptr-asn-table tbody tr.dt-row').length === 5, { message: 'picker' });
      const ripe = await page.evaluate(() => window.__ripeLog);
      assertEqual(ripe, ['https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64496&sourceapp=domainscope'], 'one request');
      const picker = await page.evaluate(() => [...document.querySelectorAll('.ptr-asn-table tbody tr.dt-row')].map((tr) => {
        const cb = tr.querySelector('input[type="checkbox"]');
        return `${cb.dataset.prefix}:${cb.disabled ? 'off' : 'on'}:${tr.cells[3].textContent.trim()}`;
      }));
      assertEqual(picker, [
        '192.0.2.0/24:on:—', '198.18.0.0/15:off:larger than a /22Sweep 198.18.0.0/22', '198.51.100.0/24:on:—',
        '203.0.113.0/24:on:no longer announced', '2001:db8::/32:off:IPv6: not swept'
      ], 'rows');
      for (const p of ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']) await jsClick(page, `.ptr-asn-table input[data-prefix="${p}"]`);
      assert(/Selected: 3 prefixes · 768 of at most 1,024 addresses/.test(await text(page, '.ptr-asn-selected')), 'selection');
      await jsClick(page, '.ptr-asn-table input[data-prefix="192.0.2.0/24"]');
      await shot(page, opts, 'ptr-asn-picker-desktop-light-en');
      await page.click('[data-action="ptr-asn-sweep"]');
      await waitDone(page, 'AS sweep');
      assertEqual(await page.evaluate(() => document.querySelector('.ptr-stats [data-stat="addresses"] .stat-value').textContent), '512', 'two /24s');
      assert(/AS64496: 198\.51\.100\.0\/24, 203\.0\.113\.0\/24/.test(await text(page, '.ptr-results-title')), 'label');
      await setSelect(page, '[data-role="ptr-filter"]', 'ptr');
      await sleep(120);
      assertEqual((await rows(page)).map((x) => `${x.ip} ${x.ptr} ${x.status}`), ['198.51.100.1 ns1.example.org confirmed'], 'the one name');
      assertEqual(await page.evaluate(() => window.__ripeLog.length), 1, 'still one RIPEstat request');
    });

    await run.step('Domain Health: the MX addresses get forward-confirmed reverse DNS rows and a table', async () => {
      await page.evaluate(() => { location.hash = '#/health?domain=example.com'; });
      await page.waitFor(() => !!document.querySelector('.hlt-check[data-id="mail-identity.fcrdns-ok"]'), { timeout: 30000, message: 'health report' });
      const ids = await page.evaluate(() => [...document.querySelectorAll('.hlt-check')].filter((c) => c.dataset.id.startsWith('mail-identity')).map((c) => `${c.dataset.id}:${c.dataset.severity}`));
      assertEqual(ids.sort(), ['mail-identity.fcrdns-missing:warn', 'mail-identity.fcrdns-ok:ok'], 'checks');
      assert(/mx2\.example\.com \(192\.0\.2\.4\)/.test(await text(page, '.hlt-check[data-id="mail-identity.fcrdns-missing"]')), 'missing detail');
      const table = await page.evaluate(() => [...document.querySelectorAll('.hlt-fcrdns tbody tr')].map((tr) => `${tr.dataset.status}:${tr.cells[1].textContent}`));
      assertEqual(table, ['confirmed:192.0.2.1Reverse DNS', 'nxdomain:192.0.2.4Reverse DNS'], 'table');
      assertEqual(await page.evaluate(() => document.querySelector('.hlt-fcrdns a.hlt-fcrdns-sweep').getAttribute('href')), '#/ptr?target=192.0.2.1&focus=example.com', 'sweep link');
      await page.evaluate(() => document.querySelector('.hlt-fcrdns').scrollIntoView());
      await shot(page, opts, 'ptr-health-fcrdns-desktop-light-en');
    });

    run.group('Phone 375×667, Turkish / English, light / dark');
    await run.step('the form, the picker and the results at 375 px: no horizontal scroll', async () => {
      await gotoRoute(page, 'ptr?target=192.0.2.0/28&focus=example.com');
      await page.click('[data-action="ptr-run"]');
      await waitDone(page, 'phone sweep');
      await page.setViewport({ width: 375, height: 667, mobile: true });
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await page.waitFor(() => document.querySelector('.ptr-progress')?.dataset.status === 'done', { message: 'results kept after the language switch' });
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await page.evaluate(() => window.scrollTo(0, 0));
          await assertNoHorizontalScroll(page, `ptr ${scheme} ${lang}`);
          await shot(page, opts, `ptr-results-mobile-${scheme}-${lang}`);
        }
      }
      await typeTarget(page, 'AS64496');
      await page.click('[data-action="ptr-run"]');
      await page.waitFor(() => document.querySelectorAll('.ptr-asn-table tbody tr.dt-row').length === 5, { message: 'picker (phone)' });
      await assertNoHorizontalScroll(page, 'picker');
      await shot(page, opts, 'ptr-asn-picker-mobile-light-en');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.setViewport({ width: 1440, height: 900 });
      await shot(page, opts, 'ptr-asn-picker-desktop-dark-en');
      await setLangUi(page, 'tr');
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, opts, 'ptr-results-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'ptr', origin));
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
