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
 * Covers: the nav entry (Map IPs to servers, after Bulk Resolve), the empty state, input issues (an IPv6
 * network, a network over the /22 cap with its suggestion, a wholly private one without,
 * private space, a range typed with spaces, "ASN 64496"), a /28 sweep with a focus domain
 * (focus rows first, a collapsed pattern, the forward-check statuses, the operator from a PTR
 * name, the inventory match, stats, filters, "Expand patterns", row details), the CSV / JSON /
 * names.txt exports (a filtered JSON export keeps the whole sweep's summary), "Add to Servers"
 * (the Servers editor gets a draft in the list's own format, nothing is saved, a second click
 * adds nothing, a JSON map is left alone and the hosts are shown to copy), "Add names to a
 * scan" (Subdomains gets the names in exact mode, the user presses Scan, the scan's origin
 * panel links an IPv4 network back to a sweep that waits for a click), an AS (Stop cancels
 * the lookup, typing a network drops it; one RIPEstat request, the prefix picker, the cap, a
 * sweep of the picked prefixes), a shared link that pre-fills and waits (one opened while a
 * sweep runs waits for it to end; a range typed with spaces stays one range in the URL, after
 * a reload and in a link typed with an en dash; a link naming the last sweep with another focus
 * domain fills the form, also over a draft), "Under your domain" off without a focus domain,
 * keyboard focus
 * Sweep ⇄ Stop and a stopped sweep, Domain Health's mail identity (FCrDNS) rows and table
 * (at 320 and 375 px too), TR / EN × light / dark at 375 px, zero console errors / CSP violations /
 * missing i18n keys, nothing sent outside the page.
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
  // eight provider-generated names; the one of 192.0.2.10 does not resolve back
  for (let i = 7; i <= 14; i += 1) {
    const name = `192-0-2-${i}.dyn.isp.example.net`;
    add(rev(`192.0.2.${i}`), 'PTR', name);
    add(name, 'A', i === 10 ? '198.51.100.10' : `192.0.2.${i}`);
  }
  add(rev('192.0.2.15'), 'PTR', 'server-192-0-2-15.fra50.r.cloudfront.net');
  add('server-192-0-2-15.fra50.r.cloudfront.net', 'A', '192.0.2.15');
  add(rev('198.51.100.1'), 'PTR', 'ns1.example.org');
  add('ns1.example.org', 'A', '198.51.100.1');
  add('example.com', 'MX', { preference: 10, exchange: 'mail.example.com' }, { preference: 20, exchange: 'mx2.example.com' },
    { preference: 30, exchange: 'mx-in-01.inbound.mailhost-provider.example.net' });
  add('mx2.example.com', 'A', '192.0.2.4');
  // a mail provider's MX host with a long name and a generic PTR that forward-confirms
  add('mx-in-01.inbound.mailhost-provider.example.net', 'A', '192.0.2.200');
  add(rev('192.0.2.200'), 'PTR', '192-0-2-200.out.mailhost-provider.example.net');
  add('192-0-2-200.out.mailhost-provider.example.net', 'A', '192.0.2.200');
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
      ['192.0.0.0/20', WINDOW.query_endtime], ['192.0.2.0/24', WINDOW.query_endtime], ['198.51.100.0/24', WINDOW.query_endtime], ['203.0.113.0/24', '2026-09-20T08:00:00'],
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
  window.__ripeDelay = 0;
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
  const wait = (ms, signal) => new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
  });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://stat.ripe.net/data/announced-prefixes/')) {
      window.__ripeLog.push(url);
      if (window.__ripeDelay) await wait(window.__ripeDelay, init?.signal);
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
    ip: (cells[0].querySelector('.ptr-ipcell, .ptr-ip') || cells[0]).textContent.trim(),
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
    await run.step('boots on #/ptr: nav entry after Bulk Resolve in Map IPs to servers, empty state, nothing sent', async () => {
      await page.goto(`${server.url}#/ptr`);
      await waitReady(page);
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.setInventory('web01 192.0.2.1'));
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'ptr');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/ip"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '')) : [];
      });
      assertEqual(nav, ['ip', 'bulk', 'ptr'], 'Map IPs to servers group');
      assertEqual(await text(page, 'h1'), 'Reverse DNS', 'title');
      assert(await page.evaluate(() => !!document.querySelector('.ptr-empty .empty')), 'empty state');
      assertEqual(await dnsCount(page), 0, 'no DNS query');
      await shot(page, opts, 'ptr-empty-desktop-light-en');
    });

    await run.step('input issues: an IPv6 network is explained, a /20 is over the cap with a /22 to use, private space is left out', async () => {
      await typeTarget(page, '2001:db8::/64');
      await page.waitFor(() => !!document.querySelector('.ptr-issues [data-issue="v6-range"]'), { message: 'v6 issue' });
      assert(/18 quintillion/.test(await text(page, '.ptr-issues [data-issue="v6-range"]')), 'why no IPv6 sweep');
      await typeTarget(page, '192.0.0.0/20');
      await page.waitFor(() => !!document.querySelector('.ptr-issues [data-issue="too-large"]'), { message: 'too large' });
      assert(/4,096 addresses.*1,024/.test(await text(page, '.ptr-issues [data-issue="too-large"]')), 'counts');
      await page.click('[data-action="ptr-use-suggestion"]');
      await page.waitFor(() => document.querySelector('[data-role="ptr-target"]').value === '192.0.0.0/22', { message: 'suggestion used' });
      assertEqual(await issues(page), ['private'], 'its 192.0.0.0/24 is private, the rest is swept');
      assert(/768 addresses/.test(await text(page, '.ptr-parsed')), 'the public part');
      // a wholly private network over the cap says so, and offers no part of it to sweep
      await typeTarget(page, '10.0.0.0/8');
      await page.waitFor(() => /private address space/.test(document.querySelector('.ptr-issues [data-issue="too-large"]')?.textContent || ''), { message: 'private /8' });
      assert(!await page.evaluate(() => !!document.querySelector('[data-action="ptr-use-suggestion"]')), 'no suggestion');
      // a range typed with spaces and "ASN 64496" are read as one token each
      await typeTarget(page, '192.0.2.10 - 192.0.2.20');
      await page.waitFor(() => /11 addresses/.test(document.querySelector('.ptr-parsed')?.textContent || ''), { message: 'spaced range' });
      assertEqual(await issues(page), [], 'no ignored "-"');
      await typeTarget(page, 'ASN 64496');
      await page.waitFor(() => /List prefixes/.test(document.querySelector('[data-action="ptr-run"]').textContent), { message: 'ASN with a space' });
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
      assertEqual(stats, { addresses: '16', named: '12', confirmed: '10', none: '3', failed: '1', focus: '2' }, 'stats');
      assert(/Under example\.com/.test(await text(page, '.ptr-stats [data-stat="focus"]')), 'focus card');
      const queried = await page.evaluate(() => new Set(window.__fakeDnsLog.filter((q) => q.type === 'PTR').map((q) => q.name)).size);
      assertEqual(queried, 16, 'one reverse name per address');
      assert(/target=192\.0\.2\.0%2F28&focus=example\.com$/.test(await page.evaluate(() => location.hash)), 'the URL carries the run');
      // a focus edited after the sweep goes into the URL (and so into Copy link); an invalid one does not
      await page.type('[data-role="ptr-focus"]', 'example.org');
      await page.waitFor(() => /target=192\.0\.2\.0%2F28&focus=example\.org$/.test(location.hash), { message: 'focus in the URL' });
      await page.type('[data-role="ptr-focus"]', 'not a domain');
      await sleep(400);
      assert(/focus=example\.org$/.test(await page.evaluate(() => location.hash)), 'an invalid focus is not put into the URL');
      await page.type('[data-role="ptr-focus"]', 'example.com');
      await page.waitFor(() => /focus=example\.com$/.test(location.hash), { message: 'focus back' });
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

    await run.step('a filtered JSON export: the rows shown, the filter recorded, the summary of the whole sweep', async () => {
      await setSelect(page, '[data-role="ptr-filter"]', 'ptr');
      await sleep(100);
      await takeDownloads(page);
      await page.click('.ptr-table [data-export="json"]');
      await sleep(150);
      const j = JSON.parse((await takeDownloads(page)).find((f) => f.name.endsWith('.json')).text);
      assertEqual([j.planned, j.aborted, j.exported, j.results.length], [16, false, 12, 12], 'counts');
      assertEqual(j.filter, { show: 'ptr', search: '' }, 'filter');
      assertEqual([j.summary.done, j.summary.byStatus.nxdomain, j.summary.noReverse], [16, 2, 3], 'the whole sweep');
    });

    await run.step('a filter or a search keeps only the pattern members that pass: "1 of 8 match", and the export writes only them', async () => {
      const exported = async () => {
        await takeDownloads(page);
        // (a click from JS: the export toasts can sit over the table's footer)
        await jsClick(page, '.ptr-table [data-export="csv"]');
        await jsClick(page, '.ptr-table [data-export="json"]');
        await sleep(150);
        const files = await takeDownloads(page);
        const csv = files.find((f) => f.name.endsWith('.csv')).text.trim().split(/\r?\n/).slice(1).map((l) => l.split(',').slice(0, 2).join(' '));
        const j = JSON.parse(files.find((f) => f.name.endsWith('.json')).text);
        return { csv, json: j.results.map((r) => `${r.ip} ${r.status}`), filter: j.filter, done: j.summary.done };
      };
      const matching = () => page.evaluate(() => document.querySelector('.ptr-row-pattern .ptr-matching')?.textContent || '');
      await setSelect(page, '[data-role="ptr-filter"]', 'mismatch');
      await sleep(150);
      assertEqual((await rows(page)).map((x) => x.pattern ? 'pattern' : x.ip), ['192.0.2.2', 'pattern'], 'the mismatch and the pattern that holds one');
      assertEqual(await matching(), '1 of 8 matches', 'pattern note');
      const mismatch = await exported();
      assertEqual(mismatch.csv, ['192.0.2.2 mismatch', '192.0.2.10 mismatch'], 'CSV: not the seven confirmed members');
      assertEqual([mismatch.json, mismatch.filter, mismatch.done], [['192.0.2.2 mismatch', '192.0.2.10 mismatch'], { show: 'mismatch', search: '' }, 16], 'JSON');
      await shot(page, opts, 'ptr-filter-pattern-desktop-light-en');
      // the search judges a pattern's members one by one too; the mismatch filter's note says
      // "1 of 8" as well and goes on the next frame, so wait for "all" to drop it first
      await setSelect(page, '[data-role="ptr-filter"]', 'all');
      await page.waitFor(() => document.querySelectorAll('.ptr-table tbody tr.dt-row').length === 9 && !document.querySelector('.ptr-matching'), { message: 'every row, no note' });
      await page.type('.ptr-table .dt-search-input', '192.0.2.9');
      await page.waitFor(() => /1 of 8/.test(document.querySelector('.ptr-row-pattern .ptr-matching')?.textContent || ''), { message: 'search note' });
      assertEqual((await rows(page)).length, 1, 'only the pattern row');
      const searched = await exported();
      assertEqual([searched.csv, searched.filter], [['192.0.2.9 confirmed'], { show: 'all', search: '192.0.2.9' }], 'searched export');
      await page.type('.ptr-table .dt-search-input', '');
      await page.waitFor(() => document.querySelectorAll('.ptr-table tbody tr.dt-row').length === 9 && !document.querySelector('.ptr-matching'), { message: 'search cleared' });
    });

    await run.step('exports: CSV one line per address, JSON, names.txt without generated names', async () => {
      await setSelect(page, '[data-role="ptr-filter"]', 'all');
      await sleep(100);
      await takeDownloads(page);
      await jsClick(page, '.ptr-table [data-export="csv"]');
      await jsClick(page, '.ptr-table [data-export="json"]');
      await jsClick(page, '[data-action="ptr-names"]');
      await sleep(150);
      const files = await takeDownloads(page);
      const csv = files.find((f) => f.name.endsWith('.csv'));
      const lines = csv.text.trim().split(/\r?\n/);
      assertEqual(lines[0], 'ip,status,ptr,confirmed,forward,template,operator,servers,focus,error', 'CSV header');
      assertEqual(lines.length, 17, 'header + 16 addresses');
      assert(csv.bom, 'BOM');
      const j = JSON.parse(files.find((f) => f.name.endsWith('.json')).text);
      assertEqual([j.schema, j.results.length, j.focus, j.summary.byStatus.confirmed, j.filter], ['domainscope.ptr-sweep/1', 16, 'example.com', 10, null], 'JSON');
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

    await run.step('Add to Servers in the list’s own format: nothing twice, a JSON list gets an element, a JSON map is left alone', async () => {
      const inventory = (text) => page.evaluate(async (t) => {
        const { state } = await import('./assets/js/state.js');
        state.takeSession('inventoryDraft');
        state.setInventory(t);
      }, text);
      const editor = () => page.evaluate(() => document.querySelector('[data-role="inventory-text"]').value);
      // a second click while the draft is unsaved adds nothing (the draft already has the host)
      await gotoRoute(page, 'ptr');
      await page.waitFor(() => document.querySelector('.ptr-progress')?.dataset.status === 'done', { message: 'results kept' });
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
      await page.click('[data-action="ptr-to-inventory"]');
      await page.waitFor(() => [...document.querySelectorAll('.toast')].some((el) => /already in the Servers editor/.test(el.textContent)), { message: 'nothing twice' });
      assertEqual(await page.evaluate(() => document.documentElement.dataset.view), 'ptr', 'stays on the page');
      // a JSON array gets one more element and stays JSON
      await inventory('[\n  {"name": "web01", "ip": "192.0.2.1"}\n]');
      await page.click('[data-action="ptr-to-inventory"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'inventory' && !!document.querySelector('[data-role="inventory-text"]'), { message: 'Servers view (JSON)' });
      assertEqual(JSON.parse(await editor()), [{ name: 'web01', ip: '192.0.2.1' }, { name: 'host.example.net', ip: '192.0.2.3' }], 'JSON draft');
      // a JSON map is not rewritten: the hosts are shown to copy, the editor is untouched
      await gotoRoute(page, 'ptr');
      await page.waitFor(() => document.querySelector('.ptr-progress')?.dataset.status === 'done', { message: 'results kept (2)' });
      await inventory('{"web01": "192.0.2.1"}');
      await page.click('[data-action="ptr-to-inventory"]');
      await page.waitFor(() => !!document.querySelector('dialog.ptr-inv-manual[open]'), { message: 'dialog' });
      const dialog = await page.evaluate(() => {
        const d = document.querySelector('dialog.ptr-inv-manual');
        const p = d.querySelector('.modal-message');
        return { reason: p.dataset.reason, format: p.dataset.format, message: p.textContent, lines: d.querySelector('pre').textContent };
      });
      assertEqual([dialog.reason, dialog.format, dialog.lines], ['format', 'json', 'host.example.net 192.0.2.3\n'], 'dialog');
      assert(/Your server list is JSON/.test(dialog.message), dialog.message);
      assertEqual(await page.evaluate(async () => (await import('./assets/js/state.js')).state.getSession('inventoryDraft') ?? null), null, 'no draft');
      await shot(page, opts, 'ptr-inventory-manual-desktop-light-en');
      await page.evaluate(() => [...document.querySelectorAll('dialog.ptr-inv-manual .modal-foot .btn')].find((b) => /Open Servers/.test(b.textContent)).click());
      await page.waitFor(() => document.documentElement.dataset.view === 'inventory' && !!document.querySelector('[data-role="inventory-text"]'), { message: 'Servers view (map)' });
      assertEqual(await editor(), '{"web01": "192.0.2.1"}', 'the saved map, unchanged');
      await gotoRoute(page, 'ptr');
      await inventory('web01 192.0.2.1');
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

    await run.step('the origin panel (the Origins tab) links an IPv4 network to a Reverse DNS sweep that waits for a click', async () => {
      await page.click('.sub-tabs .tab[data-tab="origins"]');
      await page.waitFor(() => {
        const link = document.querySelector('.sub-org-net[data-cidr="192.0.2.0/24"] [data-action="sub-org-ptr"]');
        return !!link && !link.closest('[hidden]');
      }, { message: 'Origins tab' });
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

    await run.step('an AS lookup: Stop cancels it, and typing something else drops it (no stale prefix list)', async () => {
      const controls = () => page.evaluate(() => ({
        run: !document.querySelector('[data-action="ptr-run"]').hidden,
        stop: !document.querySelector('[data-action="ptr-stop"]').hidden,
        busy: document.querySelector('[aria-busy="true"]') !== null,
        card: !!document.querySelector('.ptr-asn'),
        picker: !!document.querySelector('.ptr-asn-table')
      }));
      await page.evaluate(() => { window.__ripeDelay = 5000; });
      await typeTarget(page, 'AS64496');
      await page.waitFor(() => /List prefixes/.test(document.querySelector('[data-action="ptr-run"]').textContent), { message: 'button label' });
      await page.click('[data-action="ptr-run"]');
      await page.waitFor(() => !document.querySelector('[data-action="ptr-stop"]').hidden, { message: 'Stop shown' });
      assertEqual(await controls(), { run: false, stop: true, busy: true, card: true, picker: false }, 'listing');
      await page.click('[data-action="ptr-stop"]');
      await page.waitFor(() => !document.querySelector('[data-action="ptr-run"]').hidden, { message: 'stopped' });
      assertEqual(await controls(), { run: true, stop: false, busy: false, card: false, picker: false }, 'after Stop');
      await page.click('[data-action="ptr-run"]');
      await page.waitFor(() => !document.querySelector('[data-action="ptr-stop"]').hidden, { message: 'listing again' });
      await typeTarget(page, '192.0.2.0/30');
      await page.waitFor(() => !document.querySelector('[data-action="ptr-run"]').hidden && !document.querySelector('.ptr-asn'), { message: 'dropped' });
      assertEqual(await controls(), { run: true, stop: false, busy: false, card: false, picker: false }, 'after typing a network');
      assert(/Sweep/.test(await text(page, '[data-action="ptr-run"]')), 'Sweep again');
      await page.evaluate(() => { window.__ripeDelay = 0; window.__ripeLog = []; });
    });

    await run.step('an AS: one RIPEstat request, the prefix picker, the cap, a sweep of the picked prefixes', async () => {
      await typeTarget(page, 'AS64496');
      await page.waitFor(() => /List prefixes/.test(document.querySelector('[data-action="ptr-run"]').textContent), { message: 'button label' });
      await page.click('[data-action="ptr-run"]');
      await page.waitFor(() => document.querySelectorAll('.ptr-asn-table tbody tr.dt-row').length === 6, { message: 'picker' });
      const ripe = await page.evaluate(() => window.__ripeLog);
      assertEqual(ripe, ['https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64496&sourceapp=domainscope'], 'one request');
      const picker = await page.evaluate(() => [...document.querySelectorAll('.ptr-asn-table tbody tr.dt-row')].map((tr) => {
        const cb = tr.querySelector('input[type="checkbox"]');
        return `${cb.dataset.prefix}:${cb.disabled ? 'off' : 'on'}:${tr.cells[3].textContent.trim()}`;
      }));
      assertEqual(picker, [
        '192.0.0.0/20:off:larger than a /22Use 192.0.0.0/22', '192.0.2.0/24:on:—', '198.18.0.0/15:off:private space: not swept',
        '198.51.100.0/24:on:—', '203.0.113.0/24:on:no longer announced', '2001:db8::/32:off:IPv6: not swept'
      ], 'rows');
      // "Use" only fills the form with the /22 (nothing is sent)
      await jsClick(page, '.ptr-asn-table td.ptr-asn-notes [data-action="ptr-asn-part"]');
      await page.waitFor(() => document.querySelector('[data-role="ptr-target"]').value === '192.0.0.0/22', { message: 'part used' });
      assertEqual(await page.evaluate(() => window.__ripeLog.length), 1, 'no new request');
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

    await run.step('each sweep starts at the default filter; one that finds no PTR name shows every address', async () => {
      await setSelect(page, '[data-role="ptr-filter"]', 'confirmed');
      await typeTarget(page, '203.0.113.0/26');
      await sleep(200);
      await page.click('[data-action="ptr-run"]');
      await waitDone(page, 'a sweep without names');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="ptr-filter"]').value), 'all', 'filter');
      assertEqual((await rows(page)).length, 64, 'every address');
      assert(!await page.evaluate(() => !!document.querySelector('.ptr-table .empty')), 'no "nothing matches"');
    });

    await run.step('Domain Health: the MX addresses get forward-confirmed reverse DNS rows and a table', async () => {
      await page.evaluate(() => { location.hash = '#/health?domain=example.com'; });
      await page.waitFor(() => !!document.querySelector('.hlt-check[data-id="mail-identity.fcrdns-ok"]'), { timeout: 30000, message: 'health report' });
      const ids = await page.evaluate(() => [...document.querySelectorAll('.hlt-check')].filter((c) => c.dataset.id.startsWith('mail-identity')).map((c) => `${c.dataset.id}:${c.dataset.severity}`));
      // the provider's generic PTR gets no "set a PTR that names the host" advice (it is not the user's to set)
      assertEqual(ids.sort(), ['mail-identity.fcrdns-missing:warn', 'mail-identity.fcrdns-ok:ok'], 'checks');
      assert(/mx2\.example\.com \(192\.0\.2\.4\)/.test(await text(page, '.hlt-check[data-id="mail-identity.fcrdns-missing"]')), 'missing detail');
      const table = await page.evaluate(() => [...document.querySelectorAll('.hlt-fcrdns tbody tr')].map((tr) => `${tr.dataset.status}:${tr.cells[1].querySelector('.hlt-ip').textContent}`));
      assertEqual(table, ['confirmed:192.0.2.1', 'nxdomain:192.0.2.4', 'confirmed:192.0.2.200'], 'table');
      assert(/provider/.test(await text(page, '.hlt-fcrdns tbody tr:nth-child(3) .hlt-fcrdns-host')) && /generic name/.test(await text(page, '.hlt-fcrdns tbody tr:nth-child(3) .hlt-fcrdns-ptr')), 'provider row');
      assertEqual(await page.evaluate(() => document.querySelector('.hlt-fcrdns a.hlt-fcrdns-sweep').getAttribute('href')), '#/ptr?target=192.0.2.1&focus=example.com', 'sweep link');
      await page.evaluate(() => document.querySelector('.hlt-fcrdns').scrollIntoView());
      await shot(page, opts, 'ptr-health-fcrdns-desktop-light-en');
      // on a phone (the narrowest too) the verdict sits under the address and the table fits its card
      for (const width of [320, 375]) {
        await page.setViewport({ width, height: 667, mobile: true });
        await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
        const phone = await page.evaluate(() => {
          const box = document.querySelector('.hlt-fcrdns-table');
          const visible = (el) => !!el && getComputedStyle(el).display !== 'none';
          return {
            fits: box.scrollWidth <= box.clientWidth + 1,
            inline: [...box.querySelectorAll('.hlt-fcrdns-st-inline')].every(visible),
            column: [...box.querySelectorAll('td:nth-child(4)')].some(visible)
          };
        });
        assertEqual(phone, { fits: true, inline: true, column: false }, `phone table at ${width} px`);
        await assertNoHorizontalScroll(page, `health fcrdns at ${width} px`);
      }
      await page.evaluate(() => document.querySelector('.hlt-fcrdns').scrollIntoView());
      await shot(page, opts, 'ptr-health-fcrdns-mobile-light-en');
      await page.setViewport({ width: 1440, height: 900 });
    });

    await run.step('the names hand-off belongs to its domains; About › Delete all local data drops it while Subdomains is not mounted', async () => {
      await gotoRoute(page, 'subdomains');
      const chip = () => page.evaluate(() => ({
        chip: document.querySelector('[data-role="names-chip"]')?.dataset.applies ?? 'none',
        scope: document.querySelector('.sub-handoff-scope')?.dataset.scope || '',
        plan: document.querySelector('.sub-wl-plan')?.dataset.handoffExact
      }));
      assertEqual(await chip(), { chip: '1', scope: '', plan: '1' }, 'kept for example.com');
      // another domain: neither the names nor exact mode apply to it
      await page.type('[data-role="sub-domain"]', 'example.org');
      await page.waitFor(() => document.querySelector('[data-role="names-chip"]')?.dataset.applies === '0'
        && document.querySelector('.sub-wl-plan')?.dataset.handoffExact === '0', { message: 'not for example.org' });
      assertEqual(await chip(), { chip: '0', scope: 'elsewhere', plan: '0' }, 'example.org');
      assert(/these names are under example\.com/.test(await text(page, '.sub-handoff-scope')), 'says whose names they are');
      await shot(page, opts, 'ptr-subdomains-chip-elsewhere-desktop-light-en');
      await page.type('[data-role="sub-domain"]', 'example.com');
      await page.waitFor(() => document.querySelector('.sub-wl-plan')?.dataset.handoffExact === '1', { message: 'back to example.com' });
      assertEqual(await chip(), { chip: '1', scope: '', plan: '1' }, 'example.com again');
      // wipe from About: the Subdomains view (and its own 'cleared' listener) is not mounted
      await gotoRoute(page, 'about');
      await page.click('[data-action="clear-data"]');
      try {
        await page.waitFor(() => !!document.querySelector('dialog.modal[open] .btn-danger'), { message: 'confirmation' });
        await page.click('dialog.modal[open] .btn-danger');
        await page.waitFor(() => !document.querySelector('dialog.modal[open]'), { message: 'dialog closed' });
      } finally {
        await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
      }
      await gotoRoute(page, 'subdomains');
      assertEqual(await chip(), { chip: 'none', scope: '', plan: '0' }, 'no names after Delete all local data');
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
    });

    await run.step('a link opened while a sweep runs waits for it: the form keeps the running sweep, Stop lets the link in', async () => {
      await gotoRoute(page, 'ptr');
      // addresses no earlier step looked up (the DoH client caches answers)
      await page.evaluate(() => { window.__fakeDnsDelay = 400; });
      await typeTarget(page, '192.0.2.128/25');
      await sleep(200);
      const focusBefore = await page.evaluate(() => document.querySelector('[data-role="ptr-focus"]').value);
      await page.click('[data-action="ptr-run"]');
      await page.waitFor(() => !document.querySelector('[data-action="ptr-stop"]').hidden, { message: 'running' });
      await page.evaluate(() => { location.hash = '#/ptr?target=203.0.113.0%2F30&focus=example.org'; });
      await page.waitFor(() => !!document.querySelector('.ptr-prompt [data-prompt="waiting"]'), { message: 'waiting prompt' });
      const form = () => page.evaluate(() => [document.querySelector('[data-role="ptr-target"]').value, document.querySelector('[data-role="ptr-focus"]').value]);
      assertEqual(await form(), ['192.0.2.128/25', focusBefore], 'the form keeps the running sweep');
      assert(/203\.0\.113\.0\/30 goes into the form when the running sweep ends/.test(await text(page, '.ptr-prompt')), 'says the link waits');
      assert(/192\.0\.2\.128\/25/.test(await text(page, '.ptr-results-title')), 'the running sweep’s results');
      await shot(page, opts, 'ptr-link-waiting-desktop-light-en');
      await page.click('[data-action="ptr-stop"]');
      await waitDone(page, 'stopped for the link');
      await page.waitFor(() => !!document.querySelector('.ptr-prompt [data-prompt="link"]'), { message: 'the link is in the form' });
      assertEqual(await form(), ['203.0.113.0/30', 'example.org'], 'the link in the form');
      assert(/203\.0\.113\.0\/30 \(4 addresses\)/.test(await text(page, '.ptr-prompt')), 'and waits for a click');
      assertEqual(await page.evaluate(() => document.querySelector('.ptr-progress').dataset.status), 'cancelled', 'nothing new ran');
      await page.evaluate(() => { window.__fakeDnsDelay = 0; });
    });

    await run.step('"Under your domain" is off without a focus domain, and a table showing it goes back to the default', async () => {
      await typeTarget(page, '192.0.2.0/28');
      await page.type('[data-role="ptr-focus"]', 'example.com');
      await sleep(200);
      await page.click('[data-action="ptr-run"]');
      await waitDone(page, 'sweep with a focus');
      const option = () => page.evaluate(() => document.querySelector('[data-role="ptr-filter"] option[value="focus"]').disabled);
      assertEqual(await option(), false, 'on with a focus domain');
      await setSelect(page, '[data-role="ptr-filter"]', 'focus');
      await sleep(120);
      assertEqual((await rows(page)).map((x) => x.ip), ['192.0.2.1', '192.0.2.2'], 'under example.com');
      await page.type('[data-role="ptr-focus"]', '');
      await page.waitFor(() => document.querySelector('[data-role="ptr-filter"]').value === 'ptr', { message: 'back to the default filter' });
      assertEqual(await option(), true, 'off without one');
      assert(!await page.evaluate(() => !!document.querySelector('.ptr-table .empty')), 'no "nothing matches"');
    });

    await run.step('a range typed with spaces stays one range: in the URL, after a reload, in a link typed with an en dash', async () => {
      await typeTarget(page, '192.0.2.10 - 192.0.2.14');
      await sleep(200);
      await page.click('[data-action="ptr-run"]');
      await waitDone(page, 'spaced range');
      const hash = await page.evaluate(() => location.hash);
      assert(/[?&]target=192\.0\.2\.10-192\.0\.2\.14(&|$)/.test(hash), `one range in the URL: ${hash}`);
      await page.reload();
      await waitReady(page);
      await page.waitFor(() => !!document.querySelector('.ptr-prompt [data-prompt="link"]'), { message: 'prompt after a reload' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="ptr-target"]').value), '192.0.2.10-192.0.2.14', 'one range in the form');
      assertEqual(await issues(page), [], 'nothing ignored');
      assert(/192\.0\.2\.10-192\.0\.2\.14 \(5 addresses\)/.test(await text(page, '.ptr-prompt')), 'the prompt offers the whole range');
      await page.evaluate(() => { location.hash = '#/ptr?target=192.0.2.20%20%E2%80%93%2022'; });
      await page.waitFor(() => document.querySelector('[data-role="ptr-target"]').value === '192.0.2.20-22', { message: 'en-dash link' });
      assert(/192\.0\.2\.20-192\.0\.2\.22 \(3 addresses\)/.test(await text(page, '.ptr-prompt')), 'three addresses');
      assertEqual(await dnsCount(page), 0, 'a link never sweeps by itself');
    });

    await run.step('a link naming the last sweep with another focus domain fills the form and waits, also over a draft', async () => {
      const form = () => page.evaluate(() => [document.querySelector('[data-role="ptr-target"]').value, document.querySelector('[data-role="ptr-focus"]').value]);
      const linked = () => page.evaluate(() => !!document.querySelector('.ptr-prompt [data-prompt="link"]'));
      await typeTarget(page, '192.0.2.1');
      await page.type('[data-role="ptr-focus"]', '');
      await sleep(200);
      await page.click('[data-action="ptr-run"]');
      await waitDone(page, 'a sweep without a focus');
      // The same target with a focus domain (Domain Health's per-MX link, a second domain on a shared host).
      let before = await dnsCount(page);
      await page.evaluate(() => { location.hash = '#/ptr?target=192.0.2.1&focus=example.com'; });
      await page.waitFor(() => document.querySelector('[data-role="ptr-focus"]').value === 'example.com', { message: 'the link\'s focus' });
      assertEqual(await form(), ['192.0.2.1', 'example.com'], 'the link in the form');
      assert(await linked(), 'the link prompt');
      await sleep(200);
      assertEqual(await dnsCount(page), before, 'the link sent nothing');
      // A draft typed after a sweep, then a link naming that sweep's target with another focus.
      await page.click('[data-action="ptr-run"]');
      await waitDone(page, 'the sweep with the focus');
      await typeTarget(page, '198.51.100.0/30');
      await sleep(200);
      before = await dnsCount(page);
      await page.evaluate(() => { location.hash = '#/ptr?target=192.0.2.1&focus=example.net'; });
      await page.waitFor(() => document.querySelector('[data-role="ptr-target"]').value === '192.0.2.1', { message: 'the link over the draft' });
      assertEqual(await form(), ['192.0.2.1', 'example.net'], 'the link in the form');
      assert(await linked(), 'and its prompt');
      await sleep(200);
      assertEqual(await dnsCount(page), before, 'the link sent nothing');
    });

    await run.step('Settings › Delete all local data with a sweep running: it stops, and the form, the results and the link are forgotten', async () => {
      const shown = () => page.evaluate(() => ({
        hash: location.hash,
        target: document.querySelector('[data-role="ptr-target"]')?.value,
        results: !!document.querySelector('.ptr-results'),
        stop: !document.querySelector('[data-action="ptr-stop"]')?.hidden
      }));
      // addresses no earlier step looked up (the DoH client caches answers)
      await page.evaluate(() => { window.__fakeDnsDelay = 250; });
      try {
        await typeTarget(page, '198.51.100.64/26');
        await page.type('[data-role="ptr-focus"]', '');
        await sleep(200);
        await page.click('[data-action="ptr-run"]');
        await page.waitFor(() => !document.querySelector('[data-action="ptr-stop"]').hidden, { message: 'running' });
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
        await sleep(300);
        const before = await dnsCount(page);
        await sleep(800);
        assertEqual(await dnsCount(page), before, 'the sweep asks nothing more');
        assertEqual(await shown(), { hash: '#/ptr', target: '', results: false, stop: false }, 'the page forgot the sweep');
        await gotoRoute(page, 'about');
        await gotoRoute(page, 'ptr');
        assertEqual(await shown(), { hash: '#/ptr', target: '', results: false, stop: false }, 'and the next visit shows none of it');
      } finally {
        await page.evaluate(() => { window.__fakeDnsDelay = 0; });
      }
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
    });

    run.group('Phone 375×667, Turkish / English, light / dark');
    await run.step('the form, the picker and the results at 375 px: no horizontal scroll', async () => {
      await gotoRoute(page, 'ptr?target=192.0.2.0/28&focus=example.com');
      await page.click('[data-action="ptr-run"]');
      await waitDone(page, 'phone sweep');
      await page.setViewport({ width: 375, height: 667, mobile: true });
      // the forward check sits under the address, in view without scrolling the table sideways
      await setSelect(page, '[data-role="ptr-filter"]', 'all');
      const phone = await page.evaluate(() => {
        const visible = (el) => !!el && getComputedStyle(el).display !== 'none';
        const scroller = document.querySelector('.ptr-table .dt-scroll');
        const inline = [...document.querySelectorAll('.ptr-table tbody tr.dt-row .ptr-st-inline')];
        const box = scroller.getBoundingClientRect();
        return {
          column: [...document.querySelectorAll('.ptr-table td.ptr-col-check')].some(visible),
          inline: inline.length > 0 && inline.every(visible),
          inView: inline.every((el) => el.getBoundingClientRect().right <= box.right + 1),
          first: inline[0]?.querySelector('[data-status]')?.dataset.status || ''
        };
      });
      assertEqual(phone, { column: false, inline: true, inView: true, first: 'confirmed' }, 'phone verdicts');
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
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await typeTarget(page, 'AS64496');
      await page.click('[data-action="ptr-run"]');
      await page.waitFor(() => document.querySelectorAll('.ptr-asn-table tbody tr.dt-row').length === 6, { message: 'picker (phone)' });
      await assertNoHorizontalScroll(page, 'picker');
      // why a box cannot be ticked sits under the prefix; the Notes column is hidden
      const notes = await page.evaluate(() => ({
        column: [...document.querySelectorAll('.ptr-asn-table td.ptr-asn-notes')].some((td) => getComputedStyle(td).display !== 'none'),
        inline: [...document.querySelectorAll('.ptr-asn-table .ptr-asn-notes-inline')].map((el) => getComputedStyle(el).display !== 'none' && el.textContent.trim())
      }));
      assertEqual(notes, { column: false, inline: ['larger than a /22Use 192.0.0.0/22', 'private space: not swept', 'no longer announced', 'IPv6: not swept'] }, 'notes under the prefix');
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
