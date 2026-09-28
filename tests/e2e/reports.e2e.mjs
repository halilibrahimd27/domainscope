#!/usr/bin/env node
/**
 * reports.e2e.mjs — end-to-end test of the "DMARC & TLS reports" view in a real headless Chrome/Edge.
 * OFFLINE: every DoH query is answered in the page by a fake resolver built from the zone below
 * (window.fetch wrapped before the app loads), RIPEstat and ipwho.is by the same wrapper; every
 * other https:// request is blocked, and every request that leaves the page's origin is counted
 * through CDP.
 *
 *   node tests/e2e/reports.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry (Mail & domain, after Domain Health), the empty state and the privacy note;
 * a dropped zip of a mailbox folder (a Google-style .zip and a Microsoft-style .xml.gz of DMARC
 * reports, a DMARCbis report, two TLS-RPT .json.gz, a notes.txt that is no report) read in the
 * browser: the files line and what could not be used, the busiest domain as the current target,
 * the reports' domain's SPF looked up (TXT / MX / A only) and the sources classified with the
 * server list — your servers, an authorized third party through an include, forwarders, unknown
 * senders —, the verdict "not ready for p=reject" with the sources to fix first and their fixes,
 * the class tiles filtering the table, a row's details, the reverse DNS and network of an address
 * only on a click, the CSV export (every column), Copy summary; the TLS-RPT tab: success rate,
 * policies, failure types with advice and links to Domain Health, DNS Lookup and the Certificate
 * view; the second domain; a failed SPF lookup said so and Check again; the kept reports on the way
 * back (no new query); Forget; 375 / 320 px without horizontal scroll, TR / EN × light / dark; zero
 * console errors / CSP violations / missing i18n keys, nothing sent outside the page.
 *
 * Data is documentation space only (tests/fixtures/mailreports: example.com / .net / .org,
 * 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
 */

import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, stubClipboard, takeClipboard, takeDownloads, waitReady, csvHeader
} from './scan.e2e.mjs';

const MAILBOX = path.join(FIXTURES, 'mailreports', 'reports-2026-09.zip');

/** example.com's SPF (its own server, its MX, its own include, a mailing service) and the reverse DNS of one sender. */
const ZONE = {
  'example.com': {
    TXT: [['v=spf1 ip4:203.0.113.25 mx include:_spf.example.com include:spf.mailer.example.net ~all']],
    MX: [{ preference: 10, exchange: 'mx1.example.com' }]
  },
  'mx1.example.com': { A: ['203.0.113.26'] },
  '_spf.example.com': { TXT: [['v=spf1 ip6:2001:db8:25::/64 -all']] },
  'spf.mailer.example.net': { TXT: [['v=spf1 ip4:198.51.100.0/26 -all']] },
  'example.net': { TXT: [['v=spf1 ip4:192.0.2.10 -all']] },
  '200.2.0.192.in-addr.arpa': { PTR: ['host-200.spam.example.org'] }
};

/** In-page stubs: DoH from the zone (NXDOMAIN outside it), RIPEstat, ipwho.is. */
const fakeScript = () => `(() => {
  const Z = ${JSON.stringify(ZONE)};
  window.__dnsLog = [];
  window.__ipLog = [];
  window.__rcodes = {};
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const u = new URL(url, location.href);
    if (u.hostname === 'stat.ripe.net') {
      const ip = u.searchParams.get('resource');
      const call = u.pathname.split('/')[2];
      window.__ipLog.push(call + ' ' + ip);
      if (call === 'prefix-overview') {
        return json({ status: 'ok', data: { announced: true, asns: [{ asn: 64496, holder: 'EXAMPLE-AS - Example Hosting Ltd' }],
          resource: ip.split('.').slice(0, 3).join('.') + '.0/24', block: { desc: 'Administered by RIPE NCC' } } });
      }
      if (call === 'maxmind-geo-lite') {
        return json({ status: 'ok', data: { located_resources: [{ locations: [{ country: 'NL', city: 'Amsterdam', covered_percentage: 100 }] }] } });
      }
      return json({ status: 'error' }, 400);
    }
    if (u.hostname === 'ipwho.is') { window.__ipLog.push('ipwhois'); return json({ success: false, message: 'quota' }); }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const qname = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__dnsLog.push({ name: qname, type: q.type });
    const forced = window.__rcodes[qname + '|' + q.type];
    const node = Z[qname];
    const answers = forced || !node ? [] : (node[q.type] || []).map((data) => ({ name: qname, type: q.type, ttl: 300, data }));
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: forced || (node ? 'NOERROR' : 'NXDOMAIN'),
      questions: [{ name: q.name, type: q.type }], answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);
const counts = (page) => page.evaluate(() => ({ dns: window.__dnsLog.length, ip: window.__ipLog.length }));
/** The sources table as [ip, class] in its order (only the rows it shows). */
const tableClasses = (page) => page.evaluate(() => [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')]
  .map((tr) => [tr.querySelector('.rpt-ip')?.dataset.ip, tr.querySelector('.badge[data-cls]')?.dataset.cls]));
const waitDmarc = (page, message = 'DMARC tab with its sources') => page.waitFor(() => document.querySelectorAll('.rpt-sources tbody tr.dt-row').length > 0
  && document.querySelector('.rpt-spf')?.dataset.state !== 'loading', { timeout: 20000, message });

/** In the page: save `text` as the active workspace's inventory ('' clears it). */
function saveInventory(textValue) {
  return import('./assets/js/state.js').then(async ({ state }) => {
    await state.setInventory(textValue).done;
    await state.whenSaved();
  });
}

async function main() {
  const opts = cliOptions();
  const run = createRunner();

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
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript() });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/reports: the nav entry after Domain Health, the empty state, the privacy note, nothing sent', async () => {
      await page.goto(`${server.url}#/reports`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'reports');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/health"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '').split('?')[0]) : [];
      });
      assertEqual(nav, ['health', 'reports'], 'Mail & domain group');
      assertEqual(await text(page, 'h1'), 'DMARC & TLS reports', 'title');
      assert(await page.evaluate(() => !!document.querySelector('.rpt-page .empty')), 'empty state');
      assert(/never uploaded or saved/.test(await text(page, '#page-body .alert')), 'privacy note');
      assertEqual(await counts(page), { dns: 0, ip: 0 }, 'nothing sent');
      await page.evaluate(saveInventory, 'mail01 203.0.113.25\napp02 203.0.113.99\n');
      await shot(page, opts, 'reports-empty-desktop-light-en');
    });

    await run.step('a dropped mailbox zip is read in the browser: the files line, what could not be used, the busiest domain as the target', async () => {
      await page.setFileInput('.rpt-load .filedrop-input', [MAILBOX]);
      await waitDmarc(page);
      assertEqual(await text(page, '[data-role="rpt-files"]'), '1 file · 3 DMARC reports · 2 TLS reports · 1 could not be used', 'files line');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-problem-list li')].map((li) => [li.dataset.code, li.querySelector('.rpt-problem-path').textContent])),
        [['not-report', 'reports-2026-09.zip › notes.txt']], 'problems');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-tabs [role="tab"]')].map((b) => b.dataset.tab)), ['dmarc', 'tls'], 'tabs');
      assertEqual(await text(page, '.rpt-results-title'), 'Reports for 2 domains', 'results title');
      assertEqual(await page.evaluate(() => document.activeElement?.classList.contains('rpt-results-title')), true, 'the focus on the results');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-domain option')].map((o) => o.textContent)),
        ['example.com — 5,175 messages', 'example.net — 29 messages'], 'domains, busiest first');
      await page.waitFor(() => document.querySelector('[data-role="target-chip"] .target-chip-value')?.textContent === 'example.com', { message: 'target chip' });
      const asked = await page.evaluate(() => [...new Set(window.__dnsLog.map((q) => `${q.name}|${q.type}`))].sort());
      assertEqual(asked, ['_spf.example.com|TXT', 'example.com|MX', 'example.com|TXT', 'mx1.example.com|A', 'mx1.example.com|AAAA', 'spf.mailer.example.net|TXT'], 'only the SPF tree');
      assertEqual((await counts(page)).ip, 0, 'no IP data yet');
    });

    await run.step('the sources classified against the current SPF and the server list; the verdict and what to fix first', async () => {
      const cls = Object.fromEntries(await tableClasses(page));
      assertEqual(cls, {
        '198.51.100.10': 'third-party', '203.0.113.25': 'yours', '203.0.113.26': 'yours', '198.51.100.20': 'third-party',
        '2001:db8:25::10': 'yours', '203.0.113.99': 'yours', '192.0.2.200': 'unknown', '198.51.100.200': 'unknown',
        '192.0.2.44': 'forwarder', '192.0.2.45': 'forwarder'
      }, 'classes');
      assertEqual(await page.evaluate(() => document.querySelector('.rpt-spf').dataset.state), 'ok', 'SPF checked');
      assert(/v=spf1 ip4:203\.0\.113\.25 mx include:_spf\.example\.com/.test(await text(page, '.rpt-spf')), 'the record');
      assertEqual(await page.evaluate(() => document.querySelector('.rpt-verdict').dataset.verdict), 'fix-first', 'verdict');
      assertEqual(await text(page, '.rpt-compliance'), '95%', 'compliance');
      const fixes = await page.evaluate(() => [...document.querySelectorAll('.rpt-fix-item')].map((li) => [li.dataset.ip, [...li.querySelectorAll('[data-fix]')].map((f) => f.dataset.fix)]));
      assertEqual(fixes, [['198.51.100.20', ['dkim-align', 'spf-align']], ['203.0.113.99', ['dkim-sign', 'spf-add']]], 'fix first');
      const first = await text(page, '.rpt-fix-item[data-ip="198.51.100.20"]');
      assert(/Authorized through include:spf\.mailer\.example\.net/.test(first) && /120 of 120 messages fail/.test(first)
        && /It signs DKIM only as mailer\.example\.net: set up DKIM for example\.com/.test(first), first);
      assert(/In your server list: app02/.test(await text(page, '.rpt-fix-item[data-ip="203.0.113.99"]')), 'the server of the list');
      assert(/2 unknown senders, 85 failing messages/.test(await text(page, '.rpt-unknown-line')), 'unknown senders');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-notes li')].map((li) => li.dataset.note)), ['short-range'], 'notes');
      await shot(page, opts, 'reports-dmarc-desktop-light-en');
    });

    await run.step('a class tile filters the table; a row\'s details say why, with the current SPF', async () => {
      await page.click('.rpt-cls [data-cls="unknown"]');
      await page.waitFor(() => document.querySelectorAll('.rpt-sources tbody tr.dt-row').length === 2, { message: 'unknown only' });
      assertEqual((await tableClasses(page)).map(([, c]) => c), ['unknown', 'unknown'], 'filtered');
      assertEqual(await page.evaluate(() => document.querySelector('.rpt-cls [data-cls="unknown"]').getAttribute('aria-pressed')), 'true', 'pressed');
      await page.click('[data-action="rpt-cls-clear"]');
      await page.waitFor(() => document.querySelectorAll('.rpt-sources tbody tr.dt-row').length === 10, { message: 'every class again' });
      await page.evaluate(() => {
        const tr = [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')].find((r) => r.querySelector('.rpt-ip')?.dataset.ip === '192.0.2.44');
        tr.querySelector('.dt-expand-btn').click();
      });
      await page.waitFor(() => !!document.querySelector('.rpt-sources .rpt-details'), { message: 'details' });
      const det = await text(page, '.rpt-sources .rpt-details');
      assert(/example\.com \/ mail2026: pass/.test(det) && /softfail by ~all in example\.com/.test(det) && /Open in IP Intel/.test(det), det);
      assert(/Carries the DKIM signature your senders make \(selector mail2026\)/.test(await text(page, '.rpt-sources tbody')), 'why');
      await page.evaluate(() => document.querySelector('.rpt-sources').scrollIntoView());
      await shot(page, opts, 'reports-details-desktop-light-en');
    });

    await run.step('the reverse DNS and network of an address only on a click; the bulk button counts what is left', async () => {
      assertEqual((await counts(page)).ip, 0, 'nothing asked before the click');
      const bulk = await text(page, '[data-action="rpt-intel-all"]');
      assertEqual(bulk, 'Look up 10 addresses', 'bulk label');
      await page.click('[data-action="rpt-intel"][data-ip="192.0.2.200"]');
      await page.waitFor(() => /host-200\.spam\.example\.org/.test(document.querySelector('.rpt-sources tbody')?.textContent || ''), { message: 'PTR' });
      assert(/AS64496 Example Hosting Ltd/.test(await text(page, '.rpt-sources tbody')), 'AS holder');
      assertEqual((await page.evaluate(() => window.__ipLog)).sort(), ['maxmind-geo-lite 192.0.2.200', 'prefix-overview 192.0.2.200'], 'one address, RIPEstat only');
      await page.waitFor(() => /Look up 9 addresses/.test(document.querySelector('[data-action="rpt-intel-all"]')?.textContent || ''), { message: 'bulk count' });
    });

    await run.step('CSV of the sources (every column) and Copy summary (no server name, the bare link)', async () => {
      await page.click('.rpt-sources [data-export="csv"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'download' });
      const [file] = await takeDownloads(page);
      assert(/^dmarc-sources-example\.com-.*\.csv$/.test(file.name), file.name);
      const { DMARC_CSV_COLUMNS } = await import('../../assets/js/lib/dmarcreport.js');
      assertEqual(csvHeader(file.text), [...DMARC_CSV_COLUMNS], 'CSV header');
      assertEqual(file.text.trim().split(/\r?\n/).length, 11, 'one row per source');
      await stubClipboard(page);
      await page.click('.rpt-results-head [data-action="copy-summary"]');
      await page.waitFor(() => (window.__clip || []).length === 1, { message: 'copied' });
      const [out] = await takeClipboard(page);
      const ls = out.trimEnd().split('\n');
      assertEqual(ls[0], '**DMARC & TLS reports · `example.com`**', 'title');
      assert(ls.includes('- **DMARC:** 94.9% of 5,175 messages pass · `p=none` · 2 reports, 2026-09-25 → 2026-09-26'), out);
      assert(ls.includes('- **Fix first:** `203.0.113.99` (your server): 57 messages fail — sign its mail with DKIM for the domain'), out);
      assert(ls.includes('- **TLS-RPT:** 99% of 6,201 TLS sessions succeeded · 2 reports'), out);
      assert(!out.includes('app02') && !out.includes('mail01'), 'no server name');
      assert(/\/domainscope\/#\/reports$/.test(ls[ls.length - 1]), ls[ls.length - 1]);
    });

    await run.step('the TLS-RPT tab: success rate, policies, failure types with advice and links', async () => {
      await page.click('.rpt-tabs [data-tab="tls"]');
      await page.waitFor(() => !!document.querySelector('.rpt-tls-head'), { message: 'TLS tab' });
      assertEqual(await text(page, '.rpt-tls-rate'), '99%', 'rate');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-tls-policies li')].map((li) => li.dataset.policy)), ['sts', 'no-policy-found', 'tlsa'], 'policies');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-tls-type')].map((a) => a.dataset.type)),
        ['certificate-expired', 'starttls-not-supported', 'certificate-host-mismatch', 'validation-failure', 'sts-policy-fetch-error'], 'types');
      const expired = await text(page, '.rpt-tls-type[data-type="certificate-expired"]');
      assert(/40 failed sessions · MX mx2\.example\.com · reported by Google Inc\./.test(expired) && /Renew it/.test(expired), expired);
      const links = await page.evaluate(() => [...document.querySelectorAll('.rpt-tls-type [data-tool]')].map((a) => [a.closest('.rpt-tls-type').dataset.type, a.dataset.tool, a.getAttribute('href')]));
      assert(links.some(([ty, tool, href]) => ty === 'sts-policy-fetch-error' && tool === 'health' && /#\/health\?domain=example\.com&run=0$/.test(href)), JSON.stringify(links));
      assert(links.some(([ty, tool, href]) => ty === 'certificate-expired' && tool === 'cert' && /#\/cert\?host=mx2\.example\.com&run=0$/.test(href)), JSON.stringify(links));
      assert(links.some(([ty, tool, href]) => ty === 'validation-failure' && tool === 'cert' && /host=mx-backup\.example\.com/.test(href)), JSON.stringify(links));
      assertEqual(await page.evaluate(() => document.querySelectorAll('.rpt-tls-failures tbody tr.dt-row').length), 5, 'failure rows');
      await shot(page, opts, 'reports-tls-desktop-light-en');
      await page.click('.rpt-tabs [data-tab="dmarc"]');
    });

    await run.step('the second domain: its own sources and SPF; strict policy, reject enforced', async () => {
      const before = (await counts(page)).dns;
      await page.evaluate(() => {
        const sel = document.querySelector('.rpt-domain select');
        sel.value = 'example.net';
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => /example\.net/.test(document.querySelector('.rpt-head .card-title')?.textContent || '')
        && document.querySelector('.rpt-spf')?.dataset.state === 'ok', { message: 'example.net' });
      assertEqual(await page.evaluate(() => document.querySelector('.rpt-verdict').dataset.verdict), 'enforced', 'p=reject enforced');
      assertEqual(Object.fromEntries(await tableClasses(page)), { '192.0.2.10': 'yours', '198.51.100.250': 'unknown' }, 'classes');
      assert((await counts(page)).dns > before, 'its SPF looked up');
    });

    await run.step('an SPF lookup that fails is said so, never "not authorized"; Check again asks once more', async () => {
      await page.evaluate(() => { window.__rcodes['example.net|TXT'] = 'SERVFAIL'; });
      await page.click('[data-action="rpt-spf-retry"]');
      await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'failed', { message: 'failed' });
      assert(/could not be read/.test(await text(page, '.rpt-spf')), await text(page, '.rpt-spf'));
      assert(await page.evaluate(() => !!document.querySelector('.rpt-notes [data-note="spf-unknown"]')), 'the note');
      // The reports saw 192.0.2.10 pass SPF aligned: without the current SPF it still counts as yours.
      assertEqual(Object.fromEntries(await tableClasses(page))['192.0.2.10'], 'yours', 'from the reports');
      await page.evaluate(() => { delete window.__rcodes['example.net|TXT']; });
      await page.click('[data-action="rpt-spf-retry"]');
      await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'ok', { message: 'ok again' });
      await page.evaluate(() => {
        const sel = document.querySelector('.rpt-domain select');
        sel.value = 'example.com';
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => /example\.com/.test(document.querySelector('.rpt-head .card-title')?.textContent || ''), { message: 'back to example.com' });
    });

    await run.step('the reports are kept: back through the nav link they show again with no new query', async () => {
      const before = await counts(page);
      await gotoRoute(page, 'lookup');
      await page.click('a.nav-link[data-view="reports"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'reports' && !!document.querySelector('.rpt-sources tbody tr.dt-row'), { message: 'back' });
      await page.waitFor(() => /Reports read at/.test(document.querySelector('.page-kept:not([hidden]) .kept-note')?.textContent || ''), { message: 'kept note' });
      assertEqual(await page.evaluate(() => !!document.querySelector('.page-kept [data-action="kept-rerun"]')), false, 'nothing to run again');
      assertEqual(await counts(page), before, 'no new request');
    });

    run.group('Phone 375 and 320 px, Turkish / English, light / dark');
    await run.step('the reports at 375 px: no horizontal scroll; TR / EN × light / dark', async () => {
      await page.setViewport({ width: 375, height: 740, mobile: true });
      for (const lang of ['en', 'tr']) {
        await setLangUi(page, lang);
        await waitDmarc(page, 'kept after the language switch');
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await page.evaluate(() => window.scrollTo(0, 0));
          await assertNoHorizontalScroll(page, `reports ${scheme} ${lang}`);
          await shot(page, opts, `reports-dmarc-mobile-${scheme}-${lang}`);
        }
      }
      assertEqual(await text(page, 'h1'), 'DMARC ve TLS raporları', 'Turkish title');
      await page.click('.rpt-tabs [data-tab="tls"]');
      await page.waitFor(() => !!document.querySelector('.rpt-tls-head'), { message: 'TLS tab' });
      await assertNoHorizontalScroll(page, 'reports tls tr dark');
      await shot(page, opts, 'reports-tls-mobile-dark-tr');
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      await assertNoHorizontalScroll(page, 'reports tls 320 tr dark');
      await page.click('.rpt-tabs [data-tab="dmarc"]');
      await waitDmarc(page);
      await assertNoHorizontalScroll(page, 'reports dmarc 320 tr dark');
      const fits = await page.evaluate(() => [...document.querySelectorAll('.rpt-head, .rpt-fix-item, .rpt-sources tbody tr.dt-row')].filter((c) => c.scrollWidth > c.clientWidth + 1).map((c) => c.className));
      assertEqual(fits, [], 'every card fits at 320 px');
      await shot(page, opts, 'reports-dmarc-mobile320-dark-tr');
      await page.setViewport({ width: 1440, height: 900 });
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, opts, 'reports-dmarc-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Forget');
    await run.step('Forget drops the reports: the empty state again, nothing kept', async () => {
      await waitDmarc(page);
      await page.click('[data-action="rpt-forget"]');
      await page.waitFor(() => !!document.querySelector('.rpt-page .empty') && !document.querySelector('.rpt-sources'), { message: 'forgotten' });
      await gotoRoute(page, 'lookup');
      await page.click('a.nav-link[data-view="reports"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'reports' && !!document.querySelector('.rpt-page .empty'), { message: 'still empty' });
      assertEqual(await page.evaluate(() => !!document.querySelector('.page-kept:not([hidden]) .kept-note')), false, 'no kept note');
      await page.evaluate(saveInventory, '');
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'reports', origin));
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
