#!/usr/bin/env node
/**
 * bulk.e2e.mjs — end-to-end test of the "Bulk Resolve" view against the LIVE DoH resolvers
 * (and RIPEstat for the ASN option) in a real headless Chrome/Edge.
 *
 *   node tests/e2e/bulk.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--no-quota-apis]
 *
 * --no-quota-apis blocks the small-quota ipwho.is fallback of the ASN option in the browser.
 *
 * Node side: parseBulkInput / sanitizeBulkOptions / bulkRowMatches / ipRowMatches / bulkStats.
 *
 * Browser side:
 *   - ~50 real hostnames (Cloudflare, Fastly, Akamai, platforms, direct, private via nip.io,
 *     NXDOMAIN) plus duplicates, an IP, invalid entries and a URL; the parse summary matches
 *     the Node parser; the inventory is seeded so dns.google (8.8.8.8) is "your" server
 *   - resolve with PTR: every row present, classification, inventory match, IP table with PTR,
 *     filters, row details, CSV / JSON export (captured in the page), copy buttons
 *   - ASN / owner lookups (RIPEstat) for two well-known IPs
 *   - Cancel, a job that keeps running while another tool is open (toast → back),
 *     "use the names of the last scan", #/bulk?names=… route params
 *   - language switch, dark mode, 390 px phone layout, screenshots, zero console errors /
 *     exceptions / CSP violations, no missing i18n keys.
 */

import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  csvHeader, gotoRoute, installDownloadCapture, setLangUi, shot, sleep, takeDownloads, waitReady
} from './scan.e2e.mjs';

/** Real hostnames with stable, well-known hosting (the assertions only rely on a few of them). */
const NAMES = [
  // Cloudflare
  'www.cloudflare.com', 'cloudflare.com', 'discord.com', 'www.npmjs.com', 'npmjs.com', 'registry.npmjs.org', 'canva.com',
  // Fastly / CDNs
  'pypi.org', 'www.reddit.com', 'github.githubassets.com', 'www.fastly.com',
  // Akamai / CloudFront / Azure
  'www.microsoft.com', 'www.apple.com', 'aws.amazon.com', 'www.bing.com',
  // Platforms
  'pages.github.com', 'nextjs.org', 'docs.github.com', 'www.netlify.com',
  // Direct
  'dns.google', 'one.one.one.one', 'www.arin.net', 'www.usa.gov', 'www.nasa.gov', 'www.nist.gov',
  'www.gov.uk', 'www.denic.de', 'www.ripe.net', 'www.iana.org', 'www.kernel.org', 'www.debian.org', 'www.python.org',
  'www.wikipedia.org', 'www.google.com', 'mail.google.com', 'www.youtube.com', 'www.gitlab.com', 'gitlab.com',
  'www.mozilla.org', 'www.openssl.org',
  // Private (wildcard DNS services that echo the IP)
  '10-0-0-1.nip.io', '192-168-1-20.nip.io',
  // Not existing
  'no-such-host-e2e-7c1f.example.com', 'surely-missing-e2e-9a2b.example.org', 'nope-e2e.invalid-tld-xyz'
];
const EXTRA_INPUT = [
  'dns.google', 'DNS.Google.', // duplicates (case / trailing dot)
  'https://www.iana.org/domains/root', // URL → hostname (duplicate of www.iana.org)
  '8.8.4.4', // an IP — reported, not resolved
  'bad..name', 'under_score_only', // invalid
  '# a comment line'
];

async function nodeChecks(run) {
  const B = await import('../../assets/js/views/bulk.js');
  run.group('Node: views/bulk.js helpers');
  await run.step('parseBulkInput: normalize, de-duplicate, separate IPs and invalid tokens, cap', () => {
    const r = B.parseBulkInput('www.A.com, www.a.com.\nhttps://b.com/x 1.2.3.4 ::1 bad..x *.w.com\n# note\nörnek.com.tr');
    assertEqual(r.names, ['www.a.com', 'b.com', 'xn--rnek-4qa.com.tr'], 'names');
    assertEqual(r.ips, ['1.2.3.4', '::1'], 'ips');
    assertEqual(r.invalid, ['bad..x', '*.w.com'], 'invalid');
    assertEqual(r.duplicates, 1, 'duplicates');
    const capped = B.parseBulkInput(Array.from({ length: 30 }, (_, i) => `h${i}.example.com`).join('\n'), { max: 10 });
    assert(capped.truncated && capped.names.length === 10 && capped.total === 30, 'cap');
  });
  await run.step('sanitizeBulkOptions', () => {
    assertEqual(B.sanitizeBulkOptions({ ptr: true, asn: 'yes', noCache: true, resolver: 'google' }), { ptr: true, asn: false, noCache: true, resolver: 'google' }, 'valid');
    assertEqual(B.sanitizeBulkOptions({ resolver: 'evil' }).resolver, '', 'unknown resolver → chain');
  });
  await run.step('bulkRowMatches / ipRowMatches / bulkStats', () => {
    const row = (kind, extra = {}) => ({
      name: `${kind}.x.com`,
      ips: extra.ips || [],
      servers: extra.servers || [],
      classification: { kind, dangling: !!extra.dangling, hidesOrigin: kind === 'cloudflare' || kind === 'cdn' },
      resolution: { status: extra.status || (extra.ips && extra.ips.length ? 'NOERROR' : 'NXDOMAIN') }
    });
    const rows = [
      row('cloudflare', { ips: ['104.16.0.1'] }),
      row('direct', { ips: ['8.8.8.8'], servers: [{ serverId: 'g', name: 'google-dns', ip: '8.8.8.8' }] }),
      row('direct', { ips: ['9.9.9.9'] }),
      row('private', { ips: ['10.0.0.1'] }),
      row('nxdomain'),
      row('unresolved', { status: 'SERVFAIL' }),
      row('unresolved', { dangling: true, status: 'NOERROR' })
    ];
    const pick = (f) => rows.filter((r) => B.bulkRowMatches(r, f)).length;
    assertEqual(BULK_COUNTS.map((f) => [f, pick(f)]), [['all', 7], ['resolving', 4], ['hidden', 1], ['direct', 3], ['mine', 1], ['unknown', 1], ['unresolved', 3], ['errors', 1], ['dangling', 1]], 'filters');
    const ips = new Map([
      ['8.8.8.8', { ip: '8.8.8.8', version: 4, private: false, provider: null, servers: [{}] }],
      ['104.16.0.1', { ip: '104.16.0.1', version: 4, private: false, provider: { id: 'cloudflare' }, servers: [] }],
      ['10.0.0.1', { ip: '10.0.0.1', version: 4, private: true, provider: null, servers: [] }],
      ['2001:db8::1', { ip: '2001:db8::1', version: 6, private: false, provider: null, servers: [] }]
    ]);
    const ipPick = (f) => [...ips.values()].filter((r) => B.ipRowMatches(r, f)).map((r) => r.ip);
    assertEqual(ipPick('mine'), ['8.8.8.8'], 'mine');
    assertEqual(ipPick('unknown'), ['2001:db8::1'], 'unknown');
    assertEqual(ipPick('cdn'), ['104.16.0.1'], 'cdn');
    assertEqual(ipPick('private'), ['10.0.0.1'], 'private');
    const s = B.bulkStats(rows, ips);
    assertEqual([s.total, s.resolved, s.hidden, s.cloudflare, s.direct, s.onServers, s.unresolved, s.errors, s.ips, s.v4, s.v6, s.servers],
      [7, 4, 1, 1, 3, 1, 3, 1, 4, 3, 1, 1], 'stats');
  });
}
const BULK_COUNTS = ['all', 'resolving', 'hidden', 'direct', 'mine', 'unknown', 'unresolved', 'errors', 'dangling'];

const jobStatus = (page) => page.evaluate(() => {
  const el = document.querySelector('.bulk-results');
  return el ? { id: el.dataset.job, status: el.querySelector('.bulk-progress').dataset.status } : null;
});

async function waitJobDone(page, prevId, timeout = 180000) {
  await page.waitFor((prev) => {
    const el = document.querySelector('.bulk-results');
    return el && el.dataset.job !== prev && ['done', 'cancelled', 'error'].includes(el.querySelector('.bulk-progress').dataset.status);
  }, { args: [prevId || ''], timeout, interval: 300, message: 'bulk job finished' });
}

async function setOption(page, name, on) {
  await page.evaluate((n, v) => {
    const input = document.querySelector(`input[data-option="${n}"]`);
    if (input.checked !== v) input.click();
  }, name, on);
}

async function rowsOf(page, table) {
  return page.evaluate((sel) => [...document.querySelectorAll(`${sel} tbody tr.dt-row`)].map((tr) => ({
    text: tr.textContent,
    kind: tr.querySelector('[data-kind]')?.dataset.kind || null,
    first: tr.querySelector('td:not(.dt-expander)')?.textContent.trim()
  })), table);
}

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  await nodeChecks(run);
  const B = await import('../../assets/js/views/bulk.js');
  const input = [...NAMES, ...EXTRA_INPUT].join('\n');
  const expected = B.parseBulkInput(input);

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}; ${expected.names.length} hostnames\n`);
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    if (opts.has('--no-quota-apis')) {
      await page.send('Network.enable');
      await page.send('Network.setBlockedURLs', { urls: ['*://ipwho.is/*', '*://api.hackertarget.com/*'] });
    }
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/bulk with the intro and a disabled Resolve button', async () => {
      await page.goto(`${server.url}#/bulk`);
      await waitReady(page);
      await page.evaluate(() => localStorage.removeItem('ssds.bulk.options'));
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.setInventory('google-dns 8.8.8.8 8.8.4.4\nlab01 10.0.0.1\nweb09 203.0.113.9'));
      await page.reload();
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      const info = await page.evaluate(() => ({
        intro: !!document.querySelector('.bulk-intro'),
        disabled: document.querySelector('[data-action="bulk-run"]').disabled
      }));
      assert(info.intro && info.disabled, JSON.stringify(info));
      await shot(page, opts, 'bulk-desktop-light-en-empty');
    });

    await run.step('pasting the list shows the parse summary (same as the Node parser)', async () => {
      await page.type('[data-role="bulk-input"]', input);
      await page.waitFor((n) => document.querySelector('.bulk-parse')?.textContent.includes(`${n} hostnames`), { args: [expected.names.length] });
      const text = await page.evaluate(() => document.querySelector('.bulk-parse').textContent);
      assert(text.includes(`${expected.duplicates} duplicates removed`), `duplicates in: ${text}`);
      assert(text.includes(`${expected.invalid.length} invalid entries`), `invalid in: ${text}`);
      assert(text.includes('1 IP address ignored'), `IPs in: ${text}`);
      assert(!await page.evaluate(() => document.querySelector('[data-action="bulk-run"]').disabled), 'Resolve enabled');
    });

    await run.step(`LIVE: resolve ${expected.names.length} names with PTR lookups`, async () => {
      await setOption(page, 'ptr', true);
      const t0 = Date.now();
      await page.click('[data-action="bulk-run"]');
      await page.waitFor(() => !!document.querySelector('.bulk-results'));
      await sleep(300);
      await shot(page, opts, 'bulk-desktop-light-en-running');
      await waitJobDone(page, '');
      assertEqual((await jobStatus(page)).status, 'done', 'status');
      process.stdout.write(`        done in ${((Date.now() - t0) / 1000).toFixed(1)} s\n`);
    });

    await run.step('every name has a row; classification and inventory match are right', async () => {
      const rows = await rowsOf(page, '.bulk-hosts');
      assertEqual(rows.length, expected.names.length, 'rows');
      const by = (name) => rows.find((r) => r.first === name);
      const google = by('dns.google');
      assert(google && google.kind === 'direct' && google.text.includes('8.8.8.8') && google.text.includes('google-dns'), `dns.google: ${JSON.stringify(google)}`);
      assertEqual(by('nope-e2e.invalid-tld-xyz').kind, 'nxdomain', 'NXDOMAIN (no such TLD)');
      // example.com is served by Cloudflare DNS, which answers missing names with NOERROR/NODATA ("black lies").
      assert(['nxdomain', 'unresolved'].includes(by('no-such-host-e2e-7c1f.example.com').kind), 'missing name does not resolve');
      assertEqual(by('www.cloudflare.com').kind, 'cloudflare', 'Cloudflare');
      const privateRow = by('10-0-0-1.nip.io');
      if (privateRow.text.includes('10.0.0.1')) {
        assertEqual(privateRow.kind, 'private', 'nip.io → private');
        assert(privateRow.text.includes('lab01'), 'private IP matched to the inventory');
      }
      const kinds = new Set(rows.map((r) => r.kind));
      assert(kinds.has('cdn') || kinds.has('platform'), `CDN / platform present: ${[...kinds]}`);
      const stats = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.bulk-stats .stat')].map((s) => [s.dataset.stat, s.querySelector('.stat-value').textContent])));
      assertEqual(Number(stats.names), expected.names.length, 'stat names');
      assert(Number(stats.servers) >= 1, `servers stat ${stats.servers}`);
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, opts, 'bulk-desktop-light-en-results');
    });

    await run.step('PTR column filled (dns.google → dns.google)', async () => {
      await page.waitFor(() => {
        const tr = [...document.querySelectorAll('.bulk-hosts tbody tr.dt-row')].find((r) => r.querySelector('td:not(.dt-expander)')?.textContent.trim() === 'dns.google');
        const col = [...document.querySelectorAll('.bulk-hosts thead th')].findIndex((th) => th.dataset.key === 'ptr');
        return tr && col >= 0 && /dns\.google/.test(tr.children[col].textContent);
      }, { timeout: 20000, message: 'PTR of 8.8.8.8' });
    });

    await run.step('filters: "On my servers", "Not resolving", search', async () => {
      const setFilter = (v) => page.evaluate((val) => {
        const sel = document.querySelector('[data-role="bulk-filter"]');
        sel.value = val;
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      }, v);
      await setFilter('mine');
      let rows = await rowsOf(page, '.bulk-hosts');
      assert(rows.length >= 1 && rows.every((r) => /google-dns|lab01|web09/.test(r.text)), `mine: ${rows.map((r) => r.first)}`);
      await setFilter('unresolved');
      rows = await rowsOf(page, '.bulk-hosts');
      assert(rows.some((r) => r.first === 'no-such-host-e2e-7c1f.example.com') && rows.every((r) => ['nxdomain', 'unresolved', 'dangling'].includes(r.kind)), 'unresolved');
      await setFilter('all');
      await page.type('.bulk-hosts .dt-search-input', '.gov');
      await page.waitFor(() => {
        const rows = [...document.querySelectorAll('.bulk-hosts tbody tr.dt-row')];
        return rows.length >= 1 && rows.every((tr) => tr.textContent.includes('.gov'));
      });
      await page.type('.bulk-hosts .dt-search-input', '');
    });

    await run.step('row details link to Global DNS and DNS Lookup', async () => {
      await page.click('.bulk-hosts tbody tr.dt-row .dt-expand-btn');
      await page.waitForSelector('.bulk-hosts .bulk-details');
      const links = await page.evaluate(() => [...document.querySelectorAll('.bulk-hosts .bulk-details a')].map((a) => a.getAttribute('href')));
      assert(links.some((l) => l.startsWith('#/global?name=')) && links.some((l) => l.startsWith('#/lookup?name=')), `links ${links}`);
      await page.click('.bulk-hosts tbody tr.dt-row .dt-expand-btn');
    });

    await run.step('IP addresses tab: 8.8.8.8 with its names, owner type, server and PTR', async () => {
      await page.click('.bulk-tabs [data-tab="ips"]');
      await page.waitForSelector('.bulk-ips tbody tr.dt-row');
      const rows = await page.evaluate(() => [...document.querySelectorAll('.bulk-ips tbody tr.dt-row')].map((tr) => [...tr.querySelectorAll('td')].map((td) => td.textContent.trim())));
      const g = rows.find((r) => r[0] === '8.8.8.8');
      assert(g, '8.8.8.8 listed');
      assert(g[3].includes('dns.google') && g[4].includes('google-dns') && g[5].includes('dns.google'), `8.8.8.8 row: ${g}`);
      assert(rows.some((r) => r[1] === 'Cloudflare'), 'a Cloudflare IP');
      const set = (v) => page.evaluate((val) => {
        const sel = document.querySelector('[data-role="bulk-ip-filter"]');
        sel.value = val;
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      }, v);
      await set('mine');
      const mine = await page.evaluate(() => [...document.querySelectorAll('.bulk-ips tbody tr.dt-row td:first-child')].map((td) => td.textContent));
      assert(mine.includes('8.8.8.8') && mine.every((ip) => ['8.8.8.8', '8.8.4.4', '10.0.0.1'].includes(ip)), `mine: ${mine}`);
      await set('all');
      await shot(page, opts, 'bulk-desktop-light-en-ips');
    });

    await run.step('exports: hosts CSV / JSON and IP CSV (captured downloads)', async () => {
      await takeDownloads(page);
      await page.click('.bulk-ips [data-export="csv"]');
      await page.click('.bulk-tabs [data-tab="hosts"]');
      await page.click('.bulk-hosts [data-export="csv"]');
      await page.click('.bulk-hosts [data-export="json"]');
      const files = await takeDownloads(page);
      const ipCsv = files.find((f) => /^bulk-ips-.*\.csv$/.test(f.name));
      const hostCsv = files.find((f) => /^bulk-resolve-.*\.csv$/.test(f.name));
      const hostJson = files.find((f) => /^bulk-resolve-.*\.json$/.test(f.name));
      assert(ipCsv && hostCsv && hostJson, `files: ${files.map((f) => f.name)}`);
      assertEqual(csvHeader(hostCsv.text), ['Hostname', 'Status', 'IPv4', 'Your servers', 'PTR', 'CNAME chain', 'IPv6', 'TTL'], 'hosts header');
      assert(hostCsv.bom, 'BOM for Excel');
      assertEqual(csvHeader(ipCsv.text)[0], 'IP address', 'ip header');
      const json = JSON.parse(hostJson.text);
      assertEqual(json.length, expected.names.length, 'JSON rows');
      assert(json.some((r) => r.name === 'dns.google' && String(r.ipv4).includes('8.8.8.8')), 'JSON content');
    });

    await run.step('copy buttons report the number of copied lines', async () => {
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((t) => t.remove()));
      await page.click('[data-action="bulk-copy-names"]');
      await page.waitFor(() => !!document.querySelector('.toast'));
      const text = await page.evaluate(() => document.querySelector('.toast').textContent);
      assert(/lines copied|Could not copy/.test(text), `toast: ${text}`);
    });

    await run.step('LIVE: ASN / owner / country via RIPEstat', async () => {
      const prev = (await jobStatus(page)).id;
      await page.type('[data-role="bulk-input"]', 'dns.google\none.one.one.one');
      await setOption(page, 'asn', true);
      await page.click('[data-action="bulk-run"]');
      await waitJobDone(page, prev, 120000);
      await page.click('.bulk-tabs [data-tab="ips"]');
      await page.waitFor(() => /AS15169/.test(document.querySelector('.bulk-ips')?.textContent || '')
        && /AS13335/.test(document.querySelector('.bulk-ips').textContent), { timeout: 60000, message: 'ASNs shown' });
      const text = await page.evaluate(() => document.querySelector('.bulk-ips').textContent);
      assert(/United States|US/.test(text) || /Country/.test(text), 'country column');
      await shot(page, opts, 'bulk-desktop-light-en-asn');
      await setOption(page, 'asn', false);
    });

    await run.step('Cancel stops a long job and keeps the rows resolved so far', async () => {
      const many = Array.from({ length: 600 }, (_, i) => `e2e-cancel-${Date.now().toString(36)}-${i}.example.com`).join('\n');
      await page.type('[data-role="bulk-input"]', many);
      const seen = await page.evaluate(async () => {
        const prev = document.querySelector('.bulk-results')?.dataset.job || '';
        document.querySelector('[data-action="bulk-run"]').click();
        const t0 = performance.now();
        while (document.querySelector('.bulk-results')?.dataset.job === prev) {
          if (performance.now() - t0 > 5000) return null;
          await new Promise((r) => setTimeout(r, 10));
        }
        await new Promise((r) => setTimeout(r, 200));
        const status = document.querySelector('.bulk-progress').dataset.status;
        document.querySelector('[data-action="bulk-cancel"]').click();
        return status;
      });
      assertEqual(seen, 'running', 'running before cancel');
      await page.waitFor(() => document.querySelector('.bulk-progress')?.dataset.status === 'cancelled', { timeout: 15000 });
      const note = await page.evaluate(() => document.querySelector('.bulk-progress').textContent);
      assert(/Cancelled/.test(note) && /of 600 hostnames/.test(note), `note: ${note}`);
    });

    await run.step('a job keeps running on another page; the toast leads back', async () => {
      const many = Array.from({ length: 150 }, (_, i) => `e2e-bg-${Date.now().toString(36)}-${i}.example.com`).join('\n');
      await page.type('[data-role="bulk-input"]', many);
      const ok = await page.evaluate(async () => {
        const prev = document.querySelector('.bulk-results')?.dataset.job || '';
        document.querySelector('[data-action="bulk-run"]').click();
        const t0 = performance.now();
        while (document.querySelector('.bulk-results')?.dataset.job === prev) {
          if (performance.now() - t0 > 5000) return false;
          await new Promise((r) => setTimeout(r, 10));
        }
        const running = document.querySelector('.bulk-progress').dataset.status === 'running';
        window.location.hash = '#/about';
        return running;
      });
      assert(ok, 'left while running');
      await page.waitFor(() => [...document.querySelectorAll('.toast')].some((t) => /Bulk resolve finished/.test(t.textContent)), { timeout: 90000 });
      await page.evaluate(() => [...document.querySelectorAll('.toast')].find((t) => /Bulk resolve finished/.test(t.textContent)).querySelector('.btn-ghost').click());
      await page.waitFor(() => document.documentElement.dataset.view === 'bulk' && document.querySelector('.bulk-progress')?.dataset.status === 'done');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.bulk-hosts tbody tr.dt-row').length), 150, 'rows after returning');
    });

    await run.step('"Use the names of the last scan" and #/bulk?names=… fill the list', async () => {
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.setSession('scanHosts', {
        domains: ['example.com'], names: ['www.example.com', 'example.com', 'mail.example.com'], finishedAt: new Date()
      }));
      await page.waitForSelector('[data-action="bulk-from-scan"]');
      await page.click('[data-action="bulk-from-scan"]');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="bulk-input"]').value.trim().split('\n')), ['www.example.com', 'example.com', 'mail.example.com'], 'from scan');
      await page.evaluate(() => { location.hash = '#/bulk?names=a.example.org,b.example.org'; });
      await page.waitFor(() => document.querySelector('[data-role="bulk-input"]').value === 'a.example.org\nb.example.org');
      await gotoRoute(page, 'bulk');
    });

    await run.step('language switch (Turkish) keeps the results; options persist', async () => {
      const id = (await jobStatus(page)).id;
      await setLangUi(page, 'tr');
      await page.waitForSelector('.bulk-results');
      assertEqual((await jobStatus(page)).id, id, 'same job');
      assert(/Host adları/.test(await page.evaluate(() => document.querySelector('.bulk-tabs').textContent)), 'Turkish tabs');
      const stored = await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.bulk.options')));
      assert(stored.ptr === true && stored.asn === false, `stored options ${JSON.stringify(stored)}`);
      await setLangUi(page, 'en');
    });

    await run.step('dark theme', async () => {
      await page.type('[data-role="bulk-input"]', input);
      const prev = (await jobStatus(page)).id;
      await page.click('[data-action="bulk-run"]');
      await waitJobDone(page, prev);
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.evaluate(() => window.scrollTo(0, 0));
      await assertNoHorizontalScroll(page, 'dark');
      await shot(page, opts, 'bulk-desktop-dark-en-results');
      await page.click('.bulk-tabs [data-tab="ips"]');
      await shot(page, opts, 'bulk-desktop-dark-en-ips');
      await page.click('.bulk-tabs [data-tab="hosts"]');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    run.group('Phone 390×844 (Turkish)');
    await run.step('phone layout fits 390 px in light and dark', async () => {
      await page.setViewport({ width: 390, height: 844, mobile: true });
      await setLangUi(page, 'tr');
      for (const scheme of ['light', 'dark']) {
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await page.evaluate(() => window.scrollTo(0, 0));
        await assertNoHorizontalScroll(page, `phone ${scheme}`);
        await shot(page, opts, `bulk-mobile-${scheme}-tr-results`);
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await page.setViewport({ width: 1440, height: 900 });
    });

    run.group('Quality');
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'bulk', origin));
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
