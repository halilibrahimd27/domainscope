#!/usr/bin/env node
/**
 * ip.e2e.mjs — end-to-end test of the "IP Intel" view in a real headless browser, against the
 * live RIPEstat / ipwho.is / HackerTarget APIs and DoH (network required).
 *
 *   node tests/e2e/ip.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--no-quota-apis]
 *
 * --no-quota-apis blocks ipwho.is and HackerTarget in the browser (their anonymous daily quotas
 * are small): the reverse-IP step then checks the error path instead of spending a unit.
 *
 * Covers: pure helpers (Node); shared link with IPv4, IPv6, a private IP and a host name;
 * PTR / ASN / owner / location / operator columns (incl. the well-known-network hint for
 * 1.1.1.1 and the flag / country-code fallback); inventory matching; private IPs never
 * looked up; one reverse-IP lookup (uses 1 HackerTarget quota unit — "limited" is accepted);
 * row details; input validation notes; language re-mount keeping rows; phone light/dark;
 * no console errors, exceptions or CSP violations; complete i18n.
 *
 * Tolerated: request failures of FLAKY_HOSTS (ipwho.is and HackerTarget answer 429 once their
 * small free quotas are used up — the app reports that in the table).
 */

import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { parseIpInput, classifyIp, MAX_IPS } from '../../assets/js/views/ip.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SHOTS = path.join(HERE, 'screenshots');
const BASE = '/domainscope/';
const argv = process.argv.slice(2);
const optValue = (name, def) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : def;
};
const BROWSER = optValue('--browser', 'auto');
const HEADED = argv.includes('--headed');
const SHOTS_ON = !argv.includes('--no-shots');
const NO_QUOTA_APIS = argv.includes('--no-quota-apis');
// Third-party hosts whose request failures the view reports in its UI (not app errors): every
// public DoH resolver can time out or, like Quad9 over HTTP/3, omit CORS headers.
const FLAKY_HOSTS = ['ipwho.is', 'api.hackertarget.com', ...RESOLVERS.map((r) => new URL(r.url).hostname)];
const ROWS_DONE = "document.querySelectorAll('.ipi-row').length > 0 && document.querySelectorAll('.ipi-row.is-pending').length === 0 && !document.querySelector('[data-action=\"run\"]').hidden";

/* ------------------------------------------------------------------------ */
/* Tiny runner                                                              */
/* ------------------------------------------------------------------------ */

const results = [];
const notes = [];
let currentGroup = '';

function group(name) {
  currentGroup = name;
  process.stdout.write(`\n${name}\n`);
}

async function step(name, fn) {
  const t0 = Date.now();
  try {
    await fn();
    results.push({ group: currentGroup, name, ok: true });
    process.stdout.write(`  PASS  ${name} (${Date.now() - t0} ms)\n`);
  } catch (err) {
    results.push({ group: currentGroup, name, ok: false, error: err });
    process.stdout.write(`  FAIL  ${name}\n        ${String((err && err.stack) || err).split('\n').slice(0, 4).join('\n        ')}\n`);
  }
}

function assert(cond, message) {
  if (!cond) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

/** Block the small-quota APIs in this tab (--no-quota-apis); failures show up in the UI only. */
async function blockQuotaApis(page) {
  await page.send('Network.enable');
  await page.send('Network.setBlockedURLs', { urls: ['*://ipwho.is/*', '*://api.hackertarget.com/*'] });
}

async function waitReady(page) {
  await page.waitFor(() => document.documentElement.dataset.appReady === 'true', { timeout: 20000, message: 'app ready' });
}

async function gotoHash(page, hash, view) {
  // Wait for the hashchange to be handled, so a same-view navigation cannot race the checks below.
  await page.evaluate((hsh) => new Promise((resolve) => {
    if (window.location.hash === hsh) {
      resolve();
      return;
    }
    window.addEventListener('hashchange', () => setTimeout(resolve, 0), { once: true });
    window.location.hash = hsh;
  }), hash);
  await page.waitFor((v) => document.documentElement.dataset.view === v && document.querySelector('#page-body')?.dataset.view === v
    && document.querySelector('#page-body').childElementCount > 0 && !document.querySelector('#page-body .page-loading'),
  { args: [view], message: `view ${view}` });
}

async function assertNoHorizontalScroll(page, where) {
  const rep = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
  assert(rep.sw <= rep.cw + 1, `${where}: page scrolls horizontally (${rep.sw} > ${rep.cw})`);
}

async function shot(page, name) {
  if (!SHOTS_ON) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((x) => x.remove()));
  await page.screenshot(path.join(SHOTS, `${name}.png`), { fullPage: true });
}

async function assertClean(page, where) {
  const p = await page.problems();
  const issues = [
    ...p.consoleErrors.map((m) => `console.${m.type}: ${m.text}`),
    ...p.exceptions.map((e) => `exception: ${e.text}`),
    ...p.csp.map((c) => `CSP: ${JSON.stringify(c).slice(0, 300)}`)
  ];
  for (const e of p.logErrors) {
    const text = `${e.text || ''} ${e.url || ''}`;
    if (FLAKY_HOSTS.some((host) => text.includes(`//${host}/`))) notes.push(`${where}: tolerated ${e.source} error for ${FLAKY_HOSTS.find((host) => text.includes(`//${host}/`))}`);
    else issues.push(`log(${e.source}): ${e.text} ${e.url || ''}`);
  }
  assert(issues.length === 0, `${where}: ${issues.length} problem(s):\n          ${issues.join('\n          ')}`);
}

async function setLangUi(page, lang) {
  if (await page.evaluate(() => document.documentElement.lang) === lang) return;
  await page.click(`[data-control="lang"] [data-value="${lang}"]`);
  await page.waitFor((l) => document.documentElement.lang === l, { args: [lang], message: `lang ${lang}` });
  await page.waitFor(() => document.querySelector('#page-body')?.childElementCount > 0);
}

async function checkI18n(page) {
  const info = await page.evaluate(async () => {
    const i = await import('./assets/js/i18n.js');
    const en = i.listKeys('en').filter((k) => k.startsWith('ipi.'));
    const tr = i.listKeys('tr').filter((k) => k.startsWith('ipi.'));
    return { missing: i.getMissingKeys(), onlyEn: en.filter((k) => !tr.includes(k)), onlyTr: tr.filter((k) => !en.includes(k)) };
  });
  assertEqual(info.missing, [], 'missing i18n keys');
  assertEqual(info.onlyEn, [], 'ipi.* keys only in EN');
  assertEqual(info.onlyTr, [], 'ipi.* keys only in TR');
}

/** Row text by IP. */
function rowsInfo() {
  const out = {};
  for (const tr of document.querySelectorAll('.ipi-row')) {
    const ip = tr.querySelector('.ipi-ip')?.textContent;
    out[ip] = {
      text: tr.textContent.replace(/\s+/g, ' '),
      kind: tr.querySelector('[data-kind]')?.dataset.kind,
      network: tr.querySelector('[data-network]')?.dataset.network || null,
      relation: tr.querySelector('[data-relation]')?.dataset.relation || null,
      flag: (() => {
        const f = tr.querySelector('.ipi-flag');
        if (!f) return null;
        const mode = ['is-emoji', 'is-code', 'is-globe'].find((c) => f.classList.contains(c)) || null;
        return { cc: f.dataset.cc || null, mode, text: f.textContent };
      })(),
      reverse: tr.querySelector('.ipi-rev')?.dataset.state || (tr.querySelector('[data-action="reverse"]') ? 'button' : 'none')
    };
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  group('Pure helpers (Node)');
  await step('parseIpInput: ports, brackets, URLs, IDN, CIDR, junk, duplicates', () => {
    const p = parseIpInput('8.8.8.8, 1.1.1.1:443 [2001:db8::1]:8443 # comment\nhttps://www.Bücher.example/x github.com 10.0.0.0/8 bogus!! 8.8.8.8\n"192.0.2.7"');
    assertEqual(p.ips, ['8.8.8.8', '1.1.1.1', '2001:db8::1', '192.0.2.7'], 'ips');
    assertEqual(p.hosts, ['www.xn--bcher-kva.example', 'github.com'], 'hosts');
    assertEqual(p.cidrs, ['10.0.0.0/8'], 'cidrs');
    assertEqual(p.invalid, ['bogus!!'], 'invalid');
    assertEqual(parseIpInput(''), { ips: [], hosts: [], invalid: [], cidrs: [] }, 'empty');
    assert(MAX_IPS >= 100, 'sane limit');
  });
  await step('classifyIp: Cloudflare / private / direct', () => {
    assertEqual(classifyIp('104.16.132.229').kind, 'cloudflare', 'cloudflare');
    assertEqual(classifyIp('10.1.2.3').kind, 'private', 'private');
    assertEqual(classifyIp('8.8.8.8').kind, 'direct', 'direct');
    assertEqual(classifyIp('2606:4700:4700::1111').kind, 'cloudflare', 'cloudflare v6');
  });

  await mkdir(SHOTS, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: BROWSER, headless: !HEADED });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}\n`);

  try {
    group('Desktop 1440×900 (English, live APIs)');
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    if (NO_QUOTA_APIS) await blockQuotaApis(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/about`);
    await waitReady(page);
    await setLangUi(page, 'en');
    await page.evaluate(async () => {
      const { state } = await import('./assets/js/state.js');
      state.setInventory('dns-google 8.8.8.8\nlan-box 10.0.0.1\n');
    });

    await step('empty state; "My servers’ IPs" button loads the inventory', async () => {
      await gotoHash(page, '#/ip', 'ip');
      assert(await page.evaluate(() => !!document.querySelector('.ipi-empty .empty')), 'empty state');
      await page.click('[data-action="inventory"]');
      const text = await page.evaluate(() => document.querySelector('[data-role="ip-input"]').value);
      assertEqual(text.trim().split('\n'), ['8.8.8.8', '10.0.0.1'], 'inventory IPs');
    });

    await step('shared link with IPv4, IPv6, private IP and a host name → full rows', async () => {
      await gotoHash(page, '#/about', 'about');
      await gotoHash(page, '#/ip?ips=8.8.8.8,2606:4700:4700::1111,10.0.0.1,1.1.1.1,github.com', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 60000, message: 'rows looked up' });
      const rows = await page.evaluate(rowsInfo);
      const ips = Object.keys(rows);
      assert(ips.length >= 5, `rows: ${ips}`);
      const g = rows['8.8.8.8'];
      assert(/dns\.google/.test(g.text) && /AS15169/.test(g.text) && /dns-google/.test(g.text), `8.8.8.8 row: ${g.text}`);
      assertEqual(g.kind, 'direct', '8.8.8.8 kind');
      assertEqual(rows['2606:4700:4700::1111'].kind, 'cloudflare', 'Cloudflare IPv6');
      assert(/AS13335/.test(rows['2606:4700:4700::1111'].text), 'AS13335');
      assertEqual(rows['10.0.0.1'].kind, 'private', 'private kind');
      assert(/lan-box/.test(rows['10.0.0.1'].text) && /not for private IPs/.test(rows['10.0.0.1'].text), 'private row: server + no reverse');
      // 1.1.1.1 is AS13335 but outside Cloudflare's proxy ranges: still 'direct', with a network hint.
      const one = rows['1.1.1.1'];
      assertEqual([one.kind, one.network, one.relation], ['direct', 'cloudflare', 'outside-proxy-ranges'], '1.1.1.1 operator');
      assert(/AS13335/.test(one.text) && /Cloudflare network/.test(one.text) && /not a proxied-site range/.test(one.text), `1.1.1.1 row: ${one.text}`);
      assertEqual([g.network, g.relation], ['google', 'hosted'], '8.8.8.8 network hint');
      assertEqual(rows['2606:4700:4700::1111'].network, null, 'no hint on a proxied range');
      // Flags: an emoji where the platform draws them, else the ISO code in a chip (Windows Chrome/Edge).
      const flagMode = await page.evaluate(async () => ((await import('./assets/js/ui/flag.js')).supportsFlagEmoji() ? 'is-emoji' : 'is-code'));
      const flags = Object.values(rows).map((r) => r.flag).filter((f) => f && f.cc);
      assert(g.flag && g.flag.cc === 'US', `8.8.8.8 flag: ${JSON.stringify(g.flag)}`);
      for (const f of flags) {
        assertEqual(f.mode, flagMode, `flag mode for ${f.cc}`);
        assert(/^[A-Z]{2}$/.test(f.cc), `flag cc ${f.cc}`);
        if (f.mode === 'is-code') assertEqual(f.text, f.cc, 'code chip text');
        else assertEqual([...f.text].length, 2, `emoji flag for ${f.cc}`);
      }
      notes.push(`flags rendered as ${flagMode === 'is-code' ? 'ISO-code chips (no flag emoji on this platform)' : 'emoji'}`);
      assert(Object.values(rows).some((r) => /from github\.com/.test(r.text)), 'host name resolved and credited');
      const stats = await page.evaluate(() => [...document.querySelectorAll('.ipi-stats .stat-value')].map((v) => v.textContent));
      assertEqual(stats[2], '2', 'your servers stat');
      await assertNoHorizontalScroll(page, 'rows');
      await shot(page, 'ip-desktop-light-en');
    });

    await step('CSV and JSON exports contain the looked-up data', async () => {
      const files = await page.evaluate(async () => {
        // Capture downloads: ui/download.js creates a Blob URL and clicks a temporary <a download>.
        const captured = [];
        const origCreate = URL.createObjectURL;
        const origClick = HTMLAnchorElement.prototype.click;
        const blobs = new Map();
        URL.createObjectURL = (blob) => {
          const url = origCreate.call(URL, blob);
          blobs.set(url, blob);
          return url;
        };
        HTMLAnchorElement.prototype.click = function click() {
          if (this.download && blobs.has(this.href)) captured.push({ name: this.download, blob: blobs.get(this.href) });
          else origClick.call(this);
        };
        try {
          document.querySelector('.ipi-results [data-export="csv"]').click();
          document.querySelector('.ipi-results [data-export="json"]').click();
        } finally {
          URL.createObjectURL = origCreate;
          HTMLAnchorElement.prototype.click = origClick;
        }
        return Promise.all(captured.map(async (f) => ({ name: f.name, text: await f.blob.text() })));
      });
      assertEqual(files.length, 2, 'two downloads');
      const [csv, json] = files;
      assert(/^ip-intel-.*\.csv$/.test(csv.name) && /^ip-intel-.*\.json$/.test(json.name), `file names: ${csv.name}, ${json.name}`);
      assert(csv.text.includes('8.8.8.8') && csv.text.includes('AS15169') && csv.text.includes('dns-google'), `CSV: ${csv.text.slice(0, 300)}`);
      const data = JSON.parse(json.text);
      const g = data.find((r) => r.ip === '8.8.8.8');
      assert(g && g.asn === 15169 && g.servers.includes('dns-google') && g.ptr.includes('dns.google'), `JSON row: ${JSON.stringify(g)}`);
    });

    await step('private addresses are never sent to the intel APIs', async () => {
      const sent = await page.evaluate(() => performance.getEntriesByType('resource').map((e) => e.name).filter((u) => /10\.0\.0\.1/.test(u) && !/^http:\/\/127/.test(u)));
      assertEqual(sent, [], 'requests mentioning 10.0.0.1');
    });

    await step('row details: RIR, sources and external links', async () => {
      await page.evaluate(() => {
        const row = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === '8.8.8.8');
        row.querySelector('.dt-expand-btn').click();
      });
      await page.waitFor(() => !!document.querySelector('.dt-details .ipi-details'));
      const text = await page.evaluate(() => document.querySelector('.dt-details .ipi-details').textContent);
      assert(/ARIN/.test(text) && /RIPEstat/.test(text) && /ripestat/.test(text), `details: ${text.slice(0, 300)}`);
    });

    await step('reverse IP (1 HackerTarget quota unit): domains, or a clear quota message', async () => {
      await page.evaluate(() => document.querySelector('[data-action="reverse"][data-ip="1.1.1.1"]').click());
      await page.waitFor(() => {
        const row = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === '1.1.1.1');
        return !!row && !!row.querySelector('.ipi-rev');
      }, { timeout: 30000, message: 'reverse IP result' });
      const state = (await page.evaluate(rowsInfo))['1.1.1.1'].reverse;
      assert(NO_QUOTA_APIS ? state === 'error' : ['done', 'limited', 'error'].includes(state), `reverse state ${state}`);
      notes.push(`reverse IP outcome: ${state}${NO_QUOTA_APIS ? ' (HackerTarget blocked by --no-quota-apis)' : ''}`);
    });

    await step('input notes: junk and CIDR ranges are reported; nothing usable → field error', async () => {
      await page.type('[data-role="ip-input"]', '1.1.1.1 junk!! 10.0.0.0/8');
      await page.click('[data-action="run"]');
      await page.waitFor(ROWS_DONE, { timeout: 30000 });
      const notesText = await page.evaluate(() => document.querySelector('.ipi-notes').textContent);
      assert(/junk!!/.test(notesText) && /10\.0\.0\.0\/8/.test(notesText), `notes: ${notesText}`);
      assert((await page.evaluate(() => window.location.hash)).includes('ips=1.1.1.1'), 'URL updated');
      await page.type('[data-role="ip-input"]', '10.0.0.0/8');
      await page.click('[data-action="run"]');
      await page.waitFor(() => !!document.querySelector('.ipi-input.has-error'), { message: 'field error' });
    });

    await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
    await step('[dark] example list renders; language switch keeps rows (no re-query)', async () => {
      await page.click('[data-action="example"]');
      await page.click('[data-action="run"]');
      await page.waitFor(ROWS_DONE, { timeout: 60000 });
      await shot(page, 'ip-desktop-dark-en');
      const before = Object.keys(await page.evaluate(rowsInfo));
      const shareLabel = () => page.evaluate(() => [...document.querySelectorAll('.page-actions button')].map((b) => b.textContent.trim()));
      assertEqual(await shareLabel(), ['Copy link'], 'header action before the switch');
      await setLangUi(page, 'tr');
      await page.waitFor(() => document.querySelector('[data-action="run"] .btn-label')?.textContent === 'Sorgula');
      const after = await page.evaluate(rowsInfo);
      assertEqual(Object.keys(after), before, 'rows kept');
      assert(Object.values(after).every((r) => !/Looking up|Sorgulanıyor/.test(r.text)), 'no pending rows');
      assertEqual(await shareLabel(), ['Bağlantıyı kopyala'], 'header "Copy link" kept (translated) for the restored rows');
      await assertNoHorizontalScroll(page, 'dark tr');
      await shot(page, 'ip-desktop-dark-tr');
      await setLangUi(page, 'en');
    });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    await step('i18n: no missing keys; ipi.* TR/EN key sets match', () => checkI18n(page));
    await step('desktop: no console errors, exceptions or CSP violations', () => assertClean(page, 'desktop'));
    await page.evaluate(async () => (await import('./assets/js/state.js')).state.clearInventory());
    await page.close();

    group('Phone 390×844 (Turkish)');
    const phone = await browser.newPage('about:blank', { width: 390, height: 844, mobile: true });
    if (NO_QUOTA_APIS) await blockQuotaApis(phone);
    await phone.goto(`${server.url}#/about`);
    await waitReady(phone);
    await setLangUi(phone, 'tr');
    for (const scheme of ['light', 'dark']) {
      await step(`[${scheme}] lookup fits 390 px`, async () => {
        await phone.emulateMedia({ 'prefers-color-scheme': scheme });
        await gotoHash(phone, '#/about', 'about');
        await gotoHash(phone, `#/ip?ips=${scheme === 'light' ? '8.8.8.8,1.1.1.1' : '140.82.121.4,104.16.132.229'}`, 'ip');
        await phone.waitFor(ROWS_DONE, { timeout: 60000 });
        await assertNoHorizontalScroll(phone, `phone ${scheme}`);
        await shot(phone, `ip-mobile-${scheme}-tr`);
      });
    }
    await step('phone: no console errors, exceptions or CSP violations', () => assertClean(phone, 'phone'));
    await step('phone: i18n complete', () => checkI18n(phone));
    await phone.close();
  } finally {
    await browser.close();
    await server.close();
  }

  const failed = results.filter((r) => !r.ok);
  for (const n of [...new Set(notes)]) process.stdout.write(`  note: ${n}\n`);
  process.stdout.write(`\n${results.length - failed.length} passed, ${failed.length} failed${SHOTS_ON ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : ''}\n`);
  if (failed.length) {
    for (const f of failed) process.stdout.write(`  - ${f.group}: ${f.name}\n`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
