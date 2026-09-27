#!/usr/bin/env node
/**
 * ip.e2e.mjs — end-to-end test of the "IP Intel" view in a real headless browser, against the
 * live RIPEstat / ipwho.is / HackerTarget APIs and DoH (network required).
 *
 *   node tests/e2e/ip.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--no-quota-apis] [--offline]
 *
 * OFFLINE group (always runs; --offline skips the live ones): RIPEstat, ipwho.is and reverse DNS
 * answered in the page (nothing leaves it). A source that answers 429 or fails marks only the
 * cells it leaves empty "⚠ n/a" (tooltip: which source, what error), a chip per service sums the
 * failures up, and Retry — per row, or per chip for every row it failed on — asks exactly those
 * sources again; a reverse lookup answered SERVFAIL says so; Stop leaves no chip "asking…"; a
 * Retry still in flight when a new lookup starts never draws over the new run's row; the CSV
 * says "n/a" in every language; stat cards with a zero count fold into one sentence; Copy
 * summary says how many lookups failed when every source failed (EN + TR); 1440 and 375 px,
 * light and dark, English and Turkish.
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
import { zoneHandoffScript, stubClipboard, takeClipboard } from './scan.e2e.mjs';
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
const OFFLINE = argv.includes('--offline');
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
    await offlineGroup(browser, server);
    if (!OFFLINE) await liveGroups(browser, server);
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

/* ------------------------------------------------------------------------ */
/* Offline: a failed source is never a silent dash                          */
/* ------------------------------------------------------------------------ */

/** Reverse DNS of the offline addresses (the zone script answers under in-addr.arpa). */
const PTR_ZONE = {
  '7.113.0.203.in-addr.arpa': { PTR: ['web.example.com'] },
  '8.113.0.203.in-addr.arpa': { PTR: ['app.example.com'] },
  '60.113.0.203.in-addr.arpa': { PTR: ['retry.example.com'] },
  // A broken reverse delegation: every resolver answers SERVFAIL.
  '70.113.0.203.in-addr.arpa': { RCODE: { PTR: 'SERVFAIL' } },
  '20.100.51.198.in-addr.arpa': { PTR: ['mail.example.net'] }
};

/**
 * RIPEstat and ipwho.is answered in the page (installed after the zone script, which blocks
 * every other request): addresses in `window.__ipFake.limited` when the request is made get
 * HTTP 429 from RIPEstat, an address in `window.__ipFake.slow` (ip → ms) is answered that much
 * later (an abort still ends the wait), and ipwho.is always says its quota is used up. `calls` lists "<dataset> <ip>" per
 * request.
 */
const IP_FAKE_SCRIPT = `(() => {
  const inner = window.fetch;
  const fake = window.__ipFake = { limited: [], calls: [], slow: {} };
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const wait = (ms, signal) => new Promise((resolve, reject) => {
    if (signal && signal.aborted) { reject(new DOMException('Aborted', 'AbortError')); return; }
    const timer = setTimeout(resolve, ms);
    if (signal) signal.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
  });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const u = new URL(url, location.href);
    if (u.hostname === 'stat.ripe.net') {
      const ip = u.searchParams.get('resource');
      const call = u.pathname.split('/')[2];
      fake.calls.push(call + ' ' + ip);
      const limited = fake.limited.includes(ip);
      if (fake.slow[ip]) await wait(fake.slow[ip], (init && init.signal) || (typeof input === 'object' && input && input.signal) || null);
      if (limited) return new Response('Too Many Requests', { status: 429 });
      if (call === 'prefix-overview') {
        return json({ status: 'ok', data: { announced: true, asns: [{ asn: 64500, holder: 'EXAMPLE-NET - Example Networks B.V.' }],
          resource: ip.split('.').slice(0, 3).join('.') + '.0/24', block: { desc: 'Administered by RIPE NCC' } } });
      }
      if (call === 'maxmind-geo-lite') {
        return json({ status: 'ok', data: { located_resources: [{ locations: [{ country: 'NL', city: 'Amsterdam', covered_percentage: 100 }] }] } });
      }
      return json({ status: 'error', messages: [['error', 'unknown call']] }, 400);
    }
    if (u.hostname === 'ipwho.is') {
      fake.calls.push('ipwhois ' + u.pathname.slice(1));
      return json({ success: false, message: 'You have exceeded the rate limit' });
    }
    return inner(input, init);
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

/** The CSV and JSON exports of the IP table, captured in the page: [{ name, text }] (CSV first). */
function exportFiles(page) {
  return page.evaluate(async () => {
    const captured = [];
    const origCreate = URL.createObjectURL;
    const origClick = HTMLAnchorElement.prototype.click;
    const blobs = new Map();
    URL.createObjectURL = (blob) => { const url = origCreate.call(URL, blob); blobs.set(url, blob); return url; };
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
}

/** Per address: which cells say n/a (with their tooltips), the row's Retry, the chips and the folded stats. */
function failureInfo() {
  const rows = {};
  for (const tr of document.querySelectorAll('.ipi-row')) {
    const ip = tr.querySelector('.ipi-ip')?.textContent;
    const na = {};
    for (const col of ['ptr', 'network', 'prefix', 'location']) {
      const mark = tr.querySelector(`.ipi-col-${col} .na-mark`);
      if (mark) na[col] = { sources: mark.dataset.na, title: mark.title, sr: mark.querySelector('.sr-only')?.textContent || '' };
    }
    const retry = tr.querySelector('.ipi-retry');
    rows[ip] = {
      na, retry: retry ? retry.dataset.sources : null, retryName: retry ? retry.getAttribute('aria-label') : null,
      busy: retry?.getAttribute('aria-busy') === 'true', text: tr.textContent.replace(/\s+/g, ' ')
    };
  }
  return {
    rows,
    chips: [...document.querySelectorAll('.ipi-sources .src-chip')].map((c) => ({
      id: c.dataset.source, state: c.dataset.state, value: c.querySelector('.src-chip-value')?.textContent || '', retry: !!c.querySelector('[data-action="retry-source"]')
    })),
    shownStats: [...document.querySelectorAll('.ipi-stats .stat')].filter((s) => !s.hidden).map((s) => s.dataset.stat),
    zero: document.querySelector('.ipi-zero')?.hidden ? null : document.querySelector('.ipi-zero')?.textContent
  };
}

async function offlineGroup(browser, server) {
  group('Offline: failed sources (RIPEstat, ipwho.is and reverse DNS answered in the page)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const netHits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript('in-addr.arpa', PTR_ZONE) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: IP_FAKE_SCRIPT });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  const calls = () => page.evaluate(() => window.__ipFake.calls.slice());
  const info = () => page.evaluate(failureInfo);
  const IPS = '203.0.113.7,198.51.100.20,10.0.0.1';
  try {
    await step('a 429 marks only the cells it leaves empty "⚠ n/a", naming the source and the wait', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await page.evaluate(async () => {
        (await import('./assets/js/state.js')).state.clearInventory();
        window.__ipFake.limited = ['203.0.113.7'];
      });
      await gotoHash(page, `#/ip?ips=${IPS}`, 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      const i = await info();
      const bad = i.rows['203.0.113.7'];
      assertEqual(Object.keys(bad.na), ['network', 'prefix', 'location'], 'n/a cells of the limited address');
      assertEqual([bad.na.network.sources, bad.na.prefix.sources, bad.na.location.sources], ['ripestat ipwhois', 'ripestat', 'ripestat-geo ipwhois'], 'sources per cell, primary first');
      assert(bad.na.prefix.title === 'RIPEstat: rate limited — try again in a few minutes', `tooltip: ${bad.na.prefix.title}`);
      assert(bad.na.network.title.includes('ipwho.is: rate limited — try again later'), `fallback in the tooltip: ${bad.na.network.title}`);
      assert(/^not available: RIPEstat: rate limited/.test(bad.na.prefix.sr), `screen-reader text: ${bad.na.prefix.sr}`);
      assert(/web\.example\.com/.test(bad.text), 'the PTR answered: shown');
      assertEqual(bad.retry, 'ripestat ipwhois ripestat-geo', 'the row Retry asks only the failed sources');
      assertEqual(bad.retryName, 'Retry 203.0.113.7 (RIPEstat, ipwho.is, RIPEstat (location))', 'its accessible name says which row and which sources');
      assertEqual(i.rows['198.51.100.20'].na, {}, 'a complete row has no n/a');
      assertEqual(i.rows['198.51.100.20'].retry, null, 'and no Retry');
      assertEqual([i.rows['10.0.0.1'].na, i.rows['10.0.0.1'].retry], [{}, null], 'a private address is never looked up, never n/a');
      assertEqual(i.chips.map((c) => [c.id, c.state, c.retry]), [['ripestat', 'failed', true], ['ipwhois', 'failed', true], ['ptr', 'ok', false]], 'chips');
      assert(/1 failed · rate limited — try again in a few minutes/.test(i.chips[0].value), `RIPEstat chip: ${i.chips[0].value}`);
      // Zero counts fold into one sentence (no server list saved: "your servers" is not claimed).
      assertEqual(i.shownStats, ['ips', 'priv', 'nets', 'countries'], 'stat cards shown');
      assertEqual(i.zero, 'None of these addresses is behind a CDN / proxy.', 'folded zero counts');
      await assertNoHorizontalScroll(page, 'failed sources');
      await shot(page, 'ip-offline-desktop-light-en-failed');
    });

    await step('the JSON export says which fields are unavailable and why; CSV says n/a', async () => {
      const files = await exportFiles(page);
      const row = JSON.parse(files[1].text).find((r) => r.ip === '203.0.113.7');
      assertEqual(row.unavailable, { network: ['ripestat', 'ipwhois'], prefix: ['ripestat'], location: ['ripestat-geo', 'ipwhois'] }, 'unavailable');
      assert(row.sourceErrors.some((e) => e.source === 'ripestat' && e.status === 429 && e.errorKind === 'rate-limit'), `sourceErrors: ${JSON.stringify(row.sourceErrors)}`);
      const line = files[0].text.split(/\r?\n/).find((l) => l.startsWith('203.0.113.7'));
      assert(/,n\/a,n\/a,n\/a,/.test(line), `CSV row: ${line}`);
    });

    await step('Retry (keyboard) asks only the failed sources of that row again; the cells fill in', async () => {
      await page.evaluate(() => { window.__ipFake.limited = []; });
      const before = (await calls()).length;
      await page.evaluate(() => document.querySelector('.ipi-retry[data-ip="203.0.113.7"]').focus());
      await page.press('Enter');
      await page.waitFor(() => {
        const tr = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === '203.0.113.7');
        return tr && !tr.querySelector('.na-mark') && !tr.querySelector('.ipi-retry');
      }, { timeout: 15000, message: 'row filled in' });
      const after = (await calls()).slice(before);
      assertEqual(after.sort(), ['maxmind-geo-lite 203.0.113.7', 'prefix-overview 203.0.113.7'], 'requests of the Retry (ipwho.is had nothing left to fill)');
      const i = await info();
      assert(/AS64500/.test(i.rows['203.0.113.7'].text) && /203\.0\.113\.0\/24/.test(i.rows['203.0.113.7'].text), `row: ${i.rows['203.0.113.7'].text}`);
      assertEqual(i.chips.map((c) => [c.id, c.state]), [['ripestat', 'ok'], ['ipwhois', 'idle'], ['ptr', 'ok']], 'chips after the Retry');
      const focus = await page.evaluate(() => {
        const a = document.activeElement;
        return a && a !== document.body ? !!a.closest('.ipi-row') : false;
      });
      assert(focus, 'keyboard focus stays in the row');
    });

    await step('Look up again once the limit is over: only the failed sources are asked, the cells fill in', async () => {
      // A cached answer with failed sources is never served as it is: "try again in a few minutes" has to work.
      const ip = '203.0.113.12';
      await page.evaluate((x) => { window.__ipFake.limited = [x]; }, ip);
      await gotoHash(page, `#/ip?ips=${ip},198.51.100.20`, 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      assertEqual(Object.keys((await info()).rows[ip].na), ['network', 'prefix', 'location'], 'n/a after the 429');
      await page.evaluate(() => { window.__ipFake.limited = []; });
      const before = (await calls()).length;
      await page.click('[data-action="run"]');
      await page.waitFor((x) => {
        const tr = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === x);
        return tr && !tr.classList.contains('is-pending') && !tr.querySelector('.na-mark') && !document.querySelector('[data-action="run"]').hidden;
      }, { args: [ip], timeout: 15000, message: 'row filled in' });
      const after = (await calls()).slice(before).sort();
      assertEqual(after, [`maxmind-geo-lite ${ip}`, `prefix-overview ${ip}`], 'requests of the new lookup (the complete row and the PTR come from the cache)');
      const i = await info();
      assertEqual([Object.keys(i.rows[ip].na), i.rows[ip].retry], [[], null], 'no n/a, no Retry');
      assertEqual(i.chips[0].state, 'ok', 'RIPEstat chip ok');
    });

    await step('a chip Retry asks again for every row its service failed on, and only those', async () => {
      // Answers are cached per address for an hour (a retried one too): fresh addresses here.
      await page.evaluate(() => { window.__ipFake.limited = ['203.0.113.8', '203.0.113.9']; });
      await gotoHash(page, '#/ip?ips=203.0.113.8,203.0.113.9,198.51.100.20', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      let i = await info();
      assertEqual(Object.keys(i.rows).filter((ip) => Object.keys(i.rows[ip].na).length), ['203.0.113.8', '203.0.113.9'], 'two rows with n/a');
      assert(/2 failed/.test(i.chips[0].value), `chip: ${i.chips[0].value}`);
      await page.evaluate(() => { window.__ipFake.limited = []; });
      const before = (await calls()).length;
      await page.click('.ipi-sources [data-chip="ripestat"]');
      await page.waitFor(() => !document.querySelector('.ipi-row .na-mark'), { timeout: 15000, message: 'rows filled in' });
      const after = (await calls()).slice(before).sort();
      assertEqual(after, ['maxmind-geo-lite 203.0.113.8', 'maxmind-geo-lite 203.0.113.9', 'prefix-overview 203.0.113.8', 'prefix-overview 203.0.113.9'], 'requests of the chip Retry');
      i = await info();
      assertEqual(i.chips[0].state, 'ok', 'RIPEstat chip ok');
    });

    await step('a reverse lookup answered SERVFAIL says so ("answered SERVFAIL", not a bare "failed")', async () => {
      await page.evaluate(() => { window.__ipFake.limited = []; });
      await gotoHash(page, '#/ip?ips=203.0.113.70,198.51.100.20', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      const i = await info();
      const row = i.rows['203.0.113.70'];
      assertEqual([Object.keys(row.na), row.retry], [['ptr'], 'ptr'], 'only the PTR cell is n/a; Retry asks reverse DNS');
      assertEqual(row.na.ptr.title, 'Reverse DNS: answered SERVFAIL', 'tooltip');
      const ptr = i.chips.find((c) => c.id === 'ptr');
      assertEqual([ptr.state, ptr.value], ['failed', '1 failed · answered SERVFAIL'], 'reverse DNS chip');
    });

    await step('Stop before every address is looked up: no chip keeps saying "asking…"', async () => {
      // Twelve fresh addresses: two answer at once, RIPEstat keeps the rest waiting 4 s.
      const ips = Array.from({ length: 12 }, (_, n) => `203.0.113.${40 + n}`);
      await page.evaluate((list) => {
        window.__ipFake.limited = [];
        window.__ipFake.slow = Object.fromEntries(list.slice(2).map((ip) => [ip, 4000]));
      }, ips);
      try {
        await gotoHash(page, `#/ip?ips=${ips.join(',')}`, 'ip');
        await page.waitFor(() => document.querySelectorAll('.ipi-row').length === 12
          && document.querySelectorAll('.ipi-row:not(.is-pending)').length === 2, { timeout: 10000, message: 'two rows answered' });
        const running = await info();
        assertEqual(running.chips.map((c) => c.state), ['pending', 'pending', 'pending'], 'asking while rows are looked up');
        await page.click('[data-action="stop"]');
        await page.waitFor(() => !document.querySelector('[data-action="run"]').hidden, { timeout: 5000, message: 'stopped' });
        const i = await info();
        assertEqual(i.chips.map((c) => [c.id, c.state, c.value]), [['ripestat', 'ok', '2 answered'], ['ipwhois', 'idle', 'not needed'], ['ptr', 'ok', '2 answered']],
          'rows a stopped run never asked count for nothing');
        const left = await page.evaluate(() => ({
          spinners: document.querySelectorAll('.ipi-sources .spinner, .ipi-row .spinner').length,
          note: document.querySelector('.ipi-notes')?.textContent || ''
        }));
        assertEqual(left.spinners, 0, 'no spinner left');
        assert(left.note.includes('Stopped — rows without data were not looked up.'), `note: ${left.note}`);
        assertEqual(Object.values(i.rows).filter((r) => Object.keys(r.na).length || r.retry).length, 0, 'an unasked row is not n/a');
      } finally {
        await page.evaluate(() => { window.__ipFake.slow = {}; });
      }
    });

    await step('a Retry still in flight when a new lookup starts is cancelled: the new run’s row settles, no busy Retry', async () => {
      // 203.0.113.60 has a PTR record, so its answer is partial (RIPEstat 429) and cached; the next run asks RIPEstat again.
      const ip = '203.0.113.60';
      await page.evaluate((x) => { window.__ipFake.limited = [x]; }, ip);
      await gotoHash(page, `#/ip?ips=${ip},198.51.100.20`, 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      assertEqual(Object.keys((await info()).rows[ip].na), ['network', 'prefix', 'location'], 'n/a before the Retry');
      // The Retry waits 2.5 s at RIPEstat; "Look up" is pressed 300 ms after it.
      await page.evaluate((x) => { window.__ipFake.limited = []; window.__ipFake.slow = { [x]: 2500 }; }, ip);
      try {
        await page.click(`.ipi-retry[data-ip="${ip}"]`);
        await page.waitFor((x) => document.querySelector(`.ipi-retry[data-ip="${x}"]`)?.getAttribute('aria-busy') === 'true', { args: [ip], message: 'Retry busy' });
        await new Promise((resolve) => { setTimeout(resolve, 300); });
        // The new run's own question to RIPEstat is still limited (the Retry's would have been answered).
        await page.evaluate((x) => { window.__ipFake.limited = [x]; window.__ipFake.slow = {}; }, ip);
        await page.click('[data-action="run"]');
        await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'new run done' });
        // Past the moment the cancelled Retry would have answered.
        await new Promise((resolve) => { setTimeout(resolve, 3200); });
        const i = await info();
        const row = i.rows[ip];
        assertEqual([Object.keys(row.na), row.retry, row.busy], [['network', 'prefix', 'location'], 'ripestat ipwhois ripestat-geo', false],
          'the new run’s row: its own answer and a Retry ready to use');
        assertEqual(i.chips[0].state, 'failed', 'the chip agrees with the row');
        // That Retry works: the row fills in.
        await page.evaluate(() => { window.__ipFake.limited = []; window.__ipFake.slow = {}; });
        await page.click(`.ipi-retry[data-ip="${ip}"]`);
        await page.waitFor((x) => {
          const tr = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === x);
          return tr && !tr.querySelector('.na-mark') && !tr.querySelector('.ipi-retry');
        }, { args: [ip], timeout: 15000, message: 'row filled in' });
        assertEqual((await info()).chips[0].state, 'ok', 'RIPEstat chip ok');
      } finally {
        await page.evaluate(() => { window.__ipFake.slow = {}; });
      }
    });

    await step('Copy summary when every source fails: how many lookups failed, never a clean result or "no network data"; TR', async () => {
      // Fresh addresses without a PTR record: RIPEstat answers 429 and ipwho.is has no quota left.
      const failed = ['203.0.113.90', '203.0.113.91'];
      await page.evaluate((list) => { window.__ipFake.limited = list; }, failed);
      const copy = async () => {
        await stubClipboard(page);
        await page.click('[data-summary="ip"] [data-action="copy-summary"]');
        await page.click('[data-summary="ip"] [data-action="copy-summary-text"]');
        await page.waitFor(() => window.__clip.length === 2, { message: 'two copies' });
        return (await takeClipboard(page)).map((x) => x.split('\n')[0]);
      };
      await gotoHash(page, `#/ip?ips=${failed.join(',')}`, 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      const i = await info();
      assert(failed.every((ip) => i.rows[ip] && i.rows[ip].na.network), `every row says n/a: ${JSON.stringify(i.rows)}`);
      assertEqual(await copy(), ['**IP Intel · 2 addresses**: 2 lookups failed', 'IP Intel · 2 addresses: 2 lookups failed'], 'several addresses');
      await gotoHash(page, '#/about', 'about');
      await gotoHash(page, `#/ip?ips=${failed[0]}`, 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'row looked up' });
      assertEqual((await copy())[0], `**IP Intel · \`${failed[0]}\`**: Direct · lookup failed`, 'one address: the failure, not a clean "Direct"');
      await setLangUi(page, 'tr');
      assertEqual((await copy())[0], `**IP Bilgisi · \`${failed[0]}\`**: Doğrudan · sorgu başarısız`, 'Turkish, after the re-mount');
      await setLangUi(page, 'en');
    });

    for (const [n, scheme, lang, width] of [[30, 'dark', 'tr', 1440], [31, 'light', 'en', 375], [32, 'dark', 'tr', 375]]) {
      await step(`[${scheme}, ${lang.toUpperCase()}, ${width} px] the failed state reads well and fits`, async () => {
        const ip = `203.0.113.${n}`;
        await page.setViewport(width < 600 ? { width, height: 812, mobile: true } : { width, height: 900 });
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await setLangUi(page, lang);
        await page.evaluate((x) => { window.__ipFake.limited = [x]; }, ip);
        await gotoHash(page, '#/about', 'about');
        await gotoHash(page, `#/ip?ips=${ip},198.51.100.20,10.0.0.1`, 'ip');
        await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
        const i = await info();
        assertEqual(Object.keys(i.rows[ip].na), ['network', 'prefix', 'location'], 'n/a cells');
        if (lang === 'tr') {
          assert(i.rows[ip].na.prefix.title === 'RIPEstat: hız sınırı — birkaç dakika sonra tekrar deneyin', `TR tooltip: ${i.rows[ip].na.prefix.title}`);
          assertEqual(i.zero, 'Bu adreslerin hiçbiri CDN / proxy arkasında değil.', 'TR sentence');
          assertEqual(i.rows[ip].na.prefix.sr.startsWith('alınamadı: '), true, 'TR screen-reader text');
          if (width > 600) {
            // The CSV mark does not follow the UI language: a script reads the same file either way.
            const [csv] = await exportFiles(page);
            const line = csv.text.split(/\r?\n/).find((l) => l.startsWith(ip));
            assert(/,n\/a,n\/a,n\/a,/.test(line) && !csv.text.includes('alınamadı'), `TR CSV row: ${line}`);
          }
        }
        await assertNoHorizontalScroll(page, `${scheme} ${lang} ${width}`);
        await shot(page, `ip-offline-${width < 600 ? 'mobile' : 'desktop'}-${scheme}-${lang}-failed`);
      });
    }

    await step('nothing left the page; i18n complete; no console errors', async () => {
      assertEqual(netHits, [], 'https requests that reached the network');
      const blocked = await page.evaluate(() => window.__zoneBlocked.slice());
      assertEqual(blocked, [], 'requests the zone script had to block');
      await checkI18n(page);
      await assertClean(page, 'offline');
    });
  } finally {
    await page.setViewport({ width: 1440, height: 900 });
    await page.close();
  }
}

/** The live groups: real resolvers and intel APIs. */
async function liveGroups(browser, server) {
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
    const mine = await page.evaluate(() => document.querySelector('.ipi-stats [data-stat="mine"] .stat-value').textContent);
    assertEqual(mine, '2', 'your servers stat');
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

  await step('a reverse IP lookup cut short by a language switch leaves its button usable (no quota spent)', async () => {
    // Hold the HackerTarget request in the browser (it never leaves: no quota unit is used).
    if (NO_QUOTA_APIS) await page.send('Network.setBlockedURLs', { urls: [] });
    await page.send('Fetch.enable', { patterns: [{ urlPattern: '*hackertarget*', requestStage: 'Request' }] });
    const btn = '[data-action="reverse"][data-ip="9.9.9.9"]';
    try {
      await page.evaluate((sel) => document.querySelector(sel).click(), btn);
      await page.waitFor((sel) => document.querySelector(sel)?.getAttribute('aria-busy') === 'true', { args: [btn], message: 'reverse lookup running' });
      await setLangUi(page, 'tr');
      await page.waitFor(() => document.querySelector('[data-action="run"] .btn-label')?.textContent === 'Sorgula');
      await page.evaluate(() => new Promise((resolve) => { setTimeout(resolve, 300); }));
      const state = await page.evaluate((sel) => {
        const b = document.querySelector(sel);
        return b ? { disabled: b.disabled, busy: b.getAttribute('aria-busy') } : null;
      }, btn);
      assertEqual(state, { disabled: false, busy: null }, 'reverse button after the re-mount');
    } finally {
      await page.send('Fetch.disable');
      if (NO_QUOTA_APIS) await blockQuotaApis(page);
      await setLangUi(page, 'en');
    }
  });

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
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
