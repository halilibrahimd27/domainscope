#!/usr/bin/env node
/**
 * ip.e2e.mjs — end-to-end test of the "IP Intel" view in a real headless browser, against the
 * live RIPEstat / ipwho.is / HackerTarget APIs and DoH (network required).
 *
 *   node tests/e2e/ip.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--no-quota-apis] [--offline]
 *
 * OFFLINE group (always runs; --offline skips the live ones): RIPEstat, ipwho.is, HackerTarget and
 * reverse DNS answered in the page (nothing leaves it). A source that answers 429 or fails marks only the
 * cells it leaves empty "⚠ n/a" (tooltip: which source, what error), a chip per service sums the
 * failures up, and Retry — per row, or per chip for every row it failed on — asks exactly those
 * sources again; a reverse lookup answered SERVFAIL says so; Stop leaves no chip "asking…"; a
 * Retry or a reverse IP answer still in flight when a new lookup starts never draws over the new
 * run's row; Copy summary and the print header link to the rows shown, never to an address
 * carried into the box; the CSV
 * says "n/a" in every language; stat cards with a zero count fold into one sentence; Copy
 * summary says how many lookups failed when every source failed (EN + TR); 1440 and 375 px,
 * light and dark, English and Turkish.
 *
 * OFFLINE enrichment group (always runs): a row's "Routing, RPKI and abuse contact" panel with
 * RIPEstat's routing calls and PeeringDB answered in the page: nothing is sent before Check
 * routing, nor for a private or documentation address; the CIDR breadcrumb lists the saved
 * servers per range; RPKI valid / invalid, MOAS and more-specific flags; a 429 is n/a whose Retry
 * asks only that source; a kept result shows at once after a language re-mount; 1440 and 375 px,
 * light and dark, English and Turkish.
 *
 * OFFLINE group 2, Domains on this IP (ui/reverse-ip-panel.js): HackerTarget, ip.thc.org, OTX, Robtex,
 * InternetDB, Shodan, WhoisXML and DoH answered in the page; names merged and checked (here / moved /
 * CDN / none / failed / workspace only), filters, exports, a private address sending nothing, a
 * 429's Retry, InternetDB's lockout, typed keys never leaking, Check more, a re-mount, phones.
 *
 * OFFLINE Blocklists group (always runs): blocklist answers, refusal codes and test points answered in
 * the page. A row's Blocklists panel sends nothing before its button; documentation and private
 * addresses are never sent; a listing shows its meaning and delist page; a refusal code or a test
 * point that does not come back listed says "cannot check here" (never "not listed") and the address
 * never goes to that list; a failed list has a Retry that asks only it again; Stop asks nothing
 * more; the results survive a row redraw and a language re-mount; 1440, 375 and 320 px, EN + TR.
 *
 * --no-quota-apis blocks ipwho.is and HackerTarget in the browser (their anonymous daily quotas
 * are small): the reverse-IP step then checks the error path instead of spending a unit.
 *
 * Covers: pure helpers (Node); shared link with IPv4, IPv6, a private IP and a host name;
 * PTR / ASN / owner / location / operator columns (incl. the well-known-network hint for
 * 1.1.1.1 and the flag / country-code fallback); inventory matching; private IPs never
 * looked up; one reverse-IP lookup (Domains on this IP: one request per source, 1 HackerTarget quota unit);
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
import { DNSBL_IP_LISTS, DNSBL_DOMAIN_LISTS } from '../../assets/js/lib/dnsbl.js';

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
    await enrichGroup(browser, server);
    await reverseIpGroup(browser, server);
    await blocklistGroup(browser, server);
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
 * RIPEstat, ipwho.is and HackerTarget answered in the page (installed after the zone script, which blocks
 * every other request): addresses in `window.__ipFake.limited` when the request is made get
 * HTTP 429 from RIPEstat, an address in `window.__ipFake.slow` (ip → ms) is answered that much
 * later (an abort still ends the wait), and ipwho.is always says its quota is used up. HackerTarget's
 * reverse IP names two domains, `window.__ipFake.htDelay` ms later. `calls` lists "<dataset> <ip>" per
 * request.
 */
const IP_FAKE_SCRIPT = `(() => {
  const inner = window.fetch;
  const fake = window.__ipFake = { limited: [], calls: [], slow: {}, htDelay: 0 };
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
    if (u.hostname === 'api.hackertarget.com') {
      fake.calls.push('hackertarget ' + u.searchParams.get('q'));
      if (fake.htDelay) await wait(fake.htDelay, (init && init.signal) || null);
      return new Response('site-a.example.org\\nsite-b.example.org\\n', { status: 200, headers: { 'content-type': 'text/plain' } });
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
        // The table redraws the settled rows in its next frame, the one that first paints "Look up":
        // read the page as that frame shows it, not in between.
        await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
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

    await step('under an address carried over from another tool, Copy summary and the print header link to the rows shown, never the box', async () => {
      await page.evaluate(() => { window.__ipFake.limited = []; });
      await gotoHash(page, '#/ip?ips=203.0.113.7', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      await gotoHash(page, '#/about', 'about');
      // Another tool's target (run=0): the kept rows come back and only the box takes the address.
      await gotoHash(page, '#/ip?ips=198.51.100.20&run=0', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'kept rows shown' });
      const shown = await page.evaluate(() => ({
        rows: [...document.querySelectorAll('.ipi-row .ipi-ip')].map((e) => e.textContent),
        box: document.querySelector('[data-role="ip-input"]').value.trim()
      }));
      assertEqual(shown, { rows: ['203.0.113.7'], box: '198.51.100.20' }, 'the kept rows under the carried address');
      const header = await page.evaluate(async () => (await import('./assets/js/ui/summary-button.js')).resultPermalink(document.querySelector('#page-body')));
      assert(header && header.endsWith('#/ip?ips=203.0.113.7'), `print header link: ${header}`);
      await stubClipboard(page);
      await page.click('[data-summary="ip"] [data-action="copy-summary"]');
      await page.waitFor(() => window.__clip.length === 1, { message: 'summary copied' });
      const [md] = await takeClipboard(page);
      assert(md.startsWith('**IP Intel · `203.0.113.7`**') && md.trim().endsWith('#/ip?ips=203.0.113.7'), `summary: ${md}`);
    });

    await step('the header’s Copy link leaves out private and inventory addresses, as Copy summary’s link does', async () => {
      await page.evaluate(async () => {
        (await import('./assets/js/state.js')).state.setInventory('origin-web 198.51.100.20\n');
        window.__ipFake.limited = [];
      });
      try {
        await gotoHash(page, '#/about', 'about');
        await gotoHash(page, `#/ip?ips=${IPS}`, 'ip');
        await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows shown' });
        await page.evaluate(() => document.querySelector('[data-action="run"]').click());
        await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
        await stubClipboard(page);
        await page.evaluate(() => document.querySelector('.page-actions .copy-btn').click());
        await page.waitFor(() => window.__clip.length === 1, { message: 'link copied' });
        const [link] = await takeClipboard(page);
        assertEqual(new URL(link).hash, '#/ip?ips=203.0.113.7', 'the header’s Copy link');
        const summary = await page.evaluate(async () => (await import('./assets/js/ui/summary-button.js')).resultPermalink(document.querySelector('#page-body')));
        assertEqual(new URL(summary).hash, '#/ip?ips=203.0.113.7', 'Copy summary’s link');
      } finally {
        await page.evaluate(async () => { (await import('./assets/js/state.js')).state.clearInventory(); });
      }
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

/* ------------------------------------------------------------------------ */
/* Offline: a row's routing, RPKI and abuse contact panel                   */
/* ------------------------------------------------------------------------ */

/**
 * RIPEstat's network-info, rpki-validation, routing-status and abuse-contact-finder and PeeringDB,
 * answered in the page (installed last: the outermost fetch wrapper; prefix-overview stays with
 * IP_FAKE_SCRIPT, which gives every address its /24 and AS64500). 193.0.6.0/24 is clean and RPKI
 * valid; 8.8.8.0/24 is announced by two origins with a more-specific route and an RPKI ROA for
 * another AS. A call named in `window.__enrichFake.limited` answers 429. `calls` lists
 * "<call> <resource or asn> [prefix]" per request.
 */
const ENRICH_FAKE_SCRIPT = `(() => {
  const inner = window.fetch;
  const fake = window.__enrichFake = { limited: [], calls: [] };
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const ok = (data) => json({ status: 'ok', data_call_status: 'supported', data });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const u = new URL(url, location.href);
    const call = u.hostname === 'www.peeringdb.com' ? 'peeringdb' : u.hostname === 'stat.ripe.net' ? u.pathname.split('/')[2] : null;
    if (!['network-info', 'rpki-validation', 'routing-status', 'abuse-contact-finder', 'peeringdb'].includes(call)) return inner(input, init);
    const what = u.searchParams.get('resource') || u.searchParams.get('asn');
    const prefix = u.searchParams.get('prefix');
    fake.calls.push(call + ' ' + what + (prefix ? ' ' + prefix : ''));
    if (fake.limited.includes(call)) return new Response('Too Many Requests', { status: 429 });
    const v8 = (what + (prefix || '')).includes('8.8.8.');
    if (call === 'rpki-validation') {
      return ok(v8
        ? { resource: '64500', prefix, status: 'invalid_asn', validator: 'routinator', validating_roas: [{ origin: '64501', prefix: '8.8.8.0/24', max_length: 24, validity: 'invalid_asn' }] }
        : { resource: '64500', prefix, status: 'valid', validator: 'routinator', validating_roas: [{ origin: '64500', prefix: '193.0.6.0/24', max_length: 24, validity: 'valid' }] });
    }
    if (call === 'routing-status') {
      return ok({
        resource: what, first_seen: { prefix: what, origin: '64500', time: '2004-05-06T08:00:00' },
        visibility: { v4: { ris_peers_seeing: 98, total_ris_peers: 98 }, v6: { ris_peers_seeing: 0, total_ris_peers: 0 } },
        origins: v8 ? [{ origin: 64500 }, { origin: 64501 }] : [{ origin: 64500 }],
        more_specifics: v8 ? [{ prefix: '8.8.8.0/25', origin: 64501 }] : [], less_specifics: []
      });
    }
    if (call === 'abuse-contact-finder') return ok({ abuse_contacts: ['abuse@example.net'], authoritative_rir: 'ripe' });
    if (call === 'network-info') return ok({ asns: ['64500'], prefix: what.split('.').slice(0, 3).join('.') + '.0/24' });
    return what === '64500'
      ? json({ data: [{ id: 1001, asn: 64500, name: 'Example Networks', website: 'https://www.example.net/', info_type: 'Content', info_types: ['Content'], info_scope: 'Global', policy_general: 'Selective' }], meta: {} })
      : json({ data: [], meta: { error: 'Entity not found' } }, 404);
  };
})();`;

/** The panel of the row of `ip` (its details opened): state, crumbs, the chosen range's servers, n/a marks. */
function enrichInfo(ip) {
  const slot = document.querySelector(`.ipi-enrich[data-ip="${ip}"]`);
  if (!slot) return null;
  return {
    state: slot.dataset.state,
    text: slot.textContent.replace(/\s+/g, ' '),
    check: !!slot.querySelector('[data-action="enrich"]'),
    retry: slot.querySelector('[data-enrich-retry]')?.dataset.sources || null,
    crumbs: [...slot.querySelectorAll('.ipe-crumb')].map((b) => `${b.dataset.cidr}=${b.dataset.count}${b.getAttribute('aria-pressed') === 'true' ? '*' : ''}`),
    servers: [...slot.querySelectorAll('.ipe-server-list li')].map((li) => li.textContent.replace(/\s+/g, ' ').trim()),
    na: [...slot.querySelectorAll('.na-mark')].map((m) => ({ sources: m.dataset.na, title: m.title })),
    rpki: [...slot.querySelectorAll('.ipe-rpki-row')].map((r) => `${r.dataset.asn}:${r.dataset.status}`),
    flags: slot.querySelector('.ipe-routing')?.dataset.flags ?? null
  };
}

/** Open the details of the row of `ip` (once) and wait for its panel. */
async function openEnrich(page, ip) {
  await page.evaluate((x) => {
    const row = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === x);
    if (row.querySelector('.dt-expand-btn').getAttribute('aria-expanded') !== 'true') row.querySelector('.dt-expand-btn').click();
  }, ip);
  await page.waitFor((x) => !!document.querySelector(`.ipi-enrich[data-ip="${x}"] .ipe-head`), { args: [ip], timeout: 15000, message: `panel of ${ip}` });
}

async function enrichGroup(browser, server) {
  group('Offline: a row’s routing, RPKI and abuse contact (RIPEstat and PeeringDB answered in the page)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const netHits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript('in-addr.arpa', PTR_ZONE) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: IP_FAKE_SCRIPT });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: ENRICH_FAKE_SCRIPT });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  const calls = () => page.evaluate(() => window.__enrichFake.calls.slice());
  const panel = (ip) => page.evaluate(enrichInfo, ip);
  try {
    await step('the panel sends nothing before “Check routing”; the breadcrumb lists your servers per range', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await page.evaluate(async () => {
        (await import('./assets/js/state.js')).state.setInventory('web-1 193.0.6.139\nweb-2 193.0.6.140\nedge 193.0.0.10\nlan-box 10.0.0.1\n');
      });
      await gotoHash(page, '#/ip?ips=193.0.6.139,8.8.8.8,10.0.0.1,192.0.2.10', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      await openEnrich(page, '193.0.6.139');
      const p = await panel('193.0.6.139');
      assertEqual([p.state, p.check], ['idle', true], 'idle, with its button');
      assert(p.text.includes('Nothing has been sent yet.') && p.text.includes('PeeringDB'), `privacy note: ${p.text}`);
      assertEqual(await calls(), [], 'no enrichment request before the click');
      // The narrowest range that holds another of your servers is chosen.
      assertEqual(p.crumbs, ['193.0.0.0/8=3', '193.0.0.0/16=3', '193.0.6.0/24=2*', '193.0.6.139/32=1'], 'crumbs with server counts');
      assertEqual(p.servers, ['web-1 193.0.6.139 this address', 'web-2 193.0.6.140'], 'servers in the /24');
      await page.evaluate(() => document.querySelector('.ipi-enrich[data-ip="193.0.6.139"] .ipe-crumb[data-cidr="193.0.0.0/16"]').click());
      const wide = await panel('193.0.6.139');
      assertEqual(wide.servers, ['web-1 193.0.6.139 this address', 'edge 193.0.0.10', 'web-2 193.0.6.140'], 'servers in the /16: this address first, then by name');
      assertEqual(wide.crumbs.filter((c) => c.endsWith('*')), ['193.0.0.0/16=3*'], 'one crumb pressed');
    });

    await step('Check routing: prefix and origin, RPKI valid with its ROA, clean routing, abuse contact, PeeringDB', async () => {
      await page.evaluate(() => document.querySelector('.ipi-enrich[data-ip="193.0.6.139"] [data-action="enrich"]').click());
      await page.waitFor(() => document.querySelector('.ipi-enrich[data-ip="193.0.6.139"]')?.dataset.state === 'done', { timeout: 15000, message: 'enriched' });
      assertEqual((await calls()).sort(), ['abuse-contact-finder 193.0.6.139', 'peeringdb 64500', 'routing-status 193.0.6.0/24', 'rpki-validation AS64500 193.0.6.0/24'],
        'the row’s prefix and origin were used: no network-info');
      const p = await panel('193.0.6.139');
      assertEqual([p.rpki, p.flags, p.na, p.retry, p.check], [['64500:valid'], '', [], null, false], 'valid, clean, nothing failed');
      for (const s of ['193.0.6.0/24', 'Origin AS AS64500', 'ROA 193.0.6.0/24 · max length /24 · AS64500', 'One origin, seen by 98 of 98 RIS peers', 'abuse@example.net', 'registered at RIPE NCC', 'Example Networks', 'Content', 'peering: Selective']) {
        assert(p.text.includes(s), `panel text has “${s}”: ${p.text}`);
      }
      assertEqual(p.servers, ['web-1 193.0.6.139 this address', 'edge 193.0.0.10', 'web-2 193.0.6.140'], `the chosen range is kept (${p.crumbs.join(' ')})`);
    });

    await step('an invalid origin, MOAS and a more-specific route are flagged; a 429 is n/a whose Retry asks only that source', async () => {
      await page.evaluate(() => { window.__enrichFake.limited = ['abuse-contact-finder']; window.__enrichFake.calls = []; });
      await openEnrich(page, '8.8.8.8');
      await page.evaluate(() => document.querySelector('.ipi-enrich[data-ip="8.8.8.8"] [data-action="enrich"]').click());
      await page.waitFor(() => document.querySelector('.ipi-enrich[data-ip="8.8.8.8"]')?.dataset.state === 'done', { timeout: 15000, message: 'enriched' });
      const p = await panel('8.8.8.8');
      assertEqual([p.rpki, p.flags], [['64500:invalid-asn'], 'moas more-specifics'], 'RPKI and routing flags');
      assert(p.text.includes('Announced by AS64500, AS64501 (MOAS)') && p.text.includes('8.8.8.0/25 (AS64501)'), `flags explained: ${p.text}`);
      assert(p.text.includes('networks that validate RPKI drop this route'), `invalid explained: ${p.text}`);
      assertEqual(p.na, [{ sources: 'ripestat-abuse', title: 'RIPEstat (abuse contact): rate limited — try again in a few minutes' }], 'the abuse contact is n/a, with its reason');
      assertEqual(p.retry, 'ripestat-abuse', 'Retry asks only the failed source');
      await page.evaluate(() => { window.__enrichFake.limited = []; window.__enrichFake.calls = []; });
      // With the keyboard: the focus stays in the panel when the Retry it pressed is replaced.
      await page.evaluate(() => document.querySelector('.ipi-enrich[data-ip="8.8.8.8"] [data-enrich-retry]').focus());
      await page.press('Enter');
      await page.waitFor(() => (document.querySelector('.ipi-enrich[data-ip="8.8.8.8"]')?.textContent || '').includes('abuse@example.net'), { timeout: 15000, message: 'abuse contact after Retry' });
      assertEqual(await calls(), ['abuse-contact-finder 8.8.8.8'], 'requests of the Retry');
      const after = await panel('8.8.8.8');
      assertEqual([after.na, after.retry], [[], null], 'nothing n/a any more');
      const focus = await page.evaluate(() => (document.activeElement && document.activeElement.closest('.ipi-enrich') ? document.activeElement.className : null));
      assertEqual(focus, 'ipe-title', 'keyboard focus on the panel’s title, not dropped to the page');
    });

    await step('a private or documentation address: the panel says nothing is sent, the breadcrumb still works', async () => {
      await page.evaluate(() => { window.__enrichFake.calls = []; });
      await openEnrich(page, '10.0.0.1');
      const p = await panel('10.0.0.1');
      assertEqual([p.state, p.check], ['not-routable', false], 'not routable: no button');
      assert(p.text.includes('Not a globally routable address'), `note: ${p.text}`);
      // No other server in any range: the /24 is chosen.
      assertEqual(p.crumbs, ['10.0.0.0/8=1', '10.0.0.0/16=1', '10.0.0.0/24=1*', '10.0.0.1/32=1'], 'the address’s own server only');
      await openEnrich(page, '192.0.2.10');
      assertEqual((await panel('192.0.2.10')).state, 'not-routable', 'documentation space');
      assertEqual(await calls(), [], 'nothing asked for either');
    });

    for (const [scheme, lang, width] of [['dark', 'tr', 1440], ['light', 'en', 375], ['dark', 'tr', 375]]) {
      await step(`[${scheme}, ${lang.toUpperCase()}, ${width} px] a kept result shows at once after a re-mount, reads well and fits`, async () => {
        await page.setViewport(width < 600 ? { width, height: 812, mobile: true } : { width, height: 900 });
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await setLangUi(page, lang);
        await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows kept' });
        const before = (await calls()).length;
        await openEnrich(page, '193.0.6.139');
        const p = await panel('193.0.6.139');
        assertEqual([p.state, (await calls()).length - before], ['done', 0], 'the kept result, no new request');
        if (lang === 'tr') {
          for (const s of ['Yönlendirme, RPKI ve abuse iletişimi', 'Geçerli', 'en fazla /24', 'Tek kaynak; 98 RIS eşinden 98 tanesi görüyor', 'kayıt: RIPE NCC', 'İçerik', 'içindeki sunucularınız']) {
            assert(p.text.includes(s), `TR panel text has “${s}”: ${p.text}`);
          }
        }
        await page.evaluate(() => document.querySelector('.ipi-enrich[data-ip="193.0.6.139"]').scrollIntoView());
        await assertNoHorizontalScroll(page, `enrich ${scheme} ${lang} ${width}`);
        await shot(page, `ip-enrich-${width < 600 ? 'mobile' : 'desktop'}-${scheme}-${lang}`);
      });
    }

    await step('“Delete all local data” forgets which addresses were checked: the panel is idle again, nothing sent', async () => {
      await page.evaluate(async () => { await (await import('./assets/js/state.js')).state.clearAll(); });
      await gotoHash(page, '#/about', 'about');
      await gotoHash(page, '#/ip?ips=193.0.6.139', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'row looked up' });
      const before = (await calls()).length;
      await openEnrich(page, '193.0.6.139');
      const p = await panel('193.0.6.139');
      assertEqual([p.state, p.check, (await calls()).length - before], ['idle', true, 0], 'no kept answer, no request');
    });

    await step('nothing left the page; i18n complete; no console errors', async () => {
      assertEqual(netHits, [], 'https requests that reached the network');
      assertEqual(await page.evaluate(() => window.__zoneBlocked.slice()), [], 'requests the zone script had to block');
      await checkI18n(page);
      await assertClean(page, 'enrich');
    });
  } finally {
    await page.setViewport({ width: 1440, height: 900 });
    await page.close();
  }
}

/* ------------------------------------------------------------------------ */
/* Offline: Domains on this IP (ui/reverse-ip-panel.js, lib/reverseip.js)   */
/* ------------------------------------------------------------------------ */

/** Made-up API keys, built from pieces so that no file holds anything key-shaped. */
const RIP_SHODAN_KEY = ['e2e', 'shodan', 'made', 'up'].join('-');
const RIP_WHOIS_KEY = ['e2e', 'whois', 'made', 'up'].join('-');

/** DNS of the reverse-IP group: the PTR of 203.0.113.10 and the names its sources give (A / AAAA, a SERVFAIL). */
const RIP_DNS = {
  '10.113.0.203.in-addr.arpa': { PTR: ['host-10.example.net'] },
  'host-10.example.net': { A: ['203.0.113.10'] },
  'www.example.com': { A: ['203.0.113.10'] },
  'blog.example.com': { A: ['203.0.113.10'], AAAA: ['2001:db8::10'] },
  'shop.example.net': { A: ['192.0.2.1'] },
  'cdn.example.org': { A: ['104.16.5.5'] },
  'mail.example.org': { RCODE: { A: 'SERVFAIL', AAAA: 'SERVFAIL' } },
  'web.example.com': { A: ['198.51.100.30'] },
  'whois.example.com': { A: ['198.51.100.30'] }
};

/**
 * Domains on this IP answered in the page: a fake DoH for every name of `window.__rip.dns` (anything
 * else NXDOMAIN), RIPEstat / ipwho.is for the row lookup, and HackerTarget, ip.thc.org, OTX, Robtex,
 * InternetDB, Shodan and WhoisXML from `window.__rip.data[ip]`. `otx429` / `idb429` make those answer
 * 429; `calls` lists "<host> <ip>" per request, `dnsNames` every name asked, `blocked` anything else.
 */
const RIP_FAKE_SCRIPT = (dns) => `(() => {
  const realFetch = window.fetch.bind(window);
  const fake = window.__rip = { dns: ${JSON.stringify(dns)}, data: {}, calls: [], dnsNames: [], blocked: [], otx429: [], idb429: false, slow: 0,
    shodanKey: ${JSON.stringify(RIP_SHODAN_KEY)}, whoisKey: ${JSON.stringify(RIP_WHOIS_KEY)} };
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const text = (body, status = 200, type = 'text/plain') => new Response(body, { status, headers: { 'content-type': type } });
  const SOA = { mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
  let wire = null;
  const answer = (name, type) => {
    const node = fake.dns[name];
    if (!node) return { rcode: 'NXDOMAIN', answers: [], authorities: [{ name: 'example.com', type: 'SOA', ttl: 300, data: SOA }] };
    if (node.RCODE && node.RCODE[type]) return { rcode: node.RCODE[type], answers: [], authorities: [] };
    const answers = (node[type] || []).map((data) => ({ name, type, ttl: 300, data }));
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: 'example.com', type: 'SOA', ttl: 300, data: SOA }] };
  };
  const data = (ip) => fake.data[ip] || {};
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const u = new URL(url, location.href);
    if (u.origin === location.origin) return realFetch(input, init);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (m) {
      wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
      const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
      const name = String(q.name).toLowerCase().replace(/[.]$/, '');
      if (!fake.dnsNames.includes(name)) fake.dnsNames.push(name);
      const out = answer(name, q.type);
      return new Response(wire.encodeMessage({ id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
        questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities, edns: {} }), { headers: { 'content-type': 'application/dns-message' } });
    }
    const host = u.hostname;
    if (host === 'stat.ripe.net') {
      const ip = u.searchParams.get('resource');
      if (u.pathname.includes('prefix-overview')) return json({ status: 'ok', data: { announced: true, asns: [{ asn: 64500, holder: 'EXAMPLE-NET - Example Networks B.V.' }], resource: ip + '/32', block: { desc: 'Administered by RIPE NCC' } } });
      return json({ status: 'ok', data: { located_resources: [{ locations: [{ country: 'NL', city: 'Amsterdam', covered_percentage: 100 }] }] } });
    }
    if (host === 'ipwho.is') return json({ success: false, message: 'You have exceeded the rate limit' });
    if (host === 'api.hackertarget.com') {
      const ip = u.searchParams.get('q');
      fake.calls.push('hackertarget ' + ip);
      return text((data(ip).ht || []).join('\\n') || 'No DNS A records found');
    }
    if (host === 'ip.thc.org') {
      const body = JSON.parse((init && init.body) || '{}');
      fake.calls.push('thc ' + body.ip_address);
      const list = data(body.ip_address).thc || [];
      return json({ matching_records: list.length, domains: list.map((domain) => ({ domain })), next_page_state: '' });
    }
    if (host === 'otx.alienvault.com') {
      const ip = u.pathname.split('/')[5];
      fake.calls.push('otx ' + ip);
      const sig = (init && init.signal) || null;
      if (fake.slow) {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(resolve, fake.slow);
          if (sig) sig.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
        });
      }
      if (fake.otx429.includes(ip)) return text('Too Many Requests', 429);
      const list = data(ip).otx || [];
      return json({ passive_dns: list.map((hostname) => ({ address: ip, hostname, first: '2025-01-01T00:00:00', last: '2026-10-03T07:53:19', record_type: 'A' })), count: list.length });
    }
    if (host === 'freeapi.robtex.com') {
      const ip = u.pathname.split('/')[3];
      fake.calls.push('robtex ' + ip);
      return text((data(ip).robtex || []).map((rrname) => JSON.stringify({ rrname, rrdata: ip, rrtype: 'A', time_first: 1700000000, time_last: 1790000000, count: 1 })).join('\\n'), 200, 'application/x-ndjson');
    }
    if (host === 'internetdb.shodan.io') {
      const ip = u.pathname.slice(1);
      fake.calls.push('internetdb ' + ip);
      if (fake.idb429) return json({ detail: 'Too Many Requests' }, 429);
      const d = data(ip).idb;
      return d ? json({ ip, cpes: [], hostnames: d.hostnames || [], ports: d.ports || [], tags: d.tags || [], vulns: d.vulns || [] }) : json({ detail: 'No information available' }, 404);
    }
    if (host === 'api.shodan.io') {
      const ip = u.pathname.split('/')[3];
      fake.calls.push('shodan ' + ip);
      if (u.searchParams.get('key') !== fake.shodanKey) return text('401 Unauthorized', 401);
      return json({ ip_str: ip, hostnames: data(ip).shodan || [], domains: [], ports: [443] });
    }
    if (host === 'reverse-ip.whoisxmlapi.com') {
      const ip = u.searchParams.get('ip');
      fake.calls.push('whoisxml ' + ip);
      if (u.searchParams.get('apiKey') !== fake.whoisKey) return json({ code: 403, messages: 'Access restricted.' }, 403);
      const list = data(ip).whois || [];
      return json({ current_page: '0', size: list.length, result: list.map((name) => ({ name, first_seen: 1700000000, last_visit: 1780000000 })) });
    }
    fake.blocked.push(url);
    throw new TypeError('blocked by the E2E (Domains on this IP)');
  };
})();`;

/** The panel as the user sees it: rows by name, chips by source, notes, facts, the Check more line, hand-offs. */
function ripInfo() {
  const panel = document.querySelector('.rip-panel');
  if (!panel) return null;
  const rows = {};
  for (const tr of panel.querySelectorAll('.rip-row')) {
    const name = tr.querySelector('.rip-name')?.textContent;
    rows[name] = {
      status: tr.querySelector('[data-status]')?.dataset.status || null,
      sources: tr.querySelector('.rip-sources')?.dataset.sources || '',
      domain: tr.querySelector('td.rip-col-domain')?.textContent || '',
      resolves: tr.querySelector('td.rip-col-resolves')?.textContent.replace(/\s+/g, ' ').trim() || '',
      first: tr.querySelector('td.rip-col-first time')?.getAttribute('datetime') || null
    };
  }
  const run = panel.querySelector('[data-action="rip-run"]');
  return {
    rows,
    count: panel.querySelectorAll('.rip-row').length,
    chips: Object.fromEntries([...panel.querySelectorAll('.rip-chip')].map((c) => [c.dataset.source, {
      state: c.dataset.state, skip: c.dataset.skip, value: c.querySelector('.src-chip-value')?.textContent || '', retry: !!c.querySelector('[data-action="retry-source"]'), title: c.title
    }])),
    notes: [...panel.querySelectorAll('.rip-notes > *')].map((a) => a.textContent.replace(/\s+/g, ' ').trim()),
    facts: [...panel.querySelectorAll('.rip-facts > *')].map((a) => a.textContent.replace(/\s+/g, ' ').trim()),
    done: !!(run && !run.hidden && !panel.querySelector('.rip-chip[data-state="pending"]') && panel.querySelector('.rip-progress').hidden),
    more: panel.querySelector('.rip-more') && !panel.querySelector('.rip-more').hidden ? panel.querySelector('[data-action="rip-more"]').textContent.trim() : null,
    handoffs: [...panel.querySelectorAll('[data-handoff]')].map((a) => [a.dataset.handoff, a.getAttribute('href')])
  };
}

/** The CSV and JSON exports of the panel's table, captured in the page: [{ name, text }] (CSV first). */
function ripExports(page) {
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
      document.querySelector('.rip-panel [data-export="csv"]').click();
      document.querySelector('.rip-panel [data-export="json"]').click();
    } finally {
      URL.createObjectURL = origCreate;
      HTMLAnchorElement.prototype.click = origClick;
    }
    return Promise.all(captured.map(async (f) => ({ name: f.name, text: await f.blob.text() })));
  });
}

async function reverseIpGroup(browser, server) {
  group('Offline: Domains on this IP (every source answered in the page)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  // A visible tab: the table draws its updates on animation frames.
  await page.send('Page.bringToFront');
  const netHits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: RIP_FAKE_SCRIPT(RIP_DNS) });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  const rip = () => page.evaluate(ripInfo);
  const calls = () => page.evaluate(() => window.__rip.calls.slice());
  const waitRip = async (message) => {
    await page.waitFor(() => {
      const p = document.querySelector('.rip-panel');
      const b = p && p.querySelector('[data-action="rip-run"]');
      return !!(b && !b.hidden && p.querySelector('.rip-results') && !p.querySelector('.rip-results').hidden
        && !p.querySelector('.rip-chip[data-state="pending"]') && p.querySelector('.rip-progress').hidden);
    }, { timeout: 30000, message });
    // The table draws on the next animation frames (with a timeout: a hidden tab gets none).
    await page.evaluate(() => new Promise((resolve) => {
      const done = setTimeout(resolve, 500);
      requestAnimationFrame(() => requestAnimationFrame(() => { clearTimeout(done); resolve(); }));
    }));
  };
  const runPanel = async (ips) => {
    await page.evaluate((text) => {
      const box = document.querySelector('[data-role="rip-addresses"]');
      box.value = text;
      document.querySelector('[data-action="rip-run"]').click();
    }, ips);
    await waitRip(`lookup of ${ips}`);
  };
  try {
    await step('Find domains on a public address: every source asked once, names merged, checked in DNS now', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await page.evaluate(async () => {
        const { state } = await import('./assets/js/state.js');
        state.setInventory('web01 203.0.113.10\nlan-box 10.0.0.5\n');
        state.setWorkspaceData('origins', { v: 1, remember: true, entries: [
          { name: 'origin.example.com', ip: '203.0.113.10', port: 443, source: 'manual', firstSeen: '2026-09-01T00:00:00Z', lastConfirmed: '2026-10-01T00:00:00Z' },
          { name: 'intranet-app.example.com', ip: '10.0.0.5', port: 443, source: 'manual', firstSeen: '2026-09-01T00:00:00Z', lastConfirmed: '2026-10-01T00:00:00Z' }
        ] });
        window.__rip.data['203.0.113.10'] = {
          ht: ['www.example.com', 'blog.example.com'], thc: ['api.example.com'], otx: ['www.example.com', 'shop.example.net', '203.0.113.10'],
          robtex: ['WWW.Example.com.', 'gone.example.com'], idb: { hostnames: ['cdn.example.org', '*.mail.example.org'], ports: [443, 80], tags: ['cloud'], vulns: ['CVE-2026-0001'] }
        };
      });
      await gotoHash(page, '#/ip?ips=203.0.113.10,10.0.0.5', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      assertEqual(await calls(), [], 'nothing asked before a click');
      await page.evaluate(() => document.querySelector('[data-action="reverse"][data-ip="203.0.113.10"]').click());
      await waitRip('reverse lookup');
      const i = await rip();
      const st = Object.fromEntries(Object.entries(i.rows).map(([n, r]) => [n, r.status]));
      assertEqual(st, {
        'api.example.com': 'none', 'blog.example.com': 'here', 'gone.example.com': 'none', 'origin.example.com': 'workspace', 'www.example.com': 'here',
        'host-10.example.net': 'here', 'shop.example.net': 'moved', 'cdn.example.org': 'cdn', 'mail.example.org': 'failed'
      }, 'status of every name (sortHostnames order)');
      assertEqual(Object.keys(i.rows), ['api.example.com', 'blog.example.com', 'gone.example.com', 'origin.example.com', 'www.example.com', 'host-10.example.net', 'shop.example.net', 'cdn.example.org', 'mail.example.org'], 'one row per name, junk dropped');
      assertEqual(i.rows['www.example.com'].sources, 'hackertarget otx robtex', 'per-name sources');
      assertEqual(i.rows['www.example.com'].domain, 'example.com', 'registrable domain');
      assertEqual(i.rows['www.example.com'].first, '2023-11-14T22:13:20.000Z', 'first seen: the earliest sighting (Robtex)');
      assert(/192\.0\.2\.1/.test(i.rows['shop.example.net'].resolves), `moved: where to (${i.rows['shop.example.net'].resolves})`);
      assertEqual(i.rows['host-10.example.net'].sources, 'ptr', 'the PTR name, forward-confirmed');
      assertEqual((await calls()).sort(), ['hackertarget 203.0.113.10', 'internetdb 203.0.113.10', 'otx 203.0.113.10', 'robtex 203.0.113.10', 'thc 203.0.113.10'], 'one request per source');
      const names = await page.evaluate(() => window.__rip.dnsNames.slice());
      assert(!names.includes('origin.example.com'), 'a name only the workspace knows is never sent');
      const chips = Object.fromEntries(Object.entries(i.chips).map(([s, c]) => [s, [c.state, c.value]]));
      assertEqual(chips, {
        workspace: ['ok', '1 name'], ptr: ['ok', '1 name'], hackertarget: ['ok', '2 names'], thc: ['ok', '1 name'], otx: ['ok', '2 names'],
        robtex: ['ok', '2 names'], internetdb: ['ok', '2 names'], shodan: ['idle', 'add a key to ask'], whoisxml: ['idle', 'add a key to ask']
      }, 'one chip per source');
      assert(/About 50 lookups a day/.test(i.chips.hackertarget.title), 'the HackerTarget quota note');
      assert(i.facts.includes('Your servers on 203.0.113.10: web01'), `servers: ${i.facts}`);
      assert(i.facts.includes('203.0.113.10 · Shodan InternetDB: open ports 80, 443 · tags cloud · 1 known vulnerability'), `InternetDB facts: ${i.facts}`);
      const cell = await page.evaluate(() => {
        const tr = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === '203.0.113.10');
        const rev = tr.querySelector('.ipi-rev');
        return rev ? [rev.dataset.state, rev.dataset.count] : null;
      });
      assertEqual(cell, ['done', '9'], 'the row keeps the count (and the first names) as before');
      assertEqual(i.handoffs.map(([k]) => k), ['subdomains', 'subdomains', 'subdomains', 'scan', 'retire'], 'hand-offs');
      assert(i.handoffs.some(([k, href]) => k === 'subdomains' && /domain=example\.com/.test(href) && /run=0/.test(href)), `Subdomains link: ${JSON.stringify(i.handoffs)}`);
      assert(i.handoffs.some(([k, href]) => k === 'retire' && /ips=203\.0\.113\.10/.test(href)), 'Retire an IP link');
      await assertNoHorizontalScroll(page, 'reverse IP desktop');
      await shot(page, 'ip-reverse-desktop-light-en');
    });

    await step('filters by status and source, and the CSV / JSON exports', async () => {
      const shown = async (status, source) => page.evaluate(([a, b]) => {
        const set = (role, v) => {
          const s = document.querySelector(`[data-role="${role}"]`);
          s.value = v;
          s.dispatchEvent(new Event('change', { bubbles: true }));
        };
        set('rip-filter-status', a);
        set('rip-filter-source', b);
        return [...document.querySelectorAll('.rip-panel .rip-row .rip-name')].map((n) => n.textContent);
      }, [status, source]);
      assertEqual(await shown('here', ''), ['blog.example.com', 'www.example.com', 'host-10.example.net'], 'status: here now');
      assertEqual(await shown('', 'robtex'), ['gone.example.com', 'www.example.com'], 'source: Robtex');
      assertEqual(await shown('none', 'robtex'), ['gone.example.com'], 'both');
      assertEqual((await shown('', '')).length, 9, 'All again');
      const files = await ripExports(page);
      assert(files.length === 2 && files.every((f) => /^reverse-ip/.test(f.name)), `file names: ${files.map((f) => f.name)}`);
      const json = JSON.parse(files[1].text);
      const www = json.find((r) => r.name === 'www.example.com');
      assertEqual([www.status, www.domain, www.sources, www.addresses], ['here', 'example.com', ['hackertarget', 'otx', 'robtex'], ['203.0.113.10']], 'JSON row');
      assert(/^name,|"name"|Name/.test(files[0].text.split(/\r?\n/)[0]), `CSV header: ${files[0].text.split(/\r?\n/)[0]}`);
      assert(files[0].text.includes('shop.example.net') && files[0].text.includes('moved'), 'CSV rows carry the status code');
    });

    await step('a private address: only the workspace, nothing sent (no request, no PTR question)', async () => {
      const before = (await calls()).length;
      const dnsBefore = await page.evaluate(() => window.__rip.dnsNames.slice());
      await page.evaluate(() => document.querySelector('[data-action="reverse"][data-ip="10.0.0.5"]').click());
      await waitRip('private lookup');
      const i = await rip();
      assertEqual((await calls()).length, before, 'no third-party request');
      const dnsAfter = await page.evaluate(() => window.__rip.dnsNames.slice());
      assertEqual(dnsAfter.filter((n) => !dnsBefore.includes(n)), [], 'no DNS question either');
      assert(i.notes.some((n) => /10\.0\.0\.5 is a private or reserved address: only what your workspace knows is shown, and nothing was sent/.test(n)), `note: ${i.notes}`);
      assertEqual(Object.fromEntries(Object.entries(i.rows).map(([n, r]) => [n, r.status])), { 'intranet-app.example.com': 'workspace' }, 'the workspace name, never sent');
      assertEqual(Object.entries(i.chips).filter(([, c]) => c.skip === 'local').map(([s]) => s), ['ptr', 'hackertarget', 'thc', 'otx', 'robtex', 'internetdb', 'shodan', 'whoisxml'], 'every other source: not asked');
      assert(i.facts.includes('Your servers on 10.0.0.5: lan-box'), `servers: ${i.facts}`);
    });

    await step('a failed source is "n/a" with the reason; its Retry asks only it again', async () => {
      await page.evaluate(() => {
        window.__rip.otx429 = ['198.51.100.20'];
        window.__rip.data['198.51.100.20'] = { otx: ['retry.example.com'], ht: ['web.example.com'] };
      });
      await runPanel('198.51.100.20');
      let i = await rip();
      assertEqual([i.chips.otx.state, i.chips.otx.retry], ['failed', true], 'OTX chip failed, with a Retry');
      assert(/^n\/a · rate limited — try again later/.test(i.chips.otx.value), `OTX chip: ${i.chips.otx.value}`);
      assert(/AlienVault OTX: rate limited/.test(i.chips.otx.title), `tooltip: ${i.chips.otx.title}`);
      const before = (await calls()).length;
      await page.evaluate(() => { window.__rip.otx429 = []; });
      await page.evaluate(() => document.querySelector('.rip-chip[data-source="otx"] [data-action="retry-source"]').click());
      await page.waitFor(() => document.querySelector('.rip-chip[data-source="otx"]')?.dataset.state === 'ok', { timeout: 15000, message: 'OTX answered' });
      await waitRip('after the Retry');
      assertEqual((await calls()).slice(before), ['otx 198.51.100.20'], 'the Retry asked OTX alone');
      i = await rip();
      // The table draws its updates on the next animation frame.
      await page.waitFor(() => document.querySelector('.rip-row [data-status]') && [...document.querySelectorAll('.rip-row')]
        .some((tr) => tr.querySelector('.rip-name')?.textContent === 'retry.example.com' && tr.querySelector('[data-status]')?.dataset.status === 'none'),
      { timeout: 10000, message: 'the new name, checked' });
      i = await rip();
      assertEqual(i.rows['retry.example.com']?.sources, 'otx', 'its name joined the table and was checked');
    });

    await step('InternetDB: its first 429 locks it — the next address is not sent, and the panel says until when', async () => {
      await page.evaluate(() => { window.__rip.idb429 = true; });
      await runPanel('198.51.100.21');
      let i = await rip();
      assertEqual(i.chips.internetdb.state, 'failed', 'InternetDB failed');
      assert(/try again in 60 min/.test(i.chips.internetdb.value), `chip: ${i.chips.internetdb.value}`);
      assertEqual(i.chips.internetdb.retry, false, 'no Retry while it is locked');
      assert(i.facts.some((f) => /Shodan InternetDB locked this browser out after a burst of requests: it is not asked again before/.test(f)), `note: ${i.facts}`);
      await runPanel('198.51.100.22');
      i = await rip();
      assertEqual((await calls()).filter((c) => c === 'internetdb 198.51.100.22'), [], 'the next address is not sent to InternetDB');
      assertEqual([i.chips.internetdb.state, i.chips.internetdb.skip], ['failed', 'locked'], 'locked');
    });

    await step('typed keys: Shodan and WhoisXML asked with them; a key is never in the page, a link or an export', async () => {
      await page.evaluate(([a, b]) => {
        document.querySelector('.rip-keys summary')?.click();
        const set = (role, v) => {
          const el = document.querySelector(`[data-role="${role}"]`);
          el.value = v;
          el.dispatchEvent(new Event('input', { bubbles: true }));
        };
        set('rip-key-shodan', a);
        set('rip-key-whoisxml', b);
        window.__rip.data['198.51.100.30'] = { shodan: ['web.example.com'], whois: ['whois.example.com'] };
      }, [RIP_SHODAN_KEY, RIP_WHOIS_KEY]);
      const before = (await calls()).length;
      await runPanel('198.51.100.30');
      const after = (await calls()).slice(before);
      assert(after.includes('shodan 198.51.100.30') && after.includes('whoisxml 198.51.100.30'), `keyed requests: ${after}`);
      const i = await rip();
      assertEqual([i.rows['web.example.com']?.status, i.rows['whois.example.com']?.status], ['here', 'here'], 'their names, checked');
      assertEqual([i.chips.shodan.state, i.chips.whoisxml.state], ['ok', 'ok'], 'chips');
      const files = await ripExports(page);
      const leak = await page.evaluate(([a, b]) => {
        const text = `${document.body.innerText} ${location.href} ${document.body.outerHTML.replace(/value="[^"]*"/g, '')}`;
        return [a, b].filter((k) => text.includes(k));
      }, [RIP_SHODAN_KEY, RIP_WHOIS_KEY]);
      assertEqual(leak, [], 'no key in the page text, the markup or the URL');
      assert(!files.some((f) => f.text.includes(RIP_SHODAN_KEY) || f.text.includes(RIP_WHOIS_KEY)), 'no key in an export');
    });

    await step('a refused key says so (Shodan 401)', async () => {
      await page.evaluate(() => {
        const el = document.querySelector('[data-role="rip-key-shodan"]');
        el.value = 'wrong';
        window.__rip.data['198.51.100.31'] = {};
      });
      await runPanel('198.51.100.31');
      const i = await rip();
      assertEqual(i.chips.shodan.state, 'failed', 'Shodan failed');
      assert(i.facts.includes('Shodan API refused the key (HTTP 401): check the key and its credits.'), `note: ${i.facts}`);
      await page.evaluate(() => {
        document.querySelector('[data-role="rip-key-shodan"]').value = '';
        document.querySelector('[data-role="rip-key-whoisxml"]').value = '';
      });
    });

    await step('past 300 names: the first 300 are checked, "Check more" checks the rest', async () => {
      await page.evaluate(() => {
        window.__rip.data['198.51.100.40'] = { ht: Array.from({ length: 305 }, (_, n) => `n${n + 1}.example.com`) };
      });
      await runPanel('198.51.100.40');
      let i = await rip();
      assertEqual(i.more, 'Check 5 more names', 'the rest wait for a click');
      const asked = await page.evaluate(() => window.__rip.dnsNames.filter((n) => /^n\d+\.example\.com$/.test(n)).length);
      assertEqual(asked, 300, 'exactly the first batch was sent');
      await page.evaluate(() => document.querySelector('[data-action="rip-more"]').click());
      await page.waitFor(() => document.querySelector('.rip-more')?.hidden === true && document.querySelector('[data-action="rip-run"]') && !document.querySelector('[data-action="rip-run"]').hidden, { timeout: 30000, message: 'check more done' });
      const total = await page.evaluate(() => window.__rip.dnsNames.filter((n) => /^n\d+\.example\.com$/.test(n)).length);
      assertEqual(total, 305, 'every name checked');
      i = await rip();
      assertEqual(i.more, null, 'nothing left');
    });

    await step('Stop while an address is still asked: its row offers Find domains again, never a spinner', async () => {
      await page.evaluate(() => {
        window.__rip.slow = 5000;
        window.__rip.data['198.51.100.50'] = { ht: ['slow.example.com'] };
      });
      await gotoHash(page, '#/ip?ips=198.51.100.50', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'row looked up' });
      const btn = '[data-action="reverse"][data-ip="198.51.100.50"]';
      await page.evaluate((sel) => document.querySelector(sel).click(), btn);
      await page.waitFor((sel) => document.querySelector(sel)?.getAttribute('aria-busy') === 'true', { args: [btn], timeout: 10000, message: 'row busy' });
      await page.evaluate(() => document.querySelector('[data-action="rip-stop"]').click());
      await waitRip('stopped');
      const state = await page.evaluate((sel) => {
        const b = document.querySelector(sel);
        return b ? { busy: b.getAttribute('aria-busy'), disabled: b.disabled } : null;
      }, btn);
      assertEqual(state, { busy: null, disabled: false }, 'the row button, usable again');
      assert((await rip()).notes.some((n) => /^Stopped/.test(n)), 'the panel says it stopped');
      await page.evaluate(() => { window.__rip.slow = 0; });
    });

    await step('a Domains on this IP answer that lands after a new lookup of the same address fills in the new run’s row, never an old copy of it', async () => {
      // The in-row reverse lookup this guarded (fix(ip) 19b3708) became the panel: its answer is drawn into
      // the rows on screen when it lands, so the new run's row never keeps a spinner and the export matches it.
      const ip = '198.51.100.51';
      await page.evaluate((x) => { window.__rip.slow = 2500; window.__rip.data[x] = { ht: ['late.example.com'] }; }, ip);
      try {
        await gotoHash(page, `#/ip?ips=${ip}`, 'ip');
        await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'row looked up' });
        const btn = `[data-action="reverse"][data-ip="${ip}"]`;
        await page.evaluate((sel) => document.querySelector(sel).click(), btn);
        await page.waitFor((sel) => document.querySelector(sel)?.getAttribute('aria-busy') === 'true', { args: [btn], timeout: 10000, message: 'row busy' });
        // The same address again while that answer is on its way.
        await page.evaluate(() => document.querySelector('[data-action="run"]').click());
        await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'second lookup' });
        await waitRip('the late answer');
        const cells = await page.evaluate((x) => [...document.querySelectorAll('.ipi-row')]
          .filter((tr) => tr.querySelector('.ipi-ip')?.textContent === x)
          .map((tr) => {
            const rev = tr.querySelector('.ipi-rev');
            const b = tr.querySelector('[data-action="reverse"]');
            return { state: rev ? rev.dataset.state : null, count: rev ? rev.dataset.count : null, busy: b ? b.getAttribute('aria-busy') : null };
          }), ip);
        assertEqual(cells, [{ state: 'done', count: '1', busy: null }], 'the new run’s one row: filled in, no spinner left');
        const files = await exportFiles(page);
        const exported = JSON.parse(files[1].text).find((r) => r.ip === ip);
        assertEqual(exported.reverseIp, ['late.example.com'], 'the export holds what the table shows');
        assertEqual((await calls()).filter((c) => c === `hackertarget ${ip}`).length, 1, 'one HackerTarget request');
      } finally {
        await page.evaluate(() => { window.__rip.slow = 0; });
      }
    });

    await step('a language re-mount shows the lookup again in Turkish, with nothing sent and no key kept', async () => {
      await page.evaluate(() => {
        document.querySelector('[data-role="rip-key-shodan"]').value = 'kept-nowhere';
      });
      await runPanel('203.0.113.10');
      const before = (await calls()).length;
      await setLangUi(page, 'tr');
      await page.waitFor(() => document.querySelectorAll('.rip-panel .rip-row').length > 0, { timeout: 15000, message: 'panel restored' });
      const i = await rip();
      assertEqual((await calls()).length, before, 'nothing asked again');
      assertEqual(i.count, 9, 'the same rows');
      const tr = await page.evaluate(() => ({
        title: document.querySelector('.rip-panel [data-role="rip-title"]')?.textContent,
        status: document.querySelector('.rip-panel .rip-row [data-status="here"]')?.textContent,
        key: document.querySelector('[data-role="rip-key-shodan"]').value
      }));
      assertEqual(tr, { title: 'Bu IP’deki alan adları', status: 'şu an burada', key: '' }, 'Turkish, and the key field empty');
      await assertNoHorizontalScroll(page, 'reverse IP desktop tr');
    });

    for (const [scheme, lang, width] of [['dark', 'tr', 375], ['light', 'en', 320]]) {
      await step(`[${scheme}, ${lang.toUpperCase()}, ${width} px] the panel reads well and fits`, async () => {
        await page.setViewport({ width, height: 812, mobile: true });
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await setLangUi(page, lang);
        await page.waitFor(() => document.querySelectorAll('.rip-panel .rip-row').length > 0, { timeout: 15000, message: 'panel shown' });
        await assertNoHorizontalScroll(page, `reverse IP ${scheme} ${lang} ${width}`);
        await shot(page, `ip-reverse-mobile-${scheme}-${lang}`);
      });
    }

    await step('nothing left the page; i18n complete; no console errors', async () => {
      assertEqual(netHits, [], 'https requests that reached the network');
      assertEqual(await page.evaluate(() => window.__rip.blocked.slice()), [], 'requests the fake had to block');
      await checkI18n(page);
      await assertClean(page, 'reverse IP');
    });
  } finally {
    await page.setViewport({ width: 1440, height: 900 });
    await page.close();
  }
}

/* ------------------------------------------------------------------------ */
/* Offline: a row's Blocklists panel (ui/dnsbl-panel.js over lib/dnsbl.js)   */
/* ------------------------------------------------------------------------ */

/** The zones the fake below answers: every list of lib/dnsbl.js. */
const BL_ZONES = [...DNSBL_IP_LISTS.flatMap((l) => [l.zone, typeof l.v6 === 'string' ? l.v6 : null]), ...DNSBL_DOMAIN_LISTS.map((l) => l.zone)].filter(Boolean);

/**
 * Blocklists and one host name answered in the page (installed last, so it is the outermost
 * fetch wrapper): `window.__bl.answers[name]` is `{ A: [...] }` or `{ RCODE: 'SERVFAIL' }`; any other
 * test point (127.0.0.2 reversed, or a list's test domain) answers listed and every other name under
 * a list's zone NXDOMAIN. `names` lists every blocklist name asked; `delay` ms slows each answer
 * (an abort still ends the wait). Any other request goes on to the inner fakes.
 */
const BL_FAKE_SCRIPT = `(() => {
  const ZONES = ${JSON.stringify(BL_ZONES)};
  const inner = window.fetch;
  const bl = window.__bl = { names: [], delay: 0, answers: {
    'www.example.com': { A: ['8.8.8.8'] },
    '2.0.0.127.zen.spamhaus.org': { A: ['127.255.255.254'] },
    'dbltest.com.dbl.spamhaus.org': { A: ['127.255.255.254'] },
    'dbltest.com.zrd.spamhaus.org': { RCODE: 'NXDOMAIN' },
    'test.uribl.com.multi.uribl.com': { A: ['127.0.0.1'] },
    '2.0.0.127.psbl.surriel.com': { RCODE: 'SERVFAIL' },
    '8.8.8.8.bl.spamcop.net': { A: ['127.0.0.2'] },
    '8.8.8.8.dnsbl-2.uceprotect.net': { A: ['127.0.0.2'] }
  } };
  let wire = null;
  const isTest = (name) => /^2\\.0\\.0\\.127\\.|^2\\.0\\.0\\.0\\.0\\.0\\.f\\.7\\.f\\.f\\.f\\.f\\./.test(name) || /^(?:dbltest\\.com|test\\.surbl\\.org|test\\.uribl\\.com|test)\\./.test(name);
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return inner(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    const listed = ZONES.some((z) => name.endsWith('.' + z));
    if (!listed && !bl.answers[name]) return inner(input, init);
    if (listed) bl.names.push(name);
    const signal = (init && init.signal) || null;
    if (bl.delay) {
      await new Promise((resolve, reject) => {
        if (signal && signal.aborted) { reject(new DOMException('Aborted', 'AbortError')); return; }
        const timer = setTimeout(resolve, bl.delay);
        if (signal) signal.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
      });
    }
    const node = bl.answers[name] || (listed && isTest(name) ? { A: ['127.0.0.2'] } : null);
    const rcode = node && node.RCODE ? node.RCODE : node ? 'NOERROR' : 'NXDOMAIN';
    const answers = node && node[q.type] ? node[q.type].map((data) => ({ name, type: q.type, ttl: 60, data })) : [];
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode, questions: [{ name: q.name, type: q.type }], answers, authorities: [], edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/** The Blocklists panel of the row of `ip`: its state, summary, and per list status and text. */
function blocklistInfo(ip) {
  const panel = document.querySelector(`.ipi-bl[data-ip="${ip}"]`);
  if (!panel) return null;
  const status = panel.querySelector('.ipi-bl-status');
  const lists = {};
  for (const tr of panel.querySelectorAll('.ipi-bl-row')) {
    const link = tr.querySelector('.ipi-bl-link');
    lists[`${tr.closest('.ipi-bl-section').dataset.target} ${tr.dataset.list}`] = {
      status: tr.dataset.status, text: tr.textContent.replace(/\s+/g, ' ').trim(), href: link ? link.getAttribute('href') : null,
      dig: tr.querySelector('.ipi-bl-dig code')?.textContent || null
    };
  }
  // The lists that said "not listed", and those not asked, are names on one line each.
  for (const [sel, status] of [['.ipi-bl-clean .ipi-bl-item', 'not-listed'], ['.ipi-bl-skip .ipi-bl-item', 'skipped']]) {
    for (const item of panel.querySelectorAll(sel)) {
      lists[`${item.closest('.ipi-bl-section').dataset.target} ${item.dataset.list}`] = { status, text: item.textContent, href: null, dig: null };
    }
  }
  const shown = (sel) => { const el = panel.querySelector(sel); return !!el && !el.hidden; };
  return {
    state: status ? status.dataset.state : null, status: status ? status.textContent : '', intro: panel.querySelector('.ipi-bl-intro')?.textContent || '',
    sent: shown('.ipi-bl-sent'), check: shown('[data-action="dnsbl-check"]'), stop: shown('[data-action="dnsbl-stop"]'), retry: shown('[data-action="dnsbl-retry"]'),
    never: panel.querySelector('.ipi-bl-never')?.textContent || null, lists
  };
}

/** Open the details of the row of `ip` (no-op when open) and wait for its Blocklists slot to fill. */
async function openBlocklists(page, ip) {
  await page.evaluate((x) => {
    const row = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === x);
    const btn = row.querySelector('.dt-expand-btn');
    if (btn.getAttribute('aria-expanded') !== 'true') btn.click();
  }, ip);
  await page.waitFor((x) => !!document.querySelector(`.ipi-bl[data-ip="${x}"]`), { args: [ip], timeout: 15000, message: `blocklists panel of ${ip}` });
}

async function blocklistGroup(browser, server) {
  group('Offline: Blocklists (DNSBL answers, refusal codes and test points answered in the page)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const netHits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript('in-addr.arpa', PTR_ZONE) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: IP_FAKE_SCRIPT });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: BL_FAKE_SCRIPT });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  const info = (ip) => page.evaluate(blocklistInfo, ip);
  const names = () => page.evaluate(() => window.__bl.names.slice());
  const done = (ip) => page.waitFor((x) => {
    const st = document.querySelector(`.ipi-bl[data-ip="${x}"] .ipi-bl-status`);
    return !!st && ['done', 'stopped'].includes(st.dataset.state);
  }, { args: [ip], timeout: 20000, message: `blocklist check of ${ip}` });
  try {
    await step('a row’s Blocklists panel sends nothing before its button; reserved and private addresses never', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await page.evaluate(async () => { (await import('./assets/js/state.js')).state.clearInventory(); });
      await gotoHash(page, '#/ip?ips=8.8.8.8,www.example.com,203.0.113.7,10.0.0.1', 'ip');
      await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows looked up' });
      await openBlocklists(page, '8.8.8.8');
      const i = await info('8.8.8.8');
      assertEqual([i.state, i.sent, i.check, i.stop, i.retry], ['idle', true, true, false, false], 'idle panel');
      assert(i.intro.includes(`Asks ${DNSBL_IP_LISTS.length} IP blocklists through your DoH resolver whether 8.8.8.8 is listed.`), `intro: ${i.intro}`);
      assert(i.intro.includes('Domain lists (Spamhaus DBL, Spamhaus ZRD, SURBL, URIBL, NordSpam DBL): example.com.'), `the host name's domain: ${i.intro}`);
      assertEqual(await names(), [], 'blocklist names asked before the click');
      await openBlocklists(page, '203.0.113.7');
      assertEqual((await info('203.0.113.7')).never, 'Reserved and documentation addresses are never sent to a blocklist.', 'documentation address');
      const keys = await page.evaluate(() => {
        const row = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === '10.0.0.1');
        row.querySelector('.dt-expand-btn').click();
        return [...document.querySelectorAll('.dt-details .kv-key')].map((k) => k.textContent);
      });
      assertEqual(keys.filter((k) => k === 'Blocklists').length, 2, 'Blocklists in the public and documentation rows only, never the private one');
    });

    await step('Check blocklists: listed with the meaning and the delist page; refusals and failed test points never "not listed"', async () => {
      await page.evaluate(() => document.querySelector('.ipi-bl[data-ip="8.8.8.8"] [data-action="dnsbl-check"]').click());
      await done('8.8.8.8');
      const i = await info('8.8.8.8');
      const l = i.lists;
      assertEqual([l['8.8.8.8 spamcop'].status, l['8.8.8.8 spamcop'].href], ['listed', 'https://www.spamcop.net/bl.shtml?8.8.8.8'], 'SpamCop listed, its page');
      assert(/Delist/.test(l['8.8.8.8 spamcop'].text), `delist link: ${l['8.8.8.8 spamcop'].text}`);
      assert(/network \(allocation\) is listed because of other addresses in it/.test(l['8.8.8.8 uceprotect-2'].text), `UCEPROTECT 2 meaning: ${l['8.8.8.8 uceprotect-2'].text}`);
      assertEqual(l['8.8.8.8 spamhaus-zen'].status, 'refused', 'Spamhaus ZEN');
      assert(/Cannot check here.*Refuses queries from public resolvers \(answer 127\.255\.255\.254\)/.test(l['8.8.8.8 spamhaus-zen'].text), `ZEN text: ${l['8.8.8.8 spamhaus-zen'].text}`);
      assertEqual(l['8.8.8.8 spamhaus-zen'].dig, 'dig +short 8.8.8.8.zen.spamhaus.org A', 'a command for a resolver of one’s own');
      assertEqual([l['8.8.8.8 psbl'].status, /SERVFAIL/.test(l['8.8.8.8 psbl'].text)], ['error', true], 'a test point that failed');
      assertEqual(l['8.8.8.8 barracuda'].status, 'not-listed', 'Barracuda');
      assertEqual(['spamhaus-dbl', 'spamhaus-zrd', 'surbl', 'uribl', 'nordspam-dbl'].map((id) => l[`example.com ${id}`].status), ['refused', 'refused', 'not-listed', 'refused', 'not-listed'], 'domain lists');
      assert(/did not come back listed through this resolver/.test(l['example.com spamhaus-zrd'].text), `ZRD: ${l['example.com spamhaus-zrd'].text}`);
      assert(/answer 127\.0\.0\.1/.test(l['example.com uribl'].text), `URIBL: ${l['example.com uribl'].text}`);
      assert(i.status.startsWith('Listed on 2 lists · 13 not listed · 4 cannot be checked from a public resolver · 1 failed · checked '), `summary: ${i.status}`);
      assertEqual([i.sent, i.retry], [false, true], 'no "nothing sent" note; Retry of the failed list');
      const asked = await names();
      for (const n of ['8.8.8.8.zen.spamhaus.org', '8.8.8.8.psbl.surriel.com', 'example.com.dbl.spamhaus.org', 'example.com.multi.uribl.com', 'example.com.zrd.spamhaus.org']) {
        assert(!asked.includes(n), `${n} was sent to a list that cannot be checked here`);
      }
      assert(asked.includes('8.8.8.8.bl.spamcop.net') && asked.includes('example.com.multi.surbl.org'), 'the lists that answered their test point got the address and the domain');
      await assertNoHorizontalScroll(page, 'blocklists');
      await shot(page, 'ip-offline-desktop-light-en-blocklists');
    });

    await step('the panel keeps its results when the table redraws the row; Retry asks only the failed list again', async () => {
      await page.evaluate(() => document.querySelector('[data-action="reverse"][data-ip="8.8.8.8"]').click());
      await page.waitFor(() => {
        const row = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === '8.8.8.8');
        return !!row && !!row.querySelector('.ipi-rev');
      }, { timeout: 15000, message: 'reverse IP answer redraws the row' });
      assertEqual((await info('8.8.8.8')).lists['8.8.8.8 spamcop'].status, 'listed', 'results kept across the redraw');
      await page.evaluate(() => { window.__bl.answers['2.0.0.127.psbl.surriel.com'] = { A: ['127.0.0.2'] }; window.__bl.names.length = 0; });
      await page.evaluate(() => document.querySelector('.ipi-bl[data-ip="8.8.8.8"] [data-action="dnsbl-retry"]').click());
      await done('8.8.8.8');
      const i = await info('8.8.8.8');
      assertEqual([i.lists['8.8.8.8 psbl'].status, i.retry], ['not-listed', false], 'PSBL after the Retry');
      assertEqual((await names()).sort(), ['2.0.0.127.psbl.surriel.com', '8.8.8.8.psbl.surriel.com'], 'only the failed list was asked again');
      assert(i.status.startsWith('Listed on 2 lists · 14 not listed · 4 cannot be checked from a public resolver · checked '), `summary: ${i.status}`);
    });

    await step('Stop cancels a check: nothing more is asked and the panel says so', async () => {
      await page.evaluate(() => { window.__bl.delay = 400; window.__bl.names.length = 0; });
      await page.evaluate(() => document.querySelector('.ipi-bl[data-ip="8.8.8.8"] [data-action="dnsbl-check"]').click());
      await page.waitFor(() => window.__bl.names.length > 0, { timeout: 10000, message: 'the check started' });
      const running = await info('8.8.8.8');
      assertEqual([running.state, running.stop, running.check], ['running', true, false], 'running');
      await page.evaluate(() => document.querySelector('.ipi-bl[data-ip="8.8.8.8"] [data-action="dnsbl-stop"]').click());
      await done('8.8.8.8');
      const asked = (await names()).length;
      await page.evaluate(() => new Promise((r) => setTimeout(r, 900)));
      assertEqual((await names()).length, asked, 'names asked after Stop');
      const i = await info('8.8.8.8');
      assertEqual([i.state, i.status, i.check], ['stopped', 'Stopped — lists without a result were not asked.', true], 'stopped');
      await page.evaluate(() => { window.__bl.delay = 0; });
    });

    for (const [scheme, lang, width] of [['dark', 'tr', 1440], ['light', 'en', 375], ['dark', 'tr', 320]]) {
      await step(`[${scheme}, ${lang.toUpperCase()}, ${width} px] the last finished check is kept over a language re-mount and fits`, async () => {
        await page.setViewport(width < 600 ? { width, height: 812, mobile: true } : { width, height: 900 });
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await setLangUi(page, lang);
        await page.waitFor(ROWS_DONE, { timeout: 30000, message: 'rows kept' });
        await openBlocklists(page, '8.8.8.8');
        const i = await info('8.8.8.8');
        assertEqual(i.state, 'done', 'the kept check');
        assertEqual(i.lists['8.8.8.8 spamcop'].status, 'listed', 'kept results');
        if (lang === 'tr') {
          assert(i.status.startsWith('2 listede yer alıyor · 14 listede yok · 4 liste genel bir çözümleyiciden kontrol edilemez · kontrol: '), `TR summary: ${i.status}`);
          assert(/Buradan kontrol edilemez/.test(i.lists['8.8.8.8 spamhaus-zen'].text), `TR refused: ${i.lists['8.8.8.8 spamhaus-zen'].text}`);
        }
        await assertNoHorizontalScroll(page, `blocklists ${scheme} ${lang} ${width}`);
        await shot(page, `ip-offline-${width < 600 ? 'mobile' : 'desktop'}-${scheme}-${lang}-blocklists`);
      });
    }

    await step('blocklists: nothing left the page; i18n complete; no console errors', async () => {
      assertEqual(netHits, [], 'https requests that reached the network');
      assertEqual(await page.evaluate(() => window.__zoneBlocked.slice()), [], 'requests the zone script had to block');
      await checkI18n(page);
      await assertClean(page, 'blocklists');
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
    assert(/lan-box/.test(rows['10.0.0.1'].text) && /your workspace only/.test(rows['10.0.0.1'].text), 'private row: server + a reverse lookup of the workspace only');
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

  await step('reverse IP (one request per source: HackerTarget, ip.thc.org, OTX, Robtex, InternetDB): domains, or why not', async () => {
    await page.evaluate(() => document.querySelector('[data-action="reverse"][data-ip="1.1.1.1"]').click());
    // OTX answers a busy address slowly (over 25 s for 1.1.1.1): the row fills in once every source answered.
    await page.waitFor(() => {
      const row = [...document.querySelectorAll('.ipi-row')].find((r) => r.querySelector('.ipi-ip')?.textContent === '1.1.1.1');
      return !!row && !!row.querySelector('.ipi-rev');
    }, { timeout: 90000, message: 'reverse IP result' });
    const state = (await page.evaluate(rowsInfo))['1.1.1.1'].reverse;
    assert(['done', 'error'].includes(state), `reverse state ${state}`);
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
