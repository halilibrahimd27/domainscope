#!/usr/bin/env node
/**
 * integration.e2e.mjs — cross-view integration run of every tool against LIVE services in
 * a real headless Chrome/Edge, the way a user would chain them:
 *
 *   node tests/e2e/integration.e2e.mjs [--domain npmjs.com] [--sources crtsh,certspotter,anubis,hackertarget]
 *                                      [--global-name www.netflix.com] [--health-no-rdap denic.de] [--no-quota-apis]
 *                                      [--browser chrome|edge] [--headed] [--no-shots]
 *
 *   1. Servers   — a sample inventory file is imported through the file picker and saved; it
 *                  holds real direct IPs of the scan domain (found at run time), 8.8.8.8 and 10.0.0.5
 *   1b. Subdomains — the landing view: #/subdomains?domain=…&run=1 + one click on the link prompt
 *                  (Cloudflare rows, inventory match, the Hosts tab first; Overview, Origins and
 *                  Sources are checked in the four modes too); with learned names switched on
 *                  (opt-in), the scan's bare labels land in the workspace's learned-names store,
 *                  which SSL Targets then shows and uses too
 *   2. SSL Targets — the fixture certificate auto-fills its domain; then the domain's LIVE
 *                  certificate (fetched with node:tls) is loaded and the domain is scanned:
 *                  Cloudflare hosts, certificate coverage, the inventory server, CLI command
 *   3. Certificate — the scan's certificate is shared; chain.pem, with_key.pem (key never shown)
 *                  and test.pfx (the PKCS#12 password dialog, then its certificates)
 *   4. Global DNS  — www.netflix.com A over every resolver + ECS location, worldwide IP table
 *   5. DNS Lookup  — cloudflare.com, type=ALL ("All common"), DNSSEC on
 *   6. Bulk Resolve — 40 names
 *   7. IP Intel    — 8.8.8.8, 1.1.1.1, 10.0.0.5 (private, never sent anywhere; inventory match)
 *   8. Domain Health — github.com and a ccTLD domain without RDAP (explained)
 *   9. About
 *
 * Every view is checked and screenshotted in four modes — desktop 1440×900 light + dark
 * (English) and phone 390×844 dark + light (Turkish, after a language re-mount that must keep
 * the results) — for: no horizontal page scroll, no raw i18n keys / unreplaced {placeholders} /
 * "undefined" / "[object Object]" in text or attributes, and no text below 3:1 contrast.
 * Console errors, exceptions and CSP violations fail the run; failed requests to third-party
 * APIs (crt.sh 502 without CORS, 429s, Quad9 over HTTP/3) are reported but tolerated, because
 * the UI must (and does) show them as facts of a backend-free app.
 */

import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { RESOLVERS, GEO_VANTAGES } from '../../assets/js/lib/resolvers.js';
import {
  BASE, FIXTURES, cliOptions, createRunner, assert, assertEqual, sleep, installDownloadCapture,
  takeDownloads, waitReady, gotoRoute, setLangUi, assertNoHorizontalScroll, shot, splitProblems,
  assertNoMissingKeys, openScanOptions
} from './scan.e2e.mjs';

const DESKTOP = { width: 1440, height: 900, mobile: false };
const PHONE = { width: 390, height: 844, mobile: true };

const BULK_NAMES = [
  'www.cloudflare.com', 'one.one.one.one', 'blog.cloudflare.com', 'www.github.com', 'api.github.com',
  'github.githubassets.com', 'www.google.com', 'mail.google.com', 'dns.google', 'www.youtube.com',
  'www.microsoft.com', 'login.microsoftonline.com', 'www.apple.com', 'www.amazon.com', 'aws.amazon.com',
  'www.netflix.com', 'www.wikipedia.org', 'www.reddit.com', 'www.nytimes.com', 'pypi.org',
  'www.fastly.com', 'www.shopify.com', 'vercel.com', 'www.netlify.com', 'pages.github.com',
  'www.bbc.co.uk', 'www.spiegel.de', 'www.lemonde.fr', 'www.gov.uk', 'www.canada.ca',
  'www.rakuten.co.jp', 'www.usa.gov', 'www.ecb.europa.eu', 'www.npmjs.com', 'registry.npmjs.org',
  'www.example.com', 'example.org', '10.0.0.5.nip.io', 'nx-integration-check.example.invalid', 'www.ietf.org'
];

/* ------------------------------------------------------------------------ */
/* In-page audits                                                           */
/* ------------------------------------------------------------------------ */

/** Raw keys, unreplaced placeholders and junk values in text nodes and text attributes. */
function textAudit(keyList) {
  const keys = new Set(keyList);
  const issues = [];
  const codeLike = (el) => !!(el && el.closest('code, pre, textarea, .mono, .dt-cell-mono, [data-raw]'));
  const check = (value, where, el) => {
    const s = String(value || '').trim();
    if (!s) return;
    if (keys.has(s)) issues.push(`raw i18n key "${s}" in ${where}`);
    if (/\[object Object\]/.test(s)) issues.push(`[object Object] in ${where}: ${s.slice(0, 80)}`);
    if (!codeLike(el)) {
      if (/(^|[^$])\{[a-zA-Z][a-zA-Z0-9_]*\}/.test(s)) issues.push(`unreplaced placeholder in ${where}: ${s.slice(0, 100)}`);
      if (/\bundefined\b|\bNaN\b/.test(s)) issues.push(`undefined/NaN in ${where}: ${s.slice(0, 100)}`);
    }
  };
  const root = document.querySelector('#app');
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const el = n.parentElement;
    if (!el || el.closest('script, style')) continue;
    check(n.nodeValue, `<${el.tagName.toLowerCase()}${el.className && typeof el.className === 'string' ? `.${el.className.split(' ')[0]}` : ''}>`, el);
  }
  for (const el of root.querySelectorAll('[title], [aria-label], [placeholder], [alt]')) {
    for (const a of ['title', 'aria-label', 'placeholder', 'alt']) if (el.hasAttribute(a)) check(el.getAttribute(a), `@${a} of <${el.tagName.toLowerCase()}>`, el);
  }
  return [...new Set(issues)].slice(0, 20);
}

/**
 * WCAG contrast of visible text against its composited background. Returns offenders below
 * `min` (large text: 3, normal text: 3 by default here — a floor for "clearly unreadable").
 */
function contrastAudit(min) {
  const cv = document.createElement('canvas');
  cv.width = 1;
  cv.height = 1;
  const cx = cv.getContext('2d', { willReadFrequently: true });
  const lum = ([r, g, b]) => {
    const f = (v) => { const c = v / 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const chainOf = (el) => {
    const chain = [];
    for (let p = el; p; p = p.parentElement) chain.unshift(p);
    return chain;
  };
  const out = [];
  let checked = 0;
  const all = document.querySelectorAll('#app *');
  for (const el of all) {
    if (checked > 4000) break;
    const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.nodeValue.trim());
    if (!own) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    // Content of closed <details> (content-visibility: hidden) still has boxes: skip it.
    if (el.checkVisibility && !el.checkVisibility({ contentVisibilityAuto: true, visibilityProperty: true })) continue;
    if (el.closest('.sr-only, [aria-hidden="true"], :disabled, [disabled], .is-disabled, .skip-link')) continue;
    if (cs.clipPath && cs.clipPath !== 'none') continue;
    const chain = chainOf(el);
    let skip = false;
    for (const p of chain) {
      const s = getComputedStyle(p);
      if (Number(s.opacity) < 1) skip = true;
      if (s.backgroundImage && s.backgroundImage !== 'none' && p !== document.documentElement && p !== document.body) skip = true;
    }
    if (skip) continue;
    checked += 1;
    // Composite the backgrounds from the root down (canvas does the alpha blending), then
    // the text colour on top.
    cx.clearRect(0, 0, 1, 1);
    cx.fillStyle = '#ffffff';
    cx.fillRect(0, 0, 1, 1);
    for (const p of chain) {
      cx.fillStyle = 'rgba(0,0,0,0)';
      cx.fillStyle = getComputedStyle(p).backgroundColor;
      cx.fillRect(0, 0, 1, 1);
    }
    const bgPx = [...cx.getImageData(0, 0, 1, 1).data.slice(0, 3)];
    cx.fillStyle = 'rgba(0,0,0,0)';
    cx.fillStyle = cs.color;
    cx.fillRect(0, 0, 1, 1);
    const fgPx = [...cx.getImageData(0, 0, 1, 1).data.slice(0, 3)];
    const [l1, l2] = [lum(fgPx), lum(bgPx)].sort((a, b) => b - a);
    const ratio = (l1 + 0.05) / (l2 + 0.05);
    if (ratio < min) {
      const text = [...el.childNodes].filter((n) => n.nodeType === 3).map((n) => n.nodeValue.trim()).join(' ').slice(0, 40);
      out.push(`${ratio.toFixed(2)}:1 <${el.tagName.toLowerCase()}.${[...el.classList].join('.')}> "${text}" fg=rgb(${fgPx}) bg=rgb(${bgPx})`);
    }
  }
  return { checked, offenders: out.slice(0, 15) };
}

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

/** Fetch the certificate a domain serves (leaf + chain as PEM) with node:tls; null on failure. */
function fetchLiveCertPem(host) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 10000 }, () => {
      const pems = [];
      const seen = new Set();
      for (let c = sock.getPeerCertificate(true); c && c.raw && !seen.has(c.fingerprint256); c = c.issuerCertificate) {
        seen.add(c.fingerprint256);
        const b64 = c.raw.toString('base64').replace(/.{1,64}/g, '$&\n');
        pems.push(`-----BEGIN CERTIFICATE-----\n${b64}-----END CERTIFICATE-----\n`);
        if (c.issuerCertificate === c) break;
      }
      sock.end();
      resolve(pems.length ? pems.join('') : null);
    });
    sock.on('error', () => resolve(null));
    sock.on('timeout', () => { sock.destroy(); resolve(null); });
  });
}

/** Public, non-CDN IPv4 addresses of a few common names of the domain (to seed the inventory). */
async function findDirectIps(page, domain) {
  return page.evaluate(async (d) => {
    const app = await import('./assets/js/app.js');
    const net = await import('./assets/js/lib/netinfo.js');
    const dns = await app.getDns();
    const found = [];
    for (const label of ['api', 'mail', 'ftp', 'cms', 's', 'panel', 'webmail', 'smtp', 'direct', 'origin', '']) {
      const name = label ? `${label}.${d}` : d;
      const r = await dns.resolveHost(name);
      const c = net.classifyResolution(r);
      if (c.kind === 'direct' && r.ipv4.length && !found.some((f) => f.ip === r.ipv4[0])) found.push({ name, ip: r.ipv4[0] });
      if (found.length >= 2) break;
    }
    return found;
  }, domain);
}

/** Wait for an in-page condition string/function with a long timeout. */
function waitDone(page, cond, message, timeout = 90000) {
  return page.waitFor(cond, { timeout, interval: 250, message });
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  const opts = cliOptions();
  const DOMAIN = opts.value('--domain', 'npmjs.com');
  const SOURCES = opts.value('--sources', 'crtsh,certspotter,anubis,hackertarget').split(',').map((s) => s.trim()).filter(Boolean);
  const GLOBAL_NAME = opts.value('--global-name', 'www.netflix.com');
  // A ccTLD whose registry has no RDAP service (.de, .jp, .tr …); --health-tr is the old name.
  const HEALTH_NO_RDAP = opts.value('--health-no-rdap', opts.value('--health-tr', 'denic.de'));
  const run = createRunner();
  const notes = [];
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-integration-'));

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}; domain ${DOMAIN}, sources ${SOURCES.join(', ')}\n`);

  const page = await browser.newPage('about:blank', DESKTOP);
  if (opts.has('--no-quota-apis')) {
    // ipwho.is and HackerTarget have small anonymous daily quotas: keep them out of this run.
    await page.send('Network.enable');
    await page.send('Network.setBlockedURLs', { urls: ['*://ipwho.is/*', '*://api.hackertarget.com/*'] });
  }
  await installDownloadCapture(page);
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  let keyList = [];

  /** Page-level checks for the current mode. */
  const checkPage = async (where) => {
    // Theme switches animate colours (--dur): measure only once every CSS transition has ended.
    await page.waitFor(() => document.getAnimations().every((a) => !(a instanceof CSSTransition) || a.playState !== 'running'), { timeout: 5000, message: 'transitions settled' })
      .catch(() => {});
    await assertNoHorizontalScroll(page, where);
    // Views register their strings when first loaded: refresh the key list every time.
    keyList = await page.evaluate(async () => (await import('./assets/js/i18n.js')).listKeys('en'));
    const text = await page.evaluate(textAudit, keyList);
    assertEqual(text, [], `${where}: text audit`);
    const contrast = await page.evaluate(contrastAudit, 3);
    assert(contrast.offenders.length === 0, `${where}: ${contrast.offenders.length} text element(s) below 3:1 contrast (of ${contrast.checked}):\n          ${contrast.offenders.join('\n          ')}`);
  };

  /**
   * Desktop light + dark (EN), then a TR re-mount and phone dark + light; back to desktop EN.
   * `ready` (in-page condition) must hold again after the language re-mount (results restored).
   */
  const fourModes = async (label, ready) => {
    const waitReadyAgain = async () => {
      await page.waitFor(() => document.querySelector('#page-body')?.childElementCount > 0 && !document.querySelector('#page-body .page-loading'));
      if (ready) await waitDone(page, ready, `${label}: ready after re-mount`, 60000);
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
    };
    // Screenshot first, then check; collect failures so every mode is still captured.
    const failures = [];
    const mode = async (name) => {
      await page.waitFor(() => document.getAnimations().every((a) => !(a instanceof CSSTransition) || a.playState !== 'running'), { timeout: 5000 }).catch(() => {});
      await shot(page, opts, `integration-${label}-${name}`);
      try {
        await checkPage(`${label} ${name}`);
      } catch (err) {
        failures.push(err.message);
      }
    };
    try {
      await page.evaluate(() => window.scrollTo(0, 0));
      await mode('desktop-light-en');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await mode('desktop-dark-en');
      await setLangUi(page, 'tr');
      await waitReadyAgain();
      await page.setViewport(PHONE);
      await sleep(300);
      await mode('mobile-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await mode('mobile-light-tr');
    } finally {
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport(DESKTOP);
      await setLangUi(page, 'en');
      await waitReadyAgain();
    }
    assert(failures.length === 0, failures.join('\n        '));
  };

  let direct = [];
  let liveCert = null;
  /** Labels the Subdomains scan taught this browser (the learned-names store). */
  let learnedAfterSub = [];
  try {
    run.group(`Boot (${DESKTOP.width}×${DESKTOP.height})`);
    await run.step('app boots with empty storage; English UI', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      // Empty storage: the workspaces (IndexedDB) and every 'ssds.*' key.
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.clearAll());
      await page.reload();
      await waitReady(page);
      await setLangUi(page, 'en');
      keyList = await page.evaluate(async () => (await import('./assets/js/i18n.js')).listKeys('en'));
      assert(keyList.length > 200, `shell keys loaded: ${keyList.length}`);
    });

    /* ---------------- 1. Servers ---------------- */
    run.group('1. Servers (inventory import)');
    await run.step(`inventory file with real direct IPs of ${DOMAIN} is imported and saved`, async () => {
      direct = await findDirectIps(page, DOMAIN);
      const lines = ['# integration inventory (hosts-file style)', ...direct.map((d, i) => `${d.ip} web-origin${i ? i + 1 : ''} ${d.name}`),
        '8.8.8.8 dns-google', '10.0.0.5 lab-box', '10.20.30.40 web02', '2001:db8::10 web03'];
      const file = path.join(tmp, 'servers.txt');
      await writeFile(file, `${lines.join('\n')}\n`);
      await gotoRoute(page, 'inventory');
      await page.setFileInput('.inv-editor .filedrop-input', [file]);
      if (await page.waitFor(() => !!document.querySelector('dialog.modal[open]'), { timeout: 1500 }).catch(() => false)) {
        await page.click('dialog.modal[open] .modal-foot .btn-primary');
      }
      await page.waitFor(() => document.querySelector('[data-role="inventory-text"]').value.includes('dns-google'), { message: 'file imported' });
      await page.waitFor((n) => document.querySelectorAll('.inv-results .dt-table tbody tr').length === n, { args: [direct.length + 4], message: 'parsed rows' });
      await page.click('[data-action="save"]');
      await page.waitFor(async () => {
        const { state } = await import('./assets/js/state.js');
        await state.whenSaved();
        return !!state.workspaceData('inventory');
      }, { message: 'saved' });
      process.stdout.write(`        direct hosts: ${direct.map((d) => `${d.name}=${d.ip}`).join(', ') || 'none found'}\n`);
    });
    await run.step('Servers view in four modes', () => fourModes('inventory', "document.querySelectorAll('.inv-results .dt-table tbody tr').length > 0"));

    /* ---------------- 1b. Subdomains (landing view) ---------------- */
    run.group('1b. Subdomains');
    const SUB_DONE = "document.querySelector('.sub-run')?.dataset.status === 'done' && document.querySelectorAll('.sub-table tbody tr.dt-row').length > 0";
    await run.step(`#/subdomains?domain=${DOMAIN}&run=1 (one click): hosts, Cloudflare rows, the inventory server`, async () => {
      // The link run uses the saved options: save --sources first, so no other (quota-limited)
      // source is queried — and opt in to learned names (off by default), which this run checks.
      await page.evaluate((srcs) => localStorage.setItem('ssds.subdomains.options', JSON.stringify({ sources: srcs, learned: true })), SOURCES);
      await gotoRoute(page, `#/subdomains?domain=${DOMAIN}&run=1`);
      // A shared link never scans on its own: it pre-fills the box and offers "Start scan".
      await page.waitFor(() => document.querySelector('[data-action="sub-link-start"]'), { timeout: 15000, message: 'link prompt' });
      await page.click('[data-action="sub-link-start"]');
      await waitDone(page, () => ['done', 'error', 'cancelled'].includes(document.querySelector('.sub-run')?.dataset.status), 'subdomains scan', 180000);
      assertEqual(await page.evaluate(() => document.querySelector('.sub-run').dataset.status), 'done', 'status');
      const info = await page.evaluate(() => {
        const rows = [...document.querySelectorAll('.sub-table tbody tr.dt-row')];
        return {
          rows: rows.length,
          cf: rows.filter((r) => r.querySelector('[data-kind="cloudflare"]')).length,
          text: rows.map((r) => r.textContent).join(' '),
          tab: document.querySelector('.sub-tabs .tab[aria-selected="true"]')?.dataset.tab || null,
          shown: document.querySelector('.sub-table').getBoundingClientRect().height > 0
        };
      });
      process.stdout.write(`        ${info.rows} rows, ${info.cf} behind Cloudflare\n`);
      assert(info.rows >= 3 && info.cf >= 1, JSON.stringify({ rows: info.rows, cf: info.cf }));
      assert(info.tab === 'hosts' && info.shown, `hosts first: the Hosts tab shows the table (${info.tab})`);
      if (direct.length) assert(/web-origin/.test(info.text), 'inventory server shown for the direct host');
      // The scan taught this browser its naming vocabulary: bare labels only, never names or IPs.
      learnedAfterSub = await page.evaluate(async () => Object.keys(((await import('./assets/js/state.js')).state.workspaceData('learned') || {}).labels || {}));
      assert(learnedAfterSub.length > 0 && learnedAfterSub.every((l) => /^[a-z0-9-]+$/.test(l)), `learned labels: ${learnedAfterSub.slice(0, 12)}`);
      process.stdout.write(`        ${learnedAfterSub.length} labels learned in this browser\n`);
    });
    await run.step('Subdomains in four modes', () => fourModes('subdomains', SUB_DONE));
    // The other result tabs (a picked tab is kept across the language re-mount of fourModes).
    for (const tab of ['overview', 'origins', 'sources']) {
      await run.step(`Subdomains › ${tab} tab in four modes`, async () => {
        await page.click(`.sub-tabs .tab[data-tab="${tab}"]`);
        const ready = `${SUB_DONE} && !!document.querySelector('.sub-tabs .tab[data-tab="${tab}"][aria-selected="true"]')`;
        await waitDone(page, ready, `${tab} tab`, 10000);
        await fourModes(`subdomains-${tab}`, ready);
      });
    }

    /* ---------------- 2. SSL Targets ---------------- */
    run.group('2. SSL Targets');
    await run.step('fixture certificate auto-fills its registrable domain', async () => {
      await gotoRoute(page, 'scan');
      await page.setFileInput('.scan-step-cert .filedrop-input', [path.join(FIXTURES, 'rsa_multi_san.pem')]);
      await page.waitForSelector('.scan-step-cert .cert-summary');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="scan-domains"]').value), 'example-test.com.tr', 'auto-filled');
      assert(await page.evaluate(() => /Test Root CA/.test(document.querySelector('.cert-summary').textContent)), 'issuer shown');
      // The vocabulary is shared with Subdomains: automatic Turkish pack for .com.tr, and the
      // labels the Subdomains scan just learned are tried first here too.
      const vocab = await page.evaluate(() => document.querySelector('[data-role="scan-vocab"] .scan-vocab-text')?.textContent || '');
      const n = Math.min(learnedAfterSub.length, 1000); // LEARNED_TRY_MAX: the most frequent are tried
      assertEqual(vocab, `Languages / markets: Auto: Turkish (.com.tr) · ${n.toLocaleString('en-US')} learned name${n === 1 ? '' : 's'} first`, 'shared vocabulary line');
    });
    await run.step(`the live certificate of ${DOMAIN} replaces it`, async () => {
      liveCert = await fetchLiveCertPem(DOMAIN);
      if (!liveCert) { notes.push(`could not fetch the live certificate of ${DOMAIN}; scanning with the fixture`); return; }
      const file = path.join(tmp, `${DOMAIN}.pem`);
      await writeFile(file, liveCert);
      await page.evaluate(() => { const d = document.querySelector('.scan-step-cert details'); if (d) d.open = true; });
      const input = await page.evaluate(() => [...document.querySelectorAll('.scan-step-cert .filedrop-input')].length);
      assert(input >= 1, 'a file input for another certificate');
      await page.setFileInput('.scan-step-cert .filedrop-input', [file]);
      await page.waitFor((d) => document.querySelector('[data-role="scan-domains"]').value === d
        || [...document.querySelectorAll('.scan-step-cert .cert-summary-names, .scan-step-cert .cert-summary')].some((n) => n.textContent.includes(d)),
      { args: [DOMAIN], message: 'live certificate loaded' });
    });
    await run.step(`LIVE scan of ${DOMAIN}: Cloudflare hosts, coverage, the inventory server, Behind CDN`, async () => {
      await page.evaluate((srcs) => {
        for (const input of document.querySelectorAll('input[name="scan-sources"]')) if (input.checked !== srcs.includes(input.value)) input.click();
      }, SOURCES);
      await openScanOptions(page);
      await page.click('input[name="scan-bruteforce"][value="small"]');
      await page.type('[data-role="scan-domains"]', DOMAIN);
      const prev = await page.evaluate(() => document.querySelector('.scan-run-ui')?.dataset.run || '');
      const t0 = Date.now();
      await page.click('[data-action="scan-run"]');
      await page.waitFor((p) => document.querySelector('.scan-run-ui')?.dataset.run !== p, { args: [prev] });
      await waitDone(page, () => ['done', 'error', 'cancelled'].includes(document.querySelector('.scan-run')?.dataset.status), 'scan finished', 300000);
      assertEqual(await page.evaluate(() => document.querySelector('.scan-run').dataset.status), 'done', 'status');
      const info = await page.evaluate(() => {
        const stat = (k) => Number((document.querySelector(`[data-stat="${k}"] .stat-value`)?.textContent || '').replace(/\D/g, '')) || 0;
        return {
          hosts: stat('hosts'), cloudflare: stat('cloudflare'), covered: stat('covered'),
          chips: [...document.querySelectorAll('.scan-chip')].map((c) => `${c.dataset.source}=${c.dataset.state}`),
          refs: [...document.querySelectorAll('.scan-hosts .scan-server-ref')].map((r) => r.textContent.trim())
        };
      });
      process.stdout.write(`        ${((Date.now() - t0) / 1000).toFixed(1)} s: ${info.hosts} hosts, ${info.cloudflare} Cloudflare, ${info.covered} covered; ${info.chips.join(', ')}\n`);
      assert(info.hosts >= 3, `hosts ${info.hosts}`);
      assert(info.cloudflare >= 1, `Cloudflare hosts ${info.cloudflare}`);
      if (liveCert) assert(info.covered >= 1, `covered by the live certificate: ${info.covered}`);
      if (direct.length) assert(info.refs.some((r) => r.startsWith('web-origin')), `inventory server matched: ${info.refs}`);
      await page.click('.scan-tabs [data-tab="servers"]');
      await page.waitForSelector('.scan-tab-servers .dt');
      const servers = await page.evaluate(() => [...document.querySelectorAll('.scan-servers-table tbody tr.dt-row')].map((tr) => ({
        name: tr.querySelector('.scan-srv-name')?.textContent, status: tr.querySelector('[data-status]')?.dataset.status
      })));
      if (direct.length) {
        const s = servers.find((x) => x.name === 'web-origin');
        assert(s, `web-origin in Servers: ${JSON.stringify(servers)}`);
        process.stdout.write(`        web-origin status: ${s.status}\n`);
      }
      await page.click('.scan-tabs [data-tab="cdn"]');
      await page.waitForSelector('.scan-tab-cdn .scan-cli');
      assertEqual(await page.evaluate(() => document.querySelector('.scan-cli code').textContent),
        'python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem', 'CLI command');
      await takeDownloads(page);
      await page.click('[data-action="cli-targets"]');
      const [targets] = await takeDownloads(page);
      assert(targets && /web-origin|dns-google/.test(targets.text), `targets.txt holds inventory servers: ${targets && targets.text.slice(0, 200)}`);
      await page.click('.scan-tabs [data-tab="hosts"]');
      // SSL Targets learns like Subdomains does (the store only grows; still labels only).
      const learned = await page.evaluate(async () => Object.keys(((await import('./assets/js/state.js')).state.workspaceData('learned') || {}).labels || {}));
      assert(learned.length >= learnedAfterSub.length && learned.every((l) => /^[a-z0-9-]+$/.test(l)), `learned after SSL Targets: ${learned.length}`);
      // ... and the mounted view refreshes its vocabulary line with the grown store right away
      // (active.refreshVocab), without an edit or a re-mount.
      const n2 = Math.min(learned.length, 1000); // LEARNED_TRY_MAX
      await page.waitFor((want) => (document.querySelector('[data-role="scan-vocab"] .scan-vocab-text')?.textContent || '').endsWith(want),
        { args: [`${n2.toLocaleString('en-US')} learned name${n2 === 1 ? '' : 's'} first`], timeout: 5000, message: 'vocabulary line counts the learned names after the scan' });
    });
    await run.step('SSL Targets in four modes (results kept over the TR re-mount)', () => fourModes('scan', "document.querySelector('.scan-run')?.dataset.status === 'done' && document.querySelectorAll('.scan-hosts tbody tr.dt-row').length > 0"));

    /* ---------------- 3. Certificate ---------------- */
    run.group('3. Certificate');
    const upload = async (file) => {
      const hasReload = await page.evaluate(() => !!document.querySelector('.cert-reload'));
      if (hasReload) await page.evaluate(() => { document.querySelector('.cert-reload').open = true; });
      await page.setFileInput(hasReload ? '.cert-reload .filedrop-input' : '.cert-loader-card .filedrop-input', [path.join(FIXTURES, file)]);
    };
    await run.step('the scan certificate is shared with the Certificate view', async () => {
      await gotoRoute(page, 'cert');
      await page.waitForSelector('.cert-overview');
      const cn = await page.evaluate(() => document.querySelector('.cert-overview-cn').textContent);
      assert(liveCert ? cn.includes(DOMAIN) : cn === 'www.example-test.com.tr', `shared certificate: ${cn}`);
    });
    await run.step('chain.pem: leaf + CA in order', async () => {
      await upload('chain.pem');
      await page.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === 'www.example-test.com.tr', { message: 'chain leaf' });
      await page.click('.cert-tabs [data-tab="chain"]');
      const issues = await page.evaluate(() => [...document.querySelectorAll('[data-chain-issue]')].map((a) => a.dataset.chainIssue));
      assert(!issues.includes('order'), `chain order ok: ${issues}`);
      await page.click('.cert-tabs [data-tab="overview"]').catch(() => {});
    });
    await run.step('Certificate view in four modes', () => fourModes('cert', "!!document.querySelector('.cert-overview')"));
    await run.step('with_key.pem: warning; key material never in the page', async () => {
      await upload('with_key.pem');
      await page.waitForSelector('[data-warning="PRIVATE_KEY_PRESENT"]');
      const leaked = await page.evaluate(() => document.body.textContent.includes('PRIVATE KEY-----')
        || [...document.querySelectorAll('textarea, input')].some((el) => /PRIVATE KEY|MII[A-Za-z0-9+/]{20}/.test(el.value)));
      assert(!leaked, 'no key material in the DOM');
      await checkPage('cert with_key');
      await shot(page, opts, 'integration-cert-with-key-desktop-light-en');
    });
    await run.step('test.pfx: the PKCS#12 password dialog, then its certificates', async () => {
      await upload('test.pfx');
      await page.waitForSelector('[data-role="pfx-password"]');
      await page.type('[data-role="pfx-password"]', 'test');
      await page.click('[data-action="pfx-open"]');
      await page.waitFor(() => document.querySelector('.pfx-note') && document.querySelector('.cert-overview-cn')?.textContent === 'www.example-test.com.tr', { message: 'PKCS#12 opened' });
      await checkPage('cert pfx');
      await shot(page, opts, 'integration-cert-pfx-desktop-light-en');
    });

    /* ---------------- 4. Global DNS ---------------- */
    run.group('4. Global DNS');
    const GLOBAL_DONE = "document.querySelector('.glb-summary .alert') && document.querySelector('.glb-summary .alert').dataset.state !== 'running'";
    await run.step(`${GLOBAL_NAME} A: ${RESOLVERS.length} resolvers + ${GEO_VANTAGES.length} locations, worldwide IPs`, async () => {
      await gotoRoute(page, `#/global?name=${GLOBAL_NAME}&type=A`);
      await waitDone(page, GLOBAL_DONE, 'global done', 60000);
      const info = await page.evaluate(() => ({
        resolvers: document.querySelectorAll('.glb-resolvers tbody tr.dt-row').length,
        geo: document.querySelectorAll('.glb-geo tbody tr.dt-row').length,
        pending: document.querySelectorAll('.glb-row.is-pending').length,
        ips: [...document.querySelectorAll('.glb-ips tbody tr.dt-row')].map((r) => r.querySelector('[data-kind]')?.dataset.kind),
        failed: document.querySelectorAll('.glb-resolvers .glb-fail').length,
        state: document.querySelector('.glb-summary .alert').dataset.state
      }));
      process.stdout.write(`        ${info.ips.length} IPs (${[...new Set(info.ips)].join(', ')}), state ${info.state}, ${info.failed} resolver(s) failed\n`);
      assertEqual([info.resolvers, info.geo, info.pending], [RESOLVERS.length, GEO_VANTAGES.length, 0], 'rows');
      assert(info.ips.length >= 1 && info.ips.every(Boolean), 'IP table with classification badges');
      assert(info.failed <= 3, `failed resolvers ${info.failed}`);
    });
    await run.step('Global DNS in four modes', () => fourModes('global', `${GLOBAL_DONE} && document.querySelectorAll('.glb-row.is-pending').length === 0`));

    /* ---------------- 5. DNS Lookup ---------------- */
    run.group('5. DNS Lookup');
    // Every type answered: a NODATA type has no card (it is listed in the summary's "No records" line).
    const LOOKUP_DONE = "!!document.querySelector('.lkp-sum') && !document.querySelector('.lkp-card[data-state=\"pending\"]') && document.querySelector('[data-action=\"run\"]')?.getAttribute('aria-busy') !== 'true'";
    await run.step('cloudflare.com, type=ALL, DNSSEC on: every common type answered and validated', async () => {
      await gotoRoute(page, '#/lookup?name=cloudflare.com&type=ALL&dnssec=1');
      await waitDone(page, LOOKUP_DONE, 'lookup done', 45000);
      const cards = await page.evaluate(() => [...document.querySelectorAll('.lkp-card')].map((c) => ({
        type: c.dataset.type, state: c.dataset.state, text: c.textContent
      })));
      const noRecords = await page.evaluate(() => (document.querySelector('.lkp-nodata')?.dataset.types || '').split(' ').filter(Boolean));
      const common = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'HTTPS'];
      assertEqual(common.filter((type) => cards.some((c) => c.type === type) || noRecords.includes(type)), common, 'every type: a card or the "No records" line');
      assert(noRecords.includes('CNAME'), `an apex has no CNAME: folded into "No records" (${noRecords})`);
      assert(cards.every((c) => c.state === 'noerror'), `states: ${cards.map((c) => `${c.type}=${c.state}`)}`);
      assert(/RRSIG/.test(cards[0].text), 'RRSIG shown with DO');
      const dnssecOn = await page.evaluate(() => document.querySelector('[data-role="lookup-dnssec"]').checked);
      assert(dnssecOn, 'DNSSEC switch from the URL');
    });
    await run.step('DNS Lookup in four modes', () => fourModes('lookup', LOOKUP_DONE));

    /* ---------------- 6. Bulk Resolve ---------------- */
    run.group('6. Bulk Resolve');
    const BULK_DONE = "document.querySelector('.bulk-results .bulk-progress')?.dataset.status === 'done'";
    await run.step(`${BULK_NAMES.length} names resolve; inventory match; IP tab`, async () => {
      await gotoRoute(page, `#/bulk?names=${BULK_NAMES.join(',')}`);
      await page.waitFor(() => !document.querySelector('[data-action="bulk-run"]').disabled, { message: 'Resolve enabled' });
      const parse = await page.evaluate(() => document.querySelector('.bulk-parse')?.textContent || '');
      assert(parse.includes(`${BULK_NAMES.length} hostnames`) && !/duplicate/.test(parse), `?names= fills each name once: ${parse}`);
      await page.click('[data-action="bulk-run"]');
      await waitDone(page, BULK_DONE, 'bulk done', 120000);
      const rows = await page.evaluate(() => [...document.querySelectorAll('.bulk-hosts tbody tr.dt-row')].map((tr) => ({
        name: tr.querySelector('td:not(.dt-expander)')?.textContent.trim(), kind: tr.querySelector('[data-kind]')?.dataset.kind, text: tr.textContent
      })));
      assertEqual(rows.length, BULK_NAMES.length, 'rows');
      const google = rows.find((r) => r.name === 'dns.google');
      assert(google && /dns-google/.test(google.text), `dns.google → inventory: ${google && google.text.slice(0, 120)}`);
      assert(rows.find((r) => r.name === 'www.cloudflare.com')?.kind === 'cloudflare', 'Cloudflare classified');
      assert(rows.find((r) => r.name === 'nx-integration-check.example.invalid')?.kind === 'nxdomain', 'NXDOMAIN');
      const lab = rows.find((r) => r.name === '10.0.0.5.nip.io');
      assert(lab && lab.kind === 'private' && /lab-box/.test(lab.text), `10.0.0.5.nip.io → private + lab-box: ${lab && lab.text.slice(0, 120)}`);
    });
    await run.step('Bulk Resolve in four modes', () => fourModes('bulk', `${BULK_DONE} && document.querySelectorAll('.bulk-hosts tbody tr.dt-row').length > 0`));

    /* ---------------- 7. IP Intel ---------------- */
    run.group('7. IP Intel');
    const IP_DONE = "document.querySelectorAll('.ipi-row').length > 0 && document.querySelectorAll('.ipi-row.is-pending').length === 0 && !document.querySelector('[data-action=\"run\"]').hidden";
    await run.step('8.8.8.8, 1.1.1.1, 10.0.0.5: owner, operator, private flag, inventory', async () => {
      await gotoRoute(page, '#/ip?ips=8.8.8.8,1.1.1.1,10.0.0.5');
      await waitDone(page, IP_DONE, 'ip done', 90000);
      const rows = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.ipi-row')].map((tr) => [
        tr.dataset.ip || tr.querySelector('.ipi-ip, .mono')?.textContent.trim(), { text: tr.textContent, kind: tr.querySelector('[data-kind]')?.dataset.kind }
      ])));
      const find = (ip) => Object.entries(rows).find(([k, v]) => k === ip || v.text.includes(ip))?.[1];
      const g = find('8.8.8.8');
      const c = find('1.1.1.1');
      const p = find('10.0.0.5');
      assert(g && /AS15169/.test(g.text) && /dns-google/.test(g.text), `8.8.8.8: ${g && g.text.slice(0, 200)}`);
      // 1.1.1.0/24 is Cloudflare's resolver prefix, not one of its published proxy ranges, so the
      // operator badge may say Direct; the owner must still be Cloudflare's AS13335.
      assert(c && /AS13335/.test(c.text) && /one\.one\.one\.one/.test(c.text), `1.1.1.1: ${c && `${c.kind} ${c.text.slice(0, 200)}`}`);
      assert(p && p.kind === 'private' && /lab-box/.test(p.text), `10.0.0.5: ${p && `${p.kind} ${p.text.slice(0, 200)}`}`);
      const leaked = await page.evaluate(() => performance.getEntriesByType('resource').some((e) => e.name.includes('10.0.0.5')));
      assert(!leaked, 'the private IP was never sent to any service');
    });
    await run.step('IP Intel in four modes', () => fourModes('ip', IP_DONE));

    /* ---------------- 8. Domain Health ---------------- */
    run.group('8. Domain Health');
    const healthDone = (d) => `document.querySelector('.hlt-hero-domain')?.textContent === '${d}' && !document.querySelector('[data-action="run"]').hidden`;
    await run.step('github.com: score, grouped checks, RDAP expiry', async () => {
      await gotoRoute(page, '#/health?domain=github.com');
      await waitDone(page, healthDone('github.com'), 'github health', 60000);
      const info = await page.evaluate(() => ({
        light: document.querySelector('.hlt-hero')?.dataset.light,
        score: Number(document.querySelector('.hlt-hero')?.dataset.score),
        checks: document.querySelectorAll('.hlt-check').length,
        text: document.querySelector('#page-body').textContent
      }));
      assert(['ok', 'warn', 'error'].includes(info.light) && info.score >= 0 && info.checks >= 12, JSON.stringify({ ...info, text: undefined }));
      assert(/MarkMonitor/.test(info.text), 'RDAP registrar');
    });
    await run.step('Domain Health (github.com) in four modes', () => fourModes('health', healthDone('github.com')));
    await run.step(`${HEALTH_NO_RDAP}: a registry without RDAP → explained; four modes`, async () => {
      await gotoRoute(page, `#/health?domain=${HEALTH_NO_RDAP}`);
      await waitDone(page, healthDone(HEALTH_NO_RDAP), 'no-RDAP health', 60000);
      const ids = await page.evaluate(() => [...document.querySelectorAll('.hlt-check')].map((c) => c.dataset.id));
      assert(ids.includes('rdap.unsupported'), `rdap.unsupported in ${ids}`);
      await fourModes('health-nordap', healthDone(HEALTH_NO_RDAP));
    });

    /* ---------------- 9. About ---------------- */
    run.group('9. About');
    await run.step('About in four modes; the CLI is served next to the page', async () => {
      await gotoRoute(page, 'about');
      const res = await fetch(`${server.url}cli/ssl_origin_scan.py`);
      assert(res.ok && (await res.text()).startsWith('#!'), 'CLI download');
      await fourModes('about', null);
    });

    run.group('Global checks');
    await run.step('no missing i18n keys; TR/EN key sets identical', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations (third-party API failures reported only)', async () => {
      const { issues, external } = splitProblems(await page.problems(), origin);
      const hosts = [...new Set(external.map((e) => (/https:\/\/([^/'\s]+)/.exec(e) || [])[1]).filter(Boolean))];
      if (external.length) notes.push(`${external.length} third-party request failure(s) tolerated: ${hosts.join(', ')}`);
      assert(issues.length === 0, `${issues.length} problem(s):\n          ${issues.join('\n          ')}`);
    });
  } finally {
    await page.close().catch(() => {});
    await browser.close();
    await server.close();
    await rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
  for (const n of notes) process.stdout.write(`  note: ${n}\n`);
  run.finish(opts.shots ? ' — screenshots in tests/e2e/screenshots/integration-*' : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
