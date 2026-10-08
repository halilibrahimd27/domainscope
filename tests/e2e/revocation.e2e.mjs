#!/usr/bin/env node
/**
 * revocation.e2e.mjs — the renewal radar in the page, in a real headless Chrome/Edge: revocation
 * from Cert Spotter (Domain portfolio › Certificates (CT), Certificate › CT logs › "Is it
 * revoked?") and the CLI's --ari / --revocation records in Certificate estate. OFFLINE: Cert
 * Spotter is answered in the page (window.fetch wrapped before the app loads, every request it
 * gets recorded); a network-level guard (CDP Fetch) fails and records any https request that
 * still leaves — the suite asserts none. The page's clock starts at 2026-10-09 12:00 UTC.
 *
 *   node tests/e2e/revocation.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - Certificates (CT): Check CT asks Cert Spotter with expand=revocation and
 *     expand=problem_reporting; a revoked certificate's row says when and why; the revoked row and
 *     the row from an unexpected CA offer the CA's problem-reporting contact (its own text, line
 *     breaks kept, no link made of it; the disclosure opens from the keyboard), a plain row none;
 *     the CSV holds revokedAt and revocationReason;
 *   - Is it revoked?: the card shows the one name it would send and sends nothing before the
 *     click; then one GET with that name only (no hash, no serial, no certificate), the answer
 *     matched by the certificate's SHA-256: revoked (when, why, the CA's contact), kept across a
 *     language switch and another tab without a second request; another certificate not revoked,
 *     with when Cert Spotter last read the CA's revocation list; a CA certificate has no card;
 *   - Certificate estate: a CLI report made with --ari and --revocation adds the renewal-window
 *     and revocation columns, their counts in the overview, the records in a row's details and
 *     the CLI's columns in the CSV; a report without them shows none of it;
 *   - Turkish + dark at 375 px and 320 px: no horizontal scroll in the three places;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; nothing sent.
 *
 * Documentation names only (example.com / .net / .org; the estate fixture's own names).
 */

import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { pinnedClockScript } from './clock.mjs';
import { orderSuites } from './run-all.mjs';
import { spotterRow, CT_PROBLEM_REPORTING } from '../js/ct-fake.mjs';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { CT_EXPORT_COLUMNS } from '../../assets/js/lib/ctwatch.js';
import { ESTATE_ARI_COLUMNS, ESTATE_CSV_COLUMNS, ESTATE_REVOCATION_COLUMNS } from '../../assets/js/lib/estate.js';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  csvHeader, gotoRoute, installDownloadCapture, setLangUi, takeDownloads, waitReady
} from './scan.e2e.mjs';

/** The instant the expectations were written for; the page's clock starts here on every load. */
const NOW = Date.parse('2026-10-09T12:00:00Z');
const fixture = (name) => path.join(FIXTURES, name);
const LE = "C=US, O=Let's Encrypt, CN=R11";
const OTHER_CA = 'C=US, O=Example Other CA, CN=Example Other CA R3';
const OTHER_REPORTING = 'Example Other CA accepts certificate problem reports at:\n  · https://pki.example.org/report\n\nRevocation requests by e-mail: revoke[at]example[dot]org';

/** The certificates the Certificate view loads, with the SHA-256 Cert Spotter's answer carries. */
const leafOf = async (file) => {
  const cert = parseCertificates(await readFile(fixture(file))).certificates[0];
  const der = Buffer.from(cert.der);
  return { der, sha256: createHash('sha256').update(der).digest('hex'), serialHex: cert.serialHex };
};

/** Cert Spotter's answers, by `sub|<domain>` (a subdomain search) or `name|<name>` (one name). */
function spotterAnswers(leaf, leaf2) {
  const R = spotterRow({ names: ['example.com', 'www.example.com'], notBefore: '2026-09-20T00:00:00Z', notAfter: '2026-12-19T00:00:00Z', serial: 11,
    issuer: LE, friendly: "Let's Encrypt", revokedAt: '2026-10-05T09:30:00Z', reason: 1 });
  const N = spotterRow({ names: ['example.com', 'www.example.com'], notBefore: '2026-10-05T10:00:00Z', notAfter: '2027-01-03T10:00:00Z', serial: 12,
    issuer: LE, friendly: "Let's Encrypt" });
  const U = spotterRow({ names: ['shop.example.com'], notBefore: '2026-10-01T00:00:00Z', notAfter: '2026-12-30T00:00:00Z', serial: 13,
    issuer: OTHER_CA, friendly: 'Example Other CA', problemReporting: OTHER_REPORTING });
  const P = spotterRow({ names: ['api.example.com'], notBefore: '2026-09-01T00:00:00Z', notAfter: '2026-11-30T00:00:00Z', serial: 14,
    issuer: LE, friendly: "Let's Encrypt" });
  // "Is it revoked?": crl_leaf.pem revoked as its CRL says (keyCompromise, 2026-09-01 12:00), next
  // to another certificate of the name; crl_leaf2.pem not revoked
  const own = (l, names, extra) => ({ ...spotterRow({ names, notBefore: '2025-01-01T00:00:00Z', notAfter: '2060-01-01T00:00:00Z', ...extra }), cert_sha256: l.sha256 });
  return {
    'sub|example.com': [R, N, U, P],
    'name|www.example.com': [N, own(leaf, ['www.example.com', 'example.com'], { revokedAt: '2026-09-01T12:00:00Z', reason: 1, checkedAt: '2026-10-09T06:00:00Z' })],
    'name|api.example.net': [own(leaf2, ['api.example.net'], { checkedAt: '2026-10-09T06:00:00Z' })]
  };
}

/** In-page Cert Spotter (and crt.sh, never expected): every request recorded in window.__ctLog. */
const fakeScript = (answers) => `(() => {
  const A = ${JSON.stringify(answers)};
  window.__ctLog = [];
  const realFetch = window.fetch.bind(window);
  const json = (v) => new Response(JSON.stringify(v), { status: 200, headers: { 'content-type': 'application/json' } });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://api.certspotter.com/') || url.startsWith('https://crt.sh/')) {
      const u = new URL(url);
      const sub = u.searchParams.get('include_subdomains') === 'true';
      const entry = {
        host: u.host, url, method: (init && init.method) || (input && input.method) || 'GET', body: init && init.body != null ? String(init.body) : null,
        domain: u.searchParams.get('domain'), sub, after: u.searchParams.get('after'), expand: u.searchParams.getAll('expand')
      };
      window.__ctLog.push(entry);
      if (u.host !== 'api.certspotter.com' || entry.after) return json([]);
      return json(A[(sub ? 'sub|' : 'name|') + entry.domain] || []);
    }
    return realFetch(input, init);
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

/** Element screenshot (beyond the viewport if needed); no-op with --no-shots. */
async function shotEl(page, opts, name, selector) {
  if (!opts.shots) return;
  await removeToasts(page);
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    window.scrollTo(0, 0);
    const r = el.getBoundingClientRect();
    return { x: Math.max(0, r.left + window.scrollX - 8), y: Math.max(0, r.top + window.scrollY - 8), width: r.width + 16, height: r.height + 16 };
  }, selector);
  if (!box || !box.width || !box.height) return;
  await mkdir(opts.shotsDir, { recursive: true });
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.min(Math.ceil(box.height), 9000), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(opts.shotsDir, `${name}.png`), Buffer.from(data, 'base64'));
}

/** Full-page screenshot; no-op with --no-shots. */
async function shotPage(page, opts, name) {
  if (!opts.shots) return;
  await removeToasts(page);
  await mkdir(opts.shotsDir, { recursive: true });
  await page.screenshot(path.join(opts.shotsDir, `${name}.png`), { fullPage: true });
}

const removeToasts = (page) => page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
/** Wait for the DataTable's next frame: its rows render on requestAnimationFrame. */
const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
const ctLog = (page) => page.evaluate(() => window.__ctLog.slice());
const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);

/** Elements under `selector` sticking out of the viewport (table scrollers scroll inside). */
const overflowingIn = (page, selector) => page.evaluate((sel) => {
  const root = document.querySelector(sel);
  if (!root) return ['(missing)'];
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of root.querySelectorAll('*')) {
    if (el.closest('pre, .codeblock, .tablist-scroll')) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
}, selector);

/** The CT table's rows: names, flags, the revocation line and whether the CA's contact is offered. */
const ctRows = (page) => page.evaluate(() => [...document.querySelectorAll('.pf-ct-table tbody tr.dt-row')].map((tr) => ({
  names: [...tr.querySelectorAll('td.pf-ct-names .mono')].map((e) => e.textContent).join(' '),
  flags: [...tr.querySelectorAll('[data-flag]')].map((e) => e.dataset.flag),
  revoked: tr.querySelector('[data-role="rev-line"]')?.textContent || null,
  report: !!tr.querySelector('[data-role="rev-report"]')
})));
const setCtFilter = (page, value) => page.evaluate((v) => {
  const s = document.querySelector('[data-role="ct-filter"]');
  s.value = v;
  s.dispatchEvent(new Event('change'));
}, value);
const waitCt = (page) => page.waitFor(() => !!document.querySelector('.pf-ct .pf-head[data-status="done"]')
  && !document.querySelector('[data-action="ct-run"]').hidden, { timeout: 30000, message: 'CT checked' });

/** Open the Certificate view with `file` on its CT logs tab. */
async function certCtTab(page, file, cn) {
  await gotoRoute(page, 'cert');
  if (!(await page.evaluate((c) => document.querySelector('.cert-overview-cn')?.textContent === c, cn))) {
    const reload = await page.evaluate(() => !!document.querySelector('.cert-reload'));
    if (reload) await page.evaluate(() => { document.querySelector('.cert-reload').open = true; });
    await page.setFileInput(reload ? '.cert-reload .filedrop-input' : '.cert-loader-card .filedrop-input', [fixture(file)]);
    await page.waitFor((c) => document.querySelector('.cert-overview-cn')?.textContent === c, { args: [cn], message: `${file} loaded` });
  }
  await removeToasts(page);
  await openCertTab(page, 'ct', '[data-role="rev-card"]');
}

/**
 * Select a tab of the Certificate view and wait for `selector` in it. On a busy machine (after other
 * suites of a run-all) a click right after a file loads was seen to go unanswered: the tab is
 * clicked again once before the step fails, and the failure says which tab was shown.
 */
async function openCertTab(page, id, selector) {
  for (let attempt = 0; ; attempt += 1) {
    await page.click(`.cert-tabs [data-tab="${id}"]`);
    try {
      await page.waitForSelector(selector, { timeout: attempt ? 15000 : 5000 });
      return;
    } catch (err) {
      if (attempt) {
        const state = await page.evaluate(() => ({
          selected: document.querySelector('.cert-tabs [aria-selected="true"]')?.dataset.tab || null,
          host: document.querySelector('.cert-rev-host')?.textContent.replace(/\s+/g, ' ').trim().slice(0, 300) ?? null
        }));
        throw new Error(`${err.message} (tab shown: ${state.selected}; revocation part: ${state.host})`);
      }
    }
  }
}

/** The estate report of the suite: report-a.json with --ari / --revocation records on three certificates. */
async function radarReport(dir) {
  const doc = JSON.parse(await readFile(path.join(FIXTURES, 'estate', 'report-a.json'), 'utf8'));
  const sha = (cn) => Object.keys(doc.certificates).find((k) => doc.certificates[k].subjectCN === cn);
  const ari = (extra) => ({ ca: 'letsencrypt', certId: 'aaaa.AQ', start: null, end: null, explanationURL: null, checkedAt: '2026-10-09T06:00:00Z',
    retryAfter: null, status: 200, error: null, ...extra });
  const rev = (extra) => ({ status: 'good', reason: null, reasonCode: null, time: null, crl: 'http://crl.example.com/test-ca.crl',
    checkedAt: '2026-10-09T06:00:00Z', thisUpdate: '2026-10-09T00:00:00Z', nextUpdate: '2026-10-16T00:00:00Z', signature: 'not-verified', error: null, ...extra });
  Object.assign(doc.certificates[sha('legacy.example.org')], {
    ari: ari({ start: '2026-10-08T00:00:00Z', end: '2026-10-10T00:00:00Z', explanationURL: 'https://ca.example.org/incident-2026-10' }),
    revocation: rev({ status: 'revoked', reason: 'keyCompromise', reasonCode: 1, time: '2026-09-21T10:15:00Z' })
  });
  Object.assign(doc.certificates[sha('CloudFlare Origin Certificate')], {
    ari: ari({ start: '2026-10-20T06:00:00Z', end: '2026-10-22T06:00:00Z' }),
    revocation: rev({})
  });
  Object.assign(doc.certificates[sha('legacy.example.net')], {
    ari: ari({ ca: null, certId: null, status: null, error: 'unsupported' }),
    revocation: rev({ status: 'unknown', crl: null, thisUpdate: null, nextUpdate: null, signature: null, error: 'no-crl' })
  });
  doc.options = { ...doc.options, ari: true, revocation: true };
  const file = path.join(dir, 'estate-radar.json');
  await writeFile(file, JSON.stringify(doc, null, 2));
  return file;
}

/** The estate table: per certificate name, its ARI and revocation cells. */
const estateCells = (page) => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.estate-table tbody tr.dt-row')].map((tr) => {
  const cell = (key) => tr.querySelector(`td.estate-col-${key}`);
  return [tr.querySelector('.estate-cert-name')?.textContent, {
    ari: cell('ari')?.querySelector('[data-ari]')?.dataset.ari || null,
    ariText: cell('ari')?.textContent.replace(/\s+/g, ' ').trim() || '',
    rev: cell('revocation')?.querySelector('[data-revocation]')?.dataset.revocation || null,
    revText: cell('revocation')?.textContent.replace(/\s+/g, ' ').trim() || ''
  }];
})));

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-revocation-e2e-'));
  const leaf = await leafOf('crl_leaf.pem');
  const leaf2 = await leafOf('crl_leaf2.pem');
  const report = await radarReport(tmp);

  run.group('Node: harness');
  await run.step('run-all orders the revocation suite right after portfolio', () => {
    assertEqual(orderSuites(['carry.e2e.mjs', 'revocation.e2e.mjs', 'portfolio.e2e.mjs']), ['portfolio', 'revocation', 'carry'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}; offline: Cert Spotter answered in the page\n`);
  let page = null;
  let netHits = [];
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: pinnedClockScript(NOW) });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript(spotterAnswers(leaf, leaf2)) });
    netHits = await networkGuard(page);
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/about`);
    await waitReady(page);
    await setLangUi(page, 'en');

    run.group('Domain portfolio › Certificates (CT), desktop 1440×900, English, light');
    await run.step('Check CT asks Cert Spotter for the revocation and the CA\'s contact with the certificates', async () => {
      await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.setWorkspaceData('expectedCas', ["Let's Encrypt"])));
      await gotoRoute(page, 'portfolio');
      await page.type('[data-role="pf-domains"]', 'example.com');
      await page.click('.pf-results .tab[data-tab="ct"]');
      await page.waitFor(() => !!document.querySelector('[data-action="ct-run"]'), { message: 'the CT panel' });
      assertEqual(await ctLog(page), [], 'nothing sent before Check CT');
      await page.click('[data-action="ct-run"]');
      await waitCt(page);
      const log = await ctLog(page);
      assertEqual(log.map((x) => `${x.host} ${x.domain} ${x.sub}${x.after ? ' next' : ''}`), ['api.certspotter.com example.com true', 'api.certspotter.com example.com true next'], 'requests');
      assertEqual(log[0].expand, ['dns_names', 'issuer', 'cert_der', 'revocation', 'problem_reporting'], 'expansions');
    });

    await run.step('a revoked row says when and why; it and the unexpected CA\'s row offer the CA\'s contact, a plain row none', async () => {
      await setCtFilter(page, 'all');
      await frames(page);
      const rows = await ctRows(page);
      const by = (names) => rows.find((r) => r.names === names && (names !== 'example.com www.example.com' || r.flags.includes('revoked')));
      const revoked = by('example.com www.example.com');
      assert(revoked, JSON.stringify(rows));
      assert(revoked.flags.includes('revoked'), `flags: ${revoked.flags}`);
      assertEqual(revoked.revoked, 'on Oct 5, 2026, reason: key compromise', 'when and why');
      assert(revoked.report, 'the CA\'s contact on the revoked row');
      const shop = by('shop.example.com');
      assert(shop.flags.includes('unexpected') && shop.report && !shop.revoked, JSON.stringify(shop));
      const api = by('api.example.com');
      assert(api && !api.report && !api.revoked, JSON.stringify(api));
      const renewed = rows.find((r) => r.names === 'example.com www.example.com' && !r.flags.includes('revoked'));
      assert(renewed && !renewed.report, 'the replacement has no contact line');
      const title = await page.evaluate(() => document.querySelector('.pf-ct-table [data-role="rev-line"]').title);
      assertEqual(title, 'Revoked at Oct 5, 2026, 9:30 AM UTC', 'the exact time in its tooltip');
    });

    await run.step('the CA\'s contact: its own text, line breaks kept, no link; the disclosure opens from the keyboard', async () => {
      const sel = '.pf-ct-table tbody tr.dt-row [data-role="rev-report"]';
      await page.evaluate((s) => document.querySelector(s).querySelector('summary').focus(), sel);
      await page.press('Enter');
      await page.waitFor((s) => document.querySelector(s).open, { args: [sel], message: 'opened with Enter' });
      const info = await page.evaluate((s) => {
        const el = document.querySelector(s);
        const body = el.querySelector('.rev-report-text');
        return { text: body.textContent, links: el.querySelectorAll('a').length, ws: getComputedStyle(body).whiteSpace, size: getComputedStyle(body).fontSize, summary: el.querySelector('summary').textContent };
      }, sel);
      assertEqual(info.text, CT_PROBLEM_REPORTING, 'the CA\'s text as it is');
      assertEqual(info.links, 0, 'no link made of it');
      assertEqual(info.ws, 'pre-wrap', 'line breaks kept');
      assertEqual(info.size, '12.5px', 'the table\'s size');
      assertEqual(info.summary, 'Report a problem to the CA', 'summary');
      await shotEl(page, opts, 'revocation-ct-desktop-light-en', '.pf-ct-results');
      await page.press('Enter');
      await page.waitFor((s) => !document.querySelector(s).open, { args: [sel], message: 'closed with Enter' });
    });

    await run.step('the CSV holds when and why it was revoked', async () => {
      await takeDownloads(page);
      await page.click('[data-action="ct-csv"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'CSV' });
      const [csv] = await takeDownloads(page);
      assertEqual(csvHeader(csv.text), [...CT_EXPORT_COLUMNS], 'columns');
      const lines = csv.text.trim().split('\r\n');
      const revoked = lines.find((l) => l.includes('2026-10-05T09:30:00.000Z'));
      assert(revoked && revoked.endsWith(',2026-10-05T09:30:00.000Z,keyCompromise'), revoked);
      assertEqual(lines.filter((l) => l.endsWith(',,')).length, 3, 'the others: empty cells');
      await removeToasts(page);
    });

    run.group('Certificate › CT logs › Is it revoked?');
    await run.step('the card names what it would send and sends nothing before the click', async () => {
      await page.evaluate(() => { window.__ctLog.length = 0; });
      await certCtTab(page, 'crl_leaf.pem', 'www.example.com');
      const info = await page.evaluate(() => ({
        title: document.querySelector('[data-role="rev-card"] .card-title')?.textContent,
        name: document.querySelector('[data-role="rev-name"]')?.textContent,
        run: document.querySelector('[data-action="rev-run"]')?.textContent.trim(),
        state: document.querySelector('[data-role="rev-card"]').dataset.state
      }));
      assertEqual(info, { title: 'Is it revoked?', name: 'www.example.com', run: 'Ask Cert Spotter', state: 'idle' }, 'the card');
      assertEqual(await ctLog(page), [], 'nothing sent');
    });

    await run.step('one GET with the name only; revoked: when, why and the CA\'s contact', async () => {
      await page.click('[data-action="rev-run"]');
      await page.waitFor(() => document.querySelector('[data-role="rev-card"]')?.dataset.status === 'revoked', { message: 'revoked' });
      const log = await ctLog(page);
      assertEqual(log.length, 1, 'one request');
      const [req] = log;
      assertEqual([req.host, req.method, req.body, req.domain, req.sub, req.expand], ['api.certspotter.com', 'GET', null, 'www.example.com', false,
        ['revocation', 'problem_reporting']], 'the request');
      const url = req.url.toLowerCase();
      assert(!url.includes(leaf.sha256) && !url.includes(leaf.serialHex.toLowerCase()) && !url.includes(leaf.der.toString('base64').slice(0, 24).toLowerCase()),
        `only the name leaves the page: ${req.url}`);
      const card = await page.evaluate(() => {
        const c = document.querySelector('[data-role="rev-card"]');
        return { title: c.querySelector('.alert-title')?.textContent, message: c.querySelector('.alert-message')?.textContent, report: !!c.querySelector('[data-role="rev-report"]') };
      });
      assertEqual(card.title, 'Revoked on Sep 1, 2026, 12:00 PM UTC', 'when');
      assert(card.message.startsWith('Reason: key compromise. '), card.message);
      assert(card.report, 'the CA\'s contact');
      await page.evaluate(() => { document.querySelector('[data-role="rev-card"] [data-role="rev-report"]').open = true; });
      const size = await page.evaluate(() => getComputedStyle(document.querySelector('[data-role="rev-card"] .rev-report-text')).fontSize);
      assertEqual(size, '13px', 'the card\'s own size, the Domain portfolio\'s sheet loaded too');
      await shotEl(page, opts, 'revocation-cert-revoked-desktop-light-en', '[data-role="rev-card"]');
    });

    await run.step('the answer stays across a language switch and another tab, without a second request', async () => {
      try {
        await setLangUi(page, 'tr');
        await page.waitForSelector('[data-role="rev-card"][data-status="revoked"]');
        const tr = await text(page, '[data-role="rev-card"]');
        assert(tr.includes('İptal edilmiş mi?') && tr.includes('tarihinde iptal edilmiş') && tr.includes('Gerekçe: anahtar ele geçirilmiş.'), tr);
        await page.click('.cert-tabs [data-tab="names"]');
        await openCertTab(page, 'ct', '[data-role="rev-card"][data-status="revoked"]');
        assertEqual((await ctLog(page)).length, 1, 'still one request');
      } finally {
        await setLangUi(page, 'en');
      }
    });

    await run.step('another certificate: not revoked, with when Cert Spotter last read the CA\'s list; a CA certificate has no card', async () => {
      await certCtTab(page, 'crl_leaf2.pem', 'api.example.net');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="rev-card"]').dataset.state), 'idle', 'its own card, not the last one\'s answer');
      await page.click('[data-action="rev-run"]');
      await page.waitFor(() => document.querySelector('[data-role="rev-card"]')?.dataset.status === 'good', { message: 'good' });
      const card = [await text(page, '[data-role="rev-card"] .alert-title'), await text(page, '[data-role="rev-card"] .alert-message')];
      assertEqual(card, ['Not revoked', 'Cert Spotter last read the CA’s revocation list 6 hours ago.'], 'not revoked');
      const log = await ctLog(page);
      assertEqual(log.map((x) => x.domain), ['www.example.com', 'api.example.net'], 'one request each');
      await shotEl(page, opts, 'revocation-cert-good-desktop-light-en', '[data-role="rev-card"]');
      // a CA certificate: Cert Spotter lists server certificates by name, so no card
      await page.evaluate(() => { document.querySelector('.cert-reload').open = true; });
      await page.setFileInput('.cert-reload .filedrop-input', [fixture('crl_ca.pem')]);
      await page.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === 'Example Test CRL CA', { message: 'the CA loaded' });
      await removeToasts(page);
      await openCertTab(page, 'ct', '.cert-ct');
      await frames(page);
      assert(await page.evaluate(() => !document.querySelector('[data-role="rev-card"]') && !document.querySelector('.cert-rev-host')), 'no card for a CA');
    });

    run.group('Certificate estate: the CLI\'s --ari and --revocation');
    await run.step('a report with the records: the two columns, their counts, the cells', async () => {
      await gotoRoute(page, 'estate');
      await page.setFileInput('.estate-page .estate-drop .filedrop-input', [report]);
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, { message: '9 rows', timeout: 15000 });
      await frames(page);
      const heads = await page.evaluate(() => [...document.querySelectorAll('.estate-table thead th')].map((th) => th.textContent.trim()));
      assert(heads.includes('Renewal window (ARI)') && heads.includes('Revocation'), heads.join(' | '));
      const lines = await page.evaluate(() => [...document.querySelectorAll('.estate-line')].map((l) => l.textContent.replace(/\s+/g, ' ').trim()));
      assert(lines.includes('Renewal window (ARI)renew now 1overdue 0not open yet 1not read 1'), lines.join(' / '));
      assert(lines.includes('Revocationrevoked 1unknown 1not revoked 1'), lines.join(' / '));
      const cells = await estateCells(page);
      assertEqual([cells['legacy.example.org'].ari, cells['legacy.example.org'].rev], ['open', 'revoked'], 'legacy.example.org');
      assert(cells['legacy.example.org'].ariText.includes('open: renew now'), cells['legacy.example.org'].ariText);
      assertEqual(cells['legacy.example.org'].revText, 'Revoked on Sep 21, 2026, reason: key compromise', 'revoked');
      assertEqual([cells['CloudFlare Origin Certificate'].ari, cells['CloudFlare Origin Certificate'].rev], ['before', 'good'], 'the Origin CA certificate');
      assert(cells['CloudFlare Origin Certificate'].ariText.endsWith('opens in 11 days'), cells['CloudFlare Origin Certificate'].ariText);
      assertEqual(cells['legacy.example.net'], {
        ari: 'error', ariText: 'no ARI server known for this CA', rev: 'unknown', revText: 'Unknown The certificate names no CRL to read (OCSP is not asked).'
      }, 'legacy.example.net');
      assertEqual(await page.evaluate(() => document.querySelector('.estate-stats [data-filter="all"] .stat-value')?.textContent), '9', 'all');
      await shotPage(page, opts, 'revocation-estate-desktop-light-en');
    });

    await run.step('a row\'s details: the window with times, the CA\'s explanation, the CRL', async () => {
      await page.evaluate(() => {
        const tr = [...document.querySelectorAll('.estate-table tbody tr.dt-row')].find((r) => r.querySelector('.estate-cert-name')?.textContent === 'legacy.example.org');
        tr.querySelector('.dt-expand-btn').click();
      });
      const details = await page.waitFor(() => document.querySelector('.estate-table .estate-details')?.textContent.replace(/\s+/g, ' '), { message: 'details' });
      assert(details.includes('Renewal window') && details.includes('Oct 8, 2026, 12:00 AM UTC – Oct 10, 2026, 12:00 AM UTC'), details);
      assert(details.includes('CA asked (ARI)') && details.includes('letsencrypt'), 'the CA asked');
      assert(details.includes('Revoked · on Sep 21, 2026, reason: key compromise'), details);
      assert(details.includes('http://crl.example.com/test-ca.crl') && details.includes('CRL issued'), 'the CRL');
      const link = await page.evaluate(() => {
        const a = document.querySelector('.estate-table .estate-details a.ext-link');
        return a ? { href: a.getAttribute('href'), rel: a.rel, text: a.textContent.trim() } : null;
      });
      assertEqual(link && [link.href, link.rel], ['https://ca.example.org/incident-2026-10', 'noopener noreferrer'], 'the CA\'s explanation, opened by the user');
      assert(!(await page.evaluate(() => [...document.querySelectorAll('.estate-table .estate-details a')].some((a) => a.getAttribute('href').startsWith('http://crl.')))), 'the CRL is text');
      await shotEl(page, opts, 'revocation-estate-details-desktop-light-en', '.estate-table');
    });

    await run.step('the CSV: the CLI\'s columns, then the ARI and revocation ones', async () => {
      await takeDownloads(page);
      await page.click('.estate-table [data-export="csv"]');
      const [file] = await takeDownloads(page);
      assertEqual(csvHeader(file.text), [...ESTATE_CSV_COLUMNS, ...ESTATE_ARI_COLUMNS, ...ESTATE_REVOCATION_COLUMNS].map((c) => c.key), 'columns');
      assert(file.text.includes(',2026-10-08T00:00:00Z,2026-10-10T00:00:00Z,https://ca.example.org/incident-2026-10,,revoked,2026-09-21T10:15:00Z,keyCompromise,'), 'a revoked row');
      await removeToasts(page);
    });

    await run.step('a report without them shows none of it', async () => {
      await page.click('[data-action="estate-forget"]');
      await page.waitFor(() => !document.querySelector('.estate-report') && document.querySelector('.estate-page .empty'), { message: 'forgotten' });
      await page.setFileInput('.estate-page .estate-drop .filedrop-input', [path.join(FIXTURES, 'estate', 'report-a.json')]);
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, { message: 'report-a' });
      const info = await page.evaluate(() => ({
        heads: [...document.querySelectorAll('.estate-table thead th')].map((th) => th.textContent.trim()),
        lines: document.querySelectorAll('.estate-line').length
      }));
      assert(!info.heads.includes('Renewal window (ARI)') && !info.heads.includes('Revocation'), info.heads.join(' | '));
      assertEqual(info.lines, 2, 'the expiry and kinds lines only');
    });

    run.group('Turkish + dark, phones 375 and 320 px');
    await run.step('Certificate estate at 375 px (Turkish, dark): cards, no horizontal scroll', async () => {
      await removeToasts(page);
      await page.click('[data-action="estate-forget"]');
      await page.waitFor(() => !document.querySelector('.estate-report') && document.querySelector('.estate-page .empty'), { message: 'forgotten again' });
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.setFileInput('.estate-page .estate-drop .filedrop-input', [report]);
      await page.waitFor(() => document.querySelectorAll('.estate-table tbody tr.dt-row').length === 9, { message: '9 rows (TR)' });
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 375, { message: 'phone viewport' });
      await frames(page);
      const cells = await estateCells(page);
      assertEqual(cells['legacy.example.org'].revText, 'İptal edilmiş 21 Eyl 2026 tarihinde, gerekçe: anahtar ele geçirilmiş', 'Turkish');
      assert(cells['CloudFlare Origin Certificate'].ariText.endsWith('11 gün sonra açılıyor'), cells['CloudFlare Origin Certificate'].ariText);
      await assertNoHorizontalScroll(page, 'estate 375 TR dark');
      assertEqual(await overflowingIn(page, '.estate-page'), [], 'the page inside 375 px');
      await shotPage(page, opts, 'revocation-estate-phone-dark-tr');
    });

    await run.step('Is it revoked? at 375 and 320 px (Turkish, dark)', async () => {
      await certCtTab(page, 'crl_leaf.pem', 'www.example.com');
      await page.waitForSelector('[data-role="rev-card"][data-status="revoked"]');
      await page.evaluate(() => { document.querySelector('[data-role="rev-card"] [data-role="rev-report"]').open = true; });
      await assertNoHorizontalScroll(page, 'cert card 375 TR dark');
      assertEqual(await overflowingIn(page, '[data-role="rev-card"]'), [], 'the card inside 375 px');
      await shotEl(page, opts, 'revocation-cert-revoked-phone-dark-tr', '[data-role="rev-card"]');
      await page.setViewport({ width: 320, height: 720, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 320, { message: '320 px' });
      await frames(page);
      await assertNoHorizontalScroll(page, 'cert card 320 TR dark');
      assertEqual(await overflowingIn(page, '[data-role="rev-card"]'), [], 'the card inside 320 px');
    });

    await run.step('the CT table at 375 and 320 px (Turkish, dark): the revoked row as a card, the CA\'s contact open', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 375, { message: 'phone viewport' });
      await gotoRoute(page, 'portfolio');
      await page.click('.pf-results .tab[data-tab="ct"]');
      await page.waitFor(() => document.querySelectorAll('.pf-ct-table tbody tr.dt-row').length > 0, { message: 'the last check, shown again' });
      await setCtFilter(page, 'all');
      await frames(page);
      const rows = await ctRows(page);
      const revoked = rows.find((r) => r.flags.includes('revoked'));
      assertEqual(revoked && revoked.revoked, '5 Eki 2026 tarihinde, gerekçe: anahtar ele geçirilmiş', 'Turkish line');
      await page.evaluate(() => { document.querySelectorAll('.pf-ct-table [data-role="rev-report"]').forEach((d) => { d.open = true; }); });
      await assertNoHorizontalScroll(page, 'CT 375 TR dark');
      assertEqual(await overflowingIn(page, '.pf-ct-results'), [], 'the results inside 375 px');
      await shotPage(page, opts, 'revocation-ct-phone-dark-tr');
      await page.setViewport({ width: 320, height: 720, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth === 320, { message: '320 px' });
      await frames(page);
      await assertNoHorizontalScroll(page, 'CT 320 TR dark');
      assertEqual(await overflowingIn(page, '.pf-ct-results'), [], 'the results inside 320 px');
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    await run.step('desktop, Turkish, dark: the three places', async () => {
      await page.setViewport({ width: 1440, height: 900 }); // also after a failed phone step
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await frames(page);
      await assertNoHorizontalScroll(page, 'CT desktop TR dark');
      await shotEl(page, opts, 'revocation-ct-desktop-dark-tr', '.pf-ct-results');
      await certCtTab(page, 'crl_leaf.pem', 'www.example.com');
      await shotEl(page, opts, 'revocation-cert-revoked-desktop-dark-tr', '[data-role="rev-card"]');
      await gotoRoute(page, 'estate');
      await frames(page);
      await assertNoHorizontalScroll(page, 'estate desktop TR dark');
      await shotPage(page, opts, 'revocation-estate-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Quality');
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations; nothing sent to the network', async () => {
      await assertClean(page, 'revocation', origin);
      assertEqual(netHits, [], 'https requests that reached the network');
      assertEqual((await ctLog(page)).filter((x) => x.host !== 'api.certspotter.com'), [], 'crt.sh never asked');
    });
  } finally {
    if (page) await page.close().catch(() => {});
    await browser.close();
    await server.close();
    await rm(tmp, { recursive: true, force: true });
  }
  run.finish();
}

main().catch((err) => {
  process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
