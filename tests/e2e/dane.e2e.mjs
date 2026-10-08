#!/usr/bin/env node
/**
 * dane.e2e.mjs — end-to-end test of the DANE / TLSA check (ui/dane-panel.js over lib/dane.js)
 * in the Certificate view and in SSL Targets, in a real headless Chrome/Edge. OFFLINE: every DNS
 * answer comes from a fake DoH zone inside the page, nothing leaves the page.
 *
 *   node tests/e2e/dane.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * Setup (installed with Page.addScriptToEvaluateOnNewDocument before the app loads):
 *   - a fake DoH zone answered inside the page for every resolver: MX, A and TLSA records, the AD
 *     flag per name and an RRSIG (for its original TTL) when the query sets DO. Every query is
 *     recorded with its DO / CD bits in window.__dnsLog; any other external fetch gets a 503 and
 *     is recorded in window.__externalFetches. A name listed in window.__dnsHang gets no answer
 *     at all (a silent resolver): the request ends only when it is aborted, and window.__dnsHung
 *     records when it started and ended;
 *   - a network-level guard (CDP Fetch): any https request that still reached the network is
 *     failed and recorded; the suite asserts it stays empty;
 *   - the new certificate is tests/fixtures/cli_renewed_wild.pem (*.wild.example.net), the old
 *     one ec_wildcard.pem (another key): the zone's TLSA records pin one or the other.
 *
 * What is checked:
 *   - Certificate view: the DANE / TLSA tab sends nothing until "Check TLSA records" is clicked;
 *     then exactly one MX and one TLSA query per endpoint, all with DO; the wildcard is not looked
 *     up. Verdicts: the MX host that pins the old key "will break" (with the exact record to add
 *     and 2 × the signed TTL), a third-party MX is "another certificate", the apex name is safe;
 *     the certificate's own TLSA values; CSV export; Turkish, dark mode, 375 px phone; keyboard
 *     focus follows Check → Stop → Check again; Stop ends a check stuck on a silent resolver at
 *     once ("cancelled"); the same certificate in another file (with a CA certificate) gets a
 *     check of its own, and the first file loaded again shows its own;
 *   - SSL Targets: the DANE tab follows Verify, a summary line points to it when the scan mined
 *     mail servers, the check adds the covered hosts the scan found (one breaks, one is not
 *     DNSSEC-validated), the tab badge, the scan's full JSON carries `dane`, and a new scan
 *     cancels the old run's running check;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations.
 */

import { readFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import { SOURCES as LIB_SOURCES } from '../../assets/js/lib/sources.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions,
  createRunner, csvHeader, gotoRoute, installDownloadCapture, openScanOptions, setLangUi, sleep, takeDownloads, waitReady
} from './scan.e2e.mjs';

/* ------------------------------------------------------------------------ */
/* Test data                                                                */
/* ------------------------------------------------------------------------ */

const NEW_FILE = path.join(FIXTURES, 'cli_renewed_wild.pem');
const certOf = async (file) => parseCertificates(await readFile(path.join(FIXTURES, file))).leaf;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** The fake zone: the MX host pins the OLD key, the apex name the NEW certificate. */
function buildZone(NEW, OLD) {
  const tlsa = (usage, selector, matchingType, data) => ({ usage, selector, matchingType, data });
  return {
    'example.net': { MX: [{ preference: 10, exchange: 'mail.wild.example.net' }, { preference: 20, exchange: 'mx.example.org' }], A: ['192.0.2.1'], ad: true },
    'wild.example.net': { A: ['192.0.2.10'], ad: true },
    'www.wild.example.net': { A: ['192.0.2.10'], ad: true },
    'api.wild.example.net': { A: ['192.0.2.11'], ad: true },
    'mail.wild.example.net': { A: ['192.0.2.25'], ad: true },
    '_25._tcp.mail.wild.example.net': { TLSA: [tlsa(3, 1, 1, sha256(OLD.spkiDer))], ad: true, sig: 3600 },
    '_25._tcp.mx.example.org': { TLSA: [tlsa(3, 1, 1, '5a'.repeat(32))], ad: true, sig: 3600 },
    '_443._tcp.wild.example.net': { TLSA: [tlsa(3, 0, 1, sha256(NEW.der))], ad: true, sig: 300 },
    '_443._tcp.www.wild.example.net': { TLSA: [tlsa(3, 1, 1, sha256(OLD.spkiDer))], ad: true, sig: 1800 },
    '_443._tcp.api.wild.example.net': { TLSA: [tlsa(3, 1, 1, sha256(OLD.spkiDer))], ad: false }
  };
}

/* ------------------------------------------------------------------------ */
/* In-page fake and network guard                                           */
/* ------------------------------------------------------------------------ */

/**
 * The zone answered inside the page for every DoH resolver. Names under a zone apex that are not
 * listed get NXDOMAIN (or NOERROR / NODATA when a listed name lies below them), with an SOA.
 */
const fakeZoneScript = (zone) => `(() => {
  const ZONE = ${JSON.stringify(zone)};
  const APEXES = ['example.net', 'example.org'];
  const SOA = { mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
  const apexOf = (name) => APEXES.find((a) => name === a || name.endsWith('.' + a)) || null;
  const answer = (name, type, dnssecOk) => {
    const node = ZONE[name];
    const apex = apexOf(name);
    const soa = apex ? [{ name: apex, type: 'SOA', ttl: 300, data: SOA }] : [];
    if (!node) {
      const exists = Object.keys(ZONE).some((k) => k.endsWith('.' + name));
      return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', ad: true, answers: [], authorities: soa };
    }
    const ttl = node.sig || 300;
    const answers = (node[type] || []).map((data) => ({ name, type, ttl, data }));
    if (answers.length && node.sig && dnssecOk) {
      answers.push({ name, type: 'RRSIG', ttl, data: {
        typeCovered: type, algorithm: 13, labels: name.split('.').length, originalTtl: node.sig,
        expiration: new Date('2030-01-01T00:00:00Z'), inception: new Date('2026-01-01T00:00:00Z'),
        keyTag: 4242, signerName: apex || name, signature: 'AAAA'
      } });
    }
    return { rcode: 'NOERROR', ad: node.ad !== false, answers, authorities: answers.length ? [] : soa };
  };
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.__dnsLog = [];
  window.__externalFetches = [];
  window.__dnsHang = [];
  window.__dnsHung = [];
  /** No answer until the request is aborted (a resolver that never replies). */
  const silence = (name, signal) => new Promise((resolve, reject) => {
    const entry = { name, start: Date.now(), end: null };
    window.__dnsHung.push(entry);
    const stop = () => {
      entry.end = Date.now();
      reject(signal.reason || new DOMException('aborted', 'AbortError'));
    };
    if (!signal) return;
    if (signal.aborted) stop();
    else signal.addEventListener('abort', stop, { once: true });
  });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (new URL(url, location.href).origin === location.origin) return realFetch(input, init);
      window.__externalFetches.push(url);
      return new Response('blocked by the E2E harness', { status: 503 });
    }
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const query = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1])));
    const q = query.questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    const dnssecOk = !!(query.edns && query.edns.dnssecOk);
    window.__dnsLog.push({ name, type: q.type, do: dnssecOk, cd: !!query.flags.cd });
    if (window.__dnsHang.includes(name)) return silence(name, init && init.signal);
    const out = apexOf(name) ? answer(name, q.type, dnssecOk) : { rcode: 'NXDOMAIN', ad: false, answers: [], authorities: [] };
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true, ad: out.ad }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities, edns: { dnssecOk }
    }), { headers: { 'content-type': 'application/dns-message' } });
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

/* ------------------------------------------------------------------------ */
/* Page helpers                                                             */
/* ------------------------------------------------------------------------ */

/** Element screenshot (beyond the viewport if needed); no-op with --no-shots. */
async function shotEl(page, opts, name, selector) {
  if (!opts.shots) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
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

/** Elements of `selector` sticking out of the viewport (tables and code scroll inside). */
const overflowingIn = (page, selector) => page.evaluate((sel) => {
  const root = document.querySelector(sel);
  if (!root) return ['(missing)'];
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of root.querySelectorAll('*')) {
    if (el.closest('.dt-scroll, pre, .codeblock')) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
}, selector);

/** DNS queries of the given types recorded since index `from`. */
const dnsLog = (page, from = 0, types = ['MX', 'TLSA']) => page.evaluate((f, ty) => window.__dnsLog.slice(f).filter((q) => ty.includes(q.type)), from, types);
const dnsCount = (page) => page.evaluate(() => window.__dnsLog.length);

/** The data-action of the focused element, else its tag name ('BODY' when the focus fell to the page). */
const focusedAction = (page) => page.evaluate(() => {
  const a = document.activeElement;
  return (a && a.dataset && a.dataset.action) || (a ? a.tagName : null);
});

/** The DANE table rows under `root`: [{ qname, status, dnssec, recs }]. */
const readRows = (page, root) => page.evaluate((r) => [...document.querySelectorAll(`${r} .dane-table tbody tr.dt-row`)].map((tr) => ({
  qname: tr.querySelector('.dane-qname')?.textContent || '',
  status: tr.querySelector('[data-dane-status]')?.dataset.daneStatus || '',
  recs: [...tr.querySelectorAll('[data-rec]')].map((x) => x.dataset.rec)
})), root);
const byQname = (rows) => Object.fromEntries(rows.map((r) => [r.qname, r]));

/** Are the verdict and the TLSA name of every DANE row under `root` inside the viewport (no table scroll needed)? */
const verdictsVisible = (page, root) => page.evaluate((r) => {
  const vw = document.documentElement.clientWidth;
  const rows = [...document.querySelectorAll(`${r} .dane-table tbody tr.dt-row`)];
  const inside = (el) => {
    const box = el ? el.getBoundingClientRect() : null;
    return !!box && box.width > 0 && box.right <= vw + 1;
  };
  return rows.length > 0 && rows.every((tr) => inside(tr.querySelector('[data-dane-status]'))
    && [...tr.querySelectorAll('.dane-qname, .dane-verdict-ep')].some(inside));
}, root);

/** Click "Check TLSA records" under `root` and wait for the finished result. */
async function runCheck(page, root) {
  const before = await page.evaluate((r) => document.querySelector(`${r} .dane-meta`)?.textContent || '', root);
  await page.click(`${root} [data-action="dane-run"]`);
  await page.waitFor((r, b) => {
    const p = document.querySelector(`${r} .dane-panel`);
    return p && p.dataset.state === 'done' && (document.querySelector(`${r} .dane-meta`)?.textContent || '') !== b;
  }, { args: [root, before], timeout: 20000, message: 'DANE check done' });
  await sleep(100);
}

async function settleScroll(page) {
  let last = null;
  for (let i = 0; i < 40; i += 1) {
    const y = await page.evaluate(() => Math.round(window.scrollY));
    if (y === last) return;
    last = y;
    await sleep(120);
  }
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const NEW = await certOf('cli_renewed_wild.pem');
  const OLD = await certOf('ec_wildcard.pem');
  const NEW_SPKI = sha256(NEW.spkiDer).toUpperCase();
  // The same certificate with a CA certificate in its file: another chain, so another check.
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-dane-e2e-'));
  const WITH_CA = path.join(tmp, 'renewed_with_ca.pem');
  await writeFile(WITH_CA, `${await readFile(NEW_FILE, 'utf8')}${await readFile(path.join(FIXTURES, 'cli_private_ca.pem'), 'utf8')}`);

  run.group('Node: harness');
  await run.step('run-all orders the dane suite right after cert', () => {
    assertEqual(orderSuites(['global.e2e.mjs', 'dane.e2e.mjs', 'cert.e2e.mjs', 'verify.e2e.mjs']), ['verify', 'cert', 'dane', 'global'], 'order');
  });
  await run.step('the fixtures are a real renewal: another key, the same names', () => {
    assert(sha256(NEW.spkiDer) !== sha256(OLD.spkiDer), 'a new key');
    assertEqual(NEW.hostnames, OLD.hostnames, 'names');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: fake DoH zone (example.net, example.org)\n`);
  let page = null;
  let netHits = [];
  const CERT = '.cert-tabs';
  const SCAN = '.scan-tab-dane';
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    netHits = await networkGuard(page);
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeZoneScript(buildZone(NEW, OLD)) });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Certificate view (desktop 1440×900, English, light)');
    await run.step('seed offline scan options, load the new certificate, open DANE / TLSA: nothing is sent', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      const known = LIB_SOURCES.map((s) => s.id);
      await page.evaluate((k) => {
        localStorage.setItem('ssds.scan.options', JSON.stringify({ sources: [], knownSources: k, bruteforce: 'off', permutations: false, originHints: false }));
      }, known);
      await page.reload();
      await waitReady(page);
      await gotoRoute(page, 'cert');
      await page.setFileInput('.cert-loader-card .filedrop-input', [NEW_FILE]);
      await page.waitFor(() => document.querySelector('.cert-overview-cn'), { message: 'certificate loaded' });
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
      const tabs = await page.evaluate(() => [...document.querySelectorAll('.cert-tabs .tab[data-tab]')].map((b) => b.dataset.tab));
      assertEqual(tabs, ['names', 'details', 'chain', 'caa', 'dane', 'ct', 'pem'], 'tab order');
      await page.click('.cert-tabs .tab[data-tab="dane"]');
      await page.waitFor(() => document.querySelector('.cert-tabs [data-dane="panel"]'), { message: 'DANE panel' });
      await sleep(300);
      assertEqual(await dnsLog(page), [], 'opening the tab sends no MX or TLSA query');
      const info = await page.evaluate(() => ({
        plan: document.querySelector('.cert-tabs [data-dane="plan"]')?.textContent || '',
        notes: [...document.querySelectorAll('.cert-tabs .dane-note')].map((n) => n.textContent).join(' | '),
        state: document.querySelector('.cert-tabs .dane-panel')?.dataset.state
      }));
      assert(/mail servers of example\.net \(port 25\) and 1 name \(port 443\)/.test(info.plan), `plan: ${info.plan}`);
      assert(/\*\.wild\.example\.net/.test(info.notes) && /_443\._tcp\.www\.wild\.example\.net/.test(info.notes), `wildcard note: ${info.notes}`);
      assertEqual(info.state, 'idle', 'idle');
    });

    await run.step('the certificate\'s own TLSA values are computed locally', async () => {
      await page.evaluate(() => { document.querySelector('.cert-tabs [data-dane="values"]').open = true; });
      const text = await page.waitFor(() => {
        const s = document.querySelector('.cert-tabs [data-dane="values"] pre')?.textContent || '';
        return s || false;
      }, { message: 'values rendered' });
      assert(text.startsWith(`3 1 1 ${NEW_SPKI}`), `first line: ${text.split('\n')[0]}`);
      assertEqual(await dnsLog(page), [], 'still nothing sent');
      await shotEl(page, opts, 'dane-cert-desktop-light-en-idle', '.cert-tabs');
      await page.evaluate(() => { document.querySelector('.cert-tabs [data-dane="values"]').open = false; });
    });

    await run.step('Check: one MX + three TLSA queries, all with DO; verdicts, headline and the record to publish', async () => {
      const from = await dnsCount(page);
      await runCheck(page, CERT);
      const q = await dnsLog(page, from);
      assertEqual(q.map((x) => `${x.type} ${x.name}`).sort(), [
        'MX example.net', 'TLSA _25._tcp.mail.wild.example.net', 'TLSA _25._tcp.mx.example.org', 'TLSA _443._tcp.wild.example.net'
      ], 'queries');
      assert(q.every((x) => x.do && !x.cd), 'DO set, CD clear');
      const rows = byQname(await readRows(page, CERT));
      assertEqual(rows['_25._tcp.mail.wild.example.net'].status, 'danger', 'MX host pinning the old key');
      assertEqual(rows['_25._tcp.mail.wild.example.net'].recs, ['no'], 'its record does not match');
      assertEqual(rows['_25._tcp.mx.example.org'].status, 'not-covered', 'third-party MX');
      assertEqual(rows['_443._tcp.wild.example.net'].status, 'safe', 'apex name');
      const out = await page.evaluate(() => ({
        head: document.querySelector('.cert-tabs [data-dane-head]')?.dataset.daneHead,
        publish: document.querySelector('.cert-tabs [data-dane="publish"] pre')?.textContent || '',
        wait: document.querySelector('.cert-tabs [data-dane="wait"]')?.textContent || '',
        card: document.querySelector('.cert-tabs [data-dane-publish]')?.dataset.danePublish,
        first: document.querySelector('.cert-tabs .dane-table tbody tr.dt-row [data-dane-status]')?.dataset.daneStatus
      }));
      assertEqual(out.head, 'danger', 'headline');
      assertEqual(out.card, 'error', 'the publish card is an error: an endpoint would break');
      assertEqual(out.publish, `_25._tcp.mail.wild.example.net. IN TLSA 3 1 1 ${NEW_SPKI}`, 'record to publish');
      assert(/\(2 h\)/.test(out.wait), `wait: ${out.wait}`);
      assertEqual(out.first, 'danger', 'worst first');
      const heads = await page.evaluate(() => [...document.querySelectorAll('.cert-tabs .dane-table thead th:not(.dt-expander-col)')].map((th) => th.textContent.trim()).filter(Boolean));
      assertEqual(heads, ['Result', 'TLSA name', 'DNSSEC', 'TLSA records'], 'the verdict comes first');
    });

    await run.step('row details: the signed TTL, the notes and the records to add; CSV export', async () => {
      await page.click('.cert-tabs .dane-table tbody tr.dt-row .dt-expand-btn');
      const det = await page.waitFor(() => document.querySelector('.cert-tabs .dane-details')?.textContent || false, { message: 'details' });
      assert(/1 h \(original TTL, from the signature\)/.test(det), `details TTL: ${det}`);
      assert(det.includes(`IN TLSA 3 1 1 ${NEW_SPKI}`), 'records to add in the details');
      await shotEl(page, opts, 'dane-cert-desktop-light-en', '.cert-tabs');
      await takeDownloads(page);
      await page.click('.cert-tabs .dane-table [data-export="csv"]');
      const [csv] = await takeDownloads(page);
      assert(csv && /^dane.*\.csv$/.test(csv.name), `download: ${csv && csv.name}`);
      assertEqual(csvHeader(csv.text), ['tlsa_name', 'service', 'port', 'host', 'via', 'status', 'dnssec', 'records', 'add_records', 'wait_seconds'], 'CSV header');
      assert(/_25\._tcp\.mail\.wild\.example\.net,smtp,25,mail\.wild\.example\.net,example\.net,danger,true,/.test(csv.text), 'danger row in the CSV');
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
    });

    await run.step('the same certificate in a file with a CA certificate: no check yet, nothing sent; the first file again shows its own check', async () => {
      const from = await dnsCount(page);
      const load = async (file, count) => {
        await page.evaluate(() => {
          document.querySelectorAll('.toast').forEach((el) => el.remove());
          document.querySelector('details.cert-reload').open = true;
        });
        await page.setFileInput('.cert-reload .filedrop-input', [file]);
        await page.waitFor((n) => !!document.querySelector('.toast') && (n > 1) === !!document.querySelector('[data-role="cert-select"]'),
          { args: [count], message: `${path.basename(file)} loaded` });
        await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
        return page.waitFor(() => {
          const panel = document.querySelector('.cert-tabs .dane-panel');
          return panel ? { state: panel.dataset.state, head: document.querySelector('.cert-tabs [data-dane-head]')?.dataset.daneHead || null } : false;
        }, { message: 'DANE panel' });
      };
      assertEqual(await load(WITH_CA, 2), { state: 'idle', head: null }, 'another chain: not the check of the certificate alone');
      assertEqual(await load(NEW_FILE, 1), { state: 'done', head: 'danger' }, 'the certificate alone again: its own check');
      assertEqual(await dnsLog(page, from), [], 'nothing sent');
    });

    run.group('Languages, themes, phone (Certificate view)');
    await run.step('Turkish + dark: the result is re-rendered from the kept job, no raw keys', async () => {
      const from = await dnsCount(page);
      await setLangUi(page, 'tr');
      await page.waitFor(() => document.querySelector('.cert-tabs .dane-panel')?.dataset.state === 'done', { message: 'DANE result after re-mount' });
      const text = await page.evaluate(() => document.querySelector('.cert-tabs .dane-panel')?.innerText || '');
      assert(/uç nokta yeni sertifikayı reddeder/.test(text), 'Turkish headline');
      assert(/Bozulacak/.test(text) && /Güvenli/.test(text), 'Turkish statuses');
      assertEqual(text.match(/\bdane\.[\w.-]+|\{[a-zA-Z]+\}/g) || [], [], 'raw keys or placeholders');
      assertEqual(await dnsLog(page, from), [], 'a language switch sends nothing');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await sleep(200);
      await assertNoHorizontalScroll(page, 'desktop dark TR');
      await shotEl(page, opts, 'dane-cert-desktop-dark-tr', '.cert-tabs');
    });

    await run.step('phone 375×812: TR dark and EN light fit without horizontal scroll', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await sleep(300);
      await assertNoHorizontalScroll(page, 'phone dark TR');
      assertEqual(await overflowingIn(page, '.cert-tabs .dane-panel'), [], 'DANE panel inside 375 px (TR dark)');
      assert(await verdictsVisible(page, '.cert-tabs'), 'every verdict and name visible on the phone without scrolling the table');
      await shotEl(page, opts, 'dane-cert-phone-dark-tr', '.cert-tabs');
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.waitFor(() => document.querySelector('.cert-tabs .dane-panel')?.dataset.state === 'done', { message: 'DANE result (EN)' });
      await sleep(200);
      await assertNoHorizontalScroll(page, 'phone light EN');
      assertEqual(await overflowingIn(page, '.cert-tabs .dane-panel'), [], 'DANE panel inside 375 px (EN light)');
      await shotEl(page, opts, 'dane-cert-phone-light-en', '.cert-tabs');
      await page.setViewport({ width: 1440, height: 900 });
      await sleep(200);
    });

    await run.step('keyboard: Enter on the run button starts a new check; the focus comes back to it', async () => {
      const from = await dnsCount(page);
      await page.evaluate(() => document.querySelector('.cert-tabs [data-action="dane-run"]').focus());
      const before = await page.evaluate(() => document.querySelector('.cert-tabs .dane-meta')?.textContent || '');
      await page.press('Enter');
      await page.waitFor((b) => document.querySelector('.cert-tabs .dane-panel')?.dataset.state === 'done'
        && (document.querySelector('.cert-tabs .dane-meta')?.textContent || '') !== b, { args: [before], timeout: 20000, message: 'second check' });
      assertEqual((await dnsLog(page, from)).length, 4, 'a second check sends the same four queries');
      assertEqual(await focusedAction(page), 'dane-run', 'focus on "Check again", not on <body>');
    });

    await run.step('Stop: a check stuck on a silent resolver ends at once as cancelled; focus Check → Stop → Check again', async () => {
      await page.evaluate(() => { window.__dnsHang = ['_443._tcp.wild.example.net']; });
      const hung0 = await page.evaluate(() => window.__dnsHung.length);
      await page.evaluate(() => document.querySelector('.cert-tabs [data-action="dane-run"]').focus());
      await page.press('Enter');
      await page.waitFor((n) => window.__dnsHung.length > n, { args: [hung0], message: 'the TLSA query hangs' });
      const running = await page.evaluate(() => ({
        state: document.querySelector('.cert-tabs .dane-panel')?.dataset.state,
        run: document.querySelector('.cert-tabs [data-action="dane-run"]').hidden,
        stop: document.querySelector('.cert-tabs [data-action="dane-stop"]').hidden,
        progress: document.querySelector('.cert-tabs .dane-actions .progress').hidden
      }));
      assertEqual(running, { state: 'running', run: true, stop: false, progress: false }, 'running: Stop in place of Check');
      assertEqual(await focusedAction(page), 'dane-stop', 'the focus moved to Stop');
      await shotEl(page, opts, 'dane-cert-desktop-light-en-running', '.cert-tabs .dane-actions');
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.cert-tabs .dane-panel')?.dataset.state === 'cancelled', { timeout: 3000, message: 'cancelled at once' });
      const out = await page.evaluate((n) => ({
        alert: document.querySelector('.cert-tabs [data-dane="cancelled"]')?.textContent || '',
        label: document.querySelector('.cert-tabs [data-action="dane-run"] .btn-label')?.textContent || '',
        stop: document.querySelector('.cert-tabs [data-action="dane-stop"]').hidden,
        table: !!document.querySelector('.cert-tabs .dane-table'),
        pending: window.__dnsHung.slice(n).filter((x) => x.end === null).length
      }), hung0);
      assertEqual(out, { alert: 'The check was cancelled.', label: 'Check again', stop: true, table: false, pending: 0 }, 'cancelled');
      assertEqual(await focusedAction(page), 'dane-run', 'the focus is back on "Check again"');
      await page.evaluate(() => { window.__dnsHang = []; });
    });

    run.group('SSL Targets');
    await run.step('scan the emulated zone with the shared certificate: a DANE tab after Verify, a summary hint', async () => {
      await gotoRoute(page, 'scan');
      await page.waitFor(() => document.querySelector('.scan-step-cert .cert-summary'), { message: 'shared certificate' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="scan-domains"]').value), 'example.net', 'domain from the certificate');
      // Extra hostnames sit in the collapsed Options step.
      await openScanOptions(page);
      await page.type('textarea[data-role="scan-extra"]', 'www.wild.example.net\napi.wild.example.net');
      const ext0 = await page.evaluate(() => window.__externalFetches.length);
      await page.click('[data-action="scan-run"]');
      await page.waitFor(() => document.querySelector('.scan-run-ui .scan-run')?.dataset.status === 'done', { timeout: 90000, interval: 150, message: 'scan done' });
      await settleScroll(page);
      assertEqual(await page.evaluate((n) => window.__externalFetches.slice(n), ext0), [], 'external requests during the scan');
      const info = await page.evaluate(() => ({
        tabs: [...document.querySelectorAll('.scan-tabs .tab[data-tab]')].map((b) => b.dataset.tab),
        hint: document.querySelector('[data-summary="dane"]')?.textContent || ''
      }));
      assertEqual(info.tabs, ['hosts', 'servers', 'cdn', 'verify', 'dane', 'sources', 'ct'], 'tab order');
      assert(/mail servers \(MX\)/.test(info.hint), `summary hint: ${info.hint}`);
    });

    await run.step('the DANE tab: nothing on open; the check adds the covered hosts of the scan', async () => {
      const from = await dnsCount(page);
      await page.click('.scan-tabs .tab[data-tab="dane"]');
      await page.waitFor(() => document.querySelector(`.scan-tab-dane [data-dane="panel"]`), { message: 'DANE panel' });
      await sleep(300);
      assertEqual(await dnsLog(page, from), [], 'opening the tab sends nothing');
      const plan = await page.evaluate(() => document.querySelector('.scan-tab-dane [data-dane="plan"]')?.textContent || '');
      assert(/hosts this scan found/.test(plan), `plan: ${plan}`);
      await runCheck(page, SCAN);
      const rows = byQname(await readRows(page, SCAN));
      assertEqual(rows['_443._tcp.www.wild.example.net'].status, 'danger', 'www (found by the scan) pins the old key');
      assertEqual(rows['_443._tcp.api.wild.example.net'].status, 'insecure', 'api: not DNSSEC-validated');
      assertEqual(rows['_25._tcp.mail.wild.example.net'].status, 'danger', 'the MX host');
      assertEqual(rows['_443._tcp.wild.example.net'].status, 'safe', 'apex');
      const badge = await page.evaluate(() => {
        const b = document.querySelector('.scan-tabs .tab[data-tab="dane"] .tab-badge');
        return b && !b.hidden ? { text: b.textContent, error: b.classList.contains('tab-badge-error') } : null;
      });
      assertEqual(badge, { text: '2', error: true }, 'tab badge');
      const publish = await page.evaluate(() => document.querySelector('.scan-tab-dane [data-dane="publish"] pre')?.textContent || '');
      assertEqual(publish.split('\n'), [
        `_25._tcp.mail.wild.example.net. IN TLSA 3 1 1 ${NEW_SPKI}`,
        `_443._tcp.www.wild.example.net. IN TLSA 3 1 1 ${NEW_SPKI}`
      ], 'records to publish');
      await shotEl(page, opts, 'dane-scan-desktop-light-en', '.scan-tab-dane');
    });

    await run.step('the scan\'s full JSON carries the DANE report', async () => {
      await takeDownloads(page);
      await page.click('.scan-exports [data-export="json"]');
      const files = await takeDownloads(page);
      const scan = files.find((f) => /^scan.*\.json$/.test(f.name));
      assert(scan, `downloads: ${files.map((f) => f.name).join(', ')}`);
      const doc = JSON.parse(scan.text);
      assertEqual([doc.dane && doc.dane.schema, doc.dane && doc.dane.summary.headline], ['domainscope.dane/1', 'danger'], 'dane block');
      assert(!/-----BEGIN/.test(scan.text), 'no certificate text');
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
    });

    await run.step('TR dark on desktop and on a 375×812 phone, then EN light: the SSL Targets DANE tab fits', async () => {
      const from = await dnsCount(page);
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await page.waitFor(() => document.querySelector('.scan-tab-dane .dane-panel')?.dataset.state === 'done', { message: 'DANE result (TR)' });
      await sleep(200);
      await assertNoHorizontalScroll(page, 'scan desktop dark TR');
      await shotEl(page, opts, 'dane-scan-desktop-dark-tr', '.scan-tab-dane');
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await sleep(300);
      await assertNoHorizontalScroll(page, 'scan phone dark TR');
      assertEqual(await overflowingIn(page, '.scan-tab-dane'), [], 'DANE tab inside 375 px');
      assert(await verdictsVisible(page, '.scan-tab-dane'), 'every verdict and name visible without scrolling the table');
      await shotEl(page, opts, 'dane-scan-phone-dark-tr', '.scan-tab-dane');
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.waitFor(() => document.querySelector('.scan-tab-dane .dane-panel')?.dataset.state === 'done', { message: 'DANE result (EN)' });
      await sleep(200);
      await assertNoHorizontalScroll(page, 'scan phone light EN');
      assertEqual(await overflowingIn(page, '.scan-tab-dane'), [], 'DANE tab inside 375 px (EN light)');
      await shotEl(page, opts, 'dane-scan-phone-light-en', '.scan-tab-dane');
      assertEqual(await dnsLog(page, from), [], 'language and theme switches send nothing');
      await page.setViewport({ width: 1440, height: 900 });
    });

    await run.step('a new scan cancels the old run\'s running check', async () => {
      await page.evaluate(() => { window.__dnsHang = ['_443._tcp.wild.example.net']; });
      const hung0 = await page.evaluate(() => window.__dnsHung.length);
      await page.click(`${SCAN} [data-action="dane-run"]`);
      await page.waitFor((n) => window.__dnsHung.length > n, { args: [hung0], message: 'the TLSA query hangs' });
      assertEqual(await page.evaluate(() => document.querySelector('.scan-tab-dane .dane-panel')?.dataset.state), 'running', 'running');
      await page.click('[data-action="scan-run"]');
      // The client's own timeout is 8 s: an end this soon is the cancel.
      await page.waitFor((n) => window.__dnsHung.slice(n).every((x) => x.end !== null), { args: [hung0], timeout: 3000, message: 'the old check aborted' });
      await page.waitFor(() => document.querySelector('.scan-run-ui .scan-run')?.dataset.status === 'done', { timeout: 90000, interval: 150, message: 'new scan done' });
      await settleScroll(page);
      await page.evaluate(() => { window.__dnsHang = []; });
      await page.click('.scan-tabs .tab[data-tab="dane"]');
      await page.waitFor(() => document.querySelector('.scan-tab-dane [data-dane="panel"]'), { message: 'DANE panel of the new run' });
      assertEqual(await page.evaluate(() => document.querySelector('.scan-tab-dane .dane-panel')?.dataset.state), 'idle', 'the new run starts idle');
    });

    run.group('Quality');
    await run.step('nothing left the page', async () => {
      assertEqual(netHits, [], 'https requests that reached the network');
      assertEqual(await page.evaluate(() => window.__externalFetches.slice()), [], 'external fetches blocked in the page');
    });
    await run.step('i18n: no missing keys, TR and EN key sets match', async () => {
      await assertNoMissingKeys(page);
    });
    await run.step('no console errors, exceptions or CSP violations', async () => {
      await assertClean(page, 'dane', origin);
    });
  } finally {
    if (page) await page.close().catch(() => {});
    await browser.close();
    await server.close();
    await rm(tmp, { recursive: true, force: true });
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), opts.shotsDir)}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
