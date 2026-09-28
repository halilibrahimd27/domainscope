#!/usr/bin/env node
/**
 * renewal.e2e.mjs — end-to-end test of SSL Targets with several certificates at once (a renewal
 * week) in a real headless Chrome/Edge. OFFLINE: 0 real probes, nothing leaves the page.
 *
 *   node tests/e2e/renewal.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Setup (installed with Page.addScriptToEvaluateOnNewDocument before the app loads):
 *   - a fake DoH zone for example.com answered inside the page; every other external fetch gets a
 *     503 and is recorded in window.__externalFetches;
 *   - a fake Globalping API serving, per `target|host`, one of the fixture certificates (their real
 *     SHA-256 fingerprints) or an old one;
 *   - a network-level guard (CDP Fetch domain): any https request that still reached the network
 *     is failed and recorded; the suite asserts it stays empty.
 *   - seed: no passive sources, no wordlist, no permutations, no origin hints; the inventory
 *     `web01 1.2.3.4` / `web02 1.2.3.5` / `db01 10.0.0.5`.
 *
 * Certificates (tests/fixtures/gen_x509_fixtures.mjs): set A is an RSA 2048 + ECDSA P-256 pair
 * for example.com and *.example.com (renew_a_rsa.pem, renew_a_ecdsa.pem), set B one RSA 2048
 * certificate for shop.example.com and pay.example.com (renew_b_rsa.pem) — both also under set
 * A's wildcard, so the exact names must win.
 *
 * What is checked:
 *   - step 1: several PEM blocks pasted at once, one file then "Add certificates", a folder (with a
 *     key, a CA file and a file of another type in it) — each grouped into the two sets with their
 *     key types; a file that adds nothing is listed with why and can be removed; Remove all;
 *   - one scan of the union of names; the Hosts tab names each host's set (shop → B, www → A) and
 *     "not covered" for x.dev.example.com;
 *   - the Renewal plan tab: the server × set matrix (db01, web01, web02, 5.6.7.8 not in the list),
 *     the uncovered names, the CSV work list (server, IP, names, set, key types, files);
 *   - Behind CDN: one --cert per certificate in the command and a download for each;
 *   - Verify: one queue for every set (5 checks, cost shown once), a Set column, verdicts against
 *     the planned set (a set-A certificate on pay.example.com is new, marked "Another set"), the
 *     CLI card with the three --cert, CSV / JSON exports with the sets;
 *   - DANE: a picker of the three certificates, nothing sent;
 *   - the scan's full JSON: certificateSets and the plan;
 *   - TR + dark at 375 px: labelled cards, no horizontal scroll, no missing i18n keys;
 *   - one certificate alone is the classic flow again (no plan tab, `--cert new-cert.pem`);
 *   - zero console errors, exceptions and CSP violations.
 */

import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import { SOURCES as LIB_SOURCES } from '../../assets/js/lib/sources.js';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions,
  createRunner, csvHeader, gotoRoute, installDownloadCapture, openScanOptions, setLangUi, takeDownloads, waitReady
} from './scan.e2e.mjs';

/* ------------------------------------------------------------------------ */
/* Test data                                                                */
/* ------------------------------------------------------------------------ */

export const FILES = {
  aRsa: path.join(FIXTURES, 'renew_a_rsa.pem'),
  aEc: path.join(FIXTURES, 'renew_a_ecdsa.pem'),
  bRsa: path.join(FIXTURES, 'renew_b_rsa.pem'),
  key: path.join(FIXTURES, 'ec_wildcard.key'),
  ca: path.join(FIXTURES, 'ca.pem'),
  other: path.join(FIXTURES, 'expected.json')
};
export const APEX = 'example.com';
export const ZONE = {
  'example.com': { A: ['1.2.3.4'] },
  'www.example.com': { A: ['1.2.3.4'] },
  'api.example.com': { A: ['1.2.3.5'] },
  'shop.example.com': { A: ['1.2.3.5'] },
  'pay.example.com': { A: ['5.6.7.8'] },
  'vpn.example.com': { A: ['10.0.0.5'] },
  'x.dev.example.com': { A: ['1.2.3.4'] }
};
export const INVENTORY = 'web01 1.2.3.4\nweb02 1.2.3.5\ndb01 10.0.0.5';
const GP = 'https://api.globalping.io/v1';
const THREE_CERTS = '--cert new-cert-a-rsa.pem --cert new-cert-a-ecdsa.pem --cert new-cert-b-rsa.pem';

/** SHA-256 of a PEM certificate's DER as Globalping reports it ('AB:CD:…'). */
export async function colonSha256(file) {
  const pem = await readFile(file, 'utf8');
  const b64 = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(pem)[1].replace(/\s+/g, '');
  return createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex').toUpperCase().match(/../g).join(':');
}

/* ------------------------------------------------------------------------ */
/* In-page fakes                                                            */
/* ------------------------------------------------------------------------ */

/** The example.com zone answered inside the page for every DoH resolver; nothing else leaves it. */
export const fakeZoneScript = (apex, zone) => `(() => {
  const APEX = ${JSON.stringify(apex)};
  const ZONE = ${JSON.stringify(zone)};
  const SOA = { mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
  const answer = (name, type) => {
    const node = ZONE[name];
    if (!node) {
      const exists = Object.keys(ZONE).some((k) => k.endsWith('.' + name));
      return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers: [], authorities: [{ name: APEX, type: 'SOA', ttl: 300, data: SOA }] };
    }
    const answers = (node[type] || []).map((data) => ({ name, type, ttl: 300, data }));
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: APEX, type: 'SOA', ttl: 300, data: SOA }] };
  };
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.__externalFetches = [];
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (new URL(url, location.href).origin === location.origin) return realFetch(input, init);
      window.__externalFetches.push(url);
      return new Response('blocked by the E2E harness', { status: 503 });
    }
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    const out = name === APEX || name.endsWith('.' + APEX) ? answer(name, q.type) : { rcode: 'NXDOMAIN', answers: [], authorities: [] };
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/**
 * Fake Globalping v1 (outermost window.fetch): /limits, POST /measurements and GET of a result,
 * which is final at once. `window.__gp.calls` records every call; each `target|host` serves one
 * certificate: a set-A one (RSA or ECDSA), or an old certificate for shop.example.com.
 */
export const fakeGlobalpingScript = (fp) => `(() => {
  const API = ${JSON.stringify(GP)};
  const FP = ${JSON.stringify(fp)};
  const OLD_FP = Array(32).fill('AB').join(':');
  const gp = window.__gp = { calls: [], n: 0, measurements: {} };
  const tls = (fingerprint256, cn, alt, keyType) => ({
    authorized: true, protocol: 'TLSv1.3', cipherName: 'TLS_AES_128_GCM_SHA256',
    createdAt: '2026-09-01T00:00:00.000Z', expiresAt: '2036-09-01T00:00:00.000Z',
    issuer: { C: 'XX', O: 'DomainScope Test', CN: 'DomainScope Test Renewal CA' }, subject: { CN: cn, alt },
    keyType, keyBits: keyType === 'RSA' ? 2048 : 256, serialNumber: '01', fingerprint256, publicKey: '04:11:22'
  });
  const A_ALT = 'DNS:example.com, DNS:*.example.com';
  const SERVED = {
    '1.2.3.4|example.com': () => tls(FP.aRsa, 'example.com', A_ALT, 'RSA'),
    '1.2.3.4|www.example.com': () => tls(FP.aEc, 'example.com', A_ALT, 'EC'),
    '1.2.3.5|api.example.com': () => tls(FP.aEc, 'example.com', A_ALT, 'EC'),
    '1.2.3.5|shop.example.com': () => ({ ...tls(OLD_FP, 'shop.example.com', 'DNS:shop.example.com', 'RSA'), issuer: { C: 'US', O: 'Example Test CA', CN: 'Example Test CA R1' } }),
    '5.6.7.8|pay.example.com': () => tls(FP.aRsa, 'example.com', A_ALT, 'RSA')
  };
  const PROBE = { continent: 'EU', region: 'Western Europe', country: 'DE', state: null, city: 'Falkenstein', asn: 24940, network: 'Hetzner Online GmbH', latitude: 50.48, longitude: 12.37, tags: ['datacenter-network'], resolvers: ['private'] };
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers } });
  const quota = (remaining) => ({ 'x-ratelimit-limit': '250', 'x-ratelimit-consumed': String(250 - remaining), 'x-ratelimit-remaining': String(remaining), 'x-ratelimit-reset': '3600' });
  const inner = window.fetch;
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!url.startsWith('https://api.globalping.io/')) return inner(input, init);
    const method = String(init.method || 'GET').toUpperCase();
    let body = null;
    try { body = typeof init.body === 'string' ? JSON.parse(init.body) : null; } catch { body = null; }
    const p = url.slice(API.length);
    gp.calls.push({ method, path: p, body });
    if (p === '/limits' && method === 'GET') {
      return json(200, { rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: 250 - gp.n, reset: 3600 } } } });
    }
    if (p === '/measurements' && method === 'POST') {
      gp.n += 1;
      const id = 'fakeMeas' + String(gp.n).padStart(8, '0');
      gp.measurements[id] = { id, target: body.target, host: body.measurementOptions.request.host, at: Date.now() };
      return json(202, { id, probesCount: 1 }, { ...quota(250 - gp.n), 'x-request-cost': '1', location: API + '/measurements/' + id });
    }
    const m = /^\\/measurements\\/([A-Za-z0-9]+)$/.exec(p);
    if (m && method === 'GET' && gp.measurements[m[1]]) {
      const meas = gp.measurements[m[1]];
      const make = SERVED[meas.target + '|' + meas.host];
      const result = make ? {
        status: 'finished', resolvedAddress: meas.target, statusCode: 200, statusCodeName: 'OK',
        timings: { total: 48, dns: null, tcp: 11, tls: 24, firstByte: 9, download: 1 }, tls: make(),
        headers: { server: 'fake' }, rawHeaders: 'Server: fake', rawBody: null, rawOutput: 'HTTP/1.1 200', truncated: false
      } : {
        status: 'failed', resolvedAddress: null, statusCode: null, statusCodeName: null, timings: { total: null },
        tls: null, headers: {}, rawHeaders: null, rawBody: null, rawOutput: 'connect ECONNREFUSED ' + meas.target + ':443', truncated: false
      };
      return json(200, {
        id: meas.id, type: 'http', status: 'finished', createdAt: new Date(meas.at).toISOString(), updatedAt: new Date().toISOString(),
        target: meas.target, probesCount: 1, locations: [{ magic: 'world', limit: 1 }], measurementOptions: { port: 443, request: { host: meas.host } },
        results: [{ probe: PROBE, result }]
      });
    }
    return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
  };
})();`;

/* ------------------------------------------------------------------------ */
/* Page helpers                                                             */
/* ------------------------------------------------------------------------ */

const STEP1 = '.scan-step-cert';
const DIALOG = 'dialog.vfy-confirm[open]';

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
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    window.scrollTo(0, 0);
    const r = el.getBoundingClientRect();
    return { x: Math.max(0, r.left + window.scrollX - 8), y: Math.max(0, r.top + window.scrollY - 8), width: r.width + 16, height: r.height + 16 };
  }, selector);
  if (!box || !box.width || !box.height) return;
  await mkdir(SHOTS, { recursive: true });
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.min(Math.ceil(box.height), 9000), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}

/** Step 1 as data: the sets (id, names, key types, files), the files not used, the step badge. */
const readStep1 = (page) => page.evaluate((s) => {
  const root = document.querySelector(`${s} [data-role="renewal-sets"]`);
  return {
    single: !!document.querySelector(`${s} .cert-summary`),
    renewal: !!root,
    sets: root ? Number(root.dataset.sets) : 0,
    certs: root ? Number(root.dataset.certs) : 0,
    list: root ? [...root.querySelectorAll('.rw-set')].map((el) => ({
      id: el.dataset.set,
      names: [...el.querySelectorAll('.rw-set-head .tlist-item')].map((x) => x.textContent),
      keys: [...el.querySelectorAll('.rw-leaf .rw-key')].map((x) => x.textContent),
      files: [...el.querySelectorAll('.rw-leaf-files')].map((x) => x.textContent)
    })) : [],
    skipped: root ? [...root.querySelectorAll('.rw-skip')].map((el) => `${el.dataset.issue}:${el.querySelector('.mono').textContent}`) : [],
    badge: document.querySelector('[data-step="cert"] .scan-step-status')?.textContent || '',
    domains: document.querySelector('[data-role="scan-domains"]')?.value || ''
  };
}, STEP1);

/** Wait until step 1 shows a renewal of `certs` certificates (or, with 0, one certificate or none). */
const waitStep1 = (page, certs, message) => page.waitFor((s, n) => {
  const root = document.querySelector(`${s} [data-role="renewal-sets"]`);
  return n ? root && Number(root.dataset.certs) === n : !root;
}, { args: [STEP1, certs], message });

/** Open a results tab of the current run. */
async function openTab(page, id) {
  await page.click(`.scan-tabs .tab[data-tab="${id}"]`);
  await page.waitFor((t) => document.querySelector(`.scan-tabs .tab[data-tab="${t}"]`)?.getAttribute('aria-selected') === 'true', { args: [id], message: `tab ${id}` });
}

const runId = (page) => page.evaluate(() => document.querySelector('.scan-run-ui')?.dataset.run || null);

/** Start a scan with the form as it is and wait until it is done (nothing may leave the page). */
async function runScan(page) {
  const before = await runId(page);
  const ext0 = await page.evaluate(() => window.__externalFetches.length);
  await page.click('[data-action="scan-run"]');
  await page.waitFor((b) => {
    const ui = document.querySelector('.scan-run-ui');
    return ui && ui.dataset.run !== b && ui.querySelector('.scan-run')?.dataset.status === 'done';
  }, { args: [before], timeout: 90000, interval: 150, message: 'scan done' });
  // The stat cards redraw on a short throttle after the end and may move what sits below them:
  // wait for their final values (the servers card leaves '…') before clicking anything.
  await page.waitFor(() => {
    const v = document.querySelector('.scan-run-ui [data-stat="servers"] .stat-value');
    return v && v.textContent !== '…';
  }, { message: 'final stat cards' });
  const ext = await page.evaluate((n) => window.__externalFetches.slice(n), ext0);
  assertEqual(ext, [], 'external requests during the scan');
}

/** Seed the offline scan options (no passive source, no wordlist, no permutations, no origin hints). */
export async function seedOptions(page) {
  const known = LIB_SOURCES.map((s) => s.id);
  await page.evaluate((k) => {
    localStorage.setItem('ssds.scan.options', JSON.stringify({ sources: [], knownSources: k, bruteforce: 'off', permutations: false, originHints: false }));
  }, known);
}

/** The Hosts table as { name: set id | 'covered' | 'not covered' } once it has drawn `count` rows. */
async function readHostSets(page, count) {
  await page.waitFor((n) => document.querySelectorAll('.scan-hosts tbody tr.dt-row').length === n, { args: [count], message: `${count} host rows` });
  return page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.scan-hosts tbody tr.dt-row')].map((tr) => [
    tr.querySelector('.scan-host-name').textContent,
    tr.querySelector('.rw-set-badge')?.dataset.set || (tr.querySelector('[data-set]') ? 'set' : 'not covered')
  ])));
}

/** The plan matrix as [server, { set: [names] }] rows once it has drawn `count` rows. */
async function readMatrix(page, count) {
  await page.waitFor((n) => document.querySelectorAll('.rw-matrix tbody tr.dt-row').length === n, { args: [count], message: `${count} matrix rows` });
  return page.evaluate(() => {
    const heads = [...document.querySelectorAll('.rw-matrix thead th')].map((th) => th.textContent.trim());
    return [...document.querySelectorAll('.rw-matrix tbody tr.dt-row')].map((tr) => {
      const cells = [...tr.cells];
      const sets = {};
      cells.forEach((td, i) => {
        if (!td.classList.contains('rw-col-set')) return;
        const names = [...td.querySelectorAll('.rw-cell-name')].map((x) => x.firstChild.textContent);
        if (names.length) sets[heads[i]] = names;
      });
      return [tr.querySelector('.rw-srv-name').textContent, sets, !!tr.querySelector('.rw-srv-badges .badge')];
    });
  });
}

/** The Verify table as { 'name|ip': { state, status, set, warn } } once it has drawn `count` rows. */
async function readVerify(page, count) {
  await page.waitFor((n) => document.querySelectorAll('.scan-tab-verify .vfy-table tbody tr.dt-row').length === n, { args: [count], message: `${count} verify rows` });
  return page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.scan-tab-verify .vfy-table tbody tr.dt-row')].map((tr) => [
    `${tr.querySelector('.vfy-name').textContent}|${tr.querySelector('.vfy-ip').textContent}`,
    {
      state: tr.querySelector('[data-vfy-state]')?.dataset.vfyState || '',
      status: tr.querySelector('[data-vfy-status]')?.dataset.vfyStatus || '',
      set: tr.querySelector('.rw-set-badge')?.dataset.set || '',
      warn: [...tr.querySelectorAll('[data-vfy-warn]')].map((b) => b.dataset.vfyWarn).join(',')
    }
  ])));
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  const fp = { aRsa: await colonSha256(FILES.aRsa), aEc: await colonSha256(FILES.aEc), bRsa: await colonSha256(FILES.bRsa) };
  const pems = { aRsa: await readFile(FILES.aRsa, 'utf8'), aEc: await readFile(FILES.aEc, 'utf8'), bRsa: await readFile(FILES.bRsa, 'utf8') };

  run.group('Node: harness');
  await run.step('run-all orders the renewal suite right after verify', () => {
    assertEqual(orderSuites(['renewal.e2e.mjs', 'verify.e2e.mjs', 'scan.e2e.mjs', 'shell.e2e.mjs']), ['shell', 'scan', 'verify', 'renewal'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: fake DoH zone ${APEX} + fake Globalping (0 real probes)\n`);
  let page = null;
  let netHits = [];
  let folder = null;
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    netHits = await networkGuard(page);
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeZoneScript(APEX, ZONE) });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeGlobalpingScript(fp) });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Step 1: several certificates (desktop 1440×900, English, light)');
    await run.step('seed the inventory and offline options; step 1 says several certificates can be loaded at once', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await seedOptions(page);
      await page.evaluate((text) => localStorage.setItem('ssds.inventory', JSON.stringify({ v: 1, text, updatedAt: new Date().toISOString() })), INVENTORY);
      await page.reload();
      await waitReady(page);
      await gotoRoute(page, 'scan');
      const info = await page.evaluate((s) => ({
        several: document.querySelector(`${s} .scan-cert-several`)?.textContent || '',
        multiple: document.querySelector(`${s} .filedrop-input`)?.multiple,
        folder: !!document.querySelector(`${s} [data-action="cert-folder"]`)
      }), STEP1);
      assert(/several certificates/.test(info.several), `the hint: ${info.several}`);
      assertEqual([info.multiple, info.folder], [true, true], 'multi-select file input and a folder button (Chrome has webkitdirectory)');
    });

    await run.step('three PEM blocks pasted at once: two sets, the RSA + ECDSA pair is one', async () => {
      await page.evaluate((s) => { document.querySelector(`${s} .cert-paste`).open = true; }, STEP1);
      await page.type(`${STEP1} textarea[data-role="cert-paste"]`, [pems.aRsa, pems.aEc, pems.bRsa].join('\n'));
      await page.click(`${STEP1} [data-action="cert-paste-read"]`);
      await waitStep1(page, 3, 'pasted renewal');
      const s = await readStep1(page);
      assertEqual([s.sets, s.certs], [2, 3], 'two sets, three certificates');
      assertEqual(s.list.map((x) => [x.id, x.names.join(' '), x.keys.join('+')]), [
        ['A', 'example.com *.example.com', 'RSA 2048+ECDSA P-256'],
        ['B', 'pay.example.com shop.example.com', 'RSA 2048']
      ], 'sets');
      assertEqual(s.domains, APEX, 'step 2 filled from the certificates');
      assert(/3 certificates/.test(s.badge), `step badge: ${s.badge}`);
      await shotEl(page, opts, 'renewal-step1-pasted-en-light', STEP1);
    });

    await run.step('Remove all, then one file: the classic single-certificate step', async () => {
      await page.click(`${STEP1} [data-action="cert-remove-all"]`);
      await waitStep1(page, 0, 'renewal removed');
      await page.waitFor((s) => !document.querySelector(`${s} .cert-summary`) && document.querySelector(`${s} .filedrop`), { args: [STEP1], message: 'empty step 1' });
      await page.setFileInput(`${STEP1} .filedrop-input`, [FILES.aRsa]);
      await page.waitFor((s) => document.querySelector(`${s} .cert-summary`), { args: [STEP1], message: 'one certificate' });
      const s = await readStep1(page);
      assertEqual([s.single, s.renewal, s.badge], [true, false, 'ready'], 'single-certificate step');
      assert(await page.evaluate((st) => !!document.querySelector(`${st} [data-action="cert-add"]`), STEP1), 'an Add certificates button');
    });

    await run.step('"Add certificates": the twin, set B and a private key; the key is listed as not used and can be removed', async () => {
      await page.setFileInput(`${STEP1} [data-role="cert-add-picker"] .filedrop-input`, [FILES.aEc, FILES.bRsa, FILES.key]);
      await waitStep1(page, 3, 'added certificates');
      let s = await readStep1(page);
      assertEqual(s.list.map((x) => [x.id, x.files.join(' | ')]), [['A', 'renew_a_rsa.pem | renew_a_ecdsa.pem'], ['B', 'renew_b_rsa.pem']], 'files per set');
      assertEqual(s.skipped, ['no-certificate:ec_wildcard.key'], 'the key file is not used');
      await shotEl(page, opts, 'renewal-step1-added-en-light', STEP1);
      await page.click(`${STEP1} .rw-skip button`);
      await page.waitFor((st) => !document.querySelector(`${st} .rw-skip`), { args: [STEP1], message: 'skipped file removed' });
      s = await readStep1(page);
      assertEqual([s.sets, s.certs, s.skipped.length], [2, 3, 0], 'still two sets');
    });

    await run.step('a folder: its certificate files only (a key and a CA file listed as not used, another type left out)', async () => {
      await page.click(`${STEP1} [data-action="cert-remove-all"]`);
      await waitStep1(page, 0, 'renewal removed');
      // A directory input takes a folder: Chrome lists it as a real folder pick would.
      folder = await mkdtemp(path.join(tmpdir(), 'ds-renewal-'));
      for (const f of [FILES.aRsa, FILES.aEc, FILES.bRsa, FILES.key, FILES.ca, FILES.other]) await copyFile(f, path.join(folder, path.basename(f)));
      await page.setFileInput(`${STEP1} input[webkitdirectory]`, [folder]);
      await waitStep1(page, 3, 'folder renewal');
      const s = await readStep1(page);
      assertEqual([s.sets, s.certs], [2, 3], 'two sets from the folder');
      // in the folder's (name) order; expected.json is not a certificate type: left out
      assertEqual(s.skipped, ['ca-only:ca.pem', 'no-certificate:ec_wildcard.key'], 'files not used');
      assertEqual(s.list.map((x) => [x.id, x.keys.join('+')]), [['A', 'RSA 2048+ECDSA P-256'], ['B', 'RSA 2048']], 'a set by key type, whatever the file order');
      await page.click(`${STEP1} .rw-skip button`);
      await page.waitFor((st) => document.querySelectorAll(`${st} .rw-skip`).length === 1, { args: [STEP1], message: 'one skipped file left' });
      await page.click(`${STEP1} .rw-skip button`);
      await page.waitFor((st) => !document.querySelector(`${st} .rw-skip`), { args: [STEP1], message: 'no skipped file' });
    });

    await run.step('Details on the ECDSA twin opens it in the Certificate view; back in SSL Targets the renewal is intact', async () => {
      await page.click(`${STEP1} .rw-set[data-set="A"] .rw-leaf[data-key="ecdsa"] .rw-leaf-actions button`);
      await page.waitFor(() => document.documentElement.dataset.view === 'cert' && /P-256/.test(document.querySelector('#page-body')?.textContent || ''),
        { message: 'the Certificate view shows the ECDSA certificate' });
      await gotoRoute(page, 'scan');
      await waitStep1(page, 3, 'renewal kept');
      const s = await readStep1(page);
      assertEqual([s.sets, s.certs, s.domains], [2, 3, APEX], 'still the two sets and the domain');
    });

    run.group('One scan of every set\'s names');
    await run.step('scan the emulated zone: the run summary counts three certificates; one scan', async () => {
      await openScanOptions(page);
      await page.type('textarea[data-role="scan-extra"]', Object.keys(ZONE).join('\n'));
      assert(/with 3 certificates/.test(await page.evaluate(() => document.querySelector('.scan-runbar-summary')?.textContent || '')), 'run bar summary');
      await runScan(page);
      const tabs = await page.evaluate(() => [...document.querySelectorAll('.scan-tabs .tab[data-tab]')].map((b) => b.dataset.tab));
      assertEqual(tabs, ['hosts', 'servers', 'plan', 'cdn', 'verify', 'dane', 'sources', 'ct'], 'tabs: the Renewal plan after Servers');
      const sum = await page.evaluate(() => document.querySelector('[data-summary="renewal"]')?.textContent || '');
      assert(/2 certificate sets: 3 servers need one of them/.test(sum), `summary: ${sum}`);
      assert(await page.evaluate(() => !!document.querySelector('[data-summary="renewal-uncovered"]')), 'the uncovered-names line');
    });

    await run.step('Hosts: each host names its set — an exact name wins over the wildcard; x.dev is not covered', async () => {
      const sets = await readHostSets(page, Object.keys(ZONE).length);
      assertEqual(sets, {
        'example.com': 'A', 'api.example.com': 'A', 'x.dev.example.com': 'not covered', 'pay.example.com': 'B',
        'shop.example.com': 'B', 'vpn.example.com': 'A', 'www.example.com': 'A'
      }, 'host → set');
      await shotEl(page, opts, 'renewal-hosts-en-light', '.scan-tab-hosts');
    });

    await run.step('Renewal plan: the server × set matrix, the uncovered name, the CSV work list', async () => {
      await page.click('[data-action="scan-open-plan"]');
      await page.waitFor(() => document.querySelector('.scan-tabs .tab[data-tab="plan"]')?.getAttribute('aria-selected') === 'true', { message: 'plan tab' });
      const matrix = await readMatrix(page, 4);
      assertEqual(matrix, [
        ['db01', { 'Set A': ['vpn.example.com'] }, false],
        ['web01', { 'Set A': ['example.com', 'www.example.com'] }, false],
        ['web02', { 'Set A': ['api.example.com'], 'Set B': ['shop.example.com'] }, false],
        ['5.6.7.8', { 'Set B': ['pay.example.com'] }, true]
      ], 'matrix');
      const info = await page.evaluate(() => ({
        sets: [...document.querySelectorAll('.rw-plan-set')].map((el) => `${el.dataset.set}:${el.dataset.hosts}:${el.dataset.servers}`),
        uncovered: [...document.querySelectorAll('.rw-uncovered tbody tr.dt-row td:first-child')].map((td) => td.textContent),
        title: document.querySelector('[data-role="renewal-uncovered-title"]')?.textContent || ''
      }));
      assertEqual(info.sets, ['A:4:3', 'B:2:2'], 'hosts and servers per set');
      assertEqual(info.uncovered, ['x.dev.example.com'], 'uncovered names');
      assert(/1 host no certificate covers/.test(info.title), info.title);
      await takeDownloads(page);
      await page.click('[data-export="worklist"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'work list download' });
      const [csv] = await takeDownloads(page);
      assert(/^renewal-worklist-example\.com-.*\.csv$/.test(csv.name), `file name: ${csv.name}`);
      assertEqual(csvHeader(csv.text), ['Server', 'IP', 'Names', 'Possible origin names', 'Certificate set', 'Key types', 'Expires', 'Files'], 'work list header');
      const lines = csv.text.replace(/^﻿/, '').trim().split(/\r\n/).slice(1);
      assertEqual(lines.map((l) => l.split(',').slice(0, 5).join(',')), [
        'db01,10.0.0.5,vpn.example.com,,A', 'web01,1.2.3.4,example.com www.example.com,,A', 'web02,1.2.3.5,api.example.com,,A',
        'web02,1.2.3.5,shop.example.com,,B', ',5.6.7.8,pay.example.com,,B'
      ], 'work list rows');
      assert(lines[1].endsWith(',RSA 2048 ECDSA P-256,2036-09-01T00:00:00.000Z,renew_a_rsa.pem renew_a_ecdsa.pem'), `key types and files: ${lines[1]}`);
      await shotEl(page, opts, 'renewal-plan-en-light', '.scan-tab-plan');
    });

    await run.step('Behind CDN: one --cert per certificate in the command, and a download for each', async () => {
      await openTab(page, 'cdn');
      const cli = await page.evaluate(() => ({
        command: document.querySelector('.scan-cli-command code, .scan-cli-command pre')?.textContent || '',
        files: [...document.querySelectorAll('[data-role="cli-cert-files"] [data-action="cli-cert-file"]')].map((b) => b.dataset.file),
        single: !!document.querySelector('[data-action="cli-cert"]')
      }));
      assertEqual(cli.command, `python3 ssl_origin_scan.py -t targets.txt -n names.txt ${THREE_CERTS}`, 'CLI command');
      assertEqual(cli.files, ['new-cert-a-rsa.pem', 'new-cert-a-ecdsa.pem', 'new-cert-b-rsa.pem'], 'one download per certificate');
      assertEqual(cli.single, false, 'no single new-cert.pem button');
      await shotEl(page, opts, 'renewal-cdn-cli-en-light', '.scan-tab-cdn .scan-cli');
      await page.click('[data-action="cli-cert-file"][data-file="new-cert-a-ecdsa.pem"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'certificate download' });
      const [file] = await takeDownloads(page);
      assertEqual(file.name, 'new-cert-a-ecdsa.pem', 'file name');
      assertEqual(file.text.replace(/\s+/g, ''), pems.aEc.replace(/\s+/g, ''), 'that certificate, as PEM');
    });

    run.group('Verify: one queue for every set');
    await run.step('five checks, the cost once; a Set column; nothing sent when the tab opens', async () => {
      await openTab(page, 'verify');
      const rows = await readVerify(page, 6);
      assertEqual(Object.fromEntries(Object.entries(rows).map(([k, v]) => [k, `${v.state}:${v.set}`])), {
        'example.com|1.2.3.4': 'pending:A', 'www.example.com|1.2.3.4': 'pending:A', 'api.example.com|1.2.3.5': 'pending:A',
        'shop.example.com|1.2.3.5': 'pending:B', 'pay.example.com|5.6.7.8': 'pending:B', 'vpn.example.com|10.0.0.5': 'skipped:A'
      }, 'rows and their sets');
      const info = await page.evaluate(() => ({
        checks: document.querySelector('[data-vfy="plan"]')?.dataset.checks,
        servers: document.querySelector('[data-vfy="plan"]')?.dataset.servers,
        sets: document.querySelector('[data-vfy="sets"]')?.textContent || '',
        gp: window.__gp.calls.length
      }));
      assertEqual([info.checks, info.servers, info.gp], ['5', '3', 0], 'plan line; no Globalping call yet');
      assert(/Set A: example\.com \+1 · Set B: pay\.example\.com \+1/.test(info.sets), `sets sentence: ${info.sets}`);
    });

    await run.step('Start → one dialog with the whole cost → five POSTs; verdicts against each name\'s set', async () => {
      await page.click('[data-action="vfy-start"]');
      await page.waitFor((d) => document.querySelector(d), { args: [DIALOG], message: 'consent dialog' });
      const cost = await page.evaluate((d) => document.querySelector(`${d} [data-vfy="confirm-cost"]`)?.dataset.checks, DIALOG);
      assertEqual(cost, '5', 'one cost for every set');
      await page.click(`${DIALOG} .modal-foot .btn-primary`);
      await page.waitFor(() => document.querySelector('.scan-tab-verify [data-vfy="panel"]')?.dataset.status === 'done', { timeout: 30000, message: 'batch done' });
      const posts = await page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST').map((c) => `${c.body.target}|${c.body.measurementOptions.request.host}`).sort());
      assertEqual(posts, ['1.2.3.4|example.com', '1.2.3.4|www.example.com', '1.2.3.5|api.example.com', '1.2.3.5|shop.example.com', '5.6.7.8|pay.example.com'], 'POSTs');
      await page.waitFor(() => document.querySelectorAll('.scan-tab-verify [data-vfy-status]').length === 5, { message: 'five verdicts drawn' });
      const rows = await readVerify(page, 6);
      const verdicts = Object.entries(rows).filter(([, v]) => v.status).map(([k, v]) => `${k} ${v.status}${v.warn ? `:${v.warn}` : ''}`).sort();
      assertEqual(verdicts, [
        'api.example.com|1.2.3.5 UPDATED', 'example.com|1.2.3.4 UPDATED', 'pay.example.com|5.6.7.8 UPDATED:other-set',
        'shop.example.com|1.2.3.5 NEEDS_UPDATE', 'www.example.com|1.2.3.4 UPDATED'
      ], 'verdicts (either twin of set A is new; a set-A certificate on a set-B name is new, from another set)');
      const head = await page.evaluate(() => [...document.querySelectorAll('.scan-tab-verify .vfy-headline [data-head]')].map((a) => a.dataset.head));
      assertEqual(head[0], 'some', 'headline');
      await shotEl(page, opts, 'renewal-verify-en-light', '.scan-tab-verify');
    });

    await run.step('Verify CLI card: three --cert and their downloads; CSV / JSON exports carry the sets', async () => {
      const cli = await page.evaluate(() => ({
        command: document.querySelector('.vfy-cli-cmd code, .vfy-cli-cmd pre')?.textContent || '',
        files: [...document.querySelectorAll('[data-vfy="cli-certs"] [data-action="cli-cert-file"]')].map((b) => b.dataset.file)
      }));
      assert(cli.command.includes(`-n vpn.example.com ${THREE_CERTS} --json verify-cli.json`), `CLI command: ${cli.command}`);
      assertEqual(cli.files.length, 3, 'three downloads');
      await takeDownloads(page);
      await page.click('.scan-tab-verify .vfy-table [data-export="csv"]');
      await page.click('.scan-tab-verify .vfy-table [data-export="json"]');
      await page.waitFor(() => (window.__downloads || []).length === 2, { message: 'verify exports' });
      const files = await takeDownloads(page);
      const csv = files.find((f) => f.name.endsWith('.csv'));
      const header = csvHeader(csv.text);
      assertEqual(header.slice(-2), ['set', 'served_set'], 'CSV set columns');
      const json = JSON.parse(files.find((f) => f.name.endsWith('.json')).text);
      assertEqual(json.certificateSets.map((s) => [s.id, s.sha256.length]), [['A', 2], ['B', 1]], 'JSON certificate sets');
      const pay = json.rows.find((r) => r.name === 'pay.example.com');
      assertEqual([pay.set, pay.servedSet, pay.status], ['B', 'A', 'UPDATED'], 'JSON row');
    });

    await run.step('DANE: a picker of the three certificates; nothing is sent', async () => {
      await openTab(page, 'dane');
      const opts3 = await page.evaluate(() => [...document.querySelectorAll('.scan-dane-pick select option')].map((o) => o.textContent));
      assertEqual(opts3.length, 3, `options: ${opts3.join(' / ')}`);
      assert(/^Set A · RSA 2048 · renew_a_rsa\.pem$/.test(opts3[0]) && /^Set B · RSA 2048/.test(opts3[2]), opts3.join(' / '));
      await page.evaluate(() => {
        const sel = document.querySelector('.scan-dane-pick select');
        sel.value = '2';
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => document.querySelector('.scan-dane-pick select')?.value === '2', { message: 'set B picked' });
      assertEqual(await page.evaluate(() => window.__externalFetches.length), 0, 'no request');
    });

    await run.step('the scan\'s full JSON: the sets, the set of every host, the plan', async () => {
      await takeDownloads(page);
      await page.click('.scan-exports [data-export="json"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'full JSON' });
      const doc = JSON.parse((await takeDownloads(page))[0].text);
      assertEqual(doc.certificateSets.map((s) => `${s.id}:${s.keyTypes.join('+')}`), ['A:RSA 2048+ECDSA P-256', 'B:RSA 2048'], 'sets');
      assertEqual([doc.renewal.assigned['shop.example.com'].set, doc.renewal.assigned['www.example.com'].set], ['B', 'A'], 'assigned sets');
      assertEqual(doc.renewal.uncovered.map((u) => u.name), ['x.dev.example.com'], 'uncovered');
      assertEqual(doc.verification.certificateSets.length, 2, 'the verification block carries the sets too');
    });

    run.group('Turkish, dark, a 375 px phone');
    await run.step('TR + dark: the plan is labelled cards that fit; no horizontal scroll', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await page.setViewport({ width: 375, height: 800, mobile: true });
      await page.waitFor(() => document.querySelector('.scan-tabs'), { message: 'results after the re-mount' });
      await openTab(page, 'plan');
      await page.waitFor(() => document.querySelectorAll('.rw-matrix tbody tr.dt-row').length === 4, { message: 'matrix rows' });
      const cards = await page.evaluate(() => {
        const td = document.querySelector('.rw-matrix tbody tr.dt-row td.rw-col-set');
        return { label: td?.dataset.label || '', display: getComputedStyle(document.querySelector('.rw-matrix tbody tr.dt-row')).display, before: getComputedStyle(td, '::before').content };
      });
      assertEqual([cards.label, cards.display], ['A seti', 'grid'], 'a labelled card');
      assert(/A seti/.test(cards.before), `the label is drawn: ${cards.before}`);
      await assertNoHorizontalScroll(page, 'plan tab, 375 px');
      await shotEl(page, opts, 'renewal-plan-tr-dark-375', '.scan-tab-plan');
      await openTab(page, 'verify');
      await assertNoHorizontalScroll(page, 'verify tab, 375 px');
      await page.evaluate(() => window.scrollTo(0, 0));
      await assertNoHorizontalScroll(page, 'step 1, 375 px');
      await shotEl(page, opts, 'renewal-step1-tr-dark-375', STEP1);
    });

    await run.step('one certificate alone is the classic flow: no plan tab, --cert new-cert.pem', async () => {
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport({ width: 1440, height: 900 });
      await page.click(`${STEP1} [data-action="cert-remove-all"]`);
      await waitStep1(page, 0, 'renewal removed');
      await page.setFileInput(`${STEP1} .filedrop-input`, [FILES.bRsa]);
      await page.waitFor((s) => document.querySelector(`${s} .cert-summary`), { args: [STEP1], message: 'one certificate' });
      await page.setViewport({ width: 375, height: 800, mobile: true });
      await page.waitFor(() => document.documentElement.clientWidth <= 375, { message: 'phone width' });
      await assertNoHorizontalScroll(page, 'one certificate with Add certificates, 375 px');
      await shotEl(page, opts, 'renewal-step1-single-en-light-375', STEP1);
      await page.setViewport({ width: 1440, height: 900 });
      await runScan(page);
      const info = await page.evaluate(() => ({
        tabs: [...document.querySelectorAll('.scan-tabs .tab[data-tab]')].map((b) => b.dataset.tab),
        renewal: !!document.querySelector('[data-summary="renewal"]')
      }));
      assertEqual(info.tabs, ['hosts', 'servers', 'cdn', 'verify', 'dane', 'sources', 'ct'], 'tabs');
      assertEqual(info.renewal, false, 'no renewal summary');
      await openTab(page, 'cdn');
      const command = await page.evaluate(() => document.querySelector('.scan-cli-command code, .scan-cli-command pre')?.textContent || '');
      assertEqual(command, 'python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem', 'single-certificate command');
    });

    run.group('Page health');
    await run.step('no request reached the network (Globalping included)', async () => {
      assertEqual(netHits, [], 'network requests');
      assertEqual(await page.evaluate(() => window.__externalFetches), [], 'external fetches');
    });
    await run.step('i18n: no missing keys, TR and EN key sets match', async () => {
      await assertNoMissingKeys(page);
    });
    await run.step('no console errors, exceptions or CSP violations', async () => {
      await assertClean(page, 'renewal', origin);
    });
  } finally {
    if (page) await page.close().catch(() => {});
    if (folder) await rm(folder, { recursive: true, force: true }).catch(() => {});
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

// Run only when executed directly (the fakes above can be imported by other scripts).
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
    process.exitCode = 1;
  });
}
