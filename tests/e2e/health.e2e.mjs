#!/usr/bin/env node
/**
 * health.e2e.mjs — end-to-end test of the "Domain Health" view in a real headless browser,
 * against live DoH resolvers and RDAP registries (network required), plus an offline group.
 *
 *   node tests/e2e/health.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--offline]
 *
 * Covers: pure helpers (Node); github.com (summary, traffic light, grouped + translated checks,
 * RDAP card with expiry countdown, SPF lookup meter + tree, DMARC tags, DKIM table, CAA "which
 * CAs"), the problems filter, cloudflare.com (DNSSEC validated), a .com.tr domain (no RDAP →
 * explained), validation, the language re-mount keeping the report, phone light/dark, no
 * console errors / exceptions / CSP violations and complete i18n (all health.* keys).
 *
 * OFFLINE group (always runs; --offline skips the live ones): example.com answered in the page
 * (scan.e2e.mjs zoneHandoffScript: every other request is blocked) and a fake Globalping API
 * built from the live captures tests/fixtures/globalping/m26 + m27 — 0 real probes, and a
 * network guard proves nothing left the page. It checks the CAA card's RFC 8657 restriction
 * (only dns-01, with its renewal note) and the MTA-STS policy check: nothing sent before the
 * click; one free /limits read and the consent + cost dialog (Cancel sends nothing); exactly the
 * lib/mtasts request; a valid policy covering both MX hosts; "Check again" without a dialog and
 * an MX host the policy misses (error); the policy in "Report (JSON)"; a language switch that
 * keeps the result without a new probe; a quota at 0 (nothing asked or sent); a policy host
 * that does not resolve; 1440 px and a 375 px phone, light and dark, without horizontal scroll.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { installDownloadCapture, takeDownloads, zoneHandoffScript } from './scan.e2e.mjs';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { healthScore, trafficLight, groupChecks, parseSelectors, HEALTH_GROUPS } from '../../assets/js/views/health.js';
import { HEALTH_I18N, HEALTH_CHECK_IDS } from '../../assets/js/lib/health.js';
import { mtaStsPolicyRequest } from '../../assets/js/lib/mtasts.js';

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
const OFFLINE = argv.includes('--offline');
const GP_FIXTURES = path.join(HERE, '..', 'fixtures', 'globalping');
// Third-party hosts whose request failures the view reports in its UI (not app errors): every
// public DoH resolver can time out or, like Quad9 over HTTP/3, omit CORS headers.
const FLAKY_HOSTS = [...RESOLVERS.map((r) => new URL(r.url).hostname)];
const DONE = "!!document.querySelector('.hlt-hero') && !document.querySelector('[data-action=\"run\"]').hidden";

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
    if (FLAKY_HOSTS.some((host) => text.includes(`//${host}/`))) notes.push(`${where}: tolerated ${e.source} error for a flaky third-party host`);
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
    const pick = (lang) => i.listKeys(lang).filter((k) => k.startsWith('hlt.') || k.startsWith('health.'));
    const en = pick('en');
    const tr = pick('tr');
    return { missing: i.getMissingKeys(), onlyEn: en.filter((k) => !tr.includes(k)), onlyTr: tr.filter((k) => !en.includes(k)), count: en.length };
  });
  assertEqual(info.missing, [], 'missing i18n keys');
  assertEqual(info.onlyEn, [], 'keys only in EN');
  assertEqual(info.onlyTr, [], 'keys only in TR');
  assert(info.count > 245, `health.* + hlt.* keys registered (${info.count})`);
}

/** What the page shows. */
function reportInfo() {
  const hero = document.querySelector('.hlt-hero');
  const checks = [...document.querySelectorAll('.hlt-check')];
  return {
    light: hero?.dataset.light,
    score: Number(hero?.dataset.score),
    groups: [...document.querySelectorAll('.hlt-group')].map((g) => g.dataset.group),
    checks: checks.map((c) => ({ id: c.dataset.id, severity: c.dataset.severity })),
    untranslated: checks.map((c) => c.querySelector('.hlt-check-title').textContent).filter((x) => /^health\.|\.title$/.test(x)),
    rdap: document.querySelector('.hlt-rdap')?.textContent.replace(/\s+/g, ' ') || '',
    dnssec: document.querySelector('.hlt-dnssec')?.textContent.replace(/\s+/g, ' ') || '',
    caa: document.querySelector('.hlt-caa')?.textContent.replace(/\s+/g, ' ') || '',
    mail: document.querySelector('.hlt-mail')?.textContent.replace(/\s+/g, ' ') || '',
    meter: document.querySelector('.hlt-meter')?.getAttribute('aria-valuenow') ?? null,
    expiryDays: document.querySelector('.hlt-expiry')?.dataset.days ?? null
  };
}

/* ------------------------------------------------------------------------ */
/* Offline: CAA restrictions and the MTA-STS policy check                   */
/* ------------------------------------------------------------------------ */

const MAIL_APEX = 'example.com';
const MAIL_SOA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026092701, refresh: 3600, retry: 900, expire: 1209600, minimum: 300 };
/** example.com as the page sees it: two MX hosts, MTA-STS + TLS-RPT records, CAA with RFC 8657. */
const MAIL_ZONE = {
  'example.com': {
    A: ['192.0.2.80'], SOA: [MAIL_SOA], NS: ['ns1.example.com', 'ns2.example.com'],
    MX: [{ preference: 10, exchange: 'mx.example.com' }, { preference: 20, exchange: 'alt1.mx.example.com' }],
    TXT: [['v=spf1 mx -all']],
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=dns-01' }, { flags: 0, tag: 'issuewild', value: ';' }]
  },
  'ns1.example.com': { A: ['192.0.2.53'] },
  'ns2.example.com': { A: ['198.51.100.53'] },
  'mx.example.com': { A: ['192.0.2.25'] },
  'alt1.mx.example.com': { A: ['198.51.100.25'] },
  '_mta-sts.example.com': { TXT: [['v=STSv1; id=20260927T1200']] },
  '_smtp._tls.example.com': { TXT: [['v=TLSRPTv1; rua=mailto:tls-reports@example.com']] },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']] }
};
const MTASTS_CARD = '[data-mtasts="card"]';
const GP_DIALOG = 'dialog.gp-confirm[open]';

/**
 * Fake Globalping v1 API (the outermost window.fetch wrapper): /limits (window.__gp.limitsRemaining),
 * POST /measurements (202 + quota headers; the result scenario is the next of window.__gp.next,
 * default 'ok') and GET /measurements/:id (in progress for 600 ms + __gp.delayMs, then the
 * scenario's result with a certificate valid from 30 days ago to 60 days ahead; 503 while
 * __gp.getDown). Every call is recorded in __gp.calls; window.__gpNewWindow(remaining) opens a
 * later quota window.
 * @param {Object<string, object>} results scenario → Globalping `result` object
 * @param {object} probe the probe object of every result
 */
const fakeGlobalpingScript = (results, probe) => `(() => {
  const API = 'https://api.globalping.io/v1';
  const RESULTS = ${JSON.stringify(results)};
  const PROBE = ${JSON.stringify(probe)};
  const gp = window.__gp = { calls: [], n: 0, limitsRemaining: 250, windowEnd: null, next: [], measurements: {}, delayMs: 0, getDown: false };
  // A later hourly window (the client never raises "remaining" inside one).
  window.__gpNewWindow = (remaining) => {
    gp.windowEnd = Math.max(Date.now() + 3600e3, (gp.windowEnd || 0) + 120e3);
    gp.limitsRemaining = remaining;
  };
  const iso = (ms) => new Date(ms).toISOString();
  const resetS = () => (gp.windowEnd ? Math.max(1, Math.ceil((gp.windowEnd - Date.now()) / 1000)) : 0);
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers } });
  const inner = window.fetch;
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!url.startsWith('https://api.globalping.io/')) return inner(input, init);
    const method = String(init.method || (input && input.method) || 'GET').toUpperCase();
    const headers = {};
    new Headers(init.headers || (typeof input === 'object' && input.headers) || {}).forEach((v, k) => { headers[k] = v; });
    let body = null;
    try { body = typeof init.body === 'string' ? JSON.parse(init.body) : null; } catch { body = String(init.body); }
    const p = url.startsWith(API) ? url.slice(API.length) : url;
    gp.calls.push({ method, path: p, headers, body });
    if (init.signal && init.signal.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
    if (p === '/limits' && method === 'GET') {
      return json(200, { rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: gp.limitsRemaining, reset: resetS() } } } });
    }
    if (p === '/measurements' && method === 'POST') {
      if (!/^application\\/json\\b/i.test(headers['content-type'] || '')) {
        return json(400, { error: { type: 'validation_error', message: 'Parameters validation failed.', params: { type: '"type" is required' } } });
      }
      if (!gp.windowEnd) gp.windowEnd = Date.now() + 3600e3;
      gp.limitsRemaining = Math.max(0, gp.limitsRemaining - 1);
      gp.n += 1;
      const id = 'fakeMtaSts' + String(gp.n).padStart(6, '0');
      gp.measurements[id] = { id, at: Date.now(), target: body.target, scenario: gp.next.shift() || 'ok' };
      return json(202, { id, probesCount: 1 }, {
        'x-ratelimit-limit': '250', 'x-ratelimit-consumed': String(250 - gp.limitsRemaining), 'x-ratelimit-remaining': String(gp.limitsRemaining),
        'x-ratelimit-reset': String(resetS()), 'x-request-cost': '1'
      });
    }
    const m = /^\\/measurements\\/([A-Za-z0-9]+)$/.exec(p);
    if (m && method === 'GET') {
      const meas = gp.measurements[m[1]];
      if (!meas) return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
      if (gp.getDown) return json(503, { error: { type: 'api_error', message: 'Service Unavailable.' } });
      const base = {
        id: meas.id, type: 'http', createdAt: iso(meas.at), updatedAt: iso(Date.now()), target: meas.target, timeout: 10, probesCount: 1,
        measurementOptions: { port: 443, request: { method: 'GET', path: '/.well-known/mta-sts.txt' } }
      };
      if (Date.now() - meas.at < 600 + gp.delayMs) {
        return json(200, { ...base, status: 'in-progress', results: [{ probe: PROBE, result: { status: 'in-progress', rawHeaders: '', rawBody: '', rawOutput: '' } }] });
      }
      const result = JSON.parse(JSON.stringify(RESULTS[meas.scenario]));
      if (result.tls) {
        result.tls.createdAt = iso(Date.now() - 30 * 864e5);
        result.tls.expiresAt = iso(Date.now() + 60 * 864e5);
      }
      return json(200, { ...base, status: 'finished', results: [{ probe: PROBE, result }] });
    }
    return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
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

/** What the MTA-STS card shows. */
function mtaStsInfo() {
  const card = document.querySelector('[data-mtasts="card"]');
  if (!card) return null;
  return {
    state: card.dataset.state,
    headline: card.querySelector('[data-mtasts-headline]')?.dataset.mtastsHeadline ?? null,
    findings: [...card.querySelectorAll('.hlt-finding')].map((f) => ({ id: f.dataset.id, severity: f.dataset.severity })),
    mx: [...card.querySelectorAll('[data-mx]')].map((x) => `${x.dataset.mx}:${x.dataset.matched}`),
    button: card.querySelector('[data-action="mtasts-check"]')?.textContent.trim() ?? null,
    busy: card.querySelector('[data-action="mtasts-check"]')?.getAttribute('aria-busy') === 'true',
    link: card.querySelector('.hlt-mtasts-link')?.getAttribute('href') ?? null,
    file: !!card.querySelector('.hlt-mtasts-file'),
    text: card.textContent.replace(/\s+/g, ' ')
  };
}

async function mtaStsGroup(browser, server) {
  const fx = async (name) => JSON.parse(await readFile(path.join(GP_FIXTURES, `${name}.json`), 'utf8'));
  const m26 = await fx('m26-mta-sts-policy');
  const m27 = await fx('m27-mta-sts-no-host');
  const live = m26.final.body.results[0];
  const results = {
    ok: live.result,
    unmatched: { ...live.result, rawBody: 'version: STSv1\r\nmode: enforce\r\nmx: mx.example.com\r\nmax_age: 1209600\r\n' },
    nohost: m27.final.body.results[0].result
  };

  group('Offline: CAA restrictions and the MTA-STS policy check (emulated example.com, fake Globalping)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const netHits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(MAIL_APEX, MAIL_ZONE) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeGlobalpingScript(results, live.probe) });
  await installDownloadCapture(page);
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  const gpCalls = () => page.evaluate(() => window.__gp.calls.map((c) => ({ method: c.method, path: c.path, body: c.body })));
  const posts = (calls) => calls.filter((c) => c.method === 'POST');
  const card = () => page.evaluate(mtaStsInfo);
  const settled = (label) => page.waitFor((sel) => {
    const el = document.querySelector(sel);
    return el && el.dataset.state !== 'running';
  }, { args: [MTASTS_CARD], timeout: 20000, message: label });

  try {
    await step('the report renders the MTA-STS card and the CAA restriction; nothing goes to Globalping', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await gotoHash(page, `#/health?domain=${MAIL_APEX}`, 'health');
      await page.waitFor(DONE, { timeout: 30000, message: 'health report' });
      const c = await card();
      assert(c, 'MTA-STS card');
      assertEqual([c.state, c.button, c.busy], ['idle', 'Check the policy (1 Globalping probe)', false], 'idle card');
      assert(c.text.includes('v=STSv1; id=20260927T1200') && c.text.includes('https://mta-sts.example.com/.well-known/mta-sts.txt'), `TXT + URL: ${c.text.slice(0, 300)}`);
      const caa = await page.evaluate(() => ({
        restricted: [...document.querySelectorAll('.hlt-caa [data-caa="restricted"]')].map((x) => x.dataset.issuer),
        note: document.querySelector('.hlt-caa [data-note="methods"]')?.textContent || '',
        text: document.querySelector('.hlt-caa')?.textContent.replace(/\s+/g, ' ') || ''
      }));
      assertEqual(caa.restricted, ['letsencrypt.org'], 'CAA: letsencrypt.org restricted');
      assert(/only dns-01/.test(caa.text) && /http-01/.test(caa.note), `CAA restriction and renewal note: ${caa.note}`);
      assertEqual(await gpCalls(), [], 'no Globalping call, not even /limits');
      await assertNoHorizontalScroll(page, 'mta-sts idle');
    });

    await step('first click: one free /limits read and the consent dialog (host, path, cost); Cancel sends nothing', async () => {
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((d) => document.querySelector(d), { args: [GP_DIALOG], message: 'consent dialog' });
      const dlg = await page.evaluate((d) => {
        const el = document.querySelector(d);
        return {
          privacy: el.querySelector('[data-gp="confirm-privacy"]')?.textContent || '',
          probes: el.querySelector('[data-gp="confirm-cost"]')?.dataset.probes,
          cost: el.querySelector('[data-gp="confirm-cost"]')?.textContent || ''
        };
      }, GP_DIALOG);
      assert(dlg.privacy.includes('mta-sts.example.com') && dlg.privacy.includes('/.well-known/mta-sts.txt') && /six months/.test(dlg.privacy), `privacy: ${dlg.privacy}`);
      assertEqual(dlg.probes, '1', 'cost: one probe');
      assert(/250/.test(dlg.cost), `cost text: ${dlg.cost}`);
      assertEqual((await gpCalls()).map((c) => `${c.method} ${c.path}`), ['GET /limits'], 'only the free quota read before consent');
      if (SHOTS_ON) await page.screenshot(path.join(SHOTS, 'health-mtasts-desktop-light-en-confirm.png'));
      await page.click(`${GP_DIALOG} .modal-foot .btn:not(.btn-primary)`);
      await page.waitFor((d) => !document.querySelector(d), { args: [GP_DIALOG], message: 'dialog closed' });
      await settled('card back to idle');
      assertEqual((await card()).state, 'idle', 'cancel restores the card');
      assertEqual(posts(await gpCalls()).length, 0, 'Cancel sends nothing');
    });

    await step('Send: exactly the lib/mtasts request; the policy is valid and matches both MX hosts', async () => {
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((d) => document.querySelector(d), { args: [GP_DIALOG], message: 'consent dialog again (cancel granted nothing)' });
      await page.click(`${GP_DIALOG} .modal-foot .btn-primary`);
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done', { args: [MTASTS_CARD], timeout: 20000, message: 'policy checked' });
      const calls = await gpCalls();
      assertEqual(posts(calls).map((c) => c.body), [mtaStsPolicyRequest(MAIL_APEX)], 'one POST: the HTTPS GET of the policy');
      const c = await card();
      assertEqual(c.headline, 'ok', 'headline');
      assertEqual(c.mx, ['mx.example.com:true', 'alt1.mx.example.com:true'], 'both MX hosts matched');
      for (const id of ['tls.ok', 'mode.enforce', 'max-age.days', 'mx.ok', 'mx.unused']) assert(c.findings.some((f) => f.id === id), `finding ${id}: ${JSON.stringify(c.findings)}`);
      assertEqual(c.findings[0].severity, 'info', 'worst first (no error or warning here)');
      assertEqual([c.link, c.file, c.button], ['https://api.globalping.io/v1/measurements/fakeMtaSts000001', true, 'Check again (1 probe)'], 'link, policy file, button');
      assert(/Tokyo/.test(c.text) && /STARTTLS/.test(c.text), 'probe place and the SMTP note');
      await assertNoHorizontalScroll(page, 'mta-sts done');
      await shotCard(page, 'health-mtasts-desktop-light-en-ok');
    });

    await step('Check again: no dialog (consent kept); an MX host the policy misses is an error in enforce mode', async () => {
      await page.evaluate(() => { window.__gp.next.push('unmatched'); });
      const before = (await gpCalls()).length;
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done' && document.querySelector(`${sel} [data-mtasts-headline="problems"]`),
        { args: [MTASTS_CARD], timeout: 20000, message: 'second check' });
      assert(!(await page.evaluate((d) => !!document.querySelector(d), GP_DIALOG)), 'no dialog');
      const calls = (await gpCalls()).slice(before);
      assertEqual(calls.filter((x) => x.path === '/limits' || x.method === 'POST').map((x) => `${x.method} ${x.path}`), ['GET /limits', 'POST /measurements'], 'one /limits, one POST');
      const c = await card();
      assertEqual(c.mx, ['mx.example.com:true', 'alt1.mx.example.com:false'], 'alt1 not matched');
      assertEqual(c.findings[0], { id: 'mx.unmatched', severity: 'error' }, 'the error comes first');
      await shotCard(page, 'health-mtasts-desktop-light-en-problems');
    });

    await step('"Report (JSON)" carries the policy check', async () => {
      await takeDownloads(page);
      await page.click('[data-action="download"]');
      await page.waitFor(() => (window.__downloads || []).length > 0, { message: 'download' });
      const [d] = await takeDownloads(page);
      const json = JSON.parse(d.text);
      assertEqual([json.domain, json.mtaStsPolicy?.headline, json.mtaStsPolicy?.measurementId, json.mtaStsPolicy?.url],
        [MAIL_APEX, 'problems', 'fakeMtaSts000002', 'https://mta-sts.example.com/.well-known/mta-sts.txt'], 'mtaStsPolicy block');
      assert(json.mtaStsPolicy.findings.some((f) => f.id === 'mx.unmatched'), 'findings exported');
    });

    await step('[dark, TR] a language switch keeps the result and sends nothing', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      const before = (await gpCalls()).length;
      await setLangUi(page, 'tr');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done', { args: [MTASTS_CARD], message: 'restored card' });
      const c = await card();
      assertEqual([c.headline, c.button], ['problems', 'Yeniden kontrol et (1 ölçüm)'], 'restored in Turkish');
      assert(/MTA-STS politikası|Politika/.test(c.text) && /mx kalıbı yok/.test(c.text), `Turkish card: ${c.text.slice(0, 200)}`);
      await page.evaluate(() => new Promise((r) => { setTimeout(r, 400); }));
      assertEqual((await gpCalls()).length, before, 'no Globalping call');
      await assertNoHorizontalScroll(page, 'mta-sts dark tr');
      await shotCard(page, 'health-mtasts-desktop-dark-tr-problems');
      await shotCaa(page, 'health-caa-desktop-dark-tr');
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await shotCaa(page, 'health-caa-desktop-light-en');
    });

    await step('quota used up: nothing asked, nothing sent, the reset time shown', async () => {
      await page.evaluate(() => { window.__gp.limitsRemaining = 0; });
      const before = (await gpCalls()).length;
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'quota', { args: [MTASTS_CARD], message: 'quota state' });
      const calls = (await gpCalls()).slice(before);
      assertEqual(calls.map((x) => `${x.method} ${x.path}`), ['GET /limits'], 'only the free quota read');
      assert(!(await page.evaluate((d) => !!document.querySelector(d), GP_DIALOG)), 'no dialog');
      assert(/quota is used up/.test((await card()).text), 'quota message');
      await page.evaluate(() => window.__gpNewWindow(200));
    });

    await step('a policy host that does not resolve: senders cannot use the policy', async () => {
      await page.evaluate(() => { window.__gp.next.push('nohost'); });
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done' && document.querySelector(`${sel} [data-mtasts-headline="unreachable"]`),
        { args: [MTASTS_CARD], timeout: 20000, message: 'unreachable verdict' });
      const c = await card();
      assertEqual(c.findings.map((f) => f.id), ['fetch.dns'], 'one DNS finding');
      assertEqual([c.mx, c.file], [[], false], 'no MX table, no file');
    });

    await step('a result that cannot be read: the paid measurement is read again, never a new probe', async () => {
      await page.evaluate(() => { window.__gp.getDown = true; });
      const before = posts(await gpCalls()).length;
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'error', { args: [MTASTS_CARD], timeout: 20000, message: 'error state' });
      let c = await card();
      assertEqual(c.button, 'Read the result again (no new probe)', 'free re-read offered');
      assert(/costs nothing/.test(c.text), 'paid note');
      await shotCard(page, 'health-mtasts-desktop-light-en-error');
      await page.evaluate(() => { window.__gp.getDown = false; });
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done', { args: [MTASTS_CARD], timeout: 20000, message: 'read again' });
      c = await card();
      assertEqual([c.headline, posts(await gpCalls()).length], ['ok', before + 1], 'one POST for both attempts');
      assert(!(await page.evaluate((d) => !!document.querySelector(d), GP_DIALOG)), 'no dialog for a re-read');
    });

    await step('a language switch while the result is pending keeps polling the paid measurement', async () => {
      await page.evaluate(() => { window.__gp.delayMs = 2500; });
      const before = posts(await gpCalls()).length;
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor(() => window.__gp.calls.some((c) => c.method === 'GET' && c.path.startsWith('/measurements/fakeMtaSts')
        && c.path.endsWith(String(window.__gp.n).padStart(6, '0'))), { timeout: 10000, message: 'first poll of the new measurement' });
      await setLangUi(page, 'tr');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done', { args: [MTASTS_CARD], timeout: 20000, message: 'result after the re-mount' });
      assertEqual(posts(await gpCalls()).length, before + 1, 'still one POST');
      assertEqual((await card()).headline, 'ok', 'the carried-over measurement was read');
      await page.evaluate(() => { window.__gp.delayMs = 0; });
      await setLangUi(page, 'en');
    });

    for (const [scheme, lang] of [['light', 'en'], ['dark', 'tr']]) {
      await step(`[375 px, ${scheme}, ${lang.toUpperCase()}] the card fits a phone`, async () => {
        await page.evaluate(() => { window.__gp.next.push('unmatched'); });
        await page.click('[data-action="mtasts-check"]');
        await page.waitFor((sel) => document.querySelector(`${sel} [data-mtasts-headline="problems"]`), { args: [MTASTS_CARD], timeout: 20000, message: 'problems again' });
        await page.setViewport({ width: 375, height: 812, mobile: true });
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await setLangUi(page, lang);
        await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done', { args: [MTASTS_CARD], message: 'card after re-mount' });
        await assertNoHorizontalScroll(page, `phone ${scheme}`);
        await shotCard(page, `health-mtasts-mobile-${scheme}-${lang}`);
        await shotCaa(page, `health-caa-mobile-${scheme}-${lang}`);
        await page.setViewport({ width: 1440, height: 900 });
        await page.emulateMedia({ 'prefers-color-scheme': 'light' });
        await setLangUi(page, 'en');
      });
    }

    await step('nothing left the page: no real Globalping request; i18n complete; no console errors', async () => {
      const blocked = await page.evaluate(() => window.__zoneBlocked.slice());
      assertEqual(netHits, [], 'https requests that reached the network');
      assert(!blocked.some((u) => u.includes('globalping')), `Globalping never reached the zone guard: ${blocked}`);
      const calls = await gpCalls();
      assertEqual(posts(calls).length, 7, 'seven fake probes in total');
      await checkI18n(page);
      await assertClean(page, 'mta-sts offline');
    });
  } finally {
    await page.close();
  }
}

/** Element screenshot of one details card, however tall (no-op with --no-shots). */
async function shotSelector(page, name, selector) {
  if (!SHOTS_ON) return;
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    window.scrollTo(0, 0);
    const r = el.getBoundingClientRect();
    return { x: Math.max(0, r.left + window.scrollX - 8), y: Math.max(0, r.top + window.scrollY - 8), width: r.width + 16, height: r.height + 16 };
  }, selector);
  if (!box) return;
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.ceil(box.height), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}
const shotCard = (page, name) => shotSelector(page, name, '.hlt-mtasts');
const shotCaa = (page, name) => shotSelector(page, name, '.hlt-caa');

/** The live groups: real DoH resolvers and RDAP registries. */
async function liveGroups(browser, server) {
  group('Desktop 1440×900 (English, live DNS + RDAP)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  await setLangUi(page, 'en');

  await step('a typed but unsubmitted domain survives a language switch without querying', async () => {
    await gotoHash(page, '#/health', 'health');
    await page.type('[data-role="health-domain"]', 'example.org');
    await page.evaluate(() => performance.clearResourceTimings());
    await setLangUi(page, 'tr');
    await page.evaluate(() => new Promise((resolve) => { setTimeout(resolve, 800); }));
    const info = await page.evaluate(() => ({
      requests: performance.getEntriesByType('resource').filter((e) => !e.name.startsWith(window.location.origin)).map((e) => e.name),
      hash: window.location.hash,
      domain: document.querySelector('[data-role="health-domain"]').value,
      report: !!document.querySelector('.hlt-hero')
    }));
    await setLangUi(page, 'en');
    assertEqual(info, { requests: [], hash: '#/health', domain: 'example.org', report: false }, 'draft kept, nothing sent');
  });

  await step('github.com via shared link: summary, grouped translated checks and detail panels', async () => {
    await gotoHash(page, '#/health?domain=github.com', 'health');
    await page.waitFor(DONE, { timeout: 60000, message: 'health report' });
    const r = await page.evaluate(reportInfo);
    assert(['ok', 'warn', 'error'].includes(r.light), `light ${r.light}`);
    assert(r.score >= 0 && r.score <= 100, `score ${r.score}`);
    assert(r.groups.includes('dns') && r.groups.includes('email') && r.groups.includes('registration'), `groups ${r.groups}`);
    assert(r.checks.length >= 12, `checks ${r.checks.length}`);
    assertEqual(r.untranslated, [], 'untranslated titles');
    assert(r.checks.some((c) => c.id === 'spf.present') && r.checks.some((c) => c.id.startsWith('dmarc.policy-')), 'SPF + DMARC checks');
    assert(/MarkMonitor/.test(r.rdap) && Number(r.expiryDays) > 0, `RDAP card: ${r.rdap.slice(0, 200)}`);
    assert(Number(r.meter) >= 1, `SPF lookup meter ${r.meter}`);
    assert(/quarantine|reject/.test(r.mail) && /DKIM/.test(r.mail), 'DMARC + DKIM blocks');
    assert(/DigiCert/.test(r.caa), `CAA lists CAs: ${r.caa.slice(0, 200)}`);
    // Worst-first ordering inside each group.
    const orderOk = await page.evaluate(() => [...document.querySelectorAll('.hlt-group')].every((g) => {
      const rank = { error: 0, warn: 1, info: 2, ok: 3 };
      const sev = [...g.querySelectorAll('.hlt-check')].map((c) => rank[c.dataset.severity]);
      return sev.every((v, i) => i === 0 || sev[i - 1] <= v);
    }));
    assert(orderOk, 'checks sorted worst first');
    await assertNoHorizontalScroll(page, 'github');
    await shot(page, 'health-desktop-light-en-github');
  });

  await step('filter "Warnings & errors" hides passed and info checks', async () => {
    await page.click('[data-control="health-filter"] [data-value="problems"]');
    const sev = await page.evaluate(() => [...document.querySelectorAll('.hlt-check')].map((c) => c.dataset.severity));
    assert(sev.every((s) => s === 'warn' || s === 'error'), `only problems: ${sev}`);
    await page.click('[data-control="health-filter"] [data-value="all"]');
  });

  await step('cloudflare.com: DNSSEC signed and validated; CAA and email extras', async () => {
    await page.type('[data-role="health-domain"]', 'cloudflare.com');
    await page.click('[data-action="run"]');
    await page.waitFor(() => window.location.hash.includes('domain=cloudflare.com'), { message: 'URL updated' });
    await page.waitFor(DONE, { timeout: 60000 });
    await page.waitFor(() => document.querySelector('.hlt-hero-domain')?.textContent === 'cloudflare.com');
    const r = await page.evaluate(reportInfo);
    assert(r.checks.some((c) => c.id === 'dnssec.ok'), `dnssec.ok check: ${r.checks.map((c) => c.id).filter((x) => x.startsWith('dnssec'))}`);
    assert(/Signed and validated/.test(r.dnssec) && /KSK/.test(r.dnssec), `DNSSEC card: ${r.dnssec.slice(0, 200)}`);
    assert(/MTA-STS/.test(r.mail), 'email extras');
  });

  await step('.tr domain: RDAP unsupported is explained (nic.tr), other checks still run', async () => {
    await gotoHash(page, '#/health?domain=trabis.gov.tr', 'health');
    await page.waitFor(() => document.querySelector('.hlt-hero-domain')?.textContent === 'trabis.gov.tr' && !document.querySelector('[data-action="run"]').hidden, { timeout: 60000 });
    const r = await page.evaluate(reportInfo);
    assert(/nic\.tr/.test(r.rdap), `RDAP explanation: ${r.rdap}`);
    assert(r.checks.some((c) => c.id === 'rdap.unsupported'), 'rdap.unsupported check');
    assert(r.checks.some((c) => c.id.startsWith('ns.')), 'NS checks ran');
    await shot(page, 'health-desktop-light-en-tr');
  });

  await step('validation: IPs and garbage are rejected', async () => {
    await page.type('[data-role="health-domain"]', '8.8.8.8');
    await page.click('[data-action="run"]');
    await page.waitFor(() => !!document.querySelector('.hlt-form .field.has-error'));
    assert((await page.evaluate(() => window.location.hash)).includes('trabis.gov.tr'), 'URL unchanged');
  });

  await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
  await step('[dark] report renders; language switch keeps the report and translates it', async () => {
    await gotoHash(page, '#/health?domain=github.com', 'health');
    await page.waitFor(() => document.querySelector('.hlt-hero-domain')?.textContent === 'github.com' && !document.querySelector('[data-action="run"]').hidden, { timeout: 60000 });
    await shot(page, 'health-desktop-dark-en-github');
    const before = await page.evaluate(reportInfo);
    await setLangUi(page, 'tr');
    await page.waitFor(() => document.querySelector('[data-action="run"] .btn-label')?.textContent === 'Sağlığı kontrol et', { message: 'TR form' });
    const after = await page.evaluate(reportInfo);
    assertEqual(after.checks, before.checks, 'same checks (restored, not re-run)');
    assertEqual(after.untranslated, [], 'untranslated titles (TR)');
    const title = await page.evaluate(() => document.querySelector('.hlt-group .card-title').textContent);
    assertEqual(title, 'DNS', 'group label');
    assert(await page.evaluate(() => /Kayıt|Sağlıklı|İlgilenilmesi|Sorun/.test(document.querySelector('.hlt-hero').textContent)), 'Turkish hero');
    await assertNoHorizontalScroll(page, 'dark tr');
    await shot(page, 'health-desktop-dark-tr-github');
    await setLangUi(page, 'en');
  });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });

  await step('i18n: no missing keys; hlt.* + health.* TR/EN key sets match', () => checkI18n(page));
  await step('desktop: no console errors, exceptions or CSP violations', () => assertClean(page, 'desktop'));
  await page.close();

  group('Phone 390×844 (Turkish)');
  const phone = await browser.newPage('about:blank', { width: 390, height: 844, mobile: true });
  await phone.goto(`${server.url}#/about`);
  await waitReady(phone);
  await setLangUi(phone, 'tr');
  for (const scheme of ['light', 'dark']) {
    await step(`[${scheme}] report fits 390 px`, async () => {
      await phone.emulateMedia({ 'prefers-color-scheme': scheme });
      await gotoHash(phone, '#/about', 'about');
      const domain = scheme === 'light' ? 'github.com' : 'example.com';
      await gotoHash(phone, `#/health?domain=${domain}`, 'health');
      await phone.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d && !document.querySelector('[data-action="run"]').hidden, { timeout: 60000, args: [domain] });
      await assertNoHorizontalScroll(phone, `phone ${scheme}`);
      await shot(phone, `health-mobile-${scheme}-tr`);
    });
  }
  await step('phone: no console errors, exceptions or CSP violations', () => assertClean(phone, 'phone'));
  await step('phone: i18n complete', () => checkI18n(phone));
  await phone.close();
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  group('Pure helpers (Node)');
  await step('healthScore / trafficLight', () => {
    assertEqual(healthScore({ ok: 10 }), 100, 'perfect');
    assertEqual(healthScore({ error: 1, warn: 2 }), 68, 'mixed');
    assertEqual(healthScore({ error: 9 }), 0, 'clamped');
    assertEqual(healthScore(null), 100, 'null');
    assertEqual([trafficLight({ error: 1, warn: 3 }), trafficLight({ warn: 1 }), trafficLight({ ok: 4, info: 2 })], ['error', 'warn', 'ok'], 'lights');
  });
  await step('groupChecks (worst first, stable) / parseSelectors', () => {
    const checks = [
      { id: 'a', severity: 'ok', group: 'dns' }, { id: 'b', severity: 'error', group: 'dns' },
      { id: 'c', severity: 'warn', group: 'email' }, { id: 'd', severity: 'info' }, { id: 'e', severity: 'error', group: 'dns' }
    ];
    assertEqual(groupChecks(checks, 'dns').map((c) => c.id), ['b', 'e', 'd', 'a'], 'dns group');
    assertEqual(groupChecks(checks, 'email').map((c) => c.id), ['c'], 'email group');
    assertEqual(HEALTH_GROUPS, ['dns', 'email', 'security', 'registration'], 'group order');
    assertEqual(parseSelectors('Mailgun, s1024._domainkey.example.com google bad!sel mailgun'), ['mailgun', 's1024'], 'selectors');
  });
  await step('every check id has EN + TR title/detail strings', () => {
    const missing = [];
    for (const id of HEALTH_CHECK_IDS) {
      for (const lang of ['en', 'tr']) {
        for (const part of ['title', 'detail']) if (!HEALTH_I18N[lang][`health.${id}.${part}`]) missing.push(`${lang}:${id}.${part}`);
      }
    }
    assertEqual(missing, [], 'missing health strings');
  });

  await mkdir(SHOTS, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: BROWSER, headless: !HEADED });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}\n`);

  try {
    await mtaStsGroup(browser, server);
    if (OFFLINE) process.stdout.write('\n(--offline: the live DNS + RDAP groups are skipped)\n');
    else await liveGroups(browser, server);
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
