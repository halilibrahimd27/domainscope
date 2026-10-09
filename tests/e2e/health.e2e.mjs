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
 * (only dns-01, with its renewal note; a wrong-case DNS-01 allows no method) and the MTA-STS
 * policy check: nothing sent before the click; one free /limits read and the consent + cost
 * dialog (Escape / Cancel sends nothing); exactly the lib/mtasts request; a valid policy
 * covering both MX hosts; keyboard focus back on the card's button after the dialog and after
 * the result, every outcome announced; "Check again" without a dialog and an MX host the policy
 * misses (error); the policy in "Report (JSON)"; a language switch that keeps the result
 * without a new probe; a quota at 0 (nothing asked or sent); a policy host that does not
 * resolve; mode none ("off", never "every MX host matches"); a policy served as
 * application/octet-stream (strict senders ignore it: an error headline, never "works"); a failed
 * MX and AAAA lookup (mxfail.example.com: "lookup failed" in the DNS card, never a dash or "no
 * IPv6"; the policy check "not compared", never "no MX"); "Show the fix" of an SPF "+all" (the
 * record with ~all, the other TXT record kept by the Route 53 change batch, the link that opens it
 * in the DNS change request, nothing sent) and of a CAA tag marked critical that no CA knows (only
 * the flag cleared); 1440 px and a 375 px phone, light and dark, without horizontal scroll.
 * It also clicks Copy summary (a clipboard recorder, scan.e2e.mjs stubClipboard): the Markdown and
 * plain text of what the hero and the checks show with the permalink, Turkish, and the dialog a
 * refused clipboard gets; then a second check that is stopped: the button is off while it runs,
 * and the report left on screen is copied (and printed) with its own link, not the new route's.
 * A second offline group covers the Web category (ui/health-v2.js over lib/healthweb.js): the Web
 * card (the HTTPS record, www against the bare domain, the HSTS preload link), the problems-first
 * panel scoring the Web category, and the HTTP security grade from a fake Mozilla HTTP Observatory
 * answered in the page — nothing sent on arrival, one POST on the click (the grade with its
 * failing-test count and the MDN report link), and a failure shown as a status with Retry, never a
 * grade; a network guard proves no Observatory request ever left the page.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { installDownloadCapture, resultAction, stubClipboard, takeClipboard, takeDownloads, zoneHandoffScript } from './scan.e2e.mjs';
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
const NL = '\n';

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
    CAA: [
      { flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=dns-01' },
      { flags: 0, tag: 'issue', value: 'sectigo.com; validationmethods=DNS-01' }, // labels are case-sensitive: no method at all
      { flags: 0, tag: 'issuewild', value: ';' }
    ]
  },
  'ns1.example.com': { A: ['192.0.2.53'] },
  'ns2.example.com': { A: ['198.51.100.53'] },
  'mx.example.com': { A: ['192.0.2.25'] },
  'alt1.mx.example.com': { A: ['198.51.100.25'] },
  '_mta-sts.example.com': { TXT: [['v=STSv1; id=20260927T1200']] },
  '_smtp._tls.example.com': { TXT: [['v=TLSRPTv1; rua=mailto:tls-reports@example.com']] },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']] },
  // A name whose MX and AAAA queries fail (SERVFAIL) while its _mta-sts record answers.
  'mxfail.example.com': { A: ['192.0.2.81'], MX: [{ preference: 10, exchange: 'mx.example.com' }], RCODE: { MX: 'SERVFAIL', AAAA: 'SERVFAIL' } },
  '_mta-sts.mxfail.example.com': { TXT: [['v=STSv1; id=20260927T1300']] },
  // Two v=STSv1 records: senders assume no policy (RFC 8461 §3.1), however valid the file is.
  'twosts.example.com': { A: ['192.0.2.82'], MX: [{ preference: 10, exchange: 'mx.example.com' }, { preference: 20, exchange: 'alt1.mx.example.com' }] },
  '_mta-sts.twosts.example.com': { TXT: [['v=STSv1; id=20260927T1400'], ['v=STSv1; id=20260927T1401']] },
  // A zone of its own whose SPF lets every server send ("+all") next to a site verification, and whose
  // CAA set has an unknown tag marked critical (every CA must refuse): "Show the fix" of both.
  'fix.example.com': {
    A: ['192.0.2.83'], SOA: [{ ...MAIL_SOA, mname: 'ns1.example.com' }], NS: ['ns1.example.com', 'ns2.example.com'],
    MX: [{ preference: 10, exchange: 'mx.example.com' }], TXT: [['v=spf1 mx +all'], ['site-verification=fix123']],
    CAA: [{ flags: 128, tag: 'tbs', value: 'unknown' }, { flags: 0, tag: 'issue', value: 'letsencrypt.org' }]
  }
};
const MTASTS_CARD = '[data-mtasts="card"]';
const GP_DIALOG = 'dialog.gp-confirm[open]';

/**
 * RDAP answered in the page: while `window.__rdap.on` is false every RDAP request (the IANA
 * bootstrap, the registry, rdap.org) fails like a blocked or unreachable service; once it is on,
 * the bootstrap sends .com to rdap.example.net, which knows example.com (registered by "Example
 * Registrar, Inc.", expiring in 400 days). Requests are recorded in __rdap.calls.
 */
const RDAP_FAKE_SCRIPT = `(() => {
  const inner = window.fetch;
  const rdap = window.__rdap = { on: false, calls: [] };
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/rdap+json' } });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!/^https:\\/\\/(data\\.iana\\.org\\/rdap\\/|rdap\\.example\\.net\\/|rdap\\.org\\/)/.test(url)) return inner(input, init);
    rdap.calls.push(url);
    if (!rdap.on) throw new TypeError('Failed to fetch');
    if (url === 'https://data.iana.org/rdap/dns.json') return json({ services: [[['com', 'net', 'org'], ['https://rdap.example.net/']]] });
    if (url === 'https://rdap.example.net/domain/example.com') {
      return json({
        objectClassName: 'domain', ldhName: 'EXAMPLE.COM', status: ['client transfer prohibited'],
        entities: [{ roles: ['registrar'], publicIds: [{ type: 'IANA Registrar ID', identifier: '376' }], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar, Inc.']]] }],
        events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }, { eventAction: 'expiration', eventDate: new Date(Date.now() + 400 * 864e5).toISOString() }],
        secureDNS: { delegationSigned: false },
        nameservers: [{ ldhName: 'NS1.EXAMPLE.COM' }, { ldhName: 'NS2.EXAMPLE.COM' }]
      });
    }
    return json({ errorCode: 404, title: 'Not Found' }, 404);
  };
})();`;

/**
 * Fake Mozilla HTTP Observatory (window.__obs) answered in the page, so no real request ever
 * leaves: one `POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=…` returns the next
 * scenario of window.__obs.next (default 'ok'): a grade with its counts, a 429 with Retry-After,
 * an HTTP error carrying the API's reason, or a 200 with no grade. window.__obs.delayMs delays the
 * answer and honours the request's abort signal. Every call is recorded in window.__obs.calls.
 */
const fakeObservatoryScript = `(() => {
  const inner = window.fetch;
  const obs = window.__obs = { calls: [], next: [], delayMs: 0 };
  const json = (status, body, headers) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*', ...(headers || {}) } });
  const SCENARIOS = {
    ok: () => json(200, { grade: 'B+', score: 75, tests_failed: 3, tests_passed: 9, tests_quantity: 12, status_code: 200, scanned_at: new Date(Date.now() - 120000).toISOString(), algorithm_version: 4 }),
    rate: () => json(429, { error: 'rate limited' }, { 'retry-after': '30' }),
    httperror: () => json(422, { error: 'invalid-hostname-lookup', message: 'could not resolve the host name' }),
    nograde: () => json(200, { error: 'scan failed' })
  };
  window.fetch = async (input, init) => {
    init = init || {};
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!url.startsWith('https://observatory-api.mdn.mozilla.net/')) return inner(input, init);
    const method = String(init.method || (input && input.method) || 'GET').toUpperCase();
    obs.calls.push({ method, url });
    const signal = init.signal || (typeof input === 'object' && input && input.signal) || null;
    if (signal && signal.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
    if (obs.delayMs) await new Promise((resolve, reject) => {
      const to = setTimeout(resolve, obs.delayMs);
      if (signal) signal.addEventListener('abort', () => { clearTimeout(to); reject(new DOMException('The operation was aborted.', 'AbortError')); }, { once: true });
    });
    const scenario = obs.next.shift() || 'ok';
    return (SCENARIOS[scenario] || SCENARIOS.ok)();
  };
})();`;

/** What the RDAP card shows. */
function rdapInfo() {
  const card = document.querySelector('.hlt-rdap');
  if (!card) return null;
  const marks = [...card.querySelectorAll('.na-mark')];
  return {
    state: card.dataset.rdap,
    na: marks.length,
    title: marks[0]?.title || null,
    status: card.querySelector('.hlt-rdap-status')?.textContent || null,
    retry: !!card.querySelector('[data-action="retry-source"]'),
    text: card.textContent.replace(/\s+/g, ' '),
    days: card.querySelector('.hlt-expiry')?.dataset.days ?? null
  };
}

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

/** Where keyboard focus is: the MTA-STS button, <body> or another element. */
function focusInfo() {
  const a = document.activeElement;
  if (!a || a === document.body) return 'body';
  return a.matches('[data-mtasts="card"] [data-action="mtasts-check"]') ? 'mtasts-check' : `${a.tagName.toLowerCase()}.${a.className}`;
}

/** Wait until the page's polite live region (ui/components.announce, on <body>, written after 60 ms) matches `re`. */
const announced = (page, re, message) => page.waitFor((src) => [...document.querySelectorAll('body > .sr-only[aria-live="polite"]')]
  .some((region) => new RegExp(src).test(region.textContent)), { args: [re.source], timeout: 5000, message });

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
    off: { ...live.result, rawBody: 'version: STSv1\r\nmode: none\r\nmax_age: 86400\r\n' },
    // what an S3 / CDN upload often gets: a type strict senders refuse
    wrongtype: { ...live.result, headers: { ...live.result.headers, 'content-type': 'application/octet-stream' } },
    // the live policy on mta-sts.mxfail.example.com, with a certificate for that name
    mxfail: { ...live.result, tls: { ...live.result.tls, subject: { CN: 'mta-sts.mxfail.example.com', alt: 'DNS:mta-sts.mxfail.example.com' } } },
    twosts: { ...live.result, tls: { ...live.result.tls, subject: { CN: 'mta-sts.twosts.example.com', alt: 'DNS:mta-sts.twosts.example.com' } } },
    nohost: m27.final.body.results[0].result
  };

  group('Offline: CAA restrictions and the MTA-STS policy check (emulated example.com, fake Globalping)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const netHits = await networkGuard(page);
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(MAIL_APEX, MAIL_ZONE) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeGlobalpingScript(results, live.probe) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: RDAP_FAKE_SCRIPT });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeObservatoryScript });
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
        unusable: [...document.querySelectorAll('.hlt-caa [data-caa="unusable"]')].map((x) => `${x.dataset.issuer}: ${x.querySelector('.hlt-ca-problem')?.textContent}`),
        note: document.querySelector('.hlt-caa [data-note="methods"]')?.textContent || '',
        text: document.querySelector('.hlt-caa')?.textContent.replace(/\s+/g, ' ') || ''
      }));
      assertEqual(caa.restricted, ['letsencrypt.org'], 'CAA: letsencrypt.org restricted');
      assertEqual(caa.unusable.length, 1, `CAA: sectigo.com unusable: ${caa.unusable}`);
      assert(/^sectigo\.com: .*case-sensitive/.test(caa.unusable[0]), `DNS-01 is no method: ${caa.unusable[0]}`);
      assert(/only dns-01/.test(caa.text) && /http-01/.test(caa.note), `CAA restriction and renewal note: ${caa.note}`);
      assertEqual(await gpCalls(), [], 'no Globalping call, not even /limits');
      await assertNoHorizontalScroll(page, 'mta-sts idle');
    });

    await step('first check (keyboard): one free /limits read and the consent dialog (host, path, cost); Escape sends nothing, focus comes back', async () => {
      await page.evaluate(() => document.querySelector('[data-action="mtasts-check"]').focus());
      await page.press('Enter');
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
      await page.press('Escape');
      await page.waitFor((d) => !document.querySelector(d), { args: [GP_DIALOG], message: 'dialog closed' });
      await settled('card back to idle');
      assertEqual((await card()).state, 'idle', 'Escape restores the card');
      assertEqual(posts(await gpCalls()).length, 0, 'Escape sends nothing');
      assertEqual(await page.evaluate(focusInfo), 'mtasts-check', 'keyboard focus back on the button, not <body>');
    });

    await step('Cancel sends nothing either, and focus comes back', async () => {
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((d) => document.querySelector(d), { args: [GP_DIALOG], message: 'consent dialog again (Escape granted nothing)' });
      await page.click(`${GP_DIALOG} .modal-foot .btn:not(.btn-primary)`);
      await page.waitFor((d) => !document.querySelector(d), { args: [GP_DIALOG], message: 'dialog closed' });
      await settled('card back to idle');
      assertEqual(posts(await gpCalls()).length, 0, 'Cancel sends nothing');
      assertEqual(await page.evaluate(focusInfo), 'mtasts-check', 'focus on the button after Cancel');
    });

    await step('Send (keyboard): exactly the lib/mtasts request; the policy is valid and matches both MX hosts; focus stays on the card', async () => {
      await page.evaluate(() => document.querySelector('[data-action="mtasts-check"]').focus());
      await page.press('Enter');
      await page.waitFor((d) => document.querySelector(d), { args: [GP_DIALOG], message: 'consent dialog again (cancel granted nothing)' });
      assertEqual(await page.evaluate((d) => document.activeElement === document.querySelector(`${d} .modal-foot .btn-primary`), GP_DIALOG), true,
        'the dialog focuses "Send and check"');
      await page.press('Enter');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done', { args: [MTASTS_CARD], timeout: 20000, message: 'policy checked' });
      assertEqual(await page.evaluate(focusInfo), 'mtasts-check', 'keyboard focus on "Check again", not <body>');
      await announced(page, /every MX host matches it/, 'the verdict is announced');
      const calls = await gpCalls();
      assertEqual(posts(calls).map((c) => c.body), [mtaStsPolicyRequest(MAIL_APEX)], 'one POST: the HTTPS GET of the policy');
      const c = await card();
      assertEqual(c.headline, 'ok', 'headline');
      assertEqual(c.mx, ['mx.example.com:true', 'alt1.mx.example.com:true'], 'both MX hosts matched');
      for (const id of ['tls.ok', 'mode.enforce', 'max-age.days', 'mx.ok', 'mx.unused']) assert(c.findings.some((f) => f.id === id), `finding ${id}: ${JSON.stringify(c.findings)}`);
      assertEqual(c.findings[0].severity, 'info', 'worst first (no error or warning here)');
      assert(/86,400 seconds is less than a week/.test(c.text), 'max_age grouped in the finding, like the max_age row');
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
      // In the result header's Export ▾ menu (opened first, as a person would).
      await resultAction(page, '[data-action="download"]', '.hlt-hero');
      await page.waitFor(() => (window.__downloads || []).length > 0, { message: 'download' });
      const [d] = await takeDownloads(page);
      const json = JSON.parse(d.text);
      assertEqual([json.domain, json.mtaStsPolicy?.headline, json.mtaStsPolicy?.measurementId, json.mtaStsPolicy?.url],
        [MAIL_APEX, 'problems', 'fakeMtaSts000002', 'https://mta-sts.example.com/.well-known/mta-sts.txt'], 'mtaStsPolicy block');
      assert(json.mtaStsPolicy.findings.some((f) => f.id === 'mx.unmatched'), 'findings exported');
    });

    await step('Copy summary: Markdown and plain text of what the hero and the checks show, the permalink, TR; a blocked clipboard gets a dialog', async () => {
      await stubClipboard(page);
      const shown = await page.evaluate(() => ({
        score: document.querySelector('.hlt-hero').dataset.score,
        grade: document.querySelector('.hlt-hero').dataset.grade,
        verdict: document.querySelector('.hlt-hero-verdict').textContent,
        problems: [...document.querySelectorAll('.hlt-check')].filter((c) => c.dataset.severity === 'error' || c.dataset.severity === 'warn')
          .map((c) => c.querySelector('.hlt-check-title').textContent),
        tip: document.querySelector('[data-action="copy-summary"]').title
      }));
      assert(/nothing from your server list/.test(shown.tip) && !/file/.test(shown.tip), `the tooltip says what is in it (no file here): ${shown.tip}`);
      await page.click('[data-action="copy-summary"]');
      await page.click('[data-action="copy-summary-text"]');
      await page.waitFor(() => window.__clip.length === 2, { message: 'two copies' });
      const [md, text] = await takeClipboard(page);
      const lines = md.trim().split(NL);
      assertEqual(lines[0], `**Domain Health · \`${MAIL_APEX}\`**`, 'title (the domain as a code span)');
      assertEqual(lines[1], `- ${shown.verdict} · grade ${shown.grade} · score ${shown.score}/100`, 'verdict, grade and score as on the hero');
      // Lines with text (the Markdown footer is its own paragraph, after an empty line).
      assert(lines.length - 1 >= 5 && lines.length - 1 <= 12, `5–12 lines: ${lines.length - 1}`);
      for (const title of shown.problems.slice(0, 5)) assert(md.includes(title), `problem "${title}" in: ${md}`);
      assertEqual(lines[lines.length - 2], '', 'an empty line before the footer');
      assert(/^DomainScope · checked \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC · http:\/\/127\.0\.0\.1:\d+\/domainscope\/#\/health\?domain=example\.com$/.test(lines[lines.length - 1]),
        `footer with the permalink: ${lines[lines.length - 1]}`);
      assert(!text.includes('**') && text.startsWith(`Domain Health · ${MAIL_APEX}${NL}`), `plain text: ${text}`);
      assertEqual(text.trim().split(NL).length, lines.length - 1, 'the same lines in plain text, no empty one');
      // Turkish, then a clipboard the browser refuses: the text in a dialog, selected.
      await setLangUi(page, 'tr');
      await stubClipboard(page, { fail: true });
      await page.click('[data-action="copy-summary"]');
      const dlg = await page.waitFor(() => {
        const area = document.querySelector('dialog.sum-fallback[open] textarea');
        return area ? { value: area.value, selected: area.selectionStart === 0 && area.selectionEnd === area.value.length, focused: document.activeElement === area } : false;
      }, { message: 'fallback dialog' });
      const trLines = dlg.value.split(NL);
      assert(trLines[0] === `**Alan Adı Sağlığı · \`${MAIL_APEX}\`**` && / · puan \d+\/100$/.test(trLines[1]), `Turkish summary in the dialog: ${dlg.value}`);
      assertEqual([dlg.selected, dlg.focused], [true, true], 'the text is focused and selected, ready for Ctrl+C');
      await page.press('Escape');
      await page.waitFor(() => !document.querySelector('dialog.sum-fallback'), { message: 'dialog closed' });
      await stubClipboard(page);
      await setLangUi(page, 'en');
    });

    await step('[dark, TR] a language switch keeps the result and sends nothing', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      const before = (await gpCalls()).length;
      await setLangUi(page, 'tr');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done', { args: [MTASTS_CARD], message: 'restored card' });
      const c = await card();
      assertEqual([c.headline, c.button], ['problems', 'Yeniden kontrol et (1 ölçüm)'], 'restored in Turkish');
      assert(/MTA-STS politikası|Politika/.test(c.text) && /mx kalıbı yok/.test(c.text), `Turkish card: ${c.text.slice(0, 200)}`);
      assert(/en fazla 1\.209\.600 saniye/.test(c.text), 'max_age grouped the Turkish way in the finding');
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
      try {
        const before = (await gpCalls()).length;
        await page.evaluate(() => document.querySelector('[data-action="mtasts-check"]').focus());
        await page.press('Enter');
        await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'quota', { args: [MTASTS_CARD], message: 'quota state' });
        const calls = (await gpCalls()).slice(before);
        assertEqual(calls.map((x) => `${x.method} ${x.path}`), ['GET /limits'], 'only the free quota read');
        assert(!(await page.evaluate((d) => !!document.querySelector(d), GP_DIALOG)), 'no dialog');
        assert(/quota is used up/.test((await card()).text), 'quota message');
        await announced(page, /quota is used up/, 'the quota outcome is announced');
        assertEqual(await page.evaluate(focusInfo), 'mtasts-check', 'focus on the button in the quota state');
      } finally {
        await page.evaluate(() => window.__gpNewWindow(200)); // the later steps need probes
      }
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

    await step('mode none: the headline says MTA-STS is off, as information, and claims no MX match', async () => {
      await page.evaluate(() => { window.__gp.next.push('off'); });
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(`${sel} [data-mtasts-headline="off"]`), { args: [MTASTS_CARD], timeout: 20000, message: 'off verdict' });
      const c = await card();
      assert(c.findings.some((f) => f.id === 'mode.none') && !c.findings.some((f) => f.id.startsWith('mx.')), `findings: ${JSON.stringify(c.findings)}`);
      assertEqual(await page.evaluate((sel) => document.querySelector(`${sel} [data-mtasts-headline]`).classList.contains('alert-info'), MTASTS_CARD), true, 'an info alert, not a green one');
      assert(/switches MTA-STS off/.test(c.text) && !/every MX host matches/.test(c.text), 'headline text');
      await announced(page, /switches MTA-STS off/, 'announced');
    });

    await step('served as application/octet-stream: strict senders ignore it, an error headline (never "works"); the MX table still shows', async () => {
      await page.evaluate(() => { window.__gp.next.push('wrongtype'); });
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(`${sel} [data-mtasts-headline="wrong-type"]`), { args: [MTASTS_CARD], timeout: 20000, message: 'wrong-type verdict' });
      const c = await card();
      assertEqual(c.findings[0], { id: 'http.content-type', severity: 'error' }, 'the media type first, as an error');
      assertEqual(c.mx, ['mx.example.com:true', 'alt1.mx.example.com:true'], 'senders that do not check the type use it: still compared');
      assertEqual(await page.evaluate((sel) => document.querySelector(`${sel} [data-mtasts-headline]`).classList.contains('alert-error'), MTASTS_CARD), true, 'a red alert');
      assert(/Strict senders ignore this policy/.test(c.text) && /application\/octet-stream/.test(c.text) && !/The policy works/.test(c.text), 'headline and finding text');
      await announced(page, /Strict senders ignore this policy/, 'announced');
      await shotCard(page, 'health-mtasts-desktop-light-en-wrong-type');
    });

    await step('a result that cannot be read: the paid measurement is read again, never a new probe', async () => {
      await page.evaluate(() => { window.__gp.getDown = true; });
      const before = posts(await gpCalls()).length;
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'error', { args: [MTASTS_CARD], timeout: 20000, message: 'error state' });
      await announced(page, /^The policy could not be checked: ./, 'the error is announced');
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

    await step('a second check stopped at once: Copy summary is off while it runs, then copies the report on screen with its own link (the print header too)', async () => {
      await stubClipboard(page);
      const shown = await page.evaluate(() => document.querySelector('.hlt-hero-domain').textContent);
      const other = `www.${MAIL_APEX}`; // not a later step's hash: those navigate by hash change
      // Start and stop in one task: the check never gets to answer, the old report stays.
      const during = await page.evaluate((d) => {
        document.querySelector('[data-role="health-domain"]').value = d;
        document.querySelector('[data-action="run"]').click();
        const disabled = [...document.querySelectorAll('.hlt-hero [data-summary="health"] button')].map((b) => b.disabled);
        const hash = location.hash;
        document.querySelector('[data-action="stop"]').click();
        return { disabled, hash };
      }, other);
      assertEqual(during, { disabled: [true, true], hash: `#/health?domain=${other}` }, 'both buttons off while the check runs; the route already names the new domain');
      await page.waitFor(() => !document.querySelector('[data-action="run"]').hidden
        && !document.querySelector('.hlt-hero [data-action="copy-summary"]').disabled, { message: 'stopped, the button back on' });
      assertEqual(await page.evaluate(() => document.querySelector('.hlt-hero-domain').textContent), shown, 'the previous report stays on screen');
      await page.click('.hlt-hero [data-action="copy-summary"]');
      await page.waitFor(() => window.__clip.length === 1, { message: 'copied' });
      const lines = (await takeClipboard(page))[0].trim().split(NL);
      assertEqual(lines[0], `**Domain Health · \`${shown}\`**`, 'the report on screen');
      assert(lines[lines.length - 1].endsWith(`/domainscope/#/health?domain=${shown}`), `its own link, not the route's: ${lines[lines.length - 1]}`);
      await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
      const printed = await page.evaluate(() => document.querySelector('.print-head .print-permalink')?.getAttribute('href') || '');
      await page.evaluate(() => window.dispatchEvent(new Event('afterprint')));
      assert(printed.endsWith(`/domainscope/#/health?domain=${shown}`), `the print header links to the printed report: ${printed}`);
    });

    await step('after the stop the report on screen still works: Copy link, the filter, RDAP Retry, the policy check, and it is kept on leaving', async () => {
      const shown = await page.evaluate(() => document.querySelector('.hlt-hero-domain').textContent);
      await takeClipboard(page);
      await resultAction(page, '[data-action="copy-link"]', '.hlt-hero');
      await page.waitFor(() => window.__clip.length === 1, { message: 'Copy link' });
      const link = (await takeClipboard(page))[0];
      assert(link.endsWith(`/domainscope/#/health?domain=${shown}`), `Copy link shares the report on screen: ${link}`);
      await page.click('[data-control="health-filter"] [data-value="problems"]');
      const sev = await page.evaluate(() => [...document.querySelectorAll('.hlt-check')].map((c) => c.dataset.severity));
      assert(sev.length > 0 && sev.every((s) => s === 'warn' || s === 'error'), `the filter re-renders the checks: ${sev}`);
      await page.click('[data-control="health-filter"] [data-value="all"]');
      const rdapBefore = await page.evaluate(() => window.__rdap.calls.length);
      await page.click('.hlt-rdap [data-action="retry-source"]');
      await page.waitFor((n) => window.__rdap.calls.length > n, { args: [rdapBefore], timeout: 15000, message: 'RDAP Retry asks RDAP again' });
      await page.evaluate(() => { window.__gp.next.push('ok'); });
      const before = (await gpCalls()).length;
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(`${sel}[data-state="done"] [data-mtasts-headline="ok"]`),
        { args: [MTASTS_CARD], timeout: 20000, message: 'the policy check of the report on screen' });
      assertEqual(posts((await gpCalls()).slice(before)).length, 1, 'one measurement');
      await gotoHash(page, '#/lookup', 'lookup');
      await gotoHash(page, '#/health', 'health');
      await page.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d, { args: [shown], timeout: 10000, message: 'the report is kept on leaving' });
    });

    await step('a failed MX lookup: the DNS card says so, and the policy check says it compared nothing, never "no MX"', async () => {
      const domain = `mxfail.${MAIL_APEX}`;
      await gotoHash(page, `#/health?domain=${domain}`, 'health');
      await page.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d && !document.querySelector('[data-action="run"]').hidden,
        { args: [domain], timeout: 30000, message: 'mxfail report' });
      let c = await card();
      assertEqual([c.state, c.button], ['idle', 'Check the policy (1 Globalping probe)'], 'the card shows for the _mta-sts record');
      const dnsText = await page.evaluate(() => document.querySelector('.hlt-dns').textContent.replace(/\s+/g, ' '));
      assert(/Mail servers \(MX\)\s*lookup failed/.test(dnsText), `DNS card MX row: ${dnsText.slice(0, 300)}`);
      // A failed AAAA lookup is never a bare dash nor "no IPv6".
      assert(/IPv6 \(AAAA\)\s*lookup failed/.test(dnsText) && /IPv4 \(A\)\s*192\.0\.2\.81/.test(dnsText), `DNS card address rows: ${dnsText.slice(0, 400)}`);
      const ids = (await page.evaluate(reportInfo)).checks.map((x) => x.id);
      assert(ids.includes('apex.ok') && !ids.includes('ipv6.missing'), `address checks: ${ids.filter((x) => /apex|ipv6/.test(x))}`);
      const apex = await page.evaluate(() => document.querySelector('.hlt-check[data-id="apex.ok"] .hlt-check-detail')?.textContent);
      assertEqual(apex, 'IPv4: 192.0.2.81; IPv6: lookup failed.', '"Domain resolves" names the failed family, no dash');
      await page.evaluate(() => { window.__gp.next.push('mxfail'); });
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done', { args: [MTASTS_CARD], timeout: 20000, message: 'policy checked' });
      c = await card();
      assertEqual(c.headline, 'mx-unknown', 'headline');
      assert(c.findings.some((f) => f.id === 'mx.unknown') && !c.findings.some((f) => f.id === 'mx.none'), `findings: ${JSON.stringify(c.findings)}`);
      assertEqual(c.mx, [], 'no MX table');
      assert(/MX lookup failed/.test(c.text) && !/no MX hosts to compare|publishes no MX/.test(c.text), 'no "no MX" claim');
      await shotCard(page, 'health-mtasts-desktop-light-en-mx-unknown');
    });

    await step('two _mta-sts records: the TXT row says senders ignore them, and a valid policy is never "ok"', async () => {
      const domain = `twosts.${MAIL_APEX}`;
      await gotoHash(page, `#/health?domain=${domain}`, 'health');
      await page.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d && !document.querySelector('[data-action="run"]').hidden,
        { args: [domain], timeout: 30000, message: 'twosts report' });
      const badge = () => page.evaluate((sel) => document.querySelector(`${sel} .hlt-mtasts-txt-invalid`)?.textContent ?? null, MTASTS_CARD);
      assertEqual(await badge(), 'not valid: senders ignore it', 'the TXT row is marked');
      await page.evaluate(() => { window.__gp.next.push('twosts'); });
      await page.click('[data-action="mtasts-check"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.state === 'done', { args: [MTASTS_CARD], timeout: 20000, message: 'policy checked' });
      const c = await card();
      assertEqual(c.headline, 'txt-invalid', 'headline');
      assert(c.findings.some((f) => f.id === 'txt.invalid') && !c.findings.some((f) => f.id === 'txt.missing'), `findings: ${JSON.stringify(c.findings)}`);
      assert(/RFC 8461 §3\.1/.test(c.text), 'the finding cites the rule');
      assertEqual(await badge(), 'not valid: senders ignore it', 'still marked after the check');
      await shotCard(page, 'health-mtasts-desktop-light-en-txt-invalid');
    });

    await step('RDAP out of reach: its fields say n/a and why, never "—"; Retry (keyboard) asks RDAP alone again, the summary link keeps the selectors', async () => {
      await gotoHash(page, `#/health?domain=${MAIL_APEX}&selectors=custom1`, 'health');
      await page.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d && !document.querySelector('[data-action="run"]').hidden,
        { args: [MAIL_APEX], timeout: 30000, message: 'example.com report' });
      let r = await page.evaluate(rdapInfo);
      assertEqual([r.state, r.na, r.retry], ['failed', 5, true], 'failed RDAP card');
      assertEqual(r.title, 'RDAP: could not be reached (offline, blocked, or no browser access)', 'n/a tooltip');
      assertEqual(r.status, r.title, 'the reason is also written out (touch screens have no tooltip)');
      assert(!/—/.test(r.text), `no silent dash: ${r.text}`);
      assert((await page.evaluate(reportInfo)).checks.some((c) => c.id === 'rdap.error'), 'rdap.error check');
      await shotSelector(page, 'health-rdap-desktop-light-en-failed', '.hlt-rdap');
      const before = await page.evaluate(() => ({ dns: window.__zoneDnsQueries, rdap: window.__rdap.calls.length, score: document.querySelector('.hlt-hero').dataset.score }));
      await page.evaluate(() => {
        window.__rdap.on = true;
        document.querySelector('.hlt-rdap [data-action="retry-source"]').focus();
      });
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.hlt-rdap')?.dataset.rdap === 'ok', { timeout: 15000, message: 'RDAP answered' });
      r = await page.evaluate(rdapInfo);
      assert(/Example Registrar, Inc\./.test(r.text) && Number(r.days) >= 399, `registration data: ${r.text.slice(0, 200)} (${r.days} days)`);
      const after = await page.evaluate(() => ({
        dns: window.__zoneDnsQueries,
        rdap: window.__rdap.calls.slice(),
        focus: document.activeElement === document.querySelector('.hlt-rdap')
      }));
      assertEqual(after.dns, before.dns, 'no DNS query: only RDAP was asked again');
      assertEqual(after.rdap.slice(before.rdap), ['https://data.iana.org/rdap/dns.json', 'https://rdap.example.net/domain/example.com'], 'RDAP requests of the Retry');
      assert(after.focus, 'keyboard focus on the RDAP card');
      const checks = (await page.evaluate(reportInfo)).checks.map((c) => c.id);
      assert(checks.includes('rdap.expiry-ok') && !checks.includes('rdap.error'), `registration checks: ${checks.filter((c) => c.startsWith('rdap'))}`);
      await announced(page, /Registration data loaded/, 'retry announced');
      await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
      const printed = await page.evaluate(() => document.querySelector('.print-head .print-permalink')?.getAttribute('href') || '');
      await page.evaluate(() => window.dispatchEvent(new Event('afterprint')));
      assert(printed.endsWith(`/domainscope/#/health?domain=${MAIL_APEX}&selectors=custom1`), `the summary link keeps the run's selectors: ${printed}`);
      await shotSelector(page, 'health-rdap-desktop-light-en-retried', '.hlt-rdap');
    });

    await step('[dark, TR, 375 px] the failed RDAP card fits and is translated', async () => {
      await page.evaluate(() => { window.__rdap.on = false; });
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await gotoHash(page, `#/health?domain=twosts.${MAIL_APEX}`, 'health');
      await page.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d && !document.querySelector('[data-action="run"]').hidden,
        { args: [`twosts.${MAIL_APEX}`], timeout: 30000, message: 'twosts report' });
      const r = await page.evaluate(rdapInfo);
      assertEqual([r.state, r.retry], ['failed', true], 'failed RDAP card');
      assertEqual(r.title, 'RDAP: ulaşılamadı (çevrimdışı, engellenmiş ya da tarayıcı erişimine kapalı)', 'TR tooltip');
      await assertNoHorizontalScroll(page, 'rdap phone');
      await shotSelector(page, 'health-rdap-mobile-dark-tr-failed', '.hlt-rdap');
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    await step('"Show the fix" of SPF +all: the record with ~all, the other TXT record kept by Route 53, the edit link; nothing sent', async () => {
      await gotoHash(page, `#/health?domain=fix.${MAIL_APEX}`, 'health');
      await page.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d && !document.querySelector('[data-action="run"]').hidden,
        { args: [`fix.${MAIL_APEX}`], timeout: 30000, message: 'fix.example.com report' });
      const fixable = await page.evaluate(() => [...document.querySelectorAll('[data-action="health-fix"]')].map((b) => b.dataset.check));
      assert(fixable.includes('spf.all-pass') && !fixable.includes('spf.present'), `fix buttons: ${fixable}`);
      const queries = await page.evaluate(() => window.__zoneDnsQueries);
      const toggle = '[data-action="health-fix"][data-check="spf.all-pass"]';
      await page.click(toggle);
      await page.waitFor(() => !!document.querySelector('[data-fix-for="spf.all-pass"] .fix-outputs'), { message: 'fix panel', timeout: 10000 });
      const panel = await page.evaluate((sel) => {
        const host = document.querySelector('[data-fix-for="spf.all-pass"]');
        return {
          expanded: document.querySelector(sel).getAttribute('aria-expanded'),
          controls: document.querySelector(sel).getAttribute('aria-controls') === host.id,
          sets: [...host.querySelectorAll('.fix-set')].map((li) => `${li.dataset.action} ${li.dataset.name}: ${[...li.querySelectorAll('.fix-value-text')].map((v) => v.textContent).join(' | ')}`),
          edit: host.querySelector('a[href*="#/change?"]')?.getAttribute('href') || ''
        };
      }, toggle);
      assertEqual([panel.expanded, panel.controls], ['true', true], 'toggle state');
      assertEqual(panel.sets, ['replace fix.example.com: "v=spf1 mx ~all" | "v=spf1 mx +all"'], 'the fix');
      assert(panel.edit.startsWith('#/change?t=record&name=fix.example.com&type=TXT') && panel.edit.includes('zone=fix.example.com'), `edit link: ${panel.edit}`);
      await page.evaluate(() => document.querySelector('[data-fix-for="spf.all-pass"] .tab[data-tab="route53"]').click());
      const r53 = JSON.parse(await page.evaluate(() => document.querySelector('[data-fix-for="spf.all-pass"] .tabpanel[data-tab="route53"] .codeblock-pre').textContent));
      assertEqual(r53.Changes[0].ResourceRecordSet.ResourceRecords.map((r) => r.Value), ['"site-verification=fix123"', '"v=spf1 mx ~all"'], 'the UPSERT keeps the other TXT record');
      assertEqual(await page.evaluate(() => window.__zoneDnsQueries), queries, 'the panel sends nothing');
      await shotSelector(page, 'health-fix-desktop-light-en', '[data-id="spf.all-pass"]');
      await page.click(toggle);
      assert(await page.evaluate(() => document.querySelector('[data-fix-for="spf.all-pass"]').hidden), 'Hide the fix');
    });

    await step('"Show the fix" of an unknown critical CAA tag: only its critical flag goes, the other value stays; nothing sent', async () => {
      const toggle = '[data-action="health-fix"][data-check="caa.critical-unknown"]';
      assert(await page.evaluate((sel) => !!document.querySelector(sel), toggle), 'a fix button on the CAA error');
      const queries = await page.evaluate(() => window.__zoneDnsQueries);
      await page.click(toggle);
      await page.waitFor(() => !!document.querySelector('[data-fix-for="caa.critical-unknown"] .fix-outputs'), { message: 'CAA fix panel', timeout: 10000 });
      const panel = await page.evaluate(() => {
        const host = document.querySelector('[data-fix-for="caa.critical-unknown"]');
        return {
          sets: [...host.querySelectorAll('.fix-set')].map((li) => `${li.dataset.action} ${li.dataset.name}: ${[...li.querySelectorAll('.fix-value-text')].map((v) => v.textContent).join(' | ')}`),
          advice: host.querySelector('.fix-advice')?.textContent || '',
          edit: host.querySelector('a[href*="#/change?"]')?.getAttribute('href') || ''
        };
      });
      assertEqual(panel.sets, ['replace fix.example.com: 0 tbs "unknown" | 0 issue "letsencrypt.org" | 128 tbs "unknown"'], 'the fix');
      assert(/The critical flag goes from tbs/.test(panel.advice), `advice: ${panel.advice}`);
      assert(panel.edit.startsWith('#/change?t=record&name=fix.example.com&type=CAA'), `edit link: ${panel.edit}`);
      assertEqual(await page.evaluate(() => window.__zoneDnsQueries), queries, 'the panel sends nothing');
      await page.click(toggle);
    });

    group('Offline: the Web card and the HTTP security grade (fake Mozilla Observatory, emulated example.com)');

    const obsCalls = () => page.evaluate(() => window.__obs.calls.map((c) => `${c.method} ${c.url}`));
    const webInfo = () => page.evaluate(() => {
      const card = document.querySelector('.hv2-web');
      const obs = document.querySelector('.hv2-obs');
      const problems = document.querySelector('.hv2-problems');
      return {
        webText: card ? card.textContent.replace(/\s+/g, ' ') : null,
        hsts: card?.querySelector('.hv2-hsts-link')?.getAttribute('href') || '',
        obsState: obs?.dataset.obs || null,
        obsWhat: obs?.querySelector('.hv2-obs-what')?.textContent || '',
        button: obs?.querySelector('[data-action="observatory-check"]')?.textContent.trim() || null,
        grade: obs?.querySelector('.hv2-obs-result')?.dataset.grade || null,
        result: obs?.querySelector('.hv2-obs-result')?.textContent.replace(/\s+/g, ' ').trim() || '',
        report: obs?.querySelector('.hv2-obs-report')?.getAttribute('href') || '',
        status: obs?.querySelector('.hv2-obs-status')?.textContent.replace(/\s+/g, ' ').trim() || '',
        reason: obs?.querySelector('.hv2-obs-status')?.dataset.reason || null,
        webChip: document.querySelector('.hlt-metrics [data-metric="web"] .metric-value')?.textContent || null,
        wwwMissing: !!problems?.querySelector('.hv2-problem[data-id="www.missing"]')
      };
    });

    await step('the Web card: HTTPS record, www against the bare domain, the HSTS link; the metric strip scores the Web category; nothing sent to the Observatory', async () => {
      await gotoHash(page, `#/health?domain=${MAIL_APEX}`, 'health');
      await page.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d && !document.querySelector('[data-action="run"]').hidden,
        { args: [MAIL_APEX], timeout: 30000, message: 'example.com report' });
      await page.waitFor(() => document.querySelector('.hv2-web') && document.querySelector('.hv2-obs'), { timeout: 10000, message: 'the Web card (lazy ui/health-v2.js)' });
      const w = await webInfo();
      assert(/192\.0\.2\.80/.test(w.webText), `the bare domain's address: ${w.webText}`);
      assert(w.webText.includes('www.example.com') && w.webText.includes('No address'), `www row with no address: ${w.webText}`);
      assert(/None \(optional\)/.test(w.webText), `the HTTPS record is none/optional: ${w.webText}`);
      assertEqual(w.hsts, 'https://hstspreload.org/?domain=example.com', 'the HSTS preload link opens the status page');
      assert(w.wwwMissing, 'the www.missing warning is in the problems-first panel');
      assertEqual(w.webChip, '85', 'the Web category scores 85 (one warning) in the metric strip under the header');
      assertEqual(w.obsState, 'idle', 'the Observatory has not been sent to yet');
      assert(/Content-Security-Policy/.test(w.obsWhat), `the "what it measures" text: ${w.obsWhat.slice(0, 80)}`);
      assertEqual(w.button, 'Check HTTP security', 'the check button');
      assertEqual(await obsCalls(), [], 'nothing sent to the Observatory on arrival');
      await assertNoHorizontalScroll(page, 'web card');
    });

    await step('the Observatory grade: one POST on the click, the grade with its failing-test count, the MDN link; nothing leaves the page', async () => {
      await page.click('.hv2-obs [data-action="observatory-check"]');
      await page.waitFor(() => document.querySelector('.hv2-obs')?.dataset.obs === 'done', { timeout: 15000, message: 'the grade came back' });
      const w = await webInfo();
      assertEqual(w.grade, 'B+', 'the grade badge');
      assert(/75\/100/.test(w.result) && /3 of 12 tests failed/.test(w.result), `the score and failing count: ${w.result}`);
      assertEqual(w.report, 'https://developer.mozilla.org/en-US/observatory/analyze?host=example.com', 'the MDN report link');
      assertEqual(w.button, 'Check again', 'the button becomes Check again');
      assertEqual(await obsCalls(), ['POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=example.com'], 'exactly one POST to the Observatory');
      assertEqual(netHits, [], 'no request reached the network');
      if (SHOTS_ON) await page.screenshot(path.join(SHOTS, 'health-observatory-desktop-light-en.png'));
    });

    await step('a failed Observatory check is a status with Retry, never a grade; Retry asks again and the grade returns', async () => {
      await page.evaluate(() => { window.__obs.next.push('rate'); });
      await page.click('.hv2-obs [data-action="observatory-check"]');
      await page.waitFor(() => document.querySelector('.hv2-obs')?.dataset.obs === 'failed', { timeout: 15000, message: 'the failure status' });
      const w = await webInfo();
      assertEqual([w.obsState, w.grade], ['failed', null], 'a status, never a grade');
      assert(/^rate-limit/.test(w.reason) && /rate limited/.test(w.status), `the reason is written out: ${w.reason} / ${w.status}`);
      await page.evaluate(() => { window.__obs.next.push('ok'); });
      await page.click('.hv2-obs [data-action="observatory-check"]');
      await page.waitFor(() => document.querySelector('.hv2-obs')?.dataset.obs === 'done', { timeout: 15000, message: 'the grade after Retry' });
      assertEqual((await webInfo()).grade, 'B+', 'the grade after Retry');
      assertEqual(netHits, [], 'still nothing reached the network');
    });

    await step('nothing left the page: no real Globalping request; i18n complete; no console errors', async () => {
      const blocked = await page.evaluate(() => window.__zoneBlocked.slice());
      assertEqual(netHits, [], 'https requests that reached the network');
      assert(!blocked.some((u) => u.includes('globalping')), `Globalping never reached the zone guard: ${blocked}`);
      const calls = await gpCalls();
      assertEqual(posts(calls).length, 12, 'twelve fake probes in total');
      await checkI18n(page);
      await assertClean(page, 'mta-sts offline');
    });
  } finally {
    await page.close();
  }
}

/* ------------------------------------------------------------------------ */
/* Offline: Delegation (fake DoH + fake Globalping DNS)                     */
/* ------------------------------------------------------------------------ */

const DLG_ZONE_NAME = 'example.org';
const DLG_SOA = { mname: 'ns1.example.org', rname: 'hostmaster.example.org', serial: 2026100801, refresh: 3600, retry: 900, expire: 1209600, minimum: 300 };
/** example.org as the resolvers see it: three name servers (one inside the zone), and the parent's server. */
const DLG_DNS = {
  'example.org': { SOA: [DLG_SOA], NS: ['ns1.example.org', 'ns2.example.net', 'ns1.digitalocean.com'], A: ['192.0.2.80'] },
  'ns1.example.org': { A: ['192.0.2.53'], AAAA: ['2001:db8::53'] },
  'ns2.example.net': { A: ['198.51.100.53'] },
  'ns1.digitalocean.com': { A: ['203.0.113.10'] },
  org: { NS: ['a0.org-servers.example.net'] }
};
const DLG_NS = ['ns1.example.org', 'ns2.example.net', 'ns1.digitalocean.com'];
const dlgSoa = (serial) => [['example.org', 'SOA', `ns1.example.org. hostmaster.example.org. ${serial} 3600 900 1209600 300`]];
const dlgNs = DLG_NS.map((n) => ['example.org', 'NS', `${n}.`]);
/**
 * What each server answers (`<resolver>|<name>|<type>`): ns2 serves an older serial and answers an
 * unrelated name (an open resolver), the DigitalOcean server refuses the zone (a lame delegation
 * at a provider of the Sitting Ducks list) and the parent hands out a stale glue address.
 */
const DLG_ROUTES = {
  'ns1.example.org|example.org|SOA': { answer: dlgSoa(2026100801), nsid: 'ns1-ams' },
  'ns1.example.org|example.org|NS': { answer: dlgNs },
  'ns1.example.org|example.net|A': { rcode: 'REFUSED', flags: 'qr rd' },
  'ns2.example.net|example.org|SOA': { answer: dlgSoa(2026100700) },
  'ns2.example.net|example.org|NS': { answer: dlgNs },
  'ns2.example.net|example.net|A': { flags: 'qr rd ra', answer: [['example.net', 'A', '192.0.2.80']] },
  'ns1.digitalocean.com|example.org|SOA': { rcode: 'REFUSED', flags: 'qr rd' },
  'ns1.digitalocean.com|example.net|A': { rcode: 'REFUSED', flags: 'qr rd' },
  'a0.org-servers.example.net|example.org|NS': { flags: 'qr rd', authority: dlgNs, additional: [['ns1.example.org', 'A', '192.0.2.99']] }
};

/**
 * Fake DoH for the delegation group: `?dns=` queries answered from DLG_DNS (a name without the
 * type is NOERROR / no data, an unknown name NXDOMAIN with the zone's SOA); every question is
 * kept in window.__dlgDns.
 */
const delegationDnsScript = (table, apex, soa) => `(() => {
  const TABLE = ${JSON.stringify(table)};
  const APEX = ${JSON.stringify(apex)};
  const SOA = ${JSON.stringify(soa)};
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.__dlgDns = [];
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__dlgDns.push(name + '|' + q.type);
    const node = TABLE[name];
    const exists = !!node || Object.keys(TABLE).some((k) => k.endsWith('.' + name));
    const answers = node && node[q.type] ? node[q.type].map((data) => ({ name, type: q.type, ttl: 300, data })) : [];
    const authorities = answers.length ? [] : [{ name: APEX, type: 'SOA', ttl: 300, data: SOA }];
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: exists ? 'NOERROR' : 'NXDOMAIN',
      questions: [{ name: q.name, type: q.type }], answers, authorities, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/**
 * Fake Globalping v1 API for DNS measurements (the outermost window.fetch wrapper): /limits
 * (window.__gp.limitsRemaining), POST /measurements (202 + quota headers) and GET
 * /measurements/:id, finished at once with the dig text of the route the body names
 * (`<resolver>|<target>|<type>`, DLG_ROUTES; an unknown one times out). Calls in window.__gp.calls.
 */
const fakeDnsGlobalpingScript = (routes, probe) => `(() => {
  const API = 'https://api.globalping.io/v1';
  const ROUTES = ${JSON.stringify(routes)};
  const PROBE = ${JSON.stringify(probe)};
  const gp = window.__gp = { calls: [], n: 0, limitsRemaining: 250, measurements: {} };
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers } });
  const line = (r) => r[0] + '.\\t\\t3600\\tIN\\t' + r[1] + '\\t' + r[2];
  const hex = (s) => [...s].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
  const dig = (target, type, resolver, spec) => {
    const flags = spec.flags || 'qr aa rd';
    const out = ['', '; <<>> DiG 9.18.49 <<>> -t ' + type + ' ' + target + ' @' + resolver + ' -p 53 -4 +nsid', ';; global options: +cmd', ';; Got answer:',
      ';; ->>HEADER<<- opcode: QUERY, status: ' + (spec.rcode || 'NOERROR') + ', id: 1',
      ';; flags: ' + flags + '; QUERY: 1, ANSWER: ' + (spec.answer || []).length + ', AUTHORITY: ' + (spec.authority || []).length + ', ADDITIONAL: 1', '',
      ';; OPT PSEUDOSECTION:', '; EDNS: version: 0, flags:; udp: 1232'];
    if (spec.nsid) out.push('; NSID: ' + hex(spec.nsid) + ' ("' + spec.nsid + '")');
    out.push(';; QUESTION SECTION:', ';' + target + '.\\t\\t\\tIN\\t' + type, '');
    for (const [title, list] of [['ANSWER', spec.answer], ['AUTHORITY', spec.authority], ['ADDITIONAL', spec.additional]]) {
      if (list && list.length) out.push(';; ' + title + ' SECTION:', ...list.map(line), '');
    }
    out.push(';; Query time: 9 msec', ';; SERVER: 192.0.2.53#53(' + resolver + ') (UDP)', '');
    return out.join('\\n');
  };
  const inner = window.fetch;
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!url.startsWith('https://api.globalping.io/')) return inner(input, init);
    const method = String(init.method || 'GET').toUpperCase();
    let body = null;
    try { body = typeof init.body === 'string' ? JSON.parse(init.body) : null; } catch { body = null; }
    const p = url.startsWith(API) ? url.slice(API.length) : url;
    gp.calls.push({ method, path: p, body });
    if (init.signal && init.signal.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
    if (p === '/limits' && method === 'GET') {
      return json(200, { rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: gp.limitsRemaining, reset: 1800 } } } });
    }
    if (p === '/measurements' && method === 'POST') {
      gp.limitsRemaining = Math.max(0, gp.limitsRemaining - 1);
      gp.n += 1;
      const id = 'fakeDelegation' + String(gp.n).padStart(6, '0');
      gp.measurements[id] = body;
      return json(202, { id, probesCount: 1 }, {
        'x-ratelimit-limit': '250', 'x-ratelimit-consumed': String(250 - gp.limitsRemaining), 'x-ratelimit-remaining': String(gp.limitsRemaining),
        'x-ratelimit-reset': '1800', 'x-request-cost': '1'
      });
    }
    const m = /^\\/measurements\\/([A-Za-z0-9]+)$/.exec(p);
    if (m && method === 'GET') {
      const b = gp.measurements[m[1]];
      if (!b) return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
      const resolver = b.measurementOptions.resolver;
      const type = b.measurementOptions.query.type;
      const spec = ROUTES[resolver + '|' + b.target + '|' + type];
      const result = spec
        ? { status: 'finished', rawOutput: dig(b.target, type, resolver, spec), statusCodeName: spec.rcode || 'NOERROR', statusCode: spec.rcode === 'REFUSED' ? 5 : 0,
          answers: (spec.answer || []).map((r) => ({ name: r[0] + '.', type: r[1], ttl: 3600, class: 'IN', value: r[2] })), timings: { total: 9 }, resolver }
        : { status: 'failed', rawOutput: ';; communications error to 192.0.2.53#53: timed out\\n;; no servers could be reached', resolver };
      return json(200, { id: m[1], type: 'dns', status: 'finished', target: b.target, probesCount: 1, results: [{ probe: PROBE, result }] });
    }
    return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
  };
})();`;

/** What the Delegation card shows. */
function delegationInfo() {
  const card = document.querySelector('[data-delegation="card"]');
  if (!card) return null;
  const panel = card.querySelector('[data-delegation="panel"]');
  return {
    state: panel ? panel.dataset.state : 'hook',
    button: (card.querySelector('[data-action="dlg-open"], [data-action="dlg-run"]')?.textContent || '').trim(),
    verdict: card.querySelector('[data-dlg-verdict]')?.dataset.dlgVerdict ?? null,
    findings: [...card.querySelectorAll('[data-finding]')].map((li) => `${li.dataset.finding}:${li.dataset.severity}`),
    servers: [...card.querySelectorAll('tr[data-ns]')].map((tr) => `${tr.dataset.ns}=${tr.dataset.state}`),
    glue: [...card.querySelectorAll('tr[data-glue]')].map((tr) => `${tr.dataset.host}=${tr.dataset.glue}`),
    parent: card.querySelector('[data-parent]')?.dataset.parent ?? null,
    refs: card.querySelectorAll('[data-finding="sitting-ducks"] .dlg-refs a').length,
    links: [...card.querySelectorAll('tr[data-ns] a[href]')].map((a) => a.getAttribute('href')),
    text: card.textContent.replace(/\s+/g, ' ')
  };
}

async function delegationGroup(browser, server) {
  group('Offline: Delegation (emulated example.org, fake Globalping DNS)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  const netHits = await networkGuard(page);
  const probe = { continent: 'EU', region: 'Western Europe', country: 'NL', city: 'Amsterdam', asn: 64500, network: 'Example Net', tags: ['datacenter-network'] };
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: delegationDnsScript(DLG_DNS, DLG_ZONE_NAME, DLG_SOA) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeDnsGlobalpingScript(DLG_ROUTES, probe) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: RDAP_FAKE_SCRIPT });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  const gpCalls = () => page.evaluate(() => window.__gp.calls.map((c) => ({ method: c.method, path: c.path, body: c.body })));
  const posts = async () => (await gpCalls()).filter((c) => c.method === 'POST')
    .map((c) => `${c.body.measurementOptions.resolver}|${c.body.target}|${c.body.measurementOptions.query.type}`).sort();
  const card = () => page.evaluate(delegationInfo);
  const panelState = (want, message) => page.waitFor((w) => document.querySelector('[data-delegation="panel"]')?.dataset.state === w,
    { args: [want], timeout: 20000, message });
  try {
    await step('the report has an idle Delegation card with its cost; nothing goes to Globalping', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await gotoHash(page, `#/health?domain=${DLG_ZONE_NAME}`, 'health');
      await page.waitFor(DONE, { timeout: 30000, message: 'health report' });
      const c = await card();
      assert(c, 'Delegation card');
      assertEqual([c.state, c.button], ['hook', 'Check the delegation'], 'idle card');
      assert(c.text.includes('Asks every name server of example.org directly') && c.text.includes('About 10 Globalping probes.'), `intro: ${c.text.slice(0, 200)}`);
      assertEqual(await gpCalls(), [], 'no Globalping call, not even /limits');
      await assertNoHorizontalScroll(page, 'delegation idle');
    });

    await step('the click reads the delegation from DoH, then the consent dialog names the zone, the servers asked and the cost; Cancel sends nothing', async () => {
      await page.click('[data-action="dlg-open"]');
      await page.waitFor((d) => document.querySelector(d), { args: [GP_DIALOG], timeout: 20000, message: 'consent dialog' });
      const dlg = await page.evaluate((d) => {
        const el = document.querySelector(d);
        return { privacy: el.querySelector('[data-gp="confirm-privacy"]')?.textContent || '', probes: el.querySelector('[data-gp="confirm-cost"]')?.dataset.probes };
      }, GP_DIALOG);
      assert(dlg.privacy.includes('example.org') && dlg.privacy.includes('example.net') && dlg.privacy.includes('a0.org-servers.example.net'), `privacy: ${dlg.privacy}`);
      assertEqual(dlg.probes, '10', 'cost: SOA, NS and the unrelated name at three servers, and the parent');
      assertEqual((await gpCalls()).map((c) => `${c.method} ${c.path}`), ['GET /limits'], 'only the free quota read before consent');
      const dohNames = await page.evaluate(() => window.__dlgDns.slice());
      for (const q of ['example.org|NS', 'ns1.example.org|A', 'ns1.example.org|AAAA', 'org|NS']) assert(dohNames.includes(q), `DoH asked ${q}`);
      assert(!dohNames.includes('example.net|A'), 'the unrelated name never goes to DoH');
      await page.click(`${GP_DIALOG} .modal-foot .btn:not(.btn-primary)`);
      await page.waitFor((d) => !document.querySelector(d), { args: [GP_DIALOG], message: 'dialog closed' });
      await panelState('idle', 'panel back to idle');
      assertEqual(await posts(), [], 'Cancel sends nothing');
    });

    await step('Send: exactly the planned measurements; lame, Sitting Ducks, serial drift, stale glue and an open resolver', async () => {
      await page.click('[data-action="dlg-run"]');
      await page.waitFor((d) => document.querySelector(d), { args: [GP_DIALOG], timeout: 20000, message: 'consent dialog (Cancel granted nothing)' });
      await page.click(`${GP_DIALOG} .modal-foot .btn-primary`);
      await panelState('done', 'delegation result');
      assertEqual(await posts(), [
        'a0.org-servers.example.net|example.org|NS',
        'ns1.digitalocean.com|example.net|A', 'ns1.digitalocean.com|example.org|SOA',
        'ns1.example.org|example.net|A', 'ns1.example.org|example.org|NS', 'ns1.example.org|example.org|SOA',
        'ns2.example.net|example.net|A', 'ns2.example.net|example.org|NS', 'ns2.example.net|example.org|SOA'
      ], 'nine measurements: no NS question to the server that refused the zone');
      const c = await card();
      assertEqual(c.verdict, 'error', 'verdict');
      assertEqual(c.findings, ['lame:error', 'sitting-ducks:error', 'serial-drift:warn', 'glue-differs:warn', 'open-recursion:warn'], 'findings, worst first');
      assertEqual(c.servers, ['ns1.digitalocean.com=refused', 'ns1.example.org=ok', 'ns2.example.net=ok'], 'servers');
      assertEqual(c.glue, ['ns1.example.org=differs'], 'stale glue for the server inside the zone');
      assertEqual(c.parent, 'ok', 'the parent delegates');
      assertEqual(c.refs, 3, 'the Sitting Ducks references');
      assert(c.links.length === 8 && c.links.every((u) => u.startsWith('https://api.globalping.io/v1/measurements/fakeDelegation')), `measurement links: ${c.links}`);
      assert(c.text.includes('SOA serials differ: 2026100700, 2026100801') && c.text.includes('NSID ns1-ams') && c.text.includes('DigitalOcean'), `text: ${c.text.slice(0, 400)}`);
      await assertNoHorizontalScroll(page, 'delegation result');
      await shotSelector(page, 'health-delegation-desktop-light-en', '.hlt-dlg');
    });

    await step('a language switch keeps the result in Turkish, without a new probe', async () => {
      await setLangUi(page, 'tr');
      await page.waitFor(() => document.querySelector('[data-delegation="panel"]')?.dataset.state === 'done', { timeout: 20000, message: 'result after the re-mount' });
      const c = await card();
      assert(c.text.includes('Sitting Ducks riski') && c.text.includes('Delegasyonda 2 sorun var.'), `Turkish: ${c.text.slice(0, 300)}`);
      assertEqual((await posts()).length, 9, 'no new measurement');
      await setLangUi(page, 'en');
      await page.waitFor(() => document.querySelector('[data-delegation="panel"]')?.dataset.state === 'done', { timeout: 20000, message: 'result back in English' });
    });

    for (const scheme of ['light', 'dark']) {
      await step(`[375 px, ${scheme}] the Delegation card fits a phone`, async () => {
        await page.setViewport({ width: 375, height: 812, mobile: true });
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await assertNoHorizontalScroll(page, `delegation 375 ${scheme}`);
        await shotSelector(page, `health-delegation-phone-${scheme}-en`, '.hlt-dlg');
        await page.setViewport({ width: 1440, height: 900 });
        await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      });
    }

    await step('a quota that cannot cover the check: nothing is sent, the card says when it comes back', async () => {
      await page.evaluate(() => { window.__gp.limitsRemaining = 3; });
      await page.click('[data-action="dlg-run"]');
      await panelState('quota', 'quota state');
      const c = await card();
      assert(/quota cannot cover the check; it resets/.test(c.text), `quota text: ${c.text.slice(0, 300)}`);
      assertEqual((await posts()).length, 9, 'no measurement over the quota');
    });

    await step('nothing left the page; i18n complete; no console errors', async () => {
      assertEqual(netHits, [], 'https requests that reached the network');
      await checkI18n(page);
      await assertClean(page, 'delegation offline');
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
    // The restored report is on screen and the box still asks for it: Run reads "Run again".
    await page.waitFor(() => document.querySelector('[data-action="run"] .btn-label')?.textContent === 'Yeniden çalıştır', { message: 'TR form' });
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
    assertEqual(HEALTH_GROUPS, ['dns', 'email', 'security', 'registration', 'web'], 'group order');
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
    await delegationGroup(browser, server);
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
