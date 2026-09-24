#!/usr/bin/env node
/**
 * LIVE: the passive sources (assets/js/lib/sources.js) inside a REAL headless
 * Chrome/Edge — real fetch, real CORS, the production CSP — instead of Node
 * mocks. Not run by `npm test` (network + browser).
 *
 *   node tests/live/browser-sources.mjs                        # targets.local.json, else github.com
 *   node tests/live/browser-sources.mjs example.com --no-all   # skip fetchAllSources (Cert Spotter quota)
 *   node tests/live/browser-sources.mjs --no-live              # only the simulated failure paths
 *
 * Two tabs on the locally served site (tests/e2e/serve.mjs):
 *   live tab  index.html with its real CSP. For each domain: fetchSource('crtsh'),
 *             fetchSource('thc'); for the first domain fetchAllSources with
 *             hackertarget/otx disabled (crt.sh, Cert Spotter, Anubis, ip.thc.org)
 *             + the sourceHealthSummary() text. Every request is also recorded
 *             via CDP Network events (status, ACAO, CORS error, preflights).
 *   sim tab   same page with CSP bypassed (CDP Page.setBypassCSP) so it may call a
 *             local fixture server on ANOTHER origin — CORS is still enforced by
 *             Chrome. The fixture plays crt.sh failing the way it really does:
 *             502 pages without Access-Control-Allow-Origin (→ TypeError in the
 *             page), a 2×502-then-200 flap, 429 with CORS (Retry-After not
 *             exposed), a hanging server (abort + timeout), plus a Cert Spotter
 *             stand-in for the fallback and a 3-page ip.thc.org for page spacing.
 *             These are asserted: exit code 1 when a check fails.
 *
 * Options:
 *   --no-live              skip every real network call
 *   --no-sim               skip the simulated failure paths
 *   --no-all               skip the live fetchAllSources run (saves Cert Spotter's ~10/h quota)
 *   --thc-paging DOMAIN    also page a big domain on the real ip.thc.org (≤10 requests, 2 s apart)
 *   --real-backoff         simulate with crt.sh's production backoff (≈4+8+16+32 s) instead of a 150 ms base
 *   --headful              show the browser window
 *   --json FILE            write everything recorded as JSON (it names the scanned domains, so inside
 *                          the repository only a gitignored path such as tests/live/private/sources.json
 *                          is accepted; see targets.mjs reportPath)
 */
import http from 'node:http';
import { launchBrowser } from '../e2e/cdp.mjs';
import { startServer } from '../e2e/serve.mjs';
import { pickDomains, reportPathOrExit, writeReport } from './targets.mjs';

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const option = (name, fallback = null) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
};
const VALUE_OPTIONS = new Set(['--json', '--thc-paging']);
const positional = argv.filter((a, i) => !a.startsWith('--') && !VALUE_OPTIONS.has(argv[i - 1]));
const DOMAINS = pickDomains(positional, ['github.com']);
const JSON_OUT = reportPathOrExit(option('--json'));
const LIVE = !flag('--no-live');
const SIM = !flag('--no-sim');
const RETRY_BASE_MS = flag('--real-backoff') ? undefined : 150;
const SIM_DOMAIN = 'example.com.tr';

const t0 = Date.now();
const secs = (ms) => `${(ms / 1000).toFixed(2)}s`;
const pad = (s, n) => String(s).padEnd(n).slice(0, n);
const log = (...a) => console.log(...a);
const report = { startedAt: new Date().toISOString(), browser: null, live: {}, sim: {}, checks: [] };

/** Record a check (sim checks decide the exit code). */
function check(name, pass, detail = '') {
  report.checks.push({ name, pass: !!pass, detail });
  log(`    ${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? `  — ${detail}` : ''}`);
  return !!pass;
}

/* ------------------------------------------------------------------------ */
/* Fixture server: a cross-origin stand-in for crt.sh / Cert Spotter / THC   */
/* ------------------------------------------------------------------------ */

function startFixture() {
  const hits = [];
  const counters = new Map();
  const CORS = { 'Access-Control-Allow-Origin': '*' };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://fixture');
    const hit = {
      at: Date.now(), method: req.method, path: url.pathname, search: url.search,
      origin: req.headers.origin || null, contentType: req.headers['content-type'] || null, closedAt: null
    };
    hits.push(hit);
    const [, area, scenario] = url.pathname.split('/');
    const n = (counters.get(url.pathname) || 0) + 1;
    counters.set(url.pathname, n);
    if (req.method === 'OPTIONS') { // a CORS preflight — must never happen for these requests
      res.writeHead(204, { ...CORS, 'Access-Control-Allow-Methods': '*', 'Access-Control-Allow-Headers': '*' });
      res.end();
      return;
    }
    if (area === 'crt') {
      const q = url.searchParams.get('q') || '';
      const domain = q.replace(/^%\./, '');
      const rows = JSON.stringify([{
        issuer_ca_id: 7, issuer_name: 'C=TR, O=Sim CA, CN=Sim CA R1', common_name: `www.${domain}`,
        name_value: `www.${domain}\napi.${domain}\n*.dev.${domain}`, id: 1001, entry_timestamp: '2026-09-01T10:00:00.000',
        not_before: '2026-09-01T10:00:00', not_after: '2026-12-01T10:00:00', serial_number: '0a1b2c', result_count: 3
      }]);
      const badGateway = () => { // crt.sh's proxy: HTML error page, no CORS header
        res.writeHead(502, { 'Content-Type': 'text/html' });
        res.end('<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center><hr><center>nginx</center></body></html>');
      };
      if (scenario === 'down') return badGateway();
      if (scenario === 'flaky') {
        if (n <= 2) return badGateway();
        res.writeHead(200, { ...CORS, 'Content-Type': 'application/json' });
        return res.end(rows);
      }
      if (scenario === 'ratelimit') {
        res.writeHead(429, { ...CORS, 'Content-Type': 'text/plain', 'Retry-After': '1' });
        return res.end('Too Many Requests');
      }
      if (scenario === 'hang') {
        req.socket.on('close', () => { hit.closedAt = Date.now(); });
        return undefined; // never answers
      }
    }
    if (area === 'certspotter') {
      const domain = url.searchParams.get('domain') || '';
      const body = url.searchParams.get('after') ? [] : [{
        id: '555', tbs_sha256: 'ab'.repeat(32), cert_sha256: 'cd'.repeat(32), dns_names: [`${domain}`, `mail.${domain}`],
        pubkey_sha256: 'ef'.repeat(32), issuer: { friendly_name: 'Sim CA', name: 'C=TR, O=Sim CA, CN=Sim CA R1' },
        not_before: '2026-09-01T10:00:00Z', not_after: '2026-12-01T10:00:00Z', revoked: false
      }];
      res.writeHead(200, { ...CORS, 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(body));
    }
    if (area === 'thc' && req.method === 'POST') {
      let raw = '';
      req.on('data', (c) => { raw += c; });
      req.on('end', () => {
        let payload = {};
        try { payload = JSON.parse(raw); } catch { /* keep {} */ }
        hit.body = payload;
        const page = payload.page_state ? Number(String(payload.page_state).replace('p', '')) : 1;
        const d = payload.domain || 'x';
        const next = page < 3 ? `p${page + 1}` : '';
        res.writeHead(200, { ...CORS, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          comment: 'sim', processed_domain: d, matching_records: 250,
          domains: Array.from({ length: 100 }, (_, i) => ({ domain: `h${(page - 1) * 100 + i}.${d}`, last_seen_on: '2026-09-20' })),
          next_page_state: next
        }));
      });
      return undefined;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('not found');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const origin = `http://127.0.0.1:${server.address().port}`;
      resolve({
        origin,
        hits,
        hitsFor: (prefix) => hits.filter((h) => h.path.startsWith(prefix)),
        close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); })
      });
    });
  });
}

/* ------------------------------------------------------------------------ */
/* In-page helpers (serialized into the tab — no closures over Node scope)   */
/* ------------------------------------------------------------------------ */

async function installHelpers() {
  const m = await import('/assets/js/lib/sources.js');
  const plain = (v) => JSON.parse(JSON.stringify(v ?? null, (k, x) => {
    if (x instanceof Map) return Object.fromEntries([...x].map(([a, b]) => [a, b instanceof Set ? [...b] : b]));
    if (x instanceof Set) return [...x];
    return x;
  }));
  const slim = (r) => ({
    source: r.source, domain: r.domain, ok: r.ok, partial: r.partial, errorKind: r.errorKind, error: r.error,
    attempts: r.attempts, elapsedMs: r.elapsedMs, rows: r.rows, names: r.names, wildcardBases: r.wildcardBases,
    certs: r.certs.length, ipHints: r.ipHints.length, queryForm: r.queryForm, available: r.available,
    truncated: r.truncated, quota: plain(r.quota), lastSeen: r.lastSeen
  });
  window.__bs = {
    async run(kind, domain, o = {}) {
      const t0 = performance.now();
      const at = () => Math.round(performance.now() - t0);
      const events = [];
      const requests = [];
      const fetchErrors = [];
      const rewrite = o.rewrite || [];
      const fetchImpl = (url, init) => {
        let u = String(url);
        for (const [from, to] of rewrite) {
          if (u.startsWith(from)) { u = to + u.slice(from.length); break; }
        }
        requests.push({ at: at(), url: u, method: (init && init.method) || 'GET' });
        return fetch(u, init).catch((e) => {
          fetchErrors.push({ at: at(), url: u, name: e && e.name, message: e && e.message });
          throw e;
        });
      };
      const ctl = new AbortController();
      let abortedAt = null;
      const abort = () => {
        if (abortedAt === null) { abortedAt = at(); ctl.abort(); }
      };
      if (o.abortAfterMs) setTimeout(abort, o.abortAfterMs);
      const onEvent = (e) => {
        events.push({ ...e, at: at() });
        if (o.abortOnRetry && e.type === 'retry') setTimeout(abort, 50);
      };
      const common = { fetchImpl, signal: ctl.signal, onEvent };
      if (o.retryDelayMs !== undefined && o.retryDelayMs !== null) common.retryDelayMs = o.retryDelayMs;
      if (o.timeoutMs) common.timeoutMs = o.timeoutMs;
      if (o.includeExpired) common.includeExpired = true;
      try {
        if (kind === 'all') {
          const out = await m.fetchAllSources(domain, { ...common, sources: o.sources });
          return {
            elapsed: at(), events, requests, fetchErrors, results: out.results.map(slim),
            names: [...out.names.keys()], wildcardBases: out.wildcardBases, health: plain(out.health)
          };
        }
        const r = await m.fetchSource(kind, domain, common);
        return { elapsed: at(), events, requests, fetchErrors, result: slim(r), health: plain(m.sourceHealthSummary([r])) };
      } catch (e) {
        return { elapsed: at(), events, requests, fetchErrors, rejected: { name: e && e.name, message: e && e.message }, abortedAt };
      }
    }
  };
  return m.SOURCES.map((s) => s.id);
}

/** Record CDP Network events of a tab (status, ACAO, CORS errors, preflights). */
function recordNetwork(page) {
  const byId = new Map();
  const list = [];
  const on = (m, fn) => page.conn.on(m, fn, page.sessionId);
  on('Network.requestWillBeSent', (p) => {
    const e = {
      id: p.requestId, url: p.request.url, method: p.request.method, type: p.type || null,
      initiator: p.initiator?.type || null, ts: p.timestamp, wall: p.wallTime, status: null, acao: null, failed: null, cors: null
    };
    byId.set(`${p.requestId}|${p.request.method}`, e);
    byId.set(p.requestId, e);
    list.push(e);
  });
  on('Network.responseReceived', (p) => {
    const e = byId.get(p.requestId);
    if (!e) return;
    e.status = p.response.status;
    const h = Object.fromEntries(Object.entries(p.response.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    e.acao = h['access-control-allow-origin'] ?? null;
  });
  // Raw status / headers even when CORS hides the response from the page.
  on('Network.responseReceivedExtraInfo', (p) => {
    const e = byId.get(p.requestId);
    if (!e) return;
    const h = Object.fromEntries(Object.entries(p.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    e.rawStatus = p.statusCode ?? null;
    e.rawAcao = h['access-control-allow-origin'] ?? null;
    e.rawType = h['content-type'] ?? null;
    e.rawServer = h.server ?? null;
  });
  on('Network.loadingFailed', (p) => {
    const e = byId.get(p.requestId);
    if (!e) return;
    e.failed = p.errorText || 'failed';
    e.cors = p.corsErrorStatus?.corsError || null;
  });
  return {
    list,
    /** Requests sent at/after an epoch time in seconds (CDP wallTime). */
    since: (wall) => list.filter((e) => e.wall >= wall),
    preflights: (host) => list.filter((e) => e.url.includes(host) && (e.method === 'OPTIONS' || /preflight/i.test(`${e.type} ${e.initiator}`)))
  };
}

const nowTs = (page) => page.evaluate(() => performance.timeOrigin + performance.now()).then((ms) => ms / 1000);

function printRun(label, out) {
  const r = out.result;
  if (out.rejected) {
    log(`  ${pad(label, 34)} REJECTED ${out.rejected.name}: ${out.rejected.message} after ${secs(out.elapsed)}`);
    return;
  }
  const status = r.ok ? (r.partial ? 'PARTIAL' : 'ok') : `FAIL:${r.errorKind}`;
  log(`  ${pad(label, 34)} ${pad(status, 16)} names=${pad(r.names.length, 4)} certs=${pad(r.certs, 3)} req=${pad(r.attempts, 2)} `
    + `${secs(r.elapsedMs)}${r.queryForm ? ` form=${r.queryForm}` : ''}${r.available !== null ? ` available=${r.available}` : ''}${r.truncated ? ' TRUNCATED' : ''}`);
  if (r.names.length) log(`  ${' '.repeat(34)} ${r.names.slice(0, 25).join(' ')}${r.names.length > 25 ? ` … (+${r.names.length - 25})` : ''}`);
  if (r.error) log(`  ${' '.repeat(34)} error: ${r.error}`);
  for (const e of out.events) {
    log(`  ${' '.repeat(34)} ${secs(e.at)} ${e.type}${e.attempt ? ` → attempt ${e.attempt}/${e.maxAttempts}` : ''}`
      + `${e.page ? ` → page ${e.page}/${e.maxPages}` : ''}${e.form ? ` (${e.form})` : ''} after ${e.delayMs} ms wait${e.reason ? `, reason: ${e.reason}` : ''}`);
  }
  for (const f of out.fetchErrors) log(`  ${' '.repeat(34)} ${secs(f.at)} page saw ${f.name}: ${f.message}`);
}

function printHealth(health) {
  log('  sourceHealthSummary():');
  for (const s of health) {
    log(`    ${pad(s.name, 15)} ${pad(s.state, 13)} ${s.message}${s.fallback ? `  [fallback: ${s.fallback}]` : ''}`
      + `  (req=${s.attempts}, ${secs(s.elapsedMs)})`);
  }
}

/* ------------------------------------------------------------------------ */
/* Run                                                                      */
/* ------------------------------------------------------------------------ */

const site = await startServer({ base: '/' });
const fixture = SIM ? await startFixture() : null;
const browser = await launchBrowser({ headless: !flag('--headful') });
let exitCode = 0;
try {
  const version = await browser.version();
  report.browser = version.product;
  log(`browser-sources — ${version.product}; site ${site.url}${fixture ? `; fixture ${fixture.origin}` : ''}`);

  /* ---------------- live tab: production CSP, real services ---------------- */
  if (LIVE) {
    const page = await browser.newPage('about:blank');
    const net = recordNetwork(page);
    await page.send('Network.enable');
    await page.goto(site.url);
    await page.waitFor(() => document.documentElement.dataset.appReady === 'true', { timeout: 20000 });
    const ids = await page.evaluate(installHelpers);
    log(`\n[live] ${new Date().toISOString()}  sources.js loaded in the page (sources: ${ids.join(', ')}); CSP enforced`);
    report.live.domains = {};
    for (const domain of DOMAINS) {
      log(`\n=== ${domain}`);
      const entry = {};
      for (const id of ['crtsh', 'thc']) {
        const since = await nowTs(page);
        const out = await page.evaluate((i, d) => window.__bs.run(i, d), id, domain);
        out.network = net.since(since - 0.05).filter((e) => !/^(data|blob|chrome)/.test(e.url) && !e.url.startsWith(site.origin));
        entry[id] = out;
        printRun(`fetchSource('${id}')`, out);
        for (const e of out.network) {
          log(`  ${' '.repeat(34)} net ${e.method} ${e.url.slice(0, 90)} → ${e.status ?? '-'} ACAO=${e.acao ?? '(none)'}${e.failed ? ` FAILED ${e.failed}${e.cors ? ` (${e.cors})` : ''}` : ''}${e.type ? ` [${e.type}]` : ''}`
            + `${e.rawStatus !== undefined ? `  raw: HTTP ${e.rawStatus} ${e.rawType ?? ''} ACAO=${e.rawAcao ?? '(none)'} server=${e.rawServer ?? '?'}` : ''}`);
        }
      }
      const thcPre = entry.thc.network.filter((e) => e.method === 'OPTIONS' || /preflight/i.test(`${e.type} ${e.initiator}`));
      check(`live ip.thc.org from the browser (${domain}): CORS ok, POST text/plain without preflight`,
        entry.thc.result?.ok && thcPre.length === 0 && entry.thc.network.some((e) => e.method === 'POST' && e.acao === '*'),
        `names: ${(entry.thc.result?.names || []).join(', ') || '(none)'}; preflights: ${thcPre.length}`);
      check(`live crt.sh from the browser (${domain}) answered or failed cleanly`,
        entry.crtsh.result && (entry.crtsh.result.ok || ['unavailable', 'timeout', 'rate-limit'].includes(entry.crtsh.result.errorKind)),
        entry.crtsh.result?.ok ? `ok in ${secs(entry.crtsh.result.elapsedMs)}, ${entry.crtsh.result.attempts} request(s)` : entry.crtsh.result?.error);
      report.live.domains[domain] = entry;
    }
    if (!flag('--no-all')) {
      const domain = DOMAINS[0];
      log(`\n=== fetchAllSources('${domain}') — crt.sh, Cert Spotter, Anubis, ip.thc.org (HackerTarget / OTX off)`);
      const out = await page.evaluate((d) => window.__bs.run('all', d, { sources: ['crtsh', 'certspotter', 'anubis', 'thc'] }), domain);
      for (const r of out.results) printRun(r.source, { result: r, events: out.events.filter((e) => e.source === r.source), fetchErrors: [] });
      log(`  ${out.names.length} unique names in ${secs(out.elapsed)}: ${out.names.join(' ')}`);
      log(`  wildcard bases: ${out.wildcardBases.join(', ') || '(none)'}`);
      printHealth(out.health);
      report.live.all = out;
    }
    const pagingDomain = option('--thc-paging');
    if (pagingDomain) {
      log(`\n=== ip.thc.org paging on the real service: ${pagingDomain}`);
      const since = await nowTs(page);
      const out = await page.evaluate((d) => window.__bs.run('thc', d), pagingDomain);
      printRun("fetchSource('thc')", out);
      const posts = net.since(since - 0.05).filter((e) => e.url.includes('ip.thc.org') && e.method === 'POST');
      const gaps = posts.slice(1).map((e, i) => Math.round((e.ts - posts[i].ts) * 1000));
      check('live ip.thc.org pages are ≥ 2 s apart, no preflight',
        gaps.every((g) => g >= 1950) && net.preflights('ip.thc.org').length === 0,
        `${posts.length} POSTs, gaps ${gaps.join(', ') || '-'} ms, truncated=${out.result?.truncated}, available=${out.result?.available}`);
      report.live.thcPaging = { ...out, gaps };
    }
    await page.close();
  }

  /* ---------------- sim tab: CSP bypassed, CORS enforced by Chrome ---------------- */
  if (SIM) {
    const page = await browser.newPage('about:blank');
    await page.send('Page.setBypassCSP', { enabled: true });
    const net = recordNetwork(page);
    await page.send('Network.enable');
    await page.goto(site.url);
    await page.waitFor(() => document.documentElement.dataset.appReady === 'true', { timeout: 20000 });
    await page.evaluate(installHelpers);
    const F = fixture.origin;
    const crt = (scenario) => [['https://crt.sh/', `${F}/crt/${scenario}/`]];
    const base = RETRY_BASE_MS;
    log(`\n[sim] crt.sh / Cert Spotter / ip.thc.org stand-ins at ${F} (cross-origin to ${site.origin}); retry base ${base ?? 'production (4 s)'}${base ? ' ms' : ''}`);

    /* S1: crt.sh down — 502 without CORS on every attempt; Cert Spotter answers. */
    log('\nS1  crt.sh 502 without CORS on every attempt + Cert Spotter fallback (fetchAllSources)');
    let since = await nowTs(page);
    const s1 = await page.evaluate((d, rw, b) => window.__bs.run('all', d, { sources: ['crtsh', 'certspotter'], rewrite: rw, retryDelayMs: b }),
      SIM_DOMAIN, [...crt('down'), ['https://api.certspotter.com/v1/', `${F}/certspotter/`]], base);
    const s1crt = s1.results.find((r) => r.source === 'crtsh');
    const s1cs = s1.results.find((r) => r.source === 'certspotter');
    printRun('crtsh', { result: s1crt, events: s1.events.filter((e) => e.source === 'crtsh'), fetchErrors: s1.fetchErrors.filter((f) => f.url.includes('/crt/')) });
    printRun('certspotter', { result: s1cs, events: [], fetchErrors: [] });
    printHealth(s1.health);
    const s1net = net.since(since - 0.05).filter((e) => e.url.includes('/crt/down'));
    const delays = s1.events.filter((e) => e.source === 'crtsh' && e.type === 'retry').map((e) => e.delayMs);
    check('S1 each CORS-less 502 surfaces in Chrome as TypeError',
      s1.fetchErrors.filter((f) => f.url.includes('/crt/down')).length === 5 && s1.fetchErrors.every((f) => f.name === 'TypeError'),
      s1.fetchErrors.map((f) => `${f.name}: ${f.message}`).filter((v, i, a) => a.indexOf(v) === i).join(' | '));
    check('S1 Chrome reports the CORS reason (CDP loadingFailed)', s1net.length === 5 && s1net.every((e) => e.cors === 'MissingAllowOriginHeader'),
      s1net.map((e) => `${e.status ?? '-'} ${e.cors ?? e.failed}`).join(', '));
    check('S1 5 attempts: 4 × subdomain search then the identity search', s1crt.attempts === 5
      && fixture.hitsFor('/crt/down').map((h) => (h.search.includes('q=%25.') ? 's' : 'i')).join('') === 'ssssi',
    fixture.hitsFor('/crt/down').map((h) => decodeURIComponent(h.search).replace(/&.*/, '')).join(' '));
    const expected = base ? [base, 2 * base, 4 * base, 8 * base] : [4000, 8000, 16000, 32000];
    check('S1 exponential backoff with ±25 % jitter', delays.length === 4 && delays.every((d, i) => d >= expected[i] * 0.75 && d <= expected[i] * 1.25),
      `waits ${delays.join(', ')} ms`);
    check('S1 final state unavailable + message explains CORS', s1crt.errorKind === 'unavailable' && /CORS/.test(s1crt.error || ''), s1crt.error);
    const s1h = s1.health.find((h) => h.source === 'crtsh');
    check('S1 health: Cert Spotter used as the fallback', s1h?.fallback === 'certspotter' && s1cs.ok && /Cert Spotter was used/.test(s1h.message), s1h?.message);
    check('S1 no CORS preflight for GET', fixture.hitsFor('/crt/').every((h) => h.method === 'GET'));
    report.sim.s1 = { ...s1, network: s1net };

    /* S2: crt.sh flaps: 502 (no CORS) twice, then 200 with CORS. */
    log('\nS2  crt.sh 502 ×2 (no CORS) then 200');
    const s2 = await page.evaluate((d, rw, b) => window.__bs.run('crtsh', d, { rewrite: rw, retryDelayMs: b }), SIM_DOMAIN, crt('flaky'), base);
    printRun("fetchSource('crtsh')", s2);
    check('S2 recovers on the 3rd attempt with the full subdomain search', s2.result?.ok && !s2.result.partial && s2.result.attempts === 3
      && s2.result.queryForm === 'subdomains' && s2.result.names.includes(`api.${SIM_DOMAIN}`), `names ${s2.result?.names.join(' ')}`);
    report.sim.s2 = s2;

    /* S3: 429 with CORS: classified as rate-limit; Retry-After is not readable cross-origin. */
    log('\nS3  crt.sh 429 (with CORS, Retry-After: 1 not exposed)');
    const s3 = await page.evaluate((d, rw, b) => window.__bs.run('crtsh', d, { rewrite: rw, retryDelayMs: b }), SIM_DOMAIN, crt('ratelimit'), base);
    printRun("fetchSource('crtsh')", s3);
    check('S3 rate-limit with a quota hint; backoff used because Retry-After is hidden', s3.result?.errorKind === 'rate-limit'
      && s3.result.quota?.limited && s3.result.quota.retryAfterMs === null && s3.events.length === 4,
    `quota ${JSON.stringify(s3.result?.quota)}`);
    report.sim.s3 = s3;

    /* S4: abort while waiting between retries. */
    log('\nS4  abort during the backoff wait');
    const s4 = await page.evaluate((d, rw) => window.__bs.run('crtsh', d, { rewrite: rw, retryDelayMs: 5000, abortOnRetry: true }), SIM_DOMAIN, crt('down'));
    printRun("fetchSource('crtsh')", s4);
    check('S4 rejects with AbortError promptly, no further request', s4.rejected?.name === 'AbortError' && s4.elapsed - s4.abortedAt < 300
      && s4.requests.length === 1, `aborted at ${s4.abortedAt} ms, settled at ${s4.elapsed} ms, ${s4.requests.length} request(s)`);
    report.sim.s4 = s4;

    /* S5: abort while the request is in flight (server never answers). */
    log('\nS5  abort an in-flight request (hanging server)');
    const hangBefore = fixture.hitsFor('/crt/hang').length;
    const s5 = await page.evaluate((d, rw) => window.__bs.run('crtsh', d, { rewrite: rw, abortAfterMs: 800 }), SIM_DOMAIN, crt('hang'));
    printRun("fetchSource('crtsh')", s5);
    await new Promise((r) => setTimeout(r, 300));
    const s5hit = fixture.hitsFor('/crt/hang')[hangBefore];
    check('S5 rejects with AbortError right after abort; the connection is dropped', s5.rejected?.name === 'AbortError'
      && s5.elapsed - s5.abortedAt < 300, `settled ${s5.elapsed - s5.abortedAt} ms after abort; server saw close: ${s5hit?.closedAt ? 'yes' : 'no'}`);
    report.sim.s5 = s5;

    /* S6: per-request timeout: a timed-out query form is not repeated. */
    log('\nS6  timeout (hanging server, timeoutMs 1000)');
    const s6 = await page.evaluate((d, rw, b) => window.__bs.run('crtsh', d, { rewrite: rw, timeoutMs: 1000, retryDelayMs: b }), SIM_DOMAIN, crt('hang'), base);
    printRun("fetchSource('crtsh')", s6);
    check('S6 timeout: subdomain search once, identity search once, errorKind timeout', s6.result?.errorKind === 'timeout' && s6.result.attempts === 2,
      s6.result?.error);
    report.sim.s6 = s6;

    /* S7: ip.thc.org paging: text/plain POST, no preflight, ≥ 2 s spacing. */
    log('\nS7  ip.thc.org 3 pages (stand-in)');
    since = await nowTs(page);
    const s7 = await page.evaluate((d, rw) => window.__bs.run('thc', d, { rewrite: rw }), SIM_DOMAIN,
      [['https://ip.thc.org/api/v1/lookup/subdomains', `${F}/thc/subdomains`]]);
    printRun("fetchSource('thc')", s7);
    const posts = fixture.hitsFor('/thc/');
    const gaps = posts.slice(1).map((h, i) => h.at - posts[i].at);
    check('S7 three POSTs with a CORS-safelisted text/plain body, no OPTIONS', posts.length === 3 && posts.every((h) => h.method === 'POST'
      && /^text\/plain/i.test(h.contentType || '')) && net.preflights('/thc/').length === 0,
    posts.map((h) => `${h.method} ${h.contentType} ${JSON.stringify(h.body)}`).join(' | '));
    check('S7 pages ≥ 2 s apart and page_state forwarded', gaps.every((g) => g >= 1990) && posts[1]?.body?.page_state === 'p2'
      && posts[2]?.body?.page_state === 'p3', `gaps ${gaps.join(', ')} ms`);
    check('S7 300 names collected, available = 250 reported by the service', s7.result?.names.length === 300 && s7.result.available === 250
      && !s7.result.truncated);
    report.sim.s7 = { ...s7, gaps };
    await page.close();
  }
} catch (err) {
  console.error(err);
  exitCode = 2;
} finally {
  await browser.close();
  await site.close();
  if (fixture) {
    report.sim.fixtureHits = fixture.hits;
    await fixture.close();
  }
}

const failed = report.checks.filter((c) => !c.pass);
log(`\n${report.checks.length - failed.length}/${report.checks.length} checks passed in ${secs(Date.now() - t0)}`);
if (failed.length) for (const c of failed) log(`  FAILED: ${c.name}${c.detail ? ` — ${c.detail}` : ''}`);
if (JSON_OUT) {
  writeReport(JSON_OUT, JSON.stringify(report, null, 2));
  log(`wrote ${JSON_OUT}`);
}
process.exitCode = exitCode || (failed.length ? 1 : 0);
