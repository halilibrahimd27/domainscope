#!/usr/bin/env node
/**
 * renew.e2e.mjs — end-to-end test of the "Renewal readiness" view in a real headless Chrome/Edge.
 * OFFLINE: every DoH query is answered in the page by a fake resolver built from the table below
 * (window.fetch wrapped before the app loads; the four consistency resolvers are told apart by
 * their URL, so one of them can lag behind), Globalping is a fake API whose results reuse the
 * probes of the live capture tests/fixtures/globalping/m28, every other https:// request is
 * blocked, and every request that leaves the page's origin is counted through CDP.
 *
 *   node tests/e2e/renew.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry (Certificates group, after Certificate), the empty state (nothing sent),
 * names that are not host names and a wildcard under a public suffix, a check of four names against Let's Encrypt with HTTP-01 started
 * from the keyboard (focus on Stop meanwhile, back on Check readiness after; a wildcard CAA forbids
 * and HTTP-01 cannot validate, a private address, a lagging resolver on a CNAME'd name, a ready
 * name with IPv6), the per-name cards (worst first, findings by area, the resolvers' answers), the
 * URL, Copy summary, the CSV / JSON exports, the HTTP-01 reachability test (nothing sent before the
 * click; the consent + cost dialog, Escape sends nothing and leaves the focus on the button, which
 * keeps it while busy and after; exactly the lib/renewal.js requests, IPv4 and IPv6; an IPv6
 * server that answers 503 fails the name; a redirect to HTTPS keeping the token passes; leaving the
 * view mid-test reads the paid measurement again on return, with no new probe; Stop, then "Read the
 * results again" for free; the quota running out after the IPv4 measurement: IPv6 keeps the earlier
 * failure and its time, the name still fails; a new check stops a running test and the card says so
 * at once),
 * the language switch keeping report and test, the certificate block (the sample: its names, a CA
 * not in the list), the links from Certificate and SSL Targets over a kept report (the same
 * certificate leaves a CA chosen by hand; a newly shared Sectigo certificate brings its names and
 * its CA; other carried names drop that CA's hint; a link never sets its CA or challenge next to a
 * draft it left alone; nothing sent), a check past the 50-name cap still replaced by a certificate's
 * link, a shared link that runs on open (DNS-01: the Cloudflare plugins, TXT leftovers), Ctrl+Enter,
 * an AAAA lookup no resolver answers (IPv6 not checked: "could not be checked", only IPv4 counted),
 * 320 / 375 px phones light / dark in both languages without horizontal scroll, every resolver
 * answering 429 ("could not be checked", never "ready"), zero console errors / CSP violations /
 * missing i18n keys, nothing sent outside the page. The Plan panel: loaded on its first open, the SC-081 schedule with the
 * step in force, the sample's plan (over the limit it was issued under, two thirds of its lifetime, no renewal before
 * 2030), Let's Encrypt chosen by hand: nothing sent before the click, then exactly the directory and the renewal-info of
 * its CertID (the CA's window; a 404 shows "n/a" and why, Retry asks again), the coverage planner (the groupings, what a
 * wildcard leaves uncovered, one certificate per environment, the CSR configurations per key type and their download,
 * the form's names), and the panel on 320 / 375 px phones in both languages, light and dark.
 *
 * Data is documentation space only (example.com / .net, 192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24, 2001:db8::/32, 10.0.0.0/8) plus provider name servers (ns.cloudflare.com, natrohost.com)
 * and the public certificate tests/fixtures/real_github.pem, whose names are only filled in, never checked.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';
import { ariCertId, scheduleStep, validityDays } from '../../assets/js/lib/renewalplan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const M28 = JSON.parse(readFileSync(path.join(HERE, '..', 'fixtures', 'globalping', 'm28-acme-http-404.json'), 'utf8'));

const SOA = (z) => ({ mname: `ns1.${z}`, rname: `hostmaster.${z}`, serial: 2026092801, refresh: 7200, retry: 900, expire: 1209600, minimum: 300 });
const CAA = (tag, value) => ({ flags: 0, tag, value });

/** The fake DNS: name → { TYPE: [data…] | CNAME: target }. */
const ZONE = {
  'example.com': {
    SOA: [SOA('example.com')], NS: ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'], A: ['203.0.113.10'],
    CAA: [CAA('issue', 'letsencrypt.org'), CAA('issuewild', ';'), CAA('iodef', 'mailto:security@example.com')]
  },
  'www.example.com': { A: ['203.0.113.10'], AAAA: ['2001:db8::10'] },
  'api.example.com': { A: ['10.0.0.5'] },
  'shop.example.com': { CNAME: 'shop.example.net' },
  'example.net': { SOA: [SOA('example.net')], NS: ['ns1.natrohost.com', 'ns2.natrohost.com'] },
  'shop.example.net': { A: ['198.51.100.20'] },
  '_acme-challenge.www.example.com': { TXT: ['old-token-1', 'old-token-2'] }
};
/** CZ.NIC still sees an old CAA record set on shop.example.com (a lagging name server). */
const VIEWS = { cznic: { 'shop.example.com': { CAA: [CAA('issue', 'letsencrypt.org'), CAA('issue', 'pki.goog')] } } };
const SIGNED = ['example.com'];
const HOSTS = { 'cloudflare-dns.com': 'cloudflare', 'dns.google': 'google', 'doh.dns.sb': 'dnssb', 'odvr.nic.cz': 'cznic' };

/** Globalping scenario per target and IP version (the probes answer the made-up token like this). */
const GP_SCENARIOS = { 'www.example.com|4': 'not-found', 'www.example.com|6': 'server-error', 'shop.example.com|4': 'redirect' };
const GP_PROBES = M28.final.body.results.map((r) => r.probe);

/** In-page stubs: DoH from the table (per resolver), a fake Globalping, the RDAP bootstrap. */
const fakeScript = () => `(() => {
  const Z = ${JSON.stringify(ZONE)};
  const VIEWS = ${JSON.stringify(VIEWS)};
  const SIGNED = ${JSON.stringify(SIGNED)};
  const HOSTS = ${JSON.stringify(HOSTS)};
  const SCEN = ${JSON.stringify(GP_SCENARIOS)};
  const PROBES = ${JSON.stringify(GP_PROBES)};
  window.__fakeDnsLog = [];
  window.__dnsDelayMs = 0;
  // Non-zero: every DoH request gets this HTTP status (a rate limit on every resolver).
  window.__dnsStatus = 0;
  // 'name|TYPE' → an rcode every resolver answers for that question (SERVFAIL: no answer for one family).
  window.__dnsRcodeFor = {};
  // rejectPost: the number of the POST that gets a quota 429 (rate_limit_exceeded) instead of a measurement.
  const gp = window.__gp = { calls: [], n: 0, posts: 0, remaining: 250, measurements: {}, delayMs: 0, rejectPost: 0 };
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200, headers = {}) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json', ...headers } });
  const under = (n, z) => n === z || n.endsWith('.' + z);
  const soaOwner = (z, n) => { let cur = n; while (cur.includes('.')) { if (z[cur] && z[cur].SOA) return cur; cur = cur.slice(cur.indexOf('.') + 1); } return null; };
  function globalping(url, init) {
    const API = 'https://api.globalping.io/v1';
    const p = url.slice(API.length);
    const method = String((init && init.method) || 'GET').toUpperCase();
    let body = null;
    try { body = init && typeof init.body === 'string' ? JSON.parse(init.body) : null; } catch { body = null; }
    gp.calls.push({ method, path: p, body });
    if (p === '/limits') return json({ rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: gp.remaining, reset: 0 } } } });
    if (p === '/measurements' && method === 'POST') {
      gp.posts += 1;
      if (gp.posts === gp.rejectPost) {
        return json({ error: { type: 'rate_limit_exceeded', message: 'API rate limit exceeded.' } }, 429, { 'x-ratelimit-limit': '250', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '3600' });
      }
      const cost = (body.locations || []).reduce((n, l) => n + (l.limit || 1), 0) || body.limit || 1;
      gp.remaining -= cost;
      gp.n += 1;
      const id = 'fakeRenew' + String(gp.n).padStart(6, '0');
      gp.measurements[id] = { id, at: Date.now(), body, cost };
      return json({ id, probesCount: cost }, 202, { 'x-ratelimit-limit': '250', 'x-ratelimit-remaining': String(gp.remaining), 'x-ratelimit-consumed': String(250 - gp.remaining), 'x-ratelimit-reset': '3600', 'x-request-cost': String(cost) });
    }
    const m = /^\\/measurements\\/([A-Za-z0-9]+)$/.exec(p);
    if (m && gp.measurements[m[1]]) {
      const meas = gp.measurements[m[1]];
      const fam = (meas.body.measurementOptions && meas.body.measurementOptions.ipVersion) || 4;
      const base = { id: meas.id, type: 'http', target: meas.body.target, probesCount: meas.cost, measurementOptions: meas.body.measurementOptions };
      if (Date.now() - meas.at < 400 + gp.delayMs) return json({ ...base, status: 'in-progress', results: [] });
      const scen = SCEN[meas.body.target + '|' + fam] || 'not-found';
      const path = meas.body.measurementOptions.request.path;
      const address = fam === 6 ? '2001:db8::10' : (meas.body.target === 'shop.example.com' ? '198.51.100.20' : '203.0.113.10');
      const result = () => {
        if (scen === 'timeout') return { status: 'failed', failureSource: 'target', resolvedAddress: null, rawOutput: 'Request timed out while establishing the TCP connection.', statusCode: null, tls: null };
        if (scen === 'redirect') return { status: 'finished', resolvedAddress: address, statusCode: 301, headers: { location: 'https://' + meas.body.target + path }, tls: null };
        if (scen === 'server-error') return { status: 'finished', resolvedAddress: address, statusCode: 503, headers: {}, tls: null };
        return { status: 'finished', resolvedAddress: address, statusCode: 404, headers: {}, tls: null };
      };
      return json({ ...base, status: 'finished', results: PROBES.map((probe) => ({ probe, result: result() })) });
    }
    return json({ error: { type: 'not_found', message: 'Not Found.' } }, 404);
  }
  // Let's Encrypt's ACME server for the Plan panel's ARI: its directory and renewal-info (status: what renewal-info answers).
  const ari = window.__ari = { calls: [], status: 200 };
  function acme(url) {
    const p = url.slice('https://acme-v02.api.letsencrypt.org'.length);
    ari.calls.push(p);
    if (p === '/directory') return json({ newNonce: 'https://acme-v02.api.letsencrypt.org/acme/new-nonce', renewalInfo: 'https://acme-v02.api.letsencrypt.org/acme/renewal-info' });
    if (p.startsWith('/acme/renewal-info/') && ari.status === 200) {
      return json({ suggestedWindow: { start: '2032-08-30T00:00:00Z', end: '2032-09-01T00:00:00Z' } }, 200, { 'retry-after': '21600' });
    }
    return json({ type: 'urn:ietf:params:acme:error:malformed', detail: 'Certificate not found', status: 404 }, p.startsWith('/acme/renewal-info/') ? ari.status : 404);
  }
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://api.globalping.io/')) return globalping(url, init);
    if (url.startsWith('https://acme-v02.api.letsencrypt.org/')) return acme(url);
    if (url.startsWith('https://data.iana.org/rdap/')) return json({ services: [] });
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    const resolver = HOSTS[new URL(url).hostname] || new URL(url).hostname;
    window.__fakeDnsLog.push({ name, type: q.type, resolver });
    if (window.__dnsDelayMs) await new Promise((r) => setTimeout(r, window.__dnsDelayMs));
    if (window.__dnsStatus) return new Response('', { status: window.__dnsStatus });
    const forced = window.__dnsRcodeFor[name + '|' + q.type];
    if (forced) {
      return new Response(wire.encodeMessage({
        id: 0, flags: { qr: true, rd: true, ra: true }, rcode: forced, questions: [{ name: q.name, type: q.type }], answers: [], authorities: [], edns: {}
      }), { headers: { 'content-type': 'application/dns-message' } });
    }
    const z = { ...Z, ...(VIEWS[resolver] || {}) };
    const answers = [];
    let cur = name;
    let rcode = 'NOERROR';
    for (let i = 0; i < 8; i += 1) {
      const node = z[cur];
      if (!node) { rcode = 'NXDOMAIN'; break; }
      if (node.CNAME && q.type !== 'CNAME') { answers.push({ name: cur, type: 'CNAME', ttl: 300, data: node.CNAME }); cur = node.CNAME; continue; }
      for (const data of node[q.type] || []) answers.push({ name: cur, type: q.type, ttl: 300, data: q.type === 'TXT' ? [data] : data });
      break;
    }
    const authorities = [];
    if (!answers.some((a) => a.type === q.type)) {
      const owner = soaOwner(z, cur);
      if (owner) authorities.push({ name: owner, type: 'SOA', ttl: 300, data: z[owner].SOA[0] });
    }
    const ad = SIGNED.some((s) => under(cur, s));
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true, ad }, rcode,
      questions: [{ name: q.name, type: q.type }], answers, authorities, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent || '', sel);
const dnsCount = (page) => page.evaluate(() => window.__fakeDnsLog.length);
const gpCalls = (page) => page.evaluate(() => window.__gp.calls.map((c) => `${c.method} ${c.path}`));
const postCount = (page) => page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST').length);
/** The page at 320 and 375 px without horizontal scroll (a shot at 375), then back on the desktop. */
async function phoneCheck(page, opts, name) {
  for (const width of [320, 375]) {
    await page.setViewport({ width, height: 700, mobile: true });
    await assertNoHorizontalScroll(page, `${name} ${width}`);
  }
  await page.evaluate(() => document.querySelector('.rnw-test-card')?.scrollIntoView({ block: 'start' }));
  await shot(page, opts, name);
  await page.setViewport({ width: 1440, height: 900 });
}
const focusedAction = (page) => page.evaluate(() => document.activeElement?.dataset?.action || document.activeElement?.tagName);
const typeNames = (page, value) => page.evaluate((v) => {
  const ta = document.querySelector('[data-role="renew-names"]');
  ta.value = v;
  ta.dispatchEvent(new Event('input', { bubbles: true }));
}, value);
const setSelect = (page, sel, value) => page.evaluate(([s, v]) => {
  const el = document.querySelector(s);
  el.value = v;
  el.dispatchEvent(new Event('change', { bubbles: true }));
}, [sel, value]);
/** The name cards in display order: name, verdict, finding ids, open. */
const cards = (page) => page.evaluate(() => [...document.querySelectorAll('.rnw-name')].map((c) => ({
  name: c.dataset.name, verdict: c.dataset.verdict, open: c.open,
  findings: [...c.querySelectorAll('.rnw-finding')].map((li) => `${li.dataset.id}:${li.dataset.severity}`)
})));
const waitDone = (page, message = 'check done') => page.waitFor(() => !!document.querySelector('.rnw-hero')
  && !document.querySelector('[data-action="renew-run"]').hidden && document.querySelector('[data-action="renew-stop"]').hidden, { timeout: 20000, message });
/** Open a route on the view already shown; resolves once the app has handled its hashchange (its listener came first). */
const routeTo = (page, hash) => page.evaluate((to) => new Promise((resolve) => {
  window.addEventListener('hashchange', () => resolve(), { once: true });
  location.hash = to;
}), hash);
const waitTestDone = (page, message = 'test done') => page.waitFor(() => ['done', 'error', 'quota'].includes(document.querySelector('.rnw-test')?.dataset.state), { timeout: 20000, message });

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}\n`);
  const external = [];
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    page.conn.on('Network.requestWillBeSent', (p) => {
      const u = String((p.request && p.request.url) || '');
      if (!u.startsWith(origin) && !/^(data|blob|about|chrome-extension):/.test(u)) external.push(u);
    }, page.sessionId);
    await page.send('Network.enable');
    await page.send('Network.setBlockedURLs', { urls: ['https://*'] });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript() });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/renew: nav entry after Certificate in the Certificates group, empty state, nothing sent', async () => {
      await page.goto(`${server.url}#/renew`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'renew');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/cert"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '').split('?')[0]) : [];
      });
      assertEqual(nav, ['scan', 'cert', 'renew', 'estate'], 'Certificates group');
      assertEqual(await text(page, 'h1'), 'Renewal readiness', 'title');
      assert(await page.evaluate(() => !!document.querySelector('.rnw-empty .empty')), 'empty state');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="renew-ca"]').value, document.querySelector('[data-role="renew-challenge"]').value]), ['', 'unknown'], 'defaults');
      assertEqual(await dnsCount(page), 0, 'no DNS query');
      await shot(page, opts, 'renew-empty-desktop-light-en');
    });

    await run.step('names that are not host names, and a wildcard no CA issues, are left out and said; an empty box asks for a name', async () => {
      await typeNames(page, 'www.example.com 192.0.2.1 _acme-challenge.example.com *.co.uk');
      await page.waitFor(() => /Not host names, left out: 192\.0\.2\.1, _acme-challenge\.example\.com/.test(document.querySelector('.rnw-names-note')?.textContent || ''), { message: 'invalid note' });
      assert(/No CA issues a wildcard directly under a public suffix, left out: \*\.co\.uk/.test(await text(page, '.rnw-names-note')), `suffix note: ${await text(page, '.rnw-names-note')}`);
      await typeNames(page, '');
      await page.click('[data-action="renew-run"]');
      await page.waitFor(() => /at least one host name/.test(document.querySelector('.rnw-form-card')?.textContent || ''), { message: 'no names' });
      assertEqual(await dnsCount(page), 0, 'nothing sent');
    });

    await run.step('four names against Let\'s Encrypt with HTTP-01 (keyboard: focus follows Check ⇄ Stop): worst first, findings by area, the URL', async () => {
      await typeNames(page, 'www.example.com\n*.example.com\napi.example.com\nshop.example.com');
      await setSelect(page, '[data-role="renew-ca"]', 'letsencrypt');
      await setSelect(page, '[data-role="renew-challenge"]', 'http-01');
      // Slow answers keep the check running long enough to see where the focus is meanwhile.
      await page.evaluate(() => { window.__dnsDelayMs = 150; document.querySelector('[data-action="renew-run"]').focus(); });
      await page.press('Enter');
      await page.waitFor(() => document.activeElement === document.querySelector('[data-action="renew-stop"]') && !document.activeElement.hidden, { message: 'focus on Stop while the check runs' });
      await page.evaluate(() => { window.__dnsDelayMs = 0; });
      await waitDone(page);
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'renew-run', 'focus back on Check readiness');
      assertEqual(await page.evaluate(() => document.querySelector('.rnw-hero').dataset.headline), 'fail', 'headline');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rnw-counts [data-count]')].map((b) => b.textContent)), ['2 will fail', '1 with warnings', '1 ready'], 'counts');
      const c = await cards(page);
      assertEqual(c.map((x) => [x.name, x.verdict, x.open]), [['*.example.com', 'fail', true], ['api.example.com', 'fail', true], ['shop.example.com', 'warnings', true], ['www.example.com', 'ready', false]], 'order');
      // A wildcard needs DNS-01, so its DNS side is checked too.
      assertEqual(c[0].findings, ['caa.deny-all:error', 'resolvers.agree:ok', 'wildcard.method:error', 'acme.none:ok', 'provider.known:info', 'dnssec.secure:ok'], 'wildcard');
      assert(c[1].findings.includes('http.private:error'), `private: ${c[1].findings}`);
      assertEqual(c[2].findings.slice(0, 3), ['caa.cname:info', 'caa.allowed:ok', 'resolvers.differ:warn'], 'shop');
      assertEqual(c[3].findings, ['caa.allowed:ok', 'resolvers.agree:ok', 'acme.leftover:info', 'dnssec.secure:ok', 'http.ok:ok', 'http.ipv6:info'], 'www');
      // The lagging resolver is named on the shop card; every resolver was asked for CAA by name.
      const shop = await page.evaluate(() => [...document.querySelectorAll('.rnw-name[data-name="shop.example.com"] .rnw-resolver')].map((li) => `${li.dataset.resolver}:${li.querySelector('.rnw-resolver-name').textContent}${li.querySelector('.rnw-resolver-state').textContent}`));
      assertEqual(shop, ['cloudflare:Cloudflare3 records at example.com', 'google:Google Public DNS3 records at example.com', 'dnssb:DNS.SB3 records at example.com', 'cznic:CZ.NIC ODVR2 records at shop.example.com'], 'resolver lines');
      const resolvers = await page.evaluate(() => [...new Set(window.__fakeDnsLog.filter((q) => q.type === 'CAA').map((q) => q.resolver))].sort());
      assertEqual(resolvers, ['cloudflare', 'cznic', 'dnssb', 'google'], 'CAA asked of each resolver');
      assert(/names=www\.example\.com%2C\*\.example\.com%2Capi\.example\.com%2Cshop\.example\.com&ca=letsencrypt&challenge=http-01$/.test(await page.evaluate(() => location.hash)), `URL: ${await page.evaluate(() => location.hash)}`);
      assertEqual(await gpCalls(page), [], 'no Globalping before a click');
      await shot(page, opts, 'renew-results-desktop-light-en');
    });

    await run.step('Copy summary, CSV and JSON', async () => {
      await stubClipboard(page);
      await page.click('.rnw-hero .sum-actions button');
      await page.waitFor(() => (window.__clip || []).length === 1, { message: 'copied' });
      const [md] = await takeClipboard(page);
      const lines = md.split('\n');
      assertEqual(lines.slice(0, 3), [
        '**Renewal readiness · `www.example.com`, `*.example.com`, `api.example.com` +1 more**',
        '- 2 will fail · 1 with warnings · 1 ready',
        "- CA: Let's Encrypt · challenge: HTTP-01"
      ], 'summary head');
      assert(lines.includes('- **Error:** `*.example.com` — CAA forbids every CA'), md);
      assert(lines.includes('- **Warning:** `shop.example.com` — Resolvers see different CAA records'), md);
      assert(/#\/renew\?names=www\.example\.com%2C/.test(lines[lines.length - 2]), 'permalink');
      await page.click('[data-action="renew-csv"]');
      await page.click('[data-action="renew-json"]');
      const files = await takeDownloads(page);
      assertEqual(files.map((f) => f.name.replace(/-\d{8}-\d{4}/, '')), ['renewal-readiness-example.com.csv', 'renewal-readiness-example.com.json'], 'file names');
      assert(files[0].bom && files[0].text.startsWith('name,verdict,caa_at,caa_records,resolvers,acme_challenge,dnssec,dns_provider,addresses,http01,errors,warnings'), 'CSV header');
      assert(files[0].text.includes('api.example.com,fail,example.com'), 'CSV row');
      const json = JSON.parse(files[1].text);
      assertEqual([json.schema, json.challenge, json.ca.id, json.names.length, json.summary.fail], ['domainscope.renewal/1', 'http-01', 'letsencrypt', 4, 2], 'JSON');
    });

    await run.step('HTTP-01 test (keyboard): consent dialog (Escape sends nothing, focus back on the button), then IPv4 + IPv6 from three continents', async () => {
      assertEqual(await page.evaluate(() => document.querySelector('[data-action="renew-http01"]').textContent), 'Test 2 names (9 probes)', 'batch button');
      const focusedTestButton = () => page.evaluate(() => {
        const el = document.activeElement;
        return el && el.dataset.action === 'renew-http01' ? (el.getAttribute('aria-busy') ? 'busy' : 'idle') : `${el?.tagName}:${el?.dataset?.action || el?.className}`;
      });
      await page.evaluate(() => document.querySelector('[data-action="renew-http01"]').focus());
      await page.press('Enter');
      await page.waitFor(() => !!document.querySelector('.gp-confirm'), { message: 'dialog' });
      const dialog = await text(page, '.gp-confirm');
      assert(/www\.example\.com, shop\.example\.com/.test(dialog) && /\/\.well-known\/acme-challenge\//.test(dialog) && /Cost: 9 probes of the 250 left/.test(dialog), dialog);
      await page.press('Escape');
      await page.waitFor(() => !document.querySelector('.gp-confirm') && document.querySelector('.rnw-test')?.dataset.state === 'idle', { message: 'closed' });
      assertEqual(await focusedTestButton(), 'idle', 'focus on the test button after Escape');
      assertEqual(await gpCalls(page), ['GET /limits'], 'only the free quota read');
      await page.press('Enter');
      await page.waitFor(() => !!document.querySelector('.gp-confirm'), { message: 'dialog again' });
      await page.click('.gp-confirm .btn-primary');
      await page.waitFor(() => !document.querySelector('.gp-confirm'), { message: 'dialog closed' });
      assertEqual(await focusedTestButton(), 'busy', 'focus stays on the busy test button while the test runs');
      await waitTestDone(page);
      assertEqual(await page.evaluate(() => document.querySelector('.rnw-test').dataset.state), 'done', 'test done');
      assertEqual(await focusedTestButton(), 'idle', 'focus on the test button after the test');
      const posts = await page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST').map((c) => c.body));
      assertEqual(posts.map((b) => [b.target, b.measurementOptions.ipVersion || 4, b.measurementOptions.protocol, b.measurementOptions.port, b.locations.map((l) => l.continent).join('')]),
        [['www.example.com', 4, 'HTTP', 80, 'EUNAAS'], ['www.example.com', 6, 'HTTP', 80, 'EUNAAS'], ['shop.example.com', 4, 'HTTP', 80, 'EUNAAS']], 'requests');
      assert(posts.every((b) => /^\/\.well-known\/acme-challenge\/domainscope-check-[a-z0-9]{16}$/.test(b.measurementOptions.request.path)), 'made-up token');
      assertEqual(posts[0].measurementOptions.request.path, posts[1].measurementOptions.request.path, 'one token per name');
      const c = await cards(page);
      const www = c.find((x) => x.name === 'www.example.com');
      assertEqual([www.verdict, www.findings.slice(-2)], ['fail', ['http01.ok:ok', 'http01.failed:error']], 'the IPv6 server answers 503');
      assert(c.find((x) => x.name === 'shop.example.com').findings.includes('http01.redirect:ok'), 'a redirect to HTTPS keeping the token passes');
      assertEqual(c.map((x) => x.name), ['www.example.com', '*.example.com', 'api.example.com', 'shop.example.com'], 'worst first, then as entered');
      const probes = await page.evaluate(() => [...document.querySelectorAll('.rnw-name[data-name="www.example.com"] .rnw-family')].map((f) => `${f.dataset.family}:${f.dataset.verdict}:${[...f.querySelectorAll('.rnw-probe')].map((p) => p.dataset.outcome).join(',')}`));
      assertEqual(probes, ['4:ok:not-found,not-found,not-found', '6:failed:server-error,server-error,server-error'], 'probe lines');
      assert(/Helsinki, FI \(Hetzner Online\)/.test(await text(page, '.rnw-name[data-name="www.example.com"] .rnw-probe')), 'probe place');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rnw-counts [data-count]')].map((b) => b.textContent)), ['3 will fail', '1 with warnings'], 'counts after the test');
      await shot(page, opts, 'renew-tested-desktop-light-en');
    });

    await run.step('the language switch keeps the report and the test, without a new query', async () => {
      const before = await dnsCount(page);
      const calls = (await gpCalls(page)).length;
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('.rnw-hero'), { message: 'report kept' });
      assertEqual(await text(page, 'h1'), 'Yenileme hazırlığı', 'Turkish title');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rnw-counts [data-count]')].map((b) => b.textContent)), ['3 tanesi başarısız olacak', '1 tanesi uyarılı'], 'Turkish counts');
      assert(/IPv6 üzerinden erişilemiyor/.test(await text(page, '.rnw-name[data-name="www.example.com"]')), 'Turkish finding');
      assertEqual([await dnsCount(page), (await gpCalls(page)).length], [before, calls], 'nothing sent');
      await shot(page, opts, 'renew-tested-desktop-light-tr');
      await setLangUi(page, 'en');
    });

    await run.step('leaving the view while a test reads its results: coming back reads the paid measurement again, no new probe', async () => {
      await page.evaluate(() => { window.__gp.delayMs = 2500; });
      const posts = () => page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST').length);
      const before = await posts();
      await page.click('.rnw-name[data-name="shop.example.com"] [data-action="renew-http01-name"]');
      await page.waitFor((n) => window.__gp.calls.filter((c) => c.method === 'POST').length === n + 1, { args: [before], message: 'one measurement created (consent given before: no dialog)' });
      assert(!await page.evaluate(() => !!document.querySelector('.gp-confirm')), 'no second dialog in the page session');
      await gotoRoute(page, 'lookup');
      await page.evaluate(() => { window.__gp.delayMs = 0; });
      await page.click('.nav-link[data-view="renew"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'renew' && document.querySelector('.rnw-test')?.dataset.state === 'done', { message: 'read again on return', timeout: 20000 });
      assertEqual(await posts(), before + 1, 'no new probe');
      const shop = (await cards(page)).find((x) => x.name === 'shop.example.com');
      assert(shop.findings.includes('http01.redirect:ok'), `shop tested: ${shop.findings}`);
    });

    await run.step('Stop during a test (keyboard): the paid measurements are read again for free; focus moves on to the next action', async () => {
      await page.evaluate(() => { window.__gp.delayMs = 60000; });
      const before = await postCount(page);
      await page.click('.rnw-name[data-name="www.example.com"] [data-action="renew-http01-name"]');
      await page.waitFor((n) => window.__gp.calls.filter((c) => c.method === 'POST').length === n + 2 && !!document.querySelector('[data-action="renew-http01-stop"]'),
        { args: [before], message: 'IPv4 + IPv6 measurements created, Stop offered' });
      await page.evaluate(() => document.querySelector('[data-action="renew-http01-stop"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.rnw-test')?.dataset.state === 'stopped', { message: 'stopped' });
      assert(/^Stopped\. The probes were already used/.test(await text(page, '.rnw-test .alert')), `stopped note: ${await text(page, '.rnw-test .alert')}`);
      assertEqual(await focusedAction(page), 'renew-http01-reread', 'focus on Read the results again');
      await phoneCheck(page, opts, 'renew-stopped-mobile-light-en');
      await page.evaluate(() => document.querySelector('[data-action="renew-http01-reread"]').focus());
      await page.evaluate(() => { window.__gp.delayMs = 0; });
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.rnw-test')?.dataset.state === 'done', { message: 'read again', timeout: 20000 });
      assertEqual(await postCount(page), before + 2, 'no new probe');
      assertEqual(await focusedAction(page), 'renew-http01', 'focus on the test button');
    });

    await run.step('a new check stops a running test: the card drops it at once and says the probes were not read', async () => {
      await page.evaluate(() => { window.__gp.delayMs = 60000; });
      const before = await postCount(page);
      await page.click('.rnw-name[data-name="www.example.com"] [data-action="renew-http01-name"]');
      await page.waitFor((n) => window.__gp.calls.filter((c) => c.method === 'POST').length === n + 2 && !!document.querySelector('[data-action="renew-http01-stop"]'),
        { args: [before], message: 'the test is reading its measurements' });
      await page.evaluate(() => { window.__dnsDelayMs = 150; });
      await page.click('[data-action="renew-run"]');
      await page.waitFor(() => !document.querySelector('[data-action="renew-stop"]').hidden && document.querySelector('.rnw-test')?.dataset.state === 'idle'
        && !document.querySelector('[data-action="renew-http01-stop"]') && !document.querySelector('.rnw-results [aria-busy="true"]')
        && [...document.querySelectorAll('.rnw-results [data-action^="renew-http01"]')].every((b) => b.disabled), { message: 'the test card while the check runs' });
      assert(/^The HTTP-01 test was stopped by the new check/.test(await text(page, '.rnw-test .alert')), `note: ${await text(page, '.rnw-test .alert')}`);
      await page.evaluate(() => { window.__dnsDelayMs = 0; window.__gp.delayMs = 0; });
      await waitDone(page, 'the new check');
      assert(/^The HTTP-01 test was stopped by the new check/.test(await text(page, '.rnw-test .alert')), 'the note stays with the new report');
      const www = (await cards(page)).find((x) => x.name === 'www.example.com');
      assert(!www.findings.some((f) => f.startsWith('http01.')), `a new report, untested: ${www.findings}`);
      assertEqual(await postCount(page), before + 2, 'no new probe');
    });

    await run.step('the quota runs out after the IPv4 measurement: read again, IPv6 keeps the earlier failure (and its time), the name still fails, the note says the test is incomplete', async () => {
      // A full test of the new report first: IPv4 passes, the IPv6 server answers 503.
      await page.click('.rnw-name[data-name="www.example.com"] [data-action="renew-http01-name"]');
      await page.waitFor(() => document.querySelector('.rnw-test')?.dataset.state === 'done', { message: 'full test', timeout: 20000 });
      assertEqual((await cards(page)).find((x) => x.name === 'www.example.com').verdict, 'fail', 'IPv6 fails');
      await page.evaluate(() => { window.__gp.rejectPost = window.__gp.posts + 2; });
      await page.click('.rnw-name[data-name="www.example.com"] [data-action="renew-http01-name"]');
      await waitTestDone(page, 'the quota stops the test');
      assertEqual(await page.evaluate(() => document.querySelector('.rnw-test').dataset.state), 'error', 'stopped by the quota, one measurement paid');
      await page.click('[data-action="renew-http01-reread"]');
      await page.waitFor(() => document.querySelector('.rnw-test')?.dataset.state === 'done', { message: 'read again', timeout: 20000 });
      assert(/^HTTP-01 reachability tested for 1 name, but not completely/.test((await text(page, '.rnw-test-done')).trim()), await text(page, '.rnw-test-done'));
      const www = (await cards(page)).find((x) => x.name === 'www.example.com');
      assertEqual([www.verdict, www.findings.slice(-2)], ['fail', ['http01.ok:ok', 'http01.failed:error']], 'less evidence never improves the verdict');
      const families = await page.evaluate(() => [...document.querySelectorAll('.rnw-name[data-name="www.example.com"] .rnw-family')].map((f) => [f.dataset.family, f.dataset.verdict, f.querySelector('.rnw-family-head').textContent, f.querySelectorAll('.rnw-probe').length]));
      assertEqual(families.map((f) => f.slice(0, 2)), [['4', 'ok'], ['6', 'failed']], 'families');
      assert(/^IPv4 · tested /.test(families[0][2]) && families[0][3] === 3, `IPv4 line: ${families[0]}`);
      assert(/^IPv6 · tested /.test(families[1][2]) && families[1][3] === 3, `IPv6 line: ${families[1]}`);
      // Each family carries the time it was measured: IPv6's is the earlier test's.
      await page.click('[data-action="renew-json"]');
      const [file] = await takeDownloads(page);
      const tested = JSON.parse(file.text).names.find((n) => n.name === 'www.example.com').http01;
      const [v4At, v6At] = tested.families.map((f) => Date.parse(f.at));
      assert(v6At < v4At && v4At === Date.parse(tested.at), `family times: ${tested.families.map((f) => f.at)} (test ${tested.at})`);
      await phoneCheck(page, opts, 'renew-partial-mobile-light-en');
    });

    await run.step('the certificate block: the sample fills the names; its CA is not in the list', async () => {
      await gotoRoute(page, 'renew');
      await page.evaluate(() => { document.querySelector('.rnw-cert-block').open = true; });
      await page.click('.rnw-cert-block [data-action="cert-sample"]');
      await page.waitFor(() => document.querySelector('[data-role="renew-names"]').value === 'example.com\n*.example.com\nexample.net\nwww.example.net', { message: 'sample names' });
      assert(/not in the list/.test(await text(page, '.rnw-ca')), `CA hint: ${await text(page, '.rnw-ca')}`);
      assert(await page.evaluate(() => !!document.querySelector('.rnw-cert .cert-summary')), 'the certificate is shown');
      await shot(page, opts, 'renew-cert-desktop-light-en');
    });

    await run.step('links from Certificate and SSL Targets fill the names and take the CA of a newly shared certificate (over a kept report with another CA); nothing is sent', async () => {
      const box = () => page.evaluate(() => document.querySelector('[data-role="renew-names"]')?.value);
      const caNow = () => page.evaluate(() => [document.querySelector('[data-role="renew-ca"]').value, document.querySelector('.rnw-ca .field-hint')?.textContent || document.querySelector('.rnw-ca').textContent]);
      // A CA chosen by hand for the sample's names: the same certificate's link leaves it.
      await setSelect(page, '[data-role="renew-ca"]', 'letsencrypt');
      const before = await dnsCount(page);
      // The sample loaded above is the page session's certificate: the Certificate view shows it.
      await gotoRoute(page, 'cert');
      await page.waitFor(() => !!document.querySelector('.cert-actions [data-action="renew-link"]'), { message: 'Certificate link' });
      const href = await page.evaluate(() => document.querySelector('.cert-actions [data-action="renew-link"]').getAttribute('href'));
      assert(/#\/renew\?names=example\.com%2C\*\.example\.com%2Cexample\.net%2Cwww\.example\.net&run=0$/.test(href), href);
      await page.click('.cert-actions [data-action="renew-link"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'renew' && !!document.querySelector('.rnw-hero')
        && document.querySelector('[data-role="renew-names"]')?.value === 'example.com\n*.example.com\nexample.net\nwww.example.net', { message: 'names kept, report kept' });
      assertEqual((await caNow())[0], 'letsencrypt', 'the same certificate: the CA chosen since stays');
      // Another certificate, from a CA in the list (Sectigo), shared from Certificate: its link brings its names and its CA.
      await gotoRoute(page, 'cert');
      await page.evaluate(() => { const d = document.querySelector('.cert-reload'); if (d) d.open = true; });
      await page.setFileInput('.cert-reload .filedrop-input', [path.join(FIXTURES, 'real_github.pem')]);
      await page.waitFor(() => /names=github\.com%2Cwww\.github\.com&run=0$/.test(document.querySelector('.cert-actions [data-action="renew-link"]')?.getAttribute('href') || ''), { message: 'the new certificate\'s link' });
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((t) => t.remove()));
      await page.click('.cert-actions [data-action="renew-link"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'renew' && document.querySelector('[data-role="renew-names"]')?.value === 'github.com\nwww.github.com', { message: 'the new names' });
      assert(await page.evaluate(() => !!document.querySelector('.rnw-hero')), 'the kept report is still under the form');
      const [ca, hint] = await caNow();
      assertEqual(ca, 'sectigo', 'the CA of the new certificate');
      assert(hint.includes('Set from the certificate’s issuer (Sectigo Limited · Sectigo Public Server Authentication CA DV E36).'), `hint: ${hint}`);
      // SSL Targets shares the same certificate: its link changes nothing.
      await gotoRoute(page, 'scan');
      await page.waitFor(() => !!document.querySelector('.cert-summary [data-action="renew-link"]'), { message: 'SSL Targets link' });
      await page.click('.cert-summary [data-action="renew-link"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'renew' && !!document.querySelector('[data-role="renew-ca"]'), { message: 'renew from SSL Targets' });
      assertEqual([await box(), (await caNow())[0]], ['github.com\nwww.github.com', 'sectigo'], 'names and CA');
      // Other names carried in: the hint about that certificate's issuer goes (the CA stays).
      await routeTo(page, '#/renew?names=www.example.org&run=0');
      assertEqual([await box(), ...(await caNow())], ['www.example.org', 'sectigo', 'Checked against the CAA records. A certificate you load sets it from its issuer.'], 'hint dropped');
      // A draft of the user's stays, and so do the CA and challenge next to it.
      const challenge = await page.evaluate(() => document.querySelector('[data-role="renew-challenge"]').value);
      await typeNames(page, 'draft.example.com');
      await routeTo(page, '#/renew?names=www.example.net&run=0&ca=google&challenge=dns-01');
      assertEqual([await box(), (await caNow())[0], await page.evaluate(() => document.querySelector('[data-role="renew-challenge"]').value)],
        ['draft.example.com', 'sectigo', challenge], 'the draft, its CA and challenge');
      assert(challenge !== 'dns-01', `challenge before: ${challenge}`);
      assertEqual(await dnsCount(page), before, 'the links sent nothing');
    });

    await run.step('a check of more names than the cap: the box still holds what was run, so a certificate\'s link replaces it', async () => {
      const many = Array.from({ length: 55 }, (_, i) => `h${i + 1}.example.com`).join('\n');
      await typeNames(page, many);
      await page.waitFor(() => /Only the first 50 names are checked; 5 more are left out/.test(document.querySelector('.rnw-names-note')?.textContent || ''), { message: 'over the cap' });
      await page.click('[data-action="renew-run"]');
      await page.waitFor(() => document.querySelectorAll('.rnw-name').length === 50 && !document.querySelector('[data-action="renew-run"]').hidden, { message: '50 names checked', timeout: 30000 });
      await gotoRoute(page, 'cert');
      await page.waitFor(() => !!document.querySelector('.cert-actions [data-action="renew-link"]'), { message: 'Certificate link' });
      await page.click('.cert-actions [data-action="renew-link"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'renew' && document.querySelectorAll('.rnw-name').length === 50, { message: 'back with the report' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="renew-names"]').value), 'github.com\nwww.github.com', 'the certificate\'s names');
    });

    await run.step('a shared link runs on open (DNS-01: Cloudflare\'s plugins, TXT leftovers); Ctrl+Enter runs again', async () => {
      await page.evaluate(() => { location.hash = '#/renew?names=www.example.com&challenge=dns-01'; });
      await page.waitFor(() => document.querySelector('.rnw-name')?.dataset.name === 'www.example.com' && !!document.querySelector('.rnw-hero') && document.querySelector('[data-action="renew-run"]').hidden === false, { message: 'shared link ran', timeout: 20000 });
      const c = await cards(page);
      assertEqual(c.map((x) => [x.name, x.verdict]), [['www.example.com', 'ready']], 'one ready name');
      assert(c[0].findings.includes('provider.known:info') && c[0].findings.includes('acme.leftover:info') && !c[0].findings.some((f) => f.startsWith('http.')), `${c[0].findings}`);
      assert(/lego --dns cloudflare · acme\.sh --dns dns_cf · certbot-dns-cloudflare/.test(await text(page, '.rnw-name [data-id="provider.known"]')), 'plugins');
      assert(!await page.evaluate(() => !!document.querySelector('.rnw-test-card')), 'no HTTP-01 test for DNS-01');
      const before = await dnsCount(page);
      await page.evaluate(() => document.querySelector('[data-role="renew-names"]').focus());
      await page.press('Enter', { ctrl: true });
      await page.waitFor((n) => window.__fakeDnsLog.length > n, { args: [before], message: 'Ctrl+Enter ran the check' });
      await waitDone(page, 'second check');
    });

    await run.step('the AAAA lookup gets no answer (SERVFAIL everywhere): IPv6 not checked, so the name could not be checked — never ready', async () => {
      await page.evaluate(() => { window.__dnsRcodeFor = { 'www.example.com|AAAA': 'SERVFAIL' }; });
      await routeTo(page, '#/renew?names=www.example.com&ca=letsencrypt&challenge=http-01');
      await page.waitFor(() => document.querySelector('.rnw-name')?.dataset.name === 'www.example.com' && !!document.querySelector('.rnw-hero')
        && !document.querySelector('[data-action="renew-run"]').hidden, { message: 'checked', timeout: 20000 });
      await page.evaluate(() => { window.__dnsRcodeFor = {}; });
      const [c] = await cards(page);
      assertEqual(c.verdict, 'unknown', 'could not be checked');
      assert(c.findings.includes('http.family-error:warn') && c.findings.includes('http.ok-partial:ok'), `${c.findings}`);
      assert(!c.findings.includes('http.ok:ok') && !c.findings.some((f) => f.startsWith('http.ipv6') || f.startsWith('http.none')), `${c.findings}`);
      const words = await text(page, '.rnw-name [data-id="http.ok-partial"]');
      assert(/1 IPv4; the IPv6 lookup got no answer/.test(words) && !/0 IPv6/.test(words), words);
      assert(/The IPv6 addresses of www\.example\.com could not be read/.test(await text(page, '.rnw-name [data-id="http.family-error"]')), 'the family named');
    });

    run.group('Phone 320 / 375 px, Turkish / English, light / dark');
    await run.step('the form and the results fit a phone: no horizontal scroll', async () => {
      await page.evaluate(() => { location.hash = '#/renew?names=www.example.com,*.example.com,api.example.com,shop.example.com&ca=letsencrypt&challenge=unknown'; });
      await page.waitFor(() => document.querySelectorAll('.rnw-name').length === 4 && !document.querySelector('[data-action="renew-run"]').hidden, { message: 'phone check', timeout: 20000 });
      for (const width of [320, 375]) {
        await page.setViewport({ width, height: 700, mobile: true });
        await page.evaluate(() => document.querySelectorAll('.rnw-name').forEach((d) => { d.open = true; }));
        for (const lang of ['en', 'tr']) {
          await setLangUi(page, lang);
          await page.waitFor(() => document.querySelectorAll('.rnw-name').length === 4, { message: 'report kept' });
          await page.evaluate(() => document.querySelectorAll('.rnw-name').forEach((d) => { d.open = true; }));
          for (const scheme of ['light', 'dark']) {
            await page.emulateMedia({ 'prefers-color-scheme': scheme });
            await page.evaluate(() => window.scrollTo(0, 0));
            await assertNoHorizontalScroll(page, `renew ${width} ${scheme} ${lang}`);
            if (width === 375) await shot(page, opts, `renew-results-mobile-${scheme}-${lang}`);
          }
        }
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.setViewport({ width: 1440, height: 900 });
      await shot(page, opts, 'renew-results-desktop-dark-tr');
      await setLangUi(page, 'en');
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, opts, 'renew-results-desktop-dark-en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    // Last of the checks: the rate-limited resolvers stay in the DoH client's circuit breaker for a while.
    run.group('No resolver answers');
    await run.step('every DoH request answered 429: each name could not be checked, never "ready" or "with warnings"', async () => {
      await page.evaluate(() => { window.__dnsStatus = 429; location.hash = '#/renew?names=www.example.com,api.example.com&ca=letsencrypt&challenge=http-01'; });
      await page.waitFor(() => document.querySelector('.rnw-hero')?.dataset.headline === 'incomplete' && !document.querySelector('[data-action="renew-run"]').hidden,
        { message: 'check done', timeout: 30000 });
      await page.evaluate(() => { window.__dnsStatus = 0; });
      assertEqual(await text(page, '.rnw-hero .alert'), 'At least one name could not be checked — check again', 'headline');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rnw-counts [data-count]')].map((b) => b.textContent)), ['2 could not be checked'], 'counts');
      const c = await cards(page);
      assertEqual(c.map((x) => [x.name, x.verdict, x.open]), [['www.example.com', 'unknown', true], ['api.example.com', 'unknown', true]], 'verdicts');
      for (const x of c) {
        assert(x.findings.includes('caa.error:warn') && x.findings.includes('http.error:warn') && !x.findings.some((f) => f.endsWith(':ok')), `${x.name}: ${x.findings}`);
      }
      assertEqual(await text(page, '.rnw-name[data-name="www.example.com"] .rnw-verdict'), 'Could not be checked', 'badge');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await phoneCheck(page, opts, 'renew-unknown-mobile-dark-en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    run.group('Plan panel: lifetimes, renewal window, coverage and CSR');
    const planText = (sel) => page.evaluate((s) => document.querySelector(s)?.textContent || '', sel);
    const openPlan = async () => {
      if (!(await page.evaluate(() => document.querySelector('.rnw-plan').open))) await page.click('.rnw-plan > summary');
      await page.waitFor(() => !!document.querySelector('.rpl-panel .rpl-sched-table'), { message: 'planner loaded' });
    };
    await run.step('the panel loads on its first open: the SC-081 schedule with the step in force marked, nothing sent', async () => {
      await gotoRoute(page, 'renew');
      assert(await page.evaluate(() => !document.querySelector('.rnw-plan').open && !document.querySelector('.rpl-panel')), 'closed and not loaded');
      await openPlan();
      const rows = await page.evaluate(() => [...document.querySelectorAll('.rpl-sched-table tbody tr')].map((tr) => [tr.dataset.step, ...[...tr.children].slice(1).map((c) => c.textContent)]));
      assertEqual(rows, [['before', '398 days', '398 days'], ['2026', '200 days', '200 days'], ['2027', '100 days', '100 days'], ['2029', '47 days', '10 days']], 'schedule');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpl-sched-table tr.rpl-now')].map((tr) => tr.dataset.step)), [scheduleStep(Date.now()).id], 'in force');
      assertEqual(await page.evaluate(() => window.__ari.calls.length), 0, 'nothing asked');
    });

    await run.step('the sample: a lifetime over the limit it was issued under, two thirds of it as the window, no renewal before 2030, no ARI for its CA', async () => {
      await page.evaluate(() => { document.querySelector('.rnw-cert-block').open = true; });
      if (await page.evaluate(() => !!document.querySelector('[data-action="renew-cert-remove"]'))) await page.click('[data-action="renew-cert-remove"]');
      await page.click('.rnw-cert-block [data-action="cert-sample"]');
      await page.waitFor(() => document.querySelector('.rpl-state')?.dataset.source === 'two-thirds', { message: 'the sample planned' });
      const life = validityDays(Date.parse('2026-01-01T00:00:00Z'), Date.parse('2036-01-01T00:00:00Z'));
      const kv = await planText('.rpl-kv');
      assert(kv.includes(`${life.toLocaleString('en-US')} days · the limit when it was issued: 398 days`), kv);
      assert(/no publicly trusted CA can have issued it/.test(await planText('.rpl-cert')), 'over the limit');
      assertEqual(await page.evaluate(() => document.querySelector('.rpl-ari [data-ari]')?.dataset.ari), 'other-ca', 'no ARI for a CA not in the list');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.rpl-next-table tbody tr').length), 6, 'six renewals');
      const y0 = new Date().getUTCFullYear();
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpl-years li')].map((li) => [li.dataset.year, li.dataset.count])),
        Array.from({ length: Math.max(0, 2030 - y0 + 1) }, (_, i) => [String(y0 + i), '0']), 'its window opens in 2032');
      assertEqual(await page.evaluate(() => window.__ari.calls.length), 0, 'nothing asked');
    });

    await run.step('Let’s Encrypt chosen: nothing sent before the click, then exactly its directory and the renewal-info of the CertID; the CA’s window, the focus kept', async () => {
      await setSelect(page, '[data-role="renew-ca"]', 'letsencrypt');
      await page.waitFor(() => !!document.querySelector('[data-action="rpl-ari"]'), { message: 'ARI offered' });
      assert(/the issuer’s key identifier and the serial number.*to acme-v02\.api\.letsencrypt\.org/.test(await planText('.rpl-ari-privacy')), await planText('.rpl-ari-privacy'));
      assertEqual(await page.evaluate(() => window.__ari.calls.length), 0, 'nothing before the click');
      await page.evaluate(() => document.querySelector('[data-action="rpl-ari"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.rpl-state')?.dataset.source === 'ari', { message: 'the ARI window' });
      const id = ariCertId({ authorityKeyId: '2d2bb41d2dd7a9408aec1a96c08b5ae58ac75864', serialHex: '577145a5506a7e185071af8b53bbee63' });
      assertEqual(await page.evaluate(() => window.__ari.calls), ['/directory', `/acme/renewal-info/${id}`], 'the two requests');
      assert(/suggested by Let['’]s Encrypt \(asked /.test(await planText('[data-role="rpl-window"]')), await planText('[data-role="rpl-window"]'));
      assert(/asks to be asked again after/.test(await planText('.rpl-ari')), 'Retry-After');
      assertEqual(await focusedAction(page), 'rpl-ari', 'the focus stays on the button');
      assertEqual(external, [], 'nothing left the page');
    });

    await run.step('ARI answers 404: n/a and why, two thirds of the lifetime again; Retry asks ARI again', async () => {
      await page.evaluate(() => { window.__ari.status = 404; window.__ari.calls = []; });
      await page.click('[data-action="rpl-ari"]');
      await page.waitFor(() => !!document.querySelector('.rpl-ari-failed[data-ari="not-found"]'), { message: 'the 404' });
      assert(await page.evaluate(() => !!document.querySelector('.rpl-ari-failed .na-mark')), 'n/a mark');
      assert(/Let['’]s Encrypt does not know this certificate \(HTTP 404\)/.test(await planText('.rpl-ari-failed')), await planText('.rpl-ari-failed'));
      assertEqual(await page.evaluate(() => document.querySelector('.rpl-state').dataset.source), 'two-thirds', 'the window falls back');
      assertEqual(await focusedAction(page), 'retry-source', 'the focus on Retry');
      await page.evaluate(() => { window.__ari.status = 200; window.__ari.calls = []; });
      await page.click('.rpl-ari [data-action="retry-source"]');
      await page.waitFor(() => document.querySelector('.rpl-state')?.dataset.source === 'ari', { message: 'retried' });
      assertEqual(await page.evaluate(() => window.__ari.calls.length), 2, 'asked again');
    });

    await run.step('the coverage planner: the groupings, what a wildcard leaves uncovered, one certificate per environment, the CSR files per key type', async () => {
      await page.evaluate((v) => {
        const ta = document.querySelector('[data-role="rpl-names"]');
        ta.value = v;
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      }, 'example.com www.example.com api.example.com shop.example.com dev.example.com api.dev.example.com web.dev.example.com staging.example.com a.b.example.com example.net 192.0.2.1');
      await page.waitFor(() => document.querySelectorAll('.rpl-tabs [role="tab"]').length === 3 && !!document.querySelector('.rpl-invalid'), { message: 'groupings' });
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpl-tabs [role="tab"]')].map((b) => [b.querySelector('.tab-label').textContent, b.querySelector('.tab-badge').textContent])),
        [['One SAN list', '1'], ['Wildcards', '2'], ['Per environment', '3']], 'tabs');
      assert(/left out: 192\.0\.2\.1/.test(await planText('.rpl-invalid')), 'the address left out');
      await page.evaluate(() => document.querySelectorAll('.rpl-tabs [role="tab"]')[1].click());
      await page.waitFor(() => !!document.querySelector('.rpl-g[data-grouping="wildcard"]') && !document.querySelector('.rpl-g[data-grouping="wildcard"]').closest('[hidden]'), { message: 'wildcards' });
      const W = '.rpl-g[data-grouping="wildcard"]';
      assertEqual(await page.evaluate((w) => [...document.querySelectorAll(`${w} .rpl-unc-list li`)].map((li) => [li.dataset.name, li.dataset.reason]), W),
        [['example.com', 'apex'], ['a.b.example.com', 'deeper']], 'uncovered');
      assertEqual(await page.evaluate((w) => [...document.querySelectorAll(`${w} .rpl-c`)].map((c) => c.dataset.names), W),
        ['example.com *.example.com *.dev.example.com a.b.example.com', 'example.net'], 'certificates');
      const conf = await planText(`${W} [data-role="rpl-openssl"] code`);
      assert(conf.includes('DNS.2 = *.example.com') && conf.includes('CN = example.com') && !/PRIVATE KEY/.test(conf), conf);
      assertEqual(await planText(`${W} [data-role="rpl-openssl-cmd"] code`), 'openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout example.com.key -out example.com.csr -config example.com.cnf', 'command');
      await setSelect(page, '[data-role="rpl-keytype"]', 'rsa-2048');
      await page.waitFor((w) => /-newkey rsa:2048 /.test(document.querySelector(`${w} [data-role="rpl-openssl-cmd"] code`)?.textContent || ''), { args: [W], message: 'RSA' });
      assert((await planText(`${W} [data-role="rpl-certreq"] code`)).includes('KeyLength = 2048'), 'certreq RSA');
      await page.click(`${W} [data-action="rpl-download"][data-file="example.com.inf"]`);
      const [dl] = await takeDownloads(page);
      assert(dl && dl.name === 'example.com.inf' && dl.text.includes('_continue_ = "dns=*.dev.example.com&"\r\n'), `download: ${dl && dl.name}`);
      await page.evaluate(() => document.querySelectorAll('.rpl-tabs [role="tab"]')[2].click());
      await page.waitFor(() => !!document.querySelector('.rpl-g[data-grouping="environment"]'), { message: 'environments' });
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpl-g[data-grouping="environment"] .rpl-c')].map((c) => c.dataset.env)), ['prod', 'staging', 'dev'], 'one per environment');
      assert(await page.evaluate(() => !!document.querySelector('.rpl-g[data-grouping="environment"] [data-note="no-prod-wildcard"]')), 'no production wildcard');
      await page.click('[data-action="rpl-from-form"]');
      await page.waitFor(() => document.querySelectorAll('.rpl-tabs [role="tab"]').length === 2, { message: 'the form’s names' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="rpl-names"]').value), 'example.com\n*.example.com\nexample.net\nwww.example.net', 'the names above');
      assertEqual(await page.evaluate(() => window.__ari.calls.length), 2, 'the planner sends nothing');
      assertEqual(external, [], 'nothing left the page');
    });

    await run.step('the panel fits 320 / 375 px phones, light and dark, in English and Turkish', async () => {
      for (const lang of ['en', 'tr']) {
        if (lang === 'tr') {
          await setLangUi(page, 'tr');
          await page.waitFor(() => !!document.querySelector('.rnw-plan'), { message: 'view again' });
          await openPlan();
          await page.waitFor(() => !!document.querySelector('.rpl-state'), { message: 'the certificate kept' });
        }
        for (const width of [320, 375]) {
          await page.setViewport({ width, height: 700, mobile: true });
          for (const scheme of ['light', 'dark']) {
            await page.emulateMedia({ 'prefers-color-scheme': scheme });
            await assertNoHorizontalScroll(page, `plan ${width} ${scheme} ${lang}`);
          }
          if (width === 375) {
            await page.evaluate(() => document.querySelector('.rnw-plan').scrollIntoView({ block: 'start' }));
            await shot(page, opts, `renew-plan-mobile-dark-${lang}`);
          }
        }
        await page.setViewport({ width: 1440, height: 900 });
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'renew', origin));
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
