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
 * names that are not host names, a check of four names against Let's Encrypt with HTTP-01 (a
 * wildcard CAA forbids and HTTP-01 cannot validate, a private address, a lagging resolver on a
 * CNAME'd name, a ready name with IPv6), the per-name cards (worst first, findings by area, the
 * resolvers' answers), the URL, Copy summary, the CSV / JSON exports, the HTTP-01 reachability test
 * (nothing sent before the click; the consent + cost dialog, Cancel sends nothing; exactly the
 * lib/renewal.js requests, IPv4 and IPv6; an IPv6 address that times out fails the name; a
 * redirect to HTTPS keeping the token passes), the language switch keeping report and test, the
 * certificate block (the sample: its names, a CA not in the list), the links from Certificate and
 * SSL Targets (names filled in, the CA from the shared certificate, nothing sent), a shared link
 * that runs on open (DNS-01: the Cloudflare plugins, TXT leftovers), Ctrl+Enter, 320 / 375 px
 * phones light / dark in both languages without horizontal scroll, zero console errors / CSP
 * violations / missing i18n keys, nothing sent outside the page.
 *
 * Data is documentation space only (example.com / .net, 192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24, 2001:db8::/32, 10.0.0.0/8) plus provider name servers (ns.cloudflare.com, natrohost.com).
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, sleep, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';

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
const GP_SCENARIOS = { 'www.example.com|4': 'not-found', 'www.example.com|6': 'timeout', 'shop.example.com|4': 'redirect' };
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
  const gp = window.__gp = { calls: [], n: 0, remaining: 250, measurements: {}, delayMs: 0 };
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
        return { status: 'finished', resolvedAddress: address, statusCode: 404, headers: {}, tls: null };
      };
      return json({ ...base, status: 'finished', results: PROBES.map((probe) => ({ probe, result: result() })) });
    }
    return json({ error: { type: 'not_found', message: 'Not Found.' } }, 404);
  }
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://api.globalping.io/')) return globalping(url, init);
    if (url.startsWith('https://data.iana.org/rdap/')) return json({ services: [] });
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    const resolver = HOSTS[new URL(url).hostname] || new URL(url).hostname;
    window.__fakeDnsLog.push({ name, type: q.type, resolver });
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
      assertEqual(nav, ['scan', 'cert', 'renew'], 'Certificates group');
      assertEqual(await text(page, 'h1'), 'Renewal readiness', 'title');
      assert(await page.evaluate(() => !!document.querySelector('.rnw-empty .empty')), 'empty state');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="renew-ca"]').value, document.querySelector('[data-role="renew-challenge"]').value]), ['', 'unknown'], 'defaults');
      assertEqual(await dnsCount(page), 0, 'no DNS query');
      await shot(page, opts, 'renew-empty-desktop-light-en');
    });

    await run.step('names that are not host names are left out and said; an empty box asks for a name', async () => {
      await typeNames(page, 'www.example.com 192.0.2.1 _acme-challenge.example.com');
      await page.waitFor(() => /Not host names, left out: 192\.0\.2\.1, _acme-challenge\.example\.com/.test(document.querySelector('.rnw-names-note')?.textContent || ''), { message: 'invalid note' });
      await typeNames(page, '');
      await page.click('[data-action="renew-run"]');
      await page.waitFor(() => /at least one host name/.test(document.querySelector('.rnw-form-card')?.textContent || ''), { message: 'no names' });
      assertEqual(await dnsCount(page), 0, 'nothing sent');
    });

    await run.step('four names against Let\'s Encrypt with HTTP-01: worst first, findings by area, the URL', async () => {
      await typeNames(page, 'www.example.com\n*.example.com\napi.example.com\nshop.example.com');
      await setSelect(page, '[data-role="renew-ca"]', 'letsencrypt');
      await setSelect(page, '[data-role="renew-challenge"]', 'http-01');
      await page.click('[data-action="renew-run"]');
      await waitDone(page);
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

    await run.step('HTTP-01 test: consent dialog (Cancel sends nothing), then IPv4 + IPv6 from three continents', async () => {
      assertEqual(await page.evaluate(() => document.querySelector('[data-action="renew-http01"]').textContent), 'Test 2 names (9 probes)', 'batch button');
      await page.click('[data-action="renew-http01"]');
      await page.waitFor(() => !!document.querySelector('.gp-confirm'), { message: 'dialog' });
      const dialog = await text(page, '.gp-confirm');
      assert(/www\.example\.com, shop\.example\.com/.test(dialog) && /\/\.well-known\/acme-challenge\//.test(dialog) && /Cost: 9 probes of the 250 left/.test(dialog), dialog);
      await page.press('Escape');
      await page.waitFor(() => !document.querySelector('.gp-confirm'), { message: 'closed' });
      assertEqual(await gpCalls(page), ['GET /limits'], 'only the free quota read');
      await page.click('[data-action="renew-http01"]');
      await page.waitFor(() => !!document.querySelector('.gp-confirm'), { message: 'dialog again' });
      await page.click('.gp-confirm .btn-primary');
      await waitTestDone(page);
      assertEqual(await page.evaluate(() => document.querySelector('.rnw-test').dataset.state), 'done', 'test done');
      const posts = await page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST').map((c) => c.body));
      assertEqual(posts.map((b) => [b.target, b.measurementOptions.ipVersion || 4, b.measurementOptions.protocol, b.measurementOptions.port, b.locations.map((l) => l.continent).join('')]),
        [['www.example.com', 4, 'HTTP', 80, 'EUNAAS'], ['www.example.com', 6, 'HTTP', 80, 'EUNAAS'], ['shop.example.com', 4, 'HTTP', 80, 'EUNAAS']], 'requests');
      assert(posts.every((b) => /^\/\.well-known\/acme-challenge\/domainscope-check-[a-z0-9]{16}$/.test(b.measurementOptions.request.path)), 'made-up token');
      assertEqual(posts[0].measurementOptions.request.path, posts[1].measurementOptions.request.path, 'one token per name');
      const c = await cards(page);
      const www = c.find((x) => x.name === 'www.example.com');
      assertEqual([www.verdict, www.findings.slice(-2)], ['fail', ['http01.ok:ok', 'http01.failed:error']], 'IPv6 times out');
      assert(c.find((x) => x.name === 'shop.example.com').findings.includes('http01.redirect:ok'), 'a redirect to HTTPS keeping the token passes');
      assertEqual(c.map((x) => x.name), ['www.example.com', '*.example.com', 'api.example.com', 'shop.example.com'], 'worst first, then as entered');
      const probes = await page.evaluate(() => [...document.querySelectorAll('.rnw-name[data-name="www.example.com"] .rnw-family')].map((f) => `${f.dataset.family}:${f.dataset.verdict}:${[...f.querySelectorAll('.rnw-probe')].map((p) => p.dataset.outcome).join(',')}`));
      assertEqual(probes, ['4:ok:not-found,not-found,not-found', '6:failed:timeout,timeout,timeout'], 'probe lines');
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

    await run.step('the certificate block: the sample fills the names; its CA is not in the list', async () => {
      await gotoRoute(page, 'renew');
      await page.evaluate(() => { document.querySelector('.rnw-cert-block').open = true; });
      await page.click('.rnw-cert-block [data-action="cert-sample"]');
      await page.waitFor(() => document.querySelector('[data-role="renew-names"]').value === 'example.com\n*.example.com\nexample.net\nwww.example.net', { message: 'sample names' });
      assert(/not in the list/.test(await text(page, '.rnw-ca')), `CA hint: ${await text(page, '.rnw-ca')}`);
      assert(await page.evaluate(() => !!document.querySelector('.rnw-cert .cert-summary')), 'the certificate is shown');
      await shot(page, opts, 'renew-cert-desktop-light-en');
    });

    await run.step('links from Certificate and SSL Targets fill the names; the CA comes from the shared certificate; nothing is sent', async () => {
      // The sample loaded above is the page session's certificate: the Certificate view shows it.
      await gotoRoute(page, 'cert');
      await page.waitFor(() => !!document.querySelector('.cert-actions [data-action="renew-link"]'), { message: 'Certificate link' });
      const before = await dnsCount(page);
      const href = await page.evaluate(() => document.querySelector('.cert-actions [data-action="renew-link"]').getAttribute('href'));
      assert(/#\/renew\?names=example\.com%2C\*\.example\.com%2Cexample\.net%2Cwww\.example\.net&run=0$/.test(href), href);
      await page.click('.cert-actions [data-action="renew-link"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'renew'
        && document.querySelector('[data-role="renew-names"]')?.value === 'example.com\n*.example.com\nexample.net\nwww.example.net', { message: 'names filled' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="renew-ca"]').value), '', 'a CA outside the list is not chosen');
      assert(/not in the list/.test(await text(page, '.rnw-ca')), 'the hint says why');
      await gotoRoute(page, 'scan');
      await page.waitFor(() => !!document.querySelector('.cert-summary [data-action="renew-link"]'), { message: 'SSL Targets link' });
      await page.click('.cert-summary [data-action="renew-link"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'renew', { message: 'renew from SSL Targets' });
      await sleep(200);
      assertEqual(await dnsCount(page), before, 'the links sent nothing');
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
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
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
