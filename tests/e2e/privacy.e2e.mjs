#!/usr/bin/env node
/**
 * privacy.e2e.mjs — end-to-end test of what the page tells about its own traffic, in a real
 * headless Chrome/Edge. OFFLINE: every DoH query, Cert Spotter and crt.sh request is answered in
 * the page by a fake built before the app loads (window.fetch wrapped, as the other offline suites
 * do); every other https:// request that leaves the page is failed through CDP, except two the
 * test sends itself past the app (a crt.sh search and an unknown tracker host), which CDP answers
 * so the browser's Resource Timing reports them.
 *
 *   node tests/e2e/privacy.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers:
 *   - About › What this page sent: the footer link (`section=sent`: the section scrolled to, its
 *     title focused, the param dropped), the page's own files counted from Resource Timing, a
 *     request the app's fetch never saw still counted (Resource Timing), a host the registry does
 *     not know listed first with a warning, a fetch without an answer, the live refresh, the
 *     footer's count, Clear, the "never sent" list and the development copy's version line;
 *   - Subdomains › Sources › Related domains: a scan of example.com whose Cert Spotter and crt.sh
 *     answers name example.net (two certificates), example.org (a crt.sh common name only: the
 *     partial-names note) and thirteen customer domains of one shared certificate (folded, no
 *     scan button); opening the card sends nothing; "Scan too" scans example.com and example.net
 *     together; the ledger then names every host the scans contacted, none unknown;
 *   - Certificate › CT logs › Key continuity: the sample certificate's public-key SHA-256 computed
 *     in the page (compared with Node's), nothing sent before the click, then exactly one crt.sh
 *     search by that hash, "Key reused across renewals" with the TLSA / pinning consequences, and
 *     the button that opens the DANE / TLSA tab; the ledger names it "A public-key SHA-256";
 *   - the Pages bundle (tools/assemble-site.mjs into a temporary folder): the ledger names the
 *     deploy and links its commit from version.json;
 *   - 375 px (and 320 px for the ledger) without horizontal scroll, TR / EN × light / dark; zero
 *     console errors, exceptions and CSP violations; no missing i18n keys; nothing reached the network.
 *
 * Data is documentation space only (example.com / .net / .org, the reserved .example TLD,
 * 203.0.113.0/24).
 */

import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, ROOT, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, setLangUi, shot, waitReady
} from './scan.e2e.mjs';
import { SOURCES } from '../../assets/js/lib/sourceinfo.js';
import { assembleSite } from '../../tools/assemble-site.mjs';
import { REPO_URL } from '../../assets/js/app.js';

const DAY = 86400000;
const NOW = Date.now();
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const crtshDate = (ms) => new Date(ms).toISOString().slice(0, 19);

/** The live DNS of the scanned domains (NXDOMAIN outside). */
const ZONE = {
  'example.com': { A: ['203.0.113.10'] },
  'www.example.com': { A: ['203.0.113.10'] },
  'shop.example.com': { A: ['203.0.113.12'] },
  'api.example.com': { A: ['203.0.113.13'] },
  'example.net': { A: ['203.0.113.20'] },
  'shop.example.net': { A: ['203.0.113.21'] }
};
/** Thirteen customers of one shared (CDN) certificate: more registrable domains than a brand certificate holds. */
const CROWD = Array.from({ length: 13 }, (_, i) => `customer${i + 1}.example`);
const issuance = (id, names, from, to) => ({
  id: String(id), tbs_sha256: String(id).repeat(64).slice(0, 64), cert_sha256: `${id}`.padStart(64, 'c'), pubkey_sha256: 'dd'.repeat(32),
  dns_names: names, not_before: iso(from), not_after: iso(to), revoked: false,
  issuer: { name: "C=US, O=Let's Encrypt, CN=R11", friendly_name: "Let's Encrypt" }
});
/** Cert Spotter's issuances of example.com (every name of each certificate). */
const SPOTTER = [
  issuance(101, ['example.com', 'www.example.com', 'example.net', 'shop.example.net'], NOW - 20 * DAY, NOW + 70 * DAY),
  issuance(102, ['api.example.com', 'api.example.net'], NOW - 200 * DAY, NOW - 110 * DAY),
  issuance(103, ['cdn.example.com', ...CROWD], NOW - 10 * DAY, NOW + 80 * DAY)
];
/** crt.sh's rows for %.example.com: only the matching name, and the common name under example.org. */
const CRTSH = [{
  issuer_ca_id: 7, issuer_name: 'C=US, O=Example CA, CN=Example R1', common_name: '*.example.org', name_value: 'shop.example.com',
  id: 9001, not_before: crtshDate(NOW - 5 * DAY), not_after: crtshDate(NOW + 85 * DAY), serial_number: '0a0b0c', result_count: 1
}];

/** The sample certificate (assets/data/sample-cert.pem): its serial, issuer and public key hash as Node reads them. */
const SAMPLE = new X509Certificate(await readFile(path.join(ROOT, 'assets', 'data', 'sample-cert.pem')));
const SAMPLE_SPKI = createHash('sha256').update(SAMPLE.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
const SAMPLE_ISSUER = 'C=XX, O=DomainScope Sample, CN=DomainScope Sample Intermediate CA';
/** crt.sh's answer for the sample's key: the sample (precertificate + certificate) and last year's renewal with the same key. */
const KEY_ROWS = [
  { issuer_ca_id: 5, issuer_name: SAMPLE_ISSUER, name_value: SAMPLE_SPKI, id: 8002, not_before: '2026-01-01T00:00:00', not_after: '2036-01-01T00:00:00', serial_number: SAMPLE.serialNumber.toLowerCase(), result_count: 0 },
  { issuer_ca_id: 5, issuer_name: SAMPLE_ISSUER, name_value: SAMPLE_SPKI, id: 8001, not_before: '2026-01-01T00:00:00', not_after: '2036-01-01T00:00:00', serial_number: SAMPLE.serialNumber.toLowerCase(), result_count: 0 },
  { issuer_ca_id: 5, issuer_name: SAMPLE_ISSUER, name_value: SAMPLE_SPKI, id: 7001, not_before: '2025-01-01T00:00:00', not_after: '2025-12-31T00:00:00', serial_number: '0102', result_count: 0 }
];

/** Requests the test sends past the app, answered by CDP so Resource Timing reports them. */
const WITNESS = ['https://crt.sh/?q=rt-witness.example.com&output=json', 'https://tracker.example.net/collect?id=1'];

/** In-page fakes: DoH from ZONE, Cert Spotter, crt.sh (search and key search); anything else is refused. */
const fakeScript = () => `(() => {
  const ZONE = ${JSON.stringify(ZONE)};
  const SPOTTER = ${JSON.stringify(SPOTTER)};
  const CRTSH = ${JSON.stringify(CRTSH)};
  const KEY_ROWS = ${JSON.stringify(KEY_ROWS)};
  const SOA = { mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
  window.__realFetch = window.fetch.bind(window);
  window.__fake = { ct: [], key: [], blocked: [], dns: 0 };
  let wire = null;
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
  const apexOf = (name) => ['example.com', 'example.net'].find((a) => name === a || name.endsWith('.' + a)) || null;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (new URL(url, location.href).origin === location.origin) return window.__realFetch(input, init);
    if (url.startsWith('https://api.certspotter.com/')) {
      window.__fake.ct.push(url);
      return json(/[?&]after=/.test(url) || !/domain=example\\.com&/.test(url) ? [] : SPOTTER);
    }
    if (url.startsWith('https://crt.sh/')) {
      if (url.includes('spkisha256=')) {
        window.__fake.key.push(url);
        return json(KEY_ROWS);
      }
      window.__fake.ct.push(url);
      return json(/example\\.com/.test(decodeURIComponent(url)) ? CRTSH : []);
    }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      window.__fake.blocked.push(url);
      throw new TypeError('blocked by the E2E');
    }
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__fake.dns += 1;
    const apex = apexOf(name);
    const node = ZONE[name];
    const answers = node ? (node[q.type] || []).map((data) => ({ name, type: q.type, ttl: 300, data })) : [];
    const exists = !!node || Object.keys(ZONE).some((k) => k.endsWith('.' + name));
    const rcode = apex && exists ? 'NOERROR' : 'NXDOMAIN';
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode, questions: [{ name: q.name, type: q.type }], answers,
      authorities: answers.length ? [] : [{ name: apex || 'example.com', type: 'SOA', ttl: 300, data: SOA }], edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/** The Subdomains options for these scans: Certificate Transparency only, no wordlist, no permutations. */
const OPTIONS_SCRIPT = `(() => {
  try {
    localStorage.setItem('ssds.subdomains.options', JSON.stringify({
      sources: ['crtsh', 'certspotter'], knownSources: ${JSON.stringify(SOURCES.map((s) => s.id))},
      bruteforce: 'off', permutations: false, originHints: false, includeExpired: false, learned: false
    }));
  } catch (e) { /* storage blocked: the defaults run */ }
})();`;

/**
 * Answer the witness requests through CDP (with CORS, so the page can read them) and fail every
 * other https request that reaches the network; returns the failed ones.
 */
async function networkGate(page) {
  const leaks = [];
  page.conn.on('Fetch.requestPaused', (p) => {
    const url = p.request.url;
    if (WITNESS.includes(url)) {
      page.send('Fetch.fulfillRequest', {
        requestId: p.requestId,
        responseCode: 200,
        responseHeaders: [{ name: 'access-control-allow-origin', value: '*' }, { name: 'content-type', value: 'application/json' }],
        body: Buffer.from('[]').toString('base64')
      }).catch(() => {});
      return;
    }
    leaks.push(url);
    page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://*' }] });
  return leaks;
}

/* ------------------------------------------------------------------------ */
/* Page helpers                                                             */
/* ------------------------------------------------------------------------ */

/** The ledger as shown: one entry per row. */
const ledger = (page) => page.evaluate(() => [...document.querySelectorAll('.egress-table tbody tr.dt-row')].map((tr) => ({
  kind: ['self', 'service', 'unknown'].find((k) => tr.classList.contains(`egress-row-${k}`)),
  name: tr.querySelector('.egress-name')?.textContent.replace(/\s+/g, ' ').trim(),
  host: tr.querySelector('.egress-host')?.textContent || null,
  requests: Number(tr.querySelector('.egress-count .num')?.textContent.replace(/\D/g, '') || 0),
  failed: tr.querySelector('.egress-failed')?.textContent || null,
  kinds: [...tr.querySelectorAll('.egress-kinds li')].map((li) => li.dataset.kind)
})));
/** The page's request log as the meter keeps it (the same module instance the app uses). */
const logEntries = (page) => page.evaluate(() => import('./assets/js/ui/egress-meter.js').then((m) => m.egressLog.snapshot().entries));
const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);
const waitRun = (page, message) => page.waitFor(() => {
  const p = document.querySelector('.sub-run-ui .sub-run');
  return !!p && p.dataset.status === 'done';
}, { timeout: 30000, message });

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}\n`);
  let bundleDir = null;
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    const leaks = await networkGate(page);
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript() });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: OPTIONS_SCRIPT });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('About › What this page sent (desktop, English)');
    await run.step('the footer link opens the section, focuses its title and drops the param; the app\'s own files are counted', async () => {
      await page.goto(`${server.url}#/about?section=sent`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') {
        await setLangUi(page, 'en');
        await gotoRoute(page, '#/about?section=sent');
      }
      await page.waitFor(() => document.activeElement?.closest('#about-sent') && location.hash === '#/about', { message: 'section focused, param dropped' });
      assertEqual(await text(page, '#about-sent .section-title'), 'What this page sent', 'title');
      const top = await page.evaluate(() => document.querySelector('#about-sent').getBoundingClientRect().top);
      assert(top >= 0 && top < 200, `section in view (top ${top})`);
      await page.waitFor(() => document.querySelector('.egress-row-self'), { message: 'this site row' });
      const rows = await ledger(page);
      assertEqual(rows.map((r) => r.kind), ['self'], 'only the page\'s own files so far');
      assert(rows[0].requests >= 10, `module files counted from Resource Timing: ${rows[0].requests}`);
      assertEqual(rows[0].kinds, ['appFiles'], 'nothing of the user\'s');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="egress-summary"]').dataset.requests), '0', 'no third party');
      assert(/nothing to a third party/.test(await text(page, '[data-role="egress-summary"]')), 'summary');
      const footer = await page.evaluate(() => ({
        href: document.querySelector('[data-control="sent"]').getAttribute('href'),
        count: document.querySelector('.footer-sent-count').dataset.count,
        text: document.querySelector('[data-control="sent"]').textContent
      }));
      assertEqual([footer.href, footer.count], ['#/about?section=sent', '0'], 'footer link');
      assert(/What this page sent · nothing to third parties yet/.test(footer.text), footer.text);
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.egress-never li')].map((li) => li.dataset.never)),
        ['certificates', 'keys', 'zone', 'inventory', 'workspace', 'tracking'], 'never sent');
      assert(/^Development copy/.test(await text(page, '[data-role="egress-version"]')), 'the repository has no deploy version');
    });

    await run.step('a request the app\'s fetch never saw is still counted (Resource Timing); an unknown host comes first, flagged', async () => {
      await page.evaluate((urls) => Promise.all(urls.map((u) => window.__realFetch(u).then((r) => r.text()))), WITNESS);
      await page.waitFor(() => document.querySelectorAll('.egress-table tbody tr.dt-row').length === 3, { message: 'live refresh' });
      const rows = await ledger(page);
      assertEqual(rows.map((r) => [r.kind, r.name, r.requests]), [
        ['unknown', 'tracker.example.net Not in the registry', 1], ['service', 'crt.sh', 1], ['self', 'This site', rows[2].requests]
      ], 'rows');
      assertEqual(rows[1].kinds, ['domains'], 'what crt.sh received');
      const crt = (await logEntries(page)).find((e) => e.host === 'crt.sh');
      assertEqual([crt.fetch, crt.resource], [0, 1], 'seen by Resource Timing only');
      assert(/1 host is not a service DomainScope uses/.test(await text(page, '.egress-unknown')), 'warning');
      await page.waitFor(() => document.querySelector('.footer-sent-count')?.dataset.count === '2', { message: 'footer count' });
    });

    await run.step('a fetch the app started that got no answer counts, marked', async () => {
      await page.evaluate(() => fetch('https://api.hackertarget.com/hostsearch/?q=example.com').catch(() => null));
      await page.waitFor(() => [...document.querySelectorAll('.egress-name')].some((n) => n.textContent === 'HackerTarget'), { message: 'HackerTarget row' });
      const ht = (await ledger(page)).find((r) => r.name === 'HackerTarget');
      assertEqual([ht.requests, ht.failed, ht.kinds], [1, '1 got no answer', ['domains']], 'HackerTarget');
      await shot(page, opts, 'privacy-ledger-desktop-light-en');
    });

    await run.step('Clear empties the ledger and the footer count; it counts on from there', async () => {
      await page.click('[data-action="egress-clear"]');
      await page.waitFor(() => document.querySelector('[data-role="egress-summary"]').dataset.requests === '0', { message: 'cleared' });
      assertEqual((await ledger(page)).length, 0, 'no rows');
      await page.waitFor(() => document.querySelector('.footer-sent-count')?.dataset.count === '0', { message: 'footer count cleared' });
      assertEqual((await logEntries(page)).length, 0, 'the log itself');
    });

    run.group('Subdomains › Sources › Related domains');
    await run.step('a scan of example.com lists the domains of its certificates, from the answers it already has', async () => {
      await gotoRoute(page, 'subdomains');
      await page.type('[data-role="sub-domain"]', 'example.com');
      await page.click('[data-action="sub-run"]');
      await waitRun(page, 'scan done');
      const ctBefore = await page.evaluate(() => window.__fake.ct.length);
      assert(ctBefore >= 2, `Cert Spotter and crt.sh asked (${ctBefore})`);
      await page.click('.sub-tabs [role="tab"][data-tab="sources"]');
      await page.waitFor(() => document.querySelector('.sub-rel')?.dataset.state === 'ready' && document.querySelectorAll('.sub-rel-item').length > 0, { message: 'related card' });
      const items = await page.evaluate(() => [...document.querySelectorAll('.sub-rel-item')].map((li) => [li.dataset.domain, li.dataset.certs,
        !!li.querySelector('[data-action="rel-scan"]')]));
      assertEqual(items, [['example.net', '2', true], ['example.org', '1', true]], 'brand domains');
      const net = await page.evaluate(() => {
        const li = document.querySelector('.sub-rel-item[data-domain="example.net"]');
        return { names: li.querySelector('.sub-rel-names').textContent, certs: li.querySelectorAll('.sub-rel-cert').length, badges: li.querySelector('.sub-rel-badges').textContent };
      });
      assert(/shop\.example\.net/.test(net.names) && /api\.example\.net/.test(net.names), net.names);
      assert(/2 certificates/.test(net.badges) && /Current/.test(net.badges), net.badges);
      assert(/13 domains appear only in shared certificates/.test(await text(page, '.sub-rel-shared summary')), 'shared certificate folded');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.sub-rel-shared [data-action="rel-scan"]').length), 0, 'no scan of a shared certificate\'s domains');
      assert(/1 certificate only crt\.sh reported may name more domains/.test(await text(page, '.sub-rel .alert')), 'partial names');
      assert(/2 other domains share certificates with these hosts \(4 certificates read\)/.test(await text(page, '[data-role="rel-summary"]')), await text(page, '[data-role="rel-summary"]'));
      await page.waitFor(() => Number(document.querySelector('.footer-sent-count')?.dataset.count) > 0, { message: 'the footer counts the scan' });
      assertEqual(await page.evaluate(() => window.__fake.ct.length), ctBefore, 'the card sent nothing');
      await page.click('.sub-rel-item[data-domain="example.net"] .sub-rel-certs summary');
      await shot(page, opts, 'privacy-related-desktop-light-en');
    });

    await run.step('the ledger names every host the scan contacted, and what each received — none unknown', async () => {
      await gotoRoute(page, '#/about?section=sent');
      await page.waitFor(() => document.querySelectorAll('.egress-table tbody tr.dt-row').length > 2, { message: 'ledger rows' });
      const rows = await ledger(page);
      assertEqual(rows.filter((r) => r.kind === 'unknown'), [], 'no unknown host');
      const crt = rows.find((r) => r.name === 'crt.sh');
      const spotter = rows.find((r) => r.name === 'Cert Spotter');
      assert(crt && crt.requests >= 1 && crt.kinds.join() === 'domains', JSON.stringify(crt));
      assert(spotter && spotter.requests >= 1 && spotter.kinds.join() === 'domains', JSON.stringify(spotter));
      const dns = rows.filter((r) => r.kinds.join() === 'dnsQuestions');
      const dnsCount = dns.reduce((sum, r) => sum + r.requests, 0);
      assert(dns.length >= 1, 'DoH resolvers listed');
      assertEqual(dnsCount, await page.evaluate(() => window.__fake.dns), 'every DoH question counted');
    });

    await run.step('"Scan too" scans example.com and example.net together; example.net is then no longer related', async () => {
      await gotoRoute(page, 'subdomains');
      await page.click('.sub-tabs [role="tab"][data-tab="sources"]');
      await page.waitFor(() => !!document.querySelector('.sub-rel-item[data-domain="example.net"] [data-action="rel-scan"]'), { message: 'kept result' });
      await page.click('.sub-rel-item[data-domain="example.net"] [data-action="rel-scan"]');
      await page.waitFor(() => /example\.com, example\.net/.test(document.querySelector('.sub-run-title')?.textContent || ''), { message: 'second scan' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="sub-domain"]').value), 'example.com, example.net', 'the box');
      await waitRun(page, 'second scan done');
      await page.click('.sub-tabs [role="tab"][data-tab="sources"]');
      await page.waitFor(() => document.querySelector('.sub-rel')?.dataset.state === 'ready' && !!document.querySelector('.sub-rel-item'), { message: 'related again' });
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.sub-rel-item')].map((li) => li.dataset.domain)), ['example.org'], 'example.net is scanned now');
      assert(/#\/subdomains\?domain=example\.com%2Cexample\.net/.test(await page.evaluate(() => location.hash)), 'the URL names both');
    });

    run.group('Certificate › CT logs › Key continuity');
    await run.step('the key\'s SHA-256 is computed in the page; nothing is sent before the click', async () => {
      await gotoRoute(page, 'cert');
      await page.click('[data-action="cert-sample"]');
      await page.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === 'example.com', { message: 'sample loaded' });
      await page.click('.cert-tabs [role="tab"][data-tab="ct"]');
      await page.waitFor(() => /^[0-9a-f]{64}$/.test(document.querySelector('[data-role="key-spki"]')?.textContent || ''), { message: 'SPKI computed' });
      assertEqual(await text(page, '[data-role="key-spki"]'), SAMPLE_SPKI, 'the same hash as Node computes');
      assertEqual(await page.evaluate(() => window.__fake.key.length), 0, 'nothing sent yet');
      assertEqual(await page.evaluate(() => document.querySelector('.cert-key-card').dataset.state), 'idle', 'idle');
    });

    await run.step('the lookup sends one crt.sh search by the hash and says the key was reused, with what that means', async () => {
      await page.click('[data-action="key-run"]');
      await page.waitFor(() => !!document.querySelector('[data-key-status]'), { timeout: 15000, message: 'key result' });
      assertEqual(await page.evaluate(() => window.__fake.key), [`https://crt.sh/?spkisha256=${SAMPLE_SPKI}&output=json`], 'one search, the hash only');
      assertEqual(await page.evaluate(() => document.querySelector('[data-key-status]').dataset.keyStatus), 'reused', 'status');
      const body = await text(page, '.cert-key-card');
      assert(/Key reused across renewals/.test(body) && /1 other logged certificate/.test(body) && /1 issued before this one and 0 after it/.test(body), body);
      assert(/TLSA 3 1 1: a record for this key keeps matching/.test(body) && /Key pinning/.test(body), 'consequences');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.cert-key-table tbody tr.dt-row')].map((tr) => tr.classList.contains('cert-key-row-this'))),
        [false, true], 'oldest first, this certificate marked');
      await shot(page, opts, 'privacy-key-desktop-light-en');
      await page.click('[data-action="key-dane"]');
      await page.waitFor(() => document.querySelector('.cert-tabs [role="tab"][data-tab="dane"]')?.getAttribute('aria-selected') === 'true', { message: 'DANE tab' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.tab), 'dane', 'the DANE tab has the focus');
    });

    await run.step('the ledger says crt.sh received a public-key SHA-256', async () => {
      await gotoRoute(page, '#/about?section=sent');
      await page.waitFor(() => [...document.querySelectorAll('.egress-kinds li')].some((li) => li.dataset.kind === 'keyHash'), { message: 'key hash kind' });
      const crt = (await ledger(page)).find((r) => r.name === 'crt.sh');
      assertEqual(crt.kinds, ['domains', 'keyHash'], 'crt.sh kinds');
    });

    run.group('Phone 375 px, TR / EN × light / dark');
    await run.step('the ledger, the related domains and the key card fit without scrolling sideways', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      for (const lang of ['en', 'tr']) {
        await setLangUi(page, lang);
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await gotoRoute(page, '#/about?section=sent');
          await page.waitFor(() => document.querySelectorAll('.egress-table tbody tr.dt-row').length > 2, { message: 'ledger' });
          await assertNoHorizontalScroll(page, `ledger ${lang} ${scheme}`);
          assertEqual(await page.evaluate(() => [...document.querySelectorAll('.egress-table tbody tr')].filter((tr) => tr.scrollWidth > tr.clientWidth + 1).length), 0, 'cards fit');
          await shot(page, opts, `privacy-ledger-mobile-${scheme}-${lang}`);
          await gotoRoute(page, 'subdomains');
          await page.click('.sub-tabs [role="tab"][data-tab="sources"]');
          await page.waitFor(() => !!document.querySelector('.sub-rel-item'), { message: 'related' });
          await page.evaluate(() => document.querySelector('.sub-rel').scrollIntoView({ block: 'start' }));
          await assertNoHorizontalScroll(page, `related ${lang} ${scheme}`);
          assertEqual(await page.evaluate(() => [...document.querySelectorAll('.sub-rel-item')].filter((li) => li.scrollWidth > li.clientWidth + 1).length), 0, 'items fit');
          await shot(page, opts, `privacy-related-mobile-${scheme}-${lang}`);
          await gotoRoute(page, 'cert');
          await page.click('.cert-tabs [role="tab"][data-tab="ct"]');
          await page.waitFor(() => !!document.querySelector('.cert-key-card [data-key-status]'), { message: 'kept key result' });
          await page.evaluate(() => document.querySelector('.cert-key-card').scrollIntoView({ block: 'start' }));
          await assertNoHorizontalScroll(page, `key ${lang} ${scheme}`);
          await shot(page, opts, `privacy-key-mobile-${scheme}-${lang}`);
        }
      }
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await gotoRoute(page, '#/about?section=sent');
      await page.waitFor(() => document.querySelectorAll('.egress-table tbody tr.dt-row').length > 2, { message: 'ledger 320' });
      await assertNoHorizontalScroll(page, 'ledger 320 tr dark');
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Quality');
    await run.step('nothing reached the network (the witnesses were answered by the test)', () => assertEqual(leaks, [], 'requests that left the page'));
    await run.step('the app never sent to a host its fakes refuse, except the one the test asked for', async () => {
      assertEqual(await page.evaluate(() => window.__fake.blocked), ['https://api.hackertarget.com/hostsearch/?q=example.com'], 'refused');
    });
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'privacy', origin));
    await page.close();

    run.group('The Pages bundle names its deploy');
    await run.step('version.json: the ledger shows the deploy and links its commit', async () => {
      bundleDir = await mkdtemp(path.join(os.tmpdir(), 'ds-privacy-'));
      const sha = '0123456789abcdef0123456789abcdef01234567';
      await assembleSite({ out: path.join(bundleDir, 'site'), version: 'e2e0123abcd', commit: sha });
      const bundle = await startServer({ root: path.join(bundleDir, 'site'), base: BASE });
      try {
        const p = await browser.newPage('about:blank', { width: 1280, height: 900 });
        await networkGate(p);
        await p.goto(`${bundle.url}#/about?section=sent`);
        await waitReady(p);
        await p.waitFor(() => !!document.querySelector('[data-role="egress-version"] a'), { message: 'commit link' });
        const v = await p.evaluate(() => {
          const el = document.querySelector('[data-role="egress-version"]');
          return { version: el.dataset.version, href: el.querySelector('a').getAttribute('href'), text: el.textContent };
        });
        assertEqual([v.version, v.href], ['e2e0123abcd', `${REPO_URL}/commit/${sha}`], 'deploy and commit');
        assert(/e2e0123abcd/.test(v.text) && /0123456789ab/.test(v.text), v.text);
        const self = (await ledger(p)).find((r) => r.kind === 'self');
        assert(self && self.requests > 0, 'the version file and the modules: the page\'s own files');
        await assertClean(p, 'bundle', new URL(bundle.url).origin);
        await p.close();
      } finally {
        await bundle.close();
      }
    });
  } finally {
    await browser.close();
    await server.close();
    if (bundleDir) await rm(bundleDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(() => {});
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
