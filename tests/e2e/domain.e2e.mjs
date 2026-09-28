#!/usr/bin/env node
/**
 * domain.e2e.mjs — end-to-end test of the "Domain overview" view in a real headless Chrome/Edge.
 * OFFLINE: every DoH query is answered in the page by a fake resolver built from the zone below
 * (window.fetch wrapped before the app loads), the RDAP bootstrap and registry, Cert Spotter and
 * crt.sh by the same wrapper; every other https:// request is blocked, and every request that
 * leaves the page's origin is counted through CDP.
 *
 *   node tests/e2e/domain.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry (Discover, after Subdomains), the empty state, a shared link that only
 * fills the box (a host name reduced to its registrable domain, "Nothing has been sent yet") and
 * an IP refused; Build overview → the seven cards fill as their lookups land: an RDAP 503 and a
 * SERVFAIL for NS show "⚠ n/a" with the reason and a Retry that asks only that lookup again (the
 * keyboard focus stays on the card), at once when pressed while the build still waits for RDAP
 * (the health checks then follow the new answer); DNS hosting, mail platform with SPF / DMARC
 * one-liners, apex and www with their CDN, CAA, SaaS vendors without a single token on the page,
 * the health score; the CT issuers on a click (exactly one Cert Spotter request) compared with
 * CAA; Copy summary (names only, the permalink); the print stylesheet; the kept result on the way
 * back (no new query); Ctrl+Enter builds and Esc stops (the cards not looked up offer to be,
 * named "Look up" for a screen reader too, the focus back on Build); a .tr domain (no RDAP: the
 * registry's WHOIS); 320 / 375 px without horizontal scroll, TR / EN × light / dark; zero console
 * errors / CSP violations / missing i18n keys, nothing sent outside the page.
 *
 * Data is documentation space only (example.com / .net / .org, example-test.com.tr,
 * 198.51.100.0/24, 203.0.113.0/24) plus the Cloudflare edge 104.16.1.1 and the provider host names
 * the tables name.
 */

import path from 'node:path';
import { startServer } from './serve.mjs';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, setLangUi, shot, stubClipboard, takeClipboard, waitReady
} from './scan.e2e.mjs';

const DAY = 86400000;
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const NOW = Date.now();
const TOKENS = ['E2ETOKENgoogle', 'E2ETOKENatlassian', 'ms90210', 'e2e0token'];
/** A DNSKEY and a DS with its key tag, so the fake zone's DNSSEC reads as healthy. */
const DNSKEY = { flags: 257, protocol: 3, algorithm: 13, publicKey: Buffer.alloc(64, 7).toString('base64') };
const KEY_TAG = decodeMessage(encodeMessage({ answers: [{ name: 'example.com', type: 'DNSKEY', ttl: 300, data: DNSKEY }] })).answers[0].data.keyTag;

/** The fake zone: example.com on Cloudflare with Microsoft 365 mail, example-test.com.tr on Natro with Yaani mail. */
const ZONE = {
  'example.com': {
    SOA: [{ mname: 'adam.ns.cloudflare.com', rname: 'dns.cloudflare.com', serial: 2026092801, refresh: 10000, retry: 2400, expire: 604800, minimum: 1800 }],
    NS: ['adam.ns.cloudflare.com', 'bella.ns.cloudflare.com'],
    A: ['104.16.1.1'],
    MX: [{ preference: 0, exchange: 'example-com.mail.protection.outlook.com' }],
    TXT: [
      ['v=spf1 include:spf.protection.outlook.com include:sendgrid.net -all'],
      [`google-site-verification=${TOKENS[0]}`], [`atlassian-domain-verification=${TOKENS[1]}`], [`MS=${TOKENS[2]}`],
      [`stripe-verification=${TOKENS[3]}`], ['something-unknown=1']
    ],
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'iodef', value: 'mailto:security@example.com' }],
    DS: [{ keyTag: KEY_TAG, algorithm: 13, digestType: 2, digest: 'ab'.repeat(32) }],
    DNSKEY: [DNSKEY],
    HTTPS: [{ priority: 1, target: '.', params: { alpn: ['h3', 'h2'] } }]
  },
  'www.example.com': { CNAME: 'example.com' },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']] },
  'example-com.mail.protection.outlook.com': { A: ['198.51.100.25'] },
  'adam.ns.cloudflare.com': { A: ['198.51.100.53'] },
  'bella.ns.cloudflare.com': { A: ['203.0.113.54'] },
  // the SPF includes, so the record's lookups resolve
  'spf.protection.outlook.com': { TXT: [['v=spf1 ip4:198.51.100.0/24 -all']] },
  'sendgrid.net': { TXT: [['v=spf1 ip4:203.0.113.0/24 -all']] },
  'example-test.com.tr': {
    SOA: [{ mname: 'ns1.natrohost.com', rname: 'hostmaster.example-test.com.tr', serial: 2026090101, refresh: 3600, retry: 600, expire: 1209600, minimum: 300 }],
    NS: ['ns1.natrohost.com', 'ns2.natrohost.com'],
    A: ['203.0.113.80'],
    MX: [{ preference: 10, exchange: 'mx.yaanimail.com' }],
    TXT: [['v=spf1 -all']]
  },
  'www.example-test.com.tr': { A: ['203.0.113.80'] },
  // built only by the mid-build Retry step, so none of its answers is in the resolver's cache yet
  'example.net': {
    SOA: [{ mname: 'adam.ns.cloudflare.com', rname: 'dns.cloudflare.com', serial: 2026092802, refresh: 10000, retry: 2400, expire: 604800, minimum: 1800 }],
    NS: ['adam.ns.cloudflare.com', 'bella.ns.cloudflare.com'],
    A: ['104.16.1.1'],
    TXT: [['v=spf1 -all']]
  },
  'mx.yaanimail.com': { A: ['203.0.113.90'] }
};
const SIGNED = ['example.com'];

/** The registry's RDAP answer (no transfer lock: status "active" only). */
const RDAP = {
  'example.com': {
    objectClassName: 'domain', ldhName: 'EXAMPLE.COM', status: ['active'],
    events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }, { eventAction: 'expiration', eventDate: iso(NOW + 200 * DAY) }],
    entities: [{ objectClassName: 'entity', roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar, Inc.']]], publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }] }],
    nameservers: [{ ldhName: 'ADAM.NS.CLOUDFLARE.COM' }, { ldhName: 'BELLA.NS.CLOUDFLARE.COM' }],
    secureDNS: { delegationSigned: true }
  }
};
RDAP['example.net'] = { ...RDAP['example.com'], ldhName: 'EXAMPLE.NET', nameservers: RDAP['example.com'].nameservers, secureDNS: { delegationSigned: false } };

/** Cert Spotter's current issuances of example.com: Let's Encrypt (CAA allows it) and Sectigo (it does not). */
const issuance = (id, dn, friendly, caa) => ({
  id: String(id), tbs_sha256: 'aa'.repeat(32), cert_sha256: 'bb'.repeat(32), pubkey_sha256: 'cc'.repeat(32),
  issuer: { friendly_name: friendly, caa_domains: caa, operator: { name: friendly, website: 'https://ca.example.org/' }, pubkey_sha256: 'dd'.repeat(32), name: dn },
  not_before: iso(NOW - 30 * DAY), not_after: iso(NOW + 60 * DAY), revoked: false
});
const SPOTTER = [
  issuance(101, "C=US, O=Let's Encrypt, CN=R11", "Let's Encrypt", ['letsencrypt.org']),
  issuance(102, "C=US, O=Let's Encrypt, CN=R10", "Let's Encrypt", ['letsencrypt.org']),
  issuance(103, 'C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV R36', 'Sectigo', ['sectigo.com'])
];

/** In-page stubs: DoH from the zone (NXDOMAIN outside it), RDAP, Cert Spotter, crt.sh. */
const fakeScript = () => `(() => {
  const Z = ${JSON.stringify(ZONE)};
  const SIGNED = ${JSON.stringify(SIGNED)};
  const RDAP = ${JSON.stringify(RDAP)};
  const SPOTTER = ${JSON.stringify(SPOTTER)};
  window.__dnsLog = [];
  window.__rdapLog = [];
  window.__ctLog = [];
  window.__rcodes = {};
  window.__rdapStatus = 200;
  window.__rdapGate = null;
  window.__dnsHold = {};
  window.__dnsDelay = 0;
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
  const wait = (ms, signal) => new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
  });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://data.iana.org/rdap/')) return json({ services: [[['com', 'net', 'org'], ['https://rdap.example.net/']]] });
    if (url.startsWith('https://rdap.example.net/') || url.startsWith('https://rdap.org/')) {
      window.__rdapLog.push(url);
      // a promise the test resolves: the registry answers only then
      if (window.__rdapGate) await window.__rdapGate;
      if (window.__rdapStatus !== 200) return json({ errorCode: window.__rdapStatus }, window.__rdapStatus);
      const name = decodeURIComponent(url.split('/domain/')[1] || '');
      return RDAP[name] ? json(RDAP[name]) : json({ errorCode: 404 }, 404);
    }
    if (url.startsWith('https://api.certspotter.com/')) { window.__ctLog.push(url); return json(SPOTTER); }
    if (url.startsWith('https://crt.sh/')) { window.__ctLog.push(url); return json([]); }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const qname = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__dnsLog.push({ name: qname, type: q.type });
    if (window.__dnsDelay) await wait(window.__dnsDelay, init?.signal);
    // a question held back until the test resolves its promise
    if (window.__dnsHold[qname + '|' + q.type]) await window.__dnsHold[qname + '|' + q.type];
    const forced = window.__rcodes[qname + '|' + q.type];
    const answers = [];
    let rcode = forced || 'NOERROR';
    let cur = qname;
    for (let i = 0; !forced && i < 8; i += 1) {
      const node = Z[cur];
      if (!node) { rcode = 'NXDOMAIN'; break; }
      if (node.CNAME && q.type !== 'CNAME') { answers.push({ name: cur, type: 'CNAME', ttl: 300, data: node.CNAME }); cur = node.CNAME; continue; }
      for (const data of node[q.type] || []) answers.push({ name: cur, type: q.type, ttl: 300, data });
      break;
    }
    const ad = SIGNED.some((z) => cur === z || cur.endsWith('.' + z));
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true, ad }, rcode,
      questions: [{ name: q.name, type: q.type }], answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

async function nodeChecks(run) {
  const V = await import('../../assets/js/views/domain.js');
  run.group('Node: views/domain.js');
  await run.step('each card links to the tool that goes deeper; status flag colours', () => {
    assertEqual(V.cardLink('dns', 'example.com'), { view: 'lookup', params: { name: 'example.com', type: 'NS,SOA,DS,DNSKEY' } }, 'dns');
    assertEqual(V.cardLink('certs', 'example.com'), { view: 'cert', params: { host: 'example.com', run: '0' } }, 'certs: filled, never loaded');
    assertEqual(V.cardLink('web', 'example.com').view, 'global', 'web');
    assertEqual(V.cardLink('saas', 'example.com').params.type, 'TXT', 'saas');
    for (const c of ['registration', 'mail', 'health']) assertEqual(V.cardLink(c, 'example.com').view, 'health', c);
    assertEqual(['lock', 'hold', 'pending', 'ok', 'other'].map(V.flagVariant), ['ok', 'error', 'error', 'neutral', 'neutral'], 'flags');
  });
}

const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);
const counts = (page) => page.evaluate(() => ({ dns: window.__dnsLog.length, rdap: window.__rdapLog.length, ct: window.__ctLog.length }));
/** Every card's state ('pending' | 'ready' | 'stopped') and its failed lookups. */
const cardStates = (page) => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.dov-slot')].map((s) => {
  const c = s.querySelector('.dov-card');
  return [s.dataset.card, c ? `${c.dataset.state}${c.dataset.failed ? `:${c.dataset.failed}` : ''}` : 'none'];
})));
/** Cards whose title and links overlap (a long Turkish link next to a title on a phone). */
const overlaps = () => [...document.querySelectorAll('.dov-card')].filter((c) => {
  const a = c.querySelector('.card-title').getBoundingClientRect();
  const b = c.querySelector('.card-actions').getBoundingClientRect();
  return a.right > b.left + 1 && b.right > a.left + 1 && a.bottom > b.top + 1 && b.bottom > a.top + 1;
}).map((c) => c.querySelector('.card-title').textContent);
const waitBuilt = (page, message = 'overview built') => page.waitFor(() => !!document.querySelector('.dov-head')
  && !document.querySelector('[data-action="dov-run"]').hidden
  && [...document.querySelectorAll('.dov-card')].every((c) => c.dataset.state !== 'pending'), { timeout: 30000, message });

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  await nodeChecks(run);

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
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/domain: the nav entry in Discover after Subdomains, the empty state, nothing sent', async () => {
      await page.goto(`${server.url}#/domain`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'domain');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/zone"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '').split('?')[0]) : [];
      });
      assertEqual(nav, ['subdomains', 'domain', 'zone'], 'Discover group');
      assertEqual(await text(page, 'h1'), 'Domain overview', 'title');
      assert(await page.evaluate(() => !!document.querySelector('.dov-empty .empty')), 'empty state');
      assertEqual(await counts(page), { dns: 0, rdap: 0, ct: 0 }, 'nothing sent');
      await shot(page, opts, 'domain-empty-desktop-light-en');
    });

    await run.step('a shared link only fills the box (a host name reduced to its domain) and says nothing was sent; an IP is refused', async () => {
      await gotoRoute(page, '#/domain?name=www.example.com');
      await page.waitFor(() => !!document.querySelector('.dov-prompt [data-prompt="link"]'), { message: 'link prompt' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="dov-name"]').value), 'www.example.com', 'box');
      assert(/press Build overview to look up example\.com\. Nothing has been sent yet\./.test(await text(page, '.dov-prompt')), await text(page, '.dov-prompt'));
      assertEqual(await counts(page), { dns: 0, rdap: 0, ct: 0 }, 'still nothing sent');
      await page.type('[data-role="dov-name"]', '192.0.2.10');
      await page.click('[data-action="dov-run"]');
      await page.waitFor(() => /not an IP address/.test(document.querySelector('.dov-name')?.textContent || ''), { message: 'IP refused' });
      assertEqual(await counts(page), { dns: 0, rdap: 0, ct: 0 }, 'nothing sent for an IP');
      await page.type('[data-role="dov-name"]', 'www.example.com');
    });

    await run.step('Build overview: the cards fill; an RDAP 503 and a SERVFAIL for NS say "n/a" with the reason and a Retry', async () => {
      await page.evaluate(() => { window.__rdapStatus = 503; window.__rcodes['example.com|NS'] = 'SERVFAIL'; });
      await page.click('[data-action="dov-run"]');
      await page.waitFor(() => !document.querySelector('[data-action="dov-stop"]').hidden || !!document.querySelector('.dov-head'), { message: 'running' });
      await waitBuilt(page);
      assert(/#\/domain\?name=example\.com$/.test(await page.evaluate(() => location.hash)), 'the URL names the domain');
      assertEqual(await cardStates(page), {
        registration: 'ready:rdap', dns: 'ready:ns', mail: 'ready', web: 'ready', certs: 'ready', saas: 'ready', health: 'ready'
      }, 'cards');
      assert(/Overview of example\.com, the registrable domain of www\.example\.com\./.test(await text(page, '.dov-head')), 'reduced note');
      assert(/RDAP: answered HTTP 503/.test(await text(page, '.dov-card-registration .dov-status')), await text(page, '.dov-card-registration'));
      assert(await page.evaluate(() => document.querySelectorAll('.dov-card-registration .na-mark').length >= 3), 'n/a fields');
      assert(/DNS resolver: answered SERVFAIL/.test(await text(page, '.dov-card-dns .dov-status')), 'NS reason');
      assert(await page.evaluate(() => !!document.querySelector('.dov-card-dns [data-action="retry-source"]')), 'DNS Retry');
      assert(/Signed and validated/.test(await text(page, '.dov-card-dns')), 'DNSSEC');
      assert(/primary adam\.ns\.cloudflare\.com · serial 2026092801/.test(await text(page, '.dov-card-dns')) && /changed 2026-09-28/.test(await text(page, '.dov-card-dns')), 'SOA');
      const mail = await text(page, '.dov-card-mail');
      assert(/Microsoft 365/.test(mail) && /Hard fail \(-all\)/.test(mail) && /SendGrid/.test(mail) && /Reject \(p=reject\)/.test(mail), mail);
      const web = await text(page, '.dov-card-web');
      assert(/Cloudflare/.test(web) && /alias of example\.com/.test(web), web);
      assert(await page.evaluate(() => document.querySelectorAll('.dov-card-web [data-kind="cloudflare"]').length === 2), 'apex and www on Cloudflare');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.dov-card-certs [data-caa="present"] .badge')].map((b) => b.textContent)), ["Let's Encrypt"], 'CAA');
      const vendors = await page.evaluate(() => [...document.querySelectorAll('.dov-vendor')].map((v) => v.dataset.vendor));
      assertEqual(vendors, ['atlassian', 'google', 'microsoft', 'stripe'], 'vendors');
      const page0 = await page.evaluate(() => document.querySelector('.dov-results').textContent);
      for (const tok of ['E2ETOKENgoogle', 'E2ETOKENatlassian', 'ms90210', 'e2e0token']) assert(!page0.includes(tok), `no token on the page: ${tok}`);
      assert(/^\d+$/.test(await page.evaluate(() => document.querySelector('.dov-score')?.dataset.score || '')), 'health score');
      const c = await counts(page);
      assertEqual([c.rdap, c.ct], [4, 0], 'RDAP asked (one retry, then rdap.org, twice each); no CT request');
      await shot(page, opts, 'domain-results-desktop-light-en');
    });

    await run.step('Retry asks only the failed lookup again, and the keyboard focus stays on the card', async () => {
      await page.evaluate(() => { window.__rdapStatus = 200; delete window.__rcodes['example.com|NS']; });
      const before = await counts(page);
      await page.evaluate(() => document.querySelector('.dov-card-registration [data-action="retry-source"]').focus());
      await page.press('Enter');
      await page.waitFor(() => /Example Registrar, Inc\./.test(document.querySelector('.dov-card-registration')?.textContent || ''), { timeout: 15000, message: 'registration filled' });
      const reg = await text(page, '.dov-card-registration');
      assert(/IANA ID 9999/.test(reg) && /days left/.test(reg) && /Off/.test(reg) && /clientTransferProhibited/.test(reg), reg);
      assertEqual(await page.evaluate(() => document.querySelector('.dov-card-registration').dataset.failed), '', 'no failure left');
      assertEqual(await page.evaluate(() => !!document.activeElement?.closest('.dov-card-registration')), true, 'focus on the card');
      const after = await counts(page);
      assertEqual([after.rdap - before.rdap, after.dns - before.dns], [1, 0], 'one RDAP request, no DNS');
      assert(await page.evaluate(() => !!document.querySelector('.dov-problem[data-id="ns.error"]')), 'the health card still has the NS failure');
      // the DNS card's Retry: NS alone, past the cache
      const dnsBefore = await page.evaluate(() => window.__dnsLog.length);
      await page.click('.dov-card-dns [data-action="retry-source"]');
      await page.waitFor(() => document.querySelector('.dov-card-dns')?.dataset.failed === '' && /Cloudflare/.test(document.querySelector('.dov-card-dns').textContent), { message: 'dns filled' });
      // the health checks run again on the retried answer (the rest from the resolver's cache)
      await page.waitFor(() => !document.querySelector('.dov-card-health .dov-updating') && !!document.querySelector('.dov-score')
        && !document.querySelector('.dov-problem[data-id="ns.error"]'), { timeout: 15000, message: 'health refreshed' });
      assertEqual(await page.evaluate((n) => window.__dnsLog.slice(n).filter((q) => q.name === 'example.com' && q.type === 'NS').length, dnsBefore), 1, 'NS asked once, past the cache');
      // Nothing the first run asked is asked again: only what the new NS answer leads to (the name
      // servers' addresses) and the health run's random probes (wildcard, DKIM) are new questions.
      const again = await page.evaluate((n) => window.__dnsLog.slice(n).map((q) => `${q.name}|${q.type}`).filter((k) => k !== 'example.com|NS'
        && !/^(?:adam|bella)\.ns\.cloudflare\.com\|/.test(k) && !/^[a-z0-9]{10,}\.(?:_domainkey\.)?example\.com\|/.test(k)), dnsBefore);
      assertEqual(again, [], 'the health run read the rest from the cache');
      assert(/adam\.ns\.cloudflare\.com/.test(await text(page, '.dov-card-dns')), 'name servers');
      assertEqual(await page.evaluate(() => document.querySelector('.dov-score').dataset.light), 'ok', 'the fixed zone is healthy: no error or warning left');
    });

    await run.step('the CT issuers on a click: exactly one Cert Spotter request, compared with CAA', async () => {
      await page.click('.dov-card-certs [data-action="dov-ct"]');
      await page.waitFor(() => document.querySelector('.dov-ct')?.dataset.ct === 'ok', { message: 'CT issuers' });
      assertEqual((await counts(page)).ct, 1, 'one request');
      assert(/expand=issuer/.test(await page.evaluate(() => window.__ctLog[0])), 'the issuer expanded');
      const rows = await page.evaluate(() => [...document.querySelectorAll('.dov-issuer')].map((li) => [li.querySelector('.dov-issuer-name').textContent, li.dataset.verdict]));
      assertEqual(rows, [["Let's Encrypt", 'allowed'], ['Sectigo', 'denied']], 'issuers');
      assert(/CAA does not allow Sectigo/.test(await text(page, '.dov-card-certs')), 'the renewal warning');
      assert(/first page of current certificates \(3 read\)/.test(await text(page, '.dov-card-certs')), 'says it read one page');
      await shot(page, opts, 'domain-ct-desktop-light-en');
    });

    await run.step('Copy summary: one line per card, names only, the permalink; the print stylesheet', async () => {
      await stubClipboard(page);
      await page.click('.dov-head [data-action="copy-summary"]');
      await page.waitFor(() => (window.__clip || []).length === 1, { message: 'copied' });
      const [out] = await takeClipboard(page);
      const ls = out.trimEnd().split('\n');
      assertEqual(ls[0], '**Domain overview · `example.com`**', 'title');
      assert(ls.some((l) => l.startsWith('- **Registration:** `Example Registrar, Inc.` · expires') && l.endsWith('· no transfer lock')), out);
      assert(ls.includes('- **DNS:** Cloudflare · DNSSEC validated'), out);
      assert(ls.includes('- **Mail:** Microsoft 365 · SPF -all · DMARC p=reject'), out);
      assert(ls.includes("- **Certificates:** CAA allows Let's Encrypt · issuers in CT: `Let's Encrypt` (2), `Sectigo` (1) · not allowed by CAA: `Sectigo`"), out);
      assert(ls.includes('- **Services:** 4 services verified the domain by TXT: Atlassian, Google, Microsoft 365 +1 more'), out);
      assert(/\/domainscope\/#\/domain\?name=example\.com$/.test(ls[ls.length - 1]), ls[ls.length - 1]);
      for (const tok of TOKENS) assert(!out.includes(tok), `no token in the summary: ${tok}`);
      await page.send('Emulation.setEmulatedMedia', { media: 'print' });
      const printed = await page.evaluate(() => {
        const shown = (sel) => [...document.querySelectorAll(sel)].some((el) => getComputedStyle(el).display !== 'none' && el.getClientRects().length);
        return { form: shown('.dov-form-card'), actions: shown('.dov-card-actions'), cards: document.querySelectorAll('.dov-card').length, cardShown: shown('.dov-card-mail'), grid: getComputedStyle(document.querySelector('.dov-grid')).display };
      });
      await page.send('Emulation.setEmulatedMedia', { media: '' });
      assertEqual(printed, { form: false, actions: false, cards: 7, cardShown: true, grid: 'block' }, 'print');
    });

    await run.step('the overview is kept: back through the nav link it shows again with no new query', async () => {
      const before = await counts(page);
      await gotoRoute(page, 'lookup');
      await page.click('a.nav-link[data-view="domain"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'domain' && !!document.querySelector('.dov-head'), { message: 'back' });
      await page.waitFor(() => !!document.querySelector('.page-kept:not([hidden]) .kept-note'), { message: 'kept note' });
      assertEqual(await counts(page), before, 'no new request');
      assertEqual(await page.evaluate(() => document.querySelector('.dov-ct')?.dataset.ct), 'ok', 'the CT issuers kept too');
      assert(/Example Registrar/.test(await text(page, '.dov-card-registration')), 'the retried registration kept');
    });

    await run.step('Ctrl+Enter builds, Esc stops: the cards not looked up offer to be, and the focus is back on Build', async () => {
      await page.type('[data-role="dov-name"]', 'example.org');
      await page.evaluate(() => { window.__dnsDelay = 400; window.__rdapStatus = 200; });
      await page.press('Enter', { ctrl: true });
      await page.waitFor(() => !document.querySelector('[data-action="dov-stop"]').hidden, { message: 'running' });
      // a link opened meanwhile waits: the running build keeps its box
      await page.evaluate(() => { location.hash = '#/domain?name=example.net'; });
      await page.waitFor(() => /name=example\.net/.test(location.hash), { message: 'link opened' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="dov-name"]').value), 'example.org', 'the box keeps the running build');
      await page.evaluate(() => document.querySelector('[data-action="dov-stop"]').focus());
      await page.press('Escape');
      await page.waitFor(() => !document.querySelector('[data-action="dov-run"]').hidden, { message: 'stopped' });
      await page.evaluate(() => { window.__dnsDelay = 0; });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'dov-run', 'focus on Build');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="dov-name"]').value), 'example.net', 'then the link fills the box');
      assert(/press Build overview to look up example\.net/.test(await text(page, '.dov-prompt')), 'and waits for a click');
      const states = Object.values(await cardStates(page));
      assert(states.some((s) => s.startsWith('stopped')), `a stopped card: ${states}`);
      assert(/Stopped/.test(await text(page, '.dov-head')), 'the head says so');
      // "Look up", not "Retry": the visible label, the accessible name (it starts with the label) and the tooltip
      const lookUp = await page.evaluate(() => [...document.querySelectorAll('.dov-card[data-state="stopped"] [data-action="retry-source"]')]
        .map((b) => [b.textContent.trim(), b.getAttribute('aria-label'), b.title]));
      assert(lookUp.length && lookUp.every(([label, name, title]) => label === 'Look up' && /^Look up \S/.test(name) && /^Ask /.test(title)), JSON.stringify(lookUp));
      await shot(page, opts, 'domain-stopped-desktop-light-en');
    });

    await run.step('a .tr domain: no RDAP service, the registry\'s WHOIS instead; DNS at Natro, mail at Yaani', async () => {
      const before = await counts(page);
      await page.type('[data-role="dov-name"]', 'example-test.com.tr');
      await page.click('[data-action="dov-run"]');
      await waitBuilt(page, '.tr overview');
      const reg = await page.evaluate(() => ({
        text: document.querySelector('.dov-card-registration').textContent,
        href: document.querySelector('.dov-card-registration .dov-whois a')?.getAttribute('href')
      }));
      assert(/The \.tr registry publishes no RDAP service/.test(reg.text) && /TRABİS/.test(reg.text), reg.text);
      assertEqual(reg.href, 'https://www.trabis.gov.tr/whois', 'WHOIS link');
      assertEqual((await counts(page)).rdap, before.rdap, 'no RDAP request for .tr');
      assert(/Natro/.test(await text(page, '.dov-card-dns')), 'Natro');
      assert(/Yaani Mail/.test(await text(page, '.dov-card-mail')), 'Yaani');
      await shot(page, opts, 'domain-tr-desktop-light-en');
    });

    await run.step('a Retry pressed while the build still runs asks again at once; the health checks follow the new answer', async () => {
      try {
        // RDAP and one question only the health run asks are held back, so the Retry lands first.
        await page.evaluate(() => {
          window.__rcodes['example.net|NS'] = 'SERVFAIL';
          window.__rdapGate = new Promise((resolve) => { window.__openRdap = resolve; });
          window.__dnsHold['_smtp._tls.example.net|TXT'] = new Promise((resolve) => { window.__openHealth = resolve; });
        });
        await page.type('[data-role="dov-name"]', 'example.net');
        await page.click('[data-action="dov-run"]');
        // The DNS card is complete with NS failed while the registry holds its answer back.
        await page.waitFor(() => document.querySelector('.dov-card-dns')?.dataset.failed === 'ns'
          && !!document.querySelector('.dov-card-dns [data-action="retry-source"]'), { message: 'DNS card with its Retry' });
        assert(await page.evaluate(() => !document.querySelector('[data-action="dov-stop"]').hidden), 'the build still runs');
        const nsAsked = () => page.evaluate(() => window.__dnsLog.filter((q) => q.name === 'example.net' && q.type === 'NS').length);
        const before = await nsAsked();
        await page.evaluate(() => { delete window.__rcodes['example.net|NS']; });
        await page.click('.dov-card-dns [data-action="retry-source"]');
        await page.waitFor(() => document.querySelector('.dov-card-dns')?.dataset.failed === '' && /Cloudflare/.test(document.querySelector('.dov-card-dns').textContent),
          { message: 'DNS card filled during the build' });
        assertEqual(await nsAsked() - before, 1, 'NS asked again at once');
        assert(await page.evaluate(() => !document.querySelector('[data-action="dov-stop"]').hidden), 'before the build ended');
        // The build's health run lands now, made on the SERVFAIL it shares with the build.
        await page.evaluate(() => { delete window.__dnsHold['_smtp._tls.example.net|TXT']; window.__openHealth(); window.__openRdap(); });
        await waitBuilt(page, 'the build ends');
        assertEqual(await page.evaluate(() => document.querySelector('.dov-card-dns').dataset.failed), '', 'the DNS card keeps the retried answer');
        // It runs again on the retried answer.
        await page.waitFor(() => !document.querySelector('.dov-card-health .dov-updating') && !!document.querySelector('.dov-score')
          && !document.querySelector('.dov-problem[data-id="ns.error"]'), { timeout: 15000, message: 'health follows the retried NS' });
      } finally {
        // the registry answers again, whatever happened above
        await page.evaluate(() => {
          window.__dnsHold = {};
          for (const open of [window.__openHealth, window.__openRdap]) if (open) open();
          window.__rdapGate = null;
        });
      }
    });

    run.group('Phone 375 and 320 px, Turkish / English, light / dark');
    await run.step('the overview at 375 px: no horizontal scroll; TR / EN × light / dark', async () => {
      await page.type('[data-role="dov-name"]', 'example.com');
      await page.click('[data-action="dov-run"]');
      await waitBuilt(page, 'example.com again');
      await page.setViewport({ width: 375, height: 667, mobile: true });
      for (const lang of ['en', 'tr']) {
        await setLangUi(page, lang);
        await page.waitFor(() => !!document.querySelector('.dov-head'), { message: 'kept after the language switch' });
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await page.evaluate(() => window.scrollTo(0, 0));
          await assertNoHorizontalScroll(page, `domain ${scheme} ${lang}`);
          await shot(page, opts, `domain-results-mobile-${scheme}-${lang}`);
        }
      }
      const fit375 = await page.evaluate(() => [...document.querySelectorAll('.dov-card, .dov-head')].filter((c) => c.scrollWidth > c.clientWidth + 1).map((c) => c.className));
      assertEqual(fit375, [], 'every card fits at 375 px');
      assertEqual(await page.evaluate(overlaps), [], 'no card title under its links at 375 px (tr)');
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      await assertNoHorizontalScroll(page, 'domain 320 tr dark');
      const fits = await page.evaluate(() => [...document.querySelectorAll('.dov-card')].every((c) => c.scrollWidth <= c.clientWidth + 1));
      assert(fits, 'every card fits at 320 px');
      assertEqual(await page.evaluate(overlaps), [], 'no card title under its links at 320 px (tr)');
      await shot(page, opts, 'domain-results-mobile320-dark-tr');
      await page.setViewport({ width: 1440, height: 900 });
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, opts, 'domain-results-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'domain', origin));
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
