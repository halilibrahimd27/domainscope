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
 * Covers: the nav entry (the first of Investigate a domain), the empty state, a shared link that only
 * fills the box (a host name reduced to its registrable domain, "Nothing has been sent yet") and
 * an IP refused; Build overview → the seven cards fill as their lookups land: an RDAP 503 and a
 * SERVFAIL for NS show "⚠ n/a" with the reason and a Retry that asks only that lookup again (the
 * keyboard focus stays on the card, or on Copy summary when it moved there meanwhile), at once
 * when pressed while the build still waits for RDAP (the health checks then follow the new
 * answer); DNS hosting, mail platform with SPF / DMARC one-liners, apex and www with their CDN,
 * CAA, SaaS vendors without a single token on the page, the health score; the CT issuers on a
 * click (exactly one Cert Spotter request) compared with CAA; Copy summary (names only, the
 * permalink); the print stylesheet; the kept result on the way back (no new query); Ctrl+Enter
 * builds and Esc stops (the cards not looked up offer to be, named "Look up" for a screen reader
 * too, the focus back on Build); a .tr domain (no RDAP: the registry's WHOIS; CAA without an
 * issue property); CAA with an unknown tag marked critical; Report (ui/report.js): the downloaded
 * HTML file has no script, escapes a crafted SPF record, names no token and links the overview's
 * permalink, "Print / save as PDF" puts the report alone on paper and goes away after printing, and
 * the file follows the UI language; 320 / 375 px without horizontal
 * scroll, TR / EN × light / dark; zero console errors / CSP violations / missing i18n keys,
 * nothing sent outside the page.
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
  gotoRoute, installDownloadCapture, setLangUi, shot, stubClipboard, takeClipboard, takeDownloads, waitReady
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
    TXT: [['v=spf1 -all']],
    // no issue property: any CA for the name, none for wildcards
    CAA: [{ flags: 0, tag: 'iodef', value: 'mailto:security@example.com' }, { flags: 0, tag: 'issuewild', value: ';' }]
  },
  'www.example-test.com.tr': { A: ['203.0.113.80'] },
  // built only by the mid-build Retry step, so none of its answers is in the resolver's cache yet
  'example.net': {
    SOA: [{ mname: 'adam.ns.cloudflare.com', rname: 'dns.cloudflare.com', serial: 2026092802, refresh: 10000, retry: 2400, expire: 604800, minimum: 1800 }],
    NS: ['adam.ns.cloudflare.com', 'bella.ns.cloudflare.com'],
    A: ['104.16.1.1'],
    TXT: [['v=spf1 -all']],
    // a critical tag no CA knows: nobody may issue, whatever issue names
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 128, tag: 'tbs', value: 'unknown' }]
  },
  'mx.yaanimail.com': { A: ['203.0.113.90'] },
  // Lookalikes of example.com (the Lookalike domains panel): rn for m with mail, registered last
  // week; a Cyrillic а with mail; a 1 for l on example.com's own name servers and address.
  'exarnple.com': { NS: ['ns1.example.org'], A: ['203.0.113.66'], MX: [{ preference: 10, exchange: 'mx.exarnple.com' }] },
  'xn--exmple-4nf.com': { NS: ['ns1.example.org'], A: ['203.0.113.67'], MX: [{ preference: 10, exchange: 'mx.example.org' }] },
  'examp1e.com': { NS: ['adam.ns.cloudflare.com', 'bella.ns.cloudflare.com'], A: ['104.16.1.1'] },
  // the customer report: a crafted SPF record (escaped in the file) and a token (never in it)
  'example.org': {
    SOA: [{ mname: 'adam.ns.cloudflare.com', rname: 'dns.cloudflare.com', serial: 2026100801, refresh: 10000, retry: 2400, expire: 604800, minimum: 1800 }],
    NS: ['adam.ns.cloudflare.com', 'bella.ns.cloudflare.com'],
    A: ['203.0.113.70'],
    TXT: [['v=spf1 <script>alert(1)</script> -all'], ['google-site-verification=E2ETOKENorg']]
  }
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
const registered = (name, ms) => ({ ...RDAP['example.com'], ldhName: name.toUpperCase(), events: [{ eventAction: 'registration', eventDate: iso(ms) }] });
RDAP['exarnple.com'] = registered('exarnple.com', NOW - 10 * DAY);
RDAP['xn--exmple-4nf.com'] = registered('xn--exmple-4nf.com', NOW - 400 * DAY);
RDAP['examp1e.com'] = registered('examp1e.com', Date.parse('2001-05-01T00:00:00Z'));
/** crt.sh's current certificates of the lookalikes (any other search: none). */
const CRTSH = {
  'exarnple.com': [{ issuer_ca_id: 1, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: 'exarnple.com', name_value: 'exarnple.com', id: 1, serial_number: '0a', not_before: iso(NOW - 3 * DAY).replace('Z', ''), not_after: iso(NOW + 87 * DAY).replace('Z', '') }]
};

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
  const CRTSH = ${JSON.stringify(CRTSH)};
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
    if (url.startsWith('https://crt.sh/')) {
      window.__ctLog.push(url);
      const q = new URL(url).searchParams.get('q') || '';
      return json(CRTSH[q] || []);
    }
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
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/domain: the first nav entry of Investigate a domain, the empty state, nothing sent', async () => {
      await page.goto(`${server.url}#/domain`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'domain');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/health"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '').split('?')[0]) : [];
      });
      assertEqual(nav, ['domain', 'health', 'subdomains', 'lookup'], 'Investigate a domain group');
      assertEqual(await text(page, 'h1'), 'Domain overview', 'title');
      assert(await page.evaluate(() => !!document.querySelector('.dov-empty .tool-empty')), 'empty state');
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
      // the DNS card's Retry: NS alone, past the cache. Its answer waits while the keyboard moves
      // on to Copy summary, which keeps the focus when the head is drawn again.
      const dnsBefore = await page.evaluate(() => window.__dnsLog.length);
      await page.evaluate(() => { window.__dnsHold['example.com|NS'] = new Promise((resolve) => { window.__openNs = resolve; }); });
      await page.click('.dov-card-dns [data-action="retry-source"]');
      await page.waitFor((n) => window.__dnsLog.slice(n).some((q) => q.name === 'example.com' && q.type === 'NS'), { args: [dnsBefore], message: 'NS asked' });
      await page.evaluate(() => document.querySelector('.dov-head [data-action="copy-summary"]').focus());
      await page.evaluate(() => { delete window.__dnsHold['example.com|NS']; window.__openNs(); });
      await page.waitFor(() => document.querySelector('.dov-card-dns')?.dataset.failed === '' && /Cloudflare/.test(document.querySelector('.dov-card-dns').textContent), { message: 'dns filled' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'copy-summary', 'the focus stays on Copy summary');
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
      assert(ls.includes('- **Mail:** Microsoft 365 · SPF `-all` · DMARC `p=reject`'), out);
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
      // iodef and issuewild ";" only: CAA leaves the name to any CA, and no CA may issue a wildcard
      assertEqual(await page.evaluate(() => document.querySelector('.dov-card-certs [data-caa]')?.dataset.caa), 'unrestricted', 'CAA state');
      const certs = await text(page, '.dov-card-certs');
      assert(/Allowed CAs\s*any CA \(CAA has no issue property\)/.test(certs) && /Wildcard certificates\s*no CA/.test(certs), certs);
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
        // a critical unknown tag: no CA, Let's Encrypt named or not
        assertEqual(await page.evaluate(() => document.querySelector('.dov-card-certs [data-caa]')?.dataset.caa), 'critical', 'CAA state');
        assert(/unknown tag marked critical \(tbs\): CAs must refuse/.test(await text(page, '.dov-card-certs')), await text(page, '.dov-card-certs'));
        // It runs again on the retried answer.
        await page.waitFor(() => !document.querySelector('.dov-card-health .dov-updating') && !!document.querySelector('.dov-score')
          && !document.querySelector('.dov-problem[data-id="ns.error"]'), { timeout: 15000, message: 'health follows the retried NS' });
        // Behind the critical tag even the CA that CAA names is blocked: the note says what to fix.
        await page.click('.dov-card-certs [data-action="dov-ct"]');
        await page.waitFor(() => document.querySelector('.dov-ct')?.dataset.ct === 'ok', { message: 'CT issuers' });
        assertEqual(await page.evaluate(() => [...document.querySelectorAll('.dov-issuer')].map((li) => li.dataset.verdict)), ['denied', 'denied'], 'CT verdicts');
        assert(/CAA’s critical flag blocks Let's Encrypt, Sectigo: their next renewal/.test(await text(page, '.dov-card-certs')), await text(page, '.dov-card-certs'));
      } finally {
        // the registry answers again, whatever happened above
        await page.evaluate(() => {
          window.__dnsHold = {};
          for (const open of [window.__openHealth, window.__openRdap]) if (open) open();
          window.__rdapGate = null;
        });
      }
    });

    run.group('Lookalike domains');
    const lkRows = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.lk-table tr.dt-row')].map((tr) => [
      tr.querySelector('.lk-name')?.dataset.name || '',
      { level: tr.querySelector('.lk-risk')?.dataset.level || '', text: tr.textContent.replace(/\s+/g, ' ').trim() }
    ])));
    const lkIdle = (message) => page.waitFor(() => !!document.querySelector('.lk-panel') && document.querySelector('[data-action="lk-stop"]').hidden
      && !document.querySelector('.lk-rdap:not([hidden])'), { timeout: 30000, message });
    const asked = (name, type) => page.evaluate((n, ty) => window.__dnsLog.filter((q) => q.name === n && (!ty || q.type === ty)).length, name, type);
    const setBudget = (value) => page.evaluate((v) => {
      const s = document.querySelector('[data-role="lk-budget"]');
      s.value = v;
      s.dispatchEvent(new Event('change', { bubbles: true }));
    }, value);

    await run.step('Find lookalikes loads the panel: the list is made in the page, nothing is sent, the workspace\'s own domain is marked', async () => {
      // example.net and example.org are recent domains of the workspace (built above; recorded again here)
      await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.recordRecent('example.org').then(() => state.recordRecent('example.net'))));
      await page.type('[data-role="dov-name"]', 'example.com');
      await page.click('[data-action="dov-run"]');
      await waitBuilt(page, 'example.com for its lookalikes');
      const before = await counts(page);
      await page.click('[data-action="lk-open"]');
      await page.waitFor(() => !!document.querySelector('.lk-panel [data-action="lk-check"]'), { message: 'lookalike panel' });
      assertEqual(await counts(page), before, 'nothing sent by opening it');
      const sent = await text(page, '.lk-sent');
      assert(/^300 names to check \(300 made by 13 techniques\). 2 of them are domains of your workspace: they are never checked or flagged. Nothing has been sent yet\.$/.test(sent), sent);
      assertEqual(await text(page, '[data-action="lk-check"]'), 'Check 298 names', 'check button');
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'lk-check', 'the focus on Check');
      await page.type('.lk-table .dt-search input', 'example.net');
      await page.waitFor(() => document.querySelectorAll('.lk-table tr.dt-row').length === 2
        && !!document.querySelector('.lk-table .lk-name[data-name="example.net"]'), { message: 'search: example.net and example.net.tr' });
      const own = (await lkRows())['example.net'];
      assert(own && own.level === 'own' && /Yours/.test(own.text) && /in your workspace/.test(own.text), JSON.stringify(own));
      await page.type('.lk-table .dt-search input', '');
      await shot(page, opts, 'domain-lookalikes-list-desktop-light-en');
    });

    await run.step('Check: NS for each name, A / AAAA / MX and RDAP only for the ones in DNS; worst first; a SERVFAIL is n/a with a Retry', async () => {
      await setBudget('100');
      await page.waitFor(() => /Check 98 names/.test(document.querySelector('[data-action="lk-check"]')?.textContent || ''), { message: 'budget 100' });
      await page.evaluate(() => { window.__rcodes['exampel.com|NS'] = 'SERVFAIL'; });
      const before = await counts(page);
      const ownAsked = await asked('example.net') + await asked('example.org');
      await page.click('[data-action="lk-check"]');
      await lkIdle('first check');
      const rows = await lkRows();
      const names = Object.keys(rows);
      assertEqual(names.slice(0, 3), ['exarnple.com', 'examp1e.com', 'exampel.com'], 'worst first; the names not in DNS hidden');
      assertEqual(rows['exarnple.com'].level, 'high', 'MX, web, registered 10 days ago');
      assert(/MX/.test(rows['exarnple.com'].text) && /New/.test(rows['exarnple.com'].text) && /mx\.exarnple\.com/.test(rows['exarnple.com'].text), rows['exarnple.com'].text);
      assertEqual(rows['examp1e.com'].level, 'low', 'on example.com\'s own name servers and address');
      assert(/Same NS/.test(rows['examp1e.com'].text) && /Same IP/.test(rows['examp1e.com'].text), rows['examp1e.com'].text);
      assertEqual(rows['exampel.com'].level, 'unknown', 'SERVFAIL');
      assert(await page.evaluate(() => !!document.querySelector('.lk-table .lk-risk[data-level="unknown"] [data-na="doh"]')), 'n/a in the row');
      assert(/1 lookup failed: DNS resolver: answered SERVFAIL/.test(await text(page, '.lk-failed')), await text(page, '.lk-failed'));
      assertEqual(await page.evaluate(() => document.querySelector('.lk-counts')?.dataset.registered), '2', 'two names in DNS');
      assertEqual(await asked('xample.com'), 1, 'a name not in DNS: one NS question');
      assertEqual(await asked('xample.com', 'MX'), 0, 'no MX for it');
      assertEqual(await asked('example.net') + await asked('example.org') - ownAsked, 0, 'nothing for the own domains');
      assertEqual([await asked('exarnple.com', 'A'), await asked('exarnple.com', 'MX')], [1, 1], 'A and MX for a name in DNS');
      const after = await counts(page);
      assertEqual([after.rdap - before.rdap, after.ct - before.ct], [2, 0], 'RDAP for the two names in DNS, no crt.sh');
      assert(/In DNS: 2 of 98 checked names — 1 high, 0 medium and 1 low risk\./.test(await text(page, '.lk-counts')), await text(page, '.lk-counts'));
    });

    await run.step('Retry asks only the failed lookup again; a larger list checks only the names added', async () => {
      await page.evaluate(() => { delete window.__rcodes['exampel.com|NS']; });
      const ns = await asked('exampel.com', 'NS');
      const all = (await counts(page)).dns;
      await page.click('[data-role="lk-retry"]');
      await page.waitFor(() => !document.querySelector('[data-role="lk-retry"]') && !document.querySelector('.lk-name[data-name="exampel.com"]'), { message: 'retried: not in DNS' });
      await lkIdle('retry ended');
      assertEqual(await asked('exampel.com', 'NS') - ns, 1, 'its NS asked again');
      assertEqual((await counts(page)).dns - all, 1, 'nothing else asked');
      // more on demand: every name (300); the 99 checked ones are not asked again
      await setBudget('300');
      await page.waitFor(() => /Check 200 names/.test(document.querySelector('[data-action="lk-check"]')?.textContent || ''), { message: 'budget 300' });
      await page.click('[data-action="lk-check"]');
      await lkIdle('second check');
      assertEqual(await asked('exarnple.com', 'NS'), 1, 'a checked name is not asked again');
      const idn = (await lkRows())['xn--exmple-4nf.com'];
      assert(idn && idn.level === 'high' && /exаmple\.com/.test(idn.text) && /IDN/.test(idn.text), JSON.stringify(idn));
      assert(/Every name in the list has been checked/.test(await text(page, '.lk-sent')), await text(page, '.lk-sent'));
      assert(await page.evaluate(() => document.querySelector('[data-action="lk-check"]').hidden), 'nothing left to check');
    });

    await run.step('certificates of the top names: one crt.sh search each, one at a time; CSV worst first with n/a', async () => {
      const ct = (await counts(page)).ct;
      await page.evaluate(() => { window.__ctLog = []; });
      assertEqual(await text(page, '[data-action="lk-ct"]'), 'Look up the certificates of the top 3', 'three names in DNS');
      await page.click('[data-action="lk-ct"]');
      await lkIdle('certificates');
      await page.waitFor(() => !document.querySelector('[data-action="lk-ct"]').disabled, { message: 'certificate round ended' });
      const urls = await page.evaluate(() => window.__ctLog);
      assertEqual(urls.map((u) => new URL(u).searchParams.get('q')), ['exarnple.com', 'xn--exmple-4nf.com', 'examp1e.com'], 'the worst first, one search each');
      assert(urls.every((u) => u.startsWith('https://crt.sh/?q=') && /&exclude=expired/.test(u)), urls.join(' '));
      assert(ct >= 0);
      const top = (await lkRows())['exarnple.com'];
      assert(/1 current certificate/.test(top.text) && /Certificate/.test(top.text), top.text);
      assert(/none current/.test((await lkRows())['examp1e.com'].text), 'none for the others');
      await page.click('[data-action="lk-csv"]');
      const [csv] = await takeDownloads(page);
      assert(csv && /^lookalikes-.*\.csv$/.test(csv.name) && csv.bom, csv && csv.name);
      const lines = csv.text.replace(/^﻿/, '').trimEnd().split('\r\n');
      assertEqual(lines[0], 'domain,unicode,technique,state,risk,score,reasons,registered,registrar,addresses,mx,ns,certificates,newestCertificate', 'header');
      assert(lines[1].startsWith('exarnple.com,exarnple.com,homoglyph,registered,high,100,mx web new cert,'), lines[1]);
      assertEqual(lines.length, 301, 'every name, the own one too');
      assert(lines.some((l) => l.startsWith('example.net,example.net,tld-swap,own,own,')), 'own row');
      await shot(page, opts, 'domain-lookalikes-checked-desktop-light-en');
    });

    await run.step('the list is kept across a language switch with no new request, in Turkish too', async () => {
      const before = await counts(page);
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('.lk-panel .lk-name[data-name="exarnple.com"]'), { message: 'the panel again, in Turkish' });
      assertEqual(await counts(page), before, 'nothing asked again');
      const row = (await lkRows())['exarnple.com'];
      assert(/Yüksek/.test(row.text) && /Yeni/.test(row.text) && /1 geçerli sertifika/.test(row.text), row.text);
      assert(/DNS’te olan: kontrol edilen 298 addan 3 tanesi — 2 yüksek, 0 orta ve 1 düşük risk\./.test(await text(page, '.lk-counts')), await text(page, '.lk-counts'));
      await shot(page, opts, 'domain-lookalikes-desktop-light-tr');
      await setLangUi(page, 'en');
      await page.waitFor(() => !!document.querySelector('.lk-panel .lk-name[data-name="exarnple.com"]'), { message: 'the panel again, in English' });
    });

    run.group('Customer report');
    const openReport = async () => {
      await page.click('.dov-head [data-action="report"]');
      await page.waitFor(() => !!document.querySelector('dialog.crep-modal[open]'), { message: 'report panel' });
    };
    await run.step('Report › Download HTML: one file, no script, the crafted SPF record escaped, no token, the permalink; nothing sent', async () => {
      await page.type('[data-role="dov-name"]', 'example.org');
      await page.click('[data-action="dov-run"]');
      await waitBuilt(page, 'example.org overview');
      const before = await counts(page);
      await openReport();
      assert(/nothing is sent/.test(await text(page, 'dialog.crep-modal')), await text(page, 'dialog.crep-modal'));
      await page.click('dialog.crep-modal [data-action="report-download"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'downloaded' });
      const [file] = await takeDownloads(page);
      assert(/^domain-overview-report-example\.org-\d{8}-\d{4}\.html$/.test(file.name), file.name);
      assert(/^text\/html/.test(file.type), file.type);
      assert(file.text.startsWith('<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;;'), file.text.slice(0, 200));
      assert(!/<script/i.test(file.text), 'no script in the file');
      assert(file.text.includes('Invalid terms: &lt;script&gt;alert(1)&lt;/script&gt;.'), 'the crafted TXT value, escaped');
      assert(!file.text.includes('E2ETOKENorg'), 'no verification token');
      assert(/<a href="http:\/\/[^"]+\/domainscope\/#\/domain\?name=example\.org" rel="noreferrer">/.test(file.text), 'the re-run link');
      assert(/<section class="crep-card crep-section crep-problems" data-section="problems">/.test(file.text), 'problems first');
      assertEqual(await counts(page), before, 'nothing sent');
      assert(await page.evaluate(() => !document.querySelector('dialog.crep-modal')), 'the panel closed');
    });

    await run.step('Report › Print / save as PDF: the report alone on paper, styled, not on screen; gone after printing', async () => {
      const sheets = await page.evaluate(() => {
        window.__prints = [];
        window.print = () => window.__prints.push(document.querySelector('.crep-print-host')?.shadowRoot?.textContent || null);
        return document.adoptedStyleSheets.length;
      });
      await openReport();
      await page.click('dialog.crep-modal [data-action="report-print"]');
      await page.waitFor(() => window.__prints.length === 1, { message: 'printed' });
      const printed = await page.evaluate(() => window.__prints[0]);
      assert(printed && printed.includes('Invalid terms: <script>alert(1)</script>.') && printed.includes('Problems and advice'), String(printed).slice(0, 300));
      await page.send('Emulation.setEmulatedMedia', { media: 'print' });
      const paper = await page.evaluate(() => {
        const root = document.querySelector('.crep-print-host').shadowRoot;
        const subject = root.querySelector('.crep-subject');
        return {
          shown: [...document.body.children].filter((el) => getComputedStyle(el).display !== 'none').map((el) => el.className),
          scripts: root.querySelectorAll('script').length, subject: subject.textContent, weight: getComputedStyle(subject).fontWeight
        };
      });
      await page.send('Emulation.setEmulatedMedia', { media: '' });
      assertEqual(paper, { shown: ['crep-print-host'], scripts: 0, subject: 'example.org', weight: '700' }, 'on paper');
      // On screen the host is hidden; or already gone, when Chrome reported the end of print media (matchMedia) before this ran.
      assertEqual(await page.evaluate(() => { const host = document.querySelector('.crep-print-host'); return host ? getComputedStyle(host).display : 'none'; }), 'none', 'not on screen');
      await page.evaluate(() => window.dispatchEvent(new Event('afterprint')));
      assertEqual(await page.evaluate(() => [!!document.querySelector('.crep-print-host'), document.adoptedStyleSheets.length]), [false, sheets], 'gone after printing');
    });

    await run.step('in Turkish: the panel and the file in Turkish; unticked, the file has no link', async () => {
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('.dov-head [data-action="report"]'), { message: 'kept after the language switch' });
      await openReport();
      assertEqual(await text(page, 'dialog.crep-modal .modal-title'), 'Müşteri raporu', 'title');
      await page.evaluate(() => document.querySelector('dialog.crep-modal [data-role="report-link"]').click());
      await page.click('dialog.crep-modal [data-action="report-download"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'downloaded' });
      const [file] = await takeDownloads(page);
      assert(file.text.startsWith('<!doctype html>\n<html lang="tr">') && file.text.includes('Sorunlar ve öneriler') && file.text.includes('Geçersiz ifadeler: &lt;script&gt;'), file.text.slice(0, 200));
      assert(!/<script/i.test(file.text) && !file.text.includes('<a '), 'no script, no link');
      await setLangUi(page, 'en');
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
