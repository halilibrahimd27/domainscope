#!/usr/bin/env node
/**
 * portfolio.e2e.mjs — end-to-end test of the "Domain portfolio" view in a real headless Chrome/Edge.
 * OFFLINE: every DoH query is answered in the page by a fake resolver built from the zone below
 * (window.fetch wrapped before the app loads), the RDAP bootstrap and registry by the same wrapper;
 * every other https:// request is blocked, and every request that leaves the page's origin is
 * counted through CDP.
 *
 *   node tests/e2e/portfolio.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry (the first of Watch & report), the box filled in from the
 * workspace's recent domains, a shared link that only fills it ("Nothing has been sent yet");
 * Check portfolio over three domains (example.com, example.org, example-test.com.tr): rows fill as
 * the lookups land; the expiry countdown coloured by the days left, a missing transfer lock, the
 * name servers' own domain (example.net, served to all three) asked of RDAP once and its expiry in
 * every row, the .tr row honest about having no RDAP (the registry's WHOIS instead), DNSSEC, CAA,
 * SPF / DMARC / DKIM / MTA-STS / TLS-RPT, a parked domain locked down; an RDAP 503 and a CAA
 * SERVFAIL as "⚠ n/a" with a Retry that asks only that cell's lookup; sort, the Domains tab's
 * read-only figures, the status summary and the Show select as the filters; the CSV, JSON and .ics
 * exports from the result header's Export menu (RFC 5545: CRLF, lines folded within 75 octets, a stable UID per domain,
 * the alarms 30 and 7 days before); the policy: a preset, the rule controls and the JSON kept in
 * step and in the workspace, a rule that does not exist said and left out, the matrix with the
 * evidence of each cell and its CSV; Copy summary; Esc stops a run (rows not looked up offer
 * "Look up"); the Certificates (CT) tab (ui/ctwatch-panel.js, loaded on its first use) over a fake
 * Cert Spotter and crt.sh answered in the page: nothing sent before Check CT, Cert Spotter one
 * request at a time and crt.sh after its 429, the figures, the status summary and flags (new since the workspace's
 * baseline, an unexpected CA, a wildcard, a precertificate only, a superseded certificate), the
 * radar's colours, a domain both sources failed as "⚠ n/a" with a Retry of that domain, the
 * baseline written to the workspace and a second check with nothing new, the CSV and the .ics
 * (a UID per name set, reminders on the radar's days); 375 / 320 px without horizontal scroll,
 * TR / EN × light / dark; offline, the shell's note and Check portfolio sending nothing (Check CT
 * neither); zero console errors / CSP violations / missing i18n keys, nothing sent outside the page.
 *
 * Data is documentation space only (example.com / .net / .org, example-test.com.tr, 192.0.2.0/24,
 * 198.51.100.0/24, 203.0.113.0/24).
 */

import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { launchBrowser } from './cdp.mjs';
import { spotterRow, crtshRow } from '../js/ct-fake.mjs';
import { certId, CT_EXPORT_COLUMNS } from '../../assets/js/lib/ctwatch.js';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, resultAction, setLangUi, shot, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';

const DAY = 86400000;
const NOW = Date.now();
// half a day past the count, so a run a few minutes later still counts the same whole days
const iso = (days) => new Date(NOW + days * DAY + DAY / 2).toISOString().replace(/\.\d{3}Z$/, 'Z');
const DNSKEY = { flags: 257, protocol: 3, algorithm: 13, publicKey: Buffer.alloc(64, 7).toString('base64') };
const KEY_TAG = decodeMessage(encodeMessage({ answers: [{ name: 'example.com', type: 'DNSKEY', ttl: 300, data: DNSKEY }] })).answers[0].data.keyTag;
const DOMAINS = ['example.com', 'example.org', 'example-test.com.tr'];

/** Three zones on one provider's name servers (ns*.example.net). */
const ZONE = {
  'example.com': {
    NS: ['ns1.example.net', 'ns2.example.net'],
    DS: [{ keyTag: KEY_TAG, algorithm: 13, digestType: 2, digest: 'ab'.repeat(32) }],
    DNSKEY: [DNSKEY],
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }],
    MX: [{ preference: 10, exchange: 'mx.example.com' }],
    TXT: [['v=spf1 include:_spf.example.net -all'], ['site-verification=e2e']]
  },
  '_spf.example.net': { TXT: [['v=spf1 ip4:192.0.2.0/24 -all']] },
  'mx.example.com': { A: ['192.0.2.25'] },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']] },
  'google._domainkey.example.com': { TXT: [['v=DKIM1; k=rsa; p=MIIBIjANBgkqh']] },
  '_mta-sts.example.com': { TXT: [['v=STSv1; id=20261001']] },
  '_smtp._tls.example.com': { TXT: [['v=TLSRPTv1; rua=mailto:tls@example.com']] },
  'example.org': {
    NS: ['ns1.example.net', 'ns.example.org'],
    MX: [{ preference: 0, exchange: '.' }],
    // takes no mail but ends its SPF with ~all: the lock-down is missing -all
    TXT: [['v=spf1 ~all']]
  },
  '_dmarc.example.org': { TXT: [['v=DMARC1; p=reject']] },
  // its second name server sits under a domain nobody has registered (the classic takeover)
  'example-test.com.tr': {
    NS: ['ns1.example.net', 'ns1.example.test'],
    MX: [{ preference: 10, exchange: 'mx.example-test.com.tr' }],
    TXT: [['v=spf1 ~all']]
  },
  'mx.example-test.com.tr': { A: ['203.0.113.25'] }
};
const SIGNED = ['example.com'];

const rdapJson = (domain, status, days) => ({
  objectClassName: 'domain', ldhName: domain.toUpperCase(), status,
  events: [{ eventAction: 'registration', eventDate: '2001-05-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: iso(days) }],
  entities: [{ objectClassName: 'entity', roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar, Inc.']]], publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }] }],
  secureDNS: { delegationSigned: domain === 'example.com' }
});
const RDAP = {
  // the registry's transfer prohibition alone (serverTransferProhibited): transfers are prohibited all the
  // same, but it is a partial registry lock (a registry lock is server transfer, update and delete prohibited)
  'example.com': rdapJson('example.com', ['server transfer prohibited', 'client delete prohibited'], 400),
  // no transfer lock: a hijack risk; expires in 20 days
  'example.org': rdapJson('example.org', ['active'], 20),
  // the name servers' domain: expires in 12 days
  'example.net': rdapJson('example.net', ['client transfer prohibited'], 12)
};

/** Certificate Transparency for the CT tab: Cert Spotter rows of example.com and example.org, crt.sh's of example-test.com.tr. */
const LE = "C=US, O=Let's Encrypt, CN=R11";
const OTHER_CA = 'C=US, O=Example Other CA, CN=Example Other CA R3';
const CT_CERTS = {
  // renewed by B: superseded
  A: { names: ['example.com', 'www.example.com'], notBefore: iso(-80), notAfter: iso(10), serial: 1, issuer: LE },
  B: { names: ['example.com', 'www.example.com'], notBefore: iso(-5), notAfter: iso(85), serial: 2, issuer: LE },
  // 5 days left: the radar's last band
  C: { names: ['*.example.com'], notBefore: iso(-85), notAfter: iso(5), serial: 3, issuer: LE },
  // another CA, logged only as a precertificate
  D: { names: ['shop.example.com'], notBefore: iso(-2), notAfter: iso(88), serial: 4, issuer: OTHER_CA, friendly: 'Example Other CA', precert: true },
  E: { names: ['example.org', 'www.example.org'], notBefore: iso(-30), notAfter: iso(60), serial: 5, issuer: LE }
};
/** A certificate as a crt.sh row has it: dates in UTC without a zone, the serial in hex. */
const crtOf = (c) => ({ names: c.names, notBefore: c.notBefore.replace(/Z$/, ''), notAfter: c.notAfter.replace(/Z$/, ''), serial: c.serial.toString(16).padStart(2, '0'), issuer: c.issuer });
const CT = {
  spotter: {
    'example.com': ['A', 'B', 'C', 'D'].map((k) => spotterRow(CT_CERTS[k])),
    'example.org': [spotterRow(CT_CERTS.E)]
  },
  // crt.sh lists the same certificates (one row each, `deduplicate=Y`): the same ids, so a check
  // that falls back to it marks nothing new
  crtsh: {
    'example.com': ['A', 'B', 'C', 'D'].map((k, i) => crtshRow({ id: 9101 + i, ...crtOf(CT_CERTS[k]) })),
    'example.org': [crtshRow({ id: 9201, ...crtOf(CT_CERTS.E) })],
    'example-test.com.tr': [crtshRow({ id: 9001, names: ['example-test.com.tr', 'www.example-test.com.tr'], notBefore: iso(-10).replace(/Z$/, ''), notAfter: iso(80).replace(/Z$/, ''), serial: '06', issuer: LE })]
  }
};
/** The workspace's baseline: example.com checked a week ago, with A and C. */
const CT_SEEN = JSON.stringify({
  v: 1,
  domains: { 'example.com': { at: new Date(NOW - 7 * DAY).toISOString(), ids: { [certId({ intermediate: 'R11', serialHex: '01' })]: iso(10).slice(0, 10), [certId({ intermediate: 'R11', serialHex: '03' })]: iso(5).slice(0, 10) } } }
});

/** In-page stubs: DoH from the zone (NXDOMAIN outside it), the RDAP bootstrap and registry, Cert Spotter and crt.sh. */
export const fakeScript = () => `(() => {
  const Z = ${JSON.stringify(ZONE)};
  const SIGNED = ${JSON.stringify(SIGNED)};
  const RDAP = ${JSON.stringify(RDAP)};
  const CT = ${JSON.stringify(CT)};
  window.__ctLog = [];
  window.__ctStatus = {};
  window.__dnsLog = [];
  window.__rdapLog = [];
  window.__rcodes = {};
  window.__rdapStatus = {};
  window.__dnsDelay = 0;
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/rdap+json' } });
  const wait = (ms, signal) => new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
  });
  const ctJson = (v, status = 200, headers = {}) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json', ...headers } });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://api.certspotter.com/v1/issuances?')) {
      const u = new URL(url);
      const d = u.searchParams.get('domain');
      window.__ctLog.push({ source: 'certspotter', domain: d, after: u.searchParams.get('after'), subdomains: u.searchParams.get('include_subdomains'), expand: u.searchParams.getAll('expand') });
      const status = window.__ctStatus['certspotter|' + d];
      if (status) return ctJson({ code: 'rate_limited', message: 'Rate limit exceeded' }, status, { 'retry-after': '5' });
      return ctJson(u.searchParams.get('after') ? [] : (CT.spotter[d] || []));
    }
    if (url.startsWith('https://crt.sh/?')) {
      const d = (new URL(url).searchParams.get('q') || '').replace(/^%[.]/, '');
      window.__ctLog.push({ source: 'crtsh', domain: d });
      const status = window.__ctStatus['crtsh|' + d];
      if (status) return new Response('Too Many Requests', { status, headers: { 'retry-after': '120' } });
      return ctJson(CT.crtsh[d] || []);
    }
    if (url.startsWith('https://data.iana.org/rdap/')) return json({ services: [[['com', 'net', 'org', 'test'], ['https://rdap.example.net/']]] });
    if (url.startsWith('https://rdap.example.net/') || url.startsWith('https://rdap.org/')) {
      const name = decodeURIComponent(url.split('/domain/')[1] || '');
      window.__rdapLog.push(name);
      const status = window.__rdapStatus[name];
      if (status) return json({ errorCode: status }, status);
      return RDAP[name] ? json(RDAP[name]) : json({ errorCode: 404 }, 404);
    }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const qname = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__dnsLog.push({ name: qname, type: q.type });
    if (window.__dnsDelay) await wait(window.__dnsDelay, init?.signal);
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
  const V = await import('../../assets/js/views/portfolio.js');
  run.group('Node: views/portfolio.js');
  await run.step('a link\'s list, the share params (capped), the calendar events worded', () => {
    assertEqual(V.linkText('example.com, example.org;example.net'), 'example.com\nexample.org\nexample.net', 'link text');
    assertEqual(V.shareParams(['example.com', 'example.org']), { domains: 'example.com,example.org' }, 'share params');
    assertEqual(V.shareParams(Array.from({ length: V.MAX_LINK_DOMAINS + 1 }, (_, i) => `d${i}.example.com`)), {}, 'a long list stays out of the URL');
  });
}

const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);
const counts = (page) => page.evaluate(() => ({ dns: window.__dnsLog.length, rdap: window.__rdapLog.length }));
/** One row of the table: its cells' text by column class, and what failed. */
const rowOf = (page, domain) => page.evaluate((d) => {
  const tr = [...document.querySelectorAll('.pf-table tbody tr.dt-row')].find((r) => r.querySelector('.pf-domain')?.textContent === d);
  if (!tr) return null;
  const out = { risk: [...tr.classList].find((c) => c.startsWith('pf-risk-')) || null };
  for (const td of tr.querySelectorAll('td')) {
    const col = [...td.classList].find((c) => c.startsWith('pf-col-'));
    if (col) out[col.slice(7)] = td.textContent.replace(/\s+/g, ' ').trim();
  }
  out.failed = [...tr.querySelectorAll('.pf-na')].map((x) => x.dataset.failed);
  out.days = tr.querySelector('.pf-expiry')?.dataset.days ?? null;
  return out;
}, domain);
const waitDone = (page, message = 'portfolio checked') => page.waitFor(() => !!document.querySelector('.pf-head[data-status="done"], .pf-head[data-status="stopped"]')
  && !document.querySelector('[data-action="pf-run"]').hidden && !document.querySelector('.pf-pending'), { timeout: 40000, message });

/** The CT tab: its check done (or stopped) and Check CT back. */
const waitCt = (page, message = 'CT checked') => page.waitFor(() => !!document.querySelector('.pf-ct .pf-head[data-status="done"], .pf-ct .pf-head[data-status="stopped"]')
  && !document.querySelector('[data-action="ct-run"]').hidden, { timeout: 40000, message });
/** The CT tab's figures (its read-only metric strip): a zero folded into "None: …" reads '0'. */
const ctTiles = (page) => page.evaluate(() => {
  const strip = document.querySelector('.pf-ct-tiles');
  const out = Object.fromEntries([...strip.querySelectorAll('[data-metric]')].map((el) => [el.dataset.metric, el.querySelector('.metric-value').textContent.trim()]));
  for (const id of (strip.querySelector('.metric-zero')?.dataset.folded || '').split(' ').filter(Boolean)) out[id] = '0';
  return out;
});
/** The CT table's rows: the names, the flags and the radar band of each. */
const ctRows = (page) => page.evaluate(() => [...document.querySelectorAll('.pf-ct-table tbody tr.dt-row')].map((tr) => ({
  names: [...tr.querySelectorAll('td.pf-ct-names .mono')].map((e) => e.textContent).join(' '),
  flags: [...tr.querySelectorAll('[data-flag]')].map((e) => e.dataset.flag),
  band: ([...tr.classList].find((c) => c.startsWith('pf-ct-band-')) || '').replace('pf-ct-band-', '') || null
})));
const setCtFilter = (page, value) => page.evaluate((v) => { const s = document.querySelector('[data-role="ct-filter"]'); s.value = v; s.dispatchEvent(new Event('change')); }, value);

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
    await run.step('the first nav entry of Watch & report; the box filled in from the workspace\'s recent domains; nothing sent', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      // what the workspace worked on before (the most recent first)
      await page.evaluate(() => import('./assets/js/state.js').then(async ({ state }) => {
        for (const d of ['example-test.com.tr', 'www.example.org', 'example.com']) await state.recordRecent(d);
        await state.setWorkspaceData('policy', '');
      }));
      await gotoRoute(page, 'portfolio');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/reports"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '').split('?')[0]) : [];
      });
      assertEqual(nav, ['portfolio', 'monitor', 'reports'], 'Watch & report group');
      assertEqual(await text(page, 'h1'), 'Domain portfolio', 'title');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="pf-domains"]').value), DOMAINS.join('\n'), 'recent domains, most recent first');
      assert(await page.evaluate(() => !!document.querySelector('[data-note="prefilled"]')), 'says where the list came from');
      assert(/3 domains/.test(await text(page, '.pf-box-status')), 'counted');
      assert(await page.evaluate(() => !!document.querySelector('.pf-empty .tool-empty')), 'empty state');
      assertEqual(await counts(page), { dns: 0, rdap: 0 }, 'nothing sent');
      await shot(page, opts, 'portfolio-empty-desktop-light-en');
    });

    await run.step('a shared link only fills the box and says nothing was sent; junk is said and left out', async () => {
      await page.evaluate(() => { document.querySelector('[data-role="pf-domains"]').value = ''; document.querySelector('[data-role="pf-domains"]').dispatchEvent(new Event('input')); });
      await gotoRoute(page, '#/portfolio?domains=example.com,example.org,example-test.com.tr');
      await page.waitFor(() => !!document.querySelector('.pf-prompt [data-prompt="link"]'), { message: 'link prompt' });
      assert(/look up 3 domains\. Nothing has been sent yet\./.test(await text(page, '.pf-prompt')), await text(page, '.pf-prompt'));
      assertEqual(await counts(page), { dns: 0, rdap: 0 }, 'still nothing sent');
      await page.type('[data-role="pf-domains"]', 'example.com\n192.0.2.1\nexample.com');
      await page.waitFor(() => /Not a domain, left out: 192\.0\.2\.1/.test(document.querySelector('.pf-box-status')?.textContent || ''), { message: 'junk said' });
      await page.type('[data-role="pf-domains"]', `${DOMAINS.join('\n')}\nwww.example.com`);
    });

    await run.step('Check portfolio: rows fill; countdowns, locks, the name servers\' domain once for all, no RDAP for .tr, the mail posture', async () => {
      await page.evaluate(() => { window.__rdapStatus['example.org'] = 503; window.__rcodes['example-test.com.tr|CAA'] = 'SERVFAIL'; });
      await page.click('[data-action="pf-run"]');
      await page.waitFor(() => !document.querySelector('[data-action="pf-stop"]').hidden || !!document.querySelector('.pf-head'), { message: 'running' });
      await waitDone(page);
      assert(/#\/portfolio\?domains=example\.com%2Cexample\.org%2Cexample-test\.com\.tr$|#\/portfolio\?domains=example\.com,example\.org,example-test\.com\.tr$/.test(await page.evaluate(() => location.hash)), await page.evaluate(() => location.hash));
      assertEqual(await page.evaluate(() => document.querySelectorAll('.pf-table tbody tr.dt-row').length), 3, 'one row each (www.example.com is example.com)');
      const rdap = await page.evaluate(() => window.__rdapLog.slice());
      assertEqual(rdap.filter((d) => d === 'example.net').length, 1, 'the name servers\' domain asked once for all three');
      assertEqual(rdap.filter((d) => d === 'example.com').length, 1, 'example.com once');
      assert(!rdap.includes('example-test.com.tr'), 'no RDAP request for .tr');
      assertEqual(rdap.filter((d) => d === 'example.test').length, 1, 'the unregistered name server domain asked once');

      const com = await rowOf(page, 'example.com');
      assert(/400 days left/.test(com.expiry) && com.days === '400', `expiry: ${com.expiry}`);
      assert(/Partial registry lock/.test(com.status) && !/No transfer lock/.test(com.status) && /Example Registrar, Inc\./.test(com.registrar), JSON.stringify(com));
      assert(/Validated/.test(com.dnssec), com.dnssec);
      assert(/example\.net\s*12 days left/.test(com.ns), `ns: ${com.ns}`);
      assertEqual(com.risk, 'pf-risk-ns-expiring', 'its name servers\' domain lapses in 12 days');
      assert(/letsencrypt\.org/.test(com.caa) && /-all/.test(com.spf) && /1\/10 lookups/.test(com.spf), JSON.stringify(com));
      assert(/p=reject/.test(com.dmarc) && /google/.test(com.dkim) && /MTA-STS yes/.test(com.mtaSts) && /TLS-RPT yes/.test(com.mtaSts), JSON.stringify(com));
      assert(/Receives mail/.test(com.parked), com.parked);

      const org = await rowOf(page, 'example.org');
      assertEqual(org.failed, ['rdap', 'rdap', 'rdap'], 'expiry, status and registrar: n/a with a Retry');
      assert(/RDAP: answered HTTP 503/.test(await page.evaluate(() => [...document.querySelectorAll('.pf-table .na-mark')].map((m) => m.title).join('\n'))), 'the reason');
      assert(/Missing: -all/.test(org.parked), `parked: ${org.parked}`);
      assert(/example\.org\s*own/.test(org.ns) && /example\.net\s*12 days left/.test(org.ns), org.ns);

      const tr = await rowOf(page, 'example-test.com.tr');
      assert(/No RDAP/.test(tr.expiry) && /WHOIS: TRABİS/.test(tr.expiry), `tr: ${tr.expiry}`);
      assert(/Partial: no RDAP/.test(tr.domain), `the row says it is partial: ${tr.domain}`);
      assert(!/Partial/.test(com.domain), 'only the row without RDAP');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.pf-whois')].map((a) => a.getAttribute('href'))), ['https://www.trabis.gov.tr/whois'], 'WHOIS link');
      assertEqual(tr.failed, ['caa'], 'CAA SERVFAIL: n/a');
      assertEqual(tr.risk, 'pf-risk-ns-unregistered', 'a name server domain nobody registered: the row says so first');
      assert(/example\.test\s*Not registered/.test(tr.ns) && /NS domain not registered/.test(tr.domain), `${tr.ns} | ${tr.domain}`);
      assert(/No DMARC/.test(tr.dmarc) && /~all/.test(tr.spf), JSON.stringify(tr));
      await shot(page, opts, 'portfolio-results-desktop-light-en');
    });

    await run.step('Retry asks only that cell\'s lookup, past the cache; the keyboard focus stays in the row', async () => {
      await page.evaluate(() => { delete window.__rdapStatus['example.org']; });
      const before = await counts(page);
      await page.evaluate(() => document.querySelector('.pf-table [data-cell="expiry"][data-domain="example.org"]').focus());
      await page.press('Enter');
      await page.waitFor(() => { const tr = [...document.querySelectorAll('.pf-table tbody tr.dt-row')].find((r) => r.querySelector('.pf-domain')?.textContent === 'example.org'); return tr && /20 days left/.test(tr.textContent); }, { timeout: 15000, message: 'example.org registration' });
      const after = await counts(page);
      assertEqual([after.rdap - before.rdap, after.dns - before.dns], [1, 0], 'one RDAP request, no DNS');
      const org = await rowOf(page, 'example.org');
      assert(/No transfer lock/.test(org.status), org.status);
      assertEqual(org.risk, 'pf-risk-expiring', 'expires in 20 days');
      // the row is drawn again without the Retry: the focus goes to its domain, never to the page
      await page.waitFor(() => document.activeElement?.closest('.pf-table') && document.activeElement.classList.contains('pf-domain')
        && document.activeElement.textContent === 'example.org', { message: 'focus on the row' });
      // the CAA cell of the .tr row: CAA alone
      await page.evaluate(() => { delete window.__rcodes['example-test.com.tr|CAA']; });
      const n = await counts(page);
      await page.click('.pf-table [data-cell="caa"][data-domain="example-test.com.tr"]');
      await page.waitFor(() => !document.querySelector('.pf-table [data-cell="caa"]'), { message: 'CAA filled' });
      const q = await page.evaluate((k) => window.__dnsLog.slice(k).map((x) => `${x.name}|${x.type}`), n.dns);
      assertEqual([...new Set(q)], ['example-test.com.tr|CAA'], 'CAA only');
    });

    await run.step('sort by expiry; the figures, the status summary and the Show select', async () => {
      await page.click('.pf-table th[data-key="expiry"] .dt-sort');
      const order = await page.evaluate(() => [...document.querySelectorAll('.pf-table tbody .pf-domain')].map((d) => d.textContent));
      assertEqual(order, ['example.org', 'example.com', 'example-test.com.tr'], 'soonest first, the unknown last');
      assertEqual(await page.evaluate(() => document.querySelector('.pf-tiles [data-metric="expiring"] .metric-value').textContent), '1', 'one domain expires within 30 days');
      await page.click('.pf-head .status-item[data-status="ns"]');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.pf-table tbody tr.dt-row').length), 3, 'every zone is served from example.net');
      await page.click('.pf-head .status-item[data-status="unlocked"]');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.pf-table tbody .pf-domain')].map((d) => d.textContent)), ['example.org'], 'no transfer lock');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="pf-filter"]').value), 'unlocked', 'the select follows');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.pf-head .status-item[aria-pressed="true"]')].map((b) => b.dataset.status)), ['unlocked'], 'pressed');
      await page.evaluate(() => { const s = document.querySelector('[data-role="pf-filter"]'); s.value = 'all'; s.dispatchEvent(new Event('change')); });
      assertEqual(await page.evaluate(() => document.querySelectorAll('.pf-table tbody tr.dt-row').length), 3, 'all again');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.pf-head .status-item[aria-pressed="true"]').length), 0, 'none pressed');
    });

    await run.step('exports: CSV, JSON and the .ics calendar (CRLF, folded within 75 octets, a UID per domain, alarms 30 and 7 days before)', async () => {
      await takeDownloads(page);
      await resultAction(page, '[data-action="pf-csv"]', '.pf-head');
      await resultAction(page, '[data-action="pf-json"]', '.pf-head');
      await resultAction(page, '[data-action="pf-ics"]', '.pf-head');
      await page.waitFor(() => (window.__downloads || []).length === 3, { message: 'three downloads' });
      const [csv, json, ics] = await takeDownloads(page);
      assert(/^domain-portfolio-.*\.csv$/.test(csv.name) && csv.bom, csv.name);
      assert(csv.text.startsWith('domain,registration,registrar,registrarClass,expires,daysLeft,risk,'), csv.text.slice(0, 80));
      assert(/\r\nexample\.org,ok,"Example Registrar, Inc\.",/.test(csv.text), 'the rows shown, sorted');
      const doc = JSON.parse(json.text);
      assertEqual([doc.format, doc.domains.length, doc.domains[0].domain], ['domainscope-portfolio', 3, 'example.org'], 'JSON');
      assert(/\.ics$/.test(ics.name) && /text\/calendar/.test(ics.type), `${ics.name} ${ics.type}`);
      const t = ics.text;
      assert(t.startsWith('BEGIN:VCALENDAR\r\nVERSION:2.0\r\n') && t.endsWith('END:VCALENDAR\r\n'), 'a calendar with CRLF');
      assert(!/[^\r]\n/.test(t), 'never a bare LF');
      const octets = t.split('\r\n').map((l) => new TextEncoder().encode(l).length);
      assert(Math.max(...octets) <= 75, `folded: ${Math.max(...octets)} octets`);
      const unfolded = t.replace(/\r\n /g, '');
      assertEqual(unfolded.match(/^UID:.*$/gm).map((l) => l.trim()), ['UID:expiry-example.net@domainscope', 'UID:expiry-example.org@domainscope', 'UID:expiry-example.com@domainscope'], 'one event per domain, the name servers\' domain too, soonest first');
      assertEqual((t.match(/TRIGGER:-P30D/g) || []).length, 3, '30 days before');
      assertEqual((t.match(/TRIGGER:-P7D/g) || []).length, 3, '7 days before');
      const nsSummary = (/^SUMMARY:example\.net expires \(name servers of (.*)\)\r?$/m.exec(unfolded) || [])[1] || '';
      assertEqual(nsSummary.split('\\, ').sort(), ['example-test.com.tr', 'example.com', 'example.org'], 'the name servers\' domain says whose');
    });

    await run.step('the policy: a preset; the rules and the JSON in step and kept in the workspace; the matrix with its evidence', async () => {
      await page.click('.pf-results .tab[data-tab="policy"]');
      await page.waitFor(() => !!document.querySelector('.pf-pol-card'), { message: 'policy tab' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-matrix="no-rules"]') ? 'no-rules' : null), 'no-rules', 'no rule yet');
      await page.click('[data-preset="baseline"]');
      await page.waitFor(() => !!document.querySelector('.pf-matrix'), { message: 'matrix' });
      const json = JSON.parse(await page.evaluate(() => document.querySelector('[data-role="pf-policy-json"]').value));
      assertEqual(json.name, 'baseline', 'the preset\'s JSON');
      assertEqual(json.rules.expiryDays, '>= 30', 'its rules');
      assert(await page.evaluate(() => document.querySelector('.pf-pol-rule[data-rule="transferLock"] input[type="checkbox"]').checked), 'the controls follow');
      await page.waitFor(() => import('./assets/js/state.js').then(({ state }) => /"baseline"/.test(state.workspaceData('policy'))), { message: 'kept in the workspace' });
      const cells = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.pf-matrix tbody tr.dt-row')].map((tr) => [
        tr.querySelector('td strong').textContent,
        Object.fromEntries([...tr.querySelectorAll('[data-rule]')].map((c) => [c.dataset.rule, c.dataset.status]))
      ])));
      assertEqual(cells['example.com'], { expiryDays: 'pass', transferLock: 'pass', 'status.critical': 'pass', nsExpiryDays: 'fail', spf: 'pass', 'spf.lookups': 'pass', 'dmarc.policy': 'pass' }, 'example.com');
      assertEqual(cells['example.org'], { expiryDays: 'fail', transferLock: 'fail', 'status.critical': 'pass', nsExpiryDays: 'fail', spf: 'pass', 'spf.lookups': 'pass', 'dmarc.policy': 'pass' }, 'example.org');
      assertEqual(cells['example-test.com.tr'], { expiryDays: 'unknown', transferLock: 'unknown', 'status.critical': 'unknown', nsExpiryDays: 'fail', spf: 'pass', 'spf.lookups': 'pass', 'dmarc.policy': 'fail' }, 'the .tr domain: registration not known');
      const evidence = await page.evaluate(() => [...document.querySelectorAll('.pf-matrix [data-rule="expiryDays"][data-status="fail"] .pf-evidence')].map((e) => e.textContent));
      assert(/^20 days left \(\d{4}-\d{2}-\d{2}\)$/.test(evidence[0] || ''), `evidence: ${evidence}`);
      assertEqual(await text(page, '.pf-matrix-counts'), '3 of 3 domains fail the policy', 'matrix counts (the empty ones left out)');
      // one control changed: the JSON follows
      await page.evaluate(() => { const c = document.querySelector('.pf-pol-rule[data-rule="nsExpiryDays"] input[type="checkbox"]'); c.click(); });
      await page.waitFor(() => !/nsExpiryDays/.test(document.querySelector('[data-role="pf-policy-json"]').value), { message: 'rule off in the JSON' });
      // a rule that does not exist, typed in the JSON: said and left out, the rest kept
      await page.evaluate(() => {
        const box = document.querySelector('[data-role="pf-policy-json"]');
        box.value = '{ "name": "e2e", "rules": { "expiryDays": ">= 30", "dnsec": "signed", "dmarc.policy": ">= quarantine" } }';
        box.dispatchEvent(new Event('input'));
      });
      await page.waitFor(() => /Unknown rule “dnsec”/.test(document.querySelector('.pf-pol-status')?.textContent || ''), { message: 'unknown rule said' });
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.pf-pol-rule.is-on')].map((r) => r.dataset.rule)), ['expiryDays', 'dmarc.policy'], 'the controls follow the JSON');
      await page.waitFor(() => document.querySelectorAll('.pf-matrix thead th').length === 4, { message: 'two rules in the matrix' });
      await shot(page, opts, 'portfolio-policy-desktop-light-en');
      await takeDownloads(page);
      await page.click('[data-action="pf-matrix-csv"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'matrix CSV' });
      const [mcsv] = await takeDownloads(page);
      const lines = mcsv.text.replace(/^\uFEFF/, '').trimEnd().split('\r\n');
      assertEqual(lines[0], 'Domain,Failed,Not known,Passed,expiryDays (>= 30),dmarc.policy (>= quarantine)', 'matrix CSV header');
      assert(lines.some((l) => /^example\.org,1,0,1,FAIL · 20 days left/.test(l)), lines.join('\n'));
      // a value typed into a rule that is off turns it on; a list takes its entries between semicolons
      // (a registrar's name has commas)
      await page.evaluate(() => {
        const input = document.querySelector('.pf-pol-rule[data-rule="registrar"] .pf-pol-list');
        input.focus();
        input.value = 'Example Registrar, Inc.; Other Registrar';
        input.dispatchEvent(new Event('input'));
      });
      await page.waitFor(() => /"registrar"/.test(document.querySelector('[data-role="pf-policy-json"]').value), { message: 'the rule turned on by its value' });
      assert(await page.evaluate(() => document.querySelector('.pf-pol-rule[data-rule="registrar"] input[type="checkbox"]').checked), 'ticked');
      assertEqual(JSON.parse(await page.evaluate(() => document.querySelector('[data-role="pf-policy-json"]').value)).rules.registrar,
        ['Example Registrar, Inc.', 'Other Registrar'], 'the comma inside a name stays');
      await page.waitFor(() => document.querySelectorAll('.pf-matrix thead th').length === 5, { message: 'three rules in the matrix' });
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.pf-matrix [data-rule="registrar"]')].map((c) => c.dataset.status).sort()), ['pass', 'pass', 'unknown'],
        'the registrar rule: met twice, not known without RDAP');
      // the policy column of the domains table
      await page.click('.pf-results .tab[data-tab="domains"]');
      assert(/1 rule fails/.test((await rowOf(page, 'example.org')).policy || ''), 'policy column');
    });

    await run.step('Copy summary: what needs a look, by name; the permalink', async () => {
      await stubClipboard(page);
      await page.click('.pf-head [data-action="copy-summary"]');
      await page.waitFor(() => (window.__clip || []).length === 1, { message: 'copied' });
      const [out] = await takeClipboard(page);
      const ls = out.trimEnd().split('\n');
      assertEqual(ls[0], '**Domain portfolio · 3 domains**', 'title');
      assert(ls.includes('- **Expire within 30 days:** `example.org` (20 days)'), out);
      assert(ls.some((l) => l.startsWith('- **Name server domains expiring within 30 days:** `example.net` (12 days; name servers of 3 domains)')), out);
      assert(ls.includes('- **No transfer lock:** `example.org`'), out);
      assert(ls.includes('- **Name server domains not registered (anyone can register them and take over DNS):** `example.test` (name servers of 1 domain)'), out);
      assert(ls.some((l) => /^- \*\*Policy\*\* `e2e`: 2 of 3 domains fail/.test(l)), out);
      assert(/#\/portfolio\?domains=example\.com(%2C|,)example\.org(%2C|,)example-test\.com\.tr$/.test(ls[ls.length - 1]), ls[ls.length - 1]);
    });

    await run.step('Ctrl+Enter runs, Esc stops: the rows not looked up say so and offer "Look up"', async () => {
      await page.evaluate(() => { window.__dnsDelay = 600; });
      await page.evaluate(() => document.querySelector('[data-role="pf-domains"]').focus());
      await page.press('Enter', { ctrl: true });
      await page.waitFor(() => !document.querySelector('[data-action="pf-stop"]').hidden, { message: 'running' });
      await page.evaluate(() => document.querySelector('[data-action="pf-stop"]').focus());
      await page.press('Escape');
      await page.waitFor(() => !document.querySelector('[data-action="pf-run"]').hidden, { message: 'stopped' });
      await page.evaluate(() => { window.__dnsDelay = 0; });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'pf-run', 'focus on Check portfolio');
      assert(/Stopped/.test(await text(page, '.pf-head')), 'the head says so');
      assert(await page.evaluate(() => document.querySelectorAll('.pf-table [data-row]').length > 0), 'Look up on a row');
      await page.click('.pf-table [data-row]');
      await page.waitFor(() => !document.querySelector('.pf-pending') && !document.querySelector('.pf-table [data-row] [aria-busy="true"]'), { timeout: 20000, message: 'the row looked up' });
    });

    run.group('Certificates (CT)');
    await run.step('the CT tab loads on its first use and sends nothing: the portfolio\'s domains, public certificates only, the quota', async () => {
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
      await page.evaluate((seen) => import('./assets/js/state.js').then(async ({ state }) => {
        await state.setWorkspaceData('expectedCas', ["Let's Encrypt"]);
        await state.setWorkspaceData('ctSeen', seen);
      }), CT_SEEN);
      await page.click('.pf-results .tab[data-tab="ct"]');
      await page.waitFor(() => !!document.querySelector('[data-action="ct-run"]'), { message: 'the CT panel' });
      assert(/^3 domains from the portfolio list/.test(await text(page, '.pf-ct-domains')), await text(page, '.pf-ct-domains'));
      assert(/publicly trusted certificates only/.test(await text(page, '.pf-ct-form')), 'CT lists public certificates only');
      assert(await page.evaluate(() => !!document.querySelector('.pf-ct-empty .tool-empty') && document.querySelector('.pf-ct-results').hidden), 'the empty state');
      assert(/^Cert Spotter: 0 of 10 /.test(await text(page, '[data-role="ct-quota"]')), await text(page, '[data-role="ct-quota"]'));
      assertEqual(await page.evaluate(() => window.__ctLog.length), 0, 'nothing sent');
    });

    await run.step('Check CT: Cert Spotter one request at a time, crt.sh after its 429; new since the baseline, an unexpected CA, a wildcard, a precertificate, the radar', async () => {
      await page.evaluate(() => { window.__ctStatus['certspotter|example-test.com.tr'] = 429; window.__ctStatus['crtsh|example-test.com.tr'] = 429; });
      await page.click('[data-action="ct-run"]');
      await waitCt(page);
      const log = await page.evaluate(() => window.__ctLog.map((x) => `${x.source} ${x.domain}${x.after ? ' (next page)' : ''}`));
      assertEqual(log, ['certspotter example.com', 'certspotter example.com (next page)', 'certspotter example.org', 'certspotter example.org (next page)',
        'certspotter example-test.com.tr', 'crtsh example-test.com.tr'], 'the requests, in turn');
      assertEqual(await page.evaluate(() => `${window.__ctLog[0].subdomains} ${window.__ctLog[0].expand.join(',')}`), 'true dns_names,issuer,cert_der,revocation,problem_reporting',
        'the subdomain search, the DER, the revocation and the CA\'s contact expanded');
      assertEqual(await ctTiles(page), { current: '4', expiring: '1', new: '2', unexpected: '1', wildcard: '1', precert: '1' }, 'tiles');
      assertEqual(await ctRows(page), [
        { names: '*.example.com', flags: ['wildcard'], band: 'last' },
        { names: 'example.org www.example.org', flags: [], band: null },
        { names: 'example.com www.example.com', flags: ['new'], band: null },
        { names: 'shop.example.com', flags: ['new', 'unexpected', 'precert'], band: null }
      ], 'the newest of each name set, the soonest expiry first');
      assert(await page.evaluate(() => !!document.querySelector('[data-role="ct-failed"] [data-domain="example-test.com.tr"] .pf-na [data-action="retry-source"]')), 'both sources failed: n/a with a Retry');
      assert(/1 domain is checked for the first time in this workspace \(example\.org\)/.test(await text(page, '[data-note="first"]')), await text(page, '[data-note="first"]'));
      assert(/^Cert Spotter: 5 of 10 /.test(await text(page, '[data-role="ct-quota"]')), await text(page, '[data-role="ct-quota"]'));
      const seen = JSON.parse(await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.workspaceData('ctSeen'))));
      assertEqual(Object.keys(seen.domains).sort(), ['example.com', 'example.org'], 'the baseline: the domains read');
      assertEqual(Object.keys(seen.domains['example.com'].ids).length, 4, 'example.com: what it had, and what is new');
      // Home counts the expiry days of the current certificates (`due`), never the ids a renewal replaced.
      const due = seen.domains['example.com'].due;
      assert(Array.isArray(due) && due.length > 0 && due.length < 4 && due.every((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)), `due: ${JSON.stringify(due)}`);
      await setCtFilter(page, 'all');
      const all = await ctRows(page);
      assertEqual(all.length, 5, 'every unexpired certificate');
      assertEqual(all.filter((r) => r.flags.includes('superseded')).map((r) => r.names), ['example.com www.example.com'], 'the renewed one is superseded');
      await page.click('.pf-ct-head .status-item[data-status="precert"]');
      assertEqual((await ctRows(page)).map((r) => r.names), ['shop.example.com'], 'a status item filters');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="ct-filter"]').value), 'precert', 'the select follows');
      await page.click('.pf-ct-head .status-item[data-status="current"]');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="ct-filter"]').value), 'current', 'the current certificates again');
      await shot(page, opts, 'portfolio-ct-desktop-light-en');
    });

    await run.step('Retry asks only that domain again: crt.sh answers this time, and the line says why Cert Spotter did not', async () => {
      await page.evaluate(() => { delete window.__ctStatus['crtsh|example-test.com.tr']; window.__ctLog.length = 0; });
      await page.click('[data-role="ct-failed"] [data-action="retry-source"]');
      await page.waitFor(() => !document.querySelector('[data-role="ct-failed"]') && document.querySelectorAll('.pf-ct-table tbody tr.dt-row').length === 5, { timeout: 20000, message: 'read again' });
      const log = await page.evaluate(() => window.__ctLog.map((x) => `${x.source} ${x.domain}`));
      assert(log.length > 0 && log.every((l) => l.endsWith(' example-test.com.tr')) && log.at(-1) === 'crtsh example-test.com.tr', log.join(', '));
      const line = await text(page, '[data-role="ct-reads"] [data-domain="example-test.com.tr"]');
      assert(/crt\.sh · 1 certificate · crt\.sh answered: Cert Spotter’s quota was used up/.test(line), line);
    });

    await run.step('exports: the CSV of the rows shown; the .ics with a UID per name set and reminders on the radar\'s days', async () => {
      await takeDownloads(page);
      await resultAction(page, '[data-action="ct-csv"]', '.pf-ct-head');
      await resultAction(page, '[data-action="ct-ics"]', '.pf-ct-head');
      await page.waitFor(() => (window.__downloads || []).length === 2, { message: 'two downloads' });
      const [csv, ics] = await takeDownloads(page);
      assert(/^ct-watch-.*\.csv$/.test(csv.name), csv.name);
      assert(csv.text.startsWith(`${CT_EXPORT_COLUMNS.join(',')}\r\n`), csv.text.slice(0, 160));
      assertEqual(csv.text.trim().split('\r\n').length, 6, 'a header and the five rows shown');
      assert(/^ct-expiry-.*\.ics$/.test(ics.name) && /text\/calendar/.test(ics.type), `${ics.name} ${ics.type}`);
      const unfolded = ics.text.replace(/\r\n /g, '');
      const uids = unfolded.match(/^UID:.*$/gm) || [];
      assertEqual(uids.length, 5, 'one event per current name set');
      assert(uids.every((u) => /^UID:ct-[0-9a-f]{16}@domainscope\r?$/.test(u)), uids.join(' '));
      for (const d of [30, 14, 7]) assertEqual((ics.text.match(new RegExp(`TRIGGER:-P${d}D`, 'g')) || []).length, 5, `${d} days before`);
      assert(/^SUMMARY:Certificate expires: \*\.example\.com\r?$/m.test(unfolded), 'worded');
    });

    await run.step('a second check while Cert Spotter waits out its 429: crt.sh for every domain, the same ids, nothing new; it says what it compared with', async () => {
      await page.evaluate(() => { window.__ctLog.length = 0; });
      await page.click('[data-action="ct-run"]');
      await waitCt(page, 'checked again');
      assertEqual((await page.evaluate(() => window.__ctLog.map((x) => `${x.source} ${x.domain}`))).sort(), ['crtsh example-test.com.tr', 'crtsh example.com', 'crtsh example.org'], 'crt.sh only');
      assert(await page.evaluate(() => !!document.querySelector('[data-role="ct-quota"] [data-quota="out"]')), 'the quota line says Cert Spotter waits');
      const tiles = await ctTiles(page);
      assertEqual([tiles.current, tiles.new, tiles.precert], ['5', '0', '0'], 'the same certificates, nothing new; crt.sh cannot tell a precertificate');
      assert(/crt\.sh does not say which entries are precertificates/.test(await text(page, '.pf-ct-sources')), 'says so');
      assert(await page.evaluate(() => !document.querySelector('[data-note="first"]')), 'no first check any more');
      assert(/^Compared with the check of /.test(await text(page, '.pf-ct [data-note="compared"]')), await text(page, '.pf-ct [data-note="compared"]'));
      await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.setWorkspaceData('expectedCas', [])));
      await page.waitFor(() => {
        const strip = document.querySelector('.pf-ct-tiles');
        const shown = strip.querySelector('[data-metric="unexpected"] .metric-value');
        return shown ? shown.textContent.trim() === '0' : (strip.querySelector('.metric-zero')?.dataset.folded || '').split(' ').includes('unexpected');
      }, { message: 'no expected CAs: no flag' });
      await page.click('.pf-results .tab[data-tab="domains"]');
    });

    run.group('Phone 375 and 320 px, desktop, Turkish / English, light / dark');
    await run.step('the table and the matrix as cards: no horizontal scroll; TR / EN × light / dark, both tabs', async () => {
      await page.click('[data-action="pf-run"]');
      await waitDone(page, 'checked again');
      const tab = async (id) => {
        // a toast closes itself after a few seconds, longer than these steps take: one left over from the
        // runs above could sit over the tabs at 320 px
        await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
        await page.click(`.pf-results .tab[data-tab="${id}"]`);
        await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
        await page.evaluate(() => window.scrollTo(0, 0));
      };
      await page.setViewport({ width: 375, height: 760, mobile: true });
      for (const lang of ['en', 'tr']) {
        await setLangUi(page, lang);
        await page.waitFor(() => !!document.querySelector('.pf-head'), { message: 'kept after the language switch' });
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await tab('domains');
          await assertNoHorizontalScroll(page, `portfolio ${scheme} ${lang}`);
          await shot(page, opts, `portfolio-results-mobile-${scheme}-${lang}`);
          await tab('policy');
          await assertNoHorizontalScroll(page, `policy ${scheme} ${lang}`);
          await shot(page, opts, `portfolio-policy-mobile-${scheme}-${lang}`);
          await tab('ct');
          assertEqual(await page.evaluate(() => document.querySelectorAll('.pf-ct-table tbody tr.dt-row').length), 5, `the CT check kept (${lang})`);
          await assertNoHorizontalScroll(page, `ct ${scheme} ${lang}`);
          await shot(page, opts, `portfolio-ct-mobile-${scheme}-${lang}`);
        }
      }
      await tab('domains');
      const fit = await page.evaluate(() => [...document.querySelectorAll('.pf-table tbody tr.dt-row')].filter((r) => r.scrollWidth > r.clientWidth + 1).length);
      assertEqual(fit, 0, 'every card fits at 375 px');
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await tab('policy');
      // the baseline's long evidence ("…(clientTransferProhibited or serverTransferProhibited)…") on the narrowest phone
      await page.evaluate(() => document.querySelector('[data-preset="baseline"]').click());
      await page.waitFor(() => document.querySelectorAll('.pf-matrix thead th').length === 9, { message: 'the seven rules of the baseline' });
      await assertNoHorizontalScroll(page, 'policy 320 tr dark');
      const spill = () => page.evaluate(() => [...document.querySelectorAll('.pf-matrix .pf-evidence')].filter((el) => {
        const range = document.createRange();
        range.selectNodeContents(el);
        return range.getBoundingClientRect().right > el.closest('td').getBoundingClientRect().right + 0.5;
      }).map((el) => el.textContent));
      assertEqual(await spill(), [], 'every evidence stays inside its card at 320 px (Turkish)');
      await setLangUi(page, 'en');
      await page.waitFor(() => !!document.querySelector('.pf-head'), { message: 'kept after the language switch' });
      await tab('policy');
      await page.waitFor(() => !!document.querySelector('.pf-matrix tbody tr'), { message: 'the matrix again' });
      assertEqual(await spill(), [], 'every evidence stays inside its card at 320 px (English)');
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('.pf-head'), { message: 'kept after the language switch' });
      await tab('policy');
      await tab('domains');
      const parkedWhole = await page.evaluate(() => [...document.querySelectorAll('.pf-table [data-parked="open"] .pf-nowrap')].map((e) => e.textContent));
      assertEqual(parkedWhole, ['-all'], '"-all" never breaks after its hyphen');
      await tab('policy');
      await shot(page, opts, 'portfolio-policy-mobile320-dark-tr');
      await tab('ct');
      await assertNoHorizontalScroll(page, 'ct 320 tr dark');
      await shot(page, opts, 'portfolio-ct-mobile320-dark-tr');
      await tab('domains');
      await assertNoHorizontalScroll(page, 'portfolio 320 tr dark');
      await shot(page, opts, 'portfolio-results-mobile320-dark-tr');

      // Desktop: the domain column stays in view while the table scrolls sideways.
      await page.setViewport({ width: 1440, height: 900 });
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await page.waitFor(() => !!document.querySelector('.pf-head'), { message: 'kept after the language switch' });
        for (const scheme of ['dark', 'light']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await tab('domains');
          await shot(page, opts, `portfolio-results-desktop-${scheme}-${lang}`);
          await tab('policy');
          await shot(page, opts, `portfolio-policy-desktop-${scheme}-${lang}`);
        }
      }
      await tab('domains');
      const sticky = await page.evaluate(() => {
        const scroll = document.querySelector('.pf-table .dt-scroll');
        const cell = document.querySelector('.pf-table tbody td.pf-col-domain');
        const before = cell.getBoundingClientRect().left;
        scroll.scrollLeft = scroll.scrollWidth;
        const after = cell.getBoundingClientRect().left;
        scroll.scrollLeft = 0;
        return { wide: scroll.scrollWidth > scroll.clientWidth, moved: Math.round(after - before) };
      });
      assertEqual(sticky.moved, 0, `the domain column stays put while the table scrolls: ${JSON.stringify(sticky)}`);
    });

    run.group('Offline');
    await run.step('offline: the page says the portfolio needs the network; Check portfolio sends nothing and the rows stay', async () => {
      const setOnline = async (on) => {
        await page.send('Network.emulateNetworkConditions', { offline: !on, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
        await page.waitFor((o) => navigator.onLine === o, { args: [on], message: `navigator.onLine ${on}` });
      };
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
      const before = await counts(page);
      const rows = () => page.evaluate(() => document.querySelectorAll('.pf-table tbody tr.dt-row').length);
      const shown = await rows();
      await setOnline(false);
      try {
        await page.waitFor(() => document.querySelector('#page-offline')?.hidden === false, { message: 'the offline note' });
        assert(/^Domain portfolio needs the network/.test(await text(page, '#page-offline .alert-message, #page-offline p')), await text(page, '#page-offline'));
        await page.click('[data-action="pf-run"]');
        await page.waitFor(() => [...document.querySelectorAll('.toast')].some((x) => /this needs the network/.test(x.textContent)), { message: 'the offline toast' });
        assertEqual(await counts(page), before, 'nothing sent');
        assertEqual(await rows(), shown, 'the rows on screen stay');
        assert(await page.evaluate(() => document.querySelector('[data-action="pf-stop"]').hidden), 'nothing running');
      } finally {
        await setOnline(true);
      }
      await page.waitFor(() => document.querySelector('#page-offline')?.hidden === true, { message: 'the note goes once online' });
    });

    await run.step('offline: Check CT sends nothing either', async () => {
      const setOnline = async (on) => {
        await page.send('Network.emulateNetworkConditions', { offline: !on, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
        await page.waitFor((o) => navigator.onLine === o, { args: [on], message: `navigator.onLine ${on}` });
      };
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
      await page.click('.pf-results .tab[data-tab="ct"]');
      const before = await page.evaluate(() => window.__ctLog.length);
      await setOnline(false);
      try {
        await page.click('[data-action="ct-run"]');
        await page.waitFor(() => [...document.querySelectorAll('.toast')].some((x) => /this needs the network/.test(x.textContent)), { message: 'the offline toast' });
        assertEqual(await page.evaluate(() => window.__ctLog.length), before, 'nothing sent');
        assert(await page.evaluate(() => document.querySelector('[data-action="ct-stop"]').hidden), 'nothing running');
      } finally {
        await setOnline(true);
      }
      await page.click('.pf-results .tab[data-tab="domains"]');
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'portfolio', origin));
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

// Run as a program (run-all, or by hand); imported, it only lends its fake services.
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
    process.exitCode = 1;
  });
}
