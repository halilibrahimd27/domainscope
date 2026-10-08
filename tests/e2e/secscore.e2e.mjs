#!/usr/bin/env node
/**
 * secscore.e2e.mjs — end-to-end test of the Domain portfolio's domain security (lock depth,
 * registrar class, DNS redundancy and the Domain security tab) in a real headless Chrome/Edge.
 * OFFLINE: every DoH query is answered in the page by a fake resolver built from the zone below
 * (window.fetch wrapped before the app loads), the RDAP bootstrap and registry by the same
 * wrapper; every other https:// request is blocked, and every request that leaves the page's
 * origin is counted through CDP.
 *
 *   node tests/e2e/secscore.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: Check portfolio over four domains — a corporate registrar (IANA ID 292) with a registry
 * lock, two DNS providers, DNSSEC, CAA and authenticated mail (8 of 8); a retail registrar
 * (IANA ID 1068) whose registry prohibits transfers only ("Partial registry lock", with what that
 * is also set for); a reserved IANA ID (9999: the registry acting as registrar) with the
 * registrar's full lock in EPP spelling; a .tr domain without RDAP. The Domains tab says each
 * lock's depth and a corporate registrar; its CSV carries the class, the lock level and the DNS
 * providers. The Domain security tab (ui/secscore-panel.js, loaded on its first use, by mouse
 * and by keyboard) sends nothing: the line above the bars, the eight adoption bars (inline SVG,
 * their segments as shares of the domains, a label for screen readers), the table of scores
 * worst first with each measure met / not met / not known and its evidence, search, sort, and
 * its CSV. The Corporate preset in the policy tab: its nine rules and their evidence. TR / EN ×
 * light / dark, 375 / 320 px without horizontal scroll; zero console errors / CSP violations /
 * missing i18n keys, nothing sent outside the page.
 *
 * Data is documentation space only (example.com / .net / .org, example-test.com.tr, 192.0.2.0/24,
 * 203.0.113.0/24).
 */

import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, takeDownloads, waitReady
} from './scan.e2e.mjs';

const DAY = 86400000;
const NOW = Date.now();
// half a day past the count, so a run a few minutes later still counts the same whole days
const iso = (days) => new Date(NOW + days * DAY + DAY / 2).toISOString().replace(/\.\d{3}Z$/, 'Z');
const DNSKEY = { flags: 257, protocol: 3, algorithm: 13, publicKey: Buffer.alloc(64, 7).toString('base64') };
const KEY_TAG = decodeMessage(encodeMessage({ answers: [{ name: 'example.com', type: 'DNSKEY', ttl: 300, data: DNSKEY }] })).answers[0].data.keyTag;
const DOMAINS = ['example.com', 'example.org', 'example.net', 'example-test.com.tr'];
const DKIM_KEY = 'v=DKIM1; k=rsa; p=MIIBIjANBgkqh';

/**
 * Four zones: every measure met, few met, a parked domain on its own name servers, a .tr domain. A
 * second DNS provider is example-test.com.tr's name servers: example.net's and example.org's are
 * example.com's own name at other suffixes (one provider, as a company's own name servers are).
 */
const ZONE = {
  'example.com': {
    NS: ['ns1.example.net', 'ns1.example-test.com.tr'],
    DS: [{ keyTag: KEY_TAG, algorithm: 13, digestType: 2, digest: 'ab'.repeat(32) }],
    DNSKEY: [DNSKEY],
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }],
    MX: [{ preference: 10, exchange: 'mx.example.com' }],
    TXT: [['v=spf1 ip4:192.0.2.0/24 -all']]
  },
  'mx.example.com': { A: ['192.0.2.25'] },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']] },
  'google._domainkey.example.com': { TXT: [[DKIM_KEY]] },
  'example.org': {
    NS: ['ns1.example.net', 'ns2.example.net'],
    MX: [{ preference: 10, exchange: 'mx.example.org' }],
    TXT: [['v=spf1 ~all']]
  },
  'mx.example.org': { A: ['192.0.2.26'] },
  '_dmarc.example.org': { TXT: [['v=DMARC1; p=none']] },
  // parked: null MX, -all, p=reject, CAA that allows no CA; its own name server and example-test.com.tr's
  'example.net': {
    NS: ['ns1.example.net', 'ns1.example-test.com.tr'],
    CAA: [{ flags: 0, tag: 'issue', value: ';' }],
    MX: [{ preference: 0, exchange: '.' }],
    TXT: [['v=spf1 -all']]
  },
  '_dmarc.example.net': { TXT: [['v=DMARC1; p=reject']] },
  'example-test.com.tr': {
    NS: ['ns1.example.net', 'ns2.example.net'],
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }],
    MX: [{ preference: 10, exchange: 'mx.example-test.com.tr' }],
    TXT: [['v=spf1 ~all']]
  },
  'mx.example-test.com.tr': { A: ['203.0.113.25'] },
  '_dmarc.example-test.com.tr': { TXT: [['v=DMARC1; p=quarantine']] },
  'selector1._domainkey.example-test.com.tr': { TXT: [[DKIM_KEY]] }
};
const SIGNED = ['example.com'];

const rdapJson = (domain, { status, days, registrar, ianaId }) => ({
  objectClassName: 'domain', ldhName: domain.toUpperCase(), status,
  events: [{ eventAction: 'registration', eventDate: '2001-05-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: iso(days) }],
  entities: [{ objectClassName: 'entity', roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', registrar]]], publicIds: [{ type: 'IANA Registrar ID', identifier: ianaId }] }],
  secureDNS: { delegationSigned: domain === 'example.com' }
});
const RDAP = {
  // a corporate registrar (MarkMonitor's IANA ID) and a registry lock: server transfer, update and delete prohibited
  'example.com': rdapJson('example.com', {
    status: ['client transfer prohibited', 'client update prohibited', 'client delete prohibited', 'server transfer prohibited', 'server update prohibited', 'server delete prohibited'],
    days: 400, registrar: 'Example Corporate Registrar', ianaId: '292'
  }),
  // a retail registrar; the registry prohibits transfers only
  'example.org': rdapJson('example.org', { status: ['client transfer prohibited', 'server transfer prohibited'], days: 200, registrar: 'Example Registrar, Inc.', ianaId: '1068' }),
  // a reserved IANA ID (the registry acting as registrar); the registrar's full lock in EPP spelling
  'example.net': rdapJson('example.net', { status: ['clientTransferProhibited', 'clientUpdateProhibited', 'clientDeleteProhibited'], days: 300, registrar: 'Example Registry Services', ianaId: '9999' })
};

/** In-page stubs: DoH from the zone (NXDOMAIN outside it), the RDAP bootstrap and registry. */
const fakeScript = () => `(() => {
  const Z = ${JSON.stringify(ZONE)};
  const SIGNED = ${JSON.stringify(SIGNED)};
  const RDAP = ${JSON.stringify(RDAP)};
  window.__dnsLog = [];
  window.__rdapLog = [];
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/rdap+json' } });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://data.iana.org/rdap/')) return json({ services: [[['com', 'net', 'org'], ['https://rdap.example.net/']]] });
    if (url.startsWith('https://rdap.example.net/') || url.startsWith('https://rdap.org/')) {
      const name = decodeURIComponent(url.split('/domain/')[1] || '');
      window.__rdapLog.push(name);
      return RDAP[name] ? json(RDAP[name]) : json({ errorCode: 404 }, 404);
    }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const qname = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__dnsLog.push({ name: qname, type: q.type });
    const answers = [];
    let rcode = 'NOERROR';
    const node = Z[qname];
    if (!node && !Object.keys(Z).some((k) => k.endsWith('.' + qname))) rcode = 'NXDOMAIN';
    for (const data of (node && node[q.type]) || []) answers.push({ name: qname, type: q.type, ttl: 300, data });
    const ad = SIGNED.some((z) => qname === z || qname.endsWith('.' + z));
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true, ad }, rcode,
      questions: [{ name: q.name, type: q.type }], answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/** The fields of one CSV line (RFC 4180: quoted fields, "" inside them). */
function csvFields(line) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') {
        cur += '"';
        i += 1;
      } else if (c === '"') quoted = false;
      else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out;
}
const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);
const counts = (page) => page.evaluate(() => ({ dns: window.__dnsLog.length, rdap: window.__rdapLog.length }));
const waitDone = (page, message = 'portfolio checked') => page.waitFor(() => !!document.querySelector('.pf-head[data-status="done"]')
  && !document.querySelector('[data-action="pf-run"]').hidden && !document.querySelector('.pf-pending'), { timeout: 40000, message });
/** The Domains table's status and registrar cells by domain. */
const domainCells = (page) => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.pf-table:not(.pf-sec-table) tbody tr.dt-row')].map((tr) => [
  tr.querySelector('.pf-domain').textContent,
  {
    lock: tr.querySelector('td.pf-col-status [data-lock-level]')?.dataset.lockLevel || null,
    status: tr.querySelector('td.pf-col-status')?.textContent.replace(/\s+/g, ' ').trim() || '',
    badge: tr.querySelector('td.pf-col-status [data-lock-level] .badge-text')?.textContent || null,
    note: tr.querySelector('td.pf-col-status .pf-lock-note')?.textContent || null,
    corporate: !!tr.querySelector('td.pf-col-registrar [data-registrar-class="corporate"]')
  }
])));
/** The security table's rows in their order: the domain, the score, each measure's status. */
const secRows = (page) => page.evaluate(() => [...document.querySelectorAll('.pf-sec-table tbody tr.dt-row')].map((tr) => ({
  domain: tr.querySelector('.pf-domain').textContent,
  score: tr.querySelector('.pf-sec-score').dataset.score,
  unknown: tr.querySelector('.pf-sec-score').dataset.unknown,
  measures: Object.fromEntries([...tr.querySelectorAll('[data-measure]')].map((c) => [c.dataset.measure, c.dataset.status]))
})));
/** The adoption bars: per measure its counts and the drawn segments (kind and width in the 100-wide box). */
const bars = (page) => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.pf-sec-bar')].map((b) => [b.dataset.measure, {
  pass: b.dataset.pass, fail: b.dataset.fail, unknown: b.dataset.unknown,
  segments: [...b.querySelectorAll('rect[data-segment]')].map((r) => `${r.dataset.segment}:${Number(r.getAttribute('width'))}`),
  label: b.querySelector('svg').getAttribute('aria-label'),
  role: b.querySelector('svg').getAttribute('role'),
  value: b.querySelector('.pf-sec-bar-value').textContent
}])));
const tab = async (page, id) => {
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  await page.click(`.pf-results .tab[data-tab="${id}"]`);
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
  await page.evaluate(() => window.scrollTo(0, 0));
};

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
    await run.step('before a check the Domain security tab says what it needs; it fills while the check runs', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.setWorkspaceData('policy', '')));
      await gotoRoute(page, `#/portfolio?domains=${DOMAINS.join(',')}`);
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.pf-results .tab')].map((x) => x.dataset.tab)), ['domains', 'security', 'policy', 'ct'], 'the tabs');
      await tab(page, 'security');
      await page.waitFor(() => !!document.querySelector('.pf-sec [data-sec="no-run"]'), { message: 'the tab, loaded on its first use' });
      assert(await page.evaluate(() => !document.querySelector('[data-sec="no-run"]').hidden && document.querySelector('.pf-sec-table-card').hidden
        && document.querySelector('[data-role="sec-totals"]').hidden), 'no check yet: only what it needs');
      assertEqual(await text(page, '[data-sec="no-run"]'), 'Check a portfolio first: the score uses its results and sends nothing more.', 'the hint');
      assertEqual(await counts(page), { dns: 0, rdap: 0 }, 'nothing sent');
      await page.click('[data-action="pf-run"]');
      await waitDone(page);
      await page.waitFor(() => document.querySelectorAll('.pf-sec-table tbody tr.dt-row').length === 4
        && /^4 domains · average score 4\.3 of 8/.test(document.querySelector('[data-role="sec-totals"]').textContent), { message: 'the scores of the check on screen' });
      assert(await page.evaluate(() => document.querySelector('[data-sec="no-run"]').hidden), 'the hint goes');
    });

    await run.step('the Domains tab says each lock\'s depth and a corporate registrar; its CSV carries them', async () => {
      await tab(page, 'domains');
      const cells = await domainCells(page);
      assertEqual(cells['example.com'].lock, 'registry', 'example.com: a registry lock');
      assert(/Registry lock/.test(cells['example.com'].status) && cells['example.com'].corporate, JSON.stringify(cells['example.com']));
      assertEqual(cells['example.org'].lock, 'registry-partial', 'example.org: the registry prohibits transfers only');
      assertEqual([cells['example.org'].badge, cells['example.org'].note], ['Partial registry lock',
        'transfer only — also what a registry sets during a dispute or the 60-day lock after a transfer'], 'the partial lock says what it is');
      assert(!cells['example.org'].corporate, 'a retail registrar has no badge');
      assertEqual(cells['example.net'].lock, 'registrar-full', 'example.net: the registrar\'s full lock (EPP spelling)');
      assert(/Registrar lock/.test(cells['example.net'].status) && !cells['example.net'].corporate, JSON.stringify(cells['example.net']));
      assert(/No RDAP/.test(cells['example-test.com.tr'].status), cells['example-test.com.tr'].status);
      assertEqual(await page.evaluate(() => document.querySelector('[data-lock-level="registry-partial"]').title),
        'Set by the registry: server transfer prohibited. A registry lock is server transfer, update and delete prohibited together.', 'the partial lock\'s tooltip');
      // the prohibitions a lock's badge names are not listed again beside it
      assert(!/client update prohibited|client delete prohibited/.test(cells['example.net'].status), cells['example.net'].status);
      assert(!/server update prohibited|server delete prohibited/.test(cells['example.com'].status), cells['example.com'].status);
      await takeDownloads(page);
      await page.click('[data-action="pf-csv"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the Domains CSV' });
      const [csv] = await takeDownloads(page);
      const lines = csv.text.replace(/^\uFEFF/, '').trimEnd().split('\r\n');
      const head = csvFields(lines[0]);
      const col = (row, name) => csvFields(row)[head.indexOf(name)];
      const rowOf = (domain) => lines.find((l) => l.startsWith(`${domain},`));
      assertEqual(['registrarClass', 'lockLevel', 'nsProviders'].map((c) => col(rowOf('example.com'), c)), ['corporate', 'registry', '2'], 'example.com in the CSV');
      assertEqual(['registrarClass', 'lockLevel', 'nsProviders'].map((c) => col(rowOf('example.org'), c)), ['retail', 'registry-partial', '1'], 'example.org in the CSV');
      await shot(page, opts, 'secscore-domains-desktop-light-en');
    });

    await run.step('the Domain security tab sends nothing: the line, the eight bars, the scores worst first', async () => {
      const before = await counts(page);
      await tab(page, 'security');
      await page.waitFor(() => document.querySelectorAll('.pf-sec-table tbody tr.dt-row').length === 4, { message: 'the security table' });
      assertEqual(await counts(page), before, 'nothing sent');
      assertEqual(await text(page, '[data-role="sec-totals"]'), '4 domains · average score 4.3 of 8 · 1 meets all eight · 3 measures could not be checked', 'the line');
      const b = await bars(page);
      assertEqual(Object.keys(b), ['registrar', 'registryLock', 'caa', 'dnsRedundancy', 'dnssec', 'spf', 'dkim', 'dmarc'], 'a bar per measure, in CSC\'s order');
      assertEqual(b.registrar.segments, ['pass:25', 'fail:25', 'unknown:50'], 'registrar: met, not met, not known as shares');
      assertEqual(b.spf.segments, ['pass:100'], 'SPF: every domain');
      assertEqual([b.registrar.value, b.registryLock.value, b.caa.value, b.dnsRedundancy.value, b.dnssec.value, b.dkim.value, b.dmarc.value], [
        '1 of 4 (25%) · 2 not known', '1 of 4 (25%) · 1 not known', '3 of 4 (75%)', '2 of 4 (50%)', '1 of 4 (25%)', '2 of 4 (50%)', '3 of 4 (75%)'
      ], 'the bars\' texts');
      assertEqual([b.registryLock.role, b.registryLock.label], ['img', 'Registry lock: 1 met, 2 not met, 1 not known'], 'a bar\'s label for screen readers');
      const rows = await secRows(page);
      assertEqual(rows.map((r) => `${r.domain} ${r.score}/${r.unknown}`), ['example.org 1/0', 'example-test.com.tr 4/2', 'example.net 4/1', 'example.com 8/0'], 'worst first');
      assertEqual(rows[0].measures, { registrar: 'fail', registryLock: 'fail', caa: 'fail', dnsRedundancy: 'fail', dnssec: 'fail', spf: 'pass', dkim: 'fail', dmarc: 'fail' }, 'example.org');
      assertEqual(rows[2].measures, { registrar: 'unknown', registryLock: 'fail', caa: 'pass', dnsRedundancy: 'pass', dnssec: 'fail', spf: 'pass', dkim: 'fail', dmarc: 'pass' }, 'example.net');
      assertEqual(rows[1].measures.registrar, 'unknown', 'no RDAP: not known');
      const evidence = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.pf-sec-table tbody tr.dt-row')].map((tr) => [
        tr.querySelector('.pf-domain').textContent,
        Object.fromEntries([...tr.querySelectorAll('[data-measure]')].map((c) => [c.dataset.measure, c.querySelector('.pf-evidence').textContent]))
      ])));
      assertEqual(evidence['example.org'].registryLock, 'a partial registry lock, server transfer prohibited only: a registry lock is server transfer, update and delete prohibited together', 'the partial lock said');
      assertEqual(evidence['example.org'].registrar, 'not a corporate registrar: Example Registrar, Inc. (IANA ID 1068)', 'a retail registrar');
      assertEqual(evidence['example.net'].registrar, 'IANA ID 9999 is a reserved one (such as the registry acting as registrar): whether the registrar is corporate is not known', 'a reserved ID');
      assertEqual(evidence['example.net'].dnsRedundancy, '2 DNS providers: example-test.com.tr, example.net', 'its own name server and example-test.com.tr\'s');
      assertEqual(evidence['example.org'].dnsRedundancy, '1 DNS provider: example.org', 'example.net\'s name servers: its own name at another suffix');
      assertEqual(evidence['example.com'].registrar, 'a corporate registrar: Example Corporate Registrar (IANA ID 292)', 'a corporate registrar');
      await shot(page, opts, 'secscore-security-desktop-light-en');
    });

    await run.step('search, sort, and the CSV of the rows shown (every measure with its evidence)', async () => {
      await page.type('.pf-sec-table .dt-search input', 'example.n');
      await page.waitFor(() => document.querySelectorAll('.pf-sec-table tbody tr.dt-row').length === 1, { message: 'searched' });
      await page.type('.pf-sec-table .dt-search input', '');
      await page.waitFor(() => document.querySelectorAll('.pf-sec-table tbody tr.dt-row').length === 4, { message: 'search cleared' });
      await page.click('.pf-sec-table th[data-key="score"] .dt-sort');
      assertEqual((await secRows(page)).map((r) => r.domain)[0], 'example.com', 'the best score first');
      await page.click('.pf-sec-table th[data-key="score"] .dt-sort');
      await takeDownloads(page);
      await page.click('[data-action="sec-csv"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the security CSV' });
      const [csv] = await takeDownloads(page);
      assert(/^domain-security-4-domains-\d{8}-\d{4}\.csv$/.test(csv.name) && csv.bom, csv.name);
      const lines = csv.text.replace(/^\uFEFF/, '').trimEnd().split('\r\n');
      assertEqual(lines[0], 'Domain,Score (of 8),Not known,Corporate registrar,Registry lock,CAA,DNS redundancy,DNSSEC,SPF,DKIM,DMARC', 'the header');
      assertEqual(lines.length, 5, 'a header and the four rows');
      assert(lines[1].startsWith('example.org,1,0,"FAIL · not a corporate registrar: Example Registrar, Inc. (IANA ID 1068)",'), lines[1]);
      assert(lines.some((l) => l.startsWith('example.com,8,0,PASS · a corporate registrar: Example Corporate Registrar (IANA ID 292),')), lines.join('\n'));
    });

    await run.step('the keyboard: the tabs move with the arrow keys, the CSV button is reached with Tab', async () => {
      await page.evaluate(() => document.querySelector('.pf-results .tab[data-tab="domains"]').click());
      await page.evaluate(() => document.querySelector('.pf-results .tab[data-tab="domains"]').focus());
      await page.press('ArrowRight');
      await page.waitFor(() => document.activeElement?.dataset.tab === 'security' && document.activeElement.getAttribute('aria-selected') === 'true', { message: 'the security tab by keyboard' });
      assert(await page.evaluate(() => !document.querySelector('.pf-sec-table').closest('[role="tabpanel"]').hidden), 'its panel shown');
      await page.evaluate(() => document.querySelector('.pf-sec-table .dt-search input').focus());
      let reached = false;
      for (let i = 0; i < 6 && !reached; i += 1) {
        await page.press('Tab');
        reached = await page.evaluate(() => document.activeElement?.dataset.action === 'sec-csv');
      }
      assert(reached, 'the CSV button is in the tab order');
    });

    await run.step('the Corporate preset: nine rules over the same facts, with their evidence', async () => {
      await tab(page, 'policy');
      await page.waitFor(() => !!document.querySelector('[data-preset="corporate"]'), { message: 'the presets' });
      await page.click('[data-preset="corporate"]');
      await page.waitFor(() => document.querySelectorAll('.pf-matrix thead th').length === 11, { message: 'nine rules in the matrix' });
      const json = JSON.parse(await page.evaluate(() => document.querySelector('[data-role="pf-policy-json"]').value));
      assertEqual(json.rules, {
        'lock.level': '>= registrar-full', registryLock: true, 'registrar.class': 'corporate', 'ns.providers': '>= 2', dnssec: '>= signed', caa: 'present',
        spf: 'valid', 'dmarc.policy': '>= quarantine', dkim: true
      }, 'the preset\'s JSON');
      const cells = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.pf-matrix tbody tr.dt-row')].map((tr) => [
        tr.querySelector('td strong').textContent,
        Object.fromEntries([...tr.querySelectorAll('[data-rule]')].map((c) => [c.dataset.rule, c.dataset.status]))
      ])));
      assert(Object.values(cells['example.com']).every((s) => s === 'pass'), JSON.stringify(cells['example.com']));
      assertEqual([cells['example.net']['lock.level'], cells['example.net'].registryLock, cells['example.net']['registrar.class']], ['pass', 'fail', 'unknown'], 'example.net: the registrar\'s full lock');
      assertEqual([cells['example.org']['lock.level'], cells['example.org']['ns.providers']], ['pass', 'fail'], 'example.org: a partial registry lock ranks above the registrar\'s full lock');
      assertEqual(await text(page, '.pf-matrix-counts'), '3 of 4 domains fail the policy · 1 meets every rule', 'the matrix line');
      await shot(page, opts, 'secscore-policy-desktop-light-en');
    });

    run.group('Phone 375 and 320 px, Turkish / English, light / dark');
    await run.step('the tab in Turkish and English, light and dark: no horizontal scroll at 375 and 320 px', async () => {
      await page.setViewport({ width: 375, height: 760, mobile: true });
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await page.waitFor(() => !!document.querySelector('.pf-head'), { message: 'kept after the language switch' });
        for (const scheme of ['dark', 'light']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await tab(page, 'security');
          await page.waitFor(() => document.querySelectorAll('.pf-sec-table tbody tr.dt-row').length === 4, { message: `the table (${lang})` });
          await assertNoHorizontalScroll(page, `security ${scheme} ${lang}`);
          await shot(page, opts, `secscore-security-mobile-${scheme}-${lang}`);
          await tab(page, 'domains');
          await assertNoHorizontalScroll(page, `domains ${scheme} ${lang}`);
        }
        if (lang === 'tr') {
          await tab(page, 'security');
          assertEqual(await text(page, '.pf-results .tab[data-tab="security"]'), 'Alan adı güvenliği', 'the tab\'s name');
          assertEqual(await text(page, '[data-role="sec-totals"]'), '4 alan adı · ortalama puan 8 üzerinden 4,3 · 1 tanesi sekizini birden karşılıyor · 3 ölçüt kontrol edilemedi', 'the line in Turkish');
          const b = await bars(page);
          assertEqual([b.registrar.value, b.spf.value], ['4 alan adından 1 tanesi (%25) · 2 tanesi bilinmiyor', '4 alan adından 4 tanesi (%100)'], 'the bars in Turkish');
          const org = await page.evaluate(() => {
            const cell = [...document.querySelectorAll('.pf-sec-table tbody tr.dt-row')].find((tr) => tr.querySelector('.pf-domain').textContent === 'example.org')
              .querySelector('[data-measure="registryLock"]');
            return [cell.querySelector('.badge-text').textContent, cell.querySelector('.pf-evidence').textContent];
          });
          assertEqual(org, ['Karşılanmıyor', 'kısmi kayıt kuruluşu kilidi, yalnızca server transfer prohibited: kayıt kuruluşu kilidi server transfer, update ve delete prohibited durumlarının üçü birdendir'], 'a cell in Turkish');
          await tab(page, 'domains');
          const trOrg = (await domainCells(page))['example.org'];
          assertEqual([trOrg.badge, trOrg.note], ['Kısmi kayıt kuruluşu kilidi',
            'yalnızca transfer — kayıt kuruluşları bunu bir anlaşmazlık sırasında ya da transferden sonraki 60 günlük kilitte de koyar'], 'the partial lock in Turkish');
        }
      }
      // the narrowest phone: the bars stack, the cards keep every measure inside
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('.pf-head'), { message: 'kept after the language switch' });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await tab(page, 'security');
      await assertNoHorizontalScroll(page, 'security 320 tr dark');
      const spill = await page.evaluate(() => [...document.querySelectorAll('.pf-sec-table .pf-evidence, .pf-sec-bar-value')].filter((el) => {
        const range = document.createRange();
        range.selectNodeContents(el);
        const box = el.closest('td, .pf-sec-bar').getBoundingClientRect();
        return range.getBoundingClientRect().right > box.right + 0.5;
      }).map((el) => el.textContent));
      assertEqual(spill, [], 'every evidence and bar text stays inside its card at 320 px');
      await shot(page, opts, 'secscore-security-mobile320-dark-tr');
      await tab(page, 'domains');
      await assertNoHorizontalScroll(page, 'domains 320 tr dark');
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await tab(page, 'security');
      await shot(page, opts, 'secscore-security-desktop-dark-tr');
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'secscore', origin));
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
    process.exitCode = 1;
  });
}
