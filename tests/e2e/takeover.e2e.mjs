#!/usr/bin/env node
/**
 * takeover.e2e.mjs — Domain Health › Dependencies (the Takeover risks audit of one domain,
 * ui/takeover-panel.js DependencyPanel over lib/takeover.js) in a real headless browser, OFFLINE:
 * every DoH question is answered in the page from a small world (CNAME chains followed across it,
 * NXDOMAIN outside it), the IANA RDAP bootstrap and one registry are answered in the page too,
 * and any other request that leaves the page is refused and noted.
 *
 *   node tests/e2e/takeover.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * The world: example.com is ours; example.org is nobody's (RDAP 404, NXDOMAIN), example-test.com.tr
 * is pending deletion, and example.net's registry answers 503 until healed, then "expiring in 12
 * days". example.com's records point at them: an SPF include and an a: host, the DMARC report
 * address, a DKIM selector's CNAME, the MTA-STS host on GitHub Pages, the _acme-challenge
 * delegation and a SIP SRV record.
 *
 * Covers: the card says what a click sends and sends nothing before it (no question of a new kind,
 * no RDAP lookup but the health check's own); the keyboard opens it; every kind on that one click,
 * worst first (critical _acme-challenge, the DMARC report address, the SPF a: host, a dangling SRV
 * target, the MTA-STS host "to check"); our own domain and the catalogue's providers never looked
 * up; the 503 as "⚠ n/a" with a Retry that asks only that registry again and brings the expiring
 * SPF include, DKIM CNAME and SRV target; the CSV; the page check offered (never sent); the results
 * kept across a language switch, with the Turkish words; 375 and 320 px in light and dark without
 * horizontal scroll; a new check of another domain starts the card afresh, and Stop leaves the
 * card's own button; no console errors, exceptions or CSP violations, complete i18n.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { installDownloadCapture, takeDownloads } from './scan.e2e.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASE = '/domainscope/';
const argv = process.argv.slice(2);
const optValue = (name, def) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : def;
};
const BROWSER = optValue('--browser', 'auto');
const HEADED = argv.includes('--headed');
const SHOTS_ON = !argv.includes('--no-shots');
const SHOTS = path.resolve(optValue('--shots-dir', path.join(HERE, 'screenshots')));
const HEALTH_DONE = "!!document.querySelector('.hlt-hero') && !document.querySelector('[data-action=\"run\"]').hidden";
const CARD = '.hlt-dep';

/* ------------------------------------------------------------------------ */
/* Tiny runner                                                              */
/* ------------------------------------------------------------------------ */

const results = [];
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitReady(page) {
  await page.waitFor(() => document.documentElement.dataset.appReady === 'true', { timeout: 20000, message: 'app ready' });
}

async function gotoHash(page, hash, view) {
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

/** Elements of `selector` that stick out of the viewport (tables scroll inside their own box). */
const overflowingIn = (page, selector) => page.evaluate((sel) => {
  const root = document.querySelector(sel);
  if (!root) return ['(no element)'];
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of root.querySelectorAll('*')) {
    if (el.closest('.dt-scroll, pre, .code-block')) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
}, selector);

/** A screenshot of one element (the card), however tall. */
async function shotEl(page, name, selector) {
  if (!SHOTS_ON) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    window.scrollTo(0, 0);
    const r = el.getBoundingClientRect();
    return { x: Math.max(0, r.left + window.scrollX), y: Math.max(0, r.top + window.scrollY), width: r.width, height: r.height };
  }, selector);
  if (!box || !box.width || !box.height) return;
  await mkdir(SHOTS, { recursive: true });
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.min(Math.ceil(box.height), 9000), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}

async function assertClean(page, where) {
  const p = await page.problems();
  const issues = [
    ...p.consoleErrors.map((m) => `console.${m.type}: ${m.text}`),
    ...p.exceptions.map((e) => `exception: ${e.text}`),
    ...p.csp.map((c) => `CSP: ${JSON.stringify(c).slice(0, 300)}`)
  ];
  for (const e of p.logErrors) {
    // The registry's 503 and 404 the world asks for are failed resource loads in the log.
    if (/status of (404|503)/.test(e.text || '')) continue;
    issues.push(`log(${e.source}): ${e.text} ${e.url || ''}`);
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
    const pick = (lang) => i.listKeys(lang).filter((k) => k.startsWith('tko.') || k.startsWith('hlt.dep.'));
    const en = pick('en');
    const tr = pick('tr');
    return { missing: i.getMissingKeys(), onlyEn: en.filter((k) => !tr.includes(k)), onlyTr: tr.filter((k) => !en.includes(k)), count: en.length };
  });
  assertEqual(info.missing, [], 'missing i18n keys');
  assertEqual(info.onlyEn, [], 'tko.* / hlt.dep.* keys only in EN');
  assertEqual(info.onlyTr, [], 'tko.* / hlt.dep.* keys only in TR');
  assert(info.count > 100, `tko.* and hlt.dep.* keys registered (${info.count})`);
}

/* ------------------------------------------------------------------------ */
/* The world, answered in the page                                          */
/* ------------------------------------------------------------------------ */

const SOA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026100901, refresh: 3600, retry: 900, expire: 1209600, minimum: 300 };
/** Documentation names and addresses only. */
const WORLD = {
  'example.com': {
    A: ['192.0.2.80'], SOA: [SOA], NS: ['ns1.example.com', 'ns2.example.com'], MX: [{ preference: 10, exchange: 'mx.example.com' }],
    TXT: [['v=spf1 include:_spf.example.net a:relay.example.org -all']],
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'iodef', value: 'mailto:security@example.com' }],
    HTTPS: [{ priority: 1, target: '.', params: { alpn: ['h2'] } }]
  },
  'www.example.com': { A: ['192.0.2.80'] },
  'ns1.example.com': { A: ['192.0.2.53'] },
  'ns2.example.com': { A: ['198.51.100.53'] },
  'mx.example.com': { A: ['192.0.2.25'] },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; rua=mailto:dmarc@reports.example-test.com.tr']] },
  'selector1._domainkey.example.com': { CNAME: 'selector1.dkim.example.net' },
  '_mta-sts.example.com': { TXT: [['v=STSv1; id=20261009']] },
  'mta-sts.example.com': { CNAME: 'example-mta-sts.github.io' },
  '_acme-challenge.example.com': { CNAME: '_acme-challenge.example.org' },
  '_sip._tls.example.com': { SRV: [{ priority: 100, weight: 1, port: 443, target: 'sipdir.example.net' }] },
  'example-mta-sts.github.io': { A: ['198.51.100.80'] },
  '_spf.example.net': { TXT: [['v=spf1 ip4:192.0.2.0/24 -all']] },
  'selector1.dkim.example.net': { TXT: [['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA']] },
  'example.net': {
    A: ['203.0.113.10'], SOA: [{ ...SOA, mname: 'ns1.example.net' }], NS: ['ns1.example.net'], MX: [{ preference: 10, exchange: 'mx.example.org' }], TXT: [['v=spf1 mx -all']]
  },
  'ns1.example.net': { A: ['203.0.113.53'] }
};

/**
 * The page's network: DoH from `WORLD` (CNAME chains followed across it), the IANA bootstrap and
 * rdap.registry.invalid (example.com and, once healed, example.net registered; example-test.com.tr
 * pending deletion; anything else 404; example.net 503 until `__tw.heal`), `__tw.delay` ms before
 * each RDAP answer (aborted with its request). Every question lands in `__tw.dns`, every RDAP
 * domain in `__tw.rdap`, anything else is refused and lands in `__tw.blocked`.
 */
const worldScript = (world) => `(() => {
  const WORLD = ${JSON.stringify(world)};
  const tw = window.__tw = { dns: [], rdap: [], blocked: [], heal: false, delay: 0 };
  const day = 864e5;
  const below = (name) => Object.keys(WORLD).some((k) => k.endsWith('.' + name));
  const answer = (qname, type) => {
    const answers = [];
    let name = qname;
    for (let hop = 0; hop < 8; hop += 1) {
      const node = WORLD[name];
      if (!node) return { rcode: below(name) ? 'NOERROR' : 'NXDOMAIN', answers };
      if (node.CNAME && type !== 'CNAME') {
        answers.push({ name, type: 'CNAME', ttl: 300, data: node.CNAME });
        name = node.CNAME;
        continue;
      }
      for (const data of node[type] || []) answers.push({ name, type, ttl: 300, data });
      return { rcode: 'NOERROR', answers };
    }
    return { rcode: 'SERVFAIL', answers };
  };
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/rdap+json' } });
  const domainJson = (d, status, days) => ({
    objectClassName: 'domain', ldhName: d.toUpperCase(), status,
    events: [{ eventAction: 'registration', eventDate: '2001-05-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: new Date(Date.now() + days * day).toISOString() }]
  });
  const wait = (ms, signal) => new Promise((resolve, reject) => {
    if (!ms) return resolve();
    const timer = setTimeout(resolve, ms);
    if (signal) signal.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
  });
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url === 'https://data.iana.org/rdap/dns.json') {
      return json({ version: '1.0', publication: '2026-10-01T00:00:00Z', services: [[['com', 'net', 'org', 'tr'], ['https://rdap.registry.invalid/']]] });
    }
    const rd = /^https:[/][/](?:rdap[.]registry[.]invalid|rdap[.]org)[/]domain[/]([^/?#]+)$/.exec(url);
    if (rd) {
      const d = rd[1].toLowerCase();
      tw.rdap.push(d);
      await wait(tw.delay, init && init.signal);
      if (d === 'example.com') return json(domainJson(d, ['client transfer prohibited'], 400));
      if (d === 'example.net') return tw.heal ? json(domainJson(d, ['client transfer prohibited'], 12)) : json({ errorCode: 503, title: 'Service Unavailable' }, 503);
      if (d === 'example-test.com.tr') return json(domainJson(d, ['pending delete'], -3));
      return json({ errorCode: 404, title: 'Not Found' }, 404);
    }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (new URL(url, location.href).origin === location.origin) return realFetch(input, init);
      tw.blocked.push(url);
      throw new TypeError('blocked by the E2E (takeover world)');
    }
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    tw.dns.push(name + '|' + q.type);
    const out = answer(name, q.type);
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode, questions: [{ name: q.name, type: q.type }], answers: out.answers,
      authorities: out.answers.length ? [] : [{ name: 'example.com', type: 'SOA', ttl: 300, data: ${JSON.stringify(SOA)} }], edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/** The card's rows: severity, host, record, target (the first four cells). */
const depRows = (page) => page.evaluate((card) => [...document.querySelectorAll(`${card} .tko-table tbody tr.dt-row`)]
  .map((tr) => [...tr.querySelectorAll('td')].slice(0, 4).map((td) => td.textContent.trim()).join(' | ')), CARD);
/** What the card shows besides its rows. */
const cardInfo = (page) => page.evaluate((card) => {
  const el = document.querySelector(card);
  if (!el) return null;
  const summary = el.querySelector('[data-part="tko-summary"]');
  return {
    title: el.querySelector('.card-title')?.textContent || '',
    risks: summary ? summary.dataset.risks : null,
    failed: [...el.querySelectorAll('[data-failed]')].map((li) => [li.dataset.failed, li.querySelector('.na-mark')?.dataset.na || null]),
    retry: !!el.querySelector('[data-action="tko-retry"]'),
    page: el.querySelector('[data-action="tko-http"]')?.textContent || null,
    open: el.querySelector('[data-action="dep-open"]')?.textContent || null,
    run: el.querySelector('[data-action="tko-run"]')?.textContent || null,
    text: el.textContent.replace(/\s+/g, ' ')
  };
}, CARD);

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  if (SHOTS_ON) await mkdir(SHOTS, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: BROWSER, headless: !HEADED });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}\n`);
  try {
    await dependenciesGroup(browser, server);
  } finally {
    await browser.close();
    await server.close();
  }
  const failed = results.filter((r) => !r.ok);
  process.stdout.write(`\n${results.length - failed.length} passed, ${failed.length} failed${SHOTS_ON ? ` — screenshots in ${SHOTS}` : ''}\n`);
  if (failed.length) {
    for (const f of failed) process.stdout.write(`  - ${f.group}: ${f.name}\n`);
    process.exitCode = 1;
  }
}

async function dependenciesGroup(browser, server) {
  group('Offline: Domain Health › Dependencies (DNS and RDAP answered in the page)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: worldScript(WORLD) });
  await installDownloadCapture(page);
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  try {
    await step('example.com: nothing sent before the click; every kind on one click (the keyboard opens it); n/a and Retry; the CSV; the page check offered', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await gotoHash(page, '#/health?domain=example.com', 'health');
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'the health check' });
      await page.waitFor((card) => !!document.querySelector(`${card} [data-action="dep-open"]`), { args: [CARD], message: 'the Dependencies card' });
      const before = await cardInfo(page);
      assertEqual([before.title, before.open], ['Dependencies', 'Check dependencies (RDAP)'], 'the card before the click');
      assert(/Runs only when you click: DNS queries go to your resolver, and RDAP lookups of those domains go to their registries\./.test(before.text), 'what a click sends');
      assert(/The domains example\.com depends on through its records/.test(before.text), 'the intro names the domain');
      const sentBefore = await page.evaluate(() => ({
        rdap: [...new Set(window.__tw.rdap)], rdapCalls: window.__tw.rdap.filter((d) => d === 'example.com').length, dns: window.__tw.dns.slice()
      }));
      assertEqual(sentBefore.rdap, ['example.com'], 'only the health check\'s own RDAP lookup');
      assertEqual(sentBefore.dns.filter((q) => /^(_acme-challenge|mta-sts|_sip\._tls|_autodiscover\._tcp)\./.test(q)), [], 'no question of a new kind before the click');

      // The keyboard opens it: Enter on the focused button.
      await page.evaluate((card) => document.querySelector(`${card} [data-action="dep-open"]`).focus(), CARD);
      await page.press('Enter');
      await page.waitFor((card) => !!document.querySelector(`${card} [data-part="tko-summary"]`), { args: [CARD], timeout: 30000, message: 'the dependency results' });
      const first = await cardInfo(page);
      assertEqual([first.risks, first.failed, first.retry, first.page], ['4', [['example.net', 'rdap']], true, 'Check the page (1 probe)'],
        'four at risk, the 503 as n/a with Retry, the page check offered');
      assertEqual(await depRows(page), [
        'Critical | _acme-challenge.example.com | _acme-challenge CNAME | _acme-challenge.example.org',
        'High | _dmarc.example.com | DMARC | reports.example-test.com.tr',
        'High | example.com | SPF host | relay.example.org',
        'Low | _sip._tls.example.com | SRV | sipdir.example.net',
        'To check | mta-sts.example.com | MTA-STS CNAME | example-mta-sts.github.io'
      ], 'every kind, worst first');
      const asked = await page.evaluate(() => ({ rdap: window.__tw.rdap.slice(), dns: window.__tw.dns.slice() }));
      assertEqual([...new Set(asked.rdap)].sort(), ['example-test.com.tr', 'example.com', 'example.net', 'example.org'], 'RDAP: the domains the records name');
      assertEqual(asked.rdap.filter((d) => d === 'example.com').length, sentBefore.rdapCalls, 'never our own domain again');
      assert(!asked.rdap.some((d) => /github\.io/.test(d)), 'a catalogue provider is never looked up');
      for (const q of ['_acme-challenge.example.com|TXT', 'mta-sts.example.com|A', '_sip._tls.example.com|SRV', '_autodiscover._tcp.example.com|SRV', 'example.com|HTTPS', 'example.com|CAA',
        'k1._domainkey.example.com|TXT', 'relay.example.org|A', 'sipdir.example.net|A']) assert(asked.dns.includes(q), `asked ${q}`);
      const fixes = await page.evaluate((card) => [...document.querySelectorAll(`${card} .tko-table tbody tr.dt-row td[data-label="Fix"]`)].map((td) => td.textContent), CARD);
      assert(fixes.includes('Remove a:relay.example.org from the SPF record, or register example.org yourself.'), `the SPF host's fix: ${fixes.join(' / ')}`);
      assert(fixes.includes('Renew example-test.com.tr if it is yours; otherwise remove the report address at reports.example-test.com.tr from the DMARC record (rua) before the domain is released.'),
        `the DMARC fix: ${fixes.join(' / ')}`);
      await shotEl(page, 'takeover-dependencies-1440-en', CARD);

      // Retry asks only the registry that failed; it answers now, and what rests on example.net appears.
      const rdapBefore = await page.evaluate(() => { window.__tw.heal = true; return window.__tw.rdap.length; });
      await page.click(`${CARD} [data-action="tko-retry"]`);
      await page.waitFor((card) => document.querySelector(`${card} [data-part="tko-summary"]`)?.dataset.risks === '6', { args: [CARD], timeout: 30000, message: 'after Retry' });
      const again = await page.evaluate((n) => [...new Set(window.__tw.rdap.slice(n))], rdapBefore);
      assertEqual(again, ['example.net'], 'only example.net asked again');
      assertEqual((await cardInfo(page)).failed, [], 'no failure left');
      assertEqual(await depRows(page), [
        'Critical | _acme-challenge.example.com | _acme-challenge CNAME | _acme-challenge.example.org',
        'High | _dmarc.example.com | DMARC | reports.example-test.com.tr',
        'High | example.com | SPF host | relay.example.org',
        'Medium | _sip._tls.example.com | SRV | sipdir.example.net',
        'Medium | example.com | SPF include | _spf.example.net',
        'Medium | selector1._domainkey.example.com | DKIM CNAME | selector1.dkim.example.net',
        'To check | mta-sts.example.com | MTA-STS CNAME | example-mta-sts.github.io'
      ], 'the expiring domain\'s references after Retry');

      // CSV: severity and record kind as codes, the rest in English.
      await takeDownloads(page);
      await page.click(`${CARD} [data-export="csv"]`);
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'CSV export' });
      const [csv] = await takeDownloads(page);
      const lines = csv.text.replace(/^﻿/, '').trim().split(/\r\n/);
      assertEqual(lines[0], 'Severity,Host,Record,Points to,Service,Service status,Evidence,Fix,Reference', 'CSV header');
      assertEqual(lines.length, 8, 'a header and seven rows');
      assert(lines[1].startsWith('critical,_acme-challenge.example.com,acme,_acme-challenge.example.org,,,'), `first row: ${lines[1]}`);
      assert(lines.some((l) => l.startsWith('info,mta-sts.example.com,mta-sts,example-mta-sts.github.io,GitHub Pages,edge,')), 'the GitHub Pages row');
      const sent = await page.evaluate(() => window.__tw.blocked.slice());
      assertEqual(sent, [], 'nothing else left the page (the page check was not clicked: no Globalping)');
      await assertClean(page, 'dependencies');
    });

    await step('the results stay across a language switch (Turkish words), and fit 375 and 320 px in light and dark', async () => {
      const sentBefore = await page.evaluate(() => [window.__tw.rdap.length, window.__tw.dns.length]);
      await setLangUi(page, 'tr');
      await page.waitFor((card) => !!document.querySelector(`${card} [data-part="tko-summary"]`), { args: [CARD], timeout: 15000, message: 'results after the re-mount' });
      const tr = await cardInfo(page);
      assertEqual([tr.title, tr.risks], ['Bağımlılıklar', '6'], 'the Turkish card keeps its results');
      const rows = await depRows(page);
      assertEqual(rows[0], 'Kritik | _acme-challenge.example.com | _acme-challenge CNAME | _acme-challenge.example.org', 'Turkish severity');
      assert(rows.includes('Yüksek | example.com | SPF host | relay.example.org'), rows.join(' / '));
      const fixes = await page.evaluate((card) => [...document.querySelectorAll(`${card} .tko-table tbody tr.dt-row td[data-label="Çözüm"]`)].map((td) => td.textContent), CARD);
      assert(fixes.includes('SPF kaydından a:relay.example.org ifadesini kaldırın ya da example.org alan adını kendiniz kaydedin.'), `Turkish fix: ${fixes.join(' / ')}`);
      assertEqual((await page.evaluate(() => [window.__tw.rdap.length, window.__tw.dns.length]))[0], sentBefore[0], 'no RDAP lookup asked again by the re-mount');
      await checkI18n(page);
      for (const width of [375, 320]) {
        await page.setViewport({ width, height: 800, mobile: true });
        for (const lang of ['tr', 'en']) {
          for (const scheme of ['dark', 'light']) {
            await setLangUi(page, lang);
            await page.emulateMedia({ 'prefers-color-scheme': scheme });
            await page.waitFor((card) => !!document.querySelector(`${card} [data-part="tko-summary"]`), { args: [CARD], timeout: 15000, message: 'results after re-mount' });
            await sleep(150);
            await assertNoHorizontalScroll(page, `dependencies ${width} ${lang} ${scheme}`);
            assertEqual(await overflowingIn(page, CARD), [], `the card inside ${width} px (${lang} ${scheme})`);
            if (width === 375 && scheme === 'dark') await shotEl(page, `takeover-dependencies-375-${lang}-dark`, CARD);
          }
        }
      }
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await assertClean(page, 'dependencies re-mounted');
    });

    await step('a check of another domain starts the card afresh; Stop sends nothing more and leaves the card\'s own button', async () => {
      await gotoHash(page, '#/health?domain=example.net', 'health');
      await page.waitFor(() => document.querySelector('.hlt-hero')?.textContent.includes('example.net'), { timeout: 30000, message: 'example.net checked' });
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'the health check of example.net' });
      await page.waitFor((card) => !!document.querySelector(`${card} [data-action="dep-open"]`), { args: [CARD], message: 'the card afresh' });
      assert(!(await cardInfo(page)).risks, 'no result of example.com on example.net\'s card');
      const rdapBefore = await page.evaluate(() => { window.__tw.delay = 4000; return window.__tw.rdap.length; });
      await page.click(`${CARD} [data-action="dep-open"]`);
      await page.waitFor((card) => !!document.querySelector(`${card} [data-action="tko-stop"]`), { args: [CARD], timeout: 15000, message: 'running' });
      // example.net's MX names example.org: its RDAP lookup waits in the world's delay.
      await page.waitFor((n) => window.__tw.rdap.slice(n).includes('example.org'), { args: [rdapBefore], timeout: 15000, message: 'an RDAP lookup in flight' });
      await page.click(`${CARD} [data-action="tko-stop"]`);
      await page.waitFor((card) => !!document.querySelector(`${card} [data-action="tko-run"]`), { args: [CARD], timeout: 15000, message: 'stopped' });
      const stopped = await cardInfo(page);
      assert(/The check was stopped; nothing more was sent\./.test(stopped.text), stopped.text);
      assertEqual(stopped.run, 'Check dependencies (RDAP)', 'the card\'s own button after a stop');
      await page.evaluate(() => { window.__tw.delay = 0; });
      await assertClean(page, 'stopped');
    });
  } finally {
    await page.close();
  }
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
