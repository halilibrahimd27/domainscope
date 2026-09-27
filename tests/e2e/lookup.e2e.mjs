#!/usr/bin/env node
/**
 * lookup.e2e.mjs — end-to-end test of the "DNS Lookup" view in a real headless browser,
 * against live DoH resolvers (network required).
 *
 *   node tests/e2e/lookup.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--offline]
 *
 * OFFLINE group (always runs; --offline skips the live ones): example.com answered in the page
 * (scan.e2e.mjs zoneHandoffScript). NODATA types fold into one "No records" line of the summary,
 * the resolver and the header flags are said once there, a card repeats only what differs; a
 * query that got no answer (HTTP 429 from every resolver) keeps its card with the reason and a
 * Retry that asks that type alone again, also while a slower type of the same lookup still runs;
 * 1440 and 375 px, light and dark, English and Turkish.
 *
 * Covers: pure helpers (Node); shared link with many types + DNSSEC (parsed A/AAAA, MX, TXT,
 * SOA, CAA, HTTPS, DS, DNSKEY cards, AD flag, RRSIG section, raw dig text); IP → PTR; NXDOMAIN;
 * a specific resolver; presets and "other types" validation; host links navigating inside the
 * view; language re-mount keeping results; phone light/dark; no console errors, exceptions or
 * CSP violations; complete i18n.
 */

import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { zoneHandoffScript } from './scan.e2e.mjs';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import {
  parseTypes, parseLookupName, soaSerialDate, rrsigStatus, txtKinds, digLine, responseText, TYPE_PRESETS
} from '../../assets/js/views/lookup.js';

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
/** Third-party hosts whose request failures the view reports in its UI: every public DoH
 *  resolver can time out or, like Quad9 over HTTP/3, omit CORS headers. */
const FLAKY_HOSTS = [...RESOLVERS.map((r) => new URL(r.url).hostname)];
// Every type answered: a NODATA type has no card (it is listed in the summary's "No records" line).
const ALL_DONE = "!!document.querySelector('.lkp-sum') && !document.querySelector('.lkp-card[data-state=\"pending\"]') && document.querySelector('[data-action=\"run\"]')?.getAttribute('aria-busy') !== 'true'";

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
    const en = i.listKeys('en').filter((k) => k.startsWith('lkp.'));
    const tr = i.listKeys('tr').filter((k) => k.startsWith('lkp.'));
    return { missing: i.getMissingKeys(), onlyEn: en.filter((k) => !tr.includes(k)), onlyTr: tr.filter((k) => !en.includes(k)) };
  });
  assertEqual(info.missing, [], 'missing i18n keys');
  assertEqual(info.onlyEn, [], 'lkp.* keys only in EN');
  assertEqual(info.onlyTr, [], 'lkp.* keys only in TR');
}

/**
 * Summary of every card: type → { state, count, flags set, text sample }. The flags every answer
 * shares are shown once in the summary; a card shows its own only when they differ.
 */
function cardsInfo() {
  const out = {};
  const shared = [...document.querySelectorAll('.lkp-sum-flags .lkp-flag[data-set="1"]')].map((f) => f.dataset.flag);
  for (const card of document.querySelectorAll('.lkp-card')) {
    const own = card.querySelector('.lkp-flags');
    out[card.dataset.type] = {
      state: card.dataset.state,
      count: Number(card.dataset.count || 0),
      flags: own ? [...own.querySelectorAll('.lkp-flag[data-set="1"]')].map((f) => f.dataset.flag) : shared,
      ownFlags: !!own,
      ownMeta: !!card.querySelector('.lkp-meta'),
      sigs: !!card.querySelector('.lkp-sigs'),
      text: card.textContent.replace(/\s+/g, ' ').slice(0, 2000),
      raw: card.querySelector('.lkp-raw code')?.textContent || ''
    };
  }
  return out;
}

/** The summary: name, meta line, shared flags, the "No records" types. */
function summaryInfo() {
  const sum = document.querySelector('.lkp-sum');
  if (!sum) return null;
  return {
    meta: sum.querySelector('.lkp-sum-meta')?.textContent.replace(/\s+/g, ' ') || '',
    flags: [...sum.querySelectorAll('.lkp-sum-flags .lkp-flag[data-set="1"]')].map((f) => f.dataset.flag),
    noRecords: sum.querySelector('.lkp-nodata')?.dataset.types.split(' ') || [],
    noRecordsText: sum.querySelector('.lkp-nodata summary')?.textContent.replace(/\s+/g, ' ').trim() || ''
  };
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  group('Pure helpers (Node)');
  await step('parseTypes: mnemonics, numbers, TYPE123, meta types rejected', () => {
    assertEqual(parseTypes('a, mx TYPE65 bogus 28 axfr opt'), { types: ['A', 'MX', 'HTTPS', 'AAAA'], invalid: ['bogus', 'axfr', 'opt'] }, 'mixed');
    assertEqual(parseTypes(['A,AAAA', 'MX', 'a']), { types: ['A', 'AAAA', 'MX'], invalid: [] }, 'array + dedupe');
    assertEqual(parseTypes(''), { types: [], invalid: [] }, 'empty');
    assertEqual(parseTypes('ALL').types, [...TYPE_PRESETS.common], 'ALL = "All common" preset');
    assertEqual(parseTypes('mx,dnssec').types, ['MX', 'DS', 'DNSKEY', 'SOA'], 'preset names expand in place');
    assertEqual(TYPE_PRESETS.common, ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'HTTPS'], 'common preset');
  });
  await step('parseLookupName: IP → PTR name, URL/IDN hosts, TLDs, root, garbage', () => {
    assertEqual(parseLookupName('8.8.8.8'), { name: '8.8.8.8.in-addr.arpa', ptrFor: '8.8.8.8' }, 'v4');
    assertEqual(parseLookupName('2001:db8::1').name.endsWith('.8.b.d.0.1.0.0.2.ip6.arpa'), true, 'v6 nibbles');
    assertEqual(parseLookupName('https://Örnek.com.tr/path'), { name: 'xn--rnek-4qa.com.tr', ptrFor: null }, 'IDN URL');
    assertEqual(parseLookupName('com'), { name: 'com', ptrFor: null }, 'TLD');
    assertEqual(parseLookupName('.'), { name: '.', ptrFor: null }, 'root');
    assertEqual(parseLookupName('not a name'), null, 'garbage');
    assertEqual(parseLookupName(''), null, 'empty');
  });
  await step('soaSerialDate, rrsigStatus, txtKinds, digLine, responseText', () => {
    assertEqual(soaSerialDate(2024092301), { date: '2024-09-23', rev: 1 }, 'date serial');
    assertEqual(soaSerialDate(2415557203), null, 'not a date');
    assertEqual(soaSerialDate(2024023101), null, 'impossible date');
    const now = Date.UTC(2026, 8, 23);
    assertEqual(rrsigStatus({ inception: new Date(now - 1e6), expiration: new Date(now + 1e6) }, now), 'valid', 'valid');
    assertEqual(rrsigStatus({ inception: new Date(now - 2e6), expiration: new Date(now - 1e6) }, now), 'expired', 'expired');
    assertEqual(rrsigStatus({ inception: new Date(now + 1e6), expiration: new Date(now + 2e6) }, now), 'future', 'future');
    assertEqual(rrsigStatus({}), 'unknown', 'unknown');
    assertEqual(txtKinds('v=spf1 -all').map((k) => k.kind), ['spf'], 'spf');
    assertEqual(txtKinds('v=DMARC1; p=reject').map((k) => k.kind), ['dmarc'], 'dmarc');
    assertEqual(txtKinds('google-site-verification=x'), [{ kind: 'verification', service: 'Google' }], 'google');
    assertEqual(txtKinds('docker-verification=x'), [{ kind: 'verification', service: 'Docker' }], 'generic');
    assertEqual(txtKinds('hello world'), [], 'plain');
    assertEqual(digLine({ name: 'example.com', ttl: 60, type: 'A', text: '192.0.2.1' }), 'example.com.\t60\tIN\tA\t192.0.2.1', 'dig line');
    const txt = responseText({ name: 'example.com', type: 'A', resolver: 'cloudflare', ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: true }, elapsedMs: 12, ede: [{ code: 3, name: 'Stale Answer', text: '' }], answers: [{ name: 'example.com', ttl: 60, type: 'A', text: '192.0.2.1' }], authorities: [] });
    assert(txt.includes('status: NOERROR, flags: qr rd ra ad, 12 ms') && txt.includes(';; ANSWER SECTION:') && txt.includes(';; EDE 3 (Stale Answer)'), `responseText: ${txt}`);
  });

  await mkdir(SHOTS, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: BROWSER, headless: !HEADED });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}\n`);

  try {
    await offlineGroup(browser, server);
    if (!OFFLINE) await liveGroups(browser, server);
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

/* ------------------------------------------------------------------------ */
/* Offline: density and a query that got no answer                          */
/* ------------------------------------------------------------------------ */

/** A typical small apex, answered in the page: no CNAME, CAA or HTTPS records (NODATA). */
const APEX_ZONE = {
  'example.com': {
    A: ['203.0.113.10'],
    AAAA: ['2001:db8::10'],
    MX: [{ preference: 10, exchange: 'mx1.example.com' }, { preference: 20, exchange: 'mx2.example.com' }],
    NS: ['ns1.example.com', 'ns2.example.com'],
    TXT: [['v=spf1 mx -all'], ['google-site-verification=abcdefghijklmnopqrstuvwxyz0123456789']],
    SOA: [{ mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026092701, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }]
  },
  'mx1.example.com': { A: ['203.0.113.25'] },
  'mx2.example.com': { A: ['203.0.113.26'] },
  // Seven cards: balanced columns would move TXT between them when the SOA or CAA raw answer opens.
  'cols.example.com': {
    A: ['203.0.113.11'],
    AAAA: ['2001:db8::11'],
    MX: [{ preference: 10, exchange: 'mx1.example.com' }, { preference: 20, exchange: 'mx2.example.com' }],
    NS: ['ns1.example.com', 'ns2.example.com'],
    TXT: [['v=spf1 mx -all'], ['google-site-verification=abcdefghijklmnopqrstuvwxyz0123456789']],
    SOA: [{ mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026092701, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }],
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'iodef', value: 'mailto:security@example.com' }]
  }
};

/**
 * Every DoH query for a type in `window.__dohFail.types` gets HTTP 429 from every resolver (a
 * rate limit), and a type in `window.__dohFail.slow` (type → ms) is answered that much later,
 * before the zone script answers the rest. `asked` lists the type of every query. Installed
 * after the zone script.
 */
const DOH_FAIL_SCRIPT = `(() => {
  const inner = window.fetch;
  let wire = null;
  const fail = window.__dohFail = { types: [], slow: {}, hits: 0, asked: [] };
  const wait = (ms, signal) => new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    if (signal) signal.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
  });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (m) {
      wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
      const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
      fail.asked.push(q.type);
      if (fail.types.includes(q.type)) {
        fail.hits += 1;
        return new Response('Too Many Requests', { status: 429 });
      }
      if (fail.slow[q.type]) await wait(fail.slow[q.type], init && init.signal);
    }
    return inner(input, init);
  };
})();`;

async function offlineGroup(browser, server) {
  group('Offline: density and a failed query (example.com answered in the page)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript('example.com', APEX_ZONE) });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: DOH_FAIL_SCRIPT });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  try {
    await step('NODATA types fold into one "No records" line; resolver and flags are said once', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await gotoHash(page, '#/lookup?name=example.com&type=ALL', 'lookup');
      await page.waitFor(ALL_DONE, { timeout: 30000, message: 'all types answered' });
      const c = await page.evaluate(cardsInfo);
      const s = await page.evaluate(summaryInfo);
      assertEqual(Object.keys(c), ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA'], 'cards: the types with records');
      assertEqual(s.noRecords, ['CNAME', 'CAA', 'HTTPS'], 'the NODATA types');
      assertEqual(s.noRecordsText, 'No records: CNAME, CAA, HTTPS', 'the line');
      assertEqual(s.flags, ['rd', 'ra'], 'the shared header flags, once');
      assert(/answered by Cloudflare/.test(s.meta), `the resolver, once: ${s.meta}`);
      assert(Object.values(c).every((x) => !x.ownFlags && !x.ownMeta), 'no card repeats the flags or the resolver');
      // The folded answers are one click away: what NODATA means, the negative-caching time, the raw text.
      await page.click('.lkp-nodata summary');
      const body = await page.evaluate(() => document.querySelector('.lkp-nodata .disclosure-body').textContent.replace(/\s+/g, ' '));
      assert(/has no records of these types \(NODATA\)/.test(body) && /Negative answer cached for 1 min/.test(body), `details: ${body.slice(0, 200)}`);
      const raw = await page.evaluate(() => document.querySelector('.lkp-nodata .lkp-raw code').textContent);
      assert(['CNAME', 'CAA', 'HTTPS'].every((type) => raw.includes(`example.com. ${type} @`)), `raw answers: ${raw.slice(0, 200)}`);
      const cols = await page.evaluate(() => getComputedStyle(document.querySelector('.lkp-cards')).columnWidth);
      assertEqual(cols, '480px', 'record cards flow in CSS columns');
      await assertNoHorizontalScroll(page, 'density desktop');
      await shot(page, 'lookup-offline-desktop-light-en');
    });

    await step('opening a raw answer grows its own column only: the other cards keep their place', async () => {
      const rects = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.lkp-card')].map((card) => {
        const r = card.getBoundingClientRect();
        return [card.dataset.type, { left: Math.round(r.left), top: Math.round(r.top + scrollY) }];
      })));
      await gotoHash(page, '#/lookup?name=cols.example.com&type=ALL', 'lookup');
      await page.waitFor(ALL_DONE, { timeout: 30000, message: 'all types answered' });
      await page.waitFor(() => document.querySelector('.lkp-card.lkp-col-start'), { timeout: 3000, message: 'columns pinned' });
      const before = await rects();
      assertEqual(Object.keys(before), ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA'], 'cards');
      assert(new Set(Object.values(before).map((r) => r.left)).size === 2, `two columns at 1440 px: ${JSON.stringify(before)}`);
      for (const type of ['A', 'SOA', 'CAA']) {
        await page.click(`.lkp-card[data-type="${type}"] .lkp-raw summary`);
        await page.waitFor((x) => document.querySelector(`.lkp-card[data-type="${x}"] .lkp-raw`)?.open, { args: [type], message: `${type} raw answer open` });
        const after = await rects();
        const moved = Object.keys(before).filter((k) => after[k].left !== before[k].left
          || (before[k].left !== before[type].left && after[k].top !== before[k].top));
        assertEqual(moved, [], `cards that moved when the ${type} raw answer opened`);
        await page.click(`.lkp-card[data-type="${type}"] .lkp-raw summary`);
      }
      // One column on a narrower window: no pin is left to push a card into an overflow column.
      await page.setViewport({ width: 900, height: 900 });
      await page.waitFor(() => !document.querySelector('.lkp-card.lkp-col-start'), { timeout: 3000, message: 'pins dropped at 900 px' });
      await assertNoHorizontalScroll(page, 'one column');
      await page.setViewport({ width: 1440, height: 900 });
      await page.waitFor(() => document.querySelector('.lkp-card.lkp-col-start'), { timeout: 3000, message: 'pinned again at 1440 px' });
      assertEqual(await rects(), before, 'the same layout as before');
    });

    await step('a query that got no answer keeps its card, with the reason and a Retry of that type alone (also while a slow type still runs)', async () => {
      // MX is rate limited at once; TXT takes 4 s, so the lookup is still running when MX fails.
      await page.evaluate(() => { window.__dohFail.types = ['MX']; window.__dohFail.slow = { TXT: 4000 }; });
      await gotoHash(page, '#/lookup?name=example.com&type=A,MX,TXT,CAA', 'lookup');
      await page.waitFor(() => document.querySelector('.lkp-card[data-type="MX"]')?.dataset.state === 'error', { timeout: 15000, message: 'MX failed' });
      let c = await page.evaluate(cardsInfo);
      assertEqual([c.MX.state, c.TXT.state], ['error', 'pending'], 'MX failed while TXT is still asked');
      assert(/Every resolver tried: rate limited — try again in a few minutes/.test(c.MX.text), `reason: ${c.MX.text.slice(0, 300)}`);
      assert(/1 × The query failed/.test((await page.evaluate(summaryInfo)).meta), 'the summary counts the failure');
      await page.evaluate(() => { window.__dohFail.types = []; });
      const before = await page.evaluate(() => window.__dohFail.asked.length);
      await page.evaluate(() => document.querySelector('.lkp-card[data-type="MX"] [data-action="retry-source"]').focus());
      await page.press('Enter');
      // The Retry works during the run: it does not wait for TXT.
      await page.waitFor(() => document.querySelector('.lkp-card[data-type="MX"]')?.dataset.state === 'noerror', { timeout: 3000, message: 'MX answered during the run' });
      c = await page.evaluate(cardsInfo);
      assertEqual([c.MX.count, c.TXT.state], [2, 'pending'], 'MX records while TXT is still on its way');
      const after = await page.evaluate(() => ({ asked: window.__dohFail.asked.slice(), focus: document.activeElement?.dataset?.type || document.activeElement?.tagName }));
      assertEqual(after.asked.slice(before), ['MX'], 'the Retry asked one query: MX');
      assertEqual(after.focus, 'MX', 'keyboard focus on the MX card');
      await page.waitFor(ALL_DONE, { timeout: 30000, message: 'answered' });
      c = await page.evaluate(cardsInfo);
      assertEqual([Object.keys(c), c.MX.state, c.MX.count, c.TXT.state], [['A', 'MX', 'TXT'], 'noerror', 2, 'noerror'], 'the run ends with MX answered; CAA folds');
      assert(!(await page.evaluate(summaryInfo)).meta.includes('failed'), 'no failure left in the summary');
      await page.evaluate(() => { window.__dohFail.slow = {}; });
    });

    await step('the "No records" line keeps its open raw answer and the keyboard focus while slower types answer', async () => {
      // TXT (a card) answers after 1.5 s, HTTPS (one more NODATA type) after 3 s.
      await page.evaluate(() => { window.__dohFail.slow = { TXT: 1500, HTTPS: 3000 }; });
      await gotoHash(page, '#/lookup?name=example.com&type=A,TXT,CNAME,CAA,HTTPS', 'lookup');
      await page.waitFor(() => document.querySelector('.lkp-nodata')?.dataset.types === 'CNAME CAA', { timeout: 3000, message: 'the line, before TXT' });
      await page.evaluate(() => document.querySelector('.lkp-nodata summary').focus());
      await page.press('Enter');
      await page.evaluate(() => document.querySelector('.lkp-nodata .lkp-raw summary').focus());
      await page.press('Enter');
      await page.evaluate(() => { document.querySelector('.lkp-nodata').dataset.mark = 'kept'; });
      const line = () => page.evaluate(() => {
        const el = document.querySelector('.lkp-nodata');
        const a = document.activeElement;
        return {
          types: el.dataset.types,
          mark: el.dataset.mark || null,
          open: el.querySelector('.lkp-nodata-box').open,
          raw: el.querySelector('.lkp-raw').open,
          focus: a && a.tagName === 'SUMMARY' && el.contains(a) ? (a.closest('.lkp-raw') ? 'raw' : 'line') : a?.tagName,
          text: el.querySelector('.lkp-raw code').textContent
        };
      });
      assertEqual(await line().then(({ text, ...x }) => x), { types: 'CNAME CAA', mark: 'kept', open: true, raw: true, focus: 'raw' }, 'opened with the keyboard');
      await page.waitFor(() => document.querySelector('.lkp-card[data-type="TXT"]')?.dataset.state === 'noerror', { timeout: 5000, message: 'TXT answered' });
      // TXT is a card: the line is the same node, nothing closed, the focus where it was.
      assertEqual(await line().then(({ text, ...x }) => x), { types: 'CNAME CAA', mark: 'kept', open: true, raw: true, focus: 'raw' }, 'after TXT');
      await page.waitFor(ALL_DONE, { timeout: 10000, message: 'HTTPS answered' });
      // HTTPS joins the line: drawn anew with its raw answer, still open, the focus on the same control.
      const last = await line();
      assertEqual([last.types, last.mark, last.open, last.raw, last.focus], ['CNAME CAA HTTPS', null, true, true, 'raw'], 'after HTTPS joined');
      assert(last.text.includes('example.com. HTTPS @'), `the new raw answer: ${last.text.slice(0, 200)}`);
      await page.evaluate(() => { window.__dohFail.slow = {}; });
    });

    for (const [scheme, lang, width] of [['light', 'en', 375], ['dark', 'tr', 375], ['dark', 'tr', 1440]]) {
      await step(`[${scheme}, ${lang.toUpperCase()}, ${width} px] the compact lookup reads well and fits`, async () => {
        await page.setViewport(width < 600 ? { width, height: 812, mobile: true } : { width, height: 900 });
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await setLangUi(page, lang);
        await page.evaluate(() => { window.__dohFail.types = ['HTTPS']; window.__dohFail.slow = {}; });
        await gotoHash(page, '#/about', 'about');
        await gotoHash(page, '#/lookup?name=example.com&type=ALL', 'lookup');
        await page.waitFor(ALL_DONE, { timeout: 30000, message: 'answered' });
        const s = await page.evaluate(summaryInfo);
        assertEqual(s.noRecords, ['CNAME', 'CAA'], 'NODATA line');
        if (lang === 'tr') assertEqual(s.noRecordsText, 'Kayıt yok: CNAME, CAA', 'TR line');
        await assertNoHorizontalScroll(page, `${scheme} ${lang} ${width}`);
        await shot(page, `lookup-offline-${width < 600 ? 'mobile' : 'desktop'}-${scheme}-${lang}`);
        await page.evaluate(() => { window.__dohFail.types = []; });
      });
    }

    await step('offline: nothing blocked, i18n complete, no console errors', async () => {
      assertEqual(await page.evaluate(() => window.__zoneBlocked.slice()), [], 'requests outside the zone');
      await checkI18n(page);
      await assertClean(page, 'offline');
    });
  } finally {
    await page.setViewport({ width: 1440, height: 900 });
    await page.close();
  }
}

/** The live groups: real DoH resolvers. */
async function liveGroups(browser, server) {
  group('Desktop 1440×900 (English, live resolvers)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  await setLangUi(page, 'en');

  await step('a typed but unsubmitted name survives a language switch without querying', async () => {
    await gotoHash(page, '#/lookup', 'lookup');
    await page.type('[data-role="lookup-name"]', 'example.org');
    await page.evaluate(() => performance.clearResourceTimings());
    await setLangUi(page, 'tr');
    await page.evaluate(() => new Promise((resolve) => { setTimeout(resolve, 800); }));
    const info = await page.evaluate(() => ({
      requests: performance.getEntriesByType('resource').filter((e) => !e.name.startsWith(window.location.origin)).map((e) => e.name),
      hash: window.location.hash,
      name: document.querySelector('[data-role="lookup-name"]').value,
      cards: document.querySelectorAll('.lkp-card').length
    }));
    await setLangUi(page, 'en');
    assertEqual(info, { requests: [], hash: '#/lookup', name: 'example.org', cards: 0 }, 'draft kept, nothing sent');
  });

  await step('shared link: cloudflare.com, 10 types, DNSSEC on → parsed cards', async () => {
    await gotoHash(page, '#/lookup?name=cloudflare.com&type=A,AAAA,MX,NS,TXT,SOA,CAA,HTTPS,DS,DNSKEY&dnssec=1', 'lookup');
    await page.waitFor(ALL_DONE, { timeout: 45000, message: 'all cards answered' });
    const c = await page.evaluate(cardsInfo);
    assertEqual(Object.keys(c), ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'HTTPS', 'DS', 'DNSKEY'], 'card order');
    for (const [type, info] of Object.entries(c)) assertEqual(info.state, 'noerror', `${type} NOERROR`);
    assert(c.A.count >= 1 && /Cloudflare/.test(c.A.text), 'A records with Cloudflare badge');
    assert(c.A.flags.includes('ad') && c.A.flags.includes('ra'), `AD + RA flags on A: ${c.A.flags}`);
    assert(c.A.sigs, 'RRSIG section with DO');
    assert(/Primary name server/.test(c.SOA.text) && /Negative TTL/.test(c.SOA.text), 'SOA fields');
    assert(/issue/.test(c.CAA.text) && /May issue certificates/.test(c.CAA.text), 'CAA parsed');
    assert(/alpn/.test(c.HTTPS.text), 'HTTPS params');
    assert(/KSK/.test(c.DNSKEY.text) && /ZSK/.test(c.DNSKEY.text), 'DNSKEY roles');
    assert(/ECDSAP256SHA256/.test(c.DS.text), 'DS algorithm');
    assert(/SPF/.test(c.TXT.text), 'SPF recognised in TXT');
    assert(c.MX.count >= 1, 'MX records');
    assert(c.A.raw.includes(';; ANSWER SECTION:') && c.A.raw.includes('cloudflare.com.'), 'raw dig text');
    const form = await page.evaluate(() => ({
      name: document.querySelector('[data-role="lookup-name"]').value,
      dnssec: document.querySelector('[data-role="lookup-dnssec"]').checked,
      checked: [...document.querySelectorAll('.lkp-types input:checked')].map((i) => i.value)
    }));
    assertEqual(form.name, 'cloudflare.com', 'name from URL');
    assert(form.dnssec, 'DO switch from URL');
    assertEqual(form.checked, ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'HTTPS', 'DS', 'DNSKEY'], 'types from URL');
    await assertNoHorizontalScroll(page, 'cloudflare');
    await shot(page, 'lookup-desktop-light-en-cloudflare');
  });

  await step('IP address → PTR (8.8.8.8 → dns.google) with a link to IP Intel', async () => {
    await page.type('[data-role="lookup-name"]', '8.8.8.8');
    await page.click('[data-action="run"]');
    await page.waitFor(() => document.querySelectorAll('.lkp-card').length === 1 && document.querySelector('.lkp-card').dataset.type === 'PTR'
      && document.querySelector('.lkp-card').dataset.state !== 'pending', { timeout: 30000 });
    const info = await page.evaluate(() => ({
      text: document.querySelector('.lkp-card').textContent,
      note: document.querySelector('.lkp-note').textContent,
      ipLink: !!document.querySelector('.lkp-sum a[href^="#/ip?ips=8.8.8.8"]'),
      checked: [...document.querySelectorAll('.lkp-types input:checked')].map((i) => i.value)
    }));
    assert(info.text.includes('dns.google'), 'PTR dns.google');
    assert(/8\.8\.8\.8\.in-addr\.arpa/.test(info.note), 'PTR note');
    assert(info.ipLink, 'IP Intel link');
    assertEqual(info.checked, ['PTR'], 'form synced to PTR');
  });

  await step('NXDOMAIN is explained (with the negative-caching TTL)', async () => {
    const name = `e2e-${Date.now().toString(36)}.invalid`; // RFC 6761: never exists
    await gotoHash(page, `#/lookup?name=${name}&type=A`, 'lookup');
    await page.waitFor(ALL_DONE, { timeout: 30000 });
    const c = await page.evaluate(cardsInfo);
    assertEqual(c.A.state, 'nxdomain', 'card state');
    assert(/does not exist/.test(c.A.text) && /Negative answer cached/.test(c.A.text), `explanation: ${c.A.text.slice(0, 300)}`);
  });

  await step('specific resolver (Google) + host links navigate inside the view', async () => {
    await gotoHash(page, '#/lookup?name=github.com&type=MX&resolver=google', 'lookup');
    await page.waitFor(ALL_DONE, { timeout: 30000 });
    const info = await page.evaluate(() => ({
      via: document.querySelector('.lkp-sum-meta').textContent,
      sel: document.querySelector('[data-role="lookup-resolver"]').value,
      href: document.querySelector('.lkp-card a.lkp-host')?.getAttribute('href')
    }));
    assert(/answered by Google Public DNS/.test(info.via), `answered by Google, said once in the summary: ${info.via}`);
    assertEqual(info.sel, 'google', 'resolver select');
    assert(info.href && info.href.startsWith('#/lookup?name='), `host link: ${info.href}`);
    const marker = await page.evaluate(() => { window.__lkpBody = document.querySelector('.lkp-view'); return true; });
    assert(marker, 'marker');
    await page.click('.lkp-card a.lkp-host');
    await page.waitFor(() => /name=[^&]*outlook\.com/.test(window.location.hash) && document.querySelector('[data-role="lookup-name"]').value.endsWith('outlook.com'), { message: 'navigated to MX host' });
    await page.waitFor(ALL_DONE, { timeout: 30000 });
    const after = await page.evaluate(() => ({ same: window.__lkpBody === document.querySelector('.lkp-view'), types: [...document.querySelectorAll('.lkp-card')].map((c) => c.dataset.type) }));
    assert(after.same, 'handled by update() without a re-mount');
    assertEqual(after.types, ['A', 'AAAA'], 'host link asks A + AAAA');
  });

  await step('presets and "other types" validation', async () => {
    await page.click('[data-preset="dnssec"]');
    const checked = await page.evaluate(() => [...document.querySelectorAll('.lkp-types input:checked')].map((i) => i.value));
    assertEqual(checked, ['SOA', 'DS', 'DNSKEY'], 'DNSSEC preset');
    await page.click('[data-preset="none"]');
    await page.type('[data-role="lookup-name"]', 'example.com');
    await page.type('[data-role="lookup-other-types"]', 'URI, NOPE');
    await page.click('[data-action="run"]');
    await page.waitFor(() => /NOPE/.test(document.querySelector('.lkp-other .field-error')?.textContent || ''), { message: 'bad type error' });
    await page.type('[data-role="lookup-other-types"]', '');
    await page.click('[data-action="run"]');
    await page.waitFor(() => !document.querySelector('.lkp-form-error').hidden, { message: 'no types error' });
    await page.click('[data-preset="common"]');
    await page.click('[data-action="run"]');
    await page.waitFor(ALL_DONE, { timeout: 30000 });
    const c = await page.evaluate(cardsInfo);
    const s = await page.evaluate(summaryInfo);
    assertEqual(Object.keys(c).length + s.noRecords.length, 9, 'common preset → 9 types: cards + the "No records" line');
    assert(s.noRecords.every((type) => !c[type]), `a NODATA type has no card: ${s.noRecords}`);
    assert(/Null MX/.test(c.MX.text), 'example.com has a null MX');
  });

  await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
  await step('[dark] DNSSEC lookup of ietf.org renders; no horizontal scroll', async () => {
    await gotoHash(page, '#/lookup?name=ietf.org&type=DS,DNSKEY,SOA&dnssec=1', 'lookup');
    await page.waitFor(ALL_DONE, { timeout: 30000 });
    await assertNoHorizontalScroll(page, 'dark');
    await shot(page, 'lookup-desktop-dark-en-ietf');
  });

  await step('language switch keeps results (snapshot) and translates', async () => {
    const before = await page.evaluate(cardsInfo);
    const shareLabel = () => page.evaluate(() => [...document.querySelectorAll('.page-actions button')].map((b) => b.textContent.trim()));
    assertEqual(await shareLabel(), ['Copy link'], 'header action before the switch');
    await setLangUi(page, 'tr');
    await page.waitFor(() => document.querySelector('[data-action="run"] .btn-label')?.textContent === 'Sorgula', { message: 'TR form' });
    const after = await page.evaluate(cardsInfo);
    assertEqual(Object.keys(after), Object.keys(before), 'cards kept');
    assert(Object.values(after).every((c) => c.state !== 'pending'), 'restored without re-query');
    assert(/Ham yanıt/.test(Object.values(after)[0].text), 'Turkish card text');
    assertEqual(await shareLabel(), ['Bağlantıyı kopyala'], 'header "Copy link" kept (translated) for the restored run');
    await shot(page, 'lookup-desktop-dark-tr-ietf');
    await setLangUi(page, 'en');
  });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });

  await step('i18n: no missing keys; lkp.* TR/EN key sets match', () => checkI18n(page));
  await step('desktop: no console errors, exceptions or CSP violations', () => assertClean(page, 'desktop'));
  await page.close();

  group('Phone 390×844 (Turkish)');
  const phone = await browser.newPage('about:blank', { width: 390, height: 844, mobile: true });
  await phone.goto(`${server.url}#/about`);
  await waitReady(phone);
  await setLangUi(phone, 'tr');
  for (const scheme of ['light', 'dark']) {
    await step(`[${scheme}] lookup fits 390 px`, async () => {
      await phone.emulateMedia({ 'prefers-color-scheme': scheme });
      await gotoHash(phone, '#/about', 'about');
      await gotoHash(phone, `#/lookup?name=${scheme === 'light' ? 'github.com' : 'cloudflare.com'}&type=A,MX,TXT,CAA,HTTPS&dnssec=${scheme === 'dark' ? 1 : 0}`, 'lookup');
      await phone.waitFor(ALL_DONE, { timeout: 30000 });
      await assertNoHorizontalScroll(phone, `phone ${scheme}`);
      await shot(phone, `lookup-mobile-${scheme}-tr`);
    });
  }
  await step('phone: no console errors, exceptions or CSP violations', () => assertClean(phone, 'phone'));
  await step('phone: i18n complete', () => checkI18n(phone));
  await phone.close();
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
