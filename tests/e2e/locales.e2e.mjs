#!/usr/bin/env node
/**
 * locales.e2e.mjs — end-to-end test of the adaptive locale packs (ROADMAP P1.9, SPEC §5.89) in a
 * real headless Chrome/Edge. OFFLINE: every DoH query and the Anubis source are answered in the
 * page by a fake built before the app loads (window.fetch wrapped, as the other offline suites
 * do); every https:// request that would still leave the page is failed through CDP and recorded.
 *
 *   node tests/e2e/locales.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers:
 *   - Subdomains › Advanced, before a scan: a domain whose TLD names no market says its packs come
 *     from the scan's evidence (the languages line), the plan line adds "plus market packs if the
 *     scan finds evidence" with a higher ceiling of queries, a .com.tr keeps its Turkish pack, both
 *     together read "Auto: Turkish (.com.tr), from evidence for .com";
 *   - a Smart scan of example.com whose Anubis names (destek, bayi, kampanya) and mail servers
 *     (.com.tr) point to Turkish: the run's header says the Turkish pack was added and why as soon
 *     as the wordlist stage starts and keeps it, a label only the Turkish pack has
 *     (yonetimpanel.example.com) is found by the wordlist, the Overview's wordlist line marks the
 *     pack "(picked from evidence)", and the JSON export carries `localeSource` / `localeEvidence`;
 *   - an English zone (example.net) keeps the global list: no banner, "no market pack";
 *   - Turkish, dark mode, 375 px: the same scan in Turkish, the banner and the languages line
 *     inside the viewport, no horizontal page scroll; English light at 375 px too;
 *   - zero console errors, exceptions and CSP violations; no missing i18n keys; nothing reached
 *     the network.
 *
 * Data is documentation space only (example.com / .net, example.com.tr, 203.0.113.0/24,
 * 198.51.100.0/24).
 */

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, takeDownloads, waitReady
} from './scan.e2e.mjs';
import { SOURCES } from '../../assets/js/lib/sourceinfo.js';

/** The DNS of the two scanned domains (anything else is NXDOMAIN). */
const ZONE = {
  'example.com': {
    A: ['203.0.113.10'],
    NS: ['ns1.example.net', 'ns2.example.net'],
    MX: [{ preference: 10, exchange: 'mx1.example.com.tr' }, { preference: 20, exchange: 'mx2.example.com.tr' }]
  },
  'www.example.com': { A: ['203.0.113.10'] },
  'destek.example.com': { A: ['203.0.113.11'] },
  'bayi.example.com': { A: ['203.0.113.12'] },
  'kampanya.example.com': { A: ['203.0.113.13'] },
  // Only the Turkish pack has this label: the scan finds it only if the pack was added.
  'yonetimpanel.example.com': { A: ['203.0.113.14'] },
  'mx1.example.com.tr': { A: ['198.51.100.25'] },
  'mx2.example.com.tr': { A: ['198.51.100.26'] },
  'example.net': { A: ['203.0.113.20'], MX: [{ preference: 10, exchange: 'mail.example.net' }] },
  'www.example.net': { A: ['203.0.113.20'] },
  'shop.example.net': { A: ['203.0.113.21'] },
  'support.example.net': { A: ['203.0.113.22'] },
  'mail.example.net': { A: ['203.0.113.23'] }
};
/** What Anubis knows of each domain. */
const ANUBIS = {
  'example.com': ['www.example.com', 'destek.example.com', 'bayi.example.com', 'kampanya.example.com'],
  'example.net': ['www.example.net', 'shop.example.net', 'support.example.net']
};

/** In-page fakes: DoH from ZONE, Anubis; any other cross-origin request is refused and recorded. */
const fakeScript = () => `(() => {
  const ZONE = ${JSON.stringify(ZONE)};
  const ANUBIS = ${JSON.stringify(ANUBIS)};
  const SOA = { mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
  const realFetch = window.fetch.bind(window);
  window.__fake = { dns: 0, anubis: [], blocked: [] };
  let wire = null;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (new URL(url, location.href).origin === location.origin) return realFetch(input, init);
    if (url.startsWith('https://anubisdb.com/')) {
      const domain = decodeURIComponent(url.split('/').pop());
      window.__fake.anubis.push(domain);
      return new Response(JSON.stringify(ANUBIS[domain] || []), { headers: { 'content-type': 'application/json' } });
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
    const node = ZONE[name];
    const answers = node ? (node[q.type] || []).map((data) => ({ name, type: q.type, ttl: 300, data })) : [];
    const exists = !!node || Object.keys(ZONE).some((k) => k.endsWith('.' + name));
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: exists ? 'NOERROR' : 'NXDOMAIN', questions: [{ name: q.name, type: q.type }], answers,
      authorities: answers.length ? [] : [{ name: 'example.com', type: 'SOA', ttl: 300, data: SOA }], edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/** The Subdomains options for these scans: Anubis only, the Smart wordlist, automatic languages, no permutations or hints. */
const OPTIONS_SCRIPT = `(() => {
  try {
    localStorage.setItem('ssds.subdomains.options', JSON.stringify({
      sources: ['anubis'], knownSources: ${JSON.stringify(SOURCES.map((s) => s.id))},
      bruteforce: 'smart', permutations: false, originHints: false, includeExpired: false, learned: false, locales: null
    }));
  } catch (e) { /* storage blocked: the defaults run */ }
})();`;

/** Fail every https request that reaches the network; returns the list of the ones that tried. */
async function networkGate(page) {
  const leaks = [];
  page.conn.on('Fetch.requestPaused', (p) => {
    leaks.push(p.request.url);
    page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://*' }] });
  return leaks;
}

/* ------------------------------------------------------------------------ */
/* Page helpers                                                             */
/* ------------------------------------------------------------------------ */

const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);
/** The id of the run shown (null before the first scan). */
const runId = (page) => page.evaluate(() => document.querySelector('.sub-run-ui')?.dataset.run || null);

/**
 * Type the domain(s) into the search box (no scan) and wait until the languages line reads `want`:
 * the plan line and the languages line follow the box together (debounced), so the plan is then
 * current too.
 */
async function typeDomain(page, value, want) {
  await page.type('[data-role="sub-domain"]', value);
  await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
  await page.waitFor((w) => (document.querySelector('.sub-lang-line')?.textContent.replace(/\s+/g, ' ').trim() || '') === w,
    { args: [want], message: `languages line: ${want}` });
}

/** Scan the domain in the box and wait until that run is done; returns its id. */
async function scan(page, domain) {
  const before = await runId(page);
  await page.type('[data-role="sub-domain"]', domain);
  await page.click('[data-action="sub-run"]');
  await page.waitFor((prev) => {
    const ui = document.querySelector('.sub-run-ui');
    return !!ui && ui.dataset.run !== prev;
  }, { args: [before], message: 'a new run', timeout: 20000 });
  return page.waitFor(() => {
    const ui = document.querySelector('.sub-run-ui');
    const panel = ui && ui.querySelector('.sub-run');
    return panel && panel.dataset.status !== 'running' ? `${ui.dataset.run}:${panel.dataset.status}` : false;
  }, { timeout: 180000, interval: 200, message: `scan of ${domain} done` });
}

/** The locale banner of the run shown: its lines (text, locale, domain), or null when hidden. */
const banner = (page) => page.evaluate(() => {
  const host = document.querySelector('.sub-run-ui .sub-locale-host');
  if (!host || host.hidden) return null;
  return [...host.querySelectorAll('.sub-locale-line')].map((p) => ({ text: p.textContent, locale: p.dataset.locale, domain: p.dataset.domain }));
});

/** A focused screenshot of one element (beyond the viewport if needed); skipped with --no-shots. */
async function shotEl(page, opts, name, selector) {
  if (!opts.shots) return;
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { x: Math.max(0, r.left + window.scrollX), y: Math.max(0, r.top + window.scrollY), width: r.width, height: r.height };
  }, selector);
  if (!box || !box.width || !box.height) return;
  await mkdir(SHOTS, { recursive: true });
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.min(Math.ceil(box.height), 4000), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}

async function openTab(page, id) {
  await page.click(`.sub-tabs [role="tab"][data-tab="${id}"]`);
  await page.waitFor((t) => document.querySelector(`.sub-tabs [role="tab"][data-tab="${t}"]`)?.getAttribute('aria-selected') === 'true', { args: [id], message: `tab ${id}` });
}

/** Every element of the run header and the languages line inside the viewport (a phone). */
const outside = (page) => page.evaluate(() => {
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of document.querySelectorAll('.sub-locale-banner *, .sub-lang-line, .sub-wl-plan, .sub-wl-usage *')) {
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
});

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

const EN_LINE = 'Turkish pack added for example.com. Evidence: words in the names found (bayi, destek, kampanya), the mail servers’ domain ending (.com.tr).';
const TR_LINE = 'example.com için Türkçe paket eklendi. Kanıt: bulunan adlardaki kelimeler (bayi, destek, kampanya), posta sunucularının alan adı uzantısı (.com.tr).';

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}\n`);
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    const leaks = await networkGate(page);
    await installDownloadCapture(page);
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript() });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: OPTIONS_SCRIPT });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Before a scan: the languages and plan lines (desktop, English)');
    await run.step('a .com says its packs come from the scan\'s evidence; the plan line counts them in its ceiling', async () => {
      await page.goto(`${server.url}#/subdomains`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await gotoRoute(page, '#/subdomains');
      await typeDomain(page, 'example.com',
        'Auto: .com names no market, so the scan picks packs from evidence — the words in the names it finds and the countries of the name and mail servers');
      const plan = await page.evaluate(() => {
        const el = document.querySelector('.sub-wl-plan');
        return { text: el.textContent, min: Number(el.dataset.queriesMin), max: Number(el.dataset.queriesMax) };
      });
      assert(/\(7,000 smart, plus market packs if the scan finds evidence\)/.test(plan.text), plan.text);
      assert(plan.max > plan.min, `a range: ${plan.min}–${plan.max}`);
      await shot(page, opts, 'locales-plan-desktop-en');
    });
    await run.step('a .com.tr keeps its Turkish pack; both together say where each comes from', async () => {
      await typeDomain(page, 'example.com.tr', 'Auto: Turkish (.com.tr)');
      const planTr = await text(page, '.sub-wl-plan');
      assert(/\+283 Turkish\)/.test(planTr) && !/evidence/.test(planTr), planTr);
      await typeDomain(page, 'example.com.tr, example.com', 'Auto: Turkish (.com.tr), from evidence for .com');
      assert(/per domain: 7,000 smart, \+283 Turkish, plus market packs if the scan finds evidence/.test(await text(page, '.sub-wl-plan')), 'plan line');
    });

    run.group('A scan of example.com (emulated DNS and Anubis, nothing leaves the page)');
    await run.step('the header says the Turkish pack was added from evidence, with its reasons, and keeps it', async () => {
      const status = await scan(page, 'example.com');
      assert(status.endsWith(':done'), status);
      assertEqual(await banner(page), [{ text: EN_LINE, locale: 'tr', domain: 'example.com' }], 'banner');
      assertEqual(await page.evaluate(() => window.__fake.anubis), ['example.com'], 'Anubis asked once');
    });
    await run.step('a label only the Turkish pack has is found by the wordlist', async () => {
      await openTab(page, 'hosts');
      await page.waitFor(() => [...document.querySelectorAll('.sub-table .sub-host-name')].some((a) => a.textContent === 'yonetimpanel.example.com'),
        { message: 'yonetimpanel.example.com listed' });
      const names = await page.evaluate(() => [...document.querySelectorAll('.sub-table .sub-host-name')].map((a) => a.textContent).sort());
      for (const n of ['bayi.example.com', 'destek.example.com', 'kampanya.example.com', 'yonetimpanel.example.com']) assert(names.includes(n), `${n} in ${names.join(', ')}`);
    });
    await run.step('the Overview\'s wordlist line marks the pack "(picked from evidence)"', async () => {
      await openTab(page, 'overview');
      await page.waitFor(() => !!document.querySelector('.sub-wl-usage [data-role="sub-wl-evidence"]'), { message: 'usage line' });
      const usage = await text(page, '.sub-wl-usage');
      assert(/^Wordlist: smart/.test(usage), usage);
      assertEqual(await text(page, '.sub-wl-usage [data-role="sub-wl-evidence"]'), 'with Turkish (picked from evidence)', 'evidence part');
      await shot(page, opts, 'locales-run-desktop-en');
      await shotEl(page, opts, 'locales-banner-desktop-en', '.sub-run-ui .sub-run');
    });
    await run.step('the JSON export carries how the packs were chosen and the evidence', async () => {
      await openTab(page, 'hosts');
      await page.click('.sub-actions [data-export="json"]');
      const downloads = await takeDownloads(page);
      assertEqual(downloads.length, 1, 'one download');
      const wl = JSON.parse(downloads[0].text).options.wordlist;
      const pd = wl.perDomain[0];
      assertEqual([pd.domain, pd.localeSource, pd.locales, pd.localeEvidence.locales], ['example.com', 'evidence', ['tr'], ['tr']], 'perDomain');
      const tr = pd.localeEvidence.signals.find((s) => s.locale === 'tr');
      assertEqual([tr.words, tr.mx, tr.points.mx], [['bayi', 'destek', 'kampanya'], ['.com.tr'], 2], 'the Turkish signal');
      assertEqual(wl.localePacks, ['tr'], 'packs');
    });

    run.group('An English zone (example.net) keeps the global list');
    await run.step('no banner, and the wordlist line says no market pack', async () => {
      const status = await scan(page, 'example.net');
      assert(status.endsWith(':done'), status);
      assertEqual(await banner(page), null, 'no banner');
      await openTab(page, 'overview');
      await page.waitFor(() => !!document.querySelector('.sub-wl-usage [data-role="sub-wl-evidence"]'), { message: 'usage line' });
      assertEqual(await text(page, '.sub-wl-usage [data-role="sub-wl-evidence"]'), 'no market pack: the evidence points to no market', 'none');
      await assertClean(page, 'desktop', origin);
      await assertNoMissingKeys(page);
    });

    run.group('Turkish, dark mode, phone (375 px)');
    await run.step('the scan in Turkish: the banner and the wordlist line, inside the viewport', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      const status = await scan(page, 'example.com');
      assert(status.endsWith(':done'), status);
      assertEqual(await banner(page), [{ text: TR_LINE, locale: 'tr', domain: 'example.com' }], 'banner');
      await openTab(page, 'overview');
      await page.waitFor(() => !!document.querySelector('.sub-wl-usage [data-role="sub-wl-evidence"]'), { message: 'usage line' });
      assertEqual(await text(page, '.sub-wl-usage [data-role="sub-wl-evidence"]'), 'Türkçe ile (kanıta göre seçildi)', 'evidence part');
      await page.evaluate(() => window.scrollTo(0, 0));
      assertEqual(await outside(page), [], 'inside the viewport');
      await assertNoHorizontalScroll(page, 'tr 375 run');
      await shot(page, opts, 'locales-run-375-tr-dark');
      await shotEl(page, opts, 'locales-banner-375-tr-dark', '.sub-run-ui .sub-run');
      await shotEl(page, opts, 'locales-usage-375-tr-dark', '.sub-run-ui .sub-tech');
    });
    await run.step('the languages and plan lines in Turkish, inside the viewport', async () => {
      await typeDomain(page, 'example.com',
        'Otomatik: .com bir pazara işaret etmiyor; tarama paketleri kanıta göre seçer — bulduğu adlardaki kelimeler ile ad ve posta sunucularının ülkesi');
      assert(/kanıt bulunursa pazar paketleri de/.test(await text(page, '.sub-wl-plan')), 'plan line');
      assertEqual(await outside(page), [], 'inside the viewport');
      await assertNoHorizontalScroll(page, 'tr 375 form');
      await page.evaluate(() => document.querySelector('.sub-langs')?.scrollIntoView({ block: 'start' }));
      await shot(page, opts, 'locales-plan-375-tr-dark');
      await shotEl(page, opts, 'locales-langs-375-tr-dark', '.sub-langs');
      await shotEl(page, opts, 'locales-planline-375-tr-dark', '.sub-wl-plan');
    });
    await run.step('English, light, 375 px: the banner fits', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await page.waitFor(() => !!document.querySelector('.sub-locale-line'), { message: 'banner after the language switch' });
      assertEqual(await banner(page), [{ text: EN_LINE, locale: 'tr', domain: 'example.com' }], 'banner in English');
      await page.evaluate(() => window.scrollTo(0, 0));
      assertEqual(await outside(page), [], 'inside the viewport');
      await assertNoHorizontalScroll(page, 'en 375');
      await shot(page, opts, 'locales-run-375-en-light');
      await shotEl(page, opts, 'locales-banner-375-en-light', '.sub-run-ui .sub-run');
      await assertClean(page, 'phone', origin);
      await assertNoMissingKeys(page);
    });
    await run.step('nothing reached the network', async () => {
      assertEqual(leaks, [], 'requests the CDP guard failed');
      assertEqual(await page.evaluate(() => window.__fake.blocked), [], 'requests the in-page fake refused');
      assert(await page.evaluate(() => window.__fake.dns) > 7000, 'the Smart sweeps went through the fake DoH');
    });
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
