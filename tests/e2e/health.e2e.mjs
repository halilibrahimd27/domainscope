#!/usr/bin/env node
/**
 * health.e2e.mjs — end-to-end test of the "Domain Health" view in a real headless browser,
 * against live DoH resolvers and RDAP registries (network required).
 *
 *   node tests/e2e/health.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: pure helpers (Node); github.com (summary, traffic light, grouped + translated checks,
 * RDAP card with expiry countdown, SPF lookup meter + tree, DMARC tags, DKIM table, CAA "which
 * CAs"), the problems filter, cloudflare.com (DNSSEC validated), a .com.tr domain (no RDAP →
 * explained), validation, the language re-mount keeping the report, phone light/dark, no
 * console errors / exceptions / CSP violations and complete i18n (all health.* keys).
 */

import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { healthScore, trafficLight, groupChecks, parseSelectors, HEALTH_GROUPS } from '../../assets/js/views/health.js';
import { HEALTH_I18N, HEALTH_CHECK_IDS } from '../../assets/js/lib/health.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SHOTS = path.join(HERE, 'screenshots');
const BASE = '/subdomain-scanner/';
const argv = process.argv.slice(2);
const optValue = (name, def) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : def;
};
const BROWSER = optValue('--browser', 'auto');
const HEADED = argv.includes('--headed');
const SHOTS_ON = !argv.includes('--no-shots');
const FLAKY_HOSTS = ['dns.quad9.net', 'dns11.quad9.net'];
const DONE = "!!document.querySelector('.hlt-hero') && !document.querySelector('[data-action=\"run\"]').hidden";

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
    const pick = (lang) => i.listKeys(lang).filter((k) => k.startsWith('hlt.') || k.startsWith('health.'));
    const en = pick('en');
    const tr = pick('tr');
    return { missing: i.getMissingKeys(), onlyEn: en.filter((k) => !tr.includes(k)), onlyTr: tr.filter((k) => !en.includes(k)), count: en.length };
  });
  assertEqual(info.missing, [], 'missing i18n keys');
  assertEqual(info.onlyEn, [], 'keys only in EN');
  assertEqual(info.onlyTr, [], 'keys only in TR');
  assert(info.count > 245, `health.* + hlt.* keys registered (${info.count})`);
}

/** What the page shows. */
function reportInfo() {
  const hero = document.querySelector('.hlt-hero');
  const checks = [...document.querySelectorAll('.hlt-check')];
  return {
    light: hero?.dataset.light,
    score: Number(hero?.dataset.score),
    groups: [...document.querySelectorAll('.hlt-group')].map((g) => g.dataset.group),
    checks: checks.map((c) => ({ id: c.dataset.id, severity: c.dataset.severity })),
    untranslated: checks.map((c) => c.querySelector('.hlt-check-title').textContent).filter((x) => /^health\.|\.title$/.test(x)),
    rdap: document.querySelector('.hlt-rdap')?.textContent.replace(/\s+/g, ' ') || '',
    dnssec: document.querySelector('.hlt-dnssec')?.textContent.replace(/\s+/g, ' ') || '',
    caa: document.querySelector('.hlt-caa')?.textContent.replace(/\s+/g, ' ') || '',
    mail: document.querySelector('.hlt-mail')?.textContent.replace(/\s+/g, ' ') || '',
    meter: document.querySelector('.hlt-meter')?.getAttribute('aria-valuenow') ?? null,
    expiryDays: document.querySelector('.hlt-expiry')?.dataset.days ?? null
  };
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  group('Pure helpers (Node)');
  await step('healthScore / trafficLight', () => {
    assertEqual(healthScore({ ok: 10 }), 100, 'perfect');
    assertEqual(healthScore({ error: 1, warn: 2 }), 68, 'mixed');
    assertEqual(healthScore({ error: 9 }), 0, 'clamped');
    assertEqual(healthScore(null), 100, 'null');
    assertEqual([trafficLight({ error: 1, warn: 3 }), trafficLight({ warn: 1 }), trafficLight({ ok: 4, info: 2 })], ['error', 'warn', 'ok'], 'lights');
  });
  await step('groupChecks (worst first, stable) / parseSelectors', () => {
    const checks = [
      { id: 'a', severity: 'ok', group: 'dns' }, { id: 'b', severity: 'error', group: 'dns' },
      { id: 'c', severity: 'warn', group: 'email' }, { id: 'd', severity: 'info' }, { id: 'e', severity: 'error', group: 'dns' }
    ];
    assertEqual(groupChecks(checks, 'dns').map((c) => c.id), ['b', 'e', 'd', 'a'], 'dns group');
    assertEqual(groupChecks(checks, 'email').map((c) => c.id), ['c'], 'email group');
    assertEqual(HEALTH_GROUPS, ['dns', 'email', 'security', 'registration'], 'group order');
    assertEqual(parseSelectors('Mailgun, s1024._domainkey.example.com google bad!sel mailgun'), ['mailgun', 's1024'], 'selectors');
  });
  await step('every check id has EN + TR title/detail strings', () => {
    const missing = [];
    for (const id of HEALTH_CHECK_IDS) {
      for (const lang of ['en', 'tr']) {
        for (const part of ['title', 'detail']) if (!HEALTH_I18N[lang][`health.${id}.${part}`]) missing.push(`${lang}:${id}.${part}`);
      }
    }
    assertEqual(missing, [], 'missing health strings');
  });

  await mkdir(SHOTS, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: BROWSER, headless: !HEADED });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}\n`);

  try {
    group('Desktop 1440×900 (English, live DNS + RDAP)');
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/about`);
    await waitReady(page);
    await setLangUi(page, 'en');

    await step('github.com via shared link: summary, grouped translated checks and detail panels', async () => {
      await gotoHash(page, '#/health?domain=github.com', 'health');
      await page.waitFor(DONE, { timeout: 60000, message: 'health report' });
      const r = await page.evaluate(reportInfo);
      assert(['ok', 'warn', 'error'].includes(r.light), `light ${r.light}`);
      assert(r.score >= 0 && r.score <= 100, `score ${r.score}`);
      assert(r.groups.includes('dns') && r.groups.includes('email') && r.groups.includes('registration'), `groups ${r.groups}`);
      assert(r.checks.length >= 12, `checks ${r.checks.length}`);
      assertEqual(r.untranslated, [], 'untranslated titles');
      assert(r.checks.some((c) => c.id === 'spf.present') && r.checks.some((c) => c.id.startsWith('dmarc.policy-')), 'SPF + DMARC checks');
      assert(/MarkMonitor/.test(r.rdap) && Number(r.expiryDays) > 0, `RDAP card: ${r.rdap.slice(0, 200)}`);
      assert(Number(r.meter) >= 1, `SPF lookup meter ${r.meter}`);
      assert(/quarantine|reject/.test(r.mail) && /DKIM/.test(r.mail), 'DMARC + DKIM blocks');
      assert(/DigiCert/.test(r.caa), `CAA lists CAs: ${r.caa.slice(0, 200)}`);
      // Worst-first ordering inside each group.
      const orderOk = await page.evaluate(() => [...document.querySelectorAll('.hlt-group')].every((g) => {
        const rank = { error: 0, warn: 1, info: 2, ok: 3 };
        const sev = [...g.querySelectorAll('.hlt-check')].map((c) => rank[c.dataset.severity]);
        return sev.every((v, i) => i === 0 || sev[i - 1] <= v);
      }));
      assert(orderOk, 'checks sorted worst first');
      await assertNoHorizontalScroll(page, 'github');
      await shot(page, 'health-desktop-light-en-github');
    });

    await step('filter "Warnings & errors" hides passed and info checks', async () => {
      await page.click('[data-control="health-filter"] [data-value="problems"]');
      const sev = await page.evaluate(() => [...document.querySelectorAll('.hlt-check')].map((c) => c.dataset.severity));
      assert(sev.every((s) => s === 'warn' || s === 'error'), `only problems: ${sev}`);
      await page.click('[data-control="health-filter"] [data-value="all"]');
    });

    await step('cloudflare.com: DNSSEC signed and validated; CAA and email extras', async () => {
      await page.type('[data-role="health-domain"]', 'cloudflare.com');
      await page.click('[data-action="run"]');
      await page.waitFor(() => window.location.hash.includes('domain=cloudflare.com'), { message: 'URL updated' });
      await page.waitFor(DONE, { timeout: 60000 });
      await page.waitFor(() => document.querySelector('.hlt-hero-domain')?.textContent === 'cloudflare.com');
      const r = await page.evaluate(reportInfo);
      assert(r.checks.some((c) => c.id === 'dnssec.ok'), `dnssec.ok check: ${r.checks.map((c) => c.id).filter((x) => x.startsWith('dnssec'))}`);
      assert(/Signed and validated/.test(r.dnssec) && /KSK/.test(r.dnssec), `DNSSEC card: ${r.dnssec.slice(0, 200)}`);
      assert(/MTA-STS/.test(r.mail), 'email extras');
    });

    await step('.com.tr domain: RDAP unsupported is explained (nic.tr), other checks still run', async () => {
      await gotoHash(page, '#/health?domain=turkcell.com.tr', 'health');
      await page.waitFor(() => document.querySelector('.hlt-hero-domain')?.textContent === 'turkcell.com.tr' && !document.querySelector('[data-action="run"]').hidden, { timeout: 60000 });
      const r = await page.evaluate(reportInfo);
      assert(/nic\.tr/.test(r.rdap), `RDAP explanation: ${r.rdap}`);
      assert(r.checks.some((c) => c.id === 'rdap.unsupported'), 'rdap.unsupported check');
      assert(r.checks.some((c) => c.id.startsWith('ns.')), 'NS checks ran');
      await shot(page, 'health-desktop-light-en-comtr');
    });

    await step('validation: IPs and garbage are rejected', async () => {
      await page.type('[data-role="health-domain"]', '8.8.8.8');
      await page.click('[data-action="run"]');
      await page.waitFor(() => !!document.querySelector('.hlt-form .field.has-error'));
      assert((await page.evaluate(() => window.location.hash)).includes('turkcell.com.tr'), 'URL unchanged');
    });

    await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
    await step('[dark] report renders; language switch keeps the report and translates it', async () => {
      await gotoHash(page, '#/health?domain=github.com', 'health');
      await page.waitFor(() => document.querySelector('.hlt-hero-domain')?.textContent === 'github.com' && !document.querySelector('[data-action="run"]').hidden, { timeout: 60000 });
      await shot(page, 'health-desktop-dark-en-github');
      const before = await page.evaluate(reportInfo);
      await setLangUi(page, 'tr');
      await page.waitFor(() => document.querySelector('[data-action="run"] .btn-label')?.textContent === 'Sağlığı kontrol et', { message: 'TR form' });
      const after = await page.evaluate(reportInfo);
      assertEqual(after.checks, before.checks, 'same checks (restored, not re-run)');
      assertEqual(after.untranslated, [], 'untranslated titles (TR)');
      const title = await page.evaluate(() => document.querySelector('.hlt-group .card-title').textContent);
      assertEqual(title, 'DNS', 'group label');
      assert(await page.evaluate(() => /Kayıt|Sağlıklı|İlgilenilmesi|Sorun/.test(document.querySelector('.hlt-hero').textContent)), 'Turkish hero');
      await assertNoHorizontalScroll(page, 'dark tr');
      await shot(page, 'health-desktop-dark-tr-github');
      await setLangUi(page, 'en');
    });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    await step('i18n: no missing keys; hlt.* + health.* TR/EN key sets match', () => checkI18n(page));
    await step('desktop: no console errors, exceptions or CSP violations', () => assertClean(page, 'desktop'));
    await page.close();

    group('Phone 390×844 (Turkish)');
    const phone = await browser.newPage('about:blank', { width: 390, height: 844, mobile: true });
    await phone.goto(`${server.url}#/about`);
    await waitReady(phone);
    await setLangUi(phone, 'tr');
    for (const scheme of ['light', 'dark']) {
      await step(`[${scheme}] report fits 390 px`, async () => {
        await phone.emulateMedia({ 'prefers-color-scheme': scheme });
        await gotoHash(phone, '#/about', 'about');
        const domain = scheme === 'light' ? 'github.com' : 'example.com';
        await gotoHash(phone, `#/health?domain=${domain}`, 'health');
        await phone.waitFor((d) => document.querySelector('.hlt-hero-domain')?.textContent === d && !document.querySelector('[data-action="run"]').hidden, { timeout: 60000, args: [domain] });
        await assertNoHorizontalScroll(phone, `phone ${scheme}`);
        await shot(phone, `health-mobile-${scheme}-tr`);
      });
    }
    await step('phone: no console errors, exceptions or CSP violations', () => assertClean(phone, 'phone'));
    await step('phone: i18n complete', () => checkI18n(phone));
    await phone.close();
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

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
