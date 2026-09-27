#!/usr/bin/env node
/**
 * shell.e2e.mjs — end-to-end check of the UI shell in a real headless browser.
 *
 *   node tests/e2e/shell.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Serves the repo under /domainscope/ (like the GitHub Pages project site), then on a
 * desktop (1440×900) and a phone (390×844) viewport:
 *   - opens every route in light and dark, in English and Turkish, checks the title, that the
 *     page never scrolls horizontally, and saves full-page screenshots to tests/e2e/screenshots/
 *   - exercises the router (default/unknown/anchor hashes), skip link, language + theme toggles,
 *     the settings dialog, the Servers view (typing, file import, warnings, save → reload, clear)
 *   - builds a component gallery (badges, kinds, stats, alerts, progress, tabs, fields, DataTable)
 *     and tests DataTable paging/sorting/search/streaming and Tabs keyboard navigation, CopyButton's
 *     own toast text and its onFail hand-over (Copy summary's dialog), and the table's print styles
 *   - prints from dark mode (print media): the light palette, no shell or controls, Disclosures
 *     opened and the print header (title, UTC time, permalink) on beforeprint, undone afterwards
 *   - fails on any console error, uncaught exception, failed request or CSP violation, and on
 *     i18n keys that are missing in either language.
 * Then it serves the GitHub Pages bundle (tools/assemble-site.mjs, assets under v/<version>/):
 * the app boots from it, About's links resolve, a view that fails to load offline (or blocked)
 * keeps the plain network error with Retry, and after a second "deploy" a view opened in the
 * old tab offers a page reload that brings the new version (that tab has no service worker).
 * Finally the installable app, on a bundle and origin of its own: the service worker installs and
 * precaches the version; with the server dropping every request the app reloads from the cache,
 * Certificate, Zone File and Servers work and DNS Lookup says it needs the network and sends
 * nothing; a second deploy brings "Update ready — Reload", which loads it — and a second tab of
 * the old version, taken over by that click, offers the reload again; a bundle assembled again
 * under the same version with one file changed is an update too (sw.js carries its digest).
 * No network access is needed: the shell views never call external APIs.
 */

import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { parseInventory } from '../../assets/js/lib/inventory.js';
import { t as translate, setLang as setNodeLang } from '../../assets/js/i18n.js';
import { DEFAULT_CHAIN, getResolver } from '../../assets/js/lib/resolvers.js';
import { REPO_URL, VIEW_CSS_ORDER } from '../../assets/js/app.js';
import { REPO_ROOT, ROOT_DIRS, ROOT_FILES, VERSIONED_DIR, assembleSite } from '../../tools/assemble-site.mjs';
import { cacheNames } from '../../assets/js/lib/pwa.js';
import { zoneHandoffScript } from './scan.e2e.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SHOTS = path.join(HERE, 'screenshots');
const BASE = '/domainscope/';
const ROUTES = ['subdomains', 'zone', 'scan', 'cert', 'global', 'lookup', 'bulk', 'ip', 'ptr', 'health', 'inventory', 'about'];

const argv = process.argv.slice(2);
const opt = (name) => argv.includes(name);
const optValue = (name, def) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : def;
};
const BROWSER = optValue('--browser', 'auto');
const HEADED = opt('--headed');
const SHOTS_ON = !opt('--no-shots');

const SAMPLE_INVENTORY = [
  '# e2e inventory',
  'web01 10.0.1.11',
  'web02 10.0.1.12 2001:db8::12',
  'lb-edge 198.51.100.5',
  'db01 10.0.2.20',
  'web03 10.0.1.300',
  'cache01'
].join('\n');

// Addresses with their own port (the CLI scans them there), a bad port and a host name with a port.
const PORT_INVENTORY = [
  '# e2e inventory with ports',
  'web01 203.0.113.10:8443',
  'web02 [2001:db8::2]:8443 203.0.113.12',
  'web04 203.0.113.14:99999',
  'web05 web05.example.net:8443',
  'web03 10.0.0.13 10.0.0.13:8443',
  '203.0.113.17:2222 ansible_user=deploy'
].join('\n');
const FILE_INVENTORY = 'hostname,ip_address,role\napi01,10.0.3.21,api\napi02,10.0.3.22,api\nmail01,192.168.10.5,mail\n';

/* ------------------------------------------------------------------------ */
/* Tiny test runner                                                         */
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
    process.stdout.write(`  FAIL  ${name}\n        ${String(err && err.stack || err).split('\n').slice(0, 4).join('\n        ')}\n`);
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

function title(id, lang) {
  setNodeLang(lang);
  return translate(`nav.${id}`);
}

/* ------------------------------------------------------------------------ */
/* Page helpers                                                             */
/* ------------------------------------------------------------------------ */

async function waitReady(page) {
  await page.waitFor(() => document.documentElement.dataset.appReady === 'true', { timeout: 15000, message: 'app ready' });
}

async function gotoRoute(page, id) {
  await page.evaluate((view) => {
    window.__routeT0 = performance.now();
    window.location.hash = `#/${view}`;
  }, id);
  await page.waitFor((view) => document.documentElement.dataset.view === view
    && document.querySelector('#page-body')?.dataset.view === view
    && document.querySelector('#page-body').childElementCount > 0
    && !document.querySelector('#page-body .page-loading'), { args: [id], message: `route ${id}` });
  // Let fonts/layout settle and toasts finish animating in.
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

/** Elements that stick out of the viewport horizontally (outside any scrolling container). */
function overflowReport() {
  const vw = document.documentElement.clientWidth;
  const offenders = [];
  if (document.documentElement.scrollWidth > vw + 1) {
    const clipped = (el) => {
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        const s = getComputedStyle(p);
        if (/(auto|scroll|hidden|clip)/.test(s.overflowX)) return true;
      }
      return false;
    };
    for (const el of document.body.querySelectorAll('*')) {
      const r = el.getBoundingClientRect();
      if (r.width && r.right > vw + 1 && !clipped(el)) {
        offenders.push(`${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}.${[...el.classList].join('.')} right=${Math.round(r.right)}`);
        if (offenders.length > 8) break;
      }
    }
  }
  return { scrollWidth: document.documentElement.scrollWidth, clientWidth: vw, offenders };
}

async function assertNoHorizontalScroll(page, where) {
  const rep = await page.evaluate(overflowReport);
  assert(rep.scrollWidth <= rep.clientWidth + 1,
    `${where}: page scrolls horizontally (scrollWidth ${rep.scrollWidth} > ${rep.clientWidth}); offenders: ${rep.offenders.join(', ')}`);
}

async function shot(page, name) {
  if (!SHOTS_ON) return;
  await page.screenshot(path.join(SHOTS, `${name}.png`), { fullPage: true });
}

async function assertClean(page, where, { offline = false } = {}) {
  const p = await page.problems();
  // Offline, the browser's own requests (the favicon on Linux Chrome) fail on purpose; so do those that
  // reach a test server told to drop every request (setOffline) — what must work offline is checked by the steps.
  const logErrors = offline ? p.logErrors.filter((e) => !/ERR_(?:INTERNET_DISCONNECTED|EMPTY_RESPONSE|CONNECTION_(?:RESET|CLOSED))/.test(e.text)) : p.logErrors;
  const issues = [
    ...p.consoleErrors.map((m) => `console.${m.type}: ${m.text}`),
    ...p.exceptions.map((e) => `exception: ${e.text}`),
    ...logErrors.map((e) => `log(${e.source}): ${e.text} ${e.url || ''}`),
    ...p.csp.map((c) => `CSP: ${JSON.stringify(c).slice(0, 300)}`)
  ];
  assert(issues.length === 0, `${where}: ${issues.length} problem(s):\n          ${issues.join('\n          ')}`);
}

async function setLangUi(page, lang) {
  const now = await page.evaluate(() => document.documentElement.lang);
  if (now === lang) return;
  await page.click(`[data-control="lang"] [data-value="${lang}"]`);
  await page.waitFor((l) => document.documentElement.lang === l, { args: [lang], message: `lang ${lang}` });
  await page.waitFor(() => document.querySelector('#page-body')?.childElementCount > 0);
}

async function dismissToasts(page) {
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((t) => t.remove()));
}

/* ------------------------------------------------------------------------ */
/* A long job outside its view (ui/jobs.js)                                 */
/* ------------------------------------------------------------------------ */

/** 60 names under example.com per run (runs a–d: the DoH client caches answers), answered in the page. */
const jobNames = (run) => Array.from({ length: 60 }, (_, i) => `${run}-host${i + 1}.example.com`);
const JOB_ZONE = Object.fromEntries([['example.com', { A: ['203.0.113.10'] }],
  ...['a', 'b', 'c', 'd'].flatMap((run) => jobNames(run).map((n, i) => [n, { A: [`203.0.113.${100 + i}`] }]))]);

/**
 * Before the app loads: every DoH answer waits `window.__dnsDelay` ms (so a Bulk Resolve of 60
 * names takes seconds), `Date.now()` can be moved forward by `window.__clockSkew` ms (the 30 s
 * mark of "Notify me when done" without waiting for it), and a fake Notification API records
 * what would be shown (window.__notes) and how often permission was asked (__permAsked); the
 * prompt's answer is window.__permAnswer ('default' = closed without an answer).
 */
const JOB_PAGE_SCRIPT = `(() => {
  const inner = window.fetch;
  window.__dnsDelay = 0;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (window.__dnsDelay && /[?&]dns=/.test(url)) await new Promise((r) => setTimeout(r, window.__dnsDelay));
    return inner(input, init);
  };
  const realNow = Date.now.bind(Date);
  window.__clockSkew = 0;
  Date.now = () => realNow() + window.__clockSkew;
  window.__notes = [];
  window.__permAsked = 0;
  window.__permAnswer = 'granted';
  window.Notification = class {
    constructor(title, opts) { window.__notes.push({ title, body: (opts && opts.body) || '' }); }
    close() {}
    static async requestPermission() {
      window.__permAsked += 1;
      // A real prompt answers later, not in the same tick.
      await new Promise((resolve) => setTimeout(resolve, 300));
      window.Notification.permission = window.__permAnswer;
      return window.__permAnswer;
    }
  };
  window.Notification.permission = 'default';
  try { localStorage.setItem('ssds.bulk.options', JSON.stringify({ ptr: false, asn: false })); } catch { /* private mode */ }
})();`;

/** What the signals outside the view show: tab title, the nav ring of a view, the favicon. */
function jobSignals(view) {
  const link = document.querySelector(`#app-nav .nav-link[data-view="${view}"]`);
  const ring = link && link.querySelector('.nav-job');
  const icon = document.querySelector('link[rel~="icon"]');
  const href = icon ? icon.getAttribute('href') : '';
  const arc = /stroke-dasharray%3D%22(\d+)%20100%22/.exec(href);
  return {
    title: document.title,
    ring: ring ? { percent: ring.dataset.percent, sr: ring.querySelector('.sr-only').textContent, dash: ring.querySelector('.nav-job-bar').getAttribute('stroke-dasharray') } : null,
    linkClass: link ? link.className : '',
    icon: href.startsWith('data:image/svg+xml,') ? 'badge' : href,
    iconArc: arc ? Number(arc[1]) : null
  };
}

async function jobsGroup(browser, server) {
  group('A long job while another view is open (Bulk Resolve, DoH answered in the page)');
  const jobs = await browser.newPage('about:blank', { width: 1440, height: 900 });
  await jobs.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript('example.com', JOB_ZONE) });
  await jobs.send('Page.addScriptToEvaluateOnNewDocument', { source: JOB_PAGE_SCRIPT });
  await jobs.emulateMedia({ 'prefers-color-scheme': 'light' });
  const signals = (view = 'bulk') => jobs.evaluate(jobSignals, view);
  const startBulk = async (run) => {
    await gotoRoute(jobs, 'bulk');
    await jobs.type('[data-role="bulk-input"]', jobNames(run).join('\n'));
    await dismissToasts(jobs); // the last job's "finished" toast may cover the button
    await jobs.click('[data-action="bulk-run"]');
    await jobs.waitFor(() => !!document.querySelector('.bulk-progress[data-status="running"]'), { message: 'bulk job running' });
  };
  try {
    await step('while it runs elsewhere: "(n%)" in the tab title, a ring on its nav entry, a badge on the favicon', async () => {
      await jobs.goto(`${server.url}#/about`);
      await waitReady(jobs);
      await setLangUi(jobs, 'en');
      await jobs.evaluate(async () => {
        (await import('./assets/js/state.js')).state.updateSettings({ concurrency: 2 });
        window.__dnsDelay = 200; // about 12 s for 60 names at 2 queries in flight
      });
      const idle = await signals();
      assertEqual([idle.title, idle.ring, idle.icon], ['About · DomainScope', null, 'favicon.svg'], 'no job: nothing extra');
      await startBulk('a');
      await gotoRoute(jobs, 'about');
      await jobs.waitFor(() => /^\(\d{1,2}%\) About · DomainScope$/.test(document.title), { timeout: 5000, message: 'title prefix' });
      const a = await signals();
      assert(a.ring && /^\d+$/.test(a.ring.percent), `ring on Bulk Resolve: ${JSON.stringify(a.ring)}`);
      assert(/^, running, \d+% done$/.test(a.ring.sr), `screen-reader text: ${a.ring.sr}`);
      assert(/\bhas-job\b/.test(a.linkClass), 'the nav entry is marked');
      assertEqual(a.icon, 'badge', 'favicon badge');
      assert(a.iconArc === null || a.iconArc % 5 === 0, `favicon steps of 5 %: ${a.iconArc}`);
      await jobs.waitFor((p) => {
        const m = /^\((\d+)%\)/.exec(document.title);
        return m && Number(m[1]) > Number(p);
      }, { args: [a.ring.percent], timeout: 10000, message: 'progress moves on' });
      const other = await signals('about');
      assertEqual(other.ring, null, 'no ring on the open view');
      await shot(jobs, 'desktop-light-en-job-elsewhere');
    });

    await step('"Notify me when done" appears at the 30 s mark; permission is asked only on the click', async () => {
      await gotoRoute(jobs, 'bulk');
      const hidden = () => jobs.evaluate(() => document.querySelector('.bulk-progress .job-notify')?.hidden);
      assertEqual(await hidden(), true, 'not offered before 30 s');
      assertEqual(await jobs.evaluate(() => window.__permAsked), 0, 'nothing asked yet');
      await jobs.evaluate(() => { window.__clockSkew = 31000; });
      await jobs.waitFor(() => document.querySelector('.bulk-progress .job-notify')?.hidden === false, { timeout: 3000, message: 'offered at 30 s' });
      const live = "[...document.querySelectorAll('[aria-live=\"polite\"]')].map((el) => el.textContent).join('|')";
      // The prompt closed without an answer: nothing was blocked, the button stays offered.
      await jobs.evaluate(() => { window.__permAnswer = 'default'; });
      await jobs.evaluate(() => document.querySelector('[data-action="job-notify"]').focus());
      await jobs.press('Enter');
      // While the prompt is open the button is busy but keeps the focus (a disabled one would drop it).
      await jobs.waitFor(() => document.querySelector('[data-action="job-notify"]').getAttribute('aria-busy') === 'true', { message: 'busy while asking' });
      assertEqual(await jobs.evaluate(() => document.activeElement?.dataset.action), 'job-notify', 'focus kept while the prompt is open');
      await jobs.waitFor(`${live}.includes('No desktop notification.')`, { timeout: 3000, message: 'dismissed prompt announced' });
      const dismissed = await jobs.evaluate(`({ text: ${live}, pressed: document.querySelector('[data-action="job-notify"]').getAttribute('aria-pressed'),
        blocked: !document.querySelector('.job-notify-blocked')?.hidden, focus: document.activeElement?.dataset.action })`);
      assertEqual([dismissed.text.includes('blocked'), dismissed.pressed, dismissed.blocked, dismissed.focus], [false, 'false', false, 'job-notify'],
        'a dismissed prompt is not "blocked"; the focus stays on the button');
      // A refusal: the button goes, and the keyboard lands on the sentence that replaced it.
      await jobs.evaluate(() => { window.__permAnswer = 'denied'; });
      await jobs.evaluate(() => document.querySelector('[data-action="job-notify"]').focus());
      await jobs.press('Enter');
      await jobs.waitFor(`${live}.includes('blocked for this site')`, { timeout: 3000, message: 'refusal announced' });
      const denied = await jobs.evaluate(() => ({ btn: document.querySelector('[data-action="job-notify"]').hidden,
        blocked: document.querySelector('.job-notify-blocked').hidden, focus: document.activeElement.textContent }));
      assertEqual(denied, { btn: true, blocked: false, focus: 'Desktop notifications are blocked for this site in your browser.' }, 'refused: said, focus kept');
      // Unblocked in the browser's site settings: offered again at the next tick.
      await jobs.evaluate(() => { window.Notification.permission = 'default'; });
      await jobs.waitFor(() => document.querySelector('[data-action="job-notify"]')?.hidden === false, { timeout: 3000, message: 'offered again once unblocked' });
      await jobs.evaluate(() => { window.__permAnswer = 'granted'; window.Notification.permission = 'default'; });
      await jobs.evaluate(() => document.querySelector('[data-action="job-notify"]').focus());
      await jobs.press('Enter');
      await jobs.waitFor(() => document.querySelector('[data-action="job-notify"]')?.getAttribute('aria-pressed') === 'true', { message: 'opted in' });
      const state = await jobs.evaluate(() => {
        const btn = document.querySelector('[data-action="job-notify"]');
        return { asked: window.__permAsked, label: btn.textContent.trim(), on: btn.classList.contains('is-on'), focus: document.activeElement === btn };
      });
      // A toggle: the label stays (a screen reader hears "pressed" once, not a new label as well).
      assertEqual(state, { asked: 3, label: 'Notify me when done', on: true, focus: true }, 'opted in for this page session, the focus on the button');
      await shot(jobs, 'desktop-light-en-job-notify');
    });

    await step('done while the user is elsewhere: one desktop notification, and every signal goes back', async () => {
      await gotoRoute(jobs, 'about');
      await jobs.evaluate(() => { window.__dnsDelay = 0; });
      await jobs.waitFor(() => !document.querySelector('#app-nav .nav-job'), { timeout: 30000, message: 'job finished' });
      await jobs.waitFor(() => document.title === 'About · DomainScope', { timeout: 3000, message: 'title restored' });
      const s = await signals();
      assertEqual([s.ring, s.icon], [null, 'favicon.svg'], 'ring gone, favicon restored');
      const notes = await jobs.evaluate(() => window.__notes.slice());
      assertEqual(notes, [{ title: 'Bulk Resolve finished', body: 'Bulk resolve finished: 60 hostnames' }], 'the notification');
    });

    await step('reduced motion: the favicon moves in 10 % steps, the ring does not animate; a Turkish title reads "(%n)"', async () => {
      await jobs.emulateMedia({ 'prefers-color-scheme': 'dark', 'prefers-reduced-motion': 'reduce' });
      await setLangUi(jobs, 'tr');
      await jobs.evaluate(() => { window.__dnsDelay = 200; window.__notes = []; });
      await startBulk('b');
      await gotoRoute(jobs, 'about');
      await jobs.waitFor(() => /^\(%\d{1,2}\) /.test(document.title), { timeout: 5000, message: 'TR title prefix' });
      const arcs = new Set();
      for (let i = 0; i < 8; i += 1) {
        const s = await signals();
        if (s.iconArc !== null) arcs.add(s.iconArc);
        await jobs.evaluate(() => new Promise((r) => { setTimeout(r, 150); }));
      }
      assert([...arcs].every((x) => x % 10 === 0), `favicon steps of 10 %: ${[...arcs]}`);
      const motion = await jobs.evaluate(() => {
        const bar = document.querySelector('#app-nav .nav-job-bar');
        return bar ? parseFloat(getComputedStyle(bar).transitionDuration) : null;
      });
      assert(motion !== null && motion < 0.01, `ring transition off: ${motion}`);
      const sr = (await signals()).ring.sr;
      assert(/^, çalışıyor, %\d+ tamamlandı$/.test(sr), `TR screen-reader text: ${sr}`);
      await shot(jobs, 'desktop-dark-tr-job-elsewhere');
      await jobs.evaluate(() => { window.__dnsDelay = 0; });
      await jobs.waitFor(() => !document.querySelector('#app-nav .nav-job'), { timeout: 30000, message: 'job finished' });
      assertEqual((await jobs.evaluate(() => window.__notes.slice())).length, 1, 'opt-in kept for the page session');
    });

    await step('on a phone the ring sits in the horizontal nav and the page does not scroll sideways', async () => {
      await jobs.setViewport({ width: 375, height: 812, mobile: true });
      await jobs.emulateMedia({ 'prefers-color-scheme': 'light' });
      await jobs.evaluate(() => { window.__dnsDelay = 150; });
      await startBulk('c');
      await gotoRoute(jobs, 'ip');
      await jobs.waitFor(() => !!document.querySelector('#app-nav .nav-link[data-view="bulk"] .nav-job'), { message: 'ring' });
      await assertNoHorizontalScroll(jobs, 'phone with a job');
      await jobs.evaluate(() => { document.querySelector('#app-nav .nav-link[data-view="bulk"]').scrollIntoView({ inline: 'center' }); });
      await shot(jobs, 'mobile-light-tr-job-elsewhere');
      await jobs.evaluate(() => { window.__dnsDelay = 0; });
      await jobs.waitFor(() => !document.querySelector('#app-nav .nav-job'), { timeout: 30000, message: 'job finished' });
      await jobs.setViewport({ width: 1440, height: 900 });
      await setLangUi(jobs, 'en');
    });

    await step('a browser that refuses to show the notification: the opt-in goes off and a toast says so', async () => {
      // Granted and opted in (above), but the constructor throws, as where only a service worker may notify.
      await jobs.evaluate(() => {
        const Prev = window.Notification;
        window.Notification = class {
          constructor() { throw new TypeError('Illegal constructor.'); }
          static requestPermission() { return Prev.requestPermission(); }
        };
        window.Notification.permission = 'granted';
        window.__notes = [];
        window.__dnsDelay = 60;
      });
      await startBulk('d');
      await gotoRoute(jobs, 'about');
      await jobs.evaluate(() => { window.__dnsDelay = 0; });
      await jobs.waitFor(() => !document.querySelector('#app-nav .nav-job'), { timeout: 30000, message: 'job finished' });
      await jobs.waitFor(() => [...document.querySelectorAll('.toast')].some((el) => el.textContent.includes('did not show the desktop notification')),
        { timeout: 3000, message: 'refusal said' });
      const after = await jobs.evaluate(async () => {
        const { NotifyButton } = await import('./assets/js/ui/jobs.js');
        const el = NotifyButton({ startedAt: new Date(0), running: () => true });
        return { notes: window.__notes.length, hidden: el.hidden, button: !!el.querySelector('button') };
      });
      assertEqual(after, { notes: 0, hidden: true, button: false }, 'not offered again this page session');
      await dismissToasts(jobs);
    });

    await step('jobs page: nothing blocked, no console errors, exceptions or CSP violations (the data: favicon included)', async () => {
      assertEqual(await jobs.evaluate(() => window.__zoneBlocked.slice()), [], 'requests outside the page');
      await assertClean(jobs, 'jobs');
    });
  } finally {
    await jobs.close();
  }

  // Chromium on Android has the API and its prompt but no `new Notification()` (service worker
  // only), on a tablet too: `mobile` is false there, the platform is what counts.
  const phone = await browser.newPage('about:blank', { width: 375, height: 812, mobile: true });
  await phone.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript('example.com', JOB_ZONE) });
  await phone.send('Page.addScriptToEvaluateOnNewDocument', { source: JOB_PAGE_SCRIPT });
  await phone.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `Object.defineProperty(Navigator.prototype, 'userAgentData', { configurable: true,
      get: () => ({ mobile: false, platform: 'Android', brands: [] }) });`
  });
  try {
    await step('Chromium on Android: "Notify me when done" is never offered and no permission is asked', async () => {
      await phone.goto(`${server.url}#/bulk`);
      await waitReady(phone);
      await setLangUi(phone, 'en');
      await phone.evaluate(async () => {
        (await import('./assets/js/state.js')).state.updateSettings({ concurrency: 2 });
        window.__dnsDelay = 100;
      });
      await phone.type('[data-role="bulk-input"]', jobNames('a').join('\n'));
      await phone.click('[data-action="bulk-run"]');
      await phone.waitFor(() => !!document.querySelector('.bulk-progress[data-status="running"]'), { message: 'bulk job running' });
      await phone.evaluate(() => { window.__clockSkew = 31000; });
      await phone.evaluate(() => new Promise((r) => { setTimeout(r, 1500); })); // past the 1 s re-check
      const offered = await phone.evaluate(() => {
        const el = document.querySelector('.bulk-progress .job-notify');
        return { panel: !!el, hidden: el ? el.hidden : null, button: !!document.querySelector('[data-action="job-notify"]'), asked: window.__permAsked };
      });
      assertEqual(offered, { panel: true, hidden: true, button: false, asked: 0 }, 'nothing offered, nothing asked');
      await phone.evaluate(() => { window.__dnsDelay = 0; });
      await phone.waitFor(() => !document.querySelector('.bulk-progress[data-status="running"]'), { timeout: 30000, message: 'job finished' });
      assertEqual(await phone.evaluate(() => [window.__permAsked, window.__notes.length]), [0, 0], 'nothing asked or sent at the end');
      await assertClean(phone, 'android notify');
    });
  } finally {
    await phone.close();
  }
}

/* ------------------------------------------------------------------------ */
/* Component gallery (runs inside the page)                                 */
/* ------------------------------------------------------------------------ */

async function buildGallery() {
  const C = await import('./assets/js/ui/components.js');
  const { h } = await import('./assets/js/ui/dom.js');
  const body = document.getElementById('page-body');
  body.replaceChildren();
  document.getElementById('page-title').textContent = 'Component gallery';
  const kinds = [
    { kind: 'cloudflare', reasonKey: 'class.cloudflare.ip', provider: { name: 'Cloudflare' } },
    { kind: 'cdn', reasonKey: 'class.cdn.cname', provider: { name: 'Fastly' } },
    { kind: 'platform', reasonKey: 'class.platform.cname', provider: { name: 'Vercel' } },
    { kind: 'direct', reasonKey: 'class.direct' },
    { kind: 'private', reasonKey: 'class.private' },
    { kind: 'unresolved', reasonKey: 'class.nodata' },
    { kind: 'nxdomain', reasonKey: 'class.nxdomain' },
    { kind: 'unresolved', dangling: true, reasonKey: 'class.dangling.nxdomain', provider: { name: 'Heroku' } }
  ];
  const rows = [];
  const kindNames = ['cloudflare', 'cdn', 'platform', 'direct', 'private', 'nxdomain'];
  for (let i = 1; i <= 450; i += 1) {
    rows.push({
      name: `web-${i}.example.com`,
      ip: `10.${Math.floor(i / 250)}.${i % 250}.${(i * 7) % 250}`,
      kind: kindNames[i % kindNames.length],
      ttl: (i * 37) % 3600,
      covered: i % 3 !== 0
    });
  }
  window.__table = C.DataTable({
    caption: 'Hosts',
    search: true,
    rows,
    export: { filename: 'hosts' },
    toolbar: C.checkbox({ label: 'Covered only', onChange: (on) => window.__table.setFilter(on ? (r) => r.covered : null) }),
    details: (r) => C.KeyValueList([['Name', r.name], { key: 'IP', value: r.ip, mono: true, copy: true }]),
    columns: [
      { key: 'name', label: 'Name', sortable: true, mono: true },
      { key: 'ip', label: 'IP', sortable: true, mono: true, sortValue: (r) => C.ipSortValue(r.ip) },
      { key: 'kind', label: 'Status', render: (r) => C.KindBadge(r.kind), sortable: true },
      { key: 'ttl', label: 'TTL', sortable: true, align: 'end', className: 'num' },
      { key: 'covered', label: 'Cert', render: (r) => (r.covered ? C.Badge('✓ covered', { variant: 'ok' }) : C.Badge('✗ not covered', { variant: 'error' })), sortable: true }
    ]
  });
  const progress = C.ProgressBar({ label: 'Resolving names' });
  progress.set(45, 120);
  const indet = C.ProgressBar({ label: 'Querying crt.sh', indeterminate: true });
  const busyBtn = C.Button({ label: 'Busy', icon: 'play' });
  C.setButtonBusy(busyBtn, true);
  const stat = (label, value, variant, hint, icon) => C.StatCard({ label, value, variant, hint, icon });
  window.__tabs = C.Tabs([
    { id: 'hosts', label: 'Hosts', badge: 450, icon: 'list', content: () => window.__table.el },
    { id: 'servers', label: 'Servers', badge: 12, icon: 'server', content: () => C.EmptyState({ icon: 'server', title: 'No servers matched', message: 'Add your inventory to match IPs to servers.', action: C.Button({ label: 'Open inventory', icon: 'arrow-right' }) }) },
    { id: 'cdn', label: 'Behind CDN', badge: 7, icon: 'cloud', content: () => C.CodeBlock('python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem', { label: 'Command' }) },
    { id: 'off', label: 'Disabled', disabled: true }
  ]);
  window.__tabs.setBadge('cdn', 7, 'warn');
  body.append(h('div', { class: 'stack-lg', id: 'gallery' },
    C.Section({
      title: 'Badges & status',
      children: h('div', { class: 'stack-sm' },
        h('div', { class: 'cluster' }, ['neutral', 'accent', 'ok', 'info', 'warn', 'error'].map((v) => C.Badge(v, { variant: v }))),
        h('div', { class: 'cluster' }, kinds.map((k) => C.KindBadge(k))),
        h('div', { class: 'cluster' }, ['ok', 'info', 'warn', 'error'].map((s) => C.SeverityIcon(s, { label: true })), ['ok', 'warn', 'error'].map((s) => C.SeverityBadge(s))))
    }),
    C.Section({
      title: 'Buttons',
      children: h('div', { class: 'cluster' },
        C.Button({ label: 'Run scan', icon: 'play', variant: 'primary' }),
        C.Button({ label: 'Secondary', icon: 'download' }),
        C.Button({ label: 'Ghost', variant: 'ghost', icon: 'refresh' }),
        C.Button({ label: 'Delete', variant: 'danger', icon: 'trash' }),
        C.Button({ label: 'Small', size: 'sm' }),
        C.IconButton({ icon: 'sliders', label: 'Settings' }),
        C.CopyButton('copied text', { className: 'gallery-copy' }),
        // Copy summary's options: its own toast text, and the text handed over when copying fails.
        C.CopyButton('summary text', { label: 'Copy summary', toastOnCopy: 'Summary copied', className: 'gallery-copy-summary', onFail: (text) => { window.__copyFailed = text; } }),
        busyBtn,
        C.ExternalLink('https://crt.sh/?q=example.com', 'crt.sh'))
    }),
    h('div', { class: 'stat-grid' },
      stat('Hosts', 1284, 'accent', '312 resolving', 'globe'),
      stat('Cloudflare', 212, 'cloudflare', 'origin hidden', 'cloud'),
      stat('CDN', 18, 'cdn', 'Fastly, CloudFront', 'zap'),
      stat('Direct', 64, 'direct', '41 servers matched', 'server'),
      stat('Dangling', 3, 'dangling', 'takeover risk', 'unlink'),
      stat('Errors', 0, 'default', null, 'alert')),
    h('div', { class: 'grid-2' },
      h('div', { class: 'stack-sm' },
        C.Alert({ variant: 'info', title: 'Heads up', message: 'crt.sh can take a minute to answer.' }),
        C.Alert({ variant: 'ok', title: 'Done', message: '42 hosts resolved in 3.2 s.' }),
        C.Alert({ variant: 'warn', title: 'Quota', message: 'HackerTarget daily quota exceeded.', dismissible: true }),
        C.ErrorBanner(Object.assign(new TypeError('Failed to fetch'), { url: 'https://api.certspotter.com/v1/issuances' }), { onRetry: () => {} })),
      h('div', { class: 'stack' },
        C.Card({ title: 'Progress', icon: 'activity', children: h('div', { class: 'stack' }, progress, indet, C.Spinner({ showLabel: true })) }),
        C.Card({
          title: 'Certificate', subtitle: '*.example.com', icon: 'shield',
          children: C.KeyValueList([
            ['Subject', 'CN=*.example.com, O=Exämple Ltd., C=US'],
            { key: 'SHA-256', value: 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89', mono: true, copy: true },
            ['Valid until', '2027-01-15 (478 days left)'],
            ['Empty', null]
          ])
        }))),
    C.Section({ title: 'Tabs + DataTable', children: window.__tabs }),
    h('div', { class: 'grid-2' },
      C.Card({
        title: 'Fields', icon: 'sliders',
        children: h('div', { class: 'stack' },
          C.textInput({ label: 'Domain', placeholder: 'example.com', hint: 'Apex or subdomain', value: 'bücher.example' }),
          C.select({ label: 'Record type', options: ['A', 'AAAA', 'CNAME', { label: 'Mail', options: ['MX', 'TXT'] }], value: 'MX' }),
          C.checkbox({ label: 'Include expired certificates', hint: 'crt.sh returns more names but slower', checked: true }),
          C.checkbox({ label: 'DNSSEC (DO bit)', switch: true, checked: true }),
          C.radioGroup({ legend: 'Brute force', name: 'bf', inline: true, value: 'small', options: [{ value: 'off', label: 'Off' }, { value: 'small', label: 'Small (159)' }, { value: 'medium', label: 'Medium (1303)' }] }),
          C.checkboxGroup({ legend: 'Sources', name: 'src', selectAll: true, values: ['crtsh', 'anubis'], options: [{ value: 'crtsh', label: 'crt.sh', hint: 'Certificate Transparency' }, { value: 'certspotter', label: 'Cert Spotter' }, { value: 'anubis', label: 'Anubis' }] }))
      }),
      h('div', { class: 'stack' },
        C.FileDrop({ accept: '.pem,.crt,.cer,.der,.p7b', onFiles: () => {} }),
        C.textarea({ label: 'Hostnames', rows: 4, value: 'www.example.com\napi.example.com' }).el,
        C.Disclosure({ summary: 'Raw response', children: C.CodeBlock('example.com. 300 IN A 93.184.215.14') }),
        C.SegmentedControl({ label: 'Size', options: [{ value: 's', label: 'Small' }, { value: 'm', label: 'Medium' }, { value: 'l', label: 'Large' }], value: 'm' }).el,
        C.TruncatedList(['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5'], { max: 3 })))));
  return true;
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  await mkdir(SHOTS, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: BROWSER, headless: !HEADED });
  const version = await browser.version();
  process.stdout.write(`Serving ${server.url} — ${version.product} (${browser.executablePath})\n`);
  const tmpDir = path.join(os.tmpdir(), `ssds-e2e-${process.pid}`);
  await mkdir(tmpDir, { recursive: true });
  const csvFile = path.join(tmpDir, 'servers.csv');
  await writeFile(csvFile, FILE_INVENTORY);
  const expectedSample = parseInventory(SAMPLE_INVENTORY);
  const expectedPorts = parseInventory(PORT_INVENTORY);

  try {
    /* ---------------- Desktop ---------------- */
    group('Desktop 1440×900');
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    await step('boots at the site root and shows the default view (subdomains)', async () => {
      await page.goto(server.url);
      await waitReady(page);
      assertEqual(await page.evaluate(() => document.documentElement.dataset.view), 'subdomains', 'default view');
      assertEqual(await page.evaluate(() => document.querySelector('h1').textContent), title('subdomains', 'en'), 'h1');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.nav-link').length), ROUTES.length, 'nav links');
      assertEqual(await page.evaluate(() => document.documentElement.lang), 'en', 'html lang');
    });

    await step('the start route loads the global stylesheet and its own; development registers no service worker', async () => {
      const sheets = await page.evaluate(() => [...document.querySelectorAll('link[rel="stylesheet"]')].map((l) => new URL(l.href).pathname));
      assertEqual(sheets, [`${BASE}assets/css/style.css`, `${BASE}assets/css/views/subdomains.css`], 'stylesheets');
      // registration is attempted when the browser is idle: give it that chance first
      await page.evaluate(() => new Promise((r) => requestIdleCallback(() => setTimeout(r, 200), { timeout: 3000 })));
      assertEqual(await page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length), 0, 'registrations');
      assertEqual(await page.evaluate(() => document.querySelector('link[rel="manifest"]').getAttribute('href')), 'manifest.webmanifest', 'manifest');
    });

    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({ 'prefers-color-scheme': scheme });
      for (const id of ROUTES) {
        await step(`[${scheme}] #/${id} renders without horizontal scroll`, async () => {
          await gotoRoute(page, id);
          assertEqual(await page.evaluate(() => document.querySelector('h1.page-title').textContent), title(id, 'en'), 'page title');
          assertEqual(await page.evaluate(() => document.querySelector('.nav-link[aria-current="page"]')?.dataset.view), id, 'active nav');
          assert((await page.evaluate(() => document.title)).includes(title(id, 'en')), 'document.title');
          await assertNoHorizontalScroll(page, id);
          await shot(page, `desktop-${scheme}-en-${id}`);
        });
      }
    }
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    await step('each view brought its stylesheets, kept in cascade order whatever the visiting order', async () => {
      const injected = await page.evaluate(() => [...document.querySelectorAll('link[data-view-css]')].map((l) => l.dataset.viewCss));
      assertEqual(injected, [...VIEW_CSS_ORDER], 'view stylesheets');
      const idle = await page.evaluate(() => [...document.querySelectorAll('link[rel="modulepreload"]')]
        .map((l) => new URL(l.href).pathname).filter((p) => p.includes('/lib/scanner.js')).length);
      assertEqual(idle, 1, 'the scan engine is modulepreloaded once, when idle');
    });

    await step('router: unknown view → subdomains (URL rewritten), anchors keep the view', async () => {
      await gotoRoute(page, 'about');
      await page.evaluate(() => { window.location.hash = '#/definitely-not-a-view'; });
      await page.waitFor(() => document.documentElement.dataset.view === 'subdomains' && window.location.hash === '#/subdomains');
      await gotoRoute(page, 'about');
      await page.evaluate(() => { window.location.hash = '#main'; });
      await new Promise((r) => setTimeout(r, 200));
      assertEqual(await page.evaluate(() => document.documentElement.dataset.view), 'about', 'view after #main');
      await gotoRoute(page, 'lookup');
      await page.evaluate(() => { window.location.hash = '#/lookup?name=example.com&type=MX'; });
      await page.waitFor(() => document.documentElement.dataset.view === 'lookup');
    });

    await step('router: a same-view link that repeats a key keeps every value (#/scan?domain=a&domain=b)', async () => {
      const field = () => page.evaluate(() => document.querySelector('[data-role="scan-domains"]')?.value);
      const go = (hash, want, message) => page.evaluate((x) => { window.location.hash = x; }, hash)
        .then(() => page.waitFor((w) => document.querySelector('[data-role="scan-domains"]')?.value === w, { args: [want], message }));
      await gotoRoute(page, 'scan');
      await go('#/scan?domain=c.example.com', 'c.example.com', 'one domain (view update)');
      await go('#/scan?domain=a.example.com&domain=b.example.com', 'a.example.com\nb.example.com', 'both repeated values');
      await go('#/scan?domain=x.example.com&domain=b.example.com', 'x.example.com\nb.example.com', 'only a non-last value changed');
      assertEqual(await field(), 'x.example.com\nb.example.com', 'scan domains');
      await page.type('[data-role="scan-domains"]', '');
    });

    await step('skip link moves focus to the page title', async () => {
      await page.evaluate(() => document.getElementById('skip-link').focus());
      await page.press('Enter');
      await page.waitFor(() => document.activeElement && document.activeElement.id === 'page-title');
    });

    await step('theme toggle overrides the system preference', async () => {
      const bg = () => page.evaluate(() => {
        const m = getComputedStyle(document.body).backgroundColor.match(/\d+/g).map(Number);
        return (0.2126 * m[0] + 0.7152 * m[1] + 0.0722 * m[2]) / 255;
      });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      assert(await bg() > 0.8, 'light background under system light');
      await page.click('[data-control="theme"] [data-value="dark"]');
      await page.waitFor(() => document.documentElement.dataset.theme === 'dark');
      assert(await bg() < 0.15, 'dark background with data-theme=dark');
      await shot(page, 'desktop-forced-dark-header');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.click('[data-control="theme"] [data-value="light"]');
      await page.waitFor(() => document.documentElement.dataset.theme === 'light');
      assert(await bg() > 0.8, 'light background with data-theme=light under system dark');
      await page.click('[data-control="theme"] [data-value="auto"]');
      await page.waitFor(() => !document.documentElement.dataset.theme);
      assert(await bg() < 0.15, 'auto follows system dark');
      const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.settings')).theme);
      assertEqual(saved, 'auto', 'persisted theme');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    await step('theme toggle takes a click on its previous option after a change made elsewhere', async () => {
      const theme = () => page.evaluate(() => document.documentElement.dataset.theme || 'auto');
      await page.click('[data-control="theme"] [data-value="dark"]');
      await page.waitFor(() => document.documentElement.dataset.theme === 'dark');
      // "Delete all local data" resets the theme to auto without going through the toggle.
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.clearAll());
      await page.waitFor(() => !document.documentElement.dataset.theme, { message: 'auto after clearAll' });
      await page.click('[data-control="theme"] [data-value="dark"]');
      await page.waitFor(() => document.documentElement.dataset.theme === 'dark', { message: 'Dark clicked again' });
      assertEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.settings')).theme), 'dark', 'persisted theme');
      // The phone cycle button (hidden on desktop) changes the theme too: dark → auto.
      await page.evaluate(() => document.querySelector('[data-control="theme-cycle"]').click());
      await page.waitFor(() => !document.documentElement.dataset.theme, { message: 'cycle to auto' });
      await page.click('[data-control="theme"] [data-value="dark"]');
      await page.waitFor(() => document.documentElement.dataset.theme === 'dark', { message: 'Dark after the cycle button' });
      await page.click('[data-control="theme"] [data-value="auto"]');
      await page.waitFor(() => !document.documentElement.dataset.theme);
      assertEqual(await theme(), 'auto', 'back to auto');
      await dismissToasts(page);
    });

    await step('print from dark mode: light palette, no shell or controls, details opened and a header on beforeprint, restored after', async () => {
      await gotoRoute(page, 'about');
      await page.click('[data-control="theme"] [data-value="dark"]');
      await page.waitFor(() => document.documentElement.dataset.theme === 'dark');
      const lum = (rgb) => {
        const m = rgb.match(/\d+/g).map(Number);
        return (0.2126 * m[0] + 0.7152 * m[1] + 0.0722 * m[2]) / 255;
      };
      const closedBefore = await page.evaluate(() => document.querySelectorAll('#main details:not([open])').length);
      assert(closedBefore > 0, 'About has a closed Disclosure');
      try {
        await page.send('Emulation.setEmulatedMedia', { media: 'print', features: [{ name: 'prefers-color-scheme', value: 'dark' }] });
        await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
        const printed = await page.evaluate(() => {
          const shown = (sel) => {
            const el = document.querySelector(sel);
            return !!el && getComputedStyle(el).display !== 'none';
          };
          const head = document.querySelector('.print-head');
          return {
            text: getComputedStyle(document.body).color,
            paper: getComputedStyle(document.body).backgroundColor,
            nav: shown('.app-nav'), header: shown('.app-header'), pageHeader: shown('.page-header'), button: shown('#page-body .btn'),
            closed: document.querySelectorAll('#main details:not([open])').length,
            head: head ? { shown: getComputedStyle(head).display !== 'none', text: head.textContent, href: head.querySelector('a').getAttribute('href') } : null
          };
        });
        assert(lum(printed.text) < 0.25 && lum(printed.paper) > 0.9, `dark text on white paper: ${printed.text} on ${printed.paper}`);
        assertEqual([printed.nav, printed.header, printed.pageHeader, printed.button], [false, false, false, false], 'nav, header, page header and buttons hidden');
        assertEqual(printed.closed, 0, 'every Disclosure opened for the print');
        assert(printed.head && printed.head.shown, 'print header shown');
        assert(/^DomainScope · About/.test(printed.head.text) && /Printed \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC/.test(printed.head.text), `print header: ${printed.head.text}`);
        assert(printed.head.href.endsWith('/domainscope/#/about'), `permalink: ${printed.head.href}`);
        if (SHOTS_ON) await page.screenshot(path.join(SHOTS, 'desktop-print-dark-about.png'));
        await page.evaluate(() => window.dispatchEvent(new Event('afterprint')));
        const after = await page.evaluate(() => ({ closed: document.querySelectorAll('#main details:not([open])').length, head: !!document.querySelector('.print-head') }));
        assertEqual(after, { closed: closedBefore, head: false }, 'afterprint closes them again and drops the header');
        // A real print (Page.printToPDF) fires the same events and yields a PDF.
        const pdf = await page.send('Page.printToPDF', { preferCSSPageSize: true });
        assertEqual(Buffer.from(pdf.data, 'base64').subarray(0, 5).toString('latin1'), '%PDF-', 'a PDF');
        assertEqual(await page.evaluate(() => ({ closed: document.querySelectorAll('#main details:not([open])').length, head: !!document.querySelector('.print-head') })),
          { closed: closedBefore, head: false }, 'nothing left behind by a print');
      } finally {
        await page.emulateMedia({ 'prefers-color-scheme': 'light' });
        await page.click('[data-control="theme"] [data-value="auto"]');
        await page.waitFor(() => !document.documentElement.dataset.theme);
      }
    });

    await step('language toggle switches shell + view to Turkish and back', async () => {
      await gotoRoute(page, 'inventory');
      await setLangUi(page, 'tr');
      assertEqual(await page.evaluate(() => document.querySelector('h1.page-title').textContent), title('inventory', 'tr'), 'TR h1');
      assertEqual(await page.evaluate(() => document.querySelector('.nav-link[data-view="scan"] .nav-label').textContent), title('scan', 'tr'), 'TR nav');
      assert(await page.evaluate(() => document.querySelector('.brand-sub').textContent === 'SSL & DNS araç kutusu'), 'TR subtitle');
      assertEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.settings')).lang), 'tr', 'persisted lang');
      await shot(page, 'desktop-light-tr-inventory-empty');
      await setLangUi(page, 'en');
      assertEqual(await page.evaluate(() => document.querySelector('h1.page-title').textContent), title('inventory', 'en'), 'EN h1');
    });

    await step('About › CLI examples are labelled in both languages, the cron monitoring one included', async () => {
      await gotoRoute(page, 'about');
      const examples = () => page.evaluate(async () => {
        const i = await import('./assets/js/i18n.js');
        return {
          want: i.t('about.ex7'),
          list: [...document.querySelectorAll('#about-cli .about-examples .codeblock')].map((b) => ({
            label: b.querySelector('.codeblock-label')?.textContent ?? '',
            cmd: b.querySelector('pre code').textContent
          }))
        };
      });
      const labels = {};
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        const { want, list } = await examples();
        assert(list.length >= 6 && list.every((ex) => ex.label && ex.cmd.startsWith('python3 ssl_origin_scan.py ')),
          `examples (${lang}): ${JSON.stringify(list)}`);
        const cron = list.find((ex) => ex.cmd.includes('--baseline'));
        assertEqual(cron?.label, want, `cron example label (${lang})`);
        assert(cron.cmd.includes('--baseline last.json --json last.json --warn-days 21'), `cron command: ${cron.cmd}`);
        labels[lang] = cron.label;
      }
      assert(labels.tr !== labels.en && labels.tr.includes('DOMAINSCOPE_NOTIFY_URL'), `labels: ${JSON.stringify(labels)}`);
    });

    await step('settings dialog: reorder/toggle resolvers, restore defaults, Esc closes', async () => {
      // Expectations are derived from DEFAULT_CHAIN so they follow any change of the default.
      assert(DEFAULT_CHAIN.length >= 3, `DEFAULT_CHAIN needs 3+ resolvers for this step: ${DEFAULT_CHAIN}`);
      const waitChain = (want, message) => page.waitFor((w) => JSON.parse(localStorage.getItem('ssds.settings') || '{}').chain?.join(',') === w,
        { args: [want], message });
      const toggled = DEFAULT_CHAIN[1];
      const afterToggle = DEFAULT_CHAIN.filter((id) => id !== toggled);
      const moved = afterToggle[afterToggle.length - 1];
      const afterMove = afterToggle.slice();
      [afterMove[afterMove.length - 2], afterMove[afterMove.length - 1]] = [moved, afterMove[afterMove.length - 2]];

      await page.click('[data-control="settings"]');
      try {
        await page.waitForSelector('dialog.modal[open] .settings-resolvers');
        await shot(page, 'desktop-light-en-settings');
        // The dialog lists the active chain first, in order, and explains the resolvers browsers cannot use.
        const listed = await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open] .settings-resolver.is-active')].map((li) => li.dataset.resolver));
        assertEqual(listed, [...DEFAULT_CHAIN], 'active resolvers in dialog');
        const notes = await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open] [data-note]')].map((n) => n.dataset.note));
        assert(notes.includes('quad9') && notes.includes('controld'), `resolver notes in the dialog: ${notes}`);

        await page.click(`dialog.modal[open] [data-resolver="${toggled}"] input[type="checkbox"]`);
        await waitChain(afterToggle.join(','), `chain without ${toggled}`);
        await page.click(`dialog.modal[open] [data-resolver="${moved}"] .btn-icon`); // first icon button = move up
        await waitChain(afterMove.join(','), `chain after moving ${moved} up`);
        setNodeLang('en');
        const wantStatus = translate('shell.dohStatus', { chain: afterMove.map((id) => getResolver(id).name).join(' → ') });
        const status = await page.evaluate(() => document.querySelector('[data-status="doh"]').textContent);
        assertEqual(status, wantStatus, 'nav DoH status reflects the new order');
        await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open] .modal-foot button')][0].click());
        await waitChain(DEFAULT_CHAIN.join(','), 'restore defaults → DEFAULT_CHAIN');
        await page.press('Escape');
        await page.waitFor(() => !document.querySelector('dialog.modal'), { message: 'dialog closed' });
      } finally {
        // Never leave a modal open on failure: it would make the rest of the page inert and
        // turn one failed assertion into a cascade of unrelated failures in the next steps.
        await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
      }
    });

    await step('settings dialog: keyboard focus survives every re-render; the last resolver stays ticked', async () => {
      const waitChain = (want, message) => page.waitFor((w) => JSON.parse(localStorage.getItem('ssds.settings') || '{}').chain?.join(',') === w,
        { args: [want.join(',')], message });
      const focused = () => page.evaluate(() => {
        const a = document.activeElement;
        return {
          id: a.id || null,
          move: a.dataset.move || null,
          disabled: !!a.disabled,
          resolver: a.closest('[data-resolver]')?.dataset.resolver || null,
          inDialog: !!a.closest('dialog.modal[open]')
        };
      });
      const focusOn = (sel) => page.evaluate((s) => document.querySelector(`dialog.modal[open] ${s}`).focus(), sel);
      const restoreDefaults = () => page.evaluate(() => [...document.querySelectorAll('dialog.modal[open] .modal-foot button')][0].click());
      const [first, second] = DEFAULT_CHAIN;
      const last = DEFAULT_CHAIN[DEFAULT_CHAIN.length - 1];

      await page.click('[data-control="settings"]');
      try {
        await page.waitForSelector('dialog.modal[open] .settings-resolvers');
        // Space on a checkbox: the list is rebuilt and the new checkbox takes the focus back.
        await focusOn(`[data-resolver="${second}"] input[type="checkbox"]`);
        await page.press('Space');
        await waitChain(DEFAULT_CHAIN.filter((id) => id !== second), `chain without ${second}`);
        let f = await focused();
        assertEqual([f.id, f.inDialog], [`settings-res-${second}`, true], 'focus after Space');
        await restoreDefaults();
        await waitChain(DEFAULT_CHAIN, 'defaults');

        // Move up to the top: its Move up is disabled now, so Move down takes the focus.
        await focusOn(`[data-resolver="${second}"] [data-move="up"]`);
        await page.press('Enter');
        const top = [second, first, ...DEFAULT_CHAIN.slice(2)];
        await waitChain(top, `${second} moved to the top`);
        f = await focused();
        assertEqual([f.resolver, f.move, f.disabled, f.inDialog], [second, 'down', false, true], 'focus after a move to the top');
        // Move down to the bottom: Move up takes the focus.
        const penult = top[top.length - 2];
        await focusOn(`[data-resolver="${penult}"] [data-move="down"]`);
        await page.press('Enter');
        const bottom = [...top.slice(0, -2), top[top.length - 1], penult];
        await waitChain(bottom, `${penult} moved to the bottom`);
        f = await focused();
        assertEqual([f.resolver, f.move, f.disabled, f.inDialog], [penult, 'up', false, true], 'focus after a move to the bottom');
        await restoreDefaults();
        await waitChain(DEFAULT_CHAIN, 'defaults');

        // Untick all but one, then the last one: refused, and its checkbox stays ticked.
        for (let i = 0; i < DEFAULT_CHAIN.length - 1; i += 1) {
          await page.click(`dialog.modal[open] [data-resolver="${DEFAULT_CHAIN[i]}"] input[type="checkbox"]`);
          await waitChain(DEFAULT_CHAIN.slice(i + 1), `unticked ${DEFAULT_CHAIN[i]}`);
        }
        await focusOn(`[data-resolver="${last}"] input[type="checkbox"]`);
        await page.press('Space');
        await page.waitFor(() => !document.querySelector('dialog.modal[open] .field-error').hidden, { message: 'refusal shown' });
        const refused = await page.evaluate((id) => ({
          checked: document.getElementById(`settings-res-${id}`).checked,
          ticked: [...document.querySelectorAll('dialog.modal[open] .settings-resolver input:checked')].map((c) => c.id),
          chain: JSON.parse(localStorage.getItem('ssds.settings')).chain
        }), last);
        assertEqual(refused, { checked: true, ticked: [`settings-res-${last}`], chain: [last] }, 'the last resolver stays ticked and in the chain');
        f = await focused();
        assertEqual(f.id, `settings-res-${last}`, 'focus after the refusal');
        await restoreDefaults();
        await waitChain(DEFAULT_CHAIN, 'defaults');
        assert(await page.evaluate(() => document.querySelector('dialog.modal[open] .field-error').hidden), 'restore defaults hides the error');
        await page.press('Escape');
        await page.waitFor(() => !document.querySelector('dialog.modal'), { message: 'dialog closed' });
      } finally {
        await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
      }
    });

    await step('getDns() lazily creates a shared DohClient from settings', async () => {
      const info = await page.evaluate(async () => {
        const app = await import('./assets/js/app.js');
        const a = await app.getDns();
        const b = await app.getDns();
        return { same: a === b, hasQuery: typeof a.query === 'function', ctor: a.constructor.name };
      });
      assert(info.same && info.hasQuery, `getDns: ${JSON.stringify(info)}`);
    });

    await step('Servers: typing parses live (table, stats, warnings)', async () => {
      await gotoRoute(page, 'inventory');
      await page.type('[data-role="inventory-text"]', SAMPLE_INVENTORY);
      await page.waitFor((n) => document.querySelectorAll('.inv-results .dt-table tbody tr').length === n,
        { args: [expectedSample.servers.length], message: 'parsed rows' });
      const ui = await page.evaluate(() => ({
        servers: document.querySelector('.inv-stats .stat .stat-value').textContent,
        warnings: [...document.querySelectorAll('.inv-warning')].map((w) => w.dataset.code),
        unsaved: !!document.querySelector('.inv-status .badge-warn'),
        saveEnabled: !document.querySelector('[data-action="save"]').disabled
      }));
      assertEqual(ui.servers, String(expectedSample.servers.length), 'servers stat');
      assertEqual(ui.warnings, expectedSample.warnings.map((w) => w.code), 'warning codes');
      assert(ui.unsaved && ui.saveEnabled, 'unsaved state');
    });

    await step('Servers: clicking a warning selects that line in the editor', async () => {
      const w = expectedSample.warnings[0];
      await page.click(`.inv-warning[data-line="${w.line}"]`);
      const sel = await page.evaluate(() => {
        const ta = document.querySelector('[data-role="inventory-text"]');
        return { active: document.activeElement === ta, text: ta.value.slice(ta.selectionStart, ta.selectionEnd) };
      });
      assert(sel.active, 'textarea focused');
      assertEqual(sel.text, SAMPLE_INVENTORY.split('\n')[w.line - 1], 'selected line');
    });

    await step('Servers: search filters the table; examples tabs are keyboard accessible', async () => {
      await page.type('.inv-results .dt-search-input', 'lb-edge');
      await page.waitFor(() => document.querySelectorAll('.inv-results .dt-table tbody tr').length === 1);
      await page.type('.inv-results .dt-search-input', '');
      await page.waitFor((n) => document.querySelectorAll('.inv-results .dt-table tbody tr').length === n, { args: [expectedSample.servers.length] });
      await page.evaluate(() => { document.querySelector('.inv-formats').open = true; });
      await page.evaluate(() => document.querySelector('.inv-examples [role="tab"][aria-selected="true"]').focus());
      await page.press('ArrowRight');
      assertEqual(await page.evaluate(() => document.activeElement.dataset.tab), 'hosts', 'focused tab after ArrowRight');
      assertEqual(await page.evaluate(() => document.querySelector('.inv-examples [role="tab"][aria-selected="true"]').dataset.tab), 'hosts', 'selected tab');
      await page.press('End');
      assertEqual(await page.evaluate(() => document.activeElement.dataset.tab), 'json', 'End → last tab');
    });

    await step('Servers: save persists across reload and updates the nav status', async () => {
      await page.click('[data-action="save"]');
      await page.waitFor(() => !!localStorage.getItem('ssds.inventory'));
      await page.waitFor((n) => document.querySelector('[data-status="inventory"]').textContent.includes(String(n)), { args: [expectedSample.servers.length] });
      await shot(page, 'desktop-light-en-inventory-filled');
      await page.reload();
      await waitReady(page);
      await page.waitFor(() => document.documentElement.dataset.view === 'inventory');
      const text = await page.evaluate(() => document.querySelector('[data-role="inventory-text"]').value);
      assertEqual(text, SAMPLE_INVENTORY, 'text after reload');
      assert(await page.evaluate(() => document.querySelector('[data-action="save"]').disabled), 'save disabled when clean');
    });

    await step('Servers: importing a file asks Replace/Append and replaces', async () => {
      await page.setFileInput('.inv-editor .filedrop-input', [csvFile]);
      await page.waitForSelector('dialog.modal[open]');
      await page.click('dialog.modal[open] .modal-foot .btn-primary');
      await page.waitFor(() => document.querySelector('[data-role="inventory-text"]').value.startsWith('hostname,ip_address'));
      await page.waitFor(() => document.querySelectorAll('.inv-results .dt-table tbody tr').length === 3);
      const groups = await page.evaluate(() => [...document.querySelectorAll('.inv-results .inv-groups .badge')].map((b) => b.textContent));
      assert(groups.includes('api') && groups.includes('mail'), `CSV role column → groups: ${groups}`);
    });

    await step('Servers: unsaved edits survive navigating away (session draft)', async () => {
      await gotoRoute(page, 'about');
      await gotoRoute(page, 'inventory');
      const text = await page.evaluate(() => document.querySelector('[data-role="inventory-text"]').value);
      assert(text.startsWith('hostname,ip_address'), 'draft restored');
    });

    await step('Servers: language switch keeps the editor content (snapshot)', async () => {
      await setLangUi(page, 'tr');
      const text = await page.evaluate(() => document.querySelector('[data-role="inventory-text"]').value);
      assert(text.startsWith('hostname,ip_address'), 'text kept across re-mount');
      await setLangUi(page, 'en');
    });

    await step('Servers: clear asks for confirmation and removes the saved inventory', async () => {
      await dismissToasts(page);
      await page.click('[data-action="clear"]');
      await page.waitForSelector('dialog.modal[open]');
      await page.click('dialog.modal[open] .btn-danger');
      await page.waitFor(() => document.querySelector('[data-role="inventory-text"]').value === '' && !localStorage.getItem('ssds.inventory'));
      await page.type('[data-role="inventory-text"]', SAMPLE_INVENTORY);
      await page.click('[data-action="save"]');
      await page.waitFor(() => !!localStorage.getItem('ssds.inventory'));
    });

    await step('Servers: Settings › Delete all local data empties the open editor (no draft brings it back)', async () => {
      await dismissToasts(page);
      await page.click('[data-control="settings"]');
      try {
        await page.waitForSelector('dialog.modal[open] .settings-danger');
        await page.click('dialog.modal[open] .settings-danger .btn-danger');
        await page.waitFor(() => document.querySelectorAll('dialog.modal[open]').length === 2, { message: 'confirmation' });
        await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open]')].find((d) => !d.querySelector('.settings-danger')).querySelector('.btn-danger').click());
        await page.waitFor(() => !document.querySelector('dialog.modal[open]'), { message: 'dialogs closed' });
      } finally {
        await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
      }
      const ui = () => page.evaluate(() => ({
        text: document.querySelector('[data-role="inventory-text"]').value,
        rows: document.querySelectorAll('.inv-results .dt-table tbody tr.dt-row').length,
        unsaved: !!document.querySelector('.inv-status .badge-warn'),
        saveDisabled: document.querySelector('[data-action="save"]').disabled,
        keys: Object.keys(localStorage).filter((k) => k.startsWith('ssds.'))
      }));
      const want = { text: '', rows: 0, unsaved: false, saveDisabled: true, keys: [] };
      assertEqual(await ui(), want, 'editor emptied with the storage');
      await gotoRoute(page, 'about');
      await gotoRoute(page, 'inventory');
      assertEqual(await ui(), want, 'no session draft restored');
      // Back to the saved sample for the steps below.
      await page.type('[data-role="inventory-text"]', SAMPLE_INVENTORY);
      await page.click('[data-action="save"]');
      await page.waitFor(() => !!localStorage.getItem('ssds.inventory'));
      await dismissToasts(page);
    });

    await step('Servers: an address written with a port is shown and exported with it; a bad port is a warning; an Ansible host keeps -p', async () => {
      await page.type('[data-role="inventory-text"]', PORT_INVENTORY);
      // The saved sample has as many servers: wait for this inventory's own rows.
      await page.waitFor((n) => document.querySelectorAll('.inv-results .dt-table tbody tr.dt-row').length === n
        && [...document.querySelectorAll('.inv-results .inv-ip')].some((s) => s.firstChild.textContent === '203.0.113.10:8443'),
      { args: [expectedPorts.servers.length], message: 'parsed rows' });
      const ui = await page.evaluate(() => ({
        ips: [...document.querySelectorAll('.inv-results .dt-table tbody tr.dt-row')]
          .map((tr) => [...tr.querySelectorAll('.inv-ip')].map((s) => s.firstChild.textContent)),
        warnings: [...document.querySelectorAll('.inv-warning')].map((w) => [Number(w.dataset.line), w.dataset.code]),
        texts: [...document.querySelectorAll('.inv-warning .inv-warning-code')].map((c) => c.textContent)
      }));
      assertEqual(ui.ips, [['203.0.113.10:8443'], ['[2001:db8::2]:8443', '203.0.113.12'], ['10.0.0.13', '10.0.0.13:8443'], ['203.0.113.17']],
        'ip:port in the table, an Ansible SSH port not');
      assertEqual(ui.warnings, [[4, 'INVALID_IP'], [5, 'PARSE'], [5, 'NO_IP'], [7, 'PARSE']], 'bad port, host:port and SSH port warned');
      assertEqual([...ui.texts.slice(0, 2), ui.texts[3]], ['Invalid port — a port is a number from 1 to 65535',
        'Host name with a port — servers are matched by address here, so write the address with the port',
        'Ansible SSH port — a port on an Ansible host is its SSH port (ansible_port), not a TLS port: the CLI scans this server on its -p ports'],
      'the warnings say what is wrong');
      const file = await page.evaluate(async () => {
        // Capture the download: ui/download.js creates a Blob URL and clicks a temporary <a download>.
        const create = URL.createObjectURL;
        const click = HTMLAnchorElement.prototype.click;
        const blobs = new Map();
        let got = null;
        URL.createObjectURL = (blob) => { const url = create.call(URL, blob); blobs.set(url, blob); return url; };
        HTMLAnchorElement.prototype.click = function capture() {
          if (this.download && blobs.has(this.href)) got = { name: this.download, blob: blobs.get(this.href) };
          else click.call(this);
        };
        try {
          document.querySelector('[data-action="targets"]').click();
        } finally {
          URL.createObjectURL = create;
          HTMLAnchorElement.prototype.click = click;
        }
        return got && { name: got.name, text: await got.blob.text() };
      });
      assertEqual(file && file.name, 'targets.txt', 'targets.txt downloaded');
      assertEqual(file.text, 'web01 203.0.113.10:8443\nweb02 [2001:db8::2]:8443 203.0.113.12\nweb03 10.0.0.13 10.0.0.13:8443\n203.0.113.17\n',
        'the CLI scans the same ip:port, and the Ansible host on -p');
      await shot(page, 'desktop-light-en-inventory-ports');
      // Back to the saved sample (the editor was only edited, never saved).
      await page.type('[data-role="inventory-text"]', SAMPLE_INVENTORY);
      await page.waitFor((n) => document.querySelectorAll('.inv-results .dt-table tbody tr.dt-row').length === n,
        { args: [expectedSample.servers.length] });
      await dismissToasts(page);
    });

    await step('component gallery renders; DataTable paging, sorting, search and streaming work', async () => {
      await gotoRoute(page, 'about');
      await page.evaluate(buildGallery);
      const rowCount = () => page.evaluate(() => document.querySelectorAll('#gallery .dt-table tbody tr.dt-row').length);
      assertEqual(await rowCount(), 200, 'first page');
      await page.click('#gallery .dt-more .btn-secondary');
      await page.waitFor(() => document.querySelectorAll('#gallery .dt-table tbody tr.dt-row').length === 400);
      await page.click('#gallery th[data-key="name"] .dt-sort');
      await page.click('#gallery th[data-key="name"] .dt-sort');
      assertEqual(await page.evaluate(() => document.querySelector('#gallery th[data-key="name"]').getAttribute('aria-sort')), 'descending', 'aria-sort');
      assertEqual(await page.evaluate(() => document.querySelector('#gallery .dt-table tbody tr.dt-row td:nth-child(2)').textContent), 'web-450.example.com', 'natural desc sort');
      await page.type('#gallery .dt-search-input', 'web-12');
      await page.waitFor(() => document.querySelectorAll('#gallery .dt-table tbody tr.dt-row').length === 11);
      await page.type('#gallery .dt-search-input', '');
      await page.waitFor(() => window.__table.getVisibleRows().length === 450);
      await page.evaluate(() => {
        for (let i = 451; i <= 500; i += 1) window.__table.addRows([{ name: `stream-${i}.example.com`, ip: '192.0.2.1', kind: 'direct', ttl: 60, covered: true }]);
      });
      await page.waitFor(() => window.__table.getRows().length === 500 && /500/.test(document.querySelector('#gallery .dt-count').textContent));
      await page.click('#gallery .dt-toolbar .check-input');
      await page.waitFor(() => window.__table.getVisibleRows().length === 350);
      await page.click('#gallery .dt-toolbar .check-input');
      await page.click('#gallery .dt-row .dt-expand-btn');
      await page.waitForSelector('#gallery .dt-details .kv');
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, 'desktop-light-en-gallery');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await shot(page, 'desktop-dark-en-gallery');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    await step('CopyButton: a text toastOnCopy toasts that text; onFail gets the text in place of the "could not copy" toast', async () => {
      // A clipboard recorder (or a refusing one) in place of the page's clipboard, removed afterwards.
      const clipboard = (mode) => page.evaluate((m) => {
        window.__clip = [];
        window.__copyFailed = null;
        if (m === 'real') {
          delete navigator.clipboard;
          delete document.execCommand;
          return;
        }
        Object.defineProperty(navigator, 'clipboard', {
          configurable: true,
          value: {
            writeText: async (text) => {
              if (m === 'fail') throw new DOMException('Write permission denied.', 'NotAllowedError');
              window.__clip.push(String(text));
            }
          }
        });
        if (m === 'fail') document.execCommand = () => false;
      }, mode);
      const toasts = () => page.evaluate(() => [...document.querySelectorAll('.toast')].map((el) => ({ type: el.className, text: el.textContent })));
      try {
        await dismissToasts(page);
        await clipboard('ok');
        await page.click('#gallery .gallery-copy-summary');
        const copied = await page.waitFor(() => (window.__clip.length && document.querySelector('.toast') ? window.__clip : false), { message: 'copied + toast' });
        assertEqual(copied, ['summary text'], 'copied');
        const [shown] = await toasts();
        assert(/Summary copied/.test(shown.text) && /success/.test(shown.type), `its own toast text: ${JSON.stringify(shown)}`);
        await dismissToasts(page);
        await clipboard('fail');
        await page.click('#gallery .gallery-copy-summary');
        await page.waitFor(() => window.__copyFailed === 'summary text', { message: 'onFail called with the text' });
        await page.evaluate(() => new Promise((r) => { setTimeout(r, 150); }));
        assertEqual(await toasts(), [], 'no "could not copy" toast when onFail takes over');
        await page.click('#gallery .gallery-copy');
        const failed = await page.waitFor(() => document.querySelector('.toast')?.textContent || false, { message: 'error toast without onFail' });
        assert(/Could not copy/.test(failed), `a plain CopyButton still says it failed: ${failed}`);
      } finally {
        await clipboard('real');
        await dismissToasts(page);
      }
    });

    await step('print: a sortable header keeps its label as header text (repeated on every page); cells break between words only', async () => {
      await page.send('Emulation.setEmulatedMedia', { media: 'print' });
      try {
        const css = await page.evaluate(() => {
          const th = document.querySelector('#gallery th[data-key="name"]');
          return {
            sort: getComputedStyle(th.querySelector('.dt-sort')).display,
            label: th.textContent.trim(),
            cell: getComputedStyle(document.querySelector('#gallery .dt-table tbody td')).overflowWrap,
            item: getComputedStyle(document.querySelector('#gallery .tlist-item')).overflowWrap
          };
        });
        assertEqual(css, { sort: 'contents', label: 'Name', cell: 'break-word', item: 'break-word' }, 'print styles of the table');
      } finally {
        await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      }
    });

    await step('DataTable keeps keyboard focus on a row control when rows stream in, on refresh and on expand', async () => {
      const focusInfo = () => page.evaluate(() => {
        const a = document.activeElement;
        const tr = a && a.closest('#gallery tbody tr.dt-row');
        return { expandBtn: !!a && a.classList.contains('dt-expand-btn'), row: tr ? tr.querySelector('td:nth-child(2)').textContent : null, expanded: a && a.getAttribute('aria-expanded') };
      });
      const nextFrame = () => page.evaluate(() => new Promise((resolve) => { requestAnimationFrame(() => setTimeout(resolve, 50)); }));
      const name = await page.evaluate(() => {
        const tr = document.querySelectorAll('#gallery tbody tr.dt-row')[1];
        tr.querySelector('.dt-expand-btn').focus();
        return tr.querySelector('td:nth-child(2)').textContent;
      });
      await page.evaluate(() => window.__table.addRows([{ name: 'stream-501.example.com', ip: '192.0.2.2', kind: 'direct', ttl: 60, covered: true }]));
      await nextFrame();
      assertEqual(await focusInfo(), { expandBtn: true, row: name, expanded: 'false' }, 'after streamed rows');
      await page.evaluate(() => window.__table.refresh());
      assertEqual(await focusInfo(), { expandBtn: true, row: name, expanded: 'false' }, 'after refresh (rebuilt row)');
      await page.press('Enter');
      assertEqual(await focusInfo(), { expandBtn: true, row: name, expanded: 'true' }, 'after expanding with the keyboard');
    });

    await step('gallery: toast, modal and Tabs behave', async () => {
      await page.evaluate(async () => {
        const C = await import('./assets/js/ui/components.js');
        C.toast('Saved 12 servers', { type: 'success', timeout: 0 });
        C.toast('HackerTarget quota exceeded', { type: 'error', title: 'Rate limited', timeout: 0 });
      });
      await page.waitFor(() => document.querySelectorAll('.toast').length === 2);
      const modalResult = page.evaluate(async () => {
        const C = await import('./assets/js/ui/components.js');
        return C.Modal({ title: 'Replace inventory?', content: 'The editor already has content.', actions: [{ label: 'Cancel', value: 'no' }, { label: 'Replace', value: 'yes', variant: 'primary' }] }).open();
      });
      await page.waitForSelector('dialog.modal[open]');
      await shot(page, 'desktop-light-en-modal-toasts');
      await page.click('dialog.modal[open] .btn-primary');
      assertEqual(await modalResult, 'yes', 'modal result');
      // Past the limit the oldest timed toast goes; the sticky ones (an update offer) stay.
      const kept = await page.evaluate(async () => {
        const C = await import('./assets/js/ui/components.js');
        for (let i = 1; i <= 5; i += 1) C.toast(`Timed ${i}`);
        return [...document.querySelectorAll('.toast .toast-message')].map((el) => el.textContent);
      });
      assertEqual(kept, ['Saved 12 servers', 'HackerTarget quota exceeded', 'Timed 4', 'Timed 5'], 'toasts past the limit');
      await dismissToasts(page);
      await page.evaluate(() => window.__tabs.select('servers'));
      assertEqual(await page.evaluate(() => window.__tabs.getSelected()), 'servers', 'tabs.select');
    });

    await step('Settings › Delete all local data also forgets the learned names and this tab\'s custom wordlist', async () => {
      await dismissToasts(page);
      // Seed the per-browser vocabulary the way the Subdomains view keeps it.
      await page.evaluate(() => {
        localStorage.setItem('ssds.learned.labels', JSON.stringify({ v: 1, seq: 2, labels: { api: [2, 1], vpn: [1, 2] } }));
        sessionStorage.setItem('ssds.wordlist.custom', 'portal\nbilling');
        sessionStorage.setItem('other.key', 'keep');
      });
      await page.reload();
      await waitReady(page);
      await gotoRoute(page, 'subdomains');
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
      const before = await page.evaluate(() => ({
        learned: document.querySelector('.sub-learned .check-text').textContent,
        custom: document.querySelector('[data-role="sub-custom"]').value
      }));
      assert(/\(2\)$/.test(before.learned) && before.custom === 'portal\nbilling', `seeded: ${JSON.stringify(before)}`);
      await page.click('[data-control="settings"]');
      try {
        await page.waitForSelector('dialog.modal[open] .settings-danger');
        const hint = await page.evaluate(() => document.querySelector('dialog.modal[open] .settings-danger .field-hint').textContent);
        assert(/learned subdomain names and the custom wordlist/.test(hint), `the hint says what is deleted: ${hint}`);
        await page.click('dialog.modal[open] .settings-danger .btn-danger');
        await page.waitFor(() => document.querySelectorAll('dialog.modal[open]').length === 2, { message: 'confirmation' });
        await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open]')].find((d) => !d.querySelector('.settings-danger')).querySelector('.btn-danger').click());
        await page.waitFor(() => !document.querySelector('dialog.modal[open]'), { message: 'dialogs closed' });
      } finally {
        await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
      }
      const after = await page.waitFor(() => {
        const label = document.querySelector('.sub-learned .check-text').textContent;
        return /none yet/.test(label) ? {
          label,
          custom: document.querySelector('[data-role="sub-custom"]').value,
          status: document.querySelector('.sub-custom-status').textContent,
          learnedKey: localStorage.getItem('ssds.learned.labels'),
          customKey: sessionStorage.getItem('ssds.wordlist.custom'),
          other: sessionStorage.getItem('other.key')
        } : false;
      }, { message: 'view refreshed after the delete' });
      assertEqual([after.custom, after.status, after.learnedKey, after.customKey, after.other], ['', 'No custom names.', null, null, 'keep'],
        'learned names + custom wordlist gone; other session keys kept');
      await page.evaluate(() => sessionStorage.removeItem('other.key'));
      // Settings were reset too: back to English for the remaining steps.
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = false; });
    });

    await step('About › Delete all local data also drops the custom wordlist while Subdomains is not mounted', async () => {
      await dismissToasts(page);
      await gotoRoute(page, 'subdomains');
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
      await page.type('[data-role="sub-custom"]', 'portal, billing');
      await page.waitFor(() => sessionStorage.getItem('ssds.wordlist.custom') === 'portal, billing', { message: 'custom list kept for this tab' });
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = false; });
      // Wipe from another view: the Subdomains view (and its 'cleared' listener) is unmounted now.
      await gotoRoute(page, 'about');
      await page.click('[data-action="clear-data"]');
      try {
        await page.waitFor(() => !!document.querySelector('dialog.modal[open] .btn-danger'), { message: 'confirmation' });
        await page.click('dialog.modal[open] .btn-danger');
        await page.waitFor(() => !document.querySelector('dialog.modal[open]'), { message: 'dialog closed' });
      } finally {
        await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
      }
      await gotoRoute(page, 'subdomains');
      const after = await page.evaluate(() => ({
        custom: document.querySelector('[data-role="sub-custom"]').value,
        status: document.querySelector('.sub-custom-status').textContent,
        key: sessionStorage.getItem('ssds.wordlist.custom')
      }));
      assertEqual([after.custom, after.status, after.key], ['', 'No custom names.', null], 'the module keeps no stale copy after a delete from another view');
      await dismissToasts(page);
    });

    await step('a laptop screen (1366 × 657): every tool link of the sidebar in view; shorter still, the sidebar scrolls to the open tool', async () => {
      const sidebar = () => page.evaluate(() => {
        const nav = document.getElementById('app-nav');
        const box = nav.getBoundingClientRect();
        const links = [...nav.querySelectorAll('.nav-link')].map((a) => ({ view: a.dataset.view, r: a.getBoundingClientRect() }));
        const inside = (r) => r.top >= box.top && r.bottom <= box.bottom;
        const active = links.find((l) => l.view === document.documentElement.dataset.view);
        return {
          count: links.length,
          outside: links.filter((l) => !inside(l.r)).map((l) => l.view),
          room: Math.round(box.bottom - links[links.length - 1].r.bottom),
          linkHeight: Math.round(links[0].r.height),
          activeInside: !!active && inside(active.r),
          navScrolled: nav.scrollTop > 0,
          pageScrolled: window.scrollY > 0
        };
      });
      await page.setViewport({ width: 1366, height: 657 });
      try {
        await gotoRoute(page, 'about');
        const fit = await sidebar();
        assertEqual(fit.count, ROUTES.length, 'nav links');
        assertEqual(fit.outside, [], `every link inside the sidebar: ${JSON.stringify(fit)}`);
        assert(fit.room >= fit.linkHeight, `room for one more tool: ${JSON.stringify(fit)}`);
        assert(!fit.navScrolled, 'nothing to scroll');
        await shot(page, 'desktop-light-en-sidebar-1366x657');
        // Too short for every link: the sidebar (not the page) scrolls to the open tool, About the last one.
        await page.setViewport({ width: 1280, height: 480 });
        await gotoRoute(page, 'lookup');
        await gotoRoute(page, 'about');
        const short = await sidebar();
        assert(short.outside.length > 0, `some links below the fold at 480 px: ${JSON.stringify(short)}`);
        assert(short.activeInside && short.navScrolled && !short.pageScrolled, `the open tool's link in view: ${JSON.stringify(short)}`);
        // A link already in view: following it moves nothing.
        const before = await page.evaluate(() => {
          const nav = document.getElementById('app-nav');
          const link = nav.querySelector('.nav-link[data-view="inventory"]');
          const r = link.getBoundingClientRect();
          const box = nav.getBoundingClientRect();
          if (r.top < box.top || r.bottom > box.bottom) return null;
          const top = nav.scrollTop;
          link.click();
          return top;
        });
        assert(before !== null, 'the Servers link is in view');
        await page.waitFor(() => document.documentElement.dataset.view === 'inventory', { message: 'Servers opened from the sidebar' });
        assertEqual(await page.evaluate(() => document.getElementById('app-nav').scrollTop), before, 'the sidebar stays put');
      } finally {
        await page.setViewport({ width: 1440, height: 900 });
      }
    });

    await step('i18n: no missing keys, TR and EN key sets match', async () => {
      const info = await page.evaluate(async () => {
        const i = await import('./assets/js/i18n.js');
        const en = i.listKeys('en');
        const tr = new Set(i.listKeys('tr'));
        return { missing: i.getMissingKeys(), onlyEn: en.filter((k) => !tr.has(k)), onlyTr: [...tr].filter((k) => !en.includes(k)) };
      });
      assertEqual(info.missing, [], 'missing keys');
      assertEqual(info.onlyEn, [], 'keys only in EN');
      assertEqual(info.onlyTr, [], 'keys only in TR');
    });

    await step('desktop page: no console errors, exceptions, failed requests or CSP violations', async () => {
      await assertClean(page, 'desktop');
    });
    await page.close();

    /* ---------------- A long job while another view is open ---------------- */
    await jobsGroup(browser, server);

    /* ---------------- Mobile ---------------- */
    group('Phone 390×844 (Turkish)');
    const phone = await browser.newPage('about:blank', { width: 390, height: 844, mobile: true });
    await phone.emulateMedia({ 'prefers-color-scheme': 'light' });

    await step('boots on a phone and switches to Turkish', async () => {
      await phone.goto(`${server.url}#/scan`);
      await waitReady(phone);
      await setLangUi(phone, 'tr');
      assertEqual(await phone.evaluate(() => document.querySelector('h1.page-title').textContent), title('scan', 'tr'), 'TR h1');
    });

    for (const scheme of ['light', 'dark']) {
      await phone.emulateMedia({ 'prefers-color-scheme': scheme });
      for (const id of ROUTES) {
        await step(`[${scheme}] #/${id} fits 390 px`, async () => {
          await gotoRoute(phone, id);
          assertEqual(await phone.evaluate(() => document.querySelector('h1.page-title').textContent), title(id, 'tr'), 'page title');
          await assertNoHorizontalScroll(phone, id);
          await shot(phone, `mobile-${scheme}-tr-${id}`);
        });
      }
    }
    await phone.emulateMedia({ 'prefers-color-scheme': 'light' });

    await step('phone header: brand name not clipped, one-button theme cycle works', async () => {
      const brand = await phone.evaluate(() => {
        const el = document.querySelector('.brand-name');
        return { scroll: el.scrollWidth, client: el.clientWidth, cycleVisible: getComputedStyle(document.querySelector('.theme-cycle')).display !== 'none' };
      });
      assert(brand.scroll <= brand.client + 1, `brand name clipped (${brand.scroll} > ${brand.client})`);
      assert(brand.cycleVisible, 'theme cycle button visible on phones');
      await phone.click('[data-control="theme-cycle"]');
      await phone.waitFor(() => document.documentElement.dataset.theme === 'light');
      await phone.click('[data-control="theme-cycle"]');
      await phone.waitFor(() => document.documentElement.dataset.theme === 'dark');
      await shot(phone, 'mobile-forced-dark-tr-header');
      await phone.click('[data-control="theme-cycle"]');
      await phone.waitFor(() => !document.documentElement.dataset.theme);
    });

    await step('phone nav is a sticky bar: the Tools button and the current tool, no strip of three', async () => {
      await gotoRoute(phone, 'about');
      const info = await phone.evaluate(async () => {
        window.scrollTo(0, 900);
        await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
        const nav = document.getElementById('app-nav');
        const btn = nav.querySelector('[data-control="nav-menu"]').getBoundingClientRect();
        const footerBtn = document.querySelector('.app-footer [data-control="shortcuts"]');
        return {
          top: Math.round(nav.getBoundingClientRect().top),
          button: btn.width > 0 && btn.left >= 0 && btn.right <= window.innerWidth,
          buttonHeight: Math.round(btn.height),
          links: [...nav.querySelectorAll('.nav-link')].filter((a) => a.getClientRects().length).length,
          current: nav.querySelector('.nav-menu-current').textContent,
          touchOnly: matchMedia('(hover: none) and (pointer: coarse)').matches,
          footerShortcuts: !!footerBtn && footerBtn.getClientRects().length > 0
        };
      });
      assertEqual(info.top, 0, 'nav sticks to the top');
      assert(info.button, `Tools button in view: ${JSON.stringify(info)}`);
      assert(info.buttonHeight >= 44, `the Tools button is a full touch target: ${info.buttonHeight} px`);
      assertEqual(info.links, 0, 'no strip of links');
      assertEqual(info.current, title('about', 'tr'), 'current tool');
      // The footer's "Keyboard shortcuts" button: not on a touch-only device (no keyboard to use them with).
      assertEqual(info.footerShortcuts, !info.touchOnly, `footer shortcuts button (touch only: ${info.touchOnly})`);
      await phone.evaluate(() => window.scrollTo(0, 0));
    });

    await step('turned to 800 px: the Tools bar gives way to the sticky strip of links, scrolled to the active one', async () => {
      // Still on About, the strip's last link: in view only once the strip has scrolled.
      await phone.setViewport({ width: 800, height: 900 });
      try {
        await gotoRoute(phone, 'about');
        const info = await phone.evaluate(async () => {
          await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
          const nav = document.getElementById('app-nav');
          const link = nav.querySelector('.nav-link[aria-current="page"]').getBoundingClientRect();
          const box = nav.getBoundingClientRect();
          return {
            links: [...nav.querySelectorAll('.nav-link')].filter((a) => a.getClientRects().length).length,
            scrollable: nav.scrollWidth > nav.clientWidth,
            scrolled: nav.scrollLeft > 0,
            activeVisible: link.left >= box.left && link.right <= box.right,
            toolsBar: nav.querySelector('.nav-menu-bar').getClientRects().length > 0
          };
        });
        assert(info.links > 3 && info.scrollable && info.scrolled && info.activeVisible, `nav strip: ${JSON.stringify(info)}`);
        assert(!info.toolsBar, 'no Tools button above 720 px');
        await assertNoHorizontalScroll(phone, 'nav strip at 800 px');
      } finally {
        await phone.setViewport({ width: 390, height: 844, mobile: true });
      }
    });

    await step('phone gallery fits and looks right', async () => {
      await phone.evaluate(buildGallery);
      await assertNoHorizontalScroll(phone, 'gallery');
      await shot(phone, 'mobile-light-tr-gallery');
      await phone.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await shot(phone, 'mobile-dark-tr-gallery');
      await phone.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    await step('reduced motion: spinners slow down, indeterminate bars stop sliding', async () => {
      await phone.emulateMedia({ 'prefers-reduced-motion': 'reduce' });
      const anim = await phone.evaluate(() => getComputedStyle(document.querySelector('#gallery .progress.is-indeterminate .progress-fill')).animationName);
      assertEqual(anim, 'none', 'indeterminate animation');
      await phone.emulateMedia({});
    });

    await step('phone page: no console errors, exceptions, failed requests or CSP violations', async () => {
      await assertClean(phone, 'phone');
    });
    await phone.close();

    /* ---------------- First visit, the Tools menu and keyboard shortcuts ---------------- */
    group('Start page, Tools menu (375 px) and keyboard shortcuts');
    const sm = await browser.newPage('about:blank', { width: 375, height: 740, mobile: true });
    await sm.emulateMedia({ 'prefers-color-scheme': 'light' });
    const JOBS = ['subdomains', 'certificate', 'health', 'propagation', 'zone'];
    const pickerShown = (p) => p.evaluate(() => !!document.querySelector('[data-role="start-picker"]'));
    // DNS answers never arrive (offline suite): a run stays in progress until it is cancelled.
    const holdFetches = (p) => p.evaluate(() => {
      window.__realFetch = window.__realFetch || window.fetch;
      window.__heldFetches = 0;
      window.fetch = (input, init = {}) => new Promise((resolve, reject) => {
        window.__heldFetches += 1;
        const signal = init.signal || (input && input.signal);
        if (signal) signal.addEventListener('abort', () => reject(signal.reason || new DOMException('Aborted', 'AbortError')), { once: true });
      });
    });
    const releaseFetches = (p) => p.evaluate(() => {
      if (window.__realFetch) window.fetch = window.__realFetch;
    });
    /**
     * A Ctrl+click on `sel` (a synthetic one: no new tab opens). Returns whether the app took it
     * (called preventDefault); a window listener then cancels what the browser would do.
     */
    const ctrlClick = (p, sel) => p.evaluate((q) => {
      let taken = null;
      const after = (event) => {
        taken = event.defaultPrevented;
        event.preventDefault();
      };
      window.addEventListener('click', after, { once: true });
      document.querySelector(q).dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, ctrlKey: true, button: 0 }));
      window.removeEventListener('click', after);
      return taken;
    }, sel);
    const pause = (p, ms = 300) => p.evaluate((t) => new Promise((r) => setTimeout(r, t)), ms);
    /** A first-time visitor: nothing stored but the language. */
    const firstVisit = async (p, lang = 'en') => {
      await p.evaluate((l) => {
        localStorage.clear();
        localStorage.setItem('ssds.settings', JSON.stringify({ v: 2, lang: l }));
        window.location.hash = '#/subdomains';
      }, lang);
      await p.reload();
      await waitReady(p);
    };

    await step('a first visit shows the task picker above Subdomains; each job links to its tool', async () => {
      await sm.goto(server.url);
      await waitReady(sm);
      await firstVisit(sm);
      const info = await sm.evaluate(() => {
        const picker = document.querySelector('[data-role="start-picker"]');
        if (!picker) return null;
        return {
          above: !!(picker.compareDocumentPosition(document.querySelector('.page-header')) & Node.DOCUMENT_POSITION_FOLLOWING),
          label: document.getElementById(picker.getAttribute('aria-labelledby'))?.textContent,
          jobs: [...picker.querySelectorAll('.start-task')].map((a) => [a.dataset.task, a.getAttribute('href')]),
          hide: picker.querySelector('[data-action="start-hide"]')?.getAttribute('aria-label')
        };
      });
      assert(info, 'picker shown');
      assert(info.above, 'above the Subdomains page header');
      assertEqual(info.label, 'New here? Pick a job to start with', 'region label');
      assertEqual(info.jobs, [['subdomains', '#/subdomains'], ['certificate', '#/scan'], ['health', '#/health'], ['propagation', '#/global'], ['zone', '#/zone']], 'jobs');
      assertEqual(info.hide, 'Hide these suggestions', 'dismiss button label');
      // Short chips in two columns (the job alone; the tool's name read out, not shown), so the tool's own
      // field still starts on the first screen.
      const chips = await sm.evaluate(() => {
        const cards = [...document.querySelectorAll('.start-picker .start-task')];
        return {
          columns: new Set(cards.map((a) => Math.round(a.getBoundingClientRect().left))).size,
          toolShown: cards.some((a) => a.querySelector('.start-task-tool').getBoundingClientRect().width > 1),
          toolNames: cards.map((a) => a.textContent).join(' | '),
          fieldTop: Math.round(document.querySelector('[data-role="sub-domain"]').getBoundingClientRect().top),
          screen: window.innerHeight
        };
      });
      assertEqual(chips.columns, 2, 'two columns of chips');
      assert(!chips.toolShown && chips.toolNames.includes('SSL Targets'), `each chip names its tool for screen readers only: ${chips.toolNames}`);
      assert(chips.fieldTop < chips.screen, `the domain field starts on the first screen: ${chips.fieldTop} of ${chips.screen} px`);
      await assertNoHorizontalScroll(sm, 'start picker');
      await shot(sm, 'mobile-light-en-start-picker');
      await sm.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await shot(sm, 'mobile-dark-en-start-picker');
      await sm.emulateMedia({ 'prefers-color-scheme': 'light' });
      // The smallest phones (320 × 568): still two columns, the chips without icons, so the page's own title stays in view.
      await sm.setViewport({ width: 320, height: 568, mobile: true });
      try {
        const small = await sm.evaluate(() => {
          const cards = [...document.querySelectorAll('.start-picker .start-task')];
          return {
            columns: new Set(cards.map((a) => Math.round(a.getBoundingClientRect().left))).size,
            icons: cards.some((a) => a.querySelector('.start-task-icon').getClientRects().length > 0),
            titleBottom: Math.round(document.getElementById('page-title').getBoundingClientRect().bottom),
            screen: window.innerHeight
          };
        });
        assert(small.columns === 2 && !small.icons, `320 px chips: ${JSON.stringify(small)}`);
        assert(small.titleBottom < small.screen, `the page title is on the first screen at 320 × 568: ${small.titleBottom} px`);
        await assertNoHorizontalScroll(sm, 'start picker at 320 px');
        await shot(sm, 'mobile-light-en-start-picker-320');
      } finally {
        await sm.setViewport({ width: 375, height: 740, mobile: true });
      }
    });

    await step('the start page\'s own job focuses its input; another job opens its tool', async () => {
      // A Ctrl+click (a new tab) is the browser's: the page keeps its focus.
      await sm.evaluate(() => document.getElementById('page-title').focus());
      assertEqual(await ctrlClick(sm, '.start-task[data-task="subdomains"]'), false, 'the app leaves a Ctrl+click alone');
      assertEqual(await sm.evaluate(() => document.activeElement?.id), 'page-title', 'no jump to the input on a Ctrl+click');
      await sm.click('.start-task[data-task="subdomains"]');
      await sm.waitFor(() => document.activeElement?.dataset.role === 'sub-domain', { message: 'domain field focused' });
      assertEqual(await sm.evaluate(() => document.documentElement.dataset.view), 'subdomains', 'still on Subdomains');
      await sm.click('.start-task[data-task="zone"]');
      await sm.waitFor(() => document.documentElement.dataset.view === 'zone', { message: 'Zone File opened' });
      await gotoRoute(sm, 'subdomains');
      assert(await pickerShown(sm), 'still offered: nothing was run');
    });

    await step('dismissing hides it for good (persisted); About › Where to start still lists the jobs', async () => {
      await sm.click('[data-action="start-hide"]');
      await sm.waitFor(() => !document.querySelector('[data-role="start-picker"]'));
      assertEqual(await sm.evaluate(() => document.activeElement?.id), 'page-title', 'focus moves to the page title');
      assertEqual(await sm.evaluate(() => JSON.parse(localStorage.getItem('ssds.settings')).startTasks), false, 'stored');
      assert(await sm.evaluate(() => [...document.querySelectorAll('.toast')].some((x) => x.textContent.includes('About › Where to start'))),
        'the toast says where to find the jobs again');
      await dismissToasts(sm);
      await sm.reload();
      await waitReady(sm);
      assert(!await pickerShown(sm), 'still hidden after a reload');
      await gotoRoute(sm, 'about');
      const about = await sm.evaluate(() => ({
        title: document.querySelector('#about-start .section-title')?.textContent,
        jobs: [...document.querySelectorAll('#about-start .start-task')].map((a) => a.dataset.task)
      }));
      assertEqual(about.title, 'Where to start', 'About section');
      assertEqual(about.jobs, JOBS, 'About lists every job');
      await sm.click('#about-start .start-task[data-task="certificate"]');
      await sm.waitFor(() => document.documentElement.dataset.view === 'scan', { message: 'SSL Targets opened from About' });
    });

    await step('running something ends the first visit; so does data from an earlier visit', async () => {
      const stored = () => sm.evaluate(() => JSON.parse(localStorage.getItem('ssds.settings') || '{}').startTasks);
      await firstVisit(sm);
      assert(await pickerShown(sm), 'offered again after the data was deleted');
      // The main signal: a tool at work (Bulk Resolve started with Ctrl+Enter, its answers held back).
      await gotoRoute(sm, 'bulk');
      assertEqual(await stored(), undefined, 'nothing run yet');
      await holdFetches(sm);
      await sm.type('[data-role="bulk-input"]', 'www.example.com');
      await sm.press('Enter', { ctrl: true });
      await sm.waitFor(() => document.getElementById('app-header').classList.contains('is-busy') && window.__heldFetches > 0,
        { message: 'Bulk Resolve at work' });
      await sm.waitFor(() => JSON.parse(localStorage.getItem('ssds.settings')).startTasks === false, { message: 'a run ends the first visit (stored)' });
      await sm.evaluate(() => document.querySelector('[data-action="bulk-cancel"]').click());
      await sm.waitFor(() => !document.getElementById('app-header').classList.contains('is-busy'), { message: 'run stopped' });
      await releaseFetches(sm);
      await gotoRoute(sm, 'subdomains');
      assert(!await pickerShown(sm), 'no picker after a run');
      // An imported zone file (a sample: nothing is sent, the view never goes busy).
      await firstVisit(sm);
      await gotoRoute(sm, 'zone');
      await sm.click('[data-sample="cloudflare"]');
      await sm.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'sample imported' });
      await sm.waitFor(() => JSON.parse(localStorage.getItem('ssds.settings')).startTasks === false, { message: 'an imported zone ends the first visit' });
      // Saved servers.
      await firstVisit(sm);
      await gotoRoute(sm, 'inventory');
      await sm.type('[data-role="inventory-text"]', 'web01 192.0.2.10');
      await sm.press('Enter', { ctrl: true }); // the shared shortcut: Ctrl+Enter clicks Save
      await sm.waitFor(() => (JSON.parse(localStorage.getItem('ssds.inventory') || 'null') || {}).text === 'web01 192.0.2.10',
        { message: 'saved with Ctrl+Enter, no new line typed' });
      await gotoRoute(sm, 'subdomains');
      assert(!await pickerShown(sm), 'saved servers count as a run');
      // Remembered options alone (a switch flipped on the start page) are no run; learned names are.
      await firstVisit(sm);
      await sm.evaluate(() => localStorage.setItem('ssds.subdomains.options', '{}'));
      await sm.reload();
      await waitReady(sm);
      assert(await pickerShown(sm), 'remembered view options are no run');
      await sm.evaluate(() => localStorage.setItem('ssds.learned.labels', JSON.stringify({ v: 1, seq: 1, labels: { api: { hits: 1, last: 1 } } })));
      await sm.reload();
      await waitReady(sm);
      assert(!await pickerShown(sm), 'a browser that ran a scan before (learned names)');
      await firstVisit(sm, 'tr');
      assert(await pickerShown(sm), 'offered in Turkish too');
      assertEqual(await sm.evaluate(() => document.querySelector('.start-picker-title').textContent), 'İlk kez mi geliyorsunuz? Başlamak için bir iş seçin', 'TR title');
      await assertNoHorizontalScroll(sm, 'start picker (TR)');
      await shot(sm, 'mobile-light-tr-start-picker');
    });

    await step('375 px: the Tools menu lists every tool by group, marks the current one; Esc closes it, focus returns', async () => {
      await setLangUi(sm, 'en');
      await gotoRoute(sm, 'lookup');
      const bar = await sm.evaluate(() => {
        const btn = document.querySelector('[data-control="nav-menu"]');
        return { expanded: btn.getAttribute('aria-expanded'), popup: btn.getAttribute('aria-haspopup'), name: btn.textContent.trim() };
      });
      assertEqual(bar, { expanded: 'false', popup: 'dialog', name: 'Tools' }, 'Tools button');
      await sm.click('[data-control="nav-menu"]');
      await sm.waitFor(() => document.querySelector('dialog.navmenu-modal[open]'), { message: 'menu open' });
      const menu = await sm.evaluate(() => {
        const d = document.querySelector('dialog.navmenu-modal');
        return {
          modal: d.matches(':modal'),
          title: document.getElementById(d.getAttribute('aria-labelledby'))?.textContent,
          groups: [...d.querySelectorAll('.navmenu-group')].map((g) => [g.querySelector('.navmenu-label').textContent,
            [...g.querySelectorAll('.navmenu-link')].map((a) => a.dataset.view)]),
          current: [...d.querySelectorAll('.navmenu-link[aria-current="page"]')].map((a) => a.dataset.view),
          focused: document.activeElement?.dataset.view,
          expanded: document.querySelector('[data-control="nav-menu"]').getAttribute('aria-expanded'),
          fits: d.getBoundingClientRect().right <= window.innerWidth && d.getBoundingClientRect().left >= 0
        };
      });
      assert(menu.modal, 'a modal dialog (focus trap, the page inert)');
      assertEqual(menu.title, 'Tools', 'dialog title');
      assertEqual(menu.groups, [
        ['Discover', ['subdomains', 'zone']], ['Certificates', ['scan', 'cert']], ['DNS tools', ['global', 'lookup', 'bulk']],
        ['IP addresses', ['ip', 'ptr']], ['Mail & domain', ['health']], ['Workspace', ['inventory', 'about']]
      ], 'groups');
      assertEqual(menu.current, ['lookup'], 'current tool marked');
      assertEqual(menu.focused, 'lookup', 'focus starts on the current tool');
      assertEqual(menu.expanded, 'true', 'aria-expanded while open');
      assert(menu.fits, 'menu fits 375 px');
      await assertNoHorizontalScroll(sm, 'Tools menu');
      await shot(sm, 'mobile-light-en-tools-menu');
      await sm.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await shot(sm, 'mobile-dark-en-tools-menu');
      await sm.emulateMedia({ 'prefers-color-scheme': 'light' });
      for (let i = 0; i < 4; i += 1) await sm.press('Tab');
      assert(await sm.evaluate(() => !!document.activeElement?.closest('dialog.navmenu-modal')), 'Tab stays in the menu');
      await sm.press('Escape');
      await sm.waitFor(() => !document.querySelector('dialog.navmenu-modal'), { message: 'menu closed' });
      await sm.waitFor(() => document.activeElement?.dataset.control === 'nav-menu', { message: 'focus back on the Tools button' });
      assertEqual(await sm.evaluate(() => document.querySelector('[data-control="nav-menu"]').getAttribute('aria-expanded')), 'false', 'collapsed');
      assertEqual(await sm.evaluate(() => document.documentElement.dataset.view), 'lookup', 'no navigation');
    });

    await step('375 px: a tool picked in the menu opens and its title takes the focus', async () => {
      await sm.click('[data-control="nav-menu"]');
      await sm.waitFor(() => document.querySelector('dialog.navmenu-modal[open]'));
      await sm.click('.navmenu-link[data-view="health"]');
      await sm.waitFor(() => document.documentElement.dataset.view === 'health' && !document.querySelector('dialog.navmenu-modal'),
        { message: 'Domain Health opened, menu closed' });
      await sm.waitFor(() => document.activeElement?.id === 'page-title', { message: 'focus on the new page title' });
      assertEqual(await sm.evaluate(() => document.querySelector('.nav-menu-current').textContent), 'Domain Health', 'current tool in the bar');
      // The open tool's own entry only closes the menu: the route (and its params) stays.
      await sm.evaluate(() => window.history.replaceState(null, '', '#/health?keep=1'));
      await sm.click('[data-control="nav-menu"]');
      await sm.waitFor(() => document.querySelector('dialog.navmenu-modal[open]'));
      await sm.click('.navmenu-link[data-view="health"]');
      await sm.waitFor(() => !document.querySelector('dialog.navmenu-modal') && document.activeElement?.dataset.control === 'nav-menu',
        { message: 'closed, focus back on the button' });
      assertEqual(await sm.evaluate(() => window.location.hash), '#/health?keep=1', 'route kept');
    });

    await step('375 px: the running tool pulses in the Tools menu; a Ctrl+click is the browser\'s; turned past 720 px the menu closes', async () => {
      await gotoRoute(sm, 'bulk');
      await holdFetches(sm);
      await sm.type('[data-role="bulk-input"]', 'www.example.com');
      await sm.click('[data-action="bulk-run"]');
      await sm.waitFor(() => document.getElementById('app-header').classList.contains('is-busy') && window.__heldFetches > 0, { message: 'running' });
      await sm.click('[data-control="nav-menu"]');
      await sm.waitFor(() => document.querySelector('dialog.navmenu-modal[open]'), { message: 'menu open' });
      const dots = await sm.evaluate(() => [...document.querySelectorAll('.navmenu-link')].filter((a) => a.classList.contains('is-busy')
        && getComputedStyle(a, '::after').content !== 'none' && getComputedStyle(a, '::after').width === '7px').map((a) => a.dataset.view));
      assertEqual(dots, ['bulk'], 'the busy dot on the running tool only');
      await shot(sm, 'mobile-light-en-tools-menu-busy');
      assertEqual(await ctrlClick(sm, '.navmenu-link[data-view="lookup"]'), false, 'the app leaves a Ctrl+click alone');
      assert(await sm.evaluate(() => !!document.querySelector('dialog.navmenu-modal[open]') && document.documentElement.dataset.view === 'bulk'),
        'the menu stays open, no navigation');
      await sm.setViewport({ width: 800, height: 740, mobile: true });
      try {
        await sm.waitFor(() => !document.querySelector('dialog.navmenu-modal'), { message: 'the menu closes past 720 px' });
        const after = await sm.evaluate(() => ({
          focus: document.activeElement?.id,
          expanded: document.querySelector('[data-control="nav-menu"]').getAttribute('aria-expanded')
        }));
        assertEqual(after, { focus: 'page-title', expanded: 'false' }, 'the focus goes to the page title');
      } finally {
        await sm.setViewport({ width: 375, height: 740, mobile: true });
      }
      await sm.press('Escape');
      await sm.waitFor(() => !document.getElementById('app-header').classList.contains('is-busy'), { message: 'cancelled with Esc' });
      await sm.click('[data-control="nav-menu"]');
      await sm.waitFor(() => document.querySelector('dialog.navmenu-modal[open]'));
      assertEqual(await sm.evaluate(() => document.querySelectorAll('.navmenu-link.is-busy').length), 0, 'no dot once it stopped');
      await sm.press('Escape');
      await sm.waitFor(() => !document.querySelector('dialog.navmenu-modal'));
      await releaseFetches(sm);
    });

    await step('start page and menu: no console errors, exceptions, failed requests or CSP violations', async () => {
      await assertClean(sm, 'start page / menu');
    });
    await sm.close();

    const kb = await browser.newPage('about:blank', { width: 1280, height: 800 });
    await kb.emulateMedia({ 'prefers-color-scheme': 'light' });
    const active = () => kb.evaluate(() => {
      const a = document.activeElement;
      return a ? (a.dataset.role || a.dataset.control || a.id || a.tagName.toLowerCase()) : null;
    });

    await step("'?' opens the shortcut list (also from the footer); Esc closes it and the focus returns", async () => {
      await kb.goto(`${server.url}#/lookup`);
      await waitReady(kb);
      await kb.evaluate(() => document.getElementById('page-title').focus());
      await kb.press('?', { shift: true });
      await kb.waitFor(() => document.querySelector('dialog.keys-modal[open]'), { message: 'shortcut list open' });
      const rows = await kb.evaluate(() => [...document.querySelectorAll('.keys-table tr')].map((tr) => [tr.dataset.key,
        [...tr.querySelectorAll('kbd')].map((k) => k.textContent).join('+')]));
      assertEqual(rows, [['submit', 'Ctrl+Enter'], ['cancel', 'Esc'], ['focus', '/'], ['help', '?']], 'shortcuts listed');
      await shot(kb, 'desktop-light-en-shortcuts');
      await kb.press('Escape');
      await kb.waitFor(() => !document.querySelector('dialog.keys-modal'), { message: 'closed' });
      assertEqual(await active(), 'page-title', 'focus back where it was');
      assertEqual(await kb.evaluate(() => document.querySelector('[data-control="shortcuts"]').getAttribute('aria-haspopup')), 'dialog',
        'the footer button says it opens a dialog');
      await kb.click('[data-control="shortcuts"]');
      await kb.waitFor(() => document.querySelector('dialog.keys-modal[open]'), { message: 'opened from the footer' });
      await kb.press('Escape');
      await kb.waitFor(() => !document.querySelector('dialog.keys-modal'));
      assertEqual(await active(), 'shortcuts', 'focus back on the footer button');
    });

    await step("'/' jumps to the view's main input; inside a field '/' and '?' are typed as usual", async () => {
      await kb.evaluate(() => document.getElementById('page-title').focus());
      await kb.press('/');
      assertEqual(await active(), 'lookup-name', 'DNS Lookup: the name field');
      await kb.press('/');
      await kb.press('?', { shift: true });
      assertEqual(await kb.evaluate(() => document.querySelector('[data-role="lookup-name"]').value), '/?', 'typed into the field');
      assert(!await kb.evaluate(() => !!document.querySelector('dialog[open]')), 'no dialog while typing');
      await kb.type('[data-role="lookup-name"]', '');
      for (const [view, want] of [['inventory', 'inventory-text'], ['bulk', 'bulk-input'], ['ip', 'ip-input'], ['subdomains', 'sub-domain']]) {
        await gotoRoute(kb, view);
        await kb.evaluate(() => document.getElementById('page-title').focus());
        await kb.press('/');
        assertEqual(await active(), want, `${view}: main input`);
      }
      await gotoRoute(kb, 'zone');
      await kb.evaluate(() => document.getElementById('page-title').focus());
      await kb.press('/');
      assert(await kb.evaluate(() => document.activeElement?.classList.contains('filedrop')), 'Zone File: the drop zone');
      await gotoRoute(kb, 'about');
      await kb.evaluate(() => document.getElementById('page-title').focus());
      await kb.press('/');
      assertEqual(await active(), 'page-title', 'About has no input: the focus stays');
    });

    await step('SSL Targets: Ctrl+Enter in the domains starts the scan (not the paste box\'s Read); in the paste box it reads', async () => {
      await gotoRoute(kb, 'scan');
      await kb.click('.scan-step-cert [data-action="cert-sample"]');
      await kb.waitFor(() => document.querySelector('[data-role="scan-domains"]')?.value === 'example.com\nexample.net',
        { message: 'the sample certificate filled the domains' });
      await holdFetches(kb);
      // The paste box of "Load another certificate" is a form of its own: Ctrl+Enter there reads it, and starts no scan.
      await kb.evaluate(() => {
        const another = document.querySelector('.scan-cert-another');
        another.open = true;
        another.querySelector('.cert-paste').open = true;
      });
      await kb.type('.scan-cert-another [data-role="cert-paste"]', '');
      await kb.press('Enter', { ctrl: true });
      await kb.waitFor(() => /Paste a PEM block first/.test(document.querySelector('.scan-cert-another .cert-paste')?.textContent || ''),
        { message: 'Read answered the paste box' });
      assert(await kb.evaluate(() => !document.querySelector('.scan-run-ui') && window.__heldFetches === 0), 'no scan from the paste box');
      await kb.evaluate(() => { document.querySelector('.scan-cert-another').open = false; });
      // Closed again (as it normally is), the paste box's Read is no candidate: the domains field runs the scan.
      await kb.evaluate(() => document.querySelector('[data-role="scan-domains"]').focus());
      await kb.press('Enter', { ctrl: true });
      await kb.waitFor(() => {
        const cancel = document.querySelector('[data-action="scan-cancel"]');
        return document.querySelector('.scan-run')?.dataset.status === 'running' && cancel && !cancel.hidden && window.__heldFetches > 0;
      }, { message: 'the scan started from the domains field' });
      assertEqual(await kb.evaluate(() => document.querySelector('[data-role="scan-domains"]').value), 'example.com\nexample.net', 'no new line typed');
      await kb.press('Escape');
      await kb.waitFor(() => document.querySelector('.scan-run')?.dataset.status === 'cancelled'
        && !document.getElementById('app-header').classList.contains('is-busy'), { message: 'cancelled with Esc' });
      // A field of the results (a table's filter, an option) is no part of the form: Ctrl+Enter there starts no new scan.
      const held = await kb.evaluate(() => window.__heldFetches);
      const fields = await kb.evaluate(() => [...document.querySelectorAll('.scan-results-host input, .scan-results-host select')]
        .filter((el) => el.checkVisibility({ visibilityProperty: true }) && !el.disabled).map((el, i) => {
          el.dataset.testField = String(i);
          return i;
        }));
      assert(fields.length > 0, 'the cancelled run shows fields of its own');
      for (const i of fields) {
        // A field gone from the page: a new scan replaced the results (the check below says so).
        const there = await kb.evaluate((n) => {
          const el = document.querySelector(`[data-test-field="${n}"]`);
          if (el) el.focus();
          return !!el;
        }, i);
        if (!there) break;
        await kb.press('Enter', { ctrl: true });
      }
      await pause(kb);
      const after = await kb.evaluate(() => ({
        status: document.querySelector('.scan-run')?.dataset.status,
        busy: document.getElementById('app-header').classList.contains('is-busy'),
        fetches: window.__heldFetches
      }));
      assertEqual(after, { status: 'cancelled', busy: false, fetches: held }, `no new scan from ${fields.length} result fields`);
      await releaseFetches(kb);
    });

    await step('Ctrl+Enter runs the tool from its field; Esc cancels the running job (Bulk Resolve, answers held back)', async () => {
      await gotoRoute(kb, 'bulk');
      await holdFetches(kb);
      const text = 'www.example.com\napi.example.com';
      await kb.type('[data-role="bulk-input"]', text);
      await kb.press('Enter', { ctrl: true });
      await kb.waitFor(() => {
        const cancel = document.querySelector('[data-action="bulk-cancel"]');
        return cancel && !cancel.hidden && window.__heldFetches > 0;
      }, { message: 'the run started from the textarea' });
      assertEqual(await kb.evaluate(() => document.querySelector('[data-role="bulk-input"]').value), text, 'no new line typed');
      assert(await kb.evaluate(() => document.getElementById('app-header').classList.contains('is-busy')), 'busy');
      await kb.press('Enter', { ctrl: true }); // while it runs: nothing (Run is hidden, no other button stands in)
      // Esc in the results filter with text clears the filter (the browser's own Esc there) and leaves the run alone.
      const filter = await kb.waitFor(() => {
        const el = [...document.querySelectorAll('#page-body input[type="search"]')].find((x) => x.getClientRects().length);
        if (!el) return false;
        el.dataset.testFilter = '1';
        return '[data-test-filter="1"]';
      }, { message: 'the results filter is shown while the run goes on' });
      await kb.type(filter, 'www');
      await kb.press('Escape');
      await kb.waitFor((sel) => document.querySelector(sel).value === '', { args: [filter], message: 'the filter cleared' });
      assert(await kb.evaluate(() => !document.querySelector('[data-action="bulk-cancel"]').hidden
        && document.getElementById('app-header').classList.contains('is-busy')), 'the run goes on');
      // The app clears it, not only the browser (Firefox leaves a search field alone on Esc): a synthetic
      // Esc has no default action, yet the filter empties and the table follows.
      await kb.type(filter, 'www');
      const cleared = await kb.evaluate((sel) => {
        const el = document.querySelector(sel);
        let heard = false;
        el.addEventListener('input', () => { heard = true; }, { once: true });
        const taken = !el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
        return { value: el.value, taken, heard };
      }, filter);
      assertEqual(cleared, { value: '', taken: true, heard: true }, 'Esc empties the filter in every browser');
      assert(await kb.evaluate(() => !document.querySelector('[data-action="bulk-cancel"]').hidden), 'the run still goes on');
      // In the emptied filter, the next Esc cancels.
      await kb.press('Escape');
      await kb.waitFor(() => {
        const run = document.querySelector('[data-action="bulk-run"]');
        return run && !run.hidden && document.querySelector('[data-action="bulk-cancel"]').hidden
          && !document.getElementById('app-header').classList.contains('is-busy');
      }, { message: 'cancelled with Esc' });
      assert(await kb.evaluate(() => document.getElementById('page-body').textContent.includes('Cancelled')), 'the run says it was cancelled');
      // The results filter is no part of the form: Ctrl+Enter there starts no new run (it once did, as the view's Run).
      const held = await kb.evaluate(() => {
        const el = [...document.querySelectorAll('.bulk-results-host input[type="search"]')].find((x) => x.checkVisibility());
        el.dataset.testFilter = '2';
        return window.__heldFetches;
      });
      await kb.type('[data-test-filter="2"]', 'api');
      await kb.press('Enter', { ctrl: true });
      await pause(kb);
      const after = await kb.evaluate(() => ({
        running: !document.querySelector('[data-action="bulk-cancel"]').hidden,
        busy: document.getElementById('app-header').classList.contains('is-busy'),
        fetches: window.__heldFetches
      }));
      assertEqual(after, { running: false, busy: false, fetches: held }, 'Ctrl+Enter in the results filter starts nothing');
      // The form's own field still runs it.
      await kb.evaluate(() => document.querySelector('[data-role="bulk-input"]').focus());
      await kb.press('Enter', { ctrl: true });
      await kb.waitFor(() => !document.querySelector('[data-action="bulk-cancel"]').hidden, { message: 'a new run from the textarea' });
      await kb.evaluate(() => document.querySelector('[data-action="bulk-cancel"]').click());
      await kb.waitFor(() => !document.getElementById('app-header').classList.contains('is-busy'), { message: 'stopped again' });
      // Esc with nothing running does nothing (and never navigates).
      await kb.press('Escape');
      assertEqual(await kb.evaluate(() => document.documentElement.dataset.view), 'bulk', 'still on Bulk Resolve');
    });

    await step('Zone File: Ctrl+Enter imports from the importer\'s fields, runs the live check from its options, nothing from a table; Esc stops the check from another tab', async () => {
      await releaseFetches(kb);
      await gotoRoute(kb, 'zone');
      await kb.evaluate(() => { document.querySelector('.zone-paste').open = true; });
      await kb.type('[data-role="zone-paste"]', [
        '$ORIGIN example.com.',
        '@ 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600',
        '@ 3600 IN NS ns1.example.com.',
        'www 300 IN A 192.0.2.10',
        'api 300 IN A 192.0.2.11'
      ].join('\n'));
      // The format is an option of the import: Ctrl+Enter there imports the pasted zone.
      await kb.evaluate(() => document.querySelector('.zone-format-field select').focus());
      await kb.press('Enter', { ctrl: true });
      await kb.waitFor(() => !!document.querySelector('.zone-summary') && document.querySelector('.zone-tabs'), { message: 'imported from the format field' });
      // A table's filter in the analysis submits nothing (the zone stays, nothing is sent).
      await kb.click('.zone-tabs .tab[data-tab="records"]');
      await kb.waitForSelector('.zone-records .dt-search-input');
      await holdFetches(kb);
      await kb.type('.zone-records .dt-search-input', 'www');
      await kb.press('Enter', { ctrl: true });
      await pause(kb);
      assertEqual(await kb.evaluate(() => window.__heldFetches), 0, 'nothing sent from the records filter');
      // An option of the live check starts it; Esc stops it.
      await kb.click('.zone-tabs .tab[data-tab="live"]');
      await kb.waitFor(() => !!document.querySelector('[data-role="zone-live-skip"]'), { message: 'live check shown' });
      await kb.evaluate(() => document.querySelector('[data-role="zone-live-skip"]').focus());
      await kb.press('Enter', { ctrl: true });
      await kb.waitFor(() => !!document.querySelector('[data-action="zone-live-cancel"]') && window.__heldFetches > 0,
        { message: 'the live check started from its option' });
      // Its Stop button in a closed tab still answers Esc: the check runs on while another tab is read.
      await kb.click('.zone-tabs .tab[data-tab="records"]');
      assert(await kb.evaluate(() => !document.querySelector('[data-action="zone-live-cancel"]').checkVisibility()), 'Stop out of sight');
      await kb.press('Escape');
      await kb.waitFor(() => !document.querySelector('[data-action="zone-live-cancel"]')
        && /Stopped/.test(document.querySelector('.zone-live')?.textContent || ''), { message: 'stopped with Esc from the Records tab' });
      assertEqual(await kb.evaluate(() => document.querySelector('.zone-tabs .tab[aria-selected="true"]').dataset.tab), 'records', 'the open tab stays');
      await releaseFetches(kb);
    });

    await step('shortcuts: no console errors, exceptions, failed requests or CSP violations', async () => {
      await assertClean(kb, 'shortcuts');
    });
    await kb.close();

    /* ---------------- The Pages bundle, and a deploy while a tab is open ---------------- */
    group('Pages bundle (tools/assemble-site.mjs)');
    const site = path.join(tmpDir, 'site');
    await assembleSite({ out: site, version: 'e2e-one' });
    const pages = await startServer({ root: site, base: BASE });
    const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
    // These steps are about a page no service worker answers for — the first visit, a browser or
    // private window without one — so this tab has none (the installable app has its own group).
    await tab.send('Page.addScriptToEvaluateOnNewDocument', {
      source: "Object.defineProperty(Navigator.prototype, 'serviceWorker', { get: () => undefined, configurable: true });"
    });
    const moduleSrc = () => tab.evaluate(() => document.querySelector('script[type="module"]').getAttribute('src'));
    try {
      await step('boots from v/<version>/assets/; About links reach the licences, the CLI and its source on GitHub', async () => {
        await tab.goto(`${pages.url}#/about`);
        await waitReady(tab);
        assertEqual(await moduleSrc(), 'v/e2e-one/assets/js/app.js', 'module script');
        const links = await tab.evaluate(() => ({
          licences: document.querySelector('a[href$="/THIRD_PARTY_LICENSES.txt"]')?.href,
          downloads: [...document.querySelectorAll('a[download="ssl_origin_scan.py"]')].map((a) => a.href),
          source: [...document.querySelectorAll('#about-cli a.btn')].find((a) => !a.hasAttribute('download'))?.href
        }));
        assertEqual(links.licences, `${pages.url}v/e2e-one/assets/data/THIRD_PARTY_LICENSES.txt`, 'licences link');
        assert(links.downloads.length === 2 && links.downloads.every((u) => u === `${pages.url}cli/ssl_origin_scan.py`), `downloads: ${links.downloads}`);
        // GitHub Pages serves .py as application/octet-stream: the site's copy would download, not show
        assertEqual(links.source, `${REPO_URL}/blob/main/cli/ssl_origin_scan.py`, 'View source');
        for (const url of [links.licences, links.downloads[0]]) {
          assertEqual(await tab.evaluate(async (u) => (await fetch(u, { method: 'HEAD' })).status, url), 200, url);
        }
        await gotoRoute(tab, 'subdomains');
        await assertClean(tab, 'bundle');
      });

      // Offline, or with the view's file unreachable while app.js still answers, the failed import
      // looks exactly like a deploy's; the shell must keep the network error and its Retry, never
      // claim an update or push a reload (offline it would lose everything held in memory).
      const failedView = async (id) => {
        await tab.evaluate((view) => { window.location.hash = `#/${view}`; }, id);
        await tab.waitFor(() => !!document.querySelector('#page-body > .alert'), { message: `${id}: load failure shown` });
        // the probe (if any) has answered: its HEAD request is done, then give its .then a frame
        await tab.waitFor(() => !navigator.onLine || performance.getEntriesByType('resource')
          .some((e) => e.initiatorType === 'fetch' && e.name.endsWith('/assets/js/app.js')), { message: `${id}: probe` });
        await tab.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
        setNodeLang('en');
        const banner = await tab.evaluate(() => ({
          text: document.querySelector('#page-body > .alert').textContent,
          reload: !!document.querySelector('[data-action="reload-page"]'),
          toast: document.querySelector('.toast')?.textContent || '',
          buttons: [...document.querySelectorAll('#page-body > .alert button')].map((b) => b.textContent.trim())
        }));
        assert(!banner.reload && !banner.text.includes(translate('shell.viewOutdated')), `${id}: claims an update: ${banner.text}`);
        assert(!banner.toast.includes(translate('shell.viewOutdated')), `${id}: update toast: ${banner.toast}`);
        assert(banner.text.includes(translate('error.kind.network')), `${id}: not the network error: ${banner.text}`);
        assertEqual(banner.buttons.join('|'), translate('common.retry'), `${id}: actions`);
        // the rest of the app keeps working
        await tab.resetProblems(); // the failed import is logged on purpose
        await gotoRoute(tab, 'about');
        await assertClean(tab, `after ${id}`, { offline: await tab.evaluate(() => !navigator.onLine) });
      };

      await step('offline, a view that fails to load shows the network error and Retry, not "updated"', async () => {
        const conditions = (offline) => tab.send('Network.emulateNetworkConditions', { offline, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
        await tab.send('Network.enable');
        await conditions(true);
        try {
          await failedView('health');
        } finally {
          await conditions(false);
        }
      });

      await step('online with only the view file unreachable (app.js still served), the same: no update claimed', async () => {
        await tab.send('Network.setBlockedURLs', { urls: ['*/views/bulk.js'] });
        try {
          await failedView('bulk');
        } finally {
          await tab.send('Network.setBlockedURLs', { urls: [] });
          await tab.send('Network.disable');
        }
      });

      await step('a view first opened after a deploy offers a page reload, which loads the new version', async () => {
        await assembleSite({ out: site, version: 'e2e-two' }); // the next deploy: v/e2e-one/ is gone
        await tab.evaluate(() => { window.location.hash = '#/ip'; });
        await tab.waitFor(() => !!document.querySelector('#page-body [data-action="reload-page"]'), { message: 'reload offered' });
        setNodeLang('en');
        const text = await tab.evaluate(() => document.querySelector('#page-body .alert').textContent);
        assert(text.includes(translate('shell.viewOutdated')), `banner: ${text}`);
        await tab.resetProblems(); // the failed import is logged on purpose
        await tab.click('#page-body [data-action="reload-page"]');
        await tab.waitFor(() => document.documentElement.dataset.appReady === 'true'
          && document.querySelector('#page-body')?.dataset.view === 'ip'
          && document.querySelector('#page-body').childElementCount > 0
          && !document.querySelector('#page-body .page-loading'), { timeout: 15000, message: 'IP Intel after the reload' });
        assertEqual(await moduleSrc(), 'v/e2e-two/assets/js/app.js', 'module script after the reload');
        assertEqual(await tab.evaluate(() => !!document.querySelector('[data-action="reload-page"]')), false, 'banner gone');
        await assertClean(tab, 'after the reload');
      });
    } finally {
      await tab.close();
      await pages.close();
    }

    /* ---------------- The installable app: service worker, offline tools, update ---------------- */
    group('Installable app (sw.js from the Pages bundle)');
    // Its own bundle and server (a new origin: no service worker from the steps above).
    const appSite = path.join(tmpDir, 'site-app');
    await assembleSite({ out: appSite, version: 'app-one' });
    // The deploy's manifest in sw.js, and the cache names its worker derives for the scope.
    const deployed = async () => {
      const build = JSON.parse(/^const BUILD = (\{[\s\S]*?\n\}); /m.exec(await readFile(path.join(appSite, 'sw.js'), 'utf8'))[1]);
      return { build, names: cacheNames(BASE, build) };
    };
    const { build: workerBuild, names: workerCaches } = await deployed();
    const app = await startServer({ root: appSite, base: BASE });
    const pwa = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await pwa.emulateMedia({ 'prefers-color-scheme': 'light' });
    await pwa.send('Network.enable');
    const pwaSrc = () => pwa.evaluate(() => document.querySelector('script[type="module"]').getAttribute('src'));
    const srcOf = (page) => page.evaluate(() => document.querySelector('script[type="module"]').getAttribute('src'));
    const updateToast = (page) => page.waitFor((text) => document.querySelector('.toast[data-toast="pwa-update"]')?.textContent.includes(text),
      { args: [translate('pwa.updateReady')], timeout: 30000, message: 'update toast' });
    let other = null; // a second tab of the same version
    const network = async (online) => {
      app.setOffline(!online); // the worker's own fetches fail too, so an answer can only come from its cache
      await pwa.send('Network.emulateNetworkConditions', { offline: !online, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
      await pwa.waitFor((on) => navigator.onLine === on, { args: [online], message: `navigator.onLine ${online}` });
    };
    try {
      await step('installs the service worker (CSP worker-src falls back to script-src \'self\') and precaches this version', async () => {
        await pwa.goto(app.url);
        await waitReady(pwa);
        const sw = await pwa.waitFor(async (name, count) => {
          const reg = await navigator.serviceWorker.getRegistration();
          if (!reg || !reg.active || !navigator.serviceWorker.controller) return false;
          const n = (await caches.has(name)) ? (await (await caches.open(name)).keys()).length : 0;
          return n === count && { scope: reg.scope, script: reg.active.scriptURL, caches: (await caches.keys()).sort() };
        }, { args: [workerCaches.shell, workerBuild.precache.length], timeout: 30000, message: 'service worker in control, app shell precached' });
        assertEqual(sw, { scope: app.url, script: `${app.url}sw.js`, caches: [workerCaches.shell, workerCaches.wordlists].sort() }, 'registration');
        const manifest = await pwa.evaluate(async () => {
          const link = document.querySelector('link[rel="manifest"]');
          const m = await (await fetch(link.href)).json();
          return { href: link.getAttribute('href'), name: m.short_name, start: new URL(m.start_url, link.href).href };
        });
        assertEqual(manifest, { href: 'manifest.webmanifest', name: 'DomainScope', start: app.url }, 'web app manifest');
        // The installed app's identity is the project path, not the origin root (an id of "./" would be).
        const { appId } = await pwa.send('Page.getAppId');
        assertEqual(appId, app.url, 'app id');
        await assertClean(pwa, 'service worker install');
      });

      await step('offline: the app starts from the cache; Certificate, Zone File and Servers work', async () => {
        await network(false);
        await pwa.reload({ ignoreCache: false }); // a normal reload: a hard one would skip the service worker
        await waitReady(pwa);
        assertEqual(await pwaSrc(), 'v/app-one/assets/js/app.js', 'the cached index.html');
        await gotoRoute(pwa, 'cert');
        await pwa.click('[data-action="cert-sample"]');
        await pwa.waitFor(() => document.querySelector('.cert-overview-cn')?.textContent === 'example.com', { message: 'sample certificate parsed offline' });
        // Opening the CAA tab starts its check by itself: offline it sends nothing and says so in
        // place — no "this needs the network" toast for something nobody clicked.
        await dismissToasts(pwa);
        await pwa.click('.cert-tabs [data-tab="caa"]');
        await pwa.waitFor(() => !!document.querySelector('.cert-caa [data-offline="auto"]'), { message: 'CAA offline note' });
        setNodeLang('en');
        const caaOffline = await pwa.evaluate((text) => ({
          toasts: [...document.querySelectorAll('.toast')].filter((el) => el.textContent.includes(text)).length,
          button: document.querySelector('.cert-caa [data-action="caa-run"]')?.disabled
        }), translate('shell.offlineAction'));
        assertEqual(caaOffline, { toasts: 0, button: false }, 'CAA tab offline');
        await gotoRoute(pwa, 'zone');
        await pwa.click('[data-sample="bind"]');
        await pwa.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'zone file parsed offline' });
        await gotoRoute(pwa, 'inventory');
        await pwa.type('[data-role="inventory-text"]', 'web01 192.0.2.10');
        await pwa.waitFor(() => document.querySelectorAll('.inv-results .dt-table tbody tr.dt-row').length === 1, { message: 'servers parsed offline' });
        const notes = await pwa.evaluate(() => document.querySelector('#page-offline').hidden);
        assertEqual(notes, true, 'no offline note on a tool that works offline');
        await shot(pwa, 'desktop-light-en-offline-zone');
      });

      await step('offline: a network tool says it needs the network, names the offline tools and sends nothing; a shared link only fills the form', async () => {
        await gotoRoute(pwa, 'lookup');
        setNodeLang('en');
        const note = await pwa.evaluate(() => ({
          hidden: document.querySelector('#page-offline').hidden,
          title: document.querySelector('#page-offline .alert-title')?.textContent,
          tools: [...document.querySelectorAll('#page-offline a[data-view]')].map((a) => a.dataset.view)
        }));
        assertEqual(note, { hidden: false, title: translate('shell.offlineTitle'), tools: ['zone', 'cert', 'inventory', 'about'] }, 'offline note');
        await pwa.type('[data-role="lookup-name"]', 'example.com');
        await pwa.click('[data-action="run"]');
        await pwa.waitFor((text) => [...document.querySelectorAll('.toast')].some((el) => el.textContent.includes(text)),
          { args: [translate('shell.offlineAction')], message: 'offline toast' });
        // Clicked again, it is said again, not stacked (copies would push other toasts out).
        await pwa.click('[data-action="run"]');
        await pwa.click('[data-action="run"]');
        const offlineToasts = () => pwa.evaluate((text) => [...document.querySelectorAll('.toast')]
          .filter((el) => el.textContent.includes(text)).length, translate('shell.offlineAction'));
        assertEqual(await offlineToasts(), 1, 'offline toasts after three clicks');
        await shot(pwa, 'desktop-light-en-offline-lookup');
        // A shared link opened offline fills the form and runs nothing; the page's note says why,
        // and no toast (nobody clicked Run).
        await dismissToasts(pwa);
        await pwa.evaluate(() => { window.location.hash = '#/health?domain=example.com'; });
        await pwa.waitFor(() => document.querySelector('#page-body')?.dataset.view === 'health'
          && !!document.querySelector('[data-role="health-domain"]'), { message: 'Domain Health from a shared link' });
        await pwa.evaluate(() => new Promise((r) => setTimeout(r, 250)));
        const shared = await pwa.evaluate(() => {
          const field = document.querySelector('[data-role="health-domain"]');
          return { domain: (field.matches('input') ? field : field.querySelector('input')).value, note: !document.querySelector('#page-offline').hidden };
        });
        assertEqual({ ...shared, toasts: await offlineToasts() }, { domain: 'example.com', note: true, toasts: 0 }, 'shared link offline');
        const sent = await pwa.evaluate(() => performance.getEntriesByType('resource').filter((e) => /dns-query|\/resolve\?/.test(e.name)).length);
        assertEqual(sent, 0, 'no DoH request');
        await assertClean(pwa, 'offline', { offline: true });
        await pwa.resetProblems(); // the browser's own offline failures must not count once it is back online
      });

      await step('back online, a new deploy: "Update ready — Reload" loads it and drops the old version\'s cache', async () => {
        await network(true);
        await dismissToasts(pwa);
        other = await browser.newPage('about:blank', { width: 1440, height: 900 });
        await other.goto(app.url);
        await waitReady(other);
        await other.waitFor(() => !!navigator.serviceWorker.controller, { message: 'second tab under the service worker' });
        await assembleSite({ out: appSite, version: 'app-two' });
        // The browser looks for a new sw.js on navigations; a hash-routed page asks when it becomes
        // visible or comes back online (at most hourly), so the test asks now.
        await pwa.evaluate(async () => (await navigator.serviceWorker.getRegistration()).update());
        setNodeLang('en');
        await updateToast(pwa);
        assertEqual(await pwaSrc(), 'v/app-one/assets/js/app.js', 'still the running version until the click');
        // The second tab is offered the update too; dismissed there, it must come back once the
        // click in this tab has the new version take that tab over as well (next step).
        await updateToast(other);
        await dismissToasts(other);
        await shot(pwa, 'desktop-light-en-update-ready');
        await pwa.click('.toast[data-toast="pwa-update"] .btn');
        await pwa.waitFor(() => document.querySelector('script[type="module"]')?.getAttribute('src') === 'v/app-two/assets/js/app.js'
          && document.documentElement.dataset.appReady === 'true', { timeout: 30000, message: 'the new version after the reload' });
        const after = await pwa.waitFor(async () => {
          const reg = await navigator.serviceWorker.getRegistration();
          const keys = (await caches.keys()).sort();
          return reg && !reg.waiting && keys.length === 2 && keys;
        }, { timeout: 15000, message: 'old cache dropped' });
        const two = (await deployed()).names;
        assertEqual(after, [two.shell, two.wordlists].sort(), 'caches');
        assertEqual(await pwa.evaluate(() => !!document.querySelector('.toast[data-toast="pwa-update"]')), false, 'toast gone');
        await assertClean(pwa, 'after the update');
      });

      await step('the other tab, whose version that update dropped from the cache, offers the reload again and takes it', async () => {
        await updateToast(other);
        assertEqual(await srcOf(other), 'v/app-one/assets/js/app.js', 'still its old version until the click');
        // A language switch while it is on screen re-says it in the new language (and links that manifest).
        await setLangUi(other, 'tr');
        setNodeLang('tr');
        const tr = await other.evaluate(() => ({
          toasts: [...document.querySelectorAll('.toast[data-toast="pwa-update"]')].map((el) => [el.querySelector('.toast-message').textContent, el.querySelector('.btn-label').textContent]),
          manifest: document.querySelector('link[rel="manifest"]').getAttribute('href')
        }));
        assertEqual(tr, { toasts: [[translate('pwa.updateReady'), translate('pwa.reload')]], manifest: 'manifest.tr.webmanifest' }, 'update toast in Turkish');
        setNodeLang('en');
        await other.click('.toast[data-toast="pwa-update"] .btn');
        await other.waitFor(() => document.querySelector('script[type="module"]')?.getAttribute('src') === 'v/app-two/assets/js/app.js'
          && document.documentElement.dataset.appReady === 'true', { timeout: 15000, message: 'the new version in the other tab' });
        await assertClean(other, 'other tab after the update');
      });

      await step('the same version assembled again with one file changed is an update too: new worker, new cache, the new file', async () => {
        await other.close();
        other = null;
        await setLangUi(pwa, 'en'); // the other tab's switch to Turkish reached this one through the shared settings
        await dismissToasts(pwa);
        const before = (await deployed()).names.shell;
        // A copy of the repository with one module changed, assembled under the version running now
        // (a local preview reassembled after an edit, a manual deploy that reuses its version).
        const copy = path.join(tmpDir, 'repo-edited');
        for (const name of [...ROOT_FILES, ...ROOT_DIRS, VERSIONED_DIR]) {
          await cp(path.join(REPO_ROOT, name), path.join(copy, name), { recursive: true });
        }
        const about = path.join(copy, VERSIONED_DIR, 'js', 'views', 'about.js');
        await writeFile(about, `${await readFile(about, 'utf8')}// rebuilt under the same version\n`);
        await assembleSite({ out: appSite, version: 'app-two', root: copy });
        const rebuilt = (await deployed()).names.shell;
        assert(rebuilt !== before, `the same shell cache ${rebuilt}`);
        const aboutText = () => pwa.evaluate(async () => (await fetch('v/app-two/assets/js/views/about.js')).text());
        assert(!(await aboutText()).endsWith('// rebuilt under the same version\n'), 'the running version answers from its cache');
        await pwa.evaluate(async () => (await navigator.serviceWorker.getRegistration()).update());
        setNodeLang('en');
        await updateToast(pwa);
        await pwa.evaluate(() => { window.__beforeUpdate = true; });
        await pwa.click('.toast[data-toast="pwa-update"] .btn');
        await pwa.waitFor(() => !window.__beforeUpdate && document.documentElement.dataset.appReady === 'true',
          { timeout: 30000, message: 'reloaded into the rebuilt version' });
        assertEqual(await pwaSrc(), 'v/app-two/assets/js/app.js', 'the same version');
        assert((await aboutText()).endsWith('// rebuilt under the same version\n'), 'the changed file');
        const keys = await pwa.waitFor(async (name) => {
          const k = (await caches.keys()).sort();
          return k.length === 2 && k.includes(name) && k;
        }, { args: [rebuilt], timeout: 15000, message: 'the earlier build\'s cache dropped' });
        assertEqual(keys, [rebuilt, (await deployed()).names.wordlists].sort(), 'caches');
        await assertClean(pwa, 'after the rebuilt update');
      });
    } finally {
      if (other) await other.close();
      await pwa.close();
      await app.close();
    }
  } finally {
    await browser.close();
    await server.close();
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }

  const failed = results.filter((r) => !r.ok);
  process.stdout.write(`\n${results.length - failed.length} passed, ${failed.length} failed${SHOTS_ON ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : ''}\n`);
  if (failed.length) {
    for (const f of failed) process.stdout.write(`  - ${f.group}: ${f.name}\n`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${err && err.stack || err}\n`);
  process.exitCode = 1;
});
