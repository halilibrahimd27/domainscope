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
 *     and tests DataTable paging/sorting/search/streaming and Tabs keyboard navigation
 *   - fails on any console error, uncaught exception, failed request or CSP violation, and on
 *     i18n keys that are missing in either language.
 * Then it serves the GitHub Pages bundle (tools/assemble-site.mjs, assets under v/<version>/):
 * the app boots from it, About's links resolve, a view that fails to load offline (or blocked)
 * keeps the plain network error with Retry, and after a second "deploy" a view opened in the
 * old tab offers a page reload that brings the new version.
 * No network access is needed: the shell views never call external APIs.
 */

import { mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { parseInventory } from '../../assets/js/lib/inventory.js';
import { t as translate, setLang as setNodeLang } from '../../assets/js/i18n.js';
import { DEFAULT_CHAIN, getResolver } from '../../assets/js/lib/resolvers.js';
import { REPO_URL } from '../../assets/js/app.js';
import { assembleSite } from '../../tools/assemble-site.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SHOTS = path.join(HERE, 'screenshots');
const BASE = '/domainscope/';
const ROUTES = ['subdomains', 'zone', 'scan', 'cert', 'global', 'lookup', 'bulk', 'ip', 'health', 'inventory', 'about'];

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
  // Offline, the browser's own requests (the favicon on Linux Chrome) fail on purpose.
  const logErrors = offline ? p.logErrors.filter((e) => !/ERR_INTERNET_DISCONNECTED/.test(e.text)) : p.logErrors;
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
        C.CopyButton('copied text'),
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

    await step('phone nav is a sticky horizontal scroller with the active item in view', async () => {
      await gotoRoute(phone, 'about');
      const info = await phone.evaluate(async () => {
        window.scrollTo(0, 900);
        await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
        const nav = document.getElementById('app-nav');
        const link = nav.querySelector('.nav-link[aria-current="page"]').getBoundingClientRect();
        return {
          top: Math.round(nav.getBoundingClientRect().top),
          scrollable: nav.scrollWidth > nav.clientWidth,
          activeVisible: link.left >= 0 && link.right <= window.innerWidth
        };
      });
      assertEqual(info.top, 0, 'nav sticks to the top');
      assert(info.scrollable && info.activeVisible, `nav scroller: ${JSON.stringify(info)}`);
      await phone.evaluate(() => window.scrollTo(0, 0));
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

    /* ---------------- The Pages bundle, and a deploy while a tab is open ---------------- */
    group('Pages bundle (tools/assemble-site.mjs)');
    const site = path.join(tmpDir, 'site');
    await assembleSite({ out: site, version: 'e2e-one' });
    const pages = await startServer({ root: site, base: BASE });
    const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
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
