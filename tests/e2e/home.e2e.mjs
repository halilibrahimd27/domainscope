#!/usr/bin/env node
/**
 * home.e2e.mjs — end-to-end test of Home (views/home.js, docs/DESIGN.md §4), the start page, in a
 * real headless Chrome/Edge. OFFLINE: Home reads only what the browser keeps; the workspace is
 * seeded through `state` with what the real writers store (lib/ctseen.js, lib/regwatch.js,
 * lib/waivers.js, lib/rollout.js, lib/digests.js); a network-level guard (CDP Fetch) fails and
 * records any https request — the suite asserts none.
 *
 *   node tests/e2e/home.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - the bare site URL opens Home: first in the navigation, in a group without a heading; the
 *     brand links to it; the <h1> and the tab's title are the workspace's name;
 *   - a new workspace: the empty state — the quick start, the six job cards (two columns of chips
 *     on a phone), the setup checklist, the privacy line; Home's counts never load;
 *   - the quick start is the palette's box: "/" reaches it, ui/palette.js loads on its first
 *     focus, a domain's actions fill a tool in and send nothing;
 *   - a seeded workspace: Needs attention counts certificate and registration expiry, registry
 *     risks (a registry lock is no risk), an accepted risk ending, the rollout, the nightly
 *     results and the server list's warnings, error → warn → info, six rows then "Show all"; a CT
 *     check older than 14 days reads "as of <date>"; each row is one link filling its tool in
 *     (Domain portfolio's CT tab with the domains), the accepted risks open the Workspaces dialog
 *     on them; a running job is a row with its ring; lib/homedigest.js loads after the first paint;
 *   - Recent domains with their quick actions (a name makes it the current target), Results in
 *     this tab with a result's open risks, Start a job folded to a short list, This workspace, the
 *     setup checklist with its ✓ and "Hide this list" for good;
 *   - every relative time (the last activity, "last checked", Recent domains, Results in this tab) is a
 *     <time datetime> whose title is the absolute local time with its UTC offset;
 *   - a workspace switch re-renders Home under the other workspace's name; a workspace whose only data
 *     is the nightly results' digest is no new one: Home counts them;
 *   - 375 px (Turkish, dark): the "⋯" menu of a recent domain (keyboard: ↓, a letter, Esc), 320 px: no
 *     horizontal scroll anywhere;
 *   - no missing i18n keys; zero console errors, exceptions and CSP violations; no request sent.
 */

import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner, gotoRoute,
  setLangUi, waitReady
} from './scan.e2e.mjs';

/**
 * In-page script: the workspace as the real writers leave it, dated from the page's clock — the
 * CT watch's baseline (example.com: 3 days left; example.org: 16 days, checked 20 days ago;
 * shop.example.net checked before `due` existed), the registration watch's snapshot (example.com
 * ends in 20 days; example.net unknown to its registry; shop.example.com on hold; example.org
 * without a transfer lock; lock.example.com under a registry lock), an accepted risk ending in 5
 * days, a rollout board (1 of 3 verified), the Monitoring digest (2 targets with bad changes, a
 * certificate expiring), two servers and a line that is no server, an expected CA, notes and three
 * recent domains (newest first: example.com, example.org, shop.example.net). tests/e2e and the
 * screenshot scripts share it.
 * @returns {string}
 */
export const seedWorkspaceScript = () => `(async () => {
  const [{ state }, ct, rw, wv, ro, dg] = await Promise.all([
    import('./assets/js/state.js'), import('./assets/js/lib/ctseen.js'), import('./assets/js/lib/regwatch.js'),
    import('./assets/js/lib/waivers.js'), import('./assets/js/lib/rollout.js'), import('./assets/js/lib/digests.js')
  ]);
  const NOW = Date.now();
  const DAY = 86400000;
  const at = (days) => new Date(NOW - days * DAY);
  const day = (days) => new Date(NOW + days * DAY).toISOString().slice(0, 10);
  const cert = (id, names, from, to) => ({ id, names, notBefore: new Date(NOW + from * DAY), notAfter: new Date(NOW + to * DAY) });
  let seen = ct.updateSeen(ct.emptySeen(), [
    { domain: 'example.com', at: at(1), state: 'ok', certs: [cert('00000000000000a1', ['example.com', 'www.example.com'], -80, 3.5)] },
    { domain: 'api.example.com', at: at(1), state: 'ok', certs: [cert('00000000000000a2', ['api.example.com'], -10, 80)] }
  ], { now: at(1) });
  seen = ct.updateSeen(seen, [{ domain: 'example.org', at: at(20), state: 'ok', certs: [cert('00000000000000b1', ['example.org'], -60, 16.5)] }], { now: at(20) });
  seen.domains['shop.example.net'] = { at: at(3).toISOString(), ids: { '00000000000000c1': day(40) } };
  const snap = (registration) => rw.registrationSnapshot({ registration: { state: 'ok', registrar: 'Example Registrar', ianaId: '9999', nameservers: ['ns1.example.net'], ...registration } });
  const rdap = rw.updateRdapSeen(rw.emptyRdapSeen(), [
    { domain: 'example.com', snapshot: snap({ expires: day(20), statuses: ['client transfer prohibited'] }) },
    { domain: 'example.net', snapshot: rw.registrationSnapshot({ registration: { state: 'not-found' } }) },
    { domain: 'shop.example.com', snapshot: snap({ expires: day(300), statuses: ['server hold', 'client transfer prohibited'] }) },
    { domain: 'example.org', snapshot: snap({ expires: day(200), statuses: ['client delete prohibited'] }) },
    { domain: 'lock.example.com', snapshot: snap({ expires: day(300), statuses: ['server transfer prohibited', 'server update prohibited', 'server delete prohibited'] }) }
  ], { now: at(1) });
  const waivers = wv.addWaiver([], { kind: 'finding', domain: 'example.com', ref: 'dmarc.policy-none', reason: 'Moving to quarantine', owner: 'Mail team', expires: day(5) }, { now: NOW }).list;
  const board = { id: 'ab'.repeat(32), label: '*.example.com' };
  let rollout = ro.setStep(ro.emptyRollout(), board, { key: 's:web01', name: 'web01' }, 'verified', true, { now: () => NOW - DAY });
  rollout = ro.setStep(rollout, board, { key: 's:web02', name: 'web02' }, 'installed', true, { now: () => NOW - DAY });
  rollout = ro.setTotal(rollout, board.id, 3);
  await state.setInventory('web01 192.0.2.10\\nweb02 192.0.2.11\\nthis line names no address').done;
  await Promise.all([
    state.setWorkspaceData('ctSeen', ct.seenText(seen)),
    state.setWorkspaceData('rdapSeen', rw.rdapSeenText(rdap)),
    state.setWorkspaceData('waivers', wv.waiversPartText(waivers)),
    state.setWorkspaceData('rollout', ro.serializeRollout(rollout)),
    state.setWorkspaceData('digests', dg.withDigest('', 'monitor', { at: at(0.5), imported: at(0.4), targets: 5, bad: 2, expiring: 1, incomplete: 0 })),
    state.setWorkspaceData('expectedCas', ["Let's Encrypt"]),
    state.setWorkspaceData('notes', 'Renewals every March.\\nCall the NOC first.')
  ]);
  for (const value of ['shop.example.net', 'example.org', 'example.com']) state.recordRecent(value);
  await state.whenSaved();
  return true;
})()`;

/** Fail every https request that reaches the network; returns the list it records. */
async function networkGuard(page) {
  const hits = [];
  page.conn.on('Fetch.requestPaused', (p) => {
    hits.push(p.request.url);
    page.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
  }, page.sessionId);
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://*' }] });
  return hits;
}

/** What Home shows. */
const homeInfo = (page) => page.evaluate(() => {
  const card = (role) => document.querySelector(`[data-role="${role}"]`);
  const attention = card('home-attention');
  return {
    view: document.documentElement.dataset.view,
    h1: document.querySelector('h1.page-title')?.textContent,
    purpose: document.querySelector('.page-header .page-purpose')?.textContent,
    docTitle: document.title,
    empty: !!document.querySelector('.home.home-empty'),
    cards: [...document.querySelectorAll('.home-card')].filter((c) => !c.hidden).map((c) => c.dataset.role),
    loading: !!document.querySelector('[data-role="home-loading"]'),
    rows: attention ? [...attention.querySelectorAll('.home-row')].map((r) => ({
      kind: r.dataset.kind, severity: r.dataset.severity, stale: r.dataset.stale === '1',
      text: r.querySelector('.home-row-text')?.textContent, detail: r.querySelector('.home-row-detail')?.textContent || '',
      href: r.getAttribute('href'), tag: r.tagName.toLowerCase()
    })) : [],
    more: attention?.querySelector('[data-action="home-show-all"]')?.textContent || null,
    privacy: document.querySelector('[data-role="home-privacy"]')?.textContent || null
  };
});

const resources = (page) => page.evaluate(() => performance.getEntriesByType('resource').map((e) => new URL(e.name).pathname));
const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));

/** Open Home again (a fresh mount), its counts drawn. */
async function remountHome(page, { counts = true } = {}) {
  await gotoRoute(page, 'about');
  await gotoRoute(page, 'home');
  if (counts) await page.waitFor(() => !document.querySelector('[data-role="home-loading"]') && document.querySelector('.home-row'), { message: 'Home counted', timeout: 15000 });
  await frames(page);
}

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const shot = async (page, name, { full = true } = {}) => {
    if (!opts.shots) return;
    await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
    await mkdir(opts.shotsDir, { recursive: true });
    await page.screenshot(path.join(opts.shotsDir, `${name}.png`), { fullPage: full });
  };

  run.group('Node: harness');
  await run.step('run-all orders the home suite right after shell', () => {
    assertEqual(orderSuites(['subdomains.e2e.mjs', 'home.e2e.mjs', 'shell.e2e.mjs']), ['shell', 'home', 'subdomains'], 'order');
  });

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: Home sends nothing\n`);
  let page = null;
  let netHits = [];
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    netHits = await networkGuard(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('A new workspace (desktop 1440×900, English, light)');
    await run.step('the bare site URL opens Home: first in the navigation without a group heading; the brand links to it; the title is the workspace\'s', async () => {
      await page.goto(server.url);
      await waitReady(page);
      await setLangUi(page, 'en');
      const shell = await page.evaluate(() => {
        const first = document.querySelector('#app-nav .nav-group');
        return {
          hash: location.hash,
          brand: document.getElementById('brand').getAttribute('href'),
          firstLinks: [...first.querySelectorAll('.nav-link')].map((a) => a.dataset.view),
          firstLabel: first.querySelector('.nav-group-label')?.textContent ?? null,
          current: document.querySelector('.nav-link[aria-current="page"]')?.dataset.view,
          about: !!document.querySelector('.page-header [data-action="page-about"]'),
          sheets: [...document.querySelectorAll('link[rel="stylesheet"]')].map((l) => new URL(l.href).pathname.replace(/^.*\/assets\//, ''))
        };
      });
      assertEqual(shell, { hash: '', brand: '#/home', firstLinks: ['home'], firstLabel: null, current: 'home', about: false, sheets: ['css/style.css', 'css/views/home.css'] },
        'Home is the start page');
      const info = await homeInfo(page);
      assertEqual([info.view, info.h1, info.docTitle], ['home', 'Default workspace', 'Default workspace · DomainScope'], 'title');
      assertEqual(info.purpose, 'Everything runs in this browser. Nothing is sent until you run a tool.', 'a new workspace\'s line');
    });

    await run.step('the empty state: the quick start, six job cards, the setup checklist, the privacy line — and nothing counted', async () => {
      const info = await homeInfo(page);
      assert(info.empty, 'empty state');
      assertEqual(info.cards, ['start-picker', 'home-setup'], 'cards (Needs attention, Recent domains and This workspace left out)');
      assertEqual(info.privacy, 'Home reads only what this browser keeps; it sends nothing.', 'privacy line');
      const jobs = await page.evaluate(() => {
        const card = document.querySelector('[data-role="start-picker"]');
        return {
          title: card.querySelector('.home-card-title').textContent,
          compact: card.classList.contains('is-compact'),
          jobs: [...card.querySelectorAll('.start-task')].map((a) => [a.dataset.task, a.getAttribute('href')]),
          fold: card.querySelector('[data-action="start-hide"]')?.textContent.trim()
        };
      });
      assertEqual(jobs, {
        title: 'Start a job', compact: false,
        jobs: [['subdomains', '#/subdomains'], ['certificate', '#/scan'], ['health', '#/health'], ['propagation', '#/global'], ['zone', '#/zone'], ['portfolio', '#/portfolio']],
        fold: 'Show as a short list'
      }, 'job cards');
      const setup = await page.evaluate(() => [...document.querySelectorAll('[data-role="home-setup"] .home-setup-item')].map((li) => [li.dataset.item, li.dataset.done]));
      assertEqual(setup, [['servers', '0'], ['cas', '0'], ['portfolio', '0'], ['workspaces', '0']], 'nothing set up yet');
      const quick = await page.evaluate(() => {
        const input = document.querySelector('[data-role="home-quick"]');
        return { placeholder: input.placeholder, label: input.getAttribute('aria-label'), shortcut: input.dataset.shortcut };
      });
      assertEqual(quick, { placeholder: 'Domain, host name, IP address, network or AS number …or paste a PEM certificate', label: 'Quick start', shortcut: 'focus' }, 'quick start');
      const loaded = await resources(page);
      assert(!loaded.some((p) => /\/lib\/homedigest\.js$|\/ui\/palette\.js$|\/views\/subdomains\.js$/.test(p)), `nothing more loaded: ${loaded.filter((p) => p.endsWith('.js')).slice(-6).join(', ')}`);
      await assertNoHorizontalScroll(page, 'empty Home');
      await shot(page, 'home-desktop-light-en-empty');
    });

    await run.step('"/" reaches the quick start, which loads the palette; a domain\'s actions fill a tool in and send nothing', async () => {
      await page.evaluate(() => document.getElementById('page-title').focus());
      await page.press('/');
      await page.waitFor(() => document.activeElement?.dataset.role === 'home-quick', { message: '"/" focuses the quick start' });
      await page.waitFor(() => performance.getEntriesByType('resource').some((e) => e.name.endsWith('/ui/palette.js')), { message: 'the palette loads on first focus' });
      await page.waitFor(() => document.querySelector('[data-role="home-quick"]').getAttribute('role') === 'combobox', { message: 'the box is the palette\'s combobox' });
      await page.type('[data-role="home-quick"]', 'example.com', { replace: true });
      await page.waitFor(() => document.querySelector('.home-quick-results .pal-option[data-entry="action:health"]'), { message: 'the domain\'s actions' });
      const typed = await page.evaluate(() => ({
        expanded: document.querySelector('[data-role="home-quick"]').getAttribute('aria-expanded'),
        hint: document.querySelector('.home-quick-hint').hidden,
        entries: [...document.querySelectorAll('.home-quick-results .pal-option')].map((o) => o.dataset.entry).slice(0, 3)
      }));
      assert(typed.expanded === 'true' && typed.hint && typed.entries.every((e) => e.startsWith('action:')), `actions under the box: ${JSON.stringify(typed)}`);
      await shot(page, 'home-desktop-light-en-quick', { full: false });
      await page.press('Escape');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="home-quick"]').value, document.querySelector('.home-quick-hint').hidden]), ['', false],
        'Esc empties the box, the hint is back');
      await page.type('[data-role="home-quick"]', 'example.com', { replace: true });
      await page.waitFor(() => document.querySelector('.home-quick-results .pal-option[data-entry="action:health"]'));
      await page.click('.home-quick-results .pal-option[data-entry="action:health"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'health', { message: 'Domain Health opened' });
      assertEqual(await page.evaluate(() => location.hash), '#/health?domain=example.com&run=0', 'filled in, not run');
      await gotoRoute(page, 'home');
    });

    run.group('A seeded workspace (desktop 1440×900, English, light)');
    await run.step('Needs attention: certificates, registrations, registry risks, an accepted risk, the rollout, the nightly results and the server list — error, warn, info; six rows, then "Show all"', async () => {
      assertEqual(await page.evaluate(SEED_HOLDER.script), true, 'seeded');
      await remountHome(page);
      const info = await homeInfo(page);
      assert(!info.empty, 'not the empty state');
      assertEqual(info.cards, ['home-attention', 'home-recent', 'start-picker', 'home-workspace', 'home-setup'], 'cards');
      assertEqual(info.rows.map((r) => `${r.severity}:${r.kind}`), [
        'error:cert', 'error:reg', 'error:regGone', 'error:regRisk', 'error:monitorBad', 'warn:waivers'
      ], 'the first six, error first, the soonest first');
      assertEqual(info.more, 'Show all (12)', 'the rest behind "Show all"');
      const cert = info.rows[0];
      assert(/^1 certificate expires within 7 days$/.test(cert.text), `CT row: ${cert.text}`);
      assert(cert.detail.startsWith('example.com · last checked'), `names and freshness: ${cert.detail}`);
      assertEqual(cert.href, '#/portfolio?domains=example.com&tab=ct&run=0', 'the CT tab with the domain filled in');
      assert(/^Registration expires in (19|20) days$/.test(info.rows[1].text), info.rows[1].text);
      assertEqual(info.rows[2].text, 'The registry does not know this domain', 'regGone');
      assertEqual(info.rows[3].text, 'Registry status: server hold', 'the portfolio\'s own rule');
      assertEqual(info.rows[4].text, 'Monitoring: 2 targets had a bad change in the last 7 days', 'the nightly results as written');
      assertEqual([info.rows[5].tag, info.rows[5].href], ['button', null], 'the accepted risks open a dialog');
      assert(!info.rows.some((r) => r.detail.includes('lock.example.com')), 'a registry lock is no risk');
      assert(await page.evaluate(() => performance.getEntriesByType('resource').some((e) => e.name.endsWith('/lib/homedigest.js'))), 'the counts loaded with lib/homedigest.js');
      // Every relative time is a <time datetime>; its title, the absolute local time with its UTC offset, matches a log (DESIGN §6.3).
      const times = await page.evaluate(() => [...document.querySelectorAll('.page-purpose time, .home time')].map((el) => ({
        role: el.closest('[data-role="home-attention"], [data-role="home-recent"], [data-role="home-kept"]')?.dataset.role || 'purpose',
        iso: el.getAttribute('datetime'), title: el.title, text: el.textContent
      })));
      assertEqual([...new Set(times.map((x) => x.role))], ['purpose', 'home-attention', 'home-recent'], `the times: ${JSON.stringify(times)}`);
      assert(times.every((x) => Number.isFinite(Date.parse(x.iso)) && /\d.* UTC[+-]\d\d:\d\d$/.test(x.title) && x.text && x.text !== x.title),
        `a datetime, the local time with its offset as the title: ${JSON.stringify(times)}`);
      await assertNoHorizontalScroll(page, 'seeded Home');
      await shot(page, 'home-desktop-light-en-seeded');
    });

    await run.step('"Show all" lists the twelve and keeps the focus; a CT check older than 14 days reads "as of <date> · Check again"', async () => {
      await page.click('[data-action="home-show-all"]');
      await page.waitFor(() => document.querySelectorAll('[data-role="home-attention"] .home-row').length === 12, { message: 'all twelve' });
      const info = await homeInfo(page);
      assertEqual(info.rows.map((r) => `${r.severity}:${r.kind}`).slice(5), [
        'warn:waivers', 'warn:cert', 'warn:regNoLock', 'warn:monitorExpiring', 'warn:servers', 'info:ctFirst', 'info:rollout'
      ], 'warnings, then notes');
      assertEqual(await page.evaluate(() => [document.activeElement?.dataset.action, document.activeElement?.textContent, document.activeElement?.getAttribute('aria-expanded')]),
        ['home-show-all', 'Show fewer', 'true'], 'focus kept on the toggle');
      const stale = info.rows.find((r) => r.kind === 'cert' && r.severity === 'warn');
      assert(stale.stale && /^example\.org · as of .+ · Check again$/.test(stale.detail), `stale row: ${JSON.stringify(stale)}`);
      assertEqual(info.rows.find((r) => r.kind === 'servers').text, '1 line in Servers could not be read', 'server list');
      assertEqual(info.rows.find((r) => r.kind === 'rollout').text, 'Rollout: 1 of 3 servers updated', 'rollout');
      assertEqual(info.rows.find((r) => r.kind === 'ctFirst').text, 'CT: check once to see expiries here', 'a baseline written before `due`');
      assertEqual(info.rows.find((r) => r.kind === 'waivers').text, '1 accepted risk ends within 14 days', 'accepted risk');
      await shot(page, 'home-desktop-light-en-all');
    });

    await run.step('the accepted-risk row opens the Workspaces dialog on them; Esc gives the focus back', async () => {
      await page.click('[data-role="home-attention"] button.home-row[data-kind="waivers"]');
      await page.waitFor(() => document.querySelector('dialog.ws-modal[open]') && document.activeElement?.dataset.role === 'ws-waivers-counts',
        { message: 'the dialog, on the accepted risks', timeout: 15000 });
      await page.press('Escape');
      await page.waitFor(() => !document.querySelector('dialog.ws-modal'), { message: 'closed' });
    });

    await run.step('a row is one link: the CT row opens Domain portfolio\'s Certificates (CT) tab with the domain filled in, nothing sent', async () => {
      await page.click('[data-role="home-attention"] a.home-row[data-kind="cert"][data-severity="error"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'portfolio' && document.querySelector('.tab[data-tab="ct"][aria-selected="true"]'),
        { message: 'Domain portfolio, its CT tab', timeout: 15000 });
      assertEqual(await page.evaluate(() => document.querySelector('.pf-box textarea, textarea.pf-box')?.value), 'example.com', 'the box holds the domain');
      assertEqual(netHits, [], 'nothing sent');
      await gotoRoute(page, 'home');
    });

    await run.step('a running job is a row with its ring (after the warnings: "Show all (13)"), and goes when it ends', async () => {
      await page.evaluate(async () => {
        const jobs = await import('./assets/js/ui/jobs.js');
        window.__job = jobs.startJob({ view: 'bulk', subject: 'example.com' });
        window.__job.update(0.4);
      });
      try {
        await page.waitFor(() => document.querySelector('[data-action="home-show-all"]')?.textContent === 'Show all (13)', { message: 'one more row' });
        await page.click('[data-action="home-show-all"]');
        await page.waitFor(() => document.querySelector('.home-row[data-severity="running"]'), { message: 'the running row' });
        assertEqual(await page.evaluate(() => [...document.querySelectorAll('.home-row')].map((r) => r.dataset.severity).indexOf('running')), 10,
          'after the five errors and five warnings');
      const row = await page.evaluate(() => {
        const r = document.querySelector('.home-row[data-severity="running"]');
        return { text: r.querySelector('.home-row-text').textContent, ring: !!r.querySelector('.home-ring svg'), view: r.getAttribute('href').split('?')[0] };
      });
      assertEqual(row, { text: 'Bulk Resolve is running — 40% done', ring: true, view: '#/bulk' }, 'running row');
      } finally {
        await page.evaluate(() => window.__job.finish({ status: 'cancelled' }));
      }
      await page.waitFor(() => !document.querySelector('.home-row[data-severity="running"]'), { message: 'gone once it ended' });
    });

    await run.step('Recent domains: newest first with their quick actions; a name makes it the current target', async () => {
      const recent = await page.evaluate(() => [...document.querySelectorAll('[data-role="home-recent"] .home-recent-row')].map((li) => ({
        value: li.dataset.value,
        actions: [...li.querySelectorAll('.home-recent-action')].map((a) => [a.textContent, a.getAttribute('href')]),
        menu: getComputedStyle(li.querySelector('.home-recent-menu') || document.body).display
      })));
      assertEqual(recent.map((r) => r.value), ['example.com', 'example.org', 'shop.example.net'], 'newest first');
      assertEqual(recent[0].actions, [
        ['Health', '#/health?domain=example.com&run=0'], ['Overview', '#/domain?name=example.com&run=0'],
        ['Subdomains', '#/subdomains?domain=example.com&run=0'], ['Lookup', '#/lookup?name=example.com&run=0']
      ], 'quick actions fill the tools in');
      assertEqual(recent[0].menu, 'none', 'no "⋯" on a desktop');
      await page.click('[data-role="home-recent"] .home-recent-row[data-value="example.org"] [data-action="home-target"]');
      await page.waitFor(() => document.querySelector('[data-role="target-chip"] .target-chip-value')?.textContent === 'example.org', { message: 'the current target' });
    });

    await run.step('Results in this tab: a kept result with its open risks; its link brings it back', async () => {
      await page.evaluate(async () => {
        const { pageSession } = await import('./assets/js/app.js');
        // newer than the current target (example.org): its link brings the result back
        pageSession.keep('health', { params: { domain: 'example.com' }, subject: 'example.com', at: new Date(), status: { error: 1, warn: 2 } });
      });
      await remountHome(page);
      const kept = await page.evaluate(() => [...document.querySelectorAll('[data-role="home-kept"] .home-kept-row')].map((a) => ({
        view: a.dataset.view, tool: a.querySelector('.home-kept-tool').textContent, subject: a.querySelector('.home-kept-subject')?.textContent,
        tags: [...a.querySelectorAll('.tag')].map((t) => t.textContent), href: a.getAttribute('href'),
        time: /UTC[+-]\d\d:\d\d$/.test(a.querySelector('time.home-kept-when[datetime]')?.title || '')
      })));
      assertEqual(kept, [{ view: 'health', tool: 'Domain Health', subject: 'example.com', tags: ['1 error', '2 warnings'], href: '#/health?domain=example.com&run=0', time: true }],
        'kept result');
    });

    await run.step('Start a job is a short list now; This workspace counts what it holds; the checklist ticks what is done and hides for good', async () => {
      const info = await page.evaluate(() => {
        const jobs = document.querySelector('[data-role="start-picker"]');
        const ws = document.querySelector('[data-role="home-workspace"]');
        return {
          compact: jobs.classList.contains('is-compact') && !!jobs.querySelector('.start-tasks-compact'),
          tasks: jobs.querySelectorAll('.start-task').length,
          fold: !!jobs.querySelector('[data-action="start-hide"]'),
          counts: ws.querySelector('.home-ws-counts').textContent,
          note: ws.querySelector('.home-ws-note')?.textContent,
          setup: [...document.querySelectorAll('[data-role="home-setup"] .home-setup-item')].map((li) => [li.dataset.item, li.dataset.done]),
          facts: document.querySelector('.page-header .page-purpose').textContent
        };
      });
      assertEqual([info.compact, info.tasks, info.fold], [true, 6, false], 'a short list once there is data');
      assertEqual(info.counts, '2 servers · 1 expected CA · 1 accepted risk', 'counts');
      assertEqual(info.note, '“Renewals every March.”', 'the first line of the notes');
      assertEqual(info.setup, [['servers', '1'], ['cas', '1'], ['portfolio', '1'], ['workspaces', '0']], 'ticks');
      assert(/^2 servers · 3 recent domains · last activity /.test(info.facts), `facts: ${info.facts}`);
      await page.click('[data-action="home-setup-hide"]');
      await page.waitFor(() => !document.querySelector('[data-role="home-setup"]') && document.activeElement?.id === 'page-title', { message: 'hidden, focus on the title' });
      assertEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.settings')).homeSetup), false, 'stored');
      await remountHome(page);
      assert(!await page.evaluate(() => !!document.querySelector('[data-role="home-setup"]')), 'still hidden');
    });

    await run.step('a workspace switch re-renders Home under the other workspace\'s name; back to Default', async () => {
      await page.evaluate(async () => (await import('./assets/js/ui/jobs.js')).jobList().length === 0 || window.__job.finish({ status: 'cancelled' }));
      const id = await page.evaluate(async () => {
        const { state } = await import('./assets/js/state.js');
        const ws = await state.createWorkspace('Acme');
        await state.switchWorkspace(ws.meta.id);
        return ws.meta.id;
      });
      await page.waitFor(() => document.querySelector('h1.page-title')?.textContent === 'Acme', { message: 'Acme', timeout: 15000 });
      const info = await homeInfo(page);
      assertEqual([info.h1, info.docTitle, info.empty], ['Acme', 'Acme · DomainScope', true], 'the new workspace\'s Home');
      // Monitoring never adds a recent domain: a workspace that holds only its nightly results' digest is in use, and Home counts them.
      await page.evaluate(async () => {
        const [{ state }, dg] = await Promise.all([import('./assets/js/state.js'), import('./assets/js/lib/digests.js')]);
        await state.setWorkspaceData('digests', dg.withDigest('', 'monitor', { at: new Date(), imported: new Date(), targets: 6, bad: 3, expiring: 2, incomplete: 1 }));
        await state.whenSaved();
      });
      await remountHome(page);
      const digest = await homeInfo(page);
      assertEqual([digest.h1, digest.empty, digest.rows.map((r) => `${r.severity}:${r.kind}`)], ['Acme', false, ['error:monitorBad', 'warn:monitorExpiring', 'warn:monitorIncomplete']],
        'a digest alone: no first-run page, its counts');
      assertEqual(digest.rows[0].text, 'Monitoring: 3 targets had a bad change in the last 7 days', 'the nightly results');
      await page.evaluate(async (wid) => {
        const { state } = await import('./assets/js/state.js');
        await state.switchWorkspace('default');
        await state.deleteWorkspace(wid);
      }, id);
      await page.waitFor(() => document.querySelector('h1.page-title')?.textContent === 'Default workspace', { message: 'Default again', timeout: 15000 });
    });

    await run.step('the header\'s Manage opens the Workspaces dialog; desktop page clean', async () => {
      await page.click('[data-action="home-manage"]');
      await page.waitFor(() => document.querySelector('dialog.ws-modal[open]'), { message: 'Workspaces dialog', timeout: 15000 });
      await page.press('Escape');
      await page.waitFor(() => !document.querySelector('dialog.ws-modal'));
      await assertNoMissingKeys(page);
      await assertClean(page, 'Home (desktop)', origin);
    });

    await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
    await remountHome(page);
    await shot(page, 'home-desktop-dark-en-seeded');
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Phone 375×812 (Turkish, dark) and 320 px');
    await run.step('375 px, Turkish: one column, every card fits; the quick actions sit behind "⋯", a menu the keyboard drives', async () => {
      await page.setViewport({ width: 375, height: 812, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await remountHome(page);
      const info = await homeInfo(page);
      assertEqual([info.h1, info.docTitle], ['Varsayılan çalışma alanı', 'Varsayılan çalışma alanı · DomainScope'], 'TR title');
      assertEqual(info.rows[0].text, '1 sertifikanın süresi 7 gün içinde doluyor', 'TR row');
      assertEqual(info.more, 'Tümünü göster (12)', 'TR show all');
      const shown = await page.evaluate(() => {
        const row = document.querySelector('.home-recent-row');
        return { actions: getComputedStyle(row.querySelector('.home-recent-actions')).display, menu: getComputedStyle(row.querySelector('.home-recent-menu')).display };
      });
      // a flex item: inline-flex is computed as flex
      assertEqual(shown, { actions: 'none', menu: 'flex' }, '"⋯" on a phone');
      await assertNoHorizontalScroll(page, 'Home 375 TR');
      await shot(page, 'home-phone-dark-tr-seeded');
      const btn = '.home-recent-row[data-value="example.com"] [data-action="home-recent-more"]';
      await page.click(btn);
      await page.waitFor(() => document.activeElement?.getAttribute('role') === 'menuitem', { message: 'the menu, its first item focused' });
      const menu = await page.evaluate((sel) => {
        const b = document.querySelector(sel);
        const m = document.getElementById(b.getAttribute('aria-controls'));
        const r = m.getBoundingClientRect();
        return {
          expanded: b.getAttribute('aria-expanded'), open: m.matches(':popover-open'), label: b.getAttribute('aria-label'),
          items: [...m.querySelectorAll('[role="menuitem"]')].map((a) => a.textContent), inside: r.left >= 0 && r.right <= innerWidth,
          first: document.activeElement.textContent
        };
      }, btn);
      assertEqual(menu, {
        expanded: 'true', open: true, label: 'example.com için diğer işlemler',
        items: ['Alan Adı Sağlığı', 'Alan adı özeti', 'Subdomain Tarama', 'DNS Sorgulama'], inside: true, first: 'Alan Adı Sağlığı'
      }, 'menu');
      await shot(page, 'home-phone-dark-tr-menu', { full: false });
      await page.press('ArrowDown');
      assertEqual(await page.evaluate(() => document.activeElement.textContent), 'Alan adı özeti', '↓ moves');
      // Type-ahead: a letter moves to the next item that starts with it, wrapping around.
      await page.press('d');
      assertEqual(await page.evaluate(() => document.activeElement.textContent), 'DNS Sorgulama', '"d": the next item starting with it');
      await page.press('a');
      assertEqual(await page.evaluate(() => document.activeElement.textContent), 'Alan Adı Sağlığı', '"a": around to the first');
      await page.press('Escape');
      await page.waitFor((sel) => document.activeElement === document.querySelector(sel) && document.querySelector(sel).getAttribute('aria-expanded') === 'false',
        { args: [btn], message: 'Esc closes, the focus back on "⋯"' });
      await page.click(btn);
      await page.waitFor(() => document.activeElement?.getAttribute('role') === 'menuitem');
      await page.press('ArrowDown');
      await page.press('Enter');
      await page.waitFor(() => document.documentElement.dataset.view === 'domain', { message: 'Domain overview opened from the menu' });
      assertEqual(await page.evaluate(() => location.hash), '#/domain?name=example.com&run=0', 'filled in, not run');
      assertEqual(netHits, [], 'nothing sent');
      await gotoRoute(page, 'home');
    });

    await run.step('320 px: still no horizontal scroll, the job chips in two columns', async () => {
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await remountHome(page);
      await assertNoHorizontalScroll(page, 'Home 320 TR');
      const columns = await page.evaluate(() => new Set([...document.querySelectorAll('[data-role="start-picker"] .start-task')]
        .map((a) => Math.round(a.getBoundingClientRect().left))).size);
      assertEqual(columns, 2, 'two columns of chips');
      await shot(page, 'home-phone320-dark-tr-seeded');
      await setLangUi(page, 'en');
      await assertNoHorizontalScroll(page, 'Home 320 EN');
      await shot(page, 'home-phone320-dark-en-seeded');
    });

    await run.step('phone: no missing keys; no console errors, exceptions or CSP violations; nothing sent', async () => {
      await assertNoMissingKeys(page);
      await assertClean(page, 'Home (phone)', origin);
      const sent = await page.evaluate((own) => performance.getEntriesByType('resource').map((e) => e.name).filter((u) => !u.startsWith(own)), origin);
      assertEqual([sent, netHits], [[], []], 'no request left the page');
    });
  } finally {
    if (page) await page.close().catch(() => {});
    await browser.close();
    await server.close();
  }
  run.finish();
}

/** The seed script, built once (a function body string the page evaluates). */
const SEED_HOLDER = { script: seedWorkspaceScript() };

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stdout.write(`\n${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  });
}
export { main };
// Keep the file's directory at hand for scripts that import it (screenshots).
export const HOME_E2E_DIR = path.dirname(fileURLToPath(import.meta.url));
