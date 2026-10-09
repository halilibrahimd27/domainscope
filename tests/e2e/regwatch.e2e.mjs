#!/usr/bin/env node
/**
 * regwatch.e2e.mjs — end-to-end test of the Domain portfolio's registration watch ("Changed since
 * your last check", lib/regwatch.js over the workspace part `rdapSeen`) in a real headless
 * Chrome/Edge. OFFLINE: every DoH query is answered in the page by a fake resolver built from the
 * zone below (window.fetch wrapped before the app loads), the RDAP bootstrap and registry by the same
 * wrapper, whose answers the test changes between two checks; every other https:// request is
 * blocked, and every request that leaves the page's origin is counted through CDP.
 *
 *   node tests/e2e/regwatch.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: a first Check portfolio over three domains says nothing changed (no baseline yet) and
 * writes the workspace's baseline; the registry then answers another registrar without the transfer
 * lock for example.com and a later expiry for example.org; the next Check portfolio shows "Changed
 * since your last check (date): registrar, lock removed" on example.com (red: needs a look) and
 * "renewed" on example.org, nothing on example.net; the tile counts them and filters, as the Show
 * select does; Copy summary names them; a third check says nothing (the baseline moved on); the
 * baseline travels in the workspace hand-over file (exported, imported as another workspace, where a
 * check finds nothing changed); a check that a switch to another workspace drops (the registry holds
 * an answer back meanwhile) writes nothing into the new workspace's baseline; a registration that
 * failed (HTTP 503) is written into it by its Retry. 375 / 320 px without horizontal scroll, TR / EN
 * × light / dark; zero console errors / CSP violations / missing i18n keys, nothing sent outside the
 * page.
 *
 * Data is documentation space only (example.com / .net / .org, 192.0.2.0/24).
 */

import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, setLangUi, shot, stubClipboard, takeClipboard, waitReady
} from './scan.e2e.mjs';

const DAY = 86400000;
const NOW = Date.now();
// half a day past the count, so a run a few minutes later still counts the same whole days
const iso = (days) => new Date(NOW + days * DAY + DAY / 2).toISOString().replace(/\.\d{3}Z$/, 'Z');
const DOMAINS = ['example.com', 'example.org', 'example.net'];

/** Three zones on their own name servers (in-bailiwick: no name server domain to look up). */
const ZONE = Object.fromEntries(DOMAINS.map((d) => [d, {
  NS: [`ns1.${d}`, `ns2.${d}`], MX: [{ preference: 10, exchange: `mx.${d}` }], TXT: [['v=spf1 -all']]
}]));
ZONE['mx.example.com'] = { A: ['192.0.2.25'] };

const rdapJson = (domain, { status = ['client transfer prohibited', 'client delete prohibited'], days = 300, registrar = 'Example Registrar, Inc.', ianaId = '9999' } = {}) => ({
  objectClassName: 'domain', ldhName: domain.toUpperCase(), status,
  events: [{ eventAction: 'registration', eventDate: '2001-05-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: iso(days) }],
  entities: [{ objectClassName: 'entity', roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', registrar]]], publicIds: [{ type: 'IANA Registrar ID', identifier: ianaId }] }],
  nameservers: [{ objectClassName: 'nameserver', ldhName: `NS1.${domain.toUpperCase()}` }, { objectClassName: 'nameserver', ldhName: `NS2.${domain.toUpperCase()}` }]
});
const RDAP = Object.fromEntries(DOMAINS.map((d) => [d, rdapJson(d)]));
/** What the registry says at the second check: another registrar without the lock, a renewal. */
const RDAP_AFTER = {
  'example.com': rdapJson('example.com', { status: ['client delete prohibited'], registrar: 'Other Registrar LLC', ianaId: '1068' }),
  'example.org': rdapJson('example.org', { days: 665 })
};

/**
 * In-page stubs: DoH from the zone (NXDOMAIN outside it), the RDAP bootstrap and a registry the test
 * can change (`window.__rdap`), hold an answer back until the check stops (`window.__rdapHold`: a
 * domain) or fail with HTTP 503 (`window.__rdapFail`: domains).
 */
const fakeScript = () => `(() => {
  const Z = ${JSON.stringify(ZONE)};
  window.__rdap = ${JSON.stringify(RDAP)};
  window.__dnsLog = [];
  window.__rdapLog = [];
  window.__rdapHold = null;
  window.__rdapFail = [];
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/rdap+json' } });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://data.iana.org/rdap/')) return json({ services: [[['com', 'net', 'org'], ['https://rdap.example.net/']]] });
    if (url.startsWith('https://rdap.example.net/') || url.startsWith('https://rdap.org/')) {
      const name = decodeURIComponent(url.split('/domain/')[1] || '');
      window.__rdapLog.push(name);
      if (window.__rdapHold === name) {
        // a slow registry: no answer until the check is stopped
        await new Promise((resolve, reject) => {
          const signal = init && init.signal;
          if (!signal) return;
          const stop = () => reject(signal.reason || new DOMException('The operation was aborted.', 'AbortError'));
          if (signal.aborted) stop();
          else signal.addEventListener('abort', stop, { once: true });
        });
      }
      if (window.__rdapFail.includes(name)) return json({ errorCode: 503 }, 503);
      return window.__rdap[name] ? json(window.__rdap[name]) : json({ errorCode: 404 }, 404);
    }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const qname = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__dnsLog.push({ name: qname, type: q.type });
    const node = Z[qname];
    const rcode = node || Object.keys(Z).some((k) => k.endsWith('.' + qname)) ? 'NOERROR' : 'NXDOMAIN';
    const answers = ((node && node[q.type]) || []).map((data) => ({ name: qname, type: q.type, ttl: 300, data }));
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode, questions: [{ name: q.name, type: q.type }], answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);
const waitDone = (page, message = 'portfolio checked') => page.waitFor(() => !!document.querySelector('.pf-head[data-status="done"], .pf-head[data-status="stopped"]')
  && !document.querySelector('[data-action="pf-run"]').hidden && !document.querySelector('.pf-pending'), { timeout: 40000, message });
/** Each row's "changed" badge: its codes, tone and words, by domain. */
const changedRows = (page) => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.pf-table tbody tr.dt-row')].map((tr) => {
  const el = tr.querySelector('.pf-changed');
  return [tr.querySelector('.pf-domain')?.textContent, el ? { codes: el.dataset.changed, tone: el.dataset.tone, text: el.textContent.replace(/\s+/g, ' ').trim() } : null];
})));
const tile = (page, k) => page.evaluate((key) => {
  const el = document.querySelector(`[data-tile="${key}"]`);
  return el ? { value: el.querySelector('.stat-value').textContent.trim(), error: el.classList.contains('stat-v-error') } : null;
}, k);
const shownDomains = (page) => page.evaluate(() => [...document.querySelectorAll('.pf-table tbody .pf-domain')].map((d) => d.textContent));
const seenOf = (page) => page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.workspaceData('rdapSeen')));

async function check(page) {
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  await page.click('[data-action="pf-run"]');
  await page.waitFor(() => !document.querySelector('[data-action="pf-stop"]').hidden || !!document.querySelector('.pf-head'), { message: 'running' });
  await waitDone(page);
}

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
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('the first check: nothing to compare yet, nothing marked; the workspace keeps what each registry said', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.setWorkspaceData('rdapSeen', '')));
      await gotoRoute(page, `#/portfolio?domains=${DOMAINS.join(',')}`);
      await page.waitFor(() => !!document.querySelector('[data-action="pf-run"]'), { message: 'the view' });
      await check(page);
      assertEqual(await page.evaluate(() => document.querySelectorAll('.pf-table tbody tr.dt-row').length), 3, 'three rows');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.pf-changed').length), 0, 'no baseline: nothing changed');
      assertEqual(await tile(page, 'changed'), { value: '0', error: false }, 'the tile');
      const seen = JSON.parse(await seenOf(page));
      assertEqual(Object.keys(seen.domains).sort(), [...DOMAINS].sort(), 'each registry\'s answer kept');
      assertEqual([seen.domains['example.com'].registrar, seen.domains['example.com'].ianaId, seen.domains['example.com'].nameservers],
        ['Example Registrar, Inc.', '9999', ['ns1.example.com', 'ns2.example.com']], 'the registrar, its IANA ID, the registry\'s name servers');
      assertEqual(seen.domains['example.com'].statuses, ['client delete prohibited', 'client transfer prohibited'], 'the statuses');
    });

    await run.step('the next check: another registrar and the lock removed (red), a renewal (green), the rest unchanged', async () => {
      await page.evaluate((after) => Object.assign(window.__rdap, after), RDAP_AFTER);
      await check(page);
      const rows = await changedRows(page);
      assertEqual(rows['example.com'] && [rows['example.com'].codes, rows['example.com'].tone], ['registrar lock-removed', 'bad'], 'example.com');
      assert(/^Changed since your last check \(.+\): registrar, lock removed$/.test(rows['example.com'].text), rows['example.com'].text);
      assertEqual(rows['example.org'] && [rows['example.org'].codes, rows['example.org'].tone], ['expiry-later', 'good'], 'example.org');
      assert(/\): renewed$/.test(rows['example.org'].text), rows['example.org'].text);
      assertEqual(rows['example.net'], null, 'unchanged');
      assertEqual(await tile(page, 'changed'), { value: '2', error: true }, 'two changed, one of them bad');
      assert(await page.evaluate(() => /example\.com/.test(document.querySelector('.pf-changed')?.closest('tr')?.textContent || '')), 'the badge sits in the domain cell');
      await shot(page, opts, 'regwatch-changed-desktop-light-en');
    });

    await run.step('the tile and the Show select filter the changed rows; "needs a look" holds the bad one only', async () => {
      await page.click('[data-tile="changed"]');
      assertEqual((await shownDomains(page)).sort(), ['example.com', 'example.org'], 'the changed rows');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="pf-filter"]').value), 'changed', 'the select follows');
      assert(/Changed since your last check \(2\)/.test(await page.evaluate(() => [...document.querySelectorAll('[data-role="pf-filter"] option')].map((o) => o.textContent).join('|'))), 'its count');
      await page.evaluate(() => { const s = document.querySelector('[data-role="pf-filter"]'); s.value = 'attention'; s.dispatchEvent(new Event('change')); });
      assertEqual(await shownDomains(page), ['example.com'], 'a renewal needs no look');
      await page.evaluate(() => { const s = document.querySelector('[data-role="pf-filter"]'); s.value = 'all'; s.dispatchEvent(new Event('change')); });
    });

    await run.step('Copy summary names what changed, the bad one first', async () => {
      await stubClipboard(page);
      await page.click('.pf-head [data-action="copy-summary"]');
      await page.waitFor(() => (window.__clip || []).length === 1, { message: 'copied' });
      const [out] = await takeClipboard(page);
      const ls = out.trimEnd().split('\n');
      assertEqual(ls[1], '- **Changed since your last check:** `example.com` (registrar, lock removed), `example.org` (renewed)', 'the line');
    });

    run.group('Phone 375 and 320 px, Turkish / English, light / dark');
    await run.step('the badge wraps inside its card: no horizontal scroll', async () => {
      await page.setViewport({ width: 375, height: 760, mobile: true });
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await page.waitFor(() => !!document.querySelector('.pf-head'), { message: 'kept after the language switch' });
        for (const scheme of ['dark', 'light']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await page.evaluate(() => window.scrollTo(0, 0));
          await assertNoHorizontalScroll(page, `regwatch ${scheme} ${lang}`);
          await shot(page, opts, `regwatch-changed-mobile-${scheme}-${lang}`);
        }
      }
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('.pf-head'), { message: 'kept' });
      const tr = await changedRows(page);
      assert(/^Son kontrolünüzden beri değişti \(.+\): kayıt firması, kilit kaldırıldı$/.test(tr['example.com'].text), tr['example.com'].text);
      assert(/\): yenilendi$/.test(tr['example.org'].text), tr['example.org'].text);
      const spill = await page.evaluate(() => [...document.querySelectorAll('.pf-table tbody tr.dt-row')].filter((r) => r.scrollWidth > r.clientWidth + 1).length);
      assertEqual(spill, 0, 'every card fits at 375 px');
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await assertNoHorizontalScroll(page, 'regwatch 320 tr dark');
      await shot(page, opts, 'regwatch-changed-mobile320-dark-tr');
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await shot(page, opts, 'regwatch-changed-desktop-dark-tr');
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.waitFor(() => !!document.querySelector('.pf-head'), { message: 'kept' });
    });

    run.group('The baseline moves on, and travels with the workspace');
    await run.step('a third check: nothing changed since the second', async () => {
      await check(page);
      assertEqual(await page.evaluate(() => document.querySelectorAll('.pf-changed').length), 0, 'said once');
      assertEqual(await tile(page, 'changed'), { value: '0', error: false });
      const seen = JSON.parse(await seenOf(page));
      assertEqual([seen.domains['example.com'].registrar, seen.domains['example.com'].statuses], ['Other Registrar LLC', ['client delete prohibited']], 'the baseline is the last check\'s');
    });

    await run.step('the hand-over file carries the baseline: imported as another workspace, a check there finds nothing changed', async () => {
      const id = await page.evaluate(async () => {
        const [{ state }, handover, ws] = await Promise.all([import('./assets/js/state.js'), import('./assets/js/lib/handover.js'), import('./assets/js/lib/workspace.js')]);
        const data = Object.fromEntries(ws.WORKSPACE_PARTS.map((p) => [p, state.workspaceData(p)]));
        const file = await handover.exportWorkspaceFile({ name: 'Acme', data });
        if (!JSON.parse(file).workspace.parts.rdapSeen) throw new Error('no rdapSeen in the file');
        const opened = await handover.openWorkspaceFile(file);
        const { meta } = await state.createWorkspace('Acme (imported)', opened.data);
        await state.switchWorkspace(meta.id);
        return meta.id;
      });
      assert(id, 'switched');
      const seen = JSON.parse(await seenOf(page));
      assertEqual(seen.domains['example.com'].registrar, 'Other Registrar LLC', 'the imported workspace has the baseline');
      await gotoRoute(page, `#/portfolio?domains=${DOMAINS.join(',')}`);
      await page.waitFor(() => !!document.querySelector('[data-action="pf-run"]'), { message: 'the view' });
      await check(page);
      assertEqual(await page.evaluate(() => document.querySelectorAll('.pf-changed').length), 0, 'compared with the imported baseline');
      await page.evaluate(async (wid) => {
        const { state } = await import('./assets/js/state.js');
        await state.switchWorkspace('default');
        await state.deleteWorkspace(wid);
      }, id);
    });

    run.group('The baseline belongs to its workspace');
    let otherId = null;
    const portfolioRuns = () => page.evaluate(() => import('./assets/js/ui/jobs.js').then((m) => m.runningWork().includes('nav.portfolio')));
    await run.step('a check that a switch to another workspace drops writes nothing into the new workspace\'s baseline', async () => {
      await gotoRoute(page, '#/about');
      await gotoRoute(page, `#/portfolio?domains=${DOMAINS.join(',')}`);
      await page.waitFor(() => !!document.querySelector('[data-action="pf-run"]'), { message: 'the view' });
      // the registry holds example.net's answer back: the check still runs, example.com read, when the workspace changes
      await page.evaluate(() => { window.__rdapLog.length = 0; window.__rdapHold = 'example.net'; });
      await page.click('[data-action="pf-run"]');
      await page.waitFor(() => window.__rdapLog.includes('example.com') && window.__rdapLog.includes('example.net'), { message: 'example.com read, example.net held', timeout: 20000 });
      assert(await portfolioRuns(), 'the check is running');
      otherId = await page.evaluate(async () => {
        const { state } = await import('./assets/js/state.js');
        const { meta } = await state.createWorkspace('Beta');
        await state.switchWorkspace(meta.id);
        return meta.id;
      });
      await page.waitFor(() => import('./assets/js/ui/jobs.js').then((m) => !m.runningWork().includes('nav.portfolio')), { message: 'the dropped check ended' });
      assertEqual(await seenOf(page), '', 'nothing the dropped check read went into the new workspace');
    });

    await run.step('a Retry of a registration that failed writes it into the baseline', async () => {
      await page.evaluate(() => { window.__rdapHold = null; window.__rdapFail = ['example.net']; });
      await gotoRoute(page, '#/about');
      await gotoRoute(page, `#/portfolio?domains=${DOMAINS.join(',')}`);
      await page.waitFor(() => !!document.querySelector('[data-action="pf-run"]'), { message: 'the view' });
      await check(page);
      assertEqual(Object.keys(JSON.parse(await seenOf(page)).domains).sort(), ['example.com', 'example.org'], 'the registry that failed is not in it');
      await page.evaluate(() => { window.__rdapFail = []; });
      await page.click('button[data-cell="registrar"][data-domain="example.net"]');
      await page.waitFor(() => import('./assets/js/state.js').then(({ state }) => /"example\.net"/.test(state.workspaceData('rdapSeen') || '')),
        { message: 'example.net written after its Retry', timeout: 20000 });
      const seen = JSON.parse(await seenOf(page));
      assertEqual([seen.domains['example.net'].registrar, seen.domains['example.net'].ianaId], ['Example Registrar, Inc.', '9999'], 'what the Retry read');
      await page.evaluate(async (wid) => {
        const { state } = await import('./assets/js/state.js');
        await state.switchWorkspace('default');
        await state.deleteWorkspace(wid);
      }, otherId);
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'regwatch', origin));
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

// Run as a program (run-all, or by hand).
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
    process.exitCode = 1;
  });
}
