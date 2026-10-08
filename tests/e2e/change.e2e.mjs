#!/usr/bin/env node
/**
 * change.e2e.mjs — end-to-end test of the "DNS change request" view in a real headless Chrome/Edge.
 * OFFLINE: every DoH query is answered in the page by a fake resolver built from a table that the
 * test changes as it goes (window.__dns; the four check resolvers are told apart by their URL, so
 * one can lag behind, serve a wrong value or fail; `delay` makes every answer slow); every other
 * https:// request is blocked, and every request that leaves the page's origin is counted through
 * CDP.
 *
 *   node tests/e2e/change.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry (DNS tools, after Bulk Resolve) and the empty form (nothing sent); an ACME
 * DNS-01 TXT request typed in (the change as it is built, a token of the wrong shape flagged, the
 * admin's instructions in English and Turkish, BIND with its download, the route that reopens the
 * form; the format tab and the instructions' language picked stay while the form is edited; the
 * record name an ACME client prints taken for the certificate name); an SPF include with "Read the current records" from the keyboard (only names and types
 * asked; the include merged into the record there, the site verification kept by the Route 53
 * change batch, the lookups counted, then "read again" once the form changes the record); a CNAME
 * next to an A record found by the read (a lint error, no outputs); a form opened from its route
 * (CAA, the way Domain Health's "Edit in DNS change request" opens it); the check link opened from
 * the outputs: per-resolver verdicts (done, not yet
 * with the negative TTL waited for, no answer), the next check never before a cached answer
 * expires, Check now after the change reaches the lagging resolver, "done on every resolver that
 * answered", then done everywhere and the loop stopped, and Check again asks every resolver once
 * more (from the keyboard: the focus moves to Stop while a round runs, then to Check again); a check with the old value known (not yet vs wrong value), Esc stops it, Check again; Esc
 * while a slow round runs (its answers shown, nothing scheduled after it); no resolver answering
 * at all (said so after the first round, stopped as failed after three); a language switch that
 * resumes the check without asking again; a check opened offline (it says so, schedules nothing and
 * asks once the connection is back); a link that cannot be read (nothing sent); Retry after the check
 * page crashed (the check page again, its link kept); a builder
 * link near the length limit opens; 320 / 375 px phones light / dark in
 * both languages without horizontal scroll; no console errors, CSP violations or missing i18n
 * keys; nothing sent outside the page.
 *
 * Data is documentation space only (example.com / .net / .org, 192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24) plus Google's SPF include name, which the SPF template publishes.
 */

import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner, gotoRoute,
  installDownloadCapture, setLangUi, shot, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';

const TOKEN_A = 'gfj9Xq3Wr1Bm5zQXxZrW1zFeI6nY6cRgO0sIkWQfVbk';
const TOKEN_B = 'LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0';
const SOA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026092801, refresh: 7200, retry: 900, expire: 1209600, minimum: 300 };

/** The fake DNS: name → { TYPE: [data…] }, with per-resolver overrides in VIEWS. */
const ZONE = {
  'example.com': { SOA: [SOA], TXT: [['v=spf1 include:spf.protection.outlook.com ~all'], ['google-site-verification=abc123']], MX: [{ preference: 10, exchange: 'mail.example.com' }] },
  'spf.protection.outlook.com': { TXT: [['v=spf1 ip4:192.0.2.0/24 -all']] },
  '_spf.google.com': { TXT: [['v=spf1 ip4:198.51.100.0/24 ~all']] },
  'shop.example.com': { A: ['203.0.113.7'] },
  '_acme-challenge.example.com': { TXT: [[TOKEN_A], [TOKEN_B]] },
  'www.example.com': { A: ['192.0.2.10'] }
};
/** Google has not seen the token yet (its cached NXDOMAIN); CZ.NIC answers HTTP 500. */
const VIEWS = { google: { '_acme-challenge.example.com': null, 'www.example.com': { A: ['198.51.100.5'] } }, cznic: { '_status': 500 } };
const HOSTS = { 'cloudflare-dns.com': 'cloudflare', 'dns.google': 'google', 'doh.dns.sb': 'dnssb', 'odvr.nic.cz': 'cznic' };

const fakeScript = () => `(() => {
  const dns = window.__dns = { zone: ${JSON.stringify(ZONE)}, views: ${JSON.stringify(VIEWS)}, log: [] };
  const HOSTS = ${JSON.stringify(HOSTS)};
  let wire = null;
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    const resolver = HOSTS[new URL(url).hostname] || new URL(url).hostname;
    dns.log.push({ name, type: q.type, resolver });
    if (dns.delay) await new Promise((resolve) => setTimeout(resolve, dns.delay));
    const view = dns.views[resolver] || {};
    if (view._status) return new Response('', { status: view._status });
    const node = Object.prototype.hasOwnProperty.call(view, name) ? view[name] : dns.zone[name];
    const answers = node ? (node[q.type] || []).map((data) => ({ name, type: q.type, ttl: 120, data })) : [];
    const authorities = answers.length ? [] : [{ name: 'example.com', type: 'SOA', ttl: 300, data: dns.zone['example.com'].SOA[0] }];
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: node ? 'NOERROR' : 'NXDOMAIN',
      questions: [{ name: q.name, type: q.type }], answers, authorities, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

const dnsLog = (page) => page.evaluate(() => window.__dns.log.slice());
const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent || '', sel);
/** Type into a form field of the builder (by its data-field) and let the form rebuild. */
const fill = (page, field, value) => page.evaluate(([f, v]) => {
  const el = document.querySelector(`[data-field="${f}"]`);
  const input = el.matches('input, textarea, select') ? el : el.querySelector('input, textarea, select');
  input.value = v;
  input.dispatchEvent(new Event(input.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
}, [field, value]);
const pickTemplate = (page, id) => page.evaluate((v) => {
  const el = document.querySelector('[data-role="change-template"]');
  el.value = v;
  el.dispatchEvent(new Event('change', { bubbles: true }));
}, id);
/** The change's sets as the page shows them: 'action type name: +added -removed'. */
const sets = (page) => page.evaluate(() => [...document.querySelectorAll('.fix-set')].map((li) => `${li.dataset.action} ${li.dataset.type} ${li.dataset.name}: ${[...li.querySelectorAll('.fix-value')].map((v) => `${v.classList.contains('fix-value-add') ? '+' : v.classList.contains('fix-value-remove') ? '-' : '='}${v.querySelector('.fix-value-text').textContent}`).join(' ')}`));
/** Wait for the outputs to show `fn(state)` true (the form rebuilds after a short debounce). */
const waitOutputs = (page, message) => page.waitFor(() => !!document.querySelector('.chg-outputs .fix-outputs'), { message, timeout: 8000 });
const tabText = async (page, id) => {
  await page.evaluate((t) => document.querySelector(`.fix-tabs .tab[data-tab="${t}"]`).click(), id);
  return page.evaluate((t) => document.querySelector(`.fix-tabs .tabpanel[data-tab="${t}"] .codeblock-pre`)?.textContent || '', id);
};
/** Open a check link and wait until its first round has answered. */
async function openCheck(page, query) {
  await page.evaluate((q) => { window.location.hash = `#/change/check?${q}`; }, query);
  await page.waitFor(() => document.querySelector('[data-page="check"]')?.dataset.round >= '1'
    || document.querySelector('[data-page="check"]')?.dataset.state === 'bad', { message: 'check page', timeout: 15000 });
}
const resolverRows = (page) => page.evaluate(() => [...document.querySelectorAll('.chg-set')].map((c) => [...c.querySelectorAll('.chg-res')]
  .map((li) => `${li.dataset.resolver}:${li.dataset.verdict}${li.dataset.reason ? `/${li.dataset.reason}` : ''}`)));
const checkInfo = (page) => page.evaluate(() => {
  const v = document.querySelector('[data-page="check"]');
  return { state: v.dataset.state, headline: v.dataset.headline, round: Number(v.dataset.round), nextAt: Number(v.dataset.nextAt) || null, now: Date.now(),
    next: v.dataset.nextPairs ? v.dataset.nextPairs.split(' ') : [] };
});

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  process.stdout.write(`\nServing ${server.url} — ${(await browser.version()).product}\n`);
  const external = [];
  let checkQuery = null;
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
    await run.step('boots on #/change: nav entry after Bulk Resolve in DNS tools, the empty form, nothing sent', async () => {
      await page.goto(`${server.url}#/change`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'change');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/bulk"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.dataset.view) : [];
      });
      assertEqual(nav, ['global', 'lookup', 'bulk', 'change'], 'DNS tools group');
      assertEqual(await text(page, 'h1'), 'DNS change request', 'title');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="change-template"]').value), 'acme-txt', 'first template');
      assert(await page.evaluate(() => !!document.querySelector('.chg-empty .empty')), 'empty state');
      assertEqual(await dnsLog(page), [], 'no DNS query');
      await shot(page, opts, 'change-empty-desktop-light-en');
    });

    await run.step('ACME DNS-01 TXT typed in: the set, a token of the wrong shape, the notes; the route reopens the form', async () => {
      await fill(page, 'name', '*.example.com');
      await fill(page, 'tokens', `${TOKEN_A}\nnot-a-token`);
      await page.waitFor(() => /not-a-token/.test(document.querySelector('.chg-problems')?.textContent || ''), { message: 'token warning' });
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.fix-problem')].map((p) => `${p.dataset.severity} ${p.dataset.key}`)), ['warn fix.p.token-format'], 'a warning, not an error');
      await fill(page, 'tokens', `${TOKEN_A}\n${TOKEN_B}`);
      await page.waitFor(() => !document.querySelector('.fix-problem'), { message: 'warning gone' });
      await waitOutputs(page, 'outputs');
      assertEqual(await sets(page), [`add TXT _acme-challenge.example.com: +"${TOKEN_A}" +"${TOKEN_B}"`], 'the set');
      const hash = await page.evaluate(() => location.hash);
      assert(hash.startsWith('#/change?t=acme-txt&name=*.example.com&tokens=') && hash.includes(TOKEN_B), `route: ${hash}`);
      assertEqual(await dnsLog(page), [], 'still nothing sent');
    });

    await run.step('the admin\'s instructions in English and Turkish; BIND and its download; the check link', async () => {
      const en = await tabText(page, 'admin');
      assert(en.startsWith('DNS change request: example.com') && en.includes('Name: _acme-challenge.example.com') && en.includes('/#/change/check?z=example.com&r=has+_acme-challenge+TXT+'), `EN: ${en.slice(0, 400)}`);
      await page.click('[data-control="fix-lang"] [data-value="tr"]');
      await page.waitFor(() => /^DNS değişiklik talebi: example\.com/.test(document.querySelector('.fix-admin-text .codeblock-pre')?.textContent || ''), { message: 'Turkish instructions' });
      const bind = await tabText(page, 'bind');
      assert(bind.includes(`_acme-challenge 300 IN TXT "${TOKEN_A}"`) && bind.includes('$ORIGIN example.com.'), `BIND: ${bind}`);
      await page.click('.fix-tabs .tabpanel[data-tab="bind"] [data-action="fix-download"]');
      const files = await takeDownloads(page);
      assertEqual(files.map((f) => f.name), ['dns-change-example.com.zone'], 'download');
      assertEqual(files[0].text, bind, 'the file is the text shown');
      const cf = await tabText(page, 'cloudflare');
      assert(cf.includes(': "${CLOUDFLARE_API_TOKEN:?') && !/Bearer [A-Za-z0-9]{20}/.test(cf), 'the token stays a shell variable');
      checkQuery = await page.evaluate(() => document.querySelector('.fix-check a.btn').getAttribute('href').replace('#/change/check?', ''));
      assertEqual(checkQuery, `z=example.com&r=has+_acme-challenge+TXT+%22${TOKEN_A}%22%7C%22${TOKEN_B}%22`, 'check link');
      await shot(page, opts, 'change-acme-desktop-light-en');
    });

    await run.step('the format being watched and the instructions\' language stay while the form is edited', async () => {
      await page.click('.fix-tabs .tab[data-tab="route53"]');
      await page.evaluate(() => { document.querySelector('.chg-outputs .fix-outputs').dataset.stale = '1'; });
      await fill(page, 'tokens', TOKEN_A);
      await page.waitFor(() => !!document.querySelector('.chg-outputs .fix-outputs:not([data-stale])'), { message: 'rebuilt' });
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.fix-tabs .tab[aria-selected="true"]')].map((b) => b.dataset.tab)), ['route53'], 'the Route 53 tab stays selected');
      const r53 = await page.evaluate(() => document.querySelector('.fix-tabs .tabpanel[data-tab="route53"]:not([hidden]) .codeblock-pre')?.textContent || '');
      assert(r53.includes(TOKEN_A) && !r53.includes(TOKEN_B), `the edited change on screen: ${r53.slice(0, 200)}`);
      assert(/^DNS değişiklik talebi: example\.com/.test(await tabText(page, 'admin')), 'the instructions stay in Turkish');
      await page.click('[data-control="fix-lang"] [data-value="en"]');
      await fill(page, 'tokens', `${TOKEN_A}\n${TOKEN_B}`);
      await page.waitFor((t) => (document.querySelector('.fix-admin-text .codeblock-pre')?.textContent || '').includes(t), { args: [TOKEN_B], message: 'both tokens again' });
    });

    await run.step('the record name an ACME client prints, pasted as the certificate name: the label is not doubled, and it is said', async () => {
      await fill(page, 'name', '_acme-challenge.example.com');
      await page.waitFor(() => !!document.querySelector('.fix-problem[data-key="fix.p.acme-name"]'), { message: 'the note' });
      assertEqual(await page.evaluate(() => document.querySelector('.fix-problem[data-key="fix.p.acme-name"]').dataset.severity), 'info', 'info, not an error');
      await waitOutputs(page, 'outputs');
      assertEqual(await sets(page), [`add TXT _acme-challenge.example.com: +"${TOKEN_A}" +"${TOKEN_B}"`], 'one _acme-challenge label');
      await fill(page, 'name', '*.example.com');
      await page.waitFor(() => !document.querySelector('.fix-problem'), { message: 'note gone' });
    });

    await run.step('SPF include: "Read the current records" with Ctrl+Enter asks only names and types; the include joins the record there', async () => {
      await pickTemplate(page, 'spf');
      await fill(page, 'domain', 'example.com');
      await fill(page, 'includes', '_spf.google.com');
      await page.waitFor(() => /read the current records first/.test(document.querySelector('.chg-problems')?.textContent || ''), { message: 'read first' });
      await page.evaluate(() => document.querySelector('textarea[data-field="includes"]').focus());
      await page.press('Enter', { ctrl: true });
      await page.waitFor(() => /Current records read at/.test(document.querySelector('.chg-read-note')?.textContent || ''), { message: 'read done', timeout: 10000 });
      const asked = await dnsLog(page);
      assertEqual([...new Set(asked.map((q) => `${q.name} ${q.type}`))].sort(), ['_spf.google.com TXT', 'example.com CNAME', 'example.com TXT', 'spf.protection.outlook.com TXT'], 'names and types only: the record, its CNAME clash and the includes counted');
      await waitOutputs(page, 'outputs after the read');
      assertEqual(await sets(page), ['replace TXT example.com: +"v=spf1 include:spf.protection.outlook.com include:_spf.google.com ~all" -"v=spf1 include:spf.protection.outlook.com ~all"'], 'merged SPF');
      const r53 = JSON.parse(await tabText(page, 'route53'));
      assertEqual(r53.Changes[0].ResourceRecordSet.ResourceRecords.map((r) => r.Value), ['"google-site-verification=abc123"', '"v=spf1 include:spf.protection.outlook.com include:_spf.google.com ~all"'], 'UPSERT keeps the site verification');
      assert(/needs 2 of 10 DNS lookups/.test(await text(page, '.chg-problems')), 'lookups counted');
      // Edited after the read: the count was of the record then, so it is no longer shown; "read again" is.
      await fill(page, 'includes', '_spf.google.com\nspf.example.net');
      await page.waitFor(() => !!document.querySelector('.fix-problem[data-key="fix.p.spf-recount"]'), { message: 'read again to count' });
      assert(!/needs \d+ of 10 DNS lookups/.test(await text(page, '.chg-problems')), 'no count of another record');
      assert(/changed after its lookups were counted/.test(await text(page, '.chg-read-note')), 'the read note says so');
      await page.evaluate(() => { window.__dns.log.length = 0; });
    });

    await run.step('a CNAME next to an A record the read finds: an error, and nothing is written out', async () => {
      await pickTemplate(page, 'record');
      await fill(page, 'name', 'shop.example.com');
      await fill(page, 'type', 'CNAME');
      await fill(page, 'values', 'shops.example.net');
      await waitOutputs(page, 'outputs before the read');
      await page.click('[data-action="change-read"]');
      await page.waitFor(() => !!document.querySelector('.fix-problem[data-key="zone.lint.CNAME_AND_OTHER_DATA"]'), { message: 'CNAME conflict', timeout: 10000 });
      const lint = await text(page, '.fix-problem[data-key="zone.lint.CNAME_AND_OTHER_DATA"]');
      assert(/shop\.example\.com has a CNAME and A\./.test(lint), `the lint text: ${lint}`);
      assert(await page.evaluate(() => !document.querySelector('.chg-outputs .fix-outputs') && !!document.querySelector('.chg-blocked')), 'no outputs while an error stands');
    });

    await run.step('a form opened from its route (CAA for Google, no wildcard): the fields and the records', async () => {
      await page.evaluate(() => { window.__dns.log.length = 0; window.location.hash = '#/change?t=caa&domain=example.org&cas=google&wild=none'; });
      await page.waitFor(() => document.querySelector('input[data-field="domain"]')?.value === 'example.org', { message: 'domain filled' });
      await waitOutputs(page, 'CAA outputs');
      assertEqual(await sets(page), ['replace CAA example.org: +0 issue "pki.goog" +0 issuewild ";"'], 'CAA set');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('[data-field="cas"] input:checked')].map((i) => i.value)), ['google'], 'the CA box');
      assertEqual(await dnsLog(page), [], 'opening a form sends nothing');
    });

    run.group('The check link');
    await run.step('opened from the outputs: done, not yet (the cached NXDOMAIN waited for), no answer; nothing asked before it can change', async () => {
      await openCheck(page, checkQuery);
      assertEqual(await resolverRows(page), [['cloudflare:done', 'google:pending/missing', 'dnssb:done', 'cznic:error/http']], 'verdicts');
      assertEqual(await text(page, '.chg-res[data-resolver="cznic"] .chg-res-verdict'), 'No answer (server error)', 'the error in words, not its code');
      const info = await checkInfo(page);
      assertEqual([info.headline, info.state], ['pending', 'waiting'], 'pending, waiting for the next round');
      // CZ.NIC failed: asked again after the backoff; Google's NXDOMAIN is cached for 300 s: not before then.
      assertEqual(info.next, ['0|cznic'], 'the next round asks CZ.NIC only');
      assert(info.nextAt - info.now >= 10_000 && info.nextAt - info.now <= 30_000, `the backoff: ${Math.round((info.nextAt - info.now) / 1000)} s`);
      assert(/cached until/.test(await text(page, '.chg-res[data-resolver="google"]')), 'the cached answer of Google is said');
      const asked = await dnsLog(page);
      assertEqual(asked.map((q) => `${q.name} ${q.type} ${q.resolver}`).sort(), ['_acme-challenge.example.com TXT cloudflare', '_acme-challenge.example.com TXT cznic', '_acme-challenge.example.com TXT dnssb', '_acme-challenge.example.com TXT google'], 'one query per resolver');
      assert(/Everything on this page came from its link/.test(await text(page, '.chg-check-privacy')), 'privacy note');
      assert(/Zone example\.com/.test(await text(page, '.chg-zone')), 'zone');
      await shot(page, opts, 'change-check-pending-desktop-light-en');
    });

    await run.step('Check now after the change reaches Google: done on every resolver that answered; CZ.NIC fixed: done, and the loop stops', async () => {
      await page.evaluate(() => { delete window.__dns.views.google['_acme-challenge.example.com']; window.__dns.log.length = 0; window.__dns.delay = 600; });
      // From the keyboard: Check now is off while its round runs, so the focus moves to Stop, never to the page.
      await page.evaluate(() => document.querySelector('[data-action="check-now"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.state === 'running', { message: 'running' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action || document.activeElement?.tagName), 'check-stop', 'focus during the round');
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.headline === 'done-partial', { message: 'done-partial', timeout: 10000 });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action || document.activeElement?.tagName), 'check-stop', 'focus after the round');
      await page.evaluate(() => { window.__dns.delay = 0; });
      assertEqual((await dnsLog(page)).map((q) => q.resolver).sort(), ['cznic', 'google'], 'only the resolvers not done yet are asked again');
      assert(/1 resolver did not answer/.test(await text(page, '.chg-check-head-wrap')), 'says which part is missing');
      await page.evaluate(() => { delete window.__dns.views.cznic; });
      await page.evaluate(() => document.querySelector('[data-action="check-now"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.state === 'done', { message: 'stopped: done', timeout: 10000 });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action || document.activeElement?.tagName), 'check-again', 'focus once done: Check again');
      const info = await checkInfo(page);
      assertEqual([info.headline, info.nextAt], ['done', null], 'done, nothing scheduled');
      assert(await page.evaluate(() => document.querySelector('[data-action="check-now"]').hidden && document.querySelector('[data-action="check-stop"]').hidden && !document.querySelector('[data-action="check-again"]').hidden), 'once done: Check again, no Check now / Stop');
    });

    await run.step('Check again once done asks every resolver for every record again (a revert would show)', async () => {
      await page.evaluate(() => { window.__dns.log.length = 0; window.__dns.delay = 600; });
      await page.evaluate(() => document.querySelector('[data-action="check-again"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.state === 'running', { message: 'running' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action || document.activeElement?.tagName), 'check-stop', 'focus during the round');
      await page.waitFor(() => { const v = document.querySelector('[data-page="check"]'); return v.dataset.state === 'done' && v.dataset.round === '1'; }, { message: 'done again', timeout: 10000 });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action || document.activeElement?.tagName), 'check-again', 'focus once done again');
      await page.evaluate(() => { window.__dns.delay = 0; });
      assertEqual((await dnsLog(page)).map((q) => `${q.name} ${q.type} ${q.resolver}`).sort(), ['_acme-challenge.example.com TXT cloudflare', '_acme-challenge.example.com TXT cznic',
        '_acme-challenge.example.com TXT dnssb', '_acme-challenge.example.com TXT google'], '4 resolvers × 1 record set');
      assertEqual(await resolverRows(page), [['cloudflare:done', 'google:done', 'dnssb:done', 'cznic:done']], 'verdicts');
    });

    await run.step('Copy summary of the check: the headline, each set with what the resolvers saw, this check\'s link', async () => {
      await stubClipboard(page);
      await page.click('[data-summary="change"] [data-action="copy-summary"]');
      await page.click('[data-summary="change"] [data-action="copy-summary-text"]');
      await page.waitFor(() => window.__clip.length === 2, { message: 'two copies' });
      const [md, plain] = await takeClipboard(page);
      const lines = md.trim().split('\n');
      assertEqual(lines.slice(0, 4), ['**DNS change request · `example.com`**', '- Done: every resolver sees the change.',
        '- `_acme-challenge.example.com` TXT: live · seen on 4 of 4 resolvers', ''], 'title, headline, the set');
      const foot = lines[lines.length - 1];
      assert(foot.startsWith('DomainScope · checked ') && foot.includes(` UTC · ${origin}${BASE}#/change/check?z=example.com&r=`), `footer: ${foot}`);
      assertEqual(plain, md.replace(/\*\*|`/g, '').replace('\n\nDomainScope · ', '\nDomainScope · '), 'the same lines in plain text');
    });

    const wrongQuery = 'z=example.com&r=is+www+A+192.0.2.10^198.51.100.5';
    await run.step('the old value known: Google not yet (still the old value), DNS.SB wrong; Esc stops, Check again runs again', async () => {
      await page.evaluate(() => { window.__dns.views.dnssb = { 'www.example.com': { A: ['203.0.113.9'] } }; window.__dns.log.length = 0; });
      await openCheck(page, wrongQuery);
      assertEqual(await resolverRows(page), [['cloudflare:done', 'google:pending/old', 'dnssb:wrong', 'cznic:done']], 'verdicts');
      assertEqual((await checkInfo(page)).headline, 'wrong', 'headline');
      assert(/Serves: 203\.0\.113\.9/.test(await text(page, '.chg-res[data-resolver="dnssb"]')), 'the wrong value is shown');
      await page.evaluate(() => document.querySelector('[data-action="check-now"]').focus());
      await page.press('Escape');
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.state === 'user', { message: 'stopped' });
      assert(await page.evaluate(() => !document.querySelector('[data-action="check-again"]').hidden && document.activeElement?.dataset.action === 'check-again'), 'Check again, focused');
      const before = (await dnsLog(page)).length;
      await page.evaluate(() => { window.__dns.views.dnssb = {}; delete window.__dns.views.google['www.example.com']; });
      await page.click('[data-action="check-again"]');
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.state === 'done', { message: 'done after Check again', timeout: 10000 });
      assert((await dnsLog(page)).length > before, 'asked again');
      await shot(page, opts, 'change-check-done-desktop-light-en');
    });

    await run.step('Esc while a slow round runs: the round\'s answers are shown, nothing is scheduled after it', async () => {
      // Every resolver serves 192.0.2.10 for www: "not yet, another value" everywhere, so the check keeps going.
      await openCheck(page, 'z=example.com&r=is+www+A+192.0.2.99');
      assertEqual((await checkInfo(page)).state, 'waiting', 'scheduled');
      await page.evaluate(() => { window.__dns.delay = 1500; });
      await page.click('[data-action="check-now"]');
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.state === 'running', { message: 'running' });
      await page.press('Escape');
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.state === 'user', { message: 'stopped during the round' });
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.round === '2', { message: 'the round ends', timeout: 10000 });
      const info = await checkInfo(page);
      assertEqual([info.state, info.nextAt, info.next], ['user', null, []], 'still stopped, nothing scheduled');
      assert(await page.evaluate(() => document.querySelector('[data-action="check-now"]').hidden && document.querySelector('[data-action="check-stop"]').hidden
        && !document.querySelector('[data-action="check-again"]').hidden), 'Check again, no Check now / Stop');
      assert(/Stopped\./.test(await text(page, '.chg-stopped')), 'says stopped');
      assertEqual(await resolverRows(page), [['cloudflare:pending/other', 'google:pending/other', 'dnssb:pending/other', 'cznic:pending/other']], 'the round\'s answers');
      await page.evaluate(() => { window.__dns.delay = 0; });
    });

    await run.step('no resolver answers at all: said after the first round, stopped as failed after three; Check again recovers', async () => {
      await page.evaluate(() => { for (const r of ['cloudflare', 'google', 'dnssb', 'cznic']) window.__dns.views[r] = { _status: 500 }; window.__dns.log.length = 0; });
      await openCheck(page, 'z=example.com&r=is+shop+A+203.0.113.7');
      let info = await checkInfo(page);
      assertEqual([info.headline, info.state], ['no-answer', 'waiting'], 'no answer yet, asking again');
      assert(/No resolver answered for 1 record set/.test(await text(page, '.chg-check-head-wrap')), 'the headline says so');
      for (const round of ['2', '3']) {
        await page.click('[data-action="check-now"]');
        await page.waitFor((r) => { const v = document.querySelector('[data-page="check"]'); return v.dataset.round === r && v.dataset.state !== 'running'; },
          { args: [round], message: `round ${round}`, timeout: 10000 });
      }
      info = await checkInfo(page);
      assertEqual([info.headline, info.state, info.nextAt], ['no-answer', 'failed', null], 'stopped as failed, not done');
      assert(/Stopped: no answer in three rounds in a row/.test(await text(page, '.chg-stopped')), 'the stop is explained');
      assert(await page.evaluate(() => !document.querySelector('[data-action="check-again"]').hidden), 'Check again offered');
      assertEqual((await dnsLog(page)).length, 12, '3 rounds × 4 resolvers');
      await shot(page, opts, 'change-check-failed-desktop-light-en');
      await page.evaluate(() => { window.__dns.views = { google: {} }; });
      await page.click('[data-action="check-again"]');
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.state === 'done', { message: 'done after Check again', timeout: 10000 });
    });

    await run.step('a link near the length limit, full of ; = : @ (a DMARC record with its report addresses), opens', async () => {
      const tail = '; rua=mailto:dmarc@example.com,mailto:d2@example.net; ruf=mailto:f@example.com; fo=1:d:s; adkim=s; aspf=s'.repeat(3);
      const query = await page.evaluate(async (tl) => {
        const { encodeCheck } = await import(new URL('assets/js/lib/changecheck.js', document.baseURI).href);
        const { normalizeValue } = await import(new URL('assets/js/lib/fixes.js', document.baseURI).href);
        const values = [];
        let q = null;
        for (let n = 1; n < 40; n++) {
          values.push(normalizeValue('TXT', `v=DMARC1; p=quarantine; pct=${n}${tl}`));
          const enc = encodeCheck({ zone: 'example.com', sets: [{ name: '_dmarc.example.com', type: 'TXT', mode: 'has', family: null, values: [...values], old: null, maxTtl: null }] });
          if (!enc.ok) break;
          q = enc.query;
        }
        return q;
      }, tail);
      assert(query.length > 3800 && query.length <= 4000, `near the limit: ${query.length}`);
      await openCheck(page, query);
      assert(await page.evaluate(() => document.querySelector('[data-page="check"]').dataset.state !== 'bad'), 'not refused as too long');
    });

    await run.step('a language switch keeps the answers and asks nothing again', async () => {
      await openCheck(page, wrongQuery);
      const before = (await dnsLog(page)).length;
      await setLangUi(page, 'tr');
      await page.waitFor(() => /Tamam: tüm çözümleyiciler/.test(document.querySelector('.chg-check-head-wrap')?.textContent || ''), { message: 'Turkish headline' });
      assertEqual((await dnsLog(page)).length, before, 'no new query');
      await setLangUi(page, 'en');
    });

    await run.step('opened offline: the check says so and schedules nothing; back online it asks by itself', async () => {
      const setOnline = async (on) => {
        await page.send('Network.emulateNetworkConditions', { offline: !on, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
        await page.waitFor((o) => navigator.onLine === o, { args: [on], message: `navigator.onLine ${on}` });
      };
      await page.evaluate(() => { window.__dns.views = {}; window.__dns.log.length = 0; });
      await setOnline(false);
      try {
        await page.evaluate(() => { window.location.hash = '#/change/check?z=example.com&r=is+www+A+192.0.2.10'; });
        await page.waitFor(() => /You are offline/.test(document.querySelector('.chg-check-meta')?.textContent || ''), { message: 'offline note' });
        const info = await checkInfo(page);
        assertEqual([info.round, info.nextAt, info.state], [0, null, 'waiting'], 'no round, nothing scheduled');
        assert(!/Next check in/.test(await text(page, '.chg-check-meta')), `no countdown: ${await text(page, '.chg-check-meta')}`);
        assert(await page.evaluate(() => document.querySelector('#page-offline').hidden), 'no shell note: the form works offline, the page says what waits');
        assertEqual(await dnsLog(page), [], 'nothing asked');
      } finally {
        await setOnline(true);
      }
      await page.waitFor(() => document.querySelector('[data-page="check"]').dataset.state === 'done', { message: 'asked once back online', timeout: 10000 });
      assertEqual((await dnsLog(page)).length, 4, 'one round, 4 resolvers');
    });

    await run.step('a link that cannot be read says why and sends nothing', async () => {
      await page.evaluate(() => { window.__dns.log.length = 0; window.location.hash = '#/change/check?z=example.com&r=is+www+NS+ns1.example.com.'; });
      await page.waitFor(() => /This check link cannot be read/.test(document.querySelector('#page-body')?.textContent || ''), { message: 'bad link' });
      assert(/One of its records cannot be read: is www NS/.test(await text(page, '#page-body')), 'the record named');
      assertEqual(await dnsLog(page), [], 'nothing sent');
    });

    await run.step('Retry after the check page crashed opens the check page again, on its link', async () => {
      const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
      try {
        await tab.send('Network.enable');
        await tab.send('Network.setBlockedURLs', { urls: ['https://*'] });
        await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript() });
        // views/change.js as served, with a mount() that throws the first time (patched in flight).
        await tab.send('Fetch.enable', { patterns: [{ urlPattern: '*/views/change.js', requestStage: 'Response' }] });
        tab.conn.on('Fetch.requestPaused', async (p) => {
          const { body, base64Encoded } = await tab.send('Fetch.getResponseBody', { requestId: p.requestId });
          const src = (base64Encoded ? Buffer.from(body, 'base64').toString('utf8') : body).replace('export function mount(container, ctx) {',
            "export function mount(container, ctx) {\n  if (!globalThis.__crashed) { globalThis.__crashed = true; throw new Error('mount crashed once'); }");
          await tab.send('Fetch.fulfillRequest', {
            requestId: p.requestId, responseCode: 200, body: Buffer.from(src, 'utf8').toString('base64'),
            responseHeaders: [{ name: 'Content-Type', value: 'text/javascript; charset=utf-8' }]
          });
        }, tab.sessionId);
        const hash = '#/change/check?z=example.com&r=is+www+A+192.0.2.10';
        await tab.goto(`${server.url}${hash}`);
        await tab.waitFor(() => window.__crashed && document.querySelector('#page-body .alert button'), { message: 'the crash with its Retry', timeout: 15000 });
        await tab.evaluate(() => document.querySelector('#page-body .alert button').click());
        await tab.waitFor(() => document.querySelector('.chg-view[data-page]'), { message: 'a page after Retry', timeout: 15000 });
        assertEqual(await tab.evaluate(() => [!!document.querySelector('[data-page="check"]'), location.hash]), [true, hash], 'the check page, its link kept');
      } finally {
        await tab.close();
      }
    });

    run.group('Phones 320 / 375 px, light / dark, English / Turkish');
    await run.step('the form with its outputs and the check page fit without horizontal scroll', async () => {
      // CZ.NIC fails: the check page carries the longest verdict badge ("No answer (server error)").
      await page.evaluate(() => { window.__dns.views = { cznic: { _status: 500 } }; });
      for (const [lang, theme] of [['en', 'light'], ['tr', 'dark']]) {
        await setLangUi(page, lang);
        await page.emulateMedia({ 'prefers-color-scheme': theme });
        await page.evaluate((q) => { window.location.hash = `#/change?t=acme-txt&name=*.example.com&tokens=${q}`; }, TOKEN_A);
        await waitOutputs(page, 'outputs on the phone');
        for (const width of [320, 375]) {
          await page.setViewport({ width, height: 740, mobile: true });
          await assertNoHorizontalScroll(page, `form ${lang} ${theme} ${width}`);
        }
        await shot(page, opts, `change-form-phone-${theme}-${lang}`);
        // Microsoft 365 not read: the longest set badge ("Add or change") next to the DKIM CNAMEs.
        await page.setViewport({ width: 1440, height: 900 });
        await page.evaluate(() => { window.location.hash = '#/change?t=m365&domain=example.com&tenant=example.onmicrosoft.com'; });
        await page.waitFor(() => document.querySelectorAll('.fix-set[data-action="set"]').length === 2, { message: 'two sets to add or change', timeout: 8000 });
        for (const width of [320, 375]) {
          await page.setViewport({ width, height: 740, mobile: true });
          await assertNoHorizontalScroll(page, `m365 ${lang} ${theme} ${width}`);
        }
        await shot(page, opts, `change-m365-unread-phone-${theme}-${lang}`);
        await openCheck(page, checkQuery);
        for (const width of [320, 375]) {
          await page.setViewport({ width, height: 740, mobile: true });
          await assertNoHorizontalScroll(page, `check ${lang} ${theme} ${width}`);
        }
        await shot(page, opts, `change-check-phone-${theme}-${lang}`);
        await page.setViewport({ width: 1440, height: 900 });
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Hygiene');
    await run.step('nothing left the page', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'change', origin));
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish();
}

main().catch((err) => {
  process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
  process.exitCode = 1;
});
