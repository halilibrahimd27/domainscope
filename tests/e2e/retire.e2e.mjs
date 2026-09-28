#!/usr/bin/env node
/**
 * retire.e2e.mjs — end-to-end test of "Retire an IP" in a real headless Chrome/Edge. OFFLINE:
 * every DoH query is answered in the page by a fake resolver built from the table below (window.fetch
 * wrapped before the app loads), HackerTarget's reverse IP and ip.thc.org's lookup are answered by
 * the same wrapper, every other https:// request is blocked, and every request that leaves the
 * page's origin is counted through CDP.
 *
 *   node tests/e2e/retire.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry (IP addresses group, after Reverse DNS), the empty state, the address box's
 * issues (too wide, junk, private space), the domain box filled in from the page session (a zone
 * imported under Zone File, the last scan), the known host names per domain, a check of
 * 192.0.2.10 (MX and SPF break mail, an include at a provider, an in-bailiwick name server with its
 * glue, an A record, an HTTPS hint, a CNAME chain into another zone, the zone's proxied origin, a
 * record only in the file, an internal name never sent), the evidence chips, the owner from the
 * server list, Copy summary, CSV / JSON, the passive lookup (two services, unverified until checked;
 * "Check these too" adds their domains and checks again: one gone, one live), the Small-wordlist
 * discovery offered for a domain without host names (and nothing run before the click), Stop and
 * the keyboard focus, a shared link that fills the form and waits, a carried address (never over a
 * draft), the 375 px layout in TR / EN × light / dark, zero console errors / CSP violations /
 * missing i18n keys, nothing sent outside the page.
 *
 * Data is documentation space only (example.com / .net / .org, 192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24, 2001:db8::/32) plus the Cloudflare edge 104.16.1.1.
 */

import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, sleep, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';

const CF_EDGE = '104.16.1.1';

/** The fake DNS: name → { TYPE: [data…], CNAME: target }; a name missing is NXDOMAIN. */
export function fakeTable() {
  const T = {};
  const add = (name, type, ...data) => {
    const node = T[name] || (T[name] = {});
    (node[type] || (node[type] = [])).push(...data);
  };
  add('example.com', 'A', '192.0.2.10');
  add('example.com', 'MX', { preference: 10, exchange: 'mail.example.com' }, { preference: 20, exchange: 'mx2.example.net' });
  add('example.com', 'NS', 'ns1.example.com', 'ns2.example.net');
  add('example.com', 'TXT', ['v=spf1 ip4:192.0.2.10 include:_spf.example.net ~all'], ['site-verification=example']);
  add('example.com', 'HTTPS', { priority: 1, target: '', params: { alpn: ['h2'], ipv4hint: ['192.0.2.10'] } });
  T['www.example.com'] = { CNAME: 'lb.example.net' };
  add('lb.example.net', 'A', '192.0.2.10', '198.51.100.5');
  add('api.example.com', 'A', '198.51.100.6');
  add('mail.example.com', 'A', '192.0.2.10');
  add('mx2.example.net', 'A', '198.51.100.8');
  add('ns1.example.com', 'A', '192.0.2.10');
  add('ns2.example.net', 'A', '198.51.100.9');
  add('_spf.example.net', 'TXT', ['v=spf1 ip4:192.0.2.0/24 -all']);
  // The zone's proxied origin: public DNS shows the proxy's edge.
  add('shop.example.com', 'A', CF_EDGE);
  // example.net: its apex elsewhere; one host on the address, found only by a discovery (the Small wordlist has www).
  add('example.net', 'A', '198.51.100.20');
  add('www.example.net', 'A', '192.0.2.10');
  // Passive hits: one still on the address, one gone elsewhere.
  add('example.org', 'A', '198.51.100.30');
  add('blog.example.org', 'A', '192.0.2.10');
  add('shop.example.net', 'A', '198.51.100.77');
  return T;
}

/** A Cloudflare export of example.com (the zone the Zone File view imports). */
export const ZONE = [
  ';; Domain:     example.com.',
  ';; Exported:   2026-09-28 08:00:00',
  'example.com.\t3600\tIN\tSOA\tns1.example.com. hostmaster.example.com. 2026092801 10000 2400 604800 3600',
  'example.com.\t86400\tIN\tNS\tns1.example.com.',
  'example.com.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:false',
  'shop.example.com.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:true',
  'old.example.com.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:false',
  'intranet.example.com.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:false',
  'mail.example.com.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:false',
  'www.example.com.\t1\tIN\tCNAME\tlb.example.net. ; cf_tags=cf-proxied:false',
  'example.com.\t1\tIN\tMX\t10 mail.example.com.',
  'example.com.\t1\tIN\tTXT\t"v=spf1 ip4:192.0.2.10 include:_spf.example.net ~all"',
  ''
].join('\n');

/**
 * In-page stubs: DoH from the table (CNAMEs chased, NXDOMAIN outside it), HackerTarget and ip.thc.org.
 * `window.__fakeDnsRcodes` forces an answer's rcode: keyed 'name|TYPE', 'name' or '*' (every query).
 */
export const fakeScript = (table) => `(() => {
  const T = ${JSON.stringify(table)};
  window.__fakeDnsLog = [];
  window.__passiveLog = [];
  window.__fakeDnsDelay = 0;
  window.__fakeDnsRcodes = {};
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url.startsWith('https://api.hackertarget.com/reverseiplookup/')) {
      window.__passiveLog.push(url);
      return new Response('mail.example.com\\nshop.example.net\\n', { status: 200, headers: { 'content-type': 'text/plain' } });
    }
    if (url.startsWith('https://ip.thc.org/api/v1/lookup')) {
      window.__passiveLog.push(url + ' ' + (init && init.body));
      return json({ matching_records: 1, domains: [{ domain: 'blog.example.org', apex_domain: 'example.org' }], next_page_state: '' });
    }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__fakeDnsLog.push({ name, type: q.type });
    if (window.__fakeDnsDelay) {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, window.__fakeDnsDelay);
        init?.signal?.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
      });
    }
    const answers = [];
    let cur = name;
    const forced = window.__fakeDnsRcodes;
    let rcode = forced[name + '|' + q.type] || forced[name] || forced['*'] || 'NOERROR';
    for (let hop = 0; hop < 8 && rcode === 'NOERROR'; hop += 1) {
      const node = T[cur];
      if (!node) { rcode = 'NXDOMAIN'; break; }
      if (node.CNAME && q.type !== 'CNAME') {
        answers.push({ name: cur, type: 'CNAME', ttl: 300, data: node.CNAME });
        cur = node.CNAME;
        continue;
      }
      for (const data of node[q.type] || []) answers.push({ name: cur, type: q.type, ttl: 300, data });
      break;
    }
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode,
      questions: [{ name: q.name, type: q.type }], answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

async function nodeChecks(run) {
  const V = await import('../../assets/js/views/retire.js');
  run.group('Node: views/retire.js helpers');
  await run.step('share params, the prefill, the change texts', () => {
    assertEqual(V.shareParams('192.0.2.10\n# old\n192.0.2.0/28', 'Example.COM\nexample.net'), { ips: '192.0.2.10,192.0.2.0/28', domains: 'example.com,example.net' }, 'share');
    assertEqual(V.shareParams('', 'example.com'), null, 'no address, no link');
    assertEqual(V.shareParams('192.0.2.10', Array.from({ length: 30 }, (_, i) => `host-${i}.example.com`).join('\n')), null, 'too long for a link');
    assertEqual(V.linkText('192.0.2.10,192.0.2.0/28'), '192.0.2.10\n192.0.2.0/28', 'link text');
    assertEqual(V.prefillDomains({ scanHosts: { domains: ['example.com', 'example.net'] }, zone: { origin: 'example.org' } }),
      { domains: ['example.com', 'example.net', 'example.org'], sources: ['scan', 'zone'] }, 'prefill');
    assertEqual(V.prefillDomains({}), { domains: [], sources: [] }, 'nothing known');
    const base = { key: 'k', group: 'example.com', groupKind: 'domain', name: 'example.com', type: 'TXT', value: 'ip4:192.0.2.10', addresses: ['192.0.2.10'], blocks: ['192.0.2.10/32'], via: ['example.com'], roles: [], sources: ['spf'], foundFor: ['example.com'], spf: { holder: 'example.com', range: '192.0.2.10/32' } };
    assertEqual(V.changeText({ ...base, severity: 'mail', action: 'remove' }).key, 'retire.act.remove.spf', 'SPF remove');
    assertEqual(V.changeText({ ...base, severity: 'stale', action: 'remove' }).key, 'retire.act.remove.spfStale', 'stale SPF');
    assertEqual(V.changeText({ ...base, type: 'MX', value: '10 mail.example.com', severity: 'mail', action: 'repoint', spf: null }), { key: 'retire.act.repoint.mx', params: { host: 'mail.example.com' } }, 'MX');
    assertEqual(V.changeText({ ...base, severity: 'unknown', action: 'check', reason: 'macro', value: 'exists:%{i}.x.example.com' }).key, 'retire.act.check.macro', 'macro');
  });
}

const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent || '', sel);
const jsClick = (page, sel) => page.evaluate((s) => { const el = document.querySelector(s); if (!el) throw new Error(`no ${s}`); el.click(); }, sel);
const typeInto = (page, role, value) => page.evaluate(([r, v]) => {
  const ta = document.querySelector(`[data-role="${r}"]`);
  ta.value = v;
  ta.dispatchEvent(new Event('input', { bubbles: true }));
}, [role, value]);
const issues = (page) => page.evaluate(() => [...document.querySelectorAll('.retire-issues .alert')].map((a) => a.dataset.issue));
const dnsCount = (page) => page.evaluate(() => window.__fakeDnsLog.length);
const waitDone = (page, message = 'check done', status = 'done') => page.waitFor((s) => document.querySelector('.retire-job')?.dataset.status === s
  && !document.querySelector('[data-action="retire-run"]').hidden, { args: [status], timeout: 30000, message });
/** The change rows: [group, severity, name, type, value, verified]. */
const rows = (page) => page.evaluate(() => [...document.querySelectorAll('.retire-group')].flatMap((card) => [...card.querySelectorAll('tbody tr')].map((tr) => [
  card.dataset.group, tr.dataset.severity, tr.querySelector('.retire-name').textContent, tr.dataset.type,
  tr.querySelector('.retire-value .mono').textContent, tr.dataset.verified
])));
const chips = (page) => page.evaluate(() => [...document.querySelectorAll('.retire-chips .src-chip')].map((c) => [c.dataset.source, c.dataset.state]));

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  await nodeChecks(run);

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
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript(fakeTable()) });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/retire: nav entry after Reverse DNS in the IP addresses group, empty state, nothing sent', async () => {
      await page.goto(`${server.url}#/retire`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'retire');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('#app-nav .nav-group')].find((g) => g.querySelector('.nav-link[data-view="retire"]'));
        return { links: [...group.querySelectorAll('.nav-link')].map((a) => a.dataset.view), title: document.querySelector('h1.page-title').textContent };
      });
      assertEqual(nav, { links: ['ip', 'ptr', 'retire'], title: 'Retire an IP' }, 'nav');
      assert(await page.evaluate(() => !!document.querySelector('.retire-empty .empty-title')), 'empty state');
      assertEqual(await dnsCount(page), 0, 'nothing sent');
    });

    await run.step('the address box: too wide, junk, private space; a /28 counts its addresses', async () => {
      await typeInto(page, 'retire-ips', '192.0.2.0/23');
      await page.waitFor(() => document.querySelector('.retire-issues .alert[data-issue="too-large"]'), { message: 'too large' });
      await typeInto(page, 'retire-ips', 'web01');
      await page.waitFor(() => document.querySelector('.retire-issues .alert[data-issue="nothing"]'), { message: 'nothing' });
      assertEqual(await issues(page), ['invalid', 'nothing'], 'junk');
      await typeInto(page, 'retire-ips', '10.0.0.5');
      await page.waitFor(() => document.querySelector('.retire-issues .alert[data-issue="private"]'), { message: 'private' });
      await typeInto(page, 'retire-ips', '192.0.2.5/28');
      await page.waitFor(() => /16 addresses/.test(document.querySelector('.retire-parsed')?.textContent || ''), { message: '16 addresses' });
      assertEqual(await issues(page), ['host-bits'], 'host bits');
      // Run with no domain: the domain box says so.
      await typeInto(page, 'retire-ips', '192.0.2.10');
      await typeInto(page, 'retire-domains', '');
      await page.click('[data-action="retire-run"]');
      await page.waitFor(() => document.querySelector('.retire-domains .field-error, .retire-domains [role="alert"]')?.textContent, { message: 'domain required' });
      assertEqual(await dnsCount(page), 0, 'nothing sent');
    });

    /** The verdict and what the head card says around it. */
    const verdict = () => page.evaluate(() => {
      const v = document.querySelector('[data-role="retire-verdict"]');
      return {
        variant: [...v.classList].find((c) => /^alert-(ok|info|warn|error)$/.test(c)),
        title: v.querySelector('.alert-title')?.textContent || '',
        message: v.querySelector('.alert-message')?.textContent || '',
        stopped: /Stopped/.test(document.querySelector('.retire-head').textContent),
        clean: !!document.querySelector('[data-role="retire-clean"]')
      };
    });
    const chipValues = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.retire-chips .src-chip')]
      .map((c) => [c.dataset.source, [c.dataset.state, c.querySelector('.src-chip-value').textContent]])));

    await run.step('every lookup failing (SERVFAIL): never the green "nothing"; the card names what failed; the SPF record "cannot tell"', async () => {
      await page.evaluate(() => { window.__fakeDnsRcodes = { '*': 'SERVFAIL' }; });
      await typeInto(page, 'retire-domains', 'servfail.example.org');
      await page.click('[data-action="retire-run"]');
      await waitDone(page, 'the SERVFAIL check');
      await page.evaluate(() => { window.__fakeDnsRcodes = {}; });
      const v = await verdict();
      assertEqual([v.variant, v.title, v.clean], ['alert-warn', 'Nothing found pointing at 192.0.2.10, but not everything could be checked', false], 'verdict');
      assert(/lookups failed · 1 SPF result cannot be told from here: the list may be incomplete\./.test(v.message), v.message);
      const failures = await text(page, '.retire-group[data-group="servfail.example.org"] [data-role="retire-failures"]');
      assert(/^Lookups that failed for servfail\.example\.org: MX, NS, the SPF record, the HTTPS record, 1 host name \(servfail\.example\.org\)\./.test(failures), failures);
      assertEqual(await rows(page), [['servfail.example.org', 'unknown', 'servfail.example.org', 'TXT', '—', 'unknown']], 'the SPF row');
      const c = await chipValues();
      assertEqual([c.dns[0], c.spf], ['failed', ['failed', '1 could not be read']], 'chips');
      assert(await page.evaluate(() => document.querySelector('.retire-stats [data-stat="unknown"]') !== null), 'a "Cannot tell" stat');
      await shot(page, opts, 'retire-servfail-desktop-light-en');
    });

    await run.step('Stop before the first domain finishes: never "nothing"; public DNS and SPF read "not checked"', async () => {
      // Every answer waits 5 s: the stop comes long before the first domain can finish.
      await page.evaluate(() => { window.__fakeDnsDelay = 5000; });
      await typeInto(page, 'retire-domains', 'slow.example.org');
      await page.click('[data-action="retire-run"]');
      await page.waitFor(() => document.querySelector('.retire-job')?.dataset.status === 'running' && !document.querySelector('[data-action="retire-stop"]').hidden, { message: 'running' });
      await jsClick(page, '[data-action="retire-stop"]');
      await waitDone(page, 'stopped at once', 'cancelled');
      await page.evaluate(() => { window.__fakeDnsDelay = 0; });
      const v = await verdict();
      assertEqual([v.variant, v.title, v.stopped, v.clean], ['alert-warn', 'Nothing found pointing at 192.0.2.10, but not everything could be checked', true, false], 'verdict');
      assert(/1 domain not checked/.test(v.message), v.message);
      const c = await chipValues();
      assertEqual([c.dns, c.spf], [['idle', 'not checked'], ['idle', 'not checked']], 'chips');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.retire-group').length), 0, 'no card for a domain never checked');
    });

    await run.step('a zone imported under Zone File and the last scan fill an empty domain box; the host names per domain', async () => {
      const before = await dnsCount(page);
      await gotoRoute(page, 'zone');
      await page.evaluate(() => { document.querySelectorAll('.zone-import-folded, .zone-paste').forEach((d) => { d.open = true; }); });
      await page.type('[data-role="zone-paste"]', ZONE);
      await page.click('[data-action="zone-paste-import"]');
      await page.waitFor(async () => {
        const { state } = await import('./assets/js/state.js');
        return !!(state.getSession('zone') && state.getSession('zone').records);
      }, { message: 'zone published', timeout: 15000 });
      await page.evaluate(async () => {
        const { state } = await import('./assets/js/state.js');
        state.setSession('scanHosts', { domains: ['example.com'], names: ['www.example.com', 'api.example.com', 'www.example.org'], resolving: [], finishedAt: new Date() });
        state.setInventory('web01 192.0.2.10 198.51.100.44\ndb01 198.51.100.6');
      });
      // Leave the view with an empty domain box: it is filled in on the way back.
      await gotoRoute(page, 'retire');
      await typeInto(page, 'retire-domains', '');
      await gotoRoute(page, 'about');
      await gotoRoute(page, 'retire');
      const form = await page.evaluate(() => ({
        domains: document.querySelector('[data-role="retire-domains"]').value,
        filled: document.querySelector('.retire-filled')?.dataset.filled || '',
        hosts: [...document.querySelectorAll('.retire-hosts-list li')].map((li) => [li.dataset.domain, li.dataset.hosts])
      }));
      assertEqual(form.domains, 'example.com', 'the scan\'s domain and the zone\'s origin, once');
      assertEqual(form.filled, 'scan', 'says where from (the zone adds no other domain)');
      // www, api (scan) + shop, old, mail, ns1 (zone; the internal name left out).
      assertEqual(form.hosts, [['example.com', '6']], 'known host names');
      assertEqual(await dnsCount(page), before, 'nothing sent');
      await shot(page, opts, 'retire-form-desktop-light-en');
    });

    let firstRunQueries = 0;
    await run.step('a check of 192.0.2.10: every reference, worst first, grouped by domain; the internal name never sent', async () => {
      await typeInto(page, 'retire-ips', '192.0.2.10');
      await page.click('[data-action="retire-run"]');
      await waitDone(page);
      firstRunQueries = await dnsCount(page);
      const got = await rows(page);
      const want = [
        ['example.com', 'mail', 'example.com', 'MX', '10 mail.example.com', 'live'],
        ['example.com', 'mail', 'example.com', 'TXT', 'ip4:192.0.2.10', 'live'],
        ['example.com', 'mail', 'mail.example.com', 'A', '192.0.2.10', 'live'],
        ['example.com', 'ns', 'example.com', 'NS', 'ns1.example.com', 'live'],
        ['example.com', 'ns', 'ns1.example.com', 'A', '192.0.2.10', 'live'],
        ['example.com', 'live', 'example.com', 'A', '192.0.2.10', 'live'],
        ['example.com', 'live', 'example.com', 'HTTPS', '192.0.2.10', 'live'],
        ['example.com', 'live', 'intranet.example.com', 'A', '192.0.2.10', 'internal'],
        ['example.com', 'origin', 'shop.example.com', 'A', '192.0.2.10', 'hidden'],
        ['example.com', 'chain', 'www.example.com', 'CNAME', 'lb.example.net', 'live'],
        ['example.com', 'file', 'old.example.com', 'A', '192.0.2.10', 'file'],
        ['other', 'mail', '_spf.example.net', 'TXT', 'ip4:192.0.2.0/24', 'live'],
        ['other', 'live', 'lb.example.net', 'A', '192.0.2.10', 'live']
      ];
      assertEqual(got, want, 'rows');
      const log = await page.evaluate(() => window.__fakeDnsLog.map((q) => q.name));
      assert(!log.some((n) => n.startsWith('intranet.')), 'the internal zone name is never sent');
      assertEqual(await chips(page), [['dns', 'ok'], ['spf', 'ok'], ['zone', 'ok'], ['servers', 'ok'], ['passive', 'idle']], 'chips');
      const head = await page.evaluate(() => ({
        verdict: document.querySelector('[data-role="retire-verdict"] .alert-title')?.textContent,
        owner: document.querySelector('.retire-owner-list li')?.dataset.server,
        stats: Object.fromEntries([...document.querySelectorAll('.retire-stats .stat')].map((s) => [s.dataset.stat, s.querySelector('.stat-value').textContent])),
        glue: document.querySelector('.retire-group tr[data-type="NS"] .retire-change')?.dataset.action,
        chip: document.querySelector('[data-role="target-chip"] .target-chip-value')?.textContent || null
      }));
      assertEqual(head, {
        verdict: '12 records break something once 192.0.2.10 is gone', owner: 'web01',
        stats: { breaking: '12', mail: '4', file: '1' }, glue: 'glue', chip: '192.0.2.10'
      }, 'head');
      await shot(page, opts, 'retire-results-desktop-light-en');
    });

    await run.step('Copy summary (Markdown), CSV and JSON of the change list', async () => {
      await stubClipboard(page);
      await jsClick(page, '[data-action="copy-summary"]');
      const [md] = await takeClipboard(page);
      assert(md.startsWith('**Retire an IP · `192.0.2.10`**\n- 13 records still point at it · 12 break something once it is gone\n'), md);
      assert(md.includes('- Owned by 1 server in your list'), 'a count of servers');
      assert(!md.includes('web01'), 'never a server name');
      assert(/#\/retire\?domains=example\.com$/m.test(md), `the link leaves out the inventory address: ${md}`);
      await jsClick(page, '[data-export="csv"]');
      await jsClick(page, '[data-export="json"]');
      const [csv, json] = await takeDownloads(page);
      assert(/^ip-retire-192\.0\.2\.10-\d{8}-\d{4}\.csv$/.test(csv.name), csv.name);
      assertEqual(csv.text.split('\r\n')[0], 'group,severity,name,type,value,address,action,verified,via,sources,line', 'CSV header');
      assert(csv.text.includes('example.com,mail,example.com,TXT (SPF),ip4:192.0.2.10,192.0.2.10,remove,live'), 'SPF row');
      const doc = JSON.parse(json.text);
      assertEqual([doc.schema, doc.addresses, doc.domains, doc.changes.length, doc.owners.map((o) => o.name)],
        ['domainscope.ip-retire/1', ['192.0.2.10/32'], ['example.com'], 13, ['web01']], 'JSON');
    });

    await run.step('a domain without host names gets the Small-wordlist discovery offered, never run before the click', async () => {
      await typeInto(page, 'retire-domains', 'example.com\nexample.net');
      await page.waitFor(() => document.querySelector('.retire-hosts-list li[data-domain="example.net"]'), { message: 'example.net listed' });
      const offer = await page.evaluate(() => ({
        bare: [...document.querySelectorAll('.retire-hosts-list li[data-hosts="0"]')].map((li) => li.dataset.domain),
        button: !!document.querySelector('[data-action="retire-discover"]')
      }));
      assertEqual(offer, { bare: ['example.net'], button: true }, 'offer');
      assert(!(await page.evaluate(() => window.__fakeDnsLog.some((q) => q.name === 'www.example.net'))), 'no guess sent yet');
      await jsClick(page, '[data-action="retire-discover"]');
      await page.waitFor(() => [...document.querySelectorAll('.retire-group[data-group="example.net"] tbody tr')].some((tr) => tr.querySelector('.retire-name').textContent === 'www.example.net'),
        { timeout: 60000, message: 'discovered www.example.net checked' });
      await waitDone(page, 'the check after the discovery');
      const hosts = await page.evaluate(() => document.querySelector('.retire-hosts-list li[data-domain="example.net"]')?.dataset.hosts);
      assert(Number(hosts) >= 1, `example.net has discovered host names now: ${hosts}`);
      await shot(page, opts, 'retire-discovered-desktop-light-en');
    });

    await run.step('the passive lookup: two services on a click, unverified until checked; "Check these too" adds their domains', async () => {
      assertEqual(await page.evaluate(() => window.__passiveLog.length), 0, 'nothing asked before the click');
      await jsClick(page, '[data-action="retire-passive"]');
      await page.waitFor(() => document.querySelector('.retire-group[data-kind="passive"]'), { message: 'passive group' });
      const log = await page.evaluate(() => window.__passiveLog);
      assertEqual(log.length, 2, 'one request to each service');
      assert(log[1].includes('"ip_address":"192.0.2.10"'), log[1]);
      // mail.example.com is checked already: it joins its row; shop.example.net was discovered and
      // resolves elsewhere now: gone. Only blog.example.org is new and unverified.
      const passive = (await rows(page)).filter((r) => r[0] === 'passive');
      assertEqual(passive, [['passive', 'stale', 'blog.example.org', 'A', '192.0.2.10', 'unverified']], 'unverified hits');
      const mail = await page.evaluate(() => document.querySelector('.retire-group[data-group="example.com"] tr[data-key="mail.example.com|A|192.0.2.10"] .retire-evidence')?.textContent || '');
      assert(/passive reverse IP/.test(mail), `the checked name carries the passive source: ${mail}`);
      const gone = () => page.evaluate(() => [...document.querySelectorAll('.retire-gone-list li .mono')].map((x) => x.textContent));
      assertEqual(await gone(), ['shop.example.net'], 'gone');
      assert((await chips(page)).some(([s, st]) => s === 'passive' && st === 'ok'), 'passive chip');
      await shot(page, opts, 'retire-passive-desktop-light-en');
      await jsClick(page, '[data-action="retire-check-too"]');
      await waitDone(page, 'the check with the passive domains');
      const form = await page.evaluate(() => document.querySelector('[data-role="retire-domains"]').value);
      assertEqual(form, 'example.com\nexample.net\nexample.org', 'their domain joined the list');
      const after = await rows(page);
      assert(after.some((r) => r[0] === 'example.org' && r[2] === 'blog.example.org' && r[5] === 'live'), 'blog.example.org is live');
      assert(!after.some((r) => r[0] === 'passive'), 'nothing unverified left');
      assertEqual(await gone(), ['shop.example.net'], 'still gone');
    });

    await run.step('Stop: the keyboard focus moves Check ⇄ Stop; a stopped check says so', async () => {
      // A domain nothing has asked about yet (the DohClient caches every answer it got).
      await typeInto(page, 'retire-domains', 'example.com\nstop.example.org');
      await page.evaluate(() => { window.__fakeDnsDelay = 400; });
      await page.evaluate(() => document.querySelector('[data-action="retire-run"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.activeElement?.dataset.action === 'retire-stop', { message: 'focus on Stop' });
      await page.press('Escape');
      await waitDone(page, 'stopped', 'cancelled');
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'retire-run', 'focus back on Check');
      assert(/Stopped/.test(await text(page, '.retire-head')), 'stopped note');
      const groups = await page.evaluate(() => [...document.querySelectorAll('.retire-group')].map((g) => g.dataset.group));
      assert(groups.includes('example.com') && !groups.includes('stop.example.org'), `only the finished domain is listed: ${groups}`);
      await page.evaluate(() => { window.__fakeDnsDelay = 0; });
      await typeInto(page, 'retire-domains', 'example.com\nexample.net\nexample.org');
      await page.click('[data-action="retire-run"]');
      await waitDone(page, 'a full check again');
    });

    await run.step('a shared link fills the form and waits; a carried address replaces the last run, never a draft', async () => {
      const before = await dnsCount(page);
      await page.evaluate(() => { location.hash = '#/retire?ips=198.51.100.7&domains=example.org'; });
      await page.waitFor(() => document.querySelector('[data-role="retire-ips"]').value === '198.51.100.7', { message: 'link filled' });
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="retire-domains"]').value, document.querySelector('.retire-prompt .alert')?.dataset.prompt]),
        ['example.org', 'link'], 'prompt');
      await sleep(200);
      assertEqual(await dnsCount(page), before, 'the link sent nothing');
      // A carried address (run=0) over a draft: the draft stays.
      await typeInto(page, 'retire-ips', '203.0.113.9');
      await page.evaluate(() => { location.hash = '#/retire?ips=192.0.2.44&run=0'; });
      await sleep(200);
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="retire-ips"]').value), '203.0.113.9', 'a draft stays');
      // Over the last check's address it is taken.
      await typeInto(page, 'retire-ips', '192.0.2.10');
      await page.evaluate(() => { location.hash = '#/retire?ips=192.0.2.45&run=0'; });
      await page.waitFor(() => document.querySelector('[data-role="retire-ips"]').value === '192.0.2.45', { message: 'carried address' });
      await typeInto(page, 'retire-ips', '192.0.2.10');
      await typeInto(page, 'retire-domains', 'example.com\nexample.net\nexample.org');
    });

    run.group('Phone 375×667, Turkish / English, light / dark');
    await run.step('the form and the change list at 375 px: labelled cards, no horizontal scroll', async () => {
      await page.click('[data-action="retire-run"]');
      await waitDone(page, 'phone check');
      await page.setViewport({ width: 375, height: 667, mobile: true });
      const phone = await page.evaluate(() => {
        const tr = document.querySelector('.retire-table tbody tr');
        const box = tr.getBoundingClientRect();
        return {
          head: getComputedStyle(document.querySelector('.retire-table thead')).display,
          label: getComputedStyle(tr.querySelector('td'), '::before').content,
          fits: box.right <= document.documentElement.clientWidth
        };
      });
      assertEqual(phone, { head: 'none', label: '"Severity"', fits: true }, 'phone cards');
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await page.waitFor(() => document.querySelector('.retire-job')?.dataset.status === 'done', { message: 'results kept after the language switch' });
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await page.evaluate(() => window.scrollTo(0, 0));
          await assertNoHorizontalScroll(page, `retire ${scheme} ${lang}`);
          await shot(page, opts, `retire-results-mobile-${scheme}-${lang}`);
        }
      }
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await assertNoHorizontalScroll(page, 'retire 320 px');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'tr');
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, opts, 'retire-results-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'retire', origin));
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

// Run only when executed directly (the fakes above are reused by other scripts).
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
    process.exitCode = 1;
  });
}
