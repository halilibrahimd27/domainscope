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
 * glue, an A record, an HTTPS hint, a CNAME chain into another zone, a zone wildcard asked through a
 * random name under it, the zone's proxied origin, a record only in the file, an internal name never
 * sent even with the Zone File hand-off toggle off), the evidence chips, the owner from the server
 * list, Copy summary, CSV / JSON, the passive lookup (its cost written next to the button, two
 * services, a cut-off ip.thc.org list said, unverified until checked; "Check these too" adds their
 * domains and checks again: one gone, one live), the Small-wordlist
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

/** The fake DNS: name → { TYPE: [data…], CNAME: target }; a name missing is answered by a `*.` entry one label up, else NXDOMAIN. */
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
  // The zone's wildcard: every name under dev.example.com answers with the address.
  add('*.dev.example.com', 'A', '192.0.2.10');
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
  '*.dev.example.com.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:false',
  'mail.example.com.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:false',
  'www.example.com.\t1\tIN\tCNAME\tlb.example.net. ; cf_tags=cf-proxied:false',
  'example.com.\t1\tIN\tMX\t10 mail.example.com.',
  'example.com.\t1\tIN\tTXT\t"v=spf1 ip4:192.0.2.10 include:_spf.example.net ~all"',
  ''
].join('\n');

/**
 * In-page stubs: DoH from the table (CNAMEs chased, a wildcard one label up, NXDOMAIN outside it), HackerTarget and ip.thc.org.
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
      // One page of a longer list: the view says the passive list is incomplete.
      return json({ matching_records: 250, domains: [{ domain: 'blog.example.org', apex_domain: 'example.org' }], next_page_state: 'page2' });
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
      const node = T[cur] || T['*.' + cur.split('.').slice(1).join('.')];
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

/** The two public addresses of the comparison: example.com's (IANA, well-known), as an old and a new server. */
const OLD_IP = '93.184.215.14';
const NEW_IP = '93.184.216.34';

/**
 * In-page fake Globalping for the old / new server comparison: an HTTPS GET at an address answers
 * like a web server of www.example.com. `window.__compareScenario`: 'differs' (the new server has
 * its own certificate, no HSTS header and another Server header), 'broken' (its certificate names
 * another host), 'down' (neither address answers), 'origin-ca' (both serve the same answer and the
 * same certificate, which the probe does not trust: an origin CA behind a CDN).
 * `window.__gp.allowUpTo`: measurements numbered above it stay in progress. Every call is logged
 * in window.__gp.
 */
const fakeCompareScript = () => `(() => {
  const gp = window.__gp = { calls: [], n: 0, remaining: 250, measurements: {}, allowUpTo: Infinity };
  window.__compareScenario = 'differs';
  const prevFetch = window.fetch;
  const json = (v, status = 200, headers = {}) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json', ...headers } });
  const probe = { continent: 'EU', region: 'Western Europe', country: 'DE', city: 'Frankfurt', asn: 24940, network: 'Hetzner Online', tags: ['datacenter-network'] };
  const body = '<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1></body></html>';
  const cert = (fp, names) => ({
    authorized: true, protocol: 'TLSv1.3', cipherName: 'TLS_AES_128_GCM_SHA256', createdAt: '2026-09-01T00:00:00.000Z', expiresAt: '2026-12-30T23:59:59.000Z',
    issuer: { C: 'US', O: 'Example Test CA', CN: 'Example Test CA R1' }, subject: { CN: names[0], alt: names.map((n) => 'DNS:' + n).join(', ') },
    keyType: 'EC', keyBits: 256, serialNumber: '0A:0B', fingerprint256: Array.from({ length: 32 }, () => fp).join(':')
  });
  function result(ip, host, path) {
    if (window.__compareScenario === 'down') return { status: 'failed', rawOutput: 'connect ECONNREFUSED ' + ip + ':443', timings: {} };
    const twin = window.__compareScenario === 'origin-ca';
    const old = ip === '${OLD_IP}' || twin;
    const broken = !old && window.__compareScenario === 'broken';
    const headers = { 'content-type': 'text/html; charset=utf-8', server: old ? 'nginx' : 'caddy' };
    if (old) headers['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
    const tls = cert(old ? 'AA' : 'BB', broken ? ['www.example.net'] : [host, 'example.com']);
    if (twin) Object.assign(tls, { authorized: false, error: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', issuer: { C: 'US', O: 'Example Origin CA', CN: 'Example Origin CA' } });
    return {
      status: 'finished', resolvedAddress: ip, statusCode: 200, statusCodeName: 'OK', headers, rawBody: body, truncated: false,
      tls, timings: { total: 120 }
    };
  }
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!url.startsWith('https://api.globalping.io/')) return prevFetch(input, init);
    const p = url.slice('https://api.globalping.io/v1'.length);
    const method = String((init && init.method) || 'GET').toUpperCase();
    let b = null;
    try { b = init && typeof init.body === 'string' ? JSON.parse(init.body) : null; } catch { b = null; }
    gp.calls.push({ method, path: p, body: b });
    if (p === '/limits') return json({ rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: gp.remaining, reset: 0 } } } });
    if (p === '/measurements' && method === 'POST') {
      gp.remaining -= 1;
      gp.n += 1;
      const id = 'fakeCompare' + String(gp.n).padStart(6, '0');
      gp.measurements[id] = { id, body: b, n: gp.n };
      return json({ id, probesCount: 1 }, 202, { 'x-ratelimit-limit': '250', 'x-ratelimit-remaining': String(gp.remaining), 'x-ratelimit-reset': '3600', 'x-request-cost': '1' });
    }
    const m = /^\\/measurements\\/([A-Za-z0-9]+)$/.exec(p);
    if (m && gp.measurements[m[1]]) {
      const { id, body: q, n } = gp.measurements[m[1]];
      if (n > gp.allowUpTo) return json({ id, type: 'http', status: 'in-progress', target: q.target, probesCount: 1, results: [] });
      return json({ id, type: 'http', status: 'finished', target: q.target, probesCount: 1,
        results: [{ probe, result: result(q.target, q.measurementOptions.request.host, q.measurementOptions.request.path) }] });
    }
    return json({ error: { type: 'not_found', message: 'Not Found.' } }, 404);
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
      { domains: ['example.com', 'example.net', 'example.org'], sources: ['scan', 'zone'], internal: [] }, 'prefill');
    assertEqual(V.prefillDomains({}), { domains: [], sources: [], internal: [] }, 'nothing known');
    assertEqual(V.prefillDomains({ zone: { origin: 'example.corp', originInternal: true } }), { domains: [], sources: [], internal: ['example.corp'] }, 'an internal-looking zone domain');
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
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeCompareScript() });
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

    await run.step('a domain that does not exist (a typo?): its card says so, never the green "nothing"', async () => {
      await typeInto(page, 'retire-domains', 'exmaple.example.org');
      await page.click('[data-action="retire-run"]');
      await waitDone(page, 'the check of a domain that does not exist');
      const v = await verdict();
      assertEqual([v.variant, v.title, v.clean], ['alert-warn', 'Nothing found pointing at 192.0.2.10, but not everything could be checked', false], 'verdict');
      assert(/1 domain does not exist: the list may be incomplete\./.test(v.message), v.message);
      const note = await text(page, '.retire-group[data-group="exmaple.example.org"] [data-role="retire-missing"]');
      assert(/^exmaple\.example\.org does not exist: public DNS answers NXDOMAIN for it and it has no name servers\. A typo\?/.test(note), note);
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
      // "Leave out names that look internal" unchecked: the scan hand-off's names now hold intranet.example.com,
      // which Retire an IP must still never send.
      await page.waitFor(() => document.querySelector('.zone-next-scan input[type="checkbox"]'), { message: 'the hand-off toggle' });
      await jsClick(page, '.zone-next-scan input[type="checkbox"]');
      await page.waitFor(async () => {
        const { state } = await import('./assets/js/state.js');
        const z = state.getSession('zone');
        return !!(z && z.names.includes('intranet.example.com') && z.internalNames.includes('intranet.example.com'));
      }, { message: 'the zone republished with its internal names' });
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
      // www, api (scan) + shop, old, mail, ns1 (zone; the internal name left out, though the hand-off toggle is off).
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
        ['example.com', 'live', '*.dev.example.com', 'A', '192.0.2.10', 'live'],
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
      // The wildcard is asked through a random name under it, never as "*.": a live address record.
      const probe = log.find((n) => n.endsWith('.dev.example.com'));
      assert(/^[a-z0-9]{12}\.dev\.example\.com$/.test(probe || '') && !log.some((n) => n.startsWith('*')), `the wildcard probe: ${probe}`);
      const wildcard = await text(page, '.retire-group tr[data-key="*.dev.example.com|A|192.0.2.10"] .retire-evidence');
      assert(wildcard.includes(`a wildcard: checked through the random name ${probe}`), wildcard);
      assertEqual(await chips(page), [['dns', 'ok'], ['spf', 'ok'], ['zone', 'ok'], ['servers', 'ok'], ['passive', 'idle']], 'chips');
      const head = await page.evaluate(() => ({
        verdict: document.querySelector('[data-role="retire-verdict"] .alert-title')?.textContent,
        owner: document.querySelector('.retire-owner-list li')?.dataset.server,
        stats: Object.fromEntries([...document.querySelectorAll('.retire-stats .stat')].map((s) => [s.dataset.stat, s.querySelector('.stat-value').textContent])),
        glue: document.querySelector('.retire-group tr[data-type="NS"] .retire-change')?.dataset.action,
        chip: document.querySelector('[data-role="target-chip"] .target-chip-value')?.textContent || null
      }));
      assertEqual(head, {
        verdict: '13 records break something once 192.0.2.10 is gone', owner: 'web01',
        stats: { breaking: '13', mail: '4', file: '1' }, glue: 'glue', chip: '192.0.2.10'
      }, 'head');
      await shot(page, opts, 'retire-results-desktop-light-en');
    });

    await run.step('Copy summary (Markdown), CSV and JSON of the change list', async () => {
      await stubClipboard(page);
      await jsClick(page, '[data-action="copy-summary"]');
      const [md] = await takeClipboard(page);
      assert(md.startsWith('**Retire an IP · `192.0.2.10`**\n- 14 records still point at it · 13 break something once it is gone\n'), md);
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
        ['domainscope.ip-retire/1', ['192.0.2.10/32'], ['example.com'], 14, ['web01']], 'JSON');
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
      // The offer on a 320 px phone in both languages: the cost is written out, the button wraps
      // inside its box and nothing scrolls sideways.
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await page.setViewport({ width: 320, height: 640, mobile: true });
        await page.waitFor(() => document.querySelector('[data-action="retire-discover"]')?.getBoundingClientRect().width > 0, { message: `the offer at 320 px (${lang})` });
        await page.evaluate(() => document.querySelector('.retire-discover').scrollIntoView({ block: 'center' }));
        await assertNoHorizontalScroll(page, `retire discovery offer 320 px ${lang}`);
        const fit = await page.evaluate(() => {
          const box = document.querySelector('.retire-discover').getBoundingClientRect();
          const btn = document.querySelector('[data-action="retire-discover"]');
          const b = btn.getBoundingClientRect();
          const cost = document.getElementById(btn.getAttribute('aria-describedby'));
          // The passive lookup's button, under the chips of the head card, fits its card too.
          const card = document.querySelector('.retire-head-card').getBoundingClientRect();
          const passive = document.querySelector('[data-action="retire-passive"]').getBoundingClientRect();
          return {
            inside: b.left >= box.left - 0.5 && b.right <= box.right + 0.5,
            passive: passive.width > 0 && passive.left >= card.left - 0.5 && passive.right <= card.right + 0.5,
            cost: cost ? cost.textContent : ''
          };
        });
        assert(fit.inside, `the button stays inside its box (${lang})`);
        assert(fit.passive, `the passive lookup's button stays inside the head card (${lang})`);
        assert(/159/.test(fit.cost) && /\d+–\d+/.test(fit.cost), `the cost next to the button (${lang}): ${fit.cost}`);
        if (lang === 'tr') await shot(page, opts, 'retire-discover-320-tr');
        await page.setViewport({ width: 1440, height: 900 });
      }
      await jsClick(page, '[data-action="retire-discover"]');
      await page.waitFor(() => [...document.querySelectorAll('.retire-group[data-group="example.net"] tbody tr')].some((tr) => tr.querySelector('.retire-name').textContent === 'www.example.net'),
        { timeout: 60000, message: 'discovered www.example.net checked' });
      await waitDone(page, 'the check after the discovery');
      const hosts = await page.evaluate(() => document.querySelector('.retire-hosts-list li[data-domain="example.net"]')?.dataset.hosts);
      assert(Number(hosts) >= 1, `example.net has discovered host names now: ${hosts}`);
      // The central SPF policy example.com includes is under a checked domain now: the user's to narrow.
      const central = await page.evaluate(() => document.querySelector('.retire-group[data-group="example.net"] tr[data-key="_spf.example.net|TXT|ip4:192.0.2.0/24"] .retire-change')?.dataset.action);
      assertEqual(central, 'narrow', 'the central SPF policy');
      await shot(page, opts, 'retire-discovered-desktop-light-en');
    });

    await run.step('the passive lookup: two services on a click, unverified until checked; "Check these too" adds their domains', async () => {
      assertEqual(await page.evaluate(() => window.__passiveLog.length), 0, 'nothing asked before the click');
      // The cost and the quota are written next to the button (not a tooltip), and linked to it.
      const offer = await page.evaluate(() => {
        const btn = document.querySelector('[data-action="retire-passive"]');
        const cost = document.getElementById(btn.getAttribute('aria-describedby'));
        return { inChip: !!btn.closest('.src-chip'), cost: cost ? cost.textContent : '', visible: !!cost && cost.getBoundingClientRect().height > 0 };
      });
      assertEqual([offer.inChip, offer.visible], [false, true], 'the passive button and its cost');
      assert(/1 request to each\. HackerTarget allows about 50 free lookups a day/.test(offer.cost), offer.cost);
      // From the keyboard: the button goes while the lookup runs, and the focus goes with Stop (then back to Check), never to <body>.
      await page.evaluate(() => document.querySelector('[data-action="retire-passive"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.retire-group[data-kind="passive"]'), { message: 'passive group' });
      const focused = await page.waitFor(() => {
        const a = document.activeElement;
        return a && ['retire-run', 'retire-stop'].includes(a.dataset.action) ? a.dataset.action : false;
      }, { message: 'the focus on Stop or Check, not <body>' });
      assert(['retire-run', 'retire-stop'].includes(focused), focused);
      assertEqual(await text(page, '.retire-passive-note[data-address="192.0.2.10"]'),
        ' ip.thc.org lists 250 names for 192.0.2.10; only the first 100 were fetched, so the passive list is incomplete.', 'a cut-off list is said');
      assert(!(await page.evaluate(() => document.querySelector('[data-action="retire-passive"]'))), 'no second lookup offered');
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

    run.group('Compare the old and the new server');
    const ocRows = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.oc-table tbody tr')]
      .map((tr) => [tr.dataset.field, `${tr.dataset.severity}${tr.dataset.same === 'true' ? '' : ' differs'}`])));
    await run.step('the card takes the retired address and the first domain; nothing sent; a private address gets the CLI command', async () => {
      await page.evaluate(() => document.querySelector('.oc-card')?.scrollIntoView());
      // The boxes follow the form (debounced) while nobody has typed in them.
      await page.waitFor(() => document.querySelector('[data-role="oc-oldIp"]')?.value === '192.0.2.10'
        && document.querySelector('[data-role="oc-host"]')?.value === 'example.com', { message: 'filled from the form' });
      await typeInto(page, 'oc-newIp', '10.0.0.20');
      await page.waitFor(() => !!document.querySelector('[data-role="oc-cli"] code'), { message: 'CLI block' });
      assertEqual((await page.evaluate(() => document.querySelector('[data-role="oc-cli"] code').textContent)).trim(),
        'python3 ssl_origin_scan.py --compare 192.0.2.10 10.0.0.20 -n example.com', 'CLI command');
      assert(!await page.evaluate(() => !!document.querySelector('[data-action="oc-run"]')), 'no Compare button for addresses a probe cannot reach');
      assertEqual(await page.evaluate(() => window.__gp.calls.length), 0, 'no Globalping');
    });

    await run.step('two public addresses: the consent dialog, two probes (the second from the first one\'s probe), side by side', async () => {
      await typeInto(page, 'oc-host', 'www.example.com');
      await typeInto(page, 'oc-oldIp', OLD_IP);
      await typeInto(page, 'oc-newIp', NEW_IP);
      await page.waitFor(() => !!document.querySelector('[data-action="oc-run"]') && !document.querySelector('[data-action="oc-run"]').disabled, { message: 'Compare button' });
      await page.click('[data-action="oc-run"]');
      await page.waitFor(() => !!document.querySelector('.gp-confirm'), { message: 'dialog' });
      assert(/Cost: 2 probes/.test(await page.evaluate(() => document.querySelector('.gp-confirm').textContent)), 'cost in the dialog');
      await page.click('.gp-confirm .btn-primary');
      await page.waitFor(() => !!document.querySelector('.oc-results'), { timeout: 20000, message: 'results' });
      const posts = await page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST').map((c) => c.body));
      assertEqual(posts.length, 2, 'two probes');
      assertEqual([posts[0].target, posts[0].limit, posts[1].target, posts[1].locations], [OLD_IP, 1, NEW_IP, 'fakeCompare000001'], 'the old address first, then the same probe at the new one');
      assert(posts.every((b) => b.type === 'http' && b.measurementOptions.request.method === 'GET' && b.measurementOptions.request.host === 'www.example.com'
        && b.measurementOptions.request.path === '/' && b.measurementOptions.protocol === 'HTTPS'), 'GET / with the name as SNI and Host');
      assertEqual(await page.evaluate(() => document.querySelector('.oc-results').dataset.verdict), 'differs', 'verdict');
      const rows = await ocRows();
      assertEqual([rows.status, rows.title, rows.body, rows.hsts, rows.server, rows.certSubject, rows.certCovers, rows.certFingerprint],
        ['ok', 'ok', 'ok', 'warn differs', 'info differs', 'ok', 'ok', 'info differs'], 'fields');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.oc-row[data-field="certSubject"] td')].map((td) => td.textContent)),
        ['www.example.com, example.com', 'www.example.com, example.com'], 'the names each certificate carries');
      assert(/visitors whose browsers never saw it/.test(await page.evaluate(() => document.querySelector('.oc-row[data-field="hsts"]').textContent)), 'the HSTS note');
      await takeDownloads(page);
      await page.click('[data-action="oc-json"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'JSON' });
      const [dl] = await takeDownloads(page);
      const doc = JSON.parse(dl.text);
      assertEqual([doc.schema, doc.verdict, doc.old.ip, doc.new.ip, doc.measurements.length], ['domainscope.compare/1', 'differs', OLD_IP, NEW_IP, 2], 'JSON');
      assertEqual(external, [], 'no external request');
      await page.evaluate(() => document.querySelector('.oc-card').scrollIntoView());
      await shot(page, opts, 'retire-compare-desktop-light-en');
    });

    await run.step('a new server whose certificate names another host: broken, no second dialog', async () => {
      await page.evaluate(() => { window.__compareScenario = 'broken'; });
      await page.click('[data-action="oc-run"]');
      await page.waitFor(() => document.querySelector('.oc-results')?.dataset.verdict === 'broken', { timeout: 20000, message: 'broken' });
      assert(!await page.evaluate(() => !!document.querySelector('.gp-confirm')), 'consent kept for the page session');
      assertEqual((await ocRows()).certCovers, 'error differs', 'the certificate covers another name');
      assertEqual((await ocRows()).certSubject, 'info differs', 'another certificate\'s names, side by side');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.oc-row[data-field="certSubject"] td')[1].textContent), 'www.example.net', 'the name it carries');
      await page.evaluate(() => { window.__compareScenario = 'differs'; });
    });

    await run.step('neither server answers: "unreachable" (maybe the probe\'s network), never "not ready"; the reason in the page\'s language', async () => {
      await page.evaluate(() => { window.__compareScenario = 'down'; });
      await page.click('[data-action="oc-run"]');
      await page.waitFor(() => document.querySelector('.oc-results')?.dataset.verdict === 'unreachable', { timeout: 20000, message: 'unreachable' });
      assertEqual(await ocRows(), { reach: 'warn' }, 'the same on both sides: a warning, nothing else compared');
      assert(/Neither server answered this probe/.test(await page.evaluate(() => document.querySelector('.oc-results .alert').textContent)), 'the verdict');
      const reach = () => page.evaluate(() => document.querySelectorAll('.oc-row[data-field="reach"] td')[1].textContent);
      assert((await reach()).startsWith('no: connection refused — connect ECONNREFUSED'), await reach());
      await setLangUi(page, 'tr');
      await page.waitFor(() => (document.querySelectorAll('.oc-row[data-field="reach"] td')[1]?.textContent || '').startsWith('hayır: bağlantı reddedildi'), { message: 'TR reason' });
      await setLangUi(page, 'en');
      await page.evaluate(() => { window.__compareScenario = 'differs'; });
    });

    await run.step('the same untrusted certificate on both (an origin CA behind a CDN): the same answer, the shared warning said apart', async () => {
      await page.evaluate(() => { window.__compareScenario = 'origin-ca'; });
      await page.click('[data-action="oc-run"]');
      await page.waitFor(() => document.querySelector('.oc-results')?.dataset.verdict === 'same', { timeout: 20000, message: 'same' });
      const rows = await ocRows();
      assertEqual(rows.certTrusted, 'warn', 'a warning both share, no difference');
      assertEqual(Object.entries(rows).filter(([, v]) => v !== 'ok').map(([k]) => k), ['certTrusted'], 'nothing else marked');
      const results = await page.evaluate(() => document.querySelector('.oc-results').textContent);
      assert(/answers like the old one/.test(results) && !/answers differently/.test(results), 'the verdict: the same');
      assert(/Both servers serve a certificate the probe does not trust/.test(results), 'the shared warning');
      await takeDownloads(page);
      await page.click('[data-action="oc-json"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'JSON' });
      const [dl] = await takeDownloads(page);
      assertEqual([JSON.parse(dl.text).verdict, JSON.parse(dl.text).shared], ['same', ['cert-untrusted']], 'JSON');
      await page.evaluate(() => document.querySelector('.oc-card').scrollIntoView());
      await shot(page, opts, 'retire-compare-shared-desktop-light-en');
      await setLangUi(page, 'tr');
      await page.waitFor(() => /İki sunucu da ölçüm noktasının güvenmediği/.test(document.querySelector('.oc-results')?.textContent || ''), { message: 'TR shared warning' });
      await setLangUi(page, 'en');
      await page.evaluate(() => { window.__compareScenario = 'differs'; });
    });

    await run.step('Compare from the keyboard: focus goes to Stop and back; a stop after the old server keeps its answer on screen', async () => {
      // The old address answers; the new one stays in progress until the stop.
      const base = await page.evaluate(() => { window.__gp.allowUpTo = window.__gp.n + 1; return window.__gp.n; });
      await page.waitFor(() => !!document.querySelector('[data-action="oc-run"]'), { message: 'Compare button' });
      await page.evaluate(() => document.querySelector('[data-action="oc-run"]').focus());
      await page.press('Enter');
      await page.waitFor(() => document.activeElement?.dataset.action === 'oc-stop', { message: 'keyboard focus on Stop' });
      await page.waitFor((b) => window.__gp.n >= b + 2, { args: [base], message: 'the new address asked' });
      await page.press('Enter');
      await page.waitFor(() => !document.querySelector('[data-action="oc-stop"]') && !!document.querySelector('.oc-partial'), { message: 'stopped with the old answer' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'oc-run', 'keyboard focus back on Compare');
      assert(/Stopped after the old server was asked/.test(await page.evaluate(() => document.querySelector('.oc-card').textContent)), 'the stop alert');
      assertEqual(await page.evaluate(() => document.querySelector('.oc-partial tr[data-field="status"] td')?.textContent), '200', 'the old server\'s answer kept');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.oc-partial thead th').length), 2, 'the old server alone');
      await page.evaluate(() => { window.__gp.allowUpTo = Infinity; });
      await page.click('[data-action="oc-run"]');
      await page.waitFor(() => document.querySelector('.oc-results')?.dataset.verdict === 'differs' && !document.querySelector('.oc-partial'), { timeout: 20000, message: 'compared again' });
    });

    await run.step('leaving Retire an IP during a run and coming back: the card on screen gets the result and its Compare button back', async () => {
      // The old address answers; the new one is held while the view is left and opened again.
      const base = await page.evaluate(() => { window.__compareScenario = 'broken'; window.__gp.allowUpTo = window.__gp.n + 1; return window.__gp.n; });
      await page.click('[data-action="oc-run"]');
      await page.waitFor((b) => window.__gp.n >= b + 2 && !!document.querySelector('[data-action="oc-stop"]'), { args: [base], message: 'the new address asked' });
      await gotoRoute(page, 'about');
      await gotoRoute(page, 'retire');
      await page.waitFor(() => !!document.querySelector('[data-action="oc-stop"]'), { message: 'the run shown on the new card' });
      await page.evaluate(() => { window.__gp.allowUpTo = Infinity; });
      await page.waitFor(() => document.querySelector('.oc-results')?.dataset.verdict === 'broken' && !document.querySelector('[data-action="oc-stop"]'),
        { timeout: 20000, message: 'the result on the card shown, no Stop' });
      assert(await page.evaluate(() => !document.querySelector('[data-action="oc-run"]').disabled), 'Compare enabled again');
      await page.evaluate(() => { window.__compareScenario = 'differs'; });
      await page.click('[data-action="oc-run"]');
      await page.waitFor(() => document.querySelector('.oc-results')?.dataset.verdict === 'differs', { timeout: 20000, message: 'compared again' });
    });

    await run.step('the comparison at 320 and 375 px, TR / EN × light / dark: labelled cards, no horizontal scroll', async () => {
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await page.waitFor(() => !!document.querySelector('.oc-results'), { message: 'kept after the language switch' });
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          for (const width of [320, 375]) {
            await page.setViewport({ width, height: 700, mobile: true });
            await assertNoHorizontalScroll(page, `compare ${width} ${scheme} ${lang}`);
          }
          const label = await page.evaluate(() => getComputedStyle(document.querySelector('.oc-table td'), '::before').content);
          assert(/·/.test(label), `a labelled value: ${label}`);
          await page.evaluate(() => document.querySelector('.oc-card').scrollIntoView());
          await shot(page, opts, `retire-compare-mobile-${scheme}-${lang}`);
        }
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'en');
      await page.evaluate(() => window.scrollTo(0, 0));
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

    run.group('A zone whose own domain looks internal');
    await run.step('corp.example.com imported under Zone File: its domain is not filled in, the note says why, nothing is sent', async () => {
      const before = await dnsCount(page);
      await page.evaluate(async () => {
        const { state } = await import('./assets/js/state.js');
        state.setSession('scanHosts', undefined);
      });
      await gotoRoute(page, 'zone');
      await page.evaluate(() => { document.querySelectorAll('.zone-import-folded, .zone-paste').forEach((d) => { d.open = true; }); });
      await page.type('[data-role="zone-paste"]', [
        '$ORIGIN corp.example.com.',
        '@ 3600 IN SOA ns1.corp.example.com. hostmaster.corp.example.com. 1 7200 3600 1209600 300',
        '@ 3600 IN A 203.0.113.80',
        'www 3600 IN A 192.0.2.10',
        ''
      ].join('\n'));
      await page.click('[data-action="zone-paste-import"]');
      await page.waitFor(async () => {
        const { state } = await import('./assets/js/state.js');
        const z = state.getSession('zone');
        return !!(z && z.origin === 'corp.example.com' && z.originInternal === true);
      }, { message: 'the corp zone published', timeout: 15000 });
      await gotoRoute(page, 'retire');
      await typeInto(page, 'retire-domains', '');
      await gotoRoute(page, 'about');
      await gotoRoute(page, 'retire');
      const form = await page.evaluate(() => ({
        domains: document.querySelector('[data-role="retire-domains"]').value,
        leftOut: document.querySelector('[data-left-out]')?.dataset.leftOut || '',
        note: document.querySelector('[data-left-out]')?.textContent || ''
      }));
      assertEqual([form.domains, form.leftOut], ['', 'corp.example.com'], 'not filled in, named');
      assert(/corp\.example\.com, the imported zone’s own domain, looks internal/.test(form.note), form.note);
      // Typed in, it is checked as typed; the note goes.
      await typeInto(page, 'retire-domains', 'corp.example.com');
      await page.waitFor(() => !document.querySelector('[data-left-out]'), { message: 'the note goes once it is typed in' });
      assertEqual(await dnsCount(page), before, 'nothing sent');
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
