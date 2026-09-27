#!/usr/bin/env node
/**
 * subdomains.e2e.mjs — end-to-end test of the "Subdomains" view (the default route) against
 * the LIVE services (DoH resolvers, crt.sh / Anubis / HackerTarget) in a real headless
 * Chrome/Edge.
 *
 *   node tests/e2e/subdomains.e2e.mjs [--domain npmjs.com] [--sources crtsh,anubis,hackertarget]
 *                                     [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Free source quotas are small (Cert Spotter ≈ 10 requests/hour, HackerTarget ≈ 50/day), so
 * the live scan uses crt.sh, Anubis and HackerTarget only (set through the Advanced options,
 * which also checks that the choice is remembered); pass --sources to change that.
 *
 * What is checked:
 *   - pure helpers of views/subdomains.js (Node side)
 *   - the site root lands on #/subdomains: first nav item, "Discover" group, hero, intro
 *   - validation (IP, public suffix, empty), the "only under shop.x" scope hint, example chips
 *   - a live scan started with Enter: URL rewritten to ?domain=… (no run=1: a reload only pre-fills), Cancel
 *     visible, stages and per-source chips, hosts streaming into the table, stat cards
 *   - filters (segmented control, stat cards, search), lookup / IP Intel links, exports
 *     (copy, names.txt, CSV, JSON — downloads are captured in the page) and "resolving only"
 *   - results survive a visit to DNS Lookup and the browser Back button (no re-scan)
 *   - the hand-over card opens SSL Targets with the domain pre-filled
 *   - TR + EN, light + dark, desktop 1440×900 and phone 390×844 without horizontal page scroll
 *   - route params: `?domain=` pre-fills without running, `&run=1` shows a one-click "Start scan"
 *     prompt (a link never scans on its own) and a reload does not scan again, update()
 *     takes new params without a re-mount; Cancel stops a running scan
 *   - Advanced: languages / markets (auto from the domain ending, manual packs, remembered), the
 *     custom wordlist (paste + .txt upload read in the browser, accepted / rejected counts, clear,
 *     this tab only), learned names (bare labels saved after the scan, forget button), the
 *     wordlist plan line; the ORIGIN panel's POSIX / PowerShell command toggle
 *   - focused screenshots of the Advanced panel and the ORIGIN panel at 390 px (TR/EN × light/dark),
 *     with every control inside the viewport
 *   - an emulated zone (example.net answered inside the page, no network): proxied + DNS-only
 *     hosts give an origin /24 and the sweep command in both shells, whatever the live domain has
 *   - zero console errors, exceptions and CSP violations (third-party API failures such as a
 *     crt.sh 502 without CORS are reported, not counted); no missing i18n keys
 */

import { mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { SOURCES as LIB_SOURCES } from '../../assets/js/lib/sources.js';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  csvHeader, gotoRoute, installDownloadCapture, setLangUi, shot, sleep, takeDownloads, waitReady,
  ZONE_HANDOFF_APEX, ZONE_HANDOFF_DNS, ZONE_HANDOFF_INPUT, zoneHandoffScript
} from './scan.e2e.mjs';

const DEFAULT_SOURCES = ['crtsh', 'anubis', 'hackertarget'];
/** Sources the app enables by default (lib/sources.js is the single source of truth). */
const DEFAULT_ENABLED = LIB_SOURCES.filter((s) => s.defaultEnabled).length;
const DONE = (id) => `(() => { const p = document.querySelector('.sub-run-ui[data-run="${id}"] .sub-run'); return p && p.dataset.status !== 'running' ? p.dataset.status : false; })()`;

/* ------------------------------------------------------------------------ */
/* Node-side checks                                                         */
/* ------------------------------------------------------------------------ */

async function nodeChecks(run) {
  const S = await import('../../assets/js/views/subdomains.js');
  run.group('Node: views/subdomains.js helpers');
  await run.step('parseTargets: URLs, www → apex, subdomains kept, IPs / public suffixes / invalid reported', () => {
    const r = S.parseTargets('https://www.Example.com.tr/path shop.example.com *.foo.com com.tr 1.2.3.4 bad..x example.com.tr');
    assertEqual(r.domains, ['example.com.tr', 'shop.example.com', 'foo.com'], 'domains');
    assertEqual(r.ips, ['1.2.3.4'], 'ips');
    assertEqual(r.publicSuffixes, ['com.tr'], 'public suffixes');
    assertEqual(r.invalid, ['bad..x'], 'invalid');
    assertEqual(S.parseTargets('example.org, www.example.org; api.example.org').domains, ['example.org'], 'names inside another target are dropped');
    assertEqual(S.parseTargets('[2001:db8::1]').ips, ['2001:db8::1'], 'bracketed IPv6');
    assertEqual(S.parseTargets('').domains, [], 'empty');
  });
  await run.step('routeTargets reads repeated / comma-separated params', () => {
    assertEqual(S.routeTargets(new URLSearchParams('domain=a.com,b.com&domain=c.com.tr'), {}), ['a.com', 'b.com', 'c.com.tr'], 'repeated');
    assertEqual(S.routeTargets(null, { domains: 'x.org y.org' }), ['x.org', 'y.org'], 'alias');
    assertEqual(S.routeTargets(new URLSearchParams(''), {}), [], 'none');
  });
  await run.step('sanitizeOptions: smart wordlist, permutations, origin hints and every default source by default', () => {
    const d = S.sanitizeOptions(null);
    assertEqual([d.sources.length, d.bruteforce, d.permutations, d.permutationBudget, d.originHints, d.includeExpired],
      [DEFAULT_ENABLED, 'smart', true, 1500, true, false], 'defaults');
    const x = S.sanitizeOptions({ sources: ['crtsh', 'nope', 'crtsh'], bruteforce: 'huge', includeExpired: true, permutationBudget: 7 });
    assertEqual([x.sources, x.bruteforce, x.includeExpired, x.permutationBudget], [['crtsh'], 'huge', true, 1500], 'sanitized (huge is a real level now)');
    assertEqual(S.sanitizeOptions({ bruteforce: 'medium' }).bruteforce, 'smart', 'a saved medium level loads as smart');
    assertEqual(S.sanitizeOptions({ bruteforce: 'nope' }).bruteforce, 'smart', 'an unknown level falls back to smart');
    assertEqual([S.sanitizeOptions(null).locales, S.sanitizeOptions(null).learned], [null, false], 'languages auto, learned names opt-in (off by default)');
    assertEqual(S.sanitizeOptions({ sources: [], bruteforce: 'off' }).sources, [], 'no sources is allowed');
  });
  await run.step('techniqueCounts / originOverview (engine v2 output)', () => {
    const t = S.techniqueCounts([
      { name: 'a.x', origins: ['input'] }, { name: 'mail.x', origins: ['dns-mine:MX'] }, { name: 'api.x', origins: ['wordlist', 'crtsh'] },
      { name: 'api2.x', origins: ['permutation'] }, { name: 'z.x', origins: ['wordlist'], wildcardSuspect: true }
    ]);
    assertEqual([t.total, t.dns, t.sources, t.dnsOnly, t.mine, t.wordlist, t.permutation], [4, 3, 1, 2, 1, 1, 1], 'technique counts');
    const o = S.originOverview({
      hosts: [{ name: 'www.x.com', origins: ['wordlist'], classification: { hidesOrigin: true }, resolution: { ipv4: ['104.21.1.1'], ipv6: [] }, candidateNetworks: ['203.0.113.0/24'] }],
      originHints: [{ ip: '203.0.113.77', reasons: [{ kind: 'resolver-leak', host: 'www.x.com', resolver: 'google', detail: 'www.x.com via google' }] }],
      originNetworks: [{ cidr: '203.0.113.0/24', ips: ['203.0.113.14'], hosts: ['api.x.com'], provider: null }],
      cliTargets: ['203.0.113.0/24'],
      cliNames: ['www.x.com'],
      cliSuggestion: 'python3 cli/ssl_origin_scan.py -t 203.0.113.0/24 -n www.x.com'
    });
    assertEqual([o.proxied.length, o.proxied[0].leaks[0].ip, o.networks.length, o.command, o.commands.powershell],
      [1, '203.0.113.77', 1, 'python3 ssl_origin_scan.py -t 203.0.113.0/24 -n www.x.com', 'python ssl_origin_scan.py -t 203.0.113.0/24 -n www.x.com'], 'origin overview + PowerShell variant');
  });
  const host = (name, kind, extra = {}) => ({
    name,
    classification: { kind, dangling: !!extra.dangling, hidesOrigin: kind === 'cloudflare' },
    resolution: { ipv4: extra.ips || [], ipv6: extra.ips6 || [], cnames: [], status: 'NOERROR' },
    servers: extra.servers || [],
    wildcardSuspect: !!extra.wildcard,
    origins: ['crtsh']
  });
  await run.step('matchesFilter / countHosts / namesText', () => {
    const hosts = [
      host('www.a.com', 'cloudflare', { ips: ['104.16.1.1'] }),
      host('cdn.a.com', 'cdn', { ips: ['151.101.1.1'] }),
      host('app.a.com', 'platform', { ips6: ['2606:50c0::1'] }),
      host('api.a.com', 'direct', { ips: ['203.0.113.5'], servers: [{ name: 'web01', ip: '203.0.113.5' }] }),
      host('db.a.com', 'private', { ips: ['10.0.0.5'] }),
      host('old.a.com', 'nxdomain'),
      host('shop.a.com', 'unresolved', { dangling: true }),
      host('x1.a.com', 'direct', { ips: ['203.0.113.9'], wildcard: true })
    ];
    const pick = (f) => hosts.filter((x) => S.matchesFilter(x, f)).map((x) => x.name.split('.')[0]);
    assertEqual(pick('resolving'), ['www', 'cdn', 'app', 'api', 'db', 'x1'], 'resolving');
    assertEqual(pick('cdn'), ['cdn', 'app'], 'cdn/platform');
    assertEqual(pick('direct'), ['api', 'db', 'x1'], 'direct (+private)');
    assertEqual(pick('unresolved'), ['old', 'shop'], 'not resolving');
    assertEqual(pick('dangling'), ['shop'], 'dangling');
    const c = S.countHosts(hosts);
    assertEqual([c.found, c.resolving, c.cloudflare, c.cdn, c.direct, c.private, c.unresolved, c.dangling, c.onServers, c.wildcard],
      [7, 5, 1, 2, 2, 1, 2, 1, 1, 1], 'counts without wildcard suspects');
    assertEqual(S.countHosts(hosts, { includeWildcard: true }).found, 8, 'with wildcard suspects');
    assertEqual(S.namesText([hosts[3], hosts[0], hosts[3]]), 'api.a.com\nwww.a.com\n', 'names: sorted, unique');
    assertEqual(S.namesText([]), '', 'empty names');
  });
  await run.step('sourceChipState aggregates per-domain results', () => {
    const r = (source, ok, names, extra = {}) => ({ source, ok, names, partial: false, errorKind: ok ? null : 'rate-limit', error: ok ? null : 'HTTP 429', ...extra });
    assertEqual(S.sourceChipState([], 'crtsh', 1).state, 'pending', 'nothing yet');
    const ok = S.sourceChipState([r('crtsh', true, ['a.x', 'b.x']), r('crtsh', true, ['b.x', 'c.y'])], 'crtsh', 2);
    assertEqual([ok.state, ok.names], ['ok', 3], 'ok + unique names');
    assertEqual(S.sourceChipState([r('otx', false, [])], 'otx', 1).errorKind, 'rate-limit', 'rate limited');
    assertEqual(S.sourceChipState([r('otx', false, []), r('otx', true, ['a'])], 'otx', 2).state, 'partial', 'mixed');
  });
}

/* ------------------------------------------------------------------------ */
/* Page helpers                                                             */
/* ------------------------------------------------------------------------ */

const statValue = (page, key) => page.evaluate((k) => {
  const el = document.querySelector(`.sub-stats [data-stat="${k}"]`);
  if (!el || el.hidden) return null;
  const n = Number(el.querySelector('.stat-value').textContent.replace(/[^\d]/g, ''));
  return Number.isFinite(n) ? n : null;
}, key);

const tableInfo = (page) => page.evaluate(() => {
  const rows = [...document.querySelectorAll('.sub-table tbody tr.dt-row')];
  return {
    rows: rows.length,
    names: rows.map((r) => r.querySelector('.sub-host-name')?.textContent || ''),
    withIp: rows.filter((r) => r.querySelector('.sub-ip')).length,
    kinds: rows.map((r) => r.querySelector('.sub-kind [data-kind]')?.dataset.kind || ''),
    count: document.querySelector('.sub-table .dt-count')?.textContent || '',
    pressed: document.querySelector('.sub-filter [aria-pressed="true"]')?.dataset.value || null
  };
});

async function typeAndSubmit(page, text) {
  await page.type('[data-role="sub-domain"]', text);
  await page.evaluate(() => document.querySelector('[data-role="sub-domain"]').focus());
  await page.press('Enter');
}

async function setSources(page, sources) {
  await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
  await page.evaluate((srcs) => {
    for (const input of document.querySelectorAll('input[name="sub-sources"]')) {
      if (input.checked !== srcs.includes(input.value)) input.click();
    }
  }, sources);
}

const currentRunId = (page) => page.evaluate(() => document.querySelector('.sub-run-ui')?.dataset.run || null);

/**
 * Screenshot one element (clipped, beyond the viewport if needed) — a focused image of a panel
 * to review, next to the full-page shots. Skipped with --no-shots.
 */
async function shotEl(page, opts, name, selector) {
  if (!opts.shots) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    window.scrollTo(0, 0);
    const r = el.getBoundingClientRect();
    return { x: Math.max(0, r.left + window.scrollX), y: Math.max(0, r.top + window.scrollY), width: r.width, height: r.height };
  }, selector);
  if (!box || !box.width || !box.height) return;
  await mkdir(SHOTS, { recursive: true });
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.min(Math.ceil(box.height), 9000), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}

/**
 * A tiny authoritative zone for example.net, answered inside the page for every DoH resolver
 * (window.fetch is wrapped before the app loads; other requests pass through). Two proxied names
 * (Cloudflare addresses) and three DNS-only ones in 203.0.113.0/24, so the ORIGIN panel always
 * has a network and a sweep command — no matter what the live domain looks like today.
 */
const FAKE_APEX = 'example.net';
const FAKE_ZONE = {
  'example.net': { A: ['203.0.113.10'] },
  'www.example.net': { A: ['104.16.5.5'] },
  'shop.example.net': { A: ['172.67.1.5'] },
  'api.example.net': { A: ['203.0.113.14'] },
  'mail.example.net': { A: ['203.0.113.12'] }
};
const fakeZoneScript = (apex, zone) => `(() => {
  const APEX = ${JSON.stringify(apex)};
  const ZONE = ${JSON.stringify(zone)};
  const SOA = { mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
  const answer = (name, type) => {
    const node = ZONE[name];
    if (!node) {
      const exists = Object.keys(ZONE).some((k) => k.endsWith('.' + name));
      return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers: [], authorities: [{ name: APEX, type: 'SOA', ttl: 300, data: SOA }] };
    }
    const answers = (node[type] || []).map((data) => ({ name, type, ttl: 300, data }));
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: APEX, type: 'SOA', ttl: 300, data: SOA }] };
  };
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.__fakeDnsQueries = 0;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    if (name !== APEX && !name.endsWith('.' + APEX)) return realFetch(input, init);
    window.__fakeDnsQueries += 1;
    const out = answer(name, q.type);
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/**
 * Two apexes answered in the page for the sibling-domain candidate: a proxied `ticket.example.net`
 * (Cloudflare), and `ticket.example.org` as a DNS-only public host at 203.0.113.20 — the same
 * left-most label on a sister brand, which the engine raises to an exact origin candidate when both
 * domains are scanned together. Documentation ranges only; no last octet .11/.27/.28/.41.
 */
const SIBLING_APEXES = ['example.net', 'example.org'];
const SIBLING_ZONE = {
  'example.net': { A: ['203.0.113.10'] },
  'www.example.net': { A: ['203.0.113.10'] },
  'ticket.example.net': { A: ['104.16.7.7'] },
  'api.example.net': { A: ['203.0.113.14'] },
  'example.org': { A: ['203.0.113.50'] },
  'www.example.org': { A: ['203.0.113.50'] },
  'ticket.example.org': { A: ['203.0.113.20'] },
  'api.example.org': { A: ['203.0.113.14'] }
};

/**
 * A DoH stub answering several apexes in the page (window.fetch wrapped before the app loads); any
 * name outside every apex passes through to the real fetch. Shape matches {@link fakeZoneScript}.
 */
const multiZoneScript = (apexes, zone) => `(() => {
  const APEXES = ${JSON.stringify(apexes)};
  const ZONE = ${JSON.stringify(zone)};
  const apexOf = (name) => APEXES.find((a) => name === a || name.endsWith('.' + a)) || null;
  const soa = (apex) => ({ mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60, apex });
  const answer = (name, type) => {
    const apex = apexOf(name);
    const node = ZONE[name];
    if (!node) {
      const exists = Object.keys(ZONE).some((k) => k.endsWith('.' + name));
      return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers: [], authorities: [{ name: apex || name, type: 'SOA', ttl: 300, data: soa(apex || name) }] };
    }
    const answers = (node[type] || []).map((data) => ({ name, type, ttl: 300, data }));
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: apex || name, type: 'SOA', ttl: 300, data: soa(apex || name) }] };
  };
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.__fakeDnsQueries = 0;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    if (!apexOf(name)) return realFetch(input, init);
    window.__fakeDnsQueries += 1;
    const out = answer(name, q.type);
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/**
 * Real DoH latency for a DoH stub installed before it: every answer waits `window.__dnsDelay` ms
 * (0 at first). Streamed rows are then drawn before the scan ends, and a scan can be caught running.
 */
const slowDnsScript = `(() => {
  window.__dnsDelay = 0;
  const inner = window.fetch;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (window.__dnsDelay && /[?&]dns=/.test(url)) await new Promise((r) => setTimeout(r, window.__dnsDelay));
    return inner(input, init);
  };
})();`;

/**
 * Elements of a panel that stick out of the viewport on the right (text or a control cut off on
 * a phone). Content inside a scrolling wrapper (the tables) is allowed to be wider.
 */
const overflowingIn = (page, selector) => page.evaluate((sel) => {
  const root = document.querySelector(sel);
  if (!root) return [];
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of root.querySelectorAll('*')) {
    if (el.closest('.dt-scroll, pre, .code-block')) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
}, selector);

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  const opts = cliOptions();
  const DOMAIN = opts.value('--domain', 'npmjs.com');
  const SOURCES = opts.value('--sources', DEFAULT_SOURCES.join(',')).split(',').map((s) => s.trim()).filter(Boolean);
  const run = createRunner();

  await nodeChecks(run);

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; live domain ${DOMAIN}, sources ${SOURCES.join(', ')}\n`);
  let scanRunId = null;
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await browser.conn.send('Browser.grantPermissions', { origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] }).catch(() => {});

    run.group('Desktop 1440×900 (English)');
    await run.step('the site root lands on #/subdomains: first nav item, Discover group, hero and intro', async () => {
      await page.goto(server.url);
      await waitReady(page);
      await setLangUi(page, 'en');
      const info = await page.evaluate(() => ({
        view: document.documentElement.dataset.view,
        hash: location.hash,
        h1: document.querySelector('h1.page-title').textContent,
        firstNav: document.querySelector('.nav-link')?.dataset.view,
        firstGroup: document.querySelector('.nav-group-label')?.textContent,
        firstGroupShown: getComputedStyle(document.querySelector('.nav-group-label')).textTransform,
        brand: document.getElementById('brand').getAttribute('href'),
        input: !!document.querySelector('.sub-hero [data-role="sub-domain"]'),
        placeholder: document.querySelector('[data-role="sub-domain"]').placeholder,
        label: document.querySelector('.sub-hero-title label')?.htmlFor === document.querySelector('[data-role="sub-domain"]').id,
        focused: document.activeElement === document.querySelector('[data-role="sub-domain"]'),
        intro: !document.querySelector('.sub-intro').hidden,
        introItems: document.querySelectorAll('.sub-intro-item').length,
        aboutLink: document.querySelector('[data-action="sub-about"]')?.getAttribute('href'),
        examples: [...document.querySelectorAll('[data-example]')].map((b) => b.dataset.example),
        wordlistOn: document.querySelector('[data-role="sub-wordlist"]').checked,
        advancedOpen: document.querySelector('.sub-advanced').open
      }));
      assertEqual([info.view, info.firstNav, info.h1, info.firstGroup, info.brand], ['subdomains', 'subdomains', 'Subdomains', 'Discover', '#/subdomains'], 'default route');
      assertEqual(info.firstGroupShown, 'uppercase', 'group labels are upper-cased by CSS');
      assert(info.input && info.label && info.placeholder === 'example.com', `search box: ${JSON.stringify(info)}`);
      assert(info.focused, 'search box focused on first load');
      assert(info.intro && info.introItems === 3 && info.aboutLink === '#/about', `intro: ${JSON.stringify(info)}`);
      assertEqual(info.examples, ['github.com', 'cloudflare.com', 'wikipedia.org'], 'example chips (global, public domains)');
      assert(info.wordlistOn && !info.advancedOpen, 'wordlist switch on by default, advanced closed');
      await assertNoHorizontalScroll(page, 'empty');
      await shot(page, opts, 'subdomains-desktop-light-en-empty');
    });

    await run.step('validation: IP address, public suffix and empty input are explained', async () => {
      const errorAfter = async (text) => {
        await typeAndSubmit(page, text);
        return page.waitFor(() => {
          const e = document.querySelector('.sub-search-field .field-error');
          return e && !e.hidden && e.textContent;
        }, { message: `error for ${text}` });
      };
      assert(/IP address/.test(await errorAfter('8.8.8.8')), 'IP message');
      assert(/public suffix/.test(await errorAfter('com.tr')), 'public suffix message');
      await page.type('[data-role="sub-domain"]', '');
      await page.click('[data-action="sub-run"]');
      await page.waitFor(() => /Enter a domain/.test(document.querySelector('.sub-search-field .field-error').textContent));
      assertEqual(await page.evaluate(() => document.querySelector('.sub-run-ui')), null, 'no run started');
      await page.type('[data-role="sub-domain"]', 'x');
      assert(await page.evaluate(() => document.querySelector('.sub-search-field .field-error').hidden), 'typing clears the error');
    });

    await run.step('a subdomain keeps its scope; "Scan all of …" switches to the registrable domain', async () => {
      await page.type('[data-role="sub-domain"]', 'https://shop.github.com/cart');
      await page.waitFor(() => !document.querySelector('.sub-scope').hidden);
      assert(/shop\.github\.com/.test(await page.evaluate(() => document.querySelector('.sub-scope').textContent)), 'scope note');
      await page.click('[data-action="sub-scope-all"]');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="sub-domain"]').value), 'github.com', 'rewritten to the apex');
      assert(await page.evaluate(() => document.querySelector('.sub-scope').hidden), 'scope note gone');
    });

    await run.step('advanced options: sources with quota notes, wordlist levels with real counts, permutations, remembered', async () => {
      await page.click('.sub-advanced > summary');
      await page.waitFor(() => document.querySelector('.sub-advanced').open);
      const notes = await page.evaluate(() => [...document.querySelectorAll('.sub-sources .check-hint')].map((x) => x.textContent));
      assert(notes.length === LIB_SOURCES.length && notes.some((n) => /10 requests per hour/.test(n)) && notes.some((n) => /50 requests per day/.test(n)), `quota notes: ${notes.join(' | ')}`);
      // Levels: Off / Small / Smart (recommended, default, real count once the base list loaded) / Large (self-hosted).
      const levels = await page.waitFor(() => {
        const smart = document.querySelector('.sub-bf-label[data-level="smart"]')?.textContent || '';
        if (!/\d{1,3}(,\d{3})+|\d{4,}/.test(smart)) return false;
        const hintOf = (v) => document.querySelector(`input[name="sub-bruteforce"][value="${v}"]`).closest('.check').querySelector('.check-hint').textContent;
        return {
          values: [...document.querySelectorAll('input[name="sub-bruteforce"]')].map((i) => i.value),
          checked: document.querySelector('input[name="sub-bruteforce"]:checked').value,
          smart,
          smartHint: hintOf('smart'),
          largeHint: hintOf('large'),
          perm: document.querySelector('[data-role="sub-permutations"]').checked,
          budget: document.querySelector('[data-role="sub-perm-budget"]').value,
          origin: document.querySelector('[data-role="sub-origin-hints"]').checked
        };
      }, { message: 'smart wordlist count' });
      assertEqual(levels.values, ['off', 'small', 'smart', 'large', 'huge'], 'levels');
      assertEqual(levels.checked, 'smart', 'smart is the default');
      const smartCount = Number(levels.smart.replace(/[^\d]/g, ''));
      assert(smartCount > 5000 && /recommended/.test(levels.smart), `smart label: ${levels.smart}`);
      assert(/≈ \d+ (s|min) per domain/.test(levels.smartHint), `time estimate: ${levels.smartHint}`);
      assert(/loaded from this site/.test(levels.largeHint) && !/GitHub/.test(levels.largeHint), `large says the list is self-hosted: ${levels.largeHint}`);
      assert(levels.perm && levels.budget === '1500' && levels.origin, `permutations / origin defaults: ${JSON.stringify(levels)}`);
      await page.click('.sub-perm .check-label');
      assert(await page.evaluate(() => document.querySelector('[data-role="sub-perm-budget"]').disabled), 'budget disabled without permutations');
      await page.click('.sub-perm .check-label');
      await page.click('input[name="sub-bruteforce"][value="off"]');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="sub-wordlist"]').checked), false, 'switch follows the radio');
      await page.click('.sub-wordlist .check-label');
      assertEqual(await page.evaluate(() => document.querySelector('input[name="sub-bruteforce"]:checked').value), 'smart', 'radio follows the switch');
      assert(/smart wordlist · \d/.test(await page.evaluate(() => document.querySelector('.sub-wordlist').textContent)), 'switch label names the level and count');
      await setSources(page, SOURCES);
      const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.subdomains.options')));
      assertEqual([...saved.sources].sort(), [...SOURCES].sort(), 'remembered sources');
      assertEqual([saved.bruteforce, saved.permutations, saved.permutationBudget], ['smart', true, 1500], 'remembered wordlist + permutations');
      const summary = await page.evaluate(() => document.querySelector('.sub-adv-summary').textContent);
      assert(new RegExp(`^${SOURCES.length} sources? · smart wordlist · permutations · origin hints`).test(summary), `summary line: ${summary}`);
      await shot(page, opts, 'subdomains-desktop-light-en-advanced');
      await page.click('.sub-advanced > summary');
    });

    await run.step('Advanced: languages / markets follow the typed domain, can be chosen by hand and are remembered', async () => {
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
      await page.type('[data-role="sub-domain"]', 'example.com.tr');
      const auto = await page.waitFor(() => {
        const line = document.querySelector('.sub-lang-line');
        const plan = document.querySelector('.sub-wl-plan')?.textContent || '';
        return line && !line.hidden && /Turkish/.test(line.textContent) && /Turkish/.test(plan)
          ? { line: line.textContent, plan, packsHidden: document.querySelector('.sub-lang-list').hidden, auto: document.querySelector('[data-role="sub-lang-auto"]').checked }
          : false;
      }, { message: 'automatic language line for .com.tr' });
      assertEqual([auto.line, auto.auto, auto.packsHidden], ['Auto: Turkish (.com.tr)', true, true], 'automatic pick from the domain ending');
      // The plan line now shows the honest whole-scan DNS-query estimate as a range (wordlist +
      // permutations + deeper round + origin hints), with the wordlist breakdown in parentheses.
      assert(/^≈ [\d,]+(?:–[\d,]+)? DNS queries for 1 domain \([\d,]+ smart, \+[\d,]+ Turkish\) · ≈ \d+ (s|min)$/.test(auto.plan), `plan line: ${auto.plan}`);
      const planRange = await page.evaluate(() => ({ min: Number(document.querySelector('.sub-wl-plan').dataset.queriesMin), max: Number(document.querySelector('.sub-wl-plan').dataset.queriesMax) }));
      assert(planRange.min > 5000 && planRange.max > planRange.min, `plan range brackets the run: ${JSON.stringify(planRange)}`);
      await page.type('[data-role="sub-domain"]', 'example.com');
      await page.waitFor(() => /no market pack/.test(document.querySelector('.sub-lang-line').textContent), { message: '.com has no pack' });
      await page.type('[data-role="sub-domain"]', 'example.com.tr');
      await page.waitFor(() => /Turkish/.test(document.querySelector('.sub-lang-line').textContent));
      // Manual: seeded with the automatic pick, German added — remembered with the options.
      await page.click('.sub-lang-auto-toggle .check-label');
      await page.waitFor(() => !document.querySelector('.sub-lang-list').hidden, { message: 'manual packs shown' });
      const packs = await page.evaluate(() => [...document.querySelectorAll('[data-role="sub-lang-pack"]')].map((i) => ({ v: i.value, on: i.checked, label: i.closest('.check').textContent })));
      assertEqual(packs.filter((x) => x.on).map((x) => x.v), ['tr'], 'the manual choice starts from the automatic pick');
      assert(packs.length >= 12 && packs.every((x) => /· [\d,]+$/.test(x.label)), `every pack shows its size: ${packs.map((x) => x.label).join(' | ')}`);
      await page.click('[data-role="sub-lang-pack"][value="de"] + .check-label');
      await page.waitFor(() => /German/.test(document.querySelector('.sub-wl-plan').textContent), { message: 'plan counts German' });
      const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.subdomains.options')).locales);
      assertEqual(saved, ['tr', 'de'], 'manual packs remembered');
      assert(/\+Turkish, German/.test(await page.evaluate(() => document.querySelector('.sub-adv-summary').textContent)), 'summary lists the languages');
      // None: the global list only.
      await page.click('[data-role="sub-lang-pack"][value="tr"] + .check-label');
      await page.click('[data-role="sub-lang-pack"][value="de"] + .check-label');
      await page.waitFor(() => !/Turkish|German/.test(document.querySelector('.sub-wl-plan').textContent), { message: 'no packs' });
      assertEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.subdomains.options')).locales), [], 'none is remembered as []');
      // Back to automatic.
      await page.click('.sub-lang-auto-toggle .check-label');
      await page.waitFor(() => !document.querySelector('.sub-lang-line').hidden && document.querySelector('.sub-lang-list').hidden);
      assertEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.subdomains.options')).locales), null, 'automatic is remembered as null');
    });

    await run.step('Advanced: custom wordlist (paste + .txt upload read in the browser), accepted / rejected counts, clear', async () => {
      const status = () => page.evaluate(() => document.querySelector('.sub-custom-status').textContent);
      assertEqual(await status(), 'No custom names.', 'empty by default');
      await page.type('[data-role="sub-custom"]', 'api\nbilling, dev.api\n-bad-');
      await page.waitFor(() => /accepted/.test(document.querySelector('.sub-custom-status').textContent), { message: 'custom status' });
      const st = await status();
      assert(/3 names accepted/.test(st) && /1 rejected: -bad-/.test(st), `status: ${st}`);
      assertEqual(await page.evaluate(() => sessionStorage.getItem('ssds.wordlist.custom')), 'api\nbilling, dev.api\n-bad-', 'kept in this tab (sessionStorage)');
      assertEqual(await page.evaluate(() => localStorage.getItem('ssds.wordlist.custom')), null, 'never in localStorage');
      // A .txt file is read in the browser (FileReader-style, no network) and appended.
      const file = path.join(os.tmpdir(), `domainscope-e2e-wordlist-${process.pid}.txt`);
      await writeFile(file, 'vpn\nportal\n');
      try {
        await page.setFileInput('[data-role="sub-custom-file"]', [file]);
        const after = await page.waitFor(() => {
          const st2 = document.querySelector('.sub-custom-status').textContent;
          return /5 names accepted/.test(st2) ? { st: st2, value: document.querySelector('[data-role="sub-custom"]').value } : false;
        }, { message: 'uploaded names merged' });
        assert(/-bad-\nvpn\nportal/.test(after.value), `upload appended: ${JSON.stringify(after.value)}`);
      } finally {
        await rm(file, { force: true });
      }
      const info = await page.evaluate(() => ({
        plan: document.querySelector('.sub-wl-plan').textContent,
        summary: document.querySelector('.sub-adv-summary').textContent,
        learned: document.querySelector('.sub-learned .check-text').textContent,
        learnedOn: document.querySelector('[data-role="sub-learned"]').checked,
        learnedHint: document.querySelector('.sub-learned .check-hint').textContent,
        forget: document.querySelector('[data-action="sub-learned-clear"]').disabled
      }));
      assert(/\+5 yours/.test(info.plan), `plan counts the custom names: ${info.plan}`);
      assert(/5 custom names/.test(info.summary), `summary: ${info.summary}`);
      assertEqual([info.learned, info.learnedOn, info.forget], ['Try names found in your earlier scans first (none yet)', false, true], 'learned names: opt-in (off), empty');
      // The hint must say what really happens: the labels are tried as DNS lookups under later targets.
      assert(/Off by default/.test(info.learnedHint) && /nameservers see these labels/.test(info.learnedHint) && !/never leaves/.test(info.learnedHint),
        `learned hint: ${info.learnedHint}`);
      // Switch it on for the live scan below (remembered with the options), which then records its labels.
      await page.click('[data-role="sub-learned"] + .check-label .switch-track');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="sub-learned"]').checked, JSON.parse(localStorage.getItem('ssds.subdomains.options')).learned]),
        [true, true], 'learned names switched on and remembered');
      await shotEl(page, opts, 'subdomains-advanced-desktop-light-en', '.sub-advanced');
      await page.click('[data-action="sub-custom-clear"]');
      await page.waitFor(() => document.querySelector('.sub-custom-status').textContent === 'No custom names.', { message: 'cleared' });
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="sub-custom"]').value, sessionStorage.getItem('ssds.wordlist.custom')]), ['', null], 'clear empties the box and the tab storage');
      await page.type('[data-role="sub-domain"]', '');
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = false; });
    });

    await run.step(`live scan of ${DOMAIN} (Enter): shareable URL, Cancel, stages and source chips while running`, async () => {
      await typeAndSubmit(page, `https://www.${DOMAIN}/`);
      await page.waitFor(() => document.querySelector('.sub-run-ui'), { message: 'run UI' });
      scanRunId = await currentRunId(page);
      const info = await page.evaluate(() => ({
        hash: location.hash,
        value: document.querySelector('[data-role="sub-domain"]').value,
        cancel: !document.querySelector('[data-action="sub-cancel"]').hidden,
        run: !document.querySelector('[data-action="sub-run"]').hidden,
        intro: !document.querySelector('.sub-intro').hidden,
        stages: [...document.querySelectorAll('.sub-stage')].map((s) => s.dataset.stage),
        chips: [...document.querySelectorAll('.sub-chip')].map((c) => c.dataset.source),
        live: !!document.querySelector('.sub-progress [aria-live="polite"]'),
        busy: document.getElementById('main').getAttribute('aria-busy')
      }));
      assertEqual(info.hash, `#/subdomains?domain=${DOMAIN}`, 'URL (no run=1: a reload must not scan again)');
      assertEqual(info.value, DOMAIN, 'www. dropped from the URL input');
      assert(info.cancel && !info.run && !info.intro, `buttons / intro while running: ${JSON.stringify(info)}`);
      assertEqual(info.stages, ['sources', 'mining', 'wildcard', 'bruteforce', 'permutations', 'resolve', 'hints'], 'stages');
      assertEqual([...info.chips].sort(), [...SOURCES].sort(), 'source chips');
      assert(info.live && info.busy === 'true', 'aria-live progress + aria-busy');
      await sleep(1500);
      await shot(page, opts, 'subdomains-desktop-light-en-running');
    });

    await run.step('hosts stream into the table; the scan finishes with Cloudflare-classified rows', async () => {
      // Streaming: rows appear while the run is still going (resolve stage) — or the run was simply fast.
      const streamed = await page.waitFor((id) => {
        const p = document.querySelector(`.sub-run-ui[data-run="${id}"] .sub-run`);
        const rows = document.querySelectorAll('.sub-table tbody tr.dt-row').length;
        if (p && p.dataset.status === 'running' && rows > 0) return 'streaming';
        return p && p.dataset.status !== 'running' ? 'finished' : false;
      }, { args: [scanRunId], timeout: 300000, interval: 60, message: 'rows or finish' });
      process.stdout.write(`        note: first rows seen while ${streamed}\n`);
      const status = await page.waitFor(DONE(scanRunId), { timeout: 300000, message: 'scan finished' });
      assertEqual(status, 'done', 'run status');
      const chips = await page.evaluate(() => [...document.querySelectorAll('.sub-chip')].map((c) => `${c.dataset.source}:${c.dataset.state}${c.dataset.health ? `/${c.dataset.health}` : ''}`));
      process.stdout.write(`        note: sources ${chips.join(', ')}\n`);
      const info = await tableInfo(page);
      const found = await statValue(page, 'found');
      assert(found >= 3, `found ≥ 3 (${found})`);
      assertEqual(info.rows, Math.min(found, 200), 'table rows = Found (wildcard suspects hidden)');
      assert(info.names.includes(DOMAIN), 'apex listed');
      assert(info.kinds.includes('cloudflare'), `a Cloudflare row: ${info.kinds.join(',')}`);
      const ui = await page.evaluate(() => ({
        cancel: !document.querySelector('[data-action="sub-cancel"]').hidden,
        busy: document.getElementById('main').getAttribute('aria-busy'),
        meta: document.querySelector('.sub-run-meta').textContent,
        progressHidden: document.querySelector('.sub-progress').hidden,
        actions: [...document.querySelectorAll('.page-actions button')].map((b) => b.textContent.trim()),
        reasonTitle: document.querySelector('.sub-kind [data-kind="cloudflare"]')?.title || ''
      }));
      assert(!ui.cancel && ui.busy === 'false' && /Finished in/.test(ui.meta) && ui.progressHidden, `finished UI: ${JSON.stringify(ui)}`);
      assert(ui.actions.includes('Copy link') && ui.actions.includes('Run again'), `page actions: ${ui.actions}`);
      assert(/Cloudflare/.test(ui.reasonTitle), `translated reason tooltip: ${ui.reasonTitle}`);
      const cf = await statValue(page, 'cloudflare');
      assert(cf >= 1, 'Behind Cloudflare stat');
      assert(await page.evaluate(() => !!document.querySelector('.sub-summary [data-summary="cloudflare"]')), 'Cloudflare note');
      await assertNoHorizontalScroll(page, 'results');
      await shot(page, opts, 'subdomains-desktop-light-en-results');
    });

    await run.step('engine v2: stage counts, "found through DNS" chips, readable origin ids', async () => {
      const info = await page.evaluate(() => ({
        stages: Object.fromEntries([...document.querySelectorAll('.sub-stage')].map((s) => [s.dataset.stage, `${s.dataset.state}${s.dataset.found !== undefined ? `+${s.dataset.found}` : ''}`])),
        summary: document.querySelector('.sub-tech-summary')?.textContent || '',
        dns: Number(document.querySelector('.sub-tech-summary')?.dataset.dns),
        chips: [...document.querySelectorAll('.sub-tech-chip')].map((c) => `${c.dataset.tech}=${c.querySelector('.sub-tech-count').textContent}`),
        origins: [...new Set([...document.querySelectorAll('.sub-table .sub-origin')].map((o) => `${o.dataset.origin}=${o.textContent}`))]
      }));
      process.stdout.write(`        note: stages ${JSON.stringify(info.stages)}\n        note: ${info.summary} · ${info.chips.join(', ')}\n`);
      assert(Object.values(info.stages).every((s) => /^(done|skipped)/.test(s)), `stages settled: ${JSON.stringify(info.stages)}`);
      assert(/^done\+\d+$/.test(info.stages.bruteforce), `wordlist stage shows what it found: ${info.stages.bruteforce}`);
      assert(/Found through DNS: [\d,]+ · from passive sources: [\d,]+/.test(info.summary), `technique summary: ${info.summary}`);
      assert(info.dns >= 1 && info.chips.some((c) => c.startsWith('wordlist=')), `DNS discovery found names: ${info.chips}`);
      assert(!info.origins.some((o) => /=(dns-mine:|wordlist$|permutation$|recursive$)/.test(o)), `origin ids are labelled: ${info.origins}`);
    });

    await run.step('learned names: the finished scan saved bare labels only; the wordlist line says what was used', async () => {
      const info = await page.waitFor(() => {
        const raw = localStorage.getItem('ssds.learned.labels');
        const label = document.querySelector('.sub-learned .check-text')?.textContent || '';
        return raw && /\(\d[\d,]*\)$/.test(label) ? { raw, label, usage: document.querySelector('.sub-wl-usage')?.textContent || '' } : false;
      }, { message: 'learned labels recorded' });
      const labels = Object.keys(JSON.parse(info.raw).labels || {});
      assert(labels.length > 0 && labels.every((l) => /^[a-z0-9-]+$/.test(l) && !/^\d+$/.test(l)), `bare, non-numeric labels only: ${labels.slice(0, 20)}`);
      assert(!labels.includes(DOMAIN.split('.')[0]), 'the apex itself is not a label');
      assertEqual(info.label, `Try names found in your earlier scans first (${labels.length.toLocaleString('en-US')})`, 'switch label counts them');
      assert(/^Wordlist: smart/.test(info.usage), `wordlist usage line: ${info.usage}`);
      process.stdout.write(`        note: ${labels.length} learned labels; ${info.usage}\n`);
      // The Advanced summary counts what the next scan tries (at most 1,000), and "Forget learned
      // names" updates it at once — it sits in the disclosure's <summary>, right above the button.
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
      const tried = Math.min(labels.length, 1000);
      const summary = await page.waitFor((want) => {
        const text = document.querySelector('.sub-adv-summary').textContent;
        return text.includes(want) ? text : false;
      }, { args: [`${tried.toLocaleString('en-US')} learned name${tried === 1 ? '' : 's'}`], timeout: 5000, message: 'summary counts the learned names' });
      await page.click('[data-action="sub-learned-clear"]');
      const forgot = await page.waitFor(() => {
        const label = document.querySelector('.sub-learned .check-text').textContent;
        return /none yet/.test(label) ? { label, summary: document.querySelector('.sub-adv-summary').textContent } : false;
      }, { timeout: 5000, message: 'learned names forgotten' });
      assert(!/learned name/.test(forgot.summary), `summary refreshed after Forget: ${forgot.summary} (was: ${summary})`);
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = false; });
    });

    await run.step('source status: quota / outage texts instead of generic errors (HackerTarget quota is often used up)', async () => {
      const info = await page.evaluate(() => ({
        chips: [...document.querySelectorAll('.sub-chip')].map((c) => ({ id: c.dataset.source, state: c.dataset.state, health: c.dataset.health || '', value: c.querySelector('.sub-chip-value').textContent, title: c.title })),
        notes: [...document.querySelectorAll('.sub-src-note')].map((n) => ({ id: n.dataset.source, health: n.dataset.health, text: n.textContent }))
      }));
      for (const n of info.notes) process.stdout.write(`        note: ${n.id} (${n.health}): ${n.text}\n`);
      assert(info.chips.every((c) => c.state !== 'pending'), `chips settled: ${JSON.stringify(info.chips)}`);
      for (const c of info.chips.filter((x) => x.health === 'rate-limited')) {
        assertEqual([c.state, c.value], ['limited', 'Quota used up'], `${c.id} chip`);
        assert(/quota|limit/i.test(c.title), `${c.id} tooltip explains the quota: ${c.title}`);
        assert(info.notes.some((n) => n.id === c.id && /quota|limit/i.test(n.text)), `${c.id} status line`);
      }
      for (const c of info.chips.filter((x) => ['unavailable', 'timeout', 'error'].includes(x.health))) {
        assert(info.notes.some((n) => n.id === c.id), `${c.id} has a status line`);
      }
      const ht = info.chips.find((c) => c.id === 'hackertarget');
      if (ht) process.stdout.write(`        note: HackerTarget chip: ${ht.state}/${ht.health} "${ht.value}"\n`);
    });

    await run.step('ORIGIN panel: proxied hosts, origin networks, candidates and the CLI sweep command', async () => {
      const info = await page.evaluate(() => {
        const panel = document.querySelector('.sub-org');
        if (!panel) return null;
        return {
          proxied: Number(panel.dataset.proxied),
          networks: [...panel.querySelectorAll('.sub-org-net')].map((n) => n.dataset.cidr),
          leaks: [...panel.querySelectorAll('.sub-org-leak')].map((l) => `${l.dataset.host}→${l.dataset.ip}`),
          command: panel.querySelector('.sub-org-command code')?.textContent || null,
          cli: panel.querySelector('a[download]')?.getAttribute('href') || null,
          lead: panel.querySelector('.sub-org-lead').textContent,
          rows: panel.querySelectorAll('.sub-org-table tbody tr.dt-row').length,
          jump: !!document.querySelector('.sub-summary [data-action="sub-origin-link"]')
        };
      });
      assert(info, 'origin panel shown (the domain has Cloudflare hosts)');
      process.stdout.write(`        note: ${info.proxied} proxied, networks ${info.networks.join(', ') || 'none'}, leaks ${info.leaks.join(', ') || 'none'}\n        note: command ${info.command || '-'}\n`);
      assert(info.proxied >= 1 && /never publishes/.test(info.lead), `lead: ${info.lead}`);
      assertEqual(info.cli, 'cli/ssl_origin_scan.py', 'CLI download link');
      assert(info.jump, 'the Cloudflare summary links to the panel');
      if (info.networks.length) {
        // An IPv4 /24 is swept whole when it clusters several origins, otherwise as its exact
        // addresses; an IPv6 /48 (which the CLI refuses) always goes in as its known addresses.
        const tokens = (info.command || '').split(/\s+/);
        const covered = (cidr) => tokens.includes(cidr) || tokens.some((x) => x.startsWith(cidr.replace(/0\/24$/, '')));
        assert(info.command && info.command.startsWith('python3 ssl_origin_scan.py -t ') && info.networks.filter((c) => !c.includes(':')).every(covered)
          && !/:\S*\/48\b/.test(info.command), `command sweeps the networks: ${info.command}`);
      }
      if (info.command) {
        // The same (validated, quoted-when-needed) tokens for PowerShell, launched with `python`.
        await page.click('.sub-org-shell .seg-btn[data-value="powershell"]');
        const ps = await page.waitFor(() => {
          const c = document.querySelector('.sub-org-command code')?.textContent || '';
          return c.startsWith('python ssl_origin_scan.py') ? c : false;
        }, { message: 'PowerShell variant' });
        assertEqual(ps.replace(/^python /, 'python3 '), info.command, 'same tokens in both shells');
        await page.click('.sub-org-shell .seg-btn[data-value="posix"]');
        await page.waitFor(() => (document.querySelector('.sub-org-command code')?.textContent || '').startsWith('python3 '), { message: 'back to POSIX' });
      }
      await page.evaluate(() => document.querySelector('.sub-org').scrollIntoView({ block: 'start' }));
      await shot(page, opts, 'subdomains-desktop-light-en-origin');
      await shotEl(page, opts, 'subdomains-origin-desktop-light-en', '.sub-org');
      await page.evaluate(() => window.scrollTo(0, 0));
    });

    await run.step('filters: segmented control, stat cards and search narrow the table', async () => {
      const all = (await tableInfo(page)).rows;
      await page.click('.sub-filter [data-value="resolving"]');
      let info = await tableInfo(page);
      assertEqual(info.pressed, 'resolving', 'pressed');
      assertEqual(info.withIp, info.rows, 'every row resolves');
      assertEqual(info.rows, Math.min(await statValue(page, 'resolving'), 200), 'rows = Resolving stat');
      await page.click('.sub-filter [data-value="cloudflare"]');
      info = await tableInfo(page);
      assert(info.rows > 0 && info.kinds.every((k) => k === 'cloudflare'), `cloudflare only: ${info.kinds}`);
      assertEqual(await page.evaluate(() => document.querySelector('[data-stat="cloudflare"]').getAttribute('aria-pressed')), 'true', 'stat card pressed');
      await page.click('.sub-filter [data-value="unresolved"]');
      info = await tableInfo(page);
      assertEqual(info.withIp, 0, 'no IPs among the non-resolving');
      await page.click('.sub-stats [data-stat="direct"]');
      info = await tableInfo(page);
      assert(info.kinds.every((k) => k === 'direct' || k === 'private'), `direct only: ${info.kinds}`);
      assertEqual(info.pressed, 'direct', 'segmented follows the stat card');
      await page.click('.sub-stats [data-stat="cdn"]');
      info = await tableInfo(page);
      assert(info.kinds.every((k) => k === 'cdn' || k === 'platform'), `cdn only: ${info.kinds}`);
      assertEqual(info.pressed, null, 'no segment for CDN / platform');
      await page.click('.sub-filter [data-value="all"]');
      assertEqual((await tableInfo(page)).rows, all, 'all again');
      await page.type('.sub-table .dt-search-input', `www.${DOMAIN}`);
      await page.waitFor((d) => [...document.querySelectorAll('.sub-table tbody tr.dt-row')].every((r) => r.textContent.includes(d)), { args: [`www.${DOMAIN}`], message: 'search' });
      await shot(page, opts, 'subdomains-desktop-light-en-search');
      await page.type('.sub-table .dt-search-input', '');
      await page.waitFor((n) => document.querySelectorAll('.sub-table tbody tr.dt-row').length === n, { args: [all], message: 'search cleared' });
    });

    await run.step('links: subdomain → DNS Lookup, IP → IP Intel; sources shown as badges', async () => {
      const links = await page.evaluate(() => ({
        host: document.querySelector('.sub-table .sub-host-name')?.getAttribute('href'),
        ip: document.querySelector('.sub-table .sub-ip')?.getAttribute('href'),
        origins: [...new Set([...document.querySelectorAll('.sub-table .sub-origin')].map((o) => o.dataset.origin))],
        mono: getComputedStyle(document.querySelector('.sub-table .sub-host-name')).fontFamily
      }));
      assert(/^#\/lookup\?name=/.test(links.host), `lookup link ${links.host}`);
      assert(/^#\/ip\?ip=/.test(links.ip), `ip link ${links.ip}`);
      assert(links.origins.includes('input'), `origins ${links.origins}`);
      assert(/mono|Consolas|Menlo|Courier/i.test(links.mono), `monospace names: ${links.mono}`);
    });

    await run.step('exports: copy, names.txt, CSV and JSON; "resolving only" narrows them', async () => {
      const found = await statValue(page, 'found');
      const resolving = await statValue(page, 'resolving');
      const count = () => page.evaluate(() => Number(document.querySelector('.sub-act-count').textContent.replace(/[^\d]/g, '')));
      assertEqual(await count(), found, 'count badge');
      await takeDownloads(page);
      await page.click('[data-export="names"]');
      await page.click('[data-export="csv"]');
      await page.click('[data-export="json"]');
      const files = await takeDownloads(page);
      assertEqual(files.map((f) => f.name.replace(/\d{8}-\d{4}/, 'STAMP')), ['names.txt', `subdomains-${DOMAIN}-STAMP.csv`, `subdomains-${DOMAIN}-STAMP.json`], 'files');
      const names = files[0].text.trim().split('\n');
      assertEqual(names.length, found, 'names.txt lines');
      assert(names.includes(DOMAIN), 'apex in names.txt');
      assertEqual(csvHeader(files[1].text).slice(0, 4), ['Subdomain', 'DNS status', 'Classification', 'Provider'], 'CSV header');
      assert(files[1].bom, 'CSV has a BOM (Excel)');
      const json = JSON.parse(files[2].text);
      assertEqual([json.generator, json.domains[0], json.subdomains.length, json.complete], ['DomainScope', DOMAIN, found, true], 'JSON');
      assert(json.discovery && json.discovery.total === found && Array.isArray(json.sourceHealth) && json.origin && Array.isArray(json.origin.networks), 'JSON carries discovery, source health and origin data');
      assertEqual(json.options.bruteforce, 'smart', 'JSON options');
      await page.click('.sub-resolving-only .check-label');
      assertEqual(await count(), resolving, 'resolving-only count');
      await page.click('[data-export="names"]');
      const [only] = await takeDownloads(page);
      assertEqual(only.text.trim().split('\n').length, resolving, 'resolving-only names.txt');
      await page.click('[data-action="sub-copy"]');
      await page.waitFor(() => document.querySelector('[data-action="sub-copy"]').classList.contains('is-copied')
        || document.querySelector('.toast-error'), { message: 'copy feedback' });
      const copy = await page.evaluate(async () => {
        const ok = document.querySelector('[data-action="sub-copy"]').classList.contains('is-copied');
        let text = null;
        try { text = await navigator.clipboard.readText(); } catch { text = null; }
        document.querySelectorAll('.toast').forEach((x) => x.remove());
        return { ok, text };
      });
      assert(copy.ok, 'copy succeeded (button shows "Copied")');
      if (copy.text !== null) assertEqual(copy.text.trim().split('\n').length, resolving, 'clipboard lines');
      else process.stdout.write('        note: clipboard not readable in this browser; copy feedback checked only\n');
      await page.click('.sub-resolving-only .check-label');
      assertEqual(await count(), found, 'count restored');
    });

    await run.step('wildcard suspects are hidden by default and can be shown', async () => {
      const wild = await page.evaluate(() => {
        const box = document.querySelector('.sub-wild-toggle');
        return box && !box.hidden ? Number(box.textContent.replace(/[^\d]/g, '')) : 0;
      });
      if (!wild) {
        assert(await page.evaluate(() => !document.querySelector('.sub-table .sub-row-wildcard')), 'no wildcard rows shown');
        process.stdout.write(`        note: ${DOMAIN} has no wildcard suspects; toggle hidden as expected\n`);
        return;
      }
      const before = (await tableInfo(page)).rows;
      await page.click('.sub-wild-toggle .check-label');
      await page.waitFor((n) => document.querySelectorAll('.sub-table tbody tr.dt-row').length === n, { args: [Math.min(before + wild, 200)] });
      await page.click('.sub-wild-toggle .check-label');
    });

    await run.step('results survive DNS Lookup + Back (no re-scan)', async () => {
      const name = await page.evaluate(() => document.querySelector('.sub-table .sub-host-name').textContent);
      await page.click('.sub-table .sub-host-name');
      await page.waitFor(() => document.documentElement.dataset.view === 'lookup', { message: 'lookup view' });
      const [route, query = ''] = (await page.evaluate(() => location.hash)).split('?');
      assertEqual(route, '#/lookup', 'lookup route');
      assertEqual(new URLSearchParams(query).get('name'), name, 'lookup hash carries the name');
      await page.evaluate(() => history.back());
      await page.waitFor(() => document.documentElement.dataset.view === 'subdomains' && document.querySelector('.sub-run-ui'), { message: 'back to subdomains' });
      await sleep(300);
      assertEqual(await currentRunId(page), scanRunId, 'same run');
      assertEqual(await page.evaluate(() => document.querySelector('.sub-run').dataset.status), 'done', 'not re-running');
      assert((await tableInfo(page)).rows >= 3, 'rows still there');
    });

    await run.step('hand-over: "Open in SSL Targets" pre-fills the domain there', async () => {
      assert(await page.evaluate(() => /Which servers need the certificate/.test(document.querySelector('.sub-cta').textContent)), 'CTA text');
      await page.click('[data-action="sub-cta"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'scan' && document.querySelector('[data-role="scan-domains"]'), { timeout: 15000, message: 'scan view' });
      const info = await page.evaluate(() => ({ hash: location.hash, value: document.querySelector('[data-role="scan-domains"]').value }));
      assertEqual(info.hash, `#/scan?domain=${DOMAIN}`, 'scan route');
      assert(info.value.includes(DOMAIN), `domain pre-filled: ${info.value}`);
      await gotoRoute(page, '#/subdomains');
      assertEqual(await currentRunId(page), scanRunId, 'results still there');
    });

    run.group('Turkish, dark mode, phone');
    await run.step('Turkish re-mount keeps the results; natural Turkish labels', async () => {
      await setLangUi(page, 'tr');
      await page.waitFor(() => document.querySelector('.sub-run-ui'));
      const info = await page.evaluate(() => ({
        h1: document.querySelector('h1.page-title').textContent,
        group: document.querySelector('.nav-group-label').textContent,
        run: document.querySelector('[data-action="sub-run"]').textContent.trim(),
        title: document.querySelector('.sub-hero-title').textContent,
        stat: document.querySelector('[data-stat="cloudflare"] .stat-label').textContent,
        segs: [...document.querySelectorAll('.sub-filter .seg-btn')].map((b) => b.textContent),
        cta: document.querySelector('[data-action="sub-cta"]').textContent.trim(),
        rows: document.querySelectorAll('.sub-table tbody tr.dt-row').length
      }));
      assertEqual([info.h1, info.group, info.run, info.title], ['Subdomain Tarama', 'Keşif', 'Tara', 'Hangi alan adını tarayalım?'], 'TR labels');
      assertEqual(info.stat, 'Cloudflare arkasında', 'TR stat');
      assertEqual(info.segs, ['Tümü', 'Çözümlenen', 'Cloudflare', 'Doğrudan', 'Çözümlenmeyen'], 'TR filters');
      assertEqual(info.cta, 'SSL Hedefleri’nde aç', 'TR CTA');
      assert(info.rows >= 3, 'rows kept');
      assertEqual(await currentRunId(page), scanRunId, 'same run after the re-mount');
      await shot(page, opts, 'subdomains-desktop-light-tr-results');
    });

    await run.step('dark mode (TR + EN) has no horizontal scroll', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await sleep(150);
      await assertNoHorizontalScroll(page, 'dark');
      await shot(page, opts, 'subdomains-desktop-dark-tr-results');
      await setLangUi(page, 'en');
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
      await shot(page, opts, 'subdomains-desktop-dark-en-results');
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = false; });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    await run.step('phone 390×844 (TR, light + dark): the results stack into cards, name + classification on screen, never a page scroll', async () => {
      await page.setViewport({ width: 390, height: 844, mobile: true });
      await setLangUi(page, 'tr');
      await sleep(200);
      await assertNoHorizontalScroll(page, 'phone results');
      // Stacked card rows: each row is a block, and the classification (Cloudflare / Doğrudan) stays
      // inside the viewport (the phone's main answer is no longer scrolled off to the right).
      const table = await page.evaluate(() => {
        const row = document.querySelector('.sub-table tbody tr.dt-row');
        if (!row) return null;
        const vw = document.documentElement.clientWidth;
        const kind = row.querySelector('.sub-kind [data-kind]');
        const name = row.querySelector('.sub-host-name');
        return {
          block: getComputedStyle(row).display,
          nameVisible: !!name && name.getBoundingClientRect().right <= vw + 1,
          kindVisible: !!kind && kind.getBoundingClientRect().right <= vw + 1
        };
      });
      assert(table && table.block === 'block' && table.nameVisible && table.kindVisible, `stacked, name + classification on screen: ${JSON.stringify(table)}`);
      const btn = await page.evaluate(() => {
        const r = document.querySelector('[data-action="sub-run"]').getBoundingClientRect();
        return { w: Math.round(r.width), vw: document.documentElement.clientWidth };
      });
      assert(btn.w > btn.vw * 0.7, `full-width Scan button on phones: ${JSON.stringify(btn)}`);
      await shot(page, opts, 'subdomains-mobile-light-tr-results');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await sleep(150);
      await assertNoHorizontalScroll(page, 'phone dark');
      await shot(page, opts, 'subdomains-mobile-dark-tr-results');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await page.setViewport({ width: 1440, height: 900 });
    });

    await run.step('phone 390×844: the Advanced options and the ORIGIN panel fit (TR/EN × light/dark)', async () => {
      await page.setViewport({ width: 390, height: 844, mobile: true });
      await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
      // Show every control: a manual language choice and a custom list with a rejected entry.
      await page.click('.sub-lang-auto-toggle .check-label');
      await page.type('[data-role="sub-custom"]', 'api\nkunden\n-bad-');
      try {
        for (const lang of ['en', 'tr']) {
          for (const scheme of ['light', 'dark']) {
            await setLangUi(page, lang);
            await page.emulateMedia({ 'prefers-color-scheme': scheme });
            await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
            await sleep(200);
            await assertNoHorizontalScroll(page, `phone ${lang} ${scheme}`);
            const adv = await overflowingIn(page, '.sub-advanced');
            assertEqual(adv, [], `Advanced controls inside 390 px (${lang} ${scheme})`);
            await shotEl(page, opts, `subdomains-advanced-mobile-${scheme}-${lang}`, '.sub-advanced');
            if (await page.evaluate(() => !!document.querySelector('.sub-org'))) {
              const org = await overflowingIn(page, '.sub-org');
              assertEqual(org, [], `ORIGIN panel inside 390 px (${lang} ${scheme})`);
              await shotEl(page, opts, `subdomains-origin-mobile-${scheme}-${lang}`, '.sub-org');
            }
          }
        }
      } finally {
        await page.emulateMedia({ 'prefers-color-scheme': 'light' });
        await setLangUi(page, 'en');
        await page.evaluate(() => { document.querySelector('.sub-advanced').open = true; });
        await page.click('.sub-lang-auto-toggle .check-label');
        await page.click('[data-action="sub-custom-clear"]');
        await page.evaluate(() => { document.querySelector('.sub-advanced').open = false; });
        await page.setViewport({ width: 1440, height: 900 });
      }
      assertEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.subdomains.options')).locales), null, 'back to automatic languages');
    });

    run.group('Route params and Cancel');
    await run.step('update(): a new ?domain= pre-fills the box without a re-mount or a scan', async () => {
      const marker = await page.evaluate(() => { document.querySelector('.sub-view').dataset.marker = 'kept'; return true; });
      assert(marker, 'marker');
      await page.evaluate(() => { location.hash = '#/subdomains?domain=example.org'; });
      await page.waitFor(() => document.querySelector('[data-role="sub-domain"]').value === 'example.org', { message: 'prefilled' });
      assertEqual(await page.evaluate(() => document.querySelector('.sub-view').dataset.marker), 'kept', 'no re-mount');
      assertEqual(await currentRunId(page), scanRunId, 'no new scan');
    });

    await run.step('Cancel stops a running scan and keeps what was found', async () => {
      await setSources(page, ['anubis']);
      await page.click('input[name="sub-bruteforce"][value="smart"]');
      await typeAndSubmit(page, 'github.com');
      await page.waitFor((old) => {
        const ui = document.querySelector('.sub-run-ui');
        return ui && ui.dataset.run !== old;
      }, { args: [scanRunId], message: 'new run' });
      const id = await currentRunId(page);
      await sleep(800);
      await page.click('[data-action="sub-cancel"]');
      assertEqual(await page.waitFor(DONE(id), { timeout: 20000, message: 'cancelled' }), 'cancelled', 'status');
      const info = await page.evaluate(() => ({
        notice: document.querySelector('.sub-run-notice')?.textContent || '',
        run: !document.querySelector('[data-action="sub-run"]').hidden,
        readOnly: document.querySelector('[data-role="sub-domain"]').readOnly
      }));
      assert(/Cancelled after/.test(info.notice) && info.run && !info.readOnly, `after cancel: ${JSON.stringify(info)}`);
      // Streamed partials never resolve once cancelled: no row may keep claiming "resolving…" (the
      // table redraws on its next frame).
      await page.waitFor(() => ![...document.querySelectorAll('.sub-table .sub-mini-badge')].some((b) => /resolving/i.test(b.textContent)),
        { timeout: 5000, message: 'no "resolving…" badge left after Cancel' });
      await shot(page, opts, 'subdomains-desktop-light-en-cancelled');
    });

    await run.step('i18n: no missing keys, TR and EN key sets match', async () => {
      await assertNoMissingKeys(page);
    });
    await run.step('no console errors, exceptions or CSP violations (main tab)', async () => {
      await assertClean(page, 'subdomains', origin);
    });
    await page.close();

    run.group('Fresh tabs: shared links');
    await run.step('#/subdomains?domain=… only pre-fills; the phone empty state has no horizontal scroll', async () => {
      const phone = await browser.newPage('about:blank', { width: 390, height: 844, mobile: true });
      await phone.goto(`${server.url}#/subdomains?domain=github.com`);
      await waitReady(phone);
      await setLangUi(phone, 'tr');
      const info = await phone.evaluate(() => ({
        value: document.querySelector('[data-role="sub-domain"]').value,
        run: !!document.querySelector('.sub-run-ui'),
        intro: !document.querySelector('.sub-intro').hidden
      }));
      assertEqual(info, { value: 'github.com', run: false, intro: true }, 'pre-filled, not started');
      await assertNoHorizontalScroll(phone, 'phone empty');
      await shot(phone, opts, 'subdomains-mobile-light-tr-empty');
      await phone.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await sleep(150);
      await shot(phone, opts, 'subdomains-mobile-dark-tr-empty');
      await assertClean(phone, 'phone empty', origin);
      await phone.close();
    });

    await run.step('#/subdomains?domain=…&run=1 asks for one click, then scans (sources, wordlist, permutations and hints off); a reload does not scan', async () => {
      const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
      // A new tab follows the host's colour scheme: pin light so the *-light-* screenshots are light.
      await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
      await tab.goto(`${server.url}#/about`);
      await waitReady(tab);
      await tab.evaluate(() => localStorage.setItem('ssds.subdomains.options', JSON.stringify({ sources: [], bruteforce: 'off', includeExpired: false, permutations: false, originHints: false })));
      await tab.evaluate(() => { location.hash = '#/subdomains?domain=example.com&run=1'; });
      await tab.waitFor(() => document.querySelector('[data-action="sub-link-start"]'), { timeout: 15000, message: 'link prompt' });
      await sleep(500);
      const before = await tab.evaluate(() => ({
        run: !!document.querySelector('.sub-run-ui'),
        value: document.querySelector('[data-role="sub-domain"]').value,
        prompt: document.querySelector('.sub-link-prompt').textContent
      }));
      assertEqual([before.run, before.value], [false, 'example.com'], 'pre-filled, not started by the link');
      assert(before.prompt.includes('example.com'), `the prompt names the domain: ${before.prompt}`);
      await shot(tab, opts, 'subdomains-desktop-light-en-link-prompt');
      await tab.click('[data-action="sub-link-start"]');
      await tab.waitFor(() => document.querySelector('.sub-run-ui'), { timeout: 15000, message: 'started by the click' });
      assertEqual(await tab.evaluate(() => document.querySelector('.sub-link-prompt').hidden), true, 'prompt gone');
      assertEqual(await tab.evaluate(() => location.hash), '#/subdomains?domain=example.com', 'run=1 removed once started');
      const id = await currentRunId(tab);
      assertEqual(await tab.waitFor(DONE(id), { timeout: 60000, message: 'done' }), 'done', 'status');
      const info = await tab.evaluate(() => ({
        chips: document.querySelectorAll('.sub-chip').length,
        chipsHidden: document.querySelector('.sub-chips').hidden,
        stages: [...document.querySelectorAll('.sub-stage')].map((s) => `${s.dataset.stage}:${s.dataset.state}`),
        rows: [...document.querySelectorAll('.sub-table tbody tr.dt-row .sub-host-name')].map((a) => a.textContent)
      }));
      assert(info.chipsHidden && info.chips === 0, 'no source chips without sources');
      assertEqual(info.stages, ['sources:skipped', 'mining:done', 'wildcard:done', 'bruteforce:skipped', 'permutations:skipped', 'resolve:done', 'hints:skipped'], 'stages');
      assert(info.rows.includes('example.com'), `apex resolved: ${info.rows}`);
      await assertClean(tab, 'run=1', origin);
      // A reload (or a restored tab) pre-fills the box; nothing scans.
      await tab.reload();
      await waitReady(tab);
      await sleep(1000);
      const reloaded = await tab.evaluate(() => ({
        run: !!document.querySelector('.sub-run-ui'),
        prompt: !document.querySelector('.sub-link-prompt').hidden,
        value: document.querySelector('[data-role="sub-domain"]').value
      }));
      assertEqual(reloaded, { run: false, prompt: false, value: 'example.com' }, 'reload pre-fills only');
      await tab.close();
    });

    run.group('Emulated zone (no network): the ORIGIN panel with a network and both shells');
    await run.step(`${FAKE_APEX} answered in the page: origin /24, sweep command for POSIX and PowerShell, 390 px TR/EN × light/dark`, async () => {
      const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
      // A new tab follows the host's colour scheme: pin light so the *-light-* screenshots are light.
      await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
      try {
        await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeZoneScript(FAKE_APEX, FAKE_ZONE) });
        await tab.goto(`${server.url}#/about`);
        await waitReady(tab);
        await setLangUi(tab, 'en');
        // No passive source (nothing leaves the page), the small list, no permutations.
        await tab.evaluate(() => localStorage.setItem('ssds.subdomains.options', JSON.stringify({ sources: [], bruteforce: 'small', permutations: false, originHints: true })));
        await tab.evaluate((d) => { location.hash = `#/subdomains?domain=${d}&run=1`; }, FAKE_APEX);
        await tab.waitFor(() => document.querySelector('[data-action="sub-link-start"]'), { timeout: 15000, message: 'link prompt' });
        await tab.click('[data-action="sub-link-start"]');
        await tab.waitFor(() => document.querySelector('.sub-run-ui'), { timeout: 15000, message: 'started' });
        const id = await currentRunId(tab);
        assertEqual(await tab.waitFor(DONE(id), { timeout: 60000, message: 'emulated scan done' }), 'done', 'status');
        const info = await tab.evaluate(() => {
          const panel = document.querySelector('.sub-org');
          return {
            queries: window.__fakeDnsQueries,
            rows: [...document.querySelectorAll('.sub-table tbody tr.dt-row .sub-host-name')].map((a) => a.textContent).sort(),
            proxied: panel ? Number(panel.dataset.proxied) : 0,
            networks: panel ? [...panel.querySelectorAll('.sub-org-net')].map((n) => n.dataset.cidr) : [],
            command: panel?.querySelector('.sub-org-command code')?.textContent || null,
            shells: panel ? [...panel.querySelectorAll('.sub-org-shell .seg-btn')].map((b) => `${b.dataset.value}:${b.getAttribute('aria-pressed')}`) : []
          };
        });
        assert(info.queries > 100, `the zone answered the scan's queries: ${info.queries}`);
        assertEqual(info.rows, ['api.example.net', 'example.net', 'mail.example.net', 'shop.example.net', 'www.example.net'], 'hosts');
        assertEqual([info.proxied, info.networks], [2, ['203.0.113.0/24']], 'proxied hosts + the DNS-only network');
        assertEqual(info.command, 'python3 ssl_origin_scan.py -t 203.0.113.0/24 -n shop.example.net www.example.net', 'POSIX command');
        assertEqual(info.shells, ['posix:true', 'powershell:false'], 'shell toggle');
        await tab.click('.sub-org-shell .seg-btn[data-value="powershell"]');
        const ps = await tab.waitFor(() => {
          const c = document.querySelector('.sub-org-command code')?.textContent || '';
          return c.startsWith('python ') ? c : false;
        }, { message: 'PowerShell command' });
        assertEqual(ps, 'python ssl_origin_scan.py -t 203.0.113.0/24 -n shop.example.net www.example.net', 'PowerShell command');
        // The copy button copies exactly the command that is shown.
        await browser.conn.send('Browser.grantPermissions', { origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] }).catch(() => {});
        await tab.click('.sub-org-command .codeblock-head button');
        const clip = await tab.evaluate(() => navigator.clipboard.readText().catch(() => null));
        if (clip !== null) assertEqual(clip, ps, 'copied command');
        await shotEl(tab, opts, 'subdomains-origin-emulated-desktop-light-en', '.sub-org');
        // Phone: the panel (networks, command, toggle) fits in both languages and themes.
        await tab.setViewport({ width: 390, height: 844, mobile: true });
        for (const lang of ['en', 'tr']) {
          for (const scheme of ['light', 'dark']) {
            await setLangUi(tab, lang);
            await tab.emulateMedia({ 'prefers-color-scheme': scheme });
            await tab.waitFor(() => document.querySelector('.sub-org .sub-org-command code'), { message: 'panel after re-mount' });
            await sleep(150);
            await assertNoHorizontalScroll(tab, `emulated ${lang} ${scheme}`);
            assertEqual(await overflowingIn(tab, '.sub-org'), [], `ORIGIN panel inside 390 px (${lang} ${scheme})`);
            await shotEl(tab, opts, `subdomains-origin-emulated-mobile-${scheme}-${lang}`, '.sub-org');
          }
        }
        assert(/python ssl_origin_scan\.py/.test(await tab.evaluate(() => document.querySelector('.sub-org-command code').textContent)), 'the chosen shell survives a language re-mount');
        await assertClean(tab, 'emulated zone', origin);
      } finally {
        await tab.close();
      }
    });

    run.group('Emulated sibling domains (no network): the cross-brand origin candidate');
    await run.step('two apexes scanned together: a proxied ticket.<a> gets ticket.<b> (DNS-only) as its exact origin', async () => {
      const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
      // A new tab follows the host's colour scheme: pin light so the *-light-* screenshots are light.
      await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
      try {
        await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: multiZoneScript(SIBLING_APEXES, SIBLING_ZONE) });
        await tab.goto(`${server.url}#/about`);
        await waitReady(tab);
        await setLangUi(tab, 'en');
        // No passive source; small list; a custom list guarantees `ticket` is tried under both apexes.
        await tab.evaluate(() => {
          localStorage.setItem('ssds.subdomains.options', JSON.stringify({ sources: [], bruteforce: 'small', permutations: false, originHints: true }));
          sessionStorage.setItem('ssds.wordlist.custom', 'ticket\napi\nwww');
        });
        await tab.evaluate(() => { location.hash = '#/subdomains?domain=example.net,example.org&run=1'; });
        await tab.waitFor(() => document.querySelector('[data-action="sub-link-start"]'), { timeout: 15000, message: 'link prompt' });
        await tab.click('[data-action="sub-link-start"]');
        await tab.waitFor(() => document.querySelector('.sub-run-ui'), { timeout: 15000, message: 'started' });
        const id = await currentRunId(tab);
        assertEqual(await tab.waitFor(DONE(id), { timeout: 60000, message: 'sibling scan done' }), 'done', 'status');
        const info = await tab.evaluate(() => {
          const panel = document.querySelector('.sub-org');
          const rows = [...(panel ? panel.querySelectorAll('.sub-org-table tbody tr.dt-row') : [])];
          const ticket = rows.find((r) => (r.querySelector('td')?.textContent || '').startsWith('ticket.example.net'));
          return {
            proxied: panel ? Number(panel.dataset.proxied) : 0,
            suggest: !!(panel && panel.querySelector('.sub-org-suggest')),
            siblingCands: [...(panel ? panel.querySelectorAll('.sub-org-cand[data-kind="sibling-domain"]') : [])].map((c) => c.textContent),
            ticketRow: ticket ? ticket.textContent : null
          };
        });
        assert(info.proxied >= 1, `a proxied host on example.net: ${JSON.stringify(info)}`);
        assert(info.suggest, 'the panel suggests scanning sibling domains together');
        assert(info.siblingCands.some((tx) => /ticket\.example\.org/.test(tx) && /203\.0\.113\.20/.test(tx)),
          `ticket.example.net shows ticket.example.org (203.0.113.20) as a sibling-domain candidate: ${JSON.stringify(info.siblingCands)}`);
        assert(info.ticketRow && /203\.0\.113\.20/.test(info.ticketRow), `the candidate is on the ticket.example.net row: ${info.ticketRow}`);
        await shotEl(tab, opts, 'subdomains-origin-siblings-desktop-light-en', '.sub-org');
        await assertClean(tab, 'sibling zone', origin);
      } finally {
        await tab.close();
      }
    });

    run.group('Zone File hand-off (emulated DNS, nothing else leaves the page)');
    await run.step('"Scan now" in exact mode: chip, banner, zone names only (no sources / wordlist / permutations), exact origins + host targets in the command', async () => {
      const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
      // A new tab follows the host's colour scheme: pin light so the *-light-* screenshots are light.
      await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
      try {
        await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(ZONE_HANDOFF_APEX, ZONE_HANDOFF_DNS) });
        await tab.goto(`${server.url}#/about`);
        await waitReady(tab);
        await setLangUi(tab, 'en');
        // Stored options that WOULD ask sources and guess names: exact mode ignores them for one run.
        const stored = JSON.stringify({ sources: ['crtsh', 'anubis'], bruteforce: 'smart', permutations: true, originHints: true });
        await tab.evaluate((s) => localStorage.setItem('ssds.subdomains.options', s), stored);
        // What the Zone File view does on "Scan now": publish the zone, a one-shot intent, navigate.
        await tab.evaluate(async (zone) => {
          const { state } = await import('./assets/js/state.js');
          state.setSession('zone', zone);
          state.setSession('zoneScanIntent', { v: 1, target: 'subdomains', domain: zone.origin, mode: 'exact', autostart: true, at: Date.now() });
          location.hash = `#/subdomains?domain=${zone.origin}`;
        }, ZONE_HANDOFF_INPUT);
        await tab.waitFor(() => document.querySelector('.sub-run-ui'), { timeout: 15000, message: 'the intent started the scan' });
        const id = await currentRunId(tab);
        assertEqual(await tab.waitFor(DONE(id), { timeout: 60000, message: 'exact zone scan done' }), 'done', 'status');
        const info = await tab.evaluate(() => {
          const panel = document.querySelector('.sub-org');
          return {
            domain: document.querySelector('[data-role="sub-domain"]').value,
            chip: document.querySelector('[data-role="zone-chip"] .sub-zone-title')?.textContent || null,
            pressed: document.querySelector('.sub-zone-mode .seg-btn[aria-pressed="true"]')?.dataset.value || null,
            banner: document.querySelector('.sub-zone-banner')?.dataset.zoneMode || null,
            plan: { exact: document.querySelector('.sub-wl-plan')?.dataset.zoneExact || null, text: document.querySelector('.sub-wl-plan')?.textContent || '' },
            sourceChips: document.querySelectorAll('.sub-chip').length,
            stages: [...document.querySelectorAll('.sub-stage')].map((s) => `${s.dataset.stage}:${s.dataset.state}`),
            rows: [...document.querySelectorAll('.sub-table tbody tr.dt-row .sub-host-name')].map((a) => a.textContent).sort(),
            zoneChips: document.querySelectorAll('.sub-table [data-origin="zone"]').length,
            zoneBlock: panel ? [...panel.querySelectorAll('.sub-org-block[data-block="zone"] li')].map((li) => `${li.dataset.host}→${li.dataset.ip}`) : [],
            zoneLink: !!(panel && panel.querySelector('.sub-org-block[data-block="zone"] a')),
            command: panel?.querySelector('.sub-org-command code')?.textContent || null,
            blocked: window.__zoneBlocked,
            names: window.__zoneDnsNames,
            options: localStorage.getItem('ssds.subdomains.options')
          };
        });
        assertEqual([info.domain, info.pressed, info.banner], ['example.net', 'exact', 'exact'], 'pre-filled domain, exact chip, exact banner');
        assert(/6 names, 3 exact origins/.test(info.chip || ''), `chip: ${info.chip}`);
        // The Advanced plan line describes the exact run, not the stored wordlist options.
        assert(info.plan.exact === '1' && /Exact mode: only the 6 names from your zone file/.test(info.plan.text), `exact plan line: ${JSON.stringify(info.plan)}`);
        assertEqual(info.sourceChips, 0, 'no passive source was asked');
        for (const st of ['sources:skipped', 'bruteforce:skipped', 'permutations:skipped']) assert(info.stages.includes(st), `${st} in ${info.stages.join(' ')}`);
        // The zone's names, plus its wildcard base (`*.apps` → apps.example.net, seeded, never brute-forced).
        assertEqual(info.rows, ['api.example.net', 'apps.example.net', 'example.net', 'mail.example.net', 'shop.example.net', 'www.example.net'], 'only the zone names');
        assert(info.zoneChips >= 5, `"Zone file" origin chips in the table: ${info.zoneChips}`);
        assertEqual(info.zoneBlock, ['www.example.net→192.0.2.10'], 'exact origin from the zone file, first block');
        assert(!info.zoneLink, 'a zone origin is never an IP Intel link');
        const tokens = (info.command || '').split(/\s+/);
        assert(tokens[0] === 'python3' && tokens.includes('192.0.2.10') && !info.command.includes('192.0.2.0/24'), `exact zone origin, never a /24: ${info.command}`);
        assert(tokens.includes('origin-lb.example.org') && info.command.includes("'*.apps.example.net'"), `host target + quoted wildcard name: ${info.command}`);
        assertEqual(info.blocked, [], 'no request left the page except DNS for the zone');
        assert(info.names.every((n) => ['example.net', 'www.example.net', 'shop.example.net', 'api.example.net', 'mail.example.net', 'apps.example.net'].includes(n)),
          `only the zone's names were resolved (no guesses): ${info.names.join(', ')}`);
        assertEqual(info.options, stored, 'the exact run never touched the stored options');
        await tab.evaluate(() => document.querySelector('.sub-org-shell .seg-btn[data-value="powershell"]').click());
        const ps = await tab.waitFor(() => {
          const c = document.querySelector('.sub-org-command code')?.textContent || '';
          return c.startsWith('python ') ? c : false;
        }, { message: 'PowerShell command' });
        assert(ps.includes("'*.apps.example.net'") && ps.split(/\s+/).includes('192.0.2.10'), `PowerShell command: ${ps}`);
        await shotEl(tab, opts, 'subdomains-zone-chip-desktop-light-en', '.sub-hero');
        await shotEl(tab, opts, 'subdomains-zone-origin-desktop-light-en', '.sub-org');
        // "Include in discovery" / "Leave out" only change the next run (nothing starts).
        await tab.evaluate(() => document.querySelector('.sub-zone-mode .seg-btn[data-value="discover"]').click());
        const note = await tab.evaluate(() => document.querySelector('.sub-zone-note').dataset.mode);
        assertEqual(note, 'discover', 'mode note follows the choice');
        assertEqual(await currentRunId(tab), id, 'choosing a mode starts nothing');
        // Phone: chip + ORIGIN panel fit (EN light, TR dark).
        await tab.setViewport({ width: 390, height: 844, mobile: true });
        for (const [lang, scheme] of [['en', 'light'], ['tr', 'dark']]) {
          await setLangUi(tab, lang);
          await tab.emulateMedia({ 'prefers-color-scheme': scheme });
          await tab.waitFor(() => document.querySelector('[data-role="zone-chip"]') && document.querySelector('.sub-org'), { message: 'chip + panel after re-mount' });
          await sleep(150);
          await assertNoHorizontalScroll(tab, `zone chip ${lang} ${scheme}`);
          assertEqual(await overflowingIn(tab, '.sub-zone'), [], `zone chip inside 390 px (${lang} ${scheme})`);
          assertEqual(await overflowingIn(tab, '.sub-org'), [], `ORIGIN panel inside 390 px (${lang} ${scheme})`);
          await shotEl(tab, opts, `subdomains-zone-chip-mobile-${scheme}-${lang}`, '.sub-hero');
        }
        await setLangUi(tab, 'en');
        // Forget in the Zone File view (or "Delete all local data") removes the chip at once.
        await tab.evaluate(async () => (await import('./assets/js/state.js')).state.setSession('zone', undefined));
        await tab.waitFor(() => !document.querySelector('[data-role="zone-chip"]'), { message: 'chip gone after Forget' });
        await assertClean(tab, 'zone hand-off (Subdomains)', origin);
      } finally {
        await tab.close();
      }
    });

    /** What the Zone File view does on "Scan now": publish the zone, a one-shot intent, open Subdomains. */
    const zoneScanNow = (tab) => tab.evaluate(async (zone) => {
      const { state } = await import('./assets/js/state.js');
      state.setSession('zone', zone);
      state.setSession('zoneScanIntent', { v: 1, target: 'subdomains', domain: zone.origin, mode: 'exact', autostart: true, at: Date.now() });
      location.hash = `#/subdomains?domain=${zone.origin}`;
    }, ZONE_HANDOFF_INPUT);

    await run.step('slow DNS: the rows drawn while resolving get their "origin?" badge as soon as the zone scan ends', async () => {
      const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
      await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
      try {
        await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(ZONE_HANDOFF_APEX, ZONE_HANDOFF_DNS) });
        await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: slowDnsScript });
        await tab.goto(`${server.url}#/about`);
        await waitReady(tab);
        await setLangUi(tab, 'en');
        await tab.evaluate(() => { window.__dnsDelay = 40; });
        await zoneScanNow(tab);
        await tab.waitFor(() => document.querySelector('.sub-run-ui'), { timeout: 15000, message: 'the intent started the scan' });
        const id = await currentRunId(tab);
        // Rows on screen while the scan still runs: the case where the table reuses rows drawn
        // before the ORIGIN panel knew which hosts have an exact origin.
        const early = await tab.waitFor(() => {
          if (document.querySelector('.sub-run')?.dataset.status !== 'running') return 'after';
          return document.querySelector('.sub-table tbody tr.dt-row') ? 'while running' : false;
        }, { timeout: 60000, message: 'rows or the end of the scan' });
        if (early !== 'while running') process.stdout.write('        note: no row was drawn before the scan ended; the badge check below is weaker\n');
        assertEqual(await tab.waitFor(DONE(id), { timeout: 60000, message: 'slow zone scan done' }), 'done', 'status');
        const info = await tab.evaluate(() => ({
          badges: [...document.querySelectorAll('.sub-table tbody tr.dt-row')].filter((tr) => tr.querySelector('.sub-origin-hint'))
            .map((tr) => tr.querySelector('.sub-host-name').textContent).sort(),
          candidates: [...new Set([...document.querySelectorAll('.sub-org-block li[data-host]')].map((li) => li.dataset.host))].sort()
        }));
        assert(info.candidates.includes('www.example.net'), `the zone's exact origin is in the panel: ${info.candidates}`);
        assertEqual(info.badges, info.candidates, 'every host with an exact origin has its "origin?" badge, without leaving the page');
        await tab.evaluate(() => document.querySelector('.sub-table .sub-origin-hint').click());
        await tab.waitFor(() => document.activeElement?.classList.contains('sub-org-title'), { message: 'the badge jumps to the ORIGIN panel' });
        await assertClean(tab, 'slow zone scan', origin);
      } finally {
        await tab.close();
      }
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
