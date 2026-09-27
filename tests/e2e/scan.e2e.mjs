#!/usr/bin/env node
/**
 * scan.e2e.mjs — end-to-end test of the "SSL Targets" view against the LIVE services
 * (DoH resolvers, crt.sh / Anubis / HackerTarget …) in a real headless Chrome/Edge.
 *
 *   node tests/e2e/scan.e2e.mjs [--domain npmjs.com] [--sources crtsh,anubis,hackertarget]
 *                               [--bruteforce small] [--browser chrome|edge] [--headed] [--no-shots]
 *
 * The default domain is a mid-size public site behind Cloudflare. Free source quotas are
 * small (Cert Spotter ≈ 10 requests/hour, HackerTarget ≈ 50/day), so the default source list
 * leaves Cert Spotter and OTX out; pass --sources to include them.
 *
 * What is checked:
 *   - pure helpers of views/scan.js (Node side)
 *   - the setup form: one requirement line (a check once met) instead of "optional" labels, a
 *     check on each completed step, Options as one collapsed line listing what differs from the
 *     defaults
 *   - the fixture certificate (tests/fixtures/rsa_multi_san.pem) uploaded through the file input
 *     (DOM.setFileInputFiles) auto-fills the domains; validation of empty / public-suffix input
 *   - Cancel, and a scan that keeps running while another tool is open (toast → back to results)
 *   - a full live scan: stages, per-source chips, streamed hosts, Cloudflare classification,
 *     inventory matching (the inventory is seeded with a real direct IP of the domain), the
 *     Servers / Behind CDN / Sources / CT tabs, filters, row details and every export
 *     (downloads are captured in the page, nothing is written to disk)
 *   - route params (#/scan?domain=…), language switch keeping the results, dark mode,
 *     390 px phone layout without horizontal scrolling, screenshots in tests/e2e/screenshots/
 *   - offline at 375×667: the sticky run bar keeps Start on screen without scrolling once a
 *     domain is entered, never covers the focused field, rests at the form's end, keeps focus
 *     Start ⇄ Cancel, floats with a shadow in both themes (TR too), no transition with reduced
 *     motion, stays compact on a tablet and in the flow on a wide screen; a CA certificate
 *     (tests/fixtures/ca.pem, no DNS names) leaves step 1 open with a warning sign, and the
 *     requirement line and Start's error say why
 *   - offline (emulated example.net, tests/fixtures/ec_wildcard.pem): keyboard focus moving
 *     Start ⇄ Cancel, a run cancelled mid-wordlist exporting its streamed hits (hosts CSV,
 *     names.txt with coverage; Copy summary stays off without a result), reduced motion (no
 *     smooth scroll), Copy summary of the finished scan (the servers that need the certificate
 *     by name, the inventory tooltip, a link with only the domain), one shell choice shared
 *     by the Behind CDN quick sweep, its step 3 and the Verify CLI card, and a rescan with crt.sh
 *     failing in the page (Copy summary says the host list may be incomplete)
 *   - zero console errors, exceptions and CSP violations; failures of the third-party APIs
 *     themselves (crt.sh 502 without CORS, 429s) are reported but do not fail the run.
 *
 * The small harness (runner, download capture, problem filter) is exported for
 * cert.e2e.mjs and bulk.e2e.mjs.
 */

import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { SOURCES as LIB_SOURCES } from '../../assets/js/lib/sources.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
/** Repository root. */
export const ROOT = path.resolve(HERE, '..', '..');
/** Screenshot folder (git-ignored). */
export const SHOTS = path.join(HERE, 'screenshots');
/** Test fixtures (certificates, keys, containers). */
export const FIXTURES = path.join(ROOT, 'tests', 'fixtures');
/** Served under a project path, like GitHub Pages (the live site is /domainscope/). */
export const BASE = '/domainscope/';

/* ------------------------------------------------------------------------ */
/* Harness (shared with cert.e2e.mjs and bulk.e2e.mjs)                      */
/* ------------------------------------------------------------------------ */

/** Command-line options. */
export function cliOptions(argv = process.argv.slice(2)) {
  const has = (name) => argv.includes(name);
  const value = (name, def) => {
    const i = argv.indexOf(name);
    return i !== -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : def;
  };
  return { has, value, browser: value('--browser', 'auto'), headed: has('--headed'), shots: !has('--no-shots') };
}

/** Minimal step runner with a summary and a non-zero exit code on failure. */
export function createRunner() {
  const results = [];
  let current = '';
  return {
    results,
    group(name) {
      current = name;
      process.stdout.write(`\n${name}\n`);
    },
    async step(name, fn) {
      const t0 = Date.now();
      try {
        await fn();
        results.push({ group: current, name, ok: true });
        process.stdout.write(`  PASS  ${name} (${Date.now() - t0} ms)\n`);
      } catch (err) {
        results.push({ group: current, name, ok: false, error: err });
        process.stdout.write(`  FAIL  ${name}\n        ${String((err && err.stack) || err).split('\n').slice(0, 5).join('\n        ')}\n`);
      }
    },
    finish(extra = '') {
      const failed = results.filter((r) => !r.ok);
      process.stdout.write(`\n${results.length - failed.length} passed, ${failed.length} failed${extra}\n`);
      for (const f of failed) process.stdout.write(`  - ${f.group}: ${f.name}\n`);
      if (failed.length) process.exitCode = 1;
      return failed.length;
    }
  };
}

/** Throw `message` unless `cond` is truthy. */
export function assert(cond, message) {
  if (!cond) throw new Error(message);
}

/** Deep equality through JSON (enough for plain test data). */
export function assertEqual(actual, expected, message) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

/** Promise-based delay. */
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Capture downloads inside the page: blob downloads made through ui/download.js are kept
 * in `window.__downloads` instead of being saved. Installed for every new document.
 */
export async function installDownloadCapture(page) {
  await page.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `(() => {
      window.__downloads = [];
      const blobs = new Map();
      const create = URL.createObjectURL.bind(URL);
      URL.createObjectURL = (obj) => { const url = create(obj); blobs.set(url, obj); return url; };
      const click = HTMLAnchorElement.prototype.click;
      HTMLAnchorElement.prototype.click = function () {
        if (this.download && String(this.href).startsWith('blob:') && blobs.has(this.href)) {
          window.__downloads.push({ name: this.download, blob: blobs.get(this.href) });
          return undefined;
        }
        return click.call(this);
      };
    })();`
  });
}

/**
 * Replace the page's clipboard with a recorder: what the "Copy" buttons write lands in
 * window.__clip (read back with {@link takeClipboard}), without clipboard permissions. With
 * `fail`, every copy fails (the async API rejects and execCommand('copy') returns false), for the
 * fallbacks. Takes effect at once: the app reads navigator.clipboard at click time.
 * @param {import('./cdp.mjs').Page} page
 * @param {{ fail?: boolean }} [opts]
 */
export async function stubClipboard(page, { fail = false } = {}) {
  await page.evaluate((f) => {
    window.__clip = [];
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (text) => {
          if (f) throw new DOMException('Write permission denied.', 'NotAllowedError');
          window.__clip.push(String(text));
        }
      }
    });
    if (f) document.execCommand = () => false;
    else delete document.execCommand;
  }, fail);
}

/** Texts written to the stubbed clipboard since the last call ({@link stubClipboard}). */
export async function takeClipboard(page) {
  return page.evaluate(() => {
    const list = window.__clip || [];
    window.__clip = [];
    return list;
  });
}

/** Downloads captured since the last call: [{ name, text, bom, type }] (Blob.text() drops a BOM, `bom` reports it). */
export async function takeDownloads(page) {
  return page.evaluate(async () => {
    const list = window.__downloads || [];
    window.__downloads = [];
    return Promise.all(list.map(async (d) => {
      const head = new Uint8Array(await d.blob.slice(0, 3).arrayBuffer());
      return { name: d.name, text: await d.blob.text(), bom: head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf, type: d.blob.type };
    }));
  });
}

/** Wait until the shell has rendered its first route. */
export async function waitReady(page) {
  await page.waitFor(() => document.documentElement.dataset.appReady === 'true', { timeout: 20000, message: 'app ready' });
}

/** Navigate by hash and wait until the view has rendered. */
export async function gotoRoute(page, route) {
  const id = route.replace(/^#?\//, '').split('?')[0];
  await page.evaluate((r) => { window.location.hash = r; }, route.startsWith('#') ? route : `#/${route}`);
  await page.waitFor((view) => document.documentElement.dataset.view === view
    && document.querySelector('#page-body')?.dataset.view === view
    && document.querySelector('#page-body').childElementCount > 0
    && !document.querySelector('#page-body .page-loading'), { args: [id], message: `route ${id}`, timeout: 15000 });
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

/** Switch the UI language through the header toggle and wait for the re-mount. */
export async function setLangUi(page, lang) {
  const now = await page.evaluate(() => document.documentElement.lang);
  if (now === lang) return;
  await page.click(`[data-control="lang"] [data-value="${lang}"]`);
  await page.waitFor((l) => document.documentElement.lang === l, { args: [lang], message: `lang ${lang}` });
  await page.waitFor(() => document.querySelector('#page-body')?.childElementCount > 0);
  await sleep(150);
}

/** Elements sticking out of the viewport horizontally (outside scrolling containers). */
function overflowReport() {
  const vw = document.documentElement.clientWidth;
  const offenders = [];
  if (document.documentElement.scrollWidth > vw + 1) {
    const clipped = (el) => {
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        if (/(auto|scroll|hidden|clip)/.test(getComputedStyle(p).overflowX)) return true;
      }
      return false;
    };
    for (const el of document.body.querySelectorAll('*')) {
      const r = el.getBoundingClientRect();
      if (r.width && r.right > vw + 1 && !clipped(el)) {
        offenders.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} right=${Math.round(r.right)}`);
        if (offenders.length > 8) break;
      }
    }
  }
  return { scrollWidth: document.documentElement.scrollWidth, clientWidth: vw, offenders };
}

/** Fail when the page (not an inner scroller) scrolls horizontally. */
export async function assertNoHorizontalScroll(page, where) {
  const rep = await page.evaluate(overflowReport);
  assert(rep.scrollWidth <= rep.clientWidth + 1,
    `${where}: page scrolls horizontally (${rep.scrollWidth} > ${rep.clientWidth}); offenders: ${rep.offenders.join(', ')}`);
}

/** Full-page screenshot into SHOTS (toasts removed first); no-op with --no-shots. */
export async function shot(page, opts, name) {
  if (!opts.shots) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  await mkdir(SHOTS, { recursive: true });
  await page.screenshot(path.join(SHOTS, `${name}.png`), { fullPage: true });
}

/**
 * Failures of third-party services (a 502 without CORS headers from crt.sh, a 429 from OTX,
 * a resolver that is down) are facts of life for a backend-free app and are shown in the UI;
 * they are reported but do not fail the test. Everything else — console errors,
 * exceptions, CSP violations, failures of our own origin — does.
 */
export function splitProblems(p, ownOrigin) {
  const external = [];
  const issues = [
    ...p.consoleErrors.map((m) => `console.${m.type}: ${m.text}`),
    ...p.exceptions.map((e) => `exception: ${e.text}`),
    ...p.csp.map((c) => `CSP: ${JSON.stringify(c).slice(0, 300)}`)
  ];
  for (const e of p.logErrors) {
    const text = String(e.text || '');
    // The resource that failed: CORS messages name it ("Access to fetch at '<url>' from origin …"),
    // network entries carry it in e.url.
    const cors = /Access to \w+ at '([^']+)'/.exec(text);
    const target = cors ? cors[1] : String(e.url || '');
    const thirdParty = /^https:\/\//.test(target) && !target.startsWith(ownOrigin)
      && (e.source === 'network' || /CORS policy|Failed to load resource|net::ERR_/i.test(text));
    if (thirdParty) external.push(`log(${e.source}): ${e.text} ${e.url || ''}`.trim());
    else issues.push(`log(${e.source}): ${e.text} ${e.url || ''}`);
  }
  return { issues, external };
}

/** Fail on console errors, exceptions, CSP violations or failures of our own origin. */
export async function assertClean(page, where, ownOrigin) {
  const { issues, external } = splitProblems(await page.problems(), ownOrigin);
  if (external.length) {
    process.stdout.write(`        note: ${external.length} third-party request failure(s) (not counted):\n          ${external.slice(0, 6).join('\n          ')}\n`);
  }
  assert(issues.length === 0, `${where}: ${issues.length} problem(s):\n          ${issues.join('\n          ')}`);
}

/** Fail on i18n keys that were requested but missing, or that exist in only one language. */
export async function assertNoMissingKeys(page) {
  const info = await page.evaluate(async () => {
    const i = await import('./assets/js/i18n.js');
    const en = i.listKeys('en');
    const tr = new Set(i.listKeys('tr'));
    return { missing: i.getMissingKeys(), onlyEn: en.filter((k) => !tr.has(k)), onlyTr: [...tr].filter((k) => !en.includes(k)) };
  });
  assertEqual(info.missing, [], 'missing i18n keys');
  assertEqual(info.onlyEn, [], 'keys only in EN');
  assertEqual(info.onlyTr, [], 'keys only in TR');
}

/** Parse one CSV line (RFC 4180 subset, enough for headers). */
export function csvHeader(text) {
  const line = text.replace(/^﻿/, '').split(/\r?\n/)[0];
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i += 1; } else if (ch === '"') quoted = false; else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { out.push(cur); cur = ''; } else cur += ch;
  }
  out.push(cur);
  return out;
}

/* ------------------------------------------------------------------------ */
/* Scan test                                                                */
/* ------------------------------------------------------------------------ */

const DEFAULT_SOURCES = ['crtsh', 'anubis', 'hackertarget'];
/** Sources the app enables by default (lib/sources.js is the single source of truth). */
const DEFAULT_ENABLED = LIB_SOURCES.filter((s) => s.defaultEnabled).length;

async function nodeChecks(run) {
  const S = await import('../../assets/js/views/scan.js');
  run.group('Node: views/scan.js helpers');
  await run.step('parseDomainsInput normalizes, strips wildcards, rejects public suffixes', () => {
    const r = S.parseDomainsInput('Example.COM.tr\nhttps://www.örnek.com.tr/path *.foo.com com.tr bad..x example.com.tr');
    assertEqual(r.domains, ['example.com.tr', 'www.xn--rnek-4qa.com.tr', 'foo.com'], 'domains');
    assertEqual(r.publicSuffixes, ['com.tr'], 'public suffixes');
    assertEqual(r.invalid, ['bad..x'], 'invalid');
    assertEqual(S.parseDomainsInput('').domains, [], 'empty');
  });
  await run.step('routeDomains reads repeated and comma-separated params', () => {
    const sp = new URLSearchParams('domain=a.com,b.com&domain=c.com.tr');
    assertEqual(S.routeDomains(sp, {}), ['a.com', 'b.com', 'c.com.tr'], 'repeated');
    assertEqual(S.routeDomains(null, { domains: 'x.org y.org' }), ['x.org', 'y.org'], 'alias');
    assertEqual(S.routeDomains(new URLSearchParams(''), {}), [], 'none');
  });
  await run.step('sanitizeOptions keeps valid values and falls back otherwise', () => {
    const x = S.sanitizeOptions({ sources: ['crtsh', 'nope', 'crtsh'], bruteforce: 'huge', includeExpired: 'yes', originHints: false });
    // A save from before `knownSources` keeps its unticked sources off and gains only ip.thc.org.
    assertEqual([x.sources, x.includeExpired, x.bruteforce, x.originHints, x.permutations, x.permutationBudget],
      [['crtsh', 'thc'], false, 'huge', false, true, 1500], 'sanitized (huge is a real level now)');
    assertEqual(S.sanitizeOptions({ bruteforce: 'medium' }).bruteforce, 'smart', 'a saved medium level loads as smart');
    assertEqual(S.sanitizeOptions({ bruteforce: 'nope' }).bruteforce, 'smart', 'an unknown level falls back to smart');
    const d = S.sanitizeOptions(null);
    assert(d.sources.length === DEFAULT_ENABLED && d.bruteforce === 'smart' && d.originHints === true && d.permutations === true, 'defaults');
  });
  const host = (kind, extra = {}) => ({
    name: `${kind}.example.com`,
    classification: { kind, dangling: false, hidesOrigin: kind === 'cloudflare' || kind === 'cdn', ...(extra.classification || {}) },
    resolution: { ipv4: extra.ips || [], ipv6: [], cnames: [], status: 'NOERROR' },
    cert: extra.cert || null,
    servers: extra.servers || [],
    wildcardSuspect: !!extra.wildcard
  });
  await run.step('kindMatches / hostFilter / countHosts', () => {
    const hosts = [
      host('cloudflare', { ips: ['104.16.1.1'], cert: { covered: true } }),
      host('cdn', { ips: ['151.101.1.1'] }),
      host('direct', { ips: ['203.0.113.5'], servers: [{ serverId: 'web01' }], cert: { covered: true } }),
      host('private', { ips: ['10.0.0.5'] }),
      host('nxdomain'),
      host('unresolved', { classification: { dangling: true } }),
      host('direct', { ips: ['203.0.113.9'], wildcard: true })
    ];
    const pick = (f) => hosts.filter(S.hostFilter(f) || (() => true)).map((x) => x.classification.kind);
    assertEqual(pick({ kind: 'hidden' }), ['cloudflare', 'cdn'], 'hidden');
    assertEqual(pick({ kind: 'unresolved' }), ['nxdomain', 'unresolved'], 'unresolved');
    assertEqual(pick({ kind: 'dangling' }), ['unresolved'], 'dangling');
    assertEqual(pick({ covered: true }), ['cloudflare', 'direct'], 'covered');
    assertEqual(pick({ matched: true }), ['direct'], 'matched');
    assertEqual(pick({ resolving: true, hideWildcard: true }).length, 4, 'resolving & no wildcard');
    assertEqual(S.hostFilter({}), null, 'no filter → null');
    const c = S.countHosts(hosts);
    assertEqual([c.total, c.resolved, c.cloudflare, c.cdn, c.direct, c.private, c.nxdomain, c.unresolved, c.dangling, c.covered, c.hidden, c.onServers],
      [7, 5, 1, 1, 2, 1, 1, 1, 1, 2, 2, 1], 'counts');
  });
  await run.step('sourceChipState aggregates per-domain results', () => {
    const r = (source, ok, names, extra = {}) => ({ source, ok, names, partial: false, errorKind: ok ? null : 'rate-limit', error: ok ? null : 'HTTP 429', ...extra });
    assertEqual(S.sourceChipState([], 'crtsh', 2).state, 'pending', 'nothing yet');
    assertEqual(S.sourceChipState([r('crtsh', true, ['a.x'])], 'crtsh', 2).state, 'pending', 'one of two');
    const ok = S.sourceChipState([r('crtsh', true, ['a.x', 'b.x']), r('crtsh', true, ['b.x', 'c.y'])], 'crtsh', 2);
    assertEqual([ok.state, ok.names], ['ok', 3], 'ok + unique names');
    assertEqual(S.sourceChipState([r('otx', false, [])], 'otx', 1).state, 'error', 'error');
    assertEqual(S.sourceChipState([r('otx', false, []), r('otx', true, ['a'])], 'otx', 2).state, 'partial', 'mixed');
    assertEqual(S.sourceChipState([r('certspotter', true, ['a'], { partial: true })], 'certspotter', 1).state, 'partial', 'partial');
  });
  await run.step('ctStatus: expired / expiring (≤ 30 days) / valid', () => {
    const now = Date.UTC(2026, 8, 23);
    const at = (days) => ({ notAfter: new Date(now + days * 86400000) });
    assertEqual(S.ctStatus(at(-1), now).state, 'expired', 'expired');
    assertEqual(S.ctStatus(at(10), now), { state: 'expiring', days: 10 }, 'expiring');
    assertEqual(S.ctStatus(at(31), now).state, 'valid', 'valid');
    assertEqual(S.ctStatus({ notAfter: null }, now).state, 'unknown', 'unknown');
  });
}

/** Find a name of the domain that resolves to a public, non-CDN IP (used to seed the inventory). */
async function findDirectIp(page, domain) {
  return page.evaluate(async (d) => {
    const app = await import('./assets/js/app.js');
    const net = await import('./assets/js/lib/netinfo.js');
    const dns = await app.getDns();
    for (const label of ['api', 'mail', 'ftp', 'cms', 's', 'panel', 'webmail', 'smtp', 'direct', '']) {
      const name = label ? `${label}.${d}` : d;
      const r = await dns.resolveHost(name);
      const c = net.classifyResolution(r);
      if (c.kind === 'direct' && r.ipv4.length) return { name, ip: r.ipv4[0] };
    }
    return null;
  }, domain);
}

/** Open the collapsed Options step (a <details>): its controls are not rendered while closed. */
export async function openScanOptions(page) {
  await page.evaluate(() => {
    const box = document.querySelector('.scan-options-box');
    if (box && !box.open) box.open = true;
  });
}

async function setOptions(page, { sources, bruteforce }) {
  await openScanOptions(page);
  await page.evaluate((srcs) => {
    for (const input of document.querySelectorAll('input[name="scan-sources"]')) {
      if (input.checked !== srcs.includes(input.value)) input.click();
    }
  }, sources);
  await page.click(`input[name="scan-bruteforce"][value="${bruteforce}"]`);
  // A missed click would start a much longer scan than asked for: fail here, not a minute later.
  const checked = await page.evaluate(() => document.querySelector('input[name="scan-bruteforce"]:checked')?.value);
  assertEqual(checked, bruteforce, 'wordlist level after the click');
}

/* ------------------------------------------------------------------------ */
/* Zone File hand-off (shared with subdomains.e2e.mjs): an emulated zone     */
/* ------------------------------------------------------------------------ */

/** The apex the Zone File hand-off steps scan (answered in the page, never on the network). */
export const ZONE_HANDOFF_APEX = 'example.net';
/**
 * Live DNS of the emulated apex: www / shop are proxied (Cloudflare edge addresses), the apex, api
 * and mail are DNS-only in 203.0.113.0/24. Documentation ranges only; no last octet .11/.27/.28/.41.
 */
export const ZONE_HANDOFF_DNS = {
  'example.net': { A: ['203.0.113.10'] },
  'www.example.net': { A: ['104.16.5.5'] },
  'shop.example.net': { A: ['172.67.1.5'] },
  'api.example.net': { A: ['203.0.113.14'] },
  'mail.example.net': { A: ['203.0.113.12'] }
};
/**
 * What the Zone File view publishes as `state.session.zone` (the zoneScanInput shape): www's exact
 * origin 192.0.2.10, shop behind a host-name origin, and a proxied wildcard `*.apps`.
 */
export const ZONE_HANDOFF_INPUT = {
  v: 1,
  origin: 'example.net',
  names: ['example.net', 'www.example.net', 'shop.example.net', 'api.example.net', 'mail.example.net'],
  wildcardBases: ['apps.example.net'],
  delegations: [],
  proxied: [
    { name: 'www.example.net', ips: ['192.0.2.10'], host: null },
    { name: 'shop.example.net', ips: [], host: 'origin-lb.example.org' },
    { name: '*.apps.example.net', ips: ['192.0.2.10'], host: null }
  ],
  skipped: [],
  label: 'E2E zone · example.net',
  counts: { names: 6, origins: 3, skipped: 0 }
};

/**
 * A page script (installed before the app loads) that answers every DoH query under `apex` from
 * `zone` and BLOCKS any other request that leaves the page origin (recorded in
 * window.__zoneBlocked), so a hand-off step proves that nothing but DNS for the zone's own names
 * is sent. Queried names are recorded in window.__zoneDnsNames. A node's `RCODE: { MX: 'SERVFAIL' }`
 * answers that type with that rcode (a failed lookup).
 * @param {string} apex
 * @param {object} zone
 * @returns {string}
 */
export const zoneHandoffScript = (apex, zone) => `(() => {
  const APEX = ${JSON.stringify(apex)};
  const ZONE = ${JSON.stringify(zone)};
  const SOA = { mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
  const answer = (name, type) => {
    const node = ZONE[name];
    if (!node) {
      const exists = Object.keys(ZONE).some((k) => k.endsWith('.' + name));
      return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers: [], authorities: [{ name: APEX, type: 'SOA', ttl: 300, data: SOA }] };
    }
    if (node.RCODE && node.RCODE[type]) return { rcode: node.RCODE[type], answers: [], authorities: [] };
    const answers = (node[type] || []).map((data) => ({ name, type, ttl: 300, data }));
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: APEX, type: 'SOA', ttl: 300, data: SOA }] };
  };
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.__zoneDnsQueries = 0;
  window.__zoneDnsNames = [];
  window.__zoneBlocked = [];
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (new URL(url, location.href).origin === location.origin) return realFetch(input, init);
      window.__zoneBlocked.push(url);
      throw new TypeError('blocked by the E2E (Zone File hand-off)');
    }
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    if (name !== APEX && !name.endsWith('.' + APEX)) {
      window.__zoneBlocked.push('dns:' + name);
      throw new TypeError('blocked by the E2E (DNS outside the zone)');
    }
    window.__zoneDnsQueries += 1;
    if (!window.__zoneDnsNames.includes(name)) window.__zoneDnsNames.push(name);
    const out = answer(name, q.type);
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/**
 * The offline certificate scan: tests/fixtures/ec_wildcard.pem (*.wild.example.net,
 * wild.example.net) against an emulated example.net. web01 serves wild / www, shop is proxied
 * (a Cloudflare address) and vpn is private (a pair the Verify tab hands to the CLI).
 * Documentation ranges only; no last octet .11/.27/.28/.41.
 */
const OFFLINE_APEX = 'example.net';
const OFFLINE_DNS = {
  'example.net': { A: ['203.0.113.10'] },
  'www.example.net': { A: ['203.0.113.10'] },
  'mail.example.net': { A: ['203.0.113.12'] },
  'wild.example.net': { A: ['203.0.113.20'] },
  'www.wild.example.net': { A: ['203.0.113.20'] },
  'mail.wild.example.net': { A: ['203.0.113.22'] },
  'api.wild.example.net': { A: ['203.0.113.21'] },
  'shop.wild.example.net': { A: ['104.16.5.5'] },
  'vpn.wild.example.net': { A: ['10.0.0.5'] }
};
const OFFLINE_INVENTORY = 'web01 203.0.113.20\ndb01 10.0.0.5';
/** Slows every DoH answer by `window.__dnsDelay` ms (0 = off), so a run can be cancelled mid-wordlist. */
const dnsDelayScript = `(() => {
  const inner = window.fetch;
  window.__dnsDelay = 0;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (window.__dnsDelay && /[?&]dns=/.test(url)) {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, window.__dnsDelay);
        const signal = init && init.signal;
        if (signal) signal.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
      });
    }
    return inner(input, init);
  };
})();`;

const runStatus = (page) => page.evaluate(() => {
  const ui = document.querySelector('.scan-run-ui');
  return ui ? { id: ui.dataset.run, status: ui.querySelector('.scan-run').dataset.status } : null;
});

async function main() {
  const opts = cliOptions();
  const DOMAIN = opts.value('--domain', 'npmjs.com');
  const SOURCES = opts.value('--sources', DEFAULT_SOURCES.join(',')).split(',').map((s) => s.trim()).filter(Boolean);
  const BRUTE = opts.value('--bruteforce', 'small');
  const run = createRunner();

  await nodeChecks(run);

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; live domain ${DOMAIN}, sources ${SOURCES.join(', ')}, brute force ${BRUTE}\n`);
  let direct = null;
  try {
    const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/scan with the four setup steps and an empty run bar', async () => {
      await page.goto(`${server.url}#/scan`);
      await waitReady(page);
      await page.evaluate(() => {
        localStorage.removeItem('ssds.scan.options');
        localStorage.removeItem('ssds.inventory');
      });
      await page.reload();
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      const steps = await page.evaluate(() => [...document.querySelectorAll('.scan-step')].map((s) => s.dataset.step));
      assertEqual(steps, ['cert', 'domains', 'inventory', 'options'], 'steps');
      assert(await page.evaluate(() => !document.querySelector('.scan-run-ui')), 'no results yet');
      // One requirement line instead of "optional" on every step; Options is one collapsed line.
      const form = await page.evaluate(() => ({
        req: document.querySelector('[data-role="scan-requirement"]').textContent,
        reqState: document.querySelector('[data-role="scan-requirement"]').dataset.state,
        heads: [...document.querySelectorAll('.scan-step-head')].map((x) => x.textContent).join(' | '),
        done: [...document.querySelectorAll('.scan-step-num[data-done="true"]')].length,
        optionsOpen: document.querySelector('.scan-options-box').open,
        optSummary: document.querySelector('[data-role="scan-opt-summary"]').textContent
      }));
      assertEqual([form.req, form.reqState, form.done], ['A certificate or at least one domain is required', 'unmet', 0], 'requirement line');
      assert(!/optional/i.test(form.heads), `no step is labelled optional: ${form.heads}`);
      assertEqual([form.optionsOpen, form.optSummary], [false, 'recommended defaults'], 'Options collapsed, defaults');
      await page.click('.scan-options-box > summary');
      assert(await page.evaluate(() => document.querySelector('.scan-options-box').open), 'Options open on a click');
      const bf = await page.waitFor(() => {
        const smart = document.querySelector('.scan-bf [data-level="smart"]')?.textContent || '';
        return /\d{1,3}(,\d{3})+|\d{4,}/.test(smart) ? {
          values: [...document.querySelectorAll('input[name="scan-bruteforce"]')].map((i) => i.value),
          checked: document.querySelector('input[name="scan-bruteforce"]:checked').value,
          smart,
          perm: document.querySelector('[data-role="scan-permutations"]').checked,
          summary: document.querySelector('.scan-runbar-summary').textContent
        } : false;
      }, { message: 'wordlist levels' });
      assertEqual([bf.values, bf.checked, bf.perm], [['off', 'small', 'smart', 'large', 'huge'], 'smart', true], 'wordlist levels + permutations');
      assert(/smart wordlist\s*·\s*permutations/.test(bf.summary), `run summary: ${bf.summary}`);
      // The parts left out (no zone, no variations) leave nothing behind — not even a "null".
      assert(!/null|undefined/.test(bf.summary), `run summary without "null": ${bf.summary}`);
      await page.click('[data-role="scan-permutations"]');
      const noPerm = await page.evaluate(() => document.querySelector('.scan-runbar-summary').textContent);
      assert(/smart wordlist\s*·\s*no certificate/.test(noPerm) && !/null|undefined|permutations/.test(noPerm), `run summary without variations: ${noPerm}`);
      // The Options line lists what differs from the defaults.
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="scan-opt-summary"]').textContent), 'no permutations', 'Options summary');
      await page.click('[data-role="scan-permutations"]');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="scan-permutations"]').checked), true, 'variations back on');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="scan-opt-summary"]').textContent), 'recommended defaults', 'Options summary back');
      assertEqual(await page.evaluate(() => document.querySelectorAll('input[name="scan-sources"]:checked').length), DEFAULT_ENABLED, 'all sources on by default');
      await assertNoHorizontalScroll(page, 'setup');
      await shot(page, opts, 'scan-desktop-light-en-setup');
    });

    await run.step('seeds the inventory with a real direct IP of the domain (matching test)', async () => {
      direct = await findDirectIp(page, DOMAIN);
      const text = [`# e2e inventory`, direct ? `web-origin ${direct.ip}` : null, 'web02 10.20.30.40', 'db01 10.20.30.50'].filter(Boolean).join('\n');
      await page.evaluate(async (tx) => (await import('./assets/js/state.js')).state.setInventory(tx), text);
      await page.waitFor(() => document.querySelector('.scan-inv-count')?.dataset.servers >= 2, { message: 'inventory step updated' });
      process.stdout.write(`        direct host: ${direct ? `${direct.name} → ${direct.ip}` : 'none found (server matching is not asserted)'}\n`);
    });

    await run.step('validation: nothing to scan, public suffix, invalid names', async () => {
      await page.type('[data-role="scan-domains"]', '');
      await page.click('[data-action="scan-run"]');
      await page.waitFor(() => /least one domain/.test(document.querySelector('.scan-step-domains .field-error')?.textContent || ''));
      await page.type('[data-role="scan-domains"]', 'com.tr');
      await page.click('[data-action="scan-run"]');
      await page.waitFor(() => /public suffix/.test(document.querySelector('.scan-step-domains .field-error')?.textContent || ''));
      await page.type('[data-role="scan-domains"]', 'example.com bad..name');
      await page.click('[data-action="scan-run"]');
      await page.waitFor(() => /bad\.\.name/.test(document.querySelector('.scan-step-domains .field-error')?.textContent || ''));
      assert(await page.evaluate(() => !document.querySelector('.scan-run-ui')), 'no run started');
    });

    await run.step('certificate upload (setFileInputFiles) auto-fills the registrable domain', async () => {
      await page.type('[data-role="scan-domains"]', '');
      await page.setFileInput('.scan-step-cert .filedrop-input', [path.join(FIXTURES, 'rsa_multi_san.pem')]);
      await page.waitForSelector('.scan-step-cert .cert-summary');
      const info = await page.evaluate(() => ({
        cn: document.querySelector('.cert-summary-cn').textContent,
        domains: document.querySelector('[data-role="scan-domains"]').value,
        badge: document.querySelector('.scan-step-cert .scan-step-status').textContent,
        done: [...document.querySelectorAll('.scan-step-num[data-done="true"]')].map((n) => n.closest('.scan-step').dataset.step),
        req: document.querySelector('[data-role="scan-requirement"]').dataset.state,
        summary: document.querySelector('.scan-runbar-summary').textContent
      }));
      assertEqual(info.cn, 'www.example-test.com.tr', 'CN');
      assertEqual(info.domains, 'example-test.com.tr', 'auto-filled domains');
      assert(/ready/.test(info.badge), 'step badge');
      // The certificate and its domains complete steps 1 and 2 (the inventory was seeded above).
      assertEqual([info.done, info.req], [['cert', 'domains', 'inventory'], 'met'], 'checked steps + requirement met');
      assert(/with certificate/.test(info.summary), `run summary: ${info.summary}`);
      await shot(page, opts, 'scan-desktop-light-en-cert');
    });

    await run.step('wordlist plan + shared vocabulary follow the certificate domain (.com.tr → Turkish pack)', async () => {
      const info = await page.waitFor(() => {
        const plan = document.querySelector('[data-role="scan-wl-plan"]')?.textContent || '';
        const vocab = document.querySelector('[data-role="scan-vocab"]');
        return /Turkish/.test(plan) && vocab && !vocab.hidden ? {
          plan,
          vocab: vocab.querySelector('.scan-vocab-text').textContent,
          link: vocab.querySelector('[data-action="scan-vocab-change"]').getAttribute('href')
        } : false;
      }, { message: 'plan + vocabulary lines' });
      // The fixture's *.cdn.example-test.com.tr SAN is a second wordlist base (the scanner runs the
      // level list under cdn.example-test.com.tr too), so the plan counts 2 bases, not 1 domain.
      assert(/^≈ [\d,]+(?:–[\d,]+)? DNS queries for 2 domains \(per domain: [\d,]+ smart, \+[\d,]+ Turkish\) · ≈ \d+ (s|min)$/.test(info.plan), `plan: ${info.plan}`);
      // Learned names are opt-in (Subdomains › Advanced): off unless this browser switched them on.
      assert(/^Languages \/ markets: Auto: Turkish \(\.com\.tr\) · (learned names off|no learned names yet|[\d,]+ learned names? first)$/.test(info.vocab), `vocabulary: ${info.vocab}`);
      assertEqual(info.link, '#/subdomains', 'the vocabulary is changed in Subdomains › Advanced');
      // The query estimate follows the variation budget and the origin hints at once.
      const queries = () => page.evaluate(() => {
        const d = document.querySelector('[data-role="scan-wl-plan"]').dataset;
        return { min: Number(d.queriesMin), max: Number(d.queriesMax) };
      });
      const setBudget = (v) => page.evaluate((x) => {
        const sel = document.querySelector('.scan-perm-budget select');
        sel.value = x;
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      }, v);
      const q1500 = await queries();
      await setBudget('5000');
      const q5000 = await queries();
      assert(q5000.max > q1500.max, `budget 5,000 raises the estimate at once: ${JSON.stringify([q1500, q5000])}`);
      await setBudget('1500');
      assertEqual(await queries(), q1500, 'back to 1,500');
      await page.click('[data-role="scan-origin-hints"]');
      const noHints = await queries();
      assert(noHints.max < q1500.max, `no origin hints lowers it at once: ${JSON.stringify([q1500, noHints])}`);
      await page.click('[data-role="scan-origin-hints"]');
      assertEqual(await queries(), q1500, 'origin hints back on');
      // Off: no plan to count, no vocabulary line.
      await page.click('input[name="scan-bruteforce"][value="off"]');
      assert(await page.evaluate(() => document.querySelector('[data-role="scan-vocab"]').hidden && /No names are guessed/.test(document.querySelector('[data-role="scan-wl-plan"]').textContent)), 'off hides the vocabulary');
      await page.click('input[name="scan-bruteforce"][value="smart"]');
    });

    await run.step('typing another domain offers the certificate domains again ("Use these")', async () => {
      await page.type('[data-role="scan-domains"]', DOMAIN);
      await page.waitForSelector('[data-action="use-cert-domains"]');
      await page.click('[data-action="use-cert-domains"]');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="scan-domains"]').value), 'example-test.com.tr', 'restored');
      await page.type('[data-role="scan-domains"]', DOMAIN);
    });

    await run.step('Cancel stops a running scan and keeps the partial hosts', async () => {
      await setOptions(page, { sources: [], bruteforce: 'smart' });
      await page.type('[data-role="scan-domains"]', 'example.com');
      // Start and cancel inside the page: a warm DoH cache can finish 1,300 lookups in ~2 s.
      const seen = await page.evaluate(async () => {
        const prev = document.querySelector('.scan-run-ui')?.dataset.run || '';
        document.querySelector('[data-action="scan-run"]').click();
        const t0 = performance.now();
        while (document.querySelector('.scan-run-ui')?.dataset.run === prev || !document.querySelector('.scan-run-ui')) {
          if (performance.now() - t0 > 5000) return { started: false };
          await new Promise((r) => setTimeout(r, 20));
        }
        await new Promise((r) => setTimeout(r, 250));
        const state = {
          started: true,
          status: document.querySelector('.scan-run').dataset.status,
          cancelVisible: !document.querySelector('[data-action="scan-cancel"]').hidden,
          busy: document.querySelector('#app-header').classList.contains('is-busy')
        };
        document.querySelector('[data-action="scan-cancel"]').click();
        return state;
      });
      assert(seen.started && seen.status === 'running', `run started: ${JSON.stringify(seen)}`);
      assert(seen.cancelVisible && seen.busy, `cancel button and header busy bar while running: ${JSON.stringify(seen)}`);
      await page.waitFor(() => document.querySelector('.scan-run')?.dataset.status === 'cancelled', { timeout: 15000 });
      const info = await page.evaluate(() => ({
        notice: document.querySelector('.scan-run-notice')?.textContent || '',
        run: !document.querySelector('[data-action="scan-run"]').hidden,
        busy: document.querySelector('#app-header').classList.contains('is-busy'),
        ct: document.querySelector('.scan-tab-ct')?.textContent || ''
      }));
      assert(/Cancelled/.test(info.notice), `cancel notice: ${info.notice}`);
      // Streamed partials never resolve once cancelled: no row may keep claiming "resolving…" (the
      // table redraws on its next frame).
      await page.waitFor(() => ![...document.querySelectorAll('.scan-mini-badge')].some((b) => /resolving/i.test(b.textContent)),
        { timeout: 5000, message: 'no "resolving…" badge left after Cancel' });
      assert(info.run && !info.busy, 'run button back, not busy');
      // The export bar covers what the table keeps (the offline group checks the files).
      const bar = await page.evaluate(() => ({
        rows: document.querySelectorAll('.scan-hosts tbody tr.dt-row').length,
        hosts: document.querySelector('.scan-exports [data-export="hosts-csv"]').disabled,
        names: document.querySelector('.scan-exports [data-export="names"]').disabled
      }));
      if (bar.rows) assert(!bar.hosts && !bar.names, `export bar enabled for the ${bar.rows} kept rows: ${JSON.stringify(bar)}`);
    });

    await run.step('a scan keeps running on another page; the toast leads back to the results', async () => {
      await setOptions(page, { sources: [], bruteforce: 'small' });
      await page.type('[data-role="scan-domains"]', 'example.com');
      // Start, then leave as soon as the run exists, so it is still running when the view unmounts.
      const left = await page.evaluate(async () => {
        const prev = document.querySelector('.scan-run-ui')?.dataset.run || '';
        document.querySelector('[data-action="scan-run"]').click();
        const t0 = performance.now();
        while (document.querySelector('.scan-run-ui')?.dataset.run === prev) {
          if (performance.now() - t0 > 5000) return false;
          await new Promise((r) => setTimeout(r, 10));
        }
        const running = document.querySelector('.scan-run').dataset.status === 'running';
        window.location.hash = '#/about';
        return running;
      });
      assert(left, 'left while the scan was running');
      await page.waitFor(() => document.documentElement.dataset.view === 'about', { message: 'left the scan view' });
      await page.waitFor(() => [...document.querySelectorAll('.toast')].some((t) => /Scan finished/.test(t.textContent)),
        { timeout: 60000, message: 'finish toast while away' });
      await page.evaluate(() => [...document.querySelectorAll('.toast')].find((t) => /Scan finished/.test(t.textContent)).querySelector('.btn-ghost').click());
      await page.waitFor(() => document.documentElement.dataset.view === 'scan' && document.querySelector('.scan-run')?.dataset.status === 'done');
      const hosts = await page.evaluate(() => document.querySelectorAll('.scan-hosts tbody tr.dt-row').length);
      assert(hosts >= 1, `hosts after background run: ${hosts}`);
      await page.evaluate(() => document.querySelectorAll('.toast').forEach((t) => t.remove()));
    });

    await run.step(`LIVE: full scan of ${DOMAIN} with the certificate and ${SOURCES.length} sources`, async () => {
      await setOptions(page, { sources: SOURCES, bruteforce: BRUTE });
      await page.type('[data-role="scan-domains"]', DOMAIN);
      const before = await runStatus(page);
      const t0 = Date.now();
      await page.click('[data-action="scan-run"]');
      await page.waitFor((prev) => document.querySelector('.scan-run-ui')?.dataset.run !== prev, { args: [before.id] });
      // Progress UI while running.
      await page.waitFor(() => document.querySelectorAll('.scan-chip').length > 0, { timeout: 20000, message: 'source chips' });
      assertEqual((await page.evaluate(() => [...document.querySelectorAll('.scan-chip')].map((c) => c.dataset.source))).sort(), [...SOURCES].sort(), 'chips');
      await page.evaluate(() => window.scrollTo(0, document.querySelector('.scan-run').getBoundingClientRect().top + window.scrollY - 70));
      await shot(page, opts, 'scan-desktop-light-en-running');
      await page.waitFor(() => ['done', 'error', 'cancelled'].includes(document.querySelector('.scan-run')?.dataset.status),
        { timeout: 300000, interval: 500, message: 'scan finished' });
      const status = await page.evaluate(() => document.querySelector('.scan-run').dataset.status);
      assertEqual(status, 'done', 'final status');
      process.stdout.write(`        finished in ${((Date.now() - t0) / 1000).toFixed(1)} s\n`);
      assertEqual(await page.evaluate(() => new URLSearchParams(location.hash.split('?')[1]).get('domain')), DOMAIN, 'shareable URL');
    });

    await run.step('progress panel: all stages finished, every source chip settled', async () => {
      const info = await page.evaluate(() => ({
        stages: Object.fromEntries([...document.querySelectorAll('.scan-stage')].map((s) => [s.dataset.stage, s.dataset.state])),
        chips: [...document.querySelectorAll('.scan-chip')].map((c) => ({ id: c.dataset.source, state: c.dataset.state, text: c.textContent })),
        meta: document.querySelector('.scan-run-meta').textContent
      }));
      assert(Object.values(info.stages).every((s) => s === 'done' || s === 'skipped'), `stages ${JSON.stringify(info.stages)}`);
      assert(info.chips.every((c) => c.state !== 'pending'), `chips ${JSON.stringify(info.chips)}`);
      assert(/DNS queries/.test(info.meta), `meta: ${info.meta}`);
      process.stdout.write(`        sources: ${info.chips.map((c) => `${c.id}=${c.state}`).join(', ')}\n`);
    });

    await run.step('results: hosts streamed, Cloudflare detected, stats and summary', async () => {
      const info = await page.evaluate(() => ({
        rows: document.querySelectorAll('.scan-hosts tbody tr.dt-row').length,
        total: Number(document.querySelector('[data-stat="hosts"] .stat-value').textContent.replace(/\D/g, '')),
        cloudflare: Number(document.querySelector('[data-stat="cloudflare"] .stat-value').textContent.replace(/\D/g, '')),
        cfBadges: document.querySelectorAll('.scan-hosts [data-kind="cloudflare"]').length,
        covered: document.querySelector('[data-stat="covered"] .stat-value')?.textContent,
        summary: [...document.querySelectorAll('.scan-summary [data-summary]')].map((a) => a.dataset.summary),
        hostBadge: document.querySelector('.scan-tabs [data-tab="hosts"] .tab-badge').textContent
      }));
      assert(info.total >= 3 && info.rows === Math.min(info.total, 200), `rows ${info.rows} / total ${info.total}`);
      assert(info.cloudflare >= 1 && info.cfBadges >= 1, `cloudflare stat ${info.cloudflare}, badges ${info.cfBadges}`);
      assert(info.summary.includes('hidden'), `summary: ${info.summary}`);
      assert(info.summary.includes('needs') || info.summary.includes('needs-none'), `certificate summary present: ${info.summary}`);
      const names = await page.evaluate(() => [...document.querySelectorAll('.scan-hosts .scan-host-name')].map((n) => n.textContent));
      assert(names.includes(DOMAIN) || names.some((n) => n.endsWith(`.${DOMAIN}`)), 'hosts belong to the domain');
      process.stdout.write(`        ${info.total} hosts, ${info.cloudflare} behind Cloudflare\n`);
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, opts, 'scan-desktop-light-en-results');
    });

    await run.step('inventory match: the seeded server is found through DNS', async () => {
      if (!direct) return;
      const info = await page.evaluate((ip) => ({
        refs: [...document.querySelectorAll('.scan-hosts .scan-server-ref')].map((r) => `${r.textContent.trim()}@${r.title}`),
        direct: document.querySelector('[data-stat="direct"] .stat-hint').textContent
      }), direct.ip);
      assert(info.refs.some((r) => r.startsWith('web-origin') && r.endsWith(direct.ip)), `server refs: ${info.refs}`);
      assert(/on your servers/.test(info.direct), `direct hint: ${info.direct}`);
    });

    await run.step('Hosts tab: kind filter, stat-card filter, checkboxes and search', async () => {
      await page.evaluate(() => {
        const sel = document.querySelector('[data-role="scan-filter-kind"]');
        sel.value = 'cloudflare';
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => [...document.querySelectorAll('.scan-hosts tbody tr.dt-row')].every((tr) => tr.querySelector('[data-kind]').dataset.kind === 'cloudflare'));
      assert(await page.evaluate(() => document.querySelector('[data-stat="cloudflare"]').getAttribute('aria-pressed')) === 'true', 'stat pressed');
      await page.click('[data-stat="unresolved"]');
      await page.waitFor(() => [...document.querySelectorAll('.scan-hosts tbody tr.dt-row')].every((tr) => ['nxdomain', 'unresolved', 'dangling'].includes(tr.querySelector('[data-kind]').dataset.kind)));
      await page.click('[data-stat="hosts"]');
      await page.click('.scan-hosts input[data-filter="covered"]');
      const covered = await page.evaluate(() => [...document.querySelectorAll('.scan-hosts tbody tr.dt-row')].map((tr) => tr.querySelector('.scan-host-name').textContent));
      assert(covered.length >= 1 && covered.every((n) => n.endsWith('example-test.com.tr')), `covered: ${covered}`);
      await page.click('.scan-hosts input[data-filter="covered"]');
      await page.type('.scan-hosts .dt-search-input', 'example-test');
      await page.waitFor(() => [...document.querySelectorAll('.scan-hosts .scan-host-name')].map((n) => n.textContent).includes('www.example-test.com.tr'),
        { message: 'certificate names are always resolved' });
      await page.type('.scan-hosts .dt-search-input', `www.${DOMAIN}`);
      await page.waitFor((n) => {
        const rows = [...document.querySelectorAll('.scan-hosts tbody tr.dt-row')];
        return rows.length >= 1 && rows.every((tr) => tr.textContent.includes(n));
      }, { args: [`www.${DOMAIN}`] });
      await page.type('.scan-hosts .dt-search-input', '');
    });

    await run.step('row details: DNS answer, reason and links to Global DNS / Lookup', async () => {
      await page.click('.scan-hosts tbody tr.dt-row .dt-expand-btn');
      await page.waitForSelector('.scan-hosts .dt-details .scan-host-details');
      const links = await page.evaluate(() => [...document.querySelectorAll('.scan-hosts .dt-details a.btn')].map((a) => a.getAttribute('href')));
      assert(links.some((l) => l.startsWith('#/global?name=')) && links.some((l) => l.startsWith('#/lookup?name=')), `links ${links}`);
      await page.click('.scan-hosts tbody tr.dt-row .dt-expand-btn');
    });

    await run.step('Servers tab lists the matched server and the IPs not in the inventory', async () => {
      await page.click('.scan-tabs [data-tab="servers"]');
      await page.waitForSelector('.scan-tab-servers .dt');
      const info = await page.evaluate(() => ({
        servers: [...document.querySelectorAll('.scan-servers-table tbody tr.dt-row')].map((tr) => ({
          name: tr.querySelector('.scan-srv-name').textContent, status: tr.querySelector('[data-status]').dataset.status
        })),
        unmatched: document.querySelectorAll('.scan-unmatched-table tbody tr.dt-row').length
      }));
      if (direct) {
        const s = info.servers.find((x) => x.name === 'web-origin');
        assert(s, `web-origin listed: ${JSON.stringify(info.servers)}`);
        assert(['none', 'needs', 'maybe'].includes(s.status), `status ${s.status}`);
      }
      await shot(page, opts, 'scan-desktop-light-en-servers');
    });

    await run.step('Behind CDN tab: explanation, proxied hosts, origin hints and the CLI command', async () => {
      await page.click('.scan-tabs [data-tab="cdn"]');
      await page.waitForSelector('.scan-tab-cdn .scan-cli');
      const info = await page.evaluate(() => ({
        why: document.querySelector('.scan-tab-cdn .alert-title')?.textContent,
        proxied: document.querySelectorAll('.scan-cdn-hosts tbody tr.dt-row').length,
        hints: [...document.querySelectorAll('.scan-hints-table tbody tr.dt-row')].map((tr) => tr.querySelector('td').textContent),
        command: document.querySelector('.scan-cli code').textContent,
        cliHref: document.querySelector('.scan-cli a[download]').getAttribute('href'),
        names: document.querySelector('[data-action="cli-names"]').dataset.count,
        targets: document.querySelector('[data-action="cli-targets"]').dataset.count
      }));
      assertEqual(info.why, 'Why the real servers are hidden', 'explanation');
      assert(info.proxied >= 1, `proxied rows ${info.proxied}`);
      const nets = await page.evaluate(() => ({
        table: !!document.querySelector('.scan-networks-table'),
        rows: [...document.querySelectorAll('.scan-networks-table tbody tr.dt-row')].map((tr) => tr.querySelector('td').textContent),
        quick: document.querySelector('.scan-cli-quick code')?.textContent || null
      }));
      process.stdout.write(`        origin networks: ${nets.rows.join(', ') || 'none'}; quick command: ${nets.quick || '-'}\n`);
      assert(nets.table, 'origin networks table');
      // An IPv4 /24 is swept whole when it clusters several origins, otherwise as its exact
      // addresses; an IPv6 /48 (which the CLI refuses) always goes in as its known addresses.
      if (nets.rows.length) {
        const tokens = (nets.quick || '').split(/\s+/);
        const sweeps = (raw) => {
          const cidr = raw.trim();
          return tokens.includes(cidr) || tokens.some((x) => x.startsWith(cidr.replace(/0\/24$/, '')));
        };
        assert(nets.quick && nets.quick.startsWith('python3 ssl_origin_scan.py -t ') && nets.rows.filter((c) => !c.includes(':')).every(sweeps)
          && !/:\S*\/48\b/.test(nets.quick), `quick sweep command: ${nets.quick}`);
        // PowerShell variant: the same validated tokens, launched with `python`.
        await page.click('.scan-cli-shell .seg-btn[data-value="powershell"]');
        const ps = await page.waitFor(() => {
          const c = document.querySelector('.scan-cli-quick code')?.textContent || '';
          return c.startsWith('python ssl_origin_scan.py') ? c : false;
        }, { message: 'PowerShell sweep command' });
        assertEqual(ps.replace(/^python /, 'python3 '), nets.quick, 'same tokens in both shells');
        await page.click('.scan-cli-shell .seg-btn[data-value="posix"]');
      }
      assertEqual(info.command, 'python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem', 'CLI command');
      assertEqual(info.cliHref, 'cli/ssl_origin_scan.py', 'CLI link');
      if (direct) assert(info.hints.includes(direct.ip), `origin hints include the non-proxied sibling ${direct.ip}: ${info.hints}`);
      assert(Number(info.targets) >= 3, `targets ${info.targets}`);
      const res = await fetch(`${server.url}cli/ssl_origin_scan.py`);
      assert(res.ok && (await res.text()).includes('ssl_origin_scan'), 'the CLI is served next to the page');
      await shot(page, opts, 'scan-desktop-light-en-cdn');
    });

    await run.step('Sources tab: one row per source with status and timing', async () => {
      await page.click('.scan-tabs [data-tab="sources"]');
      const rows = await page.evaluate(() => [...document.querySelectorAll('.scan-sources-table tbody tr.dt-row')].map((tr) => ({
        status: tr.querySelector('[data-status]')?.dataset.status, text: tr.textContent
      })));
      assertEqual(rows.length, SOURCES.length, 'source rows');
      assert(rows.every((r) => ['ok', 'partial', 'failed'].includes(r.status)), `status badges: ${JSON.stringify(rows.map((r) => r.status))}`);
      const health = await page.evaluate(() => [...document.querySelectorAll('.scan-src-health-line')].map((l) => `${l.dataset.source}/${l.dataset.health}: ${l.textContent}`));
      for (const line of health) process.stdout.write(`        note: ${line}\n`);
      for (const r of rows.filter((x) => x.status === 'failed')) {
        assert(!/Rate limited: this service/.test(r.text) || /quota/i.test(r.text), `a quota failure explains when it resets: ${r.text.slice(0, 160)}`);
      }
    });

    await run.step('CT certificates tab: certificates with validity status (when a CT source answered)', async () => {
      await page.click('.scan-tabs [data-tab="ct"]');
      await page.waitForSelector('.scan-tab-ct .dt');
      const info = await page.evaluate(() => ({
        rows: document.querySelectorAll('.scan-ct-table tbody tr.dt-row').length,
        match: document.querySelector('.scan-tab-ct [data-ct-match]')?.dataset.ctMatch ?? null,
        ctOk: [...document.querySelectorAll('.scan-chip')].some((c) => ['crtsh', 'certspotter'].includes(c.dataset.source) && ['ok', 'partial'].includes(c.dataset.state) && c.dataset.health !== 'empty')
      }));
      if (info.ctOk) assert(info.rows >= 1, `CT rows ${info.rows}`);
      if (info.rows) assertEqual(info.match, 'false', 'the private test certificate is not in CT');
      await shot(page, opts, 'scan-desktop-light-en-ct');
    });

    await run.step('exports: hosts CSV, servers CSV, full JSON, names.txt, targets.txt, new-cert.pem', async () => {
      await takeDownloads(page);
      for (const kind of ['hosts-csv', 'servers-csv', 'json', 'names', 'targets']) await page.click(`[data-export="${kind}"]`);
      await page.click('.scan-tabs [data-tab="cdn"]');
      await page.click('[data-action="cli-cert"]');
      const files = await takeDownloads(page);
      const by = (re) => files.find((f) => re.test(f.name));
      const hosts = by(/^hosts-.*\.csv$/);
      assert(hosts, `hosts csv in ${files.map((f) => f.name)}`);
      assertEqual(csvHeader(hosts.text).slice(0, 4), ['Hostname', 'DNS status', 'Classification', 'Provider'], 'hosts header');
      assert(hosts.bom && hosts.text.includes(DOMAIN), 'UTF-8 BOM (Excel) + content');
      const servers = by(/^servers-.*\.csv$/);
      assertEqual(csvHeader(servers.text)[0], 'Server', 'servers header');
      const json = JSON.parse(by(/^scan-.*\.json$/).text);
      assert(json.scan && Array.isArray(json.scan.hosts) && json.scan.hosts.length >= 3 && json.certificate.serialHex, 'full JSON');
      assert(!JSON.stringify(json).includes('"der"'), 'no DER bytes in the JSON');
      const names = by(/^names\.txt$/).text.trim().split('\n');
      assert(names.length >= 1, 'names.txt');
      const targets = by(/^targets\.txt$/).text;
      assert(targets.includes('web02 10.20.30.40'), `targets.txt has the inventory: ${targets}`);
      if (direct) assert(targets.includes(direct.ip), 'targets.txt has the direct IP');
      const pem = by(/^new-cert\.pem$/).text;
      assert(pem.startsWith('-----BEGIN CERTIFICATE-----') && !/PRIVATE KEY/.test(pem), 'certificate only');
    });

    await run.step('results survive navigation and a language switch (Turkish), options persist', async () => {
      const id = (await runStatus(page)).id;
      await gotoRoute(page, 'inventory');
      await gotoRoute(page, 'scan');
      assertEqual((await runStatus(page)).id, id, 'same run after navigation');
      await setLangUi(page, 'tr');
      await page.waitForSelector('.scan-run-ui');
      assertEqual((await runStatus(page)).id, id, 'same run after re-mount');
      assertEqual(await page.evaluate(() => document.querySelector('.scan-results-title').textContent), 'Sonuçlar', 'Turkish');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="scan-domains"]').value), DOMAIN, 'domains kept');
      const stored = await page.evaluate(() => JSON.parse(localStorage.getItem('ssds.scan.options')));
      assertEqual([...stored.sources].sort(), [...SOURCES].sort(), 'options remembered');
      await setLangUi(page, 'en');
    });

    await run.step('route params: #/scan?domain=… updates the domains without a re-mount', async () => {
      const id = (await runStatus(page)).id;
      await page.evaluate(() => { location.hash = '#/scan?domain=example.org,example.net'; });
      await page.waitFor(() => document.querySelector('[data-role="scan-domains"]').value === 'example.org\nexample.net');
      assertEqual((await runStatus(page)).id, id, 'results still shown');
      await page.evaluate((d) => { location.hash = `#/scan?domain=${d}`; }, DOMAIN);
      await page.waitFor((d) => document.querySelector('[data-role="scan-domains"]').value === d, { args: [DOMAIN] });
    });

    await run.step('dark theme renders the results without horizontal scroll', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await page.click('.scan-tabs [data-tab="hosts"]');
      await page.evaluate(() => window.scrollTo(0, 0));
      await assertNoHorizontalScroll(page, 'dark');
      await shot(page, opts, 'scan-desktop-dark-en-results');
      await page.click('.scan-tabs [data-tab="cdn"]');
      await shot(page, opts, 'scan-desktop-dark-en-cdn');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    });

    run.group('Phone 390×844 (Turkish)');
    await run.step('phone layout: setup + results fit 390 px in light and dark', async () => {
      await page.setViewport({ width: 390, height: 844, mobile: true });
      await setLangUi(page, 'tr');
      await page.click('.scan-tabs [data-tab="hosts"]');
      for (const scheme of ['light', 'dark']) {
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await page.evaluate(() => window.scrollTo(0, 0));
        await assertNoHorizontalScroll(page, `phone ${scheme}`);
        await shot(page, opts, `scan-mobile-${scheme}-tr-results`);
      }
      await page.click('.scan-tabs [data-tab="cdn"]');
      await assertNoHorizontalScroll(page, 'phone cdn');
      await shot(page, opts, 'scan-mobile-dark-tr-cdn');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await page.setViewport({ width: 1440, height: 900 });
    });

    run.group('Zone File hand-off (emulated DNS, nothing else leaves the page)');
    await run.step('"Find certificate targets": step 2 pre-filled with an exact-mode chip and no auto-start; Run → zone origins on Behind CDN, via: zone on Servers, exact command', async () => {
      const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
      // A new tab follows the host's colour scheme: pin light so the *-light-* screenshots are light.
      await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
      // The live suite's stored options / inventory are restored afterwards.
      const saved = await page.evaluate(() => ({ options: localStorage.getItem('ssds.scan.options'), inventory: localStorage.getItem('ssds.inventory') }));
      try {
        await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(ZONE_HANDOFF_APEX, ZONE_HANDOFF_DNS) });
        await tab.goto(`${server.url}#/about`);
        await waitReady(tab);
        await setLangUi(tab, 'en');
        // Stored options that WOULD ask sources and guess names: exact mode ignores them for one run.
        const stored = JSON.stringify({ sources: ['crtsh', 'anubis'], bruteforce: 'smart', permutations: true, originHints: true });
        await tab.evaluate(async (s) => {
          localStorage.setItem('ssds.scan.options', s);
          (await import('./assets/js/state.js')).state.setInventory('web01 192.0.2.10');
        }, stored);
        await tab.evaluate(async (zone) => {
          const { state } = await import('./assets/js/state.js');
          state.setSession('zone', zone);
          state.setSession('zoneScanIntent', { v: 1, target: 'scan', domain: zone.origin, mode: 'exact', autostart: false, at: Date.now() });
          location.hash = `#/scan?domain=${zone.origin}`;
        }, ZONE_HANDOFF_INPUT);
        await tab.waitFor(() => document.querySelector('.scan-step-domains [data-role="zone-chip"]'), { timeout: 15000, message: 'zone chip in step 2' });
        await sleep(600);
        const before = await tab.evaluate(() => ({
          domains: document.querySelector('[data-role="scan-domains"]').value,
          chip: document.querySelector('[data-role="zone-chip"] .sub-zone-title').textContent,
          pressed: document.querySelector('.sub-zone-mode .seg-btn[aria-pressed="true"]')?.dataset.value,
          started: !!document.querySelector('.scan-run-ui'),
          summary: document.querySelector('.scan-runbar-summary').textContent,
          plan: document.querySelector('[data-role="scan-wl-plan"]').textContent,
          queries: window.__zoneDnsQueries
        }));
        assertEqual([before.domains, before.pressed, before.started, before.queries], ['example.net', 'exact', false, 0], 'pre-filled, exact, nothing started or sent');
        assert(/6 names, 3 exact origins/.test(before.chip), `chip: ${before.chip}`);
        assert(/no passive sources/.test(before.summary) && /Zone file/.test(before.summary), `run summary: ${before.summary}`);
        // The run bar's estimate is the zone's names, not the stored wordlist the run will not use.
        assert(/^Exact mode: only the 6 names from your zone file/.test(before.plan), `plan line: ${before.plan}`);
        // DOM clicks: the results scroll smoothly into view, which can move a coordinate click.
        await tab.evaluate(() => document.querySelector('[data-action="scan-run"]').click());
        const done = await tab.waitFor(() => {
          const ui = document.querySelector('.scan-run-ui');
          const st = ui && ui.querySelector('.scan-run').dataset.status;
          return st && st !== 'running' ? st : false;
        }, { timeout: 60000, message: 'exact zone scan done' });
        assertEqual(done, 'done', 'status');
        assert(await tab.evaluate(() => document.querySelector('.scan-run .sub-zone-banner')?.dataset.zoneMode === 'exact'), 'exact banner');
        // The discovery summary says where the hosts came from: the zone file, not "0 by DNS · 0 by sources" alone.
        const discovery = await tab.evaluate(() => document.querySelector('[data-summary="discovery"]')?.textContent || '');
        assert(/from your zone file: [1-9]/.test(discovery), `discovery summary names the zone file: ${discovery}`);
        await tab.evaluate(() => document.querySelector('.scan-tabs [data-tab="cdn"]').click());
        const cdn = await tab.waitFor(() => {
          const quick = document.querySelector('.scan-cli-quick code')?.textContent || '';
          return quick ? {
            zoneRows: [...document.querySelectorAll('.scan-zone-origins tbody tr.dt-row')].map((r) => r.textContent),
            quick
          } : false;
        }, { timeout: 15000, message: 'Behind CDN command' });
        assertEqual(cdn.zoneRows.length, 1, `one proxied host with a zone origin: ${JSON.stringify(cdn.zoneRows)}`);
        assert(/www\.example\.net/.test(cdn.zoneRows[0]) && /192\.0\.2\.10/.test(cdn.zoneRows[0]), `zone row: ${cdn.zoneRows[0]}`);
        const tokens = cdn.quick.split(/\s+/);
        assert(tokens.includes('192.0.2.10') && !cdn.quick.includes('192.0.2.0/24'), `exact zone origin, never a /24: ${cdn.quick}`);
        assert(tokens.includes('origin-lb.example.org') && cdn.quick.includes("'*.apps.example.net'"), `host target + quoted wildcard name: ${cdn.quick}`);
        await shot(tab, opts, 'scan-zone-cdn-desktop-light-en');
        await tab.evaluate(() => document.querySelector('.scan-tabs [data-tab="servers"]').click());
        const via = await tab.waitFor(() => {
          const el = document.querySelector('.scan-srv-host.is-zone');
          return el ? el.textContent : false;
        }, { timeout: 10000, message: 'via zone on Servers' });
        assert(/www\.example\.net/.test(via) && /Zone file/.test(via), `web01 matched via the zone file: ${via}`);
        const after = await tab.evaluate(() => ({
          blocked: window.__zoneBlocked,
          names: window.__zoneDnsNames,
          options: localStorage.getItem('ssds.scan.options')
        }));
        assertEqual(after.blocked, [], 'no request left the page except DNS for the zone');
        assert(after.names.every((n) => ['example.net', 'www.example.net', 'shop.example.net', 'api.example.net', 'mail.example.net', 'apps.example.net'].includes(n)),
          `only the zone's names were resolved (no guesses): ${after.names.join(', ')}`);
        assertEqual(after.options, stored, 'the exact run never touched the stored options');
        // Phone: the chip fits in EN light and TR dark.
        await tab.evaluate(() => document.querySelector('.scan-tabs [data-tab="hosts"]').click());
        await tab.setViewport({ width: 390, height: 844, mobile: true });
        for (const [lang, scheme] of [['en', 'light'], ['tr', 'dark']]) {
          await setLangUi(tab, lang);
          await tab.emulateMedia({ 'prefers-color-scheme': scheme });
          await tab.waitFor(() => document.querySelector('[data-role="zone-chip"]'), { message: 'chip after re-mount' });
          await tab.evaluate(() => window.scrollTo(0, 0));
          await assertNoHorizontalScroll(tab, `zone chip ${lang} ${scheme}`);
          await shot(tab, opts, `scan-zone-mobile-${scheme}-${lang}`);
        }
        await setLangUi(tab, 'en');
        // Forget in the Zone File view (or "Delete all local data") removes the chip at once.
        await tab.evaluate(async () => (await import('./assets/js/state.js')).state.setSession('zone', undefined));
        await tab.waitFor(() => !document.querySelector('[data-role="zone-chip"]'), { message: 'chip gone after Forget' });
        await assertClean(tab, 'zone hand-off (SSL Targets)', origin);
      } finally {
        await tab.close();
        await page.evaluate((s) => {
          for (const [key, value] of [['ssds.scan.options', s.options], ['ssds.inventory', s.inventory]]) {
            if (value === null) localStorage.removeItem(key);
            else localStorage.setItem(key, value);
          }
        }, saved);
      }
    });

    run.group('Setup form at 375 px: sticky run bar (emulated DNS, nothing else leaves the page)');
    {
      const tab = await browser.newPage('about:blank', { width: 375, height: 667, mobile: true });
      await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
      const saved = await page.evaluate(() => ({ options: localStorage.getItem('ssds.scan.options'), inventory: localStorage.getItem('ssds.inventory') }))
        .catch(() => null);
      /** Where Start, the bar and a field sit on screen right now (no scrolling done here). */
      const layout = (field) => tab.evaluate((sel) => {
        const bar = document.querySelector('[data-role="scan-runbar"]');
        const btn = document.querySelector('[data-action="scan-run"]');
        const b = btn.getBoundingClientRect();
        const hit = document.elementFromPoint(b.left + b.width / 2, b.top + b.height / 2);
        const f = sel ? document.querySelector(sel).getBoundingClientRect() : null;
        return {
          scrollY: Math.round(window.scrollY),
          startVisible: !btn.hidden && b.top >= 0 && b.bottom <= window.innerHeight && !!hit && btn.contains(hit),
          stuck: bar.dataset.stuck,
          position: getComputedStyle(bar).position,
          barTop: Math.round(bar.getBoundingClientRect().top),
          barBottom: Math.round(bar.getBoundingClientRect().bottom),
          fieldTop: f ? Math.round(f.top) : null,
          fieldBottom: f ? Math.round(f.bottom) : null,
          vh: window.innerHeight
        };
      }, field || null);
      const frames = () => tab.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(r, 50)))));
      try {
        await run.step('375×667: one requirement line, Options collapsed, Start on screen before any input; an empty Start focuses the domains field above the bar', async () => {
          await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(OFFLINE_APEX, OFFLINE_DNS) });
          await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: dnsDelayScript });
          await tab.goto(`${server.url}#/about`);
          await waitReady(tab);
          await setLangUi(tab, 'en');
          const known = LIB_SOURCES.map((s) => s.id);
          await tab.evaluate((k) => {
            localStorage.setItem('ssds.scan.options', JSON.stringify({ sources: [], knownSources: k, bruteforce: 'small', permutations: false, originHints: true }));
            localStorage.removeItem('ssds.inventory');
          }, known);
          await tab.reload();
          await waitReady(tab);
          await gotoRoute(tab, 'scan');
          await tab.evaluate(() => window.scrollTo(0, 0));
          await frames();
          const top = await layout();
          assert(top.startVisible && top.position === 'sticky' && top.stuck === 'true', `Start floats on screen at the top of the page: ${JSON.stringify(top)}`);
          const form = await tab.evaluate(() => ({
            req: document.querySelector('[data-role="scan-requirement"]').dataset.state,
            open: document.querySelector('.scan-options-box').open,
            opt: document.querySelector('[data-role="scan-opt-summary"]').textContent,
            rootVar: document.documentElement.style.getPropertyValue('--scan-runbar-h'),
            // Every step title is an <h2> (heading navigation), the Options one inside its summary.
            headings: [...document.querySelectorAll('.scan-setup h2')].map((x) => (x.id || x.querySelector('[id]')?.id || '').replace('scan-step-', '')),
            optHeading: !!document.querySelector('.scan-options-box > summary > h2.disclosure-heading #scan-step-options')
          }));
          assertEqual([form.req, form.open], ['unmet', false], 'requirement unmet, Options collapsed');
          assertEqual([form.headings, form.optHeading], [['cert', 'domains', 'inventory', 'options'], true], 'one heading per step');
          // The stored options differ from the defaults: the collapsed line says how.
          assertEqual(form.opt, 'no passive sources · small wordlist · no permutations', 'Options summary');
          assert(/^\d+px$/.test(form.rootVar), `the bar's height is published for scroll-padding: ${form.rootVar}`);
          // Start with nothing entered: the error focuses the domains field, scrolled clear of the bar.
          await tab.evaluate(() => document.querySelector('[data-action="scan-run"]').focus({ preventScroll: true }));
          await tab.press('Enter');
          await tab.waitFor(() => document.activeElement?.dataset.role === 'scan-domains'
            && /least one domain/.test(document.querySelector('.scan-step-domains .field-error')?.textContent || ''), { message: 'error + focus on the domains field' });
          await frames();
          const err = await layout('[data-role="scan-domains"]');
          assert(err.fieldTop >= 0 && err.fieldBottom <= err.barTop, `the focused field is not under the bar: ${JSON.stringify(err)}`);
        });

        await run.step('375 px: a CA certificate without DNS names leaves step 1 open with a warning; the requirement line and Start say why', async () => {
          await tab.setFileInput('.scan-step-cert .filedrop-input', [path.join(FIXTURES, 'ca.pem')]);
          await tab.waitFor(() => document.querySelector('.scan-step-cert .cert-summary'), { message: 'CA certificate loaded' });
          await frames();
          const read = () => tab.evaluate(() => {
            const num = document.querySelector('.scan-step-cert .scan-step-num');
            const req = document.querySelector('[data-role="scan-requirement"]');
            return {
              done: num.dataset.done,
              warn: num.dataset.warn,
              heading: document.querySelector('#scan-step-cert').textContent,
              badge: document.querySelector('.scan-step-cert .scan-step-status').textContent,
              caAlert: /not a server certificate/.test(document.querySelector('.scan-step-cert .scan-step-body').textContent),
              req: req.dataset.state,
              note: req.dataset.note || '',
              reqText: req.textContent,
              domains: document.querySelector('[data-role="scan-domains"]').value
            };
          });
          const ca = await read();
          assertEqual([ca.done, ca.warn, ca.caAlert, ca.domains], ['false', 'true', true, ''], 'step 1: a warning sign, not a check');
          assert(/\(needs attention: CA certificate\)$/.test(ca.heading) && !/done/.test(ca.heading), `spoken as a CA certificate: ${ca.heading}`);
          assertEqual(ca.badge, 'CA certificate', 'status badge (desktop)');
          assertEqual([ca.req, ca.note], ['unmet', 'certNoNames'], 'requirement still unmet, with a note');
          assert(/is required\s*This certificate has no DNS names: enter at least one domain\.$/.test(ca.reqText), `requirement line: ${ca.reqText}`);
          // Start: the error asks for a domain, not for the certificate that is loaded.
          await tab.evaluate(() => document.querySelector('[data-action="scan-run"]').click());
          const error = await tab.waitFor(() => {
            const text = document.querySelector('.scan-step-domains .field-error')?.textContent || '';
            return /no DNS names/.test(text) ? text : false;
          }, { message: 'Start error for a certificate without names' });
          assert(!/load a certificate/.test(error), `Start error: ${error}`);
          assert(await tab.evaluate(() => !document.querySelector('.scan-run-ui')), 'no run started');
          await assertNoHorizontalScroll(tab, 'CA certificate 375 px');
          await tab.evaluate(() => window.scrollTo(0, 0));
          await frames();
          await shot(tab, opts, 'scan-form-375-light-en-ca-cert');
          // Removed: step 1 back to its number, the plain requirement line.
          await tab.evaluate(() => document.querySelector('[data-action="cert-remove"]').click());
          await tab.waitFor(() => !document.querySelector('.scan-step-cert .cert-summary'), { message: 'certificate removed' });
          const gone = await read();
          assertEqual([gone.done, gone.warn, gone.heading, gone.req, gone.note], ['false', 'false', 'Certificate', 'unmet', ''], 'back to the plain step');
          // The next step focuses the domains field itself (the error left the focus there, and
          // typing into a focused field only reveals its caret, not the whole field).
          await tab.evaluate(() => document.activeElement?.blur());
        });

        await run.step('375×667: a domain entered — Start is visible without scrolling, the requirement and step 2 turn into checks, the estimate sits next to Start', async () => {
          await tab.type('[data-role="scan-domains"]', OFFLINE_APEX);
          await frames();
          const typed = await layout('[data-role="scan-domains"]');
          assert(typed.startVisible, `Start on screen where the domain was typed: ${JSON.stringify(typed)}`);
          assert(typed.fieldBottom <= typed.barTop, `the bar does not cover the field being typed in: ${JSON.stringify(typed)}`);
          const info = await tab.evaluate(() => ({
            req: document.querySelector('[data-role="scan-requirement"]').dataset.state,
            via: document.querySelector('[data-role="scan-requirement"]').dataset.via,
            done: [...document.querySelectorAll('.scan-step-num[data-done="true"]')].map((n) => n.closest('.scan-step').dataset.step),
            heading: document.querySelector('#scan-step-domains').textContent,
            plan: document.querySelector('[data-role="scan-runbar"] [data-role="scan-wl-plan"]')?.textContent || ''
          }));
          assertEqual([info.req, info.via, info.done], ['met', 'domains', ['domains']], 'requirement met through the domain, step 2 checked');
          assert(/\(done\)$/.test(info.heading), `the check is spoken too: ${info.heading}`);
          assert(/DNS queries for 1 domain/.test(info.plan), `plan line in the bar: ${info.plan}`);
          // And from the very top of the page, before any scrolling.
          await tab.evaluate(() => window.scrollTo(0, 0));
          await frames();
          assert((await layout()).startVisible, 'Start on screen at the top of the page');
          await shot(tab, opts, 'scan-form-375-light-en-top');
          // At the end of the form the bar rests in its own place, below the Options line.
          await tab.evaluate(() => document.querySelector('.scan-options-box').scrollIntoView({ block: 'start' }));
          await tab.evaluate(() => window.scrollBy(0, 400));
          await frames();
          const end = await layout('.scan-options-box');
          assert(end.stuck === 'false' && end.fieldBottom <= end.barTop, `the bar rests after the Options line: ${JSON.stringify(end)}`);
          await assertNoHorizontalScroll(tab, 'setup form 375 px');
        });

        await run.step('375 px keyboard: Start → focus on Cancel in the bar → Enter cancels → focus back on Start', async () => {
          await tab.evaluate(() => {
            window.__dnsDelay = 250;
            window.scrollTo(0, 0);
            document.querySelector('[data-action="scan-run"]').focus({ preventScroll: true });
          });
          await tab.press('Enter');
          await tab.waitFor(() => document.querySelector('.scan-run-ui .scan-run')?.dataset.status === 'running'
            && document.activeElement?.dataset.action === 'scan-cancel', { timeout: 15000, message: 'running, keyboard focus on Cancel (not <body>)' });
          await tab.press('Enter');
          await tab.waitFor(() => document.querySelector('.scan-run')?.dataset.status === 'cancelled', { timeout: 15000, message: 'cancelled' });
          await tab.waitFor(() => document.activeElement?.dataset.action === 'scan-run', { timeout: 5000, message: 'keyboard focus back on Start' });
          await tab.evaluate(() => { window.__dnsDelay = 0; });
        });

        await run.step('375 px in Turkish and dark: the bar floats with its shadow, no horizontal scroll; a tablet keeps it compact, wide screens in the flow', async () => {
          await setLangUi(tab, 'tr');
          for (const scheme of ['dark', 'light']) {
            await tab.emulateMedia({ 'prefers-color-scheme': scheme });
            await tab.evaluate(() => window.scrollTo(0, 0));
            await frames();
            const l = await layout();
            const shadow = await tab.evaluate(() => getComputedStyle(document.querySelector('[data-role="scan-runbar"]')).boxShadow);
            assert(l.startVisible && l.stuck === 'true' && shadow !== 'none', `${scheme}: ${JSON.stringify({ ...l, shadow })}`);
            assertEqual(await tab.evaluate(() => document.querySelector('[data-role="scan-requirement"]').textContent), 'Bir sertifika ya da en az bir alan adı gerekli (tamam)', 'Turkish requirement line');
            await assertNoHorizontalScroll(tab, `setup form 375 px ${scheme} tr`);
            await shot(tab, opts, `scan-form-375-${scheme}-tr-top`);
          }
          // Reduced motion: the stuck shadow appears without a transition.
          await tab.emulateMedia({ 'prefers-color-scheme': 'light', 'prefers-reduced-motion': 'reduce' });
          const dur = await tab.evaluate(() => parseFloat(getComputedStyle(document.querySelector('[data-role="scan-runbar"]')).transitionDuration) || 0);
          assert(dur < 0.001, `no transition with reduced motion: ${dur}s`);
          await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
          // A tablet keeps the sticky bar compact: Start beside the estimate, not full width.
          await tab.setViewport({ width: 768, height: 1024, mobile: true });
          await tab.evaluate(() => window.dispatchEvent(new Event('resize')));
          await frames();
          const tablet = await tab.evaluate(() => ({
            position: getComputedStyle(document.querySelector('[data-role="scan-runbar"]')).position,
            bar: document.querySelector('[data-role="scan-runbar"]').getBoundingClientRect().width,
            btn: document.querySelector('[data-action="scan-run"]').getBoundingClientRect().width
          }));
          assert(tablet.position === 'sticky' && tablet.btn < tablet.bar / 2, `tablet: ${JSON.stringify(tablet)}`);
          await tab.setViewport({ width: 1440, height: 900 });
          await tab.evaluate(() => window.dispatchEvent(new Event('resize')));
          await frames();
          const wide = await layout();
          assert(wide.position !== 'sticky' && wide.stuck === 'false', `in the flow on a wide screen: ${JSON.stringify(wide)}`);
          await setLangUi(tab, 'en');
          // Leaving the view takes the bar's height off the root again.
          await gotoRoute(tab, 'about');
          assertEqual(await tab.evaluate(() => document.documentElement.style.getPropertyValue('--scan-runbar-h')), '', 'root variable removed on unmount');
          assertEqual(await tab.evaluate(() => window.__zoneBlocked), [], 'nothing but DNS for the zone left the page');
          await assertClean(tab, 'setup form 375 px', origin);
        });
      } finally {
        await tab.close();
        if (saved) {
          await page.evaluate((s) => {
            for (const [key, value] of [['ssds.scan.options', s.options], ['ssds.inventory', s.inventory]]) {
              if (value === null) localStorage.removeItem(key);
              else localStorage.setItem(key, value);
            }
          }, saved);
        }
      }
    }

    run.group('Offline certificate scan (emulated DNS, nothing else leaves the page)');
    {
      const tab = await browser.newPage('about:blank', { width: 1440, height: 900 });
      await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
      // The live suite's stored options / inventory are restored afterwards.
      const saved = await page.evaluate(() => ({ options: localStorage.getItem('ssds.scan.options'), inventory: localStorage.getItem('ssds.inventory') }))
        .catch(() => null);
      const pressed = (scope) => tab.evaluate((s) => document.querySelector(`${s} .seg-btn[aria-pressed="true"]`)?.dataset.value || null, scope);
      const code = (sel) => tab.evaluate((s) => document.querySelector(s)?.textContent || null, sel);
      // Page scroll positions from the moment Start is pressed (the smooth scroll to the results).
      const armScrollLog = async () => {
        await tab.evaluate(() => window.scrollTo(0, 0));
        await sleep(250);
        await tab.evaluate(() => {
          if (!window.__scrollLog) window.addEventListener('scroll', () => window.__scrollLog.push({ y: Math.round(window.scrollY), t: performance.now() }), { passive: true });
          window.__scrollLog = [];
          window.__scrollT0 = performance.now();
        });
      };
      /** Distinct positions in the first 600 ms: a smooth scroll passes many, a jump one or two. */
      const earlyScroll = () => tab.evaluate(() => {
        const early = window.__scrollLog.filter((x) => x.t - window.__scrollT0 < 600).map((x) => x.y);
        return { distinct: new Set(early).size, last: early[early.length - 1] || 0, ys: early.slice(0, 16).join(',') };
      });
      const openTab = async (id) => {
        await tab.evaluate((x) => document.querySelector(`.scan-tabs [data-tab="${x}"]`).click(), id);
        await tab.waitFor((x) => document.querySelector(`.scan-tabs [data-tab="${x}"]`)?.getAttribute('aria-selected') === 'true', { args: [id], message: `tab ${id}` });
      };
      try {
        await run.step('keyboard Start → focus on Cancel → Enter cancels mid-wordlist → focus back; the export bar exports the streamed hits', async () => {
          await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: zoneHandoffScript(OFFLINE_APEX, OFFLINE_DNS) });
          await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: dnsDelayScript });
          await installDownloadCapture(tab);
          await tab.goto(`${server.url}#/about`);
          await waitReady(tab);
          await setLangUi(tab, 'en');
          const known = LIB_SOURCES.map((s) => s.id);
          await tab.evaluate((k, inv) => {
            localStorage.setItem('ssds.scan.options', JSON.stringify({ sources: [], knownSources: k, bruteforce: 'small', permutations: false, originHints: true }));
            localStorage.setItem('ssds.inventory', JSON.stringify({ v: 1, text: inv, updatedAt: new Date().toISOString() }));
          }, known, OFFLINE_INVENTORY);
          await tab.reload();
          await waitReady(tab);
          await gotoRoute(tab, 'scan');
          await tab.setFileInput('.scan-step-cert .filedrop-input', [path.join(FIXTURES, 'ec_wildcard.pem')]);
          await tab.waitFor(() => document.querySelector('.scan-step-cert .cert-summary'), { message: 'certificate loaded' });
          assertEqual(await tab.evaluate(() => document.querySelector('[data-role="scan-domains"]').value), OFFLINE_APEX, 'domain from the certificate');
          // Slow answers keep the wordlist stage running; the scroll log is the reduced-motion control.
          await armScrollLog();
          await tab.evaluate(() => {
            window.__dnsDelay = 250;
            document.querySelector('[data-action="scan-run"]').focus({ preventScroll: true });
          });
          await tab.press('Enter');
          const started = await tab.waitFor(() => {
            const st = document.querySelector('.scan-run-ui .scan-run')?.dataset.status;
            return st === 'running' && document.activeElement?.dataset.action === 'scan-cancel' ? st : false;
          }, { timeout: 15000, message: 'running, keyboard focus on Cancel (not <body>)' });
          assertEqual(started, 'running', 'status');
          await tab.waitFor(() => [...document.querySelectorAll('.scan-hosts tbody tr.dt-row')]
            .filter((tr) => /resolving/.test(tr.textContent)).length >= 2, { timeout: 30000, message: 'two streamed "resolving…" rows' });
          await tab.press('Enter');
          await tab.waitFor(() => document.querySelector('.scan-run')?.dataset.status === 'cancelled', { timeout: 15000, message: 'cancelled' });
          await tab.waitFor(() => document.activeElement?.dataset.action === 'scan-run', { timeout: 5000, message: 'keyboard focus back on Start' });
          const smooth = await earlyScroll();
          assert(smooth.distinct >= 5 && smooth.last > 0, `the control run scrolls smoothly: ${JSON.stringify(smooth)}`);
          const kept = await tab.evaluate(() => ({
            names: [...document.querySelectorAll('.scan-hosts tbody tr.dt-row .scan-host-name')].map((n) => n.textContent),
            hosts: document.querySelector('.scan-exports [data-export="hosts-csv"]').disabled,
            names_: document.querySelector('.scan-exports [data-export="names"]').disabled,
            json: document.querySelector('.scan-exports [data-export="json"]').disabled
          }));
          assert(kept.names.length >= 2, `rows kept after Cancel: ${kept.names}`);
          assertEqual([kept.hosts, kept.names_, kept.json], [false, false, true], 'hosts CSV and names.txt enabled, full JSON waits for a finished scan');
          await takeDownloads(tab);
          await tab.evaluate(() => {
            document.querySelector('.scan-exports [data-export="hosts-csv"]').click();
            document.querySelector('.scan-exports [data-export="names"]').click();
          });
          const files = await takeDownloads(tab);
          const csv = files.find((f) => /^hosts-.*\.csv$/.test(f.name));
          const names = files.find((f) => f.name === 'names.txt');
          assert(csv && names, `downloads: ${files.map((f) => f.name)}`);
          for (const n of kept.names) assert(csv.text.includes(n), `hosts CSV lists ${n}`);
          // names.txt is "only covered" with a certificate: *.wild.example.net covers one label under wild.
          const covered = kept.names.filter((n) => n === 'wild.example.net' || /^[^.]+\.wild\.example\.net$/.test(n));
          assert(covered.length >= 1, `a covered name among ${kept.names}`);
          assertEqual(names.text.split('\n').filter(Boolean).sort(), [...covered].sort(), 'names.txt: the covered hits found so far');
          assertEqual(await tab.evaluate(() => [...document.querySelectorAll('[data-summary="scan"] button')].map((b) => b.disabled)), [true, true],
            'a cancelled scan keeps no result: Copy summary stays off');
        });

        await run.step('reduced motion: Start jumps to the results instead of scrolling smoothly', async () => {
          await tab.emulateMedia({ 'prefers-color-scheme': 'light', 'prefers-reduced-motion': 'reduce' });
          const before = await runStatus(tab);
          await armScrollLog();
          await tab.evaluate(() => {
            window.__dnsDelay = 0;
            document.querySelector('[data-action="scan-run"]').click();
          });
          await tab.waitFor((prev) => {
            const ui = document.querySelector('.scan-run-ui');
            return ui && ui.dataset.run !== prev && ui.querySelector('.scan-run').dataset.status === 'done';
          }, { args: [before.id], timeout: 60000, message: 'offline scan done' });
          const jump = await earlyScroll();
          assert(jump.last > 0 && jump.distinct <= 2, `one jump to the results, no animation: ${JSON.stringify(jump)}`);
          await tab.emulateMedia({ 'prefers-color-scheme': 'light' });
        });

        await run.step('Copy summary names the servers from the list that need the certificate (the tooltip says so); its link carries only the domain', async () => {
          await stubClipboard(tab);
          const tip = await tab.evaluate(() => document.querySelector('[data-summary="scan"] [data-action="copy-summary"]').title);
          assert(/names the servers from your list that need the certificate/.test(tip) && /the link carries only the domains/.test(tip), `tooltip: ${tip}`);
          await tab.click('[data-summary="scan"] [data-action="copy-summary"]');
          await tab.click('[data-summary="scan"] [data-action="copy-summary-text"]');
          await tab.waitFor(() => window.__clip.length === 2, { message: 'two copies' });
          const [md, plain] = await takeClipboard(tab);
          const lines = md.trim().split('\n');
          assertEqual(lines[0], '**SSL Targets · `example.net`**', 'title: the scanned domain (the certificate is line 1)');
          // A self-signed wildcard names itself as the issuer: a code span (no backslash for Slack to show).
          assert(/^- Certificate `\*\.wild\.example\.net` · issued by `[^`\\]+` · valid until 2051-01-01 \(\d[\d,]* days left\)$/.test(lines[1]), `certificate line: ${lines[1]}`);
          assert(/^- \d+ hosts found · \d+ covered by the certificate$/.test(lines[2]), `hosts line: ${lines[2]}`);
          assertEqual(lines[3], '- 2 servers in your list need the certificate: `db01`, `web01`', 'the servers that need it, by name, as the Servers tab lists them');
          assert(lines.includes('- Verify: not checked from the internet yet'), `Verify line: ${md}`);
          const foot = lines[lines.length - 1];
          assertEqual(lines[lines.length - 2], '', 'an empty line: the footer is its own paragraph');
          assert(new RegExp(`^DomainScope · scanned \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2} UTC · ${origin}/domainscope/#/scan\\?domain=example\\.net&run=1$`).test(foot), `footer: ${foot}`);
          assert(!/web01|db01|203\.0\.113\.20|10\.0\.0\.5/.test(foot), 'no inventory data in the link');
          assertEqual(plain, md.replace(/\*\*|`/g, '').replace('\n\nDomainScope · ', '\nDomainScope · '), 'the same lines in plain text');
        });

        await run.step('Behind CDN and Verify share one shell: step 3, the sweep and both toggles follow a change in either card', async () => {
          await openTab('cdn');
          const posix = 'python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem';
          const ps = 'python ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem';
          const cdn = async () => ({
            toggles: await tab.evaluate(() => document.querySelectorAll('.scan-tab-cdn .scan-cli-shell').length),
            pressed: await pressed('.scan-tab-cdn .scan-cli-shell'),
            step3: await code('.scan-tab-cdn .scan-cli-command code'),
            quick: await code('.scan-tab-cdn .scan-cli-quick code')
          });
          const first = await cdn();
          process.stdout.write(`        quick sweep: ${first.quick || 'none (the toggle sits in the CLI card)'}\n`);
          assertEqual([first.toggles, first.pressed, first.step3], [1, 'posix', posix], 'one toggle, POSIX');
          // Behind CDN → PowerShell: step 3 and the sweep switch to `python`.
          await tab.evaluate(() => document.querySelector('.scan-tab-cdn .scan-cli-shell .seg-btn[data-value="powershell"]').click());
          const second = await cdn();
          assertEqual([second.pressed, second.step3], ['powershell', ps], 'PowerShell in Behind CDN');
          if (first.quick) assert(second.quick.startsWith('python ssl_origin_scan.py'), `quick sweep: ${second.quick}`);
          // … and the Verify card follows (the reverse of the next check).
          await openTab('verify');
          await tab.waitFor(() => document.querySelector('.scan-tab-verify .vfy-cli code'), { message: 'Verify CLI card' });
          assertEqual(await pressed('.scan-tab-verify [data-vfy="shell"]'), 'powershell', 'Verify toggle follows Behind CDN');
          assert((await code('.scan-tab-verify .vfy-cli code')).startsWith('python ssl_origin_scan.py'), 'Verify command follows Behind CDN');
          // Verify → POSIX: back in Behind CDN the pressed segment and every command agree.
          await tab.evaluate(() => document.querySelector('.scan-tab-verify [data-vfy="shell"] .seg-btn[data-value="posix"]').click());
          assert((await code('.scan-tab-verify .vfy-cli code')).startsWith('python3 ssl_origin_scan.py'), 'Verify POSIX command');
          await openTab('cdn');
          const third = await cdn();
          assertEqual([third.pressed, third.step3], ['posix', posix], 'Behind CDN follows the Verify card');
          if (first.quick) {
            assert(third.quick.startsWith('python3 ssl_origin_scan.py'), `quick sweep: ${third.quick}`);
            // Redrawing the sweep (an exclude) keeps the shell the toggle shows.
            await tab.type('[data-role="scan-cdn-exclude"]', '203.0.113.99');
            await tab.waitFor(() => /203\.0\.113\.99/.test(document.querySelector('.scan-cli-quick code')?.textContent || ''), { message: 'sweep redrawn with the exclude' });
            const fourth = await cdn();
            assertEqual(fourth.pressed, 'posix', 'toggle after an exclude');
            assert(fourth.quick.startsWith('python3 ssl_origin_scan.py'), `quick sweep after an exclude: ${fourth.quick}`);
          }
          const after = await tab.evaluate(() => ({ blocked: window.__zoneBlocked }));
          assertEqual(after.blocked, [], 'nothing but DNS for the zone left the page');
          await assertClean(tab, 'offline certificate scan', origin);
        });

        await run.step('a passive source that fails (crt.sh answers 400 in the page): Copy summary says the host list may be incomplete, right under the host count', async () => {
          await setOptions(tab, { sources: ['crtsh'], bruteforce: 'small' });
          // A 400 is no transient failure: crt.sh fails at once. (A network error would first go
          // through its whole backoff, 45–75 s, before the scan could finish.)
          await tab.evaluate(() => {
            window.__crtshAsked = 0;
            const inner = window.fetch;
            window.fetch = (input, init) => {
              const url = typeof input === 'string' ? input : (input && input.url) || String(input);
              if (/^https:\/\/crt\.sh\//.test(url)) {
                window.__crtshAsked += 1;
                return Promise.resolve(new Response('bad request', { status: 400 }));
              }
              return inner(input, init);
            };
          });
          const before = await runStatus(tab);
          await tab.evaluate(() => document.querySelector('[data-action="scan-run"]').click());
          await tab.waitFor((prev) => {
            const ui = document.querySelector('.scan-run-ui');
            return ui && ui.dataset.run !== prev && ui.querySelector('.scan-run').dataset.status === 'done';
          }, { args: [before.id], timeout: 30000, message: 'offline scan with crt.sh done' });
          const shown = await tab.evaluate(() => ({
            warning: document.querySelector('.scan-summary [data-summary="sources-failed"]')?.textContent || '',
            asked: window.__crtshAsked
          }));
          assert(shown.asked > 0 && /1 source failed/.test(shown.warning), `the results warn about crt.sh: ${JSON.stringify(shown)}`);
          await stubClipboard(tab);
          await tab.click('[data-summary="scan"] [data-action="copy-summary"]');
          await tab.waitFor(() => window.__clip.length === 1, { message: 'copied' });
          const lines = (await takeClipboard(tab))[0].trim().split('\n');
          assert(/^- \d+ hosts found · \d+ covered by the certificate$/.test(lines[2]), `hosts line: ${lines[2]}`);
          assertEqual(lines[3], '- 1 passive source failed: the list may be incomplete', 'the failed source, before the servers line');
          assertEqual(lines[4], '- 2 servers in your list need the certificate: `db01`, `web01`', 'the servers line follows');
        });
      } finally {
        await tab.close();
        if (saved) {
          await page.evaluate((s) => {
            for (const [key, value] of [['ssds.scan.options', s.options], ['ssds.inventory', s.inventory]]) {
              if (value === null) localStorage.removeItem(key);
              else localStorage.setItem(key, value);
            }
          }, saved);
        }
      }
    }

    run.group('Quality');
    await run.step('i18n: no missing keys, TR and EN key sets match', async () => {
      await assertNoMissingKeys(page);
    });
    await run.step('no console errors, exceptions or CSP violations', async () => {
      await assertClean(page, 'scan', origin);
    });
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

// Run only when executed directly (the harness above is imported by the other E2E files).
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
    process.exitCode = 1;
  });
}
