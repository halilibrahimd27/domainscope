#!/usr/bin/env node
/**
 * verify.e2e.mjs — end-to-end test of SSL Targets › Verify (the Globalping check from the
 * internet) in a real headless Chrome/Edge. OFFLINE: 0 real probes, nothing leaves the page.
 *
 *   node tests/e2e/verify.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Setup (everything installed with Page.addScriptToEvaluateOnNewDocument before the app loads):
 *   - a fake DoH zone for example.net answered inside the page (copied from subdomains.e2e.mjs,
 *     which must not be imported: it runs its suite on load). Unlike that copy it passes NOTHING
 *     through: every other external fetch gets a 503 and is recorded in window.__externalFetches;
 *   - a fake Globalping API (window.__gp), installed after the zone so it is the outermost
 *     window.fetch. It records every call, answers /v1/limits (quota in the body only),
 *     POST /v1/measurements (202 + x-ratelimit-* / x-request-cost headers, or a 429
 *     rate_limit_exceeded; a non-JSON content type gets the real API's 400) and
 *     GET /v1/measurements/:id (in progress first, then a canned result per `target|host`);
 *   - a network-level guard (CDP Fetch domain): any https request that still reached the network
 *     is failed and recorded. The suite asserts it stays empty, api.globalping.io included.
 *   - seed: no passive sources, no wordlist, no permutations, origin hints on; the inventory
 *     `web01 1.2.3.4` / `db01 10.0.0.5`; the certificate tests/fixtures/ec_wildcard.pem.
 *
 * What is checked (spec §9.4 as corrected by the critic notes C.2.6, C.2.7, C.3.1, C.6):
 *   - the Verify tab exists only with a certificate, sits after Behind CDN, is linked from the
 *     Servers tab and the summary, and opening it sends nothing (not even /limits);
 *   - the pair list (7 rows: the private db01 pairs skipped, the origin-hint pair optional),
 *     the plan line, the not-checkable line;
 *   - consent per page session: the first Start shows the privacy text and the cost; Cancel
 *     sends nothing; later batches skip the dialog; "Delete all local data" asks again;
 *     consent is never stored;
 *   - request shape: one free /limits per click, POST bodies (IP target, port 443, limit 1,
 *     timeout 10, HTTPS HEAD, no ipVersion), JSON content type, no Authorization, GETs without
 *     custom headers, no-store, at least 450 ms apart per measurement id; never a private or
 *     CDN-edge address; the origin-hint pair only after the opt-in is ticked;
 *   - verdicts, warnings (chain-incomplete), exposure (exposed), headline keys and the tab badge
 *     across the first batch, the origin opt-in, a certificate swap and "Check again";
 *   - the CLI card (targets, names, --cert, --json, PowerShell prefix), new-cert.pem, the CSV /
 *     JSON exports and the scan's full JSON `verification` block;
 *   - quota: /limits at 0 → alert and 0 POSTs; a POST 429 in a new window → not-run · quota with
 *     the last verdict kept; the buttons stay usable;
 *   - Stop → "Not checked · Stopped", then Check again polls the paid id without a new POST;
 *   - a batch finishing while another view is open → toast → "Show results" lands on Verify;
 *   - a new scan cancels the running verification; Globalping unreachable → ErrorBanner + Retry;
 *   - TR + EN, light + dark, 1440 px and a 390 px phone without horizontal scroll; no missing
 *     i18n keys; zero console errors, exceptions and CSP violations.
 */

import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { orderSuites } from './run-all.mjs';
import { SOURCES as LIB_SOURCES } from '../../assets/js/lib/sources.js';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions,
  createRunner, csvHeader, gotoRoute, installDownloadCapture, setLangUi, sleep, takeDownloads, waitReady
} from './scan.e2e.mjs';

/* ------------------------------------------------------------------------ */
/* Test data                                                                */
/* ------------------------------------------------------------------------ */

const CERT_FILE = path.join(FIXTURES, 'ec_wildcard.pem');
const APEX = 'example.net';
const ZONE = {
  'wild.example.net': { A: ['1.2.3.4'] },
  'www.wild.example.net': { A: ['1.2.3.4'] },
  'api.wild.example.net': { A: ['5.6.7.8'] },
  'legacy.wild.example.net': { A: ['1.2.3.5'] },
  'shop.wild.example.net': { A: ['104.16.5.5'] }, // a Cloudflare address: proxied
  'vpn.wild.example.net': { A: ['10.0.0.5'] } // private
};
const INVENTORY = 'web01 1.2.3.4\ndb01 10.0.0.5';
const N = (label) => `${label}.wild.example.net`;
const WILD = 'wild.example.net';
/** Addresses that must never reach Globalping: private, and a CDN edge. */
const NEVER_SENT = ['10.0.0.5', '104.16.5.5'];
const GP = 'https://api.globalping.io/v1';

/** SHA-256 of a PEM certificate's DER (lowercase hex). */
async function pemSha256(file) {
  const pem = await readFile(file, 'utf8');
  const b64 = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(pem)[1].replace(/\s+/g, '');
  return createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex');
}
const colonHex = (hex) => hex.toUpperCase().match(/../g).join(':');

/* ------------------------------------------------------------------------ */
/* In-page fakes                                                            */
/* ------------------------------------------------------------------------ */

/**
 * A tiny authoritative zone answered inside the page for every DoH resolver.
 * Copied from subdomains.e2e.mjs (critic note C.2.8: that module cannot be imported), with
 * `passthrough: false`: names outside the apex get NXDOMAIN, and any other request to another
 * origin gets a 503 and is recorded — no scanner lookup (SPF, MX, resolver-leak, IP intel)
 * leaves the page.
 */
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
  window.__externalFetches = [];
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (new URL(url, location.href).origin === location.origin) return realFetch(input, init);
      window.__externalFetches.push(url);
      return new Response('blocked by the E2E harness', { status: 503 });
    }
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__fakeDnsQueries += 1;
    const out = name === APEX || name.endsWith('.' + APEX) ? answer(name, q.type) : { rcode: 'NXDOMAIN', answers: [], authorities: [] };
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/**
 * Fake Globalping v1 API (outermost window.fetch wrapper). Knobs on window.__gp:
 * limitsRemaining (what /limits reports), postRemaining (a POST answers 429 at 0), delayMs
 * (extra time before a result is final), limitsDelayMs (a slow /limits answer; an abort ends
 * it), netDown (every /measurements request throws a
 * TypeError). __gpFlip() swaps www and shop to the new certificate; __gpNewWindow({limits,
 * post}) opens a later quota window (the hour rolled over).
 */
const fakeGlobalpingScript = (newFp) => `(() => {
  const API = ${JSON.stringify(GP)};
  const NEW_FP = ${JSON.stringify(newFp)};
  const OLD_FP = Array(32).fill('AB').join(':');
  const iso = (ms) => new Date(ms).toISOString();
  const PROBES = [
    { continent: 'EU', region: 'Western Europe', country: 'DE', state: null, city: 'Falkenstein', asn: 24940, network: 'Hetzner Online GmbH', latitude: 50.48, longitude: 12.37, tags: ['datacenter-network'], resolvers: ['private'] },
    { continent: 'NA', region: 'Northern America', country: 'US', state: 'CA', city: 'Los Angeles', asn: 36352, network: 'HostPapa', latitude: 34.05, longitude: -118.24, tags: ['datacenter-network', 'u-probe'], resolvers: ['private'] },
    { continent: 'AS', region: 'Western Asia', country: 'TR', state: null, city: 'Istanbul', asn: 209604, network: '2E Telekomunikasyon', latitude: 41.01, longitude: 28.95, tags: ['eyeball-network'], resolvers: ['private'] }
  ];
  const gp = window.__gp = {
    calls: [], gets: {}, measurements: {}, n: 0,
    limitsRemaining: 250, postRemaining: 250, windowEnd: null, delayMs: 0, limitsDelayMs: 0, netDown: false, flipped: false
  };
  window.__gpFlip = () => { gp.flipped = true; };
  window.__gpNewWindow = ({ limits, post }) => {
    gp.windowEnd = Math.max(Date.now() + 3600e3, (gp.windowEnd || 0) + 120e3);
    gp.limitsRemaining = limits;
    gp.postRemaining = post;
  };
  const resetS = () => (gp.windowEnd ? Math.max(1, Math.ceil((gp.windowEnd - Date.now()) / 1000)) : 0);
  const quotaHeaders = (remaining) => ({
    'x-ratelimit-limit': '250', 'x-ratelimit-consumed': String(250 - remaining),
    'x-ratelimit-remaining': String(remaining), 'x-ratelimit-reset': String(resetS())
  });
  const newCert = () => ({
    authorized: true, protocol: 'TLSv1.3', cipherName: 'TLS_AES_128_GCM_SHA256',
    createdAt: '2025-01-01T00:00:00.000Z', expiresAt: '2051-01-01T00:00:00.000Z',
    issuer: { CN: '*.wild.example.net' }, subject: { CN: '*.wild.example.net', alt: 'DNS:*.wild.example.net, DNS:wild.example.net' },
    keyType: 'EC', keyBits: 256, serialNumber: '07', fingerprint256: NEW_FP, publicKey: '04:11:22'
  });
  const oldCert = () => ({
    authorized: true, protocol: 'TLSv1.3', cipherName: 'TLS_AES_256_GCM_SHA384',
    createdAt: iso(Date.now() - 85 * 864e5), expiresAt: iso(Date.now() + 5 * 864e5 + 3600e3),
    issuer: { C: 'US', O: 'Example Test CA', CN: 'Example Test CA E1' }, subject: { CN: '*.wild.example.net', alt: 'DNS:*.wild.example.net, DNS:wild.example.net' },
    keyType: 'EC', keyBits: 256, serialNumber: '5A:17:00:C3', fingerprint256: OLD_FP, publicKey: '04:33:44'
  });
  const ok = (target, tls) => ({
    status: 'finished', resolvedAddress: target, statusCode: 200, statusCodeName: 'OK',
    timings: { total: 48, dns: null, tcp: 11, tls: 24, firstByte: 9, download: 1 }, tls,
    headers: { server: 'fake' }, rawHeaders: 'Server: fake', rawBody: null, rawOutput: 'HTTP/1.1 200\\nServer: fake', truncated: false
  });
  const failed = (text, total = null) => ({
    status: 'failed', resolvedAddress: null, statusCode: null, statusCodeName: null, timings: { total, dns: null, tcp: null, tls: null, firstByte: null, download: null },
    tls: null, headers: {}, rawHeaders: null, rawBody: null, rawOutput: text, truncated: false
  });
  const canned = (target, host) => {
    switch (target + '|' + host) {
      case '1.2.3.4|wild.example.net': return ok(target, newCert());
      case '1.2.3.4|www.wild.example.net': return ok(target, gp.flipped ? newCert() : oldCert());
      case '1.2.3.4|shop.wild.example.net':
        return ok(target, gp.flipped ? newCert() : { ...newCert(), authorized: false, error: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
      case '5.6.7.8|api.wild.example.net': return ok(target, newCert());
      case '1.2.3.5|legacy.wild.example.net': return failed('Request timed out while establishing the TCP connection.', 10001);
      default: return failed('connect ECONNREFUSED ' + target + ':443');
    }
  };
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers } });
  const inner = window.fetch;
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!url.startsWith('https://api.globalping.io/')) return inner(input, init);
    const method = String(init.method || (input && input.method) || 'GET').toUpperCase();
    const headers = {};
    new Headers(init.headers || (typeof input === 'object' && input.headers) || {}).forEach((v, k) => { headers[k] = v; });
    let body = null;
    try { body = typeof init.body === 'string' ? JSON.parse(init.body) : null; } catch { body = String(init.body); }
    const p = url.startsWith(API) ? url.slice(API.length) : url;
    gp.calls.push({ method, path: p, headers, body, cache: init.cache || null, t: Date.now() });
    if (init.signal && init.signal.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
    if (p === '/limits' && method === 'GET') {
      if (gp.limitsDelayMs) {
        // A slow quota read (a click can land while it is pending); an abort ends it like fetch.
        await new Promise((resolve, reject) => {
          const timer = setTimeout(resolve, gp.limitsDelayMs);
          if (init.signal) init.signal.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('The operation was aborted.', 'AbortError')); }, { once: true });
        });
      }
      return json(200, { rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: gp.limitsRemaining, reset: resetS() } } } });
    }
    if (p.startsWith('/measurements') && gp.netDown) throw new TypeError('Failed to fetch');
    if (p === '/measurements' && method === 'POST') {
      if (!/^application\\/json\\b/i.test(headers['content-type'] || '')) {
        return json(400, { error: { type: 'validation_error', message: 'Parameters validation failed.', params: { type: '"type" is required' } } });
      }
      if (!gp.windowEnd) gp.windowEnd = Date.now() + 3600e3;
      if (gp.postRemaining <= 0) {
        return json(429, { error: { type: 'rate_limit_exceeded', message: 'This measurement exceeds the remaining hourly rate limit for your IP address.' } },
          { ...quotaHeaders(0), 'x-request-cost': '1' });
      }
      gp.postRemaining -= 1;
      gp.limitsRemaining = Math.max(0, gp.limitsRemaining - 1);
      gp.n += 1;
      const id = 'fakeMeas' + String(gp.n).padStart(8, '0');
      gp.measurements[id] = { id, target: body.target, host: body.measurementOptions.request.host, at: Date.now(), probe: PROBES[gp.n % PROBES.length] };
      return json(202, { id, probesCount: 1 }, { ...quotaHeaders(gp.limitsRemaining), 'x-request-cost': '1', location: API + '/measurements/' + id });
    }
    const m = /^\\/measurements\\/([A-Za-z0-9]+)$/.exec(p);
    if (m && method === 'GET') {
      (gp.gets[m[1]] = gp.gets[m[1]] || []).push(Date.now());
      const meas = gp.measurements[m[1]];
      if (!meas) return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
      const done = Date.now() - meas.at >= 700 + gp.delayMs;
      const base = {
        id: meas.id, type: 'http', createdAt: iso(meas.at), updatedAt: iso(Date.now()), target: meas.target, probesCount: 1,
        locations: [{ magic: 'world', limit: 1 }], measurementOptions: { port: 443, request: { host: meas.host } }
      };
      if (!done) return json(200, { ...base, status: 'in-progress', results: [{ probe: meas.probe, result: { status: 'in-progress', rawHeaders: '', rawBody: '', rawOutput: '' } }] });
      return json(200, { ...base, status: 'finished', results: [{ probe: meas.probe, result: canned(meas.target, meas.host) }] });
    }
    return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
  };
})();`;

/**
 * Transitions of the Verify panel (data-starting true → false: a click settled; data-status
 * running → other: a batch ended), counted by a MutationObserver so a fast transition between
 * two polls is never missed.
 */
const panelWatchScript = `(() => {
  window.__vfy = { launches: 0, batches: 0 };
  const start = () => new MutationObserver((records) => {
    for (const r of records) {
      const el = r.target;
      if (!el.matches || !el.matches('[data-vfy="panel"]')) continue;
      const now = el.getAttribute(r.attributeName);
      if (r.attributeName === 'data-starting' && r.oldValue === 'true' && now === 'false') window.__vfy.launches += 1;
      if (r.attributeName === 'data-status' && r.oldValue === 'running' && now !== 'running') window.__vfy.batches += 1;
    }
  }).observe(document.documentElement, { subtree: true, attributes: true, attributeOldValue: true, attributeFilter: ['data-starting', 'data-status'] });
  if (document.documentElement) start(); else document.addEventListener('DOMContentLoaded', start);
})();`;

/* ------------------------------------------------------------------------ */
/* Page helpers                                                             */
/* ------------------------------------------------------------------------ */

const PANEL = '.scan-tab-verify [data-vfy="panel"]';
const DIALOG = 'dialog.vfy-confirm[open]';

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

/** Element screenshot (clipped, beyond the viewport if needed); no-op with --no-shots. */
async function shotEl(page, opts, name, selector) {
  if (!opts.shots) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
  const box = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    window.scrollTo(0, 0);
    const r = el.getBoundingClientRect();
    return { x: Math.max(0, r.left + window.scrollX - 8), y: Math.max(0, r.top + window.scrollY - 8), width: r.width + 16, height: r.height + 16 };
  }, selector);
  if (!box || !box.width || !box.height) return;
  await mkdir(SHOTS, { recursive: true });
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.min(Math.ceil(box.height), 9000), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}

/** Viewport screenshot (a dialog is only drawn in the viewport). */
async function shotView(page, opts, name) {
  if (!opts.shots) return;
  await mkdir(SHOTS, { recursive: true });
  await page.screenshot(path.join(SHOTS, `${name}.png`));
}

/** Elements of `selector` sticking out of the viewport (tables and code scroll inside). */
const overflowingIn = (page, selector) => page.evaluate((sel) => {
  const root = document.querySelector(sel);
  if (!root) return ['(missing)'];
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of root.querySelectorAll('*')) {
    if (el.closest('.dt-scroll, pre, .code-block, .codeblock')) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    if (r.right > vw + 1 || r.left < -1) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} ${Math.round(r.left)}..${Math.round(r.right)}`);
  }
  return out.slice(0, 8);
}, selector);

/** Every Globalping call recorded by the fake, from index `from`. */
const gpCalls = (page, from = 0) => page.evaluate((f) => window.__gp.calls.slice(f), from);
const gpCount = (page) => page.evaluate(() => window.__gp.calls.length);
const posts = (calls) => calls.filter((c) => c.method === 'POST' && c.path === '/measurements');
const limitsReads = (calls) => calls.filter((c) => c.method === 'GET' && c.path === '/limits');
const pairOf = (c) => `${c.body.target}|${c.body.measurementOptions.request.host}`;

/** Panel status + transition counters. */
const panelState = (page) => page.evaluate((sel) => {
  const p = document.querySelector(sel);
  return { status: p ? p.dataset.status : null, starting: p ? p.dataset.starting : null, ...window.__vfy };
}, PANEL);

/** Wait until the launch counter passed `mark` (the click settled: dialog closed, batch started or refused). */
async function waitLaunch(page, mark, message = 'launch settled') {
  await page.waitFor((n) => window.__vfy.launches > n, { args: [mark.launches], timeout: 15000, message });
}

/** Wait until a batch that started after `mark` ended. */
async function waitBatch(page, mark, message = 'batch finished', timeout = 30000) {
  await page.waitFor((n) => window.__vfy.batches > n, { args: [mark.batches], timeout, message });
  await page.waitFor((sel) => document.querySelector(sel)?.dataset.starting === 'false', { args: [PANEL], message: `${message} (settled)` });
}

/** The Verify table as [{ key, name, ip, state, status, skip, notRun, error, warn, exp, last, served, sub }]. */
const readRows = (page) => page.evaluate(() => [...document.querySelectorAll('.scan-tab-verify .vfy-table tbody tr.dt-row')].map((tr) => {
  const q = (s) => tr.querySelector(s);
  const name = q('.vfy-name')?.textContent || '';
  const ip = q('.vfy-ip')?.textContent || '';
  return {
    key: `${name}|${ip}`,
    name,
    ip,
    state: q('[data-vfy-state]')?.dataset.vfyState || '',
    status: q('[data-vfy-status]')?.dataset.vfyStatus || '',
    skip: q('[data-vfy-skip]')?.dataset.vfySkip || '',
    notRun: q('[data-vfy-not-run]')?.dataset.vfyNotRun || '',
    error: q('[data-vfy-error]')?.dataset.vfyError || '',
    warn: [...tr.querySelectorAll('[data-vfy-warn]')].map((b) => b.dataset.vfyWarn),
    exp: q('[data-vfy-exp]')?.dataset.vfyExp || '',
    last: q('[data-vfy-last]')?.dataset.vfyLast || '',
    served: q('.vfy-served-cn')?.closest('.vfy-cell-2')?.textContent || '',
    sub: q('.vfy-ip')?.parentElement?.querySelector('.vfy-sub')?.textContent || ''
  };
}));
const byKey = (rows) => Object.fromEntries(rows.map((r) => [r.key, r]));
const headKeys = (page) => page.evaluate(() => [...document.querySelectorAll('.scan-tab-verify .vfy-headline [data-head]')].map((a) => a.dataset.head));
const badge = (page) => page.evaluate(() => {
  const b = document.querySelector('.scan-tabs .tab[data-tab="verify"] .tab-badge');
  return b && !b.hidden ? { text: b.textContent, warn: b.classList.contains('tab-badge-warn'), ok: b.classList.contains('tab-badge-ok') } : null;
});
const recheckCount = (page) => page.evaluate(() => document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]')?.dataset.count ?? null);

/** Wait until the page stops scrolling (a scan start scrolls to the results smoothly). */
async function settleScroll(page) {
  let last = null;
  for (let i = 0; i < 40; i += 1) {
    const y = await page.evaluate(() => Math.round(window.scrollY));
    if (y === last) return;
    last = y;
    await sleep(120);
  }
}

/** Open a results tab of the current run. */
async function openTab(page, id) {
  await settleScroll(page);
  await page.click(`.scan-tabs .tab[data-tab="${id}"]`);
  await page.waitFor((t) => document.querySelector(`.scan-tabs .tab[data-tab="${t}"]`)?.getAttribute('aria-selected') === 'true', { args: [id], message: `tab ${id}` });
}

/** Current run id (the run UI's data-run). */
const runId = (page) => page.evaluate(() => document.querySelector('.scan-run-ui')?.dataset.run || null);

/** Start a scan with the form as it is, and wait until it is done (offline: nothing may leave the page). */
async function runScan(page) {
  const before = await runId(page);
  const ext0 = await page.evaluate(() => window.__externalFetches.length);
  await page.click('[data-action="scan-run"]');
  await page.waitFor((b) => {
    const ui = document.querySelector('.scan-run-ui');
    return ui && ui.dataset.run !== b && ui.querySelector('.scan-run')?.dataset.status === 'done';
  }, { args: [before], timeout: 90000, interval: 150, message: 'scan done' });
  await settleScroll(page);
  const ext = await page.evaluate((n) => window.__externalFetches.slice(n), ext0);
  assertEqual(ext, [], 'external requests during the scan (the seeded options must disable every passive source)');
  return runId(page);
}

/** Seed the offline scan options (no passive source, no wordlist, no permutations, origin hints on). */
async function seedOptions(page) {
  const known = LIB_SOURCES.map((s) => s.id);
  await page.evaluate((k) => {
    localStorage.setItem('ssds.scan.options', JSON.stringify({ sources: [], knownSources: k, bruteforce: 'off', permutations: false, originHints: true }));
  }, known);
}

/** Dismiss toasts that would cover buttons. */
const dismissToasts = (page) => page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));

/* ------------------------------------------------------------------------ */
/* Node-side checks                                                         */
/* ------------------------------------------------------------------------ */

async function nodeChecks(run, newSha) {
  run.group('Node: harness and fixtures');
  await run.step('run-all orders the verify suite right after scan', () => {
    assertEqual(orderSuites(['cert.e2e.mjs', 'verify.e2e.mjs', 'scan.e2e.mjs', 'shell.e2e.mjs']), ['shell', 'scan', 'verify', 'cert'], 'order');
  });
  await run.step('ec_wildcard.pem fingerprint (the fake serves it as the new certificate)', async () => {
    const expected = JSON.parse(await readFile(path.join(FIXTURES, 'expected.json'), 'utf8'))['ec_wildcard.pem'].sha256;
    assertEqual(newSha, expected, 'sha256');
  });
  await run.step('the verify-panel pure helpers agree with the headline base (Node)', async () => {
    const P = await import('../../assets/js/ui/verify-panel.js');
    assertEqual(P.badgeFromSummary({ servers: { total: 3, filteredOrigins: 1, live: 2, old: 0, chain: 0, incomplete: 0, base: 2 }, exposed: 0 }),
      { value: '2/2', variant: 'ok' }, 'ok when every counted server is live (filtered origins left out)');
    assertEqual(P.badgeFromSummary({ servers: { total: 3, filteredOrigins: 0, live: 1, old: 1, chain: 0, incomplete: 0, base: 3 }, exposed: 0 }),
      { value: '1/3', variant: 'warn' }, 'warn while a server is still old');
  });
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  const newSha = await pemSha256(CERT_FILE);
  await nodeChecks(run, newSha);

  const server = await startServer({ base: BASE });
  const origin = new URL(server.url).origin;
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}; offline: fake DoH zone ${APEX} + fake Globalping (0 real probes)\n`);
  let page = null;
  let netHits = [];
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    netHits = await networkGuard(page);
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeZoneScript(APEX, ZONE) });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeGlobalpingScript(colonHex(newSha)) });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: panelWatchScript });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    let run1 = null;
    run.group('Scan with a certificate (desktop 1440×900, English, light)');
    await run.step('seed the inventory and offline options, upload ec_wildcard.pem, scan the emulated zone', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      await seedOptions(page);
      await page.evaluate((text) => localStorage.setItem('ssds.inventory', JSON.stringify({ v: 1, text, updatedAt: new Date().toISOString() })), INVENTORY);
      await page.reload();
      await waitReady(page);
      await gotoRoute(page, 'scan');
      await page.setFileInput('.scan-step-cert .filedrop-input', [CERT_FILE]);
      await page.waitFor(() => document.querySelector('.scan-step-cert .cert-summary'), { message: 'certificate loaded' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="scan-domains"]').value), APEX, 'domain filled from the certificate');
      await page.type('textarea[data-role="scan-extra"]', Object.keys(ZONE).join('\n'));
      run1 = await runScan(page);
      assert(await page.evaluate(() => window.__fakeDnsQueries > 10), 'the zone answered the scan');
      assertEqual(await gpCount(page), 0, 'no Globalping call during the scan');
    });

    await run.step('the Verify tab follows Behind CDN; Servers tab and summary link to it; nothing is sent', async () => {
      const tabs = await page.evaluate(() => [...document.querySelectorAll('.scan-tabs .tab[data-tab]')].map((b) => b.dataset.tab));
      assertEqual(tabs, ['hosts', 'servers', 'cdn', 'verify', 'sources', 'ct'], 'tab order');
      assert(await page.evaluate(() => !!document.querySelector('[data-summary="verify"]')), 'summary hint');
      await openTab(page, 'servers');
      await page.waitFor(() => document.querySelector('[data-action="scan-open-verify"]'), { message: 'Servers tab hint' });
      await page.click('[data-action="scan-open-verify"]');
      await page.waitFor(() => document.querySelector('.scan-tabs .tab[data-tab="verify"]')?.getAttribute('aria-selected') === 'true'
        && document.querySelector('.scan-tab-verify [data-vfy="panel"]'), { message: 'Verify tab opened' });
      await sleep(300);
      assertEqual(await gpCount(page), 0, 'opening the tab sends nothing, not even /limits');
      assertEqual(await badge(page), null, 'no badge before the first batch');
    });

    await run.step('pair list: 7 rows (private db01 pairs skipped, the origin-hint pair optional), plan and not-checkable lines', async () => {
      const rows = byKey(await readRows(page));
      assertEqual(Object.keys(rows).sort(), [
        `${N('api')}|5.6.7.8`, `${N('legacy')}|1.2.3.5`, `${N('shop')}|1.2.3.4`, `${N('shop')}|10.0.0.5`,
        `${N('vpn')}|10.0.0.5`, `${N('www')}|1.2.3.4`, `${WILD}|1.2.3.4`
      ].sort(), 'rows');
      for (const k of [`${WILD}|1.2.3.4`, `${N('www')}|1.2.3.4`, `${N('api')}|5.6.7.8`, `${N('legacy')}|1.2.3.5`]) assertEqual(rows[k].state, 'pending', `${k} pending`);
      assertEqual([rows[`${N('shop')}|1.2.3.4`].state, rows[`${N('shop')}|1.2.3.4`].notRun], ['not-run', 'optional'], 'origin-hint pair waits for the opt-in');
      assert(/web01/.test(rows[`${N('shop')}|1.2.3.4`].sub), 'hint pair on web01');
      for (const k of [`${N('vpn')}|10.0.0.5`, `${N('shop')}|10.0.0.5`]) assertEqual([rows[k].state, rows[k].skip], ['skipped', 'private'], `${k} skipped`);
      const info = await page.evaluate(() => ({
        plan: { checks: document.querySelector('[data-vfy="plan"]')?.dataset.checks, servers: document.querySelector('[data-vfy="plan"]')?.dataset.servers },
        planText: document.querySelector('[data-vfy="plan"]')?.textContent,
        nothere: document.querySelector('[data-vfy="nothere"]')?.textContent || '',
        privacy: !!document.querySelector('[data-vfy="privacy"]'),
        origins: document.querySelector('[data-vfy="origins"] input')?.checked,
        start: document.querySelector('[data-action="vfy-start"]')?.disabled
      }));
      assertEqual([info.plan.checks, info.plan.servers], ['4', '3'], `plan line (${info.planText})`);
      assert(/1 private address\b/.test(info.nothere), `not-checkable line: ${info.nothere}`);
      assertEqual([info.privacy, info.origins, info.start], [true, false, false], 'privacy notice, opt-in off, Start enabled');
      await shotEl(page, opts, 'verify-desktop-light-en-idle', '.scan-tabs');
    });

    run.group('Consent, cost and the first batch');
    await run.step('Start → one free /limits, the privacy + cost dialog; Cancel sends nothing', async () => {
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('[data-action="vfy-start"]');
      await page.waitFor((d) => document.querySelector(d), { args: [DIALOG], message: 'confirm dialog' });
      const dlg = await page.evaluate((d) => {
        const el = document.querySelector(d);
        const cost = el.querySelector('[data-vfy="confirm-cost"]');
        return { privacy: el.querySelector('[data-vfy="confirm-privacy"]')?.textContent || '', checks: cost?.dataset.checks, fit: cost?.dataset.fit, cost: cost?.textContent || '' };
      }, DIALOG);
      assert(/Globalping/.test(dlg.privacy) && /six months/.test(dlg.privacy) && /Only check servers you operate/.test(dlg.privacy), 'privacy text in the dialog');
      assertEqual([dlg.checks, dlg.fit], ['4', '4'], `cost preview (${dlg.cost})`);
      assert(/\b4\b/.test(dlg.cost) && /250/.test(dlg.cost), `cost text: ${dlg.cost}`);
      const calls = await gpCalls(page, c0);
      assertEqual(calls.map((c) => `${c.method} ${c.path}`), ['GET /limits'], 'only the free quota read before consent');
      await shotView(page, opts, 'verify-desktop-light-en-confirm');
      await page.click(`${DIALOG} .modal-foot .btn:not(.btn-primary)`);
      await waitLaunch(page, mark, 'dialog cancelled');
      assertEqual(posts(await gpCalls(page, c0)).length, 0, 'Cancel sends nothing');
      assertEqual((await panelState(page)).status, 'idle', 'still idle');
    });

    await run.step('Start again → the dialog again (no consent yet) → 4 checks; never a private, CDN or hint pair', async () => {
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('[data-action="vfy-start"]');
      await page.waitFor((d) => document.querySelector(d), { args: [DIALOG], message: 'confirm dialog' });
      assert(await page.evaluate((d) => !!document.querySelector(`${d} [data-vfy="confirm-privacy"]`), DIALOG), 'privacy text again');
      await page.click(`${DIALOG} .modal-foot .btn-primary`);
      await waitLaunch(page, mark);
      await sleep(250);
      await shotEl(page, opts, 'verify-desktop-light-en-running', '.scan-tab-verify');
      await waitBatch(page, mark);
      const calls = await gpCalls(page, c0);
      assertEqual(limitsReads(calls).length, 1, 'one /limits per click');
      assertEqual(posts(calls).map(pairOf).sort(), [`1.2.3.4|${N('www')}`, `1.2.3.4|${WILD}`, `1.2.3.5|${N('legacy')}`, `5.6.7.8|${N('api')}`].sort(), 'the 4 DNS / unmatched pairs');
      assertEqual((await panelState(page)).status, 'done', 'done');
    });

    await run.step('verdicts: new cert on wild and api, old on www ("in 5 days"), no answer on legacy; headline and badge', async () => {
      const rows = byKey(await readRows(page));
      const pick = (k) => [rows[k].state, rows[k].status];
      assertEqual(pick(`${WILD}|1.2.3.4`), ['done', 'UPDATED'], 'wild');
      assertEqual(pick(`${N('api')}|5.6.7.8`), ['done', 'UPDATED'], 'api');
      assertEqual(pick(`${N('www')}|1.2.3.4`), ['done', 'NEEDS_UPDATE'], 'www');
      assert(/in 5 days/.test(rows[`${N('www')}|1.2.3.4`].served), `www served column: ${rows[`${N('www')}|1.2.3.4`].served}`);
      assertEqual(pick(`${N('legacy')}|1.2.3.5`), ['done', 'TIMEOUT'], 'legacy');
      assertEqual([rows[`${N('shop')}|1.2.3.4`].state, rows[`${N('shop')}|1.2.3.4`].notRun], ['not-run', 'optional'], 'shop still optional');
      assertEqual(rows[`${N('vpn')}|10.0.0.5`].skip, 'private', 'vpn');
      assertEqual(await headKeys(page), ['some', 'unreachable', 'notHere'], 'headline keys');
      assertEqual(await badge(page), { text: '1/3', warn: true, ok: false }, 'tab badge');
      assertEqual(await recheckCount(page), '2', 'Check again (www, legacy)');
      await shotEl(page, opts, 'verify-desktop-light-en-done', '.scan-tab-verify');
    });

    await run.step('requests: IP target, port 443, limit 1, timeout 10, HTTPS HEAD, JSON, no token; polls ≥ 450 ms apart per id', async () => {
      const calls = await gpCalls(page);
      for (const c of posts(calls)) {
        const b = c.body;
        const o = b.measurementOptions;
        assertEqual([b.type, b.limit, b.timeout, o.protocol, o.port, o.request.method, o.request.path, 'ipVersion' in b, 'ipVersion' in o, 'locations' in b],
          ['http', 1, 10, 'HTTPS', 443, 'HEAD', '/', false, false, false], `POST body ${pairOf(c)}`);
        assert(/^application\/json/.test(c.headers['content-type'] || ''), 'JSON content type');
        assert(!('authorization' in c.headers), 'no Authorization header');
      }
      for (const c of calls.filter((x) => x.method === 'GET')) {
        assertEqual(Object.keys(c.headers), [], `GET ${c.path} has no custom headers (no preflight)`);
        if (c.path.startsWith('/measurements/')) assertEqual(c.cache, 'no-store', 'poll is no-store');
      }
      const gets = await page.evaluate(() => window.__gp.gets);
      let closest = Infinity;
      for (const times of Object.values(gets)) for (let i = 1; i < times.length; i += 1) closest = Math.min(closest, times[i] - times[i - 1]);
      assert(closest >= 450, `closest two GETs on one id: ${closest} ms`);
      const sent = JSON.stringify(calls.map((c) => c.body));
      for (const ip of NEVER_SENT) assert(!sent.includes(ip), `${ip} never sent`);
    });

    run.group('CLI card and exports');
    await run.step('CLI card: private and unanswered addresses, --cert / --json, PowerShell prefix, new-cert.pem', async () => {
      const cmd = await page.evaluate(() => document.querySelector('.scan-tab-verify .vfy-cli code')?.textContent || '');
      assert(cmd.startsWith('python3 ssl_origin_scan.py -t '), `POSIX command: ${cmd}`);
      assert(cmd.endsWith(' --cert new-cert.pem --json verify-cli.json'), `options: ${cmd}`);
      const [targets, names] = /-t (.+?) -n (.+?) --cert/.exec(cmd).slice(1).map((s) => s.split(' ').sort());
      assertEqual(targets, ['1.2.3.5', '10.0.0.5'], 'targets');
      assertEqual(names, [N('legacy'), N('shop'), N('vpn')].sort(), 'names');
      await page.click('.scan-tab-verify [data-vfy="shell"] [data-value="powershell"]');
      const ps = await page.waitFor(() => {
        const c = document.querySelector('.scan-tab-verify .vfy-cli code')?.textContent || '';
        return c.startsWith('python ') ? c : false;
      }, { message: 'PowerShell command' });
      assert(ps.startsWith('python ssl_origin_scan.py -t '), `PowerShell: ${ps}`);
      await page.click('.scan-tab-verify [data-vfy="shell"] [data-value="posix"]');
      await takeDownloads(page);
      await page.click('.scan-tab-verify [data-action="vfy-cert"]');
      const [pem] = await takeDownloads(page);
      assertEqual(pem && pem.name, 'new-cert.pem', 'download name');
      assert(/^-----BEGIN CERTIFICATE-----/.test(pem.text), 'PEM');
      assertEqual(pem.text.replace(/\r/g, '').trim(), (await readFile(CERT_FILE, 'utf8')).replace(/\r/g, '').trim(), 'the loaded certificate');
    });

    await run.step('exports: CSV starts with the CLI columns, 7 rows; JSON without key material; scan JSON has `verification`', async () => {
      await takeDownloads(page);
      await page.click('.scan-tab-verify .vfy-table [data-export="csv"]');
      await page.click('.scan-tab-verify .vfy-table [data-export="json"]');
      await page.click('.scan-exports [data-export="json"]');
      const files = await takeDownloads(page);
      const csv = files.find((f) => /^verify.*\.csv$/.test(f.name));
      const json = files.find((f) => /^verify.*\.json$/.test(f.name));
      const scan = files.find((f) => /^scan.*\.json$/.test(f.name));
      assert(csv && json && scan, `downloads: ${files.map((f) => f.name).join(', ')}`);
      const head = csvHeader(csv.text);
      assertEqual(head.slice(0, 9), ['server', 'ip', 'port', 'probe', 'name', 'sni', 'status', 'covered_by', 'new_cert_covers'], 'CSV header starts with the CLI columns');
      assert(csv.bom, 'CSV has a BOM (Excel)');
      const lines = csv.text.replace(/^﻿/, '').trim().split(/\r?\n/);
      assertEqual(lines.length, 8, 'header + 7 rows');
      const col = (name) => head.indexOf(name);
      const vpn = csvHeader(lines.find((l) => l.includes(N('vpn'))));
      assertEqual([vpn[col('status')], vpn[col('state')], vpn[col('skip')]], ['', 'skipped', 'private'], 'a skipped row has an empty CLI status');
      const www = csvHeader(lines.find((l) => l.includes(`,${N('www')},`)));
      assertEqual([www[col('status')], www[col('source')]], ['NEEDS_UPDATE', 'globalping'], 'www row');
      const doc = JSON.parse(json.text);
      assertEqual([doc.schema, doc.rows.length], ['domainscope.verify/1', 7], 'verify JSON');
      assert(!/publicKey|rawHeaders|"headers"|-----BEGIN/i.test(json.text), 'no key material or headers in the JSON');
      const full = JSON.parse(scan.text);
      assertEqual([full.verification && full.verification.schema, full.verification && full.verification.rows.length], ['domainscope.verify/1', 7], 'scan JSON carries the verification');
      await dismissToasts(page);
    });

    run.group('Origin opt-in, certificate swap and Check again');
    await run.step('a partial batch after consent: the dialog shows; the DNS rows go first, the origin check waits', async () => {
      await page.evaluate(() => window.__gpNewWindow({ limits: 2, post: 2 }));
      await page.click('.scan-tab-verify [data-vfy="origins"] input');
      await page.waitFor(() => document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]')?.dataset.count === '3', { message: 'Check again (3)' });
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await page.waitFor((d) => document.querySelector(d), { args: [DIALOG], message: 'partial dialog even after consent' });
      const dlg = await page.evaluate((d) => {
        const el = document.querySelector(d);
        const cost = el.querySelector('[data-vfy="confirm-cost"]');
        return {
          checks: cost?.dataset.checks, fit: cost?.dataset.fit, go: el.querySelector('.modal-foot .btn-primary')?.textContent || '',
          privacy: !!el.querySelector('[data-vfy="confirm-privacy"]'), origins: !!el.querySelector('[data-vfy="confirm-origins"]')
        };
      }, DIALOG);
      assertEqual([dlg.checks, dlg.fit, dlg.privacy, dlg.origins], ['3', '2', false, true], `partial preview (${dlg.go})`);
      assert(/Check 2 now/.test(dlg.go), `goPartial label: ${dlg.go}`);
      await page.click(`${DIALOG} .modal-foot .btn-primary`);
      await waitBatch(page, mark, 'partial batch');
      assertEqual(posts(await gpCalls(page, c0)).map(pairOf).sort(), [`1.2.3.4|${N('www')}`, `1.2.3.5|${N('legacy')}`].sort(),
        'exactly the 2 that fit, and they are the DNS rows (servers that need the certificate)');
      const shop = byKey(await readRows(page))[`${N('shop')}|1.2.3.4`];
      assertEqual([shop.state, shop.notRun], ['not-run', 'budget'], 'the origin check waits: not in this batch');
      // Back to a roomy window with the opt-in off, as the next step expects.
      await page.evaluate(() => window.__gpNewWindow({ limits: 250, post: 250 }));
      await page.click('.scan-tab-verify [data-vfy="origins"] input');
      await page.waitFor(() => document.querySelector('.scan-tab-verify [data-vfy="origins"] input')?.checked === false, { message: 'opt-in off' });
    });

    await run.step('ticking the origin opt-in queues the hint pair; Check again (3) runs without a dialog', async () => {
      await page.click('.scan-tab-verify [data-vfy="origins"] input');
      await page.waitFor(() => document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]')?.dataset.count === '3', { message: 'Check again (3)' });
      assert(await page.evaluate(() => document.activeElement?.matches('.scan-tab-verify [data-vfy="origins"] input') === true),
        'keyboard focus stays on the opt-in after the panel re-renders');
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await waitLaunch(page, mark);
      assert(!(await page.evaluate((d) => !!document.querySelector(d), DIALOG)), 'no dialog: consent given and the batch fits');
      await waitBatch(page, mark);
      const sent = posts(await gpCalls(page, c0)).map(pairOf).sort();
      assertEqual(sent, [`1.2.3.4|${N('shop')}`, `1.2.3.4|${N('www')}`, `1.2.3.5|${N('legacy')}`].sort(), '3 POSTs, the hint pair only now');
      const focus = await page.evaluate(() => document.activeElement?.closest('.scan-tab-verify [data-vfy="panel"]') ? document.activeElement.dataset.action || document.activeElement.tagName : null);
      assertEqual(focus, 'vfy-recheck', 'focus comes back to the action button after the batch (not <body>)');
      const said = await page.waitFor(() => [...document.querySelectorAll('.sr-only[aria-live="polite"]')].map((x) => x.textContent).find((x) => /Verification finished/.test(x)) || false,
        { message: 'completion announced' });
      assert(/of 3 servers/.test(said), `announcement: ${said}`);
      const rows = byKey(await readRows(page));
      const shop = rows[`${N('shop')}|1.2.3.4`];
      assertEqual([shop.status, shop.warn, shop.exp], ['UPDATED', ['chain-incomplete'], 'exposed'], 'shop: new cert, intermediate missing, origin exposed');
      assertEqual(await headKeys(page), ['some', 'chain', 'unreachable', 'exposed', 'notHere'], 'headline keys');
      assertEqual(await badge(page), { text: '1/3', warn: true, ok: false }, 'badge');
    });

    await run.step('certificate swapped on the server: Check again (3) → www and shop new, headline "partial" 2 of 3', async () => {
      await page.evaluate(() => window.__gpFlip());
      assertEqual(await recheckCount(page), '3', 'www, shop (chain), legacy');
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await waitBatch(page, mark);
      assertEqual(posts(await gpCalls(page, c0)).length, 3, '3 POSTs');
      const rows = byKey(await readRows(page));
      assertEqual([rows[`${N('www')}|1.2.3.4`].status, rows[`${N('shop')}|1.2.3.4`].status, rows[`${N('shop')}|1.2.3.4`].warn], ['UPDATED', 'UPDATED', []], 'www + shop new, no chain warning');
      const keys = await headKeys(page);
      assertEqual(keys[0], 'partial', `headline ${keys.join(',')}`);
      const text = await page.evaluate(() => document.querySelector('.scan-tab-verify .vfy-headline [data-head="partial"]').textContent);
      assert(/2 of 3/.test(text), `partial text: ${text}`);
      assertEqual((await badge(page)).text, '2/3', 'badge 2/3');
      assertEqual(await recheckCount(page), '1', 'only legacy left');
    });

    run.group('Quota');
    await run.step('/limits reports 0 in this window → quota alert, nothing posted, the last verdict stays', async () => {
      await page.evaluate(() => { window.__gp.limitsRemaining = 0; });
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await waitLaunch(page, mark);
      await page.waitFor(() => document.querySelector('.scan-tab-verify [data-vfy="quota-out"]'), { message: 'quota alert' });
      const calls = await gpCalls(page, c0);
      assertEqual(calls.map((c) => `${c.method} ${c.path}`), ['GET /limits'], 'only the free read');
      const legacy = byKey(await readRows(page))[`${N('legacy')}|1.2.3.5`];
      assertEqual([legacy.state, legacy.status], ['done', 'TIMEOUT'], 'legacy keeps its verdict');
      const info = await page.evaluate(() => ({
        text: document.querySelector('.scan-tab-verify [data-vfy="quota-out"]').textContent,
        credits: document.querySelector('.scan-tab-verify [data-vfy="quota-out"] a[href="https://globalping.io/credits"]')?.getAttribute('rel') || null,
        disabled: document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]')?.disabled
      }));
      assert(/resets in/.test(info.text), `reset time: ${info.text}`);
      assert(info.credits !== null && /noopener/.test(info.credits), 'credits link (external, noopener)');
      assertEqual(info.disabled, false, 'Check again stays usable (each click re-reads /limits for free)');
      await shotEl(page, opts, 'verify-desktop-light-en-quota', '.scan-tab-verify');
    });

    await run.step('new window, 5 left, but the POST gets 429 (shared quota) → not-run · quota, "Last: No answer" kept', async () => {
      await page.evaluate(() => window.__gpNewWindow({ limits: 5, post: 0 }));
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await waitLaunch(page, mark);
      await page.waitFor((sel) => {
        const p = document.querySelector(sel);
        return p && p.dataset.status === 'stopped' && p.dataset.starting === 'false';
      }, { args: [PANEL], message: 'stopped by the quota' });
      const calls = await gpCalls(page, c0);
      assertEqual(calls.filter((c) => c.method === 'POST').length, 1, 'one POST (answered 429)');
      const legacy = byKey(await readRows(page))[`${N('legacy')}|1.2.3.5`];
      assertEqual([legacy.state, legacy.notRun, legacy.last], ['not-run', 'quota', 'TIMEOUT'], 'legacy: not run, last verdict kept');
      assert(await page.evaluate(() => !!document.querySelector('.scan-tab-verify [data-vfy="quota-out"]')), 'quota alert');
      assertEqual((await headKeys(page))[0], 'partial', 'the stale verdict keeps the headline');
      assertEqual(await page.evaluate(() => document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]')?.disabled), false, 'Check again usable');
    });

    run.group('Stop, free re-poll, background completion');
    await run.step('Stop → "Not checked · Stopped"; Check again polls the paid measurement without a new POST', async () => {
      await page.evaluate(() => { window.__gpNewWindow({ limits: 200, post: 200 }); window.__gp.delayMs = 4000; });
      let mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await waitLaunch(page, mark);
      await page.waitFor((from) => window.__gp.calls.slice(from).some((c) => c.method === 'GET' && c.path.startsWith('/measurements/')), { args: [c0], message: 'polling' });
      await page.click('.scan-tab-verify [data-action="vfy-stop"]');
      await waitBatch(page, mark, 'stopped');
      assertEqual((await panelState(page)).status, 'cancelled', 'cancelled');
      assert(await page.evaluate(() => !!document.querySelector('.scan-tab-verify [data-vfy="stopped"]')), 'Stopped note');
      const legacy = byKey(await readRows(page))[`${N('legacy')}|1.2.3.5`];
      assertEqual([legacy.state, legacy.notRun], ['not-run', 'cancelled'], 'legacy not checked · stopped');
      const paid = posts(await gpCalls(page, c0));
      assertEqual(paid.length, 1, 'one paid POST before Stop');
      await page.evaluate(() => { window.__gp.delayMs = 0; });
      mark = await panelState(page);
      const c1 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await waitBatch(page, mark, 're-poll finished');
      const calls = await gpCalls(page, c1);
      assertEqual(posts(calls).length, 0, 'no new POST');
      assert(calls.some((c) => c.method === 'GET' && c.path.startsWith('/measurements/')), 'the paid id was polled');
      const after = byKey(await readRows(page))[`${N('legacy')}|1.2.3.5`];
      assertEqual([after.state, after.status], ['done', 'TIMEOUT'], 'legacy verdict from the paid measurement');
    });

    await run.step('a batch that ends while DNS Lookup is open shows a toast; "Show results" lands on the Verify tab', async () => {
      await page.evaluate(() => { window.__gp.delayMs = 2500; });
      const mark = await panelState(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await waitLaunch(page, mark);
      await gotoRoute(page, 'lookup');
      const toastText = await page.waitFor(() => {
        const tst = [...document.querySelectorAll('.toast')].find((x) => /Verification finished/.test(x.textContent));
        return tst ? tst.textContent : false;
      }, { timeout: 15000, message: 'completion toast' });
      assert(/2 of 3 servers/.test(toastText), `toast: ${toastText}`);
      await page.evaluate(() => [...document.querySelectorAll('.toast')].find((x) => /Verification finished/.test(x.textContent)).querySelector('.btn').click());
      await page.waitFor(() => document.documentElement.dataset.view === 'scan'
        && document.querySelector('.scan-tabs .tab[data-tab="verify"]')?.getAttribute('aria-selected') === 'true'
        && document.querySelector('.scan-tab-verify [data-vfy="panel"]'), { message: 'back on Verify' });
      const rows = await readRows(page);
      assert(rows.every((r) => r.state !== 'running' && r.state !== 'pending'), 'every row final');
      assertEqual(await runId(page), run1, 'same scan run');
      await page.evaluate(() => { window.__gp.delayMs = 0; });
      await dismissToasts(page);
    });

    await run.step('consent is never stored', async () => {
      const keys = await page.evaluate(() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)]);
      assertEqual(keys.filter((k) => /consent|globalping|verify|gp\b/i.test(k)), [], `storage keys: ${keys.join(', ')}`);
    });

    run.group('A click while the quota read is pending');
    await run.step('while /limits is pending the origin opt-in is frozen; the batch sends what was clicked', async () => {
      await page.evaluate(() => { window.__gp.limitsDelayMs = 1200; });
      const count = await recheckCount(page);
      assert(count !== null, 'a Check again button');
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.starting === 'true', { args: [PANEL], message: 'starting' });
      const frozen = await page.evaluate(() => ({
        origins: document.querySelector('.scan-tab-verify [data-vfy="origins"] input')?.disabled ?? null,
        busy: document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]')?.getAttribute('aria-busy') ?? null
      }));
      assertEqual(frozen, { origins: true, busy: 'true' }, 'opt-in disabled and the button busy during the quota read');
      await waitBatch(page, mark, 'batch after a slow /limits');
      assertEqual(posts(await gpCalls(page, c0)).length, Number(count), 'the clicked rows, no more');
      assertEqual(await page.evaluate(() => document.querySelector('.scan-tab-verify [data-vfy="origins"] input')?.disabled), false, 'usable again');
      await page.evaluate(() => { window.__gp.limitsDelayMs = 0; });
    });

    await run.step('switching language while /limits is pending drops the launch: nothing sent, the re-mounted button is usable', async () => {
      await page.evaluate(() => { window.__gp.limitsDelayMs = 2500; });
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.starting === 'true', { args: [PANEL], message: 'starting' });
      await setLangUi(page, 'tr');
      await page.waitFor((sel) => {
        const p = document.querySelector(sel);
        return p && p.dataset.starting === 'false' && document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]');
      }, { args: [PANEL], timeout: 8000, message: 're-mounted panel settles' });
      await sleep(2800); // past the slow quota read: the dropped launch must not come back
      const after = await page.evaluate((d) => ({
        dialog: !!document.querySelector(d),
        starting: document.querySelector('.scan-tab-verify [data-vfy="panel"]')?.dataset.starting,
        disabled: document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]')?.disabled,
        busy: document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]')?.classList.contains('is-busy')
      }), DIALOG);
      assertEqual(after, { dialog: false, starting: 'false', disabled: false, busy: false }, 'no dialog; Check again usable');
      const calls = await gpCalls(page, c0);
      assertEqual(posts(calls).length, 0, 'nothing sent');
      assert(calls.every((c) => c.method === 'GET' && c.path === '/limits'), `only the free read: ${calls.map((c) => `${c.method} ${c.path}`).join(', ')}`);
      await page.evaluate(() => { window.__gp.limitsDelayMs = 0; });
      await setLangUi(page, 'en');
      await page.waitFor(() => document.querySelector('.scan-tab-verify .vfy-table tbody tr.dt-row'), { message: 'verify table (EN)' });
    });

    run.group('Languages, themes, phone');
    await run.step('Turkish: the panel re-renders from the job, no raw keys or placeholders', async () => {
      await setLangUi(page, 'tr');
      await page.waitFor(() => document.querySelector('.scan-tab-verify .vfy-table tbody tr.dt-row'), { message: 'verify table after re-mount' });
      const tr = await page.evaluate(() => ({
        tab: document.querySelector('.scan-tabs .tab[data-tab="verify"]')?.textContent || '',
        selected: document.querySelector('.scan-tabs .tab.is-selected')?.dataset.tab,
        text: document.querySelector('.scan-tab-verify')?.innerText || ''
      }));
      assert(/Doğrula/.test(tr.tab), `tab label: ${tr.tab}`);
      assertEqual(tr.selected, 'verify', 'the Verify tab stays selected');
      assert(/Yeni sertifika/.test(tr.text), 'status text in Turkish');
      assertEqual(tr.text.match(/\bvfy\.[\w.-]+|\{[a-zA-Z]+\}/g) || [], [], 'raw keys or placeholders');
      await assertNoMissingKeys(page);
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await sleep(150);
      await assertNoHorizontalScroll(page, 'desktop dark TR');
      await shotEl(page, opts, 'verify-desktop-dark-tr', '.scan-tab-verify');
    });

    await run.step('phone 390×844: TR dark and EN light fit without horizontal scroll', async () => {
      await page.setViewport({ width: 390, height: 844, mobile: true });
      await sleep(300);
      await assertNoHorizontalScroll(page, 'phone dark TR');
      assertEqual(await overflowingIn(page, '.scan-tab-verify'), [], 'Verify panel inside 390 px (TR dark)');
      await shotEl(page, opts, 'verify-phone-dark-tr', '.scan-tab-verify');
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.waitFor(() => document.querySelector('.scan-tab-verify .vfy-table tbody tr.dt-row'), { message: 'verify table (EN)' });
      await sleep(200);
      await assertNoHorizontalScroll(page, 'phone light EN');
      assertEqual(await overflowingIn(page, '.scan-tab-verify'), [], 'Verify panel inside 390 px (EN light)');
      await shotEl(page, opts, 'verify-phone-light-en', '.scan-tab-verify');
      await page.setViewport({ width: 1440, height: 900 });
      await sleep(200);
    });

    run.group('A new scan, an outage, consent reset, no certificate');
    await run.step('a new scan cancels the running verification; the new run starts idle on Hosts', async () => {
      await page.evaluate(() => { window.__gp.delayMs = 6000; });
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await waitLaunch(page, mark);
      await page.waitFor((from) => window.__gp.calls.slice(from).some((c) => c.method === 'GET' && c.path.startsWith('/measurements/')), { args: [c0], message: 'polling' });
      const oldId = await page.evaluate(() => Object.keys(window.__gp.measurements).pop());
      assertEqual(posts(await gpCalls(page, c0)).length, 1, 'one POST (legacy)');
      const run2 = await runScan(page);
      assert(run2 && run2 !== run1, 'a new run');
      const settled = (await page.evaluate((id) => window.__gp.gets[id] || [], oldId)).length;
      await sleep(2500);
      assertEqual((await page.evaluate((id) => window.__gp.gets[id] || [], oldId)).length, settled, 'the old measurement is no longer polled');
      assertEqual(await page.evaluate(() => document.querySelector('.scan-tabs .tab.is-selected')?.dataset.tab), 'hosts', 'a new scan opens on Hosts');
      await openTab(page, 'verify');
      const fresh = await page.evaluate(() => ({
        status: document.querySelector('.scan-tab-verify [data-vfy="panel"]')?.dataset.status,
        start: !!document.querySelector('.scan-tab-verify [data-action="vfy-start"]'),
        pending: document.querySelectorAll('.scan-tab-verify [data-vfy-state="pending"]').length
      }));
      assertEqual(fresh, { status: 'idle', start: true, pending: 4 }, 'fresh, idle verification');
      assertEqual(await badge(page), null, 'no badge yet');
      await page.evaluate(() => { window.__gp.delayMs = 0; });
    });

    await run.step('a new scan while /limits is pending drops the old launch: no dialog, nothing sent for the old run', async () => {
      await page.evaluate(() => { window.__gp.limitsDelayMs = 2500; });
      const before = await runId(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-start"]');
      await page.waitFor((sel) => document.querySelector(sel)?.dataset.starting === 'true', { args: [PANEL], message: 'starting' });
      const next = await runScan(page);
      assert(next && next !== before, 'a new run');
      await sleep(2800); // past the slow quota read
      assert(!(await page.evaluate((d) => !!document.querySelector(d), DIALOG)), 'no dialog for the old scan');
      const calls = await gpCalls(page, c0);
      assertEqual(posts(calls).length, 0, 'nothing sent for the old run');
      await page.evaluate(() => { window.__gp.limitsDelayMs = 0; });
      await openTab(page, 'verify');
      const fresh = await page.evaluate(() => ({
        status: document.querySelector('.scan-tab-verify [data-vfy="panel"]')?.dataset.status,
        starting: document.querySelector('.scan-tab-verify [data-vfy="panel"]')?.dataset.starting,
        start: document.querySelector('.scan-tab-verify [data-action="vfy-start"]')?.disabled
      }));
      assertEqual(fresh, { status: 'idle', starting: 'false', start: false }, 'the new run starts idle and usable');
    });

    await run.step('Globalping unreachable → ErrorBanner with Retry; Retry succeeds (consent kept: no dialog)', async () => {
      await page.evaluate(() => { window.__gp.netDown = true; });
      const mark = await panelState(page);
      await page.click('.scan-tab-verify [data-action="vfy-start"]');
      await waitLaunch(page, mark);
      assert(!(await page.evaluate((d) => !!document.querySelector(d), DIALOG)), 'no dialog in the same page session');
      await waitBatch(page, mark, 'unreachable');
      await page.waitFor(() => document.querySelector('.scan-tab-verify [data-vfy="unreachable"]'), { message: 'error banner' });
      // Up to 4 checks were in flight when the third network error stopped the queue: each ends
      // as a network error, or "Not checked · Globalping unreachable" when it was still queued.
      const rows = (await readRows(page)).filter((r) => r.state !== 'skipped' && r.notRun !== 'optional');
      assertEqual(rows.length, 4, 'the 4 targeted rows');
      assert(rows.filter((r) => r.state === 'error' && r.error === 'network').length >= 3, 'at least 3 network errors');
      assert(rows.every((r) => (r.state === 'error' && r.error === 'network') || (r.state === 'not-run' && r.notRun === 'unreachable')), `row states: ${rows.map((r) => `${r.state}:${r.error || r.notRun}`).join(', ')}`);
      await shotEl(page, opts, 'verify-desktop-light-en-unreachable', '.scan-tab-verify');
      await page.evaluate(() => { window.__gp.netDown = false; });
      const mark2 = await panelState(page);
      await page.click('.scan-tab-verify [data-vfy="unreachable"] .btn');
      await waitBatch(page, mark2, 'retry');
      assert(!(await page.evaluate(() => !!document.querySelector('.scan-tab-verify [data-vfy="unreachable"]'))), 'banner gone');
      const after = byKey(await readRows(page));
      assertEqual([after[`${WILD}|1.2.3.4`].status, after[`${N('www')}|1.2.3.4`].status, after[`${N('legacy')}|1.2.3.5`].status],
        ['UPDATED', 'UPDATED', 'TIMEOUT'], 'verdicts after Retry');
    });

    await run.step('"Delete all local data" resets consent: the next click asks again (Cancel → nothing sent)', async () => {
      await gotoRoute(page, 'about');
      await page.click('[data-action="clear-data"]');
      try {
        await page.waitFor(() => !!document.querySelector('dialog.modal[open] .btn-danger'), { message: 'confirmation' });
        await page.click('dialog.modal[open] .btn-danger');
        await page.waitFor(() => !document.querySelector('dialog.modal[open]'), { message: 'dialog closed' });
      } finally {
        await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
      }
      // The dialog's 'close' event (and so the wipe) lands a task after [open] goes away: wait for
      // the wipe itself, or it can erase the options seeded below on a busy machine.
      await page.waitFor(() => localStorage.getItem('ssds.inventory') === null, { message: 'local data wiped' });
      await dismissToasts(page);
      await seedOptions(page); // the wipe restored every passive source: keep the suite offline
      await gotoRoute(page, 'scan');
      await page.waitFor(() => document.querySelector('.scan-tabs .tab[data-tab="verify"]'), { message: 'results restored' });
      await openTab(page, 'verify');
      await page.waitFor(() => document.querySelector('.scan-tab-verify [data-action="vfy-recheck"]'), { message: 'Verify tab restored' });
      const mark = await panelState(page);
      const c0 = await gpCount(page);
      await page.click('.scan-tab-verify [data-action="vfy-recheck"]');
      await page.waitFor((d) => document.querySelector(d), { args: [DIALOG], message: 'consent dialog again' });
      assert(await page.evaluate((d) => !!document.querySelector(`${d} [data-vfy="confirm-privacy"]`), DIALOG), 'privacy text again');
      await page.click(`${DIALOG} .modal-foot .btn:not(.btn-primary)`);
      await waitLaunch(page, mark);
      assertEqual(posts(await gpCalls(page, c0)).length, 0, 'nothing sent');
    });

    await run.step('without a certificate there is no Verify tab, hint or summary line', async () => {
      if (await page.evaluate(() => !!document.querySelector('[data-action="cert-remove"]'))) {
        await page.click('[data-action="cert-remove"]');
        await page.waitFor(() => !document.querySelector('.scan-step-cert .cert-summary'), { message: 'certificate removed' });
      }
      await runScan(page);
      const info = await page.evaluate(() => ({
        tabs: [...document.querySelectorAll('.scan-tabs .tab[data-tab]')].map((b) => b.dataset.tab),
        hint: !!document.querySelector('[data-action="scan-open-verify"]'),
        summary: !!document.querySelector('[data-summary="verify"]')
      }));
      assertEqual(info, { tabs: ['hosts', 'servers', 'cdn', 'sources', 'ct'], hint: false, summary: false }, 'no Verify');
    });

    run.group('Quality');
    await run.step('nothing left the page: no real Globalping request, no external fetch; totals', async () => {
      const calls = await gpCalls(page);
      const ext = await page.evaluate(() => window.__externalFetches.slice());
      assertEqual(netHits, [], 'https requests that reached the network');
      assertEqual(ext, [], 'external fetches blocked in the page');
      const sent = JSON.stringify(calls.map((c) => c.body));
      for (const ip of NEVER_SENT) assert(!sent.includes(ip), `${ip} never sent`);
      process.stdout.write(`        fake Globalping: ${posts(calls).length} POSTs, ${limitsReads(calls).length} /limits, ${calls.filter((c) => c.path.startsWith('/measurements/')).length} GETs; real probes: 0\n`);
    });
    await run.step('i18n: no missing keys, TR and EN key sets match', async () => {
      await assertNoMissingKeys(page);
    });
    await run.step('no console errors, exceptions or CSP violations', async () => {
      await assertClean(page, 'verify', origin);
    });
  } finally {
    if (page) await page.close().catch(() => {});
    await browser.close();
    await server.close();
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
