#!/usr/bin/env node
/**
 * zone.e2e.mjs — end-to-end test of the "Zone File" view in a real headless Chrome/Edge.
 * OFFLINE: every DoH query is answered in the page by a fake resolver built from the fixture
 * (window.fetch wrapped before the app loads; no pass-through), every other https:// request is
 * blocked, and every request that leaves the page's origin is counted through CDP.
 *
 *   node tests/e2e/zone.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry, the empty state, the import of the Cloudflare export (format, origin,
 * counts), the Records filters, the proxied-origin map with the inventory (also servers added
 * or renamed after the import), the exact sweep
 * command (no /24, host target, wildcard name, PowerShell), the zone-targets.txt download, the
 * Problems → Records jump, Copy summary (counts, the worst problems, a bare #/zone link), the live check (nothing sent before the click, planned query count,
 * hidden targets / internal names never queried, statuses, redacted export, cancel, kept for the
 * page session with "Live check from" and Run again; the note gone with the Live tab's own Run,
 * a new import and Forget), the exact-mode hand-off contract, Route 53 (incomplete export) and
 * cPanel imports ("Show the fix" of the cPanel localhost record: exact BIND and Route 53), a certificate
 * pasted by mistake, two API pages, an $INCLUDE part dropped before its main file, Compare (the
 * Cloudflare sample against the Route 53 sample: the rows lib/zonediff.js finds, the options from
 * the keyboard, redacted CSV / JSON, Copy summary without values, "Forget the second zone", Forget
 * clearing both) and Convert (every format as lib/zoneconvert.js writes it, its notes, each download
 * read back, Copy all), at 320 / 375 px in TR / EN and light / dark, Forget,
 * "Delete all local data", nothing persisted, TR/EN, light/dark, 390 px, zero console errors /
 * CSP violations / missing i18n keys.
 *
 * Fixtures are documentation data only (example.com, 192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32,
 * the fake Cloudflare edge 104.16.1.1).
 */

import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, sleep, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';

const ZONES = path.join(FIXTURES, 'zones');
const CF_FILE = path.join(ZONES, 'cloudflare-export.txt');
const CF_EDGE_V4 = '104.16.1.1';
const CF_EDGE_V6 = '2606:4700::6810:101';

/**
 * The fake live zone: the fixture's own records (dnswire data shape), with every proxied name
 * answering the Cloudflare edge, except www which answers its origin (proxy switched off live →
 * origin-exposed), and a newer SOA serial.
 */
async function fakeTable() {
  const P = await import('../../assets/js/lib/zoneparse.js');
  const z = P.parseZone(await readFile(CF_FILE, 'utf8'), { filename: 'example.com.txt' });
  const table = {};
  const proxied = new Set();
  for (const r of z.records) {
    if (r.data === null || r.data === undefined || r.duplicateOf !== undefined) continue;
    if (r.name.endsWith('.dev.example.com')) continue; // below the delegation: served by the child zone
    const node = table[r.name] || (table[r.name] = {});
    (node[r.type] || (node[r.type] = [])).push(r.data);
    if (r.proxied === true) proxied.add(r.name);
  }
  for (const name of proxied) {
    const node = table[name];
    delete node.CNAME;
    node.A = [CF_EDGE_V4];
    if (name === 'www.example.com' || node.AAAA) node.AAAA = [CF_EDGE_V6];
  }
  table['www.example.com'].A = ['192.0.2.10'];
  const soa = table['example.com'].SOA[0];
  table['example.com'].SOA = [{ ...soa, serial: Number(soa.serial) + 1 }];
  return table;
}

/** The page header's kept-result note: its text ('' when none shows) and whether it offers Run again. */
const keptNote = (page) => page.evaluate(() => ({
  text: document.querySelector('.page-kept:not([hidden]) .kept-note-text')?.textContent || '',
  rerun: !!document.querySelector('.page-kept:not([hidden]) [data-action="kept-rerun"]'),
  hash: location.hash
}));

/** Leave the Zone File for About and come back (the shell keeps the finished live check). */
async function leaveAndReturn(page) {
  await gotoRoute(page, 'about');
  await gotoRoute(page, 'zone');
}

/** In-page DoH stub: answers EVERY DoH query from the table (NXDOMAIN outside it), logs it. */
const fakeDnsScript = (table) => `(() => {
  const T = ${JSON.stringify(table)};
  const APEX = 'example.com';
  const SOA = T[APEX].SOA[0];
  window.__fakeDnsLog = [];
  window.__fakeDnsDelay = 0;
  const hasBelow = (name) => Object.keys(T).some((k) => k.endsWith('.' + name));
  const nodeOf = (name) => {
    if (T[name]) return T[name];
    const parent = name.split('.').slice(1).join('.');
    if (T['*.' + parent] && !hasBelow(name)) return T['*.' + parent];
    return null;
  };
  const answer = (qname, type) => {
    const answers = [];
    let name = qname;
    for (let hop = 0; hop < 8; hop += 1) {
      const node = nodeOf(name);
      if (!node) return { rcode: hop || hasBelow(name) ? 'NOERROR' : 'NXDOMAIN', answers };
      if (node[type]) {
        for (const data of node[type]) answers.push({ name, type, ttl: 300, data });
        return { rcode: 'NOERROR', answers };
      }
      if (node.CNAME && type !== 'CNAME') {
        const target = String(node.CNAME[0]).replace(/[.]$/, '');
        answers.push({ name, type: 'CNAME', ttl: 300, data: target });
        if (target !== APEX && !target.endsWith('.' + APEX)) return { rcode: 'NOERROR', answers };
        name = target;
        continue;
      }
      return { rcode: 'NOERROR', answers };
    }
    return { rcode: 'NOERROR', answers };
  };
  let wire = null;
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__fakeDnsLog.push({ name, type: q.type });
    if (window.__fakeDnsDelay) await new Promise((r) => setTimeout(r, window.__fakeDnsDelay));
    const out = (name === APEX || name.endsWith('.' + APEX)) ? answer(name, q.type) : { rcode: 'NXDOMAIN', answers: [] };
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers,
      authorities: out.answers.length ? [] : [{ name: APEX, type: 'SOA', ttl: 300, data: SOA }], edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/** The new provider's name servers of the parity steps (documentation names). */
const NEW_NS = ['ns1.example.net', 'ns2.example.net'];

/**
 * The NEW provider's zone for the "New name servers" tab: the fixture's records as presentation
 * text (a provider that does not proxy: every proxied record answers its origin, a flattened CNAME
 * is a plain CNAME), except mail A (missing), the MX set (another mail host), the tunnel (a
 * Cloudflare Tunnel cannot move: missing) and vpn A (TTL 3600, the file says 300); its own NS
 * records; the dev delegation answered by referral.
 */
async function newProviderTable() {
  const P = await import('../../assets/js/lib/zoneparse.js');
  const z = P.parseZone(await readFile(CF_FILE, 'utf8'), { filename: 'example.com.txt' });
  const records = {};
  for (const r of z.records) {
    if (r.data === null || r.data === undefined || r.duplicateOf !== undefined || r.type === 'SOA') continue;
    if (r.name === 'dev.example.com' && r.type === 'NS') continue;
    if (r.name.endsWith('.dev.example.com') || (r.name === 'example.com' && r.type === 'NS')) continue;
    (records[`${r.name}|${r.type}`] ||= []).push([r.ttlAuto ? 300 : r.ttl, r.text]);
  }
  records['example.com|NS'] = NEW_NS.map((n) => [86400, `${n}.`]);
  records['example.com|MX'] = [[300, '10 mx.example.net.']];
  delete records['mail.example.com|A'];
  delete records['tunnel.example.com|CNAME'];
  records['vpn.example.com|A'] = [[3600, '203.0.113.5']];
  return { records, cuts: { 'dev.example.com': ['ns-1.example-dns.net.', 'ns-2.example-dns.net.'] } };
}

/**
 * In-page fake Globalping for DNS measurements: each new name server answers from `table` as an
 * authoritative server would (the dig flags line with aa, CNAME chains inside the zone, a
 * wildcard, NXDOMAIN, a referral for the delegation). Every call is logged in window.__gp.
 * `window.__gp.allowUpTo`: measurements numbered above it stay in progress (a test holds a run
 * part way, then lets it go on); `window.__gp.quotaAfter`: a POST past that many measurements gets
 * the quota 429 (rate_limit_exceeded) and creates nothing, its window ending `quotaResetS` seconds
 * later (`quotaResetAt`: when).
 */
const fakeGlobalpingScript = (table, servers) => `(() => {
  const T = ${JSON.stringify(table)};
  const SERVERS = ${JSON.stringify(servers)};
  const gp = window.__gp = { calls: [], remaining: 250, n: 0, measurements: {}, allowUpTo: Infinity, quotaAfter: Infinity, quotaResetS: 3600, quotaResetAt: 0 };
  const prevFetch = window.fetch;
  const json = (v, status = 200, headers = {}) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json', ...headers } });
  const probe = { continent: 'EU', region: 'Western Europe', country: 'DE', city: 'Frankfurt', asn: 24940, network: 'Hetzner Online', tags: ['datacenter-network'] };
  const owners = new Set(Object.keys(T.records).map((k) => k.split('|')[0]));
  const nodeOf = (name) => {
    if (owners.has(name)) return name;
    const wild = '*.' + name.split('.').slice(1).join('.');
    return owners.has(wild) ? wild : null;
  };
  function answer(ns, name, type) {
    const serial = SERVERS[ns];
    const done = (rcode, answers, raw = ';; flags: qr aa rd; QUERY: 1, ANSWER: ' + answers.length + '\\n') => ({
      status: 'finished', statusCodeName: rcode, statusCode: { NOERROR: 0, NXDOMAIN: 3, REFUSED: 5 }[rcode], rawOutput: raw, answers, timings: { total: 4 }, resolver: ns
    });
    if (serial === undefined) return { status: 'failed', rawOutput: "dig: couldn't get address for '" + ns + "': not found" };
    if (serial === null) return done('REFUSED', [], ';; flags: qr rd; QUERY: 1, ANSWER: 0\\n');
    if (type === 'SOA' && name === 'example.com') return done('NOERROR', [{ name: 'example.com.', type: 'SOA', ttl: 3600, class: 'IN', value: 'ns1.example.net. hostmaster.example.com. ' + serial + ' 7200 900 1209600 300' }]);
    const cut = Object.keys(T.cuts).find((c) => name === c || name.endsWith('.' + c));
    if (cut && type !== 'DS') {
      const raw = ';; flags: qr rd; QUERY: 1, ANSWER: 0\\n\\n;; AUTHORITY SECTION:\\n' + T.cuts[cut].map((t) => cut + '.\\t\\t3600\\tIN\\tNS\\t' + t).join('\\n') + '\\n\\n';
      return done('NOERROR', [], raw);
    }
    const answers = [];
    let cur = name;
    for (let hop = 0; hop < 6; hop += 1) {
      const node = nodeOf(cur);
      if (!node) return done(hop ? 'NOERROR' : (Object.keys(T.records).some((k) => k.split('|')[0].endsWith('.' + cur)) ? 'NOERROR' : 'NXDOMAIN'), answers);
      const own = T.records[node + '|' + type];
      if (own) {
        for (const [ttl, value] of own) answers.push({ name: cur + '.', type, ttl, class: 'IN', value });
        return done('NOERROR', answers);
      }
      const cname = type !== 'CNAME' && T.records[node + '|CNAME'];
      if (!cname) return done('NOERROR', answers);
      answers.push({ name: cur + '.', type: 'CNAME', ttl: cname[0][0], class: 'IN', value: cname[0][1] });
      cur = cname[0][1].replace(/[.]$/, '');
      if (cur !== 'example.com' && !cur.endsWith('.example.com')) return done('NOERROR', answers);
    }
    return done('NOERROR', answers);
  }
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!url.startsWith('https://api.globalping.io/')) return prevFetch(input, init);
    const p = url.slice('https://api.globalping.io/v1'.length);
    const method = String((init && init.method) || 'GET').toUpperCase();
    let body = null;
    try { body = init && typeof init.body === 'string' ? JSON.parse(init.body) : null; } catch { body = null; }
    gp.calls.push({ method, path: p, body });
    if (p === '/limits') return json({ rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: gp.remaining, reset: 0 } } } });
    if (p === '/measurements' && method === 'POST') {
      if (gp.n >= gp.quotaAfter) {
        gp.quotaResetAt = Date.now() + gp.quotaResetS * 1000;
        return json({ error: { type: 'rate_limit_exceeded', message: 'API rate limit exceeded.' } }, 429, { 'x-ratelimit-limit': '250', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(gp.quotaResetS) });
      }
      gp.remaining -= 1;
      gp.n += 1;
      const id = 'fakeParity' + String(gp.n).padStart(6, '0');
      gp.measurements[id] = { id, body, n: gp.n };
      return json({ id, probesCount: 1 }, 202, { 'x-ratelimit-limit': '250', 'x-ratelimit-remaining': String(gp.remaining), 'x-ratelimit-reset': '3600', 'x-request-cost': '1' });
    }
    const m = /^\\/measurements\\/([A-Za-z0-9]+)$/.exec(p);
    if (m && gp.measurements[m[1]]) {
      const { id, body: b, n } = gp.measurements[m[1]];
      if (n > gp.allowUpTo) return json({ id, type: 'dns', status: 'in-progress', target: b.target, probesCount: 1, results: [] });
      const result = answer(b.measurementOptions.resolver, b.target, b.measurementOptions.query.type);
      return json({ id, type: 'dns', status: 'finished', target: b.target, probesCount: 1, results: [{ probe, result }] });
    }
    return json({ error: { type: 'not_found', message: 'Not Found.' } }, 404);
  };
})();`;

/** A made-up API token, built from pieces (no file holds anything token-shaped). */
const FETCH_TOKEN = ['e2e', 'made', 'up', 'token', '42'].join('-');

/**
 * The two DNS provider APIs of Zone File › Fetch, answered inside the page (installed before the app,
 * so the egress meter counts the requests as it would real ones): deSEC from the fixture listing
 * (`paged`: over 500 RRsets, read by type; `throttle-once`: one 429), DigitalOcean from the two
 * fixture pages (`forbidden`: a token without domain:read). Only the fixture token is accepted; every
 * request is logged with what it carried — whether the token was in the header, never its value.
 */
const fakeProviderScript = (desec, doPages, token) => `(() => {
  const DESEC = ${JSON.stringify(desec)};
  const DO = ${JSON.stringify(doPages)};
  const TOKEN = ${JSON.stringify(token)};
  const P = window.__prov = { calls: [], mode: { desec: 'ok', digitalocean: 'ok' }, delayMs: 0, throttled: false };
  const prevFetch = window.fetch;
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const isDesec = url.startsWith('https://desec.io/');
    if (!isDesec && !url.startsWith('https://api.digitalocean.com/')) return prevFetch(input, init);
    const headers = init.headers || {};
    const auth = String(headers.authorization || headers.Authorization || '');
    P.calls.push({
      url, scheme: auth.split(' ')[0], tokenOk: auth === (isDesec ? 'Token ' : 'Bearer ') + TOKEN, tokenInUrl: url.includes(TOKEN),
      credentials: init.credentials, redirect: init.redirect, referrerPolicy: init.referrerPolicy
    });
    if (P.delayMs) await new Promise((r) => setTimeout(r, P.delayMs));
    const u = new URL(url);
    if (isDesec) {
      if (auth !== 'Token ' + TOKEN) return json({ detail: 'Invalid token.' }, 401);
      const m = /^\\/api\\/v1\\/domains\\/([^/]+)\\/rrsets\\/$/.exec(u.pathname);
      if (!m || m[1] !== 'example.com') return json({ detail: 'Not found.' }, 404);
      if (P.mode.desec === 'throttle-once' && !P.throttled) {
        P.throttled = true;
        return json({ detail: 'Request was throttled. Expected available in 1 second.' }, 429);
      }
      const type = u.searchParams.get('type');
      if (type) return json(DESEC.filter((s) => s.type === type));
      if (P.mode.desec === 'paged') {
        return json({ detail: 'Pagination required. You can query up to 500 items at a time (' + DESEC.length + ' total). Please use the \`first\` page link (see Link header).' }, 400);
      }
      return json(DESEC);
    }
    if (auth !== 'Bearer ' + TOKEN) return json({ id: 'Unauthorized', message: 'Unable to authenticate you' }, 401);
    if (P.mode.digitalocean === 'forbidden') return json({ id: 'forbidden', message: 'You do not have permission to perform this action.' }, 403);
    if (u.pathname !== '/v2/domains/example.com/records') return json({ id: 'not_found', message: 'The resource you requested could not be found.' }, 404);
    return json(DO[Number(u.searchParams.get('page') || 1) - 1] || { domain_records: [], links: {}, meta: { total: 0 } });
  };
})();`;

/** Open the importer (folded under "Replace" while a zone is loaded) and its fetch panel. */
const openFetch = (page) => page.evaluate(() => {
  const folded = document.querySelector('.zone-import-folded');
  if (folded) folded.open = true;
  const panel = document.querySelector('.zone-fetch');
  if (!panel) throw new Error('no fetch panel');
  panel.open = true;
});

/** Everything this page keeps where the token must never be: storage, the DOM, every IndexedDB store. */
const keptAnywhere = (page) => page.evaluate(async () => {
  const parts = [document.documentElement.outerHTML, location.href];
  for (const st of [localStorage, sessionStorage]) for (let i = 0; i < st.length; i += 1) parts.push(st.key(i), st.getItem(st.key(i)));
  const state = (await import('./assets/js/state.js')).state;
  parts.push(JSON.stringify(state.getSession('zone') ?? null));
  for (const info of (indexedDB.databases ? await indexedDB.databases() : [])) {
    const db = await new Promise((res, rej) => { const r = indexedDB.open(info.name); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    for (const name of db.objectStoreNames) {
      const all = await new Promise((res) => { const r = db.transaction(name).objectStore(name).getAll(); r.onsuccess = () => res(r.result); r.onerror = () => res([]); });
      parts.push(JSON.stringify(all));
    }
    db.close();
  }
  return parts.join('\n');
});

async function nodeChecks(run) {
  const V = await import('../../assets/js/views/zone.js');
  const O = await import('../../assets/js/lib/zoneorigins.js');
  run.group('Node: views/zone.js helpers');
  await run.step('the Cloudflare fixture: exact sweep command, no /24', async () => {
    const z = V.parseFiles([{ name: 'example.com.txt', text: await readFile(CF_FILE, 'utf8') }]);
    const cmd = V.sweepCommand(O.zoneSweep(z, { scope: 'proxied', shell: 'posix' }));
    assert(cmd.command.includes(' origin-lb.example.net ') && cmd.command.includes("'*.apps.example.com'"), cmd.command);
    assert(!/\/2[0-9]\b/.test(cmd.command), 'no CIDR');
  });
}

const count = (page, sel) => page.evaluate((s) => document.querySelectorAll(s).length, sel);
const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent || '', sel);
const clickTab = async (page, tab) => {
  await page.click(`.zone-tabs .tab[data-tab="${tab}"]`);
  await page.waitFor((t) => !document.querySelector(`.zone-tabs .tabpanel[data-tab="${t}"]`)?.hidden
    && document.querySelector(`.zone-tabs .tabpanel[data-tab="${t}"]`).childElementCount > 0, { args: [tab], message: `tab ${tab}` });
};
const jsClick = (page, sel) => page.evaluate((s) => { const el = document.querySelector(s); if (!el) throw new Error(`no ${s}`); el.click(); }, sel);
const noZoneStorage = (page) => page.evaluate(() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)].filter((k) => /zone/i.test(k)));

async function main() {
  const opts = cliOptions();
  const run = createRunner();
  await nodeChecks(run);
  const table = await fakeTable();

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
    await browser.conn.send('Browser.grantPermissions', { origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] }).catch(() => {});
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeDnsScript(table) });
    // ns1 / ns2 serve the new zone (the same serial), ns9 refuses it, any other name does not resolve.
    await page.send('Page.addScriptToEvaluateOnNewDocument', {
      source: fakeGlobalpingScript(await newProviderTable(), { [NEW_NS[0]]: 2026092801, [NEW_NS[1]]: 2026092801, 'ns9.example.org': null })
    });
    // deSEC and DigitalOcean for Fetch, from the fixture listings.
    const doPages = [JSON.parse(await readFile(path.join(ZONES, 'digitalocean-api-page1.json'), 'utf8')),
      JSON.parse(await readFile(path.join(ZONES, 'digitalocean-api-page2.json'), 'utf8'))];
    await page.send('Page.addScriptToEvaluateOnNewDocument', {
      source: fakeProviderScript(JSON.parse(await readFile(path.join(ZONES, 'desec-api.json'), 'utf8')), doPages, FETCH_TOKEN)
    });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/zone: nav entry, empty state, nothing sent', async () => {
      await page.goto(`${server.url}#/zone`);
      await waitReady(page);
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.setInventory('web01 192.0.2.10').done);
      await page.reload();
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'zone');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/subdomains"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '')) : [];
      });
      assertEqual(nav.slice(0, 3), ['subdomains', 'domain', 'zone'], 'Zone File in Discover, after Subdomains and Domain overview');
      assert(/Zone File/.test(await text(page, 'h1')), 'title');
      const ui = await page.evaluate(() => ({
        drop: !!document.querySelector('.zone-drop'),
        origin: !!document.querySelector('[data-role="zone-origin"]'),
        samples: document.querySelectorAll('[data-sample]').length,
        howto: !!document.querySelector('.zone-howto'),
        paste: !!document.querySelector('.zone-paste'),
        privacy: /never|nothing is uploaded/i.test(document.querySelector('#page-body .alert')?.textContent || '')
      }));
      assertEqual(ui, { drop: true, origin: true, samples: 3, howto: true, paste: true, privacy: true }, 'empty state');
      assertEqual(await page.evaluate(() => window.__fakeDnsLog.length), 0, 'no DNS query');
      assertEqual(external, [], 'no external request');
      await shot(page, opts, 'zone-empty-desktop-light-en');
    });

    await run.step('import the Cloudflare export: format, origin, counts, focus; still nothing sent', async () => {
      await page.setFileInput('.zone-drop .filedrop-input', [CF_FILE]);
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'summary' });
      assertEqual(await text(page, '.zone-format-badge'), 'Cloudflare export (BIND)', 'format');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="zone-origin"]').value), 'example.com', 'origin');
      assert(/header/.test(await text(page, '.zone-origin-field')), 'origin source hint');
      assert(/^39 records · 26 names · 10 proxied$/.test((await text(page, '[data-role="zone-counts"]')).trim()), await text(page, '[data-role="zone-counts"]'));
      assert(await page.evaluate(() => document.activeElement?.classList.contains('zone-summary-title')), 'focus on the summary heading');
      const badge = await page.evaluate(() => document.querySelector('.zone-tabs .tab[data-tab="problems"] .tab-badge'));
      assert(badge !== undefined, 'problems badge');
      assertEqual(await page.evaluate(() => window.__fakeDnsLog.length), 0, 'no DNS query');
      assertEqual(external, [], 'no external request');
      const session = await page.evaluate(async () => {
        const s = (await import('./assets/js/state.js')).state.getSession('zone');
        return s ? { v: s.v, origin: s.origin, www: s.names.includes('www.example.com'), intranet: s.names.includes('intranet.example.com') } : null;
      });
      assertEqual(session, { v: 1, origin: 'example.com', www: true, intranet: false }, 'state.session.zone');
      assertEqual(await noZoneStorage(page), [], 'nothing persisted');
      await shot(page, opts, 'zone-overview-desktop-light-en');
    });

    await run.step('Records: 39 rows, Proxied only → 10, CNAME filter, search, tags in details', async () => {
      await clickTab(page, 'records');
      const rows = () => count(page, '.zone-records tbody tr.dt-row');
      assertEqual(await rows(), 39, 'all rows');
      await jsClick(page, '[data-role="zone-proxied-only"]');
      await page.waitFor(() => document.querySelectorAll('.zone-records tbody tr.dt-row').length === 10, { message: 'proxied only' });
      await jsClick(page, '[data-role="zone-proxied-only"]');
      await page.click('.zone-type-filter [data-value="CNAME"]');
      const cnames = await rows();
      assert(cnames >= 4 && cnames < 39, `CNAME rows ${cnames}`);
      await page.click('.zone-type-filter [data-value="all"]');
      await page.type('.zone-records .dt-search-input', 'mixed');
      await page.waitFor(() => document.querySelectorAll('.zone-records tbody tr.dt-row').length === 2, { message: 'search mixed' });
      await page.type('.zone-records .dt-search-input', 'tagged');
      await page.waitFor(() => document.querySelectorAll('.zone-records tbody tr.dt-row').length === 1, { message: 'search tagged' });
      await page.click('.zone-records tbody tr.dt-row .dt-expander button');
      await page.waitFor(() => /ops, eu/.test(document.querySelector('.zone-records .dt-details')?.textContent || ''), { message: 'tag chip' });
      await page.type('.zone-records .dt-search-input', '');
    });

    await run.step('Origins: 10 rows, web01 behind @ / www / docs, skipped provider + tunnel, exact command', async () => {
      await clickTab(page, 'origins');
      assertEqual(await count(page, '.zone-origins-table tbody tr.dt-row'), 10, 'origin rows');
      const rows = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.zone-origins-table tbody tr.dt-row')]
        .map((tr) => [tr.querySelector('td:not(.dt-expander) strong')?.textContent, tr.textContent])));
      for (const n of ['@', 'www', 'docs']) assert(/web01/.test(rows[n] || ''), `${n} → web01: ${rows[n]}`);
      assert(/Shopify|shopify/.test(rows.shop || ''), `shop: ${rows.shop}`);
      assert(/Tunnel/.test(rows.tunnel || ''), `tunnel: ${rows.tunnel}`);
      const cmd = await text(page, '.zone-command code');
      assert(cmd.startsWith('python3 ssl_origin_scan.py -t 192.0.2.10 '), cmd);
      assert(cmd.includes(' origin-lb.example.net ') && cmd.includes("'*.apps.example.com'"), cmd);
      assert(!/192\.0\.2\.0\/24/.test(cmd) && !/\/24\b/.test(cmd), 'never a /24');
      assert(/Skipped: shop \(/.test(await text(page, '[data-role="zone-skipped"]')), 'skipped line');
      const est1 = await text(page, '[data-role="zone-estimate"]');
      assert(/9 SNI names × 8 targets = at least 72/.test(est1), est1);
      await page.click('.zone-shell [data-value="powershell"]');
      await page.waitFor(() => (document.querySelector('.zone-command code')?.textContent || '').startsWith('python ssl_origin_scan.py'), { message: 'PowerShell' });
      await page.click('.zone-scope [data-value="all"]');
      await page.waitFor((e) => (document.querySelector('[data-role="zone-estimate"]')?.textContent || '') !== e, { args: [est1.replace('8 names', '8 names')], message: 'scope all' });
      await page.click('.zone-scope [data-value="proxied"]');
      await page.click('.zone-shell [data-value="posix"]');
      await takeDownloads(page);
      await page.click('[data-action="zone-targets-file"]');
      await page.waitFor(() => (window.__downloads || []).length === 1);
      const [dl] = await takeDownloads(page);
      // The same hand-off computed in Node from the same fixture (the zones-analysis goldens use their own inputs).
      const V = await import('../../assets/js/views/zone.js');
      const O = await import('../../assets/js/lib/zoneorigins.js');
      const sw = O.zoneSweep(V.parseFiles([{ name: 'example.com.txt', text: await readFile(CF_FILE, 'utf8') }]), { scope: 'proxied' });
      const expected = [...sw.targets, ...sw.hostTargets];
      const got = dl.text.split('\n').filter((l) => l && !l.startsWith('#'));
      assertEqual(dl.name, 'zone-targets.txt', 'file name');
      assertEqual(got.map((l) => l.split(' ').pop()), expected.map((l) => l.split(' ').pop()), 'targets');
      assert(got.includes('web01 192.0.2.10'), 'inventory name in the targets file');
      assertEqual(external, [], 'no external request');
      await shot(page, opts, 'zone-origins-desktop-light-en');
    });

    await run.step('servers added or renamed after the import update the Origins and Records server columns', async () => {
      const setInv = (inv) => page.evaluate(async (s) => { (await import('./assets/js/state.js')).state.setInventory(s); }, inv);
      const originRows = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.zone-origins-table tbody tr.dt-row')]
        .map((tr) => [tr.querySelector('td:not(.dt-expander) strong')?.textContent, tr.textContent])));
      await setInv('');
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'forgotten' });
      await page.setFileInput('.zone-drop .filedrop-input', [CF_FILE]);
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'summary' });
      await clickTab(page, 'origins');
      assert(await count(page, '.zone-origins-table a[href$="#/inventory"]') > 0, '"Add your servers" links');
      await gotoRoute(page, 'inventory');
      await setInv('web01 192.0.2.10');
      await gotoRoute(page, 'zone');
      await clickTab(page, 'origins');
      let rows = await originRows();
      for (const n of ['@', 'www', 'docs']) assert(/web01/.test(rows[n] || ''), `${n} → web01 after adding the server: ${rows[n]}`);
      await clickTab(page, 'records');
      const cells = await page.evaluate(() => [...document.querySelectorAll('.zone-records tbody tr.dt-row')]
        .filter((tr) => [...tr.cells].some((td) => td.textContent.trim() === '192.0.2.10')).map((tr) => tr.textContent));
      assert(cells.length > 0 && cells.every((c) => /web01/.test(c)), `Records server cell: ${cells}`);
      // renamed while the view is shown (another tab, or a script): the columns follow without navigating
      await clickTab(page, 'origins');
      await setInv('web-a 192.0.2.10');
      await page.waitFor(() => /web-a/.test(document.querySelector('.zone-origins-table')?.textContent || ''), { message: 'renamed server' });
      rows = await originRows();
      assert(!/web01/.test(rows.www || '') && /web-a/.test(rows.www || ''), `www → web-a: ${rows.www}`);
      await setInv('web01 192.0.2.10');
    });

    await run.step('Problems: rollup, Errors filter, ftp → Records filtered with the line highlighted', async () => {
      await clickTab(page, 'problems');
      assert(await count(page, '.zone-problems-all .zone-problem') >= 5, 'problems listed');
      await page.click('.zone-prob-filter [data-value="error"]');
      assert(await page.evaluate(() => [...document.querySelectorAll('.zone-problems-all .zone-problem')].every((li) => li.dataset.severity === 'error')), 'errors only');
      await page.evaluate(() => [...document.querySelectorAll('.zone-problem-link')].find((b) => b.dataset.name === 'ftp.example.com').click());
      await page.waitFor(() => !document.querySelector('.zone-tabs .tabpanel[data-tab="records"]')?.hidden
        && document.querySelector('.zone-records .dt-search-input')?.value === 'ftp.example.com', { message: 'records filtered' });
      assert(await count(page, '.zone-records tr.zone-row-hit') >= 1, 'line highlighted');
      assert(/tab=records/.test(await page.evaluate(() => location.hash)), 'hash tab');
    });

    await run.step('Copy summary: counts, the worst problems as the Problems tab words them, the privacy line, a bare #/zone link', async () => {
      await stubClipboard(page);
      await clickTab(page, 'problems');
      await page.click('.zone-prob-filter [data-value="all"]');
      const shown = await page.evaluate(() => ({
        tip: document.querySelector('[data-summary="zone"] [data-action="copy-summary"]').title,
        problems: [...document.querySelectorAll('.zone-problems-all .zone-problem')].filter((li) => li.dataset.severity === 'error' || li.dataset.severity === 'warn')
          .map((li) => `- ${li.dataset.severity === 'error' ? 'Error' : 'Warning'}: ${li.querySelector('.zone-problem-title').textContent}`)
      }));
      assert(/nothing from your server list/.test(shown.tip) && /without any file contents/.test(shown.tip), `tooltip: ${shown.tip}`);
      await page.click('[data-summary="zone"] [data-action="copy-summary"]');
      await page.click('[data-summary="zone"] [data-action="copy-summary-text"]');
      await page.waitFor(() => window.__clip.length === 2, { message: 'two copies' });
      const [md, plain] = await takeClipboard(page);
      const lines = md.trim().split('\n');
      assertEqual(lines.slice(0, 2), ['**Zone File · `example.com`**', '- Cloudflare export (BIND): 39 records · 26 names · 10 proxied'], 'title and counts');
      assert(/^- Problems: \d+ errors? · \d+ warnings?/.test(lines[2]), `problems line: ${lines[2]}`);
      assertEqual(plain.trim().split('\n').slice(3, 6), shown.problems.slice(0, 3), 'the worst three, worded as on the Problems tab');
      // The footer is its own paragraph (an empty line before it), not a continuation of the last item.
      assertEqual(lines.slice(-3, -1), ['- The zone file stays in this browser: the link opens Zone File without it', ''], 'privacy line, then an empty line');
      assert(new RegExp(`^DomainScope · as of \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2} UTC · ${origin}/domainscope/#/zone$`).test(lines[lines.length - 1]),
        `a bare #/zone link (no tab, nothing of the file): ${lines[lines.length - 1]}`);
      assert(lines.length - 1 >= 5 && lines.length - 1 <= 12, `5–12 lines: ${lines.length - 1}`);
      assertEqual(plain.trim().split('\n').length, lines.length - 1, 'plain text: the same lines, no empty one');
      assertEqual(await page.evaluate(() => window.__fakeDnsLog.length), 0, 'no DNS query');
    });

    await run.step('Live check: disclosure first, nothing sent before Run; planned queries; hidden names never sent', async () => {
      await clickTab(page, 'live');
      const lead = await page.evaluate(() => {
        const el = document.querySelector('[data-role="zone-live-lead"]');
        return { text: el.textContent, queries: Number(el.dataset.queries) };
      });
      assert(/record sets → \d+ DNS queries through /.test(lead.text), lead.text);
      assert(/Skip names that look internal \(1\)/.test(await text(page, '.zone-live-card')), 'skip internal (1)');
      assertEqual(await page.evaluate(() => window.__fakeDnsLog.length), 0, 'no DNS query before Run');
      await page.click('[data-action="zone-live-run"]');
      await page.waitFor(() => document.querySelector('.zone-drift')?.dataset.status === 'done', { timeout: 30000, message: 'drift done' });
      const log = await page.evaluate(() => window.__fakeDnsLog);
      const keys = new Set(log.map((q) => `${q.name}|${q.type}`));
      assertEqual(keys.size, lead.queries, 'unique queries = planned');
      for (const hidden of ['origin-lb.example.net', 'intranet.example.com', 'old.dev.example.com']) {
        assert(!log.some((q) => q.name === hidden), `${hidden} never queried`);
      }
      const statuses = await page.evaluate(() => [...new Set([...document.querySelectorAll('.zone-drift-table [data-status]')].map((e) => e.dataset.status))]);
      for (const s of ['proxied-ok', 'origin-exposed', 'match']) assert(statuses.includes(s), `${s} in ${statuses}`);
      assert(/newer than the file/.test(await text(page, '.zone-drift')), 'serial banner');
      await page.click('.zone-chip[data-filter="origin-exposed"]');
      const shown = await page.evaluate(() => [...document.querySelectorAll('.zone-drift-table tbody tr.dt-row [data-status]')].map((e) => e.dataset.status));
      assert(shown.length >= 1 && shown.every((s) => s === 'origin-exposed'), `chip filter: ${shown}`);
      await page.click('.zone-chip[data-filter="all"]');
      await takeDownloads(page);
      await page.click('.zone-drift-table .dt-export button');
      await page.waitFor(() => (window.__downloads || []).length === 1);
      const [csv] = await takeDownloads(page);
      for (const ip of ['192.0.2.10', '192.0.2.14', '192.0.2.40', '2001:db8::10', 'origin-lb.example.net']) assert(!csv.text.includes(ip), `${ip} redacted`);
      assert(csv.text.includes('[origin hidden]'), 'redaction marker');
      await jsClick(page, '[data-role="zone-include-origins"]');
      await page.click('.zone-drift-table .dt-export button');
      await page.waitFor(() => (window.__downloads || []).length === 1);
      const [csv2] = await takeDownloads(page);
      assert(csv2.text.includes('192.0.2.10'), 'origins included on opt-in');
      assertEqual(external, [], 'no external request (DoH answered in the page)');
      await shot(page, opts, 'zone-live-desktop-light-en');
    });

    await run.step('Live check: Cancel stops a slow run; Re-run completes', async () => {
      await page.evaluate(() => { window.__fakeDnsDelay = 400; });
      await page.click('[data-action="zone-live-run"]');
      await page.waitFor(() => !!document.querySelector('[data-action="zone-live-cancel"]'), { message: 'running' });
      await sleep(300);
      await page.click('[data-action="zone-live-cancel"]');
      await page.waitFor(() => /Stopped: \d+ of \d+ record sets checked/.test(document.querySelector('.zone-live')?.textContent || ''), { timeout: 15000, message: 'stopped' });
      await page.evaluate(() => { window.__fakeDnsDelay = 0; });
      await page.click('[data-action="zone-live-run"]');
      await page.waitFor(() => document.querySelector('.zone-drift')?.dataset.status === 'done', { timeout: 30000, message: 're-run done' });
    });

    await run.step('Live check options keep the keyboard focus when toggled with Space', async () => {
      for (const role of ['zone-live-skip', 'zone-live-wildcards']) {
        for (let round = 0; round < 2; round += 1) {
          const before = await page.evaluate((r) => { const el = document.querySelector(`[data-role="${r}"]`); el.focus(); return el.checked; }, role);
          await page.press('Space');
          await page.waitFor((r, b) => document.querySelector(`[data-role="${r}"]`)?.checked === !b, { args: [role, before], message: `${role} toggled` });
          const now = await page.evaluate(() => ({ role: document.activeElement?.dataset.role, checked: document.activeElement?.checked }));
          assertEqual(now, { role, checked: !before }, `${role}: focus kept on the option`);
        }
      }
    });

    await run.step('the finished live check is kept like a result: "Live check from" on any tab, Run again on the Live tab, nothing in the URL or the target', async () => {
      await clickTab(page, 'overview');
      const chip = () => page.evaluate(() => document.querySelector('[data-role="target-chip"] .target-chip-value')?.textContent || null);
      const chipBefore = await chip();
      await leaveAndReturn(page);
      const note = await keptNote(page);
      assert(/^Live check from \d{1,2}:\d{2}(\s[AP]M)?$/.test(note.text), `the note names the live check on the Overview tab: ${note.text}`);
      assertEqual([note.rerun, note.hash], [true, '#/zone'], 'Run again; nothing in the URL');
      await shot(page, opts, 'zone-kept-desktop-light-en');
      const sent = await page.evaluate(() => window.__fakeDnsLog.length);
      await page.click('[data-action="kept-rerun"]');
      await page.waitFor((n) => window.__fakeDnsLog.length > n && !document.querySelector('.zone-tabs .tabpanel[data-tab="live"]')?.hidden
        && document.querySelector('.zone-drift')?.dataset.status === 'done', { args: [sent], timeout: 30000, message: 'the live check again, on its tab' });
      assertEqual(await page.evaluate(() => !!document.querySelector('.page-kept:not([hidden])')), false, 'note gone');
      assertEqual(await chip(), chipBefore, 'the zone never becomes the current target');
      assertEqual(await page.evaluate(() => location.hash), '#/zone?tab=live', 'only the tab in the URL');
      assertEqual(external, [], 'no external request');
    });

    await run.step('the Live tab\'s own Run replaces the kept check: the note goes at once and stays gone', async () => {
      await leaveAndReturn(page);
      assert(/^Live check from /.test((await keptNote(page)).text), 'kept again');
      await clickTab(page, 'live');
      await page.evaluate(() => { window.__fakeDnsDelay = 150; });
      await page.click('[data-action="zone-live-run"]');
      await page.waitFor(() => !!document.querySelector('[data-action="zone-live-cancel"]'), { message: 'running' });
      assertEqual((await keptNote(page)).text, '', 'no note over a check that runs');
      await page.evaluate(() => { window.__fakeDnsDelay = 0; });
      await page.waitFor(() => document.querySelector('.zone-drift')?.dataset.status === 'done', { timeout: 30000, message: 'check done' });
      assertEqual((await keptNote(page)).text, '', 'no note over the fresh result');
    });

    await run.step('Turkish: the note names the live check too, and a language switch keeps it', async () => {
      await setLangUi(page, 'tr');
      await leaveAndReturn(page);
      const note = await keptNote(page);
      assert(/^Önceki canlı kontrol: \d{1,2}:\d{2}$/.test(note.text), `TR note: ${note.text}`);
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await shot(page, opts, 'zone-kept-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      assert(/^Live check from /.test((await keptNote(page)).text), 'kept through the language switch');
    });

    const gpPosts = () => page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST').map((c) => c.body));
    const typeNs = (value) => page.evaluate((v) => {
      const ta = document.querySelector('[data-role="par-ns"]');
      ta.value = v;
      ta.dispatchEvent(new Event('input', { bubbles: true }));
    }, value);
    const parityRows = () => page.evaluate(() => {
      const keys = [...document.querySelectorAll('.par-table thead th')].map((th) => th.dataset.key || '');
      return [...document.querySelectorAll('.par-table tbody tr.dt-row')].map((tr) => ({
        status: tr.querySelector('[data-status]')?.dataset.status,
        name: tr.cells[keys.indexOf('name')]?.textContent.trim(),
        type: tr.cells[keys.indexOf('type')]?.textContent.trim()
      }));
    });
    let plannedProbes = 0;

    await run.step('New name servers: nothing sent before Compare; the file\'s own server is flagged; the plan is the library\'s', async () => {
      await clickTab(page, 'parity');
      assert(/Compare with the new name servers/.test(await text(page, '.par-card')), 'the card');
      await typeNs('ada.ns.cloudflare.com');
      await page.waitFor(() => /one of this file’s own name servers/.test(document.querySelector('[data-role="par-issues"]')?.textContent || ''), { message: 'in-file issue' });
      await typeNs(NEW_NS.join('\n'));
      await page.waitFor(() => Number(document.querySelector('[data-role="par-plan"]')?.dataset.probes) > 0 && !document.querySelector('[data-role="par-issues"]'), { message: 'plan' });
      plannedProbes = Number(await page.evaluate(() => document.querySelector('[data-role="par-plan"]').dataset.probes));
      const V = await import('../../assets/js/views/zone.js');
      const NP = await import('../../assets/js/lib/nsparity.js');
      const z = V.parseFiles([{ name: 'example.com.txt', text: await readFile(CF_FILE, 'utf8') }]);
      assertEqual(plannedProbes, NP.planParity(z, { nameservers: NEW_NS }).probes, 'the planned probes, as lib/nsparity.js counts them');
      assert(/CAA/.test(await text(page, '[data-role="par-not-queryable"]')), 'CAA left to the CLI');
      await page.evaluate(() => { document.querySelector('.par-cli').open = true; });
      assertEqual((await text(page, '.par-command code')).trim(), `python3 dns_parity.py example.com.parity.zone --ns ${NEW_NS.join(' ')}`, 'CLI command');
      assert(await page.evaluate(() => document.querySelector('.par-cli a[href="cli/dns_parity.py"]')?.getAttribute('download') === 'dns_parity.py'), 'script link');
      assertEqual(await page.evaluate(() => window.__gp.calls.length), 0, 'no Globalping before a click');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.par-step')].map((li) => li.dataset.step)), ['ttl', 'fix', 'dnssec', 'switch', 'wait', 'after'], 'the runbook before a run');
      assertEqual(external, [], 'no external request');
    });

    await run.step('Compare: the consent + cost dialog (Escape sends nothing), then exactly the planned probes, names and types only', async () => {
      await page.click('[data-action="par-run"]');
      await page.waitFor(() => !!document.querySelector('.gp-confirm'), { message: 'dialog' });
      const dialog = await text(page, '.gp-confirm');
      assert(new RegExp(`Cost: ${plannedProbes} probes`).test(dialog) && /never|stay here/.test(dialog), `dialog: ${dialog}`);
      await page.press('Escape');
      await page.waitFor(() => !document.querySelector('.gp-confirm') && !document.querySelector('[data-action="par-stop"]'), { message: 'closed' });
      assertEqual((await gpPosts()).length, 0, 'Escape sends nothing');
      await page.click('[data-action="par-run"]');
      await page.waitFor(() => !!document.querySelector('.gp-confirm'), { message: 'dialog again' });
      await page.click('.gp-confirm .btn-primary');
      await page.waitFor(() => document.querySelector('.par-results')?.dataset.status === 'done', { timeout: 30000, message: 'compared' });
      const posts = await gpPosts();
      assertEqual(posts.length, plannedProbes, 'exactly the planned probes');
      assert(posts.every((b) => b.type === 'dns' && NEW_NS.includes(b.measurementOptions.resolver)), 'DNS measurements at the new servers');
      assertEqual(posts.filter((b) => b.measurementOptions.resolver === NEW_NS[1]).map((b) => `${b.target} ${b.measurementOptions.query.type}`), ['example.com SOA'], 'the second server: its serial only');
      for (const hidden of ['intranet.example.com', 'origin-lb.example.net', 'statuspage.example.org', 'old.dev.example.com']) {
        assert(!posts.some((b) => b.target === hidden), `${hidden} never sent`);
      }
      assert(!posts.some((b) => b.measurementOptions.query.type === 'CAA'), 'no CAA question');
      assert(posts.every((b) => !JSON.stringify(b).includes('192.0.2.')), 'no value of the file');
      assert(await page.evaluate(() => window.__fakeDnsLog.some((q) => q.name === 'example.com' && q.type === 'DS')), 'the DS question went to DoH');
      assertEqual(external, [], 'no external request');
    });

    await run.step('Results: fix verdict, the servers, statuses per record set, TTL difference, the runbook', async () => {
      assertEqual(await page.evaluate(() => document.querySelector('.par-results').dataset.verdict), 'fix', 'verdict');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.par-server')].map((li) => `${li.dataset.ns} ${li.dataset.role} ${li.dataset.state}`)),
        [`${NEW_NS[0]} full ok`, `${NEW_NS[1]} serial ok`], 'servers');
      const rows = await parityRows();
      const of = (name, type) => rows.find((r) => r.name === name && r.type === type)?.status;
      assertEqual([of('mail', 'A'), of('tunnel', 'CNAME'), of('@', 'MX'), of('www', 'A'), of('app', 'CNAME'), of('@', 'NS'), of('dev', 'NS'),
        of('status', 'CNAME'), of('@', 'CAA'), of('intranet', 'A'), of('vpn', 'A'), of('google._domainkey', 'TXT')],
      ['missing', 'missing', 'different', 'unproxied', 'unproxied', 'same', 'same', 'same', 'skipped', 'skipped', 'same', 'same'], 'statuses');
      assert(await page.evaluate(() => [...document.querySelectorAll('.par-ttl-differs')].some((el) => el.textContent.trim() === '300 → 3600')), 'the vpn TTL difference');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.par-step')].map((li) => `${li.dataset.step}:${li.dataset.state}`)),
        ['ttl:todo', 'fix:todo', 'dnssec:ok', 'switch:blocked', 'wait:todo', 'after:todo'], 'runbook');
      await page.click('.par-results .zone-chip[data-filter="missing"]');
      await page.waitFor(() => document.querySelectorAll('.par-table tbody tr.dt-row').length === 2, { message: 'missing filter' });
      await page.click('.par-results .zone-chip[data-filter="all"]');
      await shot(page, opts, 'zone-parity-desktop-light-en');
    });

    await run.step('Exports redact origin addresses by default; the zone for the CLI is canonical BIND', async () => {
      await takeDownloads(page);
      await page.click('.par-table .dt-export button');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'CSV' });
      const [csv] = await takeDownloads(page);
      for (const ip of ['192.0.2.10', '192.0.2.14', 'origin-lb.example.net']) assert(!csv.text.includes(ip), `${ip} redacted`);
      assert(csv.text.includes('[origin hidden]'), 'redaction marker');
      await page.click('[data-action="par-zone-file"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'zone file' });
      const [zoneFile] = await takeDownloads(page);
      assertEqual(zoneFile.name, 'example.com.parity.zone', 'file name');
      assert(zoneFile.text.startsWith('; DomainScope zone export') && zoneFile.text.includes('$ORIGIN example.com.'), 'canonical BIND');
    });

    await run.step('A server that does not serve the zone: one probe, no second dialog, blocked, and the switch waits', async () => {
      const before = (await gpPosts()).length;
      await typeNs('ns9.example.org');
      await page.waitFor(() => document.querySelector('[data-role="par-plan"]')?.dataset.probes !== String(0), { message: 'plan' });
      await page.click('[data-action="par-run"]');
      await page.waitFor(() => document.querySelector('.par-results')?.dataset.verdict === 'blocked', { timeout: 20000, message: 'blocked' });
      assert(!await page.evaluate(() => !!document.querySelector('.gp-confirm')), 'no second dialog in the page session');
      assertEqual((await gpPosts()).length - before, 1, 'the SOA question only');
      assertEqual(await page.evaluate(() => document.querySelector('.par-server')?.dataset.state), 'refused', 'refused');
      assertEqual(await page.evaluate(() => document.querySelector('.par-step[data-step="fix"]').dataset.state), 'blocked', 'fix blocked');
      await typeNs(NEW_NS.join(' '));
      await page.waitFor(() => document.querySelector('[data-role="par-ns"]')?.value === 'ns1.example.net ns2.example.net', { message: 'typed' });
    });

    await run.step('A private server goes into the CLI command; with the internal skip off, the privacy line says those names are sent', async () => {
      await typeNs(`${NEW_NS[0]}\n10.0.0.53`);
      await page.waitFor(() => /10\.0\.0\.53/.test(document.querySelector('.par-command code')?.textContent || ''), { message: 'the private server in the command' });
      assertEqual((await text(page, '.par-command code')).trim(), `python3 dns_parity.py example.com.parity.zone --ns ${NEW_NS[0]} 10.0.0.53`, 'CLI command');
      assert(/asks it from your network/.test(await text(page, '[data-role="par-issues"] [data-code="private"]')), 'the issue points at the command');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="par-plan"]').dataset.probes !== '0'), true, 'the public server is still compared');
      assert(/the names that look internal stay here/.test(await text(page, '[data-role="par-privacy"]')), 'internal names stay by default');
      await page.click('[data-role="par-skip-private"]');
      await page.waitFor(() => /are included, because you turned their skip off/.test(document.querySelector('[data-role="par-privacy"]')?.textContent || ''), { message: 'privacy with internal names' });
      assert(!/stay here\. Anyone/.test(await text(page, '[data-role="par-privacy"]')), 'no promise that they stay');
      await page.click('[data-role="par-skip-private"]');
      await page.waitFor(() => /the names that look internal stay here/.test(document.querySelector('[data-role="par-privacy"]')?.textContent || ''), { message: 'skip on again' });
      await typeNs(NEW_NS.join(' '));
      await page.waitFor(() => !document.querySelector('[data-role="par-issues"]') && document.querySelector('[data-role="par-plan"]')?.dataset.probes !== '0', { message: 'typed' });
    });

    await run.step('Compare from the keyboard: focus goes to Stop while it runs and back to Compare; the stop counts what it left out', async () => {
      const NP = await import('../../assets/js/lib/nsparity.js');
      const V = await import('../../assets/js/views/zone.js');
      const plan = NP.planParity(V.parseFiles([{ name: 'example.com.txt', text: await readFile(CF_FILE, 'utf8') }]), { nameservers: NEW_NS });
      // Hold every new measurement: the stop comes while the first server's SOA question is out.
      const base = await page.evaluate(() => { window.__gp.allowUpTo = window.__gp.n; return window.__gp.n; });
      await page.evaluate(() => document.querySelector('[data-action="par-run"]').focus());
      await page.press('Enter');
      // The consent was given in this page session, and the batch is small: no dialog.
      await page.waitFor(() => document.activeElement?.dataset.action === 'par-stop', { message: 'keyboard focus on Stop' });
      await page.waitFor((b) => window.__gp.n > b, { args: [base], message: 'the SOA question sent' });
      await page.press('Enter');
      await page.waitFor(() => !document.querySelector('[data-action="par-stop"]') && document.querySelector('.par-results')?.dataset.status === 'done', { message: 'stopped' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'par-run', 'keyboard focus back on Compare');
      assertEqual(await page.evaluate(() => document.querySelector('.par-results').dataset.verdict), 'partial', 'nothing judged');
      const head = await text(page, '.par-results > .alert');
      const left = plan.checked + plan.skipped.type + plan.skipped.budget;
      assert(head.includes(`${left} record sets were not`), `the record sets the stop left out (${left}): ${head}`);
      assert(/Stopped: what was answered is shown/.test(await text(page, '.par-results')), 'the stop alert');
      await page.evaluate(() => { window.__gp.allowUpTo = Infinity; });
    });

    await run.step('Leaving Zone File during a run: the tab it comes back to keeps counting the probes', async () => {
      const base = await page.evaluate(() => { window.__gp.allowUpTo = window.__gp.n; return window.__gp.n; });
      await page.click('[data-action="par-run"]');
      await page.waitFor((b) => !!document.querySelector('[data-action="par-stop"]') && window.__gp.n > b, { args: [base], message: 'running' });
      await leaveAndReturn(page);
      await clickTab(page, 'parity');
      await page.waitFor(() => /^0 \/ \d+ probes/.test(document.querySelector('.par-progress .progress-label')?.textContent || ''), { message: 'the progress of the new tab' });
      await page.evaluate((b) => { window.__gp.allowUpTo = b + 3; }, base);
      await page.waitFor(() => /^3 \/ \d+ probes/.test(document.querySelector('.par-progress .progress-label')?.textContent || ''), { message: 'the new tab counts on' });
      await page.evaluate(() => { window.__gp.allowUpTo = Infinity; });
      await page.waitFor(() => document.querySelector('.par-results')?.dataset.status === 'done' && !document.querySelector('[data-action="par-stop"]'), { timeout: 30000, message: 'done' });
      assertEqual(await page.evaluate(() => document.querySelector('.par-results').dataset.verdict), 'fix', 'the whole comparison');
    });

    await run.step('A quota stop while another view is shown: a warning toast says what was not compared; the headline and the switch wait', async () => {
      // Five measurements (the SOA and four record sets), then the quota 429, while About is shown.
      // The quota window ends a second after the 429, so the later steps can send again.
      const base = await page.evaluate(() => Object.assign(window.__gp, { allowUpTo: window.__gp.n, quotaAfter: window.__gp.n + 5, quotaResetS: 1 }).n);
      await page.click('[data-action="par-run"]');
      await page.waitFor((b) => !!document.querySelector('[data-action="par-stop"]') && window.__gp.n > b, { args: [base], message: 'running' });
      await gotoRoute(page, 'about');
      await page.evaluate(() => { window.__gp.allowUpTo = Infinity; });
      const parityToast = () => page.evaluate(() => {
        const el = [...document.querySelectorAll('.toast')].find((x) => /New name servers:/.test(x.textContent));
        return el ? { text: el.textContent, warn: el.classList.contains('toast-warn') } : null;
      });
      await page.waitFor(() => [...document.querySelectorAll('.toast')].some((x) => /New name servers:/.test(x.textContent)), { timeout: 30000, message: 'the toast' });
      const note = await parityToast();
      assert(/New name servers: stopped, \d+ record sets not compared/.test(note.text) && note.warn, `a warning that names the stop: ${JSON.stringify(note)}`);
      assert(!/nothing to fix/.test(note.text), 'never "nothing to fix" after a stop');
      await gotoRoute(page, 'zone');
      await clickTab(page, 'parity');
      await page.waitFor(() => document.querySelector('.par-results')?.dataset.status === 'done', { message: 'the result on the tab' });
      assertEqual(await page.evaluate(() => document.querySelector('.par-results').dataset.verdict), 'partial', 'what the stop left out could hold anything');
      const head = await text(page, '.par-results > .alert');
      assert(/so far, but not everything was compared: \d+ record sets were not/.test(head), `the headline says the comparison did not finish: ${head}`);
      assert(/The hourly Globalping quota ran out/.test(await text(page, '.par-results')), 'the quota alert');
      assertEqual(await page.evaluate(() => document.querySelector('.par-step[data-step="switch"]').dataset.state), 'warn', 'the switch waits');
      assert(/Compare again, or run the CLI below, before you switch/.test(await text(page, '.par-step[data-step="switch"]')), 'the switch step says why');
      const fixStep = await text(page, '.par-step[data-step="fix"]');
      assert(/Nothing is missing or different so far, but the comparison did not finish/.test(fixStep), `the fix step says "so far": ${fixStep}`);
      await shot(page, opts, 'zone-parity-stopped-desktop-light-en');
      await page.evaluate(() => { window.__gp.quotaAfter = Infinity; });
      await page.waitFor(() => Date.now() > window.__gp.quotaResetAt + 250, { message: 'the quota window is over' });
      await page.click('[data-action="par-run"]');
      await page.waitFor(() => document.querySelector('.par-results')?.dataset.verdict === 'fix' && !document.querySelector('[data-action="par-stop"]'), { timeout: 30000, message: 'compared again' });
      assertEqual(await page.evaluate(() => document.querySelector('.par-step[data-step="switch"]').dataset.state), 'blocked', 'the whole comparison: fix first');
    });

    await run.step('The comparison table fits its card at 1280 and 1440 px: no inner horizontal scroll, the notes whole', async () => {
      for (const width of [1280, 1440]) {
        await page.setViewport({ width, height: 900 });
        const fits = () => page.evaluate(() => {
          const s = document.querySelector('.par-table .dt-scroll');
          return s && document.querySelectorAll('.par-table tbody tr.dt-row').length > 0 ? { sw: s.scrollWidth, cw: s.clientWidth,
            cols: [...document.querySelectorAll('.par-table thead th')].map((th) => `${th.dataset.key}:${th.offsetWidth}`).join(' ') } : null;
        });
        await page.waitFor(() => {
          const s = document.querySelector('.par-table .dt-scroll');
          return !!s && document.querySelectorAll('.par-table tbody tr.dt-row').length > 0 && s.scrollWidth <= s.clientWidth + 1;
        }, { timeout: 3000, message: `the table fits at ${width} px` }).catch(async (err) => {
          throw new Error(`${err.message}: ${JSON.stringify(await fits())}`);
        });
      }
      await page.setViewport({ width: 1440, height: 900 });
    });

    await run.step('Scan these names (exact): publishes the zone + one-shot intent and opens Subdomains', async () => {
      await clickTab(page, 'overview');
      const before = await page.evaluate(() => localStorage.getItem('ssds.subdomains.options'));
      const extBefore = external.length;
      await page.evaluate(async () => {
        // Observe the hand-off without depending on how Subdomains consumes it.
        const { state } = await import('./assets/js/state.js');
        window.__intents = [];
        state.subscribe(({ key, value }) => { if (key === 'session' && value.name === 'zoneScanIntent' && value.value) window.__intents.push(value.value); });
      });
      await page.click('[data-action="zone-scan"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'subdomains', { message: 'Subdomains opened' });
      assert(/domain=example\.com/.test(await page.evaluate(() => location.hash)), 'domain param');
      const intent = await page.evaluate(() => window.__intents[0]);
      assertEqual({ v: intent.v, target: intent.target, domain: intent.domain, mode: intent.mode, autostart: intent.autostart },
        { v: 1, target: 'subdomains', domain: 'example.com', mode: 'exact', autostart: true }, 'intent');
      await sleep(500);
      await page.evaluate(() => document.querySelector('[data-action="sub-cancel"]:not([disabled])')?.click());
      assertEqual(await page.evaluate(() => localStorage.getItem('ssds.subdomains.options')), before, 'Subdomains options unchanged');
      await gotoRoute(page, 'zone');
      // Requests Subdomains made (its own sources, blocked here) are not the zone view's.
      if (external.length > extBefore) process.stdout.write(`        note: Subdomains tried ${external.length - extBefore} external request(s) (blocked)
`);
      external.length = extBefore;
      assert(await page.evaluate(() => !!document.querySelector('.zone-summary')), 'zone kept in memory across views');
    });

    await run.step('Find certificate targets: SSL Targets opens with the domain, no auto-start intent', async () => {
      await page.evaluate(() => { window.__intents = []; });
      await page.click('[data-action="zone-cert"]');
      const extBefore = external.length;
      await page.waitFor(() => document.documentElement.dataset.view === 'scan', { message: 'SSL Targets opened' });
      const intent = await page.evaluate(() => window.__intents[0]);
      assertEqual([intent.target, intent.autostart, intent.domain], ['scan', false, 'example.com'], 'cert intent');
      await gotoRoute(page, 'zone');
      external.length = extBefore;
    });

    await run.step('Route 53 JSON pasted: incomplete export alert (the old zone\'s kept check loses its note); cPanel: missing-dot error', async () => {
      assert(/^Live check from /.test((await keptNote(page)).text), 'the check kept over the trips to Subdomains and SSL Targets');
      const r53 = await readFile(path.join(ZONES, 'route53.json'), 'utf8');
      await page.evaluate(() => { document.querySelectorAll('.zone-import-folded, .zone-paste').forEach((d) => { d.open = true; }); });
      await page.type('[data-role="zone-paste"]', r53);
      await page.click('[data-action="zone-paste-import"]');
      await page.waitFor(() => /AWS Route 53/.test(document.querySelector('.zone-format-badge')?.textContent || ''), { message: 'route53' });
      assert(/incomplete/i.test(await text(page, '.zone-partial')), 'incomplete export alert');
      assertEqual((await keptNote(page)).text, '', 'a new import: no note about the old zone\'s check');
      // ... and no comparison with the old file's new name servers either; the servers typed in stay.
      await clickTab(page, 'parity');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="par-ns"]').value), NEW_NS.join(' '), 'servers kept over the new import');
      assert(!await page.evaluate(() => !!document.querySelector('.par-results')), 'the old results went with the old import');
      await page.setFileInput('.zone-drop .filedrop-input', [path.join(ZONES, 'cpanel-example.com.db.txt')]);
      await page.waitFor(() => /cPanel/.test(document.querySelector('.zone-format-badge')?.textContent || ''), { message: 'cpanel' });
      await clickTab(page, 'problems');
      assert(await page.evaluate(() => !!document.querySelector('.zone-problem[data-code="OWNER_MISSING_TRAILING_DOT"]')), 'OWNER_MISSING_TRAILING_DOT');
    });

    await run.step('"Show the fix" of the cPanel localhost record: delete it, exactly as the file has it (BIND, Route 53), no check link; only fixable findings offer one', async () => {
      const offered = await page.evaluate(() => [...document.querySelectorAll('.zone-problems-all [data-action="zone-fix"]')].map((b) => b.dataset.code));
      assertEqual(offered, ['LOCALHOST_RECORD'], 'only the fixable finding offers a fix (never the duplicate or the missing dot)');
      const toggle = '.zone-problems-all [data-action="zone-fix"]';
      await page.click(toggle);
      await page.waitFor(() => !!document.querySelector('.zone-problems-all .zone-fix .fix-outputs'), { message: 'fix panel', timeout: 10000 });
      const panel = await page.evaluate(() => {
        const host = document.querySelector('.zone-problems-all .zone-fix .fix-host');
        return {
          sets: [...host.querySelectorAll('.fix-set')].map((li) => `${li.dataset.action} ${li.dataset.type} ${li.dataset.name}: ${[...li.querySelectorAll('.fix-value-text')].map((v) => v.textContent).join(' | ')}`),
          expanded: document.querySelector('.zone-problems-all [data-action="zone-fix"]').getAttribute('aria-expanded'),
          // nothing about an imported zone reaches a URL: no check link, and the instructions name none
          checkLink: !!host.querySelector('.fix-check') || /change\/check/.test(host.textContent)
        };
      });
      assertEqual(panel, { sets: ['delete A localhost.example.com: 127.0.0.1'], expanded: 'true', checkLink: false }, 'the fix, without a check link');
      const code = (tab) => page.evaluate((t) => {
        document.querySelector(`.zone-problems-all .zone-fix .tab[data-tab="${t}"]`).click();
        return document.querySelector(`.zone-problems-all .zone-fix .tabpanel[data-tab="${t}"] .codeblock-pre`).textContent;
      }, tab);
      assert((await code('bind')).includes('; delete: localhost 14400 IN A 127.0.0.1'), 'BIND names the line to delete, with its TTL from the file');
      const r53 = JSON.parse(await code('route53'));
      assertEqual(r53.Changes, [{ Action: 'DELETE', ResourceRecordSet: { Name: 'localhost.example.com.', Type: 'A', TTL: 14400, ResourceRecords: [{ Value: '127.0.0.1' }] } }], 'Route 53 DELETE, exact');
      await shot(page, opts, 'zone-fix-desktop-light-en');
      await page.click(toggle);
      assertEqual(await page.evaluate(() => document.querySelector('.zone-problems-all .zone-fix .fix-host').hidden), true, 'Hide the fix');
    });

    await run.step('an internal zone: the Live card and the pinned alert give the same address counts', async () => {
      await page.setFileInput('.zone-drop .filedrop-input', [path.join(ZONES, 'internal.zone.txt')]);
      await page.waitFor(() => /internal\.zone\.txt/.test(document.querySelector('.zone-files')?.textContent || ''), { message: 'internal zone' });
      await clickTab(page, 'live');
      const counts = await page.evaluate(() => {
        const of = (el) => (/\((\d+) of (\d+) addresses are private\)/.exec(el?.textContent || '') || []).slice(1).join('/');
        return { pinned: of([...document.querySelectorAll('.zone-page > .alert')].find((a) => /internal zone/.test(a.textContent))), live: of(document.querySelector('.zone-live-card .alert')) };
      });
      assertEqual(counts, { pinned: '6/8', live: '6/8' }, 'internal-zone counts');
    });

    await run.step('a certificate by mistake → NOT_A_ZONE with a Certificate link; two API pages → one zone', async () => {
      await page.setFileInput('.zone-drop .filedrop-input', [path.join(ZONES, 'bad', 'cert.pem.txt')]);
      await page.waitFor(() => document.querySelector('.zone-fatal')?.dataset.code === 'NOT_A_ZONE', { message: 'fatal' });
      assert(await page.evaluate(() => !!document.querySelector('.zone-fatal a[href*="#/cert"]')), 'Certificate link');
      await page.setFileInput('.zone-drop .filedrop-input', [path.join(ZONES, 'cloudflare-api-page1.json'), path.join(ZONES, 'cloudflare-api-page2.json')]);
      await page.waitFor(() => /Cloudflare API/.test(document.querySelector('.zone-format-badge')?.textContent || ''), { message: 'API pages' });
      assert(/cloudflare-api-page1\.json, cloudflare-api-page2\.json/.test(await text(page, '.zone-files')), 'both files');
    });

    await run.step('an $INCLUDE part dropped before its main file: one zone, each row names its own file', async () => {
      const dir = await mkdtemp(path.join(os.tmpdir(), 'ds-zone-e2e-'));
      try {
        const part = path.join(dir, 'mail.inc');
        const main = path.join(dir, 'db.example.com');
        await writeFile(part, 'mail IN A 192.0.2.80\n@ IN MX 10 mail\n');
        await writeFile(main, '$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 h 1 2 3 4 5\n@ IN NS ns1\nns1 IN A 192.0.2.53\n$INCLUDE mail.inc\n');
        await page.setFileInput('.zone-drop .filedrop-input', [part, main]);
        await page.waitFor(() => /mail\.inc, db\.example\.com/.test(document.querySelector('.zone-files')?.textContent || ''), { message: 'include pair' });
        assertEqual(await text(page, '.zone-summary-title'), 'Zone example.com', 'one zone');
        await clickTab(page, 'records');
        const rows = await page.evaluate(() => {
          const keys = [...document.querySelectorAll('.zone-records thead th')].map((th) => th.dataset.key || '');
          const cell = (tr, key) => tr.cells[keys.indexOf(key)];
          return Object.fromEntries([...document.querySelectorAll('.zone-records tbody tr.dt-row')].map((tr) => [
            `${cell(tr, 'name').querySelector('.zone-name')?.title} ${cell(tr, 'type').textContent.trim()}`, cell(tr, 'line').textContent.trim()]));
        });
        assertEqual(rows, {
          'mail.example.com A': 'mail.inc:1', 'example.com MX': 'mail.inc:2',
          'example.com SOA': 'db.example.com:3', 'example.com NS': 'db.example.com:4', 'ns1.example.com A': 'db.example.com:5'
        }, 'line column');
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    await run.step('Forget → empty state, toast, session cleared, no note; nothing persisted; hash only tab=', async () => {
      // A finished live check of this zone, kept over a trip away: Forget drops it with its note.
      await clickTab(page, 'live');
      await page.click('[data-action="zone-live-run"]');
      await page.waitFor(() => document.querySelector('.zone-drift')?.dataset.status === 'done', { timeout: 30000, message: 'check done' });
      await leaveAndReturn(page);
      assert((await keptNote(page)).rerun, 'kept, with Run again');
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary') && document.querySelectorAll('[data-sample]').length === 3, { message: 'empty' });
      assert(await page.evaluate(() => [...document.querySelectorAll('.toast')].some((t) => /Zone forgotten/.test(t.textContent))), 'toast');
      assertEqual(await keptNote(page), { text: '', rerun: false, hash: await page.evaluate(() => location.hash) }, 'no note, no dead Run again over the empty view');
      assertEqual(await page.evaluate(async () => (await import('./assets/js/state.js')).state.getSession('zone')), undefined, 'session cleared');
      assertEqual(await noZoneStorage(page), [], 'no zone key in storage');
      assert(/^#\/zone(\?tab=\w+)?$/.test(await page.evaluate(() => location.hash)), 'hash');
    });

    await run.step('Forget during a comparison: the run stops and drops out quietly (no toast, no result for a zone that is gone)', async () => {
      await page.click('[data-sample="cloudflare"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'sample' });
      await clickTab(page, 'parity');
      await typeNs(NEW_NS.join('\n'));
      await page.waitFor(() => Number(document.querySelector('[data-role="par-plan"]')?.dataset.probes) > 0, { message: 'plan' });
      const base = await page.evaluate(() => { window.__gp.allowUpTo = window.__gp.n; return window.__gp.n; });
      await page.click('[data-action="par-run"]');
      await page.waitFor(() => !!document.querySelector('.gp-confirm') || !!document.querySelector('[data-action="par-stop"]'), { message: 'dialog or run' });
      if (await page.evaluate(() => !!document.querySelector('.gp-confirm'))) await page.click('.gp-confirm .btn-primary');
      await page.waitFor((b) => !!document.querySelector('[data-action="par-stop"]') && window.__gp.n > b, { args: [base], message: 'running' });
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary') && document.getElementById('main')?.getAttribute('aria-busy') === 'false', { message: 'forgotten, the run ended' });
      assert(!await page.evaluate(() => [...document.querySelectorAll('.toast')].some((x) => /New name servers:/.test(x.textContent))), 'no toast for the dropped run');
      await page.evaluate(() => { window.__gp.allowUpTo = Infinity; });
      const posted = await page.evaluate(() => window.__gp.n);
      await page.click('[data-sample="cloudflare"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'the sample again' });
      await clickTab(page, 'parity');
      assert(!await page.evaluate(() => !!document.querySelector('.par-results')), 'no result of the dropped run');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="par-ns"]').value), '', 'Forget drops the servers typed in too');
      assertEqual(await page.evaluate(() => window.__gp.n), posted, 'nothing sent after Forget');
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'empty again' });
    });

    // Zone File › Compare and Convert: the Cloudflare sample against the Route 53 sample, then the
    // sample written in every format. Computed again in Node from the same samples with the libraries.
    const ZD = await import('../../assets/js/lib/zonediff.js');
    const ZC = await import('../../assets/js/lib/zoneconvert.js');
    const ZP = await import('../../assets/js/lib/zoneparse.js');
    const ZV = await import('../../assets/js/views/zone.js');
    const sampleZone = (id) => {
      const s = ZV.SAMPLES.find((x) => x.id === id);
      return ZV.parseFiles([{ name: s.file, text: s.text }]);
    };
    const cmpRows = () => page.evaluate(() => {
      const keys = [...document.querySelectorAll('.zcmp-table thead th')].map((th) => th.dataset.key || '');
      return [...document.querySelectorAll('.zcmp-table tbody tr.dt-row')].map((tr) => `${tr.querySelector('[data-status]')?.dataset.status} ${tr.cells[keys.indexOf('name')]?.textContent.trim()} ${tr.cells[keys.indexOf('type')]?.textContent.trim()}`);
    });
    const expectRows = (res, filter = 'diff') => res.rows.filter((r) => ZD.diffFilter(r, filter)).map((r) => `${r.status} ${r.rel} ${r.type}`);
    const differences = () => page.evaluate(() => Number(document.querySelector('[data-role="zcmp-head"]')?.dataset.differences));

    await run.step('Compare: the second zone from a sample; a semantic diff the libraries agree with; nothing sent or kept', async () => {
      const sent = await page.evaluate(() => ({ dns: window.__fakeDnsLog.length, gp: window.__gp.calls.length }));
      await page.click('[data-sample="cloudflare"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'sample' });
      await clickTab(page, 'compare');
      await page.waitFor(() => !!document.querySelector('[data-compare-sample="route53"]'), { message: 'the second zone\'s importer', timeout: 10000 });
      assert(/kept only in this tab’s memory/.test(await text(page, '.zcmp-privacy')), 'privacy line');
      assertEqual(await count(page, '[data-sample]'), 0, 'the first importer\'s samples stay folded away');
      await page.click('[data-compare-sample="route53"]');
      await page.waitFor(() => !!document.querySelector('[data-role="zcmp-results"]'), { message: 'compared' });
      assert(/^Compared with example\.com$/.test(await text(page, '.zcmp-other-title')), await text(page, '.zcmp-other-title'));
      assertEqual(await text(page, '.zcmp-format-badge'), 'AWS Route 53 (JSON)', 'the other zone\'s format');
      const res = ZD.diffZones(sampleZone('cloudflare'), sampleZone('route53'));
      assertEqual(await differences(), res.counts.added + res.counts.removed + res.counts.changed, 'differences');
      assertEqual(await cmpRows(), expectRows(res), 'the differences, as lib/zonediff.js finds them');
      assert((await cmpRows()).includes('changed @ A') && (await cmpRows()).includes('added app A') && (await cmpRows()).includes('removed app CNAME'), 'a changed, an added and a removed set');
      await page.click('.zcmp-chips .zone-chip[data-filter="same"]');
      await page.waitFor((n) => document.querySelectorAll('.zcmp-table tbody tr.dt-row').length === n, { args: [res.counts.same], message: 'same filter' });
      assertEqual(await cmpRows(), expectRows(res, 'same'), 'the same sets');
      await page.click('.zcmp-chips .zone-chip[data-filter="diff"]');
      assertEqual(await page.evaluate(() => window.__fakeDnsLog.length), sent.dns, 'no DNS query');
      assertEqual(await page.evaluate(() => window.__gp.calls.length), sent.gp, 'no Globalping call');
      assertEqual(external, [], 'no external request');
      assertEqual(await noZoneStorage(page), [], 'neither zone persisted');
      assert(/^#\/zone\?tab=compare$/.test(await page.evaluate(() => location.hash)), 'only the tab in the URL');
      await shot(page, opts, 'zone-compare-desktop-light-en');
    });

    await run.step('Compare options: TTLs, the SOA serial / timers and the apex NS left out from the keyboard; each row says what was hidden', async () => {
      for (const [role, options] of [['zcmp-opt-ignoreTtl', { ignoreTtl: true }], ['zcmp-opt-ignoreSoa', { ignoreTtl: true, ignoreSoa: true }],
        ['zcmp-opt-ignoreApexNs', { ignoreTtl: true, ignoreSoa: true, ignoreApexNs: true }]]) {
        await page.evaluate((r) => document.querySelector(`[data-role="${r}"]`).focus(), role);
        await page.press('Space');
        const res = ZD.diffZones(sampleZone('cloudflare'), sampleZone('route53'), options);
        await page.waitFor((n) => Number(document.querySelector('[data-role="zcmp-head"]')?.dataset.differences) === n,
          { args: [res.counts.added + res.counts.removed + res.counts.changed], message: role });
        assertEqual(await page.evaluate(() => document.activeElement?.dataset.role), role, `${role}: focus kept`);
        assertEqual(await cmpRows(), expectRows(res), `${role}: rows`);
      }
      await page.click('.zcmp-chips .zone-chip[data-filter="ignored"]');
      await page.waitFor(() => document.querySelectorAll('.zcmp-table tbody tr.dt-row').length === 1, { message: 'ignored filter' });
      assert(/NS at the apex, ignored/.test(await text(page, '.zcmp-table tbody tr.dt-row')), 'the ignored row says why');
      await page.click('.zcmp-chips .zone-chip[data-filter="diff"]');
      for (const role of ['zcmp-opt-ignoreTtl', 'zcmp-opt-ignoreSoa', 'zcmp-opt-ignoreApexNs']) await jsClick(page, `[data-role="${role}"]`);
      await page.waitFor((n) => Number(document.querySelector('[data-role="zcmp-head"]')?.dataset.differences) === n,
        { args: [ZD.diffZones(sampleZone('cloudflare'), sampleZone('route53')).rows.filter((r) => ZD.diffFilter(r)).length], message: 'options off again' });
    });

    await run.step('Compare: CSV / JSON exports hide the proxied origins until opted in; Copy summary names sets, never values', async () => {
      await takeDownloads(page);
      await page.click('.zcmp-table .dt-export [data-export="csv"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'CSV' });
      const [csv] = await takeDownloads(page);
      assertEqual(csv.name, 'example.com-compare.csv', 'CSV name');
      assert(csv.text.split('\n')[0].includes('status,name,type,ttl_a,ttl_b'), 'CSV header');
      for (const ip of ['192.0.2.10', '192.0.2.14']) assert(!csv.text.includes(ip), `${ip} redacted`);
      assert(csv.text.includes('[origin hidden]') && csv.text.includes('192.0.2.21'), 'origins hidden, other values kept');
      await jsClick(page, '[data-role="zcmp-include-origins"]');
      await page.click('.zcmp-table .dt-export [data-export="json"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'JSON' });
      const [json] = await takeDownloads(page);
      const doc = JSON.parse(json.text);
      assertEqual(Object.keys(doc), ['a', 'b', 'relative', 'options', 'counts', 'rows'], 'JSON keys');
      assert(json.text.includes('192.0.2.14'), 'origins included on opt-in');
      await jsClick(page, '[data-role="zcmp-include-origins"]');
      await stubClipboard(page);
      assertEqual(await page.evaluate(() => document.querySelector('.zcmp-summary')?.getAttribute('aria-label')), 'Summary of the comparison',
        'the comparison\'s Copy summary group is told apart from the zone\'s');
      await page.click('.zcmp-summary [data-action="copy-summary"]');
      await page.waitFor(() => window.__clip.length === 1, { message: 'copied' });
      const [md] = await takeClipboard(page);
      const ls = md.trim().split('\n');
      assertEqual(ls.slice(0, 2), ['**Zone File · `example.com` ↔ `example.com`**', '- This zone: Cloudflare export (BIND) · the other: AWS Route 53 (JSON)'], 'title and formats');
      assert(ls.some((l) => /^- \d+ added · \d+ removed · \d+ changed · \d+ record sets the same$/.test(l)), `counts: ${md}`);
      assert(ls.includes('- **Changed:** `@` A (values)') || ls.some((l) => l.startsWith('- **Changed:** `@`')), `a difference by name: ${md}`);
      assert(!/192\.0\.2\.|198\.51\.100\./.test(md), 'no value in the summary');
      assert(new RegExp(`· ${origin}/domainscope/#/zone$`).test(ls[ls.length - 1]), `a bare #/zone link: ${ls[ls.length - 1]}`);
    });

    /** Paste a second zone into the folded importer and compare. */
    const pasteOther = async (value) => {
      await page.evaluate((v) => {
        for (const d of document.querySelectorAll('.zcmp-loader-folded, .zcmp-paste')) d.open = true;
        const el = document.querySelector('[data-role="zcmp-paste"]');
        const ta = el.tagName === 'TEXTAREA' ? el : el.querySelector('textarea');
        ta.value = v;
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      }, value);
      await jsClick(page, '[data-action="zcmp-paste-run"]');
    };
    const copySummary = async () => {
      await stubClipboard(page);
      await page.click('.zcmp-summary [data-action="copy-summary"]');
      await page.waitFor(() => window.__clip.length === 1, { message: 'copied' });
      return (await takeClipboard(page))[0];
    };

    await run.step('Compare: a change batch is changes, not a zone: named after this zone, said in its bar and Copy summary, the sets it leaves alone never removed', async () => {
      // One UPSERT alone would name the batch after its record (api.example.com) and "remove" the rest.
      const batch = JSON.stringify({ Comment: 'one change', Changes: [{ Action: 'UPSERT', ResourceRecordSet: { Name: 'api.example.com.', Type: 'A', TTL: 300, ResourceRecords: [{ Value: '192.0.2.15' }] } }] });
      await pasteOther(batch);
      await page.waitFor(() => !!document.querySelector('[data-role="zcmp-batch"]'), { message: 'the change batch said' });
      assertEqual(await text(page, '.zcmp-other-title'), 'Compared with example.com', 'named after this zone, not after its one record');
      assert(/Route 53 change batch, not a whole zone \(created or updated: 1, deleted: 0\)/.test(await text(page, '[data-role="zcmp-batch"]')), await text(page, '[data-role="zcmp-batch"]'));
      const res = ZD.diffZones(sampleZone('cloudflare'), ZP.parseZone(batch, { origin: 'example.com' }));
      assertEqual([res.counts.removed, res.counts.changed, res.counts.ignored], [0, 1, 9], 'one change, nothing removed, the rest not in the batch');
      assertEqual(await cmpRows(), expectRows(res), 'the differences, as lib/zonediff.js finds them');
      await page.click('.zcmp-chips .zone-chip[data-filter="ignored"]');
      await page.waitFor(() => document.querySelectorAll('.zcmp-table tbody tr.dt-row').length === 9, { message: 'ignored filter' });
      assert(/Not in the change batch/.test(await text(page, '.zcmp-table tbody tr.dt-row')), 'an ignored row says why');
      await page.click('.zcmp-chips .zone-chip[data-filter="diff"]');
      const md = await copySummary();
      assert(md.includes('- The other file is a Route 53 change batch, not a whole zone (created or updated: 1, deleted: 0): only the record sets it changes were compared'), md);
      assert(!/192\.0\.2\.|198\.51\.100\./.test(md), 'no value in the summary');
    });

    await run.step('Compare: an incomplete export says so in its bar and Copy summary; each set it lacks may only be in the part that is missing', async () => {
      const page1 = JSON.stringify({ success: true, errors: [], messages: [], result: [
        { id: '1', zone_name: 'example.com', name: 'example.com', type: 'A', content: '192.0.2.10', proxied: true, ttl: 1 },
        { id: '2', zone_name: 'example.com', name: 'mail.example.com', type: 'A', content: '198.51.100.25', proxied: false, ttl: 1 }
      ], result_info: { page: 1, per_page: 2, count: 2, total_count: 11, total_pages: 6 } });
      await pasteOther(page1);
      await page.waitFor(() => !!document.querySelector('[data-role="zcmp-partial"]'), { message: 'the incomplete export said' });
      assert(!await page.evaluate(() => !!document.querySelector('[data-role="zcmp-batch"]')), 'no change batch now');
      const bar = await text(page, '[data-role="zcmp-partial"]');
      assert(/This export is incomplete/.test(bar) && /Only 2 records are in this export/.test(bar), bar);
      const res = ZD.diffZones(sampleZone('cloudflare'), ZP.parseZone(page1, { origin: 'example.com' }));
      assert(res.counts.removed > 0 && res.rows.filter((r) => r.status === 'removed').every((r) => r.notes.includes('partial')), 'every removed set carries the note');
      assertEqual(await cmpRows(), expectRows(res), 'the differences');
      const removedRow = await page.evaluate(() => [...document.querySelectorAll('.zcmp-table tbody tr.dt-row')].find((tr) => tr.querySelector('[data-status="removed"]'))?.textContent || '');
      assert(/may be in the part that is missing/.test(removedRow), `a removed row says the file is incomplete: ${removedRow}`);
      const md = await copySummary();
      assert(md.includes('- The other file is incomplete: a record set it lacks may only be in the part that is missing'), md);
      await shot(page, opts, 'zone-compare-partial-desktop-light-en');
    });

    await run.step('Compare: a long owner name wraps in its column: the table fits its card at 1280 and 1440 px', async () => {
      const long = `${'x'.repeat(60)}.${'y'.repeat(30)}`;
      await pasteOther(`$ORIGIN example.com.\n$TTL 300\n${long} 300 IN TXT "v=spf1 -all"\nwww 300 IN CNAME example.com.\n`);
      await page.waitFor((n) => [...document.querySelectorAll('.zcmp-table tbody tr.dt-row')].some((tr) => tr.textContent.includes(n)), { args: [long], message: 'the long name' });
      for (const width of [1280, 1440]) {
        await page.setViewport({ width, height: 900 });
        await page.waitFor(() => {
          const s = document.querySelector('.zcmp-table .dt-scroll');
          return !!s && s.scrollWidth <= s.clientWidth + 1;
        }, { timeout: 3000, message: `the table fits at ${width} px` }).catch(async (err) => {
          throw new Error(`${err.message}: ${JSON.stringify(await page.evaluate(() => {
            const s = document.querySelector('.zcmp-table .dt-scroll');
            return { sw: s.scrollWidth, cw: s.clientWidth, cols: [...document.querySelectorAll('.zcmp-table thead th')].map((th) => `${th.dataset.key}:${th.offsetWidth}`).join(' ') };
          }))}`);
        });
      }
      await page.setViewport({ width: 1440, height: 900 });
    });

    await run.step('Convert: BIND, Route 53, octoDNS and DNSControl as the library writes them, with their notes; each download reads back', async () => {
      await clickTab(page, 'convert');
      await page.waitFor(() => !!document.querySelector('[data-role="zconv"]'), { message: 'convert tab', timeout: 10000 });
      const zone = sampleZone('cloudflare');
      for (const target of ZC.CONVERT_TARGETS) {
        await page.click(`.zconv-targets [data-value="${target}"]`);
        await page.waitFor((t) => document.querySelector('[data-action="zconv-download"]')?.dataset.target === t, { args: [target], message: target });
        const res = ZC.convertZone(zone, target);
        const shown = await page.evaluate(() => [...document.querySelectorAll('.zconv-pitfall')].map((li) => `${li.dataset.severity}:${li.dataset.code}`));
        assertEqual(shown, res.pitfalls.map((p) => `${p.severity}:${p.code}`), `${target}: notes`);
        await takeDownloads(page);
        await page.click('[data-action="zconv-download"]');
        await page.waitFor(() => (window.__downloads || []).length === 1, { message: `${target} download` });
        const [dl] = await takeDownloads(page);
        assertEqual([dl.name, dl.text], [res.filename, res.text], `${target}: the file`);
        if (target !== 'dnscontrol') {
          const back = ZP.parseZone(dl.text, { origin: 'example.com', filename: dl.name });
          assert(!back.fatal, `${target}: reads back`);
          const gone = new Set([...res.omitted, ...res.changed].map((x) => x.id));
          const d = ZD.diffZones({ ...zone, records: zone.records.filter((r) => !gone.has(r.id)) }, { ...back, records: back.records.filter((r) => r.type !== 'ALIAS') });
          assertEqual(d.rows.filter((r) => r.status !== 'same').map((r) => r.key), [], `${target}: the same record sets`);
        }
      }
      assert(await page.evaluate(() => [...document.querySelectorAll('.zconv-pitfall')].some((li) => li.dataset.code === 'proxied')), 'the proxy note');
      await page.click('.zconv-targets [data-value="route53"]');
      await page.waitFor(() => document.querySelector('[data-action="zconv-download"]')?.dataset.target === 'route53', { message: 'route53' });
      assert(/Route 53 has none\. These names would point straight at their origin servers/.test(await text(page, '[data-role="zconv-pitfalls"]')), 'the Route 53 proxy warning');
      await stubClipboard(page);
      await page.click('.zconv-copy');
      await page.waitFor(() => window.__clip.length === 1, { message: 'copy all' });
      assertEqual((await takeClipboard(page))[0], ZC.convertZone(zone, 'route53').text, 'Copy all copies the whole file');
      assertEqual(external, [], 'no external request');
      await shot(page, opts, 'zone-convert-desktop-light-en');
    });

    await run.step('"Forget the second zone" keeps the first; Forget clears both', async () => {
      await clickTab(page, 'compare');
      await page.waitFor(() => !!document.querySelector('[data-role="zcmp-results"]'), { message: 'the comparison kept over the tabs' });
      await page.click('[data-action="zcmp-forget"]');
      await page.waitFor(() => !document.querySelector('[data-role="zcmp-results"]') && !!document.querySelector('[data-compare-sample]'), { message: 'second zone forgotten' });
      assert(await page.evaluate(() => !!document.querySelector('.zone-summary')), 'the first zone stays');
      await page.click('[data-compare-sample="bind"]');
      await page.waitFor(() => !!document.querySelector('[data-role="zcmp-results"]'), { message: 'compared again' });
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'forgotten' });
      await page.click('[data-sample="cloudflare"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'sample again' });
      await clickTab(page, 'compare');
      await page.waitFor(() => !!document.querySelector('[data-compare-sample]'), { message: 'importer', timeout: 10000 });
      assert(!await page.evaluate(() => !!document.querySelector('[data-role="zcmp-results"]')), 'Forget dropped the second zone too');
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'empty again' });
    });

    await run.step('Convert a zone over Route 53\'s batch limits: several change batches AWS takes, in order, each to download or copy', async () => {
      const big = ['$ORIGIN example.com.', '$TTL 300', ...Array.from({ length: 600 }, (_, i) => `h${i} A 192.0.2.${i % 250}`), ''].join('\n');
      await page.evaluate((v) => {
        document.querySelectorAll('.zone-import-folded, .zone-paste').forEach((d) => { d.open = true; });
        const el = document.querySelector('[data-role="zone-paste"]');
        const ta = el.tagName === 'TEXTAREA' ? el : el.querySelector('textarea');
        ta.value = v;
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      }, big);
      await page.click('[data-action="zone-paste-import"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'the big zone' });
      await clickTab(page, 'convert');
      await page.waitFor(() => !!document.querySelector('[data-role="zconv"]'), { message: 'convert tab', timeout: 10000 });
      await page.click('.zconv-targets [data-value="route53"]');
      await page.waitFor(() => document.querySelector('[data-role="zconv-files"]')?.dataset.count === '2', { message: 'two change batches' });
      const res = ZC.convertZone(ZP.parseZone(big, { format: 'bind' }), 'route53');
      assertEqual(res.files.map((f) => [f.filename, f.written]), [['example.com.route53.1.json', 500], ['example.com.route53.2.json', 100]], 'the library\'s batches');
      assert(/^Send them to Route 53 one after another, in this order:/.test(await text(page, '[data-role="zconv-files"]')), await text(page, '[data-role="zconv-files"]'));
      assert(await page.evaluate(() => [...document.querySelectorAll('.zconv-pitfall')].some((li) => li.dataset.code === 'batch-split')), 'the note says why');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('[data-action="zconv-download"]')].map((b) => b.getAttribute('aria-label'))),
        ['Download example.com.route53.1.json', 'Download example.com.route53.2.json'], 'each button names its file');
      await takeDownloads(page);
      await page.click('[data-action="zconv-download"][data-part="2"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'the second batch' });
      const [dl] = await takeDownloads(page);
      assertEqual([dl.name, dl.text], [res.files[1].filename, res.files[1].text], 'the second batch, as the library writes it');
      await stubClipboard(page);
      await page.click('.zconv-file[data-part="1"] .zconv-copy');
      await page.waitFor(() => window.__clip.length === 1, { message: 'copied' });
      assertEqual((await takeClipboard(page))[0], res.files[0].text, 'Copy copies its own file');
      assert(/^The preview shows the first 400 of the [\d,]+ lines of example\.com\.route53\.1\.json, the first of 2 files; its download and Copy have them all\.$/
        .test(await text(page, '[data-role="zconv-preview-note"]')), await text(page, '[data-role="zconv-preview-note"]'));
      await shot(page, opts, 'zone-convert-batches-desktop-light-en');
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'forgotten' });
    });

    await run.step('Compare: a new first zone reads the kept second file again — a one-record batch then takes the new zone\'s name', async () => {
      const pasteZone = async (value) => {
        await page.evaluate((v) => {
          document.querySelectorAll('.zone-import-folded, .zone-paste').forEach((d) => { d.open = true; });
          const el = document.querySelector('[data-role="zone-paste"]');
          const ta = el.tagName === 'TEXTAREA' ? el : el.querySelector('textarea');
          ta.value = v;
          ta.dispatchEvent(new Event('input', { bubbles: true }));
        }, value);
        await page.click('[data-action="zone-paste-import"]');
      };
      const title = () => page.evaluate(() => document.querySelector('.zcmp-other-title')?.textContent.trim() || '');
      await pasteZone('$ORIGIN example.org.\n$TTL 300\n@ 300 IN A 192.0.2.10\nwww 300 IN A 192.0.2.10\n');
      await page.waitFor(() => document.querySelector('.zone-summary-title')?.textContent === 'Zone example.org', { message: 'example.org' });
      await clickTab(page, 'compare');
      await page.waitFor(() => !!document.querySelector('.zcmp-drop'), { message: 'the second zone\'s importer', timeout: 10000 });
      await pasteOther(JSON.stringify({ Changes: [{ Action: 'UPSERT', ResourceRecordSet: { Name: 'www.example.com.', Type: 'A', TTL: 300, ResourceRecords: [{ Value: '192.0.2.99' }] } }] }));
      await page.waitFor(() => document.querySelector('.zcmp-other-title')?.textContent.trim() === 'Compared with www.example.com', { message: 'no name of example.org fits: the guess stays' });
      await pasteZone('$ORIGIN example.com.\n$TTL 300\n@ 300 IN A 192.0.2.10\nwww 300 IN A 192.0.2.10\n');
      await page.waitFor(() => document.querySelector('.zone-summary-title')?.textContent === 'Zone example.com', { message: 'example.com' });
      await clickTab(page, 'compare');
      await page.waitFor(() => !!document.querySelector('[data-role="zcmp-results"]'), { message: 'the comparison kept', timeout: 10000 });
      assertEqual(await title(), 'Compared with example.com', 'read again under the new first zone\'s name');
      const rows = await cmpRows();
      assert(rows.includes('changed www A') && !rows.some((r) => r.includes(' @ ')), `www compared with www, never with the apex: ${rows}`);
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'forgotten' });
    });

    await run.step('"Delete all local data" drops a loaded zone; a reload forgets it', async () => {
      await page.click('[data-sample="cloudflare"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'));
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.clearAll());
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'cleared' });
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.setInventory('web01 192.0.2.10').done);
      await page.click('[data-sample="bind"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'));
      await page.reload();
      await waitReady(page);
      await gotoRoute(page, 'zone');
      assert(!await page.evaluate(() => !!document.querySelector('.zone-summary')), 'reload forgets');
    });

    run.group('Fetch from deSEC / DigitalOcean (the provider APIs answered in the page)');
    const fetchState = () => page.evaluate(() => {
      const st = document.querySelector('.zone-fetch-status');
      const token = document.querySelector('[data-role="zone-fetch-token"]');
      return { state: st?.dataset.state || null, code: st?.dataset.code || null, text: st?.textContent || '', token: token ? token.value : null };
    });
    const typeFetch = async (domain, token) => {
      await page.type('[data-role="zone-fetch-domain"]', domain);
      await page.type('[data-role="zone-fetch-token"]', token);
    };

    await run.step('the panel: a password field, where the token goes and how to make it read-only; nothing sent before Fetch', async () => {
      await openFetch(page);
      const ui = await page.evaluate(() => {
        const tok = document.querySelector('[data-role="zone-fetch-token"]');
        return {
          type: tok.type, autocomplete: tok.getAttribute('autocomplete'), spellcheck: tok.getAttribute('spellcheck'),
          providers: [...document.querySelectorAll('.zone-fetch .seg-btn')].map((b) => b.dataset.value),
          privacy: document.querySelector('.zone-fetch-privacy')?.textContent || '',
          links: [...document.querySelectorAll('.zone-fetch-links a')].map((a) => [a.getAttribute('href'), a.getAttribute('rel'), a.target])
        };
      });
      assertEqual([ui.type, ui.autocomplete, ui.spellcheck], ['password', 'off', 'false'], 'token field');
      assertEqual(ui.providers, ['desec', 'digitalocean'], 'providers');
      assert(/only to desec\.io/.test(ui.privacy) && /never saved/.test(ui.privacy) && /never logged/.test(ui.privacy) && /emptied/.test(ui.privacy), `privacy: ${ui.privacy}`);
      assertEqual(ui.links.map((l) => l[0]), ['https://desec.io/tokens', 'https://desec.readthedocs.io/en/latest/auth/tokens.html#token-scoping-policies'], 'deSEC links');
      assert(ui.links.every((l) => /noopener/.test(l[1] || '') && l[2] === '_blank'), `links open apart: ${JSON.stringify(ui.links)}`);
      assert(/read-only/.test(await text(page, '.zone-fetch-how')), 'read-only advice');
      assertEqual(await page.evaluate(() => window.__prov.calls.length), 0, 'nothing sent');
      await shot(page, opts, 'zone-fetch-desktop-light-en');
    });

    await run.step('deSEC refuses a wrong token: 401 with deSEC\'s words, the field emptied, one request with the token in its header only', async () => {
      await typeFetch('example.com', `wrong-${FETCH_TOKEN}`);
      await page.click('[data-action="zone-fetch"]');
      await page.waitFor(() => document.querySelector('.zone-fetch-status')?.dataset.state === 'error', { message: 'error' });
      const st = await fetchState();
      assertEqual([st.code, st.token], ['auth', ''], 'code and empty field');
      assert(/did not accept the token \(HTTP 401\)/.test(st.text) && /deSEC said: “Invalid token\.”/.test(st.text) && /paste the token again/.test(st.text), st.text);
      const calls = await page.evaluate(() => window.__prov.calls);
      assertEqual(calls.map((c) => [c.url, c.scheme, c.tokenInUrl, c.credentials, c.redirect, c.referrerPolicy]),
        [['https://desec.io/api/v1/domains/example.com/rrsets/', 'Token', false, 'omit', 'error', 'no-referrer']], 'the request');
      assert(!(await keptAnywhere(page)).includes('wrong-'), 'the wrong token is nowhere');
      await shot(page, opts, 'zone-fetch-error-desktop-light-en');
    });

    await run.step('deSEC over 500 record sets: read type by type from the keyboard (Enter), imported as deSEC API with the zone name confirmed', async () => {
      await page.evaluate(() => { window.__prov.mode.desec = 'paged'; window.__prov.calls = []; });
      await page.type('[data-role="zone-fetch-token"]', FETCH_TOKEN);
      await page.press('Enter');
      await page.waitFor(() => /deSEC API/.test(document.querySelector('.zone-format-badge')?.textContent || ''), { timeout: 20000, message: 'imported' });
      assertEqual(await text(page, '.zone-summary-title'), 'Zone example.com', 'zone');
      assert(/deSEC API · example\.com/.test(await text(page, '.zone-files')), await text(page, '.zone-files'));
      assert(!await page.evaluate(() => !!document.querySelector('[data-action="zone-confirm"]')), 'the zone name asked for is taken as confirmed');
      const calls = await page.evaluate(() => window.__prov.calls);
      assertEqual(calls.map((c) => c.url.replace('https://desec.io/api/v1/domains/example.com/rrsets/', '')),
        ['', ...['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'CAA', 'SRV', 'HTTPS', 'SVCB', 'TLSA', 'DS'].map((t) => `?type=${t}`)], 'base, then types until all 21 are in');
      assert(calls.every((c) => c.tokenOk && !c.tokenInUrl), 'the token in every header, in no URL');
      assertEqual(await count(page, '.zone-partial'), 0, 'complete');
      const kept = await keptAnywhere(page);
      assert(!kept.includes(FETCH_TOKEN), 'the token is in no storage, IndexedDB store, session value, URL or the DOM');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="zone-fetch-token"]')?.value ?? ''), '', 'field empty');
      // The ledger names deSEC with what it got.
      const row = await page.evaluate(async () => {
        const { egressLog } = await import('./assets/js/ui/egress-meter.js');
        const { ledgerRows } = await import('./assets/js/lib/egress.js');
        const r = ledgerRows(egressLog.snapshot(), { origin: location.origin }).find((x) => x.serviceId === 'desec');
        return r ? { name: r.name, role: r.role, requests: r.requests, sends: r.sends } : null;
      });
      assertEqual(row, { name: 'deSEC', role: 'dnsHosting', requests: 14, sends: ['domains', 'apiToken'] }, 'ledger row (the refused request and the 13 of this fetch)');
    });

    await run.step('the fetched zone is analysed like a dropped one: records, problems and the live check', async () => {
      await clickTab(page, 'records');
      assert(/27/.test(await text(page, '[data-role="zone-counts"]')), await text(page, '[data-role="zone-counts"]'));
      await clickTab(page, 'problems');
      assert(await count(page, '.zone-problems-all > li') > 0, 'problems listed');
      await clickTab(page, 'live');
      await page.click('[data-action="zone-live-run"]');
      await page.waitFor(() => document.querySelector('.zone-drift')?.dataset.status === 'done', { timeout: 30000, message: 'live check done' });
    });

    await run.step('DigitalOcean: a token without domain:read says which scope is missing; then both pages, merged', async () => {
      await openFetch(page);
      await page.click('.zone-fetch .seg-btn[data-value="digitalocean"]');
      assert(/only to api\.digitalocean\.com/.test(await text(page, '.zone-fetch-privacy')), 'privacy names DigitalOcean');
      assert(/domain: read/.test(await text(page, '.zone-fetch-how')), 'scope advice');
      await page.evaluate(() => { window.__prov.mode.digitalocean = 'forbidden'; window.__prov.calls = []; });
      await page.type('[data-role="zone-fetch-token"]', FETCH_TOKEN);
      await page.click('[data-action="zone-fetch"]');
      await page.waitFor(() => document.querySelector('.zone-fetch-status')?.dataset.state === 'error', { message: 'error' });
      const st = await fetchState();
      assertEqual([st.code, st.token], ['forbidden', ''], 'forbidden');
      assert(/domain: read scope/.test(st.text), st.text);
      await page.evaluate(() => { window.__prov.mode.digitalocean = 'ok'; window.__prov.calls = []; });
      await page.type('[data-role="zone-fetch-token"]', FETCH_TOKEN);
      await page.click('[data-action="zone-fetch"]');
      await page.waitFor(() => /DigitalOcean API/.test(document.querySelector('.zone-format-badge')?.textContent || ''), { timeout: 20000, message: 'imported' });
      const calls = await page.evaluate(() => window.__prov.calls);
      assertEqual(calls.map((c) => [new URL(c.url).searchParams.get('page'), c.scheme, c.tokenOk]), [['1', 'Bearer', true], ['2', 'Bearer', true]], 'two pages');
      assert(/16/.test(await text(page, '[data-role="zone-counts"]')), await text(page, '[data-role="zone-counts"]'));
      assert(!(await keptAnywhere(page)).includes(FETCH_TOKEN), 'the token is nowhere');
    });

    await run.step('deSEC asks to slow down once: the wait is shown and the fetch goes on; Stop ends a slow one and imports nothing', async () => {
      await openFetch(page);
      await page.click('.zone-fetch .seg-btn[data-value="desec"]');
      await page.evaluate(() => { window.__prov.mode.desec = 'throttle-once'; window.__prov.throttled = false; window.__prov.calls = []; });
      await page.type('[data-role="zone-fetch-token"]', FETCH_TOKEN);
      await page.click('[data-action="zone-fetch"]');
      await page.waitFor(() => /waiting 1 s/.test(document.querySelector('.zone-fetch-status')?.textContent || ''), { message: 'the wait is shown' });
      await page.waitFor(() => /deSEC API/.test(document.querySelector('.zone-format-badge')?.textContent || ''), { timeout: 20000, message: 'imported after the wait' });
      assertEqual(await page.evaluate(() => window.__prov.calls.length), 2, 'asked again once');
      const files = await text(page, '.zone-files');
      await openFetch(page);
      await page.evaluate(() => { window.__prov.delayMs = 5000; window.__prov.mode.desec = 'ok'; });
      await page.type('[data-role="zone-fetch-token"]', FETCH_TOKEN);
      await page.click('[data-action="zone-fetch"]');
      await page.waitFor(() => !!document.querySelector('[data-action="zone-fetch-stop"]'), { message: 'running' });
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="zone-fetch-token"]').value), '', 'emptied while it runs');
      await page.click('[data-action="zone-fetch-stop"]');
      await page.waitFor(() => /Stopped\. Nothing was imported\./.test(document.querySelector('.zone-fetch-status')?.textContent || ''), { message: 'stopped' });
      await sleep(5500);
      assertEqual(await text(page, '.zone-files'), files, 'the loaded zone is unchanged');
      await page.evaluate(() => { window.__prov.delayMs = 0; });
    });

    await run.step('offline: Fetch zone says it needs the network, sends nothing and leaves the token in its field', async () => {
      const setOnline = async (on) => {
        await page.send('Network.emulateNetworkConditions', { offline: !on, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
        await page.waitFor((o) => navigator.onLine === o, { args: [on], message: `navigator.onLine ${on}` });
      };
      await openFetch(page);
      await page.evaluate(() => { window.__prov.calls = []; });
      await typeFetch('example.com', FETCH_TOKEN);
      await setOnline(false);
      try {
        await page.click('[data-action="zone-fetch"]');
        await page.waitFor(() => [...document.querySelectorAll('.toast')].some((x) => /this needs the network/.test(x.textContent)), { message: 'the offline toast' });
        const st = await fetchState();
        assert(!['running', 'error'].includes(st.state), `no fetch, no error: ${st.state}`);
        assertEqual(st.token, FETCH_TOKEN, 'the token kept for when the connection is back');
        assert(!await page.evaluate(() => !!document.querySelector('[data-action="zone-fetch-stop"]')), 'nothing running');
        assertEqual(await page.evaluate(() => window.__prov.calls.length), 0, 'nothing sent');
      } finally {
        await setOnline(true);
      }
      await page.evaluate(() => { document.querySelector('[data-role="zone-fetch-token"]').value = ''; });
    });

    await run.step('keyboard: the focus survives every repaint — the provider, the token field after an error, Stop through progress, Fetch after Stop', async () => {
      const active = () => page.evaluate(() => {
        const el = document.activeElement;
        if (!el) return null;
        return el.dataset.action || el.dataset.role || (el.classList.contains('seg-btn') ? `seg:${el.dataset.value}` : el.tagName.toLowerCase());
      });
      await openFetch(page);
      // The provider, picked from the keyboard: the focus stays on it.
      await page.evaluate(() => document.querySelector('.zone-fetch .seg-btn[data-value="digitalocean"]').focus());
      await page.press('Enter');
      await page.waitFor(() => /api\.digitalocean\.com/.test(document.querySelector('.zone-fetch-privacy')?.textContent || ''), { message: 'DigitalOcean picked' });
      assertEqual(await active(), 'seg:digitalocean', 'the focus stays on the provider');
      // DigitalOcean refuses a token (401): its own words, nothing about deSEC; the focus is back in the token field.
      await page.type('[data-role="zone-fetch-domain"]', 'example.com');
      await page.type('[data-role="zone-fetch-token"]', `wrong-${FETCH_TOKEN}`);
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.zone-fetch-status')?.dataset.code === 'auth', { message: 'auth error' });
      const auth = await fetchState();
      assert(/DigitalOcean did not accept the token \(HTTP 401\)/.test(auth.text) && !/deSEC/.test(auth.text), `DigitalOcean's 401 says nothing of deSEC: ${auth.text}`);
      assertEqual([auth.token, await active()], ['', 'zone-fetch-token'], 'emptied, and the focus there to paste it again');
      // A bad zone name with a token pasted: the token field was emptied too, and the message says so.
      await page.type('[data-role="zone-fetch-domain"]', 'not a zone');
      await page.type('[data-role="zone-fetch-token"]', FETCH_TOKEN);
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.zone-fetch-status')?.dataset.code === 'domain', { message: 'domain error' });
      const bad = await fetchState();
      assert(/Enter the zone name/.test(bad.text) && /The token field was emptied/.test(bad.text), `the token's fate is said: ${bad.text}`);
      assertEqual([bad.token, await active()], ['', 'zone-fetch-domain'], 'the focus on the field to fix');
      // A slow deSEC fetch started with Enter: the focus goes to Stop and stays there through the progress.
      await page.evaluate(() => document.querySelector('.zone-fetch .seg-btn[data-value="desec"]').click());
      await page.evaluate(() => { window.__prov.mode.desec = 'paged'; window.__prov.delayMs = 600; window.__prov.calls = []; });
      await page.type('[data-role="zone-fetch-domain"]', 'example.com');
      await page.type('[data-role="zone-fetch-token"]', FETCH_TOKEN);
      await page.press('Enter');
      await page.waitFor(() => document.activeElement?.dataset.action === 'zone-fetch-stop', { message: 'the focus on Stop' });
      await page.waitFor(() => window.__prov.calls.length >= 3 && /requests/.test(document.querySelector('.zone-fetch-status')?.textContent || ''), { timeout: 15000, message: 'progress shown' });
      assertEqual(await active(), 'zone-fetch-stop', 'still on Stop after the progress updates');
      await page.press('Enter');
      await page.waitFor(() => /Stopped\. Nothing was imported\./.test(document.querySelector('.zone-fetch-status')?.textContent || ''), { message: 'stopped' });
      assertEqual(await active(), 'zone-fetch', 'the focus on Fetch zone again');
      await page.evaluate(() => { window.__prov.delayMs = 0; window.__prov.mode.desec = 'ok'; });
      // Turkish: one "yeniden" when the token must be pasted again; the privacy line says "yalnızca" once.
      await setLangUi(page, 'tr');
      await openFetch(page);
      const privacy = await text(page, '.zone-fetch-privacy');
      assertEqual((privacy.match(/yalnızca/g) || []).length, 1, `TR privacy: ${privacy}`);
      await page.type('[data-role="zone-fetch-domain"]', 'example.com');
      await page.type('[data-role="zone-fetch-token"]', `wrong-${FETCH_TOKEN}`);
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.zone-fetch-status')?.dataset.state === 'error', { message: 'TR error' });
      const tr = await fetchState();
      assert(/tekrar denemek için anahtarı yeniden yapıştırın/.test(tr.text), `TR again: ${tr.text}`);
      await setLangUi(page, 'en');
    });

    await run.step('the zone typed in the panel is the customer\'s: another workspace and "Delete all local data" empty the field', async () => {
      const zoneField = () => page.evaluate(() => document.querySelector('[data-role="zone-fetch-domain"]')?.value ?? null);
      await openFetch(page);
      await page.type('[data-role="zone-fetch-domain"]', 'customer-a.example');
      const wsId = await page.evaluate(() => import('./assets/js/state.js').then(async ({ state }) => {
        const { meta } = await state.createWorkspace('Zone fetch e2e');
        await state.switchWorkspace(meta.id);
        return meta.id;
      }));
      await page.waitFor(() => !document.querySelector('.zone-summary') && !!document.querySelector('.zone-fetch'), { message: 'the switch emptied the view' });
      await openFetch(page);
      assertEqual(await zoneField(), '', 'another workspace: the last customer\'s zone is not in the field');
      await page.type('[data-role="zone-fetch-domain"]', 'customer-b.example');
      await page.evaluate((id) => import('./assets/js/state.js').then(async ({ state }) => {
        await state.switchWorkspace(state.workspaces.find((w) => w.isDefault).id);
        await state.deleteWorkspace(id);
      }), wsId);
      await openFetch(page);
      assertEqual(await zoneField(), '', 'back in Default: nothing typed in the other workspace');
      await page.type('[data-role="zone-fetch-domain"]', 'customer-a.example');
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.clearAll());
      await openFetch(page);
      assertEqual(await zoneField(), '', '"Delete all local data" empties the field');
      // A zone imported after that names the field again.
      await page.click('[data-sample="bind"]');
      await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'sample imported' });
      await openFetch(page);
      assertEqual(await zoneField(), 'example.com', 'the imported zone fills the empty field');
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.setInventory('web01 192.0.2.10').done);
    });

    await run.step('the fetch panel at 320 and 375 px, TR/EN × light/dark: no horizontal scroll', async () => {
      await page.click('[data-action="zone-forget"]');
      await page.waitFor(() => !document.querySelector('.zone-summary'), { message: 'empty' });
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await openFetch(page);
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          for (const width of [320, 375]) {
            await page.setViewport({ width, height: 800, mobile: true });
            await openFetch(page);
            await page.evaluate(() => document.querySelector('.zone-fetch').scrollIntoView());
            await assertNoHorizontalScroll(page, `fetch ${width} ${scheme} ${lang}`);
          }
          await shot(page, opts, `zone-fetch-mobile-${scheme}-${lang}`);
        }
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'en');
    });

    run.group('Phone 390×844 and Turkish / dark');
    await run.step('TR/EN × light/dark at 390 px on Overview, Origins and Live: no horizontal scroll', async () => {
      await page.setFileInput('.zone-drop .filedrop-input', [CF_FILE]);
      await page.waitFor(() => !!document.querySelector('.zone-summary'));
      await page.setViewport({ width: 390, height: 844, mobile: true });
      for (const lang of ['tr', 'en']) {
        await setLangUi(page, lang);
        await page.waitFor(() => !!document.querySelector('.zone-summary'), { message: 'zone kept after the language switch' });
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          for (const tab of ['overview', 'origins', 'live']) {
            await clickTab(page, tab);
            await page.evaluate(() => window.scrollTo(0, 0));
            await assertNoHorizontalScroll(page, `${tab} ${scheme} ${lang}`);
            await shot(page, opts, `zone-${tab}-mobile-${scheme}-${lang}`);
          }
        }
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'en');
    });

    await run.step('New name servers with results at 320 and 375 px, TR/EN × light/dark: no horizontal scroll', async () => {
      await clickTab(page, 'parity');
      await typeNs(NEW_NS.join('\n'));
      await page.waitFor(() => Number(document.querySelector('[data-role="par-plan"]')?.dataset.probes) > 0, { message: 'plan' });
      await page.click('[data-action="par-run"]');
      // "Delete all local data" also dropped the consent: the dialog again.
      await page.waitFor(() => !!document.querySelector('.gp-confirm') || !!document.querySelector('.par-results'), { message: 'dialog or results' });
      if (await page.evaluate(() => !!document.querySelector('.gp-confirm'))) await page.click('.gp-confirm .btn-primary');
      await page.waitFor(() => document.querySelector('.par-results')?.dataset.status === 'done', { timeout: 30000, message: 'compared again' });
      for (const lang of ['en', 'tr']) {
        await setLangUi(page, lang);
        await clickTab(page, 'parity');
        await page.waitFor(() => !!document.querySelector('.par-results'), { message: 'results kept after the language switch' });
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          for (const width of [320, 375]) {
            await page.setViewport({ width, height: 800, mobile: true });
            await page.evaluate(() => window.scrollTo(0, 0));
            await assertNoHorizontalScroll(page, `parity ${width} ${scheme} ${lang}`);
          }
          await shot(page, opts, `zone-parity-mobile-${scheme}-${lang}`);
        }
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'en');
    });

    await run.step('Compare and Convert at 320 and 375 px, TR/EN × light/dark: no horizontal scroll', async () => {
      await clickTab(page, 'compare');
      await page.waitFor(() => !!document.querySelector('[data-compare-sample="route53"]') || !!document.querySelector('[data-role="zcmp-results"]'), { message: 'compare tab', timeout: 10000 });
      if (!await page.evaluate(() => !!document.querySelector('[data-role="zcmp-results"]'))) {
        await page.click('[data-compare-sample="route53"]');
        await page.waitFor(() => !!document.querySelector('[data-role="zcmp-results"]'), { message: 'compared' });
      }
      for (const lang of ['en', 'tr']) {
        await setLangUi(page, lang);
        for (const tab of ['compare', 'convert']) {
          await clickTab(page, tab);
          await page.waitFor((t) => !!document.querySelector(t === 'compare' ? '[data-role="zcmp-results"]' : '[data-role="zconv"]'), { args: [tab], message: `${tab} after the language switch`, timeout: 10000 });
          for (const scheme of ['light', 'dark']) {
            await page.emulateMedia({ 'prefers-color-scheme': scheme });
            for (const width of [320, 375]) {
              await page.setViewport({ width, height: 800, mobile: true });
              await page.evaluate(() => window.scrollTo(0, 0));
              await assertNoHorizontalScroll(page, `${tab} ${width} ${scheme} ${lang}`);
            }
            await shot(page, opts, `zone-${tab}-mobile-${scheme}-${lang}`);
            await page.setViewport({ width: 1440, height: 900 });
          }
        }
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    await run.step('The second zone\'s notes at 320 and 375 px, TR/EN × light/dark: a guessed name, an incomplete export, its problems, a change batch', async () => {
      await clickTab(page, 'compare');
      const listing = JSON.stringify({ ResourceRecordSets: [
        { Name: 'www.example.net.', Type: 'A', TTL: 300, ResourceRecords: [{ Value: '192.0.2.10' }] },
        { Name: 'bad.example.net.', Type: 'A', TTL: 300 }
      ], IsTruncated: true, NextRecordName: 'zz.example.net.', NextRecordType: 'A' });
      const batch = JSON.stringify({ Changes: [
        { Action: 'UPSERT', ResourceRecordSet: { Name: 'api.example.com.', Type: 'A', TTL: 300, ResourceRecords: [{ Value: '192.0.2.15' }] } },
        { Action: 'DELETE', ResourceRecordSet: { Name: 'ftp.example.com.', Type: 'A', TTL: 1, ResourceRecords: [{ Value: '192.0.2.10' }] } }
      ] });
      const openProblems = () => page.evaluate(() => { for (const d of document.querySelectorAll('.zcmp-problems')) d.open = true; });
      for (const [label, value, roles] of [['listing', listing, ['zcmp-guessed', 'zcmp-partial']], ['batch', batch, ['zcmp-batch']]]) {
        await pasteOther(value);
        await page.waitFor((rs) => rs.every((r) => !!document.querySelector(`[data-role="${r}"]`)), { args: [roles], message: label });
        if (label === 'listing') {
          assertEqual(await text(page, '.zcmp-other-title'), 'Compared with example.net', 'names of another zone keep their guess');
          assert(await page.evaluate(() => !!document.querySelector('.zcmp-problems .zone-problem[data-code="BAD_RECORD"]')), 'the record it could not read is listed');
        } else {
          const rows = await cmpRows();
          assert(rows.includes('removed ftp A') && rows.includes('changed api A') && !rows.some((r) => r.startsWith('removed ') && r !== 'removed ftp A'), `only the DELETE is removed: ${rows}`);
        }
        for (const lang of ['en', 'tr']) {
          await setLangUi(page, lang);
          await page.waitFor((rs) => rs.every((r) => !!document.querySelector(`[data-role="${r}"]`)), { args: [roles], message: `${label} after the language switch`, timeout: 10000 });
          await openProblems();
          for (const scheme of ['light', 'dark']) {
            await page.emulateMedia({ 'prefers-color-scheme': scheme });
            for (const width of [320, 375]) {
              await page.setViewport({ width, height: 800, mobile: true });
              await page.evaluate(() => window.scrollTo(0, 0));
              await assertNoHorizontalScroll(page, `${label} ${width} ${scheme} ${lang}`);
            }
            await shot(page, opts, `zone-compare-${label}-mobile-${scheme}-${lang}`);
            await page.setViewport({ width: 1440, height: 900 });
          }
        }
        await page.emulateMedia({ 'prefers-color-scheme': 'light' });
        await setLangUi(page, 'en');
      }
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'zone', origin));
    await page.close();
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
