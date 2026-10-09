#!/usr/bin/env node
/**
 * global.e2e.mjs — end-to-end test of the "Global DNS" view in a real headless browser,
 * against the live public DoH resolvers (network required), after an offline part.
 *
 *   node tests/e2e/global.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--offline]
 *
 * Covers: pure helpers (Node), shared-link auto-run, streaming into pre-filled resolver and
 * location tables, answer groups (letters + colours) and group filtering, the worldwide IP
 * table with inventory matching, form validation, resolvers-only mode, the language re-mount
 * keeping results without re-querying, desktop + phone in light/dark, no horizontal page
 * scroll, no console errors / exceptions / CSP violations and no missing i18n keys.
 *
 * OFFLINE (always; alone with --offline): a fake DoH inside the page answers every query — the
 * mainland China locations' AliDNS questions in its JSON form (?name=&type=&edns_client_subnet=)
 * too — so the verdict (why answers differ: CDN / GeoDNS edges by design, or which part looks
 * like propagation or a misconfiguration), the operator on every answer group and the China row
 * group are checked with fixed answers, in EN / TR, light / dark, at 1440 px and 375 px, with
 * nothing leaving the page. A fake Globalping answers the ISP resolvers panel (ui/isp-resolvers.js):
 * the consent, a measurement through each probe's own resolver, one ISP still on the old address
 * ("Stale at 1 ISP resolver" with the TTL left), CloudFront edges at the ISPs (by design), the
 * quota, a Turkish re-mount that keeps the rows, and 375 px.
 *
 * Quad9 / Quad9 ECS (resolvers.js browserReliable:false): browsers use HTTP/3 for them and
 * Quad9's HTTP/3 answers carry no CORS header (tests/live/browser-doh-matrix.mjs), so their rows
 * must show the muted "Not readable in browsers" state with a dig command — never "Query failed"
 * — and the summary must say so without counting them as failures.
 *
 * Tolerated: network failures of FLAKY_HOSTS (every public resolver can time out; Control D
 * is unreachable from some networks), which the view reports in its UI.
 */

import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { stubClipboard, takeClipboard } from './scan.e2e.mjs';
import { groupAnswers, groupLetter, median, minAnswerTtl, splitChain, isBrowserBlocked, terminalCommand, GLOBAL_TYPES } from '../../assets/js/views/global.js';
import { RESOLVERS, ECS_RESOLVERS, GEO_VANTAGES } from '../../assets/js/lib/resolvers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SHOTS = path.join(HERE, 'screenshots');
const BASE = '/domainscope/';
const argv = process.argv.slice(2);
const optValue = (name, def) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : def;
};
const BROWSER = optValue('--browser', 'auto');
const HEADED = argv.includes('--headed');
const SHOTS_ON = !argv.includes('--no-shots');
const OFFLINE = argv.includes('--offline');
/** Third-party hosts whose request failures the view reports in its UI: every public DoH
 *  resolver can time out or, like Quad9 over HTTP/3, omit CORS headers. */
const FLAKY_HOSTS = [...RESOLVERS, ...ECS_RESOLVERS].map((r) => new URL(r.url).hostname);
const DONE = "document.querySelector('.glb-summary .alert') && document.querySelector('.glb-summary .alert').dataset.state !== 'running'";

/* ------------------------------------------------------------------------ */
/* Tiny runner                                                              */
/* ------------------------------------------------------------------------ */

const results = [];
const notes = [];
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
    process.stdout.write(`  FAIL  ${name}\n        ${String((err && err.stack) || err).split('\n').slice(0, 4).join('\n        ')}\n`);
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

async function waitReady(page) {
  await page.waitFor(() => document.documentElement.dataset.appReady === 'true', { timeout: 20000, message: 'app ready' });
}

async function gotoHash(page, hash, view) {
  // Wait for the hashchange to be handled, so a same-view navigation cannot race the checks below.
  await page.evaluate((hsh) => new Promise((resolve) => {
    if (window.location.hash === hsh) {
      resolve();
      return;
    }
    window.addEventListener('hashchange', () => setTimeout(resolve, 0), { once: true });
    window.location.hash = hsh;
  }), hash);
  await page.waitFor((v) => document.documentElement.dataset.view === v && document.querySelector('#page-body')?.dataset.view === v
    && document.querySelector('#page-body').childElementCount > 0 && !document.querySelector('#page-body .page-loading'),
  { args: [view], message: `view ${view}` });
}

async function assertNoHorizontalScroll(page, where) {
  const rep = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
  assert(rep.sw <= rep.cw + 1, `${where}: page scrolls horizontally (${rep.sw} > ${rep.cw})`);
}

async function shot(page, name) {
  if (!SHOTS_ON) return;
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((x) => x.remove()));
  await page.screenshot(path.join(SHOTS, `${name}.png`), { fullPage: true });
}

async function assertClean(page, where) {
  const p = await page.problems();
  const issues = [
    ...p.consoleErrors.map((m) => `console.${m.type}: ${m.text}`),
    ...p.exceptions.map((e) => `exception: ${e.text}`),
    ...p.csp.map((c) => `CSP: ${JSON.stringify(c).slice(0, 300)}`)
  ];
  for (const e of p.logErrors) {
    const text = `${e.text || ''} ${e.url || ''}`;
    if (FLAKY_HOSTS.some((host) => text.includes(`//${host}/`))) notes.push(`${where}: tolerated ${e.source} error for a flaky third-party host`);
    else issues.push(`log(${e.source}): ${e.text} ${e.url || ''}`);
  }
  assert(issues.length === 0, `${where}: ${issues.length} problem(s):\n          ${issues.join('\n          ')}`);
}

async function setLangUi(page, lang) {
  if (await page.evaluate(() => document.documentElement.lang) === lang) return;
  await page.click(`[data-control="lang"] [data-value="${lang}"]`);
  await page.waitFor((l) => document.documentElement.lang === l, { args: [lang], message: `lang ${lang}` });
  await page.waitFor(() => document.querySelector('#page-body')?.childElementCount > 0);
}

async function checkI18n(page) {
  const info = await page.evaluate(async () => {
    const i = await import('./assets/js/i18n.js');
    const en = i.listKeys('en').filter((k) => k.startsWith('glb.'));
    const tr = i.listKeys('tr').filter((k) => k.startsWith('glb.'));
    return { missing: i.getMissingKeys(), onlyEn: en.filter((k) => !tr.includes(k)), onlyTr: tr.filter((k) => !en.includes(k)) };
  });
  assertEqual(info.missing, [], 'missing i18n keys');
  assertEqual(info.onlyEn, [], 'glb.* keys only in EN');
  assertEqual(info.onlyTr, [], 'glb.* keys only in TR');
}

/* ------------------------------------------------------------------------ */
/* Page helpers                                                             */
/* ------------------------------------------------------------------------ */

function tableInfo() {
  const rows = (sel) => [...document.querySelectorAll(`${sel} tbody tr.dt-row`)];
  const res = rows('.glb-resolvers');
  const geo = rows('.glb-geo');
  return {
    resolvers: res.length,
    geo: geo.length,
    pending: document.querySelectorAll('.glb-row.is-pending').length,
    groups: [...document.querySelectorAll('.glb-legend .glb-chip')].map((c) => c.dataset.group),
    ips: document.querySelectorAll('.glb-ips tbody tr.dt-row').length,
    state: document.querySelector('.glb-summary .alert')?.dataset.state,
    failed: document.querySelectorAll('.glb-resolvers .glb-fail').length,
    unavailable: document.querySelectorAll('.glb-resolvers .glb-skip').length,
    // Quad9 rows (operator "Quad9 Foundation"): answered, or muted — never an error row.
    quad9: res.filter((tr) => tr.textContent.includes('Quad9 Foundation')).map((tr) => ({
      state: tr.querySelector('.glb-skip') ? 'unavailable' : tr.querySelector('.glb-fail') ? 'failed' : /NOERROR/.test(tr.textContent) ? 'answered' : 'other',
      muted: tr.classList.contains('is-unavailable'),
      cmd: tr.querySelector('.glb-skip-cmd code')?.textContent || null,
      label: tr.querySelector('.glb-skip .badge-text')?.textContent || null
    })),
    summary: document.querySelector('.glb-summary .alert')?.textContent || '',
    answeredHint: document.querySelector('.glb-stats .stat')?.textContent || '',
    errorChip: !!document.querySelector('.glb-legend .glb-chip[data-group="error"]'),
    cfStatus: res.find((tr) => tr.textContent.includes('Cloudflare, Inc.'))?.textContent || '',
    hash: window.location.hash
  };
}

/* ------------------------------------------------------------------------ */
/* Offline: the verdict over a fake DoH (no request leaves the page)        */
/* ------------------------------------------------------------------------ */

/** Resolver DoH URL → id, so the fake can answer per resolver (AliDNS: the JSON form). */
const RESOLVER_URLS = RESOLVERS.map((r) => [r.url, r.id]);
const JSON_URLS = ECS_RESOLVERS.map((r) => [r.url, r.id]);
/** The mainland China locations (asked through AliDNS) and what the China group shows for them. */
const CHINA = GEO_VANTAGES.filter((v) => v.group === 'cn');
/** The vantage whose /24 asks AliDNS once from outside China (the control). */
const CONTROL = GEO_VANTAGES.find((v) => v.id === ECS_RESOLVERS.find((r) => r.id === 'alidns').control);
/** Locations whose ECS queries get a SERVFAIL for mixed.example.com (Istanbul, Ankara). */
const SERVFAIL_SUBNETS = [GEO_VANTAGES[0].subnet, GEO_VANTAGES[1].subnet];

/**
 * Answers every DoH query inside the page (installed before the app loads):
 * - www.example.com: a steering CNAME (tp.edge.example.com) that sends most sources to
 *   CloudFront edges (several addresses) and some ECS locations through *.edgekey.net to
 *   Akamai — every answer differs by design;
 * - mixed.example.com: Cloudflare edges, but IIJ and CZ.NIC still return a direct address
 *   (203.0.113.10), DNS.SB answers NXDOMAIN and two locations SERVFAIL — a warning that names
 *   each part;
 * - moved.example.com: CNAME to one CloudFront distribution on Google, DNS.SB and every ECS
 *   location (Google answers those), to another one elsewhere — a change still propagating;
 * - stale / new / renamed.example.com: only one filtering resolver still has the old answer
 *   (Quad9 an address, Cloudflare Family NXDOMAIN, CleanBrowsing a CNAME), Tiarap REFUSES
 *   stale.example.com — stale caches, never taken for a filter's policy;
 * - search.example.com: Cloudflare Family rewrites it to forcesafesearch.google.com (SafeSearch),
 *   everyone else agrees — the filter's policy;
 * - example.org: Vercel's address at the apex, Netlify's on IIJ and CZ.NIC — a move between
 *   providers, not steering;
 * - steered.example.com: weighted records send each source to zone1 or zone2, both CNAMEs to
 *   the same Fastly name — steering in the name's own DNS, by design;
 * - nov6.example.com: a shared name steers to Fastly or Cloudflare; for AAAA every answer is
 *   empty (A records only), so only the CNAME chains are judged — by design;
 * - broken.example.com: SERVFAIL everywhere — nobody resolves it, never "agree";
 * - china.example.com: its DNS answers the mainland China subnets from a line of its own — a CNAME
 *   to Alibaba Cloud CDN — and everyone else, AliDNS on behalf of a subnet outside China (the
 *   control) included, with one CloudFront distribution: by design, the China rows' operator named;
 * - china-stale.example.com: AliDNS gives the Alibaba name whatever the subnet, the control too:
 *   its own answer, not China's line — a move between providers, as from any resolver;
 * - china-nocontrol.example.com: as china.example.com, but the control gets no answer: the China
 *   branch is told with a doubt and the TTL;
 * - china-servfail.example.com: AliDNS SERVFAILs for Shanghai: a failure, never "DNSSEC";
 * - china-anycast(-stale|-nocontrol).example.com: as china(-stale|-nocontrol), but the world is on
 *   Cloudflare's anycast addresses, so every resolver and location outside China agrees;
 * - china-bare.example.com: Fastly's anycast address everywhere, a bare Cloudflare-range address
 *   with no name in front only for the China rows: the shape of a forged answer;
 * - china-partner.example.com: as china.example.com, but Alibaba Cloud CDN hands the China rows on
 *   to a cache name nobody here knows: still different, worded as the CDN's possible partner;
 * - isp.example.com: the new address everywhere (the ISP resolvers group asks it of a fake Globalping);
 * - txt.example.com TXT: eight records; AliDNS would give three of them (it cuts large answers short
 *   without TC), so the China rows are not asked for TXT at all.
 * The China rows' questions reach AliDNS in its JSON form and are answered in it (recorded in
 * window.__jsonQueries); every other name answers them like the other locations.
 * An AAAA query gets the same answers without their A records.
 * Any other request to another origin gets a 503 and is recorded in window.__externalFetches.
 */
const fakeGlobalDnsScript = () => `(() => {
  const RESOLVER_URLS = ${JSON.stringify(RESOLVER_URLS)};
  const JSON_URLS = ${JSON.stringify(JSON_URLS)};
  const SERVFAIL_SUBNETS = ${JSON.stringify(SERVFAIL_SUBNETS)};
  const CN_SUBNETS = ${JSON.stringify(CHINA.map((v) => v.subnet))};
  const SHANGHAI = ${JSON.stringify(CHINA.find((v) => v.id === 'cn-sha-ct').subnet)};
  const OLD = '192.0.2.10';
  const NEW = '198.51.100.20';
  const CLOUDFRONT = ['13.32.0.10', '13.32.1.20', '13.33.2.30', '13.35.3.40'];
  const AKAMAI = ['2.16.10.10', '2.17.20.20'];
  const FASTLY = ['151.101.1.52', '151.101.65.52'];
  const hash = (s) => [...s].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);
  const cn = (name, data) => ({ name, type: 'CNAME', ttl: 60, data });
  const a = (name, data) => ({ name, type: 'A', ttl: 60, data });
  const answer = (qname, resolver, ecs) => {
    const h = hash(ecs || resolver);
    if (qname === 'www.example.com') {
      const head = [cn(qname, 'tp.edge.example.com')];
      if (ecs && h % 4 === 0) {
        return { answers: [...head, cn('tp.edge.example.com', 'www.example.com.edgekey.net'), cn('www.example.com.edgekey.net', 'e1.dsca.akamaiedge.net'), a('e1.dsca.akamaiedge.net', AKAMAI[h % 2])] };
      }
      return { answers: [...head, cn('tp.edge.example.com', 'cf.edge.example.com'), a('cf.edge.example.com', CLOUDFRONT[h % 4])] };
    }
    if (qname === 'mixed.example.com') {
      if (SERVFAIL_SUBNETS.includes(ecs)) return { rcode: 'SERVFAIL', answers: [] };
      if (resolver === 'dnssb') return { rcode: 'NXDOMAIN', answers: [] };
      if (resolver === 'iij' || resolver === 'cznic') return { answers: [a(qname, '203.0.113.10')] };
      return { answers: [a(qname, h % 2 ? '104.16.1.1' : '104.16.1.2')] };
    }
    if (qname === 'moved.example.com') {
      const target = resolver === 'google' || resolver === 'dnssb' ? 'd222222abcdef8.cloudfront.net' : 'd111111abcdef8.cloudfront.net';
      return { answers: [cn(qname, target), a(target, CLOUDFRONT[h % 4])] };
    }
    if (qname === 'stale.example.com') {
      if (resolver === 'tiar') return { rcode: 'REFUSED', answers: [] };
      return { answers: [a(qname, resolver === 'quad9' ? OLD : NEW)] };
    }
    if (qname === 'isp.example.com') return { answers: [a(qname, NEW)] };
    if (qname === 'new.example.com') {
      return resolver === 'cloudflare-family' ? { rcode: 'NXDOMAIN', answers: [] } : { answers: [a(qname, NEW)] };
    }
    if (qname === 'renamed.example.com') {
      const target = resolver === 'cleanbrowsing' ? 'old.example.net' : 'new.example.net';
      return { answers: [cn(qname, target), a(target, target === 'old.example.net' ? OLD : NEW)] };
    }
    if (qname === 'search.example.com') {
      if (resolver === 'cloudflare-family') return { answers: [cn(qname, 'forcesafesearch.google.com'), a('forcesafesearch.google.com', '192.0.2.99')] };
      return { answers: [a(qname, NEW)] };
    }
    if (qname === 'example.org') return { answers: [a(qname, resolver === 'iij' || resolver === 'cznic' ? '75.2.60.5' : '76.76.21.21')] };
    if (qname === 'steered.example.com') {
      const zone = (h % 2 ? 'zone1.' : 'zone2.') + qname;
      return { answers: [cn(qname, zone), cn(zone, 'h3.example.map.fastly.net'), a('h3.example.map.fastly.net', FASTLY[(h >>> 1) % 2])] };
    }
    if (qname === 'nov6.example.com') {
      const glb = 'glb.nov6.example.com';
      const [target, ip] = h % 3 ? ['example-dynamic.map.fastly.net', FASTLY[h % 2]] : ['nov6.example.com.cdn.cloudflare.net', '104.16.1.1'];
      return { answers: [cn(qname, glb), cn(glb, target), a(target, ip)] };
    }
    if (qname === 'broken.example.com') return { rcode: 'SERVFAIL', answers: [] };
    if (/^china(-stale|-nocontrol|-servfail)?\.example\.com$/.test(qname)) {
      const world = { answers: [cn(qname, 'd333333abcdef8.cloudfront.net'), a('d333333abcdef8.cloudfront.net', CLOUDFRONT[h % 4])] };
      if (resolver !== 'alidns') return world;
      if (qname === 'china-servfail.example.com') return ecs === SHANGHAI ? { rcode: 'SERVFAIL', answers: [] } : world;
      const inChina = CN_SUBNETS.includes(ecs);
      if (!inChina && qname === 'china-nocontrol.example.com') return { rcode: 'SERVFAIL', answers: [] };
      if (!inChina && qname !== 'china-stale.example.com') return world;
      const edge = qname + '.w.kunluncan.com';
      return { answers: [{ ...cn(qname, edge), ttl: 600 }, a(edge, h % 2 ? '198.51.100.17' : '198.51.100.18')] };
    }
    if (/^china-anycast(-stale|-nocontrol)?\.example\.com$/.test(qname)) {
      const edge = qname + '.cdn.cloudflare.net';
      const world = { answers: [cn(qname, edge), a(edge, '104.16.1.1')] };
      if (resolver !== 'alidns') return world;
      const inChina = CN_SUBNETS.includes(ecs);
      if (!inChina && qname === 'china-anycast-nocontrol.example.com') return { rcode: 'SERVFAIL', answers: [] };
      if (!inChina && qname === 'china-anycast.example.com') return world;
      const ali = qname + '.w.kunluncan.com';
      return { answers: [{ ...cn(qname, ali), ttl: 600 }, a(ali, h % 2 ? '198.51.100.17' : '198.51.100.18')] };
    }
    if (qname === 'china-bare.example.com') return { answers: [a(qname, resolver === 'alidns' && CN_SUBNETS.includes(ecs) ? '104.16.5.5' : FASTLY[0])] };
    if (qname === 'china-partner.example.com') {
      const world = { answers: [cn(qname, 'd444444abcdef8.cloudfront.net'), a('d444444abcdef8.cloudfront.net', CLOUDFRONT[h % 4])] };
      if (resolver !== 'alidns' || !CN_SUBNETS.includes(ecs)) return world;
      const ali = qname + '.w.kunluncan.com';
      return { answers: [cn(qname, ali), cn(ali, 'cache01.partner.example.net'), a('cache01.partner.example.net', '198.51.100.66')] };
    }
    if (qname === 'txt.example.com') {
      const all = ['example-verification=aaaa0001', 'example-verification=aaaa0002', 'example-verification=aaaa0003', 'example-verification=aaaa0004',
        'example-verification=aaaa0005', 'example-verification=aaaa0006', 'example-verification=aaaa0007', 'v=spf1 -all'];
      const list = resolver === 'alidns' ? all.slice(0, 3) : all;
      return { answers: list.map((v) => ({ name: qname, type: 'TXT', ttl: 300, data: [v] })) };
    }
    return { rcode: 'NXDOMAIN', answers: [] };
  };
  // The JSON form (AliDNS /resolve): the same answers, as AliDNS writes them.
  const JSON_TYPES = { A: 1, CNAME: 5, TXT: 16, AAAA: 28 };
  const RCODES = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 };
  window.__jsonQueries = [];
  const jsonAnswer = (url, resolver, init) => {
    const u = new URL(url);
    const qname = String(u.searchParams.get('name')).toLowerCase().replace(/[.]$/, '');
    const type = Number(u.searchParams.get('type'));
    const ecs = u.searchParams.get('edns_client_subnet');
    const headers = (init && init.headers) || {};
    window.__jsonQueries.push({ resolver, name: qname, type, ecs, accept: typeof headers.get === 'function' ? headers.get('accept') : headers.accept });
    const out = answer(qname, resolver, ecs);
    if (type === 28) out.answers = out.answers.filter((rr) => rr.type !== 'A');
    const rr = (x) => ({
      name: x.name + '.', TTL: x.ttl, type: JSON_TYPES[x.type],
      data: x.type === 'CNAME' ? x.data + '.' : x.type === 'TXT' ? x.data.map((v) => JSON.stringify(v)).join(' ') : x.data
    });
    return new Response(JSON.stringify({
      Status: RCODES[out.rcode || 'NOERROR'], TC: false, RD: true, RA: true, AD: false, CD: false,
      Question: { name: qname + '.', type }, ...(out.answers.length ? { Answer: out.answers.map(rr) } : {}),
      ...(ecs ? { edns_client_subnet: ecs } : {})
    }), { headers: { 'content-type': 'application/json' } });
  };
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.__externalFetches = [];
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const viaJson = JSON_URLS.find(([u]) => url.startsWith(u + '?'));
    if (viaJson) return jsonAnswer(url, viaJson[1], init);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (new URL(url, location.href).origin === location.origin) return realFetch(input, init);
      window.__externalFetches.push(url);
      return new Response('blocked by the E2E harness', { status: 503 });
    }
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const query = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1])));
    const q = query.questions[0];
    const resolver = (RESOLVER_URLS.find(([u]) => url.startsWith(u + '?')) || [null, 'unknown'])[1];
    const ecs = query.edns && query.edns.ecs ? query.edns.ecs.subnet : null;
    const out = answer(String(q.name).toLowerCase().replace(/[.]$/, ''), resolver, ecs);
    if (q.type === 'AAAA') out.answers = out.answers.filter((rr) => rr.type !== 'A');
    const edns = ecs ? { ecs: { address: ecs.split('/')[0], sourcePrefix: 24, scopePrefix: 24 } } : {};
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode || 'NOERROR',
      questions: [{ name: q.name, type: q.type }], answers: out.answers, edns
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/** Summary alert, verdict findings and the operator labels of the answer groups. */
function verdictInfo() {
  const alert = document.querySelector('.glb-summary .alert');
  return {
    state: alert?.dataset.state,
    title: alert?.querySelector('.alert-title')?.textContent || '',
    message: alert?.querySelector('.alert-message')?.textContent || '',
    findings: [...document.querySelectorAll('.glb-summary .glb-finding')].map((li) => ({
      code: li.dataset.finding, marks: [...li.querySelectorAll('.glb-mark')].map((m) => m.textContent), text: li.lastElementChild.textContent
    })),
    chips: [...document.querySelectorAll('.glb-legend .glb-chip')].map((c) => ({
      group: c.dataset.group, ops: [...c.querySelectorAll('.glb-chip-ops .glb-prov')].map((o) => o.textContent)
    })),
    groupsStat: document.querySelectorAll('.glb-stats .stat')[1]?.className || '',
    external: window.__externalFetches
  };
}

/** The verdict line of the Global DNS Copy summary (Markdown): its second line. */
async function copiedVerdict(page) {
  await stubClipboard(page);
  await page.click('[data-summary="global"] [data-action="copy-summary"]');
  await page.waitFor(() => window.__clip.length === 1, { message: 'summary copied' });
  return (await takeClipboard(page))[0].split('\n')[1];
}

async function offlineVerdicts(browser, server) {
  group('Offline: why answers differ (fake DoH, 1440 px and 375 px)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeGlobalDnsScript() });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  await setLangUi(page, 'en');

  await step('CDN edges that differ per source: "Differs by design" with the operators, operator on every group', async () => {
    await gotoHash(page, '#/global?name=www.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'by-design', `state (${info.title})`);
    assert(/^Differs by design: CDN \/ GeoDNS edges \(Amazon CloudFront, Akamai\)$/.test(info.title), `title: ${info.title}`);
    assert(/not propagation/.test(info.message) && /multi-CDN/.test(info.message), `body: ${info.message}`);
    assertEqual(info.findings, [], 'no findings');
    assert(info.chips.length >= 3 && info.chips.every((c) => c.ops.length === 1), `one operator per chip: ${JSON.stringify(info.chips)}`);
    assertEqual([...new Set(info.chips.map((c) => c.ops[0]))].sort(), ['Akamai', 'Amazon CloudFront'], 'chip operators');
    assert(/stat-v-info/.test(info.groupsStat), `distinct answers stat is info, not a warning: ${info.groupsStat}`);
    assertEqual(info.external, [], 'nothing left the page');
    await assertNoHorizontalScroll(page, 'by design');
    await shot(page, 'global-offline-desktop-light-en-by-design');
  });

  await step('mixed answers: a warning that names the SERVFAIL, the NXDOMAIN and the direct address', async () => {
    await gotoHash(page, '#/global?name=mixed.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'differ', 'state');
    assertEqual(info.title, 'Answers differ', 'title');
    assert(/The differences between Cloudflare edges are by design/.test(info.message), `design part: ${info.message}`);
    assertEqual(info.findings.map((f) => f.code), ['rcode', 'nxdomain', 'mixed'], 'finding codes');
    const [rcode, nx, mixed] = info.findings;
    assert(/^Istanbul, Türkiye; Ankara, Türkiye: SERVFAIL — /.test(rcode.text) && /DNSSEC/.test(rcode.text), `rcode: ${rcode.text}`);
    assert(/^DNS\.SB: NXDOMAIN/.test(nx.text), `nxdomain: ${nx.text}`);
    assert(/^IIJ Public DNS; CZ\.NIC ODVR: a direct address \(203\.0\.113\.10\) that is not on Cloudflare\./.test(mixed.text), `mixed: ${mixed.text}`);
    assert(info.findings.every((f) => f.marks.length === 1), `one group mark per finding: ${JSON.stringify(info.findings.map((f) => f.marks))}`);
    const direct = info.chips.find((c) => c.ops.includes('Direct'));
    assert(direct && mixed.marks[0] === direct.group, `the mixed finding points at the "Direct" group: ${JSON.stringify(info.chips)}`);
    assert(/stat-v-warn/.test(info.groupsStat), `distinct answers stat warns: ${info.groupsStat}`);
    await shot(page, 'global-offline-desktop-light-en-mixed');
  });

  await step('[dark, TR] the verdict is translated after a language re-mount (no re-query)', async () => {
    await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
    await setLangUi(page, 'tr');
    await page.waitFor(() => document.querySelector('.glb-summary .alert-title')?.textContent === 'Yanıtlar farklı', { message: 'TR verdict' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.findings.map((f) => f.code), ['rcode', 'nxdomain', 'mixed'], 'finding codes kept');
    assert(/doğrudan/.test(info.findings[2].text) && info.chips.some((c) => c.ops.includes('Doğrudan')), `TR texts: ${info.findings[2].text}`);
    await shot(page, 'global-offline-desktop-dark-tr-mixed');
    await gotoHash(page, '#/global?name=www.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000 });
    const design = await page.evaluate(verdictInfo);
    assert(/^Tasarım gereği farklı: CDN \/ GeoDNS uç sunucuları \(Amazon CloudFront, Akamai\)$/.test(design.title), `TR title: ${design.title}`);
    assert(/Bu sağlayıcılar/.test(design.message) && /Birden fazla sağlayıcı/.test(design.message), `TR body: ${design.message}`);
    await shot(page, 'global-offline-desktop-dark-tr-by-design');
    await gotoHash(page, '#/global?name=example.org&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000 });
    const move = await page.evaluate(verdictInfo);
    assert(/^example\.org adının A kayıtları kaynağa göre farklı sağlayıcıları gösteriyor \(Vercel, Netlify\)\./.test(move.findings[0]?.text || ''), `TR move: ${JSON.stringify(move.findings)}`);
    await setLangUi(page, 'en');
  });

  await step('another CloudFront distribution on some resolvers: the CNAME is named, not called steering', async () => {
    await gotoHash(page, '#/global?name=moved.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'differ', `state (${info.title})`);
    assertEqual(info.findings.map((f) => f.code), ['cname'], 'finding codes');
    const [f] = info.findings;
    assert(/^The record at moved\.example\.com differs between sources: CNAME d222222abcdef8\.cloudfront\.net · CNAME d111111abcdef8\.cloudfront\.net\./.test(f.text), `cname: ${f.text}`);
    assertEqual(f.marks, [], 'every group is on one side or the other: no marks that repeat the legend');
    assert(!/by design/.test(info.message), `no design part when the CNAME differs: ${info.message}`);
    assert(info.chips.every((c) => c.ops.join() === 'Amazon CloudFront'), `every group is still on CloudFront: ${JSON.stringify(info.chips)}`);
  });

  await step('an old answer only one filtering resolver still has stays a difference (Quad9 A, Cloudflare Family NXDOMAIN, CleanBrowsing CNAME)', async () => {
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    const check = async (name) => {
      await gotoHash(page, `#/global?name=${name}&type=A`, 'global');
      await page.waitFor(DONE, { timeout: 20000, message: `offline check done (${name})` });
      const info = await page.evaluate(verdictInfo);
      assertEqual(info.state, 'differ', `${name}: state (${info.title}: ${info.message})`);
      assert(/stat-v-warn/.test(info.groupsStat), `${name}: distinct answers stat warns: ${info.groupsStat}`);
      assert(!/SafeSearch/.test(info.message), `${name}: not called a rewrite: ${info.message}`);
      return info;
    };
    const quad9 = await check('stale.example.com');
    assertEqual(quad9.findings.map((f) => f.code), ['rcode', 'direct'], 'Quad9: finding codes');
    await shot(page, 'global-offline-desktop-light-en-stale-quad9');
    assert(/^Tiarap: REFUSED — the question was refused or could not be answered\./.test(quad9.findings[0].text) && !/DNSSEC/.test(quad9.findings[0].text), `REFUSED: ${quad9.findings[0].text}`);
    const family = await check('new.example.com');
    assertEqual(family.findings.map((f) => f.code), ['nxdomain'], 'Cloudflare Family: finding codes');
    assert(/^Cloudflare Family: NXDOMAIN/.test(family.findings[0].text) && /they may also be blocking the name\.$/.test(family.findings[0].text), `nxdomain: ${family.findings[0].text}`);
    const clean = await check('renamed.example.com');
    assertEqual(clean.findings.map((f) => f.code), ['cname'], 'CleanBrowsing: finding codes');
    assert(/^The record at renamed\.example\.com differs between sources: CNAME new\.example\.net · CNAME old\.example\.net\./.test(clean.findings[0].text), `cname: ${clean.findings[0].text}`);
  });

  await step('a SafeSearch rewrite by Cloudflare Family is its policy: the others agree', async () => {
    await gotoHash(page, '#/global?name=search.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'agree', `state (${info.title})`);
    assert(/Cloudflare Family: a SafeSearch rewrite \(forcesafesearch\.google\.com\), the policy of these filtering resolvers/.test(info.message), `body: ${info.message}`);
    assert(/stat-v-info/.test(info.groupsStat), `distinct answers stat is info: ${info.groupsStat}`);
  });

  await step('Netlify → Vercel at the apex: a move between providers, not "by design"', async () => {
    await gotoHash(page, '#/global?name=example.org&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'differ', `state (${info.title})`);
    assertEqual(info.findings.map((f) => f.code), ['operators'], 'finding codes');
    assert(/^The A records of example\.org point to different providers depending on the source \(Vercel, Netlify\)\. A move between them that is still propagating/.test(info.findings[0].text), `operators: ${info.findings[0].text}`);
    assert(!/by design/.test(info.message), `no design part: ${info.message}`);
    assertEqual(info.chips.map((c) => c.ops.join()), ['Vercel', 'Netlify'], 'chip operators');
    assertEqual(info.external, [], 'nothing left the page');
    await shot(page, 'global-offline-desktop-light-en-move');
  });

  await step('weighted records before one Fastly name: by design, and the steering is named', async () => {
    await gotoHash(page, '#/global?name=steered.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'by-design', `state (${info.title}: ${info.message})`);
    assertEqual(info.title, 'Differs by design: CDN / GeoDNS edges (Fastly)', 'title');
    assert(/^Every answer is an edge .* On the way, steered\.example\.com sends sources to different names \(zone[12]\.steered\.example\.com, zone[12]\.steered\.example\.com\), but they lead to the same CDN names: weighted or load-balanced records/.test(info.message), `body: ${info.message}`);
    assertEqual(info.findings, [], 'no findings');
    assert(info.chips.every((c) => c.ops.join() === 'Fastly'), `every group on Fastly: ${JSON.stringify(info.chips)}`);
    assert(/stat-v-info/.test(info.groupsStat), `distinct answers stat is info: ${info.groupsStat}`);
  });

  await step('AAAA with no records anywhere: the CNAME chains to Fastly or Cloudflare differ by design', async () => {
    await gotoHash(page, '#/global?name=nov6.example.com&type=AAAA', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'by-design', `state (${info.title}: ${info.message})`);
    assertEqual(info.title, 'No AAAA records anywhere — the CNAME chains differ by design (Fastly, Cloudflare)', 'title');
    assert(/^No source returns AAAA records for this name\./.test(info.message) && /multi-CDN/.test(info.message), `body: ${info.message}`);
    assertEqual(info.chips.map((c) => c.ops.join()), ['Fastly', 'Cloudflare'], 'operator next to each empty answer');
    assert(/stat-v-info/.test(info.groupsStat), `distinct answers stat is info: ${info.groupsStat}`);
    // The A answers of the same name: edges of two CDNs behind one shared name.
    await gotoHash(page, '#/global?name=nov6.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const a = await page.evaluate(verdictInfo);
    assertEqual([a.state, a.title], ['by-design', 'Differs by design: CDN / GeoDNS edges (Fastly, Cloudflare)'], 'A verdict');
    await shot(page, 'global-offline-desktop-light-en-nov6');
  });

  await step('mainland China: AliDNS rows in a group of their own; a CDN only there is by design, its operator named (EN / TR)', async () => {
    await page.evaluate(() => { window.__jsonQueries.length = 0; });
    await gotoHash(page, '#/global?name=china.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'by-design', `state (${info.title}: ${info.message})`);
    assertEqual(info.title, 'Differs by design: CDN / GeoDNS edges (Amazon CloudFront, Alibaba Cloud CDN)', 'title');
    assert(/^Every answer is an edge .* china\.example\.com sends Beijing, China; Shanghai, China; Guangzhou, China to CNAME china\.example\.com\.w\.kunluncan\.com, unlike every other source\. Asked on behalf of a subnet outside China, AliDNS gives the rest of the world.s answer: .*mainland China/.test(info.message),
      `body: ${info.message}`);
    assert(!/multi-CDN/.test(info.message), `a CDN only mainland China gets is not called multi-CDN steering: ${info.message}`);
    assertEqual(info.findings, [], 'no findings');
    assert(info.chips.some((c) => c.ops.join() === 'Alibaba Cloud CDN') && info.chips.some((c) => c.ops.join() === 'Amazon CloudFront'),
      `the chips name both operators: ${JSON.stringify(info.chips)}`);
    assert(/stat-v-info/.test(info.groupsStat), `distinct answers stat is info: ${info.groupsStat}`);
    assertEqual(info.external, [], 'nothing left the page');
    const cn = await page.evaluate(() => {
      const group = document.querySelector('.glb-geo .glb-geo-group[data-group="cn"]');
      const rows = [...(group ? group.querySelectorAll('tbody tr.dt-row') : [])];
      return {
        title: group ? group.querySelector('.glb-geo-group-title > span:not(.flag)').textContent.trim() : null,
        flagHidden: group ? group.querySelector('.glb-geo-group-title .flag').getAttribute('aria-hidden') : null,
        rows: rows.map((tr) => ({
          via: tr.querySelector('.glb-via')?.textContent,
          scope: tr.querySelector('.dt-null')?.getAttribute('title') || null,
          ops: [...tr.querySelectorAll('.glb-ops .badge-text')].map((b) => b.textContent),
          text: tr.textContent
        })),
        mainCn: [...document.querySelectorAll('.glb-geo tbody tr.dt-row')].filter((tr) => !tr.closest('.glb-geo-group') && /China/.test(tr.textContent)).length,
        desc: group ? group.querySelector('.section-desc')?.textContent || '' : '',
        queries: window.__jsonQueries
      };
    });
    assertEqual([cn.title, cn.flagHidden], ['Mainland China', 'true'], 'group title, its flag decorative');
    assert(/For A and AAAA it is also asked once on behalf of a US subnet, to tell a China line from an older answer./.test(cn.desc), `the note names the control question: ${cn.desc}`);
    assertEqual(cn.rows.length, 3, 'three China rows');
    assertEqual(cn.mainCn, 0, 'no China row in the main location table');
    assert(cn.rows.every((r) => r.via === 'AliDNS (ECS)' && r.scope === 'Not reported' && r.ops.some((o) => /Alibaba Cloud CDN/.test(o))), `AliDNS, no ECS scope, Alibaba Cloud CDN on each row: ${JSON.stringify(cn.rows.map(({ text, ...r }) => r))}`);
    assert(['Beijing', 'Shanghai', 'Guangzhou'].every((c) => cn.rows.some((r) => r.text.includes(c))), 'the three cities');
    const bySubnet = (a, b) => (a[3] < b[3] ? -1 : a[3] > b[3] ? 1 : 0);
    assertEqual(cn.queries.map((q) => [q.resolver, q.name, q.type, q.ecs, q.accept]).sort(bySubnet),
      [...CHINA.map((v) => v.subnet), CONTROL.subnet].map((subnet) => ['alidns', 'china.example.com', 1, subnet, 'application/dns-json']).sort(bySubnet),
      'one JSON question to AliDNS per China row, with its subnet, and one on behalf of a subnet outside China');
    await assertNoHorizontalScroll(page, 'china');
    await shot(page, 'global-offline-desktop-light-en-china');
    await setLangUi(page, 'tr');
    await page.waitFor(() => /^Tasarım gereği farklı/.test(document.querySelector('.glb-summary .alert-title')?.textContent || ''), { message: 'TR verdict' });
    const tr = await page.evaluate(() => ({
      title: document.querySelector('.glb-geo-group[data-group="cn"] .glb-geo-group-title > span:not(.flag)')?.textContent.trim(),
      desc: document.querySelector('.glb-geo-group[data-group="cn"] .section-desc')?.textContent || '',
      message: document.querySelector('.glb-summary .alert-message')?.textContent || ''
    }));
    assertEqual(tr.title, 'Anakara Çin', 'TR group title');
    assert(/A ve AAAA için ayrıca bir kez ABD’deki bir alt ağ adına sorulur/.test(tr.desc), `TR note names the control question: ${tr.desc}`);
    assert(/Pekin, Çin; Şanghay, Çin; Guangzhou, Çin konumlarını diğer tüm kaynaklardan farklı bir yere \(CNAME china\.example\.com\.w\.kunluncan\.com\) gönderiyor/.test(tr.message), `TR body: ${tr.message}`);
    await setLangUi(page, 'en');
  });

  await step('mainland China: a branch AliDNS gives outside China too is its own answer, a move as from any resolver; no control answer: told with a doubt and the TTL', async () => {
    await gotoHash(page, '#/global?name=china-stale.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const stale = await page.evaluate(verdictInfo);
    assertEqual(stale.state, 'differ', `stale: state (${stale.title}: ${stale.message})`);
    assertEqual(stale.findings.map((f) => f.code), ['cname'], 'stale: finding codes');
    assert(/points to different providers depending on the source \(Amazon CloudFront, Alibaba Cloud CDN\)/.test(stale.findings[0].text), `stale: the move: ${stale.findings[0].text}`);
    await gotoHash(page, '#/global?name=china-nocontrol.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const unsure = await page.evaluate(verdictInfo);
    assertEqual(unsure.state, 'by-design', `unsure: state (${unsure.title}: ${unsure.message})`);
    assertEqual(unsure.title, 'Most likely by design: CDN / GeoDNS edges (Amazon CloudFront, Alibaba Cloud CDN)', 'unsure: a hedged title');
    assertEqual(await copiedVerdict(page), '- Most likely by design: CDN / GeoDNS edges (Amazon CloudFront, Alibaba Cloud CDN); AliDNS may still hold an older answer for mainland China',
      'unsure: a hedged Copy summary');
    assert(/sends Beijing, China; Shanghai, China; Guangzhou, China to CNAME china-nocontrol\.example\.com\.w\.kunluncan\.com, unlike every other source: either .* a line of its own .*, or AliDNS still holds an older answer — that would expire within 10 min\. AliDNS asked on behalf of a subnet outside China could not tell the two apart\./.test(unsure.message),
      `unsure: the doubt and the TTL: ${unsure.message}`);
    await setLangUi(page, 'tr');
    await page.waitFor(() => /eski bir yanıt/.test(document.querySelector('.glb-summary .alert-message')?.textContent || ''), { message: 'TR doubt' });
    assertEqual(await page.evaluate(() => document.querySelector('.glb-summary .alert-title')?.textContent), 'Büyük olasılıkla tasarım gereği farklı: CDN / GeoDNS uç sunucuları (Amazon CloudFront, Alibaba Cloud CDN)', 'TR hedged title');
    await setLangUi(page, 'en');
    assertEqual([stale.external, unsure.external], [[], []], 'nothing left the page');
  });

  await step('mainland China when every resolver agrees (anycast): the China branch still needs the control, a bare CDN address there is never GeoDNS', async () => {
    const check = async (name) => {
      await gotoHash(page, `#/global?name=${name}&type=A`, 'global');
      await page.waitFor(DONE, { timeout: 20000, message: `${name}: offline check done` });
      return page.evaluate(verdictInfo);
    };
    // The control gets the world's Cloudflare answer: China's line, GeoDNS, told as such.
    const line = await check('china-anycast.example.com');
    assertEqual([line.state, line.title], ['geo', 'Resolvers agree — locations differ'], `line: ${line.message}`);
    assert(/china-anycast\.example\.com sends Beijing, China; Shanghai, China; Guangzhou, China to CNAME china-anycast\.example\.com\.w\.kunluncan\.com, unlike every other source\. Asked on behalf of a subnet outside China, AliDNS gives the rest of the world.s answer/.test(line.message),
      `line: the split told: ${line.message}`);
    // The control gets China's branch too: AliDNS's own older answer, a move from Alibaba Cloud CDN to Cloudflare.
    const stale = await check('china-anycast-stale.example.com');
    assertEqual([stale.state, stale.findings.map((f) => f.code)], ['differ', ['cname']], `stale: ${stale.title}: ${stale.message}`);
    assert(/points to different providers depending on the source \(Cloudflare, Alibaba Cloud CDN\)/.test(stale.findings[0].text), `stale: the move: ${stale.findings[0].text}`);
    // No control answer: likely GeoDNS, never certain — the title, the body and the Copy summary say so.
    const unsure = await check('china-anycast-nocontrol.example.com');
    assertEqual([unsure.state, unsure.title], ['geo', 'Resolvers agree — locations differ, most likely by GeoDNS'], `unsure: ${unsure.message}`);
    assert(/one difference is not certain: .*either a line of its own for the resolvers in mainland China .*, or an older answer AliDNS still holds — that would expire within 10 min\./.test(unsure.message),
      `unsure: the doubt and the TTL: ${unsure.message}`);
    assertEqual(await copiedVerdict(page), '- Resolvers agree — locations differ, most likely by GeoDNS; AliDNS may still hold an older answer for mainland China', 'unsure: Copy summary');
    await setLangUi(page, 'tr');
    await page.waitFor(() => document.querySelector('.glb-summary .alert-title')?.textContent === 'Çözümleyiciler aynı — konumlar büyük olasılıkla GeoDNS yüzünden farklı', { message: 'TR hedged geo title' });
    assertEqual(await copiedVerdict(page), '- Çözümleyiciler aynı — konumlar büyük olasılıkla GeoDNS yüzünden farklı; AliDNS anakara Çin için hâlâ eski bir yanıtı tutuyor olabilir', 'TR Copy summary');
    await setLangUi(page, 'en');
    // A bare Cloudflare-range address only in China while the world gets Fastly's anycast address.
    const bare = await check('china-bare.example.com');
    assertEqual([bare.state, bare.findings.map((f) => f.code)], ['differ', ['operators']], `bare: ${bare.title}: ${bare.message}`);
    assert(/point to different providers depending on the source \(Fastly, Cloudflare\)/.test(bare.findings[0].text), `bare: ${bare.findings[0].text}`);
    assertEqual([line.external, stale.external, unsure.external, bare.external], [[], [], [], []], 'nothing left the page');
  });

  await step('mainland China: a CDN handing over to a cache name nobody knows still differs, and the finding says it may be the partner (EN / TR)', async () => {
    await gotoHash(page, '#/global?name=china-partner.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'differ', `the verdict is kept (${info.title}: ${info.message})`);
    assertEqual(info.findings.map((f) => f.code), ['cname'], 'one finding');
    const partner = await page.evaluate(() => document.querySelector('.glb-summary .glb-finding[data-partner="true"]')?.lastElementChild.textContent || '');
    assertEqual(partner, 'Beijing, China; Shanghai, China; Guangzhou, China: the China answer ends at a cache name this tool does not recognise '
      + '(cache01.partner.example.net), after Alibaba Cloud CDN; it may be the CDN’s partner. It is not counted as the CDN’s own edge, so the answers still differ.', 'worded as a partner');
    assertEqual(info.findings[0].marks.length, 1, 'marked with the China group only');
    await stubClipboard(page);
    await page.click('[data-summary="global"] [data-action="copy-summary"]');
    await page.waitFor(() => window.__clip.length === 1, { message: 'summary copied' });
    const copied = (await takeClipboard(page))[0];
    assert(copied.includes('\n- The China answer ends at a cache name not recognised, maybe the CDN’s partner (3 sources)\n'), `Copy summary: ${copied}`);
    await shot(page, 'global-offline-desktop-light-en-china-partner');
    await page.setViewport({ width: 375, height: 812, mobile: true });
    await shot(page, 'global-offline-mobile-light-en-china-partner');
    await page.setViewport({ width: 1440, height: 900 });
    await setLangUi(page, 'tr');
    const tr = await page.waitFor(() => {
      const text = document.querySelector('.glb-summary .glb-finding[data-partner="true"]')?.lastElementChild.textContent || '';
      return /iş ortağı olabilir/.test(text) ? text : false;
    }, { message: 'TR partner finding' });
    assertEqual(tr, 'Pekin, Çin; Şanghay, Çin; Guangzhou, Çin: Çin’deki yanıt, Alibaba Cloud CDN üzerinden geçtikten sonra bu aracın tanımadığı bir önbellek adında '
      + '(cache01.partner.example.net) bitiyor; bu CDN’in iş ortağı olabilir. CDN’in kendi uç sunucusu sayılmadığı için yanıtlar yine farklı görünüyor.', 'TR wording');
    await setLangUi(page, 'en');
    assertEqual(info.external, [], 'nothing left the page');
  });

  await step('mainland China: an AliDNS SERVFAIL is a failure there, never a DNSSEC validation failure', async () => {
    await gotoHash(page, '#/global?name=china-servfail.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    const f = info.findings.find((x) => x.code === 'rcode');
    assert(f && /^Shanghai, China: SERVFAIL/.test(f.text), `the SERVFAIL finding: ${JSON.stringify(info.findings)}`);
    assert(!/DNSSEC validation failure/.test(f.text) && /AliDNS does not validate DNSSEC/.test(f.text), `no DNSSEC blame: ${f.text}`);
  });

  await step('TXT: the China rows are not asked — AliDNS cuts large answers short without saying so — and nothing is sent to it', async () => {
    await page.evaluate(() => { window.__jsonQueries.length = 0; });
    await gotoHash(page, '#/global?name=txt.example.com&type=TXT', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    const rows = await page.evaluate(() => [...document.querySelectorAll('.glb-geo-group[data-group="cn"] tbody tr.dt-row')].map((tr) => ({
      muted: tr.classList.contains('is-unavailable'), text: tr.querySelector('.glb-skip')?.textContent || '', mark: tr.querySelector('.glb-mark')?.textContent
    })));
    assertEqual(info.state, 'agree', `state (${info.title}: ${info.message})`);
    assert(/Beijing, China; Shanghai, China; Guangzhou, China: not asked for TXT/.test(info.message), `the summary says why: ${info.message}`);
    assertEqual(rows.length, 3, 'three China rows');
    assert(rows.every((r) => r.muted && /Not asked/.test(r.text) && /cuts large answers short/.test(r.text)), `muted, with the reason: ${JSON.stringify(rows)}`);
    assertEqual(await page.evaluate(() => window.__jsonQueries.length), 0, 'no question to AliDNS, not even the control');
    const answered = await page.evaluate(() => document.querySelector('.glb-stats .stat')?.textContent || '');
    assert(/43 \/ 43/.test(answered) && /3 not asked/.test(answered), `the answered stat leaves them out and says so: ${answered}`);
    await setLangUi(page, 'tr');
    await page.waitFor(() => /Sorulmadı/.test(document.querySelector('.glb-geo-group[data-group="cn"] .glb-skip')?.textContent || ''), { message: 'TR not asked' });
    await setLangUi(page, 'en');
    await assertNoHorizontalScroll(page, 'txt');
  });

  await step('SERVFAIL everywhere: an error, never "All answers agree" (EN / TR)', async () => {
    await gotoHash(page, '#/global?name=broken.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'offline check done' });
    const info = await page.evaluate(verdictInfo);
    assertEqual(info.state, 'unresolved', `state (${info.title})`);
    assertEqual(info.title, 'No source could resolve the name', 'title');
    assertEqual(info.findings.map((f) => f.code), ['rcode'], 'finding codes');
    assert(/: SERVFAIL — no answer at all, typically a DNSSEC validation failure or name servers that cannot be reached\./.test(info.findings[0].text), `servfail: ${info.findings[0].text}`);
    assert(/stat-v-error/.test(info.groupsStat), `distinct answers stat is an error: ${info.groupsStat}`);
    await setLangUi(page, 'tr');
    await page.waitFor(() => document.querySelector('.glb-summary .alert-title')?.textContent === 'Hiçbir kaynak adı çözümleyemedi', { message: 'TR unresolved title' });
    const tr = await page.evaluate(verdictInfo);
    assert(/ulaşılamayan ad sunucuları/.test(tr.findings[0].text), `TR servfail: ${tr.findings[0].text}`);
    await setLangUi(page, 'en');
  });

  await step('375 px phone: verdict and operator chips fit without horizontal scroll', async () => {
    await page.setViewport({ width: 375, height: 812, mobile: true });
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({ 'prefers-color-scheme': scheme });
      for (const name of ['www.example.com', 'example.org', 'china.example.com', 'china-anycast-nocontrol.example.com', 'mixed.example.com']) {
        await gotoHash(page, `#/global?name=${name}&type=A`, 'global');
        await page.waitFor(DONE, { timeout: 20000 });
        await assertNoHorizontalScroll(page, `375 px ${scheme} ${name}`);
        if (name === 'china.example.com') {
          // The China group: its heading, description and table stay inside the page width.
          const fit = await page.evaluate(() => {
            const g = document.querySelector('.glb-geo-group[data-group="cn"]');
            const r = g.getBoundingClientRect();
            return { left: r.left, right: r.right, width: document.documentElement.clientWidth, rows: g.querySelectorAll('tbody tr.dt-row').length };
          });
          assert(fit.left >= 0 && fit.right <= fit.width + 1 && fit.rows === 3, `375 px ${scheme}: the China group fits: ${JSON.stringify(fit)}`);
          await shot(page, `global-offline-mobile-${scheme}-en-china`);
        }
      }
      await shot(page, `global-offline-mobile-${scheme}-en-mixed`);
    }
  });

  await step('offline: no console errors, exceptions, CSP violations or missing keys', async () => {
    await checkI18n(page);
    await assertClean(page, 'offline verdicts');
  });
  await page.close();
}

/* ------------------------------------------------------------------------ */
/* Offline: ISP resolvers through a fake Globalping (ui/isp-resolvers.js)   */
/* ------------------------------------------------------------------------ */

/**
 * Fake Globalping v1 API for DNS measurements through the probes' own resolvers (outermost
 * window.fetch wrapper, installed after the fake DoH). Ten eyeball probes; per target:
 * isp.example.com — every probe on the new address except Istanbul, whose ISP still caches the
 * old one for 1,500 s; www.example.com — the steering chain to CloudFront edges (by design);
 * anything else NXDOMAIN. A GET right after the POST is still in progress (half the probes).
 * Knobs on window.__gpIsp: limitsRemaining (what /limits reports), calls (every request).
 */
const fakeIspGlobalpingScript = () => `(() => {
  const API = 'https://api.globalping.io/v1';
  const OLD = '192.0.2.10';
  const NEW = '198.51.100.20';
  const CLOUDFRONT = ['13.32.0.10', '13.32.1.20', '13.33.2.30', '13.35.3.40'];
  const PROBES = [
    ['EU', 'DE', 'Berlin', 3320, 'Deutsche Telekom AG'], ['EU', 'FR', 'Paris', 3215, 'Orange S.A.'], ['AS', 'TR', 'Istanbul', 209604, '2E Telekomunikasyon'],
    ['NA', 'US', 'Chicago', 7922, 'Comcast Cable Communications, LLC'], ['NA', 'CA', 'Toronto', 812, 'Rogers Communications Canada Inc.'],
    ['AS', 'JP', 'Tokyo', 2516, 'KDDI Corporation'], ['EU', 'GB', 'London', 2856, 'British Telecommunications PLC'],
    ['SA', 'BR', 'Sao Paulo', 28573, 'Claro NXT Telecomunicacoes Ltda'], ['OC', 'AU', 'Sydney', 1221, 'Telstra Limited'], ['AF', 'ZA', 'Johannesburg', 37457, 'Telkom SA Ltd']
  ].map(([continent, country, city, asn, network]) => ({ continent, region: '', country, state: null, city, asn, network, latitude: 0, longitude: 0, tags: ['eyeball-network'], resolvers: ['private'] }));
  const gp = window.__gpIsp = { calls: [], measurements: {}, n: 0, limitsRemaining: 250 };
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  const rr = (name, type, ttl, value) => ({ name: name + '.', type, ttl, class: 'IN', value });
  const test = (target, i) => {
    let answers;
    if (target === 'isp.example.com') answers = [i === 2 ? rr(target, 'A', 1500, OLD) : rr(target, 'A', 240, NEW)];
    else if (target === 'www.example.com') {
      answers = [rr(target, 'CNAME', 60, 'tp.edge.example.com.'), rr('tp.edge.example.com', 'CNAME', 60, 'cf.edge.example.com.'), rr('cf.edge.example.com', 'A', 60, CLOUDFRONT[i % 4])];
    } else answers = [];
    const rcode = answers.length ? 'NOERROR' : 'NXDOMAIN';
    const raw = ';; ->>HEADER<<- opcode: QUERY, status: ' + rcode + ', id: 1\\n;; flags: qr rd ra' + (i % 2 ? ' ad' : '') + '; QUERY: 1, ANSWER: ' + answers.length + '\\n\\n;; SERVER: x.x.x.x#53(x.x.x.x) (UDP)\\n';
    return { status: 'finished', rawOutput: raw, statusCodeName: rcode, statusCode: rcode === 'NOERROR' ? 0 : 3, answers, timings: { total: 10 + i }, resolver: i === 3 ? '8.8.8.8' : 'private' };
  };
  const inner = window.fetch;
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (!url.startsWith(API)) return inner(input, init);
    const method = String(init.method || 'GET').toUpperCase();
    let body = null;
    try { body = typeof init.body === 'string' ? JSON.parse(init.body) : null; } catch { body = null; }
    const p = url.slice(API.length);
    gp.calls.push({ method, path: p, body });
    if (init.signal && init.signal.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
    const quota = () => ({ 'x-ratelimit-limit': '250', 'x-ratelimit-remaining': String(gp.limitsRemaining), 'x-ratelimit-reset': '1800' });
    if (p === '/limits') return json(200, { rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: gp.limitsRemaining, reset: 1800 } } } });
    if (p === '/measurements' && method === 'POST') {
      const probes = Math.min(PROBES.length, (body.locations || []).reduce((n, l) => n + (l.limit || 1), 0) || body.limit || 1);
      gp.limitsRemaining = Math.max(0, gp.limitsRemaining - probes);
      gp.n += 1;
      const id = 'fakeIsp' + String(gp.n).padStart(8, '0');
      gp.measurements[id] = { id, target: body.target, probes, gets: 0, createdAt: new Date().toISOString() };
      return json(202, { id, probesCount: probes }, { ...quota(), 'x-request-cost': String(probes) });
    }
    const m = /^\\/measurements\\/([A-Za-z0-9]+)$/.exec(p);
    if (m && method === 'GET') {
      const meas = gp.measurements[m[1]];
      if (!meas) return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
      meas.gets += 1;
      const done = meas.gets > 1;
      const results = PROBES.slice(0, meas.probes).map((probe, i) => ({
        probe, result: done || i % 2 === 0 ? test(meas.target, i) : { status: 'in-progress', rawOutput: '' }
      }));
      return json(200, { id: meas.id, type: 'dns', status: done ? 'finished' : 'in-progress', createdAt: meas.createdAt, updatedAt: new Date().toISOString(), target: meas.target, probesCount: meas.probes, results });
    }
    return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
  };
})();`;

/** The ISP panel and the summary as the user sees them. */
function ispInfo() {
  const panel = document.querySelector('[data-role="isp-panel"]');
  const rows = [...document.querySelectorAll('.glb-isp-table tbody tr.dt-row')];
  const alert = document.querySelector('.glb-summary .alert');
  return {
    panel: !!panel,
    status: document.querySelector('[data-role="isp-status"] [data-isp-status]')?.dataset.ispStatus || null,
    statusText: document.querySelector('[data-role="isp-status"]')?.textContent || '',
    quota: document.querySelector('[data-role="isp-quota"]')?.textContent || '',
    rows: rows.length,
    pending: rows.filter((tr) => tr.classList.contains('is-pending')).length,
    istanbul: rows.find((tr) => tr.textContent.includes('Istanbul'))?.textContent || '',
    chicago: rows.find((tr) => tr.textContent.includes('Chicago'))?.textContent || '',
    state: alert?.dataset.state,
    title: alert?.querySelector('.alert-title')?.textContent || '',
    message: alert?.textContent || '',
    findings: [...document.querySelectorAll('.glb-summary .glb-finding')].map((li) => li.textContent),
    chips: document.querySelectorAll('.glb-legend .glb-chip').length,
    oldIp: [...document.querySelectorAll('.glb-ips tbody tr.dt-row')].find((tr) => tr.textContent.includes('192.0.2.10'))?.querySelectorAll('.glb-flag').length || 0,
    calls: window.__gpIsp.calls.map((c) => `${c.method} ${c.path}`),
    posts: window.__gpIsp.calls.filter((c) => c.method === 'POST').map((c) => c.body),
    external: window.__externalFetches
  };
}

async function offlineIsp(browser, server) {
  group('Offline: ISP resolvers through a fake Globalping (stale at an ISP, CDN by design, quota)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeGlobalDnsScript() });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeIspGlobalpingScript() });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  await setLangUi(page, 'en');
  const DONE_ISP = () => ['done', 'stopped', 'partial', 'failed', 'quota'].includes(document.querySelector('[data-role="isp-status"] [data-isp-status]')?.dataset.ispStatus);

  await step('the panel loads on first use and sends nothing by itself', async () => {
    await gotoHash(page, '#/global?name=isp.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'check done' });
    assertEqual(await page.evaluate(() => !!document.querySelector('[data-role="isp-panel"]')), false, 'not loaded before the click');
    await page.click('[data-action="isp-open"]');
    await page.waitFor(() => !!document.querySelector('[data-role="isp-panel"]'), { message: 'panel' });
    const info = await page.evaluate(ispInfo);
    assertEqual(info.calls, [], 'nothing sent to Globalping');
    assert(/Globalping: 250 probes per hour/.test(info.quota), `quota line: ${info.quota}`);
    assertEqual(info.state, 'agree', 'the check alone agrees');
  });

  await step('ask 10 probes over the continents: consent, the probes’ own resolvers, rows with ISP, resolver and TTL left', async () => {
    await page.click('[data-action="isp-run"]');
    await page.waitFor(() => !!document.querySelector('.gp-confirm'), { message: 'consent dialog' });
    const dialog = await page.evaluate(() => document.querySelector('.gp-confirm').textContent);
    assert(/isp\.example\.com/.test(dialog) && /10 probes of the 250/.test(dialog), `dialog: ${dialog}`);
    await page.click('.gp-confirm .btn-primary');
    await page.waitFor(DONE_ISP, { timeout: 20000, message: 'ISP run done' });
    const info = await page.evaluate(ispInfo);
    assertEqual(info.status, 'done', `status (${info.statusText})`);
    assertEqual([info.rows, info.pending], [10, 0], 'ten rows, none pending');
    const [post] = info.posts;
    assertEqual(post.measurementOptions, { query: { type: 'A' }, protocol: 'UDP', port: 53 }, 'no resolver: each probe asks its own');
    assertEqual(post.locations.map((l) => `${l.continent}${l.limit}`).join(' '), 'EU3 NA2 AS2 SA1 OC1 AF1', 'spread over the continents');
    assert(post.locations.every((l) => l.tags[0] === 'eyeball-network'), 'ISP networks only');
    assert(/2E Telekomunikasyon/.test(info.istanbul) && /AS209604/.test(info.istanbul) && /ISP-internal/.test(info.istanbul) && /1,500/.test(info.istanbul), `Istanbul row: ${info.istanbul}`);
    assert(/8\.8\.8\.8/.test(info.chicago) && /Google Public DNS/.test(info.chicago), `Chicago row names the public resolver: ${info.chicago}`);
    assert(/10 of 10 probes answered/.test(info.statusText), `status: ${info.statusText}`);
    assert(/Globalping: 240 of 250 probes left/.test(info.quota), `quota after: ${info.quota}`);
  });

  await step('one ISP still on the old address: "Stale at 1 ISP resolver", when it expires, the IP table names its country', async () => {
    const info = await page.evaluate(ispInfo);
    assertEqual(info.state, 'stale', `state (${info.title})`);
    assertEqual(info.title, 'Stale at 1 ISP resolver', 'title');
    assert(/The public resolvers and locations agree\./.test(info.message), `reference: ${info.message}`);
    assert(info.findings.length === 1 && /^2E Telekomunikasyon \(Istanbul, TR\): 192\.0\.2\.10 — expires within 25 min/.test(info.findings[0]), `finding: ${JSON.stringify(info.findings)}`);
    assertEqual(info.chips, 2, 'two answer groups');
    assertEqual(info.oldIp, 1, 'the old address carries the ISP’s flag');
    assertEqual(info.external, [], 'nothing left the page');
    await assertNoHorizontalScroll(page, 'stale at an ISP');
    await shot(page, 'global-offline-desktop-light-en-isp-stale');
  });

  await step('[TR, dark] a language re-mount keeps the ISP rows and words the verdict in Turkish (no new measurement)', async () => {
    await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
    await setLangUi(page, 'tr');
    await page.waitFor(() => document.querySelector('.glb-summary .alert-title')?.textContent === '1 İSS çözümleyicisinde eskimiş yanıt', { timeout: 10000, message: 'TR stale title' });
    const info = await page.evaluate(ispInfo);
    assertEqual(info.rows, 10, 'rows kept');
    assertEqual(info.posts.length, 1, 'no second measurement');
    assert(/İSS iç ağı/.test(info.istanbul), `TR resolver cell: ${info.istanbul}`);
    await shot(page, 'global-offline-desktop-dark-tr-isp-stale');
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await setLangUi(page, 'en');
  });

  await step('CloudFront edges at the ISPs through the same chain: by design, not stale', async () => {
    await gotoHash(page, '#/global?name=www.example.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 20000, message: 'check done' });
    await page.waitFor(() => !!document.querySelector('[data-action="isp-run"]'), { message: 'panel kept open' });
    const before = await page.evaluate(ispInfo);
    assertEqual(before.rows, 0, 'a new check drops the ISP rows of the last one');
    await page.click('[data-action="isp-run"]');
    await page.waitFor(DONE_ISP, { timeout: 20000, message: 'ISP run done' });
    const info = await page.evaluate(ispInfo);
    assertEqual(info.posts.length, 2, 'consent kept for the page session: no second dialog');
    assertEqual(info.state, 'by-design', `state (${info.title})`);
    assert(/Amazon CloudFront/.test(info.title), `title: ${info.title}`);
  });

  await step('quota used up: says when it resets and sends nothing', async () => {
    await page.evaluate(() => { window.__gpIsp.limitsRemaining = 0; });
    await page.click('[data-action="isp-run"]');
    await page.waitFor(DONE_ISP, { timeout: 10000, message: 'quota status' });
    const info = await page.evaluate(ispInfo);
    assertEqual(info.status, 'quota', 'status');
    assert(/quota for this hour is used up/.test(info.statusText) && /Nothing was sent/.test(info.statusText), `text: ${info.statusText}`);
    assertEqual(info.posts.length, 2, 'no POST');
  });

  await step('375 px, light and dark: the ISP panel and table stay inside the page', async () => {
    await page.setViewport({ width: 375, height: 812, mobile: true });
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({ 'prefers-color-scheme': scheme });
      await assertNoHorizontalScroll(page, `375 px ${scheme} ISP panel`);
    }
    await shot(page, 'global-offline-mobile-dark-en-isp');
    await page.setViewport({ width: 1440, height: 900 });
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  });

  await step('ISP resolvers: no console errors, exceptions, CSP violations or missing keys', async () => {
    await checkI18n(page);
    await assertClean(page, 'ISP resolvers');
  });
  await page.close();
}

/** The live groups: desktop (English) and phone (Turkish) against the public resolvers. */
async function liveChecks(browser, server) {
  /* ---------------- Desktop ---------------- */
  group('Desktop 1440×900 (English, live resolvers)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  await page.goto(`${server.url}#/about`);
  await waitReady(page);
  await setLangUi(page, 'en');

  await step('empty state before a query', async () => {
    await gotoHash(page, '#/global', 'global');
    const info = await page.evaluate(() => ({ empty: !!document.querySelector('.glb-empty .empty'), resultsHidden: document.querySelector('.glb-results').hidden }));
    assert(info.empty && info.resultsHidden, `empty state: ${JSON.stringify(info)}`);
    await assertNoHorizontalScroll(page, 'empty');
  });

  await step('a typed but unsubmitted name survives a language switch without querying', async () => {
    await page.type('[data-role="global-name"]', 'example.org');
    await page.evaluate(() => performance.clearResourceTimings());
    await setLangUi(page, 'tr');
    await page.evaluate(() => new Promise((resolve) => { setTimeout(resolve, 800); }));
    const info = await page.evaluate(() => ({
      requests: performance.getEntriesByType('resource').filter((e) => !e.name.startsWith(window.location.origin)).map((e) => e.name),
      hash: window.location.hash,
      name: document.querySelector('[data-role="global-name"]').value,
      resultsHidden: document.querySelector('.glb-results').hidden
    }));
    await setLangUi(page, 'en');
    assertEqual(info, { requests: [], hash: '#/global', name: 'example.org', resultsHidden: true }, 'draft kept, nothing sent');
  });

  await step(`shared link #/global?name=www.amazon.com&type=A runs, streams and groups ${RESOLVERS.length} + ${GEO_VANTAGES.length} sources`, async () => {
    await gotoHash(page, '#/about', 'about');
    await gotoHash(page, '#/global?name=www.amazon.com&type=A', 'global');
    // Rows exist (pre-filled) before the answers arrive.
    await page.waitFor(() => document.querySelectorAll('.glb-resolvers tbody tr.dt-row').length === 12, { message: 'pre-filled resolver rows' });
    await page.waitFor(DONE, { timeout: 45000, message: 'global check done' });
    const info = await page.evaluate(tableInfo);
    assertEqual(info.resolvers, RESOLVERS.length, 'resolver rows');
    assertEqual(info.geo, GEO_VANTAGES.length, 'geo rows');
    assertEqual(info.pending, 0, 'pending rows');
    assert(info.groups.includes('A'), `group A present: ${info.groups}`);
    assert(info.ips >= 2, `worldwide IPs listed: ${info.ips}`);
    assert(['agree', 'by-design', 'geo', 'differ'].includes(info.state), `summary state ${info.state}`);
    // CloudFront / Akamai edges everywhere: when they differ, the summary says so by design.
    if (info.state === 'by-design') assert(/Differs by design: .*(CloudFront|Akamai)/.test(info.summary), `by-design names the CDN: ${info.summary.slice(0, 200)}`);
    process.stdout.write(`        verdict: ${info.state}\n`);
    assert(/NOERROR/.test(info.cfStatus), `Cloudflare row answered NOERROR: ${info.cfStatus.slice(0, 200)}`);
    assert(info.failed <= 3, `at most the flaky resolvers failed (${info.failed})`);
    assertEqual(info.quad9.length, 2, 'two Quad9 rows');
    for (const q of info.quad9) {
      assert(q.state === 'unavailable' || q.state === 'answered', `Quad9 row is answered or "not readable", never an error: ${JSON.stringify(q)}`);
      if (q.state === 'unavailable') {
        assert(q.muted && q.label === 'Not readable in browsers' && /^dig @9.9.9.(9|11) www.amazon.com A$/.test(q.cmd || ''), `muted row with dig command: ${JSON.stringify(q)}`);
      }
    }
    if (info.unavailable) {
      assert(/not readable from a browser/.test(info.summary) && /Quad9/.test(info.summary), `summary explains Quad9: ${info.summary.slice(0, 300)}`);
      assert(/not readable in browsers/.test(info.answeredHint), `answered stat hint: ${info.answeredHint}`);
      assertEqual(info.errorChip, info.failed > 0, 'an error chip only for real failures');
    }
    process.stdout.write(`        Quad9 rows: ${info.quad9.map((q) => q.state).join(', ')}; other failures: ${info.failed}
`);
    const form = await page.evaluate(() => ({ name: document.querySelector('[data-role="global-name"]').value, type: document.querySelector('[data-role="global-type"]').value }));
    assertEqual(form, { name: 'www.amazon.com', type: 'A' }, 'form filled from URL');
    await assertNoHorizontalScroll(page, 'amazon');
    await shot(page, 'global-desktop-light-en-amazon');
  });

  await step('group chips carry letters; clicking one filters both tables and the IP list', async () => {
    const before = await page.evaluate(() => ({
      rows: document.querySelectorAll('.glb-resolvers tbody tr.dt-row, .glb-geo tbody tr.dt-row').length,
      ips: document.querySelectorAll('.glb-ips tbody tr.dt-row').length,
      members: Number(/\d+/.exec(document.querySelector('.glb-legend .glb-chip[data-group="A"] .glb-chip-count').textContent)[0])
    }));
    await page.click('.glb-legend .glb-chip[data-group="A"]');
    await page.waitFor(() => document.querySelector('.glb-legend .glb-chip[data-group="A"]').getAttribute('aria-pressed') === 'true');
    const after = await page.evaluate(() => ({
      rows: document.querySelectorAll('.glb-resolvers tbody tr.dt-row, .glb-geo tbody tr.dt-row').length,
      ips: document.querySelectorAll('.glb-ips tbody tr.dt-row').length,
      note: !document.querySelector('.glb-filter-note').hidden,
      onlyA: [...document.querySelectorAll('.glb-resolvers tbody tr.dt-row .glb-mark, .glb-geo tbody tr.dt-row .glb-mark')].every((m) => m.textContent === 'A')
    }));
    assertEqual(after.rows, before.members, 'filtered rows = group members');
    assert(after.onlyA && after.note, `only group A rows + note: ${JSON.stringify(after)}`);
    assert(after.ips >= 1 && after.ips <= before.ips, `IP list filtered (${after.ips} of ${before.ips})`);
    await page.click('.glb-legend .glb-chip[data-group="A"]');
    await page.waitFor((n) => document.querySelectorAll('.glb-resolvers tbody tr.dt-row, .glb-geo tbody tr.dt-row').length === n, { args: [before.rows] });
  });

  await step('IP table: provider badges, "returned by" counts and links to IP Intel', async () => {
    const info = await page.evaluate(() => {
      const rows = [...document.querySelectorAll('.glb-ips tbody tr.dt-row')];
      return {
        kinds: [...new Set(rows.map((r) => r.querySelector('[data-kind]')?.dataset.kind))],
        link: rows[0]?.querySelector('a.glb-ip')?.getAttribute('href'),
        seen: rows[0]?.querySelector('.glb-seen')?.textContent || ''
      };
    });
    assert(info.kinds.every(Boolean) && info.kinds.length >= 1, `kind badges: ${info.kinds}`);
    assert(/^#\/ip\?ips=/.test(info.link || ''), `IP link: ${info.link}`);
    assert(/\d+ of \d+/.test(info.seen), `seen text: ${info.seen}`);
  });

  await step('form run: github.com MX, resolvers only (geo off) → URL updated, geo section hidden', async () => {
    await page.type('[data-role="global-name"]', 'github.com');
    await page.evaluate(() => {
      const sel = document.querySelector('[data-role="global-type"]');
      sel.value = 'MX';
      const geo = document.querySelector('[data-role="global-geo"]');
      if (geo.checked) geo.click();
    });
    await page.click('[data-action="run"]');
    await page.waitFor(() => window.location.hash.includes('name=github.com') && window.location.hash.includes('type=MX'), { message: 'URL params' });
    await page.waitFor(DONE, { timeout: 45000, message: 'MX check done' });
    const info = await page.evaluate(() => ({
      geoHidden: document.querySelector('.glb-geo').hidden,
      mx: [...document.querySelectorAll('.glb-resolvers .glb-mx a')].map((a) => a.textContent),
      hash: window.location.hash,
      ipsEmpty: document.querySelectorAll('.glb-ips tbody tr.dt-row').length === 0
    }));
    assert(info.geoHidden, 'geo section hidden');
    assert(info.hash.includes('geo=0'), `geo=0 in URL: ${info.hash}`);
    assert(info.mx.some((x) => x.endsWith('outlook.com')), `MX target links: ${info.mx.slice(0, 3)}`);
    assert(info.ipsEmpty, 'no A/AAAA addresses for an MX query');
  });

  await step('validation: garbage and IP addresses are rejected without querying', async () => {
    await page.type('[data-role="global-name"]', 'not a domain!');
    await page.click('[data-action="run"]');
    await page.waitFor(() => !!document.querySelector('.glb-form .field.has-error'));
    await page.type('[data-role="global-name"]', '8.8.8.8');
    await page.press('Enter');
    const err = await page.evaluate(() => document.querySelector('.glb-form .field-error:not([hidden])')?.textContent || '');
    assert(/IP/.test(err), `IP error message: ${err}`);
    assert((await page.evaluate(() => window.location.hash)).includes('name=github.com'), 'URL unchanged');
  });

  await step('inventory match: a saved server owning an answer IP is named in the IP table', async () => {
    // Find one of cloudflare.com's current IPs, save it as a server, then check globally.
    const ip = await page.evaluate(async () => {
      const app = await import('./assets/js/app.js');
      const dns = await app.getDns();
      const res = await dns.resolveHost('cloudflare.com');
      return res.ipv4[0];
    });
    assert(ip, 'cloudflare.com resolves');
    await page.evaluate(async (addr) => {
      const { state } = await import('./assets/js/state.js');
      state.setInventory(`edge-test ${addr}`);
    }, ip);
    await gotoHash(page, '#/global?name=cloudflare.com&type=A', 'global');
    await page.waitFor(DONE, { timeout: 45000 });
    const names = await page.evaluate(() => [...document.querySelectorAll('.glb-ips tbody tr.dt-row')].map((r) => r.lastElementChild.textContent));
    assert(names.some((n) => n.includes('edge-test')), `server name in IP table: ${names.join('|')}`);
    await page.evaluate(async () => (await import('./assets/js/state.js')).state.clearInventory());
  });

  await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
  await step('[dark] results render; no horizontal scroll', async () => {
    await assertNoHorizontalScroll(page, 'dark');
    await shot(page, 'global-desktop-dark-en-cloudflare');
  });

  await step('language switch keeps the answers (snapshot, no re-query) and translates the view', async () => {
    const before = await page.evaluate(tableInfo);
    await page.evaluate(() => { window.__glbMarker = document.querySelector('.glb-results'); });
    await setLangUi(page, 'tr');
    await page.waitFor(() => document.querySelector('.glb-resolvers .section-title')?.textContent === 'Genel çözümleyiciler', { message: 'TR titles' });
    const after = await page.evaluate(tableInfo);
    for (const q of after.quad9.filter((x) => x.state === 'unavailable')) assertEqual(q.label, 'Tarayıcıda okunamıyor', 'TR label of the muted Quad9 row');
    if (after.unavailable) assert(/tarayıcıdan okunamıyor/.test(after.summary), `TR summary explains Quad9: ${after.summary.slice(0, 300)}`);
    assertEqual(after.pending, 0, 'no pending rows after re-mount (restored, not re-queried)');
    assertEqual(after.resolvers, before.resolvers, 'resolver rows kept');
    assertEqual(after.state, before.state, 'summary state kept');
    assert(await page.evaluate(() => window.__glbMarker !== document.querySelector('.glb-results')), 'view was re-mounted');
    await shot(page, 'global-desktop-dark-tr-cloudflare');
    await setLangUi(page, 'en');
  });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });

  await step('Stop cancels a running check: unanswered rows are marked, the summary says "Stopped"', async () => {
    await page.type('[data-role="global-name"]', 'www.wikipedia.org');
    await page.evaluate(() => {
      document.querySelector('[data-action="run"]').click();
      document.querySelector('[data-action="stop"]').click(); // same tick: before any answer
    });
    await page.waitFor(() => document.querySelector('.glb-summary .alert')?.dataset.state === 'stopped', { message: 'stopped state' });
    const info = await page.evaluate(() => ({
      runVisible: !document.querySelector('[data-action="run"]').hidden,
      spinners: document.querySelectorAll('.glb-results .glb-pending').length
    }));
    assert(info.runVisible && info.spinners === 0, `after stop: ${JSON.stringify(info)}`);
  });

  await step('i18n: no missing keys; glb.* TR/EN key sets match', () => checkI18n(page));
  await step('desktop: no console errors, exceptions or CSP violations', () => assertClean(page, 'desktop'));
  await page.close();

  /* ---------------- Phone ---------------- */
  group('Phone 390×844 (Turkish)');
  const phone = await browser.newPage('about:blank', { width: 390, height: 844, mobile: true });
  await phone.emulateMedia({ 'prefers-color-scheme': 'light' });
  await phone.goto(`${server.url}#/about`);
  await waitReady(phone);
  await setLangUi(phone, 'tr');

  for (const scheme of ['light', 'dark']) {
    await step(`[${scheme}] check runs and fits 390 px`, async () => {
      await phone.emulateMedia({ 'prefers-color-scheme': scheme });
      await gotoHash(phone, '#/about', 'about');
      await gotoHash(phone, `#/global?name=${scheme === 'light' ? 'www.microsoft.com' : 'wikipedia.org'}&type=A`, 'global');
      await phone.waitFor(DONE, { timeout: 45000 });
      const info = await phone.evaluate(tableInfo);
      assertEqual(info.pending, 0, 'pending');
      assert(await phone.evaluate(() => document.querySelector('.glb-resolvers .section-title').textContent === 'Genel çözümleyiciler'), 'Turkish UI');
      await assertNoHorizontalScroll(phone, `phone ${scheme}`);
      await shot(phone, `global-mobile-${scheme}-tr`);
    });
  }
  await step('phone: no console errors, exceptions or CSP violations', () => assertClean(phone, 'phone'));
  await step('phone: i18n complete', () => checkI18n(phone));
  await phone.close();
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  group('Pure helpers (Node)');
  await step('groupLetter / splitChain / median / minAnswerTtl', () => {
    assertEqual([0, 1, 25, 26, 27, 51, 52, 701, 702].map(groupLetter), ['A', 'B', 'Z', 'AA', 'AB', 'AZ', 'BA', 'ZZ', 'AAA'], 'letters');
    assertEqual(splitChain(['1.2.3.4', 'CNAME a.example.net', '5.6.7.8', 'CNAME b.cdn.net']), { plain: ['1.2.3.4', '5.6.7.8'], chain: ['a.example.net', 'b.cdn.net'] }, 'splitChain');
    assertEqual(median([]), null, 'median empty');
    assertEqual(median([5, 1, 3]), 3, 'median odd');
    assertEqual(median([1, 2, 3, 10]), 3, 'median even (rounded)');
    assertEqual(minAnswerTtl({ answers: [{ ttl: 300 }, { ttl: 20 }, { ttl: 60 }] }), 20, 'min ttl');
    assertEqual(minAnswerTtl(null), null, 'min ttl null');
    assertEqual(GLOBAL_TYPES, ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'HTTPS', 'SOA'], 'types (spec §6.3)');
  });
  await step('groupAnswers: letters by size, failed/blocked last without letters', () => {
    const g = groupAnswers([
      { key: 'resolver:a', values: ['1.1.1.1'] },
      { key: 'resolver:b', values: ['ERROR'] },
      { key: 'geo:x', values: ['2.2.2.2'] },
      { key: 'geo:y', values: ['2.2.2.2'] },
      { key: 'resolver:f', values: ['0.0.0.0'], filtered: true },
      { key: 'resolver:p', pending: true }
    ]);
    assertEqual(g.map((x) => x.letter), ['A', 'B', null, null], 'letters');
    assertEqual(g.map((x) => x.members.length), [2, 1, 1, 1], 'members');
    assertEqual([g[2].filtered, g[3].error], [true, true], 'blocked then failed');
    assertEqual(g.slice(0, 2).map((x) => x.color), [0, 1], 'colours');
  });
  await step('isBrowserBlocked / terminalCommand (Quad9: HTTP/3 without CORS)', () => {
    const q9 = RESOLVERS.find((r) => r.id === 'quad9');
    const cf = RESOLVERS.find((r) => r.id === 'cloudflare');
    assertEqual(isBrowserBlocked({ kind: 'resolver', resolver: q9, pending: false, values: ['ERROR'] }), true, 'quad9 transport failure');
    assertEqual(isBrowserBlocked({ kind: 'resolver', resolver: q9, pending: false, values: ['1.2.3.4'] }), false, 'quad9 answer');
    assertEqual(isBrowserBlocked({ kind: 'resolver', resolver: cf, pending: false, values: ['ERROR'] }), false, 'cloudflare failure');
    assertEqual(terminalCommand('quad9', 'www.amazon.com', 'A'), 'dig @9.9.9.9 www.amazon.com A', 'dig command');
  });

  await mkdir(SHOTS, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: BROWSER, headless: !HEADED });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}\n`);

  try {
    await offlineVerdicts(browser, server);
    await offlineIsp(browser, server);
    if (OFFLINE) process.stdout.write('\n--offline: the live resolver groups are skipped\n');
    else await liveChecks(browser, server);
  } finally {
    await browser.close();
    await server.close();
  }

  const failed = results.filter((r) => !r.ok);
  for (const n of [...new Set(notes)]) process.stdout.write(`  note: ${n}\n`);
  process.stdout.write(`\n${results.length - failed.length} passed, ${failed.length} failed${SHOTS_ON ? ` — screenshots in ${path.relative(process.cwd(), SHOTS)}` : ''}\n`);
  if (failed.length) {
    for (const f of failed) process.stdout.write(`  - ${f.group}: ${f.name}\n`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
