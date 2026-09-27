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
 * OFFLINE (always; alone with --offline): a fake DoH inside the page answers every query, so
 * the verdict (why answers differ: CDN / GeoDNS edges by design, or which part looks like
 * propagation or a misconfiguration) and the operator on every answer group are checked with
 * fixed answers, in EN / TR, light / dark, at 1440 px and 375 px, with nothing leaving the page.
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
import { groupAnswers, groupLetter, median, minAnswerTtl, splitChain, isBrowserBlocked, terminalCommand, GLOBAL_TYPES } from '../../assets/js/views/global.js';
import { RESOLVERS, GEO_VANTAGES } from '../../assets/js/lib/resolvers.js';

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
const FLAKY_HOSTS = [...RESOLVERS.map((r) => new URL(r.url).hostname)];
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

/** Resolver DoH URL → id, so the fake can answer per resolver. */
const RESOLVER_URLS = RESOLVERS.map((r) => [r.url, r.id]);
/** Locations whose ECS queries get a SERVFAIL for mixed.example.com. */
const SERVFAIL_SUBNET = GEO_VANTAGES[0].subnet;

/**
 * Answers every DoH query inside the page (installed before the app loads):
 * - www.example.com: a steering CNAME (tp.edge.example.com) that sends most sources to
 *   CloudFront edges (several addresses) and some ECS locations through *.edgekey.net to
 *   Akamai — every answer differs by design;
 * - mixed.example.com: Cloudflare edges, but IIJ and CZ.NIC still return a direct address
 *   (203.0.113.10), DNS.SB answers NXDOMAIN and one location SERVFAIL — a warning that names
 *   each part;
 * - moved.example.com: CNAME to one CloudFront distribution on Google, DNS.SB and every ECS
 *   location (Google answers those), to another one elsewhere — a change still propagating.
 * Any other request to another origin gets a 503 and is recorded in window.__externalFetches.
 */
const fakeGlobalDnsScript = () => `(() => {
  const RESOLVER_URLS = ${JSON.stringify(RESOLVER_URLS)};
  const SERVFAIL_SUBNET = ${JSON.stringify(SERVFAIL_SUBNET)};
  const CLOUDFRONT = ['13.32.0.10', '13.32.1.20', '13.33.2.30', '13.35.3.40'];
  const AKAMAI = ['2.16.10.10', '2.17.20.20'];
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
      if (ecs === SERVFAIL_SUBNET) return { rcode: 'SERVFAIL', answers: [] };
      if (resolver === 'dnssb') return { rcode: 'NXDOMAIN', answers: [] };
      if (resolver === 'iij' || resolver === 'cznic') return { answers: [a(qname, '203.0.113.10')] };
      return { answers: [a(qname, h % 2 ? '104.16.1.1' : '104.16.1.2')] };
    }
    if (qname === 'moved.example.com') {
      const target = resolver === 'google' || resolver === 'dnssb' ? 'd222222abcdef8.cloudfront.net' : 'd111111abcdef8.cloudfront.net';
      return { answers: [cn(qname, target), a(target, CLOUDFRONT[h % 4])] };
    }
    return { rcode: 'NXDOMAIN', answers: [] };
  };
  const realFetch = window.fetch.bind(window);
  let wire = null;
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
    const query = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1])));
    const q = query.questions[0];
    const resolver = (RESOLVER_URLS.find(([u]) => url.startsWith(u + '?')) || [null, 'unknown'])[1];
    const ecs = query.edns && query.edns.ecs ? query.edns.ecs.subnet : null;
    const out = answer(String(q.name).toLowerCase().replace(/[.]$/, ''), resolver, ecs);
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
    assert(/SERVFAIL/.test(rcode.text) && /DNSSEC/.test(rcode.text), `rcode: ${rcode.text}`);
    assert(/^DNS\.SB: NXDOMAIN/.test(nx.text), `nxdomain: ${nx.text}`);
    assert(/203\.0\.113\.10/.test(mixed.text) && /not on Cloudflare/.test(mixed.text), `mixed: ${mixed.text}`);
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
    await shot(page, 'global-offline-desktop-dark-tr-by-design');
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

  await step('375 px phone: verdict and operator chips fit without horizontal scroll', async () => {
    await page.setViewport({ width: 375, height: 812, mobile: true });
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({ 'prefers-color-scheme': scheme });
      for (const name of ['www.example.com', 'mixed.example.com']) {
        await gotoHash(page, `#/global?name=${name}&type=A`, 'global');
        await page.waitFor(DONE, { timeout: 20000 });
        await assertNoHorizontalScroll(page, `375 px ${scheme} ${name}`);
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

  await step('shared link #/global?name=www.amazon.com&type=A runs, streams and groups 12 + 31 sources', async () => {
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
