#!/usr/bin/env node
/**
 * cutover.e2e.mjs — the cutover follow-ups of wave 6 in a real headless Chrome/Edge. OFFLINE: a fake
 * DoH and a fake Globalping answer inside the page, every https request is blocked at the network
 * and every request that leaves the page's origin is counted through CDP.
 *
 *   node tests/e2e/cutover.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers:
 *   - Global DNS › Expected value (lib/expected.js): a shared link with `expect=` judges every
 *     answer ("Matches" / "Not yet" with until when the old answer may stay cached), the card
 *     counts them, says when the last cached old copy expires and estimates the worst case anywhere
 *     (at least the 3412 s a copy had left, most likely the zone TTL 3600 s it counts down from),
 *     with the public resolvers' cache-flush pages; "Show only the sources not there yet" filters
 *     the tables; contains and regex; an invalid regex and an exact A value that is a host name at
 *     the field (no card); editing the value asks nothing again and keeps it in the link; Copy
 *     summary's line; the CSV's export-only "Expected value" column; a link's regex is held until
 *     Enter in the field;
 *   - the zone's name server (ui/soa-probe.js, lib/soaprobe.js): a brand-new name still NXDOMAIN at
 *     some resolvers — the worst case first estimated from the SOA in their answers (min(minimum
 *     1800, SOA TTL 650 counted down → 900) = 900 s, at least 650 s), then one Globalping probe asks
 *     ns1.example.com (the SOA's primary, from the zone's NS set over DoH) for the SOA of the name:
 *     the consent dialog names the name, the server and the cost; the body is one SOA query with
 *     that resolver; the answer says the server answers with authority, the name exists there and
 *     the negative-cache time is 700 s, which the worst case takes; Ask again needs no second
 *     dialog; a used-up quota sends nothing; an internal name is never sent; a Turkish re-mount
 *     keeps the answer (no new probe); a changed record: the probe asks the A record itself, whose
 *     TTL there (3600 s) makes the worst case exact; redrawing the card inserts no alert again;
 *   - DNS change request › the TTL planner as a calendar: the .ics of the four steps (UTC times,
 *     reminders, the flush pages in the change's event) in English and Turkish, and the flush links;
 *   - 375 / 320 px, light / dark, English / Turkish without horizontal scroll; no console errors,
 *     exceptions or CSP violations; no missing i18n keys; nothing left the page.
 *
 * Data is documentation space only (example.com / .net / .org, 192.0.2.0/24, 198.51.100.0/24).
 */

import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import {
  BASE, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner, gotoRoute,
  installDownloadCapture, setLangUi, shot, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';
import { RESOLVERS, ECS_RESOLVERS, GEO_VANTAGES } from '../../assets/js/lib/resolvers.js';
import { FLUSH_LINKS } from '../../assets/js/lib/expected.js';
import { pinnedClockScript } from './clock.mjs';

/**
 * The instant the expectations were written for: 10:00 local time on a fixed day, where the page's clock starts. The
 * cards say "expires by 11:43 AM" for an expiry today and put the date before the time for any other day, so a run in
 * the last hour before midnight would read "Oct 9, 2026, 12:43 AM".
 */
const CUTOVER_NOW = new Date(2026, 9, 8, 10, 0, 0).getTime();

const RESOLVER_URLS = RESOLVERS.map((r) => [r.url, r.id]);
const JSON_URLS = ECS_RESOLVERS.map((r) => [r.url, r.id]);
/** Two locations (Google with their subnet) that still hold the old answer. */
const OLD_SUBNETS = GEO_VANTAGES.filter((v) => !v.resolver).slice(0, 2).map((v) => v.subnet);
/** Every source of a Global DNS check: the resolvers and the locations. */
const SOURCES = RESOLVERS.length + GEO_VANTAGES.length;
/** The check's result header (the page template) says it ended. */
const DONE = () => document.querySelector('.glb-summary')?.dataset.state === 'done';

/**
 * The fake DoH (RFC 8484 wire and AliDNS's JSON form), installed before the app loads:
 * - cut.example.com A: Google (without ECS), DNS.SB and two locations still give the old address
 *   (192.0.2.10) with 3412 s left; everyone else the new one (198.51.100.20, TTL 300);
 * - new.example.com A: the same sources still say NXDOMAIN (the zone's SOA in the authority section,
 *   650 s left of its TTL 700, minimum 1800); the others the new address. Any other type of it:
 *   NODATA with the SOA;
 * - example.com: its SOA (primary ns1.example.com) and NS (ns2.example.net, ns1.example.com);
 * - www.example.com A: 192.0.2.10 with 3412 s left (the change page's check);
 * - anything else NXDOMAIN without an authority.
 * Every question is logged in window.__dnsLog as "name TYPE resolver".
 */
export const fakeDnsScript = () => `(() => {
  const RESOLVER_URLS = ${JSON.stringify(RESOLVER_URLS)};
  const JSON_URLS = ${JSON.stringify(JSON_URLS)};
  const OLD_SUBNETS = ${JSON.stringify(OLD_SUBNETS)};
  const OLD = '192.0.2.10';
  const NEW = '198.51.100.20';
  const SOA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026100801, refresh: 7200, retry: 900, expire: 1209600, minimum: 1800 };
  const soaAuth = [{ name: 'example.com', type: 'SOA', ttl: 650, data: SOA }];
  const a = (name, ip, ttl) => ({ name, type: 'A', ttl, data: ip });
  window.__dnsLog = [];
  const answer = (qname, qtype, resolver, ecs) => {
    const stale = (resolver === 'google' && !ecs) || resolver === 'dnssb' || OLD_SUBNETS.includes(ecs);
    if (qname === 'cut.example.com' && qtype === 'A') return { answers: [stale ? a(qname, OLD, 3412) : a(qname, NEW, 300)], authorities: [] };
    if (qname === 'new.example.com') {
      if (qtype === 'A') return stale ? { rcode: 'NXDOMAIN', answers: [], authorities: soaAuth } : { answers: [a(qname, NEW, 300)], authorities: [] };
      return { answers: [], authorities: soaAuth };
    }
    if (qname === 'example.com' && qtype === 'NS') {
      return { answers: ['ns2.example.net', 'ns1.example.com'].map((data) => ({ name: 'example.com', type: 'NS', ttl: 3600, data })), authorities: [] };
    }
    if (qname === 'example.com' && qtype === 'SOA') return { answers: [{ name: 'example.com', type: 'SOA', ttl: 3600, data: SOA }], authorities: [] };
    if (qname === 'www.example.com' && qtype === 'A') return { answers: [a(qname, OLD, 3412)], authorities: [] };
    return { rcode: 'NXDOMAIN', answers: [], authorities: [] };
  };
  const JSON_TYPES = { 1: 'A', 5: 'CNAME', 28: 'AAAA', 65: 'HTTPS' };
  const RCODES = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3 };
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.__externalFetches = [];
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const viaJson = JSON_URLS.find(([u]) => url.startsWith(u + '?'));
    if (viaJson) {
      const u = new URL(url);
      const qname = String(u.searchParams.get('name')).toLowerCase().replace(/[.]$/, '');
      const type = JSON_TYPES[Number(u.searchParams.get('type'))] || 'A';
      const ecs = u.searchParams.get('edns_client_subnet');
      window.__dnsLog.push(qname + ' ' + type + ' ' + viaJson[1]);
      const out = answer(qname, type, viaJson[1], ecs);
      const rr = (x) => ({ name: x.name + '.', TTL: x.ttl, type: 1, data: x.data });
      return new Response(JSON.stringify({
        Status: RCODES[out.rcode || 'NOERROR'], TC: false, RD: true, RA: true, AD: false, CD: false,
        Question: { name: qname + '.', type: Number(u.searchParams.get('type')) },
        ...(out.answers.length ? { Answer: out.answers.filter((x) => x.type === 'A').map(rr) } : {}),
        ...(ecs ? { edns_client_subnet: ecs } : {})
      }), { headers: { 'content-type': 'application/json' } });
    }
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
    const qname = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__dnsLog.push(qname + ' ' + q.type + ' ' + resolver);
    const out = answer(qname, q.type, resolver, ecs);
    const edns = ecs ? { ecs: { address: ecs.split('/')[0], sourcePrefix: 24, scopePrefix: 24 } } : {};
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode || 'NOERROR',
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities || [], edns
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/**
 * The fake Globalping v1 API (the outermost window.fetch wrapper, installed after the fake DoH):
 * /limits (the quota in the body), POST /measurements (202 with the quota headers; one probe) and
 * GET /measurements/:id (finished at once): ns1.example.com answers with authority — the A record
 * of cut.example.com (198.51.100.20, the zone's TTL 3600: the change is live there), else NOERROR
 * with no answer and the zone's SOA in the authority section (TTL 700, minimum 1800). Knobs and
 * records on window.__gp: remaining (what /limits reports), calls.
 */
export const fakeGpScript = () => `(() => {
  const API = 'https://api.globalping.io/v1';
  const gp = window.__gp = { calls: [], n: 0, remaining: 250, measurements: {} };
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  const PROBE = { continent: 'EU', region: 'Western Europe', country: 'DE', state: null, city: 'Frankfurt', asn: 64500, network: 'Example Networks', latitude: 0, longitude: 0, tags: ['datacenter-network'], resolvers: ['private'] };
  const records = (target, type) => (target === 'cut.example.com' && type === 'A' ? [{ name: 'cut.example.com', ttl: 3600, type: 'A', value: '198.51.100.20' }] : []);
  const raw = (target, type, answers) => [
    '; <<>> DiG 9.18.28 <<>> @ns1.example.com ' + target + ' ' + type + ' +nsid',
    ';; global options: +cmd', ';; Got answer:',
    ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242',
    ';; flags: qr aa rd; QUERY: 1, ANSWER: ' + answers.length + ', AUTHORITY: ' + (answers.length ? 0 : 1) + ', ADDITIONAL: 1', '',
    ';; OPT PSEUDOSECTION:', '; EDNS: version: 0, flags:; udp: 1232', '; NSID: 6e 73 31 ("ns1-fra")',
    ';; QUESTION SECTION:', ';' + target + '.\\t\\tIN\\t' + type, '',
    ...(answers.length
      ? [';; ANSWER SECTION:', ...answers.map((a) => a.name + '.\\t\\t' + a.ttl + '\\tIN\\t' + a.type + '\\t' + a.value), '']
      : [';; AUTHORITY SECTION:', 'example.com.\\t\\t700\\tIN\\tSOA\\tns1.example.com. hostmaster.example.com. 2026100801 7200 900 1209600 1800', '']),
    ';; Query time: 12 msec', ';; SERVER: 192.0.2.53#53(ns1.example.com) (UDP)'
  ].join('\\n');
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
    const quota = () => ({ 'x-ratelimit-limit': '250', 'x-ratelimit-remaining': String(gp.remaining), 'x-ratelimit-reset': '1800' });
    if (p === '/limits') return json(200, { rateLimit: { measurements: { create: { type: 'ip', limit: 250, remaining: gp.remaining, reset: 1800 } } } });
    if (p === '/measurements' && method === 'POST') {
      gp.remaining = Math.max(0, gp.remaining - 1);
      gp.n += 1;
      const id = 'fakeSoa' + String(gp.n).padStart(8, '0');
      const type = (body.measurementOptions && body.measurementOptions.query && body.measurementOptions.query.type) || 'A';
      gp.measurements[id] = { id, target: body.target, type, createdAt: new Date().toISOString() };
      return json(202, { id, probesCount: 1 }, { ...quota(), 'x-request-cost': '1' });
    }
    const m = /^\\/measurements\\/([A-Za-z0-9]+)$/.exec(p);
    if (m && method === 'GET') {
      const meas = gp.measurements[m[1]];
      if (!meas) return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
      const answers = records(meas.target, meas.type);
      return json(200, {
        id: meas.id, type: 'dns', status: 'finished', createdAt: meas.createdAt, updatedAt: new Date().toISOString(), target: meas.target, probesCount: 1,
        results: [{ probe: PROBE, result: {
          status: 'finished', rawOutput: raw(meas.target, meas.type, answers), statusCodeName: 'NOERROR', statusCode: 0, timings: { total: 12 }, resolver: 'ns1.example.com',
          answers: answers.map((a) => ({ name: a.name + '.', type: a.type, ttl: a.ttl, class: 'IN', value: a.value }))
        } }]
      });
    }
    return json(404, { error: { type: 'not_found', message: 'Not Found.' } });
  };
})();`;

/** Set a form field (by its data-role) and fire what the app listens to. */
const setField = (page, role, value) => page.evaluate(([r, v]) => {
  const input = document.querySelector(`[data-role="${r}"]`);
  input.value = v;
  input.dispatchEvent(new Event(input.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
}, [role, value]);

/** The expected value's card and marks as the user sees them. */
function expInfo() {
  const card = document.querySelector('[data-role="expected"]');
  const count = document.querySelector('[data-role="exp-count"]');
  const marks = (sel, v) => document.querySelectorAll(`${sel} .glb-exp-mark[data-exp="${v}"]`).length;
  return {
    shown: !!card && !card.hidden,
    state: card ? card.dataset.state : null,
    value: card ? card.querySelector('.glb-exp-value')?.textContent || '' : '',
    count: count ? { match: Number(count.dataset.match), mismatch: Number(count.dataset.mismatch), judged: Number(count.dataset.judged), text: count.textContent } : null,
    last: (() => { const el = document.querySelector('[data-role="exp-last"]'); return el && !el.hidden ? el.textContent : null; })(),
    worst: (() => { const el = document.querySelector('[data-role="exp-worst"]'); return el && !el.hidden ? { text: el.textContent, seconds: el.dataset.seconds, exact: el.dataset.exact } : null; })(),
    flush: [...document.querySelectorAll('[data-role="exp-flush"]:not([hidden]) a')].map((x) => x.getAttribute('href')),
    toggle: (() => { const b = document.querySelector('[data-action="exp-missing"]'); return b && !b.hidden ? { text: b.textContent, pressed: b.getAttribute('aria-pressed') } : null; })(),
    resolverMarks: { match: marks('.glb-resolvers', 'match'), mismatch: marks('.glb-resolvers', 'mismatch') },
    geoMarks: { match: marks('.glb-geo', 'match'), mismatch: marks('.glb-geo', 'mismatch') },
    rows: document.querySelectorAll('.glb-resolvers tbody tr.dt-row').length + document.querySelectorAll('.glb-geo tbody tr.dt-row').length,
    soaSlot: (() => { const s = document.querySelector('[data-role="soa-slot"]'); return !!s && !s.hidden; })(),
    soaStatus: document.querySelector('[data-soa-status]')?.dataset.soaStatus || null,
    soaResult: (() => { const r = document.querySelector('[data-soa-state]'); return r ? { state: r.dataset.soaState, exists: r.dataset.soaExists, text: r.textContent } : null; })(),
    fieldError: document.querySelector('.glb-expect-value .field-error')?.textContent || '',
    fieldHint: document.querySelector('.glb-expect-value .field-hint')?.textContent || '',
    hash: location.hash
  };
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
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: pinnedClockScript(CUTOVER_NOW) });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeDnsScript() });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeGpScript() });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/about`);
    await waitReady(page);
    await setLangUi(page, 'en');
    const info = () => page.evaluate(expInfo);

    run.group('Global DNS › Expected value (a fake DoH; nothing leaves the page)');
    await run.step('a shared link with expect=: every answer judged, the counts, the last cached old copy, the worst case, the flush pages', async () => {
      await gotoRoute(page, '#/global?name=cut.example.com&type=A&expect=198.51.100.20');
      await page.waitFor(DONE, { timeout: 20000, message: 'check done' });
      await page.waitFor(() => document.querySelector('[data-role="expected"]')?.dataset.state === 'pending', { message: 'expected card' });
      const i = await info();
      assertEqual(i.count && [i.count.match, i.count.mismatch, i.count.judged], [SOURCES - 4, 4, SOURCES], 'four sources hold the old answer');
      assertEqual([i.resolverMarks.mismatch, i.geoMarks.mismatch], [2, 2], 'Google and DNS.SB, and two locations, marked "Not yet"');
      assertEqual([i.rows, i.resolverMarks.match + i.geoMarks.match], [SOURCES, SOURCES - 4], 'every other row marked "Matches"');
      assert(/198\.51\.100\.20/.test(i.value) && /Exact/.test(i.value), `value: ${i.value}`);
      assert(/^Served by \d+ of \d+ sources/.test(i.count.text), `count: ${i.count.text}`);
      assert(/^4 sources still give another answer; the last of their cached copies expires by \d{1,2}:\d{2}/.test(i.last), `last: ${i.last}`);
      assertEqual([i.worst.seconds, i.worst.exact], ['3600', 'false'], 'the old TTL 3412 read as 3600: an estimate, the copies count down');
      assert(/Worst case for any resolver in the world: at least 57 minutes after the change was published, most likely 1 hour\./.test(i.worst.text)
        && /most likely 3,600 s/.test(i.worst.text) && /was 3,412 s/.test(i.worst.text) && /Cached TTLs count down, so this is an estimate/.test(i.worst.text), `worst: ${i.worst.text}`);
      assertEqual(i.flush, FLUSH_LINKS.map((l) => l.url), 'the cache-flush pages');
      assert(i.soaSlot, 'the name server probe is offered');
      const title = await page.evaluate(() => document.querySelector('.glb-resolvers .glb-exp-mark[data-exp="mismatch"]').title);
      assert(/may keep it cached until \d{1,2}:\d{2}/.test(title), `mark tooltip: ${title}`);
      assertEqual(await page.evaluate(() => window.__gp.calls.length), 0, 'nothing sent to Globalping');
      await assertNoHorizontalScroll(page, 'expected value desktop');
      await shot(page, opts, 'cutover-global-expected-desktop-light-en');
    });

    await run.step('"Show only the sources not there yet" filters the tables; "Show all" brings them back', async () => {
      await page.click('[data-action="exp-missing"]');
      await page.waitFor(() => document.querySelector('[data-action="exp-missing"]')?.getAttribute('aria-pressed') === 'true', { message: 'pressed' });
      const rows = await page.evaluate(() => ({
        res: [...document.querySelectorAll('.glb-resolvers tbody tr.dt-row')].map((tr) => tr.textContent),
        geo: document.querySelectorAll('.glb-geo tbody tr.dt-row').length,
        ips: [...document.querySelectorAll('.glb-ips tbody tr.dt-row')].map((tr) => tr.querySelector('.glb-ip')?.textContent),
        note: document.querySelector('.glb-filter-note')?.textContent || ''
      }));
      assertEqual(rows.res.length, 2, 'two resolvers');
      assert(rows.res.some((x) => /Google/.test(x)) && rows.res.some((x) => /DNS\.SB/.test(x)), `resolvers: ${rows.res.join(' | ')}`);
      assertEqual(rows.geo, 2, 'two locations');
      assertEqual(rows.ips, ['192.0.2.10'], 'only the old address in the IP table');
      assert(/do not serve the expected value yet/.test(rows.note), `note: ${rows.note}`);
      await page.click('[data-action="exp-missing"]');
      await page.waitFor(() => document.querySelectorAll('.glb-resolvers tbody tr.dt-row').length > 2, { message: 'all rows back' });
    });

    await run.step('contains and regex judge the same answers; an invalid regex is said at the field and hides the card; nothing asked again', async () => {
      const asked = await page.evaluate(() => window.__dnsLog.length);
      await setField(page, 'global-match', 'contains');
      await setField(page, 'global-expect', '198.51.100');
      await page.waitFor(() => /Contains/.test(document.querySelector('.glb-exp-value')?.textContent || ''), { message: 'contains' });
      assertEqual((await info()).count.mismatch, 4, 'contains');
      await setField(page, 'global-match', 'regex');
      await setField(page, 'global-expect', '^198\\.51\\.100\\.\\d+$');
      await page.waitFor(() => /Regex/.test(document.querySelector('.glb-exp-value')?.textContent || ''), { message: 'regex' });
      assertEqual((await info()).count.mismatch, 4, 'regex');
      assert((await info()).hash.includes('match=regex') && (await info()).hash.includes('expect='), `the link keeps the value: ${(await info()).hash}`);
      await setField(page, 'global-expect', '(198');
      await page.waitFor(() => document.querySelector('[data-role="expected"]').hidden, { message: 'card hidden' });
      const bad = await info();
      assert(/^Not a valid regular expression/.test(bad.fieldError), `field error: ${bad.fieldError}`);
      assert(!bad.hash.includes('expect='), `an unusable value leaves the link: ${bad.hash}`);
      assertEqual(await page.evaluate(() => document.querySelectorAll('.glb-exp-mark').length), 0, 'no marks');
      await setField(page, 'global-match', 'exact');
      await setField(page, 'global-expect', 'new-lb.example.net');
      await page.waitFor(() => /new-lb\.example\.net/.test(document.querySelector('.glb-expect-value .field-error')?.textContent || ''), { message: 'host name at the field' });
      const host = await info();
      assert(/^An exact A value is an IPv4 address — new-lb\.example\.net is not one\. To check the host name the name points to, choose Contains or the CNAME type\.$/.test(host.fieldError),
        `field error: ${host.fieldError}`);
      assert(!host.shown, 'no card: a host name never equals an A record');
      await setField(page, 'global-expect', '198.51.100.20');
      await page.waitFor(() => document.querySelector('.glb-exp-pattern')?.textContent === '198.51.100.20'
        && document.querySelector('[data-role="expected"]')?.dataset.state === 'pending', { message: 'exact again' });
      assertEqual(await page.evaluate(() => window.__dnsLog.length), asked, 'editing the value asked nothing again');
    });

    await run.step('Copy summary names the expected value; Copy link carries it; the CSV has an "Expected value" column', async () => {
      await stubClipboard(page);
      await page.click('[data-summary="global"] [data-action="copy-summary"]');
      await page.waitFor(() => window.__clip.length === 1, { message: 'summary copied' });
      const md = (await takeClipboard(page))[0];
      assert(md.includes(`- Expected value (exact): \`198.51.100.20\` — served by ${SOURCES - 4} of ${SOURCES} sources`), `summary: ${md}`);
      assert(/#\/global\?name=cut\.example\.com&type=A&expect=198\.51\.100\.20/.test(md), `summary link: ${md}`);
      await page.evaluate(() => document.querySelector('.glb-resolvers [data-export="csv"]').click());
      const [csv] = await takeDownloads(page);
      const header = csv.text.split(/\r?\n/)[0];
      assert(/Expected value/.test(header), `CSV header: ${header}`);
      assert(csv.text.split(/\r?\n/).some((l) => /DNS\.SB/.test(l) && /mismatch/.test(l)), 'DNS.SB is a mismatch in the CSV');
    });

    await run.step('a link’s regex is held — shown, kept in the link, applied only on Enter in the field (it would run against answers the link’s author may write)', async () => {
      await gotoRoute(page, '#/global?name=cut.example.com&type=A&match=regex&expect=%5E198%5C.51');
      await page.waitFor(DONE, { timeout: 20000, message: 'check done' });
      const held = await info();
      assert(!held.shown, 'no card: the pattern is not applied');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.glb-exp-mark').length), 0, 'no marks');
      const field = await page.evaluate(() => [document.querySelector('[data-role="global-expect"]').value, document.querySelector('[data-role="global-match"]').value]);
      assertEqual(field, ['^198\\.51', 'regex'], 'the fields show it');
      assert(/^A regular expression from a link is applied only once you press Enter in the field or edit it/.test(held.fieldHint), `hint: ${held.fieldHint}`);
      assert(held.hash.includes('match=regex') && held.hash.includes('expect=%5E198'), `the link keeps it: ${held.hash}`);
      await page.evaluate(() => document.querySelector('[data-role="global-expect"]').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })));
      await page.waitFor(() => /Regex/.test(document.querySelector('.glb-exp-value')?.textContent || '') && document.querySelector('[data-role="expected"]')?.dataset.state === 'pending', { message: 'applied on Enter' });
      const applied = await info();
      assertEqual([applied.count.match, applied.count.mismatch], [SOURCES - 4, 4], 'judged once applied');
      assert(!/press Enter/.test(applied.fieldHint), `the usual hint again: ${applied.fieldHint}`);
    });

    run.group('Global DNS › the zone’s name server (one Globalping SOA probe, a fake API)');
    await run.step('a brand-new name: the worst case from the SOA in the NXDOMAIN answers, before any probe', async () => {
      await gotoRoute(page, '#/global?name=new.example.com&type=A&expect=198.51.100.20');
      await page.waitFor(DONE, { timeout: 20000, message: 'check done' });
      await page.waitFor(() => document.querySelector('[data-role="expected"]')?.dataset.state === 'pending', { message: 'expected card' });
      const i = await info();
      assertEqual(i.count.mismatch, 4, 'four sources still say NXDOMAIN');
      assertEqual([i.worst.seconds, i.worst.exact], ['900', 'false'], 'min(SOA minimum 1800, SOA TTL 650 counted down → 900): an estimate');
      assert(/at least 11 minutes after the change was published, most likely 15 minutes\./.test(i.worst.text)
        && /negative-cache time: most likely 900 s, read from the SOA in their answers/.test(i.worst.text), `worst: ${i.worst.text}`);
      assert(/expires by \d{1,2}:\d{2}.*\(in 11 minutes\)/.test(i.last), `last: ${i.last}`);
      assertEqual(await page.evaluate(() => window.__gp.calls.length), 0, 'nothing sent yet');
    });

    await run.step('Ask the zone’s name server: the consent names the name, the server and the cost; one SOA query to ns1.example.com', async () => {
      await page.click('[data-action="soa-open"]');
      await page.waitFor(() => !!document.querySelector('.gp-confirm'), { message: 'consent dialog', timeout: 15000 });
      const dialog = await page.evaluate(() => document.querySelector('.gp-confirm').textContent);
      assert(/new\.example\.com/.test(dialog) && /ns1\.example\.com/.test(dialog) && /1 probe of the 250/.test(dialog) && /the record type SOA/.test(dialog), `dialog: ${dialog}`);
      await page.click('.gp-confirm .btn-primary');
      await page.waitFor(() => !!document.querySelector('[data-soa-state]'), { message: 'the name server’s answer', timeout: 15000 });
      const calls = await page.evaluate(() => window.__gp.calls);
      const posts = calls.filter((c) => c.method === 'POST');
      assertEqual(posts.length, 1, 'one measurement');
      assertEqual(posts[0].body, {
        type: 'dns', target: 'new.example.com', limit: 1, timeout: 15,
        measurementOptions: { query: { type: 'SOA' }, resolver: 'ns1.example.com', protocol: 'UDP', port: 53 }
      }, 'the SOA question of the name, asked of the primary');
      const i = await info();
      assertEqual([i.soaResult.state, i.soaResult.exists], ['ok', 'true'], 'an authoritative answer: the name exists there');
      assert(/ns1\.example\.com answers for the zone example\.com with authority\./.test(i.soaResult.text) && /SOA serial 2026100801, primary ns1\.example\.com\./.test(i.soaResult.text)
        && /new\.example\.com exists there\./.test(i.soaResult.text) && /Negative-cache time: 700 s/.test(i.soaResult.text) && /Frankfurt/.test(i.soaResult.text), `result: ${i.soaResult.text}`);
      assertEqual([i.worst.seconds, i.worst.exact], ['700', 'true'], 'the worst case takes the name server’s negative-cache time');
      assert(/Worst case for any resolver in the world: 12 minutes after the change was published\./.test(i.worst.text)
        && /700 s, as the zone’s name server ns1\.example\.com serves it/.test(i.worst.text) && !/estimate/.test(i.worst.text), `worst: ${i.worst.text}`);
      assert(await page.evaluate(() => !!document.querySelector('[data-role="soa-measurement"]')), 'the measurement link');
      await shot(page, opts, 'cutover-global-soa-desktop-light-en');
    });

    await run.step('Ask again: no second dialog in the page session', async () => {
      await page.click('[data-action="soa-run"]');
      await page.waitFor(() => window.__gp.calls.filter((c) => c.method === 'POST').length === 2, { message: 'second measurement', timeout: 15000 });
      await page.waitFor(() => !document.querySelector('[data-soa-status="running"]') && !!document.querySelector('[data-soa-state]'), { message: 'answered again', timeout: 15000 });
      assert(!(await page.evaluate(() => !!document.querySelector('.gp-confirm'))), 'no dialog');
    });

    await run.step('[TR, dark] a language re-mount keeps the expected value and the name server’s answer (no new probe)', async () => {
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('[data-soa-state]') && document.querySelector('[data-role="expected"]')?.dataset.state === 'pending', { message: 'TR card', timeout: 10000 });
      const i = await info();
      assert(/Tam/.test(i.value), `TR mode: ${i.value}`);
      assert(/kaynaktan \d+ tanesi döndürüyor/.test(i.count.text), `TR count: ${i.count.text}`);
      assert(/bölgenin ad sunucusu ns1\.example\.com böyle bildiriyor/.test(i.worst.text), `TR worst: ${i.worst.text}`);
      assert(/example\.com bölgesi için yetkili olarak yanıt veriyor/.test(i.soaResult.text), `TR result: ${i.soaResult.text}`);
      assertEqual(await page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST').length), 2, 'no new measurement');
      await shot(page, opts, 'cutover-global-soa-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    await run.step('an internal name is never sent to Globalping', async () => {
      await gotoRoute(page, '#/global?name=printer.local&type=A&expect=198.51.100.20');
      await page.waitFor(DONE, { timeout: 20000, message: 'check done' });
      await page.waitFor(() => { const s = document.querySelector('[data-role="soa-slot"]'); return s && !s.hidden; }, { message: 'probe offered' });
      const before = await page.evaluate(() => window.__gp.calls.length);
      await page.click('[data-action="soa-run"]');
      await page.waitFor(() => document.querySelector('[data-soa-status]')?.dataset.soaStatus === 'plan-internal', { message: 'refused', timeout: 10000 });
      assert(/An internal name \(printer\.local\) is never sent to Globalping\./.test(await page.evaluate(() => document.querySelector('[data-soa-status]').textContent)), 'internal text');
      assertEqual(await page.evaluate(() => window.__gp.calls.length), before, 'nothing sent, not even /limits');
    });

    await run.step('a changed record: the probe asks ns1.example.com for the A record itself; its TTL there (3600 s) makes the worst case exact', async () => {
      await gotoRoute(page, '#/global?name=cut.example.com&type=A&expect=198.51.100.20');
      await page.waitFor(DONE, { timeout: 20000, message: 'check done' });
      await page.waitFor(() => { const s = document.querySelector('[data-role="soa-slot"]'); return s && !s.hidden; }, { message: 'probe offered' });
      const posts = () => page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST'));
      const before = (await posts()).length;
      await page.evaluate(() => (document.querySelector('[data-action="soa-open"]:not([hidden])') || document.querySelector('[data-action="soa-run"]')).click());
      await page.waitFor(() => !!document.querySelector('[data-soa-state]') && !document.querySelector('[data-soa-status="running"]'), { message: 'the name server’s answer', timeout: 15000 });
      const sent = (await posts()).slice(before);
      assertEqual(sent.length, 1, 'one measurement, no second dialog');
      assertEqual(sent[0].body.measurementOptions.query, { type: 'A' }, 'the check’s own question: the old answers are records');
      const i = await info();
      assert(/cut\.example\.com exists there\./.test(i.soaResult.text) && /TTL of the A answer there: 3,600 s\./.test(i.soaResult.text), `result: ${i.soaResult.text}`);
      assertEqual([i.worst.seconds, i.worst.exact], ['3600', 'true'], 'the record’s own TTL');
      assert(/Worst case for any resolver in the world: 1 hour after the change was published\./.test(i.worst.text)
        && /The record’s TTL at the zone’s name server ns1\.example\.com: 3,600 s\./.test(i.worst.text) && !/estimate/.test(i.worst.text), `worst: ${i.worst.text}`);
    });

    await run.step('a11y: redrawing the card (an edit of the value, as the 30 s ticker does) inserts no alert into the probe panel again', async () => {
      await page.evaluate(() => {
        window.__inserted = [];
        window.__obs = new MutationObserver((list) => {
          for (const m of list) {
            for (const n of m.addedNodes) {
              if (n.nodeType === 1 && (n.matches('[role="alert"],[role="status"]') || n.querySelector('[role="alert"],[role="status"]'))) window.__inserted.push(n.textContent.slice(0, 60));
            }
          }
        });
        window.__obs.observe(document.querySelector('[data-role="soa-panel"]'), { childList: true, subtree: true });
        window.__noteNode = document.querySelector('[data-soa-state]');
      });
      for (const value of ['198.51.100.20,198.51.100.20', '198.51.100.20']) {
        await setField(page, 'global-expect', value);
        await page.waitFor((v) => document.querySelector('.glb-exp-pattern')?.textContent === v, { args: [value], message: `card redrawn for ${value}` });
      }
      const out = await page.evaluate(() => {
        window.__obs.disconnect();
        return { inserted: window.__inserted, same: window.__noteNode === document.querySelector('[data-soa-state]') };
      });
      assertEqual(out.inserted, [], 'no alert or status node inserted again');
      assert(out.same, 'the answer’s alert is the same node');
    });

    // Last of the probes: once the quota reads 0, the client keeps it for the rest of the hour's window.
    await run.step('a used-up quota sends nothing; the answer on screen stays', async () => {
      const posts = () => page.evaluate(() => window.__gp.calls.filter((c) => c.method === 'POST').length);
      const before = await posts();
      await page.evaluate(() => { window.__gp.remaining = 0; });
      await page.click('[data-action="soa-run"]');
      await page.waitFor(() => document.querySelector('[data-soa-status]')?.dataset.soaStatus === 'quota', { message: 'quota status', timeout: 15000 });
      const quota = await page.evaluate(() => document.querySelector('[data-soa-status]').textContent);
      assert(/quota for this hour is used up/.test(quota) && /Nothing was sent/.test(quota), `quota text: ${quota}`);
      assertEqual(await posts(), before, 'no POST');
      assert(await page.evaluate(() => !!document.querySelector('[data-soa-state]')), 'the last answer stays');
      await page.evaluate(() => { window.__gp.remaining = 250; });
    });

    run.group('DNS change request › the TTL planner as a calendar (.ics)');
    await run.step('the four steps as calendar events, the flush pages in the change’s event; English and Turkish', async () => {
      await page.evaluate(() => { window.location.hash = '#/change/check?z=example.com&r=is+www+A+192.0.2.10'; });
      await page.waitFor(() => document.querySelector('[data-page="check"]')?.dataset.round >= '1', { message: 'check page', timeout: 15000 });
      await page.waitFor(() => !!document.querySelector('.chg-cut-plan'), { message: 'planner', timeout: 10000 });
      await page.evaluate(() => { document.querySelector('.chg-cut-plan').open = true; });
      await page.waitFor(() => [...document.querySelectorAll('.chg-cut-step')].map((s) => s.dataset.step).join(',') === 'lower,change,live,raise', { message: 'four steps', timeout: 8000 });
      const flush = await page.evaluate(() => [...document.querySelectorAll('[data-part="flush"] a')].map((a) => a.getAttribute('href')));
      assertEqual(flush, FLUSH_LINKS.map((l) => l.url), 'the flush links under the checklist');
      const steps = await page.evaluate(() => [...document.querySelectorAll('.chg-cut-step')].map((s) => Number(s.dataset.at)));
      await takeDownloads(page);
      await page.click('[data-action="cut-ics"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'calendar saved' });
      const [en] = await takeDownloads(page);
      assert(/^dns-cutover-example\.com-\d{8}-\d{4}\.ics$/.test(en.name), `file: ${en.name}`);
      assert(en.type.startsWith('text/calendar'), `type: ${en.type}`);
      const flat = en.text.replace(/\r\n /g, '');
      assertEqual(flat.split('BEGIN:VEVENT').length - 1, 4, 'four events');
      assert(/\r\nX-WR-CALNAME:DNS cutover — example\.com\r\n/.test(flat), 'calendar name');
      const stamp = (ms) => `${new Date(ms).toISOString().slice(0, 19).replace(/[-:]/g, '')}Z`;
      for (const at of steps) assert(flat.includes(`DTSTART:${stamp(at)}`), `an event at ${stamp(at)}`);
      assert(/SUMMARY:Lower the TTL in example\.com: 3600 s → 300 s/.test(flat), 'the lower step');
      for (const l of FLUSH_LINKS) assert(flat.includes(l.url), `the change's event names ${l.url}`);
      assertEqual((flat.match(/TRIGGER:-PT15M/g) || []).length, 3, 'a reminder before each thing to do');
      await shot(page, opts, 'cutover-change-plan-desktop-light-en');
      await page.click('[data-control="cut-lang"] [data-value="tr"]');
      await page.waitFor(() => !!document.querySelector('[data-action="cut-ics"]') && /Türkçe/.test(document.querySelector('.chg-cut-list .codeblock-label')?.textContent || ''), { message: 'Turkish planner' });
      await page.click('[data-action="cut-ics"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'Turkish calendar saved' });
      const [tr] = await takeDownloads(page);
      const trFlat = tr.text.replace(/\r\n /g, '');
      assert(/\r\nX-WR-CALNAME:DNS geçişi — example\.com\r\n/.test(trFlat) && /SUMMARY:example\.com için DNS değişikliğini yapın/.test(trFlat), 'Turkish calendar');
      await page.click('[data-control="cut-lang"] [data-value="en"]');
    });

    run.group('Phones 375 / 320 px, light / dark, English / Turkish');
    await run.step('the expected value card, the form and the planner fit without horizontal scroll', async () => {
      for (const [lang, theme] of [['en', 'light'], ['tr', 'dark']]) {
        await setLangUi(page, lang);
        await page.emulateMedia({ 'prefers-color-scheme': theme });
        await gotoRoute(page, '#/global?name=cut.example.com&type=A&expect=198.51.100.20');
        await page.waitFor(DONE, { timeout: 20000, message: 'check done' });
        await page.waitFor(() => document.querySelector('[data-role="expected"]')?.dataset.state === 'pending', { message: 'card' });
        for (const width of [375, 320]) {
          await page.setViewport({ width, height: 812, mobile: true });
          await assertNoHorizontalScroll(page, `global ${lang} ${theme} ${width}`);
        }
        await page.setViewport({ width: 375, height: 812, mobile: true });
        await page.evaluate(() => document.querySelector('[data-role="expected"]').scrollIntoView({ block: 'start' }));
        await shot(page, opts, `cutover-global-expected-phone-${theme}-${lang}`);
        await page.evaluate(() => { window.location.hash = '#/change/check?z=example.com&r=is+www+A+192.0.2.10'; });
        await page.waitFor(() => !!document.querySelector('.chg-cut-plan'), { message: 'planner', timeout: 15000 });
        await page.evaluate(() => { document.querySelector('.chg-cut-plan').open = true; });
        await page.waitFor(() => !!document.querySelector('[data-action="cut-ics"]'), { message: 'planner output', timeout: 8000 });
        for (const width of [375, 320]) {
          await page.setViewport({ width, height: 812, mobile: true });
          await assertNoHorizontalScroll(page, `planner ${lang} ${theme} ${width}`);
        }
        await page.setViewport({ width: 1440, height: 900 });
      }
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Hygiene');
    await run.step('nothing left the page', async () => {
      assertEqual(external, [], 'requests that left the origin');
      assertEqual(await page.evaluate(() => window.__externalFetches), [], 'fetches the harness blocked');
    });
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'cutover', origin));
  } finally {
    await browser.close();
    await server.close();
  }
  run.finish();
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  });
}
