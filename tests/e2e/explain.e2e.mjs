#!/usr/bin/env node
/**
 * explain.e2e.mjs — DNS Lookup › Explain (ROADMAP P1.5) in a real headless browser, OFFLINE: every
 * DoH question is answered in the page from a small zone under example.com / .net / .org, and any
 * other request that leaves the page is refused and noted.
 *
 *   node tests/e2e/explain.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * Covers: the summary's Explain button (none for a reverse name); the SPF section — the record, the
 * lookup meter, Domain Health's findings, every term in order with its result and cost, an include's
 * policy one click away with "only a pass counts", a string join that breaks a term; "Does an address
 * pass?" for an address an include lists, one its carve-out leaves out (softfail), one only an
 * %{i} macro lists (pass, asked for that address), an mx host, a bad address; an a: host whose A
 * question got no answer (cannot tell, kept by the flatten preview), a sender that cannot be one;
 * the flatten preview; CAA that forbids S/MIME and VMC certificates;
 * DMARC tag by tag (pct, an external report domain) and inherited by a subdomain with its CAA; CAA
 * who may issue; HTTPS with a stale address hint and the ECH configuration decoded; the lookup's own
 * answers never asked again; a failed question as "n/a" with a Retry; a new lookup closes the panel;
 * the keyboard; 1440, 375 and 320 px in light and dark, English and Turkish; no console errors,
 * exceptions or CSP violations, complete i18n.
 */

import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { base64Encode } from '../../assets/js/lib/dnswire.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASE = '/domainscope/';
const argv = process.argv.slice(2);
const optValue = (name, def) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : def;
};
const BROWSER = optValue('--browser', 'auto');
const HEADED = argv.includes('--headed');
const SHOTS_ON = !argv.includes('--no-shots');
const SHOTS = path.resolve(optValue('--shots-dir', path.join(HERE, 'screenshots')));
const FLAKY_HOSTS = [...RESOLVERS.map((r) => new URL(r.url).hostname)];
const ALL_DONE = "!!document.querySelector('.lkp-sum') && !document.querySelector('.lkp-card[data-state=\"pending\"]') && document.querySelector('[data-action=\"run\"]')?.getAttribute('aria-busy') !== 'true'";
const EXPLAINED = "['done', 'error'].includes(document.querySelector('.xpl-panel')?.dataset.state)";

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
    // A 429 the test asked for is a failed resource load in the log, like any rate limit.
    if (FLAKY_HOSTS.some((host) => text.includes(`//${host}/`)) || /status of 429/.test(text)) notes.push(`${where}: tolerated ${e.source} error for an answer the test refused`);
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
    const en = i.listKeys('en').filter((k) => k.startsWith('xpl.'));
    const tr = i.listKeys('tr').filter((k) => k.startsWith('xpl.'));
    return { missing: i.getMissingKeys(), onlyEn: en.filter((k) => !tr.includes(k)), onlyTr: tr.filter((k) => !en.includes(k)) };
  });
  assertEqual(info.missing, [], 'missing i18n keys');
  assertEqual(info.onlyEn, [], 'xpl.* keys only in EN');
  assertEqual(info.onlyTr, [], 'xpl.* keys only in TR');
}

/* ------------------------------------------------------------------------ */
/* The zone, answered in the page                                           */
/* ------------------------------------------------------------------------ */

const u16 = (n) => [(n >> 8) & 0xff, n & 0xff];
/** An ECHConfigList (version 0xfe0d, X25519, HKDF-SHA256 + AES-128-GCM), public name ech.example.net. */
function echList() {
  const name = [...'ech.example.net'].map((c) => c.charCodeAt(0));
  const key = Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
  const contents = [0x2a, ...u16(0x0020), ...u16(32), ...key, ...u16(4), ...u16(1), ...u16(1), 0, name.length, ...name, ...u16(0)];
  const config = [...u16(0xfe0d), ...u16(contents.length), ...contents];
  return base64Encode(Uint8Array.from([...u16(config.length), ...config]));
}

/** Documentation names and addresses only. */
const ZONE = {
  'example.com': {
    A: ['192.0.2.1'],
    AAAA: ['2001:db8::1'],
    MX: [{ preference: 10, exchange: 'mx1.example.com' }],
    TXT: [['v=spf1 ip4:192.0.2.0/28 include:_spf.example.net exists:%{i}._allow.example.com mx ~all'], ['google-site-verification=abcdefghijklmnop']],
    CAA: [
      { flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=dns-01' },
      { flags: 0, tag: 'issuewild', value: ';' },
      { flags: 0, tag: 'iodef', value: 'mailto:security@example.com' }
    ],
    HTTPS: [{ priority: 1, target: '.', params: { alpn: ['h3', 'h2'], ipv4hint: ['192.0.2.1', '192.0.2.99'], ech: echList(), ipv6hint: ['2001:db8::1'] } }]
  },
  'mx1.example.com': { A: ['203.0.113.25'] },
  '_spf.example.net': { TXT: [['v=spf1 -ip4:198.51.100.66 ip4:198.51.100.0/24 ~all']] },
  '203.0.113.7._allow.example.com': { A: ['127.0.0.2'] },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com,mailto:reports@example.net; ri=3600']] },
  'shop.example.com': { A: ['192.0.2.30'], TXT: [['v=spf1 include:_spf.example.net -all']] },
  'split.example.org': { TXT: [['v=spf1 ip4:192.0.2.0/24', 'include:_spf.example.net -all']] },
  '_dmarc.example.org': { TXT: [['v=DMARC1; p=reject']] },
  'mail.example.net': { TXT: [['v=spf1 -all']], MX: [{ preference: 10, exchange: 'mx1.example.com' }] },
  // An a: host whose A question the test fails (its AAAA answers); CAA that forbids S/MIME and VMC certificates.
  'mail.example.org': {
    TXT: [['v=spf1 a:relay.example.org mx -all']],
    MX: [{ preference: 10, exchange: 'mx1.example.org' }],
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'issuemail', value: ';' }, { flags: 0, tag: 'issuevmc', value: ';' }]
  },
  'relay.example.org': { A: ['192.0.2.10'], AAAA: ['2001:db8::10'] },
  'mx1.example.org': { A: ['203.0.113.26'] },
  '_dmarc.example.net': { TXT: [['v=DMARC1; p=reject']] }
};

/**
 * An in-page DoH from `ZONE`: `window.__xplAsked` lists every question (`name|TYPE`), a key in
 * `window.__xplFail` gets HTTP 429 from every resolver, any other request that leaves the page is
 * refused and noted in `window.__xplBlocked`.
 */
const dohScript = (zone) => `(() => {
  const ZONE = ${JSON.stringify(zone)};
  const SOA = { mname: 'ns1.example.net', rname: 'hostmaster.example.net', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
  window.__xplAsked = [];
  window.__xplFail = [];
  window.__xplBlocked = [];
  const below = (name) => Object.keys(ZONE).some((k) => k.endsWith('.' + name));
  const answer = (name, type) => {
    const node = ZONE[name];
    if (!node) return { rcode: below(name) ? 'NOERROR' : 'NXDOMAIN', answers: [], authorities: [{ name: 'example.net', type: 'SOA', ttl: 300, data: SOA }] };
    const answers = (node[type] || []).map((data) => ({ name, type, ttl: 300, data }));
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: 'example.net', type: 'SOA', ttl: 300, data: SOA }] };
  };
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (new URL(url, location.href).origin === location.origin) return realFetch(input, init);
      window.__xplBlocked.push(url);
      throw new TypeError('blocked by the E2E (Explain)');
    }
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    const key = name + '|' + q.type;
    window.__xplAsked.push(key);
    if (window.__xplFail.includes(key)) return new Response('Too Many Requests', { status: 429 });
    if (!/(^|[.])example[.](com|net|org)$/.test(name) && !name.endsWith('.in-addr.arpa')) {
      window.__xplBlocked.push('dns:' + key);
      return new Response('outside the zone', { status: 404 });
    }
    const out = answer(name, q.type);
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/** What the panel shows. */
function panelInfo() {
  const panel = document.querySelector('.xpl-panel');
  if (!panel) return null;
  const sec = (key) => panel.querySelector(`.xpl-sec[data-section="${key}"]`);
  const text = (el) => (el ? el.textContent.replace(/\s+/g, ' ').trim() : '');
  const spf = sec('spf');
  return {
    state: panel.dataset.state || '',
    sections: [...panel.querySelectorAll('.xpl-sec')].map((s) => s.dataset.section),
    spf: spf ? {
      record: text(spf.querySelector('.xpl-record-text')),
      meter: spf.querySelector('.xpl-meter')?.dataset.count || '',
      meterText: text(spf.querySelector('.xpl-meter-head')),
      findings: [...spf.querySelectorAll(':scope > div > .xpl-findings > .xpl-finding')].map((f) => f.dataset.check),
      steps: [...spf.querySelectorAll(':scope > .xpl-policy > .xpl-steps > .xpl-step')].map((s) => [s.dataset.term, s.dataset.result, s.dataset.state]),
      text: text(spf)
    } : null,
    dmarc: text(sec('dmarc')),
    dmarcRows: [...(sec('dmarc')?.querySelectorAll('.xpl-tag-row') || [])].map((r) => [r.dataset.tag, r.dataset.meaning]),
    caa: text(sec('caa')),
    caaRows: [...(sec('caa')?.querySelectorAll('.xpl-tag-row') || [])].map((r) => [r.dataset.tag, r.dataset.usable]),
    svcb: text(sec('svcb')),
    svcbNotes: [...(sec('svcb')?.querySelectorAll('.xpl-finding') || [])].map((f) => f.dataset.note),
    foot: text(panel.querySelector('.xpl-foot')),
    title: text(panel.querySelector('.xpl-title'))
  };
}

async function openExplain(page, name, types) {
  await gotoHash(page, `#/lookup?name=${name}&type=${types}`, 'lookup');
  await page.waitFor(ALL_DONE, { timeout: 30000, message: `${name} answered` });
  await page.waitFor((n) => document.querySelector('.lkp-sum-name')?.textContent === n, { args: [name], message: `${name} summary` });
  await page.click('[data-action="explain"]');
  await page.waitFor(EXPLAINED, { timeout: 30000, message: `${name} explained` });
  return page.evaluate(panelInfo);
}

/** Type an address (and optionally a sender) into "Does an address pass?" and check it. */
async function checkAddress(page, ip) {
  await page.type('[data-role="explain-ip"]', ip);
  await page.click('[data-action="explain-check"]');
  // The verdict of this address (a canonical one), or the field's error with no verdict left on screen.
  await page.waitFor((a) => !!document.querySelector(`.xpl-verdict[data-ip="${a}"]`)
    || (!document.querySelector('.xpl-verdict') && !!document.querySelector('.xpl-check-ip .field-error:not([hidden])')?.textContent),
  { args: [ip], timeout: 20000, message: `${ip} checked` });
  return page.evaluate(() => {
    const v = document.querySelector('.xpl-verdict');
    return v ? { result: v.dataset.result, reason: v.dataset.reason, term: v.dataset.term, text: v.textContent.replace(/\s+/g, ' ').trim() }
      : { error: document.querySelector('.xpl-check-ip .field-error').textContent };
  });
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  if (SHOTS_ON) await mkdir(SHOTS, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: BROWSER, headless: !HEADED });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}\n`);
  try {
    await explainGroup(browser, server);
  } finally {
    await browser.close();
    await server.close();
  }
  const failed = results.filter((r) => !r.ok);
  for (const n of [...new Set(notes)]) process.stdout.write(`  note: ${n}\n`);
  process.stdout.write(`\n${results.length - failed.length} passed, ${failed.length} failed${SHOTS_ON ? ` — screenshots in ${SHOTS}` : ''}\n`);
  if (failed.length) {
    for (const f of failed) process.stdout.write(`  - ${f.group}: ${f.name}\n`);
    process.exitCode = 1;
  }
}

async function explainGroup(browser, server) {
  group('Offline: DNS Lookup › Explain (example.com / .net / .org answered in the page)');
  const page = await browser.newPage('about:blank', { width: 1440, height: 900 });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: dohScript(ZONE) });
  await page.emulateMedia({ 'prefers-color-scheme': 'light' });
  try {
    await step('Explain: SPF term by term with its meter and findings, DMARC and CAA tag by tag, HTTPS with a stale hint and ECH', async () => {
      await page.goto(`${server.url}#/about`);
      await waitReady(page);
      await setLangUi(page, 'en');
      const before = await page.evaluate(() => window.__xplAsked.length);
      const info = await openExplain(page, 'example.com', 'TXT,MX,CAA,HTTPS');
      assertEqual(info.state, 'done', 'panel state');
      assertEqual(info.sections, ['spf', 'dmarc', 'caa', 'svcb'], 'sections');
      assertEqual(info.spf.record, 'v=spf1 ip4:192.0.2.0/28 include:_spf.example.net exists:%{i}._allow.example.com mx ~all', 'the SPF record');
      assertEqual(info.spf.meter, '3', 'lookups');
      assert(/DNS lookups: 3 of 10/.test(info.spf.meterText) && /Lookups that find nothing: 0 of 2/.test(info.spf.meterText), info.spf.meterText);
      assertEqual(info.spf.findings, ['spf.all-softfail'], 'findings');
      assertEqual(info.spf.steps, [
        ['ip4:192.0.2.0/28', 'pass', 'ok'], ['include:_spf.example.net', 'pass', 'ok'],
        ['exists:%{i}._allow.example.com', 'pass', 'macro'], ['mx', 'pass', 'ok'], ['~all', 'softfail', 'ok']
      ], 'steps');
      assert(info.spf.text.includes('Mail from 192.0.2.0 to 192.0.2.15 (16 addresses) matches.'), 'the range in words');
      assert(info.spf.text.includes('mail servers: mx1.example.com'), 'the mx hosts');
      // The DMARC record: pct, an external report domain that must allow the reports.
      assert(info.dmarc.includes('Published at _dmarc.example.com.') && info.dmarc.includes('treated as suspicious') && info.dmarc.includes('Only 50% of it; the rest gets none.'), info.dmarc.slice(0, 400));
      assert(info.dmarc.includes('example.com._report._dmarc.example.net'), 'the external report domain');
      assertEqual(info.dmarcRows.map((r) => r[0]), ['v', 'p', 'sp', 'pct', 'rua', 'adkim', 'aspf', 'ri'], 'DMARC rows');
      assert(info.dmarc.includes('Aggregate report interval: 1 h'), 'the report interval');
      assert(info.caa.includes("May issue: Let's Encrypt (letsencrypt.org)") && info.caa.includes('Wildcard certificates: no CA') && info.caa.includes('Only with dns-01 validation.'), info.caa);
      assertEqual(info.caaRows, [['issue', '1'], ['issuewild', '0'], ['iodef', '0']], 'CAA rows');
      assertEqual(info.svcbNotes, ['h3', 'hint-stale', 'ech'], 'HTTPS notes');
      assert(info.svcb.includes('192.0.2.99 is not an address of example.com') && info.svcb.includes('outer name ech.example.net') && info.svcb.includes('DHKEM(X25519, HKDF-SHA256)'), info.svcb);
      // The lookup's own answers were reused: none of its questions was asked again.
      const asked = await page.evaluate((n) => window.__xplAsked.slice(n), before);
      for (const type of ['TXT', 'MX', 'CAA', 'HTTPS']) assertEqual(asked.filter((k) => k === `example.com|${type}`).length, 1, `example.com ${type} asked once (by the lookup)`);
      for (const k of ['_spf.example.net|TXT', '_dmarc.example.com|TXT', 'example.com|A', 'example.com|AAAA', 'mx1.example.com|A']) assert(asked.includes(k), `asked ${k}`);
      assert(!asked.some((k) => k.includes('_allow.example.com')), 'the %{i} macro is not asked without an address');
      assert(/Asked \d+ more questions through/.test(info.foot), info.foot);
      await shot(page, 'explain-desktop-light-en');
    });

    await step('an include’s policy is one click away: only a pass counts there', async () => {
      await page.click('.xpl-spf .xpl-child summary');
      const child = await page.evaluate(() => {
        const box = document.querySelector('.xpl-spf .xpl-child[open]');
        return box ? {
          steps: [...box.querySelectorAll('.xpl-step')].map((s) => [s.dataset.term, s.dataset.result]),
          noMatch: [...box.querySelectorAll('.xpl-no-match')].map((b) => b.textContent.trim()),
          text: box.textContent.replace(/\s+/g, ' ')
        } : null;
      });
      assert(child, 'the include opened');
      assertEqual(child.steps, [['-ip4:198.51.100.66', 'no-match'], ['ip4:198.51.100.0/24', 'pass'], ['~all', 'no-match']], 'the include’s steps');
      assertEqual(child.noMatch, ['counts as no match', 'counts as no match'], 'the fail and the softfail count as no match');
      assert(child.text.includes('Inside an include only a pass counts'), child.text.slice(0, 300));
    });

    await step('Does an address pass? An include, its carve-out, an %{i} macro asked for that address, an mx host, a bad address', async () => {
      let v = await checkAddress(page, '198.51.100.20');
      assertEqual([v.result, v.term], ['pass', 'ip4:198.51.100.0/24'], `include: ${v.text}`);
      assert(v.text.includes('in the policy of _spf.example.net') && v.text.includes('example.com → _spf.example.net'), v.text);
      v = await checkAddress(page, '198.51.100.66');
      assertEqual([v.result, v.term], ['softfail', '~all'], `the carve-out: ${v.text}`);
      const asked = await page.evaluate(() => window.__xplAsked.length);
      v = await checkAddress(page, '203.0.113.7');
      assertEqual([v.result, v.term], ['pass', 'exists:%{i}._allow.example.com'], `the macro: ${v.text}`);
      assert((await page.evaluate((n) => window.__xplAsked.slice(n), asked)).includes('203.0.113.7._allow.example.com|A'), 'the macro asked for that address');
      v = await checkAddress(page, '203.0.113.25');
      assertEqual([v.result, v.term], ['pass', 'mx'], `the mx host: ${v.text}`);
      assert(v.text.includes('Matched through mx1.example.com (203.0.113.25).'), v.text);
      v = await checkAddress(page, '192.0.2');
      assert(/Enter an IPv4 or IPv6 address/.test(v.error || ''), `a bad address: ${JSON.stringify(v)}`);
    });

    await step('the flatten preview: the addresses of today, the macro term kept', async () => {
      await page.click('.xpl-flat summary');
      const flat = await page.evaluate(() => ({
        record: document.querySelector('.xpl-flat-record code').textContent,
        notes: [...document.querySelectorAll('.xpl-flat .xpl-finding')].map((f) => f.dataset.code)
      }));
      assertEqual(flat.record, 'v=spf1 ip4:192.0.2.0/28 ip4:198.51.100.0/24 exists:%{i}._allow.example.com ip4:203.0.113.25 ~all', 'the flattened record');
      assertEqual(flat.notes, ['exceptions', 'sender'], 'its notes');
    });

    await step('a subdomain inherits DMARC (its sp) and CAA; strings that join without a space break a term', async () => {
      const shop = await openExplain(page, 'shop.example.com', 'A,TXT');
      assert(shop.dmarc.includes('No record at _dmarc.shop.example.com: the organizational domain’s record at _dmarc.example.com applies'), shop.dmarc.slice(0, 300));
      assert(shop.caa.includes('No CAA at shop.example.com: the set of example.com applies'), shop.caa.slice(0, 300));
      assert(shop.svcb.includes('No HTTPS record'), shop.svcb);
      const split = await openExplain(page, 'split.example.org', 'TXT');
      assertEqual(split.spf.findings[0], 'join', `findings: ${split.spf.findings}`);
      assert(split.spf.text.includes('Strings 1 and 2 join without a space, so receivers read “ip4:192.0.2.0/24include:_spf.example.net”'), split.spf.text.slice(0, 500));
      assert(split.dmarc.includes('the organizational domain’s record at _dmarc.example.org applies'), `a name with SPF sends mail: ${split.dmarc.slice(0, 300)}`);
    });

    await step('an A question that got no answer: the a term says so, the check cannot tell, the preview keeps it; CAA forbids S/MIME and VMC; a sender that is none', async () => {
      await page.evaluate(() => { window.__xplFail = ['relay.example.org|A']; });
      const info = await openExplain(page, 'mail.example.org', 'TXT');
      assertEqual(info.spf.steps, [['a:relay.example.org', 'pass', 'partial'], ['mx', 'pass', 'ok'], ['-all', 'fail', 'ok']], 'steps');
      assert(info.spf.text.includes('Got no answer here for the IPv4 addresses of relay.example.org'), info.spf.text.slice(0, 700));
      const v = await checkAddress(page, '192.0.2.10');
      assertEqual([v.result, v.reason, v.term], ['unknown', 'lookup-failed', 'a:relay.example.org'], v.text);
      await page.click('.xpl-flat summary');
      const flat = await page.evaluate(() => ({
        record: document.querySelector('.xpl-flat-record code').textContent,
        notes: [...document.querySelectorAll('.xpl-flat .xpl-finding')].map((f) => f.dataset.code)
      }));
      assertEqual(flat, { record: 'v=spf1 a:relay.example.org ip4:203.0.113.26 -all', notes: ['failed'] }, 'the flatten preview');
      assert(info.caa.includes('No CA may issue S/MIME (email) certificates (an empty value).')
        && info.caa.includes('No CA may issue Verified Mark Certificates (an empty value).'), info.caa);
      // A space cannot be in a MAIL FROM: the field says so, its disclosure open, and no verdict stays.
      await page.click('.xpl-check-more summary');
      await page.type('[data-role="explain-sender"]', 'a b@example.org');
      await page.click('[data-action="explain-check"]');
      await page.waitFor(() => !document.querySelector('.xpl-verdict')
        && /Enter an email address/.test(document.querySelector('.xpl-check-more[open] .field-error:not([hidden])')?.textContent || ''),
      { timeout: 20000, message: 'the sender field error' });
      await page.evaluate(() => { window.__xplFail = []; });
    });

    await step('a question that got no answer: "n/a" with a Retry that asks again; a new lookup closes the panel', async () => {
      // A question nothing asked before (the DoH client's cache would answer it otherwise).
      await page.evaluate(() => { window.__xplFail = ['_dmarc.example.net|TXT']; });
      const info = await openExplain(page, 'mail.example.net', 'TXT,MX');
      assert(/⚠ DNS resolver: rate limited/.test(info.dmarc), `the DMARC section says why: ${info.dmarc}`);
      assert(info.spf && info.spf.record === 'v=spf1 -all', 'the other sections are there');
      await page.evaluate(() => { window.__xplFail = []; });
      await page.click('.xpl-dmarc [data-action="retry-source"]');
      await page.waitFor(() => /Mail from mail\.example\.net that fails DMARC is rejected/.test(document.querySelector('.xpl-dmarc')?.textContent || ''),
        { timeout: 30000, message: 'DMARC after the Retry' });
      await gotoHash(page, '#/lookup?name=example.net&type=A', 'lookup');
      await page.waitFor(ALL_DONE, { timeout: 30000, message: 'example.net answered' });
      assertEqual(await page.evaluate(() => document.querySelectorAll('.xpl-panel').length), 0, 'no panel of the old lookup');
      await gotoHash(page, '#/lookup?name=192.0.2.1&type=PTR', 'lookup');
      await page.waitFor(ALL_DONE, { timeout: 30000, message: 'the reverse name answered' });
      assertEqual(await page.evaluate(() => !!document.querySelector('[data-action="explain"]')), false, 'no Explain for a reverse name');
    });

    await step('the keyboard: Explain from its button, an address checked with Enter', async () => {
      await gotoHash(page, '#/lookup?name=example.com&type=TXT', 'lookup');
      await page.waitFor(ALL_DONE, { timeout: 30000, message: 'answered' });
      await page.evaluate(() => document.querySelector('[data-action="explain"]').focus());
      await page.press('Enter');
      await page.waitFor(EXPLAINED, { timeout: 30000, message: 'explained' });
      await page.evaluate(() => document.querySelector('[data-role="explain-ip"]').focus());
      await page.type('[data-role="explain-ip"]', '192.0.2.5');
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.xpl-verdict')?.dataset.result === 'pass', { timeout: 20000, message: 'checked with Enter' });
    });

    for (const [scheme, lang, width] of [['light', 'en', 375], ['dark', 'tr', 375], ['dark', 'tr', 1440], ['light', 'tr', 320]]) {
      await step(`[${scheme}, ${lang.toUpperCase()}, ${width} px] the panel reads well and fits`, async () => {
        await page.setViewport(width < 600 ? { width, height: 812, mobile: true } : { width, height: 900 });
        await page.emulateMedia({ 'prefers-color-scheme': scheme });
        await setLangUi(page, lang);
        const info = await openExplain(page, 'example.com', 'TXT,MX,CAA,HTTPS');
        assertEqual(info.sections, ['spf', 'dmarc', 'caa', 'svcb'], 'sections');
        if (lang === 'tr') {
          assertEqual(info.title, 'Kayıtları açıkla', 'Turkish title');
          assert(info.spf.text.includes('DNS sorguları: 3/10') && info.caa.includes('Sertifika verebilir'), info.spf.text.slice(0, 300));
          assert(info.dmarc.includes('Toplu rapor aralığı: 1 sa (alıcıların çoğu yine de günde bir gönderir).'), info.dmarc.slice(0, 600));
        }
        await page.click('.xpl-spf .xpl-child summary');
        const v = await checkAddress(page, '198.51.100.20');
        assertEqual(v.result, 'pass', `checked at ${width}`);
        await assertNoHorizontalScroll(page, `${scheme} ${lang} ${width}`);
        await shot(page, `explain-${width < 600 ? `mobile${width}` : 'desktop'}-${scheme}-${lang}`);
      });
    }

    await step('Explain: nothing left the page, i18n complete, no console errors', async () => {
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'en');
      assertEqual(await page.evaluate(() => window.__xplBlocked.slice()), [], 'requests outside the zone');
      await checkI18n(page);
      await assertClean(page, 'explain');
    });
  } finally {
    await page.setViewport({ width: 1440, height: 900 });
    await page.close();
  }
}

main().catch((err) => {
  process.stdout.write(`\nFATAL ${err && err.stack ? err.stack : err}\n`);
  process.exitCode = 1;
});
