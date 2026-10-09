#!/usr/bin/env node
/**
 * waivers.e2e.mjs — accepted risks and known certificates (lib/waivers.js, ui/waivers.js) in a
 * real headless Chrome/Edge, OFFLINE: DoH, the RDAP bootstrap and registry and Cert Spotter are
 * answered in the page from a small world (window.fetch wrapped before the app loads); any other
 * request that leaves the page is refused and noted, and a network-level guard (CDP Fetch) fails
 * any https request that still gets out. The page's clock starts at 2026-10-09 12:00 UTC, then is
 * moved past the waiver's end date.
 *
 *   node tests/e2e/waivers.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir <dir>]
 *
 * What is checked:
 *   - Domain Health: "Accept this risk…" (opened from the keyboard) asks for a reason, an owner and an
 *     end date (a reason is required); the finding leaves the problems, the counts and the score, the
 *     hero says "1 accepted risk (until …)" with the score including it, the check row is marked and
 *     its "All checks" card counts it apart, the focus lands on its Remove, Copy summary says "1
 *     accepted risk excluded"; while a check runs the old report's Accept and Remove are disabled;
 *     the what-if planner projects the score of the ticked problems; the waiver is kept across a
 *     reload (IndexedDB) and a language switch (Turkish); Remove makes it count again; then the clock
 *     passes its end date and the finding counts again, saying its acceptance expired;
 *   - the Domain overview: its health card leaves the accepted risk out too — the same score and light
 *     as Domain Health, the problems without it, the line that says so, Copy summary — at 375 px;
 *   - the Workspaces dialog: the waiver listed as expired, waivers.json exported (the runner reads it
 *     back with lib/waivers.js), the expired ones removed, an import merged with the entry it could
 *     not read said;
 *   - the Domain portfolio's policy matrix: an imported rule waiver makes its failed cell "Accepted",
 *     "Accept…" on another failed cell (its dialog says what accepting a rule does), the counts, the
 *     CSV's WAIVED;
 *   - the CT tab: an imported known certificate is flagged "Known"; a certificate from an unexpected CA
 *     logged since the last check offers "Known certificate…", and once known it is neither new nor
 *     unexpected; once that acceptance is over it is flagged again and says so;
 *   - 375 and 320 px in Turkish and English, light and dark, without horizontal scroll; no missing
 *     i18n keys; zero console errors, exceptions and CSP violations; nothing sent outside the page.
 *
 * Documentation names and addresses only.
 */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { pinnedClockScript } from './clock.mjs';
import { spotterRow } from '../js/ct-fake.mjs';
import { parseWaivers } from '../../assets/js/lib/waivers.js';
import {
  BASE, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner, gotoRoute,
  installDownloadCapture, setLangUi, stubClipboard, takeClipboard, takeDownloads, waitReady
} from './scan.e2e.mjs';

/** The instant the expectations were written for; the page's clock starts here on every load. */
const NOW = Date.parse('2026-10-09T12:00:00Z');
/** The day after the waiver's last day (2026-10-20). */
const LATER = Date.parse('2026-10-21T12:00:00Z');
const HEALTH_DONE = "!!document.querySelector('.hlt-hero') && !document.querySelector('[data-action=\"run\"]').hidden && !!document.querySelector('.hv2-problems')";
const LE = "C=US, O=Let's Encrypt, CN=R11";
const OTHER_CA = 'C=US, O=Example Other CA, CN=Example Other CA R3';
const LE_KEY = 'a1'.repeat(32);
const OTHER_KEY = 'b2'.repeat(32);

/* ------------------------------------------------------------------------ */
/* The world, answered in the page                                          */
/* ------------------------------------------------------------------------ */

const SOA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026100901, refresh: 3600, retry: 900, expire: 1209600, minimum: 300 };
/** Documentation names and addresses only: example.com with DMARC at p=none and a mail server without reverse DNS. */
const WORLD = {
  'example.com': {
    A: ['192.0.2.80'], SOA: [SOA], NS: ['ns1.example.com', 'ns2.example.net'], MX: [{ preference: 10, exchange: 'mx.example.com' }],
    TXT: [['v=spf1 mx -all']], CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }]
  },
  'www.example.com': { A: ['192.0.2.80'] },
  'ns1.example.com': { A: ['192.0.2.53'] },
  'ns2.example.net': { A: ['198.51.100.53'] },
  'mx.example.com': { A: ['192.0.2.25'] },
  // the mail server's reverse DNS points back at it (FCrDNS): DMARC at p=none is the one warning
  '25.2.0.192.in-addr.arpa': { PTR: ['mx.example.com'] },
  '_dmarc.example.com': { TXT: [['v=DMARC1; p=none; rua=mailto:dmarc@example.com']] },
  'example.net': { A: ['198.51.100.80'], SOA: [{ ...SOA, mname: 'ns1.example.net' }], NS: ['ns2.example.net'] }
};

/** Cert Spotter's answers: round 1 the Let's Encrypt certificate, from round 2 one from another CA too. */
function spotterRows() {
  const le = { ...spotterRow({ names: ['example.com', 'www.example.com'], notBefore: '2026-09-20T00:00:00Z', notAfter: '2026-12-19T00:00:00Z', serial: 31, issuer: LE, friendly: "Let's Encrypt" }), pubkey_sha256: LE_KEY };
  const other = { ...spotterRow({ names: ['cdn.example.com'], notBefore: '2026-10-05T00:00:00Z', notAfter: '2027-01-03T00:00:00Z', serial: 32, issuer: OTHER_CA, friendly: 'Example Other CA' }), pubkey_sha256: OTHER_KEY };
  return { le, other };
}

/**
 * The page's network: DoH from `WORLD` (CNAME chains followed), the IANA bootstrap and
 * rdap.registry.invalid (example.com and example.net registered), Cert Spotter (`__ww.round`).
 * Every question lands in `__ww.dns`, every RDAP domain in `__ww.rdap`, every Cert Spotter request
 * in `__ww.ct`, anything else is refused and lands in `__ww.blocked`.
 */
const worldScript = (world, rows) => `(() => {
  const WORLD = ${JSON.stringify(world)};
  const ROWS = ${JSON.stringify(rows)};
  const ww = window.__ww = { dns: [], rdap: [], ct: [], blocked: [], round: 1 };
  const day = 864e5;
  const below = (name) => Object.keys(WORLD).some((k) => k.endsWith('.' + name));
  const answer = (qname, type) => {
    const answers = [];
    let name = qname;
    for (let hop = 0; hop < 8; hop += 1) {
      const node = WORLD[name];
      if (!node) return { rcode: below(name) ? 'NOERROR' : 'NXDOMAIN', answers };
      if (node.CNAME && type !== 'CNAME') {
        answers.push({ name, type: 'CNAME', ttl: 300, data: node.CNAME });
        name = node.CNAME;
        continue;
      }
      for (const data of node[type] || []) answers.push({ name, type, ttl: 300, data });
      return { rcode: 'NOERROR', answers };
    }
    return { rcode: 'SERVFAIL', answers };
  };
  const json = (body, status = 200, type = 'application/rdap+json') => new Response(JSON.stringify(body), { status, headers: { 'content-type': type } });
  const domainJson = (d, days) => ({
    objectClassName: 'domain', ldhName: d.toUpperCase(), status: ['client transfer prohibited'],
    events: [{ eventAction: 'registration', eventDate: '2001-05-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: new Date(Date.now() + days * day).toISOString() }]
  });
  const realFetch = window.fetch.bind(window);
  let wire = null;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    if (url === 'https://data.iana.org/rdap/dns.json') {
      return json({ version: '1.0', publication: '2026-10-01T00:00:00Z', services: [[['com', 'net', 'org'], ['https://rdap.registry.invalid/']]] });
    }
    const rd = /^https:[/][/](?:rdap[.]registry[.]invalid|rdap[.]org)[/]domain[/]([^/?#]+)$/.exec(url);
    if (rd) {
      const d = rd[1].toLowerCase();
      ww.rdap.push(d);
      if (d === 'example.com') return json(domainJson(d, 300));
      if (d === 'example.net') return json(domainJson(d, 500));
      return json({ errorCode: 404, title: 'Not Found' }, 404);
    }
    if (url.startsWith('https://api.certspotter.com/')) {
      const u = new URL(url);
      ww.ct.push(u.searchParams.get('domain') + (u.searchParams.get('after') ? ' next' : ''));
      if (u.searchParams.get('after') || u.searchParams.get('domain') !== 'example.com') return json([], 200, 'application/json');
      return json(ww.round >= 2 ? [ROWS.le, ROWS.other] : [ROWS.le], 200, 'application/json');
    }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (new URL(url, location.href).origin === location.origin) return realFetch(input, init);
      ww.blocked.push(url);
      throw new TypeError('blocked by the E2E (waivers world)');
    }
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    ww.dns.push(name + '|' + q.type);
    const out = answer(name, q.type);
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode, questions: [{ name: q.name, type: q.type }], answers: out.answers,
      authorities: out.answers.length ? [] : [{ name: 'example.com', type: 'SOA', ttl: 300, data: ${JSON.stringify(SOA)} }], edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

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

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

const opts = cliOptions();
const SHOTS_DIR = path.resolve(opts.value('--shots-dir', SHOTS));
const run = createRunner();
const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);

/** Element screenshot (beyond the viewport if needed); no-op with --no-shots. */
async function shotEl(page, name, selector) {
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
  await mkdir(SHOTS_DIR, { recursive: true });
  const clip = { x: box.x, y: box.y, width: Math.ceil(box.width), height: Math.min(Math.ceil(box.height), 9000), scale: 1 };
  const { data } = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
  await writeFile(path.join(SHOTS_DIR, `${name}.png`), Buffer.from(data, 'base64'));
}

/** Elements under `selector` sticking out of the viewport (table scrollers scroll inside). */
const overflowingIn = (page, selector) => page.evaluate((sel) => {
  const root = document.querySelector(sel);
  if (!root) return ['(missing)'];
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

/** What the hero and the problems card show. */
const healthInfo = (page) => page.evaluate(() => {
  const hero = document.querySelector('.hlt-hero');
  const card = document.querySelector('.hv2-problems');
  return {
    score: hero ? Number(hero.dataset.score) : null,
    grade: hero ? hero.dataset.grade : null,
    light: hero ? hero.dataset.light : null,
    waived: document.querySelector('[data-role="hero-waived"]')?.textContent.replace(/\s+/g, ' ').trim() || null,
    problems: card ? [...card.querySelectorAll('.hv2-section:not(.hv2-section-accepted) .hv2-problem')].map((li) => li.dataset.id) : [],
    accepted: card ? [...card.querySelectorAll('.hv2-section-accepted .hv2-problem')].map((li) => [li.dataset.id, li.querySelector('[data-role="waiver-line"]')?.textContent.trim() || '']) : [],
    expired: card ? [...card.querySelectorAll('[data-role="waiver-expired"]')].map((p) => p.textContent.trim()) : []
  };
});

/** Fill the waiver dialog and press its main button; resolves once it is closed. */
async function fillDialog(page, { reason = null, owner = null, expires = null } = {}) {
  await page.evaluate((v) => {
    const set = (sel, value) => {
      if (value === null) return;
      const el = document.querySelector(sel);
      el.value = value;
      el.dispatchEvent(new Event('input', { bubbles: true }));
    };
    set('dialog.wvr-modal [data-role="wvr-reason"]', v.reason);
    set('dialog.wvr-modal [data-role="wvr-owner"]', v.owner);
    set('dialog.wvr-modal [data-role="wvr-expires"]', v.expires);
  }, { reason, owner, expires });
  await page.click('dialog.wvr-modal [data-action="wvr-save"]');
  await page.waitFor(() => !document.querySelector('dialog.wvr-modal'), { message: 'the dialog closed' });
}

const blocked = (page) => page.evaluate(() => window.__ww.blocked.slice());

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

async function main() {
  if (opts.shots) await mkdir(SHOTS_DIR, { recursive: true });
  const server = await startServer({ base: BASE });
  const browser = await launchBrowser({ browser: opts.browser, headless: !opts.headed });
  const version = await browser.version();
  process.stdout.write(`\nServing ${server.url} — ${version.product}\n`);
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'ds-waivers-e2e-'));
  let page = null;
  let netHits = [];
  try {
    page = await browser.newPage('about:blank', { width: 1440, height: 900 });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: pinnedClockScript(NOW) });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: worldScript(WORLD, spotterRows()) });
    netHits = await networkGuard(page);
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });
    await page.goto(`${server.url}#/about`);
    await waitReady(page);
    await setLangUi(page, 'en');
    let before = null;

    run.group('Domain Health: accept a finding, then let its end date pass (1440×900, English, light)');
    await run.step('the what-if planner (before anything is accepted): tick a problem, read the score and the grade it would give', async () => {
      await gotoRoute(page, '#/health?domain=example.com');
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'the health check' });
      before = await healthInfo(page);
      await page.click('.hv2-whatif summary');
      await page.waitFor(() => !!document.querySelector('.hv2-whatif[open] .hv2-whatif-item'), { message: 'the planner open' });
      const items = await page.evaluate(() => [...document.querySelectorAll('.hv2-whatif-item')].map((el) => el.dataset.check));
      assertEqual(items, before.problems, 'every open problem');
      assertEqual(await text(page, '[data-role="whatif-result"]'), 'Tick a problem to see the projected score.', 'nothing ticked');
      await page.evaluate(() => document.querySelector('.hv2-whatif-item[data-check="dmarc.policy-none"] input').click());
      const result = await page.evaluate(() => {
        const el = document.querySelector('[data-role="whatif-result"]');
        return { text: el.textContent, score: Number(el.dataset.score), grade: el.dataset.grade };
      });
      assertEqual(result.text, `Fixing 1 problem: ${before.score}/100 (${before.grade}) → ${result.score}/100 (${result.grade})`, 'the projection');
      assert(result.score > before.score, `fixing it would raise the score: ${before.score} → ${result.score}`);
      await page.evaluate(() => document.querySelector('.hv2-whatif-item[data-check="dmarc.policy-none"] input').click());
      assertEqual(await text(page, '[data-role="whatif-result"]'), 'Tick a problem to see the projected score.', 'unticked');
      assertEqual((await healthInfo(page)).score, before.score, 'nothing changed or saved');
    });

    await run.step('"Accept this risk…" asks for a reason, an owner and an end date; the finding leaves the problems, the counts and the score', async () => {
      assert(before.problems.includes('dmarc.policy-none'), `DMARC at p=none is a problem: ${before.problems.join(', ')}`);
      assertEqual([before.waived, before.accepted], [null, []], 'nothing accepted yet');
      // the keyboard opens the dialog
      await page.evaluate(() => document.querySelector('[data-action="hv2-accept"][data-check="dmarc.policy-none"]').focus());
      await page.press('Enter');
      await page.waitFor(() => !!document.querySelector('dialog.wvr-modal[open]'), { message: 'the dialog' });
      const dlg = await page.evaluate(() => {
        const d = document.querySelector('dialog.wvr-modal');
        const date = d.querySelector('[data-role="wvr-expires"]');
        return {
          title: d.querySelector('.modal-title').textContent, ref: d.querySelector('[data-role="wvr-ref"]').textContent, text: d.textContent,
          date: [date.value, date.min, date.max], focus: document.activeElement && document.activeElement.dataset.role
        };
      });
      assertEqual([dlg.title, dlg.ref, dlg.date, dlg.focus], ['Accept a risk', 'dmarc.policy-none', ['2027-01-07', '2026-10-09', '2027-10-10'], 'wvr-reason'],
        'the finding, the end date offered (90 days) within today and 366 days, the focus on the reason');
      assert(/example\.com/.test(dlg.text), 'the domain');
      // a reason is required
      await page.click('dialog.wvr-modal [data-action="wvr-save"]');
      await page.waitFor(() => /Give a reason/.test(document.querySelector('dialog.wvr-modal [data-role="wvr-reason"]')?.closest('.field')?.textContent || ''), { message: 'the reason asked for' });
      await fillDialog(page, { reason: 'Moving to quarantine after the vendor audit', owner: 'Mail team', expires: '2026-10-20' });
      await page.waitFor(() => !!document.querySelector('.hv2-section-accepted [data-id="dmarc.policy-none"]'), { message: 'listed as accepted', timeout: 10000 });
      const after = await healthInfo(page);
      assert(!after.problems.includes('dmarc.policy-none'), 'out of the problems');
      assertEqual(after.accepted, [['dmarc.policy-none', 'Accepted until 2026-10-20 by Mail team: Moving to quarantine after the vendor audit']], 'the accepted section');
      assert(after.score > before.score, `the score rises without it: ${before.score} → ${after.score} (problems before: ${before.problems.join(', ')})`);
      assertEqual(after.waived, `1 accepted risk (until 2026-10-20). With it, the score would be ${before.score}/100 (${before.grade}).`, 'the hero says it, with the score including it');
      // "All checks": the Email card counts it apart, as the hero does — not as a warning
      const email = await page.evaluate(() => {
        const card = document.querySelector('.hlt-group[data-group="email"]');
        return { warn: card.classList.contains('hlt-group-warn'), badges: [...card.querySelectorAll('.card-actions .badge')].map((b) => [b.className.match(/badge-(\w+)/)[1], b.textContent.trim(), b.title]) };
      });
      assert(!email.warn && !email.badges.some(([variant]) => variant === 'warn') && email.badges.some((b) => b.join('|') === 'neutral|1|1 accepted risk'),
        `the Email card: no warning, one accepted risk: ${JSON.stringify(email)}`);
      const row = await page.evaluate(() => {
        const li = document.querySelector('.hlt-check[data-id="dmarc.policy-none"]');
        return [li.classList.contains('is-waived'), li.querySelector('.hlt-waived-badge')?.textContent];
      });
      assertEqual(row, [true, 'Accepted until 2026-10-20'], 'the check row is marked');
      const focus = await page.evaluate(() => [document.activeElement?.dataset.action, document.activeElement?.dataset.check]);
      assertEqual(focus, ['hv2-waiver-remove', 'dmarc.policy-none'], 'the focus on its Remove');
      const kept = await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => JSON.parse(state.workspaceData('waivers')).waivers.map((w) => [w.kind, w.domain, w.ref, w.expires])));
      assertEqual(kept, [['finding', 'example.com', 'dmarc.policy-none', '2026-10-20']], 'kept in the workspace');
      // Copy summary
      await stubClipboard(page);
      await page.click('.hlt-hero [data-action="copy-summary"]');
      await page.waitFor(() => (window.__clip || []).length > 0, { message: 'copied' });
      const [md] = await takeClipboard(page);
      assert(md.includes('- 1 accepted risk excluded (until 2026-10-20)'), md);
      assert(md.includes(`score ${after.score}/100`), 'the score without it');
      await shotEl(page, 'waivers-health-1440-en', '.hv2-problems');
      assertEqual(await blocked(page), [], 'nothing else left the page');
      await assertClean(page, 'accepted', server.url);
    });

    await run.step('a check running: the report on screen is the previous one, so its "Accept this risk…" and Remove are disabled until the new one lands', async () => {
      const during = await page.evaluate(() => {
        document.querySelector('[data-action="run"]').click();
        return [...document.querySelectorAll('[data-action="hv2-accept"], [data-action="hv2-waiver-remove"]')].map((b) => [b.dataset.action, b.dataset.check, b.disabled]);
      });
      assert(during.some(([action, check]) => action === 'hv2-waiver-remove' && check === 'dmarc.policy-none') && during.every(([, , disabled]) => disabled),
        `disabled while it runs: ${JSON.stringify(during)}`);
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'the check again' });
      await page.waitFor(() => {
        const btns = [...document.querySelectorAll('[data-action="hv2-accept"], [data-action="hv2-waiver-remove"]')];
        return btns.length > 0 && btns.every((b) => !b.disabled) && !!document.querySelector('.hv2-section-accepted [data-id="dmarc.policy-none"]');
      }, { message: 'enabled again on the new report' });
    });

    await run.step('the Domain overview\'s health card leaves it out too: the same score as Domain Health, the problems without it, the line that says so, Copy summary', async () => {
      const hero = await healthInfo(page);
      await gotoRoute(page, '#/domain?name=example.com');
      await page.waitFor(() => !!document.querySelector('[data-action="dov-run"]') && !document.querySelector('[data-action="dov-run"]').hidden, { message: 'the overview' });
      await page.click('[data-action="dov-run"]');
      await page.waitFor(() => !!document.querySelector('.dov-head') && !!document.querySelector('.dov-score[data-score]') && !document.querySelector('[data-action="dov-run"]').hidden
        && [...document.querySelectorAll('.dov-card')].every((c) => c.dataset.state !== 'pending'), { timeout: 30000, message: 'the overview built' });
      const card = await page.evaluate(() => {
        const s = document.querySelector('.dov-score[data-score]');
        return {
          score: Number(s.dataset.score), light: s.dataset.light, problems: [...document.querySelectorAll('.dov-problem')].map((li) => li.dataset.id),
          waived: document.querySelector('[data-role="dov-waived"]')?.textContent.replace(/\s+/g, ' ').trim() || null
        };
      });
      assertEqual([card.score, card.light], [hero.score, hero.light], 'the score and the light Domain Health shows');
      assert(!card.problems.includes('dmarc.policy-none'), `not among the problems: ${card.problems.join(', ')}`);
      assertEqual(card.waived, `1 accepted risk (until 2026-10-20). With it, the score would be ${before.score}/100 (${before.grade}).`, 'said on the card');
      await stubClipboard(page);
      await page.click('.dov-head [data-action="copy-summary"]');
      await page.waitFor(() => (window.__clip || []).length > 0, { message: 'copied' });
      const [md] = await takeClipboard(page);
      assert(md.includes(`score ${hero.score}/100 · 1 accepted risk excluded (until 2026-10-20)`), md);
      await page.setViewport({ width: 375, height: 800, mobile: true });
      await frames(page);
      await assertNoHorizontalScroll(page, 'the overview at 375 px');
      assertEqual(await overflowingIn(page, '.dov-card-health'), [], 'the health card inside 375 px');
      await page.setViewport({ width: 1440, height: 900 });
      assertEqual(await blocked(page), [], 'nothing else left the page');
      await assertClean(page, 'overview', server.url);
      // Coming back shows the kept report with `run=0` in the URL (a reload would only fill the form):
      // checked again, the URL is the check's own, as the reload of the next step needs.
      await gotoRoute(page, '#/health?domain=example.com');
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'back to Domain Health' });
      await page.evaluate(() => document.querySelector('[data-action="run"]').click());
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'checked again' });
      assertEqual(await page.evaluate(() => location.hash), '#/health?domain=example.com', 'the check\'s own URL');
    });

    await run.step('kept: a reload shows it accepted; Turkish words it; 375 and 320 px in light and dark fit', async () => {
      await page.reload();
      await waitReady(page);
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'the check after the reload' });
      await page.waitFor(() => !!document.querySelector('.hv2-section-accepted [data-id="dmarc.policy-none"]'), { message: 'still accepted' });
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('.hv2-section-accepted [data-id="dmarc.policy-none"]'), { message: 'after the re-mount' });
      const tr = await healthInfo(page);
      assertEqual(tr.accepted[0][1], '2026-10-20 tarihine kadar Mail team tarafından kabul edildi: Moving to quarantine after the vendor audit', 'Turkish');
      assert(/^1 kabul edilen risk \(2026-10-20 tarihine kadar\)\. O da sayılsaydı puan \d+\/100 \([A-F]\) olurdu\.$/.test(tr.waived), tr.waived);
      await assertNoMissingKeys(page);
      for (const width of [375, 320]) {
        await page.setViewport({ width, height: 800, mobile: true });
        for (const lang of ['tr', 'en']) {
          for (const scheme of ['dark', 'light']) {
            await setLangUi(page, lang);
            await page.emulateMedia({ 'prefers-color-scheme': scheme });
            await page.waitFor(() => !!document.querySelector('.hv2-section-accepted'), { message: 'the card' });
            await frames(page);
            await assertNoHorizontalScroll(page, `health ${width} ${lang} ${scheme}`);
            assertEqual(await overflowingIn(page, '.hv2-problems'), [], `the problems card inside ${width} px (${lang} ${scheme})`);
            assertEqual(await overflowingIn(page, '.hlt-hero'), [], `the hero inside ${width} px (${lang} ${scheme})`);
            if (width === 375 && scheme === 'dark') {
              await shotEl(page, `waivers-health-375-${lang}-dark`, '.hv2-problems');
              await shotEl(page, `waivers-hero-375-${lang}-dark`, '.hlt-hero');
            }
          }
        }
      }
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await assertClean(page, 'kept', server.url);
    });

    await run.step('Remove: it counts again (the focus on its "Accept this risk…"); accepted again until 2026-10-20', async () => {
      await page.waitFor(() => !!document.querySelector('[data-action="hv2-waiver-remove"][data-check="dmarc.policy-none"]'), { message: 'its Remove' });
      await page.click('[data-action="hv2-waiver-remove"][data-check="dmarc.policy-none"]');
      await page.waitFor(() => !document.querySelector('.hv2-section-accepted'), { message: 'removed' });
      const info = await healthInfo(page);
      assertEqual([info.score, info.waived, info.problems.includes('dmarc.policy-none')], [before.score, null, true], 'back as before');
      const focus = await page.evaluate(() => [document.activeElement?.dataset.action, document.activeElement?.dataset.check]);
      assertEqual(focus, ['hv2-accept', 'dmarc.policy-none'], 'the focus on its accept button');
      // the dialog at 375 px, Turkish, dark
      await page.setViewport({ width: 375, height: 800, mobile: true });
      await setLangUi(page, 'tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
            await page.evaluate(() => document.querySelector('[data-action="hv2-accept"]').click());
      await page.waitFor(() => !!document.querySelector('dialog.wvr-modal[open]'), { message: 'the dialog at 375 px' });
      assertEqual(await text(page, 'dialog.wvr-modal .modal-title'), 'Bir riski kabul et', 'Turkish title');
      await assertNoHorizontalScroll(page, 'the dialog at 375 px');
      await shotEl(page, 'waivers-dialog-375-tr-dark', 'dialog.wvr-modal .modal-box');
      await page.click('dialog.wvr-modal [data-action="wvr-cancel"]');
      await page.waitFor(() => !document.querySelector('dialog.wvr-modal'), { message: 'cancelled' });
      await page.setViewport({ width: 1440, height: 900 });
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
      await page.click('[data-action="hv2-accept"][data-check="dmarc.policy-none"]');
      await page.waitFor(() => !!document.querySelector('dialog.wvr-modal[open]'), { message: 'the dialog' });
      await fillDialog(page, { reason: 'Moving to quarantine after the vendor audit', owner: 'Mail team', expires: '2026-10-20' });
      await page.waitFor(() => !!document.querySelector('.hv2-section-accepted [data-id="dmarc.policy-none"]'), { message: 'accepted again' });
    });

    await run.step('the day after its end date: the finding counts again, and says its acceptance expired', async () => {
      await setLangUi(page, 'en');
      await page.send('Page.addScriptToEvaluateOnNewDocument', { source: pinnedClockScript(LATER) });
      await page.reload();
      await waitReady(page);
      await page.waitFor(HEALTH_DONE, { timeout: 30000, message: 'the check on the later day' });
      const info = await healthInfo(page);
      assert(info.problems.includes('dmarc.policy-none'), 'a problem again');
      assertEqual([info.accepted, info.expired], [[], ['Accepted risk expired on 2026-10-20: it counts again']], 'said on the problem');
      assertEqual(await text(page, '[data-role="hero-waived"]'), '1 accepted risk has expired and counts again.', 'and in the hero');
      assertEqual(info.score, before.score, 'the score as without it');
      assertEqual(await text(page, '[data-action="hv2-accept"][data-check="dmarc.policy-none"]'), 'Accept again…', 'it can be accepted again');
      await stubClipboard(page);
      await page.click('.hlt-hero [data-action="copy-summary"]');
      await page.waitFor(() => (window.__clip || []).length > 0, { message: 'copied' });
      const [md] = await takeClipboard(page);
      assert(!md.includes('accepted risk'), md);
      await shotEl(page, 'waivers-health-expired-1440-en', '.hv2-problems');
      await assertClean(page, 'expired', server.url);
    });

    run.group('Workspaces: waivers.json out and in');
    await run.step('listed as expired; exported as waivers.json (the runner\'s input); the expired ones removed; an import merged, the entry it could not read said', async () => {
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'en');
      await page.click('[data-control="workspace"]');
      await page.waitFor(() => !!document.querySelector('dialog.ws-modal[open] [data-role="ws-waivers"]'), { message: 'the dialog', timeout: 15000 });
      const block = await page.evaluate(() => {
        const b = document.querySelector('[data-role="ws-waivers"]');
        const part = (li, sel) => li.querySelector(sel)?.textContent.replace(/\s+/g, ' ').trim();
        return {
          total: b.dataset.total, expired: b.dataset.expired,
          items: [...b.querySelectorAll('[data-role="ws-waiver"]')].map((li) => [li.dataset.kind, li.dataset.state, part(li, '.ws-waiver-domain'), part(li, '.ws-waiver-ref'),
            part(li, '.ws-waiver-when'), part(li, '.ws-waiver-why')])
        };
      });
      assertEqual([block.total, block.expired], ['1', '1'], 'one, expired');
      assertEqual(block.items, [['finding', 'expired', 'example.com', 'dmarc.policy-none', 'expired 2026-10-20', 'Mail team: Moving to quarantine after the vendor audit']], 'its line');
      await takeDownloads(page);
      await page.click('[data-action="ws-waivers-export"]');
      await page.waitFor(() => (window.__downloads || []).length > 0, { message: 'exported' });
      const [file] = await takeDownloads(page);
      assertEqual(file.name, 'waivers.json', 'the runner\'s file name');
      const parsed = parseWaivers(file.text, { now: LATER });
      assertEqual([parsed.ok, parsed.errors, parsed.waivers.map((w) => [w.kind, w.domain, w.ref, w.owner, w.expires])],
        [true, [], [['finding', 'example.com', 'dmarc.policy-none', 'Mail team', '2026-10-20']]], 'lib/waivers.js reads it back');
      assert(JSON.parse(file.text).exportedAt.startsWith('2026-10-21T12:'), 'stamped with the page\'s clock (it runs on from the instant it was pinned to)');
      await page.click('[data-action="ws-waivers-drop-expired"]');
      await page.waitFor(() => !!document.querySelector('[data-role="ws-waivers-empty"]'), { message: 'none left' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.role), 'ws-waivers-empty', 'the focus on what took their place');
      const incoming = path.join(tmp, 'waivers-import.json');
      await writeFile(incoming, JSON.stringify({
        format: 'domainscope-waivers', v: 1,
        waivers: [
          { kind: 'rule', domain: 'example.com', ref: 'dmarc.policy', reason: 'Quarantine planned for Q1', owner: 'Mail team', expires: '2026-12-31' },
          { kind: 'cert', domain: 'example.com', ref: LE_KEY, reason: 'Our own certificate', owner: 'Web team', expires: '2026-12-31' },
          { kind: 'nope', domain: 'example.com', ref: 'x', reason: 'r', expires: '2026-12-31' }
        ]
      }));
      await page.setFileInput('[data-role="ws-waivers-import"] input[type="file"]', [incoming]);
      await page.waitFor(() => /2 added, 0 replaced/.test(document.querySelector('[data-role="ws-waivers-outcome"]')?.textContent || ''), { message: 'imported' });
      const said = await text(page, '[data-role="ws-waivers-outcome"]');
      assert(/1 entry was left out: The kind is not finding, rule or cert\./.test(said), said);
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('[data-role="ws-waiver"]')].map((li) => li.dataset.kind)), ['rule', 'cert'], 'merged');
      await page.setViewport({ width: 375, height: 800, mobile: true });
      await frames(page);
      await assertNoHorizontalScroll(page, 'the Workspaces dialog at 375 px');
      assertEqual(await overflowingIn(page, '[data-role="ws-waivers"]'), [], 'the accepted risks inside 375 px');
      await page.evaluate(() => document.querySelector('[data-role="ws-waivers"]').scrollIntoView({ block: 'start' }));
      await shotEl(page, 'waivers-workspaces-375-en', 'dialog.ws-modal .modal-box');
      await page.setViewport({ width: 1440, height: 900 });
      await page.click('dialog.ws-modal[open] .modal-head .btn');
      await page.waitFor(() => !document.querySelector('dialog.ws-modal'), { message: 'closed' });
      await assertClean(page, 'workspaces', server.url);
    });

    run.group('Domain portfolio: the policy matrix and the CT tab');
    await run.step('the imported rule waiver makes its failed cell "Accepted"; "Accept…" on another failed cell, its dialog worded for a rule; the counts; the CSV says WAIVED', async () => {
      await gotoRoute(page, 'portfolio');
      await page.type('[data-role="pf-domains"]', 'example.com');
      await page.click('[data-action="pf-run"]');
      try {
        await page.waitFor(() => !!document.querySelector('.pf-head[data-status="done"]') && !document.querySelector('[data-action="pf-run"]').hidden && !document.querySelector('.pf-pending'),
          { timeout: 40000, message: 'portfolio checked' });
      } catch (err) {
        const why = await page.evaluate(() => ({
          head: document.querySelector('.pf-head')?.dataset.status, run: document.querySelector('[data-action="pf-run"]')?.hidden,
          pending: [...document.querySelectorAll('.pf-pending')].map((e) => e.closest('td')?.dataset.label || e.textContent).slice(0, 10),
          dns: window.__ww.dns.slice(-10), rdap: window.__ww.rdap.slice(), blocked: window.__ww.blocked.slice()
        }));
        throw new Error(`${err.message}: ${JSON.stringify(why)}`);
      }
      await page.click('.pf-results .tab[data-tab="policy"]');
      await page.waitFor(() => !!document.querySelector('.pf-pol-card'), { message: 'policy tab' });
      await page.evaluate(() => {
        const box = document.querySelector('[data-role="pf-policy-json"]');
        box.value = '{ "name": "mail", "rules": { "dmarc.policy": ">= quarantine", "mtaSts": true } }';
        box.dispatchEvent(new Event('input'));
      });
      await page.waitFor(() => document.querySelectorAll('.pf-matrix thead th').length === 4, { message: 'two rules in the matrix' });
      await frames(page);
      const cells = () => page.evaluate(() => [...document.querySelectorAll('.pf-matrix .pf-cell[data-rule]')].map((c) => [c.dataset.rule, c.dataset.status, c.querySelector('[data-role="pf-waiver"]')?.textContent || null]));
      assertEqual(await cells(), [['dmarc.policy', 'waived', 'accepted until 2026-12-31 by Mail team: Quarantine planned for Q1'], ['mtaSts', 'fail', null]], 'the imported waiver applies');
      assertEqual(await text(page, '.pf-matrix-counts'), '1 of 1 domains fails the policy · 1 failed rule is an accepted risk', 'counted on its own');
      await page.click('.pf-matrix [data-action="pf-accept"][data-waive="mtaSts"]');
      await page.waitFor(() => !!document.querySelector('dialog.wvr-modal[open]'), { message: 'the dialog' });
      assert(/MTA-STS record \(mtaSts true\)/.test(await text(page, 'dialog.wvr-modal')), 'the rule it accepts');
      assertEqual(await text(page, 'dialog.wvr-modal [data-role="wvr-intro"]'),
        'Until the end date its cell reads “Accepted”: neither a pass nor a fail. Then it counts again and is listed as expired. Kept in this workspace and in its hand-over file.',
        'what accepting a rule does (a rule has no score)');
      await fillDialog(page, { reason: 'No inbound mail on this domain', owner: 'Mail team' });
      await page.waitFor(() => !!document.querySelector('.pf-matrix .pf-cell[data-rule="mtaSts"][data-status="waived"]'), { message: 'accepted', timeout: 10000 });
      assertEqual(await text(page, '.pf-matrix-counts'), 'The domain meets every rule · 2 failed rules are accepted risks', 'both accepted');
      await page.waitFor(() => document.activeElement?.dataset.rule === 'mtaSts', { message: 'the focus on the accepted cell' });
      await takeDownloads(page);
      await page.click('[data-action="pf-matrix-csv"]');
      await page.waitFor(() => (window.__downloads || []).length > 0, { message: 'CSV' });
      const [csv] = await takeDownloads(page);
      const lines = csv.text.replace(/^\ufeff/, '').trim().split(/\r\n/);
      assertEqual(lines[0], 'Domain,Failed,Not known,Accepted,Passed,dmarc.policy (>= quarantine),mtaSts (true)', 'the Accepted column');
      assert(/^example\.com,0,0,2,0,WAIVED · DMARC p=none · accepted until 2026-12-31 by Mail team: Quarantine planned for Q1,WAIVED · /.test(lines[1]), lines[1]);
      await shotEl(page, 'waivers-matrix-1440-en', '.pf-matrix-card');
      await assertClean(page, 'matrix', server.url);
    });

    await run.step('the CT tab: the imported key is "Known"; a certificate from an unexpected CA logged since the last check offers "Known certificate…", once known is neither new nor unexpected, and is flagged again once that is over', async () => {
      await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.setWorkspaceData('expectedCas', ["Let's Encrypt"])));
      await page.click('.pf-results .tab[data-tab="ct"]');
      await page.waitFor(() => !!document.querySelector('[data-action="ct-run"]'), { message: 'the CT panel', timeout: 15000 });
      const waitCt = () => page.waitFor(() => !!document.querySelector('.pf-ct .pf-head[data-status="done"]') && !document.querySelector('[data-action="ct-run"]').hidden, { timeout: 30000, message: 'CT checked' });
      await page.click('[data-action="ct-run"]');
      await waitCt();
      // the second check finds a certificate logged since, from another CA
      await page.evaluate(() => { window.__ww.round = 2; });
      await page.click('[data-action="ct-run"]');
      await waitCt();
      await page.evaluate(() => {
        const s = document.querySelector('[data-role="ct-filter"]');
        s.value = 'all';
        s.dispatchEvent(new Event('change'));
      });
      await frames(page);
      const rows = () => page.evaluate(() => [...document.querySelectorAll('.pf-ct-table tbody tr.dt-row')].map((tr) => ({
        names: [...tr.querySelectorAll('td.pf-ct-names .mono')].map((e) => e.textContent).join(' '),
        flags: [...tr.querySelectorAll('[data-flag]')].map((e) => e.dataset.flag),
        known: tr.querySelector('[data-role="ct-known-line"]')?.textContent || null,
        button: !!tr.querySelector('[data-action="ct-known"]')
      })));
      const first = await rows();
      const le = first.find((r) => r.names.startsWith('example.com'));
      const cdn = first.find((r) => r.names === 'cdn.example.com');
      assertEqual([le.flags, le.known, le.button], [['known'], 'Accepted until 2026-12-31 by Web team: Our own certificate', false], 'the imported known certificate');
      assertEqual([cdn.flags, cdn.button], [['new', 'unexpected'], true], 'new, from an unexpected CA, offering "Known certificate…"');
      await page.click('[data-action="ct-known"]');
      await page.waitFor(() => !!document.querySelector('dialog.wvr-modal[open]'), { message: 'the dialog' });
      const dlg = await page.evaluate(() => [document.querySelector('dialog.wvr-modal .modal-title').textContent, document.querySelector('[data-role="wvr-reason"]').value,
        document.querySelector('[data-role="wvr-ref"]').textContent]);
      assertEqual(dlg, ['Known certificate', 'Our own certificate', 'b2'.repeat(32)], 'the key it marks known, a reason offered');
      await fillDialog(page, { owner: 'Web team' });
      await page.waitFor(() => [...document.querySelectorAll('.pf-ct-table [data-role="ct-known-line"]')].length === 2, { message: 'both known', timeout: 10000 });
      const after = (await rows()).find((r) => r.names === 'cdn.example.com');
      assertEqual([after.flags, after.button], [['known'], false], 'neither new nor unexpected');
      // the CT tab's figures (its read-only metric strip): a zero folds into "None: …"
      const tiles = await page.evaluate(() => {
        const strip = document.querySelector('.pf-ct-tiles');
        const out = Object.fromEntries([...strip.querySelectorAll('[data-metric]')].map((el) => [el.dataset.metric, el.querySelector('.metric-value')?.textContent.trim()]));
        for (const id of (strip.querySelector('.metric-zero')?.dataset.folded || '').split(' ').filter(Boolean)) out[id] = '0';
        return out;
      });
      assertEqual([tiles.new, tiles.unexpected], ['0', '0'], 'the figures follow');
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.role), 'ct-known-line', 'the focus on the row\'s known line');
      // the focus scrolled the table to the row's line: back to its start for the picture
      await page.evaluate(() => document.querySelectorAll('.pf-ct-table .dt-scroll').forEach((el) => { el.scrollLeft = 0; }));
      await shotEl(page, 'waivers-ct-1440-en', '.pf-ct-table');
      // the CDN key's acceptance ends on 2026-10-20, before the page's clock: its row is flagged again, and says why
      await page.evaluate((key) => import('./assets/js/state.js').then(({ state }) => {
        const doc = JSON.parse(state.workspaceData('waivers'));
        doc.waivers = doc.waivers.map((w) => (w.ref === key ? { ...w, expires: '2026-10-20' } : w));
        return state.setWorkspaceData('waivers', JSON.stringify(doc));
      }), OTHER_KEY);
      await page.waitFor(() => !!document.querySelector('.pf-ct-table [data-role="ct-known-expired"]'), { message: 'flagged again', timeout: 10000 });
      const ended = (await rows()).find((r) => r.names === 'cdn.example.com');
      assertEqual([ended.flags, ended.button, await text(page, '.pf-ct-table [data-role="ct-known-expired"]')],
        [['new', 'unexpected'], true, 'Accepted as known until 2026-10-20, expired: flagged again'], 'its acceptance over');
      assertEqual(await page.evaluate(() => window.__ww.ct.slice()), ['example.com', 'example.com next', 'example.com', 'example.com next'], 'Cert Spotter: two checks, nothing more');
      assertEqual(await blocked(page), [], 'nothing else left the page');
      assertEqual(netHits, [], 'nothing reached the network');
      await assertNoMissingKeys(page);
      await assertClean(page, 'CT', server.url);
    });
  } finally {
    if (page) await page.close();
    await browser.close();
    await server.close();
    await rm(tmp, { recursive: true, force: true });
  }
  run.finish(opts.shots ? ` — screenshots in ${SHOTS_DIR}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
