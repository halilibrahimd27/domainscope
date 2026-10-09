#!/usr/bin/env node
/**
 * dmarchistory.e2e.mjs — end-to-end test of DMARC & TLS reports › History (the report history a
 * workspace keeps, lib/dmarchistory.js, ui/report-history.js) and the DMARC customer report, in a
 * real headless Chrome/Edge. OFFLINE: every DoH query is answered in the page by a fake resolver
 * (window.fetch wrapped before the app loads), every other https:// request is blocked, and every
 * request that leaves the page's origin is counted through CDP. The page's clock starts at
 * 2026-09-30 12:00 UTC on every load, the days the fixture reports were written for.
 *
 *   node tests/e2e/dmarchistory.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots] [--shots-dir DIR]
 *
 * Covers: the switch "Keep a summary of these reports in this workspace", off by default — a drop
 * writes nothing to the workspace or IndexedDB; turned on, the reports read are kept (a toast says
 * how many) and the History tab draws the domain's trend; the stored summary holds no file name,
 * reporter contact or XML; the same zip dropped twice leaves the counts unchanged; 20 days of daily
 * reports of another domain: the domain picker, a bar a day, the tooltip on the pointer and on the
 * arrow keys, a sender new since the history's first week with its service, the table view and its
 * CSV; the roll-up across the domains with each verdict and its CSV, a domain shown from it; 400 days
 * drawn by week; Report: the DMARC customer report of the domain on screen with its trend, no re-run
 * link, no script, no server of the list, nothing sent; a reload keeps the history (not the reports);
 * 375 / 320 px without horizontal scroll, TR / EN × light / dark; turned off after a confirmation, a
 * drop writes nothing; Forget report history; Delete all local data clears it; another tab turning
 * the switch on, off and on again, followed every time; a history at its size limit taking a drop
 * and then a domain classed again against its SPF, trimmed and never lost; a day whose mail all
 * failed drawn as a stub in the compliance chart; zero console errors / CSP violations / missing
 * i18n keys, nothing sent outside the page.
 *
 * Data is documentation space only (tests/fixtures/mailreports: example.com / .net / .org,
 * 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
 */

import path from 'node:path';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { pinnedClockScript } from './clock.mjs';
import { crc32 } from '../../assets/js/lib/zipread.js';
import { HISTORY_MAX_BYTES, historyText } from '../../assets/js/lib/dmarchistory.js';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, takeDownloads, waitReady, csvHeader
} from './scan.e2e.mjs';

const MAILBOX = path.join(FIXTURES, 'mailreports', 'reports-2026-09.zip');
/** The instant the expectations were written for: four days after the fixture reports. */
const HISTORY_NOW = Date.parse('2026-09-30T12:00:00Z');
const DAY_S = 86400;
/** 2026-09-10 00:00 UTC: the first of the 20 daily reports of example.org. */
const ORG_FIRST = Date.parse('2026-09-10T00:00:00Z') / 1000;

/** The SPF of the three domains and the A of example.com's MX. */
const ZONE = {
  'example.com': {
    TXT: [['v=spf1 ip4:203.0.113.25 mx include:_spf.example.com include:spf.mailer.example.net ~all']],
    MX: [{ preference: 10, exchange: 'mx1.example.com' }]
  },
  'mx1.example.com': { A: ['203.0.113.26'] },
  '_spf.example.com': { TXT: [['v=spf1 ip6:2001:db8:25::/64 -all']] },
  'spf.mailer.example.net': { TXT: [['v=spf1 ip4:198.51.100.0/26 -all']] },
  'example.net': { TXT: [['v=spf1 ip4:192.0.2.10 -all']] },
  'example.org': { TXT: [['v=spf1 ip4:192.0.2.30 -all']] }
};

/** In-page stubs: DoH from the zone (NXDOMAIN outside it). */
const fakeScript = () => `(() => {
  const Z = window.__zone = ${JSON.stringify(ZONE)};
  window.__dnsLog = [];
  let wire = null;
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const qname = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__dnsLog.push({ name: qname, type: q.type });
    const node = Z[qname];
    const answers = !node ? [] : (node[q.type] || []).map((data) => ({ name: qname, type: q.type, ttl: 300, data }));
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: node ? 'NOERROR' : 'NXDOMAIN',
      questions: [{ name: q.name, type: q.type }], answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/**
 * One day of example.org's mail (day 0 = 2026-09-10): its own server (100 + day messages, aligned),
 * an unknown sender (3, failing), and from day 17 (2026-09-27) a new sender that signs as
 * sendgrid.net only (7, failing DMARC).
 */
const orgReport = (day, { id = `org-${day}` } = {}) => {
  const begin = ORG_FIRST + day * DAY_S;
  const rec = (ip, count, aligned, auth) => `<record><row><source_ip>${ip}</source_ip><count>${count}</count><policy_evaluated><disposition>none</disposition>
<dkim>${aligned ? 'pass' : 'fail'}</dkim><spf>${aligned ? 'pass' : 'fail'}</spf></policy_evaluated></row><identifiers><header_from>example.org</header_from></identifiers>
<auth_results>${auth}</auth_results></record>`;
  return `<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata><org_name>google.com</org_name><email>noreply-dmarc-support@example.org</email>
<report_id>${id}</report_id><date_range><begin>${begin}</begin><end>${begin + DAY_S - 1}</end></date_range></report_metadata>
<policy_published><domain>example.org</domain><p>none</p></policy_published>
${rec('192.0.2.30', 100 + day, true, '<dkim><domain>example.org</domain><selector>s1</selector><result>pass</result></dkim><spf><domain>example.org</domain><result>pass</result></spf>')}
${rec('203.0.113.77', 3, false, '<spf><domain>example.org</domain><result>fail</result></spf>')}
${day >= 17 ? rec('198.51.100.88', 7, false, '<dkim><domain>sendgrid.net</domain><selector>smtpapi</selector><result>pass</result></dkim><spf><domain>sendgrid.net</domain><result>pass</result></spf>') : ''}
</feedback>`;
};

/** 2026-09-29 00:00 UTC: the day of the two reports the size-limit steps drop. */
const CAP_DAY = Date.parse('2026-09-29T00:00:00Z') / 1000;

/** A report of one day (CAP_DAY) of `domain`: [ip, count, aligned] records, aligned in SPF and DKIM or in neither. */
const dayReport = (domain, id, records) => `<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata><org_name>google.com</org_name><email>noreply-dmarc-support@example.org</email>
<report_id>${id}</report_id><date_range><begin>${CAP_DAY}</begin><end>${CAP_DAY + DAY_S - 1}</end></date_range></report_metadata>
<policy_published><domain>${domain}</domain><p>none</p></policy_published>
${records.map(([ip, count, aligned]) => `<record><row><source_ip>${ip}</source_ip><count>${count}</count><policy_evaluated><disposition>none</disposition>
<dkim>${aligned ? 'pass' : 'fail'}</dkim><spf>${aligned ? 'pass' : 'fail'}</spf></policy_evaluated></row><identifiers><header_from>${domain}</header_from></identifiers>
<auth_results><spf><domain>${domain}</domain><result>${aligned ? 'pass' : 'fail'}</result></spf></auth_results></record>`).join('\n')}
</feedback>`;

/**
 * A stored history just under `target` characters: example.com with one day and as many sources of
 * one message as fit (the size cap drops those first). Every address has the same length (four hex
 * digits a group, none with a leading zero), so every source weighs the same.
 */
function fillerHistory(target) {
  const day = { msgs: 10000, dmarcPass: 0, spfAligned: 0, dkimAligned: 0, quarantine: 0, reject: 0, unknownMsgs: 10000, knownFail: 0 };
  const d = { days: { '2026-09-01': day }, sources: {}, recent: {}, policy: null, seen: {}, cut: null, checked: null };
  const h = { v: 1, keep: true, updatedAt: null, domains: { 'example.com': d } };
  const add = (from, to) => {
    for (let k = from; k < to; k += 1) {
      d.sources[`2001:db8:${(0x1000 + (k >> 12)).toString(16)}:${(0x1000 + (k & 0xfff)).toString(16)}::1`] = {
        first: '2026-09-01', last: '2026-09-01', msgs: 1, passMsgs: 0, cls: 'unknown', service: null, type: null
      };
    }
  };
  add(0, 1);
  const base = historyText(h).length;
  add(1, 2);
  const per = historyText(h).length - base;
  const n = 1 + Math.floor((target - base) / per);
  add(2, n);
  // As many digits as the 10000 measured with.
  day.msgs = n;
  day.unknownMsgs = n;
  return historyText(h);
}

/** A stored (uncompressed) zip of [name, text] entries: a mailbox folder saved as one archive. */
function storedZip(entries) {
  const le = (v, size) => {
    const b = Buffer.alloc(size);
    if (size === 2) b.writeUInt16LE(v);
    else b.writeUInt32LE(v);
    return b;
  };
  const locals = [];
  const central = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const n = Buffer.from(name);
    const data = Buffer.from(content);
    const crc = crc32(data);
    const local = Buffer.concat([le(0x04034b50, 4), le(20, 2), le(0x800, 2), le(0, 2), le(0, 4), le(crc, 4), le(data.length, 4), le(data.length, 4),
      le(n.length, 2), le(0, 2), n, data]);
    central.push(Buffer.concat([le(0x02014b50, 4), le(20, 2), le(20, 2), le(0x800, 2), le(0, 2), le(0, 4), le(crc, 4), le(data.length, 4), le(data.length, 4),
      le(n.length, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(offset, 4), n]));
    locals.push(local);
    offset += local.length;
  }
  const cd = Buffer.concat(central);
  return Buffer.concat([...locals, cd, le(0x06054b50, 4), le(0, 2), le(0, 2), le(entries.length, 2), le(entries.length, 2), le(cd.length, 4), le(offset, 4), le(0, 2)]);
}

const text = (page, sel) => page.evaluate((s) => document.querySelector(s)?.textContent.replace(/\s+/g, ' ').trim() || '', sel);
const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
const removeToasts = (page) => page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
const dnsCount = (page) => page.evaluate(() => window.__dnsLog.length);

/** The workspace part as state.js holds it ('' when nothing is kept). */
const storedText = (page) => page.evaluate(() => import('./assets/js/state.js').then(({ state }) => state.workspaceData('reportHistory') || ''));
/** The part parsed (null when nothing is kept). */
const kept = async (page) => {
  const t = await storedText(page);
  return t ? JSON.parse(t) : null;
};
/** Messages kept per domain. */
const keptTotals = async (page) => {
  const h = await kept(page);
  return h ? Object.fromEntries(Object.entries(h.domains).map(([d, x]) => [d, Object.values(x.days).reduce((n, v) => n + v.msgs, 0)])) : {};
};
/** The record of the part in IndexedDB itself (null: none), read without ever creating the database. */
const idbRecord = (page) => page.evaluate(() => new Promise((resolve, reject) => {
  (indexedDB.databases ? indexedDB.databases() : Promise.resolve([])).then((list) => {
    if (!list.some((d) => d.name === 'ssds.workspaces')) {
      resolve(null);
      return;
    }
    const req = indexedDB.open('ssds.workspaces');
    req.onsuccess = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('records')) {
        db.close();
        resolve(null);
        return;
      }
      const get = db.transaction('records', 'readonly').objectStore('records').get('wsdata/default/reportHistory');
      get.onsuccess = () => {
        db.close();
        resolve(get.result === undefined ? null : get.result);
      };
      get.onerror = () => {
        db.close();
        reject(get.error);
      };
    };
    req.onerror = () => reject(req.error);
  }, reject);
}));

/** In the page: save `text` as the active workspace's inventory and wait until it is stored. */
function saveInventory(textValue) {
  return import('./assets/js/state.js').then(async ({ state }) => {
    await state.setInventory(textValue).done;
    await state.whenSaved();
  });
}

const waitDmarc = (page, message = 'DMARC tab with its sources') => page.waitFor(() => document.querySelectorAll('.rpt-sources tbody tr.dt-row').length > 0
  && document.querySelector('.rpt-spf')?.dataset.state !== 'loading' && !document.querySelector('[data-role="rpt-busy"]'), { timeout: 20000, message });

/** Wait for a toast whose text matches. */
const toastText = (page, re, message) => page.waitFor((src) => [...document.querySelectorAll('.toast')].map((el) => el.textContent).find((x) => new RegExp(src).test(x)) || false,
  { args: [re.source], message, timeout: 15000 });

/** Open the History tab and wait for its panel. */
async function openHistory(page) {
  await page.click('.rpt-tabs [data-tab="history"]');
  await page.waitFor(() => !!document.querySelector('.rh-domain-card, .rh-panel .empty'), { message: 'the History panel', timeout: 15000 });
  await frames(page);
}

/** Pick a domain in the History tab's picker. */
async function pickHistoryDomain(page, domain) {
  await page.evaluate((d) => {
    const sel = document.querySelector('.rh-domain select');
    sel.value = d;
    sel.dispatchEvent(new Event('change', { bubbles: true }));
  }, domain);
  await page.waitFor((d) => document.querySelector('.rh-domain-card .card-title')?.textContent === d, { args: [domain], message: `history of ${domain}` });
  await frames(page);
}

/** The bars a chart drew: [day, segments]. */
const bars = (page, chart) => page.evaluate((c) => [...document.querySelectorAll(`.rh-chart[data-chart="${c}"] g.rh-bar`)]
  .map((g) => [g.dataset.day, [...g.children].map((s) => s.dataset.seg)]), chart);

/** The cards and charts of the History tab wider than their box: '<table> › <column>' or the chart. */
const overflowing = (page) => page.evaluate(() => [...document.querySelectorAll('.rh-panel .dt-row, .rh-chart')]
  .filter((c) => c.scrollWidth > c.clientWidth + 1)
  .map((c) => {
    if (c.matches('.rh-chart')) return `chart ${c.dataset.chart}`;
    const table = c.closest('.dt')?.className || c.closest('table')?.className || '?';
    const cell = [...c.children].find((td) => td.scrollWidth > td.clientWidth + 1 || td.getBoundingClientRect().right > c.getBoundingClientRect().right + 1);
    return `${table} › ${cell ? cell.dataset.label || cell.className : '?'} (${c.scrollWidth} > ${c.clientWidth})`;
  }));

/** Settings › "Delete all local data", confirmed. */
async function deleteAllLocalData(page) {
  await page.click('[data-control="settings"]');
  try {
    await page.waitForSelector('dialog.modal[open] .settings-danger');
    await page.click('dialog.modal[open] .settings-danger .btn-danger');
    await page.waitFor(() => document.querySelectorAll('dialog.modal[open]').length === 2, { message: 'confirmation' });
    await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open]')].find((d) => !d.querySelector('.settings-danger')).querySelector('.btn-danger').click());
    await page.waitFor(() => !document.querySelector('dialog.modal[open]'), { message: 'dialogs closed' });
  } finally {
    await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
  }
  await page.waitFor(() => document.querySelector('#page-body')?.childElementCount > 0 && !document.querySelector('#page-body .page-loading'), { message: 'the tool opened again' });
  await frames(page);
}

/** Click the button of an open confirmation dialog by its label. */
const confirmWith = (page, label) => page.evaluate((l) => {
  const dialog = [...document.querySelectorAll('dialog.modal[open]')].pop();
  const btn = dialog && [...dialog.querySelectorAll('.modal-foot button')].find((b) => b.textContent.trim() === l);
  if (!btn) throw new Error(`no "${l}" button`);
  btn.click();
}, label);

async function main() {
  const opts = cliOptions();
  opts.shotsDir = path.resolve(opts.value('--shots-dir', SHOTS));
  const run = createRunner();
  const shot = async (page, name) => {
    if (!opts.shots) return;
    await removeToasts(page);
    await mkdir(opts.shotsDir, { recursive: true });
    await page.screenshot(path.join(opts.shotsDir, `${name}.png`), { fullPage: true });
  };
  const dir = await mkdtemp(path.join(tmpdir(), 'ds-dmarchistory-'));
  const orgZip = path.join(dir, 'example.org-2026-09.zip');
  await writeFile(orgZip, storedZip(Array.from({ length: 20 }, (_, d) => [`google.com!example.org!${ORG_FIRST + d * DAY_S}.xml`, orgReport(d)])));
  const lateReport = path.join(dir, 'google.com!example.org!late.xml');
  await writeFile(lateReport, orgReport(20, { id: 'org-late' }));
  // One day of two domains: example.org (the busiest, its mail aligned) and example.net, whose 400
  // addresses all fail (0 % compliance) and whose SPF is not looked up at the drop.
  const capZip = path.join(dir, 'two-domains-2026-09-29.zip');
  const netIps = Array.from({ length: 400 }, (_, i) => (i < 200 ? `198.51.100.${i + 1}` : `203.0.113.${i - 199}`));
  await writeFile(capZip, storedZip([
    ['google.com!example.org!cap.xml', dayReport('example.org', 'cap-org', [['192.0.2.30', 100000, true]])],
    ['google.com!example.net!cap.xml', dayReport('example.net', 'cap-net', netIps.map((ip) => [ip, 5, false]))]
  ]));

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
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: pinnedClockScript(HISTORY_NOW) });
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript() });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('off by default: a dropped mailbox is read, and nothing is written to the workspace or IndexedDB', async () => {
      await page.goto(`${server.url}#/reports`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'reports');
      await page.evaluate(saveInventory, 'mail01 203.0.113.25\napp02 203.0.113.99\n');
      const sw = await page.evaluate(() => {
        const input = document.querySelector('[data-role="rpt-keep"]');
        return { checked: input?.checked, role: input?.getAttribute('role'), label: document.querySelector(`label[for="${input?.id}"]`)?.textContent.trim() };
      });
      assertEqual(sw, { checked: false, role: 'switch', label: 'Keep a summary of these reports in this workspace' }, 'the switch, off');
      assert(/nothing is written/.test(await text(page, '.rpt-keep .check-hint')), await text(page, '.rpt-keep .check-hint'));
      await page.setFileInput('.rpt-load .filedrop-input', [MAILBOX]);
      await waitDmarc(page);
      await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'ok', { message: 'the SPF checked' });
      await page.evaluate(() => new Promise((r) => setTimeout(r, 600)));
      assertEqual(await page.evaluate(() => !!document.querySelector('.rpt-tabs [data-tab="history"]')), false, 'no History tab');
      assertEqual(await storedText(page), '', 'nothing in the workspace');
      assertEqual(await idbRecord(page), null, 'nothing in IndexedDB');
    });

    await run.step('turned on: the reports read are kept, with a toast; the History tab draws the trend; the summary holds no file, contact or XML', async () => {
      await removeToasts(page);
      await page.click('[data-role="rpt-keep"]');
      const said = await toastText(page, /reports added to the history of this workspace/, 'the toast');
      assert(/^3 reports added to the history of this workspace\./.test(said), said);
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.role), 'rpt-keep', 'the focus stays on the switch');
      assertEqual(await keptTotals(page), { 'example.com': 5175, 'example.net': 29 }, 'every message of both domains');
      const stored = await storedText(page);
      for (const secret of ['reports-2026-09', '.xml', 'noreply-dmarc-support', 'dmarc-reports@', 'Mail & Co.', 'example.net-20260925', 'enterprise.protection.outlook.com', '<feedback', 'envelope']) {
        assert(!stored.includes(secret), `the summary keeps "${secret}"`);
      }
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.whenSaved());
      assertEqual(await idbRecord(page), stored, 'stored in IndexedDB as the workspace holds it');
      const h = JSON.parse(stored);
      assertEqual(h.domains['example.com'].sources['203.0.113.99'].cls, 'yours', 'the server of the list, classed');
      assertEqual(h.domains['example.com'].sources['198.51.100.20'].cls, 'third-party', 'with the SPF: an authorized third party');
      assertEqual(h.domains['example.com'].checked, '2026-09-30', 'classed against the current SPF');
      await openHistory(page);
      assertEqual(await text(page, '.rh-domain-card .card-title'), 'example.com', 'the domain on screen first');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.rh-stats .stat-value')[0].textContent), '5,175', 'messages');
      assertEqual((await bars(page, 'volume')).map(([d]) => d), ['2026-09-25', '2026-09-26'], 'a bar for each day with a report');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.rh-chart[data-chart="volume"] .rh-x-label').length > 1), true, 'dates under the bars');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rh-chart[data-chart="volume"] .rh-legend-item')].map((x) => x.textContent)),
        ['Passed DMARC', 'Failed: unknown senders, forwarders', 'Failed: your servers, third parties'], 'the legend');
      assert(/A sender is marked new once the history of this domain covers 7 days before it/.test(await text(page, '[data-role="rh-new-line"]')), 'nothing new on day two');
      await shot(page, 'dmarchistory-first-desktop-light-en');
    });

    await run.step('the same zip dropped twice leaves the counts unchanged', async () => {
      const before = await storedText(page);
      await removeToasts(page);
      await page.setFileInput('.rpt-load .filedrop-input', [MAILBOX]);
      const said = await toastText(page, /in the history already/, 'the toast');
      assertEqual(said, '3 reports were in the history already and are not counted again.', 'what it says');
      assertEqual(await storedText(page), before, 'the stored summary is the same, to the byte');
      assertEqual(await text(page, '[data-role="rpt-files"]'), '2 files · 6 DMARC reports · 4 TLS reports · 5 reports dropped twice count once · 2 could not be used', 'the tab counts them once too');
    });

    await run.step('20 days of another domain: the picker, a bar a day, the tooltip on the pointer and the arrow keys, a new sender and its service, the table and its CSV', async () => {
      await removeToasts(page);
      await page.setFileInput('.rpt-load .filedrop-input', [orgZip]);
      const said = await toastText(page, /reports added/, 'kept');
      assert(/^20 reports added/.test(said), said);
      await openHistory(page);
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rh-domain option')].map((o) => o.value)), ['example.com', 'example.org', 'example.net'], 'the most mail first');
      await pickHistoryDomain(page, 'example.org');
      const drawn = await bars(page, 'volume');
      assertEqual(drawn.length, 20, 'a bar for each of the 20 days');
      assertEqual(drawn[0], ['2026-09-10', ['pass', 'other']], 'passed and failed from an unknown sender');
      assertEqual(drawn[19], ['2026-09-29', ['pass', 'other']], 'the new sender fails too, and nothing names it yours');
      assertEqual((await bars(page, 'compliance')).length, 20);
      // The pointer over the bar of 2026-09-27: its day and values.
      await page.evaluate(() => {
        const bar = document.querySelector('.rh-chart[data-chart="volume"] g.rh-bar[data-day="2026-09-27"]').getBoundingClientRect();
        const plot = document.querySelector('.rh-chart[data-chart="volume"] .rh-plot');
        plot.dispatchEvent(new PointerEvent('pointermove', { clientX: bar.x + bar.width / 2, clientY: bar.y + bar.height / 2, bubbles: true }));
      });
      const tip = await page.waitFor(() => {
        const el = document.querySelector('.rh-chart[data-chart="volume"] .rh-tip');
        return el && !el.hidden ? [...el.children].map((c) => c.textContent) : false;
      }, { message: 'the tooltip' });
      assertEqual(tip, ['Sep 27, 2026', '127 messages', '92.1% passed DMARC', '10 failed from unknown senders or forwarders'], 'the tooltip of the day');
      // The keyboard: the plot takes the focus on the last day with a report, the arrow keys move from bar to bar, a live region says it.
      await page.evaluate(() => {
        const plot = document.querySelector('.rh-chart[data-chart="volume"] .rh-plot');
        plot.dispatchEvent(new PointerEvent('pointerleave', { bubbles: false }));
        plot.focus();
      });
      assert(/^Sep 29, 2026\. 129 messages\./.test(await page.evaluate(() => document.querySelector('.rh-chart[data-chart="volume"] .sr-only').textContent)), 'the last day with a report');
      await page.press('ArrowLeft');
      const live = await page.evaluate(() => document.querySelector('.rh-chart[data-chart="volume"] .sr-only').textContent);
      assert(/^Sep 28, 2026\. 128 messages\./.test(live), live);
      assert(/arrow keys/.test(await page.evaluate(() => document.querySelector('.rh-chart[data-chart="volume"] .rh-plot').getAttribute('aria-label'))), 'the plot says how to read it');
      await page.press('Home');
      assert(/^Sep 1, 2026\. No report for this day$/.test(await page.evaluate(() => document.querySelector('.rh-chart[data-chart="volume"] .sr-only').textContent)), 'the first day of the period');
      await page.evaluate(() => document.activeElement.blur());
      // A new sender since the history's first week, named from its DKIM signature.
      assertEqual(await text(page, '[data-role="rh-new-line"]'), '1 new sender since Sep 17, 2026.', 'the new line');
      const rows = await page.evaluate(() => [...document.querySelectorAll('.rh-sources tbody tr.dt-row')].map((tr) => [tr.querySelector('.rpt-ip')?.dataset.ip,
        tr.querySelector('.rpt-svc-meta')?.textContent || null, tr.querySelector('.rh-new')?.textContent || null]));
      assertEqual(rows, [['192.0.2.30', null, null], ['203.0.113.77', null, null], ['198.51.100.88', 'SendGrid — Transactional email', 'New since Sep 27, 2026']], 'the sources, the most mail first, the new one badged');
      await page.click('[data-role="rh-only-new"]');
      await page.waitFor(() => document.querySelectorAll('.rh-sources tbody tr.dt-row').length === 1, { message: 'only the new one' });
      await page.click('[data-role="rh-only-new"]');
      await page.waitFor(() => document.querySelectorAll('.rh-sources tbody tr.dt-row').length === 3, { message: 'all again' });
      // The table view of the charts, and its CSV.
      await page.click('.rh-days-box summary');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.rh-days tbody tr.dt-row').length), 20, 'one row per day with a report');
      await page.click('.rh-days [data-export="csv"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'download' });
      const [file] = await takeDownloads(page);
      assert(/^dmarc-history-days-example\.org-.*\.csv$/.test(file.name), file.name);
      const { TREND_CSV_COLUMNS } = await import('../../assets/js/lib/dmarchistory.js');
      assertEqual(csvHeader(file.text), [...TREND_CSV_COLUMNS], 'CSV header');
      assertEqual(file.text.trim().split(/\r?\n/).length, 21, 'a row per day');
      await page.click('.rh-days-box summary');
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, 'dmarchistory-trend-desktop-light-en');
    });

    await run.step('the roll-up: every domain with its verdict, the totals, a CSV; a domain shown from it', async () => {
      const roll = await page.evaluate(() => [...document.querySelectorAll('.rh-rollup tbody tr.dt-row')].map((tr) => [tr.querySelector('.rh-show')?.dataset.domain,
        tr.querySelector('[data-verdict]')?.dataset.verdict, !!tr.querySelector('.rh-not-checked')]));
      assertEqual(roll, [['example.com', 'fix-first', false], ['example.org', 'ready', true], ['example.net', 'enforced', true]],
        'the most mail first; a domain whose SPF was not checked says so');
      assert(/^3 domains · 7,475 messages · /.test(await text(page, '[data-role="rh-rollup-totals"]')), await text(page, '[data-role="rh-rollup-totals"]'));
      await page.click('.rh-rollup [data-export="csv"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'roll-up download' });
      const [file] = await takeDownloads(page);
      assert(/^dmarc-rollup-.*\.csv$/.test(file.name), file.name);
      const { ROLLUP_CSV_COLUMNS } = await import('../../assets/js/lib/dmarchistory.js');
      assertEqual(csvHeader(file.text), [...ROLLUP_CSV_COLUMNS], 'CSV header');
      assert(file.text.split(/\r?\n/).some((l) => /^example\.net,29,.*,reject,quarantine,100,2026-09-25,enforced,/.test(l)), file.text);
      await page.click('.rh-rollup .rh-show[data-domain="example.net"]');
      await page.waitFor(() => document.querySelector('.rh-domain-card .card-title')?.textContent === 'example.net', { message: 'example.net shown' });
      assertEqual(await page.evaluate(() => document.activeElement?.matches('.rh-domain select')), true, 'the focus on the picker');
      await page.evaluate(() => document.querySelector('.rh-rollup-card').scrollIntoView());
      await shot(page, 'dmarchistory-rollup-desktop-light-en');
      await pickHistoryDomain(page, 'example.org');
    });

    await run.step('400 days: a bar a week, the last one ending today', async () => {
      await page.click('.rh-period .seg-btn[data-value="400"]');
      await page.waitFor(() => document.querySelector('.rh-chart[data-chart="volume"] .rh-chart-title')?.textContent === 'Messages per week', { message: 'by week' });
      await frames(page);
      assertEqual((await bars(page, 'volume')).map(([d]) => d), ['2026-09-10', '2026-09-17', '2026-09-24'], 'the weeks with a report');
      assertEqual(await page.evaluate(() => document.activeElement?.matches('.rh-period .seg-btn[data-value="400"]')), true, 'the focus stays on the period');
      await page.click('.rh-period .seg-btn[data-value="30"]');
      await page.waitFor(() => document.querySelector('.rh-chart[data-chart="volume"] .rh-chart-title')?.textContent === 'Messages per day', { message: 'by day again' });
    });

    await run.step('Report: the DMARC customer report of the domain on screen with its trend; no re-run link, no script, no server of the list, nothing sent', async () => {
      await page.click('.rpt-tabs [data-tab="dmarc"]');
      const before = await dnsCount(page);
      await page.click('.rpt-results-head [data-action="report"]');
      await page.waitFor(() => !!document.querySelector('dialog.crep-modal[open]'), { message: 'report panel' });
      assertEqual(await page.evaluate(() => !!document.querySelector('dialog.crep-modal [data-role="report-link"]')), false, 'no link to offer');
      await page.click('dialog.crep-modal [data-action="report-download"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'downloaded' });
      const [file] = await takeDownloads(page);
      assert(/^dmarc-report-example\.com-\d{8}-\d{4}\.html$/.test(file.name), file.name);
      assert(file.text.startsWith('<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy"'), file.text.slice(0, 160));
      assert(!/<script/i.test(file.text) && !file.text.includes('<a '), 'no script, no link');
      assert(file.text.includes('<title>DMARC report · example.com</title>'), 'the title');
      const sections = [...file.text.matchAll(/data-section="([a-z]+)"/g)].map((m) => m[1]).filter((x) => x !== 'services');
      assertEqual(sections, ['problems', 'reports', 'classes', 'notes', 'trend', 'new', 'method'], 'the sections');
      assert(file.text.includes('203.0.113.99') && file.text.includes('In your server list'), 'the server of the list by its address');
      for (const secret of ['mail01', 'app02', 'noreply-dmarc-support', 'reports-2026-09']) assert(!file.text.includes(secret), secret);
      assertEqual(await dnsCount(page), before, 'nothing sent');
    });

    await run.step('a reload keeps the history, not the reports: the History tab alone, the switch on, its report', async () => {
      await page.reload();
      await waitReady(page);
      await page.waitFor(() => !!document.querySelector('.rpt-tabs [data-tab="history"]'), { message: 'the History tab', timeout: 15000 });
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-tabs [role="tab"]')].map((b) => b.dataset.tab)), ['history'], 'the History tab alone');
      assertEqual(await text(page, '.rpt-results-title'), 'Report history of this workspace', 'the title');
      assertEqual(await page.evaluate(() => document.querySelector('[data-role="rpt-keep"]').checked), true, 'the switch on');
      assertEqual(await keptTotals(page), { 'example.com': 5175, 'example.net': 29, 'example.org': 2271 }, 'kept');
      await page.waitFor(() => !!document.querySelector('.rh-domain-card'), { message: 'the panel' });
      assertEqual(await text(page, '.rh-domain-card .card-title'), 'example.com', 'the domain with the most mail');
      await page.click('.rpt-results-head [data-action="report"]');
      await page.waitFor(() => !!document.querySelector('dialog.crep-modal[open]'), { message: 'report panel' });
      await page.click('dialog.crep-modal [data-action="report-download"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'downloaded' });
      const [file] = await takeDownloads(page);
      assert(file.text.includes('The reports themselves are not open in DomainScope'), 'the sources to fix are not known without the reports');
      assertEqual([...file.text.matchAll(/data-section="([a-z]+)"/g)].map((m) => m[1]), ['problems', 'trend', 'new', 'method'], 'the history alone');
    });

    run.group('Phone 375 and 320 px, Turkish / English, light / dark');
    await run.step('the History tab at 375 px in Turkish (dark) and English (light), and at 320 px: no horizontal scroll', async () => {
      await page.setViewport({ width: 375, height: 760, mobile: true });
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('.rh-domain-card'), { message: 'the panel in Turkish', timeout: 15000 });
      await pickHistoryDomain(page, 'example.org');
      assertEqual(await text(page, '.rpt-tabs [data-tab="history"] .tab-label'), 'Geçmiş', 'the tab in Turkish');
      assertEqual(await text(page, '[data-role="rh-new-line"]'), '17 Eyl 2026 tarihinden bu yana 1 yeni gönderici var.', 'the new line in Turkish');
      assertEqual(await page.evaluate(() => document.querySelector('.rh-chart[data-chart="volume"] .rh-chart-title').textContent), 'Günlük e-posta sayısı');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await frames(page);
      await assertNoHorizontalScroll(page, 'history 375 tr dark');
      assertEqual(await overflowing(page), [], 'every card and chart fits at 375 px');
      await shot(page, 'dmarchistory-375-dark-tr');
      await setLangUi(page, 'en');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await page.waitFor(() => !!document.querySelector('.rh-domain-card'), { message: 'the panel in English', timeout: 15000 });
      await frames(page);
      await assertNoHorizontalScroll(page, 'history 375 en light');
      await shot(page, 'dmarchistory-375-light-en');
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await frames(page);
      await assertNoHorizontalScroll(page, 'history 320 en light');
      assertEqual(await overflowing(page), [], 'every card and chart fits at 320 px');
      await page.emulateMedia({ 'prefers-color-scheme': 'dark' });
      await frames(page);
      await assertNoHorizontalScroll(page, 'history 320 en dark');
      await shot(page, 'dmarchistory-320-dark-en');
      await page.setViewport({ width: 1440, height: 900 });
      await setLangUi(page, 'tr');
      await page.waitFor(() => !!document.querySelector('.rh-domain-card'), { message: 'the panel', timeout: 15000 });
      await frames(page);
      await shot(page, 'dmarchistory-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Off, Forget, Delete all local data');
    await run.step('turned off after a confirmation: a new drop writes nothing; the History tab says keeping is off', async () => {
      await page.waitFor(() => !!document.querySelector('[data-role="rpt-keep"]'), { message: 'the switch' });
      const before = await storedText(page);
      await page.click('[data-role="rpt-keep"]');
      await page.waitFor(() => !!document.querySelector('dialog.modal[open]'), { message: 'the confirmation' });
      assert(/New reports are no longer added/.test(await text(page, 'dialog.modal[open]')), await text(page, 'dialog.modal[open]'));
      await confirmWith(page, 'Stop keeping');
      await page.waitFor(() => document.querySelector('[data-role="rpt-keep"]')?.checked === false, { message: 'off' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.role), 'rpt-keep', 'the focus on the switch');
      const off = JSON.parse(await storedText(page));
      assertEqual([off.keep, JSON.stringify(off.domains) === JSON.stringify(JSON.parse(before).domains)], [false, true], 'off, what is kept stays');
      const stored = await storedText(page);
      await page.setFileInput('.rpt-load .filedrop-input', [lateReport]);
      await waitDmarc(page);
      await page.evaluate(() => new Promise((r) => setTimeout(r, 600)));
      assertEqual(await storedText(page), stored, 'nothing written');
      await openHistory(page);
      assert(/Keeping is off: new reports are not added/.test(await text(page, '.rh-footer')), await text(page, '.rh-footer'));
    });

    await run.step('Forget report history: confirmed, nothing is kept; turned on again it keeps; Delete all local data clears it', async () => {
      await page.click('[data-action="rh-forget"]');
      await page.waitFor(() => !!document.querySelector('dialog.modal[open]'), { message: 'the confirmation' });
      assert(/Delete the report history of 3 domains in this workspace\?/.test(await text(page, 'dialog.modal[open]')), await text(page, 'dialog.modal[open]'));
      await confirmWith(page, 'Forget report history');
      await page.waitFor(() => !document.querySelector('.rpt-tabs [data-tab="history"]'), { message: 'no History tab: off and empty' });
      assertEqual(await storedText(page), '', 'nothing kept');
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.whenSaved());
      assertEqual(await idbRecord(page), null, 'the record is gone');
      // On again: the report read in the tab is kept at once.
      await removeToasts(page);
      await page.click('[data-role="rpt-keep"]');
      await toastText(page, /1 report added/, 'kept');
      assertEqual(await keptTotals(page), { 'example.org': 130 }, 'the report of the tab');
      await deleteAllLocalData(page);
      await gotoRoute(page, 'reports');
      assertEqual(await storedText(page), '', 'cleared with the rest');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="rpt-keep"]')?.checked, !!document.querySelector('.rpt-tabs [data-tab="history"]')]), [false, false], 'off, no History tab');
      await setLangUi(page, 'en');
    });

    run.group('Another tab, the size limit');
    await run.step('another tab turns keeping on, off and on again: the switch here follows every change', async () => {
      const other = await browser.newPage('about:blank', { width: 1280, height: 900 });
      try {
        await other.send('Network.enable');
        await other.send('Network.setBlockedURLs', { urls: ['https://*'] });
        await other.send('Page.addScriptToEvaluateOnNewDocument', { source: pinnedClockScript(HISTORY_NOW) });
        await other.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript() });
        await other.goto(`${server.url}#/reports`);
        await waitReady(other);
        const follows = (p, on, message) => p.waitFor((v) => document.querySelector('[data-role="rpt-keep"]')?.checked === v, { args: [on], message, timeout: 10000 });
        // A click goes to the tab in front (a tab behind it runs its timers once a second).
        const front = (p) => p.send('Page.bringToFront');
        await follows(other, false, 'off in the other tab');
        await front(page);
        await page.click('[data-role="rpt-keep"]');
        await follows(other, true, 'on here: on there');
        // Nothing is kept yet: turned off without a question.
        await front(other);
        await other.click('[data-role="rpt-keep"]');
        await follows(page, false, 'off there: off here');
        // On again there: the workspace holds the very text this tab wrote first.
        await other.click('[data-role="rpt-keep"]');
        await follows(page, true, 'on again there: on again here');
        assertEqual(JSON.parse(await storedText(page)).keep, true, 'on in the workspace');
      } finally {
        await other.close();
        await page.send('Page.bringToFront');
      }
    });

    await run.step('a history at its size limit takes a drop of two domains: its oldest details are trimmed, the rest kept', async () => {
      const filler = fillerHistory(HISTORY_MAX_BYTES - 2000);
      assert(filler.length <= HISTORY_MAX_BYTES - 2000 && filler.length > HISTORY_MAX_BYTES - 2200, `the filler: ${filler.length} characters`);
      await page.evaluate((value) => import('./assets/js/state.js').then(async ({ state }) => {
        await state.setWorkspaceData('reportHistory', value);
        await state.whenSaved();
      }), filler);
      await page.waitFor(() => !!document.querySelector('.rpt-tabs [data-tab="history"]'), { message: 'the History tab follows the workspace', timeout: 15000 });
      await removeToasts(page);
      await page.setFileInput('.rpt-load .filedrop-input', [capZip]);
      const said = await toastText(page, /reports added/, 'kept');
      assert(/^2 reports added to the history of this workspace\. The history reached its size limit \(4 MB\): its oldest details were dropped\.$/.test(said), said);
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.whenSaved());
      const stored = await storedText(page);
      assert(stored.length > HISTORY_MAX_BYTES - 1000 && stored.length < HISTORY_MAX_BYTES, `${stored.length} characters`);
      assertEqual(Object.keys(JSON.parse(stored).domains), ['example.com', 'example.net', 'example.org'], 'every domain');
    });

    await run.step('a day whose mail all failed is a bar in the compliance chart, a stub in the error band, not a gap', async () => {
      await openHistory(page);
      await pickHistoryDomain(page, 'example.net');
      assertEqual((await bars(page, 'volume')).map(([d]) => d), ['2026-09-29'], 'its messages');
      assertEqual(await bars(page, 'compliance'), [['2026-09-29', ['compliance']]], 'its compliance');
      const stub = await page.evaluate(() => {
        const seg = document.querySelector('.rh-chart[data-chart="compliance"] g.rh-bar[data-day="2026-09-29"] [data-seg]');
        return { cls: seg.getAttribute('class'), height: Math.round(seg.getBBox().height * 100) / 100 };
      });
      assertEqual(stub, { cls: 'rh-band-error', height: 2 }, 'a 2 px stub in the error band');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.rh-stats .stat-value')[1].textContent), '0%', 'the compliance of the period');
    });

    await run.step('its SPF landing classes that domain again at the limit: trimmed again and said so, never lost', async () => {
      await page.click('.rpt-tabs [data-tab="dmarc"]');
      await page.waitFor(() => !!document.querySelector('.rpt-domain select'), { message: 'the DMARC domain picker' });
      await page.evaluate(() => import('./assets/js/state.js').then(({ state }) => {
        window.__keptBefore = state.workspaceData('reportHistory') || '';
      }));
      await removeToasts(page);
      await page.evaluate(() => {
        const sel = document.querySelector('.rpt-domain select');
        sel.value = 'example.net';
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'ok', { message: 'the SPF of example.net', timeout: 15000 });
      // The history follows a moment later (HISTORY_SYNC_MS): every source of example.net now rests on its SPF.
      await page.waitFor(() => import('./assets/js/state.js').then(({ state }) => (state.workspaceData('reportHistory') || '') !== window.__keptBefore),
        { message: 'the history classed again', timeout: 15000 });
      await page.evaluate(async () => (await import('./assets/js/state.js')).state.whenSaved());
      const stored = await storedText(page);
      assert(stored.length > HISTORY_MAX_BYTES - 1000 && stored.length < HISTORY_MAX_BYTES, `the history is still there: ${stored.length} characters`);
      assertEqual(await idbRecord(page), stored, 'in IndexedDB as the workspace holds it');
      const h = JSON.parse(stored);
      assertEqual([h.keep, Object.keys(h.domains), h.domains['example.net'].checked], [true, ['example.com', 'example.net', 'example.org'], '2026-09-30'], 'on, every domain, example.net checked');
      assertEqual(Object.values(h.domains['example.net'].sources).filter((s) => !s.checked).length, 0, 'every address of example.net classed against its SPF');
      await toastText(page, /^The history reached its size limit \(4 MB\): its oldest details were dropped\.$/, 'the trim said');
      assertEqual(await page.evaluate(() => [document.querySelector('[data-role="rpt-keep"]').checked, !!document.querySelector('.rpt-tabs [data-tab="history"]')]),
        [true, true], 'the switch on, the History tab there');
    });

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'dmarchistory', origin));
    await page.close();
  } finally {
    await browser.close();
    await server.close();
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
  run.finish(opts.shots ? ` — screenshots in ${path.relative(process.cwd(), opts.shotsDir)}` : '');
}

main().catch((err) => {
  process.stderr.write(`E2E crashed: ${(err && err.stack) || err}\n`);
  process.exitCode = 1;
});
