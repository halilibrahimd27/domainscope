#!/usr/bin/env node
/**
 * reports.e2e.mjs — end-to-end test of the "DMARC & TLS reports" view in a real headless Chrome/Edge.
 * OFFLINE: every DoH query is answered in the page by a fake resolver built from the zone below
 * (window.fetch wrapped before the app loads), RIPEstat and ipwho.is by the same wrapper; every
 * other https:// request is blocked, and every request that leaves the page's origin is counted
 * through CDP.
 *
 *   node tests/e2e/reports.e2e.mjs [--browser chrome|edge] [--headed] [--no-shots]
 *
 * Covers: the nav entry (Watch & report, after Monitoring), the empty state and the privacy note;
 * a dropped zip of a mailbox folder (a Google-style .zip and a Microsoft-style .xml.gz of DMARC
 * reports, a DMARCbis report, two TLS-RPT .json.gz, a notes.txt that is no report) read in the
 * browser: the files line and what could not be used, the busiest domain as the current target,
 * the reports' domain's SPF looked up (TXT / MX / A only) and the sources classified with the
 * server list — your servers, an authorized third party through an include, forwarders, unknown
 * senders —, the verdict "not ready for p=reject" with the sources to fix first and their fixes,
 * the classes' read-only figures and the Show select filtering the table, a row's details, the reverse DNS and network of an address
 * only on a click, the CSV export (every column), Copy summary; the TLS-RPT tab: success rate,
 * policies, failure types with advice and links to Domain Health, DNS Lookup and the Certificate
 * view; the second domain; a failed SPF lookup said so and Check again; the kept reports on the way
 * back (no new query); Forget; 150 daily reports in one drop (past the 100 other drop zones take) with
 * a zip whose entries share one stream, refused at once; a zip of 205 files that are no report: the
 * first 200 listed, "+5 more", and Forget offered for them alone; files dropped while reading wait their turn,
 * the bar counts them, and Stop (Esc) before a report was read keeps nothing; a zipped mailbox
 * folder of 300 reports counted report by report and stopped in its middle, the reports read before
 * the Stop kept and counted in its toast; a switch to another workspace while files are read names
 * the read in its confirmation, and Cancel keeps reading; an SPF record with a
 * syntax error: the SPF line, the note and the verdict say receivers get a permanent error, the
 * server it lists stays yours and its mail that passed through SPF alone is to fix, refused now once
 * p=reject is in force; offline, a dropped
 * report classified from its own evidence with the SPF line saying it was not checked and nothing
 * sent, then Check again online; 375 / 320 px without
 * horizontal scroll, TR / EN × light / dark; zero
 * console errors / CSP violations / missing i18n keys, nothing sent outside the page.
 *
 * Data is documentation space only (tests/fixtures/mailreports: example.com / .net / .org,
 * 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
 */

import path from 'node:path';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { deflateRawSync } from 'node:zlib';
import { startServer } from './serve.mjs';
import { launchBrowser } from './cdp.mjs';
import { crc32 } from '../../assets/js/lib/zipread.js';
import { DEFAULT_CHAIN, getResolver } from '../../assets/js/lib/resolvers.js';
import {
  BASE, FIXTURES, SHOTS, assert, assertClean, assertEqual, assertNoHorizontalScroll, assertNoMissingKeys, cliOptions, createRunner,
  gotoRoute, installDownloadCapture, setLangUi, shot, stubClipboard, takeClipboard, takeDownloads, waitReady, csvHeader
} from './scan.e2e.mjs';

const MAILBOX = path.join(FIXTURES, 'mailreports', 'reports-2026-09.zip');
const MICROSOFT_GZ = path.join(FIXTURES, 'mailreports', 'enterprise.protection.outlook.com!example.com!1790294400!1790380800.xml.gz');

/** example.com's SPF (its own server, its MX, its own include, a mailing service) and the reverse DNS of one sender. */
const ZONE = {
  'example.com': {
    TXT: [['v=spf1 ip4:203.0.113.25 mx include:_spf.example.com include:spf.mailer.example.net ~all']],
    MX: [{ preference: 10, exchange: 'mx1.example.com' }]
  },
  'mx1.example.com': { A: ['203.0.113.26'] },
  '_spf.example.com': { TXT: [['v=spf1 ip6:2001:db8:25::/64 -all']] },
  'spf.mailer.example.net': { TXT: [['v=spf1 ip4:198.51.100.0/26 -all']] },
  'example.net': { TXT: [['v=spf1 ip4:192.0.2.10 -all']] },
  '200.2.0.192.in-addr.arpa': { PTR: ['host-200.spam.example.org'] }
};

/** In-page stubs: DoH from the zone (NXDOMAIN outside it), RIPEstat, ipwho.is. */
const fakeScript = () => `(() => {
  const Z = window.__zone = ${JSON.stringify(ZONE)};
  window.__dnsLog = [];
  window.__ipLog = [];
  window.__rcodes = {};
  let wire = null;
  const realFetch = window.fetch.bind(window);
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const u = new URL(url, location.href);
    if (u.hostname === 'stat.ripe.net') {
      const ip = u.searchParams.get('resource');
      const call = u.pathname.split('/')[2];
      window.__ipLog.push(call + ' ' + ip);
      if (call === 'prefix-overview') {
        return json({ status: 'ok', data: { announced: true, asns: [{ asn: 64496, holder: 'EXAMPLE-AS - Example Hosting Ltd' }],
          resource: ip.split('.').slice(0, 3).join('.') + '.0/24', block: { desc: 'Administered by RIPE NCC' } } });
      }
      if (call === 'maxmind-geo-lite') {
        return json({ status: 'ok', data: { located_resources: [{ locations: [{ country: 'NL', city: 'Amsterdam', covered_percentage: 100 }] }] } });
      }
      return json({ status: 'error' }, 400);
    }
    if (u.hostname === 'ipwho.is') { window.__ipLog.push('ipwhois'); return json({ success: false, message: 'quota' }); }
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) return realFetch(input, init);
    wire = wire || await import(new URL('assets/js/lib/dnswire.js', document.baseURI).href);
    const q = wire.decodeMessage(wire.base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const qname = String(q.name).toLowerCase().replace(/[.]$/, '');
    window.__dnsLog.push({ name: qname, type: q.type, host: u.hostname });
    const forced = window.__rcodes[qname + '|' + q.type];
    const node = Z[qname];
    const answers = forced || !node ? [] : (node[q.type] || []).map((data) => ({ name: qname, type: q.type, ttl: 300, data }));
    return new Response(wire.encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: forced || (node ? 'NOERROR' : 'NXDOMAIN'),
      questions: [{ name: q.name, type: q.type }], answers, edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
})();`;

/** One day's aggregate report of example.com from one reporter (its own report id): 10 messages of 203.0.113.25. */
const dailyReport = (day, { dkim = 'pass', p = 'none' } = {}) => {
  const begin = 1790294400 + day * 86400;
  return `<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata><org_name>google.com</org_name><email>noreply-dmarc-support@example.org</email>
<report_id>daily-${day}</report_id><date_range><begin>${begin}</begin><end>${begin + 86399}</end></date_range></report_metadata>
<policy_published><domain>example.com</domain><p>${p}</p></policy_published>
<record><row><source_ip>203.0.113.25</source_ip><count>10</count><policy_evaluated><disposition>none</disposition><dkim>${dkim}</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>example.com</header_from></identifiers><auth_results><dkim><domain>example.com</domain><selector>mail2026</selector><result>${dkim}</result></dkim>
<spf><domain>example.com</domain><result>pass</result></spf></auth_results></record></feedback>`;
};

/**
 * One week of example.org's mail, whose sources the senders group names: one authorized by a
 * service's SPF include, one signing with a service's DKIM, one bouncing through a service's
 * return-path, three nothing in the report names, and a private address.
 */
const sendersReport = () => {
  const rec = (ip, count, { dkim = 'fail', spf = 'fail', auth = '<spf><domain>example.org</domain><result>fail</result></spf>' } = {}) => `<record><row><source_ip>${ip}</source_ip><count>${count}</count>
<policy_evaluated><disposition>none</disposition><dkim>${dkim}</dkim><spf>${spf}</spf></policy_evaluated></row>
<identifiers><header_from>example.org</header_from></identifiers><auth_results>${auth}</auth_results></record>`;
  return `<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata><org_name>google.com</org_name><email>noreply-dmarc-support@example.org</email>
<report_id>senders-1</report_id><date_range><begin>1790294400</begin><end>1790899199</end></date_range></report_metadata>
<policy_published><domain>example.org</domain><p>none</p></policy_published>
${rec('203.0.113.40', 40, { spf: 'pass', auth: '<spf><domain>example.org</domain><result>pass</result></spf>' })}
${rec('198.51.100.61', 25, { dkim: 'pass', auth: '<dkim><domain>example.org</domain><selector>s1</selector><result>pass</result></dkim><dkim><domain>sendgrid.net</domain><selector>smtpapi</selector><result>pass</result></dkim><spf><domain>sendgrid.net</domain><result>pass</result></spf>' })}
${rec('192.0.2.62', 9, { dkim: 'pass', auth: '<dkim><domain>example.org</domain><selector>pm</selector><result>pass</result></dkim><spf><domain>pm.mtasv.net</domain><result>pass</result></spf>' })}
${rec('192.0.2.70', 6)}
${rec('198.51.100.71', 4)}
${rec('203.0.113.72', 3)}
${rec('10.1.2.3', 2)}
</feedback>`;
};

/** A zip of `n` central directory entries that all name one deflate stream of 8 MB (each claims 100 bytes). */
function overlappingZip(n) {
  const le = (v, size) => {
    const b = Buffer.alloc(size);
    if (size === 2) b.writeUInt16LE(v);
    else b.writeUInt32LE(v);
    return b;
  };
  const name = Buffer.from('a.xml');
  const data = deflateRawSync(Buffer.alloc(8 * 1024 * 1024, 0x20), { level: 9 });
  const local = Buffer.concat([le(0x04034b50, 4), le(20, 2), le(0, 2), le(8, 2), le(0, 4), le(0, 4), le(data.length, 4), le(100, 4), le(name.length, 2), le(0, 2), name, data]);
  const entry = Buffer.concat([le(0x02014b50, 4), le(20, 2), le(20, 2), le(0, 2), le(8, 2), le(0, 4), le(0, 4), le(data.length, 4), le(100, 4),
    le(name.length, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(0, 4), name]);
  const central = Buffer.concat(Array.from({ length: n }, () => entry));
  const end = Buffer.concat([le(0x06054b50, 4), le(0, 2), le(0, 2), le(n, 2), le(n, 2), le(central.length, 4), le(local.length, 4), le(0, 2)]);
  return Buffer.concat([local, central, end]);
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
/** The sending addresses' Show select: one class ('' for every class). */
const setClass = (page, cls) => page.evaluate((v) => {
  const sel = document.querySelector('[data-role="rpt-cls-filter"]');
  sel.value = v;
  sel.dispatchEvent(new Event('change', { bubbles: true }));
}, cls);
const counts = (page) => page.evaluate(() => ({ dns: window.__dnsLog.length, ip: window.__ipLog.length }));
/** The Service column: ip → "name|via" (a named source) or its muted text ("—", "not identified"). */
const tableServices = (page) => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.rpt-sources tbody tr.dt-row')].map((tr) => {
  const svc = tr.querySelector('.rpt-svc');
  return [tr.querySelector('.rpt-ip')?.dataset.ip, svc ? `${svc.querySelector('.rpt-svc-name').textContent}|${svc.dataset.via}` : tr.querySelector('.rpt-svc-none')?.textContent || ''];
})));
/** The service view's rows: [group key, name, addresses] in their order. */
const tableGroups = (page) => page.evaluate(() => [...document.querySelectorAll('.rpt-services tbody tr.dt-row')].map((tr) => {
  const svc = tr.querySelector('.rpt-svc');
  return [svc?.dataset.group, svc?.querySelector('.rpt-svc-name')?.textContent, tr.querySelector('td.rpt-grp-addr')?.textContent];
}));
/** The sources table as [ip, class] in its order (only the rows it shows). */
const tableClasses = (page) => page.evaluate(() => [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')]
  .map((tr) => [tr.querySelector('.rpt-ip')?.dataset.ip, tr.querySelector('.badge[data-cls]')?.dataset.cls]));
/**
 * Wait for the DataTable's next frame. An SPF answer redraws the SPF line, the tiles and the verdict at once, but the
 * table's changed rows on its next animation frame (DataTable.updateRows): a read that follows the line alone can still
 * see the classes the reports gave before the SPF (a third party as yours, or as unknown).
 */
const frames = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
const waitDmarc = async (page, message = 'DMARC tab with its sources') => {
  await page.waitFor(() => document.querySelectorAll('.rpt-sources tbody tr.dt-row').length > 0
    && document.querySelector('.rpt-spf')?.dataset.state !== 'loading', { timeout: 20000, message });
  await frames(page);
};

/** In the page: save `text` as the active workspace's inventory ('' clears it). */
function saveInventory(textValue) {
  return import('./assets/js/state.js').then(async ({ state }) => {
    await state.setInventory(textValue).done;
    await state.whenSaved();
  });
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
    await page.send('Page.addScriptToEvaluateOnNewDocument', { source: fakeScript() });
    await installDownloadCapture(page);
    await page.emulateMedia({ 'prefers-color-scheme': 'light' });

    run.group('Desktop 1440×900 (English)');
    await run.step('boots on #/reports: the nav entry after Monitoring, the empty state, the privacy note, nothing sent', async () => {
      await page.goto(`${server.url}#/reports`);
      await waitReady(page);
      if (await page.evaluate(() => document.documentElement.lang) !== 'en') await setLangUi(page, 'en');
      await gotoRoute(page, 'reports');
      const nav = await page.evaluate(() => {
        const group = [...document.querySelectorAll('.nav-list')].find((ul) => ul.querySelector('[href$="#/monitor"]'));
        return group ? [...group.querySelectorAll('.nav-link')].map((a) => a.getAttribute('href').replace(/^.*#\//, '').split('?')[0]) : [];
      });
      assertEqual(nav, ['portfolio', 'monitor', 'reports'], 'Watch & report group');
      assertEqual(await text(page, 'h1'), 'DMARC & TLS reports', 'title');
      assert(await page.evaluate(() => !!document.querySelector('.rpt-page .tool-empty')), 'empty state');
      assert(/never uploaded or saved/.test(await text(page, '.rpt-load .tool-input-foot .privacy-note')), 'privacy note');
      assertEqual(await counts(page), { dns: 0, ip: 0 }, 'nothing sent');
      await page.evaluate(saveInventory, 'mail01 203.0.113.25\napp02 203.0.113.99\n');
      await shot(page, opts, 'reports-empty-desktop-light-en');
    });

    await run.step('a dropped mailbox zip is read in the browser: the files line, what could not be used, the busiest domain as the target', async () => {
      await page.setFileInput('.rpt-load .filedrop-input', [MAILBOX]);
      await waitDmarc(page);
      assertEqual(await text(page, '[data-role="rpt-files"]'), '1 file · 3 DMARC reports · 2 TLS reports · 1 could not be used', 'files line');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-problem-list li')].map((li) => [li.dataset.code, li.querySelector('.rpt-problem-path').textContent])),
        [['not-report', 'reports-2026-09.zip › notes.txt']], 'problems');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-tabs [role="tab"]')].map((b) => b.dataset.tab)), ['dmarc', 'tls'], 'tabs');
      assertEqual(await text(page, '.rpt-results-title'), 'Reports for 2 domains', 'results title');
      assertEqual(await page.evaluate(() => document.activeElement?.classList.contains('rpt-results-title')), true, 'the focus on the results');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-domain option')].map((o) => o.textContent)),
        ['example.com — 5,175 messages', 'example.net — 29 messages'], 'domains, busiest first');
      await page.waitFor(() => document.querySelector('[data-role="target-chip"] .target-chip-value')?.textContent === 'example.com', { message: 'target chip' });
      const asked = await page.evaluate(() => [...new Set(window.__dnsLog.map((q) => `${q.name}|${q.type}`))].sort());
      assertEqual(asked, ['_spf.example.com|TXT', 'example.com|MX', 'example.com|TXT', 'mx1.example.com|A', 'mx1.example.com|AAAA', 'spf.mailer.example.net|TXT'], 'only the SPF tree');
      assertEqual((await counts(page)).ip, 0, 'no IP data yet');
    });

    await run.step('the sources classified against the current SPF and the server list; the verdict and what to fix first', async () => {
      const cls = Object.fromEntries(await tableClasses(page));
      assertEqual(cls, {
        '198.51.100.10': 'third-party', '203.0.113.25': 'yours', '203.0.113.26': 'yours', '198.51.100.20': 'third-party',
        '2001:db8:25::10': 'yours', '203.0.113.99': 'yours', '192.0.2.200': 'unknown', '198.51.100.200': 'unknown',
        '192.0.2.44': 'forwarder', '192.0.2.45': 'forwarder'
      }, 'classes');
      assertEqual(await page.evaluate(() => document.querySelector('.rpt-spf').dataset.state), 'ok', 'SPF checked');
      assert(/v=spf1 ip4:203\.0\.113\.25 mx include:_spf\.example\.com/.test(await text(page, '.rpt-spf')), 'the record');
      assertEqual(await page.evaluate(() => document.querySelector('.rpt-verdict').dataset.verdict), 'fix-first', 'verdict');
      assertEqual(await text(page, '.rpt-compliance'), '94.9%', 'compliance, as Copy summary says it');
      const fixes = await page.evaluate(() => [...document.querySelectorAll('.rpt-fix-item')].map((li) => [li.dataset.ip, [...li.querySelectorAll('[data-fix]')].map((f) => f.dataset.fix)]));
      assertEqual(fixes, [['198.51.100.20', ['dkim-align', 'spf-align']], ['203.0.113.99', ['dkim-sign', 'spf-add']]], 'fix first');
      const first = await text(page, '.rpt-fix-item[data-ip="198.51.100.20"]');
      assert(/Authorized through include:spf\.mailer\.example\.net/.test(first) && /120 of 120 messages fail/.test(first)
        && /It signs DKIM only as mailer\.example\.net: set up DKIM for example\.com/.test(first), first);
      assert(/In your server list: app02/.test(await text(page, '.rpt-fix-item[data-ip="203.0.113.99"]')), 'the server of the list');
      assert(/2 unknown senders, 85 failing messages/.test(await text(page, '.rpt-unknown-line')), 'unknown senders');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-notes li')].map((li) => li.dataset.note)), ['short-range'], 'notes');
      await shot(page, opts, 'reports-dmarc-desktop-light-en');
    });

    await run.step('the class figures; the Show select filters the table; a row\'s details say why, with the current SPF', async () => {
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-cls .metric')].map((m) => `${m.dataset.cls} ${m.querySelector('.metric-value').textContent}`)),
        ['yours 2,055', 'third-party 3,010', 'forwarder 25', 'unknown 85'], 'the messages of each class, read-only');
      assertEqual(await page.evaluate(() => document.querySelectorAll('.rpt-cls button, .rpt-cls [tabindex]').length), 0, 'figures, not buttons');
      await setClass(page, 'unknown');
      await page.waitFor(() => document.querySelectorAll('.rpt-sources tbody tr.dt-row').length === 2, { message: 'unknown only' });
      assertEqual((await tableClasses(page)).map(([, c]) => c), ['unknown', 'unknown'], 'filtered');
      await setClass(page, '');
      await page.waitFor(() => document.querySelectorAll('.rpt-sources tbody tr.dt-row').length === 10, { message: 'every class again' });
      await page.evaluate(() => {
        const tr = [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')].find((r) => r.querySelector('.rpt-ip')?.dataset.ip === '192.0.2.44');
        tr.querySelector('.dt-expand-btn').click();
      });
      await page.waitFor(() => !!document.querySelector('.rpt-sources .rpt-details'), { message: 'details' });
      const det = await text(page, '.rpt-sources .rpt-details');
      assert(/example\.com \/ mail2026: pass/.test(det) && /softfail by ~all in example\.com/.test(det) && /Open in IP Intel/.test(det), det);
      assert(/Carries the DKIM signature your senders make \(selector mail2026\)/.test(await text(page, '.rpt-sources tbody')), 'why');
      await page.evaluate(() => document.querySelector('.rpt-sources').scrollIntoView());
      await shot(page, opts, 'reports-details-desktop-light-en');
    });

    await run.step('the reverse DNS and network of an address only on a click; the bulk button counts what is left', async () => {
      assertEqual((await counts(page)).ip, 0, 'nothing asked before the click');
      const bulk = await text(page, '[data-action="rpt-intel-all"]');
      assertEqual(bulk, 'Look up 10 addresses', 'bulk label');
      await page.click('[data-action="rpt-intel"][data-ip="192.0.2.200"]');
      await page.waitFor(() => /host-200\.spam\.example\.org/.test(document.querySelector('.rpt-sources tbody')?.textContent || ''), { message: 'PTR' });
      assert(/AS64496 Example Hosting Ltd/.test(await text(page, '.rpt-sources tbody')), 'AS holder');
      assertEqual((await page.evaluate(() => window.__ipLog)).sort(), ['maxmind-geo-lite 192.0.2.200', 'prefix-overview 192.0.2.200'], 'one address, RIPEstat only');
      await page.waitFor(() => /Look up 9 addresses/.test(document.querySelector('[data-action="rpt-intel-all"]')?.textContent || ''), { message: 'bulk count' });
    });

    await run.step('a resolver taken out of the chain in Settings: the next reverse DNS goes to the chain as it is now', async () => {
      const host = (id) => new URL(getResolver(id).url).hostname;
      const ptrs = () => page.evaluate(() => window.__dnsLog.filter((q) => q.type === 'PTR').map((q) => `${q.name} ${q.host}`));
      assertEqual(await ptrs(), [`200.2.0.192.in-addr.arpa ${host(DEFAULT_CHAIN[0])}`], 'the first lookup asked the first resolver');
      const waitChain = (want, message) => page.waitFor((w) => JSON.parse(localStorage.getItem('ssds.settings') || '{}').chain?.join(',') === w,
        { args: [want], message });
      const settings = async (act) => {
        await page.click('[data-control="settings"]');
        try {
          await page.waitForSelector('dialog.modal[open] .settings-resolvers');
          await act();
        } finally {
          await page.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
        }
        await page.waitFor(() => !document.querySelector('dialog[open]'), { message: 'settings closed' });
      };
      await settings(async () => {
        await page.click(`dialog.modal[open] [data-resolver="${DEFAULT_CHAIN[0]}"] input[type="checkbox"]`);
        await waitChain(DEFAULT_CHAIN.slice(1).join(','), `chain without ${DEFAULT_CHAIN[0]}`);
      });
      const ip = await page.evaluate(() => document.querySelector('[data-action="rpt-intel"]')?.dataset.ip);
      await page.click(`[data-action="rpt-intel"][data-ip="${ip}"]`);
      await page.waitFor(() => window.__dnsLog.filter((q) => q.type === 'PTR').length === 2, { message: 'second PTR' });
      const second = (await ptrs())[1];
      assert(second.endsWith(` ${host(DEFAULT_CHAIN[1])}`), `the reverse DNS of ${ip} goes to the new chain: ${second}`);
      await settings(async () => {
        await page.evaluate(() => [...document.querySelectorAll('dialog.modal[open] .modal-foot button')][0].click());
        await waitChain(DEFAULT_CHAIN.join(','), 'restore defaults');
      });
    });

    await run.step('CSV of the sources (every column) and Copy summary (no server name, the bare link)', async () => {
      await page.click('.rpt-sources [data-export="csv"]');
      await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'download' });
      const [file] = await takeDownloads(page);
      assert(/^dmarc-sources-example\.com-.*\.csv$/.test(file.name), file.name);
      const { DMARC_CSV_COLUMNS } = await import('../../assets/js/lib/dmarcreport.js');
      assertEqual(csvHeader(file.text), [...DMARC_CSV_COLUMNS], 'CSV header');
      assertEqual(file.text.trim().split(/\r?\n/).length, 11, 'one row per source');
      await stubClipboard(page);
      await page.click('.rpt-results-head [data-action="copy-summary"]');
      await page.waitFor(() => (window.__clip || []).length === 1, { message: 'copied' });
      const [out] = await takeClipboard(page);
      const ls = out.trimEnd().split('\n');
      assertEqual(ls[0], '**DMARC & TLS reports · `example.com`**', 'title');
      assert(ls.includes('- **DMARC:** 94.9% of 5,175 messages pass · `p=none` · 2 reports, 2026-09-25 → 2026-09-26'), out);
      assert(ls.includes('- **Fix first:** `203.0.113.99` (your server): 57 messages fail — sign its mail with DKIM for the domain'), out);
      assert(ls.includes('- **TLS-RPT:** 99% of 6,201 TLS sessions succeeded · 2 reports'), out);
      assert(!out.includes('app02') && !out.includes('mail01'), 'no server name');
      assert(/\/domainscope\/#\/reports$/.test(ls[ls.length - 1]), ls[ls.length - 1]);
    });

    await run.step('the TLS-RPT tab: success rate, policies, failure types with advice and links', async () => {
      await page.click('.rpt-tabs [data-tab="tls"]');
      await page.waitFor(() => !!document.querySelector('.rpt-tls-head'), { message: 'TLS tab' });
      assertEqual(await text(page, '.rpt-tls-rate'), '99%', 'rate');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-tls-policies li')].map((li) => li.dataset.policy)), ['sts', 'no-policy-found', 'tlsa'], 'policies');
      assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-tls-type')].map((a) => a.dataset.type)),
        ['certificate-expired', 'starttls-not-supported', 'certificate-host-mismatch', 'validation-failure', 'sts-policy-fetch-error'], 'types');
      const expired = await text(page, '.rpt-tls-type[data-type="certificate-expired"]');
      assert(/40 failed sessions · MX mx2\.example\.com · reported by Google Inc\./.test(expired) && /Renew it/.test(expired), expired);
      const links = await page.evaluate(() => [...document.querySelectorAll('.rpt-tls-type [data-tool]')].map((a) => [a.closest('.rpt-tls-type').dataset.type, a.dataset.tool, a.getAttribute('href')]));
      assert(links.some(([ty, tool, href]) => ty === 'sts-policy-fetch-error' && tool === 'health' && /#\/health\?domain=example\.com&run=0$/.test(href)), JSON.stringify(links));
      assert(links.some(([ty, tool, href]) => ty === 'certificate-expired' && tool === 'cert' && /#\/cert\?host=mx2\.example\.com&run=0$/.test(href)), JSON.stringify(links));
      assert(links.some(([ty, tool, href]) => ty === 'validation-failure' && tool === 'cert' && /host=mx-backup\.example\.com/.test(href)), JSON.stringify(links));
      assertEqual(await page.evaluate(() => document.querySelectorAll('.rpt-tls-failures tbody tr.dt-row').length), 5, 'failure rows');
      await shot(page, opts, 'reports-tls-desktop-light-en');
      await page.click('.rpt-tabs [data-tab="dmarc"]');
    });

    await run.step('the second domain: its own sources and SPF; strict policy, reject enforced; the picker keeps the focus', async () => {
      const before = (await counts(page)).dns;
      await page.evaluate(() => {
        const sel = document.querySelector('.rpt-domain select');
        sel.focus();
        sel.value = 'example.net';
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => /example\.net/.test(document.querySelector('.rpt-head .card-title')?.textContent || '')
        && document.querySelector('.rpt-spf')?.dataset.state === 'ok', { message: 'example.net' });
      assertEqual(await page.evaluate(() => document.querySelector('.rpt-verdict').dataset.verdict), 'enforced', 'p=reject enforced');
      assertEqual(Object.fromEntries(await tableClasses(page)), { '192.0.2.10': 'yours', '198.51.100.250': 'unknown' }, 'classes');
      assert((await counts(page)).dns > before, 'its SPF looked up');
      assertEqual(await page.evaluate(() => !!document.activeElement?.matches('.rpt-domain select')), true, 'the focus on the picker drawn again');
    });

    await run.step('an SPF lookup that fails is said so, never "not authorized"; Check again asks once more, keeps the focus and the open details', async () => {
      // The SPF landed: the table draws its rows again on its next frame. A click on a row it replaces is lost.
      await page.waitFor(() => [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')].find((r) => r.querySelector('.rpt-ip')?.dataset.ip === '192.0.2.10')
        ?.textContent.includes('Your SPF authorizes it: ip4:192.0.2.10'), { message: 'the rows drawn from the SPF' });
      await page.evaluate(() => [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')].find((r) => r.querySelector('.rpt-ip')?.dataset.ip === '192.0.2.10')
        .querySelector('.dt-expand-btn').click());
      await page.waitFor(() => !!document.querySelector('.rpt-sources .rpt-details'), { message: 'details open' });
      await page.evaluate(() => {
        window.__rcodes['example.net|TXT'] = 'SERVFAIL';
        document.querySelector('[data-action="rpt-spf-retry"]').focus();
      });
      await page.press('Enter');
      await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'failed', { message: 'failed' });
      assertEqual(await page.evaluate(() => document.activeElement?.dataset.action), 'rpt-spf-retry', 'the focus on Check again drawn again');
      // The open details are drawn again with the failed lookup on the table's next frame.
      await page.waitFor(() => /could not be read \(a lookup that failed here\)|cannot tell from here/.test(document.querySelector('.rpt-sources .rpt-details')?.textContent || ''),
        { message: 'the details say the SPF could not be read' });
      assert(/could not be read/.test(await text(page, '.rpt-spf')), await text(page, '.rpt-spf'));
      assert(await page.evaluate(() => !!document.querySelector('.rpt-notes [data-note="spf-unknown"]')), 'the note');
      // The reports saw 192.0.2.10 pass SPF aligned: without the current SPF it still counts as yours.
      assertEqual(Object.fromEntries(await tableClasses(page))['192.0.2.10'], 'yours', 'from the reports');
      await page.evaluate(() => { delete window.__rcodes['example.net|TXT']; });
      await page.click('[data-action="rpt-spf-retry"]');
      await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'ok', { message: 'ok again' });
      await page.evaluate(() => {
        const sel = document.querySelector('.rpt-domain select');
        sel.value = 'example.com';
        sel.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitFor(() => /example\.com/.test(document.querySelector('.rpt-head .card-title')?.textContent || ''), { message: 'back to example.com' });
    });

    await run.step('offline, the domain picker there and back: an SPF checked before stays checked, nothing is sent', async () => {
      const offline = (on) => page.send('Network.emulateNetworkConditions', { offline: on, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
      const pick = async (domain) => {
        await page.evaluate((d) => {
          const sel = document.querySelector('.rpt-domain select');
          sel.value = d;
          sel.dispatchEvent(new Event('change', { bubbles: true }));
        }, domain);
        await page.waitFor((d) => (document.querySelector('.rpt-head .card-title')?.textContent || '').includes(d), { args: [domain], message: domain });
      };
      await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'ok', { message: 'example.com checked' });
      const before = await counts(page);
      await offline(true);
      try {
        await page.waitFor(() => navigator.onLine === false, { message: 'offline' });
        await pick('example.net');
        await pick('example.com');
        const line = await page.evaluate(() => ({
          state: document.querySelector('.rpt-spf')?.dataset.state,
          note: !!document.querySelector('.rpt-notes [data-note="spf-unknown"]')
        }));
        assertEqual(line, { state: 'ok', note: false }, 'the SPF line and the notes of example.com');
        assertEqual(await counts(page), before, 'nothing sent');
      } finally {
        await offline(false);
      }
      await page.waitFor(() => navigator.onLine === true, { message: 'online' });
    });

    await run.step('the reports are kept: back through the nav link they show again with no new query', async () => {
      const before = await counts(page);
      await gotoRoute(page, 'lookup');
      await page.click('a.nav-link[data-view="reports"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'reports' && !!document.querySelector('.rpt-sources tbody tr.dt-row'), { message: 'back' });
      await page.waitFor(() => /Reports read at/.test(document.querySelector('.page-kept:not([hidden]) .kept-note')?.textContent || ''), { message: 'kept note' });
      assertEqual(await page.evaluate(() => !!document.querySelector('.page-kept [data-action="kept-rerun"]')), false, 'nothing to run again');
      assertEqual(await counts(page), before, 'no new request');
    });

    run.group('Phone 375 and 320 px, Turkish / English, light / dark');
    await run.step('the reports at 375 px: no horizontal scroll; TR / EN × light / dark', async () => {
      await page.setViewport({ width: 375, height: 740, mobile: true });
      for (const lang of ['en', 'tr']) {
        await setLangUi(page, lang);
        await waitDmarc(page, 'kept after the language switch');
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await page.evaluate(() => window.scrollTo(0, 0));
          await assertNoHorizontalScroll(page, `reports ${scheme} ${lang}`);
          await shot(page, opts, `reports-dmarc-mobile-${scheme}-${lang}`);
        }
      }
      assertEqual(await text(page, 'h1'), 'DMARC ve TLS raporları', 'Turkish title');
      await page.click('.rpt-tabs [data-tab="tls"]');
      await page.waitFor(() => !!document.querySelector('.rpt-tls-head'), { message: 'TLS tab' });
      await assertNoHorizontalScroll(page, 'reports tls tr dark');
      await shot(page, opts, 'reports-tls-mobile-dark-tr');
      await page.setViewport({ width: 320, height: 640, mobile: true });
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      await assertNoHorizontalScroll(page, 'reports tls 320 tr dark');
      await page.click('.rpt-tabs [data-tab="dmarc"]');
      await waitDmarc(page);
      await assertNoHorizontalScroll(page, 'reports dmarc 320 tr dark');
      const fits = await page.evaluate(() => [...document.querySelectorAll('.rpt-head, .rpt-fix-item, .rpt-sources tbody tr.dt-row')].filter((c) => c.scrollWidth > c.clientWidth + 1).map((c) => c.className));
      assertEqual(fits, [], 'every card fits at 320 px');
      await shot(page, opts, 'reports-dmarc-mobile320-dark-tr');
      await page.setViewport({ width: 1440, height: 900 });
      await page.evaluate(() => window.scrollTo(0, 0));
      await shot(page, opts, 'reports-dmarc-desktop-dark-tr');
      await page.emulateMedia({ 'prefers-color-scheme': 'light' });
      await setLangUi(page, 'en');
    });

    run.group('Forget');
    await run.step('Forget drops the reports: the empty state again, nothing kept', async () => {
      await waitDmarc(page);
      await page.click('[data-action="rpt-forget"]');
      await page.waitFor(() => !!document.querySelector('.rpt-page .tool-empty') && !document.querySelector('.rpt-sources'), { message: 'forgotten' });
      await gotoRoute(page, 'lookup');
      await page.click('a.nav-link[data-view="reports"]');
      await page.waitFor(() => document.documentElement.dataset.view === 'reports' && !!document.querySelector('.rpt-page .tool-empty'), { message: 'still empty' });
      assertEqual(await page.evaluate(() => !!document.querySelector('.page-kept:not([hidden]) .kept-note')), false, 'no kept note');
      await page.evaluate(saveInventory, '');
    });

    run.group('Many files, a hostile archive, Stop');
    await run.step('150 daily reports in one drop are all read; a zip whose entries share one stream is refused at once', async () => {
      const dir = await mkdtemp(path.join(tmpdir(), 'ds-reports-many-'));
      try {
        const files = [];
        for (let day = 0; day < 150; day += 1) {
          const f = path.join(dir, `google.com!example.com!${1790294400 + day * 86400}!${1790294400 + day * 86400 + 86399}.xml`);
          await writeFile(f, dailyReport(day));
          files.push(f);
        }
        const bomb = path.join(dir, 'bomb.zip');
        await writeFile(bomb, overlappingZip(20));
        files.push(bomb);
        await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
        await page.setFileInput('.rpt-load .filedrop-input', files);
        await page.waitFor(() => /^151 files/.test(document.querySelector('[data-role="rpt-files"]')?.textContent || '')
          && document.querySelector('.rpt-spf')?.dataset.state !== 'loading', { timeout: 20000, message: 'every file read' });
        assertEqual(await text(page, '[data-role="rpt-files"]'), '151 files · 150 DMARC reports · 0 TLS reports · 20 could not be used', 'files line');
        assertEqual(await page.evaluate(() => [...new Set([...document.querySelectorAll('.rpt-problem-list li')].map((li) => li.dataset.code))]), ['overlap'], 'the bomb, named');
        assert(/an archive built to unpack far more than it holds/.test(await text(page, '.rpt-problem-list li')), 'why');
        assertEqual(await page.evaluate(() => [...document.querySelectorAll('.toast-warn')].length), 0, 'nothing left out');
        assertEqual(await page.evaluate(() => document.querySelector('.rpt-domain option') ? 'picker' : document.querySelector('.rpt-head .card-title')?.textContent), 'example.com', 'one domain');
        assert(/Reports for example\.com/.test(await text(page, '.rpt-results-title')), 'results title');
        await page.click('[data-action="rpt-forget"]');
        await page.waitFor(() => !!document.querySelector('.rpt-page .tool-empty'), { message: 'forgotten' });
      } finally {
        await rm(dir, { recursive: true, force: true }).catch(() => {});
      }
    });

    await run.step('only files that are no report: the first 200 listed, the rest counted, and Forget drops them', async () => {
      const dir = await mkdtemp(path.join(tmpdir(), 'ds-reports-junk-'));
      const before = await counts(page);
      try {
        const zip = path.join(dir, 'notes.zip');
        await writeFile(zip, storedZip(Array.from({ length: 205 }, (_, i) => [`notes/n${i}.txt`, `note ${i}`])));
        await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
        await page.setFileInput('.rpt-load .filedrop-input', [zip]);
        await page.waitFor(() => /could not be used/.test(document.querySelector('[data-role="rpt-files"]')?.textContent || ''), { message: 'read' });
        assertEqual(await text(page, '[data-role="rpt-files"]'), '1 file · 0 DMARC reports · 0 TLS reports · 205 could not be used', 'files line');
        assertEqual(await text(page, '.rpt-problems summary'), 'What could not be used (205)', 'the list counts them all');
        assertEqual(await page.evaluate(() => document.querySelectorAll('.rpt-problem-list li').length), 200, 'the first 200 listed');
        assertEqual(await text(page, '.rpt-problem-list li:last-child .rpt-problem-path'), 'notes.zip › notes/n199.txt', 'in their order');
        assertEqual(await text(page, '.rpt-problem-more'), '+5 more', 'the rest counted');
        assert(await page.evaluate(() => !!document.querySelector('.rpt-page .tool-empty')), 'no results to show');
        await page.click('[data-action="rpt-forget"]');
        await page.waitFor(() => !document.querySelector('[data-role="rpt-files"]'), { message: 'forgotten' });
        assertEqual(await page.evaluate(() => document.querySelectorAll('.rpt-problem-list li, [data-action="rpt-forget"]').length), 0, 'the list and Forget gone');
        assertEqual(await page.evaluate(() => document.activeElement?.classList.contains('filedrop')), true, 'the focus on the drop zone');
        assertEqual(await counts(page), before, 'nothing sent');
      } finally {
        await rm(dir, { recursive: true, force: true }).catch(() => {});
      }
    });

    await run.step('files dropped while reading wait their turn and the bar counts them; Stop (Esc) before a report was read keeps nothing', async () => {
      // Every DecompressionStream holds its output until the gate opens: the read stays busy for as long as the test needs.
      await page.evaluate(() => {
        const Real = window.DecompressionStream;
        window.__realDecompressionStream = Real;
        window.__gate = new Promise((resolve) => { window.__openGate = resolve; });
        window.DecompressionStream = function Gated(format) {
          const real = new Real(format);
          const hold = new TransformStream({ transform: async (chunk, c) => { await window.__gate; c.enqueue(chunk); } });
          return { writable: real.writable, readable: real.readable.pipeThrough(hold) };
        };
        document.querySelectorAll('.toast').forEach((el) => el.remove());
      });
      const before = await counts(page);
      try {
        await page.setFileInput('.rpt-load .filedrop-input', [MICROSOFT_GZ]);
        await page.waitFor(() => /^0 \/ 1\b/.test(document.querySelector('[data-role="rpt-busy"] .progress-value')?.textContent || ''), { message: 'reading, 0 of 1' });
        assertEqual(await text(page, '[data-role="rpt-busy"] .progress-label'), 'Reading the reports…', 'the bar');
        await page.setFileInput('.rpt-load .filedrop-input', [MAILBOX]);
        await page.waitFor(() => /^0 \/ 2\b/.test(document.querySelector('[data-role="rpt-busy"] .progress-value')?.textContent || ''), { message: 'the second drop joins: 0 of 2' });
        await page.evaluate(() => document.querySelector('.rpt-load .filedrop').focus());
        await page.press('Escape');
        await page.waitFor(() => !document.querySelector('[data-role="rpt-busy"]'), { message: 'stopped' });
        const toastText = await page.waitFor(() => document.querySelector('.toast-info .toast-message')?.textContent, { message: 'toast' });
        assertEqual(toastText, 'Reading stopped. No report had been read yet.', 'the toast');
        assert(await page.evaluate(() => !!document.querySelector('.rpt-page .tool-empty') && !document.querySelector('[data-role="rpt-files"]')), 'nothing read, nothing kept');
        assertEqual(await page.evaluate(() => document.activeElement?.classList.contains('filedrop')), true, 'the focus back on the drop zone');
        assertEqual(await counts(page), before, 'nothing sent');
      } finally {
        await page.evaluate(() => {
          window.__openGate();
          window.DecompressionStream = window.__realDecompressionStream;
        });
      }
      // The reader works again: the same file is read in full.
      await page.setFileInput('.rpt-load .filedrop-input', [MICROSOFT_GZ]);
      await waitDmarc(page, 'read after the stop');
      assertEqual(await text(page, '[data-role="rpt-files"]'), '1 file · 1 DMARC report · 0 TLS reports', 'files line');
      await page.click('[data-action="rpt-forget"]');
      await page.waitFor(() => !!document.querySelector('.rpt-page .tool-empty'), { message: 'forgotten' });
    });

    await run.step('a zipped mailbox folder: the bar counts the reports inside it, Stop (Esc) acts between them and keeps the reports read before it', async () => {
      const dir = await mkdtemp(path.join(tmpdir(), 'ds-reports-zip-'));
      const n = 300;
      const before = await counts(page);
      try {
        const zip = path.join(dir, 'mailbox.zip');
        await writeFile(zip, storedZip(Array.from({ length: n }, (_, day) => [`dmarc/google.com!example.com!${1790294400 + day * 86400}.xml`, dailyReport(day)])));
        // Every report decodes slowly (10 ms, a busy page): the archive takes seconds to read, so the Stop lands in its middle.
        await page.evaluate(() => {
          const real = TextDecoder.prototype.decode;
          window.__realDecode = real;
          window.__decodes = 0;
          TextDecoder.prototype.decode = function slowDecode(input, options) {
            if (input && input.byteLength > 400) {
              window.__decodes += 1;
              const until = performance.now() + 10;
              while (performance.now() < until) { /* a long report */ }
            }
            return real.call(this, input, options);
          };
          document.querySelectorAll('.toast').forEach((el) => el.remove());
        });
        try {
          await page.setFileInput('.rpt-load .filedrop-input', [zip]);
          const bar = await page.waitFor((total) => {
            const m = /^(\d+) \/ (\d+)\b/.exec(document.querySelector('[data-role="rpt-busy"] .progress-value')?.textContent || '');
            return m && Number(m[1]) >= 5 && Number(m[2]) === total ? m[0] : null;
          }, { args: [n], message: 'the bar counts the reports inside the archive' });
          assert(Number(bar.split(' / ')[0]) < n, bar);
          await page.evaluate(() => document.querySelector('.rpt-load .filedrop').focus());
          await page.press('Escape');
          await page.waitFor(() => !document.querySelector('[data-role="rpt-busy"]'), { message: 'stopped' });
          const decoded = await page.evaluate(() => window.__decodes);
          assert(decoded < n, `stopped in the middle of the archive, not after it: ${decoded} of ${n} reports read`);
          const toastText = await page.waitFor(() => document.querySelector('.toast-info .toast-message')?.textContent, { message: 'the toast' });
          const said = /^Reading stopped\. The ([\d,]+) reports read before it are kept\.$/.exec(toastText);
          assert(said, `the toast says how many reports were kept: ${toastText}`);
          const kept = Number(said[1].replace(/,/g, ''));
          assert(kept >= 5 && kept <= decoded, `kept ${kept}, read ${decoded}`);
          assertEqual(await text(page, '[data-role="rpt-files"]'), `1 file · ${kept} DMARC reports · 0 TLS reports`, 'the reports read before the Stop are kept');
          assertEqual(await text(page, '.rpt-results-title'), 'Reports for example.com', 'and shown');
          assertEqual(await page.evaluate(() => document.activeElement?.classList.contains('filedrop')), true, 'the focus back on the drop zone');
          assertEqual((await counts(page)).ip, before.ip, 'no IP data asked');
          await waitDmarc(page, 'the kept reports classified');
          await page.click('[data-action="rpt-forget"]');
          await page.waitFor(() => !!document.querySelector('.rpt-page .tool-empty'), { message: 'forgotten' });
        } finally {
          await page.evaluate(() => { TextDecoder.prototype.decode = window.__realDecode; });
        }
      } finally {
        await rm(dir, { recursive: true, force: true }).catch(() => {});
      }
    });

    await run.step('a switch to another workspace while files are read names the read first; Cancel keeps reading', async () => {
      const dir = await mkdtemp(path.join(tmpdir(), 'ds-reports-switch-'));
      const otherId = await page.evaluate(() => import('./assets/js/state.js').then(async ({ state }) => (await state.createWorkspace('Reports e2e')).meta.id));
      try {
        const zip = path.join(dir, 'mailbox.zip');
        await writeFile(zip, storedZip(Array.from({ length: 500 }, (_, day) => [`dmarc/google.com!example.com!${1790294400 + day * 86400}.xml`, dailyReport(day)])));
        // Every report decodes slowly (10 ms): the read (5 s) is still going while the switch is asked.
        await page.evaluate(() => {
          const real = TextDecoder.prototype.decode;
          window.__realDecode = real;
          TextDecoder.prototype.decode = function slowDecode(input, options) {
            if (input && input.byteLength > 400) {
              const until = performance.now() + 10;
              while (performance.now() < until) { /* a long report */ }
            }
            return real.call(this, input, options);
          };
          document.querySelectorAll('.toast').forEach((el) => el.remove());
        });
        try {
          await page.setFileInput('.rpt-load .filedrop-input', [zip]);
          await page.waitFor(() => {
            const m = /^(\d+) \/ 500\b/.exec(document.querySelector('[data-role="rpt-busy"] .progress-value')?.textContent || '');
            return !!m && Number(m[1]) >= 2;
          }, { message: 'reading the archive' });
          await page.click('[data-control="workspace"]');
          await page.waitFor(() => document.querySelector('dialog.ws-modal[open] .ws-list li'), { message: 'workspaces dialog', timeout: 15000 });
          await page.click(`dialog.ws-modal li[data-ws-id="${otherId}"] [data-action="ws-switch"]`);
          const message = await page.waitFor(() => {
            const d = [...document.querySelectorAll('dialog.modal-sm[open]')].pop();
            return d ? d.querySelector('.modal-message').textContent : false;
          }, { message: 'confirmation' });
          assert(/^Still running here: Reading DMARC & TLS report files\. Switching to “Reports e2e” stops the work in progress/.test(message), message);
          await page.evaluate(() => [...document.querySelectorAll('dialog.modal-sm[open]')].pop().querySelector('.modal-foot .btn').click());
          await page.waitFor(() => !document.querySelector('dialog.modal-sm[open]'), { message: 'confirmation closed' });
          await page.click('dialog.ws-modal[open] .modal-head .btn');
          await page.waitFor(() => !document.querySelector('dialog.ws-modal'), { message: 'dialog closed' });
          assert(await page.evaluate(() => !!document.querySelector('[data-role="rpt-busy"]')), 'still reading after Cancel, in this workspace');
          await page.click('[data-action="rpt-stop"]');
          await page.waitFor(() => !document.querySelector('[data-role="rpt-busy"]'), { message: 'stopped' });
          assertEqual(await page.evaluate(() => import('./assets/js/ui/jobs.js').then(({ runningWork }) => runningWork())), [], 'nothing read now: nothing named');
        } finally {
          await page.evaluate(() => { TextDecoder.prototype.decode = window.__realDecode; });
        }
        await waitDmarc(page, 'the kept reports classified');
        await page.click('[data-action="rpt-forget"]');
        await page.waitFor(() => !!document.querySelector('.rpt-page .tool-empty'), { message: 'forgotten' });
      } finally {
        await page.evaluate((id) => import('./assets/js/state.js').then(({ state }) => state.deleteWorkspace(id)), otherId);
        await rm(dir, { recursive: true, force: true }).catch(() => {});
      }
    });

    await run.step('an SPF record with a syntax error: receivers get a permanent error, said on the SPF line, in a note and in the verdict', async () => {
      const dir = await mkdtemp(path.join(tmpdir(), 'ds-reports-spf-'));
      const good = ZONE['example.com'].TXT;
      try {
        const file = path.join(dir, 'google.com!example.com!spf-only.xml');
        await writeFile(file, dailyReport(200, { dkim: 'fail' }));
        await page.evaluate(() => { window.__zone['example.com'].TXT = [['v=spf1 ip4:203.0.113.25 mx include:_spf.example.com foo:bar ~all']]; });
        await page.setFileInput('.rpt-load .filedrop-input', [file]);
        await waitDmarc(page);
        // The resolver's cache may still hold the record read before: Check again asks past it.
        await page.click('[data-action="rpt-spf-retry"]');
        await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.error === 'syntax', { message: 'the SPF line says it errs' });
        assert(/checked .* · a permanent error for receivers: a syntax error/.test(await text(page, '.rpt-spf')), await text(page, '.rpt-spf'));
        assertEqual(await page.evaluate(() => document.querySelector('.rpt-verdict').dataset.verdict), 'spf-broken', 'verdict');
        assert(/Not ready for p=reject: the SPF record gives a permanent error/.test(await text(page, '.rpt-verdict')), await text(page, '.rpt-verdict'));
        assertEqual(Object.fromEntries(await tableClasses(page)), { '203.0.113.25': 'yours' }, 'still your server');
        const item = await text(page, '.rpt-fix-item[data-ip="203.0.113.25"]');
        assert(/Listed by your SPF \(ip4:203\.0\.113\.25\), but receivers get a permanent error from the record first/.test(item)
          && /10 of 10 messages passed through SPF alone/.test(item)
          && /Repair the SPF record of example\.com: receivers get a permanent error from it \(a syntax error\)/.test(item), item);
        assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-fix-item [data-fix]')].map((f) => f.dataset.fix)), ['spf-permerror', 'dkim-fix'], 'fixes: the record, then its DKIM signature that does not verify');
        assert(/Receivers get a permanent error from the current SPF of example\.com for 1 sending address: a syntax error/.test(await text(page, '.rpt-notes [data-note="spf-permerror"]')), 'the note');
        // A later report publishes p=reject: that mail is refused now, an error, never "not ready yet".
        const later = path.join(dir, 'google.com!example.com!spf-reject.xml');
        await writeFile(later, dailyReport(201, { dkim: 'fail', p: 'reject' }));
        await page.setFileInput('.rpt-load .filedrop-input', [later]);
        await page.waitFor(() => document.querySelector('.rpt-verdict')?.dataset.look === 'enforcedSpfBroken', { message: 'p=reject in force' });
        assert(/p=reject is in force, and the SPF record now gives a permanent error/.test(await text(page, '.rpt-verdict'))
          && /20 messages in these reports/.test(await text(page, '.rpt-verdict')), await text(page, '.rpt-verdict'));
        assertEqual(await page.evaluate(() => [document.querySelector('.rpt-verdict').dataset.verdict, document.querySelector('.rpt-verdict').classList.contains('alert-error')]),
          ['spf-broken', true], 'an error');
      } finally {
        await page.evaluate((txt) => { window.__zone['example.com'].TXT = txt; }, good);
        await rm(dir, { recursive: true, force: true }).catch(() => {});
      }
      await page.click('[data-action="rpt-forget"]');
      await page.waitFor(() => !!document.querySelector('.rpt-page .tool-empty'), { message: 'forgotten' });
    });

    run.group('Offline');
    await run.step('offline: a dropped .xml.gz is read and classified from the reports alone, the SPF line says so, nothing is sent; online, Check again', async () => {
      const offline = (on) => page.send('Network.emulateNetworkConditions', { offline: on, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
      const before = await counts(page);
      await offline(true);
      try {
        await page.waitFor(() => navigator.onLine === false, { message: 'offline' });
        await page.setFileInput('.rpt-load .filedrop-input', [MICROSOFT_GZ]);
        await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'offline', { message: 'SPF not checked' });
        assert(/not checked: the browser is offline/.test(await text(page, '.rpt-spf')), await text(page, '.rpt-spf'));
        assert(await page.evaluate(() => !!document.querySelector('.rpt-notes [data-note="spf-unknown"]')), 'the note');
        // No server list any more, no SPF: what passed SPF aligned in the report counts as yours, the rest is unknown.
        assertEqual(Object.fromEntries(await tableClasses(page)), {
          '198.51.100.10': 'yours', '203.0.113.25': 'yours', '203.0.113.99': 'unknown', '192.0.2.200': 'unknown'
        }, 'classes from the report');
        assertEqual(await counts(page), before, 'nothing sent');
      } finally {
        await offline(false);
      }
      await page.waitFor(() => navigator.onLine === true, { message: 'online' });
      await page.click('[data-action="rpt-spf-retry"]');
      await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'ok', { message: 'checked online' });
      await frames(page);
      const cls = Object.fromEntries(await tableClasses(page));
      assertEqual([cls['198.51.100.10'], cls['203.0.113.25']], ['third-party', 'yours'], 'the SPF tells them apart');
      await page.click('[data-action="rpt-forget"]');
      await page.waitFor(() => !!document.querySelector('.rpt-page .tool-empty'), { message: 'forgotten' });
    });

    run.group('Senders named by service');
    const sendersDir = await mkdtemp(path.join(tmpdir(), 'ds-reports-senders-'));
    try {
      await run.step('the sources are named from the report and the SPF with no lookup; Identify senders asks only for the rest', async () => {
        const file = path.join(sendersDir, 'google.com!example.org!1790294400!1790899199.xml');
        await writeFile(file, sendersReport());
        await page.evaluate(() => {
          // example.org's SPF authorizes Google Workspace's (documentation) range; three addresses get reverse names.
          Object.assign(window.__zone, {
            'example.org': { TXT: [['v=spf1 include:_spf.google.com ~all']] },
            '_spf.google.com': { TXT: [['v=spf1 ip4:203.0.113.32/27 ~all']] },
            '70.2.0.192.in-addr.arpa': { PTR: ['mail-yw1-f70.google.com'] },
            'mail-yw1-f70.google.com': { A: ['192.0.2.70'] },
            '71.100.51.198.in-addr.arpa': { PTR: ['c-198-51-100-71.hsd1.ca.comcast.net'] }
          });
          window.__dnsLog = [];
          window.__ipLog = [];
          document.querySelectorAll('.toast').forEach((el) => el.remove());
        });
        await page.setFileInput('.rpt-load .filedrop-input', [file]);
        await waitDmarc(page);
        await page.waitFor(() => document.querySelector('.rpt-spf')?.dataset.state === 'ok', { message: 'example.org\'s SPF' });
        await frames(page);
        assertEqual(await tableServices(page), {
          '203.0.113.40': 'Google Workspace|spf-include',
          '198.51.100.61': 'SendGrid|dkim',
          '192.0.2.62': 'Postmark|return-path',
          '192.0.2.70': '—', '198.51.100.71': '—', '203.0.113.72': '—', '10.1.2.3': '—'
        }, 'named from the report and the SPF');
        assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')]
          .filter((tr) => !tr.querySelector('.rpt-addr .rpt-ip') || !tr.querySelector('.rpt-addr .rpt-svc, .rpt-addr .rpt-svc-none')).length), 0,
        'the service under each address, in the same cell: no column of its own');
        assertEqual(await page.evaluate(() => document.querySelector('.rpt-sources tbody tr.dt-row .rpt-ip[data-ip="10.1.2.3"]')?.closest('tr').querySelector('.rpt-svc-none')?.title),
          'A private address: Identify senders leaves it out.', 'a source Identify leaves out says so');
        assertEqual(await page.evaluate(() => [...new Set(window.__dnsLog.map((q) => `${q.name}|${q.type}`))].sort()), ['_spf.google.com|TXT', 'example.org|TXT'], 'only the SPF tree: nothing about the senders');
        assertEqual(await text(page, '[data-action="rpt-identify"]'), 'Identify 3 senders', 'the unnamed public sources');
        await shot(page, opts, 'reports-senders-desktop-light-en');
        await page.click('[data-action="rpt-identify"]');
        await page.waitFor(() => /Example Hosting Ltd/.test([...document.querySelectorAll('.rpt-sources tbody tr.dt-row')]
          .find((tr) => tr.querySelector('.rpt-ip')?.dataset.ip === '203.0.113.72')?.querySelector('.rpt-svc')?.textContent || '')
          && document.querySelector('[data-action="rpt-identify"]')?.hidden, { timeout: 20000, message: 'every unnamed sender looked up' });
        await frames(page);
        const named = await tableServices(page);
        assertEqual([named['192.0.2.70'], named['198.51.100.71'], named['203.0.113.72'], named['10.1.2.3']],
          ['Google (Including Gmail and Google Workspace)|ptr', 'ISP or home network|isp', 'Example Hosting Ltd|asn', '—'], 'named by the reverse DNS, the ISP list, the network');
        const asked = await page.evaluate(() => window.__dnsLog.filter((q) => q.type === 'PTR').map((q) => q.name));
        assertEqual([...new Set(asked)].sort(), ['70.2.0.192.in-addr.arpa', '71.100.51.198.in-addr.arpa', '72.113.0.203.in-addr.arpa'], 'reverse DNS of the three unnamed public sources only');
        const forward = await page.evaluate(() => [...new Set(window.__dnsLog.filter((q) => q.type === 'A').map((q) => q.name))].sort());
        assertEqual(forward, ['c-198-51-100-71.hsd1.ca.comcast.net', 'mail-yw1-f70.google.com'], 'each name found checked forward');
        assertEqual((await page.evaluate(() => window.__ipLog)).sort(), ['maxmind-geo-lite 203.0.113.72', 'prefix-overview 203.0.113.72'], 'the network of the one still unnamed');
        const cell = await page.evaluate(() => [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')].map((tr) => tr.querySelector('.rpt-svc'))
          .filter(Boolean).map((s) => [s.dataset.via, s.dataset.confidence, s.querySelector('.rpt-svc-meta').textContent]));
        assert(cell.some(([via, conf, meta]) => via === 'isp' && conf === 'low' && meta === 'comcast.net · reverse DNS, not confirmed'), JSON.stringify(cell));
        assert(cell.some(([via, conf, meta]) => via === 'ptr' && conf === 'medium' && meta === 'Mailbox provider · reverse DNS'), JSON.stringify(cell));
      });

      await run.step('a source\'s details say how it was named and how to align the service; the sources CSV has the service', async () => {
        await page.evaluate(() => [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')].find((r) => r.querySelector('.rpt-ip')?.dataset.ip === '198.51.100.61')
          .querySelector('.dt-expand-btn').click());
        await page.waitFor(() => !!document.querySelector('.rpt-sources .rpt-details .rpt-guide'), { message: 'details' });
        const det = await text(page, '.rpt-sources .rpt-details');
        assert(/SendGrid — Transactional email/.test(det) && /Named from its DKIM signature, which verified: d=sendgrid\.net/.test(det)
          && /SendGrid: authenticate example\.org under Settings › Sender Authentication/.test(det), det);
        await page.click('.rpt-sources [data-export="csv"]');
        await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'download' });
        const [csv] = await takeDownloads(page);
        const { DMARC_CSV_COLUMNS } = await import('../../assets/js/lib/dmarcreport.js');
        assertEqual(csvHeader(csv.text), [...DMARC_CSV_COLUMNS], 'CSV header');
        const line = csv.text.split(/\r?\n/).find((l) => l.includes('198.51.100.61'));
        assert(/,SendGrid,transactional,dkim,high,/.test(line), line);
      });

      await run.step('By service: one row per service with totals, the unnamed last; a group\'s guide and addresses; the class tiles apply', async () => {
        await page.click('.rpt-view .seg-btn[data-value="service"]');
        await page.waitFor(() => document.querySelectorAll('.rpt-services tbody tr.dt-row').length > 0, { message: 'the service view' });
        assertEqual(await page.evaluate(() => document.activeElement?.matches('.rpt-view .seg-btn[data-value="service"]')), true, 'the focus stays on the switch');
        assertEqual(await tableGroups(page), [
          ['svc:google', 'Google Workspace', '1'],
          ['svc:sendgrid', 'SendGrid', '1'],
          ['svc:postmark', 'Postmark', '1'],
          ['name:google (including gmail and google workspace)', 'Google (Including Gmail and Google Workspace)', '1'],
          ['isp', 'ISP or home networks', '1'],
          ['net:example hosting ltd', 'Example Hosting Ltd', '1'],
          ['unnamed', 'Not identified', '1']
        ], 'groups, the most mail first, the unnamed last');
        assertEqual(await text(page, '[data-role="rpt-grp-totals"]'), '6 services · 7 addresses · 89 messages · 1 address not identified (2 messages)', 'totals');
        await page.evaluate(() => [...document.querySelectorAll('.rpt-services tbody tr.dt-row')].find((r) => r.querySelector('[data-group="svc:postmark"]'))
          .querySelector('.dt-expand-btn').click());
        await page.waitFor(() => !!document.querySelector('.rpt-services .rpt-details'), { message: 'group details' });
        const det = await text(page, '.rpt-services .rpt-details');
        assert(/Postmark: verify example\.org/.test(det) && /pm\.mtasv\.net/.test(det) && /192\.0\.2\.62/.test(det) && /Named from\s*return-path/.test(det), det);
        await shot(page, opts, 'reports-services-desktop-light-en');
        await page.click('.rpt-services [data-export="csv"]');
        await page.waitFor(() => (window.__downloads || []).length === 1, { message: 'services download' });
        const [csv] = await takeDownloads(page);
        assert(/^dmarc-services-example\.org-.*\.csv$/.test(csv.name), csv.name);
        const { SERVICE_CSV_COLUMNS } = await import('../../assets/js/lib/senders.js');
        assertEqual(csvHeader(csv.text), [...SERVICE_CSV_COLUMNS], 'services CSV header');
        await setClass(page, 'unknown');
        await page.waitFor(() => document.querySelectorAll('.rpt-services tbody tr.dt-row').length === 4, { message: 'the unknown senders\' services' });
        assertEqual((await tableGroups(page)).map(([k]) => k), ['name:google (including gmail and google workspace)', 'isp', 'net:example hosting ltd', 'unnamed'], 'filtered');
        await setClass(page, '');
        await page.waitFor(() => document.querySelectorAll('.rpt-services tbody tr.dt-row').length === 7, { message: 'every class again' });
      });

      await run.step('the service view at 375 and 320 px in Turkish, light and dark: no horizontal scroll', async () => {
        await page.setViewport({ width: 375, height: 740, mobile: true });
        await setLangUi(page, 'tr');
        await page.waitFor(() => document.querySelectorAll('.rpt-services tbody tr.dt-row').length === 7, { message: 'kept after the language switch' });
        assertEqual(await page.evaluate(() => [...document.querySelectorAll('.rpt-view .seg-btn')].map((b) => b.textContent)), ['Adrese göre', 'Hizmete göre'], 'the switch in Turkish');
        assertEqual((await tableGroups(page)).map(([, name]) => name).slice(-3), ['İSS’ler ya da ev ağları', 'Example Hosting Ltd', 'Tanımlanamadı'], 'groups in Turkish');
        assertEqual(await text(page, '[data-role="rpt-grp-totals"]'), '6 hizmet · 7 adres · 89 e-posta · 1 adres tanımlanamadı (2 e-posta)', 'totals in Turkish');
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({ 'prefers-color-scheme': scheme });
          await page.evaluate(() => document.querySelector('.rpt-sources-section').scrollIntoView());
          await assertNoHorizontalScroll(page, `services ${scheme} tr`);
          await shot(page, opts, `reports-services-mobile-${scheme}-tr`);
        }
        await page.setViewport({ width: 320, height: 640, mobile: true });
        await frames(page);
        await assertNoHorizontalScroll(page, 'services 320 tr dark');
        await page.click('.rpt-view .seg-btn[data-value="address"]');
        await page.waitFor(() => document.querySelectorAll('.rpt-sources tbody tr.dt-row').length === 7, { message: 'the address view' });
        await assertNoHorizontalScroll(page, 'addresses 320 tr dark');
        const fits = await page.evaluate(() => [...document.querySelectorAll('.rpt-sources tbody tr.dt-row')].filter((c) => c.scrollWidth > c.clientWidth + 1).map((c) => c.className));
        assertEqual(fits, [], 'every card fits at 320 px');
        assert(/İşlemsel e-posta · DKIM/.test(await text(page, '.rpt-sources tbody')), 'the Service column in Turkish');
        await shot(page, opts, 'reports-senders-mobile320-dark-tr');
        await page.setViewport({ width: 1440, height: 900 });
        await page.emulateMedia({ 'prefers-color-scheme': 'light' });
        await setLangUi(page, 'en');
        await page.click('[data-action="rpt-forget"]');
        await page.waitFor(() => !!document.querySelector('.rpt-page .tool-empty'), { message: 'forgotten' });
      });
    } finally {
      await rm(sendersDir, { recursive: true, force: true }).catch(() => {});
    }

    run.group('Quality');
    await run.step('no request ever left the page origin', () => assertEqual(external, [], 'external requests'));
    await run.step('i18n: no missing keys, TR and EN key sets match', () => assertNoMissingKeys(page));
    await run.step('no console errors, exceptions or CSP violations', () => assertClean(page, 'reports', origin));
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
