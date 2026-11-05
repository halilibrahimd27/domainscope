// lib/ipscan.js, lib/ipscansummary.js and views/ipscan.js's pure helpers: the typed range, the
// CLI's reports (tests/fixtures/ipscan/report-*.json are what cli/ip_scan.py writes: its own
// report_to_dict over faked probes), the map with the server list on top, the free addresses to
// suggest, the exports, the Copy summary in both languages, and every string key the view builds
// from a vocabulary. Pure Node: the view is DOM-free at import time. Only documentation ranges
// and private ranges appear.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hasString, setLang } from '../../assets/js/i18n.js';
import { t } from '../../assets/js/i18n.js';
import {
  IPSCAN_FILTERS, IPSCAN_MAX_ADDRESSES, IPSCAN_REASONS, IPSCAN_STATES, RANGE_ISSUES, REPORT_ERRORS,
  addressMap, cliCommand, foldAddresses, freeListText, freeRuns, ipscanCsvRows, ipscanMatches, ipscanSummaryFacts, mergeScanReports,
  parseScanRange, rangeTokens, readScanReport, reportsRange, reservedRole, suggestFree
} from '../../assets/js/lib/ipscan.js';
import { buildIpIndex, parseInventory } from '../../assets/js/lib/inventory.js';
import { buildSummary, renderSummary } from '../../assets/js/lib/summarycore.js';
import { toCsv } from '../../assets/js/lib/export.js';
import {
  GRID_COLUMNS, IPSCAN_TABS, importReports, leadingCells, moveIndex, stateVariant
} from '../../assets/js/views/ipscan.js';

const fixture = (name) => readFileSync(new URL(`./../fixtures/ipscan/${name}`, import.meta.url), 'utf8');
const A = () => readScanReport(fixture('report-a.json'), { name: 'report-a.json' }).report;
const B = () => readScanReport(fixture('report-b.json'), { name: 'report-b.json' }).report;
const byIp = (map) => Object.fromEntries(map.rows.map((r) => [r.ip, r]));

describe('the typed range', () => {
  test('a network marks its network and broadcast address; /31 and /32 none', () => {
    const r = parseScanRange('10.0.5.0/29');
    assert.equal(r.ok, true);
    assert.equal(r.label, '10.0.5.0/29');
    assert.equal(r.total, 8);
    assert.deepEqual([reservedRole('10.0.5.0', r.blocks), reservedRole('10.0.5.7', r.blocks), reservedRole('10.0.5.1', r.blocks)], ['network', 'broadcast', null]);
    const small = parseScanRange('192.0.2.4/31 198.51.100.9/32');
    assert.deepEqual(small.addresses, ['192.0.2.4', '192.0.2.5', '198.51.100.9']);
    assert.ok(small.addresses.every((ip) => reservedRole(ip, small.blocks) === null));
  });

  test('ranges long, short, spaced and with an en dash; comments; overlaps once; the same block once', () => {
    for (const text of ['10.0.5.10-10.0.5.13', '10.0.5.10-13', '10.0.5.10 - 10.0.5.13', '10.0.5.10 – 13']) {
      const r = parseScanRange(text);
      assert.deepEqual(r.addresses, ['10.0.5.10', '10.0.5.11', '10.0.5.12', '10.0.5.13'], text);
      assert.equal(r.blocks[0].label, '10.0.5.10-10.0.5.13');
    }
    assert.deepEqual(rangeTokens('# office\n10.0.5.0/30, 10.0.5.9 # printer\n10.0.5.20 - 21'), ['10.0.5.0/30', '10.0.5.9', '10.0.5.20-21']);
    const r = parseScanRange('10.0.5.4/30 10.0.5.5 10.0.5.6-8 10.0.5.4/30');
    assert.equal(r.blocks.length, 3);
    assert.equal(r.total, 5);
    assert.deepEqual(r.addresses, ['10.0.5.4', '10.0.5.5', '10.0.5.6', '10.0.5.7', '10.0.5.8']);
  });

  test('host bits are said; what is not a range says why; nothing typed is no issue', () => {
    const hb = parseScanRange('192.0.2.77/24');
    assert.equal(hb.ok, true);
    assert.deepEqual(hb.issues.map((i) => [i.code, i.params.cidr]), [['host-bits', '192.0.2.0/24']]);
    const bad = parseScanRange('2001:db8::1 db.example.com 10.0.5.9-3 10.0.5.0/33');
    assert.equal(bad.ok, false);
    assert.deepEqual(bad.issues.map((i) => i.code), ['invalid', 'v6', 'reversed']);
    assert.deepEqual(bad.addresses, []);
    assert.deepEqual(parseScanRange('').issues, []);
    assert.deepEqual(parseScanRange('  # only a comment').issues, []);
  });

  test('more than a /20 is refused, with the first /20 to map instead', () => {
    const r = parseScanRange('10.0.0.0/16');
    assert.equal(r.ok, false);
    assert.deepEqual(r.issues, [{ code: 'too-large', severity: 'error', params: { count: 65536, max: IPSCAN_MAX_ADDRESSES, suggestion: '10.0.0.0/20' } }]);
    assert.equal(parseScanRange('10.0.0.0/20').ok, true);
    assert.equal(parseScanRange('10.0.0.0-10.0.20.255').issues[0].params.suggestion, '', 'a range has no network to cut');
  });
});

describe('the reports of ip_scan.py', () => {
  test('a report of the CLI is read, every row checked', () => {
    const read = readScanReport(fixture('report-a.json'), { name: 'report-a.json' });
    assert.equal(read.ok, true);
    const r = read.report;
    assert.equal(r.name, 'report-a.json');
    assert.equal(r.finishedAt.toISOString(), '2026-11-05T08:30:19.000Z');
    assert.deepEqual(r.targets, ['192.0.2.0/28']);
    assert.deepEqual(r.methods, { icmp: 'dgram', arp: 'proc', ports: [22, 80, 443, 3389], ptr: true, web: true });
    assert.equal(r.rows.size, 16);
    assert.deepEqual(r.rows.get('192.0.2.1'), {
      ip: '192.0.2.1', state: 'used', confirmed: false, reasons: ['icmp', 'tcp-open', 'arp', 'ptr'], reserved: null, rttMs: 0.4,
      open: [22, 443], refused: [], mac: '00:00:5e:00:53:01', onLink: true, ptr: ['gw.example.net'], ptrTemplated: false, web: { 443: 'Apache' }
    });
    assert.equal(r.rows.get('192.0.2.12').ptrTemplated, true);
    assert.equal(r.rows.get('192.0.2.12').state, 'free');
  });

  test('nothing of the file is trusted: hostile values are dropped or cleaned', () => {
    const doc = {
      schema: 'domainscope.ip-scan/1',
      targets: ['10.0.5.0/30', 7, 'x‮'],
      results: [
        { ip: '10.0.5.1', state: 'used', reasons: ['icmp', 'evil'], rttMs: -3, open: [22, 0, 70000, '80', 22], mac: 'not-a-mac', ptr: ['ok.example.net', 'bad name', 'x'.repeat(300)],
          web: { 80: 'nginx\u0007‮', abc: 'x', 99999: 'y' }, confirmed: true, onLink: 'yes' },
        { ip: '2001:db8::1', state: 'used' },
        { ip: '10.0.5.2', state: 'owned' },
        { ip: '10.0.5.1', state: 'free' },
        null, 'row'
      ]
    };
    const read = readScanReport(JSON.stringify(doc));
    assert.equal(read.ok, true);
    assert.deepEqual([...read.report.rows.keys()], ['10.0.5.1'], 'IPv6, an unknown state and a second row of an address are dropped');
    const row = read.report.rows.get('10.0.5.1');
    assert.deepEqual([row.reasons, row.rttMs, row.open, row.mac, row.ptr, row.web, row.confirmed, row.onLink],
      [['icmp'], null, [22], null, ['ok.example.net'], { 80: 'nginx' }, false, null]);
    assert.deepEqual(read.report.targets, ['10.0.5.0/30', 'x']);
  });

  test('what is not a report says why', () => {
    assert.deepEqual(readScanReport('x'.repeat(16 * 1048576 + 1)), { ok: false, error: 'too-large' });
    assert.deepEqual(readScanReport('{nope'), { ok: false, error: 'not-json' });
    assert.deepEqual(readScanReport(JSON.stringify({ tool: 'ssl_origin_scan' })), { ok: false, error: 'not-report' });
    assert.deepEqual(readScanReport('[]'), { ok: false, error: 'not-report' });
    assert.deepEqual(readScanReport(JSON.stringify({ schema: 'domainscope.ip-scan/2' })), { ok: false, error: 'version', detail: '2' });
    assert.deepEqual(readScanReport(JSON.stringify({ schema: 'domainscope.ip-scan/1', results: [] })), { ok: false, error: 'no-results' });
    assert.equal(readScanReport(`﻿${fixture('report-b.json')}`).ok, true, 'a BOM is fine');
    assert.deepEqual(REPORT_ERRORS, ['too-large', 'not-json', 'not-report', 'version', 'no-results']);
  });

  test('several reports: the newest answers for an address; the view keeps one copy of a scan', () => {
    const merged = mergeScanReports([A(), B()]);
    assert.equal(merged.get('192.0.2.9').row.state, 'claimed', 'today: nothing answered, a DNS name');
    assert.equal(merged.get('192.0.2.9').report, 0);
    assert.equal(merged.get('192.0.2.16').row.state, 'used', 'only last week’s report covers it');
    assert.equal(merged.get('192.0.2.16').report, 1);
    const opened = importReports([], [{ name: 'a.json', text: fixture('report-a.json') }, { name: 'copy.json', text: fixture('report-a.json') }, { name: 'x.txt', text: 'hello' }]);
    assert.deepEqual([opened.added, opened.duplicates, opened.errors], [1, ['copy.json'], [{ name: 'x.txt', error: 'not-json' }]]);
  });

  test('the reports’ range when none was typed: their targets', () => {
    assert.equal(reportsRange([A()]), '192.0.2.0/28');
    assert.equal(reportsRange([A(), B()]), '192.0.2.0/28 192.0.2.8-192.0.2.20');
    const noTargets = { ...A(), targets: [] };
    assert.equal(reportsRange([noTargets]), '192.0.2.0-192.0.2.15');
    assert.deepEqual(foldAddresses(['10.0.5.4', '10.0.5.2', '10.0.5.3', '10.0.5.9', '10.0.6.0', '10.0.5.255', 'x', '2001:db8::1']),
      ['10.0.5.2-10.0.5.4', '10.0.5.9', '10.0.5.255-10.0.6.0']);
  });
});

describe('the map', () => {
  const range = parseScanRange('192.0.2.0/28');

  test('without a scan: the server list claims its addresses, the rest is not scanned', () => {
    const index = buildIpIndex(parseInventory('db1 192.0.2.3\nweb 192.0.2.2\nvip-holder 192.0.2.40').servers);
    const map = addressMap({ range, index });
    const r = byIp(map);
    assert.deepEqual([r['192.0.2.3'].state, r['192.0.2.3'].reasons, r['192.0.2.3'].servers], ['claimed', ['inventory'], [{ id: 'db1', name: 'db1' }]]);
    assert.equal(r['192.0.2.4'].state, 'unscanned');
    assert.equal(r['192.0.2.0'].state, 'reserved');
    assert.deepEqual(map.counts, { total: 16, freeConfirmed: 0, used: 0, claimed: 2, free: 0, reserved: 2, unscanned: 12 });
    assert.equal(map.scanned, 0);
  });

  test('with the scans and the server list: every state, its reasons and evidence', () => {
    const index = buildIpIndex(parseInventory('db1 192.0.2.3\nweb1 192.0.2.2').servers);
    const map = addressMap({ range, reports: [A(), B()], index });
    const r = byIp(map);
    assert.deepEqual([r['192.0.2.1'].state, r['192.0.2.1'].reasons], ['used', ['icmp', 'tcp-open', 'arp', 'ptr']]);
    assert.deepEqual([r['192.0.2.2'].state, r['192.0.2.2'].reasons, r['192.0.2.2'].servers.map((s) => s.name)], ['used', ['icmp', 'tcp-open', 'tcp-refused', 'arp', 'ptr', 'inventory'], ['web1']]);
    assert.deepEqual([r['192.0.2.3'].state, r['192.0.2.3'].reasons, r['192.0.2.3'].confirmed], ['claimed', ['inventory'], false], 'silent, but the server list names it: never free');
    assert.deepEqual([r['192.0.2.4'].state, r['192.0.2.4'].confirmed, r['192.0.2.4'].reasons], ['free', true, ['arp-incomplete']]);
    assert.deepEqual([r['192.0.2.6'].state, r['192.0.2.6'].reasons], ['used', ['arp']]);
    assert.deepEqual([r['192.0.2.9'].state, r['192.0.2.9'].names], ['claimed', ['old-db.example.net']]);
    assert.deepEqual([r['192.0.2.11'].state, r['192.0.2.11'].reasons], ['used', ['tcp-refused']]);
    assert.deepEqual([r['192.0.2.12'].state, r['192.0.2.12'].confirmed, r['192.0.2.12'].names], ['free', false, []], 'a provider template claims nothing');
    assert.deepEqual([r['192.0.2.15'].state, r['192.0.2.15'].reserved], ['reserved', 'broadcast']);
    assert.deepEqual(map.counts, { total: 16, freeConfirmed: 6, used: 5, claimed: 2, free: 7, reserved: 2, unscanned: 0 });
    assert.equal(map.scanned, 16);
    assert.equal(map.outside, 5, 'report B’s .16–.20');
    assert.deepEqual(map.groups.map((g) => [g.label, g.rows.length]), [['192.0.2.0/24', 16]]);
    assert.equal(r['192.0.2.9'].report, 0);
  });

  test('a range wider than the scans: the rest is not scanned; groups by /24', () => {
    const map = addressMap({ range: parseScanRange('192.0.2.0/28 10.0.5.250-10.0.6.3'), reports: [A()] });
    assert.deepEqual(map.groups.map((g) => [g.label, g.rows.length]), [['192.0.2.0/24', 16], ['10.0.5.0/24', 6], ['10.0.6.0/24', 4]]);
    assert.equal(map.counts.unscanned, 10);
  });

  test('the filters', () => {
    const map = addressMap({ range, reports: [A()] });
    const count = (f) => map.rows.filter((row) => ipscanMatches(row, f)).length;
    assert.deepEqual(IPSCAN_FILTERS.map((f) => [f, count(f)]), [
      ['all', 16], ['taken', 6], ['used', 5], ['claimed', 1], ['free', 8], ['confirmed', 7], ['unscanned', 0], ['reserved', 2]
    ]);
  });

  test('the addresses to suggest: confirmed first; the free runs, longest first', () => {
    const map = addressMap({ range, reports: [A()] });
    assert.deepEqual(suggestFree(map.rows, { count: 9 }).map((r) => r.ip),
      ['192.0.2.3', '192.0.2.4', '192.0.2.5', '192.0.2.7', '192.0.2.8', '192.0.2.13', '192.0.2.14', '192.0.2.12']);
    assert.deepEqual(freeRuns(map.rows, { min: 2 }), [
      { first: '192.0.2.3', last: '192.0.2.5', length: 3, confirmed: 3 },
      { first: '192.0.2.7', last: '192.0.2.8', length: 2, confirmed: 2 },
      { first: '192.0.2.12', last: '192.0.2.14', length: 3, confirmed: 2 }
    ].sort((a, b) => b.length - a.length));
    assert.deepEqual(suggestFree([], {}), []);
  });

  test('the exports: CSV rows (spreadsheet-safe through lib/export.js), the free list, the command', () => {
    const map = addressMap({ range, reports: [A()], index: buildIpIndex(parseInventory('app1 192.0.2.14').servers) });
    const rows = ipscanCsvRows(map.rows);
    assert.deepEqual(rows.find((r) => r.ip === '192.0.2.1'), {
      ip: '192.0.2.1', state: 'used', confirmed: '', reasons: 'icmp tcp-open arp ptr', ping_ms: 0.4, open_ports: '22 443', refused_ports: '',
      mac: '00:00:5e:00:53:01', ptr: 'gw.example.net', web: '443=Apache', servers: '', reserved: ''
    });
    assert.deepEqual([rows.find((r) => r.ip === '192.0.2.14').state, rows.find((r) => r.ip === '192.0.2.14').servers], ['claimed', 'app1']);
    const csv = toCsv(rows, Object.keys(rows[0]).map((key) => ({ key, header: key })));
    assert.ok(csv.startsWith('\uFEFFip,state,confirmed,reasons,ping_ms'));
    assert.equal(freeListText(map.rows, { confirmedOnly: true }), '192.0.2.3\n192.0.2.4\n192.0.2.5\n192.0.2.7\n192.0.2.8\n192.0.2.13\n');
    assert.equal(freeListText([]), '');
    assert.equal(cliCommand(range), 'python3 ip_scan.py 192.0.2.0/28 --json scan.json');
    assert.equal(cliCommand(parseScanRange('10.0.5.10-20 10.0.6.0/30'), { file: 'x.json' }), 'python3 ip_scan.py 10.0.5.10-10.0.5.20 10.0.6.0/30 --json x.json');
    assert.equal(cliCommand(null), 'python3 ip_scan.py 10.0.5.0/24 --json scan.json');
  });
});

describe('the view’s helpers', () => {
  test('a column is the last octet mod 16; the arrow keys move in the grid', () => {
    assert.equal(GRID_COLUMNS, 16);
    assert.deepEqual([leadingCells(0), leadingCells(10), leadingCells(16), leadingCells(255)], [0, 10, 0, 15]);
    // 256 cells from .0
    assert.deepEqual(['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp', 'Home', 'End', 'x'].map((k) => moveIndex(k, 17, 256)), [18, 16, 33, 1, 16, 31, null]);
    assert.equal(moveIndex('ArrowLeft', 0, 256), 0);
    assert.equal(moveIndex('ArrowDown', 250, 256), 255);
    // a range from .10: the first cell sits in column 11
    assert.equal(moveIndex('Home', 3, 40, 10), 0, 'the first row starts at the first cell');
    assert.equal(moveIndex('End', 3, 40, 10), 5);
    assert.equal(moveIndex('Home', 8, 40, 10), 6);
    assert.deepEqual(IPSCAN_TABS, ['map', 'list']);
    assert.deepEqual(IPSCAN_STATES.map(stateVariant), ['neutral', 'warn', 'ok', 'neutral', 'neutral']);
  });

  test('every string the view builds from a vocabulary exists in both languages', () => {
    const keys = [
      ...IPSCAN_STATES.flatMap((s) => [`ipscan.state.${s}`, `ipscan.stateHelp.${s}`]),
      'ipscan.stateHelp.freeConfirmed', 'ipscan.stateHelp.freeUnconfirmed',
      ...['used', 'claimed', 'free', 'unscanned'].map((s) => `ipscan.st.${s}`),
      ...IPSCAN_FILTERS.map((f) => `ipscan.filter.${f}`),
      ...IPSCAN_REASONS.map((r) => `ipscan.reason.${r}`),
      ...RANGE_ISSUES.map((c) => `ipscan.issue.${c}`),
      ...REPORT_ERRORS.map((e) => `ipscan.error.${e}`),
      ...IPSCAN_TABS.map((x) => `ipscan.tab.${x}`),
      ...['ping', 'ports', 'arp', 'dns', 'servers'].map((c) => `ipscan.check.${c}`),
      'nav.ipscan', 'nav.ipscan.desc', 'nav.ipscan.purpose', 'pal.act.freeIps'
    ];
    // the palette's labels register with its panel
    return import('../../assets/js/ui/palette.js').then(() => {
      for (const key of keys) {
        assert.ok(hasString(key, 'en'), `en ${key}`);
        assert.ok(hasString(key, 'tr'), `tr ${key}`);
      }
    });
  });
});

describe('Copy summary', () => {
  const range = parseScanRange('192.0.2.0/28');

  test('addresses and states only, never a server name, MAC address or DNS name; in both languages', () => {
    const index = buildIpIndex(parseInventory('secret-db 192.0.2.3').servers);
    const map = addressMap({ range, reports: [A()], index });
    const facts = ipscanSummaryFacts({ range, map, reports: [A()] });
    assert.deepEqual(facts.free, ['192.0.2.4-192.0.2.5', '192.0.2.7-192.0.2.8', '192.0.2.12-192.0.2.14']);
    assert.deepEqual(facts.confirmed, ['192.0.2.4-192.0.2.5', '192.0.2.7-192.0.2.8', '192.0.2.13-192.0.2.14']);
    try {
      setLang('en');
      const md = renderSummary(buildSummary('ipscan', facts, { t, lang: 'en', url: 'https://example.org/#/ipscan?range=192.0.2.0/28', now: new Date('2026-11-05T09:00:00Z') }), 'markdown');
      assert.match(md, /IP Scan · `192\.0\.2\.0\/28`/);
      assert.match(md, /16 addresses · 5 used · 2 claimed \(server list or DNS\) · 7 free \(6 confirmed\) · 2 reserved/);
      assert.match(md, /Free, confirmed \(no device answered ARP\):\*\* `192\.0\.2\.4-192\.0\.2\.5`, `192\.0\.2\.7-192\.0\.2\.8`, `192\.0\.2\.13-192\.0\.2\.14`/);
      assert.match(md, /7 taken:\*\* `192\.0\.2\.1` \(used\), `192\.0\.2\.2` \(used\), `192\.0\.2\.3` \(claimed\)/);
      assert.match(md, /scanned 2026-11-05 08:30 UTC/);
      for (const secret of ['secret-db', 'gw.example.net', 'old-db', '00:00:5e', 'nginx', 'Apache']) assert.ok(!md.includes(secret), secret);
      setLang('tr');
      const tr = renderSummary(buildSummary('ipscan', facts, { t, lang: 'tr', url: null, now: new Date('2026-11-05T09:00:00Z') }), 'text');
      assert.match(tr, /IP Tarama · 192\.0\.2\.0\/28/);
      assert.match(tr, /16 adres · 5 dolu · 2 kayıtlı \(sunucu listesi ya da DNS\) · 7 boş \(6 doğrulandı\) · 2 ayrılmış/);
      assert.match(tr, /Tarama raporları tarayıcıda kalır/);
    } finally {
      setLang('en');
    }
  });

  test('without a scan: what the server list claims, and that nothing was scanned', () => {
    const map = addressMap({ range, index: buildIpIndex(parseInventory('db1 192.0.2.3').servers) });
    const facts = ipscanSummaryFacts({ range, map, reports: [] });
    const text = renderSummary(buildSummary('ipscan', facts, { t, lang: 'en', url: null, now: new Date('2026-11-05T09:00:00Z') }), 'text');
    assert.match(text, /16 addresses · 1 claimed \(server list or DNS\) · 2 reserved/);
    assert.match(text, /No scan yet/);
    assert.match(text, /as of 2026-11-05 09:00 UTC/);
  });
});
