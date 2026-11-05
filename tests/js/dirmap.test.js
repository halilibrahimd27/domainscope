// lib/dirmap.js, lib/dirmapsummary.js and views/dirmap.js's pure helpers: the CLI's reports
// (tests/fixtures/dirmap/report-*.json are what cli/dir_scan.py writes), the map, the answered
// paths, the exports, the Copy summary in both languages, and every vocabulary key in both
// languages. Pure Node: the view is DOM-free at import time. Only documentation names appear.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hasString, setLang, t } from '../../assets/js/i18n.js';
import {
  DIRMAP_CSV_COLUMNS, DIRMAP_FILTERS, DIRMAP_VERDICTS, REPORT_ERRORS,
  dirMap, dirmapCsvRows, dirmapMatches, dirmapSummaryFacts, foundPaths, mergeDirReports, readDirReport
} from '../../assets/js/lib/dirmap.js';
import { buildSummary, renderSummary } from '../../assets/js/lib/summarycore.js';
import { toCsv } from '../../assets/js/lib/export.js';
import { importReports, pathRows, verdictVariant } from '../../assets/js/views/dirmap.js';

const fixture = (name) => readFileSync(new URL(`./../fixtures/dirmap/${name}`, import.meta.url), 'utf8');
const A = () => readDirReport(fixture('report-a.json'), { name: 'report-a.json' }).report;
const B = () => readDirReport(fixture('report-b.json'), { name: 'report-b.json' }).report;

describe('the reports of dir_scan.py', () => {
  test('a report is read, every host and result checked', () => {
    const read = readDirReport(fixture('report-a.json'), { name: 'report-a.json' });
    assert.equal(read.ok, true);
    assert.equal(read.report.hosts.length, 2);
    assert.equal(read.report.generatedAt.toISOString(), '2026-11-05T09:30:00.000Z');
    const web = read.report.hosts.find((h) => h.host === 'web.example.com');
    assert.equal(web.baseline.kind, 'hard-404');
    const api = web.paths.find((p) => p.path === '/api');
    assert.deepEqual([api.verdict, api.status, api.contentType, api.length], ['found', 200, 'application/json', 42]);
    assert.equal(web.paths.find((p) => p.path === '/old').verdict, 'redirect');
  });

  test('nothing of the file is trusted: hostile values are dropped or cleaned', () => {
    const doc = {
      schema: 'domainscope.dir-scan/1',
      hosts: [
        { host: 'web.example.com', url: 'https://web.example.com/', results: [
          { path: '/ok', verdict: 'FOUND', status: 200, detail: 'fine' },
          { path: '/ok', verdict: 'FOUND', status: 200 },       // a second row of the path
          { path: '/bad', verdict: 'NONSENSE', status: 200 },    // unknown verdict
          { verdict: 'FOUND', status: 200 },                     // no path
          { path: '/weird', verdict: 'FOUND', status: 9000, detail: 'x‮', location: 'y'.repeat(400) }
        ] },
        { url: 'https://no-host.example.com/' },                 // no host field
        null
      ]
    };
    const read = readDirReport(JSON.stringify(doc));
    assert.equal(read.ok, true);
    assert.equal(read.report.hosts.length, 1);
    const paths = read.report.hosts[0].paths;
    assert.deepEqual(paths.map((p) => p.path), ['/ok', '/weird']);
    assert.equal(paths[0].status, 200);
    assert.equal(paths[1].status, null, 'a status out of range is dropped');
    assert.equal(paths[1].detail.includes('‮'), false, 'bidi stripped');
    assert.ok(paths[1].location.length <= 256);
  });

  test('what is not a report says why', () => {
    assert.deepEqual(readDirReport('x'.repeat(17 * 1048576)), { ok: false, error: 'too-large' });
    assert.deepEqual(readDirReport('{nope'), { ok: false, error: 'not-json' });
    assert.deepEqual(readDirReport(JSON.stringify({ tool: 'content_audit' })), { ok: false, error: 'not-report' });
    assert.deepEqual(readDirReport(JSON.stringify({ schema: 'domainscope.dir-scan/2' })), { ok: false, error: 'version', detail: '2' });
    assert.deepEqual(readDirReport(JSON.stringify({ schema: 'domainscope.dir-scan/1', hosts: [] })), { ok: false, error: 'no-hosts' });
    assert.equal(readDirReport(`﻿${fixture('report-b.json')}`).ok, true, 'a BOM is fine');
    assert.deepEqual(REPORT_ERRORS, ['too-large', 'not-json', 'not-report', 'version', 'no-hosts']);
  });

  test('several reports: the newest answers for a host', () => {
    const merged = mergeDirReports([B(), A()]);
    const web = merged.get('https://web.example.com/');
    assert.equal(web.report, 1, 'report A (index 1) is newer');
    assert.equal(web.host.paths.length, 7, 'report A’s full host, not report B’s single path');
    const opened = importReports([], [{ name: 'a.json', text: fixture('report-a.json') }, { name: 'copy.json', text: fixture('report-a.json') }, { name: 'x.txt', text: 'hi' }]);
    assert.deepEqual([opened.added, opened.duplicates, opened.errors], [1, ['copy.json'], [{ name: 'x.txt', error: 'not-json' }]]);
  });
});

describe('the map', () => {
  test('entries, counts and the found paths', () => {
    const map = dirMap({ reports: [A(), B()] });
    assert.equal(map.hosts, 2);
    assert.equal(map.reachable, 2);
    assert.deepEqual([map.counts.found, map.counts.listing, map.counts.protected, map.counts.redirect, map.counts.unchecked, map.counts.paths],
      [3, 1, 1, 1, 1, 10]);
    // sorted: the host with more hits first
    assert.deepEqual(map.entries.map((e) => e.host), ['web.example.com', 'app.example.net']);
    assert.deepEqual(foundPaths(map.entries), [
      'https://web.example.com/api', 'https://web.example.com/health', 'https://web.example.com/files', 'https://app.example.net/graphql'
    ]);
    assert.deepEqual(foundPaths(map.entries, { includeProtected: true }).filter((u) => u.endsWith('/admin')), ['https://web.example.com/admin']);
  });

  test('the filters', () => {
    const rows = pathRows(dirMap({ reports: [A()] }).entries);
    const count = (f) => rows.filter((r) => dirmapMatches(r, f)).length;
    assert.deepEqual(DIRMAP_FILTERS.map((f) => [f, count(f)]), [
      ['all', 10], ['answered', 6], ['found', 3], ['listing', 1], ['protected', 1], ['redirect', 1], ['unchecked', 1], ['not-found', 3]
    ]);
    assert.deepEqual(DIRMAP_VERDICTS.map(verdictVariant), ['ok', 'error', 'warn', 'info', 'neutral', 'warn', 'warn', 'warn']);
  });

  test('the CSV rows (spreadsheet-safe through lib/export.js)', () => {
    const map = dirMap({ reports: [A()] });
    const rows = dirmapCsvRows(map.entries, (p) => dirmapMatches(p, 'answered'));
    assert.equal(rows.length, 6);
    const old = rows.find((r) => r.path === '/old');
    assert.deepEqual([old.verdict, old.location], ['redirect', 'https://cdn.example.net']);
    const csv = toCsv(rows, DIRMAP_CSV_COLUMNS.map((key) => ({ key, header: key })));
    assert.ok(csv.startsWith('﻿host,path,verdict,status'));
  });
});

describe('Copy summary', () => {
  test('hosts and paths only, never a body or header; in both languages', () => {
    const map = dirMap({ reports: [A()] });
    const facts = dirmapSummaryFacts({ map, reports: [A()] });
    assert.equal(facts.hosts, 2);
    assert.equal(facts.found.length, 4);
    try {
      setLang('en');
      const md = renderSummary(buildSummary('dirmap', facts, { t, lang: 'en', url: null, now: new Date('2026-11-05T10:00:00Z') }), 'markdown');
      assert.match(md, /Endpoint map · 2 hosts/);
      assert.match(md, /2 hosts mapped · 3 found · 1 open listing · 1 protected · 1 redirect/);
      assert.match(md, /Answered:\*\* `web\.example\.com\/api`/);
      assert.match(md, /`web\.example\.com\/files` \(listing\)/);
      assert.match(md, /1 path not checked/);
      assert.match(md, /scanned 2026-11-05 09:30 UTC/);
      for (const secret of ['application/json', '42', 'cdn.example.net']) assert.ok(!md.includes(secret), secret);
      setLang('tr');
      const tr = renderSummary(buildSummary('dirmap', facts, { t, lang: 'tr', url: null, now: new Date('2026-11-05T10:00:00Z') }), 'text');
      assert.match(tr, /Endpoint haritası · 2 host/);
      assert.match(tr, /2 host haritalandı · 3 bulundu/);
    } finally {
      setLang('en');
    }
  });
});

describe('every string the view builds from a vocabulary exists in both languages', () => {
  test('verdicts, filters, steps and nav', () => {
    const keys = [
      ...DIRMAP_VERDICTS.map((v) => `dirmap.v.${v}`),
      ...DIRMAP_FILTERS.map((f) => `dirmap.filter.${f}`),
      ...['found', 'listing', 'protected', 'redirect', 'unchecked'].map((k) => `dirmap.st.${k}`),
      ...['found', 'listing', 'protected', 'redirect', 'unchecked'].map((k) => `dirmap.stHelp.${k}`),
      ...REPORT_ERRORS.map((e) => `dirmap.error.${e}`),
      ...['status', 'reach', 'rate'].map((k) => `dirmap.steps.cannot.${k}`),
      ...['list', 'group', 'export'].map((k) => `dirmap.steps.can.${k}`),
      'dirmap.steps.title', 'dirmap.steps.s1', 'dirmap.steps.s2', 'dirmap.steps.s3',
      'nav.dirmap', 'nav.dirmap.desc', 'nav.dirmap.purpose'
    ];
    for (const key of keys) {
      assert.ok(hasString(key, 'en'), `en ${key}`);
      assert.ok(hasString(key, 'tr'), `tr ${key}`);
    }
  });
});
