/**
 * lib/monitor.js — the Monitoring view's model: the runner's history line (written by
 * tools/ds/history.mjs, read here), the history files parsed with a bad line skipped, merged and
 * pruned, the reports checked with the runner's own shape rules (lib/runreport.js, the rules of a
 * --baseline), one row per target, the tiles, the timeline and its CSV, the sparkline series. The
 * results folder is tests/js/monitor-fixture.mjs (made up, documentation names only).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  HISTORY_VERSION, HISTORY_MAX_CHANGES, HISTORY_KEEP_MONTHS, MONITOR_WARN_DAYS, STALE_MS, TIMELINE_CSV_COLUMNS, MONITOR_MAX_REPORTS,
  checkCompleted, targetFacts, historyLines, historyFileName, monthIndex, staleHistoryFiles, recentHistoryFiles, runLink, repoOfRun,
  readHistoryLine, parseHistory, mergeLines, pruneLines, lineKey, readReport, readMonitorFiles, emptyMonitor, allLines, fileKind,
  monitorRows, monitorTiles, rowMatches, timelineEntries, filterTimeline, timelineCsv, seriesOf, sparkPoints, expiringCertificates,
  worstTlsStatus, latestRun, monitorSummaryFacts, commandOrder
} from '../../assets/js/lib/monitor.js';
import { reportProblem, DS_TOOL, DS_VERSION } from '../../assets/js/lib/runreport.js';
import { baselineProblem } from '../../tools/ds/diff.mjs';
import { monitorFixture, MONITOR_NOW } from './monitor-fixture.mjs';

const DAY = 86400000;
const NOW = MONITOR_NOW;
const report = (command, targets, extra = {}) => ({
  tool: DS_TOOL, version: DS_VERSION, command, startedAt: '2026-10-09T03:00:00.000Z', finishedAt: '2026-10-09T03:02:00.000Z', options: {}, targets, ...extra
});
const loaded = () => readMonitorFiles(emptyMonitor(), monitorFixture().files);

describe('the history line', () => {
  test('one per target of a run: whether it completed, the score and grade, the soonest expiry, the changes counted and cut', () => {
    const many = Array.from({ length: 25 }, (_, i) => ({ tag: 'NEW', tone: i < 3 ? 'bad' : 'info', counts: i < 2, target: 'example.com', item: `h${i}.example.com`, kind: 'appeared', text: 'x' }));
    const doc = report('health', [
      { target: 'example.com', score: 82, grade: 'B', failedLookups: [], checks: [] },
      { target: 'example.org', score: 58, grade: 'E', failedLookups: ['txt'], checks: [] }
    ], {
      changes: [...many, { tag: 'GONE', tone: 'info', counts: true, target: 'example.net', item: null, kind: 'disappeared', text: 'example.net: no longer checked' }]
    });
    const lines = historyLines(doc, { run: 'https://github.com/example-org/nightly/actions/runs/42' });
    assert.equal(lines.length, 3);
    const [com, org, net] = lines;
    assert.deepEqual(Object.keys(com), ['v', 'at', 'command', 'target', 'ok', 'score', 'grade', 'counts', 'changes', 'run']);
    assert.deepEqual([com.v, com.at, com.command, com.target, com.ok, com.score, com.grade], [HISTORY_VERSION, '2026-10-09T03:02:00.000Z', 'health', 'example.com', true, 82, 'B']);
    // bad: the bad changes that count (2: the third bad one is listed only); info: every other one listed
    assert.deepEqual(com.counts, { bad: 2, info: 23 });
    assert.equal(com.changes.length, HISTORY_MAX_CHANGES);
    assert.deepEqual(com.changes[0], { tag: 'NEW', tone: 'bad', item: 'h0.example.com' });
    assert.deepEqual([org.ok, org.score, org.counts], [false, 58, { bad: 0, info: 0 }]);
    // a target of the baseline no longer checked: a line for its changes, marked gone
    assert.deepEqual([net.target, net.gone, net.ok, net.changes], ['example.net', true, true, [{ tag: 'GONE', tone: 'info', item: null }]]);
    // outside GitHub Actions there is no run link; a link that is not one is never written
    assert.ok(!('run' in historyLines(doc)[0]));
    assert.ok(!('run' in historyLines(doc, { run: 'javascript:alert(1)' })[0]));
    assert.deepEqual(historyLines({}), []);
    assert.deepEqual(historyLines({ ...doc, finishedAt: 'x', startedAt: null }), []);
  });

  test('the soonest expiry: tls the certificates served (not one a failed handshake carried), ct the current ones', () => {
    const at = Date.parse('2026-10-09T03:00:00Z');
    const tls = { target: 'www.example.com', endpoints: [
      { address: '192.0.2.10', port: 443, status: 'OK', cert: { sha256: 'a', notAfter: '2026-10-30T03:00:00Z' } },
      { address: '192.0.2.11', port: 443, status: 'TIMEOUT', lastGood: { cert: { sha256: 'b', notAfter: '2026-10-10T03:00:00Z' } } }
    ] };
    assert.deepEqual(targetFacts('tls', tls, at), { ok: true, minDaysLeft: 21 });
    const ct = { target: 'example.com', answered: true, certificates: [
      { id: '1', ca: 'x', names: [], notAfter: '2026-10-12T03:00:00Z', current: false },
      { id: '2', ca: 'x', names: [], notAfter: '2026-11-08T03:00:00Z', current: true }
    ] };
    assert.deepEqual(targetFacts('ct', ct, at), { ok: true, minDaysLeft: 30 });
    // a ct report without the watch's `current`: the certificates still valid
    const old = { ...ct, certificates: ct.certificates.map(({ current, ...c }) => c) };
    assert.equal(targetFacts('ct', old, at).minDaysLeft, 3);
    assert.deepEqual(targetFacts('health', { score: 101, grade: 'Z', failedLookups: [] }, at), { ok: true, score: 101 });
  });

  test('did the check complete: each command\'s own rule', () => {
    assert.equal(checkCompleted('health', { failedLookups: ['mx'] }), false);
    assert.equal(checkCompleted('health', { failedLookups: [] }), true);
    assert.equal(checkCompleted('subdomains', { mode: 'discover', sources: [{ source: 'crtsh', state: 'rate-limited' }, { source: 'anubis', state: 'ok' }] }), true, 'one source answered');
    assert.equal(checkCompleted('subdomains', { mode: 'discover', sources: [{ source: 'crtsh', state: 'ok', skipped: true }] }), false);
    assert.equal(checkCompleted('subdomains', { mode: 'exact', sources: [], warnings: [] }), true);
    assert.equal(checkCompleted('subdomains', { mode: 'exact', sources: [], warnings: ['DNS_UNREACHABLE'] }), false);
    assert.equal(checkCompleted('ct', { answered: false }), false);
    assert.equal(checkCompleted('ct', { answered: true, complete: false }), true, 'one source of two is a read');
    assert.equal(checkCompleted('drift', { aborted: false, rows: [{ status: 'match' }, { status: 'error' }] }), false);
    assert.equal(checkCompleted('drift', { aborted: true, rows: [] }), false);
    assert.equal(checkCompleted('renew', { verdict: 'unknown' }), false);
    assert.equal(checkCompleted('renew', { verdict: 'ready' }), true);
    assert.equal(checkCompleted('dane', { endpoints: [{ status: 'error' }] }), false);
    assert.equal(checkCompleted('audit', { unknown: 2 }), false);
    assert.equal(checkCompleted('tls', { carried: { from: null } }), false);
    assert.equal(checkCompleted('takeover', { failures: [{ source: 'rdap' }] }), false);
    assert.equal(checkCompleted('watch', {}), null, 'a command this page does not know');
  });

  test('the month files: a run\'s file, the months the runner deletes, the months the page reads', () => {
    assert.equal(historyFileName('2026-10-31T23:59:59.999Z'), '2026-10.jsonl');
    assert.equal(historyFileName(new Date('2026-11-01T00:00:00Z')), '2026-11.jsonl');
    assert.equal(monthIndex('2026-01.jsonl'), 2026 * 12);
    assert.equal(monthIndex('2026-13.jsonl'), null);
    const names = ['2025-09.jsonl', '2025-10.jsonl', '2025-11.jsonl', '2026-10.jsonl', 'notes.txt', '2024-1.jsonl', '2026-11.jsonl'];
    // this month and the twelve before it stay: 2025-10 is the oldest kept on 2026-10-09
    assert.deepEqual(staleHistoryFiles(names, new Date('2026-10-09T00:00:00Z')), ['2025-09.jsonl']);
    assert.deepEqual(staleHistoryFiles(names, new Date('2026-11-01T00:00:00Z')), ['2025-09.jsonl', '2025-10.jsonl']);
    assert.equal(HISTORY_KEEP_MONTHS, 13);
    assert.deepEqual(recentHistoryFiles(names, Date.parse('2026-10-09T00:00:00Z'), 3), ['2026-10.jsonl'], 'never a month to come');
    assert.deepEqual(recentHistoryFiles(names, Date.parse('2026-11-20T00:00:00Z'), 13), ['2026-11.jsonl', '2026-10.jsonl', '2025-11.jsonl']);
  });

  test('a run link is GitHub Actions\' own, and names its repository', () => {
    assert.equal(runLink('https://github.com/example-org/nightly/actions/runs/123'), 'https://github.com/example-org/nightly/actions/runs/123');
    for (const bad of ['http://github.com/a/b/actions/runs/1', 'https://github.com/a/b/actions/runs/x', 'https://github.com/a/actions/runs/1', 'https://github.com/a/b/actions/runs/1?x', 5, null]) {
      assert.equal(runLink(bad), null, String(bad));
    }
    assert.deepEqual(repoOfRun('https://github.com/example-org/nightly/actions/runs/123'), { server: 'https://github.com', owner: 'example-org', repo: 'nightly' });
    assert.equal(repoOfRun('nope'), null);
  });
});

describe('reading the history', () => {
  test('a history file\'s lines, a bad line skipped with its number and why, the rest read', () => {
    const good = { v: 1, at: '2026-10-08T03:20:00Z', command: 'health', target: 'example.com', ok: true, score: 82, grade: 'B', counts: { bad: 0, info: 0 }, changes: [] };
    const text = [
      `﻿${JSON.stringify(good)}`,
      '',
      '{"v":1,"at":"2026-10-08',
      JSON.stringify({ ...good, v: 2 }),
      JSON.stringify({ ...good, at: 'yesterday' }),
      JSON.stringify({ ...good, command: 'Health!' }),
      JSON.stringify({ ...good, target: '' }),
      JSON.stringify({ ...good, ok: 'yes' }),
      JSON.stringify({ ...good, counts: { bad: -1, info: 0 } }),
      JSON.stringify({ ...good, changes: [{ tag: 'new', tone: 'bad', item: null }] }),
      JSON.stringify({ ...good, score: 'high' }),
      JSON.stringify({ ...good, run: 'https://example.org/run' }),
      '[1,2]',
      JSON.stringify({ ...good, target: 'example.org', minDaysLeft: -4, changes: [{ tag: 'WORSE', tone: 'bad', item: '198.51.100.25|443' }], counts: { bad: 1, info: 0 } })
    ].join('\r\n');
    const { lines, skipped } = parseHistory(text);
    assert.deepEqual(lines.map((l) => l.target), ['example.com', 'example.org']);
    assert.equal(lines[0].at, '2026-10-08T03:20:00.000Z', 'the time normalized');
    assert.equal(lines[0].ms, Date.parse('2026-10-08T03:20:00Z'));
    assert.deepEqual(lines[1].changes, [{ tag: 'WORSE', tone: 'bad', item: '198.51.100.25|443' }]);
    assert.deepEqual(skipped.map((s) => `${s.line}:${s.why}`), ['3:not-json', '4:version', '5:at', '6:command', '7:target', '8:ok', '9:counts', '10:changes', '11:value', '12:value', '13:not-object']);
    assert.deepEqual(readHistoryLine({ ...good, gone: false }), { why: 'value' });
    assert.deepEqual(parseHistory(''), { lines: [], skipped: [] });
  });

  test('merging: a line read twice is kept once (the first given wins), oldest first; pruning keeps a window', () => {
    const l = (target, at, extra = {}) => readHistoryLine({ v: 1, at, command: 'health', target, ok: true, counts: { bad: 0, info: 0 }, changes: [], ...extra }).line;
    const a = l('example.com', '2026-10-08T03:20:00Z', { run: 'https://github.com/example-org/nightly/actions/runs/1' });
    const again = l('example.com', '2026-10-08T03:20:00Z');
    const b = l('example.org', '2026-10-07T03:20:00Z');
    const c = l('example.com', '2026-10-09T03:20:00Z');
    const merged = mergeLines([a, c], [again, b]);
    assert.deepEqual(merged.map(lineKey), [lineKey(b), lineKey(a), lineKey(c)]);
    assert.equal(merged[1].run, a.run, 'the history file\'s line, with its run, wins over a report\'s own');
    assert.deepEqual(pruneLines(merged, Date.parse('2026-10-08T00:00:00Z')).map((x) => x.target), ['example.com', 'example.com']);
  });
});

describe('reading the reports', () => {
  test('a report of the runner opens; anything else says why, in the runner\'s own words for a damaged one', () => {
    const ok = readReport(JSON.stringify(report('health', [{ target: 'example.com', score: 90, grade: 'A', failedLookups: [], checks: [] }])), { name: 'health.json' });
    assert.equal(ok.ok, true);
    assert.deepEqual([ok.report.name, ok.report.command, ok.report.finishedAt], ['health.json', 'health', Date.parse('2026-10-09T03:02:00Z')]);
    assert.equal(ok.report.lines.length, 1, 'its own line: a folder without history still has one point');
    assert.deepEqual(readReport('{"tool":'), { ok: false, error: 'not-json' });
    assert.deepEqual(readReport('{"tool":"ssl_origin_scan","version":"1.0.0"}'), { ok: false, error: 'not-report' });
    assert.deepEqual(readReport(JSON.stringify({ ...report('health', []), version: '2.0.0' })), { ok: false, error: 'version', detail: '2.0.0' });
    const damaged = report('health', [{ target: 'example.com', checks: [{ id: 'a' }] }]);
    const r = readReport(JSON.stringify(damaged));
    assert.deepEqual([r.ok, r.error], [false, 'damaged']);
    assert.equal(r.detail, 'targets[0] checks[0] has no "severity"');
    assert.equal(readReport(JSON.stringify(report('health', []))).ok, true, 'a run without targets is a report');
    // a command this version does not know (a newer runner's): the envelope and the targets' names only
    assert.equal(readReport(JSON.stringify(report('watch', [{ target: 'example.com', anything: 1 }]))).ok, true);
    assert.equal(readReport(JSON.stringify(report('watch', [{ name: 'example.com' }]))).detail, 'targets[0] has no "target"');
  });

  test('the page and the runner judge a report with one set of rules (lib/runreport.js)', () => {
    const docs = [
      report('ct', [{ target: 'example.com', names: [], issuers: [], certificates: [{ id: 'x', ca: 'y' }] }]),
      report('tls', [{ target: 'www.example.com', endpoints: [{ address: '192.0.2.1', port: 443 }] }]),
      report('takeover', [{ target: 'example.com', risks: [{ key: 'k', kind: 'mx', host: 'example.com', target: 'mx.example.org' }] }]),
      report('audit', [{ target: 'example.com', rules: [{ id: 'dnssec', status: 'maybe' }] }]),
      report('subdomains', [{ target: 'example.com', mode: 'discover', hosts: [{ name: 'a.example.com', ipv4: '192.0.2.1' }] }]),
      report('health', [{ target: 'example.com', score: 90, failedLookups: [], checks: [] }])
    ];
    for (const doc of docs) {
      assert.equal(reportProblem(doc), baselineProblem(doc, doc.command), doc.command);
      const read = readReport(JSON.stringify(doc));
      assert.equal(read.ok ? null : read.detail, baselineProblem(doc, doc.command), doc.command);
    }
    assert.match(baselineProblem(report('ct', []), 'health'), /a report of "ct", not of "health"/, 'the runner still checks the command');
  });

  test('a results folder: reports and history months read, the summaries left alone, a bad line counted, other files named', () => {
    const fx = monitorFixture();
    const r = readMonitorFiles(emptyMonitor(), [...fx.files, { name: 'notes.txt', text: 'hello' }, { name: 'broken.json', text: '{' }]);
    assert.deepEqual(r.data.reports.map((x) => x.name), ['audit.json', 'ct.json', 'health.json', 'takeover.json', 'tls.json']);
    assert.deepEqual(r.data.files.filter((f) => f.kind === 'history').map((f) => f.name), ['2026-08.jsonl', '2026-09.jsonl', '2026-10.jsonl']);
    assert.equal(r.skippedLines, 2, 'the line cut short and the newer format');
    assert.deepEqual(r.problems.map((p) => `${p.name}:${p.error}`), ['notes.txt:not-results', 'broken.json:not-json']);
    assert.deepEqual([r.added.reports, r.added.history], [5, 3]);
    // 51 nights: health 3 targets, ct 2, tls 2, takeover 1 (49 nights), audit 1 (9 nights)
    assert.equal(r.data.lines.length, 153 + 102 + 102 + 49 + 9);
    // the same report again is a duplicate; the same month again replaces its entry (it may have grown)
    const again = readMonitorFiles(r.data, [fx.files.find((f) => f.name === 'ct.json'), fx.history[2]]);
    assert.deepEqual(again.duplicates, ['ct.json']);
    assert.equal(again.data.files.filter((f) => f.name === '2026-10.jsonl').length, 1);
    assert.equal(again.data.lines.length, r.data.lines.length, 'no line twice');
    assert.equal(again.added.lines, 0);
    assert.equal(fileKind({ name: 'Pasted text', text: '{"tool":"x"}', source: 'paste' }), 'report');
    assert.equal(fileKind({ name: 'Pasted text', text: '{"v":1}\n{"v":1}', source: 'paste' }), 'history');
    assert.equal(fileKind({ name: 'health.md' }), 'summary');
    // a history file of nothing but bad lines is no history
    const bad = readMonitorFiles(emptyMonitor(), [{ name: '2026-10.jsonl', text: 'x\ny\n' }]);
    assert.deepEqual(bad.problems, [{ name: '2026-10.jsonl', error: 'empty-history', detail: '2' }]);
  });

  test('past the cap of open reports, the rest are not read', () => {
    const files = Array.from({ length: MONITOR_MAX_REPORTS + 2 }, (_, i) => ({
      name: `r${i}.json`, text: JSON.stringify({ ...report('health', []), finishedAt: new Date(NOW - i * DAY).toISOString() })
    }));
    const r = readMonitorFiles(emptyMonitor(), files);
    assert.equal(r.data.reports.length, MONITOR_MAX_REPORTS);
    assert.equal(r.capped, true);
  });
});

describe('rows, tiles, timeline', () => {
  test('one row per target, the latest check of each command, worst first', () => {
    const { data } = loaded();
    const rows = monitorRows(data, { now: NOW });
    assert.deepEqual(rows.map((r) => r.target), ['example.com', 'example.org', 'mail.example.net', 'www.example.com', 'example.net']);
    const com = rows[0];
    assert.deepEqual(com.commands, ['health', 'ct', 'takeover', 'audit']);
    assert.deepEqual([com.cells.health.score, com.cells.health.grade, com.cells.health.warnings, com.cells.health.from], [82, 'B', 1, 'report']);
    assert.deepEqual([com.cells.ct.current, com.cells.ct.minDaysLeft, com.cells.ct.newIssuers], [2, 15, ['Google Trust Services']]);
    assert.deepEqual([com.cells.takeover.risks, com.cells.takeover.worst, com.cells.takeover.stale], [1, 'high', true], 'the takeover check last ran two nights ago');
    assert.deepEqual([com.cells.audit.fail, com.cells.audit.security], [1, { score: 5, max: 8 }]);
    assert.deepEqual(com.incomplete, ['takeover']);
    assert.equal(com.bad7, 3, 'the DMARC policy (10-05), the takeover risk (10-03), the new issuer (tonight)');
    assert.equal(com.minDaysLeft, 15);
    assert.deepEqual([com.lastChange.tag, com.lastChange.command], ['ISSUER', 'ct']);
    const org = rows.find((r) => r.target === 'example.org');
    assert.deepEqual([org.cells.health.ok, org.incomplete], [false, ['health']]);
    const mail = rows.find((r) => r.target === 'mail.example.net');
    assert.deepEqual([mail.cells.tls.worst, mail.cells.tls.minDaysLeft, mail.cells.tls.problems], ['EXPIRED', -4, 1]);
    const www = rows.find((r) => r.target === 'www.example.com');
    assert.deepEqual([www.cells.tls.worst, www.cells.tls.minDaysLeft, www.cells.tls.endpoints], ['OK', 53, 2]);
    const net = rows.find((r) => r.target === 'example.net');
    assert.deepEqual([net.incomplete, net.bad7, net.minDaysLeft], [[], 0, null]);
  });

  test('the history stands in for a report that is not open, and a target no longer checked leaves the rows', () => {
    const fx = monitorFixture();
    const { data } = readMonitorFiles(emptyMonitor(), fx.history);
    const rows = monitorRows(data, { now: NOW });
    const com = rows.find((r) => r.target === 'example.com');
    assert.deepEqual([com.cells.health.from, com.cells.health.score, com.cells.health.grade], ['history', 82, 'B']);
    assert.equal(com.cells.takeover.stale, true);
    // example.net is dropped from the list one night: the next night's line says so (gone)
    const gone = { v: 1, at: '2026-10-09T04:00:00.000Z', command: 'health', target: 'example.net', ok: true, counts: { bad: 0, info: 1 }, changes: [{ tag: 'GONE', tone: 'info', item: null }], gone: true };
    const more = readMonitorFiles(data, [{ name: 'extra.jsonl', text: JSON.stringify(gone) }]);
    assert.ok(!monitorRows(more.data, { now: NOW }).some((r) => r.target === 'example.net'));
  });

  test('the tiles: bad changes in 7 days, certificates under 21 days, checks that did not complete', () => {
    const { data } = loaded();
    const rows = monitorRows(data, { now: NOW });
    const tiles = monitorTiles(rows, data, { now: NOW });
    assert.equal(tiles.targets, 5);
    assert.deepEqual(tiles.bad.sort(), ['example.com', 'example.org', 'mail.example.net']);
    assert.deepEqual(tiles.expiring.map((c) => `${c.name} ${c.daysLeft} ${c.command}`), ['mail.example.net -4 tls', 'example.com 15 ct']);
    assert.deepEqual(tiles.incomplete, [{ target: 'example.com', command: 'takeover', stale: true }, { target: 'example.org', command: 'health', stale: false }]);
    assert.deepEqual(rows.filter((r) => rowMatches(r, 'expiring')).map((r) => r.target), ['example.com', 'mail.example.net']);
    assert.deepEqual(rows.filter((r) => rowMatches(r, 'incomplete')).map((r) => r.target), ['example.com', 'example.org']);
    assert.equal(rows.filter((r) => rowMatches(r, 'all')).length, 5);
    assert.equal(MONITOR_WARN_DAYS, 21);
    // a week later nothing is "recent" any more, and the expired certificate has more days behind it
    const later = monitorTiles(monitorRows(data, { now: NOW + 8 * DAY }), data, { now: NOW + 8 * DAY });
    assert.deepEqual(later.bad, []);
    assert.equal(later.expiring[0].daysLeft, -12);
  });

  test('a certificate seen by tls and ct is one, by its SHA-256', () => {
    const tls = readReport(JSON.stringify(report('tls', [{ target: 'www.example.com', endpoints: [{ address: '192.0.2.1', port: 443, status: 'OK', cert: { sha256: 'AB'.repeat(32), subject: 'www.example.com', notAfter: '2026-10-19T00:00:00Z' } }] }]))).report;
    const ct = readReport(JSON.stringify(report('ct', [{ target: 'example.com', names: [], issuers: [], answered: true, certificates: [{ id: 'c1', ca: 'x', names: ['www.example.com'], sha256: 'ab'.repeat(32), notAfter: '2026-10-19T00:00:00Z', current: true }] }]))).report;
    const certs = expiringCertificates([ct, tls], NOW);
    assert.deepEqual(certs.map((c) => [c.command, c.daysLeft]), [['tls', 9]]);
  });

  test('the timeline: newest first, a run\'s own words where its report is open, filtered by command, target and tone', () => {
    const { data } = loaded();
    const entries = timelineEntries(data);
    assert.deepEqual(entries.slice(0, 3).map((e) => `${e.at.slice(11, 16)} ${e.command} ${e.target} ${e.tag}`), [
      '03:25 ct example.com ISSUER', '03:20 health example.org NEW', '03:20 health example.org SCORE'
    ]);
    assert.equal(entries[1].text, 'example.org: error spf.error — SPF record has an error');
    assert.deepEqual([entries[1].counts, entries[2].counts], [true, false]);
    assert.equal(entries[1].run, 'https://github.com/example-org/nightly/actions/runs/4069');
    const older = entries.find((e) => e.tag === 'RISK');
    assert.deepEqual([older.text, older.counts, older.item], [null, null, 'mx|example.com|mx.example.org'], 'a night only the history has: the tag and the item');
    assert.deepEqual(filterTimeline(entries, { command: 'tls' }).map((e) => `${e.target} ${e.tag}`), ['mail.example.net WORSE', 'www.example.com CERT']);
    assert.deepEqual(filterTimeline(entries, { target: 'example.com', tone: 'bad' }).map((e) => e.tag), ['ISSUER', 'WORSE', 'RISK']);
    assert.deepEqual(filterTimeline(entries, { tone: 'info' }).map((e) => e.tag), ['SCORE', 'SCORE', 'CERT'], 'info and quiet');
    assert.equal(filterTimeline(entries, { tone: 'all' }).length, entries.length);
    assert.equal(latestRun(data), 'https://github.com/example-org/nightly/actions/runs/4069');
  });

  test('the timeline\'s CSV: its columns, a BOM, spreadsheet-safe cells', () => {
    const csv = timelineCsv([{ at: '2026-10-09T03:20:00.000Z', command: 'health', target: 'example.org', tag: 'NEW', tone: 'bad', counts: true, item: '=cmd()', text: 'a, "b"', run: null }]);
    const [head, row] = csv.replace(/^﻿/, '').split('\r\n');
    assert.ok(csv.startsWith('﻿'));
    assert.equal(head, TIMELINE_CSV_COLUMNS.map((c) => c.key).join(','));
    assert.equal(row, '2026-10-09T03:20:00.000Z,health,example.org,NEW,bad,yes,\'=cmd(),"a, ""b""",');
  });

  test('sparklines: the score and the soonest expiry over the nights, as points in a box', () => {
    const { data } = loaded();
    const lines = allLines(data);
    const www = seriesOf(lines.filter((l) => l.target === 'www.example.com'));
    assert.equal(www.score.length, 0);
    assert.equal(www.days.length, 51);
    const renewed = www.days.findIndex((p, i) => i > 0 && p.value > www.days[i - 1].value);
    assert.equal(new Date(www.days[renewed].ms).toISOString().slice(0, 10), '2026-09-10', 'the renewal is the jump');
    const com = seriesOf(lines.filter((l) => l.target === 'example.com'));
    assert.deepEqual([com.score[0].value, com.score[com.score.length - 1].value], [90, 82]);
    assert.ok(com.days.length > 0, 'ct\'s days when tls does not check the target');
    assert.deepEqual(sparkPoints([]), { points: '', last: null });
    assert.deepEqual(sparkPoints([5]), { points: '48,12', last: { x: 48, y: 12 } });
    assert.equal(sparkPoints([7, 7, 7], { width: 10, height: 10 }).points, '2,5 5,5 8,5', 'a flat series in the middle');
    assert.equal(sparkPoints([0, 100], { width: 10, height: 10 }).points, '2,8 8,2');
    assert.equal(sparkPoints([50, 50], { width: 10, height: 10, domain: [0, 100] }).points, '2,5 8,5', 'a fixed domain');
  });

  test('the worst tls status, the commands\' order, the Copy summary\'s facts (names only)', () => {
    assert.equal(worstTlsStatus(['OK', 'SKIPPED', 'TIMEOUT']), 'TIMEOUT');
    assert.equal(worstTlsStatus(['OK', 'NAME_MISMATCH', 'EXPIRED']), 'EXPIRED');
    assert.equal(worstTlsStatus([]), null);
    assert.deepEqual(['watch', 'audit', 'health', 'drift', 'beta'].sort(commandOrder), ['health', 'audit', 'drift', 'beta', 'watch']);
    const { data } = loaded();
    const rows = monitorRows(data, { now: NOW });
    const facts = monitorSummaryFacts(rows, monitorTiles(rows, data, { now: NOW }), data);
    assert.deepEqual([facts.targets, facts.reports], [5, 5]);
    assert.deepEqual(facts.bad.map((b) => `${b.target} ${b.count}`).sort(), ['example.com 3', 'example.org 1', 'mail.example.net 1']);
    assert.deepEqual(facts.expiring, [{ name: 'mail.example.net', daysLeft: -4 }, { name: 'example.com', daysLeft: 15 }]);
    assert.equal(facts.at.toISOString(), '2026-10-09T03:40:00.000Z');
    assert.equal(facts.since.toISOString(), '2026-08-20T03:20:00.000Z');
    assert.ok(!/192\.0\.2\.|198\.51\.100\.|2001:db8/.test(JSON.stringify(facts)), 'no address');
    assert.ok(STALE_MS >= DAY);
  });
});
