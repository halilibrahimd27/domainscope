/**
 * lib/dmarchistory.js — the DMARC report history of a workspace: a report filed under the UTC day
 * of its begin, a report dropped again (in the same drop or a later one) never counted twice, the
 * counts of a day and of a source, the classes that make a day's unknown mail and known failures,
 * the recent rows a later class corrects (older days kept as they were), the window (400 days,
 * a day ahead at most), pruning in its order and under the cap, the stored text read back entry by
 * entry (nothing stray, nothing it must never keep), the trend by day and by week, the new
 * senders, the roll-up with its verdicts and CSV, and the fixture reports merged twice.
 * Pure Node, no network; documentation data only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  HISTORY_VERSION, HISTORY_DAYS, RECENT_DAYS, HISTORY_MAX_BYTES, HISTORY_PERIODS, HISTORY_CLASSES, DAY_FIELDS, RECENT_FIELDS, ROLLUP_VERDICTS,
  ROLLUP_CSV_COLUMNS, TREND_CSV_COLUMNS, NEW_BASELINE_DAYS, NEW_WINDOW_DAYS, WEEK_BIN_AFTER, SERVICE_MAX,
  dayOf, addDays, isDay, utf8Length, reportHash, emptyHistory, sanitizeHistory, readHistory, historyText, setKeep, forgetHistory,
  mergeReports, reclassify, prune, historyDomains, historySummary, trend, newSince, newSources, historySources, rollup, rollupVerdict,
  rollupCsvRows, trendCsvRows, daysSince
} from '../../assets/js/lib/dmarchistory.js';
import { SOURCE_CLASSES, parseAggregateReport, aggregateDmarc, classifySources, readReportFiles } from '../../assets/js/lib/dmarcreport.js';
import { WORKSPACE_LIMITS, sanitizePart } from '../../assets/js/lib/workspace.js';
import { buildIpIndex, parseInventory } from '../../assets/js/lib/inventory.js';

const NOW = Date.parse('2026-10-09T12:00:00Z');
const TODAY = '2026-10-09';
const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'mailreports');

let seq = 0;
/**
 * A parsed aggregate report (lib/dmarcreport.js AggregateReport) of one day. A record:
 * [ip, count, { dkim, spf, disposition }]; dkim / spf: the policy_evaluated (aligned) results.
 */
function rep({ domain = 'example.com', org = 'reporter.example.org', id = null, day = '2026-10-01', begin = null, p = 'none', sp = null, pct = 100, testing = null, records = [] } = {}) {
  seq += 1;
  const reportId = id || `report-id-${seq}`;
  const start = begin ? new Date(begin) : new Date(`${day}T00:00:00Z`);
  const recs = records.map(([ip, count, o = {}]) => ({
    ip, count, disposition: o.disposition || 'none', dkim: o.dkim || 'pass', spf: o.spf || 'pass', reasons: [],
    headerFrom: domain, envelopeFrom: 'bounce.example.net', envelopeTo: 'inbox.secret.example.net', dkimAuth: [], spfAuth: []
  }));
  return {
    kind: 'dmarc', key: `${org}|${reportId}`, file: `report-file-${seq}.xml`, org, email: 'noreply@contact.example.org', extraContact: null, reportId,
    begin: start, end: new Date(start.getTime() + 86399000), errors: ['an error note'],
    policy: { domain, p, sp: sp || p, np: null, pct, adkim: 'r', aspf: 'r', fo: null, testing },
    records: recs, messages: recs.reduce((n, r) => n + r.count, 0), skipped: 0
  };
}

/** A classifier from a table: ip → class (and service), the same for every domain. */
const classes = (table, { provisional = false } = {}) => (domain, ip) => {
  const v = table[ip];
  if (!v) return null;
  return typeof v === 'string' ? { cls: v, provisional } : { provisional, ...v };
};

const merge = (h, reports, opts = {}) => mergeReports(h, reports, { now: NOW, ...opts });

describe('the shape and its helpers', () => {
  test('constants agree with the modules they mirror', () => {
    assert.deepEqual([...HISTORY_CLASSES], [...SOURCE_CLASSES], 'lib/dmarcreport.js SOURCE_CLASSES');
    assert.equal(HISTORY_MAX_BYTES, WORKSPACE_LIMITS.reportHistory, 'the workspace part holds a capped history whole');
    assert.equal(HISTORY_VERSION, 1);
    assert.deepEqual([...HISTORY_PERIODS], [30, 90, 400]);
    assert.equal(HISTORY_PERIODS[HISTORY_PERIODS.length - 1], HISTORY_DAYS, 'the longest period is everything kept');
    assert.equal(RECENT_DAYS, 31);
    assert.equal(DAY_FIELDS.length, 8);
    assert.equal(RECENT_FIELDS.length, 6);
    assert.deepEqual(RECENT_FIELDS, DAY_FIELDS.slice(0, 6), 'a recent row is the first six counts of a day');
    assert.ok(WEEK_BIN_AFTER >= 90 && WEEK_BIN_AFTER < 400);
  });

  test('days are UTC; a day that does not exist is none', () => {
    assert.equal(dayOf(new Date('2026-09-25T23:59:59-05:00')), '2026-09-26');
    assert.equal(dayOf(Date.parse('2026-09-25T00:00:00Z')), '2026-09-25');
    assert.equal(dayOf('nope'), null);
    assert.equal(dayOf(null), null);
    assert.equal(addDays('2026-02-28', 1), '2026-03-01');
    assert.equal(addDays('2028-02-28', 1), '2028-02-29');
    assert.equal(addDays('2026-01-01', -1), '2025-12-31');
    assert.equal(isDay('2026-02-29'), false);
    assert.equal(isDay('2028-02-29'), true);
    assert.equal(isDay('2026-9-1'), false);
    assert.equal(daysSince('2026-10-01', { now: NOW }), 8);
  });

  test('reportHash: FNV-1a 64 as 16 hex digits (known answers), never the key', () => {
    assert.equal(reportHash(''), 'cbf29ce484222325');
    assert.equal(reportHash('a'), 'af63dc4c8601ec8c');
    assert.match(reportHash('google.com|1234567890'), /^[0-9a-f]{16}$/);
    assert.notEqual(reportHash('google.com|1'), reportHash('google.com|2'));
  });

  test('utf8Length: what the cap counts', () => {
    assert.equal(utf8Length('abc'), 3);
    assert.equal(utf8Length('çğ'), 4);
    assert.equal(utf8Length('€'), 3);
    assert.equal(utf8Length('🙂'), 4);
  });

  test('an empty history; the switch; forget keeps the switch', () => {
    assert.deepEqual(emptyHistory(), { v: 1, keep: false, updatedAt: null, domains: {} });
    assert.equal(historyText(emptyHistory()), '', 'nothing to keep: no text, no record');
    const on = setKeep(emptyHistory(), true);
    assert.equal(on.keep, true);
    assert.deepEqual(JSON.parse(historyText(on)), { v: 1, keep: true, updatedAt: null, domains: {} });
    const { history } = merge(on, [rep({ records: [['192.0.2.10', 5]] })]);
    const off = setKeep(history, false);
    assert.equal(off.keep, false);
    assert.ok(off.domains['example.com'], 'turning it off keeps what is there');
    assert.ok(history.keep, 'setKeep returns a new history');
    const forgotten = forgetHistory(history, { now: NOW });
    assert.deepEqual(forgotten.domains, {});
    assert.equal(forgotten.keep, true);
    assert.equal(historyText(forgetHistory(off)), '', 'off and forgotten: nothing stored');
  });
});

describe('mergeReports', () => {
  test('a report is filed under the UTC day of its begin, with the day\'s counts', () => {
    const a = rep({ begin: '2026-10-01T23:30:00Z', records: [['192.0.2.10', 10], ['198.51.100.7', 4, { dkim: 'fail', spf: 'fail', disposition: 'quarantine' }],
      ['203.0.113.9', 3, { dkim: 'fail', spf: 'pass' }], ['203.0.113.10', 2, { dkim: 'pass', spf: 'fail', disposition: 'reject' }]] });
    const b = rep({ begin: '2026-10-02T00:00:00Z', records: [['192.0.2.10', 6]] });
    const { history, merged, duplicates, domains } = merge(emptyHistory({ keep: true }), [a, b]);
    assert.equal(merged, 2);
    assert.equal(duplicates, 0);
    assert.deepEqual(domains, ['example.com']);
    const d = history.domains['example.com'];
    assert.deepEqual(Object.keys(d.days).sort(), ['2026-10-01', '2026-10-02']);
    assert.deepEqual(d.days['2026-10-01'], { msgs: 19, dmarcPass: 15, spfAligned: 13, dkimAligned: 12, quarantine: 4, reject: 2, unknownMsgs: 0, knownFail: 0 });
    assert.deepEqual(d.days['2026-10-02'], { msgs: 6, dmarcPass: 6, spfAligned: 6, dkimAligned: 6, quarantine: 0, reject: 0, unknownMsgs: 0, knownFail: 0 });
    assert.deepEqual(d.sources['192.0.2.10'], { first: '2026-10-01', last: '2026-10-02', msgs: 16, passMsgs: 16, cls: null, service: null, type: null });
    assert.deepEqual(d.sources['198.51.100.7'], { first: '2026-10-01', last: '2026-10-01', msgs: 4, passMsgs: 0, cls: null, service: null, type: null });
    assert.deepEqual(d.recent['2026-10-01']['203.0.113.10'], [2, 2, 0, 2, 0, 2]);
    assert.deepEqual(d.policy, { p: 'none', sp: 'none', pct: 100, seenAt: '2026-10-02T23:59:59.000Z' });
    assert.equal(history.updatedAt, new Date(NOW).toISOString());
  });

  test('classes: the mail of unknown senders, and that of known sources (yours, third parties) that fails', () => {
    const r = rep({ records: [['192.0.2.10', 10], ['192.0.2.11', 4, { dkim: 'fail', spf: 'fail' }], ['198.51.100.7', 5, { dkim: 'fail', spf: 'fail' }],
      ['198.51.100.8', 2, { dkim: 'pass', spf: 'fail' }], ['203.0.113.9', 7, { dkim: 'fail', spf: 'fail' }], ['203.0.113.50', 1, { dkim: 'fail', spf: 'fail' }]] });
    const classify = classes({
      '192.0.2.10': { cls: 'yours', service: 'Google Workspace', type: 'mailbox' }, '192.0.2.11': 'yours', '198.51.100.7': 'third-party',
      '198.51.100.8': 'forwarder', '203.0.113.9': 'unknown'
    });
    const { history } = merge(emptyHistory(), [r], { classify });
    const d = history.domains['example.com'];
    const day = d.days['2026-10-01'];
    assert.equal(day.unknownMsgs, 7, 'the unknown sender');
    assert.equal(day.knownFail, 9, 'your failing server and the failing third party; not the forwarder, not the unclassified');
    assert.deepEqual([d.sources['192.0.2.10'].cls, d.sources['192.0.2.10'].service, d.sources['192.0.2.10'].type], ['yours', 'Google Workspace', 'mailbox']);
    assert.equal(d.sources['192.0.2.10'].checked, true, 'a class the SPF decided');
    assert.equal(d.sources['203.0.113.50'].cls, null, 'nothing said: no class');
    assert.equal(d.checked, TODAY);
  });

  test('a report dropped twice counts once: in the same drop, in a later one; the same id of another reporter or domain counts', () => {
    const r = rep({ id: 'same-id', records: [['192.0.2.10', 10]] });
    const first = merge(emptyHistory(), [r, r]);
    assert.equal(first.merged, 1);
    assert.equal(first.duplicates, 1);
    const again = merge(first.history, [rep({ id: 'same-id', records: [['192.0.2.10', 10]] })]);
    assert.equal(again.merged, 0);
    assert.equal(again.duplicates, 1);
    assert.deepEqual(again.history.domains, first.history.domains, 'counts unchanged');
    const other = merge(first.history, [rep({ id: 'same-id', org: 'other.example.org', records: [['192.0.2.10', 1]] }),
      rep({ id: 'same-id', domain: 'example.net', records: [['192.0.2.10', 1]] })]);
    assert.equal(other.merged, 2);
    assert.equal(other.history.domains['example.com'].days['2026-10-01'].msgs, 11);
    assert.equal(other.history.domains['example.net'].days['2026-10-01'].msgs, 1);
    // The seen list holds hashes, never the reporter or the id.
    assert.deepEqual(first.history.domains['example.com'].seen, { '2026-10-01': [reportHash('reporter.example.org|same-id')] });
  });

  test('the window: older than 400 days, more than a day ahead, a day prune cut, and what is no DMARC report are not taken', () => {
    const oldest = addDays(TODAY, -(HISTORY_DAYS - 1));
    const res = merge(emptyHistory(), [
      rep({ day: addDays(oldest, -1), records: [['192.0.2.10', 1]] }),
      rep({ day: oldest, records: [['192.0.2.10', 1]] }),
      rep({ day: addDays(TODAY, 1), records: [['192.0.2.10', 1]] }),
      rep({ day: addDays(TODAY, 2), records: [['192.0.2.10', 1]] }),
      { kind: 'tlsrpt', key: 'x|y', begin: new Date(NOW), policies: [] },
      { ...rep({ records: [] }), policy: { domain: 'not a domain' } },
      null
    ]);
    assert.equal(res.merged, 2, 'the first day of the window and tomorrow');
    assert.deepEqual(res.skipped, { old: 1, future: 1, cut: 0, invalid: 1 });
    const h = res.history;
    h.domains['example.com'].cut = '2026-09-01';
    const cut = merge(h, [rep({ day: '2026-09-01', records: [['192.0.2.10', 1]] }), rep({ day: '2026-09-02', records: [['192.0.2.10', 1]] })]);
    assert.deepEqual([cut.merged, cut.skipped.cut], [1, 1]);
  });

  test('recent rows only for the last 31 days; the policy of the report that ends last, whatever the order', () => {
    const late = rep({ day: '2026-10-05', p: 'reject', pct: 50, testing: 'y', records: [['192.0.2.10', 2]] });
    const early = rep({ day: addDays(TODAY, -(RECENT_DAYS)), p: 'quarantine', records: [['192.0.2.10', 3]] });
    const { history } = merge(emptyHistory(), [late, early]);
    const d = history.domains['example.com'];
    assert.deepEqual(Object.keys(d.recent), ['2026-10-05'], 'the day 31 days back is outside the recent window');
    assert.ok(d.days[addDays(TODAY, -RECENT_DAYS)], 'its day is kept');
    assert.deepEqual(d.policy, { p: 'reject', sp: 'reject', pct: 50, seenAt: '2026-10-05T23:59:59.000Z', testing: 'y' });
    // A policy that is no DMARC policy is not taken.
    const junk = merge(emptyHistory(), [rep({ p: '<script>', records: [['192.0.2.10', 1]] })]).history;
    assert.equal(junk.domains['example.com'].policy, null);
  });

  test('never keeps the report XML, file names, envelope_to, the reporter, its contact, its id or its notes', () => {
    const r = rep({ id: 'very-secret-report-id', org: 'reporter.example.org', records: [['192.0.2.10', 10]] });
    const text = historyText(merge(emptyHistory({ keep: true }), [r]).history);
    for (const s of ['report-file', 'inbox.secret.example.net', 'reporter.example.org', 'contact.example.org', 'very-secret-report-id', 'an error note', 'bounce.example.net', '<']) {
      assert.ok(!text.includes(s), s);
    }
  });

  test('the input history is never changed', () => {
    const h = merge(emptyHistory(), [rep({ records: [['192.0.2.10', 1]] })]).history;
    const before = JSON.stringify(h);
    merge(h, [rep({ records: [['192.0.2.10', 1]] })]);
    reclassify(h, classes({ '192.0.2.10': 'unknown' }), { now: NOW });
    prune(h, { now: NOW, maxBytes: 10 });
    assert.equal(JSON.stringify(h), before);
  });
});

describe('reclassify', () => {
  test('a class that changes corrects the recent days, never the older ones; the service follows and is never erased', () => {
    const old = rep({ day: addDays(TODAY, -40), records: [['198.51.100.7', 5, { dkim: 'fail', spf: 'fail' }]] });
    const recent = rep({ day: '2026-10-07', records: [['198.51.100.7', 4, { dkim: 'fail', spf: 'fail' }], ['192.0.2.10', 6]] });
    const provisional = classes({ '198.51.100.7': 'unknown', '192.0.2.10': 'yours' }, { provisional: true });
    const { history } = merge(emptyHistory(), [old, recent], { classify: provisional });
    let d = history.domains['example.com'];
    assert.equal(d.days[addDays(TODAY, -40)].unknownMsgs, 5);
    assert.equal(d.days['2026-10-07'].unknownMsgs, 4);
    assert.equal(d.checked, null, 'no class came from the SPF yet');
    // The SPF landed: the address is an authorized third party whose mail fails.
    const next = reclassify(history, classes({ '198.51.100.7': { cls: 'third-party', service: 'SendGrid', type: 'transactional' } }), { now: NOW });
    assert.equal(next.changed, true);
    d = next.history.domains['example.com'];
    assert.deepEqual([d.days['2026-10-07'].unknownMsgs, d.days['2026-10-07'].knownFail], [0, 4], 'the recent day follows');
    assert.deepEqual([d.days[addDays(TODAY, -40)].unknownMsgs, d.days[addDays(TODAY, -40)].knownFail], [5, 0], 'an older day keeps its class');
    assert.deepEqual([d.sources['198.51.100.7'].cls, d.sources['198.51.100.7'].service, d.sources['198.51.100.7'].checked], ['third-party', 'SendGrid', true]);
    assert.equal(d.checked, TODAY);
    // A provisional class (no SPF this time) never replaces it; a service is never erased.
    const weak = reclassify(next.history, classes({ '198.51.100.7': { cls: 'unknown', service: null } }, { provisional: true }), { now: NOW });
    assert.equal(weak.changed, false);
    assert.equal(weak.history, next.history, 'nothing changed: the same object');
    // …but it fills a class the reports alone gave.
    const filled = reclassify(next.history, classes({ '192.0.2.10': 'unknown' }, { provisional: true }), { now: NOW });
    assert.equal(filled.history.domains['example.com'].sources['192.0.2.10'].cls, 'unknown');
    assert.equal(filled.history.domains['example.com'].days['2026-10-07'].unknownMsgs, 6);
    // Only the domains asked for.
    const none = reclassify(next.history, classes({ '198.51.100.7': 'yours' }), { now: NOW, domains: ['example.net'] });
    assert.equal(none.changed, false);
  });

  test('a later drop classes again with the same rule: a source of the history keeps the SPF\'s class against a provisional one', () => {
    const { history } = merge(emptyHistory(), [rep({ day: '2026-10-06', records: [['198.51.100.7', 3, { dkim: 'fail', spf: 'fail' }]] })],
      { classify: classes({ '198.51.100.7': 'third-party' }) });
    const later = merge(history, [rep({ day: '2026-10-07', records: [['198.51.100.7', 2, { dkim: 'fail', spf: 'fail' }]] })],
      { classify: classes({ '198.51.100.7': 'unknown' }, { provisional: true }) }).history;
    const d = later.domains['example.com'];
    assert.equal(d.sources['198.51.100.7'].cls, 'third-party');
    assert.deepEqual([d.days['2026-10-07'].knownFail, d.days['2026-10-07'].unknownMsgs], [2, 0]);
  });
});

describe('prune', () => {
  test('the window: days, reports seen and sources past 400 days, recent rows past 31; an empty domain goes', () => {
    const h = emptyHistory({ keep: true });
    h.domains['example.com'] = {
      days: { '2025-01-01': { ...Object.fromEntries(DAY_FIELDS.map((f) => [f, 0])), msgs: 1 }, '2026-10-01': { ...Object.fromEntries(DAY_FIELDS.map((f) => [f, 0])), msgs: 2 } },
      sources: { '192.0.2.10': { first: '2025-01-01', last: '2025-01-01', msgs: 1, passMsgs: 1, cls: null, service: null, type: null },
        '192.0.2.11': { first: '2025-01-01', last: '2026-10-01', msgs: 2, passMsgs: 2, cls: null, service: null, type: null } },
      recent: { '2026-09-01': { '192.0.2.11': [1, 1, 1, 1, 0, 0] }, '2026-10-01': { '192.0.2.11': [1, 1, 1, 1, 0, 0] } },
      policy: null, seen: { '2025-01-01': ['00000000000000aa'], '2026-10-01': ['00000000000000bb'] }, cut: '2025-01-01', checked: null
    };
    h.domains['example.net'] = { days: { '2025-01-01': { ...Object.fromEntries(DAY_FIELDS.map((f) => [f, 0])), msgs: 1 } }, sources: {}, recent: {}, policy: null, seen: {}, cut: null, checked: null };
    const { history, dropped } = prune(h, { now: NOW });
    const d = history.domains['example.com'];
    assert.deepEqual(Object.keys(d.days), ['2026-10-01']);
    assert.deepEqual(Object.keys(d.seen), ['2026-10-01']);
    assert.deepEqual(Object.keys(d.sources), ['192.0.2.11'], 'a source goes 400 days after its last day');
    assert.deepEqual(Object.keys(d.recent), ['2026-10-01']);
    assert.equal(d.cut, null, 'a cut the window passed');
    assert.ok(!history.domains['example.net'], 'nothing left');
    assert.equal(dropped.domains, 1);
  });

  test('over the cap: the oldest recent days first, then the sources with the fewest messages, then the oldest days', () => {
    const reports = [];
    for (let i = 0; i < 20; i += 1) {
      const day = addDays(TODAY, -i);
      reports.push(rep({ day, records: Array.from({ length: 30 }, (_, j) => [`198.51.100.${j + 1}`, j + 1 + i]) }));
    }
    for (let i = 0; i < 60; i += 1) reports.push(rep({ day: addDays(TODAY, -40 - i), records: [['203.0.113.1', 1000]] }));
    const { history } = merge(emptyHistory({ keep: true }), reports);
    const full = utf8Length(historyText(history));
    // Just under the full size: only the oldest recent day goes.
    const lastRecent = Object.keys(history.domains['example.com'].recent).sort()[0];
    const one = prune(history, { now: NOW, maxBytes: full - 10 });
    assert.deepEqual([one.dropped.recentDays, one.dropped.sources, one.dropped.days], [1, 0, 0]);
    assert.ok(!one.history.domains['example.com'].recent[lastRecent], 'the oldest recent day');
    assert.ok(one.bytes <= full - 10 && one.bytes === utf8Length(historyText(one.history)));
    // Without the recent rows it is still too big: the sources with the fewest messages go next.
    const noRecent = utf8Length(historyText({ ...history, domains: { 'example.com': { ...history.domains['example.com'], recent: {} } } }));
    const two = prune(history, { now: NOW, maxBytes: noRecent - 200 });
    const d2 = two.history.domains['example.com'];
    assert.deepEqual(Object.keys(d2.recent), [], 'every recent day went first');
    assert.ok(two.dropped.sources > 0 && two.dropped.days === 0, JSON.stringify(two.dropped));
    assert.ok(!d2.sources['198.51.100.1'], 'the source with the fewest messages');
    assert.ok(d2.sources['203.0.113.1'], 'the one with the most stays');
    // Still too big without any source: the oldest days go, and the domain's cut moves past them.
    const three = prune(history, { now: NOW, maxBytes: 4000 });
    const d3 = three.history.domains['example.com'];
    assert.ok(three.bytes <= 4000, String(three.bytes));
    assert.ok(three.dropped.days > 0);
    const keptDays = Object.keys(d3.days).sort();
    assert.ok(d3.cut && d3.cut < keptDays[0], `${d3.cut} < ${keptDays[0]}`);
    assert.ok(keptDays.includes(TODAY), 'the newest days stay');
    // A report filed on a day that was cut is not taken again.
    const back = merge(three.history, [rep({ day: d3.cut, records: [['192.0.2.10', 1]] })]);
    assert.deepEqual([back.merged, back.skipped.cut], [0, 1]);
    // A cap no history fits: nothing left but the switch.
    const none = prune(history, { now: NOW, maxBytes: 10 });
    assert.deepEqual(none.history.domains, {});
  });

  test('the default cap is the workspace part\'s: a pruned history is always stored', () => {
    const many = [];
    for (let i = 0; i < 31; i += 1) {
      many.push(rep({ day: addDays(TODAY, -i), records: Array.from({ length: 2000 }, (_, j) => [`2001:db8:${(j >> 8).toString(16)}::${(j & 255).toString(16)}:${i.toString(16)}`, 1]) }));
    }
    const { history } = merge(emptyHistory({ keep: true }), many);
    assert.ok(utf8Length(historyText(history)) > HISTORY_MAX_BYTES, 'over the cap before');
    const { history: small, bytes } = prune(history, { now: NOW });
    const text = historyText(small);
    assert.ok(bytes <= HISTORY_MAX_BYTES && utf8Length(text) === bytes);
    assert.equal(sanitizePart('reportHistory', text), text, 'the workspace keeps it whole');
  });
});

describe('the stored text', () => {
  test('a round trip gives the same history; keys in order', () => {
    const { history } = merge(emptyHistory({ keep: true }), [rep({ day: '2026-10-02', records: [['198.51.100.7', 1], ['192.0.2.10', 2]] }),
      rep({ day: '2026-10-01', records: [['192.0.2.10', 3]] })], { classify: classes({ '192.0.2.10': { cls: 'yours', service: 'Zendesk', type: 'saas' } }) });
    const text = historyText(history);
    assert.deepEqual(readHistory(text), history);
    assert.equal(historyText(readHistory(text)), text, 'stable');
    const parsed = JSON.parse(text);
    assert.deepEqual(Object.keys(parsed.domains['example.com'].days), ['2026-10-01', '2026-10-02']);
    assert.deepEqual(Object.keys(parsed.domains['example.com'].sources), ['192.0.2.10', '198.51.100.7']);
  });

  test('anything that is not one is no history; every entry is checked on its own', () => {
    for (const bad of [null, '', 'not json', '[]', '{"v":2,"domains":{}}', 42, { v: 1 }]) {
      assert.deepEqual(readHistory(typeof bad === 'string' ? bad : JSON.stringify(bad)), emptyHistory(), String(bad));
    }
    const day = { msgs: 5, dmarcPass: 9, spfAligned: -1, dkimAligned: 2.5, quarantine: '3', reject: 1, unknownMsgs: 7, knownFail: 4 };
    const raw = {
      v: 1, keep: 'yes', updatedAt: 'whenever',
      domains: {
        'Example.COM': { days: { '2026-10-01': day } },
        __proto__: { days: { '2026-10-01': day } },
        'example.com': {
          days: { '2026-10-01': day, '2026-02-30': day, 'x': day },
          sources: {
            '192.0.2.10': { first: '2026-10-01', last: '2026-10-01', msgs: 3, passMsgs: 8, cls: 'boss', service: ' Evil\u202e<b>Corp</b>\u0000 ', type: 'Saas!', checked: true },
            '192.0.2.011': { first: '2026-10-01', last: '2026-10-01', msgs: 1, passMsgs: 1 },
            '2001:DB8::1': { first: '2026-10-01', last: '2026-10-01', msgs: 1, passMsgs: 1 },
            '198.51.100.7': { first: '2026-10-02', last: '2026-10-01', msgs: 1, passMsgs: 1 },
            '203.0.113.9': { first: '2026-10-01', last: '2026-10-01', msgs: 2, passMsgs: 1, cls: 'unknown', checked: true, service: 'x'.repeat(200), type: 'isp' }
          },
          recent: { '2026-10-01': { '192.0.2.10': [3, 4, 1, 1, 0, 0], '198.51.100.7': [1, 2, 3], 'nope': [1, 1, 1, 1, 1, 1] } },
          policy: { p: 'reject', sp: 'bogus', pct: 250, seenAt: '2026-10-01T00:00:00Z', testing: 'n' },
          seen: { '2026-10-01': ['00000000000000aa', '00000000000000aa', 'zz', 7] },
          cut: '2026-13-01',
          checked: '2026-10-01'
        }
      }
    };
    const h = sanitizeHistory(JSON.parse(JSON.stringify(raw)));
    assert.equal(h.keep, false, 'only true is on');
    assert.equal(h.updatedAt, null);
    assert.deepEqual(Object.keys(h.domains), ['example.com'], 'a name not as stored and __proto__ are dropped');
    assert.equal(Object.getPrototypeOf(h.domains), Object.prototype);
    const d = h.domains['example.com'];
    assert.deepEqual(Object.keys(d.days), ['2026-10-01']);
    assert.deepEqual(d.days['2026-10-01'], { msgs: 5, dmarcPass: 5, spfAligned: 0, dkimAligned: 0, quarantine: 0, reject: 1, unknownMsgs: 5, knownFail: 0 });
    assert.deepEqual(Object.keys(d.sources), ['192.0.2.10', '203.0.113.9'], 'an address not as stored, or first after last, is dropped');
    assert.deepEqual(d.sources['192.0.2.10'], { first: '2026-10-01', last: '2026-10-01', msgs: 3, passMsgs: 3, cls: null, service: 'Evil <b>Corp</b>', type: null });
    assert.equal(d.sources['203.0.113.9'].service.length, SERVICE_MAX);
    assert.equal(d.sources['203.0.113.9'].checked, true);
    assert.deepEqual(d.recent, { '2026-10-01': { '192.0.2.10': [3, 3, 1, 1, 0, 0] } });
    assert.deepEqual(d.policy, { p: 'reject', sp: 'reject', pct: 100, seenAt: '2026-10-01T00:00:00.000Z' });
    assert.deepEqual(d.seen, { '2026-10-01': ['00000000000000aa'] });
    assert.equal(d.cut, null);
    assert.equal(d.checked, '2026-10-01');
  });

  test('the workspace part: the text kept whole or not at all, anything else empty', () => {
    const text = historyText(merge(emptyHistory({ keep: true }), [rep({ records: [['192.0.2.10', 1]] })]).history);
    assert.equal(sanitizePart('reportHistory', text), text);
    assert.equal(sanitizePart('reportHistory', 'h'.repeat(WORKSPACE_LIMITS.reportHistory)).length, WORKSPACE_LIMITS.reportHistory);
    assert.equal(sanitizePart('reportHistory', 'h'.repeat(WORKSPACE_LIMITS.reportHistory + 1)), '', 'a cut text would be no JSON');
    assert.equal(sanitizePart('reportHistory', { v: 1, domains: {} }), '');
    assert.equal(sanitizePart('reportHistory', null), '');
  });
});

describe('reading it back', () => {
  const build = () => {
    const reports = [];
    // 10 days of example.com: 100 messages a day, 2 failing from an unknown sender; a new sender on the last two days.
    for (let i = 0; i < 10; i += 1) {
      const day = addDays(TODAY, -i - 1);
      const records = [['192.0.2.10', 98], ['203.0.113.9', 2, { dkim: 'fail', spf: 'fail' }]];
      if (i < 2) records.push(['198.51.100.7', 5, { dkim: 'fail', spf: 'fail' }]);
      reports.push(rep({ day, p: 'quarantine', records }));
    }
    // example.net: p=reject, a known source that fails.
    reports.push(rep({ domain: 'example.net', day: addDays(TODAY, -3), p: 'reject', records: [['192.0.2.20', 10], ['192.0.2.21', 3, { dkim: 'fail', spf: 'fail' }]] }));
    // example.org: p=reject, everything passes; and its last report 60 days ago.
    reports.push(rep({ domain: 'example.org', day: addDays(TODAY, -2), p: 'reject', records: [['192.0.2.30', 4]] }));
    reports.push(rep({ domain: 'example.org', day: addDays(TODAY, -60), p: 'none', records: [['192.0.2.30', 4]] }));
    const classify = classes({ '192.0.2.10': 'yours', '203.0.113.9': 'unknown', '198.51.100.7': { cls: 'third-party', service: 'Mailgun', type: 'transactional' },
      '192.0.2.20': 'yours', '192.0.2.21': 'yours', '192.0.2.30': 'yours' });
    return merge(emptyHistory({ keep: true }), reports, { classify }).history;
  };

  test('trend: one slot a day up to today, days without a report said so, the period\'s totals', () => {
    const tr = trend(build(), 'example.com', { days: 30, now: NOW });
    assert.equal(tr.bin, 'day');
    assert.equal(tr.slots.length, 30);
    assert.deepEqual([tr.from, tr.to], [addDays(TODAY, -29), TODAY]);
    const last = tr.slots[tr.slots.length - 1];
    assert.deepEqual([last.day, last.reportedDays, last.msgs, last.compliance], [TODAY, 0, 0, null], 'no report today: no mail said, no compliance');
    const y = tr.slots[tr.slots.length - 2];
    assert.deepEqual([y.day, y.reportedDays, y.msgs, y.dmarcPass, y.unknownMsgs, y.knownFail], [addDays(TODAY, -1), 1, 105, 98, 2, 5]);
    assert.equal(y.compliance, 98 / 105);
    assert.equal(tr.totals.msgs, 1010);
    assert.equal(tr.totals.reportedDays, 10);
    assert.equal(tr.totals.unknownShare, 20 / 1010);
    assert.deepEqual([tr.totals.first, tr.totals.last, tr.last], [addDays(TODAY, -10), addDays(TODAY, -1), addDays(TODAY, -1)]);
    const csv = trendCsvRows(tr);
    assert.equal(csv.length, 10, 'the days with a report');
    assert.deepEqual(Object.keys(csv[0]), [...TREND_CSV_COLUMNS]);
    assert.equal(csv[csv.length - 1].compliance_pct, '93.3');
  });

  test('trend: a week a bar over a long period, the last ending today; an unknown domain is an empty trend', () => {
    const tr = trend(build(), 'example.org', { days: 400, now: NOW });
    assert.equal(tr.bin, 'week');
    assert.equal(tr.slots.length, Math.ceil(400 / 7));
    assert.equal(tr.slots[tr.slots.length - 1].to, TODAY);
    assert.equal(tr.slots[0].day, addDays(TODAY, -399));
    assert.equal(tr.slots.reduce((n, s) => n + s.msgs, 0), 8);
    assert.equal(tr.slots.filter((s) => s.reportedDays).length, 2);
    const none = trend(build(), 'unknown.example.net', { days: 30, now: NOW });
    assert.deepEqual([none.slots.length, none.totals.msgs, none.last, none.totals.compliance], [30, 0, null, null]);
    assert.equal(trend(build(), 'example.org', { days: 30, now: NOW }).totals.reportedDays, 1, 'the report 60 days ago is outside');
  });

  test('new senders: those first seen in the last 30 days, once the domain has a week of history before them; the newest first', () => {
    const h = build();
    // example.com began 10 days ago: a sender is new only from its eighth day on.
    const since = newSince(h, 'example.com', { now: NOW });
    assert.equal(since, addDays(addDays(TODAY, -10), NEW_BASELINE_DAYS));
    assert.deepEqual(newSources(h, 'example.com', since).map((s) => [s.ip, s.first, s.service]), [['198.51.100.7', addDays(TODAY, -2), 'Mailgun']]);
    const all = historySources(h, 'example.com', { since });
    assert.deepEqual(all.map((s) => [s.ip, s.isNew]), [['192.0.2.10', false], ['203.0.113.9', false], ['198.51.100.7', true]], 'the most mail first');
    // With a history of 60 days: the last 30 days.
    const longer = merge(h, [rep({ day: addDays(TODAY, -60), records: [['192.0.2.10', 1]] })]).history;
    const window = newSince(longer, 'example.com', { now: NOW });
    assert.equal(window, addDays(TODAY, -(NEW_WINDOW_DAYS - 1)));
    assert.deepEqual(newSources(longer, 'example.com', window).map((s) => s.ip), ['198.51.100.7', '203.0.113.9'], 'the newest first');
    // A history of one day: nothing is new yet; no domain, no day.
    assert.equal(newSince(h, 'example.net', { now: NOW }), null);
    assert.deepEqual(newSources(h, 'example.net', null), []);
    assert.equal(newSince(h, 'unknown.example.net', { now: NOW }), null);
    assert.deepEqual(historySources(h, 'unknown.example.net'), []);
  });

  test('the roll-up: every domain, the most mail first, with its verdict; totals; the CSV', () => {
    const r = rollup(build(), { now: NOW, days: 30 });
    assert.deepEqual(r.rows.map((x) => [x.domain, x.msgs, x.verdict]), [['example.com', 1010, 'fix-first'], ['example.net', 13, 'enforced-losing'], ['example.org', 4, 'enforced']]);
    const com = r.rows[0];
    assert.deepEqual([com.knownFail, com.unknownMsgs, com.reportedDays, com.sources, com.newSources, com.policy.p], [10, 20, 10, 3, 1, 'quarantine']);
    assert.equal(com.compliance, 980 / 1010);
    assert.equal(r.totals.msgs, 1027);
    assert.equal(r.totals.domains, 3);
    const csv = rollupCsvRows(r.rows);
    assert.deepEqual(Object.keys(csv[0]), [...ROLLUP_CSV_COLUMNS]);
    assert.deepEqual([csv[0].domain, csv[0].compliance_pct, csv[0].unknown_pct, csv[0].policy_p, csv[0].verdict, csv[0].spf_checked], ['example.com', '97', '2', 'quarantine', 'fix-first', TODAY]);
    // A domain with no report in the period: no mail.
    const later = rollup(build(), { now: Date.parse('2027-01-30T12:00:00Z'), days: 30 });
    assert.ok(later.rows.every((x) => x.verdict === 'no-mail'));
    assert.equal(later.totals.compliance, null);
  });

  test('rollupVerdict: no mail, p=reject in force (100 %, not t=y) with or without known failures, fix first, ready', () => {
    const p = (o) => ({ p: 'reject', sp: 'reject', pct: 100, seenAt: '2026-10-01T00:00:00.000Z', ...o });
    assert.equal(rollupVerdict({ msgs: 0, knownFail: 0, policy: p() }), 'no-mail');
    assert.equal(rollupVerdict({ msgs: 5, knownFail: 0, policy: p() }), 'enforced');
    assert.equal(rollupVerdict({ msgs: 5, knownFail: 1, policy: p() }), 'enforced-losing');
    assert.equal(rollupVerdict({ msgs: 5, knownFail: 1, policy: p({ pct: 50 }) }), 'fix-first');
    assert.equal(rollupVerdict({ msgs: 5, knownFail: 0, policy: p({ testing: 'y' }) }), 'ready');
    assert.equal(rollupVerdict({ msgs: 5, knownFail: 0, policy: null }), 'ready');
    for (const v of ['no-mail', 'enforced', 'enforced-losing', 'fix-first', 'ready']) assert.ok(ROLLUP_VERDICTS.includes(v));
  });

  test('the domains and the summary of a history', () => {
    const h = build();
    assert.deepEqual(historyDomains(h).map((x) => [x.domain, x.msgs]), [['example.com', 1010], ['example.net', 13], ['example.org', 8]]);
    const s = historySummary(h);
    assert.deepEqual([s.keep, s.domains, s.sources, s.reports, s.first, s.last], [true, 3, 6, 13, addDays(TODAY, -60), addDays(TODAY, -1)]);
    assert.deepEqual(historySummary(emptyHistory()), { keep: false, domains: 0, days: 0, sources: 0, reports: 0, first: null, last: null });
  });
});

describe('the fixture reports, as the view merges them', () => {
  test('a mailbox zip merged with the classes classifySources gives; merged again, nothing changes', async () => {
    const bytes = new Uint8Array(readFileSync(join(DIR, 'reports-2026-09.zip')));
    const read = await readReportFiles([{ name: 'reports-2026-09.zip', bytes }]);
    assert.equal(read.dmarc.length, 3);
    const agg = aggregateDmarc(read.dmarc);
    const index = buildIpIndex(parseInventory('mail01 203.0.113.25\n').servers);
    const rows = new Map(agg.domains.map((a) => [a.domain, new Map(classifySources(a, { index }).map((r) => [r.ip, r]))]));
    const classify = (domain, ip) => {
      const r = rows.get(domain) && rows.get(domain).get(ip);
      return r ? { cls: r.cls, provisional: true } : null;
    };
    const now = Date.parse('2026-09-30T12:00:00Z');
    const once = mergeReports(emptyHistory({ keep: true }), read.dmarc, { now, classify });
    assert.equal(once.merged, 3);
    const h = once.history;
    assert.deepEqual(Object.keys(h.domains).sort(), ['example.com', 'example.net']);
    const total = (d) => Object.values(d.days).reduce((n, x) => n + x.msgs, 0);
    assert.equal(total(h.domains['example.com']), agg.domains.find((a) => a.domain === 'example.com').messages, 'every message of the domain');
    assert.equal(total(h.domains['example.net']), agg.domains.find((a) => a.domain === 'example.net').messages);
    // The Microsoft report begins on 2026-09-25, Google's on 2026-09-26: each on its own day.
    assert.deepEqual(Object.keys(h.domains['example.com'].days).sort(), ['2026-09-25', '2026-09-26']);
    const twice = mergeReports(h, (await readReportFiles([{ name: 'again.zip', bytes }])).dmarc, { now, classify });
    assert.deepEqual([twice.merged, twice.duplicates], [0, 3]);
    assert.equal(historyText(twice.history), historyText(h), 'the same zip dropped twice leaves the counts unchanged');
    // The DMARCbis report of example.net: its policy as published.
    assert.equal(h.domains['example.net'].policy.p, parseAggregateReport(readFileSync(join(DIR, 'src', 'mail.example.org!example.net!1790294400!1790380799.xml'), 'utf8')).report.policy.p);
  });
});
