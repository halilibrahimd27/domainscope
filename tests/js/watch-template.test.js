/**
 * The page template's status items of the three "Watch & report" tools (docs/DESIGN.md §5.4, §5.6;
 * redesign phase 6): Domain portfolio (lib/portfolio.js portfolioStatus) and its Certificates (CT)
 * tab (lib/ctwatch.js ctWatchStatus), Monitoring (lib/monitor.js monitorStatus) and DMARC & TLS
 * reports (lib/dmarcreport.js reportsStatus), as lib/template.js statusItems shows them. Pure Node.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { statusItems, STATUS_MAX } from '../../assets/js/lib/template.js';
import { portfolioStatus } from '../../assets/js/lib/portfolio.js';
import { ctWatchStatus, CT_WATCH_FILTERS } from '../../assets/js/lib/ctwatch.js';
import { monitorStatus, monitorRows, monitorTiles, rowMatches, MONITOR_RECENT_DAYS, MONITOR_WARN_DAYS } from '../../assets/js/lib/monitor.js';
import { reportsStatus, aggregateDmarc, parseAggregateReport } from '../../assets/js/lib/dmarcreport.js';
import { PORTFOLIO_FILTERS } from '../../assets/js/views/portfolio.js';
import { MONITOR_FILTERS, importFiles, viewOf } from '../../assets/js/views/monitor.js';
import { monitorFixture, MONITOR_NOW } from './monitor-fixture.mjs';

const keys = (list) => list.map((x) => x.key);
const shape = (list) => list.map((x) => [x.key, x.severity, x.count]);

describe('Domain portfolio: portfolioStatus', () => {
  test('expiring, critical and failed lookups are errors; no lock and name servers at risk warnings; each its Domains filter', () => {
    const items = portfolioStatus({ expiring: 1, critical: 2, failed: 1, unlocked: 1, ns: 3, changed: 0 });
    assert.deepEqual(shape(items), [
      ['expiring', 'error', 1], ['critical', 'error', 2], ['failed', 'error', 1], ['unlocked', 'warn', 1], ['ns', 'warn', 3], ['changed', 'warn', 0]
    ]);
    for (const x of items) {
      assert.equal(x.filter, x.key, `${x.key}: its own filter`);
      assert.ok(PORTFOLIO_FILTERS.includes(x.filter), `${x.key}: a filter of the table`);
      assert.equal(x.tab, 'domains');
    }
    assert.deepEqual(keys(statusItems(items)), ['expiring', 'critical', 'failed', 'unlocked', 'ns'], 'errors first, the zero left out');
  });

  test('a change since the last check: an error when one is bad, else a warning', () => {
    assert.equal(portfolioStatus({ changed: 2, changedBad: true }).find((x) => x.key === 'changed').severity, 'error');
    assert.equal(portfolioStatus({ changed: 2 }).find((x) => x.key === 'changed').severity, 'warn');
    assert.deepEqual(keys(statusItems(portfolioStatus({ changed: 2, changedBad: true, unlocked: 1 }))), ['changed', 'unlocked'], 'a bad change before the warnings');
  });

  test('six items at most, five shown: the last warning gives way', () => {
    const all = portfolioStatus({ expiring: 1, critical: 1, failed: 1, unlocked: 1, ns: 1, changed: 1 });
    assert.equal(all.length, 6);
    assert.equal(statusItems(all).length, STATUS_MAX);
    assert.deepEqual(keys(statusItems(all)), ['expiring', 'critical', 'failed', 'unlocked', 'ns']);
  });

  test('counts are whole numbers of 0 or more; nothing to say without a count', () => {
    assert.deepEqual(portfolioStatus({ expiring: 2.7, critical: -1, failed: 'x', ns: '3' }).map((x) => x.count), [2, 0, 0, 0, 3, 0]);
    assert.deepEqual(statusItems(portfolioStatus()), []);
    assert.deepEqual(statusItems(portfolioStatus(null)), []);
  });
});

describe('Domain portfolio › Certificates (CT): ctWatchStatus', () => {
  test('expiring, unexpected CA and precertificate only are warnings, new information, the current certificates a fact', () => {
    const items = ctWatchStatus({ current: 4, all: 5, expiring: 1, new: 2, unexpected: 1, wildcard: 1, precert: 1, known: 0 });
    assert.deepEqual(shape(items), [['expiring', 'warn', 1], ['unexpected', 'warn', 1], ['precert', 'warn', 1], ['new', 'info', 2], ['current', 'neutral', 4]]);
    for (const x of items) assert.ok(CT_WATCH_FILTERS.includes(x.filter) && x.filter === x.key, x.key);
    assert.equal(items.length, STATUS_MAX, 'five at most: wildcards stay in the metric strip');
    assert.deepEqual(keys(statusItems(ctWatchStatus({ current: 5, new: 0, precert: 0 }))), ['current'], 'a second check with nothing new');
    assert.deepEqual(statusItems(ctWatchStatus(null)), []);
  });
});

describe('Monitoring: monitorStatus', () => {
  test('the fixture: 3 targets with bad changes, 2 certificates, 2 checks that did not complete, 5 targets', () => {
    const { data } = importFiles(null, monitorFixture().files);
    const rows = monitorRows(data, { now: MONITOR_NOW });
    const tiles = monitorTiles(rows);
    assert.deepEqual(viewOf(data, MONITOR_NOW).tiles, tiles, 'what the view counts');
    const items = monitorStatus(tiles);
    assert.deepEqual(shape(items), [['bad', 'error', 3], ['expiring', 'warn', 2], ['incomplete', 'warn', 2], ['targets', 'neutral', 5]]);
    for (const x of items) {
      assert.ok(MONITOR_FILTERS.includes(x.filter), `${x.key}: a filter of the table`);
      assert.equal(x.tab, 'targets');
    }
    // each filter keeps the rows its item counts (the certificates and checks are counted by target there)
    assert.equal(rows.filter((r) => rowMatches(r, 'bad')).length, 3);
    assert.equal(rows.filter((r) => rowMatches(r, 'all')).length, 5);
    assert.deepEqual(keys(statusItems(items)), ['bad', 'expiring', 'incomplete', 'targets']);
    assert.ok(MONITOR_RECENT_DAYS === 7 && MONITOR_WARN_DAYS === 21);
  });

  test('a quiet night: only the targets; nothing open: nothing to say', () => {
    assert.deepEqual(keys(statusItems(monitorStatus({ targets: 4, bad: [], expiring: [], incomplete: [] }))), ['targets']);
    assert.deepEqual(statusItems(monitorStatus(null)), []);
    assert.deepEqual(monitorStatus({ targets: -2, bad: 'x' }).map((x) => x.count), [0, 0, 0, 0]);
  });
});

describe('DMARC & TLS reports: reportsStatus', () => {
  const feedback = (domain, rows) => `<?xml version="1.0"?><feedback><report_metadata><org_name>example.org</org_name><report_id>${domain}-1</report_id>
<date_range><begin>1790294400</begin><end>1790380799</end></date_range></report_metadata><policy_published><domain>${domain}</domain><p>none</p></policy_published>
${rows.map(([ip, count, ok]) => `<record><row><source_ip>${ip}</source_ip><count>${count}</count><policy_evaluated><disposition>none</disposition>
<dkim>${ok ? 'pass' : 'fail'}</dkim><spf>${ok ? 'pass' : 'fail'}</spf></policy_evaluated></row><identifiers><header_from>${domain}</header_from></identifiers>
<auth_results><spf><domain>${domain}</domain><result>${ok ? 'pass' : 'fail'}</result></spf></auth_results></record>`).join('')}</feedback>`;

  test('the failing messages and the failed TLS sessions of every domain read, then the messages, the addresses and the sessions', () => {
    const dmarc = aggregateDmarc([
      parseAggregateReport(feedback('example.com', [['192.0.2.1', 100, true], ['198.51.100.7', 12, false]])).report,
      parseAggregateReport(feedback('example.net', [['203.0.113.9', 5, false]])).report
    ]);
    const tls = { domains: [{ domain: 'example.com', success: 990, failure: 10 }, { domain: 'example.net', success: 0, failure: 0 }] };
    const items = reportsStatus({ dmarc, tls });
    assert.deepEqual(shape(items), [['failing', 'error', 17], ['tlsFailed', 'error', 10], ['messages', 'neutral', 117], ['senders', 'neutral', 3], ['sessions', 'neutral', 1000]]);
    assert.deepEqual(items.map((x) => x.tab), ['dmarc', 'tls', 'dmarc', 'dmarc', 'tls'], 'each opens the tab that lists it');
    assert.deepEqual(keys(statusItems(items)), ['failing', 'tlsFailed', 'messages', 'senders', 'sessions']);
  });

  test('DMARC reports alone, TLS reports alone, none', () => {
    const dmarc = aggregateDmarc([parseAggregateReport(feedback('example.org', [['192.0.2.5', 40, true]])).report]);
    assert.deepEqual(keys(statusItems(reportsStatus({ dmarc }))), ['messages', 'senders'], 'every message passes: no "0 failing"');
    assert.deepEqual(keys(statusItems(reportsStatus({ tls: { domains: [{ success: 3, failure: 1 }] } }))), ['tlsFailed', 'sessions']);
    assert.deepEqual(statusItems(reportsStatus()), []);
    assert.deepEqual(statusItems(reportsStatus({ dmarc: { domains: [null, { messages: -4, fail: 'x', sources: null }] } })), []);
  });
});
