// views/estate.js pure helpers: reading dropped report files into the open list (duplicates,
// files that are not reports, the cap), the estate of the open reports, the expiry badge variants
// and the endpoint labels, and every string key the view builds from a library code. Pure Node
// (the view is DOM-free at import time); the fixtures are the CLI's own reports
// (tests/fixtures/estate, documentation addresses only).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { listKeys } from '../../assets/js/i18n.js';
import {
  ESTATE_TABS, CLI_EXAMPLE, bucketVariant, endpointLabel, estateOfReports, importReports
} from '../../assets/js/views/estate.js';
import {
  ESTATE_BUCKETS, ESTATE_FILTERS, ESTATE_FLAGS, ESTATE_KINDS, ESTATE_MAX_REPORTS, ESTATE_WEAK_REASONS, REPORT_ERRORS
} from '../../assets/js/lib/estate.js';

const file = (name) => ({ name, text: readFileSync(new URL(`../fixtures/estate/${name}`, import.meta.url), 'utf8') });

describe('importReports', () => {
  test('reports are added in order; the same report twice is a duplicate, never a second copy', () => {
    const first = importReports([], [file('report-a.json')]);
    assert.equal(first.added, 1);
    assert.deepEqual(first.errors, []);
    const second = importReports(first.reports, [file('report-a.json'), file('report-b.json')]);
    assert.equal(second.added, 1);
    assert.deepEqual(second.duplicates, ['report-a.json']);
    assert.deepEqual(second.reports.map((r) => r.name), ['report-a.json', 'report-b.json']);
    assert.equal(first.reports.length, 1, 'the open list is not changed in place');
  });

  test('files that are not reports say why; the cap is kept', () => {
    const r = importReports([], [{ name: 'report.csv', text: 'sha256,subject_cn\n' }, { name: 'x.json', text: '{"tool":"other"}' },
      { name: 'old.json', text: '{"tool":"ssl_origin_scan","version":"0.9.0","results":[]}' }, null]);
    assert.deepEqual(r.errors.map((e) => [e.name, e.error]), [['report.csv', 'not-json'], ['x.json', 'not-report'], ['old.json', 'version'], ['', 'not-json']]);
    assert.equal(r.errors[2].detail, '0.9.0');
    const many = Array.from({ length: ESTATE_MAX_REPORTS + 2 }, (_, i) => {
      const doc = JSON.parse(file('report-b.json').text);
      doc.startedAt = `2026-10-${String(i + 1).padStart(2, '0')}T00:00:00.000Z`;
      return { name: `r${i}.json`, text: JSON.stringify(doc) };
    });
    const capped = importReports([], many);
    assert.equal(capped.reports.length, ESTATE_MAX_REPORTS);
    assert.equal(capped.capped, true);
  });
});

describe('estateOfReports', () => {
  test('nothing open: null; one or more reports: the merged estate, days counted from now', () => {
    assert.equal(estateOfReports([]), null);
    const { reports } = importReports([], [file('report-a.json'), file('report-b.json')]);
    const view = estateOfReports(reports, Date.parse('2026-10-05T12:00:00Z'));
    assert.deepEqual(view.merged.overlaps, ['192.0.2.11|443']);
    assert.equal(view.estate.counts.endpoints, 8);
    assert.equal(view.estate.counts.expiry.expired, 2, 'the weak certificate has expired by then');
  });
});

describe('small helpers', () => {
  test('badge variants and endpoint labels', () => {
    assert.deepEqual(ESTATE_BUCKETS.map(bucketVariant), ['error', 'error', 'warn', 'info', 'ok']);
    assert.equal(endpointLabel('192.0.2.10', 443), '192.0.2.10:443');
    assert.equal(endpointLabel('2001:db8::13', 8443), '[2001:db8::13]:8443');
    assert.match(CLI_EXAMPLE, /^python3 ssl_origin_scan\.py .* --estate --json estate\.json$/);
  });

  test('every key the view builds from a library code exists in EN and TR', () => {
    const keys = [
      ...ESTATE_FILTERS.map((f) => `estate.filter.${f}`),
      ...ESTATE_FLAGS.flatMap((f) => [`estate.flag.${f}`, `estate.flagTitle.${f}`]),
      ...ESTATE_KINDS.map((k) => `estate.kind.${k}`),
      ...ESTATE_BUCKETS.map((b) => `estate.bucket.${b}`),
      ...ESTATE_WEAK_REASONS.flatMap((w) => [`estate.weak.${w}`, `estate.weakShort.${w}`]),
      ...REPORT_ERRORS.map((e) => `estate.error.${e}`),
      ...ESTATE_TABS.map((tab) => `estate.tab.${tab}`)
    ];
    for (const lang of ['en', 'tr']) {
      const have = new Set(listKeys(lang));
      assert.deepEqual(keys.filter((k) => !have.has(k)), [], lang);
    }
  });
});
