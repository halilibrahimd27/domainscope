/**
 * lib/tlsrpt.js — SMTP TLS reports (RFC 8460): a Google- and a Microsoft-style report read into
 * plain objects (MTA-STS, TLSA and no-policy-found policies, every failure detail, a reporter's
 * variations), what is no TLS report, the per-domain summary (a report dropped twice counts once,
 * failures by type and MX host), the advice each failure type points at and the CSV rows.
 * Pure Node, no network; documentation data only (tests/fixtures/mailreports/src).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  TLS_RESULT_TYPES, TLS_POLICY_TYPES, TLS_REPORT_ERRORS, TLS_CSV_COLUMNS, TLS_ADVICE_AREAS, parseTlsReport, summarizeTls, tlsAdvice, tlsCsvRows
} from '../../assets/js/lib/tlsrpt.js';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'mailreports', 'src');
const src = (name) => readFileSync(join(SRC, name), 'utf8');
const GOOGLE = 'google.com!example.com!1790380800!1790467199!001.json';
const MICROSOFT = 'microsoft.com!example.com!1790294400!1790380800.json';
const read = (name) => {
  const r = parseTlsReport(src(name), { file: name });
  assert.ok(r.ok, JSON.stringify(r));
  return r.report;
};

describe('parseTlsReport — RFC 8460 §4.4', () => {
  test('a Google-style report: one MTA-STS policy in testing mode, three failure types', () => {
    const r = read(GOOGLE);
    assert.equal(r.kind, 'tlsrpt');
    assert.equal(r.org, 'Google Inc.');
    assert.equal(r.contact, 'smtp-tls-reporting@google.com');
    assert.equal(r.reportId, '2026-09-26T00:00:00Z_example.com');
    assert.equal(r.key, 'google inc.|2026-09-26T00:00:00Z_example.com');
    assert.equal(r.begin.toISOString(), '2026-09-26T00:00:00.000Z');
    assert.equal(r.end.toISOString(), '2026-09-26T23:59:59.000Z');
    assert.equal(r.file, GOOGLE);
    assert.deepEqual([r.success, r.failure], [5326, 49]);
    const [p] = r.policies;
    assert.deepEqual([p.type, p.domain, p.mode, p.mx], ['sts', 'example.com', 'testing', ['mx1.example.com', 'mx2.example.com']]);
    assert.equal(p.strings.length, 5);
    assert.deepEqual(p.failures[0], {
      type: 'certificate-expired', known: true, sendingIp: '198.51.100.61', mx: 'mx2.example.com', helo: null, receivingIp: '203.0.113.27',
      sessions: 40, reason: null, info: null
    });
    assert.equal(p.failures[1].receivingIp, '2001:db8:25::27');
    assert.equal(p.failures[2].reason, 'HTTP 404 for https://mta-sts.example.com/.well-known/mta-sts.txt');
  });

  test('a Microsoft-style report on one line: no-policy-found with no failure, a TLSA policy with two', () => {
    const r = read(MICROSOFT);
    assert.equal(r.org, 'Microsoft Corporation');
    assert.deepEqual(r.policies.map((p) => [p.type, p.success, p.failure, p.failures.length]), [['no-policy-found', 812, 0, 0], ['tlsa', 0, 14, 2]]);
    assert.equal(r.policies[1].strings[0].startsWith('3 1 1 '), true);
    const [starttls, validation] = r.policies[1].failures;
    assert.deepEqual([starttls.type, starttls.mx, starttls.receivingIp, starttls.info], ['starttls-not-supported', 'mx-backup.example.com', '192.0.2.53', 'https://tlsrpt.example.org/info?id=starttls']);
    assert.equal(validation.reason, 'X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY');
  });

  test('variations: mx-host-pattern, counts as strings, capitals, an unknown type, a trailing dot', () => {
    const r = parseTlsReport({
      'organization-name': 'Example Mail', 'date-range': { 'start-datetime': 'bad', 'end-datetime': '2026-09-26T23:59:59Z' }, 'report-id': 'x1',
      policies: [{
        policy: { 'policy-type': 'STS', 'policy-domain': 'Example.COM.', 'mx-host-pattern': ['*.example.com'], 'policy-string': ['mode: Enforce'] },
        summary: { 'total-successful-session-count': '10', 'total-failure-session-count': -3 },
        'failure-details': [{ 'result-type': 'Certificate-Expired', 'failed-session-count': '2', 'receiving-mx-hostname': 'MX1.example.com.' }, { 'result-type': 'vendor-specific-thing', 'failed-session-count': 1 }, null]
      }]
    });
    assert.ok(r.ok);
    const [p] = r.report.policies;
    assert.deepEqual([p.type, p.domain, p.mode, p.mx, p.success, p.failure], ['sts', 'example.com', 'enforce', ['*.example.com'], 10, 0]);
    assert.deepEqual(p.failures.map((f) => [f.type, f.known, f.sessions, f.mx]), [['certificate-expired', true, 2, 'mx1.example.com'], ['vendor-specific-thing', false, 1, null]]);
    assert.equal(r.report.begin, null);
  });

  test('what is no TLS report says why', () => {
    assert.equal(parseTlsReport('{"policies": [').code, 'not-json');
    assert.equal(parseTlsReport('[1,2]').code, 'not-tlsrpt');
    assert.equal(parseTlsReport('{"hello": 1}').code, 'not-tlsrpt');
    assert.deepEqual(parseTlsReport({ 'report-id': 'x', policies: [] }), { ok: false, code: 'incomplete', detail: 'organization-name' });
    assert.deepEqual(parseTlsReport({ 'organization-name': 'x', policies: [{ policy: {} }] }), { ok: false, code: 'incomplete', detail: 'policies' });
    for (const c of ['not-json', 'not-tlsrpt', 'incomplete']) assert.ok(TLS_REPORT_ERRORS.includes(c));
  });
});

describe('summarizeTls — a policy domain\'s reports together', () => {
  test('sessions, the success rate, senders, policies, failures by type and by MX host; a duplicate counts once', () => {
    const { domains, duplicates } = summarizeTls([read(GOOGLE), read(MICROSOFT), read(GOOGLE)]);
    assert.equal(duplicates, 1);
    assert.equal(domains.length, 1);
    const d = domains[0];
    assert.deepEqual([d.domain, d.reports, d.success, d.failure], ['example.com', 2, 6138, 63]);
    assert.equal(Math.round(d.rate * 1000), 990);
    assert.equal(d.begin.toISOString(), '2026-09-25T00:00:00.000Z');
    assert.deepEqual(d.orgs.map((o) => [o.org, o.reports, o.success, o.failure]), [['Google Inc.', 1, 5326, 49], ['Microsoft Corporation', 1, 812, 14]]);
    assert.deepEqual(d.policies.map((p) => [p.type, p.mode, p.success, p.failure]), [['sts', 'testing', 5326, 49], ['no-policy-found', null, 812, 0], ['tlsa', null, 0, 14]]);
    assert.deepEqual(d.byType.map((t) => [t.type, t.sessions]), [
      ['certificate-expired', 40], ['starttls-not-supported', 9], ['certificate-host-mismatch', 6], ['validation-failure', 5], ['sts-policy-fetch-error', 3]
    ]);
    assert.deepEqual(d.byType[0].mx, ['mx2.example.com']);
    assert.deepEqual(d.byType[0].orgs, ['Google Inc.']);
    assert.deepEqual(d.byMx.map((m) => [m.mx, m.sessions, m.types]), [
      ['mx2.example.com', 46, ['certificate-expired', 'certificate-host-mismatch']],
      ['mx-backup.example.com', 14, ['starttls-not-supported', 'validation-failure']],
      ['mx1.example.com', 3, ['sts-policy-fetch-error']]
    ]);
    assert.equal(d.failures.length, 5);
    assert.equal(d.failures[0].failed_sessions, 40);
  });

  test('no reports, no sessions: an empty list and a null rate', () => {
    assert.deepEqual(summarizeTls([]), { domains: [], duplicates: 0 });
    const r = parseTlsReport({ 'organization-name': 'x', 'report-id': 'y', policies: [{ policy: { 'policy-type': 'sts', 'policy-domain': 'example.net' }, summary: {} }] });
    assert.equal(summarizeTls([r.report]).domains[0].rate, null);
  });
});

test('tlsAdvice: every RFC 8460 type points at what to fix and the check that goes deeper', () => {
  for (const type of TLS_RESULT_TYPES) {
    const a = tlsAdvice(type);
    assert.equal(a.type, type);
    assert.ok(TLS_ADVICE_AREAS.includes(a.area), type);
    assert.ok(a.tools.length > 0, type);
  }
  assert.deepEqual(tlsAdvice('sts-policy-fetch-error'), { type: 'sts-policy-fetch-error', area: 'sts-policy', tools: ['health'] });
  assert.deepEqual(tlsAdvice('dnssec-invalid'), { type: 'dnssec-invalid', area: 'dane', tools: ['tlsa'] });
  assert.deepEqual(tlsAdvice('certificate-expired'), { type: 'certificate-expired', area: 'certificate', tools: ['cert'] });
  assert.deepEqual(tlsAdvice('vendor-thing'), { type: 'other', area: 'other', tools: [] });
  assert.deepEqual(TLS_POLICY_TYPES, ['sts', 'tlsa', 'no-policy-found']);
  assert.equal(TLS_RESULT_TYPES.length, 11);
});

test('tlsCsvRows: one row per failure detail with every column', () => {
  const { domains } = summarizeTls([read(GOOGLE), read(MICROSOFT)]);
  const rows = tlsCsvRows(domains[0]);
  assert.equal(rows.length, 5);
  for (const r of rows) assert.deepEqual(Object.keys(r), [...TLS_CSV_COLUMNS]);
  assert.deepEqual(rows[0], {
    policy_domain: 'example.com', organization: 'Google Inc.', report_id: '2026-09-26T00:00:00Z_example.com',
    begin: '2026-09-26T00:00:00.000Z', end: '2026-09-26T23:59:59.000Z', policy_type: 'sts', result_type: 'certificate-expired',
    receiving_mx: 'mx2.example.com', receiving_ip: '203.0.113.27', sending_mta_ip: '198.51.100.61', failed_sessions: 40,
    failure_reason_code: '', additional_information: ''
  });
  assert.deepEqual(tlsCsvRows(null), []);
});
