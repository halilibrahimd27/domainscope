// Unit tests for assets/js/lib/estate.js — the certificate estate of `ssl_origin_scan.py --json`
// reports (the Certificate estate view): reading report files, merging several, the estate itself
// (the CLI's estate_from_report: each report's own `estate` section in tests/fixtures/estate must
// come out exactly), the filters and the CSV. Pure: the fixture reports are what the CLI writes
// over a made-up network (tests/python/test_estate.py keeps them so).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  ESTATE_BUCKETS, ESTATE_CSV_COLUMNS, ESTATE_FILTERS, ESTATE_FLAGS, ESTATE_KINDS, ESTATE_MAX_BYTES, REPORT_ERRORS,
  estateCsv, estateCsvRows, estateFilterCounts, estateMatches, estateOf, expiryBucket, keyLabel, mergeReports,
  readEstateReport, weakReasons
} from '../../assets/js/lib/estate.js';

const text = (f) => readFileSync(new URL(`../fixtures/estate/${f}`, import.meta.url), 'utf8');
const docA = () => JSON.parse(text('report-a.json'));
const docB = () => JSON.parse(text('report-b.json'));
const WWW = 'www.example-test.com.tr';
const WILD = 'a.wild.example.net';
const byCn = (estate, cn) => estate.certificates.filter((c) => c.subjectCN === cn);

describe('the rules shared with the CLI', () => {
  test('expiry buckets by whole days left', () => {
    const cases = [[-1, 'expired'], [0, '7d'], [6, '7d'], [7, '30d'], [29, '30d'], [30, '90d'], [89, '90d'], [90, 'later']];
    for (const [days, bucket] of cases) assert.equal(expiryBucket(days), bucket, String(days));
    assert.deepEqual(ESTATE_BUCKETS, ['expired', '7d', '30d', '90d', 'later']);
  });

  test('weak keys and signatures, key labels', () => {
    assert.deepEqual(weakReasons('RSA', 1024, 'sha1WithRSAEncryption'), ['rsa-short', 'sha1']);
    assert.deepEqual(weakReasons('RSA', 2048, 'sha256WithRSAEncryption'), []);
    assert.deepEqual(weakReasons('EC', 256, 'ecdsa-with-SHA1'), ['sha1']);
    assert.deepEqual(weakReasons('RSA', 1024, 'md2WithRSAEncryption'), ['rsa-short', 'md5']);
    assert.deepEqual(weakReasons('RSA', null, null), []);
    assert.equal(keyLabel('RSA', 2048, null), 'RSA 2048');
    assert.equal(keyLabel('EC', 256, 'P-256'), 'EC P-256');
    assert.equal(keyLabel('EC', null, null), 'EC');
    assert.equal(keyLabel('Ed25519', 256, null), 'Ed25519');
    assert.equal(keyLabel(null, null, null), 'unknown');
  });
});

describe('readEstateReport', () => {
  test('a report of the CLI, with and without --estate', () => {
    const r = readEstateReport(text('report-a.json'), { name: 'report-a.json' });
    assert.equal(r.ok, true);
    assert.equal(r.report.name, 'report-a.json');
    assert.equal(r.report.estate, true);
    assert.equal(r.report.keyHashes, true);
    assert.equal(r.report.finishedAt.toISOString(), '2026-09-28T12:00:00.000Z');
    const plain = docA();
    delete plain.estate;
    delete plain.options.estate;
    const p = readEstateReport(`﻿${JSON.stringify(plain)}`);
    assert.equal(p.ok, true, 'a BOM is fine');
    assert.equal(p.report.estate, false);
    assert.equal(p.report.id, r.report.id, 'the same scan read twice has the same id');
    for (const entry of Object.values(plain.certificates)) delete entry.spkiSha256;
    assert.equal(readEstateReport(JSON.stringify(plain)).report.keyHashes, false);
  });

  test('what is not a report says why', () => {
    const err = (t) => readEstateReport(t).error;
    assert.equal(err('{nope'), 'not-json');
    assert.equal(err('[]'), 'not-report');
    assert.equal(err('{"tool":"something"}'), 'not-report');
    assert.equal(err('{"tool":"ssl_origin_scan","version":"2.0.0","results":[]}'), 'version');
    assert.equal(readEstateReport('{"tool":"ssl_origin_scan","version":"2.0.0","results":[]}').detail, '2.0.0');
    assert.equal(err('{"tool":"ssl_origin_scan","version":"1.3.0"}'), 'no-results');
    assert.equal(err(' '.repeat(ESTATE_MAX_BYTES + 1)), 'too-large');
    assert.equal(err(undefined), 'not-json');
    assert.deepEqual(REPORT_ERRORS, ['too-large', 'not-json', 'not-report', 'version', 'no-results']);
  });
});

describe('estateOf — the CLI\'s estate_from_report', () => {
  test('each fixture report\'s own estate section comes out exactly', () => {
    for (const doc of [docA(), docB()]) {
      const { estate } = doc;
      delete doc.estate;
      assert.deepEqual(estateOf(doc, { now: Date.parse(doc.finishedAt) }), estate);
      assert.deepEqual(estateOf(doc), estate, 'now defaults to the report\'s finishedAt');
    }
  });

  test('site A: what the estate finds', () => {
    const estate = estateOf(docA());
    assert.equal(estate.counts.certificates, 9);
    assert.deepEqual(estate.counts.expiry, { expired: 1, '7d': 1, '30d': 1, '90d': 0, later: 6 });
    assert.deepEqual(estate.counts.kinds, { 'origin-ca': 1, 'self-signed': 6, 'private-ca': 1, other: 1 });
    assert.deepEqual(estate.nameConflicts.map((c) => c.name), [WWW, WILD]);
    const wild = estate.nameConflicts[1].certificates;
    assert.deepEqual(wild.map((c) => c.stale), [false, true, false], 'the old wildcard next to its renewal; the Origin CA one is another kind');
    assert.deepEqual(estate.sharedKeys[0].servers, ['web03', 'legacy-a', 'legacy-b']);
    assert.equal(estate.sharedKeys[0].certificates.length, 2);
    assert.deepEqual(estate.weakKeys.map((w) => w.reasons), [['rsa-short', 'sha1'], ['rsa-short', 'md5']]);
    assert.equal(estate.coversNone.length, 3);
    for (const cert of estate.certificates) for (const f of cert.flags) assert.ok(ESTATE_FLAGS.includes(f));
    assert.ok(estate.certificates.every((c) => ESTATE_KINDS.includes(c.kind)));
  });

  test('now moves the buckets: a week later the weak certificate has expired', () => {
    const estate = estateOf(docA(), { now: Date.parse('2026-10-05T12:00:00Z') });
    assert.equal(byCn(estate, WWW).find((c) => c.key === 'RSA 1024').expiry, 'expired');
    assert.equal(estate.counts.expiry.expired, 2);
  });

  test('a report of an older CLI: names from the rows, kinds from selfSigned, no key hashes', () => {
    const doc = docA();
    delete doc.estate;
    delete doc.names;
    delete doc.endpoints;
    for (const entry of Object.values(doc.certificates)) {
      delete entry.kind;
      delete entry.spkiSha256;
    }
    const estate = estateOf(doc);
    assert.deepEqual(estate.namesAsked, [WWW, WILD]);
    assert.deepEqual(estate.sharedKeys, []);
    assert.deepEqual(estate.counts.kinds, { 'origin-ca': 0, 'self-signed': 6, 'private-ca': 0, other: 3 });
    assert.equal(estate.counts.endpoints, 7);
    assert.equal(estate.counts.openEndpoints, 6);
  });

  test('no names asked: coverage stays open; junk rows are skipped', () => {
    const doc = docA();
    delete doc.estate;
    doc.names = [];
    doc.results = doc.results.filter((r) => r.probe === 'default' || r.probe === 'connect');
    doc.results.push(null, { probe: 'sni', ip: 5, port: 443 }, { probe: 'default', ip: '192.0.2.99', port: 443, certSha256: 'nope' });
    const estate = estateOf(doc);
    assert.equal(estate.coversNone, null);
    assert.deepEqual(estate.nameConflicts, []);
    assert.ok(estate.certificates.every((c) => !c.flags.includes('covers-none')));
    assert.deepEqual(estateOf(null).certificates, []);
  });
});

describe('mergeReports', () => {
  test('one report comes back as it is', () => {
    const doc = docA();
    const merged = mergeReports([{ doc }]);
    assert.equal(merged.doc, doc);
    assert.deepEqual(merged.overlaps, []);
    assert.equal(merged.origin.get('192.0.2.10|443'), 0);
  });

  test('an endpoint both reports scanned takes the newer report\'s answers', () => {
    const [a, b] = [docA(), docB()];
    for (const order of [[a, b], [b, a]]) {
      const merged = mergeReports(order.map((doc) => ({ doc })));
      assert.deepEqual(merged.overlaps, ['192.0.2.11|443']);
      const newer = order.indexOf(b);
      assert.equal(merged.origin.get('192.0.2.11|443'), newer);
      assert.equal(merged.doc.finishedAt, b.finishedAt);
      const estate = estateOf(merged.doc, { now: Date.parse(b.finishedAt) });
      assert.deepEqual(estate.namesAsked.sort(), ['a.wild.example.net', 'api.example-test.com.tr', WWW].sort());
      // web02 serves the renewed wildcard without SNI now (report B); web01 still the legacy one (report A)
      const legacy = byCn(estate, 'legacy.example.org')[0];
      assert.deepEqual(legacy.endpoints.map((e) => e.servers), [['web01']]);
      const renewed = estate.certificates.find((c) => c.sha256 === '773223c65605a70c8fef4da270b24e8ce1874cf142e64ba827d2ba7ac134003f');
      // both reports put it on web02: B without SNI, A for the wildcard name
      assert.deepEqual(merged.sources.get(`192.0.2.11|443|${renewed.sha256}`).sort(), [0, 1]);
      const legacySha = byCn(estate, 'legacy.example.org')[0].sha256;
      assert.deepEqual(merged.sources.get(`192.0.2.10|443|${legacySha}`), [order.indexOf(a)]);
      // without SNI from report B; for a.wild.example.net, which only report A asked, from A
      assert.deepEqual(renewed.endpoints.map((e) => [e.servers, e.defaultCert, e.names]), [[['web02'], true, [WILD]]]);
      assert.equal(estate.nameConflicts.find((c) => c.name === WILD).certificates.length, 3, 'the renewal still next to the old wildcard');
      assert.equal(estate.counts.endpoints, 8, 'A\'s 7 and B\'s web05; web02 once');
      // the public RSA certificate: web01, web02 (A, B) and web05 (B) - one key on three hosts
      const rsa = estate.sharedKeys.find((g) => g.key === 'RSA 2048' && g.servers.includes('web05'));
      assert.deepEqual(rsa.servers.sort(), ['web01', 'web02', 'web05']);
    }
  });

  test('a port the newer report found closed drops the older answers there', () => {
    const b = docB();
    b.results = b.results.filter((r) => r.ip !== '192.0.2.11');
    b.results.push({ server: 'web02', ip: '192.0.2.11', port: 443, probe: 'connect', name: null, sni: null, status: 'CLOSED', error: 'connection refused' });
    b.endpoints = b.endpoints.map((e) => (e.ip === '192.0.2.11' ? { ...e, state: 'CLOSED', error: 'connection refused' } : e));
    const merged = mergeReports([{ doc: docA() }, { doc: b }]);
    const estate = estateOf(merged.doc, { now: Date.parse(b.finishedAt) });
    assert.ok(estate.certificates.every((c) => c.endpoints.every((e) => e.ip !== '192.0.2.11')), 'nothing served at web02 any more');
    assert.equal(estate.counts.openEndpoints, 6, 'A\'s other 5 and web05');
    assert.ok(!estate.certificates.some((c) => c.sha256 === '773223c65605a70c8fef4da270b24e8ce1874cf142e64ba827d2ba7ac134003f'), 'the renewal was only there');
  });

  test('junk in the list is skipped, a report without endpoints is counted from its rows', () => {
    const b = docB();
    delete b.endpoints;
    const merged = mergeReports([null, { doc: docA() }, { nope: 1 }, { doc: b }]);
    assert.equal(merged.doc.endpoints, undefined);
    assert.equal(estateOf(merged.doc).counts.endpoints, 8);
    assert.deepEqual(mergeReports([]).overlaps, []);
  });
});

describe('filters and CSV', () => {
  test('every filter, and its counts', () => {
    const estate = estateOf(docA());
    const counts = estateFilterCounts(estate);
    assert.deepEqual(Object.keys(counts), [...ESTATE_FILTERS]);
    assert.equal(counts.all, 9);
    assert.equal(counts.expiring, 3);
    assert.equal(counts['name-conflict'], 5);
    assert.equal(counts.weak, 2);
    assert.equal(counts['covers-none'], 3);
    assert.equal(counts.private, 7);
    assert.equal(counts['origin-ca'], 1);
    assert.equal(counts.attention, estate.certificates.filter((c) => c.flags.length || ['expired', '7d', '30d'].includes(c.expiry)).length);
    assert.equal(estateMatches(null, 'all'), false);
    assert.deepEqual(estateFilterCounts(null).all, 0);
  });

  test('one row per certificate, endpoint and server, as the CLI writes them', () => {
    const doc = docA();
    const estate = estateOf(doc);
    const rows = estateCsvRows(estate);
    assert.equal(rows.length, estate.certificates.reduce((n, c) => n + c.endpoints.reduce((m, e) => m + e.servers.length, 0), 0));
    const md5 = rows.filter((r) => r.weak === 'rsa-short md5');
    assert.deepEqual(md5.map((r) => r.server), ['legacy-a', 'legacy-b']);
    assert.equal(md5[0].default_cert, 'yes');
    assert.equal(md5[0].flags, 'shared-key weak covers-none');
    const csv = estateCsv(estate);
    assert.ok(csv.startsWith('﻿sha256,subject_cn,issuer,kind,not_after,days_left,expiry,key,'));
    assert.deepEqual(csv.split('\r\n')[0].replace('﻿', '').split(','), ESTATE_CSV_COLUMNS.map((c) => c.key));
    // a filtered view, and the report of each row when several are merged
    const weak = estate.certificates.filter((c) => estateMatches(c, 'weak'));
    const some = estateCsvRows(estate, { certificates: weak, reportName: () => 'report-a.json' });
    assert.equal(some.length, 3);
    assert.equal(some[0].report, 'report-a.json');
    assert.ok(estateCsv(estate, { reportName: () => 'x' }).split('\r\n')[0].endsWith(',report'));
  });

  test('a certificate field that looks like a formula stays text', () => {
    const doc = docA();
    const sha = Object.keys(doc.certificates)[0];
    doc.certificates[sha].subjectCN = '=HYPERLINK("x")';
    for (const row of doc.results) if (row.certSha256 === sha) row.server = '@web';
    const csv = estateCsv(estateOf(doc));
    assert.match(csv, /'=HYPERLINK\(""x""\)/);
    assert.match(csv, /,'@web,/);
  });
});
