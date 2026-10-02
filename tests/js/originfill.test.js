/**
 * What each source tells the origin map (lib/originfill.js): a zone file's exact origins, the
 * CLI's --json reports (read with the Certificate estate's reader), Verify's origin checks and
 * the old / new server comparison — each turned into observations and applied with the merge
 * rules. Example names and documentation addresses only. No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  zoneObservations, cliReportObservations, readCliReports, verifyObservations, compareObservations, outcomeOf,
  applyObservations, addManualOrigin, setRemember, HOSTED_STATUSES
} from '../../assets/js/lib/originfill.js';
import { originKey, knownForScan } from '../../assets/js/lib/originmap.js';
import { proxiedOriginMap } from '../../assets/js/lib/zoneorigins.js';
import { loadFixture } from '../fixtures/zones-analysis/gen-analysis-golden.mjs';

const ON = setRemember(null, true);
const AT = '2026-10-01T08:00:00.000Z';
const fixture = (name) => readFile(new URL(`../fixtures/estate/${name}`, import.meta.url), 'utf8');

/** A minimal CLI --json report (the fields the reader and the filler use). */
function report({ finishedAt = AT, rows }) {
  return {
    tool: 'ssl_origin_scan', version: '1.0.0', startedAt: finishedAt, finishedAt,
    names: [...new Set(rows.filter((r) => r.name).map((r) => r.name))].map((name) => ({ name, sni: name, wildcard: false })),
    results: rows.map((r) => ({ probe: r.name ? 'sni' : 'default', sni: r.name || null, port: 443, server: null, ...r })),
    certificates: {}
  };
}

describe('outcomes', () => {
  test('every covering certificate serves the name (PRIVATE_CERT too: a self-signed or private-CA one); NOT_HOSTED does not; the rest is no answer', () => {
    assert.deepEqual([...HOSTED_STATUSES], ['UPDATED', 'NEEDS_UPDATE', 'ORIGIN_CERT', 'PRIVATE_CERT']);
    assert.deepEqual(['UPDATED', 'NEEDS_UPDATE', 'ORIGIN_CERT', 'PRIVATE_CERT', 'NOT_HOSTED', 'TLS_ERROR', 'TIMEOUT', 'CLOSED', null].map(outcomeOf),
      ['hosted', 'hosted', 'hosted', 'hosted', 'not-hosted', 'unknown', 'unknown', 'unknown', 'unknown']);
  });

  test('a Cloudflare "Full" origin with a self-signed certificate is remembered from a report and from Verify', () => {
    const doc = report({ rows: [{ name: 'shop.example.com', ip: '203.0.113.10', status: 'PRIVATE_CERT', server: 'web03' }] });
    let res = applyObservations(ON, cliReportObservations(doc).observations, { source: 'cli-json', at: AT });
    assert.deepEqual(res.added, ['shop.example.com|203.0.113.10|443']);
    const rows = [{ state: 'done', stale: false, proxied: true, via: 'known', ip: '203.0.113.10', port: 443, name: 'shop.example.com', server: { id: 's1', name: 'web03' }, status: 'PRIVATE_CERT' }];
    res = applyObservations(res.map, verifyObservations(rows), { source: 'verify', at: '2026-10-01T09:00:00.000Z' });
    assert.deepEqual(res.confirmed, ['shop.example.com|203.0.113.10|443']);
  });
});

describe('Zone File › Origins & servers', () => {
  test('every exact address of a proxied name, without a port; host, Tunnel and provider origins are no address', () => {
    const rows = proxiedOriginMap(loadFixture('cloudflare-export'));
    const obs = zoneObservations(rows);
    assert.deepEqual(obs.map((o) => `${o.name} ${o.ip}`), [
      'example.com 192.0.2.10', 'api.example.com 192.0.2.13', '*.apps.example.com 192.0.2.20', 'docs.example.com 192.0.2.10',
      'docs.example.com 2001:db8::10', 'mixed.example.com 192.0.2.30', 'mixed.example.com 192.0.2.31', 'tagged.example.com 192.0.2.40',
      'www.example.com 192.0.2.10', 'www.example.com 2001:db8::10'
    ]);
    assert.ok(obs.every((o) => o.port === null && o.outcome === 'hosted'));
    const { map, added } = applyObservations(ON, obs, { source: 'zone', at: AT });
    assert.equal(added.length, 10);
    assert.ok(map.entries.every((e) => e.port === 443 && e.source === 'zone'));
    assert.deepEqual(zoneObservations(null), []);
  });
});

describe('the CLI --json reports', () => {
  test('a report of the estate fixture: hosted (private certificates too), not hosted and Origin CA names', async () => {
    const { reports, errors } = readCliReports([{ name: 'report-a.json', text: await fixture('report-a.json') }]);
    assert.deepEqual(errors, []);
    const [r] = reports;
    assert.equal(r.at, '2026-09-28T12:00:00.000Z');
    assert.deepEqual(r.originCertNames, ['a.wild.example.net']);
    const hosted = r.observations.filter((o) => o.outcome === 'hosted').map((o) => `${o.name} ${o.ip} ${o.server}`).sort();
    assert.deepEqual(hosted, [
      'a.wild.example.net 192.0.2.10 web01',
      'a.wild.example.net 192.0.2.11 web02',
      'a.wild.example.net 198.51.100.20 origin',
      'www.example-test.com.tr 192.0.2.10 web01',
      'www.example-test.com.tr 192.0.2.11 web02',
      'www.example-test.com.tr 2001:db8::13 web03'
    ], 'PRIVATE_CERT on web01, web02 and web03 is a covering certificate');
    assert.ok(r.observations.some((o) => o.outcome === 'not-hosted' && o.ip === '198.51.100.20' && o.name === 'www.example-test.com.tr'));
    assert.ok(!r.observations.some((o) => o.ip === '198.51.100.21'), 'a closed port (a connect row) is no observation');
  });

  test('only names known to be behind a CDN are added: here the Origin CA one', async () => {
    const { reports } = readCliReports([{ name: 'report-a.json', text: await fixture('report-a.json') }]);
    const [r] = reports;
    const origin = new Set(r.originCertNames);
    const res = applyObservations(ON, r.observations, { source: 'cli-json', at: r.at, proxied: (n) => origin.has(n) });
    assert.deepEqual(res.added, ['a.wild.example.net|192.0.2.10|443', 'a.wild.example.net|192.0.2.11|443', 'a.wild.example.net|198.51.100.20|443']);
    assert.deepEqual(res.skipped, ['www.example-test.com.tr']);
    assert.equal(res.map.entries.find((e) => e.ip === '198.51.100.20').server, 'origin', 'the CLI\'s server name');
  });

  test('a later report that finds the name on another server marks the remembered origin stale', () => {
    let { map } = applyObservations(ON, [{ name: 'shop.example.com', ip: '203.0.113.10', port: 443, outcome: 'hosted' }], { source: 'zone', at: '2026-09-20T08:00:00Z' });
    const doc = report({
      rows: [
        { name: 'shop.example.com', ip: '203.0.113.10', status: 'NOT_HOSTED', server: 'web03' },
        { name: 'shop.example.com', ip: '198.51.100.20', status: 'UPDATED', server: 'web05' },
        { name: 'shop.example.com', ip: '198.51.100.21', status: 'TIMEOUT', server: 'web06' },
        { name: 'api.example.com', ip: '198.51.100.20', status: 'NEEDS_UPDATE', server: 'web05' }
      ]
    });
    const { reports, errors } = readCliReports([{ name: 'r.json', text: JSON.stringify(doc) }]);
    assert.deepEqual(errors, []);
    const res = applyObservations(map, reports[0].observations, { source: 'cli-json', at: reports[0].at, proxied: (n) => n === 'shop.example.com' });
    ({ map } = res);
    assert.deepEqual(res.added, ['shop.example.com|198.51.100.20|443']);
    assert.deepEqual(res.skipped, ['api.example.com']);
    assert.deepEqual(res.staled, ['shop.example.com|203.0.113.10|443']);
    const stale = map.entries.find((e) => originKey(e) === 'shop.example.com|203.0.113.10|443').stale;
    assert.deepEqual(stale, { reason: 'cli-elsewhere', at: AT, ip: '198.51.100.20', port: 443 });
    assert.deepEqual(knownForScan(map).map((k) => `${k.ip} ${k.server}`), ['198.51.100.20 web05']);
  });

  test('an undated report is read last: it is applied as now', () => {
    const dated = report({ finishedAt: '2026-09-02T08:00:00.000Z', rows: [{ name: 'shop.example.com', ip: '203.0.113.10', status: 'UPDATED' }] });
    const undated = { ...report({ rows: [{ name: 'shop.example.com', ip: '198.51.100.20', status: 'UPDATED' }] }), startedAt: null, finishedAt: null };
    const { reports } = readCliReports([{ name: 'undated.json', text: JSON.stringify(undated) }, { name: 'dated.json', text: JSON.stringify(dated) }]);
    assert.deepEqual(reports.map((r) => [r.name, r.at]), [['dated.json', '2026-09-02T08:00:00.000Z'], ['undated.json', null]]);
  });

  test('a bare-address target is no server name; another port is kept', () => {
    const { observations } = cliReportObservations(report({ rows: [{ name: 'shop.example.com', ip: '203.0.113.10', port: 8443, status: 'UPDATED', server: '203.0.113.10' }] }));
    assert.deepEqual(observations, [{ name: 'shop.example.com', ip: '203.0.113.10', port: 8443, outcome: 'hosted', server: null }]);
  });

  test('files that are not reports are named, the others read oldest first', async () => {
    const late = report({
      finishedAt: '2026-10-02T08:00:00.000Z',
      rows: [{ name: 'shop.example.com', ip: '198.51.100.20', status: 'UPDATED' }, { name: 'shop.example.com', ip: '203.0.113.10', status: 'NOT_HOSTED' }]
    });
    const early = report({ finishedAt: '2026-09-02T08:00:00.000Z', rows: [{ name: 'shop.example.com', ip: '203.0.113.10', status: 'UPDATED' }] });
    const { reports, errors } = readCliReports([
      { name: 'late.json', text: JSON.stringify(late) }, { name: 'notes.txt', text: 'hello' },
      { name: 'other.json', text: '{"tool":"other"}' }, { name: 'early.json', text: JSON.stringify(early) },
      { name: 'v2.json', text: JSON.stringify({ ...early, version: '2.0.0' }) }
    ]);
    assert.deepEqual(reports.map((r) => r.name), ['early.json', 'late.json']);
    assert.deepEqual(errors, [
      { name: 'notes.txt', error: 'not-json' }, { name: 'other.json', error: 'not-report' }, { name: 'v2.json', error: 'version', detail: '2.0.0' }
    ]);
    // Applied in that order, the later report has the last word.
    let map = ON;
    for (const r of reports) ({ map } = applyObservations(map, r.observations, { source: 'cli-json', at: r.at }));
    assert.deepEqual(knownForScan(map).map((k) => k.ip), ['198.51.100.20']);
  });
});

describe('SSL Targets › Verify', () => {
  const row = (extra) => ({
    state: 'done', stale: false, proxied: true, via: 'hint', ip: '203.0.113.10', port: 443, name: 'shop.example.com',
    server: { id: 's1', name: 'web03' }, status: 'UPDATED', ...extra
  });

  test('only exact origins say something: remembered and zone-file checks with a verdict, an unanswered one included', () => {
    const obs = verifyObservations([
      row({ via: 'known' }), row({ via: 'zone', ip: '203.0.113.20', status: 'NOT_HOSTED' }), row({ via: 'known', ip: '203.0.113.30', status: 'TIMEOUT' }),
      row({ via: 'hint' }), row({ via: 'dns' }), row({ via: 'known', state: 'pending' }), row({ via: 'known', stale: true }),
      row({ via: 'known', proxied: false }), row({ via: 'known', status: null })
    ]);
    assert.deepEqual(obs, [
      { name: 'shop.example.com', ip: '203.0.113.10', port: 443, outcome: 'hosted', server: 'web03' },
      { name: 'shop.example.com', ip: '203.0.113.20', port: 443, outcome: 'not-hosted', server: 'web03' },
      { name: 'shop.example.com', ip: '203.0.113.30', port: 443, outcome: 'unknown', server: 'web03' }
    ], 'a hint is only a candidate: never an observation');
  });

  test('candidates a hint pointed at are never remembered and contradict nothing (one wildcard certificate everywhere)', () => {
    // The mail server and the apex web server both serve the company's wildcard certificate, so every
    // hint pair "answers" for every proxied name. The remembered origins are on servers Verify never asked.
    let { map } = applyObservations(ON, [{ name: 'www.example.com', ip: '198.51.100.30', port: 443, outcome: 'hosted' }], { source: 'cli-json', at: '2026-09-30T08:00:00Z' });
    ({ map } = addManualOrigin(map, { name: 'shop.example.com', ip: '198.51.100.31' }, { at: '2026-09-30T09:00:00Z' }));
    const rows = [];
    for (const name of ['blog.example.com', 'shop.example.com', 'www.example.com']) {
      for (const ip of ['203.0.113.10', '203.0.113.25']) rows.push(row({ via: 'hint', name, ip, status: 'NEEDS_UPDATE' }));
    }
    const res = applyObservations(map, verifyObservations(rows), { source: 'verify', at: AT });
    assert.deepEqual([res.added, res.confirmed, res.staled], [[], [], []]);
    assert.deepEqual(res.map, map, 'the map is unchanged');
  });

  test('a remembered origin is confirmed when it serves the name, stale when it answers without it', () => {
    let { map } = applyObservations(ON, [
      { name: 'shop.example.com', ip: '203.0.113.10', port: 443, outcome: 'hosted' },
      { name: 'www.example.com', ip: '203.0.113.20', port: 443, outcome: 'hosted' }
    ], { source: 'cli-json', at: '2026-09-20T08:00:00Z' });
    const res = applyObservations(map, verifyObservations([
      row({ via: 'known' }), row({ via: 'known', name: 'www.example.com', ip: '203.0.113.20', status: 'NOT_HOSTED' })
    ]), { source: 'verify', at: AT });
    ({ map } = res);
    assert.deepEqual([res.added, res.confirmed, res.staled], [[], ['shop.example.com|203.0.113.10|443'], ['www.example.com|203.0.113.20|443']]);
    assert.equal(map.entries.find((e) => e.name === 'shop.example.com').source, 'verify');
    assert.deepEqual(map.entries.find((e) => e.name === 'www.example.com').stale, { reason: 'verify-not-hosted', at: AT });
  });

  test('a zone-file origin found serving the name is remembered; an unanswered remembered origin is marked only when the name was found elsewhere', () => {
    let { map } = applyObservations(ON, [{ name: 'shop.example.com', ip: '203.0.113.20', port: 443, outcome: 'hosted' }], { source: 'cli-json', at: '2026-09-20T08:00:00Z' });
    let res = applyObservations(map, verifyObservations([row({ via: 'known', ip: '203.0.113.20', status: 'TIMEOUT' })]), { source: 'verify', at: AT });
    assert.deepEqual([res.added, res.confirmed, res.staled], [[], [], []], 'no answer alone says nothing');
    res = applyObservations(map, verifyObservations([row({ via: 'zone' }), row({ via: 'known', ip: '203.0.113.20', status: 'TIMEOUT' })]), { source: 'verify', at: AT });
    ({ map } = res);
    assert.deepEqual([res.added, res.staled], [['shop.example.com|203.0.113.10|443'], ['shop.example.com|203.0.113.20|443']]);
    assert.deepEqual(map.entries.find((e) => e.ip === '203.0.113.20').stale, { reason: 'verify-elsewhere', at: AT, ip: '203.0.113.10', port: 443 });
  });
});

describe('Retire an IP › the old and the new server', () => {
  const result = (verdict, cert = { covers: true }, ok = true) => ({
    host: 'www.example.com', port: 443, at: new Date(AT), comparison: { verdict },
    old: { ip: '203.0.113.10', ok: true, cert: { covers: true } }, new: { ip: '198.51.100.20', ok, cert }
  });

  test('the new address serves the name when it answered with a certificate covering it', () => {
    assert.deepEqual(compareObservations(result('same')), [{ name: 'www.example.com', ip: '198.51.100.20', port: 443, outcome: 'hosted' }]);
    assert.equal(compareObservations(result('differs')).length, 1);
    assert.equal(compareObservations(result('incomplete')).length, 1, 'the old server not answering does not matter');
    assert.deepEqual(compareObservations(result('broken')), []);
    assert.deepEqual(compareObservations(result('unreachable', null, false)), []);
    assert.deepEqual(compareObservations(result('same', { covers: false })), []);
    assert.deepEqual(compareObservations(null), []);
  });

  test('a comparison adds the new server and marks nothing stale', () => {
    let { map } = applyObservations(ON, [{ name: 'www.example.com', ip: '203.0.113.10', port: 443, outcome: 'hosted' }], { source: 'zone', at: '2026-09-20T08:00:00Z' });
    const res = applyObservations(map, compareObservations(result('same')), { source: 'compare', at: AT });
    ({ map } = res);
    assert.deepEqual([res.added, res.staled], [['www.example.com|198.51.100.20|443'], []]);
    assert.deepEqual(knownForScan(map).map((k) => `${k.ip} ${k.source}`).sort(), ['198.51.100.20 compare', '203.0.113.10 zone']);
  });
});
