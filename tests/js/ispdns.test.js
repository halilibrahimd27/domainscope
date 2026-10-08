// Unit tests for lib/ispdns.js (Global DNS › ISP resolvers: the Globalping measurement through
// each probe's own default resolver, its rows and their remaining TTLs) and for the ISP rows in
// lib/propagation.js propagationVerdict (by design, propagating, or stale at these ISPs).
// Fixtures: tests/fixtures/globalping/isp-default-resolvers.json (the live shape of 2026-10-08,
// documentation data) and d04-cname-chain.json. No network.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  ISP_PURPOSE, ISP_PROBE_CHOICES, ISP_DEFAULT_PROBES, ISP_CONTINENTS, ISP_PLAN_ERRORS, ISP_ROW_STATUSES, EYEBALL_TAG,
  isInternalName, parsePicks, spreadProbes, planIspMeasurement, resolverOf, remainingTtl, mapIspResults, pendingIspRows, longestTtl
} from '../../assets/js/lib/ispdns.js';
import { dnsQueryRequest, GP_LIMITS } from '../../assets/js/lib/globalping.js';
import { propagationVerdict, VERDICT_STATES } from '../../assets/js/lib/propagation.js';

const fx = (name) => JSON.parse(readFileSync(new URL(`../fixtures/globalping/${name}.json`, import.meta.url), 'utf8'));
const MEASUREMENT = fx('isp-default-resolvers').final.body;

describe('planIspMeasurement', () => {
  test('constants', () => {
    assert.equal(ISP_PURPOSE, 'isp-dns');
    assert.deepEqual(ISP_PROBE_CHOICES, [5, 10, 20, 50]);
    assert.ok(ISP_PROBE_CHOICES.every((n) => n <= GP_LIMITS.maxProbesPerMeasurement) && ISP_PROBE_CHOICES.includes(ISP_DEFAULT_PROBES));
    assert.deepEqual(ISP_PLAN_ERRORS, ['name', 'internal', 'type', 'picks', 'probes']);
    assert.deepEqual(ISP_ROW_STATUSES, ['pending', 'answer', 'failed', 'offline']);
    assert.ok(Object.isFrozen(ISP_CONTINENTS) && Object.isFrozen(ISP_PLAN_ERRORS));
  });

  test('default: 10 probes over the continents, eyeball networks only, the probes’ own resolvers', () => {
    const plan = planIspMeasurement({ name: 'www.example.com', type: 'A' });
    assert.equal(plan.ok, true);
    assert.equal(plan.probes, 10);
    assert.deepEqual(plan.locations.map((l) => [l.continent, l.limit]), [['EU', 3], ['NA', 2], ['AS', 2], ['SA', 1], ['OC', 1], ['AF', 1]]);
    assert.ok(plan.locations.every((l) => l.tags.length === 1 && l.tags[0] === EYEBALL_TAG));
    assert.deepEqual(plan.body.measurementOptions, { query: { type: 'A' }, protocol: 'UDP', port: 53 }, 'no resolver: each probe asks its own');
    assert.equal('limit' in plan.body, false, 'per-location limits only (the API refuses both)');
    assert.equal(plan.body.target, 'www.example.com');
  });

  test('more probes keep the spread; picks share the probes evenly; eyeball off drops the tag', () => {
    const big = planIspMeasurement({ name: 'example.com', type: 'AAAA', probes: 50 });
    assert.deepEqual(big.locations.map((l) => l.limit), [15, 10, 10, 5, 5, 5]);
    const few = planIspMeasurement({ name: 'example.com', type: 'A', probes: 5 });
    assert.deepEqual(few.locations.map((l) => [l.continent, l.limit]), [['EU', 2], ['NA', 1], ['AS', 1], ['SA', 1]]);
    const { picks } = parsePicks('TR, AS9121, Istanbul');
    const plan = planIspMeasurement({ name: 'example.com', type: 'MX', probes: 10, picks, eyeball: false });
    assert.deepEqual(plan.locations, [{ country: 'TR', limit: 4 }, { asn: 9121, limit: 3 }, { magic: 'Istanbul', limit: 3 }]);
  });

  test('refused before anything is sent: name, internal name, type, places, probe count', () => {
    assert.equal(planIspMeasurement({ name: '*.example.com', type: 'A' }).error, 'name');
    assert.equal(planIspMeasurement({ name: 'nas.home.arpa', type: 'A' }).error, 'internal');
    assert.equal(planIspMeasurement({ name: 'printer.local', type: 'A' }).error, 'internal');
    assert.equal(planIspMeasurement({ name: 'example.com', type: 'CAA' }).error, 'type', 'Globalping knows no CAA');
    assert.equal(planIspMeasurement({ name: 'example.com', type: 'A', probes: 0 }).error, 'probes');
    assert.equal(planIspMeasurement({ name: 'example.com', type: 'A', probes: 51 }).error, 'probes');
    const bad = parsePicks('TR, x@y');
    assert.deepEqual(planIspMeasurement({ name: 'example.com', type: 'A', ...bad }), { ok: false, error: 'picks', detail: 'x@y' });
    const many = parsePicks('TR, DE, FR');
    assert.equal(planIspMeasurement({ name: 'example.com', type: 'A', probes: 2, picks: many.picks }).error, 'picks', 'more places than probes');
  });

  test('isInternalName / parsePicks / spreadProbes', () => {
    assert.deepEqual(['intranet.corp', 'a.internal', 'example.com', 'www.example.org'].map(isInternalName), [true, true, false, false]);
    assert.deepEqual(parsePicks('tr; de\nAS9121, as9121, Comcast Cable, , São Paulo'), {
      picks: [
        { kind: 'country', value: 'TR', label: 'TR' }, { kind: 'country', value: 'DE', label: 'DE' },
        { kind: 'asn', value: 9121, label: 'AS9121' }, { kind: 'magic', value: 'Comcast Cable', label: 'Comcast Cable' },
        { kind: 'magic', value: 'São Paulo', label: 'São Paulo' }
      ],
      invalid: []
    });
    assert.deepEqual(parsePicks('<b>, AS0').invalid, ['<b>', 'AS0']);
    assert.deepEqual(spreadProbes(7, [1, 1, 1]), [3, 2, 2]);
    assert.deepEqual(spreadProbes(2, [3, 2, 1]), [1, 1, 0]);
  });

  test('dnsQueryRequest: no resolver means the probe’s default, a bad one is still refused', () => {
    assert.deepEqual(dnsQueryRequest({ name: 'example.com', type: 'A', probes: 3 }).measurementOptions, { query: { type: 'A' }, protocol: 'UDP', port: 53 });
    assert.deepEqual(dnsQueryRequest({ name: 'example.com', type: 'A', resolver: null }).measurementOptions.resolver, undefined);
    assert.throws(() => dnsQueryRequest({ name: 'example.com', type: 'A', resolver: '10.0.0.1' }), TypeError);
    assert.throws(() => dnsQueryRequest({ name: 'example.com', type: 'A', resolver: '' }), TypeError);
  });
});

describe('mapIspResults', () => {
  const { rows, done, at } = mapIspResults(MEASUREMENT, { name: 'www.example.com', type: 'A', run: 7 });

  test('one row per probe, in order, with the probe and the resolver it asked', () => {
    assert.equal(done, false, 'one probe still asking');
    assert.equal(at, '2026-10-08T10:00:00.000Z');
    assert.deepEqual(rows.map((r) => r.key), ['isp:7-0', 'isp:7-1', 'isp:7-2', 'isp:7-3', 'isp:7-4', 'isp:7-5']);
    assert.deepEqual(rows.map((r) => r.status), ['answer', 'answer', 'answer', 'failed', 'answer', 'pending']);
    assert.ok(rows.every((r) => r.kind === 'isp' && r.resolver === null && r.vantage === null && r.filtered === false));
    const [de, tr, us] = rows;
    assert.deepEqual([de.isp.country, de.isp.city, de.isp.asn, de.isp.network, de.isp.kind], ['DE', 'Berlin', 3320, 'Deutsche Telekom AG', 'eyeball']);
    assert.deepEqual(de.isp.resolver, { address: null, private: true, publicName: null }, 'Globalping masks a private resolver');
    assert.deepEqual(us.isp.resolver, { address: '8.8.8.8', private: false, publicName: 'Google Public DNS' }, 'a public resolver, not the ISP’s');
    assert.equal(tr.response.ad, true, 'the flags line says the resolver validated');
    assert.equal(de.response.ad, false);
  });

  test('answers compare like DoH answers; the TTL is what is left of the cache; it says when it expires', () => {
    const [de, tr, , br, au, za] = rows;
    assert.deepEqual(de.values, ['198.51.100.20']);
    assert.deepEqual(tr.values, ['192.0.2.10']);
    assert.deepEqual(tr.addresses, ['192.0.2.10']);
    assert.deepEqual([de.ttl, tr.ttl], [204, 1500]);
    assert.equal(tr.expiresAt, '2026-10-08T10:25:00.000Z');
    assert.equal(tr.response.elapsedMs, 15);
    assert.deepEqual(au.values, ['NXDOMAIN']);
    assert.equal(au.ttl, 900, 'a cached NXDOMAIN lasts as long as its SOA record');
    assert.deepEqual(br.values, ['ERROR']);
    assert.deepEqual([br.response.ok, br.response.errorKind, br.ttl], [false, 'timeout', null]);
    assert.equal(br.response.error, 'no servers could be reached');
    assert.deepEqual([za.pending, za.values, za.response], [true, null, null]);
    assert.deepEqual(longestTtl(rows), { ttl: 1500, expiresAt: '2026-10-08T10:25:00.000Z' });
  });

  test('a CNAME chain (d04) gives the values a DoH answer gives; offline probes and odd input', () => {
    const m = fx('d04-cname-chain').final.body;
    const [row] = mapIspResults(m, { name: 'www.example.com', type: 'A' }).rows;
    assert.deepEqual(row.values, ['192.0.2.10', 'CNAME example.com']);
    assert.equal(row.ttl, 60, 'the shortest TTL of the chain');
    const off = mapIspResults({ status: 'finished', results: [{ probe: {}, result: { status: 'offline' } }] }, { name: 'example.com', type: 'A' });
    assert.deepEqual([off.done, off.rows[0].status, off.rows[0].values], [true, 'offline', ['ERROR']]);
    assert.deepEqual(mapIspResults(null, { name: 'example.com', type: 'A' }), { rows: [], done: false, at: null });
    assert.deepEqual(pendingIspRows(3, 2).map((r) => [r.key, r.pending]), [['isp:2-0', true], ['isp:2-1', true], ['isp:2-2', true]]);
    assert.deepEqual(resolverOf('192.0.2.53'), { address: '192.0.2.53', private: false, publicName: null });
    assert.deepEqual(resolverOf('10.0.0.53'), { address: '10.0.0.53', private: true, publicName: null });
    assert.equal(remainingTtl({ ok: true, answers: [], authorities: [] }), null);
    assert.equal(remainingTtl(null), null);
  });
});

// ISP rows in the verdict: a row group of its own, judged like locations, plus "stale at these ISPs".
const item = (key, ...values) => ({ key, kind: key.split(':')[0], values });
const NEW = '198.51.100.20';
const OLD = '192.0.2.10';
const CF_A = ['13.32.0.1', '13.32.0.2', '13.32.0.3', '13.32.0.4'];
const REF = [item('resolver:cloudflare', NEW), item('resolver:google', NEW), item('geo:tr-ist-tt', NEW), item('geo:de-ham', NEW)];

describe('propagationVerdict with ISP rows', () => {
  test('a new state between "geo" and "differ"; no ISP rows: isp is null and nothing changes', () => {
    assert.deepEqual(VERDICT_STATES, ['none', 'unresolved', 'agree', 'by-design', 'geo', 'stale', 'differ']);
    const v = propagationVerdict(REF, { type: 'A' });
    assert.deepEqual([v.state, v.isp], ['agree', null]);
  });

  test('every public source agrees, one ISP still has the old address: stale at that ISP', () => {
    const v = propagationVerdict([...REF, item('isp:1-0', NEW), item('isp:1-1', OLD)], { type: 'A' });
    assert.equal(v.state, 'stale');
    assert.deepEqual(v.findings, []);
    assert.deepEqual(v.isp.stale, [{ key: OLD, members: ['isp:1-1'], status: 'answer' }]);
    assert.deepEqual([v.isp.reference, v.isp.members, v.isp.faults, v.isp.unsure], ['agree', ['isp:1-0', 'isp:1-1'], [], false]);
  });

  test('cached NXDOMAIN / NODATA at an ISP are stale; a SERVFAIL there is a fault, not a cached answer', () => {
    const nx = propagationVerdict([...REF, item('isp:1-0', 'NXDOMAIN'), item('isp:1-1', 'NODATA')], { type: 'A' });
    assert.equal(nx.state, 'stale');
    assert.deepEqual(nx.isp.stale.map((s) => s.status), ['nxdomain', 'nodata']);
    const fail = propagationVerdict([...REF, item('isp:1-0', 'SERVFAIL'), item('isp:1-1', OLD)], { type: 'A' });
    assert.equal(fail.state, 'differ');
    assert.deepEqual(fail.findings.map((f) => f.code), ['rcode', 'direct']);
    assert.deepEqual(fail.isp.faults, [{ key: 'SERVFAIL', members: ['isp:1-0'], status: 'rcode' }]);
    assert.deepEqual(fail.isp.stale.map((s) => s.members), [['isp:1-1']], 'the old address is still named');
  });

  test('another edge of the same CDN at an ISP is by design; a direct address next to CDN edges is stale', () => {
    const ref = [item('resolver:cloudflare', CF_A[0]), item('resolver:google', CF_A[0]), item('geo:de-ham', CF_A[1])];
    const design = propagationVerdict([...ref, item('isp:1-0', CF_A[2]), item('isp:1-1', CF_A[3])], { type: 'A' });
    assert.equal(design.state, 'by-design');
    assert.deepEqual([design.isp.reference, design.isp.stale], ['by-design', []]);
    assert.deepEqual(design.operators[0].members.filter((m) => m.startsWith('isp:')), ['isp:1-0', 'isp:1-1'], 'ISP rows count for the operator');
    const moved = propagationVerdict([...ref, item('isp:1-0', CF_A[2]), item('isp:1-1', OLD)], { type: 'A' });
    assert.equal(moved.state, 'stale', 'the address from before the move to the CDN');
    assert.deepEqual(moved.isp.stale.map((s) => s.members), [['isp:1-1']]);
  });

  test('public resolvers that disagree: propagating, with the ISP rows in the findings', () => {
    const v = propagationVerdict([item('resolver:cloudflare', NEW), item('resolver:google', OLD), item('isp:1-0', OLD), item('isp:1-1', NEW)], { type: 'A' });
    assert.equal(v.state, 'differ');
    assert.deepEqual(v.findings.map((f) => f.code), ['direct']);
    assert.deepEqual([v.isp.reference, v.isp.stale], ['differ', []]);
  });

  test('locations that already differ by GeoDNS: an ISP-only answer is GeoDNS or stale (unsure)', () => {
    const geo = [item('resolver:cloudflare', NEW), item('resolver:google', NEW), item('geo:jp-tyo', '203.0.113.5'), item('geo:de-ham', NEW)];
    const v = propagationVerdict([...geo, item('isp:1-0', OLD)], { type: 'A' });
    assert.equal(v.state, 'geo');
    assert.deepEqual([v.isp.unsure, v.isp.stale.map((s) => s.members)], [true, [['isp:1-0']]]);
    const agree = propagationVerdict([...REF, item('isp:1-0', NEW)], { type: 'A' });
    assert.deepEqual([agree.state, agree.isp.stale], ['agree', []]);
  });
});
