/**
 * lib/originnow.js — a scan's remembered origins as the origin map reads them now: a used origin
 * the map marks stale is flagged on its server (and on the servers a load balancer passed it to),
 * in the origin hints and on its Verify row, and no longer makes its server need the certificate
 * nor ranks it first. Synthetic results; example names and documentation addresses only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { originStaleMark, staleKnownUses, hintsNow, serversNow, resultNow, markStaleOrigins } from '../../assets/js/lib/originnow.js';
import { originIndex } from '../../assets/js/lib/originmap.js';
import { rankServerGroups } from '../../assets/js/lib/topology.js';

const DAY1 = '2026-09-20T08:00:00.000Z';
const DAY2 = '2026-10-01T08:00:00.000Z';

const entry = (name, ip, port, stale = null) => ({ name, ip, port, source: 'cli-json', firstSeen: DAY1, lastConfirmed: DAY1, ...(stale ? { stale } : {}) });
const map = (...entries) => ({ v: 1, remember: true, entries });
const NOT_HOSTED = { reason: 'verify-not-hosted', at: DAY2 };
const ELSEWHERE = { reason: 'cli-elsewhere', at: DAY2, ip: '198.51.100.40', port: 443 };

const server = (name, ip) => ({ id: name, name, ips: [ip] });
const known = (host, port = 443) => ({ kind: 'known', host, port, source: 'cli-json', lastConfirmed: DAY1, detail: `origin map: ${host}` });

/** web01 needs the certificate through DNS; web03 only through the remembered origin of www; web05 a candidate. */
function result() {
  return {
    hosts: [],
    originHints: [
      { ip: '192.0.2.40', reasons: [known('www.example.com'), known('shop.example.com', 8443)], servers: [{ serverId: 'web03', name: 'web03' }] },
      { ip: '192.0.2.50', reasons: [{ kind: 'spf', detail: 'spf: example.com' }], servers: [{ serverId: 'web05', name: 'web05' }] }
    ],
    servers: [
      { server: server('web01', '203.0.113.10'), needsCert: true, maybeNeedsCert: false, hosts: [{ name: 'example.com', ip: '203.0.113.10', covered: true, via: 'dns' }] },
      {
        server: server('web03', '192.0.2.40'), needsCert: true, maybeNeedsCert: false,
        hosts: [{ name: 'www.example.com', ip: '192.0.2.40', port: 443, covered: true, via: 'known' }, { name: 'shop.example.com', ip: '192.0.2.40', port: 8443, covered: false, via: 'known' }]
      },
      { server: server('web05', '192.0.2.50'), needsCert: false, maybeNeedsCert: true, hosts: [{ name: 'www.example.com', ip: '192.0.2.50', covered: true, via: 'hint' }] }
    ],
    unmatchedIps: [],
    stats: { needsCert: 2, hintedServers: 1 }
  };
}

describe('lib/originnow.js', () => {
  test('nothing stale (or no map): the scan\'s own objects, untouched', () => {
    const r = result();
    for (const m of [null, map(entry('www.example.com', '192.0.2.40', 443)), map(entry('www.example.com', '192.0.2.40', 8443, NOT_HOSTED))]) {
      assert.equal(staleKnownUses(r, m).size, 0);
      assert.equal(resultNow(r, m), r);
      assert.equal(serversNow(r, m), r.servers);
      assert.equal(hintsNow(r, m), r.originHints);
    }
    assert.equal(resultNow(null, null), null);
  });

  test('a used origin the map now marks stale: flagged on its server and in the hints, out of needsCert and the ranking', () => {
    const r = result();
    const before = JSON.stringify(r);
    const m = map(entry('www.example.com', '192.0.2.40', 443, NOT_HOSTED), entry('shop.example.com', '192.0.2.40', 8443));
    assert.deepEqual([...staleKnownUses(r, m)], [['www.example.com|192.0.2.40|443', NOT_HOSTED]]);
    const now = resultNow(r, m);
    assert.equal(JSON.stringify(r), before, 'the scan result is never changed');
    // web03 had only the remembered origin of www: no longer a server to update; its covered names gone, not a candidate either.
    assert.deepEqual(now.servers.map((g) => [g.server.name, g.needsCert, g.maybeNeedsCert]), [['web01', true, false], ['web05', false, true], ['web03', false, false]]);
    assert.equal(now.stats.needsCert, 1);
    assert.equal(now.stats.hintedServers, 1, 'other counts as the scan made them');
    const web03 = now.servers.find((g) => g.server.name === 'web03');
    assert.deepEqual(web03.hosts.map((e) => [e.name, e.port, e.stale || null]), [['www.example.com', 443, NOT_HOSTED], ['shop.example.com', 8443, null]]);
    assert.deepEqual(now.originHints[0].reasons.map((x) => [x.host, x.stale || null]), [['www.example.com', NOT_HOSTED], ['shop.example.com', null]]);
    assert.equal(now.originHints[1], r.originHints[1], 'a hint without a stale reason is the same object');
    assert.equal(now.servers.find((g) => g.server.name === 'web01'), r.servers[0], 'an untouched group is the same object');
  });

  test('a server still tied by DNS, the zone or another active origin keeps needing the certificate', () => {
    const r = result();
    r.servers[1].hosts.push({ name: 'blog.example.com', ip: '192.0.2.40', covered: true, via: 'zone' });
    const now = resultNow(r, map(entry('www.example.com', '192.0.2.40', 443, ELSEWHERE)));
    const web03 = now.servers.find((g) => g.server.name === 'web03');
    assert.deepEqual([web03.needsCert, web03.hosts[0].stale], [true, ELSEWHERE]);
    assert.deepEqual(now.servers.map((g) => g.server.name), ['web01', 'web03', 'web05']);
    // Left with a candidate only: "maybe".
    const r2 = result();
    r2.servers[1].hosts.push({ name: 'blog.example.com', ip: '192.0.2.40', covered: true, via: 'hint' });
    const web03b = serversNow(r2, map(entry('www.example.com', '192.0.2.40', 443, ELSEWHERE))).find((g) => g.server.name === 'web03');
    assert.deepEqual([web03b.needsCert, web03b.maybeNeedsCert], [false, true]);
  });

  test('stats.hintedServers counted again: a server the stale origins leave with candidates only is "possible via hints"', () => {
    const r = result();
    r.servers[1].hosts.push({ name: 'blog.example.com', ip: '192.0.2.40', covered: true, via: 'hint' });
    const now = resultNow(r, map(entry('www.example.com', '192.0.2.40', 443, NOT_HOSTED), entry('shop.example.com', '192.0.2.40', 8443, ELSEWHERE)));
    assert.deepEqual(now.servers.filter((g) => g.maybeNeedsCert).map((g) => g.server.name), ['web03', 'web05']);
    assert.deepEqual([now.stats.needsCert, now.stats.hintedServers], [1, 2], 'the Servers card says what the tab shows');
    assert.deepEqual([r.stats.needsCert, r.stats.hintedServers], [2, 1], 'the scan\'s own counts untouched');
  });

  test('a covering wildcard masked by the name\'s own stale entry at its address and port: stale too', () => {
    const r = result();
    const m = map(entry('*.example.com', '192.0.2.40', 443), entry('www.example.com', '192.0.2.40', 443, NOT_HOSTED));
    assert.deepEqual(originStaleMark(originIndex(m), 'www.example.com', '192.0.2.40', 443), NOT_HOSTED);
    assert.equal(originStaleMark(m, 'blog.example.com', '192.0.2.40', null), null, 'the wildcard still covers the other names');
    assert.equal(resultNow(r, m).stats.needsCert, 1);
  });

  test('through a load balancer: a backend\'s entry is stale when every tie of the name on it is', () => {
    const lb = { server: server('lb01', '192.0.2.40'), needsCert: true, maybeNeedsCert: false, topology: { behind: [], backends: [{ name: 'web07' }], vips: [] },
      hosts: [{ name: 'www.example.com', ip: '192.0.2.40', port: 443, covered: true, via: 'known' }] };
    const web07 = { server: server('web07', '10.0.0.70'), needsCert: true, maybeNeedsCert: false, topology: { behind: ['lb01'], backends: [], vips: [] },
      hosts: [{ name: 'www.example.com', ip: '10.0.0.70', covered: true, via: 'known', lbs: ['lb01'] }] };
    const r = { originHints: [{ ip: '192.0.2.40', reasons: [known('www.example.com')], servers: [] }], servers: [lb, web07], stats: { needsCert: 2 } };
    const m = map(entry('www.example.com', '192.0.2.40', 443, NOT_HOSTED));
    const now = resultNow(r, m);
    assert.deepEqual(now.servers.map((g) => [g.server.name, g.needsCert, !!g.hosts[0].stale]), [['lb01', false, true], ['web07', false, true]]);
    // The load balancer also reached by DNS: the backend keeps the certificate.
    lb.hosts.push({ name: 'www.example.com', ip: '192.0.2.40', covered: true, via: 'dns' });
    const kept = resultNow(r, m);
    assert.deepEqual(kept.servers.map((g) => [g.server.name, g.needsCert, !!g.hosts[0].stale]), [['lb01', true, true], ['web07', true, false]]);
  });

  test('markStaleOrigins: the Verify rows of remembered origins get the mark, the others are left alone', () => {
    const rows = [
      { via: 'known', name: 'www.example.com', ip: '192.0.2.40', port: 443 },
      { via: 'known', name: 'shop.example.com', ip: '192.0.2.40', port: 8443, originStale: { reason: 'old' } },
      { via: 'dns', name: 'example.com', ip: '203.0.113.10', port: 443 }
    ];
    assert.equal(markStaleOrigins(rows, map(entry('www.example.com', '192.0.2.40', 443, NOT_HOSTED), entry('shop.example.com', '192.0.2.40', 8443))), 1);
    assert.deepEqual(rows.map((x) => ('originStale' in x ? x.originStale : 'unset')), [NOT_HOSTED, null, 'unset']);
    assert.equal(markStaleOrigins(rows, null), 0, 'the map gone: no mark left');
    assert.deepEqual(rows.map((x) => ('originStale' in x ? x.originStale : 'unset')), [null, null, 'unset']);
  });

  test('rankServerGroups: needs, maybe, then names in numeric order; a new array', () => {
    const g = (name, needsCert, maybeNeedsCert) => ({ server: { id: name, name }, needsCert, maybeNeedsCert, hosts: [] });
    const list = [g('web10', false, false), g('web2', true, false), g('web1', false, true), g('web9', true, false)];
    const ranked = rankServerGroups(list);
    assert.deepEqual(ranked.map((x) => x.server.name), ['web2', 'web9', 'web1', 'web10']);
    assert.notEqual(ranked, list);
    assert.deepEqual(list.map((x) => x.server.name), ['web10', 'web2', 'web1', 'web9'], 'the input is not sorted in place');
  });
});
