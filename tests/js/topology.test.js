// Unit tests for the inventory topology (where TLS really terminates) across the web app:
// lib/topology.js on server groups, a scan whose names reach a load balancer through a VIP and a
// server through NAT (lib/scanner.js), the SSL Targets Servers tab's grouping, the Renewal plan
// and its work list (lib/certsets.js), the CLI hand-offs (lib/export.js, views/inventory.js
// targetsText) and the Verify pairs (lib/verify.js). No network: the DoH answers come from a
// small emulated zone.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInventory } from '../../assets/js/lib/inventory.js';
import {
  applyTopology, orderByLoadBalancer, topologyNotes, topologyTokens, tlsNowhere, scanTargetsKeys, TOPOLOGY_CSV_COLUMN
} from '../../assets/js/lib/topology.js';
import { noCertStatus } from '../../assets/js/ui/topology.js';
import { runScan } from '../../assets/js/lib/scanner.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { planRenewal, workListRows, workListColumns, WORKLIST_COLUMNS } from '../../assets/js/lib/certsets.js';
import { toCsv, scanServerRows, targetsForCli, cliServerName, SERVER_COLUMNS } from '../../assets/js/lib/export.js';
import { buildVerifyPairs } from '../../assets/js/lib/verify.js';
import { targetsText } from '../../assets/js/views/inventory.js';

const TOPOLOGY_DIR = new URL('../fixtures/topology/', import.meta.url);
const INVENTORY = parseInventory(readFileSync(new URL('inventory.txt', TOPOLOGY_DIR), 'utf8')).servers;
const CORE = INVENTORY.filter((s) => ['lb01', 'lb02', 'web01', 'web02', 'app01', 'db01'].includes(s.name));

/* ---- an emulated zone behind every DoH resolver ------------------------------------------- */

const D = 'example.net';
const SOA = { mname: `ns1.${D}`, rname: `hostmaster.${D}`, serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
/** www answers with the VIP lb01 and lb02 share, api with app01's public NAT address, shop with lb01 itself. */
const ZONE = {
  [`www.${D}`]: ['203.0.113.50'],
  [`api.${D}`]: ['203.0.113.10'],
  [`shop.${D}`]: ['203.0.113.2'],
  [`mail.${D}`]: ['203.0.113.12']
};

function dohWorld(zone = ZONE) {
  const fetchImpl = async (url) => {
    const resolver = RESOLVERS.find((r) => url.startsWith(`${r.url}?`));
    if (!resolver) throw new TypeError(`unexpected URL ${url}`);
    const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
    const name = String(q.name).toLowerCase().replace(/\.$/, '');
    const answers = q.type === 'A' ? (zone[name] || []).map((data) => ({ name, type: 'A', ttl: 300, data })) : [];
    const rcode = zone[name] || name === D ? 'NOERROR' : 'NXDOMAIN';
    return new Response(encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode, questions: [{ name: q.name, type: q.type }],
      answers, authorities: answers.length ? [] : [{ name: D, type: 'SOA', ttl: 300, data: SOA }], edns: {}
    }));
  };
  return { fetchImpl, dns: new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 }) };
}

/** A certificate set covering the zone (lib/certsets.js CertSet: only what the plan reads). */
const SET_A = { id: 'A', names: [D, `*.${D}`], keyTypes: ['RSA 2048'], files: ['new-cert.pem'], expires: null, notAfter: null, leaves: [], certs: [] };

async function topologyScan(inventory = CORE, zone = ZONE) {
  const { fetchImpl, dns } = dohWorld(zone);
  return runScan({
    domains: [D], extraNames: Object.keys(zone), exact: true, sources: [], bruteforce: 'off', mine: false,
    permutationBudget: 0, recursive: false, originHints: false, certs: [{ hostnames: SET_A.names, serialHex: '01' }],
    inventory, dns, fetchImpl
  });
}

const groupsByName = (scan) => Object.fromEntries(scan.servers.map((g) => [g.server.name, g]));

/* ---- lib/topology.js on server groups ------------------------------------------------------ */

describe('applyTopology / orderByLoadBalancer', () => {
  test('a VIP pair with 40 backends and 5000 names stays fast: no name-by-name search per entry', () => {
    const names = Array.from({ length: 40 }, (_, i) => `web${i}`);
    const { servers } = parseInventory([`lb01 203.0.113.2 vip=203.0.113.50 backends=${names}`, `lb02 203.0.113.3 vip=203.0.113.50 backends=${names}`,
      ...names.map((n, i) => `${n} 10.0.0.${i + 1}`)].join('\n'));
    const hosts = () => Array.from({ length: 5000 }, (_, i) => ({ name: `h${i}.${D}`, ip: '203.0.113.50', covered: true, via: 'dns', through: 'vip' }));
    const started = performance.now();
    const out = applyTopology([{ server: servers[0], hosts: hosts() }, { server: servers[1], hosts: hosts() }], servers);
    const ms = performance.now() - started;
    assert.deepEqual([out.length, out[2].hosts.length, out[2].hosts[4999].lbs], [42, 5000, ['lb01', 'lb02']]);
    assert.ok(ms < 1000, `applyTopology took ${Math.round(ms)} ms`);
  });

  const [lb01, lb02, web01, web02, app01] = ['lb01', 'lb02', 'web01', 'web02', 'app01'].map((n) => CORE.find((s) => s.name === n));
  const entry = (name, ip, extra = {}) => ({ name, ip, covered: true, via: 'dns', ...extra });

  test('a load balancer\'s names reach its backends, each on its own addresses; the groups say where TLS terminates', () => {
    const groups = applyTopology([
      { server: lb01, hosts: [entry(`www.${D}`, '203.0.113.50', { through: 'vip' }), entry(`shop.${D}`, '203.0.113.2')] },
      { server: app01, hosts: [entry(`api.${D}`, '203.0.113.10', { through: 'nat' })] }
    ], CORE);
    const by = Object.fromEntries(groups.map((g) => [g.server.name, g]));
    assert.deepEqual(groups.map((g) => g.server.name), ['lb01', 'app01', 'web01', 'web02']);
    assert.deepEqual(by.web01.hosts, [
      { name: `www.${D}`, ip: '10.0.0.21', covered: true, via: 'dns', lbs: ['lb01'] },
      { name: `shop.${D}`, ip: '10.0.0.21', covered: true, via: 'dns', lbs: ['lb01'] }
    ]);
    assert.deepEqual(by.lb01.topology, {
      terminatesTls: true,
      backends: [{ id: 'web01', name: 'web01', terminatesTls: false }, { id: 'web02', name: 'web02', terminatesTls: true }],
      behind: [], vips: [{ ip: '203.0.113.50', servers: ['lb01', 'lb02'], plain: [] }], nats: [], tlsPorts: [443, 8443], suspect: false, nowhere: []
    });
    assert.deepEqual([by.web01.topology.terminatesTls, by.web01.topology.behind], [false, ['lb01']]);
    assert.deepEqual([by.web02.topology.terminatesTls, by.web02.topology.behind, by.web02.topology.tlsPorts], [true, ['lb01'], [8443]]);
    assert.deepEqual(by.app01.topology.nats, [{ ip: '203.0.113.10', addresses: ['10.0.0.30'] }]);
    // the order of a list: each load balancer, then what is behind it
    assert.deepEqual(orderByLoadBalancer([by.app01, by.web01, by.lb01, by.web02]).map((g) => g.server.name), ['app01', 'lb01', 'web01', 'web02']);
  });

  test('a backend that is itself a load balancer passes the names on; hints stay hints', () => {
    const { servers } = parseInventory('edge 203.0.113.2 backends=mid\nmid 10.0.0.2 backends=app\napp 10.0.0.3 terminates_tls=no');
    const groups = applyTopology([{ server: servers[0], hosts: [entry(`www.${D}`, '203.0.113.2', { via: 'hint' })] }], servers);
    assert.deepEqual(groups.map((g) => [g.server.name, g.hosts.map((e) => [e.ip, e.via, e.lbs])]), [
      ['edge', [['203.0.113.2', 'hint', undefined]]],
      ['mid', [['10.0.0.2', 'hint', ['edge']]]],
      ['app', [['10.0.0.3', 'hint', ['mid']]]]
    ]);
    // a loop of load balancers ends
    const loop = parseInventory('a 10.0.0.1 backends=b\nb 10.0.0.2 backends=a').servers;
    assert.equal(applyTopology([{ server: loop[0], hosts: [entry('x.example.net', '10.0.0.1')] }], loop).length, 2);
  });

  test('a VIP pair passes a name to the same backend: both are named; a stronger tie replaces a hint, a direct match stays', () => {
    const { servers } = parseInventory([
      'lb01 203.0.113.2 vip=203.0.113.50 backends=web01,web02', 'lb02 203.0.113.3 vip=203.0.113.50 backends=web01',
      'web01 10.0.0.21 terminates_tls=no', 'web02 203.0.113.12'
    ].join('\n'));
    const [l1, l2, w1, w2] = servers;
    const groups = applyTopology([
      { server: l1, hosts: [entry(`www.${D}`, '203.0.113.50', { through: 'vip' }), entry(`api.${D}`, '203.0.113.2', { via: 'hint' }), entry(`shop.${D}`, '203.0.113.2')] },
      { server: l2, hosts: [entry(`www.${D}`, '203.0.113.50', { through: 'vip' }), entry(`api.${D}`, '203.0.113.3')] },
      { server: w2, hosts: [entry(`shop.${D}`, '203.0.113.12')] }
    ], servers);
    const by = Object.fromEntries(groups.map((g) => [g.server.name, g]));
    assert.deepEqual(by.web01.hosts.map((e) => [e.name, e.via, e.lbs]), [
      [`www.${D}`, 'dns', ['lb01', 'lb02']],
      [`api.${D}`, 'dns', ['lb02']], // DNS through lb02 over the hint through lb01
      [`shop.${D}`, 'dns', ['lb01']]
    ]);
    // shop answers with web02's own address too: that entry stays direct (no lbs); lb02 does not forward to web02
    assert.deepEqual(by.web02.hosts.map((e) => [e.name, e.ip, e.via, e.lbs ?? null]), [
      [`shop.${D}`, '203.0.113.12', 'dns', null],
      [`www.${D}`, '203.0.113.12', 'dns', ['lb01']],
      [`api.${D}`, '203.0.113.12', 'hint', ['lb01']]
    ]);
    assert.deepEqual([by.web01.topology.behind, by.web02.topology.behind], [['lb01', 'lb02'], ['lb01']]);
    assert.equal(w1.terminatesTls, false);
    // a VIP pair comes together, then what is behind either of them
    assert.deepEqual(orderByLoadBalancer([by.lb01, by.web02, by.web01, by.lb02]).map((g) => g.server.name), ['lb01', 'lb02', 'web01', 'web02']);
  });

  test('a remembered origin (via known) ties stronger than the zone file and a hint, and reaching a terminates_tls=no server directly keeps its certificate', () => {
    const { servers } = parseInventory([
      'lb01 203.0.113.2 backends=web01', 'lb02 203.0.113.3 backends=web01', 'web01 10.0.0.21 terminates_tls=no', 'solo 203.0.113.30 terminates_tls=no'
    ].join('\n'));
    const [l1, l2, , solo] = servers;
    const groups = applyTopology([
      { server: l1, hosts: [entry(`api.${D}`, '203.0.113.2', { via: 'hint' }), entry(`shop.${D}`, '203.0.113.2', { via: 'known', port: 8443 })] },
      { server: l2, hosts: [entry(`api.${D}`, '203.0.113.3', { via: 'known', port: 8443 }), entry(`shop.${D}`, '203.0.113.3', { via: 'zone' })] },
      { server: solo, hosts: [entry(`app.${D}`, '203.0.113.30', { via: 'known', port: 8443 })] }
    ], servers);
    const by = Object.fromEntries(groups.map((g) => [g.server.name, g]));
    // api: the remembered origin through lb02 over the hint through lb01; shop: through lb01 over the zone file's through lb02
    assert.deepEqual(by.web01.hosts.map((e) => [e.name, e.via, e.lbs]), [[`api.${D}`, 'known', ['lb02']], [`shop.${D}`, 'known', ['lb01']]]);
    // a plain-HTTP server a remembered origin points at is no plain-HTTP server: the inventory is wrong, the certificate goes there
    assert.equal(by.solo.topology.suspect, true);
    assert.equal(by.web01.topology.suspect, false, 'behind a load balancer it stays plain HTTP');
  });

  test('without a topology key the groups are untouched', () => {
    const { servers } = parseInventory('web01 203.0.113.10\nweb02 203.0.113.13');
    const groups = [{ server: servers[0], hosts: [entry(`www.${D}`, '203.0.113.10')], needsCert: true }];
    const out = applyTopology(groups, servers);
    assert.equal(out, groups);
    assert.equal('topology' in out[0], false);
    assert.deepEqual(orderByLoadBalancer(out), out);
  });

  test('topologyNotes: the CSV text of a group\'s topology', () => {
    assert.deepEqual(topologyNotes({ terminatesTls: true, backends: [{ name: 'web01' }], behind: [], vips: [{ ip: '203.0.113.50', servers: ['lb01', 'lb02'] }], nats: [], tlsPorts: [443, 8443] }),
      ['load balancer for web01', 'VIP 203.0.113.50 (lb01, lb02)', 'TLS ports 443,8443']);
    assert.deepEqual(topologyNotes({ terminatesTls: false, backends: [], behind: ['lb01', 'lb02'], vips: [], nats: [], tlsPorts: [] }), ['behind lb01, lb02 (plain HTTP, no certificate)']);
    assert.deepEqual(topologyNotes({ terminatesTls: false, backends: [{ name: 'web01' }], behind: [], vips: [], nats: [], tlsPorts: [] }), ['load balancer for web01 (passes TLS through)']);
    assert.deepEqual(topologyNotes({ terminatesTls: true, backends: [], behind: [], vips: [], nats: [{ ip: '203.0.113.10', addresses: ['10.0.0.30'] }], tlsPorts: [] }), ['NAT 203.0.113.10 -> 10.0.0.30']);
    assert.deepEqual(topologyNotes(null), []);
  });
});

/* ---- a scan: DNS through the VIP and NAT, the Servers tab's grouping ------------------------ */

describe('a scan with load balancers, a VIP pair and a NAT address', () => {
  test('DNS answers match through vip= and nat=; the hosts say so', async () => {
    const scan = await topologyScan();
    const hosts = Object.fromEntries(scan.hosts.map((x) => [x.name, x]));
    assert.deepEqual(hosts[`www.${D}`].servers, [
      { serverId: 'lb01', name: 'lb01', ip: '203.0.113.50', through: 'vip' },
      { serverId: 'lb02', name: 'lb02', ip: '203.0.113.50', through: 'vip' }
    ]);
    assert.deepEqual(hosts[`api.${D}`].servers, [{ serverId: 'app01', name: 'app01', ip: '203.0.113.10', through: 'nat' }]);
    assert.deepEqual(hosts[`shop.${D}`].servers, [{ serverId: 'lb01', name: 'lb01', ip: '203.0.113.2' }]);
    // the VIP and the NAT address belong to your servers: only mail's address is outside the inventory
    assert.deepEqual(scan.unmatchedIps.map((u) => u.ip), ['203.0.113.12']);
  });

  test('install on the load balancers (both holders of the VIP) and the re-encrypting backend; the plain-HTTP backend needs nothing; the VIP pair is followed by its backends', async () => {
    const scan = await topologyScan();
    assert.deepEqual(scan.servers.map((g) => [g.server.name, g.needsCert]), [
      ['app01', true], ['lb01', true], ['lb02', true], ['web01', false], ['web02', true]
    ]);
    const g = groupsByName(scan);
    assert.deepEqual(g.lb02.topology.vips, [{ ip: '203.0.113.50', servers: ['lb01', 'lb02'], plain: [] }]);
    assert.deepEqual([g.web01.topology.terminatesTls, g.web01.topology.behind, g.web01.maybeNeedsCert], [false, ['lb01', 'lb02'], false]);
    // shop answers with lb01's own address, www with the VIP both hold
    assert.deepEqual(g.web01.hosts.map((e) => [e.name, e.ip, e.lbs]), [
      [`shop.${D}`, '10.0.0.21', ['lb01']], [`www.${D}`, '10.0.0.21', ['lb01', 'lb02']]
    ]);
    assert.deepEqual([g.web02.topology.behind, g.web02.hosts.every((e) => e.ip === '10.0.0.22')], [['lb01', 'lb02'], true]);
    assert.equal(g.db01, undefined, 'a server no name reaches stays out');
    assert.equal(scan.stats.needsCert, 4);
    assert.equal(scan.stats.matchedServers, 3, 'reached by DNS itself: app01, lb01, lb02');
  });

  test('the same scan without the topology keys: the old behaviour (backends unreached, VIP and NAT unmatched)', async () => {
    const plain = parseInventory(CORE.map((s) => `${s.name} ${s.ips.join(' ')}`).join('\n')).servers;
    const scan = await topologyScan(plain);
    assert.deepEqual(scan.servers.map((g) => [g.server.name, g.needsCert]), [['lb01', true]]);
    assert.ok(scan.servers.every((x) => !('topology' in x)));
    assert.deepEqual(scan.unmatchedIps.map((u) => u.ip), ['203.0.113.10', '203.0.113.12', '203.0.113.50']);
  });

  test('the Renewal plan and its work list follow the same rules', async () => {
    const scan = await topologyScan();
    const plan = planRenewal(scan, [SET_A]);
    assert.deepEqual(plan.rows.map((r) => [r.key, Object.values(r.cells).flat().map((e) => e.name)]), [
      ['s:app01', [`api.${D}`]],
      ['s:lb01', [`shop.${D}`, `www.${D}`]],
      ['s:lb02', [`www.${D}`]],
      ['s:web02', [`shop.${D}`, `www.${D}`]],
      ['ip:203.0.113.12', [`mail.${D}`]]
    ]);
    assert.deepEqual(plan.plain, [{ server: { id: 'web01', name: 'web01', ips: ['10.0.0.21'] }, behind: ['lb01', 'lb02'], passthrough: false, backends: [] }]);
    assert.deepEqual(plan.perSet.A, { names: 5, rows: 5, servers: 4, addresses: 1 }, 'the apex resolves to nothing: no row');
    const columns = workListColumns(plan);
    assert.deepEqual(columns.map((c) => c.header), [...WORKLIST_COLUMNS.map((c) => c.header), 'Topology']);
    const csv = toCsv(workListRows(plan), columns, { bom: false }).trim().split('\r\n');
    assert.equal(csv.length, 6);
    assert.ok(csv.some((l) => l.startsWith('web02,10.0.0.22,') && l.endsWith(',"behind lb01, lb02 (re-encrypts); TLS ports 8443"')), csv.join('\n'));
    assert.ok(csv.some((l) => l.startsWith('lb02,203.0.113.50,') && l.includes('VIP 203.0.113.50 (lb01, lb02)')), csv.join('\n'));
    assert.ok(!csv.some((l) => l.startsWith('web01,')), 'the plain-HTTP backend is not on the work list');
    // a plan without topology keeps the old columns
    assert.equal(workListColumns({ rows: [{ cells: {} }] }), WORKLIST_COLUMNS);
  });

  test('the Servers CSV carries the topology; the Verify tab never checks a plain-HTTP backend; NAT pairs scan the inside address', async () => {
    const scan = await topologyScan();
    const rows = scanServerRows(scan);
    const csv = toCsv(rows, [...SERVER_COLUMNS, TOPOLOGY_CSV_COLUMN], { bom: false });
    assert.ok(csv.includes('web01,10.0.0.21,,false,shop.example.net,10.0.0.21,dns,true,"behind lb01, lb02 (plain HTTP, no certificate)"'), csv);
    const { pairs } = buildVerifyPairs(scan);
    assert.deepEqual([...new Set(pairs.map((p) => (p.server ? p.server.name : '(not in the list)')))].sort(), ['(not in the list)', 'app01', 'lb01', 'web02']);
    const vip = pairs.find((p) => p.ip === '203.0.113.50');
    assert.deepEqual([vip.server.name, vip.alsoServers.map((s) => s.name)], ['lb01', ['lb02']]);
    const nat = pairs.find((p) => p.ip === '203.0.113.10');
    // (a documentation address is never sent to Globalping: 'reserved'; the CLI card scans app01 from inside)
    assert.deepEqual([nat.skip, nat.cliTargets], ['reserved', ['10.0.0.30']]);
    assert.equal(pairs.find((p) => p.server && p.server.name === 'web02').skip, 'private');
  });
});

/* ---- the inventory and DNS disagree: err toward "needs the certificate" -------------------- */

describe('when the inventory and DNS disagree, the certificate is still planned and the inventory flagged', () => {
  const scanOf = (text, zone) => topologyScan(parseInventory(text).servers, zone);
  const DIRECT = 'lb01 203.0.113.2 backends=web01\nweb01 203.0.113.12 terminates_tls=no';

  test('a terminates_tls=no backend that a name reaches directly needs the certificate and says the inventory looks wrong', async () => {
    const scan = await scanOf(DIRECT, { [`www.${D}`]: ['203.0.113.2'], [`direct.${D}`]: ['203.0.113.12'] });
    const g = groupsByName(scan);
    assert.deepEqual([g.lb01.needsCert, g.web01.needsCert, g.web01.topology.suspect, g.lb01.topology.suspect], [true, true, true, false]);
    assert.equal(noCertStatus(g.web01), null, 'never "No certificate needed"');
    assert.equal(scan.stats.needsCert, 2);
    assert.equal('tlsNowhere' in scan, false, 'the name terminates somewhere: on web01, which the inventory gets wrong');
    assert.ok(topologyNotes(g.web01.topology).includes('terminates_tls=no, yet DNS points here directly (check the inventory)'), topologyNotes(g.web01.topology).join(' | '));
    assert.ok(!topologyNotes(g.web01.topology).some((n) => /no certificate/.test(n)), 'no "no certificate" claim on the CSV');
    // the Renewal plan and its work list, Verify, and the CLI's targets keep it
    const plan = planRenewal(scan, [SET_A]);
    assert.deepEqual(plan.rows.map((r) => r.key), ['s:lb01', 's:web01']);
    assert.deepEqual(plan.plain, []);
    assert.deepEqual(workListRows(plan).map((r) => r.server), ['lb01', 'web01']);
    const { pairs } = buildVerifyPairs(scan);
    assert.ok(pairs.some((p) => p.server && p.server.name === 'web01' && p.name === `direct.${D}`), JSON.stringify(pairs.map((p) => [p.name, p.ip])));
    // tests/python/test_topology_scan.py reads this file back: the CLI scans web01
    const text = targetsForCli(parseInventory(DIRECT).servers, { keys: scanTargetsKeys(scan, cliServerName) });
    assert.equal(text, readFileSync(new URL('targets-direct.txt', TOPOLOGY_DIR), 'utf8'));
    assert.ok(!/terminates_tls=no/.test(text), text);
  });

  test('the same server reached only directly (no load balancer in the scan) needs it too', async () => {
    const scan = await scanOf(DIRECT, { [`direct.${D}`]: ['203.0.113.12'] });
    const g = groupsByName(scan);
    assert.deepEqual(scan.servers.map((x) => [x.server.name, x.needsCert]), [['web01', true]]);
    assert.equal(g.web01.topology.suspect, true);
    assert.deepEqual(planRenewal(scan, [SET_A]).plain, []);
  });

  test('VIP holders that disagree: both need it (DNS reaches both), the note says the inventory disagrees', async () => {
    const scan = await scanOf('db01 10.0.0.71 vip=203.0.113.70\ndb02 10.0.0.72 vip=203.0.113.70 terminates_tls=no', { [`db.${D}`]: ['203.0.113.70'] });
    const g = groupsByName(scan);
    assert.deepEqual(scan.servers.map((x) => [x.server.name, x.needsCert]), [['db01', true], ['db02', true]]);
    assert.deepEqual([g.db01.topology.vips, g.db02.topology.suspect], [[{ ip: '203.0.113.70', servers: ['db01', 'db02'], plain: ['db02'] }], true]);
    assert.ok(topologyNotes(g.db01.topology).includes('VIP 203.0.113.70 (db01, db02; terminates_tls=no: db02)'), topologyNotes(g.db01.topology).join(' | '));
  });

  test('backends that loop end the scan: the load balancer DNS reaches keeps the certificate', async () => {
    const scan = await scanOf('lb03 203.0.113.4 backends=lb04 terminates_tls=no\nlb04 203.0.113.5 backends=lb03 terminates_tls=no', { [`www.${D}`]: ['203.0.113.4'] });
    const g = groupsByName(scan);
    assert.deepEqual([g.lb03.needsCert, g.lb03.topology.suspect, scan.tlsNowhere], [true, true, [`www.${D}`]]);
  });

  test('a VIP held only by terminates_tls=no servers: both holders need the certificate', async () => {
    const scan = await scanOf('web01 10.0.0.21 vip=203.0.113.50 terminates_tls=no\nweb02 10.0.0.22 vip=203.0.113.50 terminates_tls=no',
      { [`www.${D}`]: ['203.0.113.50'] });
    assert.deepEqual(scan.servers.map((x) => [x.server.name, x.needsCert, x.topology.suspect]), [['web01', true, true], ['web02', true, true]]);
    assert.equal(buildVerifyPairs(scan).pairs.filter((p) => p.ip === '203.0.113.50').length, 1, 'the VIP is checked once');
  });

  test('a passthrough load balancer in front of plain backends: TLS terminates nowhere — the load balancer DNS reaches needs it, and the scan says so', async () => {
    const scan = await scanOf('lb01 203.0.113.2 terminates_tls=no backends=web01\nweb01 10.0.0.21 terminates_tls=no', { [`www.${D}`]: ['203.0.113.2'] });
    const g = groupsByName(scan);
    assert.deepEqual([g.lb01.needsCert, g.lb01.topology.suspect, g.web01.needsCert, g.web01.topology.suspect], [true, true, false, false]);
    assert.deepEqual(scan.tlsNowhere, [`www.${D}`]);
    assert.deepEqual(tlsNowhere(scan.servers), [`www.${D}`]);
    assert.equal(noCertStatus(g.web01), 'plain', 'the backend behind it stays plain HTTP');
    assert.deepEqual(planRenewal(scan, [SET_A]).plain.map((p) => p.server.name), ['web01']);
  });

  test('a passthrough load balancer with a backend that terminates TLS is no contradiction', async () => {
    const scan = await scanOf('lb01 203.0.113.2 terminates_tls=no backends=web01,web02\nweb01 10.0.0.21\nweb02 10.0.0.22 terminates_tls=no',
      { [`www.${D}`]: ['203.0.113.2'] });
    assert.deepEqual(scan.servers.map((x) => [x.server.name, x.needsCert, x.topology.suspect]), [['lb01', false, false], ['web01', true, false], ['web02', false, false]]);
    assert.equal('tlsNowhere' in scan, false);
    assert.equal(noCertStatus(groupsByName(scan).lb01), 'passthrough');
    // and the fixture's scan has no contradiction either
    const core = await topologyScan();
    assert.ok(core.servers.every((x) => !x.topology || !x.topology.suspect));
    assert.equal('tlsNowhere' in core, false);
  });
});

/* ---- the CLI hand-offs ------------------------------------------------------------------- */

test('targets.txt (Servers view and SSL Targets) writes the topology keys the CLI reads back', () => {
  // tests/python/test_inventory_targets.py reads this file back to the same model.
  const want = readFileSync(new URL('targets.txt', TOPOLOGY_DIR), 'utf8');
  assert.equal(targetsText(INVENTORY), want);
  const keys = (s) => topologyTokens(s, cliServerName);
  assert.deepEqual(targetsForCli(INVENTORY, { keys }).split('\n').filter(Boolean), want.split('\n').filter(Boolean));
  // lib/export.js stays on the start route without lib/topology.js: no key writer, no keys
  assert.equal(targetsForCli(INVENTORY).includes('terminates_tls'), false);
  // without topology keys a line is as before
  assert.equal(targetsText(parseInventory('web01 203.0.113.10').servers), 'web01 203.0.113.10\n');
});
