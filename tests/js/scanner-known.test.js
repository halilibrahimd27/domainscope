/**
 * The origin map in discovery (lib/scanner.js `knownOrigins`): a remembered exact origin of a
 * proxied name is a host-specific hint of kind 'known' that ranks above every other candidate
 * (the zone file's included), runs with origin hints off, skips the resolver-leak pass, matches
 * its inventory server as `via: 'known'`, and goes into the CLI command exactly (`ip`, or
 * `ip:port` on another port). Then the command the views build from it (views/subdomains.js
 * originSweep) and the Verify pairs (lib/verify.js). A run without the option is unchanged.
 * No network: an emulated zone answers every DoH resolver. Example names and documentation
 * addresses only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { runScan, HOST_SPECIFIC_HINT_KINDS } from '../../assets/js/lib/scanner.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { parseInventory } from '../../assets/js/lib/inventory.js';
import { buildVerifyPairs, isOriginPair } from '../../assets/js/lib/verify.js';
import { knownForScan } from '../../assets/js/lib/originmap.js';
import { applyObservations, setRemember } from '../../assets/js/lib/originfill.js';
import { originOverview, originSweep, originSweepTokens, knownOfResult } from '../../assets/js/views/subdomains.js';

const SOA = { mname: 'ns.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };
const WORLD = {
  'example.com': { A: ['203.0.113.10'] },
  'www.example.com': { CNAME: 'proxy.cdn.cloudflare.net' },
  'shop.example.com': { CNAME: 'proxy.cdn.cloudflare.net' },
  'blog.example.com': { CNAME: 'proxy.cdn.cloudflare.net' },
  'api.example.com': { A: ['203.0.113.12'] },
  'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
};
// Another resolver leaks a direct answer for every proxied name (the resolver-leak pass).
const LEAK = {
  'www.example.com': { A: ['203.0.113.50'] },
  'shop.example.com': { A: ['203.0.113.51'] },
  'blog.example.com': { A: ['203.0.113.52'] }
};

function answer(zone, name, type) {
  const answers = [];
  let current = name;
  for (let hop = 0; hop < 8; hop += 1) {
    const node = zone[current];
    if (!node) return { rcode: answers.length ? 'NOERROR' : 'NXDOMAIN', answers, authorities: [{ name: current, type: 'SOA', ttl: 300, data: SOA }] };
    if (node.CNAME && type !== 'CNAME') {
      answers.push({ name: current, type: 'CNAME', ttl: 300, data: node.CNAME });
      current = node.CNAME;
      continue;
    }
    for (const data of node[type] || []) answers.push({ name: current, type, ttl: 300, data });
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: current, type: 'SOA', ttl: 300, data: SOA }] };
  }
  return { rcode: 'SERVFAIL', answers: [] };
}

function world() {
  const log = [];
  const fetchImpl = async (url) => {
    const resolver = RESOLVERS.find((r) => url.startsWith(`${r.url}?`));
    if (!resolver) throw new TypeError(`unexpected URL ${url}`);
    const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
    log.push({ name: q.name, type: q.type, resolver: resolver.id });
    const out = answer(resolver.id === 'google' ? { ...WORLD, ...LEAK } : WORLD, q.name, q.type);
    return new Response(encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities || [], edns: {}
    }));
  };
  return { fetchImpl, log, dns: new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 }) };
}

const LAST = '2026-09-28T08:00:00.000Z';
const KNOWN = [
  { name: 'www.example.com', ip: '192.0.2.40', port: 443, source: 'cli-json', lastConfirmed: LAST, server: 'web03' },
  { name: 'shop.example.com', ip: '198.51.100.30', port: 8443, source: 'zone', lastConfirmed: LAST },
  { name: 'gone.example.com', ip: '198.51.100.31', port: 443, source: 'manual', lastConfirmed: LAST },
  { name: 'www.example.com', ip: '104.16.5.9', port: 443, source: 'manual', lastConfirmed: LAST },
  { name: 'bad name', ip: '198.51.100.32' }
];

async function scan(extra = {}) {
  const w = world();
  const stages = [];
  const result = await runScan({
    domains: ['example.com'], sources: [], bruteforce: 'small', wordlist: ['www', 'shop', 'blog', 'api'], mine: false,
    permutationBudget: 0, recursive: false, balance: false, sourceGraceMs: 0,
    inventory: parseInventory('web03 192.0.2.40\nweb01 203.0.113.10'), dns: w.dns, fetchImpl: w.fetchImpl, ...extra
  }, { onStage: (name, info) => stages.push([name, info]) });
  return { result, stages, log: w.log };
}
const byName = (r) => new Map(r.hosts.map((h) => [h.name, h]));

describe('config.knownOrigins: the remembered origins rank first', () => {
  test("'known' is a host-specific hint kind", () => {
    assert.ok(HOST_SPECIFIC_HINT_KINDS.has('known'));
  });

  test('a proxied host\'s remembered origin is its first candidate, above a leak and the networks', async () => {
    const { result } = await scan({ knownOrigins: KNOWN, resolverLeak: true });
    const www = byName(result).get('www.example.com');
    assert.deepEqual(www.originCandidates[0], {
      ip: '192.0.2.40', kind: 'known', score: 120, evidence: { port: 443, source: 'cli-json', lastConfirmed: LAST }
    });
    assert.ok(www.originCandidates.slice(1).every((c) => c.score < 120), 'everything else below it');
    const shop = byName(result).get('shop.example.com');
    assert.deepEqual([shop.originCandidates[0].ip, shop.originCandidates[0].kind, shop.originCandidates[0].evidence.port], ['198.51.100.30', 'known', 8443]);
    // A CDN edge is never an origin, whatever the map says; a name of no proxied host adds nothing.
    assert.ok(!result.originHints.some((h) => h.ip === '104.16.5.9' || h.ip === '198.51.100.31'));
    const hint = result.originHints.find((h) => h.ip === '192.0.2.40');
    assert.deepEqual(hint.reasons.map((r) => [r.kind, r.host, r.port, r.source]), [['known', 'www.example.com', 443, 'cli-json']]);
    assert.deepEqual(hint.servers.map((s) => s.name), ['web03']);
  });

  test('hosts with a remembered origin skip the resolver-leak pass; the others still get it', async () => {
    const { result, stages } = await scan({ knownOrigins: KNOWN, resolverLeak: true });
    const hints = stages.find(([n]) => n === 'hints')[1];
    const without = (await scan({ resolverLeak: true })).stages.find(([n]) => n === 'hints')[1];
    assert.ok(hints.leakQueries < without.leakQueries, `${hints.leakQueries} < ${without.leakQueries}`);
    const blog = byName(result).get('blog.example.com');
    assert.ok(blog.originCandidates.some((c) => c.kind === 'resolver-leak' && c.ip === '203.0.113.52'), 'blog has no remembered origin: leaked as before');
    assert.ok(!result.originHints.some((h) => h.reasons.some((r) => r.kind === 'resolver-leak' && r.host === 'www.example.com')));
  });

  test('origin hints off: the remembered origins still count (they cost no query)', async () => {
    const { result } = await scan({ knownOrigins: KNOWN, originHints: false, resolverLeak: false });
    assert.equal(byName(result).get('www.example.com').originCandidates[0].kind, 'known');
    assert.deepEqual(result.known.names, ['shop.example.com', 'www.example.com']);
  });

  test('its inventory server matches as via known and needs the certificate', async () => {
    const { result } = await scan({ knownOrigins: KNOWN });
    const web03 = result.servers.find((g) => g.server.name === 'web03');
    assert.deepEqual(web03.hosts.map((x) => [x.name, x.ip, x.via]), [['www.example.com', '192.0.2.40', 'known']]);
    assert.equal(web03.needsCert, true);
  });

  test('the CLI command carries them exactly: the address on 443, ip:port on another port, never a /24', async () => {
    const { result } = await scan({ knownOrigins: KNOWN });
    assert.ok(result.cliTargets.includes('192.0.2.40'));
    assert.ok(result.cliTargets.includes('198.51.100.30:8443'));
    assert.ok(!result.cliTargets.some((tok) => tok.startsWith('192.0.2.0/') || tok.startsWith('198.51.100.0/')), 'never widened');
    assert.deepEqual(result.known, { entries: 3, names: ['shop.example.com', 'www.example.com'], cliTargets: ['192.0.2.40', '198.51.100.30:8443'] });
    assert.match(result.cliSuggestion, /-t .*192\.0\.2\.40 198\.51\.100\.30:8443 .*-n blog\.example\.com shop\.example\.com www\.example\.com$/);
  });

  test('above the zone file\'s origin of the same name', async () => {
    const zone = { v: 1, origin: 'example.com', names: ['www.example.com'], wildcardBases: [], proxied: [{ name: 'www.example.com', ips: ['192.0.2.10'], host: null }] };
    const { result } = await scan({ knownOrigins: KNOWN, zone });
    const www = byName(result).get('www.example.com');
    assert.deepEqual(www.originCandidates.slice(0, 2).map((c) => [c.ip, c.kind]), [['192.0.2.40', 'known'], ['192.0.2.10', 'zone']]);
    assert.ok(result.cliTargets.includes('192.0.2.40') && result.cliTargets.includes('192.0.2.10'));
  });

  test('a run without the option has no `known` key; an empty map runs as before', async () => {
    const plain = (await scan()).result;
    assert.ok(!('known' in plain));
    const empty = (await scan({ knownOrigins: [] })).result;
    assert.deepEqual(empty.known, { entries: 0, names: [], cliTargets: [] });
    assert.deepEqual(empty.cliTargets, plain.cliTargets);
    assert.equal(empty.cliSuggestion, plain.cliSuggestion);
    assert.deepEqual(byName(empty).get('www.example.com').originCandidates, byName(plain).get('www.example.com').originCandidates);
  });

  test('a stale entry of the map is never passed to the scan', () => {
    let map = setRemember(null, true);
    ({ map } = applyObservations(map, [{ name: 'www.example.com', ip: '192.0.2.40', port: 443, outcome: 'hosted' }], { source: 'zone', at: '2026-09-01T00:00:00Z' }));
    ({ map } = applyObservations(map, [{ name: 'www.example.com', ip: '192.0.2.40', port: 443, outcome: 'not-hosted' }], { source: 'cli-json', at: LAST }));
    assert.deepEqual(knownForScan(map), []);
  });
});

describe('the command the views build (views/subdomains.js) and the Verify pairs', () => {
  test('originSweep keeps the remembered targets exactly, ip:port included, in both shells', async () => {
    const { result } = await scan({ knownOrigins: KNOWN });
    assert.deepEqual(knownOfResult(result), { targets: ['192.0.2.40', '198.51.100.30:8443'], ports: true });
    const tokens = originSweepTokens(result, { names: ['www.example.com', 'shop.example.com', 'blog.example.com'] });
    assert.ok(tokens.targets.includes('192.0.2.40') && tokens.targets.includes('198.51.100.30:8443'));
    const o = originOverview(result);
    assert.equal(o.droppedCount, 0, 'an ip:port target is valid, not dropped');
    assert.deepEqual(o.proxied.find((p) => p.name === 'shop.example.com').known, [{ ip: '198.51.100.30', port: 8443, target: '198.51.100.30:8443' }]);
    assert.equal(o.knownCount, 2);
    for (const shell of ['posix', 'powershell']) {
      const { command } = originSweep(result, { names: o.proxied.map((p) => p.name), shell });
      assert.match(command, /192\.0\.2\.40/, shell);
      assert.match(command, /198\.51\.100\.30:8443/, shell);
    }
    assert.deepEqual(knownOfResult({}), { targets: [], ports: false });
  });

  test('a remembered origin on an inventory server is an origin pair (opt-in), checked like the zone\'s', async () => {
    const { result } = await scan({ knownOrigins: KNOWN });
    const { pairs } = buildVerifyPairs(result);
    const pair = pairs.find((p) => p.ip === '192.0.2.40' && p.name === 'www.example.com');
    assert.equal(pair.via, 'known');
    assert.equal(isOriginPair(pair), true);
    assert.equal(isOriginPair({ via: 'dns' }), false);
  });
});
