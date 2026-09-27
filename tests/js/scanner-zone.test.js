// Unit tests for the zone-import hand-off in assets/js/lib/scanner.js (`config.zone`,
// `config.exact`): zone names as seeds (origin 'zone'), exact mode, the zone file's
// exact origins as host-specific hints / `via: 'zone'` server matches / exact CLI
// targets (never widened to a /24), host targets, `*.x` names, and the regression
// guarantee that a run WITHOUT a zone is unchanged. No network: an emulated
// authoritative zone sits behind every DoH resolver. Example names and
// documentation addresses only; 192.0.2.0 appears only as the Cloudflare placeholder.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { runScan, learnedLabelsFromScan, HOST_SPECIFIC_HINT_KINDS } from '../../assets/js/lib/scanner.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { parseInventory } from '../../assets/js/lib/inventory.js';
import { zoneScanInput } from '../../assets/js/lib/zoneorigins.js';
import { loadFixture } from '../fixtures/zones-analysis/gen-analysis-golden.mjs';

/* ------------------------------------------------------------------------ */
/* Mock world                                                               */
/* ------------------------------------------------------------------------ */

const OUT_SOA = { mname: 'ns-hidden.dns-infra.invalid', rname: 'hostmaster.dns-infra.invalid', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };

function zoneAnswer(zone, name, type) {
  const answers = [];
  let current = name;
  for (let hop = 0; hop < 10; hop += 1) {
    let node = zone[current];
    if (!node) {
      const parent = current.split('.').slice(1).join('.');
      const exists = Object.keys(zone).some((k) => k.endsWith(`.${current}`) && !k.startsWith('*.'));
      if (!exists && zone[`*.${parent}`]) node = zone[`*.${parent}`];
      else return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers, authorities: [{ name: current, type: 'SOA', ttl: 300, data: OUT_SOA }] };
    }
    if (node.CNAME && type !== 'CNAME') {
      answers.push({ name: current, type: 'CNAME', ttl: 300, data: node.CNAME });
      current = node.CNAME;
      continue;
    }
    for (const data of node[type] || []) answers.push({ name: current, type, ttl: 300, data });
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: current, type: 'SOA', ttl: 300, data: OUT_SOA }] };
  }
  return { rcode: 'SERVFAIL', answers: [] };
}

function mkWorld({ zone, zonesByResolver = {}, sources = {} }) {
  const log = { doh: [], http: [] };
  const fetchImpl = async (url) => {
    const resolver = RESOLVERS.find((r) => url.startsWith(`${r.url}?`));
    if (resolver) {
      const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
      log.doh.push({ name: q.name, type: q.type, resolver: resolver.id });
      const z = zonesByResolver[resolver.id] ? { ...zone, ...zonesByResolver[resolver.id] } : zone;
      const out = zoneAnswer(z, q.name, q.type);
      return new Response(encodeMessage({
        id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
        questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities || [], edns: {}
      }));
    }
    log.http.push(url);
    for (const [prefix, handler] of Object.entries(sources)) if (url.startsWith(prefix)) return Response.json(await handler(url));
    throw new TypeError(`unexpected URL ${url}`);
  };
  return { fetchImpl, log, dns: new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 }) };
}

const byName = (scan) => new Map(scan.hosts.map((h) => [h.name, h]));

/* ------------------------------------------------------------------------ */
/* Regression: a run without a zone is unchanged                             */
/* ------------------------------------------------------------------------ */

// A deterministic scan that exercises sources, mining (MX / SPF), the wordlist,
// permutations, the recursive round, wildcard checks, a certificate, inventory
// matches, resolver-leak, sibling-domain, direct-sibling, origin networks and the
// CLI command. Its normalised output (result + every stage event) was hashed with
// the scanner BEFORE the zone hand-off landed; the digest below pins it.
const REGRESSION_WORLD = {
  'example.com': { A: ['203.0.113.10'], MX: [{ preference: 10, exchange: 'mail.example.com' }], TXT: [['v=spf1 ip4:198.51.100.0/24 a:api.example.com -all']] },
  'www.example.com': { CNAME: 'proxy.cdn.cloudflare.net' },
  'shop.example.com': { CNAME: 'proxy.cdn.cloudflare.net' },
  'api.example.com': { A: ['203.0.113.12'] },
  'app.example.com': { A: ['203.0.113.13'] },
  'mail.example.com': { A: ['198.51.100.25'] },
  'dev.example.com': { A: ['10.0.0.5'] },
  'v2.api.example.com': { A: ['203.0.113.14'] },
  'dev.api.example.com': { A: ['203.0.113.15'] },
  'example.net': { A: ['203.0.113.31'] },
  'shop.example.net': { A: ['203.0.113.30'] },
  'proxy.cdn.cloudflare.net': { A: ['104.16.5.5'] }
};
// Re-pinned since: the wildcard results gained `targets` / `variable`, then `conclusive`
// (each time the only difference in the normalised output).
const PRE_ZONE_DIGEST = 'f4a10be9d760fdc5dc605b2e9ff25378f9e4b0375639ee5aab764cf0cf58e346';

async function regressionScan(extra = {}) {
  const { fetchImpl, dns } = mkWorld({
    zone: REGRESSION_WORLD,
    zonesByResolver: { google: { 'www.example.com': { A: ['203.0.113.50'] } } },
    sources: { 'https://anubisdb.com/': (url) => (url.includes('example.com') ? ['www.example.com', 'shop.example.com', 'old.example.com'] : ['shop.example.net']) }
  });
  const inventory = parseInventory('web01 203.0.113.10\nedge01 203.0.113.50\nmx01 198.51.100.25');
  const stages = [];
  const result = await runScan({
    domains: ['example.com', 'example.net'], cert: { hostnames: ['example.com', '*.example.com'], serialHex: 'aa' },
    sources: ['anubis'], bruteforce: 'small', wordlist: ['www', 'api', 'app', 'shop', 'dev', 'mail', 'v2', 'dev.api'],
    mine: true, permutationBudget: 40, recursive: true, balance: false, sourceGraceMs: 0,
    inventory, dns, fetchImpl, ...extra
  }, { onStage: (name, info) => stages.push([name, info]) });
  return { result, stages };
}

// Timing fields vary run to run; the zone fields are new (absent / neutral without a zone).
const VOLATILE = new Set(['startedAt', 'finishedAt', 'elapsedMs', 'ms', 'durationMs', 'latencyMs', 'fetchedAt', 'at', 'tookMs', 'time']);
const NEW_ANY = new Set(['zoneSeeds', 'zoneResolved', 'zoneOnly', 'cliHostTargets']);
function digest({ result, stages }) {
  const r = { ...result, options: { ...result.options } };
  delete r.zone;
  delete r.options.zone;
  delete r.options.exact;
  const json = JSON.stringify({ r, stages }, (k, v) => {
    if (VOLATILE.has(k) || NEW_ANY.has(k)) return undefined;
    if (v instanceof Set) return [...v];
    if (v instanceof Map) return [...v.entries()];
    return v;
  });
  return createHash('sha256').update(json).digest('hex');
}

describe('runScan without a zone is unchanged', () => {
  test('normalised result + stage events match the pre-zone digest (no key, zone: null, exact: false)', async () => {
    for (const extra of [{}, { zone: null, exact: false }, { zone: undefined }]) {
      const run = await regressionScan(extra);
      assert.equal(digest(run), PRE_ZONE_DIGEST, `a no-zone run changed (${JSON.stringify(extra)}); if intended, re-pin the digest`);
      assert.equal(run.result.zone, null);
      assert.deepEqual(run.result.cliHostTargets, []);
      assert.equal(run.result.options.zone, null);
      assert.equal(run.result.options.exact, false);
      assert.ok(!('zoneSeeds' in run.result.stats) && !('zoneResolved' in run.result.stats), 'stats keep their exact shape');
      assert.ok(run.result.hosts.every((h) => h.zoneOnly === false));
    }
  });

  test('an empty or malformed zone input is ignored', async () => {
    const run = await regressionScan({ zone: { v: 1, names: [], proxied: 'nope', wildcardBases: null } });
    assert.equal(digest(run), PRE_ZONE_DIGEST);
    assert.equal(run.result.zone, null);
  });
});

/* ------------------------------------------------------------------------ */
/* Zone hand-off with the Cloudflare export fixture                          */
/* ------------------------------------------------------------------------ */

const CF_ZONE = loadFixture('cloudflare-export');
const ZONE_INPUT = zoneScanInput(CF_ZONE); // intranet.example.com (private-looking) skipped by default

// The live world: proxied names answer Cloudflare edges; DNS-only names answer their
// zone values; one name exists live that is not in the zone (only a guess finds it).
const LIVE = {
  'example.com': { A: ['104.16.1.1'], MX: [{ preference: 10, exchange: 'mail.example.com' }] },
  'www.example.com': { A: ['104.16.1.1'], AAAA: ['2606:4700::1'] },
  'docs.example.com': { CNAME: 'www.example.com' },
  'api.example.com': { A: ['104.16.1.2'] },
  'app.example.com': { A: ['104.16.1.3'] },
  'mixed.example.com': { A: ['104.16.1.4'] },
  'tagged.example.com': { A: ['104.16.1.5'] },
  'tunnel.example.com': { A: ['104.16.1.6'] },
  'x1.apps.example.com': { A: ['104.16.1.7'] },
  'admin.example.com': { A: ['192.0.2.12'] },
  'ftp.example.com': { A: ['192.0.2.10'] },
  'mail.example.com': { A: ['198.51.100.25'] },
  'vpn.example.com': { A: ['203.0.113.5'] },
  'status.example.com': { A: ['203.0.113.80'] },
  'legacy.shop.example.com': { A: ['192.0.2.50'] },
  'v6only.example.com': { AAAA: ['2001:db8::77'] },
  'blog.example.com': { CNAME: 'example-blog.github.io' },
  'example-blog.github.io': { A: ['185.199.108.153'] },
  'shop.example.com': { CNAME: 'shops.myshopify.com' },
  'shops.myshopify.com': { A: ['198.51.100.66'] },
  'secret.example.com': { A: ['203.0.113.9'] }
};

async function zoneScan(extra = {}, { zonesByResolver = {} } = {}) {
  const world = mkWorld({ zone: LIVE, zonesByResolver });
  const stages = [];
  const result = await runScan({
    domains: ['example.com'], sources: [], bruteforce: 'small', wordlist: ['secret'], mine: false,
    permutationBudget: 0, recursive: false, balance: false, sourceGraceMs: 0,
    inventory: parseInventory('web01 192.0.2.10\nweb02 192.0.2.40'),
    zone: ZONE_INPUT, dns: world.dns, fetchImpl: world.fetchImpl, ...extra
  }, { onStage: (name, info) => stages.push([name, info]) });
  return { result, stages, log: world.log };
}

describe('config.zone: seeds and exact mode', () => {
  test('exact mode resolves the zone names only: no sources, mining, wordlist, permutations or wildcard probes', async () => {
    const { result, stages, log } = await zoneScan({ exact: true, sources: ['anubis'], mine: true, permutationBudget: 50, recursive: true, originHints: false });
    const h = byName(result);
    const seeds = new Set([...ZONE_INPUT.names, ...ZONE_INPUT.wildcardBases, ...ZONE_INPUT.delegations]);
    for (const n of seeds) assert.ok(h.has(n), `seed ${n} resolved`);
    assert.ok(!h.has('secret.example.com'), 'no wordlist guess in exact mode');
    assert.equal(log.http.length, 0, 'no passive source was contacted');
    assert.ok(log.doh.every((q) => seeds.has(q.name)), `only seed names are queried: ${[...new Set(log.doh.map((q) => q.name))].filter((n) => !seeds.has(n))}`);
    const stage = Object.fromEntries(stages);
    assert.equal(stage.sources.skipped, true);
    assert.equal(stage.mining.skipped, true);
    assert.equal(stage.wildcard.skipped, true);
    assert.equal(stage.bruteforce.skipped, true);
    assert.equal(stage.permutations.skipped, true);
    assert.equal(result.options.exact, true);
    assert.equal(result.options.bruteforce, 'off');
    assert.deepEqual(result.options.sources, []);
    assert.equal(result.options.mine, false);
    assert.equal(result.stats.zoneSeeds, seeds.size);
    assert.ok(result.stats.zoneResolved >= 15);
    assert.deepEqual(result.warnings, []);
  });

  test('zone origins rank after input and before the certificate; zoneOnly marks zone-only hosts', async () => {
    const { result } = await zoneScan({ exact: true, cert: { hostnames: ['example.com', 'www.example.com'], serialHex: '01' } });
    const h = byName(result);
    assert.deepEqual(h.get('example.com').origins, ['input', 'zone', 'cert']);
    assert.deepEqual(h.get('www.example.com').origins, ['zone', 'cert']);
    assert.equal(h.get('example.com').zoneOnly, false);
    assert.equal(h.get('www.example.com').zoneOnly, false, 'the certificate is other evidence');
    assert.equal(h.get('tagged.example.com').zoneOnly, true);
    assert.deepEqual(learnedLabelsFromScan(result).filter((l) => ['tagged', 'mixed', 'vpn', 'legacy', 'shop'].includes(l)), [],
      'zone-only labels are never learned');
  });

  test('discovery mode: zone names seed a normal scan; a zone wildcard base is never a brute-force base', async () => {
    const { result, stages } = await zoneScan({ exact: false });
    const h = byName(result);
    assert.deepEqual(h.get('secret.example.com').origins, ['wordlist'], 'the normal options still run');
    assert.ok(h.get('tagged.example.com').origins.includes('zone'));
    const bfStage = stages.find(([n]) => n === 'bruteforce')[1];
    assert.deepEqual(bfStage.parents, ['example.com']);
    assert.deepEqual(result.wildcardBases, [], 'certificate wildcard bases are untouched');
    assert.deepEqual(result.zone.wildcardBases, ['apps.example.com']);
    assert.ok(h.get('apps.example.com').origins.includes('zone'));
    assert.equal(result.options.exact, false);
  });

  test('names outside every scanned root are dropped with one ZONE_OUT_OF_SCOPE warning', async () => {
    const { result } = await zoneScan({ exact: true, domains: ['example.org'] });
    const total = ZONE_INPUT.names.length + ZONE_INPUT.wildcardBases.length + ZONE_INPUT.delegations.length;
    assert.deepEqual(result.warnings, [{ code: 'ZONE_OUT_OF_SCOPE', detail: String(total) }]);
    assert.deepEqual(result.hosts.map((x) => x.name), ['example.org']);
    assert.equal(result.zone.outOfScope, total);
    assert.equal(result.zone.seeds, 0);
    assert.equal(result.zone.proxied, 0);
    assert.deepEqual(result.cliHostTargets, []);
    assert.ok(!result.originHints.some((x) => x.reasons.some((r) => r.kind === 'zone')));
  });

  test('without domains the zone origin is the target', async () => {
    const { result } = await zoneScan({ exact: true, domains: [] });
    assert.deepEqual(result.domains, ['example.com']);
    assert.equal(result.zone.origin, 'example.com');
  });
});

describe('config.zone: exact origins', () => {
  test('host-specific zone hints, via: zone server matches, exact CLI targets, host targets and *.x names', async () => {
    const { result } = await zoneScan({ exact: true, originHints: false });
    // hints: one per exact origin address, host-specific; *.x names none; CF placeholders none
    const zoneHint = (ip) => result.originHints.find((x) => x.ip === ip);
    assert.deepEqual(zoneHint('192.0.2.10').reasons.filter((r) => r.kind === 'zone').map((r) => r.host).sort(),
      ['docs.example.com', 'example.com', 'www.example.com']);
    assert.deepEqual(zoneHint('192.0.2.10').hosts, ['example.com', 'docs.example.com', 'www.example.com']);
    assert.ok(!zoneHint('192.0.2.20'), 'a *.x origin names no single host');
    assert.ok(HOST_SPECIFIC_HINT_KINDS.has('zone'));
    // origin candidates: the zone origin first
    const www = byName(result).get('www.example.com');
    assert.deepEqual(www.originCandidates[0], { ip: '192.0.2.10', kind: 'zone', score: 110, evidence: { source: 'zone' } });
    // server groups: the zone origin matches its own host only, as 'zone', and counts toward needsCert
    const web02 = result.servers.find((g) => g.server.name === 'web02');
    assert.deepEqual(web02.hosts.map((e) => [e.name, e.ip, e.via]), [['tagged.example.com', '192.0.2.40', 'zone']]);
    assert.equal(web02.needsCert, true);
    assert.equal(web02.maybeNeedsCert, false);
    const web01 = result.servers.find((g) => g.server.name === 'web01');
    assert.deepEqual(web01.hosts.map((e) => `${e.via}:${e.name}`),
      ['dns:ftp.example.com', 'zone:example.com', 'zone:docs.example.com', 'zone:www.example.com']);
    // CLI: every exact zone origin as an exact token (IPv4 first), the host origin, the *.x name
    for (const ip of ['192.0.2.10', '192.0.2.13', '192.0.2.20', '192.0.2.30', '192.0.2.31', '192.0.2.40', '2001:db8::10']) {
      assert.ok(result.cliTargets.includes(ip), `exact target ${ip}`);
    }
    assert.deepEqual(result.cliHostTargets, ['origin-lb.example.net']);
    assert.ok(result.cliNames.includes('*.apps.example.com'));
    assert.ok(result.cliNames.includes('app.example.com'));
    assert.match(result.cliSuggestion, / '\*\.apps\.example\.com'/);
    assert.match(result.cliSuggestion, / origin-lb\.example\.net /);
    assert.deepEqual(result.zone.cliHostTargets, ['origin-lb.example.net']);
    assert.deepEqual(result.zone.cliTargets, ['192.0.2.10', '192.0.2.13', '192.0.2.20', '192.0.2.30', '192.0.2.31', '192.0.2.40', '2001:db8::10']);
    assert.deepEqual(result.zone.cliNames, ['example.com', 'api.example.com', 'app.example.com', '*.apps.example.com',
      'docs.example.com', 'mixed.example.com', 'tagged.example.com', 'www.example.com']);
    // originNetworks never gains a network from the zone alone
    assert.ok(!result.originNetworks.some((n) => n.hosts.includes('www.example.com')));
  });

  test('general hints stay hint; a zone-known host skips the resolver-leak pass', async () => {
    const leak = { google: { 'www.example.com': { A: ['203.0.113.50'] }, 'tunnel.example.com': { A: ['203.0.113.60'] } } };
    const { result, log } = await zoneScan({ exact: true, originHints: true }, { zonesByResolver: leak });
    const web01 = result.servers.find((g) => g.server.name === 'web01');
    const via = Object.fromEntries(web01.hosts.map((e) => [e.name, e.via]));
    assert.equal(via['www.example.com'], 'zone');
    assert.equal(via['ftp.example.com'], 'dns');
    assert.equal(via['tunnel.example.com'], 'hint', 'the direct-sibling hint on the same address is general');
    const order = web01.hosts.map((e) => e.via);
    assert.deepEqual(order, [...order].sort((a, b) => ['dns', 'zone', 'hint'].indexOf(a) - ['dns', 'zone', 'hint'].indexOf(b)));
    const leaked = result.originHints.flatMap((x) => x.reasons.filter((r) => r.kind === 'resolver-leak').map((r) => r.host));
    assert.deepEqual(leaked, ['tunnel.example.com'], 'www (zone-known) is never re-resolved; tunnel (not in the proxied map) is');
    assert.ok(!log.doh.some((q) => q.name === 'www.example.com' && q.resolver !== 'cloudflare'));
  });

  test('private zone origins are exact targets (never a /24); placeholders and Cloudflare addresses never are', async () => {
    const world = mkWorld({ zone: { 'example.com': { A: ['104.16.1.1'] }, 'int.example.com': { A: ['104.16.1.8'] }, 'ph.example.com': { A: ['104.16.1.9'] } } });
    const result = await runScan({
      domains: ['example.com'], exact: true, originHints: false, balance: false,
      zone: {
        v: 1, origin: 'example.com', names: ['int.example.com', 'ph.example.com', 'cf.example.com'], wildcardBases: [],
        proxied: [
          { name: 'int.example.com', ips: ['10.20.30.40', '10.20.30.42'], host: null },
          { name: 'ph.example.com', ips: ['192.0.2.0', '100::'], host: null },
          { name: 'cf.example.com', ips: ['104.16.1.9'], host: null },
          { name: 'bad.example.com', ips: ['not-an-ip'], host: '0x7f.0x1' }
        ]
      },
      dns: world.dns, fetchImpl: world.fetchImpl
    });
    assert.deepEqual(result.cliTargets, ['10.20.30.40', '10.20.30.42']);
    assert.deepEqual(result.cliHostTargets, []);
    // live-proxied names join -n as always; cf.example.com (not live, no usable origin) does not
    assert.deepEqual(result.cliNames, ['example.com', 'int.example.com', 'ph.example.com']);
    assert.deepEqual(result.zone.cliNames, ['int.example.com']);
    assert.deepEqual(result.originHints.map((x) => x.ip), ['10.20.30.40', '10.20.30.42']);
    assert.equal(result.zone.proxied, 1, 'placeholder-only, Cloudflare-only and invalid entries are dropped');
    assert.match(result.cliSuggestion, /-t 10\.20\.30\.40 10\.20\.30\.42 -n /);
  });

  test('zone names are kept first when maxHosts truncates', async () => {
    const { result } = await zoneScan({ exact: false, wordlist: ['secret', 'nope1', 'nope2'], maxHosts: 5 });
    const zoneNames = result.hosts.filter((x) => x.origins.includes('zone')).length;
    assert.equal(result.hosts.length, 5);
    assert.equal(zoneNames, 5, 'every kept host is an input / zone seed');
    assert.ok(result.warnings.some((w) => w.code === 'TRUNCATED'));
  });
});
