// Unit tests for assets/js/lib/scanner.js — end-to-end scans against a mocked
// world: an emulated authoritative zone behind every DoH resolver, mocked
// passive sources (same payload shapes as the real services), a real parsed
// certificate fixture and a parsed inventory. No network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runScan, SCAN_STAGES } from '../../assets/js/lib/scanner.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { parseInventory } from '../../assets/js/lib/inventory.js';
import { AbortError } from '../../assets/js/lib/util.js';

const FIX = new URL('../fixtures/', import.meta.url);
// SANs: example-test.com.tr, www., api., *.cdn., xn--mnchen-3ya.  (serial f1e2d3c4b5a69788)
const CERT = parseCertificates(readFileSync(new URL('rsa_multi_san.pem', FIX), 'utf8')).leaf;

const D = 'example-test.com.tr';
const SOA = { mname: `ns1.${D}`, rname: `hostmaster.${D}`, serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };

/* ------------------------------------------------------------------------ */
/* Mock world                                                               */
/* ------------------------------------------------------------------------ */

const BASE_ZONE = {
  [D]: {
    A: ['203.0.113.10'],
    MX: [{ preference: 10, exchange: `mail.${D}` }],
    TXT: [[`v=spf1 ip4:203.0.113.25 a:mail.${D} include:_spf.provider.net ip4:10.20.0.0/24 -ip4:203.0.113.10 ~all`], ['google-site-verification=abc']]
  },
  [`www.${D}`]: { CNAME: `${D}.cdn.cloudflare.net` },
  [`${D}.cdn.cloudflare.net`]: { A: ['104.16.10.1', '172.67.1.1'], AAAA: ['2606:4700::6810:a01'] },
  [`api.${D}`]: { A: ['104.21.5.5'] },
  [`mail.${D}`]: { A: ['203.0.113.25'] },
  [`shop.${D}`]: { A: ['172.67.2.2'] },
  [`dev.${D}`]: { A: ['10.20.0.7'] },
  [`old.${D}`]: { CNAME: 'old-app.herokuapp.com' },
  [`cdn.${D}`]: { CNAME: 'd111.cloudfront.net' },
  [`*.cdn.${D}`]: { CNAME: 'd111.cloudfront.net' },
  [`static.cdn.${D}`]: { A: ['198.51.100.77'] },
  'd111.cloudfront.net': { A: ['13.32.1.1'] },
  [`admin.${D}`]: { A: ['203.0.113.10'] },
  [`vpn.${D}`]: { A: ['203.0.113.99'] },
  '_spf.provider.net': { TXT: [['v=spf1 ip4:198.18.5.5 ip4:192.0.2.0/24 include:_spf.provider.net -all']] }
};

function zoneAnswer(zone, name, type) {
  const answers = [];
  let current = name;
  for (let hop = 0; hop < 10; hop += 1) {
    let node = zone[current];
    if (!node) {
      const parent = current.split('.').slice(1).join('.');
      const exists = Object.keys(zone).some((k) => k.endsWith(`.${current}`) && !k.startsWith('*.'));
      if (!exists && zone[`*.${parent}`]) node = zone[`*.${parent}`];
      else return { rcode: exists ? 'NOERROR' : 'NXDOMAIN', answers, authorities: [{ name: D, type: 'SOA', ttl: 300, data: SOA }] };
    }
    if (node.CNAME && type !== 'CNAME') {
      answers.push({ name: current, type: 'CNAME', ttl: 300, data: node.CNAME });
      current = node.CNAME;
      continue;
    }
    for (const data of node[type] || []) answers.push({ name: current, type, ttl: 300, data });
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: D, type: 'SOA', ttl: 300, data: SOA }] };
  }
  return { rcode: 'SERVFAIL', answers: [] };
}

const SOURCE_PAYLOADS = {
  'https://crt.sh/': () => [
    { issuer_ca_id: 1, issuer_name: 'C=US, CN=Test CA', common_name: D, name_value: `${D}\nwww.${D}\napi.${D}\n*.cdn.${D}\nxn--mnchen-3ya.${D}`, id: 100, not_before: '2026-06-01T00:00:00', not_after: '2034-06-01T00:00:00', serial_number: 'f1e2d3c4b5a69788' },
    { issuer_ca_id: 2, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: `shop.${D}`, name_value: `shop.${D}\nold.${D}`, id: 101, not_before: '2026-08-01T00:00:00', not_after: '2026-10-30T00:00:00', serial_number: '0badc0de' }
  ],
  'https://api.certspotter.com/': (url) => (url.includes('after=') ? [] : [{ id: '9', cert_sha256: 'aa'.repeat(32), dns_names: [`gone.${D}`], not_before: '2026-01-01T00:00:00Z', not_after: '2026-12-01T00:00:00Z' }]),
  'https://api.hackertarget.com/': () => new Response(`www.${D},104.16.10.1\n${D},203.0.113.10\n`),
  'https://anubisdb.com/': () => [`dev.${D}`, 'unrelated.other.com'],
  'https://otx.alienvault.com/': () => ({
    passive_dns: [
      { hostname: `www.${D}`, address: '203.0.113.50', record_type: 'A', first: '2022-01-01T00:00:00', last: '2024-05-01T00:00:00' },
      { hostname: `shop.${D}`, address: '203.0.113.60', record_type: 'A', first: '2023-01-01T00:00:00', last: '2023-06-01T00:00:00' },
      { hostname: `api.${D}`, address: '104.21.5.5', record_type: 'A', first: '2024-01-01T00:00:00', last: '2026-09-01T00:00:00' }
    ]
  }),
  'https://ip.thc.org/': () => ({ matching_records: 0, domains: [], next_page_state: '' })
};

const INVENTORY_TEXT = `
# name ip
web01 203.0.113.10
mail01 203.0.113.25
app02 203.0.113.50
dev01 10.20.0.7
relay01 192.0.2.44
spare01 198.51.100.200
`;

/** fetchImpl serving DoH (zone) for every resolver URL and the mocked passive sources. */
function world({ zone = BASE_ZONE, sources = SOURCE_PAYLOADS, dohDelay = 0, onDoh } = {}) {
  const log = { doh: [], http: [] };
  const fetchImpl = async (url, init = {}) => {
    const resolver = RESOLVERS.find((r) => url.startsWith(`${r.url}?`));
    if (resolver) {
      const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
      log.doh.push({ name: q.name, type: q.type, resolver: resolver.id });
      if (onDoh) await onDoh(q, init);
      if (dohDelay) await new Promise((r) => setTimeout(r, dohDelay));
      const out = zoneAnswer(zone, q.name, q.type);
      return new Response(encodeMessage({
        id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
        questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities || [], edns: {}
      }));
    }
    log.http.push(url);
    for (const [prefix, handler] of Object.entries(sources)) {
      if (url.startsWith(prefix)) {
        const out = await handler(url, init);
        return out instanceof Response ? out : Response.json(out);
      }
    }
    throw new TypeError(`unexpected URL ${url}`);
  };
  return { fetchImpl, log, dns: new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 }) };
}

const byName = (scan) => new Map(scan.hosts.map((h) => [h.name, h]));
const serverGroup = (scan, name) => scan.servers.find((g) => g.server.name === name);

/* ------------------------------------------------------------------------ */

describe('runScan end-to-end', () => {
  test('full pipeline: seeds, sources, wildcard, brute force, resolve, classify, coverage, inventory, hints', async () => {
    const { fetchImpl, dns, log } = world();
    const inventory = parseInventory(INVENTORY_TEXT).servers;
    const stages = [];
    const sourcesSeen = [];
    const streamed = [];
    const progress = [];
    const scan = await runScan({
      domains: [D], cert: CERT, extraNames: [], sources: undefined, includeExpired: false,
      bruteforce: 'small', wordlist: ['api', 'static', 'admin', 'panel', 'vpn'],
      // this test pins the classic sources+wildcard+wordlist+resolve+hints path;
      // the DNS-mine / permutation / recursive stages are covered in scanner-v2.test.js
      mine: false, permutationBudget: 0, recursive: false,
      inventory, originHints: true, dns, fetchImpl
    }, {
      onStage: (s, info) => stages.push([s, info]),
      onSource: (r) => sourcesSeen.push(r.source),
      onHost: (hr) => streamed.push(hr.name),
      onProgress: (p) => progress.push(p)
    });

    // stages reported in execution order
    assert.deepEqual(stages.map((s) => s[0]), [...SCAN_STAGES]);
    assert.deepEqual(stages[0][1].domains, [D]);
    assert.equal(sourcesSeen.length, 6);
    assert.ok(progress.some((p) => p.stage === 'resolve' && p.done === p.total));
    assert.ok(progress.some((p) => p.stage === 'bruteforce' && p.total === 9));

    // hosts: deterministic order, out-of-scope and wildcard brute-force names dropped
    assert.deepEqual(scan.hosts.map((h) => h.name), [
      D, `admin.${D}`, `api.${D}`, `cdn.${D}`, `static.cdn.${D}`, `dev.${D}`, `gone.${D}`,
      `old.${D}`, `shop.${D}`, `vpn.${D}`, `www.${D}`, `xn--mnchen-3ya.${D}`
    ]);
    assert.deepEqual([...streamed].sort(), scan.hosts.map((h) => h.name).sort());
    assert.deepEqual(scan.domains, [D]);
    assert.deepEqual(scan.wildcardBases, [`cdn.${D}`]);
    assert.ok(scan.startedAt instanceof Date && scan.finishedAt instanceof Date);

    const h = byName(scan);
    // origins
    assert.deepEqual(h.get(D).origins, ['input', 'cert', 'crtsh', 'hackertarget']);
    assert.deepEqual(h.get(`www.${D}`).origins, ['cert', 'crtsh', 'hackertarget', 'otx']);
    assert.deepEqual(h.get(`admin.${D}`).origins, ['wordlist']);
    assert.deepEqual(h.get(`dev.${D}`).origins, ['anubis']);
    assert.deepEqual(h.get(`gone.${D}`).origins, ['certspotter']);

    // classification
    const kind = (n) => h.get(n).classification.kind;
    assert.equal(kind(`www.${D}`), 'cloudflare');
    assert.equal(h.get(`www.${D}`).classification.hidesOrigin, true);
    assert.deepEqual(h.get(`www.${D}`).resolution.cnames, [`${D}.cdn.cloudflare.net`]);
    assert.equal(kind(`api.${D}`), 'cloudflare');
    assert.equal(kind(`cdn.${D}`), 'cdn');
    assert.equal(h.get(`cdn.${D}`).classification.provider.id, 'cloudfront');
    assert.equal(kind(D), 'direct');
    assert.equal(kind(`dev.${D}`), 'private');
    assert.equal(kind(`gone.${D}`), 'nxdomain');
    assert.equal(kind(`old.${D}`), 'unresolved');
    assert.equal(h.get(`old.${D}`).classification.dangling, true);

    // certificate coverage (RFC 6125 wildcard rules)
    assert.deepEqual(h.get(`www.${D}`).cert, { covered: true, by: `www.${D}` });
    assert.deepEqual(h.get(`static.cdn.${D}`).cert, { covered: true, by: `*.cdn.${D}` });
    assert.equal(h.get(`cdn.${D}`).cert.covered, false, '*.cdn.x does not cover cdn.x');
    assert.equal(h.get(`admin.${D}`).cert.covered, false);

    // inventory matches
    assert.deepEqual(h.get(D).servers, [{ serverId: 'web01', name: 'web01', ip: '203.0.113.10' }]);
    assert.deepEqual(h.get(`dev.${D}`).servers.map((s) => s.name), ['dev01']);
    assert.deepEqual(h.get(`www.${D}`).servers, []);

    // passive IP hints attached to hosts
    assert.deepEqual(h.get(`www.${D}`).ipHints.map((x) => `${x.source}:${x.ip}`).sort(), ['hackertarget:104.16.10.1', 'otx:203.0.113.50']);
    assert.ok(scan.hosts.every((x) => x.wildcardSuspect === false));

    // wildcard detection per domain / base
    assert.equal(scan.wildcards[D].wildcard, false);
    assert.equal(scan.wildcards[`cdn.${D}`].wildcard, true);
    assert.deepEqual(scan.wildcards[`cdn.${D}`].cnames, ['d111.cloudfront.net']);

    // stats
    assert.deepEqual({ ...scan.stats, dnsQueries: 0, elapsedMs: 0 }, {
      total: 12, resolved: 9, cloudflare: 3, cdn: 1, platform: 0, direct: 4, private: 1, nxdomain: 2,
      dangling: 1, covered: 5, matchedServers: 2, wildcardSuspects: 0,
      unresolved: 1, hiddenOrigin: 4, needsCert: 1, hintedServers: 3, originHints: 8, unmatchedIps: 2,
      sourcesOk: 6, sourcesFailed: 0,
      fromSources: 9, fromDns: 3, wildcardParents: 1, mineFound: 0,
      wordlistFound: 3, permutationFound: 0, recursiveFound: 0,
      bruteforceTried: 9, bruteforceFound: 3, bruteforceWildcardDropped: 4, bruteforceErrors: 0,
      permutationTried: 0, permutationWildcardDropped: 0, permutationErrors: 0,
      recursiveTried: 0, recursiveWildcardDropped: 0, recursiveErrors: 0,
      ctCerts: 3, dnsQueries: 0, truncated: false, elapsedMs: 0
    });

    // origin hints
    const hints = new Map(scan.originHints.map((x) => [x.ip, x]));
    assert.deepEqual([...hints.keys()].sort(), [
      '10.20.0.7', '192.0.2.44', '198.51.100.77', '203.0.113.10', '203.0.113.25', '203.0.113.50', '203.0.113.60', '203.0.113.99'
    ]);
    assert.ok(!hints.has('198.18.5.5'), 'third-party SPF IP without inventory match is dropped');
    assert.ok(!hints.has('104.16.10.1'), 'CDN IPs are never origin hints');
    // v2: 'history' reasons carry structured { host, source, lastSeen } so the
    // views no longer parse the human-readable `detail` string.
    assert.deepEqual(hints.get('203.0.113.50').reasons, [{ kind: 'history', host: `www.${D}`, source: 'otx', lastSeen: '2024-05-01', detail: `otx: www.${D} (last seen 2024-05-01)` }]);
    assert.deepEqual(hints.get('203.0.113.50').servers, [{ serverId: 'app02', name: 'app02' }]);
    assert.deepEqual(hints.get('203.0.113.25').reasons.map((r) => r.kind).sort(), ['mx', 'spf', 'spf']);
    assert.ok(hints.get('203.0.113.25').reasons.some((r) => r.detail === `${D}: MX 10 mail.${D}`));
    assert.deepEqual(hints.get('192.0.2.44').reasons, [{ kind: 'spf', detail: `${D} → _spf.provider.net: ip4:192.0.2.0/24` }]);
    assert.deepEqual(hints.get('10.20.0.7').reasons.map((r) => r.kind).sort(), ['direct-sibling', 'spf']);
    assert.deepEqual(hints.get('203.0.113.10').reasons, [{ kind: 'direct-sibling', detail: `${D}, admin.${D}` }]);
    assert.equal(hints.get('203.0.113.60').servers.length, 0);
    // hints with inventory servers come first
    const firstNoServer = scan.originHints.findIndex((x) => !x.servers.length);
    assert.ok(scan.originHints.slice(firstNoServer).every((x) => !x.servers.length));

    // server groups
    assert.deepEqual(scan.servers.map((g) => g.server.name), ['web01', 'app02', 'dev01', 'mail01', 'relay01']);
    const web01 = serverGroup(scan, 'web01');
    assert.equal(web01.needsCert, true);
    assert.deepEqual(web01.hosts.filter((x) => x.via === 'dns'), [
      { name: D, ip: '203.0.113.10', covered: true, via: 'dns' },
      { name: `admin.${D}`, ip: '203.0.113.10', covered: false, via: 'dns' }
    ]);
    assert.deepEqual(web01.hosts.filter((x) => x.via === 'hint').map((x) => x.name), [`api.${D}`, `cdn.${D}`, `shop.${D}`, `www.${D}`]);
    const app02 = serverGroup(scan, 'app02');
    assert.deepEqual(app02.hosts, [{ name: `www.${D}`, ip: '203.0.113.50', covered: true, via: 'hint' }]);
    assert.equal(app02.needsCert, false);
    assert.equal(app02.maybeNeedsCert, true);
    const dev01 = serverGroup(scan, 'dev01');
    assert.equal(dev01.needsCert, false, 'dev is not covered by the certificate');
    assert.equal(dev01.maybeNeedsCert, true);
    assert.ok(!scan.servers.some((g) => g.server.name === 'spare01'));

    // unmatched direct IPs
    assert.deepEqual(scan.unmatchedIps.map((u) => [u.ip, u.hosts]), [
      ['198.51.100.77', [`static.cdn.${D}`]],
      ['203.0.113.99', [`vpn.${D}`]]
    ]);
    assert.equal(scan.unmatchedIps[0].provider, null);

    // sources + CT certificates
    assert.deepEqual(scan.sources.map((r) => [r.source, r.ok]), [['crtsh', true], ['certspotter', true], ['hackertarget', true], ['anubis', true], ['otx', true], ['thc', true]]);
    assert.equal(scan.ctCerts.find((c) => c.serialHex === 'f1e2d3c4b5a69788').matchesCert, true);
    assert.equal(scan.ctCerts.filter((c) => c.matchesCert).length, 1);

    // one source request per source (certspotter: + one empty page); bulk A-only probes
    // and the final resolve use balance mode, and the resolver-leak hint re-resolves
    // proxied hosts through the failover chain — so DoH spreads across several healthy
    // resolvers, every one a known resolver (which exact ids depends on resolvers.js).
    assert.equal(log.http.filter((u) => u.startsWith('https://crt.sh/')).length, 1);
    const usedResolvers = new Set(log.doh.map((q) => q.resolver));
    assert.ok(usedResolvers.size > 1, 'balance mode + resolver-leak spread DoH across the pool');
    assert.ok([...usedResolvers].every((r) => RESOLVERS.some((x) => x.id === r)), 'every resolver used is a known resolver');
  });

  test('domains default to the registrable domains of the certificate names', async () => {
    const { fetchImpl, dns } = world();
    const scan = await runScan({ cert: CERT, sources: [], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false, dns, fetchImpl, originHints: false });
    assert.deepEqual(scan.domains, [D]);
    assert.deepEqual(scan.hosts.map((h) => h.name), [D, `api.${D}`, `cdn.${D}`, `www.${D}`, `xn--mnchen-3ya.${D}`]);
    assert.equal(scan.stats.covered, 4);
    assert.deepEqual(scan.originHints, []);
    assert.deepEqual(scan.servers, []);
  });

  test('sources disabled, no cert: coverage is null and every DNS-matched server "needs" the cert', async () => {
    const { fetchImpl, dns, log } = world();
    const stages = [];
    const scan = await runScan({
      domains: `${D}\n# comment`, extraNames: [`admin.${D}`, 'not a name!'], sources: [],
      bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false, dns, fetchImpl,
      inventory: parseInventory(INVENTORY_TEXT), originHints: false
    }, { onStage: (s, info) => stages.push([s, info.skipped]) });
    assert.equal(log.http.length, 0);
    assert.deepEqual(stages, [['sources', true], ['mining', true], ['wildcard', undefined], ['bruteforce', true], ['permutations', true], ['resolve', undefined], ['hints', true], ['done', undefined]]);
    assert.deepEqual(scan.hosts.map((h) => h.name), [D, `admin.${D}`]);
    assert.ok(scan.hosts.every((h) => h.cert === null));
    assert.equal(serverGroup(scan, 'web01').needsCert, true);
    assert.deepEqual(scan.warnings, [{ code: 'INVALID_NAME', detail: 'not a name!' }]);
    assert.equal(scan.stats.covered, 0);
  });

  test('wildcard zones: brute-force hits identical to the wildcard are dropped; passive names are flagged', async () => {
    const zone = {
      'wild.example': { A: ['192.0.2.1'] },
      '*.wild.example': { A: ['192.0.2.80'] },
      'real.wild.example': { A: ['192.0.2.81'] },
      'app.wild.example': { A: ['192.0.2.80'] } // explicit record, same answer as the wildcard
    };
    const { fetchImpl, dns } = world({
      zone,
      sources: { 'https://anubisdb.com/': () => ['app.wild.example', 'foo.wild.example'] }
    });
    const scan = await runScan({
      domains: ['wild.example'], sources: ['anubis'], bruteforce: 'small', wordlist: ['www', 'real', 'mail', 'api'],
      dns, fetchImpl, originHints: false
    });
    const h = byName(scan);
    assert.equal(scan.wildcards['wild.example'].wildcard, true);
    assert.deepEqual(scan.wildcards['wild.example'].ipv4, ['192.0.2.80']);
    assert.ok(h.has('real.wild.example'), 'brute-force hit with a different answer is kept');
    assert.ok(!h.has('www.wild.example') && !h.has('mail.wild.example') && !h.has('api.wild.example'));
    assert.equal(h.get('app.wild.example').wildcardSuspect, true, 'passive name kept but flagged');
    assert.equal(h.get('foo.wild.example').wildcardSuspect, true);
    assert.equal(h.get('real.wild.example').wildcardSuspect, false);
    assert.equal(scan.stats.wildcardSuspects, 2);
    assert.equal(scan.stats.bruteforceWildcardDropped, 3);
    assert.equal(scan.stats.bruteforceFound, 1);
  });

  test('source failures are reported and do not stop the scan', async () => {
    const { fetchImpl, dns } = world({
      sources: {
        ...SOURCE_PAYLOADS,
        'https://otx.alienvault.com/': () => new Response(JSON.stringify({ detail: 'Anonymous access is limited' }), { status: 429 }),
        'https://api.hackertarget.com/': () => new Response('API count exceeded - Increase Quota with Membership')
      }
    });
    const scan = await runScan({ domains: [D], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false, dns, fetchImpl, originHints: false });
    const failed = scan.sources.filter((r) => !r.ok).map((r) => [r.source, r.errorKind]);
    assert.deepEqual(failed, [['hackertarget', 'rate-limit'], ['otx', 'rate-limit']]);
    assert.equal(scan.stats.sourcesFailed, 2);
    assert.ok(byName(scan).has(`shop.${D}`));
  });

  test('DNS transport failures surface as ERROR hosts, not exceptions', async () => {
    const { fetchImpl, dns } = world({ onDoh: (q) => { if (q.name === `api.${D}`) throw new TypeError('network down'); } });
    const scan = await runScan({ domains: [D], cert: CERT, sources: [], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false, dns, fetchImpl, originHints: false });
    const api = byName(scan).get(`api.${D}`);
    assert.equal(api.resolution.status, 'ERROR');
    assert.equal(api.classification.kind, 'unresolved');
    assert.match(api.resolution.error, /network down/);
  });

  test('maxHosts keeps input/cert names first; warnings report truncation', async () => {
    const many = Array.from({ length: 30 }, (_, i) => `h${i}.${D}`);
    const { fetchImpl, dns } = world({ sources: { 'https://anubisdb.com/': () => many } });
    const scan = await runScan({ domains: [D], cert: CERT, sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false, dns, fetchImpl, maxHosts: 8, originHints: false });
    assert.equal(scan.hosts.length, 8);
    for (const n of [D, `www.${D}`, `api.${D}`, `cdn.${D}`, `xn--mnchen-3ya.${D}`]) assert.ok(byName(scan).has(n), n);
    assert.equal(scan.stats.truncated, true);
    assert.equal(scan.warnings.find((w) => w.code === 'TRUNCATED').detail, '35 > 8');
  });

  test('SPF include loops and lookup limits are bounded', async () => {
    const zone = {
      'loop.example': { A: ['192.0.2.9'], TXT: [['v=spf1 include:a.loop.example ip4:192.0.2.200 -all']] },
      'a.loop.example': { TXT: [['v=spf1 include:b.loop.example -all']] },
      'b.loop.example': { TXT: [['v=spf1 include:a.loop.example include:loop.example a mx a:x1.loop.example a:x2.loop.example a:x3.loop.example a:x4.loop.example a:x5.loop.example a:x6.loop.example a:x7.loop.example a:x8.loop.example a:x9.loop.example -all']] },
      'proxied.loop.example': { A: ['104.16.0.1'] }
    };
    const { fetchImpl, dns } = world({ zone, sources: { 'https://anubisdb.com/': () => ['proxied.loop.example'] } });
    const scan = await runScan({ domains: ['loop.example'], sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false, dns, fetchImpl });
    assert.ok(scan.hintErrors.some((e) => /lookup limit/.test(e)));
    assert.ok(scan.originHints.some((x) => x.ip === '192.0.2.200'));
    assert.ok(scan.originHints.some((x) => x.ip === '192.0.2.9' && x.reasons.some((r) => r.kind === 'direct-sibling')));
  });

  test('hooks that throw do not break the scan', async () => {
    const { fetchImpl, dns } = world();
    const boom = () => { throw new Error('ui bug'); };
    const scan = await runScan({ domains: [D], sources: ['anubis'], bruteforce: 'off', mine: false, permutationBudget: 0, recursive: false, dns, fetchImpl }, {
      onStage: boom, onSource: boom, onHost: boom, onProgress: boom
    });
    assert.ok(scan.hosts.length > 0);
  });

  test('input validation', async () => {
    const { fetchImpl, dns } = world();
    await assert.rejects(runScan({ domains: [D], fetchImpl }), TypeError);
    await assert.rejects(runScan({ domains: ['!!'], dns, fetchImpl }), TypeError);
    await assert.rejects(runScan({ domains: ['com.tr'], dns, fetchImpl }), TypeError, 'public suffixes are refused');
  });
});

describe('cancellation', () => {
  test('already-aborted signal rejects before any request', async () => {
    const { fetchImpl, dns, log } = world();
    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(runScan({ domains: [D], dns, fetchImpl, signal: ctl.signal }), (e) => e instanceof AbortError);
    assert.equal(log.doh.length + log.http.length, 0);
  });

  for (const stageName of ['sources', 'bruteforce', 'resolve', 'hints']) {
    test(`aborting during "${stageName}" rejects promptly with AbortError`, async () => {
      const ctl = new AbortController();
      const { fetchImpl, dns } = world({
        dohDelay: 2,
        sources: { ...SOURCE_PAYLOADS, 'https://crt.sh/': () => new Promise((r) => setTimeout(() => r(Response.json([])), stageName === 'sources' ? 5000 : 1)) }
      });
      let abortedAt = 0;
      const p = runScan({
        domains: [D], cert: CERT, bruteforce: stageName === 'bruteforce' ? 'medium' : 'small', dns, fetchImpl,
        signal: ctl.signal, inventory: parseInventory(INVENTORY_TEXT).servers
      }, {
        onStage: (s) => {
          if (s === stageName) setTimeout(() => { abortedAt = Date.now(); ctl.abort(); }, 5);
        }
      });
      await assert.rejects(p, (e) => e instanceof AbortError);
      assert.ok(abortedAt > 0, 'the stage was reached');
      assert.ok(Date.now() - abortedAt < 500, `prompt (${Date.now() - abortedAt} ms)`);
    });
  }
});
