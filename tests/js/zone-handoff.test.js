// Unit tests for the Zone File hand-off in the Subdomains / SSL Targets views
// (assets/js/views/subdomains.js helpers, shared by scan.js): which zone belongs to the typed
// domains, the one-shot intent check, the exact-mode scan config, and the origin panel + CLI
// command built from a real runScan with a zone (exact origins first, never widened to a /24,
// host targets and `*.x` names kept). No network: an emulated zone sits behind every DoH
// resolver. Example names and documentation addresses only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../../assets/js/lib/scanner.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import {
  zoneForDomains, validZoneIntent, zoneScanOverrides, zoneChipCounts, zoneOfResult, originOverview, originSweep,
  realOriginNetworks, techniqueCounts, ZONE_MODES, ZONE_INTENT_MAX_AGE, WARNING_CODES
} from '../../assets/js/views/subdomains.js';
import { HINT_KINDS } from '../../assets/js/ui/subdomains-run.js';
import * as scanView from '../../assets/js/views/scan.js';

const SOA = { mname: 'ns.example.net', rname: 'hostmaster.example.net', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 };

// The live DNS: www / shop / *.apps are proxied (Cloudflare edge addresses), docs CNAMEs to www,
// api is DNS-only in 198.51.100.0/24 next to the apex.
const WORLD = {
  'example.com': { A: ['198.51.100.10'] },
  'www.example.com': { A: ['104.16.1.1'] },
  'docs.example.com': { CNAME: 'www.example.com' },
  'shop.example.com': { A: ['104.16.1.2'] },
  'api.example.com': { A: ['198.51.100.20'] },
  '*.apps.example.com': { A: ['104.16.1.3'] }
};

function answer(name, type) {
  const answers = [];
  let current = name;
  for (let hop = 0; hop < 8; hop += 1) {
    let node = WORLD[current];
    if (!node) {
      const parent = current.split('.').slice(1).join('.');
      node = WORLD[`*.${parent}`];
      if (!node) return { rcode: 'NXDOMAIN', answers, authorities: [{ name: 'example.com', type: 'SOA', ttl: 300, data: SOA }] };
    }
    if (node.CNAME && type !== 'CNAME') {
      answers.push({ name: current, type: 'CNAME', ttl: 300, data: node.CNAME });
      current = node.CNAME;
      continue;
    }
    for (const data of node[type] || []) answers.push({ name: current, type, ttl: 300, data });
    return { rcode: 'NOERROR', answers, authorities: answers.length ? [] : [{ name: 'example.com', type: 'SOA', ttl: 300, data: SOA }] };
  }
  return { rcode: 'SERVFAIL', answers: [] };
}

function mkDns() {
  const log = { doh: [], http: [] };
  const fetchImpl = async (url) => {
    const resolver = RESOLVERS.find((r) => url.startsWith(`${r.url}?`));
    if (!resolver) {
      log.http.push(url);
      throw new TypeError(`unexpected URL ${url}`);
    }
    const q = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns'))).questions[0];
    log.doh.push(`${q.name} ${q.type}`);
    const out = answer(q.name, q.type);
    return new Response(encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers, authorities: out.authorities || [], edns: {}
    }));
  };
  return { log, dns: new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 }) };
}

// The zoneScanInput shape the Zone File view publishes as state.session.zone.
const ZONE = Object.freeze({
  v: 1,
  origin: 'example.com',
  names: ['example.com', 'www.example.com', 'docs.example.com', 'shop.example.com', 'api.example.com', 'other.example.org'],
  wildcardBases: ['apps.example.com'],
  delegations: [],
  proxied: [
    { name: 'www.example.com', ips: ['192.0.2.10'], host: null },
    { name: 'shop.example.com', ips: [], host: 'origin-lb.example.net' },
    { name: '*.apps.example.com', ips: ['192.0.2.10'], host: null }
  ],
  skipped: [],
  label: 'test zone',
  counts: { names: 7, origins: 3, skipped: 0 }
});

describe('zone hand-off helpers', () => {
  test('zoneForDomains: only a v1 zone whose origin equals or sits under a typed domain', () => {
    assert.equal(zoneForDomains(ZONE, ['example.com']), ZONE);
    assert.equal(zoneForDomains({ ...ZONE, origin: 'dev.example.com' }, ['example.com']).origin, 'dev.example.com');
    assert.equal(zoneForDomains(ZONE, ['dev.example.com']), null, 'a parent zone is not a sub-zone of the typed domain');
    assert.equal(zoneForDomains(ZONE, ['example.org']), null);
    assert.equal(zoneForDomains(ZONE, []), null);
    assert.equal(zoneForDomains({ ...ZONE, v: 2 }, ['example.com']), null);
    assert.equal(zoneForDomains(null, ['example.com']), null);
    assert.equal(zoneForDomains({ v: 1, origin: 'not a name' }, ['example.com']), null);
  });

  test('validZoneIntent: v1, this view, fresh, and the zone still loaded', () => {
    const now = 1_000_000;
    const ok = { v: 1, target: 'subdomains', domain: 'example.com', mode: 'exact', autostart: true, at: now - 1000 };
    assert.equal(validZoneIntent(ok, 'subdomains', ZONE, now), true);
    assert.equal(validZoneIntent(ok, 'scan', ZONE, now), false, 'meant for the other view');
    assert.equal(validZoneIntent({ ...ok, at: now - ZONE_INTENT_MAX_AGE - 1 }, 'subdomains', ZONE, now), false, 'stale');
    assert.equal(validZoneIntent({ ...ok, at: now + 5000 }, 'subdomains', ZONE, now), false, 'from the future');
    assert.equal(validZoneIntent({ ...ok, v: 2 }, 'subdomains', ZONE, now), false);
    assert.equal(validZoneIntent(ok, 'subdomains', undefined, now), false, 'the zone was forgotten');
    assert.equal(validZoneIntent(undefined, 'subdomains', ZONE, now), false);
  });

  test('zoneScanOverrides: exact turns every guessing and quota step off; discover only adds the zone', () => {
    assert.deepEqual(ZONE_MODES, ['exact', 'discover', 'off']);
    const exact = zoneScanOverrides(ZONE, 'exact');
    assert.equal(exact.zone, ZONE);
    assert.equal(exact.exact, true);
    assert.deepEqual(exact.sources, []);
    assert.equal(exact.bruteforce, 'off');
    assert.equal(exact.permutationBudget, 0);
    assert.equal(exact.recursive, false);
    assert.equal(exact.mine, false);
    assert.equal(exact.learnedLabels, null);
    assert.equal(exact.customWordlist, null);
    assert.deepEqual(zoneScanOverrides(ZONE, 'discover'), { zone: ZONE });
    assert.deepEqual(zoneScanOverrides(ZONE, 'off'), {});
    assert.deepEqual(zoneScanOverrides(null, 'exact'), {});
    assert.deepEqual(zoneScanOverrides(ZONE, 'bogus'), {});
  });

  test('zoneChipCounts reads the published counts, else counts the lists', () => {
    assert.deepEqual(zoneChipCounts(ZONE), { names: 7, origins: 3 });
    assert.deepEqual(zoneChipCounts({ ...ZONE, counts: undefined }), { names: 7, origins: 3 });
  });

  test('both views know the zone origin, hint kind and warning', () => {
    assert.ok(HINT_KINDS.includes('zone'));
    assert.ok(scanView.HINT_KINDS.includes('zone'));
    assert.ok(WARNING_CODES.includes('ZONE_OUT_OF_SCOPE'));
    assert.equal(zoneOfResult({ hosts: [] }), null, 'no zone, no zone tokens');
  });
});

describe('an exact zone scan end to end (fake DNS)', () => {
  test('only zone names are resolved, no source is asked, and the command sweeps the exact origins', async () => {
    const { dns, log } = mkDns();
    const result = await runScan({
      domains: ['example.com'],
      cert: null,
      originHints: false,
      inventory: [],
      dns,
      ...zoneScanOverrides(ZONE, 'exact')
    });
    assert.deepEqual(log.http, [], 'no passive source, no third-party request');
    // Only zone names (and their CNAME targets) reach DNS — no wordlist guesses.
    const asked = new Set(log.doh.map((q) => q.split(' ')[0]));
    for (const name of asked) {
      assert.ok(['example.com', 'www.example.com', 'docs.example.com', 'shop.example.com', 'api.example.com', 'apps.example.com'].includes(name) || name.endsWith('.apps.example.com'),
        `unexpected query ${name}`);
    }
    assert.ok(result.warnings.some((w) => w.code === 'ZONE_OUT_OF_SCOPE' && w.detail === '1'), 'other.example.org is out of scope');
    const names = result.hosts.map((x) => x.name);
    assert.ok(names.includes('www.example.com') && names.includes('api.example.com'));
    assert.ok(result.hosts.filter((x) => x.name === 'www.example.com').every((x) => x.origins.includes('zone')));
    assert.ok(techniqueCounts(result.hosts).zone >= 5);

    const o = originOverview(result);
    const www = o.proxied.find((p) => p.name === 'www.example.com');
    assert.ok(www, 'www is proxied');
    assert.deepEqual(www.zone, [{ ip: '192.0.2.10' }], 'the zone file’s exact origin, host-specific');
    assert.equal(o.zoneCount >= 1, true);
    assert.ok(!o.general.some((g) => (g.reasons || []).some((r) => r.kind === 'zone')), 'a zone hint is never a general hint');

    const { networks, dropped } = realOriginNetworks(result.originNetworks, result.hosts);
    const proxiedNames = o.proxied.map((p) => p.name);
    for (const shell of ['posix', 'powershell']) {
      const sweep = originSweep(result, { names: proxiedNames, networks, dropped, shell });
      assert.ok(sweep.command, `${shell}: a command`);
      const tokens = sweep.command.split(/\s+/);
      assert.ok(tokens.includes('192.0.2.10'), `${shell}: the exact zone origin`);
      assert.ok(!sweep.command.includes('192.0.2.0/24'), `${shell}: never widened to a /24`);
      assert.ok(tokens.includes('origin-lb.example.net'), `${shell}: the host origin as a target`);
      assert.ok(sweep.command.includes("'*.apps.example.com'"), `${shell}: the wildcard name, quoted`);
      assert.ok(tokens.includes('www.example.com'), `${shell}: the proxied name`);
    }
    assert.equal(o.droppedCount, 0, 'a `*.x` zone name is not counted as an invalid token');
  });

  test('a scan without a zone keeps the plain command (no host targets, no wildcard names)', async () => {
    const { dns } = mkDns();
    const result = await runScan({
      domains: ['example.com'], cert: null, originHints: false, inventory: [], dns,
      sources: [], bruteforce: 'off', permutationBudget: 0, recursive: false, mine: false, extraNames: ['www.example.com', 'api.example.com']
    });
    assert.equal(result.zone, null);
    const o = originOverview(result);
    assert.ok(o.proxied.every((p) => p.zone.length === 0));
    if (o.command) {
      assert.ok(!o.command.includes('origin-lb.example.net'));
      assert.ok(!o.command.includes('*.apps'));
    }
  });
});
