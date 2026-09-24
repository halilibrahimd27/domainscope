// Unit tests for assets/js/lib/zoneorigins.js — pure, no network. Zones are built by hand
// in the lib/zoneparse.js shape; the parser is never imported. Documentation addresses
// and example.* names only; 192.0.2.0 / 100:: appear only as Cloudflare placeholders.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ORIGIN_KINDS, PLACEHOLDERS, CF_HOSTED_SUFFIXES, TUNNEL_SUFFIX, SEED_EXCLUSIONS, MAX_CNAME_CHAIN,
  zoneIndex, wildcardCovers, deriveSeeds, handoffNames, proxiedOriginMap, addressMap, cliHandoff, zoneSweep,
  handoffFiles, zoneScanInput, privateLookingNames, isInetAtonNumeric, validateHostTargets, validateSweepNames,
  classifyExternalTarget, isCloudflareIp, sortIps, zoneConstants, effectiveTargets
} from '../../assets/js/lib/zoneorigins.js';
import { parseInventory, buildIpIndex } from '../../assets/js/lib/inventory.js';
import { buildSweepCommand } from '../../assets/js/lib/cmdline.js';
import { zone, cfZone, P, D } from '../fixtures/zones-analysis/zone-builder.mjs';
import {
  fixtureNames, loadFixture, goldenFiles, constantsFile, HERE, GOLDEN_NOW
} from '../fixtures/zones-analysis/gen-analysis-golden.mjs';

const PERF_FACTOR = process.env.ZONE_PERF_STRICT === '1' ? 1 : 3;
const byName = (rows) => Object.fromEntries(rows.map((r) => [r.name, r]));
const inventory = (text) => buildIpIndex(parseInventory(text).servers);
const CF = loadFixture('cloudflare-export');

describe('vocabulary and helpers', () => {
  test('frozen closed sets', () => {
    assert.deepEqual(ORIGIN_KINDS, ['ip', 'host', 'tunnel', 'provider', 'placeholder', 'cloudflare-ip', 'unresolved', 'loop']);
    assert.deepEqual(PLACEHOLDERS, ['192.0.2.0', '100::']);
    assert.deepEqual(CF_HOSTED_SUFFIXES, ['pages.dev', 'workers.dev']);
    assert.equal(TUNNEL_SUFFIX, 'cfargotunnel.com');
    assert.ok(Object.isFrozen(ORIGIN_KINDS) && Object.isFrozen(SEED_EXCLUSIONS));
  });

  test('sortIps: IPv4 before IPv6, numeric, canonical, unique', () => {
    assert.deepEqual(sortIps(['2001:db8::10', '192.0.2.40', '192.0.2.9', '2001:DB8::1', '192.0.2.9']),
      ['192.0.2.9', '192.0.2.40', '2001:db8::1', '2001:db8::10']);
  });

  test('isCloudflareIp agrees with the published ranges', () => {
    assert.equal(isCloudflareIp('104.16.1.1'), true);
    assert.equal(isCloudflareIp('2606:4700::6810:1'), true);
    assert.equal(isCloudflareIp('::ffff:104.16.1.1'), true);
    assert.equal(isCloudflareIp('192.0.2.10'), false);
    assert.equal(isCloudflareIp('not an ip'), false);
  });

  test('classifyExternalTarget: tunnel, Cloudflare-hosted, AWS, SaaS / CDN, DNS steering, plain host', () => {
    const k = (t) => { const c = classifyExternalTarget(t); return `${c.kind}:${c.provider}`; };
    assert.equal(k('0f1e.cfargotunnel.com'), 'tunnel:cloudflare-tunnel');
    assert.equal(k('site.pages.dev'), 'provider:cloudflare-pages');
    assert.equal(k('api.worker.workers.dev'), 'provider:cloudflare-workers');
    assert.equal(k('d-abc.execute-api.us-east-1.amazonaws.com'), 'provider:aws-api-gateway');
    assert.equal(k('app.eu-west-1.elasticbeanstalk.com'), 'provider:aws-elastic-beanstalk');
    assert.equal(k('a1.awsglobalaccelerator.com'), 'provider:aws-global-accelerator');
    assert.equal(k('vpce-1.vpce.amazonaws.com'), 'provider:aws-vpc-endpoint');
    assert.equal(k('shops.myshopify.com'), 'provider:shopify');
    assert.equal(k('example-blog.github.io'), 'provider:github-pages');
    assert.equal(k('d111111abcdef8.cloudfront.net'), 'provider:cloudfront');
    assert.equal(k('app.trafficmanager.net'), 'host:azure-trafficmanager');
    assert.equal(k('origin-lb.example.net'), 'host:null');
  });

  test('effectiveTargets prefers the intended form of a suspected missing dot', () => {
    const [r] = zone([['blog', 'CNAME', 'example-blog.github.io', { intendedTargets: ['example-blog.github.io'] }]]).records;
    assert.deepEqual(effectiveTargets(r), ['example-blog.github.io']);
  });

  test('the index is cached per zone object and never throws on junk', () => {
    assert.equal(zoneIndex(CF), zoneIndex(CF));
    for (const junk of [null, undefined, 1, 'x', { records: [null, { name: 1 }] }]) assert.equal(zoneIndex(junk).unique.length, 0);
    assert.equal(zoneIndex({ ...CF, fatal: { code: 'EMPTY' } }).unique.length, 0);
  });
});

describe('wildcardCovers (RFC 4592, not certificate matching)', () => {
  const z = zone([['*.apps', 'A', '192.0.2.20'], ['c.b2.apps', 'A', '192.0.2.21'], ['dev', 'NS', 'ns.example.net.'], ['*.dev', 'A', '192.0.2.22']]);
  test('any depth below the closest encloser', () => {
    assert.equal(wildcardCovers(z, 'x7.apps.example.com'), '*.apps.example.com');
    assert.equal(wildcardCovers(z, 'a.b.apps.example.com'), '*.apps.example.com');
  });
  test('an existing closer node (even an empty non-terminal) stops it', () => {
    assert.equal(wildcardCovers(z, 'a.b2.apps.example.com'), null);
    assert.equal(wildcardCovers(z, 'b2.apps.example.com'), null);
    assert.equal(wildcardCovers(z, 'apps.example.com'), null, 'apps is an empty non-terminal: NODATA');
  });
  test('nothing is synthesised at or below a delegation, outside the zone or for the apex', () => {
    assert.equal(wildcardCovers(z, 'x.dev.example.com'), null);
    assert.equal(wildcardCovers(z, 'x.apps.example.net'), null);
    assert.equal(wildcardCovers(z, 'example.com'), null);
    assert.equal(wildcardCovers(zone([['www', 'A', '192.0.2.1']]), 'x.example.com'), null);
  });
});

describe('deriveSeeds', () => {
  test('Cloudflare export: 18 names, the wildcard base, the delegation, the exclusions', () => {
    const s = deriveSeeds(CF);
    assert.deepEqual([...s.names].sort(), ['admin', 'api', 'app', 'blog', 'docs', 'example.com', 'ftp', 'intranet', 'legacy.shop', 'mail',
      'mixed', 'shop', 'status', 'tagged', 'tunnel', 'v6only', 'vpn', 'www'].map((n) => (n === 'example.com' ? n : `${n}.example.com`)).sort());
    assert.deepEqual(s.wildcardBases, ['apps.example.com']);
    assert.deepEqual(s.delegations, ['dev.example.com']);
    assert.deepEqual(s.excluded, [{ name: 'selector1._domainkey.example.com', why: 'service-label' }, { name: 'old.dev.example.com', why: 'occluded' }]);
    const skipped = deriveSeeds(CF, { skip: privateLookingNames(CF) });
    assert.equal(skipped.names.length, 17);
    assert.ok(!skipped.names.includes('intranet.example.com'));
    assert.deepEqual(skipped.excluded.find((e) => e.name === 'intranet.example.com'), { name: 'intranet.example.com', why: 'skipped' });
  });

  test('in-zone MX / SRV / NS targets are seeds; escaped, invalid and out-of-zone owners are not', () => {
    const z = zone([['@', 'MX', '10 mx1'], ['_sip._tcp', 'SRV', '0 0 5060 sip'], ['@', 'NS', 'ns1'], ['@', 'MX', '20 mx.example.net.'],
      ['dot\\.label', 'A', '192.0.2.96'], ['x', 'A', '999.1.1.1', { invalid: true }], ['other.example.org.', 'A', '192.0.2.5'],
      ['*._tcp', 'A', '192.0.2.6'], ['alias', 'A', null, { alias: { target: 'd1.cloudfront.net', zoneId: null, evaluateTargetHealth: false, provider: 'cloudfront' } }]]);
    const s = deriveSeeds(z);
    assert.deepEqual(s.names, ['alias.example.com', 'mx1.example.com', 'ns1.example.com', 'sip.example.com']);
    assert.deepEqual(Object.fromEntries(s.excluded.map((e) => [e.name, e.why])), {
      'dot\\.label.example.com': 'escaped', 'x.example.com': 'invalid', 'other.example.org': 'out-of-zone', '*._tcp.example.com': 'service-label'
    });
  });

  test('a suspected missing-dot owner seeds its intended name', () => {
    const s = deriveSeeds(zone([['example.com', 'A', '192.0.2.80', { intendedName: 'example.com' }]]));
    assert.deepEqual(s.names, ['example.com']);
  });

  test('handoffNames (CLI scope all): A/AAAA/CNAME and alias owners only, *.x kept', () => {
    const z = zone([['@', 'A', '192.0.2.1'], ['*.apps', 'A', '192.0.2.2'], ['svc', 'HTTPS', { priority: 1, target: '.', params: {} }],
      ['@', 'MX', '10 mx1'], ['mx1', 'A', '192.0.2.3'], ['_dmarc', 'TXT', 'v=DMARC1; p=none']]);
    assert.deepEqual(handoffNames(z), ['example.com', '*.apps.example.com', 'mx1.example.com']);
  });
});

describe('proxiedOriginMap', () => {
  test('Cloudflare export: 10 rows with exact origins, docs via www, provider and tunnel', () => {
    const rows = byName(proxiedOriginMap(CF, { inventoryIndex: inventory('web01 192.0.2.10') }));
    assert.equal(Object.keys(rows).length, 10);
    const view = (n) => `${rows[n].kind} ${rows[n].ips.join(',') || rows[n].host || '-'} ${rows[n].via.join('>') || '-'} ${rows[n].provider || '-'}`;
    assert.equal(view('example.com'), 'ip 192.0.2.10 - -');
    assert.equal(view('www.example.com'), 'ip 192.0.2.10,2001:db8::10 - -');
    assert.equal(view('api.example.com'), 'ip 192.0.2.13 - -');
    assert.equal(view('*.apps.example.com'), 'ip 192.0.2.20 - -');
    assert.equal(view('mixed.example.com'), 'ip 192.0.2.30,192.0.2.31 - -');
    assert.equal(view('tagged.example.com'), 'ip 192.0.2.40 - -');
    assert.equal(view('docs.example.com'), 'ip 192.0.2.10,2001:db8::10 www.example.com -');
    assert.equal(view('app.example.com'), 'host origin-lb.example.net - -');
    assert.equal(view('shop.example.com'), 'provider - - shopify');
    assert.equal(view('tunnel.example.com'), 'tunnel - - cloudflare-tunnel');
    for (const n of ['example.com', 'www.example.com', 'docs.example.com']) {
      assert.deepEqual(rows[n].servers, [{ serverId: 'web01', name: 'web01', ip: '192.0.2.10' }], n);
    }
    assert.deepEqual(rows['www.example.com'].exposure, [{ by: 'sibling', name: 'ftp.example.com' }, { by: 'spf', name: 'example.com' }]);
    assert.equal(rows['docs.example.com'].proxiedBy, 'chain');
  });

  test('per-host origins: two proxied names never share one guessed origin', () => {
    const rows = byName(proxiedOriginMap(cfZone([['a', 'A', '198.51.100.7', P], ['b', 'A', '203.0.113.7', P]])));
    assert.deepEqual(rows['a.example.com'].ips, ['198.51.100.7']);
    assert.deepEqual(rows['b.example.com'].ips, ['203.0.113.7']);
  });

  test('chains: DNS-only CNAME → proxied name → DNS-only name with an A', () => {
    const rows = byName(proxiedOriginMap(cfZone([['a', 'CNAME', 'b', D], ['b', 'CNAME', 'c', P], ['c', 'A', '198.51.100.9', D]])));
    assert.equal(rows['a.example.com'].kind, 'ip');
    assert.deepEqual(rows['a.example.com'].via, ['b.example.com', 'c.example.com']);
    assert.deepEqual(rows['b.example.com'].ips, ['198.51.100.9']);
    assert.equal(rows['c.example.com'], undefined, 'the DNS-only target itself is not proxied');
  });

  test('a loop a → b → a gives kind loop without hanging; a 20-hop chain stops at 16', () => {
    const loop = byName(proxiedOriginMap(cfZone([['a', 'CNAME', 'b', P], ['b', 'CNAME', 'a', D]])));
    assert.equal(loop['a.example.com'].kind, 'loop');
    assert.equal(loop['a.example.com'].target, 'a.example.com');
    const rows = [['h0', 'CNAME', 'h1', P], ...Array.from({ length: 19 }, (_, i) => [`h${i + 1}`, 'CNAME', `h${i + 2}`, D]), ['h20', 'A', '198.51.100.1', D]];
    const long = byName(proxiedOriginMap(cfZone(rows)))['h0.example.com'];
    assert.equal(long.kind, 'unresolved');
    assert.equal(long.via.length, MAX_CNAME_CHAIN, 'follows 16 hops');
    assert.equal(long.target, 'h17.example.com', 'and gives up on the 17th');
  });

  test('in-zone target without records is unresolved; a delegated target is a host', () => {
    const rows = byName(proxiedOriginMap(cfZone([['a', 'CNAME', 'missing', P], ['b', 'CNAME', 'x.dev', P], ['dev', 'NS', 'ns.example.net.']])));
    assert.deepEqual([rows['a.example.com'].kind, rows['a.example.com'].target], ['unresolved', 'missing.example.com']);
    assert.deepEqual([rows['b.example.com'].kind, rows['b.example.com'].host], ['host', 'x.dev.example.com']);
  });

  test('a CNAME into a DNS wildcard resolves through the wildcard records', () => {
    const rows = byName(proxiedOriginMap(cfZone([['a', 'CNAME', 'x.apps', P], ['*.apps', 'A', '198.51.100.3', D]])));
    assert.deepEqual([rows['a.example.com'].kind, rows['a.example.com'].ips.join()], ['ip', '198.51.100.3']);
  });

  test('placeholders mean "no server"; Cloudflare addresses are error 1000, not origins', () => {
    const rows = byName(proxiedOriginMap(cfZone([['worker', 'A', '192.0.2.0', P], ['edge', 'AAAA', '100::', P], ['err', 'A', '104.16.1.1', P],
      ['both', 'A', '198.51.100.5', P], ['both', 'A', '104.16.1.1', P]])));
    assert.deepEqual([rows['worker.example.com'].kind, rows['edge.example.com'].kind, rows['err.example.com'].kind], ['placeholder', 'placeholder', 'cloudflare-ip']);
    assert.deepEqual(rows['both.example.com'].ips, ['198.51.100.5']);
    assert.deepEqual(rows['both.example.com'].ignored, ['104.16.1.1']);
  });

  test('a private origin is kept (the CLI runs inside the network) and flagged', () => {
    const row = byName(proxiedOriginMap(cfZone([['backend', 'A', '10.0.0.5', P]])))['backend.example.com'];
    assert.deepEqual([row.kind, row.ips.join(), row.private], ['ip', '10.0.0.5', true]);
  });

  test('a suspected missing dot on a proxied CNAME target uses the intended host', () => {
    const row = byName(proxiedOriginMap(cfZone([['app', 'CNAME', 'origin-lb.example.net', { ...P, intendedTargets: ['origin-lb.example.net'] }]])))['app.example.com'];
    assert.equal(row.host, 'origin-lb.example.net');
  });
});

describe('addressMap', () => {
  test('192.0.2.10 → @, www and docs (proxied) and ftp (DNS-only, exposed), with the server', () => {
    const map = addressMap(CF, { inventoryIndex: inventory('web01 192.0.2.10') });
    const e = map.find((a) => a.ip === '192.0.2.10');
    assert.deepEqual(e.names.map((n) => [n.name, n.proxied, !!n.exposed, !!n.via]), [
      ['example.com', true, false, false], ['docs.example.com', true, false, true], ['ftp.example.com', false, true, false], ['www.example.com', true, false, false]]);
    assert.equal(e.exposed, true);
    assert.deepEqual(e.servers.map((s) => s.name), ['web01']);
    assert.equal(map.find((a) => a.ip === '192.0.2.60').names[0].occluded, true);
    assert.deepEqual(map.map((a) => a.ip), sortIps(map.map((a) => a.ip)));
  });

  test('provider, private and placeholder flags', () => {
    const map = byName(addressMap(cfZone([['w', 'A', '192.0.2.0', P], ['e', 'A', '104.16.1.1', P], ['p', 'A', '10.0.0.5', D]])).map((a) => ({ ...a, name: a.ip })));
    assert.equal(map['192.0.2.0'].placeholder, true);
    assert.equal(map['104.16.1.1'].provider, 'cloudflare');
    assert.equal(map['10.0.0.5'].private, true);
  });
});

describe('CLI hand-off', () => {
  test('Cloudflare export, scope proxied: 7 exact addresses + 1 host × 8 names, shop and tunnel skipped', () => {
    const h = cliHandoff(CF);
    assert.deepEqual(h.targets, ['192.0.2.10', '192.0.2.13', '192.0.2.20', '192.0.2.30', '192.0.2.31', '192.0.2.40', '2001:db8::10']);
    assert.deepEqual(h.hostTargets, ['origin-lb.example.net']);
    assert.equal(h.names.length, 8);
    assert.ok(h.names.includes('docs.example.com') && h.names.includes('*.apps.example.com'));
    assert.deepEqual(h.skipped.map((s) => `${s.name} ${s.kind}`), ['shop.example.com provider', 'tunnel.example.com tunnel']);
    assert.ok(h.targets.every((t) => !t.includes('/')), 'exact addresses only, never a /24');
  });

  test('placeholders and Cloudflare addresses never become targets', () => {
    const h = cliHandoff(loadFixture('placeholder-cf'));
    for (const bad of ['192.0.2.0', '100::', '104.16.1.1']) assert.ok(!h.targets.includes(bad), bad);
    assert.ok(h.targets.includes('10.0.0.5'), 'a private origin stays a CLI target');
    assert.ok(h.hostTargets.includes('example-app.trafficmanager.net'), 'DNS steering → host origin');
    assert.deepEqual(h.skipped.map((s) => s.kind).sort(), ['cloudflare-ip', 'placeholder', 'placeholder', 'provider', 'provider']);
  });

  test('zoneSweep proxied: probes count the wildcard SNI, sizes and opt-in command options', () => {
    const s = zoneSweep(CF);
    assert.equal(s.tokens, 16);
    assert.equal(s.probes, 9 * 8, 'eight names incl. *.apps → 9 probe names × 8 targets');
    assert.equal(s.probesAtLeast, true);
    assert.equal(s.fileForm, false);
    assert.equal(s.command, null, 'no command without an injected builder');
    assert.deepEqual([s.commandOptions.allowHostTargets, s.commandOptions.allowWildcardNames, s.commandOptions.targetsFile], [true, true, 'zone-targets.txt']);
    assert.equal(s.chars, `ssl_origin_scan.py -t ${[...s.targets, ...s.hostTargets].join(' ')} -n ${s.names.map((n) => (n.startsWith('*') ? `'${n}'` : n)).join(' ')}`.length);
  });

  test('zoneSweep all: DNS-only names and addresses added; Cloudflare and placeholder addresses left out', () => {
    const all = zoneSweep(loadFixture('placeholder-cf'), { scope: 'all' });
    assert.ok(all.names.includes('direct.example.com'));
    assert.ok(all.targets.includes('198.51.100.20') && all.targets.includes('10.0.0.5'));
    for (const bad of ['192.0.2.0', '100::', '104.16.1.1']) assert.ok(!all.targets.includes(bad), bad);
    const cfAll = zoneSweep(CF, { scope: 'all' });
    assert.ok(cfAll.targets.length > 7 && cfAll.names.length > 8 && cfAll.probes > 72);
  });

  test('the file form above 60 tokens; an injected builder gets the zone opt-ins', () => {
    const rows = Array.from({ length: 70 }, (_, i) => [`h${i}`, 'A', `198.51.100.${i + 1}`, P]);
    const big = zoneSweep(cfZone(rows));
    assert.equal(big.fileForm, true);
    let seen = null;
    const s = zoneSweep(CF, { shell: 'powershell', buildCommand: (opts) => { seen = opts; return buildSweepCommand(opts); } });
    assert.equal(seen.shell, 'powershell');
    assert.deepEqual(seen.targets, [...s.targets, ...s.hostTargets]);
    assert.equal(typeof s.command, 'string');
    assert.ok(s.command.startsWith('ssl_origin_scan.py -t 192.0.2.10 '));
  });

  test('handoffFiles: exact text, inventory names, host targets last', () => {
    const s = zoneSweep(CF);
    const { namesTxt, targetsTxt } = handoffFiles(s, { origin: 'example.com', inventoryIndex: inventory('web01 192.0.2.10\n192.0.2.13'), now: GOLDEN_NOW });
    const head = '# DomainScope zone hand-off for example.com — 2026-01-01T00:00:00.000Z';
    assert.equal(namesTxt, `${head}\n${s.names.join('\n')}\n`);
    assert.equal(targetsTxt, [head, 'web01 192.0.2.10', '192.0.2.13', '192.0.2.20', '192.0.2.30', '192.0.2.31', '192.0.2.40', '2001:db8::10', 'origin-lb.example.net', ''].join('\n'));
    const hostile = handoffFiles({ names: ['a;b.example.com', 'ok.example.com'], targets: ['192.0.2.1'], hostTargets: ['$(id)'] }, { origin: 'bad\norigin', now: GOLDEN_NOW });
    assert.equal(hostile.namesTxt.split('\n')[0], '# DomainScope zone hand-off for zone — 2026-01-01T00:00:00.000Z');
    assert.ok(!hostile.namesTxt.includes('a;b') && !hostile.targetsTxt.includes('$(id)'));
  });
});

describe('validators (zone spec §6.5 rules)', () => {
  test('isInetAtonNumeric covers decimal, octal and hex forms', () => {
    for (const s of ['2026092401', '0x7f.0x1', '0177.1', '10.1', '127.0.0.1', '0xdeadbeef']) assert.equal(isInetAtonNumeric(s), true, s);
    for (const s of ['origin-lb.example.net', '0xdeadbeef.example.com', '123.example.com', 'a1.example.com']) assert.equal(isInetAtonNumeric(s), false, s);
  });

  test('host targets keep real host names and drop numeric, option-like and hostile tokens', () => {
    const r = validateHostTargets(['origin-lb.example.net', 'Origin-LB.Example.NET.', '0x7f.0x1', '2026092401', '10.1', '0177.1',
      '-evil.example.com', 'a;b.example.com', '$(id)', 'web01', '192.0.2.10', '192.0.2.0/24']);
    assert.deepEqual(r.valid, ['origin-lb.example.net']);
    assert.equal(r.dropped.length, 10);
  });

  test('names keep *.x and drop broken wildcards', () => {
    const r = validateSweepNames(['*.apps.example.com', 'www.example.com', '*.*.example.com', 'a.*.example.com', '*', 'x y', '0x7f.0x1']);
    assert.deepEqual(r.valid, ['*.apps.example.com', 'www.example.com']);
    assert.deepEqual(r.dropped, ['*.*.example.com', 'a.*.example.com', '*', 'x y', '0x7f.0x1']);
  });
});

describe('privacy helpers', () => {
  test('privateLookingNames: private addresses, internal labels and suffixes, CNAMEs into them', () => {
    const z = zone([['intranet', 'A', '198.51.100.1'], ['db', 'A', '10.1.2.4'], ['printer.lan', 'A', '198.51.100.2'], ['x.home.arpa.', 'A', '198.51.100.3'],
      ['build', 'CNAME', 'db'], ['wiki', 'CNAME', 'build'], ['www', 'A', '198.51.100.4'], ['@', 'MX', '10 mail.internal'], ['proxy', 'CNAME', 'db', { proxied: true }]]);
    assert.deepEqual([...privateLookingNames(z)].sort(), ['build.example.com', 'db.example.com', 'intranet.example.com', 'mail.internal.example.com',
      'printer.lan.example.com', 'wiki.example.com', 'x.home.arpa'].sort());
  });

  test('zoneScanInput: private-looking names skipped by default; only ip / host origins become hints', () => {
    const s = zoneScanInput(CF);
    assert.equal(s.v, 1);
    assert.equal(s.origin, 'example.com');
    assert.equal(s.names.length, 17);
    assert.deepEqual(s.skipped, ['intranet.example.com']);
    assert.deepEqual(s.wildcardBases, ['apps.example.com']);
    assert.deepEqual(s.delegations, ['dev.example.com']);
    assert.deepEqual(s.proxied.map((p) => p.name), ['example.com', 'api.example.com', 'app.example.com', '*.apps.example.com',
      'docs.example.com', 'mixed.example.com', 'tagged.example.com', 'www.example.com']);
    assert.equal(zoneScanInput(CF, { skipPrivate: false }).names.length, 18);
    assert.ok(!zoneScanInput(CF, { skip: ['www.example.com'] }).proxied.some((p) => p.name === 'www.example.com'));
    const ph = zoneScanInput(loadFixture('placeholder-cf'), { skipPrivate: false });
    for (const p of ph.proxied) assert.ok(p.host || p.ips.every((ip) => !PLACEHOLDERS.includes(ip) && !isCloudflareIp(ip)), p.name);
  });
});

describe('goldens and constants', () => {
  test('every fixture equals its expected analysis / hand-off / download files', () => {
    for (const name of fixtureNames()) {
      for (const [rel, content] of goldenFiles(name, loadFixture(name))) {
        assert.equal(content, readFileSync(join(HERE, rel), 'utf8'), `${rel} (rerun gen-analysis-golden.mjs --write after review)`);
      }
    }
  });

  test('zone-constants.json mirrors the live constants for the CLI port', () => {
    assert.equal(constantsFile(), readFileSync(join(HERE, 'zone-constants.json'), 'utf8'));
    const c = zoneConstants();
    assert.deepEqual(c.placeholders, [...PLACEHOLDERS]);
    assert.ok(c.cloudflareCidrs.includes('104.16.0.0/13'));
    assert.ok(c.dnsOnly.includes('azure-trafficmanager'));
    assert.ok(c.cnameSuffixes.shopify.includes('myshopify.com'));
  });

  test('the downloads parse as plain CLI lists (one token per line after the header)', () => {
    for (const name of fixtureNames()) {
      for (const [rel, content] of goldenFiles(name, loadFixture(name))) {
        if (!rel.endsWith('.names.txt') && !rel.endsWith('.targets.txt')) continue;
        const lines = content.trimEnd().split('\n');
        assert.match(lines[0], /^# DomainScope zone hand-off for [a-z0-9.-]+ — \d{4}-\d\d-\d\dT/);
        for (const line of lines.slice(1)) assert.match(line, /^(?:[A-Za-z0-9_.-]+ )?[*A-Za-z0-9_.:-]+$/, `${rel}: ${line}`);
      }
    }
  });
});

describe('performance', () => {
  test(`proxiedOriginMap on 20,000 records in under ${100 * PERF_FACTOR} ms`, () => {
    const rows = [];
    for (let i = 0; i < 20000; i += 1) {
      const k = i % 4;
      if (k === 0) rows.push([`h${i}`, 'A', `10.8.${(i >> 8) & 255}.${i & 255}`, { proxied: i % 8 === 0, ttlAuto: true }]);
      else if (k === 1) rows.push([`c${i}`, 'CNAME', `h${i - 1}`, { proxied: false }]);
      else if (k === 2) rows.push([`p${i}`, 'CNAME', `svc${i}.example.net.`, { proxied: true }]);
      else rows.push([`t${i}`, 'TXT', 'hello']);
    }
    const big = cfZone(rows);
    // best of 3 runs: one parallel-suite GC / scheduler stall must not fail a budget test
    let map;
    let ms = Infinity;
    for (let run = 0; run < 3; run += 1) {
      const t0 = performance.now();
      map = proxiedOriginMap(big);
      ms = Math.min(ms, performance.now() - t0);
    }
    assert.ok(map.length > 5000);
    assert.ok(ms < 100 * PERF_FACTOR, `origin map took ${ms.toFixed(0)} ms`);
  });
});
