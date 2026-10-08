// Unit tests for assets/js/lib/zonelint.js — pure, no network. Zones are built by hand
// in the lib/zoneparse.js shape (tests/fixtures/zones-analysis/zone-builder.mjs); the
// parser is never imported. Documentation addresses and example.* names only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { lintZone, LINT_RULES, LINT_I18N, SEVERITY_ORDER, CF_PROXY_PORTS } from '../../assets/js/lib/zonelint.js';
import { zone, cfZone, P, D } from '../fixtures/zones-analysis/zone-builder.mjs';
import { fixtureNames, loadFixture, HERE } from '../fixtures/zones-analysis/gen-analysis-golden.mjs';

const codes = (z) => lintZone(z).findings.map((f) => f.code);
const find = (z, code) => lintZone(z).findings.filter((f) => f.code === code);
const PERF_FACTOR = process.env.ZONE_PERF_STRICT === '1' ? 1 : 3;

const SOA = ['@', 'SOA', { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 1, refresh: 3600, retry: 600, expire: 604800, minimum: 3600 }];

describe('vocabulary', () => {
  test('LINT_RULES is a frozen closed set with a known severity and scopes', () => {
    assert.ok(Object.isFrozen(LINT_RULES));
    assert.deepEqual(SEVERITY_ORDER, ['error', 'warn', 'info']);
    for (const [code, rule] of Object.entries(LINT_RULES)) {
      assert.match(code, /^[A-Z][A-Z0-9_]+$/);
      assert.ok(SEVERITY_ORDER.includes(rule.severity), code);
      assert.ok(Array.isArray(rule.scopes) && rule.scopes.length, code);
      if (rule.severityCf) assert.ok(SEVERITY_ORDER.includes(rule.severityCf), code);
    }
    // folded into ORIGIN_EXPOSED_BY_SIBLING (role 'mx'), per the critic notes
    assert.equal(LINT_RULES.ORIGIN_EXPOSED_BY_MX, undefined);
    assert.ok(LINT_RULES.MX_TARGET_PROXIED && LINT_RULES.SRV_TARGET_PROXIED);
  });

  test('LINT_I18N: a title and a why text for every code, in English and Turkish, with the same placeholders', () => {
    const holes = (s) => [...new Set([...String(s).matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]))].sort().join(',');
    for (const code of Object.keys(LINT_RULES)) {
      for (const key of [`zone.lint.${code}`, `zone.lint.${code}.why`]) {
        assert.ok(LINT_I18N.en[key] && LINT_I18N.tr[key], key);
        assert.equal(holes(LINT_I18N.en[key]), holes(LINT_I18N.tr[key]), key);
      }
    }
    assert.equal(Object.keys(LINT_I18N.en).length, Object.keys(LINT_RULES).length * 2);
    assert.deepEqual(Object.keys(LINT_I18N.tr).sort(), Object.keys(LINT_I18N.en).sort());
  });

  test('a clean zone has no findings, and malformed / fatal input never throws', () => {
    const clean = zone([SOA, ['@', 'NS', 'ns1'], ['@', 'NS', 'ns2.example.net.'], ['ns1', 'A', '192.0.2.53'], ['@', 'A', '192.0.2.10'],
      ['www', 'CNAME', '@'], ['@', 'MX', '10 mail'], ['mail', 'A', '198.51.100.25'], ['@', 'TXT', 'v=spf1 mx -all']]);
    assert.deepEqual(codes(clean), []);
    for (const bad of [null, undefined, {}, { records: 'x' }, { records: [null, 1, { name: 5 }] }]) {
      assert.deepEqual(lintZone(bad).findings, []);
    }
    const fatal = zone([['@', 'A', '192.0.2.10']], { fatal: { code: 'NOT_A_ZONE' } });
    assert.deepEqual(lintZone(fatal).findings, []);
  });
});

describe('CNAME rules', () => {
  test('CNAME_AND_OTHER_DATA lists the other types; RRSIG/NSEC companions are fine', () => {
    const [f] = find(zone([['www', 'CNAME', '@'], ['www', 'A', '192.0.2.10'], ['www', 'TXT', 'x']]), 'CNAME_AND_OTHER_DATA');
    assert.equal(f.severity, 'error');
    assert.deepEqual(f.params, { name: 'www.example.com', types: ['A', 'TXT'] });
    assert.equal(f.recordIds.length, 3);
    assert.deepEqual(find(zone([['www', 'CNAME', '@'], ['www', 'NSEC', 'x']]), 'CNAME_AND_OTHER_DATA'), []);
  });

  test('CNAME_AT_APEX is an error in BIND and info on Cloudflare (flattened)', () => {
    assert.equal(find(zone([['@', 'CNAME', 'lb.example.net.']]), 'CNAME_AT_APEX')[0].severity, 'error');
    const cf = find(cfZone([['@', 'CNAME', 'lb.example.net.', D]]), 'CNAME_AT_APEX')[0];
    assert.equal(cf.severity, 'info');
    assert.deepEqual(cf.params, { name: 'example.com', target: 'lb.example.net' });
  });

  test('MULTIPLE_CNAME counts unique CNAMEs only', () => {
    assert.deepEqual(find(zone([['a', 'CNAME', 'b'], ['a', 'CNAME', 'c'], ['b', 'A', '192.0.2.1'], ['c', 'A', '192.0.2.2']]), 'MULTIPLE_CNAME')[0].params,
      { name: 'a.example.com', count: 2 });
    assert.deepEqual(find(zone([['a', 'CNAME', 'b'], ['a', 'CNAME', 'b', { duplicateOf: 0 }], ['b', 'A', '192.0.2.1']]), 'MULTIPLE_CNAME'), []);
  });

  test('MULTIPLE_CNAME counts per routing variant: weighted, failover, geo and octoDNS pools are alternatives', () => {
    const rt = (policy, id) => ({ routing: { policy, id } });
    const none = (rows) => assert.deepEqual(find(zone(rows, { format: 'route53', dialect: null }), 'MULTIPLE_CNAME'), []);
    none([['app', 'CNAME', 'blue.example.net.', rt('weighted', 'blue')], ['app', 'CNAME', 'green.example.net.', rt('weighted', 'green')]]);
    none([['api', 'CNAME', 'a.example.net.', rt('failover', 'primary')], ['api', 'CNAME', 'b.example.net.', rt('failover', 'secondary')]]);
    none([['geo', 'CNAME', 'eu.example.net.', rt('geolocation', 'eu')], ['geo', 'CNAME', 'us.example.net.', rt('geolocation', 'us')]]);
    none([['same', 'CNAME', 'x.example.net.', rt('weighted', 'a')], ['same', 'CNAME', 'x.example.net.', rt('weighted', 'b')]]);
    none([['dyn', 'CNAME', 'default.example.net.', rt('dynamic', null)], ['dyn', 'CNAME', 'eu.example.net.', rt('dynamic', 'eu')],
      ['dyn', 'CNAME', 'us.example.net.', rt('dynamic', 'us')]]);
    // two CNAMEs inside one variant, or a plain CNAME next to a routed one, still clash
    const one = zone([['app', 'CNAME', 'a.example.net.', rt('weighted', 'blue')], ['app', 'CNAME', 'b.example.net.', rt('weighted', 'blue')],
      ['app', 'CNAME', 'c.example.net.', rt('weighted', 'green')]], { format: 'route53', dialect: null });
    assert.deepEqual(find(one, 'MULTIPLE_CNAME').map((f) => [f.params, f.recordIds]), [[{ name: 'app.example.com', count: 2 }, [0, 1]]]);
    const mixed = zone([['app', 'CNAME', 'a.example.net.'], ['app', 'CNAME', 'b.example.net.', rt('weighted', 'blue')]], { format: 'route53', dialect: null });
    assert.deepEqual(find(mixed, 'MULTIPLE_CNAME')[0].params, { name: 'app.example.com', count: 2 });
  });

  test('CNAME_LOOP is reported once per cycle, at the first member in the file', () => {
    const z = zone([['c', 'CNAME', 'a'], ['a', 'CNAME', 'b'], ['b', 'CNAME', 'a']]);
    const loops = find(z, 'CNAME_LOOP');
    assert.equal(loops.length, 1);
    assert.deepEqual(loops[0].params, { name: 'a.example.com', chain: ['a.example.com', 'b.example.com', 'a.example.com'] });
    assert.deepEqual(find(zone([['a', 'CNAME', 'b'], ['b', 'CNAME', 'c'], ['c', 'A', '192.0.2.1']]), 'CNAME_LOOP'), []);
    assert.equal(find(zone([['self', 'CNAME', 'self']]), 'CNAME_LOOP').length, 1);
  });

  test('CNAME_CHAIN_LONG fires above 8 in-zone hops, at the chain head only', () => {
    const chain = (hops) => zone([...Array.from({ length: hops }, (_, i) => [`h${i}`, 'CNAME', `h${i + 1}`]), [`h${hops}`, 'A', '192.0.2.1']]);
    const long = find(chain(10), 'CNAME_CHAIN_LONG');
    assert.equal(long.length, 1);
    assert.deepEqual(long[0].params, { name: 'h0.example.com', hops: 10 });
    assert.deepEqual(find(chain(8), 'CNAME_CHAIN_LONG'), []);
  });

  test('MX / NS / SRV targets that own a CNAME (RFC 2181 §10.3)', () => {
    const z = zone([['@', 'MX', '10 mx'], ['@', 'NS', 'ns'], ['_sip._tcp', 'SRV', '0 0 5060 sip'],
      ['mx', 'CNAME', 'mail'], ['ns', 'CNAME', 'mail'], ['sip', 'CNAME', 'mail'], ['mail', 'A', '192.0.2.25']]);
    assert.deepEqual(codes(z).filter((c) => c.endsWith('_TO_CNAME')).sort(), ['MX_TO_CNAME', 'NS_TO_CNAME', 'SRV_TO_CNAME']);
    assert.deepEqual(find(z, 'MX_TO_CNAME')[0].params, { name: 'example.com', target: 'mx.example.com' });
    assert.deepEqual(find(zone([['@', 'MX', '10 mail'], ['mail', 'A', '192.0.2.25']]), 'MX_TO_CNAME'), []);
  });

  test('TARGET_IS_IP: an NS / MX target written as an address', () => {
    const [f] = find(zone([['@', 'NS', '192.0.2.53.']]), 'TARGET_IS_IP');
    assert.deepEqual(f.params, { name: 'example.com', target: '192.0.2.53' });
    assert.deepEqual(find(zone([['@', 'NS', 'ns1.example.net.']]), 'TARGET_IS_IP'), []);
  });
});

describe('DANGLING_IN_ZONE_TARGET', () => {
  test('an in-zone target with no records is flagged', () => {
    const [f] = find(zone([['www', 'CNAME', 'web'], ['@', 'MX', '10 mail']]), 'DANGLING_IN_ZONE_TARGET');
    assert.equal(f.severity, 'warn');
    assert.equal(find(zone([['www', 'CNAME', 'web'], ['@', 'MX', '10 mail']]), 'DANGLING_IN_ZONE_TARGET').length, 2);
  });

  test('negative under a DNS wildcard (any depth, RFC 4592), a cut, a partial export or an external target', () => {
    const wild = zone([['*.apps', 'A', '192.0.2.20'], ['x', 'CNAME', 'a.b.apps']]);
    assert.deepEqual(find(wild, 'DANGLING_IN_ZONE_TARGET'), []);
    // an existing closer node (b.apps) stops the wildcard: then it dangles
    const closer = zone([['*.apps', 'A', '192.0.2.20'], ['c.b.apps', 'A', '192.0.2.21'], ['x', 'CNAME', 'a.b.apps']]);
    assert.equal(find(closer, 'DANGLING_IN_ZONE_TARGET').length, 1);
    // the wildcard's parent is an empty non-terminal: NODATA, so it dangles
    assert.equal(find(zone([['*.apps', 'A', '192.0.2.20'], ['x', 'CNAME', 'apps']]), 'DANGLING_IN_ZONE_TARGET').length, 1);
    assert.deepEqual(find(zone([['dev', 'NS', 'ns.example.net.'], ['x', 'CNAME', 'a.dev']]), 'DANGLING_IN_ZONE_TARGET'), []);
    assert.deepEqual(find(zone([['x', 'CNAME', 'web']], { partial: true }), 'DANGLING_IN_ZONE_TARGET'), []);
    assert.deepEqual(find(zone([['x', 'CNAME', 'web.example.net.']]), 'DANGLING_IN_ZONE_TARGET'), []);
  });

  test('a suspected missing dot is judged on the intended target', () => {
    const z = zone([['blog', 'CNAME', 'example-blog.github.io', { intendedTargets: ['example-blog.github.io'] }]]);
    assert.deepEqual(find(z, 'DANGLING_IN_ZONE_TARGET'), []);
  });
});

describe('duplicates and occlusion', () => {
  test('DUPLICATE_RR once per repeated record, pointing at the first', () => {
    const [f, ...rest] = find(zone([['old', 'A', '192.0.2.12'], ['old', 'A', '192.0.2.12', { duplicateOf: 0 }]]), 'DUPLICATE_RR');
    assert.equal(rest.length, 0);
    assert.deepEqual(f.params, { name: 'old.example.com', type: 'A' });
    assert.deepEqual(f.recordIds, [0, 1]);
  });

  test('OCCLUDED_BY_DELEGATION: below a cut and non-NS/DS data at it; glue is exempt', () => {
    const z = zone([['dev', 'NS', 'ns1.dev'], ['dev', 'DS', '12345 13 2 00ff'], ['ns1.dev', 'A', '192.0.2.53'],
      ['old.dev', 'A', '192.0.2.60'], ['dev', 'A', '192.0.2.61'], ['dev', 'TXT', 'x']]);
    const occ = find(z, 'OCCLUDED_BY_DELEGATION');
    assert.deepEqual(occ.map((f) => `${f.name} ${f.type} ${f.params.cut}`).sort(),
      ['dev.example.com A dev.example.com', 'dev.example.com TXT dev.example.com', 'old.dev.example.com A dev.example.com']);
    const res = lintZone(z);
    assert.equal(res.occluded.get('old.dev.example.com'), 'cut');
    assert.equal(res.occluded.has('ns1.dev.example.com'), false);
    assert.deepEqual([...res.occludedIds].sort(), [3, 4, 5]);
  });

  test('an in-domain name server named after the cut keeps its glue at the cut', () => {
    const z = zone([['dev', 'NS', 'dev'], ['dev', 'A', '192.0.2.60'], ['dev', 'AAAA', '2001:db8::60'], ['dev', 'TXT', 'x']]);
    assert.deepEqual(find(z, 'OCCLUDED_BY_DELEGATION').map((f) => `${f.name} ${f.type}`), ['dev.example.com TXT']);
    const res = lintZone(z);
    assert.deepEqual([...res.occludedIds], [3]);
    assert.equal(res.occluded.has('dev.example.com'), false);
  });

  test("Cloudflare's meta.shadowed_by (occludedBy) counts, one finding per RRset", () => {
    const z = cfZone([['old.dev', 'A', '192.0.2.60', { occludedBy: 'delegation' }], ['old.dev', 'A', '192.0.2.61', { occludedBy: 'delegation' }]],
      { format: 'cloudflare-api', dialect: null });
    const occ = find(z, 'OCCLUDED_BY_DELEGATION');
    assert.equal(occ.length, 1);
    assert.equal(occ[0].recordIds.length, 2);
  });

  test('OCCLUDED_BY_DNAME: data below a DNAME owner', () => {
    const [f] = find(zone([['old', 'DNAME', 'new.example.net.'], ['a.old', 'A', '192.0.2.5']]), 'OCCLUDED_BY_DNAME');
    assert.deepEqual(f.params, { name: 'a.old.example.com', dname: 'old.example.com' });
  });
});

describe('addresses', () => {
  test('PRIVATE_IP, LOCALHOST_RECORD and NON_GLOBAL_IPV6', () => {
    const z = zone([['intranet', 'A', '10.20.30.40'], ['localhost', 'A', '127.0.0.1'], ['v6', 'AAAA', '200::1'], ['ok6', 'AAAA', '2001:db8::1'], ['pub', 'A', '203.0.113.5']]);
    assert.deepEqual(find(z, 'PRIVATE_IP').map((f) => f.params), [{ name: 'intranet.example.com', ip: '10.20.30.40' }]);
    assert.deepEqual(find(z, 'LOCALHOST_RECORD').map((f) => f.params), [{ name: 'localhost.example.com', ip: '127.0.0.1' }]);
    assert.deepEqual(find(z, 'NON_GLOBAL_IPV6').map((f) => f.params), [{ name: 'v6.example.com', ip: '200::1' }]);
  });

  test('invalid records are left to the parser (no address finding)', () => {
    assert.deepEqual(codes(zone([['x', 'A', '999.1.1.1', { invalid: true }]])), []);
  });
});

describe('Cloudflare rules', () => {
  test('MIXED_PROXY_FLAGS: one proxied and one DNS-only A/AAAA at a name', () => {
    const [f] = find(cfZone([['mixed', 'A', '192.0.2.30', P], ['mixed', 'A', '192.0.2.31', D]]), 'MIXED_PROXY_FLAGS');
    assert.deepEqual(f.params, { name: 'mixed.example.com' });
    assert.deepEqual(find(cfZone([['a', 'A', '192.0.2.30', P], ['a', 'A', '192.0.2.31', P]]), 'MIXED_PROXY_FLAGS'), []);
  });

  test('ORIGIN_EXPOSED_BY_SIBLING: a DNS-only record elsewhere publishes the origin', () => {
    const z = cfZone([['@', 'A', '192.0.2.10', P], ['www', 'A', '192.0.2.10', P], ['ftp', 'A', '192.0.2.10', D],
      ['mixed', 'A', '192.0.2.30', P], ['mixed', 'A', '192.0.2.31', D]]);
    const found = find(z, 'ORIGIN_EXPOSED_BY_SIBLING');
    assert.equal(found.length, 1, 'a DNS-only A on a proxied name is proxied too (Cloudflare rule)');
    assert.equal(found[0].severity, 'error');
    assert.deepEqual(found[0].params, { name: 'ftp.example.com', ip: '192.0.2.10', proxied: ['example.com', 'www.example.com'], role: 'record' });
  });

  test('the MX exchange case is folded in (role mx); a CNAME to a host origin exposes it too', () => {
    const z = cfZone([['www', 'A', '198.51.100.20', P], ['@', 'MX', '10 mail'], ['mail', 'A', '198.51.100.20', D],
      ['app', 'CNAME', 'origin-lb.example.net.', P], ['lb2', 'CNAME', 'origin-lb.example.net.', D]]);
    const byName = Object.fromEntries(find(z, 'ORIGIN_EXPOSED_BY_SIBLING').map((f) => [f.name, f.params]));
    assert.equal(byName['mail.example.com'].role, 'mx');
    assert.deepEqual(byName['lb2.example.com'], { name: 'lb2.example.com', host: 'origin-lb.example.net', proxied: ['app.example.com'], role: 'record' });
  });

  test('a placeholder or Cloudflare address is not an origin, so it is never "exposed"', () => {
    const z = cfZone([['worker', 'A', '192.0.2.0', P], ['other', 'A', '192.0.2.0', D], ['e', 'A', '104.16.1.1', P], ['f', 'A', '104.16.1.1', D]]);
    assert.deepEqual(find(z, 'ORIGIN_EXPOSED_BY_SIBLING'), []);
  });

  test('ORIGIN_EXPOSED_BY_SPF: once per SPF record, with every covered origin', () => {
    const z = cfZone([['@', 'A', '192.0.2.10', P], ['api', 'A', '192.0.2.13', P], ['admin', 'A', '192.0.2.12', D],
      ['@', 'TXT', 'v=spf1 ip4:198.51.100.25 ip4:192.0.2.8/29 ~all']]);
    const spf = find(z, 'ORIGIN_EXPOSED_BY_SPF');
    assert.equal(spf.length, 1);
    assert.equal(spf[0].severity, 'warn');
    assert.deepEqual(spf[0].params, { spfName: 'example.com', ips: ['192.0.2.10', '192.0.2.13'], proxied: ['example.com', 'api.example.com'] });
    assert.deepEqual(find(cfZone([['@', 'A', '192.0.2.10', P], ['@', 'TXT', 'v=spf1 ip4:198.51.100.0/24 -all']]), 'ORIGIN_EXPOSED_BY_SPF'), []);
  });

  test('PROXIED_PRIVATE_ORIGIN, PROXIED_TO_CLOUDFLARE_IP (error 1000) and ORIGINLESS_PLACEHOLDER', () => {
    const z = cfZone([['backend', 'A', '10.0.0.5', P], ['err', 'A', '104.16.1.1', P], ['worker', 'A', '192.0.2.0', P], ['edge', 'AAAA', '100::', P]]);
    assert.deepEqual(find(z, 'PROXIED_PRIVATE_ORIGIN').map((f) => f.params), [{ name: 'backend.example.com', ip: '10.0.0.5' }]);
    assert.deepEqual(find(z, 'PROXIED_TO_CLOUDFLARE_IP').map((f) => f.params), [{ name: 'err.example.com', ip: '104.16.1.1' }]);
    assert.deepEqual(find(z, 'ORIGINLESS_PLACEHOLDER').map((f) => f.params.name).sort(), ['edge.example.com', 'worker.example.com']);
    assert.deepEqual(find(z, 'PRIVATE_IP'), [], 'the private origin is not published, so it is not PRIVATE_IP');
    assert.deepEqual(find(z, 'NON_GLOBAL_IPV6'), [], '100:: proxied is a placeholder, not a non-global AAAA');
  });

  test('PROXIED_TUNNEL and PROXIED_PROVIDER; a DNS-steering provider is a host origin', () => {
    const z = cfZone([['t', 'CNAME', 'abc.cfargotunnel.com.', P], ['shop', 'CNAME', 'shops.myshopify.com.', P],
      ['pages', 'CNAME', 'site.pages.dev.', P], ['gw', 'CNAME', 'abc123.execute-api.eu-west-1.amazonaws.com.', P],
      ['tm', 'CNAME', 'app.trafficmanager.net.', P], ['blog', 'CNAME', 'example-blog.github.io.', D]]);
    assert.deepEqual(find(z, 'PROXIED_TUNNEL').map((f) => f.params), [{ name: 't.example.com', target: 'abc.cfargotunnel.com' }]);
    assert.deepEqual(find(z, 'PROXIED_PROVIDER').map((f) => `${f.name} ${f.params.provider}`),
      ['shop.example.com shopify', 'pages.example.com cloudflare-pages', 'gw.example.com aws-api-gateway']);
  });

  test('MX_TARGET_PROXIED (also through a chain) and SRV_TARGET_PROXIED off the proxied ports', () => {
    const z = cfZone([['www', 'A', '198.51.100.20', P], ['smtp', 'CNAME', 'www', D], ['@', 'MX', '10 www'], ['@', 'MX', '20 smtp'],
      ['_sip._tcp', 'SRV', '10 5 5060 www'], ['_autodiscover._tcp', 'SRV', '0 0 443 www']]);
    assert.deepEqual(find(z, 'MX_TARGET_PROXIED').map((f) => f.params.target).sort(), ['smtp.example.com', 'www.example.com']);
    const srv = find(z, 'SRV_TARGET_PROXIED');
    assert.deepEqual(srv.map((f) => f.params), [{ name: '_sip._tcp.example.com', target: 'www.example.com', port: 5060 }]);
    assert.ok(CF_PROXY_PORTS.includes(443) && CF_PROXY_PORTS.includes(8443));
  });

  test('Cloudflare rules stay silent on a zone without proxy flags', () => {
    const z = zone([['@', 'A', '192.0.2.10'], ['ftp', 'A', '192.0.2.10'], ['@', 'TXT', 'v=spf1 ip4:192.0.2.0/24 -all'], ['@', 'MX', '10 @']]);
    assert.deepEqual(codes(z), []);
  });
});

describe('mail, CAA, TTL, SOA and NS rules', () => {
  test('MULTIPLE_SPF, SPF_INVALID (health wording code) and SPF_RR_TYPE', () => {
    const z = zone([['@', 'TXT', 'v=spf1 mx -all'], ['@', 'TXT', 'v=spf1 a -all'], ['bad', 'TXT', 'v=spf1 foo:bar -all'], ['old', 'SPF', 'v=spf1 -all']]);
    assert.deepEqual(find(z, 'MULTIPLE_SPF')[0].params, { name: 'example.com', count: 2 });
    assert.equal(find(z, 'SPF_INVALID')[0].params.error, 'unknown-mechanism');
    assert.deepEqual(find(z, 'SPF_RR_TYPE')[0].params, { name: 'old.example.com' });
    assert.deepEqual(find(zone([['@', 'TXT', 'v=spf10 not spf'], ['@', 'TXT', 'v=spf1 -all']]), 'MULTIPLE_SPF'), []);
    // weighted variants each serve one SPF; two inside one variant clash
    const w = (id) => ({ routing: { policy: 'weighted', id } });
    assert.deepEqual(find(zone([['mail', 'TXT', 'v=spf1 mx -all', w('a')], ['mail', 'TXT', 'v=spf1 a -all', w('b')]]), 'MULTIPLE_SPF'), []);
    assert.equal(find(zone([['mail', 'TXT', 'v=spf1 mx -all', w('a')], ['mail', 'TXT', 'v=spf1 a -all', w('a')]]), 'MULTIPLE_SPF').length, 1);
  });

  test('DMARC_INVALID for a v=DMARC1 record that fails the health parser only', () => {
    assert.equal(find(zone([['_dmarc', 'TXT', 'v=DMARC1; p=bogus']]), 'DMARC_INVALID')[0].params.error, 'invalid-p');
    assert.deepEqual(find(zone([['_dmarc', 'TXT', 'v=DMARC1; p=none; rua=mailto:d@example.com']]), 'DMARC_INVALID'), []);
    assert.deepEqual(find(zone([['_dmarc', 'TXT', 'some-verification=abc']]), 'DMARC_INVALID'), []);
  });

  test('TXT_STRING_TOO_LONG counts UTF-8 bytes; error in BIND, info for the CF API', () => {
    const umlauts = ['ä'.repeat(130)]; // 130 characters, 260 bytes
    const [bind] = find(zone([['long', 'TXT', umlauts]]), 'TXT_STRING_TOO_LONG');
    assert.deepEqual(bind.params, { name: 'long.example.com', bytes: 260 });
    assert.equal(bind.severity, 'error');
    const api = find(zone([['long', 'TXT', ['x'.repeat(300)]]], { format: 'cloudflare-api', dialect: null }), 'TXT_STRING_TOO_LONG')[0];
    assert.equal(api.severity, 'info');
    assert.deepEqual(find(zone([['ok', 'TXT', ['x'.repeat(255), 'y']]]), 'TXT_STRING_TOO_LONG'), []);
  });

  test('TXT_STRING_TOO_LONG counts the bytes the zone holds, not each string decoded on its own', () => {
    // "<254×a>\197" "\159<44×b>": 255 and 45 bytes, a 'ş' (C5 9F) split across them, so the parser
    // decodes each string as Latin-1 (one character a byte, two bytes again as UTF-8).
    const data = [`${'a'.repeat(254)}Å`, `\u009f${'b'.repeat(44)}`];
    const text = `"${'a'.repeat(254)}\\197" "\\159${'b'.repeat(44)}"`;
    assert.deepEqual(find(zone([['note', 'TXT', 'x', { data, text }]]), 'TXT_STRING_TOO_LONG'), []);
    const long = find(zone([['note', 'TXT', 'x', { data: [`${'a'.repeat(255)}Å`], text: `"${'a'.repeat(255)}\\197"` }]]), 'TXT_STRING_TOO_LONG');
    assert.deepEqual(long.map((f) => f.params.bytes), [256]);
  });

  test('CAA_UNKNOWN_TAG and CAA_FLAGS', () => {
    const z = zone([['@', 'CAA', '0 isue "example-ca.example"'], ['@', 'CAA', '5 issue "letsencrypt.org"'], ['@', 'CAA', '128 issue "letsencrypt.org"']]);
    assert.deepEqual(find(z, 'CAA_UNKNOWN_TAG').map((f) => f.params), [{ name: 'example.com', tag: 'isue' }]);
    assert.deepEqual(find(z, 'CAA_FLAGS').map((f) => f.params), [{ name: 'example.com', flags: 5 }]);
  });

  test('TTL_OUTLIER / TTL_TOO_LOW against the zone median; auto TTLs, aliases, SOA and NS are ignored', () => {
    const z = zone([SOA, ['@', 'NS', 'ns1.example.net.', { ttl: 172800 }], ['a', 'A', '192.0.2.1', { ttl: 3600 }], ['b', 'A', '192.0.2.2', { ttl: 3600 }],
      ['slow', 'A', '192.0.2.3', { ttl: 604800 }], ['fast', 'A', '192.0.2.4', { ttl: 10 }], ['auto', 'A', '192.0.2.5', { ttl: 1, ttlAuto: true }],
      ['al', 'A', null, { alias: { target: 'd1.cloudfront.net', zoneId: null, evaluateTargetHealth: false, provider: 'cloudfront' } }]]);
    assert.deepEqual(find(z, 'TTL_OUTLIER').map((f) => f.params), [{ name: 'slow.example.com', ttl: 604800, median: 3600 }]);
    assert.deepEqual(find(z, 'TTL_TOO_LOW').map((f) => f.params), [{ name: 'fast.example.com', ttl: 10, median: 3600 }]);
  });

  test('SOA_NEGATIVE_TTL and SINGLE_NS', () => {
    const z = zone([['@', 'SOA', { mname: 'ns1.example.net', rname: 'h.example.com', serial: 1, refresh: 1, retry: 1, expire: 1, minimum: 172800 }], ['@', 'NS', 'ns1.example.net.']]);
    assert.deepEqual(find(z, 'SOA_NEGATIVE_TTL')[0].params, { name: 'example.com', minimum: 172800 });
    assert.deepEqual(find(z, 'SINGLE_NS')[0].params, { name: 'example.com' });
    assert.deepEqual(find(zone([['@', 'NS', 'a.example.net.'], ['@', 'NS', 'b.example.net.']]), 'SINGLE_NS'), []);
  });

  test('ALIAS_TARGET_MISSING for a same-zone Route 53 alias, not on a partial export', () => {
    const alias = { target: 'api.example.com', zoneId: 'Z0EXAMPLE', evaluateTargetHealth: false, provider: 'same-zone' };
    const z = zone([['www', 'A', null, { alias }]], { format: 'route53', dialect: null });
    assert.deepEqual(find(z, 'ALIAS_TARGET_MISSING')[0].params, { name: 'www.example.com', target: 'api.example.com' });
    assert.deepEqual(find(zone([['www', 'A', null, { alias }]], { format: 'route53', dialect: null, partial: true }), 'ALIAS_TARGET_MISSING'), []);
    assert.deepEqual(find(zone([['www', 'A', null, { alias }], ['api', 'A', '192.0.2.21']], { format: 'route53', dialect: null }), 'ALIAS_TARGET_MISSING'), []);
  });
});

describe('finding shape', () => {
  test('params hold values, not English; sorted by severity then line', () => {
    const f = lintZone(loadFixture('bind-edge')).findings;
    assert.ok(f.length > 5);
    for (const x of f) {
      assert.ok(x.code in LINT_RULES, x.code);
      assert.ok(Number.isInteger(x.line) && x.line >= 0);
      assert.ok(Array.isArray(x.recordIds) && x.recordIds.every(Number.isInteger));
      for (const v of Object.values(x.params)) {
        assert.ok(v === null || ['string', 'number'].includes(typeof v) || (Array.isArray(v) && v.every((s) => typeof s === 'string')), x.code);
      }
      assert.equal(typeof x.detail, 'string');
    }
    const rank = (s) => SEVERITY_ORDER.indexOf(s);
    for (let i = 1; i < f.length; i += 1) {
      assert.ok(rank(f[i - 1].severity) < rank(f[i].severity)
        || (rank(f[i - 1].severity) === rank(f[i].severity) && f[i - 1].line <= f[i].line));
    }
  });
});

describe('fixtures', () => {
  test('the Cloudflare export: the pinned findings and no other error', () => {
    const f = lintZone(loadFixture('cloudflare-export')).findings;
    const got = f.map((x) => `${x.code} ${x.name}`);
    for (const want of ['MIXED_PROXY_FLAGS mixed.example.com', 'OCCLUDED_BY_DELEGATION old.dev.example.com', 'PRIVATE_IP intranet.example.com',
      'PROXIED_TUNNEL tunnel.example.com', 'PROXIED_PROVIDER shop.example.com', 'ORIGIN_EXPOSED_BY_SIBLING ftp.example.com']) {
      assert.ok(got.includes(want), want);
    }
    const spf = f.filter((x) => x.code === 'ORIGIN_EXPOSED_BY_SPF');
    assert.equal(spf.length, 1);
    assert.deepEqual(spf[0].params.ips, ['192.0.2.10', '192.0.2.13']);
    assert.deepEqual(f.filter((x) => x.severity === 'error').map((x) => x.code), ['ORIGIN_EXPOSED_BY_SIBLING']);
  });

  test('every fixture: the lint lines of its analysis golden', () => {
    for (const name of fixtureNames()) {
      const golden = readFileSync(join(HERE, 'expected', `${name}.analysis.golden.txt`), 'utf8').split('\n').filter((l) => l.startsWith('lint '));
      const lines = lintZone(loadFixture(name)).findings.map((x) => {
        const kv = Object.entries(x.params).map(([k, v]) => {
          const s = Array.isArray(v) ? (v.length ? v.join(',') : '-') : v === null ? '-' : String(v);
          return `${k}=${s === '' || /[\s"]/.test(s) ? JSON.stringify(s) : s}`;
        }).join(' ');
        return `lint ${x.severity} ${x.code} ${x.name} ${x.type || '-'} @${x.line} ${kv}`.trimEnd();
      });
      assert.deepEqual(lines, golden, name);
    }
  });
});

describe('performance', () => {
  test(`20,000 records lint in under ${300 * PERF_FACTOR} ms`, () => {
    const rows = [];
    for (let i = 0; i < 20000; i += 1) {
      const k = i % 5;
      const oct = `${(i >> 8) & 255}.${i & 255}`;
      if (k === 0) rows.push([`h${i}`, 'A', `10.9.${oct}`, { proxied: i % 10 === 0, ttlAuto: true }]);
      else if (k === 1) rows.push([`c${i}`, 'CNAME', `h${i - 1}`, { proxied: false }]);
      else if (k === 2) rows.push([`t${i}`, 'TXT', `v=spf1 ip4:10.9.${oct} -all`]);
      else if (k === 3) rows.push([`m${i}`, 'MX', `10 h${i - 3}`]);
      else rows.push([`s${i}.dev${i % 7}`, 'A', `198.51.100.${i % 250}`]);
    }
    const big = cfZone(rows);
    // best of 3 runs: one parallel-suite GC / scheduler stall must not fail a budget test
    let res;
    let ms = Infinity;
    for (let run = 0; run < 3; run += 1) {
      const t0 = performance.now();
      res = lintZone(big);
      ms = Math.min(ms, performance.now() - t0);
    }
    assert.ok(res.findings.length > 0);
    assert.ok(ms < 300 * PERF_FACTOR, `lint took ${ms.toFixed(0)} ms`);
  });
});
