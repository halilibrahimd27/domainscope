// Unit tests for assets/js/lib/networklabel.js — the provider network-tier label of a direct
// address (ROADMAP P2.10 follow-up), merged with IP Intel's AS-based hint. A synthetic range dataset
// of documentation prefixes is installed, so the tests do not depend on the weekly refresh.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { LABEL_RELATIONS, LABEL_SOURCES, networkLabel, firstNetworkLabel } from '../../assets/js/lib/networklabel.js';
import { RANGES_FORMAT, classifyResolution, installRanges, NETWORKS } from '../../assets/js/lib/netinfo.js';
import { networkHint } from '../../assets/js/lib/ipintel.js';

const DATASET = Object.freeze({
  manifest: { format: RANGES_FORMAT, generated: '2026-10-08' },
  edges: { cloudflare: ['203.0.113.0/26'] },
  networks: {
    cloudflare: ['203.0.113.0/24'],
    aws: ['198.51.100.0/25'],
    'google-cloud': ['198.51.100.128/26'],
    digitalocean: ['192.0.2.0/25', '2001:db8:d0::/48']
  }
});
const classify = (ip) => classifyResolution({ status: 'NOERROR', ipv4: ip.includes(':') ? [] : [ip], ipv6: ip.includes(':') ? [ip] : [] });

describe('networkLabel with the range dataset', () => {
  before(() => assert.equal(installRanges(DATASET).source, 'data'));
  after(() => installRanges(null));

  test('a Cloudflare network address outside its proxy ranges: direct, "not necessarily proxied"', () => {
    const c = classify('203.0.113.100');
    assert.equal(c.kind, 'direct');
    assert.equal(c.network.id, 'cloudflare');
    assert.deepEqual(networkLabel({ classification: c, ip: '203.0.113.100' }), {
      id: 'cloudflare', name: 'Cloudflare', category: 'cdn', relation: 'outside-proxy-ranges', asn: null, source: 'ranges'
    });
  });

  test('an edge address is proxied: no label (the classification names Cloudflare)', () => {
    const c = classify('203.0.113.5');
    assert.equal(c.kind, 'cloudflare');
    assert.equal(networkLabel({ classification: c, ip: '203.0.113.5' }), null);
  });

  test('cloud and hosting networks: hosted; IPv6 too', () => {
    assert.equal(networkLabel({ classification: classify('198.51.100.20') }).relation, 'hosted');
    assert.equal(networkLabel({ classification: classify('198.51.100.20') }).name, 'AWS');
    assert.equal(networkLabel({ ip: '198.51.100.130' }).id, 'google-cloud');
    assert.deepEqual(networkLabel({ ip: '2001:db8:d0::7' }), {
      id: 'digitalocean', name: 'DigitalOcean', category: 'hosting', relation: 'hosted', asn: null, source: 'ranges'
    });
  });

  test('the same operator in the AS hint adds its AS number (Google Cloud counts as Google)', () => {
    const c = classify('198.51.100.20');
    const hint = networkHint({ asn: 16509 }, c);
    assert.equal(hint.id, 'aws');
    assert.deepEqual(networkLabel({ classification: c, hint }), {
      id: 'aws', name: 'AWS', category: 'cloud', relation: 'hosted', asn: 16509, source: 'both'
    });
    const g = networkLabel({ classification: classify('198.51.100.130'), hint: networkHint({ asn: 396982 }, classify('198.51.100.130')) });
    assert.equal(g.source, 'both');
    assert.equal(g.asn, 396982);
    assert.equal(g.name, 'Google Cloud');
  });

  test('another operator in the AS hint: the published range decides, the AS number is not borrowed', () => {
    const c = classify('198.51.100.20');
    const label = networkLabel({ classification: c, hint: networkHint({ asn: 24940 }, c) });
    assert.equal(label.id, 'aws');
    assert.equal(label.source, 'ranges');
    assert.equal(label.asn, null);
  });

  test('a classification made before the dataset loaded: the address is looked up', () => {
    const early = { kind: 'direct', provider: null };
    assert.equal(networkLabel({ classification: early, ip: '192.0.2.10' }).id, 'digitalocean');
    assert.equal(networkLabel({ classification: early }), null, 'nothing to look up without the address');
  });

  test('private, unresolved and unknown addresses have no label', () => {
    assert.equal(networkLabel({ classification: classify('10.0.0.5'), ip: '10.0.0.5' }), null);
    assert.equal(networkLabel({ classification: { kind: 'nxdomain' }, ip: '198.51.100.20' }), null);
    assert.equal(networkLabel({ ip: '192.0.2.200' }), null, 'outside every network tier');
    assert.equal(networkLabel({ ip: 'not-an-ip' }), null);
    assert.equal(networkLabel(), null);
  });

  test('firstNetworkLabel: the first address of a host that has one', () => {
    assert.equal(firstNetworkLabel(['192.0.2.200', '203.0.113.100']).id, 'cloudflare');
    assert.equal(firstNetworkLabel(['192.0.2.200']), null);
    assert.equal(firstNetworkLabel(['203.0.113.100'], { kind: 'cdn' }), null, 'a CDN answer has no network label');
    assert.equal(firstNetworkLabel([], classify('198.51.100.20')).id, 'aws', 'the classification carries it');
  });
});

describe('networkLabel without the dataset', () => {
  before(() => installRanges(null));

  test('the AS hint alone (IP Intel before or without the dataset)', () => {
    const c = classify('1.1.1.1');
    assert.equal(c.network, undefined, 'no network tier without the dataset');
    const hint = networkHint({ asn: 13335 }, c);
    assert.deepEqual(networkLabel({ classification: c, ip: '1.1.1.1', hint }), {
      id: 'cloudflare', name: 'Cloudflare', category: 'cdn', relation: 'outside-proxy-ranges', asn: 13335, source: 'asn'
    });
    const akamai = networkLabel({ classification: c, hint: networkHint({ asn: 20940 }, c) });
    assert.equal(akamai.relation, 'cdn-edge', 'a CDN without a published edge list');
    assert.equal(networkLabel({ classification: c, ip: '1.1.1.1' }), null);
  });

  test('vocabularies', () => {
    assert.deepEqual([...LABEL_RELATIONS], ['outside-proxy-ranges', 'cdn-edge', 'hosted']);
    assert.deepEqual([...LABEL_SOURCES], ['ranges', 'asn', 'both']);
    assert.ok(NETWORKS.every((n) => ['cdn', 'cloud', 'hosting'].includes(n.category)), 'every network-tier category maps to a relation');
  });
});
