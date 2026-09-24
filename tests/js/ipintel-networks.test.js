/**
 * ipintel.js well-known infrastructure networks (INFRA_NETWORKS / infraNetworkByAsn /
 * networkHint): the IP view's display hint for plain 'direct' addresses such as 1.1.1.1
 * (AS13335, outside Cloudflare's proxy ranges). Also pins that netinfo.classifyResolution —
 * the scanner's contract — is unchanged by it. No network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { INFRA_NETWORKS, infraNetworkByAsn, networkHint } from '../../assets/js/lib/ipintel.js';
import { classifyResolution, getProvider } from '../../assets/js/lib/netinfo.js';

const classify = (ip) => classifyResolution({ status: 'NOERROR', ipv4: ip.includes(':') ? [] : [ip], ipv6: ip.includes(':') ? [ip] : [] });

describe('INFRA_NETWORKS', () => {
  test('well-formed: unique ids and AS numbers, known categories, proxy ranges exist in netinfo', () => {
    const ids = new Set();
    const asns = new Set();
    for (const n of INFRA_NETWORKS) {
      assert.ok(Object.isFrozen(n) && Object.isFrozen(n.asns), n.id);
      assert.ok(!ids.has(n.id), `duplicate id ${n.id}`);
      ids.add(n.id);
      assert.match(n.id, /^[a-z0-9-]+$/);
      assert.ok(n.name && typeof n.name === 'string');
      assert.ok(['cdn', 'waf', 'cloud', 'hosting', 'platform'].includes(n.category), `${n.id} category`);
      assert.ok(n.asns.length > 0);
      for (const a of n.asns) {
        assert.ok(Number.isInteger(a) && a > 0 && a < 4294967296, `${n.id} AS${a}`);
        assert.ok(!(a >= 64496 && a <= 65551), `${n.id}: documentation / private AS${a}`);
        assert.ok(!asns.has(a), `AS${a} listed twice`);
        asns.add(a);
      }
      if (n.proxyRanges !== null) {
        const p = getProvider(n.proxyRanges);
        assert.ok(p && p.cidrs.length > 0, `${n.id}: netinfo provider ${n.proxyRanges} with published ranges`);
      }
    }
  });

  test('includes the networks people ask about most', () => {
    const want = { 13335: 'cloudflare', 16509: 'aws', 14618: 'aws', 15169: 'google', 396982: 'google', 8075: 'microsoft', 54113: 'fastly', 20940: 'akamai', 16625: 'akamai' };
    for (const [asn, id] of Object.entries(want)) assert.equal(infraNetworkByAsn(Number(asn))?.id, id, `AS${asn}`);
  });
});

describe('infraNetworkByAsn', () => {
  test('accepts numbers, numeric strings and "AS…" forms', () => {
    for (const v of [13335, '13335', 'AS13335', 'as13335', ' AS13335 ']) assert.equal(infraNetworkByAsn(v)?.name, 'Cloudflare', String(v));
  });

  test('unknown, documentation and junk AS numbers → null', () => {
    for (const v of [64500, 64511, 9999999, 0, -1, 1.5, NaN, null, undefined, '', 'AS', 'cloudflare', {}]) {
      assert.equal(infraNetworkByAsn(v), null, String(v));
    }
  });
});

describe('networkHint', () => {
  test('1.1.1.1: classified direct (not a Cloudflare proxy range) → "Cloudflare network, outside proxy ranges"', () => {
    const cls = classify('1.1.1.1');
    assert.equal(cls.kind, 'direct');
    assert.equal(cls.provider, null);
    assert.deepEqual(networkHint({ asn: 13335, asns: [{ asn: 13335, holder: 'CLOUDFLARENET' }] }, cls), {
      id: 'cloudflare', name: 'Cloudflare', category: 'cdn', asn: 13335, relation: 'outside-proxy-ranges'
    });
  });

  test('addresses inside published proxy ranges keep their classification (no hint)', () => {
    const cf = classify('104.16.132.229');
    assert.equal(cf.kind, 'cloudflare');
    assert.equal(networkHint({ asn: 13335 }, cf), null);
    const v6 = classify('2606:4700:4700::1111');
    assert.equal(v6.kind, 'cloudflare');
    assert.equal(networkHint({ asn: 13335 }, v6), null);
    const cloudfront = classify('13.32.0.1');
    assert.equal(cloudfront.kind, 'cdn');
    assert.equal(networkHint({ asn: 16509 }, cloudfront), null);
  });

  test('cloud / hosting / platform networks → "hosted"; CDNs without published ranges → "cdn-edge"', () => {
    const direct = { kind: 'direct' };
    assert.deepEqual(networkHint({ asn: 15169 }, direct), { id: 'google', name: 'Google', category: 'cloud', asn: 15169, relation: 'hosted' });
    assert.equal(networkHint({ asn: 16509 }, direct).relation, 'hosted', 'AWS outside CloudFront');
    assert.equal(networkHint({ asn: 24940 }, direct).category, 'hosting');
    assert.equal(networkHint({ asn: 36459 }, classify('140.82.121.4')).relation, 'hosted', 'GitHub');
    assert.deepEqual(networkHint({ asn: 20940 }, direct), { id: 'akamai', name: 'Akamai', category: 'cdn', asn: 20940, relation: 'cdn-edge' });
    assert.equal(networkHint({ asn: 19551 }, direct).relation, 'cdn-edge', 'Imperva');
    assert.equal(networkHint({ asn: 54113 }, direct).relation, 'outside-proxy-ranges', 'Fastly (ranges known)');
  });

  test('MOAS: the first origin AS that is well known wins', () => {
    const hint = networkHint({ asn: 64500, asns: [{ asn: 64500, holder: 'EXAMPLE-NET' }, { asn: 13335, holder: 'CLOUDFLARENET' }] }, { kind: 'direct' });
    assert.equal(hint.id, 'cloudflare');
    assert.equal(hint.asn, 13335);
  });

  test('no hint for private / unresolved classifications, unknown ASes or missing info', () => {
    assert.equal(networkHint({ asn: 13335 }, classify('10.0.0.1')), null, 'private');
    assert.equal(networkHint({ asn: 13335 }, { kind: 'unresolved' }), null);
    assert.equal(networkHint({ asn: 64500, asns: [] }, { kind: 'direct' }), null, 'unknown AS');
    assert.equal(networkHint({ asn: null, asns: [] }, { kind: 'direct' }), null);
    for (const bad of [null, undefined, 42, 'x']) assert.equal(networkHint(bad, { kind: 'direct' }), null);
  });

  test('without a classification only the AS number is used', () => {
    assert.equal(networkHint({ asn: 8075 }).id, 'microsoft');
  });
});
