/**
 * ipintel.js well-known infrastructure networks (INFRA_NETWORKS / infraNetworkByAsn /
 * networkHint): the IP view's display hint for plain 'direct' addresses such as 1.1.1.1
 * (AS13335, outside Cloudflare's proxy ranges). Also pins that netinfo.classifyResolution —
 * the scanner's contract — is unchanged by it. No network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  INFRA_NETWORKS, infraNetworkByAsn, networkHint,
  networkQuery, summarizeNetwork, describeNetwork, createIpIntel, parsePrefixOverview
} from '../../assets/js/lib/ipintel.js';
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

/* -------------------------------------------------------------------- */
/* describeNetwork (origin-network ownership, on demand)                */
/* -------------------------------------------------------------------- */

const po = (data) => ({ status: 'ok', data });
// A RIPEstat prefix-overview mock for one announcing AS + prefix + RIR block.
const poFor = (resource, asn, holder, rir = 'ARIN') => po({
  announced: true, resource, asns: [{ asn, holder }], block: { desc: `Administered by ${rir}` }
});

function mockFetch(handler) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    const out = handler(url);
    if (out instanceof Response) return out;
    return Response.json(out);
  };
  return { fetchImpl, calls };
}

describe('networkQuery', () => {
  test('an address, a CIDR (host bits masked), IPv6, and invalid input', () => {
    assert.deepEqual({ ...networkQuery('192.0.2.7'), range: undefined }, { input: '192.0.2.7', ip: '192.0.2.7', version: 4, range: undefined });
    const c = networkQuery('192.0.2.77/24');
    assert.equal(c.input, '192.0.2.0/24');
    assert.equal(c.ip, '192.0.2.0'); // any address of the /24 shares its announced prefix
    const v6 = networkQuery('2001:db8:1::/48');
    assert.equal(v6.input, '2001:db8:1::/48');
    assert.equal(v6.version, 6);
    assert.equal(networkQuery('nope'), null);
    assert.equal(networkQuery(''), null);
  });
});

describe('summarizeNetwork (pure)', () => {
  test('a cloud AS is shared and its infra operator is named; coversInput reflects the prefix', () => {
    const q = networkQuery('192.0.2.0/24');
    const d = summarizeNetwork(q, parsePrefixOverview(poFor('192.0.2.0/24', 16509, 'AMAZON-02 - Amazon.com, Inc.')));
    assert.equal(d.asn, 16509);
    assert.equal(d.asName, 'AMAZON-02');
    assert.equal(d.holder, 'Amazon.com, Inc.');
    assert.equal(d.prefix, '192.0.2.0/24');
    assert.deepEqual(d.infra, { id: 'aws', name: 'AWS', category: 'cloud' });
    assert.equal(d.category, 'cloud');
    assert.equal(d.shared, true);
    assert.equal(d.coversInput, true);
    assert.equal(d.rir, 'ARIN');
  });

  test('an unknown AS is not shared (that is not proof of single ownership); a wider block is only partly covered', () => {
    const q = networkQuery('203.0.113.0/24');
    const d = summarizeNetwork(q, parsePrefixOverview(poFor('203.0.113.0/25', 64500, 'EXAMPLE-AS - Example Hosting')));
    assert.equal(d.asn, 64500);
    assert.equal(d.infra, null);
    assert.equal(d.shared, false, 'a plain unknown AS: not a KNOWN shared operator');
    assert.equal(d.coversInput, false, 'the announced /25 does not cover the whole queried /24');
  });

  test('no RIPEstat data: shared is unknown (null), unless a netinfo provider range already says so', () => {
    const d = summarizeNetwork(networkQuery('203.0.113.0/24'), null);
    assert.equal(d.shared, null);
    assert.equal(d.asn, null);
    // Cloudflare-range address is known shared offline even without a lookup
    const cf = summarizeNetwork(networkQuery('104.16.0.0/24'), null);
    assert.equal(cf.provider && cf.provider.id, 'cloudflare');
    assert.equal(cf.shared, true);
  });
});

describe('describeNetwork (service + module helper)', () => {
  test('one RIPEstat request per network; cached and deduped by masked prefix', async () => {
    const { fetchImpl, calls } = mockFetch(() => poFor('198.51.100.0/24', 16509, 'AMAZON-02 - Amazon.com, Inc.'));
    const svc = createIpIntel({ fetchImpl });
    const a = await svc.describeNetwork('198.51.100.9/24');
    assert.equal(a.asn, 16509);
    assert.equal(a.shared, true);
    const b = await svc.describeNetwork('198.51.100.200/24'); // same /24 → cache hit
    assert.equal(b.asn, 16509);
    assert.equal(calls.length, 1, 'the second lookup of the same /24 is served from cache');
  });

  test('private / reserved space is never looked up', async () => {
    const { fetchImpl, calls } = mockFetch(() => poFor('10.0.0.0/8', 64500, 'X'));
    const d = await describeNetwork('10.1.2.0/24', { fetchImpl });
    assert.equal(d.private, true);
    assert.equal(d.asn, null);
    assert.equal(calls.length, 0, 'no request for private space');
  });

  test('invalid input is reported, not thrown', async () => {
    const d = await describeNetwork('not-an-ip', { fetchImpl: async () => { throw new Error('should not fetch'); } });
    assert.equal(d.errorKind, 'invalid');
    assert.equal(d.error, 'Invalid IP address or CIDR block');
  });

  test('a lookup failure is reported in error; shared stays null (never blocks the caller)', async () => {
    const fetchImpl = async () => new Response('nope', { status: 503 });
    const d = await describeNetwork('203.0.113.0/24', { fetchImpl });
    assert.equal(d.asn, null);
    assert.equal(d.shared, null);
    assert.match(d.error, /ripestat/i);
  });

  test('abort rejects with an AbortError', async () => {
    const ctl = new AbortController();
    const fetchImpl = async () => { ctl.abort(); await new Promise((r) => setTimeout(r, 5)); return Response.json(poFor('192.0.2.0/24', 1, 'X')); };
    await assert.rejects(describeNetwork('192.0.2.0/24', { fetchImpl, signal: ctl.signal }), (e) => e.name === 'AbortError');
  });
});
