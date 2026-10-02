// Unit tests for assets/js/lib/propagation.js — no network (mock DoH servers).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkPropagation, answerValues, answerAddresses, isFilteredResponse } from '../../assets/js/lib/propagation.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS, ECS_RESOLVERS, GEO_VANTAGES, getResolver } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode, typeToNumber, typeToName } from '../../assets/js/lib/dnswire.js';
import { AbortError } from '../../assets/js/lib/util.js';

const FIX_DIR = new URL('../fixtures/dns/', import.meta.url);
const fixture = (id) => decodeMessage(new Uint8Array(readFileSync(new URL(`${id}.bin`, FIX_DIR))));

function resolverIdOf(url) {
  const r = [...RESOLVERS, ...ECS_RESOLVERS].find((x) => url.startsWith(`${x.url}?`));
  return r ? r.id : new URL(url).host;
}

/**
 * Mock DoH fetch; handler gets { resolver, name, type, ecs, json } and returns a message spec or throws.
 * A JSON-form question (AliDNS: ?name=&type=&edns_client_subnet=) gets the same spec as a JSON answer.
 */
function mockFetch(handler) {
  const calls = [];
  const fetchImpl = async (url) => {
    const params = new URL(url).searchParams;
    if (params.has('name')) {
      const call = { resolver: resolverIdOf(url), name: params.get('name'), type: typeToName(Number(params.get('type'))), ecs: params.get('edns_client_subnet'), json: true };
      calls.push(call);
      const out = await handler(call);
      const rr = (a) => ({ name: `${a.name}.`, type: typeToNumber(a.type), TTL: a.ttl, data: String(a.data) });
      return new Response(JSON.stringify({
        Status: { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3 }[out.rcode || 'NOERROR'], TC: false, RD: true, RA: true, AD: false, CD: false,
        Question: { name: `${call.name}.`, type: typeToNumber(call.type) }, Answer: (out.answers || []).map(rr),
        ...(call.ecs ? { edns_client_subnet: call.ecs } : {})
      }), { headers: { 'content-type': 'application/json' } });
    }
    const query = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns')));
    const q = query.questions[0];
    const call = { resolver: resolverIdOf(url), name: q.name, type: q.type, ecs: query.edns && query.edns.ecs ? query.edns.ecs.subnet : null };
    calls.push(call);
    const out = await handler(call);
    return new Response(encodeMessage({
      id: 0,
      flags: { qr: true, rd: true, ra: true },
      rcode: out.rcode || 'NOERROR',
      questions: [{ name: q.name, type: q.type }],
      answers: out.answers || [],
      edns: out.edns || {}
    }));
  };
  return { fetchImpl, calls };
}

const A = (name, ...ips) => ips.map((data) => ({ name, type: 'A', ttl: 300, data }));
const client = (fetchImpl) => new DohClient({ fetchImpl, baseDelayMs: 1, maxDelayMs: 2, retries: 0 });

/* ------------------------------------------------------------------------ */

describe('answerValues', () => {
  const res = (rcode, answers, name = 'www.example.com') => ({ ok: true, rcode, name, answers });

  test('sorted canonical rdata text of the requested type, without TTLs', () => {
    const r = res('NOERROR', [
      { name: 'www.example.com', type: 'A', typeNum: 1, ttl: 5, text: '192.0.2.9' },
      { name: 'www.example.com', type: 'A', typeNum: 1, ttl: 300, text: '192.0.2.10' },
      { name: 'www.example.com', type: 'A', typeNum: 1, ttl: 300, text: '192.0.2.9' }
    ]);
    assert.deepEqual(answerValues(r, 'A'), ['192.0.2.10', '192.0.2.9']);
  });

  test('CNAME chain appended as "CNAME target" (in chain order) unless type is CNAME', () => {
    const r = res('NOERROR', [
      { name: 'www.example.com', type: 'CNAME', typeNum: 5, data: 'b.cdn.net', text: 'b.cdn.net.' },
      { name: 'b.cdn.net', type: 'CNAME', typeNum: 5, data: 'a.cdn.net', text: 'a.cdn.net.' },
      { name: 'a.cdn.net', type: 'A', typeNum: 1, data: '192.0.2.1', text: '192.0.2.1' }
    ]);
    assert.deepEqual(answerValues(r, 'A'), ['192.0.2.1', 'CNAME b.cdn.net', 'CNAME a.cdn.net']);
    assert.deepEqual(answerValues(r, 'CNAME'), ['a.cdn.net.', 'b.cdn.net.']);
  });

  test('NXDOMAIN, other rcodes, NODATA and errors', () => {
    assert.deepEqual(answerValues(res('NXDOMAIN', []), 'A'), ['NXDOMAIN']);
    assert.deepEqual(answerValues(res('SERVFAIL', []), 'A'), ['SERVFAIL']);
    assert.deepEqual(answerValues(res('NOERROR', []), 'A'), ['NODATA']);
    assert.deepEqual(answerValues({ ok: false, error: 'x' }, 'A'), ['ERROR']);
    assert.deepEqual(answerValues(null, 'A'), ['ERROR']);
  });

  test('real fixtures: MX, TXT (multi-string) and the ECS answer', () => {
    const mx = { ok: true, name: 'google.com', ...fixture('cf-mx-google.com'), rcode: 'NOERROR' };
    assert.deepEqual(answerValues(mx, 'MX'), ['10 smtp.google.com.']);
    const txt = { ok: true, name: '_spf.apple.com', ...fixture('cf-txt-spf-long'), rcode: 'NOERROR' };
    const v = answerValues(txt, 'TXT');
    assert.equal(v.length, 1);
    assert.match(v[0], /^"v=spf1 ip4:17\.151\.62\.66 /);
    const amz = { ok: true, name: 'www.amazon.com', ...fixture('gg-ecs-v4-amazon'), rcode: 'NOERROR' };
    assert.deepEqual(answerValues(amz, 'A'), [
      '65.9.93.124', 'CNAME tp.47cf2c8c9-frontier.amazon.com', 'CNAME cf.47cf2c8c9-frontier.amazon.com'
    ]);
  });

  test('ANY lists every record with its type', () => {
    const r = res('NOERROR', [
      { name: 'x', type: 'A', typeNum: 1, text: '192.0.2.1' },
      { name: 'x', type: 'TXT', typeNum: 16, text: '"hi"' }
    ], 'x');
    assert.deepEqual(answerValues(r, 'ANY'), ['A 192.0.2.1', 'TXT "hi"']);
  });
});

describe('answerAddresses', () => {
  test('canonical A/AAAA of the chain owners, answer order, de-duplicated', () => {
    const r = {
      ok: true, rcode: 'NOERROR', name: 'www.example.com', answers: [
        { name: 'www.example.com', type: 'CNAME', data: 'edge.example.net' },
        { name: 'edge.example.net', type: 'AAAA', data: '2606:4700::1' },
        { name: 'edge.example.net', type: 'A', data: '104.16.1.1' },
        { name: 'edge.example.net', type: 'A', data: '104.16.1.1' },
        { name: 'unrelated.example', type: 'A', data: '192.0.2.99' }
      ]
    };
    assert.deepEqual(answerAddresses(r), ['2606:4700::1', '104.16.1.1']);
    assert.deepEqual(answerAddresses({ ok: true, rcode: 'NXDOMAIN', name: 'x', answers: [] }), []);
    assert.deepEqual(answerAddresses({ ok: false }), []);
    assert.deepEqual(answerAddresses(null), []);
    const amz = { ok: true, name: 'www.amazon.com', ...fixture('gg-ecs-v4-amazon'), rcode: 'NOERROR' };
    assert.deepEqual(answerAddresses(amz), ['65.9.93.124']);
  });
});

describe('isFilteredResponse', () => {
  test('EDE 15–18 or a sinkhole answer from a filtering resolver', () => {
    const blocked = { ok: true, ...fixture('cff-blocked-ede'), rcode: 'NOERROR', ede: [{ code: 16 }] };
    assert.equal(isFilteredResponse(blocked, getResolver('cloudflare-family')), true);
    const sink = { ok: true, rcode: 'NOERROR', ede: [], answers: [{ type: 'A', data: '0.0.0.0' }] };
    assert.equal(isFilteredResponse(sink, getResolver('quad9')), true);
    assert.equal(isFilteredResponse(sink, getResolver('google')), false, 'unfiltered resolver answering 0.0.0.0 is data');
    assert.equal(isFilteredResponse({ ok: false }, getResolver('quad9')), false);
    assert.equal(isFilteredResponse({ ok: true, ede: [{ code: 9 }], answers: [] }), false);
  });
});

/* ------------------------------------------------------------------------ */

describe('checkPropagation', () => {
  test('queries every resolver and vantage; groups identical answers; streams results', async () => {
    const { fetchImpl, calls } = mockFetch(({ resolver, name, ecs }) => {
      if (resolver === 'google' && ecs) {
        // geo answers: Türkiye vantages get the IST edge, everyone else the FRA edge
        const tr = ['78.181.32.0/24', '85.99.192.0/24', '176.41.48.0/24', '31.145.64.0/24'].includes(ecs);
        return { answers: A(name, tr ? '192.0.2.34' : '192.0.2.49'), edns: { ecs: { address: ecs.split('/')[0], sourcePrefix: 24, scopePrefix: tr ? 24 : 16 } } };
      }
      if (resolver === 'iij') return { answers: A(name, '192.0.2.200') }; // stale answer
      return { answers: A(name, '192.0.2.49') };
    });
    const dns = client(fetchImpl);
    const streamed = [];
    const r = await checkPropagation('www.example.com', 'A', { dns, onResult: (item) => streamed.push(item) });

    assert.equal(r.resolverResults.length, RESOLVERS.length);
    assert.equal(r.geoResults.length, GEO_VANTAGES.length);
    assert.equal(calls.length, RESOLVERS.length + GEO_VANTAGES.length);
    assert.equal(streamed.length, calls.length);
    assert.ok(streamed.every((s) => (s.kind === 'resolver' ? s.key.startsWith('resolver:') : s.key.startsWith('geo:'))));

    // input order preserved, definitions attached
    assert.deepEqual(r.resolverResults.map((x) => x.resolver.id), RESOLVERS.map((x) => x.id));
    assert.deepEqual(r.geoResults.map((x) => x.vantage.id), GEO_VANTAGES.map((x) => x.id));
    assert.equal(r.geoResults[0].resolver.id, 'google');
    // Mainland China: AliDNS in its JSON form, with the subnet; it reports no ECS scope.
    const china = r.geoResults.filter((x) => x.vantage.group === 'cn');
    assert.deepEqual(china.map((x) => [x.vantage.id, x.resolver.id, x.resolver.name]), [
      ['cn-bjs-cu', 'alidns', 'AliDNS (ECS)'], ['cn-sha-ct', 'alidns', 'AliDNS (ECS)'], ['cn-can-cm', 'alidns', 'AliDNS (ECS)']]);
    assert.deepEqual(calls.filter((c) => c.json).map((c) => [c.resolver, c.ecs]), china.map((x) => ['alidns', x.vantage.subnet]));
    assert.ok(china.every((x) => x.response.ok && x.scopePrefix === null && x.values.join() === '192.0.2.49'));
    const ist = r.geoResults.find((x) => x.vantage.id === 'tr-ist-tt');
    assert.deepEqual(ist.values, ['192.0.2.34']);
    assert.equal(ist.scopePrefix, 24);
    assert.equal(r.geoResults.find((x) => x.vantage.id === 'jp-tyo').scopePrefix, 16);

    // groups sorted by members desc
    assert.equal(r.groups.length, 3);
    assert.deepEqual(r.groups[0].values, ['192.0.2.49']);
    assert.equal(r.groups[0].members.length, RESOLVERS.length - 1 + GEO_VANTAGES.length - 4);
    assert.deepEqual(r.groups[1].members.sort(), ['geo:tr-ank-tt', 'geo:tr-ist-tt', 'geo:tr-ist-vf', 'geo:tr-izm-sol']);
    assert.deepEqual(r.groups[2].members, ['resolver:iij']);
    assert.ok(r.groups.every((g) => typeof g.key === 'string'));
    assert.equal(r.consistent, false);
    assert.equal(r.resolversConsistent, false);
    assert.equal(r.geoConsistent, false);
    assert.equal(r.type, 'A');

    // worldwide IP summary (extension): most widely returned first, with membership
    assert.deepEqual(r.addresses.map((a) => [a.ip, a.members.length]), [
      ['192.0.2.49', RESOLVERS.length - 1 + GEO_VANTAGES.length - 4], ['192.0.2.34', 4], ['192.0.2.200', 1]
    ]);
    assert.deepEqual(r.addresses[2].members, ['resolver:iij']);
    assert.equal(r.addresses[0].version, 4);
    assert.equal(r.addresses[0].provider, null);
    assert.equal(r.addresses[0].private, false);
    assert.deepEqual(ist.addresses, ['192.0.2.34']);
    assert.ok(streamed.every((s) => Array.isArray(s.addresses)));

    // verdict (extension): direct addresses, one resolver still returns another one
    assert.equal(r.verdict.state, 'differ');
    assert.deepEqual(r.verdict.findings.map((f) => f.code), ['direct']);
    assert.deepEqual(r.verdict.groups.map((g) => g.key), r.groups.map((g) => g.key));
  });

  test('verdict: CDN edges that differ per location are by design', async () => {
    const { fetchImpl } = mockFetch(({ resolver, name, ecs }) => {
      const chain = [{ name, type: 'CNAME', ttl: 60, data: 'd111111abcdef8.cloudfront.net' }];
      if (resolver === 'google' && ecs) return { answers: [...chain, ...A('d111111abcdef8.cloudfront.net', ecs.startsWith('78.') ? '13.32.0.34' : '13.32.0.49')] };
      return { answers: [...chain, ...A('d111111abcdef8.cloudfront.net', resolver === 'iij' ? '13.32.0.200' : '13.32.0.49')] };
    });
    const r = await checkPropagation('www.example.com', 'A', { dns: client(fetchImpl), resolvers: ['cloudflare', 'google', 'iij'], vantages: ['tr-ist-tt', 'de-ham'] });
    assert.equal(r.consistent, false);
    assert.equal(r.verdict.state, 'by-design');
    assert.deepEqual(r.verdict.operators.map((op) => [op.id, op.members.length]), [['cloudfront', 5]]);
  });

  test('address summary classifies providers and skips sinkhole answers', async () => {
    const { fetchImpl } = mockFetch(({ resolver, name }) => {
      if (resolver === 'quad9') return { answers: A(name, '0.0.0.0') };
      if (resolver === 'google') return { answers: [...A(name, '104.16.132.229'), { name, type: 'AAAA', ttl: 300, data: '2606:4700::6810:84e5' }] };
      return { answers: A(name, '104.16.132.229', '10.1.2.3') };
    });
    const r = await checkPropagation('cf.example', 'A', { dns: client(fetchImpl), resolvers: ['cloudflare', 'google', 'quad9'], vantages: [] });
    assert.deepEqual(r.addresses.map((a) => a.ip), ['104.16.132.229', '10.1.2.3', '2606:4700::6810:84e5']);
    assert.equal(r.addresses[2].provider.id, 'cloudflare');
    assert.equal(r.addresses[0].provider.id, 'cloudflare');
    assert.equal(r.addresses[1].private, true);
    assert.equal(r.resolverResults[2].filtered, true);
    assert.deepEqual(r.resolverResults[2].addresses, ['0.0.0.0']);
  });

  test('resolver and vantage subsets; ids or objects; geo off with vantages: []', async () => {
    const { fetchImpl, calls } = mockFetch(({ name }) => ({ answers: A(name, '192.0.2.1') }));
    const dns = client(fetchImpl);
    const r = await checkPropagation('example.com', 'A', {
      dns, resolvers: ['cloudflare', 'google'], vantages: ['tr-ist-tt', GEO_VANTAGES.find((v) => v.id === 'us-east'), 'nope']
    });
    assert.deepEqual(r.resolverResults.map((x) => x.key), ['resolver:cloudflare', 'resolver:google']);
    assert.deepEqual(r.geoResults.map((x) => x.key), ['geo:tr-ist-tt', 'geo:us-east']);
    assert.equal(r.consistent, true);
    assert.equal(r.groups.length, 1);
    assert.equal(calls.filter((c) => c.ecs).length, 2);
    assert.ok(calls.filter((c) => c.ecs).every((c) => c.resolver === 'google'));

    const { fetchImpl: f2, calls: c2 } = mockFetch(({ name }) => ({ answers: A(name, '192.0.2.1') }));
    const r2 = await checkPropagation('example.com', 'A', { dns: client(f2), resolvers: ['dnssb'], vantages: [] });
    assert.equal(r2.geoResults.length, 0);
    assert.equal(c2.length, 1);
  });

  test('geoResolver can be switched (e.g. quad9-ecs); always fresh (noCache)', async () => {
    const { fetchImpl, calls } = mockFetch(({ name }) => ({ answers: A(name, '192.0.2.1') }));
    const dns = client(fetchImpl);
    await checkPropagation('example.com', 'A', { dns, resolvers: [], vantages: ['de-ham'], geoResolver: 'quad9-ecs' });
    await checkPropagation('example.com', 'A', { dns, resolvers: [], vantages: ['de-ham'], geoResolver: 'quad9-ecs' });
    assert.deepEqual(calls.map((c) => [c.resolver, c.ecs]), [['quad9-ecs', '79.208.0.0/24'], ['quad9-ecs', '79.208.0.0/24']]);
  });

  test('errors and filtered answers do not make the result inconsistent', async () => {
    const { fetchImpl } = mockFetch(({ resolver, name }) => {
      if (resolver === 'quad9' || resolver === 'quad9-ecs') throw new TypeError('Failed to fetch');
      if (resolver === 'cloudflare-family') return { answers: A(name, '0.0.0.0'), edns: { ede: [{ code: 16, text: '' }] } };
      if (resolver === 'cleanbrowsing') return { rcode: 'NXDOMAIN', edns: { ede: [{ code: 17, text: 'filtered' }] } };
      return { answers: A(name, '192.0.2.66') };
    });
    const r = await checkPropagation('malware.example', 'A', { dns: client(fetchImpl), vantages: [] });
    assert.equal(r.consistent, true);
    const errGroup = r.groups.find((g) => g.error);
    assert.deepEqual(errGroup.members.sort(), ['resolver:quad9', 'resolver:quad9-ecs']);
    assert.deepEqual(errGroup.values, ['ERROR']);
    const fam = r.resolverResults.find((x) => x.resolver.id === 'cloudflare-family');
    assert.equal(fam.filtered, true);
    assert.equal(r.groups.find((g) => g.members.includes('resolver:cleanbrowsing')).filtered, true);
    assert.equal(r.groups[0].filtered, false);
  });

  test('every resolver failing is not "consistent"', async () => {
    const { fetchImpl } = mockFetch(() => { throw new TypeError('offline'); });
    const r = await checkPropagation('example.com', 'A', { dns: client(fetchImpl), resolvers: ['cloudflare', 'google'], vantages: [] });
    assert.equal(r.consistent, false);
    assert.equal(r.groups.length, 1);
    assert.equal(r.groups[0].error, true);
  });

  test('NXDOMAIN everywhere is consistent; mixed NXDOMAIN / answer is not', async () => {
    const { fetchImpl } = mockFetch(() => ({ rcode: 'NXDOMAIN' }));
    const r = await checkPropagation('gone.example.com', 'A', { dns: client(fetchImpl), resolvers: ['cloudflare', 'google', 'dnssb'], vantages: [] });
    assert.equal(r.consistent, true);
    assert.deepEqual(r.groups[0].values, ['NXDOMAIN']);

    const { fetchImpl: f2 } = mockFetch(({ resolver, name }) => (resolver === 'google' ? { rcode: 'NXDOMAIN' } : { answers: A(name, '192.0.2.1') }));
    const r2 = await checkPropagation('new.example.com', 'A', { dns: client(f2), resolvers: ['cloudflare', 'google', 'dnssb'], vantages: [] });
    assert.equal(r2.consistent, false);
    assert.deepEqual(r2.groups.map((g) => g.members.length), [2, 1]);
  });

  test('a throwing onResult callback does not break the check', async () => {
    const { fetchImpl } = mockFetch(({ name }) => ({ answers: A(name, '192.0.2.1') }));
    const r = await checkPropagation('example.com', 'A', {
      dns: client(fetchImpl), resolvers: ['cloudflare'], vantages: [], onResult: () => { throw new Error('ui bug'); }
    });
    assert.equal(r.resolverResults.length, 1);
  });

  test('requires a dns client; honours AbortSignal', async () => {
    await assert.rejects(checkPropagation('example.com', 'A', {}), TypeError);
    const ctl = new AbortController();
    ctl.abort();
    const { fetchImpl, calls } = mockFetch(({ name }) => ({ answers: A(name, '192.0.2.1') }));
    await assert.rejects(checkPropagation('example.com', 'A', { dns: client(fetchImpl), signal: ctl.signal }), (e) => e instanceof AbortError);
    assert.equal(calls.length, 0);

    const hang = new DohClient({ fetchImpl: () => new Promise(() => {}), timeoutMs: 60_000 });
    const c2 = new AbortController();
    const p = checkPropagation('example.com', 'A', { dns: hang, signal: c2.signal });
    setTimeout(() => c2.abort(), 10);
    await assert.rejects(p, (e) => e instanceof AbortError);
  });
});
