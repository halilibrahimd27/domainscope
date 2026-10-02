// Unit tests for lib/propagation.js propagationVerdict — why Global DNS answers differ:
// CDN / GeoDNS edges by design, or propagation / a misconfiguration. No network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { propagationVerdict, splitChain, SAFE_SEARCH_TARGETS, VERDICT_FINDINGS, VERDICT_STATES } from '../../assets/js/lib/propagation.js';
import { getResolver } from '../../assets/js/lib/resolvers.js';

/** One answer item as checkPropagation / the view produce it: values = answerValues(). */
const item = (key, ...values) => ({ key, values });
const cname = (...targets) => targets.map((x) => `CNAME ${x}`);
const ids = (ops) => ops.map((op) => op.id);
const codes = (v) => v.findings.map((f) => f.code);

// CloudFront (published ranges, IPv4 + IPv6), Cloudflare, and Akamai edges (no published
// ranges: recognised by the *.edgekey.net / *.akamaiedge.net CNAME, addresses from 2.16.0.0/13).
const CF_A = ['13.32.0.1', '13.32.0.2', '13.32.0.3', '13.32.0.4'];
const CF_AAAA = ['2600:9000:2000::1', '2600:9000:2000::2', '2600:9000:2000::3'];
const STEER = cname('tp.frontier.example.com');

describe('propagationVerdict', () => {
  test('exports its states and finding codes', () => {
    assert.deepEqual(VERDICT_STATES, ['none', 'unresolved', 'agree', 'by-design', 'geo', 'differ']);
    assert.deepEqual(VERDICT_FINDINGS, ['rcode', 'nxdomain', 'nodata', 'private', 'mixed', 'cname', 'operators', 'direct', 'records']);
    assert.deepEqual(splitChain(['192.0.2.1', 'CNAME a.example.net', 'CNAME b.example.net']), { plain: ['192.0.2.1'], chain: ['a.example.net', 'b.example.net'] });
  });

  test('all CDN edges (CloudFront + Akamai behind one steering name): differs by design', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', CF_A[0], ...STEER, ...cname('cf.frontier.example.com')),
      item('resolver:google', CF_A[1], ...STEER, ...cname('cf.frontier.example.com')),
      item('geo:tr-ist-tt', CF_A[2], ...STEER, ...cname('cf.frontier.example.com')),
      item('geo:de-ham', CF_A[2], ...STEER, ...cname('cf.frontier.example.com')),
      item('geo:za-jnb', '2.16.1.10', ...STEER, ...cname('www.example.com.edgekey.net', 'e1.dsca.akamaiedge.net'))
    ], { type: 'A' });
    assert.equal(v.state, 'by-design');
    assert.equal(v.type, 'A');
    assert.deepEqual(ids(v.operators), ['cloudfront', 'akamai'], 'most sources first');
    assert.deepEqual(v.operators.map((op) => op.members.length), [4, 1]);
    assert.deepEqual(v.operators.map((op) => op.via), ['ip', 'cname']);
    assert.equal(v.operators[0].name, 'Amazon CloudFront');
    assert.equal(v.multiOperator, true);
    assert.deepEqual(v.findings, []);
    assert.equal(v.resolversAgree, false);
    assert.equal(v.groups.length, 4);
    assert.deepEqual(v.groups[0].members, ['geo:tr-ist-tt', 'geo:de-ham'], 'largest group first');
    assert.ok(v.groups.every((g) => g.managed && g.status === 'answer'));
    const ak = v.groups.find((g) => g.members.includes('geo:za-jnb'));
    assert.deepEqual(ak.chain, ['tp.frontier.example.com', 'www.example.com.edgekey.net', 'e1.dsca.akamaiedge.net']);
    assert.deepEqual(ak.addresses, ['2.16.1.10']);
    assert.deepEqual(ids(ak.operators), ['akamai']);
    assert.equal(ak.operators[0].kind, 'cdn');
    assert.equal(ak.operators[0].reasonKey, 'class.cdn.cname');
  });

  test('a single operator handing out many addresses', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', '104.16.1.1', '104.16.1.2'),
      item('resolver:google', '104.16.2.1', '104.16.2.2'),
      item('resolver:dnssb', '104.16.3.1', '104.16.3.2'),
      item('geo:us-east', '172.64.1.1', '172.64.1.2')
    ]);
    assert.equal(v.state, 'by-design');
    assert.deepEqual(ids(v.operators), ['cloudflare']);
    assert.equal(v.operators[0].kind, 'cloudflare');
    assert.equal(v.operators[0].members.length, 4);
    assert.equal(v.multiOperator, false);
    assert.ok(v.groups.every((g) => g.operators.length === 1 && g.operators[0].id === 'cloudflare'));
  });

  test('AAAA: IPv6 edges differ by design; an empty AAAA answer next to them does not', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', CF_AAAA[0]),
      item('resolver:google', CF_AAAA[1]),
      item('geo:jp-tyo', CF_AAAA[2])
    ], { type: 'AAAA' });
    assert.equal(v.state, 'by-design');
    assert.equal(v.type, 'AAAA');
    assert.deepEqual(ids(v.operators), ['cloudfront']);
    assert.deepEqual(v.groups[0].addresses, [CF_AAAA[0]]);

    const empty = propagationVerdict([
      item('resolver:cloudflare', CF_AAAA[0]),
      item('resolver:google', CF_AAAA[1]),
      item('resolver:dnssb', 'NODATA')
    ], { type: 28 });
    assert.equal(empty.type, 'AAAA');
    assert.equal(empty.state, 'differ');
    assert.deepEqual(codes(empty), ['nodata']);
    assert.deepEqual(empty.findings[0].members, ['resolver:dnssb']);
    assert.equal(empty.designPart, true, 'the two CloudFront answers are still by design');
  });

  test('CNAME to a CDN: addresses outside any published range are edges through the chain', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.10', ...cname('www.example.com.edgekey.net', 'e2.a.akamaiedge.net')),
      item('resolver:google', '192.0.2.11', ...cname('www.example.com.edgekey.net', 'e2.a.akamaiedge.net')),
      item('geo:br-sao', '198.51.100.12', ...cname('www.example.com.edgekey.net', 'e2.b.akamaiedge.net'))
    ]);
    assert.equal(v.state, 'by-design');
    assert.deepEqual(ids(v.operators), ['akamai']);
    assert.ok(v.groups.every((g) => g.operators[0].via === 'cname'));
  });

  test('a CNAME that differs before the CDN is a propagating change, not steering', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', CF_A[0], ...cname('old.example.net', 'd111111abcdef8.cloudfront.net')),
      item('resolver:google', CF_A[1], ...cname('new.example.net', 'd222222abcdef8.cloudfront.net')),
      item('resolver:dnssb', CF_A[1], ...cname('new.example.net', 'd222222abcdef8.cloudfront.net'))
    ]);
    assert.equal(v.state, 'differ');
    assert.deepEqual(codes(v), ['cname']);
    const f = v.findings[0];
    assert.equal(f.owner, null, 'the queried name itself');
    assert.deepEqual(f.targets, ['new.example.net', 'old.example.net'], 'most sources first');
    assert.equal(f.groups.length, 2);
    assert.deepEqual(f.members.sort(), ['resolver:cloudflare', 'resolver:dnssb', 'resolver:google']);
    assert.equal(v.designPart, false);

    // Deeper in the chain, among direct answers: the owner is the name whose record differs.
    const deep = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1', ...cname('lb.example.com', 'a.example.net')),
      item('resolver:google', '198.51.100.1', ...cname('lb.example.com', 'b.example.net'))
    ]);
    assert.deepEqual(deep.findings.map((x) => [x.code, x.owner, x.targets]), [['cname', 'lb.example.com', ['a.example.net', 'b.example.net']]]);

    // Two properties of the same CDN (distributions) at the queried name: a change, not
    // steering; behind the entry name the CDN's own names may differ.
    const dist = propagationVerdict([
      item('resolver:cloudflare', CF_A[0], ...cname('d111111abcdef8.cloudfront.net')),
      item('resolver:google', CF_A[1], ...cname('d222222abcdef8.cloudfront.net'))
    ]);
    assert.deepEqual(dist.findings.map((x) => [x.code, x.owner, x.targets]), [['cname', null, ['d111111abcdef8.cloudfront.net', 'd222222abcdef8.cloudfront.net']]]);
    const akamai = propagationVerdict([
      item('resolver:cloudflare', '2.16.1.10', ...cname('www.example.com.edgekey.net', 'e1.a.akamaiedge.net')),
      item('resolver:google', '2.16.1.11', ...cname('www.example.com.edgekey.net', 'e1.b.akamaiedge.net'))
    ]);
    assert.equal(akamai.state, 'by-design');
    const moved = propagationVerdict([
      item('resolver:cloudflare', '2.16.1.10', ...cname('www.example.com.edgesuite.net', 'a1.g.akamai.net')),
      item('resolver:google', '2.16.1.11', ...cname('www.example.com.edgekey.net', 'e1.b.akamaiedge.net'))
    ]);
    assert.deepEqual(codes(moved), ['cname']);
    // Regional load balancers of one platform behind latency routing: by design.
    const regional = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.10', ...cname('web-eu-1.eu-west-1.elb.amazonaws.com')),
      item('geo:us-east', '198.51.100.10', ...cname('web-us-1.us-east-1.elb.amazonaws.com'))
    ]);
    assert.equal(regional.state, 'by-design');
    assert.deepEqual(ids(regional.operators), ['aws-elb']);

    // Address records on one side, a CNAME on the other (null = address records).
    const flip = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1'),
      item('resolver:google', '198.51.100.1', ...cname('host.example.net'))
    ]);
    assert.deepEqual(flip.findings.map((x) => [x.code, x.owner, x.targets]), [['cname', null, [null, 'host.example.net']]]);
  });

  test('mixed CDN and direct: the direct addresses are named, the edge part stays by design', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', '104.16.1.1'),
      item('resolver:google', '104.16.1.2'),
      item('resolver:iij', '203.0.113.10'),
      item('geo:tr-ist-tt', '203.0.113.10')
    ]);
    assert.equal(v.state, 'differ');
    assert.deepEqual(codes(v), ['mixed']);
    assert.deepEqual(v.findings[0].ips, ['203.0.113.10']);
    assert.deepEqual(v.findings[0].groups, ['203.0.113.10']);
    assert.deepEqual(v.findings[0].members, ['resolver:iij', 'geo:tr-ist-tt']);
    assert.equal(v.designPart, true);
    assert.deepEqual(ids(v.operators), ['cloudflare']);
    const direct = v.groups.find((g) => g.key === '203.0.113.10');
    assert.equal(direct.managed, false);
    assert.deepEqual(direct.operators.map((op) => [op.id, op.kind, op.name]), [['direct', 'direct', null]]);

    // A record set that mixes an edge with a direct address is flagged the same way.
    const set = propagationVerdict([item('resolver:cloudflare', '104.16.1.1', '203.0.113.20'), item('resolver:google', '104.16.1.3')]);
    assert.deepEqual(set.findings.map((f) => [f.code, f.ips]), [['mixed', ['203.0.113.20']]]);
    assert.deepEqual(ids(set.groups[0].operators), ['cloudflare', 'direct']);
  });

  test('NXDOMAIN or SERVFAIL on some resolvers is never by design', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', CF_A[0]),
      item('resolver:google', CF_A[1]),
      item('resolver:iij', 'NXDOMAIN'),
      item('resolver:cznic', 'NXDOMAIN'),
      item('resolver:dnssb', 'SERVFAIL')
    ]);
    assert.equal(v.state, 'differ');
    assert.deepEqual(codes(v), ['rcode', 'nxdomain']);
    assert.equal(v.findings[0].rcode, 'SERVFAIL');
    assert.deepEqual(v.findings[0].members, ['resolver:dnssb']);
    assert.deepEqual(v.findings[1].members, ['resolver:iij', 'resolver:cznic']);
    assert.deepEqual(v.findings[1].groups, ['NXDOMAIN']);
    assert.equal(v.designPart, true);
    assert.deepEqual(v.groups.map((g) => g.status), ['nxdomain', 'answer', 'answer', 'rcode']);
    assert.deepEqual(v.groups[0].operators, []);

    // NXDOMAIN only at some locations while the resolvers agree: still a warning, not "geo".
    const geo = propagationVerdict([item('resolver:cloudflare', '192.0.2.1'), item('resolver:google', '192.0.2.1'), item('geo:jp-tyo', 'NXDOMAIN')]);
    assert.equal(geo.state, 'differ');
    assert.deepEqual(codes(geo), ['nxdomain']);
  });

  test('private addresses and a CNAME chain without addresses', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1'),
      item('resolver:google', '10.0.0.5'),
      item('resolver:dnssb', ...cname('gone.example.net'))
    ]);
    assert.equal(v.state, 'differ');
    assert.deepEqual(codes(v), ['nodata', 'private']);
    assert.deepEqual(v.findings[1].ips, ['10.0.0.5']);
    assert.equal(v.groups.find((g) => g.members.includes('resolver:dnssb')).status, 'nodata');
    assert.equal(v.groups.find((g) => g.key === '10.0.0.5').operators[0].kind, 'private');
    // A private address is never an edge, even behind a CDN's CNAME.
    const cdn = propagationVerdict([
      item('resolver:cloudflare', '2.16.1.10', ...cname('www.example.com.edgekey.net', 'e1.a.akamaiedge.net')),
      item('resolver:google', '10.0.0.5', ...cname('www.example.com.edgekey.net', 'e1.a.akamaiedge.net'))
    ]);
    assert.deepEqual([cdn.state, codes(cdn), cdn.findings[0].ips], ['differ', ['private'], ['10.0.0.5']]);
  });

  test('direct addresses: resolvers that disagree look like propagation; only locations differing is GeoDNS', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1'),
      item('resolver:google', '192.0.2.1'),
      item('resolver:iij', '198.51.100.1')
    ]);
    assert.equal(v.state, 'differ');
    assert.deepEqual(codes(v), ['direct']);
    assert.equal(v.findings[0].groups.length, 2);
    assert.deepEqual(v.operators, []);

    const geo = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1'),
      { key: 'resolver:google', kind: 'resolver', values: ['192.0.2.1'] },
      { key: 'x', kind: 'geo', values: ['198.51.100.1'] },
      item('geo:jp-tyo', '203.0.113.1')
    ]);
    assert.equal(geo.state, 'geo');
    assert.equal(geo.resolversAgree, true);
    assert.deepEqual(geo.findings, []);
  });

  test('DNS-level steering (Azure Traffic Manager) picks direct endpoints by design', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1', ...cname('app.trafficmanager.net', 'eu.example.net')),
      item('resolver:google', '198.51.100.1', ...cname('app.trafficmanager.net', 'us.example.net'))
    ]);
    assert.equal(v.state, 'by-design');
    assert.deepEqual(ids(v.operators), ['azure-trafficmanager']);
    assert.equal(v.operators[0].steering, true);
    assert.equal(v.operators[0].kind, 'direct', 'the answers are the customer\'s endpoints');
  });

  test('already fetched PTR / ASN data turns a "direct" address into a known edge', () => {
    const items = [item('resolver:cloudflare', '192.0.2.1'), item('resolver:google', '192.0.2.2')];
    assert.equal(propagationVerdict(items).state, 'differ');
    const byPtr = propagationVerdict(items, {
      ipInfo: new Map([
        ['192.0.2.1', { ptr: ['a192-0-2-1.deploy.static.akamaitechnologies.com'] }],
        ['192.0.2.2', { ptr: ['a192-0-2-2.deploy.static.akamaitechnologies.com'] }]
      ])
    });
    assert.equal(byPtr.state, 'by-design');
    assert.deepEqual(byPtr.operators.map((op) => [op.id, op.via, op.reasonKey]), [['akamai', 'ptr', 'class.cdn.ip']]);
    const byAsn = propagationVerdict(items, { ipInfo: { '192.0.2.1': { asn: 20940 }, '192.0.2.2': { asns: [{ asn: 16625 }] } } });
    assert.equal(byAsn.state, 'by-design');
    assert.deepEqual(byAsn.operators.map((op) => [op.id, op.via]), [['akamai', 'asn']]);
    // A Cloudflare AS address outside the proxy ranges (its resolver, say) is not an edge.
    const outside = propagationVerdict(items, { ipInfo: { '192.0.2.1': { asn: 13335 }, '192.0.2.2': { asn: 13335 } } });
    assert.equal(outside.state, 'differ');
    assert.deepEqual(codes(outside), ['direct']);
  });

  test('other record types: records differ, NXDOMAIN; no operator judgement', () => {
    const mx = propagationVerdict([
      item('resolver:cloudflare', '10 mx1.example.com.'),
      item('resolver:google', '10 mx2.example.com.')
    ], { type: 'MX' });
    assert.equal(mx.state, 'differ');
    assert.deepEqual(codes(mx), ['records']);
    assert.ok(mx.groups.every((g) => g.operators.length === 0 && g.addresses.length === 0));
    const geo = propagationVerdict([
      item('resolver:cloudflare', '10 mx1.example.com.'),
      item('geo:jp-tyo', '10 mx2.example.com.')
    ], { type: 'MX' });
    assert.equal(geo.state, 'geo');
    const nx = propagationVerdict([item('resolver:cloudflare', '10 mx1.example.com.'), item('resolver:google', 'NXDOMAIN')], { type: 'MX' });
    assert.deepEqual(codes(nx), ['nxdomain']);
  });

  test('a SafeSearch rewrite only filtering resolvers give is their policy, not a difference', () => {
    const row = (id, ...values) => ({ key: `resolver:${id}`, kind: 'resolver', resolver: getResolver(id), values });
    // Cloudflare Family answers www.google.com with CNAME forcesafesearch.google.com.
    const safe = ['192.0.2.99', ...cname('forcesafesearch.google.com')];
    const v = propagationVerdict([
      row('cloudflare', '192.0.2.1'),
      row('google', '192.0.2.1'),
      row('cloudflare-family', ...safe),
      row('cleanbrowsing', ...safe),
      { key: 'geo:de-ham', kind: 'geo', resolver: getResolver('quad9-ecs'), values: ['192.0.2.1'] }
    ]);
    assert.equal(v.state, 'agree');
    assert.deepEqual(v.rewritten, ['resolver:cloudflare-family', 'resolver:cleanbrowsing']);
    assert.deepEqual(v.rewriteTargets, ['forcesafesearch.google.com']);
    assert.deepEqual(v.groups.map((g) => g.rewritten), [false, true]);
    assert.deepEqual(v.findings, []);
    assert.ok(SAFE_SEARCH_TARGETS.includes('strict.bing.com') && SAFE_SEARCH_TARGETS.includes('safe.duckduckgo.com'));
    // Deeper in the chain (an alias of www.google.com), or as the record of a CNAME query.
    const deep = propagationVerdict([row('cloudflare', '192.0.2.1', ...cname('www.google.com')), row('cloudflare-family', '192.0.2.99', ...cname('www.google.com', 'forcesafesearch.google.com.'))]);
    assert.deepEqual([deep.state, deep.rewriteTargets], ['agree', ['forcesafesearch.google.com']]);
    const q = propagationVerdict([row('cloudflare', 'www.example.net.'), row('cloudflare-family', 'safe.duckduckgo.com.')], { type: 'CNAME' });
    assert.deepEqual([q.state, q.rewritten], ['agree', ['resolver:cloudflare-family']]);

    // A location (even through a filtering ECS resolver) or an unfiltered resolver giving it
    // too makes it an ordinary answer again.
    const geo = propagationVerdict([
      row('cloudflare', '192.0.2.1'),
      row('cloudflare-family', ...safe),
      { key: 'geo:de-ham', kind: 'geo', resolver: getResolver('quad9-ecs'), values: ['198.51.100.2'] }
    ]);
    assert.deepEqual(geo.rewritten, ['resolver:cloudflare-family']);
    assert.equal(geo.state, 'geo', 'the resolvers left agree; only the location differs');
    const shared = propagationVerdict([row('cloudflare', '192.0.2.1'), row('google', ...safe), row('cloudflare-family', ...safe)]);
    assert.deepEqual(shared.rewritten, []);
    assert.equal(shared.state, 'differ');
    // Only filtering resolvers answered: nothing to compare with, so their answers are judged.
    const alone = propagationVerdict([row('cloudflare-family', ...safe), row('cleanbrowsing', '198.51.100.1')]);
    assert.deepEqual(alone.rewritten, []);
    assert.equal(alone.state, 'differ');
  });

  test('any other answer only filtering resolvers give stays a difference (a stale cache looks the same)', () => {
    const row = (id, ...values) => ({ key: `resolver:${id}`, kind: 'resolver', resolver: getResolver(id), values });
    const rest = (...values) => [
      row('cloudflare', ...values), row('google', ...values), row('dnssb', ...values),
      { key: 'geo:de-ham', kind: 'geo', resolver: getResolver('google'), values }
    ];
    // Quad9 still returns the old address.
    const quad9 = propagationVerdict([...rest('198.51.100.20'), row('quad9', '192.0.2.10')]);
    assert.equal(quad9.state, 'differ');
    assert.deepEqual(codes(quad9), ['direct']);
    assert.deepEqual(quad9.rewritten, []);
    assert.ok(quad9.groups.every((g) => !g.rewritten));
    // A new name that Cloudflare Family still has cached as NXDOMAIN.
    const family = propagationVerdict([...rest('198.51.100.20'), row('cloudflare-family', 'NXDOMAIN')]);
    assert.equal(family.state, 'differ');
    assert.deepEqual(codes(family), ['nxdomain']);
    assert.deepEqual(family.findings[0].members, ['resolver:cloudflare-family']);
    assert.equal(family.findings[0].filtering, true, 'only filtering resolvers give it: it may also be their block');
    // CleanBrowsing still has the old CNAME to an ordinary name.
    const clean = propagationVerdict([...rest('198.51.100.20', ...cname('new.example.net')), row('cleanbrowsing', '192.0.2.10', ...cname('old.example.net'))]);
    assert.equal(clean.state, 'differ');
    assert.deepEqual(clean.findings.map((f) => [f.code, f.owner, f.targets]), [['cname', null, ['new.example.net', 'old.example.net']]]);
    // A CloudFront distribution change that only Quad9 has not seen yet.
    const dist = propagationVerdict([
      ...rest(CF_A[0], ...cname('d222222abcdef8.cloudfront.net')),
      row('quad9', CF_A[1], ...cname('d111111abcdef8.cloudfront.net'))
    ]);
    assert.equal(dist.state, 'differ');
    assert.deepEqual(codes(dist), ['cname']);
    // Just another edge from a filtering resolver's own cache: an ordinary, by-design answer.
    const edge = propagationVerdict([row('cloudflare', CF_A[0]), row('google', CF_A[1]), row('cleanbrowsing', CF_A[2])]);
    assert.equal(edge.state, 'by-design');
    // NXDOMAIN from an unfiltered resolver too: not only a filtering resolver's answer.
    const both = propagationVerdict([...rest('198.51.100.20'), row('quad9', 'NXDOMAIN'), row('iij', 'NXDOMAIN')]);
    assert.equal(both.findings[0].filtering, false);
  });

  test('different operators at the queried name are a move between providers, not steering', () => {
    // Netlify → Vercel at the apex: only address records, each on its platform's address.
    const apex = propagationVerdict([
      item('resolver:cloudflare', '76.76.21.21'),
      item('resolver:google', '76.76.21.21'),
      item('resolver:iij', '75.2.60.5')
    ]);
    assert.equal(apex.state, 'differ');
    assert.deepEqual(codes(apex), ['operators']);
    assert.deepEqual(ids(apex.findings[0].operators), ['vercel', 'netlify']);
    assert.equal(apex.findings[0].groups.length, 2);
    assert.equal(apex.designPart, false);
    // Cloudflare edges vs CloudFront edges at the apex.
    const edges = propagationVerdict([item('resolver:cloudflare', '104.16.1.1'), item('resolver:google', CF_A[0])]);
    assert.deepEqual(codes(edges), ['operators']);
    // CloudFront → Cloudflare by CNAME at the queried name.
    const moved = propagationVerdict([
      item('resolver:cloudflare', CF_A[0], ...cname('d111111abcdef8.cloudfront.net')),
      item('resolver:google', '104.16.1.1', ...cname('www.example.com.cdn.cloudflare.net')),
      item('geo:de-ham', '104.16.1.1', ...cname('www.example.com.cdn.cloudflare.net'))
    ]);
    assert.equal(moved.state, 'differ');
    assert.deepEqual(moved.findings.map((f) => [f.code, f.owner, f.targets]), [['cname', null, ['www.example.com.cdn.cloudflare.net', 'd111111abcdef8.cloudfront.net']]]);
    assert.deepEqual(ids(moved.findings[0].operators), ['cloudflare', 'cloudfront']);
    // Heroku → Vercel, and a direct CNAME to a CDN next to one through the customer's own name.
    const platforms = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.10', ...cname('foo.herokuapp.com')),
      item('resolver:google', '76.76.21.21', ...cname('cname.vercel-dns.com'))
    ]);
    assert.deepEqual(platforms.findings.map((f) => [f.code, ids(f.operators)]), [['cname', ['heroku', 'vercel']]]);
    const via = propagationVerdict([
      item('resolver:cloudflare', CF_A[0], ...cname('d111111abcdef8.cloudfront.net')),
      item('resolver:google', '2.16.1.10', ...cname('lb.example.com', 'www.example.com.edgekey.net', 'e1.a.akamaiedge.net'))
    ]);
    assert.deepEqual(via.findings.map((f) => [f.code, f.owner]), [['cname', null]]);

    // One platform, another site: old-site.netlify.app → new-site.netlify.app, GitHub Pages
    // users, Heroku apps, S3 buckets. The same operator, so no provider list.
    for (const [a, b] of [
      ['old-site.netlify.app', 'new-site.netlify.app'],
      ['olduser.github.io', 'newuser.github.io'],
      ['old-app.herokudns.com', 'new-app.herokudns.com'],
      ['old-bucket.s3.amazonaws.com', 'new-bucket.s3.amazonaws.com']
    ]) {
      const v = propagationVerdict([item('resolver:cloudflare', '192.0.2.10', ...cname(a)), item('resolver:google', '192.0.2.11', ...cname(b))]);
      assert.equal(v.state, 'differ', `${a} vs ${b}`);
      assert.deepEqual(v.findings.map((f) => [f.code, f.owner, f.targets, f.operators.length]), [['cname', null, [a, b], 0]], `${a} vs ${b}`);
    }

    // www.amazon.com: every source shares tp.…frontier.amazon.com, which steers to CloudFront
    // (by address) or Akamai (edgekey.net): by design.
    const tp = 'tp.47cf2c8c9-frontier.example.com';
    const amazon = propagationVerdict([
      item('resolver:cloudflare', CF_A[0], ...cname(tp, 'cf.47cf2c8c9-frontier.example.com')),
      item('resolver:google', CF_A[1], ...cname(tp, 'cf.47cf2c8c9-frontier.example.com')),
      item('geo:tr-ist-tt', '2.17.225.198', ...cname(tp, 'www.example.com.edgekey.net', 'e15316.dsca.akamaiedge.net')),
      item('geo:br-sao', '2.17.225.199', ...cname(tp, 'www.example.com.edgekey.net', 'e15316.dscb.akamaiedge.net'))
    ]);
    assert.equal(amazon.state, 'by-design');
    assert.deepEqual(ids(amazon.operators), ['cloudfront', 'akamai']);
    // The same answers, but the Akamai side no longer shares the steering name: a move.
    const unshared = propagationVerdict([
      item('resolver:cloudflare', CF_A[0], ...cname(tp, 'cf.47cf2c8c9-frontier.example.com')),
      item('resolver:google', '2.17.225.198', ...cname('www.example.com.edgekey.net', 'e15316.dsca.akamaiedge.net'))
    ]);
    assert.deepEqual(unshared.findings.map((f) => [f.code, f.owner, ids(f.operators)]), [['cname', null, ['cloudfront', 'akamai']]]);
    // Only a location gets the other provider while the resolvers agree: GeoDNS by CNAME.
    const located = propagationVerdict([
      item('resolver:cloudflare', CF_A[0], ...cname(tp, 'cf.47cf2c8c9-frontier.example.com')),
      item('resolver:google', CF_A[0], ...cname(tp, 'cf.47cf2c8c9-frontier.example.com')),
      item('geo:tr-ist-tt', '2.17.225.198', ...cname('www.example.com.edgekey.net', 'e15316.dsca.akamaiedge.net'))
    ]);
    assert.deepEqual([located.state, located.findings], ['geo', []]);
  });

  test('weighted records before one CDN entry name are steering in the name’s own DNS, not a change', () => {
    // www.etsy.com: zone1 / zone2 (Google alternates query by query) → the same Fastly name.
    const zones = propagationVerdict([
      item('resolver:cloudflare', '151.101.1.52', ...cname('zone1.www.example.com', 'h3.example.map.fastly.net')),
      item('resolver:google', '151.101.65.52', ...cname('zone2.www.example.com', 'h3.example.map.fastly.net')),
      item('resolver:dnssb', '151.101.1.52', ...cname('zone2.www.example.com', 'h3.example.map.fastly.net'))
    ]);
    assert.equal(zones.state, 'by-design');
    assert.deepEqual(zones.findings, []);
    assert.deepEqual(ids(zones.operators), ['fastly']);
    assert.deepEqual(zones.steering, [{ owner: null, targets: ['zone1.www.example.com', 'zone2.www.example.com'] }]);
    // Straight to the entry name on one side, through a zone name on the other.
    const hop = propagationVerdict([
      item('resolver:cloudflare', '151.101.1.52', ...cname('h3.example.map.fastly.net')),
      item('resolver:google', '151.101.65.52', ...cname('zone2.www.example.com', 'h3.example.map.fastly.net'))
    ]);
    assert.equal(hop.state, 'by-design');
    // www.pinterest.com: gslb / gslb2 each steer to Akamai or Fastly — the same entry names.
    const gslb = (n, ...rest) => cname('www.gslb.example.com', `www.${n}.example.net`, ...rest);
    const pin = propagationVerdict([
      item('resolver:cloudflare', '2.16.1.10', ...gslb('gslb2', 'www.example.com.edgekey.net', 'e1.a.akamaiedge.net')),
      item('resolver:google', '2.16.1.11', ...gslb('gslb', 'www.example.com.edgekey.net', 'e1.a.akamaiedge.net')),
      item('resolver:dnssb', '151.101.1.10', ...gslb('gslb2', 'prod.example.map.fastly.net')),
      item('resolver:iij', '151.101.65.10', ...gslb('gslb', 'prod.example.map.fastly.net'))
    ]);
    assert.equal(pin.state, 'by-design');
    assert.deepEqual(ids(pin.operators).sort(), ['akamai', 'fastly']);
    assert.deepEqual(pin.steering, [{ owner: 'www.gslb.example.com', targets: ['www.gslb2.example.net', 'www.gslb.example.net'] }]);
    // One branch reaching only part of the other's entry names is still steering (a sample).
    const part = propagationVerdict([
      item('resolver:cloudflare', '2.16.1.10', ...gslb('gslb2', 'www.example.com.edgekey.net', 'e1.a.akamaiedge.net')),
      item('resolver:dnssb', '151.101.1.10', ...gslb('gslb2', 'prod.example.map.fastly.net')),
      item('resolver:iij', '151.101.65.10', ...gslb('gslb', 'prod.example.map.fastly.net'))
    ]);
    assert.equal(part.state, 'by-design');

    // Different entry names behind the two names: another property, so a change.
    const split = propagationVerdict([
      item('resolver:cloudflare', '151.101.1.52', ...cname('zone1.www.example.com', 'a.example.map.fastly.net')),
      item('resolver:google', '151.101.65.52', ...cname('zone2.www.example.com', 'b.example.map.fastly.net'))
    ]);
    assert.deepEqual(split.findings.map((f) => [f.code, f.owner, f.targets]), [['cname', null, ['zone1.www.example.com', 'zone2.www.example.com']]]);
    assert.deepEqual(split.steering, []);
    // gslb → Akamai only, gslb2 → Fastly only: a move between providers, not steering.
    const moved = propagationVerdict([
      item('resolver:cloudflare', '2.16.1.10', ...gslb('gslb', 'www.example.com.edgekey.net', 'e1.a.akamaiedge.net')),
      item('resolver:google', '151.101.1.10', ...gslb('gslb2', 'prod.example.map.fastly.net'))
    ]);
    assert.deepEqual(moved.findings.map((f) => [f.code, f.owner, ids(f.operators)]), [['cname', 'www.gslb.example.com', ['akamai', 'fastly']]]);
    // Names that lead to direct addresses are never taken for steering.
    const direct = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1', ...cname('zone1.www.example.com')),
      item('resolver:google', '198.51.100.1', ...cname('zone2.www.example.com'))
    ]);
    assert.deepEqual(codes(direct), ['cname']);
  });

  test('GeoDNS by CNAME: resolvers agree, only locations get another name', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1', ...cname('eu.example.net')),
      item('resolver:google', '192.0.2.1', ...cname('eu.example.net')),
      { key: 'geo:us-east', kind: 'geo', values: ['198.51.100.1', ...cname('us.example.net')] },
      item('geo:jp-tyo', '203.0.113.1', ...cname('ap.example.net'))
    ]);
    assert.equal(v.state, 'geo', 'as the same answers without the CNAME are');
    assert.equal(v.resolversAgree, true);
    assert.deepEqual(v.findings, []);
    // Resolvers that disagree on it keep the finding.
    const resolvers = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1', ...cname('eu.example.net')),
      item('resolver:google', '198.51.100.1', ...cname('us.example.net'))
    ]);
    assert.deepEqual([resolvers.state, codes(resolvers)], ['differ', ['cname']]);
  });

  test('mainland China: a branch only the locations asked through AliDNS take is by design, not a move', () => {
    // The China rows: ECS locations whose vantage names its own resolver (resolvers.js `resolver`).
    const china = (id, ...values) => ({ key: `geo:${id}`, kind: 'geo', vantage: { id, resolver: 'alidns' }, values });
    const D = 'd333333abcdef8.cloudfront.net';
    const ALI = 'www.example.com.w.kunluncan.com';
    const world = [
      item('resolver:cloudflare', CF_A[0], ...cname(D)),
      item('resolver:google', CF_A[1], ...cname(D)),
      item('geo:de-ham', CF_A[2], ...cname(D)),
      item('geo:jp-tyo', CF_A[3], ...cname(D))
    ];
    const cn = [
      china('cn-bjs-cu', '198.51.100.17', ...cname(ALI)),
      china('cn-sha-ct', '198.51.100.18', ...cname(ALI)),
      china('cn-can-cm', '198.51.100.17', ...cname(ALI))
    ];
    const v = propagationVerdict([...world, ...cn]);
    assert.equal(v.state, 'by-design', 'CloudFront for the world, Alibaba Cloud CDN for mainland China');
    assert.deepEqual(ids(v.operators), ['cloudfront', 'alibaba-cdn']);
    assert.equal(v.resolversAgree, false);
    assert.deepEqual(v.findings, []);
    assert.deepEqual(v.geoSplits.map((s) => [s.owner, s.targets, [...s.members].sort()]), [[null, [ALI], ['geo:cn-bjs-cu', 'geo:cn-can-cm', 'geo:cn-sha-ct']]]);
    assert.ok(v.groups.every((g) => !('regional' in g) && !('geo' in g)), 'no working fields in the groups');

    // Next to a real problem the split stays a finding, marked as the location's.
    const servfail = propagationVerdict([...world, ...cn, item('resolver:dnssb', 'SERVFAIL')]);
    assert.deepEqual([servfail.state, codes(servfail)], ['differ', ['rcode', 'cname']]);
    const f = servfail.findings[1];
    assert.deepEqual([f.owner, f.targets.includes(ALI), [...f.byLocation.members].sort(), ids(f.operators)],
      [null, true, ['geo:cn-bjs-cu', 'geo:cn-can-cm', 'geo:cn-sha-ct'], ['cloudfront', 'alibaba-cdn']]);
    assert.equal(servfail.designPart, false);

    // The resolvers agree: the classic GeoDNS case, as before.
    const agree = propagationVerdict([item('resolver:cloudflare', CF_A[0], ...cname(D)), item('resolver:google', CF_A[0], ...cname(D)), ...cn]);
    assert.deepEqual([agree.state, agree.findings], ['geo', []]);

    // A resolver on the China branch too, or a Google ECS location on it alone: not a split.
    const resolver = propagationVerdict([...world, ...cn, item('resolver:iij', '198.51.100.17', ...cname(ALI))]);
    assert.deepEqual([resolver.state, codes(resolver), resolver.findings[0].byLocation, resolver.geoSplits], ['differ', ['cname'], null, []]);
    const google = propagationVerdict([...world, item('geo:hk-hkg', '198.51.100.17', ...cname(ALI))]);
    assert.deepEqual([google.state, codes(google), google.geoSplits], ['differ', ['cname'], []]);

    // An operator this page does not know in mainland China: its addresses look direct.
    const unknown = propagationVerdict([...world, china('cn-bjs-cu', '198.51.100.30', ...cname('www.example.com.cdn.example.net'))]);
    assert.deepEqual([unknown.state, codes(unknown)], ['differ', ['mixed']]);

    // A CDN only in mainland China in front of the origin everyone else reaches directly.
    const origin = [item('resolver:cloudflare', '192.0.2.10'), item('resolver:google', '192.0.2.10'), item('geo:de-ham', '192.0.2.10')];
    const front = propagationVerdict([...origin, ...cn]);
    assert.deepEqual([front.state, front.findings, ids(front.operators)], ['geo', [], ['alibaba-cdn']], 'resolvers agree: GeoDNS');
    const roundRobin = propagationVerdict([...origin, item('resolver:dnssb', '192.0.2.11'), ...cn]);
    assert.deepEqual([roundRobin.state, codes(roundRobin)], ['differ', ['mixed']], 'resolvers disagree: still named');
    // The same answers from Google ECS locations (no resolver of their own) stay a mixed finding.
    const viaGoogle = propagationVerdict([...origin, item('geo:hk-hkg', '198.51.100.17', ...cname(ALI))]);
    assert.deepEqual([viaGoogle.state, codes(viaGoogle)], ['differ', ['mixed']]);
  });

  test('entry names: a dualstack variant is the same service, a Traffic Manager profile is not regional', () => {
    const reddit = propagationVerdict([
      item('resolver:cloudflare', '151.101.1.140', ...cname('example.map.fastly.net')),
      item('resolver:google', '151.101.129.140', ...cname('dualstack.example.map.fastly.net'))
    ]);
    assert.equal(reddit.state, 'by-design');
    const elb = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.10', ...cname('web-1.eu-west-1.elb.amazonaws.com')),
      item('resolver:google', '198.51.100.10', ...cname('dualstack.web-1.eu-west-1.elb.amazonaws.com'))
    ]);
    assert.equal(elb.state, 'by-design');
    // Another Traffic Manager profile at the queried name is a profile change.
    const tm = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1', ...cname('old.trafficmanager.net', 'eu.example.net')),
      item('resolver:google', '198.51.100.1', ...cname('new.trafficmanager.net', 'us.example.net'))
    ]);
    assert.equal(tm.state, 'differ');
    assert.deepEqual(tm.findings.map((f) => [f.code, f.owner, f.targets]), [['cname', null, ['old.trafficmanager.net', 'new.trafficmanager.net']]]);
    // A name that only looks like the dualstack variant of a customer name stays another name.
    const own = propagationVerdict([
      item('resolver:cloudflare', '192.0.2.1', ...cname('lb.example.net')),
      item('resolver:google', '198.51.100.1', ...cname('dualstack.lb.example.net'))
    ]);
    assert.deepEqual(codes(own), ['cname']);
  });

  test('AAAA without records anywhere: only the CNAME chains are judged', () => {
    // www.paypal.com AAAA: a shared name steers to Fastly or Cloudflare, neither has AAAA.
    const glb = cname('www.glb.example.com');
    const v = propagationVerdict([
      item('resolver:cloudflare', ...glb, ...cname('example-dynamic.map.fastly.net')),
      item('resolver:google', ...glb, ...cname('example-dynamic.map.fastly.net')),
      item('resolver:dnssb', ...glb, ...cname('www.example.com.cdn.cloudflare.net'))
    ], { type: 'AAAA' });
    assert.equal(v.state, 'by-design');
    assert.equal(v.noRecords, true);
    assert.deepEqual(v.findings, []);
    assert.deepEqual(ids(v.operators), ['fastly', 'cloudflare']);
    assert.deepEqual(v.operators.map((op) => [op.kind, op.via, op.reasonKey]), [['cdn', 'cname', 'class.cdn.cname'], ['cloudflare', 'cname', 'class.cloudflare.cname']]);
    assert.deepEqual(v.groups.map((g) => [g.status, ids(g.operators), g.addresses]), [['nodata', ['fastly'], []], ['nodata', ['cloudflare'], []]]);
    assert.equal(v.multiOperator, true);
    // www.etsy.com AAAA: zone1 / zone2 → the same Fastly name, no AAAA.
    const zones = propagationVerdict([
      item('resolver:cloudflare', ...cname('zone1.www.example.com', 'h3.example.map.fastly.net')),
      item('resolver:google', ...cname('zone2.www.example.com', 'h3.example.map.fastly.net'))
    ], { type: 'AAAA' });
    assert.deepEqual([zones.state, zones.noRecords, zones.steering.length], ['by-design', true, 1]);
    // The chains conflict: another distribution, or a CNAME on one side only.
    const dist = propagationVerdict([
      item('resolver:cloudflare', ...cname('d111111abcdef8.cloudfront.net')),
      item('resolver:google', ...cname('d222222abcdef8.cloudfront.net'))
    ], { type: 'AAAA' });
    assert.deepEqual([dist.state, dist.noRecords], ['differ', true]);
    assert.deepEqual(dist.findings.map((f) => [f.code, f.owner, f.targets]), [['cname', null, ['d111111abcdef8.cloudfront.net', 'd222222abcdef8.cloudfront.net']]]);
    const oneSide = propagationVerdict([
      item('resolver:cloudflare', 'NODATA'),
      item('resolver:google', 'NODATA'),
      item('resolver:dnssb', ...cname('example.map.fastly.net'))
    ], { type: 'AAAA' });
    assert.deepEqual(oneSide.findings.map((f) => [f.code, f.owner, f.targets]), [['cname', null, [null, 'example.map.fastly.net']]]);
    const behind = propagationVerdict([
      item('resolver:cloudflare', ...cname('lb.example.com')),
      item('resolver:google', ...cname('lb.example.com', 'example.map.fastly.net'))
    ], { type: 'AAAA' });
    assert.deepEqual(behind.findings.map((f) => [f.code, f.owner, f.targets]), [['cname', 'lb.example.com', [null, 'example.map.fastly.net']]]);
    // Only locations differ: GeoDNS by CNAME.
    const geo = propagationVerdict([
      item('resolver:cloudflare', ...cname('eu.example.net')),
      item('resolver:google', ...cname('eu.example.net')),
      item('geo:us-east', ...cname('us.example.net'))
    ], { type: 'AAAA' });
    assert.deepEqual([geo.state, geo.findings], ['geo', []]);
    // Next to a failure the empty answer is not the difference: only the SERVFAIL is named.
    const failing = propagationVerdict([
      item('resolver:cloudflare', ...cname('example.map.fastly.net')),
      item('resolver:google', 'SERVFAIL')
    ], { type: 'AAAA' });
    assert.deepEqual([failing.state, codes(failing)], ['differ', ['rcode']]);
    // Next to real AAAA answers it is.
    const mixed = propagationVerdict([item('resolver:cloudflare', CF_AAAA[0]), item('resolver:google', ...cname('example.map.fastly.net'))], { type: 'AAAA' });
    assert.deepEqual([mixed.noRecords, codes(mixed)], [false, ['nodata']]);
  });

  test('AAAA: every resolver empty through a CDN name, two locations with its dualstack name and IPv6 edges: by design', () => {
    // www.reddit.com AAAA: x.map.fastly.net has no AAAA; Amsterdam and Dubai get dualstack.x.map.fastly.net.
    const fastlyV6 = ['2a04:4e42:400::396', '2a04:4e42:600::396'];
    const shape = (extra = []) => propagationVerdict([
      item('resolver:cloudflare', ...cname('example.map.fastly.net')),
      item('resolver:google', ...cname('example.map.fastly.net')),
      item('geo:de-ham', ...cname('example.map.fastly.net')),
      item('geo:nl-ams', fastlyV6[0], ...cname('dualstack.example.map.fastly.net')),
      item('geo:ae-dxb', fastlyV6[1], ...cname('dualstack.example.map.fastly.net')),
      ...extra
    ], { type: 'AAAA' });
    const v = shape();
    assert.deepEqual([v.state, v.resolversAgree, v.noRecords], ['by-design', true, false]);
    assert.deepEqual(v.findings, [], 'nobody is blamed for the empty answers');
    assert.deepEqual(ids(v.operators), ['fastly']);
    // Empty answers through another entry name than the addresses' — another provider, or
    // another name of the same one: only GeoDNS.
    const other = propagationVerdict([
      item('resolver:cloudflare', ...cname('www.example.com.cdn.cloudflare.net')),
      item('resolver:google', ...cname('www.example.com.cdn.cloudflare.net')),
      item('geo:nl-ams', fastlyV6[0], ...cname('dualstack.example.map.fastly.net'))
    ], { type: 'AAAA' });
    assert.equal(other.state, 'geo');
    const renamed = propagationVerdict([
      item('resolver:cloudflare', ...cname('a.example.map.fastly.net')),
      item('resolver:google', ...cname('a.example.map.fastly.net')),
      item('geo:nl-ams', fastlyV6[0], ...cname('b.example.map.fastly.net'))
    ], { type: 'AAAA' });
    assert.equal(renamed.state, 'geo');
    // When a resolver gets the addresses too, the empty answers are a difference between resolvers.
    const split = shape([item('resolver:dnssb', fastlyV6[0], ...cname('dualstack.example.map.fastly.net'))]);
    assert.deepEqual([split.state, codes(split)], ['differ', ['nodata']]);
  });

  test('every source failing with an rcode is "unresolved", never "agree"', () => {
    const v = propagationVerdict([item('resolver:cloudflare', 'SERVFAIL'), item('resolver:google', 'SERVFAIL'), item('geo:jp-tyo', 'SERVFAIL')]);
    assert.equal(v.state, 'unresolved');
    assert.deepEqual(v.findings.map((f) => [f.code, f.rcode, f.members.length]), [['rcode', 'SERVFAIL', 3]]);
    const two = propagationVerdict([item('resolver:cloudflare', 'SERVFAIL'), item('resolver:tiar', 'REFUSED')]);
    assert.deepEqual([two.state, two.findings.map((f) => f.rcode)], ['unresolved', ['SERVFAIL', 'REFUSED']]);
    // NXDOMAIN everywhere is an answer everybody agrees on; NXDOMAIN next to SERVFAIL names the failure only.
    assert.equal(propagationVerdict([item('resolver:cloudflare', 'NXDOMAIN'), item('resolver:google', 'NXDOMAIN')]).state, 'agree');
    const nx = propagationVerdict([item('resolver:cloudflare', 'NXDOMAIN'), item('resolver:google', 'NXDOMAIN'), item('resolver:dnssb', 'SERVFAIL')]);
    assert.deepEqual([nx.state, codes(nx)], ['differ', ['rcode']]);
  });

  test('failures, blocked and pending answers are ignored; none and agree', () => {
    const v = propagationVerdict([
      item('resolver:cloudflare', CF_A[0]),
      item('resolver:quad9', 'ERROR'),
      { key: 'resolver:cloudflare-family', values: ['0.0.0.0'], filtered: true },
      { key: 'resolver:google', pending: true, values: null },
      null
    ]);
    assert.equal(v.state, 'agree');
    assert.deepEqual(v.findings, []);
    assert.deepEqual(ids(v.operators), ['cloudfront'], 'the operator of a single answer is still known');
    assert.equal(propagationVerdict([item('resolver:quad9', 'ERROR')]).state, 'none');
    assert.equal(propagationVerdict([]).state, 'none');
    assert.equal(propagationVerdict(undefined).state, 'none');
  });
});
