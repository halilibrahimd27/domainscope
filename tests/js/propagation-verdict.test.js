// Unit tests for lib/propagation.js propagationVerdict — why Global DNS answers differ:
// CDN / GeoDNS edges by design, or propagation / a misconfiguration. No network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { propagationVerdict, splitChain, VERDICT_FINDINGS, VERDICT_STATES } from '../../assets/js/lib/propagation.js';
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
    assert.deepEqual(VERDICT_STATES, ['none', 'agree', 'by-design', 'geo', 'differ']);
    assert.deepEqual(VERDICT_FINDINGS, ['rcode', 'nxdomain', 'nodata', 'private', 'mixed', 'cname', 'direct', 'records']);
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

  test('an answer only filtering resolvers give (SafeSearch CNAME) is their policy, not a difference', () => {
    const row = (id, ...values) => ({ key: `resolver:${id}`, kind: 'resolver', resolver: getResolver(id), values });
    const safe = ['192.0.2.99', ...cname('forcesafesearch.example.com')];
    const v = propagationVerdict([
      row('cloudflare', '192.0.2.1'),
      row('google', '192.0.2.1'),
      row('cloudflare-family', ...safe),
      row('cleanbrowsing', ...safe),
      { key: 'geo:de-ham', kind: 'geo', resolver: getResolver('quad9-ecs'), values: ['192.0.2.1'] }
    ]);
    assert.equal(v.state, 'agree');
    assert.deepEqual(v.rewritten, ['resolver:cloudflare-family', 'resolver:cleanbrowsing']);
    assert.deepEqual(v.groups.map((g) => g.rewritten), [false, true]);
    assert.deepEqual(v.findings, []);

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
    // Just another edge from a filtering resolver's own cache: an ordinary, by-design answer.
    const edge = propagationVerdict([row('cloudflare', CF_A[0]), row('google', CF_A[1]), row('cleanbrowsing', CF_A[2])]);
    assert.equal(edge.state, 'by-design');
    assert.deepEqual(edge.rewritten, []);
    // Only filtering resolvers answered: nothing to compare with, so their answers are judged.
    const alone = propagationVerdict([row('cloudflare-family', '192.0.2.1'), row('cleanbrowsing', '198.51.100.1')]);
    assert.deepEqual(alone.rewritten, []);
    assert.deepEqual(codes(alone), ['direct']);
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
