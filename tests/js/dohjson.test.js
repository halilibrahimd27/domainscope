// Unit tests for assets/js/lib/dohjson.js and the JSON form in lib/doh.js — no network: captured,
// scrubbed AliDNS answers (tests/fixtures/dns-json/alidns.json) and a mocked fetch.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decodeDnsJson, dnsJsonUrl, ecsSubnet, DNS_JSON } from '../../assets/js/lib/dohjson.js';
import { encodeMessage, decodeMessage, DnsWireError } from '../../assets/js/lib/dnswire.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { ECS_RESOLVERS, GEO_VANTAGES, getAnyResolver, getResolver } from '../../assets/js/lib/resolvers.js';
import { answerValues } from '../../assets/js/lib/propagation.js';

const FIX = JSON.parse(readFileSync(new URL('../fixtures/dns-json/alidns.json', import.meta.url), 'utf8'));
const ALIDNS = getAnyResolver('alidns');

/** The records of a wire message carrying the same RRs as `data` shapes (what a wire resolver would answer). */
const wire = (answers) => decodeMessage(encodeMessage({ answers })).answers;
const strip = (rr) => ({ name: rr.name, type: rr.type, ttl: rr.ttl, data: rr.data, text: rr.text });

describe('the resolver and its vantages', () => {
  test('AliDNS is a JSON-form resolver for locations only: not a general resolver', () => {
    assert.deepEqual(ECS_RESOLVERS.map((r) => [r.id, r.name, r.format, r.url]), [['alidns', 'AliDNS (ECS)', 'json', 'https://dns.alidns.com/resolve']]);
    assert.equal(getResolver('alidns'), undefined, 'not offered as a resolver of its own');
    assert.equal(ALIDNS.dnssecValidating, false);
    assert.equal(ALIDNS.ecsEcho, false, 'echoes the subnet without a scope');
    const china = GEO_VANTAGES.filter((v) => v.group === 'cn');
    assert.deepEqual(china.map((v) => [v.id, v.city, v.isp, v.asn, v.subnet, v.resolver, v.verifiedCountry, v.verifiedCity]), [
      ['cn-bjs-cu', 'Beijing', 'China Unicom', 4808, '202.106.0.0/24', 'alidns', 'CN', null],
      ['cn-sha-ct', 'Shanghai', 'China Telecom', 4812, '202.96.209.0/24', 'alidns', 'CN', null],
      ['cn-can-cm', 'Guangzhou', 'China Mobile', 56040, '211.136.192.0/24', 'alidns', 'CN', null]
    ]);
    assert.ok(GEO_VANTAGES.filter((v) => v.resolver).every((v) => getAnyResolver(v.resolver)), 'every named resolver exists');
  });
});

describe('dnsJsonUrl / ecsSubnet', () => {
  test('the type as its number, the name encoded, the subnet canonical and unencoded', () => {
    assert.equal(dnsJsonUrl(ALIDNS.url, { name: 'www.example.com', type: 'A', ecs: '202.96.209.0/24' }),
      'https://dns.alidns.com/resolve?name=www.example.com&type=1&edns_client_subnet=202.96.209.0/24');
    assert.equal(dnsJsonUrl(ALIDNS.url, { name: 'example.com', type: 'HTTPS' }), 'https://dns.alidns.com/resolve?name=example.com&type=65');
    assert.equal(dnsJsonUrl('https://x.example/resolve?k=1', { name: 'a b', type: 16 }), 'https://x.example/resolve?k=1&name=a%20b&type=16');
    assert.throws(() => dnsJsonUrl(ALIDNS.url, { name: 'example.com', type: 'NOPE' }), DnsWireError);
  });

  test('ECS specs of every form; host bits zeroed; nonsense is no subnet', () => {
    assert.equal(ecsSubnet('202.96.209.77/24'), '202.96.209.0/24');
    assert.equal(ecsSubnet({ subnet: '198.51.100.0/24' }), '198.51.100.0/24');
    assert.equal(ecsSubnet({ address: '192.0.2.200', sourcePrefix: 25 }), '192.0.2.128/25');
    assert.equal(ecsSubnet('192.0.2.1'), '192.0.2.0/24', 'a bare address: its /24');
    assert.equal(ecsSubnet('2001:db8::/56'), '2001:db8::/56');
    for (const bad of [null, '', false, 'bogus', '192.0.2.0/33', '192.0.2.0/x']) assert.equal(ecsSubnet(bad), null, String(bad));
  });
});

describe('decodeDnsJson', () => {
  test('flags, rcode, question and the echoed subnet (no scope)', () => {
    const m = decodeDnsJson(FIX['a-ecs-cdn']);
    assert.deepEqual([m.flags.qr, m.flags.rd, m.flags.ra, m.flags.ad, m.flags.tc, m.rcodeName], [true, true, true, false, false, 'NOERROR']);
    assert.deepEqual(m.questions.map((q) => [q.name, q.type]), [['www.example.com', 'A']]);
    assert.deepEqual(m.edns.ecs, { family: 1, sourcePrefix: 24, scopePrefix: null, address: '202.96.209.0', subnet: '202.96.209.0/24' });
    assert.deepEqual(m.answers.map((rr) => [rr.name, rr.type, rr.ttl, rr.data]), [
      ['www.example.com', 'CNAME', 600, 'www.example.com.cdn.example.net'],
      ['www.example.com.cdn.example.net', 'A', 60, '198.51.100.17'],
      ['www.example.com.cdn.example.net', 'A', 60, '198.51.100.18']
    ]);
    assert.equal(decodeDnsJson(FIX.txt).edns, null, 'no subnet asked, none echoed');
  });

  test('every captured type reads exactly like the same records from the wire', () => {
    const cases = {
      'aaaa-ecs': [['example.com', 'AAAA', 300, '2001:db8::10'], ['example.com', 'AAAA', 300, '2001:db8::11']],
      'null-mx': [['example.com', 'MX', 300, { preference: 0, exchange: '.' }]],
      txt: [['example.com', 'TXT', 300, ['_examplechallenge0123456789']], ['example.com', 'TXT', 300, ['v=spf1 -all']]],
      'multi-string-txt': [['sel1._domainkey.example.com', 'TXT', 3600, ['v=DKIM1; k=rsa; p=AAAA', 'BBBB "quoted" ä']]],
      https: [['example.com', 'HTTPS', 300, { priority: 1, target: '.', params: { alpn: ['h3', 'h2'], ipv4hint: ['192.0.2.10', '192.0.2.11'], ipv6hint: ['2001:db8::10', '2001:db8::11'] } }]],
      caa: [['example.com', 'CAA', 86400, { flags: 0, tag: 'issue', value: 'letsencrypt.org' }]],
      srv: [['_xmpp-server._tcp.example.com', 'SRV', 60, { priority: 30, weight: 30, port: 5269, target: 'xmpp.example.com' }]],
      soa: [['example.com', 'SOA', 1800, { mname: 'ns1.example.net', rname: 'dns.example.net', serial: 2416374680, refresh: 10000, retry: 2400, expire: 604800, minimum: 1800 }]],
      ns: [['example.com', 'NS', 3600, 'ns1.example.net'], ['example.com', 'NS', 3600, 'ns2.example.net']],
      ds: [['example.com', 'DS', 3600, { keyTag: 12345, algorithm: 13, digestType: 2, digest: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' }]],
      dnskey: [['example.com', 'DNSKEY', 3600, { flags: 257, protocol: 3, algorithm: 13, publicKey: FIX.dnskey.Answer[0].data.split(' ')[3] }]],
      'tlsa-raw-hex': [['_25._tcp.mail.example.com', 'TLSA', 300, { usage: 3, selector: 1, matchingType: 1, data: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' }]]
    };
    for (const [id, rrs] of Object.entries(cases)) {
      const fromJson = decodeDnsJson(FIX[id]).answers.map(strip);
      const fromWire = wire(rrs.map(([name, type, ttl, data]) => ({ name, type, ttl, data }))).map(strip);
      assert.deepEqual(fromJson, fromWire, id);
    }
    assert.equal(decodeDnsJson(FIX.https).answers[0].text, '1 . alpn="h3,h2" ipv4hint=192.0.2.10,192.0.2.11 ipv6hint=2001:db8::10,2001:db8::11');
  });

  test('NXDOMAIN and NODATA with the authority SOA; an unknown type in the question', () => {
    const nx = decodeDnsJson(FIX.nxdomain);
    assert.deepEqual([nx.rcodeName, nx.answers.length, nx.authorities[0].type, nx.authorities[0].data.minimum], ['NXDOMAIN', 0, 'SOA', 86400]);
    const nodata = decodeDnsJson(FIX['nodata-unknown-type']);
    assert.deepEqual([nodata.rcodeName, nodata.questions[0].type, nodata.answers.length, nodata.authorities[0].name], ['NOERROR', 'TYPE999', 0, 'example.com']);
  });

  test('a record that cannot be read keeps its text; an answer that is not DNS JSON is refused', () => {
    const odd = decodeDnsJson({ Status: 0, Question: { name: 'example.com.', type: 1 }, Answer: [{ name: 'example.com.', TTL: 5, type: 1, data: 'not-an-address' }, { name: 'example.com.', TTL: 5, type: 99, data: '"v=spf1 -all"' }] });
    assert.deepEqual(odd.answers.map((rr) => [rr.type, rr.data, rr.text]), [['A', 'not-an-address', 'not-an-address'], ['SPF', ['v=spf1 -all'], '"v=spf1 -all"']]);
    for (const bad of [FIX['error-bad-subnet'], FIX['error-bad-name'], null, [], { Status: 'x' }]) {
      assert.throws(() => decodeDnsJson(bad), DnsWireError, JSON.stringify(bad));
    }
    assert.throws(() => decodeDnsJson({ Status: 0, Answer: [{ type: 1, data: '192.0.2.1' }] }), DnsWireError, 'a record without an owner');
  });
});

/** A fetch that answers JSON-form questions from a table: `name|type|subnet` → body (or a status). */
function jsonFetch(table) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const u = new URL(url);
    calls.push({ url: String(url), accept: init.headers.accept });
    const key = `${u.searchParams.get('name')}|${u.searchParams.get('type')}|${u.searchParams.get('edns_client_subnet') || ''}`;
    const v = table[key];
    if (v === undefined) return new Response(JSON.stringify(FIX['error-bad-name']), { status: 401, headers: { 'content-type': 'application/json' } });
    if (typeof v === 'string') return new Response(v, { status: 200 });
    return new Response(JSON.stringify(v), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return { fetchImpl, calls };
}

describe('DohClient over the JSON form', () => {
  const client = (fetchImpl) => new DohClient({ fetchImpl, retries: 0, baseDelayMs: 1, maxDelayMs: 2, cache: false });

  test('a vantage question to AliDNS: JSON accept, the subnet sent, the same DnsResponse shape as the wire', async () => {
    const { fetchImpl, calls } = jsonFetch({ 'www.example.com|1|202.96.209.0/24': FIX['a-ecs-cdn'] });
    const r = await client(fetchImpl).query('www.example.com', 'A', { resolver: 'alidns', ecs: '202.96.209.0/24' });
    assert.deepEqual(calls, [{ url: 'https://dns.alidns.com/resolve?name=www.example.com&type=1&edns_client_subnet=202.96.209.0/24', accept: DNS_JSON }]);
    assert.deepEqual([r.ok, r.resolver, r.rcode, r.ad, r.nsid, r.ede], [true, 'alidns', 'NOERROR', false, null, []]);
    assert.deepEqual(r.ecs, { family: 1, sourcePrefix: 24, scopePrefix: null, address: '202.96.209.0', subnet: '202.96.209.0/24' });
    assert.deepEqual(answerValues(r, 'A'), ['198.51.100.17', '198.51.100.18', 'CNAME www.example.com.cdn.example.net']);
  });

  test('the same answer from Google (wire) and AliDNS (JSON) is one answer to Global DNS', async () => {
    const google = { ok: true, rcode: 'NOERROR', name: 'www.example.com', answers: wire([
      { name: 'www.example.com', type: 'CNAME', ttl: 600, data: 'www.example.com.cdn.example.net' },
      { name: 'www.example.com.cdn.example.net', type: 'A', ttl: 20, data: '198.51.100.18' },
      { name: 'www.example.com.cdn.example.net', type: 'A', ttl: 20, data: '198.51.100.17' }
    ]) };
    const { fetchImpl } = jsonFetch({ 'www.example.com|1|202.96.209.0/24': FIX['a-ecs-cdn'] });
    const ali = await client(fetchImpl).query('www.example.com', 'A', { resolver: 'alidns', ecs: '202.96.209.0/24' });
    assert.deepEqual(answerValues(ali, 'A'), answerValues(google, 'A'));
    for (const id of ['https', 'caa', 'txt', 'soa']) {
      const json = decodeDnsJson(FIX[id]).answers;
      const type = json[0].type;
      const viaWire = { ok: true, rcode: 'NOERROR', name: json[0].name, answers: wire(json.map((rr) => ({ name: rr.name, type: rr.type, ttl: rr.ttl, data: rr.data }))) };
      assert.deepEqual(answerValues({ ok: true, rcode: 'NOERROR', name: json[0].name, answers: json }, type), answerValues(viaWire, type), id);
    }
  });

  test('AliDNS refusing a question (401 / 400 JSON), a body that is not JSON, an answer to another question', async () => {
    const { fetchImpl } = jsonFetch({ 'x.example.com|1|': '<html>', 'y.example.com|1|': FIX['a-ecs-cdn'] });
    const dns = client(fetchImpl);
    const refused = await dns.query('bad.example.com', 'A', { resolver: 'alidns' });
    assert.deepEqual([refused.ok, refused.errorKind], [false, 'http']);
    assert.match(refused.error, /401.*NoPermission/);
    const html = await dns.query('x.example.com', 'A', { resolver: 'alidns' });
    assert.deepEqual([html.ok, /not JSON/.test(html.error)], [false, true]);
    const other = await dns.query('y.example.com', 'A', { resolver: 'alidns' });
    assert.deepEqual([other.ok, /is for www\.example\.com/.test(other.error)], [false, true]);
  });

  test('the JSON form is never part of a chain or the bulk pool', () => {
    const dns = new DohClient({ fetchImpl: async () => { throw new Error('no network'); } });
    assert.ok(!dns.chain.includes('alidns'));
    assert.ok(!dns.balancePool.includes('alidns'));
  });
});
