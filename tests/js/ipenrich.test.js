/**
 * lib/ipenrich.js — IP Intel's routing enrichment: the parsers against fixtures shaped like the
 * live answers (tests/fixtures/ipenrich/), the CIDR breadcrumb math, the server matching, and the
 * service with a fake fetch and a fake clock (no network, no real waits).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ENRICH_SOURCES, RPKI_STATUSES, ROUTING_FLAGS, PEERINGDB_TYPE_CODES, PEERINGDB_INTERVAL_MS, PEERINGDB_PAUSE_MS,
  networkInfoUrl, rpkiValidationUrl, routingStatusUrl, abuseContactUrl, peeringdbNetUrl,
  parseNetworkInfo, parseRpkiValidation, parseRoutingStatus, parseAbuseContact, parsePeeringdbNet, peeringdbTypeCode,
  cidrLevels, serversInLevels, knownFromInfo, createIpEnrich
} from '../../assets/js/lib/ipenrich.js';
import { STATUS_SOURCES, sourceStatus } from '../../assets/js/lib/sourcestatus.js';
import { classifyUrl } from '../../assets/js/lib/egress.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'ipenrich');
const RIPE = JSON.parse(readFileSync(join(FIX, 'ripestat.json'), 'utf8'));
const PDB = JSON.parse(readFileSync(join(FIX, 'peeringdb.json'), 'utf8'));

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

/**
 * A fetch that answers by RIPEstat data call (or 'peeringdb'): `answers[call]` is a body, a
 * Response, or a function (url, n) → either (n: how many times that call was asked before).
 */
function fakeFetch(answers, calls = []) {
  const seen = {};
  const impl = async (url) => {
    const u = new URL(String(url));
    const call = u.host === 'www.peeringdb.com' ? 'peeringdb' : u.pathname.split('/')[2];
    calls.push(`${call} ${u.searchParams.get('resource') || u.searchParams.get('asn')}${u.searchParams.get('prefix') ? ` ${u.searchParams.get('prefix')}` : ''}`);
    const n = seen[call] || 0;
    seen[call] = n + 1;
    let a = answers[call];
    if (typeof a === 'function') a = await a(u, n);
    if (a === undefined) return json({ status: 'error', messages: [['error', `no fake for ${call}`]] }, 400);
    return a instanceof Response ? a : json(a);
  };
  return impl;
}

/** A clock that only the fake sleep moves. */
function fakeTime(start = 1_000_000) {
  const t = { clock: start, sleeps: [] };
  t.now = () => t.clock;
  t.sleep = async (ms, signal) => {
    if (signal && signal.aborted) throw signal.reason;
    t.sleeps.push(ms);
    t.clock += ms;
  };
  return t;
}

const ALL_OK = {
  'network-info': RIPE['network-info'],
  'rpki-validation': RIPE['rpki-valid'],
  'routing-status': RIPE['routing-status'],
  'abuse-contact-finder': RIPE['abuse-contact'],
  peeringdb: PDB.net
};

/** The service with documentation addresses allowed (the default refuses them: see the first test). */
function service(answers, extra = {}) {
  const calls = [];
  const time = fakeTime();
  const svc = createIpEnrich({ fetchImpl: fakeFetch(answers, calls), retries: 0, now: time.now, sleep: time.sleep, routable: () => true, ...extra });
  return { svc, calls, time };
}

describe('URLs', () => {
  test('every RIPEstat call carries sourceapp, and each is a registry endpoint', () => {
    assert.equal(networkInfoUrl('192.0.2.10'), 'https://stat.ripe.net/data/network-info/data.json?resource=192.0.2.10&sourceapp=domainscope');
    assert.equal(rpkiValidationUrl(64496, '192.0.2.0/24'), 'https://stat.ripe.net/data/rpki-validation/data.json?resource=AS64496&prefix=192.0.2.0/24&sourceapp=domainscope');
    assert.equal(routingStatusUrl('2001:db8::/32'), 'https://stat.ripe.net/data/routing-status/data.json?resource=2001:db8::/32&sourceapp=domainscope');
    assert.equal(abuseContactUrl('192.0.2.10'), 'https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=192.0.2.10&sourceapp=domainscope');
    assert.equal(peeringdbNetUrl(64496), 'https://www.peeringdb.com/api/net?asn=64496');
    const ids = [networkInfoUrl('192.0.2.10'), rpkiValidationUrl(64496, '192.0.2.0/24'), routingStatusUrl('192.0.2.0/24'), abuseContactUrl('192.0.2.10'), peeringdbNetUrl(64496)]
      .map((u) => { const c = classifyUrl(u); return `${c.service.id}/${c.endpoint && c.endpoint.id}:${c.sends.join('+')}`; });
    assert.deepEqual(ids, [
      'ripestat/network-info:ipAddresses', 'ripestat/rpki-validation:ipAddresses+asNumbers', 'ripestat/routing-status:ipAddresses',
      'ripestat/abuse-contact:ipAddresses', 'peeringdb/net:asNumbers'
    ]);
  });

  test('every source is a status source (period known), so a failure reads as a reason', () => {
    for (const s of ENRICH_SOURCES) assert.ok(Object.hasOwn(STATUS_SOURCES, s), s);
    const st = sourceStatus({ source: 'peeringdb', error: 'HTTP 429', errorKind: 'rate-limit', status: 429, retryAfterMs: PEERINGDB_PAUSE_MS, at: 0 }, { now: 1000 });
    assert.deepEqual([st.reason, st.params], ['rate-limit-wait', { minutes: 1 }]);
  });
});

describe('parsers (fixtures shaped like the live answers of 2026-10-08)', () => {
  test('network-info: the prefix and the origin ASes as numbers; an unannounced address has no prefix', () => {
    assert.deepEqual(parseNetworkInfo(RIPE['network-info']), { prefix: '192.0.2.0/24', asns: [64496] });
    assert.deepEqual(parseNetworkInfo(RIPE['network-info-unannounced']), { prefix: null, asns: [] });
    assert.deepEqual(parseNetworkInfo({ status: 'ok', data: { asns: ['64496', 'AS64497', 'x', 0, '64496'], prefix: '192.0.2.7/24' } }),
      { prefix: '192.0.2.0/24', asns: [64496, 64497] }, 'host bits masked, junk and duplicates dropped');
    assert.throws(() => parseNetworkInfo(RIPE.error), /The given resource is not valid/);
    assert.throws(() => parseNetworkInfo(null), /empty response/);
  });

  test('rpki-validation: valid, invalid (wrong origin / too specific) and not found, with the ROAs', () => {
    assert.deepEqual(parseRpkiValidation(RIPE['rpki-valid']), {
      status: 'valid', validator: 'routinator',
      roas: [{ origin: 64496, prefix: '192.0.2.0/24', maxLength: 24, validity: 'valid' }]
    });
    assert.equal(parseRpkiValidation(RIPE['rpki-invalid-asn']).status, 'invalid-asn');
    assert.deepEqual(parseRpkiValidation(RIPE['rpki-invalid-length']).roas, [{ origin: 64496, prefix: '192.0.2.0/24', maxLength: 24, validity: 'invalid-length' }]);
    assert.deepEqual(parseRpkiValidation(RIPE['rpki-unknown']), { status: 'not-found', roas: [], validator: 'routinator' });
    assert.throws(() => parseRpkiValidation({ status: 'ok', data: { status: 'maybe' } }), (err) => err.name === 'ParseError');
    for (const fixture of ['rpki-valid', 'rpki-invalid-asn', 'rpki-invalid-length', 'rpki-unknown']) {
      assert.ok(RPKI_STATUSES.includes(parseRpkiValidation(RIPE[fixture]).status), fixture);
    }
  });

  test('routing-status: one origin seen everywhere is clean; MOAS, more-specifics and low visibility are flagged', () => {
    const ok = parseRoutingStatus(RIPE['routing-status']);
    assert.deepEqual([ok.announced, ok.origins, ok.flags, ok.visibility, ok.moreSpecificCount, ok.firstSeen],
      [true, [64496], [], { seeing: 98, total: 98 }, 0, '2002-11-06T16:00:00']);
    assert.deepEqual(ok.lessSpecifics.map((r) => r.prefix), ['192.0.0.0/9', '192.0.0.0/12']);
    const moas = parseRoutingStatus(RIPE['routing-status-moas']);
    assert.deepEqual(moas.origins, [64496, 64497]);
    assert.deepEqual(moas.flags, ['moas', 'more-specifics', 'low-visibility']);
    assert.deepEqual(moas.moreSpecifics, [{ prefix: '192.0.2.0/25', origin: 64497 }, { prefix: '192.0.2.128/25', origin: 64497 }]);
    assert.deepEqual(parseRoutingStatus(RIPE['routing-status-unannounced']).flags, ['not-announced'], 'no origin: not announced (low visibility is not added)');
    // An IPv6 prefix counts the IPv6 peers.
    const v6 = parseRoutingStatus({ status: 'ok', data: { origins: [{ origin: 64496 }], visibility: { v4: { ris_peers_seeing: 0, total_ris_peers: 98 }, v6: { ris_peers_seeing: 80, total_ris_peers: 90 } }, resource: '2001:db8::/32' } });
    assert.deepEqual([v6.visibility, v6.flags], [{ seeing: 80, total: 90 }, []]);
    for (const f of [...ok.flags, ...moas.flags]) assert.ok(ROUTING_FLAGS.includes(f), f);
  });

  test('abuse-contact-finder: the addresses (junk dropped) and the RIR', () => {
    assert.deepEqual(parseAbuseContact(RIPE['abuse-contact']), { contacts: ['abuse@example.net'], rir: 'RIPE NCC' });
    assert.deepEqual(parseAbuseContact({ status: 'ok', data: { abuse_contacts: [' abuse@example.org ', 'not an address', 42, 'abuse@example.org'], authoritative_rir: 'arin' } }),
      { contacts: ['abuse@example.org'], rir: 'ARIN' });
    assert.deepEqual(parseAbuseContact({ status: 'ok', data: { abuse_contacts: [] } }), { contacts: [], rir: null });
  });

  test('PeeringDB: the record, its type codes and a safe website; no record is null', () => {
    assert.deepEqual(parsePeeringdbNet(PDB.net), {
      id: 1001, asn: 64496, name: 'Example Networks', aka: 'Example CDN', website: 'https://www.example.net/',
      types: ['Content'], scope: 'Global', policy: 'Selective', irrAsSet: 'RADB::AS-EXAMPLE'
    });
    assert.equal(parsePeeringdbNet(PDB['not-found']), null);
    const odd = parsePeeringdbNet({ data: [{ id: 7, asn: 64497, name: ' ', website: 'javascript:alert(1)', info_type: 'NSP', info_types: ['Cable/DSL/ISP', 'NSP'] }] });
    assert.deepEqual([odd.name, odd.website, odd.types], ['AS64497', null, ['Cable/DSL/ISP', 'NSP']]);
    assert.deepEqual(odd.types.map(peeringdbTypeCode), ['isp', 'nsp']);
    assert.equal(peeringdbTypeCode('Something New'), null);
    assert.ok(PEERINGDB_TYPE_CODES.includes('content'));
    assert.throws(() => parsePeeringdbNet({ error: 'x' }), (err) => err.name === 'ParseError');
  });
});

describe('CIDR breadcrumb', () => {
  test('IPv4: /8 › /16 › /24 › the address, the announced /24 merged into its block', () => {
    assert.deepEqual(cidrLevels('192.0.2.10', '192.0.2.0/24'), [
      { cidr: '192.0.0.0/8', length: 8, announced: false, address: false },
      { cidr: '192.0.0.0/16', length: 16, announced: false, address: false },
      { cidr: '192.0.2.0/24', length: 24, announced: true, address: false },
      { cidr: '192.0.2.10/32', length: 32, announced: false, address: true }
    ]);
  });

  test('an announced prefix between blocks gets its own level; one that does not hold the address is ignored', () => {
    assert.deepEqual(cidrLevels('192.0.2.10', '192.0.0.0/22').map((l) => [l.cidr, l.announced]),
      [['192.0.0.0/8', false], ['192.0.0.0/16', false], ['192.0.0.0/22', true], ['192.0.2.0/24', false], ['192.0.2.10/32', false]]);
    assert.deepEqual(cidrLevels('192.0.2.10', '203.0.113.0/24').map((l) => l.announced), [false, false, false, false]);
    assert.deepEqual(cidrLevels('192.0.2.10', '2001:db8::/32').length, 4, 'another IP version is ignored');
    assert.deepEqual(cidrLevels('192.0.2.10').map((l) => l.cidr), ['192.0.0.0/8', '192.0.0.0/16', '192.0.2.0/24', '192.0.2.10/32']);
  });

  test('IPv6: /32 › /48 › /64 › the address; an IPv4-mapped address is its IPv4 address; junk is []', () => {
    assert.deepEqual(cidrLevels('2001:db8:1:2::10', '2001:db8::/32').map((l) => [l.cidr, l.announced, l.address]), [
      ['2001:db8::/32', true, false], ['2001:db8:1::/48', false, false], ['2001:db8:1:2::/64', false, false], ['2001:db8:1:2::10/128', false, true]
    ]);
    assert.deepEqual(cidrLevels('::ffff:192.0.2.10').map((l) => l.cidr), ['192.0.0.0/8', '192.0.0.0/16', '192.0.2.0/24', '192.0.2.10/32']);
    assert.deepEqual(cidrLevels('not an ip'), []);
  });

  test('the servers inside each level: the address’s own server first, then by name; addresses outside are left out', () => {
    const index = new Map([
      ['192.0.2.20', [{ id: 'web-2', name: 'web-2' }]],
      ['192.0.2.10', [{ id: 'web-1', name: 'web-1' }]],
      ['192.0.0.5', [{ id: 'dns-1', name: 'dns-1' }, { id: 'web-1', name: 'web-1' }]],
      ['203.0.113.9', [{ id: 'mail', name: 'mail' }]],
      ['10.0.0.1', [{ id: 'db', name: 'db' }]],
      ['2001:db8::1', [{ id: 'v6', name: 'v6' }]]
    ]);
    const levels = serversInLevels(cidrLevels('192.0.2.10', '192.0.2.0/24'), index, '192.0.2.10');
    const view = levels.map((l) => [l.cidr, l.servers.map((s) => `${s.name}${s.here ? '*' : ''}:${s.ips.join('+')}`)]);
    assert.deepEqual(view, [
      ['192.0.0.0/8', ['web-1*:192.0.2.10+192.0.0.5', 'dns-1:192.0.0.5', 'web-2:192.0.2.20']],
      ['192.0.0.0/16', ['web-1*:192.0.2.10+192.0.0.5', 'dns-1:192.0.0.5', 'web-2:192.0.2.20']],
      ['192.0.2.0/24', ['web-1*:192.0.2.10', 'web-2:192.0.2.20']],
      ['192.0.2.10/32', ['web-1*:192.0.2.10']]
    ]);
    assert.deepEqual(serversInLevels(cidrLevels('192.0.2.10'), new Map(), '192.0.2.10').map((l) => l.servers), [[], [], [], []]);
  });
});

describe('the service', () => {
  test('nothing is sent for a private, reserved, documentation or invalid address (the default)', async () => {
    const calls = [];
    const svc = createIpEnrich({ fetchImpl: fakeFetch(ALL_OK, calls) });
    for (const ip of ['192.0.2.10', '10.0.0.1', '2001:db8::1', '198.51.100.7', '::1', 'fe80::1']) {
      const r = await svc.enrich(ip);
      assert.equal(r.skipped, 'not-routable', ip);
    }
    assert.equal((await svc.enrich('bogus')).skipped, 'invalid');
    assert.deepEqual(calls, []);
  });

  test('with the row’s prefix and origin: no network-info; RPKI, routing, abuse and PeeringDB answer', async () => {
    const { svc, calls } = service(ALL_OK);
    const known = knownFromInfo({ prefix: '192.0.2.0/24', asns: [{ asn: 64496, holder: 'EXAMPLE' }], announced: true });
    assert.deepEqual(known, { prefix: '192.0.2.0/24', asns: [64496], announced: true });
    const r = await svc.enrich('192.0.2.10', { known });
    assert.deepEqual(calls.sort(), ['abuse-contact-finder 192.0.2.10', 'peeringdb 64496', 'routing-status 192.0.2.0/24', 'rpki-validation AS64496 192.0.2.0/24']);
    assert.deepEqual([r.skipped, r.prefix, r.origins, r.prefixFrom, r.announced, r.errors], [null, '192.0.2.0/24', [64496], 'ip-intel', true, []]);
    assert.deepEqual(r.rpki.map((x) => [x.asn, x.status]), [[64496, 'valid']]);
    assert.deepEqual(r.routing.flags, []);
    assert.deepEqual(r.abuse, { contacts: ['abuse@example.net'], rir: 'RIPE NCC' });
    assert.deepEqual(r.peeringdb.map((x) => [x.asn, x.net.name]), [[64496, 'Example Networks']]);
  });

  test('without it: network-info first, then the rest with the prefix it gave; the result is kept', async () => {
    const { svc, calls } = service(ALL_OK);
    const r = await svc.enrich('192.0.2.10');
    assert.equal(calls.filter((c) => c.startsWith('network-info')).length, 1);
    assert.deepEqual([r.prefix, r.origins, r.prefixFrom], ['192.0.2.0/24', [64496], 'ripestat-network']);
    assert.equal(calls.length, 5);
    const again = await svc.enrich('192.0.2.10');
    assert.equal(calls.length, 5, 'a kept result asks nothing');
    assert.deepEqual(again, r);
    assert.deepEqual(svc.peek('192.0.2.10'), r);
    assert.equal(svc.peek('192.0.2.11'), null);
    await svc.enrich('192.0.2.10', { noCache: true });
    assert.equal(calls.length, 9, 'noCache asks again (PeeringDB stays cached per AS)');
  });

  test('an unannounced address: only network-info and the abuse contact are asked', async () => {
    const { svc, calls } = service({ ...ALL_OK, 'network-info': RIPE['network-info-unannounced'] });
    const r = await svc.enrich('192.0.2.10');
    assert.deepEqual(calls.sort(), ['abuse-contact-finder 192.0.2.10', 'network-info 192.0.2.10']);
    assert.deepEqual([r.prefix, r.announced, r.rpki, r.routing, r.peeringdb, r.abuse.contacts], [null, false, null, null, null, ['abuse@example.net']]);
    // The row already said so: not even network-info.
    const other = service(ALL_OK);
    const r2 = await other.svc.enrich('192.0.2.10', { known: { prefix: null, asns: [], announced: false } });
    assert.deepEqual([other.calls, r2.announced], [['abuse-contact-finder 192.0.2.10'], false]);
  });

  test('a 429 is a failure of that source only; Retry asks only it again and the result is then kept', async () => {
    let limited = true;
    const { svc, calls } = service({ ...ALL_OK, 'rpki-validation': () => (limited ? new Response('Too Many Requests', { status: 429 }) : json(RIPE['rpki-valid'])) });
    const r = await svc.enrich('192.0.2.10');
    assert.deepEqual(r.errors.map((e) => [e.source, e.status, e.errorKind, e.asn]), [['ripestat-rpki', 429, 'rate-limit', 64496]]);
    assert.deepEqual([r.rpki, r.routing.flags, r.abuse.contacts.length, r.peeringdb.length], [[], [], 1, 1]);
    assert.equal(svc.peek('192.0.2.10'), null, 'a result with a failure is not kept');
    limited = false;
    const before = calls.length;
    const fixed = await svc.retry(r);
    assert.deepEqual(calls.slice(before), ['rpki-validation AS64496 192.0.2.0/24']);
    assert.deepEqual([fixed.errors, fixed.rpki.map((x) => x.status)], [[], ['valid']]);
    assert.deepEqual(svc.peek('192.0.2.10').rpki, fixed.rpki);
    assert.deepEqual(r.errors.length, 1, 'the earlier result is not changed');
  });

  test('a failed network-info leaves the prefix sources unasked; its Retry asks them too', async () => {
    let down = true;
    const { svc, calls } = service({ ...ALL_OK, 'network-info': () => (down ? new Response('oops', { status: 503 }) : json(RIPE['network-info'])) });
    const r = await svc.enrich('192.0.2.10');
    assert.deepEqual(r.errors.map((e) => [e.source, e.status, e.errorKind]), [['ripestat-network', 503, 'http']]);
    assert.deepEqual([r.prefix, r.rpki, r.routing, r.peeringdb], [null, null, null, null]);
    assert.deepEqual(calls.sort(), ['abuse-contact-finder 192.0.2.10', 'network-info 192.0.2.10']);
    down = false;
    const before = calls.length;
    const fixed = await svc.retry(r);
    assert.deepEqual(calls.slice(before).sort(), ['network-info 192.0.2.10', 'peeringdb 64496', 'routing-status 192.0.2.0/24', 'rpki-validation AS64496 192.0.2.0/24']);
    assert.deepEqual([fixed.errors, fixed.prefix, fixed.rpki.length, fixed.peeringdb.length], [[], '192.0.2.0/24', 1, 1]);
  });

  test('MOAS: RPKI and PeeringDB per origin, in origin order; PeeringDB is paced and asked once per AS', async () => {
    const { svc, calls, time } = service({
      ...ALL_OK,
      'network-info': { status: 'ok', data: { asns: ['64496', '64497'], prefix: '192.0.2.0/24' } },
      'routing-status': RIPE['routing-status-moas'],
      'rpki-validation': (u) => json(u.searchParams.get('resource') === 'AS64497' ? RIPE['rpki-invalid-asn'] : RIPE['rpki-valid']),
      peeringdb: (u) => (u.searchParams.get('asn') === '64497' ? json(PDB['not-found'], 404) : json(PDB.net))
    });
    const r = await svc.enrich('192.0.2.10');
    assert.deepEqual(r.rpki.map((x) => [x.asn, x.status]), [[64496, 'valid'], [64497, 'invalid-asn']]);
    assert.deepEqual(r.peeringdb.map((x) => [x.asn, x.net && x.net.id]), [[64496, 1001], [64497, null]], '404: no record, not a failure');
    assert.deepEqual(r.routing.flags, ['moas', 'more-specifics', 'low-visibility']);
    assert.deepEqual(r.errors, []);
    assert.deepEqual(time.sleeps, [PEERINGDB_INTERVAL_MS], 'the second PeeringDB request waited for the pace');
    // Another address of the same origins: PeeringDB is not asked again.
    await svc.enrich('192.0.2.11');
    assert.equal(calls.filter((c) => c.startsWith('peeringdb')).length, 2);
  });

  test('PeeringDB 429: the queue pauses for Retry-After and asks once more; twice is a failure with the wait', async () => {
    const once = service({ ...ALL_OK, peeringdb: (u, n) => (n === 0 ? json({ message: 'slow down' }, 429, { 'retry-after': '6' }) : json(PDB.net)) });
    const r = await once.svc.enrich('192.0.2.10');
    assert.deepEqual([r.errors, r.peeringdb[0].net.id], [[], 1001]);
    assert.deepEqual(once.time.sleeps, [6000]);
    // A Retry-After shorter than the pace still waits for the pace.
    const short = service({ ...ALL_OK, peeringdb: (u, n) => (n === 0 ? json({}, 429, { 'retry-after': '1' }) : json(PDB.net)) });
    await short.svc.enrich('192.0.2.10');
    assert.deepEqual(short.time.sleeps, [PEERINGDB_INTERVAL_MS]);
    // Without a readable Retry-After (the browser: not exposed to CORS) the pause is PeeringDB's 10 s.
    const twice = service({ ...ALL_OK, peeringdb: () => new Response('{}', { status: 429 }) });
    const r2 = await twice.svc.enrich('192.0.2.10');
    assert.deepEqual(r2.errors.map((e) => [e.source, e.status, e.errorKind, e.retryAfterMs, e.asn]), [['peeringdb', 429, 'rate-limit', PEERINGDB_PAUSE_MS, 64496]]);
    assert.deepEqual(twice.time.sleeps, [PEERINGDB_PAUSE_MS], 'one pause, one more try, then the failure');
    assert.equal(twice.calls.filter((c) => c.startsWith('peeringdb')).length, 2);
    // A pause too long to wait out is returned at once.
    const long = service({ ...ALL_OK, peeringdb: () => json({}, 429, { 'retry-after': '120' }) });
    const r3 = await long.svc.enrich('192.0.2.10');
    assert.deepEqual([r3.errors[0].retryAfterMs, long.time.sleeps, long.calls.filter((c) => c.startsWith('peeringdb')).length], [120000, [], 1]);
  });

  test('a parse error and a network error are failures with their kind', async () => {
    const { svc } = service({
      ...ALL_OK,
      'abuse-contact-finder': () => new Response('<html>', { status: 200 }),
      peeringdb: () => { throw new TypeError('Failed to fetch'); }
    });
    const r = await svc.enrich('192.0.2.10');
    assert.deepEqual(r.errors.map((e) => [e.source, e.errorKind]).sort(), [['peeringdb', 'network'], ['ripestat-abuse', 'parse']]);
    assert.equal(r.abuse, null);
  });

  test('an abort rejects (and only an abort); a queued PeeringDB turn is let go', async () => {
    const ctl = new AbortController();
    const { svc } = service({ ...ALL_OK, 'routing-status': () => { ctl.abort(); return json(RIPE['routing-status']); } });
    await assert.rejects(svc.enrich('192.0.2.10', { signal: ctl.signal }), (err) => err.name === 'AbortError');
    await assert.rejects(svc.enrich('192.0.2.10', { signal: ctl.signal }), (err) => err.name === 'AbortError', 'an aborted signal asks nothing');
    // The queue is free again for the next caller.
    const r = await svc.enrich('192.0.2.12');
    assert.deepEqual(r.errors, []);
  });

  test('retry of a skipped or complete result asks nothing', async () => {
    const { svc, calls } = service(ALL_OK);
    const skipped = await createIpEnrich({ fetchImpl: fakeFetch(ALL_OK, calls) }).enrich('10.0.0.1');
    assert.deepEqual(await svc.retry(skipped), skipped);
    const done = await svc.enrich('192.0.2.10');
    const n = calls.length;
    assert.deepEqual(await svc.retry(done), done);
    assert.equal(calls.length, n);
  });
});
