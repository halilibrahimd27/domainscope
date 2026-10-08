// Unit tests for assets/js/lib/soaprobe.js — Global DNS's authoritative SOA question: the zone and
// its name servers over a fake DoH client, the one-probe measurement body, and the name server's
// answer read from Globalping measurements shaped like the live ones (dig text with the authority
// section, the flags line, the NSID). Documentation names only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  SOA_PROBE_PURPOSE, SOA_PROBE_COST, SOA_PLAN_ERRORS, SOA_PROBE_STATES, parseSoaRecord, findZone, pickNameserver, planSoaProbe,
  readSoaProbe, runSoaProbe
} from '../../assets/js/lib/soaprobe.js';

const SOA_DATA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026100801, refresh: 7200, retry: 900, expire: 1209600, minimum: 300 };
const SOA_TEXT = 'ns1.example.com. hostmaster.example.com. 2026100801 7200 900 1209600 300';

/**
 * A fake DohClient over a table: name → { SOA?, NS?, CNAME? }; a missing name answers NXDOMAIN with
 * the zone's SOA in the authority section (as a recursive resolver does), a name without the type
 * NODATA with it. A CNAME is followed into the target's zone, like a resolver.
 */
function fakeDns(zones, { fail = new Set() } = {}) {
  const calls = [];
  const zoneOf = (n) => Object.keys(zones).filter((z) => zones[z].SOA && (n === z || n.endsWith(`.${z}`))).sort((a, b) => b.length - a.length)[0];
  const answer = (name, type) => {
    const node = zones[name];
    const z = zoneOf(name);
    const auth = z ? [{ name: z, type: 'SOA', ttl: zones[z].soaTtl ?? 3600, data: zones[z].SOA }] : [];
    if (!node) return { ok: true, rcode: 'NXDOMAIN', answers: [], authorities: auth };
    if (node.CNAME && type !== 'CNAME') {
      const target = answer(node.CNAME, type);
      return { ...target, rcode: target.rcode, answers: [{ name, type: 'CNAME', ttl: 300, data: node.CNAME }, ...target.answers] };
    }
    const data = node[type];
    if (!data) return { ok: true, rcode: 'NOERROR', answers: [], authorities: auth };
    const list = Array.isArray(data) ? data : [data];
    return { ok: true, rcode: 'NOERROR', answers: list.map((d) => ({ name, type, ttl: type === 'SOA' ? (node.soaTtl ?? 3600) : 3600, data: d })), authorities: [] };
  };
  return {
    calls,
    async query(name, type) {
      calls.push(`${name} ${type}`);
      if (fail.has(`${name} ${type}`)) return { ok: false, error: 'network error', errorKind: 'network' };
      return answer(name, type);
    }
  };
}

const ZONES = {
  'example.com': { SOA: SOA_DATA, NS: ['ns2.example.net', 'ns1.example.com'] },
  'www.example.com': { CNAME: 'lb.example.net' },
  'api.example.com': { A: '192.0.2.10' },
  'example.net': { SOA: { ...SOA_DATA, mname: 'hidden-primary.example.net' }, NS: ['b.ns.example.net', 'a.ns.example.net'] },
  'lb.example.net': { A: '198.51.100.20' },
  'example.org': { SOA: SOA_DATA, NS: ['192.0.2.53', 'ns_bad.example.org'] }
};

/** A finished Globalping DNS measurement of one probe, as the API returns it. */
function measurement({ rcode = 'NOERROR', flags = 'qr aa rd', answers = [], authority = [], nsid = 'ns1-fra', status = 'finished', raw = null } = {}) {
  const line = (rr) => `${rr.name}.\t\t${rr.ttl}\tIN\t${rr.type}\t${rr.value}`;
  const rawOutput = raw ?? [
    '; <<>> DiG 9.18.28 <<>> @ns1.example.com www.example.com SOA +nsid',
    ';; global options: +cmd', ';; Got answer:',
    `;; ->>HEADER<<- opcode: QUERY, status: ${rcode}, id: 4242`,
    `;; flags: ${flags}; QUERY: 1, ANSWER: ${answers.length}, AUTHORITY: ${authority.length}, ADDITIONAL: 1`, '',
    ';; OPT PSEUDOSECTION:', '; EDNS: version: 0, flags:; udp: 1232', `; NSID: 6e 73 ("${nsid}")`,
    ';; QUESTION SECTION:', ';www.example.com.\t\tIN\tSOA', '',
    ...(answers.length ? [';; ANSWER SECTION:', ...answers.map(line), ''] : []),
    ...(authority.length ? [';; AUTHORITY SECTION:', ...authority.map(line), ''] : []),
    ';; Query time: 12 msec', ';; SERVER: 192.0.2.53#53(ns1.example.com) (UDP)'
  ].join('\n');
  return {
    id: 'soaFake0001', type: 'dns', status: 'finished', results: [{
      probe: { continent: 'EU', country: 'DE', city: 'Frankfurt', asn: 64500, network: 'Example Networks', tags: ['datacenter-network'] },
      result: {
        status, rawOutput, statusCodeName: rcode, statusCode: { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5, NOTAUTH: 9 }[rcode] ?? 0,
        answers: answers.map((rr) => ({ name: `${rr.name}.`, type: rr.type, ttl: rr.ttl, class: 'IN', value: rr.value })), timings: { total: 12 }
      }
    }]
  };
}

describe('the zone and its name servers (DoH, free)', () => {
  test('a name below the apex: the authority SOA names the zone; then its NS set, sorted', async () => {
    const dns = fakeDns(ZONES);
    const z = await findZone('api.example.com', { dns });
    assert.deepEqual(z, { ok: true, zone: 'example.com', soa: { ...SOA_DATA, ttl: 3600 }, nameservers: ['ns1.example.com', 'ns2.example.net'] });
    assert.deepEqual(dns.calls, ['api.example.com SOA', 'example.com NS']);
  });

  test('the apex itself: its own SOA; a name that does not exist yet: the zone above it', async () => {
    assert.equal((await findZone('example.com', { dns: fakeDns(ZONES) })).zone, 'example.com');
    assert.equal((await findZone('new.example.com', { dns: fakeDns(ZONES) })).zone, 'example.com', 'a brand-new name still has its zone');
  });

  test('an alias is skipped: a resolver follows it into the target’s zone', async () => {
    const dns = fakeDns(ZONES);
    const z = await findZone('www.example.com', { dns });
    assert.equal(z.zone, 'example.com', 'not example.net, where lb.example.net lives');
    assert.deepEqual(dns.calls, ['www.example.com SOA', 'example.com SOA', 'example.com NS']);
  });

  test('a name under no zone of its own (only a public suffix answers), a failed lookup, no NS set', async () => {
    const tld = { com: { SOA: { ...SOA_DATA, mname: 'a.gtld.example.net' }, NS: ['a.gtld.example.net'] } };
    assert.deepEqual(await findZone('example.com', { dns: fakeDns(tld) }), { ok: false, error: 'no-zone', zone: 'com' });
    const failed = await findZone('api.example.com', { dns: fakeDns(ZONES, { fail: new Set(['api.example.com SOA']) }) });
    assert.equal(failed.error, 'lookup');
    assert.equal(failed.detail, 'network error');
    const bare = { 'example.com': { SOA: SOA_DATA } };
    assert.deepEqual(await findZone('example.com', { dns: fakeDns(bare) }), { ok: false, error: 'no-ns', zone: 'example.com' });
    await assert.rejects(findZone('example.com', {}), TypeError);
  });

  test('pickNameserver: the primary when it is one of them, else the first by name; only what Globalping can ask', () => {
    assert.equal(pickNameserver(['ns2.example.net', 'ns1.example.com'], 'ns1.example.com'), 'ns1.example.com');
    assert.equal(pickNameserver(['b.ns.example.net', 'a.ns.example.net'], 'hidden-primary.example.net'), 'a.ns.example.net', 'a hidden primary is not asked');
    assert.equal(pickNameserver(['192.0.2.53', 'ns_bad.example.org', 'Ns3.Example.org.'], null), 'ns3.example.org');
    assert.equal(pickNameserver(['192.0.2.53'], null), null);
    assert.equal(pickNameserver(null), null);
  });
});

describe('the plan: one probe, one SOA question of the name', () => {
  test('the body asks the chosen name server for the SOA of the name itself', async () => {
    const plan = await planSoaProbe('API.example.com.', { dns: fakeDns(ZONES) });
    assert.equal(plan.ok, true);
    assert.deepEqual([plan.name, plan.zone, plan.ns, plan.probes], ['api.example.com', 'example.com', 'ns1.example.com', 1]);
    assert.deepEqual(plan.body, {
      type: 'dns', target: 'api.example.com', limit: 1, timeout: 15,
      measurementOptions: { query: { type: 'SOA' }, resolver: 'ns1.example.com', protocol: 'UDP', port: 53 }
    });
  });

  test('the check’s own question: its record type (the record set’s TTL there); CAA, which Globalping cannot ask, and no type ask the SOA', async () => {
    const plan = await planSoaProbe('api.example.com', { dns: fakeDns(ZONES), type: 'a' });
    assert.equal(plan.type, 'A');
    assert.deepEqual(plan.body.measurementOptions, { query: { type: 'A' }, resolver: 'ns1.example.com', protocol: 'UDP', port: 53 });
    const caa = await planSoaProbe('api.example.com', { dns: fakeDns(ZONES), type: 'CAA' });
    assert.deepEqual([caa.type, caa.body.measurementOptions.query.type], ['SOA', 'SOA']);
    assert.equal((await planSoaProbe('api.example.com', { dns: fakeDns(ZONES) })).type, 'SOA');
  });

  test('nothing is sent for an internal name, an address, a name Globalping cannot ask, or no name server it can ask', async () => {
    const dns = fakeDns(ZONES);
    assert.deepEqual(await planSoaProbe('printer.local', { dns }), { ok: false, error: 'internal' });
    assert.deepEqual(await planSoaProbe('nas.home.arpa', { dns }), { ok: false, error: 'internal' });
    assert.deepEqual(await planSoaProbe('192.0.2.10', { dns }), { ok: false, error: 'name' });
    assert.deepEqual(await planSoaProbe('*.example.com', { dns }), { ok: false, error: 'name' });
    assert.deepEqual(await planSoaProbe('localhost', { dns }), { ok: false, error: 'name' });
    assert.deepEqual(dns.calls, [], 'refused before any DNS question');
    assert.deepEqual(await planSoaProbe('www.example.org', { dns: fakeDns(ZONES) }), { ok: false, error: 'not-probeable', zone: 'example.org' });
  });

  test('vocabularies', () => {
    assert.equal(SOA_PROBE_PURPOSE, 'soa-probe');
    assert.equal(SOA_PROBE_COST, 1);
    assert.deepEqual([...SOA_PLAN_ERRORS], ['name', 'internal', 'lookup', 'no-zone', 'no-ns', 'not-probeable']);
    assert.deepEqual([...SOA_PROBE_STATES], ['ok', 'not-authoritative', 'refused', 'servfail', 'timeout', 'unreachable', 'failed']);
  });
});

describe('the name server’s answer', () => {
  const plan = { name: 'www.example.com', zone: 'example.com', ns: 'ns1.example.com' };

  test('parseSoaRecord: the seven fields, or null', () => {
    assert.deepEqual(parseSoaRecord(SOA_TEXT), { ...SOA_DATA });
    assert.equal(parseSoaRecord('ns1.example.com. hostmaster.example.com. x 1 2 3 4'), null);
    assert.equal(parseSoaRecord('ns1.example.com. hostmaster.example.com. 1 2 3'), null);
    assert.equal(parseSoaRecord('a. b. 99999999999 1 2 3 4'), null, 'past 32 bits');
    assert.equal(parseSoaRecord(null), null);
  });

  test('a name that exists (NODATA for SOA): the zone’s SOA in the authority section, the negative-cache time', () => {
    const r = readSoaProbe(measurement({ authority: [{ name: 'example.com', ttl: 3600, type: 'SOA', value: SOA_TEXT }] }), plan);
    assert.deepEqual({ state: r.state, exists: r.exists, aa: r.aa, alias: r.alias, negativeTtl: r.negativeTtl, nsid: r.nsid, rttMs: r.rttMs },
      { state: 'ok', exists: true, aa: true, alias: null, negativeTtl: 300, nsid: 'ns1-fra', rttMs: 12 });
    assert.deepEqual(r.soa, { ...SOA_DATA, ttl: 3600 });
    assert.equal(r.measurementId, 'soaFake0001');
    assert.equal(r.probe.city, 'Frankfurt');
  });

  test('the apex: the SOA in the answer; a SOA TTL below the minimum is the negative time (Route 53 style)', () => {
    const route53 = 'ns-1.awsdns.example.net. hostmaster.example.com. 1 7200 900 1209600 86400';
    const r = readSoaProbe(measurement({ answers: [{ name: 'example.com', ttl: 900, type: 'SOA', value: route53 }] }), { ...plan, name: 'example.com' });
    assert.equal(r.state, 'ok');
    assert.equal(r.negativeTtl, 900, 'min(900, 86400)');
    assert.equal(r.soa.minimum, 86400);
  });

  test('NXDOMAIN at the source: the name does not exist there (yet)', () => {
    const r = readSoaProbe(measurement({ rcode: 'NXDOMAIN', authority: [{ name: 'example.com', ttl: 300, type: 'SOA', value: SOA_TEXT }] }), plan);
    assert.deepEqual([r.state, r.exists, r.negativeTtl], ['ok', false, 300]);
  });

  test('an alias at the source: its target', () => {
    const r = readSoaProbe(measurement({ answers: [{ name: 'www.example.com', ttl: 300, type: 'CNAME', value: 'lb.example.net.' }] }), plan);
    assert.deepEqual([r.state, r.exists, r.alias, r.soa], ['ok', true, 'lb.example.net', null]);
  });

  test('the record type asked: the record set’s TTL there, the longest of the answer; none without a record of that type', () => {
    const chain = [{ name: 'www.example.com', ttl: 300, type: 'CNAME', value: 'lb.example.com.' }, { name: 'lb.example.com', ttl: 3600, type: 'A', value: '198.51.100.20' }];
    const a = readSoaProbe(measurement({ answers: chain }), { ...plan, type: 'A' });
    assert.deepEqual([a.state, a.type, a.ttl, a.alias, a.soa, a.negativeTtl], ['ok', 'A', 3600, 'lb.example.com', null, null]);
    const away = readSoaProbe(measurement({ answers: chain.slice(0, 1) }), { ...plan, type: 'A' });
    assert.equal(away.ttl, null, 'an alias that leaves the zone: the record’s own TTL is not in this answer');
    const nodata = readSoaProbe(measurement({ authority: [{ name: 'example.com', ttl: 3600, type: 'SOA', value: SOA_TEXT }] }), { ...plan, type: 'AAAA' });
    assert.deepEqual([nodata.ttl, nodata.negativeTtl, nodata.exists], [null, 300, true], 'no record of the type: the SOA and the negative-cache time');
    const apex = readSoaProbe(measurement({ answers: [{ name: 'example.com', ttl: 3600, type: 'SOA', value: SOA_TEXT }] }), { ...plan, name: 'example.com' });
    assert.deepEqual([apex.type, apex.ttl], ['SOA', 3600], 'no type: the SOA question; at the apex, the SOA record’s TTL');
    assert.equal(readSoaProbe(measurement({ rcode: 'SERVFAIL' }), { ...plan, type: 'A' }).ttl, null);
  });

  test('a lame server: no authoritative flag, NOTAUTH, REFUSED, SERVFAIL', () => {
    const noAa = readSoaProbe(measurement({ flags: 'qr rd ra', authority: [{ name: 'example.com', ttl: 3600, type: 'SOA', value: SOA_TEXT }] }), plan);
    assert.deepEqual([noAa.state, noAa.aa], ['not-authoritative', false]);
    assert.equal(readSoaProbe(measurement({ rcode: 'NOTAUTH' }), plan).state, 'not-authoritative');
    assert.equal(readSoaProbe(measurement({ rcode: 'REFUSED' }), plan).state, 'refused');
    assert.equal(readSoaProbe(measurement({ rcode: 'SERVFAIL' }), plan).state, 'servfail');
  });

  test('no answer: timed out, unreachable, failed — with dig’s line', () => {
    const out = (raw) => readSoaProbe(measurement({ status: 'failed', raw }), plan);
    const timeout = out(';; connection timed out; no servers could be reached\n');
    assert.deepEqual([timeout.state, timeout.exists], ['timeout', null]);
    assert.match(timeout.error, /timed out/);
    assert.equal(out('dig: couldn\'t get address for \'ns1.example.com\': not found\n').state, 'unreachable');
    assert.equal(out('something else\n').state, 'failed');
    assert.equal(readSoaProbe({}, plan).state, 'failed');
  });
});

describe('runSoaProbe', () => {
  test('measures the planned body once and reads the answer', async () => {
    const plan = await planSoaProbe('www.example.com', { dns: fakeDns(ZONES) });
    const sent = [];
    const client = {
      async measure(body, opts) {
        sent.push({ body, signal: opts.signal });
        return { measurement: measurement({ authority: [{ name: 'example.com', ttl: 3600, type: 'SOA', value: SOA_TEXT }] }), id: 'soaFake0001', cost: 1, quota: { remaining: 249 } };
      }
    };
    const ac = new AbortController();
    const out = await runSoaProbe(plan, { client, signal: ac.signal });
    assert.equal(sent.length, 1);
    assert.equal(sent[0].body, plan.body);
    assert.equal(sent[0].signal, ac.signal);
    assert.deepEqual([out.id, out.cost, out.quota.remaining, out.result.state, out.result.negativeTtl], ['soaFake0001', 1, 249, 'ok', 300]);
    const asked = await planSoaProbe('api.example.com', { dns: fakeDns(ZONES), type: 'A' });
    const answered = { async measure() { return { measurement: measurement({ answers: [{ name: 'api.example.com', ttl: 3600, type: 'A', value: '192.0.2.10' }] }), id: 'soaFake0002', cost: 1 }; } };
    const a = (await runSoaProbe(asked, { client: answered })).result;
    assert.deepEqual([a.type, a.ttl], ['A', 3600], 'the type the plan asked');
  });

  test('a Globalping error is thrown as it came; no client or plan is a TypeError', async () => {
    const err = Object.assign(new Error('quota'), { code: 'rate-limit' });
    await assert.rejects(runSoaProbe({ name: 'a.example.com', zone: 'example.com', ns: 'ns1.example.com', body: {} }, { client: { measure: async () => { throw err; } } }), (e) => e === err);
    await assert.rejects(runSoaProbe({ body: {} }, {}), TypeError);
    await assert.rejects(runSoaProbe(null, { client: { measure: async () => ({}) } }), TypeError);
  });
});
