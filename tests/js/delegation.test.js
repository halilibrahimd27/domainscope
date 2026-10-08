/**
 * lib/delegation.js: the dig-text readers, the per-server verdicts, the Sitting Ducks providers,
 * the free DoH plan and the Globalping run with a fake client (no network): lame servers,
 * serial drift, NS sets, glue, open recursion, the parent's referral, stops and the budget.
 * Documentation names and addresses only; d01 / d09 are the scrubbed live captures.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  digFlags, digRecords, digNsid, readDnsTest, parseSoaValue, soaState, recursionState, takeoverProvider, glueState, readReferral,
  prepareDelegation, runDelegation, assessDelegation, delegationSummary, planDelegationProbes,
  SERVER_STATES, LAME_STATES, TAKEOVER_STATES, DELEGATION_FINDINGS, FINDING_SEVERITY, SITTING_DUCKS_PROVIDERS, SITTING_DUCKS_REFERENCES,
  TAKEOVER_RISKS, RECURSION_PROBE_NAMES
} from '../../assets/js/lib/delegation.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'globalping');
const fixture = (name) => JSON.parse(readFileSync(join(FIX, `${name}.json`), 'utf8'));

const PROBE = { continent: 'EU', country: 'DE', city: 'Frankfurt', asn: 64500, network: 'Example Net', tags: ['datacenter-network'] };
const hex = (s) => [...s].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');

/** A dig text in the probes' format (dig 9.18), from presentation-format records. */
function digText({ name, type, server, rcode = 'NOERROR', flags = 'qr aa rd', answer = [], authority = [], additional = [], nsid = null }) {
  const lines = ['', `; <<>> DiG 9.18.49-1~deb12u2-Debian <<>> -t ${type} ${name} @${server} -p 53 -4 +timeout=7 +tries=2 +nofail +nocookie +nosplit +nsid`,
    ';; global options: +cmd', ';; Got answer:', `;; ->>HEADER<<- opcode: QUERY, status: ${rcode}, id: 4242`,
    `;; flags: ${flags}; QUERY: 1, ANSWER: ${answer.length}, AUTHORITY: ${authority.length}, ADDITIONAL: ${additional.length + 1}`];
  if (!flags.split(' ').includes('ra')) lines.push(';; WARNING: recursion requested but not available');
  lines.push('', ';; OPT PSEUDOSECTION:', '; EDNS: version: 0, flags:; udp: 1232');
  if (nsid) lines.push(`; NSID: ${hex(nsid)} ("${nsid}")`);
  lines.push(';; QUESTION SECTION:', `;${name}.\t\t\tIN\t${type}`, '');
  for (const [title, list] of [['ANSWER', answer], ['AUTHORITY', authority], ['ADDITIONAL', additional]]) {
    if (!list.length) continue;
    lines.push(`;; ${title} SECTION:`, ...list, '');
  }
  lines.push(';; Query time: 12 msec', `;; SERVER: 192.0.2.53#53(${server}) (UDP)`, ';; MSG SIZE  rcvd: 120', '');
  return lines.join('\n');
}

const rr = (name, type, value, ttl = 3600) => `${name}.\t\t${ttl}\tIN\t${type}\t${value}`;
const asJson = (line) => {
  const [name, ttl, cls, type, ...rest] = line.split(/\s+/);
  return { name, type, ttl: Number(ttl), class: cls, value: rest.join(' ') };
};

/** A finished Globalping DNS measurement. */
function measurement(spec) {
  const answer = spec.answer || [];
  return {
    id: spec.id || 'm', type: 'dns', status: 'finished',
    results: [{
      probe: PROBE,
      result: {
        status: 'finished', rawOutput: digText(spec), statusCodeName: spec.rcode || 'NOERROR', statusCode: { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 }[spec.rcode || 'NOERROR'],
        answers: answer.map(asJson), timings: { total: spec.rtt ?? 12 }, resolver: spec.server
      }
    }]
  };
}

/** A measurement whose test failed (dig could not reach the server). */
function failedMeasurement(server, text = ';; communications error to 192.0.2.53#53: timed out\n;; no servers could be reached') {
  return { id: 'f', type: 'dns', status: 'finished', results: [{ probe: PROBE, result: { status: 'failed', rawOutput: `\n; <<>> DiG 9.18 <<>> @${server}\n${text}\n`, resolver: server } }] };
}

const SOA = (mname, serial) => `${mname}. hostmaster.example.com. ${serial} 7200 3600 1209600 3600`;

/**
 * A fake Globalping client: `routes['<resolver>|<name>|<type>']` → a measurement spec, a
 * measurement, a function, or an Error to throw. Every body is recorded.
 */
function fakeClient(routes, { onCall } = {}) {
  const calls = [];
  let n = 0;
  return {
    calls,
    async measure(body, { signal } = {}) {
      if (signal && signal.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
      const key = `${body.measurementOptions.resolver}|${body.target}|${body.measurementOptions.query.type}`;
      calls.push(key);
      if (onCall) await onCall(key, calls.length);
      n += 1;
      const id = `meas${String(n).padStart(4, '0')}`;
      let route = routes[key];
      if (typeof route === 'function') route = route(body);
      if (route instanceof Error) throw route;
      if (!route) return { measurement: failedMeasurement(body.measurementOptions.resolver), id, cost: 1, quota: { remaining: 200 - n } };
      const m = route.results ? route : measurement({ name: body.target, type: body.measurementOptions.query.type, server: body.measurementOptions.resolver, ...route });
      return { measurement: m, id, cost: 1, quota: { remaining: 200 - n } };
    }
  };
}

/** A fake DohClient from a table `name|type` → answers data (array) or an rcode string / failure. */
function fakeDns(table) {
  const asked = [];
  return {
    asked,
    async query(name, type) {
      asked.push(`${name}|${type}`);
      const v = table[`${name}|${type}`];
      if (v === 'fail') return { ok: false, rcode: null, answers: [], authorities: [], error: 'network', errorKind: 'network' };
      if (typeof v === 'string') return { ok: true, rcode: v, answers: [], authorities: [] };
      return { ok: true, rcode: 'NOERROR', answers: (v || []).map((data) => ({ name, type, ttl: 300, data })), authorities: [] };
    }
  };
}

const ZONE_DNS = {
  'example.com|NS': ['ns1.example.com', 'ns2.example.net'],
  'ns1.example.com|A': ['192.0.2.53'], 'ns1.example.com|AAAA': ['2001:db8::53'],
  'ns2.example.net|A': ['198.51.100.53'], 'ns2.example.net|AAAA': [],
  'com|NS': ['b.tld-servers.example.net', 'a.tld-servers.example.net']
};

/** Routes for a sound delegation of example.com. */
function soundRoutes() {
  const ns = [rr('example.com', 'NS', 'ns1.example.com.'), rr('example.com', 'NS', 'ns2.example.net.')];
  return {
    'ns1.example.com|example.com|SOA': { answer: [rr('example.com', 'SOA', SOA('ns1.example.com', 2026100801))], nsid: 'ns1-fra' },
    'ns2.example.net|example.com|SOA': { answer: [rr('example.com', 'SOA', SOA('ns1.example.com', 2026100801))] },
    'ns1.example.com|example.com|NS': { answer: ns },
    'ns2.example.net|example.com|NS': { answer: ns },
    'ns1.example.com|example.net|A': { rcode: 'REFUSED', flags: 'qr rd' },
    'ns2.example.net|example.net|A': { rcode: 'REFUSED', flags: 'qr rd' },
    'a.tld-servers.example.net|example.com|NS': {
      flags: 'qr rd', authority: ns, additional: [rr('ns1.example.com', 'A', '192.0.2.53'), rr('ns1.example.com', 'AAAA', '2001:db8::53')]
    }
  };
}

describe('dig text', () => {
  test('the live SOA and REFUSED captures read as answers with their flags', () => {
    const soa = readDnsTest(fixture('d01-soa').final.body);
    assert.equal(soa.ok, true);
    assert.equal(soa.rcode, 'NOERROR');
    assert.deepEqual([soa.aa, soa.ra, soa.tc], [true, false, false]);
    assert.equal(soa.rttMs, 176);
    assert.equal(soa.answers[0].type, 'SOA');
    assert.deepEqual(parseSoaValue(soa.answers[0].value), { mname: 'ns1.example.net', serial: 2026092401 });
    assert.equal(soaState(soa, 'example.com'), 'ok');
    assert.equal(soa.probe.city, 'Lagos');
    const refused = readDnsTest(fixture('d09-refused').final.body);
    assert.deepEqual([refused.rcode, refused.aa], ['REFUSED', false]);
    assert.equal(soaState(refused, 'example.com'), 'refused');
  });

  test('a referral: NS in the authority section, glue in the additional one, the NSID text', () => {
    const raw = digText({
      name: 'example.com', type: 'NS', server: 'a.tld-servers.example.net', flags: 'qr rd', nsid: 'tld-ams1',
      authority: [rr('example.com', 'NS', 'ns1.example.com.')], additional: [rr('ns1.example.com', 'A', '192.0.2.53')]
    });
    assert.deepEqual(digFlags(raw), { aa: false, ra: false, tc: false });
    assert.deepEqual(digRecords(raw, 'AUTHORITY'), [{ name: 'example.com', type: 'NS', ttl: 3600, value: 'ns1.example.com.' }]);
    assert.deepEqual(digRecords(raw, 'ADDITIONAL').map((r) => r.value), ['192.0.2.53']);
    assert.equal(digNsid(raw), 'tld-ams1');
    assert.equal(digNsid('; NSID: 01 02 ("\u0007")'), null, 'nothing printable is no NSID');
    assert.deepEqual(digFlags('no flags here'), { aa: null, ra: null, tc: null });
    assert.deepEqual(digRecords('', 'ANSWER'), []);
  });

  test('a test that never got an answer: timeout, unreachable or failed, with its line', () => {
    const t1 = readDnsTest(failedMeasurement('ns1.example.com'));
    assert.deepEqual([t1.ok, t1.failure], [false, 'timeout']);
    assert.equal(soaState(t1, 'example.com'), 'timeout');
    const t2 = readDnsTest(failedMeasurement('ns1.example.com', 'dig: couldn\'t get address for \'ns1.example.com\': not found'));
    assert.equal(t2.failure, 'unreachable');
    assert.match(t2.error, /couldn't get address/);
    assert.equal(soaState(readDnsTest(null), 'example.com'), 'failed');
  });

  test('parseSoaValue refuses what is not an SOA', () => {
    assert.equal(parseSoaValue('ns1.example.com.'), null);
    assert.equal(parseSoaValue('a. b. 99999999999 1 2 3 4'), null);
    assert.equal(parseSoaValue('a. b. x 1 2 3 4'), null);
  });
});

describe('per-server verdicts', () => {
  const test0 = (spec) => readDnsTest(measurement({ name: 'example.com', type: 'SOA', server: 'ns1.example.com', ...spec }));
  test('the SOA states', () => {
    assert.equal(soaState(test0({ answer: [rr('example.com', 'SOA', SOA('ns1.example.com', 1))] }), 'example.com'), 'ok');
    assert.equal(soaState(test0({ flags: 'qr rd', answer: [rr('example.com', 'SOA', SOA('ns1.example.com', 1))] }), 'example.com'), 'not-authoritative');
    assert.equal(soaState(test0({ rcode: 'SERVFAIL', flags: 'qr rd' }), 'example.com'), 'servfail');
    assert.equal(soaState(test0({ rcode: 'NXDOMAIN' }), 'example.com'), 'no-zone');
    // an upward referral (a server that does not serve the zone and points at the root)
    assert.equal(soaState(test0({ flags: 'qr rd', authority: [rr('', 'NS', 'a.root-servers.example.net.')] }), 'example.com'), 'no-zone');
    for (const s of LAME_STATES) assert.ok(SERVER_STATES.includes(s), s);
    for (const s of TAKEOVER_STATES) assert.ok(LAME_STATES.includes(s), s);
  });

  test('recursion: an unrelated name answered without the authoritative flag is an open resolver', () => {
    const ask = (spec) => readDnsTest(measurement({ name: 'example.net', type: 'A', server: 'ns1.example.com', ...spec }));
    assert.equal(recursionState(ask({ flags: 'qr rd ra', answer: [rr('example.net', 'A', '192.0.2.80')] }), 'example.net'), 'open');
    assert.equal(recursionState(ask({ flags: 'qr aa rd', answer: [rr('example.net', 'A', '192.0.2.80')] }), 'example.net'), 'closed', 'its own zone too');
    assert.equal(recursionState(ask({ rcode: 'REFUSED', flags: 'qr rd ra' }), 'example.net'), 'closed', 'ra alone is no recursion');
    assert.equal(recursionState(ask({ flags: 'qr rd' }), 'example.net'), 'closed');
    assert.equal(recursionState(readDnsTest(failedMeasurement('ns1.example.com')), 'example.net'), 'unknown');
  });

  test('Sitting Ducks providers: exact name-server patterns, a risk each, references', () => {
    assert.deepEqual(takeoverProvider('NS1.DigitalOcean.com.'), { id: 'digitalocean', name: 'DigitalOcean', risk: 'claimable' });
    assert.equal(takeoverProvider('ns3.he.net').id, 'he');
    assert.equal(takeoverProvider('ns1-05.azure-dns.com').risk, 'edge');
    assert.equal(takeoverProvider('ns-cloud-a1.googledomains.com').id, 'googlecloud');
    assert.equal(takeoverProvider('ns1.example.com'), null);
    assert.equal(takeoverProvider('xns1.digitalocean.com'), null, 'anchored');
    assert.equal(takeoverProvider('ns1.digitalocean.com.example.net'), null, 'anchored at the end');
    const ids = SITTING_DUCKS_PROVIDERS.map((p) => p.id);
    assert.equal(new Set(ids).size, ids.length, 'unique ids');
    for (const p of SITTING_DUCKS_PROVIDERS) assert.ok(TAKEOVER_RISKS.includes(p.risk), p.id);
    for (const r of SITTING_DUCKS_REFERENCES) assert.match(r.url, /^https:\/\//);
  });

  test('glue states', () => {
    const child = { a: ['192.0.2.53'], aaaa: ['2001:db8::53'], known: true };
    assert.equal(glueState({ a: ['192.0.2.53'], aaaa: ['2001:db8::53'] }, child, { parentOk: true }), 'ok');
    assert.equal(glueState({ a: [], aaaa: [] }, child, { parentOk: true }), 'missing');
    assert.equal(glueState({ a: [], aaaa: [] }, child, { parentOk: true, truncated: true }), 'unknown', 'a truncated referral proves nothing');
    assert.equal(glueState({ a: ['192.0.2.99'], aaaa: [] }, child, { parentOk: true }), 'differs', 'stale glue');
    assert.equal(glueState({ a: ['192.0.2.53'], aaaa: [] }, child, { parentOk: true }), 'partial', 'no IPv6 glue');
    assert.equal(glueState({ a: ['192.0.2.53'], aaaa: [] }, { ...child, known: false }, { parentOk: true }), 'unknown');
    assert.equal(glueState(null, child, { parentOk: false }), 'unknown');
  });

  test('readReferral: the delegated set, glue by host, a parent that serves the zone too, no delegation', () => {
    const ref = readReferral(readDnsTest(measurement({
      name: 'example.com', type: 'NS', server: 'a.tld-servers.example.net', flags: 'qr rd tc',
      authority: [rr('example.com', 'NS', 'ns2.example.com.'), rr('example.com', 'NS', 'ns1.example.com.')],
      additional: [rr('ns1.example.com', 'A', '192.0.2.53'), rr('ns1.example.com', 'AAAA', '2001:DB8:0::53'), rr('ns1.example.com', 'A', '203.0.113.300')]
    })), 'example.com');
    assert.equal(ref.state, 'ok');
    assert.deepEqual(ref.ns, ['ns1.example.com', 'ns2.example.com']);
    assert.deepEqual(ref.glue, { 'ns1.example.com': { a: ['192.0.2.53'], aaaa: ['2001:db8::53'] } }, 'normalised; an invalid address dropped');
    assert.equal(ref.truncated, true);
    const own = readReferral(readDnsTest(measurement({ name: 'example.com', type: 'NS', server: 'ns.example.net', answer: [rr('example.com', 'NS', 'ns1.example.com.')] })), 'example.com');
    assert.deepEqual([own.state, own.ns], ['ok', ['ns1.example.com']]);
    const gone = readReferral(readDnsTest(measurement({ name: 'example.com', type: 'NS', server: 'ns.example.net', rcode: 'NXDOMAIN', flags: 'qr aa rd' })), 'example.com');
    assert.equal(gone.state, 'no-delegation');
    assert.equal(readReferral(readDnsTest(failedMeasurement('ns.example.net')), 'example.com').state, 'timeout');
  });
});

describe('prepareDelegation (DoH only)', () => {
  test('the delegation, the addresses, the parent server, the unrelated name and the cost', async () => {
    const dns = fakeDns({
      ...ZONE_DNS,
      'example.com|NS': ['ns1.example.com', 'ns2.example.net', 'ns3.example.org', 'ns6.example.org'],
      'ns3.example.org|A': 'NXDOMAIN', 'ns3.example.org|AAAA': 'NXDOMAIN',
      'ns6.example.org|A': [], 'ns6.example.org|AAAA': ['2001:db8::6']
    });
    const prep = await prepareDelegation('Example.COM.', { dns });
    assert.equal(prep.ok, true);
    assert.equal(prep.zone, 'example.com');
    assert.deepEqual(prep.delegation, ['ns1.example.com', 'ns2.example.net', 'ns3.example.org', 'ns6.example.org']);
    assert.deepEqual(prep.servers.map((s) => [s.ns, s.skip]), [
      ['ns1.example.com', null], ['ns2.example.net', null], ['ns3.example.org', 'no-address'], ['ns6.example.org', 'ipv6-only']
    ]);
    assert.deepEqual(prep.parent, { zone: 'com', server: 'a.tld-servers.example.net', servers: ['a.tld-servers.example.net', 'b.tld-servers.example.net'] });
    assert.equal(prep.recursionName, 'example.net');
    assert.equal(prep.probes, 2 * 3 + 1);
    assert.equal(planDelegationProbes(prep, { recursion: false, parent: false }), 4);
    assert.ok(!dns.asked.some((q) => q.startsWith('example.net|')), 'the unrelated name never goes to DoH');
  });

  test('another unrelated name inside the zone checked; the parent walks up past a name that is no zone', async () => {
    const dns = fakeDns({
      'a.example.net|NS': ['ns1.example.com'], 'ns1.example.com|A': ['192.0.2.53'], 'ns1.example.com|AAAA': [],
      'example.net|NS': ['ns1.example.org'], 'net|NS': ['a.tld-servers.example.net']
    });
    const prep = await prepareDelegation('a.example.net', { dns });
    assert.equal(prep.recursionName, 'example.org');
    assert.deepEqual([prep.parent.zone, prep.parent.server], ['example.net', 'ns1.example.org']);
    const deeper = await prepareDelegation('a.example.net', { dns: fakeDns({ ...{ 'a.example.net|NS': ['ns1.example.com'], 'ns1.example.com|A': ['192.0.2.53'] }, 'example.net|NS': 'NOERROR', 'net|NS': ['a.tld-servers.example.net'] }) });
    assert.deepEqual([deeper.parent.zone, deeper.parent.server], ['net', 'a.tld-servers.example.net']);
  });

  test('nothing to plan: an unqueryable name, a failed lookup, no NS set, nothing probeable', async () => {
    assert.deepEqual(await prepareDelegation('com', { dns: fakeDns({}) }), { ok: false, zone: 'com', why: 'not-queryable' });
    assert.equal((await prepareDelegation('example.com', { dns: fakeDns({ 'example.com|NS': 'fail' }) })).why, 'lookup-failed');
    assert.equal((await prepareDelegation('example.com', { dns: fakeDns({ 'example.com|NS': 'NXDOMAIN' }) })).why, 'no-ns');
    const none = await prepareDelegation('example.com', { dns: fakeDns({ 'example.com|NS': ['ns1.example.org'], 'ns1.example.org|A': 'NXDOMAIN', 'ns1.example.org|AAAA': 'NXDOMAIN', 'com|NS': 'fail' }) });
    assert.equal(none.why, 'nothing-to-ask');
    await assert.rejects(() => prepareDelegation('example.com', {}), TypeError);
  });
});

describe('runDelegation (fake Globalping)', () => {
  test('a sound delegation: every server authoritative, one serial, one NS set, closed, glue matching', async () => {
    const prep = await prepareDelegation('example.com', { dns: fakeDns(ZONE_DNS) });
    const client = fakeClient(soundRoutes());
    const progress = [];
    const seen = [];
    const result = await runDelegation(prep, { client, onProgress: (p) => progress.push(p), onServer: (s) => seen.push(s.ns), now: () => new Date(0) });
    assert.equal(client.calls.length, 7);
    assert.equal(new Set(client.calls).size, 7, 'each question once');
    assert.deepEqual(result.servers.map((s) => [s.ns, s.state, s.serial, s.nsState, s.recursion]), [
      ['ns1.example.com', 'ok', 2026100801, 'same', 'closed'], ['ns2.example.net', 'ok', 2026100801, 'same', 'closed']
    ]);
    assert.equal(result.servers[0].nsid, 'ns1-fra');
    assert.equal(result.servers[0].inBailiwick, true);
    assert.equal(result.servers[0].measurementIds.length, 3);
    assert.deepEqual(result.glue, [{ host: 'ns1.example.com', state: 'ok', glue: { a: ['192.0.2.53'], aaaa: ['2001:db8::53'] }, child: { a: ['192.0.2.53'], aaaa: ['2001:db8::53'] } }]);
    assert.equal(result.parent.state, 'ok');
    assert.deepEqual(result.findings.map((f) => f.code), ['consistent']);
    assert.deepEqual(delegationSummary(result), { verdict: 'ok', errors: 0, warnings: 0 });
    assert.deepEqual([result.spent, result.planned, result.stoppedBy, result.measurementIds.length], [7, 7, null, 7]);
    assert.deepEqual(progress.at(-1), { done: 7, total: 7, spent: 7 });
    assert.deepEqual(seen.sort(), ['ns1.example.com', 'ns2.example.net']);
  });

  test('a lame DigitalOcean server is a Sitting Ducks risk; drift, NS mismatch, open recursion and stale glue', async () => {
    const dns = fakeDns({
      ...ZONE_DNS,
      'example.com|NS': ['ns1.digitalocean.com', 'ns1.example.com', 'ns2.example.net', 'ns3.example.net'],
      'ns1.digitalocean.com|A': ['203.0.113.10'], 'ns1.digitalocean.com|AAAA': [],
      'ns3.example.net|A': ['198.51.100.54'], 'ns3.example.net|AAAA': []
    });
    const prep = await prepareDelegation('example.com', { dns });
    const routes = soundRoutes();
    routes['ns1.digitalocean.com|example.com|SOA'] = { rcode: 'REFUSED', flags: 'qr rd' };
    routes['ns1.digitalocean.com|example.net|A'] = { rcode: 'REFUSED', flags: 'qr rd' };
    routes['ns2.example.net|example.com|SOA'] = { answer: [rr('example.com', 'SOA', SOA('ns1.example.com', 2026100700))] };
    routes['ns2.example.net|example.net|A'] = { flags: 'qr rd ra', answer: [rr('example.net', 'A', '192.0.2.80')] };
    routes['ns3.example.net|example.com|SOA'] = { answer: [rr('example.com', 'SOA', SOA('ns1.example.com', 2026100801))] };
    routes['ns3.example.net|example.com|NS'] = { answer: [rr('example.com', 'NS', 'ns3.example.net.')] };
    routes['ns3.example.net|example.net|A'] = { rcode: 'REFUSED', flags: 'qr rd' };
    // the parent still delegates to an old server and hands out a stale address for ns1
    routes['a.tld-servers.example.net|example.com|NS'] = {
      flags: 'qr rd', authority: ['ns1.digitalocean.com', 'ns1.example.com', 'ns2.example.net', 'ns9.example.org'].map((n) => rr('example.com', 'NS', `${n}.`)),
      additional: [rr('ns1.example.com', 'A', '192.0.2.99')]
    };
    const client = fakeClient(routes);
    const result = await runDelegation(prep, { client });
    const byNs = Object.fromEntries(result.servers.map((s) => [s.ns, s]));
    assert.equal(byNs['ns1.digitalocean.com'].state, 'refused');
    assert.ok(!client.calls.includes('ns1.digitalocean.com|example.com|NS'), 'no NS question to a server that refused the zone');
    assert.equal(byNs['ns1.digitalocean.com'].recursion, 'closed', 'but the unrelated name was asked');
    assert.equal(byNs['ns2.example.net'].recursion, 'open');
    assert.equal(byNs['ns2.example.net'].ra, true);
    assert.deepEqual([byNs['ns3.example.net'].nsState, byNs['ns3.example.net'].missing.length, byNs['ns3.example.net'].extra], ['differs', 3, []]);
    const codes = result.findings.map((f) => f.code);
    assert.deepEqual(codes, ['lame', 'sitting-ducks', 'serial-drift', 'ns-mismatch', 'parent-child', 'glue-differs', 'open-recursion']);
    const f = Object.fromEntries(result.findings.map((x) => [x.code, x]));
    assert.deepEqual(f.lame.servers, ['ns1.digitalocean.com']);
    assert.deepEqual([f['sitting-ducks'].severity, f['sitting-ducks'].params.providers], ['error', 'DigitalOcean']);
    assert.equal(f['serial-drift'].params.serials, '2026100700, 2026100801');
    assert.deepEqual(f['serial-drift'].servers.sort(), ['ns1.example.com', 'ns2.example.net', 'ns3.example.net']);
    assert.deepEqual([f['parent-child'].params.parentOnly, f['parent-child'].params.childOnly], ['ns9.example.org', 'ns3.example.net']);
    assert.deepEqual(f['glue-differs'].servers, ['ns1.example.com']);
    assert.equal(delegationSummary(result).verdict, 'error');
    for (const x of result.findings) assert.equal(x.severity, x.code === 'sitting-ducks' ? 'error' : FINDING_SEVERITY[x.code], x.code);
  });

  test('servers of two primaries: a multi-provider setup, serials not compared', async () => {
    const prep = await prepareDelegation('example.com', { dns: fakeDns(ZONE_DNS) });
    const routes = soundRoutes();
    routes['ns2.example.net|example.com|SOA'] = { answer: [rr('example.com', 'SOA', SOA('ns2.example.net', 7))] };
    const result = await runDelegation(prep, { client: fakeClient(routes) });
    assert.deepEqual(result.findings.map((f) => f.code), ['multi-provider', 'consistent']);
    assert.equal(result.findings[0].params.primaries, 'ns1.example.com, ns2.example.net');
    assert.equal(delegationSummary(result).verdict, 'ok');
  });

  test('a timeout costs one probe; missing glue for an in-bailiwick server; an edge provider is a warning', async () => {
    const dns = fakeDns({ ...ZONE_DNS, 'example.com|NS': ['ns1.example.com', 'ns1-01.azure-dns.com'], 'ns1-01.azure-dns.com|A': ['203.0.113.20'], 'ns1-01.azure-dns.com|AAAA': [] });
    const prep = await prepareDelegation('example.com', { dns });
    const routes = soundRoutes();
    delete routes['ns1.example.com|example.com|SOA']; // the fake answers a timeout
    routes['ns1-01.azure-dns.com|example.com|SOA'] = { rcode: 'SERVFAIL', flags: 'qr rd' };
    routes['ns1-01.azure-dns.com|example.net|A'] = { rcode: 'REFUSED', flags: 'qr rd' };
    routes['a.tld-servers.example.net|example.com|NS'] = { flags: 'qr rd', authority: [rr('example.com', 'NS', 'ns1.example.com.'), rr('example.com', 'NS', 'ns1-01.azure-dns.com.')] };
    const client = fakeClient(routes);
    const result = await runDelegation(prep, { client });
    assert.deepEqual(client.calls.filter((c) => c.startsWith('ns1.example.com|')), ['ns1.example.com|example.com|SOA']);
    assert.equal(result.servers.find((s) => s.ns === 'ns1.example.com').state, 'timeout');
    const f = Object.fromEntries(result.findings.map((x) => [x.code, x]));
    assert.deepEqual(f.lame.servers.sort(), ['ns1-01.azure-dns.com', 'ns1.example.com']);
    assert.equal(f['sitting-ducks'].severity, 'warn');
    assert.deepEqual(f['glue-missing'].servers, ['ns1.example.com']);
    assert.ok(result.spent < result.planned, `spent ${result.spent} < planned ${result.planned}`);
  });

  test('the quota runs out: the run stops, says when it comes back, and sends nothing more', async () => {
    const prep = await prepareDelegation('example.com', { dns: fakeDns(ZONE_DNS) });
    const resetAt = new Date('2026-10-08T12:00:00Z');
    const routes = soundRoutes();
    let count = 0;
    const client = fakeClient(routes, {
      onCall: () => {
        count += 1;
        if (count === 3) throw Object.assign(new Error('rate limit'), { code: 'rate-limit', resetAt });
      }
    });
    const result = await runDelegation(prep, { client });
    assert.equal(result.stoppedBy, 'quota');
    assert.equal(result.resetAt, resetAt);
    assert.equal(client.calls.length, 3, 'nothing after the 429');
    assert.ok(result.servers.some((s) => s.state === 'not-run' || s.recursion === 'not-run' || !s.nsSet));
    assert.notEqual(delegationSummary(result).verdict, 'ok');
  });

  test('the budget caps the measurements; an abort ends the run without rejecting', async () => {
    const prep = await prepareDelegation('example.com', { dns: fakeDns(ZONE_DNS) });
    const capped = fakeClient(soundRoutes());
    const r1 = await runDelegation(prep, { client: capped, maxProbes: 3 });
    assert.equal(capped.calls.length, 3);
    assert.equal(r1.planned, 3);
    assert.ok(r1.findings.some((f) => f.code === 'not-asked'));
    const ac = new AbortController();
    const slow = fakeClient(soundRoutes(), { onCall: (key, n) => { if (n === 2) ac.abort(); } });
    const r2 = await runDelegation(prep, { client: slow, signal: ac.signal });
    assert.equal(r2.stoppedBy, 'abort');
    assert.ok(slow.calls.length <= 4, `stopped early (${slow.calls.length})`);
  });

  test('three network failures in a row stop the run as unreachable; a refused body costs nothing', async () => {
    const prep = await prepareDelegation('example.com', { dns: fakeDns(ZONE_DNS) });
    const net = fakeClient(Object.fromEntries(Object.keys(soundRoutes()).map((k) => [k, new TypeError('fetch failed')])));
    const r = await runDelegation(prep, { client: net });
    assert.equal(r.stoppedBy, 'unreachable');
    assert.equal(net.calls.length, 3);
    assert.equal(r.spent, 0);
    const refused = fakeClient(Object.fromEntries(Object.keys(soundRoutes()).map((k) => [k, Object.assign(new Error('bad'), { code: 'validation' })])));
    const r2 = await runDelegation(prep, { client: refused });
    assert.equal(r2.spent, 0);
    assert.equal(r2.stoppedBy, null);
    assert.ok(r2.servers.every((s) => s.state === 'failed'), r2.servers.map((s) => s.state).join());
    assert.equal(delegationSummary(r2).verdict, 'partial');
  });

  test('runDelegation refuses without a client or a plan', async () => {
    await assert.rejects(() => runDelegation({ ok: true }, {}), TypeError);
    await assert.rejects(() => runDelegation({ ok: false }, { client: fakeClient({}) }), TypeError);
  });
});

describe('vocabularies', () => {
  test('every finding has a severity; assessDelegation orders them', () => {
    for (const f of DELEGATION_FINDINGS) assert.ok(FINDING_SEVERITY[f], f);
    const out = assessDelegation({ zone: 'example.com', delegation: ['ns1.example.com'], servers: [], parent: null, addresses: {} });
    assert.deepEqual(out.glue.map((g) => g.state), ['unknown']);
    assert.deepEqual(out.findings, []);
    assert.deepEqual([...RECURSION_PROBE_NAMES], ['example.net', 'example.org']);
  });
});
