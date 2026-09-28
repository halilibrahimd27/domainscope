// Unit tests for assets/js/lib/nsparity.js — no network. Real, scrubbed Globalping DNS
// measurements (tests/fixtures/globalping/d*.json, captured 2026-09-28) for the result reading;
// a fake Globalping client that answers as authoritative name servers from a table for the runs.
// Documentation data only: example.* names, 192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32;
// 104.16.0.0/13 stands in for Cloudflare edges.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseNameservers, fileNameservers, extraQueries, planParity, authoritativeFlag, digSection, dnsResponse, nameserverState, createParityDns,
  parityRow, runParity, paritySummary, parityRunbook, signedInFile, parityZoneFile, buildParityCommand,
  PARITY_MODES, PARITY_MAX_PROBES, PARITY_MAX_NAMESERVERS, PARITY_CONCURRENCY, PARITY_QUERY_TYPES, PARITY_STATUSES, PARITY_SEVERITY,
  PARITY_REASONS, NS_STATES, NS_ISSUES, RUNBOOK_STEPS, RUNBOOK_STATES, PARITY_EXTRA_TYPES
} from '../../assets/js/lib/nsparity.js';
import { GlobalpingError, GP_DNS_TYPES, createGlobalping } from '../../assets/js/lib/globalping.js';
import { DRIFT_REASONS } from '../../assets/js/lib/zonedrift.js';
import { zone, cfZone, P, D } from '../fixtures/zones-analysis/zone-builder.mjs';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'globalping');
const fx = (name) => JSON.parse(readFileSync(join(FIX, `${name}.json`), 'utf8'));
const measurementOf = (name) => fx(name).final.body;

const NS1 = 'ns1.example.net';
const NS2 = 'ns2.example.net';
const NS3 = 'ns3.example.net';
const SOA_VALUE = (serial = 2026092801) => `${NS1}. hostmaster.example.com. ${serial} 7200 3600 1209600 300`;
const SOA_ROW = ['@', 'SOA', { mname: 'ns1.example.org', rname: 'hostmaster.example.com', serial: 7, refresh: 3600, retry: 600, expire: 604800, minimum: 300 }];
const seenStatuses = new Set();
const seenReasons = new Set();

/* ---- a fake Globalping answering as authoritative name servers ------------------------------ */

/**
 * @param {Object<string, { records?: Object<string, Array<[number, string]>|{ rcode: string }>, refuse?: boolean,
 *   noAa?: boolean, serial?: number }>} servers per name server: 'name|TYPE' → [[ttl, value], …] or { rcode }
 * @param {{ quotaAfter?: number, delayMs?: number, failFor?: string }} [opts] quotaAfter: the POST after this many is a quota 429
 */
function fakeGp(servers, { quotaAfter = 0, delayMs = 0, failFor = null } = {}) {
  const calls = [];
  let inFlight = 0;
  const gp = {
    calls,
    maxInFlight: 0,
    async measure(body, { signal } = {}) {
      if (signal && signal.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
      calls.push(body);
      if (quotaAfter && calls.length > quotaAfter) {
        throw new GlobalpingError('rate-limit', 'API rate limit exceeded.', { status: 429, resetAt: new Date('2026-09-28T08:00:00Z') });
      }
      inFlight += 1;
      gp.maxInFlight = Math.max(gp.maxInFlight, inFlight);
      try {
        await new Promise((r) => setTimeout(r, delayMs));
        if (signal && signal.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
        const ns = body.measurementOptions.resolver;
        const name = body.target;
        const type = body.measurementOptions.query.type;
        if (failFor && `${name}|${type}` === failFor) throw new GlobalpingError('deadline', 'No final result from Globalping in time');
        return { measurement: measurementFor(servers[ns], ns, name, type), id: `fake${String(calls.length).padStart(8, '0')}`, cost: 1, quota: null };
      } finally {
        inFlight -= 1;
      }
    }
  };
  return gp;
}

function measurementFor(server, ns, name, type) {
  const probe = { continent: 'EU', country: 'DE', city: 'Frankfurt', asn: 24940, network: 'Hetzner Online', tags: ['datacenter-network'] };
  const wrap = (result) => ({ id: 'fake', type: 'dns', status: 'finished', target: name, results: [{ probe, result }] });
  if (!server) return wrap({ status: 'failed', rawOutput: `dig: couldn't get address for '${ns}': not found` });
  const flags = (aa) => `;; flags: qr${aa ? ' aa' : ''} rd; QUERY: 1\n`;
  const finish = (rcode, answers, aa = !server.noAa) => wrap({
    status: 'finished', statusCodeName: rcode, statusCode: { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 }[rcode], rawOutput: flags(aa), answers,
    timings: { total: 5 }, resolver: ns
  });
  if (server.refuse) return finish('REFUSED', [], false);
  // A delegation: a referral, as dig prints it (the NS records in the authority section, glue in the additional one).
  const cut = Object.keys(server.cuts || {}).find((c) => name === c || name.endsWith(`.${c}`));
  if (cut && !(name === cut && type === 'DS')) {
    const { ns: targets, glue = {} } = server.cuts[cut];
    const raw = [flags(false), ';; AUTHORITY SECTION:', ...targets.map((t) => `${cut}.\t\t3600\tIN\tNS\t${t}`), '',
      ';; ADDITIONAL SECTION:', ...Object.entries(glue).map(([n, ip]) => `${n}.\t\t3600\tIN\tA\t${ip}`), ''].join('\n');
    return wrap({ status: 'finished', statusCodeName: 'NOERROR', statusCode: 0, rawOutput: raw, answers: [], timings: { total: 5 }, resolver: ns });
  }
  const recs = { 'example.com|SOA': [[3600, SOA_VALUE(server.serial)]], ...(server.records || {}) };
  const answers = [];
  let cur = name;
  for (let hop = 0; hop < 4; hop += 1) {
    const spec = recs[`${cur}|${type}`];
    if (spec && spec.rcode) return finish(spec.rcode, answers);
    if (spec) {
      for (const [ttl, value] of spec) answers.push({ name: `${cur}.`, type, ttl, class: 'IN', value });
      return finish('NOERROR', answers);
    }
    const cname = type !== 'CNAME' && recs[`${cur}|CNAME`];
    if (cname) {
      answers.push({ name: `${cur}.`, type: 'CNAME', ttl: cname[0][0], class: 'IN', value: cname[0][1] });
      cur = cname[0][1].replace(/\.$/, '');
      continue;
    }
    break;
  }
  const exists = Object.keys(recs).some((k) => k.startsWith(`${cur}|`));
  return finish(exists || answers.length ? 'NOERROR' : 'NXDOMAIN', answers);
}

async function run(z, servers, opts = {}, gpOpts = {}) {
  const client = fakeGp(servers, gpOpts);
  const result = await runParity(z, { client, labelFn: () => 'zzprobe', ...opts });
  for (const r of result.rows) {
    seenStatuses.add(r.status);
    for (const x of r.reasons) seenReasons.add(x);
  }
  const row = (key) => result.rows.find((r) => r.key === key);
  return { result, client, row };
}

const status = (r) => (r ? [r.status, ...r.reasons].join(' ') : 'none');

/* ---- vocabularies ----------------------------------------------------------------------------- */

test('constants: modes, limits, statuses, severities and reasons are frozen and consistent', () => {
  assert.deepEqual([...PARITY_MODES], ['first', 'all']);
  assert.equal(PARITY_MAX_PROBES, 100);
  assert.equal(PARITY_MAX_NAMESERVERS, 8);
  assert.equal(PARITY_CONCURRENCY, 4);
  assert.ok(!PARITY_QUERY_TYPES.includes('ANY') && PARITY_QUERY_TYPES.length === GP_DNS_TYPES.length - 1);
  assert.ok(!PARITY_QUERY_TYPES.includes('CAA'), 'Globalping cannot ask CAA');
  for (const s of PARITY_STATUSES) assert.ok(PARITY_SEVERITY[s], s);
  for (const r of PARITY_REASONS) assert.ok(!DRIFT_REASONS.includes(r), `${r} is not a drift reason`);
  for (const list of [PARITY_MODES, PARITY_STATUSES, PARITY_REASONS, NS_STATES, NS_ISSUES, RUNBOOK_STEPS, RUNBOOK_STATES, PARITY_EXTRA_TYPES]) {
    assert.ok(Object.isFrozen(list));
  }
});

/* ---- the name servers as typed ---------------------------------------------------------------- */

describe('parseNameservers', () => {
  test('host names (trailing dot, case, commas, lines, comments), public addresses; duplicates dropped', () => {
    const { list, issues } = parseNameservers('NS1.Example.NET.\nns2.example.net, ns1.example.net # old one\n  1.1.1.1;2606:4700:4700::1111');
    assert.deepEqual(list, [NS1, NS2, '1.1.1.1', '2606:4700:4700::1111']);
    assert.deepEqual(issues, []);
  });

  test('private and documentation addresses, bad tokens, more than eight, and the file\'s own servers are issues', () => {
    const { list, issues } = parseNameservers('10.0.0.53 192.0.2.53 ns_1.example.net -x a1 ns1.example.org', { fileNs: ['ns1.example.org'] });
    assert.deepEqual(list, ['ns1.example.org']);
    assert.deepEqual(issues, [
      { code: 'private', value: '10.0.0.53' }, { code: 'private', value: '192.0.2.53' }, { code: 'invalid', value: 'ns_1.example.net' },
      { code: 'invalid', value: '-x' }, { code: 'invalid', value: 'a1' }, { code: 'in-file', value: 'ns1.example.org' }
    ]);
    const many = parseNameservers(Array.from({ length: 10 }, (_, i) => `ns${i}.example.net`).join(' '));
    assert.equal(many.list.length, PARITY_MAX_NAMESERVERS);
    assert.deepEqual(many.issues.map((i) => i.code), ['too-many', 'too-many']);
    assert.deepEqual(parseNameservers(''), { list: [], issues: [] });
    assert.deepEqual(parseNameservers(null), { list: [], issues: [] });
  });

  test('fileNameservers: the apex NS of the export', () => {
    const z = zone([SOA_ROW, ['@', 'NS', 'ns2.example.org.'], ['@', 'NS', 'ns1.example.org.'], ['dev', 'NS', 'ns1.example.net.']]);
    assert.deepEqual(fileNameservers(z), ['ns1.example.org', 'ns2.example.org']);
  });
});

/* ---- reading one DNS measurement (real fixtures) ---------------------------------------------- */

describe('dnsResponse on the live captures', () => {
  const read = (file, name, type) => dnsResponse(measurementOf(file), { name, type, resolver: NS1, origin: 'example.com' });

  test('SOA asked of its own server: NOERROR, authoritative, the serial (d01)', () => {
    const r = read('d01-soa', 'example.com', 'SOA');
    assert.deepEqual([r.ok, r.rcode, r.aa, r.answers.length, r.unparsed], [true, 'NOERROR', true, 1, 0]);
    assert.equal(r.answers[0].data.serial, 2026092401);
    assert.equal(r.answers[0].ttl, 3600);
    assert.equal(r.measurementId, '2fMBxbOuE4PyivQYo00021DVq');
    assert.equal(r.probe.country, 'NG');
    assert.deepEqual(nameserverState(r, 'example.com'), { state: 'ok', serial: 2026092401, aa: true, rcode: 'NOERROR' });
  });

  test('A, MX, SRV, NS, AAAA over TCP and HTTPS values become dnswire data (d02, d05, d06, d12, d13, d07)', () => {
    assert.deepEqual(read('d02-a', 'example.com', 'A').answers.map((a) => [a.data, a.ttl]),
      ['192.0.2.80', '192.0.2.84', '192.0.2.136', '192.0.2.138', '192.0.2.232', '192.0.2.245'].map((ip) => [ip, 300]));
    assert.deepEqual(read('d05-mx', 'example.com', 'MX').answers[0].data, { preference: 10, exchange: 'smtp.example.com' });
    assert.deepEqual(read('d06-srv', '_xmpp-server._tcp.example.com', 'SRV').answers[0].data, { priority: 30, weight: 30, port: 5269, target: 'xmpp.example.com' });
    assert.deepEqual(read('d12-ns', 'example.com', 'NS').answers.map((a) => a.data), [NS1, NS2]);
    assert.deepEqual(read('d13-tcp-aaaa', 'example.com', 'AAAA').answers.map((a) => a.data).slice(0, 2), ['2001:db8::bc12', '2001:db8::bc1b']);
    const https = read('d07-https', 'example.com', 'HTTPS').answers[0].data;
    assert.deepEqual([https.priority, https.target, https.params.alpn, https.params.ipv4hint], [1, '.', ['h3', 'h2'], ['104.16.132.229', '104.16.133.229']]);
  });

  test('a TXT record of two character-strings keeps both (d03)', () => {
    const [rr] = read('d03-txt-split', 'google._domainkey.example.com', 'TXT').answers;
    assert.equal(rr.data.length, 2);
    assert.ok(rr.data[0].startsWith('v=DKIM1; k=rsa; p=') && rr.data[0].length === 255, `first string ${rr.data[0].length}`);
  });

  test('A asked of a CNAME name: the CNAME and the in-zone target (d04); a proxied name: edge addresses (d14)', () => {
    const r = read('d04-cname-chain', 'www.example.com', 'A');
    assert.deepEqual(r.answers.map((a) => [a.name, a.type, a.data]), [['www.example.com', 'CNAME', 'example.com'], ['example.com', 'A', '192.0.2.10']]);
    assert.deepEqual(read('d14-proxied-a', 'www.example.com', 'A').answers.map((a) => a.data), ['104.16.123.96', '104.16.124.96']);
  });

  test('NXDOMAIN, REFUSED, NODATA and a resolver the probe cannot find (d08–d11) → the server states', () => {
    const nx = read('d08-nxdomain', 'gp-parity-nonexistent-7q2z.example.com', 'A');
    assert.deepEqual([nx.ok, nx.rcode, nx.aa, nx.answers.length], [true, 'NXDOMAIN', true, 0]);
    assert.equal(nameserverState(nx, 'example.com').state, 'no-zone');
    const refused = read('d09-refused', 'example.com', 'A');
    assert.deepEqual([refused.rcode, refused.aa], ['REFUSED', false]);
    assert.equal(nameserverState(refused, 'example.com').state, 'refused');
    const nodata = read('d10-nodata', 'example.com', 'SRV');
    assert.deepEqual([nodata.rcode, nodata.answers.length], ['NOERROR', 0]);
    const bad = read('d11-bad-resolver', 'example.com', 'A');
    assert.deepEqual([bad.ok, bad.failure, bad.errorKind], [false, 'unreachable', 'network']);
    assert.match(bad.error, /couldn't get address/);
    assert.equal(nameserverState(bad, 'example.com').state, 'unreachable');
  });

  test('not authoritative, SERVFAIL, missing results and unsafe answers', () => {
    const soa = structuredClone(measurementOf('d01-soa'));
    soa.results[0].result.rawOutput = soa.results[0].result.rawOutput.replace('flags: qr aa rd', 'flags: qr rd ra');
    const r = dnsResponse(soa, { name: 'example.com', type: 'SOA', resolver: NS1, origin: 'example.com' });
    assert.equal(nameserverState(r, 'example.com').state, 'not-authoritative');
    const sf = structuredClone(soa);
    Object.assign(sf.results[0].result, { statusCodeName: 'SERVFAIL', statusCode: 2, answers: [] });
    assert.equal(nameserverState(dnsResponse(sf, { name: 'example.com', type: 'SOA', resolver: NS1 }), 'example.com').state, 'servfail');
    const empty = dnsResponse({ results: [] }, { name: 'example.com', type: 'A', resolver: NS1 });
    assert.deepEqual([empty.ok, empty.failure], [false, 'failed']);
    assert.equal(nameserverState(null, 'example.com').state, 'failed');
    const bad = structuredClone(measurementOf('d02-a'));
    bad.results[0].result.answers.push({ name: '$INCLUDE /etc/passwd', type: 'A', ttl: 1, value: '192.0.2.1' });
    bad.results[0].result.answers.push({ name: 'x.example.com.', type: 'TXT', ttl: 1, value: '"a"\n$INCLUDE x' });
    bad.results[0].result.answers.push({ name: 'y.example.com.', type: 'A', ttl: 1, value: 'not-an-address' });
    const out = dnsResponse(bad, { name: 'example.com', type: 'A', resolver: NS1, origin: 'example.com' });
    assert.equal(out.answers.length, 7, 'the six real answers and the unparsable one (kept as text, no data)');
    assert.equal(out.unparsed, 3);
    assert.equal(out.answers[6].data, null);
  });

  test('authoritativeFlag reads the dig flags line only', () => {
    assert.equal(authoritativeFlag(';; flags: qr aa rd; QUERY: 1'), true);
    assert.equal(authoritativeFlag(';; flags: qr rd ra; QUERY: 1'), false);
    assert.equal(authoritativeFlag('no flags here'), null);
    assert.equal(authoritativeFlag(undefined), null);
  });

  test('the real transport end to end: createGlobalping + a recorded fixture → one probe, one response', async () => {
    const f = fx('d05-mx');
    const clock = { t: Date.parse(f.capturedAt) };
    const responses = [
      new Response(JSON.stringify(f.post.body), { status: 202, headers: { 'x-request-cost': '1', 'x-ratelimit-remaining': '240', 'x-ratelimit-reset': '3000' } }),
      new Response(JSON.stringify(f.final.body), { status: 200 })
    ];
    const sent = [];
    const client = createGlobalping({
      fetchImpl: async (url, init) => { sent.push({ url, body: init && init.body }); return responses.shift(); },
      sleepImpl: async (ms) => { clock.t += ms; },
      now: () => clock.t
    });
    const dnsOf = createParityDns({ client, nameserver: NS1, origin: 'example.com' });
    const r = await dnsOf.query('example.com', 'MX');
    assert.deepEqual(JSON.parse(sent[0].body), { type: 'dns', target: 'example.com', limit: 1, timeout: 15, measurementOptions: { query: { type: 'MX' }, resolver: NS1, protocol: 'UDP', port: 53 } });
    assert.deepEqual([r.ok, r.rcode, r.answers[0].data.exchange], [true, 'NOERROR', 'smtp.example.com']);
    assert.equal(dnsOf.sent, 1);
    assert.strictEqual(await dnsOf.query('example.com', 'MX'), r, 'asked once, memoised');
  });
});

/* ---- plan ------------------------------------------------------------------------------------- */

describe('planParity', () => {
  const z = zone([SOA_ROW, ['@', 'NS', 'ns1.example.org.'], ['@', 'A', '192.0.2.10'], ['@', 'CAA', '0 issue "letsencrypt.org"'],
    ['www', 'CNAME', '@'], ['mail', 'A', '198.51.100.25'], ['@', 'MX', '10 mail'], ['intranet', 'A', '10.0.0.5']]);

  test('first mode: every record set on the first server + the SOA of each other; CAA and internal names cost nothing', () => {
    const p = planParity(z, { nameservers: [NS1, NS2, NS3] });
    // drift: SOA + NS preflight, A@, MX@, CNAME www, A mail = 6 queries; extras at the apex: AAAA, TXT (A and MX are in the file)
    assert.deepEqual([p.ok, p.mode, p.full, p.serial, p.perServer, p.extras, p.probes, p.needed, p.capped], [true, 'first', [NS1], [NS2, NS3], 8, 2, 10, 10, false]);
    assert.deepEqual([p.skipped.type, p.skipped.private], [1, 1]);
    assert.equal(p.checked, 5, 'NS, A and MX at the apex, www, mail');
    assert.deepEqual(extraQueries(z), [{ name: 'example.com', type: 'AAAA' }, { name: 'example.com', type: 'TXT' }]);
  });

  test('all mode multiplies; extras off; no servers; no zone name', () => {
    assert.equal(planParity(z, { nameservers: [NS1, NS2], mode: 'all' }).probes, 16);
    assert.equal(planParity(z, { nameservers: [NS1], extras: false }).probes, 6);
    assert.deepEqual([planParity(z, { nameservers: [] }).ok, planParity(z, { nameservers: [] }).why], [false, 'no-nameservers']);
    assert.equal(planParity(zone([['@', 'A', '192.0.2.1']], { origin: '' }), { nameservers: [NS1] }).why, 'no-origin');
    assert.equal(planParity({ ...z, fatal: { code: 'EMPTY' } }, { nameservers: [NS1] }).why, 'no-origin');
  });

  test('the hard cap: first mode checks what fits (the rest is budget); all mode past the cap is refused', () => {
    const rows = [SOA_ROW];
    for (let i = 0; i < 150; i += 1) rows.push([`h${i}`, 'A', `198.51.100.${i % 250}`]);
    const big = zone(rows);
    const p = planParity(big, { nameservers: [NS1, NS2] });
    // 2 preflight + 150 record sets + 6 extras (A, AAAA, MX, TXT at the apex; A, AAAA at www) + 1 serial
    assert.deepEqual([p.ok, p.capped, p.needed, p.probes <= PARITY_MAX_PROBES, p.probes], [true, true, 2 + 150 + 6 + 1, true, 100]);
    assert.ok(p.skipped.budget > 0 && p.checked < 150);
    const all = planParity(big, { nameservers: [NS1, NS2], mode: 'all' });
    assert.deepEqual([all.ok, all.why, all.probes], [false, 'over-cap', 0]);
    assert.equal(planParity(big, { nameservers: [NS1], maxProbes: 20 }).probes, 20);
    assert.equal(planParity(big, { nameservers: [NS1], maxProbes: 5000 }).cap, PARITY_MAX_PROBES);
  });

  test('extras: none at a CNAME name or a proxied address name; www only when no wildcard covers it', () => {
    const cf = cfZone([SOA_ROW, ['@', 'A', '192.0.2.10', P], ['@', 'TXT', 'v=spf1 -all'], ['*', 'A', '192.0.2.11', D]]);
    assert.deepEqual(extraQueries(cf), [{ name: 'example.com', type: 'MX' }]);
    const www = zone([SOA_ROW, ['@', 'CNAME', 'lb.example.net.'], ['www', 'A', '192.0.2.12']]);
    assert.deepEqual(extraQueries(www), [{ name: 'www.example.com', type: 'AAAA' }]);
    assert.deepEqual(extraQueries(zone([SOA_ROW], { origin: '' })), []);
  });
});

/* ---- runs ------------------------------------------------------------------------------------- */

describe('runParity', () => {
  const z = cfZone([
    SOA_ROW, ['@', 'NS', 'ns1.example.org.', { ttl: 86400 }], ['@', 'NS', 'ns2.example.org.', { ttl: 86400 }],
    ['@', 'A', '192.0.2.10', P], ['www', 'CNAME', '@', P], ['mail', 'A', '198.51.100.25', { proxied: false, ttl: 600 }],
    ['@', 'MX', '10 mail', { ttl: 600 }], ['@', 'TXT', 'v=spf1 mx -all', { ttl: 600 }], ['old', 'A', '198.51.100.30', D],
    ['@', 'CAA', '0 issue "letsencrypt.org"'], ['intranet', 'A', '10.0.0.5', D], ['_sip._tcp', 'SRV', '10 5 5060 sip.example.com.', { ttl: 3600 }]
  ]);
  const good = {
    'example.com|NS': [[86400, `${NS1}.`], [86400, `${NS2}.`]],
    'example.com|A': [[300, '104.16.0.1']],
    'www.example.com|A': [[300, '104.16.0.1']],
    'www.example.com|CNAME': { rcode: 'NOERROR' },
    'mail.example.com|A': [[3600, '198.51.100.25']],
    'example.com|MX': [[600, '10 mail.example.com.']],
    'example.com|TXT': [[600, '"v=spf1 mx -all"']],
    '_sip._tcp.example.com|SRV': [[3600, '10 5 5060 sip.example.com.']]
  };

  test('a move to Cloudflare: same, missing, TTL difference, the new NS set, CAA and internal names never asked', async () => {
    const { result, client, row } = await run(z, { [NS1]: { records: good }, [NS2]: { records: good } }, { nameservers: [NS1, NS2] });
    assert.equal(status(row(`${NS1}|example.com|A`)), 'same', 'proxied at the new provider too');
    assert.equal(status(row(`${NS1}|www.example.com|CNAME`)), 'same');
    assert.equal(status(row(`${NS1}|mail.example.com|A`)), 'same ttl-differs');
    assert.deepEqual([row(`${NS1}|mail.example.com|A`).fileTtl, row(`${NS1}|mail.example.com|A`).liveTtl], [600, 3600]);
    assert.equal(status(row(`${NS1}|example.com|MX`)), 'same');
    assert.equal(status(row(`${NS1}|old.example.com|A`)), 'missing nxdomain');
    assert.equal(status(row(`${NS1}|example.com|NS`)), 'same ns-new', 'the new provider names itself');
    assert.equal(status(row(`${NS1}|example.com|CAA`)), 'skipped not-queryable');
    assert.equal(status(row(`${NS1}|intranet.example.com|A`)), 'skipped private');
    assert.equal(status(row(`${NS1}|_sip._tcp.example.com|SRV`)), 'same');
    const asked = client.calls.map((b) => `${b.measurementOptions.resolver} ${b.target} ${b.measurementOptions.query.type}`);
    assert.ok(!asked.some((q) => /intranet|CAA/.test(q)), 'never sent');
    assert.deepEqual(asked.filter((q) => q.startsWith(NS2)), [`${NS2} example.com SOA`], 'the second server: its serial only');
    assert.equal(client.calls.length, result.planned, 'the plan is exact');
    assert.equal(result.spent, result.planned);
    assert.deepEqual(result.nameservers.map((s) => [s.ns, s.role, s.state, s.serial]), [[NS1, 'full', 'ok', 2026092801], [NS2, 'serial', 'ok', 2026092801]]);
    assert.equal(result.serials, 'same');
    assert.equal(result.stoppedBy, null);
    assert.ok(client.maxInFlight <= PARITY_CONCURRENCY, `in flight ${client.maxInFlight}`);
    assert.deepEqual(paritySummary(result).verdict, 'fix', 'a missing record');
  });

  test('different values, a CNAME instead, extra records at the apex and www, a proxied name served directly', async () => {
    const records = {
      ...good,
      'example.com|A': [[300, '192.0.2.10']],
      'example.com|MX': [[600, '10 mx.example.net.']],
      'mail.example.com|A': undefined,
      'mail.example.com|CNAME': [[600, 'mail.example.net.']],
      'example.com|AAAA': [[300, '2001:db8::99']],
      'www.example.com|CNAME': [[300, 'example.com.']],
      'old.example.com|A': [[300, '198.51.100.30']],
      'example.com|NS': [[86400, `${NS1}.`], [86400, 'ns9.example.net.']],
      'example.com|TXT': [[600, '"v=spf1 mx -all"'], [300, '"parking-verification=0123"']]
    };
    const { row } = await run(z, { [NS1]: { records } }, { nameservers: [NS1, NS2] });
    assert.equal(status(row(`${NS1}|example.com|A`)), 'unproxied proxy-off-live');
    assert.equal(status(row(`${NS1}|www.example.com|CNAME`)), 'unproxied proxy-off-live');
    assert.equal(status(row(`${NS1}|example.com|MX`)), 'different values');
    assert.deepEqual([row(`${NS1}|example.com|MX`).added, row(`${NS1}|example.com|MX`).removed], [['10 mx.example.net.'], ['10 mail.example.com.']]);
    assert.equal(status(row(`${NS1}|mail.example.com|A`)), 'different cname-live');
    assert.equal(status(row(`${NS1}|example.com|TXT`)), 'different values');
    const ns = row(`${NS1}|example.com|NS`);
    assert.equal(status(ns), 'different ns-mismatch');
    assert.deepEqual([ns.added, ns.removed], [['ns9.example.net'], [NS2]]);
    assert.equal(row(`${NS1}|example.com|AAAA|extra`), undefined, 'never asked at a proxied name: Cloudflare adds AAAA itself');
  });

  test('www missing from the file: a provider\'s default www CNAME is one extra row', async () => {
    const plain = zone([SOA_ROW, ['@', 'A', '192.0.2.10']]);
    const records = { 'example.com|A': [[300, '192.0.2.10']], 'example.com|AAAA': [[300, '2001:db8::99']], 'www.example.com|CNAME': [[3600, 'example.com.']] };
    const { result, row } = await run(plain, { [NS1]: { records } }, { nameservers: [NS1] });
    assert.equal(status(row(`${NS1}|www.example.com|CNAME|extra`)), 'extra extra-record');
    assert.equal(status(row(`${NS1}|example.com|AAAA|extra`)), 'extra extra-record', 'AAAA at the apex, not in the file');
    assert.deepEqual([row(`${NS1}|example.com|AAAA|extra`).live, row(`${NS1}|example.com|AAAA|extra`).liveTtl], [['2001:db8::99'], 300]);
    assert.equal(result.rows.filter((r) => r.status === 'extra').length, 2, 'the A and the AAAA question at www found the same CNAME: one row');
  });

  test('a first server that refuses the zone costs one probe; the next one is compared instead', async () => {
    const { result, client } = await run(z, { [NS1]: { refuse: true }, [NS2]: { records: good } }, { nameservers: [NS1, NS2] });
    assert.deepEqual(result.nameservers.map((s) => [s.ns, s.role, s.state]), [[NS1, 'full', 'refused'], [NS2, 'full', 'ok']]);
    assert.equal(client.calls.filter((b) => b.measurementOptions.resolver === NS1).length, 1);
    assert.ok(result.rows.every((r) => r.ns === NS2));
    assert.ok(client.calls.length <= result.planned);
    assert.equal(paritySummary(result).verdict, 'fix', 'a server that does not serve the zone must be fixed');
  });

  test('servers that do not serve the zone at all: blocked, nothing compared', async () => {
    const { result, client } = await run(z, { [NS1]: { refuse: true }, [NS2]: { records: good, noAa: true } }, { nameservers: [NS1, NS2, NS3] });
    assert.deepEqual(result.nameservers.map((s) => s.state), ['refused', 'not-authoritative', 'unreachable']);
    assert.equal(client.calls.length, 3);
    assert.deepEqual(result.rows, []);
    assert.equal(paritySummary(result).verdict, 'blocked');
    assert.equal(parityRunbook(z, result).find((s) => s.id === 'fix').state, 'blocked');
  });

  test('all mode: every record on every server; serials out of step', async () => {
    const { result } = await run(z, { [NS1]: { records: good }, [NS2]: { records: good, serial: 2026092802 } }, { nameservers: [NS1, NS2], mode: 'all' });
    assert.deepEqual(result.nameservers.map((s) => s.role), ['full', 'full']);
    assert.ok(result.rows.some((r) => r.ns === NS2 && r.key === `${NS2}|example.com|MX`));
    assert.equal(result.serials, 'differ');
  });

  test('a delegation answers by referral (its NS and glue compared); a flattened CNAME served plainly is the same', async () => {
    const zd = cfZone([SOA_ROW, ['dev', 'NS', 'ns1.dev.example.com.', { ttl: 3600 }], ['ns1.dev', 'A', '192.0.2.53', { ttl: 3600 }], ['dev', 'DS', '12345 13 2 ABCD', { ttl: 3600 }],
      ['status', 'CNAME', 'statuspage.example.org.', { proxied: false, flattenCname: true, ttlAuto: true }], ['www.dev', 'A', '192.0.2.54']]);
    const records = { 'dev.example.com|DS': [[3600, '12345 13 2 ABCD']], 'status.example.com|CNAME': [[300, 'statuspage.example.org.']] };
    const cuts = { 'dev.example.com': { ns: ['ns1.dev.example.com.'], glue: { 'ns1.dev.example.com': '192.0.2.53' } } };
    const { row } = await run(zd, { [NS1]: { records, cuts } }, { nameservers: [NS1], extras: false });
    assert.equal(status(row(`${NS1}|dev.example.com|NS`)), 'same');
    assert.equal(status(row(`${NS1}|ns1.dev.example.com|A`)), 'same', 'the glue address from the additional section');
    assert.equal(status(row(`${NS1}|dev.example.com|DS`)), 'same', 'the DS is the parent\'s own record');
    assert.equal(status(row(`${NS1}|status.example.com|CNAME`)), 'same cname-kept');
    assert.equal(status(row(`${NS1}|www.dev.example.com|A`)), 'skipped below-cut', 'data below the cut is never asked');
    const wrong = { ...cuts, 'dev.example.com': { ns: ['ns9.example.net.'], glue: {} } };
    const other = await run(zd, { [NS1]: { records, cuts: wrong } }, { nameservers: [NS1], extras: false });
    assert.equal(status(other.row(`${NS1}|dev.example.com|NS`)), 'different values');
    assert.equal(status(other.row(`${NS1}|ns1.dev.example.com|A`)), 'missing nodata', 'no glue in the referral');
  });

  test('digSection reads the authority and additional sections of the dig text', () => {
    const raw = ';; flags: qr rd;\n\n;; AUTHORITY SECTION:\ndev.example.com.\t\t3600\tIN\tNS\tns1.dev.example.com.\nbad line\n\n;; ADDITIONAL SECTION:\nns1.dev.example.com.\t3600\tIN\tA\t192.0.2.53\n';
    assert.deepEqual(digSection(raw, 'AUTHORITY'), [{ name: 'dev.example.com.', type: 'NS', ttl: 3600, class: 'IN', value: 'ns1.dev.example.com.' }]);
    assert.deepEqual(digSection(raw, 'ADDITIONAL').map((r) => r.value), ['192.0.2.53']);
    assert.deepEqual(digSection(measurementOf('d08-nxdomain').results[0].result.rawOutput, 'AUTHORITY').map((r) => r.type), ['SOA']);
    assert.deepEqual(digSection(null, 'AUTHORITY'), []);
  });

  test('servers typed as addresses: the apex NS set cannot be judged', async () => {
    const records = { ...good, 'example.com|NS': [[86400, `${NS1}.`]] };
    const { row } = await run(z, { '1.1.1.1': { records } }, { nameservers: ['1.1.1.1'] });
    assert.equal(status(row('1.1.1.1|example.com|NS')), 'skipped ns-by-address');
  });

  test('the quota runs out mid-run: stopped, the reset time kept, the rows so far kept, nothing more sent', async () => {
    const { result, client } = await run(z, { [NS1]: { records: good } }, { nameservers: [NS1, NS2] }, { quotaAfter: 3 });
    assert.equal(result.stoppedBy, 'quota');
    assert.equal(result.resetAt.toISOString(), '2026-09-28T08:00:00.000Z');
    assert.equal(result.spent, 3, 'three measurements, then the 429');
    const posted = client.calls.length;
    assert.ok(posted > 3 && posted <= 3 + PARITY_CONCURRENCY, `only what was already in flight is refused too: ${posted}`);
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(client.calls.length, posted, 'nothing sent after the stop');
    assert.equal(result.nameservers[1].state, 'not-run');
    assert.ok(result.rows.some((r) => r.status === 'same'), 'what was read before the stop is kept');
    assert.equal(paritySummary(result).verdict, 'partial', 'clean so far, but not done');
  });

  test('a measurement that finds no result in time is one error row; the budget refuses anything past the plan', async () => {
    const { row } = await run(z, { [NS1]: { records: good } }, { nameservers: [NS1] }, { failFor: 'example.com|MX' });
    assert.equal(status(row(`${NS1}|example.com|MX`)), 'error timeout');
    let asked = 0;
    const dnsOf = createParityDns({ client: fakeGp({ [NS1]: { records: good } }), nameserver: NS1, reserve: () => (asked += 1) <= 1 });
    assert.equal((await dnsOf.query('example.com', 'SOA')).ok, true);
    const refused = await dnsOf.query('example.com', 'A');
    assert.deepEqual([refused.ok, refused.errorKind], [false, 'budget']);
    const bad = await dnsOf.query('*.example.com', 'A');
    assert.equal(bad.errorKind, 'parse', 'a name Globalping refuses is never posted');
  });

  test('cancel: stoppedBy abort, no DS question; the DS question otherwise goes to the DohClient', async () => {
    const ac = new AbortController();
    const client = fakeGp({ [NS1]: { records: good } }, { delayMs: 20 });
    const p = runParity(z, { client, nameservers: [NS1], signal: ac.signal, labelFn: () => 'zzprobe' });
    setTimeout(() => ac.abort(), 30);
    const aborted = await p;
    assert.equal(aborted.stoppedBy, 'abort');
    const dsLog = [];
    const doh = { async query(name, type) { dsLog.push(`${name}|${type}`); return { ok: true, rcode: 'NOERROR', answers: [{ name, type: 'DS', ttl: 3600, data: { keyTag: 1 } }] }; } };
    const { result } = await run(z, { [NS1]: { records: good } }, { nameservers: [NS1], dns: doh });
    assert.deepEqual(dsLog, ['example.com|DS']);
    assert.deepEqual(result.dnssec, { signedInFile: false, ds: 'present' });
    const none = { async query() { return { ok: true, rcode: 'NOERROR', answers: [] }; } };
    assert.equal((await run(z, { [NS1]: { records: good } }, { nameservers: [NS1], dns: none })).result.dnssec.ds, 'absent');
    const broken = { async query() { throw new TypeError('failed to fetch'); } };
    assert.equal((await run(z, { [NS1]: { records: good } }, { nameservers: [NS1], dns: broken })).result.dnssec.ds, 'unknown');
  });

  test('observers: onRow, onServer, onProgress in probes; observer errors never break the run', async () => {
    const seen = { rows: 0, servers: [], progress: [] };
    const { result } = await run(z, { [NS1]: { records: good }, [NS2]: { records: good } }, {
      nameservers: [NS1, NS2],
      onRow: () => { seen.rows += 1; throw new Error('observer'); },
      onServer: (s) => seen.servers.push(`${s.ns}:${s.state}`),
      onProgress: (p) => seen.progress.push(p.done)
    });
    assert.equal(seen.rows, result.rows.length);
    assert.deepEqual(seen.servers, [`${NS1}:ok`, `${NS2}:ok`]);
    assert.equal(seen.progress.at(-1), result.planned);
  });

  test('input errors throw: no client, nothing to run', async () => {
    await assert.rejects(runParity(z, { nameservers: [NS1] }), TypeError);
    await assert.rejects(runParity(z, { client: fakeGp({}), nameservers: [] }), /no-nameservers/);
  });
});

/* ---- parityRow ------------------------------------------------------------------------------- */

test('parityRow: the status map, ttl-stale dropped, auto TTLs and proxied names never differ in TTL', () => {
  const base = { key: 'a.example.com|A', name: 'a.example.com', type: 'A', reasons: ['ttl-stale'], file: ['192.0.2.1'], live: ['192.0.2.1'], added: [], removed: [], fileTtl: 300, liveTtl: 600, proxied: false, recordIds: [1] };
  const ctx = { ns: NS1, origin: 'example.com', hosts: [NS1], autoTtl: new Set() };
  const map = { match: 'same', 'proxied-ok': 'same', 'flattened-ok': 'same', 'alias-ok': 'same', 'routing-ok': 'same', differs: 'different', 'missing-live': 'missing', 'origin-exposed': 'unproxied', occluded: 'skipped', skipped: 'skipped', error: 'error', bogus: 'error' };
  for (const [drift, par] of Object.entries(map)) assert.equal(parityRow({ ...base, status: drift }, ctx).status, par, drift);
  assert.deepEqual(parityRow({ ...base, status: 'match' }, ctx).reasons, ['ttl-differs']);
  assert.deepEqual(parityRow({ ...base, status: 'match' }, { ...ctx, autoTtl: new Set(['a.example.com|A']) }).reasons, []);
  assert.deepEqual(parityRow({ ...base, status: 'match', proxied: true }, ctx).reasons, []);
  assert.deepEqual(parityRow({ ...base, status: 'match', liveTtl: 300 }, ctx).reasons, []);
  assert.equal(parityRow({ ...base, status: 'match' }, ctx).key, `${NS1}|a.example.com|A`);
});

/* ---- summary, runbook, CLI -------------------------------------------------------------------- */

describe('summary and runbook', () => {
  const clean = { counts: { same: 3 }, rows: [], nameservers: [{ ns: NS1, role: 'full', state: 'ok' }], serials: 'unknown', stoppedBy: null, capped: false, dnssec: { signedInFile: false, ds: 'absent' } };

  test('verdicts: ready, check, partial', () => {
    assert.equal(paritySummary(clean).verdict, 'ready');
    assert.equal(paritySummary({ ...clean, counts: { same: 3, extra: 1 } }).verdict, 'check');
    assert.equal(paritySummary({ ...clean, serials: 'differ' }).verdict, 'check');
    assert.equal(paritySummary({ ...clean, rows: [{ status: 'same', reasons: ['ttl-differs'] }] }).verdict, 'check');
    assert.equal(paritySummary({ ...clean, capped: true }).verdict, 'partial');
    assert.equal(paritySummary({ ...clean, rows: [{ status: 'skipped', reasons: ['not-queryable'] }] }).verdict, 'partial');
    assert.equal(paritySummary({ ...clean, stoppedBy: 'quota' }).verdict, 'partial');
  });

  test('runbook: TTLs from the file, DNSSEC from the file or the DS, switch blocked while records are missing', () => {
    const z = zone([SOA_ROW, ['@', 'NS', 'ns1.example.org.', { ttl: 172800 }], ['@', 'A', '192.0.2.10', { ttl: 300 }]]);
    const steps = parityRunbook(z, null, { nameservers: [NS1, NS2] });
    assert.deepEqual(steps.map((s) => s.id), [...RUNBOOK_STEPS]);
    assert.deepEqual(steps[0], { id: 'ttl', state: 'todo', params: { nsTtl: 172800, maxTtl: 300, low: 3600 } });
    assert.deepEqual([steps[1].state, steps[2].state, steps[3].params.nameservers], ['info', 'info', `${NS1}, ${NS2}`]);
    const low = zone([SOA_ROW, ['@', 'NS', 'ns1.example.org.', { ttl: 3600 }], ['@', 'A', '192.0.2.10', { ttl: 300 }]]);
    assert.equal(parityRunbook(low, clean)[0].state, 'ok');
    assert.deepEqual(parityRunbook(low, clean).slice(1, 3).map((s) => s.state), ['ok', 'ok']);
    const signed = zone([SOA_ROW, ['@', 'DNSKEY', { flags: 257, protocol: 3, algorithm: 13, publicKey: 'AAAA' }]]);
    assert.equal(signedInFile(signed), true);
    assert.equal(parityRunbook(signed, clean)[2].state, 'todo');
    assert.equal(parityRunbook(low, { ...clean, dnssec: { signedInFile: false, ds: 'present' } })[2].state, 'todo');
    const missing = { ...clean, counts: { missing: 2, same: 1 } };
    const fix = parityRunbook(low, missing);
    assert.deepEqual([fix[1].state, fix[1].params.missing, fix[3].state], ['todo', 2, 'blocked']);
    assert.equal(parityRunbook(low, { ...clean, counts: { same: 3, unproxied: 1 } })[1].state, 'warn');
    for (const s of parityRunbook(low, missing)) assert.ok(RUNBOOK_STATES.includes(s.state), s.state);
  });

  test('the CLI command: validated, quoted per shell; a bad server is dropped and counted', () => {
    assert.equal(parityZoneFile('example.com'), 'example.com.parity.zone');
    assert.equal(parityZoneFile(''), 'zone.parity.zone');
    assert.deepEqual(buildParityCommand({ file: 'example.com.parity.zone', nameservers: [NS1, NS2] }),
      { command: `python3 dns_parity.py example.com.parity.zone --ns ${NS1} ${NS2}`, dropped: 0 });
    assert.deepEqual(buildParityCommand({ file: 'example.com.parity.zone', nameservers: [NS1, "x'; rm -rf /", '192.0.2.53'], shell: 'powershell' }),
      { command: `python dns_parity.py example.com.parity.zone --ns ${NS1} 192.0.2.53`, dropped: 1 });
    assert.equal(buildParityCommand({ file: '-rf', nameservers: [NS1] }).command, null);
    assert.equal(buildParityCommand({ file: 'a.zone', nameservers: [] }).command, null);
  });
});

test('every status and every parity reason was produced by this suite', () => {
  assert.deepEqual([...PARITY_STATUSES].filter((s) => !seenStatuses.has(s)), []);
  assert.deepEqual([...PARITY_REASONS].filter((s) => !seenReasons.has(s)), []);
});
