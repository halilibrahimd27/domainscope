// Unit tests for assets/js/lib/zonedrift.js — no network: the DoH client is a fake whose
// answers go through the real dnswire encoder / decoder and which logs every query.
// Zones are built by hand in the lib/zoneparse.js shape. Documentation addresses and
// example.* names only; 104.16.0.0/13 and 2606:4700::/32 stand in for Cloudflare edges.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import {
  rdataKey, txtJoinedKey, planDrift, driftZone, classifyExtraNames, DRIFT_STATUSES, DRIFT_REASONS, DRIFT_SEVERITY,
  DRIFT_DEFAULT_BUDGET, DRIFT_MAX_BUDGET, DRIFT_MAX_CONCURRENCY
} from '../../assets/js/lib/zonedrift.js';
import { zone, cfZone, P, D } from '../fixtures/zones-analysis/zone-builder.mjs';
import { fixtureNames, loadFixture } from '../fixtures/zones-analysis/gen-analysis-golden.mjs';

const PERF_FACTOR = process.env.ZONE_PERF_STRICT === '1' ? 1 : 3;
const SOA_DATA = { mname: 'ns1.example.net', rname: 'hostmaster.example.com', serial: 100, refresh: 3600, retry: 600, expire: 604800, minimum: 300 };
const SOA = ['@', 'SOA', SOA_DATA];
const CF4 = '104.16.0.1';
const CF6 = '2606:4700::1';
const seenStatuses = new Set();
const seenReasons = new Set();

/* ---- fake DoH client ------------------------------------------------------------------ */

function wireAnswers(qname, qtype, rcode, answers) {
  const list = answers.map((a) => ({ name: a.name ?? qname, type: a.type ?? qtype, ttl: a.ttl ?? 300, data: a.data }));
  try {
    return decodeMessage(encodeMessage({ flags: { qr: true, rd: true, ra: true }, rcode, questions: [{ name: qname, type: qtype }], answers: list })).answers;
  } catch {
    return list.map((a) => ({ ...a, text: Array.isArray(a.data) ? a.data.map((s) => `"${s}"`).join(' ') : String(a.data) }));
  }
}

/**
 * @param {object} table `'name|TYPE'` → RR list, or `{ rcode }`, `{ fail: 'timeout'|'network' }`, `{ ede, answers }`
 * @param {{ delayMs?: number, resolver?: string, respond?: (name, type) => object|undefined }} [opts]
 */
function fakeDns(table = {}, { delayMs = 0, resolver = 'cloudflare', respond = null } = {}) {
  const log = [];
  const known = new Set(Object.keys(table).map((k) => k.split('|')[0]));
  let inFlight = 0;
  const dns = {
    log,
    maxInFlight: 0,
    async query(name, type, opts = {}) {
      log.push({ name, type, opts });
      inFlight += 1;
      dns.maxInFlight = Math.max(dns.maxInFlight, inFlight);
      try {
        if (delayMs) {
          await new Promise((resolve, reject) => {
            const t = setTimeout(resolve, delayMs);
            opts.signal?.addEventListener('abort', () => { clearTimeout(t); reject(Object.assign(new Error('aborted'), { name: 'AbortError' })); }, { once: true });
          });
        }
        let spec = respond ? respond(name, type) : undefined;
        if (spec === undefined) spec = table[`${name}|${type}`];
        if (spec === undefined) spec = known.has(name) ? [] : { rcode: 'NXDOMAIN' };
        if (spec.fail) return { name, type, resolver, ok: false, rcode: null, answers: [], authorities: [], ede: [], error: 'failed', errorKind: spec.fail };
        const rcode = spec.rcode || 'NOERROR';
        const answers = Array.isArray(spec) ? spec : spec.answers || [];
        return { name, type, resolver, ok: true, rcode, answers: wireAnswers(name, type, rcode, answers), authorities: [], ede: spec.ede || [], error: null, errorKind: null };
      } finally {
        inFlight -= 1;
      }
    }
  };
  return dns;
}

const A = (data, extra = {}) => ({ type: 'A', data, ...extra });
const BASE = { 'example.com|SOA': [{ type: 'SOA', data: SOA_DATA }] };

async function drift(z, table = {}, opts = {}, fake = {}) {
  const dns = fakeDns({ ...BASE, ...table }, fake);
  const report = await driftZone(z, { dns, labelFn: () => 'zzprobe', ...opts });
  for (const r of report.rows) {
    seenStatuses.add(r.status);
    for (const x of r.reasons) seenReasons.add(x);
  }
  const row = (key) => report.rows.find((r) => r.key === key);
  const asked = (name, type) => dns.log.some((q) => q.name === name && (!type || q.type === type));
  return { report, dns, row, asked };
}

const status = (r) => [r.status, ...r.reasons].join(' ');

/* ---- canonical keys --------------------------------------------------------------------- */

describe('rdataKey / txtJoinedKey', () => {
  const roundTrip = (type, data) => rdataKey(type, decodeMessage(encodeMessage({ answers: [{ name: 'x.example.com', type, ttl: 1, data }] })).answers[0].data);
  test('file data and decoded live data give the same key for every supported type', () => {
    const cases = [
      ['A', '192.0.2.1'], ['AAAA', '2001:db8:0:0:0:0:0:10'], ['NS', 'NS1.Example.NET.'], ['CNAME', 'www.example.com'],
      ['MX', { preference: 10, exchange: 'Mail.Example.COM.' }], ['MX', { preference: 0, exchange: '.' }],
      ['SRV', { priority: 0, weight: 5, port: 443, target: 'sip.example.com.' }], ['TXT', ['v=spf1', ' -all']],
      ['CAA', { flags: 0, tag: 'ISSUE', value: 'letsencrypt.org' }], ['DS', { keyTag: 12345, algorithm: 13, digestType: 2, digest: '00FFAB' }],
      ['SOA', SOA_DATA], ['TLSA', { usage: 3, selector: 1, matchingType: 1, data: 'ABCDEF' }], ['SSHFP', { algorithm: 4, fpType: 2, fingerprint: 'AA11' }],
      ['DNSKEY', { flags: 257, protocol: 3, algorithm: 13, publicKey: 'AQID BAUG' }],
      ['HTTPS', { priority: 1, target: '.', params: { ipv4hint: ['192.0.2.2', '192.0.2.1'], alpn: ['h3', 'h2'], port: 8443 } }],
      ['TYPE65534', '0A000001']
    ];
    for (const [type, data] of cases) assert.equal(rdataKey(type, data), roundTrip(type, data), type);
  });

  test('root is "" whichever way it is written; hex is lowercase; structured types given hex compare as hex', () => {
    assert.equal(rdataKey('MX', { preference: 0, exchange: '.' }), rdataKey('MX', { preference: 0, exchange: '' }));
    assert.equal(rdataKey('MX', { preference: 0, exchange: '.' }), '0 ');
    assert.equal(rdataKey('DS', { keyTag: 1, algorithm: 13, digestType: 2, digest: 'ABCD' }), '1 13 2 abcd');
    assert.equal(rdataKey('MX', '000a00'), '#000a00');
    assert.equal(rdataKey('A', null), '');
    assert.equal(rdataKey('HTTPS', { priority: 1, target: '.', params: { alpn: ['h2', 'h3'] } }) === rdataKey('HTTPS', { priority: 1, target: '.', params: { alpn: ['h3', 'h2'] } }), false, 'alpn order kept');
  });

  test('txtJoinedKey joins character-strings (a 255+N split equals one string)', () => {
    assert.equal(txtJoinedKey('TXT', ['a'.repeat(255), 'bc']), `${'a'.repeat(255)}bc`);
    assert.equal(txtJoinedKey('A', '192.0.2.1'), '');
  });
});

/* ---- statuses --------------------------------------------------------------------------- */

describe('proxied names', () => {
  const z = cfZone([SOA, ['www', 'A', '192.0.2.10', P], ['ftp', 'A', '192.0.2.10', D], ['worker', 'A', '192.0.2.0', P]]);
  test('Cloudflare edges → proxied-ok; the origin answered → origin-exposed; another address → differs', async () => {
    let r = await drift(z, { 'www.example.com|A': [A(CF4)], 'ftp.example.com|A': [A('192.0.2.10')], 'worker.example.com|A': [A(CF4)] });
    assert.equal(status(r.row('www.example.com|A')), 'proxied-ok');
    assert.equal(status(r.row('worker.example.com|A')), 'proxied-ok placeholder');
    assert.equal(status(r.row('ftp.example.com|A')), 'match');
    r = await drift(z, { 'www.example.com|A': [A('192.0.2.10')] });
    assert.equal(status(r.row('www.example.com|A')), 'origin-exposed proxy-off-live');
    r = await drift(z, { 'www.example.com|A': [A('203.0.113.9')] });
    assert.equal(status(r.row('www.example.com|A')), 'differs not-cloudflare');
    assert.deepEqual(r.row('www.example.com|A').added, ['203.0.113.9']);
  });

  test('missing live: NXDOMAIN and NODATA', async () => {
    const r = await drift(z, { 'www.example.com|A': { rcode: 'NXDOMAIN' }, 'worker.example.com|TXT': [] });
    assert.equal(status(r.row('www.example.com|A')), 'missing-live nxdomain');
    assert.equal(status(r.row('worker.example.com|A')), 'missing-live nodata');
  });

  test('a DNS-only record answered by Cloudflare edges → differs proxy-on-live', async () => {
    const r = await drift(z, { 'ftp.example.com|A': [A(CF4)], 'www.example.com|A': [A(CF4)] });
    assert.equal(status(r.row('ftp.example.com|A')), 'differs proxy-on-live');
  });

  test('proxied CNAME: flattened (NODATA + edges) is ok; the target is never queried', async () => {
    const zc = cfZone([SOA, ['app', 'CNAME', 'origin-lb.example.net.', P], ['t', 'CNAME', 'abc.cfargotunnel.com.', P], ['shop', 'CNAME', 'shops.myshopify.com.', P]]);
    const r = await drift(zc, { 'app.example.com|A': [A(CF4)], 't.example.com|A': [A(CF4)], 'shop.example.com|A': [A(CF4)] });
    assert.equal(status(r.row('app.example.com|CNAME')), 'proxied-ok');
    assert.equal(status(r.row('t.example.com|CNAME')), 'proxied-ok tunnel');
    assert.equal(status(r.row('shop.example.com|CNAME')), 'proxied-ok provider');
    assert.equal(r.asked('origin-lb.example.net'), false);
    assert.equal(r.asked('abc.cfargotunnel.com'), false);
    assert.deepEqual(r.dns.log.filter((q) => q.name === 'app.example.com').map((q) => q.type).sort(), ['A', 'CNAME']);
  });

  test('proxied CNAME answered with the file target (CNAME or chain) → origin-exposed', async () => {
    const zc = cfZone([SOA, ['app', 'CNAME', 'origin-lb.example.net.', P]]);
    let r = await drift(zc, { 'app.example.com|CNAME': [{ type: 'CNAME', data: 'origin-lb.example.net' }] });
    assert.equal(status(r.row('app.example.com|CNAME')), 'origin-exposed proxy-off-live');
    r = await drift(zc, { 'app.example.com|A': [{ type: 'CNAME', data: 'origin-lb.example.net' }, A('198.51.100.7', { name: 'origin-lb.example.net' })] });
    assert.equal(status(r.row('app.example.com|CNAME')), 'origin-exposed proxy-off-live');
    r = await drift(zc, { 'app.example.com|A': [A('198.51.100.7')] });
    assert.equal(status(r.row('app.example.com|CNAME')), 'differs not-cloudflare');
    r = await drift(zc, { 'app.example.com|CNAME': [{ type: 'CNAME', data: 'elsewhere.example.net' }] });
    assert.equal(status(r.row('app.example.com|CNAME')), 'differs values');
  });

  test('HTTPS / SVCB at a proxied name are Cloudflare-synthesised: skipped, never queried', async () => {
    const zh = cfZone([SOA, ['@', 'A', '192.0.2.10', P], ['@', 'HTTPS', { priority: 1, target: '.', params: { alpn: ['h2'] } }]]);
    const r = await drift(zh, { 'example.com|A': [A(CF4)] });
    assert.equal(status(r.row('example.com|HTTPS')), 'skipped cf-synthesized');
    assert.equal(r.asked('example.com', 'HTTPS'), false);
  });
});

describe('flattening, aliases, routing, wildcards', () => {
  test('flattened CNAME: the target stays hidden by default', async () => {
    const z = cfZone([SOA, ['status', 'CNAME', 'statuspage.example.org.', { ...D, flattenCname: true }]]);
    const r = await drift(z, { 'status.example.com|A': [A('198.51.100.60')] });
    assert.equal(status(r.row('status.example.com|CNAME')), 'flattened-ok target-hidden');
    assert.equal(r.asked('statuspage.example.org'), false);
    assert.equal(planDrift(z).targetsHidden, 1);
  });

  test('flattened CNAME with resolveTargets: compare A(name) with A(target)', async () => {
    const z = cfZone([SOA, ['status', 'CNAME', 'statuspage.example.org.', { ...D, flattenCname: true }], ['@', 'CNAME', 'lb.example.net.', D]]);
    const table = { 'status.example.com|A': [A('198.51.100.60')], 'statuspage.example.org|A': [A('198.51.100.60')], 'example.com|A': [A('198.51.100.61')], 'lb.example.net|A': [A('198.51.100.62')] };
    const r = await drift(z, table, { resolveTargets: true });
    assert.equal(status(r.row('status.example.com|CNAME')), 'flattened-ok');
    assert.equal(status(r.row('example.com|CNAME')), 'differs flatten-mismatch', 'an apex CNAME on Cloudflare is flattened');
    assert.equal(r.report.queries, planDrift(z, { resolveTargets: true }).queries);
    const visible = await drift(z, { 'status.example.com|CNAME': [{ type: 'CNAME', data: 'statuspage.example.org' }], 'status.example.com|A': [A('198.51.100.60')] });
    assert.equal(status(visible.row('status.example.com|CNAME')), 'differs flatten-mismatch');
  });

  test('Route 53 aliases: hidden target, intersecting, rotating managed provider, disjoint', async () => {
    const alias = (target, provider) => ({ alias: { target, zoneId: null, evaluateTargetHealth: false, provider } });
    const z = zone([SOA, ['@', 'A', null, alias('d1.cloudfront.net', 'cloudfront')], ['api', 'A', null, alias('lb.elb.amazonaws.com', 'elb')],
      ['odd', 'A', null, alias('x.example.net', 'other')], ['www', 'A', null, alias('example.com', 'same-zone')]], { format: 'route53', dialect: null });
    const hidden = await drift(z, { 'example.com|A': [A('198.51.100.1')], 'api.example.com|A': [A('198.51.100.2')], 'odd.example.com|A': [A('198.51.100.3')], 'www.example.com|A': [A('198.51.100.1')] });
    assert.equal(status(hidden.row('example.com|A')), 'alias-ok target-hidden');
    assert.equal(status(hidden.row('www.example.com|A')), 'alias-ok', 'a same-zone target is in the file, so it is compared');
    assert.equal(hidden.asked('d1.cloudfront.net'), false);
    const table = {
      'example.com|A': [A('198.51.100.1')], 'd1.cloudfront.net|A': [A('198.51.100.1'), A('198.51.100.9')],
      'api.example.com|A': [A('198.51.100.2')], 'lb.elb.amazonaws.com|A': [A('198.51.100.4')],
      'odd.example.com|A': [A('198.51.100.3')], 'x.example.net|A': [A('198.51.100.5')], 'www.example.com|A': [A('198.51.100.8')]
    };
    const r = await drift(z, table, { resolveTargets: true });
    assert.equal(status(r.row('example.com|A')), 'alias-ok');
    assert.equal(status(r.row('api.example.com|A')), 'alias-ok alias-rotating');
    assert.equal(status(r.row('odd.example.com|A')), 'differs alias-disjoint');
    assert.equal(status(r.row('www.example.com|A')), 'differs alias-disjoint');
  });

  test('routing sets: live within the union of variants → routing-ok, else routing-outside', async () => {
    const w = (id) => ({ routing: { policy: 'weighted', id, weight: 50 } });
    const z = zone([SOA, ['app', 'A', '192.0.2.21', w('blue')], ['app', 'A', '192.0.2.22', w('green')]], { format: 'route53', dialect: null });
    let r = await drift(z, { 'app.example.com|A': [A('192.0.2.22')] });
    assert.equal(status(r.row('app.example.com|A')), 'routing-ok');
    r = await drift(z, { 'app.example.com|A': [A('192.0.2.23')] });
    assert.equal(status(r.row('app.example.com|A')), 'differs routing-outside');
    assert.deepEqual(r.row('app.example.com|A').added, ['192.0.2.23']);
  });

  test('a wildcard RRset is probed at <label>.x (one probe per owner) and marked', async () => {
    const z = cfZone([SOA, ['*.apps', 'A', '192.0.2.20', P], ['*.apps', 'TXT', 'hello']]);
    const r = await drift(z, { 'zzprobe.apps.example.com|A': [A(CF4)], 'zzprobe.apps.example.com|TXT': [{ type: 'TXT', data: ['hello'] }] });
    assert.equal(status(r.row('*.apps.example.com|A')), 'proxied-ok wildcard');
    assert.equal(status(r.row('*.apps.example.com|TXT')), 'match wildcard');
    assert.equal(r.row('*.apps.example.com|A').probe, 'zzprobe.apps.example.com');
    const off = await drift(z, {}, { wildcardProbes: false });
    assert.equal(status(off.row('*.apps.example.com|A')), 'skipped wildcard');
    assert.equal(off.asked('zzprobe.apps.example.com'), false);
    const bad = await drift(z, { 'zzprobe.apps.example.com|A': [A(CF4)] }, { labelFn: () => 'NOT A LABEL!' });
    assert.match(bad.row('*.apps.example.com|A').probe, /^[a-z0-9]{12}\.apps\.example\.com$/);
  });
});

describe('plain comparisons', () => {
  test('TXT split 255+N vs one live string → match txt-chunking', async () => {
    const long = 'k'.repeat(300);
    const z = zone([SOA, ['dkim', 'TXT', [long.slice(0, 255), long.slice(255)]]]);
    const r = await drift(z, { 'dkim.example.com|TXT': [{ type: 'TXT', data: [long.slice(0, 200), long.slice(200)] }] });
    assert.equal(status(r.row('dkim.example.com|TXT')), 'match txt-chunking');
  });

  test('DS digest case, MX dot and case, null MX all match', async () => {
    const z = zone([SOA, ['dev', 'DS', '12345 13 2 ABCDEF01'], ['@', 'MX', '10 Mail.Example.com.'], ['nomail', 'MX', { preference: 0, exchange: '.' }], ['mail', 'A', '198.51.100.25']]);
    const r = await drift(z, {
      'dev.example.com|DS': [{ type: 'DS', data: { keyTag: 12345, algorithm: 13, digestType: 2, digest: 'abcdef01' } }],
      'example.com|MX': [{ type: 'MX', data: { preference: 10, exchange: 'mail.example.com' } }],
      'nomail.example.com|MX': [{ type: 'MX', data: { preference: 0, exchange: '.' } }],
      'mail.example.com|A': [A('198.51.100.25')]
    });
    for (const k of ['dev.example.com|DS', 'example.com|MX', 'nomail.example.com|MX', 'mail.example.com|A']) assert.equal(status(r.row(k)), 'match', k);
  });

  test('a live CNAME where the file has an A → differs cname-live; NODATA → missing-live nodata', async () => {
    const z = zone([SOA, ['www', 'A', '192.0.2.10'], ['old', 'A', '192.0.2.12']]);
    const r = await drift(z, { 'www.example.com|A': [{ type: 'CNAME', data: 'lb.example.net' }, A('198.51.100.9', { name: 'lb.example.net' })], 'old.example.com|TXT': [] });
    assert.equal(status(r.row('www.example.com|A')), 'differs cname-live');
    assert.deepEqual(r.row('www.example.com|A').live, ['CNAME lb.example.net', '198.51.100.9']);
    assert.equal(status(r.row('old.example.com|A')), 'missing-live nodata');
  });

  test('value differences list added and removed values', async () => {
    const z = zone([SOA, ['@', 'NS', 'ns1.example.net.'], ['@', 'NS', 'ns2.example.net.']]);
    const r = await drift(z, { 'example.com|NS': [{ type: 'NS', data: 'ns1.example.net' }, { type: 'NS', data: 'ns3.example.net' }] });
    const row = r.row('example.com|NS');
    assert.equal(status(row), 'differs values');
    assert.deepEqual([row.added, row.removed], [['ns3.example.net.'], ['ns2.example.net.']]);
  });

  test("Cloudflare's hidden CAA records → match cf-caa-added (only Cloudflare CAs, only on Cloudflare zones)", async () => {
    const rows = [SOA, ['@', 'CAA', '0 issue "letsencrypt.org"']];
    const live = [{ type: 'CAA', data: { flags: 0, tag: 'issue', value: 'letsencrypt.org' } }, { type: 'CAA', data: { flags: 0, tag: 'issue', value: 'pki.goog; cansignhttpexchanges=yes' } },
      { type: 'CAA', data: { flags: 0, tag: 'issuewild', value: 'ssl.com' } }];
    let r = await drift(cfZone(rows), { 'example.com|CAA': live });
    assert.equal(status(r.row('example.com|CAA')), 'match cf-caa-added');
    r = await drift(zone(rows), { 'example.com|CAA': live });
    assert.equal(status(r.row('example.com|CAA')), 'differs values');
    r = await drift(cfZone(rows), { 'example.com|CAA': [...live, { type: 'CAA', data: { flags: 0, tag: 'issue', value: 'example-ca.example' } }] });
    assert.equal(status(r.row('example.com|CAA')), 'differs values');
  });

  test('ttl-stale when the live TTL exceeds max(file TTL, 60); never for auto TTLs', async () => {
    const z = cfZone([SOA, ['a', 'A', '198.51.100.1', { proxied: false, ttl: 300 }], ['b', 'A', '198.51.100.2', { ...D, ttl: 300 }], ['c', 'A', '198.51.100.3', { proxied: false, ttl: 30 }]]);
    const r = await drift(z, { 'a.example.com|A': [A('198.51.100.1', { ttl: 3600 })], 'b.example.com|A': [A('198.51.100.2', { ttl: 3600 })], 'c.example.com|A': [A('198.51.100.3', { ttl: 60 })] });
    assert.equal(status(r.row('a.example.com|A')), 'match ttl-stale');
    assert.equal(r.row('a.example.com|A').liveTtl, 3600);
    assert.equal(status(r.row('b.example.com|A')), 'match');
    assert.equal(status(r.row('c.example.com|A')), 'match', 'resolver TTL floors are not staleness');
  });
});

describe('what is never sent', () => {
  test('occluded, private-looking, DNSSEC, unsupported and escaped rows cost no query', async () => {
    const z = zone([SOA, ['dev', 'NS', 'ns.example.net.'], ['old.dev', 'A', '192.0.2.60'], ['intranet', 'A', '10.20.30.40'], ['@', 'RRSIG', '00'],
      ['x', 'A', '999.1.1.1', { invalid: true }], ['name\\032with\\032space', 'TXT', 'x'], ['@', 'A', '192.0.2.10']]);
    const r = await drift(z, { 'example.com|A': [A('192.0.2.10')], 'dev.example.com|NS': [{ type: 'NS', data: 'ns.example.net' }] });
    assert.equal(status(r.row('old.dev.example.com|A')), 'occluded');
    assert.equal(status(r.row('intranet.example.com|A')), 'skipped private');
    assert.equal(status(r.row('example.com|RRSIG')), 'skipped dnssec-type');
    assert.equal(status(r.row('x.example.com|A')), 'skipped unsupported-type');
    assert.equal(status(r.row('name\\032with\\032space.example.com|TXT')), 'skipped escaped-name');
    for (const n of ['old.dev.example.com', 'intranet.example.com', 'x.example.com']) assert.equal(r.asked(n), false, n);
    assert.equal(r.dns.log.length, planDrift(z).queries);
    const all = await drift(z, { 'example.com|A': [A('192.0.2.10')] }, { skipPrivate: false });
    assert.equal(all.asked('intranet.example.com'), true);
    const explicit = await drift(z, { 'example.com|A': [A('192.0.2.10')] }, { skip: ['example.com'] });
    assert.equal(explicit.asked('example.com', 'A'), false);
  });

  test('glue at a cut (dev NS dev.example.com.) is compared, not occluded', async () => {
    const z = zone([SOA, ['dev', 'NS', 'dev'], ['dev', 'A', '192.0.2.60'], ['dev', 'TXT', 'x']]);
    const r = await drift(z, { 'dev.example.com|NS': [{ type: 'NS', data: 'dev.example.com' }], 'dev.example.com|A': [A('192.0.2.60')] });
    assert.equal(status(r.row('dev.example.com|A')), 'match');
    assert.equal(status(r.row('dev.example.com|TXT')), 'occluded');
    assert.equal(r.dns.log.length, planDrift(z).queries);
  });

  test('names outside the zone (the parser\'s OUT_OF_ZONE, ignored by name servers) are never sent', async () => {
    const z = zone([SOA, ['www', 'A', '192.0.2.10'], ['staging.example.org.', 'A', '192.0.2.77'], ['*.dev.example.org.', 'A', '192.0.2.78']]);
    const r = await drift(z, { 'www.example.com|A': [A('192.0.2.10')] });
    assert.equal(status(r.row('staging.example.org|A')), 'skipped out-of-zone');
    assert.equal(status(r.row('*.dev.example.org|A')), 'skipped out-of-zone');
    assert.equal(r.dns.log.some((q) => q.name.endsWith('example.org')), false);
    const plan = planDrift(z);
    assert.equal(plan.skipped.outOfZone, 2);
    assert.equal(r.dns.log.length, plan.queries);
  });

  test('an alias or flattened target that is private-looking or skipped is never sent', async () => {
    const same = (target) => ({ alias: { target, zoneId: null, evaluateTargetHealth: false, provider: 'same-zone' } });
    const z = zone([SOA, ['vpn', 'A', '10.1.2.3'], ['jira.corp', 'A', '198.51.100.7'], ['portal', 'A', null, same('vpn.example.com')],
      ['tickets', 'A', null, same('jira.corp.example.com')], ['www', 'A', '192.0.2.10']], { format: 'route53', dialect: null });
    const r = await drift(z, { 'www.example.com|A': [A('192.0.2.10')] });
    for (const n of ['vpn.example.com', 'jira.corp.example.com', 'portal.example.com', 'tickets.example.com']) assert.equal(r.asked(n), false, n);
    assert.equal(status(r.row('portal.example.com|A')), 'skipped private');
    assert.equal(status(r.row('tickets.example.com|A')), 'skipped private');
    assert.equal(r.dns.log.length, planDrift(z).queries);
    assert.equal(planDrift(z).skipped.private, 4);
    // an explicit skip of the target wins, even with resolveTargets
    const pub = zone([SOA, ['vpn', 'A', '198.51.100.3'], ['portal', 'A', null, same('vpn.example.com')]], { format: 'route53', dialect: null });
    const s = await drift(pub, { 'portal.example.com|A': [A('198.51.100.3')] }, { skip: ['vpn.example.com'], resolveTargets: true });
    assert.equal(s.asked('vpn.example.com'), false);
    assert.equal(status(s.row('portal.example.com|A')), 'alias-ok target-hidden');
    const cf = cfZone([SOA, ['lb', 'A', '198.51.100.4', D], ['status', 'CNAME', 'lb', { ...D, flattenCname: true }]]);
    const f = await drift(cf, { 'status.example.com|A': [A('198.51.100.4')] }, { skip: ['lb.example.com'] });
    assert.equal(f.asked('lb.example.com'), false);
    assert.equal(status(f.row('status.example.com|CNAME')), 'flattened-ok target-hidden');
  });

  test('every query is noCache, never balanced; the chosen resolver is passed through', async () => {
    const z = zone([SOA, ['@', 'A', '192.0.2.10']]);
    let r = await drift(z, { 'example.com|A': [A('192.0.2.10')] });
    for (const q of r.dns.log) {
      assert.equal(q.opts.noCache, true);
      assert.equal('balance' in q.opts, false);
      assert.equal('resolver' in q.opts, false);
    }
    assert.equal(r.report.resolverPolicy, 'chain');
    r = await drift(z, { 'example.com|A': [A('192.0.2.10')] }, { resolver: 'google' });
    assert.ok(r.dns.log.every((q) => q.opts.resolver === 'google'));
    assert.equal(r.report.resolverPolicy, 'google');
  });

  test('the budget is exact and atomic per RRset; later rows are skipped: budget', async () => {
    const z = cfZone([SOA, ['a', 'A', '198.51.100.1', D], ['b', 'A', '198.51.100.2', D], ['c', 'CNAME', 'lb.example.net.', P], ['d', 'A', '198.51.100.4', D]]);
    const plan = planDrift(z, { maxQueries: 5 });
    assert.deepEqual([plan.queries, plan.needed, plan.overBudget, plan.skipped.budget], [4, 7, true, 2]);
    const r = await drift(z, {}, { maxQueries: 5 });
    assert.equal(r.dns.log.length, 4);
    assert.equal(r.report.queries, 4);
    assert.equal(status(r.row('c.example.com|CNAME')), 'skipped budget', 'two queries do not fit in the one left');
    assert.equal(status(r.row('d.example.com|A')), 'skipped budget', 'once exhausted, every later row is skipped');
    assert.equal(planDrift(z, { maxQueries: 1e9 }).maxQueries, DRIFT_MAX_BUDGET);
    assert.equal(planDrift(z).maxQueries, DRIFT_DEFAULT_BUDGET);
  });

  test('queryTypes: an RRset needing a type the transport cannot ask is skipped not-queryable, at no cost', async () => {
    const z = cfZone([SOA, ['@', 'CAA', '0 issue "letsencrypt.org"'], ['a', 'A', '198.51.100.1', D], ['c', 'CNAME', 'lb.example.net.', P],
      ['t', 'TXT', 'hello']]);
    const types = ['SOA', 'NS', 'A', 'TXT'];
    const plan = planDrift(z, { queryTypes: types });
    assert.deepEqual([plan.skipped.type, plan.rrsets, plan.queries], [2, 4, 4], 'CAA and the proxied CNAME (CNAME + A) are left out');
    assert.equal(planDrift(z).skipped.type, 0, 'no transport limit: nothing skipped for its type');
    const r = await drift(z, {}, { queryTypes: types });
    assert.equal(status(r.row('example.com|CAA')), 'skipped not-queryable');
    assert.equal(status(r.row('c.example.com|CNAME')), 'skipped not-queryable');
    assert.ok(!r.asked('example.com', 'CAA') && !r.asked('c.example.com'), 'never sent');
    assert.equal(r.dns.log.length, plan.queries);
  });

  test('a transport that refuses a query for its own budget gives error budget, not transport', async () => {
    const z = zone([SOA, ['a', 'A', '198.51.100.1']]);
    const r = await drift(z, { 'a.example.com|A': { fail: 'budget' } });
    assert.equal(status(r.row('a.example.com|A')), 'error budget');
  });

  test('a budget below the SOA + NS preflight is floored at it: never more queries sent than maxQueries reports', async () => {
    const z = cfZone([SOA, ['a', 'A', '198.51.100.1', D]]);
    for (const max of [0, 1, -5]) {
      const plan = planDrift(z, { maxQueries: max });
      assert.equal(plan.maxQueries, 2, `maxQueries ${max}`);
      assert.equal(plan.queries, 2);
      const r = await drift(z, {}, { maxQueries: max });
      assert.ok(r.dns.log.length <= plan.maxQueries, `sent ${r.dns.log.length} with maxQueries ${max}`);
      assert.equal(status(r.row('a.example.com|A')), 'skipped budget');
    }
  });
});

describe('failures, preflight and cancellation', () => {
  const z = zone([SOA, ['@', 'NS', 'ns1.example.net.'], ['a', 'A', '198.51.100.1'], ['b', 'A', '198.51.100.2'], ['c', 'A', '198.51.100.3'],
    ['d', 'A', '198.51.100.4'], ['e', 'A', '198.51.100.5']]);

  test('transport, timeout, SERVFAIL, REFUSED and filtered answers are error rows, never throws', async () => {
    const r = await drift(z, {
      'a.example.com|A': { fail: 'network' }, 'b.example.com|A': { fail: 'timeout' }, 'c.example.com|A': { rcode: 'SERVFAIL' },
      'd.example.com|A': { rcode: 'REFUSED' }, 'e.example.com|A': { answers: [A('0.0.0.0')], ede: [{ code: 17, name: 'Filtered', text: '' }] }
    });
    assert.deepEqual(['a', 'b', 'c', 'd', 'e'].map((n) => status(r.row(`${n}.example.com|A`))),
      ['error transport', 'error timeout', 'error servfail', 'error refused', 'error filtered']);
    assert.equal(DRIFT_SEVERITY.error, 'unknown');
  });

  test('preflight: serial and name-server comparison', async () => {
    let r = await drift(z, { 'example.com|SOA': [{ type: 'SOA', data: { ...SOA_DATA, serial: 101 } }], 'example.com|NS': [{ type: 'NS', data: 'ns9.example.org' }] });
    assert.deepEqual([r.report.preflight.serial, r.report.preflight.nsMatch, r.report.preflight.liveSerial], ['newer', 'disjoint', 101]);
    assert.deepEqual(r.report.preflight.fileNs, ['ns1.example.net']);
    r = await drift(z, { 'example.com|SOA': [{ type: 'SOA', data: { ...SOA_DATA, serial: 99 } }], 'example.com|NS': [{ type: 'NS', data: 'ns1.example.net' }] });
    assert.deepEqual([r.report.preflight.serial, r.report.preflight.nsMatch], ['older', 'same']);
    assert.equal(status(r.row('example.com|NS')), 'match', 'the NS row reuses the preflight answer');
    assert.equal(r.dns.log.filter((q) => q.name === 'example.com' && q.type === 'NS').length, 1);
    r = await drift(z, { 'example.com|SOA': [{ type: 'SOA', data: { ...SOA_DATA, serial: 4294967295 } }] });
    assert.equal(r.report.preflight.serial, 'older', 'RFC 1982: 2^32-1 is before 100');
  });

  test('an origin that does not exist: every queryable row errors and nothing more is sent', async () => {
    const r = await drift(z, { 'example.com|SOA': { rcode: 'NXDOMAIN' }, 'example.com|NS': { rcode: 'NXDOMAIN' } });
    assert.equal(r.report.preflight.originExists, false);
    assert.equal(r.dns.log.length, 2);
    assert.ok(r.report.rows.every((row) => status(row) === 'error nxdomain'));
  });

  test('cancel mid-run: resolves with aborted and the rows so far', async () => {
    const ac = new AbortController();
    const dns = fakeDns({ ...BASE }, { delayMs: 15 });
    const rows = [];
    const p = driftZone(z, { dns, signal: ac.signal, concurrency: 1, onRow: (row) => { rows.push(row); if (rows.length === 2) ac.abort(); } });
    const report = await p;
    assert.equal(report.aborted, true);
    assert.ok(report.rows.length >= 2 && report.rows.length < 6);
    assert.ok(report.queries < planDrift(z).queries);
    const pre = new AbortController();
    pre.abort();
    const none = await driftZone(z, { dns: fakeDns(BASE), signal: pre.signal });
    assert.deepEqual([none.aborted, none.queries, none.rows.length], [true, 0, 0]);
  });

  test('no more than `concurrency` queries in flight (capped at 8)', async () => {
    const many = zone([SOA, ...Array.from({ length: 30 }, (_, i) => [`h${i}`, 'A', `198.51.100.${i + 1}`])]);
    let dns = fakeDns(BASE, { delayMs: 2 });
    await driftZone(many, { dns, concurrency: 2 });
    assert.ok(dns.maxInFlight <= 2, `in flight ${dns.maxInFlight}`);
    dns = fakeDns(BASE, { delayMs: 2 });
    await driftZone(many, { dns, concurrency: 50 });
    assert.ok(dns.maxInFlight <= DRIFT_MAX_CONCURRENCY, `in flight ${dns.maxInFlight}`);
  });

  test('rows stream through onRow / onProgress and come back in file order with counts', async () => {
    const seen = [];
    const progress = [];
    const dns = fakeDns({ ...BASE, 'a.example.com|A': [A('198.51.100.1')] });
    const report = await driftZone(z, { dns, onRow: (row) => seen.push(row.key), onProgress: (p) => progress.push(p) });
    assert.equal(seen.length, report.rows.length);
    assert.deepEqual(progress.at(-1), { done: report.rows.length, total: report.rows.length });
    assert.deepEqual(report.rows.map((r) => r.name), ['example.com', 'a.example.com', 'b.example.com', 'c.example.com', 'd.example.com', 'e.example.com']);
    assert.equal(Object.values(report.counts).reduce((a, b) => a + b, 0), report.rows.length);
    assert.deepEqual(Object.keys(report.counts), [...DRIFT_STATUSES]);
    await assert.rejects(driftZone(z, {}), TypeError);
  });
});

describe('fixtures', () => {
  // A consistent live view of a zone: file values, Cloudflare edges for proxied names,
  // NODATA for proxied / flattened CNAMEs, one address for aliases, wildcard synthesis.
  function mirror(z) {
    const recs = z.records.filter((r) => r.duplicateOf === undefined && !r.invalid);
    const at = (name) => recs.filter((r) => r.name === name);
    const wild = (name) => {
      for (let parent = name.slice(name.indexOf('.') + 1); parent.includes('.'); parent = parent.slice(parent.indexOf('.') + 1)) {
        if (recs.some((r) => r.name === `*.${parent}`)) return `*.${parent}`;
      }
      return null;
    };
    return (name, type) => {
      let own = at(name);
      if (!own.length && wild(name)) own = at(wild(name));
      if (!own.length) return recs.some((r) => r.name.endsWith(`.${name}`)) ? [] : undefined;
      const same = own.filter((r) => r.type === type);
      const alias = same.find((r) => r.alias);
      if (alias) return [A(type === 'AAAA' ? '2001:db8::201' : '198.51.100.201', { type })];
      const cname = own.find((r) => r.type === 'CNAME');
      const flattened = cname && (cname.proxied === true || cname.flattenCname || (name === z.origin && z.dialect === 'cloudflare'));
      if (flattened && type === 'CNAME') return [];
      if (flattened && type === 'A') return [A(cname.proxied ? CF4 : '198.51.100.200')];
      if ((type === 'A' || type === 'AAAA') && own.some((r) => (r.type === 'A' || r.type === 'AAAA') && r.proxied === true)) {
        return [A(type === 'A' ? CF4 : CF6, { type })];
      }
      return same.map((r) => ({ type, data: r.data, ttl: r.ttl ?? 300 }));
    };
  }

  test('planDrift(zone).queries equals the queries sent, and a consistent zone shows no drift', async () => {
    for (const name of fixtureNames()) {
      const z = loadFixture(name);
      const respond = mirror(z);
      const dns = fakeDns({}, { respond: (n, t) => respond(n, t) ?? { rcode: 'NXDOMAIN' } });
      const report = await driftZone(z, { dns, labelFn: () => 'zzprobe' });
      const plan = planDrift(z);
      assert.equal(dns.log.length, plan.queries, `${name}: planned ${plan.queries}, sent ${dns.log.length}`);
      assert.equal(report.queries, dns.log.length, name);
      assert.equal(report.rows.length, plan.rrsets, name);
      for (const row of report.rows) {
        seenStatuses.add(row.status);
        for (const x of row.reasons) seenReasons.add(x);
        assert.ok(DRIFT_STATUSES.includes(row.status), `${name} ${row.key}`);
        assert.ok(row.reasons.every((x) => DRIFT_REASONS.includes(x)), `${name} ${row.key}`);
        assert.ok(!['differs', 'missing-live', 'origin-exposed', 'error'].includes(row.status), `${name} ${row.key}: ${status(row)}`);
      }
      for (const q of dns.log) assert.ok(!q.name.startsWith('origin-lb.') && !q.name.startsWith('intranet.') && !q.name.startsWith('old.dev.'), `${name}: ${q.name}`);
    }
  });

  test('planDrift on the fixtures: the pinned Cloudflare plan and the internal-zone share', () => {
    const cf = planDrift(loadFixture('cloudflare-export'));
    assert.deepEqual([cf.rrsets, cf.queries, cf.skipped.private, cf.skipped.occluded, cf.targetsHidden], [32, 35, 1, 1, 1]);
    assert.ok(planDrift(loadFixture('internal')).internalShare >= 0.5);
    assert.equal(planDrift({ ...loadFixture('cloudflare-export'), fatal: { code: 'EMPTY' } }).queries, 0);
  });
});

describe('classifyExtraNames', () => {
  test('wildcard (any depth), delegated, extra; file names and other zones are left out', () => {
    const z = loadFixture('cloudflare-export');
    const out = classifyExtraNames(z, ['x7.apps.example.com', 'a.b.apps.example.com', 'a.old.dev.example.com', 'new.example.com', 'www.example.com',
      'NEW.example.com.', 'other.example.org']);
    assert.deepEqual(out, [
      { name: 'a.b.apps.example.com', kind: 'wildcard', matchedBy: '*.apps.example.com' },
      { name: 'x7.apps.example.com', kind: 'wildcard', matchedBy: '*.apps.example.com' },
      { name: 'a.old.dev.example.com', kind: 'delegated', matchedBy: 'dev.example.com' },
      { name: 'new.example.com', kind: 'extra', matchedBy: null }
    ]);
    assert.deepEqual(classifyExtraNames(z, null), []);
  });
});

describe('performance and coverage', () => {
  test(`planDrift on 20,000 records in under ${100 * PERF_FACTOR} ms`, () => {
    const rows = [SOA];
    for (let i = 0; i < 20000; i += 1) {
      const k = i % 4;
      if (k === 0) rows.push([`h${i}`, 'A', `10.7.${(i >> 8) & 255}.${i & 255}`, { proxied: i % 8 === 0, ttlAuto: true }]);
      else if (k === 1) rows.push([`c${i}`, 'CNAME', `h${i - 1}`, { proxied: false }]);
      else if (k === 2) rows.push([`w${i}`, 'A', `198.51.100.${i % 250}`, { proxied: false }]);
      else rows.push([`t${i}`, 'TXT', 'hello']);
    }
    const big = cfZone(rows);
    // best of 3 runs: one parallel-suite GC / scheduler stall must not fail a budget test
    let plan;
    let ms = Infinity;
    for (let run = 0; run < 3; run += 1) {
      const t0 = performance.now();
      plan = planDrift(big);
      ms = Math.min(ms, performance.now() - t0);
    }
    assert.ok(plan.rrsets > 19000);
    assert.ok(ms < 100 * PERF_FACTOR, `plan took ${ms.toFixed(0)} ms`);
  });

  test('every status and every reason was produced by this suite', () => {
    assert.deepEqual([...DRIFT_STATUSES].filter((s) => !seenStatuses.has(s)), []);
    assert.deepEqual([...DRIFT_REASONS].filter((s) => !seenReasons.has(s)), []);
  });
});
