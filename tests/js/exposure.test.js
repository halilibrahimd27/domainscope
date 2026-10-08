/**
 * lib/exposure.js — the origin exposure audit (ROADMAP P0.2): the targets to audit (origin map,
 * imported zone, inventory label; private / reserved / wildcard / bad names probed for DNS leaks
 * only), the DNS-leak classifier over a fake DoH client (A / AAAA, MX, NS, SPF, HTTPS hint, TXT
 * literal), the whole leak scan with failures and an abort, the Globalping request bodies, the
 * reachability verdict from two measurement sides (exposed / filtered / closed / other-content /
 * incomplete), the roll-up, the CDN guess and the CSV export. Pure Node, no network; documentation
 * data only (a globally routable origin is the sanctioned scanme.nmap.org address).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  exposureTargets, targetKey, indexByIp, leaksFromCheck, txtLeaks, runLeakScan, exposureProbes, readExposureSides,
  reachabilityFinding, exposureSummary, sortFindings, exposureCsvRows, EXPOSURE_CSV_COLUMNS, cdnOf, daysAgo,
  EXPOSURE_FINDINGS, EXPOSURE_SEVERITIES, REACH_RESULTS, EXPOSURE_ADVICE, SKIP_REASONS, FINDING_SEVERITY, FINDING_ADVICE
} from '../../assets/js/lib/exposure.js';
import { hostResolutionFrom } from '../../assets/js/lib/doh.js';
import { buildIpIndex } from '../../assets/js/lib/inventory.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';

/** A globally routable stand-in origin (WELL_KNOWN: Nmap's sanctioned scan target); documentation ranges are not routable. */
const ROUTABLE = '45.33.32.156';

/* ------------------------------------------------------------------------ */
/* A fake DohClient over a table (as lib/retire.js's tests use)             */
/* ------------------------------------------------------------------------ */

function fakeDns(table, { rcodes = {}, fail = {} } = {}) {
  const calls = [];
  const response = (name, type, extra) => ({
    name, type, resolver: 'fake', ok: true, rcode: 'NOERROR', flags: {}, answers: [], authorities: [],
    error: null, errorKind: null, ...extra
  });
  async function query(qname, type = 'A', { signal } = {}) {
    throwIfAborted(signal);
    const name = String(qname).toLowerCase().replace(/\.$/, '');
    calls.push(`${name}|${type}`);
    const f = fail[`${name}|${type}`] ?? fail[name];
    if (f) return response(name, type, { ok: false, rcode: null, error: f, errorKind: 'network' });
    const forced = rcodes[`${name}|${type}`] ?? rcodes[name];
    if (forced) return response(name, type, { rcode: forced });
    const answers = [];
    let cur = name;
    for (let hop = 0; hop < 8; hop += 1) {
      const node = table[cur] || table[`*.${cur.split('.').slice(1).join('.')}`];
      if (!node) return response(name, type, { rcode: 'NXDOMAIN', answers });
      if (node.CNAME && type !== 'CNAME') {
        answers.push({ name: cur, type: 'CNAME', ttl: 300, data: node.CNAME });
        cur = node.CNAME;
        continue;
      }
      for (const data of node[type] || []) answers.push({ name: cur, type, ttl: 300, data });
      return response(name, type, { answers });
    }
    return response(name, type, { rcode: 'SERVFAIL' });
  }
  async function resolveHost(name, { signal } = {}) {
    const [a, aaaa] = await Promise.all([query(name, 'A', { signal }), query(name, 'AAAA', { signal })]);
    return hostResolutionFrom(name, a, aaaa);
  }
  return { query, resolveHost, calls };
}

/* ------------------------------------------------------------------------ */
/* The vocabularies                                                         */
/* ------------------------------------------------------------------------ */

describe('vocabularies', () => {
  test('every finding kind has a severity and an advice list; every advice code is known', () => {
    for (const k of EXPOSURE_FINDINGS) {
      assert.ok(EXPOSURE_SEVERITIES.includes(FINDING_SEVERITY[k]), `${k} severity`);
      assert.ok(Array.isArray(FINDING_ADVICE[k]) && FINDING_ADVICE[k].length, `${k} advice`);
      for (const a of FINDING_ADVICE[k]) assert.ok(EXPOSURE_ADVICE.includes(a), `${k}: ${a}`);
    }
    assert.ok(REACH_RESULTS.includes('exposed'));
    assert.deepEqual(SKIP_REASONS.includes('private') && SKIP_REASONS.includes('reserved'), true);
  });
});

/* ------------------------------------------------------------------------ */
/* The targets                                                              */
/* ------------------------------------------------------------------------ */

describe('exposureTargets', () => {
  const map = {
    v: 1, remember: true, entries: [
      { name: 'www.example.net', ip: '192.0.2.10', port: 443, source: 'zone', firstSeen: '2026-10-01T00:00:00Z', lastConfirmed: '2026-10-02T00:00:00Z', server: null },
      { name: '*.apps.example.net', ip: ROUTABLE, port: 8443, source: 'manual', firstSeen: '2026-10-01T00:00:00Z', lastConfirmed: '2026-10-02T00:00:00Z', server: null },
      { name: 'vpn.example.net', ip: '10.0.0.5', port: 443, source: 'manual', firstSeen: '2026-10-01T00:00:00Z', lastConfirmed: '2026-10-02T00:00:00Z', server: null },
      { name: 'shop.example.net', ip: ROUTABLE, port: 443, source: 'verify', firstSeen: '2026-10-01T00:00:00Z', lastConfirmed: '2026-10-02T00:00:00Z', server: null }
    ]
  };

  test('reads the origin map, labels the server from the inventory, classifies why each is not probed', () => {
    const index = buildIpIndex([{ id: 's1', name: 'edge01', ips: [ROUTABLE], groups: [], aliases: [] }]);
    const { targets, capped } = exposureTargets({ map, index });
    assert.equal(capped, false);
    const by = Object.fromEntries(targets.map((t) => [targetKey(t), t]));
    // A documentation address is reserved (not globally routable): DNS leaks only, never a probe.
    assert.equal(by['www.example.net|192.0.2.10|443'].skip, 'reserved');
    assert.equal(by['www.example.net|192.0.2.10|443'].probeable, false);
    // A wildcard is not a name a probe accepts (even at a routable address).
    assert.equal(by[`*.apps.example.net|${ROUTABLE}|8443`].skip, 'wildcard');
    assert.equal(by[`*.apps.example.net|${ROUTABLE}|8443`].wildcard, true);
    // A private origin is never sent.
    assert.equal(by['vpn.example.net|10.0.0.5|443'].skip, 'private');
    assert.equal(by['vpn.example.net|10.0.0.5|443'].private, true);
    // A public origin, a real host name and a usable port: probeable, and the inventory names the server.
    const shop = by[`shop.example.net|${ROUTABLE}|443`];
    assert.equal(shop.skip, null);
    assert.equal(shop.probeable, true);
    assert.equal(shop.server, 'edge01');
    assert.equal(shop.source, 'verify');
    assert.equal(shop.domain, 'example.net');
  });

  test('a port other than 443 shows in the target; a non-HTTP TLS port cannot be probed', () => {
    const m = { v: 1, remember: true, entries: [{ name: 'mail.example.net', ip: ROUTABLE, port: 993, source: 'manual', lastConfirmed: '2026-10-02T00:00:00Z', firstSeen: '2026-10-01T00:00:00Z', server: null }] };
    const [t] = exposureTargets({ map: m }).targets;
    assert.equal(t.target, `${ROUTABLE}:993`);
    assert.equal(t.skip, 'bad-port');
  });

  test('an imported zone’s proxied origins become targets too, de-duplicated with the map', () => {
    const zone = { proxied: [{ name: 'www.example.net', ips: ['192.0.2.10'], host: null }, { name: 'api.example.net', ips: ['192.0.2.14'], host: null }] };
    const { targets } = exposureTargets({ map, zone });
    const names = targets.map((t) => t.name);
    assert.ok(names.includes('api.example.net'), 'the zone-only name is added');
    // www.example.net|192.0.2.10|443 is in both; it appears once.
    assert.equal(targets.filter((t) => targetKey(t) === 'www.example.net|192.0.2.10|443').length, 1);
    assert.equal(targets.find((t) => t.name === 'api.example.net').source, 'zone');
  });

  test('an empty map and no zone give no targets', () => {
    assert.deepEqual(exposureTargets({}).targets, []);
    assert.deepEqual(exposureTargets({ map: null, zone: null }).targets, []);
  });
});

/* ------------------------------------------------------------------------ */
/* The DNS-leak classifier                                                  */
/* ------------------------------------------------------------------------ */

describe('leaksFromCheck', () => {
  const targets = [
    { name: 'www.example.net', ip: '192.0.2.10', port: 443, target: '192.0.2.10', server: 'web01' },
    { name: '*.apps.example.net', ip: '192.0.2.10', port: 443, target: '192.0.2.10', server: 'web01' }
  ];
  const byIp = indexByIp(targets);

  test('a non-proxied A, an MX host, an SPF term and an HTTPS hint reaching the origin each become a finding', () => {
    const check = {
      domain: 'example.net',
      names: [
        { name: 'direct.example.net', ipv4: ['192.0.2.10'], ipv6: [], roles: ['host'] },
        { name: 'mail.example.net', ipv4: ['192.0.2.10'], ipv6: [], roles: ['mx'] },
        { name: 'ns1.example.net', ipv4: ['192.0.2.10'], ipv6: [], roles: ['ns'] },
        { name: 'elsewhere.example.net', ipv4: ['203.0.113.9'], ipv6: [], roles: ['host'] }
      ],
      spf: { status: 'ok', matches: [{ block: '192.0.2.10/32', mechanism: 'ip4', term: 'ip4:192.0.2.10', holder: 'example.net', qualifier: '+' }] },
      https: { status: 'ok', hints: [{ owner: 'www.example.net', address: '192.0.2.10' }] },
      failures: []
    };
    const findings = leaksFromCheck(check, byIp);
    const byKind = Object.fromEntries(findings.map((f) => [`${f.kind}:${f.record}`, f]));
    assert.ok(byKind['dns-a:direct.example.net'], 'a direct A');
    assert.equal(byKind['dns-a:direct.example.net'].severity, 'high');
    assert.equal(byKind['dns-mx:mail.example.net'].kind, 'dns-mx');
    assert.equal(byKind['dns-ns:ns1.example.net'].kind, 'dns-ns');
    assert.ok(byKind['spf:example.net: ip4:192.0.2.10'], 'the SPF term');
    assert.equal(byKind['https-hint:www.example.net'].kind, 'https-hint');
    // Each finding lists every proxied name that shares the leaked address, and names the server.
    assert.deepEqual(byKind['dns-a:direct.example.net'].names, ['*.apps.example.net', 'www.example.net']);
    assert.equal(byKind['dns-a:direct.example.net'].server, 'web01');
    // A record that reaches a different address is not a finding.
    assert.equal(findings.some((f) => f.record === 'elsewhere.example.net'), false);
  });

  test('the proxied name’s own A pointing straight at the origin is critical (the proxy is bypassed in DNS)', () => {
    const check = {
      domain: 'example.net',
      names: [{ name: 'www.example.net', ipv4: ['192.0.2.10'], ipv6: [], roles: ['host'] }],
      spf: { matches: [] }, https: { hints: [] }, failures: []
    };
    const [f] = leaksFromCheck(check, byIp);
    assert.equal(f.kind, 'dns-a');
    assert.equal(f.severity, 'critical');
    assert.deepEqual(f.advice, [...FINDING_ADVICE['dns-a']]);
  });

  test('a missing section or an empty check yields nothing, never a throw', () => {
    assert.deepEqual(leaksFromCheck(null, byIp), []);
    assert.deepEqual(leaksFromCheck({ domain: 'example.net' }, byIp), []);
  });
});

/* ------------------------------------------------------------------------ */
/* TXT literals                                                             */
/* ------------------------------------------------------------------------ */

describe('txtLeaks', () => {
  const byIp = indexByIp([
    { name: 'www.example.net', ip: '192.0.2.10', port: 443 },
    { name: 'v6.example.net', ip: '2001:db8::10', port: 443 }
  ]);

  test('a verification TXT carrying the origin as a literal is a finding; SPF and long keys are skipped', () => {
    const answers = [
      { name: 'example.net', type: 'TXT', data: ['site-verify=abcd 192.0.2.10 ok'] },
      { name: 'example.net', type: 'TXT', data: ['v=spf1 ip4:192.0.2.10 -all'] },
      { name: '_six.example.net', type: 'TXT', data: ['host 2001:db8::10'] },
      { name: 'other.example.net', type: 'TXT', data: ['no address here'] }
    ];
    const findings = txtLeaks(answers, byIp);
    const recs = findings.map((f) => `${f.kind}:${f.record}`);
    assert.ok(recs.includes('txt-ip:example.net'), 'the IPv4 literal');
    assert.ok(recs.includes('txt-ip:_six.example.net'), 'the IPv6 literal');
    assert.equal(findings.some((f) => /spf1/.test(f.detail || '')), false, 'SPF is not a txt-ip leak');
    assert.equal(findings.some((f) => f.record === 'other.example.net'), false);
  });

  test('an address glued inside a longer number is not a false match', () => {
    const findings = txtLeaks([{ name: 'example.net', type: 'TXT', data: ['id=192.0.2.100'] }], byIp);
    assert.deepEqual(findings, []);
  });
});

/* ------------------------------------------------------------------------ */
/* The whole leak scan                                                      */
/* ------------------------------------------------------------------------ */

describe('runLeakScan', () => {
  const targets = [
    { name: 'www.example.net', ip: '192.0.2.10', port: 443, target: '192.0.2.10', server: null, domain: 'example.net', wildcard: false, probeable: false, skip: 'reserved' }
  ];

  test('finds the leaks of a domain over the fake resolver and reports a failed lookup, never a silent dash', async () => {
    const dns = fakeDns({
      'example.net': { A: ['203.0.113.1'], NS: ['ns1.example.net'], TXT: ['v=spf1 ip4:192.0.2.10 -all', 'verify 192.0.2.10'], MX: [{ preference: 10, exchange: 'mail.example.net' }] },
      'www.example.net': { A: ['192.0.2.10'] },
      'direct.example.net': { A: ['192.0.2.10'] },
      'mail.example.net': { A: ['192.0.2.10'] },
      'ns1.example.net': { A: ['203.0.113.2'] }
    }, { fail: { 'example.net|HTTPS': 'SERVFAIL' } });
    const res = await runLeakScan({ targets, dns, hosts: { 'example.net': ['direct.example.net'] } });
    assert.equal(res.aborted, false);
    const kinds = res.findings.map((f) => `${f.kind}:${f.record}`).sort();
    assert.ok(kinds.includes('dns-a:www.example.net'), 'the proxied name resolves straight to the origin');
    assert.ok(kinds.includes('dns-a:direct.example.net'), 'a sibling A');
    assert.ok(kinds.includes('dns-mx:mail.example.net'), 'the MX host');
    assert.ok(kinds.some((k) => k.startsWith('spf:')), 'the SPF term');
    assert.ok(kinds.includes('txt-ip:example.net'), 'the TXT literal');
    // The failed HTTPS lookup is a reported failure, not swallowed.
    assert.ok(res.failures.some((f) => f.what === 'https'), JSON.stringify(res.failures));
    assert.deepEqual(res.domains, ['example.net']);
    // The worst finding is the proxied name pointing straight at the origin.
    assert.equal(sortFindings(res.findings)[0].severity, 'critical');
  });

  test('an abort stops the scan and says so', async () => {
    const ac = new AbortController();
    const dns = fakeDns({ 'example.net': { A: ['203.0.113.1'] } });
    const slow = { query: (n, t, o) => { ac.abort(); return dns.query(n, t, o); }, resolveHost: dns.resolveHost };
    const res = await runLeakScan({ targets, dns: slow, signal: ac.signal });
    assert.equal(res.aborted, true);
  });

  test('a DNS client without resolveHost is refused', async () => {
    await assert.rejects(() => runLeakScan({ targets, dns: { query: async () => ({}) } }), /DNS client/);
  });
});

/* ------------------------------------------------------------------------ */
/* Reachability (opt-in Globalping)                                         */
/* ------------------------------------------------------------------------ */

/** A finished Globalping HTTP measurement: `statusCode`, body and an optional served certificate covering `cover`. */
function measurement({ statusCode = 200, body = '<title>Welcome</title>', cover = null, failure = null, id = 'm1'.repeat(8) } = {}) {
  const result = failure
    ? { status: 'failed', rawOutput: failure }
    : {
      status: 'finished', statusCode, rawBody: body, truncated: false,
      headers: { 'content-type': 'text/html' },
      tls: cover ? { fingerprint256: 'ab'.repeat(32), authorized: true, subject: { CN: cover, alt: `DNS:${cover}` }, issuer: { CN: 'Example CA', O: 'Example' }, createdAt: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z' } : null
    };
  return { id, results: [{ probe: { city: 'Berlin', country: 'DE', asn: 64500 }, result }] };
}

describe('reachability', () => {
  test('exposureProbes builds the CDN GET of the name and the origin GET with the name as Host/SNI', () => {
    const { proxied, origin } = exposureProbes({ name: 'www.example.net', ip: ROUTABLE, port: 443 });
    assert.equal(proxied.target, 'www.example.net');
    assert.equal(proxied.measurementOptions.request.host, undefined);
    assert.equal(origin.target, ROUTABLE);
    assert.equal(origin.measurementOptions.request.host, 'www.example.net');
  });

  test('exposureProbes refuses a private / reserved origin (never sent)', () => {
    assert.throws(() => exposureProbes({ name: 'www.example.net', ip: '192.0.2.10' }), /routable/);
    assert.throws(() => exposureProbes({ name: 'www.example.net', ip: '10.0.0.5' }), /routable/);
  });

  test('the origin serving the site directly with a covering certificate is exposed (critical)', () => {
    const sides = readExposureSides({
      proxiedMeasurement: measurement({ cover: 'www.example.net' }),
      originMeasurement: measurement({ cover: 'www.example.net' }),
      name: 'www.example.net', ip: ROUTABLE
    });
    const r = reachabilityFinding(sides, { name: 'www.example.net', ip: ROUTABLE, server: 'web01' });
    assert.equal(r.result, 'exposed');
    assert.equal(r.finding.kind, 'reachable');
    assert.equal(r.finding.severity, 'critical');
    assert.equal(r.finding.names[0], 'www.example.net');
    assert.equal(r.finding.server, 'web01');
  });

  test('a 403 over a covering certificate is still exposed', () => {
    const sides = readExposureSides({
      proxiedMeasurement: measurement({ statusCode: 200, cover: 'www.example.net' }),
      originMeasurement: measurement({ statusCode: 403, body: 'denied', cover: 'www.example.net' }),
      name: 'www.example.net', ip: ROUTABLE
    });
    assert.equal(reachabilityFinding(sides, { name: 'www.example.net', ip: ROUTABLE }).result, 'exposed');
  });

  test('a timeout is filtered, a refusal is closed — both good, neither a finding', () => {
    const proxiedMeasurement = measurement({ cover: 'www.example.net' });
    const timeout = readExposureSides({ proxiedMeasurement, originMeasurement: measurement({ failure: 'timed out while establishing the TCP connection' }), name: 'www.example.net', ip: ROUTABLE });
    const refused = readExposureSides({ proxiedMeasurement, originMeasurement: measurement({ failure: 'connect ECONNREFUSED' }), name: 'www.example.net', ip: ROUTABLE });
    assert.equal(reachabilityFinding(timeout, { name: 'www.example.net', ip: ROUTABLE }).result, 'filtered');
    assert.equal(reachabilityFinding(timeout, { name: 'www.example.net', ip: ROUTABLE }).finding, null);
    assert.equal(reachabilityFinding(refused, { name: 'www.example.net', ip: ROUTABLE }).result, 'closed');
  });

  test('the origin answering with a certificate that does not cover the name is other-content, not a bypass', () => {
    const sides = readExposureSides({
      proxiedMeasurement: measurement({ cover: 'www.example.net' }),
      originMeasurement: measurement({ cover: 'other.example.org' }),
      name: 'www.example.net', ip: ROUTABLE
    });
    const r = reachabilityFinding(sides, { name: 'www.example.net', ip: ROUTABLE });
    assert.equal(r.result, 'other-content');
    assert.equal(r.finding, null);
  });

  test('the CDN side itself not answering is incomplete', () => {
    const sides = readExposureSides({
      proxiedMeasurement: measurement({ failure: 'timed out' }),
      originMeasurement: measurement({ cover: 'www.example.net' }),
      name: 'www.example.net', ip: ROUTABLE
    });
    assert.equal(reachabilityFinding(sides, { name: 'www.example.net', ip: ROUTABLE }).result, 'incomplete');
  });
});

/* ------------------------------------------------------------------------ */
/* Roll-up, CDN guess, exports                                              */
/* ------------------------------------------------------------------------ */

describe('summary, CDN guess and exports', () => {
  const findings = [
    { kind: 'dns-a', severity: 'high', ip: '192.0.2.10', port: 443, target: '192.0.2.10', names: ['www.example.net'], record: 'a.example.net', recordType: 'A', detail: null, server: 'web01', advice: ['rotate', 'firewall', 'tunnel'] },
    { kind: 'reachable', severity: 'critical', ip: ROUTABLE, port: 443, target: ROUTABLE, names: ['shop.example.net'], record: 'shop.example.net', recordType: null, detail: 'same', server: null, advice: ['firewall', 'aop', 'tunnel', 'rotate'] },
    { kind: 'spf', severity: 'medium', ip: '192.0.2.10', port: 443, target: '192.0.2.10', names: ['www.example.net'], record: 'example.net: ip4:192.0.2.10', recordType: 'SPF', detail: 'ip4', server: 'web01', advice: ['move', 'rotate'] }
  ];

  test('exposureSummary counts by severity, finds the worst and the leaked addresses', () => {
    const s = exposureSummary(findings);
    assert.equal(s.total, 3);
    assert.equal(s.worst, 'critical');
    assert.equal(s.bySeverity.critical, 1);
    assert.equal(s.bySeverity.high, 1);
    assert.equal(s.exposed, 1);
    assert.equal(s.leakedIps, 2);
    assert.equal(exposureSummary([]).worst, null);
  });

  test('sortFindings puts the worst first', () => {
    const sorted = sortFindings(findings);
    assert.equal(sorted[0].kind, 'reachable');
    assert.equal(sorted[sorted.length - 1].kind, 'spf');
  });

  test('cdnOf names the CDN from the public (edge) addresses, or null', () => {
    assert.equal(cdnOf(['104.16.5.5']).id, 'cloudflare');
    assert.equal(cdnOf(['203.0.113.9']), null);
    assert.equal(cdnOf([]), null);
  });

  test('exposureCsvRows begins with the header and has one row per finding, worst first', () => {
    const rows = exposureCsvRows(findings);
    assert.deepEqual(rows[0], [...EXPOSURE_CSV_COLUMNS]);
    assert.equal(rows.length, 4);
    assert.equal(rows[1][0], 'critical');
    assert.equal(rows[1][1], 'reachable');
    assert.equal(rows[1][8], 'firewall aop tunnel rotate');
  });

  test('daysAgo counts whole days, clamped at zero', () => {
    const now = Date.parse('2026-10-10T00:00:00Z');
    assert.equal(daysAgo('2026-10-08T00:00:00Z', now), 2);
    assert.equal(daysAgo('2026-10-11T00:00:00Z', now), 0);
    assert.equal(daysAgo('not a date', now), null);
  });
});
