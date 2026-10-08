// Unit tests for assets/js/lib/dnsmine.js — a mock DoH client (no network).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mineDnsNames, SRV_SERVICES } from '../../assets/js/lib/dnsmine.js';

const APEX = 'example.net';

// Records the mock answers, keyed by "<name>|<type>". Anything not listed
// answers NOERROR with no records (NODATA), like a real quiet zone.
const ZONE = {
  [`${APEX}|NS`]: [
    { name: APEX, type: 'NS', ttl: 3600, data: 'ns1.example.net' },
    { name: APEX, type: 'NS', ttl: 3600, data: 'ns2.example.net' },
    { name: APEX, type: 'NS', ttl: 3600, data: 'ns.externaldns.net' }
  ],
  [`${APEX}|SOA`]: [
    { name: APEX, type: 'SOA', ttl: 3600, data: { mname: 'ns1.example.net', rname: 'hostmaster.example.net', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 } }
  ],
  [`${APEX}|MX`]: [
    { name: APEX, type: 'MX', ttl: 3600, data: { preference: 10, exchange: 'mail.example.net' } },
    { name: APEX, type: 'MX', ttl: 3600, data: { preference: 20, exchange: 'aspmx.l.google.com' } }
  ],
  [`${APEX}|TXT`]: [
    { name: APEX, type: 'TXT', ttl: 3600, data: ['v=spf1 a mx a:smtp.example.net include:_spf.google.com include:spf.protection.outlook.com ip4:1.2.3.4 ~all'] },
    { name: APEX, type: 'TXT', ttl: 3600, data: ['google-site-verification=abc123'] }
  ],
  [`${APEX}|CAA`]: [
    { name: APEX, type: 'CAA', ttl: 3600, data: { flags: 0, tag: 'issue', value: 'letsencrypt.org' } },
    { name: APEX, type: 'CAA', ttl: 3600, data: { flags: 0, tag: 'iodef', value: 'mailto:soc@alerts.example.net' } }
  ],
  [`${APEX}|HTTPS`]: [
    { name: APEX, type: 'HTTPS', ttl: 3600, data: { priority: 1, target: 'anycast.example.net', params: { alpn: ['h2'] } } }
  ],
  [`_dmarc.${APEX}|TXT`]: [
    { name: `_dmarc.${APEX}`, type: 'TXT', ttl: 3600, data: ['v=DMARC1; p=reject; rua=mailto:dmarc@example.net,mailto:agg@thirdparty.com; ruf=mailto:forensics@reports.example.net'] }
  ],
  [`_autodiscover._tcp.${APEX}|SRV`]: [
    { name: `_autodiscover._tcp.${APEX}`, type: 'SRV', ttl: 3600, data: { priority: 0, weight: 0, port: 443, target: 'autodiscover.example.net' } }
  ],
  [`_sip._tls.${APEX}|SRV`]: [
    { name: `_sip._tls.${APEX}`, type: 'SRV', ttl: 3600, data: { priority: 100, weight: 1, port: 5061, target: 'sip.example.net' } }
  ],
  [`_matrix._tcp.${APEX}|SRV`]: [
    { name: `_matrix._tcp.${APEX}`, type: 'SRV', ttl: 3600, data: { priority: 10, weight: 5, port: 443, target: 'matrix.externalhost.net' } }
  ],
  // A CNAME chain (and an in-domain A record) carried on one of the SRV lookups.
  [`_http._tcp.${APEX}|SRV`]: [
    { name: 'status.example.net', type: 'CNAME', ttl: 300, data: 'statuspage.example.net' },
    { name: 'status.example.net', type: 'A', ttl: 300, data: '203.0.113.66' }
  ]
};

function makeDns(zone = ZONE, { ptr = {} } = {}) {
  const calls = [];
  return {
    calls,
    async query(name, type) {
      calls.push({ name, type });
      return { ok: true, rcode: 'NOERROR', answers: zone[`${name}|${type}`] || [], authorities: [], additionals: [] };
    },
    async ptr(ip) {
      return ptr[ip] || [];
    }
  };
}

describe('mineDnsNames', () => {
  test('harvests in-domain names from every record type', async () => {
    const dns = makeDns();
    const { names, evidence, externalRefs } = await mineDnsNames(APEX, { dns });

    for (const n of [
      'ns1.example.net', 'ns2.example.net', 'mail.example.net', 'smtp.example.net',
      'alerts.example.net', 'anycast.example.net', 'reports.example.net',
      'autodiscover.example.net', 'sip.example.net', 'status.example.net', 'statuspage.example.net'
    ]) {
      assert.ok(names.includes(n), `missing name: ${n}`);
    }
    // the apex itself is never reported as a discovery
    assert.ok(!names.includes(APEX));
    // de-duplicated
    assert.equal(new Set(names).size, names.length);

    // evidence carries the right `from` source for a few names
    const from = (name) => evidence.filter((e) => e.name === name).map((e) => e.from);
    assert.ok(from('mail.example.net').includes('MX'));
    assert.ok(from('ns1.example.net').includes('NS'));
    assert.ok(from('ns1.example.net').includes('SOA'));
    assert.ok(from('smtp.example.net').includes('SPF'));
    assert.ok(from('reports.example.net').includes('DMARC'));
    assert.ok(from('alerts.example.net').includes('CAA'));
    assert.ok(from('anycast.example.net').includes('HTTPS'));
    assert.ok(from('autodiscover.example.net').includes('SRV'));
    assert.ok(from('statuspage.example.net').includes('CNAME'));

    // external references, not names
    for (const x of ['ns.externaldns.net', 'aspmx.l.google.com', '_spf.google.com',
      'spf.protection.outlook.com', 'letsencrypt.org', 'thirdparty.com', 'matrix.externalhost.net']) {
      assert.ok(externalRefs.includes(x), `missing externalRef: ${x}`);
      assert.ok(!names.includes(x), `external leaked into names: ${x}`);
    }
  });

  test('queries the apex records, _dmarc and every SRV service', async () => {
    const dns = makeDns();
    let progressCalls = 0;
    let lastDone = 0;
    const totals = [];
    // Collect inside the hook and assert afterwards: mineDnsNames swallows hook errors on purpose.
    await mineDnsNames(APEX, { dns, onProgress: (p) => { progressCalls += 1; lastDone = p.done; totals.push(p.total); } });
    const expected = 6 + 1 + SRV_SERVICES.length;
    assert.ok(totals.length > 0 && totals.every((t) => t === expected), `progress totals: ${[...new Set(totals)]}`);
    assert.equal(dns.calls.length, expected);
    assert.equal(progressCalls, expected);
    assert.equal(lastDone, expected);
    // apex query types
    const apexTypes = dns.calls.filter((c) => c.name === APEX).map((c) => c.type).sort();
    assert.deepEqual(apexTypes, ['CAA', 'HTTPS', 'MX', 'NS', 'SOA', 'TXT']);
    assert.ok(dns.calls.some((c) => c.name === `_dmarc.${APEX}` && c.type === 'TXT'));
  });

  test('PTR hook (opt-in) resolves in-domain IPs and keeps in-domain PTR names', async () => {
    const dns = makeDns(ZONE, { ptr: { '203.0.113.66': ['origin.example.net', 'shared.otherco.net'] } });
    const off = await mineDnsNames(APEX, { dns });
    assert.ok(!off.names.includes('origin.example.net'), 'PTR off by default');

    const dns2 = makeDns(ZONE, { ptr: { '203.0.113.66': ['origin.example.net', 'shared.otherco.net'] } });
    const on = await mineDnsNames(APEX, { dns: dns2, resolvePtr: true });
    assert.ok(on.names.includes('origin.example.net'), 'in-domain PTR name kept');
    assert.ok(on.externalRefs.includes('shared.otherco.net'));
    assert.ok(on.evidence.some((e) => e.name === 'origin.example.net' && e.from === 'PTR'));
  });

  test('a failing query is skipped without throwing', async () => {
    const dns = {
      async query(name, type) {
        if (name === APEX && type === 'MX') throw new TypeError('network');
        return { ok: true, rcode: 'NOERROR', answers: ZONE[`${name}|${type}`] || [] };
      }
    };
    const { names } = await mineDnsNames(APEX, { dns });
    assert.ok(!names.includes('mail.example.net'), 'the failed MX contributes nothing');
    assert.ok(names.includes('ns1.example.net'), 'other records still mined');
  });

  test('abort propagates', async () => {
    const ctl = new AbortController();
    const dns = { async query() { ctl.abort(); const e = new Error('aborted'); e.name = 'AbortError'; throw e; } };
    await assert.rejects(mineDnsNames(APEX, { dns, signal: ctl.signal }), (e) => e.name === 'AbortError');
  });

  test('service labels are never reported as names (CNAME\'d _dmarc / SRV, in-domain _spf include)', async () => {
    const vendor = `${APEX}._d.dmarcvendor.example`;
    const zone = {
      ...ZONE,
      [`${APEX}|TXT`]: [{ name: APEX, type: 'TXT', ttl: 3600, data: ['v=spf1 include:_spf.example.net ~all'] }],
      // hosted DMARC: the probed name CNAMEs to the vendor, which holds the TXT
      [`_dmarc.${APEX}|TXT`]: [
        { name: `_dmarc.${APEX}`, type: 'CNAME', ttl: 3600, data: vendor },
        { name: vendor, type: 'TXT', ttl: 3600, data: ['v=DMARC1; p=reject; rua=mailto:agg@reports.example.net'] }
      ],
      [`_autodiscover._tcp.${APEX}|SRV`]: [
        { name: `_autodiscover._tcp.${APEX}`, type: 'CNAME', ttl: 3600, data: APEX }
      ]
    };
    const { names, evidence } = await mineDnsNames(APEX, { dns: makeDns(zone) });
    for (const n of [`_dmarc.${APEX}`, `_autodiscover._tcp.${APEX}`, `_spf.${APEX}`]) {
      assert.ok(!names.includes(n), `service label reported: ${n}`);
    }
    assert.ok(names.every((n) => !n.split('.').some((l) => l.startsWith('_'))), names.join(', '));
    assert.ok(evidence.every((e) => !e.name.split('.').some((l) => l.startsWith('_'))));
    // the DMARC record is still read through the CNAME'd _dmarc
    assert.ok(names.includes('reports.example.net'));
  });

  test('a wildcard CNAME to the apex adds nothing', async () => {
    const dns = {
      async query(name) {
        const answers = name === APEX ? [] : [{ name, type: 'CNAME', ttl: 300, data: APEX }];
        return { ok: true, rcode: 'NOERROR', answers, authorities: [], additionals: [] };
      }
    };
    const { names, evidence } = await mineDnsNames(APEX, { dns });
    assert.deepEqual(names, []);
    assert.deepEqual(evidence, []);
  });

  test('SOA RNAME: an escaped dot stays in the mailbox; the mail domain is still mined', async () => {
    const soa = (rname) => ({
      ...ZONE,
      [`${APEX}|SOA`]: [{ name: APEX, type: 'SOA', ttl: 3600, data: { mname: 'ns1.example.net', rname, serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 } }]
    });
    const escaped = await mineDnsNames(APEX, { dns: makeDns(soa('dns\\.admin.example.net')) });
    assert.ok(!escaped.names.includes('admin.example.net'), 'dns\\.admin is a mailbox, not a host');

    const nested = await mineDnsNames(APEX, { dns: makeDns(soa('hostmaster.corp.example.net')) });
    assert.ok(nested.names.includes('corp.example.net'));
    assert.ok(nested.evidence.some((e) => e.name === 'corp.example.net' && e.from === 'SOA'));
  });

  test('the SOA repeated in every negative answer is one evidence row', async () => {
    const soaRr = { name: APEX, type: 'SOA', ttl: 3600, data: { mname: 'ns1.example.net', rname: 'hostmaster.example.net', serial: 1, refresh: 900, retry: 900, expire: 1800, minimum: 60 } };
    const dns = {
      async query(name, type) {
        const answers = ZONE[`${name}|${type}`] || [];
        // NXDOMAIN / NODATA answers carry the zone's SOA in the authority section
        return { ok: true, rcode: answers.length ? 'NOERROR' : 'NXDOMAIN', answers, authorities: answers.length ? [] : [soaRr], additionals: [] };
      }
    };
    const { evidence } = await mineDnsNames(APEX, { dns });
    const keys = evidence.map((e) => `${e.name}|${e.from}|${e.record}`);
    assert.equal(new Set(keys).size, keys.length, 'no duplicate evidence rows');
    assert.equal(evidence.filter((e) => e.name === 'ns1.example.net' && e.from === 'SOA').length, 1);
  });

  test('externalEvidence names the record of every external reference (the NS and MX hosts the locale packs read)', async () => {
    const { externalRefs, externalEvidence } = await mineDnsNames(APEX, { dns: makeDns() });
    const of = (from) => externalEvidence.filter((e) => e.from === from).map((e) => e.name).sort();
    assert.deepEqual(of('NS'), ['ns.externaldns.net']);
    assert.deepEqual(of('MX'), ['aspmx.l.google.com']);
    assert.deepEqual(of('SPF'), ['_spf.google.com', 'spf.protection.outlook.com']);
    assert.deepEqual(of('SRV'), ['matrix.externalhost.net']);
    assert.deepEqual(of('CAA'), ['letsencrypt.org']);
    assert.deepEqual([...new Set(externalEvidence.map((e) => e.name))].sort(), externalRefs, 'the same names as externalRefs');
    const keys = externalEvidence.map((e) => `${e.name}|${e.from}|${e.record}`);
    assert.equal(new Set(keys).size, keys.length, 'each (name, from, record) once');
  });

  test('invalid input returns empty', async () => {
    assert.deepEqual(await mineDnsNames('', { dns: makeDns() }), { names: [], evidence: [], externalRefs: [], externalEvidence: [] });
    assert.deepEqual(await mineDnsNames(APEX, {}), { names: [], evidence: [], externalRefs: [], externalEvidence: [] });
  });
});
