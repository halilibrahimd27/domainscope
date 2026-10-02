/**
 * lib/portfolio.js — the Domain portfolio: the list it reads, how RDAP statuses read for risk,
 * the name server domains (each asked once per run), a run over a fake DoH and a fake RDAP
 * registry (rows fill as lookups land, a stop, a Retry past the cache), the facts of each row,
 * the expiry dates of the calendar and the export rows. No network.
 */
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as portfolioLib from '../../assets/js/lib/portfolio.js';
import {
  PORTFOLIO_LOOKUPS, PORTFOLIO_CELLS, CELL_LOOKUPS, CRITICAL_STATUSES, PORTFOLIO_MAX_DOMAINS, PORTFOLIO_DKIM_SELECTORS,
  parsePortfolioInput, statusRisk, nsDomainsOf, createPortfolio, portfolioFacts, cellFailures,
  rowRisk, expiryBand, expiryEvents, expiryUid, exportRow, EXPORT_COLUMNS, portfolioSummaryFacts
} from '../../assets/js/lib/portfolio.js';
import { clearRdapCache } from '../../assets/js/lib/rdap.js';
import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';

const NOW = new Date('2026-10-02T12:00:00Z');
const DAY = 86400000;
const iso = (days) => new Date(NOW.getTime() + days * DAY).toISOString();

/* ------------------------------------------------------------------------ */
/* Fakes (the DohClient contract with real wire records; an RDAP registry)   */
/* ------------------------------------------------------------------------ */

function rrs(list) {
  if (!list.length) return [];
  return decodeMessage(encodeMessage({ answers: list.map((r) => ({ ttl: 300, ...r })) })).answers;
}
const asList = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

export function fakeDns(zone, { signed = [], fail = {}, rcodes = {}, delayMs = 0 } = {}) {
  const calls = [];
  const under = (name, list) => list.some((z) => name === z || name.endsWith(`.${z}`));
  const base = (name, type, extra) => ({
    name, type, resolver: 'fake', ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: false, cd: false },
    answers: [], authorities: [], ede: [], elapsedMs: 1, error: null, errorKind: null, ...extra
  });
  async function query(qname, type = 'A', { dnssec = false, cd = false, signal, noCache = false } = {}) {
    throwIfAborted(signal);
    if (delayMs) {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, delayMs);
        signal?.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
      });
    }
    const name = String(qname).toLowerCase().replace(/\.$/, '');
    calls.push({ name, type, noCache });
    const f = fail[`${name}|${type}`];
    if (f) return base(name, type, { ok: false, rcode: null, flags: null, error: f, errorKind: 'network' });
    if (rcodes[`${name}|${type}`]) return base(name, type, { rcode: rcodes[`${name}|${type}`] });
    const answers = [];
    let cur = name;
    let rcode = 'NOERROR';
    for (let i = 0; i < 12; i += 1) {
      const node = zone[cur];
      if (!node) {
        rcode = 'NXDOMAIN';
        break;
      }
      if (node.CNAME && type !== 'CNAME') {
        answers.push({ name: cur, type: 'CNAME', data: node.CNAME });
        cur = node.CNAME;
        continue;
      }
      for (const data of asList(node[type])) answers.push({ name: cur, type, data: type === 'TXT' && typeof data === 'string' ? [data] : data });
      break;
    }
    const res = base(name, type, { rcode, answers: rrs(answers) });
    res.flags = { ...res.flags, ad: under(cur, signed) && !cd };
    return res;
  }
  return { calls, query };
}

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/rdap+json' } });
const REGISTRY = 'https://rdap.example.net/';

function rdapJson(domain, { status = ['client transfer prohibited'], days = 400, registrar = 'Example Registrar, Inc.' } = {}) {
  return {
    objectClassName: 'domain', ldhName: domain.toUpperCase(), status,
    events: [{ eventAction: 'registration', eventDate: '2001-05-01T00:00:00Z' }, ...(days === null ? [] : [{ eventAction: 'expiration', eventDate: iso(days) }])],
    entities: [{ objectClassName: 'entity', roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', registrar]]], publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }] }],
    secureDNS: { delegationSigned: false }
  };
}

/** A registry for .com / .net / .org: `answers[domain]` is the JSON or an HTTP status. */
function rdapFetch(answers) {
  const log = [];
  const impl = async (url, init = {}) => {
    const u = String(url);
    log.push(u);
    if (init.signal && init.signal.aborted) throw init.signal.reason;
    if (u === 'https://data.iana.org/rdap/dns.json') return json({ services: [[['com', 'net', 'org'], [REGISTRY]]] });
    const name = decodeURIComponent(u.split('/domain/')[1] || '');
    if (u.startsWith(REGISTRY) || u.startsWith('https://rdap.org/')) {
      const a = answers[name];
      if (typeof a === 'number') return json({ errorCode: a }, a);
      return a ? json(a) : json({ errorCode: 404 }, 404);
    }
    throw new TypeError(`unexpected fetch ${u}`);
  };
  return Object.assign(impl, { log, rdap: () => log.filter((u) => u.includes('/domain/')) });
}

const DNSKEY = { flags: 257, protocol: 3, algorithm: 13, publicKey: Buffer.alloc(64, 7).toString('base64') };

/** Three domains on one provider's name servers (ns*.example.net), plus a .tr domain without RDAP. */
const ZONE = {
  'example.com': {
    NS: ['ns1.example.net', 'ns2.example.net'],
    DS: { keyTag: 1234, algorithm: 13, digestType: 2, digest: 'ab'.repeat(32) },
    DNSKEY,
    CAA: [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'issuewild', value: 'sectigo.com' }],
    MX: { preference: 10, exchange: 'mx.example.com' },
    TXT: ['v=spf1 include:_spf.example.net mx -all', 'site-verification=abc']
  },
  '_spf.example.net': { TXT: 'v=spf1 ip4:192.0.2.0/24 include:_spf2.example.net ~all' },
  '_spf2.example.net': { TXT: 'v=spf1 ip4:198.51.100.0/24 -all' },
  'mx.example.com': { A: '192.0.2.25' },
  '_dmarc.example.com': { TXT: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com' },
  'google._domainkey.example.com': { TXT: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqh' },
  '_mta-sts.example.com': { TXT: 'v=STSv1; id=20261001' },
  '_smtp._tls.example.com': { TXT: 'v=TLSRPTv1; rua=mailto:tls@example.com' },
  'example.org': {
    NS: ['ns1.example.net', 'ns.example.org'],
    MX: { preference: 0, exchange: '.' },
    TXT: 'v=spf1 -all'
  },
  '_dmarc.example.org': { TXT: 'v=DMARC1; p=reject' },
  'example.net': {
    NS: ['ns1.example.net'],
    TXT: 'v=spf1 ~all'
  },
  'example-test.com.tr': {
    NS: ['ns1.example.net'],
    MX: { preference: 10, exchange: 'mx.example-test.com.tr' },
    TXT: 'v=spf1 include:a.example.net include:b.example.net include:c.example.net include:d.example.net include:e.example.net include:f.example.net include:g.example.net include:h.example.net include:i.example.net include:j.example.net include:k.example.net -all'
  },
  'mx.example-test.com.tr': { A: '203.0.113.25' },
  ...Object.fromEntries('abcdefghijk'.split('').map((c) => [`${c}.example.net`, { TXT: 'v=spf1 ip4:203.0.113.0/24 -all' }]))
};

const RDAP = {
  'example.com': rdapJson('example.com', { days: 400 }),
  'example.org': rdapJson('example.org', { status: ['active'], days: 20 }),
  'example.net': rdapJson('example.net', { status: ['clientHold', 'redemptionPeriod', 'client transfer prohibited'], days: 12 })
};

beforeEach(() => clearRdapCache());

const run4 = (opts = {}) => {
  const dns = fakeDns(ZONE, { signed: ['example.com'], rcodes: { 'example.net|CAA': 'SERVFAIL' }, ...opts.dnsOpts });
  const fetchImpl = rdapFetch(opts.rdap || RDAP);
  const events = [];
  const run = createPortfolio({
    domains: ['example.com', 'example.org', 'example.net', 'example-test.com.tr'],
    dns, fetchImpl, rdapOptions: { rdapOrgIntervalMs: 0 }, onEvent: (e) => events.push(e), ...opts.run
  });
  return { dns, fetchImpl, events, run };
};

/* ------------------------------------------------------------------------ */

describe('the list', () => {
  test('registrable domains, de-duplicated in order; host names and URLs name their domain; junk said', () => {
    const p = parsePortfolioInput('example.com\nwww.example.com, https://shop.example.org/cart\n# a comment\nexample.com; 192.0.2.1 com.tr not_a_domain!\nexample-test.com.tr');
    assert.deepEqual(p.domains, ['example.com', 'example.org', 'example-test.com.tr']);
    assert.deepEqual(p.reduced, [{ input: 'shop.example.org', domain: 'example.org' }]);
    assert.deepEqual(p.invalid, ['192.0.2.1', 'com.tr', 'not_a_domain!']);
    assert.equal(p.capped, 0);
  });

  test('at most PORTFOLIO_MAX_DOMAINS (or `max`): the rest are counted', () => {
    const many = Array.from({ length: 5 }, (_, i) => `d${i}.example.com`).join('\n');
    const p = parsePortfolioInput(`example.net example.org ${many} example-test.com.tr`, { max: 2 });
    assert.deepEqual(p, { domains: ['example.net', 'example.org'], reduced: [], invalid: [], capped: 2 }, 'example.com (five host names) and example-test.com.tr left out');
    assert.equal(PORTFOLIO_MAX_DOMAINS, 300);
  });
});

describe('RDAP statuses read for risk', () => {
  test('no transfer prohibition at all is a hijack risk; a client, a registry (server) or a plain RFC 9083 one locks; RFC 8056 and EPP spellings alike', () => {
    assert.equal(statusRisk(['client transfer prohibited']).risk, 'ok');
    assert.equal(statusRisk(['clientTransferProhibited', 'clientDeleteProhibited']).transferLock, true);
    const open = statusRisk(['active']);
    assert.deepEqual([open.risk, open.transferLock, open.registryLock], ['hijack', false, false]);
    // A registry lock (RFC 5731: transfer requests MUST be rejected) is a transfer lock, and is said as one.
    const reg = statusRisk(['server transfer prohibited', 'active']);
    assert.deepEqual([reg.risk, reg.transferLock, reg.registryLock], ['ok', true, true]);
    assert.deepEqual(statusRisk(['serverTransferProhibited']).transferLock, true);
    // RFC 9083's plain "transfer prohibited" too.
    const plain = statusRisk(['transfer prohibited']);
    assert.deepEqual([plain.risk, plain.transferLock, plain.registryLock], ['ok', true, false]);
    // As Domain overview and Domain Health read it (lib/passport.js, lib/health.js): any transfer prohibition.
    for (const statuses of [['server delete prohibited', 'server transfer prohibited', 'server update prohibited'], ['client_transfer_prohibited'], ['Client Transfer Prohibited']]) {
      assert.equal(statusRisk(statuses).transferLock, true, statuses.join());
    }
    assert.deepEqual(statusRisk(['client transfer prohibited']).transferCodes, ['client transfer prohibited']);
    assert.deepEqual(statusRisk(['active', 'server transfer prohibited', 'transfer prohibited']).transferCodes, ['server transfer prohibited', 'transfer prohibited']);
  });

  test('serverHold, clientHold, redemptionPeriod and pendingDelete are critical, before anything else', () => {
    for (const s of ['serverHold', 'server hold', 'clientHold', 'redemption period', 'pendingDelete', 'pending delete']) {
      const r = statusRisk([s, 'client transfer prohibited']);
      assert.equal(r.risk, 'critical', s);
      assert.equal(r.critical.length, 1, s);
    }
    assert.deepEqual(statusRisk(['redemptionPeriod', 'pendingDelete', 'serverHold']).critical, ['serverHold', 'redemptionPeriod', 'pendingDelete']);
    assert.deepEqual(CRITICAL_STATUSES, ['serverHold', 'clientHold', 'redemptionPeriod', 'pendingDelete']);
    // holds sort first in the flags (lib/passport.js rdapStatusFlags)
    assert.equal(statusRisk(['client transfer prohibited', 'server hold']).flags[0].kind, 'hold');
  });

  test('a pending transfer (a hijack in progress if nobody here asked for it) is a risk of its own, ranked right after critical', () => {
    for (const statuses of [['client transfer prohibited', 'pending transfer'], ['pendingTransfer', 'clientTransferProhibited'], ['pending transfer']]) {
      assert.equal(statusRisk(statuses).risk, 'pending-transfer', statuses.join());
    }
    assert.equal(statusRisk(['pending transfer', 'server hold']).risk, 'critical', 'a critical status first');
    const facts = (status, days) => portfolioFacts({ domain: 'example.com', rdap: { ok: true, domain: 'example.com', tld: 'com', registrar: 'Example Registrar, Inc.', status, expires: new Date(NOW.getTime() + days * DAY) } }, { now: NOW });
    const f = facts(['client transfer prohibited', 'pending transfer'], 400);
    assert.equal(rowRisk(f), 'pending-transfer');
    assert.equal(rowRisk(facts(['client transfer prohibited', 'pending transfer'], -2)), 'pending-transfer', 'ranked before an expiry gone by');
    assert.equal(rowRisk(facts(['pending transfer', 'server hold'], 400)), 'critical', 'after a critical status');
    assert.deepEqual(portfolioSummaryFacts([f]).pendingTransfer, ['example.com']);
  });

  test('a row\'s risk: the first that applies, worst first', () => {
    const of = (status, days) => rowRisk(portfolioFacts({ domain: 'example.com', rdap: { ok: true, domain: 'example.com', tld: 'com', registrar: 'Example Registrar, Inc.', status, expires: new Date(NOW.getTime() + days * DAY + DAY / 2) } }, { now: NOW }));
    const locked = ['client transfer prohibited'];
    assert.deepEqual([
      of(['server hold', 'pending transfer'], -1), of(['pending transfer', ...locked], -1), of(locked, -1), of(['active'], 10), of(['active'], 45), of(locked, 45), of(locked, 400)
    ], ['critical', 'pending-transfer', 'expired', 'expiring', 'hijack', 'warn', 'ok']);
  });

  test('no status at all: nothing can be said', () => {
    assert.deepEqual(statusRisk([]), { flags: [], critical: [], transferLock: null, registryLock: null, transferCodes: [], risk: null });
    assert.deepEqual(statusRisk(undefined).risk, null);
  });

  test('expiry bands: Domain Health\'s (expired, < 30 error, < 60 warn)', () => {
    assert.deepEqual([-1, 0, 29, 30, 59, 60, null].map(expiryBand), ['expired', 'error', 'error', 'warn', 'warn', 'ok', null]);
  });
});

describe('name server domains', () => {
  test('one entry per registrable domain, own first', () => {
    assert.deepEqual(nsDomainsOf(['ns2.example.net', 'NS1.example.net.', 'ns.example.org', 'ns-1.awsdns-01.co.uk'], 'example.org'), [
      { domain: 'example.org', hosts: ['ns.example.org'], own: true },
      { domain: 'awsdns-01.co.uk', hosts: ['ns-1.awsdns-01.co.uk'], own: false },
      { domain: 'example.net', hosts: ['ns1.example.net', 'ns2.example.net'], own: false }
    ]);
  });

  test('deduped over the portfolio: a provider shared by every zone is asked once, a portfolio domain as itself', async () => {
    const zone = { ...ZONE, 'example.org': { ...ZONE['example.org'], NS: ['ns1.example.net', 'ns.example.org', 'ns1.example-test.com.tr'] } };
    const fetchImpl = rdapFetch(RDAP);
    const run = createPortfolio({ domains: ['example.com', 'example.org', 'example-test.com.tr'], dns: fakeDns(zone), fetchImpl, rdapOptions: { rdapOrgIntervalMs: 0 } });
    await run.start();
    assert.deepEqual(fetchImpl.rdap().map((u) => u.split('/domain/')[1]).sort(), ['example.com', 'example.net', 'example.org'],
      'example.net once for the three zones; .tr has no RDAP, asked neither as a domain nor as a name server domain');
    assert.deepEqual(run.affectedBy('example.net'), ['example.com', 'example.org', 'example-test.com.tr']);
    assert.deepEqual(run.affectedBy('example-test.com.tr'), ['example-test.com.tr', 'example.org'], 'a portfolio domain serving another one');
    assert.deepEqual(run.facts('example.org', { now: NOW }).ns.domains.map((d) => [d.domain, d.own]),
      [['example.org', true], ['example-test.com.tr', false], ['example.net', false]]);
  });
});

describe('a run', () => {
  test('every lookup of every row lands; RDAP once per distinct domain (portfolio and name server domains alike)', async () => {
    const { run, fetchImpl, events, dns } = run4();
    await run.start();
    assert.equal(run.status, 'done');
    const rdapAsked = fetchImpl.rdap().map((u) => u.split('/domain/')[1]).sort();
    assert.deepEqual(rdapAsked, ['example.com', 'example.net', 'example.org'], 'example.net is the provider of all four and a portfolio domain: asked once; .tr has no RDAP');
    for (const d of run.domains()) {
      assert.deepEqual(run.pending(d), [], d);
      for (const id of PORTFOLIO_LOOKUPS) assert.ok(events.some((e) => e.type === 'lookup' && e.domain === d && e.lookup === id), `${d} ${id}`);
      assert.ok(events.some((e) => e.type === 'row' && e.domain === d && e.state === 'done'), d);
    }
    assert.deepEqual(run.affectedBy('example.net'), ['example.net', 'example.com', 'example.org', 'example-test.com.tr']);
    // DKIM: the common selectors and one random one per domain; nothing else under _domainkey
    const dkim = dns.calls.filter((c) => c.name.endsWith('._domainkey.example.com'));
    assert.equal(dkim.length, PORTFOLIO_DKIM_SELECTORS.length + 1);
  });

  test('the facts of each row', async () => {
    const { run } = run4();
    await run.start();
    const com = run.facts('example.com', { now: NOW });
    assert.deepEqual([com.registration.state, com.registration.daysLeft, com.registration.expiry, com.registration.risk, com.registration.registrar],
      ['ok', 400, 'ok', 'ok', 'Example Registrar, Inc.']);
    assert.equal(com.dnssec.state, 'validated');
    assert.deepEqual(com.ns.domains.map((d) => [d.domain, d.own, d.daysLeft]), [['example.net', false, 12]]);
    assert.equal(com.ns.minDaysLeft, 12);
    assert.deepEqual([com.caa.state, com.caa.issuers, com.caa.wildIssuers], ['present', ['letsencrypt.org'], ['sectigo.com']]);
    assert.deepEqual([com.spf.state, com.spf.all, com.spf.lookups, com.spf.lookupsState, com.spf.over], ['ok', '-', 3, 'ok', false]);
    assert.deepEqual([com.dmarc.state, com.dmarc.policy], ['ok', 'reject']);
    assert.deepEqual([com.dkim.state, com.dkim.selectors], ['found', ['google']]);
    assert.deepEqual([com.mtaSts.state, com.tlsRpt.state, com.mx.state], ['present', 'present', 'some']);
    assert.deepEqual(com.parked, { parked: false, nullMx: false, spfFail: true, dmarcReject: true, complete: null });
    assert.equal(rowRisk(com), 'ns-expiring', 'its name servers\' domain expires in 12 days');

    const org = run.facts('example.org', { now: NOW });
    assert.deepEqual([org.registration.risk, org.registration.transferLock, org.registration.expiry], ['hijack', false, 'error']);
    assert.deepEqual(org.ns.domains.map((d) => [d.domain, d.own, d.daysLeft]), [['example.org', true, 20], ['example.net', false, 12]]);
    assert.deepEqual(org.parked, { parked: true, nullMx: true, spfFail: true, dmarcReject: true, complete: true }, 'a parked domain locked down');
    assert.equal(org.dnssec.state, 'unsigned');
    assert.equal(org.caa.state, 'none');
    assert.equal(rowRisk(org), 'expiring');

    const net = run.facts('example.net', { now: NOW });
    assert.deepEqual(net.registration.critical, ['clientHold', 'redemptionPeriod']);
    assert.equal(rowRisk(net), 'critical');
    assert.equal(net.caa.state, null, 'CAA SERVFAIL: not known, never "none"');
    assert.equal(net.caa.failure.reason, 'rcode');
    assert.deepEqual(cellFailures(net, 'caa').map((f) => [f.lookup, f.status.params.rcode]), [['caa', 'SERVFAIL']]);
    assert.deepEqual([net.mx.state, net.dmarc.state, net.parked.complete], ['none', 'none', false], 'no MX, no DMARC: the lock-down is open');

    const tr = run.facts('example-test.com.tr', { now: NOW });
    assert.equal(tr.registration.state, 'unsupported');
    assert.equal(tr.registration.whois.name, 'TRABİS');
    assert.deepEqual([tr.spf.lookups, tr.spf.over], [11, true], 'eleven includes: over the limit');
    assert.equal(rowRisk(tr), 'ns-expiring');
    assert.deepEqual(cellFailures(tr, 'expiry'), [], 'no RDAP is no failure: the registry\'s WHOIS is offered');
  });

  test('a failed RDAP lookup and a failed name server domain: n/a with the reason; Retry asks only them, past the cache', async () => {
    const answers = { ...RDAP, 'example.com': 503, 'example.net': 503 };
    const { run, fetchImpl, dns } = run4({ rdap: answers });
    await run.start();
    let com = run.facts('example.com', { now: NOW });
    assert.equal(com.registration.state, 'failed');
    assert.deepEqual(cellFailures(com, 'expiry').map((f) => [f.lookup, f.status.reason, f.status.params.status]), [['rdap', 'http-status', 503]]);
    assert.deepEqual(cellFailures(com, 'ns').map((f) => [f.lookup, f.nsDomain]), [['rdap', 'example.net']], 'the name server domain\'s own RDAP');
    assert.equal(com.ns.domains[0].state, 'failed');
    const before = { rdap: fetchImpl.rdap().length, dns: dns.calls.length };
    answers['example.com'] = RDAP['example.com'];
    answers['example.net'] = RDAP['example.net'];
    await run.retry('example.com', ['rdap']);
    await run.retryRdap('example.net');
    com = run.facts('example.com', { now: NOW });
    assert.deepEqual([com.registration.state, com.ns.domains[0].daysLeft], ['ok', 12]);
    assert.equal(dns.calls.length, before.dns, 'no DNS question');
    // example.com once (its retry), example.net once (the name server domain, a portfolio row too)
    assert.deepEqual(fetchImpl.rdap().slice(before.rdap).map((u) => u.split('/domain/')[1]).filter((d, i, a) => a.indexOf(d) === i).sort(), ['example.com', 'example.net']);
    assert.equal(run.facts('example.net', { now: NOW }).registration.state, 'ok', 'the portfolio row of example.net reads the retried answer too');
  });

  test('a DNS Retry: the column\'s lookups only, past the DNS cache', async () => {
    const { run, dns } = run4();
    await run.start();
    const n = dns.calls.length;
    await run.retry('example.com', CELL_LOOKUPS.spf);
    const again = dns.calls.slice(n);
    assert.ok(again.length > 0 && again.every((c) => c.noCache), 'past the cache');
    assert.ok(again.some((c) => c.name === 'example.com' && c.type === 'TXT'), 'the TXT record');
    assert.ok(!again.some((c) => c.type === 'NS' || c.type === 'CAA' || c.type === 'DS'), 'nothing of another column');
  });

  test('a stop: rows not finished are stopped, what landed stays; Look up runs the rest', async () => {
    const { run } = run4({ dnsOpts: { delayMs: 20 }, run: { concurrency: 1 } });
    const ctl = new AbortController();
    const p = run.start({ signal: ctl.signal });
    await new Promise((r) => setTimeout(r, 30));
    ctl.abort();
    await assert.rejects(p, { name: 'AbortError' });
    assert.equal(run.status, 'stopped');
    const states = run.domains().map((d) => run.row(d).state);
    assert.ok(states.every((s) => s === 'stopped' || s === 'done'), states.join());
    const last = run.domains().at(-1);
    assert.deepEqual(run.pending(last), [...PORTFOLIO_LOOKUPS], 'the last row never started');
    assert.equal(run.facts(last, { now: NOW }).registration.state, 'pending');
    await run.retry(last, run.pending(last));
    assert.deepEqual(run.pending(last), []);
    assert.equal(run.row(last).state, 'done');
  });

  test('DKIM off: no selector asked, the cell "off", never "none"', async () => {
    const { run, dns } = run4({ run: { dkim: false } });
    await run.start();
    assert.ok(!dns.calls.some((c) => c.name.includes('._domainkey.')), 'no DKIM question');
    assert.equal(run.facts('example.com', { now: NOW }).dkim.state, 'off');
  });
});

describe('the calendar and the exports', () => {
  test('one expiry per domain, the name servers\' domains too, soonest first; a stable UID', async () => {
    const { run } = run4();
    await run.start();
    const events = expiryEvents(run.allFacts({ now: NOW }));
    assert.deepEqual(events.map((e) => [e.domain, e.daysLeft, e.portfolio, e.nsOf]), [
      ['example.net', 12, true, ['example.com', 'example.org', 'example-test.com.tr']],
      ['example.org', 20, true, []],
      ['example.com', 400, true, []]
    ]);
    assert.equal(expiryUid('Example.COM.'), 'expiry-example.com@domainscope');
  });

  test('export rows: codes and values, the failed lookups named', async () => {
    const { run } = run4();
    await run.start();
    const rows = run.allFacts({ now: NOW }).map(exportRow);
    assert.deepEqual(Object.keys(rows[0]), [...EXPORT_COLUMNS]);
    assert.deepEqual(rows[0], {
      domain: 'example.com', registration: 'ok', registrar: 'Example Registrar, Inc.', expires: iso(400).slice(0, 10), daysLeft: 400, risk: 'ns-expiring',
      statuses: 'client transfer prohibited', transferLock: true, critical: '', dnssec: 'validated', delegationSigned: false,
      nameServers: 'ns1.example.net ns2.example.net', nsDomains: 'example.net:12', nsMinDaysLeft: 12, caa: 'present', caaIssuers: 'letsencrypt.org sectigo.com',
      mx: 'some', spf: 'ok', spfAll: '-all', spfLookups: 3, dmarc: 'p=reject', dkim: 'google', mtaSts: 'present', tlsRpt: 'present', parked: 'receives-mail', failed: ''
    });
    assert.equal(rows[2].failed, 'caa');
    assert.equal(rows[1].parked, 'locked');
    // the DMARC column never says "none" for two things: p=none is "p=none", no record "missing"
    assert.equal(rows[3].dmarc, 'missing', 'example-test.com.tr publishes no DMARC record');
    const txt = (v) => ({ ok: true, rcode: 'NOERROR', answers: v ? [{ type: 'TXT', data: [v] }] : [], flags: {} });
    assert.equal(exportRow(portfolioFacts({ domain: 'example.com', dmarc: txt('v=DMARC1; p=none; rua=mailto:d@example.com') })).dmarc, 'p=none');
  });

  test('20 domains of one registry that answers one request per window and 429 to the rest: every one is read, rdap.org never blamed', async () => {
    // rdap.sidn.nl answered three concurrent requests 200, 429, 429 on 2026-10-02.
    let last = 0;
    let inFlight = 0;
    let maxInFlight = 0;
    const log = { registry: 0, registry429: 0, org: 0 };
    const reg = (name) => ({ objectClassName: 'domain', ldhName: name, status: ['client transfer prohibited'], events: [{ eventAction: 'expiration', eventDate: iso(300) }], entities: [] });
    const fetchImpl = async (url) => {
      const u = String(url);
      if (u === 'https://data.iana.org/rdap/dns.json') return json({ services: [[['test'], ['https://rdap.registry.example/']]] });
      const name = u.split('/domain/')[1];
      if (u.startsWith('https://rdap.org/')) log.org += 1;
      else log.registry += 1;
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 2));
      inFlight -= 1;
      const now = Date.now();
      if (now - last < 40) {
        log.registry429 += 1;
        return json({ errorCode: 429 }, 429);
      }
      last = now;
      return json(reg(name));
    };
    const dns = { query: async (name, type) => ({ name, type, ok: true, rcode: 'NOERROR', answers: [], flags: {} }) };
    const domains = Array.from({ length: 20 }, (_, i) => `example${i}.test`);
    const run = createPortfolio({ domains, dns, fetchImpl, dkim: false, rdapOptions: { registryRetryMs: 20, rdapOrgIntervalMs: 0 } });
    await run.start();
    const res = domains.map((d) => run.row(d).raw.rdap);
    assert.equal(res.filter((r) => r && r.ok).length, 20, JSON.stringify(log));
    assert.equal(maxInFlight, 1, 'one request at a time to the registry');
    assert.equal(log.org, 0, 'rdap.org would forward to the same registry');
    assert.ok(res.every((r) => !r.rdapOrgPaused));
  });

  test('a name server domain the registry does not know (RDAP 404): the takeover is flagged — the row\'s risk, the summary, never "no data"', async () => {
    const zone = { ...ZONE, 'example.com': { ...ZONE['example.com'], NS: ['ns1.example.net', 'ns2.example-gone.org'] } };
    const dns = fakeDns(zone, { signed: ['example.com'] });
    const fetchImpl = rdapFetch({ ...RDAP, 'example.net': rdapJson('example.net', { days: 300 }) });
    const run = createPortfolio({ domains: ['example.com'], dns, fetchImpl, rdapOptions: { rdapOrgIntervalMs: 0 } });
    await run.start();
    const f = run.facts('example.com', { now: NOW });
    assert.deepEqual(f.ns.domains.map((d) => [d.domain, d.state]), [['example-gone.org', 'not-found'], ['example.net', 'ok']]);
    assert.equal(rowRisk(f), 'ns-unregistered');
    assert.equal(rowRisk({ ...f, registration: { ...f.registration, risk: 'pending-transfer' } }), 'ns-unregistered', 'before a pending transfer');
    assert.equal(rowRisk({ ...f, registration: { ...f.registration, risk: 'critical' } }), 'critical', 'a critical registry status first');
    assert.deepEqual(cellFailures(f, 'ns'), [], 'an answer, not a failure');
    const s = portfolioSummaryFacts([f], { at: NOW });
    assert.deepEqual(s.nsUnregistered, [{ domain: 'example-gone.org', of: ['example.com'] }]);
    assert.equal(exportRow(f).risk, 'ns-unregistered');
  });

  test('the summary facts: what needs a look, by domain', async () => {
    const { run } = run4();
    await run.start();
    const s = portfolioSummaryFacts(run.allFacts({ now: NOW }), { at: NOW });
    assert.deepEqual(s.expiring, [{ domain: 'example.net', daysLeft: 12 }, { domain: 'example.org', daysLeft: 20 }]);
    assert.deepEqual(s.critical, [{ domain: 'example.net', codes: ['clientHold', 'redemptionPeriod'] }]);
    assert.deepEqual(s.unlocked, ['example.org']);
    assert.equal(s.noRdap, 1);
    assert.deepEqual(s.nsExpiring, [], 'example.net is a portfolio domain: its expiry is listed once, under expiring');
    assert.deepEqual(s.spfOver, ['example-test.com.tr']);
    assert.deepEqual(s.dmarcWeak, ['example.net', 'example-test.com.tr']);
    assert.deepEqual(s.parkedOpen, ['example.net']);
    assert.equal(s.failedLookups, 1);
    assert.deepEqual(s.dnssec, { validated: 1, signed: 0, broken: 0, unsigned: 3 }, 'a DS whose keys cannot be validated is counted as broken, never as signed');
  });

  test('every column has its lookups', () => {
    assert.deepEqual(Object.keys(CELL_LOOKUPS), [...PORTFOLIO_CELLS]);
    for (const list of Object.values(CELL_LOOKUPS)) for (const id of list) assert.ok(PORTFOLIO_LOOKUPS.includes(id), id);
  });

  test('facts of nothing yet: every part pending, never "none"', () => {
    const f = portfolioFacts({ domain: 'example.com' }, { now: NOW });
    assert.equal(f.registration.state, 'pending');
    for (const k of ['caa', 'mx', 'spf', 'dmarc', 'dkim']) assert.equal(f[k].state, null, k);
    assert.equal(f.ns.state, 'pending');
    assert.equal(rowRisk(f), null);
  });
});

describe('the module', () => {
  test('no dead API: every export is read (by the module, the app or the runner), every method of a run called by the app or the runner', () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    const walk = (dir) => readdirSync(dir).flatMap((name) => {
      const p = path.join(dir, name);
      return statSync(p).isDirectory() ? walk(p) : /\.m?js$/.test(name) ? [p] : [];
    });
    const self = path.join(root, 'assets', 'js', 'lib', 'portfolio.js');
    const own = readFileSync(self, 'utf8');
    const others = [...walk(path.join(root, 'assets', 'js')), ...walk(path.join(root, 'tools'))]
      .filter((f) => path.resolve(f) !== path.resolve(self)).map((f) => readFileSync(f, 'utf8')).join('\n');
    const uses = (text, name) => (text.match(new RegExp(`(?<![\\w$])${name}(?![\\w$])`, 'g')) || []).length;
    assert.deepEqual(Object.keys(portfolioLib).filter((name) => !uses(others, name) && uses(own, name) < 2), [], 'exports nothing reads');
    const run = createPortfolio({ domains: ['example.com'], dns: fakeDns({}) });
    const methods = Object.keys(run).filter((k) => typeof run[k] === 'function');
    assert.ok(methods.includes('start') && methods.includes('retry'), methods.join());
    assert.deepEqual(methods.filter((k) => !new RegExp(`\\brun\\.${k}\\(`).test(others)), [], 'methods of a run nothing calls');
  });
});
