/**
 * lib/takeover.js — the catalogue matching, the CNAME chain logic, the registration verdict and
 * the audit over a fake DNS client and a fake RDAP lookup (no network). Names are documentation
 * names: the scanned domain is example.com, the other registrable domains example.net,
 * example.org and `.test` names (RFC 2606).
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  TAKEOVER_SERVICES, TAKEOVER_STATUSES, TAKEOVER_SIGNALS, TAKEOVER_SEVERITIES, TAKEOVER_REASONS, REGISTRATION_VERDICTS,
  HTTP_CHECK_OUTCOMES, HTTP_CHECK_MAX, UNREGISTRABLE_TLDS, matchesPattern, matchService, chainService, fingerprintMatches, registryDomainOf,
  cnameChain, spfTargets, registrationVerdict, reasonSeverity, worstSeverity, auditTakeover, httpCandidates,
  httpCheckOutcome, applyHttpCheck, TAKEOVER_REF_KINDS, TAKEOVER_DKIM_SELECTORS, TAKEOVER_SRV_NAMES, REFERENCE_QUERIES,
  spfReferences, dmarcTargets, caaIodefTargets, isDkimSelector, dkimSelectorList, findingLookups
} from '../../assets/js/lib/takeover.js';
import { PORTFOLIO_DKIM_SELECTORS } from '../../assets/js/lib/portfolio.js';

const NOW = Date.parse('2026-10-08T12:00:00Z');
const DAY = 86400000;

const ok = (name, type, answers = [], rcode = 'NOERROR') => ({ ok: true, rcode, answers, authorities: [], name, type });
const cname = (name, data) => ({ name, type: 'CNAME', ttl: 300, data });
const a = (name, data = '192.0.2.10') => ({ name, type: 'A', ttl: 300, data });
const fail = (name, type) => ({ ok: false, rcode: null, answers: [], authorities: [], error: 'Request timed out', errorKind: 'timeout', name, type });

/** A fake DohClient: `${name}|${type}` → response (default: NOERROR, no answer); every query is logged. */
function fakeDns(table) {
  const calls = [];
  return {
    calls,
    query: async (name, type, opts = {}) => {
      calls.push({ name, type, noCache: !!opts.noCache });
      const r = table[`${name}|${type}`];
      return typeof r === 'function' ? r() : r || ok(name, type);
    }
  };
}

/** A fake rdapDomain: domain → result (default: registered, expiring in a year); calls logged. */
function fakeRdap(table) {
  const calls = [];
  const fn = async (domain) => {
    calls.push(domain);
    const r = table[domain];
    if (typeof r === 'function') return r();
    return r || { ok: true, domain, status: ['active'], expires: new Date(NOW + 365 * DAY), notFound: false, unsupportedTld: false };
  };
  fn.calls = calls;
  return fn;
}

const notFound = (domain) => ({ ok: false, domain, notFound: true, unsupportedTld: false, error: 'Domain not found in the registry', errorKind: 'http' });
const rateLimited = (domain) => ({ ok: false, domain, notFound: false, unsupportedTld: false, error: 'HTTP 429', errorKind: 'rate-limit', httpStatus: 429 });

describe('the catalogue', () => {
  test('every entry is complete: a known status and signal, patterns, a reference, fingerprints where the page decides', () => {
    const ids = new Set();
    for (const s of TAKEOVER_SERVICES) {
      assert.ok(!ids.has(s.id), `duplicate id ${s.id}`);
      ids.add(s.id);
      assert.ok(TAKEOVER_STATUSES.includes(s.status), `${s.id} status`);
      assert.ok(TAKEOVER_SIGNALS.includes(s.signal), `${s.id} signal`);
      assert.ok(s.patterns.length > 0, `${s.id} patterns`);
      for (const p of s.patterns) assert.match(p, /^[a-z0-9*-]+(\.[a-z0-9*-]+)+$/, `${s.id} pattern ${p}`);
      assert.match(s.ref, /^https:\/\/[a-z0-9.-]+\//, `${s.id} ref`);
      if (s.signal === 'http' && s.status !== 'safe') assert.ok(s.fingerprints.length > 0, `${s.id}: the page decides, so it needs a fingerprint`);
      assert.ok(Object.isFrozen(s) && Object.isFrozen(s.patterns), `${s.id} frozen`);
    }
  });

  test('a pattern matches the name itself and names below it, label by label', () => {
    assert.ok(matchesPattern('github.io', 'github.io'));
    assert.ok(matchesPattern('github.io', 'example.github.io'));
    assert.ok(matchesPattern('github.io', 'EXAMPLE.GitHub.io.'), 'case and a trailing dot');
    assert.ok(!matchesPattern('github.io', 'notgithub.io'), 'never inside a label');
    assert.ok(!matchesPattern('blob.core.windows.net', 'core.windows.net'), 'fewer labels');
    assert.ok(matchesPattern('s3-*.amazonaws.com', 'www.example.com.s3-website-us-east-1.amazonaws.com'));
    assert.ok(matchesPattern('s3.*.amazonaws.com', 'files.s3.eu-central-1.amazonaws.com'));
    assert.ok(!matchesPattern('s3.*.amazonaws.com', 'files.s3.amazonaws.com'), 'a * label needs a label');
    assert.ok(!matchesPattern('', 'example.com'));
  });

  test('a CNAME target finds its service; the first matching entry wins', () => {
    assert.equal(matchService('www.example.com.s3.amazonaws.com').id, 'aws-s3');
    assert.equal(matchService('www.example.com.s3-website.eu-west-1.amazonaws.com').id, 'aws-s3');
    assert.equal(matchService('dualstack.app-1.eu-west-1.elb.amazonaws.com').id, 'aws-elb');
    assert.equal(matchService('example.azurewebsites.net').id, 'azure-app-service');
    assert.equal(matchService('example.z13.web.core.windows.net').id, 'azure-storage');
    assert.equal(matchService('example.trafficmanager.net').status, 'vulnerable');
    assert.equal(matchService('example.github.io').status, 'edge');
    assert.equal(matchService('d1234.cloudfront.net').status, 'safe');
    assert.equal(matchService('www.example.org'), null);
  });

  test('a chain takes the first hop that belongs to a service (later hops are the provider’s own)', () => {
    const m = chainService(['app.example.com', 'example.azurewebsites.net', 'waws-prod-01.cloudapp.net']);
    assert.equal(m.service.id, 'azure-app-service');
    assert.equal(m.hop, 'example.azurewebsites.net');
    assert.equal(chainService(['www.example.org']), null);
    assert.equal(chainService(null), null);
  });

  test('a fingerprint is any one of the service’s texts, case-insensitive', () => {
    const s3 = TAKEOVER_SERVICES.find((s) => s.id === 'aws-s3');
    assert.ok(fingerprintMatches(s3, '<Error><Code>NoSuchBucket</Code></Error>'));
    assert.ok(fingerprintMatches(s3, 'the specified bucket does not exist'));
    assert.ok(!fingerprintMatches(s3, '<html>Welcome</html>'));
    assert.ok(!fingerprintMatches(TAKEOVER_SERVICES.find((s) => s.id === 'aws-elb'), 'anything'), 'no fingerprint, no match');
    assert.ok(!fingerprintMatches(null, 'NoSuchBucket'));
  });
});

describe('names and records', () => {
  test('the registry domain uses ICANN suffixes only', () => {
    assert.equal(registryDomainOf('www.example.com'), 'example.com');
    assert.equal(registryDomainOf('www.example-test.com.tr'), 'example-test.com.tr');
    assert.equal(registryDomainOf('user.github.io'), 'github.io', 'a private suffix is the provider’s domain');
    assert.equal(registryDomainOf('_spf.example.net'), 'example.net');
    assert.equal(registryDomainOf('mail.gone.test'), 'gone.test');
    assert.equal(registryDomainOf('com'), null);
    assert.equal(registryDomainOf('com.tr'), null);
    assert.equal(registryDomainOf(''), null);
  });

  test('a CNAME chain is followed from the name in order, loops cut', () => {
    const r = ok('www.example.com', 'A', [cname('b.example.net', 'c.example.org'), cname('www.example.com', 'B.example.net.'), a('c.example.org')]);
    assert.deepEqual(cnameChain(r, 'www.example.com'), ['b.example.net', 'c.example.org']);
    const loop = ok('x.example.com', 'A', [cname('x.example.com', 'y.example.com'), cname('y.example.com', 'x.example.com')]);
    assert.deepEqual(cnameChain(loop, 'x.example.com'), ['y.example.com']);
    assert.deepEqual(cnameChain(null, 'x.example.com'), []);
  });

  test('SPF gives its include: and redirect= domains; macros and other mechanisms are left out', () => {
    assert.deepEqual(spfTargets('v=spf1 ip4:192.0.2.0/24 include:_spf.example.net ~include:example.org redirect=spf.gone.test -all'),
      ['_spf.example.net', 'example.org', 'spf.gone.test']);
    assert.deepEqual(spfTargets('v=spf1 include:%{d}.example.net a:mail.example.net -all'), []);
    assert.deepEqual(spfTargets('google-site-verification=abc'), []);
    assert.deepEqual(spfTargets(null), []);
  });
});

describe('the registration verdict', () => {
  const nx = ok('gone.test', 'NS', [], 'NXDOMAIN');
  const inDns = ok('gone.test', 'NS', [{ name: 'gone.test', type: 'NS', ttl: 300, data: 'ns.example.net' }]);
  const reg = (extra) => ({ ok: true, status: ['active'], expires: new Date(NOW + 200 * DAY), ...extra });

  test('a registered domain, and what its status and expiry say', () => {
    assert.equal(registrationVerdict(reg(), null, { now: NOW }).verdict, 'registered');
    assert.equal(registrationVerdict(reg({ status: ['pending delete'] }), null, { now: NOW }).verdict, 'pending-delete');
    assert.equal(registrationVerdict(reg({ status: ['redemption period'] }), null, { now: NOW }).verdict, 'pending-delete');
    assert.equal(registrationVerdict(reg({ expires: new Date(NOW - DAY) }), null, { now: NOW }).verdict, 'expired');
    assert.equal(registrationVerdict(reg({ expires: new Date(NOW + 29 * DAY) }), null, { now: NOW }).verdict, 'expiring');
    assert.equal(registrationVerdict(reg({ expires: new Date(NOW + 31 * DAY) }), null, { now: NOW }).verdict, 'registered');
    assert.equal(registrationVerdict(reg({ expires: null }), null, { now: NOW }).verdict, 'registered', 'no expiry date: registered');
    assert.deepEqual(registrationVerdict(reg({ expires: new Date(NOW + 5 * DAY) }), null, { now: NOW, expiringDays: 3 }).verdict, 'registered');
  });

  test('an RDAP 404 counts only when DNS agrees', () => {
    assert.equal(registrationVerdict(notFound('gone.test'), nx, { now: NOW }).verdict, 'unregistered');
    assert.equal(registrationVerdict(notFound('gone.test'), inDns, { now: NOW }).verdict, 'rdap-404-dns', 'reserved or redacted: not a finding');
    assert.equal(registrationVerdict(notFound('gone.test'), fail('gone.test', 'NS'), { now: NOW }).verdict, 'failed', 'no DNS answer: undecided');
    assert.equal(registrationVerdict(notFound('gone.test'), null, { now: NOW }).verdict, 'failed');
  });

  test('a TLD without RDAP is judged by DNS alone', () => {
    const none = { ok: false, unsupportedTld: true, notFound: false, error: 'No RDAP service', errorKind: 'unsupported' };
    assert.equal(registrationVerdict(none, nx, { now: NOW }).verdict, 'unregistered-dns');
    assert.equal(registrationVerdict(none, inDns, { now: NOW }).verdict, 'no-rdap');
    assert.equal(registrationVerdict(none, fail('gone.test', 'NS'), { now: NOW }).verdict, 'failed');
  });

  test('an RDAP failure or no lookup is failed', () => {
    assert.equal(registrationVerdict(rateLimited('gone.test'), nx, { now: NOW }).verdict, 'failed');
    assert.equal(registrationVerdict(null, null, { now: NOW }).verdict, 'failed');
    for (const v of ['registered', 'unregistered', 'expiring', 'failed']) assert.ok(REGISTRATION_VERDICTS.includes(v));
  });
});

describe('severity', () => {
  const svc = (id) => TAKEOVER_SERVICES.find((s) => s.id === id);
  test('a registrable target is the worst; a dangling CNAME depends on the service', () => {
    assert.equal(reasonSeverity('unregistered', 'cname'), 'critical');
    assert.equal(reasonSeverity('unregistered', 'ns'), 'critical');
    assert.equal(reasonSeverity('unregistered', 'mx'), 'high');
    assert.equal(reasonSeverity('unregistered', 'spf'), 'high');
    assert.equal(reasonSeverity('pending-delete', 'mx'), 'high');
    assert.equal(reasonSeverity('expired', 'cname'), 'high');
    assert.equal(reasonSeverity('expiring', 'ns'), 'medium');
    assert.equal(reasonSeverity('nxdomain', 'cname', svc('azure-app-service')), 'high');
    assert.equal(reasonSeverity('nxdomain', 'cname', svc('github-pages')), 'medium');
    assert.equal(reasonSeverity('nxdomain', 'cname', svc('aws-elb')), 'low');
    assert.equal(reasonSeverity('nxdomain', 'cname', null), 'medium');
    assert.equal(reasonSeverity('nxdomain', 'ns'), 'low');
    assert.equal(reasonSeverity('fingerprint', 'cname', svc('aws-s3')), 'high');
    assert.equal(reasonSeverity('fingerprint', 'cname', svc('heroku')), 'medium');
    assert.equal(reasonSeverity('check-http', 'cname', svc('aws-s3')), 'info');
    assert.equal(worstSeverity(['low', 'critical', 'medium']), 'critical');
    assert.equal(worstSeverity([]), null);
    for (const r of TAKEOVER_REASONS) assert.ok(TAKEOVER_SEVERITIES.includes(reasonSeverity(r, 'cname', null)), r);
  });
});

describe('auditTakeover', () => {
  const host = (name, cnames, extra = {}) => ({ name, resolution: { cnames, ipv4: [], ipv6: [], status: 'NOERROR' }, ...extra });
  const HOSTS = [
    host('old.example.com', ['old-app.azurewebsites.net']),
    host('files.example.com', ['files.example.com.s3.amazonaws.com']),
    host('cdn.example.com', ['cdn.gone.test']),
    host('ok.example.com', ['www.example.org']),
    host('moved.example.com', ['moved.example.net']),
    host('lb.example.com', ['app-1.eu-west-1.elb.amazonaws.com']),
    host('flaky.example.com', ['flaky.example.net']),
    host('any.example.com', ['wild.azurewebsites.net'], { wildcardSuspect: true }),
    host('www.example.com', [])
  ];
  const DNS = {
    'example.com|NS': ok('example.com', 'NS', [
      { name: 'example.com', type: 'NS', ttl: 300, data: 'ns1.example.com' }, { name: 'example.com', type: 'NS', ttl: 300, data: 'ns.dns.test' }
    ]),
    'example.com|MX': ok('example.com', 'MX', [{ name: 'example.com', type: 'MX', ttl: 300, data: { preference: 10, exchange: 'mx.mail.test' } }]),
    'example.com|TXT': ok('example.com', 'TXT', [{ name: 'example.com', type: 'TXT', ttl: 300, data: ['v=spf1 include:_spf.example.net', ' include:spf.lapsed.test -all'] }]),
    'old.example.com|A': ok('old.example.com', 'A', [cname('old.example.com', 'old-app.azurewebsites.net')], 'NXDOMAIN'),
    'files.example.com|A': ok('files.example.com', 'A', [cname('files.example.com', 'files.example.com.s3.amazonaws.com'), a('files.example.com.s3.amazonaws.com')]),
    'cdn.example.com|A': ok('cdn.example.com', 'A', [cname('cdn.example.com', 'cdn.gone.test')], 'NXDOMAIN'),
    'ok.example.com|A': ok('ok.example.com', 'A', [cname('ok.example.com', 'www.example.org'), a('www.example.org')]),
    'moved.example.com|A': ok('moved.example.com', 'A', [a('moved.example.com')]),
    'lb.example.com|A': ok('lb.example.com', 'A', [cname('lb.example.com', 'app-1.eu-west-1.elb.amazonaws.com')], 'NXDOMAIN'),
    'flaky.example.com|A': fail('flaky.example.com', 'A'),
    'ns.dns.test|A': ok('ns.dns.test', 'A', [a('ns.dns.test')]),
    'mx.mail.test|A': ok('mx.mail.test', 'A', [], 'NXDOMAIN'),
    'gone.test|NS': ok('gone.test', 'NS', [], 'NXDOMAIN')
  };
  const RDAP = {
    'gone.test': notFound('gone.test'),
    'dns.test': { ok: true, status: ['pending delete'], expires: new Date(NOW - 40 * DAY) },
    'mail.test': { ok: true, status: ['active'], expires: new Date(NOW + 10 * DAY) },
    'lapsed.test': rateLimited('lapsed.test')
  };

  test('finds what can be claimed, with the worst reason first, and never asks about providers or the scanned domain', async () => {
    const dns = fakeDns(DNS);
    const rdap = fakeRdap(RDAP);
    const progress = [];
    const out = await auditTakeover({ hosts: HOSTS, domains: ['Example.com'] }, { dns, rdap, now: () => NOW, skipTlds: [], onProgress: (d, t) => progress.push([d, t]) });
    const byHost = Object.fromEntries(out.findings.map((f) => [`${f.kind} ${f.host} ${f.target}`, f]));

    const cdn = byHost['cname cdn.example.com cdn.gone.test'];
    assert.equal(cdn.severity, 'critical');
    assert.deepEqual(cdn.reasons.map((r) => r.code), ['unregistered', 'nxdomain']);
    assert.equal(cdn.reasons[0].domain, 'gone.test');
    assert.equal(cdn.fix, 'unregistered');

    const old = byHost['cname old.example.com old-app.azurewebsites.net'];
    assert.equal(old.severity, 'high');
    assert.equal(old.service.id, 'azure-app-service');
    assert.deepEqual(old.reasons.map((r) => r.code), ['nxdomain']);

    const files = byHost['cname files.example.com files.example.com.s3.amazonaws.com'];
    assert.equal(files.severity, 'info');
    assert.deepEqual(files.reasons.map((r) => r.code), ['check-http']);

    assert.equal(byHost['cname lb.example.com app-1.eu-west-1.elb.amazonaws.com'].severity, 'low', 'not claimable: clutter');
    const ns = byHost['ns example.com ns.dns.test'];
    assert.equal(ns.severity, 'high');
    assert.equal(ns.reasons[0].code, 'pending-delete');
    const mx = byHost['mx example.com mx.mail.test'];
    assert.deepEqual(mx.reasons.map((r) => [r.code, r.severity]), [['expiring', 'medium'], ['nxdomain', 'low']]);
    assert.equal(mx.reasons[0].expires.getTime(), NOW + 10 * DAY);

    assert.ok(!Object.keys(byHost).some((k) => k.includes('ok.example.com')), 'a registered, resolving target is fine');
    assert.ok(!Object.keys(byHost).some((k) => k.includes('moved.example.com')), 'a CNAME gone since the scan is no reference');
    assert.ok(!Object.keys(byHost).some((k) => k.includes('any.example.com')), 'a wildcard look-alike is skipped');
    assert.deepEqual(out.findings.map((f) => f.severity), ['critical', 'high', 'high', 'medium', 'low', 'info'], 'most severe first');

    assert.deepEqual([...rdap.calls].sort(), ['dns.test', 'example.net', 'example.org', 'gone.test', 'lapsed.test', 'mail.test']);
    assert.ok(!dns.calls.some((c) => c.name === 'ns1.example.com'), 'an in-zone name server is not asked');
    assert.ok(dns.calls.filter((c) => c.type === 'A' && c.name.endsWith('.example.com')).every((c) => c.noCache), 'chains asked without the cache');
    assert.deepEqual(out.failures.map((f) => [f.source, f.name]).sort(), [['doh', 'flaky.example.com'], ['rdap', 'lapsed.test']]);
    assert.equal(out.registrations.get('lapsed.test').verdict, 'failed');
    assert.equal(out.checked, 5);
    assert.deepEqual(out.domains, ['example.com']);
    assert.equal(progress.at(-1)[0], progress.at(-1)[1], 'progress ends complete');
  });

  test('Retry asks only the registrations that failed, and a fixed one becomes a finding', async () => {
    const first = await auditTakeover({ hosts: HOSTS, domains: ['example.com'] }, { dns: fakeDns(DNS), rdap: fakeRdap(RDAP), now: () => NOW, skipTlds: [] });
    const rdap = fakeRdap({ ...RDAP, 'lapsed.test': notFound('lapsed.test') });
    const again = await auditTakeover({ hosts: HOSTS, domains: ['example.com'] }, {
      dns: fakeDns({ ...DNS, 'lapsed.test|NS': ok('lapsed.test', 'NS', [], 'NXDOMAIN') }), rdap, now: () => NOW, skipTlds: [], known: first.registrations
    });
    assert.deepEqual(rdap.calls, ['lapsed.test']);
    const spf = again.findings.find((f) => f.kind === 'spf' && f.target === 'spf.lapsed.test');
    assert.equal(spf.severity, 'high');
    assert.equal(spf.reasons[0].code, 'unregistered');
    assert.deepEqual(again.failures.map((f) => f.name), ['flaky.example.com']);
  });

  test('a failed NS check after an RDAP 404 is a DNS failure, not a finding', async () => {
    const out = await auditTakeover({ hosts: [host('cdn.example.com', ['cdn.gone.test'])], domains: [] }, {
      dns: fakeDns({ ...DNS, 'gone.test|NS': fail('gone.test', 'NS') }), rdap: fakeRdap(RDAP), now: () => NOW, skipTlds: []
    });
    assert.deepEqual(out.failures.map((f) => [f.source, f.name]), [['doh', 'gone.test NS']]);
    assert.deepEqual(out.findings.map((f) => f.reasons.map((r) => r.code)), [['nxdomain']]);
  });

  test('nothing to check gives no finding; an abort rejects', async () => {
    const empty = await auditTakeover({ hosts: [], domains: [] }, { dns: fakeDns({}), rdap: fakeRdap({}), now: () => NOW });
    assert.deepEqual([empty.findings, empty.failures, empty.references], [[], [], 0]);
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(auditTakeover({ hosts: HOSTS, domains: ['example.com'] }, { dns: fakeDns(DNS), rdap: fakeRdap(RDAP), signal: ac.signal }), { name: 'AbortError' });
  });

  test('by default a name under a suffix nobody can register is never looked up, nor called registrable', async () => {
    const dns = fakeDns({
      ...DNS,
      'example.com|NS': ok('example.com', 'NS', [{ name: 'example.com', type: 'NS', ttl: 300, data: 'ns.dns.test' }]),
      'example.com|MX': ok('example.com', 'MX', [{ name: 'example.com', type: 'MX', ttl: 300, data: { preference: 10, exchange: 'mx.corp.internal' } }]),
      'example.com|TXT': ok('example.com', 'TXT', [])
    });
    const rdap = fakeRdap(RDAP);
    const out = await auditTakeover({ hosts: [host('cdn.example.com', ['cdn.gone.test'])], domains: ['example.com'] }, { dns, rdap, now: () => NOW });
    assert.deepEqual(rdap.calls, [], 'no RDAP lookup');
    assert.ok(!dns.calls.some((c) => /\.(test|internal)$/.test(c.name)), `no DNS question of its own: ${dns.calls.map((c) => c.name).join(', ')}`);
    assert.deepEqual(out.findings.map((f) => [f.host, f.reasons.map((r) => r.code)]), [['cdn.example.com', ['nxdomain']]], 'the dangling CNAME still counts');
    assert.ok(UNREGISTRABLE_TLDS.includes('internal') && UNREGISTRABLE_TLDS.includes('arpa'));
  });
});

describe('the HTTP check', () => {
  const s3 = TAKEOVER_SERVICES.find((s) => s.id === 'aws-s3');
  // The shape of a finished Globalping HTTP measurement (verified live 2026-10-08).
  const measured = (statusCode, rawBody, status = 'finished') => ({ id: 'm1', results: [{ result: { status, statusCode, rawBody, truncated: false } }] });
  const finding = {
    id: 'cname|files.example.com|files.example.com.s3.amazonaws.com', severity: 'info', kind: 'cname', host: 'files.example.com',
    target: 'files.example.com.s3.amazonaws.com', chain: ['files.example.com.s3.amazonaws.com'],
    service: { id: 'aws-s3', name: 'Amazon S3', status: 'vulnerable', ref: s3.ref }, reasons: [{ code: 'check-http', severity: 'info' }], fix: 'check-http'
  };

  test('the page tells: the fingerprint, a page in use, or no usable answer', () => {
    assert.equal(httpCheckOutcome(measured(404, '<Error><Code>NoSuchBucket</Code></Error>'), s3).outcome, 'claimable');
    assert.equal(httpCheckOutcome(measured(404, '<Error><Code>NoSuchBucket</Code></Error>'), { id: 'aws-s3' }).outcome, 'claimable', 'by id');
    assert.equal(httpCheckOutcome(measured(200, '<html>Shop</html>'), s3).outcome, 'in-use');
    assert.equal(httpCheckOutcome(measured(404, '<html>Gone</html>'), s3).outcome, 'no-answer', 'an error page without the fingerprint decides nothing');
    assert.equal(httpCheckOutcome(measured(301, ''), s3).outcome, 'no-answer');
    assert.equal(httpCheckOutcome(measured(null, null, 'failed'), s3).outcome, 'no-answer');
    assert.equal(httpCheckOutcome(null, s3).measurementId, null);
    for (const m of [measured(404, 'NoSuchBucket'), measured(200, 'x'), null]) assert.ok(HTTP_CHECK_OUTCOMES.includes(httpCheckOutcome(m, s3).outcome));
  });

  test('a match raises the finding, a page in use drops it, no answer keeps it', () => {
    const hit = applyHttpCheck(finding, { outcome: 'claimable' });
    assert.equal(hit.severity, 'high');
    assert.deepEqual(hit.reasons.map((r) => r.code), ['fingerprint']);
    assert.equal(hit.fix, 'fingerprint');
    assert.equal(applyHttpCheck(finding, { outcome: 'in-use' }), null);
    assert.equal(applyHttpCheck(finding, { outcome: 'no-answer' }).severity, 'info');
    const both = { ...finding, reasons: [{ code: 'expiring', severity: 'medium', domain: 'example.net' }, { code: 'check-http', severity: 'info' }] };
    assert.deepEqual(applyHttpCheck(both, { outcome: 'in-use' }).reasons.map((r) => r.code), ['expiring']);
  });

  test('the candidates are the findings the page decides, one per host, at most HTTP_CHECK_MAX', () => {
    const many = Array.from({ length: HTTP_CHECK_MAX + 3 }, (_, i) => ({ ...finding, id: `f${i}`, host: `h${i}.example.com` }));
    assert.equal(httpCandidates(many).length, HTTP_CHECK_MAX);
    assert.deepEqual(httpCandidates([finding, { ...finding, id: 'mta-sts|files.example.com|files.example.com.s3.amazonaws.com', kind: 'mta-sts' }]).map((f) => f.id), [finding.id],
      'one page, one probe');
    assert.deepEqual(httpCandidates([{ ...finding, reasons: [{ code: 'nxdomain', severity: 'high' }] }]), []);
    assert.deepEqual(httpCandidates(null), []);
  });
});

describe('every dependency kind: what each record names', () => {
  test('SPF: include / redirect, the a / mx / exists / ptr domains with their term, CIDR lengths dropped, macros skipped and counted', () => {
    const r = spfReferences('v=spf1 a mx/24 a:Mail.Example.NET/24//64 mx:mx.example.org ~exists:check.example.org ptr:example.org '
      + 'include:_spf.example.net redirect=spf.example.org exists:%{i}._spf.example.com include:%{d}.example.net a:%{l1r/}.example.net -all');
    assert.deepEqual(r.includes, ['_spf.example.net', 'spf.example.org']);
    assert.deepEqual(r.hosts, [
      { mechanism: 'a', target: 'mail.example.net', term: 'a:mail.example.net' },
      { mechanism: 'mx', target: 'mx.example.org', term: 'mx:mx.example.org' },
      { mechanism: 'exists', target: 'check.example.org', term: 'exists:check.example.org' },
      { mechanism: 'ptr', target: 'example.org', term: 'ptr:example.org' }
    ]);
    assert.equal(r.macros, 3, 'exists:%{i}…, include:%{d}… and a:%{l1r/}… (a "/" delimiter inside the macro)');
    assert.deepEqual(spfTargets('v=spf1 include:_spf.example.net a:mail.example.net -all'), ['_spf.example.net'], 'spfTargets: includes only');
    // A name that cannot be one, a CIDR where none is allowed, a repeat, exp=: no reference.
    const odd = spfReferences('v=spf1 a:mail.example.net a:mail.example.net mx:mail.example.net include:bad_name! ptr:example.org/24 exists:x.example.org/24 exp=explain.example.net -all');
    assert.deepEqual([odd.includes, odd.hosts.map((x) => x.term), odd.macros], [[], ['a:mail.example.net'], 0]);
    assert.deepEqual(spfReferences('google-site-verification=abc'), { includes: [], hosts: [], macros: 0 });
    assert.deepEqual(spfReferences(null).hosts, []);
  });

  test('DMARC: the mailto hosts of rua and ruf, a size limit and a query dropped, each host once with its tags', () => {
    assert.deepEqual(dmarcTargets('v=DMARC1; p=reject; rua=mailto:dmarc@example.net!10m, MAILTO:Reports@Example.ORG?subject=x; ruf=mailto:forensic@example.net'), [
      { target: 'example.net', tags: ['rua', 'ruf'] }, { target: 'example.org', tags: ['rua'] }
    ]);
    assert.deepEqual(dmarcTargets('v=DMARC1;p=none;rua=mailto:agg%40reports.example.com,https://reports.example.org/dmarc'), [{ target: 'reports.example.com', tags: ['rua'] }],
      'an encoded @; a non-mailto URI is no mail host');
    assert.deepEqual(dmarcTargets('v=DMARC1; p=none; rua=mailto:a@example.net; rua=mailto:b@example.org'), [{ target: 'example.net', tags: ['rua'] }], 'a repeated tag: the first');
    assert.deepEqual(dmarcTargets('v=DMARC1; p=none; rua=mailto:nobody, mailto:x@192.0.2.1, mailto:@example.net'), [], 'no host, an address, an empty local part');
    assert.deepEqual(dmarcTargets('v=spf1 -all'), []);
    assert.deepEqual(dmarcTargets(undefined), []);
  });

  test('CAA: the iodef mailto domains and URL hosts, every other tag ignored', () => {
    assert.deepEqual(caaIodefTargets([
      { flags: 0, tag: 'issue', value: 'letsencrypt.org' },
      { flags: 0, tag: 'iodef', value: 'mailto:security@Example.NET' },
      { flags: 0, tag: 'IODEF', value: 'https://report.example.org:8443/caa?x=1' },
      { flags: 0, tag: 'iodef', value: 'http://report.example.org/other' },
      { flags: 0, tag: 'iodef', value: 'https://192.0.2.7/caa' },
      { flags: 0, tag: 'iodef', value: 'ftp://files.example.com/' },
      null
    ]), ['example.net', 'report.example.org']);
    assert.deepEqual(caaIodefTargets(null), []);
  });

  test('DKIM: the Domain portfolio\'s common selectors, then valid extra ones once', () => {
    assert.deepEqual([...TAKEOVER_DKIM_SELECTORS], [...PORTFOLIO_DKIM_SELECTORS], 'the same common selectors as lib/portfolio.js');
    assert.deepEqual(dkimSelectorList(['S2048', 'google', 'mx.2026', 'bad selector', '-x', 'a..b', '']), [...TAKEOVER_DKIM_SELECTORS, 's2048', 'mx.2026']);
    assert.ok(isDkimSelector('k2') && isDkimSelector('sel_1') && !isDkimSelector('a/b') && !isDkimSelector('x'.repeat(64)));
    assert.deepEqual([...TAKEOVER_SRV_NAMES], ['_autodiscover._tcp', '_sip._tls']);
  });

  test('every kind has its query and severity; whoever registers a host, zone or ACME target gets it critical', () => {
    for (const k of TAKEOVER_REF_KINDS.filter((x) => x !== 'cname')) assert.ok(REFERENCE_QUERIES[k], k);
    const svc = (id) => TAKEOVER_SERVICES.find((s) => s.id === id);
    assert.deepEqual(TAKEOVER_REF_KINDS.map((k) => reasonSeverity('unregistered', k)),
      ['critical', 'critical', 'high', 'high', 'high', 'high', 'high', 'high', 'critical', 'high', 'high', 'critical']);
    assert.equal(reasonSeverity('nxdomain', 'mta-sts', svc('azure-app-service')), 'high', 'mta-sts is a host: by its service');
    assert.equal(reasonSeverity('nxdomain', 'mta-sts', null), 'medium');
    for (const k of ['spf-host', 'dmarc', 'dkim', 'caa', 'srv', 'https', 'acme']) assert.equal(reasonSeverity('nxdomain', k), 'low', k);
    assert.equal(reasonSeverity('expiring', 'dkim'), 'medium');
    assert.equal(reasonSeverity('pending-delete', 'caa'), 'high');
  });

  test('the lookups a finding rests on, named as the audit names its failures', () => {
    assert.deepEqual(findingLookups({ kind: 'dmarc', host: '_dmarc.example.com', target: 'example.org', chain: ['example.org'] }),
      ['_dmarc.example.com TXT', 'example.org', 'example.org NS']);
    assert.deepEqual(findingLookups({ kind: 'cname', host: 'cdn.example.com', target: 'cdn.example.net', chain: ['edge.example.org', 'cdn.example.net'] }),
      ['cdn.example.com', 'cdn.example.net', 'example.org', 'example.org NS', 'example.net', 'example.net NS']);
    assert.deepEqual(findingLookups({ kind: 'mta-sts', host: 'mta-sts.example.com', target: 'x.example.net', chain: ['x.example.net'] })[0], 'mta-sts.example.com A');
  });
});

describe('auditTakeover: every dependency kind', () => {
  const rr = (name, type, data) => ({ name, type, ttl: 300, data });
  const DNS = {
    'example.com|TXT': ok('example.com', 'TXT', [rr('example.com', 'TXT', ['v=spf1 a:relay.lapsed.example exists:%{i}._spf.example.com mx:mx.example.org -all'])]),
    // DMARC reports to a domain nobody holds, through a DMARC host whose record is a CNAME to a vendor (hosted DMARC).
    '_dmarc.example.com|TXT': ok('_dmarc.example.com', 'TXT', [
      rr('_dmarc.example.com', 'CNAME', 'example.com._d.vendor.example'),
      rr('example.com._d.vendor.example', 'TXT', ['v=DMARC1; p=reject; rua=mailto:agg@reports.gone.example!10m; ruf=mailto:ruf@example.com'])
    ]),
    'example.com|CAA': ok('example.com', 'CAA', [rr('example.com', 'CAA', { flags: 0, tag: 'iodef', value: 'mailto:caa@iodef.pending.example' })]),
    'example.com|HTTPS': ok('example.com', 'HTTPS', [rr('example.com', 'HTTPS', { priority: 0, target: 'edge.lapsed.example', params: {} })]),
    '_sip._tls.example.com|SRV': ok('_sip._tls.example.com', 'SRV', [rr('_sip._tls.example.com', 'SRV', { priority: 100, weight: 1, port: 443, target: 'sip.example.org' })]),
    '_autodiscover._tcp.example.com|SRV': ok('_autodiscover._tcp.example.com', 'SRV', [rr('_autodiscover._tcp.example.com', 'SRV', { priority: 0, weight: 0, port: 443, target: '.' })]),
    'mta-sts.example.com|A': ok('mta-sts.example.com', 'A', [rr('mta-sts.example.com', 'CNAME', 'policy-app.azurewebsites.net')], 'NXDOMAIN'),
    '_acme-challenge.example.com|TXT': ok('_acme-challenge.example.com', 'TXT', [rr('_acme-challenge.example.com', 'CNAME', '_acme-challenge.gone.example')], 'NXDOMAIN'),
    'selector1._domainkey.example.com|TXT': ok('selector1._domainkey.example.com', 'TXT', [
      rr('selector1._domainkey.example.com', 'CNAME', 'selector1-example-com._domainkey.mail.expiring.example'),
      rr('selector1-example-com._domainkey.mail.expiring.example', 'TXT', ['v=DKIM1; p=MIIB'])
    ]),
    // a CNAME loop: the chain is cut where it repeats
    'k1._domainkey.example.com|TXT': ok('k1._domainkey.example.com', 'TXT', [
      rr('k1._domainkey.example.com', 'CNAME', 'k1.loop.example.org'), rr('k1.loop.example.org', 'CNAME', 'k1._domainkey.example.com')
    ], 'SERVFAIL'),
    's2048._domainkey.example.com|TXT': ok('s2048._domainkey.example.com', 'TXT', [rr('s2048._domainkey.example.com', 'CNAME', 's2048.keys.example.org')]),
    'mx.example.org|A': ok('mx.example.org', 'A', [], 'NXDOMAIN'),
    'sip.example.org|A': ok('sip.example.org', 'A', [], 'NXDOMAIN'),
    'relay.lapsed.example|A': ok('relay.lapsed.example', 'A', [], 'NXDOMAIN'),
    'gone.example|NS': ok('gone.example', 'NS', [], 'NXDOMAIN'),
    'lapsed.example|NS': ok('lapsed.example', 'NS', [], 'NXDOMAIN')
  };
  const RDAP = {
    'gone.example': notFound('gone.example'),
    'lapsed.example': notFound('lapsed.example'),
    'pending.example': { ok: true, status: ['redemption period'], expires: new Date(NOW - 3 * DAY) },
    'expiring.example': { ok: true, status: ['active'], expires: new Date(NOW + 12 * DAY) }
  };
  const run = (extra = {}) => {
    const dns = fakeDns({ ...DNS, ...(extra.dns || {}) });
    const rdap = fakeRdap({ ...RDAP, ...(extra.rdap || {}) });
    const progress = [];
    return auditTakeover({ hosts: extra.hosts || [], domains: ['example.com'] }, {
      dns, rdap, now: () => NOW, skipTlds: [], extraDkimSelectors: ['s2048'], ownDomains: extra.ownDomains || [], onProgress: (d, t) => progress.push([d, t])
    }).then((out) => ({ out, dns, rdap, progress }));
  };
  const row = (f) => `${f.severity} ${f.kind} ${f.host} → ${f.target}${f.term ? ` [${f.term}]` : ''}: ${f.reasons.map((r) => r.code).join(', ')}`;

  test('one click asks every kind and finds what lapsed or dangles behind it', async () => {
    const { out, dns, rdap, progress } = await run();
    assert.deepEqual(out.findings.map(row), [
      'critical acme _acme-challenge.example.com → _acme-challenge.gone.example: unregistered',
      'high dmarc _dmarc.example.com → reports.gone.example [rua]: unregistered',
      'high https example.com → edge.lapsed.example: unregistered',
      'high caa example.com → iodef.pending.example: pending-delete',
      'high spf-host example.com → relay.lapsed.example [a:relay.lapsed.example]: unregistered, nxdomain',
      'high mta-sts mta-sts.example.com → policy-app.azurewebsites.net: nxdomain',
      'medium dkim selector1._domainkey.example.com → selector1-example-com._domainkey.mail.expiring.example: expiring',
      'low srv _sip._tls.example.com → sip.example.org: nxdomain',
      'low spf-host example.com → mx.example.org [mx:mx.example.org]: nxdomain'
    ], 'worst first, then by host and target');
    const mtaSts = out.findings.find((f) => f.kind === 'mta-sts');
    assert.equal(mtaSts.service.id, 'azure-app-service', 'mta-sts.<domain> is a host: the catalogue matches its chain');
    assert.equal(out.findings.find((f) => f.kind === 'acme').fix, 'unregistered');
    assert.equal(out.spfMacros, 1, 'exists:%{i}… skipped and counted');
    // Every kind's question, the chains without the cache; the extra selector too; nothing about the own domain's registration.
    const asked = new Set(dns.calls.map((c) => `${c.name}|${c.type}`));
    for (const q of ['example.com|NS', 'example.com|MX', 'example.com|TXT', '_dmarc.example.com|TXT', 'example.com|CAA', 'example.com|HTTPS', 'mta-sts.example.com|A',
      '_acme-challenge.example.com|TXT', '_autodiscover._tcp.example.com|SRV', '_sip._tls.example.com|SRV', ...TAKEOVER_DKIM_SELECTORS.map((s) => `${s}._domainkey.example.com|TXT`),
      's2048._domainkey.example.com|TXT']) assert.ok(asked.has(q), q);
    assert.ok(dns.calls.filter((c) => /^(mta-sts|_acme-challenge)\.|\._domainkey\./.test(c.name)).every((c) => c.noCache), 'chains asked without the cache');
    assert.equal(dns.calls.filter((c) => c.name === 'sip.example.org').length, 1, 'each target asked once');
    assert.ok(!dns.calls.some((c) => c.name === '.' || c.name === ''), 'an SRV target "." is no service');
    assert.deepEqual([...rdap.calls].sort(), ['example.org', 'expiring.example', 'gone.example', 'lapsed.example', 'pending.example', 'vendor.example']);
    assert.ok(!rdap.calls.includes('azurewebsites.net'), 'a catalogue provider is never looked up');
    // 2 SPF hosts, 3 DMARC (the delegation, rua, ruf at the own domain), CAA, HTTPS, SRV, mta-sts, acme, 3 DKIM (the loop's one hop too)
    assert.equal(out.references, 13);
    assert.equal(progress.at(-1)[0], progress.at(-1)[1], 'progress ends complete');
  });

  test('a CNAME loop is cut where it repeats; a hosted DMARC record is read where the chain ends, and the delegation is a reference too', async () => {
    const { out } = await run({ rdap: { 'vendor.example': notFound('vendor.example') }, dns: { 'vendor.example|NS': ok('vendor.example', 'NS', [], 'NXDOMAIN') } });
    const dmarc = out.findings.filter((f) => f.kind === 'dmarc').map(row);
    assert.deepEqual(dmarc, [
      'high dmarc _dmarc.example.com → example.com._d.vendor.example: unregistered',
      'high dmarc _dmarc.example.com → reports.gone.example [rua]: unregistered'
    ], 'whoever registers the vendor\'s lapsed domain sets the DMARC policy');
    // k1 loops back to itself: one hop, in a registered domain, no finding.
    assert.ok(!out.findings.some((f) => f.host === 'k1._domainkey.example.com'));
  });

  test('the caller\'s other domains are its own: never looked up, their names never asked', async () => {
    const { out, rdap, dns } = await run({ ownDomains: ['example.org'] });
    assert.ok(!rdap.calls.includes('example.org'));
    assert.ok(!dns.calls.some((c) => c.name.endsWith('.example.org')), 'mx.example.org and sip.example.org are the caller\'s own');
    assert.ok(!out.findings.some((f) => f.target.endsWith('.example.org')));
  });

  test('host names given as text are asked whatever they had; a failed lookup is a failure named as findingLookups names it', async () => {
    const { out } = await run({
      hosts: ['shop.example.com', 'www.example.com', 'shop.example.com'],
      dns: {
        'shop.example.com|A': ok('shop.example.com', 'A', [rr('shop.example.com', 'CNAME', 'shop.gone.example')], 'NXDOMAIN'),
        'www.example.com|A': fail('www.example.com', 'A'),
        'example.com|CAA': fail('example.com', 'CAA')
      }
    });
    assert.equal(out.hosts, 2, 'each name once');
    assert.ok(out.findings.some((f) => f.kind === 'cname' && f.host === 'shop.example.com' && f.severity === 'critical'));
    assert.deepEqual(out.failures.map((f) => f.name).sort(), ['example.com CAA', 'www.example.com']);
    assert.ok(findingLookups({ kind: 'caa', host: 'example.com', target: 'iodef.pending.example', chain: ['iodef.pending.example'] }).includes('example.com CAA'));
    assert.ok(!out.findings.some((f) => f.kind === 'caa'), 'the iodef address was not read');
  });

  test('the reserved-name guard holds for every new kind: nothing under .test or .internal is looked up or asked', async () => {
    const dns = fakeDns({
      'example.com|TXT': ok('example.com', 'TXT', [rr('example.com', 'TXT', ['v=spf1 a:relay.gone.test -all'])]),
      '_dmarc.example.com|TXT': ok('_dmarc.example.com', 'TXT', [rr('_dmarc.example.com', 'TXT', ['v=DMARC1; p=none; rua=mailto:d@corp.internal'])]),
      'selector1._domainkey.example.com|TXT': ok('selector1._domainkey.example.com', 'TXT', [rr('selector1._domainkey.example.com', 'CNAME', 'sel.gone.test')], 'NXDOMAIN'),
      '_acme-challenge.example.com|TXT': ok('_acme-challenge.example.com', 'TXT', [rr('_acme-challenge.example.com', 'CNAME', 'acme.gone.test')], 'NXDOMAIN')
    });
    const rdap = fakeRdap({});
    const out = await auditTakeover({ domains: ['example.com'] }, { dns, rdap, now: () => NOW });
    assert.deepEqual(rdap.calls, []);
    assert.ok(!dns.calls.some((c) => /\.(test|internal)$/.test(c.name)), dns.calls.map((c) => c.name).join(', '));
    assert.deepEqual(out.findings.map(row), ['low dkim selector1._domainkey.example.com → sel.gone.test: nxdomain'], 'the dangling DKIM key still counts, from its own query');
  });

  test('an _acme-challenge delegation is judged by its domain\'s registration alone: its TXT exists only while a validation runs', async () => {
    // acme.sh --challenge-alias, lego following the CNAME: between renewals the name the delegation points to does not exist.
    const between = { '_acme-challenge.example.com|TXT': ok('_acme-challenge.example.com', 'TXT', [
      rr('_acme-challenge.example.com', 'CNAME', '_acme-challenge.example.com.validation.example.net')
    ], 'NXDOMAIN') };
    const quiet = await auditTakeover({ domains: ['example.com'] }, { dns: fakeDns(between), rdap: fakeRdap({}), now: () => NOW });
    assert.deepEqual(quiet.findings.map(row), [], 'a working delegation between renewals is no finding');
    const lapsed = await auditTakeover({ domains: ['example.com'] }, {
      dns: fakeDns({ ...between, 'example.net|NS': ok('example.net', 'NS', [], 'NXDOMAIN') }), rdap: fakeRdap({ 'example.net': notFound('example.net') }), now: () => NOW
    });
    assert.deepEqual(lapsed.findings.map(row), ['critical acme _acme-challenge.example.com → _acme-challenge.example.com.validation.example.net: unregistered'],
      'whoever registers the domain behind it passes DNS-01 for example.com');
  });

  test('mta-sts.<domain> among the hosts given is the domain\'s own reference: asked once, one finding, one page check', async () => {
    const onPages = { 'mta-sts.example.com|A': ok('mta-sts.example.com', 'A', [rr('mta-sts.example.com', 'CNAME', 'example-sts.github.io'), rr('example-sts.github.io', 'A', '198.51.100.80')]) };
    // A Subdomains scan finds it (CT always has it); the runner gets it from --names or --from-subdomains.
    for (const given of [{ name: 'mta-sts.example.com', resolution: { cnames: ['example-sts.github.io'] } }, 'MTA-STS.example.com']) {
      const dns = fakeDns(onPages);
      const out = await auditTakeover({ hosts: [given], domains: ['example.com'] }, { dns, rdap: fakeRdap({}), now: () => NOW });
      const label = typeof given === 'string' ? 'listed' : 'scanned';
      assert.deepEqual(out.findings.map(row), ['info mta-sts mta-sts.example.com → example-sts.github.io: check-http'], label);
      assert.deepEqual(httpCandidates(out.findings).map((f) => f.host), ['mta-sts.example.com'], `${label}: one probe`);
      assert.equal(dns.calls.filter((c) => c.name === 'mta-sts.example.com').length, 1, `${label}: asked once`);
      assert.equal(out.hosts, 1, `${label}: the host given counts as asked`);
    }
  });

  test('a host given with the chain the scan saw stands in when the domain\'s own query for it fails', async () => {
    const { out } = await run({
      hosts: [{ name: 'mta-sts.example.com', resolution: { cnames: ['policy.lapsed.example'] } }],
      dns: { 'mta-sts.example.com|A': fail('mta-sts.example.com', 'A') }
    });
    assert.deepEqual(out.findings.filter((f) => f.host === 'mta-sts.example.com').map(row), ['critical mta-sts mta-sts.example.com → policy.lapsed.example: unregistered']);
    assert.ok(out.failures.some((f) => f.name === 'mta-sts.example.com A'));
  });
});

describe('carried, never fixed: a failed lookup names every finding it hides', () => {
  const rr = (name, type, data) => ({ name, type, ttl: 300, data });
  // One reference of every kind, each into gone.example (RDAP 404 and NXDOMAIN: unregistered), so each is a finding.
  const WORLD = {
    'shop.example.com|A': ok('shop.example.com', 'A', [rr('shop.example.com', 'CNAME', 'shop.gone.example')]),
    'example.com|NS': ok('example.com', 'NS', [rr('example.com', 'NS', 'ns.gone.example')]),
    'example.com|MX': ok('example.com', 'MX', [rr('example.com', 'MX', { preference: 10, exchange: 'mx.gone.example' })]),
    'example.com|TXT': ok('example.com', 'TXT', [rr('example.com', 'TXT', ['v=spf1 include:_spf.gone.example a:relay.gone.example -all'])]),
    '_dmarc.example.com|TXT': ok('_dmarc.example.com', 'TXT', [rr('_dmarc.example.com', 'TXT', ['v=DMARC1; p=none; rua=mailto:d@reports.gone.example'])]),
    'selector1._domainkey.example.com|TXT': ok('selector1._domainkey.example.com', 'TXT', [rr('selector1._domainkey.example.com', 'CNAME', 'sel.gone.example')]),
    'example.com|CAA': ok('example.com', 'CAA', [rr('example.com', 'CAA', { flags: 0, tag: 'iodef', value: 'mailto:caa@iodef.gone.example' })]),
    'mta-sts.example.com|A': ok('mta-sts.example.com', 'A', [rr('mta-sts.example.com', 'CNAME', 'mta.gone.example')]),
    '_sip._tls.example.com|SRV': ok('_sip._tls.example.com', 'SRV', [rr('_sip._tls.example.com', 'SRV', { priority: 1, weight: 1, port: 443, target: 'sip.gone.example' })]),
    'example.com|HTTPS': ok('example.com', 'HTTPS', [rr('example.com', 'HTTPS', { priority: 1, target: 'edge.gone.example', params: {} })]),
    '_acme-challenge.example.com|TXT': ok('_acme-challenge.example.com', 'TXT', [rr('_acme-challenge.example.com', 'CNAME', '_acme-challenge.gone.example')]),
    'gone.example|NS': ok('gone.example', 'NS', [], 'NXDOMAIN')
  };
  const audit = (dns, rdap) => auditTakeover({ hosts: ['shop.example.com'], domains: ['example.com'] }, { dns, rdap, now: () => NOW, skipTlds: [] });
  const rankOf = (s) => TAKEOVER_SEVERITIES.indexOf(s);

  test('whatever single lookup fails, a finding it hides or lowers names it among its lookups (findingLookups, REFERENCE_QUERIES)', async () => {
    const dns = fakeDns(WORLD);
    const rdap = fakeRdap({ 'gone.example': notFound('gone.example') });
    const base = await audit(dns, rdap);
    assert.deepEqual([...new Set(base.findings.map((f) => f.kind))].sort(), [...TAKEOVER_REF_KINDS].sort(), 'a finding of every kind');
    assert.deepEqual(base.failures, []);
    const lookups = [
      ...[...new Set(dns.calls.map((c) => `${c.name}|${c.type}`))].map((q) => ({ q, dns: { [q]: () => fail(...q.split('|')) }, rdap: {} })),
      ...[...new Set(rdap.calls)].map((d) => ({ q: `RDAP ${d}`, dns: {}, rdap: { [d]: rateLimited(d) } }))
    ];
    // The kinds hidden by a failure of one of example.com's own queries (not the RDAP or NS lookup of gone.example, which hide them all).
    const hiddenByOwnQuery = new Set();
    for (const one of lookups) {
      const out = await audit(fakeDns({ ...WORLD, ...one.dns }), fakeRdap({ 'gone.example': notFound('gone.example'), ...one.rdap }));
      const failed = new Set(out.failures.map((f) => f.name));
      assert.ok(failed.size > 0, `${one.q}: its failure is reported`);
      for (const f of base.findings) {
        const now = out.findings.find((x) => x.id === f.id);
        if (now && rankOf(now.severity) <= rankOf(f.severity)) continue;
        if (/(^|\.)example\.com\|/.test(one.q)) hiddenByOwnQuery.add(f.kind);
        assert.ok(findingLookups(f).some((name) => failed.has(name)), `${one.q} hides ${f.id}, whose lookups ${findingLookups(f).join(', ')} name none of ${[...failed].join(', ')}`);
      }
    }
    assert.deepEqual([...hiddenByOwnQuery].sort(), [...TAKEOVER_REF_KINDS].sort(), 'every kind was hidden by a failure of its own record query');
  });
});
