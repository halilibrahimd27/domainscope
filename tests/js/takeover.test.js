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
  httpCheckOutcome, applyHttpCheck
} from '../../assets/js/lib/takeover.js';

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

  test('the candidates are the findings the page decides, at most HTTP_CHECK_MAX', () => {
    const many = Array.from({ length: HTTP_CHECK_MAX + 3 }, (_, i) => ({ ...finding, id: `f${i}` }));
    assert.equal(httpCandidates(many).length, HTTP_CHECK_MAX);
    assert.deepEqual(httpCandidates([{ ...finding, reasons: [{ code: 'nxdomain', severity: 'high' }] }]), []);
    assert.deepEqual(httpCandidates(null), []);
  });
});
