/**
 * renewalplan.test.js — lib/renewalplan.js: the SC-081 schedule, validity days, renewal windows and
 * plans (an injected now), the ARI CertID (RFC 9773's own example) and lookup (a fake fetch), the
 * coverage planner's groupings and the OpenSSL / certreq configurations. Documentation names only.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LIFETIME_SCHEDULE, PLAN_STATES, ARI_DIRECTORIES, ARI_FAILURES, GROUPINGS, GROUPING_NOTES, CSR_KEY_TYPES, ENVIRONMENTS,
  scheduleStep, stepEnd, validityDays, renewalWindow, stepRate, planRenewals, ariCertId, ariSupported, fetchRenewalInfo,
  nameEnvironment, planNames, wildcardCovers, coveragePlan, csrBaseName, opensslConfig, certreqInf
} from '../../assets/js/lib/renewalplan.js';

const DAY = 86400000;
const at = (s) => new Date(s);
/** A certificate like an ACME CA's: notAfter is notBefore + days − 1 s (the validity period is inclusive). */
const certOf = (from, days, extra = {}) => ({ notBefore: at(from), notAfter: new Date(Date.parse(from) + days * DAY - 1000), ...extra });

test('the schedule is ballot SC-081v3 as the Baseline Requirements §6.3.2 and §4.2.1 hold it', () => {
  assert.deepEqual(LIFETIME_SCHEDULE.map((s) => [s.from, s.maxDays, s.dcvDays]), [
    [null, 398, 398], ['2026-03-15', 200, 200], ['2027-03-15', 100, 100], ['2029-03-15', 47, 10]
  ]);
  assert.ok(Object.isFrozen(LIFETIME_SCHEDULE) && LIFETIME_SCHEDULE.every(Object.isFrozen));
  assert.equal(scheduleStep(at('2026-03-14T23:59:59Z')).id, 'before');
  assert.equal(scheduleStep(at('2026-03-15T00:00:00Z')).id, '2026');
  assert.equal(scheduleStep(Date.parse('2027-03-15T00:00:00Z') - 1).id, '2026');
  assert.equal(scheduleStep(at('2027-03-15T00:00:00Z')).id, '2027');
  assert.equal(scheduleStep(at('2029-03-15T00:00:00Z')).id, '2029');
  assert.equal(scheduleStep(at('2035-01-01T00:00:00Z')).maxDays, 47);
  assert.equal(stepEnd(LIFETIME_SCHEDULE[1]).toISOString(), '2027-03-15T00:00:00.000Z');
  assert.equal(stepEnd(LIFETIME_SCHEDULE[3]), null);
});

test('validity days count notBefore through notAfter inclusive, a part of a day a whole day', () => {
  assert.equal(validityDays(at('2026-09-04T14:34:32Z'), at('2026-12-03T14:34:31Z')), 90);
  assert.equal(validityDays(at('2026-01-01T00:00:00Z'), at('2026-04-01T00:00:00Z')), 91, 'exactly 90 days apart is one second more than 90 days');
  assert.equal(validityDays(at('2026-04-01T00:00:00Z'), new Date(Date.parse('2026-04-01T00:00:00Z') + 47 * DAY - 1000)), 47);
  assert.equal(validityDays(at('2026-04-01T00:00:00Z'), at('2026-03-01T00:00:00Z')), 0);
  assert.equal(validityDays('x', 'y'), 0);
});

test('the renewal window: two thirds of the lifetime until expiry, or the CA’s ARI window', () => {
  const cert = certOf('2026-09-01T00:00:00Z', 90);
  const w = renewalWindow(cert);
  assert.equal(w.source, 'two-thirds');
  assert.ok(Math.abs(w.start - Date.parse('2026-10-31T00:00:00Z')) < 1000, 'day 60 of 90');
  assert.equal(w.end.getTime(), cert.notAfter.getTime());
  const ari = { ok: true, start: at('2026-10-29T00:00:00Z'), end: at('2026-10-30T00:00:00Z') };
  assert.deepEqual(renewalWindow(cert, { ari }), { source: 'ari', start: ari.start, end: ari.end });
  assert.equal(renewalWindow(cert, { ari: { ok: false, code: 'not-found' } }).source, 'two-thirds');
});

test('a step’s rate: renewals a year, and domain validations when one is reused for as many renewals as fit', () => {
  const [, s2026, s2027, s2029] = LIFETIME_SCHEDULE;
  const r = stepRate(s2026, 398);
  assert.equal(r.lifetimeDays, 200, 'cut to the step’s maximum');
  assert.ok(Math.abs(r.intervalDays - 133.33) < 0.01);
  assert.ok(Math.abs(r.perYear - 2.74) < 0.01);
  assert.ok(Math.abs(r.validationsPerYear - r.perYear / 2) < 1e-9, 'a 200-day reuse covers the next renewal too');
  const r90 = stepRate(s2027, 90);
  assert.equal(r90.lifetimeDays, 90);
  assert.ok(Math.abs(r90.perYear - 6.09) < 0.01 && !r90.revalidateEach);
  const r47 = stepRate(s2029, 398);
  assert.equal(r47.lifetimeDays, 47);
  assert.ok(Math.abs(r47.perYear - 11.66) < 0.01);
  assert.ok(r47.revalidateEach && r47.validationsPerYear === r47.perYear, '10-day reuse: every renewal validates again');
});

test('a 90-day certificate: its state, window, next renewals at the shrinking caps and the renewals per year to 2030', () => {
  const cert = certOf('2026-09-04T14:34:32Z', 90);
  const plan = planRenewals(cert, { now: Date.parse('2026-10-08T12:00:00Z') });
  assert.equal(plan.lifetimeDays, 90);
  assert.equal(plan.issuedUnder.id, '2026');
  assert.equal(plan.overMax, false);
  assert.equal(plan.state, 'before-window');
  assert.equal(plan.window.source, 'two-thirds');
  assert.equal(plan.daysLeft, 56);
  assert.equal(plan.next.length, 6);
  assert.equal(plan.next[0].at.getTime(), plan.window.start.getTime(), 'the first renewal at the window’s start');
  assert.ok(plan.next.every((n, i) => i === 0 || Math.round((n.at - plan.next[i - 1].at) / DAY) === 60), 'every 60 days');
  assert.deepEqual(plan.next.map((n) => n.step), ['2026', '2026', '2026', '2027', '2027', '2027']);
  assert.equal(plan.next[0].expires.getTime(), plan.next[0].at.getTime() + 90 * DAY - 1000);
  assert.deepEqual(plan.years.map((y) => y.year), [2026, 2027, 2028, 2029, 2030]);
  assert.equal(plan.years[0].renewals, 1);
  assert.ok(plan.years[1].renewals >= 6 && plan.years[1].renewals <= 7);
  assert.ok(plan.years[4].renewals >= 11 && plan.years[4].renewals <= 12, '47-day certificates in 2030');
  assert.deepEqual(plan.steps.map((s) => [s.step, s.lifetimeDays, s.current]), [['2026', 90, true], ['2027', 90, false], ['2029', 47, false]]);
});

test('a 398-day certificate issued before the first step is renewed into 200-, 100- and 47-day ones', () => {
  const cert = certOf('2026-01-10T00:00:00Z', 398);
  const plan = planRenewals(cert, { now: Date.parse('2026-02-01T00:00:00Z'), count: 14 });
  assert.equal(plan.issuedUnder.id, 'before');
  assert.equal(plan.overMax, false);
  assert.deepEqual(plan.steps.map((s) => s.step), ['before', '2026', '2027', '2029']);
  assert.deepEqual(plan.next.slice(0, 4).map((n) => [n.at.toISOString().slice(0, 10), n.lifetimeDays]),
    [['2026-10-02', 200], ['2027-02-12', 200], ['2027-06-25', 100], ['2027-08-31', 100]]);
  assert.ok(plan.next.some((n) => n.lifetimeDays === 47));
  assert.ok(plan.next.every((n) => n.lifetimeDays <= scheduleStep(n.at).maxDays));
});

test('the states of a plan, and a lifetime longer than the step it was issued under allowed', () => {
  const cert = certOf('2026-09-01T00:00:00Z', 90);
  const state = (now) => planRenewals(cert, { now: Date.parse(now) }).state;
  assert.equal(state('2026-08-01T00:00:00Z'), 'not-yet-valid');
  assert.equal(state('2026-10-01T00:00:00Z'), 'before-window');
  assert.equal(state('2026-11-15T00:00:00Z'), 'in-window');
  assert.equal(state('2026-12-01T00:00:00Z'), 'expired');
  const ari = { ok: true, start: at('2026-10-29T00:00:00Z'), end: at('2026-10-30T00:00:00Z') };
  assert.equal(planRenewals(cert, { now: Date.parse('2026-11-05T00:00:00Z'), ari }).state, 'past-window');
  const past = planRenewals(cert, { now: Date.parse('2026-11-05T00:00:00Z'), ari });
  assert.equal(past.next[0].at.toISOString(), '2026-11-05T00:00:00.000Z', 'past the window: renew now');
  assert.deepEqual(PLAN_STATES, ['not-yet-valid', 'before-window', 'in-window', 'past-window', 'expired']);
  const long = planRenewals(certOf('2026-05-01T00:00:00Z', 398), { now: Date.parse('2026-06-01T00:00:00Z') });
  assert.equal(long.overMax, true, 'no publicly trusted certificate issued then may live 398 days');
  assert.equal(planRenewals({ notBefore: 'x', notAfter: null }), null);
  assert.equal(planRenewals(null), null);
});

test('the ARI CertID: RFC 9773’s example, a sign byte for a high-bit serial, nothing without a key identifier', () => {
  assert.equal(ariCertId({ authorityKeyId: '69885b6b87464041e1b37b847ba0ae2cde01c8d4', serialHex: '87654321' }), 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE');
  assert.equal(ariCertId({ authorityKeyId: '69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4', serialHex: '0087654321' }), 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE');
  assert.equal(ariCertId({ authorityKeyId: '0102', serialHex: '1' }), 'AQI.AQ');
  assert.equal(ariCertId({ authorityKeyId: null, serialHex: '01' }), null);
  assert.equal(ariCertId({ authorityKeyId: '0102', serialHex: '' }), null);
  assert.ok(ariSupported('letsencrypt') && !ariSupported('sectigo') && !ariSupported(null) && !ariSupported('constructor'));
});

/** A fake fetch from `routes` (url → [status, body, headers] or a function), recording each call. */
function fakeFetch(routes, calls = []) {
  const impl = async (url, init = {}) => {
    calls.push(String(url));
    const route = routes[String(url)];
    if (!route) return new Response('not found', { status: 404 });
    if (typeof route === 'function') return route(init);
    const [status, body, headers = {}] = route;
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  };
  impl.calls = calls;
  return impl;
}
const LEAF = { authorityKeyId: '69885b6b87464041e1b37b847ba0ae2cde01c8d4', serialHex: '87654321' };
const DIR = ARI_DIRECTORIES.letsencrypt;
const RI = 'https://acme-v02.api.letsencrypt.org/acme/renewal-info';
const NOW = () => Date.parse('2026-10-08T12:00:00Z');

test('ARI: the directory’s renewalInfo, then the window for the CertID, with Retry-After', async () => {
  const fetchImpl = fakeFetch({
    [DIR]: [200, { newNonce: 'x', renewalInfo: RI }],
    [`${RI}/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE`]: [200, { suggestedWindow: { start: '2026-11-02T17:18:36Z', end: '2026-11-04T12:29:25Z' }, explanationURL: 'https://example.com/why' }, { 'retry-after': '21600' }]
  });
  const r = await fetchRenewalInfo(LEAF, { fetchImpl, now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.start.toISOString(), '2026-11-02T17:18:36.000Z');
  assert.equal(r.end.toISOString(), '2026-11-04T12:29:25.000Z');
  assert.equal(r.retryAfterMs, 21600000);
  assert.equal(r.explanationUrl, 'https://example.com/why');
  assert.equal(r.at.getTime(), NOW());
  assert.deepEqual(fetchImpl.calls, [DIR, `${RI}/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE`]);
});

test('ARI failures are results with a code; only an abort rejects', async () => {
  const win = { suggestedWindow: { start: '2026-11-02T00:00:00Z', end: '2026-11-04T00:00:00Z' } };
  const id = 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE';
  const unknown = await fetchRenewalInfo(LEAF, { fetchImpl: fakeFetch({ [DIR]: [200, { renewalInfo: RI }] }), now: NOW });
  assert.deepEqual([unknown.ok, unknown.code, unknown.status], [false, 'not-found', 404]);
  const noRi = fakeFetch({ [DIR]: [200, { newNonce: 'x' }] });
  assert.equal((await fetchRenewalInfo(LEAF, { fetchImpl: noRi })).code, 'no-renewal-info');
  const elsewhere = fakeFetch({ [DIR]: [200, { renewalInfo: 'https://ari.example.net/renewal-info' }] });
  assert.equal((await fetchRenewalInfo(LEAF, { fetchImpl: elsewhere })).code, 'no-renewal-info');
  assert.deepEqual(elsewhere.calls, [DIR], 'nothing sent to a host the directory names');
  const backwards = fakeFetch({ [DIR]: [200, { renewalInfo: RI }], [`${RI}/${id}`]: [200, { suggestedWindow: { start: '2026-11-04T00:00:00Z', end: '2026-11-02T00:00:00Z' } }] });
  assert.equal((await fetchRenewalInfo(LEAF, { fetchImpl: backwards })).code, 'bad-window');
  const garbled = fakeFetch({ [DIR]: [200, { renewalInfo: RI }], [`${RI}/${id}`]: [200, '{"suggestedWindow":'] });
  assert.equal((await fetchRenewalInfo(LEAF, { fetchImpl: garbled })).code, 'parse');
  const limited = fakeFetch({ [DIR]: [200, { renewalInfo: RI }], [`${RI}/${id}`]: [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'retry-after': '60' }] });
  const rl = await fetchRenewalInfo(LEAF, { fetchImpl: limited });
  assert.deepEqual([rl.code, rl.status, rl.retryAfterMs], ['rate-limit', 429, 60000]);
  const down = async () => { throw new TypeError('Failed to fetch'); };
  assert.equal((await fetchRenewalInfo(LEAF, { fetchImpl: down })).code, 'network');
  const stall = (url, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason)));
  assert.equal((await fetchRenewalInfo(LEAF, { fetchImpl: stall, timeoutMs: 20 })).code, 'timeout');
  const none = fakeFetch({});
  assert.equal((await fetchRenewalInfo({ serialHex: '01' }, { fetchImpl: none })).code, 'no-key-id');
  assert.equal((await fetchRenewalInfo(LEAF, { ca: 'digicert', fetchImpl: none })).code, 'unsupported');
  assert.deepEqual(none.calls, [], 'nothing sent without a CertID or an ARI server');
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(fetchRenewalInfo(LEAF, { fetchImpl: fakeFetch({ [DIR]: [200, { renewalInfo: RI }], [`${RI}/${id}`]: [200, win] }), signal: controller.signal }), { name: 'AbortError' });
  assert.ok(ARI_FAILURES.includes('not-found') && Object.isFrozen(ARI_FAILURES));
});

test('environments from the labels below the registrable domain', () => {
  assert.equal(nameEnvironment('example.com'), 'prod');
  assert.equal(nameEnvironment('www.example.com'), 'prod');
  assert.equal(nameEnvironment('dev.example.com'), 'dev');
  assert.equal(nameEnvironment('api.dev.example.com'), 'dev');
  assert.equal(nameEnvironment('*.staging.example.com'), 'staging');
  assert.equal(nameEnvironment('api-stg.example.com'), 'staging');
  assert.equal(nameEnvironment('qa2.example.org'), 'test');
  assert.equal(nameEnvironment('contest.example.com'), 'prod');
  assert.equal(nameEnvironment('example-dev.com'), 'prod', 'the registrable label is the domain’s own name');
  assert.deepEqual(ENVIRONMENTS, ['prod', 'staging', 'test', 'dev']);
});

test('the planner’s names: normalized, deduplicated, and what a CA cannot certify left out', () => {
  const { names, invalid } = planNames('WWW.Example.com\nwww.example.com, *.example.com\n# a comment\n192.0.2.1 *.com localhost bad_label.example.com bücher.example.com');
  assert.deepEqual(names.map((n) => [n.name, n.wildcard, n.domain]), [
    ['www.example.com', false, 'example.com'], ['*.example.com', true, 'example.com'], ['xn--bcher-kva.example.com', false, 'example.com']
  ]);
  assert.deepEqual(invalid, ['192.0.2.1', '*.com', 'localhost', 'bad_label.example.com']);
  assert.deepEqual(planNames([{ name: 'example.net' }, 'example.net']).names.map((n) => n.name), ['example.net']);
});

test('a wildcard covers exactly one label below its base: never the apex, never deeper', () => {
  assert.ok(wildcardCovers('*.example.com', 'www.example.com'));
  assert.ok(!wildcardCovers('*.example.com', 'example.com'));
  assert.ok(!wildcardCovers('*.example.com', 'a.b.example.com'));
  assert.ok(!wildcardCovers('*.example.com', '*.example.com'));
  assert.ok(!wildcardCovers('www.example.com', 'www.example.com'));
});

const NAMES = 'example.com www.example.com api.example.com shop.example.com dev.example.com api.dev.example.com web.dev.example.com staging.example.com a.b.example.com example.net';

test('groupings: one SAN list, wildcards with what they leave uncovered, one certificate per environment', () => {
  const plan = coveragePlan(NAMES);
  assert.deepEqual(plan.groupings.map((g) => g.id), GROUPINGS);
  const [san, wild, env] = plan.groupings;
  assert.equal(san.certs.length, 1);
  assert.equal(san.entries, 10);
  assert.deepEqual(san.notes, ['mixed-domains']);
  assert.equal(san.certs[0].commonName, 'example.com');

  assert.deepEqual(wild.certs.map((c) => [c.domain, c.names]), [
    ['example.com', ['example.com', '*.example.com', '*.dev.example.com', 'a.b.example.com']],
    ['example.net', ['example.net']]
  ]);
  assert.equal(wild.entries, 5);
  assert.deepEqual(wild.uncovered, [
    { name: 'example.com', wildcard: '*.example.com', reason: 'apex' },
    { name: 'a.b.example.com', wildcard: '*.example.com', reason: 'deeper' }
  ]);
  assert.deepEqual(wild.notes, ['dns-01']);
  assert.deepEqual(wild.certs[0].covers.length, 9, 'every example.com name is served');

  assert.deepEqual(env.certs.map((c) => [c.env, c.names]), [
    ['prod', ['example.com', 'www.example.com', 'api.example.com', 'shop.example.com', 'a.b.example.com', 'example.net']],
    ['staging', ['staging.example.com']],
    ['dev', ['dev.example.com', '*.dev.example.com']]
  ]);
  assert.deepEqual(env.uncovered, [{ name: 'dev.example.com', wildcard: '*.dev.example.com', reason: 'apex' }]);
  assert.deepEqual(env.notes, ['dns-01', 'mixed-domains', 'no-prod-wildcard']);
  assert.ok(env.notes.every((n) => GROUPING_NOTES.includes(n)));
});

test('a list over the SAN limit is split; no wildcard and no environment grouping where none can form', () => {
  const plan = coveragePlan('a.example.com b.example.com c.example.com d.example.com e.example.com', { sanLimit: 2 });
  const san = plan.groupings[0];
  assert.deepEqual(san.certs.map((c) => [c.part, c.parts, c.names.length]), [[1, 3, 2], [2, 3, 2], [3, 3, 1]]);
  assert.ok(san.notes.includes('split'));
  assert.deepEqual(plan.groupings.find((g) => g.id === 'wildcard').certs.map((c) => c.names), [['*.example.com']]);
  const lone = coveragePlan('www.example.com example.org');
  assert.deepEqual(lone.groupings.map((g) => g.id), ['san']);
  assert.deepEqual(coveragePlan('').groupings, []);
  const typed = coveragePlan('*.example.com example.com');
  assert.deepEqual(typed.groupings.map((g) => g.id), ['san', 'wildcard'], 'a typed wildcard is kept');
  assert.deepEqual(typed.groupings[1].uncovered, [{ name: 'example.com', wildcard: '*.example.com', reason: 'apex' }]);
});

test('the OpenSSL configuration: no prompts, the Common Name, every entry a DNS SAN, the key made by the command', () => {
  const cert = coveragePlan(NAMES).groupings[1].certs[0];
  const o = opensslConfig(cert, { keyType: 'ec-p256' });
  assert.equal(o.file, 'example.com.cnf');
  assert.equal(o.command, 'openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout example.com.key -out example.com.csr -config example.com.cnf');
  const lines = o.config.split('\n');
  for (const l of ['[ req ]', 'prompt             = no', 'req_extensions     = req_ext', 'CN = example.com', 'subjectAltName = @alt_names',
    'DNS.1 = example.com', 'DNS.2 = *.example.com', 'DNS.3 = *.dev.example.com', 'DNS.4 = a.b.example.com']) assert.ok(lines.includes(l), l);
  assert.ok(!/BEGIN|PRIVATE KEY/.test(o.config));
  assert.match(opensslConfig(cert, { keyType: 'rsa-3072' }).command, /-newkey rsa:3072 /);
  assert.match(opensslConfig(cert, { keyType: 'nope' }).command, /ec_paramgen_curve:P-256/);
  const long = `${'a'.repeat(60)}.example.com`;
  const noCn = opensslConfig({ names: [long], commonName: null });
  assert.ok(noCn.command.endsWith(' -subj /') && !/^CN = /m.test(noCn.config));
  assert.equal(csrBaseName({ names: ['*.example.com'], commonName: '*.example.com' }), 'wildcard.example.com');
  const tampered = opensslConfig({ names: ['www.example.com', 'x.example.com\n[ evil ]', '$(id).example.com'], commonName: 'www.example.com' });
  assert.deepEqual(tampered.names, ['www.example.com'], 'only normalized host names reach a configuration');
  assert.deepEqual(CSR_KEY_TYPES, ['ec-p256', 'ec-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096']);
});

test('the certreq INF: the subject, the key in the machine store, server authentication and one _continue_ per entry', () => {
  const r = certreqInf({ names: ['www.example.com', '*.example.com'], commonName: 'www.example.com' }, { keyType: 'ec-p256' });
  assert.equal(r.file, 'www.example.com.inf');
  assert.equal(r.command, 'certreq -new www.example.com.inf www.example.com.csr');
  const lines = r.inf.split('\r\n');
  for (const l of ['[Version]', 'Signature = "$Windows NT$"', 'Subject = "CN=www.example.com"', 'KeyAlgorithm = ECDSA_P256', 'KeyLength = 256',
    'MachineKeySet = TRUE', 'RequestType = PKCS10', 'OID = 1.3.6.1.5.5.7.3.1', '2.5.29.17 = "{text}"',
    '_continue_ = "dns=www.example.com&"', '_continue_ = "dns=*.example.com&"']) assert.ok(lines.includes(l), l);
  const rsa = certreqInf({ names: ['www.example.com'], commonName: 'www.example.com' }).inf;
  assert.ok(rsa.includes('KeyLength = 2048\r\n') && rsa.includes('KeySpec = 1\r\n') && rsa.includes('KeyUsage = 0xa0\r\n'));
});
