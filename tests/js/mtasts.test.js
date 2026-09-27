/**
 * lib/mtasts.js — the MTA-STS policy (RFC 8461): the Globalping request, the policy parser, the
 * reading of a measurement and the validation Domain Health shows. No network: the two live
 * captures of 2026-09-27 (tests/fixtures/globalping/m26, m27) plus results shaped like them.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MTA_STS_PATH, MTA_STS_MAX_AGE_LIMIT, MTA_STS_MODES, MTA_STS_FINDINGS, MTA_STS_HEADLINES, MTA_STS_I18N,
  mtaStsPolicyHost, mtaStsPolicyUrl, mtaStsPolicyRequest, mxPatternMatches, parseMtaStsPolicy,
  interpretPolicyFetch, validateMtaSts
} from '../../assets/js/lib/mtasts.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'globalping');
const fx = (name) => JSON.parse(readFileSync(join(FIX, `${name}.json`), 'utf8'));
const M26 = fx('m26-mta-sts-policy');
const M27 = fx('m27-mta-sts-no-host');
const NOW = Date.parse(M26.capturedAt);
const HOST = 'mta-sts.example.com';

/** The RFC 8461 §3.2 example policy. */
const RFC_POLICY = 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmx: backupmx.example.com\nmax_age: 604800\n';

/** A finished measurement shaped like m26, with its result fields overridden. */
function measurement(result = {}, { tls = {} } = {}) {
  const base = structuredClone(M26.final.body);
  const r = base.results[0].result;
  Object.assign(r, result);
  if (r.tls && tls !== null) Object.assign(r.tls, tls);
  if (tls === null) r.tls = null;
  return base;
}
const policyFetch = (body, extra = {}, opts = {}) => interpretPolicyFetch(measurement({ rawBody: body, ...extra }, opts), { host: HOST });
const ids = (v) => v.findings.map((f) => f.id);
const sev = (v, id) => v.findings.find((f) => f.id === id)?.severity;
const MX = ['mx.example.com', 'alt1.mx.example.com'];

/* ---- constants and the request ------------------------------------------------------- */

test('constants', () => {
  assert.equal(MTA_STS_PATH, '/.well-known/mta-sts.txt');
  assert.equal(MTA_STS_MAX_AGE_LIMIT, 31557600);
  assert.deepEqual(MTA_STS_MODES, ['enforce', 'testing', 'none']);
  assert.ok(Object.isFrozen(MTA_STS_FINDINGS) && Object.isFrozen(MTA_STS_HEADLINES));
});

test('mtaStsPolicyHost / Url / Request: mta-sts.<domain>, one probe, HTTPS GET of the well-known path', () => {
  assert.equal(mtaStsPolicyHost('Example.COM.'), HOST);
  assert.equal(mtaStsPolicyUrl('example.com'), 'https://mta-sts.example.com/.well-known/mta-sts.txt');
  assert.deepEqual(mtaStsPolicyRequest('example.com'), M26.request, 'the body sent live');
  assert.equal(mtaStsPolicyRequest('example.com', { timeoutS: 20 }).timeout, 20);
  for (const bad of ['', 'localhost', '192.0.2.1', '_dmarc.example.com', null, 'bad name']) {
    assert.equal(mtaStsPolicyHost(bad), null, String(bad));
    assert.throws(() => mtaStsPolicyRequest(bad), TypeError, String(bad));
  }
});

/* ---- mx patterns (RFC 8461 §4.1) ----------------------------------------------------- */

test('mxPatternMatches: literal names, and "*." matching exactly one left-most label', () => {
  assert.equal(mxPatternMatches('*.example.com', 'mail.example.com'), true, 'the RFC example');
  assert.equal(mxPatternMatches('*.example.com', 'example.com'), false, 'the RFC example');
  assert.equal(mxPatternMatches('*.example.com', 'foo.bar.example.com'), false, 'the RFC example');
  assert.equal(mxPatternMatches('mail.example.com', 'MAIL.Example.com.'), true, 'case and a trailing dot');
  assert.equal(mxPatternMatches('mail.example.com', 'mail2.example.com'), false);
  assert.equal(mxPatternMatches('mail*.example.com', 'mail2.example.com'), false, 'a partial wildcard is no pattern');
  assert.equal(mxPatternMatches('*.com', 'example.com'), false, 'never a public suffix');
  assert.equal(mxPatternMatches('', 'mail.example.com'), false);
});

/* ---- parser (RFC 8461 §3.2) -------------------------------------------------------------- */

test('parseMtaStsPolicy: the RFC example, LF or CRLF, with or without a final line break', () => {
  for (const text of [RFC_POLICY, RFC_POLICY.replace(/\n/g, '\r\n'), RFC_POLICY.trimEnd()]) {
    const p = parseMtaStsPolicy(text);
    assert.deepEqual([p.valid, p.version, p.mode, p.maxAge], [true, 'STSv1', 'enforce', 604800]);
    assert.deepEqual(p.mx, ['mail.example.com', '*.example.net', 'backupmx.example.com']);
    assert.deepEqual(p.issues, []);
  }
  const live = parseMtaStsPolicy(M26.final.body.results[0].result.rawBody);
  assert.deepEqual([live.valid, live.mode, live.maxAge, live.mx], [true, 'enforce', 86400, ['smtp.example.com', 'mx.example.com', '*.mx.example.com']]);
});

test('parseMtaStsPolicy: whitespace after the colon and at the line end; unknown fields ignored; any field order', () => {
  const p = parseMtaStsPolicy('max_age:86400  \nmx:\tmail.example.com\nfoo_bar.x: some value\nmode:   testing\nversion: STSv1');
  assert.deepEqual([p.valid, p.mode, p.maxAge, p.mx], [true, 'testing', 86400, ['mail.example.com']]);
  assert.deepEqual(p.extensions, [{ name: 'foo_bar.x', value: 'some value' }]);
});

test('parseMtaStsPolicy: required fields, values and the grammar', () => {
  const codes = (text) => parseMtaStsPolicy(text).issues.map((x) => x.code);
  assert.deepEqual(codes(''), ['version', 'mode', 'max-age', 'mx-missing']);
  assert.equal(parseMtaStsPolicy('').valid, false);
  assert.deepEqual(codes('version: STSv2\nmode: enforce\nmx: m.example.com\nmax_age: 1'), ['version']);
  assert.deepEqual(codes('version: STSv1\nmode: Enforce\nmx: m.example.com\nmax_age: 1'), ['mode'], 'values are case-sensitive');
  assert.deepEqual(codes('version: STSv1\nmode: enforce\nmx: m.example.com\nmax_age: -1'), ['max-age']);
  assert.deepEqual(codes('version: STSv1\nmode: enforce\nmx: m.example.com\nmax_age: 12345678901'), ['max-age'], 'at most 10 digits');
  let p = parseMtaStsPolicy('version: STSv1\nmode: enforce\nmx: m.example.com\nmax_age: 31557601');
  assert.deepEqual([p.issues[0].code, p.issues[0].params, p.valid], ['max-age-too-large', { value: '31557601', max: MTA_STS_MAX_AGE_LIMIT }, false]);
  assert.equal(parseMtaStsPolicy('version: STSv1\nmode: enforce\nmx: m.example.com\nmax_age: 31557600').valid, true, 'the limit itself');
  // mode none needs no mx
  p = parseMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 86400');
  assert.deepEqual([p.valid, p.issues], [true, []]);
  // field names are case-sensitive: "Version" is an unknown field, so version is missing
  p = parseMtaStsPolicy('Version: STSv1\nmode: enforce\nmx: m.example.com\nmax_age: 86400');
  assert.deepEqual(p.issues.map((x) => [x.code, x.params]), [['field-case', { field: 'Version', expected: 'version' }], ['version', { value: '—' }]]);
  assert.equal(p.valid, false);
  // a duplicate keeps the first value
  p = parseMtaStsPolicy('version: STSv1\nmode: testing\nmode: enforce\nmx: m.example.com\nmax_age: 86400');
  assert.deepEqual([p.mode, p.valid, p.issues[0]], ['testing', true, { code: 'duplicate', params: { field: 'mode' } }]);
  // a line that is not "key: value" breaks the grammar; a space before the colon too
  p = parseMtaStsPolicy('version: STSv1\n# comment\nmode : enforce\nmx: m.example.com\nmax_age: 86400');
  assert.deepEqual(p.issues.map((x) => x.code), ['syntax', 'syntax', 'mode']);
  assert.deepEqual(p.issues[0].params, { line: 2, text: '# comment' });
  assert.equal(p.valid, false);
  // a blank line between fields is outside the grammar, but the policy is still read
  p = parseMtaStsPolicy('version: STSv1\n\nmode: enforce\nmx: m.example.com\nmax_age: 86400\n\n');
  assert.deepEqual([p.valid, p.issues], [true, [{ code: 'blank-line', params: { line: 2 } }]]);
});

test('parseMtaStsPolicy: mx patterns must be A-label host names, optionally "*."-prefixed', () => {
  const p = parseMtaStsPolicy('version: STSv1\nmode: enforce\nmx: *.example.net\nmx: mail.example.com.\nmx: münchen.example.com\nmx: *\nmx: a.*.example.com\nmx: -bad.example.com\nmx:\nmax_age: 86400');
  assert.deepEqual(p.issues, [{ code: 'mx-invalid', params: { values: 'mail.example.com., münchen.example.com, *, a.*.example.com, -bad.example.com, ""' } }]);
  assert.equal(p.valid, true, 'one valid pattern is enough');
  const none = parseMtaStsPolicy('version: STSv1\nmode: enforce\nmx: localhost\nmax_age: 86400');
  assert.deepEqual(none.issues.map((x) => x.code), ['mx-invalid', 'mx-missing']);
  assert.equal(none.valid, false);
  assert.doesNotThrow(() => parseMtaStsPolicy(undefined));
  assert.doesNotThrow(() => parseMtaStsPolicy({ toString: () => 'x' }));
});

/* ---- reading a measurement ------------------------------------------------------------- */

test('interpretPolicyFetch: the live policy (m26) and the missing host (m27)', () => {
  const f = interpretPolicyFetch(M26.final.body, { host: HOST });
  assert.equal(f.measurementId, M26.post.body.id);
  assert.deepEqual([f.finished, f.failure, f.httpStatus, f.contentType, f.truncated], [true, null, 200, 'text/plain', false]);
  assert.match(f.body, /^version: STSv1\r\n/);
  assert.deepEqual([f.tls.authorized, f.tls.covers, f.tls.hostnames, f.tls.issuer], [true, true, ['example.com', '*.example.com'], 'Google Trust Services']);
  assert.equal(f.tls.notAfter.toISOString(), '2026-12-03T19:23:18.000Z');
  assert.deepEqual([f.probe.country, f.probe.kind, f.probe.adopted, 'latitude' in f.probe], ['JP', 'datacenter', true, false]);

  const nx = interpretPolicyFetch(M27.final.body, { host: HOST });
  assert.deepEqual([nx.finished, nx.failure, nx.tls, nx.httpStatus], [false, { kind: 'dns', text: 'queryA ENODATA mta-sts.example.com' }, null, null]);
});

test('interpretPolicyFetch: redirects, header case, coverage and garbage input', () => {
  const f = interpretPolicyFetch(measurement({ statusCode: 301, headers: { Location: 'https://www.example.com/', 'Content-Type': ['text/html'] }, rawBody: '' }), { host: HOST });
  assert.deepEqual([f.httpStatus, f.location, f.contentType], [301, 'https://www.example.com/', 'text/html']);
  const other = interpretPolicyFetch(M26.final.body, { host: 'mta-sts.example.org' });
  assert.equal(other.tls.covers, false, 'the certificate names example.com only');
  assert.equal(interpretPolicyFetch(M26.final.body).tls.covers, null, 'no host, no coverage verdict');
  for (const junk of [null, {}, { results: [] }, { results: [{}] }, 'x']) {
    const x = interpretPolicyFetch(junk);
    assert.deepEqual([x.finished, x.failure.kind], [false, 'unknown']);
  }
});

/* ---- validation ---------------------------------------------------------------------- */

test('validateMtaSts: a good enforce policy that covers every MX host', () => {
  const v = validateMtaSts({
    domain: 'example.com', fetch: policyFetch(RFC_POLICY), mxHosts: ['mail.example.com', 'mx1.example.net'],
    txt: 'v=STSv1; id=20260927', tlsRpt: 'v=TLSRPTv1; rua=mailto:tls@example.com', now: NOW
  });
  assert.deepEqual([v.headline, v.severity, v.usable, v.mode, v.host], ['ok', 'info', true, 'enforce', HOST], 'info: an unused pattern');
  assert.deepEqual(ids(v), ['tls.ok', 'mode.enforce', 'max-age.ok', 'mx.ok', 'mx.unused']);
  assert.deepEqual(v.mx, [{ host: 'mail.example.com', matchedBy: 'mail.example.com' }, { host: 'mx1.example.net', matchedBy: '*.example.net' }]);
  assert.deepEqual(v.unusedPatterns, ['backupmx.example.com']);
  assert.equal(sev(v, 'mx.unused'), 'info');
  assert.deepEqual(v.findings.find((f) => f.id === 'max-age.ok').params, { host: HOST, value: 604800, days: 7 });
});

test('validateMtaSts: the live policy (m26) against the MX hosts it was written for', () => {
  const v = validateMtaSts({ domain: 'example.com', fetch: interpretPolicyFetch(M26.final.body, { host: HOST }), mxHosts: [...MX, '.'], now: NOW });
  assert.deepEqual([v.headline, v.severity], ['ok', 'info']);
  assert.deepEqual(ids(v), ['tls.ok', 'mode.enforce', 'max-age.days', 'mx.ok', 'mx.unused'], 'max_age 86400: one day is under the weeks RFC 8461 expects');
  assert.deepEqual(v.mx.map((x) => x.matchedBy), ['mx.example.com', '*.mx.example.com'], 'the null MX "." is ignored');
});

test('validateMtaSts: an MX host missing from the policy is an error in enforce mode, a warning in testing mode', () => {
  const policy = (mode) => `version: STSv1\nmode: ${mode}\nmx: mx.example.com\nmax_age: 1209600\n`;
  let v = validateMtaSts({ domain: 'example.com', fetch: policyFetch(policy('enforce')), mxHosts: ['mx.example.com', 'backup.example.org'], now: NOW });
  assert.deepEqual([v.headline, sev(v, 'mx.unmatched')], ['problems', 'error']);
  assert.deepEqual(v.findings.find((f) => f.id === 'mx.unmatched').params, { host: HOST, hosts: 'backup.example.org', patterns: 'mx.example.com' });
  v = validateMtaSts({ domain: 'example.com', fetch: policyFetch(policy('testing')), mxHosts: ['backup.example.org'], tlsRpt: null, now: NOW });
  assert.deepEqual([v.headline, sev(v, 'mx.unmatched'), sev(v, 'mode.testing'), sev(v, 'mode.testing-no-report')], ['warnings', 'warn', 'info', 'warn']);
  // mode none: nothing to match; no MX at all: noted
  v = validateMtaSts({ domain: 'example.com', fetch: policyFetch('version: STSv1\nmode: none\nmax_age: 86400\n'), mxHosts: ['backup.example.org'], now: NOW });
  assert.deepEqual(ids(v), ['tls.ok', 'mode.none', 'max-age.ok']);
  v = validateMtaSts({ domain: 'example.com', fetch: policyFetch(policy('enforce')), mxHosts: [], now: NOW });
  assert.ok(ids(v).includes('mx.none'));
});

test('validateMtaSts: max_age thresholds and a missing TXT record', () => {
  const p = (age) => `version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: ${age}\n`;
  const check = (age) => validateMtaSts({ domain: 'example.com', fetch: policyFetch(p(age)), mxHosts: ['mx.example.com'], now: NOW });
  assert.equal(sev(check(3600), 'max-age.short'), 'warn');
  assert.equal(sev(check(86400), 'max-age.days'), 'info');
  assert.equal(sev(check(604800), 'max-age.ok'), 'ok');
  const v = validateMtaSts({ domain: 'example.com', fetch: policyFetch(p(604800)), mxHosts: ['mx.example.com'], txt: null, now: NOW });
  assert.deepEqual([v.headline, sev(v, 'txt.missing')], ['warnings', 'warn']);
  assert.equal(v.findings.find((f) => f.id === 'txt.missing').params.domain, 'example.com');
});

test('validateMtaSts: transport failures (probe results shaped like the fixtures)', () => {
  const failedWith = (rawOutput, status = 'failed') => interpretPolicyFetch(measurement({ status, statusCode: null, rawBody: null, rawOutput }, { tls: null }), { host: HOST });
  const cases = [
    ['queryA ENODATA mta-sts.example.com', 'fetch.dns', 'unreachable'],
    ['Private IP ranges are not allowed.', 'fetch.private', 'unreachable'],
    ['connect ECONNREFUSED 192.0.2.80:443', 'fetch.unreachable', 'unreachable'],
    ['Request timed out while establishing the TCP connection.', 'fetch.unreachable', 'unreachable'],
    ['Client network socket disconnected before secure TLS connection was established', 'fetch.tls-failed', 'unreachable'],
    ['something odd', 'fetch.probe', 'inconclusive']
  ];
  for (const [raw, id, headline] of cases) {
    const v = validateMtaSts({ domain: 'example.com', fetch: failedWith(raw), mxHosts: MX, now: NOW });
    assert.deepEqual([ids(v), v.headline, v.usable], [[id], headline, false], raw);
  }
  const offline = interpretPolicyFetch(measurement({ status: 'offline', statusCode: null, rawOutput: '' }, { tls: null }));
  assert.deepEqual(ids(validateMtaSts({ domain: 'example.com', fetch: offline })), ['fetch.probe']);
  assert.deepEqual(ids(validateMtaSts({ domain: 'example.com', fetch: failedWith('queryA ENODATA x'), txt: null })), ['fetch.dns', 'txt.missing']);
  assert.deepEqual(ids(validateMtaSts({ domain: 'example.com', fetch: null })), ['fetch.probe']);
});

test('validateMtaSts: the certificate (expired, wrong name, chain, self-signed, expiring soon)', () => {
  const tlsCase = (tls, host = HOST) => validateMtaSts({
    domain: host.slice('mta-sts.'.length), fetch: interpretPolicyFetch(measurement({ rawBody: RFC_POLICY }, { tls }), { host }), mxHosts: ['mail.example.com'], now: NOW
  });
  let v = tlsCase({ authorized: false, error: 'CERT_HAS_EXPIRED', expiresAt: '2026-09-01T00:00:00.000Z' });
  assert.deepEqual([ids(v), v.headline], [['tls.expired'], 'unreachable']);
  assert.equal(v.findings[0].params.date, '2026-09-01');
  v = tlsCase({ authorized: false, error: 'ERR_TLS_CERT_ALTNAME_INVALID' });
  assert.deepEqual(ids(v), ['tls.name']);
  assert.equal(v.findings[0].params.names, 'example.com, *.example.com');
  // a chain error masks the name error: coverage is worked out from the names themselves
  v = tlsCase({ authorized: false, error: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }, 'mta-sts.example.org');
  assert.deepEqual(ids(v), ['tls.name', 'tls.chain']);
  v = tlsCase({ authorized: false, error: 'DEPTH_ZERO_SELF_SIGNED_CERT' });
  assert.deepEqual(ids(v), ['tls.untrusted']);
  v = tlsCase({ authorized: false, error: 'CERT_REVOKED' });
  assert.deepEqual(ids(v), ['tls.rejected']);
  v = tlsCase({ expiresAt: new Date(NOW + 5 * 86400000).toISOString() });
  assert.deepEqual([v.headline, sev(v, 'tls.expiring'), v.findings[0].params.days], ['warnings', 'warn', 5]);
});

test('validateMtaSts: HTTP status, redirect, content type and truncation', () => {
  const run = (extra) => validateMtaSts({ domain: 'example.com', fetch: policyFetch(RFC_POLICY, extra), mxHosts: ['mail.example.com'], now: NOW });
  let v = run({ statusCode: 302, headers: { location: 'https://example.com/mta-sts.txt', 'content-type': 'text/html' } });
  assert.deepEqual([ids(v), v.headline], [['tls.ok', 'http.redirect'], 'unreachable']);
  assert.deepEqual(v.findings[1].params, { host: HOST, status: 302, location: 'https://example.com/mta-sts.txt' });
  v = run({ statusCode: 404 });
  assert.deepEqual(ids(v), ['tls.ok', 'http.status']);
  v = run({ headers: { 'content-type': 'text/html; charset=utf-8' } });
  assert.deepEqual([sev(v, 'http.content-type'), v.findings.find((f) => f.id === 'http.content-type').params.type, v.usable], ['warn', 'text/html', true]);
  v = run({ headers: { 'content-type': 'Text/Plain; charset=us-ascii' } });
  assert.ok(!ids(v).includes('http.content-type'), 'parameters and case do not matter');
  v = run({ headers: {} });
  assert.equal(v.findings.find((f) => f.id === 'http.content-type').params.type, '—');
  v = run({ truncated: true });
  assert.equal(sev(v, 'http.truncated'), 'warn');
});

test('validateMtaSts: an invalid policy stops before the MX cross-check', () => {
  const v = validateMtaSts({ domain: 'example.com', fetch: policyFetch('<html>not a policy</html>'), mxHosts: MX, txt: 'v=STSv1; id=1', now: NOW });
  assert.deepEqual([v.headline, v.usable, v.severity], ['invalid', false, 'error']);
  assert.deepEqual(ids(v), ['tls.ok', 'policy.syntax', 'policy.version', 'policy.mode', 'policy.max-age', 'policy.mx-missing']);
  assert.deepEqual(v.mx, []);
  const warnOnly = validateMtaSts({ domain: 'example.com', fetch: policyFetch(`${RFC_POLICY}max_age: 1\n`), mxHosts: ['mail.example.com'], now: NOW });
  assert.deepEqual([warnOnly.headline, sev(warnOnly, 'policy.duplicate')], ['warnings', 'warn']);
});

/* ---- i18n ---------------------------------------------------------------------------- */

test('MTA_STS_I18N: every finding has an English and a Turkish title + detail with the same placeholders; headlines too', () => {
  const ph = (s) => [...String(s).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join();
  for (const id of MTA_STS_FINDINGS) {
    for (const part of ['title', 'detail']) {
      const key = `mtasts.${id}.${part}`;
      assert.ok(MTA_STS_I18N.en[key] && MTA_STS_I18N.tr[key], key);
      assert.equal(ph(MTA_STS_I18N.en[key]), ph(MTA_STS_I18N.tr[key]), key);
    }
  }
  for (const k of MTA_STS_HEADLINES) assert.ok(MTA_STS_I18N.en[`mtasts.head.${k}`] && MTA_STS_I18N.tr[`mtasts.head.${k}`], k);
  assert.deepEqual(Object.keys(MTA_STS_I18N.en).sort(), Object.keys(MTA_STS_I18N.tr).sort());
  assert.equal(Object.keys(MTA_STS_I18N.en).length, MTA_STS_FINDINGS.length * 2 + MTA_STS_HEADLINES.length, 'no stray keys');
});

test('every placeholder a finding text uses is filled by its params', () => {
  // Drive every path once and collect what the texts would miss.
  const fetches = [
    policyFetch(RFC_POLICY), policyFetch('version: STSv1\n\nmode: testing\nmx: x.example.org\nmax_age: 60\nmode: none\n\n'),
    policyFetch('version: STSv1\nmode: enforce\nmx: x.example.org\nmax_age: 31557601\n# c\n'),
    policyFetch('Version: STSv1\nmx: bad..example.com\nmax_age: 99999999999'), policyFetch(RFC_POLICY, { statusCode: 301 }),
    policyFetch(RFC_POLICY, { statusCode: 500, headers: {} }), policyFetch(RFC_POLICY, { truncated: true, headers: { 'content-type': 'text/html' } }),
    policyFetch('version: STSv1\nmode: none\nmax_age: 86400'), policyFetch('version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\nmax_age: 5'),
    interpretPolicyFetch(measurement({ rawBody: RFC_POLICY }, { tls: { authorized: false, error: 'CERT_HAS_EXPIRED' } }), { host: 'mta-sts.example.org' }),
    interpretPolicyFetch(measurement({ rawBody: RFC_POLICY }, { tls: { authorized: false, error: 'UNABLE_TO_GET_ISSUER_CERT' } }), { host: HOST }),
    interpretPolicyFetch(measurement({ rawBody: RFC_POLICY }, { tls: { authorized: false, error: 'SELF_SIGNED_CERT_IN_CHAIN' } }), { host: HOST }),
    interpretPolicyFetch(measurement({ rawBody: RFC_POLICY }, { tls: { authorized: false, error: 'CERT_REVOKED' } }), { host: HOST }),
    interpretPolicyFetch(measurement({ rawBody: RFC_POLICY }, { tls: { expiresAt: new Date(NOW + 86400000).toISOString() } }), { host: HOST }),
    ...['queryA ENODATA x', 'Private IP ranges are not allowed.', 'connect ECONNREFUSED', 'SSL alert number 40', '?'].map((raw) => interpretPolicyFetch(measurement({ status: 'failed', statusCode: null, rawOutput: raw }, { tls: null })))
  ];
  const seen = new Set();
  for (const fetch of fetches) {
    for (const [mx, tlsRpt] of [[['mail.example.com', 'other.example.org'], null], [[], 'v=TLSRPTv1'], [['mail.example.com'], undefined]]) {
      const v = validateMtaSts({ domain: 'example.com', fetch, mxHosts: mx, txt: null, tlsRpt, now: NOW });
      for (const f of v.findings) {
        seen.add(f.id);
        for (const lang of ['en', 'tr']) {
          for (const part of ['title', 'detail']) {
            for (const m of MTA_STS_I18N[lang][`mtasts.${f.id}.${part}`].matchAll(/\{(\w+)\}/g)) {
              assert.ok(m[1] in f.params, `${f.id}.${part} (${lang}) needs {${m[1]}}`);
            }
          }
        }
      }
    }
  }
  assert.deepEqual(MTA_STS_FINDINGS.filter((id) => !seen.has(id)), [], 'every finding id is reachable');
});
