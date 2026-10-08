/**
 * ds-tls.test.js — the headless runner's `tls` command (tools/ds/tls.mjs) with `--ari`
 * (tools/ds/ari.mjs) and `--revocation` (tools/ds/revocation.mjs), and its changes
 * (tools/ds/tlsdiff.mjs): the targets and the command line; handshakes with an in-process TLS
 * server on 127.0.0.1 (tests/fixtures/crl_*: a test CA, a leaf with a CRL distribution point) —
 * trusted, untrusted, another name, the leaf alone, a closed port, a silent one, an unreachable IPv6
 * address; a fake ARI server (a window, a moved window, Retry-After, 404, a rate limit, SSL.com's
 * directory per key type); the CRLs read through a fake fetch (revoked with its reason, good, another
 * CA's, a signature that does not verify, a CRL too large, an HTML page, each URL once); every change
 * (RENEW-NOW, MOVED-UP, CA-NOTICE, REVOKED, CERT, FAILED / RECOVERED / FAILING, a DNS outage carried,
 * NXDOMAIN) and three nights of `main()` over the local server and the fakes. No request leaves the
 * machine; documentation names only.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main } from '../../tools/ds.mjs';
import { parseCommandLine, parseTlsTarget, parseTargets, UsageError, EXIT, COMMANDS, USAGE } from '../../tools/ds/args.mjs';
import { handshake, runTls, ariParts, revocationParts, tlsDoc } from '../../tools/ds/tls.mjs';
import { ARI_SERVER_DIRECTORIES, ariDirectoryFor, createAriClient, windowState, ARI_MAX_RETRY_MS } from '../../tools/ds/ari.mjs';
import { createRevocationChecker, verifyCrlSignature, issuerFromChain, fetchCrl } from '../../tools/ds/revocation.mjs';
import { diffTls, tlsTargetProblem, tlsNotes, MOVED_UP_MS } from '../../tools/ds/tlsdiff.mjs';
import { diffReports, baselineProblem, baselineNotes } from '../../tools/ds/diff.mjs';
import { setupStrings, CHANGE_TAGS, changeText } from '../../tools/ds/render.mjs';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { parseCrl } from '../../assets/js/lib/crl.js';
import { ariCertId } from '../../assets/js/lib/renewalplan.js';
import { renderMarkdown } from '../../assets/js/lib/summary.js';
import { createFakeFetch } from './ds-fake-doh.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIX = join(ROOT, 'tests', 'fixtures');
const read = (f) => readFileSync(join(FIX, f));
const certOf = (f) => parseCertificates(read(f)).certificates[0];
const CA_PEM = read('crl_ca.pem');
const LEAF_PEM = read('crl_leaf.pem');
const LEAF_KEY = read('crl_leaf.key');
const CA = certOf('crl_ca.pem');
const LEAF = certOf('crl_leaf.pem');
const LEAF2 = certOf('crl_leaf2.pem');
const OTHER_CA = certOf('crl_other_ca.pem');
const DP = 'http://crl.example.com/test-ca.crl';
const AT = (s) => new Date(s);
const NOW = AT('2026-10-09T03:00:00Z');

/** An in-process TLS server on 127.0.0.1 that completes the handshake and closes. */
async function tlsServer({ cert = Buffer.concat([LEAF_PEM, CA_PEM]), key = LEAF_KEY } = {}) {
  const server = tls.createServer({ key, cert }, (s) => {
    s.on('error', () => {});
    s.end();
  });
  server.on('tlsClientError', () => {});
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { port: server.address().port, close: () => new Promise((resolve) => server.close(resolve)) };
}

/** A fetch from routes (url → [status, body, headers] or a function), recording each call; other URLs: 404. */
function routesFetch(routes, calls = []) {
  const impl = async (url) => {
    calls.push(String(url));
    const route = routes[String(url)];
    if (!route) return new Response('not found', { status: 404 });
    if (typeof route === 'function') return route();
    const [status, body, headers = {}] = route;
    const payload = body instanceof Uint8Array || Buffer.isBuffer(body) ? body : typeof body === 'string' ? body : JSON.stringify(body);
    return new Response(payload, { status, headers });
  };
  impl.calls = calls;
  return impl;
}

/** The fixture CRL with one byte of its CRL number changed: it parses, its signature does not verify. */
function tamperedCrl() {
  const bytes = Buffer.from(read('crl_empty.der'));
  const at = bytes.indexOf(Buffer.from([0x55, 0x1d, 0x14, 0x04, 0x03, 0x02, 0x01]));
  assert.ok(at > 0, 'the CRL number extension');
  bytes[at + 7] ^= 0x01;
  return bytes;
}

/* ------------------------------------------------------------------------ */
/* Targets and the command line                                             */
/* ------------------------------------------------------------------------ */

test('tls targets: a host, a port, IPv6 in brackets, an address, an https URL; nothing else', () => {
  const cases = {
    'www.example.com': { target: 'www.example.com', host: 'www.example.com', address: null, port: 443 },
    'Example.COM.:8443': { target: 'example.com:8443', host: 'example.com', address: null, port: 8443 },
    'https://example.org:8443/path?q=1': { target: 'example.org:8443', host: 'example.org', address: null, port: 8443 },
    'https://example.org/': { target: 'example.org', host: 'example.org', address: null, port: 443 },
    '[2001:DB8::1]:8443': { target: '[2001:db8::1]:8443', host: null, address: '2001:db8::1', port: 8443 },
    '2001:db8::10': { target: '[2001:db8::10]', host: null, address: '2001:db8::10', port: 443 },
    '192.0.2.10:443': { target: '192.0.2.10', host: null, address: '192.0.2.10', port: 443 }
  };
  for (const [token, want] of Object.entries(cases)) assert.deepEqual(parseTlsTarget(token), want, token);
  for (const bad of ['', 'http://example.com', 'example.com:0', 'example.com:65536', 'example.com:http', '*.example.com', '010.0.0.1', '127.1', '0x7f.1',
    '[192.0.2.1]:443', 'a b', 'host!', 'example.com:8443:1', null, undefined]) {
    assert.equal(parseTlsTarget(bad), null, String(bad));
  }
  assert.deepEqual(parseTargets('tls', ['example.com', 'EXAMPLE.com:443', 'bad host', 'example.com:8443']), {
    targets: ['example.com', 'example.com:8443'], invalid: ['bad host']
  });
});

test('the tls command line: --ari and --revocation are its own, a bad target is a usage error', () => {
  assert.ok(COMMANDS.includes('tls'));
  assert.match(USAGE, /\n {2}tls HOST\[:PORT\]\.\.\. /);
  const cl = parseCommandLine(['tls', 'www.example.com', 'example.com:8443', '--ari', '--revocation']);
  assert.deepEqual([cl.command, cl.targets, cl.options.ari, cl.options.revocation], ['tls', ['www.example.com', 'example.com:8443'], true, true]);
  const plain = parseCommandLine(['tls', '--list', 'hosts.txt']);
  assert.deepEqual([plain.options.ari, plain.options.revocation, plain.options.lists], [false, false, ['hosts.txt']]);
  assert.throws(() => parseCommandLine(['health', 'example.com', '--ari']), /--ari applies to tls only, not to health/);
  assert.throws(() => parseCommandLine(['tls']), /tls needs at least one host \(or --list FILE\)/);
  assert.throws(() => parseCommandLine(['tls', 'not a host']), (err) => err instanceof UsageError && /not a host name or address, with an optional port/.test(err.message));
});

/* ------------------------------------------------------------------------ */
/* Handshakes                                                               */
/* ------------------------------------------------------------------------ */

describe('handshakes with a local TLS server', () => {
  let full;
  let alone;
  before(async () => {
    full = await tlsServer();
    alone = await tlsServer({ cert: LEAF_PEM });
  });
  after(async () => {
    await full.close();
    await alone.close();
  });

  test('trusted with the test CA, the chain as sent, the name checked', async () => {
    const h = await handshake({ address: '127.0.0.1', port: full.port, servername: 'www.example.com', ca: [CA_PEM] });
    assert.equal(h.status, 'OK');
    assert.equal(h.authorized, true);
    assert.equal(h.authorizationError, null);
    assert.equal(h.nameMatch, true);
    assert.match(h.protocol, /^TLSv1\.[23]$/);
    assert.equal(h.chain.length, 2, 'the leaf and the CA it was sent with');
    assert.deepEqual(Buffer.from(h.chain[0]), Buffer.from(LEAF.der));
    const other = await handshake({ address: '127.0.0.1', port: full.port, servername: 'mail.example.org', ca: [CA_PEM] });
    assert.equal(other.nameMatch, false, 'checked although the chain is trusted');
    const untrusted = await handshake({ address: '127.0.0.1', port: full.port, servername: 'www.example.com' });
    assert.equal(untrusted.authorized, false);
    assert.ok(untrusted.authorizationError, 'Node says why');
    const lone = await handshake({ address: '127.0.0.1', port: alone.port, servername: 'example.com', ca: [CA_PEM] });
    assert.equal(lone.chain.length >= 1, true);
    const none = await handshake({ address: '127.0.0.1', port: full.port, servername: null, ca: [CA_PEM] });
    assert.equal(none.nameMatch, null, 'an address target asks no name');
  });

  test('a closed port, a silent one, an unreachable IPv6 address, an abort', async () => {
    const probe = net.createServer();
    await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const closedPort = probe.address().port;
    await new Promise((resolve) => probe.close(resolve));
    const closed = await handshake({ address: '127.0.0.1', port: closedPort, servername: 'www.example.com' });
    assert.ok(['CLOSED', 'TIMEOUT'].includes(closed.status), closed.status);
    const silent = net.createServer(() => {});
    await new Promise((resolve) => silent.listen(0, '127.0.0.1', resolve));
    const quiet = await handshake({ address: '127.0.0.1', port: silent.address().port, servername: 'www.example.com', timeoutMs: 200 });
    assert.deepEqual([quiet.status, quiet.error], ['TIMEOUT', 'no answer within 0 s']);
    silent.close();
    const unreachable = () => {
      const s = new EventEmitter();
      s.destroy = () => {};
      setImmediate(() => s.emit('error', Object.assign(new Error('connect ENETUNREACH 2001:db8::10:443'), { code: 'ENETUNREACH' })));
      return s;
    };
    assert.deepEqual(await handshake({ address: '2001:db8::10', port: 443, servername: 'www.example.com', connect: unreachable }), { status: 'SKIPPED', error: 'no-ipv6-route' });
    assert.equal((await handshake({ address: '192.0.2.10', port: 443, servername: 'www.example.com', connect: unreachable })).status, 'CLOSED', 'IPv4: a failure');
    const controller = new AbortController();
    const pending = handshake({ address: '2001:db8::10', port: 443, servername: 'www.example.com', connect: () => Object.assign(new EventEmitter(), { destroy() {} }), signal: controller.signal });
    controller.abort();
    await assert.rejects(pending, { name: 'AbortError' });
  });
});

/* ------------------------------------------------------------------------ */
/* Revocation                                                               */
/* ------------------------------------------------------------------------ */

test('a CRL signature verifies with its issuer’s key (ECDSA and RSA), not with another’s or when changed', () => {
  const empty = parseCrl(read('crl_empty.der'));
  const other = parseCrl(read('crl_other.der'));
  assert.equal(verifyCrlSignature(empty, CA), 'verified');
  assert.equal(verifyCrlSignature(other, OTHER_CA), 'verified', 'RSA, SHA-256');
  assert.equal(verifyCrlSignature(empty, OTHER_CA), 'failed', 'another key');
  assert.equal(verifyCrlSignature(other, CA), 'failed', 'an EC key for an RSA signature');
  assert.equal(verifyCrlSignature(parseCrl(tamperedCrl()), CA), 'failed', 'one byte of the signed part changed');
  assert.equal(verifyCrlSignature({ ...empty, scheme: null }, CA), 'unsupported');
  assert.equal(verifyCrlSignature(empty, { spkiDer: new Uint8Array([1, 2, 3]) }), 'unsupported');
  assert.equal(issuerFromChain(LEAF, [LEAF, CA]), CA);
  assert.equal(issuerFromChain(LEAF, [LEAF]), null);
  assert.equal(issuerFromChain(LEAF, [LEAF, OTHER_CA]), null, 'not the issuer');
  assert.equal(issuerFromChain(LEAF, [LEAF, { ...CA, subjectKeyId: 'ab'.repeat(20) }]), null, 'the same name, another key');
});

test('revocation: revoked with its reason, good, another CA’s CRL, a bad signature; each CRL read once', async () => {
  const at = () => NOW;
  const revoked = createRevocationChecker({ fetchImpl: routesFetch({ [DP]: [200, read('crl_revoked.der'), { 'content-type': 'application/pkix-crl' }] }), now: at });
  const got = await revoked.check([{ key: 'a', cert: LEAF, chain: [LEAF, CA] }, { key: 'b', cert: LEAF2, chain: [LEAF2] }]);
  assert.equal(revoked.downloads(), 1, 'one download for both certificates');
  assert.deepEqual(got.get('a'), {
    status: 'revoked', reason: 'keyCompromise', reasonCode: 1, time: '2026-09-01T12:00:00.000Z', crl: DP, checkedAt: NOW.toISOString(),
    thisUpdate: '2026-10-01T00:00:00.000Z', nextUpdate: '2026-10-15T00:00:00.000Z', signature: 'verified', signatureNote: null, error: null
  });
  const b = got.get('b');
  assert.deepEqual([b.status, b.reason, b.signature, b.signatureNote], ['revoked', 'superseded', 'not-verified', 'issuer-not-sent'], 'the leaf alone: the status stands, unverified');

  const good = await createRevocationChecker({ fetchImpl: routesFetch({ [DP]: [200, read('crl_empty.der')] }), now: at }).check([{ key: 'a', cert: LEAF, chain: [LEAF, CA] }]);
  assert.deepEqual([good.get('a').status, good.get('a').signature, good.get('a').error], ['good', 'verified', null]);
  const stale = await createRevocationChecker({ fetchImpl: routesFetch({ [DP]: [200, read('crl_empty.der')] }), now: () => AT('2026-10-20T00:00:00Z') })
    .check([{ key: 'a', cert: LEAF, chain: [LEAF, CA] }]);
  assert.deepEqual([stale.get('a').status, stale.get('a').error], ['unknown', 'stale']);
  const other = await createRevocationChecker({ fetchImpl: routesFetch({ [DP]: [200, read('crl_other.der')] }), now: at }).check([{ key: 'a', cert: LEAF, chain: [LEAF, CA] }]);
  assert.deepEqual([other.get('a').status, other.get('a').error], ['unknown', 'issuer-mismatch'], 'the same serial on another CA’s CRL is no revocation');
  const forged = await createRevocationChecker({ fetchImpl: routesFetch({ [DP]: [200, tamperedCrl()] }), now: at }).check([{ key: 'a', cert: LEAF, chain: [LEAF, CA] }]);
  assert.deepEqual([forged.get('a').status, forged.get('a').signature, forged.get('a').error], ['unknown', 'failed', 'bad-signature']);
});

test('revocation: no CRL, a CRL too large, an HTTP error, an HTML page, a timeout; the next URL is tried', async () => {
  const at = () => NOW;
  const item = { key: 'a', cert: LEAF, chain: [LEAF, CA] };
  const noCrl = await createRevocationChecker({ fetchImpl: routesFetch({}), now: at }).check([{ key: 'a', cert: { ...LEAF, crlUrls: ['ldap://ldap.example.com/cn=x'] }, chain: [] }]);
  assert.deepEqual([noCrl.get('a').status, noCrl.get('a').error, noCrl.get('a').crl], ['unknown', 'no-crl', null]);
  const big = await createRevocationChecker({ fetchImpl: routesFetch({ [DP]: [200, read('crl_revoked.der')] }), now: at, maxBytes: 100 }).check([item]);
  assert.equal(big.get('a').error, 'too-large');
  const declared = await fetchCrl(DP, { fetchImpl: routesFetch({ [DP]: [200, 'x', { 'content-length': '999999999' }] }), maxBytes: 1000 });
  assert.deepEqual([declared.ok, declared.error], [false, 'too-large'], 'refused by its Content-Length');
  const missing = await createRevocationChecker({ fetchImpl: routesFetch({}), now: at }).check([item]);
  assert.deepEqual([missing.get('a').error, missing.get('a').crl], ['http', DP]);
  const html = await createRevocationChecker({ fetchImpl: routesFetch({ [DP]: [200, '<!doctype html><title>Moved</title>'] }), now: at }).check([item]);
  assert.equal(html.get('a').error, 'parse');
  const stall = (url, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason)));
  const slow = await createRevocationChecker({ fetchImpl: stall, now: at, timeoutMs: 20 }).check([item]);
  assert.equal(slow.get('a').error, 'timeout');
  const second = 'http://crl2.example.com/test-ca.crl';
  const fallback = await createRevocationChecker({ fetchImpl: routesFetch({ [DP]: [200, read('crl_revoked.der')] }), now: at })
    .check([{ key: 'a', cert: { ...LEAF, crlUrls: [second, DP] }, chain: [LEAF, CA] }]);
  assert.deepEqual([fallback.get('a').status, fallback.get('a').crl], ['revoked', DP], 'the first URL failed, the second answered');
  // a partition read from another URL than the one it says it is covers other certificates
  const elsewhere = await createRevocationChecker({ fetchImpl: routesFetch({ [second]: [200, read('crl_revoked.der')] }), now: at })
    .check([{ key: 'a', cert: { ...LEAF, crlUrls: [second] }, chain: [LEAF, CA] }]);
  assert.deepEqual([elsewhere.get('a').status, elsewhere.get('a').error], ['unknown', 'scope']);
});

/* ------------------------------------------------------------------------ */
/* ARI                                                                      */
/* ------------------------------------------------------------------------ */

const DIR = 'https://acme.example.org/directory';
const RI = 'https://acme.example.org/renewal-info';
const TEST_DIRS = Object.freeze({ letsencrypt: [{ url: DIR, hosts: ['acme.example.org'] }] });
const LEAF_ID = ariCertId(LEAF);
const windowOf = (start, end, extra = {}) => ({ suggestedWindow: { start, end }, ...extra });

test('the ARI table: the five CAs, SSL.com by key type, nothing for a CA without ARI', () => {
  assert.deepEqual(Object.keys(ARI_SERVER_DIRECTORIES), ['letsencrypt', 'google', 'zerossl', 'sectigo', 'sslcom']);
  assert.equal(ariDirectoryFor('letsencrypt').url, 'https://acme-v02.api.letsencrypt.org/directory');
  assert.deepEqual(ariDirectoryFor('zerossl').hosts, ['ari.trust-provider.com']);
  assert.deepEqual(ariDirectoryFor('sectigo').hosts, ['ari.sectigo.com']);
  assert.equal(ariDirectoryFor('sslcom', 'RSA').url, 'https://acme.ssl.com/sslcom-dv-rsa');
  assert.equal(ariDirectoryFor('sslcom', 'EC').url, 'https://acme.ssl.com/sslcom-dv-ecc');
  assert.equal(ariDirectoryFor('sslcom', 'Ed25519'), null);
  for (const none of ['digicert', 'globalsign', null, 'constructor']) assert.equal(ariDirectoryFor(none), null, String(none));
  assert.ok(Object.isFrozen(ARI_SERVER_DIRECTORIES) && Object.isFrozen(ARI_SERVER_DIRECTORIES.sslcom[0].hosts));
  // the CLI asks the same directories
  const cli = readFileSync(join(ROOT, 'cli', 'ssl_origin_scan.py'), 'utf8');
  for (const list of Object.values(ARI_SERVER_DIRECTORIES)) {
    for (const e of list) {
      assert.ok(cli.includes(`'${e.url}'`), `the CLI's table has ${e.url}`);
      for (const host of e.hosts) assert.ok(cli.includes(`'${host}'`), `the CLI's table has ${host}`);
    }
  }
});

test('ARI: the window with Retry-After, each certificate once, 404 is not-found, unsupported CAs ask nothing', async () => {
  const fetchImpl = routesFetch({
    [DIR]: [200, { renewalInfo: RI }],
    [`${RI}/${LEAF_ID}`]: [200, windowOf('2026-11-01T00:00:00Z', '2026-11-03T00:00:00Z'), { 'retry-after': '21600' }],
    [`${RI}/${ariCertId(LEAF2)}`]: [404, { type: 'urn:ietf:params:acme:error:malformed' }]
  });
  const client = createAriClient({ fetchImpl, now: () => NOW, directories: TEST_DIRS, caOf: () => 'letsencrypt' });
  const a = await client.check(LEAF);
  assert.deepEqual(a, {
    ca: 'letsencrypt', certId: LEAF_ID, start: '2026-11-01T00:00:00.000Z', end: '2026-11-03T00:00:00.000Z', explanationURL: null,
    checkedAt: NOW.toISOString(), retryAfter: '2026-10-09T09:00:00.000Z', status: 200, error: null
  });
  assert.equal(await client.check(LEAF), a, 'asked once');
  const nf = await client.check(LEAF2);
  assert.deepEqual([nf.error, nf.status, nf.start], ['not-found', 404, null]);
  assert.deepEqual(fetchImpl.calls, [DIR, `${RI}/${LEAF_ID}`, `${RI}/${ariCertId(LEAF2)}`]);
  assert.equal(client.requests(), 2);
  const none = createAriClient({ fetchImpl: routesFetch({}), now: () => NOW });
  assert.deepEqual([(await none.check(LEAF)).error, (await none.check(LEAF)).ca], ['unsupported', null], 'the test CA is no CA with ARI');
  const noKey = await createAriClient({ fetchImpl: routesFetch({}), now: () => NOW, directories: TEST_DIRS, caOf: () => 'letsencrypt' }).check({ ...LEAF, authorityKeyId: null });
  assert.equal(noKey.error, 'no-key-id');
});

test('ARI: not asked before the last answer’s Retry-After; a rate limit benches the CA for the run', async () => {
  const calls = [];
  const fetchImpl = routesFetch({
    [DIR]: [200, { renewalInfo: RI }],
    [`${RI}/${LEAF_ID}`]: [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'retry-after': '120' }]
  }, calls);
  const prev = { ca: 'letsencrypt', certId: LEAF_ID, start: '2026-11-01T00:00:00.000Z', end: '2026-11-03T00:00:00.000Z', explanationURL: null, checkedAt: '2026-10-09T01:00:00.000Z', retryAfter: '2026-10-09T07:00:00.000Z', status: 200, error: null };
  const carried = await createAriClient({ fetchImpl, now: () => NOW, directories: TEST_DIRS, caOf: () => 'letsencrypt' }).check(LEAF, { prev });
  assert.deepEqual(carried, { ...prev, carried: { from: '2026-10-09T01:00:00.000Z' } });
  assert.deepEqual(calls, [], 'nothing sent before the Retry-After');
  const late = createAriClient({ fetchImpl, now: () => AT('2026-10-09T08:00:00Z'), directories: TEST_DIRS, caOf: () => 'letsencrypt' });
  const limited = await late.check(LEAF, { prev });
  assert.deepEqual([limited.error, limited.status, limited.retryAfter], ['rate-limit', 429, '2026-10-09T08:02:00.000Z']);
  const benched = await late.check(LEAF2);
  assert.deepEqual([benched.error, benched.retryAfter, !!benched.carried], ['rate-limit', '2026-10-09T08:02:00.000Z', true], 'the CA is not asked again in this run');
  assert.equal(calls.filter((u) => u.startsWith(RI)).length, 1);
  // a Retry-After of a year is cut to a week
  const far = await createAriClient({ fetchImpl: routesFetch({ [DIR]: [200, { renewalInfo: RI }], [`${RI}/${LEAF_ID}`]: [200, windowOf('2026-11-01T00:00:00Z', '2026-11-03T00:00:00Z'), { 'retry-after': String(365 * 86400) }] }), now: () => NOW, directories: TEST_DIRS, caOf: () => 'letsencrypt' }).check(LEAF);
  assert.equal(Date.parse(far.retryAfter) - NOW.getTime(), ARI_MAX_RETRY_MS);
});

test('the window’s state: before, open, past', () => {
  const ari = { start: '2026-11-01T00:00:00.000Z', end: '2026-11-03T00:00:00.000Z' };
  assert.equal(windowState(ari, Date.parse('2026-10-31T23:59:59Z')), 'before');
  assert.equal(windowState(ari, Date.parse('2026-11-01T00:00:00Z')), 'open');
  assert.equal(windowState(ari, Date.parse('2026-11-03T00:00:00Z')), 'open');
  assert.equal(windowState(ari, Date.parse('2026-11-03T00:00:01Z')), 'past');
  assert.equal(windowState({ start: null, end: null }, 0), null);
  assert.equal(windowState(null, 0), null);
});

/* ------------------------------------------------------------------------ */
/* Changes                                                                  */
/* ------------------------------------------------------------------------ */

const cert = (sha, extra = {}) => ({ sha256: sha.repeat(64).slice(0, 64), serialHex: '0c1001', subject: 'www.example.com', issuer: 'CN=Example CA', ca: 'Example CA', caId: 'letsencrypt', names: ['www.example.com', 'example.com'], notBefore: '2026-09-01T00:00:00.000Z', notAfter: '2026-11-30T00:00:00.000Z', daysLeft: 52, keyType: 'EC', keyBits: 256, curve: 'P-256', authorityKeyId: 'ab', crlUrls: [DP], ...extra });
const ariOf = (start, end, extra = {}) => ({ ca: 'letsencrypt', certId: 'x.y', start, end, explanationURL: null, checkedAt: '2026-10-08T03:00:00.000Z', retryAfter: null, status: 200, error: null, ...extra });
const ep = (address, status, extra = {}) => ({ address, family: address.includes(':') ? 6 : 4, port: 443, status, error: null, ...extra });
const report = (targets, startedAt = '2026-10-09T03:00:00.000Z', options = { ari: true, revocation: true }) => ({ tool: 'domainscope-ds', version: '1.0.0', command: 'tls', startedAt, options, targets });
const tgt = (endpoints, extra = {}) => ({ target: 'www.example.com', host: 'www.example.com', port: 443, checkedAt: '2026-10-09T03:00:00.000Z', dns: { status: 'NOERROR', ipv4: [], ipv6: [], cnames: [], error: null }, endpoints, ...extra });

test('changes: RENEW-NOW, MOVED-UP, CA-NOTICE and REVOKED, counted; said once', async () => {
  const t = await setupStrings();
  const c = cert('a');
  const before = report([tgt([ep('192.0.2.10', 'OK', { cert: c, ari: ariOf('2026-11-01T00:00:00.000Z', '2026-11-03T00:00:00.000Z'), revocation: { status: 'good' } })], { checkedAt: '2026-10-08T03:00:00.000Z' })], '2026-10-08T03:00:00.000Z');
  const moved = ariOf('2026-10-08T12:00:00.000Z', '2026-10-10T00:00:00.000Z', { checkedAt: '2026-10-09T03:00:00.000Z', explanationURL: 'https://status.example.org/incident' });
  const after = report([tgt([ep('192.0.2.10', 'OK', { cert: c, ari: moved, revocation: { status: 'revoked', reason: 'keyCompromise', time: '2026-10-09T01:00:00.000Z' } })])]);
  assert.equal(baselineProblem(before, 'tls'), null);
  const changes = diffReports('tls', before, after, { t });
  assert.deepEqual(changes.map((x) => [x.tag, x.tone, x.counts]), [['RENEW-NOW', 'bad', true], ['MOVED-UP', 'bad', true], ['CA-NOTICE', 'bad', true], ['REVOKED', 'bad', true]]);
  assert.match(changeText(changes[0]), /^www\.example\.com: www\.example\.com \(Example CA, expires 2026-11-30\): the CA's renewal window opened \(2026-10-08 – 2026-10-10\): renew it now$/);
  assert.match(changeText(changes[1]), /moved its renewal window 24 days earlier \(starts 2026-10-08, was 2026-11-01\), as CAs do before a mass revocation/);
  assert.match(changeText(changes[2]), /the CA explains its renewal window: https:\/\/status\.example\.org\/incident$/);
  assert.match(changeText(changes[3]), /revoked by its CA on 2026-10-09 \(keyCompromise\), still served$/);
  assert.ok(['RENEW-NOW', 'MOVED-UP', 'CA-NOTICE'].every((tag) => CHANGE_TAGS.includes(tag) && tag.length <= 9));
  // the night after: nothing new
  const again = report([tgt([ep('192.0.2.10', 'OK', { cert: c, ari: { ...moved, checkedAt: '2026-10-10T03:00:00.000Z' }, revocation: { status: 'revoked', reason: 'keyCompromise', time: '2026-10-09T01:00:00.000Z' } })], { checkedAt: '2026-10-09T23:00:00.000Z' })]);
  assert.deepEqual(diffTls(after, again), []);
  // the window ends with the certificate still served: RENEW-NOW again, the renewal overdue
  const past = report([tgt([ep('192.0.2.10', 'OK', { cert: c, ari: { ...moved, checkedAt: '2026-10-11T03:00:00.000Z' }, revocation: { status: 'revoked' } })], { checkedAt: '2026-10-11T03:00:00.000Z' })]);
  const overdue = diffTls(after, past);
  assert.deepEqual(overdue.map((x) => x.tag), ['RENEW-NOW']);
  assert.match(changeText(overdue[0]), /window ended on 2026-10-10: the renewal is overdue$/);
});

test('changes: a window moved by less than a day, later, or a Google-like fixed explanation are no change; a first read in the window is', () => {
  const c = cert('a');
  const before = report([tgt([ep('192.0.2.10', 'OK', { cert: c, ari: ariOf('2026-11-01T00:00:00.000Z', '2026-11-03T00:00:00.000Z', { explanationURL: 'https://status.example.org/' }) })], { checkedAt: '2026-10-08T03:00:00.000Z' })]);
  const near = report([tgt([ep('192.0.2.10', 'OK', { cert: c, ari: ariOf(new Date(Date.parse('2026-11-01T00:00:00Z') - MOVED_UP_MS + 60000).toISOString(), '2026-11-03T00:00:00.000Z', { explanationURL: 'https://status.example.org/' }) })])]);
  assert.deepEqual(diffTls(before, near), []);
  const later = report([tgt([ep('192.0.2.10', 'OK', { cert: c, ari: ariOf('2026-11-05T00:00:00.000Z', '2026-11-07T00:00:00.000Z', { explanationURL: 'https://status.example.org/' }) })])]);
  assert.deepEqual(diffTls(before, later), []);
  // a renewed certificate from the same CA keeps the CA's fixed explanation: no CA-NOTICE
  const renewed = cert('b');
  const next = report([tgt([ep('192.0.2.10', 'OK', { cert: renewed, ari: ariOf('2027-01-01T00:00:00.000Z', '2027-01-03T00:00:00.000Z', { explanationURL: 'https://status.example.org/' }) })])]);
  assert.deepEqual(diffTls(before, next).map((x) => [x.tag, x.counts]), [['CERT', false]], 'a renewal: listed only');
  // a certificate first seen inside its window (no earlier answer) is RENEW-NOW
  const first = report([tgt([ep('192.0.2.10', 'OK', { cert: renewed, ari: ariOf('2026-10-01T00:00:00.000Z', '2026-10-20T00:00:00.000Z') })])]);
  assert.deepEqual(diffTls(before, first).map((x) => x.tag), ['CERT', 'RENEW-NOW']);
  // an ARI error is no window: nothing about it
  const failed = report([tgt([ep('192.0.2.10', 'OK', { cert: c, ari: ariOf(null, null, { error: 'timeout', status: null }) })])]);
  assert.deepEqual(diffTls(before, failed), []);
});

test('changes: RENEW-NOW is said once for a window the baseline saw open, whenever the CA was last asked', () => {
  const c = cert('a');
  const W = ['2026-10-09T05:00:00.000Z', '2026-10-12T00:00:00.000Z'];
  const asked = (at) => ariOf(...W, { checkedAt: at, retryAfter: new Date(Date.parse(at) + 6 * 3600000).toISOString() });
  const night = (at, endpoint, extra = {}) => report([tgt([endpoint], { checkedAt: at, ...extra })], at);
  // 03:00 asked (the window opens at 05:00), 06:00 the answer carried (before its Retry-After), 03:00 the next day asked again
  const n1 = night('2026-10-09T03:00:00.000Z', ep('192.0.2.10', 'OK', { cert: c, ari: asked('2026-10-09T03:00:00.000Z') }));
  const n2 = night('2026-10-09T06:00:00.000Z', ep('192.0.2.10', 'OK', { cert: c, ari: { ...asked('2026-10-09T03:00:00.000Z'), carried: { from: '2026-10-09T03:00:00.000Z' } } }));
  const n3 = night('2026-10-10T03:00:00.000Z', ep('192.0.2.10', 'OK', { cert: c, ari: asked('2026-10-10T03:00:00.000Z') }));
  assert.deepEqual(diffTls(n1, n2).map((x) => x.tag), ['RENEW-NOW'], 'the window opened between the two runs');
  assert.deepEqual(diffTls(n2, n3), [], 'the baseline served it with its window open: no RENEW-NOW again');
  // an endpoint that did not answer: its last good run is when the window was last seen
  const down = (at, lastGood) => night(at, ep('192.0.2.10', 'TIMEOUT', { error: 'no answer within 10 s', lastGood }));
  const seenOpen = down('2026-10-10T03:00:00.000Z', { at: '2026-10-09T06:00:00.000Z', cert: c, ari: n2.targets[0].endpoints[0].ari });
  assert.deepEqual(diffTls(seenOpen, n3).map((x) => x.tag), ['RECOVERED'], 'its last good run already saw the window open');
  const early = night('2026-10-08T03:00:00.000Z', ep('192.0.2.10', 'OK', { cert: c, ari: asked('2026-10-08T03:00:00.000Z') }));
  const seenBefore = down('2026-10-10T03:00:00.000Z', { at: '2026-10-08T03:00:00.000Z', cert: c, ari: early.targets[0].endpoints[0].ari });
  assert.deepEqual(diffTls(seenBefore, n3).map((x) => x.tag), ['RECOVERED', 'RENEW-NOW'], 'the window opened while the endpoint was down');
  // a DNS outage carries the endpoints of the last check: compared as of that check
  const outage = night('2026-10-10T03:00:00.000Z', early.targets[0].endpoints[0], {
    dns: { status: 'SERVFAIL', ipv4: [], ipv6: [], cnames: [], error: 'x' }, carried: { from: '2026-10-08T03:00:00.000Z' }
  });
  assert.deepEqual(diffTls(outage, n3).map((x) => x.tag), ['RECOVERED', 'RENEW-NOW'], 'the window opened during the outage');
  // one certificate on two endpoints, one of them down: the newest record of it is the baseline's
  const moved = ariOf('2026-10-09T12:00:00.000Z', '2026-10-11T00:00:00.000Z', { checkedAt: '2026-10-10T03:00:00.000Z' });
  const both = report([tgt([ep('192.0.2.10', 'TIMEOUT', { lastGood: { at: '2026-10-08T03:00:00.000Z', cert: c, ari: ariOf('2026-11-01T00:00:00.000Z', '2026-11-03T00:00:00.000Z') } }),
    ep('192.0.2.11', 'OK', { cert: c, ari: moved })], { checkedAt: '2026-10-10T03:00:00.000Z' })], '2026-10-10T03:00:00.000Z');
  const back = report([tgt([ep('192.0.2.10', 'OK', { cert: c, ari: { ...moved, checkedAt: '2026-10-10T12:00:00.000Z' } }),
    ep('192.0.2.11', 'OK', { cert: c, ari: { ...moved, checkedAt: '2026-10-10T12:00:00.000Z' } })], { checkedAt: '2026-10-10T12:00:00.000Z' })], '2026-10-10T12:00:00.000Z');
  assert.deepEqual(diffTls(both, back).map((x) => x.tag), ['RECOVERED'], 'no MOVED-UP or RENEW-NOW again from the older record');
});

test('changes: a target new to the list says NEW, and RENEW-NOW and REVOKED for what it serves', () => {
  const c = cert('a');
  const old = { ...tgt([ep('192.0.2.1', 'OK', { cert: cert('b') })]), target: 'old.example.com', host: 'old.example.com' };
  const before = report([old], '2026-10-08T03:00:00.000Z');
  const added = tgt([ep('192.0.2.10', 'OK', { cert: c, ari: ariOf('2026-10-01T00:00:00.000Z', '2026-10-20T00:00:00.000Z', { checkedAt: '2026-10-09T03:00:00.000Z' }),
    revocation: { status: 'revoked', reason: 'keyCompromise', time: '2026-10-05T00:00:00.000Z' } })]);
  const after = report([old, added]);
  assert.deepEqual(diffTls(before, after).map((x) => [x.tag, x.counts]), [['NEW', true], ['RENEW-NOW', true], ['REVOKED', true]]);
  assert.deepEqual(diffTls(after, report([old, { ...added, checkedAt: '2026-10-10T03:00:00.000Z' }], '2026-10-10T03:00:00.000Z')), [], 'said once');
  const quiet = tgt([ep('192.0.2.10', 'OK', { cert: c, ari: ariOf('2026-11-01T00:00:00.000Z', '2026-11-03T00:00:00.000Z'), revocation: { status: 'good' } })]);
  assert.deepEqual(diffTls(before, report([old, quiet])).map((x) => x.tag), ['NEW'], 'a window not open yet and a good CRL: NEW only');
});

test('changes: CERT counted when a name goes or the key type or CA changes; handshake failures; SKIPPED never', () => {
  const c = cert('a');
  const base = report([tgt([ep('192.0.2.10', 'OK', { cert: c }), ep('192.0.2.11', 'OK', { cert: c }), ep('2001:db8::10', 'SKIPPED', { error: 'no-ipv6-route' })])], '2026-10-08T03:00:00.000Z');
  const rsa = cert('b', { keyType: 'RSA', keyBits: 2048, curve: null, names: ['www.example.com'] });
  const after = report([tgt([ep('192.0.2.10', 'OK', { cert: rsa }), ep('192.0.2.11', 'TIMEOUT', { error: 'no answer within 10 s' }), ep('2001:db8::10', 'SKIPPED', { error: 'no-ipv6-route' })])]);
  const changes = diffTls(base, after);
  assert.deepEqual(changes.map((x) => [x.tag, x.tone, x.counts]), [['CERT', 'bad', true], ['FAILED', 'bad', true]]);
  assert.match(changeText(changes[0]), /another certificate: .* — no longer covers example\.com; key type EC → RSA$/);
  // the night after: the silent endpoint carried its last certificate; it answers again with the new one
  const carried = { ...after.targets[0].endpoints[1], lastGood: { at: '2026-10-08T03:00:00.000Z', cert: c } };
  const night2 = report([tgt([after.targets[0].endpoints[0], carried, after.targets[0].endpoints[2]])]);
  const night3 = report([tgt([ep('192.0.2.10', 'OK', { cert: rsa }), ep('192.0.2.11', 'OK', { cert: rsa }), ep('2001:db8::10', 'OK', { cert: rsa })])]);
  const back = diffTls(night2, night3);
  assert.deepEqual(back.map((x) => [x.tag, x.tone]), [['RECOVERED', 'good'], ['CERT', 'bad']]);
  assert.match(changeText(back[0]), /answers again: OK, another certificate than before it failed/);
  // a move between failures is listed only; untrusted is WORSE, back to OK is BETTER
  const t1 = report([tgt([ep('192.0.2.10', 'CLOSED'), ep('192.0.2.11', 'OK', { cert: c })])]);
  const t2 = report([tgt([ep('192.0.2.10', 'TIMEOUT'), ep('192.0.2.11', 'UNTRUSTED', { cert: c, trustError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' })])]);
  assert.deepEqual(diffTls(t1, t2).map((x) => [x.tag, x.counts]), [['FAILING', false], ['WORSE', true]]);
  assert.match(changeText(diffTls(t1, t2)[1]), /OK → UNTRUSTED \(UNABLE_TO_VERIFY_LEAF_SIGNATURE\)$/);
  assert.deepEqual(diffTls(t2, t1).map((x) => [x.tag, x.tone]), [['FAILING', 'quiet'], ['BETTER', 'good']]);
  // addresses new or gone: listed only
  const moved = report([tgt([ep('192.0.2.12', 'OK', { cert: c })])]);
  assert.deepEqual(diffTls(t1, moved).map((x) => [x.tag, x.counts]), [['NEW', false], ['GONE', false], ['GONE', false]]);
});

test('changes: a DNS outage carries the endpoints, NXDOMAIN is GONE, targets new and gone', () => {
  const c = cert('a');
  const base = report([tgt([ep('192.0.2.10', 'OK', { cert: c })]), { ...tgt([]), target: 'old.example.com', host: 'old.example.com' }]);
  const outage = report([tgt(base.targets[0].endpoints, { dns: { status: 'SERVFAIL', ipv4: [], ipv6: [], cnames: [], error: 'x' }, carried: { from: '2026-10-08T03:00:00.000Z' } }),
    { ...tgt([]), target: 'new.example.com', host: 'new.example.com' }]);
  assert.deepEqual(diffTls(base, outage).map((x) => [x.tag, x.counts]), [['FAILED', false], ['NEW', true], ['GONE', true]]);
  const twice = diffTls(outage, outage);
  assert.deepEqual(twice, [], 'said once');
  const back = report([tgt([ep('192.0.2.10', 'OK', { cert: c })]), { ...tgt([]), target: 'new.example.com', host: 'new.example.com' }]);
  assert.deepEqual(diffTls(outage, back).map((x) => [x.tag, x.counts]), [['RECOVERED', false]], 'compared with the carried endpoints: nothing moved');
  const gone = report([tgt([], { dns: { status: 'NXDOMAIN', ipv4: [], ipv6: [], cnames: [], error: null } })]);
  assert.deepEqual(diffTls(back, gone).map((x) => [x.tag, x.tone, x.counts]), [['GONE', 'bad', true], ['GONE', 'info', true]]);
});

test('a tls baseline is checked before the run; the notes say what the runs did differently', () => {
  const good = report([tgt([ep('192.0.2.10', 'OK', { cert: cert('a') })])]);
  assert.equal(baselineProblem(good, 'tls'), null);
  const bad = (endpoints) => baselineProblem(report([tgt(endpoints)]), 'tls');
  assert.match(baselineProblem(report([{ target: 'www.example.com' }]), 'tls'), /has no "endpoints" list/);
  assert.match(bad([{ port: 443, status: 'OK' }]), /endpoints\[0\] has no "address"/);
  assert.match(bad([ep('192.0.2.10', 'OK', { cert: { names: [] } })]), /a certificate without "sha256"/);
  assert.match(bad([ep('192.0.2.10', 'OK', { ari: { start: 5 } })]), /"ari" whose times are not text/);
  assert.match(bad([ep('192.0.2.10', 'OK', { revocation: {} })]), /"revocation" without "status"/);
  assert.match(bad([ep('192.0.2.10', 'OK', { lastGood: 'x' })]), /"lastGood" that is not an object/);
  assert.equal(tlsTargetProblem({ endpoints: [], carried: { from: null } }), null);
  assert.deepEqual(tlsNotes({ ari: false, revocation: true }, { ari: true, revocation: true }), ['ARI was asked in this run only (--ari): RENEW-NOW, MOVED-UP and CA-NOTICE compare runs that both asked it.']);
  assert.equal(baselineNotes('tls', report([], undefined, { ari: true, revocation: false, resolvers: ['cloudflare'] }), report([], undefined, { ari: true, revocation: true, resolvers: ['cloudflare'] }))[0],
    'Revocation was checked in this run only (--revocation).');
});

test('the summary lines: the window and its state, the CA’s explanation, a carried answer, revocation', () => {
  const at = Date.parse('2026-10-09T03:00:00Z');
  const text = (parts) => parts.map((p) => (typeof p === 'string' ? p : p.code ?? p.strong)).join('');
  assert.equal(text(ariParts(ariOf('2026-11-01T00:00:00.000Z', '2026-11-03T00:00:00.000Z'), at)), 'ARI (letsencrypt): renew between 2026-11-01 00:00 UTC and 2026-11-03 00:00 UTC — opens in 23 days');
  assert.equal(text(ariParts(ariOf('2026-10-08T00:00:00.000Z', '2026-10-10T00:00:00.000Z', { explanationURL: 'https://status.example.org/' }), at)),
    'ARI (letsencrypt): renew between 2026-10-08 00:00 UTC and 2026-10-10 00:00 UTC — the window is open: renew now; the CA explains: https://status.example.org/');
  assert.match(text(ariParts(ariOf('2026-10-01T00:00:00.000Z', '2026-10-02T00:00:00.000Z', { carried: { from: '2026-10-08T03:00:00.000Z' }, retryAfter: '2026-10-09T09:00:00.000Z' }), at)),
    /the window has ended: the renewal is overdue \(as of 2026-10-08 03:00 UTC; not asked again before 2026-10-09 09:00 UTC, as the CA asked\)$/);
  assert.equal(text(ariParts(ariOf(null, null, { error: 'not-found', status: 404 }), at)), 'ARI (letsencrypt): the CA does not know this certificate (404)');
  assert.equal(text(ariParts(ariOf(null, null, { ca: 'sslcom', error: 'http', status: 403 }), at)), 'ARI (sslcom): the CA’s ARI server answered an HTTP error 403');
  assert.equal(ariParts(null, at), null);
  assert.equal(text(revocationParts({ status: 'revoked', reason: 'keyCompromise', time: '2026-09-01T12:00:00.000Z', thisUpdate: '2026-10-01T00:00:00.000Z', signature: 'verified' })),
    'REVOKED on 2026-09-01 12:00 UTC (keyCompromise); CRL of 2026-10-01 00:00 UTC, signature verified');
  assert.equal(text(revocationParts({ status: 'good', thisUpdate: '2026-10-01T00:00:00.000Z', signature: 'not-verified', signatureNote: 'issuer-not-sent' })),
    'Not revoked (CRL of 2026-10-01 00:00 UTC, signature not verified: the server does not send the issuer)');
  assert.equal(text(revocationParts({ status: 'unknown', error: 'no-crl' })), 'Revocation unknown: the certificate names no CRL to read (OCSP is not asked)');
  assert.equal(text(revocationParts({ status: 'unknown', error: 'stale', crl: DP })), `Revocation unknown: the CRL is out of date (its nextUpdate has passed) (${DP})`);
});

/* ------------------------------------------------------------------------ */
/* The run                                                                  */
/* ------------------------------------------------------------------------ */

describe('three nights of `tls --ari --revocation` over a local server', () => {
  let server;
  let dir;
  before(async () => {
    server = await tlsServer();
    dir = mkdtempSync(join(tmpdir(), 'ds-tls-'));
  });
  after(async () => {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  });

  /** The fakes of one night: DoH (www.example.com → 127.0.0.1), the ARI server and the CRL. */
  function night({ window, retryAfter = '86400', crl, log = [] }) {
    const table = { 'www.example.com': { A: ['127.0.0.1'] } };
    const routes = routesFetch({
      [DIR]: [200, { renewalInfo: RI }],
      [`${RI}/${LEAF_ID}`]: [200, window, { 'retry-after': retryAfter }],
      [DP]: [200, read(crl), { 'content-type': 'application/pkix-crl' }]
    }, log);
    return createFakeFetch(table, { apex: 'example.com', other: (url) => routes(url) });
  }

  async function run(argv, fetchImpl, now) {
    let out = '';
    let err = '';
    const stdout = { isTTY: false, write: (s) => { out += s; return true; } };
    const stderr = { write: (s) => { err += s; return true; } };
    const code = await main(argv, { stdout, stderr, fetchImpl, env: {}, now: () => now, tls: { ca: [CA_PEM], caOf: () => 'letsencrypt', directories: TEST_DIRS } });
    return { code, out, err };
  }

  test('night 1: the certificate, its window and a good CRL; night 2: every change; night 3: the CA not asked before its Retry-After', async () => {
    const json = join(dir, 'tls.json');
    const md = join(dir, 'tls.md');
    const target = `www.example.com:${server.port}`;
    const argv = ['tls', target, '--ari', '--revocation', '--baseline', json, '--json', json, '--md', md, '--fail-on-change', '--no-color'];
    const log1 = [];
    const n1 = await run(argv, night({ window: windowOf('2026-11-01T00:00:00Z', '2026-11-03T00:00:00Z'), crl: 'crl_empty.der', log: log1 }), NOW);
    assert.equal(n1.code, EXIT.OK, n1.err);
    assert.match(n1.out, /^Baseline tls\.json does not exist yet/);
    assert.match(n1.out, new RegExp(`TLS · www\\.example\\.com:${server.port}\\n- www\\.example\\.com · Example Test PKI · expires 2060-01-01 \\(\\d+ days left\\) · 127\\.0\\.0\\.1\\n`));
    assert.match(n1.out, /- ARI \(letsencrypt\): renew between 2026-11-01 00:00 UTC and 2026-11-03 00:00 UTC — opens in 23 days\n/);
    assert.match(n1.out, /- Not revoked \(CRL of 2026-10-01 00:00 UTC, signature verified\)\n/);
    const r1 = JSON.parse(readFileSync(json, 'utf8'));
    assert.equal(r1.command, 'tls');
    assert.deepEqual(r1.options, { ari: true, revocation: true, resolvers: ['cloudflare', 'google', 'dnssb'] });
    const e1 = r1.targets[0].endpoints[0];
    assert.deepEqual([e1.address, e1.port, e1.status, e1.trusted, e1.nameMatch, e1.chainLength], ['127.0.0.1', server.port, 'OK', true, true, 2]);
    assert.equal(e1.cert.sha256, Buffer.from(await crypto.subtle.digest('SHA-256', LEAF.der)).toString('hex'));
    assert.deepEqual([e1.cert.serialHex, e1.cert.crlUrls, e1.cert.names], ['0c1001', [DP], ['www.example.com', 'example.com']]);
    assert.deepEqual([e1.ari.start, e1.ari.retryAfter, e1.ari.error], ['2026-11-01T00:00:00.000Z', '2026-10-10T03:00:00.000Z', null]);
    assert.deepEqual([e1.revocation.status, e1.revocation.signature], ['good', 'verified']);
    assert.deepEqual(log1.filter((u) => !u.includes('?dns=')), [DP, DIR, `${RI}/${LEAF_ID}`], 'the CRL and the ARI server, once each');

    // night 2: the CA moved the window into today, explains why, and its CRL lists the certificate
    const n2 = await run(argv, night({ window: windowOf('2026-10-09T12:00:00Z', '2026-10-11T00:00:00Z', { explanationURL: 'https://status.example.org/incident' }), crl: 'crl_revoked.der' }), AT('2026-10-10T03:00:00Z'));
    assert.equal(n2.code, EXIT.CHANGED, n2.err);
    const r2 = JSON.parse(readFileSync(json, 'utf8'));
    assert.deepEqual(r2.changes.map((c) => c.tag), ['RENEW-NOW', 'MOVED-UP', 'CA-NOTICE', 'REVOKED']);
    assert.match(n2.out, /Changes since the baseline \(tls\.json, run of 2026-10-09 03:00 UTC\): 4\n {2}RENEW-NOW {2}www\.example\.com:\d+: /);
    assert.match(n2.out, /- REVOKED on 2026-09-01 12:00 UTC \(keyCompromise\); CRL of 2026-10-01 00:00 UTC, signature verified\n/);
    const markdown = readFileSync(md, 'utf8');
    assert.match(markdown, /- \*\*CA-NOTICE\*\* `www\.example\.com:\d+`: `www\.example\.com` \(`Example Test PKI`, expires 2060-01-01\): the CA explains its renewal window: `https:\/\/status\.example\.org\/incident`/);

    // night 3, before the Retry-After of night 2's answer: the CA is not asked, nothing new
    const log3 = [];
    const n3 = await run(argv, night({ window: windowOf('2026-12-01T00:00:00Z', '2026-12-03T00:00:00Z'), crl: 'crl_revoked.der', log: log3 }), AT('2026-10-10T12:00:00Z'));
    assert.equal(n3.code, EXIT.OK, n3.err);
    assert.ok(!log3.some((u) => u.startsWith(RI)), 'renewalInfo not asked before its Retry-After');
    const e3 = JSON.parse(readFileSync(json, 'utf8')).targets[0].endpoints[0];
    assert.deepEqual([e3.ari.start, e3.ari.carried], ['2026-10-09T12:00:00.000Z', { from: '2026-10-10T03:00:00.000Z' }]);
    assert.match(n3.out, /\(as of 2026-10-10 03:00 UTC; not asked again before 2026-10-11 03:00 UTC, as the CA asked\)/);
  });

  test('an endpoint that stops answering keeps its last certificate; the doc and the report say so', async () => {
    const t = await setupStrings();
    const probe = net.createServer();
    await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const port = probe.address().port;
    await new Promise((resolve) => probe.close(resolve));
    const fetchImpl = createFakeFetch({ 'www.example.com': { A: ['127.0.0.1'] } }, { apex: 'example.com' });
    const { DohClient } = await import('../../assets/js/lib/doh.js');
    const dns = new DohClient({ chain: ['cloudflare'], fetchImpl });
    const baseline = report([tgt([ep('127.0.0.1', 'OK', { port, cert: cert('a'), ari: ariOf('2026-11-01T00:00:00.000Z', '2026-11-03T00:00:00.000Z') })], { target: `www.example.com:${port}`, port })]);
    baseline.targets[0].endpoints[0].port = port;
    const env = { dns, fetchImpl, now: () => NOW, t, progress: () => {}, baseline, inputs: {}, tls: { ca: [CA_PEM] } };
    const res = await runTls([`www.example.com:${port}`], { ari: false, revocation: false, chain: ['cloudflare'] }, env);
    const e = res.targets[0].endpoints[0];
    assert.ok(['CLOSED', 'TIMEOUT'].includes(e.status), e.status);
    assert.equal(e.lastGood.cert.sha256, cert('a').sha256);
    assert.equal(e.lastGood.ari.start, '2026-11-01T00:00:00.000Z');
    const md = renderMarkdown(tlsDoc(res.targets[0], { t, now: NOW }));
    assert.match(md, new RegExp(`\`127\\.0\\.0\\.1\`: ${e.status}`));
    const changes = diffTls(baseline, { ...report(res.targets) });
    assert.deepEqual(changes.map((x) => [x.tag, x.counts]), [['FAILED', true]]);
  });
});
