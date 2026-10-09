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
 * NXDOMAIN) and three nights of `main()` over the local server and the fakes.
 * The served-certificate monitor: its command line, handshakes with fixture certificates (the
 * cross_* PKI — a chain as built and as sent, a missing intermediate, an unknown root —, a
 * self-signed certificate, a name not covered, an OCSP staple and none), statuses by the run's clock
 * (EXPIRING, EXPIRED), --http over the handshake's connection and port 80, the missing intermediate
 * named from the fixture CCADB dataset, --ct (tools/ds/tlsct.mjs), --from-subdomains, every new
 * change and its PagerDuty standing, --max-endpoints, and three nights over a local HTTPS server. No
 * request leaves the machine; documentation names only.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { main } from '../../tools/ds.mjs';
import { parseCommandLine, parseTlsTarget, parseTargets, UsageError, EXIT, COMMANDS, USAGE, DS_TOOL, DS_VERSION } from '../../tools/ds/args.mjs';
import { handshake, runTls, ariParts, revocationParts, tlsDoc, statusOf, nameMissingIntermediates, subdomainTlsHosts, tlsInputs, connectionParts, httpText } from '../../tools/ds/tls.mjs';
import { ARI_SERVER_DIRECTORIES, ariDirectoryFor, createAriClient, windowState, ARI_MAX_RETRY_MS } from '../../tools/ds/ari.mjs';
import { createRevocationChecker, verifyCrlSignature, issuerFromChain, fetchCrl } from '../../tools/ds/revocation.mjs';
import { diffTls, tlsTargetProblem, tlsNotes, MOVED_UP_MS, expiryState, TLS_STATUSES } from '../../tools/ds/tlsdiff.mjs';
import { ctReportProblem, ctLookup, newestInCt, renewalNotDeployed, NOT_DEPLOYED_MS } from '../../tools/ds/tlsct.mjs';
import { getHead, httpRecord, redirectsToHttps, hostHeader } from '../../tools/ds/tlshttp.mjs';
import { problemStanding } from '../../tools/ds/states.mjs';
import { eventSeverity } from '../../tools/ds/notify.mjs';
import { diffReports, baselineProblem, baselineNotes } from '../../tools/ds/diff.mjs';
import { setupStrings, CHANGE_TAGS, changeText } from '../../tools/ds/render.mjs';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { parseCrl } from '../../assets/js/lib/crl.js';
import { ariCertId } from '../../assets/js/lib/renewalplan.js';
import { createIntermediateStore, rootTable } from '../../assets/js/lib/chainfix.js';
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
// the three-level test PKI of the CLI's chain check (gen_cross_fixtures.sh): root → Issuing CA → leaf, with the leaf's key
const CROSS_ROOT_PEM = read('cross_root.pem');
const CROSS_INTER_PEM = read('cross_inter.pem');
const CROSS_LEAF_PEM = read('cross_leaf.pem');
const CROSS_LEAF_KEY = read('cross_leaf.key');
const CROSS_ROOT = certOf('cross_root.pem');
const CROSS_INTER = certOf('cross_inter.pem');
// a self-signed certificate for www.example.com and example.com, with its key (gen_starttls_fixtures.sh)
const SELF_PEM = read('starttls_ec_leaf.pem');
const SELF_KEY = read('starttls_ec_leaf.key');

/**
 * An in-process TLS server on 127.0.0.1 that completes the handshake and closes; `staple`: the
 * OCSP response it staples when asked (a Buffer, or null for none); `setCert` swaps what it serves.
 */
async function tlsServer({ cert = Buffer.concat([LEAF_PEM, CA_PEM]), key = LEAF_KEY, staple } = {}) {
  const server = tls.createServer({ key, cert }, (s) => {
    s.on('error', () => {});
    s.end();
  });
  server.on('tlsClientError', () => {});
  if (staple !== undefined) server.on('OCSPRequest', (c, issuer, done) => done(null, staple));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    setCert: (next) => server.setSecureContext({ key: next.key || key, cert: next.cert }),
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

/**
 * An HTTPS server on 127.0.0.1 answering every GET with `answer.status` and `answer.headers`
 * (changeable between requests), serving `cert` with `key`.
 */
async function httpsServer({ cert, key, answer }) {
  const server = https.createServer({ key, cert, ALPNProtocols: ['http/1.1'] }, (req, res) => {
    res.writeHead(answer.status, answer.headers || {});
    res.end('ok');
  });
  server.on('tlsClientError', () => {});
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    setCert: (next) => server.setSecureContext({ key: next.key || key, cert: next.cert }),
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); })
  };
}

/** A plain HTTP server on 127.0.0.1 answering with `answer` (`location` → a Location header). */
async function plainServer(answer) {
  const server = http.createServer((req, res) => {
    res.writeHead(answer.status, answer.location ? { Location: answer.location } : {});
    res.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { port: server.address().port, close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }) };
}

/** node:http's request with port 80 moved to a local plain server (the GET over TLS goes as it is). */
const requestVia = (plainPort) => (opts, cb) => http.request(opts.createConnection ? opts : { ...opts, port: plainPort }, cb);

/** A lib/chainfix.js store that knows the cross PKI's Issuing CA under its root, trusted by every store. */
function crossStore() {
  const roots = rootTable({
    generated: '2026-10-05',
    roots: [{
      sha256: 'ab'.repeat(32), name: 'Example Test Cross Root', owner: 'Example Test PKI', ski: CROSS_ROOT.subjectKeyId, dn: CROSS_ROOT.subjectDN,
      notAfter: '2060-01-01', stores: { chrome: 'tls', mozilla: 'tls', apple: 'tls', microsoft: 'tls' }
    }]
  });
  return {
    manifest: async () => ({ format: 1, generated: '2026-10-05', shards: { ski: { dir: 'ski', digits: 2 }, dn: { dir: 'dn', digits: 1 } } }),
    roots: async () => roots,
    bySki: async (ski) => (String(ski).toLowerCase() === CROSS_INTER.subjectKeyId ? [{ cert: CROSS_INTER, owner: 'Example Test PKI' }] : []),
    byDn: async (dn) => (dn === CROSS_INTER.subjectDN ? [{ cert: CROSS_INTER, owner: 'Example Test PKI' }] : [])
  };
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
  assert.throws(() => parseCommandLine(['tls']), /tls needs at least one host \(or --list FILE, or --from-subdomains FILE\)/);
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
  // a move between failures is listed only; an untrusted chain is UNTRUSTED (the host's), trusted again is BETTER
  const t1 = report([tgt([ep('192.0.2.10', 'CLOSED'), ep('192.0.2.11', 'OK', { cert: c, trusted: true })])]);
  const t2 = report([tgt([ep('192.0.2.10', 'TIMEOUT'), ep('192.0.2.11', 'UNTRUSTED', { cert: c, trusted: false, trustError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' })])]);
  assert.deepEqual(diffTls(t1, t2).map((x) => [x.tag, x.counts, x.item]), [['FAILING', false, '192.0.2.10|443'], ['UNTRUSTED', true, null]]);
  assert.match(changeText(diffTls(t1, t2)[1]), /^www\.example\.com: 192\.0\.2\.11 serves a chain this machine does not trust \(UNABLE_TO_VERIFY_LEAF_SIGNATURE\)$/);
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
  function night({ window, retryAfter = '86400', crl, log = [], hook = null }) {
    const table = { 'www.example.com': { A: ['127.0.0.1'] } };
    const routes = routesFetch({
      [DIR]: [200, { renewalInfo: RI }],
      [`${RI}/${LEAF_ID}`]: [200, window, { 'retry-after': retryAfter }],
      [DP]: [200, read(crl), { 'content-type': 'application/pkix-crl' }]
    }, log);
    // `hook`: the alert channel (--notify-bad), answered by the test
    return createFakeFetch(table, { apex: 'example.com', other: (url, init) => (hook && String(url).startsWith('https://events.pagerduty.com/') ? hook(init) : routes(url)) });
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
    assert.deepEqual(r1.options, {
      ari: true, revocation: true, warnDays: 21, http: false, ct: null, fromSubdomains: null, skipCdn: false, maxEndpoints: 500, resolvers: ['cloudflare', 'google', 'dnssb']
    });
    const e1 = r1.targets[0].endpoints[0];
    assert.deepEqual([e1.address, e1.port, e1.status, e1.trusted, e1.nameMatch, e1.chainLength, e1.chainSent, e1.ocspStapled], ['127.0.0.1', server.port, 'OK', true, true, 2, 2, false]);
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

  test('with --notify-bad to PagerDuty: the four changes of night 2 page (a revoked certificate critical), and night 3 resolves none of them while the certificate is still served', async () => {
    const json = join(dir, 'tls-pagerduty.json');
    // a credential: built in parts, never written whole
    const url = 'https://events.pagerduty.com/v2/enqueue?routing_key=' + 'R0UT1NGKEY' + 'x'.repeat(22);
    const argv = ['tls', `www.example.com:${server.port}`, '--ari', '--revocation', '--baseline', json, '--json', json, '--notify-bad', url, '--fail-on-notify-error', '--no-color'];
    const sent = [];
    const hook = (init) => {
      sent.push(JSON.parse(init.body));
      return new Response('{"status":"success"}', { status: 202 });
    };
    const n1 = await run(argv, night({ window: windowOf('2026-11-01T00:00:00Z', '2026-11-03T00:00:00Z'), crl: 'crl_empty.der', hook }), NOW);
    assert.equal(n1.code, EXIT.OK, n1.err);
    assert.deepEqual(sent, [], 'the first run has nothing to compare with');
    // night 2: the window moved into today with a notice, and the CRL lists the certificate
    const n2 = await run(argv, night({ window: windowOf('2026-10-09T12:00:00Z', '2026-10-11T00:00:00Z', { explanationURL: 'https://status.example.org/incident' }), crl: 'crl_revoked.der', hook }), AT('2026-10-10T03:00:00Z'));
    assert.equal(n2.code, EXIT.OK, n2.err);
    assert.deepEqual(sent.map((e) => [e.event_action, e.payload.custom_details.tag, e.payload.severity]),
      [['trigger', 'RENEW-NOW', 'error'], ['trigger', 'MOVED-UP', 'error'], ['trigger', 'CA-NOTICE', 'error'], ['trigger', 'REVOKED', 'critical']]);
    const sha = Buffer.from(await crypto.subtle.digest('SHA-256', LEAF.der)).toString('hex');
    assert.ok(sent.every((e) => e.payload.custom_details.item === sha && e.payload.source === 'domainscope:tls'), 'each is about the certificate');
    const open2 = JSON.parse(readFileSync(json, 'utf8')).notify.open;
    assert.deepEqual(open2.map((e) => [e.tag, e.item]), ['RENEW-NOW', 'MOVED-UP', 'CA-NOTICE', 'REVOKED'].map((tag) => [tag, sha]));
    // night 3: nothing changed and the certificate is still served: no resolve, every key stays open
    sent.length = 0;
    const n3 = await run(argv, night({ window: windowOf('2026-12-01T00:00:00Z', '2026-12-03T00:00:00Z'), crl: 'crl_revoked.der', hook }), AT('2026-10-10T12:00:00Z'));
    assert.equal(n3.code, EXIT.OK, n3.err);
    assert.deepEqual(sent, [], 'a revoked certificate still served is no reason to close its incident');
    assert.deepEqual(JSON.parse(readFileSync(json, 'utf8')).notify.open, open2);
    assert.ok(!(n2.out + n2.err + n3.out + n3.err).includes('R0UT1NGKEY'), 'the routing key is never printed');
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

/* ------------------------------------------------------------------------ */
/* The served-certificate monitor                                           */
/* ------------------------------------------------------------------------ */

test('the monitor\'s command line: --warn-days, --ct, --http, --max-endpoints, --from-subdomains, --skip-cdn', () => {
  const cl = parseCommandLine(['tls', 'www.example.com', '--warn-days', '30', '--ct', 'results/ct.json', '--http', '--max-endpoints', '50']);
  assert.deepEqual([cl.options.warnDays, cl.options.ct, cl.options.http, cl.options.maxEndpoints, cl.options.fromSubdomains, cl.options.skipCdn],
    [30, 'results/ct.json', true, 50, null, false]);
  const plain = parseCommandLine(['tls', 'www.example.com']);
  assert.deepEqual([plain.options.warnDays, plain.options.ct, plain.options.http, plain.options.maxEndpoints], [21, null, false, 500]);
  const subs = parseCommandLine(['tls', '--from-subdomains', 'subs.json', '--skip-cdn']);
  assert.deepEqual([subs.targets, subs.options.fromSubdomains, subs.options.skipCdn], [[], 'subs.json', true], 'a subdomains report can give every target');
  assert.equal(parseCommandLine(['tls', 'www.example.com', '--warn-days', '0']).options.warnDays, 0);
  const refused = [
    [['tls', 'www.example.com', '--skip-cdn'], /--skip-cdn leaves out the hosts of --from-subdomains behind a CDN: give --from-subdomains FILE/],
    [['tls', 'www.example.com', '--warn-days', '399'], /--warn-days takes a whole number from 0 to 398, not "399"/],
    [['tls', 'www.example.com', '--max-endpoints', '0'], /--max-endpoints takes a whole number from 1 to 10000, not "0"/],
    [['tls', 'www.example.com', '--ct', 'ct.json', '--json', 'ct.json'], /--json names the same file as --ct \(ct\.json\)/],
    [['tls', 'www.example.com', '--ct', '-'], /--ct takes a file, not "-"/],
    [['tls', '--from-subdomains', 's.json', '--md', 's.json'], /--md names the same file as --from-subdomains \(s\.json\)/],
    [['health', 'example.com', '--warn-days', '30'], /--warn-days applies to tls only, not to health/],
    [['ct', 'example.com', '--http'], /--http applies to tls only, not to ct/],
    [['takeover', 'example.com', '--skip-cdn'], /--skip-cdn applies to tls only, not to takeover/]
  ];
  for (const [argv, re] of refused) assert.throws(() => parseCommandLine(argv), (err) => err instanceof UsageError && re.test(err.message), argv.join(' '));
  for (const option of ['--from-subdomains FILE', '--skip-cdn', '--warn-days N', '--ct FILE', '--http', '--max-endpoints N']) assert.ok(USAGE.includes(`[${option}]`), option);
  assert.ok(['EXPIRED', 'UNTRUSTED', 'MISMATCH', 'NOT-LIVE', 'HTTP', 'REDIRECT', 'HSTS'].every((tag) => CHANGE_TAGS.includes(tag) && tag.length <= 9));
});

describe('the monitor\'s handshakes: fixture certificates on a local server', () => {
  const servers = {};
  before(async () => {
    servers.trusted = await tlsServer();
    servers.self = await tlsServer({ cert: SELF_PEM, key: SELF_KEY });
    servers.lone = await tlsServer({ cert: CROSS_LEAF_PEM, key: CROSS_LEAF_KEY });
    servers.withInter = await tlsServer({ cert: Buffer.concat([CROSS_LEAF_PEM, CROSS_INTER_PEM]), key: CROSS_LEAF_KEY });
    servers.stapled = await tlsServer({ staple: Buffer.from('a stapled OCSP response') });
    servers.noStaple = await tlsServer({ staple: null });
  });
  after(async () => {
    for (const s of Object.values(servers)) await s.close();
  });

  test('the chain as Node built it and as the server sent it, the key exchange, the staple asked for', async () => {
    const h = await handshake({ address: '127.0.0.1', port: servers.withInter.port, servername: 'www.example.com', ca: [CROSS_ROOT_PEM] });
    assert.deepEqual([h.status, h.authorized, h.authorizationError, h.nameMatch], ['OK', true, null, true]);
    assert.equal(h.chain.length, 3, 'built: the leaf, the Issuing CA sent with it and the root of the trust store');
    assert.equal(h.sent.length, 2, 'sent: the leaf and the Issuing CA');
    assert.deepEqual(Buffer.from(h.sent[1]), Buffer.from(CROSS_INTER.der));
    assert.equal(h.ocspStapled, false, 'asked for, none stapled');
    assert.ok(h.ephemeralKey === null || (typeof h.ephemeralKey.name === 'string' && h.ephemeralKey.name.length > 0), JSON.stringify(h.ephemeralKey));
    const stapled = await handshake({ address: '127.0.0.1', port: servers.stapled.port, servername: 'www.example.com', ca: [CA_PEM] });
    assert.deepEqual([stapled.status, stapled.ocspStapled], ['OK', true]);
    assert.equal((await handshake({ address: '127.0.0.1', port: servers.noStaple.port, servername: 'www.example.com', ca: [CA_PEM] })).ocspStapled, false);
  });

  test('untrusted: self-signed, a missing intermediate, an unknown root; a name not covered and an address are no trust error on a trusted chain', async () => {
    const self = await handshake({ address: '127.0.0.1', port: servers.self.port, servername: 'www.example.com' });
    assert.deepEqual([self.authorized, self.authorizationError, self.sent.length], [false, 'DEPTH_ZERO_SELF_SIGNED_CERT', 1]);
    const missing = await handshake({ address: '127.0.0.1', port: servers.lone.port, servername: 'www.example.com', ca: [CROSS_ROOT_PEM] });
    assert.deepEqual([missing.authorized, missing.authorizationError, missing.sent.length, missing.chain.length], [false, 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 1, 1]);
    const unknownRoot = await handshake({ address: '127.0.0.1', port: servers.withInter.port, servername: 'www.example.com' });
    assert.deepEqual([unknownRoot.authorized, unknownRoot.authorizationError], [false, 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY']);
    // Node reports a name it does not find only on a trusted chain: the chain is trusted, the name is the endpoint's own status
    const other = await handshake({ address: '127.0.0.1', port: servers.trusted.port, servername: 'mail.example.org', ca: [CA_PEM] });
    assert.deepEqual([other.authorized, other.authorizationError, other.nameMatch], [true, null, false]);
    const address = await handshake({ address: '127.0.0.1', port: servers.trusted.port, servername: null, ca: [CA_PEM] });
    assert.deepEqual([address.authorized, address.authorizationError, address.nameMatch], [true, null, null]);
  });

  test('--http: GET / over the handshake\'s connection, and over HTTP to port 80; the answers as the report keeps them', async () => {
    const answer = { status: 200, headers: { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } };
    const web = await httpsServer({ cert: Buffer.concat([LEAF_PEM, CA_PEM]), key: LEAF_KEY, answer });
    const plain = await plainServer({ status: 301, location: 'https://www.example.com/' });
    const mute = await tlsServer();
    try {
      const h = await handshake({ address: '127.0.0.1', port: web.port, servername: 'www.example.com', ca: [CA_PEM], http: true });
      assert.equal(h.status, 'OK');
      assert.equal(h.https.status, 200);
      const p = await getHead({ host: '127.0.0.1', port: 80, agent: false, headers: { Host: 'www.example.com' } }, { request: requestVia(plain.port) });
      assert.deepEqual(httpRecord(h.https, p, 'www.example.com'), {
        status: 200, error: null, hsts: { maxAge: 31536000, includeSubDomains: true, preload: false, valid: true },
        plain: { status: 301, location: 'https://www.example.com/', toHttps: true, error: null }
      });
      answer.status = 503;
      answer.headers = {};
      const down = await handshake({ address: '127.0.0.1', port: web.port, servername: 'www.example.com', ca: [CA_PEM], http: true });
      assert.deepEqual(httpRecord(down.https, undefined, 'www.example.com'), { status: 503, error: null, hsts: null, plain: null });
      // a TLS server that answers no HTTP: the GET's failure, the handshake's facts kept
      const quiet = await handshake({ address: '127.0.0.1', port: mute.port, servername: 'www.example.com', ca: [CA_PEM], http: true, httpTimeoutMs: 300 });
      assert.equal(quiet.status, 'OK');
      assert.ok(quiet.https.error, JSON.stringify(quiet.https));
      assert.equal(httpRecord(quiet.https, undefined, 'www.example.com').status, null);
    } finally {
      await web.close();
      await plain.close();
      await mute.close();
    }
  });
});

test('statuses through real handshakes: self-signed UNTRUSTED, another name NAME_MISMATCH, EXPIRING and EXPIRED by the run\'s clock', async () => {
  const t = await setupStrings();
  const self = await tlsServer({ cert: SELF_PEM, key: SELF_KEY });
  const good = await tlsServer();
  try {
    const fetchImpl = createFakeFetch({ 'www.example.com': { A: ['127.0.0.1'] }, 'mail.example.com': { A: ['127.0.0.1'] } }, { apex: 'example.com' });
    const { DohClient } = await import('../../assets/js/lib/doh.js');
    const run = (targets, now) => runTls(targets, { ari: false, revocation: false, chain: ['cloudflare'], warnDays: 21 }, {
      dns: new DohClient({ chain: ['cloudflare'], fetchImpl }), fetchImpl, now: () => now, t, progress: () => {}, baseline: null, inputs: {}, tls: { ca: [CA_PEM] }
    });
    const res = await run([`www.example.com:${self.port}`, `mail.example.com:${good.port}`, `www.example.com:${good.port}`], NOW);
    assert.deepEqual(res.targets.map((x) => [x.endpoints[0].status, x.endpoints[0].trustError, x.endpoints[0].trusted, x.endpoints[0].nameMatch]), [
      ['UNTRUSTED', 'DEPTH_ZERO_SELF_SIGNED_CERT', false, true], ['NAME_MISMATCH', null, true, false], ['OK', null, true, true]]);
    assert.equal(res.targets[0].endpoints[0].missingIntermediate, undefined, 'a self-signed certificate lacks no intermediate');
    // crl_leaf.pem runs to 2060-01-01: 12 days left of 35 years is EXPIRING, a day after its end EXPIRED
    const soon = (await run([`www.example.com:${good.port}`], AT('2059-12-20T00:00:00Z'))).targets[0];
    assert.deepEqual([soon.endpoints[0].status, soon.endpoints[0].cert.daysLeft], ['EXPIRING', 12]);
    assert.match(renderMarkdown(tlsDoc(soon, { t, now: AT('2059-12-20T00:00:00Z'), warnDays: 21 })), /\(12 days left: EXPIRING\)/);
    const gone = (await run([`www.example.com:${good.port}`], AT('2060-01-02T00:00:00Z'))).targets[0].endpoints[0];
    assert.deepEqual([gone.status, gone.trustError, gone.trusted], ['EXPIRED', 'CERT_HAS_EXPIRED', false]);
  } finally {
    await self.close();
    await good.close();
  }
});

test('the HTTP answers in words: a redirect to https://, the Host header, HSTS, the connection line', () => {
  assert.ok(redirectsToHttps(301, 'https://www.example.com/', 'www.example.com'));
  assert.equal(redirectsToHttps(308, '//www.example.com/', 'www.example.com'), false, 'a scheme-relative URL stays on http://');
  assert.ok(redirectsToHttps(302, 'https://login.example.org/', 'www.example.com'), 'to another host, over https');
  assert.ok(!redirectsToHttps(200, 'https://www.example.com/', 'www.example.com'));
  assert.ok(!redirectsToHttps(301, '/elsewhere', 'www.example.com'));
  assert.ok(!redirectsToHttps(301, 'http://[bad', 'www.example.com'));
  assert.equal(hostHeader('www.example.com', '192.0.2.10', 443, 443), 'www.example.com');
  assert.equal(hostHeader('www.example.com', '192.0.2.10', 8443, 443), 'www.example.com:8443');
  assert.equal(hostHeader(null, '2001:db8::10', 443, 443), '[2001:db8::10]');
  assert.equal(httpText({ status: 200, error: null, hsts: { maxAge: 31536000, includeSubDomains: true, preload: true, valid: true }, plain: { status: 301, location: 'https://www.example.com/', toHttps: true, error: null } }),
    'GET / 200 · HSTS max-age=31536000; includeSubDomains; preload · http:// redirects to https:// (301)');
  assert.equal(httpText({ status: 503, error: null, hsts: null, plain: { status: 200, location: null, toHttps: false, error: null } }), 'GET / 503 · no HSTS · http:// answers 200, no redirect to https://');
  assert.equal(httpText({ status: null, error: 'no answer within 10 s', hsts: null, plain: { status: null, location: null, toHttps: false, error: 'connection refused' } }),
    'GET / failed: no answer within 10 s · http:// failed: connection refused');
  assert.equal(httpText({ status: 200, error: null, hsts: { maxAge: null, includeSubDomains: false, preload: false, valid: false }, plain: null }), 'GET / 200 · HSTS header not valid (browsers ignore it)');
  assert.equal(httpText(undefined), null);
  assert.deepEqual(connectionParts([
    { protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', ephemeralKey: { type: 'TLSGroup', name: 'X25519MLKEM768', size: null }, chainSent: 2, ocspStapled: false },
    { protocol: 'TLSv1.2', cipher: 'ECDHE-ECDSA-AES128-GCM-SHA256', ephemeralKey: { type: 'ECDH', name: 'X25519', size: 253 }, chainSent: 2, ocspStapled: true }
  ]), ['TLSv1.3/TLSv1.2 · TLS_AES_256_GCM_SHA384/ECDHE-ECDSA-AES128-GCM-SHA256 · X25519MLKEM768/X25519 · chain sent: 2 certificates · OCSP staple: some addresses']);
  assert.deepEqual(connectionParts([{ protocol: 'TLSv1.3', chainSent: 1, ocspStapled: null }]), ['TLSv1.3 · chain sent: 1 certificate']);
});

test('the status, worst first: expired, untrusted, the name, not deployed, expiring (its automatic renewal overdue), OK', () => {
  const c = cert('a'); // 90 days: 2026-09-01 → 2026-11-30
  const ok = { authorized: true, authorizationError: null, nameMatch: true };
  const s = (h, when, opts = {}) => statusOf(h, opts.cert || c, Date.parse(when), { warnDays: 21, ...opts });
  assert.deepEqual(s(ok, '2026-10-09T03:00:00Z'), { status: 'OK', trustError: null });
  assert.deepEqual(s(ok, '2026-11-09T00:00:00Z'), { status: 'EXPIRING', trustError: null }, '21 days left; a quarter of 90 days is 22.5');
  assert.deepEqual(s(ok, '2026-11-09T00:00:00Z', { warnDays: 14 }), { status: 'OK', trustError: null });
  assert.deepEqual(s(ok, '2026-12-01T00:00:00Z'), { status: 'EXPIRED', trustError: 'CERT_HAS_EXPIRED' });
  assert.deepEqual(s(ok, '2026-08-01T00:00:00Z'), { status: 'UNTRUSTED', trustError: 'CERT_NOT_YET_VALID' });
  const missing = { authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', nameMatch: true };
  assert.deepEqual(s(missing, '2026-11-09T00:00:00Z'), { status: 'UNTRUSTED', trustError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }, 'worse than expiring');
  assert.deepEqual(s(missing, '2026-12-01T00:00:00Z'), { status: 'EXPIRED', trustError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }, 'expired, the trust error kept');
  assert.deepEqual(s({ ...missing, authorizationError: 'CERT_HAS_EXPIRED' }, '2026-10-09T03:00:00Z'), { status: 'OK', trustError: null }, 'the dates are the run\'s clock\'s');
  assert.deepEqual(s({ ...ok, nameMatch: false }, '2026-11-09T00:00:00Z'), { status: 'NAME_MISMATCH', trustError: null });
  const newer = { id: 'r1', notBefore: '2026-10-05T00:00:00.000Z' };
  assert.deepEqual(s(ok, '2026-11-09T00:00:00Z', { newer }), { status: 'NOT_DEPLOYED', trustError: null }, 'the renewal not installed says more than the expiry');
  // a 47-day certificate is renewed at a third of its life (16 days left), overdue at a quarter (11.75)
  const short = cert('b', { notBefore: '2026-10-01T00:00:00.000Z', notAfter: '2026-11-17T00:00:00.000Z' });
  assert.equal(s(ok, '2026-10-27T00:00:00Z', { cert: short }).status, 'OK');
  assert.equal(s(ok, '2026-11-06T00:00:00Z', { cert: short }).status, 'EXPIRING');
  assert.deepEqual(['2026-10-20T00:00:00Z', '2026-10-27T00:00:00Z', '2026-11-06T00:00:00Z', '2026-11-18T00:00:00Z'].map((at) => expiryState(short, Date.parse(at), 21)), ['ok', 'soon', 'expiring', 'expired']);
  assert.equal(expiryState({ notBefore: null, notAfter: null }, 0, 21), 'ok');
  assert.deepEqual(TLS_STATUSES.slice(0, 6), ['OK', 'EXPIRING', 'NOT_DEPLOYED', 'NAME_MISMATCH', 'UNTRUSTED', 'EXPIRED']);
});

test('a missing intermediate is named from the CCADB list (the site\'s dataset format); a CA the list lacks is null, an unreadable list an error', async () => {
  const manifest = pathToFileURL(join(FIX, 'intermediates', 'manifest.json')).href;
  const fileFetch = async (url) => {
    try {
      return new Response(readFileSync(fileURLToPath(url)), { status: 200, headers: { 'content-type': 'application/json' } });
    } catch {
      return new Response('{}', { status: 200 });
    }
  };
  const store = createIntermediateStore({ url: manifest, fetchImpl: fileFetch });
  const leaf = certOf('chainfix_leaf.pem');
  const unlisted = certOf('chainfix_leaf_unknown.pem');
  const at = Date.parse('2026-10-09T03:00:00Z');
  const { found, error } = await nameMissingIntermediates([{ key: 'a', leaf, certs: [leaf] }, { key: 'b', leaf: unlisted, certs: [unlisted] }, { key: 'a', leaf, certs: [leaf] }], { store, now: at });
  assert.equal(error, null);
  assert.deepEqual(found.get('a'), { name: 'DomainScope Test Issuing CA', owner: 'DomainScope Test', subjectDN: 'CN=DomainScope Test Issuing CA,O=DomainScope Test,C=XX', added: 1 });
  assert.equal(found.get('b'), null, 'not in the list: a private CA, or an intermediate the list lacks');
  const broken = createIntermediateStore({ url: manifest, fetchImpl: async () => { throw new TypeError('Failed to fetch'); } });
  const failed = await nameMissingIntermediates([{ key: 'a', leaf, certs: [leaf] }], { store: broken, now: at });
  assert.equal(failed.found.size, 0);
  assert.match(failed.error, /Failed to fetch/);
  // without a store: the site's own list, read from disk (it has no test CA)
  const site = await nameMissingIntermediates([{ key: 'x', leaf: unlisted, certs: [unlisted] }], { now: at });
  assert.deepEqual([site.error, site.found.get('x')], [null, null]);
  assert.deepEqual(await nameMissingIntermediates([], { now: at }), { found: new Map(), error: null });
});

describe('the monitor\'s inputs: the same night\'s ct report, the hosts of a subdomains report', () => {
  const ctc = (id, notBefore, notAfter, names, extra = {}) => ({
    id, ca: 'Example CA', intermediate: 'Example R1', issuer: 'CN=Example R1,O=Example CA', notBefore, notAfter, names, sha256: null, serialHex: `0${id}`,
    sources: ['crtsh'], revoked: null, precert: null, ...extra
  });
  const ctDoc = {
    tool: DS_TOOL, version: DS_VERSION, command: 'ct', startedAt: '2026-10-09T02:40:00.000Z', finishedAt: '2026-10-09T02:50:00.000Z', options: {},
    targets: [
      { target: 'example.com', names: [], readAt: null, certificates: [
        ctc('a1', '2026-09-01T00:00:00.000Z', '2026-11-30T00:00:00.000Z', ['example.com', 'www.example.com']),
        ctc('a2', '2026-10-05T00:00:00.000Z', '2027-01-03T00:00:00.000Z', ['example.com', 'www.example.com']),
        ctc('a3', '2026-10-07T00:00:00.000Z', '2027-01-05T00:00:00.000Z', ['www.example.com']),
        ctc('a4', '2026-10-08T00:00:00.000Z', '2027-01-06T00:00:00.000Z', ['example.com', 'www.example.com'], { revoked: true }),
        ctc('a5', '2026-10-10T00:00:00.000Z', '2027-01-08T00:00:00.000Z', ['example.com', 'www.example.com']),
        ctc('w1', '2026-10-06T00:00:00.000Z', '2027-01-04T00:00:00.000Z', ['*.example.com', 'example.com']),
        { id: 'broken', names: ['example.com'], notBefore: 'soon', notAfter: null }
      ] },
      { target: 'example.org', names: [], readAt: null, certificates: [ctc('b1', '2026-10-06T00:00:00.000Z', '2027-01-04T00:00:00.000Z', ['www.example.org'])] }
    ]
  };
  const at = Date.parse('2026-10-09T03:00:00Z');

  test('--ct: the renewal CT logged more than 48 hours later, for every name served, current and not revoked', () => {
    assert.equal(ctReportProblem(ctDoc), null);
    assert.match(ctReportProblem({ tool: 'ssl_origin_scan' }), /not a --json report of domainscope-ds/);
    assert.match(ctReportProblem({ ...ctDoc, version: '0.9.0' }), /written by version "0\.9\.0"/);
    assert.match(ctReportProblem({ ...ctDoc, command: 'tls' }), /a report of "tls", not of "ct"/);
    assert.match(ctReportProblem({ ...ctDoc, targets: [{ target: 'example.com' }] }), /targets\[0\] has no "certificates" list/);
    const lookup = ctLookup(ctDoc, 'ct.json');
    assert.deepEqual([lookup.file, lookup.finishedAt, lookup.domains.map((d) => [d.domain, d.certificates.length])], ['ct.json', '2026-10-09T02:50:00.000Z', [['example.com', 6], ['example.org', 1]]]);
    const served = cert('a', { notBefore: '2026-09-01T00:00:00.000Z', names: ['www.example.com', 'example.com'] });
    assert.deepEqual(renewalNotDeployed(lookup, 'www.example.com', served, at), {
      id: 'a2', ca: 'Example CA', intermediate: 'Example R1', notBefore: '2026-10-05T00:00:00.000Z', notAfter: '2027-01-03T00:00:00.000Z', serialHex: '0a2'
    }, 'not a3 (the origin\'s own, without example.com), a4 (revoked) or a5 (not valid yet); w1 is older than a2');
    assert.equal(newestInCt(lookup, 'www.example.com', at).id, 'a3', 'the newest current certificate for the name, whatever else it carries');
    const within = { ...served, notBefore: new Date(Date.parse('2026-10-05T00:00:00Z') - NOT_DEPLOYED_MS + 3600000).toISOString() };
    assert.equal(renewalNotDeployed(lookup, 'www.example.com', within, at), null, '47 hours apart: a deploy hook\'s time');
    assert.equal(renewalNotDeployed(lookup, 'www.example.com', { ...served, notBefore: '2026-10-05T00:00:00.000Z' }, at), null, 'the renewal itself is served');
    // a wildcard covers the host; the names of another domain on the served certificate are not asked of this domain's
    const wild = cert('w', { notBefore: '2026-07-01T00:00:00.000Z', names: ['*.example.com', 'example.com', 'www.example.net'] });
    assert.equal(renewalNotDeployed(lookup, 'shop.example.com', wild, at).id, 'w1');
    assert.equal(renewalNotDeployed(lookup, 'api.example.net', served, at), null, 'no report for that domain');
    assert.equal(renewalNotDeployed(lookup, null, served, at), null, 'an address target asks no name');
    assert.equal(newestInCt(lookup, 'api.example.net', at), null);
  });

  test('--from-subdomains: hosts with an address, or one a failed lookup carried; private ones, look-alikes and with --skip-cdn CDN ones left out', () => {
    const doc = { tool: DS_TOOL, version: DS_VERSION, command: 'subdomains', targets: [{ target: 'example.com', mode: 'discover', hosts: [
      { name: 'www.example.com', kind: 'direct', ipv4: ['192.0.2.10'], ipv6: [], cnames: [] },
      { name: 'shop.example.com', kind: 'cloudflare', ipv4: ['198.51.100.7'], ipv6: [], cnames: [] },
      { name: 'cdn.example.com', kind: 'cdn', ipv4: ['203.0.113.5'], ipv6: [], cnames: ['cdn.example.net'] },
      { name: 'intranet.example.com', kind: 'private', ipv4: ['10.0.0.5'], ipv6: [], cnames: [] },
      { name: 'old.example.com', kind: 'unresolved', status: 'SERVFAIL', ipv4: [], ipv6: [], cnames: [], lastGood: { at: '2026-10-08T03:00:00.000Z', ipv4: ['192.0.2.20'], ipv6: [] } },
      { name: 'gone.example.com', kind: 'nxdomain', ipv4: [], ipv6: [], cnames: [] },
      { name: 'x1.example.com', kind: 'direct', wildcardSuspect: true, ipv4: ['192.0.2.30'], ipv6: [], cnames: [] },
      { name: 'bad‮example.com', kind: 'direct', ipv4: ['192.0.2.31'], ipv6: [], cnames: [] },
      { name: 'v6.example.com', kind: 'direct', ipv4: [], ipv6: ['2001:db8::10'], cnames: [] },
      { name: 'WWW.example.com', kind: 'direct', ipv4: ['192.0.2.10'], ipv6: [], cnames: [] }
    ] }] };
    assert.deepEqual(subdomainTlsHosts(doc), {
      hosts: ['www.example.com', 'shop.example.com', 'cdn.example.com', 'old.example.com', 'v6.example.com'], invalid: ['bad‮example.com'], cdn: 0, private: 1, problem: null
    });
    const noCdn = subdomainTlsHosts(doc, { skipCdn: true });
    assert.deepEqual([noCdn.hosts, noCdn.cdn], [['www.example.com', 'old.example.com', 'v6.example.com'], 2]);
    assert.match(subdomainTlsHosts({ ...doc, command: 'ct' }).problem, /a report of "ct", not of "subdomains"/);
    assert.match(subdomainTlsHosts([]).problem, /not a --json report/);
    assert.match(subdomainTlsHosts({ ...doc, targets: null }).problem, /no "targets" list/);
  });

  test('both are read and checked before anything is sent; a --ct file not written yet is a warning', async () => {
    const subs = { tool: DS_TOOL, version: DS_VERSION, command: 'subdomains', targets: [{ target: 'example.com', hosts: [
      { name: 'www.example.com', kind: 'direct', ipv4: ['192.0.2.10'], ipv6: [] }, { name: 'intranet.example.com', kind: 'private', ipv4: ['10.0.0.5'], ipv6: [] },
      { name: 'shop.example.com', kind: 'cloudflare', ipv4: ['198.51.100.7'], ipv6: [] }
    ] }] };
    const files = { 'subs.json': JSON.stringify(subs), 'ct.json': JSON.stringify(ctDoc), 'health.json': JSON.stringify({ tool: DS_TOOL, version: DS_VERSION, command: 'health', targets: [] }), 'junk.json': '{' };
    const run = async (options) => {
      const warnings = [];
      const got = await tlsInputs({ fromSubdomains: null, skipCdn: false, ct: null, ...options }, {
        read: async (path) => files[path], exists: async (path) => path in files, warn: (w) => warnings.push(w),
        skipped: (label, invalid, what) => invalid.map((x) => `${label}: skipped "${x}": not ${what}`)
      });
      return { got, warnings };
    };
    const one = await run({ fromSubdomains: 'subs.json', skipCdn: true, ct: 'ct.json' });
    assert.deepEqual([one.got.hosts, one.got.fromSubdomains, one.got.ct.file, one.got.ct.domains.length], [['www.example.com'], 'subs.json', 'ct.json', 2]);
    assert.deepEqual(one.warnings, [
      '--from-subdomains subs.json: 1 host with private addresses only left out (a hosted runner cannot reach them; --list them to check them from your own network)',
      '--from-subdomains subs.json: 1 host behind a CDN left out (--skip-cdn)'
    ]);
    const missing = await run({ ct: 'results/ct.json' });
    assert.equal(missing.got.ct, null);
    assert.deepEqual(missing.warnings, ['--ct results/ct.json: no such file: NOT_DEPLOYED is not checked this run (the ct check writes it; run that first)']);
    await assert.rejects(run({ ct: 'health.json' }), (err) => err instanceof UsageError && /--ct: cannot read certificates from health\.json: it is a report of "health", not of "ct" \(give a report written by "ct --json"\)/.test(err.message));
    await assert.rejects(run({ ct: 'junk.json' }), (err) => err instanceof UsageError && /--ct: junk\.json is not JSON/.test(err.message));
    await assert.rejects(run({ fromSubdomains: 'ct.json' }), (err) => err instanceof UsageError && /--from-subdomains: cannot read hosts from ct\.json: it is a report of "ct"/.test(err.message));
    await assert.rejects(run({ fromSubdomains: 'junk.json' }), (err) => err instanceof UsageError && /--from-subdomains: junk\.json is not JSON/.test(err.message));
  });
});

/* ------------------------------------------------------------------------ */
/* The monitor's changes                                                    */
/* ------------------------------------------------------------------------ */

describe('the monitor\'s changes', () => {
  const night = (at, endpoints, extra = {}, options = { ari: false, revocation: false, warnDays: 21 }) => report([tgt(endpoints, { checkedAt: at, ...extra })], at, options);

  test('EXPIRING once a certificate\'s automatic renewal is overdue inside --warn-days, listed before that; EXPIRED; said once', () => {
    const c = cert('a'); // 90 days, to 2026-11-30
    const served = (at) => night(at, [ep('192.0.2.10', 'OK', { cert: c }), ep('192.0.2.11', 'OK', { cert: c })]);
    assert.deepEqual(diffTls(served('2026-10-09T03:00:00.000Z'), served('2026-11-01T03:00:00.000Z')), [], '29 days left');
    const crossed = diffTls(served('2026-11-01T03:00:00.000Z'), served('2026-11-09T03:00:00.000Z'));
    assert.deepEqual(crossed.map((x) => [x.tag, x.tone, x.counts, x.item, x.after]), [['EXPIRING', 'bad', true, c.sha256, 'EXPIRING']]);
    assert.equal(changeText(crossed[0]), 'www.example.com: www.example.com (Example CA, expires 2026-11-30): 20 days left and not renewed (served by 192.0.2.10, 192.0.2.11)');
    assert.deepEqual(diffTls(served('2026-11-09T03:00:00.000Z'), served('2026-11-10T03:00:00.000Z')), [], 'said once');
    const expired = diffTls(served('2026-11-29T03:00:00.000Z'), served('2026-12-01T03:00:00.000Z'));
    assert.deepEqual(expired.map((x) => [x.tag, x.tone, x.counts]), [['EXPIRED', 'bad', true]]);
    assert.match(changeText(expired[0]), /: expired on 2026-11-30, still served by 192\.0\.2\.10, 192\.0\.2\.11$/);
    assert.deepEqual(diffTls(served('2026-11-01T03:00:00.000Z'), served('2026-12-01T03:00:00.000Z')).map((x) => x.tag), ['EXPIRED'], 'a night skipped: expired only');
    // a 47-day certificate inside 21 days is listed only until its renewal is overdue (11.75 days)
    const s = cert('b', { notBefore: '2026-10-01T00:00:00.000Z', notAfter: '2026-11-17T00:00:00.000Z' });
    const short = (at) => night(at, [ep('192.0.2.10', 'OK', { cert: s })]);
    const soon = diffTls(short('2026-10-20T03:00:00.000Z'), short('2026-10-27T03:00:00.000Z'));
    assert.deepEqual(soon.map((x) => [x.tag, x.counts, x.after]), [['EXPIRING', false, 'soon']]);
    assert.match(changeText(soon[0]), /: 20 days left; its automatic renewal is not overdue yet$/);
    assert.deepEqual(diffTls(short('2026-10-27T03:00:00.000Z'), short('2026-11-06T03:00:00.000Z')).map((x) => [x.tag, x.counts]), [['EXPIRING', true]]);
    // a short-lived certificate first served inside --warn-days says nothing
    const six = cert('c', { notBefore: '2026-10-08T00:00:00.000Z', notAfter: '2026-10-14T00:00:00.000Z' });
    assert.deepEqual(diffTls(night('2026-10-08T03:00:00.000Z', [ep('192.0.2.10', 'OK', { cert: c })]), night('2026-10-09T03:00:00.000Z', [ep('192.0.2.10', 'OK', { cert: six })])).map((x) => [x.tag, x.counts]),
      [['CERT', false]], 'the renewal of the day');
    // each run's own --warn-days
    const wide = { ari: false, revocation: false, warnDays: 30 };
    assert.deepEqual(diffTls(served('2026-11-01T03:00:00.000Z'), report([tgt([ep('192.0.2.10', 'OK', { cert: c })], { checkedAt: '2026-11-02T03:00:00.000Z' })], '2026-11-02T03:00:00.000Z', wide))
      .map((x) => [x.tag, x.counts]), [['GONE', false], ['EXPIRING', false]], '28 days left of 90: not overdue yet, listed');
    // a target new to the list with an expired certificate
    const fresh = report([served('2026-12-01T03:00:00.000Z').targets[0], { ...tgt([ep('192.0.2.30', 'EXPIRED', { cert: cert('d', { notAfter: '2026-11-20T00:00:00.000Z' }) })]), target: 'old.example.com', host: 'old.example.com', checkedAt: '2026-12-01T03:00:00.000Z' }], '2026-12-01T03:00:00.000Z', { warnDays: 21 });
    assert.deepEqual(diffTls(served('2026-11-29T23:00:00.000Z'), fresh).map((x) => [x.target, x.tag]), [['www.example.com', 'EXPIRED'], ['old.example.com', 'NEW'], ['old.example.com', 'EXPIRED']]);
    assert.deepEqual(diffTls(served('2026-11-30T01:00:00.000Z'), fresh).map((x) => [x.target, x.tag]), [['old.example.com', 'NEW'], ['old.example.com', 'EXPIRED']], 'the baseline saw it expired already');
  });

  test('UNTRUSTED, MISMATCH once per host and problem; a pool\'s rotating addresses repeat nothing; BETTER once none has it', () => {
    const c = cert('a');
    const okEp = (address) => ep(address, 'OK', { cert: c, trusted: true, trustError: null, nameMatch: true });
    const bad = (address, extra = {}) => ep(address, 'UNTRUSTED', { cert: c, trusted: false, trustError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', nameMatch: true,
      missingIntermediate: { name: 'Example R1', owner: 'Example CA', subjectDN: 'CN=Example R1,O=Example CA', added: 1 }, ...extra });
    const n1 = night('2026-10-08T03:00:00.000Z', [okEp('192.0.2.10'), okEp('192.0.2.11')]);
    const n2 = night('2026-10-09T03:00:00.000Z', [bad('192.0.2.10'), okEp('192.0.2.11')]);
    const untrusted = diffTls(n1, n2);
    assert.deepEqual(untrusted.map((x) => [x.tag, x.tone, x.counts, x.item, x.after]), [['UNTRUSTED', 'bad', true, null, 'UNTRUSTED']]);
    assert.equal(changeText(untrusted[0]), 'www.example.com: 192.0.2.10 serves a chain this machine does not trust (UNABLE_TO_VERIFY_LEAF_SIGNATURE); the intermediate Example R1 (Example CA) is not sent');
    // the pool rotates: a new address with the problem the host already had is nothing new; one read before that gets it is
    const n3 = night('2026-10-10T03:00:00.000Z', [bad('192.0.2.10'), okEp('192.0.2.11'), bad('192.0.2.12')]);
    assert.deepEqual(diffTls(n2, n3).map((x) => [x.tag, x.counts]), [['NEW', false]]);
    const n4 = night('2026-10-11T03:00:00.000Z', [bad('192.0.2.10'), bad('192.0.2.11'), bad('192.0.2.12')]);
    const second = diffTls(n3, n4);
    assert.deepEqual(second.map((x) => x.tag), ['UNTRUSTED']);
    assert.match(changeText(second[0]), /^www\.example\.com: 192\.0\.2\.11 serves a chain/);
    // fixed everywhere: BETTER — but not while an address that had it failed this run
    const n5 = night('2026-10-12T03:00:00.000Z', [okEp('192.0.2.10'), okEp('192.0.2.11'), ep('192.0.2.12', 'TIMEOUT', { error: 'no answer within 10 s' })]);
    assert.deepEqual(diffTls(n4, n5).map((x) => x.tag), ['FAILED']);
    const n6 = night('2026-10-13T03:00:00.000Z', [okEp('192.0.2.10'), okEp('192.0.2.11')]);
    const better = diffTls(n4, n6);
    assert.deepEqual(better.map((x) => [x.tag, x.tone, x.counts, x.item]), [['GONE', 'quiet', false, '192.0.2.12|443'], ['BETTER', 'good', true, null]]);
    assert.equal(changeText(better[1]), 'www.example.com: every address serves a trusted chain again');
    // a new address with the problem while the host had none: said
    assert.deepEqual(diffTls(n1, night('2026-10-09T03:00:00.000Z', [okEp('192.0.2.10'), okEp('192.0.2.11'), bad('192.0.2.13')])).map((x) => [x.tag, x.counts]), [['NEW', false], ['UNTRUSTED', true]]);
    // a certificate without the name
    const other = cert('b', { subject: 'mail.example.org', names: ['mail.example.org'] });
    const mismatch = diffTls(n1, night('2026-10-09T03:00:00.000Z', [ep('192.0.2.10', 'NAME_MISMATCH', { cert: other, trusted: true, trustError: null, nameMatch: false }), okEp('192.0.2.11')]));
    assert.deepEqual(mismatch.map((x) => [x.tag, x.counts, x.after]), [['CERT', true, other.sha256], ['MISMATCH', true, 'NAME_MISMATCH']]);
    assert.equal(changeText(mismatch[1]), 'www.example.com: 192.0.2.10 serves mail.example.org (Example CA, expires 2026-11-30), which does not cover the name');
    // a record of an earlier version: a name mismatch it took for a trust error is no untrusted chain
    const older = night('2026-10-08T03:00:00.000Z', [ep('192.0.2.10', 'UNTRUSTED', { cert: other, trusted: false, trustError: 'ERR_TLS_CERT_ALTNAME_INVALID', nameMatch: false })]);
    assert.deepEqual(diffTls(older, night('2026-10-09T03:00:00.000Z', [ep('192.0.2.10', 'NAME_MISMATCH', { cert: other, trusted: true, trustError: null, nameMatch: false })])), []);
    // a target new to the list with an untrusted chain
    const added = report([n1.targets[0], { ...tgt([bad('192.0.2.40'), bad('192.0.2.41')]), target: 'api.example.com', host: 'api.example.com' }], '2026-10-09T03:00:00.000Z', { warnDays: 21 });
    assert.deepEqual(diffTls(n1, added).map((x) => [x.target, x.tag]), [['api.example.com', 'NEW'], ['api.example.com', 'UNTRUSTED']]);
    assert.match(changeText(diffTls(n1, added)[1]), /^api\.example\.com: 192\.0\.2\.40, 192\.0\.2\.41 serve a chain/);
  });

  test('NOT-LIVE compares runs that both read CT; HTTP and REDIRECT runs that both asked; a weaker HSTS header is listed', () => {
    const c = cert('a');
    const newer = { id: 'a2', ca: 'Example CA', intermediate: 'Example R1', notBefore: '2026-10-05T00:00:00.000Z', notAfter: '2027-01-03T00:00:00.000Z', serialHex: '0a2' };
    const ct = { newest: newer };
    const live = (address, extra = {}) => ep(address, 'OK', { cert: c, trusted: true, trustError: null, nameMatch: true, ...extra });
    const n1 = night('2026-10-04T03:00:00.000Z', [live('192.0.2.10')], { ct: { newest: null } });
    const n2 = night('2026-10-09T03:00:00.000Z', [live('192.0.2.10', { status: 'NOT_DEPLOYED', newer })], { ct });
    const stale = diffTls(n1, n2);
    assert.deepEqual(stale.map((x) => [x.tag, x.tone, x.counts, x.item, x.after]), [['NOT-LIVE', 'bad', true, null, 'NOT_DEPLOYED']]);
    assert.equal(changeText(stale[0]), 'www.example.com: 192.0.2.10 still serves the certificate of 2026-09-01 (expires 2026-11-30); CT logged its renewal of 2026-10-05 (Example CA), not installed there');
    assert.deepEqual(diffTls(night('2026-10-04T03:00:00.000Z', [live('192.0.2.10')]), n2), [], 'the baseline did not read CT');
    const installed = night('2026-10-10T03:00:00.000Z', [ep('192.0.2.10', 'OK', { cert: cert('b', { notBefore: '2026-10-05T00:00:00.000Z', notAfter: '2027-01-03T00:00:00.000Z' }), trusted: true, nameMatch: true })], { ct });
    assert.deepEqual(diffTls(n2, installed).map((x) => [x.tag, x.tone]), [['CERT', 'quiet'], ['BETTER', 'good']]);
    // --http in both runs
    const web = { ari: false, revocation: false, warnDays: 21, http: true };
    const answer = (status, plain, hsts = { maxAge: 31536000, includeSubDomains: true, preload: false, valid: true }) => ({ status, error: null, hsts, plain });
    const h1 = night('2026-10-08T03:00:00.000Z', [live('192.0.2.10', { http: answer(200, { status: 301, location: 'https://www.example.com/', toHttps: true, error: null }) })], {}, web);
    const h2 = night('2026-10-09T03:00:00.000Z', [live('192.0.2.10', { http: answer(503, { status: 200, location: null, toHttps: false, error: null }, null) })], {}, web);
    const moved = diffTls(h1, h2);
    assert.deepEqual(moved.map((x) => [x.tag, x.tone, x.counts]), [['HTTP', 'bad', true], ['REDIRECT', 'bad', true], ['HSTS', 'info', false]]);
    assert.deepEqual(moved.map(changeText), [
      'www.example.com: 192.0.2.10: GET / answers 503',
      'www.example.com: 192.0.2.10: http:// answers 200 without a redirect to https://',
      'www.example.com: 192.0.2.10: Strict-Transport-Security max-age=31536000 → none'
    ]);
    assert.deepEqual(diffTls(h2, h1).map((x) => [x.tag, x.tone]), [['BETTER', 'good'], ['BETTER', 'good']]);
    assert.deepEqual(diffTls(h1, { ...h2, options: { ...web, http: false } }), [], 'one run did not ask');
    // port 80 refused is no lost redirect; a GET that failed is no 5xx
    const h3 = night('2026-10-09T03:00:00.000Z', [live('192.0.2.10', { http: { status: null, error: 'connection reset', hsts: null, plain: { status: null, location: null, toHttps: false, error: 'connection refused' } } })], {}, web);
    assert.deepEqual(diffTls(h1, h3), []);
  });

  test('a host --max-endpoints left out is carried like a DNS outage, said once; the notes; the baseline\'s new fields are checked', () => {
    const c = cert('a');
    const n1 = night('2026-10-08T03:00:00.000Z', [ep('192.0.2.10', 'OK', { cert: c })]);
    const capped = night('2026-10-09T03:00:00.000Z', n1.targets[0].endpoints, { carried: { from: '2026-10-08T03:00:00.000Z', why: 'max-endpoints' } });
    const out = diffTls(n1, capped);
    assert.deepEqual(out.map((x) => [x.tag, x.counts]), [['FAILED', false]]);
    assert.match(changeText(out[0]), /not checked this run \(--max-endpoints: the run had checked as many endpoints as it may\): the next run compares with the last check$/);
    assert.deepEqual(diffTls(capped, { ...capped, startedAt: '2026-10-10T03:00:00.000Z' }), [], 'said once');
    assert.match(changeText(diffTls(capped, night('2026-10-10T03:00:00.000Z', [ep('192.0.2.10', 'OK', { cert: c })]))[0]), /checked again; compared with the check of 2026-10-08$/);
    const dnsAfterCap = night('2026-10-10T03:00:00.000Z', n1.targets[0].endpoints, { carried: { from: '2026-10-08T03:00:00.000Z' }, dns: { status: 'SERVFAIL', ipv4: [], ipv6: [], cnames: [], error: 'x' } });
    assert.match(changeText(diffTls(capped, dnsAfterCap)[0]), /DNS lookup failed this run \(SERVFAIL\)/, 'another reason is said');
    const newCapped = report([n1.targets[0], { ...tgt([]), target: 'new.example.com', host: 'new.example.com', carried: { from: null, why: 'max-endpoints' } }]);
    assert.match(changeText(diffTls(n1, newCapped)[0]), /new\.example\.com: now listed, not checked this run \(--max-endpoints\)$/);
    assert.deepEqual(tlsNotes({ ari: false, revocation: false, warnDays: 21, ct: null, http: false }, { ari: false, revocation: false, warnDays: 30, ct: { file: 'ct.json' }, http: true }), [
      'The warning days differ from the baseline\'s (21 → 30, --warn-days): EXPIRING can come from that.',
      'CT was read in this run only (--ct): NOT-LIVE compares runs that both read it.',
      'HTTP was asked in this run only (--http): HTTP and REDIRECT compare runs that both asked it.'
    ]);
    assert.deepEqual(tlsNotes({ ari: true, revocation: true }, { ari: true, revocation: true, warnDays: 21, ct: null, http: false }), [], 'a report of the version before: the defaults');
    const bad = (endpoints, extra = {}) => baselineProblem(report([tgt(endpoints, extra)]), 'tls');
    assert.match(bad([ep('192.0.2.10', 'OK', { newer: 'a2' })]), /endpoints\[0\] has a "newer" that is not an object/);
    assert.match(bad([ep('192.0.2.10', 'OK', { http: { plain: 301 } })]), /endpoints\[0\] has an "http\.plain" that is not an object/);
    assert.match(bad([], { ct: 'ct.json' }), /has a "ct" that is not an object/);
  });

  test('PagerDuty: a host\'s problem is over once no address read has it, a certificate\'s expiry once it is no longer served; severities', () => {
    const c = cert('a');
    const key = (tag, item = null) => ({ tag, item });
    const x = (endpoints, extra = {}) => tgt(endpoints, extra);
    const untrusted = ep('192.0.2.10', 'UNTRUSTED', { cert: c, trusted: false, trustError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
    const fine = ep('192.0.2.10', 'OK', { cert: c, trusted: true });
    assert.equal(problemStanding('tls', x([untrusted]), key('UNTRUSTED')), 'bad');
    assert.equal(problemStanding('tls', x([fine]), key('UNTRUSTED')), 'over');
    assert.equal(problemStanding('tls', x([fine, ep('192.0.2.11', 'TIMEOUT')]), key('UNTRUSTED')), 'over', 'a dead pool member is not waited for');
    assert.equal(problemStanding('tls', x([ep('192.0.2.10', 'TIMEOUT')]), key('UNTRUSTED')), 'unknown', 'nothing read');
    assert.equal(problemStanding('tls', x([untrusted], { carried: { from: null } }), key('UNTRUSTED')), 'unknown');
    assert.equal(problemStanding('tls', x([ep('192.0.2.10', 'NAME_MISMATCH', { cert: c, nameMatch: false })]), key('MISMATCH')), 'bad');
    const stale = ep('192.0.2.10', 'NOT_DEPLOYED', { cert: c, newer: { id: 'a2' } });
    assert.equal(problemStanding('tls', x([stale], { ct: { newest: null } }), key('NOT-LIVE')), 'bad');
    assert.equal(problemStanding('tls', x([fine], { ct: { newest: null } }), key('NOT-LIVE')), 'over');
    assert.equal(problemStanding('tls', x([fine]), key('NOT-LIVE')), 'unknown', 'a run that did not read CT');
    const web = (status, plain = null) => ep('192.0.2.10', 'OK', { cert: c, http: { status, error: null, hsts: null, plain } });
    assert.equal(problemStanding('tls', x([web(503)]), key('HTTP')), 'bad');
    assert.equal(problemStanding('tls', x([web(200)]), key('HTTP')), 'over');
    assert.equal(problemStanding('tls', x([fine]), key('HTTP')), 'unknown', 'a run that did not ask');
    assert.equal(problemStanding('tls', x([web(200, { status: 200, location: null, toHttps: false, error: null })]), key('REDIRECT')), 'bad');
    assert.equal(problemStanding('tls', x([web(200, { status: 301, location: 'https://www.example.com/', toHttps: true, error: null })]), key('REDIRECT')), 'over');
    assert.equal(problemStanding('tls', x([fine]), key('EXPIRING', c.sha256)), 'bad', 'still served');
    assert.equal(problemStanding('tls', x([ep('192.0.2.10', 'OK', { cert: cert('b') })]), key('EXPIRED', c.sha256)), 'over', 'renewed');
    assert.equal(eventSeverity({ tag: 'UNTRUSTED', item: null, after: 'UNTRUSTED' }, 'tls'), 'critical');
    assert.equal(eventSeverity({ tag: 'EXPIRED', item: c.sha256, after: 'EXPIRED' }, 'tls'), 'critical');
    for (const tag of ['EXPIRING', 'MISMATCH', 'NOT-LIVE', 'HTTP', 'REDIRECT']) assert.equal(eventSeverity({ tag, item: null, after: null }, 'tls'), 'error', tag);
  });
});

/* ------------------------------------------------------------------------ */
/* The monitor's runs                                                       */
/* ------------------------------------------------------------------------ */

test('--max-endpoints: the hosts past it keep their last check, said once; one never checked is left out', async () => {
  const t = await setupStrings();
  const fetchImpl = createFakeFetch({ 'a.example.com': { A: ['192.0.2.10', '192.0.2.11'] }, 'b.example.com': { A: ['192.0.2.12'] }, 'c.example.com': { A: ['192.0.2.13'] } }, { apex: 'example.com' });
  const { DohClient } = await import('../../assets/js/lib/doh.js');
  const dns = new DohClient({ chain: ['cloudflare'], fetchImpl });
  const asked = [];
  const refused = (opts) => {
    asked.push(opts.host);
    const s = new EventEmitter();
    s.destroy = () => {};
    setImmediate(() => s.emit('error', Object.assign(new Error(`connect ECONNREFUSED ${opts.host}:443`), { code: 'ECONNREFUSED' })));
    return s;
  };
  const baseline = report([{ ...tgt([ep('192.0.2.12', 'OK', { cert: cert('b') })]), target: 'b.example.com', host: 'b.example.com', checkedAt: '2026-10-08T03:00:00.000Z' }], '2026-10-08T03:00:00.000Z');
  const env = { dns, fetchImpl, now: () => NOW, t, progress: () => {}, baseline, inputs: {}, tls: { connect: refused } };
  const res = await runTls(['a.example.com', 'b.example.com', 'c.example.com'], { ari: false, revocation: false, chain: ['cloudflare'], maxEndpoints: 2, warnDays: 21 }, env);
  assert.deepEqual(asked.sort(), ['192.0.2.10', '192.0.2.11'], 'two handshakes, the first host\'s');
  assert.deepEqual(res.targets.map((x) => [x.target, x.carried || null]), [['a.example.com', null], ['b.example.com', { from: '2026-10-08T03:00:00.000Z', why: 'max-endpoints' }]]);
  assert.deepEqual(res.targets[1].endpoints, baseline.targets[0].endpoints, 'the last check kept');
  assert.deepEqual(res.warnings, ['--max-endpoints 2: 2 targets (2 addresses) not checked this run, from b.example.com on; their last check is kept for the next comparison (raise --max-endpoints, or split the list)']);
  assert.match(renderMarkdown(res.docs[1]), /not checked this run \(--max-endpoints\); the endpoints of the last check \(2026-10-08\) are kept for the next comparison/);
  const changes = diffTls(baseline, { ...report(res.targets), options: res.options });
  assert.deepEqual(changes.map((x) => [x.target, x.tag, x.counts]), [['a.example.com', 'NEW', true], ['b.example.com', 'FAILED', false]]);
});

describe('three nights of `tls --ct --http` over a local server: a missing intermediate, a renewal not installed, a 5xx and a lost redirect', () => {
  const answer = { status: 200, headers: { 'Strict-Transport-Security': 'max-age=31536000' } };
  const redirect = { status: 301, location: 'https://www.example.com/' };
  const full = { cert: Buffer.concat([CROSS_LEAF_PEM, CROSS_INTER_PEM]), key: CROSS_LEAF_KEY };
  let web;
  let plain;
  let dir;
  before(async () => {
    web = await httpsServer({ ...full, answer });
    plain = await plainServer(redirect);
    dir = mkdtempSync(join(tmpdir(), 'ds-tls-monitor-'));
  });
  after(async () => {
    await web.close();
    await plain.close();
    rmSync(dir, { recursive: true, force: true });
  });

  /** The same night's ct report: the served certificate, and `renewal` when CT has logged one. */
  function writeCt(renewal) {
    const row = (id, notBefore, notAfter) => ({ id, ca: 'Example Test PKI', intermediate: 'Example Test Cross Issuing CA', issuer: 'CN=Example Test Cross Issuing CA,O=Example Test PKI',
      notBefore, notAfter, names: ['example.com', 'www.example.com'], sha256: null, serialHex: null, sources: ['crtsh'], revoked: null, precert: null });
    const doc = { tool: DS_TOOL, version: DS_VERSION, command: 'ct', startedAt: '2026-10-08T02:40:00.000Z', finishedAt: '2026-10-08T02:50:00.000Z', options: {},
      targets: [{ target: 'example.com', names: [], readAt: null, certificates: [row('served', '2025-01-01T00:00:00.000Z', '2060-01-01T00:00:00.000Z'),
        ...(renewal ? [row('renewal', '2026-10-05T00:00:00.000Z', '2027-01-03T00:00:00.000Z')] : [])] }] };
    writeFileSync(join(dir, 'ct.json'), JSON.stringify(doc));
  }

  async function run(argv, now, sent) {
    const fetchImpl = createFakeFetch({ 'www.example.com': { A: ['127.0.0.1'] } }, {
      apex: 'example.com',
      other: (url, init) => {
        if (!String(url).startsWith('https://events.pagerduty.com/')) return new Response('not found', { status: 404 });
        sent.push(JSON.parse(init.body));
        return new Response('{"status":"success"}', { status: 202 });
      }
    });
    let out = '';
    let err = '';
    const code = await main(argv, {
      stdout: { isTTY: false, write: (s) => { out += s; return true; } }, stderr: { write: (s) => { err += s; return true; } }, fetchImpl, env: {}, now: () => now,
      tls: {
        ca: [CROSS_ROOT_PEM], intermediates: crossStore(), request: requestVia(plain.port),
        // the target is www.example.com on 443: the local server's port stands in for it
        connect: (opts, cb) => tls.connect({ ...opts, port: opts.port === 443 ? web.port : opts.port }, cb)
      }
    });
    return { code, out, err };
  }

  test('night 1 all well; night 2 every problem counted and paged; night 3 fixed but the renewal, each incident resolved but its', async () => {
    const json = join(dir, 'tls.json');
    const md = join(dir, 'tls.md');
    const url = 'https://events.pagerduty.com/v2/enqueue?routing_key=' + 'R0UT1NGKEY' + 'y'.repeat(22);
    const argv = ['tls', 'www.example.com', '--ct', join(dir, 'ct.json'), '--http', '--baseline', json, '--json', json, '--md', md, '--fail-on-change', '--notify-bad', url, '--no-color'];
    const sent = [];
    writeCt(false);
    const n1 = await run(argv, AT('2026-10-08T03:00:00Z'), sent);
    assert.equal(n1.code, EXIT.OK, n1.err);
    assert.match(n1.out, /TLS · www\.example\.com\n- www\.example\.com · Example Test PKI · expires 2060-01-01 \(\d+ days left\) · 127\.0\.0\.1\n- TLSv1\.[23] · [^\n]+ · chain sent: 2 certificates · OCSP staple: no\n- GET \/ 200 · HSTS max-age=31536000 · http:\/\/ redirects to https:\/\/ \(301\)\n/);
    const r1 = JSON.parse(readFileSync(json, 'utf8'));
    assert.deepEqual(r1.options, { ari: false, revocation: false, warnDays: 21, http: true, ct: { file: 'ct.json', finishedAt: '2026-10-08T02:50:00.000Z' }, fromSubdomains: null, skipCdn: false, maxEndpoints: 500,
      resolvers: ['cloudflare', 'google', 'dnssb'] });
    const e1 = r1.targets[0].endpoints[0];
    assert.deepEqual([e1.status, e1.trusted, e1.chainSent, e1.chainLength, e1.ocspStapled, e1.http.status, e1.http.plain.toHttps], ['OK', true, 2, 3, false, 200, true]);
    assert.deepEqual(r1.targets[0].ct, { newest: { id: 'served', ca: 'Example Test PKI', intermediate: 'Example Test Cross Issuing CA', notBefore: '2025-01-01T00:00:00.000Z', notAfter: '2060-01-01T00:00:00.000Z', serialHex: null } });
    assert.deepEqual(sent, []);

    // night 2: the server sends its leaf alone, answers 503 without HSTS, port 80 no longer redirects; CT has logged the renewal
    web.setCert({ cert: CROSS_LEAF_PEM });
    Object.assign(answer, { status: 503, headers: {} });
    Object.assign(redirect, { status: 200, location: null });
    writeCt(true);
    const n2 = await run(argv, AT('2026-10-09T03:00:00Z'), sent);
    assert.equal(n2.code, EXIT.CHANGED, n2.err);
    const r2 = JSON.parse(readFileSync(json, 'utf8'));
    assert.deepEqual(r2.changes.map((c) => [c.tag, c.counts]), [['UNTRUSTED', true], ['NOT-LIVE', true], ['HTTP', true], ['REDIRECT', true], ['HSTS', false]]);
    const e2 = r2.targets[0].endpoints[0];
    assert.deepEqual([e2.status, e2.trustError, e2.chainSent, e2.missingIntermediate, e2.newer.id], ['UNTRUSTED', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 1,
      { name: 'Example Test Cross Issuing CA', owner: 'Example Test PKI', subjectDN: 'CN=Example Test Cross Issuing CA,O=Example Test PKI', added: 1 }, 'renewal']);
    assert.match(n2.out, /\n {2}UNTRUSTED {2}www\.example\.com: 127\.0\.0\.1 serves a chain this machine does not trust \(UNABLE_TO_VERIFY_LEAF_SIGNATURE\); the intermediate Example Test Cross Issuing CA \(Example Test PKI\) is not sent\n/);
    assert.match(n2.out, /- The intermediate Example Test Cross Issuing CA \(Example Test PKI\) is not sent by 127\.0\.0\.1: named from the CCADB list; add it to the certificate file\n/);
    assert.match(n2.out, /- CT logged its renewal of 2026-10-05 \(Example Test PKI, expires 2027-01-03\): not installed on 127\.0\.0\.1\n/);
    assert.match(readFileSync(md, 'utf8'), /- \*\*NOT-LIVE\*\* `www\.example\.com`: `127\.0\.0\.1` still serves the certificate of 2025-01-01 \(expires 2060-01-01\); CT logged its renewal of 2026-10-05 \(`Example Test PKI`\), not installed there/);
    assert.deepEqual(sent.map((e) => [e.event_action, e.payload.custom_details.tag, e.payload.severity, e.payload.custom_details.item]),
      [['trigger', 'UNTRUSTED', 'critical', null], ['trigger', 'NOT-LIVE', 'error', null], ['trigger', 'HTTP', 'error', null], ['trigger', 'REDIRECT', 'error', null]]);
    assert.deepEqual(r2.notify.open.map((k) => k.tag), ['UNTRUSTED', 'NOT-LIVE', 'HTTP', 'REDIRECT']);

    // night 3: the chain, the page and the redirect are fixed; the renewal is still not installed
    sent.length = 0;
    web.setCert(full);
    Object.assign(answer, { status: 200, headers: { 'Strict-Transport-Security': 'max-age=31536000' } });
    Object.assign(redirect, { status: 301, location: 'https://www.example.com/' });
    const n3 = await run(argv, AT('2026-10-10T03:00:00Z'), sent);
    assert.equal(n3.code, EXIT.CHANGED, n3.err);
    const r3 = JSON.parse(readFileSync(json, 'utf8'));
    assert.deepEqual(r3.changes.map((c) => [c.tag, c.tone]), [['BETTER', 'good'], ['BETTER', 'good'], ['BETTER', 'good']]);
    assert.deepEqual(r3.targets[0].endpoints[0].status, 'NOT_DEPLOYED');
    assert.deepEqual(sent.map((e) => e.event_action), ['resolve', 'resolve', 'resolve']);
    assert.deepEqual(r3.notify.open.map((k) => k.tag), ['NOT-LIVE'], 'the renewal is still not installed');
    assert.ok(!(n1.out + n1.err + n2.out + n2.err + n3.out + n3.err).includes('R0UT1NGKEY'), 'the routing key is never printed');
  });
});
