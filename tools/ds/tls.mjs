/**
 * tools/ds/tls.mjs — the runner's `tls` command, the served-certificate monitor: the certificate each
 * public endpoint serves, as the job sees it — its expiry, trust and name, the chain sent, OCSP
 * stapling, the protocol and key exchange —, with `--ct` whether a renewal CT logged is installed
 * (tools/ds/tlsct.mjs), with `--http` what `GET /` answers (tools/ds/tlshttp.mjs), and with `--ari` /
 * `--revocation` what the issuing CA says about it: its ACME Renewal Information window
 * (tools/ds/ari.mjs) and whether its CRL lists it (tools/ds/revocation.mjs).
 *
 * - TARGET is `host`, `host:port`, `[v6]:port` or an address (`192.0.2.10:8443`: no SNI, the
 *   server's default certificate); the port defaults to 443 ({@link parseTlsTarget}). More hosts come
 *   from `--from-subdomains` (the hosts with an address of a `subdomains` report; `--skip-cdn` leaves
 *   out the ones behind a CDN, {@link subdomainTlsHosts}).
 * - A host's A and AAAA records come from the run's DohClient; each address is asked on its own
 *   with SNI = the host, so a pool member still serving an old certificate shows. GitHub's hosted
 *   runners have no IPv6 route: an IPv6 address the job cannot reach is SKIPPED (`no-ipv6-route`),
 *   said once per run, never a failure or a change. At most `--max-endpoints` handshakes a run: the
 *   hosts past it keep the endpoints of their last check (`carried`, `why: 'max-endpoints'`).
 * - The handshake: node:tls with `rejectUnauthorized: false` (the certificate is read whatever it
 *   is), `requestOCSP` (a staple is reported, never checked: Let's Encrypt has had no OCSP since
 *   2025-08-06), ALPN http/1.1 (the `--http` GET goes over the same connection), {@link TLS_TIMEOUT_MS}
 *   per endpoint, {@link TLS_CONCURRENCY} at once. The status, worst first: EXPIRED (by the run's
 *   clock), UNTRUSTED (Node's root store says why, its code kept: UNABLE_TO_VERIFY_LEAF_SIGNATURE is a
 *   missing intermediate, named from the CCADB list the site ships, lib/chainfix.js), NAME_MISMATCH
 *   (tls.checkServerIdentity, called whatever the chain, since Node checks the name only of a trusted
 *   one), NOT_DEPLOYED (`--ct`: an older certificate than the renewal CT logged), EXPIRING (at most
 *   `--warn-days` days left with its automatic renewal overdue, tools/ds/tlsdiff.mjs expiryState), OK;
 *   or no certificate: TLS_ERROR, TIMEOUT, CLOSED, SKIPPED.
 * - ARI and revocation are asked once per distinct certificate of the run, and every endpoint
 *   serving it carries the answer. An endpoint that did not answer keeps, as `lastGood`, the
 *   certificate (with its ARI and revocation) the last run that reached it saw; a host whose DNS
 *   lookup failed keeps the baseline's endpoints (`carried`): the next run compares with that.
 *
 * The changes (EXPIRING, EXPIRED, UNTRUSTED, MISMATCH, NOT-LIVE, HTTP, REDIRECT, RENEW-NOW, MOVED-UP,
 * CA-NOTICE, REVOKED, CERT …): tools/ds/tlsdiff.mjs.
 */

import tls from 'node:tls';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseCertificate } from '../../assets/js/lib/x509.js';
import { caForIssuer } from '../../assets/js/lib/renewal.js';
import { ariCertId } from '../../assets/js/lib/renewalplan.js';
import { issuerName } from '../../assets/js/lib/passport.js';
import { normalizeHostname } from '../../assets/js/lib/domain.js';
import { createLimiter, throwIfAborted, AbortError } from '../../assets/js/lib/util.js';
import { createAriClient, windowState, ARI_CONCURRENCY } from './ari.mjs';
import { createRevocationChecker, CRL_MAX_BYTES } from './revocation.mjs';
import { TLS_STATUSES, TLS_FAILED, NAME_ERRORS, expiryState, isUntrusted, isMismatch, isNotDeployed } from './tlsdiff.mjs';
import { ctReportProblem, ctLookup, newestInCt, renewalNotDeployed } from './tlsct.mjs';
import { getOverTls, getPlain, httpRecord, hostHeader, HTTP_TIMEOUT_MS } from './tlshttp.mjs';
import { parseTlsTarget, parseTargets, UsageError, DS_TOOL, DS_VERSION } from './args.mjs';
import { code, strong, isoDay, isoTime, summaryDoc } from './render.mjs';

export { TLS_STATUSES, TLS_FAILED };

/** Time for one handshake. */
export const TLS_TIMEOUT_MS = 10000;
/** Handshakes in flight at once. */
export const TLS_CONCURRENCY = 8;
/** Certificates of a chain read at most (a hostile server's chain is not walked forever). */
const MAX_CHAIN = 10;
const DAY_MS = 86400000;
/** The `--from-subdomains` host kinds behind a CDN's edge (lib/netinfo.js classifyResolution), left out with `--skip-cdn`. */
export const CDN_KINDS = Object.freeze(['cloudflare', 'cdn']);

/** Why a connection failed, as a status: CLOSED, TIMEOUT, SKIPPED (no IPv6 route) or TLS_ERROR. */
function failureOf(err, family) {
  const errCode = err && typeof err.code === 'string' ? err.code : '';
  const message = String((err && err.message) || err || 'error').replace(/\s+/g, ' ').slice(0, 200);
  if (family === 6 && ['ENETUNREACH', 'EHOSTUNREACH', 'EADDRNOTAVAIL', 'EAFNOSUPPORT'].includes(errCode)) {
    return { status: 'SKIPPED', error: 'no-ipv6-route' };
  }
  if (errCode === 'ECONNREFUSED') return { status: 'CLOSED', error: 'connection refused' };
  if (['ENETUNREACH', 'EHOSTUNREACH'].includes(errCode)) return { status: 'CLOSED', error: errCode === 'ENETUNREACH' ? 'network unreachable' : 'host unreachable' };
  if (errCode === 'ETIMEDOUT') return { status: 'TIMEOUT', error: 'no answer' };
  return { status: 'TLS_ERROR', error: errCode ? `${errCode}: ${message}`.slice(0, 200) : message };
}

/**
 * What a completed handshake says (synchronous, in the secureConnect callback): the chain as Node
 * built it (getPeerCertificate: what the server sent that chains up from the leaf, and the root
 * from the trust store), then the certificates as the server sent them (getPeerX509Certificate,
 * which must come second: it takes them out of the connection's list), the trust, the name, the
 * protocol, the cipher and the key exchange.
 * @param {import('node:tls').TLSSocket} socket
 * @param {string|null} servername
 * @returns {object}
 */
function readSocket(socket, servername) {
  const peer = socket.getPeerCertificate(true);
  const chain = [];
  const seen = new Set();
  for (let x = peer; x && x.raw && !seen.has(x.fingerprint256) && chain.length < MAX_CHAIN; x = x.issuerCertificate) {
    seen.add(x.fingerprint256);
    chain.push(new Uint8Array(x.raw));
  }
  if (!chain.length) return { status: 'TLS_ERROR', error: 'the server sent no certificate' };
  let sent = null;
  try {
    const x509 = typeof socket.getPeerX509Certificate === 'function' ? socket.getPeerX509Certificate() : null;
    if (x509 && x509.raw) {
      sent = [];
      for (let c = x509; c && c.raw && sent.length < MAX_CHAIN; c = c.issuerCertificate) sent.push(new Uint8Array(c.raw));
    }
  } catch {
    sent = null;
  }
  const authError = socket.authorizationError ? String(socket.authorizationError.code || socket.authorizationError) : null;
  // Node sets a name error only on a trusted chain: the chain is trusted, the name is checked below
  const nameOnly = NAME_ERRORS.includes(authError);
  const identity = servername ? tls.checkServerIdentity(servername, peer) : undefined;
  const cipher = typeof socket.getCipher === 'function' ? socket.getCipher() : null;
  const eph = typeof socket.getEphemeralKeyInfo === 'function' ? socket.getEphemeralKeyInfo() : null;
  return {
    status: 'OK',
    error: null,
    protocol: typeof socket.getProtocol === 'function' ? socket.getProtocol() || null : null,
    cipher: cipher && cipher.name ? cipher.name : null,
    ephemeralKey: eph && eph.name ? { type: eph.type || null, name: String(eph.name), size: Number.isInteger(eph.size) ? eph.size : null } : null,
    authorized: socket.authorized === true || nameOnly,
    authorizationError: nameOnly ? null : authError,
    nameMatch: servername ? !identity : null,
    chain,
    sent
  };
}

/**
 * One TLS handshake with `address:port`, SNI `servername` (none for an address target), and with
 * `http` a `GET /` over it. Resolves with the chain the server sent (DER, the leaf first: as Node
 * built it, `chain`, and as sent, `sent`), what Node said of it, the OCSP staple and the GET's answer
 * (`https`), or a failure status; rejects only on an abort.
 * @param {{ address: string, port: number, servername: string|null, timeoutMs?: number, connect?: typeof tls.connect,
 *   signal?: AbortSignal, ca?: string|Buffer|Array, http?: boolean, httpTimeoutMs?: number, request?: Function }} opts
 *   `ca`: a trust store instead of Node's (tests); `request`: node:http's request (tests)
 * @returns {Promise<{ status: string, error: string|null, protocol?: string|null, cipher?: string|null, ephemeralKey?: object|null,
 *   authorized?: boolean, authorizationError?: string|null, nameMatch?: boolean|null, chain?: Uint8Array[], sent?: Uint8Array[]|null,
 *   ocspStapled?: boolean|null, https?: object }>}
 */
export function handshake({ address, port, servername, timeoutMs = TLS_TIMEOUT_MS, connect = tls.connect, signal, ca, http = false, httpTimeoutMs = HTTP_TIMEOUT_MS, request }) {
  return new Promise((resolve, reject) => {
    throwIfAborted(signal);
    const family = isIP(address);
    let socket = null;
    let done = false;
    let stapled = null;
    const finish = (value, rejected = false) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      try {
        if (socket) socket.destroy();
      } catch {
        /* already closed */
      }
      if (rejected) reject(value);
      else resolve(value);
    };
    const onAbort = () => finish(new AbortError('The operation was aborted'), true);
    const onError = (err) => finish(failureOf(err, family));
    const onClose = () => finish({ status: 'TLS_ERROR', error: 'the connection closed during the handshake' });
    const timer = setTimeout(() => finish({ status: 'TIMEOUT', error: `no answer within ${Math.round(timeoutMs / 1000)} s` }), timeoutMs);
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    try {
      socket = connect({
        host: address, port, rejectUnauthorized: false, requestOCSP: true, ALPNProtocols: ['http/1.1'],
        ...(servername ? { servername } : {}), ...(ca ? { ca } : {})
      }, () => {
        let facts;
        try {
          facts = readSocket(socket, servername);
        } catch (err) {
          finish({ status: 'TLS_ERROR', error: String((err && err.message) || err).slice(0, 200) });
          return;
        }
        facts.ocspStapled = stapled;
        if (facts.status !== 'OK' || !http) {
          finish(facts);
          return;
        }
        // the handshake is done: the GET has a time limit of its own and reports its own failure
        clearTimeout(timer);
        socket.removeListener('error', onError);
        socket.removeListener('close', onClose);
        socket.on('error', () => {});
        getOverTls(socket, { host: servername, address, port, timeoutMs: httpTimeoutMs, request, signal })
          .then((answer) => finish({ ...facts, https: answer }), (err) => finish(err, true));
      });
      // fired during the handshake, before secureConnect: the server's staple, or null without one
      socket.on('OCSPResponse', (resp) => {
        stapled = !!(resp && resp.length);
      });
      socket.on('error', onError);
      socket.on('close', onClose);
    } catch (err) {
      finish(failureOf(err, family));
    }
  });
}

/**
 * What the report keeps of a served certificate.
 * @param {object} leaf lib/x509.js Certificate
 * @param {string} sha256
 * @param {number} at the run's time (ms)
 * @returns {object}
 */
export function certRecord(leaf, sha256, at) {
  return {
    sha256,
    serialHex: leaf.serialHex,
    subject: leaf.subjectCN || leaf.subjectDN || null,
    issuer: leaf.issuerDN,
    ca: issuerName(leaf.issuerDN),
    caId: caForIssuer(leaf.issuerDN) || null,
    names: [...leaf.hostnames],
    notBefore: isoTime(leaf.notBefore),
    notAfter: isoTime(leaf.notAfter),
    daysLeft: Math.floor((leaf.notAfter.getTime() - at) / DAY_MS),
    keyType: leaf.keyAlgorithm,
    keyBits: leaf.keyBits,
    curve: leaf.curve,
    authorityKeyId: leaf.authorityKeyId,
    crlUrls: [...leaf.crlUrls]
  };
}

/** Node's verify errors that are the certificate's dates, not its chain. */
const TIME_ONLY = Object.freeze(['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID']);

/**
 * The status of a completed handshake at `at`, worst first.
 * @param {object} h {@link handshake}'s result
 * @param {object} cert {@link certRecord}
 * @param {number} at
 * @param {{ warnDays: number, newer: object|null }} opts `newer`: the renewal CT logged ({@link renewalNotDeployed})
 * @returns {{ status: string, trustError: string|null }}
 */
export function statusOf(h, cert, at, { warnDays, newer = null }) {
  if (Date.parse(cert.notAfter) < at) return { status: 'EXPIRED', trustError: h.authorizationError || 'CERT_HAS_EXPIRED' };
  if (Date.parse(cert.notBefore) > at) return { status: 'UNTRUSTED', trustError: 'CERT_NOT_YET_VALID' };
  if (!h.authorized && h.authorizationError && !TIME_ONLY.includes(h.authorizationError)) return { status: 'UNTRUSTED', trustError: h.authorizationError };
  if (h.nameMatch === false) return { status: 'NAME_MISMATCH', trustError: null };
  if (newer) return { status: 'NOT_DEPLOYED', trustError: null };
  if (expiryState(cert, at, warnDays) === 'expiring') return { status: 'EXPIRING', trustError: null };
  return { status: 'OK', trustError: null };
}

/** The baseline's endpoint records of a target, by `address|port`. */
const endpointKey = (e) => `${e.address}|${e.port}`;

/** Every ARI record the baseline holds (endpoints and their last good answers), by CertID: the newest. */
function baselineAris(baseline) {
  const out = new Map();
  for (const x of (baseline && Array.isArray(baseline.targets) ? baseline.targets : [])) {
    for (const e of Array.isArray(x.endpoints) ? x.endpoints : []) {
      for (const ari of [e && e.ari, e && e.lastGood && e.lastGood.ari]) {
        if (!ari || typeof ari !== 'object' || typeof ari.certId !== 'string') continue;
        const had = out.get(ari.certId);
        if (!had || String(ari.checkedAt) > String(had.checkedAt)) out.set(ari.certId, ari);
      }
    }
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* The missing intermediate                                                 */
/* ------------------------------------------------------------------------ */

/** A fetch of the files of the site's own intermediates dataset (file:// URLs under assets/data/intermediates/). */
async function fileFetch(url) {
  return new Response(await readFile(fileURLToPath(url)), { status: 200, headers: { 'content-type': 'application/json' } });
}

/**
 * Name the intermediate a server does not send (Node: UNABLE_TO_VERIFY_LEAF_SIGNATURE) from the
 * CCADB list the site ships (lib/chainfix.js repairChain over the certificates as sent): `{ name,
 * owner, subjectDN, added }` of the first certificate the chain lacks (`added`: how many it lacks),
 * or null when the list has no issuer for it (a private CA, or an intermediate the list does not
 * have). Each distinct chain is looked up once.
 * @param {Array<{ key: string, leaf: object, certs: object[] }>} items
 * @param {{ store?: object, now: number }} opts `store`: a lib/chainfix.js createIntermediateStore (tests)
 * @returns {Promise<{ found: Map<string, object|null>, error: string|null }>}
 */
export async function nameMissingIntermediates(items, { store = null, now }) {
  const found = new Map();
  if (!items.length) return { found, error: null };
  const chainfix = await import('../../assets/js/lib/chainfix.js');
  const list = store || chainfix.createIntermediateStore({ fetchImpl: fileFetch });
  try {
    for (const { key, leaf, certs } of items) {
      if (found.has(key)) continue;
      const repair = await chainfix.repairChain({ certificates: certs, leaf }, { store: list, now });
      const first = repair.status === 'repaired' && repair.reason === 'missing' && repair.added.length ? repair.added[0] : null;
      found.set(key, first ? {
        name: first.cert.subjectCN || first.cert.subjectDN, owner: first.owner || null, subjectDN: first.cert.subjectDN, added: repair.added.length
      } : null);
    }
    return { found, error: null };
  } catch (err) {
    return { found, error: String((err && err.message) || err).slice(0, 200) };
  }
}

/* ------------------------------------------------------------------------ */
/* Inputs                                                                   */
/* ------------------------------------------------------------------------ */

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const hasAddress = (h) => isObj(h) && ((Array.isArray(h.ipv4) && h.ipv4.length > 0) || (Array.isArray(h.ipv6) && h.ipv6.length > 0));

/**
 * The hosts of a `subdomains` report of this runner worth a handshake: every host with an address,
 * or with one in the answer it carried while its lookup failed (`lastGood`); wildcard look-alikes
 * left out, the hosts whose addresses are all private (`kind` private: a hosted runner cannot reach
 * them) too, and with `skipCdn` the ones behind a CDN's edge ({@link CDN_KINDS}: the CDN's
 * certificate, which it renews). A name that is no host name is never sent: it is listed in
 * `invalid` (the caller warns, quoted without its control characters).
 * @param {any} doc the parsed report
 * @param {{ skipCdn?: boolean }} [opts]
 * @returns {{ hosts: string[], invalid: string[], cdn: number, private: number, problem: string|null }}
 */
export function subdomainTlsHosts(doc, { skipCdn = false } = {}) {
  const refused = (problem) => ({ hosts: [], invalid: [], cdn: 0, private: 0, problem });
  if (!isObj(doc) || doc.tool !== DS_TOOL) return refused(`it is not a --json report of ${DS_TOOL}`);
  if (!isStr(doc.version) || doc.version.split('.')[0] !== DS_VERSION.split('.')[0]) return refused(`it was written by version ${JSON.stringify(doc.version ?? null)}`);
  if (doc.command !== 'subdomains') return refused(`it is a report of "${doc.command}", not of "subdomains"`);
  if (!Array.isArray(doc.targets)) return refused('it has no "targets" list');
  const hosts = [];
  const invalid = new Set();
  const cdn = new Set();
  const priv = new Set();
  for (const x of doc.targets) {
    for (const h of (isObj(x) && Array.isArray(x.hosts) ? x.hosts : [])) {
      if (!isObj(h) || !isStr(h.name) || h.wildcardSuspect === true) continue;
      if (!hasAddress(h) && !hasAddress(h.lastGood)) continue;
      const name = normalizeHostname(h.name);
      if (!name) {
        invalid.add(h.name);
        continue;
      }
      if (hosts.includes(name) || cdn.has(name) || priv.has(name)) continue;
      if (h.kind === 'private') priv.add(name);
      else if (skipCdn && CDN_KINDS.includes(h.kind)) cdn.add(name);
      else hosts.push(name);
    }
  }
  return { hosts, invalid: [...invalid], cdn: cdn.size, private: priv.size, problem: null };
}

/**
 * What `--from-subdomains` and `--ct` give, read and checked before anything is sent (a usage error
 * names what is wrong): the hosts of a subdomains report ({@link subdomainTlsHosts}; the ones left
 * out are warnings), and the same night's `ct` report (tools/ds/tlsct.mjs ctLookup). A `--ct` file
 * that does not exist is a warning — the nightly job's ct check writes it first, and a night it
 * failed leaves none on the first night —: NOT_DEPLOYED is not checked that run.
 * @param {import('./args.mjs').DsOptions} options
 * @param {{ read: (path: string, option: string) => Promise<string>, exists: (path: string) => Promise<boolean>,
 *   warn: (text: string) => void, skipped: (label: string, invalid: string[], what: string) => string[] }} io
 * @returns {Promise<{ hosts: string[], fromSubdomains: string|null, ct: object|null }>}
 */
export async function tlsInputs(options, { read, exists, warn, skipped }) {
  const base = (p) => String(p).split(/[\\/]/).pop();
  const out = { hosts: [], fromSubdomains: null, ct: null };
  if (options.fromSubdomains) {
    const file = options.fromSubdomains;
    let doc;
    try {
      doc = JSON.parse(await read(file, '--from-subdomains'));
    } catch (err) {
      if (err instanceof UsageError) throw err;
      throw new UsageError(`--from-subdomains: ${file} is not JSON (${err.message})`);
    }
    const found = subdomainTlsHosts(doc, { skipCdn: options.skipCdn });
    if (found.problem) throw new UsageError(`--from-subdomains: cannot read hosts from ${file}: ${found.problem} (give a report written by "subdomains --json")`);
    for (const w of skipped(`--from-subdomains ${file}`, found.invalid, 'a host name')) warn(w);
    if (found.private) warn(`--from-subdomains ${file}: ${found.private} host${found.private === 1 ? '' : 's'} with private addresses only left out (a hosted runner cannot reach them; --list them to check them from your own network)`);
    if (found.cdn) warn(`--from-subdomains ${file}: ${found.cdn} host${found.cdn === 1 ? '' : 's'} behind a CDN left out (--skip-cdn)`);
    out.hosts = parseTargets('tls', found.hosts).targets;
    out.fromSubdomains = base(file);
  }
  if (options.ct) {
    if (!(await exists(options.ct))) {
      warn(`--ct ${options.ct}: no such file: NOT_DEPLOYED is not checked this run (the ct check writes it; run that first)`);
    } else {
      let doc;
      try {
        doc = JSON.parse(await read(options.ct, '--ct'));
      } catch (err) {
        if (err instanceof UsageError) throw err;
        throw new UsageError(`--ct: ${options.ct} is not JSON (${err.message})`);
      }
      const problem = ctReportProblem(doc);
      if (problem) throw new UsageError(`--ct: cannot read certificates from ${options.ct}: ${problem} (give a report written by "ct --json")`);
      out.ct = ctLookup(doc, base(options.ct));
    }
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* The summary                                                              */
/* ------------------------------------------------------------------------ */

/** Why a revocation status is unknown, in a sentence. */
export const REVOCATION_WHY = Object.freeze({
  'no-crl': 'the certificate names no CRL to read (OCSP is not asked)',
  'too-large': `its CRL is larger than ${CRL_MAX_BYTES / 1024 / 1024} MB`,
  http: 'its CRL could not be downloaded (HTTP error)',
  timeout: 'its CRL download timed out',
  network: 'its CRL could not be downloaded',
  parse: 'what its CRL URL returned is not a CRL',
  'bad-signature': 'the CRL’s signature does not verify with the issuer’s key',
  'issuer-mismatch': 'the CRL is another CA’s',
  'critical-extension': 'the CRL has a critical extension DomainScope does not read',
  delta: 'it is a delta CRL',
  scope: 'the CRL covers other certificates',
  reasons: 'the CRL covers some revocation reasons only',
  stale: 'the CRL is out of date (its nextUpdate has passed)',
  unknown: 'the CRL could not be read'
});

/** What an ARI error means, in a sentence. */
export const ARI_WHY = Object.freeze({
  'not-found': 'the CA does not know this certificate (404)',
  unsupported: 'no ARI server is known for this issuer',
  'no-key-id': 'the certificate has no authority key identifier',
  'no-renewal-info': 'the CA’s directory names no renewalInfo URL',
  'bad-window': 'the CA’s answer is no window',
  'rate-limit': 'the CA answered "rate limited"',
  http: 'the CA’s ARI server answered an HTTP error',
  timeout: 'the CA’s ARI server timed out',
  network: 'the CA’s ARI server could not be reached',
  parse: 'the CA’s answer could not be read',
  unknown: 'the CA’s answer could not be read'
});

const minute = (iso) => (iso ? `${isoTime(iso).slice(0, 16).replace('T', ' ')} UTC` : '?');
const days = (n) => `${n} day${n === 1 ? '' : 's'}`;

/** The ARI line of a certificate (parts). */
export function ariParts(ari, at) {
  if (!ari) return null;
  const label = ari.ca ? `ARI (${ari.ca}): ` : 'ARI: ';
  const asOf = ari.carried ? [` (as of ${minute(ari.carried.from)}${ari.retryAfter ? `; not asked again before ${minute(ari.retryAfter)}, as the CA asked` : ''})`] : [];
  if (ari.error) {
    const why = ARI_WHY[ari.error] || ARI_WHY.unknown;
    return [`${label}${why}${ari.error === 'http' && ari.status ? ` ${ari.status}` : ''}`, ...asOf];
  }
  const state = windowState(ari, at);
  const head = [`${label}renew between ${minute(ari.start)} and ${minute(ari.end)}`];
  if (state === 'before') head.push(` — opens in ${days(Math.max(0, Math.ceil((Date.parse(ari.start) - at) / DAY_MS)))}`);
  else if (state === 'open') head.push(' — ', strong('the window is open: renew now'));
  else if (state === 'past') head.push(' — ', strong('the window has ended: the renewal is overdue'));
  if (ari.explanationURL) head.push('; the CA explains: ', code(ari.explanationURL));
  return [...head, ...asOf];
}

/** The revocation line of a certificate (parts). */
export function revocationParts(rev) {
  if (!rev) return null;
  const sig = rev.signature === 'verified' ? 'signature verified'
    : rev.signature === 'not-verified' ? (rev.signatureNote === 'issuer-not-sent' ? 'signature not verified: the server does not send the issuer' : 'signature not verified')
      : null;
  const crl = rev.thisUpdate ? `CRL of ${minute(rev.thisUpdate)}` : 'CRL';
  if (rev.status === 'revoked') {
    return [strong('REVOKED'), ` on ${minute(rev.time)} (${rev.reason || 'no reason given'}); ${crl}${sig ? `, ${sig}` : ''}`];
  }
  if (rev.status === 'good') return [`Not revoked (${crl}${sig ? `, ${sig}` : ''})`];
  return [`Revocation unknown: ${REVOCATION_WHY[rev.error] || REVOCATION_WHY.unknown}`, ...(rev.crl ? [' (', code(rev.crl), ')'] : [])];
}

/** Distinct values joined with '/', or null when there is none. */
const distinct = (list) => {
  const values = [...new Set(list.filter((v) => v !== null && v !== undefined && v !== ''))];
  return values.length ? values.join('/') : null;
};

/** The connection line of the endpoints serving one certificate: protocol, cipher, key exchange, chain sent, OCSP staple. */
export function connectionParts(endpoints) {
  const bits = [distinct(endpoints.map((e) => e.protocol)), distinct(endpoints.map((e) => e.cipher)), distinct(endpoints.map((e) => e.ephemeralKey && e.ephemeralKey.name))];
  const sent = distinct(endpoints.map((e) => (Number.isInteger(e.chainSent) ? String(e.chainSent) : null)));
  if (sent) bits.push(`chain sent: ${sent} certificate${sent === '1' ? '' : 's'}`);
  const staples = new Set(endpoints.map((e) => e.ocspStapled).filter((v) => typeof v === 'boolean'));
  if (staples.size) bits.push(`OCSP staple: ${staples.size === 2 ? 'some addresses' : staples.has(true) ? 'yes' : 'no'}`);
  const text = bits.filter(Boolean).join(' · ');
  return text ? [text] : null;
}

/** One endpoint's `GET /` in words: the status, HSTS, and the redirect of http:// (port 443). */
export function httpText(http) {
  if (!http) return null;
  const out = [];
  if (Number.isInteger(http.status)) {
    const hsts = !http.hsts ? 'no HSTS' : http.hsts.valid ? `HSTS max-age=${http.hsts.maxAge}${http.hsts.includeSubDomains ? '; includeSubDomains' : ''}${http.hsts.preload ? '; preload' : ''}` : 'HSTS header not valid (browsers ignore it)';
    out.push(`GET / ${http.status}`, hsts);
  } else {
    out.push(`GET / failed: ${http.error || 'no answer'}`);
  }
  const p = http.plain;
  if (p) {
    if (!Number.isInteger(p.status)) out.push(`http:// failed: ${p.error || 'no answer'}`);
    else if (p.toHttps) out.push(`http:// redirects to https:// (${p.status})`);
    else out.push(`http:// answers ${p.status}${p.location ? ` → ${p.location}` : ''}, no redirect to https://`);
  }
  return out.join(' · ');
}

/** The problems of an endpoint, after its address in the certificate line. */
function endpointNote(e) {
  const notes = [];
  if (isUntrusted(e)) notes.push(`UNTRUSTED (${e.trustError})`);
  if (isMismatch(e)) notes.push('NAME_MISMATCH');
  if (isNotDeployed(e)) notes.push('NOT_DEPLOYED');
  return notes.length ? `${e.address} ${notes.join(', ')}` : e.address;
}

/**
 * The summary of one target.
 * @param {object} target
 * @param {{ t: Function, now: Date, warnDays?: number }} opts
 */
export function tlsDoc(target, { t, now, warnDays = 21 }) {
  const lines = [];
  const at = Date.parse(target.checkedAt) || now.getTime();
  if (target.carried) {
    const why = target.carried.why === 'max-endpoints' ? 'not checked this run (--max-endpoints)' : `DNS: ${target.dns ? target.dns.status : 'failed'} — nothing checked`;
    lines.push([`${why}; the endpoints of the last check (${isoDay(target.carried.from) || 'an earlier run'}) are kept for the next comparison`]);
  } else if (target.dns && !target.endpoints.length) {
    lines.push([target.dns.status === 'NXDOMAIN' ? 'The name does not resolve (NXDOMAIN)' : `The name has no address (${target.dns.status})`]);
  }
  const live = target.carried ? [] : target.endpoints;
  const groups = new Map();
  for (const e of live) {
    if (!e.cert) continue;
    if (!groups.has(e.cert.sha256)) groups.set(e.cert.sha256, { cert: e.cert, ari: e.ari, revocation: e.revocation, endpoints: [] });
    groups.get(e.cert.sha256).endpoints.push(e);
  }
  for (const g of groups.values()) {
    const c = g.cert;
    const state = expiryState(c, at, warnDays);
    const left = c.daysLeft < 0 ? `expired ${days(-c.daysLeft)} ago` : `${days(c.daysLeft)} left${state === 'expiring' ? ': EXPIRING' : ''}`;
    const where = g.endpoints.map(endpointNote);
    lines.push([code(c.subject || c.sha256.slice(0, 16)), ' · ', code(c.ca), ` · expires ${isoDay(c.notAfter)} (${left}) · `,
      ...where.slice(0, 4).flatMap((w, i) => (i ? [', ', code(w)] : [code(w)])), ...(where.length > 4 ? [` +${where.length - 4}`] : [])]);
    const missing = g.endpoints.filter((e) => e.missingIntermediate);
    if (missing.length) {
      const m = missing[0].missingIntermediate;
      lines.push(['The intermediate ', code(m.name), ...(m.owner ? [' (', code(m.owner), ')'] : []), ` is not sent${m.added > 1 ? ` (nor ${m.added - 1} more above it)` : ''} by `,
        ...missing.slice(0, 4).flatMap((e, i) => (i ? [', ', code(e.address)] : [code(e.address)])), ': named from the CCADB list; add it to the certificate file']);
    }
    const stale = g.endpoints.filter((e) => e.newer);
    if (stale.length) {
      const n = stale[0].newer;
      lines.push([`CT logged its renewal of ${isoDay(n.notBefore)} (`, code(n.ca || '?'), `, expires ${isoDay(n.notAfter)}): not installed on `,
        ...stale.slice(0, 4).flatMap((e, i) => (i ? [', ', code(e.address)] : [code(e.address)])), ...(stale.length > 4 ? [` +${stale.length - 4}`] : [])]);
    }
    const conn = connectionParts(g.endpoints);
    if (conn) lines.push(conn);
    const byText = new Map();
    for (const e of g.endpoints) {
      const text = httpText(e.http);
      if (!text) continue;
      if (!byText.has(text)) byText.set(text, []);
      byText.get(text).push(e.address);
    }
    for (const [text, addresses] of byText) {
      lines.push(byText.size > 1 ? [...addresses.slice(0, 4).flatMap((a, i) => (i ? [', ', code(a)] : [code(a)])), `: ${text}`] : [text]);
    }
    const a = ariParts(g.ari, at);
    if (a) lines.push(a);
    const r = revocationParts(g.revocation);
    if (r) lines.push(r);
  }
  const failed = live.filter((e) => TLS_FAILED.includes(e.status));
  for (const e of failed.slice(0, 5)) lines.push([code(e.address), `: ${e.status}${e.error ? ` (${e.error})` : ''}`]);
  if (failed.length > 5) lines.push([`${failed.length - 5} more endpoints did not answer (see the JSON report)`]);
  const skipped = live.filter((e) => e.status === 'SKIPPED').length;
  if (skipped) lines.push([`${skipped} IPv6 address${skipped === 1 ? '' : 'es'} not checked: no IPv6 route from this machine`]);
  return summaryDoc('tls', ['TLS · ', code(target.target)], lines, { t, at: target.checkedAt, now });
}

/* ------------------------------------------------------------------------ */
/* The run                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Run `tls` over the targets.
 * @param {string[]} targets normalized targets (args.mjs parseTargets: {@link parseTlsTarget} labels)
 * @param {import('./args.mjs').DsOptions} options `ari`, `revocation`, `warnDays`, `http`, `maxEndpoints`
 * @param {object} env runCommand's env; `env.inputs.tls`: {@link tlsInputs}; `env.tls` (tests): `{ connect, ca, caOf,
 *   directories, request, intermediates }` (`request`: node:http's, `intermediates`: a lib/chainfix.js store)
 * @returns {Promise<{ options: object, targets: object[], docs: object[], warnings: string[] }>}
 */
export async function runTls(targets, options, env) {
  const hooks = env.tls || {};
  const inputs = (env.inputs && env.inputs.tls) || { hosts: [], fromSubdomains: null, ct: null };
  const warnDays = Number.isInteger(options.warnDays) ? options.warnDays : 21;
  const maxEndpoints = Number.isInteger(options.maxEndpoints) ? options.maxEndpoints : Infinity;
  const parsed = targets.map(parseTlsTarget).filter(Boolean);
  const prevBy = new Map(((env.baseline && env.baseline.targets) || []).map((x) => [x.target, x]));

  // --- DNS ---------------------------------------------------------------------------------
  const plans = [];
  for (const [i, p] of parsed.entries()) {
    throwIfAborted(env.signal);
    env.progress(`tls ${p.target} (${i + 1}/${parsed.length})`);
    if (p.address) {
      plans.push({ ...p, dns: null, addresses: [p.address] });
      continue;
    }
    const r = await env.dns.resolveHost(p.host, { signal: env.signal });
    const addresses = [...new Set([...(r.ipv4 || []), ...(r.ipv6 || [])])];
    const failed = r.status !== 'NOERROR' && r.status !== 'NXDOMAIN';
    plans.push({
      ...p,
      dns: { status: r.status, ipv4: [...(r.ipv4 || [])].sort(), ipv6: [...(r.ipv6 || [])].sort(), cnames: [...(r.cnames || [])], error: r.error || null },
      addresses: failed ? [] : addresses,
      dnsFailed: failed && !addresses.length
    });
  }
  // at most --max-endpoints handshakes: the targets from the first one that does not fit on wait for another run
  let budget = maxEndpoints;
  for (const plan of plans) {
    if (budget !== null && plan.addresses.length <= budget) budget -= plan.addresses.length;
    else {
      budget = null;
      plan.capped = true;
    }
  }

  // --- handshakes (and with --http the GETs) -------------------------------------------------
  const limit = createLimiter(TLS_CONCURRENCY);
  const jobs = [];
  for (const plan of plans) {
    if (plan.capped) continue;
    for (const address of plan.addresses) {
      jobs.push({ plan, address, run: limit.run(async () => {
        const h = await handshake({
          address, port: plan.port, servername: plan.host, connect: hooks.connect || tls.connect, ca: hooks.ca, signal: env.signal,
          http: !!options.http, request: hooks.request
        });
        if (options.http && h.chain && plan.port === 443) h.plain = await getPlain({ host: plan.host, address, request: hooks.request, signal: env.signal });
        return h;
      }, { signal: env.signal }) });
    }
  }
  const results = await Promise.all(jobs.map((j) => j.run));
  throwIfAborted(env.signal);
  const at = env.now().getTime();

  // --- the certificates, once each --------------------------------------------------------
  const distinct = new Map();
  const endpointsOf = new Map(plans.map((p) => [p, []]));
  const unnamed = [];
  results.forEach((h, i) => {
    const { plan, address } = jobs[i];
    const e = { address, family: isIP(address), port: plan.port, status: h.status, error: h.error || null };
    if (h.chain) {
      let chain;
      let sent = null;
      try {
        chain = h.chain.map((der) => parseCertificate(der));
        if (h.sent) sent = h.sent.map((der) => parseCertificate(der));
      } catch (err) {
        Object.assign(e, { status: 'TLS_ERROR', error: `the server's certificate could not be read: ${String(err && err.message).slice(0, 120)}` });
        chain = null;
      }
      if (chain) {
        const leaf = chain[0];
        const sha256 = createHash('sha256').update(h.chain[0]).digest('hex');
        const cert = certRecord(leaf, sha256, at);
        const newer = inputs.ct && plan.host ? renewalNotDeployed(inputs.ct, plan.host, cert, at) : null;
        const s = statusOf(h, cert, at, { warnDays, newer });
        Object.assign(e, {
          status: s.status, protocol: h.protocol, cipher: h.cipher, ephemeralKey: h.ephemeralKey ?? null, ocspStapled: h.ocspStapled ?? null,
          trusted: h.authorized && !s.trustError, trustError: s.trustError, nameMatch: h.nameMatch,
          chainLength: chain.length, chainSent: sent ? sent.length : null, cert, ...(newer ? { newer } : {})
        });
        if (options.http) e.http = httpRecord(h.https, h.plain, hostHeader(plan.host, address, 80, 80));
        if (e.trustError === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
          // one lookup per chain as sent (the same leaf may come with different chains)
          const ders = h.sent && sent ? h.sent : h.chain;
          const digest = createHash('sha256');
          for (const der of ders) digest.update(der);
          unnamed.push({ key: digest.digest('hex'), leaf, certs: sent || chain, endpoint: e });
        }
        if (!distinct.has(sha256)) distinct.set(sha256, { leaf, chain });
      }
    }
    endpointsOf.get(plan).push(e);
  });

  // --- the missing intermediates, from the CCADB list -------------------------------------
  const warnings = [];
  if (unnamed.length) {
    const { found, error } = await nameMissingIntermediates(unnamed, { store: hooks.intermediates || null, now: at });
    for (const u of unnamed) if (found.has(u.key)) u.endpoint.missingIntermediate = found.get(u.key);
    if (error) warnings.push(`the CCADB list of intermediates could not be read (${error}): a missing intermediate is not named`);
  }

  // --- revocation and ARI ---------------------------------------------------------------------
  const revocations = new Map();
  const aris = new Map();
  if (options.revocation && distinct.size) {
    env.progress(`tls: revocation of ${distinct.size} certificate${distinct.size === 1 ? '' : 's'}`);
    const checker = createRevocationChecker({ fetchImpl: env.fetchImpl, signal: env.signal, now: env.now });
    const got = await checker.check([...distinct].map(([key, x]) => ({ key, cert: x.leaf, chain: x.chain })));
    for (const [k, v] of got) revocations.set(k, v);
  }
  if (options.ari && distinct.size) {
    env.progress(`tls: ARI of ${distinct.size} certificate${distinct.size === 1 ? '' : 's'}`);
    const client = createAriClient({ fetchImpl: env.fetchImpl, signal: env.signal, now: env.now, ...(hooks.directories ? { directories: hooks.directories } : {}), ...(hooks.caOf ? { caOf: hooks.caOf } : {}) });
    const prevAris = baselineAris(env.baseline);
    const ariLimit = createLimiter(ARI_CONCURRENCY);
    await Promise.all([...distinct].map(([key, x]) => ariLimit.run(async () => {
      const certId = ariCertId(x.leaf);
      aris.set(key, await client.check(x.leaf, { prev: certId ? prevAris.get(certId) || null : null }));
    }, { signal: env.signal })));
  }
  throwIfAborted(env.signal);

  // --- the report -----------------------------------------------------------------------------
  const checkedAt = new Date(at).toISOString();
  const out = [];
  const docs = [];
  let noV6 = 0;
  const capped = [];
  for (const plan of plans) {
    const prev = prevBy.get(plan.target) || null;
    if (plan.capped) {
      capped.push(plan);
      // never checked yet: nothing to carry, and nothing to report
      if (!prev) continue;
    }
    const prevEndpoints = new Map(((prev && prev.endpoints) || []).map((e) => [endpointKey(e), e]));
    const endpoints = endpointsOf.get(plan).map((e) => {
      if (e.cert) {
        if (aris.has(e.cert.sha256)) e.ari = aris.get(e.cert.sha256);
        if (revocations.has(e.cert.sha256)) e.revocation = revocations.get(e.cert.sha256);
        return e;
      }
      if (e.status === 'SKIPPED') {
        noV6 += 1;
        return e;
      }
      // not reached: the certificate the last run that reached it saw is kept for the next comparison
      const p = prevEndpoints.get(endpointKey(e));
      if (p && p.cert) e.lastGood = { at: prev.checkedAt || null, cert: p.cert, ...(p.ari ? { ari: p.ari } : {}), ...(p.revocation ? { revocation: p.revocation } : {}) };
      else if (p && p.lastGood) e.lastGood = p.lastGood;
      return e;
    });
    const carry = (plan.dnsFailed || plan.capped) && prev;
    const target = {
      target: plan.target, host: plan.host, port: plan.port, checkedAt, dns: plan.dns,
      endpoints: carry ? prev.endpoints || [] : endpoints
    };
    if (carry) {
      target.carried = { from: (prev.carried && prev.carried.from) || prev.checkedAt || null, ...(plan.capped ? { why: 'max-endpoints' } : {}) };
      if (prev.ct) target.ct = prev.ct;
    } else if (inputs.ct && plan.host) {
      target.ct = { newest: newestInCt(inputs.ct, plan.host, at) };
    }
    out.push(target);
    docs.push(tlsDoc(target, { t: env.t, now: env.now(), warnDays }));
  }
  if (noV6) warnings.push(`${noV6} IPv6 address${noV6 === 1 ? '' : 'es'} not checked: this machine has no IPv6 route (GitHub's hosted runners have none)`);
  const dnsFailed = plans.filter((p) => p.dnsFailed && !p.capped).map((p) => p.target);
  if (dnsFailed.length) warnings.push(`the DNS lookup failed for ${dnsFailed.slice(0, 10).join(', ')}${dnsFailed.length > 10 ? ` and ${dnsFailed.length - 10} more` : ''}: nothing checked there`);
  if (capped.length) {
    const addresses = capped.reduce((n, p) => n + p.addresses.length, 0);
    warnings.push(`--max-endpoints ${options.maxEndpoints}: ${capped.length} target${capped.length === 1 ? '' : 's'} (${addresses} address${addresses === 1 ? '' : 'es'}) not checked this run, from ${capped[0].target} on; `
      + 'their last check is kept for the next comparison (raise --max-endpoints, or split the list)');
  }
  return {
    options: {
      ari: !!options.ari, revocation: !!options.revocation, warnDays, http: !!options.http,
      ct: inputs.ct ? { file: inputs.ct.file, finishedAt: inputs.ct.finishedAt } : null,
      fromSubdomains: inputs.fromSubdomains, skipCdn: !!options.skipCdn, maxEndpoints: options.maxEndpoints ?? null,
      resolvers: [...options.chain]
    },
    targets: out,
    docs,
    warnings
  };
}
