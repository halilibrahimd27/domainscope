/**
 * tools/ds/tls.mjs — the runner's `tls` command: the certificate each public endpoint serves, as
 * the job sees it, and with `--ari` / `--revocation` what the issuing CA says about it: its ACME
 * Renewal Information window (tools/ds/ari.mjs) and whether its CRL lists it (tools/ds/revocation.mjs).
 *
 * - TARGET is `host`, `host:port`, `[v6]:port` or an address (`192.0.2.10:8443`: no SNI, the
 *   server's default certificate); the port defaults to 443 ({@link parseTlsTarget}).
 * - A host's A and AAAA records come from the run's DohClient; each address is asked on its own
 *   with SNI = the host, so a pool member still serving an old certificate shows. GitHub's hosted
 *   runners have no IPv6 route: an IPv6 address the job cannot reach is SKIPPED (`no-ipv6-route`),
 *   said once per run, never a failure or a change.
 * - The handshake: node:tls with `rejectUnauthorized: false` (the certificate is read whatever it
 *   is), {@link TLS_TIMEOUT_MS} per endpoint, {@link TLS_CONCURRENCY} at once. The status: OK,
 *   EXPIRED (by the run's clock), UNTRUSTED (Node's trust store says why: a missing intermediate is
 *   UNABLE_TO_VERIFY_LEAF_SIGNATURE), NAME_MISMATCH (tls.checkServerIdentity, called whatever the
 *   chain, since Node checks the name only of a trusted one), TLS_ERROR, TIMEOUT, CLOSED, SKIPPED.
 * - ARI and revocation are asked once per distinct certificate of the run, and every endpoint
 *   serving it carries the answer. An endpoint that did not answer keeps, as `lastGood`, the
 *   certificate (with its ARI and revocation) the last run that reached it saw; a host whose DNS
 *   lookup failed keeps the baseline's endpoints (`carried`): the next run compares with that.
 *
 * The changes (RENEW-NOW, MOVED-UP, CA-NOTICE, REVOKED, CERT …): tools/ds/tlsdiff.mjs.
 */

import tls from 'node:tls';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { parseCertificate } from '../../assets/js/lib/x509.js';
import { caForIssuer } from '../../assets/js/lib/renewal.js';
import { ariCertId } from '../../assets/js/lib/renewalplan.js';
import { issuerName } from '../../assets/js/lib/passport.js';
import { createLimiter, throwIfAborted, AbortError } from '../../assets/js/lib/util.js';
import { createAriClient, windowState, ARI_CONCURRENCY } from './ari.mjs';
import { createRevocationChecker, CRL_MAX_BYTES } from './revocation.mjs';
import { TLS_STATUSES, TLS_FAILED } from './tlsdiff.mjs';
import { parseTlsTarget } from './args.mjs';
import { code, strong, isoDay, isoTime, summaryDoc } from './render.mjs';

export { TLS_STATUSES, TLS_FAILED };

/** Time for one handshake. */
export const TLS_TIMEOUT_MS = 10000;
/** Handshakes in flight at once. */
export const TLS_CONCURRENCY = 8;
/** Certificates of a chain read at most (a hostile server's chain is not walked forever). */
const MAX_CHAIN = 10;
const DAY_MS = 86400000;

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
 * One TLS handshake with `address:port`, SNI `servername` (none for an address target). Resolves
 * with the chain the server sent (DER, the leaf first) and what Node said of it, or a failure
 * status; rejects only on an abort.
 * @param {{ address: string, port: number, servername: string|null, timeoutMs?: number, connect?: typeof tls.connect,
 *   signal?: AbortSignal, ca?: string|Buffer|Array }} opts `ca`: a trust store instead of Node's (tests)
 * @returns {Promise<{ status: string, error: string|null, protocol?: string|null, cipher?: string|null, authorized?: boolean,
 *   authorizationError?: string|null, nameMatch?: boolean|null, chain?: Uint8Array[] }>}
 */
export function handshake({ address, port, servername, timeoutMs = TLS_TIMEOUT_MS, connect = tls.connect, signal, ca }) {
  return new Promise((resolve, reject) => {
    throwIfAborted(signal);
    const family = isIP(address);
    let socket = null;
    let done = false;
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
    const timer = setTimeout(() => finish({ status: 'TIMEOUT', error: `no answer within ${Math.round(timeoutMs / 1000)} s` }), timeoutMs);
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    try {
      socket = connect({
        host: address, port, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'],
        ...(servername ? { servername } : {}), ...(ca ? { ca } : {})
      }, () => {
        try {
          const peer = socket.getPeerCertificate(true);
          const chain = [];
          const seen = new Set();
          for (let x = peer; x && x.raw && !seen.has(x.fingerprint256) && chain.length < MAX_CHAIN; x = x.issuerCertificate) {
            seen.add(x.fingerprint256);
            chain.push(new Uint8Array(x.raw));
          }
          if (!chain.length) {
            finish({ status: 'TLS_ERROR', error: 'the server sent no certificate' });
            return;
          }
          const authError = socket.authorizationError;
          const identity = servername ? tls.checkServerIdentity(servername, peer) : undefined;
          const cipher = typeof socket.getCipher === 'function' ? socket.getCipher() : null;
          finish({
            status: 'OK',
            error: null,
            protocol: typeof socket.getProtocol === 'function' ? socket.getProtocol() || null : null,
            cipher: cipher && cipher.name ? cipher.name : null,
            authorized: socket.authorized === true,
            authorizationError: authError ? String(authError.code || authError) : null,
            nameMatch: servername ? !identity : null,
            chain
          });
        } catch (err) {
          finish({ status: 'TLS_ERROR', error: String((err && err.message) || err).slice(0, 200) });
        }
      });
      socket.on('error', (err) => finish(failureOf(err, family)));
      socket.on('close', () => finish({ status: 'TLS_ERROR', error: 'the connection closed during the handshake' }));
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

/** The status of a completed handshake at `at`. */
function statusOf(h, leaf, at) {
  if (leaf.notAfter.getTime() < at) return { status: 'EXPIRED', trustError: h.authorizationError || 'CERT_HAS_EXPIRED' };
  if (leaf.notBefore.getTime() > at) return { status: 'UNTRUSTED', trustError: 'CERT_NOT_YET_VALID' };
  const timeOnly = ['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
  if (!h.authorized && h.authorizationError && !timeOnly.includes(h.authorizationError)) return { status: 'UNTRUSTED', trustError: h.authorizationError };
  if (h.nameMatch === false) return { status: 'NAME_MISMATCH', trustError: null };
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

/**
 * The summary of one target.
 * @param {object} target
 * @param {{ t: Function, now: Date }} opts
 */
export function tlsDoc(target, { t, now }) {
  const lines = [];
  const at = Date.parse(target.checkedAt) || now.getTime();
  if (target.carried) {
    lines.push([`DNS: ${target.dns ? target.dns.status : 'failed'} — nothing checked; the endpoints of the last check (${isoDay(target.carried.from) || 'an earlier run'}) are kept for the next comparison`]);
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
    const where = g.endpoints.map((e) => (e.status === 'OK' ? e.address : `${e.address} ${e.status}${e.trustError ? ` (${e.trustError})` : ''}`));
    lines.push([code(c.subject || c.sha256.slice(0, 16)), ' · ', code(c.ca), ` · expires ${isoDay(c.notAfter)} (${c.daysLeft < 0 ? `expired ${days(-c.daysLeft)} ago` : `${days(c.daysLeft)} left`}) · `,
      ...where.slice(0, 4).flatMap((w, i) => (i ? [', ', code(w)] : [code(w)])), ...(where.length > 4 ? [` +${where.length - 4}`] : [])]);
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
 * @param {import('./args.mjs').DsOptions} options `ari`, `revocation`
 * @param {object} env runCommand's env; `env.tls` (tests): `{ connect, ca, caOf, directories }`
 * @returns {Promise<{ options: object, targets: object[], docs: object[], warnings: string[] }>}
 */
export async function runTls(targets, options, env) {
  const hooks = env.tls || {};
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

  // --- handshakes ----------------------------------------------------------------------------
  const limit = createLimiter(TLS_CONCURRENCY);
  const jobs = [];
  for (const plan of plans) {
    for (const address of plan.addresses) {
      jobs.push({ plan, address, run: limit.run(() => handshake({
        address, port: plan.port, servername: plan.host, connect: hooks.connect || tls.connect, ca: hooks.ca, signal: env.signal
      }), { signal: env.signal }) });
    }
  }
  const results = await Promise.all(jobs.map((j) => j.run));
  throwIfAborted(env.signal);
  const at = env.now().getTime();

  // --- the certificates, once each --------------------------------------------------------
  const distinct = new Map();
  const endpointsOf = new Map(plans.map((p) => [p, []]));
  results.forEach((h, i) => {
    const { plan, address } = jobs[i];
    const e = { address, family: isIP(address), port: plan.port, status: h.status, error: h.error || null };
    if (h.chain) {
      let chain;
      try {
        chain = h.chain.map((der) => parseCertificate(der));
      } catch (err) {
        Object.assign(e, { status: 'TLS_ERROR', error: `the server's certificate could not be read: ${String(err && err.message).slice(0, 120)}` });
        chain = null;
      }
      if (chain) {
        const leaf = chain[0];
        const sha256 = createHash('sha256').update(h.chain[0]).digest('hex');
        const s = statusOf(h, leaf, at);
        Object.assign(e, {
          status: s.status, protocol: h.protocol, cipher: h.cipher, trusted: h.authorized && !s.trustError, trustError: s.trustError,
          nameMatch: h.nameMatch, chainLength: chain.length, cert: certRecord(leaf, sha256, at)
        });
        if (!distinct.has(sha256)) distinct.set(sha256, { leaf, chain });
      }
    }
    endpointsOf.get(plan).push(e);
  });

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
  for (const plan of plans) {
    const prev = prevBy.get(plan.target) || null;
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
    const target = {
      target: plan.target, host: plan.host, port: plan.port, checkedAt, dns: plan.dns,
      endpoints: plan.dnsFailed && prev ? prev.endpoints || [] : endpoints
    };
    if (plan.dnsFailed && prev) target.carried = { from: (prev.carried && prev.carried.from) || prev.checkedAt || null };
    out.push(target);
    docs.push(tlsDoc(target, { t: env.t, now: env.now() }));
  }
  const warnings = [];
  if (noV6) warnings.push(`${noV6} IPv6 address${noV6 === 1 ? '' : 'es'} not checked: this machine has no IPv6 route (GitHub's hosted runners have none)`);
  const dnsFailed = plans.filter((p) => p.dnsFailed).map((p) => p.target);
  if (dnsFailed.length) warnings.push(`the DNS lookup failed for ${dnsFailed.slice(0, 10).join(', ')}${dnsFailed.length > 10 ? ` and ${dnsFailed.length - 10} more` : ''}: nothing checked there`);
  return {
    options: { ari: !!options.ari, revocation: !!options.revocation, resolvers: [...options.chain] },
    targets: out,
    docs,
    warnings
  };
}
