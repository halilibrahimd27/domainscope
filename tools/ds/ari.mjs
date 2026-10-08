/**
 * tools/ds/ari.mjs — ACME Renewal Information (RFC 9773) for the runner's `tls --ari`: the window
 * in which the issuing CA wants each served certificate renewed, asked of the CA's own ARI server.
 *
 * - {@link ARI_SERVER_DIRECTORIES}: the CAs with an ARI server, by lib/renewal.js RENEWAL_CAS id (a
 *   certificate's issuer is mapped with caForIssuer), each with its ACME directory and the hosts its
 *   renewalInfo URL may be on (the directories were read on 2026-10-09). Server side only: of these,
 *   a page can ask Let's Encrypt alone (the others send no CORS header on renewalInfo), so the table
 *   lives here and lib/renewalplan.js keeps the page's ARI_DIRECTORIES. SSL.com has one directory per
 *   key type; its renewalInfo answered 403 "Missing Authentication Token" (the path is not routed)
 *   on 2026-10-09, which the report says as it is until it serves.
 * - {@link createAriClient}: one per run — each directory read once (fetchRenewalInfo's cache), each
 *   certificate asked once (by CertID), a CA not asked again in the run once it answered "rate
 *   limited" (429, or 503 with Retry-After), and a certificate not asked before the Retry-After of its
 *   last answer (the baseline's `retryAfter`): that answer is carried instead.
 * - {@link windowState}: before the window, in it, past it (the change RENEW-NOW).
 *
 * What is sent: the CertID (the issuer's key identifier and the serial number, both public) to the
 * issuing CA's ARI server. A 404 is `not-found` (the CA does not know the certificate: another CA
 * with the same name, or one it did not issue through ACME), not a failure.
 */

import { caForIssuer } from '../../assets/js/lib/renewal.js';
import { ariCertId, fetchRenewalInfo, ARI_TIMEOUT_MS } from '../../assets/js/lib/renewalplan.js';

const freezeEntry = (e) => Object.freeze({ ...e, hosts: Object.freeze([...e.hosts]) });

/**
 * The CAs with an ARI server: `{ url, hosts, keyType? }` per directory (`keyType` 'RSA' / 'EC'
 * where a CA has one directory per key type).
 * @type {Readonly<Record<string, ReadonlyArray<{ url: string, hosts: ReadonlyArray<string>, keyType?: string }>>>}
 */
export const ARI_SERVER_DIRECTORIES = Object.freeze({
  letsencrypt: Object.freeze([freezeEntry({ url: 'https://acme-v02.api.letsencrypt.org/directory', hosts: ['acme-v02.api.letsencrypt.org'] })]),
  google: Object.freeze([freezeEntry({ url: 'https://dv.acme-v02.api.pki.goog/directory', hosts: ['dv.acme-v02.api.pki.goog'] })]),
  zerossl: Object.freeze([freezeEntry({ url: 'https://acme.zerossl.com/v2/DV90', hosts: ['ari.trust-provider.com'] })]),
  sectigo: Object.freeze([freezeEntry({ url: 'https://acme.sectigo.com/v2/DV', hosts: ['ari.sectigo.com'] })]),
  sslcom: Object.freeze([
    freezeEntry({ url: 'https://acme.ssl.com/sslcom-dv-rsa', hosts: ['acme.ssl.com'], keyType: 'RSA' }),
    freezeEntry({ url: 'https://acme.ssl.com/sslcom-dv-ecc', hosts: ['acme.ssl.com'], keyType: 'EC' })
  ])
});

/** A Retry-After longer than this (a broken header) is cut to it, so a CA is never muted for good. */
export const ARI_MAX_RETRY_MS = 7 * 86400000;
/** How long a CA that answered "rate limited" without a Retry-After is left alone in a run. */
export const ARI_BENCH_MS = 3600000;
/** ARI requests in flight at once. */
export const ARI_CONCURRENCY = 4;

/**
 * The ARI directory of a CA for a certificate's key type, or null for a CA without an ARI server
 * (DigiCert, GlobalSign …, a private CA).
 * @param {string|null} caId lib/renewal.js RENEWAL_CAS id
 * @param {string|null} [keyAlgorithm] lib/x509.js keyAlgorithm ('RSA', 'EC' …)
 * @param {Readonly<Record<string, ReadonlyArray<object>>>} [directories] the table (tests pass their own)
 * @returns {{ url: string, hosts: ReadonlyArray<string>, keyType?: string }|null}
 */
export function ariDirectoryFor(caId, keyAlgorithm = null, directories = ARI_SERVER_DIRECTORIES) {
  const list = caId && Object.prototype.hasOwnProperty.call(directories, caId) ? directories[caId] : null;
  if (!list) return null;
  if (list.length === 1) return list[0];
  return list.find((e) => e.keyType === keyAlgorithm) || null;
}

const iso = (ms) => new Date(ms).toISOString();

/**
 * @typedef {object} AriRecord the report's `ari` of a certificate
 * @property {string|null} ca lib/renewal.js RENEWAL_CAS id of the issuer (null: not a CA the list knows)
 * @property {string|null} certId the RFC 9773 CertID asked for
 * @property {string|null} start the suggested window (ISO), null without one
 * @property {string|null} end
 * @property {string|null} explanationURL the CA's explanation of the window (https only)
 * @property {string} checkedAt when the CA answered (a carried answer keeps its time)
 * @property {string|null} retryAfter not asked again before this (ISO): the CA's Retry-After
 * @property {number|null} status the HTTP status of the renewalInfo request
 * @property {string|null} error null for a window; else lib/renewalplan.js ARI_FAILURES ('not-found': the
 *   CA does not know the certificate; 'unsupported': no ARI server for this CA; 'no-key-id': no AKI)
 * @property {{ from: string }} [carried] not asked this run (before the last answer's Retry-After, or
 *   the CA rate limited earlier in the run): the last answer, as of `from`
 */

/**
 * Where a certificate is in its ARI window at `at`: 'before', 'open', 'past', or null without a window.
 * @param {AriRecord|null|undefined} ari
 * @param {number} at ms
 * @returns {'before'|'open'|'past'|null}
 */
export function windowState(ari, at) {
  const start = ari && typeof ari.start === 'string' ? Date.parse(ari.start) : NaN;
  const end = ari && typeof ari.end === 'string' ? Date.parse(ari.end) : NaN;
  if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
  if (at < start) return 'before';
  return at <= end ? 'open' : 'past';
}

/**
 * The run's ARI client.
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, now?: () => Date, timeoutMs?: number,
 *   directories?: Readonly<Record<string, ReadonlyArray<object>>>, caOf?: (cert: object) => string|null }} [opts]
 *   `directories` / `caOf`: the table and the issuer → CA mapping (tests pass their own)
 * @returns {{ check(cert: object, opts?: { prev?: AriRecord|null }): Promise<AriRecord>, requests: () => number }}
 *   `cert`: a lib/x509.js Certificate (issuerDN, keyAlgorithm, authorityKeyId, serialHex); `prev`: the
 *   baseline's record of the same certificate (its Retry-After is honoured)
 */
export function createAriClient({
  fetchImpl = globalThis.fetch, signal, now = () => new Date(), timeoutMs = ARI_TIMEOUT_MS,
  directories = ARI_SERVER_DIRECTORIES, caOf = (cert) => caForIssuer(cert && (cert.issuerDN || cert.issuer))
} = {}) {
  const cache = new Map();
  const byCertId = new Map();
  const benched = new Map(); // directory url → until (ms)
  let requests = 0;
  const at = () => now().getTime();

  async function ask(cert, ca, entry, certId, prev) {
    const prevRetry = prev && typeof prev.retryAfter === 'string' ? Date.parse(prev.retryAfter) : NaN;
    if (prev && prev.certId === certId && Number.isFinite(prevRetry) && prevRetry > at()) {
      return { ...prev, carried: { from: (prev.carried && prev.carried.from) || prev.checkedAt } };
    }
    const bench = benched.get(entry.url);
    if (bench && bench > at()) {
      if (prev && prev.certId === certId) return { ...prev, carried: { from: (prev.carried && prev.carried.from) || prev.checkedAt } };
      return { ca, certId, start: null, end: null, explanationURL: null, checkedAt: iso(at()), retryAfter: iso(bench), status: null, error: 'rate-limit', carried: { from: iso(at()) } };
    }
    requests += 1;
    const r = await fetchRenewalInfo(cert, { directory: entry, cache, fetchImpl, signal, timeoutMs, now: at });
    const wait = Number.isFinite(r.retryAfterMs) && r.retryAfterMs > 0 ? Math.min(r.retryAfterMs, ARI_MAX_RETRY_MS) : null;
    const checked = r.at.getTime();
    if (!r.ok && (r.code === 'rate-limit' || (r.status === 503 && wait))) benched.set(entry.url, checked + (wait || ARI_BENCH_MS));
    return {
      ca,
      certId,
      start: r.ok ? r.start.toISOString() : null,
      end: r.ok ? r.end.toISOString() : null,
      explanationURL: r.ok ? r.explanationUrl : null,
      checkedAt: iso(checked),
      retryAfter: wait ? iso(checked + wait) : null,
      status: r.status ?? (r.ok ? 200 : null),
      error: r.ok ? null : r.code
    };
  }

  return {
    async check(cert, { prev = null } = {}) {
      const ca = caOf(cert) || null;
      const entry = ariDirectoryFor(ca, cert && cert.keyAlgorithm, directories);
      const base = { ca, certId: null, start: null, end: null, explanationURL: null, checkedAt: iso(at()), retryAfter: null, status: null };
      if (!entry) return { ...base, error: 'unsupported' };
      const certId = ariCertId(cert);
      if (!certId) return { ...base, error: 'no-key-id' };
      if (!byCertId.has(certId)) byCertId.set(certId, ask(cert, ca, entry, certId, prev));
      return byCertId.get(certId);
    },
    requests: () => requests
  };
}
