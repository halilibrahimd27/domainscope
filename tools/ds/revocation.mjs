/**
 * tools/ds/revocation.mjs — the runner's `tls --revocation`: is a served certificate on its CA's
 * certificate revocation list? Node only (node:crypto).
 *
 * - The CRL distribution points come from the served certificate (lib/crl.js crlUrlsOf: http and
 *   https). Each URL is read once per run ({@link CRL_MAX_BYTES} at most, {@link CRL_TIMEOUT_MS}
 *   for the whole read) and parsed once by lib/crl.js for the serial numbers of every certificate of
 *   the run that names it (a CA's CRL can list hundreds of thousands).
 * - The CRL must be the certificate issuer's (name and key identifier) and cover it (its issuing
 *   distribution point); its signature is verified with node:crypto and the issuer's public key from
 *   the handshake chain ({@link issuerFromChain}). Without the issuer in the chain (a server that
 *   sends the leaf alone) the status stands with `signature: 'not-verified'`; a signature that does
 *   not verify makes it unknown (`bad-signature`).
 * - No OCSP: Let's Encrypt has been CRL-only since 2025-08-06, and a CRL tells every certificate of
 *   a run at once.
 *
 * What is sent: a GET of each CRL URL to the CA that issued the certificate (plain http, as CAs
 * publish them; the signature is what makes the answer trustworthy).
 */

import { createPublicKey, verify as cryptoVerify, constants } from 'node:crypto';
import { parseCrl, crlStatus, crlUrlsOf, normalizeSerial, CrlParseError } from '../../assets/js/lib/crl.js';
import { fetchAndRead, HttpError, errorKind, createLimiter } from '../../assets/js/lib/util.js';

/** A CRL larger than this is not read (a CA's full CRL can be tens of megabytes). */
export const CRL_MAX_BYTES = 20 * 1024 * 1024;
/** Time for one CRL download, headers and body. */
export const CRL_TIMEOUT_MS = 15000;
/** CRL downloads in flight at once. */
export const CRL_CONCURRENCY = 4;
/** Why a status is unknown beyond lib/crl.js CRL_UNKNOWN: no CRL URL, a download or a CRL that cannot be used. */
export const REVOCATION_ERRORS = Object.freeze(['no-crl', 'too-large', 'http', 'timeout', 'network', 'parse', 'bad-signature', 'unknown']);

/**
 * The certificate of `chain` that issued `leaf`: its subject is the leaf's issuer and, when both
 * say one, its key identifier is the leaf's authority key identifier. Null when the server did not
 * send it.
 * @param {object} leaf lib/x509.js Certificate
 * @param {object[]} chain the handshake chain, lib/x509.js Certificates (the leaf first)
 * @returns {object|null}
 */
export function issuerFromChain(leaf, chain) {
  for (const c of chain || []) {
    if (!c || c === leaf || c.subjectDN !== leaf.issuerDN) continue;
    if (leaf.authorityKeyId && c.subjectKeyId && leaf.authorityKeyId !== c.subjectKeyId) continue;
    return c;
  }
  return null;
}

/**
 * Verify a CRL's signature with the issuer's public key.
 * @param {object} crl lib/crl.js Crl
 * @param {{ spkiDer: Uint8Array }} issuer lib/x509.js Certificate
 * @returns {'verified'|'failed'|'unsupported'} unsupported: an algorithm lib/crl.js has no scheme for, or a key node:crypto cannot read
 */
export function verifyCrlSignature(crl, issuer) {
  const scheme = crl && crl.scheme;
  if (!scheme || !issuer || !issuer.spkiDer) return 'unsupported';
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(issuer.spkiDer), format: 'der', type: 'spki' });
  } catch {
    return 'unsupported';
  }
  const opts = { key };
  if (scheme.scheme === 'ecdsa') opts.dsaEncoding = 'der';
  if (scheme.scheme === 'rsa-pss') {
    opts.padding = constants.RSA_PKCS1_PSS_PADDING;
    opts.saltLength = scheme.saltLength;
  }
  try {
    return cryptoVerify(scheme.hash, Buffer.from(crl.tbsDer), opts, Buffer.from(crl.signature)) ? 'verified' : 'failed';
  } catch {
    // a key of another type than the signature's (an RSA key for an ECDSA signature): not this issuer's CRL
    return 'failed';
  }
}

/**
 * Read one CRL: its bytes, or why not. Never rejects but on an abort.
 * @param {string} url
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number, maxBytes?: number }} [opts]
 * @returns {Promise<{ ok: true, bytes: Uint8Array } | { ok: false, error: string, status: number|null, size?: number }>}
 */
export async function fetchCrl(url, { fetchImpl = globalThis.fetch, signal, timeoutMs = CRL_TIMEOUT_MS, maxBytes = CRL_MAX_BYTES } = {}) {
  try {
    return await fetchAndRead(url, { fetchImpl, signal, timeoutMs, redirect: 'follow' }, async (response) => {
      if (!response.ok) throw new HttpError(response.status, url, '', { statusText: response.statusText || '' });
      const declared = Number(response.headers && typeof response.headers.get === 'function' ? response.headers.get('content-length') : NaN);
      if (Number.isFinite(declared) && declared > maxBytes) {
        if (response.body && typeof response.body.cancel === 'function') await response.body.cancel().catch(() => {});
        return { ok: false, error: 'too-large', status: response.status, size: declared };
      }
      if (response.body && typeof response.body.getReader === 'function') {
        const reader = response.body.getReader();
        const chunks = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          if (total > maxBytes) {
            await reader.cancel().catch(() => {});
            return { ok: false, error: 'too-large', status: response.status, size: total };
          }
          chunks.push(value);
        }
        const bytes = new Uint8Array(total);
        let at = 0;
        for (const c of chunks) {
          bytes.set(c, at);
          at += c.length;
        }
        return { ok: true, bytes };
      }
      const bytes = new Uint8Array(await response.arrayBuffer());
      return bytes.length > maxBytes ? { ok: false, error: 'too-large', status: response.status, size: bytes.length } : { ok: true, bytes };
    });
  } catch (err) {
    const kind = errorKind(err);
    if (kind === 'abort') throw err;
    const status = err && Number.isInteger(err.status) ? err.status : null;
    return { ok: false, error: ['http', 'timeout', 'network', 'rate-limit'].includes(kind) ? (kind === 'rate-limit' ? 'http' : kind) : 'unknown', status };
  }
}

const isoOf = (d) => (d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString() : null);

/**
 * @typedef {object} RevocationRecord the report's `revocation` of a certificate
 * @property {'good'|'revoked'|'unknown'} status
 * @property {string|null} reason lib/crl.js reasonName (null: none given, or not revoked)
 * @property {number|null} reasonCode
 * @property {string|null} time when it was revoked (ISO)
 * @property {string|null} crl the CRL URL the status comes from
 * @property {string} checkedAt
 * @property {string|null} thisUpdate the CRL's (ISO)
 * @property {string|null} nextUpdate
 * @property {'verified'|'not-verified'|'failed'|null} signature null when no CRL was read
 * @property {string|null} signatureNote why it was not verified: 'issuer-not-sent' (the issuer is not in
 *   the handshake chain), 'algorithm' (no scheme for it)
 * @property {string|null} error why it is unknown: {@link REVOCATION_ERRORS} or lib/crl.js CRL_UNKNOWN
 */

/**
 * The run's revocation checker: {@link check} takes every certificate of the run at once, so each
 * CRL is read and parsed once.
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, now?: () => Date, timeoutMs?: number, maxBytes?: number }} [opts]
 * @returns {{ check(items: Array<{ key: string, cert: object, chain: object[] }>): Promise<Map<string, RevocationRecord>>,
 *   downloads: () => number }} `key`: the certificate's SHA-256 (the map's key)
 */
export function createRevocationChecker({ fetchImpl = globalThis.fetch, signal, now = () => new Date(), timeoutMs = CRL_TIMEOUT_MS, maxBytes = CRL_MAX_BYTES } = {}) {
  let downloads = 0;
  const reads = new Map(); // url → Promise<{ ok, crl?, error?, status? }>

  return {
    async check(items) {
      const list = (items || []).filter((x) => x && x.cert && x.key);
      // every serial a URL must answer for, before the URL is read
      const serialsOf = new Map();
      for (const { cert } of list) {
        const serial = normalizeSerial(cert.serialHex);
        for (const url of crlUrlsOf(cert)) {
          if (!serialsOf.has(url)) serialsOf.set(url, new Set());
          if (serial) serialsOf.get(url).add(serial);
        }
      }
      const limit = createLimiter(CRL_CONCURRENCY);
      const read = (url) => {
        if (!reads.has(url)) {
          reads.set(url, limit.run(async () => {
            downloads += 1;
            const got = await fetchCrl(url, { fetchImpl, signal, timeoutMs, maxBytes });
            if (!got.ok) return got;
            try {
              return { ok: true, crl: parseCrl(got.bytes, { serials: serialsOf.get(url) }) };
            } catch (err) {
              if (err instanceof CrlParseError) return { ok: false, error: 'parse', status: null };
              throw err;
            }
          }, { signal }));
        }
        return reads.get(url);
      };
      const out = new Map();
      await Promise.all(list.map(async ({ key, cert, chain }) => {
        const urls = crlUrlsOf(cert);
        const base = () => ({ status: 'unknown', reason: null, reasonCode: null, time: null, crl: null, checkedAt: now().toISOString(), thisUpdate: null, nextUpdate: null, signature: null, signatureNote: null, error: null });
        if (!urls.length) {
          out.set(key, { ...base(), error: 'no-crl' });
          return;
        }
        let first = null;
        for (const url of urls) {
          const got = await read(url);
          const record = got.ok ? judge(got.crl, cert, chain, url, base()) : { ...base(), crl: url, error: got.error };
          if (record.status !== 'unknown') {
            out.set(key, record);
            return;
          }
          first = first || record;
        }
        out.set(key, first);
      }));
      return out;
    },
    downloads: () => downloads
  };

  /** What one CRL says about the certificate, its signature checked. */
  function judge(crl, cert, chain, url, base) {
    const at = now().getTime();
    const verdict = crlStatus(crl, cert, { url, now: at });
    const out = { ...base, crl: url, thisUpdate: isoOf(crl.thisUpdate), nextUpdate: isoOf(crl.nextUpdate) };
    if (verdict.code === 'issuer-mismatch') return { ...out, error: verdict.code };
    const issuer = issuerFromChain(cert, chain);
    if (!issuer) {
      Object.assign(out, { signature: 'not-verified', signatureNote: 'issuer-not-sent' });
    } else {
      const sig = verifyCrlSignature(crl, issuer);
      if (sig === 'failed') return { ...out, signature: 'failed', error: 'bad-signature' };
      Object.assign(out, sig === 'verified' ? { signature: 'verified' } : { signature: 'not-verified', signatureNote: 'algorithm' });
    }
    if (verdict.status === 'unknown') return { ...out, error: verdict.code };
    return { ...out, status: verdict.status, reason: verdict.reason, reasonCode: verdict.reasonCode, time: isoOf(verdict.time) };
  }
}
