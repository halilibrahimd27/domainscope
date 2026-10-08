/**
 * revocation.js — is a certificate revoked? The browser side of the renewal radar, from Cert
 * Spotter, which reads the CAs' revocation lists. DOM-free.
 *
 * Verified live on 2026-10-08 with `Origin: https://halilibrahimd27.github.io`: Cert Spotter
 * `GET /v1/issuances?…&expand=revocation&expand=problem_reporting` answers with ACAO `*`, each
 * issuance with `revoked`, `revocation: { time, reason, checked_at }` (an RFC 5280 CRLReason code;
 * null time and reason when not revoked), `problem_reporting` (the CA's contact for a revocation or
 * a misissuance report: free text from the CA, shown as text, never as markup), `cert_sha256` and
 * `pubkey_sha256`. Only unexpired issuances are listed.
 *
 * - {@link spotterRevocation} / {@link problemReportingText}: those fields of one issuance (the
 *   Domain portfolio's CT tab reads them for every certificate, lib/ctwatch.js).
 * - {@link checkRevocation}: the Certificate view's "Is it revoked?": one exact-name request (Cert
 *   Spotter's single-host allowance, 100 an hour per address, shared with Load from CT through
 *   lib/ctcert.js ctCooldown), the issuance matched by the certificate's SHA-256 computed here —
 *   or, when Cert Spotter has only the precertificate, by the public key's SHA-256 and the exact
 *   validity. The certificate itself is never sent: only one of its names. Another page of
 *   issuances is read only while the certificate was not on the one before (at most
 *   {@link REVOCATION_MAX_PAGES}).
 */

import { fetchJson, errorKind, throwIfAborted, ParseError } from './util.js';
import { sha256 } from './sha.js';
import { CERTSPOTTER_ISSUANCES, CT_TIMEOUT_MS, ctCooldown, noteCertspotterLimit } from './ctcert.js';
import { reasonName } from './crl.js';

/** What "Is it revoked?" can answer. */
export const REVOCATION_STATUSES = Object.freeze(['good', 'revoked', 'not-found', 'expired', 'no-name', 'rate-limited', 'error']);
/** At most this many Cert Spotter pages for one certificate. */
export const REVOCATION_MAX_PAGES = 3;
/** A CA's problem-reporting text is cut to this many characters. */
export const PROBLEM_REPORTING_MAX_CHARS = 2000;

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
const hex = (bytes) => Array.from(bytes, (b) => HEX[b]).join('');
const dateOf = (v) => {
  const t = typeof v === 'string' && v.trim() ? Date.parse(v) : NaN;
  return Number.isNaN(t) ? null : new Date(t);
};

/**
 * The revocation fields of one Cert Spotter issuance: null when it carries none (an answer without
 * `expand=revocation`), else whether it is revoked (its `revoked` flag), when and why, and when
 * Cert Spotter last read the CA's revocation list.
 * @param {any} item
 * @returns {{ revoked: boolean|null, time: Date|null, reasonCode: number|null, reason: string|null, checkedAt: Date|null }|null}
 */
export function spotterRevocation(item) {
  if (!item || typeof item !== 'object') return null;
  const r = item.revocation && typeof item.revocation === 'object' && !Array.isArray(item.revocation) ? item.revocation : null;
  if (!r) return null;
  const code = Number.isInteger(r.reason) ? r.reason : null;
  return {
    revoked: typeof item.revoked === 'boolean' ? item.revoked : null,
    time: dateOf(r.time),
    reasonCode: code,
    reason: reasonName(code),
    checkedAt: dateOf(r.checked_at)
  };
}

/**
 * A CA's problem-reporting text as the page shows it: control characters (other than line breaks)
 * and bidi overrides out, runs of blank lines folded, cut to {@link PROBLEM_REPORTING_MAX_CHARS};
 * null for none.
 * @param {unknown} value
 * @returns {string|null}
 */
export function problemReportingText(value) {
  if (typeof value !== 'string') return null;
  const clean = value
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  if (!clean) return null;
  return clean.length > PROBLEM_REPORTING_MAX_CHARS ? `${clean.slice(0, PROBLEM_REPORTING_MAX_CHARS - 1)}…` : clean;
}

/**
 * The name "Is it revoked?" asks Cert Spotter for: the certificate's first DNS name that is no
 * wildcard, else its first wildcard (`*.example.com` lists the certificates holding that very
 * name); null for a certificate without one.
 * @param {{ hostnames?: string[] }} cert lib/x509.js Certificate
 * @returns {string|null}
 */
export function revocationName(cert) {
  const names = cert && Array.isArray(cert.hostnames) ? cert.hostnames.filter((n) => typeof n === 'string' && n) : [];
  return names.find((n) => !n.startsWith('*.')) || names[0] || null;
}

/**
 * Cert Spotter's exact-name query of {@link checkRevocation}: the name's issuances (a wildcard
 * name: the certificates holding it), the revocation and problem-reporting fields expanded.
 * @param {string} name
 * @param {{ after?: string|null }} [opts]
 * @returns {string}
 */
export function revocationUrl(name, { after = null } = {}) {
  const tail = after ? `&after=${encodeURIComponent(after)}` : '';
  return `${CERTSPOTTER_ISSUANCES}?domain=${encodeURIComponent(name)}&expand=revocation&expand=problem_reporting${tail}`;
}

/**
 * The issuance of `items` that is this certificate: by its SHA-256, else (only the precertificate
 * logged) by the public key's SHA-256 and the exact validity.
 * @param {any[]} items
 * @param {{ sha256: string, spkiSha256: string|null, notBefore: Date, notAfter: Date }} want
 * @returns {{ item: object, by: 'certificate'|'issuance' }|null}
 */
export function matchIssuance(items, want) {
  const list = Array.isArray(items) ? items.filter((x) => x && typeof x === 'object') : [];
  const exact = list.find((x) => typeof x.cert_sha256 === 'string' && x.cert_sha256.toLowerCase() === want.sha256);
  if (exact) return { item: exact, by: 'certificate' };
  if (!want.spkiSha256) return null;
  const sameTime = (v, d) => {
    const t = dateOf(v);
    return !!t && !!d && Math.abs(t.getTime() - d.getTime()) < 1000;
  };
  const issuance = list.find((x) => typeof x.pubkey_sha256 === 'string' && x.pubkey_sha256.toLowerCase() === want.spkiSha256
    && sameTime(x.not_before, want.notBefore) && sameTime(x.not_after, want.notAfter));
  return issuance ? { item: issuance, by: 'issuance' } : null;
}

const JSON_INIT = Object.freeze({ headers: { accept: 'application/json' }, credentials: 'omit', referrerPolicy: 'no-referrer' });

/** Short error text for a result (never a stack). */
const errorText = (err) => String((err && err.message) || err || 'Unknown error').replace(/\s+/g, ' ').trim().slice(0, 300);

/**
 * @typedef {object} RevocationCheck
 * @property {string} status {@link REVOCATION_STATUSES}
 * @property {string|null} name the name sent to Cert Spotter (null: nothing was sent)
 * @property {number} requests HTTP requests sent
 * @property {'certificate'|'issuance'|null} matchedBy how Cert Spotter's issuance was matched
 * @property {{ time: Date|null, reasonCode: number|null, reason: string|null, checkedAt: Date|null }|null} revocation
 * @property {string|null} problemReporting the CA's contact ({@link problemReportingText})
 * @property {boolean} truncated the certificate was not on the pages read, and more were listed
 * @property {object|null} quota lib/sourceinfo SourceQuota while Cert Spotter's hourly quota is used up
 * @property {string|null} error
 * @property {string|null} errorKind
 * @property {Date} at
 */

/**
 * "Is it revoked?" of one certificate. Nothing is sent for an expired certificate (Cert Spotter
 * lists unexpired ones only), one without a name, or while Cert Spotter's quota is used up. Only
 * an abort rejects.
 * @param {object} cert lib/x509.js Certificate (der, spkiDer, hostnames, notBefore, notAfter)
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, now?: Date|number, cooldown?: ReturnType<import('./ctcert.js').createCtCooldown>,
 *   timeoutMs?: number, maxPages?: number }} [opts]
 * @returns {Promise<RevocationCheck>}
 */
export async function checkRevocation(cert, {
  fetchImpl, signal, now = Date.now(), cooldown = ctCooldown, timeoutMs = CT_TIMEOUT_MS, maxPages = REVOCATION_MAX_PAGES
} = {}) {
  throwIfAborted(signal);
  const at = now instanceof Date ? now.getTime() : Number(now);
  const out = {
    status: 'not-found', name: null, requests: 0, matchedBy: null, revocation: null, problemReporting: null,
    truncated: false, quota: null, error: null, errorKind: null, at: new Date(at)
  };
  if (cert.notAfter instanceof Date && cert.notAfter.getTime() < at) return { ...out, status: 'expired' };
  const name = revocationName(cert);
  if (!name) return { ...out, status: 'no-name' };
  const cooling = cooldown.get(at);
  if (cooling) return { ...out, status: 'rate-limited', quota: cooling };
  out.name = name;
  const want = {
    sha256: hex(sha256(cert.der)),
    spkiSha256: cert.spkiDer && cert.spkiDer.length ? hex(sha256(cert.spkiDer)) : null,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter
  };
  let after = null;
  for (let page = 0; page < Math.max(1, maxPages); page += 1) {
    let items;
    try {
      out.requests += 1;
      items = await fetchJson(revocationUrl(name, { after }), { ...JSON_INIT, fetchImpl, signal, timeoutMs });
      if (!Array.isArray(items)) throw new ParseError('Unexpected Cert Spotter response (expected a JSON array)');
    } catch (err) {
      const kind = errorKind(err);
      if (kind === 'abort') throw err;
      const quota = noteCertspotterLimit(err, { at, cooldown });
      return { ...out, status: quota ? 'rate-limited' : 'error', quota, error: errorText(err), errorKind: kind };
    }
    const hit = matchIssuance(items, want);
    if (hit) {
      const r = spotterRevocation(hit.item);
      const revoked = hit.item.revoked === true;
      return {
        ...out,
        status: revoked ? 'revoked' : 'good',
        matchedBy: hit.by,
        revocation: r ? { time: r.time, reasonCode: r.reasonCode, reason: r.reason, checkedAt: r.checkedAt } : null,
        problemReporting: problemReportingText(hit.item.problem_reporting)
      };
    }
    if (!items.length) return out;
    const last = items[items.length - 1];
    if (!last || last.id === undefined || last.id === null || String(last.id) === after) return out;
    after = String(last.id);
  }
  return { ...out, truncated: true };
}
