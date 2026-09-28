/**
 * keycontinuity.js — was a certificate's key reused across renewals, or rotated? (Certificate
 * view › CT logs › Key continuity)
 *
 * The SHA-256 of the certificate's SubjectPublicKeyInfo — the data of a TLSA `3 1 1` record and
 * of an HPKP-style pin — is looked up on crt.sh: the certificates it has indexed with the same
 * public key. Other certificates with it mean the key was carried over renewals (a `3 1 1` record
 * keeps matching while it is). Everything else is said of crt.sh, not of CT: its coverage is
 * incomplete and can lag by days or weeks (on 2026-09-28 a leaf issued 24 days earlier with
 * embedded SCTs, which Cert Spotter listed with the same key hash, was missing from crt.sh by key
 * and by serial). So only this certificate on crt.sh is "no earlier certificate with this key on
 * crt.sh", not proof of a rotation; and none at all, for a certificate that carries SCTs or comes
 * from a known public CA, is "logged but not indexed by crt.sh" ('not-indexed'), never "not logged".
 *
 * Verified live on 2026-09-28 with `Origin: https://halilibrahimd27.github.io`:
 *   - crt.sh `GET /?spkisha256=<64 hex>&output=json` answers with ACAO `*` (a simple request, no
 *     preflight). Rows are `{ issuer_ca_id, issuer_name, name_value, id, not_before, not_after,
 *     serial_number, result_count }`, `name_value` being the hash itself (no host names, no
 *     `common_name`); expired certificates are included, and the precertificate and the final
 *     certificate are two rows with the same serial (`deduplicate=Y` does not fold them in this
 *     search). Dates are UTC without a zone. Under load crt.sh answers 429 or 502 without ACAO, so
 *     a browser sees a network error.
 *   - Cert Spotter reports `pubkey_sha256` for each issuance but cannot search by it, so crt.sh is
 *     the only keyless source.
 *
 * DOM-free. The one request goes through util.fetchJson with the caller's `fetchImpl` and
 * `signal`; it sends only the hash, never the certificate.
 */

import { fetchJson, retry, defaultShouldRetry, errorKind, throwIfAborted, ParseError } from './util.js';
import { computeFingerprints } from './x509.js';

/** crt.sh base URL (the JSON search, and the certificate pages a user opens). */
export const CRTSH_BASE = 'https://crt.sh/';
/** Timeout of the crt.sh search (slow for a key on many certificates). */
export const KEY_TIMEOUT_MS = 60000;
/** crt.sh's one retry after a server error or a CORS-less error page waits 4–8 s. */
export const KEY_RETRY_DELAY_MS = 4000;
/** At most this many rows are read (a key shared by thousands of certificates is reported as more). */
export const KEY_MAX_ROWS = 2000;
/**
 * What the lookup says about the key: 'reused' (crt.sh has other certificates with it), 'single'
 * (crt.sh has only this one), 'not-indexed' (crt.sh has none, but the certificate carries SCTs or
 * comes from a known public CA, so it was logged) or 'not-found' (crt.sh has none, and nothing says
 * the certificate was logged — a private CA's never is).
 */
export const KEY_STATUSES = Object.freeze(['reused', 'single', 'not-indexed', 'not-found']);

const DAY_MS = 86400000;
const HEX64_RE = /^[0-9a-f]{64}$/;

/**
 * The SHA-256 of a certificate's SubjectPublicKeyInfo (lowercase hex): the data of its TLSA
 * `3 1 1` record and the value crt.sh searches by. WebCrypto, with lib/sha.js where the page has none.
 * @param {{ spkiDer: Uint8Array }} cert a lib/x509.js Certificate
 * @param {{ subtle?: SubtleCrypto|null }} [opts]
 * @returns {Promise<string>}
 * @throws {TypeError} without SubjectPublicKeyInfo bytes
 */
export async function spkiSha256(cert, { subtle = globalThis.crypto?.subtle } = {}) {
  if (!cert || !(cert.spkiDer instanceof Uint8Array)) throw new TypeError('spkiSha256: expected a parsed certificate (spkiDer bytes)');
  return (await computeFingerprints(cert.spkiDer, { subtle })).sha256;
}

/**
 * The crt.sh search for every logged certificate with this public key.
 * @param {string} hex SHA-256 of the SubjectPublicKeyInfo (64 hex digits, any case)
 * @returns {string}
 * @throws {TypeError} for anything but 64 hex digits
 */
export function crtshKeyUrl(hex) {
  const h = String(hex ?? '').trim().toLowerCase();
  if (!HEX64_RE.test(h)) throw new TypeError('crtshKeyUrl: expected a SHA-256 in hex (64 digits)');
  return `${CRTSH_BASE}?spkisha256=${h}&output=json`;
}

/** 'YYYY-MM-DDTHH:MM:SS' (UTC without a zone, crt.sh) → Date, or null. */
function parseUtc(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  let s = value.trim().replace(' ', 'T');
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z';
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : new Date(t);
}

/** Lowercase hex without separators or leading 00 bytes (lib/x509.js serialHex), or null. */
function normalizeSerial(value) {
  let hex = String(value ?? '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (!hex) return null;
  if (hex.length % 2) hex = `0${hex}`;
  while (hex.length > 2 && hex.startsWith('00')) hex = hex.slice(2);
  return hex;
}

/** The CN of a DN as crt.sh ('C=US, O=…, CN=R11') or lib/x509.js writes it, lower case. */
function issuerCn(dn) {
  const m = /(?:^|,\s*)CN=([^,]+)/.exec(String(dn || ''));
  return m ? m[1].trim().toLowerCase() : '';
}

/**
 * @typedef {object} KeyCert one certificate with the key (its precertificate folded in)
 * @property {string[]} ids crt.sh ids, ascending (usually two: the precertificate and the certificate)
 * @property {string|null} serialHex
 * @property {string} issuer issuer DN as crt.sh prints it
 * @property {Date|null} notBefore
 * @property {Date|null} notAfter
 * @property {boolean} isThis the certificate the lookup was made for (same serial and issuer CN)
 * @property {string} url crt.sh page of its first id
 */

/**
 * crt.sh rows of a key search → one entry per certificate (serial and issuer), oldest first.
 * @param {unknown} rows the JSON answer
 * @param {{ cert?: { serialHex?: string, issuer?: { CN?: string }, issuerCN?: string|null, issuerDN?: string }|null, maxRows?: number }} [opts]
 *   cert: the certificate looked up (marks `isThis`)
 * @returns {{ certs: KeyCert[], rows: number, truncated: boolean }}
 * @throws {ParseError} when the answer is not an array
 */
export function parseKeyRows(rows, { cert = null, maxRows = KEY_MAX_ROWS } = {}) {
  if (!Array.isArray(rows)) throw new ParseError('Unexpected crt.sh response (expected a JSON array)');
  const wantSerial = cert ? normalizeSerial(cert.serialHex) : null;
  const wantCn = cert ? String((cert.issuer && cert.issuer.CN) || cert.issuerCN || issuerCn(cert.issuerDN) || '').trim().toLowerCase() : '';
  const bySerial = new Map();
  let read = 0;
  for (const row of rows) {
    if (read >= maxRows) break;
    read += 1;
    if (!row || typeof row !== 'object') continue;
    const serialHex = normalizeSerial(row.serial_number);
    const issuer = typeof row.issuer_name === 'string' ? row.issuer_name : '';
    const id = row.id === undefined || row.id === null ? null : String(row.id);
    const key = serialHex ? `${row.issuer_ca_id ?? issuer}|${serialHex}` : `id:${id}`;
    let entry = bySerial.get(key);
    if (!entry) {
      entry = {
        ids: [], serialHex, issuer, notBefore: parseUtc(row.not_before), notAfter: parseUtc(row.not_after),
        isThis: !!wantSerial && serialHex === wantSerial && (!wantCn || !issuerCn(issuer) || issuerCn(issuer) === wantCn),
        url: ''
      };
      bySerial.set(key, entry);
    }
    if (id && !entry.ids.includes(id)) entry.ids.push(id);
  }
  const t = (d) => (d instanceof Date ? d.getTime() : Infinity);
  const certs = [...bySerial.values()].map((c) => {
    const ids = c.ids.sort((a, b) => Number(a) - Number(b) || (a < b ? -1 : 1));
    return { ...c, ids, url: ids.length ? `${CRTSH_BASE}?id=${encodeURIComponent(ids[0])}` : `${CRTSH_BASE}` };
  }).sort((a, b) => t(a.notBefore) - t(b.notBefore) || (a.serialHex || '').localeCompare(b.serialHex || ''));
  return { certs, rows: rows.length, truncated: rows.length > maxRows };
}

/**
 * @typedef {object} KeyContinuity
 * @property {'reused'|'single'|'not-indexed'|'not-found'} status {@link KEY_STATUSES}
 * @property {number|null} sctCount SCTs embedded in the certificate (lib/x509.js; null: no SCT extension)
 * @property {boolean} expectLogged the certificate carries SCTs or its issuer is a known public CA:
 *   it was (or will soon be) in public logs, whatever crt.sh says
 * @property {number} total certificates with the key
 * @property {number} others certificates with the key other than this one
 * @property {boolean} thisLogged this certificate is among them
 * @property {number} before others issued before this one (renewals that kept the key)
 * @property {number} after others issued after it
 * @property {number} current certificates with the key valid at `now`
 * @property {Date|null} firstSeen the earliest notBefore
 * @property {Date|null} lastUntil the latest notAfter
 * @property {number|null} days days from `firstSeen` to `now` (to `lastUntil` once every certificate expired)
 * @property {string[]} issuers distinct issuer DNs, oldest first
 */

/**
 * What the certificates crt.sh has with a key say about it.
 * @param {KeyCert[]} certs {@link parseKeyRows}
 * @param {{ cert?: { notBefore?: Date|null, sctCount?: number|null }|null, now?: Date|number, publicCa?: boolean }} [opts]
 *   publicCa: the certificate's issuer is a known public CA (views/cert.js: lib/health.js caaIssuerInfo)
 * @returns {KeyContinuity}
 */
export function keyContinuity(certs, { cert = null, now = Date.now(), publicCa = false } = {}) {
  const list = Array.isArray(certs) ? certs : [];
  const at = now instanceof Date ? now.getTime() : Number(now);
  const self = list.find((c) => c.isThis) || null;
  const others = list.filter((c) => !c.isThis);
  const ref = self && self.notBefore ? self.notBefore.getTime()
    : cert && cert.notBefore instanceof Date ? cert.notBefore.getTime() : null;
  const time = (d) => (d instanceof Date ? d.getTime() : null);
  const starts = list.map((c) => time(c.notBefore)).filter((x) => x !== null);
  const ends = list.map((c) => time(c.notAfter)).filter((x) => x !== null);
  const firstSeen = starts.length ? new Date(Math.min(...starts)) : null;
  const lastUntil = ends.length ? new Date(Math.max(...ends)) : null;
  const until = lastUntil && lastUntil.getTime() < at ? lastUntil.getTime() : at;
  const sctCount = cert && Number.isInteger(cert.sctCount) ? cert.sctCount : null;
  const expectLogged = (sctCount ?? 0) > 0 || !!publicCa;
  return {
    status: others.length ? 'reused' : list.length ? 'single' : expectLogged ? 'not-indexed' : 'not-found',
    sctCount,
    expectLogged,
    total: list.length,
    others: others.length,
    thisLogged: !!self,
    before: ref === null ? 0 : others.filter((c) => time(c.notBefore) !== null && time(c.notBefore) < ref).length,
    after: ref === null ? 0 : others.filter((c) => time(c.notBefore) !== null && time(c.notBefore) > ref).length,
    current: list.filter((c) => time(c.notBefore) !== null && time(c.notBefore) <= at && time(c.notAfter) !== null && time(c.notAfter) >= at).length,
    firstSeen,
    lastUntil,
    days: firstSeen ? Math.max(0, Math.floor((until - firstSeen.getTime()) / DAY_MS)) : null,
    issuers: [...new Set(list.map((c) => c.issuer).filter(Boolean))]
  };
}

/** crt.sh is retried once on a server error or a CORS-less error page, never after a timeout. */
const crtshShouldRetry = (err) => errorKind(err) !== 'timeout' && defaultShouldRetry(err);

/**
 * Look a certificate's public key up on crt.sh (one search, retried once on a server or network
 * error). Sends only the SHA-256 of the key.
 * @param {{ spkiDer: Uint8Array, serialHex?: string, notBefore?: Date|null, sctCount?: number|null }} cert a lib/x509.js Certificate
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number, retryDelayMs?: number, now?: Date|number,
 *   subtle?: SubtleCrypto|null, publicCa?: boolean }} [opts] retryDelayMs: base of the one retry (tests pass 0);
 *   publicCa: see {@link keyContinuity}
 * @returns {Promise<KeyContinuity & { spki: string, url: string, certs: KeyCert[], rows: number, truncated: boolean, checkedAt: Date }>}
 * @throws the crt.sh failure (HttpError, a network TypeError, TimeoutError, ParseError) or AbortError
 */
export async function lookupKeyContinuity(cert, {
  fetchImpl, signal, timeoutMs = KEY_TIMEOUT_MS, retryDelayMs = KEY_RETRY_DELAY_MS, now = Date.now(), subtle = globalThis.crypto?.subtle,
  publicCa = false
} = {}) {
  throwIfAborted(signal);
  const spki = await spkiSha256(cert, { subtle });
  const url = crtshKeyUrl(spki);
  const rows = await retry(() => fetchJson(url, {
    fetchImpl, signal, timeoutMs, headers: { accept: 'application/json' }, credentials: 'omit', referrerPolicy: 'no-referrer'
  }), { retries: 1, baseDelayMs: retryDelayMs, maxDelayMs: 2 * retryDelayMs, signal, shouldRetry: crtshShouldRetry });
  const parsed = parseKeyRows(rows, { cert });
  return {
    spki, url, ...parsed, ...keyContinuity(parsed.certs, { cert, now, publicCa }), checkedAt: new Date(now instanceof Date ? now.getTime() : Number(now))
  };
}
