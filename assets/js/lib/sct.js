/**
 * sct.js — the Signed Certificate Timestamps embedded in a certificate, the CT logs that issued
 * them and the certificate's standing under Chrome's and Apple's Certificate Transparency
 * policies (spec §5.82). Built for a Certificate › Transparency tab (ROADMAP P2.9) that no view
 * shows yet: nothing in the page imports this module.
 *
 * - {@link certificateScts} finds extension 1.3.6.1.4.1.11129.2.4.2 in a certificate's DER (its
 *   own small DER walk, so this module does not need lib/x509.js) and {@link decodeSctList}
 *   decodes the TLS-encoded SignedCertificateTimestampList inside its OCTET STRING (RFC 6962
 *   §3.3): each SCT's version, log ID, timestamp, extensions, hash and signature algorithms and
 *   signature. A malformed list or SCT is a code, never an exception.
 * - {@link compactLogList} turns Google's CT log list v3 (CT_LOG_LIST_URL) into the compact form
 *   of the bundled snapshot (assets/data/ctlogs.json, refreshed by tools/build-ctlogs.mjs);
 *   {@link indexLogs} maps log IDs to logs (name, operator, state, URL, shard, API).
 *   {@link loadCtLogList} fetches the live list (it sends nothing about the certificate) and falls
 *   back to the bundled copy; only an abort rejects.
 * - {@link evaluateCtPolicies} checks the embedded SCTs against both policies at the time of
 *   check, as both policies are worded (Chrome:
 *   https://googlechrome.github.io/CertificateTransparency/ct_policy.html; Apple:
 *   https://support.apple.com/en-us/103214, published 2025-04-21), with Google's log states for
 *   both: compliant, not compliant or cannot tell, each with reason codes. SCTs a server sends
 *   in the TLS handshake or a stapled OCSP response are never in a file, so a certificate without
 *   embedded SCTs is "cannot tell". SCT signatures are not verified.
 *
 * DOM-free; runs in browsers and Node 22.
 */

import { fetchJson, errorKind } from './util.js';

/** The X.509 extension that carries the embedded SCT list (RFC 6962 §3.3). */
export const SCT_OID = '1.3.6.1.4.1.11129.2.4.2';

/** Google's CT log list v3: the logs Chrome recognises, with their operators and states. */
export const CT_LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json';

/** The site's own copy of the list (compact form), used when the live list cannot be fetched. */
export const BUNDLED_LOG_LIST_URL = new URL('../../data/ctlogs.json', import.meta.url).href;

/** The status source id of the live log list (lib/sourcestatus.js, `srcst.source.ctloglist`). */
export const LOG_LIST_SOURCE = 'ctloglist';

/** Where the embedded SCTs of a certificate stand: found, none, a precertificate (no SCTs by design) or unreadable. */
export const SCT_LIST_STATUSES = Object.freeze(['embedded', 'none', 'precertificate', 'malformed']);

/** Why a list or one SCT could not be read completely. */
export const SCT_PROBLEMS = Object.freeze(['truncated', 'trailing-data', 'empty', 'not-der', 'unknown-version', 'bad-timestamp']);

/** The states of a log in the v3 list. */
export const LOG_STATES = Object.freeze(['pending', 'qualified', 'usable', 'readonly', 'retired', 'rejected']);

/** States in which a log is "currently approved" at the time of check (both policies). */
export const CURRENT_STATES = Object.freeze(['qualified', 'usable', 'readonly']);

/** Where the log list in use came from. */
export const LOG_LIST_SOURCES = Object.freeze(['live', 'bundled', 'none']);

/**
 * How one SCT counts: `current` (a currently approved log), `retired` (a retired log, the SCT
 * older than its retirement), `after-retirement`, `not-approved` (a pending or rejected log),
 * `unknown-log` (not in the list), `future` (timestamp after the time of check), `unreadable`
 * (another version, or malformed), `no-list` (no log list to tell).
 */
export const SCT_STATUSES = Object.freeze(['current', 'retired', 'after-retirement', 'not-approved', 'unknown-log', 'future', 'unreadable', 'no-list']);

/** The two policies, in display order. */
export const CT_POLICIES = Object.freeze(['chrome', 'apple']);

/** A policy's verdict on the embedded SCTs. */
export const CT_VERDICTS = Object.freeze(['compliant', 'not-compliant', 'cannot-tell']);

/** Every reason code a verdict can carry (`sct.reason.<code>` in the UI). */
export const CT_REASONS = Object.freeze([
  'no-scts', 'precertificate', 'malformed-list', 'no-log-list', 'too-few-logs', 'one-operator', 'no-current-log', 'no-rfc6962-log', 'lifetime-over-398', 'unknown-logs-bundled'
]);

/** TLS HashAlgorithm names (RFC 5246 §7.4.1.4.1); RFC 6962 allows only SHA-256. */
export const HASH_ALGORITHMS = Object.freeze({ 0: 'none', 1: 'MD5', 2: 'SHA-1', 3: 'SHA-224', 4: 'SHA-256', 5: 'SHA-384', 6: 'SHA-512', 8: 'Intrinsic' });

/** TLS SignatureAlgorithm names; RFC 6962 allows ECDSA (P-256) and RSA. */
export const SIGNATURE_ALGORITHMS = Object.freeze({ 0: 'anonymous', 1: 'RSA', 2: 'DSA', 3: 'ECDSA', 7: 'Ed25519', 8: 'Ed448' });

/** Lifetime limit (days) of the two-SCT row of both policies; longer needs three. */
export const SHORT_LIFETIME_DAYS = 180;

/** Apple's table stops at 398 days. */
export const APPLE_MAX_LIFETIME_DAYS = 398;

const DAY = 86400000;
const MAX_DATE_MS = 8.64e15;
/** DER content of OID 1.3.6.1.4.1.11129.2.4.2. */
const SCT_OID_BYTES = Object.freeze([0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]);

/**
 * @typedef {object} Sct one decoded SCT
 * @property {number} index position in the list (0-based)
 * @property {number|null} version the raw version byte (0 is v1); null for an empty entry
 * @property {string|null} logId base64 log ID (SHA-256 of the log's public key)
 * @property {string|null} logIdHex the same in hex
 * @property {number|null} timestamp milliseconds since the epoch
 * @property {string} extensions the CtExtensions bytes in hex ('' when none)
 * @property {number|null} hashAlgorithm TLS HashAlgorithm code
 * @property {number|null} signatureAlgorithm TLS SignatureAlgorithm code
 * @property {string|null} hashName {@link HASH_ALGORITHMS} name, null for an unknown code
 * @property {string|null} signatureName {@link SIGNATURE_ALGORITHMS} name, null for an unknown code
 * @property {boolean} algorithmAllowed SHA-256 with ECDSA or RSA, as RFC 6962 requires
 * @property {string|null} signature base64 signature
 * @property {number} signatureLength signature bytes
 * @property {number} length bytes of the serialized SCT
 * @property {string|null} problem {@link SCT_PROBLEMS} code, null when the SCT was read completely
 */

/**
 * @typedef {object} CertificateScts
 * @property {string} status {@link SCT_LIST_STATUSES}
 * @property {Sct[]} scts
 * @property {string|null} error {@link SCT_PROBLEMS} code of the list ('malformed' status, or
 *   a list read only in part)
 * @property {boolean} critical the extension is marked critical
 */

function asBytes(x) {
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  return null;
}

const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function toBase64(b) {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

/** One DER TLV at `pos` (low tag numbers, definite lengths of up to 4 octets), or null. */
function readTlv(bytes, pos, end) {
  if (pos + 2 > end) return null;
  const tag = bytes[pos];
  if ((tag & 0x1f) === 0x1f) return null;
  let len = bytes[pos + 1];
  let p = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > end) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[p++];
  }
  if (p + len > end) return null;
  return { tag, start: p, end: p + len };
}

function childrenOf(bytes, node) {
  const out = [];
  for (let p = node.start; p < node.end;) {
    const c = readTlv(bytes, p, node.end);
    if (!c) return null;
    out.push(c);
    p = c.end;
  }
  return out;
}

function sameBytes(bytes, node, want) {
  if (node.end - node.start !== want.length) return false;
  for (let i = 0; i < want.length; i++) if (bytes[node.start + i] !== want[i]) return false;
  return true;
}

/**
 * The embedded SCT list extension of a DER certificate: the TLS-encoded list (the contents of
 * the OCTET STRING inside extnValue), or why it could not be found.
 * @param {Uint8Array|ArrayBuffer} der
 * @returns {{ found: boolean, critical: boolean, value: Uint8Array|null, error: string|null }}
 */
export function findSctExtension(der) {
  const none = { found: false, critical: false, value: null, error: null };
  const bytes = asBytes(der);
  const root = bytes && readTlv(bytes, 0, bytes.length);
  const top = root && root.tag === 0x30 ? childrenOf(bytes, root) : null;
  const tbs = top && top[0] && top[0].tag === 0x30 ? childrenOf(bytes, top[0]) : null;
  if (!tbs) return { ...none, error: 'not-der' };
  const field = tbs.find((f) => f.tag === 0xa3);
  if (!field) return none;
  const wrapper = childrenOf(bytes, field);
  const exts = wrapper && wrapper.length === 1 && wrapper[0].tag === 0x30 ? childrenOf(bytes, wrapper[0]) : null;
  if (!exts) return { ...none, error: 'not-der' };
  for (const ext of exts) {
    const parts = ext.tag === 0x30 ? childrenOf(bytes, ext) : null;
    if (!parts || parts.length < 2 || parts[0].tag !== 0x06 || !sameBytes(bytes, parts[0], SCT_OID_BYTES)) continue;
    const critical = parts.length === 3 && parts[1].tag === 0x01 && bytes[parts[1].start] !== 0;
    const value = parts[parts.length - 1];
    const inner = value.tag === 0x04 ? readTlv(bytes, value.start, value.end) : null;
    if (!inner || inner.tag !== 0x04 || inner.end !== value.end) return { found: true, critical, value: null, error: 'not-der' };
    return { found: true, critical, value: bytes.slice(inner.start, inner.end), error: null };
  }
  return none;
}

/** Decodes one serialized SCT (RFC 6962 §3.2). */
function decodeSct(b, index) {
  const sct = {
    index, version: b.length ? b[0] : null, logId: null, logIdHex: null, timestamp: null, extensions: '',
    hashAlgorithm: null, signatureAlgorithm: null, hashName: null, signatureName: null, algorithmAllowed: false,
    signature: null, signatureLength: 0, length: b.length, problem: null
  };
  if (!b.length) return { ...sct, problem: 'truncated' };
  if (b[0] !== 0) return { ...sct, problem: 'unknown-version' };
  if (b.length < 43) return { ...sct, problem: 'truncated' };
  const logId = b.subarray(1, 33);
  sct.logId = toBase64(logId);
  sct.logIdHex = toHex(logId);
  let ms = 0;
  for (let i = 33; i < 41; i++) ms = ms * 256 + b[i];
  sct.timestamp = ms;
  const extLen = (b[41] << 8) | b[42];
  let p = 43;
  if (p + extLen > b.length) return { ...sct, problem: 'truncated' };
  sct.extensions = toHex(b.subarray(p, p + extLen));
  p += extLen;
  if (p + 4 > b.length) return { ...sct, problem: 'truncated' };
  sct.hashAlgorithm = b[p];
  sct.signatureAlgorithm = b[p + 1];
  sct.hashName = HASH_ALGORITHMS[b[p]] ?? null;
  sct.signatureName = SIGNATURE_ALGORITHMS[b[p + 1]] ?? null;
  sct.algorithmAllowed = b[p] === 4 && (b[p + 1] === 1 || b[p + 1] === 3);
  const sigLen = (b[p + 2] << 8) | b[p + 3];
  p += 4;
  if (p + sigLen > b.length) return { ...sct, problem: 'truncated' };
  sct.signature = toBase64(b.subarray(p, p + sigLen));
  sct.signatureLength = sigLen;
  p += sigLen;
  if (p !== b.length) sct.problem = 'trailing-data';
  else if (ms > MAX_DATE_MS) sct.problem = 'bad-timestamp';
  return sct;
}

/**
 * Decodes a TLS-encoded SignedCertificateTimestampList: `opaque SerializedSCT<1..2^16-1>` inside
 * `SerializedSCT sct_list<1..2^16-1>`. What could be read is returned with the first problem.
 * @param {Uint8Array|ArrayBuffer} list
 * @returns {{ scts: Sct[], error: string|null }} error: {@link SCT_PROBLEMS} code of the list
 */
export function decodeSctList(list) {
  const bytes = asBytes(list);
  if (!bytes || bytes.length < 2) return { scts: [], error: 'truncated' };
  const total = (bytes[0] << 8) | bytes[1];
  let error = total + 2 > bytes.length ? 'truncated' : total + 2 < bytes.length ? 'trailing-data' : null;
  const end = Math.min(2 + total, bytes.length);
  const scts = [];
  for (let p = 2; p < end;) {
    if (p + 2 > end) { error = 'truncated'; break; }
    const len = (bytes[p] << 8) | bytes[p + 1];
    p += 2;
    if (p + len > end) { error = 'truncated'; break; }
    scts.push(decodeSct(bytes.subarray(p, p + len), scts.length));
    p += len;
  }
  if (!scts.length && !error) error = 'empty';
  return { scts, error };
}

/**
 * The embedded SCTs of a parsed certificate (lib/x509.js shape: `der`, `isPrecertificate`).
 * @param {{ der: Uint8Array, isPrecertificate?: boolean }} cert
 * @returns {CertificateScts}
 */
export function certificateScts(cert) {
  const ext = findSctExtension(cert && cert.der);
  if (ext.error === 'not-der' && !ext.found) return { status: 'malformed', scts: [], error: 'not-der', critical: false };
  if (!ext.found) return { status: cert && cert.isPrecertificate ? 'precertificate' : 'none', scts: [], error: null, critical: false };
  if (!ext.value) return { status: 'malformed', scts: [], error: ext.error, critical: ext.critical };
  const { scts, error } = decodeSctList(ext.value);
  return { status: scts.length ? 'embedded' : 'malformed', scts, error, critical: ext.critical };
}

/* --- the log list --------------------------------------------------------------------------- */

/**
 * @typedef {object} CtLog one log of the compact list
 * @property {string} id base64 log ID
 * @property {string} name the list's description, e.g. "Google 'Argon2026h2' log"
 * @property {string} url submission URL (RFC 6962 base URL, or a static-ct-api log's submission prefix)
 * @property {string} key base64 SubjectPublicKeyInfo
 * @property {string} state {@link LOG_STATES}
 * @property {string|null} since when the log entered that state (ISO 8601)
 * @property {string|null} start shard start (inclusive, ISO 8601)
 * @property {string|null} end shard end (exclusive, ISO 8601)
 * @property {'rfc6962'|'static'} api RFC 6962 log or a static-ct-api ("tiled") log
 */

/**
 * @typedef {object} CompactLogList
 * @property {string} version the list's own version
 * @property {string} timestamp the list's log_list_timestamp
 * @property {{ name: string, logs: CtLog[] }[]} operators
 */

const iso = (v) => (typeof v === 'string' && Number.isFinite(Date.parse(v)) ? v : null);

function compactLog(log, api) {
  if (!log || typeof log !== 'object' || typeof log.log_id !== 'string') return null;
  let raw;
  try {
    raw = atob(log.log_id);
  } catch {
    return null;
  }
  if (raw.length !== 32) return null;
  const entry = log.state && typeof log.state === 'object' ? Object.entries(log.state).find(([k]) => LOG_STATES.includes(k)) : null;
  const interval = log.temporal_interval || {};
  return {
    id: log.log_id,
    name: String(log.description || ''),
    url: String(log.url || log.submission_url || ''),
    key: typeof log.key === 'string' ? log.key : '',
    state: entry ? entry[0] : 'pending',
    since: entry ? iso(entry[1] && entry[1].timestamp) : null,
    start: iso(interval.start_inclusive),
    end: iso(interval.end_exclusive),
    api
  };
}

/**
 * Google's CT log list v3 in the compact form of the bundled snapshot: per operator, its RFC 6962
 * logs and its static-ct-api ("tiled") logs, with only the fields this page uses. A compact list
 * passes through unchanged (validated).
 * @param {any} json the v3 list (or a compact list)
 * @returns {CompactLogList|null} null when `json` is not a log list
 */
export function compactLogList(json) {
  if (!json || typeof json !== 'object' || !Array.isArray(json.operators)) return null;
  const compact = typeof json.timestamp === 'string' && !('log_list_timestamp' in json);
  const operators = [];
  for (const op of json.operators) {
    if (!op || typeof op !== 'object' || typeof op.name !== 'string') continue;
    const logs = compact
      ? (Array.isArray(op.logs) ? op.logs : []).map((l) => (l && typeof l.id === 'string'
        ? compactLog({ log_id: l.id, description: l.name, url: l.url, key: l.key, state: { [l.state]: { timestamp: l.since } }, temporal_interval: { start_inclusive: l.start, end_exclusive: l.end } }, l.api === 'static' ? 'static' : 'rfc6962')
        : null))
      : [
        ...(Array.isArray(op.logs) ? op.logs : []).map((l) => compactLog(l, 'rfc6962')),
        ...(Array.isArray(op.tiled_logs) ? op.tiled_logs : []).map((l) => compactLog(l, 'static'))
      ];
    operators.push({ name: op.name, logs: logs.filter(Boolean) });
  }
  if (!operators.some((o) => o.logs.length)) return null;
  return {
    version: String(json.version ?? ''),
    timestamp: iso(compact ? json.timestamp : json.log_list_timestamp) || '',
    operators
  };
}

/**
 * Log ID → log with its operator's name.
 * @param {CompactLogList|null} list
 * @returns {Map<string, CtLog & { operator: string }>}
 */
export function indexLogs(list) {
  const map = new Map();
  for (const op of (list && list.operators) || []) for (const log of op.logs) if (!map.has(log.id)) map.set(log.id, { ...log, operator: op.name });
  return map;
}

/**
 * @typedef {object} LogListLoad
 * @property {string} source {@link LOG_LIST_SOURCES}
 * @property {CompactLogList|null} list
 * @property {object|null} failure why the live list was not used (a lib/sourcestatus.js failure:
 *   `{ source: 'ctloglist', error, errorKind, status, retryAfterMs, at }`); null when it was, or
 *   when it was not asked (`live: false`)
 * @property {object|null} bundledFailure why the bundled copy could not be read (source 'none')
 */

function failureOf(err, now, source = LOG_LIST_SOURCE) {
  return {
    source,
    error: err && err.message ? String(err.message) : String(err),
    errorKind: errorKind(err),
    status: Number.isInteger(err && err.status) ? err.status : null,
    retryAfterMs: Number.isFinite(err && err.retryAfterMs) ? err.retryAfterMs : null,
    at: now()
  };
}

/**
 * Loads the log list: Google's live list (unless `live` is false: offline), else the site's
 * bundled copy. Sends nothing about any certificate. Only an abort rejects.
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number, live?: boolean,
 *   bundledUrl?: string, now?: () => number }} [opts]
 * @returns {Promise<LogListLoad>}
 */
export async function loadCtLogList({ fetchImpl = globalThis.fetch, signal, timeoutMs = 15000, live = true, bundledUrl = BUNDLED_LOG_LIST_URL, now = Date.now } = {}) {
  let failure = null;
  if (live) {
    try {
      const list = compactLogList(await fetchJson(CT_LOG_LIST_URL, { fetchImpl, signal, timeoutMs, credentials: 'omit' }));
      if (list) return { source: 'live', list, failure: null, bundledFailure: null };
      failure = { source: LOG_LIST_SOURCE, error: 'not a CT log list', errorKind: 'parse', status: null, retryAfterMs: null, at: now() };
    } catch (err) {
      if (errorKind(err) === 'abort') throw err;
      failure = failureOf(err, now);
    }
  }
  try {
    const list = compactLogList(await fetchJson(bundledUrl, { fetchImpl, signal, timeoutMs }));
    if (list) return { source: 'bundled', list, failure, bundledFailure: null };
    return { source: 'none', list: null, failure, bundledFailure: { source: 'self', error: 'not a CT log list', errorKind: 'parse', status: null, retryAfterMs: null, at: now() } };
  } catch (err) {
    if (errorKind(err) === 'abort') throw err;
    return { source: 'none', list: null, failure, bundledFailure: failureOf(err, now, 'self') };
  }
}

/* --- the policies --------------------------------------------------------------------------- */

/**
 * @typedef {object} SctStanding how one SCT counts
 * @property {number} index
 * @property {string} status {@link SCT_STATUSES}
 * @property {(CtLog & { operator: string })|null} log
 */

/**
 * @typedef {object} PolicyVerdict
 * @property {string} verdict {@link CT_VERDICTS}
 * @property {string[]} reasons {@link CT_REASONS} codes (empty when compliant)
 * @property {number|null} required SCTs from distinct logs the lifetime needs (null: no row)
 * @property {number} logs distinct logs whose SCTs count
 * @property {number} counted what counts toward `required` (Apple: at most `perOperator` per operator)
 * @property {number} operators distinct operators of those logs
 * @property {number} current SCTs from a currently approved log
 * @property {number|null} perOperator Apple's cap per operator (null for Chrome)
 * @property {number} rfc6962 counted logs that are RFC 6962 logs (Apple needs one)
 */

/**
 * @typedef {object} CtPolicyResult
 * @property {number} lifetimeDays notAfter − notBefore, in days (as Chrome computes it)
 * @property {boolean} expired notAfter is before the time of check
 * @property {string} listSource {@link LOG_LIST_SOURCES}
 * @property {SctStanding[]} standings one per SCT, in list order
 * @property {number} unknownLogs SCTs whose log is not in the list
 * @property {{ chrome: PolicyVerdict, apple: PolicyVerdict }} policies
 */

function verdictOf(base, reasons, { listSource, unknown }) {
  if (!reasons.length) return { ...base, verdict: 'compliant', reasons };
  // A log missing from an old bundled list may be a newer one the live list knows.
  if (listSource === 'bundled' && unknown > 0 && !reasons.includes('lifetime-over-398')) return { ...base, verdict: 'cannot-tell', reasons: ['unknown-logs-bundled', ...reasons] };
  return { ...base, verdict: 'not-compliant', reasons };
}

/**
 * Checks a certificate's embedded SCTs against Chrome's and Apple's CT policies at the time of
 * check (`now`), with the log states of `logs` (Google's list, for both policies).
 *
 * Chrome: one SCT from a Qualified, Usable or ReadOnly log; SCTs from at least 2 distinct logs
 * (3 when the lifetime is over 180 days) that are Qualified, Usable, ReadOnly or Retired (an SCT of
 * a Retired log only when it is older than the retirement); among them at least two operators.
 * Apple: one SCT from a currently approved log; 2 SCTs at most one per operator (180 days or less)
 * or 3 at most two per operator (181 to 398 days) from once or currently approved logs; one SCT
 * from an RFC 6962 log. An SCT dated after `now`, of another version or malformed never counts.
 * @param {{ notBefore: Date, notAfter: Date, isPrecertificate?: boolean }} cert
 * @param {CertificateScts} embedded {@link certificateScts}
 * @param {Map<string, CtLog & { operator: string }>|null} logs {@link indexLogs}; null: no list
 * @param {{ now?: number, listSource?: string }} [opts]
 * @returns {CtPolicyResult}
 */
export function evaluateCtPolicies(cert, embedded, logs, { now = Date.now(), listSource = logs ? 'live' : 'none' } = {}) {
  const notBefore = cert.notBefore instanceof Date ? cert.notBefore.getTime() : Number(cert.notBefore);
  const notAfter = cert.notAfter instanceof Date ? cert.notAfter.getTime() : Number(cert.notAfter);
  const lifetimeDays = (notAfter - notBefore) / DAY;
  const scts = embedded.status === 'embedded' && !embedded.error ? embedded.scts : [];
  const standings = embedded.scts.map((sct) => {
    const log = logs && sct.logId ? logs.get(sct.logId) || null : null;
    let status;
    if (embedded.error || sct.problem || sct.version !== 0) status = 'unreadable';
    else if (!logs) status = 'no-list';
    else if (!log) status = 'unknown-log';
    else if (sct.timestamp > now) status = 'future';
    else if (CURRENT_STATES.includes(log.state)) status = 'current';
    else if (log.state === 'retired') status = log.since && sct.timestamp < Date.parse(log.since) ? 'retired' : 'after-retirement';
    else status = 'not-approved';
    return { index: sct.index, status, log };
  });
  const unknownLogs = standings.filter((s) => s.status === 'unknown-log').length;
  const valid = scts.length ? standings.filter((s) => s.status === 'current' || s.status === 'retired') : [];
  const byLog = new Map();
  for (const s of valid) if (!byLog.has(s.log.id)) byLog.set(s.log.id, s);
  const counted = [...byLog.values()];
  const operators = new Set(counted.map((s) => s.log.operator));
  const current = valid.filter((s) => s.status === 'current').length;
  const rfc6962 = counted.filter((s) => s.log.api === 'rfc6962').length;
  const ctx = { listSource, unknown: unknownLogs };

  const early = [];
  if (embedded.status === 'precertificate') early.push('precertificate');
  else if (embedded.status === 'none') early.push('no-scts');
  else if (embedded.status === 'malformed' || embedded.error) early.push('malformed-list');
  else if (!logs) early.push('no-log-list');
  const cannotTell = embedded.status !== 'malformed' && !embedded.error;

  const chromeRequired = lifetimeDays > SHORT_LIFETIME_DAYS ? 3 : 2;
  const chromeBase = { required: chromeRequired, logs: counted.length, counted: counted.length, operators: operators.size, current, perOperator: null, rfc6962 };
  const appleRequired = lifetimeDays > APPLE_MAX_LIFETIME_DAYS ? null : lifetimeDays > SHORT_LIFETIME_DAYS ? 3 : 2;
  const cap = appleRequired === 3 ? 2 : 1;
  const perOp = new Map();
  for (const s of counted) perOp.set(s.log.operator, (perOp.get(s.log.operator) || 0) + 1);
  const appleCounted = [...perOp.values()].reduce((n, c) => n + Math.min(c, cap), 0);
  const appleBase = { required: appleRequired, logs: counted.length, counted: appleCounted, operators: operators.size, current, perOperator: cap, rfc6962 };

  if (early.length) {
    const verdict = cannotTell ? 'cannot-tell' : 'not-compliant';
    return {
      lifetimeDays, expired: notAfter < now, listSource, standings, unknownLogs,
      policies: { chrome: { ...chromeBase, verdict, reasons: early }, apple: { ...appleBase, verdict, reasons: early } }
    };
  }

  const chromeReasons = [];
  if (!current) chromeReasons.push('no-current-log');
  if (counted.length < chromeRequired) chromeReasons.push('too-few-logs');
  if (operators.size < 2) chromeReasons.push('one-operator');

  const appleReasons = [];
  if (appleRequired === null) appleReasons.push('lifetime-over-398');
  else {
    if (!current) appleReasons.push('no-current-log');
    if (counted.length < appleRequired) appleReasons.push('too-few-logs');
    // At most one SCT per operator (two for 181 to 398 days) is the same as two operators at least.
    if (appleCounted < appleRequired && operators.size < 2) appleReasons.push('one-operator');
    if (counted.length && !rfc6962) appleReasons.push('no-rfc6962-log');
  }
  return {
    lifetimeDays, expired: notAfter < now, listSource, standings, unknownLogs,
    policies: { chrome: verdictOf(chromeBase, chromeReasons, ctx), apple: verdictOf(appleBase, appleReasons, ctx) }
  };
}
