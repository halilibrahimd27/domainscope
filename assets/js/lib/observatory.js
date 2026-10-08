/**
 * observatory.js — Mozilla's HTTP Observatory (MDN) for Domain Health's Web category (SPEC
 * §5.78): ONE `POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=<host>` per click,
 * which scans the site's HTTP response headers from Mozilla's servers and answers its grade
 * (A+ … F), score and how many of its tests passed and failed. The API sends
 * `Access-Control-Allow-Origin: *` (verified 2026-10-08). The scan answer has counts only: the
 * list of failing tests is on the MDN report page ({@link observatoryReportUrl}), a link.
 *
 * Only a public host name is ever sent ({@link observatoryEligible}): an internal name (`.local`,
 * `.internal`, `.home.arpa` …), a single label, an IP address or a host whose addresses are all
 * private (RFC 1918, loopback, link-local, CGNAT, ULA: lib/ip.js isPrivateIP) never leaves the page.
 *
 * Only an abort rejects; every other failure is a result `{ ok: false, error, errorKind,
 * httpStatus, retryAfterMs, at }` (lib/sourcestatus.js turns it into a status). DOM-free.
 */

import { errorKind, fetchAndRead, throwIfAborted } from './util.js';
import { normalizeHostname, registrableDomain } from './domain.js';
import { isPrivateIP, normalizeIP } from './ip.js';

/** The scan endpoint (POST, `?host=`). */
export const OBSERVATORY_SCAN_URL = 'https://observatory-api.mdn.mozilla.net/api/v2/scan';

/** MDN's report page of a host: the tests one by one (a link; never fetched). */
export const OBSERVATORY_REPORT_URL = 'https://developer.mozilla.org/en-US/observatory/analyze';

/** One scan takes a few seconds; Mozilla answers a recent scan of the same host from its cache. */
export const OBSERVATORY_TIMEOUT_MS = 45000;

/** Grades the Observatory gives, best first. */
export const OBSERVATORY_GRADES = Object.freeze(['A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D+', 'D', 'D-', 'F']);

/** Why a host is not sent ({@link observatoryEligible}). */
export const OBSERVATORY_SKIP_REASONS = Object.freeze(['invalid', 'internal-name', 'no-address', 'private-address']);

/** Suffixes of names that exist only inside a network (RFC 6761, 6762, 8375 and common practice). */
export const INTERNAL_NAME_SUFFIXES = Object.freeze([
  'local', 'localhost', 'internal', 'intranet', 'lan', 'corp', 'home', 'home.arpa', 'private', 'test', 'invalid', 'onion', 'alt'
]);

/**
 * The scan request URL of a host.
 * @param {string} host
 * @returns {string}
 */
export function observatoryScanUrl(host) {
  return `${OBSERVATORY_SCAN_URL}?host=${encodeURIComponent(host)}`;
}

/**
 * MDN's report page of a host (built here, never taken from the answer).
 * @param {string} host
 * @returns {string}
 */
export function observatoryReportUrl(host) {
  return `${OBSERVATORY_REPORT_URL}?host=${encodeURIComponent(host)}`;
}

/**
 * Whether a host may go to the Observatory: a public name (a registrable domain, no internal
 * suffix) with at least one address among `addresses` that is not private.
 * @param {string} host
 * @param {{ addresses?: string[] }} [opts] the host's A / AAAA addresses
 * @returns {{ ok: true, host: string }|{ ok: false, reason: string }}
 */
export function observatoryEligible(host, { addresses = [] } = {}) {
  const name = normalizeHostname(typeof host === 'string' ? host : '');
  if (!name || normalizeIP(name)) return { ok: false, reason: 'invalid' };
  if (!name.includes('.') || INTERNAL_NAME_SUFFIXES.some((s) => name === s || name.endsWith(`.${s}`)) || !registrableDomain(name)) {
    return { ok: false, reason: 'internal-name' };
  }
  const ips = (Array.isArray(addresses) ? addresses : []).filter((ip) => typeof ip === 'string' && normalizeIP(ip));
  if (!ips.length) return { ok: false, reason: 'no-address' };
  if (ips.every((ip) => isPrivateIP(ip))) return { ok: false, reason: 'private-address' };
  return { ok: true, host: name };
}

/**
 * @typedef {object} ObservatoryResult
 * @property {true} ok
 * @property {string} host
 * @property {string} grade 'A+' … 'F'
 * @property {number|null} score the Observatory's own 0…100+ score
 * @property {number|null} testsFailed
 * @property {number|null} testsPassed
 * @property {number|null} testsQuantity
 * @property {number|null} statusCode the HTTP status the site answered the scanner
 * @property {string|null} scannedAt ISO time of the scan (a cached scan is older than the click)
 * @property {number|null} algorithmVersion
 * @property {string} reportUrl {@link observatoryReportUrl}
 * @property {Date} at when the answer arrived
 */

const num = (v) => (Number.isFinite(Number(v)) && v !== null && v !== '' ? Number(v) : null);

/**
 * Read a scan answer (the JSON body) into a result, or a failure when it holds no grade.
 * @param {string} host
 * @param {object|null} body
 * @param {Date} at
 * @returns {ObservatoryResult|{ ok: false, host: string, error: string, errorKind: string, httpStatus: null, retryAfterMs: null, at: Date }}
 */
export function readObservatoryScan(host, body, at = new Date()) {
  const b = body && typeof body === 'object' ? body : {};
  const grade = typeof b.grade === 'string' ? b.grade.trim().toUpperCase() : '';
  if (b.error || !OBSERVATORY_GRADES.includes(grade)) {
    const error = typeof b.error === 'string' && b.error ? b.error.slice(0, 120) : (typeof b.message === 'string' && b.message ? b.message.slice(0, 120) : 'no grade in the answer');
    return { ok: false, host, error, errorKind: b.error ? 'unavailable' : 'parse', httpStatus: null, retryAfterMs: null, at };
  }
  return {
    ok: true,
    host,
    grade,
    score: num(b.score),
    testsFailed: num(b.tests_failed),
    testsPassed: num(b.tests_passed),
    testsQuantity: num(b.tests_quantity),
    statusCode: num(b.status_code),
    scannedAt: typeof b.scanned_at === 'string' ? b.scanned_at : null,
    algorithmVersion: num(b.algorithm_version),
    reportUrl: observatoryReportUrl(host),
    at
  };
}

/**
 * Scan a host's HTTP security headers: ONE POST to the Observatory. The caller checks
 * {@link observatoryEligible} first; a host that fails it is not sent here either.
 * @param {string} host
 * @param {{ addresses?: string[], fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number, now?: () => number }} [opts]
 * @returns {Promise<ObservatoryResult|{ ok: false, host: string, error: string, errorKind: string, httpStatus: number|null,
 *   retryAfterMs: number|null, at: Date, skipped?: string }>}
 */
export async function observatoryScan(host, { addresses = [], fetchImpl = globalThis.fetch, signal, timeoutMs = OBSERVATORY_TIMEOUT_MS, now = Date.now } = {}) {
  throwIfAborted(signal);
  const ok = observatoryEligible(host, { addresses });
  const at = () => new Date(now());
  if (!ok.ok) return { ok: false, host: String(host || ''), error: ok.reason, errorKind: 'skipped', skipped: ok.reason, httpStatus: null, retryAfterMs: null, at: at() };
  try {
    const res = await fetchAndRead(observatoryScanUrl(ok.host), { method: 'POST', fetchImpl, signal, timeoutMs }, async (response) => {
      let body = null;
      try { body = JSON.parse(await response.text()); } catch { body = null; }
      const retry = Number(response.headers.get('retry-after'));
      return { status: response.status, body, retryAfterMs: Number.isFinite(retry) && retry >= 0 ? retry * 1000 : null };
    });
    if (res.status === 429) {
      return { ok: false, host: ok.host, error: 'HTTP 429', errorKind: 'rate-limit', httpStatus: 429, retryAfterMs: res.retryAfterMs, at: at() };
    }
    if (res.status < 200 || res.status >= 300) {
      // The API names what it refused (e.g. a host it cannot resolve) in `error` / `message`.
      const why = res.body && typeof res.body === 'object' ? res.body.error || res.body.message : null;
      return {
        ok: false, host: ok.host, error: typeof why === 'string' && why ? `HTTP ${res.status}: ${why.slice(0, 120)}` : `HTTP ${res.status}`,
        errorKind: 'http', httpStatus: res.status, retryAfterMs: res.retryAfterMs, at: at()
      };
    }
    return readObservatoryScan(ok.host, res.body, at());
  } catch (err) {
    if (errorKind(err) === 'abort') throw err;
    return { ok: false, host: ok.host, error: (err && err.message) || String(err), errorKind: errorKind(err), httpStatus: null, retryAfterMs: null, at: at() };
  }
}
