/**
 * renewalplan.js — renewal planning: the CA/Browser Forum's schedule of shrinking certificate
 * lifetimes, when a certificate should be renewed and how often from now on, and which names go on
 * which certificate.
 *
 * - {@link LIFETIME_SCHEDULE}: ballot SC-081v3 (adopted 2025-04-11) as the Baseline Requirements
 *   §6.3.2 (maximum validity period) and §4.2.1 (domain validation reuse) hold it: 398 / 398 days
 *   before 2026-03-15, then 200 / 200, 100 / 100 from 2027-03-15 and 47 / 10 from 2029-03-15.
 * - {@link renewalWindow}: the CA's ACME Renewal Information (ARI, RFC 9773) window when it was
 *   read ({@link fetchRenewalInfo}: Let's Encrypt only, the one ARI server checked to answer a
 *   browser page), otherwise from two thirds of the lifetime until expiry.
 * - {@link planRenewals}: the certificate's lifetime and the step it was issued under, its window,
 *   the next renewals (each new certificate as long as this one, cut to the step in force when it
 *   is issued), and how many renewals and domain validations a year each step means until 2030.
 * - {@link coveragePlan}: groupings of a list of names — one SAN list, wildcards (with the names a
 *   wildcard leaves uncovered: the apex and deeper levels) and one certificate per environment —
 *   and {@link opensslConfig} / {@link certreqInf}: the CSR configuration of one certificate, for
 *   `openssl req -config` or Windows `certreq -new`. The key is made by those tools on the user's
 *   machine; nothing here makes or sees a key.
 *
 * DOM-free. Dates are UTC; `now` is injected. The only I/O is {@link fetchRenewalInfo} (two GETs
 * through `fetchImpl`, with a signal and a timeout); only an abort rejects.
 */

import { fetchJson, fetchAndRead, HttpError, ParseError, parseRetryAfter, errorKind } from './util.js';
import { normalizeHostname, registrableDomain, isPublicSuffix } from './domain.js';

/** One day in milliseconds (the Baseline Requirements count a day as 86,400 seconds). */
const DAY = 86400000;

/**
 * The maximum validity period and domain validation reuse period of a publicly trusted TLS
 * certificate by issuance date (Baseline Requirements §6.3.2 and §4.2.1, ballot SC-081v3): a step
 * applies to a certificate issued on or after `from` (00:00 UTC) and before the next step's.
 * @type {ReadonlyArray<{ id: string, from: string|null, maxDays: number, dcvDays: number }>}
 */
export const LIFETIME_SCHEDULE = Object.freeze([
  { id: 'before', from: null, maxDays: 398, dcvDays: 398 },
  { id: '2026', from: '2026-03-15', maxDays: 200, dcvDays: 200 },
  { id: '2027', from: '2027-03-15', maxDays: 100, dcvDays: 100 },
  { id: '2029', from: '2029-03-15', maxDays: 47, dcvDays: 10 }
].map((s) => Object.freeze(s)));

/** The last year {@link planRenewals} counts renewals for. */
export const PLAN_HORIZON_YEAR = 2030;

/** The share of a lifetime after which a certificate without an ARI window is renewed. */
export const RENEW_AT_SHARE = 2 / 3;

/** Where a renewal window comes from: the CA's ARI answer, or two thirds of the lifetime. */
export const WINDOW_SOURCES = Object.freeze(['ari', 'two-thirds']);

/** Where a certificate stands now: not valid yet, before its window, inside it, past it, expired. */
export const PLAN_STATES = Object.freeze(['not-yet-valid', 'before-window', 'in-window', 'past-window', 'expired']);

/**
 * ACME directories with ARI that a page can call (CORS: `Access-Control-Allow-Origin: *` on the
 * directory and on renewal-info, checked 2026-10-08), by lib/renewal.js RENEWAL_CAS id.
 * @type {Readonly<Record<string, string>>}
 */
export const ARI_DIRECTORIES = Object.freeze({ letsencrypt: 'https://acme-v02.api.letsencrypt.org/directory' });

/** Timeout of each ARI request. */
export const ARI_TIMEOUT_MS = 10000;

/**
 * Why an ARI lookup gave no window: no key identifier in the certificate, a CA without ARI here,
 * a directory without `renewalInfo`, a certificate the CA does not know, a malformed window, or
 * the request failed (lib/util.js errorKind codes).
 */
export const ARI_FAILURES = Object.freeze(['no-key-id', 'unsupported', 'no-renewal-info', 'not-found', 'bad-window',
  'rate-limit', 'http', 'timeout', 'network', 'parse', 'unknown']);

/** The most names Let's Encrypt puts on one certificate; a longer list is split. */
export const SAN_LIMIT = 100;

/** The ways {@link coveragePlan} groups names, in the order it proposes them. */
export const GROUPINGS = Object.freeze(['san', 'wildcard', 'environment']);

/** Environments {@link nameEnvironment} tells apart; `prod` also takes every name without a marker. */
export const ENVIRONMENTS = Object.freeze(['prod', 'staging', 'test', 'dev']);

/** Labels (or `-` parts of a label, a trailing number allowed) that mark an environment. */
const ENV_WORDS = Object.freeze({
  dev: ['dev', 'devel', 'develop', 'development', 'sandbox', 'sbx'],
  test: ['test', 'tests', 'testing', 'tst', 'qa'],
  staging: ['staging', 'stage', 'stg', 'preprod', 'uat', 'preview'],
  prod: ['prod', 'production', 'prd', 'live']
});

/** Why a name a wildcard's base holds is not covered by it: the base itself, or two levels or more below it. */
export const UNCOVERED_REASONS = Object.freeze(['apex', 'deeper']);

/**
 * Notes on a grouping: a wildcard needs DNS-01; a list over {@link SAN_LIMIT} was split; one
 * certificate holds several registrable domains; a wildcard in production would cover the other
 * environments' names, so the split lists them.
 */
export const GROUPING_NOTES = Object.freeze(['dns-01', 'split', 'mixed-domains', 'no-prod-wildcard']);

/** Key types of the CSR configurations. */
export const CSR_KEY_TYPES = Object.freeze(['ec-p256', 'ec-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096']);

/** The longest Common Name (X.520 ub-common-name); a longer first name leaves the subject empty. */
const CN_MAX = 64;

/** A name that may go into a configuration file or a file name (normalized: LDH labels, `*.` first). */
const SAFE_NAME = /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

/* ------------------------------------------------------------------------ */
/* Schedule and lifetimes                                                    */
/* ------------------------------------------------------------------------ */

const ms = (d) => (d instanceof Date ? d.getTime() : Number(d));
const stepStart = (s) => (s.from ? Date.parse(`${s.from}T00:00:00Z`) : -Infinity);

/**
 * The step of {@link LIFETIME_SCHEDULE} for a certificate issued at `at`.
 * @param {Date|number} at
 * @returns {{ id: string, from: string|null, maxDays: number, dcvDays: number }}
 */
export function scheduleStep(at) {
  const t = ms(at);
  let step = LIFETIME_SCHEDULE[0];
  for (const s of LIFETIME_SCHEDULE) if (t >= stepStart(s)) step = s;
  return step;
}

/**
 * When a step ends (the next step's start), or null for the last one.
 * @param {{ id: string }} step
 * @returns {Date|null}
 */
export function stepEnd(step) {
  const i = LIFETIME_SCHEDULE.findIndex((s) => s.id === step.id);
  const next = LIFETIME_SCHEDULE[i + 1];
  return next ? new Date(stepStart(next)) : null;
}

/**
 * A certificate's validity period in days as the Baseline Requirements count it: notBefore through
 * notAfter inclusive (one second more than the difference), any part of a day a whole day.
 * @param {Date|number} notBefore
 * @param {Date|number} notAfter
 * @returns {number} 0 for a reversed or unreadable pair
 */
export function validityDays(notBefore, notAfter) {
  const span = ms(notAfter) - ms(notBefore);
  if (!Number.isFinite(span) || span < 0) return 0;
  return Math.ceil((span + 1000) / DAY);
}

/**
 * A certificate's renewal window: the CA's ARI window when it was read, otherwise from two thirds
 * of the lifetime until expiry.
 * @param {{ notBefore: Date, notAfter: Date }} cert
 * @param {{ ari?: { ok: boolean, start?: Date, end?: Date }|null }} [opts]
 * @returns {{ source: 'ari'|'two-thirds', start: Date, end: Date }}
 */
export function renewalWindow(cert, { ari = null } = {}) {
  if (ari && ari.ok && ari.start instanceof Date && ari.end instanceof Date) return { source: 'ari', start: ari.start, end: ari.end };
  const nb = ms(cert.notBefore);
  const na = ms(cert.notAfter);
  return { source: 'two-thirds', start: new Date(nb + Math.round((na - nb) * RENEW_AT_SHARE)), end: new Date(na) };
}

/**
 * Renewals a year and the domain validations they need under one step, for certificates that
 * live `lifetimeDays` (cut to the step's maximum) and are renewed at two thirds of that: a
 * validation is reused for as many renewals as fit in the step's reuse period (at best: a CA may
 * reuse it for less).
 * @param {{ maxDays: number, dcvDays: number }} step
 * @param {number} lifetimeDays
 * @returns {{ lifetimeDays: number, intervalDays: number, perYear: number, validationsPerYear: number, revalidateEach: boolean }}
 */
export function stepRate(step, lifetimeDays) {
  const lifetime = Math.max(1, Math.min(lifetimeDays, step.maxDays));
  const intervalDays = lifetime * RENEW_AT_SHARE;
  const perYear = 365.25 / intervalDays;
  const renewalsPerValidation = Math.floor(step.dcvDays / intervalDays) + 1;
  return { lifetimeDays: lifetime, intervalDays, perYear, validationsPerYear: perYear / renewalsPerValidation, revalidateEach: step.dcvDays < intervalDays };
}

/**
 * The renewal plan of one certificate at `now`.
 *
 * `next` holds the next `count` renewals: the first at the window's start (now when that has
 * passed), each new certificate as long as this one but no longer than the step in force on its
 * issuance day, renewed at two thirds of its lifetime. `years` counts those renewals by calendar
 * year from now to {@link PLAN_HORIZON_YEAR}; `steps` gives the rate of each step in force in
 * that time.
 * @param {{ notBefore: Date, notAfter: Date }} cert
 * @param {{ now?: number|Date, ari?: object|null, count?: number, horizonYear?: number }} [opts]
 * @returns {{ lifetimeDays: number, issuedUnder: object, overMax: boolean, state: string, window: object,
 *   expires: Date, daysLeft: number, next: Array<{ at: Date, lifetimeDays: number, expires: Date, step: string }>,
 *   years: Array<{ year: number, renewals: number }>, steps: Array<object> }|null} null without a readable validity
 */
export function planRenewals(cert, { now = Date.now(), ari = null, count = 6, horizonYear = PLAN_HORIZON_YEAR } = {}) {
  const nb = ms(cert && cert.notBefore);
  const na = ms(cert && cert.notAfter);
  if (!Number.isFinite(nb) || !Number.isFinite(na) || na <= nb) return null;
  const t = ms(now);
  const lifetimeDays = validityDays(nb, na);
  const issuedUnder = scheduleStep(nb);
  const window = renewalWindow(cert, { ari });
  const ws = window.start.getTime();
  const we = window.end.getTime();
  const state = t < nb ? 'not-yet-valid' : t >= na ? 'expired' : t < ws ? 'before-window' : t <= we ? 'in-window' : 'past-window';

  const horizonEnd = Date.UTC(horizonYear + 1, 0, 1);
  const startYear = new Date(t).getUTCFullYear();
  const yearCounts = new Map();
  for (let y = startYear; y <= horizonYear; y += 1) yearCounts.set(y, 0);
  const next = [];
  let at = Math.max(t, ws);
  // Each renewal moves on by at least a day: the loop ends before the horizon in ~1,500 steps at most.
  while (at < horizonEnd || next.length < count) {
    const step = scheduleStep(at);
    const lifetime = Math.min(lifetimeDays, step.maxDays);
    if (next.length < count) next.push({ at: new Date(at), lifetimeDays: lifetime, expires: new Date(at + lifetime * DAY - 1000), step: step.id });
    const year = new Date(at).getUTCFullYear();
    if (yearCounts.has(year)) yearCounts.set(year, yearCounts.get(year) + 1);
    at += Math.max(DAY, Math.round(lifetime * RENEW_AT_SHARE * DAY));
    if (at >= horizonEnd && next.length >= count) break;
  }

  const steps = LIFETIME_SCHEDULE.filter((s) => {
    const end = stepEnd(s);
    return (!end || end.getTime() > t) && stepStart(s) < horizonEnd;
  }).map((s) => ({ step: s.id, from: s.from, maxDays: s.maxDays, dcvDays: s.dcvDays, current: s.id === scheduleStep(t).id, ...stepRate(s, lifetimeDays) }));

  return {
    lifetimeDays,
    issuedUnder,
    overMax: lifetimeDays > issuedUnder.maxDays,
    state,
    window,
    expires: new Date(na),
    daysLeft: Math.max(0, Math.floor((na - t) / DAY)),
    next,
    years: [...yearCounts].map(([year, renewals]) => ({ year, renewals })),
    steps
  };
}

/* ------------------------------------------------------------------------ */
/* ACME Renewal Information (RFC 9773)                                       */
/* ------------------------------------------------------------------------ */

const hexBytes = (hex) => {
  const s = String(hex || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  const even = s.length % 2 ? `0${s}` : s;
  const out = [];
  for (let i = 0; i < even.length; i += 2) out.push(parseInt(even.slice(i, i + 2), 16));
  return out;
};

const base64Url = (bytes) => {
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
    out += ALPHA[(n >> 18) & 63] + ALPHA[(n >> 12) & 63];
    if (i + 1 < bytes.length) out += ALPHA[(n >> 6) & 63];
    if (i + 2 < bytes.length) out += ALPHA[n & 63];
  }
  return out;
};

/**
 * A certificate's ARI CertID (RFC 9773 §4.1): the base64url of its Authority Key Identifier's
 * keyIdentifier, a dot, and the base64url of its serial number's DER content octets (a leading
 * zero byte when the first one has its high bit set).
 * @param {{ authorityKeyId?: string|null, serialHex?: string|null }} cert lib/x509.js leaf (lowercase hex)
 * @returns {string|null} null without a key identifier or a serial number
 */
export function ariCertId(cert) {
  const keyId = hexBytes(cert && cert.authorityKeyId);
  const serial = hexBytes(cert && cert.serialHex);
  if (!keyId.length || !serial.length) return null;
  while (serial.length > 1 && serial[0] === 0 && serial[1] < 0x80) serial.shift();
  if (serial[0] >= 0x80) serial.unshift(0);
  return `${base64Url(keyId)}.${base64Url(serial)}`;
}

/**
 * Whether the page can ask this CA for an ARI window.
 * @param {string|null} caId lib/renewal.js RENEWAL_CAS id
 * @returns {boolean}
 */
export function ariSupported(caId) {
  return Object.prototype.hasOwnProperty.call(ARI_DIRECTORIES, caId || '');
}

const failure = (code, at, extra = {}) => ({ ok: false, code, error: extra.error || code, errorKind: extra.errorKind || code,
  status: extra.status ?? null, retryAfterMs: extra.retryAfterMs ?? null, at: new Date(at), certId: extra.certId ?? null, url: extra.url ?? null });

/**
 * The renewalInfo URL an ACME directory names, when it is https and on one of `hosts`; null when
 * the directory names none (or one elsewhere). A failed directory read rejects. With `cache`
 * (one per run of the headless runner) each directory is read once.
 * @param {string} directoryUrl
 * @param {string[]} hosts
 * @param {object} opts fetchJson options
 * @param {Map<string, Promise<URL|null>>|null} cache
 * @returns {Promise<URL|null>}
 */
function renewalInfoBase(directoryUrl, hosts, opts, cache) {
  const read = async () => {
    const dir = await fetchJson(directoryUrl, opts);
    let base = null;
    try {
      base = dir && typeof dir.renewalInfo === 'string' ? new URL(dir.renewalInfo) : null;
    } catch {
      base = null;
    }
    return base && base.protocol === 'https:' && hosts.includes(base.host) ? base : null;
  };
  if (!cache) return read();
  if (!cache.has(directoryUrl)) {
    const pending = read();
    // a failed read is not kept: an abort, or a directory down for a moment, is asked again
    pending.catch(() => cache.delete(directoryUrl));
    cache.set(directoryUrl, pending);
  }
  return cache.get(directoryUrl);
}

/**
 * Ask the CA for the certificate's renewal window (RFC 9773): its ACME directory for the
 * `renewalInfo` URL (it must stay on the directory's host, or on one of `directory.hosts`), then
 * `<renewalInfo>/<CertID>`. Sends the CertID only: the issuer's key identifier and the serial
 * number. The page asks the CAs of {@link ARI_DIRECTORIES} (`ca`); the headless runner passes the
 * directory of another CA's server-side table (tools/ds/ari.mjs) and a `cache` of the directories
 * read in its run.
 * @param {{ authorityKeyId?: string|null, serialHex?: string|null }} cert
 * @param {{ ca?: string, directory?: { url: string, hosts?: string[] }|null, cache?: Map<string, Promise<URL|null>>|null,
 *   fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number, now?: () => number }} [opts]
 * @returns {Promise<{ ok: true, start: Date, end: Date, explanationUrl: string|null, retryAfterMs: number|null, at: Date, certId: string, url: string }
 *   | { ok: false, code: string, error: string, errorKind: string, status: number|null, retryAfterMs: number|null, at: Date,
 *   certId: string|null, url: string|null }>}
 *   `code` is one of {@link ARI_FAILURES}; only an abort rejects
 */
export async function fetchRenewalInfo(cert, {
  ca = 'letsencrypt', directory = null, cache = null, fetchImpl = globalThis.fetch, signal, timeoutMs = ARI_TIMEOUT_MS, now = Date.now
} = {}) {
  const entry = directory && typeof directory.url === 'string' ? directory : ariSupported(ca) ? { url: ARI_DIRECTORIES[ca] } : null;
  if (!entry) return failure('unsupported', now());
  const certId = ariCertId(cert);
  if (!certId) return failure('no-key-id', now());
  const directoryUrl = entry.url;
  const hosts = Array.isArray(entry.hosts) && entry.hosts.length ? entry.hosts : [new URL(directoryUrl).host];
  const opts = { fetchImpl, signal, timeoutMs };
  let url = null;
  try {
    const base = await renewalInfoBase(directoryUrl, hosts, opts, cache);
    if (!base) return failure('no-renewal-info', now(), { certId });
    url = `${base.href.replace(/\/+$/, '')}/${certId}`;
    const read = await fetchAndRead(url, opts, async (response) => {
      const retryAfterMs = response.headers && typeof response.headers.get === 'function' ? parseRetryAfter(response.headers.get('retry-after'), now()) : null;
      if (!response.ok) {
        let body = '';
        try {
          body = (await response.text()).slice(0, 500);
        } catch {
          body = '';
        }
        throw new HttpError(response.status, url, body, { statusText: response.statusText || '', retryAfterMs });
      }
      const text = await response.text();
      try {
        return { body: JSON.parse(text), retryAfterMs };
      } catch (err) {
        throw new ParseError(`Invalid JSON response: ${err.message}`, { cause: err, body: text });
      }
    });
    const w = read.body && read.body.suggestedWindow;
    const start = w && typeof w.start === 'string' ? new Date(w.start) : null;
    const end = w && typeof w.end === 'string' ? new Date(w.end) : null;
    // RFC 9773 §4.2: the end must come after the start; a window that is not one is no answer.
    if (!start || !end || Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) {
      return failure('bad-window', now(), { certId, url, status: 200, retryAfterMs: read.retryAfterMs });
    }
    const explanation = read.body && typeof read.body.explanationURL === 'string' && /^https:\/\/[^\s]+$/.test(read.body.explanationURL)
      ? read.body.explanationURL : null;
    return { ok: true, start, end, explanationUrl: explanation, retryAfterMs: read.retryAfterMs, at: new Date(now()), certId, url };
  } catch (err) {
    const kind = errorKind(err);
    if (kind === 'abort') throw err;
    const status = err && Number.isInteger(err.status) ? err.status : null;
    const code = status === 404 ? 'not-found' : ARI_FAILURES.includes(kind) ? kind : 'unknown';
    return failure(code, now(), {
      error: err && err.message ? err.message : String(err), errorKind: kind, status, retryAfterMs: err && err.retryAfterMs != null ? err.retryAfterMs : null, certId, url
    });
  }
}

/* ------------------------------------------------------------------------ */
/* Coverage planner                                                         */
/* ------------------------------------------------------------------------ */

/**
 * The environment a name's labels mark (below its registrable domain: `dev.example.com`,
 * `api-staging.example.com`, `qa2.shop.example.com`), `prod` without a marker.
 * @param {string} name a normalized host name, `*.` allowed
 * @returns {'prod'|'staging'|'test'|'dev'}
 */
export function nameEnvironment(name) {
  const host = String(name || '').replace(/^\*\./, '');
  const domain = registrableDomain(host);
  const above = domain && host.length > domain.length ? host.slice(0, -domain.length - 1).split('.') : [];
  const parts = above.flatMap((label) => label.split('-')).map((p) => p.replace(/\d+$/, ''));
  for (const env of ['dev', 'test', 'staging', 'prod']) if (parts.some((p) => ENV_WORDS[env].includes(p))) return env;
  return 'prod';
}

/** The parent of a host name (the name without its first label), or null when that is a public suffix. */
function parentOf(name) {
  const i = name.indexOf('.');
  if (i < 0) return null;
  const parent = name.slice(i + 1);
  return parent.includes('.') && !isPublicSuffix(parent, { includePrivate: false }) ? parent : null;
}

/**
 * The names a planner works on: each normalized (IDN to ASCII, `*.` kept), deduplicated, with its
 * registrable domain and environment; what is not a host name a CA can certify is `invalid`.
 * @param {Array<string|{ name: string }>|string} input
 * @returns {{ names: Array<{ name: string, base: string, wildcard: boolean, domain: string|null, env: string }>, invalid: string[] }}
 */
export function planNames(input) {
  const tokens = (Array.isArray(input) ? input.map((x) => (x && typeof x === 'object' ? x.name : x))
    : String(input ?? '').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n').split(/[\s,;]+/))
    .map((s) => String(s ?? '').trim()).filter(Boolean);
  const names = [];
  const invalid = [];
  const seen = new Set();
  for (const token of tokens) {
    const host = normalizeHostname(token, { allowWildcard: true });
    const wildcard = !!host && host.startsWith('*.');
    const base = host ? host.replace(/^\*\./, '') : null;
    if (!host || !SAFE_NAME.test(host) || /^\d+(?:\.\d+){3}$/.test(base) || isPublicSuffix(base, { includePrivate: false })) {
      if (!invalid.includes(token)) invalid.push(token);
      continue;
    }
    if (seen.has(host)) continue;
    seen.add(host);
    names.push({ name: host, base, wildcard, domain: registrableDomain(base), env: nameEnvironment(host) });
  }
  return { names, invalid };
}

/**
 * Whether a wildcard `*.<base>` covers `name`: exactly one label below its base (RFC 6125 §6.4.3),
 * so never the base itself (the apex) nor a name two levels or more below it.
 * @param {string} wildcard
 * @param {string} name
 * @returns {boolean}
 */
export function wildcardCovers(wildcard, name) {
  const w = String(wildcard || '');
  const n = String(name || '');
  if (!w.startsWith('*.') || n.startsWith('*.') || n.indexOf('.') < 1) return false;
  return n.slice(n.indexOf('.') + 1) === w.slice(2);
}

/**
 * One certificate of a grouping from its entries (wildcards and names, in order): the names it
 * covers, its Common Name (the first entry that fits 64 characters, a host name before a
 * wildcard) and its registrable domains.
 */
function makeCert(entries, covers, extra = {}) {
  const cn = entries.find((e) => !e.startsWith('*.') && e.length <= CN_MAX) || entries.find((e) => e.length <= CN_MAX) || null;
  const domains = [...new Set(entries.map((e) => registrableDomain(e.replace(/^\*\./, ''))).filter(Boolean))];
  return { names: entries, covers, commonName: cn, domains, wildcards: entries.filter((e) => e.startsWith('*.')), ...extra };
}

/** Entries over the SAN limit in chunks of at most `limit`. */
function chunk(entries, limit) {
  const out = [];
  for (let i = 0; i < entries.length; i += limit) out.push(entries.slice(i, i + limit));
  return out.length ? out : [[]];
}

/**
 * Wildcards for a set of names: those already in it, plus `*.<parent>` for every parent with at
 * least `minChildren` names exactly one label below it (`accept` filters the new ones). Returns
 * the certificate entries (wildcards and the names no wildcard covers, in first-seen order), the
 * names each covers and the names under a wildcard's base it does not cover.
 */
function wildcardEntries(names, { minChildren, accept = () => true }) {
  const plain = names.filter((n) => !n.wildcard).map((n) => n.name);
  const counts = new Map();
  for (const n of plain) {
    const p = parentOf(n);
    if (p) counts.set(p, (counts.get(p) || 0) + 1);
  }
  const wildcards = new Set(names.filter((n) => n.wildcard).map((n) => n.name));
  for (const [parent, c] of counts) if (c >= minChildren && accept(parent)) wildcards.add(`*.${parent}`);
  const entries = [];
  const covered = new Map();
  for (const n of names) {
    const by = n.wildcard ? null : [...wildcards].find((w) => wildcardCovers(w, n.name));
    const entry = by || n.name;
    if (by) covered.set(n.name, by);
    if (!entries.includes(entry)) entries.push(entry);
  }
  const uncovered = [];
  for (const w of wildcards) {
    const base = w.slice(2);
    for (const n of plain) {
      if (covered.has(n)) continue;
      if (n === base) uncovered.push({ name: n, wildcard: w, reason: 'apex' });
      else if (n.endsWith(`.${base}`)) uncovered.push({ name: n, wildcard: w, reason: 'deeper' });
    }
  }
  return { entries, covered, wildcards: [...wildcards], uncovered };
}

/**
 * Groupings of a list of names into certificates, for the planner to compare and pick from:
 *
 * - `san`: every name on one SAN list (split every {@link SAN_LIMIT} names);
 * - `wildcard`: per registrable domain, `*.<parent>` wherever `minWildcard` names or more sit
 *   exactly one label below a parent, plus the names no wildcard covers — `uncovered` lists, for
 *   each wildcard, the names under its base it leaves out (the apex, deeper levels), which stay on
 *   the certificate as names of their own; offered when it forms or keeps a wildcard;
 * - `environment`: one certificate per environment ({@link nameEnvironment}), a wildcard only
 *   under a parent that itself marks a non-production environment; offered with two environments
 *   or more.
 *
 * Each grouping has `certs` (`names`: the entries, `covers`: the names they serve), `entries`
 * (SAN entries over all its certificates, one domain validation each per renewal), `uncovered`
 * and `notes` ({@link GROUPING_NOTES}).
 * @param {Array<string|{ name: string }>|string} input
 * @param {{ sanLimit?: number, minWildcard?: number }} [opts]
 * @returns {{ names: object[], invalid: string[], groupings: Array<{ id: string, certs: object[], entries: number,
 *   uncovered: Array<{ name: string, wildcard: string, reason: string }>, notes: string[] }> }}
 */
export function coveragePlan(input, { sanLimit = SAN_LIMIT, minWildcard = 2 } = {}) {
  const { names, invalid } = planNames(input);
  const groupings = [];
  if (!names.length) return { names, invalid, groupings };
  const limit = Math.max(1, Math.floor(sanLimit));
  const notesFor = (certs, extra = []) => {
    const notes = [];
    if (certs.some((c) => c.wildcards.length)) notes.push('dns-01');
    if (certs.some((c) => c.part)) notes.push('split');
    if (certs.some((c) => c.domains.length > 1)) notes.push('mixed-domains');
    return [...notes, ...extra];
  };
  const finish = (id, certs, uncovered = [], extra = []) => {
    groupings.push({ id, certs, entries: certs.reduce((n, c) => n + c.names.length, 0), uncovered, notes: notesFor(certs, extra) });
  };
  /** Certificates from entries (chunked) with the names each chunk serves. */
  const certsFrom = (entries, coverOf, extra = {}) => {
    const parts = chunk(entries, limit);
    return parts.map((part, i) => makeCert(part, names.filter((n) => part.includes(coverOf(n))).map((n) => n.name),
      { ...extra, part: parts.length > 1 ? i + 1 : null, parts: parts.length }));
  };

  // One SAN list.
  finish('san', certsFrom(names.map((n) => n.name), (n) => n.name));

  // Wildcards, per registrable domain.
  const byDomain = new Map();
  for (const n of names) {
    const key = n.domain || n.base;
    if (!byDomain.has(key)) byDomain.set(key, []);
    byDomain.get(key).push(n);
  }
  const wCerts = [];
  const wUncovered = [];
  let formed = false;
  for (const [domain, list] of byDomain) {
    const w = wildcardEntries(list, { minChildren: minWildcard });
    if (w.wildcards.length) formed = true;
    wCerts.push(...certsFrom(w.entries, (n) => w.covered.get(n.name) || n.name, { domain }));
    wUncovered.push(...w.uncovered);
  }
  if (formed) finish('wildcard', wCerts, wUncovered);

  // One certificate per environment.
  const envs = ENVIRONMENTS.filter((env) => names.some((n) => n.env === env));
  if (envs.length >= 2) {
    const eCerts = [];
    const eUncovered = [];
    let refused = false;
    for (const env of envs) {
      const list = names.filter((n) => n.env === env);
      const w = wildcardEntries(list, {
        minChildren: minWildcard,
        accept: (parent) => {
          const ok = env !== 'prod' && nameEnvironment(parent) === env;
          if (!ok && env === 'prod') refused = true;
          return ok;
        }
      });
      eCerts.push(...certsFrom(w.entries, (n) => w.covered.get(n.name) || n.name, { env }));
      eUncovered.push(...w.uncovered);
    }
    finish('environment', eCerts, eUncovered, refused ? ['no-prod-wildcard'] : []);
  }
  return { names, invalid, groupings };
}

/* ------------------------------------------------------------------------ */
/* CSR configuration                                                        */
/* ------------------------------------------------------------------------ */

/**
 * A file name stem for a certificate's request files: its Common Name (or first entry), `*.`
 * written `wildcard.`.
 * @param {{ names: string[], commonName?: string|null }} cert
 * @returns {string}
 */
export function csrBaseName(cert) {
  const first = (cert && (cert.commonName || (cert.names && cert.names[0]))) || 'request';
  const stem = String(first).replace(/^\*\./, 'wildcard.');
  return /^[a-z0-9.-]+$/.test(stem) ? stem : 'request';
}

/** A certificate's entries that may go into a configuration (normalized host names only). */
function safeEntries(cert) {
  return (cert && Array.isArray(cert.names) ? cert.names : []).filter((n) => typeof n === 'string' && SAFE_NAME.test(n));
}

/** The `openssl req -newkey` arguments of a key type. */
const OPENSSL_NEWKEY = Object.freeze({
  'ec-p256': 'ec -pkeyopt ec_paramgen_curve:P-256',
  'ec-p384': 'ec -pkeyopt ec_paramgen_curve:P-384',
  'rsa-2048': 'rsa:2048',
  'rsa-3072': 'rsa:3072',
  'rsa-4096': 'rsa:4096'
});

/**
 * The OpenSSL configuration of one certificate's request (`[ req ]` without prompts, the Common
 * Name, every entry as a `subjectAltName` DNS name) and the command that makes the key and the CSR
 * with it on the user's machine. Without a Common Name that fits 64 characters the subject is left
 * empty (`-subj /`): CAs read the names from the SAN extension.
 * @param {{ names: string[], commonName?: string|null }} cert
 * @param {{ keyType?: string, app?: string }} [opts]
 * @returns {{ file: string, config: string, command: string, names: string[] }}
 */
export function opensslConfig(cert, { keyType = 'ec-p256', app = 'DomainScope' } = {}) {
  const names = safeEntries(cert);
  const type = OPENSSL_NEWKEY[keyType] ? keyType : 'ec-p256';
  const base = csrBaseName(cert);
  const cn = cert && typeof cert.commonName === 'string' && names.includes(cert.commonName) && cert.commonName.length <= CN_MAX ? cert.commonName : null;
  const file = `${base}.cnf`;
  const command = `openssl req -new -newkey ${OPENSSL_NEWKEY[type]} -nodes -keyout ${base}.key -out ${base}.csr -config ${file}${cn ? '' : ' -subj /'}`;
  const lines = [
    `# OpenSSL request configuration for ${names.length === 1 ? names[0] : `${names.length} names`} (${app}).`,
    '# The private key is made on your machine by this command, never by the page:',
    `#   ${command}`,
    '',
    '[ req ]',
    'prompt             = no',
    'default_md         = sha256',
    'distinguished_name = dn',
    'req_extensions     = req_ext',
    '',
    '[ dn ]',
    ...(cn ? [`CN = ${cn}`] : ['# No Common Name: none of the names fits its 64 characters; the CA reads the SAN list.']),
    '',
    '[ req_ext ]',
    'subjectAltName = @alt_names',
    '',
    '[ alt_names ]',
    ...names.map((n, i) => `DNS.${i + 1} = ${n}`)
  ];
  return { file, config: `${lines.join('\n')}\n`, command, names };
}

/** certreq's [NewRequest] key lines of a key type. */
const CERTREQ_KEY = Object.freeze({
  'ec-p256': ['KeyAlgorithm = ECDSA_P256', 'KeyLength = 256', 'ProviderName = "Microsoft Software Key Storage Provider"', 'KeyUsage = 0x80'],
  'ec-p384': ['KeyAlgorithm = ECDSA_P384', 'KeyLength = 384', 'ProviderName = "Microsoft Software Key Storage Provider"', 'KeyUsage = 0x80'],
  'rsa-2048': ['KeyAlgorithm = RSA', 'KeyLength = 2048', 'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"', 'ProviderType = 12', 'KeySpec = 1', 'KeyUsage = 0xa0'],
  'rsa-3072': ['KeyAlgorithm = RSA', 'KeyLength = 3072', 'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"', 'ProviderType = 12', 'KeySpec = 1', 'KeyUsage = 0xa0'],
  'rsa-4096': ['KeyAlgorithm = RSA', 'KeyLength = 4096', 'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"', 'ProviderType = 12', 'KeySpec = 1', 'KeyUsage = 0xa0']
});

/**
 * The Windows `certreq -new` INF of one certificate's request: the subject, the key (made by
 * Windows in the machine's key store, exportable), server authentication and the SAN extension
 * (`2.5.29.17 = "{text}"` with one `_continue_ = "dns=…&"` line per entry).
 * @param {{ names: string[], commonName?: string|null }} cert
 * @param {{ keyType?: string, app?: string }} [opts]
 * @returns {{ file: string, inf: string, command: string, names: string[] }}
 */
export function certreqInf(cert, { keyType = 'rsa-2048', app = 'DomainScope' } = {}) {
  const names = safeEntries(cert);
  const type = CERTREQ_KEY[keyType] ? keyType : 'rsa-2048';
  const base = csrBaseName(cert);
  const cn = cert && typeof cert.commonName === 'string' && names.includes(cert.commonName) && cert.commonName.length <= CN_MAX ? cert.commonName : null;
  const file = `${base}.inf`;
  const command = `certreq -new ${file} ${base}.csr`;
  const lines = [
    `; certreq request for ${names.length === 1 ? names[0] : `${names.length} names`} (${app}).`,
    '; Windows makes the private key in the machine key store when you run:',
    `;   ${command}`,
    '',
    '[Version]',
    'Signature = "$Windows NT$"',
    '',
    '[NewRequest]',
    `Subject = "${cn ? `CN=${cn}` : ''}"`,
    ...CERTREQ_KEY[type],
    'HashAlgorithm = sha256',
    'Exportable = TRUE',
    'MachineKeySet = TRUE',
    'SMIME = FALSE',
    'UseExistingKeySet = FALSE',
    'RequestType = PKCS10',
    '',
    '[EnhancedKeyUsageExtension]',
    'OID = 1.3.6.1.5.5.7.3.1',
    '',
    '[Extensions]',
    '2.5.29.17 = "{text}"',
    ...names.map((n) => `_continue_ = "dns=${n}&"`)
  ];
  return { file, inf: `${lines.join('\r\n')}\r\n`, command, names };
}
