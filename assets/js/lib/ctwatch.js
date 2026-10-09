/**
 * ctwatch.js — the CT watchlist of a domain portfolio (Domain portfolio › Certificates (CT)): for
 * each domain and its subdomains, the certificates logged in Certificate Transparency and what
 * needs a look — the newest valid certificate of each name set, the expiry radar (30 / 14 / 7 days,
 * configurable), the certificates logged since the last check (a baseline kept per workspace),
 * issuers that are not one of the workspace's expected CAs (lib/expectedca.js), wildcard
 * issuance and issuances logged only as a precertificate.
 *
 * Sources (both verified live on 2026-10-08; see SPEC §3):
 *   - Cert Spotter `GET /v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names
 *     &expand=issuer&expand=cert_der&expand=revocation&expand=problem_reporting` (ACAO `*`; the
 *     last two re-checked on 2026-10-08: when and why a certificate was revoked, and the CA's
 *     problem-reporting contact, lib/revocation.js): the unexpired issuances of the domain and every
 *     name under it, ascending id, `after=<last id>` pages on, an empty page ends the list (a
 *     short page does not: `Link: rel="next"` came with 34 rows). A subdomain search counts
 *     against Cert Spotter's hourly allowance of 10 requests per IP (`X-Ratelimit-Limit: 10`), so a
 *     domain costs two requests at least (its page, then the empty one) and the rate-limit
 *     headers are not CORS-exposed. This module paces its requests (one at a time, a gap between
 *     two), counts what this page sent in the last hour ({@link createSpotterBudget}, shown as the
 *     quota) and sends a domain to crt.sh once fewer than two requests are left or Cert Spotter
 *     answered 429. `cert_der` (the final certificate, or the precertificate while only that one
 *     is logged) is parsed with lib/x509.js: the serial number and the CT poison extension.
 *   - crt.sh `%.<d>` search through lib/sources.js (its retries, backoff and identity-search
 *     fallback), `deduplicate=Y`: the precertificate and the final certificate are one row, and
 *     nothing in its JSON tells them apart, so "precertificate only" is unknown (null) there.
 *
 * A certificate's id is the same whichever source listed it: 16 hex digits of FNV-1a (64 bits)
 * over the issuing intermediate's CN and the serial number (a CA's serials are unique, and a
 * precertificate has its certificate's serial). The baseline remembers, per domain, the ids seen
 * and when the check ran (lib/workspace.js `ctSeen`: the JSON text {@link seenText} writes, read
 * and checked by {@link readSeen}).
 *
 * Known certificates (lib/waivers.js, kind 'cert'): a certificate whose public key's SHA-256 (or
 * its own SHA-256) an active waiver of its domain names is never flagged new or from an unexpected
 * CA — its expiry and revocation are still watched; a waiver that is over leaves its certificate
 * flagged as before ({@link analyzeCt} `known`).
 *
 * CT lists publicly trusted certificates only: a private CA's, a self-signed one, or one a CA never
 * logged is not there. DOM-free; every request takes the caller's `signal` and a timeout, only an
 * abort rejects, every other failure is reported in the result.
 */

import { fetchJson, errorKind, sleep, throwIfAborted, createLimiter, ParseError } from './util.js';
import { normalizeHostname, isSubdomainOf, sortHostnames } from './domain.js';
import { fetchSource } from './sources.js';
import { parseCertificate } from './x509.js';
import { sha256 } from './sha.js';
import { certStanding, emptySeen } from './ctseen.js';

// The baseline (the workspace part `ctSeen`) lives in lib/ctseen.js, which Home reads without this module.
export { CT_SEEN_VERSION, CT_SEEN_MAX_CHARS, CT_SEEN_MAX_DUE, emptySeen, readSeen, updateSeen, seenText, certStanding, currentDue } from './ctseen.js';
import { CERTSPOTTER_ISSUANCES, CRTSH_BASE, CT_TIMEOUT_MS } from './ctcert.js';
import { caaIssuerInfo } from './health.js';
import { expectedCaStatus } from './expectedca.js';
import { spotterRevocation, problemReportingText } from './revocation.js';
import { matchWaiver } from './waivers.js';

/** Cert Spotter's hourly allowance for a subdomain search, per IP (`X-Ratelimit-Limit: 10`). */
export const CT_WATCH_SPOTTER_LIMIT = 10;
/** The window of that allowance. */
export const CT_WATCH_WINDOW_MS = 3600000;
/** A domain is read from Cert Spotter only while this many requests are left (its page, then the empty one). */
export const CT_WATCH_SPOTTER_MIN = 2;
/** Gap between two Cert Spotter requests of this module. */
export const CT_WATCH_SPACING_MS = 1500;
/** At most this many Cert Spotter pages per domain (500 issuances). */
export const CT_WATCH_MAX_PAGES = 5;
/** At most this many domains per check (crt.sh is slow, Cert Spotter's quota small). */
export const CT_WATCH_MAX_DOMAINS = 50;
/** Domains read at the same time (Cert Spotter's requests stay one at a time). */
export const CT_WATCH_CONCURRENCY = 2;
/** Per-request timeout for crt.sh (lib/sources.js retries a few times within its own budget). */
export const CT_WATCH_CRTSH_TIMEOUT_MS = 60000;
/** The expiry radar's default thresholds, in days left. */
export const CT_WATCH_DEFAULT_DAYS = Object.freeze([30, 14, 7]);
/** A threshold is 1 … this many days (the longest validity a public certificate may have). */
export const CT_WATCH_MAX_DAYS = 398;
/** At most this many thresholds. */
export const CT_WATCH_MAX_THRESHOLDS = 5;
/** What a certificate row can be flagged with, in the order a row shows them ('known': a known certificate, lib/waivers.js). */
export const CT_WATCH_FLAGS = Object.freeze(['new', 'unexpected', 'precert', 'wildcard', 'revoked', 'superseded', 'known']);
/** The table's filters, in the select's order. */
export const CT_WATCH_FILTERS = Object.freeze(['current', 'all', 'new', 'expiring', 'unexpected', 'wildcard', 'precert']);
/** How a domain's read ended. */
export const CT_WATCH_STATES = Object.freeze(['ok', 'partial', 'failed']);
/**
 * Notes on a domain's read: Cert Spotter's quota was used up (crt.sh answered), Cert Spotter
 * failed (crt.sh answered), crt.sh answered only part of its search, more issuances than the page
 * cap (the newest unread), the first check of the domain (nothing to compare).
 */
export const CT_WATCH_NOTES = Object.freeze(['spotter-quota', 'spotter-failed', 'crtsh-partial', 'truncated', 'first']);

/**
 * @typedef {object} WatchCert one certificate of a domain, as either source lists it
 * @property {string} id 16 hex digits (intermediate CN + serial, see the module header)
 * @property {string} domain the portfolio domain it was read for
 * @property {string[]} names its DNS names at or under the domain, sorted (wildcards kept as `*.x`)
 * @property {string} issuer issuer DN
 * @property {string} ca the CA it is listed under (the known CA, else the DN's O, else its CN)
 * @property {string|null} intermediate the issuer's CN
 * @property {Date} notBefore
 * @property {Date} notAfter
 * @property {string|null} serialHex lowercase hex, no leading 00
 * @property {string|null} sha256 certificate SHA-256 (Cert Spotter)
 * @property {string|null} spkiSha256 its public key's (SubjectPublicKeyInfo) SHA-256: Cert Spotter's
 *   `pubkey_sha256`, else from its DER; null from crt.sh
 * @property {boolean|null} precert logged only as a precertificate; null: not known (crt.sh)
 * @property {boolean|null} revoked Cert Spotter's flag; null: not known (crt.sh)
 * @property {{ time: Date|null, reasonCode: number|null, reason: string|null, checkedAt: Date|null }|null} revocation
 *   when and why it was revoked and when Cert Spotter last read the CA's CRL (lib/revocation.js
 *   spotterRevocation); null: not known (crt.sh)
 * @property {string|null} problemReporting the CA's problem-reporting contact, as text (Cert Spotter)
 * @property {boolean} wildcard a name is a wildcard
 * @property {'certspotter'|'crtsh'} source
 * @property {string|null} url the certificate on crt.sh
 */

/**
 * @typedef {object} DomainRead
 * @property {string} domain
 * @property {Date} at when the read began
 * @property {'ok'|'partial'|'failed'} state
 * @property {'certspotter'|'crtsh'|null} source the source the list comes from (crt.sh when both answered)
 * @property {WatchCert[]} certs
 * @property {object[]} failures lib/sourcestatus.js SourceFailure of each source that failed
 * @property {string[]} notes codes of {@link CT_WATCH_NOTES} ('first' is added by {@link analyzeCt})
 * @property {{ certspotter: number, crtsh: number }} requests HTTP requests sent
 */

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */
/* ------------------------------------------------------------------------ */

const DAY_MS = 86400000;
const encoder = new TextEncoder();
const SHA256_RE = /^[0-9a-f]{64}$/i;
const hexOf = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * FNV-1a, 64 bits, of a text's UTF-8 bytes: 16 hex digits.
 * @param {string} text
 * @returns {string}
 */
export function fnv64(text) {
  let h = 0xcbf29ce484222325n;
  for (const b of encoder.encode(String(text))) {
    h ^= BigInt(b);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

/**
 * One attribute of a DN string (`C=US, O=Let's Encrypt, CN=R11` → CN `R11`), as lib/passport.js
 * dnPart reads it; null when it is not there.
 * @param {string} dn
 * @param {string} key
 * @returns {string|null}
 */
export function dnValue(dn, key) {
  const m = new RegExp(`(?:^|[,/]\\s*)${key}=("(?:[^"\\\\]|\\\\.)*"|[^,/]+)`, 'i').exec(String(dn ?? ''));
  return m ? m[1].replace(/^"|"$/g, '').trim() : null;
}

/**
 * The CA a certificate is listed under: the known CA (lib/health.js CAA_ISSUERS), else the DN's
 * O, else its CN — from the DN alone, as lib/passport.js issuerName and tools/ds `ct` name it, so
 * a certificate reads the same whichever source listed it.
 * @param {string} dn
 * @returns {string}
 */
export function caName(dn) {
  const known = caaIssuerInfo(dn);
  if (known.length) return known[0].name;
  return dnValue(dn, 'O') || dnValue(dn, 'CN') || String(dn || '').trim() || '?';
}

/** Lowercase hex without separators and leading 00 bytes, or null. */
function serialOf(value) {
  let hex = String(value ?? '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (!hex) return null;
  if (hex.length % 2) hex = `0${hex}`;
  while (hex.length > 2 && hex.startsWith('00')) hex = hex.slice(2);
  return hex;
}

/**
 * A certificate's id: the same for Cert Spotter and crt.sh, for the precertificate and the final
 * certificate. Without a serial (an unreadable `cert_der`), the source's own key stands in.
 * @param {{ intermediate?: string|null, serialHex?: string|null, fallback?: string }} c
 * @returns {string}
 */
export function certId({ intermediate = null, serialHex = null, fallback = '' }) {
  const serial = serialOf(serialHex);
  return fnv64(serial ? `${String(intermediate || '').toLowerCase()}|${serial}` : `key|${fallback}`);
}

/** '2026-07-02T00:00:00Z' (Cert Spotter) or a Date (lib/sources.js) → Date, or null. */
function dateOf(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value !== 'string' || !value.trim()) return null;
  let s = value.trim().replace(' ', 'T');
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z';
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : new Date(t);
}

const ms = (now) => (now instanceof Date ? now.getTime() : typeof now === 'function' ? Number(now()) : Number(now));

/** The names of a certificate that are the domain or under it, lowercase, sorted. */
function ownNames(names, domain) {
  const out = new Set();
  for (const raw of Array.isArray(names) ? names : []) {
    if (typeof raw !== 'string') continue;
    const n = normalizeHostname(raw.trim(), { allowWildcard: true });
    if (!n) continue;
    const bare = n.startsWith('*.') ? n.slice(2) : n;
    if (bare === domain || isSubdomainOf(bare, domain)) out.add(n);
  }
  return sortHostnames([...out]);
}

/** Standard base64 → bytes, or null. */
function base64Bytes(text) {
  if (typeof text !== 'string' || !text) return null;
  try {
    const bin = atob(text.replace(/\s+/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Short error text for a result (never a stack). */
function errorText(err) {
  return String((err && err.message) || err || 'Unknown error').replace(/\s+/g, ' ').trim().slice(0, 300);
}

/** A failure as lib/sourcestatus.js sourceStatus reads it. */
function failureOf(source, err, at) {
  return {
    source,
    error: errorText(err),
    errorKind: (err && typeof err.kind === 'string' && err.kind) || errorKind(err),
    status: err && Number.isInteger(err.status) ? err.status : null,
    retryAfterMs: err && Number.isFinite(err.retryAfterMs) ? err.retryAfterMs : null,
    at
  };
}

/* ------------------------------------------------------------------------ */
/* Thresholds                                                               */
/* ------------------------------------------------------------------------ */

/**
 * The expiry radar's thresholds from what the user typed ("30, 14, 7"): whole days 1 …
 * {@link CT_WATCH_MAX_DAYS}, largest first, duplicates dropped, at most
 * {@link CT_WATCH_MAX_THRESHOLDS}. Null when the text holds anything else (or nothing).
 * @param {string} text
 * @returns {number[]|null}
 */
export function parseRadarDays(text) {
  const parts = String(text ?? '').split(/[\s,;]+/).filter(Boolean);
  if (!parts.length) return null;
  const out = new Set();
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 1 || n > CT_WATCH_MAX_DAYS) return null;
    out.add(n);
  }
  if (out.size > CT_WATCH_MAX_THRESHOLDS) return null;
  return [...out].sort((a, b) => b - a);
}

/**
 * The radar band of a certificate: the index of the smallest threshold it is within (0 is the
 * largest threshold), or null when it has more days left than every threshold.
 * @param {number} daysLeft
 * @param {number[]} days largest first ({@link parseRadarDays})
 * @returns {number|null}
 */
export function radarBand(daysLeft, days) {
  if (!Number.isFinite(daysLeft)) return null;
  let band = null;
  days.forEach((d, i) => {
    if (daysLeft <= d) band = i;
  });
  return band;
}

/* ------------------------------------------------------------------------ */
/* Cert Spotter quota                                                       */
/* ------------------------------------------------------------------------ */

/**
 * What this page sent to Cert Spotter's subdomain search in the last hour, against its
 * allowance: the requests are counted here (a browser cannot read the rate-limit headers), and a
 * 429 stops every request until its Retry-After (an hour when it is not readable). Memory only.
 * @param {{ limit?: number, windowMs?: number, now?: () => number }} [opts]
 * @returns {{ used(): number, left(): number, take(): boolean, exhaust(untilMs: number): void, blocked(): boolean,
 *   resetAt(): Date|null, lastAt(): number, limit: number }}
 */
export function createSpotterBudget({ limit = CT_WATCH_SPOTTER_LIMIT, windowMs = CT_WATCH_WINDOW_MS, now = Date.now } = {}) {
  let sent = [];
  let until = 0;
  let last = 0;
  const prune = () => {
    const t = now();
    sent = sent.filter((x) => x > t - windowMs);
    return t;
  };
  return {
    limit,
    used() {
      prune();
      return sent.length;
    },
    left() {
      const t = prune();
      return t < until ? 0 : Math.max(0, limit - sent.length);
    },
    take() {
      if (this.left() < 1) return false;
      last = now();
      sent.push(last);
      return true;
    },
    exhaust(untilMs) {
      until = Math.max(until, Number(untilMs) || 0);
    },
    blocked() {
      return now() < until;
    },
    resetAt() {
      const t = prune();
      if (t < until) return new Date(until);
      return sent.length >= limit ? new Date(sent[0] + windowMs) : null;
    },
    lastAt() {
      return last;
    }
  };
}

/** The page session's Cert Spotter budget, shared by every check of the CT tab. */
export const spotterBudget = createSpotterBudget();

/* ------------------------------------------------------------------------ */
/* Reading                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Cert Spotter's subdomain search URL of a domain (DNS names, issuer and DER expanded).
 * @param {string} domain normalized
 * @param {{ after?: string|null }} [opts] id of the last issuance of the previous page
 * @returns {string}
 */
export function spotterWatchUrl(domain, { after = null } = {}) {
  const tail = after ? `&after=${encodeURIComponent(after)}` : '';
  return `${CERTSPOTTER_ISSUANCES}?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert_der`
    + `&expand=revocation&expand=problem_reporting${tail}`;
}

const JSON_INIT = Object.freeze({ headers: { accept: 'application/json' }, credentials: 'omit', referrerPolicy: 'no-referrer' });

/**
 * Cert Spotter issuances (JSON rows) → certificates of the domain: unexpired, with at least one
 * name at or under it; the DER gives the serial and the precertificate flag.
 * @param {any[]} items
 * @param {string} domain normalized
 * @param {{ now?: Date|number }} [opts]
 * @returns {WatchCert[]}
 */
export function fromSpotterItems(items, domain, { now = Date.now() } = {}) {
  const t = ms(now);
  const out = [];
  for (const item of Array.isArray(items) ? items : []) {
    if (!item || typeof item !== 'object') continue;
    const names = ownNames(item.dns_names, domain);
    const notBefore = dateOf(item.not_before);
    const notAfter = dateOf(item.not_after);
    if (!names.length || !notBefore || !notAfter || notAfter.getTime() < t) continue;
    const issuer = item.issuer && typeof item.issuer === 'object' && typeof item.issuer.name === 'string' ? item.issuer.name : '';
    let cert = null;
    const der = base64Bytes(item.cert_der);
    try {
      cert = der ? parseCertificate(der) : null;
    } catch {
      cert = null;
    }
    const intermediate = dnValue(issuer, 'CN');
    const serialHex = cert ? serialOf(cert.serialHex) : null;
    const certSha = typeof item.cert_sha256 === 'string' && SHA256_RE.test(item.cert_sha256) ? item.cert_sha256.toLowerCase() : null;
    // the key's SHA-256 as Cert Spotter says it, else from the DER (both are of the SubjectPublicKeyInfo)
    const spkiSha256 = typeof item.pubkey_sha256 === 'string' && SHA256_RE.test(item.pubkey_sha256) ? item.pubkey_sha256.toLowerCase()
      : cert && cert.spkiDer instanceof Uint8Array && cert.spkiDer.length ? hexOf(sha256(cert.spkiDer)) : null;
    const fallback = typeof item.tbs_sha256 === 'string' && item.tbs_sha256 ? `tbs:${item.tbs_sha256.toLowerCase()}` : `certspotter:${item.id}`;
    const r = spotterRevocation(item);
    out.push({
      id: certId({ intermediate, serialHex, fallback }),
      domain,
      names,
      issuer,
      ca: caName(issuer),
      intermediate,
      notBefore,
      notAfter,
      serialHex,
      sha256: certSha,
      spkiSha256,
      precert: cert ? !!cert.isPrecertificate : null,
      revoked: typeof item.revoked === 'boolean' ? item.revoked : null,
      revocation: r ? { time: r.time, reasonCode: r.reasonCode, reason: r.reason, checkedAt: r.checkedAt } : null,
      problemReporting: problemReportingText(item.problem_reporting),
      wildcard: names.some((n) => n.startsWith('*.')),
      source: 'certspotter',
      url: certSha ? `${CRTSH_BASE}?q=${certSha}` : null
    });
  }
  return out;
}

/**
 * lib/sources.js crt.sh certificates (CtCert) → certificates of the domain (unexpired, with a name
 * at or under it). crt.sh does not say whether a row is the precertificate, nor whether it was
 * revoked: both are null.
 * @param {object[]} certs
 * @param {string} domain normalized
 * @param {{ now?: Date|number }} [opts]
 * @returns {WatchCert[]}
 */
export function fromCrtshCerts(certs, domain, { now = Date.now() } = {}) {
  const t = ms(now);
  const out = [];
  for (const c of Array.isArray(certs) ? certs : []) {
    if (!c || typeof c !== 'object') continue;
    const names = ownNames(c.names, domain);
    const notBefore = dateOf(c.notBefore);
    const notAfter = dateOf(c.notAfter);
    if (!names.length || !notBefore || !notAfter || notAfter.getTime() < t) continue;
    const issuer = typeof c.issuer === 'string' ? c.issuer : '';
    const intermediate = dnValue(issuer, 'CN');
    const serialHex = serialOf(c.serialHex);
    out.push({
      id: certId({ intermediate, serialHex, fallback: String(c.key || c.id || '') }),
      domain,
      names,
      issuer,
      ca: caName(issuer),
      intermediate,
      notBefore,
      notAfter,
      serialHex,
      sha256: typeof c.sha256 === 'string' && c.sha256 ? c.sha256 : null,
      spkiSha256: null,
      precert: null,
      revoked: null,
      revocation: null,
      problemReporting: null,
      wildcard: names.some((n) => n.startsWith('*.')),
      source: 'crtsh',
      url: typeof c.url === 'string' && c.url.startsWith(CRTSH_BASE) ? c.url : null
    });
  }
  return out;
}

/** One certificate per id: the first source's row wins, the other only fills what it lacks. */
function mergeById(...lists) {
  const byId = new Map();
  for (const c of lists.flat()) {
    const prev = byId.get(c.id);
    if (!prev) {
      byId.set(c.id, { ...c });
      continue;
    }
    for (const k of ['sha256', 'spkiSha256', 'serialHex', 'url', 'revocation', 'problemReporting']) if (!prev[k] && c[k]) prev[k] = c[k];
    if (prev.precert === null && c.precert !== null) prev.precert = c.precert;
    if (prev.revoked === null && c.revoked !== null) prev.revoked = c.revoked;
  }
  return [...byId.values()];
}

/**
 * Every Cert Spotter page of a domain, paced, within the budget: until the empty page (complete),
 * the page cap (truncated), the budget (quota) or an error. Only an abort rejects.
 */
async function spotterPages(domain, { fetchImpl, signal, timeoutMs, maxPages, budget, sleepImpl, spacingMs, now, count }) {
  const items = [];
  let after = null;
  for (let page = 0; page < maxPages; page += 1) {
    if (!budget.take()) return { items, complete: false, truncated: false, quota: true, error: null };
    count();
    let data;
    try {
      data = await fetchJson(spotterWatchUrl(domain, { after }), { ...JSON_INIT, fetchImpl, signal, timeoutMs });
      if (!Array.isArray(data)) throw new ParseError('Unexpected Cert Spotter response (expected a JSON array)');
    } catch (err) {
      if (errorKind(err) === 'abort') throw err;
      if (errorKind(err) === 'rate-limit') {
        const waitMs = Number.isFinite(err.retryAfterMs) && err.retryAfterMs > 0 ? Math.min(err.retryAfterMs, CT_WATCH_WINDOW_MS) : CT_WATCH_WINDOW_MS;
        budget.exhaust(ms(now) + waitMs);
        return { items, complete: false, truncated: false, quota: true, error: err };
      }
      return { items, complete: false, truncated: false, quota: false, error: err };
    }
    if (!data.length) return { items, complete: true, truncated: false, quota: false, error: null };
    items.push(...data);
    const last = data[data.length - 1];
    if (!last || last.id === undefined || last.id === null || String(last.id) === after) return { items, complete: true, truncated: false, quota: false, error: null };
    after = String(last.id);
    if (page < maxPages - 1 && spacingMs > 0) await sleepImpl(spacingMs, signal);
  }
  return { items, complete: false, truncated: true, quota: false, error: null };
}

/**
 * Read one domain's certificates (the domain and every name under it) from Certificate
 * Transparency: Cert Spotter while its budget has {@link CT_WATCH_SPOTTER_MIN} requests left
 * (paced, one request at a time through `spotterQueue`), crt.sh when the budget is used up, Cert
 * Spotter answered 429 or failed, or its list was cut by the quota (the two lists are merged).
 * A list cut at the page cap is kept as it is ('truncated': crt.sh times out on such domains).
 * @param {string} domain registrable domain (normalized here)
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, now?: () => number, budget?: ReturnType<typeof createSpotterBudget>,
 *   spotterQueue?: ReturnType<typeof createLimiter>, sleepImpl?: Function, spacingMs?: number, maxPages?: number,
 *   timeoutMs?: number, crtshTimeoutMs?: number, crtshRetryDelayMs?: number }} [opts]
 * @returns {Promise<DomainRead>}
 */
export async function readDomainCt(domain, {
  fetchImpl = globalThis.fetch, signal, now = Date.now, budget = spotterBudget, spotterQueue = createLimiter(1), sleepImpl = sleep,
  spacingMs = CT_WATCH_SPACING_MS, maxPages = CT_WATCH_MAX_PAGES, timeoutMs = CT_TIMEOUT_MS, crtshTimeoutMs = CT_WATCH_CRTSH_TIMEOUT_MS,
  crtshRetryDelayMs
} = {}) {
  throwIfAborted(signal);
  const d = normalizeHostname(String(domain ?? ''));
  if (!d) throw new TypeError(`Not a domain: ${String(domain).slice(0, 80)}`);
  const at = ms(now);
  const read = { domain: d, at: new Date(at), state: 'failed', source: null, certs: [], failures: [], notes: [], requests: { certspotter: 0, crtsh: 0 } };
  let spotted = [];
  if (budget.left() >= CT_WATCH_SPOTTER_MIN) {
    // In the queue, the budget is read again: the domains before this one may have used it up.
    const pages = await spotterQueue.run(async () => {
      if (budget.left() < CT_WATCH_SPOTTER_MIN) return null;
      const gap = budget.lastAt() + spacingMs - ms(now);
      if (budget.lastAt() && gap > 0) await sleepImpl(gap, signal);
      return spotterPages(d, { fetchImpl, signal, timeoutMs, maxPages: Math.max(1, Math.floor(maxPages) || 1), budget, sleepImpl, spacingMs, now, count: () => { read.requests.certspotter += 1; } });
    }, { signal });
    throwIfAborted(signal);
    if (pages) {
      spotted = fromSpotterItems(pages.items, d, { now: at });
      if (pages.complete || pages.truncated) {
        Object.assign(read, { state: pages.truncated ? 'partial' : 'ok', source: 'certspotter', certs: spotted });
        if (pages.truncated) read.notes.push('truncated');
        return read;
      }
      if (pages.quota) read.notes.push('spotter-quota');
      else {
        read.notes.push('spotter-failed');
        read.failures.push(failureOf('certspotter', pages.error, at));
      }
    } else {
      read.notes.push('spotter-quota');
    }
  } else {
    read.notes.push('spotter-quota');
  }
  const r = await fetchSource('crtsh', d, { fetchImpl, signal, timeoutMs: crtshTimeoutMs, retryDelayMs: crtshRetryDelayMs, sleepImpl });
  throwIfAborted(signal);
  read.requests.crtsh = r.attempts || 0;
  if (r.ok) {
    read.certs = mergeById(spotted, fromCrtshCerts(r.certs, d, { now: at }));
    read.source = 'crtsh';
    read.state = r.partial ? 'partial' : 'ok';
    if (r.partial) read.notes.push('crtsh-partial');
    return read;
  }
  read.failures.push({ source: 'crtsh', error: r.error, errorKind: r.errorKind, status: null, retryAfterMs: r.quota && Number.isFinite(r.quota.retryAfterMs) ? r.quota.retryAfterMs : null, at });
  if (read.notes.includes('spotter-quota') && !read.failures.some((f) => f.source === 'certspotter')) {
    const reset = budget.resetAt();
    read.failures.unshift({
      source: 'certspotter', error: 'Cert Spotter’s hourly quota for subdomain searches is used up', errorKind: 'rate-limit', status: null,
      retryAfterMs: reset ? Math.max(0, reset.getTime() - at) : null, at
    });
  }
  if (spotted.length) {
    Object.assign(read, { state: 'partial', source: 'certspotter', certs: spotted });
  }
  return read;
}

/**
 * Read every domain ({@link readDomainCt}), {@link CT_WATCH_CONCURRENCY} at a time, Cert Spotter's
 * requests one at a time. `onRead` gets each domain's read as it lands. Rejects only on an abort.
 * @param {string[]} domains
 * @param {Parameters<typeof readDomainCt>[1] & { onRead?: (read: DomainRead) => void, concurrency?: number }} [opts]
 * @returns {Promise<DomainRead[]>} in the order of `domains`
 */
export async function readPortfolioCt(domains, { onRead, concurrency = CT_WATCH_CONCURRENCY, ...opts } = {}) {
  const list = [...new Set((domains || []).map((x) => normalizeHostname(String(x ?? ''))).filter(Boolean))].slice(0, CT_WATCH_MAX_DOMAINS);
  const limit = createLimiter(concurrency);
  const spotterQueue = opts.spotterQueue || createLimiter(1);
  return Promise.all(list.map((d) => limit.run(async () => {
    const read = await readDomainCt(d, { ...opts, spotterQueue });
    if (typeof onRead === 'function') {
      try {
        onRead(read);
      } catch {
        /* an observer never breaks the read */
      }
    }
    return read;
  }, { signal: opts.signal })));
}

/* ------------------------------------------------------------------------ */
/* Analysis                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {WatchCert & { daysLeft: number, band: number|null, nameSet: string, newest: boolean, superseded: boolean,
 *   current: boolean, isNew: boolean|null, unexpected: boolean|null, flags: string[],
 *   known: { id: string, expires: string, reason: string, owner: string }|null,
 *   knownExpired: { id: string, expires: string, reason: string, owner: string }|null }} WatchRow
 *   `newest`: the newest valid (not revoked) certificate of its exact name set; `superseded`: every
 *   name is on another valid certificate that expires later; `current`: newest and not
 *   superseded (what the radar watches); `isNew`: not seen at the domain's last check (null: no
 *   earlier check); `unexpected`: the issuer is none of the expected CAs (null: none set); `known`:
 *   the active waiver that makes it a known certificate (then `isNew` and `unexpected` are false);
 *   `knownExpired`: one that is over (the flags are as without it)
 */

/**
 * The known-certificate waiver of a certificate (its key's SHA-256, else its own), active first.
 * @param {object[]} known lib/waivers.js waivers
 * @param {{ domain: string, spkiSha256?: string|null, sha256?: string|null }} c
 * @param {number} t now, ms
 */
function knownOf(known, c, t) {
  if (!known || !known.length) return null;
  return matchWaiver(known, { kind: 'cert', domain: c.domain, refs: [c.spkiSha256, c.sha256] }, { now: t });
}

/**
 * The rows of the table and what the tiles count, from the domains' reads.
 * @param {DomainRead[]} reads
 * @param {{ now?: Date|number, days?: number[], expected?: string[], seen?: ReturnType<typeof readSeen>, known?: object[],
 *   knownAt?: Date|number }} [opts]
 *   `known`: lib/waivers.js waivers (kind 'cert'): the known certificates, never new nor unexpected;
 *   `knownAt`: when they are matched (default `now`) — a panel drawing an earlier read matches them
 *   at the time it draws, so a waiver over since the read no longer applies
 * @returns {{ rows: WatchRow[], counts: Record<string, number>, first: string[] }} rows sorted by domain,
 *   then the soonest expiry; `first`: domains read without an earlier check; `counts.known`: the known rows
 */
export function analyzeCt(reads, { now = Date.now(), days = CT_WATCH_DEFAULT_DAYS, expected = [], seen = emptySeen(), known = [], knownAt = now } = {}) {
  const t = ms(now);
  const tKnown = ms(knownAt);
  const rows = [];
  const first = [];
  const radar = days.length ? days[0] : 0;
  for (const read of reads || []) {
    if (!read || read.state === 'failed') continue;
    const base = seen.domains[read.domain] || null;
    if (!base) first.push(read.domain);
    const certs = read.certs || [];
    // the newest valid certificate of each name set, unless a later one covers it (lib/ctseen.js)
    const standing = certStanding(certs, t);
    for (const [i, c] of certs.entries()) {
      const daysLeft = Math.floor((c.notAfter.getTime() - t) / DAY_MS);
      const { newest, superseded, current } = standing[i];
      const status = expectedCaStatus(c.issuer, expected);
      const k = knownOf(known, { ...c, domain: c.domain || read.domain }, tKnown);
      const isKnown = !!(k && k.active);
      const row = {
        ...c,
        daysLeft,
        band: current ? radarBand(daysLeft, days) : null,
        nameSet: c.names.join(' '),
        newest,
        superseded,
        current,
        // a known certificate is neither new nor unexpected: its key was accepted as ours
        isNew: base ? (isKnown ? false : !Object.prototype.hasOwnProperty.call(base.ids, c.id)) : null,
        unexpected: status ? (isKnown ? false : !status.expected) : null,
        known: isKnown ? { id: k.waiver.id, expires: k.waiver.expires, reason: k.waiver.reason, owner: k.waiver.owner } : null,
        knownExpired: k && !k.active ? { id: k.waiver.id, expires: k.waiver.expires, reason: k.waiver.reason, owner: k.waiver.owner } : null,
        flags: []
      };
      if (row.isNew) row.flags.push('new');
      if (row.unexpected) row.flags.push('unexpected');
      if (c.precert) row.flags.push('precert');
      if (c.wildcard) row.flags.push('wildcard');
      if (c.revoked) row.flags.push('revoked');
      if (superseded) row.flags.push('superseded');
      if (isKnown) row.flags.push('known');
      rows.push(row);
    }
  }
  rows.sort((a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0) || a.notAfter - b.notAfter || (a.id < b.id ? -1 : 1));
  const counts = Object.fromEntries(CT_WATCH_FILTERS.map((f) => [f, rows.filter((r) => matchesCtFilter(r, f, { radar })).length]));
  counts.known = rows.filter((r) => r.known).length;
  return { rows, counts, first };
}

/**
 * Does a row pass a filter of {@link CT_WATCH_FILTERS}?
 * @param {WatchRow} row
 * @param {string} filter
 * @param {{ radar?: number }} [opts] the largest threshold (the radar's reach)
 * @returns {boolean}
 */
export function matchesCtFilter(row, filter, { radar = CT_WATCH_DEFAULT_DAYS[0] } = {}) {
  switch (filter) {
    case 'all': return true;
    case 'current': return row.current;
    case 'new': return row.isNew === true;
    case 'expiring': return row.current && row.daysLeft <= radar;
    case 'unexpected': return row.unexpected === true;
    case 'wildcard': return row.wildcard;
    case 'precert': return row.precert === true;
    default: return true;
  }
}

/**
 * The calendar entries of the expiries: one per name set of a domain whose newest certificate is
 * current, with a UID per (domain, name set), so importing a newer file moves the event of a
 * renewed certificate instead of adding one (lib/ics.js).
 * @param {WatchRow[]} rows
 * @returns {Array<{ uid: string, date: Date, domain: string, names: string[], ca: string, intermediate: string|null }>}
 */
export function expiryEntries(rows) {
  return (rows || []).filter((r) => r.current).map((r) => ({
    uid: `ct-${fnv64(`${r.domain}|${r.nameSet}`)}@domainscope`,
    date: r.notAfter,
    domain: r.domain,
    names: r.names,
    ca: r.ca,
    intermediate: r.intermediate
  }));
}

/** The CSV columns of {@link exportCtRow}, in order. */
export const CT_EXPORT_COLUMNS = Object.freeze(['domain', 'names', 'ca', 'intermediate', 'notBefore', 'notAfter', 'daysLeft', 'current', 'new',
  'unexpectedCa', 'precertificateOnly', 'wildcard', 'revoked', 'superseded', 'serial', 'sha256', 'source', 'url', 'revokedAt', 'revocationReason',
  'publicKeySha256', 'knownUntil']);

/**
 * One row as the CSV holds it: plain values, booleans as yes / no, unknown as an empty cell.
 * @param {WatchRow} r
 * @returns {Record<string, string|number>}
 */
export function exportCtRow(r) {
  const yn = (v) => (v === true ? 'yes' : v === false ? 'no' : '');
  return {
    domain: r.domain,
    names: r.names.join(' '),
    ca: r.ca,
    intermediate: r.intermediate || '',
    notBefore: r.notBefore.toISOString(),
    notAfter: r.notAfter.toISOString(),
    daysLeft: r.daysLeft,
    current: yn(r.current),
    new: yn(r.isNew),
    unexpectedCa: yn(r.unexpected),
    precertificateOnly: yn(r.precert),
    wildcard: yn(r.wildcard),
    revoked: yn(r.revoked),
    superseded: yn(r.superseded),
    serial: r.serialHex || '',
    sha256: r.sha256 || '',
    source: r.source,
    url: r.url || '',
    revokedAt: r.revoked && r.revocation && r.revocation.time ? r.revocation.time.toISOString() : '',
    revocationReason: r.revoked && r.revocation && r.revocation.reason ? r.revocation.reason : '',
    publicKeySha256: r.spkiSha256 || '',
    knownUntil: r.known ? r.known.expires : ''
  };
}
