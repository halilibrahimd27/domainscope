/**
 * ctcert.js — the public certificate of one host name, read from Certificate Transparency, for
 * users who have no certificate file at hand (Certificate view, SSL Targets step 1).
 *
 * Verified live on 2026-09-27 with `Origin: https://halilibrahimd27.github.io`:
 *   - Cert Spotter `GET /v1/issuances?domain=<host>&match_wildcards=true&expand=dns_names
 *     &expand=cert_der` answers with ACAO `*`. `cert_der` is the base64 DER of the final
 *     certificate, or of the precertificate while only that one is logged (the CT poison
 *     extension tells them apart; www.wikipedia.org had one). Only unexpired issuances are
 *     listed, in ascending id (discovery) order, 100 per page; `after=<last id>` pages on and an
 *     empty page (`[]`, `Retry-After: 3600`) ends the list. A single-host query counts against
 *     the 100-per-hour allowance per IP (`X-Ratelimit-Limit: 100`), not the 10-per-hour
 *     full-domain one a scan's source uses (`include_subdomains=true`). `domain=*.example.com`
 *     lists the certificates holding that wildcard name. The rate-limit headers are not
 *     CORS-exposed, so a browser only ever sees a 429.
 *     The empty page is the documented end of the list; the page size is not part of the
 *     contract, so a short page does not end it and a lookup reads on to the empty page. Most
 *     names therefore cost two requests (their one page, then `[]`): about 50 lookups an hour.
 *   - crt.sh `?q=<name>&output=json&exclude=expired` answers with ACAO `*`, but its download
 *     `?d=<id>` sends no ACAO header: a page cannot read the certificate from crt.sh. Its
 *     identity search matches names literally (`q=www.example.com` does not list a
 *     `*.example.com` certificate, `q=*.example.com` does) and lists the precertificate and the
 *     final certificate as two rows with the same serial that nothing in the JSON tells apart
 *     (`deduplicate=Y` keeps the lower id, which was the precertificate for one name and the
 *     certificate for another). So crt.sh is only the fallback that FINDS the certificate when
 *     Cert Spotter cannot answer: the user downloads it from crt.sh and drops the file.
 *
 * DOM-free. Every request goes through util.fetchJson with an injected `fetchImpl` and the
 * caller's `signal`; only an abort rejects, every other failure is reported in the result.
 */

import { fetchJson, retry, defaultShouldRetry, errorKind, throwIfAborted, ParseError } from './util.js';
import { normalizeHostname, certCovers, isPublicSuffix, sortHostnames } from './domain.js';
import { parseCertificate } from './x509.js';
import { sourceQuota } from './sources.js';

/** Cert Spotter issuances endpoint (anonymous). */
export const CERTSPOTTER_ISSUANCES = 'https://api.certspotter.com/v1/issuances';
/** crt.sh base URL (JSON search, and the certificate pages / downloads a user opens). */
export const CRTSH_BASE = 'https://crt.sh/';
/** At most this many Cert Spotter pages per lookup (500 current certificates for one name). */
export const CT_MAX_PAGES = 5;
/** Per-request timeout for Cert Spotter. */
export const CT_TIMEOUT_MS = 25000;
/** Per-request timeout for crt.sh (slow for busy names). */
export const CRTSH_TIMEOUT_MS = 60000;
/** crt.sh's one retry after a server error waits 4–8 s (crt.sh flaps; sources.js waits longer). */
export const CRTSH_RETRY_DELAY_MS = 4000;
/** How long Cert Spotter is skipped after a 429 when its Retry-After is not readable (browsers). */
export const CT_COOLDOWN_MS = 3600000;
/** Lookup outcomes: a certificate to load, a crt.sh entry to download by hand, nothing current, both services failed. */
export const CT_LOOKUP_STATUSES = Object.freeze(['found', 'manual', 'not-found', 'error']);
/** What happened to the Cert Spotter request of a lookup. */
export const CT_SPOTTER_STATES = Object.freeze(['ok', 'partial', 'failed', 'skipped']);

/**
 * @typedef {object} CtIssuance a Cert Spotter issuance (or crt.sh certificate) as the UI shows it
 * @property {string} id Cert Spotter issuance id / crt.sh id
 * @property {Date} notBefore
 * @property {Date} notAfter
 * @property {string[]} dnsNames sorted
 * @property {string|null} sha256 certificate SHA-256 (lowercase hex) when the source gives it
 * @property {string|null} url crt.sh search for this certificate (by SHA-256), null without one
 */

/**
 * @typedef {object} CtCrtshEntry the newest current certificate crt.sh lists for the name
 * @property {string[]} ids every crt.sh id of this serial and issuer, ascending: usually two, the
 *   precertificate and the final certificate, and crt.sh's JSON does not say which is which (the
 *   later id was the precertificate as often as not in the 2026-09-27 samples)
 * @property {string|null} serialHex lowercase hex, no leading 00
 * @property {string} issuer issuer DN as crt.sh prints it
 * @property {Date} notBefore
 * @property {Date} notAfter
 * @property {string[]} names the matching names crt.sh reported (not the full SAN list)
 * @property {Array<{ id: string, url: string }>} downloads `https://crt.sh/?d=<id>` per id: file
 *   downloads the user saves and drops (a page cannot read them)
 * @property {string} pageUrl `https://crt.sh/?id=<first id>`
 */

/**
 * @typedef {object} CtLookup
 * @property {string} host the normalized name that was looked up ('*.x' for a wildcard)
 * @property {'found'|'manual'|'not-found'|'error'} status
 * @property {'certspotter'|'crtsh'|null} provider the service the outcome comes from
 * @property {Uint8Array|null} der the certificate to load (status 'found')
 * @property {object|null} certificate lib/x509 Certificate parsed from `der`
 * @property {CtIssuance|null} issuance
 * @property {boolean} precertificate `der` is a precertificate: no final certificate of this
 *   issuance (nor an older current one) is logged. Same names, dates, serial and key as the
 *   certificate servers send, but another fingerprint.
 * @property {CtIssuance|null} newerPrecertificate a newer issuance that is only logged as a
 *   precertificate (the loaded final certificate is the newest one logged)
 * @property {number} candidates current, non-revoked issuances that cover the name
 * @property {{ notCovering: number, notYetValid: number, expired: number, revoked: number, unreadable: number }} skipped
 * @property {boolean} truncated Cert Spotter lists more than was read (page cap, or a later page failed)
 * @property {number} requests HTTP requests sent (Cert Spotter pages + crt.sh searches, retries included)
 * @property {{ state: 'ok'|'partial'|'failed'|'skipped', error: string|null, errorKind: string|null, quota: object|null }} certspotter
 *   quota: lib/sources SourceQuota (hintKey 'source.quota.hour') when Cert Spotter is rate limited
 * @property {{ entry: CtCrtshEntry|null, candidates: number, partial: boolean, error: string|null, errorKind: string|null }|null} crtsh
 *   set when crt.sh was asked (Cert Spotter failed, was skipped, or had nothing readable)
 * @property {string|null} error status 'error': what failed last
 * @property {string|null} errorKind util.errorKind() of that error
 */

/* ------------------------------------------------------------------------ */
/* Names                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * The host name to look up: a host, URL or `*.domain` (IDN → punycode, lowercase), or null for
 * anything else (IP addresses, single labels, a wildcard directly under a public suffix).
 * @param {string} input
 * @returns {string|null}
 */
export function normalizeCtHost(input) {
  const host = normalizeHostname(String(input ?? ''), { allowWildcard: true });
  if (!host) return null;
  if (host.startsWith('*.') && isPublicSuffix(host.slice(2), { includePrivate: false })) return null;
  return host;
}

/**
 * Does a certificate with these names cover `host`? A wildcard query (`*.example.com`) asks for
 * the certificate that holds that very name; any other host follows RFC 6125 (domain.certCovers).
 * @param {string[]} names certificate DNS names
 * @param {string} host normalized ({@link normalizeCtHost})
 * @returns {boolean}
 */
export function coversCtHost(names, host) {
  const list = Array.isArray(names) ? names.filter((n) => typeof n === 'string') : [];
  if (host.startsWith('*.')) return list.some((n) => n.toLowerCase() === host);
  return certCovers(list, host).covered;
}

/**
 * Cert Spotter issuances URL for one name (single-host allowance; wildcard certificates that
 * cover the host included, DNS names and the DER expanded).
 * @param {string} host normalized
 * @param {{ after?: string|null }} [opts] id of the last issuance of the previous page
 * @returns {string}
 */
export function certspotterUrl(host, { after = null } = {}) {
  const params = [`domain=${encodeURIComponent(host)}`];
  if (!host.startsWith('*.')) params.push('match_wildcards=true');
  params.push('expand=dns_names', 'expand=cert_der');
  if (after !== null && after !== undefined && after !== '') params.push(`after=${encodeURIComponent(after)}`);
  return `${CERTSPOTTER_ISSUANCES}?${params.join('&')}`;
}

/**
 * crt.sh identity searches for one name: the name itself and, for a host below a registrable
 * domain, the wildcard of its parent (crt.sh matches names literally). Expired certificates are
 * left out; duplicates are not (the precertificate and the final certificate are both kept).
 * @param {string} host normalized
 * @returns {string[]}
 */
export function crtshSearchUrls(host) {
  const url = (q) => `${CRTSH_BASE}?q=${encodeURIComponent(q)}&output=json&exclude=expired`;
  const out = [url(host)];
  if (!host.startsWith('*.')) {
    const parent = host.slice(host.indexOf('.') + 1);
    if (parent.includes('.') && !isPublicSuffix(parent, { includePrivate: false })) out.push(url(`*.${parent}`));
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Selection                                                                */
/* ------------------------------------------------------------------------ */

/** '2026-07-02T00:00:00Z' (Cert Spotter) or '2026-07-02T00:00:00' (crt.sh, UTC without a zone). */
function parseUtc(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  let s = value.trim().replace(' ', 'T');
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z';
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : new Date(t);
}

/** Numeric ids as strings: longer is larger, then lexicographic (ids exceed 2^53 one day). */
function compareIds(a, b) {
  const x = String(a ?? '');
  const y = String(b ?? '');
  if (/^\d+$/.test(x) && /^\d+$/.test(y) && x.length !== y.length) return x.length - y.length;
  return x < y ? -1 : x > y ? 1 : 0;
}

/** Standard base64 → bytes, or null. */
function base64ToBytes(text) {
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

function lowerHex(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : null;
}

function describeIssuance(c) {
  const sha256 = lowerHex(c.item.cert_sha256);
  return {
    id: String(c.item.id ?? ''),
    notBefore: c.notBefore,
    notAfter: c.notAfter,
    dnsNames: sortHostnames(c.names),
    sha256,
    url: sha256 ? `${CRTSH_BASE}?q=${sha256}` : null
  };
}

const emptySkipped = () => ({ notCovering: 0, notYetValid: 0, expired: 0, revoked: 0, unreadable: 0 });

/**
 * Pick the certificate to load from Cert Spotter issuances: those that cover `host`, are valid at
 * `now` and not revoked, newest `not_before` first (then the highest id). A final certificate
 * wins over a newer issuance that is only logged as a precertificate (whose fingerprint no
 * server sends); a precertificate is picked only when no final certificate is logged. The DER is
 * parsed with lib/x509 and must cover the host itself.
 * @param {any[]} issuances Cert Spotter JSON rows (with dns_names and cert_der)
 * @param {string} host normalized
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ issuance: CtIssuance|null, der: Uint8Array|null, certificate: object|null, precertificate: boolean,
 *   newerPrecertificate: CtIssuance|null, candidates: number, skipped: CtLookup['skipped'] }}
 */
export function selectIssuance(issuances, host, { now = Date.now() } = {}) {
  const t = now instanceof Date ? now.getTime() : Number(now);
  const skipped = emptySkipped();
  const live = [];
  for (const item of Array.isArray(issuances) ? issuances : []) {
    if (!item || typeof item !== 'object') continue;
    const names = Array.isArray(item.dns_names) ? item.dns_names.filter((n) => typeof n === 'string') : [];
    if (!coversCtHost(names, host)) {
      skipped.notCovering += 1;
      continue;
    }
    const notBefore = parseUtc(item.not_before);
    const notAfter = parseUtc(item.not_after);
    if (!notBefore || !notAfter) skipped.unreadable += 1;
    else if (notBefore.getTime() > t) skipped.notYetValid += 1;
    else if (notAfter.getTime() < t) skipped.expired += 1;
    else if (item.revoked === true) skipped.revoked += 1;
    else live.push({ item, names, notBefore, notAfter });
  }
  live.sort((a, b) => b.notBefore - a.notBefore || compareIds(b.item.id, a.item.id));
  const none = { issuance: null, der: null, certificate: null, precertificate: false, newerPrecertificate: null, candidates: live.length, skipped };
  let precert = null;
  for (const c of live) {
    const der = base64ToBytes(c.item.cert_der);
    let certificate = null;
    try {
      certificate = der ? parseCertificate(der) : null;
    } catch {
      certificate = null;
    }
    if (!certificate || !coversCtHost(certificate.hostnames, host)) {
      skipped.unreadable += 1;
      continue;
    }
    if (certificate.isPrecertificate) {
      if (!precert) precert = { c, der, certificate };
      continue;
    }
    return { ...none, issuance: describeIssuance(c), der, certificate, newerPrecertificate: precert ? describeIssuance(precert.c) : null };
  }
  if (precert) return { ...none, issuance: describeIssuance(precert.c), der: precert.der, certificate: precert.certificate, precertificate: true };
  return none;
}

/** crt.sh serial: lowercase hex without leading 00 bytes. */
function crtshSerial(value) {
  let hex = String(value ?? '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (!hex) return null;
  if (hex.length % 2) hex = `0${hex}`;
  while (hex.length > 2 && hex.startsWith('00')) hex = hex.slice(2);
  return hex;
}

/**
 * The newest current certificate in crt.sh rows that covers `host` (rows of one serial and
 * issuer — precertificate and final certificate — are one certificate).
 * @param {any[]} rows crt.sh JSON rows
 * @param {string} host normalized
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ entry: CtCrtshEntry|null, candidates: number }}
 */
export function selectCrtshEntry(rows, host, { now = Date.now() } = {}) {
  const t = now instanceof Date ? now.getTime() : Number(now);
  const groups = new Map();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row || typeof row !== 'object' || row.id === undefined || row.id === null || !/^\d+$/.test(String(row.id))) continue;
    const names = [...String(row.name_value ?? '').split(/\s+/), String(row.common_name ?? '')]
      .map((n) => n.trim().toLowerCase()).filter(Boolean);
    if (!coversCtHost(names, host)) continue;
    const notBefore = parseUtc(row.not_before);
    const notAfter = parseUtc(row.not_after);
    if (!notBefore || !notAfter || notBefore.getTime() > t || notAfter.getTime() < t) continue;
    const serialHex = crtshSerial(row.serial_number);
    const key = serialHex ? `${row.issuer_ca_id ?? ''}|${serialHex}` : `id:${row.id}`;
    let g = groups.get(key);
    if (!g) {
      g = { ids: [], serialHex, issuer: String(row.issuer_name ?? ''), notBefore, notAfter, names: new Set() };
      groups.set(key, g);
    }
    g.ids.push(String(row.id));
    for (const n of names) if (normalizeHostname(n, { allowWildcard: true }) === n) g.names.add(n);
  }
  const list = [...groups.values()].map((g) => ({ ...g, ids: [...new Set(g.ids)].sort(compareIds) }));
  list.sort((a, b) => b.notBefore - a.notBefore || compareIds(b.ids.at(-1), a.ids.at(-1)));
  const best = list[0];
  if (!best) return { entry: null, candidates: 0 };
  return {
    entry: {
      ids: best.ids,
      serialHex: best.serialHex,
      issuer: best.issuer,
      notBefore: best.notBefore,
      notAfter: best.notAfter,
      names: sortHostnames([...best.names]),
      downloads: best.ids.map((id) => ({ id, url: `${CRTSH_BASE}?d=${id}` })),
      pageUrl: `${CRTSH_BASE}?id=${best.ids[0]}`
    },
    candidates: list.length
  };
}

/* ------------------------------------------------------------------------ */
/* Rate limit                                                               */
/* ------------------------------------------------------------------------ */

/**
 * Remembers a Cert Spotter 429 for this page session, so later lookups go straight to crt.sh
 * instead of prolonging the penalty. Memory only.
 * @returns {{ get(now?: number): object|null, set(quota: object, untilMs: number): void, clear(): void }}
 *   get: the SourceQuota while the cool-down runs, else null
 */
export function createCtCooldown() {
  let until = 0;
  let quota = null;
  return {
    get(now = Date.now()) {
      return until > now ? quota : null;
    },
    set(q, untilMs) {
      quota = q;
      until = Number(untilMs) || 0;
    },
    clear() {
      quota = null;
      until = 0;
    }
  };
}

/** The page session's cool-down, shared by every lookup that is not given its own. */
export const ctCooldown = createCtCooldown();

/* ------------------------------------------------------------------------ */
/* Lookup                                                                   */
/* ------------------------------------------------------------------------ */

const JSON_INIT = Object.freeze({ headers: { accept: 'application/json' }, credentials: 'omit', referrerPolicy: 'no-referrer' });

/** Short error text for the result (never a stack). */
function errorText(err) {
  const msg = String((err && err.message) || err || 'Unknown error').replace(/\s+/g, ' ').trim();
  return msg.slice(0, 300);
}

/**
 * Every Cert Spotter page of the name, until an empty page (the end), the page cap or an error.
 * An error on the first page is thrown; on a later page the rows read so far are returned with it.
 * A short page is not taken for the end (see the module header): the empty page costs one request.
 */
async function certspotterPages(host, { fetchImpl, signal, timeoutMs, maxPages, count }) {
  const items = [];
  let after = null;
  for (let page = 0; page < maxPages; page += 1) {
    let data;
    try {
      count();
      data = await fetchJson(certspotterUrl(host, { after }), { ...JSON_INIT, fetchImpl, signal, timeoutMs });
      if (!Array.isArray(data)) throw new ParseError('Unexpected Cert Spotter response (expected a JSON array)');
    } catch (err) {
      if (page === 0 || errorKind(err) === 'abort') throw err;
      return { items, truncated: true, error: err };
    }
    if (!data.length) return { items, truncated: false, error: null };
    items.push(...data);
    const last = data[data.length - 1];
    if (!last || last.id === undefined || last.id === null || String(last.id) === after) return { items, truncated: false, error: null };
    after = String(last.id);
  }
  return { items, truncated: true, error: null };
}

/** crt.sh is retried once on a server error or a CORS-less error page, never after a timeout. */
const crtshShouldRetry = (err) => errorKind(err) !== 'timeout' && defaultShouldRetry(err);

/** crt.sh searches (in parallel, one retry each); rows of every search that answered. */
async function crtshRows(host, { fetchImpl, signal, timeoutMs, retryDelayMs, count }) {
  const settled = await Promise.allSettled(crtshSearchUrls(host).map((url) => retry(() => {
    count();
    return fetchJson(url, { ...JSON_INIT, fetchImpl, signal, timeoutMs });
  }, { retries: 1, baseDelayMs: retryDelayMs, maxDelayMs: 2 * retryDelayMs, signal, shouldRetry: crtshShouldRetry })));
  throwIfAborted(signal);
  const rows = [];
  let error = null;
  let answered = 0;
  for (const s of settled) {
    if (s.status === 'fulfilled' && Array.isArray(s.value)) {
      answered += 1;
      rows.push(...s.value);
    } else {
      const err = s.status === 'rejected' ? s.reason : new ParseError('Unexpected crt.sh response (expected a JSON array)');
      if (errorKind(err) === 'abort') throw err;
      error = error || err;
    }
  }
  if (!answered) throw error;
  return { rows, error };
}

/**
 * Load the newest currently valid certificate of a host name from Certificate Transparency.
 * Cert Spotter first (it returns the DER); when it fails, is cooling down after a 429, or lists
 * only unreadable certificates, crt.sh finds the certificate (status 'manual': a download link,
 * because a page cannot read crt.sh's download). Nothing current → 'not-found'. Only an abort
 * rejects; an invalid name throws a TypeError before any request.
 * @param {string} input host name, URL or `*.domain`
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, now?: Date|number, cooldown?: ReturnType<typeof createCtCooldown>,
 *   maxPages?: number, timeoutMs?: number, crtshTimeoutMs?: number, crtshRetryDelayMs?: number, crtsh?: boolean }} [opts]
 *   crtsh: false never asks crt.sh (status 'error' instead of a fallback); crtshRetryDelayMs: base
 *   of the one crt.sh retry (4–8 s; tests pass 0)
 * @returns {Promise<CtLookup>}
 */
export async function lookupCtCertificate(input, {
  fetchImpl, signal, now = Date.now(), cooldown = ctCooldown, maxPages = CT_MAX_PAGES,
  timeoutMs = CT_TIMEOUT_MS, crtshTimeoutMs = CRTSH_TIMEOUT_MS, crtshRetryDelayMs = CRTSH_RETRY_DELAY_MS, crtsh = true
} = {}) {
  const host = normalizeCtHost(input);
  if (!host) throw new TypeError(`Not a host name: ${String(input).slice(0, 80)}`);
  throwIfAborted(signal);
  const at = now instanceof Date ? now.getTime() : Number(now);
  const out = {
    host,
    status: 'not-found',
    provider: null,
    der: null,
    certificate: null,
    issuance: null,
    precertificate: false,
    newerPrecertificate: null,
    candidates: 0,
    skipped: emptySkipped(),
    truncated: false,
    requests: 0,
    certspotter: { state: 'ok', error: null, errorKind: null, quota: null },
    crtsh: null,
    error: null,
    errorKind: null
  };
  const count = () => { out.requests += 1; };
  // A 429 (readable Retry-After, else an hour) skips Cert Spotter for the rest of the cool-down.
  const spotterFailed = (state, err) => {
    out.certspotter = { state, error: errorText(err), errorKind: errorKind(err), quota: null };
    if (errorKind(err) !== 'rate-limit') return;
    const waitMs = Number.isFinite(err.retryAfterMs) && err.retryAfterMs > 0 ? Math.min(err.retryAfterMs, CT_COOLDOWN_MS) : CT_COOLDOWN_MS;
    const quota = {
      ...sourceQuota('certspotter', { limited: true, retryAfterMs: waitMs }),
      resetAt: new Date(at + waitMs),
      resetHint: 'Cert Spotter’s hourly single-host quota for your IP (100 requests, about 50 lookups) is used up; try again in about an hour.'
    };
    cooldown.set(quota, at + waitMs);
    out.certspotter.quota = quota;
  };

  const cooling = cooldown.get(at);
  if (cooling) {
    out.certspotter = { state: 'skipped', error: 'Cert Spotter rate limit reached earlier in this session', errorKind: 'rate-limit', quota: cooling };
  } else {
    try {
      const pages = await certspotterPages(host, { fetchImpl, signal, timeoutMs, maxPages: Math.max(1, Math.floor(maxPages) || 1), count });
      const sel = selectIssuance(pages.items, host, { now: at });
      Object.assign(out, sel, { provider: 'certspotter', truncated: pages.truncated });
      if (pages.error) spotterFailed('partial', pages.error);
      if (sel.issuance) {
        out.status = 'found';
        return out;
      }
      // Cert Spotter answered and nothing current covers the name: crt.sh reads the same logs, so
      // asking it too would only cost time. A list cut at the page cap stays `truncated` (the
      // views hedge their note: the unread issuances are the newest); crt.sh is not asked for it
      // either, because a name with that many certificates is where its search times out.
      if (!pages.error && !sel.skipped.unreadable) return out;
    } catch (err) {
      if (errorKind(err) === 'abort') throw err;
      spotterFailed('failed', err);
    }
  }

  if (!crtsh) {
    out.status = 'error';
    out.error = out.certspotter.error;
    out.errorKind = out.certspotter.errorKind;
    return out;
  }
  try {
    const { rows, error } = await crtshRows(host, { fetchImpl, signal, timeoutMs: crtshTimeoutMs, retryDelayMs: Math.max(0, Number(crtshRetryDelayMs) || 0), count });
    const sel = selectCrtshEntry(rows, host, { now: at });
    out.crtsh = { entry: sel.entry, candidates: sel.candidates, partial: !!error, error: error ? errorText(error) : null, errorKind: error ? errorKind(error) : null };
    if (sel.entry) {
      out.status = 'manual';
      out.provider = 'crtsh';
    } else if (out.provider !== 'certspotter') {
      out.provider = 'crtsh';
    }
  } catch (err) {
    if (errorKind(err) === 'abort') throw err;
    out.crtsh = { entry: null, candidates: 0, partial: false, error: errorText(err), errorKind: errorKind(err) };
    // Cert Spotter's partial list without a current match still says "nothing found so far".
    if (out.certspotter.state !== 'partial') {
      out.status = 'error';
      out.error = errorText(err);
      out.errorKind = errorKind(err);
    }
  }
  return out;
}
