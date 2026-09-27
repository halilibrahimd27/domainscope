/**
 * sources.js — passive subdomain sources usable from a browser (CORS-enabled,
 * verified 2026-09-23): certificate transparency (crt.sh, Cert Spotter),
 * HackerTarget host search, Anubis DB, AlienVault OTX passive DNS and
 * ip.thc.org.
 *
 * Every function is DOM-free and takes an injectable `fetchImpl` (and
 * `sleepImpl` for backoff / page spacing). Source failures (quota, timeouts,
 * HTTP errors, bad payloads, services being down) never throw: they are
 * reported in the SourceResult. Only caller cancellation rejects (AbortError).
 *
 * Resilience: crt.sh is retried with exponential backoff + jitter and falls
 * back to a lighter query form; quota exhaustion (HackerTarget's 200-text,
 * OTX / Cert Spotter 429) is classified as 'rate-limit' with a `quota` hint and
 * never retried. `sourceHealthSummary()` turns results into a compact status
 * list for UIs.
 */

import {
  AbortError, TimeoutError, HttpError, RateLimitError, ParseError, fetchWithTimeout, errorKind,
  mergeSignals, abortReasonToError, parseRetryAfter, sleep
} from './util.js';
import { normalizeHostname, stripWildcard, isSubdomainOf, sortHostnames } from './domain.js';
import { normalizeIP } from './netinfo.js';

/* ------------------------------------------------------------------------ */
/* Types                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} IpHint
 * @property {string} name hostname (lowercase, no wildcard)
 * @property {string} ip canonical IP
 * @property {string} source source id
 * @property {Date} [firstSeen]
 * @property {Date} [lastSeen]
 */

/**
 * @typedef {object} CtCert
 * @property {string} key de-duplication key ('crtsh:<issuerCaId>:<serial>' or 'sha256:<hex>')
 * @property {string} source source id that reported it first
 * @property {string|number} id source-specific certificate id
 * @property {string|null} serialHex lowercase hex, leading 00 bytes stripped (as x509.serialHex)
 * @property {string} issuer issuer DN / name
 * @property {Date|null} notBefore
 * @property {Date|null} notAfter
 * @property {string[]} names every DNS name of the certificate (wildcards kept as '*.x'), sorted
 * @property {string|null} sha256 certificate SHA-256 (lowercase hex) when known
 * @property {string[]} sources extension: every source that reported it
 * @property {string|null} url extension: link to the certificate on the source site
 */

/**
 * @typedef {object} SourceResult
 * @property {string} source
 * @property {boolean} ok
 * @property {string[]} names normalized, apex + subdomains of the domain only, wildcards stripped, sorted
 * @property {string[]} wildcardBases bases of wildcard names ('*.dev.example.com' → 'dev.example.com')
 * @property {IpHint[]} ipHints
 * @property {CtCert[]} certs
 * @property {string|null} error
 * @property {string|null} errorKind util.errorKind()
 * @property {number} elapsedMs
 * @property {string|null} domain extension: the normalized queried domain
 * @property {boolean} partial extension: some data was received but a later page failed
 * @property {number} rows extension: raw rows / lines received
 * @property {number} attempts extension: HTTP requests made (retries and pages included)
 * @property {SourceQuota|null} quota extension: quota state (always set when errorKind is
 *   'rate-limit'; otherwise only when the service's rate-limit headers were readable)
 * @property {Object<string, string>} lastSeen extension: name → 'YYYY-MM-DD' last time the
 *   source saw it (ip.thc.org last_seen_on, OTX passive DNS `last`); {} when unknown
 * @property {boolean} truncated extension: the source had more records than the page cap allowed
 * @property {number|null} available extension: total records the source reports (ip.thc.org)
 * @property {string|null} queryForm extension (crt.sh): query that produced the data —
 *   'history' (with expired), 'subdomains' (%.domain, unexpired) or 'identity' (fallback)
 *
 * errorKind is util.errorKind() plus 'unavailable': the service answered every
 * retry with a server error / CORS-less error page (e.g. crt.sh 502).
 */

/**
 * @typedef {object} SourceQuota
 * @property {boolean} limited the service refused the request because of its quota
 * @property {'day'|'hour'|'minutes'|null} period how long such a limit typically lasts
 * @property {number|null} retryAfterMs from a readable Retry-After header
 * @property {Date|null} resetAt now + retryAfterMs
 * @property {number|null} limit from readable X-RateLimit-Limit (Node; browsers cannot read it)
 * @property {number|null} remaining from readable X-RateLimit-Remaining
 * @property {string|null} resetHint short English explanation
 * @property {string|null} hintKey i18n key of the localized explanation ('source.quota.*')
 */

/* ------------------------------------------------------------------------ */
/* Source catalogue                                                         */
/* ------------------------------------------------------------------------ */

/**
 * Passive sources. `noteKey` is an i18n key ('source.<id>.note') explaining
 * quotas / speed. Extensions: `timeoutMs` (default per-request timeout),
 * `quota` (short English description).
 * @type {ReadonlyArray<{ id: string, name: string, homepage: string, providesIps: boolean,
 *   providesCerts: boolean, defaultEnabled: boolean, noteKey: string, timeoutMs: number, quota: string }>}
 */
export const SOURCES = Object.freeze([
  {
    id: 'crtsh', name: 'crt.sh', homepage: 'https://crt.sh/', providesIps: false, providesCerts: true,
    defaultEnabled: true, noteKey: 'source.crtsh.note', timeoutMs: 90000,
    quota: 'No key; slow for large domains (up to 60 s+), occasional 502/503.'
  },
  {
    id: 'certspotter', name: 'Cert Spotter', homepage: 'https://sslmate.com/certspotter/', providesIps: false,
    providesCerts: true, defaultEnabled: true, noteKey: 'source.certspotter.note', timeoutMs: 25000,
    quota: 'Unauthenticated: about 10 requests per hour per IP; unexpired certificates only.'
  },
  {
    id: 'hackertarget', name: 'HackerTarget', homepage: 'https://hackertarget.com/find-dns-host-records/',
    providesIps: true, providesCerts: false, defaultEnabled: true, noteKey: 'source.hackertarget.note',
    timeoutMs: 25000, quota: 'Free: about 50 requests per day per IP (shared with reverse IP lookup).'
  },
  {
    id: 'anubis', name: 'Anubis DB', homepage: 'https://anubisdb.com/', providesIps: false, providesCerts: false,
    defaultEnabled: true, noteKey: 'source.anubis.note', timeoutMs: 25000, quota: 'No key.'
  },
  {
    id: 'otx', name: 'AlienVault OTX', homepage: 'https://otx.alienvault.com/', providesIps: true,
    providesCerts: false, defaultEnabled: true, noteKey: 'source.otx.note', timeoutMs: 25000,
    quota: 'Anonymous access is often rate-limited (HTTP 429).'
  },
  {
    id: 'thc', name: 'ip.thc.org', homepage: 'https://ip.thc.org', providesIps: false, providesCerts: false,
    defaultEnabled: true, noteKey: 'source.thc.note', timeoutMs: 25000,
    quota: 'No key; about 250 requests per IP refilling 1 every 2 s. Up to 10 pages (1,000 names) per domain, 2 s apart.'
  }
].map((s) => Object.freeze(s)));

const MAX_CERTSPOTTER_PAGES = 5;
/** crt.sh: attempts of the main query form before the identity-search fallback. */
const CRTSH_ATTEMPTS = 4;
/** crt.sh backoff: 4, 8, 16 s between main attempts and 32 s before the fallback (±25 %) ≈ 60 s. */
const CRTSH_BASE_DELAY_MS = 4000;
const CRTSH_MAX_DELAY_MS = 40000;
/** A crt.sh 429 asking to wait longer than this ends the retries. */
const CRTSH_MAX_RETRY_AFTER_MS = 60000;
/** crt.sh gives up once another attempt would start after this long (or 2 × the request timeout). */
const CRTSH_BUDGET_MS = 180000;
/** Anubis: one retry after this delay on 5xx / network errors (no quota to protect). */
const ANUBIS_RETRY_DELAY_MS = 2000;
const THC_URL = 'https://ip.thc.org/api/v1/lookup/subdomains';
/** ip.thc.org caps `limit` at 100. */
const THC_PAGE_SIZE = 100;
const THC_MAX_PAGES = 10;
/** ip.thc.org token bucket refills 1 request / 2 s: never page faster than that. */
const THC_PAGE_SPACING_MS = 2000;

/**
 * Per-source quota semantics (what a 'rate-limit' means and how long it lasts).
 * `hintKey` values are i18n keys registered in i18n.js.
 */
const QUOTA_POLICY = Object.freeze({
  hackertarget: {
    period: 'day', hintKey: 'source.quota.day',
    resetHint: 'Daily free quota for your IP is used up (about 50 requests); it resets within 24 hours.'
  },
  certspotter: {
    period: 'hour', hintKey: 'source.quota.hour',
    resetHint: 'Hourly free quota for your IP is used up (about 10 requests); try again in about an hour.'
  },
  otx: {
    period: null, hintKey: 'source.quota.later',
    resetHint: 'OTX limits anonymous access per IP; try again later.'
  },
  thc: {
    period: 'minutes', hintKey: 'source.quota.minutes',
    resetHint: 'Rate limit reached (about 250 requests, refilling 1 every 2 s); try again in a few minutes.'
  },
  crtsh: {
    period: 'minutes', hintKey: 'source.quota.minutes',
    resetHint: 'crt.sh rate limit reached; try again in a few minutes.'
  }
});
const DEFAULT_QUOTA_POLICY = Object.freeze({
  period: null, hintKey: 'source.quota.later', resetHint: 'Rate limited by the service; try again later.'
});

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

const clock = () => (globalThis.performance && typeof globalThis.performance.now === 'function'
  ? globalThis.performance.now()
  : Date.now());

function toAbortError(reason) {
  const err = abortReasonToError(reason);
  return err instanceof AbortError ? err : new AbortError(err.message, { cause: err });
}

function checkAbort(signal) {
  if (signal && signal.aborted) throw toAbortError(signal.reason);
}

/** Error carrying an explicit util.errorKind() classification (or 'unavailable'). */
function sourceError(message, kind, extra = {}) {
  const err = new Error(message);
  err.name = 'SourceError';
  err.kind = kind;
  Object.assign(err, extra);
  return err;
}

/** util.errorKind() extended with this module's own 'unavailable' kind. */
function kindOf(err) {
  if (err && typeof err === 'object' && err.kind === 'unavailable') return 'unavailable';
  return errorKind(err);
}

/** Non-negative integer from a header value, or null. */
function headerInt(headers, name) {
  if (!headers) return null;
  const v = headers.get(name);
  if (v === null || v === undefined || !/^\s*\d+\s*$/.test(String(v))) return null;
  return Number(v);
}

/**
 * Remember X-RateLimit-Limit / -Remaining when readable (Node, or a service
 * that CORS-exposes them; browsers usually cannot read them).
 */
function captureRateHeaders(stats, headers) {
  if (!stats || !headers) return;
  const limit = headerInt(headers, 'x-ratelimit-limit');
  const remaining = headerInt(headers, 'x-ratelimit-remaining');
  if (limit !== null || remaining !== null) stats.rate = { limit, remaining };
}

/**
 * Quota info for a result: `limited` when the service refused the request.
 * @returns {SourceQuota|null}
 */
function buildQuota(id, { limited = false, err = null, rate = null } = {}) {
  if (!limited && !rate) return null;
  const policy = QUOTA_POLICY[id] || DEFAULT_QUOTA_POLICY;
  const retryAfterMs = err && Number.isFinite(err.retryAfterMs) && err.retryAfterMs >= 0 ? err.retryAfterMs : null;
  return {
    limited: !!limited,
    period: policy.period,
    retryAfterMs,
    resetAt: retryAfterMs !== null ? new Date(Date.now() + retryAfterMs) : null,
    limit: rate ? rate.limit : null,
    remaining: rate ? rate.remaining : null,
    resetHint: limited ? policy.resetHint : null,
    hintKey: limited ? policy.hintKey : null
  };
}

/** Exponential backoff with ±25 % jitter: base·2^n, capped. */
function backoffMs(base, n, cap) {
  const exp = Math.min(cap, base * 2 ** n);
  return Math.max(0, Math.round(exp * (0.75 + Math.random() * 0.5)));
}

/** Transient failures worth retrying: 5xx, 429, timeouts and network (CORS-less error page) errors. */
function isTransient(err) {
  return err instanceof TimeoutError || err instanceof TypeError
    || (err instanceof HttpError && (err.status >= 500 || err.status === 429));
}

/**
 * Dates from the sources: 'YYYY-MM-DDTHH:MM:SS[.fff]' without a zone are UTC
 * (crt.sh, OTX); strings with Z / an offset are parsed as-is.
 * @returns {Date|null}
 */
function parseUtcDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value !== 'string' || !value.trim()) return null;
  let s = value.trim().replace(' ', 'T');
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) s += 'T00:00:00';
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z';
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : new Date(t);
}

/** Lowercase hex without separators and leading 00 bytes ('00' for zero). */
function normalizeSerial(value) {
  if (value === null || value === undefined) return null;
  let hex = String(value).toLowerCase().replace(/[^0-9a-f]/g, '');
  if (!hex) return null;
  if (hex.length % 2) hex = `0${hex}`;
  while (hex.length > 2 && hex.startsWith('00')) hex = hex.slice(2);
  return hex;
}

/** First useful line of an HTTP error body (JSON message/detail or plain text). */
function errorMessage(err) {
  if (!err) return 'Unknown error';
  if (err instanceof HttpError) {
    let detail = '';
    const body = (err.body || '').trim();
    if (body) {
      try {
        const j = JSON.parse(body);
        detail = j && typeof j === 'object' ? j.message || j.detail || j.error || '' : '';
      } catch {
        detail = body.startsWith('<') ? '' : body.split(/\r?\n/)[0];
      }
    }
    detail = String(detail).replace(/\s+/g, ' ').trim().slice(0, 200);
    return detail ? `${err.message}: ${detail}` : err.message;
  }
  return String(err.message || err).slice(0, 300);
}

/** Race a body read against a signal. */
function raceSignal(promise, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(abortReasonToError(signal.reason));
      return;
    }
    const onAbort = () => reject(abortReasonToError(signal.reason));
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (v) => { signal.removeEventListener('abort', onAbort); resolve(v); },
      (e) => { signal.removeEventListener('abort', onAbort); reject(e); }
    );
  });
}

/**
 * Fetch a URL as JSON or text with one timer covering headers and body.
 * Non-2xx → HttpError (body snippet, Retry-After); bad JSON → ParseError.
 * `body` + `contentType` send a POST (keep the type CORS-safelisted, e.g.
 * text/plain, so browsers skip the preflight). Counts requests and captures
 * readable rate-limit headers in `stats`.
 * @returns {Promise<{ data: any, headers: Headers|null }>}
 */
async function request(url, {
  fetchImpl, signal, timeoutMs, as = 'json', method = 'GET', body, contentType, stats
}) {
  const timeoutCtl = new AbortController();
  const timer = setTimeout(() => {
    timeoutCtl.abort(new TimeoutError(`No response within ${Math.round(timeoutMs / 1000)} s`, { timeoutMs }));
  }, timeoutMs);
  const linked = signal ? mergeSignals(signal, timeoutCtl.signal) : timeoutCtl.signal;
  if (stats) stats.attempts += 1;
  try {
    const reqHeaders = { accept: as === 'json' ? 'application/json' : 'text/plain, */*' };
    if (contentType) reqHeaders['content-type'] = contentType;
    const res = await fetchWithTimeout(url, {
      fetchImpl,
      signal: linked,
      timeoutMs: 0,
      method,
      headers: reqHeaders,
      ...(body !== undefined ? { body } : {}),
      credentials: 'omit',
      referrerPolicy: 'no-referrer'
    });
    const headers = res.headers && typeof res.headers.get === 'function' ? res.headers : null;
    captureRateHeaders(stats, headers);
    if (!res.ok) {
      let body = '';
      try {
        body = String(await raceSignal(res.text(), linked)).slice(0, 500);
      } catch (err) {
        if (linked.aborted) throw err;
      }
      throw new HttpError(res.status, url, body, {
        statusText: res.statusText || '',
        retryAfterMs: headers ? parseRetryAfter(headers.get('retry-after')) : null
      });
    }
    const text = String(await raceSignal(res.text(), linked));
    if (as === 'text') return { data: text, headers };
    try {
      return { data: JSON.parse(text), headers };
    } catch (err) {
      const snippet = text.trim().slice(0, 80).replace(/\s+/g, ' ');
      throw new ParseError(`Invalid JSON response${snippet ? ` ("${snippet}")` : ''}`, { cause: err, body: text });
    }
  } catch (err) {
    if (signal && signal.aborted) throw toAbortError(signal.reason);
    if (timeoutCtl.signal.aborted) {
      throw err instanceof TimeoutError ? err : new TimeoutError(`No response within ${Math.round(timeoutMs / 1000)} s`, { cause: err, timeoutMs });
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Collects names for one queried domain: normalizes (IDN → punycode,
 * lowercase), rejects e-mail addresses / free text / IPs, keeps only the
 * domain itself and its subdomains, and records wildcard bases.
 */
function createCollector(domain) {
  const names = new Set();
  const bases = new Set();
  return {
    /**
     * @param {unknown} raw
     * @returns {{ name: string, base: string, wildcard: boolean, inScope: boolean }|null}
     */
    add(raw) {
      const n = normalizeName(raw);
      if (!n) return null;
      const { base, wildcard } = stripWildcard(n);
      const inScope = isSubdomainOf(base, domain);
      if (inScope) {
        names.add(base);
        if (wildcard) bases.add(base);
      }
      return { name: n, base, wildcard, inScope };
    },
    result() {
      return { names: sortHostnames([...names]), wildcardBases: sortHostnames([...bases]) };
    }
  };
}

function normalizeName(raw) {
  if (typeof raw !== 'string') return null;
  let s = raw.trim();
  if (!s || s.includes('@') || /\s/.test(s)) return null;
  // Wildcard spellings seen in passive datasets: '.x.com', '**.x.com', '*.*.x.com' → '*.x.com'.
  const lead = /^(?:\*+\.|\.)+(?=[^.*])/.exec(s);
  if (lead) s = `*.${s.slice(lead[0].length)}`;
  return normalizeHostname(s, { allowWildcard: true });
}

/** Add/merge an IP hint (keeps the widest firstSeen/lastSeen window). */
function addHint(map, name, ip, source, firstSeen = null, lastSeen = null) {
  const key = `${name}|${ip}`;
  const prev = map.get(key);
  if (!prev) {
    const hint = { name, ip, source };
    if (firstSeen) hint.firstSeen = firstSeen;
    if (lastSeen) hint.lastSeen = lastSeen;
    map.set(key, hint);
    return;
  }
  if (firstSeen && (!prev.firstSeen || firstSeen < prev.firstSeen)) prev.firstSeen = firstSeen;
  if (lastSeen && (!prev.lastSeen || lastSeen > prev.lastSeen)) prev.lastSeen = lastSeen;
}

function sortHints(hints) {
  const order = new Map(sortHostnames([...new Set(hints.map((h) => h.name))]).map((n, i) => [n, i]));
  return hints.sort((a, b) => order.get(a.name) - order.get(b.name) || (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0));
}

function sortCerts(certs) {
  const t = (d) => (d instanceof Date ? d.getTime() : -Infinity);
  return certs.sort((a, b) => t(b.notBefore) - t(a.notBefore) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

/* ------------------------------------------------------------------------ */
/* Source implementations                                                   */
/* ------------------------------------------------------------------------ */

/**
 * crt.sh query forms. 'history' and 'subdomains' are the LIKE search
 * `%.domain` (with / without expired certificates); 'identity' is the plain
 * `q=domain` identity search, a different (lighter) database path used once as
 * the last resort. `deduplicate=Y` drops precertificate/leaf duplicates.
 */
const CRTSH_FORMS = Object.freeze({
  history: { q: (d) => `%.${d}`, expired: true, label: 'subdomain search with expired certificates' },
  subdomains: { q: (d) => `%.${d}`, expired: false, label: 'subdomain search' },
  identity: { q: (d) => d, expired: false, label: 'identity search' }
});

function crtshUrl(domain, form) {
  const f = CRTSH_FORMS[form];
  return `https://crt.sh/?q=${encodeURIComponent(f.q(domain))}&output=json${f.expired ? '' : '&exclude=expired'}&deduplicate=Y`;
}

/**
 * Attempt plan: the main form CRTSH_ATTEMPTS times (with includeExpired: the
 * full history first, then the lighter unexpired search), then the identity
 * search once.
 * @returns {Array<'history'|'subdomains'|'identity'>}
 */
function crtshPlan(includeExpired) {
  const main = includeExpired
    ? [...Array(Math.ceil(CRTSH_ATTEMPTS / 2)).fill('history'), ...Array(Math.floor(CRTSH_ATTEMPTS / 2)).fill('subdomains')]
    : Array(CRTSH_ATTEMPTS).fill('subdomains');
  return [...main, 'identity'];
}

/**
 * One failed crt.sh attempt. crt.sh's proxy answers overload with HTTP
 * 502/503 pages that carry no CORS header, which browsers report as a network
 * TypeError ("Failed to fetch") — so network errors count as 'unavailable'.
 */
function crtshFailure(form, err) {
  if (err instanceof TimeoutError) return { form, kind: 'timeout', label: 'timed out', retryAfterMs: null };
  if (err instanceof HttpError) {
    return { form, kind: err.status === 429 ? 'rate-limit' : 'unavailable', label: `HTTP ${err.status}`, retryAfterMs: err.retryAfterMs };
  }
  return { form, kind: 'unavailable', label: 'network error', retryAfterMs: null, network: true };
}

/** 'HTTP 502 ×3, network error' */
function summarizeFailures(failures) {
  const counts = new Map();
  for (const f of failures) counts.set(f.label, (counts.get(f.label) || 0) + 1);
  return [...counts].map(([label, n]) => (n > 1 ? `${label} ×${n}` : label)).join(', ');
}

/** All timeouts → 'timeout'; all 429 → 'rate-limit'; otherwise the service is 'unavailable'. */
function failuresKind(failures) {
  if (failures.length && failures.every((f) => f.kind === 'timeout')) return 'timeout';
  if (failures.length && failures.every((f) => f.kind === 'rate-limit')) return 'rate-limit';
  return 'unavailable';
}

function crtshFinalError(failures, elapsedMs, timeoutMs) {
  const kind = failuresKind(failures);
  const n = failures.length;
  const tries = `${n} attempt${n === 1 ? '' : 's'}`;
  const last = failures[n - 1] || {};
  if (kind === 'timeout') {
    const forms = [...new Set(failures.map((f) => CRTSH_FORMS[f.form].label))].join(', ');
    return sourceError(`crt.sh timed out: no response within ${Math.round(timeoutMs / 1000)} s (${tries}: ${forms}). `
      + 'Very large domains can be too slow for crt.sh; Cert Spotter still covers unexpired certificates.', 'timeout', { failures });
  }
  if (kind === 'rate-limit') {
    return sourceError(`crt.sh rate limit (${summarizeFailures(failures)}).`, 'rate-limit',
      { failures, retryAfterMs: last.retryAfterMs ?? null });
  }
  const cors = failures.some((f) => f.network)
    ? ' Its error pages carry no CORS header, so browsers only see a network error.'
    : '';
  return sourceError(`crt.sh is temporarily unavailable: ${tries} over ${Math.round(elapsedMs / 1000)} s failed `
    + `(${summarizeFailures(failures)}).${cors}`, 'unavailable', { failures });
}

/**
 * crt.sh: CT log search. Transient failures (5xx, 429, CORS-less error pages
 * seen as network errors) are retried with exponential backoff + jitter —
 * CRTSH_ATTEMPTS tries of the main query, then the identity search once (≈60 s
 * of waiting in total, abortable). A timed-out query form is not repeated (a
 * heavy query that timed out would time out again). With `includeExpired`,
 * the full history is tried first and the unexpired search is the fallback
 * (result marked partial).
 */
async function fromCrtsh(domain, ctx) {
  const plan = crtshPlan(ctx.includeExpired);
  const base = Number.isFinite(ctx.retryDelayMs) && ctx.retryDelayMs >= 0 ? ctx.retryDelayMs : CRTSH_BASE_DELAY_MS;
  const failures = [];
  const timedOut = new Set();
  let waits = 0;
  // Overall budget (request time + scheduled waits): room for two full
  // timeouts, at least CRTSH_BUDGET_MS. No attempt starts beyond it.
  const budget = Math.max(CRTSH_BUDGET_MS, 2 * ctx.timeoutMs);
  let spent = 0;
  for (const [index, form] of plan.entries()) {
    if (timedOut.has(form)) continue;
    if (failures.length) {
      const last = failures[failures.length - 1];
      const delayMs = Number.isFinite(last.retryAfterMs) ? last.retryAfterMs : backoffMs(base, waits, CRTSH_MAX_DELAY_MS);
      if (spent + delayMs > budget) break;
      waits += 1;
      // Upper bound from here on: timed-out forms are skipped, so fewer than plan.length remain.
      const maxAttempts = ctx.stats.attempts + plan.slice(index).filter((f) => !timedOut.has(f)).length;
      ctx.emit({ type: 'retry', attempt: ctx.stats.attempts + 1, maxAttempts, form, delayMs, reason: last.label });
      await ctx.sleep(delayMs, ctx.signal);
      spent += delayMs;
      checkAbort(ctx.signal);
    }
    let data;
    const requestStarted = clock();
    try {
      ({ data } = await request(crtshUrl(domain, form), { ...ctx, as: 'json' }));
    } catch (err) {
      spent += clock() - requestStarted;
      if (ctx.signal && ctx.signal.aborted) throw toAbortError(ctx.signal.reason);
      // crt.sh never 404s a valid query ("no results" is `[]`), but while it
      // flaps its Apache backend answers "404 Not Found" pages (probed
      // 2026-09-23, without CORS headers) → same as a 5xx.
      const backendFault = err instanceof HttpError && err.status === 404;
      if (!isTransient(err) && !backendFault) throw err;
      const failure = crtshFailure(form, err);
      failures.push(failure);
      if (failure.kind === 'rate-limit' && failure.retryAfterMs !== null && failure.retryAfterMs > CRTSH_MAX_RETRY_AFTER_MS) {
        throw sourceError(`crt.sh rate limit (${errorMessage(err)})`, 'rate-limit', { failures, retryAfterMs: failure.retryAfterMs });
      }
      if (failure.kind === 'timeout') timedOut.add(form);
      continue;
    }
    return parseCrtsh(domain, data, form, failures, ctx.includeExpired);
  }
  throw crtshFinalError(failures, spent, ctx.timeoutMs);
}

/** crt.sh rows → names + certificates (one row per log entry → de-duplicated per certificate). */
function parseCrtsh(domain, data, form, failures, includeExpired) {
  let partialError = null;
  if (failures.length && form === 'identity') {
    partialError = sourceError(`crt.sh subdomain search failed (${summarizeFailures(failures)}); these results come from `
      + 'the lighter identity search, which can miss names.', failuresKind(failures));
  } else if (failures.length && includeExpired && form === 'subdomains') {
    partialError = sourceError(`Expired certificates omitted: the full crt.sh history failed (${summarizeFailures(failures)})`,
      failuresKind(failures));
  }
  if (data === null) {
    return { rows: 0, certs: [], hints: [], collector: createCollector(domain), partialError, queryForm: form };
  }
  if (!Array.isArray(data)) throw new ParseError('Unexpected crt.sh response (expected a JSON array)');
  const collector = createCollector(domain);
  const certs = new Map();
  for (const row of data) {
    if (!row || typeof row !== 'object') continue;
    const certNames = new Set();
    const values = [
      ...(typeof row.name_value === 'string' ? row.name_value.split(/\r?\n/) : []),
      row.common_name
    ];
    for (const v of values) {
      const hit = collector.add(v);
      if (hit) certNames.add(hit.name);
    }
    const serialHex = normalizeSerial(row.serial_number);
    const issuerId = row.issuer_ca_id ?? row.issuer_name ?? '';
    const key = serialHex ? `crtsh:${issuerId}:${serialHex}` : `crtsh:id:${row.id}`;
    const existing = certs.get(key);
    if (existing) {
      for (const n of certNames) existing.nameSet.add(n);
      if (row.id !== undefined && !existing.ids.includes(row.id)) existing.ids.push(row.id);
      continue;
    }
    certs.set(key, {
      key,
      source: 'crtsh',
      id: row.id ?? null,
      serialHex,
      issuer: typeof row.issuer_name === 'string' ? row.issuer_name : '',
      notBefore: parseUtcDate(row.not_before),
      notAfter: parseUtcDate(row.not_after),
      names: [],
      sha256: null,
      sources: ['crtsh'],
      url: row.id !== undefined && row.id !== null ? `https://crt.sh/?id=${encodeURIComponent(row.id)}` : null,
      ids: row.id !== undefined && row.id !== null ? [row.id] : [],
      issuerCaId: row.issuer_ca_id ?? null,
      commonName: typeof row.common_name === 'string' ? row.common_name : null,
      nameSet: certNames
    });
  }
  const list = [...certs.values()].map(({ nameSet, ...c }) => ({ ...c, names: sortHostnames([...nameSet]) }));
  return { rows: data.length, certs: list, hints: [], collector, partialError, queryForm: form };
}

/** Cert Spotter issuances API, paginated with `after=<last id>` (max 5 pages; a full 5th page → `truncated`). */
async function fromCertspotter(domain, ctx) {
  const base = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}`
    + '&include_subdomains=true&expand=dns_names&expand=issuer';
  const collector = createCollector(domain);
  const certs = [];
  let rows = 0;
  let after = null;
  let partialError = null;
  let pages = 0;
  let truncated = false;
  for (let page = 0; page < MAX_CERTSPOTTER_PAGES; page += 1) {
    const url = after ? `${base}&after=${encodeURIComponent(after)}` : base;
    let data;
    let headers;
    try {
      ({ data, headers } = await request(url, { ...ctx, as: 'json' }));
    } catch (err) {
      if (page === 0 || (ctx.signal && ctx.signal.aborted)) throw err;
      partialError = err; // keep what we have (typically HTTP 429 on a later page)
      break;
    }
    pages += 1;
    if (!Array.isArray(data)) throw new ParseError('Unexpected Cert Spotter response (expected a JSON array)');
    rows += data.length;
    for (const item of data) {
      if (!item || typeof item !== 'object') continue;
      const names = new Set();
      for (const n of Array.isArray(item.dns_names) ? item.dns_names : []) {
        const hit = collector.add(n);
        if (hit) names.add(hit.name);
      }
      const sha = typeof item.cert_sha256 === 'string' ? item.cert_sha256.toLowerCase() : null;
      const tbs = typeof item.tbs_sha256 === 'string' ? item.tbs_sha256.toLowerCase() : null;
      const issuer = item.issuer && typeof item.issuer === 'object'
        ? String(item.issuer.name || item.issuer.friendly_name || '')
        : '';
      certs.push({
        key: sha ? `sha256:${sha}` : tbs ? `tbs:${tbs}` : `certspotter:${item.id}`,
        source: 'certspotter',
        id: item.id ?? null,
        serialHex: null,
        issuer,
        notBefore: parseUtcDate(item.not_before),
        notAfter: parseUtcDate(item.not_after),
        names: sortHostnames([...names]),
        sha256: sha,
        sources: ['certspotter'],
        url: null,
        issuerFriendlyName: item.issuer && typeof item.issuer === 'object' ? item.issuer.friendly_name || null : null,
        tbsSha256: tbs,
        pubkeySha256: typeof item.pubkey_sha256 === 'string' ? item.pubkey_sha256.toLowerCase() : null,
        revoked: typeof item.revoked === 'boolean' ? item.revoked : null
      });
    }
    if (!data.length) break;
    const last = data[data.length - 1];
    if (!last || last.id === undefined || last.id === null) break;
    after = String(last.id);
    // A readable Link header is authoritative (rel="next" ⇒ more pages).
    // Browsers cannot read it (Cert Spotter does not CORS-expose it), and an
    // absent header is indistinguishable from a hidden one, so without it we
    // continue until an empty page (at most MAX_CERTSPOTTER_PAGES requests).
    const link = headers ? headers.get('link') : null;
    if (typeof link === 'string' && link.trim() && !/rel="?next"?/i.test(link)) break;
    // A full last page under the cap: more issuances may exist (certain with a
    // readable rel="next"; without the header it cannot be told apart).
    if (page === MAX_CERTSPOTTER_PAGES - 1) truncated = true;
    // Readable X-RateLimit-Remaining: 0 (Node) → the next page would be a 429
    // (which may prolong the penalty): stop and report the quota instead.
    if (ctx.stats && ctx.stats.rate && ctx.stats.rate.remaining === 0 && page < MAX_CERTSPOTTER_PAGES - 1) {
      partialError = new RateLimitError('Cert Spotter hourly quota used up; later pages were skipped');
      break;
    }
  }
  const unique = new Map();
  for (const c of certs) if (!unique.has(c.key)) unique.set(c.key, c);
  return { rows, certs: [...unique.values()], hints: [], collector, partialError, pages, truncated };
}

const HACKERTARGET_QUOTA_RE = /api count exceeded|increase quota|too many requests/i;

/**
 * HackerTarget host search: "host,ip" lines. Quota exhaustion arrives as HTTP
 * 200 text ('API count exceeded - Increase Quota with Membership', probed
 * 2026-09-23) or occasionally as a non-2xx with the same text → RateLimitError
 * (never retried: the free quota is daily).
 */
async function fromHackertarget(domain, ctx) {
  const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
  let data;
  try {
    ({ data } = await request(url, { ...ctx, as: 'text' }));
  } catch (err) {
    if (err instanceof HttpError && HACKERTARGET_QUOTA_RE.test(err.body || '')) {
      throw new RateLimitError(`HackerTarget: ${String(err.body).trim().split(/\r?\n/)[0].slice(0, 200)}`,
        { retryAfterMs: err.retryAfterMs, cause: err });
    }
    throw err;
  }
  const text = String(data ?? '').replace(/^﻿/, '').trim();
  if (HACKERTARGET_QUOTA_RE.test(text)) {
    throw new RateLimitError(`HackerTarget: ${text.split(/\r?\n/)[0].slice(0, 200)}`);
  }
  if (/^error\b/i.test(text)) throw sourceError(`HackerTarget: ${text.split(/\r?\n/)[0].slice(0, 200)}`, 'http');
  const collector = createCollector(domain);
  const hints = new Map();
  if (!text || /^no records found/i.test(text)) return { rows: 0, certs: [], hints: [], collector };
  const lines = text.split(/\r?\n/);
  let parsed = 0;
  for (const line of lines) {
    const [host, ...rest] = line.split(',');
    const hit = collector.add(host);
    if (!hit) continue;
    parsed += 1;
    if (!hit.inScope) continue;
    for (const raw of rest) {
      const ip = normalizeIP(raw.trim());
      if (ip) addHint(hints, hit.base, ip, 'hackertarget');
    }
  }
  if (!parsed) {
    throw new ParseError(`Unexpected HackerTarget response ("${text.slice(0, 80).replace(/\s+/g, ' ')}")`, { body: text });
  }
  return { rows: lines.length, certs: [], hints: [...hints.values()], collector };
}

const RATE_LIMIT_TEXT_RE = /rate.?limit|too many|quota|throttl|anonymous access/i;

/** Message of a JSON error object ({ error | detail | message }), or ''. */
function jsonErrorText(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return '';
  const v = data.error ?? data.detail ?? data.message ?? '';
  return typeof v === 'string' ? v.replace(/\s+/g, ' ').trim().slice(0, 200) : '';
}

/**
 * Anubis DB: JSON array of names; `[]` (HTTP 200) means "nothing known", not
 * an error. A JSON error object is a service error (rate-limit when it says
 * so). 5xx / network errors are retried once (no quota to protect).
 */
async function fromAnubis(domain, ctx) {
  const url = `https://anubisdb.com/anubis/subdomains/${encodeURIComponent(domain)}`;
  let data;
  try {
    ({ data } = await request(url, { ...ctx, as: 'json' }));
  } catch (err) {
    const retryable = err instanceof TypeError || (err instanceof HttpError && err.status >= 500);
    if (!retryable || (ctx.signal && ctx.signal.aborted)) throw err;
    ctx.emit({ type: 'retry', attempt: ctx.stats.attempts + 1, maxAttempts: 2, delayMs: ANUBIS_RETRY_DELAY_MS,
      reason: err instanceof HttpError ? `HTTP ${err.status}` : 'network error' });
    await ctx.sleep(ANUBIS_RETRY_DELAY_MS, ctx.signal);
    checkAbort(ctx.signal);
    ({ data } = await request(url, { ...ctx, as: 'json' }));
  }
  const collector = createCollector(domain);
  if (data === null) return { rows: 0, certs: [], hints: [], collector };
  if (!Array.isArray(data)) {
    const msg = jsonErrorText(data);
    if (msg) throw sourceError(`Anubis: ${msg}`, RATE_LIMIT_TEXT_RE.test(msg) ? 'rate-limit' : 'http');
    throw new ParseError('Unexpected Anubis response (expected a JSON array)');
  }
  for (const n of data) collector.add(n);
  return { rows: data.length, certs: [], hints: [], collector };
}

/** 'YYYY-MM-DD' of a date-ish value, or null. */
function isoDay(value) {
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}/.test(value.trim())) return value.trim().slice(0, 10);
  const d = parseUtcDate(value);
  return d ? d.toISOString().slice(0, 10) : null;
}

/** Keep the most recent day per name. */
function noteSeen(map, name, day) {
  if (day && (!map[name] || day > map[name])) map[name] = day;
}

/**
 * AlienVault OTX passive DNS: historical A/AAAA records are origin hints.
 * Anonymous access is often refused with HTTP 429 `{"detail": "Anonymous
 * access to this endpoint is limited…"}` (probed 2026-09-23) → rate-limit.
 */
async function fromOtx(domain, ctx) {
  const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`;
  const { data } = await request(url, { ...ctx, as: 'json' });
  if (!data || typeof data !== 'object' || !Array.isArray(data.passive_dns)) {
    const msg = jsonErrorText(data);
    if (msg && RATE_LIMIT_TEXT_RE.test(msg)) throw new RateLimitError(`OTX: ${msg}`);
    throw new ParseError(`Unexpected OTX response (no passive_dns array)${msg ? `: ${msg}` : ''}`);
  }
  const collector = createCollector(domain);
  const hints = new Map();
  const lastSeen = {};
  for (const row of data.passive_dns) {
    if (!row || typeof row !== 'object') continue;
    const hit = collector.add(row.hostname);
    const type = String(row.record_type || '').toUpperCase();
    if (type === 'CNAME') collector.add(row.address); // an alias target inside the domain is a name too
    if (hit && hit.inScope) noteSeen(lastSeen, hit.base, isoDay(row.last));
    if (!hit || !hit.inScope || (type !== 'A' && type !== 'AAAA')) continue;
    const ip = normalizeIP(String(row.address ?? ''));
    if (ip) addHint(hints, hit.base, ip, 'otx', parseUtcDate(row.first), parseUtcDate(row.last));
  }
  return { rows: data.passive_dns.length, certs: [], hints: [...hints.values()], collector, lastSeen };
}

/**
 * ip.thc.org subdomain lookup (verified 2026-09-23): POST with a text/plain
 * JSON body (CORS-safelisted → no preflight), ACAO *, `limit` capped at 100,
 * paginated with `next_page_state` ('' on the last page). Its token bucket
 * (~250 requests, refilling 1 every 2 s) is respected by spacing pages
 * THC_PAGE_SPACING_MS apart and stopping after THC_MAX_PAGES (→ `truncated`).
 * Returns `last_seen_on` per name. A later page failing keeps earlier pages.
 */
async function fromThc(domain, ctx) {
  const collector = createCollector(domain);
  const lastSeen = {};
  let pageState = '';
  let rows = 0;
  let pages = 0;
  let available = null;
  let truncated = false;
  let partialError = null;
  for (let page = 0; page < THC_MAX_PAGES; page += 1) {
    if (page > 0) {
      ctx.emit({ type: 'page', page: page + 1, maxPages: THC_MAX_PAGES, delayMs: THC_PAGE_SPACING_MS, available });
      await ctx.sleep(THC_PAGE_SPACING_MS, ctx.signal);
      checkAbort(ctx.signal);
    }
    const payload = { domain, limit: THC_PAGE_SIZE };
    if (pageState) payload.page_state = pageState;
    let data;
    try {
      ({ data } = await request(THC_URL, {
        ...ctx, as: 'json', method: 'POST', body: JSON.stringify(payload), contentType: 'text/plain;charset=UTF-8'
      }));
      if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new ParseError('Unexpected ip.thc.org response (expected a JSON object)');
      }
      const failed = data.status === 'error' || (!('domains' in data) && !!data.error);
      const msg = failed ? jsonErrorText(data) || 'error' : '';
      if (msg) throw sourceError(`ip.thc.org: ${msg}`, RATE_LIMIT_TEXT_RE.test(msg) ? 'rate-limit' : 'http');
      if (data.domains !== null && data.domains !== undefined && !Array.isArray(data.domains)) {
        throw new ParseError('Unexpected ip.thc.org response (domains is not an array)');
      }
    } catch (err) {
      if (page === 0 || (ctx.signal && ctx.signal.aborted)) throw err;
      partialError = err; // keep earlier pages (typically HTTP 429 or a timeout)
      break;
    }
    const list = Array.isArray(data.domains) ? data.domains : [];
    pages += 1;
    rows += list.length;
    if (Number.isFinite(data.matching_records)) available = data.matching_records;
    for (const item of list) {
      const raw = item && typeof item === 'object' ? item.domain : item;
      const hit = collector.add(raw);
      if (hit && hit.inScope && item && typeof item === 'object') noteSeen(lastSeen, hit.base, isoDay(item.last_seen_on));
    }
    pageState = typeof data.next_page_state === 'string' ? data.next_page_state : '';
    if (!pageState || !list.length) break;
    if (page === THC_MAX_PAGES - 1) truncated = true;
  }
  return { rows, certs: [], hints: [], collector, partialError, pages, lastSeen, available, truncated };
}

const FETCHERS = {
  crtsh: fromCrtsh,
  certspotter: fromCertspotter,
  hackertarget: fromHackertarget,
  anubis: fromAnubis,
  otx: fromOtx,
  thc: fromThc
};

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

/**
 * Query one passive source for a domain.
 *
 * @param {string} id source id (see SOURCES)
 * @param {string} domain e.g. 'example.com.tr' (URLs / IDNs are normalized)
 * @param {object} [opts]
 * @param {typeof fetch} [opts.fetchImpl=globalThis.fetch]
 * @param {AbortSignal} [opts.signal]
 * @param {number} [opts.timeoutMs] per-request timeout (default: crt.sh 90 s, others 25 s)
 * @param {boolean} [opts.includeExpired=false] crt.sh: include expired certificates
 * @param {number} [opts.retryDelayMs] extension: crt.sh retry backoff base (default 4000 ms:
 *   waits of ≈4, 8, 16 and 32 s ±25 % between its 5 attempts)
 * @param {(ms: number, signal?: AbortSignal) => Promise<void>} [opts.sleepImpl] extension: waiting
 *   used for backoff and page spacing (default util.sleep; must reject when `signal` aborts)
 * @param {(ev: { source: string, domain: string, type: 'retry'|'page', attempt?: number,
 *   maxAttempts?: number, page?: number, maxPages?: number, delayMs: number, reason?: string,
 *   form?: string }) => void} [opts.onEvent] extension: progress while a source retries / pages
 * @returns {Promise<SourceResult>} never rejects except with AbortError
 */
export async function fetchSource(id, domain, {
  fetchImpl = globalThis.fetch, signal, timeoutMs, includeExpired = false, retryDelayMs, sleepImpl, onEvent
} = {}) {
  checkAbort(signal);
  const started = clock();
  const def = SOURCES.find((s) => s.id === id);
  const d = normalizeHostname(typeof domain === 'string' ? domain : '', { allowWildcard: true });
  const base = d ? stripWildcard(d).base : null;
  const result = {
    source: String(id),
    ok: false,
    names: [],
    wildcardBases: [],
    ipHints: [],
    certs: [],
    error: null,
    errorKind: null,
    elapsedMs: 0,
    domain: base,
    partial: false,
    rows: 0,
    attempts: 0,
    quota: null,
    lastSeen: {},
    truncated: false,
    available: null,
    queryForm: null
  };
  const finish = () => {
    result.elapsedMs = Math.round(clock() - started);
    return result;
  };
  if (!def) {
    result.error = `Unknown source "${id}"`;
    result.errorKind = 'unknown';
    return finish();
  }
  if (!base) {
    result.error = `Invalid domain "${domain}"`;
    result.errorKind = 'unknown';
    return finish();
  }
  const stats = { attempts: 0, rate: null };
  const ctx = {
    fetchImpl,
    signal,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : def.timeoutMs,
    includeExpired: !!includeExpired,
    retryDelayMs,
    stats,
    sleep: typeof sleepImpl === 'function' ? sleepImpl : sleep,
    emit: (ev) => {
      if (typeof onEvent !== 'function') return;
      try {
        onEvent({ source: def.id, domain: base, ...ev });
      } catch {
        /* observer errors never break the fetch */
      }
    }
  };
  try {
    const out = await FETCHERS[id](base, ctx);
    const { names, wildcardBases } = out.collector.result();
    result.ok = true;
    result.names = names;
    result.wildcardBases = wildcardBases;
    result.ipHints = sortHints(out.hints);
    result.certs = sortCerts(out.certs);
    result.rows = out.rows;
    if (out.lastSeen) {
      const seen = {};
      for (const n of sortHostnames(Object.keys(out.lastSeen))) seen[n] = out.lastSeen[n];
      result.lastSeen = seen;
    }
    result.truncated = !!out.truncated;
    result.available = Number.isFinite(out.available) ? out.available : null;
    result.queryForm = out.queryForm || null;
    if (out.partialError) {
      result.partial = true;
      result.error = out.partialError.name === 'SourceError'
        ? out.partialError.message
        : `Incomplete: ${errorMessage(out.partialError)}`;
      result.errorKind = kindOf(out.partialError);
    }
    const limited = result.errorKind === 'rate-limit';
    result.quota = buildQuota(def.id, { limited, err: limited ? out.partialError : null, rate: stats.rate });
  } catch (err) {
    if (signal && signal.aborted) throw toAbortError(signal.reason);
    result.error = errorMessage(err);
    result.errorKind = kindOf(err);
    const limited = result.errorKind === 'rate-limit';
    result.quota = buildQuota(def.id, { limited, err: limited ? err : null, rate: stats.rate });
  }
  result.attempts = stats.attempts;
  return finish();
}

/** Signature used to spot the same certificate reported by crt.sh and Cert Spotter. */
function certSignature(c) {
  const t = (d) => (d instanceof Date ? d.getTime() : 'x');
  return `${t(c.notBefore)}|${t(c.notAfter)}|${c.names.join(',')}`;
}

/**
 * Merge certificates from several results: exact key duplicates are dropped
 * and a Cert Spotter issuance matching a crt.sh certificate (same validity and
 * names) is folded into it (adding its SHA-256 and source).
 * @param {CtCert[]} list
 * @returns {CtCert[]} newest first
 */
export function mergeCerts(list) {
  const byKey = new Map();
  const bySig = new Map();
  for (const cert of Array.isArray(list) ? list : []) {
    if (!cert || typeof cert.key !== 'string') continue;
    const prev = byKey.get(cert.key);
    if (prev) {
      for (const s of cert.sources || [cert.source]) if (!prev.sources.includes(s)) prev.sources.push(s);
      continue;
    }
    const sig = certSignature(cert);
    const twin = bySig.get(sig);
    if (twin && twin.source !== cert.source) {
      if (!twin.sha256 && cert.sha256) twin.sha256 = cert.sha256;
      if (!twin.serialHex && cert.serialHex) twin.serialHex = cert.serialHex;
      for (const s of cert.sources || [cert.source]) if (!twin.sources.includes(s)) twin.sources.push(s);
      byKey.set(cert.key, twin);
      continue;
    }
    const copy = { ...cert, sources: [...(cert.sources || [cert.source])] };
    byKey.set(cert.key, copy);
    if (!bySig.has(sig)) bySig.set(sig, copy);
  }
  return sortCerts([...new Set(byKey.values())]);
}

/**
 * Query several sources in parallel for one domain.
 *
 * @param {string} domain
 * @param {object} [opts]
 * @param {string[]} [opts.sources] ids (default: every `defaultEnabled` source)
 * @param {(r: SourceResult) => void} [opts.onResult] called as each source finishes
 * @param {typeof fetch} [opts.fetchImpl]
 * @param {AbortSignal} [opts.signal]
 * @param {boolean} [opts.includeExpired=false]
 * @param {number} [opts.timeoutMs] extension: override every source's timeout
 * @param {number} [opts.retryDelayMs] extension: see fetchSource
 * @param {Function} [opts.sleepImpl] extension: see fetchSource
 * @param {Function} [opts.onEvent] extension: see fetchSource (retry / page progress)
 * @returns {Promise<{ results: SourceResult[], names: Map<string, Set<string>>, ipHints: IpHint[],
 *   certs: CtCert[], wildcardBases: string[], lastSeen: Object<string, string>,
 *   health: SourceHealth[] }>} `results` in `sources` order; `names` maps each name to the ids
 *   of the sources that reported it (sorted by name); `lastSeen` merges every source's
 *   (latest day wins); `health` = sourceHealthSummary(results). Rejects only with AbortError.
 */
export async function fetchAllSources(domain, {
  sources, onResult, fetchImpl = globalThis.fetch, signal, includeExpired = false, timeoutMs, retryDelayMs,
  sleepImpl, onEvent
} = {}) {
  checkAbort(signal);
  const ids = Array.isArray(sources) ? [...new Set(sources)] : SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
  const results = await Promise.all(ids.map(async (id) => {
    const r = await fetchSource(id, domain, { fetchImpl, signal, includeExpired, timeoutMs, retryDelayMs, sleepImpl, onEvent });
    if (typeof onResult === 'function') {
      try {
        onResult(r);
      } catch {
        /* observer errors never break the fetch */
      }
    }
    return r;
  }));
  checkAbort(signal);

  const nameSources = new Map();
  const hints = new Map();
  const bases = new Set();
  const seen = {};
  for (const r of results) {
    for (const n of r.names) {
      if (!nameSources.has(n)) nameSources.set(n, new Set());
      nameSources.get(n).add(r.source);
    }
    for (const b of r.wildcardBases) bases.add(b);
    for (const h of r.ipHints) {
      const key = `${h.source}|${h.name}|${h.ip}`;
      if (!hints.has(key)) hints.set(key, h);
    }
    for (const [n, day] of Object.entries(r.lastSeen || {})) noteSeen(seen, n, day);
  }
  const names = new Map(sortHostnames([...nameSources.keys()]).map((n) => [n, nameSources.get(n)]));
  const lastSeen = {};
  for (const n of sortHostnames(Object.keys(seen))) lastSeen[n] = seen[n];
  return {
    results,
    names,
    ipHints: sortHints([...hints.values()]),
    certs: mergeCerts(results.flatMap((r) => r.certs)),
    wildcardBases: sortHostnames([...bases]),
    lastSeen,
    health: sourceHealthSummary(results)
  };
}

/** States reported by sourceHealthSummary(), best first. */
export const SOURCE_HEALTH_STATES = Object.freeze(['ok', 'empty', 'partial', 'rate-limited', 'unavailable', 'timeout', 'error']);

const OK_STATES = new Set(['ok', 'empty', 'partial']);
/** Most informative failure first when a source failed differently for several domains. */
const FAIL_PRIORITY = ['rate-limited', 'unavailable', 'timeout', 'error'];
/** CT twins: when one fails, the other still provides certificate data. */
const CT_TWIN = Object.freeze({ crtsh: 'certspotter', certspotter: 'crtsh' });

/** @returns {'ok'|'empty'|'partial'|'rate-limited'|'unavailable'|'timeout'|'error'} */
function resultState(r) {
  if (r.ok) {
    if (r.partial) return 'partial';
    return (r.names?.length || r.certs?.length || r.ipHints?.length) ? 'ok' : 'empty';
  }
  if (r.errorKind === 'rate-limit') return 'rate-limited';
  if (r.errorKind === 'unavailable') return 'unavailable';
  if (r.errorKind === 'timeout') return 'timeout';
  return 'error';
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/**
 * @typedef {object} SourceHealth
 * @property {string} source id
 * @property {string} name display name
 * @property {string|null} homepage
 * @property {'ok'|'empty'|'partial'|'rate-limited'|'unavailable'|'timeout'|'error'} state
 *   aggregated over domains ('partial' when it worked for some domains only)
 * @property {boolean} ok at least one domain returned data or a clean empty answer
 * @property {number} names unique names over all domains
 * @property {number} ipHints
 * @property {number} certs
 * @property {number} elapsedMs slowest domain
 * @property {number} attempts HTTP requests over all domains
 * @property {string|null} errorKind first failure's kind
 * @property {string|null} error first failure's message
 * @property {SourceQuota|null} quota a limited quota first, else any readable one
 * @property {boolean} truncated
 * @property {number|null} available total records the source reported (summed)
 * @property {string|null} fallback CT twin id whose data replaced this failed source (crtsh ↔ certspotter)
 * @property {string} message short English status line (UIs localize from `state` + fields)
 * @property {Array<{ domain: string|null, state: string, names: number, errorKind: string|null, error: string|null }>} domains
 */

/**
 * Compact per-source status list for UIs and CLIs (in SOURCES order, unknown
 * ids after). Accepts SourceResult[] (any number of domains) or a
 * fetchAllSources() output.
 * @param {SourceResult[]|{ results: SourceResult[] }} results
 * @returns {SourceHealth[]}
 */
export function sourceHealthSummary(results) {
  const list = Array.isArray(results) ? results : Array.isArray(results?.results) ? results.results : [];
  const groups = new Map();
  for (const r of list) {
    if (!r || typeof r !== 'object' || typeof r.source !== 'string') continue;
    if (!groups.has(r.source)) groups.set(r.source, []);
    groups.get(r.source).push(r);
  }
  const order = [...SOURCES.map((s) => s.id).filter((id) => groups.has(id)),
    ...[...groups.keys()].filter((id) => !SOURCES.some((s) => s.id === id))];
  const okDomains = (id) => new Set((groups.get(id) || []).filter((r) => r.ok).map((r) => r.domain));
  return order.map((id) => {
    const rs = groups.get(id);
    const def = SOURCES.find((s) => s.id === id);
    const name = def ? def.name : id;
    const states = rs.map(resultState);
    const okCount = states.filter((s) => OK_STATES.has(s)).length;
    let state;
    if (okCount === states.length) {
      state = states.includes('partial') ? 'partial' : states.includes('ok') ? 'ok' : 'empty';
    } else if (okCount) {
      state = 'partial';
    } else {
      state = FAIL_PRIORITY.find((s) => states.includes(s)) || 'error';
    }
    const failed = rs.filter((r) => !r.ok || r.partial);
    const firstFail = failed.find((r) => !r.ok) || failed[0] || null;
    const quotas = rs.map((r) => r.quota).filter(Boolean);
    const quota = quotas.find((q) => q.limited) || quotas[0] || null;
    const uniqueNames = new Set(rs.flatMap((r) => r.names || []));
    const twin = CT_TWIN[id];
    let fallback = null;
    if (twin && groups.has(twin)) {
      const twinOk = okDomains(twin);
      if (rs.some((r) => !r.ok && twinOk.has(r.domain))) fallback = twin;
    }
    const twinName = fallback ? (SOURCES.find((s) => s.id === fallback) || { name: fallback }).name : '';
    const also = fallback ? `; ${twinName} was used for certificate data` : '';
    const errText = firstFail && firstFail.error ? firstFail.error : 'failed';
    const found = [plural(uniqueNames.size, 'name')];
    const ipCount = rs.reduce((a, r) => a + (r.ipHints?.length || 0), 0);
    if (ipCount) found.push(plural(ipCount, 'IP hint'));
    let message;
    switch (state) {
      case 'ok': message = found.join(', ') + (rs.some((r) => r.truncated) ? ' (page limit reached)' : ''); break;
      case 'empty': message = 'No names found'; break;
      case 'partial': message = `${found.join(', ')} (incomplete: ${errText})`; break;
      case 'rate-limited': message = `${name}: ${(quota && quota.resetHint) || errText}`; break;
      case 'unavailable': message = `${name} is temporarily down${also}`; break;
      case 'timeout': message = `${name} timed out${also}`; break;
      default: message = `${errText}${also}`;
    }
    const available = rs.map((r) => r.available).filter((v) => Number.isFinite(v));
    return {
      source: id,
      name,
      homepage: def ? def.homepage : null,
      state,
      ok: okCount > 0,
      names: uniqueNames.size,
      ipHints: ipCount,
      certs: rs.reduce((a, r) => a + (r.certs?.length || 0), 0),
      elapsedMs: Math.max(0, ...rs.map((r) => (Number.isFinite(r.elapsedMs) ? r.elapsedMs : 0))),
      attempts: rs.reduce((a, r) => a + (Number.isFinite(r.attempts) ? r.attempts : 0), 0),
      errorKind: firstFail ? firstFail.errorKind || null : null,
      error: firstFail ? firstFail.error || null : null,
      quota,
      truncated: rs.some((r) => r.truncated),
      available: available.length ? available.reduce((a, b) => a + b, 0) : null,
      fallback,
      message,
      domains: rs.map((r, i) => ({
        domain: r.domain ?? null, state: states[i], names: r.names?.length || 0, errorKind: r.errorKind ?? null, error: r.error ?? null
      }))
    };
  });
}
