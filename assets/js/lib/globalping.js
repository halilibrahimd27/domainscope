/**
 * globalping.js — DOM-free client for the Globalping v1 API (https://globalping.io, run by
 * jsDelivr and volunteers): one HTTPS HEAD request from a probe on the public internet to a server,
 * reporting the TLS certificate it was served (or one HTTPS GET of a path, for the MTA-STS policy).
 * This module is the transport only — create, get, poll, measure, limits, quota tracking, the
 * request builders and the target prefilters. It knows nothing about certificates or policies
 * (lib/verify.js and lib/mtasts.js interpret results). Runs in browsers and Node 22.
 *
 * API facts this client relies on (verified live 2026-09-24, see tests/fixtures/globalping/):
 * - POST bodies must be `application/json` (a text/plain body is ignored → 400), so every create
 *   is CORS-preflighted (allowed, cached 600 s). GETs carry no custom header: simple requests.
 * - Validation errors (400 / 401 / 422) are free. X-RateLimit-* and X-Request-Cost come only on the
 *   202; `/v1/limits` carries its quota in the body only. X-RateLimit-Remaining is NOT monotonic
 *   across concurrent POSTs, so the client keeps the minimum per window ({@link mergeQuota}). The
 *   anonymous quota (250 probes / hour) is shared by everyone behind the same egress IP.
 * - The poll limit is per measurement id: ≥ 500 ms after each response; a GET 429 carries a
 *   readable `Retry-After`. The probe-side `timeout` (5–30 s) plus 10 s is the client deadline.
 * - Port 0 is accepted AND charged (treated as 443), and so is the IPv6 documentation prefix
 *   3fff::/20: the client refuses both itself. Private / reserved targets get a free 400.
 * - Results (target IP, host name, the server's response headers) are public to anyone holding the
 *   measurement id for about six months. Callers send only what the user chose to check.
 */
import { fetchAndRead, sleep, throwIfAborted, parseRetryAfter, abortReasonToError } from './util.js';
import { normalizeHostname } from './domain.js';
import { isGloballyRoutable, parseIP, formatIP, normalizeIP, ipVersion } from './netinfo.js';

/* ------------------------------------------------------------------------ */
/* Constants                                                                */
/* ------------------------------------------------------------------------ */

/** The API base. Never configurable from a URL, a route or stored settings (tests inject `baseUrl`). */
export const GLOBALPING_API = 'https://api.globalping.io/v1';

/** Limits of the public API and of this client's polling. */
export const GP_LIMITS = Object.freeze({
  anonymousPerHour: 250, tokenPerHour: 500, maxProbesPerMeasurement: 50,
  minTimeoutS: 5, maxTimeoutS: 30, clientSlackS: 10, pollIntervalMs: 500, requestTimeoutMs: 15000
});

/** TLS ports where an HTTPS probe returns no `tls` object (mail, directory, database, RDP …): CLI only. */
export const NON_HTTP_TLS_PORTS = Object.freeze([21, 25, 110, 143, 465, 587, 636, 989, 990, 993, 995,
  1433, 1521, 3306, 3389, 5432, 5671, 5986, 6379, 8883, 9093, 27017]);

/** Every `GlobalpingError.code`. */
export const GP_ERROR_CODES = Object.freeze(['validation', 'private-target', 'bad-host', 'no-probes', 'rate-limit',
  'insufficient-credits', 'unauthorized', 'not-found', 'poll-rate', 'server', 'deadline', 'bad-response']);

/** Measurement ids are base62-ish (25 chars today); anything else never shapes a request path. */
const MEASUREMENT_ID_RE = /^[A-Za-z0-9]{8,64}$/;
/** Keys a `locations[]` entry may carry (the API's location object). */
const LOCATION_KEYS = new Set(['continent', 'region', 'country', 'state', 'city', 'asn', 'network', 'tags', 'magic', 'limit']);
const HOST_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TOKEN_RE = /^[\x21-\x7e]{1,512}$/;
/** Readings whose window ends within this span belong to the same hourly window. */
const WINDOW_SLACK_MS = 60_000;
/** A slow-down POST 429 (not a quota type) is waited out and repeated once only up to this long. */
const BURST_RETRY_MAX_MS = 60_000;
/** A GET 429 asking for a longer wait than this is reported ('poll-rate') instead of slept through. */
const POLL_RETRY_MAX_MS = 30_000;
const RETRY_DELAY_MS = 1000;

/**
 * @typedef {object} GpQuota
 * @property {number|null} limit       probes per window (X-RateLimit-Limit / limits.limit)
 * @property {number} remaining        probes left in the window (the minimum seen in that window)
 * @property {number|null} consumed
 * @property {Date|null} resetAt       end of the fixed 1-hour window; null = no window open yet
 * @property {number|null} cost        X-Request-Cost of the last create
 * @property {'ip'|'user'|null} type   anonymous (per egress IP) or token quota
 * @property {'limits'|'create'|'429'} source
 * @property {Date} at                 when the reading was taken
 */

/**
 * @typedef {object} Measurement  The API JSON as-is: `{ id, type, status: 'in-progress'|'finished',
 *   createdAt, updatedAt, target, probesCount, measurementOptions, results: [{ probe, result }] }`.
 *   Trimming is the caller's job (verify.trimTest).
 */

/* ------------------------------------------------------------------------ */
/* Error                                                                    */
/* ------------------------------------------------------------------------ */

const KIND_OF = { 'rate-limit': 'rate-limit', 'insufficient-credits': 'rate-limit', deadline: 'timeout', 'bad-response': 'parse' };

/** Every failure the API (or the poll deadline) reports. `kind` is util.errorKind-compatible. */
export class GlobalpingError extends Error {
  /**
   * @param {string} code one of {@link GP_ERROR_CODES}
   * @param {string} message
   * @param {{ status?: number|null, params?: object|null, quota?: GpQuota|null, retryAfterMs?: number|null,
   *   resetAt?: Date|null, body?: string, cause?: unknown }} [opts]
   */
  constructor(code, message, opts = {}) {
    super(message, opts.cause === undefined ? undefined : { cause: opts.cause });
    this.name = 'GlobalpingError';
    /** @type {string} */
    this.code = code;
    /** @type {'rate-limit'|'timeout'|'parse'|'http'} */
    this.kind = KIND_OF[code] || 'http';
    /** @type {number|null} */
    this.status = Number.isInteger(opts.status) ? opts.status : null;
    /** @type {object|null} `error.params` of a 400 */
    this.params = opts.params && typeof opts.params === 'object' ? opts.params : null;
    /** @type {GpQuota|null} */
    this.quota = opts.quota || null;
    /** @type {number|null} */
    this.retryAfterMs = Number.isFinite(opts.retryAfterMs) && opts.retryAfterMs >= 0 ? opts.retryAfterMs : null;
    /** @type {Date|null} */
    this.resetAt = opts.resetAt instanceof Date ? opts.resetAt : null;
    /** @type {string} first 500 characters of the response body */
    this.body = String(opts.body ?? '').slice(0, 500);
  }
}

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Is this string a well-formed measurement id? Only such ids are ever put into a request path.
 * @param {unknown} id
 * @returns {boolean}
 */
export function isMeasurementId(id) {
  return typeof id === 'string' && MEASUREMENT_ID_RE.test(id);
}

/**
 * Can a Globalping probe reach this address? = netinfo.isGloballyRoutable (IPv4-mapped v6 judged as
 * its v4). Private, reserved, documentation and multicast space is refused before any request.
 * @param {string} ip
 * @returns {boolean}
 */
export function isProbeableIP(ip) {
  return isGloballyRoutable(ip);
}

/**
 * The `target` string to send: the canonical IPv4 for a v4 or IPv4-mapped (::ffff:a.b.c.d)
 * address, RFC 5952 IPv6 otherwise; null when !{@link isProbeableIP}.
 * @param {string} ip
 * @returns {string|null}
 */
export function probeTarget(ip) {
  if (!isProbeableIP(ip)) return null;
  const addr = parseIP(ip);
  if (addr.version === 4) return formatIP(addr.value, 4);
  if (addr.value >> 32n === 0xffffn) return formatIP(addr.value & 0xffffffffn, 4);
  return normalizeIP(ip);
}

/**
 * A `request.host` Globalping accepts (anything else is a free 400): already normalised (lowercase,
 * punycode, no trailing dot, no port, no wildcard), at least two labels, every label LDH
 * (`[a-z0-9-]`, so no '_'), not an IP literal, a last label containing a letter, ≤ 253 characters.
 * @param {unknown} name
 * @returns {boolean}
 */
export function isProbeableHost(name) {
  if (typeof name !== 'string' || !name || name.length > 253) return false;
  if (normalizeHostname(name) !== name) return false;
  const labels = name.split('.');
  if (labels.length < 2 || !labels.every((l) => HOST_LABEL_RE.test(l))) return false;
  if (!/[a-z]/.test(labels[labels.length - 1])) return false;
  return ipVersion(name) === 0;
}

/**
 * An integer 1–65535 that is not a non-HTTP TLS port. Port 0 is accepted AND charged by the API
 * (silently treated as 443), so it must never reach a request.
 * @param {unknown} port
 * @returns {boolean}
 */
export function isProbeablePort(port) {
  return Number.isInteger(port) && port >= 1 && port <= 65535 && !NON_HTTP_TLS_PORTS.includes(port);
}

function locationEntry(entry, i) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new TypeError(`locations[${i}] must be an object`);
  const keys = Object.keys(entry);
  if (!keys.length || keys.every((k) => k === 'limit')) throw new TypeError(`locations[${i}] selects nothing`);
  const bad = keys.find((k) => !LOCATION_KEYS.has(k));
  if (bad) throw new TypeError(`locations[${i}] has an unknown key: ${bad}`);
  const limit = entry.limit ?? 1;
  if (!Number.isInteger(limit) || limit < 1 || limit > GP_LIMITS.maxProbesPerMeasurement) {
    throw new TypeError(`locations[${i}].limit must be an integer 1–${GP_LIMITS.maxProbesPerMeasurement}`);
  }
  return { ...entry, limit };
}

/**
 * Body for one HTTPS/TLS check of `name` on `ip:port`. `request.host` sets both the SNI and the
 * Host header when the target is an IP.
 *
 * - `locations` null → `{ limit: probes }` (probes anywhere); an Array → `{ locations }` with
 *   `limit: 1` on entries without one and NO global limit (the API refuses both together); a
 *   string (a previous measurement id) → `{ locations: id }` (the same probes again).
 * - `timeout` is rounded, clamped to 5–30 s and always sent; `port` is always sent (the API
 *   default is 80); `ipVersion` is never sent (the API refuses it with an IP target).
 * - Method HEAD, path '/', protocol HTTPS.
 *
 * @param {{ ip: string, name: string, port?: number, timeoutS?: number, probes?: number,
 *   locations?: null|string|object[] }} opts
 * @returns {{ type: 'http', target: string, limit?: number, locations?: string|object[], timeout: number,
 *   measurementOptions: { protocol: 'HTTPS', port: number, request: { method: 'HEAD', host: string, path: '/' } } }}
 * @throws {TypeError} for an unprobeable IP, host or port, a bad probe count / timeout / location,
 *   an `ipVersion` or any other unknown option.
 */
export function httpsCheckRequest({ ip, name, port = 443, timeoutS = 10, probes = 1, locations = null, ...rest } = {}) {
  if ('ipVersion' in rest) throw new TypeError('ipVersion is never sent: the API refuses it with an IP target');
  const unknown = Object.keys(rest);
  if (unknown.length) throw new TypeError(`Unknown option: ${unknown[0]}`);
  const target = probeTarget(ip);
  if (!target) throw new TypeError(`Not a globally routable address: ${String(ip)}`);
  if (!isProbeableHost(name)) throw new TypeError(`Globalping does not accept this host name: ${String(name)}`);
  if (!isProbeablePort(port)) throw new TypeError(`Port cannot be checked through Globalping: ${String(port)}`);
  if (!Number.isInteger(probes) || probes < 1 || probes > GP_LIMITS.maxProbesPerMeasurement) {
    throw new TypeError(`probes must be an integer 1–${GP_LIMITS.maxProbesPerMeasurement}`);
  }
  if (typeof timeoutS !== 'number' || !Number.isFinite(timeoutS)) throw new TypeError('timeoutS must be a finite number');
  const timeout = Math.min(GP_LIMITS.maxTimeoutS, Math.max(GP_LIMITS.minTimeoutS, Math.round(timeoutS)));

  const body = { type: 'http', target };
  applyLocations(body, locations, probes);
  body.timeout = timeout;
  body.measurementOptions = { protocol: 'HTTPS', port, request: { method: 'HEAD', host: name, path: '/' } };
  return body;
}

/**
 * Where a measurement's probes come from: `null` → `{ limit: probes }` (anywhere); an Array →
 * `{ locations }` with `limit: 1` on entries without one and no global limit (the API refuses
 * both together); a string (a previous measurement id) → `{ locations: id }`.
 * @param {object} body the request body, extended in place
 * @param {null|string|object[]} locations
 * @param {number} probes
 * @throws {TypeError} for a bad location list
 */
function applyLocations(body, locations, probes) {
  if (locations === null || locations === undefined) {
    body.limit = probes;
  } else if (typeof locations === 'string') {
    if (!isMeasurementId(locations)) throw new TypeError('locations string must be a measurement id');
    body.locations = locations;
  } else if (Array.isArray(locations)) {
    if (!locations.length) throw new TypeError('locations must not be empty');
    body.locations = locations.map(locationEntry);
    const total = body.locations.reduce((sum, l) => sum + l.limit, 0);
    if (total > GP_LIMITS.maxProbesPerMeasurement) {
      throw new TypeError(`locations ask for ${total} probes (at most ${GP_LIMITS.maxProbesPerMeasurement})`);
    }
  } else {
    throw new TypeError('locations must be null, a measurement id or an array');
  }
}

/** A request path Globalping takes and nothing else shapes: '/', then printable ASCII without spaces, '?' or '#'. */
const GET_PATH_RE = /^\/[\x21-\x22\x24-\x3e\x40-\x7e]{0,500}$/;

/**
 * Body for one HTTPS GET of `path` on a host name (Domain Health's MTA-STS policy fetch). The
 * probe resolves `host` itself and uses it as SNI and Host header; the result carries the status
 * code, the response headers, the body (`rawBody`, decoded, cut at 10 KB with `truncated`) and
 * `tls` like a HEAD check (verified live 2026-09-27, tests/fixtures/globalping/m26 + m27).
 *
 * - The target is the host name (no `request.host`); `port` and `timeout` (rounded, clamped to
 *   5–30 s) are always sent, `ipVersion` and a query string never.
 * @param {{ host: string, path?: string, port?: number, timeoutS?: number, probes?: number }} opts
 * @returns {{ type: 'http', target: string, limit: number, timeout: number,
 *   measurementOptions: { protocol: 'HTTPS', port: number, request: { method: 'GET', path: string } } }}
 * @throws {TypeError} for a host Globalping refuses, a path outside {@link GET_PATH_RE}, an unprobeable
 *   port, a bad probe count or timeout, or any unknown option
 */
export function httpsGetRequest({ host, path = '/', port = 443, timeoutS = 10, probes = 1, ...rest } = {}) {
  const unknown = Object.keys(rest);
  if (unknown.length) throw new TypeError(`Unknown option: ${unknown[0]}`);
  if (!isProbeableHost(host)) throw new TypeError(`Globalping does not accept this host name: ${String(host)}`);
  if (typeof path !== 'string' || !GET_PATH_RE.test(path)) throw new TypeError(`Not a plain request path: ${String(path)}`);
  if (!isProbeablePort(port)) throw new TypeError(`Port cannot be checked through Globalping: ${String(port)}`);
  if (!Number.isInteger(probes) || probes < 1 || probes > GP_LIMITS.maxProbesPerMeasurement) {
    throw new TypeError(`probes must be an integer 1–${GP_LIMITS.maxProbesPerMeasurement}`);
  }
  if (typeof timeoutS !== 'number' || !Number.isFinite(timeoutS)) throw new TypeError('timeoutS must be a finite number');
  const timeout = Math.min(GP_LIMITS.maxTimeoutS, Math.max(GP_LIMITS.minTimeoutS, Math.round(timeoutS)));
  return {
    type: 'http', target: host, limit: probes, timeout,
    measurementOptions: { protocol: 'HTTPS', port, request: { method: 'GET', path } }
  };
}

/**
 * Body for one plain-HTTP GET of `path` on a host name (Renewal readiness: is the HTTP-01
 * challenge path reachable?). The probe resolves `host` itself and sends it as the Host header;
 * redirects are NOT followed: a 3xx result carries its `headers.location` (verified live
 * 2026-09-28, tests/fixtures/globalping/m28–m30).
 *
 * - The target is the host name; `port` (default 80) and `timeout` (rounded, clamped to 5–30 s)
 *   are always sent, a query string never.
 * - `locations` as in {@link httpsCheckRequest} (null → `limit: probes` anywhere).
 * - `ipVersion` 4 or 6 goes into `measurementOptions` (allowed with a host-name target only): the
 *   probes then resolve and connect over that family; null leaves it out (the API's default, 4).
 * @param {{ host: string, path?: string, port?: number, timeoutS?: number, probes?: number,
 *   locations?: null|string|object[], ipVersion?: 4|6|null }} opts
 * @returns {{ type: 'http', target: string, limit?: number, locations?: string|object[], timeout: number,
 *   measurementOptions: { protocol: 'HTTP', port: number, ipVersion?: 4|6, request: { method: 'GET', path: string } } }}
 * @throws {TypeError} for a host Globalping refuses, a path outside {@link GET_PATH_RE}, an unprobeable
 *   port, a bad probe count, timeout, location list or IP version, or any unknown option
 */
export function httpGetRequest({ host, path = '/', port = 80, timeoutS = 10, probes = 1, locations = null, ipVersion = null, ...rest } = {}) {
  const unknown = Object.keys(rest);
  if (unknown.length) throw new TypeError(`Unknown option: ${unknown[0]}`);
  if (!isProbeableHost(host)) throw new TypeError(`Globalping does not accept this host name: ${String(host)}`);
  if (typeof path !== 'string' || !GET_PATH_RE.test(path)) throw new TypeError(`Not a plain request path: ${String(path)}`);
  if (!isProbeablePort(port)) throw new TypeError(`Port cannot be checked through Globalping: ${String(port)}`);
  if (!Number.isInteger(probes) || probes < 1 || probes > GP_LIMITS.maxProbesPerMeasurement) {
    throw new TypeError(`probes must be an integer 1–${GP_LIMITS.maxProbesPerMeasurement}`);
  }
  if (typeof timeoutS !== 'number' || !Number.isFinite(timeoutS)) throw new TypeError('timeoutS must be a finite number');
  if (ipVersion !== null && ipVersion !== 4 && ipVersion !== 6) throw new TypeError('ipVersion must be 4, 6 or null');
  const timeout = Math.min(GP_LIMITS.maxTimeoutS, Math.max(GP_LIMITS.minTimeoutS, Math.round(timeoutS)));
  const body = { type: 'http', target: host };
  applyLocations(body, locations, probes);
  body.timeout = timeout;
  body.measurementOptions = { protocol: 'HTTP', port };
  if (ipVersion !== null) body.measurementOptions.ipVersion = ipVersion;
  body.measurementOptions.request = { method: 'GET', path };
  return body;
}

/**
 * Probe metadata kept in app state and exports — never latitude / longitude, resolvers or the
 * `u-<username>` tag itself. `adopted`: the probe carries a `u-…` tag, i.e. a registered user
 * adopted it (65% of all probes); its absence does not mean jsDelivr runs the probe.
 * @param {object} probe
 * @returns {{ continent: string|null, country: string|null, city: string|null, asn: number|null,
 *   network: string|null, kind: 'datacenter'|'eyeball'|null, adopted: boolean }}
 */
export function probeSummary(probe) {
  const p = probe && typeof probe === 'object' ? probe : {};
  const str = (v) => (typeof v === 'string' && v ? v : null);
  const tags = Array.isArray(p.tags) ? p.tags.filter((t) => typeof t === 'string') : [];
  let kind = null;
  if (tags.includes('datacenter-network')) kind = 'datacenter';
  else if (tags.includes('eyeball-network')) kind = 'eyeball';
  return {
    continent: str(p.continent), country: str(p.country), city: str(p.city),
    asn: Number.isInteger(p.asn) && p.asn > 0 ? p.asn : null, network: str(p.network),
    kind, adopted: tags.some((t) => t.startsWith('u-'))
  };
}

/* ------------------------------------------------------------------------ */
/* Quota                                                                    */
/* ------------------------------------------------------------------------ */

const toMs = (now) => (now instanceof Date ? now.getTime() : Number(now));

function count(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
}

function headerReader(headers) {
  if (!headers) return () => null;
  if (typeof headers.get === 'function') return (k) => headers.get(k);
  const map = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return (k) => (map.has(k) ? map.get(k) : null);
}

/**
 * Quota from the headers of a POST response (202, or a 429 that carries them). Header names are
 * case-insensitive; a plain object works too. null without a readable X-RateLimit-Remaining.
 * @param {Headers|Record<string, string>|null} headers
 * @param {number|Date} [now=Date.now()]
 * @returns {GpQuota|null}
 */
export function quotaFromHeaders(headers, now = Date.now()) {
  const get = headerReader(headers);
  const remaining = count(get('x-ratelimit-remaining'));
  if (remaining === null) return null;
  const t = toMs(now);
  const reset = count(get('x-ratelimit-reset'));
  return {
    limit: count(get('x-ratelimit-limit')), remaining, consumed: count(get('x-ratelimit-consumed')),
    resetAt: reset ? new Date(t + reset * 1000) : null, cost: count(get('x-request-cost')),
    type: null, source: 'create', at: new Date(t)
  };
}

/**
 * Quota from a `GET /v1/limits` body (`rateLimit.measurements.create`; the endpoint sends no
 * X-RateLimit headers). `reset: 0` = no window open yet → resetAt null.
 * @param {object} json
 * @param {number|Date} [now=Date.now()]
 * @returns {GpQuota|null}
 */
export function quotaFromLimits(json, now = Date.now()) {
  const c = json?.rateLimit?.measurements?.create;
  if (!c || typeof c !== 'object') return null;
  const remaining = count(c.remaining);
  if (remaining === null) return null;
  const limit = count(c.limit);
  const reset = count(c.reset);
  const t = toMs(now);
  return {
    limit, remaining, consumed: limit === null ? null : Math.max(0, limit - remaining),
    resetAt: reset ? new Date(t + reset * 1000) : null, cost: null,
    type: c.type === 'ip' || c.type === 'user' ? c.type : null, source: 'limits', at: new Date(t)
  };
}

const maxOrNull = (a, b) => (a === null || a === undefined ? (b ?? null) : b === null || b === undefined ? a : Math.max(a, b));

/**
 * Merge a new quota reading into the known one.
 *
 * - Same window (both `resetAt` set and within 60 s of each other, or `next.resetAt` null while
 *   prev's window is still open, or neither has a window yet and `next` is not a /limits
 *   reading) → `remaining = min(prev, next)`, limit / type from `next` when known.
 *   X-RateLimit-Remaining is not monotonic across concurrent POSTs (220, 216, 215, 219, 217, 218
 *   in one window): the minimum is the true value.
 * - A later window (prev's window has passed, a window opened since a no-window reading, or
 *   `next.resetAt` more than 60 s after prev's), or a windowless /limits reading after a
 *   windowless one (the server says no window is open) → `next` replaces the reading.
 * - `next.source === '429'` → remaining 0 in the current window.
 *
 * Never raises `remaining` inside a window.
 * @param {GpQuota|null} prev
 * @param {GpQuota|null} next
 * @param {number|Date} [now=Date.now()]
 * @returns {GpQuota|null}
 */
export function mergeQuota(prev, next, now = Date.now()) {
  if (!next) return prev || null;
  const is429 = next.source === '429';
  const fresh = () => ({ ...next, remaining: is429 ? 0 : next.remaining, at: next.at || new Date(toMs(now)) });
  if (!prev) return fresh();
  const t = toMs(now);
  const pr = prev.resetAt ? prev.resetAt.getTime() : null;
  const nr = next.resetAt ? next.resetAt.getTime() : null;

  let same;
  if (pr !== null && pr <= t) same = false; // prev's window has ended
  // No window yet on either side (or one opened since). A /limits reading without a window is the
  // server's own word that none is open: it replaces the earlier windowless reading instead of
  // min-merging with it, so a 429 stored without a reset time cannot pin the quota at 0 for good.
  else if (pr === null) same = nr === null && next.source !== 'limits';
  else if (nr === null) same = true; // prev's window is open; a reading without a window cannot end it
  else same = nr <= pr + WINDOW_SLACK_MS; // within 60 s, or the server now says the window ends sooner
  if (!same) return fresh();

  const remaining = is429 ? 0 : Math.min(prev.remaining, next.remaining);
  const resetAt = next.resetAt || prev.resetAt || null; // the newest reading that knows the window
  return {
    limit: next.limit ?? prev.limit ?? null,
    remaining,
    consumed: maxOrNull(prev.consumed, next.consumed),
    resetAt,
    cost: next.source === 'create' ? (next.cost ?? null) : (prev.cost ?? null),
    type: next.type ?? prev.type ?? null,
    source: next.source,
    at: next.at || new Date(t)
  };
}

/* ------------------------------------------------------------------------ */
/* Client                                                                   */
/* ------------------------------------------------------------------------ */

const isAbort = (err) => !!err && typeof err === 'object' && err.name === 'AbortError';
const isNetworkish = (err) => err instanceof TypeError || (!!err && typeof err === 'object' && err.name === 'TimeoutError');

async function readBody(res, signal) {
  let text = '';
  try {
    text = await res.text();
  } catch (err) {
    if (signal?.aborted) throw abortReasonToError(signal.reason);
    if (isAbort(err)) throw err;
    text = '';
  }
  throwIfAborted(signal);
  if (!text) return { text, json: null };
  try {
    return { text, json: JSON.parse(text) };
  } catch {
    return { text, json: undefined };
  }
}

/**
 * Create a Globalping client. One instance per page keeps one quota view (app.js getGlobalping).
 *
 * @param {{ fetchImpl?: typeof fetch, token?: string|null, baseUrl?: string,
 *   sleepImpl?: (ms: number, signal?: AbortSignal) => Promise<void>, requestTimeoutMs?: number,
 *   now?: () => number }} [opts]
 *   `fetchImpl` defaults to the current `globalThis.fetch` at call time; `now` is used for every
 *   quota timestamp and the poll deadline (tests inject a fake clock and a fake sleep).
 * @returns {{
 *   readonly quota: GpQuota|null,
 *   readonly tokenState: 'none'|'set'|'rejected',
 *   setToken: (token: string|null) => void,
 *   onQuota: (fn: (q: GpQuota) => void) => () => void,
 *   limits: (opts?: { signal?: AbortSignal }) => Promise<GpQuota>,
 *   create: (body: object, opts?: { signal?: AbortSignal }) => Promise<{ id: string, probesCount: number, cost: number, quota: GpQuota|null }>,
 *   get: (id: string, opts?: { signal?: AbortSignal }) => Promise<Measurement>,
 *   poll: (id: string, opts?: { signal?: AbortSignal, deadlineAt?: number, deadlineMs?: number, intervalMs?: number,
 *     onUpdate?: (m: Measurement) => void }) => Promise<Measurement>,
 *   measure: (body: object, opts?: { signal?: AbortSignal, onUpdate?: (m: Measurement) => void }) =>
 *     Promise<{ measurement: Measurement, id: string, cost: number, quota: GpQuota|null }>
 * }}
 */
export function createGlobalping({
  fetchImpl = (input, init) => globalThis.fetch(input, init),
  token = null,
  baseUrl = GLOBALPING_API,
  sleepImpl = sleep,
  requestTimeoutMs = GP_LIMITS.requestTimeoutMs,
  now = () => Date.now()
} = {}) {
  const base = String(baseUrl).replace(/\/+$/, '');
  let authToken = null;
  /** @type {'none'|'set'|'rejected'} */
  let tokenState = 'none';
  /** @type {GpQuota|null} */
  let quota = null;
  const listeners = new Set();
  const lastResponseAt = new Map(); // measurement id → time of its last GET response
  const queues = new Map(); // measurement id → tail of its GET queue (one GET per id at a time)

  function setToken(value) {
    if (value === null || value === undefined || value === '') {
      authToken = null;
      tokenState = 'none';
      return;
    }
    const v = typeof value === 'string' ? value.trim() : '';
    if (!TOKEN_RE.test(v)) throw new TypeError('Invalid Globalping token');
    authToken = v;
    tokenState = 'set';
  }
  setToken(token);

  function dropToken() {
    authToken = null;
    tokenState = 'rejected';
  }

  function applyQuota(reading) {
    if (!reading) return quota;
    quota = mergeQuota(quota, reading, now());
    for (const fn of [...listeners]) {
      try { fn(quota); } catch { /* observer errors are ignored */ }
    }
    return quota;
  }

  // The request timeout covers the body read too: a response that stalls after its headers must
  // not hang a row (poll() only checks its deadline between GETs). A timeout is a TimeoutError.
  const send = (url, init, signal) => fetchAndRead(url, { ...init, fetchImpl, signal, timeoutMs: requestTimeoutMs },
    async (res) => ({ res, ...(await readBody(res, signal)) }));

  async function pause(ms, signal) {
    await sleepImpl(ms, signal);
    throwIfAborted(signal); // a fake / signal-less sleep must not let another request out
  }

  /* ---- GET /limits (free) --------------------------------------------- */

  async function limits({ signal } = {}) {
    throwIfAborted(signal);
    let anonRetried = false;
    let retried = false;
    for (;;) {
      const withToken = !!authToken;
      const init = { method: 'GET', cache: 'no-store' };
      if (withToken) init.headers = { authorization: `Bearer ${authToken}` };
      let res;
      let text;
      let json;
      try {
        ({ res, text, json } = await send(`${base}/limits`, init, signal));
      } catch (err) {
        if (!isAbort(err) && isNetworkish(err) && !retried) {
          retried = true;
          await pause(RETRY_DELAY_MS, signal);
          continue;
        }
        throw err;
      }
      const st = res.status;
      if (st === 200) {
        const reading = quotaFromLimits(json, now());
        if (!reading) throw new GlobalpingError('bad-response', 'Unexpected /limits body', { status: st, body: text });
        return applyQuota(reading);
      }
      if (st === 401 && withToken && !anonRetried) {
        dropToken();
        anonRetried = true;
        continue;
      }
      if (st === 401) throw new GlobalpingError('unauthorized', 'Globalping refused the request (401)', { status: st, body: text });
      if (st >= 500 && !retried) {
        retried = true;
        await pause(RETRY_DELAY_MS, signal);
        continue;
      }
      throw new GlobalpingError('server', `Globalping /limits answered HTTP ${st}`, { status: st, body: text });
    }
  }

  /* ---- POST /measurements --------------------------------------------- */

  async function create(body, { signal } = {}) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new TypeError('create() expects a measurement body object');
    const port = body.measurementOptions?.port;
    if (port !== undefined && !(Number.isInteger(port) && port >= 1 && port <= 65535)) {
      throw new TypeError(`Refusing to send port ${String(port)}: the API accepts port 0 and charges for it`);
    }
    throwIfAborted(signal);
    const payload = JSON.stringify(body);
    let anonRetried = false;
    let burstRetried = false;
    let gatewayRetried = false;
    for (;;) {
      const withToken = !!authToken;
      const headers = { 'content-type': 'application/json' };
      if (withToken) headers.authorization = `Bearer ${authToken}`;
      // A network error or timeout (headers or body) is never retried: the measurement may already
      // exist (and be charged).
      const { res, text, json } = await send(`${base}/measurements`, { method: 'POST', headers, body: payload }, signal);
      const st = res.status;
      const error = json && typeof json === 'object' && json.error && typeof json.error === 'object' ? json.error : null;

      if (st >= 200 && st < 300) {
        if (!json || typeof json !== 'object' || !isMeasurementId(json.id)) {
          throw new GlobalpingError('bad-response', 'Globalping accepted the measurement but sent no usable id', { status: st, body: text });
        }
        const probesCount = Number.isInteger(json.probesCount) && json.probesCount >= 0 ? json.probesCount : null;
        const reading = quotaFromHeaders(res.headers, now());
        const cost = count(headerReader(res.headers)('x-request-cost')) || probesCount || 0;
        const merged = reading ? applyQuota(reading) : quota;
        return { id: json.id, probesCount: probesCount ?? cost, cost, quota: merged };
      }
      if (st === 400) {
        const params = error && error.params && typeof error.params === 'object' ? error.params : null;
        const opts = { status: st, params, body: text };
        if (params && typeof params.target === 'string' && /private hostname/i.test(params.target)) {
          throw new GlobalpingError('private-target', 'Globalping cannot probe a private or reserved address', opts);
        }
        if (params && Object.keys(params).some((k) => k.includes('request.host'))) {
          throw new GlobalpingError('bad-host', 'Globalping does not accept this host name', opts);
        }
        throw new GlobalpingError('validation', error?.message || 'Globalping refused the request (400)', opts);
      }
      if (st === 401) {
        if (withToken && !anonRetried) {
          dropToken(); // free; repeat the same request anonymously
          anonRetried = true;
          continue;
        }
        throw new GlobalpingError('unauthorized', 'Globalping refused the request (401)', { status: st, body: text });
      }
      if (st === 422) throw new GlobalpingError('no-probes', error?.message || 'No matching probes available', { status: st, body: text });
      if (st === 429) {
        const type = error?.type;
        const retryAfterMs = parseRetryAfter(headerReader(res.headers)('retry-after'), now());
        const quotaType = type === 'rate_limit_exceeded' || type === 'insufficient_credits';
        if (!quotaType) {
          // Only the two quota types stop the queue (critic C.3.6). Anything else — too_many_requests,
          // an unknown type, an untyped or non-JSON 429 from an edge — is a slow-down that leaves the
          // quota alone. A 429 is not charged: wait (Retry-After, 5 s without one) and repeat the same
          // POST once when the wait is short; otherwise report it.
          const wait = retryAfterMs ?? 5000;
          if (!burstRetried && wait <= BURST_RETRY_MAX_MS) {
            burstRetried = true;
            await pause(wait, signal);
            continue;
          }
          throw new GlobalpingError('poll-rate', 'Globalping asked to slow down', { status: st, retryAfterMs, body: text });
        }
        const reading = quotaFromHeaders(res.headers, now());
        let resetAt = reading?.resetAt ?? null;
        if (!resetAt) {
          try {
            resetAt = (await limits({ signal }))?.resetAt ?? null; // free
          } catch (err) {
            if (isAbort(err) || signal?.aborted) throw err;
          }
        }
        const merged = applyQuota({
          limit: reading?.limit ?? null, remaining: 0, consumed: reading?.consumed ?? null, resetAt,
          cost: null, type: null, source: '429', at: new Date(now())
        });
        const at = merged?.resetAt ?? resetAt;
        throw new GlobalpingError(type === 'insufficient_credits' ? 'insufficient-credits' : 'rate-limit',
          error?.message || 'The Globalping quota is used up', {
            status: st, quota: merged, resetAt: at, retryAfterMs: at ? Math.max(0, at.getTime() - now()) : null, body: text
          });
      }
      if ((st === 502 || st === 503) && !gatewayRetried) {
        gatewayRetried = true; // the gateway answered: nothing was created
        await pause(RETRY_DELAY_MS, signal);
        continue;
      }
      // 504 (may have been created), other 5xx, 403 from a proxy, 404, 413 …: never retried.
      throw new GlobalpingError('server', `Globalping answered HTTP ${st}`, { status: st, body: text });
    }
  }

  /* ---- GET /measurements/{id} ----------------------------------------- */

  function assertId(id) {
    if (!isMeasurementId(id)) {
      throw new GlobalpingError('validation', 'Not a Globalping measurement id', { params: { id: 'invalid measurement id' } });
    }
  }

  async function getOnce(id, signal) {
    let rateLimited = 0;
    let failures = 0;
    for (;;) {
      throwIfAborted(signal);
      const last = lastResponseAt.get(id);
      const wait = last === undefined ? 0 : last + GP_LIMITS.pollIntervalMs - now();
      if (wait > 0) await pause(wait, signal); // per-id throttle: ≥ 500 ms after the previous response
      let res;
      let text;
      let json;
      try {
        // No custom header and no ETag: a simple CORS request, never preflighted.
        ({ res, text, json } = await send(`${base}/measurements/${encodeURIComponent(id)}`, { method: 'GET', cache: 'no-store' }, signal));
      } catch (err) {
        if (!isAbort(err) && isNetworkish(err) && failures < 2) {
          failures += 1;
          await pause(RETRY_DELAY_MS, signal);
          continue;
        }
        throw err;
      }
      const t = now();
      lastResponseAt.set(id, t);
      for (const [k, at] of lastResponseAt) if (t - at > 60_000) lastResponseAt.delete(k);
      const st = res.status;
      if (st === 200) {
        if (!json || typeof json !== 'object' || typeof json.status !== 'string' || !Array.isArray(json.results)) {
          throw new GlobalpingError('bad-response', 'Unexpected measurement body', { status: st, body: text });
        }
        return json;
      }
      if (st === 404) throw new GlobalpingError('not-found', 'Measurement not found (unknown or expired id)', { status: st, body: text });
      if (st === 429) {
        rateLimited += 1;
        const retryAfterMs = parseRetryAfter(headerReader(res.headers)('retry-after'), t) ?? 5000;
        if (rateLimited >= 3 || retryAfterMs > POLL_RETRY_MAX_MS) {
          throw new GlobalpingError('poll-rate', 'Globalping rate-limited polling this measurement', { status: st, retryAfterMs, body: text });
        }
        await pause(retryAfterMs, signal);
        continue;
      }
      rateLimited = 0;
      if (st >= 500 && failures < 2) {
        failures += 1;
        await pause(RETRY_DELAY_MS, signal);
        continue;
      }
      throw new GlobalpingError('server', `Globalping answered HTTP ${st}`, { status: st, body: text });
    }
  }

  function get(id, { signal } = {}) {
    try {
      assertId(id);
      throwIfAborted(signal);
    } catch (err) {
      return Promise.reject(err);
    }
    // Several callers on one id queue up, so the per-id throttle holds across them.
    const prev = queues.get(id) || Promise.resolve();
    const run = prev.then(() => getOnce(id, signal));
    const tail = run.then(() => {}, () => {});
    queues.set(id, tail);
    tail.then(() => { if (queues.get(id) === tail) queues.delete(id); });
    if (!signal) return run;
    // Waiting behind another caller's GET must not delay a Stop: reject as soon as the signal aborts
    // (the queued GET then never leaves: getOnce checks the signal first).
    return new Promise((resolve, reject) => {
      const onAbort = () => reject(abortReasonToError(signal.reason));
      signal.addEventListener('abort', onAbort, { once: true });
      run.then(
        (v) => { signal.removeEventListener('abort', onAbort); resolve(v); },
        (e) => { signal.removeEventListener('abort', onAbort); reject(e); }
      );
    });
  }

  /* ---- poll / measure ------------------------------------------------- */

  async function poll(id, { signal, deadlineAt, deadlineMs, intervalMs = GP_LIMITS.pollIntervalMs, onUpdate } = {}) {
    assertId(id);
    throwIfAborted(signal);
    const start = now();
    let deadline;
    if (Number.isFinite(deadlineAt)) deadline = deadlineAt;
    else if (Number.isFinite(deadlineMs)) deadline = start + deadlineMs;
    else deadline = start + (GP_LIMITS.maxTimeoutS + GP_LIMITS.clientSlackS) * 1000;
    const interval = Number.isFinite(intervalMs) && intervalMs >= 0 ? intervalMs : GP_LIMITS.pollIntervalMs;
    // The median measurement finishes after ~0.8 s: a GET right after the POST would be wasted.
    await pause(interval, signal);
    for (;;) {
      const m = await get(id, { signal });
      if (typeof onUpdate === 'function') {
        try { onUpdate(m); } catch { /* observer errors are ignored */ }
      }
      if (m.status !== 'in-progress') return m;
      if (now() >= deadline) {
        throw new GlobalpingError('deadline', 'No final result from Globalping in time (the measurement can still be polled later)');
      }
      await pause(interval, signal);
    }
  }

  async function measure(body, { signal, onUpdate } = {}) {
    const created = await create(body, { signal });
    const timeoutS = Number.isFinite(body?.timeout) ? body.timeout : GP_LIMITS.maxTimeoutS;
    const deadlineAt = now() + (timeoutS + GP_LIMITS.clientSlackS) * 1000;
    try {
      const measurement = await poll(created.id, { signal, deadlineAt, onUpdate });
      return { measurement, id: created.id, cost: created.cost, quota };
    } catch (err) {
      // Already paid for: tell the caller which id to poll later instead of posting again.
      if (err && typeof err === 'object') {
        try {
          err.measurementId ??= created.id;
          err.cost ??= created.cost;
        } catch { /* frozen error object */ }
      }
      throw err;
    }
  }

  return {
    get quota() { return quota; },
    get tokenState() { return tokenState; },
    setToken,
    onQuota(fn) {
      if (typeof fn !== 'function') return () => {};
      listeners.add(fn);
      return () => { listeners.delete(fn); };
    },
    limits,
    create,
    get,
    poll,
    measure
  };
}
