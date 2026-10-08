/**
 * sourcestatus.js — "no silent dashes": what a failed data source means for the cells it feeds.
 *
 * IP Intel, Domain Health and DNS Lookup read several third-party sources (RIPEstat, ipwho.is,
 * reverse DNS, RDAP, HackerTarget, the DoH resolvers). When one of them answers 429 or fails,
 * the fields it would have filled stay empty, and an empty cell reads as "no data". This
 * module turns a failure into a status the views render as "⚠ n/a" with an explanation
 * ("RIPEstat: rate limited — try again in 5 min") and says which empty fields a failure
 * explains, so a Retry can re-query exactly that source.
 *
 * Pure: no DOM, network, storage or i18n. Reasons are codes (`srcst.reason.<reason>` in the
 * UI) with their parameters; the clock is injectable.
 */

/**
 * The sources a status can name. `period` is the quota window a rate limit of that service
 * usually lasts when it does not say itself (a browser can read `Retry-After` only when the
 * service exposes it to CORS): 'day' | 'hour' | 'minutes' | null (unknown).
 * @type {Readonly<Record<string, { period: 'day'|'hour'|'minutes'|null }>>}
 */
export const STATUS_SOURCES = Object.freeze({
  ripestat: Object.freeze({ period: 'minutes' }),
  'ripestat-geo': Object.freeze({ period: 'minutes' }),
  ipwhois: Object.freeze({ period: null }),
  ptr: Object.freeze({ period: 'minutes' }),
  hackertarget: Object.freeze({ period: 'day' }),
  rdap: Object.freeze({ period: 'minutes' }),
  doh: Object.freeze({ period: 'minutes' }),
  // Certificate Transparency (the Domain overview's issuer lookup): Cert Spotter's anonymous
  // single-host quota is hourly; crt.sh has no published quota.
  certspotter: Object.freeze({ period: 'hour' }),
  crtsh: Object.freeze({ period: null }),
  // IP Intel › Check routing (lib/ipenrich.js): RIPEstat's data calls, and PeeringDB, whose
  // anonymous throttle pauses for seconds (it says 10).
  'ripestat-network': Object.freeze({ period: 'minutes' }),
  'ripestat-rpki': Object.freeze({ period: 'minutes' }),
  'ripestat-routing': Object.freeze({ period: 'minutes' }),
  'ripestat-abuse': Object.freeze({ period: 'minutes' }),
  peeringdb: Object.freeze({ period: 'minutes' }),
  // Domains on this IP (lib/reverseip.js): ip.thc.org's bucket refills in seconds, InternetDB's
  // burst lock lasts about an hour (its lock is timed by lib/reverseip.js), Shodan's API takes one
  // request a second; OTX, Robtex and WhoisXML publish no window. The workspace never fails.
  thc: Object.freeze({ period: 'minutes' }),
  otx: Object.freeze({ period: null }),
  robtex: Object.freeze({ period: null }),
  internetdb: Object.freeze({ period: 'hour' }),
  shodan: Object.freeze({ period: 'minutes' }),
  whoisxml: Object.freeze({ period: null }),
  workspace: Object.freeze({ period: null }),
  // Renewal readiness › Plan: Let's Encrypt's ARI window (no published quota for it)
  ari: Object.freeze({ period: null }),
  // Google's CT log list (Certificate › Transparency): a static file, no quota.
  ctloglist: Object.freeze({ period: null }),
  // Domain Health › Web: Mozilla's HTTP Observatory answers a recent scan of a host from its cache.
  observatory: Object.freeze({ period: 'minutes' })
});

/** Every reason code {@link sourceStatus} can return (`srcst.reason.<code>` in the UI). */
export const STATUS_REASONS = Object.freeze([
  'rate-limit-wait', 'rate-limit-now', 'rate-limit-day', 'rate-limit-hour', 'rate-limit-minutes', 'rate-limit',
  'timeout', 'network', 'unavailable', 'http-status', 'http', 'rcode', 'parse', 'unknown'
]);

/**
 * Which sources fill each IP Intel field (lib/ipintel.js IpInfo): the primary one first, then its
 * fallback. `network` is the origin AS and its holder, `location` the country and city.
 * @type {Readonly<Record<string, ReadonlyArray<string>>>}
 */
export const IP_FIELD_SOURCES = Object.freeze({
  ptr: Object.freeze(['ptr']),
  network: Object.freeze(['ripestat', 'ipwhois']),
  prefix: Object.freeze(['ripestat']),
  location: Object.freeze(['ripestat-geo', 'ipwhois'])
});

/** The fields of {@link IP_FIELD_SOURCES}, in table order. */
export const IP_FIELDS = Object.freeze(Object.keys(IP_FIELD_SOURCES));

/**
 * A cell a failed source left empty, in a CSV or JSON export (IP Intel, Bulk Resolve): the same
 * token in every UI language, so a script can read the file.
 */
export const EXPORT_NA = 'n/a';

/**
 * Chip groups of IP Intel: one chip per service (RIPEstat's two datasets are one service).
 * @type {Readonly<Record<string, ReadonlyArray<string>>>}
 */
export const IP_SOURCE_GROUPS = Object.freeze({
  ripestat: Object.freeze(['ripestat', 'ripestat-geo']),
  ipwhois: Object.freeze(['ipwhois']),
  ptr: Object.freeze(['ptr'])
});

const MINUTE = 60 * 1000;

/**
 * @typedef {object} SourceFailure
 * @property {string} source a {@link STATUS_SOURCES} id (any string is accepted)
 * @property {string|null} [error] technical message ('HTTP 429', 'Network error …')
 * @property {string|null} [errorKind] util.errorKind() ('rate-limit', 'timeout', …) or 'unavailable'
 * @property {number|null} [status] HTTP status, when the service answered one
 * @property {number|null} [retryAfterMs] the service's Retry-After, when readable
 * @property {boolean} [limited] the service said its quota is used up (HackerTarget's 200 text)
 * @property {string|null} [rcode] the DNS rcode of a lookup that was answered but not usable (SERVFAIL, REFUSED …)
 * @property {number|Date|null} [at] when the failure happened (ms or Date; default: now)
 */

/**
 * @typedef {object} SourceStatus
 * @property {string} source
 * @property {'rate-limit'|'timeout'|'network'|'unavailable'|'http'|'rcode'|'parse'|'unknown'} kind
 * @property {string} reason one of {@link STATUS_REASONS}
 * @property {Record<string, number|string>} params reason parameters: `{ minutes }` (rate-limit-wait), `{ status }`
 *   (http-status), `{ rcode }` (rcode: 'SERVFAIL', 'REFUSED' …)
 * @property {Date|null} retryAt when the service said it takes requests again
 * @property {string|null} detail the technical message, for a details line or a tooltip
 */

/**
 * The status of one failed lookup: why the source gave nothing and, for a rate limit, when to
 * try again — the service's own Retry-After (counted from the failure) when it sent one, else
 * the service's usual quota window.
 * @param {SourceFailure} failure
 * @param {{ now?: number }} [opts]
 * @returns {SourceStatus}
 */
export function sourceStatus(failure, { now = Date.now() } = {}) {
  const f = failure && typeof failure === 'object' ? failure : {};
  const source = String(f.source ?? '');
  const detail = typeof f.error === 'string' && f.error ? f.error : null;
  const status = httpStatusOf(f);
  const kind = failureKind(f, status);
  const out = { source, kind, reason: 'unknown', params: {}, retryAt: null, detail };
  if (kind === 'rate-limit') {
    const at = f.at instanceof Date ? f.at.getTime() : Number.isFinite(f.at) ? Number(f.at) : now;
    const wait = Number.isFinite(f.retryAfterMs) && f.retryAfterMs >= 0 ? Number(f.retryAfterMs) : null;
    if (wait !== null) {
      out.retryAt = new Date(at + wait);
      const left = out.retryAt.getTime() - now;
      // Rounded up: "in 1 min" rather than "in 0 min" while a few seconds are left.
      if (left > 0) {
        out.reason = 'rate-limit-wait';
        out.params = { minutes: Math.max(1, Math.ceil(left / MINUTE)) };
        return out;
      }
    }
    const period = (STATUS_SOURCES[source] || {}).period || null;
    // A Retry-After that has run out: the service takes requests again.
    out.reason = wait !== null ? 'rate-limit-now' : period ? `rate-limit-${period}` : 'rate-limit';
    return out;
  }
  if (kind === 'http' && status) {
    out.reason = 'http-status';
    out.params = { status };
    return out;
  }
  if (kind === 'rcode') {
    out.reason = 'rcode';
    out.params = { rcode: rcodeOf(f) };
    return out;
  }
  out.reason = kind;
  return out;
}

/** HTTP status of a failure: the `status` field, else read from an 'HTTP 429 …' message. */
function httpStatusOf(f) {
  if (Number.isInteger(f.status) && f.status >= 100 && f.status <= 599) return f.status;
  const m = /\bHTTP (\d{3})\b/.exec(String(f.error ?? ''));
  return m ? Number(m[1]) : null;
}

/** The rcode of a failure that got a DNS answer (upper case), else null. */
function rcodeOf(f) {
  return typeof f.rcode === 'string' && /^[A-Za-z0-9]{1,16}$/.test(f.rcode) ? f.rcode.toUpperCase() : null;
}

function failureKind(f, status) {
  if (f.limited === true || status === 429) return 'rate-limit';
  if (rcodeOf(f)) return 'rcode';
  const k = typeof f.errorKind === 'string' ? f.errorKind : null;
  if (k === 'rate-limit' || k === 'timeout' || k === 'network' || k === 'unavailable' || k === 'parse') return k;
  if (k === 'http' || status) return 'http';
  return 'unknown';
}

/**
 * Is `value` empty for display (null, '', an empty list)?
 * @param {unknown} value
 * @returns {boolean}
 */
function isEmpty(value) {
  return value === null || value === undefined || value === '' || (Array.isArray(value) && value.length === 0);
}

/** The value of an IP Intel field of an IpInfo (empty when not known). */
function ipFieldValue(info, field) {
  switch (field) {
    case 'ptr': return info.ptr;
    case 'network': return info.asn ?? info.holder ?? null;
    case 'prefix': return info.prefix;
    case 'location': return info.country;
    default: return null;
  }
}

/**
 * Why an IP Intel field is empty, when a failure explains it: null when the field has a value,
 * when nothing that feeds it failed (the empty value is then a real "none", e.g. no PTR record),
 * for a private address and for an info still pending. Otherwise the statuses of the failed
 * sources that feed the field, primary first.
 * @param {object|null} info lib/ipintel.js IpInfo (`errors[]`: { source, error, errorKind, status?, retryAfterMs?, at? })
 * @param {string} field one of {@link IP_FIELDS}
 * @param {{ now?: number }} [opts]
 * @returns {{ field: string, sources: string[], statuses: SourceStatus[] }|null}
 */
export function ipFieldStatus(info, field, { now = Date.now() } = {}) {
  if (!info || typeof info !== 'object' || info.private || !IP_FIELD_SOURCES[field]) return null;
  if (!isEmpty(ipFieldValue(info, field))) return null;
  const errors = Array.isArray(info.errors) ? info.errors : [];
  const statuses = [];
  for (const source of IP_FIELD_SOURCES[field]) {
    const e = errors.find((x) => x && x.source === source);
    if (e) statuses.push(sourceStatus(e, { now }));
  }
  return statuses.length ? { field, sources: statuses.map((s) => s.source), statuses } : null;
}

/**
 * The sources a Retry of one IP Intel row re-queries: every source that failed and left a field
 * empty (a failed fallback whose primary answered is not worth a request, nor is a failure whose
 * field another source filled).
 * @param {object|null} info IpInfo
 * @returns {string[]} source ids, in {@link IP_FIELD_SOURCES} order, unique
 */
export function ipRetrySources(info) {
  const out = [];
  for (const field of IP_FIELDS) {
    const st = ipFieldStatus(info, field);
    if (!st) continue;
    for (const s of st.sources) if (!out.includes(s)) out.push(s);
  }
  return out;
}

/**
 * @typedef {object} SourceChip
 * @property {string} id chip id (a {@link IP_SOURCE_GROUPS} key)
 * @property {'pending'|'ok'|'idle'|'failed'} state idle = never needed (a fallback nobody used)
 * @property {number} rows rows that used the source
 * @property {number} failed rows where it failed and left a field empty
 * @property {string[]} ips the addresses of those rows
 * @property {string[]} sources the failed source ids of the group (what a chip Retry re-queries)
 * @property {SourceStatus|null} status the most recent failure's status
 */

/**
 * One status chip per service over a table of IP Intel rows (the Subdomains source-chip pattern):
 * how many rows each service answered and where its failure left a field empty. Only a row still
 * being looked up (`pending`) makes a chip pending: a row a stopped run never asked (no info, not
 * pending) counts for nothing.
 * @param {Array<{ ip: string, info: object|null, pending?: boolean }>} rows
 * @param {{ now?: number }} [opts]
 * @returns {SourceChip[]} in {@link IP_SOURCE_GROUPS} order
 */
export function ipSourceChips(rows, { now = Date.now() } = {}) {
  const list = Array.isArray(rows) ? rows : [];
  const pending = list.some((r) => r && r.pending === true && !(r.info && r.info.private));
  return Object.entries(IP_SOURCE_GROUPS).map(([id, members]) => {
    let used = 0;
    const ips = [];
    const failedSources = new Set();
    let latest = null;
    for (const r of list) {
      const info = r && r.info;
      if (!info || info.private) continue;
      const errs = (info.errors || []).filter((e) => e && members.includes(e.source));
      if (errs.length || (info.sources || []).some((s) => sourceGroupOf(s) === id)) used += 1;
      const retry = ipRetrySources(info).filter((s) => members.includes(s));
      if (!retry.length) continue;
      ips.push(r.ip);
      retry.forEach((s) => failedSources.add(s));
      for (const e of errs.filter((x) => retry.includes(x.source))) {
        const at = e.at instanceof Date ? e.at.getTime() : Number(e.at) || 0;
        if (!latest || at >= latest.at) latest = { at, e };
      }
    }
    let state = 'ok';
    if (ips.length) state = 'failed';
    else if (pending) state = 'pending';
    else if (!used) state = 'idle';
    return {
      id,
      state,
      rows: used,
      failed: ips.length,
      ips,
      sources: members.filter((s) => failedSources.has(s)),
      status: latest ? sourceStatus(latest.e, { now }) : null
    };
  });
}

/**
 * The chip group of a source id of IpInfo.sources / errors[] ('dns' reverse lookups count as 'ptr').
 * @param {string} source
 * @returns {string|null}
 */
export function sourceGroupOf(source) {
  if (source === 'dns') return 'ptr';
  for (const [id, members] of Object.entries(IP_SOURCE_GROUPS)) if (members.includes(source)) return id;
  return null;
}

/**
 * The RDAP fields of Domain Health that a failed registration lookup leaves unknown: null when
 * RDAP answered, was not asked, or gave a real answer that is not data (the TLD publishes no
 * RDAP, the domain is not registered); else the failure's status.
 * @param {object|null} rdap lib/rdap.js rdapDomain() result (extensions: httpStatus, retryAfterMs, failedAt)
 * @param {{ now?: number }} [opts]
 * @returns {SourceStatus|null}
 */
export function rdapStatus(rdap, { now = Date.now() } = {}) {
  if (!rdap || typeof rdap !== 'object' || rdap.ok || rdap.unsupportedTld || rdap.notFound) return null;
  if (rdap.errorKind === 'invalid' || rdap.errorKind === 'unsupported') return null;
  return sourceStatus({
    source: 'rdap', error: rdap.error, errorKind: rdap.errorKind, status: rdap.httpStatus, retryAfterMs: rdap.retryAfterMs, at: rdap.failedAt
  }, { now });
}

/**
 * The status of a failed DoH query (lib/doh.js DnsResponse with ok: false); null for an answer.
 * @param {object|null} response
 * @param {{ now?: number }} [opts]
 * @returns {SourceStatus|null}
 */
export function dohStatus(response, { now = Date.now() } = {}) {
  if (!response || typeof response !== 'object' || response.ok !== false) return null;
  if (response.errorKind === 'abort') return null;
  return sourceStatus({ source: 'doh', error: response.error, errorKind: response.errorKind, retryAfterMs: response.retryAfterMs }, { now });
}
