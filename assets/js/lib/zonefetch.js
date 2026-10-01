/**
 * zonefetch.js — read a zone from a DNS provider's API with the user's token (Zone File › Fetch from
 * deSEC / DigitalOcean), as the provider's own JSON, which lib/zoneparse.js reads like a pasted API
 * listing (formats `desec-api`, `digitalocean-api`).
 *
 * Only providers whose API answers a browser were added: both send `Access-Control-Allow-Origin: *`
 * and allow the Authorization header in their preflight (verified 2026-10-02; Cloudflare's API and
 * the old Hetzner DNS API do not: docs/RESEARCH.md). Neither exposes
 * a response header to the page (no Access-Control-Expose-Headers): deSEC's `Link` pagination and
 * both providers' `Retry-After` / `ratelimit-*` are unreadable, so
 * - deSEC zones over 500 RRsets ("Pagination required … (N total)") are read type by type with the
 *   documented `?type=` filter, most common types first, until N RRsets are in (a type over 500
 *   brings its first 500: the listing is then incomplete, and lib/zoneparse.js says so);
 * - a 429 waits for the time deSEC writes in its answer ("Expected available in N seconds"), else
 *   a fixed pause, and gives up past {@link MAX_WAIT_MS}.
 *
 * The token: the caller passes it to {@link fetchZone}, which keeps it in a local variable for the
 * requests of that one fetch and sends it only to the provider's API host, in the Authorization
 * header (never in a URL); it is never stored, logged, returned or put in an error. Requests carry
 * no cookies or referrer and refuse redirects (a redirect would take the header elsewhere).
 *
 * DOM-free; I/O through the injectable `fetchImpl`.
 */

import { fetchAndRead, sleep, TimeoutError, AbortError, parseRetryAfter, abortReasonToError } from './util.js';
import { normalizeHostname } from './domain.js';

/**
 * The providers, in the order the UI offers them. `tokenUrl`: where the user makes a token;
 * `docsUrl`: how to make it read-only (links the user opens, never fetched).
 * @type {ReadonlyArray<{ id: string, name: string, api: string, format: string, scheme: string,
 *   tokenUrl: string, docsUrl: string }>}
 */
export const ZONE_PROVIDERS = Object.freeze([
  Object.freeze({
    id: 'desec',
    name: 'deSEC',
    api: 'https://desec.io/api/v1',
    format: 'desec-api',
    scheme: 'Token',
    tokenUrl: 'https://desec.io/tokens',
    docsUrl: 'https://desec.readthedocs.io/en/latest/auth/tokens.html#token-scoping-policies'
  }),
  Object.freeze({
    id: 'digitalocean',
    name: 'DigitalOcean',
    api: 'https://api.digitalocean.com/v2',
    format: 'digitalocean-api',
    scheme: 'Bearer',
    tokenUrl: 'https://cloud.digitalocean.com/account/api/tokens',
    docsUrl: 'https://docs.digitalocean.com/reference/api/scopes/'
  })
]);

/** Error codes of {@link ZoneFetchError} (the UI's `zone.fetch.err.<code>`). */
export const ZONE_FETCH_ERRORS = Object.freeze([
  'provider', 'domain', 'token', 'auth', 'forbidden', 'not-found', 'rate-limited', 'http', 'network', 'timeout', 'response'
]);

/**
 * deSEC's manageable RRset types (desec-stack RR_SET_TYPES_MANAGEABLE, 2026-10), the common ones
 * first, so a zone read type by type is usually complete after a few requests.
 */
export const DESEC_TYPES = Object.freeze([
  'A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'CAA', 'SRV', 'HTTPS', 'SVCB', 'TLSA', 'DS', 'PTR', 'SSHFP', 'SPF', 'CDS',
  'CDNSKEY', 'DNSKEY', 'DNAME', 'NAPTR', 'URI', 'OPENPGPKEY', 'SMIMEA', 'LOC', 'HINFO', 'RP', 'CERT', 'AFSDB', 'APL',
  'CSYNC', 'DHCID', 'DLV', 'EUI48', 'EUI64', 'KX', 'L32', 'L64', 'LP', 'NID'
]);

/** Records kept at most (= lib/zoneparse.js ZONE_LIMITS.maxRecords). */
export const MAX_RECORDS = 20000;
/** DigitalOcean's largest page. */
export const DO_PAGE_SIZE = 200;
/** Pages read at most (a listing that never ends cannot loop). */
const MAX_PAGES = Math.ceil(MAX_RECORDS / DO_PAGE_SIZE);
/** The longest a 429 is waited out before the fetch gives up. */
export const MAX_WAIT_MS = 60000;
/** The pause after a 429 that does not say how long to wait. */
export const DEFAULT_WAIT_MS = 20000;
/** 429s waited out in one fetch at most. */
const MAX_WAITS = 3;
/** Spacing between the requests of one fetch: deSEC allows 10 listings a second (and 50 a minute). */
const SPACING_MS = { desec: 150, digitalocean: 100 };
const TOKEN_RE = /^[\x21-\x7e]{16,512}$/;

/** A failed fetch: `code` from {@link ZONE_FETCH_ERRORS}, `params` for the message. Never holds the token. */
export class ZoneFetchError extends Error {
  /**
   * @param {string} code
   * @param {{ status?: number, detail?: string, retryAfterS?: number }} [params]
   */
  constructor(code, params = {}) {
    super(`zone fetch failed: ${code}${params.status ? ` (HTTP ${params.status})` : ''}`);
    this.name = 'ZoneFetchError';
    /** @type {string} */
    this.code = code;
    /** @type {object} */
    this.params = params;
  }
}

/**
 * A provider of {@link ZONE_PROVIDERS} by id.
 * @param {string} id
 * @returns {object|null}
 */
export function getZoneProvider(id) {
  return ZONE_PROVIDERS.find((p) => p.id === id) || null;
}

/**
 * A pasted token as it will be sent: surrounding white space removed, or null when it cannot be
 * one (white space or a control character inside, under 16 or over 512 characters).
 * @param {string} token
 * @returns {string|null}
 */
export function cleanToken(token) {
  const s = typeof token === 'string' ? token.trim() : '';
  return TOKEN_RE.test(s) ? s : null;
}

/**
 * The zone name a request names: a registrable-looking host name (punycode), or null.
 * @param {string} domain
 * @returns {string|null}
 */
export function zoneName(domain) {
  const host = normalizeHostname(String(domain ?? ''));
  return host && host.includes('.') ? host : null;
}

/** The provider's text in an error body (deSEC `detail`, DigitalOcean `message`), short and plain. */
function bodyDetail(body) {
  const v = body && typeof body === 'object' && !Array.isArray(body) ? (body.detail ?? body.message) : null;
  return typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, 200) : '';
}

/** Seconds a 429 answer asks for: a readable Retry-After, else deSEC's "Expected available in N seconds". */
export function retryAfterMs(res) {
  if (Number.isFinite(res.retryAfterMs) && res.retryAfterMs >= 0) return res.retryAfterMs;
  const m = /available in (\d+) seconds?/i.exec(bodyDetail(res.body));
  return m ? Number(m[1]) * 1000 : null;
}

/** "Pagination required … (N total)" → N, else null. */
export function desecTotal(body) {
  const m = /^Pagination required\b[^(]*\((\d+) total\)/.exec(bodyDetail(body));
  return m ? Number(m[1]) : null;
}

/** The error of a non-2xx answer. */
function httpFailure(res) {
  const detail = bodyDetail(res.body);
  const params = { status: res.status, ...(detail ? { detail } : {}) };
  if (res.status === 401) return new ZoneFetchError('auth', params);
  if (res.status === 403) return new ZoneFetchError('forbidden', params);
  if (res.status === 404) return new ZoneFetchError('not-found', params);
  return new ZoneFetchError('http', params);
}

/**
 * One GET with the token: `{ status, body, retryAfterMs }` (body: parsed JSON, or null).
 * Transport failures become ZoneFetchError 'network' / 'timeout'; cancellation stays an AbortError.
 */
async function apiGet(url, authorization, { fetchImpl, signal, timeoutMs }) {
  try {
    return await fetchAndRead(url, {
      fetchImpl,
      signal,
      timeoutMs,
      method: 'GET',
      headers: { authorization, accept: 'application/json' },
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
      redirect: 'error'
    }, async (res) => {
      const text = await res.text();
      let body = null;
      try {
        body = text ? JSON.parse(text) : null;
      } catch {
        body = null;
      }
      const ra = res.headers && typeof res.headers.get === 'function' ? parseRetryAfter(res.headers.get('retry-after')) : null;
      return { status: res.status, body, retryAfterMs: ra };
    });
  } catch (err) {
    if (signal && signal.aborted) throw abortReasonToError(signal.reason);
    if (err instanceof AbortError) throw err;
    if (err instanceof TimeoutError) throw new ZoneFetchError('timeout');
    throw new ZoneFetchError('network');
  }
}

/**
 * Read one zone. Resolves with the provider's listing as JSON documents (one per line) for
 * lib/zoneparse.js; rejects with a {@link ZoneFetchError} (or an AbortError when `signal` aborts).
 *
 * @param {string} providerId 'desec' | 'digitalocean'
 * @param {string} domain the zone name
 * @param {string} token the API token; used for this fetch only
 * @param {object} [opts]
 * @param {typeof fetch} [opts.fetchImpl]
 * @param {AbortSignal} [opts.signal]
 * @param {(p: { phase: 'request'|'wait', requests: number, records: number, total: number|null,
 *   waitMs?: number }) => void} [opts.onProgress]
 * @param {number} [opts.timeoutMs=20000] per request
 * @param {(ms: number, signal?: AbortSignal) => Promise<void>} [opts.sleepImpl] (tests)
 * @returns {Promise<{ provider: string, domain: string, format: string, text: string, requests: number,
 *   records: number, total: number|null, partial: boolean, byType: boolean }>}
 *   records: RRsets (deSEC) or records (DigitalOcean) read; total: what the provider said it has
 */
export async function fetchZone(providerId, domain, token, {
  fetchImpl = globalThis.fetch, signal, onProgress = null, timeoutMs = 20000, sleepImpl = sleep
} = {}) {
  const provider = getZoneProvider(providerId);
  if (!provider) throw new ZoneFetchError('provider');
  const zone = zoneName(domain);
  if (!zone) throw new ZoneFetchError('domain');
  const secret = cleanToken(token);
  if (!secret) throw new ZoneFetchError('token');
  const authorization = `${provider.scheme} ${secret}`;
  const state = { requests: 0, records: 0, total: null, waits: 0, last: 0 };
  const progress = (phase, extra = {}) => {
    if (typeof onProgress !== 'function') return;
    try {
      onProgress({ phase, requests: state.requests, records: state.records, total: state.total, ...extra });
    } catch {
      /* an observer never breaks the fetch */
    }
  };
  /** GET with spacing and 429 waits; resolves with every other answer. */
  const get = async (url) => {
    for (;;) {
      if (state.requests) await sleepImpl(SPACING_MS[provider.id], signal);
      state.requests += 1;
      progress('request');
      const res = await apiGet(url, authorization, { fetchImpl, signal, timeoutMs });
      if (res.status !== 429) return res;
      const wait = retryAfterMs(res) ?? DEFAULT_WAIT_MS;
      if (wait > MAX_WAIT_MS || state.waits >= MAX_WAITS) {
        throw new ZoneFetchError('rate-limited', { status: 429, retryAfterS: Math.ceil(wait / 1000), detail: bodyDetail(res.body) });
      }
      state.waits += 1;
      progress('wait', { waitMs: wait });
      await sleepImpl(wait, signal);
    }
  };
  const base = `${provider.api}/domains/${encodeURIComponent(zone)}`;
  const out = provider.id === 'desec' ? await readDesec(base, get, state) : await readDigitalOcean(base, get, state);
  return {
    provider: provider.id,
    domain: zone,
    format: provider.format,
    text: out.docs.map((d) => JSON.stringify(d)).join('\n'),
    requests: state.requests,
    records: state.records,
    total: state.total,
    partial: state.total !== null && state.records < state.total,
    byType: !!out.byType
  };
}

/** The fields of a deSEC RRset the parser reads (its timestamps are left out). */
const desecRrset = (s) => ({ domain: s.domain, subname: s.subname, name: s.name, type: s.type, ttl: s.ttl, records: s.records });
const isRrsetList = (body) => Array.isArray(body) && body.every((s) => s && typeof s === 'object' && Array.isArray(s.records));

/**
 * deSEC: the whole listing, or — over 500 RRsets — type by type until the total is in.
 * Docs: [rrsets] plus, when it paginated, deSEC's own "Pagination required … (N total)" answer.
 */
async function readDesec(base, get, state) {
  const first = await get(`${base}/rrsets/`);
  if (first.status === 200) {
    if (!isRrsetList(first.body)) throw new ZoneFetchError('response', { status: 200 });
    const sets = first.body.map(desecRrset);
    state.records = sets.length;
    state.total = sets.length;
    return { docs: [sets] };
  }
  const total = first.status === 400 ? desecTotal(first.body) : null;
  if (total === null) throw httpFailure(first);
  state.total = total;
  const sets = [];
  for (const type of DESEC_TYPES) {
    if (sets.length >= total || sets.length >= MAX_RECORDS) break;
    let res = await get(`${base}/rrsets/?type=${type}`);
    // Over 500 of one type: its first page (the next page's link is a header the page cannot read).
    if (res.status === 400 && desecTotal(res.body) !== null) res = await get(`${base}/rrsets/?type=${type}&cursor=`);
    if (res.status !== 200) throw httpFailure(res);
    if (!isRrsetList(res.body)) throw new ZoneFetchError('response', { status: 200 });
    for (const s of res.body) sets.push(desecRrset(s));
    state.records = sets.length;
  }
  return { docs: [sets.slice(0, MAX_RECORDS), first.body], byType: true };
}

/** DigitalOcean: every page of 200 (`meta.total` says how many), merged into one listing. */
async function readDigitalOcean(base, get, state) {
  const records = [];
  let total = null;
  for (let page = 1; ; page += 1) {
    const res = await get(`${base}/records?per_page=${DO_PAGE_SIZE}&page=${page}`);
    if (res.status !== 200) throw httpFailure(res);
    const list = res.body && Array.isArray(res.body.domain_records) ? res.body.domain_records : null;
    if (!list) throw new ZoneFetchError('response', { status: 200 });
    const t = res.body.meta && Number.isInteger(res.body.meta.total) ? res.body.meta.total : null;
    if (t !== null) total = Math.max(total ?? 0, t);
    records.push(...list);
    state.records = records.length;
    state.total = total;
    const more = res.body.links && res.body.links.pages && typeof res.body.links.pages.next === 'string';
    if (!list.length || records.length >= MAX_RECORDS || page >= MAX_PAGES) break;
    if (total !== null ? records.length >= total : !more) break;
  }
  if (total === null) state.total = records.length;
  return { docs: [{ domain_records: records.slice(0, MAX_RECORDS), meta: { total: state.total } }] };
}
