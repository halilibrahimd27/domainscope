/**
 * ipintel.js — IP intelligence: PTR, origin ASN / AS holder / announced
 * prefix, country / city, CDN / platform provider, and "other domains on
 * this IP" (reverse IP).
 *
 * Data sources (all CORS-enabled, verified live 2026-09-23 with an Origin header):
 *  - RIPEstat (global routing data, not just the RIPE region; `sourceapp` is
 *    always sent as RIPE NCC asks):
 *      prefix-overview   → data.asns[{asn, holder}], data.resource (prefix), data.announced, data.block.desc (RIR)
 *      maxmind-geo-lite  → data.located_resources[0].locations[{country, city, covered_percentage}]
 *      reverse-dns-ip    → data.result[] (PTR fallback when no DNS client is injected)
 *  - ipwho.is (fallback geo / ASN): { success, message?, country_code, city, connection: { asn, org, isp, domain } }
 *  - HackerTarget reverseiplookup (text, one host per line). Errors and quota
 *    exhaustion come back as HTTP 200 text ("API count exceeded ...", "error ...").
 *    The free quota (~50/day per IP) is shared with the hostsearch source.
 *
 * Private / reserved addresses (netinfo.isPrivateIP) never leave the browser.
 * DOM-free; runs in browsers and Node 22. All I/O is injectable (`fetchImpl`, `dns`).
 */

import {
  fetchJson, fetchText, retry, createLimiter, createCache, errorKind,
  throwIfAborted, abortReasonToError, HttpError, uniq
} from './util.js';
import { normalizeIP, ipVersion, isPrivateIP, matchProviderByIP } from './netinfo.js';
import { normalizeHostname, sortHostnames } from './domain.js';

/** RIPEstat Data API base URL. */
export const RIPESTAT_BASE = 'https://stat.ripe.net/data';
/** `sourceapp` value sent with every RIPEstat request (RIPE NCC fair-use policy). */
export const RIPESTAT_SOURCEAPP = 'domainscope';
/** ipwho.is base URL (fallback geo / ASN). */
export const IPWHOIS_BASE = 'https://ipwho.is';
/** HackerTarget reverse-IP endpoint (quota shared with hostsearch). */
export const HACKERTARGET_REVERSE_IP = 'https://api.hackertarget.com/reverseiplookup/';

const DEFAULT_TIMEOUT_MS = 12000;
const INFO_TTL_MS = 60 * 60 * 1000; // routing / geo data change slowly
const REVERSE_TTL_MS = 30 * 60 * 1000;

/**
 * @typedef {object} IpInfo
 * @property {string} ip canonical address (netinfo.normalizeIP; IPv4-mapped IPv6 is reported as the
 *   IPv4 address; the raw input when invalid)
 * @property {4|6|0} version 0 when the input is not an IP address
 * @property {boolean} private true for private / loopback / link-local / CGNAT … (no lookups made)
 * @property {object|null} provider netinfo PROVIDERS entry whose published ranges contain the IP
 * @property {string[]} ptr reverse DNS names (lowercase, no trailing dot)
 * @property {number|null} asn origin AS number
 * @property {string|null} asName short AS name, e.g. 'GOOGLE', 'CLOUDFLARENET'
 * @property {string|null} holder AS holder organisation, e.g. 'Google LLC'
 * @property {string|null} prefix announced (covering) prefix, e.g. '8.8.8.0/24'
 * @property {string|null} country ISO 3166-1 alpha-2 (uppercase)
 * @property {string|null} city
 * @property {string[]} sources contributing sources: 'ripestat' | 'ipwhois' | 'dns'
 * @property {string|null} error set only when nothing could be learned
 * @property {string|null} errorKind extension: util.errorKind() of `error` ('invalid' for bad input)
 * @property {Array<{ source: string, error: string, errorKind: string }>} errors extension: every partial failure
 * @property {Array<{ asn: number, holder: string|null }>} asns extension: all origin ASes (MOAS prefixes have several)
 * @property {boolean|null} announced extension: RIPEstat says the IP is routed (null when unknown)
 * @property {string|null} rir extension: 'ARIN' | 'RIPE NCC' | 'APNIC' | 'LACNIC' | 'AFRINIC' (from the IANA block)
 */

/**
 * @typedef {object} ReverseIpResult
 * @property {boolean} ok
 * @property {string[]} domains hostnames seen on the IP (sortHostnames order)
 * @property {string|null} error
 * @property {boolean} limited true when the (daily) API quota is exhausted
 * @property {string|null} errorKind extension
 */

/* ------------------------------------------------------------------------ */
/* Pure parsers (exported for tests and reuse)                              */
/* ------------------------------------------------------------------------ */

const RIRS = [
  [/\bARIN\b/i, 'ARIN'],
  [/\bRIPE\b/i, 'RIPE NCC'],
  [/\bAPNIC\b/i, 'APNIC'],
  [/\bLACNIC\b/i, 'LACNIC'],
  [/\bAFRINIC\b/i, 'AFRINIC']
];

/**
 * Split a RIPEstat AS holder string ("GOOGLE - Google LLC") into the short AS
 * name and the organisation. Strings without the " - " separator (e.g.
 * "TTNet Turk Telekomunikasyon Anonim Sirketi") are used for both.
 * @param {string|null|undefined} holder
 * @returns {{ asName: string|null, holder: string|null }}
 */
export function splitAsHolder(holder) {
  const s = typeof holder === 'string' ? holder.trim() : '';
  if (!s) return { asName: null, holder: null };
  const m = /^(\S+)\s+-\s+(.+)$/.exec(s);
  if (m) return { asName: m[1], holder: m[2].trim() };
  return { asName: s, holder: s };
}

function ripeData(json) {
  if (!json || typeof json !== 'object') throw new SyntaxError('RIPEstat: empty response');
  if (json.status && json.status !== 'ok') {
    const msg = Array.isArray(json.messages) ? json.messages.map((m) => (Array.isArray(m) ? m[1] : m)).join('; ') : '';
    throw new Error(`RIPEstat: ${msg || json.status}`);
  }
  if (!json.data || typeof json.data !== 'object') throw new SyntaxError('RIPEstat: response has no data');
  return json.data;
}

/**
 * Parse a RIPEstat prefix-overview response.
 * @param {object} json full response ({ status, data: { asns, resource, announced, block } })
 * @returns {{ asn: number|null, asName: string|null, holder: string|null, prefix: string|null,
 *   announced: boolean|null, asns: Array<{ asn: number, holder: string|null }>, rir: string|null }}
 * @throws {Error} when the response reports an error or has no data
 */
export function parsePrefixOverview(json) {
  const data = ripeData(json);
  const asns = (Array.isArray(data.asns) ? data.asns : [])
    .filter((a) => a && Number.isInteger(Number(a.asn)) && Number(a.asn) > 0)
    .map((a) => ({ asn: Number(a.asn), holder: typeof a.holder === 'string' && a.holder.trim() ? a.holder.trim() : null }));
  const first = asns[0] || null;
  const names = splitAsHolder(first ? first.holder : null);
  const resource = typeof data.resource === 'string' ? data.resource.trim() : '';
  const announced = typeof data.announced === 'boolean' ? data.announced : null;
  const blockDesc = data.block && typeof data.block.desc === 'string' ? data.block.desc : '';
  const rirHit = RIRS.find(([re]) => re.test(blockDesc));
  return {
    asn: first ? first.asn : null,
    asName: names.asName,
    holder: names.holder,
    // RIPEstat echoes the bare IP when nothing covers it; only a real prefix counts.
    prefix: announced !== false && resource.includes('/') ? resource : null,
    announced,
    asns,
    rir: rirHit ? rirHit[1] : null
  };
}

/**
 * Parse a RIPEstat maxmind-geo-lite response. When several locations are
 * listed the one with the highest `covered_percentage` wins.
 * @param {object} json
 * @returns {{ country: string|null, city: string|null }}
 */
export function parseGeoLite(json) {
  const data = ripeData(json);
  const located = Array.isArray(data.located_resources) ? data.located_resources : [];
  let best = null;
  for (const res of located) {
    for (const loc of Array.isArray(res?.locations) ? res.locations : []) {
      if (!loc || typeof loc !== 'object') continue;
      const cov = Number(loc.covered_percentage);
      if (!best || (Number.isFinite(cov) ? cov : 0) > best.cov) best = { loc, cov: Number.isFinite(cov) ? cov : 0 };
    }
  }
  if (!best) return { country: null, city: null };
  return { country: cleanCountry(best.loc.country), city: cleanText(best.loc.city) };
}

/**
 * Parse an ipwho.is response.
 * @param {object} json
 * @returns {{ asn: number|null, holder: string|null, isp: string|null, country: string|null, city: string|null }}
 * @throws {Error} when `success` is false (message e.g. 'Reserved range', quota errors)
 */
export function parseIpwhois(json) {
  if (!json || typeof json !== 'object') throw new SyntaxError('ipwho.is: empty response');
  if (json.success === false) {
    const err = new Error(`ipwho.is: ${cleanText(json.message) || 'lookup failed'}`);
    if (/limit|quota|too many/i.test(String(json.message || ''))) err.kind = 'rate-limit';
    throw err;
  }
  const conn = json.connection && typeof json.connection === 'object' ? json.connection : {};
  const asn = Number(conn.asn);
  return {
    asn: Number.isInteger(asn) && asn > 0 ? asn : null,
    holder: cleanText(conn.org) || cleanText(conn.isp),
    isp: cleanText(conn.isp),
    country: cleanCountry(json.country_code),
    city: cleanText(json.city)
  };
}

/**
 * Parse a RIPEstat reverse-dns-ip response into PTR names.
 * @param {object} json
 * @returns {string[]}
 */
export function parseRipeReverseDns(json) {
  const data = ripeData(json);
  const list = Array.isArray(data.result) ? data.result : [];
  return cleanNames(list);
}

/**
 * Interpret a HackerTarget reverseiplookup body (always HTTP 200, text).
 * @param {string} text
 * @returns {ReverseIpResult}
 */
export function parseReverseIpText(text) {
  const body = String(text ?? '').replace(/^﻿/, '').trim();
  const fail = (error, limited = false) => ({
    ok: false, domains: [], error, limited, errorKind: limited ? 'rate-limit' : 'http'
  });
  if (/api count exceeded|increase quota|rate limit|too many requests/i.test(body)) return fail(firstLine(body), true);
  if (/^error\b/i.test(body)) return fail(firstLine(body));
  if (!body || /^no (dns )?(a )?records? found/i.test(body) || /^no records/i.test(body)) {
    return { ok: true, domains: [], error: null, limited: false, errorKind: null };
  }
  const domains = [];
  let bad = 0;
  for (const line of body.split(/\r?\n/)) {
    const token = line.split(',')[0].trim();
    if (!token) continue;
    const host = normalizeHostname(token);
    if (host) domains.push(host);
    else bad += 1;
  }
  if (domains.length === 0 && bad > 0) return fail(`Unexpected response: ${firstLine(body)}`);
  return { ok: true, domains: sortHostnames(uniq(domains)), error: null, limited: false, errorKind: null };
}

function firstLine(s) {
  return String(s).split(/\r?\n/)[0].trim().slice(0, 200);
}

function cleanText(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return s ? s : null;
}

function cleanCountry(v) {
  const s = cleanText(v);
  return s && /^[a-z]{2}$/i.test(s) ? s.toUpperCase() : null;
}

function cleanNames(list) {
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    if (typeof raw !== 'string') continue;
    const host = normalizeHostname(raw, { allowSingleLabel: true });
    if (host) out.push(host);
  }
  return uniq(out);
}

/* ------------------------------------------------------------------------ */
/* Service                                                                  */
/* ------------------------------------------------------------------------ */

function isAbort(err) {
  return errorKind(err) === 'abort';
}

function describe(err) {
  if (!err) return 'Unknown error';
  if (err instanceof HttpError) return `HTTP ${err.status}`;
  return String(err.message || err);
}

/**
 * Wait for `promise` but stop early (AbortError) when `signal` aborts.
 * The underlying work keeps running for other waiters.
 */
function withSignal(promise, signal) {
  if (!signal) return promise;
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortReasonToError(signal.reason));
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (v) => { signal.removeEventListener('abort', onAbort); resolve(v); },
      (e) => { signal.removeEventListener('abort', onAbort); reject(e); }
    );
  });
}

/**
 * Share one in-flight promise per key between concurrent callers. If the
 * caller that started the work aborts, the others transparently restart it
 * with their own signal instead of inheriting the AbortError.
 */
async function shared(map, key, signal, factory) {
  for (;;) {
    throwIfAborted(signal);
    let entry = map.get(key);
    if (!entry) {
      entry = { promise: factory(signal) };
      map.set(key, entry);
      const e = entry;
      e.promise.then(() => {}, () => {}).then(() => {
        if (map.get(key) === e) map.delete(key);
      });
    }
    try {
      return await withSignal(entry.promise, signal);
    } catch (err) {
      if (isAbort(err) && !signal?.aborted) {
        if (map.get(key) === entry) map.delete(key);
        continue;
      }
      throw err;
    }
  }
}

function emptyInfo(ip, version) {
  return {
    ip,
    version,
    private: false,
    provider: null,
    ptr: [],
    asn: null,
    asName: null,
    holder: null,
    prefix: null,
    country: null,
    city: null,
    sources: [],
    error: null,
    errorKind: null,
    errors: [],
    asns: [],
    announced: null,
    rir: null
  };
}

/**
 * Create an IP intelligence service with its own cache and request limiter.
 *
 * - `info(ip)` never rejects except with AbortError/TimeoutError-from-signal
 *   when the caller's `signal` aborts; every other failure is reported in the
 *   result (`error` when nothing was learned, `errors[]` for partial failures).
 * - Order: RIPEstat prefix-overview + maxmind-geo-lite (in parallel), then
 *   ipwho.is only to fill what RIPEstat could not answer. PTR comes from
 *   `dns.ptr()` (DohClient) or, without a DNS client, RIPEstat reverse-dns-ip.
 * - Results are cached per IP (1 h; complete failures are not cached) and
 *   concurrent calls for the same IP share one lookup.
 * - `concurrency` bounds simultaneous HTTP requests to the intel APIs
 *   (RIPEstat asks for ≤ 8 concurrent requests per client).
 *
 * @param {{ fetchImpl?: typeof fetch, dns?: { ptr?: Function }|null, concurrency?: number,
 *   timeoutMs?: number, retries?: number, cacheSize?: number, hackertargetApiKey?: string|null,
 *   ipwhois?: boolean }} [opts]
 *   Extensions: timeoutMs (per request, default 12000), retries (default 1),
 *   cacheSize, hackertargetApiKey (member key appended as &apikey=),
 *   ipwhois (false disables the ipwho.is fallback).
 * @returns {{ info: (ip: string, opts?: { signal?: AbortSignal, noCache?: boolean }) => Promise<IpInfo>,
 *   reverseIp: (ip: string, opts?: { signal?: AbortSignal, noCache?: boolean }) => Promise<ReverseIpResult>,
 *   clearCache: () => void, setConcurrency: (n: number) => void }}
 */
export function createIpIntel({
  fetchImpl = globalThis.fetch,
  dns = null,
  concurrency = 4,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  retries = 1,
  cacheSize = 2000,
  hackertargetApiKey = null,
  ipwhois = true
} = {}) {
  const limiter = createLimiter(concurrency);
  const infoCache = createCache({ maxEntries: cacheSize, ttlMs: INFO_TTL_MS });
  const reverseCache = createCache({ maxEntries: cacheSize, ttlMs: REVERSE_TTL_MS });
  const infoInflight = new Map();
  const reverseInflight = new Map();

  const getJson = (url, signal) => limiter.run(
    () => retry(() => fetchJson(url, { fetchImpl, signal, timeoutMs, headers: { accept: 'application/json' } }), {
      retries, signal, baseDelayMs: 400, maxDelayMs: 4000
    }),
    { signal }
  );

  const ripeUrl = (call, ip) => `${RIPESTAT_BASE}/${call}/data.json?resource=${ip}&sourceapp=${RIPESTAT_SOURCEAPP}`;

  async function lookupPtr(ip, signal) {
    if (dns && typeof dns.ptr === 'function') {
      const names = await dns.ptr(ip, { signal });
      return { names: cleanNames(names), source: 'dns' };
    }
    const json = await getJson(ripeUrl('reverse-dns-ip', ip), signal);
    return { names: parseRipeReverseDns(json), source: 'ripestat' };
  }

  async function lookupInfo(ip, version, signal) {
    const out = emptyInfo(ip, version);
    out.provider = matchProviderByIP(ip);
    const addSource = (s) => { if (!out.sources.includes(s)) out.sources.push(s); };
    const fail = (source, err) => {
      if (isAbort(err) && signal?.aborted) throw err;
      out.errors.push({ source, error: describe(err), errorKind: errorKind(err) });
    };

    const [ptrRes, poRes, geoRes] = await Promise.allSettled([
      lookupPtr(ip, signal),
      getJson(ripeUrl('prefix-overview', ip), signal).then(parsePrefixOverview),
      getJson(ripeUrl('maxmind-geo-lite', ip), signal).then(parseGeoLite)
    ]);
    throwIfAborted(signal);

    if (ptrRes.status === 'fulfilled') {
      out.ptr = ptrRes.value.names;
      addSource(ptrRes.value.source);
    } else {
      fail('ptr', ptrRes.reason);
    }
    if (poRes.status === 'fulfilled') {
      const po = poRes.value;
      Object.assign(out, {
        asn: po.asn, asName: po.asName, holder: po.holder, prefix: po.prefix,
        announced: po.announced, asns: po.asns, rir: po.rir
      });
      addSource('ripestat');
    } else {
      fail('ripestat', poRes.reason);
    }
    if (geoRes.status === 'fulfilled') {
      out.country = geoRes.value.country;
      out.city = geoRes.value.city;
      addSource('ripestat');
    } else {
      fail('ripestat-geo', geoRes.reason);
    }

    // Fallback only for what is still missing (and not for unrouted space,
    // where ipwho.is would only answer "Reserved range").
    const unrouted = poRes.status === 'fulfilled' && out.announced === false;
    const needAsn = out.asn === null && !unrouted;
    const needGeo = out.country === null && !unrouted;
    if (ipwhois && (needAsn || needGeo)) {
      try {
        const w = parseIpwhois(await getJson(`${IPWHOIS_BASE}/${ip}`, signal));
        let used = false;
        if (needAsn && w.asn !== null) {
          out.asn = w.asn;
          out.holder = out.holder || w.holder;
          out.asns = [{ asn: w.asn, holder: w.holder }];
          used = true;
        }
        if (needGeo && w.country) {
          out.country = w.country;
          out.city = out.city || w.city;
          used = true;
        }
        if (used) addSource('ipwhois');
      } catch (err) {
        fail('ipwhois', err);
      }
    }

    const learned = out.asn !== null || out.country !== null || out.ptr.length > 0 || out.announced !== null;
    if (!learned && out.errors.length) {
      out.error = out.errors.map((e) => `${e.source}: ${e.error}`).join('; ');
      out.errorKind = out.errors[0].errorKind;
    }
    return out;
  }

  /**
   * Look up everything known about one IP address.
   * @param {string} ip
   * @param {{ signal?: AbortSignal, noCache?: boolean }} [opts]
   * @returns {Promise<IpInfo>}
   */
  async function info(ip, { signal, noCache = false } = {}) {
    throwIfAborted(signal);
    const canonical = lookupForm(ip);
    if (!canonical) {
      const out = emptyInfo(String(ip ?? ''), 0);
      out.error = 'Invalid IP address';
      out.errorKind = 'invalid';
      return out;
    }
    const version = ipVersion(canonical);
    if (isPrivateIP(canonical)) {
      const out = emptyInfo(canonical, version);
      out.private = true;
      return out;
    }
    if (!noCache) {
      const hit = infoCache.get(canonical);
      if (hit) return cloneInfo(hit);
    }
    const result = await shared(infoInflight, canonical, signal, async (sig) => {
      const res = await lookupInfo(canonical, version, sig);
      if (!res.error) infoCache.set(canonical, res);
      return res;
    });
    return cloneInfo(result);
  }

  /**
   * Other hostnames pointing at `ip` (HackerTarget). Quota exhaustion is
   * reported as `{ ok: false, limited: true }`, never thrown.
   * @param {string} ip
   * @param {{ signal?: AbortSignal, noCache?: boolean }} [opts]
   * @returns {Promise<ReverseIpResult>}
   */
  async function reverseIp(ip, { signal, noCache = false } = {}) {
    throwIfAborted(signal);
    const canonical = lookupForm(ip);
    if (!canonical) return { ok: false, domains: [], error: 'Invalid IP address', limited: false, errorKind: 'invalid' };
    if (isPrivateIP(canonical)) {
      return { ok: false, domains: [], error: 'Private IP address (not looked up)', limited: false, errorKind: 'invalid' };
    }
    if (!noCache) {
      const hit = reverseCache.get(canonical);
      if (hit) return { ...hit, domains: [...hit.domains] };
    }
    const result = await shared(reverseInflight, canonical, signal, async (sig) => {
      let url = `${HACKERTARGET_REVERSE_IP}?q=${canonical}`;
      if (hackertargetApiKey) url += `&apikey=${encodeURIComponent(hackertargetApiKey)}`;
      let res;
      try {
        const text = await limiter.run(() => fetchText(url, { fetchImpl, signal: sig, timeoutMs }), { signal: sig });
        res = parseReverseIpText(text);
      } catch (err) {
        if (isAbort(err)) throw err;
        const kind = errorKind(err);
        res = { ok: false, domains: [], error: describe(err), limited: kind === 'rate-limit', errorKind: kind };
      }
      if (res.ok) reverseCache.set(canonical, res);
      return res;
    });
    return { ...result, domains: [...result.domains] };
  }

  return {
    info,
    reverseIp,
    /** Drop every cached result. */
    clearCache() {
      infoCache.clear();
      reverseCache.clear();
    },
    /** Change the HTTP request concurrency. */
    setConcurrency(n) {
      limiter.setConcurrency(n);
    }
  };
}

/**
 * Canonical form used for lookups: IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is the
 * IPv4 host itself, so it is looked up (and cached) as IPv4.
 */
function lookupForm(ip) {
  const canonical = normalizeIP(typeof ip === 'string' ? ip : '');
  if (!canonical) return null;
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(canonical);
  return m ? m[1] : canonical;
}

function cloneInfo(info) {
  return {
    ...info,
    ptr: [...info.ptr],
    sources: [...info.sources],
    errors: info.errors.map((e) => ({ ...e })),
    asns: info.asns.map((a) => ({ ...a }))
  };
}
