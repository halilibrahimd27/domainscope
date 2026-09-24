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
import {
  normalizeIP, ipVersion, isPrivateIP, matchProviderByIP, parseCidr, formatIP, isSharedProvider
} from './netinfo.js';
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

/* ------------------------------------------------------------------------ */
/* Well-known infrastructure networks by origin ASN (display enrichment)    */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} InfraNetwork
 * @property {string} id
 * @property {string} name short display name ('Cloudflare', 'AWS' …)
 * @property {'cdn'|'waf'|'cloud'|'hosting'|'platform'} category
 * @property {ReadonlyArray<number>} asns origin AS numbers operated by this company
 * @property {string|null} proxyRanges id of the netinfo PROVIDERS entry whose published
 *   proxy / edge ranges are checked by classifyResolution (null: none published or embedded)
 */

const infra = (id, name, category, asns, proxyRanges = null) => Object.freeze({ id, name, category, asns: Object.freeze(asns), proxyRanges });

/**
 * A short list of large infrastructure operators, by the AS numbers they announce their
 * address space from (checked against RIPEstat prefix-overview / as-overview, 2026-09-23).
 *
 * Why: netinfo.classifyResolution recognises CDNs by their *published proxy ranges* only, so
 * an address the CDN company uses for something else — 1.1.1.1 is AS13335 (Cloudflare) but
 * not in https://www.cloudflare.com/ips/ — is classified 'direct'. That is right for the
 * scanner (no website is proxied there) but reads oddly in the IP view, which uses this table
 * to say "Cloudflare network (AS13335) — not a proxied-site range" instead. Display only: the
 * classification contract does not change and nothing here is used to decide coverage.
 *
 * Keep it small and well known; an unknown AS simply gets no hint.
 * @type {ReadonlyArray<InfraNetwork>}
 */
export const INFRA_NETWORKS = Object.freeze([
  infra('cloudflare', 'Cloudflare', 'cdn', [13335, 209242], 'cloudflare'),
  infra('fastly', 'Fastly', 'cdn', [54113], 'fastly'),
  infra('akamai', 'Akamai', 'cdn', [20940, 16625]),
  infra('imperva', 'Imperva', 'waf', [19551]),
  infra('sucuri', 'Sucuri', 'waf', [30148]),
  infra('aws', 'AWS', 'cloud', [16509, 14618], 'cloudfront'),
  infra('google', 'Google', 'cloud', [15169, 396982]),
  infra('microsoft', 'Microsoft', 'cloud', [8075]),
  infra('oracle', 'Oracle Cloud', 'cloud', [31898]),
  infra('alibaba', 'Alibaba Cloud', 'cloud', [45102]),
  infra('tencent', 'Tencent Cloud', 'cloud', [132203]),
  infra('digitalocean', 'DigitalOcean', 'hosting', [14061]),
  infra('linode', 'Linode (Akamai)', 'hosting', [63949]),
  infra('hetzner', 'Hetzner', 'hosting', [24940]),
  infra('ovh', 'OVHcloud', 'hosting', [16276]),
  infra('scaleway', 'Scaleway', 'hosting', [12876]),
  infra('vultr', 'Vultr', 'hosting', [20473]),
  infra('github', 'GitHub', 'platform', [36459])
]);

let infraByAsn = null;

/**
 * The well-known network that announces from `asn`, or null.
 * @param {number|string|null|undefined} asn 13335, '13335' or 'AS13335'
 * @returns {InfraNetwork|null}
 */
export function infraNetworkByAsn(asn) {
  if (!infraByAsn) {
    infraByAsn = new Map();
    for (const n of INFRA_NETWORKS) for (const a of n.asns) infraByAsn.set(a, n);
  }
  const num = typeof asn === 'number' ? asn : Number(String(asn ?? '').trim().replace(/^AS/i, ''));
  return Number.isInteger(num) && num > 0 ? infraByAsn.get(num) || null : null;
}

/**
 * @typedef {object} NetworkHint
 * @property {string} id InfraNetwork id
 * @property {string} name
 * @property {InfraNetwork['category']} category
 * @property {number} asn the matching origin AS
 * @property {'outside-proxy-ranges'|'cdn-edge'|'hosted'} relation
 *   - outside-proxy-ranges: a CDN whose proxy ranges are known, and the address is not in them
 *     (the company's own service, e.g. a DNS resolver — not a website behind the CDN)
 *   - cdn-edge: a CDN / WAF that publishes no ranges: most likely an edge in front of a site
 *   - hosted: a cloud / hosting / platform network: a server reached directly
 */

/**
 * Display hint for an address that netinfo classified as plain 'direct': which well-known
 * network announces it. Null for every other classification (Cloudflare-proxied, CDN,
 * platform, private … already say who operates it) and for unknown ASes.
 * @param {{ asn?: number|null, asns?: Array<{ asn: number }> }|null} info IpInfo (or part of it)
 * @param {{ kind?: string }|null} [classification] netinfo.classifyResolution result
 * @returns {NetworkHint|null}
 */
export function networkHint(info, classification = null) {
  if (!info || typeof info !== 'object') return null;
  if (classification && classification.kind !== 'direct') return null;
  const candidates = [info.asn, ...(Array.isArray(info.asns) ? info.asns.map((a) => a && a.asn) : [])];
  for (const asn of candidates) {
    const net = infraNetworkByAsn(asn);
    if (!net) continue;
    let relation = 'hosted';
    if (net.category === 'cdn' || net.category === 'waf') relation = net.proxyRanges ? 'outside-proxy-ranges' : 'cdn-edge';
    return { id: net.id, name: net.name, category: net.category, asn: Number(String(asn).replace(/^AS/i, '')), relation };
  }
  return null;
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

  const networkDescriber = makeNetworkDescriber(getJson, cacheSize);

  return {
    info,
    reverseIp,
    /**
     * Who announces an origin network (extension): see the module-level {@link describeNetwork}.
     * Shares this service's request limiter; cached per network (1 h).
     * @param {string} target IP address or CIDR block
     * @param {{ signal?: AbortSignal, noCache?: boolean }} [opts]
     * @returns {Promise<NetworkDescription>}
     */
    describeNetwork: networkDescriber.describe,
    /** Drop every cached result. */
    clearCache() {
      infoCache.clear();
      reverseCache.clear();
      networkDescriber.clear();
    },
    /** Change the HTTP request concurrency. */
    setConcurrency(n) {
      limiter.setConcurrency(n);
    }
  };
}

/* ------------------------------------------------------------------------ */
/* Network ownership (origin networks, on demand)                           */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} NetworkDescription
 * @property {string} input canonical query: an address, or `network/prefix` (host bits masked off)
 * @property {string|null} ip the address the lookup was made for (the block's network address for a
 *   CIDR — any address of a /24 or /48 sits under the same announced prefix); null when invalid
 * @property {4|6|0} version 0 when the input is neither an address nor a CIDR block
 * @property {boolean} private private / reserved space: nothing is looked up (never leaves the browser)
 * @property {object|null} provider netinfo PROVIDERS entry whose published ranges contain `ip` (offline)
 * @property {number|null} asn origin AS number
 * @property {string|null} asName short AS name ('AMAZON-02')
 * @property {string|null} holder AS holder organisation
 * @property {string|null} prefix the announced (covering) prefix
 * @property {boolean|null} announced
 * @property {Array<{ asn: number, holder: string|null }>} asns every origin AS (MOAS prefixes have several)
 * @property {string|null} rir
 * @property {{ id: string, name: string, category: string }|null} infra well-known operator of the AS
 *   ({@link INFRA_NETWORKS})
 * @property {string|null} category infra (or provider) category: 'cloud'|'hosting'|'cdn'|'waf'|'platform'|…
 * @property {boolean|null} shared true: known multi-tenant space (a cloud / hosting / platform / CDN
 *   operator, or a provider range) where one block serves many unrelated customers; false: the AS is
 *   not a known shared operator (NOT proof of single ownership); null: unknown (the lookup failed)
 * @property {boolean|null} coversInput the announced prefix contains the whole queried block (a block
 *   wider than its announced prefix is only partly described); null without a prefix
 * @property {string[]} sources 'ripestat' when RIPEstat answered
 * @property {string|null} error
 * @property {string|null} errorKind util.errorKind() of `error` ('invalid' for bad input)
 */

/**
 * Parse a network query: an IP address or a CIDR block.
 * @param {unknown} target
 * @returns {{ input: string, ip: string, version: 4|6, range: { version: 4|6, network: bigint, prefix: number } }|null}
 */
export function networkQuery(target) {
  const s = typeof target === 'string' ? target.trim() : '';
  if (!s) return null;
  if (s.includes('/')) {
    const range = parseCidr(s);
    if (!range) return null;
    const ip = formatIP(range.network, range.version);
    const bits = range.version === 4 ? 32 : 128;
    return { input: range.prefix === bits ? ip : `${ip}/${range.prefix}`, ip, version: range.version, range };
  }
  const ip = lookupForm(s);
  if (!ip) return null;
  const range = parseCidr(ip);
  return range ? { input: ip, ip, version: range.version, range } : null;
}

function rangeWithin(outer, inner) {
  if (!outer || !inner || outer.version !== inner.version || outer.prefix > inner.prefix) return false;
  const shift = BigInt((outer.version === 4 ? 32 : 128) - outer.prefix);
  return (inner.network >> shift) === (outer.network >> shift);
}

function emptyNetworkDescription(q, raw) {
  return {
    input: q ? q.input : String(raw ?? ''),
    ip: q ? q.ip : null,
    version: q ? q.version : 0,
    private: false,
    provider: q ? matchProviderByIP(q.ip) : null,
    asn: null,
    asName: null,
    holder: null,
    prefix: null,
    announced: null,
    asns: [],
    rir: null,
    infra: null,
    category: null,
    shared: null,
    coversInput: null,
    sources: [],
    error: null,
    errorKind: null
  };
}

/**
 * Combine a network query with a parsed RIPEstat prefix-overview (or null when the lookup failed)
 * into a {@link NetworkDescription}. Pure; exported for tests and reuse.
 * @param {ReturnType<typeof networkQuery>} q
 * @param {ReturnType<typeof parsePrefixOverview>|null} po
 * @returns {NetworkDescription}
 */
export function summarizeNetwork(q, po) {
  const out = emptyNetworkDescription(q, null);
  if (po) {
    Object.assign(out, {
      asn: po.asn, asName: po.asName, holder: po.holder, prefix: po.prefix,
      announced: po.announced, asns: po.asns.map((a) => ({ ...a })), rir: po.rir
    });
    out.sources = ['ripestat'];
    const hit = networkHint({ asn: po.asn, asns: po.asns });
    out.infra = hit ? { id: hit.id, name: hit.name, category: hit.category } : null;
    const pre = po.prefix ? parseCidr(po.prefix) : null;
    out.coversInput = pre && q ? rangeWithin(pre, q.range) : null;
  }
  out.category = (out.infra && out.infra.category) || (out.provider && out.provider.category) || null;
  if (isSharedProvider(out.provider) || (out.infra && isSharedProvider(out.infra))) out.shared = true;
  else if (po) out.shared = false;
  return out;
}

function cloneNetworkDescription(d) {
  return { ...d, asns: d.asns.map((a) => ({ ...a })), sources: [...d.sources], infra: d.infra ? { ...d.infra } : null };
}

/**
 * A cached, de-duplicated network describer over a `getJson(url, signal)` function.
 * @param {(url: string, signal?: AbortSignal) => Promise<any>} getJson
 * @param {number} [cacheSize]
 */
function makeNetworkDescriber(getJson, cacheSize = 500) {
  const cache = createCache({ maxEntries: cacheSize, ttlMs: INFO_TTL_MS });
  const inflight = new Map();
  async function describeOne(target, { signal, noCache = false } = {}) {
    throwIfAborted(signal);
    const q = networkQuery(target);
    if (!q) {
      const out = emptyNetworkDescription(null, target);
      out.error = 'Invalid IP address or CIDR block';
      out.errorKind = 'invalid';
      return out;
    }
    if (isPrivateIP(q.ip)) {
      const out = emptyNetworkDescription(q, target);
      out.private = true;
      return out;
    }
    if (!noCache) {
      const hit = cache.get(q.input);
      if (hit) return cloneNetworkDescription(hit);
    }
    const result = await shared(inflight, q.input, signal, async (sig) => {
      let po = null;
      let failure = null;
      try {
        const url = `${RIPESTAT_BASE}/prefix-overview/data.json?resource=${q.ip}&sourceapp=${RIPESTAT_SOURCEAPP}`;
        po = parsePrefixOverview(await getJson(url, sig));
      } catch (err) {
        if (isAbort(err) && sig?.aborted) throw err;
        failure = err;
      }
      const out = summarizeNetwork(q, po);
      if (failure) {
        out.error = `ripestat: ${describe(failure)}`;
        out.errorKind = errorKind(failure);
      } else {
        cache.set(q.input, out);
      }
      return out;
    });
    return cloneNetworkDescription(result);
  }
  return { describe: describeOne, clear: () => cache.clear() };
}

// One describer (own cache + limiter) per fetch implementation, created on first use.
const describersByFetch = new WeakMap();

/**
 * Who announces an origin network, on demand: one RIPEstat prefix-overview request for the block's
 * network address (or the address itself), giving the origin AS, its holder, the announced prefix
 * and — for a well-known operator — whether it is shared cloud / hosting / CDN space. For the UI to
 * call per origin network AFTER a scan (the scanner never waits on it). Private / reserved space is
 * never looked up. Cached per network for an hour (failures are not cached) and de-duplicated
 * while in flight; abortable through `signal` (rejects only with AbortError then). Every other
 * failure is reported in the result (`error`, `shared: null` unless a provider range already says).
 * @param {string} target IP address or CIDR block ('192.0.2.0/24', '2001:db8:1::/48')
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, noCache?: boolean }} [opts]
 * @returns {Promise<NetworkDescription>}
 */
export function describeNetwork(target, { fetchImpl = globalThis.fetch, signal, noCache = false } = {}) {
  let describer = typeof fetchImpl === 'function' ? describersByFetch.get(fetchImpl) : null;
  if (!describer) {
    const limiter = createLimiter(4);
    const getJson = (url, sig) => limiter.run(
      () => retry(() => fetchJson(url, { fetchImpl, signal: sig, timeoutMs: DEFAULT_TIMEOUT_MS, headers: { accept: 'application/json' } }), {
        retries: 1, signal: sig, baseDelayMs: 400, maxDelayMs: 4000
      }),
      { signal: sig }
    );
    describer = makeNetworkDescriber(getJson);
    if (typeof fetchImpl === 'function') describersByFetch.set(fetchImpl, describer);
  }
  return describer.describe(target, { signal, noCache });
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
