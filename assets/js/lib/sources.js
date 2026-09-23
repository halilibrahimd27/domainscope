/**
 * sources.js — passive subdomain sources usable from a browser (CORS-enabled,
 * verified 2026-09-23): certificate transparency (crt.sh, Cert Spotter),
 * HackerTarget host search, Anubis DB and AlienVault OTX passive DNS.
 *
 * Every function is DOM-free and takes an injectable `fetchImpl`. Source
 * failures (quota, timeouts, HTTP errors, bad payloads) never throw: they are
 * reported in the SourceResult. Only caller cancellation rejects (AbortError).
 */

import {
  AbortError, TimeoutError, HttpError, RateLimitError, ParseError, fetchWithTimeout, retry, errorKind,
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
  }
].map((s) => Object.freeze(s)));

const MAX_CERTSPOTTER_PAGES = 5;
const CRTSH_RETRIES = 1;

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

/** Error carrying an explicit util.errorKind() classification. */
function sourceError(message, kind) {
  const err = new Error(message);
  err.name = 'SourceError';
  err.kind = kind;
  return err;
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
 * GET a URL as JSON or text with one timer covering headers and body.
 * Non-2xx → HttpError (body snippet, Retry-After); bad JSON → ParseError.
 * @returns {Promise<{ data: any, headers: Headers|null }>}
 */
async function request(url, { fetchImpl, signal, timeoutMs, as = 'json' }) {
  const timeoutCtl = new AbortController();
  const timer = setTimeout(() => {
    timeoutCtl.abort(new TimeoutError(`No response within ${Math.round(timeoutMs / 1000)} s`, { timeoutMs }));
  }, timeoutMs);
  const linked = signal ? mergeSignals(signal, timeoutCtl.signal) : timeoutCtl.signal;
  try {
    const res = await fetchWithTimeout(url, {
      fetchImpl,
      signal: linked,
      timeoutMs: 0,
      method: 'GET',
      headers: { accept: as === 'json' ? 'application/json' : 'text/plain, */*' },
      credentials: 'omit',
      referrerPolicy: 'no-referrer'
    });
    const headers = res.headers && typeof res.headers.get === 'function' ? res.headers : null;
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
  const s = raw.trim();
  if (!s || s.includes('@') || /\s/.test(s)) return null;
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
 * Transient crt.sh failures: 5xx, timeouts and network errors. crt.sh's proxy
 * answers overload with HTTP 502/503 pages that carry no CORS header, which
 * browsers report as a network TypeError ("Failed to fetch").
 */
function crtshTransient(err) {
  return err instanceof TimeoutError || err instanceof TypeError || (err instanceof HttpError && err.status >= 500);
}

/** Clearer message for the opaque browser error crt.sh overload produces. */
function crtshError(err) {
  if (err instanceof TypeError) {
    return sourceError(`crt.sh did not respond (${err.message}). crt.sh is often overloaded and its HTTP 5xx `
      + 'errors carry no CORS header, so browsers only see a network error; try again later.', 'network');
  }
  return err;
}

/**
 * crt.sh: CT log search. One row per log entry → de-duplicate per certificate.
 * One retry on transient failures. With `includeExpired`, the retry asks for
 * unexpired certificates only (the full-history query is far heavier and is
 * the one that times out / 502s) and the result is marked partial.
 */
async function fromCrtsh(domain, ctx) {
  const urlFor = (expired) => `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json${expired ? '' : '&exclude=expired'}`;
  // crt.sh 502/503 bursts usually clear within seconds: wait a little longer than the util default.
  const retryDelay = ctx.retryDelayMs ?? 5000;
  let data;
  let partialError = null;
  try {
    ({ data } = await retry(() => request(urlFor(ctx.includeExpired), { ...ctx, as: 'json' }), {
      retries: ctx.includeExpired ? 0 : CRTSH_RETRIES,
      baseDelayMs: retryDelay,
      maxDelayMs: 10000,
      signal: ctx.signal,
      shouldRetry: crtshTransient
    }));
  } catch (err) {
    if (!ctx.includeExpired || !crtshTransient(err) || (ctx.signal && ctx.signal.aborted)) throw crtshError(err);
    partialError = sourceError(`Expired certificates omitted: the full crt.sh history failed (${errorMessage(err)})`, errorKind(err));
    await sleep(retryDelay, ctx.signal);
    try {
      ({ data } = await request(urlFor(false), { ...ctx, as: 'json' }));
    } catch (err2) {
      throw crtshError(err2);
    }
  }
  if (data === null) return { rows: 0, certs: [], hints: [], collector: createCollector(domain), partialError };
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
  return { rows: data.length, certs: list, hints: [], collector, partialError };
}

/** Cert Spotter issuances API, paginated with `after=<last id>` (max 5 pages). */
async function fromCertspotter(domain, ctx) {
  const base = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}`
    + '&include_subdomains=true&expand=dns_names&expand=issuer';
  const collector = createCollector(domain);
  const certs = [];
  let rows = 0;
  let after = null;
  let partialError = null;
  let pages = 0;
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
  }
  const unique = new Map();
  for (const c of certs) if (!unique.has(c.key)) unique.set(c.key, c);
  return { rows, certs: [...unique.values()], hints: [], collector, partialError, pages };
}

/** HackerTarget host search: "host,ip" lines; quota errors come as HTTP 200 text. */
async function fromHackertarget(domain, ctx) {
  const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
  const { data } = await request(url, { ...ctx, as: 'text' });
  const text = String(data ?? '').replace(/^﻿/, '').trim();
  if (/api count exceeded|increase quota|too many requests/i.test(text)) {
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

/** Anubis DB: JSON array of names. */
async function fromAnubis(domain, ctx) {
  const url = `https://anubisdb.com/anubis/subdomains/${encodeURIComponent(domain)}`;
  const { data } = await request(url, { ...ctx, as: 'json' });
  const collector = createCollector(domain);
  if (data === null) return { rows: 0, certs: [], hints: [], collector };
  if (!Array.isArray(data)) throw new ParseError('Unexpected Anubis response (expected a JSON array)');
  for (const n of data) collector.add(n);
  return { rows: data.length, certs: [], hints: [], collector };
}

/** AlienVault OTX passive DNS: historical A/AAAA records are origin hints. */
async function fromOtx(domain, ctx) {
  const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`;
  const { data } = await request(url, { ...ctx, as: 'json' });
  if (!data || typeof data !== 'object' || !Array.isArray(data.passive_dns)) {
    throw new ParseError('Unexpected OTX response (no passive_dns array)');
  }
  const collector = createCollector(domain);
  const hints = new Map();
  for (const row of data.passive_dns) {
    if (!row || typeof row !== 'object') continue;
    const hit = collector.add(row.hostname);
    const type = String(row.record_type || '').toUpperCase();
    if (type === 'CNAME') collector.add(row.address); // an alias target inside the domain is a name too
    if (!hit || !hit.inScope || (type !== 'A' && type !== 'AAAA')) continue;
    const ip = normalizeIP(String(row.address ?? ''));
    if (ip) addHint(hints, hit.base, ip, 'otx', parseUtcDate(row.first), parseUtcDate(row.last));
  }
  return { rows: data.passive_dns.length, certs: [], hints: [...hints.values()], collector };
}

const FETCHERS = {
  crtsh: fromCrtsh,
  certspotter: fromCertspotter,
  hackertarget: fromHackertarget,
  anubis: fromAnubis,
  otx: fromOtx
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
 * @param {number} [opts.retryDelayMs] extension: crt.sh retry backoff base (default 5000 ms)
 * @returns {Promise<SourceResult>} never rejects except with AbortError
 */
export async function fetchSource(id, domain, {
  fetchImpl = globalThis.fetch, signal, timeoutMs, includeExpired = false, retryDelayMs
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
    rows: 0
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
  const ctx = {
    fetchImpl,
    signal,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : def.timeoutMs,
    includeExpired: !!includeExpired,
    retryDelayMs
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
    if (out.partialError) {
      result.partial = true;
      result.error = out.partialError.name === 'SourceError'
        ? out.partialError.message
        : `Incomplete: ${errorMessage(out.partialError)}`;
      result.errorKind = errorKind(out.partialError);
    }
  } catch (err) {
    if (signal && signal.aborted) throw toAbortError(signal.reason);
    result.error = errorMessage(err);
    result.errorKind = errorKind(err);
  }
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
 * @returns {Promise<{ results: SourceResult[], names: Map<string, Set<string>>, ipHints: IpHint[],
 *   certs: CtCert[], wildcardBases: string[] }>} `results` in `sources` order; `names` maps
 *   each name to the ids of the sources that reported it (sorted by name); rejects only with AbortError.
 */
export async function fetchAllSources(domain, {
  sources, onResult, fetchImpl = globalThis.fetch, signal, includeExpired = false, timeoutMs, retryDelayMs
} = {}) {
  checkAbort(signal);
  const ids = Array.isArray(sources) ? [...new Set(sources)] : SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
  const results = await Promise.all(ids.map(async (id) => {
    const r = await fetchSource(id, domain, { fetchImpl, signal, includeExpired, timeoutMs, retryDelayMs });
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
  }
  const names = new Map(sortHostnames([...nameSources.keys()]).map((n) => [n, nameSources.get(n)]));
  return {
    results,
    names,
    ipHints: sortHints([...hints.values()]),
    certs: mergeCerts(results.flatMap((r) => r.certs)),
    wildcardBases: sortHostnames([...bases])
  };
}
